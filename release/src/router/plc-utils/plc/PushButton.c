/*====================================================================*
	Copyright (c) 2013-2018 Qualcomm Technologies, Inc.
	All Rights Reserved.
	Confidential and Proprietary - Qualcomm Technologies, Inc.
	******************************************************************
	2013 Qualcomm Atheros, Inc.
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   signed PushButton (struct plc * plc);
 *
 *   plc.h
 *
 *   THis plugin for program plc emulates pushbutton functionality
 *   using a MS_PB_ENC message; as a special case we do not expect
 *   a confirm message for one firmware version;
 *
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PUSHBUTTON_SOURCE
#define PUSHBUTTON_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/memory.h"
#include "../plc/plc.h"

signed PushButton (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed ms_pb_enc_request
	{
		struct ethernet_hdr ethernet;
		struct homeplug_hdr homeplug;
		uint8_t PBACTION;
	}
	* request = (struct ms_pb_enc_request *) (message);
	struct __packed ms_pb_enc_confirm
	{
		struct ethernet_hdr ethernet;
		struct homeplug_hdr homeplug;
		uint8_t MSTATUS;
		uint8_t AVLNSTAT;
		uint8_t PPBSTATE;
		uint8_t CPBSTATE;
	}
	* confirm = (struct ms_pb_enc_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	if (plc->pushbutton == 1)
	{
		Request (plc, "Join Network");
	}
	if (plc->pushbutton == 2)
	{
		Request (plc, "Leave Network");
	}
	if (plc->pushbutton == 3)
	{
		Request (plc, "Fetch Network Status");
	}
	if (plc->pushbutton == 4)
	{
		Request (plc, "Reset to factory defaults");
	}
	if (plc->pushbutton == 5)
	{
		Request (plc, "Stop joining the network");
	}
	if (plc->pushbutton == 6)
	{
		Request (plc, "Extend reset timeout");
	}
	if (plc->pushbutton == 7)
	{
		Request (plc, "Return PB state");
	}

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	request->homeplug.MMV = 0;
	request->homeplug.MMTYPE = HTOLE16 (MS_PB_ENC | MMTYPE_REQ);
	request->PBACTION = plc->pushbutton;
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMFG (plc, 0, (MS_PB_ENC | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	if (plc->pushbutton == 1)
	{
		Confirm (plc, "Joining ...");
		return (0);
	}
	if (plc->pushbutton == 2)
	{
		Confirm (plc, "Leaving ...");
		return (0);
	}
	if (plc->pushbutton == 3)
	{
		Confirm (plc, "Membership Status %d", confirm->AVLNSTAT);
		return (0);
	}
	if (plc->pushbutton == 4)
	{
		Confirm (plc, "Resetting ...");
		return (0);
	}
	if (plc->pushbutton == 5)
	{
		Confirm (plc, "Stopping ...");
		return (0);
	}
	if (plc->pushbutton == 6)
	{
		Confirm (plc, "Starting/Extending timeout ...");
		return (0);
	}
	if (plc->pushbutton == 7)
	{
		Confirm (plc, "Previous PB State %d", confirm->PPBSTATE); 
		Confirm (plc, "Current PB State %d", confirm->CPBSTATE); 
		return (0);
	}
	return (-1);
}

#endif



