/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ResetDevice (struct plc * plc);
 *
 *   plc.h
 *
 *   This plugin for program plc and plcrate resets the device
 *   using a VS_RS_DEV message; resetting can take several seconds
 *   after this function returns to the caller;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *	
 *
 *--------------------------------------------------------------------*/

#ifndef RESETDEVICE1_SOURCE
#define RESETDEVICE1_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../tools/memory.h"

signed ResetDevice (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_rs_dev_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint32_t RSVD;
		uint8_t CFM_ACT;
		uint32_t RSVD_1;
		uint8_t BT_SRC;
		uint32_t RSVD_2;
	}
	* request = (struct vs_rs_dev_request *) (message);
	struct __packed vs_rs_dev_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint32_t RSVD;
		uint8_t CFM_ACT;
		uint32_t RSVD_1;
		uint8_t BT_SRC;
		uint32_t RSVD_2;
	}
	* confirm = (struct vs_rs_dev_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Reset Device");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_RS_DEV | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (_anyset (plc->flag2, PLC_FLAG2_CFM_ACT))
	{
		request->CFM_ACT = 1;
	}
	if (_anyset (plc->flag2, PLC_FLAG2_BT_SRC))
	{
		request->BT_SRC = 1;
	}
	if (SendMME (plc) <= 0)
	{
		error ((plc->flags & PLC_BAILOUT), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (_anyset (plc->flag2, PLC_FLAG2_CFM_ACT))
	{
		return (0);
	}
	while (ReadMME (plc, 0, (VS_RS_DEV | MMTYPE_CNF)) > 0)
	{
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		Confirm (plc, "Resetting ...");
	}
	return (0);
}

#endif



