/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed SetNMK (struct plc * plc);
 *
 *   plc.h
 *
 *   set NMK on a local or remote device using a VS_SET_KEY message;
 *
 *   using this message to set the NMK on a remote device requires
 *   both the remote device address (RDA) and the remote device
 *   access key (DAK);
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SETNMK_SOURCE
#define SETNMK_SOURCE

#include <string.h>

#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../tools/memory.h"
#include "../key/HPAVKey.h"

signed SetNMK (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_set_key_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t EKS;
		uint8_t NMK [HPAVKEY_NMK_LEN];
		uint8_t PEKS;
		uint8_t RDA [ETHER_ADDR_LEN];
		uint8_t DAK [HPAVKEY_DAK_LEN];
	}
	* request = (struct vs_set_key_request *) (message);
	struct __packed vs_set_key_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
	}
	* confirm = (struct vs_set_key_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SET_KEY | MMTYPE_REQ));
	plc->packetsize = sizeof (struct vs_set_key_request);
	request->EKS = 0x01;
	memcpy (request->NMK, plc->NMK, sizeof (request->NMK));
	if (_anyset (plc->flags, PLC_SETREMOTEKEY))
	{
		Request (plc, "Set Remote Network Membership Key");
		memcpy (request->RDA, plc->RDA, sizeof (request->RDA));
		memcpy (request->DAK, plc->DAK, sizeof (request->DAK));
		request->PEKS = 0x00;
	}
	else 
	{
		Request (plc, "Set Local Network Membership Key");
		memset (request->RDA, 0, sizeof (request->RDA));
		memset (request->DAK, 0, sizeof (request->DAK));
		request->PEKS = 0x0F;
	}
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	if (ReadMME (plc, 0, (VS_SET_KEY | MMTYPE_CNF)) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
		return (-1);
	}
	if (confirm->MSTATUS)
	{
		Failure (plc, PLC_WONTDOIT);
		return (-1);
	}
	Confirm (plc, "Setting ...");
	return (0);
}

#endif



