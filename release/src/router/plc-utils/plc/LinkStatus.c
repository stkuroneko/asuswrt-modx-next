/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *   
 *   signed LinkStatus (struct plc * plc);
 *   
 *   plc.h
 * 
 *   read powerline link status from an INT6x00
 *   using a VS_PL_LINK_STATUS Request Message;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LINKSTATUS_SOURCE
#define LINKSTATUS_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../plc/plc.h"

signed LinkStatus (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_link_status_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_link_status_request *) (message);
	struct __packed vs_link_status_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t LINKSTATUS;
	}
	* confirm = (struct vs_link_status_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	Request (plc, "Request Link Status");
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_PL_LINK_STATUS | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	while (ReadMME (plc, 0, (VS_PL_LINK_STATUS | MMTYPE_CNF)) > 0)
	{
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
		Display (plc, "%d", confirm->LINKSTATUS);
	}
	return (0);
}

#endif



