/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Loopback (struct plc * plc, void * memory, size_t extent);
 *
 *   plc.h
 *
 *   instruct one powerline device to transmit the given Etherenet
 *   frame to another for a fixed period of time using VS_FR_LNK
 *   message;
 *
 *   See the Atheros HomePlug AV Firmware Technical Reference Manual
 *   for more information;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LOOPBACK_SOURCE
#define LOOPBACK_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/memory.h"

signed Loopback (struct plc * plc, void * memory, size_t extent)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_fr_lbk_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t DURATION;
		uint8_t RESERVED;
		uint16_t LENGTH;
		uint8_t PACKET [1038];
	}
	* request = (struct vs_fr_lbk_request *) (message);
	struct __packed vs_fr_lbk_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t DURATION;
		uint16_t LENGTH;
	}
	* confirm = (struct vs_fr_lbk_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_FR_LBK | MMTYPE_REQ));
	if (extent > sizeof (request->PACKET))
	{
		extent = sizeof (request->PACKET);
	}
	memcpy (request->PACKET, memory, extent);
	if (extent < (ETHER_MIN_LEN - ETHER_CRC_LEN))
	{
		extent = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	}
	request->DURATION = plc->timer;
	request->LENGTH = HTOLE16 ((uint16_t) (extent));
	extent += sizeof (struct ethernet_hdr);
	extent += sizeof (struct qualcomm_hdr);
	extent += 4;
	plc->packetsize = (uint16_t) (extent);
	if (SendMME (plc) <= 0)
	{
		error (1, ECANCELED, CHANNEL_CANTSEND);
	}
	while (ReadMME (plc, 0, (VS_FR_LBK | MMTYPE_CNF)) > 0)
	{
		if (confirm->MSTATUS)
		{
			Failure (plc, PLC_WONTDOIT);
			continue;
		}
	}
	return (0);
}

#endif



