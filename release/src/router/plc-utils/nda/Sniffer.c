/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Sniffer (struct plc * plc);
 *
 *   nda.h
 *
 *   enable/disable sniffer mode on a powerline device;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SNIFFER_SOURCE
#define SNIFFER_SOURCE

#include <memory.h>
#include <errno.h>

#include "../tools/memory.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../ether/channel.h"
#include "../mme/mme.h"
#include "../plc/plc.h"

signed Sniffer (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sniffer_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t SNIFFCTRL;
	}
	* request = (struct vs_sniffer_request *) (message);
	struct __packed vs_sniffer_confirm
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MSTATUS;
		uint8_t SNIFSTATE;
		uint8_t SNIFFER_DA [ETHER_ADDR_LEN];
	}
	* confirm = (struct vs_sniffer_confirm *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	ssize_t packetsize;
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_SNIFFER | MMTYPE_REQ));
	request->SNIFFCTRL = plc->action;
	if (sendpacket (channel, message, (ETHER_MIN_LEN - ETHER_CRC_LEN)) <= 0)
	{
		error (1, ECANCELED, CHANNEL_CANTSEND);
	}
	while ((packetsize = readpacket (channel, message, sizeof (* message))) > 0)
	{
		if (! UnwantedMessage (message, packetsize, 0, (VS_SNIFFER | MMTYPE_CNF)))
		{
			Display (plc, "SNIFFER %s", (confirm->SNIFSTATE)? "ON": "OFF");
			break;
		}
	}
	return (0);
}

#endif



