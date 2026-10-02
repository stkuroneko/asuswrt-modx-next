/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed RandomAddress (struct plc * plc);
 *
 *   nda.h
 *
 *   randomize hardware address on local powerline devices when in
 *   bootloader mode; this message is an AR7x00 bootloader message;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef RANDOMADDRRESS_SOURCE
#define RANDOMADDRRESS_SOURCE

#include <stdio.h>
#include <stdint.h>

#include "../tools/error.h"
#include "../mme/mme.h"
#include "../plc/plc.h"
#include "../nda/nda.h"

signed RandomAddress (struct plc * plc)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_random_addr_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t MACADDRESS [ETHER_ADDR_LEN];
		uint32_t Reserved [3];
	}
	* request = (struct vs_random_addr_request *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, channel->peer, channel->host, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_RAND_MAC_ADDR | MMTYPE_REQ));
	plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
	memcpy (request->MACADDRESS, plc->RDA, sizeof (request->MACADDRESS));
	if (SendMME (plc) <= 0)
	{
		error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
		return (-1);
	}
	return (0);
}

#endif



