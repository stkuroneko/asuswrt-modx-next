/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Antiphon (struct plc * plc);
 *
 *   plc.h
 *
 *   instruct one powerline device to send trash frames to another
 *   for a given period (in seconds) to establish source device RX
 *   PHY rate and target device TX PHY rate; this does not work if
 *   the source device is also the local device, for some reason;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ANTIPHON_SOURCE
#define ANTIPHON_SOURCE

#include <memory.h>
#include <errno.h>

#include "../tools/error.h"
#include "../tools/flags.h"
#include "../plc/plc.h"

signed Antiphon (struct plc * plc, byte source [], byte target [])

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
		uint8_t DATA [1038];
	}
	* request = (struct vs_fr_lbk_request *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	if (_allclr (plc->flags, PLC_SILENCE))
	{
		char sourcename [ETHER_ADDR_LEN * 3];
		char targetname [ETHER_ADDR_LEN * 3];
		hexdecode (source, ETHER_ADDR_LEN, sourcename, sizeof (sourcename));
		hexdecode (target, ETHER_ADDR_LEN, targetname, sizeof (targetname));
		fprintf (stderr, "%s %s %s\n", channel->ifname, sourcename, targetname);
	}
	memset (message, 0, sizeof (* message));
	EthernetHeader (& request->ethernet, source, target, channel->type);
	QualcommHeader (& request->qualcomm, 0, (VS_FR_LBK | MMTYPE_REQ));
	request->DURATION = plc->timer;
	request->LENGTH = HTOLE16 (sizeof (request->DATA));
	memset (request->DATA, 0xA5, sizeof (request->DATA));
	EthernetHeader (request->DATA, target, source, ETHERTYPE_IP);
	plc->packetsize = sizeof (* request);
	if (SendMME (plc) <= 0)
	{
		error (1, errno, CHANNEL_CANTSEND);
	}

#if 0

/*
 *	This causes a multi-device session to terminate if the device has recently
 *	been removed or powered-off; The device appears to be present but will not
 *	respond; Also, this terminates a session if the network is overloaded with
 *	traffic;
 */

	if (ReadMME (plc, 0, (VS_FR_LBK | MMTYPE_CNF)) <= 0)
	{
		error (1, errno, CHANNEL_CANTREAD);
	}

#endif

	sleep (plc->timer);
	return (0);
}

#endif



