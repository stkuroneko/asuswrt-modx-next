/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Monitor (struct plc * plc, signed colon, signed space);
 *
 *   nda.h
 *
 *   capture and print VS_SNIFFER indication messages from powerline
 *   devices in sniffer mode which may be enabled and disabled using
 *   a VS_SNIFFER request message;
 *
 *--------------------------------------------------------------------*/

#ifndef MONITOR_SOURCE
#define MONITOR_SOURCE

#include "../nda/nda.h"
#include "../plc/plc.h"

signed Monitor (struct plc * plc, signed colon, signed space)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sniffer_ind
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
		uint8_t SNIFFTYPE;
		struct vs_sniffer_ind_data
		{
			uint8_t DIRECTION [1];
			uint8_t SYSTIME [8];
			uint8_t BEACONTIME [4];
			uint8_t FRAMECTRL [16];
			uint8_t BEACONBODY [136];
		}
		SNIFFERDATA;
	}
	* indicate = (struct vs_sniffer_ind *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	signed length;
	Request (plc, "Listening");
	while ((length = readpacket (channel, message, sizeof (* message))) >= 0)
	{
		if (! length)
		{
			continue;
		}
		if (ntohs (indicate->ethernet.MTYPE) != ETH_P_HPAV)
		{
			continue;
		}
		if (indicate->qualcomm.MMV != 0)
		{
			continue;
		}
		if (LE16TOH (indicate->qualcomm.MMTYPE) != (VS_SNIFFER | MMTYPE_IND))
		{
			continue;
		}

#if 0

/*
 *	print sniffer data to stdout in binary only if stdout is not the console or a tty device.
 */

		if (! isatty (STDOUT_FILENO))
		{
			write (STDOUT_FILENO, & indicate->SNIFFERDATA, sizeof (indicate->SNIFFERDATA));
			continue;
		}

#endif

		hexout (indicate->SNIFFERDATA.DIRECTION, sizeof (indicate->SNIFFERDATA.DIRECTION), colon, space, stdout);
		hexout (indicate->SNIFFERDATA.SYSTIME, sizeof (indicate->SNIFFERDATA.SYSTIME), colon, space, stdout);
		hexout (indicate->SNIFFERDATA.BEACONTIME, sizeof (indicate->SNIFFERDATA.BEACONTIME), colon, space, stdout);
		hexout (indicate->SNIFFERDATA.FRAMECTRL, sizeof (indicate->SNIFFERDATA.FRAMECTRL), colon, space, stdout);
		hexout (indicate->SNIFFERDATA.BEACONBODY, sizeof (indicate->SNIFFERDATA.BEACONBODY), colon, '\n', stdout);
		fflush (stdout);
	}
	return (0);
}

#endif



