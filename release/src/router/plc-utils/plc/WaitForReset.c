/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WaitForReset (struct plc * plc);
 *
 *   plc.h
 *
 *   poll the device using VS_SW_VER messages until no confirmation
 *   messages are received indicating that the firmware has stopped
 *   running; return 0 if the firmware stops responding within the 
 *   allotted time or -1 if it does not or if a transmission error 
 *   occurs;
 *
 *   this function cannot distinguish between a software reset and
 *   a power failure;
 *
 *   retry is number of times to poll the device before returniung
 *   an error to indicate that the device failed to reset; timer is
 *   is the time between poll attempts;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *      Werner Henze <w.henze@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef WAITFORRESET_SOURCE
#define WAITFORRESET_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <memory.h>
#include <sys/time.h>

#include "../plc/plc.h"
#include "../tools/timer.h"
#include "../tools/error.h"

signed WaitForReset (struct plc * plc)

{
	extern const byte localcast [ETHER_ADDR_LEN];
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	unsigned timer = 0;

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_sw_ver_request
	{
		struct ethernet_hdr ethernet;
		struct qualcomm_hdr qualcomm;
	}
	* request = (struct vs_sw_ver_request *) (message);

#ifndef __GNUC__
#pragma pack (pop)
#endif

	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	for (timer = 0; timer < plc->timer; timer = SECONDS (ts, tc))
	{
		memset (message, 0, sizeof (* message));
		EthernetHeader (& request->ethernet, localcast, channel->host, channel->type);
		QualcommHeader (& request->qualcomm, 0, (VS_SW_VER | MMTYPE_REQ));
		plc->packetsize = (ETHER_MIN_LEN - ETHER_CRC_LEN);
		if (SendMME (plc) <= 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTSEND);
			return (-1);
		}
		if (ReadMME (plc, 0, (VS_SW_VER | MMTYPE_CNF)) < 0)
		{
			error (PLC_EXIT (plc), errno, CHANNEL_CANTREAD);
			return (-1);
		}
		if (gettimeofday (& tc, NULL) == -1)
		{
			error (1, errno, CANT_RESET_TIMER);
		}
		if (! plc->packetsize)
		{
			return (0);
		}
	}
	return (-1);
}

#endif



