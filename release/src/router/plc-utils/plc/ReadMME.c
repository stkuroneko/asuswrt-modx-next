/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadMME (struct plc * plc, uint8_t MMV, uint16_t MMTYPE);
 *
 *   plc.h
 *
 *   wait for a QCA vendor specific message of given MMV and MMTYPE;
 *   discard unwanted messages until the desired message arrives or
 *   the channel timeout expires; return packetsize on success, 0 on
 *   timeout or -1 on error;
 *
 *   see SendMME for the send counterpart to this function;
 *
 *   a well designed UnwantedMessage function is critical here;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *      Matthieu Poullet <m.poullet@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef READMME_SOURCE
#define READMME_SOURCE

#include <sys/time.h>

#include <stdint.h>
#include <memory.h>
#include <errno.h>

#include "../tools/error.h"
#include "../tools/timer.h"
#include "../plc/plc.h"
#include "../mme/mme.h"

signed ReadMME (struct plc * plc, uint8_t MMV, uint16_t MMTYPE)

{
	struct channel * channel = (struct channel *) (plc->channel);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	while ((plc->packetsize = readpacket (channel, message, sizeof (* message))) >= 0)
	{
		if (UnwantedMessage (message, plc->packetsize, MMV, MMTYPE))
		{
			if (gettimeofday (& tc, NULL) == -1)
			{
				error (1, errno, CANT_RESET_TIMER);
			}
			if (channel->timeout < 0)
			{
				continue;
			}
			if (channel->timeout > MILLISECONDS (ts, tc))
			{
				continue;
			}
			plc->packetsize = 0;
		}
		break;
	}
	return (plc->packetsize);
}
signed ReadMME1 (struct plc * plc, uint8_t MMV, uint16_t MMTYPE)

{
	struct channel * channel1 = (struct channel *) (plc->channel1);
	struct message * message = (struct message *) (plc->message);
	struct timeval ts;
	struct timeval tc;
	if (gettimeofday (& ts, NULL) == -1)
	{
		error (1, errno, CANT_START_TIMER);
	}
	while ((plc->packetsize = readpacket (channel1, message, sizeof (* message))) >= 0)
	{
		if (UnwantedMessage (message, plc->packetsize, MMV, MMTYPE))
		{
			if (gettimeofday (& tc, NULL) == -1)
			{
				error (1, errno, CANT_RESET_TIMER);
			}
			if (channel1->timeout < 0)
			{
				continue;
			}
			if (channel1->timeout > MILLISECONDS (ts, tc))
			{
				continue;
			}
			plc->packetsize = 0;
		}
		break;
	}
	return (plc->packetsize);
}
#endif



