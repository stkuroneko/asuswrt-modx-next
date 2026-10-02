/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ssize_t readmessage (struct channel const * channel, struct message * message, uint8_t MMV, uint16_t MMTYPE);
 *
 *   plc.h
 *
 *   wait for a QCA vendor specific message of given MMV and MMTYPE; 
 *   discard unwanted messages until the desired message arrives or
 *   the channel timeout expires; return packet length on success,
 *   0 on timeout or -1 on error;
 *
 *   see sendmessage for the send counterpart to this function;
 *
 *   a well designed UnwantedMessage function is critical here;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READMESSAGE_SOURCE
#define READMESSAGE_SOURCE

#include <sys/time.h>
#include <memory.h>
#include <errno.h>

#include "../tools/error.h"
#include "../tools/timer.h"
#include "../plc/plc.h"

ssize_t readmessage (struct channel const * channel, struct message * message, uint8_t MMV, uint16_t MMTYPE) 

{ 
	struct timeval ts; 
	struct timeval tc; 
	ssize_t length; 
	if (gettimeofday (& ts, NULL) == - 1) 
	{ 
		error (1, errno, CANT_START_TIMER); 
	} 
	while ((length = readpacket (channel, message, sizeof (* message))) >= 0) 
	{ 
		if (! UnwantedMessage (message, length, MMV, MMTYPE)) 
		{ 
			return (length); 
		} 
		if (gettimeofday (& tc, NULL) == - 1) 
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
		return (0); 
	} 
	return (- 1); 
} 

#endif



