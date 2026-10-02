/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ssize_t readchannel (struct channel const * channel, void * memory, ssize_t extent);
 *
 *   channel.h
 *
 *   read the next message from channel and return message length on 
 *   success or 0 on timeout or -1 on error; 
 *
 *--------------------------------------------------------------------*/

#ifndef READCHANNEL_SOURCE
#define READCHANNEL_SOURCE

#include <sys/time.h>
#include <memory.h>
#include <errno.h>

#include "../ether/channel.h"
#include "../tools/timer.h"
#include "../tools/error.h"

ssize_t readchannel (struct channel const * channel, void * memory, ssize_t extent) 

{ 
	struct timeval ts; 
	struct timeval tc; 
	ssize_t length; 
	if (gettimeofday (& ts, NULL) == - 1) 
	{ 
		error (1, errno, CANT_START_TIMER); 
	} 
	while ((length = readpacket (channel, memory, extent)) == 0) 
	{ 
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
		break; 
	} 
	return (length); 
} 

#endif



