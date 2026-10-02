/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   ssize_t sendpacket (struct channel const * channel, void * memory, ssize_t extent);
 *
 *   channel.h
 *   
 *   send one packet over a raw packet channel; return the number of 
 *   bytes sent or -1 on error; dump outgoing packets on stdout when 
 *   the VERBOSE flag is set; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SENDPACKET_SOURCE
#define SENDPACKET_SOURCE

#include <unistd.h>

#include "../ether/channel.h"
#include "../tools/memory.h"
#include "../tools/flags.h"

ssize_t sendpacket (struct channel const * channel, void * memory, ssize_t extent) 

{ 
	if (_anyset (channel->flags, CHANNEL_VERBOSE)) 
	{ 
		hexdump (memory, 0, extent, stdout); 
	} 

#if defined (__linux__)

	extent = sendto (channel->fd, memory, extent, 0, (struct sockaddr *) (0), (socklen_t) (0)); 

#elif defined (__APPLE__) || defined (__OpenBSD__)

	extent = write (channel->fd, memory, extent); 

#elif defined (WINPCAP) || defined (LIBPCAP)

	if (pcap_sendpacket (channel->socket, (byte *) (memory), extent)) 
	{ 
		extent = - 1; 
	} 

#else
#error "Unknown Environment"
#endif

	return (extent); 
} 

#endif



