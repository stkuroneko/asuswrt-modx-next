/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed closechannel (struct channel const * channel);
 *
 *   channel.h
 *
 *   close ethernet raw packet channel;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CLOSECHANNEL_SOURCE
#define CLOSECHANNEL_SOURCE

#include <unistd.h>
#include <stdlib.h>

#include "../ether/channel.h"

signed closechannel (struct channel const * channel) 

{ 

#if defined (__linux__) 
#if defined (RTCONFIG_QCA_PLC2)
	close (channel->bfd);
#endif
	return (close (channel->fd)); 

#elif defined (__APPLE__) || (__OpenBSD__)

	free (channel->bpf->bpf_buffer); 
	free (channel->bpf); 
	return (close (channel->fd)); 

#elif defined (WINPCAP) || defined (LIBPCAP)

	pcap_close (channel->socket); 
	return (0); 

#else
#error "Unknown Environment"
#endif

} 

#endif



