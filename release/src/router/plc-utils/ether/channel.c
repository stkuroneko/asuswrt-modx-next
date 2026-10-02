/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   channel.c - global channel structure;
 *
 *   channel.h
 *
 *   define and initialize a global channel structure; this structure
 *   is initialized for communication with Atheros devices and it is
 *   referenced by Atheros Linux Toolkit programs that do not need a 
 *   full int6k data structure;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef CHANNEL_SOURCE
#define CHANNEL_SOURCE

#include "../ether/channel.h"

struct channel channel = 

{ 
	(file_t) (- 1), 
#ifdef RTCONFIG_QCA_PLC2	/* ASUS */
	(file_t) (- 1), 		/* bfd */
#endif
	0, 
	CHANNEL_ETHNUMBER, 
	CHANNEL_ETHDEVICE, 
#ifdef RTCONFIG_QCA_PLC2	/* ASUS */
	NULL,				/* brname */
#endif
	{ 
		0x00, 
		0xB0, 
		0x52, 
		0x00, 
		0x00, 
		0x01
	}, 
	{ 
		0x00, 
		0x00, 
		0x00, 
		0x00, 
		0x00, 
		0x00
	}, 
	ETH_P_HPAV, 

#if defined (__linux__)

#elif defined (__APPLE__) || defined (__OpenBSD__)

	(struct bpf *) (0), 

#elif defined (WINPCAP) || defined (LIBPCAP)

	(pcap_t *) (0), 
	{ 
		0
	}, 

#else
#error "Unknown Environment"
#endif

	CHANNEL_CAPTURE, 
	CHANNEL_TIMEOUT, 
	CHANNEL_FLAGS
}; 


struct channel channel1 = 

{ 
	(file_t) (- 1), 
#ifdef RTCONFIG_QCA_PLC2	/* ASUS */
	(file_t) (- 1), 		/* bfd */
#endif
	0, 
	CHANNEL1_ETHNUMBER, 
	CHANNEL1_ETHDEVICE, 
#ifdef RTCONFIG_QCA_PLC2	/* ASUS */
	NULL,				/* brname */
#endif
	{ 
		0x00, 
		0xB0, 
		0x52, 
		0x00, 
		0x00, 
		0x01
	}, 
	{ 
		0x00, 
		0x00, 
		0x00, 
		0x00, 
		0x00, 
		0x00
	}, 
	ETH_P_HPAV, 

#if defined (__linux__)

#elif defined (__APPLE__) || defined (__OpenBSD__)

	(struct bpf *) (0), 

#elif defined (WINPCAP) || defined (LIBPCAP)

	(pcap_t *) (0), 
	{ 
		0
	}, 

#else
#error "Unknown Environment"
#endif

	CHANNEL_CAPTURE, 
	CHANNEL_TIMEOUT, 
	CHANNEL_FLAGS
}; 
#endif



