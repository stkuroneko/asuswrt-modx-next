/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   char * getifname (signed number);
 *
 *   ether.h
 *
 *   return the PCAP interface name for a given interface number; this
 *   function is only needed when using LIBPCAP or WINPCAP libraries;
 *   
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      
 *--------------------------------------------------------------------*/

#ifndef GETIFNAME_SOURCE
#define GETIFNAME_SOURCE

#include <string.h>

#if defined (WINPCAP) || defined (LIBPCAP)
#include <pcap.h>
#endif

#include "../ether/ether.h"
#include "../tools/error.h"

char * getifname (signed index) 

{ 
	char * name = (char *) (0); 

#if defined (__linux__)

#elif defined (__APPLE__) || defined (__OpenBSD__)

#elif defined (WINPCAP) || defined (LIBPCAP)

	char buffer [PCAP_ERRBUF_SIZE]; 
	pcap_if_t * devices = (pcap_if_t *) (0); 
	pcap_if_t * device; 
	signed count; 
	if (pcap_findalldevs (& devices, buffer) == - 1) 
	{ 
		error (1, errno, "can't enumerate pcap devices"); 
	} 
	for (device = devices, count = 1; device; device = device->next, count++) 
	{ 
		if (count == index) 
		{ 
			name = strdup (device->name); 
			break; 
		} 
	} 
	if (! device) 
	{ 
		error (1, EINVAL, "invalid interface: %d", index); 
	} 
	pcap_freealldevs (devices); 

#else
#error "Unknown environment"
#endif

	return (name); 
} 

#endif



