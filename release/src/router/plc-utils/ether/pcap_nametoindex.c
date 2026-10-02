/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   unsigned pcap_nametoindex (char const * name);
 *
 *   ether.h
 *
 *   a WinPcap version of POSIX if_nametoindex function; return error
 *   in non-pcap environments;
 *
 *   see The Open Group Base Specifications Issue 6 IEEE Std 1003.1, 
 *   2004 Edition for a description of this function;
 *
 *--------------------------------------------------------------------*/

#ifndef PCAP_NAMETOINDEX_SOURCE
#define PCAP_NAMETOINDEX_SOURCE

#include <pcap.h>
#include <string.h>
#include <errno.h>

#include "../ether/ether.h"

unsigned pcap_nametoindex (char const * name) 

{ 

#if defined (WINPCAP) || defined (LIBPCAP)

	char buffer [PCAP_ERRBUF_SIZE]; 
	pcap_if_t * devices = (pcap_if_t *) (0); 
	pcap_if_t * device; 
	if (pcap_findalldevs (& devices, buffer) != - 1) 
	{ 
		unsigned index = 1; 
		for (device = devices; device; device = device->next) 
		{ 
			if (! strcmp (name, device->name)) 
			{ 
				index++; 
				continue; 
			} 
			pcap_freealldevs (devices); 
			return (index); 
		} 
		pcap_freealldevs (devices); 
	} 

#endif
#if defined (__APPLE__)

	errno = ENXIO; 

#endif

	return (0); 
} 

#endif



