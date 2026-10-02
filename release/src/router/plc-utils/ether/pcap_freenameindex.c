/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void pcap_freenameindex (struct if_nameindex *) 
 *
 *   ether.h
 *
 *   a WinPcap version of POSIX if_freenameindex function; 
 *
 *   see The Open Group Base Specifications Issue 6 IEEE Std 1003.1, 
 *   2004 Edition for a description of this function;
 *
 *--------------------------------------------------------------------*/

#ifndef PCAP_FREENAMEINDEX_SOURCE
#define PCAP_FREENAMEINDEX_SOURCE

#include <pcap.h>
#include <stdlib.h>

#include "../ether/ether.h"

void pcap_freenameindex (struct if_nameindex * if_nameindex) 

{ 

#if defined (WINPCAP) || defined (LIBPCAP)

	struct if_nameindex * ifp = if_nameindex; 
	while (ifp->if_index) 
	{ 
		free (ifp->if_name); 
	} 
	free (if_nameindex); 

#endif

	return; 
} 

#endif



