/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed EthernetHeader (void * memory, const uint8_t peer [], const uint8_t host [], uint16_t protocol);
 *
 *   mme.h
 *
 *   encode a memory region with a standard Ethernet frame header in
 *   network byte order;
 *
 *   Contributor(s): 
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ETHERNETHEADER_SOURCE
#define ETHERNETHEADER_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../mme/mme.h"

signed EthernetHeader (void * memory, const uint8_t peer [], const uint8_t host [], uint16_t protocol) 

{ 
	struct ether_header * header = (struct ether_header *) (memory); 
	memcpy (header->ether_dhost, peer, sizeof (header->ether_dhost)); 
	memcpy (header->ether_shost, host, sizeof (header->ether_shost)); 
	header->ether_type = htons (protocol); 
	return (sizeof (* header)); 
} 

#endif



