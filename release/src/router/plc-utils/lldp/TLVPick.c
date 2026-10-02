/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void * TLVPick (void const * memory, size_t extent, uint8_t type); 
 *
 *   lldp.h
 *
 *   search an IEEE 802.1AB TLV chain for the given type; return 
 *   the address of that TLV; return NULL when no match is found;
 *   
 *--------------------------------------------------------------------*/

#ifndef TLVPICK_SOURCE
#define TLVPICK_SOURCE

#include <stdio.h>
#include <stdint.h>

#include "../tools/types.h"
#include "../lldp/lldp.h"

void * TLVPick (void const * memory, size_t extent, uint8_t type) 

{ 
	byte * offset = (void *) (memory); 
	while (extent > 0) 
	{ 
		struct tlv * tlv = (struct tlv *) (offset); 
		uint8_t mytype = TLV_TYPE (tlv); 
		uint16_t mysize = TLV_SIZE (tlv); 
		if (mytype == type) 
		{ 
			return ((void *) (offset)); 
		} 
		if (! tlv->head) 
		{ 
			break; 
		} 
		offset += sizeof (* tlv) +  mysize; 
		extent -= sizeof (* tlv) +  mysize; 
	} 
	return ((void *) (0)); 
} 

#endif



