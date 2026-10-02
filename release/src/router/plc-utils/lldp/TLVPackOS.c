/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void * TLVPackOS (void const * memory, size_t extent, uint8_t type, uint16_t length, void const * value);
 *
 *   lldp.h
 *   
 *   write an IEEE 802.1AB organizationally specific TLV into memory 
 *   and return the address of the next free memory location; type 
 *   and length are converted to 7-bits and 9-bits respectively per 
 *   the standard; 
 *
 *   use macro TLV_HEAD to insert type and length into the header;
 *   the type is 0x7F and OUI is 00:B0:52;
 *
 *--------------------------------------------------------------------*/

#ifndef TLVPACKOS_SOURCE
#define TLVPACKOS_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../tools/types.h"
#include "../lldp/lldp.h"

void * TLVPackOS (void const * memory, size_t extent, uint8_t type, uint16_t length, void const * value) 

{ 
	byte * offset = (byte *) (memory); 
	struct tlv * tlv = (struct tlv *) (memory); 
	if ((sizeof (* tlv) +  4 +  length) <= extent) 
	{ 
		tlv->head = TLV_HEAD (0x7F, length); 
		tlv->data [0] = 0x00; 
		tlv->data [1] = 0xB0; 
		tlv->data [2] = 0x52; 
		tlv->data [3] = type; 
		memcpy (tlv->data +  4, value, length); 
		offset += sizeof (* tlv) +  4 +  length; 
	} 
	return ((void *) (offset)); 
} 

#endif



