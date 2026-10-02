/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void * TLVPack (void const * memory, length_t extent, uint8_t type, uint16_t length, void const * value);
 *
 *   lldp.h
 *   
 *   write an IEEE 802.1AB TLV into memory and return the address of
 *   the next free memory location; type and length are converted to
 *   7-bits and 9-bits respectively per the standard; 
 *
 *   use macro TLV_HEAD to merge type and length into the header;
 *
 *--------------------------------------------------------------------*/

#ifndef TLVPACK_SOURCE
#define TLVPACK_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../tools/types.h"
#include "../tools/memory.h"
#include "../lldp/lldp.h"

void * TLVPack (void const * memory, size_t extent, uint8_t type, uint16_t length, void const * value) 

{ 
	byte * offset = (byte *) (memory); 
	struct tlv * tlv = (struct tlv *) (memory); 
	if ((sizeof (* tlv) +  length) <= extent) 
	{ 
		tlv->head = TLV_HEAD (type, length); 
		memcpy (tlv->data, value, length); 
		offset += sizeof (* tlv) +  length; 
	} 
	return ((void *) (offset)); 
} 

#endif



