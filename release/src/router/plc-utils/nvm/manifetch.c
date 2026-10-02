/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void * manifetch (void const * memory, size_t extent);
 *
 *   nvm.h
 *   
 *   search an nvm manifest for a given variable type and return a 
 *   void pointer to the value, if present, or NULL if not; users 
 *   must apply the correct type cast to the pointer to access the
 *   value;
 *
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MANIFETCH_SOURCE
#define MANIFETCH_SOURCE

#include <stdio.h>
#include <stdint.h>

#include "../tools/endian.h"
#include "../tools/tlv.h"

void * manifetch (void const * memory, size_t extent, uint32_t type) 

{ 
	uint8_t * offset = (uint8_t *) (memory); 
	while (extent) 
	{ 
		struct TLVNode * node = (struct TLVNode *) (offset); 
		if (LE32TOH (node->type) == type) 
		{ 
			return ((void *) (& node->data)); 
		} 
		extent -= TLVSPAN (node); 
		offset += TLVSPAN (node); 
	} 
	return ((void *) (0)); 
} 

#endif



