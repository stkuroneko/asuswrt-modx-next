/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void hexwrite (signed fd, void const * memory, size_t extent);
 *
 *   number.h
 *
 *   write a memory region as a stream of hexadecimal characters;
 *   
 *
 *--------------------------------------------------------------------*/

#ifndef HEXWRITE_SOURCE
#define HEXWRITE_SOURCE

#include <unistd.h>

#include "../tools/types.h"
#include "../tools/number.h"

void hexwrite (signed fd, void const * memory, size_t extent) 

{ 
	byte * offset = (byte *) (memory); 
	while (extent--) 
	{ 
		byte byte = * offset; 
		write (fd, & DIGITS_HEX [(byte >> 4) & 0x0F], sizeof (byte)); 
		write (fd, & DIGITS_HEX [(byte >> 0) & 0x0F], sizeof (byte)); 
		offset++; 
	} 
	return; 
} 

#endif



