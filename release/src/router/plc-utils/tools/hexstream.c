/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   char const * hexstream (char buffer [], register size_t length, void const * memory, register size_t extent) 
 *
 *   memory.h
 *
 *   encode a character buffer with a stream of hexadecimal digits;
 *
 *--------------------------------------------------------------------*/

#ifndef HEXSTREAM_SOURCE
#define HEXSTREAM_SOURCE

#include "../tools/number.h"
#include "../tools/memory.h"

char const * hexstream (char buffer [], register size_t length, void const * memory, register size_t extent) 

{ 
	register char * string = (char *) (buffer); 
	register byte * offset = (byte *) (memory); 
	if (length) 
	{ 
		length >>= 1; 
		while ((length--) && (extent--)) 
		{ 
			* string++ = DIGITS_HEX [(* offset >> 4) & 0x0F]; 
			* string++ = DIGITS_HEX [(* offset >> 0) & 0x0F]; 
			offset++; 
		} 
		* string = (char) (0); 
	} 
	return (buffer); 
} 

#endif



