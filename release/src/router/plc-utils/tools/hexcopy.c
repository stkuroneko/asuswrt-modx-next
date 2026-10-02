/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   size_t hexcopy (void * memory, size_t extent, char const * string);
 *
 *   memory.h
 *
 *   encode a hexadecimal string into a variable length memory region; 
 *   return the number of bytes encoded or 0 on error; an error will
 *   occur if the entire string cannot be converted due to illegal or 
 *   excessive digits;
 *
 *   permit an optional HEX_EXTENDER character between successive 
 *   octets; constant character HEX_EXTENDER is defined in number.h;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright (c) 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef HEXCOPY_HEADER
#define HEXCOPY_HEADER

#include "../tools/number.h"
#include "../tools/memory.h"

size_t hexcopy (void * memory, register size_t extent, register char const * string) 

{ 
	register byte * origin = (byte *) (memory); 
	register byte * offset = (byte *) (memory); 
	unsigned radix = RADIX_HEX; 
	unsigned digit = 0; 
	while ((extent) && (* string)) 
	{ 
		unsigned field = HEX_DIGITS; 
		unsigned value = 0; 
		if ((offset > origin) && (* string == HEX_EXTENDER)) 
		{ 
			string++; 
		} 
		while (field--) 
		{ 
			if ((digit = todigit (* string)) < radix) 
			{ 
				value *= radix; 
				value += digit; 
				string++; 
				continue; 
			} 
			return (0); 
		} 
		* offset = value; 
		offset++; 
		extent--; 
	} 
	return (offset - origin); 
} 

#endif



