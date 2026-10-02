/*====================================================================*
 *
 *   void hexpump (void const * memory, size_t extent, FILE * fp);
 *
 *   memory.h
 *
 *   print a memory region as a brief hex dump;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright (c) 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef HEXPUMP_SOURCE
#define HEXPUMP_SOURCE

#include <stdio.h>
#include <ctype.h>

#include "../tools/memory.h"
#include "../tools/number.h"

void hexpump (void const * memory, size_t extent, FILE * fp) 

{ 
	byte const * origin = (byte const *) (memory); 
	byte const * offset = (byte const *) (memory); 
	while (extent--) 
	{ 
		if (offset != origin) 
		{ 
			putc ((offset - origin) & 0x0F? ' ': '\n', fp); 
		} 
		putc (DIGITS_HEX [(* offset >> 4) & 0x0F], fp); 
		putc (DIGITS_HEX [(* offset >> 0) & 0x0F], fp); 
		offset++; 
	} 
	putc ('\n', fp); 
	return; 
} 

#endif



