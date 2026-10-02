/*====================================================================*
 *
 *   char const * hexstring ( char buffer [], size_t length, void const * memory, size_t extent);
 *
 *   memory.h
 *
 *   decode a memory region into a hexadecimal character buffer and 
 *   return the buffer address;
 *
 *   allow three string characters for each memory byte; this means
 *   that the buffer must hold at least three characters or nothing
 *   will be decoded; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright (c) 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   char const * hexstring (char buffer [], size_t length, void const * memory, size_t extent);
 *
 *   memory.h
 *
 *   encode a character buffer with a hexadecimal character string
 *   having octets seperated by HEX_EXTENDER, defined in number.h;
 *
 *--------------------------------------------------------------------*/

#ifndef HEXSTRING_SOURCE
#define HEXSTRING_SOURCE

#include <stdint.h>

#include "../tools/memory.h"

char const * hexstring (char buffer [], size_t length, void const * memory, size_t extent) 

{ 
	hexdecode (memory, extent, buffer, length); 
	return ((char *) (buffer)); 
} 

#endif



