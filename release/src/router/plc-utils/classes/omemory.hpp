/*====================================================================*
 *
 *   omemory.hpp - omemory class declaration;
 *
 *   static memory manipulation methods;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oMEMORY_HEADER
#define oMEMORY_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>
#include <iostream>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/stdafx.hpp"

/*====================================================================*
 *   class datatypes;
 *--------------------------------------------------------------------*/

typedef unsigned char byte;

/*====================================================================*
 *   class declaration;
 *--------------------------------------------------------------------*/

class __declspec (dllexport) omemory 

{
public:
	omemory ();
	virtual ~ omemory ();
	static void endian (void *, size_t extent);
	static void swap (void *, void *, size_t extent);
	static void * encode (void * memory, void const * source, size_t extent);
	static void const * decode (void const * memory, void * target, size_t extent);
	static void memtext (char const * string, char buffer [], size_t length);
	static signed memincr (void * memory, size_t extent);
	static signed memdecr (void * memory, size_t extent);
	static signed strincr (void * memory, size_t extent, uint8_t minimum, uint8_t maximum);
	static signed strdecr (void * memory, size_t extent, uint8_t minimum, uint8_t maximum);
	static uint16_t checksum16 (void const * memory, size_t extent, uint16_t checksum);
	static uint32_t checksum32 (void const * memory, size_t extent, uint32_t checksum);
	static char * binstring (char buffer [], size_t length, void const * memory, size_t extent);
	static char * decstring (char buffer [], size_t length, void const * memory, size_t extent);
	static char * hexstring (char buffer [], size_t length, void const * memory, size_t extent);
	static char * serial (char buffer [], size_t length, unsigned value, unsigned radix);
	static char * serial (char buffer [], size_t length, unsigned value, unsigned radix, unsigned c);
	static size_t hexencode (void * memory, size_t extent, char const * string);
	static size_t decencode (void * memory, size_t extent, char const * string);
	static size_t binencode (void * memory, size_t extent, char const * string);
	static size_t hexdecode (void const * memory, size_t extent, char buffer [], size_t length);
	static size_t decdecode (void const * memory, size_t extent, char buffer [], size_t length);
	static size_t bindecode (void const * memory, size_t extent, char buffer [], size_t length);
	static size_t hexin (void * memory, size_t extent, std::istream * stream);
	static void hexdump (void const * memory, size_t offset, size_t extent, std::ostream * stream);
	static void hexview (void const * memory, size_t offset, size_t extent, std::ostream * stream);
	static void binout (void const * memory, size_t extent, signed c, std::ostream * steam);
	static void hexout (void const * memory, size_t extent, signed c, std::ostream * stream);
	static void decout (void const * memory, size_t extent, signed c, std::ostream * stream);
	static signed todigit (signed c);
	static char const digits [];
	static char bin_extender;
	static char dec_extender;
	static char hex_extender;
private:
	static char chr_nonprint;
};

/*====================================================================*
 *   end declaration;
 *--------------------------------------------------------------------*/

#endif

