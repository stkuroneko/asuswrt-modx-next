/*====================================================================*
 *
 *   omemory.cpp - omemory class definition;
 *
 *   static memory manipulation methods;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#ifndef oMEMORY_SOURCE
#define oMEMORY_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <cstring>
#include <cctype>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../classes/omemory.hpp"
#include "../classes/oerror.hpp"

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

char const omemory::digits [] = "0123456789ABCDEF";
char omemory::bin_extender = '-';
char omemory::dec_extender = '.';
char omemory::hex_extender = ':';
char omemory::chr_nonprint = '.';

/*====================================================================*
 *
 *   void endian (void * memory, size_t extent);
 *
 *   reverse the order of bytes within a multi-byte memory region; 
 *   return no value;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::endian (void * memory, size_t extent) 

{
	register byte * byte1 = (byte *)(memory);
	register byte * byte2 = (byte *)(memory) + extent;
	while (byte1 < byte2) 
	{
		register byte byte = *byte1;
		*byte1++ = *--byte2;
		*byte2 = byte;
	}
	return;
}

/*====================================================================*
 *
 *   void swap (void * memory1, void * memory2, size_t extent);
 *
 *   exchange the contents of one memory region with that of another; 
 *   return no value; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::swap (void * memory1, void * memory2, size_t extent) 

{
	register byte * byte1 = (byte *)(memory1);
	register byte * byte2 = (byte *)(memory2);
	if (memory1 != memory2) while (extent--) 
	{
		byte byte = *byte1;
		*byte1++ = *byte2;
		*byte2++ = byte;
	}
	return;
}

/*====================================================================*
 *
 *   void memtext (char const * string, char buffer [], size_t length);
 *
 *   copy a NUL terminated string to a fixed-length buffer ensuring
 *   that the buffered string is terminated; truncate and terminate 
 *   the buffered string on overflow; pad the buffer to length with 
 *   NUL on underflow;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::memtext (char const * string, char buffer [], size_t length) 

{
	if (length--) 
	{
		while (length--) 
		{
			if ((*buffer++ = *string) != 0) 
			{
				string++;
			}
		}
		*buffer = (char)(0);
	}
	return;
}

/*====================================================================*
 *
 *   void * encode (void * memory, void const * source, size_t extent);
 *
 *   encode external memory with the contents of some source and
 *   return the address of the next unencoded memory byte;
 *
 *   use this method to pack a buffer with data stored in various 
 *   locations;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void * omemory::encode (void * memory, void const * source, size_t extent) 

{
	std::memcpy (memory, source, extent);
	return ((byte *)(memory) + extent);
}

/*====================================================================*
 *
 *   void const * decode (void const * memory, void * target, size_t extent);
 *
 *   decode external memory into the contents of some source; return
 *   the address of the next undecoded memory byte;
 *
 *   use this method to unpack a buffer into data stored in various 
 *   locations;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void const * omemory::decode (void const * memory, void * target, size_t extent) 

{
	std::memcpy (target, memory, extent);
	return ((byte *)(memory) + extent);
}

/*====================================================================*
 *
 *   uint16_t checksum16 (void const * memory, size_t extent, uint16_t checksum);
 *
 *   compute the 16 bit checksum of a memory region; region extent 
 *   is specified in bytes but truncated to a multiple of 2 bytes;
 *   the checksum is the one's complement of the XOR of all 16 bit 
 *   words in the adjusted region; 
 *
 *   passing a checksum of 0 returns the computed checksum; passing
 *   a computed checksum returns 0 only if the checksum is correct;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

uint16_t omemory::checksum16 (void const * memory, register size_t extent, register uint16_t checksum) 

{
	register byte * offset = (byte *)(memory);
	while (extent >= sizeof (checksum)) 
	{
		checksum ^= *(uint16_t *)(offset);
		offset += sizeof (checksum);
		extent -= sizeof (checksum);
	}
	return (~checksum);
}

/*====================================================================*
 *
 *   uint32_t checksum32 (void const * memory, size_t extent, uint32_t checksum);
 *
 *   compute the 32 bit checksum of a memory region; region extent 
 *   is specified in bytes but truncated to a multiple of 4 bytes;
 *   the checksum is the one's complement of the XOR of all 32 bit 
 *   words in the adjusted region; 
 *
 *   passing a checksum of 0 returns the computed checksum; passing
 *   a computed checksum returns 0 only if the checksum is correct;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

uint32_t omemory::checksum32 (void const * memory, register size_t extent, register uint32_t checksum) 

{
	register byte * offset = (byte *)(memory);
	while (extent >= sizeof (checksum)) 
	{
		checksum ^= *(uint32_t *)(offset);
		offset += sizeof (checksum);
		extent -= sizeof (checksum);
	}
	return (~checksum);
}

/*====================================================================*
 *
 *   signed memincr (void * memory, size_t extent);
 *
 *   increment a multi-byte memory region; start at 0x00 and reset 
 *   at 0xFF; return -1 once all bytes are 0xFF;
 *
 *   for example,
 *
 *      0x00 0x00 0x00 --> 0x00 0x00 0x01
 *      0xFF 0x00 0xFF --> 0xFF 0x01 0x00
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

signed omemory::memincr (void * memory, register size_t extent) 

{
	register byte * offset = (byte *)(memory);
	while (extent--) 
	{
		if (++ offset [extent] != 0x00) 
		{
			return (0);
		}
	}
	return (-1);
}

/*====================================================================*
 *
 *   signed strincr (void * memory, size_t extent, byte minimum, byte maximum);
 *
 *   increment a multi-byte memory region; start at min and reset at
 *   max; return -1 once all bytes are max;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

signed omemory::strincr (void * memory, register size_t extent, register byte minimum, register byte maximum) 

{
	register byte * offset = (byte *)(memory);
	while (extent--) 
	{
		if (++ offset [extent] <= maximum) 
		{
			return (0);
		}
		offset [extent] = minimum;
	}
	return (-1);
}

/*====================================================================*
 *
 *   signed memdecr (void * memory, size_t extent);
 *
 *   decrement a multi-byte memory region; start at 0xff and reset 
 *   at 0x00; return -1 once all bytes are 0x00;
 *
 *   for example:
 *
 *      0x00 0x00 0x00 --> 0x00 0x00 0x01
 *      0xFF 0x00 0xFF --> 0xFF 0x01 0x00
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

signed omemory::memdecr (void * memory, register size_t extent) 

{
	register byte * offset = (byte *)(memory);
	while (extent--) 
	{
		if (-- offset [extent] != 0xFF) 
		{
			return (0);
		}
	}
	return (-1);
}

/*====================================================================*
 *
 *   signed strdecr (void * memory, size_t extent, byte minimum, byte maximum);
 *
 *   decrement a multi-byte memory region; start at max and reset at
 *   min; return -1 once all bytes are min;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

signed omemory::strdecr (void * memory, register size_t extent, register byte minimum, register byte maximum) 

{
	register byte * offset = (byte *)(memory);
	while (extent--) 
	{
		if (-- offset [extent] >= minimum) 
		{
			return (0);
		}
		offset [extent] = maximum;
	}
	return (-1);
}

/*====================================================================*
 *
 *   size_t binencode (void * memory, size_t extent, char const * string);
 *
 *   encode a binary string into a byte array; return the number of 
 *   bytes encoded on success or -1 on error; permit an optional
 *   hyphen between successive octets;
 *
 *   string must contain an even multiple of 8 binary digits; bytes
 *   are fixed width fields; leading zeros are required or an error
 *   will occur; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::binencode (void * memory, register size_t extent, register char const * string) 

{
	register byte * origin = (byte *)(memory);
	register byte * offset = (byte *)(memory);
	while ((extent) && (*string)) 
	{
		register unsigned radix = 2;
		register unsigned field = 8;
		register unsigned value = 0;
		register unsigned digit = 0;
		if ((offset > origin) && (*string == omemory::bin_extender)) 
		{
			string++;
		}
		while (field--) 
		{
			if ((digit = omemory::todigit (*string)) >= radix) 
			{
				errno = EINVAL;
				return (0);
			}
			value *= radix;
			value += digit;
			string++;
		}
		*offset = (byte)(value);
		offset++;
		extent--;
	}

#if defined (WIN32)

	while (isspace ((unsigned char)*string))  
	{
		string++;
	}

#endif

	if ((extent) || (*string)) 
	{
		errno = EINVAL;
		return (0);
	}
	return (offset - origin);
}

/*====================================================================*
 *
 *   size_t decencode (void * memory, size_t extent, char const *string);
 *
 *   encode a memory region with a dotted decimal string octet; return
 *   the number of characters encoded or 0 on error; permit an optional
 *   period between octets;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::decencode (void * memory, size_t extent, char const * string) 

{
	register byte * origin = (byte *)(memory);
	register byte * offset = (byte *)(memory);
	while ((extent) && (*string)) 
	{
		unsigned radix = 10;
		unsigned field = 3;
		unsigned value = 0;
		unsigned digit = 0;
		if ((offset > origin) && (*string == omemory::dec_extender)) 
		{
			string++;
		}
		while (field--) 
		{
			if ((digit = omemory::todigit (*string)) >= radix) 
			{
				errno = EINVAL;
				return (0);
			}
			value *= radix;
			value += digit;
			if (value >> 8) 
			{
				errno = ERANGE;
				return (0);
			}
			string++;
		}
		*offset = (byte)(value);
		offset++;
		extent--;
	}

#if defined (WIN32)

	while (isspace ((unsigned char)*string))  
	{
		string++;
	}

#endif

	if ((extent) || (*string)) 
	{
		errno = EINVAL;
		return (0);
	}
	return (offset - origin);
}

/*====================================================================*
 *
 *   size_t hexencode (void * memory, size_t extent, char const * string);
 *
 *   encode a NUL terminated hexadecimal string into a fixed length 
 *   memory region; return the number of bytes encoded or 0 on error; 
 *   an error will occur of the entire region cannot be encoded or 
 *   the entire string cannot be converted due to illegal characters
 *   or excessive digits;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::hexencode (void * memory, register size_t extent, register char const * string) 

{
	register byte * origin = (byte *)(memory);
	register byte * offset = (byte *)(memory);
	while ((extent) && (*string)) 
	{
		unsigned radix = 16;
		unsigned field = 2;
		unsigned value = 0;
		unsigned digit = 0;
		if ((offset > origin) && (*string == omemory::hex_extender)) 
		{
			string++;
		}
		while (field--) 
		{
			if ((digit = omemory::todigit (*string)) >= radix) 
			{
				errno = EINVAL;
				return (0);
			}
			value *= radix;
			value += digit;
			string++;
		}
		*offset = (byte)(value);
		offset++;
		extent--;
	}

#if defined (WIN32)

	while (isspace ((unsigned char)*string)) 
	{
		string++;
	}

#endif

	if ((extent) || (*string)) 
	{
		errno = EINVAL;
		return (0);
	}
	return (offset - origin);
}

/*====================================================================*
 *
 *   size_t bindecode (void const * memory, size_t extent, char buffer [], size_t length);
 *
 *   decode a memory region as a string of binary digits; 
 *
 *   allow 9 characters per byte when allocating the buffer;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::bindecode (void const * memory, register size_t extent, char buffer [], register size_t length) 

{
	register char * string = (char *)(buffer);
	register byte * offset = (byte *)(memory);
	if ((length /= 9)) 
	{
		while ((length-- > 0) && (extent-- > 0)) 
		{
			string = omemory::serial (string, 8, *offset++, 2);
			if ((length) && (extent)) 
			{
				*string++ = omemory::bin_extender;
			}
		}
		*string = (char) (0);
	}
	return (string - buffer);
}

/*====================================================================*
 *
 *   size_t decdecode (void const * memory, size_t extent, char buffer [], size_t length);
 *
 *   decode a memory block of given length in bytes as a string of
 *   separated hexadecimal bytes; terminate once the string fills
 *   or the memory ends; terminate the string and return the actual
 *   string bytes;
 *
 *   allow three string characters for each memory byte; this means
 *   that the buffer must have at least three characters or nothing
 *   will be decoded; the maximum number of bytes is the lesser of
 *   chars/3 and bytes;; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::decdecode (void const * memory, register size_t extent, char buffer [], register size_t length) 

{
	register char * string = (char *)(buffer);
	register byte * offset = (byte *)(memory);
	if ((length /= 4)) 
	{
		while ((length--) && (extent--)) 
		{
			string = omemory::serial (string, 3, *offset++, 10);
			if ((length) && (extent)) 
			{
				*string++ = omemory::dec_extender;
			}
		}
		*string = (char) (0);
	}
	return (string - buffer);
}

/*====================================================================*
 *
 *   size_t hexdecode (void const * memory, size_t extent,   char buffer [], size_t length);
 *
 *   decode a memory region as a string of hex octets separated with 
 *   a colon;
 *
 *   allow three string characters for each memory byte; this means
 *   that the buffer must hold at least three characters or nothing
 *   will be decoded; the maximum number of bytes is the lesser of
 *   chars/3 and bytes; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::hexdecode (void const * memory, register size_t extent, char buffer [], register size_t length) 

{
	register char * string = (char *)(buffer);
	register byte * offset = (byte *)(memory);
	if ((length /= 3)) 
	{
		while ((length--) && (extent--)) 
		{
			*string++ = omemory::digits [(*offset >> 4) & 0x0F];
			*string++ = omemory::digits [(*offset >> 0) & 0x0F];
			if ((length) && (extent)) 
			{
				*string++ = omemory::hex_extender;
			}
			offset++;
		}
		*string = (char) (0);
	}
	return (string - buffer);
}

/*====================================================================*
 *
 *   void hexdump (void const * memory, size_t offset, size_t extent, std::ostream * stream);
 *
 *   print a memory region in dump format showing byte offsets, hex
 *   byte values and ASCII byte values;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::hexdump (void const * memory, size_t offset, size_t extent, std::ostream * stream) 

{
	register byte * origin = (byte *)(memory);
	unsigned field = sizeof (extent) + sizeof (extent);
	unsigned block = 0x10;
	size_t lower = block * (offset / block);
	size_t upper = block + lower;
	size_t index = 0;
	char buffer [sizeof (extent) + sizeof (extent) + 0x48];
	char * output;
	while (lower < extent) 
	{
		output = omemory::serial (buffer, (size_t)(field), (unsigned)(index), 0x10);
		*output++ = ' ';
		for (index = lower; index < upper; index++) 
		{
			if (index < offset) 
			{
				*output++ = ' ';
				*output++ = ' ';
			}
			else if (index < extent) 
			{
				*output++ = omemory::digits [(origin [index] >> 4) & 0x0F];
				*output++ = omemory::digits [(origin [index] >> 0) & 0x0F];
			}
			else 
			{
				*output++ = ' ';
				*output++ = ' ';
			}
			*output++ = ' ';
		}
		for (index = lower; index < upper; index++) 
		{
			if (index < offset) 
			{
				*output++ = ' ';
			}
			else if (index < extent) 
			{
				unsigned c = origin [index];
				*output++ = std::isprint (c)? (char)(c): omemory::chr_nonprint;
			}
			else 
			{
				*output++ = ' ';
			}
		}
		*output++ = '\n';
		stream->write (buffer, (signed)(output - buffer));
		lower += block;
		upper += block;
	}
	return;
}

/*====================================================================*
 *
 *   void hexview (void const * memory, size_t offset, size_t extent, std::ostream * stream)  
 *
 *   print a memory region in dump format showing byte offsets, hex
 *   byte values and ASCII byte values;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::hexview (void const * memory, size_t offset, size_t extent, std::ostream * stream) 

{
	register byte * origin = (byte *)(memory);
	unsigned field = sizeof (extent) + sizeof (extent);
	unsigned block = 0x10;
	size_t lower = block * (offset / block);
	size_t upper = block + lower;
	size_t index = 0;
	char buffer [sizeof (extent) + sizeof (extent) + 0x48];
	char * output;
	while (lower < offset + extent) 
	{
		output = omemory::serial (buffer, (size_t)(field), (unsigned)(index), 0x10);
		*output++ = ' ';
		for (index = lower; index < upper; index++) 
		{
			if (index < offset) 
			{
				*output++ = ' ';
				*output++ = ' ';
			}
			else if (index < offset + extent) 
			{
				*output++ = omemory::digits [(origin [index-offset] >> 4) & 0x0F];
				*output++ = omemory::digits [(origin [index-offset] >> 0) & 0x0F];
			}
			else 
			{
				*output++ = ' ';
				*output++ = ' ';
			}
			*output++ = ' ';
		}
		for (index = lower; index < upper; index++) 
		{
			if (index < offset) 
			{
				*output++ = ' ';
			}
			else if (index < offset + extent) 
			{
				unsigned c = origin [index-offset];
				*output++ = std::isprint (c)? (char)(c): omemory::chr_nonprint;
			}
			else 
			{
				*output++ = ' ';
			}
		}
		*output++ = '\n';
		stream->write (buffer, (signed)(output - buffer));
		lower += block;
		upper += block;
	}
	return;
}

/*====================================================================*
 *
 *   char * binstring (  char buffer [], size_t length, void const * memory, size_t extent);
 *
 *   decode a memory region into a binary character buffer and return
 *   the buffer address;
 *
 *   allow nine string characters for each memory byte; this means
 *   that the buffer must hold at least nine characters or nothing
 *   will be decoded; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

char * omemory::binstring (char buffer [], size_t length, void const * memory, size_t extent) 

{
	omemory::bindecode (memory, extent, buffer, length);
	return (buffer);
}

/*====================================================================*
 *
 *   char * decstring (  char buffer [], size_t length, void const * memory, size_t extent);
 *
 *   decode a memory region into a decimal character buffer and 
 *   return the buffer address;
 *
 *   allow four string characters for each memory byte; this means
 *   that the buffer must hold at least four characters or nothing
 *   will be decoded; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

char * omemory::decstring (char buffer [], size_t length, void const * memory, size_t extent) 

{
	omemory::decdecode (memory, extent, buffer, length);
	return (buffer);
}

/*====================================================================*
 *
 *   char * hexstring (  char buffer [], size_t length, void const * memory, size_t extent);
 *
 *   decode a memory region into a hexadecimal character buffer and 
 *   return the buffer address;
 *
 *   allow three string characters for each memory byte; this means
 *   that the buffer must hold at least three characters or nothing
 *   will be decoded; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

char * omemory::hexstring (char buffer [], size_t length, void const * memory, size_t extent) 

{
	omemory::hexdecode (memory, extent, buffer, length);
	return (buffer);
}

/*====================================================================*
 *
 *   void binout (void const * memory, size_t extent, signed c, std::ostream * stream);
 *
 *   print a memory region as a series of binary octets separated by 
 *   character c which is normally BIN_EXTENDER defined in number.h; 
 *
 *   for example, binout (memory, 6, '-', stdout) would print
 *
 *      00000000-11010000-01010010-00000000-00000000-00000001
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::binout (void const * memory, size_t extent, signed c, std::ostream * stream) 

{
	byte * offset = (byte *)(memory);
	while (extent--) 
	{
		unsigned bits = 8;
		while (bits--) 
		{
			stream->put (omemory::digits [(*offset >> bits) & 1]);
		}
		if ((extent) && std::isprint (c)) 
		{
			stream->put ((char)(c));
		}
		offset++;
	}
	return;
}

/*====================================================================*
 *
 *   void decout (void const * memory, size_t extent, signed c, std::ostream * stream);
 *
 *   print a memory region as a series of decimal octets separated  
 *   by character c which is normally DEC_EXTENDER as defined in 
 *   number.h; 
 *
 *   for example, decout (memory, 4, '.', stdout) would print
 *
 *      192.168.101.002
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::decout (void const * memory, size_t extent, signed c, std::ostream * stream) 

{
	byte * offset = (byte *)(memory);
	while (extent--) 
	{
		unsigned order = 100;
		while (order) 
		{
			stream->put (omemory::digits [(* offset / order) % 10]);
			order /= 10;
		}
		if ((extent) && std::isprint (c)) 
		{
			stream->put ((char)(c));
		}
		offset++;
	}
	return;
}

/*====================================================================*
 *
 *   void hexout (void const * memory, size_t extent, signed c, std::ostream * stream);
 *
 *   print  a memory region as a series of hexadecimal octets seperated 
 *   by character c which is normally HEX_EXTENDER defined in number.h;
 *
 *   for example, hexout (memory, 6, ':', stdout) would print:
 *
 *      00:B0:52:00:00:01
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void omemory::hexout (void const * memory, size_t extent, signed c, std::ostream * stream) 

{
	byte * offset = (byte *)(memory);
	while (extent--) 
	{
		stream->put (omemory::digits [(* offset >> 4) & 0x0F]);
		stream->put (omemory::digits [(* offset >> 0) & 0x0F]);
		if ((extent) && std::isprint (c)) 
		{
			stream->put ((char)(c));
		}
		offset++;
	}
	return;
}

/*====================================================================*
 *
 *   size_t hexin ( void * memory, size_t extent, std::istream * stream) 
 *
 *   read a file and convert hexadecimal octets to binary bytes then 
 *   store them in consecutive memory locations up to a given length; 
 *   return the actual number of bytes stored;
 *
 *   digits may be consecutive or separated by white space consisting 
 *   of spaces, tabs, linefeeds, carriage returns, formfeeds or other
 *   characters such as punctuation; C-style or script-style comments 
 *   are treated as white space;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

size_t omemory::hexin (void * memory, size_t extent, std::istream * stream) 

{
	byte * origin = (byte *)(memory);
	byte * offset = (byte *)(memory);
	unsigned digits = 0;
	signed c;
	while (((c = stream->get ()) != EOF) && (c != ';') && (extent)) 
	{
		if (c == '#') 
		{
			do 
			{
				c = stream->get ();
			}
			while ((c != '\n') && (c != EOF));
		}
		else if (c == '/') 
		{
			c = stream->get ();
			if (c == '/') 
			{
				do 
				{
					c = stream->get ();
				}
				while ((c != '\n') && (c != EOF));
			}
			else if (c == '*') 
			{
				while ((c != '/') && (c != EOF)) 
				{
					while ((c != '*') && (c != EOF)) 
					{
						c = stream->get ();
					}
					c = stream->get ();
				}
			}
		}
		else if ((c >= '0') && (c <= '9')) 
		{
			*offset *= 16;
			*offset += (byte)(c) - '0';
			if (digits++ & 1) 
			{
				offset++;
				extent--;
			}
		}
		else if ((c >= 'A') && (c <= 'F')) 
		{
			*offset *= 16;
			*offset += 10;
			*offset += (byte)(c) - 'A';
			if (digits++ & 1) 
			{
				offset++;
				extent--;
			}
		}
		else if ((c >= 'a') && (c <= 'f')) 
		{
			*offset *= 16;
			*offset += 10;
			*offset += (byte)(c) - 'a';
			if (digits++ & 1) 
			{
				offset++;
				extent--;
			}
		}
	}
	if (digits & 1) 
	{

#ifdef oERROR_HEADER

		oerror::error (0, EILSEQ, "Odd number of hex digits in source");

#endif

		return ((size_t)(-1));
	}
	return (offset - origin);
}

/*====================================================================*
 *
 *   char * serial (char buffer [], size_t length field, unsigned value, unsigned radix);
 *
 *   convert an unsigned integer to a numeric string of fixed length
 *   in the specified radix; return the next unformatted address;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

char * omemory::serial (register char buffer [], register size_t length, register unsigned value, register unsigned radix) 

{
	size_t offset = length;
	while (offset--) 
	{
		buffer [offset] = omemory::digits [value % radix];
		value /= radix;
	}
	return (buffer + length);
}

/*====================================================================*
 *
 *   char * serial (char buffer [], size_t length, unsigned value, unsigned radix, unsigned c);
 *
 *   convert an unsigned integer to a NUL terminated numeric string 
 *   of fixed length in the specified radix; return the string start
 *   address; 
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

char * omemory::serial (register char buffer [], register size_t length, register unsigned value, register unsigned radix, unsigned c) 

{
	if (length) 
	{
		buffer [length] = (char)(c);
	}
	while (length--) 
	{
		buffer [length] = omemory::digits [value % radix];
		value /= radix;
	}
	return (buffer);
}

/*====================================================================*
 *
 *   signed todigit (signed c);
 *  
 *   convert an ASCII digit to an integer;
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

signed omemory::todigit (signed c) 

{
	if ((c >= '0') && (c <= '9')) 
	{
		return (c - '0');
	}
	if ((c >= 'A') && (c <= 'Z')) 
	{
		return (c - 'A' + 10);
	}
	if ((c >= 'a') && (c <= 'z')) 
	{
		return (c - 'a' + 10);
	}
	return (-1);
}

/*====================================================================*
 *
 *   omemory::omemory ();
 *   
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

omemory::omemory () 

{
	return;
}

/*====================================================================*
 *
 *   ~omemory();
 *
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

omemory::~omemory () 

{
	return;
}

/*====================================================================*
 *   end definition;
 *--------------------------------------------------------------------*/

#endif

