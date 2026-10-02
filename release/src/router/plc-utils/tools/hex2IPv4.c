/*====================================================================*
 *	Copyright (c) 2020 Qualcomm Technologies, Inc.
 *	All Rights Reserved.
 *	Confidential and Proprietary - Qualcomm Technologies, Inc.
 *====================================================================*/
/*====================================================================*
 *   Motley Tools by Charles Maier <cmaier@cmassoc.net>;
 *   Copyright (c) 2001-2006 by Charles Maier Associates;
 *   Licensed under the Internet Software Consortium License;
 *====================================================================*/

/*====================================================================*
 *
 *   char const * hex2IPv4 (char buffer [], size_t length, void const * memory, size_t extent);
 *
 *   memory.h
 *
 *   encode a character buffer with a decimal equivalent of hexadecimal character string
 *   having decimals seperated by DEC_EXTENDER, defined in number.h;
 *
 *--------------------------------------------------------------------*/

#ifndef HEX2IPv4_SOURCE
#define HEX2IPv4_SOURCE

#include <stdint.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../nvm/nvm.h"

unsigned digitcount(unsigned num)
{
	unsigned dec, count;
	dec = num;
	count = 0;
	while(dec != 0)
	{
		dec = dec / RADIX_DEC;
		count++;
	}
	return count;
}

/*====================================================================*
 *
 *   char * myitoa_nonulltermination (unsigned number, char buffer [], size_t length);
 *
 *   non-standard version of itoa () with no null termination where 
 *   buffer is packed right-to-left to avoid reversing digits; ensure 
 *   buffer is longer than needed;
 *
 *--------------------------------------------------------------------*/

char * myitoa_nonulltermination (unsigned number, char buffer [], size_t length) 

{ 
	do 
	{ 
		buffer [-- length] = '0' +  (number % 10); 
		number /= 10; 
	} 
	while (number); 
	return (buffer); 
} 

char const * hex2IPv4 (char buffer [], register size_t length, void const * memory, register size_t extent) 
{ 
	register char * string = (char *) (buffer); 
	register byte * offset = (byte *) (memory);
	unsigned num, numlength;
	
	if (length) 
	{ 
		length /= HEX_DIGITS +  1;
		while ((length--) && (extent--)) 
		{ 
			num = 0;
			num += (int)((* offset >> 0) & 0x0F);
			num += ((int)((* offset >> 4) & 0x0F)) * RADIX_HEX;

			numlength = digitcount(num);
			myitoa_nonulltermination(num, string, numlength);
			string += numlength;

			if ((length) && (extent)) 
			{ 
				* string++ = DEC_EXTENDER; 
			} 
			offset++; 
		} 
		* string = (char) (0); 
	}

	 return ((char *) (buffer));
}

#endif



