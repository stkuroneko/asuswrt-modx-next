/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   uint16_t psread (uint16_t values [], uint16_t limit, FILE * fp);
 *
 *   pib.h
 *
 *   read a prescaler file and populate a scaler array;
 *
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#include "../tools/chars.h"
#include "../tools/error.h"
#include "../tools/number.h"
#include "../pib/pib.h"

uint16_t psread (uint16_t values [], uint16_t limit, FILE * fp) 

{ 
	uint16_t index = 0; 
	uint16_t count = 0; 
	uint32_t value = 0; 
	signed c; 
	while ((c = getc (fp)) != EOF) 
	{ 
		if (isspace (c)) 
		{ 
			do 
			{ 
				c = getc (fp); 
			} 
			while (isspace (c)); 
			continue; 
		} 
		if ((c == '#') || (c == ';')) 
		{ 
			do 
			{ 
				c = getc (fp); 
			} 
			while (nobreak (c)); 
			continue; 
		} 
		index = 0; 
		while (isdigit (c)) 
		{ 
			index *= 10; 
			index += c - '0'; 
			c = getc (fp); 
		} 
		if (index != count) 
		{ 
			error (1, ECANCELED, "Carrier %d out of order", index); 
		} 
		if (index >= limit) 
		{ 
			error (1, EOVERFLOW, "Too many prescalers"); 
		} 
		while (isblank (c)) 
		{ 
			c = getc (fp); 
		} 
		value = 0; 
		while (isxdigit (c)) 
		{ 
			value *= 16; 
			value += todigit (c); 
			c = getc (fp); 
		} 
		values [index] = value; 
		while ((c != '\n') && (c != EOF)) 
		{ 
			c = getc (fp); 
		}; 
		count++; 
	} 
	return (count); 
} 

