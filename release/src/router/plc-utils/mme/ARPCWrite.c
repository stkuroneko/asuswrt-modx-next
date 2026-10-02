/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void ARPCWrite (FILE * fp, void const * memory, size_t extent);
 *
 *   mme.h
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ARPCWRITE_SOURCE
#define ARPCWRITE_SOURCE

#include <stdio.h>

#include "../tools/memory.h"
#include "../mme/mme.h"

void ARPCWrite (FILE * fp, void const * memory, size_t extent) 

{ 
	uint16_t length = (uint16_t) (extent); 
	if (isatty (fileno (fp))) 
	{ 
		hexwrite (fileno (fp), & length, sizeof (length)); 
		hexwrite (fileno (fp), memory, length); 

#if defined (_WIN32)

		fputc ('\r', fp); 

#endif

		fputc ('\n', fp); 
	} 
	else 
	{ 
		fwrite (& length, sizeof (length), 1, fp); 
		fwrite (memory, length, 1, fp); 
	} 
	fflush (fp); 
	return; 
} 

#endif



