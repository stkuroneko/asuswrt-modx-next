/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void lightning_nvm_peek (void const * memory);
 *
 *   print a memory resident firmware image header on stdout;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LIGHTNING_NVM_PEEK_SOURCE
#define LIGHTNING_NVM_PEEK_SOURCE

#include <stdio.h>

#include "../tools/memory.h"
#include "../tools/format.h"
#include "../nvm/nvm.h"

void lightning_nvm_peek (void const * memory) 

{ 
	extern char const * nvm_imagetypes []; 
	extern char const * nvm_platforms []; 
	struct lightning_nvm_header * header = (struct lightning_nvm_header *) (memory); 
	char const * string = "Unknown"; 
	char platform [100]; 
	printf ("\tHeader Version = 0x%08X-%02X\n", LE32TOH (header->HEADERVERSION), header->HEADERMINORVERSION); 
	printf ("\tHeader Checksum = 0x%08X\n", LE32TOH (header->HEADERCHECKSUM)); 
	printf ("\tHeader Next = 0x%08X\n", LE32TOH (header->NEXTHEADER)); 
	printf ("\tFlash Address = 0x%08X\n", LE32TOH (header->IMAGEROMADDR)); 
	printf ("\tImage Address = 0x%08X\n", LE32TOH (header->IMAGEADDRESS)); 
	printf ("\tEntry Address = 0x%08X\n", LE32TOH (header->ENTRYPOINT)); 
	printf ("\tImage Checksum = 0x%08X\n", LE32TOH (header->IMAGECHECKSUM)); 
	printf ("\tImage Size = 0x%08X (%d)\n", LE32TOH (header->IMAGELENGTH), LE32TOH (header->IMAGELENGTH)); 
	if (LE32TOH (header->IMAGETYPE) < NVM_IMAGETYPES) 
	{ 
		string = nvm_imagetypes [LE32TOH (header->IMAGETYPE)]; 
	} 
	printf ("\tImage Type = %s\n", string); 
	strfbits (platform, sizeof (platform), nvm_platforms, "|", LE16TOH (header->IGNOREMASK)); 
	printf ("\tImage Omit = %s\n", platform); 
	return; 
} 

#endif



