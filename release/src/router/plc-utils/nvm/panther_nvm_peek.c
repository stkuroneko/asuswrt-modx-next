/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void panther_nvm_peek (void const * memory);
 *
 *   print a memory resident firmware image header on stdout;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PANTHER_NVM_PEEK_SOURCE
#define PANTHER_NVM_PEEK_SOURCE

#include <stdio.h>

#include "../tools/memory.h"
#include "../tools/format.h"
#include "../nvm/nvm.h"

void panther_nvm_peek (void const * memory) 

{ 
	extern char const * nvm_imagetypes []; 
	extern char const * nvm_platforms []; 
	struct panther_nvm_header * header = (struct panther_nvm_header *) (memory); 
	char const * string = "Unknown"; 
	char platform [100]; 
	printf ("\tHeader Version = 0x%04x-0x%04x\n", LE16TOH (header->MajorVersion), header->MinorVersion); 
	printf ("\tHeader Checksum = 0x%08X\n", LE32TOH (header->HeaderChecksum)); 
	printf ("\tHeader Next = 0x%08X\n", LE32TOH (header->NextHeader)); 
	printf ("\tHeader Prev = 0x%08X\n", LE32TOH (header->PrevHeader)); 
	printf ("\tFlash Address = 0x%08X\n", LE32TOH (header->ImageNvmAddress)); 
	printf ("\tImage Address = 0x%08X\n", LE32TOH (header->ImageAddress)); 
	printf ("\tEntry Address = 0x%08X\n", LE32TOH (header->EntryPoint)); 
	printf ("\tEntry Version = 0x%04X\n", LE16TOH (header->AppletEntryVersion)); 
	printf ("\tImage Checksum = 0x%08X\n", LE32TOH (header->ImageChecksum)); 
	printf ("\tImage ModuleID = 0x%04X\n", LE32TOH (header->ModuleID)); 
	printf ("\tImage ModuleSubID = 0x%04X\n", LE32TOH (header->ModuleSubID)); 
	printf ("\tImage Size = 0x%08X (%d)\n", LE32TOH (header->ImageLength), LE32TOH (header->ImageLength)); 
	if (LE32TOH (header->ImageType) < NVM_IMAGETYPES) 
	{ 
		string = nvm_imagetypes [LE32TOH (header->ImageType)]; 
	} 
	printf ("\tImage Type = %s\n", string); 
	strfbits (platform, sizeof (platform), nvm_platforms, "|", LE16TOH (header->ExecuteMask)); 
	printf ("\tImage Exec = %s\n", platform); 

#if 0

	printf ("\tReserved = 0x%04X\n", LE16TOH (header->Reserved0)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved1)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved2)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved3)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved4)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved5)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved6)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved7)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved8)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved9)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved10)); 
	printf ("\tReserved = 0x%08X\n", LE32TOH (header->Reserved11)); 

#endif

	return; 
} 

#endif



