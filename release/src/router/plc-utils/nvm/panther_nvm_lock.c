/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void panther_nvm_lock (struct panther_nvm_header * header);
 *
 *   example function to update a panther/lynx NVM image header 
 *   after the image has been modified; this assumes that image 
 *   immediately follows the header in memory; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PANTHER_NVM_LOCK_SOURCE
#define PANTHER_NVM_LOCK_SOURCE

#include "../tools/memory.h"
#include "../nvm/nvm.h"

void panther_nvm_lock (struct panther_nvm_header * header) 

{ 
	header->ImageChecksum = checksum32 ((char *) (header) +  sizeof (* header), LE32TOH (header->ImageLength), 0); 
	header->HeaderChecksum = checksum32 (header, sizeof (* header), header->HeaderChecksum); 
	return; 
} 

#endif



