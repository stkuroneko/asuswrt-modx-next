/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void nvmpeek (void const * memory);
 *
 *   nvm.h
 *
 *   assume memory points to a Qualcomm Atheros .nvm file header and
 *   call the appropriate function to display it based on the header
 *   version number;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NVMPEEK_SOURCE
#define NVMPEEK_SOURCE

#include "../tools/memory.h"
#include "../nvm/nvm.h"

void nvmpeek (void const * memory) 

{ 
	if (LE32TOH (* (uint32_t *) (memory)) == 0x60000000) 
	{ 
		lightning_nvm_peek (memory); 
		return; 
	} 
	panther_nvm_peek (memory); 
	return; 
} 

#endif



