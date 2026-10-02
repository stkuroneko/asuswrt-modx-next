/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void nvrampeek(struct config_nvram * config_nvram);
 *
 *   nvram.h
 *   
 *   print an nvram configuration block; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NVRAMPEEK_SOURCE
#define NVRAMPEEK_SOURCE

#include <stdio.h>

#include "../ram/nvram.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"

void nvrampeek (struct config_nvram * config_nvram) 

{ 
	printf ("TYPE=0x%02X ", LE32TOH (config_nvram->NVRAMTYPE)); 
	printf ("(%s) ", NVRAMName (LE32TOH (config_nvram->NVRAMTYPE))); 
	printf ("PAGE=0x%04X ", LE32TOH (config_nvram->NVRAMPAGE)); 
	printf ("BLOCK=0x%04X ", LE32TOH (config_nvram->NVRAMBLOCK)); 
	printf ("SIZE=0x%04X ", LE32TOH (config_nvram->NVRAMSIZE)); 
	printf ("(%d) ", LE32TOH (config_nvram->NVRAMSIZE)); 
	printf ("\n"); 
	return; 
} 

#endif



