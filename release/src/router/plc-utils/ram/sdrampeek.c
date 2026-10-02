/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void sdrampeek(const struct config_ram * config_ram);
 *
 *   sdram.h
 *   
 *   print SDRAM configuration on stdout in human-readable format;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SDRAMPEEK_SOURCE
#define SDRAMPEEK_SOURCE

#include <stdio.h>

#include "../ram/sdram.h"
#include "../tools/memory.h"

void sdrampeek (struct config_ram * config_ram) 

{ 
	printf ("\tSIZE=0x%08X (%dmb)\n", LE32TOH (config_ram->SDRAMSIZE), LE32TOH (config_ram->SDRAMSIZE) >> 20); 
	printf ("\tCONF=0x%08X\n", LE32TOH (config_ram->SDRAMCONF)); 
	printf ("\tTIM0=0x%08X\n", LE32TOH (config_ram->SDRAMTIM0)); 
	printf ("\tTIM1=0x%08X\n", LE32TOH (config_ram->SDRAMTIM1)); 
	printf ("\tCNTRL=0x%08X\n", LE32TOH (config_ram->SDRAMCNTRL)); 
	printf ("\tREF=0x%08X\n", LE32TOH (config_ram->SDRAMREF)); 
	printf ("\tCLOCK=0x%08X\n", LE32TOH (config_ram->MACCLOCK)); 
	return; 
} 

#endif



