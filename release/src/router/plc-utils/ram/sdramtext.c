/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void sdramtext(const struct config_ram * config_ram);
 *
 *   sdram.h
 *   
 *   print SDRAM configuration on stdout as an ASCII string; this
 *   format is suitable input for Atheros Windows Device Manager;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SDRAMTEXT_SOURCE
#define SDRAMTEXT_SOURCE

#include <stdio.h>
#include <unistd.h>

#include "../ram/sdram.h"
#include "../tools/memory.h"

void sdramtext (struct config_ram * config_ram) 

{ 
	printf ("%08X", htonl (config_ram->SDRAMSIZE)); 
	printf ("%08X", htonl (config_ram->SDRAMCONF)); 
	printf ("%08X", htonl (config_ram->SDRAMTIM0)); 
	printf ("%08X", htonl (config_ram->SDRAMTIM1)); 
	printf ("%08X", htonl (config_ram->SDRAMCNTRL)); 
	printf ("%08X", htonl (config_ram->SDRAMREF)); 
	printf ("%08X", htonl (config_ram->MACCLOCK)); 
	printf ("%08X", htonl (config_ram->SDRAMRSVD)); 
	return; 
} 

#endif



