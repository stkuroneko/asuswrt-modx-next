/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   sdram.h - SDRAM definitions and declarations;
 *
 *   the first section if an NVM file contains SDRAM parameters used
 *   by the bootloader;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef SDRAM_HEADER
#define SDRAM_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/types.h"
#include "../tools/flags.h"

/*====================================================================*
 *   constants; 
 *--------------------------------------------------------------------*/

#define SDRAM_SILENCE (1 << 0)
#define SDRAM_VERBOSE (1 << 1)
#define SDRAM_BASENAME (1 << 2)

/*====================================================================*
 *   variables; 
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

typedef struct __packed config_ram 

{ 
	uint32_t SDRAMSIZE; 
	uint32_t SDRAMCONF; 
	uint32_t SDRAMTIM0; 
	uint32_t SDRAMTIM1; 
	uint32_t SDRAMCNTRL; 
	uint32_t SDRAMREF; 
	uint32_t MACCLOCK; 
	uint32_t SDRAMRSVD; 
} 

config_ram; 

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

void sdrampeek (struct config_ram * config_ram); 
void sdramtext (struct config_ram * config_ram); 
int sdramfile (int fd, char const * title, flag_t flags); 
int sdramfileA (int fd, char const * title, flag_t flags); 

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#endif



