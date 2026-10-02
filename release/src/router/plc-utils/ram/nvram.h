/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   nvnvm.h - nvram definitions and declarations;
 *
 *   The Boot ROM reads a linked list of NVM headers containing 
 *   information about the size, location and execution address 
 *   of various software images;
 *
 *   See INT6300 Boot ROM Software Design Specification for more 
 *   information; the document may not be available to some
 *   customers so don't push it;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NVRAM_HEADER
#define NVRAM_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/types.h"

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define NVRAM_500KB         0x00000005
#define NVRAM_1MB           0x00000010
#define NVRAM_2MB           0x00000011
#define NVRAM_4MB           0x00000012
#define NVRAM_8MB           0x00000013
#define NVRAM_16MB          0x00000014
#define NVRAM_32MB          0x00000015

#define NVRAM_M25P20 =      0x00000011;
#define NVRAM_M25P40 =      0x00000012;
#define NVRAM_M25P80 =      0x00000013;
#define NVRAM_M25P16_ES =   0x00000014;
#define NVRAM_M25P32_ES =   0x00000015;
#define NVRAM_M25P64_ES =   0x00000016;
#define NVRAM_AT26DF161 =   0x00000046;
#define NVRAM_AT26DF161A =  0x00000146;
#define NVRAM_M25P05A =     0x00001020;
#define NVRAM_M25P10A =     0x00001120;
#define NVRAM_M25P16 =      0x00001520;
#define NVRAM_M25PX16 =     0x00001571;
#define NVRAM_M25P32 =      0x00001620;
#define NVRAM_M25P64 =      0x00001720;
#define NVRAM_FM25S16 =     0x00001532;
#define NVRAM_FM25Q16 =     0x00001532;
#define NVRAM_FM25Q32 =     0x00001632;
#define NVRAM_SST25VF016B = 0x00004125;

/*====================================================================*
 *   variables; 
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

typedef struct __packed config_nvram 

{ 
	uint32_t NVRAMTYPE; 
	uint32_t NVRAMPAGE; 
	uint32_t NVRAMBLOCK; 
	uint32_t NVRAMSIZE; 
} 

config_nvram; 

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

void nvrampeek (struct config_nvram *); 
char const * NVRAMName (uint16_t nvramtype); 

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#endif



