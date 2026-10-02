/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed HomePlugHeader1 (struct homeplug_fmi * header, uint8_t MMV, uint16_t MMTYPE);
 *
 *   mme.h
 *
 *   encode memory with a standard HomePlug AV header having HomePlug 
 *   protocol version (HOMEPLUG_MMV) and HomePlug message type (MMTYPE); 
 *   return the number of bytes actually encoded;
 *
 *   Contributor(s): 
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef HOMEPLUGHEADER1_SOURCE
#define HOMEPLUGHEADER1_SOURCE

#include <stdint.h>

#include "../mme/mme.h"
#include "../tools/endian.h"

signed HomePlugHeader1 (struct homeplug_fmi * header, uint8_t MMV, uint16_t MMTYPE) 

{ 
	header->MMV = MMV; 
	header->MMTYPE = HTOLE16 (MMTYPE); 
	header->FMSN = 0; 
	header->FMID = 0; 
	return (sizeof (* header)); 
} 

#endif



