/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed QualcommHeader1 (struct qualcomm_fmi * header, uint8_t MMV, uint16_t MMTYPE, uint16_tFMI);
 *
 *   mme.h 
 *
 *   Encode memory with an Atheros vendor specific message header 
 *   having HomePlug message protocol version (INTELLON_MMV) and 
 *   Atheros message type (MMTYPE);
 *
 *   return the number of bytes actually encoded or 0 on encode error; 
 *   the error code is stored in errno;
 *
 *   see the INT6000 Firmware Technical Reference Manual for more
 *   about MME headers and message types; the Atheros OUI is 
 *   implicit in this function;
 *
 *   MMV is the version number of the MME command set; currently, 
 *   there is only one command set for Atheros MMEs; 
 *
 *   MMTYPE indicates the desired Atheros device operation taken
 *   from the TRM; some operations are undocumented and should not
 *   be used;
 *
 *   OUI is the Organizationally Unique Identifier resgistered with
 *   the IEEE by the vendor and is a constant for Atheros Devices; 
 *
 *   There is no need to flush the header since this function writes
 *   to all locations unless there is an error; the caller may elect
 *   to flush the buffer before calling this function;
 *
 *   Contributor(s): 
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef QUALCOMMHEADER1_SOURCE
#define QUALCOMMHEADER1_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/endian.h"
#include "../mme/mme.h"

signed QualcommHeader1 (struct qualcomm_fmi * header, uint8_t MMV, uint16_t MMTYPE) 

{ 
	header->MMV = MMV; 
	header->MMTYPE = HTOLE16 (MMTYPE); 
	header->FMSN = 0; 
	header->FMID = 0; 
	header->OUI [0] = 0x00; 
	header->OUI [1] = 0xB0; 
	header->OUI [2] = 0x52; 
	return (sizeof (* header)); 
} 

#endif



