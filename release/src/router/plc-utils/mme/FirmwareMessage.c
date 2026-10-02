/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed FirmwareMessage (void const * memory);
 *
 *   mme.h
 *
 *   intercept and print Qualcomm Atheros vendor-specific VS_ARPC 
 *   messages on stdout; this message type is used for diagnostic 
 *   reporting and should not appear in released firmware;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FIRMWAREMESSAGE_SOURCE
#define FIRMWAREMESSAGE_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../plc/plc.h"
#include "../tools/memory.h" 
#include "../tools/endian.h" 
#include "../mme/mme.h"

signed FirmwareMessage (void const * memory) 

{ 
	const struct message * message = (const struct message *) (memory); 

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	static struct qualcomm_hdr header_arpc = 
	{ 
		0, 
		0, 
		{ 
			0x00, 
			0xB0, 
			0x52
		} 
	}; 
	struct __packed vs_arpc_indicate 
	{ 
		struct ethernet_hdr ethernet; 
		struct qualcomm_hdr qualcomm; 
		uint16_t RDATALENGTH; 
		uint8_t RDATAOFFSET; 
		uint8_t RDATA [1]; 
	} 
	* indicate = (struct vs_arpc_indicate *) (message); 

#ifndef __GNUC__
#pragma pack (pop)
#endif

	header_arpc.MMTYPE = HTOLE16 (VS_ARPC | MMTYPE_IND); 
	if (! memcmp (& indicate->qualcomm, & header_arpc, sizeof (header_arpc))) 
	{ 
		ARPCPrint (stderr, & indicate->RDATA [indicate->RDATAOFFSET], LE16TOH (indicate->RDATALENGTH) - indicate->RDATAOFFSET); 
		return (- 1); 
	} 
	return (0); 
} 

#endif



