/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed panther_nvm_revision (void const * memory, size_t extent);
 *
 *   print the firmware revision string on stdout in human readable 
 *   format; although a revision string appears within the manifest,
 *   the format does not match that returned by the firmware with a
 *   VS_SW_VER request; this function walks the manifest and builds 
 *   a string that matches the firmware;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PANTHER_NVM_REVISION_SOURCE
#define PANTHER_NVM_REVISION_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "../tools/format.h"
#include "../tools/memory.h"
#include "../tools/endian.h"
#include "../tools/error.h"
#include "../tools/files.h"
#include "../tools/tlv.h"
#include "../nvm/nvm.h"

/*
 *   strings must appear in order of hardware types;
 */

#ifndef PANTHER_NVM_MANIFEST_SOURCE

static char const * compatibility [] = 

{ 
	"QCA7420", 
	(char const *) (0)
}; 

#endif

signed panther_nvm_revision (void const * memory, size_t extent) 

{ 
	struct 
	{ 
		char const * hardware; 
		uint32_t device_type;
		char software [4]; 
		uint16_t build; 
		uint32_t date; 
		char const * type; 
	} 
	revision; 
	uint8_t * offset = (uint8_t *) (memory); 
	uint32_t length = (uint32_t) (extent); 
	while (length > 0) 
	{ 
		struct TLVNode * node = (struct TLVNode *) (offset); 
		uint32_t type = LE32TOH (node->type); 
		uint32_t data = LE32TOH (node->data); 
		if (type == NVM_FIELD_HARDWARE_COMPAT) 
		{ 
			static char string [1024]; 
			strfbits (string, sizeof (string), compatibility, "|", data); 
			revision.hardware = string; 
		} 
		else if (type == NVM_FIELD_DEVICE_TYPE) 
		{ 
			revision.device_type  = data; 
		} 
		else if (type == NVM_FIELD_BUILD_MAJOR_VERSION) 
		{ 
			revision.software [0] = data; 
		} 
		else if (type == NVM_FIELD_BUILD_MINOR_VERSION) 
		{ 
			revision.software [1] = data; 
		} 
		else if (type == NVM_FIELD_BUILD_MAJOR_SUBVERSION) 
		{ 
			revision.software [2] = data; 
		} 
		else if (type == NVM_FIELD_BUILD_NUMBER) 
		{ 
			revision.build = data; 
		} 
		else if (type == NVM_FIELD_BUILD_SUSTAINING_RELEASE) 
		{ 
			revision.software [3] = data; 
		} 
		else if (type == NVM_FIELD_BUILD_DATE) 
		{ 
			revision.date = data; 
		} 
		else if (type == NVM_FIELD_BUILD_TYPE) 
		{ 
			revision.type = (char const *) (& node->data); 
		} 
		length -= TLVSPAN (node); 
		offset += TLVSPAN (node); 
	} 
	//printf ("%s-", revision.hardware); 
	printf ("%s", "QCA"); 
	printf ("%04X-", revision.device_type); 
	printf ("%d.", revision.software [0]); 
	printf ("%d.", revision.software [1]); 
	printf ("%d.", revision.software [2]); 
	printf ("%d-", revision.build); 
	printf ("%02d-", revision.software [3]); 
	printf ("%08X-", revision.date); 
	printf ("%s\n", revision.type); 
	return (0); 
} 

#endif



