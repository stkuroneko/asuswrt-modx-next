/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   tlv.h - type-length-value struct definitions and declarations;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef TLV_HEADER
#define TLV_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/types.h"
#include "../tools/endian.h"
#include "../tools/memory.h"

/*====================================================================*
 *   macros;
 *--------------------------------------------------------------------*/

#define TLVSPAN(node) (sizeof(*(node))-sizeof((node)->data)+LE32TOH((node)->size)) 
#define TLVDUMP(node) hexdump(&(node)->data,0,(node)->size,stderr) 

/*====================================================================*
 *   variables;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push,1)
#endif

typedef struct __packed TLVNode 

{ 
	uint32_t type; 
	uint32_t size; 
	uint32_t data; 
} 

TLVNode; 

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#endif



