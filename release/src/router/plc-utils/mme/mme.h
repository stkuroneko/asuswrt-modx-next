/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   mme.h -
 *
 *   message header definitions and function declarations;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Matthieu Poullet <m.poullet@avm.de>
 *
 *--------------------------------------------------------------------*/

#ifndef MME_HEADER
#define MME_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../ether/ether.h"
#include "../ether/channel.h"
#include "../mme/homeplug.h"
#include "../mme/qualcomm.h"

/*====================================================================*
 *   manage cross-platform structure packing;
 *--------------------------------------------------------------------*/

#ifndef __packed
#ifdef __GNUC__
#define __packed __attribute__ ((packed))
#else
#define __packed
#endif
#endif

/*====================================================================*
 *   Ethernet, HomePlug and Qualcomm Frame headers;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push, 1)
#endif

typedef struct __packed ethernet_hdr 

{ 
	uint8_t ODA [ETHER_ADDR_LEN]; 
	uint8_t OSA [ETHER_ADDR_LEN]; 
	uint16_t MTYPE; 
} 

ethernet_hdr; 
typedef struct __packed homeplug_hdr 

{ 
	uint8_t MMV; 
	uint16_t MMTYPE; 
} 

homeplug_hdr; 
typedef struct __packed homeplug_fmi 

{ 
	uint8_t MMV; 
	uint16_t MMTYPE; 

#if 0 

	uint8_t FMID; 
	uint8_t FMSN; 

#else

	uint8_t FMSN; 
	uint8_t FMID; 

#endif

} 

homeplug_fmi; 
typedef struct __packed fragment_hdr 

{ 
	uint8_t OUI [ETHER_ADDR_LEN >> 1]; 
	uint8_t MME_STATUS; 
	uint8_t RESERVED; 
	uint16_t MME_LENGTH; 
} 

fragment_hdr; 
typedef struct __packed qualcomm_hdr 

{ 
	uint8_t MMV; 
	uint16_t MMTYPE; 
	uint8_t OUI [ETHER_ADDR_LEN >> 1]; 
} 

qualcomm_hdr; 
typedef struct __packed qualcomm_fmi 

{ 
	uint8_t MMV; 
	uint16_t MMTYPE; 

#if 0 

	uint8_t FMID; 
	uint8_t FMSN; 

#else

	uint8_t FMSN; 
	uint8_t FMID; 

#endif

	uint8_t OUI [ETHER_ADDR_LEN >> 1]; 
} 

qualcomm_fmi; 

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*=*
 * preserve legacy structure definitions;
 *-*/

typedef ethernet_hdr ethernet_std;
typedef homeplug_hdr homeplug_std;
typedef qualcomm_hdr qualcomm_std;

/*====================================================================*
 *   Composite message formats;
 *--------------------------------------------------------------------*/

#ifndef __GNUC__
#pragma pack (push, 1)
#endif

typedef struct __packed message 

{ 
	struct ethernet_hdr ethernet; 
	uint8_t content [ETHERMTU]; 
} 

MESSAGE; 

typedef struct __packed homeplug1

{ 
	struct ethernet_hdr ethernet; 
	struct homeplug_fmi homeplug; 
	uint8_t content [ETHERMTU - sizeof (struct homeplug_fmi)]; 
} 

HOMEPLUG;

typedef struct __packed qualcomm1

{ 
	struct ethernet_hdr ethernet; 
	struct qualcomm_fmi qualcomm; 
	uint8_t content [ETHERMTU - sizeof (struct qualcomm_fmi)]; 
} 

QUALCOMM; 

#ifndef __GNUC__
#pragma pack (pop)
#endif

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

void MMESize (void); 
void MMEPeek (void const * memory, size_t extent, FILE *); 
void MMEShow (void const * memory, size_t extent, FILE *); 
void ARPCPeek (void const * memory, size_t extent, FILE *); 
void ARPCWrite (FILE *, void const * memory, size_t extent); 
void ARPCPrint (FILE *, void const * memory, size_t extent); 

/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

char const * MMEName (uint16_t MMTYPE); 
char const * MMEMode (uint16_t MMTYPE); 
char const * MMECode (uint16_t MMTYPE, uint8_t MSTATUS); 
void MMETest (void); 

/*====================================================================*
 *   header encode functions;
 *--------------------------------------------------------------------*/

signed EthernetHeader (void * memory, const uint8_t peer [], const uint8_t host [], uint16_t protocol); 
signed HomePlugHeader (struct homeplug_hdr *, uint8_t MMV, uint16_t MMTYPE); 
signed QualcommHeader (struct qualcomm_hdr *, uint8_t MMV, uint16_t MMTYPE); 
signed HomePlugHeader1 (struct homeplug_fmi *, uint8_t MMV, uint16_t MMTYPE); 
signed QualcommHeader1 (struct qualcomm_fmi *, uint8_t MMV, uint16_t MMTYPE); 

/*====================================================================*
 *   header decode functions;
 *--------------------------------------------------------------------*/

signed UnwantedMessage (void const * memory, size_t extent, uint8_t MMV, uint16_t MMTYPE); 
signed FirmwareMessage (void const * memory); 

/*====================================================================*
 *   intermmediate level Ethernet send/receive functions;
 *--------------------------------------------------------------------*/

ssize_t sendmessage (struct channel const *, struct message *, ssize_t length); 
ssize_t readmessage (struct channel const *, struct message *, uint8_t MMV, uint16_t MMTYPE); 

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



