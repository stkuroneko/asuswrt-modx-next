/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   unsigned ARPCPeek (void const * memory, size_t extent, FILE * fp);
 *
 *   mme.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <unistd.h>

#include "../tools/types.h"
#include "../tools/endian.h"
#include "../mme/mme.h"

//#define ENABLE_DEBUGPRINT
void ARPCPeek (void const * memory, size_t extent, FILE * fp) 

{ 

#ifndef __GNUC__
#pragma pack (push,1)
#endif

	struct __packed vs_arpc_data 
	{ 
		uint32_t BYPASS; 
		uint16_t ARPCID; 
		uint16_t DATALENGTH; 
		uint8_t DATAOFFSET; 
		uint8_t RESERVED; 
		uint16_t ARPCSEQNUM; 
	} 
	* data = (struct vs_arpc_data *) (memory); 
	struct __packed vs_arpc_print_data 
	{ 
		uint16_t ARGOFFSET; 
		uint16_t STROFFSET; 
		uint16_t ARGLENGTH; 
		uint16_t STRLENGTH; 
	} *vpArpcPrintData;
#ifndef __GNUC__
#pragma pack (pop)
#endif

	fprintf (fp, "BYPASS=%d ", LE32TOH (data->BYPASS)); 
	fprintf (fp, "ARPCID=%d ", LE16TOH (data->ARPCID)); 
	fprintf (fp, "DATALENGTH=%d ", LE16TOH (data->DATALENGTH)); 
	fprintf (fp, "DATAOFFSET=%d ", data->DATAOFFSET); 
	fprintf (fp, "ARPCSEQNUM=%d ", LE16TOH (data->ARPCSEQNUM));

	char *vpBytePointer = (char *)data;
	vpBytePointer += sizeof(struct vs_arpc_data);
	vpBytePointer += data->DATAOFFSET;

	vpArpcPrintData = (struct vs_arpc_print_data *)vpBytePointer; 
	#ifdef ENABLE_DEBUGPRINT
		fprintf (fp, "vpArpcPrintData=%.8x ", (uint32_t)vpArpcPrintData); 
	#endif

	uint16_t vOffsetInBytesOfArgumentList = LE16TOH (vpArpcPrintData->ARGOFFSET); 
	uint16_t vOffsetInBytesOfFormatString = LE16TOH (vpArpcPrintData->STROFFSET);
	uint16_t vLengthInBytesOfArgumentList = LE16TOH (vpArpcPrintData->ARGLENGTH);
	uint16_t vLengthInBytesOfFormatString = LE16TOH (vpArpcPrintData->STRLENGTH);

	fprintf (fp, "ARGOFFSET=%d ", vOffsetInBytesOfArgumentList); 
	fprintf (fp, "STROFFSET=%d ", vOffsetInBytesOfFormatString); 
	fprintf (fp, "ARGLENGTH=%d ", vLengthInBytesOfArgumentList); 
	fprintf (fp, "STRLENGTH=%d ", vLengthInBytesOfFormatString); 

	vpBytePointer = (char *)vpArpcPrintData;
	vpBytePointer += sizeof(struct vs_arpc_print_data);
	vpBytePointer += vOffsetInBytesOfFormatString;
	#ifdef ENABLE_DEBUGPRINT
		fprintf (fp, "vpBytePointer=%.8x %d\n", (uint32_t)vpBytePointer, vpBytePointer[vLengthInBytesOfFormatString]); 
	#endif

	if (data->ARPCID == 1) 
	{ 
		fprintf (fp, "FORMAT=[%s]\n", vpBytePointer); 
	} 
	return; 
} 

