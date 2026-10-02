/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void ARPCPrint (FILE * fp, void const * memory, size_t extent);
 *
 *   mme.h
 *
 *   print formatted VS_ARPC payload on the specified output stream;
 *   this implementation is generic; memory is the start address of
 *   the message data (&RDATA [RDATAOFFSET]) and extent is the data 
 *   length (RDATALENGTH); the call might look like this ...
 *
 *   ARPCPrint (fp, &ARPC->RDATA [ARPC->RDATAOFFSET], LE16TOH (ARPC->RDATALENGTH) - ARPC->RDATAOFFSET);
 *
 *   ... where LE16TOH () performs 16-bit host endian conversion;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *	Florian Fainelli <f.fainelli@gmail.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ARPCPRINT_SOURCE
#define ARPCPRINT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>

#include "../tools/types.h"
#include "../tools/endian.h"
#include "../tools/memory.h"
#include "../mme/mme.h"

#if defined (WIN32)
#define TIMEVALUE "%012ld.%06ld"
#elif defined (__APPLE__)
#define TIMEVALUE "%012lu.%06u"
#elif defined (__linux__)
#define TIMEVALUE "%012ld.%06ld"
#elif defined (__OpenBSD__)
#define TIMEVALUE "%012ld.%06ld"
#else
#error "Unknown environment"
#endif

//#define ENABLE_DEBUGPRINT

void PrintArpcMessage (FILE * fp, const char * apFormat, const uint32_t * apArgumentList, uint32_t aArgumentCount)

{
	char MessageBuffer [2049];
	uint32_t MsgIndex;
	char GPBuffer [128];
	uint32_t Len;
	uint32_t Index;
	MsgIndex = 0;
	memset (MessageBuffer, 0, sizeof (MessageBuffer));
	Len = strlen (apFormat);
	Index = 0;
	while (apFormat [Index] && Len > 0)
	{
		if (apFormat [Index] != '%')
		{
			MessageBuffer [MsgIndex] = apFormat [Index];
			MsgIndex++;
			Index++;
			Len--;
		}
		else if (apFormat [Index + 1] == '%')
		{
			MessageBuffer [MsgIndex] = apFormat [Index];
			MsgIndex++;
			Index += 2;
			Len -= 2;
		}
		else if (apFormat [Index + 1] == '\0')
		{
			MessageBuffer [MsgIndex] = apFormat [Index];
			MsgIndex++;
			Index += 2;
			Len -= 2;
		}
		else 
		{
			uint32_t iArg = 0;
			char const * pArg = & apFormat [Index];
			while (pArg && * pArg)
			{
				switch (* pArg)
				{
				case 'c':
				case 'C':
					{
						GPBuffer [iArg] = 'c';
						GPBuffer [iArg + 1] = '\0';
						pArg = NULL;
						snprintf (& MessageBuffer [MsgIndex], sizeof (MessageBuffer) - (MsgIndex -1), GPBuffer, * apArgumentList);
						MsgIndex++;
						apArgumentList++;
						Index++;
					}
					break;
				case 'd':
				case 'D':
					{
						char Buf [24];
						GPBuffer [iArg] = 'd';
						GPBuffer [iArg + 1] = '\0';
						pArg = NULL;
						(void) snprintf (Buf, sizeof (Buf) -1, GPBuffer, * apArgumentList);
						strncat (& MessageBuffer [MsgIndex], Buf, sizeof (MessageBuffer) - (MsgIndex -1));
						(void) snprintf (& MessageBuffer [MsgIndex], sizeof (MessageBuffer) - (MsgIndex -1), "%s", Buf);
						MsgIndex += strlen (Buf);
						apArgumentList++;
						Index++;
					}
					break;
				case 'x':
				case 'X':
					{
						char Buf [24];
						GPBuffer [iArg] = 'x';
						GPBuffer [iArg + 1] = '\0';
						pArg = NULL;
						(void) snprintf (Buf, sizeof (Buf) -1, GPBuffer, * apArgumentList);
						strncat (& MessageBuffer [MsgIndex], Buf, sizeof (MessageBuffer) - (MsgIndex -1));
						(void) snprintf (& MessageBuffer [MsgIndex], sizeof (MessageBuffer) - (MsgIndex -1), "%s", Buf);
						MsgIndex += strlen (Buf);
						apArgumentList++;
						Index++;
					}
					break;
				default: 
					GPBuffer [iArg] = * pArg;
					iArg++;
					pArg++;
					Index++;

// pArg = &apFormat[Index];

				}
			}

//MessageBuffer[MsgIndex] = apFormat[Index];
//MsgIndex++;
//Index++;
//Len--;

		}
	}
	fprintf (fp, "%s", (char const *) (MessageBuffer));
}

void ARPCPrint (FILE * fp, void const * memory, size_t extent)

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
	}
	* vpArpcPrintData;
	typedef uint32_t uint32_packed_t;
	uint32_packed_t * vpWordPointer;
	uint16_t vOffsetInBytesOfArgumentList;
	uint16_t vLengthInBytesOfArgumentList;
	uint16_t vOffsetInBytesOfFormatString;

#ifdef ENABLE_DEBUGPRINT

	uint16_t vLengthInBytesOfFormatString;

#endif

	uint16_t argc;

#ifndef __GNUC__
#pragma pack (pop)
#endif

#ifdef ENABLE_DEBUGPRINT

	fprintf (fp, "BYPASS=%d ", LE32TOH (data->BYPASS));
	fprintf (fp, "ARPCID=%d ", LE16TOH (data->ARPCID));
	fprintf (fp, "DATALENGTH=%d ", LE16TOH (data->DATALENGTH));
	fprintf (fp, "DATAOFFSET=%d ", data->DATAOFFSET);
	fprintf (fp, "ARPCSEQNUM=%d ", LE16TOH (data->ARPCSEQNUM));

#endif

	char * vpBytePointer = (char *) data;
	vpBytePointer += sizeof (struct vs_arpc_data);
	vpBytePointer += data->DATAOFFSET;
	vpArpcPrintData = (struct vs_arpc_print_data *) vpBytePointer;

#ifdef ENABLE_DEBUGPRINT

	fprintf (fp, "vpArpcPrintData=%.8x ", (uint32_t) vpArpcPrintData);

#endif

	vOffsetInBytesOfArgumentList = LE16TOH (vpArpcPrintData->ARGOFFSET);
	vOffsetInBytesOfFormatString = LE16TOH (vpArpcPrintData->STROFFSET);
	vLengthInBytesOfArgumentList = LE16TOH (vpArpcPrintData->ARGLENGTH);
	argc = (vLengthInBytesOfArgumentList >> 2);

#ifdef ENABLE_DEBUGPRINT

	vLengthInBytesOfFormatString = LE16TOH (vpArpcPrintData->STRLENGTH);
	fprintf (fp, "ARGOFFSET=%d ", vOffsetInBytesOfArgumentList);
	fprintf (fp, "STROFFSET=%d ", vOffsetInBytesOfFormatString);
	fprintf (fp, "ARGLENGTH=%d ", vLengthInBytesOfArgumentList);
	fprintf (fp, "STRLENGTH=%d ", vLengthInBytesOfFormatString);

#endif

	vpBytePointer = (char *) vpArpcPrintData;
	vpBytePointer += sizeof (struct vs_arpc_print_data);
	vpBytePointer += vOffsetInBytesOfArgumentList;
	vpWordPointer = (uint32_packed_t *) vpBytePointer;

#ifdef ENABLE_DEBUGPRINT

	fprintf (fp, "vpWordPointer=%.8x ", (uint32_t) vpWordPointer);

#endif

	vpBytePointer = (char *) vpArpcPrintData;
	vpBytePointer += sizeof (struct vs_arpc_print_data);
	vpBytePointer += vOffsetInBytesOfFormatString;

#ifdef ENABLE_DEBUGPRINT

	fprintf (fp, "vpBytePointer=%.8x %d\n", (uint32_t) vpBytePointer, vpBytePointer [vLengthInBytesOfFormatString]);

#endif

	if (argc == 0)
	{
		fprintf (fp, "%s", (char const *) (vpBytePointer));
	}
	else 
	{
		uint32_t * argp = (uint32_t *) malloc (sizeof (uint32_t) * argc);
		if (argp == 0)
		{
			fprintf (fp, "ARPCPrint out of memory ");
		}
		else 
		{
			uint16_t i;
			for (i = 0; i < argc; i++)
			{
				argp [i] = LE32TOH (* vpWordPointer);
				vpWordPointer++;

#ifdef ENABLE_DEBUGPRINT

				fprintf (fp, "argp[i]=%.8x i=%d vpWordPointer=%.8x\n", argp [i], i, (uint32_t) vpWordPointer);

#endif

			}

#ifdef ENABLE_DEBUGPRINT

			fprintf (fp, "argument copy returns\n");

#endif

//there is no easy way to construct va_list across different platform

			PrintArpcMessage (fp, vpBytePointer, argp, argc);

#ifdef ENABLE_DEBUGPRINT

			fprintf (fp, "vfprintf returns\n");

#endif

		}
	}
	fprintf (fp, "\n");
	fflush (fp);
	return;
}

#endif



