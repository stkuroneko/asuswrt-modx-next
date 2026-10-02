/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void MMEShow (void const * memory, size_t length, FILE *fp);
 *
 *   mme.h
 *   
 *   print a HomePlug AV frame header on stdout in human readable 
 *   format;
 *
 *   
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MMESHOW_SOURCE
#define MMESHOW_SOURCE

#include <stdio.h>
#include <stdint.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../mme/mme.h"

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6 /* normally defined in ethernet.h or if_ether.h */
#endif

void MMEShow (void const * memory, size_t extent, FILE * fp) 

{ 
	char address [ETHER_ADDR_LEN * 3]; 
	struct message * message = (struct message *) (memory); 
	fprintf (fp, "%s ", hexstream (address, sizeof (address), message->ethernet.ODA, sizeof (message->ethernet.ODA))); 
	fprintf (fp, "%s ", hexstream (address, sizeof (address), message->ethernet.OSA, sizeof (message->ethernet.OSA))); 
	fprintf (fp, "%04X ", ntohs (message->ethernet.MTYPE)); 
	if (ntohs (message->ethernet.MTYPE) == ETH_P_HPAV) 
	{ 
		struct homeplug_hdr * homeplug = (struct homeplug_hdr *) (& message->content); 
		uint16_t mmtype = LE16TOH (homeplug->MMTYPE); 
		if (mmtype < MMTYPE_VS) 
		{ 
			if (homeplug->MMV == 0x00) 
			{ 
				struct homeplug_hdr * homeplug = (struct homeplug_hdr *) (& message->content); 
				mmtype = LE16TOH (homeplug->MMTYPE); 
				fprintf (fp, "%02X ", homeplug->MMV); 
				fprintf (fp, "%04X ", mmtype); 
				fprintf (fp, "%s.%s\n", MMEName (mmtype), MMEMode (mmtype)); 
				return; 
			} 
			if (homeplug->MMV == 0x01) 
			{ 
				struct homeplug_fmi * homeplug = (struct homeplug_fmi *) (& message->content); 
				mmtype = LE16TOH (homeplug->MMTYPE); 
				fprintf (fp, "%02X ", homeplug->MMV); 
				fprintf (fp, "%04X ", mmtype); 
				fprintf (fp, "%02X ", homeplug->FMID); 
				fprintf (fp, "%02X ", homeplug->FMSN); 
				fprintf (fp, "%s.%s\n", MMEName (mmtype), MMEMode (mmtype)); 
				return; 
			} 
		} 
		if (mmtype < MMTYPE_XX) 
		{ 
			if (homeplug->MMV == 0x00) 
			{ 
				struct qualcomm_hdr * qualcomm = (struct qualcomm_hdr *) (& message->content); 
				mmtype = LE16TOH (qualcomm->MMTYPE); 
				fprintf (fp, "%02X ", qualcomm->MMV); 
				fprintf (fp, "%04X ", mmtype); 
				fprintf (fp, "%s ", hexstring (address, sizeof (address), qualcomm->OUI, sizeof (qualcomm->OUI))); 
				fprintf (fp, "%s.%s\n", MMEName (mmtype), MMEMode (mmtype)); 
				return; 
			} 
			if (homeplug->MMV == 0x01) 
			{ 
				struct qualcomm_fmi * qualcomm = (struct qualcomm_fmi *) (& message->content); 
				mmtype = LE16TOH (qualcomm->MMTYPE); 
				fprintf (fp, "%02X ", qualcomm->MMV); 
				fprintf (fp, "%04X ", mmtype); 
				fprintf (fp, "%02X ", qualcomm->FMID); 
				fprintf (fp, "%02X ", qualcomm->FMSN); 
				fprintf (fp, "%s ", hexstring (address, sizeof (address), qualcomm->OUI, sizeof (qualcomm->OUI))); 
				fprintf (fp, "%s.%s\n", MMEName (mmtype), MMEMode (mmtype)); 
				return; 
			} 
		} 
	} 
	fprintf (fp, "UNKNOWN_MESSAGE_TYPE\n"); 
	return; 
} 

#endif



