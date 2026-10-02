/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void MMESize (void);
 *
 *
 *--------------------------------------------------------------------*/

#ifndef MMESIZE_SOURCE
#define MMESIZE_SOURCE

#include "../mme/mme.h"

void MMESize (void) 

{ 
	printf ("sizeof (struct message) = " SIZE_T_SPEC "\n", sizeof (struct message)); 
	printf ("sizeof (struct homeplug1) = " SIZE_T_SPEC "\n", sizeof (struct homeplug1)); 
	printf ("sizeof (struct qualcomm1) = " SIZE_T_SPEC "\n", sizeof (struct qualcomm1)); 
	printf ("sizeof (struct ethernet_hdr) = " SIZE_T_SPEC "\n", sizeof (struct ethernet_hdr)); 
	printf ("sizeof (struct homeplug_hdr) = " SIZE_T_SPEC "\n", sizeof (struct homeplug_hdr)); 
	printf ("sizeof (struct homeplug_fmi) = " SIZE_T_SPEC "\n", sizeof (struct homeplug_fmi)); 
	printf ("sizeof (struct qualcomm_hdr) = " SIZE_T_SPEC "\n", sizeof (struct qualcomm_hdr)); 
	printf ("sizeof (struct fragment_hdr) = " SIZE_T_SPEC "\n", sizeof (struct fragment_hdr)); 
	printf ("sizeof (struct qualcomm_fmi) = " SIZE_T_SPEC "\n", sizeof (struct qualcomm_fmi)); 
	return; 
} 

#endif



