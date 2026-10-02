/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *   
 *   uint16_t pibscalers (struct _file_ * pib);
 *
 *   return the number of scalers (carriers) based on the FWVERSION
 *   stored in a .pib file; this function is a fix so that older
 *   toolkit programs will work with newer chipsets;
 *
 *   old chipsets support 1155 carriers; new chipsets support 2880
 *   carriers; 
 *   
 *
 *--------------------------------------------------------------------*/

#ifndef PIBSCALERS_SOURCE
#define PIBSCALERS_SOURCE

#include <unistd.h>
#include <errno.h>

#include "../plc/plc.h"
#include "../pib/pib.h"
#include "../tools/error.h"

uint16_t pibscalers (struct _file_ * pib) 

{ 
	struct pib_header pib_header; 
	if (read (pib->file, & pib_header, sizeof (pib_header)) != sizeof (pib_header)) 
	{ 
		error (1, errno, "%s", pib->name); 
	} 
	if (pib_header.FWVERSION < 0x05) 
	{ 
		return (INT_CARRIERS); 
	} 
	return (AMP_CARRIERS); 
} 

#endif



