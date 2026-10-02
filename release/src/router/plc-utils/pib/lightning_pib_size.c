/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   unsigned lightning_pib_size (signed fd, char const * filename);
 *
 *   pib.h
 *
 *   return the lightning parameter image size in bytes; lightning
 *   parameter images store the image size inside the image, itself;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LIGHTNING_PIB_SIZE_SOURCE
#define LIGNTNING_PIB_SIZE_SOURCE

#include <unistd.h>

#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/endian.h"
#include "../pib/pib.h"

unsigned lightning_pib_size (signed fd, char const * filename) 

{ 
	struct pib_header header; 
	if ((fd = open (filename, O_BINARY | O_RDONLY)) == - 1) 
	{ 
		error (1, errno, FILE_CANTOPEN, filename); 
	} 
	if (read (fd, & header, sizeof (header)) != sizeof (header)) 
	{ 
		error (1, errno, FILE_CANTHOME, filename); 
	} 
	close (fd); 
	return ((unsigned) (LE16TOH (header.PIBLENGTH))); 
} 

#endif



