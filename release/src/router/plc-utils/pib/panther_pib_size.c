/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   unsigned panther_pib_size (signed fd, char const * filename);
 *
 *   pib.h
 *
 *   return panther parameter image size in bytes; panther parameter
 *   image files store the image size in the image header.
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PANTHER_PIB_SIZE_SOURCE
#define PANTHER_PIB_SIZE_SOURCE

#include <unistd.h>

#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/endian.h"
#include "../nvm/nvm.h"

unsigned panther_pib_size (signed fd, char const * filename) 

{ 
	struct panther_nvm_header header; 
	if ((fd = open (filename, O_BINARY | O_RDONLY)) == - 1) 
	{ 
		error (1, errno, FILE_CANTOPEN, filename); 
	} 
	if (panther_nvm_seek (fd, filename, & header, NVM_IMAGE_PIB)) 
	{ 
		error (1, errno, FILE_CANTHOME, filename); 
	} 
	close (fd); 
	return (LE32TOH (header.ImageLength)); 
} 

#endif



