/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   unsigned lightning_nvm_size (signed fd, char const * filename);
 *
 *   nvm.h
 *
 *--------------------------------------------------------------------*/

#ifndef LIGHTNING_NVM_SIZE_SOURCE
#define LIGHTNING_NVM_SIZE_SOURCE

#include <unistd.h>

#include "../tools/files.h"
#include "../tools/error.h"
#include "../tools/endian.h"
#include "../nvm/nvm.h"

unsigned lightning_nvm_size (signed fd, char const * filename) 

{ 
	struct lightning_nvm_header header; 
	if ((fd = open (filename, O_BINARY | O_RDONLY)) == - 1) 
	{ 
		error (1, errno, FILE_CANTOPEN, filename); 
	} 
	if (read (fd, & header, sizeof (header)) != sizeof (header)) 
	{ 
		error (1, errno, FILE_CANTHOME, filename); 
	} 
	close (fd); 
	return (LE32TOH (header.IMAGELENGTH)); 
} 

#endif



