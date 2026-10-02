/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed lightning_nvm_seek (signed fd, char const * filename, struct lightning_nvm_header * nvm_header, uint32_t imagetype);
 *
 *   nvm.h
 *
 *   search a thunderbolt/lightning PIB file for the next image of a
 *   given type; return 0 on success or -1 on failure to find another
 *   image of the given type; 
 *
 *   the call must provide an image header strucuture for use while
 *   searching; on success, that structure will contain information
 *   about the image and file will be positioned to the start of
 *   the image;
 *
 *   
 *--------------------------------------------------------------------*/

#ifndef LIGHTNING_NVM_SEEK_SOURCE
#define LIGHTNING_NVM_SEEK_SOURCE

#include <unistd.h>

#include "../tools/endian.h"
#include "../tools/error.h"
#include "../pib/pib.h"
#include "../nvm/nvm.h"

signed lightning_nvm_seek (signed fd, char const * filename, struct lightning_nvm_header * header, uint32_t imagetype) 

{ 
	unsigned module = 0; 
	do 
	{ 
		if (read (fd, header, sizeof (* header)) != sizeof (* header)) 
		{ 
			error (1, errno, NVM_HDR_CANTREAD, filename, module); 
		} 
		if (LE32TOH (header->HEADERVERSION) != 0x60000000) 
		{ 
			error (1, errno, NVM_HDR_VERSION, filename, module); 
		} 
		if (checksum32 (header, sizeof (* header), 0)) 
		{ 
			error (1, 0, NVM_HDR_CHECKSUM, filename, module); 
		} 
		if (header->IMAGETYPE == imagetype) 
		{ 
			return (0); 
		} 
		if (fdchecksum32 (fd, LE32TOH (header->IMAGELENGTH), header->IMAGECHECKSUM)) 
		{ 
			error (1, ECANCELED, NVM_IMG_CHECKSUM, filename, module); 
		} 
		module++; 
	} 
	while (~ header->NEXTHEADER); 
	if (lseek (fd, 0, SEEK_CUR) != lseek (fd, 0, SEEK_END)) 
	{ 
		error (1, errno, NVM_HDR_LINK, filename, module); 
	} 
	return (- 1); 
} 

#endif



