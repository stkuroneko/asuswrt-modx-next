/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed panther_nvm_seek (signd fd, char const * filename, struct panther_nvm_header * nvm_header, uint32_t imagetype);
 *
 *   nvm.h
 *
 *   search a panther/lynx PIB file for the next image of a given 
 *   type; return 0 on success or -1 on failure to find another
 *   image of the given type; 
 *
 *   the call must provide an image header strucuture for use while
 *   searching; on success, that structure will contain information
 *   about the image and file will be positioned to the start of
 *   the image;
 *
 *   
 *--------------------------------------------------------------------*/

#ifndef PANTHER_NVM_SEEK_SOURCE
#define PANTHER_NVM_SEEK_SOURCE

#include <unistd.h>

#include "../tools/endian.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../pib/pib.h"
#include "../nvm/nvm.h"

signed panther_nvm_seek (signed fd, char const * filename, struct panther_nvm_header * header, uint32_t imagetype) 

{ 
	unsigned module = 0; 
	uint32_t origin = ~ 0; 
	uint32_t offset = 0; 
	do 
	{ 
		if (read (fd, header, sizeof (* header)) != sizeof (* header)) 
		{ 
			error (1, errno, NVM_HDR_CANTREAD, filename, module); 
		} 
		if (LE16TOH (header->MajorVersion) != 1) 
		{ 
			error (1, 0, "(0) " NVM_HDR_VERSION, filename, module); 
		} 
		if (LE16TOH (header->MinorVersion) != 1) 
		{ 
			error (1, 0, "(1) " NVM_HDR_VERSION, filename, module); 
		} 
		if (checksum32 (header, sizeof (* header), 0)) 
		{ 
			error (1, 0, NVM_HDR_CHECKSUM, filename, module); 
		} 
		if (LE32TOH (header->PrevHeader) != origin) 
		{ 
			error (1, 0, NVM_HDR_LINK, filename, module); 
		} 
		if (LE32TOH (header->ImageType) == imagetype) 
		{ 
			return (0); 
		} 
		if (fdchecksum32 (fd, LE32TOH (header->ImageLength), header->ImageChecksum)) 
		{ 
			error (1, ECANCELED, NVM_IMG_CHECKSUM, filename, module); 
		} 
		origin = offset; 
		offset = LE32TOH (header->NextHeader); 
		module++; 
	} 
	while (~ header->NextHeader); 
	if (lseek (fd, 0, SEEK_CUR) != lseek (fd, 0, SEEK_END)) 
	{ 
		error (1, errno, NVM_HDR_LINK, filename, module); 
	} 
	if (lseek (fd, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, filename); 
	} 
	return (- 1); 
} 

#endif



