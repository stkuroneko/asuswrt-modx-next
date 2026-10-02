/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed panther_pib_file (struct _file_ const * file);
 *
 *   pib.h
 *
 *   open a panther/lynx PIB file and validate it by 
 *   checking file size, checksum and selected internal parameters; 
 *   return a file descriptor on success; terminate the program on 
 *   error;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PANTHER_PIB_FILE_SOURCE
#define PANTHER_PIB_FILE_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include "../tools/memory.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../nvm/nvm.h"
#include "../pib/pib.h"

signed panther_pib_file (struct _file_ const * file) 

{ 
	struct panther_nvm_header header; 
	uint32_t origin = ~ 0; 
	uint32_t offset = 0; 
	unsigned module = 0; 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	do 
	{ 
		if (read (file->file, & header, sizeof (header)) != sizeof (header)) 
		{ 
			error (1, errno, NVM_HDR_CANTREAD, file->name, module); 
		} 
		if (LE16TOH (header.MajorVersion) != 1) 
		{ 
			error (1, errno, NVM_HDR_VERSION, file->name, module); 
		} 
		if (LE16TOH (header.MinorVersion) != 1) 
		{ 
			error (1, errno, NVM_HDR_VERSION, file->name, module); 
		} 
		if (checksum32 (& header, sizeof (header), 0)) 
		{ 
			error (1, errno, NVM_HDR_CHECKSUM, file->name, module); 
		} 
		if (LE32TOH (header.PrevHeader) != origin) 
		{ 
			error (1, errno, NVM_HDR_LINK, file->name, module); 
		} 
		if (LE32TOH (header.ImageType) == NVM_IMAGE_PIB) 
		{ 
			if (fdchecksum32 (file->file, LE32TOH (header.ImageLength), header.ImageChecksum)) 
			{ 
				error (1, errno, NVM_IMG_CHECKSUM, file->name, module); 
			} 
			return (0); 
		} 
		if (fdchecksum32 (file->file, LE32TOH (header.ImageLength), header.ImageChecksum)) 
		{ 
			error (1, errno, NVM_IMG_CHECKSUM, file->name, module); 
		} 
		origin = offset; 
		offset = LE32TOH (header.NextHeader); 
		module++; 
	} 
	while (~ header.NextHeader); 
	return (- 1); 
} 

#endif



