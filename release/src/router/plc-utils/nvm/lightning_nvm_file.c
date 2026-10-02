/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed lightning_nvm_file (struct _file_ const * file);
 *
 *   validate a Thunderbolt/Lightning firmware image file;  
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NVMFILE1_SOURCE
#define NVMFILE1_SOURCE

#include <memory.h>
#include <errno.h>

#include "../tools/memory.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../nvm/nvm.h"

signed lightning_nvm_file (struct _file_ const * file) 

{ 
	unsigned module = 0; 
	struct lightning_nvm_header nvm_header; 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	do 
	{ 
		if (read (file->file, & nvm_header, sizeof (nvm_header)) != sizeof (nvm_header)) 
		{ 
			error (1, errno, NVM_HDR_CANTREAD, file->name, module); 
		} 
		if (LE32TOH (nvm_header.HEADERVERSION) != 0x60000000) 
		{ 
			error (1, errno, NVM_HDR_VERSION, file->name, module); 
		} 
		if (checksum32 (& nvm_header, sizeof (nvm_header), 0)) 
		{ 
			error (1, errno, NVM_HDR_CHECKSUM, file->name, module); 
		} 
		if (fdchecksum32 (file->file, LE32TOH (nvm_header.IMAGELENGTH), nvm_header.IMAGECHECKSUM)) 
		{ 
			error (1, errno, NVM_IMG_CHECKSUM, file->name, module); 
		} 
		module++; 
	} 
	while (nvm_header.NEXTHEADER); 
	if (lseek (file->file, 0, SEEK_CUR) != lseek (file->file, 0, SEEK_END)) 
	{ 
		error (1, errno, NVM_HDR_LINK, file->name, module); 
	} 
	return (0); 
} 

#endif



