/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed nvmfile (struct _file_ const * file);
 *
 *   nvm.h
 *
 *   open an NVM file and validate it by walking the header and image
 *   chain and validating all checksums; rewind valid files; return a
 *   file descriptor on success or terminate the program on error;
 *
 *   the checksum of the entire header, including header checksum, is
 *   always 0 for valid headers; similarly, the checksum of the image
 *   and image checksum is always 0 for valid images;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NVMFILE_SOURCE
#define NVMFILE_SOURCE

#include "../tools/endian.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../nvm/nvm.h"

signed nvmfile (struct _file_ const * file) 

{ 
	uint32_t version; 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	if (read (file->file, & version, sizeof (version)) != sizeof (version)) 
	{ 
		error (1, errno, FILE_CANTREAD, file->name); 
	} 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	if (LE32TOH (version) == 0x60000000) 
	{ 
		return (lightning_nvm_file (file)); 
	} 
	return (panther_nvm_file (file)); 
} 

#endif



