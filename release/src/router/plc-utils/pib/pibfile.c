/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed pibfile (struct _file_ const * file);
 *
 *   pib.h
 *   
 *   confirm that pib->file is a valid PIB file; determine if the
 *   file is a panther/lynx image chain or flat file and call the 
 *   correct functions; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PIBFILE_SOURCE
#define PIBFILE_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include "../tools/memory.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../pib/pib.h"

signed pibfile (struct _file_ const * file) 

{ 
	uint32_t version; 
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
		return (- 1); 
	} 
	if (LE32TOH (version) == 0x00010001) 
	{ 
		return (panther_pib_file (file)); 
	} 
	return (lightning_pib_file (file)); 
} 

#endif



