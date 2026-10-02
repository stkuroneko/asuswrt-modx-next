/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed fdmanifest (signed fd, char const * filename, struct panther_nvm_header * nvm_header);
 *
 *   given the manifest image header and a file positioned to the
 *   start of the manifest image, extract the manifest and print 
 *   it on stdout in human readable form;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FDMANIFEST_SOURCE
#define FDMANIFEST_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "../tools/endian.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../nvm/nvm.h"

signed fdmanifest (signed fd, char const * filename, struct panther_nvm_header * nvm_header) 

{ 
	off_t extent = LE32TOH (nvm_header->ImageLength); 
	void * memory = malloc (extent); 
	if (! memory) 
	{ 
		error (1, 0, FILE_CANTLOAD, filename); 
	} 
	if (read (fd, memory, extent) != (signed) (extent)) 
	{ 
		error (1, errno, FILE_CANTREAD, filename); 
	} 
	if (lseek (fd, (off_t) (0) - extent, SEEK_CUR) == - 1) 
	{ 
		error (1, errno, FILE_CANTSEEK, filename); 
	} 
	if (panther_nvm_manifest (memory, extent)) 
	{ 
		error (1, 0, "Bad manifest: %s", filename); 
	} 
	free (memory); 
	return (0); 
} 

#endif



