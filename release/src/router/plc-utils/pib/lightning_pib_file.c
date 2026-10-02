/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed lightning_pib_file (struct _file_ const * file);
 *
 *   pib.h
 *
 *   open a thunderbolt/lightning PIB file and validate it by 
 *   checking file size, checksum and selected internal parameters; 
 *   return a file descriptor on success; terminate the program on 
 *   error;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LIGHTNING_PIB_FILE_SOURCE
#define LIGHTNING_PIB_FILE_SOURCE

#include <unistd.h>
#include <errno.h>

#include "../tools/files.h"
#include "../tools/error.h"
#include "../pib/pib.h"

signed lightning_pib_file (struct _file_ const * file) 

{ 
	struct simple_pib simple_pib; 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	if (read (file->file, & simple_pib, sizeof (simple_pib)) != sizeof (simple_pib)) 
	{ 
		error (1, errno, FILE_CANTREAD, file->name); 
	} 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	if ((simple_pib.RESERVED1) || (simple_pib.RESERVED2)) 
	{ 
		error (1, errno, PIB_BADCONTENT, file->name); 
	} 
	if (fdchecksum32 (file->file, LE16TOH (simple_pib.PIBLENGTH), 0)) 
	{ 
		error (1, errno, PIB_BADCHECKSUM, file->name); 
	} 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	return (0); 
} 

#endif



