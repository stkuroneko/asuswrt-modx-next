/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed lightning_pib_lock (struct _file_ const * pib);
 *
 *   recompute and update the checksum on a thunderbolt or lightning 
 *   PIB file where the checksum is located inside the PIB; 
 *
 *--------------------------------------------------------------------*/

#ifndef LIGHTNING_PIB_LOCK_SOURCE
#define LIGHTNING_PIB_LOCK_SOURCE

#include <unistd.h>
#include <errno.h>

#include "../tools/error.h"
#include "../tools/files.h"
#include "../pib/pib.h"

signed lightning_pib_lock (struct _file_ const * file) 

{ 
	struct simple_pib simple_pib; 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, "1 " FILE_CANTHOME, file->name); 
	} 
	if (read (file->file, & simple_pib, sizeof (simple_pib)) != sizeof (simple_pib)) 
	{ 
		error (1, errno, FILE_CANTREAD, file->name); 
	} 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	simple_pib.CHECKSUM = fdchecksum32 (file->file, LE16TOH (simple_pib.PIBLENGTH), simple_pib.CHECKSUM); 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, "2 " FILE_CANTHOME, file->name); 
	} 
	if (write (file->file, & simple_pib, sizeof (simple_pib)) != sizeof (simple_pib)) 
	{ 
		error (1, errno, FILE_CANTSAVE, file->name); 
	} 
	if (lseek (file->file, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, file->name); 
	} 
	return (0); 
} 

#endif



