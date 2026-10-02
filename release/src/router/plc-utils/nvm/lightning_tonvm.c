/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   tonvm.c - prepend NVM image header;
 *	
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/version.h"
#include "../tools/error.h"
#include "../tools/files.h"
#include "../tools/endian.h"
#include "../tools/number.h"
#include "../tools/memory.h"
#include "../nvm/nvm.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/basespec.c"
#include "../tools/checksum32.c"
#include "../tools/todigit.c"
#include "../tools/efreopen.c"
#include "../tools/error.c"
#endif

/*====================================================================*
 *
 *   void function (void);
 *
 *--------------------------------------------------------------------*/

void function (char const * filename, struct lightning_nvm_header * header) 

{ 
	signed fd; 
	signed length; 
	void * memory; 
	if ((fd = open (filename, O_BINARY | O_RDONLY)) == - 1) 
	{ 
		error (1, errno, FILE_CANTOPEN, filename); 
	} 
	if ((length = lseek (fd, 0, SEEK_END)) == - 1) 
	{ 
		error (1, errno, FILE_CANTSIZE, filename); 
	} 
	if (! (memory = malloc (length))) 
	{ 
		error (1, errno, FILE_CANTLOAD, filename); 
	} 
	if (lseek (fd, 0, SEEK_SET)) 
	{ 
		error (1, errno, FILE_CANTHOME, filename); 
	} 
	if (read (fd, memory, length) != length) 
	{ 
		error (1, errno, FILE_CANTREAD, filename); 
	} 
	close (fd); 
	if (* (int32_t *) (memory) == HTOLE32 (0x60000000)) 
	{ 
		error (0, 0, "Nothing to do."); 
		return; 
	} 
	if (length % sizeof (uint32_t)) 
	{ 
		length += sizeof (uint32_t) - (length % sizeof (uint32_t)); 
		if (realloc (memory, length)) 
		{ 
		}; 
	} 
	header->IMAGELENGTH = HTOLE32 (length); 
	header->IMAGECHECKSUM = checksum32 (memory, length, 0); 
	header->HEADERCHECKSUM = checksum32 (header, sizeof (* header), 0); 
	if ((fd = open (filename, O_BINARY | O_WRONLY)) == - 1) 
	{ 
		error (1, errno, FILE_CANTOPEN, filename); 
	} 
	if (write (fd, header, sizeof (* header)) != sizeof (* header)) 
	{ 
		error (1, errno, FILE_CANTSAVE, filename); 
	} 
	if (write (fd, memory, length) != length) 
	{ 
		error (1, errno, FILE_CANTSAVE, filename); 
	} 
	close (fd); 
	return; 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv []);
 *   
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	struct lightning_nvm_header header; 
	static char const * optv [] = 
	{ 
		"E:F:I:M:S:T:", 
		"file [file] [file] [...]", 
		"Prepend Lightning/Thunderbolt NVM Image header", 
		"E x\tEntry Point", 
		"F x\tFlash Address", 
		"M x\tModule ID", 
		"m x\tModule SubID", 
		"S x\tSDRAM Address", 
		"T x\tImage Type", 
		"I x\tIgnore Mask", 
		(char const *) (0)
	}; 
	signed c; 
	memset (& header, 0, sizeof (header)); 
	header.HEADERVERSION = HTOLE32 (0x60000000); 
	header.HEADERMINORVERSION = 1; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'E': 
			header.ENTRYPOINT = (uint32_t) (basespec (optarg, 16, sizeof (header.ENTRYPOINT))); 
			break; 
		case 'F': 
			header.IMAGEROMADDR = (uint32_t) (basespec (optarg, 16, sizeof (header.IMAGEROMADDR))); 
			break; 
		case 'I': 
			header.IGNOREMASK = (uint32_t) (basespec (optarg, 16, sizeof (header.IGNOREMASK))); 
			break; 
		case 'M': 
			header.MODULEID = (uint32_t) (basespec (optarg, 16, sizeof (header.MODULEID))); 
			break; 
		case 'm': 
			header.MODULESUBID = (uint32_t) (basespec (optarg, 16, sizeof (header.MODULESUBID))); 
			break; 
		case 'S': 
			header.IMAGEADDRESS = (uint32_t) (basespec (optarg, 16, sizeof (header.IMAGEADDRESS))); 
			break; 
		case 'T': 
			header.IMAGETYPE = (uint8_t) (basespec (optarg, 16, sizeof (header.IMAGETYPE))); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	if (! argc) 
	{ 
		error (1, ENOTSUP, "No files given."); 
	} 
	while ((argc) && (* argv)) 
	{ 
		function (* argv, & header); 
		argc--; 
		argv++; 
	} 
	exit (0); 
} 

