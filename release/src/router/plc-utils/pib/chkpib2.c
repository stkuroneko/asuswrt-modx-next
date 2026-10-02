/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../tools/files.h"
#include "../key/HPAVKey.h"
#include "../nvm/nvm.h"
#include "../pib/pib.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/checksum32.c"
#include "../tools/fdchecksum32.c"
#include "../tools/checksum32.c"
#include "../tools/hexstring.c"
#include "../tools/hexdecode.c"
#include "../tools/strfbits.c"
#include "../tools/error.c"
#endif

#ifndef MAKEFILE
#include "../key/SHA256Reset.c"
#include "../key/SHA256Block.c"
#include "../key/SHA256Write.c"
#include "../key/SHA256Fetch.c"
#include "../key/HPAVKeyNID.c"
#include "../key/keys.c"
#endif

#ifndef MAKEFILE
#include "../pib/lightning_pib_peek.c"
#include "../pib/panther_pib_peek.c"
#endif 

#ifndef MAKEFILE
#include "../nvm/panther_nvm_manifest.c"
#include "../nvm/panther_nvm_revision.c"
#endif 

/*====================================================================*
 *
 *   signed lightning_pib_image (void const * memory, size_t extent, char const * filename, flag_t flags);
 *
 *   check memory-resident thunderbolt/lightning PIB image; return 0 
 *   for a good image and -1 for a bad image; 
 *
 *   the check performed here is not exhaustive but it is adequate;   
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static signed lightning_pib_image (void const * memory, size_t extent, char const * filename, flag_t flags) 

{ 
	struct simple_pib * simple_pib = (struct simple_pib *) (memory); 
	uint8_t NID [HPAVKEY_NID_LEN]; 
	if (_anyset (flags, PIB_VERBOSE)) 
	{ 
		printf ("------- %s -------\n", filename); 
		if (lightning_pib_peek (memory)) 
		{ 
			if (_allclr (flags, PIB_SILENCE)) 
			{ 
				error (0, 0, PIB_BADVERSION, filename); 
			} 
			return (- 1); 
		} 
	} 
	if (extent != LE16TOH (simple_pib->PIBLENGTH)) 
	{ 
		if (_allclr (flags, PIB_SILENCE)) 
		{ 
			error (0, 0, PIB_BADLENGTH, filename); 
		} 
		return (- 1); 
	} 
	if (checksum32 (memory, extent, 0)) 
	{ 
		if (_allclr (flags, PIB_SILENCE)) 
		{ 
			error (0, 0, PIB_BADCHECKSUM, filename); 
		} 
		return (- 1); 
	} 
	HPAVKeyNID (NID, simple_pib->NMK, simple_pib->PreferredNID [HPAVKEY_NID_LEN - 1] >> 4); 
	if (memcmp (NID, simple_pib->PreferredNID, sizeof (NID))) 
	{ 
		if (_allclr (flags, PIB_SILENCE)) 
		{ 
			error (0, 0, PIB_BADNID, filename); 
		} 
		return (- 1); 
	} 
	return (0); 
} 

/*====================================================================*
 *
 *   signed panther_pib_image (void const * memory, size_t extent, char const * filename, flag_t flags);
 *
 *   check memory-resident panther/lynx PIB image; return 0 for a 
 *   good image and -1 for an bad image; 
 *
 *   the check performed here is not exhaustive but it is adequate;   
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static signed panther_pib_image (void const * memory, size_t extent, char const * filename, flag_t flags) 

{ 
	struct simple_pib * simple_pib = (struct simple_pib *) (memory); 
	struct pib_header * pib_header = (struct pib_header *) (memory); 
	uint8_t NID [HPAVKEY_NID_LEN]; 
	if (_anyset (flags, PIB_VERBOSE)) 
	{ 
		pib_header->PIBLENGTH = HTOLE16 (extent); 
		printf ("------- %s -------\n", filename); 
		if (panther_pib_peek (memory)) 
		{ 
			if (_allclr (flags, PIB_SILENCE)) 
			{ 
				error (0, 0, PIB_BADVERSION, filename); 
			} 
			return (- 1); 
		} 
		memset (pib_header, 0, sizeof (* pib_header)); 
	} 
	HPAVKeyNID (NID, simple_pib->NMK, simple_pib->PreferredNID [HPAVKEY_NID_LEN - 1] >> 4); 
	if (memcmp (NID, simple_pib->PreferredNID, sizeof (NID))) 
	{ 
		if (_allclr (flags, PIB_SILENCE)) 
		{ 
			error (0, 0, PIB_BADNID, filename); 
		} 
		return (- 1); 
	} 
	return (0); 
} 

/*====================================================================*
 *
 *   signed panther_pib_chain (void const * memory, size_t extent, char const * filename, flag_t flags);
 *
 *   search a panther/lynx image chain looking for PIB images and
 *   verify each one; return 0 on success or -1 on error; errors
 *   occur due to an invalid image chain or a bad parameter block;
 *
 *   this implementation reads the parameter block from file into
 *   into memory and checks it there;
 *
 *   
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static signed panther_pib_chain (void const * memory, size_t extent, char const * filename, flag_t flags) 

{ 
	struct panther_nvm_header * header; 
	uint32_t origin = ~ 0; 
	uint32_t offset = 0; 
	unsigned module = 0; 
	do 
	{ 
		header = (struct panther_nvm_header *) ((char *) (memory) +  offset); 
		if (LE16TOH (header->MajorVersion) != 1) 
		{ 
			if (_allclr (flags, NVM_SILENCE)) 
			{ 
				error (0, 0, NVM_HDR_VERSION, filename, module); 
			} 
			return (- 1); 
		} 
		if (LE16TOH (header->MinorVersion) != 1) 
		{ 
			if (_allclr (flags, NVM_SILENCE)) 
			{ 
				error (0, 0, NVM_HDR_VERSION, filename, module); 
			} 
			return (- 1); 
		} 
		if (LE32TOH (header->PrevHeader) != origin) 
		{ 
			if (_allclr (flags, NVM_SILENCE)) 
			{ 
				error (0, 0, NVM_HDR_LINK, filename, module); 
			} 
			return (- 1); 
		} 
		if (checksum32 (header, sizeof (* header), 0)) 
		{ 
			if (_allclr (flags, NVM_SILENCE)) 
			{ 
				error (0, 0, NVM_HDR_CHECKSUM, filename, module); 
			} 
			return (- 1); 
		} 
		origin = offset; 
		offset += sizeof (* header); 
		extent -= sizeof (* header); 
		if (checksum32 ((char *) (memory) +  offset, LE32TOH (header->ImageLength), header->ImageChecksum)) 
		{ 
			if (_allclr (flags, NVM_SILENCE)) 
			{ 
				error (0, 0, NVM_IMG_CHECKSUM, filename, module); 
			} 
			return (- 1); 
		} 
		if (LE32TOH (header->ImageType) == NVM_IMAGE_MANIFEST) 
		{ 
			if (_anyset (flags, NVM_MANIFEST)) 
			{ 
				printf ("------- %s (%d) -------\n", filename, module); 
				panther_nvm_manifest ((char *) (memory) +  offset, LE32TOH (header->ImageLength)); 
				return (0); 
			} 
			if (_anyset (flags, NVM_REVISION)) 
			{ 
				panther_nvm_revision ((char *) (memory) +  offset, LE32TOH (header->ImageLength)); 
				return (0); 
			} 
		} 
		else if (LE32TOH (header->ImageType) == NVM_IMAGE_PIB) 
		{ 
			return (panther_pib_image ((char *) (memory) +  offset, LE32TOH (header->ImageLength), filename, flags)); 
		} 
		offset += LE32TOH (header->ImageLength); 
		extent -= LE32TOH (header->ImageLength); 
		module++; 
	} 
	while (~ header->NextHeader); 
	if (extent) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, errno, NVM_HDR_LINK, filename, module); 
		} 
		return (- 1); 
	} 
	error (0, 0, "%s has no PIB", filename); 
	return (- 1); 
} 

/*====================================================================*
 *
 *   signed chkpib (char const * filename, flag_t flags);
 *
 *   
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static signed chkpib (char const * filename, flag_t flags) 

{ 
	void * memory = 0; 
	signed extent = 0; 
	signed status; 
	signed fd; 
	if ((fd = open (filename, O_BINARY | O_RDONLY)) == - 1) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, errno, FILE_CANTOPEN, filename); 
		} 
		return (- 1); 
	} 
	if ((extent = lseek (fd, 0, SEEK_END)) == - 1) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, errno, FILE_CANTSIZE, filename); 
		} 
		return (- 1); 
	} 
	if (! (memory = malloc (extent))) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, errno, FILE_CANTLOAD, filename); 
		} 
		return (- 1); 
	} 
	if (lseek (fd, 0, SEEK_SET)) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, errno, FILE_CANTHOME, filename); 
		} 
		return (- 1); 
	} 
	if (read (fd, memory, extent) != extent) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, errno, FILE_CANTREAD, filename); 
		} 
		return (- 1); 
	} 
	close (fd); 
	if (LE32TOH (* (uint32_t *) (memory)) == 0x60000000) 
	{ 
		if (_allclr (flags, NVM_SILENCE)) 
		{ 
			error (0, 0, FILE_WONTREAD, filename); 
		} 
		status = - 1; 
	} 
	else if (LE32TOH (* (uint32_t *) (memory)) == 0x00010001) 
	{ 
		status = panther_pib_chain (memory, extent, filename, flags); 
	} 
	else 
	{ 
		status = lightning_pib_image (memory, extent, filename, flags); 
	} 
	free (memory); 
	return (status); 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv []);
 *
 *   
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	static char const * optv [] = 
	{ 
		"mqrv", 
		"file [file] [...]", 
		"Qualcomm Atheros PLC Parameter File Inspector", 
		"m\tdisplay manifest", 
		"q\tquiet", 
		"r\tprint firmware revision string", 
		"v\tverbose messages", 
		(char const *) (0)
	}; 
	flag_t flags = (flag_t) (0); 
	signed state = 0; 
	signed c; 
	optind = 1; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'm': 
			_setbits (flags, PIB_MANIFEST); 
			break; 
		case 'q': 
			_setbits (flags, PIB_SILENCE); 
			break; 
		case 'r': 
			_setbits (flags, PIB_REVISION); 
			break; 
		case 'v': 
			_setbits (flags, PIB_VERBOSE); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	while ((argc) && (* argv)) 
	{ 
		errno = 0; 
		if (chkpib (* argv, flags)) 
		{ 
			state = 1; 
		} 
		else if (_allclr (flags, (PIB_VERBOSE | PIB_SILENCE | PIB_MANIFEST))) 
		{ 
			printf ("%s looks good\n", * argv); 
		} 
		argc--; 
		argv++; 
	} 
	return (state); 
} 

