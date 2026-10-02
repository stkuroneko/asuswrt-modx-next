/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

#ifndef MEMDECODE_SOURCE
#define MEMDECODE_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/error.h"
#include "../pib/pib.h"

/*====================================================================*
 *
 *   void getmemory (byte const * memory, size_t extent, char const * object, size_t length);
 *
 *--------------------------------------------------------------------*/

static void getmemory (byte const * memory, size_t extent, char const * object, size_t length) 

{ 
	if (length > extent) 
	{ 
		error (1, ECANCELED, "%s exceeds PIB length of " SIZE_T_SPEC " bytes", object, length); 
	} 
	hexout (memory, length, ':', 0, stdout); 
	return; 
} 

/*====================================================================*
 *
 *   void getstring (byte const * memory, size_t extent, char const * object, size_t length);
 *
 *--------------------------------------------------------------------*/

static void getstring (char const * string, size_t extent, char const * object, size_t length) 

{ 
	if (length > extent) 
	{ 
		error (1, ECANCELED, "%s exceeds PIB length " SIZE_T_SPEC " bytes", object, length); 
	} 
	while (isprint ((unsigned char)* string) && (length--))  
	{ 
		putc (* string++, stdout); 
	} 
	return; 
} 

/*====================================================================*
 *
 *   void memdecode (void const * memory, size_t extent, char const * format, char * string) 
 *
 *   extract and print the specified data strings from memory;
 *
 *--------------------------------------------------------------------*/

size_t memdecode (void const * memory, size_t extent, char const * object, char const * string) 

{ 
	unsigned length = 0; 
	void const * origin = memory; 
	if (! strcmp (object, "byte")) 
	{ 
		uint8_t * number = (uint8_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("%u", * number); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 
	else if (! strcmp (object, "word")) 
	{ 
		uint16_t * number = (uint16_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("%u", LE16TOH (* number)); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 
	else if (! strcmp (object, "long")) 
	{ 
		uint32_t * number = (uint32_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("%u", LE32TOH (* number)); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 
	else if (! strcmp (object, "huge")) 
	{ 
		uint64_t * number = (uint64_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("%llu", LE64TOH (* number)); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 

#if 1

	else if (! strcmp (object, "xbyte")) 
	{ 
		uint8_t * number = (uint8_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("0x%02X", * number); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 
	else if (! strcmp (object, "xword")) 
	{ 
		uint16_t * number = (uint16_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("0x%04X", LE16TOH (* number)); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 
	else if (! strcmp (object, "xlong")) 
	{ 
		uint32_t * number = (uint32_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("0x%08X", LE32TOH (* number)); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 
	else if (! strcmp (object, "xhuge")) 
	{ 
		uint64_t * number = (uint64_t *) (memory); 
		if (sizeof (* number) > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		printf ("0x%016LX", LE64TOH (* number)); 
		memory += sizeof (* number); 
		extent -= sizeof (* number); 
	} 

#endif

	else if (! strcmp (object, "mac")) 
	{ 
		length = ETHER_ADDR_LEN; 
		if (length > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		getmemory (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 
	else if (! strcmp (object, "key")) 
	{ 
		length = PIB_KEY_LEN; 
		if (length > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		getmemory (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 
	else if (! strcmp (object, "hfid")) 
	{ 
		length = PIB_HFID_LEN; 
		if (length > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		getstring (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 

#if 1

	else if (! strcmp (object, "adminusername") || ! strcmp (object, "adminpassword") || ! strcmp (object, "accessusername")) 
	{ 
		length = PIB_NAME_LEN +  1; 
		if (length > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		getstring (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 
	else if (! strcmp (object, "accesspassword")) 
	{ 
		length = PIB_HFID_LEN +  1; 
		if (length > extent) 
		{ 
			error (1, ECANCELED, "%s exceeds PIB extent " SIZE_T_SPEC, object, extent); 
		} 
		getstring (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 
	else if (! strcmp (object, "username") || ! strcmp (object, "password") || ! strcmp (object, "url")) 
	{ 
		length = PIB_TEXT_LEN +  1; 
		getstring (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 

#endif

#if 1

	else if (! strcmp (object, "data")) 
	{ 
		if (! string || ! (* string)) 
		{ 
			error (1, EINVAL, "%s needs a length", object); 
		} 
		length = (unsigned) (uintspec (string, 1, extent)); 
		hexout (memory, length, 0, 0, stdout); 
		memory += length; 
		extent -= length; 
	} 
	else if (! strcmp (object, "text")) 
	{ 
		if (! string || ! (* string)) 
		{ 
			error (1, EINVAL, "%s needs a length", object); 
		} 
		length = (unsigned) (uintspec (string, 1, extent)); 
		getstring (memory, extent, object, length); 
		memory += length; 
		extent -= length; 
	} 
	else if (! strcmp (object, "skip")) 
	{ 
		if (! string || ! (* string)) 
		{ 
			error (1, EINVAL, "%s needs a length", object); 
		} 
		length = (unsigned) (uintspec (string, 1, extent)); 
		memory += length; 
		extent -= length; 
	} 

#endif

	else 
	{ 
		error (1, ENOTSUP, "%s", object); 
	} 
	return ((byte *) (memory) - (byte *) (origin)); 
} 

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



