/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   block.c - 
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <limits.h>
#include <unistd.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/version.h"
#include "../tools/error.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/error.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define MAIN_LENGTH 1024
#define MAIN_BYTE 0x00

/*====================================================================*
 *
 *   void function (unsigned length, unsigned char byte);
 *
 *   write the specified number of byte values to stdout;
 *
 *--------------------------------------------------------------------*/

static void function (unsigned length, unsigned char byte) 

{ 
	while (length--) 
	{ 
		write (STDOUT_FILENO, & byte, sizeof (byte)); 
	} 
	return; 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv []);
 *   
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	static char const * optv [] = 
	{ 
		"l:b:", 
		"> file", 
		"output a file of fixed length containing constant byte values", 
		"l n\tdata length [" LITERAL (MAIN_LENGTH) "]", 
		"b x\tbyte value [" LITERAL (MAIN_BYTE) "]", 
		(char const *) (0)
	}; 
	unsigned length = MAIN_LENGTH; 
	unsigned char byte = MAIN_BYTE; 
	signed c; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'l': 
			length = (size_t) (uintspec (optarg, 0, UINT_MAX)); 
			break; 
		case 'b': 
			byte = (unsigned char) (uintspec (optarg, 0, UCHAR_MAX)); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 

#if defined (WIN32)

	setmode (STDOUT_FILENO, O_BINARY); 

#endif

	if (! argc) 
	{ 
		function (length, byte); 
	} 
	while ((argc) && (* argv)) 
	{ 
		function (length, byte); 
		argc--; 
		argv++; 
	} 
	exit (0); 
} 

