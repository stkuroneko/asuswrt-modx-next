/*====================================================================*
 *
 *   pad.c - file pad program;
 *
 *   copy one or more files to stdout; if no files are specified 
 *   then copy stdin to stdout;
 *
 *.  Motley Tools by Charles Maier
 *:  Copyright (c) 2001-2006 by Charles Maier Associates Limited;
 *;  Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#define _GETOPT_H

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/number.h"
#include "../tools/types.h"
#include "../tools/files.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/efreopen.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/error.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define BLOCKSIZE 4

/*====================================================================*
 *
 *   signed function (signed blocksize, byte fill);
 *
 *   copy file using fixed blocksize so that the output is always a
 *   multiple of the blocksize;
 *
 *--------------------------------------------------------------------*/

static signed function (signed blocksize, byte fill) 

{ 
	void * memory = malloc (blocksize); 
	if (memory) 
	{ 
		memset (memory, fill, blocksize); 
		while (read (STDIN_FILENO, memory, blocksize) > 0) 
		{ 
			write (STDOUT_FILENO, memory, blocksize); 
			memset (memory, fill, blocksize); 
		} 
		free (memory); 
	} 
	return (0); 
} 

/*====================================================================*
 *
 *   int main (int argc, char const * argv []);
 *
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	static char const * optv [] = 
	{ 
		"b:", 
		PUTOPTV_S_FUNNEL, 
		"copy one or more files to stdout in fixed blocks", 
		"b n\tblock size is (n) bytes [" LITERAL (BLOCKSIZE) "]", 
		(char const *) (0)
	}; 
	unsigned char fill = 0; 
	signed blocksize = BLOCKSIZE; 
	signed c; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'b': 
			blocksize = (signed) (uintspec (optarg, 1, SHRT_MAX)); 
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
		function (blocksize, fill); 
	} 
	while ((argc) && (* argv)) 
	{ 
		if (efreopen (* argv, "rb", stdin)) 
		{ 
			function (blocksize, fill); 
		} 
		argc--; 
		argv++; 
	} 
	exit (0); 
} 

