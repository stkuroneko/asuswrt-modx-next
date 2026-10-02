/*====================================================================*
 *
 *   grab.c - byte stream grabber
 *
 *.  Motley Tools by Charles Maier;
 *:  Copyright (c) 2001-2006 by Charles Maier Associates Limited;
 *;  Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

#define _GETOPT_H

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/version.h"
#include "../tools/number.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../tools/files.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/basespec.c"
#include "../tools/todigit.c"
#include "../tools/error.c"
#include "../tools/efreopen.c"
#endif

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define GRAB_VERBOSE (1 << 0)
#define GRAB_SILENCE (1 << 1)
#define GRAB_NEWLINE (1 << 2)

/*====================================================================*
 *
 *   void function (size_t offset, size_t length, flag_t flags);
 *
 *
 *.  Motley Tools by Charles Maier;
 *:  Copyright (c) 2001-2006 by Charles Maier Associates Limited;
 *;  Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

void function (size_t offset, size_t length, flag_t flags) 

{ 
	signed c; 
	while (offset--) 
	{ 
		if ((c = getc (stdin)) == EOF) 
		{ 
			error (1, errno, "Can't read file"); 
		} 
	} 
	while (length--) 
	{ 
		if ((c = getc (stdin)) == EOF) 
		{ 
			error (1, errno, "Can't read file"); 
		} 
		putc (DIGITS_HEX [(c >> 4) & 0x0f], stdout); 
		putc (DIGITS_HEX [(c >> 0) & 0x0f], stdout); 
	} 
	if (_anyset (flags, GRAB_NEWLINE)) 
	{ 
		putc ('\n', stdout); 
	} 
	return; 
} 

/*====================================================================*
 *
 *   int main (int argc, char const * argv []);
 *   
 *.  Motley Tools by Charles Maier;
 *:  Copyright (c) 2001-2006 by Charles Maier Associates Limited;
 *;  Licensed under the Internet Software Consortium License;
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	static char const * optv [] = 
	{ 
		"l:no:qv", 
		PUTOPTV_S_FILTER, 
		"byte stream grabber", 
		"l n\tlength to read in bytes", 
		"n\tappend newline on output", 
		"o x\toffset to read in bytes", 
		"q\tquiet mode", 
		"v\tverbose mode", 
		(char const *) (0)
	}; 
	size_t offset = 0; 
	size_t length = 0; 
	flag_t flags = (flag_t) (0); 
	signed c; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch (c) 
		{ 
		case 'l': 
			length = (size_t) (basespec (optarg, 10, sizeof (size_t))); 
			break; 
		case 'o': 
			offset = (size_t) (basespec (optarg, 16, sizeof (size_t))); 
			break; 
		case 'n': 
			_setbits (flags, GRAB_NEWLINE); 
			break; 
		case 'q': 
			_setbits (flags, GRAB_SILENCE); 
			break; 
		case 'v': 
			_setbits (flags, GRAB_VERBOSE); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	if (! argc) 
	{ 
		function (offset, length, flags); 
	} 
	while ((argc) && (* argv)) 
	{ 
		if (efreopen (* argv, "rb", stdin)) 
		{ 
			function (offset, length, flags); 
		} 
		argc--; 
		argv++; 
	} 
	return (0); 
} 

