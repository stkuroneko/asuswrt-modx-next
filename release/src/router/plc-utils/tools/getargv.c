/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed getargv (signed argc, char const * argv [])
 *
 *   symbol.h
 *
 *   read one line from stdin; fill argv [] with fields from that
 *   line; return the number of fields found; ignore blank lines 
 *   and script style comment lines; this implementation inserts
 *   a program name at argv [0] to emulate a true argv [];
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef GETARGV_SOURCE
#define GETARGV_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <memory.h>

#include "../tools/symbol.h"
#include "../tools/chars.h"

signed getargv (signed argc, char const * argv []) 

{ 
	extern char const * program_name; 
	static char string [2048]; 
	char const ** argp = argv; 
	char * sp = string; 
	signed c = getc (stdin); 
	memset (string, 0, sizeof (string)); 
	memset ((char **) (argv), 0, argc * sizeof (char const *)); 
	while (nobreak (c)) 
	{ 
		if (isspace (c)) 
		{ 
			do 
			{ 
				c = getc (stdin); 
			} 
			while (isspace (c)); 
		} 
		if (c == '#') 
		{ 
			do 
			{ 
				c = getc (stdin); 
			} 
			while (nobreak (c)); 
			c = getc (stdin); 
			continue; 
		} 
		* argp++ = program_name; 
		* argp++ = sp = string; 
		while (nobreak (c)) 
		{ 
			if (c == '#') 
			{ 
				do 
				{ 
					c = getc (stdin); 
				} 
				while (nobreak (c)); 
				break; 
			} 
			if (isblank (c)) 
			{ 
				c = (char) (0); 
				* argp = sp +  1; 
			} 
			else if (sp == * argp) 
			{ 
				if ((signed) (argp - argv) < argc) 
				{ 
					argp++; 
				} 
			} 
			* sp++ = (char) (c); 
			c = getc (stdin); 
		} 
		* argp = (char const *) (0); 
		* sp = (char) (0); 
	} 
	return ((unsigned) (argp - argv)); 
} 

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#if 0

char const * program_name = "program"; 

#include <stdio.h>

int main (int argc, char const * argv []) 

{ 
	char const * fields [16]; 
	signed count; 
	while ((count = getargv (SIZEOF (fields), fields))) 
	{ 
		signed field; 
		for (field = 0; field < count; field++) 
		{ 
			printf ("field[%d]=[%s]\n", field, fields [field]); 
		} 
		printf ("\n"); 
	} 
	return (0); 
} 

#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



