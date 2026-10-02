/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   config.c - configuration file reader;
 *
 *   configuration files contain named parts where each part may 
 *   contain one of more named items that have text definitions; 
 *
 *   the named file can be searched for the first occurance of a
 *   named part then the first occurance of a named item; 
 *
 *   [part1]
 *   item1=string
 *   item2=string
 *
 *   [part2]
 *   item1=string
 *   item2=string
 *
 *--------------------------------------------------------------------*/

#ifndef CONFIG_SOURCE
#define CONFIG_SOURCE

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/config.h"
#include "../tools/types.h"
#include "../tools/chars.h"

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

static signed c; 

/*====================================================================*
 *
 *   bool _compare (FILE * fp, char const *sp);
 *
 *   compare file and text characters until they differ or until end
 *   of text, line or file occurs; a match is declared when the text 
 *   ends before the line or file;
 *
 *   spaces and tabs within the argument string or file string are
 *   ignored such that "item1", " item1 " and "item 1" all match;
 *
 *--------------------------------------------------------------------*/

static bool _compare (FILE * fp, char const * sp) 

{ 
	while (isblank ((unsigned char)* sp)) 
	{ 
		sp++; 
	} 
	while ((* sp) && nobreak (c)) 
	{ 
		if (toupper (c) != toupper ((unsigned char)* sp))  
		{ 
			return (0); 
		} 
		do 
		{ 
			sp++; 
		} 
		while (isblank ((unsigned char)* sp)); 
		do 
		{ 
			c = getc (fp); 
		} 
		while (isblank (c)); 
	} 
	return (! * sp); 
} 

/*====================================================================*
 *
 *   void _collect (FILE * fp, char buffer [], size_t length);
 *
 *   collect text to end of line; remove leading and trailing space
 *   but preserve embedded space; replace selected escape sequences;
 *
 *--------------------------------------------------------------------*/

static void _collect (FILE * fp, char buffer [], size_t length) 

{ 
	char * string = buffer; 
	while ((c != ';') && nobreak (c)) 
	{ 
		if (c == '\\') 
		{ 
			c = getc (fp); 
			if (c == 'n') 
			{ 
				c = '\n'; 
			} 
			if (c == 'r') 
			{ 
				c = '\r'; 
			} 
			if (c == 't') 
			{ 
				c = '\t'; 
			} 
		} 
		if (length > 1) 
		{ 
			* buffer++ = c; 
			length--; 
		} 
		if (! isblank (c)) 
		{ 
			string = buffer; 
		} 
		c = getc (fp); 
	} 
	* string = '\0'; 
	return; 
} 

/*====================================================================*
 *
 *   void _discard (FILE * fp);
 *
 *   read and discard characters until end-of-line or end-of-file 
 *   is detected; read the first character of next line if end of 
 *   file has not been detected;
 *
 *--------------------------------------------------------------------*/

static void _discard (FILE * fp) 

{ 
	while (nobreak (c)) 
	{ 
		c = getc (fp); 
	} 
	if (c != EOF) 
	{ 
		c = getc (fp); 
	} 
	return; 
} 

/*====================================================================*
 *
 *   const char * configstring (char const * file, char const * part, char const * item, char const * string)
 *
 *   open the named file, locate the named part and return the named
 *   item as a text string, if present; return an alternative string
 *   if the file, part or item is missing; the calling function must 
 *   preserve the returned strings because they are overwritten with 
 *   each call;
 *
 *--------------------------------------------------------------------*/

char const * configstring (char const * file, char const * part, char const * item, char const * string) 

{ 
	FILE * fp; 
	static char buffer [1024]; 
	if ((! file) || (! part) || (! item)) 
	{ 
		return (string); 
	} 
	if ((fp = fopen (file, "rb"))) 
	{ 
		for (c = getc (fp); c != EOF; _discard (fp)) 
		{ 
			while (isblank (c)) 
			{ 
				c = getc (fp); 
			} 
			if (c != '[') 
			{ 
				continue; 
			} 
			do 
			{ 
				c = getc (fp); 
			} 
			while (isblank (c)); 
			if (! _compare (fp, part)) 
			{ 
				continue; 
			} 
			if (c != ']') 
			{ 
				continue; 
			} 
			for (_discard (fp); (c != '[') && (c != EOF); _discard (fp)) 
			{ 
				while (isblank (c)) 
				{ 
					c = getc (fp); 
				} 
				if (c == ';') 
				{ 
					continue; 
				} 
				if (! _compare (fp, item)) 
				{ 
					continue; 
				} 
				if (c != '=') 
				{ 
					continue; 
				} 
				do 
				{ 
					c = getc (fp); 
				} 
				while (isblank (c)); 
				_collect (fp, buffer, sizeof (buffer)); 
				string = buffer; 
				break; 
			} 
			break; 
		} 
		fclose (fp); 
	} 

#if 0

	fprintf (stderr, "[%s][%s][%s]='%s'\n", file, part, item, string); 

#endif

	return (string); 
} 

/*====================================================================*
 *
 *   unsigned confignumber (char const * file, char const * part, char const * item, unsigned number)
 *
 *   open the named file, locate the named part and return the named
 *   item as an unsigned integer, if present; return a default number
 *   if the file, part or item is missing; 
 *
 *--------------------------------------------------------------------*/

unsigned confignumber (char const * file, char const * part, char const * item, unsigned number) 

{ 
	unsigned value = 0; 
	char const * string = configstring (file, part, item, ""); 
	if ((string) && (* string)) 
	{ 
		while (isdigit ((unsigned char)* string))  
		{ 
			value *= 10; 
			value += * string++ - '0'; 
		} 
		if (! (* string)) 
		{ 
			number = value; 
		} 
	} 
	return (number); 
} 

/*====================================================================*
 *
 *   int main (int argc, char const * argv []);
 *
 *   demo/test program; arguments are file, part, item and text in 
 *   that order; you can construct your own configuration file and
 *   observe behaviour; 
 *
 *--------------------------------------------------------------------*/

#if 0

#include <stdio.h>

int main (int argc, char const * argv []) 

{ 
	char const * string = configstring (argv [1], argv [2], argv [3], argv [4]); 
	printf ("file=[%s] part=[%s] item=[%s] text=[%s]\n", argv [1], argv [2], argv [3], string); 
	return (0); 
} 

#endif

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



