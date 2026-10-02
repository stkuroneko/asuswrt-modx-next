/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   char const * reword (code_t code, struct _code_ const list [], size_t size);
 *
 *   symbol.h
 *   
 *   search a _code_ list by code and return the associated name; return the
 *   corresponding name on success or NULL on failure;
 *
 *   Contributor(s):
 *	Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef REWORD_SOURCE
#define REWORD_SOURCE

#include <unistd.h>
#include <string.h>

#include "../tools/symbol.h"

char const * reword (code_t code, struct _code_ const list [], size_t size) 

{ 
	struct _code_ const * item = list; 
	while ((unsigned) (item - list) < size) 
	{ 
		if (item->code == code) 
		{ 
			return (item->name); 
		} 
		item++; 
	} 
	return (NULL); 
} 

#endif



