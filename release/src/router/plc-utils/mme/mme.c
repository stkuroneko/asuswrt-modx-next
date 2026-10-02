/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   mme.c - Qualcomm Atheros vendor-specific message code and name printer;
 *
 *   print vendor-specific mesage codes and names and with associated
 *   error codes and error text on stdout in various formats; options 
 *   are HTML, CSV and plain text;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <errno.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/number.h"
#include "../tools/format.h"
#include "../tools/error.h"
#include "../tools/flags.h"
#include "../mme/mme.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/error.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/output.c"
#endif

#ifndef MAKEFILE
#include "../mme/MMEName.c"
#include "../mme/MMEMode.c"
#endif

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#include "../mme/MMECode.c"
#include "../mme/MMESize.c"

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define MME_VERBOSE	(1 << 0)
#define MME_SILENCE	(1 << 1)
#define MME_ORDER	(1 << 2)
#define MME_TOCSV	(1 << 3)
#define MME_TOHTML	(1 << 4)
#define MME_TOTEXT	(1 << 5)
#define MME_TOSIZE	(1 << 6)

#define DEFAULT_COLUMN 50
#define DEFAULT_INDENT 2

/*====================================================================*
 *
 *   void mmetocsv ();
 *
 *
 *--------------------------------------------------------------------*/

static void mmetocsv (void) 

{ 
	unsigned index; 
	printf ("Name,Type,Code,Text\n"); 
	for (index = 0; index < SIZEOF (mme_codes); index++) 
	{ 
		unsigned type = mme_codes [index].type; 
		printf ("0x%04X,", type); 
		printf ("%s.%s,", MMEName (type), MMEMode (type)); 
		printf ("0x%02X,", mme_codes [index].code); 
		printf ("\"%s\"\n", mme_codes [index].text); 
	} 
	return; 
} 

/*====================================================================*
 *
 *   void mmetohtml (signed margin);
 *
 *
 *--------------------------------------------------------------------*/

static void mmetohtml (unsigned margin) 

{ 
	unsigned index; 
	output (margin++, "<table class='mme'>"); 
	output (margin++, "<tr class='mme'>"); 
	output (margin, "<th class='type'>Type</th>"); 
	output (margin, "<th class='name'>Name</th>"); 
	output (margin, "<th class='code'>Code</th>"); 
	output (margin, "<th class='text'>Text</th>"); 
	output (margin--, "</tr>"); 
	for (index = 0; index < SIZEOF (mme_codes); index++) 
	{ 
		unsigned type = mme_codes [index].type; 
		output (margin++, "<tr class='mme'>"); 
		output (margin, "<td class='type'>0x%04X</td>", type); 
		output (margin, "<td class='name'>%s.%s</td>", MMEName (type), MMEMode (type)); 
		output (margin, "<td class='code'>0x%02X</td>", mme_codes [index].code); 
		output (margin, "<td class='text'>%s</td>", mme_codes [index].text); 
		output (margin--, "</tr>"); 
	} 
	output (margin--, "</table>"); 
	return; 
} 

/*====================================================================*
 *
 *   void mmetotext (void);
 *
 *
 *--------------------------------------------------------------------*/

static void mmetotext (unsigned column) 

{ 
	unsigned index; 
	for (index = 0; index < SIZEOF (mme_codes); index++) 
	{ 
		signed indent = column; 
		unsigned type = mme_codes [index].type; 
		indent -= printf ("0x%04X ", type); 
		indent -= printf ("%s.%s ", MMEName (type), MMEMode (type)); 
		while (indent-- > 0) 
		{ 
			putc (' ', stdout); 
		} 
		printf ("0x%02X ", mme_codes [index].code); 
		printf ("\"%s\"\n", mme_codes [index].text); 
	} 
	return; 
} 

/*====================================================================*
 *   
 *   int main (int argc, char * argv[]);
 *   
 *   print vendor-specific message codes and names with associated
 *   error codes and text on stdout; output options are HTML, CSV 
 *   and plain text;
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	static char const * optv [] = 
	{ 
		"chost", 
		PUTOPTV_S_DIVINE, 
		"Qualcomm Atheros vendor-specific message enumerator", 
		"c\tprint CSV table on stdout", 
		"h\tprint HTML table on stdout", 
		"o\tcheck the order of MMECode table", 
		"s\tprint frame size table on stdout", 
		"t\tprint TEXT table on stdout", 
		(char const *) (0)
	}; 
	unsigned column = DEFAULT_COLUMN; 
	unsigned indent = DEFAULT_INDENT; 
	flag_t flags = (flag_t) (0); 
	signed c; 
	optind = 1; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch ((char) (c)) 
		{ 
		case 'c': 
			_setbits (flags, MME_TOCSV); 
			break; 
		case 'h': 
			_setbits (flags, MME_TOHTML); 
			break; 
		case 'o': 
			_setbits (flags, MME_ORDER); 
			break; 
		case 's': 
			_setbits (flags, MME_TOSIZE); 
			break; 
		case 't': 
			_setbits (flags, MME_TOTEXT); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	if (argc) 
	{ 
		error (1, ENOTSUP, ERROR_TOOMANY); 
	} 
	if (_anyset (flags, MME_ORDER)) 
	{ 
		MMETest (); 
		return (0); 
	} 
	if (_anyset (flags, MME_TOSIZE)) 
	{ 
		MMESize (); 
		return (0); 
	} 
	if (_anyset (flags, MME_TOTEXT)) 
	{ 
		mmetotext (column); 
		return (0); 
	} 
	if (_anyset (flags, MME_TOHTML)) 
	{ 
		mmetohtml (indent); 
		return (0); 
	} 
	if (_anyset (flags, MME_TOCSV)) 
	{ 
		mmetocsv (); 
		return (0); 
	} 
	mmetotext (column); 
	return (0); 
} 

