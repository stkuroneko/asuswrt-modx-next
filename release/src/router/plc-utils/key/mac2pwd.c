/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

#define _GETOPT_H

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#ifdef WIN32
#include <stdlib.h>
#include <time.h>
#endif
/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../key/keys.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/todigit.c"
#include "../tools/uintspec.c"
#include "../tools/error.c"
#endif

#ifndef MAKEFILE
#include "../key/MACPasswords.c"
#include "../key/RNDPasswords.c"
#include "../key/putpwd.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

/*====================================================================*
 *   program functions;
 *--------------------------------------------------------------------*/

void (* generate)(unsigned, unsigned, unsigned, unsigned, unsigned, char, flag_t) = RNDPasswords;

/*====================================================================*
 *
 *   void function (const char * file, unsigned alpha, unsigned bunch, flag_t flags)
 *
 *   read Ethernet hardware address strings from a file and print 
 *   address passwords pairs on stdout;
 *
 *   parse an Ethernet hardware address string into vendor and device
 *   ID substrings; print a specified number of consecutive addresses
 *   and password strings having a defined letter count and grouping;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void function (const char * file, unsigned alpha, unsigned bunch, unsigned space, flag_t flags)

{
	extern void (* generate)(unsigned, unsigned, unsigned, unsigned, unsigned, char, flag_t);
	unsigned line = 1;
	unsigned radix = 0x10;
	unsigned width;
	unsigned digit;
	signed c = getc (stdin);
	while (c != EOF)
	{
		uint32_t vendor = 0;
		uint32_t device = 0;
		while (isspace (c))
		{
			if (c == '\n')
			{
				line++;
			}
			c = getc (stdin);
		}
		if ((c == '#') || (c == ';'))
		{
			do
			{
				c = getc (stdin);
			}
			while ((c != '\n') && (c != EOF));
			continue;
		}
		for (width = 0; width < ETHER_ADDR_LEN; width++)
		{
			if ((digit = todigit (c)) < radix)
			{
				vendor *= radix;
				vendor += digit;
				c = getc (stdin);
				continue;
			}
			error (1, EINVAL, "%s: line %d: Illegal vendor", file, line);
		}
		if (!vendor)
		{
			error (1, EPERM, "%s: line %d: Vendor can't be zero", file, line);
		}
		for (width = 0; width < ETHER_ADDR_LEN; width++)
		{
			if ((digit = todigit (c)) < radix)
			{
				device *= radix;
				device += digit;
				c = getc (stdin);
				continue;
			}
			error (1, EINVAL, "%s: line %d: Illegal device", file, line);
		}
		if (!device)
		{
			error (1, EPERM, "%s: line %d: Device can't be zero", file, line);
		}
		while (isspace (c))
		{
			if (c == '\n')
			{
				line++;
			}
			c = getc (stdin);
		}
		generate (vendor, device, 1, alpha, bunch, space, flags);
	}
	return;
}


/*====================================================================*
 *
 *   int main (int argc, const char * argv []);
 *
 *   read one or more text files containing device address strings
 *   and print a stream of address/password pairs; device addresses
 *   must be separated by white space;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#define DEFAULT_ALPHA 25
#define DEFAULT_BUNCH 0

int main (int argc, const char * argv [])

{
#ifdef WIN32
	time_t LocalTime;
#endif
	extern void (* generate)(unsigned, unsigned, unsigned, unsigned, unsigned, char, flag_t);
	static const char * optv [] =
	{
		"b:el:mqv",
		PUTOPTV_S_FUNNEL,
		"Atheros device password generator",
		"b n\tbunching factor [" LITERAL (DEFAULT_BUNCH) "]",
		"e\tbase passwords on host system entropy (more secure)",
		"l n\tpassword letters [" LITERAL (DEFAULT_ALPHA) "]",
		"m\tbase passwords on MAC addresses (non-secure)",
		"q\tomit device address on output",
		"v\tprepend PTS flag on output",
		(const char *)(0)
	};
	unsigned alpha = DEFAULT_ALPHA;
	unsigned bunch = DEFAULT_BUNCH;
	unsigned space = '-';
	flag_t flags = (flag_t)(0);
	signed c;
	optind = 1;
#ifdef WIN32
	LocalTime = time(&LocalTime);
	srand((unsigned int)LocalTime);
#endif
	while ((c = getoptv (argc, argv, optv)) != -1)
	{
		switch ((char)(c))
		{
		case 'b':
			bunch = uintspec (optarg, 0, UCHAR_MAX);
			break;
		case 'e':
			generate = RNDPasswords;
			break;
		case 'l':
			alpha = uintspec (optarg, 12, 64);
			break;
		case 'm':
			generate = MACPasswords;
			break;
		case 'q':
			_setbits (flags, PASSWORD_SILENCE);
			break;
		case 'v':
			_setbits (flags, PASSWORD_VERBOSE);
			break;
		default:
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (!argc)
	{
		function ("stdin", alpha, bunch, space, flags);
	}
	while ((argv) && (* argv))
	{
		if (!freopen (* argv, "rb", stdin))
		{
			error (1, EINVAL, "Can't open %s", * argv);
		}
		function (* argv, alpha, bunch, space, flags);
		argc--;
		argv++;
	}
	return (0);
}

