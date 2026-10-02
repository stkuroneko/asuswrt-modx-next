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
#include <string.h>
#include <limits.h>
#include <errno.h>

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
 *   void function (const char * string, unsigned range, unsigned alpha, unsigned bunch, unsigned space, flag_t flags)
 *
 *   parse an Ethernet hardware address string into vendor and device
 *   ID substrings; print a specified number of consecutive addresses
 *   and password strings having a defined letter count and grouping;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void function (const char * string, unsigned range, unsigned alpha, unsigned bunch, unsigned space, flag_t flags)

{
	extern void (* generate)(unsigned, unsigned, unsigned, unsigned, unsigned, char, flag_t);
	const char * offset = string;
	unsigned vendor = 0;
	unsigned device = 0;
	unsigned radix = 0x10;
	unsigned width;
	unsigned digit;
	for (width = 0; width < ETHER_ADDR_LEN; width++)
	{
		if ((digit = todigit (*offset)) < radix)
		{
			vendor *= radix;
			vendor += digit;
			offset++;
			continue;
		}
		error (1, EINVAL, "Bad MAC Address: %s", string);
	}
	if (!vendor)
	{
		error (1, EPERM, "Vendor ID can't be zero");
	}
	for (width = 0; width < ETHER_ADDR_LEN; width++)
	{
		if ((digit = todigit (*offset)) < radix)
		{
			device *= radix;
			device += digit;
			offset++;
			continue;
		}
		error (1, EINVAL, "Bad MAC Address: %s", string);
	}
	if (!device)
	{
		error (1, EPERM, "Device ID can't be zero");
	}
	if (*offset)
	{
		error (1, EINVAL, "Bad MAC address: %s", string);
	}
	if (range > (0x00FFFFFF - device))
	{
		error (1, ERANGE, "Want %d passwords but only %d left in range", range, (0x00FFFFFF - device));
	}
	generate (vendor, device, range, alpha, bunch, space, flags);
	return;
}


/*====================================================================*
 *
 *   int main (int argc, const char * argv []);
 *
 *   generate unique password strings for a range of device hardware
 *   addresses; print paired addresses and passwords on stdout;
 *
 *   Many Atheros programs expect the user to enter a password to
 *   access a device; the password is encoded to produce the 16-bit
 *   Device Access Key (DAK) stored in the PIB;
 *
 *   Vendors must publish the device password so that end users can
 *   reproduce the same 16-byte hexadecimal value later; a password
 *   is more user-friendly than a 16-byte hexadecimal value;
 *
 *   given a range of MAC address, this program will produce unique
 *   passwords so vendors can program devices and print labels that
 *   ship devices;
 *
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#define DEFAULT_RANGE 1
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
		"b:el:mn:qv",
		"address [address] [...]",
		"Atheros device password generator",
		"b n\tbunching factor [" LITERAL (DEFAULT_BUNCH) "]",
		"e\tbase passwords on host system entropy (more secure)",
		"l n\tpassword letters [" LITERAL (DEFAULT_ALPHA) "]",
		"m\tbase passwords on MAC addresses (non-secure)",                     
		"n n\tgenerate n consecutive passwords [" LITERAL (DEFAULT_RANGE) "]",
		"q\tomit device address on output",
		"v\tprepend PTS flag on output",
		(const char *)(0)
	};
	unsigned range = DEFAULT_RANGE;
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
		case 'n':
			range = uintspec (optarg, 0, 0x00FFFFFF);
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
	while ((argv) && (* argv))
	{
		function (* argv, range, alpha, bunch, space, flags);
		argc--;
		argv++;
	}
	return (0);
}

