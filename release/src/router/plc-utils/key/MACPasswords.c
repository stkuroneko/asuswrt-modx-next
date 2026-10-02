/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void  MACPasswords (unsigned vendor, unsigned device, unsigned number, unsigned count, unsigned group, char space, flag_t flags);
 *
 *   keys.h
 *
 *   print a range of device address/password pairs on stdout; print
 *   an optional usage flag in first column for PTS compatability;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MACPASSWORDS_SOURCE
#define MACPASSWORDS_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include "../tools/types.h"
#include "../tools/flags.h"
#include "../key/keys.h"

static uint64_t MACSeed = 0;
static uint64_t MACSRand (uint64_t seed)

{
	uint64_t temp = MACSeed;
	MACSeed = seed;
	return (temp);
}

static unsigned MACRand ()

{
	MACSeed *= 0x41C64E6D;
	MACSeed += 0x00003029;
	return ((unsigned)((MACSeed >> 0x10) & 0x7FFFFFFF));
}

/*====================================================================*
 *
 *   void MACPassword (unsigned device, char const charset [], unsigned limit, unsigned count, unsigned group, char space);
 *
 *   keys.h
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

void MACPassword (unsigned device, char const charset [], unsigned limit, unsigned count, unsigned group, char space)

{
	MACSRand (device);
	while (count--)
	{
		unsigned index = MACRand () % limit;
		putc (charset [index & limit], stdout);
		if ((count) && (group) && !(count % group))
		{
			putc (space, stdout);
		}
	}
	return;
}

/*====================================================================*
 *
 *   void  MACPasswords (unsigned vendor, unsigned device, unsigned number, unsigned count, unsigned group, char space, flag_t flags);
 *
 *   keys.h
 *
 *   print a range of device address/password pairs on stdout; print
 *   an optional usage flag in first column for PTS compatability;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

void MACPasswords (unsigned vendor, unsigned device, unsigned number, unsigned count, unsigned group, char space, flag_t flags)

{
	char charset [UCHAR_MAX];
	unsigned offset = 0;
	if (vendor >> 24)
	{
		return;
	}
	if (device >> 24)
	{
		return;
	}
	if (number >> 24)
	{
		return;
	}
	MACSRand (vendor);
	while (offset < sizeof (charset))
	{
		unsigned c = MACRand () % (SCHAR_MAX + 1);
		if (isupper (c))
		{
			charset [offset++] = c;
		}
	}
	while (number--)
	{
		if (_anyset (flags, PASSWORD_VERBOSE))
		{
			putc ('0', stdout);
			putc (' ', stdout);
		}
		if (_allclr (flags, PASSWORD_SILENCE))
		{
			printf ("%06X", vendor & 0x00FFFFFF);
			printf ("%06X", device & 0x00FFFFFF);
			putc (' ', stdout);
		}
		MACPassword (device, charset, sizeof (charset), count, group, space);
		putc ('\n', stdout);
		device++;
	}
	return;
}


#endif

