/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   void  RNDPasswords (unsigned vendor, unsigned device, unsigned number, unsigned count, unsigned group, unsigned space, flag_t flags);
 *
 *   keys.h
 *
 *   print a number of device address/password pairs on stdout; print
 *   an optional usage flag in the first column for PTS compatability;
 *
 *   vendor is the 24-bit OUI expressed as an integer; device is the
 *   24-bit starting unit address expressed as an integer; number is
 *   the number of address/password pairs to generate; count is the
 *   number of letters/numbers in the password excluding delimiters;
 *   group is the number of letters or numbers appear between space
 *   characters; space characters are suppressed when group is zero
 *   or greater than count;
 *
 *--------------------------------------------------------------------*/

#ifndef RNDPASSWORDS_SOURCE
#define RNDPASSWORDS_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../tools/types.h"
#include "../tools/error.h"
#include "../tools/files.h"
#include "../tools/flags.h"
#include "../key/keys.h"

void RNDPasswords (unsigned vendor, unsigned device, unsigned number, unsigned count, unsigned group, char space, flag_t flags)

{
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
	while (number--)
	{
		if (_anyset (flags, PASSWORD_VERBOSE))
		{
			putc ('0', stdout);
			putc (' ', stdout);
		}
		if (_allclr (flags, PASSWORD_SILENCE))
		{
			printf ("%06X", vendor);
			printf ("%06X", device);
			putc (' ', stdout);
		}
		putpwd (count, group, space);
		putc ('\n', stdout);
		device++;
	}
	return;
}

#endif



