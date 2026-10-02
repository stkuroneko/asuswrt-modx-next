/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   psin.c - load prescalers into int6000 parameter file;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/number.h"
#include "../tools/chars.h"
#include "../tools/types.h"
#include "../tools/error.h"
#include "../pib/pib.h"
#include "../plc/plc.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/fdchecksum32.c"
#include "../tools/hexdecode.c"
#include "../tools/hexstring.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/error.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define SCALE_FACTOR 0

/*====================================================================*
 *   
 *   signed ar7x00_psin (struct _file_ * pib, uint32_t value, uint32_t index);
 *
 *   signed ar7x00_psin (struct _file_ * pib, uint32_t value, uint32_t index);
 *
 *   Places a single 10 bit prescaler into the pib file at index;
 *
 *--------------------------------------------------------------------*/

signed ar7x00_psin (struct _file_ * pib, uint32_t value, uint32_t index)

{
	off_t offset = AMP_PRESCALER_OFFSET +  (index * 10 / 8);
	uint8_t bit_offset = (index * 10) % 8;
	uint16_t tmp;
	if (lseek (pib->file, offset, SEEK_SET) != offset)
	{
		return (-1);
	}
	if (read (pib->file, & tmp, sizeof (tmp)) != sizeof (tmp))
	{
		return (-1);
	}
	if (lseek (pib->file, offset, SEEK_SET) != offset)
	{
		return (-1);
	}
	value &= 0x03FF;
	tmp = LE16TOH (tmp);
	tmp &= ~ (0x03FF << bit_offset);
	tmp |= value << bit_offset;
	tmp = HTOLE16 (tmp);
	if (write (pib->file, & tmp, sizeof (tmp)) != sizeof (tmp))
	{
		return (-1);
	}
	return (0);
}

/*====================================================================*
 *
 *   void psgraph ();
 *
 *--------------------------------------------------------------------*/

static void psgraph (unsigned limit, unsigned scale)

{
	unsigned count = 0;
	signed c;
	while ((c = getc (stdin)) != EOF)
	{
		unsigned index = 0;
		unsigned value = 0;
		if (isspace (c))
		{
			continue;
		}
		if ((c == '#') || (c == ';'))
		{
			do 
			{
				c = getc (stdin);
			}
			while (nobreak (c));
			continue;
		}
		while (isdigit (c))
		{
			index *= 10;
			index += c - '0';
			c = getc (stdin);
		}
		if (index != count)
		{
			error (1, ECANCELED, "Carrier %d out of order", index);
		}
		if (index >= limit)
		{
			error (1, EOVERFLOW, "Too many prescalers");
		}
		while (isblank (c))
		{
			c = getc (stdin);
		}
		while (isxdigit (c))
		{
			value *= 16;
			value += todigit (c);
			c = getc (stdin);
		}
		while (nobreak (c))
		{
			c = getc (stdin);
		};
		printf ("%04d %3d", index, value);
		if (scale)
		{
			printf (" %06.4f ", INDEX_TO_FREQ (index));
			while (value > scale)
			{
				value -= scale;
				putc ('#', stdout);
			}
		}
		putc ('\n', stdout);
		count++;
	}
	return;
}

/*====================================================================*
 *   
 *   int main (int argc, char const * argv []) 
 *   
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	static char const * optv [] =
	{
		"s:",
		"pibfile [< prescalers]",
		"dump prescaler file in human readable format",
		"s n\tscale factor is (n) [" LITERAL (SCALE_FACTOR) "]",
		(char const *) (0)
	};
	unsigned limit = AMP_CARRIERS;
	unsigned scale = SCALE_FACTOR;
	signed c;
	optind = 1;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch ((char) (c))
		{
		case 's':
			scale = (unsigned) (uintspec (optarg, 0, 10));
			break;
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if ((argc) || (* argv))
	{
		error (1, ECANCELED, ERROR_TOOMANY);
	}
	psgraph (limit, scale);
	return (0);
}

