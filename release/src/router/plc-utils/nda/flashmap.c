/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <unistd.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/version.h"
#include "../tools/error.h"
#include "../tools/endian.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/error.c"
#endif

/*====================================================================*
 *   program variables;
 *--------------------------------------------------------------------*/

typedef struct queue

{
	struct queue * prev;
	struct queue * next;
	byte * frame;
}

QUEUE;

/*====================================================================*
 *
 *   void function (void);
 *
 *--------------------------------------------------------------------*/

void function (void)

{
	uint32_t byte = 0;
	uint32_t word;
	while (read (STDIN_FILENO, & word, sizeof (word)) == sizeof (word))
	{
		if (word == 0x00010001)
		{
			printf ("%08X ", byte);
			while (read (STDIN_FILENO, & word, sizeof (word)) == sizeof (word))
			{
				if (word == 0xFFFFFFFF)
				{
					printf ("%08X\n", byte);
					break;
				}
				byte += sizeof (word);
			}
		}
		byte += sizeof (word);
	}
	return;
}

/*====================================================================*
 *
 *   int main (int argc, char const * argv []);
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv [])

{
	static char const * optv [] =
	{
		"",
		"",
		"Template Program",
		(char const *) (0)
	};
	signed c;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (! argc)
	{
		function ();
	}
	while ((argc) && (* argv))
	{
		function ();
		argc--;
		argv++;
	}
	exit (0);
}

