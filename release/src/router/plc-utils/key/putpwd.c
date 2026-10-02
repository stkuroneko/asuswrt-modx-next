/*====================================================================*
*
*   Copyright (c) 2015 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   void putpwd (unsigned count, unsigned group, char space);
 *
 *   keys.h
 *
 *   print a random password on stdout; passwords consist of count
 *   letters and digits; optionally, group letters and digits and 
 *   separate groups with a space character;
 *
 *   alphabet is an array of 32 printable password characters; 
 *   count is the number of characters to be selected from alphabet; 
 *   group is the grouping factor; 
 *   space is the group separator;
 *
 *   grouping is suppressed when group is zero or greater than or 
 *   equal to count;
 *
 *   Contributors:
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PUTPWD_SOURCE
#define PUTPWD_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WIN32
#include <stdlib.h>
#include <time.h>
#endif


#include "../tools/types.h"
#include "../tools/error.h"
#include "../key/keys.h"


void putpwd (unsigned count, unsigned group, char space)

{
unsigned  member;
    
#ifndef WIN32
	signed fd;

	if ((fd = open ("/dev/urandom", O_RDONLY)) == -1)
	{
		error (1, errno, "can't open /dev/urandom");
	}
#endif
    
	while (count--)
	{
		static const char alphabet [] =
		{
			'2',
			'3',
			'4',
			'5',
			'6',
			'7',
			'8',
			'9',
			'A',
			'B',
			'C',
			'D',
			'E',
			'F',
			'G',
			'H',
			'J',
			'K',
			'L',
			'M',
			'N',
			'P',
			'Q',
			'R',
			'S',
			'T',
			'U',
			'V',
			'W',
			'X',
			'Y',
			'Z'
		};
		
        
#ifndef WIN32
		if (read (fd, & member, sizeof (member)) != sizeof (member))
		{
			error (1, errno, "can't read /dev/urandom");
		}
#else
		member = rand();
#endif

		member &= 0x1F;
		putc (alphabet [member % sizeof (alphabet)], stdout);
		if ((count) && (group) && ! (count % group))
		{
			putc (space, stdout);
		}
	}

#ifndef WIN32
	close (fd);
#endif

	return;
}


#endif



