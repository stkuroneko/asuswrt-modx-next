/*====================================================================*
*
*   Copyright (c) 2015 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   char * strnpwd (char buffer [], unsigned length, unsigned count, unsigned group, char space);
 *
 *   keys.h
 *
 *   encode a buffer with a password containing the specified number
 *   of random letters and digits; optionally, group the letters and
 *   digits and separate groups with a space character; return the
 *   address of the byte following the encoded password;
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

#ifndef STRNPWD_SOURCE
#define STRNPWD_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WIN32
#include <stdlib.h>
#include <time.h>
#endif

#include "../tools/types.h"
#include "../tools/error.h"
#include "../key/keys.h"

char * strnpwd (char buffer [], unsigned length, unsigned count, unsigned group, char space)

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
		if (length)
		{
			*buffer = alphabet [member % sizeof (alphabet)];
			buffer++;
			length--;
		}
		if ((count) && (group) && ! (count % group))
		{
			if (length)
			{
				*buffer = space;
				buffer++;
				length--;
			}
		}
	}
#ifndef WIN32
	close (fd);
#endif
	return (buffer);
}

#endif



