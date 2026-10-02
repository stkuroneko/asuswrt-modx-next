/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   gpioinfo.c - print gpio Iinformation
 *
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <limits.h>
#include <errno.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/number.h"
#include "../tools/error.h"
#include "../tools/files.h"
#include "../tools/types.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/todigit.c"
#include "../tools/hexstring.c"
#include "../tools/hexdecode.c"
#include "../tools/error.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define TM_VERBOSE (1 << 0)
#define TM_SILENCE (1 << 1)

#define OFFSET 0x24BF
#define LENGTH 50

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
		"file [file] [...] [> stdout]", 
		"print GPIO information", 
		(char const *) (0)
	}; 

#ifndef __GNUC__
#pragma pack (push, 1)
#endif

	typedef struct __packed EventBlock 
	{ 
		uint8_t EvtPriorityId; 
		uint8_t EvtId; 
		uint8_t BehId [3]; 
		uint16_t ParticipatingGPIOs; 
		uint8_t EventAttributes; 
		uint8_t RSVD [3]; 
	} 
	EventBlock; 

#ifndef __GNUC__
#pragma pack (pop)
#endif

	struct EventBlock EventBlockArray [50]; 
	file_t fd; 
	signed c; 
	optind = 1; 
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
	while ((argc) && (* argv)) 
	{ 
		if ((fd = open (* argv, O_BINARY | O_RDONLY)) == - 1) 
		{ 
			error (0, errno, "Can't open %s", * argv); 
		} 
		else if (lseek (fd, OFFSET, SEEK_SET) != OFFSET) 
		{ 
			error (0, errno, "Can't seek %s", * argv); 
			close (fd); 
		} 
		else if (read (fd, & EventBlockArray, sizeof (EventBlockArray)) != sizeof (EventBlockArray)) 
		{ 
			error (0, errno, "Can't read %s", * argv); 
			close (fd); 
		} 
		else 
		{ 
			for (c = 0; c < LENGTH; c++) 
			{ 
				struct EventBlock * EventBlock = (& EventBlockArray [c]); 
				char string [10]; 
				printf ("EvtPriorityId %3d ", EventBlock->EvtPriorityId); 
				printf ("EvtId %3d ", EventBlock->EvtId); 
				printf ("BehId %s ", hexstring (string, sizeof (string), EventBlock->BehId, sizeof (EventBlock->BehId))); 
				printf ("ParticipatingGPIOs %3d ", EventBlock->ParticipatingGPIOs); 
				printf ("EventAttributes %3d ", EventBlock->EventAttributes); 
				printf ("\n"); 
			} 
			close (fd); 
		} 
		argc--; 
		argv++; 
	} 
	return (0); 
} 

