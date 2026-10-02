/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   nmk2nid.c
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/
/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/putoptv.h"
#include "../tools/version.h"
#include "../tools/memory.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/error.h"
#include "../key/HPAVKey.h"
#include "../key/SHA256.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/uintspec.c"
#include "../tools/hexencode.c"
#include "../tools/todigit.c"
#include "../tools/hexout.c"
#include "../tools/error.c"
#endif

#ifndef MAKEFILE
#include "../key/HPAVKeyNID.c"
#include "../key/HPAVKeySHA.c"
#include "../key/HPAVKeyOut.c"
#include "../key/SHA256.c"
#endif

/*====================================================================*
 *   
 *   int main (int argc, const char * argv []);
 *
 *--------------------------------------------------------------------*/

int main (int argc, const char * argv [])

{
	static const char * optv [] =
	{
		"qv",
		"NMK [NMK] [...]",
		"HomePlug AV NMK-to-NID converter",
		"q\tquiet mode",
		"v\tverbose mode",
		(const char *) (0)
	};
	struct sha256 sha256;
	byte digest [SHA256_DIGEST_LENGTH];
	byte NMK [HPAVKEY_NMK_LEN];
	byte NID [HPAVKEY_NID_LEN];
	flag_t flags = (flag_t) (0);
	signed c;
	optind = 1;
	while (~ (c = getoptv (argc, argv, optv)))
	{
		switch (c)
		{
		case 'q':
			_setbits (flags, HPAVKEY_SILENCE);
			break;
		case 'v':
			_setbits (flags, HPAVKEY_VERBOSE);
			break;
		default: 
			break;
		}
	}
	argc -= optind;
	argv += optind;
	while ((argc) && (* argv))
	{
		char const * sp = * argv;
		unsigned hash = 5;
		while (isxdigit ((unsigned char)* sp))
		{
			sp++;
		}
		if (* sp)
		{
			error (1, EINVAL, "%s", * argv);
		}
		if ((sp - * argv) != (HPAVKEY_NMK_LEN * 2))
		{
			error (1, EINVAL, "%s", * argv);
		}
		hexencode (NMK, sizeof (NMK), * argv);
		SHA256Reset (& sha256);
		SHA256Write (& sha256, NMK, sizeof (NMK));
		SHA256Fetch (& sha256, digest);
		while (-- hash)
		{
			SHA256Reset (& sha256);
			SHA256Write (& sha256, digest, sizeof (digest));
			SHA256Fetch (& sha256, digest);
		}
		memcpy (NID, digest, sizeof (NID));
		NID [sizeof (NID) -1] >>= 4;
		HPAVKeyOut (NID, sizeof (NID), * argv, flags);
		argc--;
		argv++;
	}
	return (0);
}

