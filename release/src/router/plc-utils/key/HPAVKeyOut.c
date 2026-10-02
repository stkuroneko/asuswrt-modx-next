/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *   
 *   void HPAVKeyOut (byte digest [], size_t length, const char * phrase, flag_t flags);
 *
 *   HPAVKey.h
 *
 *   print a digest in hexadecimal format on stdout; also print the 
 *   phrase after the digest if the HPAVKEY_VERBOSE flag bit is set;
 *
 *   Contributor(s);
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef HPAVKEYOUT_SOURCE
#define HPAVKEYOUT_SOURCE

#include <stdio.h>

#include "../key/HPAVKey.h"
#include "../tools/memory.h"
#include "../tools/number.h"
#include "../tools/types.h"
#include "../tools/flags.h"

void HPAVKeyOut (const uint8_t digest [], size_t length, const char * phrase, flag_t flags)

{
	hexout (digest, length, 0, 0, stdout);
	if (_anyset (flags, HPAVKEY_VERBOSE))
	{
		printf (" %s", phrase);
	}
	printf ("\n");
	return;
}

#endif



