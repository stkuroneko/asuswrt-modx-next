/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *   
 *   void HPAVKeySpec (const char * string);
 *   
 *   HPAVKey.h
 *   
 *   confirm that a string is a legal HomePlug AV pass phrase; return
 *   on success; exit the program on failure; legal pass phrases have 
 *   12 to 64 characters ranging from 0x20 thru 0x7F;
 *
 *   this function is intended to check pass phrases entered from the
 *   command line as arguments therefore it explains why it failed;
 *   
 *
 *   Contributor(s);
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef HPAVKEYSPEC_SOURCE
#define HPAVKEYSPEC_SOURCE

#include <ctype.h>

#include "../tools/error.h"
#include "../key/HPAVKey.h"

void HPAVKeySpec (const char * string)

{
	const char * sp = string;
	while (isprint ((unsigned char)* sp))
	{
		sp++;
	}
	if (* sp)
	{
		error (1, ENOTSUP, "Phrase \"%s\" has illegal characters", string);
	}
	if ((sp - string) < HPAVKEY_PHRASE_MIN)
	{
		error (1, ENOTSUP, "Phrase \"%s\" less than %d characters", string, HPAVKEY_PHRASE_MIN);
	}
	if ((sp - string) > HPAVKEY_PHRASE_MAX)
	{
		error (1, ENOTSUP, "Phrase \"%s\" more than %d characters", string, HPAVKEY_PHRASE_MAX);
	}
	return;
}

#endif



