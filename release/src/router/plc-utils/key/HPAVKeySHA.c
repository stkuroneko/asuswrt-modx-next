/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   void HPAVKeySHA (uint8_t digest [], const char * string);
 *
 *   HPAVKey.h
 *
 *   compute the SHA256 digest for a NUL terminated string; the 
 *   will always 256 bits (32 bytes) long for any string length;
 *
 *   Contributor(s);
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef HPAVKEYSHA_SOURCE
#define HPAVKEYSHA_SOURCE

#include "../key/HPAVKey.h"
#include "../key/SHA256.h"

void HPAVKeySHA (uint8_t digest [], const char * string)

{
	struct sha256 sha256;
	SHA256Reset (& sha256);
	SHA256Write (& sha256, string, strlen (string));
	SHA256Fetch (& sha256, digest);
	return;
}

#endif



