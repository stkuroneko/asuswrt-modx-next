/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   void HPAVKeyNID (uint8_t NID [], const uint8_t NMK [], signed level);
 *
 *   HPAVKey.h
 *   
 *   compute the HomePlugAV compliant Network Identification Key (NID)
 *   for a given Network Membership Key (NMK); return the key in buffer
 *   NID []; the key will be HPAVKEY_NID_LEN bytes as defined in 
 *   HPAVKey.h;
 *
 *   unlike the NMK, the NID is 54-bits and includes a 2-bit security 
 *   level; See the HomePlug AV Specification for more info;
 *
 *   hash the NMK then rehash the digest 4 times per HomePlug AV
 *   Specification; no salt is used;
 *   
 *
 *   Contributor(s);
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef HPAVKEYNID_SOURCE
#define HPAVKEYNID_SOURCE

#include <memory.h>

#include "../key/HPAVKey.h"
#include "../key/SHA256.h"

void HPAVKeyNID (uint8_t NID [], const uint8_t NMK [], uint8_t level)

{
	struct sha256 sha256;
	uint8_t digest [SHA256_DIGEST_LENGTH];
	unsigned rehash = 4;
	SHA256Reset (& sha256);
	SHA256Write (& sha256, NMK, HPAVKEY_NMK_LEN);
	SHA256Fetch (& sha256, digest);
	while (rehash--)
	{
		SHA256Reset (& sha256);
		SHA256Write (& sha256, digest, sizeof (digest));
		SHA256Fetch (& sha256, digest);
	}
#if 1

	level <<= 4;
	digest [HPAVKEY_NID_LEN -1] >>= 4;
	digest [HPAVKEY_NID_LEN -1] |= level;

#else

	digest [HPAVKEY_NID_LEN -1] &= ~ 0xC0;
	digest [HPAVKEY_NID_LEN -1] |= level << 6;

#endif

	memcpy (NID, digest, HPAVKEY_NID_LEN);
	return;
}

#endif



