/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

#ifndef HPAVKEY_HEADER
#define HPAVKEY_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>
#include <string.h>

/*====================================================================*
 *   cusotm header files;
 *--------------------------------------------------------------------*/

#include "../tools/types.h"

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define HPAVKEY_CHAR_MIN 0x20
#define HPAVKEY_CHAR_MAX 0x7E
#define HPAVKEY_PHRASE_MIN 12
#define HPAVKEY_PHRASE_MAX 64
#define HPAVKEY_SHA_LEN 32
#define HPAVKEY_DAK_LEN 16
#define HPAVKEY_NMK_LEN 16
#define HPAVKEY_NID_LEN 7

#define HPAVKEY_SHA 0
#define HPAVKEY_DAK 1
#define HPAVKEY_NMK 2
#define HPAVKEY_NID 3

#define HPAVKEY_VERBOSE (1 << 0)
#define HPAVKEY_SILENCE (1 << 1)
#define HPAVKEY_ENFORCE (1 << 2)

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

void HPAVKeyNMK (uint8_t NMK [], char const * string);
void HPAVKeyDAK (uint8_t DAK [], char const * string);
void HPAVKeyNID (uint8_t NID [], const uint8_t NMK [], uint8_t mode);
void HPAVKeySHA (uint8_t digest [], char const * string);
void HPAVKeyOut (const uint8_t digest [], size_t length, char const * phrase, flag_t flags);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif 



