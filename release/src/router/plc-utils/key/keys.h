/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   keys.h -
 *
 *.  Qualcomm Atheros HomePlug AV Powerline Toolkit
 *:  Copyright (c) 2009-2013 by Qualcomm Atheros Inc. ALL RIGHTS RESERVED;
 *;  For demonstration and evaluation only; Not for production use.
 *
 *--------------------------------------------------------------------*/

#ifndef KEYS_HEADER
#define KEYS_HEADER

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <stdint.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/types.h"
#include "../key/HPAVKey.h"

/*====================================================================*
 *   constants;
 *--------------------------------------------------------------------*/

#define PASSWORD_SILENCE (1 << 0)
#define PASSWORD_VERBOSE (1 << 1)

#define DAK0 "00000000000000000000000000000000"
#define DAK1 "689F074B8B0275A2710B0B5779AD1630"
#define DAK2 "F084B4E8F6069FF1300C9BDB812367FF"

#define NMK0 "00000000000000000000000000000000"
#define NMK1 "50D3E4933F855B7040784DF815AA8DB7"
#define NMK2 "B59319D7E8157BA001B018669CCEE30D"

#define KEYS 3
#define DAKS 6
#define NMKS 5

/*====================================================================*
 *   variables;
 *--------------------------------------------------------------------*/

typedef struct key

{
	char const * phrase;
	uint8_t DAK [HPAVKEY_DAK_LEN];
	uint8_t NMK [HPAVKEY_NMK_LEN];
}

key;

extern struct key const keys [KEYS];

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

extern struct _term_ const daks [DAKS];
extern struct _term_ const nmks [NMKS];


/*====================================================================*
 *   functions;
 *--------------------------------------------------------------------*/

void MACPasswords (unsigned vendor, unsigned device, unsigned count, unsigned alpha, unsigned bunch, char space, flag_t flags);
void RNDPasswords (unsigned vendor, unsigned device, unsigned count, unsigned alpha, unsigned bunch, char space, flag_t flags);
char * strnpwd (char buffer [], unsigned length, unsigned count, unsigned group, char space);
void putpwd (unsigned count, unsigned group, char space);

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif

