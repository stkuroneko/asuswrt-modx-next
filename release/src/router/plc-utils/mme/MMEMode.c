/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   char const * MMEMode (uint16_t MMTYPE);
 *
 *   mme.h
 *
 *   Return the mneumoic associates with a HomePlug AV MME mode; All
 *   HomePlug AV message types permit four variants, as follows, but
 *   not all messages implement all four.
 *
 *      REQ unsolicited request from host to device;
 *      CNF solicited response from device to host;
 *      IND unsolicited request from device to host;
 *      RSP solicited responds from host to device;
 * 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef MMEMODE_SOURCE
#define MMEMODE_SOURCE

#include <stdint.h>

#include "../mme/mme.h"

static char const * mme_modes [] = 

{ 
	"REQ", 
	"CNF", 
	"IND", 
	"RSP"
}; 

char const * MMEMode (uint16_t MMTYPE) 

{ 
	return (mme_modes [MMTYPE & MMTYPE_MODE]); 
} 

#endif



