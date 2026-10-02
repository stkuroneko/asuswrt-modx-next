/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   PLCSession.c -
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef QCARAND_SOURCE
#define QCARAND_SOURCE

#include <stdint.h>

#include "../tools/number.h"

uint64_t QCASeed = 0;
uint64_t QCASRand (uint32_t seed)

{
	uint64_t temp = QCASeed;
	QCASeed = (uint64_t) (seed);
	return (temp);
}

uint32_t QCARand ()

{
	QCASeed *= 0x41C64E6D;
	QCASeed += 0x00003029;
	return ((uint32_t) ((QCASeed >> 0x10) & 0x7FFFFFFF));
}

#endif



