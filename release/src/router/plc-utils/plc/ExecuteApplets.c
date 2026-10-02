/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ExecuteApplets (struct plc * plc);
 *
 *   plc.h
 *
 *   call appropriate ExecuteApplets function based on detected NVM
 *   file format;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef EXECUTEAPPLETS_SOURCE
#define EXECUTEAPPLETS_SOURCE

#include "../plc/plc.h"

signed ExecuteApplets (struct plc * plc)

{
	return (NVMSelect (plc, ExecuteApplets1, ExecuteApplets2));
}

#endif



