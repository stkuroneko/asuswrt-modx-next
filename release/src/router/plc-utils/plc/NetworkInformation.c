/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed NetworkInformation (struct plc * plc);
 *
 *   plc.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NETWORKINFORMATION_SOURCE
#define NETWORKINFORMATION_SOURCE

#include "../plc/plc.h"

signed NetworkInformation (struct plc * plc)

{
	return (PLCSelect (plc, NetworkInformation1, NetworkInformation2));
}

#endif



