/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed NetworkTraffic (struct plc * plc);
 *
 *   plc.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NETWORKTRAFFIC_SOURCE
#define NETWORKTRAFFIC_SOURCE

#include "../plc/plc.h"

signed NetworkTraffic (struct plc * plc)

{
	return ((plc->hardwareID < CHIPSET_AR7400)? NetworkTraffic1 (plc): NetworkTraffic2 (plc));
}

#endif



