/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   signed  Traffic (struct plc * plc);
 *
 *   plc.h
 *
 *   generate bi-directional traffic between a local device and all
 *   remote devices on a powerline network; remote devices need not
 *   be connected; no traffic is generated between remote devices;
 *
 *   this function is similar to NetworkTraffic but takes less time
 *   since not all powerline paths are exercised and those that are
 *   can be exercised in parallel;
 *
 *--------------------------------------------------------------------*/

#ifndef TRAFFIC_SOURCE
#define TRAFFIC_SOURCE

#include "../plc/plc.h"

signed Traffic (struct plc * plc)

{
	return (PLCSelect (plc, Traffic1, Traffic2));
}

#endif



