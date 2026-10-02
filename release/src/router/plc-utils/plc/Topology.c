/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Topology (struct plc * plc);
 *
 *   plc.h
 *
 *   call appropriate topology module based on the PLC device
 *   type;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef TOPOLOGY_SOURCE
#define TOPOLOGY_SOURCE

#include "../plc/plc.h"

signed Topology (struct plc * plc)

{
	return (PLCSelect (plc, Topology1, Topology2));
}

#endif



