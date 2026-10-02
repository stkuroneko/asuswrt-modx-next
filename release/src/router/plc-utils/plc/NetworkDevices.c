/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed NetworkDevices (struct plc * plc, void * memory, size_t extent);
 *
 *   plc.h
 *
 *   return a list powerline network device addresses on a powerline
 *   network; the list consists of a known device plus all others on
 *   the same powerline network; the device is defined by the channel
 *   peer address and appears first in the list;
 *
 *   the device address must be explicit; it cannot be the broadcast
 *   or localcast address;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef NETWORKDEVICES_SOURCE
#define NETWORKDEVICES_SOURCE

#include "../plc/plc.h"

signed NetworkDevices (struct plc * plc, void * memory, size_t extent)

{
	return ((plc->hardwareID < CHIPSET_AR7400)? NetworkDevices1 (plc, memory, extent): NetworkDevices2 (plc, memory, extent));
}

#endif



