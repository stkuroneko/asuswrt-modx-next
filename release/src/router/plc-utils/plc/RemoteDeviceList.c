/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed RemoteDeviceList (struct channel * channel, char const * space);
 *
 *   print the neighbor device list on stdout;
 *
 *--------------------------------------------------------------------*/

#ifndef REMOTEDEVICELIST_SOURCE
#define REMOTEDEVICELIST_SOURCE

#include "../plc/plc.h"

signed RemoteDeviceList (struct plc * plc, char const * space, char const * comma)

{
	return ((plc->hardwareID < CHIPSET_AR7400)? RemoteDeviceList1 (plc, space, comma): RemoteDeviceList2 (plc, space, comma));
}

#endif



