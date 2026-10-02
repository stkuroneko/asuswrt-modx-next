/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ListRemoteDevices (struct channel * channel, char const * space);
 *
 *   print the neighbor device list on stdout;
 *
 *--------------------------------------------------------------------*/

#ifndef LISTREMOTEDEVICES_SOURCE
#define LISTREMOTEDEVICES_SOURCE

#include "../plc/plc.h"

signed ListRemoteDevices (struct plc * plc, char const * space, char const * comma)

{
	return ((plc->hardwareID < CHIPSET_AR7400)? ListRemoteDevices1 (plc, space, comma): ListRemoteDevices2 (plc, space, comma));
}

#endif



