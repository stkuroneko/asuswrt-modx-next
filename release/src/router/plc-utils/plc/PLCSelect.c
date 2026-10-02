/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/
/*====================================================================*
 *
 *   signed PLCSelect (struct plc * plc, signed old (struct plc *), signed new (struct plc *));
 *
 *   plc.h
 *
 *   wait for device to start in order to determine chipset then call
 *   the approproate function based on chipset; unfortunately, chipset
 *   detection and selection may not be this simple in the future;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PLCSELECT_SOURCE
#define PLCSELECT_SOURCE

#include <stdlib.h>

#include "../plc/plc.h"

signed PLCSelect (struct plc * plc, signed old (struct plc *), signed new (struct plc *))

{
	char firmware [PLC_VERSION_STRING];
	if (WaitForStart (plc, firmware, sizeof (firmware)))
	{
		Failure (plc, PLC_NODETECT);
		exit (1);
	}
	return ((plc->hardwareID < CHIPSET_AR7400)? old (plc): new (plc));
}

#endif



