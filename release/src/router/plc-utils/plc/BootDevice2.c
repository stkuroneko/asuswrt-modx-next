/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed BootDevice2 (struct plc * plc);
 *
 *   plc.h
 *
 *   boot a powerline device by writing parameters and firmware into
 *   volatile memory and starting execution; volatile memory must be
 *   initialized and configured before calling this function;
 *
 *   this function is identical to BootDevice1 but calls functions
 *   that expect the newer image file format;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef BOOTDEVICE2_SOURCE
#define BOOTDEVICE2_SOURCE

#include <memory.h>

#include "../plc/plc.h"

signed BootDevice2 (struct plc * plc)

{
	char string [PLC_VERSION_STRING];
	if (BootParameters2 (plc))
	{
		return (-1);
	}
	if (BootFirmware2 (plc))
	{
		return (-1);
	}
	if (WaitForStart (plc, string, sizeof (string)))
	{
		return (-1);
	}
	Confirm (plc, "%s is running", string);
	return (0);
}

#endif



