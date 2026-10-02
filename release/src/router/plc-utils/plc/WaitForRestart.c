/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WaitForRestart (struct plc * plc, char string [], size_t length);
 *
 *   plc.h
 *
 *   wait for the local powerline device to reset then start again;
 *   this function may be called to stop the program from returning
 *   to the command line until a flash or reset action is completed;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef WAITFORRESTART_SOURCE
#define WAITFORRESTART_SOURCE


#include "../plc/plc.h"
#include "../tools/error.h"
#include "../tools/flags.h"

signed WaitForRestart (struct plc * plc)

{
	if (_allclr (plc->flags, PLC_QUICK_FLASH))
	{
		char firmware [PLC_VERSION_STRING];
		unsigned timer = plc->timer;
		if (WaitForReset (plc))
		{
			error ((plc->flags & PLC_BAILOUT), 0, "Device did not Reset");
			return (-1);
		}
		plc->timer = PLC_FLASH;
		if (WaitForStart (plc, firmware, sizeof (firmware)))
		{
			error ((plc->flags & PLC_BAILOUT), 0, "Device did not Start");
			plc->timer = timer;
			return (-1);
		}
		plc->timer = timer;
	}
	return (0);
}


#endif

