/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed FlashDevice4 (struct plc * plc, uint32_t options);
 *
 *   plc.h
 *
 *   flash a QCA720 device in PTS mode; force a reset because reset
 *   is not automatic;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FLASHDEVICE4_SOURCE
#define FLASHDEVICE4_SOURCE

#include <string.h>

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed FlashDevice4 (struct plc * plc, uint32_t options)

{
	if (AccessLevelPTS (plc))
	{
		return (-1);
	}
	if (FlashDevice2 (plc, options))
	{
		return (-1);
	}
	sleep (PLC_PAUSE);
	return (0);
}

#endif


