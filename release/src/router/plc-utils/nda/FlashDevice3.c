/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed FlashDevice3 (struct plc * plc);
 *
 *   plc.h
 *
 *   permanently write parameters and firmware to flash memory using
 *   VS_WR_MOD messagesand VS_MOD_NVM messages;
 *
 *   paramters and firmware are written to device SDRAM and stored
 *   until commited to flash memory;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FLASHDEVICE3_SOURCE
#define FLASHDEVICE3_SOURCE

#include "../plc/plc.h"

signed FlashDevice3 (struct plc * plc)

{
	if (WritePIB (plc))
	{
		return (-1);
	}
	if (WriteNVM (plc))
	{
		return (-1);
	}
	if (FlashPTS (plc))
	{
		return (-1);
	}
	if (WaitForRestart (plc))
	{
		return (-1);
	}
	sleep (PLC_PAUSE);
	return (0);
}

#endif

