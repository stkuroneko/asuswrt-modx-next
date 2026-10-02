/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFirmware3 (struct plc * plc);
 *
 *   plc.h
 *
 *   Read the firmware from flash memory using VS_MODULE_OPERATION
 *   messages and write to file;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFIRMWARE3_SOURCE
#define READFIRMWARE3_SOURCE

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed ReadFirmware3 (struct plc * plc)

{
	return (~ AccessLevelPTS (plc)? ModuleRead (plc, & plc->pib, PLC_MOD_OP_READ_FLASH, PLC_MODULEID_FIRMWARE, 0): (-1));
}

#endif

