/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFirmware2 (struct plc * plc);
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

#ifndef READFIRMWARE2_SOURCE
#define READFIRMWARE2_SOURCE

#include "../plc/plc.h" 

signed ReadFirmware2 (struct plc * plc)

{
	return (ModuleRead (plc, & plc->nvm, PLC_MOD_OP_READ_MEMORY, PLC_MODULEID_FIRMWARE, 0));
}

#endif



