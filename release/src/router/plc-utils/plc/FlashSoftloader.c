/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed FlashSoftloader (struct plc * plc, uint32_t options);
 *
 *   plc.h
 *
 *   This plugin upgrades a device having NVRAM; runtime firmware must
 *   be running for this to work; NVM and PIB files in struct plc must
 *   be opened before calling this plugin; this plugin is used by many
 *   programs;
 *
 *   WriteModuleParameters and WriteModuleFirmware use VS_MODULE_OPERATION instead
 *   of VS_WR_MOD and VS_MOD_NVM messages;
 *
 *   This function is for panther/lynx devices although is should also
 *   work for AR7400 devices, too.
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FLASHSOFTLOADER_SOURCE
#define FLASHSOFTLOADER_SOURCE

#include "../plc/plc.h"

signed FlashSoftloader (struct plc * plc, uint32_t options)

{
	struct vs_module_spec vs_module_spec =
	{
		PLC_MODULEID_SOFTLOADER,
		0,
		0,
		0
	};
	ModuleSpec (& plc->SFT, & vs_module_spec);
	if (ModuleSession (plc, 1, & vs_module_spec))
	{
		return (-1);
	}
	if (ModuleWrite (plc, & plc->SFT, 0, & vs_module_spec))
	{
		return (-1);
	}
	if (ModuleCommit (plc, options))
	{
		return (-1);
	}
	return (0);
}

#endif



