/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed FlashParameters (struct plc * plc, uint32_t options);
 *
 *   plc.h
 *
 *   write runtime powerline parameters into flash memory using
 *   VS_MODULE_OPERATION messages;
 *
 *   struct vs_module_spec is defined in plc.h;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef FLASHPARAMETERS_SOURCE
#define FLASHPARAMETERS_SOURCE

#include "../plc/plc.h"

signed FlashParameters (struct plc * plc, uint32_t options)

{
	struct vs_module_spec vs_module_spec =
	{
		PLC_MODULEID_PARAMETERS,
		0,
		0,
		0
	};
	ModuleSpec (& plc->PIB, & vs_module_spec);
	if (ModuleSession (plc, 1, & vs_module_spec))
	{
		return (-1);
	}
	if (ModuleWrite (plc, & plc->PIB, 0, & vs_module_spec))
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



