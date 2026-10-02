/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   struct StartFirmware (struct plc * plc, unsigned module, void const * header)
 *
 *   plc.h
 *
 *   This plugin starts software execution using VS_ST_MAC; despite
 *   an affirmative respond from the device, there is no guarantee
 *   that the firmware will actually start or continue to run so we
 *   wait for a response and report the result;
 *
 *   struct lightning_nvm_header must be little-endian order and ready to send
 *   to the device;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef STARTSOFTWARE_SOURCE
#define STARTSOFTWARE_SOURCE

#include <stdint.h>
#include <memory.h>

#include "../tools/error.h"
#include "../plc/plc.h"

signed StartFirmware (struct plc * plc, unsigned module, void const * header)

{
	return ((LE32TOH (* (uint32_t *) (header)) == 0x60000000)? StartFirmware1 (plc, module, header): StartFirmware2 (plc, module, header));
}

#endif



