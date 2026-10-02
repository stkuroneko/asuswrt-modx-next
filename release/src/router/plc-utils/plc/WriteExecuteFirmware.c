/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WriteExecuteFirmware (struct plc * plc, unsigned module, void const * nvm_header);
 *
 *   plc.h
 *
 *   call appropriate firmware download function based on the
 *   image file format;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef WRITEEXECUTEFIRMWARE_SOURCE
#define WRITEEXECUTEFIRMWARE_SOURCE

#include "../plc/plc.h" 

signed WriteExecuteFirmware (struct plc * plc, unsigned module, void const * nvm_header)

{
	return ((LE32TOH (* (uint32_t *) (nvm_header)) == 0x60000000)? WriteExecuteFirmware1 (plc, module, nvm_header): WriteExecuteFirmware2 (plc, module, nvm_header));
}

#endif



