/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WriteFirmware (struct plc * plc, unsigned module, void const * nvm_header);
 *
 *   plc.h
 *
 *   call appropriate function based on the image file format;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef WRITEFIRMWARE_SOURCE
#define WRITEFIRMWARE_SOURCE

#include "../plc/plc.h" 

signed WriteFirmware (struct plc * plc, unsigned module, void const * nvm_header)

{
	return ((LE32TOH (* (uint32_t *) (nvm_header)) == 0x60000000)? WriteFirmware1 (plc, module, nvm_header): WriteFirmware2 (plc, module, nvm_header));
}

#endif



