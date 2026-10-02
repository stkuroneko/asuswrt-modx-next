/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed WriteExecuteParameters (struct plc * plc, unsigned module, void const * nvm_header);
 *
 *   plc.h
 *
 *   call appropriate parameter block downlaod function based on
 *   the image file format;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef WRITEEXECUTEPARAMETERS_SOURCE
#define WRITEEXECUTEPARAMETERS_SOURCE

#include "../plc/plc.h" 

signed WriteExecuteParameters (struct plc * plc, unsigned module, void const * nvm_header)

{
	return ((LE32TOH (* (uint32_t *) (nvm_header)) == 0x60000000)? WriteExecuteParameters1 (plc, module, nvm_header): WriteExecuteParameters2 (plc, module, nvm_header));
}

#endif



