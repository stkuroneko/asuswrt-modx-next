/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed EraseFlashMemory (struct plc * plc);
 *
 *   plc.h
 *
 *   select the appropriate function based on the device type;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ERASEFLASHMEMORY_SOURCE
#define ERASEFLASHMEMORY_SOURCE

#include <string.h>

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed EraseReadFlashMemory (struct plc * plc)

{
	return (PLCSelect (plc, EraseFlashMemory1, EraseFlashMemory2));
}

#endif



