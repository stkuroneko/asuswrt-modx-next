/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFlashMemory (struct plc * plc);
 *
 *   plc.h
 *
 *   select the appropriate function based on the device type;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFLASHMEMORY_SOURCE
#define READFLASHMEMORY_SOURCE

#include <string.h>

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed ReadReadFlashMemory (struct plc * plc)

{
	return (PLCSelect (plc, ReadFlashMemory1, ReadFlashMemory2));
}

#endif



