/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed EraseFlashMemory3 (struct plc * plc);
 *
 *   plc.h
 *
 *   select the appropriate function based on the PLC device type;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef ERASEFLASHMEMORY3_SOURCE
#define ERASEFLASHMEMORY3_SOURCE

#include <string.h>

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed EraseFlashMemory3 (struct plc * plc)

{
	return (~ AccessLevelPTS (plc)? EraseFlashMemory2 (plc): (-1));
}

#endif



