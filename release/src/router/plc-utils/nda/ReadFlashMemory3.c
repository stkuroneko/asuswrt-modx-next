/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFlashMemory3 (struct plc * plc);
 *
 *   plc.h
 *
 *   call appropriate function if AccessLevelPTS permits it; return
 *   -1 if not;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFLASHMEMORY3_SOURCE
#define READFLASHMEMORY3_SOURCE

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed ReadFlashMemory3 (struct plc * plc)

{
	return (~ AccessLevelPTS (plc)? ReadFlashMemory2 (plc): (-1));
}

#endif



