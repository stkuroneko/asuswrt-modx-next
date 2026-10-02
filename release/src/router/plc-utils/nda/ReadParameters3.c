/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadParameters2 (struct plc * plc);
 *
 *   plc.h
 *
 *   Read the PIB Image from a QCA6410, QCA7000 or QCA7420 using as
 *   many VS_MODULE_OPERATION messages as needed; Write image blocks
 *   to file as they are read;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READPARAMETERS3_SOURCE
#define READPARAMETERS3_SOURCE

#include "../plc/plc.h" 
#include "../nda/nda.h" 

signed ReadParameters3 (struct plc * plc)

{
	return (~ AccessLevelPTS (plc)? ModuleRead (plc, & plc->pib, PLC_MOD_OP_READ_FLASH, PLC_MODULEID_PARAMETERS, 0): (-1));
}

#endif

