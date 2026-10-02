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

#ifndef READPARAMETERS2_SOURCE
#define READPARAMETERS2_SOURCE

#include "../plc/plc.h" 

signed ReadParameters2 (struct plc * plc)

{
	return (ModuleRead (plc, & plc->pib, PLC_MOD_OP_READ_MEMORY, PLC_MODULEID_PARAMETERS, 0));
}

#endif



