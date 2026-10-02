/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed ReadFirmware (struct plc * plc);
 *
 *   plc.h
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef READFIRMWARE_SOURCE
#define READFIRMWARE_SOURCE

#include "../plc/plc.h" 

signed ReadFirmware (struct plc * plc)

{
	return (PLCSelect (plc, ReadFirmware1, ReadFirmware2));
}

#endif



