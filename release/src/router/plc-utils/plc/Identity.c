/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed Identity (struct plc * plc);
 *
 *   plc.h
 *
 *   select the appropriate function based on the device type;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef IDENTITY_SOURCE
#define IDENTITY_SOURCE

#include "../plc/plc.h" 

signed Identity (struct plc * plc)

{
	return (PLCSelect (plc, Identity1, Identity2));
}

#endif



