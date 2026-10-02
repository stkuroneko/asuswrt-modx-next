/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   Devices.c - device address synonym tables
 *
 *   plc.h
 *
 *   some device addresses are so common or significant that we give
 *   them names; users can enter the name instead of the address; all
 *   toolkit programs can search table devices [] with function 
 *   synonym();
 *
 *   function synonym() uses a binary search to lookup symbols and so
 *   they must be entered in alphabetical order or lookup errors will
 *   occur;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef DEVICES_SOURCE
#define DEVICES_SOURCE

/*====================================================================*
 *   custom include files;
 *--------------------------------------------------------------------*/

#include "../plc/plc.h"
#include "../mme/mme.h"
#include "../tools/types.h"

/*====================================================================*
 *   variables;
 *--------------------------------------------------------------------*/

struct _term_ const devices [PLCDEVICES] =

{
	{
		"all",
		BROADCAST
	},
	{
		"broadcast",
		BROADCAST
	},
	{
		"local",
		LOCALCAST
	}
};

byte const broadcast [ETHER_ADDR_LEN] =

{
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF,
	0xFF
};

byte const localcast [ETHER_ADDR_LEN] =

{
	0x00,
	0xB0,
	0x52,
	0x00,
	0x00,
	0x01
};

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif



