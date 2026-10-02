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
 *   toolkit programs reference this table via function synonym();
 *
 *   function synonym() uses a binary search to lookup symbols and so
 *   they must be entered in alphabetical order or lookup errors will 
 *   occur;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef LLDP_SOURCE
#define LLDP_SOURCE

/*====================================================================*
 *   custom include files;
 *--------------------------------------------------------------------*/

#include "../tools/types.h"
#include "../lldp/lldp.h"

/*====================================================================*
 *   variables;
 *--------------------------------------------------------------------*/

struct _term_ const addresses [LLDP_ADDRESSES] = 

{ 
	{ 
		"broadcast", 
		BROADCAST
	}, 
	{ 
		"LLDP1", 
		LLDP_NEAREST_BRIDGE
	}, 
	{ 
		"LLDP2", 
		LLDP_NEAREST_NON_TMPR_BRIDGE
	}, 
	{ 
		"LLDP3", 
		LLDP_NEAREST_CUSTOMER_BRIDGE
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

byte const nearest_bridge [] = 

{ 
	0x01, 
	0x80, 
	0xC2, 
	0x00, 
	0x00, 
	0x0E
}; 

byte const nearest_non_tpmr_bridge [] = 

{ 
	0x01, 
	0x80, 
	0xC2, 
	0x00, 
	0x00, 
	0x03
}; 

byte const nearest_customer_bridge [] = 

{ 
	0x01, 
	0x80, 
	0xC2, 
	0x00, 
	0x00, 
	0x00
}; 

/*====================================================================*
 *   
 *--------------------------------------------------------------------*/

#endif



