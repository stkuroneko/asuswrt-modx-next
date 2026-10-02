/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

#ifndef TLVPEEK_SOURCE
#define TLVPEEK_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "../tools/types.h"
#include "../tools/error.h"
#include "../tools/memory.h"
#include "../tools/format.h"
#include "../lldp/lldp.h"

/*====================================================================*
 *
 *   void TLVPeek (void const * memory, size_t extent); 
 *
 *   lldp.h
 *
 *   search an IEEE 802.1AB TLV list for known types and print the
 *   values on stdout; runtime software will store values instead
 *   printing them;
 *
 *   this function handles Qualcomm Atheros Organizationally Specific 
 *   TLVs;    
 *   
 *--------------------------------------------------------------------*/

static void TLVPeekOS (void const * memory, size_t extent) 

{ 
	static const byte localcast [] = 
	{ 
		0x00, 
		0xB0, 
		0x52
	}; 
	struct tlv_os * tlv_os = (struct tlv_os *) (memory); 
	if (! memcmp (tlv_os->OUI, localcast, sizeof (tlv_os->OUI))) 
	{ 
		char buffer [TLV_SIZE_MASK + 1] = 
		{ 
			0
		}; 
		uint16_t mysize = TLV_SIZE (tlv_os); 
		switch (tlv_os->subtype) 
		{ 
		case TLV_OS_MANUFACTURER: 
			printf ("MFG %s\n", tlv_os->data); 
			break; 
		case TLV_OS_HARDWARE_MODEL: 
			printf ("MDL %s\n", tlv_os->data); 
			break; 
		case TLV_OS_SERIAL_NUMBER: 
			printf ("S/N %s\n", tlv_os->data); 
			break; 
		case TLV_OS_PLC_MAC: 
			printf ("PLC MAC %s\n", hexstring (buffer, sizeof (buffer), tlv_os->data, mysize)); 
			break; 
		case TLV_OS_HOST_MAC: 
			printf ("HOST MAC %s\n", hexstring (buffer, sizeof (buffer), tlv_os->data, mysize)); 
			break; 
		case TLV_OS_WIFI_MAC: 
			printf ("WIFI MAC %s\n", hexstring (buffer, sizeof (buffer), tlv_os->data, mysize)); 
			break; 
		case TLV_OS_WIFI_IP: 
			printf ("WIFI IP %s\n", decstring (buffer, sizeof (buffer), tlv_os->data, mysize)); 
			break; 
		default: 
			break; 
		} 
	} 
	fflush (stdout); 
	return; 
} 

/*====================================================================*
 *
 *   void ChassisID (void const * memory, ssize_t extent);
 *
 *   decode Chassis ID TLV per IEEE 802.1AB, Clause 8.5.2; 
 *
 *   this code does not handle all possible option; users must add
 *   missing code that they require;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void ChassisID (void const * memory, ssize_t extent) 

{ 
	struct tlv_id * tlv_id = (struct tlv_id *) (memory); 
	char buffer [TLV_SIZE_MASK + 1] = 
	{ 
		0
	}; 
	switch (tlv_id->subtype) 
	{ 
	case 1: 
		break; 
	case 2: 
		break; 
	case 3: 
		break; 
	case 4: 
		printf ("Chassis MAC: %s\n", hexstring (buffer, sizeof (buffer), tlv_id->data, 6)); 
		break; 
	case 5: 
		break; 
	case 6: 
		break; 
	case 7: 
		printf ("Chassis ID: %s\n", (char *) (tlv_id->data)); 
		break; 
	default: 
		error (0, EINVAL, "Unknown Chassis ID subtype (%d)", tlv_id->subtype); 
		break; 
	} 
	return; 
} 

/*====================================================================*
 *
 *   void PortID (void const * memory, ssize_t extent);
 *
 *   decode Port ID TLV per IEEE 802.1AB, Clause 8.5.3; 
 *
 *   this code does not handle all possible option; users must add
 *   missing code that they require;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void PortID (void const * memory, ssize_t extent) 

{ 
	struct tlv_id * tlv_id = (struct tlv_id *) (memory); 
	char buffer [TLV_SIZE_MASK + 1] = 
	{ 
		0
	}; 
	switch (tlv_id->subtype) 
	{ 
	case 1: 
		break; 
	case 2: 
		break; 
	case 3: 
		printf ("Port MAC: %s\n", hexstring (buffer, sizeof (buffer), tlv_id->data, 6)); 
		break; 
	case 4: 
		break; 
	case 5: 
		break; 
	case 6: 
		break; 
	case 7: 
		printf ("Port ID: %s\n", (char *) (tlv_id->data)); 
		break; 
	default: 
		error (0, EINVAL, "Unknown Port ID subtype (%d)", tlv_id->subtype); 
		break; 
	} 
	return; 
} 

/*====================================================================*
 *
 *   void TimeToLive (void const * memory, ssize_t extent);
 * 
 *   decode Time To Live TLV per IEEE 802.1AB, Clause 8.5.4; this
 *   TLV is an unsigned 16-bit integer;
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void TimeToLive (void const * memory, ssize_t extent) 

{ 
	if (extent != sizeof (uint16_t)) 
	{ 
		error (0, EINVAL, "TTL Data Length Error"); 
	} 
	printf ("TTL %d\n", BE16TOH (* (uint16_t *) (memory))); 
	return; 
} 

/*====================================================================*
 *
 *   void PortDescription (void const * memory, ssize_t extent);
 *
 *   decode Port Description per IEEE 802.1AB, Clause 8.5.5; this 
 *   TLV is a string having up to 254 octets; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void PortDescription (void const * memory, ssize_t extent) 

{ 
	if (extent > TLV_SIZE_MASK) 
	{ 
		error (0, EINVAL, "Port Description Length Error"); 
	} 
	printf ("Port Description: %s\n", (char *) (memory)); 
	return; 
} 

/*====================================================================*
 *
 *   void SystemName (void const * memory, ssize_t extent);
 *
 *   decode System Name per IEEE 802.1AB, Clause 8.5.6; this TLV is
 *   a string having up to 254 octets; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void SystemName (void const * memory, ssize_t extent) 

{ 
	if (extent > TLV_SIZE_MASK) 
	{ 
		error (0, EINVAL, "System Name Length Error"); 
	} 
	printf ("System Name: %s\n", (char *) (memory)); 
	return; 
} 

/*====================================================================*
 *
 *   void SystemDescription (void const * memory, ssize_t extent);
 *
 *   decode System Name per IEEE 802.1AB, Clause 8.5.7; this TLV is
 *   a string having up to 254 octets; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void SystemDescription (void const * memory, ssize_t extent) 

{ 
	if (extent > TLV_SIZE_MASK) 
	{ 
		error (0, EINVAL, "System Description Length Error"); 
	} 
	printf ("System Description: %s\n", (char *) (memory)); 
	return; 
} 

/*====================================================================*
 *
 *   void SystemCapability (void const * memory, ssize_t extent);
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void SystemCapability (void const * memory, ssize_t extent) 

{ 
	struct cap 
	{ 
		uint8_t subtype; 
		uint16_t available; 
		uint16_t enabled; 
	} 
	* cap = (struct cap *) (memory); 
	char const * capabilities [] = 
	{ 
		"Other", 
		"Repeater", 

#if 0

/*
 *   Full capability names from IEEE 802.1AB-2009;
 */

		"MAC Bridge", 
		"WLAN Access Point", 
		"Router", 
		"Telephone", 
		"DOCSIS Cable Device", 
		"Station Only", 
		"C-VLAN Component of VLAN Bridge", 
		"S-VLAN Component of VLAN Bridge", 
		"Two-port MAC Relay (TPMR)", 

#else

/*
 *   Abbreviated capability names compact display;
 */

		"Bridge", 
		"AP", 
		"Router", 
		"Voice", 
		"DOCSIS", 
		"Station", 
		"C-VLAN", 
		"S-VLAN", 
		"TPMR", 

#endif

		(char const *) (0)
	}; 
	char buffer [TLV_SIZE_MASK + 1] = 
	{ 
		0
	}; 
	strfbits (buffer, sizeof (buffer), capabilities, ", ", BE16TOH (cap->available)); 
	printf ("Feature: %s\n", buffer); 
	strfbits (buffer, sizeof (buffer), capabilities, ", ", BE16TOH (cap->available)); 
	printf ("Enabled: %s\n", buffer); 
	return; 
} 

/*====================================================================*
 *
 *   void ManagementAddress (void const * memory, ssize_t extent) 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

static void ManagementAddress (void const * memory, ssize_t extent) 

{ 
	printf ("MGMT URL: %s\n", (char *) (memory)); 
	return; 
} 

/*====================================================================*
 *
 *   void TLVPeek (void const * memory, ssize_t extent);
 *
 *   lldp.h
 *
 *   search an IEEE 802.1AB TLV list for known types and print the
 *   values on stdout; runtime software will store values instead
 *   printing them;
 *
 *   this function handles Qualcomm Atheros Organizationally Specific 
 *   TLVs;    
 *   
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

void TLVPeek (void const * memory, size_t extent) 

{ 
	byte * offset = (void *) (memory); 
	while (extent > 0) 
	{ 
		struct tlv * tlv = (struct tlv *) (offset); 
		uint16_t mytype = TLV_TYPE (tlv); 
		uint16_t mysize = TLV_SIZE (tlv); 
		if (! tlv->head) 
		{ 
			break; 
		} 
		switch (mytype) 
		{ 
		case TLV_IEEE_CHASSIS_ID: 
			ChassisID (tlv->data, mysize); 
			break; 
		case TLV_IEEE_PORT_ID: 
			PortID (tlv->data, mysize); 
			break; 
		case TLV_IEEE_TIME_TO_LIVE: 
			TimeToLive (tlv->data, mysize); 
			break; 
		case TLV_IEEE_PORT_DESCRIPTION: 
			PortDescription (tlv->data, mysize); 
			break; 
		case TLV_IEEE_SYSTEM_NAME: 
			SystemName (tlv->data, mysize); 
			break; 
		case TLV_IEEE_SYSTEM_DESCRIPTION: 
			SystemDescription (tlv->data, mysize); 
			break; 
		case TLV_IEEE_SYSTEM_CAPABILITIES: 
			SystemCapability (tlv->data, mysize); 
			break; 
		case TLV_IEEE_MANAGEMENT_ADDRESS: 
			ManagementAddress (tlv->data, mysize); 
			break; 
		case TLV_IEEE_ORG_SPECIFIC: 
			TLVPeekOS (offset, extent); 
			mysize += 4; 
			break; 
		default: 
			break; 
		} 
		offset += sizeof (* tlv) +  mysize; 
		extent -= sizeof (* tlv) +  mysize; 
	} 
	printf ("\n"); 
	return; 
} 

#endif



