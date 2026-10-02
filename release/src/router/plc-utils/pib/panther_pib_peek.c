/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed panther_pib_peek (void const * memory);
 *
 *   pib.h
 *
 *   print Panther/Lynx PIB identity information on stdout; 
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef PANTHER_PIB_PEEK_SOURCE
#define PANTHER_PIB_PEEK_SOURCE

#include <stdio.h>
#include <memory.h>

#include "../tools/memory.h"
#include "../tools/number.h"
#include "../key/HPAVKey.h"
#include "../key/keys.h"
#include "../pib/pib.h"

static char const * CCoMode2 [] = 

{ 
	"Auto", 
	"Never", 
	"Always", 
	"User", 
	"Covert", 
	"Unknown"
}; 

static char const * MDURole2 [] = 

{ 
	"Slave", 
	"Master"
}; 

signed panther_pib_peek (void const * memory) 

{ 
	extern const struct key keys [KEYS]; 
	struct PIB3_0 * PIB = (struct PIB3_0 *) (memory); 
	char buffer [HPAVKEY_SHA_LEN * 3]; 
	size_t key; 
	printf ("\tPIB %d-%d %d bytes\n", PIB->VersionHeader.FWVersion, PIB->VersionHeader.PIBVersion, LE16TOH (PIB->VersionHeader.PIBLength)); 
	printf ("\tMAC %s\n", hexstring (buffer, sizeof (buffer), PIB->LocalDeviceConfig.MAC, sizeof (PIB->LocalDeviceConfig.MAC))); 
	printf ("\tDAK %s", hexstring (buffer, sizeof (buffer), PIB->LocalDeviceConfig.DAK, sizeof (PIB->LocalDeviceConfig.DAK))); 
	for (key = 0; key < KEYS; key++) 
	{ 
		if (! memcmp (keys [key].DAK, PIB->LocalDeviceConfig.DAK, HPAVKEY_DAK_LEN)) 
		{ 
			printf (" (%s)", keys [key].phrase); 
			break; 
		} 
	} 
	printf ("\n"); 
	printf ("\tNMK %s", hexstring (buffer, sizeof (buffer), PIB->LocalDeviceConfig.NMK, sizeof (PIB->LocalDeviceConfig.NMK))); 
	for (key = 0; key < KEYS; key++) 
	{ 
		if (! memcmp (keys [key].NMK, PIB->LocalDeviceConfig.NMK, HPAVKEY_NMK_LEN)) 
		{ 
			printf (" (%s)", keys [key].phrase); 
			break; 
		} 
	} 
	printf ("\n"); 
	printf ("\tNID %s\n", hexstring (buffer, sizeof (buffer), PIB->LocalDeviceConfig.PreferredNID, sizeof (PIB->LocalDeviceConfig.PreferredNID))); 
	printf ("\tNET %s\n", PIB->LocalDeviceConfig.NET); 
	printf ("\tMFG %s\n", PIB->LocalDeviceConfig.MFG); 
	printf ("\tUSR %s\n", PIB->LocalDeviceConfig.USR); 
	printf ("\tCCo %s\n", CCoMode2 [PIB->LocalDeviceConfig.CCoSelection > SIZEOF (CCoMode2) - 1? SIZEOF (CCoMode2) - 1: PIB->LocalDeviceConfig.CCoSelection]); 
	printf ("\tMDU %s\n", PIB->LocalDeviceConfig.MDUConfiguration? MDURole2 [PIB->LocalDeviceConfig.MDURole & 1]: "N/A"); 
	return (0); 
} 

#endif



