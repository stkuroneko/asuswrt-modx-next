/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   pibrump.c - Qualcomm Atheros Classification Rule Dump Utility;
 *
 *   This program read classification rules stored in a PIB file and
 *   prints them on stdout in a format similar to int6krule commands;
 *   
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *   system header files;
 *--------------------------------------------------------------------*/

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*====================================================================*
 *   custom header files;
 *--------------------------------------------------------------------*/

#include "../tools/getoptv.h"
#include "../tools/memory.h"
#include "../tools/symbol.h"
#include "../tools/types.h"
#include "../tools/flags.h"
#include "../tools/files.h"
#include "../tools/error.h"
#include "../pib/pib.h"
#include "../plc/rules.h"

/*====================================================================*
 *   custom source files;
 *--------------------------------------------------------------------*/

#ifndef MAKEFILE
#include "../tools/getoptv.c"
#include "../tools/putoptv.c"
#include "../tools/version.c"
#include "../tools/lookup.c"
#include "../tools/reword.c"
#include "../tools/hexstring.c"
#include "../tools/hexdecode.c"
#include "../tools/fdchecksum32.c"
#include "../tools/memout.c"
#include "../tools/error.c"
#endif

#ifndef MAKEFILE
#include "../pib/lightning_pib_file.c"
#endif

#ifndef MAKEFILE
#include "../plc/rules.c"
#include "../plc/PrintRule.c"
#endif

/*====================================================================*
 *   program constants;
 *--------------------------------------------------------------------*/

#define PIB_MAX_AUTOCONN 16
#define PIB_MAX_PRIORITY_MAPS 8

#define PIB_AUTOCONN_COUNT_OFFSET 0x22C
#define PIB_PRIORITY_COUNT_OFFSET 0x228

#define PIB_AUTOCONN_OFFSET 0x310
#define PIB_PRIORITY_MAPS_OFFSET 0x230

/*====================================================================*
 *
 *   signed AutoConnection (struct auto_connection * auto_connection, flag_t flags) 
 *
 *   plc.h
 *
 *   This function for program pibrump displays a single AutoConnection
 *   structure;
 *
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

signed AutoConnection (struct auto_connection * auto_connection) 

{ 
	int i; 
	const char * p1; 
	const char * p2; 
	if (auto_connection->MACTION == ACTION_TAGTX) 
	{ 
		printf ("-T 0x%08X -V %d ", ntohl (auto_connection->cspec.VLAN_TAG), LE16TOH (auto_connection->cspec.CSPEC_VERSION)); 
	} 
	p1 = reword (auto_connection->MACTION, actions, SIZEOF (actions)); 
	if (p1 == NULL) 
	{ 
		error (1, 0, "invalid classifier action"); 
	} 
	p2 = reword (auto_connection->MOPERAND, operands, SIZEOF (operands)); 
	if (p2 == NULL) 
	{ 
		error (1, 0, "invalid classifier operand"); 
	} 
	printf ("%s %s ", p1, p2); 
	for (i = 0; i < LE16TOH (auto_connection->NUM_CLASSIFIERS); ++ i) 
	{ 
		struct PIBClassifier * classifier = & auto_connection->CLASSIFIER [i]; 
		PrintRule (classifier->CR_PID, classifier->CR_OPERAND, classifier->CR_VALUE); 
		putchar (' '); 
	} 
	printf ("add perm\n"); 
	return (0); 
} 

/*====================================================================*
 *
 *   signed ClassifierPriorityMap (struct classifier_priority_map * map) 
 *
 *   plc.h
 *
 *   This function for program pibrump displays a single
 *   ClassifierPriorityMap structure;
 *
 *   Contributor(s):
 *      Nathaniel Houghton <nhoughto@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

signed ClassifierPriorityMap (struct classifier_priority_map * map) 

{ 
	struct PIBClassifier * classifier = & map->CLASSIFIER; 
	const char * p = reword (LE32TOH (map->Priority), actions, SIZEOF (actions)); 
	if (p == NULL) 
	{ 
		error (1, 0, "invalid classifier priority"); 
	} 
	printf ("%s Any ", p); 
	PrintRule (classifier->CR_PID, classifier->CR_OPERAND, classifier->CR_VALUE); 
	printf (" add perm\n"); 
	return (0); 
} 

/*====================================================================*
 *   
 *   int main (int argc, char const * argv[]);
 *   
 *
 *--------------------------------------------------------------------*/

int main (int argc, char const * argv []) 

{ 
	static char const * optv [] = 
	{ 
		"eqv", 
		"pibfile", 
		"Qualcomm Atheros Classification Rule Dump Utility", 
		"e\tredirect stderr messages to stdout", 
		"q\tquiet mode", 
		"v\tverbose mode", 
		(char const *) (0)
	}; 
	struct auto_connection auto_connection [PIB_MAX_AUTOCONN]; 
	struct classifier_priority_map classifier_priority_map [PIB_MAX_PRIORITY_MAPS]; 
	uint32_t AutoConnection_count; 
	uint32_t PriorityMaps_count; 
	unsigned i; 
	flag_t flags = (flag_t) (0); 
	struct _file_ pib; 
	signed c; 
	optind = 1; 
	while (~ (c = getoptv (argc, argv, optv))) 
	{ 
		switch ((char) (c)) 
		{ 
		case 'e': 
			dup2 (STDOUT_FILENO, STDERR_FILENO); 
			break; 
		case 'q': 
			_setbits (flags, PIB_SILENCE); 
			break; 
		case 'v': 
			_setbits (flags, PIB_VERBOSE); 
			break; 
		default: 
			break; 
		} 
	} 
	argc -= optind; 
	argv += optind; 
	while ((argc) && (* argv)) 
	{ 
		pib.name = * argv; 
		if ((pib.file = open (pib.name, O_BINARY | O_RDONLY)) == - 1) 
		{ 
			error (1, errno, "%s", pib.name); 
		} 
		if (lightning_pib_file (& pib)) 
		{ 
			error (1, errno, "Bad PIB file: %s", pib.name); 
		} 
		if (lseek (pib.file, PIB_AUTOCONN_COUNT_OFFSET, SEEK_SET) != PIB_AUTOCONN_COUNT_OFFSET) 
		{ 
			error (1, errno, "could not seek to AutoConnection count"); 
		} 
		if (read (pib.file, & AutoConnection_count, sizeof (AutoConnection_count)) != sizeof (AutoConnection_count)) 
		{ 
			error (1, errno, "could not read AutoConnection count"); 
		} 
		if (lseek (pib.file, PIB_AUTOCONN_OFFSET, SEEK_SET) != PIB_AUTOCONN_OFFSET) 
		{ 
			error (1, errno, "could not seek to AutoConnections"); 
		} 
		if (read (pib.file, & auto_connection, sizeof (auto_connection)) != sizeof (auto_connection)) 
		{ 
			error (1, errno, "could not read AutoConnections"); 
		} 
		if (lseek (pib.file, PIB_PRIORITY_COUNT_OFFSET, SEEK_SET) != PIB_PRIORITY_COUNT_OFFSET) 
		{ 
			error (1, errno, "could not seek to PriorityMaps count"); 
		} 
		if (read (pib.file, & PriorityMaps_count, sizeof (PriorityMaps_count)) != sizeof (PriorityMaps_count)) 
		{ 
			error (1, errno, "could not read PriorityMaps count"); 
		} 
		if (lseek (pib.file, PIB_PRIORITY_MAPS_OFFSET, SEEK_SET) != PIB_PRIORITY_MAPS_OFFSET) 
		{ 
			error (1, errno, "could not seek to Priority Map"); 
		} 
		if (read (pib.file, & classifier_priority_map, sizeof (classifier_priority_map)) != sizeof (classifier_priority_map)) 
		{ 
			error (1, errno, "could not read Priority Map"); 
		} 
		close (pib.file); 
		if (_allclr (flags, PIB_SILENCE)) 
		{ 
			printf ("# auto connection rules:\n"); 
		} 
		for (i = 0; i < AutoConnection_count; ++ i) 
		{ 
			AutoConnection (& auto_connection [i]); 
		} 
		if (_allclr (flags, PIB_SILENCE)) 
		{ 
			printf ("# priority mapping rules:\n"); 
		} 
		for (i = 0; i < PriorityMaps_count; ++ i) 
		{ 
			ClassifierPriorityMap (& classifier_priority_map [i]); 
		} 
		argv++; 
		argc--; 
	} 
	exit (0); 
} 

