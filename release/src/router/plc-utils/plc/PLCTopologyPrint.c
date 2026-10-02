/*====================================================================*
*
*   Copyright (c) 2013 Qualcomm Atheros, Inc.
*
*   All rights reserved.
*
*====================================================================*/

/*====================================================================*
 *
 *   signed TopologyPrint (struct plcnetworks * plctopology);
 *
 *   plc.h
 *
 *   print plctopology structure in human readable format on stdout;
 *
 *   Contributor(s):
 *      Charles Maier <cmaier@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef TOPOLOGYPRINT_SOURCE
#define TOPOLOGYPRINT_SOURCE

#include <stdio.h>

#include "../plc/plc.h"
#include "../tools/memory.h"

signed PLCTopologyPrint (struct plctopology * plctopology)

{
	signed plcnetworks = plctopology->plcnetworks;
	struct plcnetwork * plcnetwork = (struct plcnetwork *) (& plctopology->plcnetwork);
	while (plcnetworks--)
	{
		signed plcstations = plcnetwork->plcstations;
		struct plcstation * plcstation = (struct plcstation *) (& plcnetwork->plcstation);
		while (plcstations--)
		{
			char address [ETHER_ADDR_LEN * 3];
			printf ("%s ", plcstation->LOC? "LOC": "REM");
			printf ("%s ", plcstation->CCO? "CCO": "STA");
			printf ("%03d ", plcstation->TEI);
			printf ("%s ", hexstring (address, sizeof (address), plcstation->MAC, sizeof (plcstation->MAC)));
			printf ("%s ", hexstring (address, sizeof (address), plcstation->BDA, sizeof (plcstation->BDA)));
			printf ("%03d ", plcstation->RX);
			printf ("%03d ", plcstation->TX);
			printf ("%s ", plcstation->hardware);
			printf ("%s ", plcstation->firmware);
			printf ("\n");
			plcstation++;
		}
		plcnetwork = (struct plcnetwork *) (plcstation);
	}

#if 0

	printf ("\n");

#endif

	return (0);
}

#endif



