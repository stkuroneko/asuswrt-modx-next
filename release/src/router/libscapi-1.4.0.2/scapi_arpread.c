/********************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 
  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ********************************************************************************/

/*  ****************************************************************************** 
 *         File Name    : scapi_arpread.c                                         *
 *         Description  : This scapi is responsible for discovering the arp table *
 *                        entries and getting the Macs of host connected to interface*
 *  *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ltq_api_include.h>

int scapi_getArpTable(arpTable_t *arpTable)
{
		char header[ARP_BUFFER_LEN];
		FILE *arpCache = fopen(ARP_CACHE, "r");
		int i = 0;
		if (!arpCache)
		{
				LOGF_LOG_ERROR("Arp Cache: Failed to open file \"" ARP_CACHE "\"");
				return -1;
		}

		/* Ignore the first line, which contains the header */
		if (!fgets(header, sizeof(header), arpCache))
		{
				fclose(arpCache);
				return -1;
		}

		while (3 == fscanf(arpCache, ARP_LINE_FORMAT, arpTable->arpEntry[i].ipAddr,\
								arpTable->arpEntry[i].hwAddr, arpTable->arpEntry[i].device))
		{
				i++;
				arpTable->numOfEntires++;
		}
		fclose(arpCache);
		return 0;
}

int scapi_getMacTable(macTable_t *macTable, char *pIntFace)
{
		char header[ARP_BUFFER_LEN];
		FILE *macCache = fopen(MAC_CACHE, "r");
		int i = 0, flag = 0;
		char *p = NULL;
		if (!macCache)
		{
				LOGF_LOG_ERROR("Mac Cache: Failed to open file \"" MAC_CACHE "\"");
				return -1;
		}

		while (fgets(header, sizeof(header), macCache)) {

				if(strstr(header,"Bridging")) {
						flag = 1;
				}

				if(flag && strstr(header,"mac")) {
						p=NULL;
						if( (p = strstr(header, "=")) ) {
								strncpy(macTable->macEntry[i].hwAddr, p+2, 17);
								p=NULL;	
						}
						continue;
				}

				if(flag  && strstr(header,"netif")) {
						p=NULL;
						if( ( p = strstr(header, pIntFace) ) != NULL ) {
								strncpy(macTable->macEntry[i].device, p , 7);
								p=NULL;
								i++;
								macTable->numOfEntires++;
						}
						continue;
				}
		}
		fclose(macCache);
		return 0;
}
