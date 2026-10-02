/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_remove_nextmac.c                                        *
 *     Project    : UGW                                                        *
 *     Description: Removes the nextmac from config file
 *                                                                             *
 ******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <ltq_api_include.h>

#define NEXT_MAC_CONF "/tmp/nextmac.conf"
#define TEMP_NEXT_MAC_CONF "/tmp/temp_nextmac.conf"


/* 
 ** =============================================================================
 **   Function Name    :scapi_removeNextMacaddr
 **
 **   Description      :Removes next mac address entry from config file
 **
 **   Parameters       :pcIfname(IN) -> interface name
 **                      pcMac(IN) -> mac address to be removed
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                      Failure -> Different -ve values 
 **
 ** ============================================================================
 */

int scapi_removeNextMacaddr(char* pcIfname)
{
	FILE* inFile = fopen(NEXT_MAC_CONF, "r");
	FILE* outFile = fopen(TEMP_NEXT_MAC_CONF, "a+");
	char line [64]; // maybe you have to user better value here
	int lineCount = 0;
	int nRet = -EXIT_FAILURE;

	if( inFile == NULL || outFile == NULL)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	while( fgets(line, sizeof(line), inFile) != NULL )
	{
		char* pcFind = strstr(line, pcIfname);
		/* Add only the lines that doesn't containt interface
		 * name to new file */
		if( pcFind == NULL){
			fprintf(outFile, "%s", line);
		}
		lineCount++;
	}
	nRet = EXIT_SUCCESS;
returnHandler:
	if(inFile != NULL)
		fclose(inFile);
	if(outFile != NULL)
		fclose(outFile);
	if(rename(TEMP_NEXT_MAC_CONF, NEXT_MAC_CONF) != 0){
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
	}
	return nRet;	 
}
