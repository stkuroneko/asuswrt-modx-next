/******************************************************************************

  Copyright (c) 2012, 2014, 2015
  Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/* 
 ** =============================================================================
 **   FILE NAME        : ltq_dumplease.c
 **   AUTHOR           : Lantiq DevM Team
 **   DESCRIPTION      : This file contains the C utility for dumplease system command
 **                      dumpleases" can list all DHCP Client information and all line content "seconds" text
 **
 **   Any use of this software is subject to the conclusion of a respective
 **   License agreement. Without such a License agreement no rights to the
 **   software are granted
 **   HISTORY          : 
 **   $Date            $Author                         $Comment
 **   Parameter        : 1. Dumplease file name (utility will consider default file, if it is NULL) [Input Parameter]
 2. Address of pointer to dump_lease_info structure [Output Parameter]
 3. &count [output parameter]
 **
 **   Returns          : Returns 0 on success and error number on failure.
 **
 ** ============================================================================
 */


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ltq_api_include.h"

#define ENABLE_DEBUG 1

//typedef uint32_t leasetime_t;

int scapi_dumplease(char *file, struct dump_lease_info **lease_info, int *no_entry)
{
	int nFd = 0, nRet = EXIT_SUCCESS;
	int i = 0,conn_count=0;
	int64_t written_at = 0, curr, expires_abs = 0;
	struct dyn_lease lease;
	struct in_addr addr ;
	char *unknown_string = "unknown";
	struct dump_lease_info *temp_info=NULL;
	struct dump_lease_info *temp_leaseinfo=NULL;

	*lease_info = NULL;

	if(strlen(file)<1)
		file=LEASES_FILE;

	nFd = open(file, O_RDONLY); 
	if(nFd < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto error;
	}

	read(nFd, &written_at, sizeof(written_at));
	curr = time(NULL);
	if (curr < written_at)
		written_at = curr; /* lease file from future! :) */

	temp_leaseinfo = NULL;

	while (read(nFd, &lease, sizeof(lease)) == sizeof(lease))
	{

		temp_info= realloc(temp_leaseinfo,(sizeof(struct dump_lease_info)*(conn_count+1)));

		if(temp_info == NULL)
		{
			nRet = -errno;
			LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
			close(nFd);
			goto error;
		}
		temp_leaseinfo = temp_info; 

		for (i = 0; i < 6; i++) 
		{
			(temp_leaseinfo+conn_count)->lease_mac[i]=lease.lease_mac[i];
		}

		addr.s_addr = lease.lease_nip;

		/* actually, 15+1 and 19+1, +1 is a space between columns */
		/* lease.hostname is char[20] and is always NUL terminated */
		if ( *lease.hostname)
		{
			sprintf((temp_leaseinfo+conn_count)->ipaddr, "%s", inet_ntoa(addr));
			sprintf((temp_leaseinfo+conn_count)->hostname, "%s", lease.hostname);
		}
		else
		{
			sprintf((temp_leaseinfo+conn_count)->ipaddr, "%s", inet_ntoa(addr));
			sprintf((temp_leaseinfo+conn_count)->hostname, "%s", unknown_string);
		}                        

		expires_abs = ntohl(lease.expires) + written_at;
		if (expires_abs <= curr) 
		{
			(temp_leaseinfo+conn_count)->expires_seconds= -1;
			continue;
		}
		unsigned expires = expires_abs - curr;

		(temp_leaseinfo+conn_count)->expires_seconds= expires;
		conn_count++;
	}
	close(nFd); 
	*no_entry=conn_count;
	*lease_info = temp_leaseinfo;

	return nRet;
error:
	if(temp_leaseinfo!= NULL)
		free(temp_leaseinfo);

	*lease_info = NULL;
	*no_entry = 0;
	return nRet;
}

