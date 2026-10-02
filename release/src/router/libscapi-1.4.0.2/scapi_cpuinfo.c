
/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_meminfo.c                                            *
 *     Project    : UGW                                                        *
 *     Description: cal - /proc/meminfo get APIs                               *
 *                                                                             *
 ******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ltq_api_include.h>

#define PROC_CPUINFO "/proc/cpuinfo"

int scapi_getCPUInfo(CPUInfo *xInfo)
{
	FILE *fp;
	char *sTmp;
	size_t sRead;
	char sBuf[1024] = { 0 };
	int nRet = -EXIT_FAILURE;

	fp = fopen(PROC_CPUINFO, "r");
	if(fp == NULL)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		return nRet;
	}

	/* Read the entire contents of /proc/cpuinfo into the buffer.  */
	sRead = fread(sBuf, 1, sizeof(sBuf), fp);
        if (sRead == 0)
        {
		LOGF_LOG_ERROR("Failed to read file content\n");
		goto end;	
        }

	/* NUL-terminate the text.  */
	sBuf[sRead] = '\0';

	/* Locate the line that starts with "cpu MHz".  */
	sTmp = strstr(sBuf, "cpu MHz");
	if(sTmp == NULL)
	{
		LOGF_LOG_ERROR("CPU MHz is not found");
		goto end;
	}

	/* Parse the line to extract the clock speed.  */
	sscanf(sTmp, "cpu MHz  :  %u", &xInfo->CpuHz);
	nRet = EXIT_SUCCESS;

end:
	LOGF_LOG_INFO("CPU Mhz: %u \n", xInfo->CpuHz);
	if(fp != NULL)
		fclose(fp);
	return nRet;
}
