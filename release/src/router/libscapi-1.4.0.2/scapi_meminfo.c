
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

#define PROC_MEMINFO "/proc/meminfo"


int scapi_getMeminfo(MemInfo *xInfo)
{
    FILE *fp;
    char sBuf[80] = { 0 };
    int nRet = -EXIT_FAILURE;

    fp = fopen(PROC_MEMINFO, "r");
    if(fp == NULL)
    {
	nRet = -errno;
	printf("ERROR = %d -> %s\n", nRet, strerror(-nRet));
	return nRet;
    }

    fscanf(fp, "MemTotal: %u %79s\n", &xInfo->uTotal, sBuf);
    fscanf(fp, "MemFree: %u %79s\n", &xInfo->uFree, sBuf);
    fscanf(fp, "Buffers: %u %79s\n", &xInfo->uBuffers, sBuf);
    fscanf(fp, "Cached: %u %79s\n", &xInfo->uCached, sBuf);
    fclose(fp);
    return EXIT_SUCCESS;
}
