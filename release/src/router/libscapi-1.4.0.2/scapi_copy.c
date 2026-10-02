
/******************************************************************************

                         Copyright (c) 2012, 2014, 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/


/*
 * =====================================================================================
 *
 *       Filename:  scapi_copy.c
 *
 *    Description: API to copy  contents of one file to other  
 *
 *        Version:  1.0
 *        Created:  08/07/14 16:43:23
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Lantiq Communications (), 
 *   Organization:  Lantiq Communications
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ltq_api_include.h>

/* 
** =============================================================================
**   Function Name    :	scapi_copy
**
**   Description      :	Copies content of one file to other
**
**   Parameters       :	pcTo(OUT) -> output file
**						pcFrom(IN)-> input file  
**
**   Return Value     : Success -> EXIT_SUCCESS
**						Failure -> -ve Value depending on the error
** 
**   Notes            :  
**
** ============================================================================
*/
int scapi_copy(const char *pcTo, const char *pcFrom)
{
	int nFdTo = -1, nFdFrom = -1;
	char caBuf[4096] = {0};
	ssize_t nRead = 0;
	int nRet = -EXIT_FAILURE;

	nFdFrom = open(pcFrom, O_RDONLY);
	if (nFdFrom < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(errno));
		goto returnHandler;
	}

	nFdTo = open(pcTo, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (nFdTo < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(errno));
		goto returnHandler;
	}
	/* Loop to read again incase sizeof caBuf is not enough to hold the whole content. nRead = 0 implies EOF */
	while (nRead = read(nFdFrom, caBuf, sizeof caBuf), nRead > 0)
	{
		char *pcOutPtr = caBuf;
		ssize_t nWritten;

		do {
			nWritten = write(nFdTo, pcOutPtr, nRead);

			if (nWritten >= 0)
			{
				nRead -= nWritten;
				pcOutPtr += nWritten;
			}
			else if (nWritten < 0)
			{
				nRet = -errno;
				LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(errno));
				goto returnHandler;
			}
		} while (nRead > 0);
	}

	if(nRead < 0)
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(errno));
		goto returnHandler;
	}

	if (0 == nRead)
	{
		/* Success! */
		nRet = EXIT_SUCCESS;
	}

returnHandler:
	if(nFdFrom != -1)
		close(nFdFrom);
	if (nFdTo != -1)
		close(nFdTo);
	return nRet;
}
