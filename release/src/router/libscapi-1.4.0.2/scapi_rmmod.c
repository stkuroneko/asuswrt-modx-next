/******************************************************************************

  Copyright (c) 2012, 2014, 2015
  Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/



#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <ltq_api_include.h>


/* Returns debug statements depending on the error number */
static const char* scapi_moderror(int nErr)
{
	switch (nErr) {
		case -1: 
			return "no such module";
		case ENOEXEC:
			return "invalid module format";
		case ENOENT:
			return "unknown symbol in module, or unknown parameter";
		case ESRCH:
			return "module has wrong symbol version";
		case ENOSYS:
			return "kernel does not support requested operation";
	}
	if (nErr < 0)
		nErr = -nErr;

	return strerror(nErr);
}

/* 
 ** =============================================================================
 **   Function Name    :rmmod_main
 **
 **   Description      :Removes a module from the kernel
 **
 **   Parameters       :pcModule -> Module name to be removed from kernel
 **			nOptions -> options to be applied along( multiple options can be applied with '|'.
 **
 **   Return Value     :Returns 0 on success and relevant error number on failure.
 **
 ** ============================================================================
 */
int scapi_rmmod(char* pcModule, int nOptions)
{
	int nRet = -EXIT_FAILURE;
	unsigned flags = O_NONBLOCK | O_EXCL;
	char* pcModuleDup = NULL, *pcTmp = NULL;

	if (nOptions & FORCE)  // option -> --force 
		flags |= O_TRUNC;


	if (pcModule == NULL){
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	pcModuleDup = strdup(pcModule);
	if(pcModuleDup == NULL){
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	pcTmp = strstr(pcModuleDup, ".ko");

	/* Remove .ko extension */
	if(pcTmp != NULL)
		*pcTmp = '\0';

	/* performs actual removing of module from kernel. Module name should be without path or .ko extension */
	if ((nRet = syscall(__NR_delete_module, pcModuleDup, flags)))
	{
		nRet = -errno;
		LOGF_LOG_ERROR("ERROR = %d -> %s. Unable to remove %s\n", nRet, scapi_moderror(-nRet), pcModule);
		goto returnHandler;
	}
	nRet= EXIT_SUCCESS;

returnHandler:
	if(pcModuleDup != NULL)
		free(pcModuleDup);
	return nRet;
}

