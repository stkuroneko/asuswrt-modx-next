/******************************************************************************

  Copyright (c) 2012, 2014, 2015
  Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/




/* ===========================================================================================================
 *
 *       Function Name   : insmod
 **
 **      Description     : API to insert kernel module
 **
 **      Parameter       : Module name to be inserted with parameter of the modules (optional)
 **
 **      Returns         : Returns 0 on success and error number on failure.
 ** ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <asm/unistd.h>
#include <glob.h>

#include <ltq_api_include.h>

#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifdef __UCLIBC__
extern int init_module(void *module, unsigned long len, const char *options);
#else
#include <sys/syscall.h>
#define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)
#endif

#define DEFAULT_MODULES_DIR "/lib/modules/*/"

static const char *scapi_moderror(int err)
{
	switch (err) {
		case ENOEXEC:
			return "Invalid module format";
		case ENOENT:
			return "Unknown symbol in module";
		case ESRCH:
			return "Module has wrong symbol version";
		case EINVAL:
			return "Invalid parameters";
		default:
			return strerror(err);
	}
}

static void *scapi_getFileData(const char *pcFileName, unsigned long *pulSize)
{
	unsigned int unMax = 16384;
	int nRet, nFd, err_save;
	void *pBuffer;

	if (!strcmp(pcFileName, "-"))
		nFd = dup(STDIN_FILENO);
	else
		nFd = open(pcFileName, O_RDONLY, 0);

	if (nFd < 0)
		return NULL;

	pBuffer = calloc(1, unMax);
	if (!pBuffer){
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", -errno, strerror(errno));
		goto returnHandler;
	}

	*pulSize = 0;
	while ((nRet = read(nFd, pBuffer + *pulSize, unMax - *pulSize)) > 0) {
		*pulSize += nRet;
		if (*pulSize == unMax) {
			void *p;

			p = realloc(pBuffer, unMax *= 2);
			if (!p){
				LOGF_LOG_ERROR("ERROR = %d -> %s\n", -errno, strerror(errno));
				goto returnHandler;
			}
			pBuffer = p;
		}
	}
	if (nRet < 0){
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", -errno, strerror(errno));
		goto returnHandler;
	}

	close(nFd);
	return pBuffer;

returnHandler:
	err_save = errno;
	free(pBuffer);
	close(nFd);
	errno = err_save;
	return NULL;
}

/* 
 ** =============================================================================
 **   Function Name    : scapi_insmod
 **
 **   Description      : Inserts a kernel module
 **
 **   Parameters       : pcModulePath(IN) --> Full path of the module. Wildcard supported
 **
 **   Return Value     :Success -> EXIT_SUCCESS
 **                     Failure -> Different -ve values depending on the error 
 ** 
 **   Notes            : Compatible with kernel versions > 2.6 
 **
 ** ============================================================================
 */

int scapi_insmod(const char* pcModulePath, const char* pcOptions)
{
	int nRet = -EXIT_FAILURE;
	void *pFile = NULL;
	char *pcModuleName = NULL;
	char *pcOptionsDup = NULL;
	glob_t xPath = {0};
	struct stat xStat = {0};
	char module_buffer[1024] = {'\0'};

	if(pcModulePath == NULL || strlen(pcModulePath) == 0){
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}

	/*  Check if '.ko' extension is present for module name. If not,
	 *  add it */
	int nModuleLen = strlen(pcModulePath);
	int nSuffixLen = strlen(".ko");

	if(nModuleLen > nSuffixLen && !strcmp(".ko", &pcModulePath[nModuleLen - 3])){
		pcModuleName = strdup(pcModulePath);
		if(pcModuleName == NULL){
			nRet = -errno;
			LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
			goto returnHandler;
		}
	}
	/* If module len is <= suffix len, ".ko" extension is not
	 * present
	 */
	else{
		pcModuleName = calloc(1, strlen(pcModulePath)+ 4*sizeof(char));
		if(pcModuleName == NULL){
			nRet = -errno;
			LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
			goto returnHandler;
		}
		strcat(pcModuleName, pcModulePath);
		strcat(pcModuleName, ".ko");
	}

	/* If there are no wildcard entries and you are not able to stat the file */
	if (strchr(pcModuleName, '*') == NULL && (stat(pcModuleName, &xStat) != 0)){
		char* pcTmp = calloc(1, strlen(pcModuleName)+ strlen(DEFAULT_MODULES_DIR) + (2*sizeof(char)));
		if(pcTmp == NULL){
			nRet = -errno;
			LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
			goto returnHandler;
		}
		/*pcTmp has enough space*/
		sprintf(pcTmp, "%s%s", DEFAULT_MODULES_DIR, pcModuleName);
		free(pcModuleName);
		pcModuleName = pcTmp;
	}

	glob(pcModuleName, 0, NULL, &xPath);

	if(xPath.gl_pathv == NULL){
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
		goto returnHandler;
	}
	else if(*(xPath.gl_pathv) != NULL){
		free(pcModuleName);
		pcModuleName = calloc(1, strlen(*(xPath.gl_pathv)) + 2*sizeof(char));
		if(pcModuleName == NULL){
			nRet = -errno;
			LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
			goto returnHandler;
		}
		/* pcModuleName is guaranteed to be bigger than source*/
		sprintf(pcModuleName, "%s", *(xPath.gl_pathv)); 
	}
	if(pcOptions == NULL){
		pcOptionsDup = pcModuleName;
	}
	else{
		pcOptionsDup = calloc(1, strlen(pcModuleName) + strlen(pcOptions) + 3*sizeof(char));
		if(pcOptionsDup == NULL){
			nRet = -errno;
			LOGF_LOG_ERROR("ERROR = %d -> %s\n", nRet, strerror(-nRet));
			goto returnHandler;
		}
		strcat(pcOptionsDup, pcModuleName);
		strcat(pcOptionsDup, " ");
		strcat(pcOptionsDup, pcOptions);
	}

	// insmoding using system
	sprintf(module_buffer,"insmod %s", pcOptionsDup);
	system(module_buffer);
	if(pcOptions == NULL){
		pcOptionsDup = NULL;
	}

	nRet = EXIT_SUCCESS;

returnHandler:
	if(pFile != NULL)
		free(pFile);
	if(pcModuleName != NULL)
		free(pcModuleName);
	if(pcOptionsDup != NULL)
		free(pcOptionsDup);
	globfree(&xPath);
	return nRet;
}
