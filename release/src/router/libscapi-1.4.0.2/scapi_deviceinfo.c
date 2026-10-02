/********************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 
  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ********************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_deviceInfo.c                                         *
 *     Project    : UGW                                                        *
 *     Description: cal - get APIs Device Info Params                          *
 *                                                                             *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ltq_api_include.h>

#define PROC_CPUINFO "/proc/cpuinfo"
#define MODEL_NAME_STR "CONFIG_IFX_MODEL_NAME"
#define MODELNAME_CONFIG_FILE_PATH "/etc/config.sh"
#define MACHINE "machine"
#define SYSTEM_TYPE "system type"

/* =============================================================================
 * Function Name : scapi_getHardwareVersion
 * Description   : function to get the Hardware Version. 
 * ============================================================================ */
int32_t scapi_getHardwareVersion(OUT char *pcHwVer)
{
	FILE *pFp = NULL;
	int32_t nRet = UGW_SUCCESS;
	char sBuf[MAX_LEN_PARAM_VALUE_D] = { 0 };
	char sHwType[MAX_LEN_PARAM_VALUE_D] = { 0 };
	char sHwName[MAX_LEN_PARAM_VALUE_D] = { 0 };
	pFp = fopen(PROC_CPUINFO, "r");
	if (NULL == pFp) {
		LOGF_LOG_CRITICAL("Error: Failed to open %s", PROC_CPUINFO);
		nRet = errno;
		goto end;
	}

	while (NULL != fgets(sBuf, sizeof(sBuf), pFp)) {
		sBuf[strcspn(sBuf, "\r\n")] = 0;
		if (strstr(sBuf, SYSTEM_TYPE) != NULL) {
			strncpy(sHwName, strchr(sBuf, ':') + 2, MAX_LEN_PARAM_VALUE_D);
		}
		if (strstr(sBuf, MACHINE) != NULL) {
			strncpy(sHwType, strchr(sBuf, ':') + 1, MAX_LEN_PARAM_VALUE_D);
		}
	}
	snprintf(pcHwVer, MAX_LEN_PARAM_VALUE_D, "%s,%s", sHwName, sHwType);

 end:
	if (pFp != NULL) {
		fclose(pFp);
		pFp = NULL;
	}
	return nRet;
}

/* =============================================================================
 * Function Name : scapi_getModelName
 * Description   : function to get the ModelName. 
 * ============================================================================ */
int32_t scapi_getModelName(OUT char *pcModelName)
{
	FILE *pFp = NULL;
	int32_t nRet = UGW_SUCCESS;
	char sBuf[MAX_LEN_PARAM_VALUE_D] = { 0 };
	pFp = fopen(MODELNAME_CONFIG_FILE_PATH, "r");
	if (NULL == pFp) {
		LOGF_LOG_CRITICAL("Error: Failed to open %s", MODELNAME_CONFIG_FILE_PATH);
		nRet = errno;
		goto end;
	}

	while (NULL != fgets(sBuf, sizeof(sBuf), pFp)) {
		sBuf[strcspn(sBuf, "\r\n")] = 0;
		if (strstr(sBuf, MODEL_NAME_STR) != NULL) {
			strncpy(pcModelName, strchr(sBuf, '"') + 1, strrchr(sBuf, '"') - strchr(sBuf, '"') - 1);
			break;
		}
	}

 end:
	if (pFp != NULL) {
		fclose(pFp);
		pFp = NULL;
	}
	return nRet;
}
