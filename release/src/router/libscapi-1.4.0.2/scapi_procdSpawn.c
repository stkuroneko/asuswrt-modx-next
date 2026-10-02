/******************************************************************************** 

        Copyright (c) 2015

        Lantiq Beteiligungs-GmbH & Co. KG 

        Lilienthalstrasse 15, 85579 Neubiberg, Germany  

        For licensing information, see the file 'LICENSE' in the root folder of 

        this software module. 

********************************************************************************/

/*========================Includes============================*/

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <ltq_api_include.h>
/*====================Implementation==========================*/
#pragma GCC diagnostic ignored "-Wcast-qual"

#define	list_procd_entry(ptr, type, field)	container_of(ptr, type, field)
#define	list_first_procd_entry(ptr, type, field)	list_procd_entry((ptr)->next, type, field)

#define list_for_each_procd_entry(p, h, field)				\
	for (p = list_first_procd_entry(h, typeof(*p), field); &p->field != (h); \
	    p = list_procd_entry(p->field.next, typeof(*p), field))

#define  FOR_EACH_PROCD_PARAM(__pxSrc,__pxParam)\
		list_for_each_procd_entry(__pxParam,&(__pxSrc->xPlist),xPlist) \

/*!  \brief function to get paramname from ProcdParamList 
  \param[in] __pxParamName Param Node ptr
  \return on successfull param name will be returned. 
*/
static inline char *GET_PROCD_PARAM_NAME(IN ProcdParamList * __pxParamName)
{
	return __pxParamName->sParamName;
}

/*!  \brief function to get paramvalue from ProcdParamList 
  \param[in] __pxParamValue Param Node ptr
  \return on successfull param value will be returned. 
*/
static inline char *GET_PROCD_PARAM_VALUE(IN ProcdParamList * __pxParamValue)
{
	return __pxParamValue->sParamValue;
}

/*!  \brief  This function constructs ubus command and will send to Procd
  \param[IN] pxProcdObj Pointer to the ProcdObj structure used to construct ubus command
  \param[IN] pcMethod Name of the method to be called(set/delete)
  \return EXIT_SUCCESS/-EXIT_FAILURE
 */
static int32_t scapi_invokeUbusCmd(IN ProcdObj * pxProcdObj, IN char *pcMethod)
{
	int32_t nRet = EXIT_SUCCESS;
	ProcdParamList *pxTmpParam = NULL;
	char *pcTemp = NULL, sVal[MAX_LEN_PARAM_VALUE_D + 16] = { 0 };
	char sTemp[MAX_LEN_PARAM_VALUE_D] = { 0 };

	/* construct command */
	char sCmd[MAX_LEN_VALID_VALUE_D] = { 0 };
	int32_t nChildExitStatus = 0;
	int32_t nSize = 0;

	/* Constructing command equvilent to "ubus call service set/delete" */
	snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "ubus call service %s \'{", pcMethod);

	/* Adding service name to the command */
	if (pxProcdObj->sServiceName[0] != '\0') {
		/* Cmd will be - ubus call service set '{"name" : "service_name", */
		snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": \"%s\", ", sCmd, "name", pxProcdObj->sServiceName);
	} else {
		LOGF_LOG_ERROR("Service name is mandatory and not mentioned for method [%s]", pcMethod);
		nRet = -EXIT_FAILURE;
		goto end;
	}

	/* Command to delete - ubus call service delete "{ \"name\": \"service_name\"}".
	   Constructing ubus command for available parameters is not required for delete */
	if (strcmp(pcMethod, "delete") != 0) {
		/* Adding script to the command */
		if (pxProcdObj->pxTrigger != NULL) {
			/*Command will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": \"%s\", ", sCmd, "script", pxProcdObj->sServiceName);
		}

		/* Adding instances table */
		/* Adding instance1 table */
		/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { */
		snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": { \"%s\": { ", sCmd, "instances", "instance1");
		/* Adding command */
		if ((pxProcdObj->sCommand[0] != '\0')) {
			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": [ ", sCmd, "command");

			pcTemp = strtok(pxProcdObj->sCommand, " ");
			while (pcTemp) {
				snprintf(sTemp, MAX_LEN_PARAM_VALUE_D, "%s\"%s\",", sTemp, pcTemp);
				pcTemp = strtok(NULL, " ");
			}

			if ((nSize = strlen(sTemp))) {
				if (sTemp[nSize - 1] == ',') {
					sTemp[nSize - 1] = '\0';
				} else {
					sTemp[nSize] = '\0';
				}
			}

			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ], */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s%s ],", sCmd, sTemp);

		} else if (strcmp(pcMethod, "set") == 0) {
			LOGF_LOG_ERROR("Command is mandatory and not mentioned for method [%s]", pcMethod);
			nRet = -EXIT_FAILURE;
			goto end;
		}
		/* Adding respawn options */
		if (pxProcdObj->xRespawn.bRespawn == 1) {
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": [ ", sCmd, "respawn");

			/* Adding respawn threshold */
			if (pxProcdObj->xRespawn.nRespawnThreshold != -1)
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%d\",", sCmd, (int)pxProcdObj->xRespawn.nRespawnThreshold);

			/* Adding respawn timeout */
			if (pxProcdObj->xRespawn.nRespawnTimeout != -1)
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%d\",", sCmd, (int)pxProcdObj->xRespawn.nRespawnTimeout);

			/* Adding respawn retry */
			if (pxProcdObj->xRespawn.nRespawnRetry != -1)
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%d\"", sCmd, (int)pxProcdObj->xRespawn.nRespawnRetry);

			nSize = strlen(sCmd);
			if (sCmd[nSize - 1] == ',') {
				sCmd[nSize - 1] = '\0';
			} else {
				sCmd[nSize] = '\0';
			}
			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s],", sCmd);
		}

		/* Adding nice option */
		if ((pxProcdObj->nNice != 0) && (pxProcdObj->nNice >= -20) && (pxProcdObj->nNice < 20)) {
			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": %d,", sCmd, "nice", pxProcdObj->nNice);
		}

		/* Adding file option */
		if (pxProcdObj->sConfFile[0] != '\0') {
			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": [ \"%s\" ],", sCmd, "file", pxProcdObj->sConfFile);
		}

		/* Adding netdev option */
		if (pxProcdObj->sNetdev[0] != '\0') {
			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": [ \"%s\" ],", sCmd, "netdev", pxProcdObj->sNetdev);
		}

		/* Adding env variables */
		if (pxProcdObj->pxEnv != NULL) {
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": { ", sCmd, "env");
			FOR_EACH_PROCD_PARAM(pxProcdObj->pxEnv, pxTmpParam) {
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": \"%s\",", sCmd, GET_PROCD_PARAM_NAME(pxTmpParam), GET_PROCD_PARAM_VALUE(pxTmpParam));
			}

			nSize = strlen(sCmd);
			if (sCmd[nSize - 1] == ',') {
				sCmd[nSize - 1] = '\0';
			} else {
				sCmd[nSize] = '\0';
			}

			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], "env" : {"env_name": "env_value" }, */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s },", sCmd);
		}

		/* Adding limits */
		if (pxProcdObj->pxLimits != NULL) {
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": { ", sCmd, "limits");
			FOR_EACH_PROCD_PARAM(pxProcdObj->pxLimits, pxTmpParam) {
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": \"%s\",", sCmd, GET_PROCD_PARAM_NAME(pxTmpParam), GET_PROCD_PARAM_VALUE(pxTmpParam));
			}
			nSize = strlen(sCmd);
			if (sCmd[nSize - 1] == ',') {
				sCmd[nSize - 1] = '\0';
			} else {
				sCmd[nSize] = '\0';
			}

			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], "env" : {"env_name": "env_value" }, "limita" : { "limit_name": "limit_value"}, */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s },", sCmd);

		}

		/* Adding data name-value pairs */
		if (pxProcdObj->pxData != NULL) {
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": { ", sCmd, "data");
			FOR_EACH_PROCD_PARAM(pxProcdObj->pxData, pxTmpParam) {
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": \"%s\",", sCmd, GET_PROCD_PARAM_NAME(pxTmpParam), GET_PROCD_PARAM_VALUE(pxTmpParam));
			}
			nSize = strlen(sCmd);
			if (sCmd[nSize - 1] == ',') {
				sCmd[nSize - 1] = '\0';
			} else {
				sCmd[nSize] = '\0';
			}

			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], "env" : {"env_name": "env_value" }, "limita" : { "limit_name": "limit_value"}, "data":{"data_name":"data_value"}, */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s },", sCmd);
		}

		nSize = strlen(sCmd);
		if (sCmd[nSize - 1] == ',') {
			sCmd[nSize - 1] = '\0';
		} else {
			sCmd[nSize] = '\0';
		}

		/*Closing instance1 table */
		/* Closing instances table */
		/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], "env" : {"env_name": "env_value" }, "limita" : { "limit_name": "limit_value"}, "data":{"data_name":"data_value"} } }, */
		snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s } },", sCmd);

		/* Construct Command for service triggers */
		if (pxProcdObj->pxTrigger != NULL) {
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s\"%s\": [ ", sCmd, "triggers");
			FOR_EACH_PROCD_PARAM(pxProcdObj->pxTrigger, pxTmpParam) {
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s[ \"%s\", [ \"%s\", ", sCmd, "config.change", "if");

				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s[ \"%s\", \"%s\", \"%s\" ],", sCmd, "eq", "package", GET_PROCD_PARAM_VALUE(pxTmpParam));
				memset(sVal, 0x0, sizeof(sVal));
				sprintf(sVal, "\\/etc\\/init.d\\/%s", pxProcdObj->sServiceName);
				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s [ \"%s\", \"%s\", \"%s\" ]", sCmd, "run_script", sVal, "reload");

				snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s ] ],", sCmd);
			}
			nSize = strlen(sCmd);
			if (sCmd[nSize - 1] == ',') {
				sCmd[nSize - 1] = '\0';
			} else {
				sCmd[nSize] = '\0';
			}

			/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], "env" : {"env_name": "env_value" }, "limita" : { "limit_name": "limit_value"}, "data":{"data_name":"data_value"} } },"triggers" : [  [ "config.change",  [ "if",  [ "eq", "package", "devm_dummy"  ], [ "runscript", "/etc/init.d/devm", "reload"  ] ] ] ] */
			snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s ]", sCmd);
		}

		nSize = strlen(sCmd);
		if (sCmd[nSize - 1] == ',') {
			sCmd[nSize - 1] = '\0';
		} else {
			sCmd[nSize] = '\0';
		}
	}
	/* Cmd will be - ubus call service set '{"name" : "devm", "script" : "/etc/init.d/devm", "instances" : { "instance1" : { "command" : [ "devm" ],"respawn" : [ "3600", "5", "5" ], "nice": 1, "file": ["file_name"], "netdev": [ "netdev_name" ], "env" : {"env_name": "env_value" }, "limita" : { "limit_name": "limit_value"}, "data":{"data_name":"data_value"} } },"triggers" : [  [ "config.change",  [ "if",  [ "eq", "package", "devm_dummy"  ], [ "runscript", "/etc/init.d/devm", "reload"  ] ] ] ] }' */
	snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s}\'", sCmd);
	nSize = strlen(sCmd);
	sCmd[nSize] = '\0';

	/* invoke the command using scapi_spawn */
	nRet = scapi_spawn(sCmd, 0, &nChildExitStatus);
	if (nRet != EXIT_SUCCESS) {
		LOGF_LOG_ERROR("Invoking Ubus command failed with return value [%d], Service Name[%s]\n", nRet, pxProcdObj->sServiceName);
		goto end;
	} else if (nChildExitStatus != EXIT_SUCCESS) {
		nRet = nChildExitStatus;
		LOGF_LOG_ERROR("Invoking Ubus command failed with exit status [%d], Service Name[%s]\n", nChildExitStatus, pxProcdObj->sServiceName);
		goto end;
	} else {
		LOGF_LOG_DEBUG("Spawning Success - Service Name[%s]\n", pxProcdObj->sServiceName);
	}

 end:
	return nRet;

}

/*!  \brief  This function sends a ubus message to procd
  \param[IN] pxProcdObj Pointer to the ProcdObj structure used to construct ubus message
  \param[IN] pcAction Pointer to action to be doen on the process start/stop.
  \return EXIT_SUCCESS/-EXIT_FAILURE
 */
int32_t scapi_procdSpawn(IN char *pcAction, IN ProcdObj * pxProcdObj)
{
	char sAction[128] = { 0 };
	int32_t nRet = EXIT_SUCCESS;

	memset(sAction, 0x0, sizeof(sAction));

	if (strcmp(pcAction, "start") == 0) {
		strcpy(sAction, "set");
	} else if (strcmp(pcAction, "stop") == 0) {
		strcpy(sAction, "delete");
	} else {
		LOGF_LOG_ERROR("Action [%s] not supported\n", pcAction);
		nRet = -EXIT_FAILURE;
		goto end;
	}
	/* Invoke Ubus command */
	nRet = scapi_invokeUbusCmd(pxProcdObj, sAction);

 end:
	return nRet;
}

/*!  \brief  This function is used to create procd param list
  \param[IN] pxParamList Pointer to the Procd param list structure used to construct ubus command
  \param[IN] pcParamName Name of the parameter to be added 
  \param[IN] pcParamValue Value of the parameter to be added 
  \return Pointer to the new paramlist / NULL
 */
ProcdParamList *scapi_setProcdParamList(IN ProcdParamList * pxParamList, IN const char *pcParamName, IN const char *pcParamValue)
{
	ProcdParamList *pxTmp;
	/* Allocate Memory */
	pxTmp = calloc(1, sizeof(ProcdParamList));
	if (!pxTmp) {
		LOGF_LOG_CRITICAL(" malloc failed\n");
		return NULL;
	}

	/* Copy the Param name */
	if ((pcParamName != NULL) && (strlen(pcParamName) < MAX_LEN_PARAM_NAME_D)) {
		strncpy(pxTmp->sParamName, pcParamName, MAX_LEN_PARAM_NAME_D);
	} else {
		if (pcParamName != NULL) {
			LOGF_LOG_CRITICAL(" Param Name Buffer OverFlow [%s] \n", pcParamName);
		} else if (!pcParamName) {
			LOGF_LOG_ERROR(" Param Name is NULL\n");
		}
		free(pxTmp);
		return NULL;
	}

	/* Copy the Param value */
	if ((pcParamValue != NULL) && (strlen(pcParamValue) < MAX_LEN_PARAM_VALUE_D)) {
		strncpy(pxTmp->sParamValue, pcParamValue, MAX_LEN_PARAM_VALUE_D);
	} else {
		if ((pcParamValue != NULL)) {
			LOGF_LOG_CRITICAL("Param Value Buffer OverFlow ParamName [%s] ParamValue[%s]: ParamValueLen[%d]\n", pcParamName, pcParamValue, strlen(pcParamValue));
		} else if (!pcParamValue) {
			LOGF_LOG_ERROR(" Param value is NULL\n");
		}
		free(pxTmp);
		return NULL;
	}

	/* Add node to the list */
	list_add_tail(&(pxTmp->xPlist), &(pxParamList->xPlist));
	return pxTmp;
}

/*!
    \brief function to allocate memory for Procd param list
    \return Parameter list ptr 
*/
void *scapi_createProcdParam(void)
{
	ProcdParamList *__pxTmpParam;
	/* Allocate memory */
	__pxTmpParam = calloc(1, sizeof(ProcdParamList));
	if (!__pxTmpParam) {
		LOGF_LOG_CRITICAL(" malloc failed\n");
		return NULL;
	}
	/* Intialize the list head */
	INIT_LIST_HEAD(&(__pxTmpParam->xPlist));
	return (void *)__pxTmpParam;
}

/*!  \brief  This function is used to initialize the Procd obj to default values
  \param[IN] pxProcdObj Pointer to the ProcdObj structure used for initialization
  \return EXIT_SUCCESS
 */
int scapi_initializeProcdObj(IN ProcdObj * pxProcdObj)
{

	/* memset the Object */
	memset(pxProcdObj, 0, sizeof(ProcdObj));

	/* initialize to default values */
	pxProcdObj->nNice = 0;
	pxProcdObj->xRespawn.nRespawnThreshold = -1;
	pxProcdObj->xRespawn.nRespawnTimeout = -1;
	pxProcdObj->xRespawn.nRespawnRetry = -1;

	return EXIT_SUCCESS;
}
