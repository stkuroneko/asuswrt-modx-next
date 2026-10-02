/******************************************************************************** 

        Copyright (c) 2016

        Lantiq Beteiligungs-GmbH & Co. KG 

        Lilienthalstrasse 15, 85579 Neubiberg, Germany  

        For licensing information, see the file 'LICENSE' in the root folder of 

        this software module. 

********************************************************************************/

/*========================Includes============================*/

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#include <ltq_api_include.h>
/*====================Implementation==========================*/

/*!  \brief Wrapper function to start crond daemon
  \return  EXIT_SUCCESS or the error code.
  */
int32_t scapi_startCrond(void)
{
	int32_t nRet = EXIT_SUCCESS;
	ProcdObj xProcdObj;
	struct stat xCronFile;
	FILE *fCron = NULL;

	scapi_initializeProcdObj(&xProcdObj);

	/* Check for CRON_ROOT_FILE, Create one if it is not exists */
	if (stat(CRON_ROOT_FILE, &xCronFile) != 0) {
		/*CRON_ROOT_FILE is not available create one */
		if ((fCron = fopen(CRON_ROOT_FILE, "w")) != NULL) {
			fclose(fCron);
		} else {
			LOGF_LOG_ERROR("Creating file[%s] failed\n", CRON_ROOT_FILE);
			nRet = errno;
			goto end;
		}
	}

	/* Mandatory argumetns */
	strcpy(xProcdObj.sServiceName, "crond");
	snprintf(xProcdObj.sCommand, MAX_LEN_VALID_VALUE_D, "crond -f -c %s", CRON_DIR);
	/* Optional arguments */
	xProcdObj.xRespawn.bRespawn = RESPAWN_PROCD_ON;
	xProcdObj.xRespawn.nRespawnThreshold = 3600;
	xProcdObj.xRespawn.nRespawnTimeout = 1;
	xProcdObj.xRespawn.nRespawnRetry = 0;

	/* Updating conf file */
	strncpy(xProcdObj.sConfFile, CRON_ROOT_FILE, sizeof(xProcdObj.sConfFile));

	nRet = scapi_procdSpawn(PROCD_START, &xProcdObj);
	if (nRet != EXIT_SUCCESS) {
		LOGF_LOG_ERROR("Starting crond failed - Error code [%d]\n", nRet);
	}

 end:
	return nRet;
}

/*!  \brief Wrapper function to stop crond daemon
  \return  EXIT_SUCCESS or the error code.
  */
int32_t scapi_stopCrond(void)
{
	int32_t nRet = EXIT_SUCCESS;

	ProcdObj xProcdObj;
	scapi_initializeProcdObj(&xProcdObj);

	/* Mandatory argumetns */
	strcpy(xProcdObj.sServiceName, "crond");

	nRet = scapi_procdSpawn(PROCD_STOP, &xProcdObj);
	if (nRet != EXIT_SUCCESS) {
		LOGF_LOG_ERROR("Stopping crond failed - Error code [%d]\n", nRet);
	}

	return nRet;
}

/*!  \brief Wrapper function to Restart crond daemon
  \return  EXIT_SUCCESS or the error code.
  */
int32_t scapi_restartCrond(void)
{
	int32_t nRet = EXIT_SUCCESS;

	nRet = scapi_stopCrond();
	if (nRet != EXIT_SUCCESS) {
		goto end;
	}

	/* Wait for 1 Sec to avoid race condition between start and stop */
	sleep(1);

	nRet = scapi_startCrond();
	if (nRet != EXIT_SUCCESS) {
		goto end;
	}

 end:
	return nRet;
}

/*!  \brief Write to the configuration file with given inputs
  \param[in] pcMin Pointer to minutes.
  \param[in] pcHour Pointer to hour.
  \param[in] pcDayOfMon Pointer to Day of month.
  \param[in] pcMonth Pointer to month.
  \param[in] pcDayOfWeek Pointer to Day of week.
  \param[in] pcCommand Pointer to command to be executed.
  \param[in] nAction Action to be performed. addition or deletion from a file
  \return  UGW_SUCCESS or the error code.
  */
int32_t scapi_setCronjob(IN char *pcMin, IN char *pcHour, IN char *pcDayOfMon, IN char *pcMonth, IN char *pcDayOfWeek, IN char *pcCommand, IN int32_t nAction)
{
	FILE *fCron = NULL;
	FILE *fCronTemp = NULL;
	char sCmd[MAX_LEN_VALID_VALUE_D] = { 0 };
	int32_t nRet = EXIT_SUCCESS;
	char sLine[MAX_LEN_VALID_VALUE_D] = { 0 };
	bool bEntryFound = false;

	if ((nAction != ADD_ENTRY) && (nAction != DELETE_ENTRY)) {
		LOGF_LOG_ERROR("Action[%d] not supported\n", nAction);
		nRet = -EXIT_FAILURE;
		goto end;
	}

	snprintf(sCmd, MAX_LEN_VALID_VALUE_D, "%s %s %s %s %s %s\n", pcMin, pcHour, pcDayOfMon, pcMonth, pcDayOfWeek, pcCommand);
	/* Open CRON_ROOT_FILE for reading */
	fCron = fopen(CRON_ROOT_FILE, "r");
	if (!fCron) {
		LOGF_LOG_ERROR("Opening crontab user file failed - Error code [%d]\n", errno);
		nRet = errno;
		goto end;
	}

	/* Open CRON_ROOT_FILE_TEMP for writing */
	fCronTemp = fopen(CRON_ROOT_FILE_TEMP, "a+");
	if (!fCronTemp) {
		LOGF_LOG_ERROR("Opening crontab temp user file failed - Error code [%d]\n", errno);
		nRet = errno;
		goto end;
	}

	if (nAction == ADD_ENTRY) {
		while ((fgets(sLine, MAX_LEN_VALID_VALUE_D, fCron)) != NULL) {
			if ((bEntryFound != true) && (strncmp(sLine, sCmd, strlen(sCmd)) == 0)) {
				/*Entry found in conf file, no need to update again */
				bEntryFound = true;
			}
			fprintf(fCronTemp, "%s", sLine);
		}
		/* If Entry not found update here */
		if (bEntryFound == false) {
			fprintf(fCronTemp, "%s", sCmd);
		}

	} else if (nAction == DELETE_ENTRY) {

		while ((fgets(sLine, MAX_LEN_VALID_VALUE_D, fCron)) != NULL) {
			if (strncmp(sLine, sCmd, strlen(sCmd)) != 0) {
				fprintf(fCronTemp, "%s", sLine);
			}
		}
	}

 end:
	/* close file pointers being opened */
	if (fCronTemp)
		fclose(fCronTemp);
	if (fCron)
		fclose(fCron);
	if (nRet == EXIT_SUCCESS) {
		/* Replace the root file */
		unlink(CRON_ROOT_FILE);
		rename(CRON_ROOT_FILE_TEMP, CRON_ROOT_FILE);
	}

	return nRet;
}
