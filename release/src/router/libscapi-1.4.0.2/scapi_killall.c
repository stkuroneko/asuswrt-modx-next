/******************************************************************************** 

        Copyright (c) 2014 

        Lantiq Beteiligungs-GmbH & Co. KG 

        Lilienthalstrasse 15, 85579 Neubiberg, Germany  

        For licensing information, see the file 'LICENSE' in the root folder of 

        this software module. 

********************************************************************************/ 

/*  ************************************************************************
*         File Name    : scapi_killall.c
*         Description  : Contains all common functions which is used*
*             Across the system.
****************************************************************************/
 

/*========================Includes============================*/ 

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#include <ltq_api_include.h>

static char* extractNameFrmStat(pid_t);
static pid_t nameMatch(pid_t, const char*);
static pid_t* findPidByName(const char*);


/*====================Implementation==========================*/ 



/* 
 ** =============================================================================
 **   Function Name    :scapi_KillAll
 **
 **   Description      :Sends given signal to  all the processes related to app name. 
 **
 **   Parameters       :pcProcessName -> processes that you want to send signal to
 **						nSignal      -> signal number that you want to send to the processes
 **
 **   Return Value     :On Failure ->  * -EINVAL for invalid signal, -EXIT_FAILURE if 
 **						related process list is NULL(happens if unable to open the /proc folder),
 **						-ESRCH is there are no related processes, -EPERM if unable to kill any 
 **						process due to unavailable root permissions
 **						On Success -> If atleast one process is killed, EXIT_SUCCESS
 ** 
 **   Notes            :1.for 'signal', macro from signal.h can be used. e.g scapi_killAll("minissdpd", SIGKILL);
 **						2.providing a -ve number for 'signal' will send the default signal 15( i.e SIGTERM )
 **
 ** ============================================================================
 */

int scapi_killAll(char *pcProcessName, int nSignal)
{
	int nRet = 0;
	int nNum = 0;
	int nKilledCount = 0;
	int nkillReturn = 0;
	int nKillError = 0;
	pid_t *pidList = NULL;
	int nSigno = 0;
	//if signal is -ve , then SIGTERM(15) is the default signal
	if(nSignal < 0)
		nSigno = 15;
	else
	{
		nSigno = nSignal;
	}

	//If invalid signal number or name is provided
	if(nSigno < 0)
	{
		nRet = -EINVAL;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto errorHandler;
	}

	pidList = findPidByName(pcProcessName);
	if(pidList == NULL)
	{
		nRet = -EXIT_FAILURE;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto errorHandler;
	}

	//If there is no related process
	if(pidList[0] == 0)
	{
		nRet = -ESRCH;
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", nRet, strerror(-nRet));
		goto errorHandler;
	}
	//iterating through 'related_processes[]' array till '0' is encountered and killing each process individually
	for(nNum = 0; pidList[nNum] != 0;++nNum )
	{
		//kill returns a 0 if it successfully killed/signal_sent to process
		nkillReturn = kill(pidList[nNum], nSigno);
		//as soon as kill() is executed, errors if any are saved to 'errno' variable
		nKillError = errno;
		nkillReturn ? perror("error:"): ++nKilledCount;
		if(nKillError == EPERM)
		{
			nKillError = -EPERM;
		}
	}

	if(nKilledCount > 0)
	{
		nRet = EXIT_SUCCESS;
		goto errorHandler;
	}
	else
	{
		LOGF_LOG_DEBUG("DEBUG = No Process to kill\n");
		nRet = nKillError;
		goto errorHandler;
	}


errorHandler:
	/*cleaning*/
	if((nSigno == 9 || nSigno == 15) && nRet == EXIT_SUCCESS)
	{
		char sBuf[32] = {0};
		snprintf(sBuf, 32, "/var/run/%s.pid", pcProcessName);
		remove(sBuf);
	}
	if(pidList != NULL)
		free(pidList);
	return nRet;
}


/* 
 ** =============================================================================
 **   Function Name    :findPidByName
 **
 **   Description      :Gives the list of process numbers related to a name
 **
 **   Parameters       :pcProcName -> process name
 **
 **   Return Value     :On failure -> returns NULL
 **						On success -> returns list related processes
 ** 
 **   Notes            :It is the duty of the caller to free this list 
 **
 ** ============================================================================
 */
static pid_t* findPidByName(const char *pcProcName)
{
	pid_t *pidList = NULL;
	pid_t *pnRet = NULL;
	DIR *pdir = NULL;
	struct dirent *entry = NULL;
	pid_t pid;
	int nCount = 0;

	pidList = (pid_t*)calloc(1, sizeof(pid_t)*64);

	if(pidList == NULL){
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", -errno, strerror(errno));
		pnRet = NULL;
		goto returnHandler;
	}

	pdir = opendir("/proc");

	if(pdir == NULL)
	{
		pnRet = NULL;
		free(pidList);
		goto returnHandler;
	}

	//iterating through every entry in 'proc' folder
	while((entry = readdir(pdir)))
	{
		pid = (pid_t)strtoul(entry->d_name, NULL, 10);
		//continue if not a pid
		if(pid == 0)
			continue;
		pid_t name_match_value = nameMatch(pid, pcProcName);

		//collecting all the processes whose name matches.Will be able to collect a maximum of 63 processes
		if((name_match_value) && (nCount<63))
		{
			pidList[nCount] = name_match_value;
			++nCount;
		}
		//if number of related processes crosses the limit
		if(nCount >= 63)
		{
			LOGF_LOG_DEBUG("Process limit exceeded\n");
			pidList[nCount] = 0;
			pnRet = pidList;
			goto returnHandler;
		}
	}
	//delimiting the list with 0 since no process can have a 0 pid value
	pidList[nCount] = 0;
	//it is the duty of the caller to free the pid list
	pnRet = pidList;

returnHandler:
	//no need to close if dir is not open. i.e pdir = NULL
	if(pdir)
		closedir(pdir);
	return pnRet;
}



/* 
 ** =============================================================================
 **   Function Name    :extractNameFrmStat
 **
 **   Description      :extracts the process name related to a process number
 **
 **   Parameters       :PID Number  
 **
 **   Return Value     :On failure returns respective error strings
 **						On success returns process name stored in the stat file of that pid.  /proc/PID/stat 
 ** 
 **   Notes            :  
 **
 ** ============================================================================
 */
static char* extractNameFrmStat(pid_t processNumber)
{
	char sFileName[32] = {0};
	char sBuffer[256] = {0};
	FILE *pfFile = NULL;
	char *pcName = NULL;
	char *pcStart = NULL;
	char *pcEnd = NULL;
	char *pcRet = NULL;

	snprintf(sFileName, 32, "/proc/%lu/stat", (unsigned long)processNumber); // \0 automatically appended to 'sFileName'

	pfFile = fopen(sFileName, "r");

	if(pfFile == NULL)
	{
		LOGF_LOG_ERROR("ERROR = %d --> %s\n", -errno, strerror(errno));
		// process probably exited
		pcRet = NULL;
		goto returnHandler;
	}

	//fgets reads min(line,256 chars). First line is sufficient for our use. Now buffer contains name of the procss enclosed in (). eg. (firefox)
	fgets(sBuffer, 256, pfFile); 
	//iterating through the sBuffer till ')' is encountered and replacing it with \0
	pcEnd = strrchr(sBuffer, ')');
	if(pcEnd == NULL)
	{
		LOGF_LOG_ERROR("ERROR = ')' Not found to extract process name\n");
		pcRet = NULL;
		goto returnHandler;
	}
	pcEnd[0] = '\0';
	//forming a C string by pointing 'name' to first character after '(' 
	pcStart = strchr(sBuffer, '(');
	if(pcStart == NULL)
	{
		LOGF_LOG_ERROR("ERROR = '(' Not found to extract process name\n");
		pcRet = NULL;
		goto returnHandler;
	}
	pcName = pcStart + 1;
	pcRet = strdup(pcName);
returnHandler:
	//no point in closing when the file in not opened
	if( pfFile != NULL)
		fclose(pfFile);
	return pcRet;
}

/* 
 ** =============================================================================
 **   Function Name    :nameMatch
 **
 **   Description      :Checks if process name matches with the name in /proc/PID/stat file
 **
 **   Parameters       :processId -> process id
 **						pcName -> equivalent process name
 **
 **   Return Value     :returns process id if name matches or else returns zero
 ** 
 **   Notes            :  
 **
 ** ============================================================================
 */
static pid_t nameMatch(pid_t processId, const char* pcName) 
{
	char* pcStatName = NULL;
	int nRet = -1;
	pcStatName = extractNameFrmStat(processId);
	if(pcStatName != NULL){
		nRet = strncasecmp(pcName, pcStatName, 15);
		free(pcStatName);
	}
	return nRet==0?processId:0;
}

