#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/shm.h>
#include <shared.h>
#include <shutils.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_slavelist.h"

#define VERSION_FILE	"/tmp/wlan_update.txt"
#define FWVER_PATTERN	"#FW"
#define EXTENDNO_PATTERN	"#EXT"
#define URL_PATTERN	"#URL"

/*
========================================================================
Routine Description:
	Retrieve version for all master/slave based on model name.

Arguments:
	fd		- file descriptor
	modelName	- model name
	version		- the firmware version that all master/slave had

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
char *cm_retrieveVersion(FILE *fd, char *modelName, char *version)
{
	static char verBuf[sizeof("0.0.0.0_000_00000-00000000XXXXX")];
	char lineBuf[300] = {0};
	char *pModelName = NULL;
	char *pFwVer = NULL;
	char *pExtendNo = NULL;
	char *pExtendNoPrefix = NULL;
	char *pExtendNoSuffix = NULL;
	char *pCommitNo = NULL;
	char tFwVer[16] = {0};
	char sFwVer[4][4];
	int sFwVerFull = 0;
	int sBuildNo = 0;
	int sExtendNo = 0;
	char fFwVer[4][4];
	int fFwVerFull = 0;
	int  fBuildNo = 0;
	int fExtendNo = 0;
	char fCommitNo[16];
	int gotNewVer = 0;

	/* 3.0.0.4.382_16073-g1b2a6e7 */
	//snprintf(fwVer, sizeof(fwVer), "%s.%s_%s", nvram_safe_get("firmver"),
	//			nvram_safe_get("buildno"), nvram_safe_get("extendno"));
	
	memset(sFwVer, 0, sizeof(sFwVer));

	sscanf(version, "%c.%c.%c.%c.%d_%d-%*s", sFwVer[0], sFwVer[1], sFwVer[2], sFwVer[3],
				&sBuildNo, &sExtendNo);

	DBG_INFO("sFwVer1(%s) sFwVer2(%s) sFwVer3(%s) sFwVer4(%s) sBuildNo(%d) sExtendNo(%d)",
		sFwVer[0], sFwVer[1], sFwVer[2], sFwVer[3], sBuildNo, sExtendNo);

	fseek(fd, 0, SEEK_SET);

	/* RT-AC86U#FW3004382#EXT15097-gb0a3036#URL#UT4208#BETAFW#BETAEXT# */
	while (fgets(lineBuf, sizeof(lineBuf), fd) ) {
		pModelName = lineBuf;
		pFwVer = strstr(lineBuf, FWVER_PATTERN);
		pExtendNo = strstr(lineBuf, EXTENDNO_PATTERN);
		pExtendNoPrefix =  strchr(pExtendNo, '-');
		pCommitNo = pExtendNoPrefix;
		pExtendNoSuffix =  strstr(lineBuf, URL_PATTERN);
		gotNewVer = 0;

		//DBG_INFO("lineBuf (%s)", lineBuf);
		if (pModelName && pFwVer && pExtendNo && pExtendNoPrefix && pExtendNoSuffix) {
			*pFwVer = '\0';
			//DBG_INFO("model name (%s)", modelName);
			/* check model name */
			if (!strcmp(modelName, pModelName)) {
				DBG_INFO("model name (%s) is match", modelName);
				*pExtendNo = '\0';
				pFwVer += strlen(FWVER_PATTERN);
				*pExtendNoPrefix = '\0';
				pExtendNo += strlen(EXTENDNO_PATTERN);
				*pExtendNoSuffix = '\0';
				pCommitNo += 1;

				DBG_INFO("fw ver (%s), extend no (%s)", pFwVer, pExtendNo);
				
				/* get fFwVer */
				memset(fFwVer, 0, sizeof(fFwVer));
				snprintf(fFwVer[0], sizeof(fFwVer[0]), "%c", pFwVer[0]);
				snprintf(fFwVer[1], sizeof(fFwVer[1]), "%c", pFwVer[1]);
				snprintf(fFwVer[2], sizeof(fFwVer[2]), "%c", pFwVer[2]);
				snprintf(fFwVer[3], sizeof(fFwVer[3]), "%c", pFwVer[3]);

				/* get fBuildNo */
				pFwVer += 4;
				//snprintf(fBuildNo, sizeof(fBuildNo), "%s", pFwVer);
				fBuildNo = atoi(pFwVer);

				/* get fExtendNo */
				//snprintf(fExtendNo, sizeof(fExtendNo), "%s", pExtendNo);
				fExtendNo = atoi(pExtendNo);

				/* get fCommitNo */
				snprintf(fCommitNo, sizeof(fCommitNo), "%s", pCommitNo);

				DBG_INFO("fFwVer1(%s) fFwVer2(%s) fFwVer3(%s) fFwVer4(%s) fBuildNo(%d) fExtendNo(%d) fCommitNo(%s)",
					fFwVer[0], fFwVer[1], fFwVer[2], fFwVer[3], fBuildNo, fExtendNo, fCommitNo);

				/* convert sFwVer to int */
				memset(tFwVer, 0, sizeof(tFwVer));
				snprintf(tFwVer, sizeof(tFwVer), "%s%s%s%s", sFwVer[0], sFwVer[1], sFwVer[2], sFwVer[3]);
				if (strlen(tFwVer) == 0) {
					DBG_INFO("tFwVer is NULL");
					continue;
				}
				else
					sFwVerFull = atoi(tFwVer);

				/* convert fFwVer to int */
				memset(tFwVer, 0, sizeof(tFwVer));
				snprintf(tFwVer, sizeof(tFwVer), "%s%s%s%s", fFwVer[0], fFwVer[1], fFwVer[2], fFwVer[3]);
				if (strlen(tFwVer) == 0) {
					DBG_INFO("tFwVer is NULL");
					continue;
				}
				else
					fFwVerFull = atoi(tFwVer);

				/* check sFwVer and fFwVer */
				if (fFwVerFull > sFwVerFull)
					gotNewVer = 1;
				else if (fFwVerFull == sFwVerFull)
				{
					if (fBuildNo > sBuildNo)
						gotNewVer = 1;
					else if (fBuildNo == sBuildNo)
					{
						if (fExtendNo > sExtendNo)
							gotNewVer = 1;
					}
				}

				break;
			}
		}
	}

	memset(verBuf, 0, sizeof(verBuf));
	if (gotNewVer) {
		snprintf(verBuf, sizeof(verBuf), "%s.%s.%s.%s.%d_%d-%s", 
			fFwVer[0], fFwVer[1], fFwVer[2], fFwVer[3], fBuildNo, fExtendNo, fCommitNo);
	}

	return verBuf;
}

/*
========================================================================
Routine Description:
	Update version for all master/slave.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
int cm_updateVersion()
{
	int shm_client_tbl_id;
	P_CM_CLIENT_TABLE p_client_tbl;
	void *shared_client_info=(void *) 0;
	int i = 0;
	int lock = 0;
	FILE *fd;
	int ret = 0;
	char newFwVer[32] = {0};

	DBG_INFO("start to update version info");

	if ((fd = fopen(VERSION_FILE, "r")) == NULL) {
		DBG_ERR("open file failed (%s)", VERSION_FILE);
		goto err;
	}

	lock = file_lock(CFG_FILE_LOCK);
	shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
	if (shm_client_tbl_id == -1){
		DBG_ERR("shmget failed");
		goto err;
	}

	shared_client_info = shmat(shm_client_tbl_id,(void *) 0,0);
	if (shared_client_info == (void *)-1){
		DBG_ERR("shmat failed");
		goto err;
	}

	p_client_tbl = (P_CM_CLIENT_TABLE)shared_client_info;
	for(i = 0; i < p_client_tbl->count; i++) {
		memset(newFwVer, 0, sizeof(newFwVer));
		snprintf(newFwVer, sizeof(newFwVer), "%s", cm_retrieveVersion(fd, p_client_tbl->modelName[i], p_client_tbl->fwVer[i]));
		if (strlen(newFwVer)) {
			if (strcmp(newFwVer, p_client_tbl->newFwVer[i])) {
				DBG_INFO("%02X:%02X:%02X:%02X:%02X:%02X update new firmware version(%s)",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5],
					newFwVer);
				snprintf(p_client_tbl->newFwVer[i], sizeof(p_client_tbl->newFwVer[i]), "%s", newFwVer);
			}
		}
	}

	shmdt(shared_client_info);

	ret = 1;
err:

	file_unlock(lock);
	if (fd) fclose(fd);

	return ret;
}

/*
========================================================================
Routine Description:
	User space main function.

Arguments:
	argc		- argument number
	*pArgv[]	- arguments

Return Value:
	0		- exit daemon
	-1		- fork fail

Note:
========================================================================
*/
int main(int argc, char *pArgv[])
{
#ifdef MASTER_DET
	if (nvram_get_int("cfg_master") == 0){
		DBG_ERR("not master, exit");
		goto err;
	}
#endif
#ifdef RTCONFIG_SW_HW_AUTH
	/* auth check for daemon */
	if (!check_auth()) {
		DBG_ERR("auth check failed, exit");
		goto err;
	}
	else
		DBG_INFO("auth check success");
#endif	/* RTCONFIG_SW_HW_AUTH */

	if (!fileExists(VERSION_FILE)) {
		DBG_ERR("%s doesn't exist, exit", VERSION_FILE);
		goto err;
	}

	cm_updateVersion();

err:

	return 0;
}