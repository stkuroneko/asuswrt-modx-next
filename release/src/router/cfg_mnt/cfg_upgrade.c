#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h> 
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_upgrade.h"
#include "cfg_dencrypt.h"

int cancelUpgrade = 0;
#ifdef FREE_MEMORY_DOWNLOAD
int stopUpgrade = 0;
#endif

/*
========================================================================
Routine Description:
	Send the status of firmware check to server.

Arguments:
	status		- firmware status
	firmVer		- firmware version

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendFirmwareStatus(int status, char *firmVer)
{
	unsigned char data[128] = {0};

	if (!cm_ctrlBlock.flagIsFirmwareCheck) {
		DBG_INFO("Don't send status out!");
		return 0;
	}

	if (status == FW_SUCCESS_CHECK && firmVer && strlen(firmVer))
		snprintf((char *)data, sizeof(data), "{\"%s\":%d,\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"}",
			CFG_STR_FWSTATUS, status, CFG_STR_MAC, get_unique_mac(), CFG_STR_FWVER, firmVer,
			CFG_STR_FRS_MODEL_NAME, nvram_safe_get("webs_state_odm"));
	else
		snprintf((char *)data, sizeof(data), "{\"%s\": %d}", CFG_STR_FWSTATUS, status);

	/* send TCP packet */
	if (cm_sendTcpPacket(REQ_FWSTAT, &data[0]) == 0) {
		DBG_ERR("Fail to send TCP packet!");
		return 0;
	}

	return 1;
} /* End of cm_sendFirmwareStatus */

/*
========================================================================
Routine Description:
	Check whether new firmware can be upgraded.

Arguments:
	verBuf		- buffer for version
	bufLen		- buffer length

Return Value:
	-1		- error
	0		- no need to upgrade
	1		- need to upgrade

========================================================================
*/
int cm_checkFwNeedUpgrade(char *verBuf, int bufLen)
{
	int ret = 1;
	int currentPath = 0;
	int checkPath = 0;
	char dFwVer[5];
	char dFirmVer[8] = {0};
	char dBuildNo[8] = {0};
	char dExtendNo[16] = {0};
	char rFirmVer[8] = {0};
	char rBuildNo[8] = {0};
	char rExtendNo[16] = {0};
	char tFwVer[16] = {0};
	int passCheck = 0;
	int rNoFirmVer = 0;

	/* current path */
	sscanf(nvram_safe_get("firmver"), "%c.%c.%c.%c",
		&dFwVer[0], &dFwVer[1], &dFwVer[2], &dFwVer[3]);
	if (dFwVer[0] == '9')
		currentPath = 1;

	/* check path */
	if (nvram_get_int("firmware_path") == 1) 
		checkPath = 1;

	DBG_INFO("currentPath(%d) checkPath(%d)", currentPath, checkPath);

	/* get firmware verion for dut */
	snprintf(dFirmVer, sizeof(dFirmVer), "%c%c%c%c", dFwVer[0], dFwVer[1], dFwVer[2], dFwVer[3]);
	if (strlen(dFirmVer) == 0) {
		DBG_INFO("dFirmVer is NULL");
		return -1;
	}

	/* get build no for dut  */
	snprintf(dBuildNo, sizeof(dBuildNo), "%s",  nvram_safe_get("buildno"));	/* buildno */
	if (strlen(dBuildNo) == 0) {
		DBG_INFO("dBuildNo is NULL");
		return -1;
	}

	/* get extend no for dut */
	snprintf(dExtendNo, sizeof(dExtendNo), "%s",  nvram_safe_get("extendno"));	/* extendno */
	if (strlen(dExtendNo) == 0) {
		DBG_INFO("dExtendNo is NULL");
		return -1;
	}

	DBG_INFO("dFirmVer(%s) dBuildNo(%s) dExtendNo(%s)", dFirmVer, dBuildNo, dExtendNo);

	/* get firmware verion, build no and extend no for remote */
	if ((currentPath == 0 && checkPath == 0) ||
		(currentPath == 1 && checkPath == 0)) {
		if (strlen(nvram_safe_get("webs_state_info")) > 5) {	/* for official */
			/* 3004_982rc1_16397-g4ee65a0 */
			sscanf(nvram_safe_get("webs_state_info"), "%[^_]_%[^_]_%s", rFirmVer, rBuildNo, rExtendNo);
		}
		else
		{
			DBG_INFO("no version info for official");
			rNoFirmVer = 1;
		}

		if (currentPath == 1 && checkPath == 0)
			passCheck = 1;
	}
	else if ((currentPath == 1 && checkPath == 1) ||
		(currentPath == 0 && checkPath == 1)) {
		if (strlen(nvram_safe_get("webs_state_info_beta")) > 5) {	/* for beta */
			/* 3004_982rc1_16397-g4ee65a0 */
			sscanf(nvram_safe_get("webs_state_info"), "%[^_]_%[^_]_%s", rFirmVer, rBuildNo, rExtendNo);
		}
		else
		{
			DBG_INFO("no version info for beta");
			rNoFirmVer = 1;
		}

		if (currentPath == 0 && checkPath == 1)
			passCheck = 1;
	}

	/* need to check version info betwen dut and remote */
	if (rNoFirmVer)
		ret = 0;	/* no need to upgrade */
	else if (!passCheck && (atoi(dFirmVer) > 0 && atoi(dBuildNo) > 0 && atoi(dExtendNo) > 0))
	{
		DBG_INFO("rFirmVer(%s) rBuildNo(%s) rExtendNo(%s)", rFirmVer, rBuildNo, rExtendNo);

		/* check buildno first */
		if (atoi(dBuildNo)  > atoi(rBuildNo))
			ret = 0;	/* no need to upgrade */
		else if (atoi(dBuildNo) == atoi(rBuildNo)) {
			if (atoi(dFirmVer) > atoi(rFirmVer))
				ret = 0;	/* no need to upgrade */
			else if (atoi(dFirmVer) == atoi(rFirmVer)) {
				if (atoi(dExtendNo) >= atoi(rExtendNo))
					ret = 0;	/* no need to upgrade */
			}
		}
	}

	if (ret == 1) {
		memset(tFwVer, 0, sizeof(tFwVer));
		snprintf(tFwVer, sizeof(tFwVer), "%d", atoi(rFirmVer));
		//9.0.0.4.382_16845-g9d8df29
		snprintf(verBuf, bufLen, "%c.%c.%c.%c.%s_%s",
			tFwVer[0], tFwVer[1], tFwVer[2], tFwVer[3], rBuildNo, rExtendNo);
		DBG_INFO("firmware version(%s)", verBuf);
	}

	return ret;
} /* End of cm_checkFwNeedUpgrade */


/*
========================================================================
Routine Description:
	Thread for check firmware.

Arguments:
	None

Return Value:
        None

========================================================================
*/
void *cm_checkFirmware(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());

	int ret = FW_START;
	int run = 0;
	char *run_script = "/usr/sbin/webs_update.sh";
	char firmVer[65] = {0};
	char rFirmVer[8] = {0};
	char rBuildNo[8] = {0};
	char rExtendNo[32] = {0};

	if (cm_ctrlBlock.role == IS_CLIENT) {
		if (cm_ctrlBlock.flagIsFirmwareCheck) {
			DBG_INFO("exit firmware check");
#ifdef PTHREAD_EXIT
			return (void *)1;
#else
			pthread_exit(NULL);
#endif
		}

		cm_ctrlBlock.flagIsFirmwareCheck = 1;
	}

#if 0
	if (cm_ctrlBlock.role == IS_SERVER)
		nvram_set_int("cfg_check", FW_START);
#endif
	nvram_set_int("cfg_fwstatus", FW_START);

	if (cm_ctrlBlock.role == IS_CLIENT)
		nvram_set("webs_update_trigger", "CFG_MNT");

	run = system(run_script);
	if (run != 127 && run != -1) {
		do {
			sleep(3);
			if (!pids(run_script))
				break;
		} while(1);
	}
	else
	{
		DBG_INFO("failed to run script");
		ret = FW_FAIL_RETRIEVE;
		goto err;
	}

	if (nvram_get_int("webs_state_update") &&
		!nvram_get_int("webs_state_error") &&
		strlen(nvram_safe_get("webs_state_info"))) {
		DBG_INFO("retrieve firmware information");

		/* check webs_state_flag (0: no need upgrade, 1: new fw, 2: force update) */
		if (nvram_get_int("webs_state_flag") == 0) {
			DBG_ERR("no need to upgrade firmware");
			ret = FW_NO_NEED_UPGRADE;
			goto err;
		}
		else
		{
			if (sscanf(nvram_safe_get("webs_state_info"), "%[^_]_%[^_]_%s", rFirmVer, rBuildNo, rExtendNo) == 3) {
				DBG_ERR("can upgrade firmware");
				rFirmVer[sizeof(rFirmVer) - 1] = '\0';
				rBuildNo[sizeof(rBuildNo) - 1] = '\0';
				rExtendNo[sizeof(rExtendNo) - 1] = '\0';
				DBG_INFO("rFirmVer(%s) rBuildNo(%s) rExtendNo(%s)", rFirmVer, rBuildNo, rExtendNo);
				snprintf(firmVer, sizeof(firmVer), "%c.%c.%c.%c.%s_%s",
					rFirmVer[0], rFirmVer[1], rFirmVer[2], rFirmVer[3], rBuildNo, rExtendNo);
				DBG_INFO("firmware version(%s)", firmVer);
			}
			else
			{
				DBG_INFO("could not retrieve firmware information");
				ret = FW_FAIL_RETRIEVE;
				goto err;
			}
		}
	} else {
		DBG_INFO("could not retrieve firmware information");
		ret = FW_FAIL_RETRIEVE;
		goto err;
	}

	ret = FW_SUCCESS_CHECK;

err:
	nvram_set_int("cfg_fwstatus", ret);
	if (cm_ctrlBlock.role == IS_CLIENT)
		cm_sendFirmwareStatus(ret, firmVer);
	else if (cm_ctrlBlock.role == IS_SERVER) {
		if (ret == FW_SUCCESS_CHECK)
			cm_updateFirmwareVersion(firmVer);
	}

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_checkFirmware */

/*
========================================================================
Routine Description:
	Thread for download firmware.

Arguments:
	None

Return Value:
        None

========================================================================
*/
void *cm_downloadFirmware(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)     
        Set_CPU();
#endif 	
	pthread_detach(pthread_self());

	int ret = FW_START;
#ifndef FREE_MEMORY_DOWNLOAD
	int run = 0;
#endif
	char *run_script = "/usr/sbin/webs_download.sh";

	cancelUpgrade = 0;
#ifdef FREE_MEMORY_DOWNLOAD
	stopUpgrade = 0;
#endif

	if (cm_ctrlBlock.role == IS_CLIENT) {
		if (cm_ctrlBlock.flagIsFirmwareCheck) {
			DBG_INFO("exit firmware download");
#ifdef PTHREAD_EXIT
			return (void *)1;
#else
			pthread_exit(NULL);
#endif
		}

		cm_ctrlBlock.flagIsFirmwareCheck = 1;
	}

#if 0
	if (cm_ctrlBlock.role == IS_SERVER)
		nvram_set_int("cfg_upgrade", FW_START);
#endif
	nvram_set_int("cfg_fwstatus", FW_START);

	unlink("/tmp/linux.trx");

	/* force firmware upgrade */
#ifdef RTAC68U
	if (f_exists("/jffs/.sys/RT-AC68U/unlock") && nvram_match("fw_check", "1")) {
		ret = FW_SUCCESS_DOWNLOAD;
		goto err;
	}
#endif

	if (nvram_get_int("webs_state_update") &&
		!nvram_get_int("webs_state_error") &&
		strlen(nvram_safe_get("webs_state_info"))) {
		DBG_INFO("retrieve firmware information");

		if (!nvram_get_int("webs_state_flag")) {
			DBG_ERR("no need to upgrade firmware");
			ret = FW_NO_NEED_UPGRADE;
			goto err;
		}

#ifdef FREE_MEMORY_DOWNLOAD
		stopUpgrade = 1;
		nvram_unset("webs_state_upgrade");
		notify_rc_and_wait("stop_upgrade;start_webs_upgrade 1");	//parameter 1: cfg_mnt trigger webs_upgrade
		do {
			sleep(3);
			if (nvram_get_int("webs_state_upgrade") == 1)
				break;
		} while(1);

#else
		run = system(run_script);
		if (run != 127 && run != -1) {
			do {
				sleep(3);
				if (!pids(run_script))
					break;
			} while(1);
		}
		else
		{
			DBG_INFO("failed to run script");
			ret = FW_FAIL_RETRIEVE;
			goto err;
		}
#endif

		if (nvram_get_int("webs_state_error")) {
			DBG_ERR("download failure");
			ret = FW_FAIL_DOWNLOAD;
			goto err;
		}
	} else {
		DBG_INFO("could not retrieve firmware information");
		ret = FW_FAIL_RETRIEVE;
		goto err;
	}

	ret = FW_SUCCESS_DOWNLOAD;

err:
	if (!cancelUpgrade) {
		nvram_set_int("cfg_fwstatus", ret);
		if (cm_ctrlBlock.role == IS_CLIENT)
			cm_sendFirmwareStatus(ret, NULL);
	}

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_downloadFirmware */

/*
========================================================================
Routine Description:
	Do firmware check.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_doFirmwareCheck(unsigned char *msg)
{
	pthread_t fwThread;
	json_object *infoObj = NULL, *autoUpgradeEnableObj = NULL, *betaPathObj = NULL;
#if defined(RTCONFIG_BETA_UPGRADE)
	json_object*updateTsObj = NULL;
#endif
	int isChange = 0;

	DBG_INFO("enter");
	if (msg)
		infoObj = json_tokener_parse((char *)msg);

	if (infoObj) {
#if defined(RTCONFIG_AUTO_FW_UPGRADE)
		json_object_object_get_ex(infoObj, "auto_upgrade_enable", &autoUpgradeEnableObj);
		if (autoUpgradeEnableObj) {
			if (!nvram_match("webs_update_enable", (char *)json_object_get_string(autoUpgradeEnableObj))) {
				isChange++;
				DBG_INFO("update webs_update_enable (%s to %s)",
					nvram_safe_get("webs_update_enable"),
					(char *)json_object_get_string(autoUpgradeEnableObj));
				nvram_set("webs_update_enable", (char *)json_object_get_string(autoUpgradeEnableObj));
			}
		}
#endif
#if defined(RTCONFIG_BETA_UPGRADE)
		json_object_object_get_ex(infoObj, "beta_path", &betaPathObj);
		if (betaPathObj) {
			if (!nvram_match("webs_update_beta", (char *)json_object_get_string(betaPathObj))) {
				isChange++;
				DBG_INFO("update webs_update_beta (%s to %s)",
				nvram_safe_get("webs_update_beta"),
				(char *)json_object_get_string(betaPathObj));
				nvram_set("webs_update_beta", (char *)json_object_get_string(betaPathObj));
				nvram_commit();
			}

			json_object_object_get_ex(infoObj, "update_ts", &updateTsObj);
			if (updateTsObj) {
				if (!nvram_match("webs_update_ts", (char *)json_object_get_string(updateTsObj))) {

					DBG_INFO("update webs_update_ts (%s to %s)",
						nvram_safe_get("webs_update_ts"),
						(char *)json_object_get_string(updateTsObj));
					nvram_set("webs_update_ts", (char *)json_object_get_string(updateTsObj));
				}
			}
		}
#endif
		
		if(isChange > 0){
			nvram_commit();
		}

		json_object_put(infoObj);
	}

	if (pthread_create(&fwThread, attrp, cm_checkFirmware, NULL) != 0)
		DBG_ERR("could not create thread !!!");

	DBG_INFO("leave");
} /* End of cm_doFirmwareCheck */

/*
========================================================================
Routine Description:
	Do firmware download.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_doFirmwareDownload()
{
	pthread_t fwThread;

	DBG_INFO("enter");

	if (pthread_create(&fwThread, attrp, cm_downloadFirmware, NULL) != 0)
		DBG_ERR("could not create thread !!!");

	DBG_INFO("leave");
} /* End of cm_doFirmwareDownload */

/*
========================================================================
Routine Description:
	Thread for report the status of firmware check.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void *cm_reportFwCheckStatus(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif
	pthread_detach(pthread_self());
	int ret = nvram_get_int("cfg_fwstatus");

	if (nvram_get_int("webs_state_update") &&
		!nvram_get_int("webs_state_error") &&
		strlen(nvram_safe_get("webs_state_info"))) {

		if (!nvram_get_int("webs_state_flag"))
			ret = FW_NO_NEED_UPGRADE;
	}
	else
	{
		if (nvram_get_int("cfg_fwstatus") == FW_START)
			ret = FW_IS_CHECKING;
		else
			ret = FW_FAIL_RETRIEVE;
	}

	cm_sendFirmwareStatus(ret, NULL);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_reportFwCheckStatus */

/*
========================================================================
Routine Description:
	Thread for report firmware status.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void *cm_reportFwDownloadStatus(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)     
        Set_CPU();
#endif 	
	pthread_detach(pthread_self());
	int ret = nvram_get_int("cfg_fwstatus");
	
	if (nvram_get_int("webs_state_error")) {
		if (nvram_get_int("webs_state_error") == 1)	/* download failure */
			ret = FW_FAIL_DOWNLOAD;
		else if (nvram_get_int("webs_state_error") == 3)	/* wrong fw */
			ret = FW_IS_WRONG;
	}
	else
	{
		if (nvram_get_int("cfg_fwstatus") > FW_START)
			ret = nvram_get_int("cfg_fwstatus");
		else
			ret = FW_IS_DOWNLOADING;
	}

	cm_sendFirmwareStatus(ret, NULL);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_reportFwDownloadStatus */

/*
========================================================================
Routine Description:
	Report the status of firmware check.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_doFwCheckStatusReport()
{
        pthread_t fwThread;

        DBG_INFO("enter");

        if (pthread_create(&fwThread, attrp, cm_reportFwCheckStatus, NULL) != 0)
                DBG_ERR("could not create thread !!!");

        DBG_INFO("leave");
} /* End of cm_doFwCheckStatusReport */

/*
========================================================================
Routine Description:
	Report the status of firmware download.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_doFwDownloadStatusReport()
{
        pthread_t fwThread;

        DBG_INFO("enter");

        if (pthread_create(&fwThread, attrp, cm_reportFwDownloadStatus, NULL) != 0)
                DBG_ERR("could not create thread !!!");

        DBG_INFO("leave");
} /* End of cm_doFwDownloadStatusReport */

/*
========================================================================
Routine Description:
	Upgrade firmware.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_upgradeFirmware()
{
	if (!cm_ctrlBlock.flagIsFirmwareCheck)
		return;

	if (nvram_get_int("cfg_fwstatus") == FW_SUCCESS_DOWNLOAD) {
#if defined(RTCONFIG_URLFW)
		sleep(6);
#endif
#ifdef RTAC68U
		if (nvram_match("fw_check", "1"))
			fw_check();
		else
#endif
		notify_rc("restart_upgrade");
	}
	else
	{
		unlink("/tmp/linux.trx");

		if (cm_ctrlBlock.role == IS_SERVER &&
			nvram_get_int("cfg_fwstatus") == FW_NO_NEED_UPGRADE) {
			sleep(10);
			nvram_set_int("cfg_upgrade", FW_NONE);
			notify_rc("restart_httpd");
		}
	}

	nvram_unset("cfg_fwstatus");

	cm_ctrlBlock.flagIsFirmwareCheck = 0;
} /* End of cm_upgradeFirmware */

/*
========================================================================
Routine Description:
	Check firmware successful.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_checkFirmwareSuccess()
{
	cm_ctrlBlock.flagIsFirmwareCheck = 0;
} /* End of cm_checkFirmwareSuccess */

/*
========================================================================
Routine Description:
	Cancel firmware check.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_cancelFirmwareCheck()
{
	cm_ctrlBlock.flagIsFirmwareCheck = 0;
	killall("wget", SIGTERM);
	killall("webs_update.sh", SIGTERM);
	unlink("/tmp/linux.trx");
} /* End of cm_cancelFirmwareUpgrade */

/*
========================================================================
Routine Description:
	Cancel firmware upgrade.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_cancelFirmwareUpgrade()
{
	cancelUpgrade = 1;
	killall("wget", SIGTERM);
	killall("webs_download.sh", SIGTERM);
	unlink("/tmp/linux.trx");
	cm_ctrlBlock.flagIsFirmwareCheck = 0;

#ifdef FREE_MEMORY_DOWNLOAD
	if (stopUpgrade)
	{
		DBG_INFO("stop upgrade (%d)", stopUpgrade);
		if (cm_ctrlBlock.role == IS_SERVER)
			sleep(10);
		kill(1, SIGTERM);
	}
#endif
} /* End of cm_cancelFirmwareUpgrade */
