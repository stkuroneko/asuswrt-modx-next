#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include <sys/un.h>
#include "encrypt_main.h"
#include "cfg_crc.h"
#include "cfg_common.h"
#include "cfg_param.h"
#include "cfg_capability.h"
#include "cfg_client.h"
#include "cfg_ipc.h"
#ifdef LEGACY_ROAMING
#include "cfg_roaming.h"
#endif
#include "cfg_udp.h"
#include "cfg_dencrypt.h"
#include "cfg_wevent.h"
#include "cfg_upgrade.h"
#ifdef ROAMING_INFO
#include "cfg_roaminginfo.h"
#endif
#include "cfg_clientlist.h"
#include "cfg_event.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#ifdef RADAR_DET
#include "cfg_radardet.h"
#include "chmgmt.h"
#endif	/* RADAR_DET */
#include "cfg_sched.h"
#include "cfg_slavelist.h"
#ifdef RTCONFIG_DWB
#include "cfg_dwb.h"
#endif
#include "cfg_chanspec.h"
#include "cfg_parammgnt.h"
#ifdef DUAL_BAND_DETECTION
#include "cfg_dualbandlist.h"
#endif
#ifdef RTCONFIG_BHCOST_OPT
#include <wlioctl.h>
#include <wlutils.h>
#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#endif
#ifdef RTCONFIG_AMAS
#include <amas-utils.h>
#endif
#include "cfg_action.h"
#ifdef PRELINK
#include "cfg_prelink.h"
#endif
#if defined(RTCONFIG_TCODE) && defined(RTCONFIG_CFGSYNC_LOCSYNC)
#include "cfg_loclist.h"	//cm_Set_location_code()
#endif
#ifdef RTCONFIG_NBR_RPT
#include "cfg_nbr_rpt.h"
#endif
#ifdef CONN_DIAG
#include "cfg_conndiag.h"
#endif

/* for parameter */
int port = 7788;
int serverPort = 7788;
CM_CTRL cm_ctrlBlock;
static char serverIp[32];
static char groupID[CFGSYNC_GROUPID_LEN+1];
int sessionKeyExpireTime = SESSION_KEY_EXPIRE_TIME;
int groupKeyExpireTime = GROUP_KEY_EXPIRE_TIME;
static void cm_closeSocket(CM_CTRL *pCtrlBK);
static int cm_checkCfgState(int all);
int lastState = START;
int curState = INIT;
int notifiedCfg = 0;
#if defined(SYNC_WCHANNEL)
int syncChannel = 1;
#endif
#ifdef ONBOARDING
int obTimeStamp = 0;
#endif

/* for pthead */
pthread_mutex_t weventLock;		/* for wireless event */
pthread_mutex_t allWeventLock;		/* for all wireless event */
pthread_mutex_t wiredClientListLock;		/* for wired client list */
pthread_mutex_t clientListLock;		/* for client list */
#ifdef ONBOARDING
pthread_mutex_t onboardingLock;		/* for onboarding */
#endif
pthread_mutex_t radarDetLock;		/* for radar detect */
#ifdef ROAMING_INFO
pthread_mutex_t roamingInfoLock;		/* for romaing info */
#endif
#ifdef LEGACY_ROAMING
pthread_mutex_t roamingLock;		/* for romaing */
#endif
pthread_mutex_t reListLock;		/* for re list */
pthread_mutex_t chanspecLock;		/* for chanspec */
#ifdef DUAL_BAND_DETECTION
pthread_mutex_t dualBandLock;		/* for wireless dual band */
#endif
#ifdef PRELINK
pthread_mutex_t prelinkLock;		/* for prelink */
#endif
pthread_mutex_t changedConfigLock;		/* for changed config */
#ifdef RTCONFIG_NBR_RPT
pthread_mutex_t nbrRptLock;		/* for neighbor report */
#endif
#ifdef CONN_DIAG
pthread_mutex_t connDiagLock;	/* for conn diag udp */
#endif
pthread_attr_t attr;
pthread_attr_t *attrp = NULL;

/* for band number */
int supportedBandNum = 0;

/* for the channel selection of 5G low/high band */
int selected5gBand = NO_SELECTION;

/* for function */
int cm_packetProcess(int sock_fd, unsigned char *data, int data_len, CM_CTRL *pCtrlBK, securityInfo *keyInfo);
#ifdef PRELINK
void cm_updateChangedHashBundleKey(json_object *keyObj);
#endif

/* for session & group key to update time */
static long uptimeDiff = 0;
static int uptimeDiffSet = 0;

/* for reset to default */
int resetDefault = 0;

#ifdef MASTER_DET
/* for validating master */
int validMaster = 0;
int masterDisconnectCount = 0;
char *masterList = NULL;
int masterListLen = 0;
int cm_detectMaster(char *invalidMasterIp);
#endif

/* for scheduler */
int lastSchedKeepAliveStatus = 0;
int schedKeepAliveCount = 0;
static struct sched scCfgCheck;	/* The scheduler for check cfg */
static struct sched scStatusReport;	/* The scheduler for reporting status */
static struct sched scWeventReport;	/* The scheduler for reporting wireless event */
static struct sched scStaListReport; /* The scheduler for reporting sta list */
static struct sched scClientListReport; /* The scheduler for reporting client list */
#if 0// defined(SYNC_WCHANNEL)
static struct sched scWchannelCheck; /* The scheduler for checking wireless channel */
#endif
static struct sched scSessionKeyCheck; /* The scheduler for checking session key */
static struct sched scGroupKeyCheck; /* The scheduler for checking group key */
#if 0
static struct sched scTopologyGet;	/* The scheduler for getting network topology */
#endif
static struct sched keepAliveCheck;	/* The scheduler for checking keepalive */
static struct sched scWiredClientListCheck; /* The scheduler for checking wired client list */

/* for connect keepalive */
int connKeepAliveCount = 0;

/* for disconnect count */
int disconnectCount = 0;

int pid = 0;

#ifdef CONN_DIAG
/* for conn diag */
struct list *connDiagUdpList = NULL;
#endif

/*
========================================================================
Routine Description:
	initiate a connection on a socket (retry)

Arguments:
	sockfd			- socket file description
	addr			- struct sockaddr
	addrlen			- struct sockaddr len
	retry_count		- retry count (0 is no retry)
	retry_timewait	- retry time wait(msec), default 10ms

Return Value:
	If the connection or binding succeeds, zero is returned. On error, -1 is returned, and errno is set appropriately.

========================================================================
*/
static int sock_connect(
	int sockfd,
	const struct sockaddr *addr,
	socklen_t addrlen,
	int retry_count,
	int retry_timewait	/* msec */)
{
	int i, res = -1;
	int flags;
	int status;
	socklen_t statusLen;
	fd_set writeFds;
	int selectRet;
	struct timeval timeout = {3, 0};

	if (retry_count <= 0)
	{
		retry_count = 1;
	}

	if (retry_timewait < 0)
	{
		retry_timewait = 100;	/* 100 msec */
	}

	/* set NONBLOCK for connect() */
	if ((flags = fcntl(sockfd, F_GETFL)) < 0) {
		DBG_LOG("F_GETFL error!");
		return res;
	}

	flags |= O_NONBLOCK;

	if (fcntl(sockfd, F_SETFL, flags) < 0) {
		DBG_LOG("F_SETFL error!");
		return res;
	}

	for (i=0; i<retry_count; i++)
	{
		DBG_INFO("sock_connect() : %d ...", i+1);

		if (connect(sockfd, addr, addrlen) < 0) {
			if (errno == EINPROGRESS) {
				FD_ZERO(&writeFds);
				FD_SET(sockfd, &writeFds);

				selectRet = select(sockfd + 1, NULL, &writeFds, NULL, &timeout);

				//Check return, -1 is error, 0 is timeout
				if (selectRet == -1 || selectRet == 0) {
					if (selectRet == -1)
						DBG_LOG("failed to select: %s(%d)", strerror(errno), errno);
					else if (selectRet == 0)
						DBG_LOG("failed to select: timeout");
					usleep(retry_timewait * 1000);
					continue;
				}
			}
			else
			{
				DBG_LOG("failed to connect: %s(%d)", strerror(errno), errno);
				usleep(retry_timewait * 1000);
				continue;
			}
		}

		/* check the status of connect() */
		status = 0;
		statusLen = sizeof(status);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
			DBG_LOG("getsockopt(SO_ERROR): %s(%d)", strerror(errno), errno);
			usleep(retry_timewait * 1000);
			continue;
		}

		if (status) {
			DBG_ERR("error for connect()");
			usleep(retry_timewait * 1000);
			continue;
		}

		res = 1;
		break;
	}

	if (res == 1) {
		/* unset NONBLOCK for connect() */
		flags &= ~O_NONBLOCK;
		if (fcntl(sockfd, F_SETFL, flags) < 0) {
			DBG_LOG("F_SETFL error!");
			res = -1;
		}
	}

	return res;
}

/*
========================================================================
Routine Description:
	Disconnection judgement.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_judgeDisconnection()
{
#if 0
	system("echo flush > /proc/dpsta_stalist");
#endif
	disconnectCount++;
	if (disconnectCount >= DISCONNECT_THRESHOLD) {
		DBG_LOG("match the disconnection criteria (%d)", disconnectCount);
		curState = DISCONN;
	}
} /* End of cm_judgeDisconnection */

/*
========================================================================
Routine Description:
	Clean disconnection count and set to 0.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_cleanDisconnection()
{
	disconnectCount = 0;
} /* End of cm_cleanDisconnection */

/*
========================================================================
Routine Description:
	Update time for sesssion and group key.

Arguments:
	None

Return Value:
	None

========================================================================
*/
static void cm_updateTime(void)
{
	long newDiff;
	struct timeval t;
	struct sysinfo i;

	gettimeofday(&t, NULL);
	sysinfo(&i);
	newDiff = t.tv_sec - i.uptime;

	if (!uptimeDiffSet) {
		uptimeDiff = newDiff;
		uptimeDiffSet = 1;
		return;
	}

	if ((newDiff - 5 > uptimeDiff) || (newDiff + 5 < uptimeDiff)) {
		/* system time has changed, update counters and timeouts */
		DBG_INFO("System time change detected.");

		/* update start time of group key */
		if (cm_ctrlBlock.groupKeyStartTime > 0)
			cm_ctrlBlock.groupKeyStartTime += newDiff - uptimeDiff;
		if (cm_ctrlBlock.groupKey1StartTime > 0)
			cm_ctrlBlock.groupKey1StartTime += newDiff - uptimeDiff;

		/* update start time of session key */
		if (cm_ctrlBlock.sessionKeyStartTime > 0)
			cm_ctrlBlock.sessionKeyStartTime += newDiff - uptimeDiff;
		if (cm_ctrlBlock.sessionKey1StartTime > 0)
			cm_ctrlBlock.sessionKey1StartTime += newDiff - uptimeDiff;
	}
	uptimeDiff = newDiff;
} /* End of cm_updateTime */

/*
========================================================================
Routine Description:
	Handle termination signal.

Arguments:
	sig		- no use

Return Value:
	None

========================================================================
*/
static void cm_terminateHandle(int sig)
{
	int sig_pid = getpid();

	if (sig == SIGTERM || sig == -1) {
		if (sig == SIGTERM) {
			DBG_INFO("pid (%d) got SIGTERM", sig_pid);
			if (pid != sig_pid) {
				DBG_INFO("pid (%d) isn't main, pass signal handle", sig_pid);
				return;
			}
		}
		else
		{
			DBG_INFO("terminate by itself");
		}

#ifdef DUAL_BAND_DETECTION
		cm_destroyDBListSharedMemory(0);
#endif

		/* delete json object */
#ifdef ROAMING_INFO
		json_object_put(staRoamingInfo);
#endif

		/* close all used sockets */
		cm_closeSocket(&cm_ctrlBlock);

		/* free session/group key */
		if (!IsNULL_PTR(cm_ctrlBlock.sessionKey)) MFREE(cm_ctrlBlock.sessionKey);
		if (!IsNULL_PTR(cm_ctrlBlock.sessionKey1)) MFREE(cm_ctrlBlock.sessionKey1);
		if (!IsNULL_PTR(cm_ctrlBlock.groupKey)) MFREE(cm_ctrlBlock.groupKey);
		if (!IsNULL_PTR(cm_ctrlBlock.groupKey1)) MFREE(cm_ctrlBlock.groupKey1);

#ifdef CONN_DIAG
		/* for conn diag */
		if (connDiagUdpList) {
			cm_terminateConnDiagPktList();
			list_delete(connDiagUdpList);
		}
#endif

		/* set flagIsTerminated for stopping to receive notification */
		cm_ctrlBlock.flagIsTerminated = 1;

#ifdef PTHREAD_STACK_SIZE
		if (attrp != NULL) pthread_attr_destroy(attrp);
#endif

#ifdef MASTER_DET
		if (masterList) {
			free(masterList);
			masterList = NULL;
		}
#endif

		/* set cfg_alive for exit */
		nvram_set("cfg_alive", "0");

		/* set flagIsRunning for exit */
		cm_ctrlBlock.flagIsRunning = 0;
	}
} /* End of cm_terminateHandle */

/*
========================================================================
Routine Description:
	Check timeout for the session key.

Arguments:
	None

Return Value:
	0		- not expired
	1		- expired

========================================================================
*/
static int cm_checkSessionKeyExpire()
{
	int sKeyTime = (int) (uptime() - cm_ctrlBlock.sessionKeyStartTime);
	int sKey1Time = (int) (uptime() - cm_ctrlBlock.sessionKey1StartTime);

	if (sKeyTime >= sessionKeyExpireTime &&
		sKey1Time >= sessionKeyExpireTime) {
		DBG_INFO("sKeyTime(%d), sKey1Time(%d), sessionKeyExpireTime(%d)",
				sKeyTime, sKey1Time, sessionKeyExpireTime);
		return 1;
	}

	return 0;
} /* End of cm_checkSessionKeyExpire */

/*
========================================================================
Routine Description:
	Check timeout for the group key.

Arguments:
	None

Return Value:
	0		- not expire
	1		- expire

========================================================================
*/
int cm_checkGroupKeyExpire()
{
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	if (!cm_ctrlBlock.groupKeyReady)
		return 1;

	if (gKeyTime >= groupKeyExpireTime &&
		gKey1Time >= groupKeyExpireTime) {
		DBG_INFO("gKeyTime(%d), gKey1Time(%d), groupKeyExpireTime(%d)",
				gKeyTime, gKey1Time, groupKeyExpireTime);
		return 1;
	}

	return 0;
} /* End of cm_checkGroupKeyExpire */

/*
========================================================================
Routine Description:
	Display client info trigger by USR1 signal.

Arguments:
	sig		- no use

Return Value:
	None

========================================================================
*/
static void cm_usr1Handle(int sig)
{
	if (!strcmp(nvram_safe_get("cfg_status"), "1")) {
		CM_CTRL *pCtrlBK = &cm_ctrlBlock;
		char *dump = NULL;

		DBG_PRINTF("Current state: %d\n", curState);
		DBG_PRINTF("Last state: %d\n", lastState);
		DBG_PRINTF("Firmware Check: %d\n", pCtrlBK->flagIsFirmwareCheck);
		DBG_PRINTF("Cost: %d\n", pCtrlBK->cost);
		DBG_PRINTF("Master's IP: %s\n", serverIp);
#ifdef MASTER_DET
		DBG_PRINTF("Valid Master: %d\n", validMaster);
#endif

		/* show time for session key */
		DBG_PRINTF("Expired time for session key: %d\n", sessionKeyExpireTime);
		DBG_PRINTF("Session Key Ready: %d\n", pCtrlBK->sessionKeyReady);
		if (pCtrlBK->sessionKeyStartTime != 0) {
			dump = dumpHEX((unsigned char *)&pCtrlBK->sessionKey[0], pCtrlBK->sessionKeyLen);
			if (!IsNULL_PTR(dump)) {
				DBG_PRINTF("*** DUMP session key ***\n%s\n", dump);
				MFREE(dump);
				dump = NULL;
			}
		}
		DBG_PRINTF("Session Key Time: %d\n", (int) (uptime() - pCtrlBK->sessionKeyStartTime));
		DBG_PRINTF("Session Key Start Time: %ld\n", pCtrlBK->sessionKeyStartTime);

		if (pCtrlBK->sessionKey1StartTime != 0) {
			dump = dumpHEX((unsigned char *)&pCtrlBK->sessionKey1[0], pCtrlBK->sessionKeyLen);
			if (!IsNULL_PTR(dump)) {
				DBG_PRINTF("*** DUMP session key ***\n%s\n", dump);
				MFREE(dump);
				dump = NULL;
			}
		}
		DBG_PRINTF("Session Key 1 Time: %d\n", (int) (uptime() - pCtrlBK->sessionKey1StartTime));
		DBG_PRINTF("Session Key 1 Start Time: %ld\n", pCtrlBK->sessionKey1StartTime);
		DBG_PRINTF("Now Up Time: %ld\n", uptime());

		/* show time for group key */
		DBG_PRINTF("Expired time for group key: %d\n", groupKeyExpireTime);
		DBG_PRINTF("Group Key Ready: %d\n", pCtrlBK->groupKeyReady);
		if (pCtrlBK->groupKeyStartTime != 0) {
		dump = dumpHEX((unsigned char *)&pCtrlBK->groupKey[0], pCtrlBK->groupKeyLen);
		if (!IsNULL_PTR(dump)) {
			DBG_PRINTF("*** DUMP group key ***\n%s\n", dump);
			MFREE(dump);
			dump = NULL;
		}
		}
		DBG_PRINTF("Group Key Time: %d\n", (int) (uptime() - pCtrlBK->groupKeyStartTime));
		DBG_PRINTF("Group Key Start Time: %ld\n", pCtrlBK->groupKeyStartTime);

		if (pCtrlBK->groupKey1StartTime != 0) {
			dump = dumpHEX((unsigned char *)&pCtrlBK->groupKey1[0], pCtrlBK->groupKeyLen);
			if (!IsNULL_PTR(dump)) {
				DBG_PRINTF("*** DUMP group key ***\n%s\n", dump);
				MFREE(dump);
				dump = NULL;
			}
		}
		DBG_PRINTF("Group Key 1 Time: %d\n", (int) (uptime() - pCtrlBK->groupKey1StartTime));
		DBG_PRINTF("Group Key 1 Start Time: %ld\n", pCtrlBK->groupKey1StartTime);
		DBG_PRINTF("Now Up Time: %ld\n", uptime());
	}

#if 0
	/* for test */
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	unsigned char msgBuf[256] = {0};
	//snprintf((char *)&msgBuf[0], sizeof(msgBuf), "{\"RAST\": { \"EID\": \"1\", \"STA\": \"00:11:22:33:44:55\", \"RSSI\": \"-80\", \"BAND\": \"2\"}}");
	//encryptedMsg = cm_aesEncryptMsg(cm_ctrlBlock.groupKey, REQ_STAMON, &msgBuf[0], strlen((char *)msgBuf), &encLen);
	//snprintf((char *)&msgBuf[0], sizeof(msgBuf), "{\"RAST\": { \"EID\": \"2\", \"STA\": \"00:11:22:33:44:55\", \"RSSI\": \"-70\", \"AP\": \"D8:50:E6:5A:3F:C0\"}}");
	//encryptedMsg = cm_aesEncryptMsg(cm_ctrlBlock.groupKey, RSP_STAMON, &msgBuf[0], strlen((char *)msgBuf), &encLen);

	snprintf((char *)&msgBuf[0], sizeof(msgBuf), "{\"RAST\": { \"EID\": \"4\", \"STA\": \"00:11:22:33:44:55\", \"RSSI\": \"-70\", \"AP\": \"%s\"}}", get_lan_hwaddr());
	encryptedMsg = cm_aesEncryptMsg(cm_ctrlBlock.groupKey, REQ_ACL, &msgBuf[0], strlen((char *)msgBuf), &encLen);

        if (IsNULL_PTR(encryptedMsg)) {
                DBG_ERR("Failed to MALLOC() !!!");
                return;
        }

        if (cm_sendUdpPacket("192.168.1.255", encryptedMsg, encLen) == 0) {
                DBG_ERR("Fail to send UDP packet to %s!");
        }

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
	DBG_INFO("send udp packet out");
#endif
} /* End of cm_usr1Handle */

/*
========================================================================
Routine Description:
	Kill running daemon if exists.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_killDaemon()
{
	kill_pidfile_s(PID_CM_CLIENT, SIGTERM);

	/* sleep for a where to kill old daemon */
	sleep(1);
} /* End of cm_killDaemon */

/*
========================================================================
Routine Description:
	Save the pid for running daemon.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_saveDaemonPid()
{
	FILE *fp;

	/* write pid */
	if ((fp = fopen(PID_CM_CLIENT, "w")) != NULL)
	{
		pid = getpid();
		fprintf(fp, "%d", pid);
		fclose(fp);
	}
} /* End of cm_saveDaemonPid */


/*
========================================================================
Routine Description:
	check specific requirements for cm_prepareCheckMsg()

Arguments:
	feature		- sub feature

Return Value:
	1: ok, 0: invalid

========================================================================
*/
static int cm_prepareCheckMsgBefore(
	struct subfeature_mapping_s *feature)
{
	int ret = 1;

	switch (feature->index)
	{
		case SUBFT_REGION:
			ret = (!nvram_contains_word("rc_support", "loclist")) ? 0 : 1;
			break;
	}

	return ret;
}

/*
========================================================================
Routine Description:
	Index to name for subfeature.

Arguments:
	ftIndex		- Index

Return Value:
	subfeature name

========================================================================
*/
static char *cm_subfeatureIndex2Name(int ftIndex)
{
	struct subfeature_mapping_s *pFeature = NULL;
	char *ftName = NULL;

	for (pFeature = &subfeature_mapping_list[0]; pFeature->index != 0; pFeature++) {
		if (ftIndex == pFeature->index) {
			ftName = pFeature->name;
			break;
		}
	}

	return ftName;
} /* End of cm_subfeatureIndex2Name */

/*
========================================================================
Routine Description:
	Add dynamic private feature for reporting.

Arguments:
	None

Return Value:
	None

========================================================================
*/
static void cm_addDynamicPrivateFeature(json_object *ftArray)
{
	char *ftName = NULL;
	int ledCtrlVal = nvram_get_int("led_ctrl_cap");
	capability_s *pCapability = NULL;
	int i = 0, radioFt[] = { SUBFT_RADIO_BAND1, SUBFT_RADIO_BAND2, SUBFT_RADIO_BAND3, SUBFT_RADIO_BAND4, 0};

	if (ftArray == NULL) {
		DBG_ERR("ftArray is NULL");
		return;
	}

	/* for led control */
	if (ledCtrlVal > 0) {
		for (pCapability = &led_ctrl_capability_list[0]; pCapability->type != 0; pCapability++) {
			if ((ledCtrlVal & pCapability->type) > 0) {
				if ((ftName = cm_subfeatureIndex2Name(pCapability->subtype)))
					json_object_array_add(ftArray, json_object_new_string(ftName));
			}
		}
	}

	/* for wifi radio */
	for (i = 0; i < supportedBandNum; i++) {
		if (radioFt[i] == 0) {
			DBG_INFO("radioFt[%d] is 0, band num(%d)", i, supportedBandNum);
			break;
		}

		if ((ftName = cm_subfeatureIndex2Name(radioFt[i])))
			json_object_array_add(ftArray, json_object_new_string(ftName));
	}
} /* End of cm_addDynamicPrivateFeature */

/*
========================================================================
Routine Description:
	Add dynamic feature for reporting.

Arguments:
	None

Return Value:
	None

========================================================================
*/
static void cm_addDynamicFeature(json_object *ftArray)
{
	char *ftName = NULL;
	int ledCtrlVal = nvram_get_int("led_ctrl_cap");
	capability_s *pCapability = NULL;
	int i = 0;
	int *pFtList = NULL;
	int *wifiBand[] = {wifi_band1_ft_list, wifi_band2_ft_list, wifi_band3_ft_list, wifi_band4_ft_list, NULL};
	struct subfeature_mapping_s *pFeature = NULL;
#if defined(RTCONFIG_WIFI_SON)
	int *pFtList_wifison;
#endif

	if (ftArray == NULL) {
		DBG_ERR("ftArray is NULL");
		return;
	}

	/* for wifi based on supportedBandNum */
	for (i = 0; i < supportedBandNum; i++) {
		if (wifiBand[i] == NULL) {
			DBG_INFO("wifiBand(%d) is NULL", i);
			break;
		}

		pFtList = wifiBand[i];
		while (*pFtList != 0) {
			for (pFeature = &subfeature_mapping_list[0]; pFeature->index != 0; pFeature++) {
				if (*pFtList == pFeature->index) {
					json_object_array_add(ftArray, json_object_new_string(pFeature->name));
					break;
				}
			}
			pFtList++;
		}
	}

	/* for common */
	pFtList = common_ft_list;
	while (*pFtList != 0) {
#if defined(RTCONFIG_WIFI_SON)
		if(nvram_match("wifison_ready", "1"))
		{
			pFtList_wifison = common_ft_1905_control;

			while(*pFtList_wifison!=0)
			{
				if (*pFtList_wifison == *pFtList)
					goto skip_FtList;
				pFtList_wifison++;
			}
		}
		else
		{
			//These commamds are illegal, if wifison is not ready yet.
			if(*pFtList==SUBFT_SPCMD
#if defined(MAPAC2200) || defined(RTAC95U)
			    || *pFtList==SUBFT_NCB
#endif
			)
				goto skip_FtList;
		}
#endif

		for (pFeature = &subfeature_mapping_list[0]; pFeature->index != 0; pFeature++) {
			if (*pFtList == pFeature->index) {
				if (cm_prepareCheckMsgBefore(pFeature))
					json_object_array_add(ftArray, json_object_new_string(pFeature->name));
				break;
			}
		}
#if defined(RTCONFIG_WIFI_SON)
skip_FtList:
#endif
		pFtList++;
	}

#if 0
	/* for led control */
	if (ledCtrlVal > 0) {
		for (pCapability = &led_ctrl_capability_list[0]; pCapability->type != 0; pCapability++) {
			if ((ledCtrlVal & pCapability->type) > 0) {
				if ((ftName = cm_subfeatureIndex2Name(pCapability->subtype)))
					json_object_array_add(ftArray, json_object_new_string(ftName));
			}
		}
	}
#endif
} /* End of cm_addDynamicFeature */

/*
========================================================================
Routine Description:
	Prepare check message.

Arguments:
	msg		- output message array
	msgLen		- the legnth of output message array
	all		- get all config to check
	reportVer		- report version info

Return Value:
	message length

========================================================================
*/

static int cm_prepareCheckMsg(char *msg, int msgLen, int all, int reportVer)
{
	json_object *root = NULL;
	char *cfgVer = nvram_safe_get("cfg_ver");
	json_object *ftArray = NULL;
	int *privFtList = private_ft_list;
	json_object *fileRoot = NULL;
	json_object *ftRoot = NULL;
	json_object *ftObj = NULL;
	json_object *ftObjNew = NULL;
	json_object *capabilityObj = NULL;
	json_object *miscInfoObj = NULL;
	char *ftName = NULL;
#if 0
	char sta2g[18] = {0};
	char sta5g[18] = {0};
#ifdef SUPPORT_TRI_BAND
	int band5g;
#if defined(RTCONFIG_WIFI_SON)
	if(nvram_match("wifison_ready", "1"))
		band5g = 1;
	else
#endif
		band5g = 2;
#else
	int band5g = 1;
#endif
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	char sta2gTraffic[18] = {0};
	char sta5gTraffic[18] = {0};
	unsigned char brMac[MAC_LEN] = {0};
#endif
#endif
#if defined(RTCONFIG_WIFI_SON)
	int mode,*pFtList_wifison;
#endif

	char prefix[sizeof("wlXXXXX_")], amasWlcPrefix[sizeof("amas_wlcXXXX_")];
	char word[256], *next, tmp[64];
	char wlIfnames[64], sta[18], staTraffic[18];
	char *staIndexStr = NULL;
	int unit = 0;
	int nband = 0;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	unsigned char brMac[MAC_LEN] = {0};
	char *staTrafficIndexStr = NULL;
#endif

	root = json_object_new_object();

	if (root == NULL) {
		DBG_ERR("root is NULL");
		return 0;
	}

	/* prepare required */
	if (reportVer) {
		json_object_object_add(root, CFG_STR_CFGVER, json_object_new_string(cfgVer));
		if (all) json_object_object_add(root, CFG_STR_CFGALL, json_object_new_string(""));
	}
	else
	{
		unit = 0;
		strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
		foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			snprintf(amasWlcPrefix, sizeof(amasWlcPrefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(unit));
			if (nvram_get_int(strcat_r(amasWlcPrefix, "use", tmp))) {
				staIndexStr = NULL;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
				staTrafficIndexStr = NULL;
#endif
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				if (nband == 2) {
					staIndexStr = CFG_STR_STA2G;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					staTrafficIndexStr = CFG_STR_STA2G_TRAFFIC;
#endif
				}
				else if (nband == 1) {;
					staIndexStr = CFG_STR_STA5G;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					staTrafficIndexStr = CFG_STR_STA5G_TRAFFIC;
#endif
				}
				else if (nband == 4) {
					staIndexStr = CFG_STR_STA6G;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					staTrafficIndexStr = CFG_STR_STA6G_TRAFFIC;
#endif
				}

				/* sta info */
				if (staIndexStr) {
					snprintf(sta, sizeof(sta), "%s", get_sta_mac(unit));
					json_object_object_add(root, staIndexStr, json_object_new_string(sta));
				}

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
				/* sta traffic info */
				if (!nvram_match(strcat_r(prefix, "mode", tmp), "wet") && staTrafficIndexStr) {
					memset(brMac, 0, sizeof(brMac));
					ether_atoe(cm_ctrlBlock.brIfMac, brMac);
					convert_smac_for_traffic(unit, brMac);
					snprintf(staTraffic, sizeof(staTraffic), "%02X:%02X:%02X:%02X:%02X:%02X",
							brMac[0], brMac[1], brMac[2], brMac[3], brMac[4], brMac[5]);
					json_object_object_add(root, staTrafficIndexStr, json_object_new_string(staTraffic));
				}
#endif
			}
		}

#if 0
		snprintf(sta2g, sizeof(sta2g), "%s", get_sta_mac(0));
		json_object_object_add(root, CFG_STR_STA2G, json_object_new_string(sta2g));
		snprintf(sta5g, sizeof(sta5g), "%s", get_sta_mac(band5g));
		json_object_object_add(root, CFG_STR_STA5G, json_object_new_string(sta5g));
#endif
		/* capability */
		capabilityObj = cm_generateCapability(RE_SUPPORT, &capability_list[0]);
		if (capabilityObj)
			json_object_object_add(root, CFG_STR_CAPABILITY, capabilityObj);

		/* misc info */
		if (f_exists(MISC_INFO_JSON_PATH)) {
			miscInfoObj = json_object_from_file(MISC_INFO_JSON_PATH);
			if (miscInfoObj)
				json_object_object_add(root, CFG_STR_MISC_INFO, miscInfoObj);
		}
#if 0
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		/* sta 2g for traffic */
		memset(brMac, 0, sizeof(brMac));
		ether_atoe(pCtrlBK->brIfMac, brMac);
		convert_smac_for_traffic(0, brMac);
		snprintf(sta2gTraffic, sizeof(sta2gTraffic), "%02X:%02X:%02X:%02X:%02X:%02X",
				brMac[0], brMac[1], brMac[2], brMac[3], brMac[4], brMac[5]);
		json_object_object_add(root, CFG_STR_STA2G_TRAFFIC, json_object_new_string(sta2gTraffic));
		/* sta 5g for traffic */
		memset(brMac, 0, sizeof(brMac));
		ether_atoe(pCtrlBK->brIfMac, brMac);
		convert_smac_for_traffic(band5g, brMac);
		snprintf(sta5gTraffic, sizeof(sta5gTraffic), "%02X:%02X:%02X:%02X:%02X:%02X",
				brMac[0], brMac[1], brMac[2], brMac[3], brMac[4], brMac[5]);
		json_object_object_add(root, CFG_STR_STA5G_TRAFFIC, json_object_new_string(sta5gTraffic));
#endif
#endif
	}

	json_object_object_add(root, CFG_STR_MODEL_NAME, json_object_new_string(get_productid()));
	json_object_object_add(root, CFG_STR_SWMODE, json_object_new_string(nvram_safe_get("sw_mode")));
	
	/* supported band number */
	json_object_object_add(root, CFG_STR_BANDNUM, json_object_new_int(supportedBandNum));
	
	json_object_object_add(root, CFG_STR_VENDOR, json_object_new_string(VENDOR_NAME));

	/* add cfg band index version */
#if defined(RTCONFIG_BANDINDEX_NEW)
	json_object_object_add(root, CFG_BAND_INDEX_VERSION, json_object_new_string("2"));
#else
	json_object_object_add(root, CFG_BAND_INDEX_VERSION, json_object_new_string("1"));
#endif
	
	/* add cfg band type */
	cm_addBandIndex(root);
	
	/* get unique mac for dut */
	json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));

	/* feature list */
	ftArray = json_object_new_array();
	if (ftArray) {
		/* add dynamic featrure in ftArray */
		cm_addDynamicFeature(ftArray);
		json_object_object_add(root, CFG_STR_FEATURE, ftArray);
	}

#if defined(RTCONFIG_WIFI_SON)
        if(nvram_match("wifison_ready", "1"))
		goto skip_priv_feature;
#endif
	/* private feature list */
	if (!reportVer) {
		ftArray = NULL;
		while (*privFtList != 0) {
			if (!ftArray)
				ftArray = json_object_new_array();

			if (ftArray) {
				if ((ftName = cm_subfeatureIndex2Name(*privFtList)))
					json_object_array_add(ftArray, json_object_new_string(ftName));
			}

			privFtList++;
		}

		if (ftArray) {
			cm_addDynamicPrivateFeature(ftArray);
			json_object_object_add(root, CFG_STR_PRIVATE_FEATURE, ftArray);
		}
	}
	else
	{
		if (all) {
			/* report private cfg w/ real parameters */
			fileRoot = json_object_from_file(PRIVATE_CFG_JSON_PATH);
			if (fileRoot) {
				json_object_object_foreach(fileRoot, key, val) {
					if (!ftRoot)
						ftRoot = json_object_new_object();
					ftName = key;
					ftObj = val;
					ftObjNew = NULL;

					json_object_object_foreach(ftObj, key, val) {
						if (!ftObjNew)
							ftObjNew = json_object_new_object();

						if (nvram_get(key))
							json_object_object_add(ftObjNew, key,
								json_object_new_string(nvram_safe_get(key)));
						else if (!strcmp(key, "action_script"))
							json_object_object_add(ftObjNew, key,
								json_object_new_string(json_object_get_string(val)));
					}

					if (ftObjNew)
						json_object_object_add(ftRoot, ftName, ftObjNew);
				}

				if (ftRoot)
					json_object_object_add(root, CFG_STR_PRIVATE_FEATURE, ftRoot);
			}

			json_object_put(fileRoot);
		}
	}
skip_priv_feature:

	snprintf(msg, msgLen, "%s", json_object_to_json_string_ext(root, 0));
	DBG_INFO("msg(%s)", msg);
	json_object_put(root);

	return strlen(msg);
} /* End of cm_prepareCheckMsg */

/*
========================================================================
Routine Description:
	Prepare report message.

Arguments:
	msg		- output message array
	msgLen		- the legnth of output message arrary
	reportIndex	- the index of report type

Return Value:
	message length

========================================================================
*/
static int cm_prepareReportMsg(char *msg, int msgLen, unsigned int *reportIndex)
{
	json_object *root = NULL, *curChannelObj = NULL, *chanspecObj = NULL, *selChannelObj = NULL;
	json_object *wiredPortObj = NULL, *configRoot = NULL, *configObj = NULL;
	json_object *wiredClientListObj = NULL;
#ifdef PLC_STATUS
	json_object *plcStatusObj = NULL;
#endif	/* PLC_STATUS */
	int unit = 0, num5g = 0;
	char prefix[16] = {0};
	char tmp[64] = {0};
	char word[256], *next;
	char *p;
	//char portNo[32] = {0};
	int reportPapInfo = 0;
	char fwVer[33] = {0};
#ifdef REPORT_PAP_INFO
	reportPapInfo = is_router_mode() ? 0 : 1;
#endif
	if (nvram_get_int("re_mode") == 1)
		reportPapInfo = 1;
#ifdef RADAR_DET
	int ret;
	char ch_data[MAX_CH_DATA_BUFLEN] = {0};
#endif
	int channel = 0;
	int bw = 0;
	int nctrlsb = 0;
	char apSsid[SSID_LEN], apSsidTmp[SSID_LEN];
#ifdef RTCONFIG_NBR_RPT
	char nbr_data[MAX_NBR_DATA_BUFLEN] = {0};
	json_object *nbrDataObj = NULL;
#endif
	char papBssid[18], papBssidTmp[18];
	char amasWlcPrefix[sizeof("amas_wlcXXXX_")];
	char wlIfnames[64], rssi[8], sta[18], papSsid[SSID_LEN], papSsidTmp[SSID_LEN], staTraffic[18];
	char *papIndexStr = NULL, *rssiIndexStr = NULL, *staIndexStr = NULL, *papSsidIndexStr = NULL;
	char *apIndexStr = NULL, *apSsidIndexStr = NULL;
	char *channelIndexStr = NULL, *bwIndexStr = NULL, *ctrlsbIndexStr = NULL;
	int rssiInt = 0;
	char ifname[16];
	int nband = 0;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	unsigned char brMac[MAC_LEN] = {0};
	char *staTrafficIndexStr = NULL;
#endif
#ifdef CONFIG_BCMWL5
	char wlPrefix[sizeof("wlXXXXX_")];
#endif
	char wlcStatus[16] = {0};

	root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return 0;
	}

	/* model name */
	json_object_object_add(root, CFG_STR_MODEL_NAME, json_object_new_string(get_productid()));

	/* product id */
	json_object_object_add(root, CFG_STR_PRODUCT_ID, json_object_new_string(nvram_safe_get("productid")));

	/* sw mode */
	json_object_object_add(root, CFG_STR_SWMODE, json_object_new_string(nvram_safe_get("sw_mode")));

	/* alias */
	json_object_object_add(root, CFG_STR_ALIAS, json_object_new_string(nvram_safe_get("cfg_alias")));

	/*RE path in br0 */
	json_object_object_add(root, CFG_STR_PATH, json_object_new_int(nvram_get_int("amas_path_stat")));

#ifdef RTCONFIG_BHCOST_OPT
	/* RE path V3 */
	json_object_object_add(root, CFG_STR_PATH_V3, json_object_new_int(nvram_get_int("amas_path_stat_v3")));
#endif

	/* get mac addr by interface */
	json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));

	/* get territory_code */
	json_object_object_add(root, CFG_STR_TERRITORY_CODE, json_object_new_string(nvram_safe_get("territory_code")));

	/* get bssid and rssi of 2g & 5g for pap */
	if (nvram_get_int("sw_mode") == SW_MODE_REPEATER || reportPapInfo) {
		int lldp_cost = -1, lldp_cost_result = -1, SUMband = 0;
		char *lldp_wlc_stat = NULL, *lldp_eth_stat = NULL, lldp_stat_tmp[16] = {};

		/* prepare upstream info */
		unit = 0;
		strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
		foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			snprintf(amasWlcPrefix, sizeof(amasWlcPrefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(unit));
			if (nvram_get_int(strcat_r(amasWlcPrefix, "use", tmp))) {
#if defined(RTCONFIG_QCA)
				get_pap_bssid(unit, &papBssid[0], sizeof(papBssid));
#else
				snprintf(papBssid, sizeof(papBssid), "%s", get_pap_bssid(unit, &papBssidTmp[0], sizeof(papBssidTmp)));
#endif

				papIndexStr = NULL;
				rssiIndexStr = NULL;
				staIndexStr = NULL;
				papSsidIndexStr = NULL;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
				staTrafficIndexStr = NULL;
#endif
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				if (nband == 2) {
					papIndexStr = CFG_STR_PAP2G;
					rssiIndexStr = CFG_STR_RSSI2G;
					staIndexStr = CFG_STR_STA2G;
					papSsidIndexStr = CFG_STR_PAP2G_SSID;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					staTrafficIndexStr = CFG_STR_STA2G_TRAFFIC;
#endif
				}
				else if (nband == 1) {
					papIndexStr = CFG_STR_PAP5G;
					rssiIndexStr = CFG_STR_RSSI5G;
					staIndexStr = CFG_STR_STA5G;
					papSsidIndexStr = CFG_STR_PAP5G_SSID;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					staTrafficIndexStr = CFG_STR_STA5G_TRAFFIC;
#endif
				}
				else if (nband == 4) {
					papIndexStr = CFG_STR_PAP6G;
					rssiIndexStr = CFG_STR_RSSI6G;
					staIndexStr = CFG_STR_STA6G;
					papSsidIndexStr = CFG_STR_PAP6G_SSID;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					staTrafficIndexStr = CFG_STR_STA6G_TRAFFIC;
#endif
				}

				/* pap bssid and rssi info */
				if (strlen(papBssid)) {
					if (papIndexStr && rssiIndexStr) {
						rssiInt = get_pap_rssi(unit);
						snprintf(rssi, sizeof(rssi), "%d", rssiInt);

						json_object_object_add(root, papIndexStr, json_object_new_string(papBssid));
						json_object_object_add(root, rssiIndexStr, json_object_new_string(rssi));
					}
				}

				/* sta info */
				if (staIndexStr) {
					snprintf(sta, sizeof(sta), "%s", get_sta_mac(unit));
					json_object_object_add(root, staIndexStr, json_object_new_string(sta));
				}

				/* pap ssid info */
				if (papSsidIndexStr) {
					strlcpy(papSsid, get_pap_ssid(unit, papSsidTmp, sizeof(papSsidTmp)), sizeof(papSsid));
					json_object_object_add(root, papSsidIndexStr, json_object_new_string(papSsid));
				}

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
				/* sta traffic info */
				if (!nvram_match(strcat_r(prefix, "mode", tmp), "wet") && staTrafficIndexStr) {
					memset(brMac, 0, sizeof(brMac));
					ether_atoe(cm_ctrlBlock.brIfMac, brMac);
					convert_smac_for_traffic(unit, brMac);
					snprintf(staTraffic, sizeof(staTraffic), "%02X:%02X:%02X:%02X:%02X:%02X",
							brMac[0], brMac[1], brMac[2], brMac[3], brMac[4], brMac[5]);
					json_object_object_add(root, staTrafficIndexStr, json_object_new_string(staTraffic));
				}
#endif
			}

			unit++;
		}

        /* lldp cost state */
        /* Wireless */
        SUMband = 0;
	    foreach (word, nvram_safe_get("wl_ifnames"), next) {
            SUMband++;
        }
        lldp_wlc_stat = calloc(SUMband*16, sizeof(char));
        if (lldp_wlc_stat) {
            for (unit = 0; unit < SUMband; unit++) {
                snprintf(tmp, sizeof(tmp), "amas_wlc%d_cost", get_wlc_bandindex_by_unit(unit));
                if (nvram_get(tmp)) lldp_cost = nvram_get_int(tmp);
                snprintf(tmp, sizeof(tmp), "amas_wlc%d_cost_result", get_wlc_bandindex_by_unit(unit));
                if (nvram_get(tmp)) lldp_cost_result = nvram_get_int(tmp);
                snprintf(lldp_stat_tmp, sizeof(lldp_stat_tmp), "<%d>%d>%d", unit, lldp_cost, lldp_cost_result);
                strncat(lldp_wlc_stat, lldp_stat_tmp, SUMband*16-strlen(lldp_wlc_stat)-1);
            }
		    json_object_object_add(root, CFG_STR_WLC_LLDP_COST_STAT, json_object_new_string(lldp_wlc_stat));
            free(lldp_wlc_stat);
        }
        /* Ethernet */
        SUMband = 0;
	    foreach (word, nvram_safe_get("eth_ifnames"), next) {
            SUMband++;
        }
        lldp_eth_stat = calloc(SUMband*16, sizeof(char));
        if (lldp_eth_stat) {
            for (unit = 0; unit < SUMband; unit++) {
                snprintf(tmp, sizeof(tmp), "amas_eth%d_cost", unit);
                if (nvram_get(tmp)) lldp_cost = nvram_get_int(tmp);
                snprintf(tmp, sizeof(tmp), "amas_eth%d_cost_result", unit);
                if (nvram_get(tmp)) lldp_cost_result = nvram_get_int(tmp);
                snprintf(lldp_stat_tmp, sizeof(lldp_stat_tmp), "<%d>%d>%d", unit, lldp_cost, lldp_cost_result);
                strncat(lldp_eth_stat, lldp_stat_tmp, SUMband*16-strlen(lldp_eth_stat)-1);
            }
		    json_object_object_add(root, CFG_STR_ETH_LLDP_COST_STAT, json_object_new_string(lldp_eth_stat));
            free(lldp_eth_stat);
        }

	}

	/* get bssid and ssid for backhaul */
	unit = 0;
	num5g = 0;
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
#ifdef CONFIG_BCMWL5
		snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", unit);
		strlcpy(ifname, nvram_safe_get(strcat_r(wlPrefix, "ifname", tmp)), sizeof(ifname));
#else
		strlcpy(ifname, word, sizeof(ifname));
#endif
		p = get_hwaddr(ifname);
		if (p) {
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			apIndexStr = NULL;
			apSsidIndexStr = NULL;
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			if (nband == 2) {
				apIndexStr = CFG_STR_AP2G;
				apSsidIndexStr = CFG_STR_AP2G_SSID;
			}
			else if (nband == 1)
			{
				num5g++;
				if (num5g == 1) {
					apIndexStr = CFG_STR_AP5G;
					apSsidIndexStr = CFG_STR_AP5G_SSID;
				}
				else if (num5g == 2)
				{
					apIndexStr = CFG_STR_AP5G1;
					apSsidIndexStr = CFG_STR_AP5G1_SSID;
				}
			}
			else if (nband == 4)
			{
				apIndexStr = CFG_STR_AP6G;
				apSsidIndexStr = CFG_STR_AP6G_SSID;
			}

			if (apIndexStr && apSsidIndexStr) {
				json_object_object_add(root, apIndexStr, json_object_new_string(p));
				strlcpy(apSsid, get_ap_ssid(unit, apSsidTmp, sizeof(apSsidTmp)), sizeof(apSsid));
				json_object_object_add(root, apSsidIndexStr, json_object_new_string(apSsid));
			}

			free(p);
			p = NULL;
		}

		unit++;
	}

	/* get bssid and ssid for fronthaul */
	unit = 0;
	num5g = 0;
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		strlcpy(ifname, get_fh_ap_ifname_by_unit(unit), sizeof(ifname));
		p = get_hwaddr(ifname);
		if (p) {
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			apIndexStr = NULL;
			apSsidIndexStr = NULL;
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			if (nband == 2) {
				apIndexStr = CFG_STR_AP2G_FH;
				apSsidIndexStr = CFG_STR_AP2G_SSID_FH;
			}
			else if (nband == 1)
			{
				num5g++;
				if (num5g == 1) {
					apIndexStr = CFG_STR_AP5G_FH;
					apSsidIndexStr = CFG_STR_AP5G_SSID_FH;
				}
				else if (num5g == 2)
				{
					apIndexStr = CFG_STR_AP5G1_FH;
					apSsidIndexStr = CFG_STR_AP5G1_SSID_FH;
				}
			}
			else if (nband == 4)
			{
				apIndexStr = CFG_STR_AP6G_FH;
				apSsidIndexStr = CFG_STR_AP6G_SSID_FH;
			}

			if (apIndexStr && apSsidIndexStr) {
				json_object_object_add(root, apIndexStr, json_object_new_string(p));
				if (nvram_get_int("fh_ap_enabled") > 0 && unit == nvram_get_int("dwb_band") && nvram_get_int("fh_ap_bss") < 1) {
					json_object_object_add(root, apSsidIndexStr, json_object_new_string(""));
				}
				else
				{
					strlcpy(apSsid, get_fh_ap_ssid_by_unit(unit), sizeof(apSsid));
					json_object_object_add(root, apSsidIndexStr, json_object_new_string(apSsid));
				
				}
			}

			free(p);
			p = NULL;
		}

		unit++;
	}

	/* get bssif of dwb */
#ifdef RTCONFIG_DWB
	if (supportedBandNum == 3) {
		if (cm_dwbIsEnabled()) {
			p = get_dwb_bssid(supportedBandNum, nvram_get_int("dwb_band"), nvram_get_int("max_guest_index"));
			if (p)
				json_object_object_add(root, CFG_STR_APDWB, json_object_new_string(p));
		}
	}
#endif

	/* get firmware version */
	snprintf(fwVer, sizeof(fwVer), "%s.%s_%s", nvram_safe_get("firmver"),
				nvram_safe_get("buildno"), nvram_safe_get("extendno"));
	json_object_object_add(root, CFG_STR_FWVER, json_object_new_string(fwVer));

	/* get wired client list */
	if ((wiredClientListObj = json_object_from_file(CURRENT_WIRED_CLIENT_LIST_JSON_PATH)) != NULL)
		json_object_object_add(root, CFG_STR_WIRED_MAC, wiredClientListObj);

#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
#ifdef RADAR_DET
	/* report available channel */
	ret = chmgmt_get_chan_info(ch_data, sizeof(ch_data));
	if( ret > 0 || ret == 0 && curState != PERCHECK)
	{
		DBG_INFO("report channel information");
		json_object_object_add(root, CFG_STR_CHANNEL, json_object_new_string(ch_data));
	}
#endif	/* RADAR_DET */

	/* supported band number */
	json_object_object_add(root, CFG_STR_BANDNUM, json_object_new_int(supportedBandNum));

	/* current channel & selected channel */
	curChannelObj = json_object_new_object();
	selChannelObj = json_object_new_object();
	if (curChannelObj && selChannelObj) {
		unit = 0;
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			channel = 0;
			bw = 0;
			nctrlsb = 0;
			wl_control_channel(unit, &channel,  &bw, &nctrlsb);

			snprintf(prefix, sizeof(prefix), "wl%d_", unit);

			json_object_object_add(curChannelObj, strcat_r(prefix, "channel", tmp), json_object_new_int(channel));
			json_object_object_add(curChannelObj, strcat_r(prefix, "bw", tmp), json_object_new_int(bw));
			json_object_object_add(curChannelObj, strcat_r(prefix, "nctrlsb", tmp), json_object_new_int(nctrlsb));

			if (nvram_get_int(strcat_r(prefix, "sel_channel", tmp))) {
				channel = nvram_get_int(strcat_r(prefix, "sel_channel", tmp));
				bw = nvram_get_int(strcat_r(prefix, "sel_bw", tmp));
				nctrlsb = nvram_get_int(strcat_r(prefix, "sel_nctrlsb", tmp));
				json_object_object_add(selChannelObj, strcat_r(prefix, "channel", tmp), json_object_new_int(channel));
				json_object_object_add(selChannelObj, strcat_r(prefix, "bw", tmp), json_object_new_int(bw));
				json_object_object_add(selChannelObj, strcat_r(prefix, "nctrlsb", tmp), json_object_new_int(nctrlsb));
			}
			unit++;
		}

		json_object_object_add(root, CFG_STR_CURRENT_CHANNEL, curChannelObj);
		json_object_object_add(root, CFG_STR_SELECTED_CHANNEL, selChannelObj);
	}

	/* supported chanspec */
	chanspecObj = json_object_new_object();
	if (chanspecObj) {
		if (cm_getChanspec(chanspecObj, 1)) {
			json_object_object_add(root, CFG_STR_CHANSPEC, chanspecObj);
			json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			*reportIndex |= BIT_SHIFT_LEFT(REPORT_TYPE_CHANSPEC);
		}
		else
			json_object_put(chanspecObj);
	}

	/* wired port status */
	wiredPortObj = json_object_new_object();
	if (wiredPortObj) {
		if (get_wired_port_status(wiredPortObj))
			json_object_object_add(root, CFG_STR_WIRED_PORT, wiredPortObj);
		else
			json_object_put(wiredPortObj);
	}

#ifdef PLC_STATUS
	/* plc status */
	plcStatusObj = json_object_new_object();
	if (plcStatusObj) {
		if (get_plc_status(plcStatusObj))
			json_object_object_add(root, CFG_STR_PLC_STATUS, plcStatusObj);
		else
			json_object_put(plcStatusObj);
	}
#endif	/* PLC_STATUS */

	/* changed config */
	pthread_mutex_lock(&changedConfigLock);
	if ((configRoot = json_object_from_file(CHANGED_CFG_JSON_PATH))) {
		configObj =  json_object_new_object();
		if (configObj) {
			json_object_object_foreach(configRoot, key, val) {
				json_object_object_add(configObj, key, json_object_new_string(json_object_get_string(val)));
			}
			json_object_object_add(root, CFG_STR_CHANGED_CONFIG, configObj);
			unlink(CHANGED_CFG_JSON_PATH);
		}
		json_object_put(configRoot);
	}
	pthread_mutex_unlock(&changedConfigLock);

#ifdef RTCONFIG_NBR_RPT
	json_object_object_add(root, CFG_STR_NBR_VERSION, json_object_new_string(nvram_safe_get("cfg_nbr_ver")));
	/* report neighbor */
	ret = cm_getNbrData(nbr_data, sizeof(nbr_data));
	if (ret > 0 || (ret == 0 && curState != PERCHECK)) {
		nbrDataObj =json_tokener_parse(nbr_data);
		if (nbrDataObj) {
			DBG_INFO("report neighbor information");
			json_object_object_add(root, CFG_STR_NBR_DATA, nbrDataObj);
		}
	}
#endif	/* RTCONFIG_NBR_RPT */

	} /* !wifison_ready */

	snprintf(msg, msgLen, "%s", json_object_to_json_string_ext(root, 0));
	DBG_INFO("msg(%s)", msg);
	json_object_put(root);

	return strlen(msg);
} /* End of cm_prepareReportMsg */

/*
========================================================================
Routine Description:
	Check information (such as cfg_ver, etc.) of the server.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_checkCfgInfo(unsigned char *decryptedMsg)
{
	struct json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	/* save file, and then check and apply late */
	json_object_to_file(CFG_JSON_FILE, decryptedRoot);

	json_object_put(decryptedRoot);
} /* End of cm_checkCfgInfo */

/*
========================================================================
Routine Description:
	Handle RE join return data from master.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	none

========================================================================
*/
static void cm_handleJoinReturnData(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *cfgObj = NULL;
#ifdef PRELINK
	json_object *keyObj = NULL;
#endif

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	/* delete private cfg first, it will be rewrie later */
	unlink(PRIVATE_CFG_JSON_PATH);

	json_object_object_get_ex(decryptedRoot, CFG_STR_PRIVATE_FEATURE, &cfgObj);
#ifdef PRELINK
	json_object_object_get_ex(decryptedRoot, CFG_STR_HASH_BUNDLE_KEY, &keyObj);
#endif

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	if (cfgObj == NULL) {
		json_object_put(decryptedRoot);
		DBG_ERR("cfgObj is null");
		return;
	}

	//f_write_string(PRIVATE_CFG_JSON_PATH, decryptedMsg, 0, 0);
	json_object_to_file(PRIVATE_CFG_JSON_PATH, cfgObj);

#ifdef PRELINK
	if (keyObj) {
		if (verify_hash_bundle_key((char *)json_object_get_string(keyObj))) {
			nvram_set("amas_hashbdlkey", json_object_get_string(keyObj));
			update_lldp_hash_bundle_key();  /* update lldp hash bundle key */
		}
	}
	else
		nvram_unset("amas_hashbdlkey");
#endif

	json_object_put(decryptedRoot);
} /* End of cm_handleJoinReturnData */

/*
========================================================================
Routine Description:
	Check group key.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_checkGroupKey(CM_CTRL *pCtrlBK, unsigned char *decryptedMsg)
{
	struct json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	struct json_object *keyObj = NULL;
	struct json_object *timeObj = NULL;
	unsigned char key[KEY_LENGTH] = {0};

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(decryptedRoot, "key", &keyObj);
	json_object_object_get_ex(decryptedRoot, "time", &timeObj);

	if (keyObj == NULL || timeObj == NULL) {
		DBG_ERR("key or time is NULL!");
		json_object_put(decryptedRoot);
		return;
	}

	/* update group key */
	key_atoe(json_object_get_string(keyObj), key);
	if (pCtrlBK->groupKey == NULL)
		pCtrlBK->groupKey = (unsigned char *)malloc(KEY_LENGTH);
	memset(pCtrlBK->groupKey, 0, sizeof(key));
	memcpy((unsigned char *)&pCtrlBK->groupKey[0], (unsigned char *)&key[0], sizeof(key));
	pCtrlBK->groupKeyLen = sizeof(key);

	/* update the start time of group key */
	pCtrlBK->groupKeyStartTime = uptime() - atoi(json_object_get_string(timeObj));
	pCtrlBK->groupKeyReady = 1;

	/* free goup key 1 */
	if (pCtrlBK->groupKey1) {
		free(pCtrlBK->groupKey1);
		pCtrlBK->groupKey1 = NULL;
	}
	pCtrlBK->groupKey1StartTime = uptime() - groupKeyExpireTime - atoi(json_object_get_string(timeObj));

	json_object_put(decryptedRoot);
} /* End of cm_checkGroupKey */

/*
========================================================================
Routine Description:
	Update session key.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_updateSessionKey(unsigned char *decryptedMsg)
{
	struct json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	struct json_object *keyObj = NULL;
	unsigned char key[KEY_LENGTH] = {0};
	int sKeyTime = (int) (uptime() - cm_ctrlBlock.sessionKeyStartTime);
	int sKey1Time = (int) (uptime() - cm_ctrlBlock.sessionKey1StartTime);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(decryptedRoot, "key", &keyObj);

	if (keyObj == NULL ) {
		DBG_ERR("key is NULL!");
		json_object_put(decryptedRoot);
		return;
	}

	/* update session key */
	key_atoe(json_object_get_string(keyObj), key);

	if (sKeyTime >= sessionKeyExpireTime) {
		DBG_INFO("sKeyTime >= sessionKeyExpireTim, update sessionKey");
		if (cm_ctrlBlock.sessionKey == NULL)
			cm_ctrlBlock.sessionKey = (unsigned char *)malloc(KEY_LENGTH);

		memset(cm_ctrlBlock.sessionKey, 0, sizeof(key));
		memcpy((unsigned char *)&cm_ctrlBlock.sessionKey[0], (unsigned char *)&key[0], sizeof(key));
		cm_ctrlBlock.sessionKeyStartTime = cm_ctrlBlock.sessionKey1StartTime + sessionKeyExpireTime;
	}
	else if (sKey1Time >= sessionKeyExpireTime) {
		DBG_INFO("sKey1Time >= sessionKeyExpireTim, update sessionKey1");
		if (cm_ctrlBlock.sessionKey1 == NULL)
			cm_ctrlBlock.sessionKey1 = (unsigned char *)malloc(KEY_LENGTH);

		memset(cm_ctrlBlock.sessionKey1, 0, sizeof(key));
		memcpy((unsigned char *)&cm_ctrlBlock.sessionKey1[0], (unsigned char *)&key[0], sizeof(key));
		cm_ctrlBlock.sessionKey1StartTime = cm_ctrlBlock.sessionKeyStartTime + sessionKeyExpireTime;
	}

	json_object_put(decryptedRoot);
} /* End of cm_updateSessionKey */

/*
========================================================================
Routine Description:
	Update group key.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_updateGroupKey(unsigned char *decryptedMsg)
{
	struct json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	struct json_object *keyObj = NULL;
	unsigned char key[KEY_LENGTH] = {0};
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(decryptedRoot, "key", &keyObj);

	if (keyObj == NULL ) {
		DBG_ERR("key is NULL!");
		json_object_put(decryptedRoot);
		return;
	}

	/* update group key */
	key_atoe(json_object_get_string(keyObj), key);

	if (gKeyTime >= groupKeyExpireTime) {
		DBG_INFO("gKeyTime >= groupKeyExpireTime, update groupKey");
		if (cm_ctrlBlock.groupKey == NULL)
			cm_ctrlBlock.groupKey = (unsigned char *)malloc(KEY_LENGTH);

		memset(cm_ctrlBlock.groupKey, 0, sizeof(key));
		memcpy((unsigned char *)&cm_ctrlBlock.groupKey[0], (unsigned char *)&key[0], sizeof(key));
		cm_ctrlBlock.groupKeyStartTime = cm_ctrlBlock.groupKey1StartTime + groupKeyExpireTime;
	}
	else if (gKey1Time >= groupKeyExpireTime) {
		DBG_INFO("gKey1Time >= groupKeyExpireTime, update groupKey1");
		if (cm_ctrlBlock.groupKey1 == NULL)
			cm_ctrlBlock.groupKey1 = (unsigned char *)malloc(KEY_LENGTH);

		memset(cm_ctrlBlock.groupKey1, 0, sizeof(key));
		memcpy((unsigned char *)&cm_ctrlBlock.groupKey1[0], (unsigned char *)&key[0], sizeof(key));
		cm_ctrlBlock.groupKey1StartTime = cm_ctrlBlock.groupKeyStartTime + groupKeyExpireTime;
	}

	json_object_put(decryptedRoot);
} /* End of cm_updateGroupKey */

/*
========================================================================
Routine Description:
	Return notify type.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	notify type

========================================================================
*/
static int cm_getNotifyType(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *typeObj = NULL;
	int notifyType = 0;

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return notifyType;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_NOTIFY_TYPE, &typeObj);
	if (typeObj)
		notifyType = json_object_get_int(typeObj);

	json_object_put(decryptedRoot);

	return notifyType;
} /* End of cm_getNotifyType */

/*
========================================================================
Routine Description:
	Check whether feature list exist or not.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	0		- no feature list
	1		- hvae feature list

========================================================================
*/
static int cm_haveFeatureList(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *cfgVerObj = NULL;
	int ret = 0;

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return ret;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_CFGVER, &cfgVerObj);
	if (cfgVerObj)
		ret = 1;

	json_object_put(decryptedRoot);

	return ret;
} /* End of cm_haveFeatureList */

#if defined(SYNC_WCHANNEL)
/*
========================================================================
Routine Description:
	Check wireless channel.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_checkWirelessChannel(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *channelRoot = NULL;
	json_object *bandNumObj = NULL;
	json_object *channelObj = NULL;
	json_object *bwObj = NULL;
	json_object *nctrlsbObj = NULL;
	json_object *lowBandChannelObj = NULL;
	int unit = 0;
	char prefix[16] = {0};
	char word[64] = {0};
	char tmp[64] = {0};
	char *next = NULL;
	int bandNum = supportedBandNum;
	int channelRE = 0;
	int bwRE = 0;
	int nctrlsbRE = 0;
	int channelCap = 0;
	int bwCap = 0;
	int nctrlsbCap = 0;
	char lowBand5g[16] = {0};
	char wlcStatus[16] = {0};
	int ret = 0;
	int suitableBw = 0, suitableNctrlsb = 0;
#ifdef RTCONFIG_NBR_RPT
	json_object *bandObj = NULL;
#endif
	if (!decryptedRoot) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	/* get channel object */
	json_object_object_get_ex(decryptedRoot, CFG_STR_CHANNEL, &channelRoot);
	if (!channelRoot){
		DBG_ERR("channelRoot is NULL");
		goto err;
	}

	/* get band number */
	json_object_object_get_ex(channelRoot, CFG_STR_BANDNUM, &bandNumObj);
	if (!bandNumObj){
		DBG_ERR("bandNumObj is NULL");
		goto err;
	}

#ifdef RTCONFIG_NBR_RPT
	{
		char r_prefix[16] = {0};
		int i;
		nvram_set_int("r_wl_band_num_cap",json_object_get_int(bandNumObj));
		for(i=0;i<bandNum;i++ ){
			snprintf(r_prefix,sizeof(r_prefix),"r_wl%d_",i);
			snprintf(prefix, sizeof(prefix), "wl%d_", i);
			json_object_object_get_ex(channelRoot, strcat_r(prefix, "channel", tmp), &channelObj);
			json_object_object_get_ex(channelRoot, strcat_r(prefix, "bw", tmp), &bwObj);
			json_object_object_get_ex(channelRoot, strcat_r(prefix, "nctrlsb", tmp), &nctrlsbObj);			
			if(channelObj) nvram_set(strcat_r(r_prefix, "channel", tmp),json_object_get_string(channelObj));
			if(bwObj) nvram_set(strcat_r(r_prefix, "bw", tmp),json_object_get_string(bwObj));
			if(nctrlsbObj) nvram_set(strcat_r(r_prefix, "nctrlsb", tmp),json_object_get_string(nctrlsbObj));
		}

		if(bandNum == 2)
		{
			json_object_object_get_ex(channelRoot, "r_selected_band", &bandObj);
			json_object_object_get_ex(channelRoot, "r_selected_channel", &channelObj);
			json_object_object_get_ex(channelRoot, "r_selected_bw", &bwObj);
			json_object_object_get_ex(channelRoot, "r_selected_nctrlsb", &nctrlsbObj);
			if(bandObj) nvram_set("r_selected5gband",json_object_get_string(bandObj));
			if(channelObj) nvram_set("r_selected5gchannel",json_object_get_string(channelObj));
			if(bwObj) nvram_set("r_selected5gbw",json_object_get_string(bwObj));
			if(nctrlsbObj) nvram_set("r_selected5gnctrlsb",json_object_get_string(nctrlsbObj));			
		}
	}
#endif //#ifdef RTCONFIG_NBR_RPT

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		memset(prefix, 0, sizeof(prefix));
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		json_object_object_get_ex(channelRoot, strcat_r(prefix, "channel", tmp), &channelObj);
		json_object_object_get_ex(channelRoot, strcat_r(prefix, "bw", tmp), &bwObj);
		json_object_object_get_ex(channelRoot, strcat_r(prefix, "nctrlsb", tmp), &nctrlsbObj);

		if (channelObj && bwObj && nctrlsbObj) {
			channelRE = 0;
			bwRE = 0;
			nctrlsbRE = 0;
			channelCap = json_object_get_int(channelObj);
			bwCap = json_object_get_int(bwObj);
			nctrlsbCap = json_object_get_int(nctrlsbObj);

			wl_control_channel(unit, &channelRE, &bwRE, &nctrlsbRE);

			DBG_INFO("channelCap(%d), bwCap(%d), nctrlsbCap(%d)", channelCap, bwCap, nctrlsbCap);
			DBG_INFO("channelRE(%d), bwRE(%d), nctrlsbRE(%d)", channelRE, bwRE, nctrlsbRE);

			if (channelRE == 0 || channelCap == 0) {
				DBG_INFO("channelRE == 0 || channelCap == 0");
				unit++;
				continue;
			}

			/* get the status of upstream connection */
			memset(wlcStatus, 0, sizeof(wlcStatus));
			snprintf(wlcStatus, sizeof(wlcStatus), "wlc%d_status",  get_wlc_bandindex_by_unit(unit));
			if (nvram_get(wlcStatus))
				DBG_INFO("%s == %d", wlcStatus, nvram_get_int(wlcStatus));
			else
				DBG_INFO("%s is NULL", wlcStatus);

			if ((channelCap == channelRE) &&
				(bwCap == bwRE) &&
				((bwCap == 40)?(nctrlsbCap == nctrlsbRE):1)) {
				DBG_INFO("channelCap == channelRE");
				if ((!nvram_get(wlcStatus) || nvram_get_int(wlcStatus) < 0) &&
					(get_psta_status(unit) != WLC_STATE_CONNECTED))
					set_channel_sync_status(unit, 1);
				unit++;
				continue;
			} else {
				/* wlc not connected(2 STATE_CONNECTED), sync channel */
				if ((!nvram_get(wlcStatus) || nvram_get_int(wlcStatus) < 0) &&
					(get_psta_status(unit) != WLC_STATE_CONNECTED)) {
					if (cm_isValidChannel(unit, channelCap) == 1) {
						DBG_ERR("check CAP's bw and nctrlsb", unit);
						/* verify CAP's channel, CAP's bw and CAP's nctrlsb */
						ret = cm_isValidBwNctrlsb(unit, channelCap, bwCap, nctrlsbCap, 1);
						if (ret == 1) {
							DBG_INFO("sync channel (%d), bw (%d), nctrlsb (%d) for unit (%d)", channelCap, bwCap, nctrlsbCap, unit);
							sync_control_channel(unit, channelCap, bwCap, nctrlsbCap);
							set_channel_sync_status(unit, 1);
						}
						else if (ret == 0)
						{
							DBG_INFO("CAP's bw and nctrlsb are invalid for unit (%d), find suitable bw and nctrlsb to sync", unit);
							ret = cm_findSuitableBwNctrlsb(unit, channelCap, &suitableBw, &suitableNctrlsb);
							if (ret == 1) {
								DBG_INFO("suitable bw (%d), suitable nctrlsb (%d) for unit (%d)", suitableBw, suitableNctrlsb, unit);
								if (channelCap == channelRE && bwRE == suitableBw) {
									DBG_INFO("channelCap == channelRE and bwRE == suitableBw, keep it and don't sync");
									set_channel_sync_status(unit, 1);
								}
								else
								{
									DBG_INFO("sync channel (%d), suitable bw (%d), suitable nctrlsb (%d) for unit (%d)", channelCap, suitableBw, suitableNctrlsb, unit);
									sync_control_channel(unit, channelCap, suitableBw, suitableNctrlsb);
									set_channel_sync_status(unit, 1);
								}
							}
							else if (ret == 0)
								DBG_ERR("can't find suitable bw and nctrlsbfor unit (%d)", unit);
							else if (ret == -1)
								DBG_ERR("finding error on bw and nctrlsb for unit (%d)", unit);
						}
						else if (ret == -1)
							DBG_ERR("checking error on bw and nctrlsb for unit (%d)", unit);
					}
					else
						DBG_INFO("channel (%d) is invalid on RE", channelCap);
				}
			}
		}

		unit++;
	}
#ifdef RTCONFIG_BCN_RPT
	lowBandChannelObj = NULL;
	//for CAP DUAL BAND RE1 TRI BAND RE2 DUAL BAND, make RE2 know second 5g band number
	if(json_object_get_int(bandNumObj) == 2 && bandNum == 2) {
		json_object_object_get_ex(channelRoot, "multi_channel_5g", &lowBandChannelObj);
	} else if(json_object_get_int(bandNumObj) == 3 && bandNum == 2) {
		memset(lowBand5g, 0, sizeof(lowBand5g));
		snprintf(lowBand5g, sizeof(lowBand5g), "wl%d_channel", LOW_BAND_5G);
		json_object_object_get_ex(channelRoot, lowBand5g, &lowBandChannelObj);
	}
	if(lowBandChannelObj)
		nvram_set_int("multi_channel_5g", json_object_get_int(lowBandChannelObj));
	else
		nvram_unset("multi_channel_5g");
#endif

err:

	json_object_put(decryptedRoot);
} /* End of cm_checkWirelessChannel */
#endif	/* SYNC_WCHANNEL */

/*
========================================================================
Routine Description:
	Update the cost of network topology.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_updateNetworkCost(CM_CTRL *pCtrlBK, unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *costObj = NULL;
#ifdef ONBOARDING
	json_object *tsObj = NULL;
	json_object_object_get_ex(decryptedRoot, CFG_STR_TIMESTAMP, &tsObj);
#endif
	json_object_object_get_ex(decryptedRoot, CFG_STR_COST, &costObj);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	/* update the cost of network topology */
	if (costObj) {
		if (pCtrlBK->cost != atoi(json_object_get_string(costObj))) {
			pCtrlBK->cost = atoi(json_object_get_string(costObj));
			update_lldp_cost(pCtrlBK->cost);
		}
	}

#ifdef ONBOARDING
	/* update timestamp for onboarding */
	if (tsObj)
		obTimeStamp = json_object_get_int(tsObj);
#endif

	json_object_put(decryptedRoot);
} /* End of cm_checkGroupKey */

/*
========================================================================
Routine Description:
	Update the level of network topology.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_updateNetworkLevel(CM_CTRL *pCtrlBK, unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *maxlevelObj = NULL, *levelObj = NULL;
#ifdef ONBOARDING
	json_object *tsObj = NULL;
	json_object_object_get_ex(decryptedRoot, CFG_STR_TIMESTAMP, &tsObj);
#endif
	json_object_object_get_ex(decryptedRoot, CFG_STR_MAXLEVEL, &maxlevelObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_LEVEL, &levelObj);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	/* update the max level of network topology */
	if (maxlevelObj)
		nvram_set_int("cfg_maxlevel", atoi(json_object_get_string(maxlevelObj)));

	/* update the level of RE */
	if (levelObj)
		nvram_set_int("cfg_level", atoi(json_object_get_string(levelObj)));

#ifdef ONBOARDING
	/* update timestamp for onboarding */
	if (tsObj)
		obTimeStamp = json_object_get_int(tsObj);
#endif

	json_object_put(decryptedRoot);
} /* End of cm_updateNetworkLevel */

/*
========================================================================
Routine Description:
	Process special parameters for sysdeps.

Arguments:
	*param		- parameter's name
	*value		= parameter's value

Return Value:
	0		- no changed
	1		- changed

========================================================================
*/
static int cm_processSpecialParam(const char *param, const char *value)
{
	int unit = 0;
	int subunit = 0;
	char prefix[16] = {0};
	char suffix[32] = {0};
	int ret = 0;
	char tmp[64] = {0};
	static char channelVal[8];
	char nctrlsb[8] = {0};

	if (strstr(param, "channel")) {
		memset(channelVal, 0, sizeof(channelVal));
		snprintf(channelVal, sizeof(channelVal), "%s", value);
	}

	if (get_ifname_unit(param, &unit, &subunit) < 0) {
		sscanf(param, "wl%d_%s", &unit, suffix);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	}
	else
		return ret;

	/* handle channel & extension channel & bandwidth */
#ifdef RTCONFIG_BCMWL6
	if (!strcmp(suffix, "nctrlsb")) {       /* for BRCM 5.x & MTK & QCA */
		char chanspec[8] = {0};

		if (strlen(channelVal) == 0) {
			DBG_INFO("channelVal is not value");
			return 0;
		}

		if (nvram_get(strcat_r(prefix, "bw", tmp))) {
			int bw = nvram_get_int(strcat_r(prefix, "bw", tmp));
			snprintf(nctrlsb, sizeof(nctrlsb), "%s", value);

			/* for wlX_bw (0 <-> 1) */
			if (bw == 0 || bw == 1) {
				bw = (bw == 0) ? 1 : 0;
				nvram_set_int(strcat_r(prefix, "bw", tmp), bw);
 				ret = 1;
			}

			/* for wlX_chanspec */
			if (bw == 0 || bw == 3) { /* for 20/40 MHz(2G) or 20/40/80 MHz(5G) or 80 MHz(5G) */
				if (unit == 0) /* for 2G */
					snprintf(chanspec, sizeof(chanspec), "%s%s",
						channelVal, !strcmp(nctrlsb, "lower") ? "l" : "u");
				else if (unit == 1) /* for 5G */
					snprintf(chanspec, sizeof(chanspec), "%s/80", channelVal);
			}
			else if (bw == 1) /* for 20 MHz */
				snprintf(chanspec, sizeof(chanspec), "%s", channelVal);
			else if (bw == 2) { /* for 40 MHz */
				snprintf(chanspec, sizeof(chanspec), "%s%s",
					channelVal, !strcmp(nctrlsb, "lower") ? "l" : "u");
			}

			if (strlen(chanspec) && strcmp(nvram_get(strcat_r(prefix, "chanspec", tmp)), chanspec)) {
				DBG_INFO("channel(%s), nctrlsb(%s), bw(%d) -> %s(%s)",
						channelVal, nctrlsb, bw, chanspec);
				nvram_set(strcat_r(prefix, "chanspec", tmp), chanspec);
				ret = 1;
			}
		}
	}
#else
	if (!strcmp(suffix, "chanspec")) { /* for BRCM 6.x */
		char channel[4] = {0};

		/* for channel */
		snprintf(channel, sizeof(channel), "%d", atoi(value));
		if (strlen(channel)) {
			DBG_INFO("%s(%s) -> %s(%s)", param, value, strcat_r(prefix, "channel", tmp), channel);
			if (nvram_get(strcat_r(prefix, "channel", tmp)) &&
				strcmp(nvram_get(strcat_r(prefix, "channel", tmp)), channel)) {
				nvram_set(strcat_r(prefix, "channel", tmp), channel);
				ret = 1;
			}
		}

		/* for extension channel */
		if (strstr(value, "l"))	/* above */
			snprintf(nctrlsb, sizeof(nctrlsb), "%s", "lower");
		else if (strstr(value, "u"))	/* below */
			snprintf(nctrlsb, sizeof(nctrlsb), "%s", "upper");

		if (strlen(nctrlsb)) {
			DBG_INFO("%s(%s) -> %s(%s)", param, value, strcat_r(prefix, "nctrlsb", tmp), nctrlsb);
			if (nvram_get(strcat_r(prefix, "nctrlsb", tmp)) &&
				strcmp(nvram_get(strcat_r(prefix, "nctrlsb", tmp)), nctrlsb)) {
                               	nvram_set(strcat_r(prefix, "nctrlsb", tmp), nctrlsb);
				ret = 1;
			}
		}
	}
#endif

	return ret;
}

#ifdef SUPPORT_TRI_BAND
/*
========================================================================
Routine Description:
	Set 5G-1 parameters of tri-band RE from 5G specific parameters of
	Dual-band CAP.

Arguments:
	key		- 5G parameter.

Return Value:
	0		- Don't need to sync.
	1		- Need to sync.

========================================================================
*/
static int cm_is_sync_to_wl1(char *key)
{
    struct param_mapping_s *pParam = &param_mapping_list[0];
    for (pParam = &param_mapping_list[0]; pParam->param; pParam++) {
        if (!strcmp(key, pParam->param) &&
            (pParam->subfeature == SUBFT_ADVANCED_BAND2 ||
             pParam->subfeature == SUBFT_TIMESCHED_BAND2 ||
             pParam->subfeature == SUBFT_ROAMING_ASSISTANT_BAND2 ||
			 pParam->subfeature == SUBFT_BSD_STEERING_POLICY_BAND2 ||
			 pParam->subfeature == SUBFT_BSD_STA_SELECT_POLICY_BAND2 ||
			 pParam->subfeature == SUBFT_BSD_IF_QUALIFY_BAND2 ||
			 pParam->subfeature == SUBFT_BW_160_BAND2
#ifdef RTCONFIG_WL_SCHED_V2
			 || pParam->subfeature == SUBFT_TIMESCHEDV2_BAND2
#endif
		)) {
            return 1;
        }
    }
    return 0;
}
#endif

/*
========================================================================
Routine Description:
	Specific parameters don't need to sync.

Arguments:
	key		- parameter.

Return Value:
	0		- Need to sync.
	1		- Don't need to sync.

========================================================================
*/
static int cm_checkParameterSync(char *key)
{
	int ret = 0;
	char suffix[32] = {0};

	if (strncmp(key, "wl", 2) == 0) {
		memset(suffix, 0, sizeof(suffix));
		sscanf(key, "wl%*d_%s", suffix);
		if (strlen(suffix) == strlen("frameburst") &&
			strcmp(suffix, "frameburst") == 0) {
			DBG_INFO("don't sync %s", key);
			ret = 1;
		}
	}
#ifdef RTCONFIG_BHCOST_OPT
	else if (!strcmp(key, "amas_eap_bhmode")) {
		if (strlen(nvram_safe_get("eth_ifnames")) == 0) {  // No uplink port.
			DBG_INFO("No uplink port. don't sync %s", key);
			ret = 1;
		}
	}
#endif

	return ret;
} /* End of cm_checkParameterSync() */

/*
========================================================================
Routine Description:
	Skip service at frst sync.

Arguments:
	actionScript		- action script.

Return Value:
	0		- Don't skip service.
	1		- Skip service.

========================================================================
*/
static int cm_skipServiceAtFirstSync(char *actionScript)
{
	int ret = 0, i = 0;
	char *servicelList[] = {RESTART_SENDFEEDBACK, RESTART_DBLOG};

	if (nvram_get_int("cfg_first_sync") == 0)
		return 0;

	for(i=0; i < ARRAY_SIZE(servicelList); i++) {
		if (strcmp(actionScript, servicelList[i]) == 0) {
			DBG_INFO("skip service (%s) at first sync", actionScript);
			ret = 1;
			break;
		}
	}

	return ret;
} /* End of cm_skipServiceAtFirstSync() */

/*
========================================================================
Routine Description:
	Sync specific parameter.

Arguments:
	key		- parameter

Return Value:
	0		- don't need sync.
	1		- need sync.

========================================================================
*/
static int cm_needSyncSpecificParam(char *key)
{
	int ret = 0;

#ifdef RTCONFIG_AMAS_SYNC_2G_BW
	char wlBw[16] = {0};

	snprintf(wlBw, sizeof(wlBw), "wl%d_bw", WL_2G_BAND);
	if (strcmp(key, wlBw) == 0)
		ret = 1;
#endif

	return ret;
} /* End of cm_needSyncSpecificParam() */

#ifdef RTCONFIG_WL_SCHED_V2
/*
========================================================================
Routine Description:
	Set sched v2 converted flag when CAP support old sched setting.

Arguments:
	param		- parameter

Return Value:
	none

========================================================================
*/
void cm_setSchedV2ConvertedFlag(char *param)
{
	int unit = 0;
	char prefix[] = "wlXXXXXXXXXX_", tmp[64], suffix[32];

	if (strncmp(param, "wl", 2) == 0 && strstr(param, "sched") && !strstr(param, "sched_v2") &&
		sscanf(param, "wl%d_%s", &unit, suffix) == 2)
	{
		if (strcmp(suffix, "sched") == 0) {
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			nvram_set_int(strcat_r(prefix, "sched_v2_converted", tmp), 0);
		}
	}
} /* End of cm_setSchedV2ConvertedFlag() */
#endif


#ifdef RTCONFIG_AMAS_WGN

#define IS_CAP()                        ( (sw_mode() == SW_MODE_ROUTER || access_point_mode()) )
#define IS_RE()                         ( (nvram_get_int("re_mode") == 1) )

int get_wl_lanaccess(
        int unit,
        int subunit)
{
        char s[81];

        if (IS_CAP()) {
                if (sw_mode() != SW_MODE_ROUTER)
                        return 1;
        }

        if (IS_RE()) {
                if (nvram_get_int("wgn_without_vlan") != 0)
                        return 1;
        }

        memset(s, 0, sizeof(s));
        if (subunit <= 0)
                snprintf(s, sizeof(s)-1, "wl%d_lanaccess", unit);
        else
                snprintf(s, sizeof(s)-1, "wl%d.%d_lanaccess", unit, subunit);
        return (nvram_match(s, "on")) ? 1 : 0;
}

char* get_wl_ifname(
        int unit,
        int subunit,
        char *buffer,
        size_t buffer_size)
{
        char s[81], *ss = NULL, *ret = NULL;

        if (!buffer || buffer_size <= 0 || unit < 0)
                return NULL;

        memset(s, 0, sizeof(s));
        if (subunit <= 0)
                snprintf(s, sizeof(s), "wl%d_ifname", unit);
        else
                snprintf(s, sizeof(s)-1, "wl%d.%d_ifname", unit, subunit);

        ss = nvram_get(s);
        if (ss && strlen(ss) > 0)
        {
                memcpy(buffer, ss, (strlen(ss) > buffer_size) ? buffer_size : strlen(ss));
                ret = &buffer[0];
        }

        return ret;
}

int get_wl_bss_enabled(
        int unit,
        int subunit)
{
        char s[81];

        if (unit < 0)
                return 0;

        if (IS_RE() && subunit == 1)
                return 0;

        memset(s, 0, sizeof(s));
        if (subunit <= 0)
                snprintf(s, sizeof(s)-1, "wl%d_bss_enabled", unit);
        else
                snprintf(s, sizeof(s)-1,  "wl%d.%d_bss_enabled", unit, subunit);

        return nvram_get_int(s);
}

int wgn_if_check_used(
        char *ifname)
{
        int found;
        int unit;
        int subunit;
        char wl_ifname[33];
        size_t i;
        size_t total = 0;
        struct wgn_vlan_rule_t vlan_list[WGN_MAXINUM_VLAN_RULELIST];

        if (!ifname && !*ifname)
                return 0;

        if (!IS_CAP() && !IS_RE())
                return 0;

        if (!ifname)
                return 0;

        memset(vlan_list, 0, sizeof(struct wgn_vlan_rule_t) * WGN_MAXINUM_VLAN_RULELIST);
        if (!wgn_vlan_list_get_from_nvram(vlan_list, WGN_MAXINUM_VLAN_RULELIST, &total))
                return 0;

		if (IS_RE())
			wgn_vlan_list_wl_subunit_shift(vlan_list, total);

        for (i=0, found=0; i<total; i++)
        {
                if (!vlan_list[i].enable)
                        continue;

                wgn_get_wl_unit(&unit,&subunit,&vlan_list[i]);
                if (unit < 0 || subunit <= 0)
                        continue;

                if (!get_wl_bss_enabled(unit, subunit))
                        continue;

                memset(wl_ifname, 0, sizeof(wl_ifname));
                if (!get_wl_ifname(unit, subunit, wl_ifname, sizeof(wl_ifname)-1))
                        continue;

                if (strncmp(ifname, wl_ifname, strlen(wl_ifname)) != 0)
                        continue;

                if (get_wl_lanaccess(unit, subunit))
                        continue;

                found = 1;
                break;
        }

        return (found) ? 1 : 0;
}

int wgn_if_enable(
        char *ifname)
{
        int found;
        int unit;
        int subunit;
        char wl_ifname[33];
        size_t i;
        size_t total = 0;
        struct wgn_vlan_rule_t vlan_list[WGN_MAXINUM_VLAN_RULELIST];

        if (!ifname && !*ifname)
                return 0;

        if (!IS_CAP() && !IS_RE())
                return 0;

        if (!ifname)
                return 0;

        memset(vlan_list, 0, sizeof(struct wgn_vlan_rule_t) * WGN_MAXINUM_VLAN_RULELIST);
        if (!wgn_vlan_list_get_from_nvram(vlan_list, WGN_MAXINUM_VLAN_RULELIST, &total))
                return 0;

		if (IS_RE())
			wgn_vlan_list_wl_subunit_shift(vlan_list, total);

        for (i=0, found=0; i<total; i++)
        {
                if (!vlan_list[i].enable)
                        continue;

                wgn_get_wl_unit(&unit,&subunit,&vlan_list[i]);
                if (unit < 0 || subunit <= 0)
                        continue;

                if (!get_wl_bss_enabled(unit, subunit))
                        continue;

                memset(wl_ifname, 0, sizeof(wl_ifname));
                if (!get_wl_ifname(unit, subunit, wl_ifname, sizeof(wl_ifname)-1))
                        continue;

                if (strncmp(ifname, wl_ifname, strlen(wl_ifname)) != 0)
                        continue;

                found = 1;
                break;
        }

        return (found) ? 1 : 0;
}

int is_wgn_enabled()
{
        char word[64], *next;
        char word2[64], *next2;
        char wlx_vifnames[128], ifname[128];
        int unit = 0;

        foreach (word, nvram_safe_get("wl_ifnames"), next) {
                snprintf(wlx_vifnames, sizeof(wlx_vifnames), "wl%d_vifnames", unit++);
                foreach (word2, nvram_safe_get(wlx_vifnames), next2) {
                    snprintf(ifname, sizeof(ifname), "%s_ifname", word2);
                    if (wgn_if_enable(nvram_safe_get(ifname)))
                        return 1;
                }
        }

        return 0;
}
#endif	// RTCONFIG_AMAS_WGN

/**
 * @brief Remove no-need action
 *
 * @param actionScript Original actionScript
 * @param actionScript_len actionScript len
 */
static void remove_extra_actions(char *actionScript, int actionScript_len) {
    char *actionScript_orig = strdup(actionScript);
    char new_actionScript[256] = {};

    if (actionScript_orig) {
        if (strstr(actionScript_orig, RESTART_WIRELESS)) {
            char *action = NULL, *savePtr = NULL;

            action = strtok_r(actionScript_orig, ";", &savePtr);
            do {
                if (strcmp(action, RESTART_AMAS_BHCTRL) && strcmp(action, TRIGGER_OPT)) {
                    if (strlen(new_actionScript) == 0) {
                        strncpy(new_actionScript, action, sizeof(new_actionScript));
                    } else {
                        strcat(new_actionScript, ";");
                        strcat(new_actionScript, action);
                    }
                }
                action = strtok_r(NULL, ";", &savePtr);
            } while (action);
        }
        free(actionScript_orig);
    }
    if (strlen(new_actionScript) > 0) {
		DBG_INFO("Reset actionScript(%s) to (%s)", actionScript, new_actionScript);
        strlcpy(actionScript, new_actionScript, actionScript_len);
	}
}

/**
 * @brief Check authentication config and convert it to valid setting.
 *
 * @param unit Band unit
 * @param subunit Guest network subunit
 * @param suffix Parameter
 * @param ftObj Wireless Json obj.
 * @param converted_val Converted authentication config
 * @param converted_val_size output size
 * @return int 0: Don't need do authentication_convert. 1: Processed authentication_convert.
 */
static int authentication_convert(int unit, int subunit, char *suffix, json_object *ftObj, char *converted_val, int converted_val_size) {

    if (strcmp(suffix, "crypto") && strcmp(suffix, "auth_mode_x"))
        return 0;

	json_object *auth_mode_x_Obj = NULL;
	char tmp[64] = {}, auth_mode_x[16] = {};
    char prefix[] = "wlXXX.XXX_", wlprefix[] = "wlXXX_";
	if (subunit > 0)
	    snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
	    snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	snprintf(wlprefix, sizeof(wlprefix), "wl%d_", unit);
    int nband = nvram_get_int(strcat_r(wlprefix, "nband", tmp));
	json_object_object_get_ex(ftObj, strcat_r(prefix, "auth_mode_x", tmp), &auth_mode_x_Obj);

	if (auth_mode_x_Obj == NULL)
		return 0;

	strlcpy(auth_mode_x, json_object_get_string(auth_mode_x_Obj), sizeof(auth_mode_x));

	if (nband == 4) {                                                     // 6G
		if (!strcmp(auth_mode_x, "owe") || !strcmp(auth_mode_x, "sae"))  //  Don't need to do convert.
			return 0;
		if (!strcmp(suffix, "auth_mode_x")) {
			if (!strcmp(auth_mode_x, "open")) {  // open -> owe
				DBG_INFO("2.4,5G -> 6G, auth_mode_x open -> owe");
				strlcpy(converted_val, "owe", converted_val_size);
				return 1;
			} else {  // ??? -> sae
				DBG_INFO("2.4,5G -> 6G, auth_mode_x ??? -> sae");
				strlcpy(converted_val, "sae", converted_val_size);
				return 1;
			}
		} else if (!strcmp(suffix, "crypto")) {
			if (!strcmp(auth_mode_x, "open")) {  // -> aes
				DBG_INFO("2.4,5G -> 6G,  auth_mode_x open, crypto -> aes");
				strlcpy(converted_val, "aes", converted_val_size);
				return 1;
			} else {  // ??? -> aes
				DBG_INFO("2.4,5G -> 6G, auth_mode_x ???, crypto -> aes");
				strlcpy(converted_val, "aes", converted_val_size);
				return 1;
			}
		}
	}
#if 0
	else {  // 2.4G/5G
		if (strcmp(auth_mode_x, "owe") && strcmp(auth_mode_x, "sae"))  //  Don't need to do convert.
			return 0;
#if defined(RTCONFIG_QCA)
		if (nvram_contains_word("rc_support", "wpa3") && !strcmp(auth_mode_x, "sae"))
			return 0;
#endif
		if (!strcmp(suffix, "auth_mode_x")) {
			if (!strcmp(auth_mode_x, "sae")) {  // sae -> psk2sae
				DBG_INFO("6G -> 2.4,5G, auth_mode_x sae -> psk2sae");
				strlcpy(converted_val, "psk2sae", converted_val_size);
				return 1;
			} else if (!strcmp(auth_mode_x, "owe")) {  // owe -> open
				DBG_INFO("6G -> 2.4,5G, auth_mode_x owe -> open");
				strlcpy(converted_val, "open", converted_val_size);
				return 1;
			}
		} else if (!strcmp(suffix, "crypto")) {
			if (!strcmp(auth_mode_x, "sae")) {  // -> aes
				DBG_INFO("6G -> 2.4G,5G, auth_mode_x sae, crypto -> aes");
				strlcpy(converted_val, "aes", converted_val_size);
				return 1;
			} else if (!strcmp(auth_mode_x, "owe")) {  // -> ""
				DBG_INFO("6G -> 2.4G,5G, auth_mode_x owe, crypto -> \"\"");
				strlcpy(converted_val, "", converted_val_size);
				return 1;
			}
		}
    }
#endif
    return 0;
}

/*
========================================================================
Routine Description:
	Apply config and action sent by server.

Arguments:
	doAction		- execute action script

Return Value:
	None

========================================================================
*/
static void cm_applyCfgAction(int doAction)
{
	json_object *cfgRoot = NULL;
	json_object *cfgVer = NULL;
	json_object *cfgAll = NULL;
	json_object *cfgbandVer = NULL;
	json_object *cfgbandType = NULL;
	json_object *cfgbandnum = NULL;
	json_object *bwcapObj = NULL;
	json_object *actionScriptObj = NULL;
	json_object *cfgSmartConnect = NULL;
	json_object *cfgModelName = NULL;
#ifdef PRELINK
	json_object *hashBundleKeyObj = NULL;
#endif
	char actionScript[256] = {0};
	int cfgChanged = 0;
	int wlChanged = 0, needUpdateCfg = 0;
	struct feature_mapping_s *pFeature = &feature_mapping_list[0];
	int concurrentRepeater = 0;
	int swMode = nvram_get_int("sw_mode");
	int unit = 0, realUnit = 0;
	int subunit = 0;
	int bwcap = -1;
	struct wlcsuffix_mapping_s *pWlcsuffix = &wlcsuffix_mapping_list[0];
	int needProcess = 0;
	int updateWlcParam = 0;
	char param[32] = {0};
	char wlparam_fix[32] = {0};
	char wlcParam[32] = {0};
	char wlcParam_fix[32] = {0};
	char wlcPrefix[16] = {0};
	char wlPrefix[16] = {0};
    char wlPrefix_fix[16] = {0};
	char suffix[32] = {0}, prefix[32] = {0};
	int i = 0;
	int wepKeyChanged[3] = {-1, -1, -1};
	char tmp[64] = {0};
	int need_fix_wlc2=0;
	int need_fix_bandindex=2;
	int passCfgCheck = 0;
	int wlc2_first_sync=1;
	int wlc3_first_sync=1;
#if defined(RTCONFIG_QCA)
	int vif_bss_enabled = 0;
#endif
	int cap_band_num = 0, cap_smart_connect_x = 0,  local_band_num = 0;
	char bsd_ifnames[65], bsd_ifnames_x[65], *bsd_ifname = NULL, bsd_ifname_word[32], *bsd_ifname_next = NULL;
#ifdef RTCONFIG_DWB
	int dwb_change = 0;
#endif
#ifdef SUPPORT_TRI_BAND
	int wifison_ready = 0;
	char wl2param_fix[32] = {0};
#endif
	int cfgbandType_num=0;
	int cfgband_Ver=0;
	char wlc_value[128] = {0};
	char wsbhParam[128] = {0};
	
#ifdef RTCONFIG_AMAS_WGN

	int x = 0, y = 0, z = 0, cap_guest_ifidx = 0, re_guest_ifidx = 0, wgn_wl_bss_enabled = 0, qos_enable = 0;
	char word[64], *next = NULL, str[64], guest_ifnames[512], *s = NULL, *wloff_vifs = NULL;
	wgn_vlan_rule vlan_list[WGN_MAXINUM_VLAN_RULELIST];
	json_object *cfgSyncNodeObj = NULL;
	json_object *cfgBssEnabledObj = NULL;
	json_object *cfgGuestIfnamesObj = NULL;
	json_object *cfgWLOffVifsObj = NULL;
	int cfgSyncNode = 0, cfgBssEnabled = 0, wgn_change_flag = 0, is_find = 0;
	int unit2 = 0, subunit2 = 0, guest_unit = 0, guest_subunit = 0, guest_ifcheck = 0, guest_band_type = 0;
	size_t vlan_list_count = 0;

#endif	// RTCONFIG_AMAS_WGN
	int bw = -1;

	DBG_INFO("enter");
	if ((cfgRoot = json_object_from_file(CFG_JSON_FILE)) == NULL) {
		DBG_ERR("cfgRoot is null");
		return;
	}

	json_object_object_get_ex(cfgRoot, CFG_STR_CFGVER, &cfgVer);
	json_object_object_get_ex(cfgRoot, CFG_STR_CFGALL, &cfgAll);
	json_object_object_get_ex(cfgRoot, CFG_BAND_INDEX_VERSION, &cfgbandVer);
	json_object_object_get_ex(cfgRoot, CFG_BAND_TYPE, &cfgbandType);
	json_object_object_get_ex(cfgRoot, CFG_STR_BANDNUM, &cfgbandnum);
	json_object_object_get_ex(cfgRoot, CFG_STR_BWCAP, &bwcapObj);
	json_object_object_get_ex(cfgRoot, CFG_ACTION_SCRIPT, &actionScriptObj);
	json_object_object_get_ex(cfgRoot, CFG_STR_SMART_CONNECT, &cfgSmartConnect);
#ifdef PRELINK
	json_object_object_get_ex(cfgRoot, CFG_STR_HASH_BUNDLE_KEY, &hashBundleKeyObj);
	cm_updateChangedHashBundleKey(hashBundleKeyObj);
#endif

	if (actionScriptObj && doAction) {	/* the action script has been recorded */
		snprintf(actionScript, sizeof(actionScript), "%s", json_object_get_string(actionScriptObj));
		cfgChanged = 1;
		passCfgCheck = 1;
	}

	/* check object whether exist/valid or not */
	if (cfgVer == NULL) {
		DBG_ERR("no cfg_ver in message!");
		json_object_put(cfgRoot);
		return;
	}
	else
	{

		if (!passCfgCheck) {
			if (!strcmp(nvram_safe_get("cfg_ver"), json_object_get_string(cfgVer)) && !cfgAll) {
				DBG_INFO("cfg ver isn't changed");
				json_object_put(cfgRoot);
				return;
			}

			if (!cfgAll) {
				DBG_INFO("change the value of cfg_ver (%s->%s)",
					nvram_safe_get("cfg_ver"), json_object_get_string(cfgVer));
				nvram_set("cfg_ver", json_object_get_string(cfgVer));
				cfgChanged = 1;
			}
		}
	}
	if (cfgbandVer == NULL) {
		DBG_INFO("cfgbandVer(0)");
		cfgband_Ver=0;
	}
	else{
		DBG_INFO("cfgbandVer(%s)", json_object_get_string(cfgbandVer));
		cfgband_Ver = atoi(json_object_get_string(cfgbandVer));
	}
	if (cfgbandType != NULL) {
		DBG_INFO("cfgbandType(%d)", json_object_get_int64(cfgbandType));
		cfgbandType_num=json_object_get_int64(cfgbandType);
	}
#if defined(SUPPORT_TRI_BAND) && defined(RTCONFIG_WIFI_SON)
	if (nvram_match("wifison_ready", "1"))
		wifison_ready = 1;
#endif /* WIFI_SON */

	if (doAction)
		nvram_set("cfg_sync_stage", "1");

	if (!passCfgCheck) {
#ifdef SUPPORT_TRI_BAND
		if(!wifison_ready) {
		if(cfgbandnum!=NULL && !strcmp("2", json_object_get_string(cfgbandnum)))
		{
			if(cfgband_Ver<2){
				need_fix_wlc2=1;
				need_fix_bandindex=nvram_get_int("dwb_band");
				DBG_INFO("need_fix_bandindex(%d)", need_fix_bandindex);
			}
			DBG_INFO("cfgbandnum(%s)", json_object_get_string(cfgbandnum));
		}
		}
#endif
		/* get bandwidth capability */
		if (bwcapObj)
			bwcap = json_object_get_int(bwcapObj);

		/* decide update wlc paramater based on mode and special */
		if (swMode == SW_MODE_REPEATER) {
			updateWlcParam = 1;
#ifdef RTCONFIG_CONCURRENTREPEATER
			concurrentRepeater = 1;
#endif
		}
		else
		{
			if (nvram_get_int("re_mode") == 1) {
				updateWlcParam = 1;
				concurrentRepeater = 1;
			}
		}

#if defined(RTCONFIG_QCA)
		extern int check_vif_bss_enabled(void);
		vif_bss_enabled = check_vif_bss_enabled();
#endif

		for (pFeature = &feature_mapping_list[0]; pFeature->index != 0; pFeature++)
		{
			struct json_object *ftObj = NULL;
			struct json_object *actionObj = NULL;
			int changed = 0;

			json_object_object_get_ex(cfgRoot, pFeature->name, &ftObj);

			if (ftObj) {
				json_object_object_foreach(ftObj, key, val) {

					if (skip_param_mapping(key, (cm_ctrlBlock.role == IS_SERVER) ? SKIP_SERVER : SKIP_CLIENT)) {
						DBG_INFO("*** skip_param_mapping(%s, %d) !! ***", key, (cm_ctrlBlock.role == IS_SERVER) ? SKIP_SERVER : SKIP_CLIENT);
						continue;
					}

					if (!strcmp(key, "action_script"))
						continue;
					DBG_INFO("key(%s), val(%s)", key, json_object_get_string(val));
					memset(prefix, 0, sizeof(prefix));
					memset(suffix, 0, sizeof(suffix));
					if (updateWlcParam && pFeature->index == FT_WIRELESS)
					{
						if (strncmp(key, "wl", 2) == 0) {
							unit = -1;
							subunit = -1;
							sscanf(key, "%[^_]_%*s", prefix);
							DBG_INFO("param(%s), prefix(%s)", key, prefix);
							if (!strstr(prefix, "."))
								sscanf(prefix, "wl%d_%*s", &unit);

							// DBG_INFO("unit(%d), subunit(%d)", unit, subunit);

							if (unit >= 0 && subunit < 0) {
								sscanf(key, "wl%*d_%s", suffix);

								if (strlen(suffix)) DBG_INFO("suffix (%s)", suffix);

								/* check the parameter need to process or not */
								needProcess = 0;
								for (pWlcsuffix = &wlcsuffix_mapping_list[0]; pWlcsuffix->name != NULL; pWlcsuffix++) {
									if (!strcmp(pWlcsuffix->name, suffix)) {
										DBG_INFO("found (%s), need to process later", pWlcsuffix->name);
										needProcess = 1;
										break;
									}
								}

								if (needProcess)
								{
									memset(wlcPrefix, 0, sizeof(wlcPrefix));
									memset(wlPrefix, 0, sizeof(wlPrefix));

									if (concurrentRepeater) {
										realUnit = get_wl_bandindex_by_unit(cfgRoot,unit,cfgbandType_num,cfgband_Ver);
										snprintf(wlcPrefix, sizeof(wlcPrefix), "wlc%d_", get_wlc_bandindex_by_unit(realUnit));
										snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", realUnit);
									}
									else
									{
										if (nvram_get_int("wlc_band") == unit) {
											snprintf(wlcPrefix, sizeof(wlcPrefix), "wlc_");
											snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", unit);
										}
										else
										{
											snprintf(wlPrefix, sizeof(wlPrefix), "wl%d_", unit);
										}
									}

									/* process wlcX related parameter first */
#ifdef SUPPORT_TRI_BAND
									if (need_fix_wlc2 && strlen(wlcPrefix) && !strncmp(wlcPrefix,"wlc2",4)
										&& !wifison_ready
									) {
										DBG_INFO("don't use wl2 sync wlc2 when CAP Dual-Band RE Tri-Band ");
									}else
#endif
									if (strlen(wlcPrefix)) {
										memset(wlcParam, 0, sizeof(wlcParam));
										memset(wsbhParam, 0, sizeof(wsbhParam));
										if (pWlcsuffix->converted_name && !strcmp(suffix, pWlcsuffix->name))
										{
											snprintf(wlcParam, sizeof(wlcParam), "%s%s", wlcPrefix, pWlcsuffix->converted_name);
											snprintf(wsbhParam, sizeof(wsbhParam), "%s%s", "wsbh_", pWlcsuffix->converted_name);
										}
										else
										{
											snprintf(wlcParam, sizeof(wlcParam), "%s%s", wlcPrefix, suffix);
											snprintf(wsbhParam, sizeof(wsbhParam), "%s%s", "wsbh_", suffix);
											//DBG_INFO("!!!!! wlcParam =%s cfgband_Ver=%d ",wlcParam ,cfgband_Ver );
										}
										if(!strcmp(suffix, "ssid")){
											memset(wlc_value, 0, sizeof(wlc_value));
											if(cfgband_Ver<2)
											{
												snprintf(wlc_value, sizeof(wlc_value), "%s", json_object_get_string(val));
											}
											else{
												//DBG_INFO("!!!!! cfgbandType_num =%d band_type=%d !!!!! ",cfgbandType_num,nvram_get_int("band_type"));
												if((cfgbandType_num==3 || cfgbandType_num==19) && ((nvram_get_int("band_type")==2) ||nvram_get_int("band_type")==4) && strstr(json_object_get_string(val), "_dwb"))
												{
														char dwb_5GH_wlc_Pararm[32] = {0};
														memset(dwb_5GH_wlc_Pararm, 0, sizeof(dwb_5GH_wlc_Pararm));
														snprintf(dwb_5GH_wlc_Pararm, sizeof(dwb_5GH_wlc_Pararm), "wlc%d_%s", get_wlc_bandindex_by_unit(check_own_unit(3)),suffix);
														//DBG_INFO("!!!!! dwb_5GH_wlc_Pararm =%s wlcParam=%s !!!!! ",dwb_5GH_wlc_Pararm,wlcParam);
														if(!strcmp(dwb_5GH_wlc_Pararm, wlcParam)){
															if (nvram_get_int("dwb_mode")){
																snprintf(wlc_value, strlen(json_object_get_string(val))-3, "%s", json_object_get_string(val));
															}
															else{
																snprintf(wlc_value, sizeof(wlc_value), "%s", json_object_get_string(val));
															}
														}
														else{
															snprintf(wlc_value, sizeof(wlc_value), "%s", json_object_get_string(val));
														}
														//DBG_INFO("!!!!! dwb_5GH_wlc_Pararm =%s wlc_value=%s !!!!! ",dwb_5GH_wlc_Pararm,wlc_value);
													
												}
												else{
													snprintf(wlc_value, sizeof(wlc_value), "%s", json_object_get_string(val));
												}
											}	
											
										}
										else{
											memset(wlc_value, 0, sizeof(wlc_value));
											snprintf(wlc_value, sizeof(wlc_value), "%s", json_object_get_string(val));
											DBG_INFO("!!!!! wlcParam =%s wlc_value=%s !!!!! ",wlcParam,wlc_value);
										}
										if ((nvram_get(wlcParam) || !strcmp(suffix, "crypto") || (wlc2_first_sync && !strncmp(wlcParam,"wlc2_",4)) || (wlc3_first_sync && !strncmp(wlcParam,"wlc3_",4))) &&
											strcmp(wlc_value, nvram_safe_get(wlcParam))) {

#ifdef RTCONFIG_DWB
											if(!Is_dwb_para(cfgRoot, wlcPrefix, wlcParam))
#endif
											{
											DBG_INFO("change the value of %s (%s->%s)",
												wlcParam, nvram_safe_get(wlcParam), wlc_value);
												if((!strcmp(nvram_safe_get("productid"),"GT-AXE16000") || !strcmp(nvram_safe_get("productid"),"GT-BE98")) && strstr(wlcParam,"wlc1_")  && nvram_get_int("smart_connect_x")>0 && cfgbandnum != NULL && supportedBandNum>json_object_get_int(cfgbandnum)){
													DBG_INFO(" wlc1_ changed but set wlChanged = 0");
												}
												else if(strstr(wlcParam,"wlc1_") && supportedBandNum==2 && !strcmp(nvram_safe_get(wlcParam),nvram_safe_get(wsbhParam))&& (nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG || nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI))
												{
													DBG_INFO(" dual band wlc1_ == wsbh_  set wlChanged = 0");
												}
												else{
													cfgChanged = 1;
													changed = 1;
													wlChanged = 1;
													DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
												}
												nvram_set(wlcParam, wlc_value);
											}
										}
#ifdef SUPPORT_TRI_BAND
										if (!wifison_ready) {
										if (need_fix_wlc2) {
											memset(wlcParam_fix, 0, sizeof(wlcParam_fix));
											if (pWlcsuffix->converted_name && !strcmp(suffix, pWlcsuffix->name))
												snprintf(wlcParam_fix, sizeof(wlcParam_fix), "%s%s", "wlc2_", pWlcsuffix->converted_name);
											else
												snprintf(wlcParam_fix, sizeof(wlcParam_fix), "%s%s", "wlc2_", suffix);

											if (strstr(wlcParam,"wlc1_") && strcmp(json_object_get_string(val), nvram_safe_get(wlcParam_fix))) {
												DBG_INFO("change the value of %s (%s->%s)",wlcParam_fix, nvram_safe_get(wlcParam_fix), json_object_get_string(val));
												nvram_set(wlcParam_fix, json_object_get_string(val));
											}
										}
										}
#endif
									}

									/* process wlX/wlX.Y releated parameter */
#ifdef SUPPORT_TRI_BAND
									char wlPrefix_check[16];
									memset(wlPrefix_check, 0, sizeof(wlPrefix_check));
									 snprintf(wlPrefix_check, sizeof(wlPrefix_check), "wl%d.", need_fix_bandindex);
									if (need_fix_wlc2 && strlen(wlPrefix) && !strncmp(wlPrefix,wlPrefix_check,4)
										&& !wifison_ready
									) {
										DBG_INFO("don't use wl%d sync wlc2 when CAP Dual-Band RE Tri-Band ",need_fix_bandindex);
									}else
#endif
									if (strlen(wlPrefix)) {
										memset(param, 0, sizeof(param));
										snprintf(param, sizeof(param), "%s%s", wlPrefix, suffix);
#ifdef SUPPORT_TRI_BAND
                                        memset(wlPrefix_fix, 0, sizeof(wlPrefix_fix));
                                        snprintf(wlPrefix_fix, sizeof(wlPrefix_fix), "%s%d.%d_", "wl", need_fix_bandindex, unit);
                                        memset(wlparam_fix, 0, sizeof(wlparam_fix));
                                        snprintf(wlparam_fix, sizeof(wlparam_fix), "%s%d.%d_%s", "wl", need_fix_bandindex, unit, suffix);
#endif
										if (strcmp(json_object_get_string(val), nvram_safe_get(param))) {

#ifdef RTCONFIG_DWB
											if(!Is_dwb_para(cfgRoot, wlPrefix, param))
#endif
											{
												//  authentication convert
												char converted_val[16] = {};
												if (authentication_convert(realUnit, 0, suffix, ftObj, converted_val, sizeof(converted_val)) == 1) {
													if (strcmp(converted_val, nvram_safe_get(param))) {
														DBG_INFO("change the value of %s (%s->%s)",
															param, nvram_safe_get(param), converted_val);
														cfgChanged = 1;
														changed = 1;
														wlChanged = 1;
														DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
														nvram_set(param, converted_val);
													}
												} else {
													if (cfgbandVer != NULL && (!strcmp(param,"wl2.1_ssid")||!strcmp(param,"wl2.1_closed"))) {
														if(((nvram_get_int("band_type")==2||nvram_get_int("band_type")==4 )&&cfgbandType_num==19)||(nvram_get_int("band_type")==3 &&(cfgbandType_num==13||cfgbandType_num==29))||(nvram_get_int("band_type")==4 &&cfgbandType_num==19)){
														nvram_set(param, json_object_get_string(val));
														}
														else{
														DBG_INFO("change the value of %s (%s->%s)",
															param, nvram_safe_get(param), json_object_get_string(val));
														cfgChanged = 1;
														changed = 1;
														wlChanged = 1;
														DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
														nvram_set(param, json_object_get_string(val));
															
														}
													}
													else if (cfgbandVer != NULL && (!strcmp(param,"wl1.1_ssid") || !strcmp(param,"wl1.1_closed")) && cfgbandVer>1) {												
													if((cfgbandType_num==3||cfgbandType_num==19) && nvram_get_int("dwb_band")==1 && (nvram_get_int("band_type")==2 ||nvram_get_int("band_type")==4))
														{
															nvram_set(param, json_object_get_string(val));
														}
														else{
														DBG_INFO("change the value of %s (%s->%s)",
															param, nvram_safe_get(param), json_object_get_string(val));
														cfgChanged = 1;
														changed = 1;
														wlChanged = 1;
														DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
														nvram_set(param, json_object_get_string(val));
															
														}
													}
													else{
														DBG_INFO("change the value of %s (%s->%s)",
															param, nvram_safe_get(param), json_object_get_string(val));
														cfgChanged = 1;
														changed = 1;
														wlChanged = 1;
														DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
														nvram_set(param, json_object_get_string(val));
													}
												}
											}

											/* for later process on wep key */
											if (!strcmp(suffix, "key") || !strcmp(suffix, "key1") || !strcmp(suffix, "key2") ||
												!strcmp(suffix, "key3") || !strcmp(suffix, "key4"))
												wepKeyChanged[unit] = 1;
										}
#ifdef SUPPORT_TRI_BAND
                                        if (!wifison_ready) {
                                            if (need_fix_wlc2) {
                                                if (strcmp(json_object_get_string(val), nvram_safe_get(wlparam_fix))) {
#ifdef RTCONFIG_DWB
                                                    if(!Is_dwb_para(cfgRoot, wlPrefix_fix, wlparam_fix))
#endif
                                                    {
                                                        DBG_INFO("change the value of %s (%s->%s)",
                                                            wlparam_fix, nvram_safe_get(wlparam_fix), json_object_get_string(val));
									if((nvram_get_int("band_type")!=3 && nvram_get_int("band_type")!=4)){
												        cfgChanged = 1;
												        changed = 1;
												        wlChanged = 1;
									}
														DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
                                                        nvram_set(wlparam_fix, json_object_get_string(val));
                                                    }
                                                }
                                            }
                                        }
#endif
									}

									continue;
								}
							}
						}
					}

					/* for smart connect enable / disable */
					if (strstr(key, "smart_connect_x"))
					{
						char s[81], *ss = NULL;
						DBG_INFO("** Process SMART_CONNECT Start!! **");
						DBG_INFO("Process key : %s", key);
						if (json_object_get_int(val) > 0)
						{
							memset(bsd_ifnames, 0, sizeof(bsd_ifnames));
							memset(bsd_ifnames_x, 0, sizeof(bsd_ifnames_x));
							for (i=0, local_band_num=num_of_wl_if(); i<local_band_num; i++)
							{
								memset(s, 0, sizeof(s));
								snprintf(s, sizeof(s)-1, "wl%d_vifs", i);
								foreach (bsd_ifname_word, nvram_safe_get(s), bsd_ifname_next)
								{
									if (json_object_get_int(val) == 3) {
										if (i < 2) {
											strncat(bsd_ifnames, bsd_ifname_word, strlen(bsd_ifname_word));
											strncat(bsd_ifnames, " ", 1);
										}
									} else {
										strncat(bsd_ifnames, bsd_ifname_word, strlen(bsd_ifname_word));
										strncat(bsd_ifnames, " ", 1);
									}
									if (local_band_num == 3 && i > 0) // Tri-Band
									{
										strncat(bsd_ifnames_x, bsd_ifname_word, strlen(bsd_ifname_word));
										strncat(bsd_ifnames_x, " ", 1);
									}
									break;
								}
							}
#if defined(RTCONFIG_DWB) && defined(SMART_CONNECT)
							cm_resetRESmartConnectBsdifnames(cfgRoot, bsd_ifnames, sizeof(bsd_ifnames));
#endif

							ss = nvram_safe_get("bsd_ifnames");
							if (strlen(ss) > 0 && strlen(bsd_ifnames) > 0)
							{
								if (bsd_ifnames[strlen(bsd_ifnames)-1] == ' ')  // remove space
									bsd_ifnames[strlen(bsd_ifnames)-1] = '\0';
								if (strcmp(ss, bsd_ifnames) != 0)
								{
									DBG_INFO("nvram set bsd_ifnames=%s", bsd_ifnames);
									nvram_set("bsd_ifnames", bsd_ifnames);
									cfgChanged = 1;
									changed = 1;
									wlChanged = 1;
									DBG_INFO("wlChanged=1");
								}
							}

							ss = nvram_safe_get("bsd_ifnames_x");
							if (strlen(ss) > 0 && strlen(bsd_ifnames_x) > 0)
							{
								bsd_ifnames_x[strlen(bsd_ifnames_x)-1] = '\0';
								if (strncmp(ss, bsd_ifnames_x, strlen(bsd_ifnames_x)) != 0)
								{
									DBG_INFO("nvram set bsd_ifnames_x=%s", bsd_ifnames_x);
									nvram_set("bsd_ifnames_x", bsd_ifnames_x);
									cfgChanged = 1;
									changed = 1;
									wlChanged = 1;
									DBG_INFO("wlChanged=1");
								}
							}
						}
						DBG_INFO("** Process SMART_CONNECT End !! **");
					}

					/* for smart connect rule */
					if (strstr(key, "bsd_steering_policy") ||
						strstr(key, "bsd_sta_select_policy") ||
						strstr(key, "bsd_if_select_policy") ||
						strstr(key, "bsd_if_qualify_policy") ||
						strstr(key, "bsd_bounce_detect"))
					{
						DBG_INFO("** Process SMART_CONNECT_RULE Start!! **");
						DBG_INFO("Process key : %s", key);
						char *if_select_policy_idx = NULL, *if_select_policy = NULL, ss[133], *s = NULL;
						if (cfgSmartConnect == NULL || cfgbandnum == NULL || (cap_smart_connect_x = json_object_get_int(cfgSmartConnect)) == 0) continue;
						cap_band_num = json_object_get_int(cfgbandnum);
						if (cap_band_num != 2 && cap_band_num != 3) continue;
						if (num_of_wl_if() != 2 && num_of_wl_if() != 3) continue;
						if (cap_band_num == num_of_wl_if()) // Tri-Band to Tri-Band or Dual-Band to Dual-Band
						{
							// sync all
							if (strstr(key, "bsd_if_select_policy_idx") || strstr(key, "bsd_if_select_policy_x_idx"))
							{
								if ((if_select_policy_idx = (char *)json_object_get_string(val)) == NULL)
								{
									DBG_INFO("call json_object_get_string() : return null");
									continue;
								}

								extern char *wl_ifindex_to_bsd_ifnames(char *ifindex, int *out_len);
								if ((if_select_policy = wl_ifindex_to_bsd_ifnames(if_select_policy_idx, NULL)) == NULL)
								{
									DBG_INFO("call wl_ifindex_to_bsd_ifnames(%s) : return null", if_select_policy_idx);
									continue;
								}

								if (strlen(if_select_policy) <= 0)
								{
									DBG_INFO("if_select_policy is empty !!");
									free(if_select_policy);
									continue;
								}
#if defined(RTCONFIG_DWB) && defined(SMART_CONNECT)
								cm_resetRESmartConnectIfPolicy(cfgRoot, key, &if_select_policy);
#endif
								memset(ss, 0, sizeof(ss));
								strncpy(ss, key, strlen(key));
								ss[strlen(key)-4] = '\0';
								s = nvram_safe_get(ss);
								if (strlen(s) > 0 && strcmp(s, if_select_policy) != 0)
								{
									DBG_INFO("nvram_set(%s:%s)", ss, if_select_policy);
									nvram_set(ss, if_select_policy);
									cfgChanged = 1;
									changed = 1;
									wlChanged = 1;
									DBG_INFO("wlChanged=1");
								}
								free(if_select_policy);
							}
						}
						else 	// Tri-Band to Dual-Band or Dual-Band to Tri-Band
						{
							if (strstr(key, "bsd_if_select_policy")) continue;	// ignore sync
							if (cap_band_num == 3 && num_of_wl_if() == 2)	// Tri-Band to Dual-Band
							{
								if (cap_smart_connect_x == 2)	// 5GHz smart connect
								{
									if (strstr(key, "bsd_steering_policy_x") ||
										strstr(key, "bsd_sta_select_policy_x") ||
										strstr(key, "bsd_if_qualify_policy_x") ||
										strstr(key, "bsd_bounce_detect_x"))
									{
										if (!strstr(key, "wl1_") && !strstr(key, "bsd_bounce_detect_x")) continue; 	// ignore sync
										key[strlen(key)-2] = '\0';
										s = nvram_safe_get(key);
										if (strlen(s) > 0 && strncmp(s, json_object_to_json_string(val), strlen(json_object_to_json_string(val))) != 0)
										{
											nvram_set(key, json_object_get_string(val));
											cfgChanged = 1;
											changed = 1;
											wlChanged = 1;
											DBG_INFO("wlChanged=1");
										}
									}
								}
							}
							else 	// Dual-Band to Tri-Band
							{
								if (strstr(key, "wl1_bsd_steering_policy_x") ||
									strstr(key, "wl2_bsd_steering_policy_x") ||
									strstr(key, "wl2_bsd_steering_policy") ||
									strstr(key, "wl1_bsd_sta_select_policy_x") ||
									strstr(key, "wl2_bsd_sta_select_policy_x") ||
									strstr(key, "wl2_bsd_sta_select_policy") ||
									strstr(key, "wl1_bsd_if_qualify_policy_x") ||
									strstr(key, "wl2_bsd_if_qualify_policy_x") ||
									strstr(key, "wl2_bsd_if_qualify_policy") ||
									strstr(key, "bsd_bounce_detect_x"))

								{
									continue;	// ignore sync
								}

							}
						}
						DBG_INFO("** Process SMART_CONNECT_RULE End !! **");
					}

					/* for wps_enable */
					if (strstr(key, "wps_enable"))
					{
						DBG_INFO("** Process WPS_ENABLE Start !! **");
						if (nvram_get_int("wps_enable_x") != json_object_get_int(val))
						{
							nvram_set("wps_enable_x", json_object_get_string(val));
							cfgChanged = 1;
							changed = 1;
							wlChanged = 1;
							DBG_INFO("wlChanged=1");
						}
						DBG_INFO("** Process WPS_ENABLE End !! **");
					}

#ifdef RTCONFIG_AMAS_WGN
					if (strncmp(key, "wl", 2) == 0)
					{
						unit = subunit = -1;
						sscanf(key, "wl%d.%d_%*s", &unit, &subunit);
						if (unit > -1 && subunit > 0)
						{
							guest_unit = guest_subunit = -1;
							cfgGuestIfnamesObj = NULL;
							guest_band_type = wgn_get_band_by_unit(mapping_wl_bandindex_by_unit(unit, cfgRoot));
							switch (guest_band_type) {
								case WGN_WL_BAND_2G:
									json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_2G, &cfgGuestIfnamesObj);
									break;
								case WGN_WL_BAND_5G:
									json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_5G, &cfgGuestIfnamesObj);
									break;
								case WGN_WL_BAND_5GH:
									json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_5GH, &cfgGuestIfnamesObj);
									break;
								case WGN_WL_BAND_6G:
									json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_6G, &cfgGuestIfnamesObj);
									break;
								default: 
									cfgGuestIfnamesObj = NULL;
									break;
							}

							if (cfgGuestIfnamesObj)
							{

								is_find = cap_guest_ifidx = 0;
								if ((s = json_object_get_string(cfgGuestIfnamesObj)))
								{
									foreach(word, s, next)
									{
										cap_guest_ifidx++;
										unit2 = subunit2 = -1;
										sscanf(word, "wl%d.%d_%*s", &unit2, &subunit2);
										if (unit2 > -1 && subunit == subunit2) {	// check subunit only
											is_find = 1;
											break;
										}
									}
								}

								if (is_find)
								{
									is_find = re_guest_ifidx = 0;
									memset(guest_ifnames, 0, sizeof(guest_ifnames));
									if (wgn_guest_ifnames(wgn_get_unit_by_band(guest_band_type), 0, guest_ifnames, sizeof(guest_ifnames)-1))
									{
										foreach(word, guest_ifnames, next)
										{
											re_guest_ifidx++;
											if (cap_guest_ifidx == re_guest_ifidx)
											{
												is_find = 1;
												break;
											}
										}
									}

									if (is_find)
									{
										unit2 = subunit2 = -1;
										sscanf(word, "wl%d.%d_%*s", &unit2, &subunit2);
										if (unit2 > -1 && subunit2 > 0) {
											guest_unit = wgn_get_unit_by_band(guest_band_type);
											guest_subunit = subunit2;
										}
									}
								}
							}

							if (guest_unit > -1 && guest_subunit > 0)
							{
								wgn_change_flag = 0;
								memset(suffix, 0, sizeof(suffix));
								sscanf(key, "wl%*d.%*d_%s", suffix);
								memset(wlPrefix, 0, sizeof(wlPrefix));
								snprintf(wlPrefix, sizeof(wlPrefix)-1, "wl%d.%d", guest_unit, guest_subunit);
								memset(tmp, 0, sizeof(tmp));
								snprintf(tmp, sizeof(tmp)-1, "%s_%s", wlPrefix, suffix);
								
								if (!strstr(key, "bss_enabled"))
								{
									//  authentication convert
									char converted_val[16] = {};
									if (authentication_convert(unit, subunit, suffix, ftObj, converted_val, sizeof(converted_val)) == 1)
									{
										if (!nvram_match(tmp, converted_val))
										{
											wgn_change_flag = 1;
											nvram_set(tmp, converted_val);
											DBG_INFO("WGN nvram set %s=%s", tmp, converted_val);
										}
									} else {
										if (!nvram_match(tmp, json_object_get_string(val)))
										{
											wgn_change_flag = 1;
											nvram_set(tmp, json_object_get_string(val));
											DBG_INFO("WGN nvram set %s=%s", tmp, json_object_get_string(val));
										}
									}
								}
								else // process wlX_bss_enabled
								{
									wgn_wl_bss_enabled = json_object_get_int(val);
									switch (guest_band_type) {
										case WGN_WL_BAND_2G:
											json_object_object_get_ex(cfgRoot, CFG_STR_SYNC_NODE_2G, &cfgSyncNodeObj);
											json_object_object_get_ex(cfgRoot, CFG_STR_BSS_ENABLED_2G, &cfgBssEnabledObj);
											break;
										case WGN_WL_BAND_5G:
											json_object_object_get_ex(cfgRoot, CFG_STR_SYNC_NODE_5G, &cfgSyncNodeObj);
											json_object_object_get_ex(cfgRoot, CFG_STR_BSS_ENABLED_5G, &cfgBssEnabledObj);
											break;
										case WGN_WL_BAND_5GH:
											json_object_object_get_ex(cfgRoot, CFG_STR_SYNC_NODE_5GH, &cfgSyncNodeObj);
											json_object_object_get_ex(cfgRoot, CFG_STR_BSS_ENABLED_5GH, &cfgBssEnabledObj);
											break;
										case WGN_WL_BAND_6G:
											json_object_object_get_ex(cfgRoot, CFG_STR_SYNC_NODE_6G, &cfgSyncNodeObj);
											json_object_object_get_ex(cfgRoot, CFG_STR_BSS_ENABLED_6G, &cfgBssEnabledObj);
											break;
										default:
											cfgSyncNodeObj = NULL;
											cfgBssEnabledObj = NULL;
											break;
									}

									if (cfgSyncNodeObj && cfgBssEnabledObj) {
										// sync node
										z = cfgSyncNode = 0;
										foreach (word, json_object_get_string(cfgSyncNodeObj), next) {
											z++;
											if (z == re_guest_ifidx) {
												cfgSyncNode = atoi(word);
												break;
											}
										}
										// bss enabled
										z = cfgBssEnabled = 0;
										foreach (word, json_object_get_string(cfgBssEnabledObj), next) {
											z++;
											if (z == re_guest_ifidx) {
												cfgBssEnabled = atoi(word);
												break;
											}
										}

										wgn_wl_bss_enabled = (cfgSyncNode == SYNC_NODE_ROUTER_ONLY) ? 0 : cfgBssEnabled;
									}

									memset(str, 0, sizeof(str));
									snprintf(str, sizeof(str), "wl%d.%d_bss_enabled", guest_unit, guest_subunit);
									memset(tmp, 0, sizeof(tmp));
									snprintf(tmp, sizeof(tmp), "%d", wgn_wl_bss_enabled);
									if (!nvram_match(str, tmp))
									{
										wgn_change_flag = 1;
										nvram_set_int(str, wgn_wl_bss_enabled);
										DBG_INFO("WGN nvram set %s=%d", str, wgn_wl_bss_enabled);
									}

								}

								if (wgn_change_flag == 1)
								{
									cfgChanged = 1;
									changed = 1;	
									wlChanged = 1;
									DBG_INFO("cfgChanged = 1, changed = 1, wlChanged = 1");
								}

							}

							continue;
						}
					}
#endif	// RTCONFIG_AMAS_WGN							

					if (strncmp(key, "wl", 2) == 0 && strstr(key, "_expire")) {
						char tmp_key[32];
						snprintf(tmp_key, sizeof(tmp_key)-1, "%s_tmp",  key);
						nvram_set(tmp_key, json_object_get_string(val));
					}

					/* check parameter sync */
					if (cm_checkParameterSync(key))	continue;

					/* check specific parameter need to sync or not */
					memset(param, 0, sizeof(param));
					strlcpy(param, key, sizeof(param));
					if (strncmp(key, "wl", 2) == 0) {
						unit = realUnit = -1;
						sscanf(key, "%[^_]_%*s", prefix);
						if (!strstr(prefix, ".")) {
							sscanf(prefix, "wl%d_%*s", &unit);
							if (unit >= 0) {
								sscanf(key, "wl%*d_%s", suffix);
								realUnit = get_wl_bandindex_by_unit(cfgRoot, unit, cfgbandType_num, cfgband_Ver);
								snprintf(param, sizeof(param), "wl%d_%s", realUnit, suffix);
							}
						}
					}

					if (cm_needSyncSpecificParam(param)) {
						/* for wlX_bw convert */
						DBG_INFO("key(%s), param(%s), val(%s)", key, param, json_object_get_string(val));
						if (strncmp(param, "wl", 2) == 0 && strstr(param, "bw") && !strstr(param, "bw_160")) {
							if (bwcap >= 0) {
								if (bwcap != BW_CAP) {
									/* for wlX_bw (0 <-> 1) */
									DBG_INFO("change wlX_bw (0 <-> 1)");
									if (nvram_get(param)) {
										bw = -1;

										/* check the value whether has content or not */
										if (strlen(json_object_get_string(val)))
											bw = atoi(json_object_get_string(val));

										if (bw == 0 || bw == 1) {
											bw = (bw == 0) ? 1 : 0;
											if (nvram_get_int(param) != bw) {	/* changed */
												DBG_INFO("change the value of %s (%s->%d)",
													param, nvram_safe_get(param), bw);
												cfgChanged = 1;
												changed = 1;
												wlChanged = 1;
												DBG_INFO("wlChanged=1");
												nvram_set_int(param, bw);
											}
										}
										else if (strcmp(json_object_get_string(val), nvram_decrypt_get(param)))
										{
											DBG_INFO("change the value of %s (%s->%s)",
												param, nvram_safe_get(param), json_object_get_string(val));
											nvram_encrypt_set(param, (char *)json_object_get_string(val));
											cfgChanged = 1;
											changed = 1;
											wlChanged = 1;
										}
									}
								}
								else if (strcmp(json_object_get_string(val), nvram_decrypt_get(param)))
								{
									DBG_INFO("change the value of %s (%s->%s)",
										param, nvram_safe_get(param), json_object_get_string(val));
									nvram_encrypt_set(param, (char *)json_object_get_string(val));
									cfgChanged = 1;
									changed = 1;
									wlChanged = 1;
								}
							}
						}
						else if (strcmp(json_object_get_string(val), nvram_decrypt_get(param)))
						{
							DBG_INFO("change the value of %s (%s->%s)",
								param, nvram_safe_get(param), json_object_get_string(val));
							nvram_encrypt_set(param, (char *)json_object_get_string(val));
							cfgChanged = 1;
							changed = 1;
						}
						continue;
					}

					/* check need to update config or not */
					needUpdateCfg = 0;
					if ((nvram_get(key) || !strcmp(key, "apps_sq") || !strcmp(key, "smart_connect_x")) &&
						strcmp(json_object_get_string(val), nvram_decrypt_get(key)))
						needUpdateCfg = 1;

					if (needUpdateCfg
#ifdef SUPPORT_TRI_BAND
						|| (need_fix_wlc2 && strstr(key, "wl1_"))
#endif
					) {
						/* pass channel sync */
						if (concurrentRepeater
#ifdef RTCONFIG_BCMWL6
							&& (strstr(key, "chanspec") || (strstr(key, "bw") && !strstr(key, "bw_160")))
#else
							&& (strstr(key, "channel") || (strstr(key, "bw") && !strstr(key, "bw_160"))
								|| strstr(key, "nctrlsb"))
#endif
							)
						{
							DBG_INFO("pass %s sync when re mode.", key);
							continue;
						}
#ifdef SUPPORT_TRI_BAND
						if (need_fix_wlc2 && strstr(key, "wl2_")) {
							DBG_INFO("skip processing wl2 param %s from CAP if CAP is dual band and RE is tri band", key);
							continue;
						}
#endif
						if (needUpdateCfg) {
							if (strcmp(key, "smart_connect_x") == 0) {
								wlChanged = 1;
								DBG_INFO("wlChanged = 1");
							}
							cfgChanged = 1;
#if defined(RTCONFIG_QCA)
					if (!vif_bss_enabled) {
						extern int sync_vif_bss_enabled(char *key, char *pre, char *now);
						vif_bss_enabled = sync_vif_bss_enabled(key, nvram_safe_get(key), json_object_get_string(val));
						if (vif_bss_enabled==0 || vif_bss_enabled==2)
							changed = 1;
					}
#endif
						}

#ifdef SUPPORT_TRI_BAND
						/* Sync parameter to wl2 */
						if (need_fix_wlc2 && strstr(key, "wl1_") ) {
							/* get suffix when key is matched wl1_ */
							memset(suffix, 0, sizeof(suffix));
							sscanf(key, "wl%*d_%s", suffix);
							if (strlen(suffix) == 0) {
								DBG_INFO("the len of suffix is 0");
								continue;
							}

							memset(wl2param_fix, 0, sizeof(wl2param_fix));
							snprintf(wl2param_fix, sizeof(wl2param_fix), "%s_%s", "wl2", suffix);
							if (nvram_get(wl2param_fix) && strcmp(nvram_safe_get(wl2param_fix), json_object_get_string(val)) != 0) {
								DBG_INFO("change the value of %s (%s->%s)",
									wl2param_fix, nvram_safe_get(wl2param_fix), json_object_get_string(val));
								nvram_set(wl2param_fix, json_object_get_string(val));
								changed = 1;
#ifdef RTCONFIG_WL_SCHED_V2
								if (strstr(wl2param_fix, "sched") && !strstr(wl2param_fix, "sched_v2"))
									cm_setSchedV2ConvertedFlag(wl2param_fix);
#endif
							}

							if (cm_is_sync_to_wl1(key) && (strcmp(nvram_safe_get(key), json_object_get_string(val)) != 0)) {
								DBG_INFO("change the value of %s (%s->%s)",
									key, nvram_safe_get(key), json_object_get_string(val));
								nvram_set(key, json_object_get_string(val));
								changed = 1;
#ifdef RTCONFIG_WL_SCHED_V2
								if (strstr(key, "sched") && !strstr(key, "sched_v2"))
									cm_setSchedV2ConvertedFlag(key);
#endif
							}
						}
						else
#endif
						{
							if (needUpdateCfg) {
								DBG_INFO("change the value of %s (%s->%s)",
									key, nvram_safe_get(key), json_object_get_string(val));
								nvram_encrypt_set(key, (char *)json_object_get_string(val));
								changed = 1;
#ifdef RTCONFIG_WL_SCHED_V2
								if (strncmp(key, "wl", 2) == 0 && strstr(key, "sched") &&
									!strstr(key, "sched_v2"))
									cm_setSchedV2ConvertedFlag(key);
#endif
							}
						}
					}
					else
					{
						/* handle channel & extension channel & bandwidth */
						if (strncmp(key, "wl", 2) == 0 && !concurrentRepeater
#ifdef RTCONFIG_BCMWL6
							&& (strstr(key, "channel") || strstr(key, "nctrlsb"))
#else
							&& strstr(key, "chanspec")
#endif
						) {
							if (cm_processSpecialParam(key, json_object_get_string(val))) {
								cfgChanged = 1;
								changed = 1;
							}
						}
					}
				}

				if (changed) {
					json_object_object_get_ex(ftObj, "action_script", &actionObj);
					if (actionObj) {
						if (!cm_skipServiceAtFirstSync((char *)json_object_get_string(actionObj))) {
							if (!strstr(actionScript, json_object_get_string(actionObj))) {
								if (strlen(actionScript))
									strlcat(actionScript, ";", sizeof(actionScript));
								strlcat(actionScript, json_object_get_string(actionObj), sizeof(actionScript));
							}
						}
					}
				}
			}
		}

		/* for process wep key releated, convert keyX to wep_key */
		for (i = 0; i < sizeof(wepKeyChanged)/sizeof(int); i++) {
			if (wepKeyChanged[i] == 1) {
				memset(wlcPrefix, 0, sizeof(wlcPrefix));
				memset(wlPrefix, 0, sizeof(wlPrefix));
				memset(wlcParam, 0, sizeof(wlcParam));
				memset(param, 0, sizeof(param));

				if (concurrentRepeater) {
					snprintf(wlcPrefix, sizeof(wlcPrefix), "wlc%d_", i);
					snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", i);
				}
				else
				{
					if (nvram_get_int("wlc_band") == i) {
						snprintf(wlcPrefix, sizeof(wlcPrefix), "wlc_");
						snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", i);
					}
					else
						snprintf(wlPrefix, sizeof(wlPrefix), "wl%d_", i);
				}

				snprintf(tmp, sizeof(tmp), "%skey", wlPrefix);
				snprintf(param, sizeof(param), "%skey%d", wlPrefix, nvram_get_int(tmp));
				snprintf(wlcParam, sizeof(wlcParam), "%swep_key", wlcPrefix);
				DBG_INFO("set %s as %s", wlcParam, nvram_safe_get(param));
				nvram_set(wlcParam, nvram_safe_get(param));
#ifdef SUPPORT_TRI_BAND
				if (!wifison_ready) {
				if (need_fix_wlc2) {
					if (strstr(wlcParam,"wlc1_")) {
						nvram_set("wlc2_wep_key", nvram_safe_get(param));
					}
				}
				}
#endif
			}
		}

		wlc2_first_sync=0;
		wlc3_first_sync=0;
		
DBG_INFO("Process smart connect, wlChanged : %d", wlChanged);
		/* for process smart connect */
		if (wlChanged == 1)
		{
			int smart_connect_x = nvram_get_int("smart_connect_x");
			if (smart_connect_x  > 0)
			{
				struct smart_connect_nvsuffix_t *P = NULL;
				for (P=&smart_connect_nvsuffix_list[0]; P->name != NULL; P++)
				{
					char w0[33], w1[33], w2[33], *s = NULL, *ss = NULL;
					if (smart_connect_x == 2)	/* copy 5G to 5G-1 */
					{

						if(supportedBandNum>2){
#ifdef SUPPORT_TRI_BAND
							if (!wifison_ready) 
#endif	/* SUPPORT_TRI_BAND */							
							{
							if (concurrentRepeater)
							{
								// wlX.X
								memset(w1, 0, sizeof(w1));
								snprintf(w1, sizeof(w1)-1, "wl%d.1_%s",check_own_unit(2), s);
								memset(w2, 0, sizeof(w2));
								snprintf(w2, sizeof(w2)-1, "wl%d.1_%s", get_wl_bandindex_by_unit(cfgRoot,2,cfgbandType_num,cfgband_Ver), s);
								ss = nvram_safe_get(w1);
								DBG_INFO("nvram set %s=%s", w2, ss);
								nvram_set(w2, ss);

								// wlcX
								if (P->converted_name != NULL) s = P->converted_name;
								memset(w1, 0, sizeof(w1));
								snprintf(w1, sizeof(w1)-1, "wlc1_%s", s);
								memset(w2, 0, sizeof(w2));
								snprintf(w2, sizeof(w2)-1, "wlc2_%s", s);
								if (nvram_get(w1)) {
									ss = nvram_safe_get(w1);
									DBG_INFO("nvram set %s=%s", w2, ss);
									nvram_set(w2, ss);
								}
							}
							else
							{
								// wlX
								memset(w1, 0, sizeof(w1));
								snprintf(w1, sizeof(w1)-1, "wl%d_%s",check_own_unit(2), s);
								memset(w2, 0, sizeof(w2));
								snprintf(w2, sizeof(w2)-1, "wl%d_%s",get_wl_bandindex_by_unit(cfgRoot,2,cfgbandType_num,cfgband_Ver), s);
								ss = nvram_safe_get(w1);
								DBG_INFO("nvram set %s=%s", w2, ss);
								nvram_set(w2, ss);
							}
							}
						}

					} else if (smart_connect_x == 3) {  /* Copy 2.4G to 5G */
						if (concurrentRepeater) {
							// wlX.X
							memset(w0, 0, sizeof(w0));
							snprintf(w0, sizeof(w0)-1, "wl%d.1_%s", check_own_unit(0), s);
							memset(w1, 0, sizeof(w1));
							snprintf(w1, sizeof(w1)-1, "wl%d.1_%s", check_own_unit(2), s);
							ss = nvram_safe_get(w0);
							DBG_INFO("nvram set %s=%s", w1, ss);
							nvram_set(w1, ss);

							// wlcX
							if (P->converted_name != NULL) s = P->converted_name;
							memset(w0, 0, sizeof(w0));
							snprintf(w0, sizeof(w0)-1, "wlc0_%s", s);
							memset(w1, 0, sizeof(w1));
							snprintf(w1, sizeof(w1)-1, "wlc1_%s", s);
							if (nvram_get(w0)) {
								ss = nvram_safe_get(w0);
								DBG_INFO("nvram set %s=%s", w1, ss);
								nvram_set(w1, ss);
							}
						} else {
							// wlX
							memset(w0, 0, sizeof(w0));
							snprintf(w0, sizeof(w0)-1, "wl%d_%s", check_own_unit(0), s);
							memset(w1, 0, sizeof(w1));
							snprintf(w1, sizeof(w1)-1, "wl%d_%s", check_own_unit(2), s);
							ss = nvram_safe_get(w0);
							DBG_INFO("nvram set %s=%s", w1, ss);
							nvram_set(w1, ss);
						}
					}
					else	/* copy 2.4G to 5G or 5G-1 */
					{
						if (concurrentRepeater)
						{
							// wlX.X
							memset(w0, 0, sizeof(w0));
							snprintf(w0, sizeof(w0)-1, "wl%d.1_%s", check_own_unit(0), s);
							memset(w1, 0, sizeof(w1));
							snprintf(w1, sizeof(w1)-1, "wl%d.1_%s", check_own_unit(2), s);
							ss = nvram_safe_get(w0);
							DBG_INFO("nvram set %s=%s", w1, ss);
							nvram_set(w1, ss);
#ifdef SUPPORT_TRI_BAND
							if (!wifison_ready) {
#ifdef RTCONFIG_DWB
								if (nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_CFG &&  nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI)
#endif	/* RTCONFIG_DWB */
								{
									memset(w2, 0, sizeof(w2));
									snprintf(w2, sizeof(w2)-1, "wl%d.1_%s", get_wl_bandindex_by_unit(cfgRoot,2,cfgbandType_num,cfgband_Ver), s);
									ss = nvram_safe_get(w0);
									DBG_INFO("nvram set %s=%s", w2, ss);
									nvram_set(w2, ss);
								}
							}
#endif	/* SUPPORT_TRI_BAND */

							// wlcX
							if (P->converted_name != NULL) s = P->converted_name;
							memset(w0, 0, sizeof(w0));
							snprintf(w0, sizeof(w0)-1, "wlc0_%s", s);
							memset(w1, 0, sizeof(w1));
							snprintf(w1, sizeof(w1)-1, "wlc1_%s", s);
							if (nvram_get(w0)) {
								ss = nvram_safe_get(w0);
								DBG_INFO("nvram set %s=%s", w1, ss);
								nvram_set(w1, ss);
							}
#ifdef SUPPORT_TRI_BAND
							if (!wifison_ready) {
#ifdef RTCONFIG_DWB
								if (nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_CFG &&  nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI)
#endif	/* RTCONFIG_DWB */
								{
									memset(w2, 0, sizeof(w2));
									snprintf(w2, sizeof(w2)-1, "wlc2_%s", s);
									if (nvram_get(w0)) {
										ss = nvram_safe_get(w0);
										DBG_INFO("nvram set %s=%s", w2, ss);
										nvram_set(w2, ss);
									}
								}
							}
#endif	/* SUPPORT_TRI_BAND */
						}
						else
						{
							// wlX
							memset(w0, 0, sizeof(w0));
							snprintf(w0, sizeof(w0)-1, "wl%d_%s", check_own_unit(0), s);
							memset(w1, 0, sizeof(w1));
							snprintf(w1, sizeof(w1)-1, "wl%d_%s", check_own_unit(2), s);
							ss = nvram_safe_get(w0);
							DBG_INFO("nvram set %s=%s", w1, ss);
							nvram_set(w1, ss);

							if(supportedBandNum>2){
#ifdef SUPPORT_TRI_BAND
								if (!wifison_ready) 
#endif	/* SUPPORT_TRI_BAND */
								{
								memset(w2, 0, sizeof(w2));
								snprintf(w2, sizeof(w2)-1, "wl%d_%s",get_wl_bandindex_by_unit(cfgRoot,2,cfgbandType_num,cfgband_Ver), s);
								ss = nvram_safe_get(w0);
								DBG_INFO("nvram set %s=%s", w2, ss);
								nvram_set(w2, ss);
								}
							}							
						}
					}
				}
			}
		}
	}

	// cm_applyCtrlAction
	(void)cm_applyCtrlAction(cfgRoot, &cfgChanged, actionScript, sizeof(actionScript));
	
#ifdef RTCONFIG_DWB
	if (Do_Setting_WiFi_Backhual_Parameter(cfgRoot)) {
		Set_transDedicated_Wifi_Backhaul_Parameter(cfgRoot, &dwb_change);
		if (dwb_change > 0)
		{
#ifdef RTCONFIG_BHCOST_OPT
			if (dwb_change & (1 << 1)) {  // DWB AP and STA or Only AP config changed. Restart wireless.
				DBG_INFO("DWB: dwb_change = %d, add restart_wireless to actionScript.", dwb_change);
				if(!strstr(actionScript, "restart_wireless")) {
					if (strlen(actionScript) == 0)
						strncpy(actionScript, "restart_wireless", sizeof(actionScript));
					else
						strcat(actionScript, ";restart_wireless");
				}
			} else {  // DWB STA config changed. Trigger OPT.
				DBG_INFO("DWB: dwb_change = %d, add trigger_opt to actionScript.", dwb_change);
				if(!strstr(actionScript, "restart_wireless") && !strstr(actionScript, "trigger_opt")) {
					if (strlen(actionScript) == 0)
						strncpy(actionScript, "trigger_opt", sizeof(actionScript));
					else
						strcat(actionScript, ";trigger_opt");
				}
			}
#else
			DBG_INFO("DWB: dwb_change = %d, add restart_wireless to actionScript.", dwb_change);
			if(!strstr(actionScript, "restart_wireless")) {
				if (strlen(actionScript) == 0)
					strncpy(actionScript, "restart_wireless", sizeof(actionScript));
				else
					strcat(actionScript, ";restart_wireless");
			}
#endif
			cfgChanged = 1;
		}
	}
#ifdef RTCONFIG_FRONTHAUL_DWB
	if (Process_DWB_Fronthaul_AP() == 1) {
		if(!strstr(actionScript, "restart_wireless")) {
			if (strlen(actionScript) == 0)
				strncpy(actionScript, "restart_wireless", sizeof(actionScript));
			else
				strcat(actionScript, ";restart_wireless");
		}
		cfgChanged = 1;
	}
#endif
#endif
	if (cfgbandVer != NULL && cfgband_Ver<2) {
		DBG_INFO("#### cfgbandType_num = %d", cfgbandType_num);
		if (nvram_get_int("band_type")>2)
		{
			if (cfgbandType_num<16){
				DBG_INFO("#### cfgbandType_num = %d <16", cfgbandType_num);
				char fix_6G_ssid[64]={0},fix_6G_ssid_Param[64]={0},fix_6G_radio_Param[64]={0};
				char fix_5Glow_ssid_Param[64]={0};
				int fix_6G_ssid_len=0;
				memset(fix_6G_ssid, 0, sizeof(fix_6G_ssid));
				memset(fix_6G_ssid_Param, 0, sizeof(fix_6G_ssid_Param));
				memset(fix_6G_radio_Param, 0, sizeof(fix_6G_radio_Param));
				memset(fix_5Glow_ssid_Param, 0, sizeof(fix_5Glow_ssid_Param));
				char fix_6G[64]={0}, fix_6G_tmp[64]={0};
				memset(fix_6G, 0, sizeof(fix_6G));
				memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));

				snprintf(fix_6G_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(6));
				snprintf(fix_6G_ssid, strlen(nvram_safe_get(fix_6G_ssid_Param))+1, "%s", nvram_safe_get(fix_6G_ssid_Param));
				snprintf(fix_6G_radio_Param, 13, "wl%d.1_closed", check_own_unit(6));
				snprintf(fix_5Glow_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(2));
				
				if(!strcmp("1",nvram_safe_get(fix_6G_radio_Param))){
					nvram_set(fix_6G_radio_Param, "0");
				}
				if(cfgbandType_num<=13){
					if (nvram_get_int("dwb_mode")){
						fix_6G_ssid_len=strlen(fix_6G_ssid)-4;
					}
					else{
						fix_6G_ssid_len=strlen(fix_6G_ssid);
					}
					if(!strncmp(fix_6G_ssid,nvram_safe_get(fix_5Glow_ssid_Param),fix_6G_ssid_len)){
						if (nvram_get_int("dwb_mode")){	
								snprintf(fix_6G, sizeof(fix_6G)-1, "%s_6G_dwb", nvram_safe_get(fix_5Glow_ssid_Param));
						}
						else
						{
							snprintf(fix_6G, sizeof(fix_6G)-1, "%s_6G", nvram_safe_get(fix_5Glow_ssid_Param));
						}
						nvram_set(fix_6G_ssid_Param, fix_6G);
					}else{
						if (nvram_get_int("dwb_mode")){
							if(strstr(nvram_safe_get(fix_6G_ssid_Param),"_6G_dwb")){
								memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
								snprintf(fix_6G_tmp, strlen(fix_6G_tmp)-6, "%s", nvram_safe_get(fix_6G_ssid_Param));
								if(strcmp(fix_6G_tmp,nvram_safe_get(fix_5Glow_ssid_Param))){
									memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
									snprintf(fix_6G_tmp, sizeof(fix_6G_tmp)-1, "%s_6G_dwb", nvram_safe_get(fix_5Glow_ssid_Param));
									nvram_set(fix_6G_ssid_Param, fix_6G_tmp);
								}
							}
							else if(strstr(nvram_safe_get(fix_6G_ssid_Param),"_dwb")&&!strstr(nvram_safe_get(fix_6G_ssid_Param),"_6G_dwb")){
									memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
									snprintf(fix_6G_tmp, strlen(fix_6G_tmp)-3, "%s", nvram_safe_get(fix_6G_ssid_Param));
									if(strcmp(fix_6G_tmp,nvram_safe_get(fix_5Glow_ssid_Param))){
										memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
										snprintf(fix_6G_tmp, sizeof(fix_6G_tmp)-1, "%s_6G_dwb", nvram_safe_get(fix_5Glow_ssid_Param));
										nvram_set(fix_6G_ssid_Param, fix_6G_tmp);
									}
							}
							else
							{
								memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
								snprintf(fix_6G_tmp, sizeof(fix_6G_tmp)-1, "%s_6G_dwb", nvram_safe_get(fix_5Glow_ssid_Param));
								nvram_set(fix_6G_ssid_Param, fix_6G_tmp);
							}
							
						}else{
							if(strstr(nvram_safe_get(fix_6G_ssid_Param),"_6G")){
								memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
								snprintf(fix_6G_tmp, strlen(fix_6G_tmp)-2, "%s", nvram_safe_get(fix_6G_ssid_Param));
								if(strcmp(fix_6G_tmp,nvram_safe_get(fix_5Glow_ssid_Param))){
									memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
									snprintf(fix_6G_tmp, sizeof(fix_6G_tmp)-1, "%s_6G", nvram_safe_get(fix_5Glow_ssid_Param));
									nvram_set(fix_6G_ssid_Param, fix_6G_tmp);
								}
							}
							else
							{
								memset(fix_6G_tmp, 0, sizeof(fix_6G_tmp));
									snprintf(fix_6G_tmp, sizeof(fix_6G_tmp)-1, "%s_6G", nvram_safe_get(fix_5Glow_ssid_Param));
									nvram_set(fix_6G_ssid_Param, fix_6G_tmp);
							}
						}
					}
					if(nvram_get_int("band_type")>3 && cfgbandType_num<13)
					{
						char fix_5GH_ssid[64]={0}, fix_5GH_ssid_Param[64]={0}, now_5GL_ssid[64]={0}, fix_5GL_radio_Param[64]={0},fix_5GH_radio_Param[64]={0};
						char fix_5Glow_ssid_Param[64]={0};
						memset(now_5GL_ssid, 0, sizeof(now_5GL_ssid));
						memset(fix_5GH_ssid, 0, sizeof(fix_5GH_ssid));
						memset(fix_5GH_ssid_Param, 0, sizeof(fix_5GH_ssid_Param));
						memset(fix_5GL_radio_Param, 0, sizeof(fix_5GL_radio_Param));
						memset(fix_5GH_radio_Param, 0, sizeof(fix_5GH_radio_Param));
						snprintf(fix_5Glow_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(2));
			
						snprintf(fix_5GH_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(3));
						snprintf(now_5GL_ssid, sizeof(now_5GL_ssid)-1, "%s", nvram_safe_get(fix_5Glow_ssid_Param));
						snprintf(fix_5GL_radio_Param, 13, "wl%d.1_closed", check_own_unit(2));
						snprintf(fix_5GH_radio_Param, 13, "wl%d.1_closed", check_own_unit(3));
						if(nvram_get_int("dwb_mode") && (check_own_unit(3) == nvram_get_int("dwb_band"))){
								nvram_set_int(fix_5GH_radio_Param, 1);
							
						}
						else{
							if(strcmp(nvram_safe_get(fix_5GL_radio_Param),nvram_safe_get(fix_5GH_radio_Param))){
								nvram_set(fix_5GH_radio_Param, nvram_safe_get(fix_5GL_radio_Param));
							}
						}
					
						if (nvram_get_int("dwb_mode")){
						snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s_dwb", now_5GL_ssid);
						}
						else{
							snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s", now_5GL_ssid);
						}
						if(strcmp(fix_5GH_ssid,nvram_safe_get(fix_5GH_ssid_Param)))
						{
								nvram_set(fix_5GH_ssid_Param, fix_5GH_ssid);
						}
					
					}
				}
			}
			if (cfgbandType_num==19 && nvram_get_int("band_type")==4){
				char fix_5GH_ssid[64]={0}, fix_5GH_ssid_Param[64]={0}, now_5GL_ssid[64]={0}, fix_5GL_radio_Param[64]={0},fix_5GH_radio_Param[64]={0};
				char fix_5Glow_ssid_Param[64]={0};
				memset(now_5GL_ssid, 0, sizeof(now_5GL_ssid));
				memset(fix_5GH_ssid, 0, sizeof(fix_5GH_ssid));
				memset(fix_5GH_ssid_Param, 0, sizeof(fix_5GH_ssid_Param));
				memset(fix_5GL_radio_Param, 0, sizeof(fix_5GL_radio_Param));
				memset(fix_5GH_radio_Param, 0, sizeof(fix_5GH_radio_Param));
				snprintf(fix_5Glow_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(2));
	
				snprintf(fix_5GH_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(3));
				snprintf(now_5GL_ssid, sizeof(now_5GL_ssid)-1, "%s", nvram_safe_get(fix_5Glow_ssid_Param));
				snprintf(fix_5GL_radio_Param, 13, "wl%d.1_closed", check_own_unit(2));
				snprintf(fix_5GH_radio_Param, 13, "wl%d.1_closed", check_own_unit(3));
				if(nvram_get_int("dwb_mode") && (check_own_unit(3) == nvram_get_int("dwb_band")))
				{
					nvram_set_int(fix_5GH_radio_Param, 1);
				}
				else{
					if(strcmp(nvram_safe_get(fix_5GL_radio_Param),nvram_safe_get(fix_5GH_radio_Param))){
						nvram_set(fix_5GH_radio_Param, nvram_safe_get(fix_5GL_radio_Param));
					}
				}
				if (nvram_get_int("dwb_mode")){
					snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s_dwb", now_5GL_ssid);
				}
				else{
					snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s", now_5GL_ssid);
				}
				if(strcmp(fix_5GH_ssid,nvram_safe_get(fix_5GH_ssid_Param)))
				{
						nvram_set(fix_5GH_ssid_Param, fix_5GH_ssid);
				}
			
			}
		}
		else if ((nvram_get_int("band_type")==2) && (cfgbandType_num==19)){
			char fix_5GH_ssid[64]={0}, fix_5GH_ssid_Param[64]={0}, now_5GL_ssid[64]={0}, fix_5GL_radio_Param[64]={0}, fix_5GH_radio_Param[64]={0};
			char fix_5Glow_ssid_Param[64]={0};
			memset(now_5GL_ssid, 0, sizeof(now_5GL_ssid));
			memset(fix_5GH_ssid, 0, sizeof(fix_5GH_ssid));
			memset(fix_5GH_ssid_Param, 0, sizeof(fix_5GH_ssid_Param));
			memset(fix_5GL_radio_Param, 0, sizeof(fix_5GL_radio_Param));
			memset(fix_5GH_radio_Param, 0, sizeof(fix_5GH_radio_Param));
			snprintf(fix_5Glow_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(2));
			
			snprintf(fix_5GH_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(3));
			snprintf(now_5GL_ssid, sizeof(now_5GL_ssid)-1, "%s", nvram_safe_get(fix_5Glow_ssid_Param));
			snprintf(fix_5GL_radio_Param, 13, "wl%d.1_closed", check_own_unit(2));
			snprintf(fix_5GH_radio_Param, 13, "wl%d.1_closed", check_own_unit(3));
			if(nvram_get_int("dwb_mode") && (check_own_unit(3) == nvram_get_int("dwb_band")))
			{
				nvram_set_int(fix_5GH_radio_Param, 1);
			}
			else{
				if(strcmp(nvram_safe_get(fix_5GL_radio_Param),nvram_safe_get(fix_5GH_radio_Param))){
					nvram_set(fix_5GH_radio_Param, nvram_safe_get(fix_5GL_radio_Param));
				}
			}
			
			if (nvram_get_int("dwb_mode")){
				snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s_dwb", now_5GL_ssid);
			}
			else{
				snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s", now_5GL_ssid);
			}
			if(strcmp(fix_5GH_ssid,nvram_safe_get(fix_5GH_ssid_Param)))
			{
					nvram_set(fix_5GH_ssid_Param, fix_5GH_ssid);
			}	
		}
	}
	else if (cfgbandVer != NULL && cfgband_Ver>1) {
		if ((cfgbandType_num==3||cfgbandType_num==19) && (nvram_get_int("band_type")==2 || nvram_get_int("band_type")==4))
		{
			char fix_5GH_ssid[64]={0}, fix_5GH_ssid_Param[64]={0}, now_5GL_ssid[64]={0}, fix_5GL_radio_Param[64]={0}, fix_5GH_radio_Param[64]={0};
			char fix_5Glow_ssid_Param[64]={0};
			memset(now_5GL_ssid, 0, sizeof(now_5GL_ssid));
			memset(fix_5GH_ssid, 0, sizeof(fix_5GH_ssid));
			memset(fix_5GH_ssid_Param, 0, sizeof(fix_5GH_ssid_Param));
			memset(fix_5GL_radio_Param, 0, sizeof(fix_5GL_radio_Param));
			memset(fix_5GH_radio_Param, 0, sizeof(fix_5GH_radio_Param));
			snprintf(fix_5Glow_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(2));
			
			snprintf(fix_5GH_ssid_Param, 11, "wl%d.1_ssid", check_own_unit(3));
			snprintf(now_5GL_ssid, sizeof(now_5GL_ssid)-1, "%s", nvram_safe_get(fix_5Glow_ssid_Param));
			snprintf(fix_5GL_radio_Param, 13, "wl%d.1_closed", check_own_unit(2));
			snprintf(fix_5GH_radio_Param, 13, "wl%d.1_closed", check_own_unit(3));
			
			if(nvram_get_int("dwb_mode") && (check_own_unit(3) == nvram_get_int("dwb_band")))
			{
				nvram_set_int(fix_5GH_radio_Param, 1);
			}else{
				if(strcmp(nvram_safe_get(fix_5GL_radio_Param),nvram_safe_get(fix_5GH_radio_Param))){
					nvram_set(fix_5GH_radio_Param, nvram_safe_get(fix_5GL_radio_Param));
				}
			}
			
			if (nvram_get_int("dwb_mode")){
				snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s_dwb", now_5GL_ssid);
			}
			else{
				snprintf(fix_5GH_ssid, sizeof(fix_5GH_ssid)-1, "%s", now_5GL_ssid);
			}
			if(strcmp(fix_5GH_ssid,nvram_safe_get(fix_5GH_ssid_Param)))
			{
					nvram_set(fix_5GH_ssid_Param, fix_5GH_ssid);
			}
		
		}
	}
#ifdef RTCONFIG_AMAS_WGN
	json_object_object_get_ex(cfgRoot, CFG_STR_WGN_WLOFF_VIFS, &cfgWLOffVifsObj);
	if (cfgWLOffVifsObj && (wloff_vifs = json_object_get_string(cfgWLOffVifsObj)))
	{
		foreach(word, wloff_vifs, next)
		{
			unit = subunit = -1;
			if (!mapping_guest_unit(cfgRoot, word, &unit, &subunit))
				continue;

			if (unit < 0 || subunit < 1)
				continue;

			memset(str, 0, sizeof(str));
			snprintf(str, sizeof(str), "wl%d.%d_bss_enabled", unit, subunit);
			nvram_set_int(str, 0);
			cfgChanged = 1;

			memset(str, 0, sizeof(str));
			snprintf(str, sizeof(str), "wl%d.%d_ifname", unit, subunit);
			memset(tmp, 0, sizeof(tmp));
			strlcpy(tmp, nvram_safe_get(str), sizeof(tmp));

#ifdef CONFIG_BCMWL5
			eval("wl", "-i", tmp, "closed", "1");
			eval("wl", "-i", tmp, "bss_maxassoc", "1");
			eval("wl", "-i", tmp, "bss", "down");
#endif
			eval("ifconfig", tmp, "down");
		}
	}
#if defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)
	DBG_ERR("wgn status of RE:%d/%d\n", nvram_match("re_mode", "1"), is_wgn_enabled());
	if(nvram_match("re_mode", "1")) {
		if(is_wgn_enabled()) {
			if(nvram_match("ctf_disable", "0")){
				nvram_set("ctf_disable", "1");
				nvram_commit();
				syslog(LOG_NOTICE,"need to reboot due ctf-change(->disable)\n");
				//kill(1, SIGTERM);
                if (!strstr(actionScript, "reboot")) {
                    if (strlen(actionScript) == 0)
                        strncpy(actionScript, "reboot", sizeof(actionScript));
                    else
                        strcat(actionScript, ";reboot");
                }
			}
		} else {	// wgn disabled
			if(nvram_match("ctf_disable", "1") && !nvram_match("ctf_disable_force", "1")){
				nvram_set("ctf_disable", "0");
				nvram_commit();
				//syslog(LOG_NOTICE,"need to reboot due ctf-change(->enable)\n");
				//kill(1, SIGTERM);
			}
		}
	}

#endif	// defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)

	// qos
	if (nvram_get_int("re_mode") == 1) {
		qos_enable = (check_wl_guest_bw_enable() == 1 && nvram_get_int("qos_type") == 2 && nvram_get_int("qos_enable") == 1) ? 1 : 0;
		if (nvram_get_int("qos_enable") != qos_enable) {
			nvram_set_int("qos_enable", qos_enable);
			nvram_commit();
			cfgChanged = 1;
			DBG_INFO("nvram set qos_enable=%d", qos_enable);

            if (!strstr(actionScript, "restart_qos")) {
                if (strlen(actionScript) == 0)
                    strncpy(actionScript, "restart_qos", sizeof(actionScript));
                else
                    strcat(actionScript, ";restart_qos");
			}

            if (!strstr(actionScript, "restart_firewall")) {
                if (strlen(actionScript) == 0)
                    strncpy(actionScript, "restart_firewall", sizeof(actionScript));
                else
                    strcat(actionScript, ";restart_firewall");
			}
		}
	}
#endif	// RTCONFIG_AMAS_WGN	

#if defined(RTCONFIG_TCODE) && defined(RTCONFIG_CFGSYNC_LOCSYNC)
    if (nvram_contains_word("rc_support", "loclist")) {
        int location_change = 0;
        cm_Set_location_code(cfgRoot, &location_change);
        DBG_INFO("Location Code: location_change = %d.\n", location_change);
        if (location_change > 0) {
            cfgChanged = 1;
            if (location_change == 2) {
                if(!strstr(actionScript, "reboot")) {
                    if (strlen(actionScript) == 0)
                        strncpy(actionScript, "reboot", sizeof(actionScript));
                    else
                        strcat(actionScript, ";reboot");
                }
            }
        }
    }
#endif

	if (doAction)
		unlink(CFG_JSON_FILE);
	else
	{
		if (strlen(actionScript)) {
			json_object_object_add(cfgRoot, CFG_ACTION_SCRIPT,
				json_object_new_string(actionScript));
			json_object_to_file(CFG_JSON_FILE, cfgRoot);
		}
	}

	json_object_put(cfgRoot);
	if (nvram_get_int("cfg_first_sync") == 1)
		nvram_unset("cfg_first_sync");

	if (cfgChanged) {
		nvram_commit();

		remove_extra_actions(actionScript, sizeof(actionScript));

		if (strlen(actionScript) && doAction) {
			notify_rc(actionScript);
#if defined(SYNC_WCHANNEL)
			if (strstr(actionScript, "restart_wireless"))
				syncChannel = 1;
#endif
			DBG_INFO("notify (%s)", actionScript);
		}
	}
	else {
		DBG_INFO("");
	}

	if (doAction) {
		notifiedCfg = 0;
		nvram_unset("cfg_sync_stage");
	}

	DBG_INFO("leave");
} /* End of cm_applyCfgAction */

/*
========================================================================
Routine Description:
	Handle feedback notification.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_handleFeedback(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_foreach(decryptedRoot, key, val) {
		nvram_set(key, json_object_get_string(val));
	}

	json_object_put(decryptedRoot);

	notify_rc("restart_sendfeedback");
} /* End of cm_handleFeedback */

#ifdef RTCONFIG_BHCOST_OPT
/*
========================================================================
Routine Description:
	Trigger self optimization.

Arguments:
	None

Return Value:
	None

========================================================================
*/
static void cm_triggerSelfOptimization()
{
	int unit = 0;
	char prefix[16], tmp[64], word[64], *next;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(unit));

		/* set amas_wlcX_optmz for trigger self optimization */
		nvram_set_int(strcat_r(prefix, "optmz", tmp), OPTMZ_FROM_CAP);
		unit++;
	}
} /* End of cm_triggerSelfOptimization */
#endif /* RTCONFIG_BHCOST_OPT */

#ifdef STA_BIND_AP
/*
========================================================================
Routine Description:
	Update sta binding list.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_updateStaBindingList(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = NULL, *bindingListObj = NULL;

	decryptedRoot = json_tokener_parse((char *)decryptedMsg);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STA_BINDING_LIST, &bindingListObj);
	if (bindingListObj) {
		if (strcmp(nvram_safe_get("sta_binding_list"), (char *)json_object_get_string(bindingListObj)) !=0) {
			DBG_INFO("sta binding list is changed, update it");
			nvram_set("sta_binding_list", (char *)json_object_get_string(bindingListObj));
			notify_rc(UPDATE_STA_BINDING);
		}
	}

	json_object_put(decryptedRoot);
} /* End of cm_updateStaBindingList */
#endif /* STA_BIND_AP */

/*
========================================================================
Routine Description:
	Select session key.

Arguments:
	keyIndex		- key index for no expired (1) and expired (0)

Return Value:
	session key

========================================================================
*/
static unsigned char *cm_selectSessionKey(int keyIndex)
{
	int sKeyTime = (int) (uptime() - cm_ctrlBlock.sessionKeyStartTime);
	int sKey1Time = (int) (uptime() - cm_ctrlBlock.sessionKey1StartTime);

	DBG_INFO("sKeyTime(%d), sKey1Time(%d), sessionKeyExpireTime(%d), rekeyTime(%d)",
				sKeyTime, sKey1Time , sessionKeyExpireTime, REKEY_TIME(sessionKeyExpireTime));

	if (sKeyTime > sessionKeyExpireTime) {
		DBG_INFO("sKeyTime > sessionKeyExpireTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? cm_ctrlBlock.sessionKey1 : cm_ctrlBlock.sessionKey);
	}

	if (sKey1Time > sessionKeyExpireTime) {
		DBG_INFO("sKeyTime > sessionKeyExpireTime, select %s", keyIndex ? "key" : "key1");
		return (keyIndex ? cm_ctrlBlock.sessionKey : cm_ctrlBlock.sessionKey1);
	}

	if (cm_ctrlBlock.sessionKeyStartTime >= cm_ctrlBlock.sessionKey1StartTime) {
		DBG_INFO("sessionKeyStartTime >= sessionKey1StartTime, select %s", keyIndex ? "key" : "key1");
		return (keyIndex ? cm_ctrlBlock.sessionKey : cm_ctrlBlock.sessionKey1);
	}
	else
	{
		DBG_INFO("sessionKey1StartTime > sessionKeyStartTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? cm_ctrlBlock.sessionKey1 : cm_ctrlBlock.sessionKey);
	}
} /* End of cm_selectSessionKey*/

/*
========================================================================
Routine Description:
	Select group key.

Arguments:
	keyIndex		- key index for no expired (1) and expired (0)

Return Value:
	group key

========================================================================
*/
unsigned char *cm_selectGroupKey(int keyIndex)
{
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	DBG_INFO("gKeyTime(%d), gKey1Time(%d), groupKeyExpireTime(%d), rekeyTime(%d)",
				gKeyTime, gKey1Time , groupKeyExpireTime, REKEY_TIME(groupKeyExpireTime));

	if (gKeyTime > groupKeyExpireTime) {
		DBG_INFO("gKeyTime > groupKeyExpireTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? cm_ctrlBlock.groupKey1 : cm_ctrlBlock.groupKey);
	}

	if (gKey1Time > groupKeyExpireTime) {
		DBG_INFO("gKeyTime > groupKeyExpireTime, select %s", keyIndex ? "key" : "key1");
		return (keyIndex ? cm_ctrlBlock.groupKey : cm_ctrlBlock.groupKey1);
	}

	if (cm_ctrlBlock.groupKeyStartTime >= cm_ctrlBlock.groupKey1StartTime) {
		DBG_INFO("groupKeyStartTime >= groupKey1StartTime, select %s", keyIndex ? "key" : "key1");
		return (keyIndex ? cm_ctrlBlock.groupKey : cm_ctrlBlock.groupKey1);
	}
	else
	{
		DBG_INFO("groupKey1StartTime > groupKeyStartTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? cm_ctrlBlock.groupKey1 : cm_ctrlBlock.groupKey);
	}
} /* End of cm_selectGroupKey*/

/*
========================================================================
Routine Description:
	Check can or can not do periodic action

Arguments:
	None

Return Value:
	0		- can not do periodic action
	1		- can do periodic action

========================================================================
*/
static int cm_checkStateForPeriodicAction()
{
	if (curState >= INIT && curState <= PENDING)
		return 0;
	return 1;
} /* End of cm_checkStateForPeriodicAction*/

/*
========================================================================
Routine Description:
	Check the config changed or not.

Arguments:
	all		- get all cofnig to check

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_checkCfgState(int all)
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *sessionKey = NULL;

	// reset the information for notify while state enter periodic check
	if (curState == PERCHECK) {
		if(f_exists(CFG_JSON_FILE))
			return ret;
	}

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("Connect to %s:%d - OK", serverIp, serverPort);

	if (cm_prepareCheckMsg((char *)&pPktBuf[0], MAX_MESSAGE_SIZE, all, 1) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, REQ_CHK, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(REQ_CHK);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen =  sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encLen) <= 0) {
		DBG_ERR("ERROR: %s , errno %d", strerror(errno), errno);
		goto err;
	}
	DBG_INFO("Send REQ_CHK to server - OK");

	MFREE(encryptedMsg);

	while (1)
	{
		memset(pPktBuf, 0, sizeof(pPktBuf));
		if ((len = read_tcp_message(sock, &pPktBuf[0], sizeof(pPktBuf))) <= 0) {
			DBG_ERR("Failed to read_tcp_message()!");
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				if (curState != CONN)
					cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

	/* apply cfg for periodic check */
	if (!notifiedCfg)
		cm_applyCfgAction(1);

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_checkCfgState */

/*
========================================================================
Routine Description:
	Ask the group key.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_askGroupKey()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char pPktBuf[MAX_PACKET_SIZE];
	int ret = 0;
	int len = 0;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	memset(&tlv, 0, sizeof(TLV_Header));
	tlv.type = htonl(REQ_GKEY);
	if (write(sock, (char*)&tlv, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("ERROR: %s, errno %d", strerror(errno), errno);
		goto err;
	}

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s, errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				if (curState != CONN)
					cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_askGroupKey */

/*
========================================================================
Routine Description:
	Request  the session rekey.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_requestSessionReKey()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char pPktBuf[MAX_PACKET_SIZE];
	int ret = 0;
	int len = 0;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	memset(&tlv, 0, sizeof(TLV_Header));
	tlv.type = htonl(REQ_SREKEY);
	if (write(sock, (char*)&tlv, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("ERROR: %s, errno %d", strerror(errno), errno);
		goto err;
	}

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s, errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_requestSessionReKey */

/*
========================================================================
Routine Description:
	Request  the group rekey.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_requestGroupReKey()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char pPktBuf[MAX_PACKET_SIZE];
	int ret = 0;
	int len = 0;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	memset(&tlv, 0, sizeof(TLV_Header));
	tlv.type = htonl(REQ_GREKEY);
	if (write(sock, (char*)&tlv, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("ERROR: %s, errno %d", strerror(errno), errno);
		goto err;
	}

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s, errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_requestGroupReKey */

/*
========================================================================
Routine Description:
	Handle to retransmit report data.

Arguments:
	reportIndex	- the index of report type

Return Value:
	None

========================================================================
*/
void cm_handleReportDataRetransmission(unsigned int reportIndex)
{
	/* check for chanspec */
	if ((BIT_SHIFT_RIGHT(reportIndex, REPORT_TYPE_CHANSPEC) & 0x1)) {
		DBG_INFO("reset private chanspec");
		cm_resetChanspec();
	}
} /* End of cm_handleReportDataRetransmission */

/*
========================================================================
Routine Description:
	Report dut's connection status.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_reportConnStatus(void)
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	int len = 0;
	unsigned char *sessionKey = NULL;
	unsigned int reportIndex = 0;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
		cm_judgeDisconnection();
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
		cm_judgeDisconnection();
		goto err;
	}
	DBG_INFO("OK");

	if (cm_prepareReportMsg((char *)&pPktBuf[0], MAX_MESSAGE_SIZE, &reportIndex) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, REQ_RPT, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);

		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(REQ_RPT);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen = sizeof(TLV_Header);
	}

	DBG_INFO("Send REQ_RPT to server ...");
	if (write(sock, (char*)encryptedMsg, encLen) <= 0) {
		DBG_ERR("ERROR: %s , errno %d", strerror(errno), errno);
		MFREE(encryptedMsg);
		goto err;
	}
	DBG_INFO("OK");

	MFREE(encryptedMsg);

	while (1)
	{
		memset(pPktBuf, 0, sizeof(pPktBuf));
		if ((len = read_tcp_message(sock, &pPktBuf[0], sizeof(pPktBuf))) <= 0) {
			DBG_ERR("Failed to read_tcp_message()!");
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
				if (curState != CONN)
					cm_judgeDisconnection();
			}
			break;
		}
	}

	if (ret == 1)
		cm_cleanDisconnection();

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_reportConnStatus */

/*
========================================================================
Routine Description:
	Report dut's wireless event.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_reportWirelessEvent()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *sessionKey = NULL;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// check file exist or not
	if (fileExists(WCLIENT_LIST_JSON_PATH) == 0)
		return 0;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	// check have the content of wireless event
	pthread_mutex_lock(&weventLock);
	if (cm_prepareWeventMsg((char *)&pPktBuf[0], MAX_MESSAGE_SIZE) == 0) {
		//DBG_INFO("no contenet of wireless event");
		goto err;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	if (strlen((char *)&pPktBuf[0]) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, REQ_WEVENT, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(REQ_WEVENT);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen = sizeof(TLV_Header);
	}

	DBG_INFO("Send REQ_WEVENT to server ...");
	if (write(sock, (char*)encryptedMsg, encLen) <= 0) {
		DBG_ERR("ERROR: %s , errno %d", strerror(errno), errno);
		MFREE(encryptedMsg);
		goto err;
	}
	DBG_INFO("OK");

	MFREE(encryptedMsg);

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s , errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				cm_judgeDisconnection();
#endif
			}

			if (ret == 1)
				unlink(WCLIENT_LIST_JSON_PATH);
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	pthread_mutex_unlock(&weventLock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_reportWirelessEvent */

#if 0// defined(SYNC_WCHANNEL)
/*
========================================================================
Routine Description:
	Ask the information of wireless channel.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_requestWirelessChannel()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char pPktBuf[MAX_PACKET_SIZE];
	int ret = 0;
	int len = 0;

	if (!syncChannel)
		return ret;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	tlv.type = htonl(REQ_CHANSYNC);
	if (write(sock, (char*)&tlv, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("ERROR: %s , errno %d", strerror(errno), errno);
		goto err;
	}

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s , errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {  	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	/* based on typeIndex to retransmit report data */
	DBG_INFO("the index of report data (0x%02X)", reportIndex);
	if (ret == 0)
		cm_handleReportDataRetransmission(reportIndex);

	DBG_INFO("leave");

	return ret;
} /* End of cm_requestWirelessChannel */
#endif	/* SYNC_WCHANNEL */

/*
========================================================================
Routine Description:
	Report dut's sta list.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_reportStaList()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *sessionKey = NULL;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	// check have the content of wireless event
	if (cm_prepareStaListMsg((char *)&pPktBuf[0], MAX_MESSAGE_SIZE) == 0) {
		DBG_INFO("no contenet of sta list");
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	if (strlen((char *)&pPktBuf[0]) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, REQ_STALIST, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(REQ_STALIST);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen = sizeof(TLV_Header);
	}

	DBG_INFO("Send REQ_STALIST to server ...");
	if (write(sock, (char*)encryptedMsg, encLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");
	DBG_INFO("OK");

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s , errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {  	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				if (curState != CONN)
					cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");
	return ret;

} /* End of cm_reportStaList */

/*
========================================================================
Routine Description:
	Report dut's all client list.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_reportClientList()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *sessionKey = NULL;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	// check have the content of wireless event
	if (cm_prepareClientListMsg((char *)&pPktBuf[0], MAX_MESSAGE_SIZE) == 0) {
		DBG_INFO("no contenet of sta list");
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	if (strlen((char *)&pPktBuf[0]) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, REQ_CLIENTLIST, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(REQ_CLIENTLIST);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen = sizeof(TLV_Header);
	}

	DBG_INFO("Send REQ_CLIENTLIST to server ...");
	if (write(sock, (char*)encryptedMsg, encLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");
	DBG_INFO("OK");

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s , errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {  	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");
	return ret;

} /* End of cm_reportStaList */

#ifdef RTCONFIG_FRONTHAUL_DWB
static int cm_requestBackhualStatus()
{
	unsigned char msg[512] = {0};

	snprintf((char *)msg, sizeof(msg), "{\"%s\":\"%s\"}", CFG_STR_MAC, get_unique_mac());

	if (cm_sendTcpPacket(REQ_BACKHUALSTATUS, &msg[0]) == 0) {
		DBG_ERR("Fail to send TCP packet!");
		return 0;
	}

	return 1;
}
#endif

/*
========================================================================
Routine Description:
	Request the cost of network topology.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_requestNetworkCost()
{
	unsigned char msg[512] = {0};
#ifdef RTCONFIG_BHCOST_OPT
	// if the aimesh select backhaul path algorithm is cost. don't need to get cost from CAP.
	int aimesh_alg = nvram_get_int("aimesh_alg") ?: AIMESH_ALG_COST;
	if (aimesh_alg == AIMESH_ALG_COST)
		return 0;
#endif

	snprintf((char *)msg, sizeof(msg), "{\"%s\":\"%s\"}", CFG_STR_MAC, get_unique_mac());

	if (cm_sendTcpPacket(REQ_COST, &msg[0]) == 0) {
		DBG_ERR("Fail to send TCP packet!");
		return 0;
	}

	return 1;
} /* End of cm_requestNetworkCost */

/*
========================================================================
Routine Description:
	Request the level of network topology.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_requestNetworkLevel()
{
	unsigned char msg[512] = {0};

	snprintf((char *)msg, sizeof(msg), "{\"%s\":\"%s\"}", CFG_STR_MAC, get_unique_mac());

	if (cm_sendTcpPacket(REQ_LEVEL, &msg[0]) == 0) {
		DBG_ERR("Fail to send TCP packet!");
		return 0;
	}

	return 1;
} /* End of cm_requestNetworkLevel */

/*
========================================================================
Routine Description:
	Request network topology.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_requestTopology(void)
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	int ret = 0;
	int len = 0;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}
	DBG_INFO("OK");

	memset(&tlv, 0, sizeof(TLV_Header));
	tlv.type = htonl(REQ_TOPOLOGY);
	if (write(sock, (char*)&tlv, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("ERROR: %s, errno %d", strerror(errno), errno);
		goto err;
	}

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s, errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_requestTopology */

/*
========================================================================
Routine Description:
	Request RE list.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_requestReList(void)
{
#ifdef RTCONFIG_BCN_RPT
	cm_sendTcpPacket(REQ_APLIST, NULL);
#endif
	return cm_sendTcpPacket(REQ_RELIST, NULL);
} /* End of cm_requestReList */

/*
========================================================================
Routine Description:
	Update wired client list.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_udpateWiredClientList(void)
{
	json_object *wiredClientList = NULL;

	if ((wiredClientList = json_object_new_array()) != NULL) {
		cm_needUpdateWiredClientlLst(wiredClientList);
		json_object_put(wiredClientList);
	}
} /* End of cm_udpateWiredClientList */

#ifdef DUAL_BAND_DETECTION
/*
========================================================================
Routine Description:
	Request dual band list.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_requestDualBandList(void)
{
	return cm_sendTcpPacket(REQ_DBLIST, NULL);
} /* End of cm_requestDualBandList */
#endif

/*
========================================================================
Routine Description:
	Send TCP packet to server.

Arguments:
	pktType		- packet for request type
	*msg		- message need to be sent out

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendTcpPacket(int pktType, unsigned char *msg)
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *sessionKey = NULL;

	// return when curState is INIT or REKEY
	if (!cm_checkStateForPeriodicAction())
		return ret;

	// return when session key is expired
	if (cm_checkSessionKeyExpire()) {
		DBG_INFO("session key expired and rekey");
		curState = REKEY;
		return ret;
	}

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* copy msg to pPktBuf */
	if (msg && strlen((char *)msg))
		snprintf((char *)pPktBuf, MAX_MESSAGE_SIZE, "%s", (char *)msg);

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
		cm_judgeDisconnection();
#endif
		goto err;
	}

	if (strlen((char *)&pPktBuf[0]) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, pktType, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(pktType);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		if (encryptedMsg) {
			memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
			encLen = sizeof(TLV_Header);
		}
		else
		{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}

	DBG_INFO("Send packet (%d) to server ...", pktType);
	if (write(sock, (char*)encryptedMsg, encLen) <= 0) {
		DBG_ERR("Failed to socket write() !!!");
		goto err;
	}

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s, errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, NULL);
		if (ret == 1 || ret == -1) {
			if (ret == -1) {	/* abort */
				ret = 0;
#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
				if (curState != CONN)
					cm_judgeDisconnection();
#endif
			}
			break;
		}
	}

#ifndef RTCONFIG_BH_SWITCH_ETH_FIRST
	if (ret == 1)
		cm_cleanDisconnection();
#endif

err:
	MFREE(encryptedMsg);

	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");
	return ret;
} /* End of cm_sendTcpPacket */

void cm_handleFirmwareCheck()
{
	//TODO
}

void cm_handleFirmwareDownload()
{
	//TODO
}

void cm_removeSlave(char *mac)
{
	//TODO
}

void cm_resetDefault(char *mac)
{
	//TODO
}

void cm_notifyConfigChanged(char *mac)
{
	//TODO
}

void cm_feedback()
{
	//TODO
}

int cm_reExistInClientList(char *reMac)
{
	//TODO
	return 0;
}

/*
========================================================================
Routine Description:
	Config changed and will send to CAP.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_configChanged(unsigned char *data)
{
	json_object *fileRoot = NULL, *rcObj = NULL, *configObj = NULL, *root = NULL, *msgObj = NULL, *changedConfigObj = NULL;

	DBG_INFO("data (%s)", data);

	if (curState != PERCHECK) {
		DBG_INFO("status is not under PERCHECK, can't send changed config out ");
		return;
	}

	if ((root = json_tokener_parse((char *)data))) {
		json_object_object_get_ex(root, RC_PREFIX, &rcObj);
		json_object_object_get_ex(rcObj, CFG_STR_CONFIG, &configObj);

		if (configObj) {
			msgObj = json_object_new_object();
			changedConfigObj = json_object_new_object();
			if (msgObj && changedConfigObj) {
				json_object_object_add(msgObj, CFG_STR_MAC, json_object_new_string(get_unique_mac()));
				json_object_object_foreach(configObj, key, val) {
					json_object_object_add(changedConfigObj, key, json_object_new_string(json_object_get_string(val)));
				}
				json_object_object_add(msgObj, CFG_STR_CHANGED_CONFIG, changedConfigObj);

				if (cm_sendTcpPacket(REQ_CHANGED_CONFIG, (unsigned char *)json_object_to_json_string_ext(msgObj, 0)) == 0) {
					DBG_INFO("changed config can't be sent successfully, keep it at local");

					pthread_mutex_lock(&changedConfigLock);
					fileRoot = json_object_from_file(CHANGED_CFG_JSON_PATH);

					if (!fileRoot) {
						fileRoot = json_object_new_object();
						if (!fileRoot) {
							json_object_put(msgObj);
							DBG_ERR("fileRoot is NULL");
							pthread_mutex_unlock(&changedConfigLock);
							return;
						}
					}

					if (fileRoot) {
						json_object_object_foreach(configObj, key, val) {
							json_object_object_add(fileRoot, key, json_object_new_string(json_object_get_string(val)));
						}
						json_object_to_file(CHANGED_CFG_JSON_PATH, fileRoot);
					}

					json_object_put(fileRoot);
					pthread_mutex_unlock(&changedConfigLock);
				}

				json_object_put(msgObj);
			}
			else
			{
				json_object_put(msgObj);
				json_object_put(changedConfigObj);
			}
		}

		json_object_put(root);
	}
} /* End of cm_configChanged */

#ifdef RTCONFIG_BHCOST_OPT
void cm_selfOptimize(char *data)
{
	//TODO
}
#endif

#ifdef RADAR_DET
/*
========================================================================
Routine Description:
	Report available wireless channel after detecting radar.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_processRadarDetection(void)
{
	unsigned char msg[1024] = {0};
	char ch_data[256] = {0};
	json_object *root = json_object_new_object();
	json_object *chanspecObj = NULL;

	DBG_INFO("Radar Detected...");

	if( root && chmgmt_get_chan_info(ch_data, sizeof(ch_data)) > 0 )
	{
		DBG_INFO("channel information updated");

		/* unique mac */
		json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));
		/* channel */
		json_object_object_add(root, CFG_STR_CHANNEL, json_object_new_string(ch_data));
		/* supported chanspec */
		chanspecObj = json_object_new_object();
		if (chanspecObj) {
			if (cm_getChanspec(chanspecObj, 0)) {
				json_object_object_add(root, CFG_STR_CHANSPEC, chanspecObj);
				json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			}
			else
				json_object_put(chanspecObj);
		}

		snprintf((char *)msg, sizeof(msg), "%s", json_object_get_string(root));

		DBG_INFO("msg(%s)", msg);

		if (cm_sendTcpPacket(REQ_RADARDET, &msg[0]) == 0) {
			DBG_ERR("Fail to send REQ_RADARDET!");
			cm_resetChanspec();
		}
	}

	json_object_put(root);
} /* End of cm_processRadarDetection */
#endif	/* RADAR_DET */

void cm_updateFirmwareVersion(char *firmVer)
{
	//TODO
}

int cm_checkClientStatus(char *mac)
{
	//TODO
	return 0;
}

#ifdef RTCONFIG_DWB
void cm_updateDwbInfo()
{
	//TODO
}
#endif

void cm_updateDutInfo()
{
	//TODO
}

void cm_updateDutChanspecs()
{
	//TODO
}

#ifdef ONBOARDING
/*
========================================================================
Routine Description:
	Prepare the group id.

Arguments:
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareGroupId(char *msg, int msgLen)
{
	unsigned char eabuf[6] = {0};
	char macaddr[32] = {0};
	json_object *root = NULL;
#if 0
#ifdef SUPPORT_TRI_BAND
	int band5g ;
#if defined(RTCONFIG_WIFI_SON)
        if(nvram_match("wifison_ready", "1"))
		band5g = 1;
        else
#endif
		band5g = 2;	/* for 5G high */
#else
	int band5g = 1;
#endif
#endif
#ifdef PRELINK
	unsigned char bundleKeyHex[HASH_BUNDLE_KEY_HEX_LEN] = {0};
	char bundleKeyStr[HASH_BUNDLE_KEY_STR_LEN] = {0};
#endif
	int unit = 0;
	char prefix[sizeof("wlXXXXX_")], amasWlcPrefix[sizeof("amas_wlcXXXX_")], wlIfnames[64], sta[18];
	char tmp[64], word[256], *next, *staIndexStr = NULL;
	int nband = 0;

	root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return 0;
	}

	ether_atoe(get_unique_mac(), eabuf);
	ether_etoa(eabuf, macaddr);

	if (strlen(macaddr)) {
		json_object_object_add(root, CFG_STR_NEW_RE_MAC, json_object_new_string(macaddr));

		/* prepare upstream used mac for 2G  & 5G & 6G */
#if 0
		json_object_object_add(root, CFG_STR_STA2G, json_object_new_string(get_sta_mac(0)));
		json_object_object_add(root, CFG_STR_STA5G, json_object_new_string(get_sta_mac(band5g)));
#endif

		strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
		foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			snprintf(amasWlcPrefix, sizeof(amasWlcPrefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(unit));
			if (nvram_get_int(strcat_r(amasWlcPrefix, "use", tmp))) {
				staIndexStr = NULL;
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				if (nband == 2)
					staIndexStr = CFG_STR_STA2G;
				else if (nband == 1)
					staIndexStr = CFG_STR_STA5G;
				else if (nband == 4)
					staIndexStr = CFG_STR_STA6G;

				/* sta info */
				if (staIndexStr) {
					snprintf(sta, sizeof(sta), "%s", get_sta_mac(unit));
					json_object_object_add(root, staIndexStr, json_object_new_string(sta));
				}
			}

			unit++;
		}

		/* supported band number */
		json_object_object_add(root, CFG_STR_BANDNUM, json_object_new_int(supportedBandNum));

#ifdef PRELINK
		/* hash bundle key */
		if (nvram_get_int("prelink") && nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey"))) {
			if (amas_gen_hash_bundle_key(&bundleKeyHex[0]) == AMAS_RESULT_SUCCESS) {
				memset(bundleKeyStr, 0, sizeof(bundleKeyStr));
				hex2str(bundleKeyHex, &bundleKeyStr[0], sizeof(bundleKeyHex));
				json_object_object_add(root, CFG_STR_HASH_BUNDLE_KEY, json_object_new_string(bundleKeyStr));
			}
		}
#endif
	}

	snprintf(msg, msgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", msg);
	json_object_put(root);

	return strlen(msg);
} /* End of cm_prepareGroupId */


/*
========================================================================
Routine Description:
	Request the group id on onboarding status.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_requestGroupId()
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *key = NULL;
	unsigned char *keyPrelink = NULL;
	int keyType = KEY_IS_UNKNOWN;

	if (cm_prepareGroupId((char *)&pPktBuf[0], MAX_MESSAGE_SIZE) == 0) {
		DBG_INFO("no contenet");
		return ret;
	}

	DBG_INFO("enter");

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to (server)%s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
		curState = DISCONN;
		goto err;
	}
	DBG_INFO("OK");

	if (strlen((char *)&pPktBuf[0]) > 0) {
#ifdef PRELINK
		if (nvram_get_int("prelink") && nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey")) && (keyPrelink = get_prelink_key()) == NULL) {
			DBG_ERR("Prelink key failed");
		}

		if (keyPrelink) keyType = KEY_IS_PRELINK;
#endif

		if (keyType == KEY_IS_UNKNOWN) {
			if ((key = get_onboarding_key()) == NULL) {
				DBG_ERR("Onboarding key failed");
				goto err;
			}

			if (key) keyType = KEY_IS_ONBOARDING;
		}

		DBG_INFO("keyType is %d", keyType);

		encryptedMsg = cm_aesEncryptMsg((keyType == KEY_IS_PRELINK) ? keyPrelink : key,
			REQ_GROUPID, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(REQ_GROUPID);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen = sizeof(TLV_Header);
	}

	DBG_INFO("Send REQ_GROUPID to server ...");
	if (write(sock, (char*)encryptedMsg, encLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");
	DBG_INFO("OK");

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("Failed to socket read() !!!");
			break;
		}

		if (cm_packetProcess(sock, pPktBuf, len, NULL, NULL))
			break;
	}

	ret = 1;
err:
	if (sock >= 0)
		close(sock);

	MFREE(key);
	MFREE(keyPrelink);

	DBG_INFO("leave");
	return ret;
} /* End of cm_requestGroupId */

/*
========================================================================
Routine Description:
	Update the group id.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_updateGroupId(CM_CTRL *pCtrlBK, unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *idObj = NULL;
	int ret = 0;

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		goto err;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_ID, &idObj);

	if (idObj == NULL) {
		DBG_INFO("idObj is null");
		goto err;
	}

 	/* update the group id */
	nvram_set("cfg_group", json_object_get_string(idObj));

	/* unset ob key */
	if (nvram_get("cfg_obkey"))
		nvram_unset("cfg_obkey");

	/* unset ob ifname */
	if (nvram_get("cfg_obifname"))
		nvram_unset("cfg_obifname");

	/* reset amas_ethernet */
	nvram_set("amas_ethernet", "3");

	ret = 1;

err:

	json_object_put(decryptedRoot);

	return ret;
} /* End of cm_updateGroupId */

/*
========================================================================
Routine Description:
	Process RSP_GROUPID packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_GROUPID(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *key = NULL;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	int ret = 0;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	unsigned char *keyPrelink = NULL;
	int keyType = KEY_IS_UNKNOWN;

	DBG_INFO("Got RSP_GROUPID ...");

#ifdef PRELINK
	if (nvram_get_int("prelink") && nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey")) && (keyPrelink = get_prelink_key()) == NULL) {
		DBG_ERR("Prelink key failed");
		goto err;
	}
#endif

	if ((key = get_onboarding_key()) == NULL) {
		DBG_ERR("Onboarding key failed");
		goto err;
	}

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no group id.");
		goto err;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			goto err;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);

#ifdef PRELINK
		if (keyPrelink) {
			decodeMsg = cm_aesDecryptMsg(keyPrelink, keyPrelink, (unsigned char *)packetMsg, ntohl(tlv.len));
			if (IsNULL_PTR(decodeMsg))
				DBG_INFO("Failed to aes_decrypt() by keyPrelink !!!");
			else
				keyType = KEY_IS_PRELINK;
		}
#endif

		if (keyType == KEY_IS_UNKNOWN) {
			decodeMsg = cm_aesDecryptMsg(key, key, (unsigned char *)packetMsg, ntohl(tlv.len));
			if (IsNULL_PTR(decodeMsg)) {
				DBG_ERR("Failed to aes_decrypt() !!!");
				goto err;
			}
			else
				keyType = KEY_IS_ONBOARDING;
		}

		DBG_INFO("keyType is %d", keyType);

		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		if (cm_updateGroupId(pCtrlBK, decodeMsg)) {
			if (cm_prepareGroupId((char *)&pPktBuf[0], MAX_MESSAGE_SIZE) == 0) {
				DBG_ERR("no contenet");
				goto err;
			}

			if (strlen((char *)&pPktBuf[0]) > 0) {
				encryptedMsg = cm_aesEncryptMsg((keyType == KEY_IS_PRELINK) ? keyPrelink : key,
					ACK_GROUPID, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
				if (IsNULL_PTR(encryptedMsg)) 	{
					DBG_ERR("Failed to MALLOC() !!!");
					goto err;
				}
			}
			else
			{
				memset(&tlv, 0, sizeof(TLV_Header));
				tlv.type = htonl(ACK_GROUPID);
				MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
				memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
				encLen = sizeof(TLV_Header);
			}

			DBG_INFO("Send ACK_GROUPID to server ...");
			if (write(sock, (char*)encryptedMsg, encLen) <= 0)
				DBG_ERR("Failed to socket write() !!!");
			else
				nvram_commit();
#ifdef RTCONFIG_QCA_PLC2
			notify_rc("restart_plc");
#endif	/* RTCONFIG_QCA_PLC2 */
		}
		else
		{
			DBG_ERR("fail to update group id");
			goto err;
		}
	}

	ret = 1;
err:
	MFREE(decodeMsg);
	MFREE(key);
	MFREE(encryptedMsg);
	MFREE(keyPrelink);

	return ret;
} /* End of cm_processRSP_GKEY */

void cm_handleOnboarding(char *data)
{
	//TODO
}

void cm_processOnboardingMsg(char *msg)
{
	//TODO
}

int cm_validateOnboardingRe(char *reMac)
{
	//TODO
	return 0;
}
#endif	/* ONBOARDING */

void cm_startWps(char *ip)
{
	//TODO
}

#ifdef PRELINK
/*
========================================================================
Routine Description:
	Update changed hash bundle key.

Arguments:
	keyObj		- json object for key

Return Value:
	None

========================================================================
*/
void cm_updateChangedHashBundleKey(json_object *keyObj)
{
	char hashBundleKey[HASH_BUNDLE_KEY_STR_LEN] = {0};

	if (keyObj)
		strlcpy(hashBundleKey, json_object_get_string(keyObj), sizeof(hashBundleKey));

	if (strcmp(hashBundleKey, nvram_safe_get("amas_hashbdlkey")) != 0) {
		if (strlen(hashBundleKey)) {
			if (verify_hash_bundle_key(hashBundleKey))
				nvram_set("amas_hashbdlkey", hashBundleKey);
		}
		else
			nvram_unset("amas_hashbdlkey");

		DBG_INFO("hash bundle key is changed, need to update in vsie and lldp");
		update_lldp_hash_bundle_key();	/* update lldp hash bundle key */
		update_vsie_info();
	}
}	/* End of cm_updateChangedHashBundleKey */
#endif	/* PRELINK */

void cm_notifyReboot(json_object *macListObj)
{
	//TODO
}

void cm_notifyAction(int eid, json_object *macListObj, json_object *dataObj)
{
	//TODO
}

/*
========================================================================
Routine Description:
	Set current state as pending.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_setStatePending()
{
	curState = PENDING;
}	/* End of cm_setStatePending */

/*
========================================================================
Routine Description:
	Process RES_KU packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRES_KU(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *P1 = NULL;
	unsigned char *PP = NULL;
	unsigned char *PPP = NULL;
	TLV_Header packetTlvHdr;
	unsigned char encodeMsg[4098] = {0};
	size_t encodeMsgLen = 0;

	DBG_INFO("response public key ...");
	if (ntohl(tlv.len) <= 0 || ntohl(tlv.crc) <= 0)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
	{
		DBG_ERR("Verify checksum error !!!");
		return 0;
	}

	keyInfo->publicKeyLen = ntohl(tlv.len);
	MALLOC(keyInfo->publicKey, unsigned char, ntohl(tlv.len));
	if (IsNULL_PTR(keyInfo->publicKey))
	{
		DBG_ERR("Failed to MALLOC() !!!");
		return 0;
	}

	memset(keyInfo->publicKey, 0, ntohl(tlv.len));
	memcpy((unsigned char *)&keyInfo->publicKey[0], (unsigned char *)packetMsg, ntohl(tlv.len));
	DBG_INFO("OK");

	DBG_INFO("%s generator master key ...", ST_NAME);
	keyInfo->masterKey = gen_rand(&keyInfo->masterKeyLen);
	if (IsNULL_PTR(keyInfo->masterKey))
	{
		DBG_ERR("Failed to gen_rand() !!");
		return 0;
	}
	DBG_INFO("OK");

	DBG_INFO("%s generator client nonce ...", ST_NAME);
	keyInfo->clientNounce = gen_rand(&keyInfo->clientNounceLen);
	if (IsNULL_PTR(keyInfo->clientNounce))
	{
		DBG_ERR("Failed to gen_rand() !!");
		return 0;
	}
	DBG_INFO("OK");

	DBG_INFO("%s send nonce request to server ...", ST_NAME);
	MALLOC(PPP, unsigned char, (sizeof(TLV_Header)+keyInfo->masterKeyLen+sizeof(TLV_Header)+keyInfo->clientNounceLen));
	if (IsNULL_PTR(PPP))
	{
		DBG_ERR("Failed to MALLOC() !!!");
		return 0;
	}

	memset(PPP, 0, sizeof(TLV_Header)+keyInfo->masterKeyLen+sizeof(TLV_Header)+keyInfo->clientNounceLen);
	P1 = &PPP[0];
	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(MASTER_KEY);
	packetTlvHdr.len = htonl(keyInfo->masterKeyLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (unsigned char *)&keyInfo->masterKey[0], keyInfo->masterKeyLen));
	memcpy((unsigned char *)P1, (unsigned char *)&packetTlvHdr, sizeof(packetTlvHdr));
	P1 += sizeof(packetTlvHdr);
	memcpy((unsigned char *)P1, (unsigned char *)&keyInfo->masterKey[0], keyInfo->masterKeyLen);
	P1 += keyInfo->masterKeyLen;

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(CLIENT_NONCE);
	packetTlvHdr.len = htonl(keyInfo->clientNounceLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (unsigned char *)&keyInfo->clientNounce[0], keyInfo->clientNounceLen));
	memcpy((unsigned char *)P1, (unsigned char *)&packetTlvHdr, sizeof(packetTlvHdr));
	P1 += sizeof(packetTlvHdr);
	memcpy((unsigned char *)P1, (unsigned char *)&keyInfo->clientNounce[0], keyInfo->clientNounceLen);

	memset(encodeMsg, 0, sizeof(encodeMsg));
	encodeMsgLen = rsa_encrypt((unsigned char *)&PPP[0], (sizeof(TLV_Header)+keyInfo->masterKeyLen+sizeof(TLV_Header)+keyInfo->clientNounceLen), keyInfo->publicKey, keyInfo->publicKeyLen, encodeMsg, sizeof(encodeMsg), 1 /* public */);
	if (encodeMsgLen <= 0)
	{
		DBG_ERR("Failed to rsa_encrypt() !!!");
		MFREE(PPP);
		return 0;
	}

	MALLOC(PP, unsigned char, (sizeof(TLV_Header)+encodeMsgLen));
	if (IsNULL_PTR(PP))
	{
		DBG_ERR("Failed to MALLOC() !!!");
		MFREE(PPP);
		return 0;
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(REQ_NC);
	packetTlvHdr.len = htonl(encodeMsgLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (void*)&encodeMsg[0], encodeMsgLen));
	memcpy((unsigned char *)PP, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
	memcpy((unsigned char *)PP+sizeof(TLV_Header), (unsigned char *)&encodeMsg[0], encodeMsgLen);
	if (write(sock, PP, sizeof(TLV_Header)+encodeMsgLen) != sizeof(TLV_Header)+encodeMsgLen)
	{
		MFREE(PPP);
		MFREE(PP);
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	MFREE(PPP);
	MFREE(PP);
	DBG_INFO("OK");
	return 1;
} /* End of cm_processRES_KU */

/*
========================================================================
Routine Description:
	Process RES_NC packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRES_NC(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *P1 = NULL;
	unsigned char *decodeMsg = NULL;
	size_t decodeMsgLen = 0;
	TLV_Header packetTlvHdr;
	//unsigned char hexGroupId[32] = {0};

	if (ntohl(tlv.len) <= 0 || ntohl(tlv.crc) <= 0) {
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
		DBG_ERR("Verify checksum error !!!");
		return 0;
	}

	// aes decrypt
	decodeMsg = aes_decrypt(keyInfo->masterKey, packetMsg, ntohl(tlv.len), &decodeMsgLen);
	if (IsNULL_PTR(decodeMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}
	DBG_INFO("respone nonce - OK");

	if (sizeof(TLV_Header) > decodeMsgLen) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	P1 = (unsigned char *)&decodeMsg[0];
	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	memcpy(&packetTlvHdr, P1, sizeof(packetTlvHdr));
	if (ntohl(packetTlvHdr.len) <= 0 || ntohl(packetTlvHdr.crc) <= 0) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	P1 += sizeof(TLV_Header);
	decodeMsgLen -= sizeof(TLV_Header);
	if (ntohl(packetTlvHdr.type) != SERVER_NONCE) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	if (ntohl(packetTlvHdr.len) > decodeMsgLen) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	if (ntohl(packetTlvHdr.crc) != Adv_CRC32(0, P1, ntohl(packetTlvHdr.len))) {
		DBG_ERR("Verify checksum error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	keyInfo->serverNounceLen = ntohl(packetTlvHdr.len);
	MALLOC(keyInfo->serverNounce, unsigned char, keyInfo->serverNounceLen);
	if (IsNULL_PTR(keyInfo->serverNounce)) {
		DBG_ERR("NS : memory allocate failed !!!");
		MFREE(decodeMsg);
		return 0;
	}
	memset(keyInfo->serverNounce, 0, keyInfo->serverNounceLen);
	memcpy((unsigned char *)&keyInfo->serverNounce[0], (unsigned char *)P1, keyInfo->serverNounceLen);
	P1 += keyInfo->serverNounceLen;
	decodeMsgLen -= ntohl(packetTlvHdr.len);
	DBG_INFO("%s get server nonce - OK", ST_NAME);

	if (sizeof(TLV_Header) > decodeMsgLen) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	memcpy(&packetTlvHdr, P1, sizeof(packetTlvHdr));
	if (ntohl(packetTlvHdr.len) <= 0 || ntohl(packetTlvHdr.crc) <= 0) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	P1 += sizeof(TLV_Header);
	decodeMsgLen -= sizeof(TLV_Header);
	if (ntohl(packetTlvHdr.type) != CLIENT_NONCE) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	if (ntohl(packetTlvHdr.len) > decodeMsgLen) {
		DBG_ERR("Parsing data error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	if (ntohl(packetTlvHdr.crc) != Adv_CRC32(0, P1, ntohl(packetTlvHdr.len))) {
		DBG_ERR("Verify checksum error !!!");
		MFREE(decodeMsg);
		return 0;
	}

	if (ntohl(packetTlvHdr.len) != keyInfo->clientNounceLen) {
		DBG_ERR("Error on varify client nonce !!!");
		MFREE(decodeMsg);
		return 0;
	}

	if (memcmp((unsigned char *)P1, (unsigned char *)&keyInfo->clientNounce[0], keyInfo->clientNounceLen) != 0) {
		DBG_ERR("Error on varify client nonce !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("%s verify client nonce - OK", ST_NAME);

	/* generate session key */
	if (!IsNULL_PTR(pCtrlBK->sessionKey)) MFREE(pCtrlBK->sessionKey);
	pCtrlBK->sessionKey = gen_session_key((unsigned char *)&groupID[0], strlen(groupID),
			keyInfo->serverNounce, keyInfo->serverNounceLen, keyInfo->clientNounce,
			keyInfo->clientNounceLen, &pCtrlBK->sessionKeyLen);
	pCtrlBK->sessionKeyStartTime = uptime();
	pCtrlBK->sessionKeyReady = 1;

	if (IsNULL_PTR(pCtrlBK->sessionKey)) {
		DBG_ERR("Failed to generate session key !!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("generate session key - OK");

	/* free session key 1 */
	if (!IsNULL_PTR(pCtrlBK->sessionKey1)) MFREE(pCtrlBK->sessionKey1);
	pCtrlBK->sessionKey1StartTime = uptime() - sessionKeyExpireTime;

	memset(&packetTlvHdr, 0, sizeof(TLV_Header));
	packetTlvHdr.type = htonl(REP_OK);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header))
	{
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	MFREE(decodeMsg);
	DBG_INFO("%s send OK message to server - OK", ST_NAME);
	return 1;
} /* End of cm_processRES_NC */

/*
========================================================================
Routine Description:
	Process RSP_CHK packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_CHK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;

	DBG_INFO("Got RSP_CHK ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no config will be apply.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_checkCfgInfo(decodeMsg);
		MFREE(decodeMsg);
	}

	snprintf((char *)pPktBuf, sizeof(pPktBuf), "{\"%s\":\"%s\"}", CFG_STR_MAC, get_unique_mac());

	if (strlen((char *)&pPktBuf[0]) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, ACK_CHK, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encLen);
		if (IsNULL_PTR(encryptedMsg)) 	{
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&tlv, 0, sizeof(TLV_Header));
		tlv.type = htonl(ACK_CHK);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
		encLen = sizeof(TLV_Header);
	}

	DBG_INFO("Send ACK_CHK to server ...");
	if (write(sock, (char*)encryptedMsg, encLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");

	MFREE(encryptedMsg);

	return 1;
} /* End of cm_processRSP_CHK */

/*
========================================================================
Routine Description:
	Process ACK_OK packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processACK_OK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *PP = NULL;
	unsigned char *encodeMsg = NULL;
	size_t encodeMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};

	/* remove changed config first */
	unlink(CHANGED_CFG_JSON_PATH);

	if (cm_prepareCheckMsg((char *)&pPktBuf[0], MAX_MESSAGE_SIZE, 0, 0) == 0) {
		DBG_ERR("No info for check");
		return 0;
	}

	DBG_INFO("ack done ... OK");
	DBG_INFO("send REQ_JOIN message to server ...");
	//encodeMsg = aes_encrypt(pCtrlBK->sessionKey, (unsigned char *)&str[0], strlen(str) + 1, &encodeMsgLen);
	encodeMsg = aes_encrypt(pCtrlBK->sessionKey, (unsigned char *)&pPktBuf[0], strlen((char *)pPktBuf) + 1, &encodeMsgLen);
	if (IsNULL_PTR(encodeMsg)) {
		DBG_ERR("Failed to aes_encrypt() !!!");
		return 0;
	}

	MALLOC(PP, unsigned char, sizeof(TLV_Header)+encodeMsgLen);
	if (IsNULL_PTR(PP)) {
		DBG_ERR("Failed to MALLOC() !!!");
		return 0;
	}

	memset(&packetTlvHdr, 0, sizeof(TLV_Header));
	packetTlvHdr.type = htonl(REQ_JOIN);
	packetTlvHdr.len = htonl(encodeMsgLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, encodeMsg, encodeMsgLen));
	memcpy((unsigned char *)PP, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
	memcpy((unsigned char *)PP+sizeof(TLV_Header), (unsigned char *)encodeMsg, encodeMsgLen);
	if (write(sock, (char *)PP, sizeof(TLV_Header)+encodeMsgLen) != sizeof(TLV_Header)+encodeMsgLen) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(encodeMsg);
		MFREE(PP);
		return 0;
	}
	DBG_INFO("OK");
	MFREE(encodeMsg);
	MFREE(PP);

	return 1;
} /* End of cm_processACK_OK */

/*
========================================================================
Routine Description:
	Process RSP_JOIN packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_JOIN(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_JOIN");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("legnth of RSP_JOIN is equal to 0");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_INFO("Master is invalid!");
			return 0;
		}
		DBG_INFO("Master is valid!");

#ifdef MASTER_DET
		validMaster = 1;
#if defined(RTCONFIG_RALINK_MT7621)
		if(!nvram_match("cfg_masterip",serverIp)) //RE only
		{
			nvram_set("cfg_masterip", serverIp); 
			//renew RE's eth-clinet ip
			if(strstr(nvram_safe_get("sta_phy_ifnames"),nvram_safe_get("amas_ifname"))) //wifi backhaul
			{
				//for all down/up
				eval("rtkswitch", "17"); 
				sleep(1);
			 	eval("rtkswitch", "16"); 
			}	 
			else 
			{
				//for lan down/up
				eval("rtkswitch", "15"); 
				sleep(1);
				eval("rtkswitch", "14"); 
			}	 
		}	
#else
		nvram_set("cfg_masterip", serverIp); 
#endif		
#endif

#if defined(RTCONFIG_WIFI_SON)
        	if(!nvram_match("wifison_ready", "1"))
#endif
		cm_handleJoinReturnData(decodeMsg);

		MFREE(decodeMsg);
	}

	DBG_INFO("OK");
	return 1;
} /* End of cm_processRSP_JOIN */

/*
========================================================================
Routine Description:
	Process REQ_NTF packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_NTF(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	int notifyType = 0;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
#ifdef RTCONFIG_BHCOST_OPT
	int aimesh_alg = nvram_get_int("aimesh_alg") ?: AIMESH_ALG_COST;
#endif

	DBG_INFO("Got REQ_NTF ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("legnth of REQ_NTF is equal to 0");
		return 0;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("%s decryption message - OK", ST_NAME);

		DBG_INFO("msg(%s)", decodeMsg);

		notifyType = cm_getNotifyType(decodeMsg);
	}

	memset(&packetTlvHdr, 0, sizeof(TLV_Header));
	packetTlvHdr.type = htonl(RSP_NTF);
	if (write(sock, (char*)&packetTlvHdr, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	/* change curState based on notify type */
	DBG_LOG("notify type(%d)", notifyType);
	switch(notifyType)
	{
		/* for config check */
		case NOTIFY_CHECK:
			if (cm_haveFeatureList(decodeMsg)) {
				cm_checkCfgInfo(decodeMsg);
				cm_applyCfgAction(0);
			}
			else
				curState = IMMCHECK;
			break;
		/* for session key */
		case NOTIFY_REKEY:
			curState = REKEY;
			break;
		/* for group key */
		case NOTIFY_GREKEY:
			curState = GREKEY;
			break;
		/* for firmware upgrade */
		case NOTIFY_FWCHECK:
			cm_doFirmwareCheck(decodeMsg);
			break;
		case NOTIFY_FWDOWNLOAD:
			cm_doFirmwareDownload();
			break;
		case NOTIFY_FWCHECKSTATUS:
			cm_doFwCheckStatusReport();
			break;
		case NOTIFY_FWDOWNLOADSTATUS:
			cm_doFwDownloadStatusReport();
			break;
		case NOTIFY_FWUPGRADE:
			cm_upgradeFirmware();
			break;
		case NOTIFY_CANCELFWCHECK:
			cm_cancelFirmwareCheck();
                        break;
		case NOTIFY_CANCELFWUPGRADE:
			cm_cancelFirmwareUpgrade();
			break;
		case NOTIFY_FWCHECKSUCCESS:
			cm_checkFirmwareSuccess();
			break;
		case NOTIFY_RESETDEFAULT:
			resetDefault = 1;
			notify_rc("resetdefault");
			break;
#ifdef ONBOARDING
		case NOTIFY_ONBOARDING:
			cm_processOnboardingEvent((char *)decodeMsg);
			break;
#endif
		case NOTIFY_REQUESTCOST:
			cm_requestNetworkCost();
#ifdef ONBOARDING
#ifdef RTCONFIG_WIFI_SON
			if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
			{
#ifdef RTCONFIG_BHCOST_OPT
				if (aimesh_alg != AIMESH_ALG_COST)
#endif
					cm_updateOnboardingVsie(nvram_get_int("cfg_obstatus"));
			}
#endif
			//cm_requestTopology();
			break;
		/* for wps */
		case NOTIFY_STARTWPS:
			notify_rc("restart_wps");
			break;
		/* for config changed */
		case NOTIFY_CFGCHANGED:
			cm_checkCfgInfo(decodeMsg);
			cm_applyCfgAction(1);
			break;
		case NOTIFY_REQUESTTOPOLOGY:
			cm_requestTopology();
			break;
#ifndef RTCONFIG_BHCOST_OPT
		/* for wlc reconnect */
		case NOTIFY_WLCRECONNECT:
			notify_rc("restart_amas_wlcconnect");
			break;
#endif
		/* for feedback */
		case NOTIFY_FEEDBACK:
			cm_handleFeedback(decodeMsg);
			break;
		case NOTIFY_UPDATERELIST:
			cm_handleReListUpdate(decodeMsg);
            break;
#ifdef RTCONFIG_BCN_RPT
		case NOTIFY_UPDATEAPLIST:
			cm_handleAPListUpdate(decodeMsg);
			break;
#endif
#ifdef DUAL_BAND_DETECTION
		case NOTIFY_UPDATEDBLIST:
			cm_handleDualBandListUpdate(decodeMsg);
			break;
#endif
#ifdef RTCONFIG_BHCOST_OPT
		case NOTIFY_SELF_OPTIMIZATION:
			cm_triggerSelfOptimization();
			break;
#endif /* RTCONFIG_BHCOST_OPT */
		case NOTIFY_REBOOT:
			notify_rc("reboot");
			break;
		case NOTIFY_ACTION:
			cm_actionHandler(decodeMsg);
			break;
#ifdef STA_BIND_AP
		case NOTIFY_UPDATE_STA_BINDING:
			cm_updateStaBindingList(decodeMsg);
			break;
#endif /* STA_BIND_AP */
#ifdef RTCONFIG_FRONTHAUL_DWB
		case NOTIFY_REQUESTBACKHUALSTATUS:
			cm_requestBackhualStatus();
			break;
#endif
#ifdef ONBOARDING_VIA_VIF
		case NOTIFY_ONBOARDING_VIF_DOWN:
			cm_obVifDownUp(OB_VIF_DOWN);
			break;
#endif
		case NOTIFY_REQUESTLEVEL:
			cm_requestNetworkLevel();
			break;
		default:
			DBG_INFO("no corresponding notify type(%d)", notifyType);
	}

	MFREE(decodeMsg);

	if (notifyType >= NOTIFY_CHECK && notifyType <= NOTIFY_REKEY)
		notifiedCfg = 1;

	/* notification from server trigged by NOTIFY_CFGACT */
	if (notifyType == NOTIFY_CFGACT) {
		DBG_INFO("got NOTIFY_CFGACT");
		cm_applyCfgAction(1);
	}

	return 1;
} /* End of cm_processREQ_NTF */

/*
========================================================================
Routine Description:
	Process RSP_GKEY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_GKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_GKEY ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no config will be apply.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_checkGroupKey(pCtrlBK, decodeMsg);
		MFREE(decodeMsg);
	}

	memset(&packetTlvHdr, 0, sizeof(TLV_Header));
	packetTlvHdr.type = htonl(ACK_GKEY);
	if (write(sock, (char*)&packetTlvHdr, sizeof(TLV_Header)) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}
	return 1;
} /* End of cm_processRSP_GKEY */

/*
========================================================================
Routine Description:
	Process RSP_SREKEY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_SREKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_SREKEY ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no config will be apply.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_updateSessionKey(decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_SREKEY */

/*
========================================================================
Routine Description:
	Process RSP_GREKEY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_GREKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_GREKEY ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no config will be apply.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_updateGroupKey(decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_GREKEY */

#if defined(SYNC_WCHANNEL)
/*
========================================================================
Routine Description:
	Process RSP_RPT packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_RPT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_RPT ...");

#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no infomation of wireless channel.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)){
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_checkWirelessChannel(decodeMsg);
#ifdef STA_BIND_AP
		cm_updateStaBindingList(decodeMsg);
#endif /* STA_BIND_AP */

#ifdef RTCONFIG_NBR_RPT
		cm_updateNbrList(decodeMsg);
#endif
		MFREE(decodeMsg);
	}
	} /* !wifison_ready */

	return 1;
} /* End of RSP_CHANSYNC */
/*
========================================================================
Routine Description:
	Process RSP_CHANSYNC packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_CHANSYNC(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_CHANSYNC ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no infomation of wireless channel.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)){
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_checkWirelessChannel(decodeMsg);
		MFREE(decodeMsg);
	}

	memset(&packetTlvHdr, 0, sizeof(TLV_Header));
	packetTlvHdr.type = htonl(ACK_CHANSYNC);
	if (write(sock, (char*)&packetTlvHdr, sizeof(TLV_Header)) <= 0)
		DBG_ERR("Failed to socket write() !!!");

	return 1;
} /* End of RSP_CHANSYNC */
#endif

#ifdef RTCONFIG_FRONTHAUL_DWB
int cm_processRSP_BACKHUALSTATUS(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_BACKHUALSTATUS ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no backhual status.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);

		json_object *decryptedRoot = json_tokener_parse((char *)decodeMsg);
		json_object *backhualstatusObj = NULL;

		json_object_object_get_ex(decryptedRoot, CFG_STR_BACKHUAL_STATUS, &backhualstatusObj);
		if (backhualstatusObj) {
			if (atoi(json_object_get_string(backhualstatusObj)) == 1) // some re connected...
				nvram_set_int("fh_ap_bss", 0);
			else
				nvram_set_int("fh_ap_bss", 1);
		}
		json_object_put(decryptedRoot);
		MFREE(decodeMsg);
	}

	return 1;
}
#endif

/*
========================================================================
Routine Description:
	Process RSP_COST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_COST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_COST ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no network cost.");
		pCtrlBK->cost = -1;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_updateNetworkCost(pCtrlBK, decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_GKEY */

/*
========================================================================
Routine Description:
	Process RSP_LEVEL packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_LEVEL(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_LEVEL ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no network level.");
		/* update the max level of network topology */
		nvram_set_int("cfg_maxlevel", -1);

		/* update the level of RE */
		nvram_set_int("cfg_level", -1);
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_updateNetworkLevel(pCtrlBK, decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_LEVEL */

/*
========================================================================
Routine Description:
	Save the network topology.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_saveNetworkTopology(CM_CTRL *pCtrlBK, unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);

	json_object_to_file(CLIENT_STALIST_JSON_PATH, decryptedRoot);
	json_object_put(decryptedRoot);
} /* End of cm_saveNetworkTopology */


/*
========================================================================
Routine Description:
	Process RSP_TOPOLOGY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_TOPOLOGY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_TOPOLOGY ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no network topology.");
		pCtrlBK->cost = -1;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_saveNetworkTopology(pCtrlBK, decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_TOPOLOGY */

/*
========================================================================
Routine Description:
	Process RSP_RELIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_RELIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_RELIST ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no re list.");
		pCtrlBK->cost = -1;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_handleReListUpdate(decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_RELIST */

#ifdef DUAL_BAND_DETECTION
/*
========================================================================
Routine Description:
	Process RSP_DBLIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_DBLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_DBLIST ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no dual band list.");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_handleDualBandListUpdate(decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_DBLIST */
#endif

#ifdef RTCONFIG_BCN_RPT
/*
========================================================================
Routine Description:
	Process RSP_APLIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_APLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got RSP_APLIST ...");

	if ((sessionKey = cm_selectSessionKey(1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(0);

	if (ntohl(tlv.len) == 0) {
		DBG_ERR("no re list.");
		pCtrlBK->cost = -1;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
		{
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);
		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
		DBG_INFO("message(%s)", decodeMsg);
		cm_handleAPListUpdate(decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processRSP_APLIST */
#endif
/*
========================================================================
Routine Description:
	Process all TCP packet.

Arguments:
	sock_fd		- socket fd
	data		- received data
	data_len	- received data length
	pCtrlBK		- CM control blcok
	keyInfo		- security information

Return Value:
	-1		- abort
	0		- continue to receive
	1		- break to receive

========================================================================
*/
int cm_packetProcess(
	int sock_fd,
	unsigned char *data,
	int data_len,
	CM_CTRL *pCtrlBK,
	securityInfo *keyInfo)
{
	int sock = sock_fd, len = 0, i = 0;
	unsigned char *pData = NULL;
	TLV_Header tlv, tlv_hdr;

	if (IsNULL_PTR(data))
	{
		DBG_ERR("%s: data is null !!!", __FUNCTION__);
		return 1;
	}

	pData = (unsigned char *)&data[0];
	len = data_len;
	DBG_INFO("data_len(%d)", len);
	for (i=0; i<len; )
	{
		struct packetHandler *handler;

		if (i+sizeof(TLV_Header) > len) {
			DBG_WARNING("Error on receive size !!!");
			break;
		}
		memset(&tlv, 0, sizeof(TLV_Header));
		memcpy((unsigned char *)&tlv, (unsigned char *)pData, sizeof(TLV_Header));

		if (ntohl(tlv.len) != (len - sizeof(TLV_Header))) {
			DBG_ERR("Checking length error !!!");
			goto packetProcess_fail;
		}

		pData += sizeof(TLV_Header);
		i += sizeof(TLV_Header);
		if (ntohl(tlv.type) <= 0 && ntohl(tlv.type) > 99) {
			DBG_WARNING("Invalid TLV type !!!");
			break;
		}

		DBG_INFO("tlv.type(%s)", ST_NAME);

		handler = NULL;
		for(handler = &packetHandlers[0]; handler->type > 0; handler++) {
			if (handler->type == ntohl(tlv.type))
				break;
		}

		if (handler == NULL || handler->type < 0)
			DBG_INFO("no corresponding function pointer(%d)", ntohl(tlv.type));
		else
		{
			if (!handler->func(sock_fd, pCtrlBK, tlv, keyInfo, (unsigned char *)&pData[0])) {
				/* abort connection */
				if (ntohl(tlv.type) == RES_KU || ntohl(tlv.type) == RES_NC ||
					ntohl(tlv.type) == ACK_OK || ntohl(tlv.type) == RSP_JOIN)
					return -1;
				else
				{
					DBG_ERR("process packet(%d) failed", ntohl(tlv.type));
					goto packetProcess_fail;
				}
			}

			if (ntohl(tlv.type) == RSP_CHK || ntohl(tlv.type) == REQ_NTF)
				return 1;
		}

		switch (ntohl(tlv.type))
		{
			case RES_NAK:
				DBG_INFO("reply un-ack ...");
				DBG_INFO("Abort, disconnect ...");
				return -1;
			case RSP_JOIN:
				DBG_INFO("join success");
			case RSP_RPT:
			case RSP_GKEY:
			case RSP_GREKEY:
			case RSP_WEVENT:
			case RSP_CHANSYNC:
			case RSP_STALIST:
			case RSP_FWSTAT:
			case RSP_COST:
			case RSP_CLIENTLIST:
#ifdef ONBOARDING
			case RSP_ONBOARDING:
			case RSP_GROUPID:
#endif
			case RSP_SREKEY:
			case RSP_TOPOLOGY:
			case RSP_RADARDET:
			case RSP_RELIST:
			case RSP_APLIST:
			case RSP_DBLIST:
			case RSP_CHANGED_CONFIG:
#ifdef RTCONFIG_FRONTHAUL_DWB
			case RSP_BACKHUALSTATUS:
#endif
				return 1;
		}

		pData += ntohl(tlv.len);
		i += ntohl(tlv.len);
	}

	return 0;

packetProcess_fail:
	memset(&tlv_hdr, 0, sizeof(tlv_hdr));
	tlv_hdr.type = htonl(RES_NAK);
	if (write(sock, (unsigned char *)&tlv_hdr, sizeof(tlv_hdr)) != sizeof(tlv_hdr))
		DBG_ERR("Failed to socket write !!!");

	return 1;
} /* End of cm_packetProcess */

/*
========================================================================
Routine Description:
	Create a thread to handle received TCP packets.

Arguments:
	*args		- arguments for socket

Return Value:
	None

Note:
========================================================================
*/
void *cm_tcpPacketHandler(void *args)
{

#if defined(RTCONFIG_RALINK_MT7621)
		Set_CPU();
#endif

	pthread_detach(pthread_self());

	int newSock = *(int*)args;
    	unsigned char pPktBuf[MAX_PACKET_SIZE];
	int len = 0;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	//struct timeval rcvTimeout = {3, 0};

	memset(pPktBuf, 0, sizeof(pPktBuf));

	//if (setsockopt(newSock, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, sizeof(struct timeval)) < 0)
	//	DBG_ERR("Failed to setsockopt() !!!");

	while (1)
	{
		/* handle the packet */
		memset(pPktBuf, 0, sizeof(pPktBuf));
		if ((len = read_tcp_message(newSock, &pPktBuf[0], sizeof(pPktBuf))) <= 0) {
			DBG_ERR("Failed to read_tcp_message()!");
			break;
		}

		if (cm_packetProcess(newSock, pPktBuf, len, pCtrlBK, NULL) == 1)
			break;
	}

	close(newSock);
	free(args);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_tcpPacketHandler */

/*
========================================================================
Routine Description:
	Handle received TCP packets.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
void cm_rcvTcpHandler(CM_CTRL *pCtrlBK)
{
	struct sockaddr_in cliSockAddr;
	int clientSock = 0, sockAddrLen = sizeof(cliSockAddr);
	char clientIP[32] = {0};
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	pthread_t sockThread;
	int *sockArgs = malloc(sizeof(int));
	char lanIpAddr[sizeof("255.255.255.255XXX")] = {0};

	DBG_INFO("enter");

	memset(&cliSockAddr, 0, sizeof(struct sockaddr_in));
	memset(pPktBuf, 0, sizeof(pPktBuf));

	/* get lan ip address*/
	snprintf(lanIpAddr, sizeof(lanIpAddr) - 1, "%s", get_lan_ipaddr());
	DBG_INFO("lanIpAddr (%s)", lanIpAddr);

	clientSock = accept(pCtrlBK->socketTCPSend, (struct sockaddr *)&cliSockAddr, (socklen_t *)&sockAddrLen);
	snprintf(clientIP, sizeof(clientIP), "%s", (char *)inet_ntoa(cliSockAddr.sin_addr));
	DBG_INFO("clientSock(%d) clientIP(%s:%d)", clientSock, clientIP, ntohs(cliSockAddr.sin_port));
	*sockArgs = clientSock;

	if (!cm_checkStateForPeriodicAction()) {
		DBG_ERR("don't need to handle tcp packet, just close socket");
		close(clientSock);
		free(sockArgs);
	}
	else if (strcmp(lanIpAddr, clientIP) == 0 || strcmp(clientIP, "0.0.0.0") == 0) {
		DBG_ERR("clientIP (%s), lanIpAddr (%s)", clientIP, lanIpAddr);
		close(clientSock);
		free(sockArgs);
	}
	else if (pthread_create(&sockThread, attrp, cm_tcpPacketHandler, sockArgs) != 0) {
		DBG_ERR("could not create thread !!!");
		close(clientSock);
		free(sockArgs);
	}

	DBG_INFO("leave");
} /* End of cm_rcvTcpHandler */

/*
========================================================================
Routine Description:
	Handle received CM packets.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
void cm_rcvHandler(CM_CTRL *pCtrlBK)
{
	fd_set fdSet;
	int sockMax;

	/* init */
	sockMax = pCtrlBK->socketTCPSend;

	if (pCtrlBK->socketUdpSendRcv > pCtrlBK->socketTCPSend)
		sockMax = pCtrlBK->socketUdpSendRcv;

	if (pCtrlBK->socketIpcSendRcv > sockMax)
		sockMax = pCtrlBK->socketIpcSendRcv;

	/* waiting for any packet */
	while(1)
	{
		/* must re- FD_SET before each select() */
		FD_ZERO(&fdSet);

		FD_SET(pCtrlBK->socketTCPSend, &fdSet);
		FD_SET(pCtrlBK->socketUdpSendRcv, &fdSet);
		FD_SET(pCtrlBK->socketIpcSendRcv, &fdSet);

		/* must use sockMax+1, not sockMax */
		if (select(sockMax+1, &fdSet, NULL, NULL, NULL) < 0)
			break;

		/* handle packets from TCP layer */
		if (FD_ISSET(pCtrlBK->socketTCPSend, &fdSet))
			cm_rcvTcpHandler(pCtrlBK);

		/* handle packets from UDP layer */
		if (FD_ISSET(pCtrlBK->socketUdpSendRcv, &fdSet))
			cm_rcvUdpHandler();

		/* handle packets from IPC */
		if (FD_ISSET(pCtrlBK->socketIpcSendRcv, &fdSet))
			cm_rcvIpcHandler(pCtrlBK->socketIpcSendRcv);

	};
} /* End of cm_rcvHandler */

/*
========================================================================
Routine Description:
	Thread for handle received packets.

Arguments:
	*args		- argument for thread

Return Value:
	None

Note:
========================================================================
*/
void *cm_rcvPacket(void *args)
{
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;

#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif

	pthread_detach(pthread_self());

	DBG_INFO("enter");

	/* init */
	pCtrlBK->flagIsTerminated = 0;
	pCtrlBK->sessionKeyReady = 0;
	pCtrlBK->groupKeyReady = 0;

	/* waiting for CM packets */
	while(!pCtrlBK->flagIsTerminated)
	{
		/* CPU suspend will be done in cm_rcvHandler() */
		cm_rcvHandler(pCtrlBK);
	} /* End of while */

	DBG_INFO("leave");

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_rcvPacket */

/*
========================================================================
Routine Description:
	Callback for check cfg.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkCfgEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK)
		cm_checkCfgState(0);

	scCfgCheck.timeout = current_time() + CHECK_TIME_INTERVAL;
} /* End of cm_checkCfgEvent */

/*
========================================================================
Routine Description:
	Callback for report dut's status.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportStatusEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK)
		cm_reportConnStatus();

	scStatusReport.timeout = current_time() + REPORT_TIME_INTERVAL;
} /* End of cm_reportStatusEvent */

/*
========================================================================
Routine Description:
	Callback for report wireless event.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportWeventEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK)
		cm_reportWirelessEvent();

	scWeventReport.timeout = current_time() + REPORT_WEVENT_INTERVAL;
} /* End of cm_reportWeventEvent */

/*
========================================================================
Routine Description:
	Callback for report wireless client list.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportStalistEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK)
		cm_reportStaList();

	scStaListReport.timeout = current_time() + REPORT_STALIST_INTERVAL;
} /* End of cm_reportStalistEvent */

/*
========================================================================
Routine Description:
	Callback for report all client list include wireless and wired client.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportClientlistEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK)
		cm_reportClientList();

	scClientListReport.timeout = current_time() + REPORT_CLIENTLIST_INTERVAL;
} /* End of cm_reportClientlistEvent */

#if 0// defined(SYNC_WCHANNEL)
/*
========================================================================
Routine Description:
	Callback for check wireless channel.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkWchannelEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK)
		cm_requestWirelessChannel();

	scWchannelCheck.timeout = current_time() + CHECK_WCHANNEL_INTERVAL;
} /* End of cm_checkWchannelEvent */
#endif	/* SYNC_WCHANNEL */

/*
========================================================================
Routine Description:
	Callback for check session key.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkSessionKeyEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK) {
		int sKeyTime = (int) (uptime() - cm_ctrlBlock.sessionKeyStartTime);
		int sKey1Time = (int) (uptime() - cm_ctrlBlock.sessionKey1StartTime);

		DBG_INFO("sKeyTime(%d), sKey1Time(%d), sessionKeyExpireTime(%d), rekeyTime(%d)",
				sKeyTime, sKey1Time , sessionKeyExpireTime, REKEY_TIME(sessionKeyExpireTime));

		/* check key ready */
		if (!cm_ctrlBlock.sessionKeyReady)
			goto err;

		/* check session key whether do rekey */
		if ((sKeyTime >= REKEY_TIME(sessionKeyExpireTime) &&
			sKeyTime <= sessionKeyExpireTime &&
			sKey1Time >= sessionKeyExpireTime) ||
			(sKey1Time >= REKEY_TIME(sessionKeyExpireTime) &&
			sKey1Time <= sessionKeyExpireTime &&
			sKeyTime >= sessionKeyExpireTime))
				cm_requestSessionReKey();
		}

err:

	scSessionKeyCheck.timeout = current_time() + CHECK_KEY_INTERVAL;
} /* End of cm_checkSessionKeyEvent */

/*
========================================================================
Routine Description:
	Callback for check group key.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkGroupKeyEvent(struct sched *sched)
{
	if (!resetDefault && curState == PERCHECK) {
		int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
		int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

		DBG_INFO("gKeyTime(%d), gKey1Time(%d), groupKeyExpireTime(%d), rekeyTime(%d)",
				gKeyTime, gKey1Time , groupKeyExpireTime, REKEY_TIME(groupKeyExpireTime));

		/* check key ready */
		if (!cm_ctrlBlock.groupKeyReady)
			goto err;

		/* check session key whether do rekey */
		if ((gKeyTime >= REKEY_TIME(groupKeyExpireTime) &&
			gKeyTime <= groupKeyExpireTime &&
			gKey1Time >= groupKeyExpireTime) ||
			(gKey1Time >= REKEY_TIME(groupKeyExpireTime) &&
			gKey1Time <= groupKeyExpireTime &&
			gKeyTime >= groupKeyExpireTime))
				cm_requestGroupReKey();
	}

err:

	scGroupKeyCheck.timeout = current_time() + CHECK_KEY_INTERVAL;
} /* End of cm_checkGroupKeyEvent */

#if 0
/*
========================================================================
Routine Description:
	Callback for request topology infot.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_requestTopologyEvent(struct sched *sched)
{
	if (!resetDefault)
		cm_requestTopology();

	scTopologyGet.timeout = current_time() + GET_TOPOLOGY_INTERVAL;
} /* End of cm_requestTopologyEvent */
#endif

/*
========================================================================
Routine Description:
	Callback for checking keepalive.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkKeepAliveEvent(struct sched *sched)
{
	if (!resetDefault) {
		if (curState == INIT || curState == REKEY || curState == CONN)
			connKeepAliveCount++;
		else
			connKeepAliveCount = 0;

		if (connKeepAliveCount >= CONNECT_KEEPALIVE_THRESHOLD) {
			DBG_LOG("connection does not alive (%d)", connKeepAliveCount);
			cm_terminateHandle(-1);
			//notify_rc("restart_cfgsync");
			exit(0);
		}
	}

	keepAliveCheck.timeout = current_time() + CHECK_KEEPALIVE_INTERVAL;
} /* End of cm_checkKeepAliveEvent */

/*
========================================================================
Routine Description:
	Callback for check wired client list.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkWiredClientListEvent(struct sched *sched)
{
	json_object *wiredClientList = NULL;

	if (!resetDefault && curState == PERCHECK) {
		if ((wiredClientList = json_object_new_array()) != NULL) {
			if (cm_needUpdateWiredClientlLst(wiredClientList)) {
				cm_reportConnStatus();
			}
			json_object_put(wiredClientList);
		}
	}

	scWiredClientListCheck.timeout = current_time() + CHECK_CLIENTLIST_INTERVAL;
} /* End of cm_checkWiredClientListEvent */

/*
========================================================================
Routine Description:
	Timer for differnt event.

Arguments:
	*args		- argument for thread

Return Value:
	None

Note:
========================================================================
*/
void *cm_eventTimer(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif
	pthread_detach(pthread_self());

	DBG_INFO("enter");

	/* register scheduler for checking cfg */
	scCfgCheck.on_timeout = cm_checkCfgEvent;
	scCfgCheck.timeout = current_time() + CHECK_TIME_INTERVAL;
	scCfgCheck.name = "CfgCheck";
	add_sched(&scCfgCheck);

	/* register scheduler for reporting status */
	scStatusReport.on_timeout = cm_reportStatusEvent;
	scStatusReport.timeout = current_time() + REPORT_TIME_INTERVAL;
	scStatusReport.name = "StatusReport";
	add_sched(&scStatusReport);

	/* register scheduler for report wireless event */
	scWeventReport.on_timeout = cm_reportWeventEvent;
	scWeventReport.timeout = current_time() + REPORT_WEVENT_INTERVAL;
	scWeventReport.name = "WeventReport";
	add_sched(&scWeventReport);

	/* register scheduler for reporting sta list */
	scStaListReport.on_timeout = cm_reportStalistEvent;
	scStaListReport.timeout = current_time() + REPORT_STALIST_INTERVAL;
	scStaListReport.name = "StaListReport";
	add_sched(&scStaListReport);

	/* register scheduler for reporting client list */
	scClientListReport.on_timeout = cm_reportClientlistEvent;
	scClientListReport.timeout = current_time() + REPORT_CLIENTLIST_INTERVAL;
	scClientListReport.name = "ClientListReport";
	add_sched(&scClientListReport);

#if 0// defined(SYNC_WCHANNEL)
	/* register scheduler for checking wireless channel */
	scWchannelCheck.on_timeout = cm_checkWchannelEvent;
	scWchannelCheck.timeout = current_time() + CHECK_WCHANNEL_INTERVAL;
	scWchannelCheck.name = "WchannelCheck";
	add_sched(&scWchannelCheck);
#endif

#ifdef ROAMING_INFO
	/* register scheduler for checking roaming info */
	cm_registerRoamingInfoSch();
#endif

	/* register scheduler for checking session key */
	scSessionKeyCheck.on_timeout = cm_checkSessionKeyEvent;
	scSessionKeyCheck.timeout = current_time() + CHECK_KEY_INTERVAL;
	scSessionKeyCheck.name = "SessionKeyCheck";
	add_sched(&scSessionKeyCheck);

	/* register scheduler for checking session key */
	scGroupKeyCheck.on_timeout = cm_checkGroupKeyEvent;
	scGroupKeyCheck.timeout = current_time() + CHECK_KEY_INTERVAL;
	scGroupKeyCheck.name = "GroupKeyCheck";
	add_sched(&scGroupKeyCheck);

#if 0
	/* register scheduler for getting network topology*/
	scTopologyGet.on_timeout = cm_requestTopologyEvent;
	scTopologyGet.timeout = current_time() + GET_TOPOLOGY_INTERVAL;
	scTopologyGet.name = "TopologyGet";
	add_sched(&scTopologyGet);
#endif

	/* register scheduler for checking keepalive */
	keepAliveCheck.on_timeout = cm_checkKeepAliveEvent;
	keepAliveCheck.timeout = current_time() + CHECK_KEEPALIVE_INTERVAL;
	keepAliveCheck.name = "KeepAliveCheck";
	add_sched(&keepAliveCheck);

	/* register scheduler for checking wired client list */
	scWiredClientListCheck.on_timeout = cm_checkWiredClientListEvent;
	scWiredClientListCheck.timeout = current_time() + CHECK_CLIENTLIST_INTERVAL;
	scWiredClientListCheck.name	= "WiredClientListCheck";
	add_sched(&scWiredClientListCheck);

	start_sched();

	DBG_INFO("leave");

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_eventTimer */

/*
========================================================================
Routine Description:
	Negotiate session key.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	0		- fail to get session key
	1		- get session key successfully

Note:
========================================================================
*/
static int cm_negotiateSessionKey(CM_CTRL *pCtrlBK)
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	TLV_Header tlv;
	securityInfo keyInfo = {0};
	int ret = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	int len = 0;

	DBG_INFO("enter");

#ifdef MASTER_DET
	validMaster = 0;
#endif

	memset(&keyInfo, 0, sizeof(keyInfo));

	if (strcmp(serverIp, get_lan_ipaddr()) == 0) {
		DBG_ERR("looping myself");
		goto err;
	}

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(serverPort);
	if (inet_aton(serverIp, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", serverIp);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d ....", serverIp, serverPort);
	if (sock_connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr), MAX_SOCK_CONNECT_RETRY_COUNT, MAX_SOCK_CONNECT_RETRY_TIMEWAIT) < 0) {
		DBG_ERR("Failed to connect() !!!");
		goto err;
	}
	DBG_INFO("OK");

	DBG_INFO("Send request public key to server ...");
	memset(&tlv, 0, sizeof(TLV_Header));
	tlv.type = htonl(REQ_KU);
	if (write(sock, (char*)&tlv, sizeof(TLV_Header)) <= 0) {
		DBG_ERR("ERROR: %s , errno %d", strerror(errno), errno);
		goto err;
	}
	DBG_INFO("OK");

	while (1)
	{
		if ((len = read(sock, pPktBuf, sizeof(pPktBuf))) <= 0) {
			DBG_WARNING("ERROR: %s , errno %d", strerror(errno), errno);
			break;
		}

		ret = cm_packetProcess(sock, pPktBuf, len, pCtrlBK, &keyInfo);
		if ( ret == 1 || ret == -1) {
			if (ret == -1)	/* abort */
				ret = 0;
			break;
		}
	}

	if (!IsNULL_PTR(keyInfo.publicKey)) MFREE(keyInfo.publicKey);
	if (!IsNULL_PTR(keyInfo.masterKey)) MFREE(keyInfo.masterKey);
	if (!IsNULL_PTR(keyInfo.serverNounce)) MFREE(keyInfo.serverNounce);
	if (!IsNULL_PTR(keyInfo.clientNounce)) MFREE(keyInfo.clientNounce);

err:
	if (sock >= 0)
		close(sock);

	DBG_INFO("leave");

	return ret;
} /* End of cm_negotiateSessionKey */

/*
========================================================================
Routine Description:
	Start CM realted threads.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_startThread()
{
	pthread_t sockThread;
	pthread_t timerThread;
	//pthread_t roamingThread;

	DBG_INFO("startThread");

	/* start thread to receive packet */
	if (pthread_create(&sockThread, attrp, cm_rcvPacket, NULL) != 0)
		DBG_ERR("could not create thread for sockThread");

	/* start thread for timer */
	if (pthread_create(&timerThread, attrp, cm_eventTimer, NULL) != 0)
		DBG_ERR("could not create thread for timerThread");

} /* End of cm_startThread */

/*
========================================================================
Routine Description:
	Init pthread mutex.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
static int cm_initThreadMutex()
{
	if (pthread_mutex_init(&weventLock, NULL) != 0) {
		DBG_ERR("mutex init failed for weventLock");
		return 0;
	}

	if (pthread_mutex_init(&radarDetLock, NULL) != 0) {
		DBG_ERR("mutex init failed for radarDetLock");
		return 0;
	}

#ifdef ROAMING_INFO
	if (pthread_mutex_init(&roamingInfoLock, NULL) != 0) {
		DBG_ERR("mutex init failed for roamingInfoLock");
		return 0;
	}
#endif

#ifdef LEGACY_ROAMING
	if (pthread_mutex_init(&roamingLock, NULL) != 0) {
		DBG_ERR("mutex init failed for roamingLock");
		return 0;
	}
#endif

	if (pthread_mutex_init(&chanspecLock, NULL) != 0) {
		DBG_ERR("mutex init failed for chanspecLock");
		return 0;
	}

	if (pthread_mutex_init(&changedConfigLock, NULL) != 0) {
		DBG_ERR("mutex init failed for changedConfigLock");
		return 0;
	}

#ifdef RTCONFIG_NBR_RPT
	if (pthread_mutex_init(&nbrRptLock, NULL) != 0) {
		DBG_ERR("mutex init failed for nbrRptLock");
		return 0;
	}
#endif

#ifdef CONN_DIAG
	if (pthread_mutex_init(&connDiagLock, NULL) != 0) {
		DBG_ERR("mutex init failed for connDiagLock");
		return 0;
	}
#endif

	return 1;
} /* End of cm_initThreadMutex */

/*
========================================================================
Routine Description:
	Start CM daemon.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
static void cm_start(CM_CTRL *pCtrlBK)
{
	DBG_INFO("cm start");

	/* init running flag */
	pCtrlBK->flagIsRunning = 1;

	/* start related thread for cm */
	cm_startThread();

	while (1)
	{
		if (!pCtrlBK->flagIsRunning)	/* stop process */
			break;

		if (lastState != curState) {
			DBG_INFO("curState(%d), lastState(%d)", curState, lastState);

			lastState = curState;

			switch(curState)
			{
				case INIT:
				case REKEY:
					connKeepAliveCount = 0;
					pCtrlBK->sessionKeyReady = 0;
					pCtrlBK->groupKeyReady = 0;
					if (cm_negotiateSessionKey(pCtrlBK)) {
						curState = CONN;
#ifdef MASTER_DET
						masterDisconnectCount = 0;	/* reset count */
#endif
					}
					else {
						curState = (curState == INIT? REKEY: INIT);
						sleep(INTERVAL_RETRY_CONNECT);
#ifdef MASTER_DET
						masterDisconnectCount++;
						/* invalid master, detect master again */
						if (!validMaster && masterDisconnectCount >= THRESHOLD_DISCONNECT_COUNT) {
							if (!cm_detectMaster(serverIp))
								curState = RESTART;
						}
#endif
					}
					break;
				case CONN:
					if (!cm_askGroupKey())
						curState = REKEY;
					else
					{
#ifdef LEGACY_ROAMING
#ifdef RTCONFIG_WIFI_SON
						if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
						cm_sendStaFilterPkt();
#endif
						cm_requestNetworkCost();
#ifdef RTCONFIG_WIFI_SON
						if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
						{
#ifdef ONBOARDING
						/* update onboarding vsie */
						cm_updateOnboardingVsie(OB_TYPE_OFF);
#endif
						cm_requestReList();
#ifdef DUAL_BAND_DETECTION
						cm_requestDualBandList();
#endif
						/* reset chanspec */
						cm_resetChanspec();
						} /* !wifison_ready */

						/* update wired client list */
						cm_udpateWiredClientList();

						nvram_set("cfg_alive", "1");
						cm_reportConnStatus();
						if (!cm_checkCfgState(1))
							curState = DISCONN;
						cm_reportStaList();

						if (curState == CONN) {
							curState = PERCHECK;
							schedKeepAliveCount = 0;
						}
					}
					break;
				case DISCONN:
				case PENDING:
					cm_cleanDisconnection();
					nvram_set("cfg_alive", "0");
					if (curState == PENDING)
						sleep(nvram_get_int("cfg_pending_time") ? : PENDING_TIME);
					curState = REKEY;
					break;
				case PERCHECK:
					break;
				case IMMCHECK:
					cm_checkCfgState(0);
					cm_applyCfgAction(0);
					curState = PERCHECK;
					break;
				case GREKEY:
					pCtrlBK->groupKeyReady = 0;
					if (cm_askGroupKey())
						curState = PERCHECK;
					break;
#ifdef MASTER_DET
				case RESTART:
					if (!cm_detectMaster(NULL)) {
						lastState = INIT;
						curState = REKEY;
						sleep(INTERVAL_RETRY_CONNECT);
					}
					else
						curState = INIT;
					break;
#endif
			}
		}
		else
		{
			/* need to check the status on scheduler */
			if (curState == PERCHECK) {
				if (lastSchedKeepAliveStatus == get_sched_status())
					schedKeepAliveCount++;
				else
					schedKeepAliveCount = 0;

				lastSchedKeepAliveStatus = get_sched_status();

				if (schedKeepAliveCount >= SCHEDULER_KEEPALIVE_THRESHOLD) {
					DBG_LOG("scheduler does not alive (%d)", schedKeepAliveCount);
					cm_terminateHandle(-1);
					//notify_rc("restart_cfgsync");
					exit(0);
				}
			}
			else if (curState == REKEY)	/* change state to INIT */
				curState = INIT;
			else if (curState == INIT || curState == DISCONN)	/* change state to REKEY */
				curState = REKEY;
		}

		usleep(PERIODIC_EXECUTION_TIME);
	}
} /* End of cm_start */

/*
========================================================================
Routine Description:
	Get interface information, such as IP, AddrNetmask, broadcast addr, etc.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
static int cm_getIfInfo(CM_CTRL *pCtrlBK)
{
	int sockIf;
	struct ifreq reqIf;
	char *pMac = NULL;

	/* init */
	snprintf(reqIf.ifr_name, IFNAMSIZ, "%s", LAN_IFNAME);

	/* open a UDP socket */
	if ((sockIf = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		DBG_ERR("open socket failed!");
		return 0;
	}

	/* get own addr */
	if (ioctl(sockIf, SIOCGIFADDR, (long) &reqIf) < 0) {
		DBG_ERR("get own address of %s failed!", reqIf.ifr_name);
		goto err;
	}

	memmove(&pCtrlBK->ownAddr,
			&((struct sockaddr_in *) &reqIf.ifr_addr)->sin_addr,
			sizeof(pCtrlBK->ownAddr));
	DBG_INFO("own address (%d.%d.%d.%d)",
			(htonl(pCtrlBK->ownAddr.s_addr) >> 24) & 0xFF,
			(htonl(pCtrlBK->ownAddr.s_addr) >> 16) & 0xFF,
			(htonl(pCtrlBK->ownAddr.s_addr) >> 8) & 0xFF,
			(htonl(pCtrlBK->ownAddr.s_addr) & 0xFF));

	/* get broadcast address */
	if (ioctl(sockIf, SIOCGIFBRDADDR, (long) &reqIf) < 0) {
		DBG_ERR("get broadcast address failed!");
		goto err;
	}

	memmove(&pCtrlBK->broadcastAddr,
			&((struct sockaddr_in *) &reqIf.ifr_addr)->sin_addr,
			sizeof(pCtrlBK->broadcastAddr));
	DBG_INFO("broadcast address (%d.%d.%d.%d)",
			(htonl(pCtrlBK->broadcastAddr.s_addr) >> 24) & 0xFF,
			(htonl(pCtrlBK->broadcastAddr.s_addr) >> 16) & 0xFF,
			(htonl(pCtrlBK->broadcastAddr.s_addr) >> 8) & 0xFF,
			(htonl(pCtrlBK->broadcastAddr.s_addr) & 0xFF));

	close(sockIf);

	/* get bridge mac */
	pMac = get_hwaddr(LAN_IFNAME);
	if (pMac) {
		memset(pCtrlBK->brIfMac, 0, sizeof(pCtrlBK->brIfMac));
		snprintf(pCtrlBK->brIfMac, sizeof(pCtrlBK->brIfMac), "%s", pMac);
		DBG_INFO("br0 mac(%s)", pCtrlBK->brIfMac);
		free(pMac);
	}

	return 1;

err:
	close(sockIf);
	return 0;
} /* End of cm_getIfInfo */

/*
========================================================================
Routine Description:
	Close socket.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
static void cm_closeSocket(CM_CTRL *pCtrlBK)
{
	if (pCtrlBK->socketTCPSend >= 0)
		close(pCtrlBK->socketTCPSend);

	if (pCtrlBK->socketUdpSendRcv >= 0)
		close(pCtrlBK->socketUdpSendRcv);

	if (pCtrlBK->socketIpcSendRcv >= 0)
		close(pCtrlBK->socketIpcSendRcv);
} /* End of cm_closeSocket */

/*
========================================================================
Routine Description:
	Open socket.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	1		- open successfully
	0		- open fail

Note:
========================================================================
*/
static int cm_openSocket(CM_CTRL *pCtrlBK)
{
	struct sockaddr_in sock_addr_tcp;
	struct sockaddr_in sock_addr_udp;
	struct sockaddr_un sock_addr_ipc;
	int broadcast = 1;
	int reused = 1;
	char *udpBindingIf = nvram_safe_get("lan_ifname");

	/* init */
	pCtrlBK->socketTCPSend = -1;
	pCtrlBK->socketUdpSendRcv = -1;
	pCtrlBK->socketIpcSendRcv = -1;

	/* Open TCP socket for accepting connection from other AP */
	pCtrlBK->socketTCPSend = socket(AF_INET, SOCK_STREAM, 0);

	if (pCtrlBK->socketTCPSend < 0){
		DBG_ERR("Failed to TCP socket create!");
		goto err;
	}

        /* set socket reusable */
	if (setsockopt(pCtrlBK->socketTCPSend, SOL_SOCKET, SO_REUSEADDR,
			&reused, sizeof(reused)) < 0) {
		DBG_ERR("Failed to setsockopt(SO_REUSEADDR)");
		goto err;
	}

	/* bind the Rcv TCP socket */
	memset(&sock_addr_tcp, 0, sizeof(sock_addr_tcp));
	sock_addr_tcp.sin_family = AF_INET;
	sock_addr_tcp.sin_addr.s_addr = INADDR_ANY;
	sock_addr_tcp.sin_port = htons(port);

	if (bind(pCtrlBK->socketTCPSend, (struct sockaddr*)&sock_addr_tcp, sizeof(struct sockaddr_in)) < 0)
	{
		DBG_ERR("Failed to bind()!");
		goto err;
	}

	listen(pCtrlBK->socketTCPSend, 10); /* max 10 TCP connections simultaneously */


	/* open a Send UDP socket */
	if ((pCtrlBK->socketUdpSendRcv = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		DBG_ERR("Failed to UDP socket create!");
		goto err;
	}

	/* bind the Send/Rcv UDP socket */
	memset(&sock_addr_udp, 0, sizeof(sock_addr_udp));
	sock_addr_udp.sin_family = AF_INET;
	sock_addr_udp.sin_addr.s_addr = INADDR_ANY;
	sock_addr_udp.sin_port = htons(port);

	if (bind(pCtrlBK->socketUdpSendRcv, (struct sockaddr *)&sock_addr_udp, sizeof(sock_addr_udp)) < 0)
	{
		DBG_ERR("Failed to bind()!");
		goto err;
	}

	/* bind interface */
	if (strlen(udpBindingIf) > 0 && setsockopt(pCtrlBK->socketUdpSendRcv, SOL_SOCKET, SO_BINDTODEVICE,
		udpBindingIf, strlen(udpBindingIf)) < 0) {
		DBG_ERR("setsockopt-SO_BINDTODEVICE failed!");
		goto err;
	}

	/* use broadcast address */
	if (setsockopt(pCtrlBK->socketUdpSendRcv, SOL_SOCKET, SO_BROADCAST,
				&broadcast, sizeof(broadcast)) < 0)
	{
		DBG_ERR("setsockopt-SO_BROADCAST failed!");
		goto err;
	}

	/* IPC Socket */
	if ( (pCtrlBK->socketIpcSendRcv = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DBG_ERR("Failed to IPC socket create!\n");
		goto err;
	}

	memset(&sock_addr_ipc, 0, sizeof(sock_addr_ipc));
	sock_addr_ipc.sun_family = AF_UNIX;
	snprintf(sock_addr_ipc.sun_path, sizeof(sock_addr_ipc.sun_path), "%s", CFGMNT_IPC_SOCKET_PATH);
	unlink(CFGMNT_IPC_SOCKET_PATH);

	if (bind(pCtrlBK->socketIpcSendRcv, (struct sockaddr*)&sock_addr_ipc, sizeof(sock_addr_ipc)) < -1) {
		DBG_ERR("Failed to IPC socket bind!\n");
		goto err;
	}

	if (listen(pCtrlBK->socketIpcSendRcv, CFGMNT_IPC_MAX_CONNECTION) == -1) {
		DBG_ERR("Failed to IPC socket listen!\n");
		goto err;
	}

	return 1;

err:
	cm_closeSocket(pCtrlBK);
	return 0;
} /* End of cm_openSocket */

/*
========================================================================
Routine Description:
	Main task.

Arguments:
	*pContext	- CM control block

Return Value:
	None

Note:
========================================================================
*/
void cm_task(void *pContext)
{
	CM_CTRL *pCtrlBK = (CM_CTRL *)pContext;

	DBG_INFO("task start");

	/* init role */
	pCtrlBK->role = IS_CLIENT;
#ifdef RTCONFIG_BHCOST_OPT
	int aimesh_alg = nvram_get_int("aimesh_alg") ?: AIMESH_ALG_COST;
#endif

	/* create folder */
	if(!check_if_dir_exist(CFG_MNT_FOLDER)) {
		DBG_INFO("create a folder for cfg_mnt (%s)", CFG_MNT_FOLDER);
		mkdir(CFG_MNT_FOLDER, 0755);
	}

	/* init the cost of network topology */
	pCtrlBK->cost = -1;

	/* get the number of supported band */
	supportedBandNum = num_of_wl_if();

	/* init group info */
	if (strlen(nvram_safe_get("cfg_group"))) {
		memset(groupID, 0, sizeof(groupID));
		snprintf(groupID, sizeof(groupID), "%s", nvram_safe_get("cfg_group"));
	}
	else
	{
#ifdef ONBOARDING
		int groupIdReady = 0;

		do {
			if (cm_requestGroupId()) {
				if (strlen(nvram_safe_get("cfg_group"))) {
					memset(groupID, 0, sizeof(groupID));
					snprintf(groupID, sizeof(groupID), "%s", nvram_safe_get("cfg_group"));
					groupIdReady = 1;
					break;
				}
			}
		} while (cm_detectMaster(serverIp));

		if (!groupIdReady)
			goto err;
#else
		DBG_ERR("doesn't set group id");
		goto err;
#endif
	}

	 /* init expired time for session key and group key */
	if (strlen(nvram_safe_get("cfg_sket")))
		sessionKeyExpireTime = nvram_get_int("cfg_sket");
	if (strlen(nvram_safe_get("cfg_gket")))
		groupKeyExpireTime = nvram_get_int("cfg_gket");

	/* unset/reset some nvram */
	nvram_unset("cfg_fwstatus");
#ifdef RTCONFIG_BHCOST_OPT
	if (aimesh_alg != AIMESH_ALG_COST)  // New cost alg, unset cost action in amas_bhctrl
#endif
	nvram_unset("cfg_cost");
	nvram_set("cfg_alive", "0");
#ifdef PRELINK
	nvram_unset("amas_hashbdlkey");
#endif

#ifdef ONBOARDING_VIA_VIF
	nvram_unset("wps_via_vif");
	nvram_unset("cfg_obvif_up");
#endif

#ifdef RTCONFIG_NBR_RPT
	/* reset nbr version for private */
	nvram_unset("cfg_nbr_ver");
#endif

	/* unset sync stage */
	nvram_unset("cfg_sync_stage");

#ifdef DUAL_BAND_DETECTION
	if (!cm_initDBListSharedMemory()) goto err;
#endif

#ifdef RTCONFIG_BHCOST_OPT
	if (aimesh_alg != AIMESH_ALG_COST)
		update_lldp_cost(-1);  /* update network cost */

	/* update rssi score */
	update_rssiscore(100);

	/* set wireless last byte to lldpd */
    set_wifi_lastbyte();

#ifdef RTCONFIG_FRONTHAUL_DWB
	check_fronthaul_dwb_value();
#endif
#endif

#ifdef ONBOARDING
#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	/* init onboarding status */
	cm_initOnboardingStatus();
#endif

	/* init signal functions */
	signal(SIGTERM, cm_terminateHandle);

	/* display client info */
	signal(SIGUSR1, cm_usr1Handle);

	/* timer for check config status */
	//signal(SIGALRM, cm_alrmHandle);

	/* init mutex for thread */
	if (!cm_initThreadMutex())
		goto err;

	/* get interface info */
	if (!cm_getIfInfo(pCtrlBK)) {
		DBG_ERR("get interface information failed");
		goto err;
	}

	/* init socket */
	if (cm_openSocket(pCtrlBK) == 0)
		goto err;

	/* save pid */
	cm_saveDaemonPid();

	/* start CM function */
	cm_start(pCtrlBK);

err:

	return;
} /* End of cmd_task */

#ifdef MASTER_DET
/*
========================================================================
Routine Description:
	Detect master and ip.

Arguments:
	invalidMasterIp		- invalid master's IP

Return Value:
	0		- no mater
	1		- have master

Note:
========================================================================
*/
int cm_detectMaster(char *invalidMasterIp)
{
	char *nv, *nvp, *b;
	char *modelNmae, *ip, *mac, *isMaster;
	int ret = 0;
	int passMaster = 0;
	int i = 0;

	if (!invalidMasterIp) {
		/* scan all asus devcie */
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIFI_SON)
		if (nvram_match("wifison_ready", "1") && (sw_mode() == SW_MODE_AP && !nvram_match("cfg_master", "1"))) {
			eval("asusdiscovery");
		} else {
#endif	/* RTCONFIG_QCA && RTCONFIG_WIFI_SON */
		nvram_unset("cfg_device_list");
		eval("asusdiscovery");

		/* check scan done or not */
		while (i < 5) {
			if (nvram_get("cfg_device_list")) break;
			i++;
			sleep(2);
		}
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIFI_SON)
		}
#endif	/* RTCONFIG_QCA && RTCONFIG_WIFI_SON */
		/* reset the releated master list */
		if (masterList) {
			free(masterList);
			masterList = NULL;
		}
		masterListLen = 0;

		/* record master list */
		masterListLen = strlen(nvram_safe_get("cfg_device_list"));
		if (masterListLen) {
			if ((masterList = (char *)malloc(masterListLen + 1)) == NULL) {
				DBG_ERR("malloc failed for master list");
				return 0;
			}

			memset(masterList, 0, masterListLen + 1);
			memcpy(&masterList[0], nvram_safe_get("cfg_device_list"), masterListLen);
			DBG_LOG("master list (%s), master list len (%d)", masterList, masterListLen);
		}
		else
		{
			DBG_LOG("no master list");
			return 0;
		}
	}
	else
	{
		DBG_LOG("invalid master's ip (%s), need to pass", invalidMasterIp);
		masterDisconnectCount = 0;
	}

	if (masterList) {
		nv = nvp = strdup(masterList);
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (strlen(b) == 0)
					continue;

				if ((vstrsep(b, ">", &modelNmae, &ip, &mac, &isMaster) != 4))
					continue;

				if (invalidMasterIp && !passMaster) {
					if (!strcmp(ip, invalidMasterIp)) {
						passMaster = 1;
						continue;
					}

					if (!passMaster)
						continue;
				}

				if (atoi(isMaster) && strcmp(mac, get_unique_mac())) {
					memset(serverIp, 0, sizeof(serverIp));
					snprintf(serverIp, sizeof(serverIp), "%s", ip);
					nvram_set("amas_cap_mac", mac);
					nvram_set("amas_cap_modelname", modelNmae);
					ret = 1;
					break;
				}
			}
			free(nv);
		}
	}

	if (ret)
		DBG_LOG("got master (%s)", serverIp);
	else
		DBG_LOG("no master be selected");

	return ret;
} /* End of cm_detectMaster */
#endif	/* MASTER_DET */

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
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	pid_t pid;
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif

#if defined(RTCONFIG_LANTIQ)
	while( !nvram_get_int("wave_ready") )
		sleep(5);
#elif defined(RTCONFIG_QCA)
	while( !nvram_get_int("wlready") )
		sleep(5);
#endif

#ifdef RTCONFIG_SW_HW_AUTH
#if defined(RTCONFIG_AMAS)
	/* check supported mode */
	if (!(getAmasSupportMode() & AMAS_RE)) {
#if defined(RTCONFIG_WIFI_SON)
          if(nvram_match("wifison_ready", "1"))
		goto skip;
#endif
		DBG_ERR("not support RE");
		goto err;
	}
#endif

#if defined(RTCONFIG_SW_CTRL_ALLLED) && defined(RTCONFIG_QCA)
	if (!nvram_get("led_val") || !nvram_match("AllLED", nvram_safe_get("led_val")))
		nvram_set_int("led_val", !!nvram_get_int("AllLED"));
#endif

#if defined(RTCONFIG_WIFI_SON) && defined(RTCONFIG_AMAS)
skip:
#endif

	/* auth check for daemon */
	if (!check_auth()) {
		DBG_ERR("auth check failed, exit");
		goto err;
	}
	else
		DBG_INFO("auth check success");
#else
	DBG_ERR("auth check is disabled, exit");
	goto err;
#endif	/* RTCONFIG_SW_HW_AUTH */

	/* init */
	memset(pCtrlBK, 0, sizeof(CM_CTRL));

	/* kill old daemon if exists */
	cm_killDaemon();

	/* Reset level & maxlevel */
	nvram_set_int("cfg_maxlevel", -1);
	nvram_set_int("cfg_level", -1);

	/* set dut band_type */
	check_band_type();
	
	/* get server ip */
#ifdef MASTER_DET
	if (!cm_detectMaster(NULL))
		goto err;
#else
	memset(serverIp, 0, sizeof(serverIp));
	snprintf(serverIp, sizeof(serverIp), "%s", nvram_safe_get("lan_gateway"));
#endif

	/* fork a 'background' process */
	pid = fork(); /* two PID is established,
					non-zero: parent process, zero: child process */
	if (pid < 0)
		goto err; /* fork fail */
	else if (pid != 0)
		exit(0); /* end up parent process */
	/* End of if */

#ifdef PTHREAD_STACK_SIZE
	attrp = &attr;
	/* change the default stack size of pthread */
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif

	cm_task((void *)pCtrlBK);

	DBG_INFO("exit daemon!");
	return 0;

err:
	exit(-1);

	return 0;
}

#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
void cm_mac2ip(char *mac,char *ip,int ip_len){
	;
}
#endif //#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
