#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/un.h>
#include <shared.h>
#include <shutils.h>
#if defined(RTCONFIG_RALINK)
#include "ralink.h"
#endif
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_roaming.h"
#include "cfg_udp.h"
#include "cfg_dencrypt.h"
#ifdef ROAMING_INFO
#include "cfg_roaminginfo.h"
#endif

/* for romaing event */
struct eventHandler 
{
    int type;
    int (*func)(unsigned char *data);
};

int cm_processStaMon(unsigned char *data);
int cm_processStaMonReport(unsigned char *data);
int cm_processStaAcl(unsigned char *data);

#define RAST_PKT_BUF_LEN 1024

struct eventHandler eventHandlers[] = {
	{ EID_RM_STA_MON, cm_processStaMon },
	{ EID_RM_STA_MON_REPORT, cm_processStaMonReport },
	{ EID_RM_STA_ACL, cm_processStaAcl },
	{-1, NULL }	
};

/* for roaming packet */
struct rmPacketHandler
{
    int type;
    int (*func)(unsigned char *data, size_t dataLen, char *peerIp);
};

int cm_processREQ_STAMON(unsigned char *data, size_t dataLen, char *peerIp);
int cm_processRSP_STAMON(unsigned char *data, size_t dataLen, char *peerIp);
int cm_processREQ_ACL(unsigned char *data, size_t dataLen, char *peerIp);
int cm_processREQ_STAFILTER(unsigned char *data, size_t dataLen, char *peerIp);
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
int cm_processREQ_EXAPCHECK(unsigned char *data, size_t dataLen, char *peerIp);
#endif
struct rmPacketHandler rmPacketHandlers[] = {
	{ REQ_STAMON, cm_processREQ_STAMON },
	{ RSP_STAMON, cm_processRSP_STAMON },
	{ REQ_ACL, cm_processREQ_ACL },
	{ REQ_STAFILTER, cm_processREQ_STAFILTER },
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP	
	{ REQ_EXAPCHECK, cm_processREQ_EXAPCHECK },
#endif	
	{-1, NULL }
};

#ifdef RTCONFIG_BCN_RPT
void cm_getBeaconReport(char* staMac, json_object** MonitorRoot);
#endif
/*
========================================================================
Routine Description:
	Send event to roaming assistant.

Arguments:
        *data		- data from rast of other AP

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendEventToRast(unsigned char *data)
{
	int fd = -1;
	int length = 0;
	int ret = 0;
	struct sockaddr_un addr;
	int flags;
	int status;
	socklen_t statusLen;
	fd_set writeFds;
	int selectRet;
	struct timeval timeout = {2, 0};

	DBG_INFO("enter");

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DBG_ERR("ipc socket error!");
		goto err;
	}

	/* set NONBLOCK for connect() */
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		DBG_ERR("F_GETFL error!");
		goto err;
	}

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0) {
		DBG_ERR("F_SETFL error!");
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, RAST_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno == EINPROGRESS) {
			FD_ZERO(&writeFds);
			FD_SET(fd, &writeFds);

			selectRet = select(fd + 1, NULL, &writeFds, NULL, &timeout);

			//Check return, -1 is error, 0 is timeout
			if (selectRet == -1 || selectRet == 0) {
				DBG_ERR("ipc connect error");
				goto err;
			}
		}
		else
		{
			DBG_ERR("ipc connect error");
			goto err;
		}
	}

	/* check the status of connect() */
	status = 0;
	statusLen = sizeof(status);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
		DBG_ERR("getsockopt(SO_ERROR): %s", strerror(errno));
		goto err;
	}

	length = write(fd, data, strlen((char *)data));

	if (length < 0) {
		DBG_ERR("error writing:%s", strerror(errno));
		goto err;
	}

	ret = 1;

	DBG_INFO("send event to rast (%s)", (char *)data);

err:
	if (fd >= 0)
        	close(fd);

	DBG_INFO("leave");
	return ret;
} /* End of cm_sendEventToRast */

/*
========================================================================
Routine Description:
	Convert json from the rast of other AP to the rast of myself 

Arguments:
	*inData		- data from rast
	*peerIp		- the ip of peer AP
	*outData	- converted data for rast
	*outDataLen	- the buf length of outData

Return Value:
	data length of converted data

========================================================================
*/
int cm_convertData(unsigned char *inData, char *peerIp, unsigned char *outData, size_t outDataLen)
{
	json_object *rastRoot = NULL;
	json_object *cfgRoot = NULL;
	json_object *rastObj = NULL;
	json_object *cfgObj = NULL;

	rastRoot = json_tokener_parse((char *)inData);
	json_object_object_get_ex(rastRoot, RAST_PREFIX, &rastObj);

	//DBG_INFO("inData(%s), peerIp(%s)", inData, peerIp);
	if (rastObj) {
		cfgObj = json_object_new_object();
		if (cfgObj) {
			json_object_object_foreach(rastObj, key, val) {
				json_object_object_add(cfgObj, key, json_object_new_string(json_object_get_string(val)));
			}

			if (peerIp)
				json_object_object_add(cfgObj, RAST_PEERIP, json_object_new_string(peerIp));

			cfgRoot = json_object_new_object();
			if (cfgRoot) {
				json_object_object_add(cfgRoot, CFG_PREFIX, cfgObj);
				snprintf((char *)outData, outDataLen, "%s", json_object_to_json_string(cfgRoot));
				DBG_INFO("convertedData(%s)", outData);
				json_object_put(cfgRoot);
			}
			else
				json_object_put(cfgObj);
		}
		else
			DBG_INFO("cfgObj is NULL");
	}

	json_object_put(rastRoot);

	return strlen((char *)outData);
} /* End of cm_convertData */

/*
========================================================================
Routine Description:
	Process REQ_STAMON packet.

Arguments:
	data		- data from rast

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_STAMON(unsigned char *data, size_t dataLen, char *peerIp)
{
	unsigned char *decryptedMsg = NULL;
	unsigned char msg[RAST_PKT_BUF_LEN] = {0};
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey = cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);

	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (cm_convertData(decryptedMsg, peerIp, &msg[0], sizeof(msg)))
		cm_sendEventToRast(&msg[0]); /* send event to rast */
	
	MFREE(decryptedMsg);

	return 1;	
} /* End of cm_processREQ_STAMON */

/*
========================================================================
Routine Description:
	Process RSP_STAMON packet.

Arguments:
	data		- data from rast

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_STAMON(unsigned char *data, size_t dataLen, char *peerIp)
{
        unsigned char *decryptedMsg = NULL;
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *apObj = NULL;
	json_object *staObj = NULL;
	json_object *rssiObj = NULL;
	json_object *staRoot = NULL;
	json_object *reportApObj = NULL;
	json_object *existApObj = NULL;
	json_object *rssiCriteriaObj = NULL;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	json_object *candidatetargetmacObj = NULL;
	char candidatetargetmacStr[32] = {0};
#endif

	char apStr[32] = {0};
	char staStr[32] = {0};
	char rssiStr[8] = {0};
	char rssiCriteriaStr[8] = {0};
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;
	char rptFile[64] = {0};

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);
	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	root = json_tokener_parse((char *)decryptedMsg);
	if (root == NULL) {
		DBG_ERR("no valid content");
		MFREE(decryptedMsg);
		return 0;
	}

	json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_AP, &apObj);
	json_object_object_get_ex(rastObj, RAST_STA, &staObj);
	json_object_object_get_ex(rastObj, RAST_RSSI, &rssiObj);
	json_object_object_get_ex(rastObj, RAST_CANDIDATE_AP_RSSI_CRITERIA, &rssiCriteriaObj);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)	
	json_object_object_get_ex(rastObj, RAST_AP_TARGET_MAC, &candidatetargetmacObj);
#endif
	if (apObj && strlen(json_object_get_string(apObj)) > 0 && 
			staObj && strlen(json_object_get_string(staObj)) > 0 && 
			rssiObj && strlen(json_object_get_string(rssiObj)) > 0) {

		snprintf(rptFile, sizeof(rptFile), "%s/%s", REPORT_ROOT_PATH, json_object_get_string(staObj));
		snprintf(apStr, sizeof(apStr), "%s", json_object_get_string(apObj));
		snprintf(staStr, sizeof(staStr), "%s", json_object_get_string(staObj));
		snprintf(rssiStr, sizeof(rssiStr), "%s", json_object_get_string(rssiObj));
		if (rssiCriteriaObj)
			snprintf(rssiCriteriaStr, sizeof(rssiCriteriaStr), "%s", json_object_get_string(rssiCriteriaObj));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		if (candidatetargetmacObj)
			snprintf(candidatetargetmacStr, sizeof(candidatetargetmacStr), "%s", json_object_get_string(candidatetargetmacObj));
#endif
		pthread_mutex_lock(&roamingLock);
		if ((staRoot = json_object_from_file(rptFile)) != NULL) {
			json_object_object_get_ex(staRoot, apStr, &existApObj);
			if (existApObj == NULL) {	/* no ap report sta mon */
				reportApObj = json_object_new_object();

				if (reportApObj) {
					json_object_object_add(reportApObj, RAST_RSSI, json_object_new_string(rssiStr));
					if (strlen(rssiCriteriaStr))
						json_object_object_add(reportApObj, RAST_CANDIDATE_AP_RSSI_CRITERIA, json_object_new_string(rssiCriteriaStr));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
					if (strlen(candidatetargetmacStr))
						json_object_object_add(reportApObj, RAST_AP_TARGET_MAC, json_object_new_string(candidatetargetmacStr));
#endif
					json_object_object_add(staRoot, apStr, reportApObj);
					json_object_to_file(rptFile, staRoot);
				}
				else
					DBG_INFO("reportApObj is NULL");
			}
			json_object_put(staRoot);
		}
		else
			DBG_INFO("no file or valid content");
		pthread_mutex_unlock(&roamingLock);
	}
	else
		DBG_INFO("the content is invalid");

	json_object_put(root);

	MFREE(decryptedMsg);

	return 1;
} /* End of cm_processRSP_STAMON */

/*
========================================================================
Routine Description:
	Process REQ_ACL packet.

Arguments:
	data		- data from rast of other AP

Return Value:
	0		- fail	
	1		- success

========================================================================
*/
int cm_processREQ_ACL(unsigned char *data, size_t dataLen, char *peerIp)
{
	unsigned char *decryptedMsg = NULL;
	unsigned char msg[RAST_PKT_BUF_LEN] = {0};
#ifdef RTCONFIG_BCN_RPT
	char word[RAST_PKT_BUF_LEN], *next, *p;
	int unit = 0;
#endif
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *apObj = NULL;
	json_object *staObj = NULL;
	int fwdToRast = 1;	
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;
	char ifname[16];
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	char wlPrefix[sizeof("wlXXXXX_")], tmp[32];
#endif

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);
	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);
	
	root = json_tokener_parse((char *)decryptedMsg);
	json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_CANDIDATE_AP, &apObj);
	json_object_object_get_ex(rastObj, RAST_STA, &staObj);

	if (root && rastObj && apObj) {
#ifdef RTCONFIG_BCN_RPT
		unit = 0;
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
			if (dpsr_mode()
#ifdef RTCONFIG_DPSTA
				|| dpsta_mode()
#endif
			) {
				snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", unit);
				strlcpy(ifname, nvram_safe_get(strcat_r(wlPrefix, "ifname", tmp)), sizeof(ifname));
			}
			else
#endif
			{
				strlcpy(ifname, word, sizeof(ifname));
			}
			p = get_hwaddr(ifname);
			if(p && !strcasecmp(json_object_get_string(apObj),p))
				fwdToRast = 0;
			if(p) {
				free(p);
				p = NULL;
			}
			unit++;
		}
#endif
		if (!strcasecmp(json_object_get_string(apObj), get_lan_hwaddr())) /* don't need foward to rast */
			fwdToRast = 0;
	}

	if (fwdToRast) {	
		if (cm_convertData(decryptedMsg, NULL, &msg[0], sizeof(msg)))
			cm_sendEventToRast(&msg[0]);	/* send event to rast */
	}
#ifdef ROAMING_INFO
	else
	{
		if (staObj)
			cm_recordRoamingInfo((char *)json_object_get_string(staObj));
	}
#endif

	json_object_put(root);

	MFREE(decryptedMsg);

	return 1;
} /* End of cm_processREQ_ACL */

/*
========================================================================
Routine Description:
	Process REQ_STAFILTER packet.

Arguments:
	data		- data from rast of other AP

Return Value:
	0		- fail	
	1		- success

========================================================================
*/
int cm_processREQ_STAFILTER(unsigned char *data, size_t dataLen, char *peerIp)
{
	unsigned char *decryptedMsg = NULL;
	unsigned char msg[RAST_PKT_BUF_LEN] = {0};
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);
	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);
	snprintf((char *)msg, sizeof(msg), "%s", decryptedMsg);
	cm_sendEventToRast(&msg[0]);	/* send event to rast */
	MFREE(decryptedMsg);

	return 1;
} /* End of cm_processREQ_STAFILTER */


#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
/*
========================================================================
Routine Description:
	Process REQ_EXAPCHECK packet.

Arguments:
	data		- data from CAP

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_EXAPCHECK(unsigned char *data, size_t dataLen, char *peerIp)
{
	unsigned char *decryptedMsg = NULL;
	unsigned char msg[RAST_PKT_BUF_LEN] = {0};
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);
	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);
	snprintf((char *)msg, sizeof(msg), "%s", decryptedMsg);
	cm_sendEventToRast(&msg[0]);	/* send event to rast */
	MFREE(decryptedMsg);

	return 1;
}
#endif //#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP

/*
========================================================================
Routine Description:
	Process roaming packets.

Arguments:
	tlv		- tlv header of the packet
	*data		- data from other AP
	*peerIp		- the ip of AP

Return Value:
        None

========================================================================
*/ 
void cm_processRoamingPkt(TLV_Header tlv, unsigned char *data, char *peerIp)
{
	struct rmPacketHandler *handler = NULL;

	for(handler = &rmPacketHandlers[0]; handler->type > 0; handler++) {
		if (handler->type == ntohl(tlv.type))
			break;
	}

	if (handler == NULL || handler->type < 0)
		DBG_INFO("no corresponding function pointer(%d)", ntohl(tlv.type));
	else
	{
		DBG_INFO("process packet (%d)", handler->type);
		if (!handler->func(data, ntohl(tlv.len), peerIp)) {
			DBG_ERR("fail to process corresponding packet");
			return;
		}
	} 
} /* End of cm_processRoamingPkt */
/*
========================================================================
Routine Description:
	Send the Candidate AP To Rast.

Arguments:
	staMac		-	the sta MAC
	rssi		- 	the RSSI of client
	bestApMac	-	the MAC of best AP
	bestRssi	-	the RSSI of the best AP
	rssiCriteria-	Criteria of the best AP
	band		-	current use band

Return Value:
	None

========================================================================
*/
void cm_sendApCandidate(char *staMac, int rssi, char* bestApMac, int bestRssi, int rssiCriteria, char* band
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	, char *bestApWifiIfMac
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming, int force_roaming_blocktime
#endif
#endif	
	)
{

	unsigned char msg[RAST_PKT_BUF_LEN] = {0};
	char eventId[8] = {0};
	json_object *cfgRoot = NULL;
	json_object *resultObj = NULL;
	
	cfgRoot = json_object_new_object();
	resultObj = json_object_new_object();

	if (cfgRoot && resultObj) {
		DBG_INFO("got best ap(%s), rssi(%d), rssiCriteria(%d)", bestApMac, bestRssi, rssiCriteria);

		snprintf(eventId, sizeof(eventId), "%d", EID_RM_STA_CANDIDATE);
		json_object_object_add(resultObj, RAST_EVENT_ID, json_object_new_string(eventId));
		json_object_object_add(resultObj, RAST_STA, json_object_new_string(staMac));
		json_object_object_add(resultObj, RAST_STA_RSSI, json_object_new_int(rssi));
		json_object_object_add(resultObj, RAST_CANDIDATE_AP, json_object_new_string(bestApMac));
		json_object_object_add(resultObj, RAST_CANDIDATE_AP_RSSI, json_object_new_int(bestRssi));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		if( strlen(bestApWifiIfMac) )
			json_object_object_add(resultObj, RAST_AP_TARGET_MAC, json_object_new_string(bestApWifiIfMac));
#ifdef RTCONFIG_FORCE_ROAMING		
		json_object_object_add(resultObj, RAST_FORCE_ROAMING, json_object_new_int(force_roaming));
		json_object_object_add(resultObj, RAST_FORCE_ROAMING_BLOCKTIME, json_object_new_int(force_roaming_blocktime));
#endif
#endif
		if (rssiCriteria != 0)
			json_object_object_add(resultObj, RAST_CANDIDATE_AP_RSSI_CRITERIA, json_object_new_int(rssiCriteria));
		if (strlen(band))
			json_object_object_add(resultObj, RAST_BAND, json_object_new_string(band));
		json_object_object_add(cfgRoot, CFG_PREFIX, resultObj);
		snprintf((char *)&msg[0], sizeof(msg), "%s", json_object_to_json_string(cfgRoot));

		json_object_put(cfgRoot);

		/* send event to rast */
		cm_sendEventToRast(&msg[0]);
	} else {
		DBG_INFO("cfgRoot or resultObj is NULL");
		json_object_put(cfgRoot);
		json_object_put(resultObj);
	}

}/*endof cm_sendApCandidate*/

/*
========================================================================
Routine Description:
	Select the best AP for roaming.

Arguments:
	staMac		- the sta mac
	rssi            - rssi that reported by self.

Return Value:
	None

========================================================================
*/
void cm_selectApCandidate(char *staMac, int rssi
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming,int force_roaming_blocktime,char *target
#endif
	)
{
	int gotBestAp = 0;
	char bestApMac[32] = {0};
	int bestRssi = rssi;
	char rptFile[64] = {0};
	json_object *root = NULL;
	char band[8] = {0};
	int rssiTolerance = 0;
	json_object *rssiObj = NULL;
	json_object *bandObj = NULL;
	json_object *rssiCriteriaObj = NULL;
	int rssiCriteria = 0;

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	char bestApWifiIfMac[32] = {0};
	json_object *candidatetargetmacObj = NULL;
#endif

#ifdef RTCONFIG_FORCE_ROAMING
	if( (strlen(target) == 0) ) {
#endif	

	snprintf(rptFile, sizeof(rptFile), "%s/%s", REPORT_ROOT_PATH, staMac);

	pthread_mutex_lock(&roamingLock);
	root = json_object_from_file(rptFile);
	pthread_mutex_unlock(&roamingLock);

	/* get roaming rssi tolerance */
	rssiTolerance = (nvram_get("cfg_rrt")) ? nvram_get_int("cfg_rrt"): ROAMING_RSSI_TOLERANCE;
	bestRssi += rssiTolerance;
	DBG_INFO("best rssi (%d), roaming rssi tolerance (%d)", bestRssi, rssiTolerance);
	if (root != NULL) {
		
		json_object_object_foreach(root, key, val) {
			if (!strcmp(key, RAST_BAND)) {
				json_object_object_get_ex(val, RAST_BAND, &bandObj);
				if (bandObj) {
					snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));
					DBG_INFO("band info (%s) for %s", band, staMac);
				}
				else
					DBG_INFO("no band info for %s", staMac);
				continue;
			}

			json_object_object_get_ex(val, RAST_RSSI, &rssiObj);
			json_object_object_get_ex(val, RAST_CANDIDATE_AP_RSSI_CRITERIA, &rssiCriteriaObj);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			json_object_object_get_ex(val, RAST_AP_TARGET_MAC, &candidatetargetmacObj);
#endif
			if (rssiObj) {
				DBG_INFO("ap(%s), rssi(%s)", key, json_object_get_string(rssiObj));
				if (atoi(json_object_get_string(rssiObj)) > bestRssi) {
					bestRssi = atoi(json_object_get_string(rssiObj));
					if (rssiCriteriaObj)
						rssiCriteria = atoi(json_object_get_string(rssiCriteriaObj));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
					if (candidatetargetmacObj)
						snprintf(bestApWifiIfMac, sizeof(bestApWifiIfMac), "%s", json_object_get_string(candidatetargetmacObj));
#endif
					gotBestAp = 1;
					memset(bestApMac, 0, sizeof(bestApMac));
					snprintf(bestApMac, sizeof(bestApMac), "%s", key);
				} 
			}
		} 
	}
	else
		DBG_INFO("no file or no valid content");

	json_object_put(root);
	pthread_mutex_lock(&roamingLock);
	unlink(rptFile);
	pthread_mutex_unlock(&roamingLock);

#ifdef RTCONFIG_FORCE_ROAMING
	} else {
	snprintf(rptFile, sizeof(rptFile), "%s/%s", REPORT_ROOT_PATH, staMac);

	pthread_mutex_lock(&roamingLock);
	root = json_object_from_file(rptFile);
	pthread_mutex_unlock(&roamingLock);
	if (root != NULL) {
		json_object_object_foreach(root, key, val) {
			if (!strcmp(key, RAST_BAND)) {
				json_object_object_get_ex(val, RAST_BAND, &bandObj);
				if (bandObj) {
					snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));
					DBG_INFO("band info (%s) for %s", band, staMac);
				}
				else
					DBG_INFO("no band info for %s", staMac);
				break;
			}
		}
	}
	json_object_put(root);
	pthread_mutex_lock(&roamingLock);
	unlink(rptFile);
	pthread_mutex_unlock(&roamingLock);
		bestRssi = -10; //just a value to make sure force roaming work well
		gotBestAp = 1;
		strncpy(bestApMac,target,sizeof(bestApMac));
	}
#endif


	if (gotBestAp) {
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		cm_sendApCandidate(staMac, rssi, bestApMac, bestRssi, rssiCriteria, band, bestApWifiIfMac
#ifdef RTCONFIG_FORCE_ROAMING
				,force_roaming, force_roaming_blocktime
#endif
			);
#else		
		cm_sendApCandidate(staMac, rssi, bestApMac, bestRssi, rssiCriteria, band);
#endif		
	}
} /* End of cm_selectApCandidate */
#if RTCONFIG_BCN_RPT
/*
========================================================================
Routine Description:
	Select the best AP report by Beacon Report for roaming.

Arguments:
	staMac		- the sta mac

Return Value:
	None

========================================================================
*/
int cm_selectApCandidatebyBeaconReport(char* staMac, int rssi) {
// get report list
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt";
	json_object *bcnRoot = NULL;
	json_object *currentAPObj = NULL;
	json_object *bandObj = NULL;
	json_object *tmpINFOObj = NULL;
	json_object *tmpRCPIObj = NULL;
	json_object *APListRoot = NULL;
	int gotBestAp = 0;
	char bestApMac[32] = {0};
	char band[8] = {0};
	int lock;
	int currentRCPI = 0, rcpiTolerance = 0, BestRCPI = 0;
	const char* APlist;

	snprintf(path, sizeof(path), "/tmp/%s_bcn_rpt", staMac);
	lock = file_lock(path+5);
	bcnRoot = json_object_from_file(path);
	if(!bcnRoot) {
		DBG_ERR("report file read err");
		goto err;
	}

	if(json_object_object_length(bcnRoot) < 4) {
		DBG_INFO("Meaningless to compare the result of beacon report");
		// 1. BAND 2. AP 3. BSSID1 4. BSSID2
		//if len < 3 means only one BSSID in the report, No comparison object.
		goto err;
	}
	
	json_object_object_get_ex(bcnRoot, RAST_BAND, &bandObj);
	if (bandObj) {
		snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));
		DBG_INFO("band info (%s) for %s", band, staMac);
	}

	json_object_object_get_ex(bcnRoot, RAST_AP, &currentAPObj);
	if(!currentAPObj) {
		DBG_ERR("No current AP record in the file");
		goto err;
	}
	DBG_INFO("current APOBJ %s\n", json_object_get_string(currentAPObj));
	// get current AP record from the bcn report

	json_object_object_get_ex(bcnRoot, json_object_get_string(currentAPObj), &tmpINFOObj);
	if(!tmpINFOObj)	goto err;

	json_object_object_get_ex(tmpINFOObj, RAST_RCPI, &tmpRCPIObj);
	if(!tmpRCPIObj) goto err;

	currentRCPI = json_object_get_int(tmpRCPIObj);
	DBG_INFO("current RCPI %d\n", currentRCPI);

	rcpiTolerance = (nvram_get("cfg_rrt")) ? nvram_get_int("cfg_rrt"): ROAMING_RSSI_TOLERANCE;
	BestRCPI = currentRCPI + rcpiTolerance;

	DBG_INFO("best rssi (%d), roaming rssi tolerance (%d)", BestRCPI, rcpiTolerance);

	APListRoot = json_object_from_file(AP_LIST_JSON_FILE);
	if(!APListRoot) {
		DBG_ERR("APList read err");
		goto err;
	}
	APlist = json_object_to_json_string(APListRoot);
	json_object_object_foreach(bcnRoot, key, val) {
		if (!strcmp(key, RAST_BAND) || !strcmp(key, RAST_AP)) {
			continue;
		}
		if(!strstr(APlist, key)) {
			// MAC cannot be found in APlist
			DBG_INFO("MAC %s cannot be found in Mesh Work", key);
			continue;
		}

		tmpRCPIObj = NULL;
		json_object_object_get_ex(val, RAST_RCPI, &tmpRCPIObj);

		if(!tmpRCPIObj)	continue;

		if(BestRCPI < json_object_get_int(tmpRCPIObj)) {
			BestRCPI = json_object_get_int(tmpRCPIObj);
			gotBestAp = 1;
			memset(bestApMac, 0, sizeof(bestApMac));
			snprintf(bestApMac, sizeof(bestApMac), "%s", key);
		}

	}

err:
	json_object_put(APListRoot);
	json_object_put(bcnRoot);
	unlink(path);
	file_unlock(lock);

/* 	rssiCriteria will be set to 0, because beacon report cannot get Criteria 
 * 	of the other client
 * 
 */
	if(gotBestAp) {
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		cm_sendApCandidate(staMac, currentRCPI, bestApMac, BestRCPI, 0, band, bestApMac
#ifdef RTCONFIG_FORCE_ROAMING
				,0,0
#endif
			);
#else		
		cm_sendApCandidate(staMac, currentRCPI, bestApMac, BestRCPI, 0, band);
#endif	
	}

	return gotBestAp;
}



#endif //RTCONFIG_BCN_RPT end
/*
========================================================================
Routine Description:
	Process EID_RM_STA_MON event.

Arguments:
	data		- data from rast

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processStaMon(unsigned char *data)
{
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *staObj = NULL;
	json_object *rssiObj = NULL;
	json_object *staRptObj = NULL;
	json_object *bandObj = NULL;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)	
	json_object *supportkvObj = NULL;
	json_object *rssiinfogathermethodObj = NULL;
#endif
#ifdef RTCONFIG_FORCE_ROAMING
	json_object *forceroamingObj = NULL;
	json_object *forceroamingblocktimeObj = NULL;
	json_object *forceroamingtargetObj = NULL;
	int force_roaming=0;
	int force_roaming_blocktime=0;
	char fr_target[18] = {0};
#endif	
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	char peerIp[32] = {0};
	char staMac[32] = {0};
	char rptFile[64] = {0};
	unsigned char *groupKey = NULL;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)	
	int support_k=0;
	int stamon_or_11k=RSSI_INFO_GATHER_BY_STAMON;//default
#endif
	/* record sta mac and rssi, and then waiting for the report of sta mon */
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_STA, &staObj);
	json_object_object_get_ex(rastObj, RAST_RSSI, &rssiObj);
	json_object_object_get_ex(rastObj, RAST_BAND, &bandObj);

#ifdef RTCONFIG_FORCE_ROAMING
	json_object_object_get_ex(rastObj, RAST_FORCE_ROAMING, &forceroamingObj);
	if( forceroamingObj ){
		force_roaming = json_object_get_int(forceroamingObj);
		DBG_INFO("force_roaming %d\n",force_roaming);
	}
	if(force_roaming){
		json_object_object_get_ex(rastObj, RAST_FORCE_ROAMING_BLOCKTIME, &forceroamingblocktimeObj);
		if( forceroamingblocktimeObj )
			force_roaming_blocktime = json_object_get_int(forceroamingblocktimeObj);
		json_object_object_get_ex(rastObj, RAST_FORCE_ROAMING_TARGET, &forceroamingtargetObj);
		if( forceroamingtargetObj )
			strncpy(fr_target,json_object_get_string(forceroamingtargetObj),sizeof(fr_target));

	}
#endif	

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	json_object_object_get_ex(rastObj, RAST_RSSI_INFO_GATHER_METHOD, &rssiinfogathermethodObj);

	if( rssiinfogathermethodObj )
		stamon_or_11k=json_object_get_int(rssiinfogathermethodObj);

	json_object_object_get_ex(rastObj, RAST_SUPPORT_11K, &supportkvObj);

	if( supportkvObj && json_object_get_int(supportkvObj) )
		support_k=1;

	if ( 
#ifdef RTCONFIG_FORCE_ROAMING
		( ( force_roaming && ( strlen(fr_target) == 0 ) || (!force_roaming) )
			&& (stamon_or_11k == RSSI_INFO_GATHER_BY_STAMON) )
		||
#endif
		( (!support_k) || (stamon_or_11k == RSSI_INFO_GATHER_BY_STAMON) ) ) {
#else //not defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifdef RTCONFIG_FORCE_ROAMING
		if ( (force_roaming && ( strlen(fr_target) == 0 )) || (!force_roaming) ) {
#endif
#endif
	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		goto err;
        }

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}
	
	/* encrypt data */
	encryptedMsg = cm_aesEncryptMsg(groupKey, REQ_STAMON, data, strlen((char *)data) + 1, &encLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
	}

	/* broadcast ip */
	snprintf(peerIp, sizeof(peerIp), "%d.%d.%d.%d", 
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 24) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 16) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 8) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) & 0xFF));

	/* send udp packet */
	if (cm_sendUdpPacket(peerIp, encryptedMsg, encLen) == 0) {
		DBG_ERR("Fail to send UDP packet to %s!", peerIp);
		goto err;
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
	ret = 1;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)			
	}
#else
#ifdef RTCONFIG_FORCE_ROAMING
	}
#endif	
#endif

	if (staObj && strlen(json_object_get_string(staObj)) > 0 &&
		rssiObj && strlen(json_object_get_string(rssiObj)) > 0 &&
		bandObj && strlen(json_object_get_string(bandObj)) > 0) {
		json_object *bandTempObj = NULL;

		/* create report file for sta */
		snprintf(rptFile, sizeof(rptFile), "%s/%s", REPORT_ROOT_PATH, json_object_get_string(staObj));
		DBG_INFO("create report file for sta(%s)", rptFile); 
		staRptObj = json_object_new_object();
		/* record band info in the file ("BAND": { "BAND": "wl_1"})*/
		bandTempObj = json_object_new_object();

		if (staRptObj && bandTempObj) {
			json_object_object_add(bandTempObj, RAST_BAND, json_object_new_string(json_object_get_string(bandObj)));
			json_object_object_add(staRptObj, RAST_BAND, bandTempObj);
			snprintf(staMac, sizeof(staMac), "%s", json_object_get_string(staObj));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			if(
#ifdef RTCONFIG_FORCE_ROAMING
				!force_roaming &&
#endif
				(support_k && (stamon_or_11k != RSSI_INFO_GATHER_BY_STAMON))) {
				DBG_INFO("waiting the report from target sta!");
				sleep(REPORT_WAITING_TIME);
				ret = cm_selectApCandidatebyBeaconReport(staMac, atoi(json_object_get_string(rssiObj)));
			} else {
#endif
				/* write to file */
				json_object_to_file(rptFile, staRptObj);
				json_object_put(staRptObj);

				DBG_INFO("waiting the report from all cap/re!");
				sleep(REPORT_WAITING_TIME);
				cm_selectApCandidate(staMac, atoi(json_object_get_string(rssiObj))
#ifdef RTCONFIG_FORCE_ROAMING
				,force_roaming,force_roaming_blocktime, fr_target
#endif
					);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			}
#endif
		}
		else
		{
			DBG_INFO("staRptObj or bandTempObj is NULL");
			json_object_put(staRptObj);
			json_object_put(bandTempObj);			
		}
	}
	else
		DBG_ERR("no sta and rssi info");

	json_object_put(root);

err:

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return ret;
} /* End of cm_processStaMon */

/*
========================================================================
Routine Description:
	Process EID_RM_STA_MON_REPORT event.

Arguments:
	data		- data from rast

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processStaMonReport(unsigned char *data)
{
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *pipObj = NULL;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	char peerIp[32] = {0};
	unsigned char *groupKey = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		goto err;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}
	
	/* encrypt data */
	encryptedMsg = cm_aesEncryptMsg(groupKey, RSP_STAMON, data, strlen((char *)data) + 1, &encLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
        }

        root = json_tokener_parse((char *)data);
        json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
        json_object_object_get_ex(rastObj, RAST_PEERIP, &pipObj);

	if (pipObj) {
		snprintf(peerIp, sizeof(peerIp), "%s", json_object_get_string(pipObj));
		/* send udp packet */
		if (cm_sendUdpPacket(peerIp, encryptedMsg, encLen) == 0) {
			DBG_ERR("Fail to send UDP packet to %s!", peerIp);
			goto err;
		}
	}

        if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
        ret = 1;

	json_object_put(root);
	
err:

        if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

        return ret;
} /* End of cm_processStaMonReport */

/*
========================================================================
Routine Description:
	Process EID_RM_STA_ACL event.

Arguments:
	data		- data from rast

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processStaAcl(unsigned char *data)
{        
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	char peerIp[32] = {0};
	unsigned char *groupKey = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		goto err;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* encrypt data */
	encryptedMsg = cm_aesEncryptMsg(groupKey, REQ_ACL, data, strlen((char *)data) + 1, &encLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
	}

	/* broadcast ip */
	snprintf(peerIp, sizeof(peerIp), "%d.%d.%d.%d",
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 24) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 16) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 8) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) & 0xFF));

	/* send udp packet */
	if (cm_sendUdpPacket(peerIp, encryptedMsg, encLen) == 0) {
		DBG_ERR("Fail to send UDP packet to %s!", peerIp);
		goto err;
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
	ret = 1;

err:

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return ret;
} /* End of cm_processStaAcL */

#if 0
/*
========================================================================
Routine Description:
	Response the status for rast.

Arguments:
	sock		- socket fd

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_responseRast(int sock, int eventId, int status)
{
	char msg[128] = {0};
	json_object *root = NULL;
	json_object *param = NULL;
	char eventIdStr[8] = {0};
	char statusStr[8] = {0};

	snprintf(eventIdStr, sizeof(eventIdStr), "%d", eventId);
	snprintf(statusStr, sizeof(statusStr), "%d", status);

	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(eventIdStr));
	json_object_object_add(param, RAST_STATUS, json_object_new_string(statusStr));
	json_object_object_add(root, CFG_PREFIX, param);

	snprintf(msg, sizeof(msg), "%s", json_object_to_json_string(root));
	json_object_put(root);

	if (write(sock, (char*)msg, strlen(msg)) <= 0) {
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	return 1;
} /* End of cm_responseRast */
#endif

/*
========================================================================
Routine Description:
	Send packet w/ EID_RM_STA_FILTER event out.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendStaFilterPkt()
{
	unsigned char data[RAST_PKT_BUF_LEN] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	char peerIp[32] = {0};
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	char eid[4] = {0};
	char staKey[16] = {0};
	unsigned char *groupKey = NULL;
	int concurrentRepeater = 0;
	char *bandPriority, *bandPriorityTmp, prefix[sizeof("wlXXXXX_")], staMac[18], tmp[32];
	int chkval = 0, w_index = 0, offset = 0, nband = 0;
	div_t chkval2;

#if defined(RTCONFIG_CONCURRENTREPEATER)
	concurrentRepeater = 1;
#endif
	if (nvram_get_int("re_mode") == 1)
		concurrentRepeater = 1;

	if (!concurrentRepeater)
		return ret;

	/* create EID_RM_STA_FILTER event */
	root = json_object_new_object();
	cfgObj = json_object_new_object();

	if (!root || !cfgObj) {
		DBG_ERR("root or cfgObj is NULL");
		return ret;
	}
	
	snprintf(eid, sizeof(eid), "%d", EID_RM_STA_FILTER);
	/* add event id */
	json_object_object_add(cfgObj, RAST_EVENT_ID, json_object_new_string(eid));

	/* add sta mac */
	if (concurrentRepeater) {
		bandPriority = strdup(nvram_safe_get("sta_priority"));
		if (bandPriority && strlen(bandPriority) > 0) {
			chkval = cal_space(bandPriority);
			chkval2 = div(chkval, 4);

			if (chkval2.rem == 0 && chkval2.quot != 0) {
				struct _wifi_ifinfo {
					int band;       // 2:2.4G,5:5G
					int bandIndex;  // 0,1,2...
					int priority;   // 1,2,3...
					int use;        // 0:stop connection. 1: try to connect to P-AP
				} *wifi = (struct _wifi_ifinfo *)malloc(chkval2.quot * sizeof(struct _wifi_ifinfo));

				if (wifi != NULL) {
					memset(wifi, 0x00, chkval2.quot * sizeof(struct _wifi_ifinfo));
					w_index = 0;
					offset = 0;
					bandPriorityTmp = bandPriority;
					while (sscanf(bandPriorityTmp, " %d%d%d%d%n", &wifi[w_index].band, &wifi[w_index].bandIndex, &wifi[w_index].priority, &wifi[w_index].use, &offset) == 4) {
						if (wifi[w_index].use == 1) {
							snprintf(prefix, sizeof(prefix), "wl%d_", w_index);
							memset(staKey, 0, sizeof(staKey));
							nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
							if (nband == 2)	/* 2G */
								snprintf(staKey, sizeof(staKey), "%s_2G", RAST_STA);
							else if (nband == 1)	/* 5G */
								snprintf(staKey, sizeof(staKey), "%s_5G", RAST_STA);
							else if (nband == 4)	/* 6G */
								snprintf(staKey, sizeof(staKey), "%s_6G", RAST_STA);

							/* sta info */
							if (strlen(staKey)) {
								memset(staMac, 0, sizeof(staMac));
								snprintf(staMac, sizeof(staMac), "%s", get_sta_mac(w_index));
								if (strlen(staMac))
									json_object_object_add(cfgObj, staKey, json_object_new_string(staMac));
							}
						}

						bandPriorityTmp += offset;
						if (w_index < chkval2.quot)
							w_index++;
					}
					free(wifi);
				}
			}
			free(bandPriority);
		}
	}
	else
	{
		memset(staMac, 0, sizeof(staMac));
		snprintf(staMac, sizeof(staMac), "%s", get_sta_mac(nvram_get_int("wlc_band")));
		if (strlen(staMac)) {
			snprintf(staKey, sizeof(staKey), "%s_%s", RAST_STA, nvram_get_int("wlc_band") == 0 ? "2G" : "5G");
			json_object_object_add(cfgObj, staKey, json_object_new_string(staMac));
		}
	}

	json_object_object_add(root, CFG_PREFIX, cfgObj);
	snprintf((char *)&data[0], sizeof(data), "%s", json_object_to_json_string(root));
	DBG_INFO("data(%s)", data);
	json_object_put(root);
	/* end of create EID_RM_STA_FILTER event */

	/* check key is valid or not */	
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		goto err;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* encrypt data */
	encryptedMsg = cm_aesEncryptMsg(groupKey, REQ_STAFILTER, data, strlen((char *)data) + 1, &encLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
	}

	/* broadcast ip */
	snprintf(peerIp, sizeof(peerIp), "%d.%d.%d.%d",
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 24) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 16) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 8) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) & 0xFF));

	/* send udp packet */
	if (cm_sendUdpPacket(peerIp, encryptedMsg, encLen) == 0) {
		DBG_ERR("Fail to send UDP packet to %s!", peerIp);
		goto err;
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
	ret = 1;

err:

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return ret;
} /* End of cm_sendStaFilterPkt */

/*
========================================================================
Routine Description:
	Process packets from rast.

Arguments:
	data		- received data

Return Value:
	0		- continue to receive
        1		- break to receive

========================================================================
*/
int cm_rastPacketProcess(unsigned char *data)
{
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *eidObj = NULL;
	int eid = 0;
	struct eventHandler *handler = NULL;
	int ret = 0;

	/* need check group key expired or not before using group key */
	if (cm_checkGroupKeyExpire()) { // group key expired
		DBG_ERR("group key expired");
		goto err;
	}

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_EVENT_ID, &eidObj);

	DBG_INFO("received data (%s)", (char *)data);

	if (eidObj) {
		eid = atoi(json_object_get_string(eidObj));

		for(handler = &eventHandlers[0]; handler->type > 0; handler++) {
			if (handler->type == eid)
				break;
		}

		if (handler == NULL || handler->type < 0)
			DBG_INFO("no corresponding function pointer(%d)", eid);
		else
		{
			DBG_INFO("process event (%d)", handler->type);
			if (!handler->func(data)) {
				DBG_ERR("fail to process corresponding event");
				goto err;
			}
		}	
	}

	ret = 1;
err:

	json_object_put(root);

	return ret;
} /* End of cm_rastPacketProcess */

/*
========================================================================
Routine Description:
	Create a thread to handle received packets from rast via IPC.

Arguments:
	*args		- arguments for socket

Return Value:
	None

Note:
========================================================================
*/
void *cm_rastPacketHandler(void *args)
{
	
#if defined(RTCONFIG_RALINK_MT7621)	
	Set_CPU();
#endif	
	pthread_detach(pthread_self());

	unsigned char pPktBuf[RAST_PKT_BUF_LEN] = {0};
	int len = 0;
	int newSock = *(int*)args;

 	memset(pPktBuf, 0, sizeof(pPktBuf));

	DBG_INFO("new_sock(%d)", newSock);

	/* handle the packet */
	if ((len = read(newSock, pPktBuf, sizeof(pPktBuf))) <= 0) {
		DBG_ERR("Failed to socket read()!!!");
		goto err;
	}

	/* need check group key expired or not before using group key */
	if (cm_checkGroupKeyExpire()) // group key expired
		DBG_ERR("group key expired");
	else
		cm_rastPacketProcess(pPktBuf);
	
err:
	if (newSock)
		close(newSock);

	free(args);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_rastPacketHandler */

/*
========================================================================
Routine Description:
	Handle received packets from rast via IPC.

Arguments:
	sock		- sock fd for IPC

Return Value:
	None

Note:
========================================================================
*/
void cm_rcvRastHandler(int sock)
{
	struct sockaddr_in cliSockAddr;
	int clientSock = 0, sockAddrLen = sizeof(cliSockAddr);
	pthread_t sockThread;
	int *sockArgs = malloc(sizeof(int));

	DBG_INFO("enter");

	memset(&cliSockAddr, 0, sizeof(struct sockaddr_in));

	clientSock = accept(sock, (struct sockaddr *)&cliSockAddr, (socklen_t *)&sockAddrLen);

	if (clientSock < 0) {
		DBG_ERR("Failed to socket accept() !!!");
		free(sockArgs);
		return;
	}

	//prepare related data for thread to handle packet
	*sockArgs = clientSock;

	if (pthread_create(&sockThread, attrp, cm_rastPacketHandler, sockArgs) != 0) {
		DBG_ERR("could not create thread !!!");
		free(sockArgs);
	}

	DBG_INFO("leave");
} /* End of cm_rcvRastHandler */
#ifdef RTCONFIG_BCN_RPT
/*
========================================================================
Routine Description:
	read beacon report from json file

Arguments:
	mac		- mac addr of station

Return Value:
	None

Note:
========================================================================
*/
void cm_getBeaconReport(char* staMac, json_object** MonitorRoot) {
	json_object *bcnRoot = NULL;
	json_object *APListRoot = NULL;
	json_object *bandObj = NULL;
	json_object *bandTmpObj = NULL;
	json_object *currentAPObj = NULL;
	int len = 0;
	int lock;
	const char *APlist;
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt";

	snprintf(path, sizeof(path), "/tmp/%s_bcn_rpt", staMac);
	lock = file_lock(path+5);
	bcnRoot = json_object_from_file(path);

	if(!bcnRoot) {
		DBG_ERR("report file read err");
		goto err;	
	}

	len = json_object_object_length(bcnRoot);
	if(len < 3) {
		DBG_ERR("beacon report is too short, no enough information. len %d", len);
	}

	if(*MonitorRoot == NULL) {
		DBG_ERR("MonitorRoot is NULL");
		*MonitorRoot = json_object_new_object();
		if(*MonitorRoot == NULL) {
			DBG_ERR("MonitorRoot init fail");
			goto err;
		}
		json_object_object_get_ex(bcnRoot, RAST_BAND, &bandObj);
		bandTmpObj = json_object_new_object();
		if(!bandObj || !bandTmpObj){
			DBG_ERR("bandObj init fail");
			json_object_put(*MonitorRoot);
			json_object_put(bandTmpObj);
			goto err;
		}
		json_object_object_add(bandTmpObj, RAST_BAND, json_object_new_string(json_object_get_string(bandObj)));
		json_object_object_add(*MonitorRoot, RAST_BAND, bandTmpObj);
	}

	APListRoot = json_object_from_file(AP_LIST_JSON_FILE);
	if(!APListRoot) {
		DBG_ERR("APList read err");
		goto err;
	}

	APlist = json_object_to_json_string(APListRoot);	

	json_object_object_get_ex(bcnRoot, RAST_AP, &currentAPObj);
	if(!currentAPObj) {
		DBG_ERR("currentAPObj is NULL");
		goto err;
	}	

	json_object_object_foreach(bcnRoot, key, val) {
		if (!strcmp(key, RAST_BAND) || !strcmp(key, RAST_AP)) {
			continue;
		}
		if(!strcmp(key, json_object_get_string(currentAPObj))) {
			DBG_INFO("This is current AP, continue");
			continue;
		}
		/* use strstr to fliter unknown AP ,maybe we can use better way in future*/
		if(strstr(APlist, key)){
			DBG_INFO("Add Mac %s to MonitorRoot, val %s", key, json_object_to_json_string(val));
			json_object_object_add(*MonitorRoot, key, json_tokener_parse(json_object_to_json_string(val)));
		}
	}

err:
	json_object_put(APListRoot);
	json_object_put(bcnRoot);
	unlink(path);
	file_unlock(lock);
}
#endif

#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
int cm_sendConnEventToExAp(char *sta_mac,char *ex_ap_mac,char *ex_ap_ip,char *present_ap)
{
	json_object *root = NULL;
	json_object *param = NULL;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	unsigned char *groupKey = NULL;
	char json_data[RAST_PKT_BUF_LEN],_EID[8];

	snprintf(_EID, sizeof(_EID), "%d", EID_RM_STA_EX_AP_CHECK);

	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta_mac));
	json_object_object_add(param, RAST_AP, json_object_new_string(present_ap));

	json_object_object_add(root, CFG_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	if( !strcasecmp(ex_ap_mac,present_ap) ) {
		DBG_ERR("ex-ap mac %s present-ap mac %s should be different\n",ex_ap_mac,present_ap);
		syslog(LOG_INFO,"Warning exap mac is invalid\n");
	} else if ( !strcasecmp(ex_ap_mac,nvram_safe_get("lan_hwaddr")) ) {
		//CAP is ex-ap
		ret = cm_sendEventToRast(json_data);
	} else {
		/* check key is valid or not */
		if (!cm_ctrlBlock.groupKeyReady) {
			DBG_ERR("key is not ready !!!");
			goto err;
		}

		/* select group key */
		if ((groupKey= cm_selectGroupKey(1)) == NULL) {
			DBG_ERR("no group key be selected");
			goto err;
		}
		
		/* encrypt data */
		encryptedMsg = cm_aesEncryptMsg(groupKey, REQ_EXAPCHECK, json_data, strlen((char *)json_data) + 1, &encLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			goto err;
		}

		/* send udp packet */
		if (cm_sendUdpPacket(ex_ap_ip, encryptedMsg, encLen) == 0) {
			DBG_ERR("Fail to send UDP packet to %s!", ex_ap_ip);
			goto err;
		}

		ret = 1;
	}

err:

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
	return ret;
} /* End of cm_sendConnEventToExAp */
#endif //#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
