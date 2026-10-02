#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_event.h"
#include "cfg_onboarding.h"
#include "cfg_wevent.h"
#include "cfg_slavelist.h"
#include "amas-utils.h"
#ifdef RTCONFIG_DWB
#include "cfg_dwb.h"
#endif
#include "cfg_clientlist.h"
#include <sysdeps/amas/amas_ob.h>
#include <sysdeps/amas/amas_path.h>
#include "cfg_capability.h"

static int wpsStopped = 1;
static int obStopped = 1;
static int obAvailableStopped = 1;
static int obAvailableSelStopped = 1;
static int obAvailableSelCanceled = 1;
static char beaconVsie[256];
static char beaconVsie_Guest[256] = {};
static char obReMac[32];
static char obNewReMac[32];
int obAvailableSelTimeout = 0;
int onboardingTimeout = 0;
int onboardingRebootTimeout = 0;
int onboardingConnectionTimeout = 0;
int onboardingTrafficTimeout = 0;
int rebootTime = 0;
int connectionTimeout = 0;
int trafficTimeout = 0;
int wpsStartTime = 0;
int wpsStopTime = 0;
int physicalConnected = 0;
int trafficConnected = 0;
#ifdef ONBOARDING_VIA_VIF
int vifIsUp = 0;
int vifDownTimeout = 0;
#endif

void cm_stopOnboardingAvailableSelection();
void cm_removeOnboardingList();

/*
========================================================================
Routine Description:
	Add vsie tlv.

Arguments:
	None

Return Value:
	onboarding available

========================================================================
*/
int cm_isOnboardingAvailable()
{
	return (nvram_get_int("cfg_obstatus") == OB_TYPE_AVAILABLE);
} /* End of cm_isOnboardingAvailable */

/*
========================================================================
Routine Description:
	Generate hashed value.

Arguments:
	val		- input value, the length must be 32.

Return Value:
	outVal	- hashed value

========================================================================
*/
char *cm_geneateHashValue(char *inVal)
{
	unsigned char hexVal[16] = {0};
	int i = 0;
	unsigned char *sha256Key = NULL;
	size_t sha256KeyLen = 0;
	char sha256KeyStr[65] = {0};
	static char outVal[41];
	int ts = time((time_t*)NULL);

	memset(outVal, 0, sizeof(outVal));

	if (inVal == NULL) {
		DBG_ERR("inVal is NULL");
		return outVal;
	}

	if (strlen(inVal) != 32) {
		DBG_ERR("the length of inVal does not meet");
		return outVal;
	}

	DBG_INFO("timestamp(%d, %04X)", ts, ts);

	if (str2hex(inVal, hexVal, strlen(inVal))) {
		/* each 4 bytes of hexVal & (And) timestamp */
		for (i = 0; i < sizeof(hexVal); i+=4) {
			hexVal[i] = hexVal[i] & ts >> 24;
			hexVal[i+1] = hexVal[i+1] & ts >> 16;
			hexVal[i+2] = hexVal[i+2] & ts >> 8;
			hexVal[i+3] = hexVal[i+3] & ts;

			//DBG_PRINTF("%02X%02X%02X%02X\n", hexId[i], hexId[i+1], hexId[i+2], hexId[i+3]);
		}

		/* generate sha256's key */
		sha256Key = gen_sha256_key(hexVal, sizeof(hexVal), &sha256KeyLen);

		if (sha256Key) {
			hex2str(sha256Key, &sha256KeyStr[0], sha256KeyLen);
			DBG_INFO("sha256Key (%s)", sha256KeyStr);
			free(sha256Key);
			sha256KeyStr[32] = '\0';
			snprintf(outVal, sizeof(outVal), "%s%02X%02X%02X%02X",
						sha256KeyStr, (ts >> 24) & 0xFF, (ts >> 16) & 0xFF,
						(ts >> 8) & 0xFF, ts & 0xFF);
			DBG_INFO("outVal (%s)", outVal);
		}
		else
			DBG_ERR("generate key is failed");
	}
	else
		DBG_INFO("str2hex is failed");

	return outVal;
} /* End of cm_geneateHashValue */

/*
========================================================================
Routine Description:
	Add vsie tlv.

Arguments:
	outData	- output data
	type		- tlv's type
	len		- tlv's len
	value	- tlv's value

Return Value:
	None

========================================================================
*/
void cm_addVsieTlv(char *outData, int type, int len, char *value)
{
	char tlStr[8] = {0};

	snprintf(tlStr, sizeof(tlStr), "%02X%02X", type, len);
	strcat(outData, tlStr);
	strcat(outData, value);
} /* End of cm_addVsieTlv */

/*
========================================================================
Routine Description:
	Generate beacon's VSIE.

Arguments:
	obType		- onboarding type
	reMac		- re's mac
	inftype	- The VSIE is for Root/Guest interface

Return Value:
	becaon's vsie

========================================================================
*/
char *cm_geneateBeaconVsie(int obType, char *reMac, enum infType infType)
{
	static char tmpBeaconVsie[256];
	char statusStr[32] = {0};
	char costStr[32] = {0};
	char idStr[64] = {0};
	unsigned char reMacHex[6] = {0};
	char reMacStr[32] = {0};
	char tsStr[32] = {0};
#ifdef RTCONFIG_BHCOST_OPT
	char buf[8], lastByteStr[32] = {0}, word[32], *next, *p;
	char capRoleStr[8];
	unsigned char eabuf[MAC_LEN] = {0};
	int unit = 0;
	char infTypeStr[8];
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
	char wdsStr[8];
#endif	
#endif	/* RTCONFIG_BHCOST_OPT */
#ifdef PRELINK
	char bundleKeyStr[64] = {0};
#endif
	unsigned char lastByte[4] = {0};
	char prefix[sizeof("wlXXXXX_")], tmp[32], ifname[16];
	int nband = 0;
	int i = 0;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	char wlPrefix[sizeof("wlXXXXX_")];
#endif

	memset(tmpBeaconVsie, 0, sizeof(tmpBeaconVsie));

	/* add required data */
	snprintf(statusStr, sizeof(statusStr), "%02X", obType);
	snprintf(costStr, sizeof(costStr), "%02X", (unsigned char)nvram_get_int("cfg_cost"));
	cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_STATUS, 1, statusStr);
	cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_COST, 1, costStr);

	/* for id */
	if (nvram_get("cfg_group")) {
		snprintf(idStr, sizeof(idStr), "%s", cm_geneateHashValue(nvram_safe_get("cfg_group")));
		if (strlen(idStr))
			cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_ID, strlen(idStr)/2, idStr);
	}

	/* for re/new re mac */
	if (reMac && strlen(reMac)) {
		ether_atoe(reMac, reMacHex);
		snprintf(reMacStr, sizeof(reMacStr), "%02X%02X%02X%02X%02X%02X",
					reMacHex[0], reMacHex[1], reMacHex[2], reMacHex[3],
					reMacHex[4], reMacHex[5]);
		cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_RE_MAC, strlen(reMacStr)/2, reMacStr);
	}

	/* for timestamp */
	snprintf(tsStr, sizeof(tsStr), "%02X%02X%02X%02X",
		(obTimeStamp >> 24) & 0xFF, (obTimeStamp >> 16) & 0xFF,
		(obTimeStamp >> 8) & 0xFF, obTimeStamp & 0xFF);
	cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_TIMESTAMP, strlen(tsStr)/2, tsStr);

#ifdef RTCONFIG_BHCOST_OPT
	/* for last byte of all bands */
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
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
		if ((p = get_hwaddr(ifname))) {
			ether_atoe(p, eabuf);
			if (nband == 2)
				lastByte[LAST_BYTE_2G] = eabuf[5];
			else if (nband == 1) {
				if (unit == LAST_BYTE_5G)
					lastByte[LAST_BYTE_5G] = eabuf[5];
				else if (unit == LAST_BYTE_5G1)
					lastByte[LAST_BYTE_5G1] = eabuf[5];
			}
			else if (nband == 4)
				lastByte[LAST_BYTE_6G] = eabuf[5];
			free(p);
			p = NULL;
		}

		unit++;
	}

	for (i = 0; i < sizeof(lastByte); i++) {
		snprintf(buf, sizeof(buf), "%02X", lastByte[i]);
		strlcat(lastByteStr, buf, sizeof(lastByteStr));
	}

	if (strlen(lastByteStr))
		cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_AP_LAST_BYTE, strlen(lastByteStr)/2, lastByteStr);

	/* for cap role */
	memset(capRoleStr, 0, sizeof(capRoleStr));
	snprintf(capRoleStr, sizeof(capRoleStr), "%02X", nvram_get_int("cfg_master"));
	if (strlen(capRoleStr))
		cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_CAP_ROLE, 1, capRoleStr);

	/* for interface type */
	memset(infTypeStr, 0, sizeof(infTypeStr));
	snprintf(infTypeStr, sizeof(infTypeStr), "%02X", (int)infType);
	if (strlen(infTypeStr))
		cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_INF_TYPE, 1, infTypeStr);
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
	/* for wds capab */
	memset(wdsStr, 0, sizeof(wdsStr));
	if(nvram_get_int("cfg_master"))
	{
		snprintf(wdsStr, sizeof(wdsStr), "%02X", 1);
	}	
	else 
	{
		if(nvram_get_int("amas_wds")>=0)
		{	
			//_dprintf("RE : vsie %s wds  (wds=%d)\n",nvram_get_int("amas_wds")?"with":"without",nvram_get_int("amas_wds"));		
			snprintf(wdsStr, sizeof(wdsStr), "%02X", nvram_get_int("amas_wds"));
		}	
	}
	if (strlen(wdsStr))
		cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_WDS, 1, wdsStr);
#endif 

#endif	/* RTCONFIG_BHCOST_OPT */

#ifdef PRELINK
	/* for bundle key */
	if (nvram_get("amas_hashbdlkey") && strlen(nvram_safe_get("amas_hashbdlkey"))){
		snprintf(bundleKeyStr, sizeof(bundleKeyStr), "%s", nvram_safe_get("amas_hashbdlkey"));
		if (strlen(bundleKeyStr))
			cm_addVsieTlv(tmpBeaconVsie, VSIE_TYPE_BUNDLE_KEY, strlen(bundleKeyStr)/2, bundleKeyStr);
	}
#endif

	DBG_INFO("data(%s)", tmpBeaconVsie);

	return tmpBeaconVsie;
} /* End of cm_geneateBeaconVsie */

/*
========================================================================
Routine Description:
	Thread for monitor wps status.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void *cm_monitorWpsStatus(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());

	int status = -1;
	int wpsTimeout = 0, wpsFailResult = OB_WPS_UNKNOWN_FAIL;
	unsigned char data[128] = {0};

	wpsStopped = 0;
	wpsStartTime = 0;
	wpsStopTime = 0;

	DBG_INFO("start wps monitor, wpsStopped(%d), wpsTimeout(%d), wpsStartTime (%d), wpsStopTime (%d)",
			wpsStopped, wpsTimeout, wpsStartTime, wpsStopTime);
	wpsStartTime = uptime();

	/* reset wps fail reslt */
	cm_updateOnboardingFailResult(OB_FAIL_NONE);

	/* check onboarding status */
	while (1) {
		if (wpsStopped) {
			status = get_wsc_status(&wpsFailResult);
			break;
		}
		else if (wpsTimeout >= WPS_WAIT_TIMEOUT)
		{
			status = 0;
			break;
		}

		sleep(WPS_CHECK_TIME);
		wpsTimeout += WPS_CHECK_TIME;
	}

	wpsStopTime = uptime();
	DBG_INFO("Stop wps and update status (%d), wpsStopped(%d), wpsTimeout(%d), wpsStartTime (%d), wpsStopTime (%d)",
			status, wpsStopped, wpsTimeout, wpsStartTime, wpsStopTime);

#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
	DBG_INFO("stop wps registrar");
	notify_rc("stop_wps_method_ob");
#endif

	/* update status */
	if (status == 1) {	/* wps success */
		snprintf((char *)data, sizeof(data), "{\"%s\": %d, \"%s\": {\"%s\": \"%s\"} }",
			CFG_STR_STATUS, OB_STATUS_WPS_SUCCESS,
			get_re_hwaddr(), CFG_STR_MAC, nvram_safe_get("cfg_obnewre"));
	}
	else		/* wps fail with result */
	{
		snprintf((char *)data, sizeof(data), "{\"%s\": %d, \"%s\": %d, \"%s\": {\"%s\": \"%s\"} }",
			CFG_STR_STATUS, OB_STATUS_WPS_FAIL,
			CFG_STR_FAIL_RESULT, wpsFailResult,
			get_re_hwaddr(), CFG_STR_MAC, nvram_safe_get("cfg_obnewre"));
	}

	if (cm_ctrlBlock.role == IS_SERVER) {
		cm_processOnboardingMsg((char *)data);
	}
	else
	{
		/* send TCP packet */
		if (cm_sendTcpPacket(REQ_ONBOARDING, &data[0]) == 0)
			DBG_ERR("Fail to send TCP packet!");
	}

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_monitorWpsStatus */

/*
========================================================================
Routine Description:
	Stop wps.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_stopWps()
{
	DBG_INFO("Stop wps before (%d)", wpsStopped);
	if (wpsStopped)
		return;
	wpsStopped = 1;
	DBG_INFO("Stop wps after (%d)", wpsStopped);
} /* End of cm_stopWps */


/*
========================================================================
Routine Description:
	Start onboarding available.

Arguments:
	args			- arguments

Return Value:
	None

========================================================================
*/
void *cm_startOnboardingAvailable(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());

	int obAvailableTimeout = 0;
	unsigned char data[64] = {0};

	obAvailableStopped = 0;

	DBG_INFO("start onboarding available, obAvailableStopped(%d), obAvailableTimeout(%d)",
				obAvailableStopped, obAvailableTimeout);

	/* check status */
	while (1) {
		if (obAvailableStopped || obAvailableTimeout >= ONBOARDING_AVAILABLE_TIMEOUT)
			break;

		sleep(ONBOARDING_AVAILABLE_CHECK_TIME);
		obAvailableTimeout += ONBOARDING_AVAILABLE_CHECK_TIME;
	}

	DBG_INFO("Stop onboarding available and send event obAvailableStopped(%d), obAvailableTimeout(%d)",
				obAvailableStopped, obAvailableTimeout);

	/* stop onboarding available selection first */
	cm_stopOnboardingAvailableSelection();

	/* update status */
	if (!obAvailableStopped) {
		obAvailableStopped = 1;
		snprintf((char *)data, sizeof(data), "{\"%s\": %d}", CFG_STR_STATUS, OB_STATUS_AVALIABLE_TIMEOUT);

		if (cm_ctrlBlock.role == IS_SERVER)
			cm_processOnboardingMsg((char *)data);
	}

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_startOnboardingAvailable */

/*
========================================================================
Routine Description:
	Stop onboarding available.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_stopOnboardingAvailable()
{
	DBG_INFO("Stop onboarding available before (%d)", obAvailableStopped);
	if (obAvailableStopped)
		return;
	obAvailableStopped = 1;
	DBG_INFO("Stop onboarding available after (%d)", obAvailableStopped);
} /* End of cm_stopOnboardingAvailable */

/*
========================================================================
Routine Description:
	Start onboarding available selection.

Arguments:
	args			- arguments

Return Value:
	None

========================================================================
*/
void *cm_startOnboardingAvailableSelection(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());

	unsigned char data[64] = {0};

	obAvailableSelStopped = 0;
	obAvailableSelCanceled = 0;
	obAvailableSelTimeout = 0;

	DBG_INFO("start onboarding available selection, obAvailableSelStopped(%d), obAvailableSelCanceled(%d), obAvailableSelTimeout(%d)",
			obAvailableSelStopped, obAvailableSelCanceled, obAvailableSelTimeout);

	/* check status */
	while (1) {
		if (obAvailableSelStopped || obAvailableSelCanceled ||
			obAvailableSelTimeout >= ONBOARDING_AVAILABLE_SEL_TIMEOUT)
			break;

		sleep(ONBOARDING_SELECTION_CHECK_TIME);
		obAvailableSelTimeout += ONBOARDING_SELECTION_CHECK_TIME;
	}

	DBG_INFO("Stop onboarding available selection and send event obAvailableSelStopped(%d), obAvailableSelCanceled(%d), obAvailableSelTimeout(%d)",
				obAvailableSelStopped, obAvailableSelCanceled, obAvailableSelTimeout);

	if (!obAvailableSelStopped && !obAvailableSelCanceled) {
		obAvailableSelStopped = 1;

		if (cm_ctrlBlock.role == IS_SERVER) {
			snprintf((char *)data, sizeof(data), "{\"%s\": %d}", CFG_STR_STATUS, OB_STATUS_CANCEL_SELECTION);
			cm_processOnboardingMsg((char *)data);
		}
	}
	else if (obAvailableSelCanceled)
		obAvailableSelStopped = 1;

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_startOnboardingAvailableSelection */

/*
========================================================================
Routine Description:
	Stop onboarding available selection.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_stopOnboardingAvailableSelection()
{
	DBG_INFO("Stop onboarding available selection before (%d)", obAvailableSelStopped);
	if (obAvailableSelStopped)
		return;
	obAvailableSelStopped = 1;
	DBG_INFO("Stop onboarding available selection after (%d)", obAvailableSelStopped);
} /* End of cm_stopOnboardingAvailableSelection */

/*
========================================================================
Routine Description:
	Cancel onboarding available selection.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_cancelOnboardingAvailableSelection()
{
	DBG_INFO("Cancel onboarding available selection before (%d)", obAvailableSelCanceled);
	if (obAvailableSelCanceled)
		return;
	obAvailableSelCanceled = 1;
	DBG_INFO("Cancel onboarding available selection after (%d)", obAvailableSelCanceled);
} /* End of cm_cancelOnboardingAvailableSelection */

/*
========================================================================
Routine Description:
	Thread for onboarding monitor.

Arguments:
	obOnRe		- onboarding via RE

Return Value:
	None

========================================================================
*/
void cm_startOnboardingMonitor(int obOnRe)
{
	int obTimeout = 0;
	char data[128] = {0};
	int updateObRelated = 0;
	int wpsTimeDiff = 0;
	int updateObTime = 0;

	obStopped = 0;
	physicalConnected =0;
	trafficConnected = 0;

	DBG_INFO("start onboarding monitor, obStopped(%d), obTimeout(%d)",
				obStopped, obTimeout);

	/* remove RE's connection history first */
	if (cm_getOnboardingPath() == FROM_WIRELESS)
		cm_removeReWifiConnectedHistory(nvram_get("cfg_newre"));

	/* check status */
	while (1) {
		if (obStopped) {
			DBG_INFO("obStopped is true, stop onboarding");
			break;
		}
		else if (obTimeout >= onboardingTimeout) {
			DBG_LOG("obTimeout >= onboardingTimeout, stop onboarding");
			cm_updateOnboardingFailResult(OB_TIMEOUT_FAIL);
			break;
		}

		if (nvram_get_int("cfg_obresult") == OB_STATUS_WPS_SUCCESS) {
			if (updateObRelated == 0) {
				if (cm_getOnboardingPath() == FROM_WIRELESS) {
					if (obOnRe)
						wpsStopTime = uptime();
					wpsTimeDiff = wpsStopTime - wpsStartTime;
					updateObTime = 1;
				}
				else if (cm_getOnboardingPath() == FROM_ETHERNET)
				{
					wpsStopTime = uptime();
					wpsTimeDiff = wpsStopTime - wpsStartTime;
					updateObTime = 1;
				}

				if (updateObTime)
				{
					DBG_LOG("re-calculate onboarding related timeout before, onboardingTimeout (%d), wpsTimeDiff (%d)",
						onboardingTimeout, wpsTimeDiff);
					/* update onboardingTimeout based on wpsTimeDiff */
					if (wpsTimeDiff >= 0 && wpsTimeDiff <= WPS_TIMEOUT)
						onboardingTimeout -= (WPS_TIMEOUT - wpsTimeDiff);

					onboardingRebootTimeout = obTimeout + rebootTime;
					onboardingConnectionTimeout = onboardingRebootTimeout + connectionTimeout;
					onboardingTrafficTimeout = onboardingConnectionTimeout + trafficTimeout;
					DBG_LOG("re-calculate onboarding timeout after, onboardingTimeout (%d), onboardingRebootTimeout (%d),"
							"onboardingConnectionTimeout (%d), onboardingTrafficTimeout (%d)",
						onboardingTimeout, onboardingRebootTimeout, onboardingConnectionTimeout,
						onboardingTrafficTimeout);
					nvram_set_int("cfg_obtimeout", onboardingTimeout);
					updateObRelated = 1;
					cm_updateOnboardingStage(OB_REBOOT_STAGE);
				}
			}

			/* update physicalConnected  */
			if (physicalConnected == 0 && obTimeout >= onboardingRebootTimeout) {
				cm_updateOnboardingStage(OB_CONNECTION_STAGE);
				if (cm_getOnboardingPath() == FROM_WIRELESS)
					physicalConnected = cm_checkReWifiConnected(nvram_get("cfg_newre"), nvram_get("cfg_obmodel"));
				else if (cm_getOnboardingPath() == FROM_ETHERNET)
					physicalConnected = cm_checkReWiredConnected(nvram_get("cfg_newre"), nvram_get("cfg_obmodel"));

				if (physicalConnected) {
					DBG_LOG("re-calculate traffic timeout before, onboardingTrafficTimeout (%d)",
						onboardingTrafficTimeout);
					onboardingTrafficTimeout = onboardingTrafficTimeout - (onboardingConnectionTimeout - obTimeout);
					DBG_LOG("re-calculate traffic timeout after, onboardingTrafficTimeout (%d)",
						onboardingTrafficTimeout);
					cm_updateOnboardingStage(OB_TRAFFIC_STAGE);
				}
			}

			/* update trafficConnected */
			if (nvram_get_int("cfg_obresult") == OB_STATUS_SUCCESS)
				trafficConnected = 1;

			/* check stop condition */
			if (obTimeout >= onboardingTimeout) {
				DBG_LOG("obTimeout >= onboardingTimeout, stop onboarding");
				cm_updateOnboardingFailResult(OB_TIMEOUT_FAIL);
				break;
			}
			else if (physicalConnected == 0 &&
				obTimeout >= onboardingConnectionTimeout && obTimeout < onboardingTrafficTimeout) {
				if (cm_getOnboardingPath() == FROM_WIRELESS) {
					DBG_LOG("from wireless, obTimeout >= onboardingConnectionTimeout, stop onboarding");
					cm_updateOnboardingFailResult(OB_WIFI_TIMEOUT_FAIL);
					break;
				}
				else if (cm_getOnboardingPath() == FROM_ETHERNET) {
					DBG_LOG("from ethernet, obTimeout >= onboardingConnectionTimeout, stop onboarding");
					cm_updateOnboardingFailResult(OB_WIRED_TIMEOUT_FAIL);
					break;
				}
			}
			else if (physicalConnected && trafficConnected == 0
				&& obTimeout >= onboardingTrafficTimeout) {
				DBG_LOG("obTimeout >= onboardingTrafficTimeout, stop onboarding");
					cm_updateOnboardingFailResult(OB_TRAFFIC_TIMEOUT_FAIL);
				break;
			}
		}

		sleep(ONBOARDING_CHECK_TIME);
		obTimeout += ONBOARDING_CHECK_TIME;
	}

	DBG_INFO("Stop onboarding monitor and update status, obStopped(%d), obTimeout(%d)",
				obStopped, obTimeout);
	/* update status */
	if (!obStopped) {
		snprintf(data, sizeof(data), "{\"%s\": %d, \"%s\": {\"%s\": \"%s\"} }",
				CFG_STR_STATUS, OB_STATUS_TERMINATE,
				obReMac, CFG_STR_MAC, obNewReMac);
		cm_processOnboardingMsg(data);
	}
} /* End of cm_startOnboardingMonitor */

/*
========================================================================
Routine Description:
	Stop onboarding monitor.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_stopOnboardingMonitor()
{
	DBG_INFO("Stop onboarding monitor before (%d)", obStopped);
	if (obStopped)
		return;
	obStopped = 1;
	DBG_INFO("Stop onboarding monitor after (%d)", obStopped);
} /* End of cm_stopOnboardingMonitor */

/*
========================================================================
Routine Description:
        Select onboarding timeout for RE by model name.

Arguments:
	reMac			- RE mac
	newReMac		- new RE mac
	rtime		- reboot time
	cTimeout		- connection timeout
	tTimeout		- traffic timeout
	updateStartTime		- update start time

Return Value:
        None

Note:
========================================================================
*/
void cm_selectOnboardingTimeout(char *reMac, char *newReMac, int rTime, int cTimeout, int tTimeout, int updateStartTime)
{
	json_object *obListObj = NULL;
	json_object *reObj = NULL;
	json_object *newReObj = NULL;
	json_object *modelObj = NULL;
	json_object *rssiObj = NULL;
	char modelName[32] = {0};
	int rssi = 0, gotTime = 0;
	struct time_mapping_s *pTime = NULL;

	onboardingTimeout = 0;
	rebootTime = 0;
	connectionTimeout = 0;
	trafficTimeout = 0;

	if (rTime && cTimeout && tTimeout) {
		DBG_INFO("got rTime(%d), cTimeout(%d), tTimeout(%d)", rTime, cTimeout, tTimeout);
		rebootTime = rTime;
		connectionTimeout = cTimeout;
		trafficTimeout = tTimeout;
		onboardingTimeout = WPS_TIMEOUT + rebootTime + connectionTimeout + trafficTimeout;
		gotTime = 1;
	}

	DBG_INFO("search model name or onboarding related time/timeout if needed");

	pthread_mutex_lock(&onboardingLock);
	obListObj = json_object_from_file(ONBOARDING_LIST_JSON_PATH);
	pthread_mutex_unlock(&onboardingLock);

	if (obListObj) {
		json_object_object_get_ex(obListObj, reMac, &reObj);
		if (reObj) {
			json_object_object_get_ex(reObj, newReMac, &newReObj);
			if (newReObj) {
				json_object_object_get_ex(newReObj, CFG_STR_RSSI, &rssiObj);
				json_object_object_get_ex(newReObj, CFG_STR_MODEL_NAME, &modelObj);
				if (rssiObj)
					rssi = json_object_get_int(rssiObj);

				if (modelObj) {
					snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(modelObj));
					DBG_INFO("got model name (%s)", modelName);

					/* if doesn't get time/timeout, need to search it */
					if (gotTime == 0) {
						for (pTime = &time_mapping_list[0]; pTime->model_name; pTime++) {
							if (!strcmp(pTime->model_name, modelName)) {
								DBG_INFO("found reboot_time(%d), connection_timeout(%d), traffic_timeout(%d)",
									pTime->reboot_time, pTime->connection_timeout, pTime->traffic_timeout);
								rebootTime = pTime->reboot_time;
								connectionTimeout = pTime->connection_timeout;
								trafficTimeout = pTime->traffic_timeout;
								onboardingTimeout = WPS_TIMEOUT + rebootTime + connectionTimeout +
									trafficTimeout;
								break;
							}
						}
					}
				}
			}
		}
	}

	json_object_put(obListObj);

	if (rebootTime == 0)
		rebootTime = REBOOT_DEF_TIME;
	if (connectionTimeout == 0)
		connectionTimeout = CONNECTION_DEF_TIMEOUT;
	if (trafficTimeout == 0)
		trafficTimeout = TRAFFIC_DEF_TIMEOUT;
	if (onboardingTimeout == 0)
		onboardingTimeout = WPS_TIMEOUT + rebootTime + connectionTimeout + trafficTimeout;

	if (updateStartTime)
		nvram_set_int("cfg_obstart", time((time_t*)NULL));
	nvram_set_int("cfg_obtimeout", onboardingTimeout);
	nvram_set_int("cfg_obreboottime", rebootTime);
	nvram_set_int("cfg_obconntimeout", connectionTimeout);
	nvram_set_int("cfg_obtraffictimeout", trafficTimeout);
	if (strlen(modelName))
		nvram_set("cfg_obmodel", modelName);
	else
		nvram_set("cfg_obmodel", "Unknown");
	nvram_set_int("cfg_obrssi", rssi);

	DBG_INFO("onboarding timeout (%d), reboot time (%d), connection timeout (%d), traffic timeout (%d)",
		onboardingTimeout, rebootTime, connectionTimeout, trafficTimeout);
} /* End of cm_selectOnboardingTimeout */

/*========================================================================
Routine Description:
	init onboarding status.

Arguments:
	None

Return Value:
	None

Note:
==========================================================================
*/
void cm_initOnboardingStatus()
{
	int obStatus = -1;

	if ((obStatus = cm_obtainOnboardingStatusFromFile()) > 0) {
		cm_updateOnboardingStatus(obStatus, NULL);
		if (f_read_string(ONBOARDING_VSIE_PATH, beaconVsie, sizeof(beaconVsie))) {
			DBG_INFO("update beacon's vsie from file (%s)", ONBOARDING_VSIE_PATH);
			if (strlen(beaconVsie))
				del_beacon_vsie(beaconVsie);
		}
	}
	else
		cm_updateOnboardingStatus(OB_TYPE_OFF, NULL);

	/* delete vsie for guest */
	if (f_read_string(GUEST_VSIE_PATH, beaconVsie_Guest, sizeof(beaconVsie_Guest))) {
		DBG_INFO("update beacon's vsie from file (%s) for guest", GUEST_VSIE_PATH);
		if (strlen(beaconVsie_Guest))
			del_beacon_vsie(beaconVsie_Guest);
	}
} /* End of cm_initOnboardingStatus */

/*========================================================================
Routine Description:
	Update onboarding status.

Arguments:
	obStatus		- onboarding status

Return Value:
	None

Note:
==========================================================================
*/
void cm_updateOnboardingStatus(int obStatus, char *obVsie)
{
	char obStatusStr[4] = {0};

	DBG_INFO("update onboarding status, obStatus(%d), cfg_obstatus(%d)", obStatus, nvram_get_int("cfg_obstatus"));

	//f (obStatus != nvram_get_int("cfg_obstatus")) {
		nvram_set_int("cfg_obstatus", obStatus);
		snprintf(obStatusStr, sizeof(obStatusStr), "%d", obStatus);
		f_write_string(ONBOARDING_STATUS_PATH, obStatusStr, 0, 0);
		if (obVsie)
			f_write_string(ONBOARDING_VSIE_PATH, obVsie, 0, 0);
	//}
} /* End of cm_updateOnboardingStatus */

/*========================================================================
Routine Description:
	Update vsie of guest interface to file.

Arguments:
	None

Return Value:
	None
Note:
==========================================================================
*/
void cm_updateGuestVsieToFile(char *vsie)
{
	if (vsie && strlen(vsie))
		f_write_string(GUEST_VSIE_PATH, vsie, 0, 0);
} /* End of cm_updateGuestVsieToFile */

/*========================================================================
Routine Description:
	Update onboarding status.

Arguments:
	result		- onboarding fail result

Return Value:
	None

Note:
==========================================================================
*/
void cm_updateOnboardingFailResult(int result)
{
	nvram_set_int("cfg_obfailresult", result);
} /* End of cm_updateOnboardingFailResult */

/*========================================================================
Routine Description:
	Update onboarding stage.

Arguments:
	stage		- onboarding stage

Return Value:
	None

Note:
==========================================================================
*/
void cm_updateOnboardingStage(int stage)
{
	nvram_set_int("cfg_obstage", stage);
} /* End of cm_updateOnboardingStage */

/*========================================================================
Routine Description:
	Obtain onboarding status from saved file.

Arguments:
	None

Return Value:
	onboarding status

Note:
==========================================================================
*/
int cm_obtainOnboardingStatusFromFile()
{
	char obStatusStr[4] = {0};

	if (f_read_string(ONBOARDING_STATUS_PATH, obStatusStr, sizeof(obStatusStr)))
		return atoi(obStatusStr);
	else
		return -1;
} /* End of cm_obtainOnboardingStatus */

/*
========================================================================
Routine Description:
	Process onboarding event.

Arguments:
	inData		- data for process

Return Value:
	None

========================================================================
*/
void cm_processOnboardingEvent(char *inData)
{
	json_object *root = json_tokener_parse(inData);
	json_object *typeObj = NULL;
	json_object *reMacObj = NULL;
	json_object *newReMacObj = NULL;
	json_object *tsObj = NULL;
	json_object *obPathObj = NULL;
	json_object *obGroupObj = NULL;
	json_object *rTimeObj = NULL, *cTimeoutObj = NULL, *tTimeoutObj = NULL;
	json_object *obViaVifObj = NULL;
	int type = -1;
	int obPath = FROM_WIRELESS;
	int rTime = 0, cTimeout = 0, tTimeout = 0;
	int obOnRe = 0;

	json_object_object_get_ex(root, CFG_STR_TYPE, &typeObj);
	json_object_object_get_ex(root, CFG_STR_RE_MAC, &reMacObj);
	json_object_object_get_ex(root, CFG_STR_NEW_RE_MAC, &newReMacObj);
	json_object_object_get_ex(root, CFG_STR_TIMESTAMP, &tsObj);
	json_object_object_get_ex(root, CFG_STR_OB_PATH, &obPathObj);
	json_object_object_get_ex(root, CFG_STR_OB_GROUP, &obGroupObj);
#ifdef ONBOARDING_VIA_VIF
	json_object_object_get_ex(root, CFG_STR_OB_VIA_VIF, &obViaVifObj);
#endif

	DBG_INFO("msg(%s)", inData);

	if (typeObj) {
		type = json_object_get_int(typeObj);

		DBG_INFO("onbarding type(%d)", type);

		if (obPathObj) {
			obPath = json_object_get_int(obPathObj);
			DBG_INFO("onbarding path(%d)", obPath);
		}

		if (type == OB_TYPE_OFF) {
			if (cm_ctrlBlock.role == IS_SERVER) {
				nvram_unset("cfg_obstart");
				nvram_unset("cfg_obtimeout");
				nvram_unset("cfg_obreboottime");
				nvram_unset("cfg_obconntimeout");
				nvram_unset("cfg_obtraffictimeout");
				nvram_unset("cfg_obkey");
				nvram_unset("cfg_obpath");
#ifdef ONBOARDING_VIA_VIF
				nvram_unset("cfg_obvif_ready");
				nvram_unset("cfg_obvif_time");
				nvram_unset("cfg_obvif_mac");
#endif

				/* for server, update timestamp for onboarding */
				if (obTimeStamp == 0)
					obTimeStamp = time((time_t*)NULL);
			}
			else		/* for client, update timestamp for onboarding */
			{
				if (tsObj)
					obTimeStamp = json_object_get_int(tsObj);
			}

			nvram_unset("cfg_obnewre");

#ifdef ONBOARDING_VIA_VIF
			nvram_unset("wps_via_vif");
			if (obViaVifObj)
				cm_obVifDownUp(OB_VIF_DOWN);
#endif
			/* for wireless */
			/* del beacon vsie first */
			if (strlen(beaconVsie))
				del_beacon_vsie(beaconVsie);

			memset(beaconVsie, 0, sizeof(beaconVsie));

			DBG_INFO("set beacon's vsie for OB_OFF");
			snprintf(beaconVsie, sizeof(beaconVsie), "%s", cm_geneateBeaconVsie(type, NULL, INF_TYPE_ROOT));
			add_beacon_vsie(beaconVsie);

			/* update onboarding status */
			cm_updateOnboardingStatus(type, beaconVsie);

			/* for guest wireless */
			/* del beacon vsie first */
			if (strlen(beaconVsie_Guest))
				del_beacon_vsie_guest(beaconVsie_Guest);

			memset(beaconVsie_Guest, 0, sizeof(beaconVsie_Guest));

			DBG_INFO("set guest beacon's vsie for OB_OFF");
			snprintf(beaconVsie_Guest, sizeof(beaconVsie_Guest), "%s", cm_geneateBeaconVsie(type, NULL, INF_TYPE_GUEST));
			add_beacon_vsie_guest(beaconVsie_Guest);

			/* update vsie for guest to file */
			cm_updateGuestVsieToFile(beaconVsie_Guest);

			/* remove onboarding list after updating ob status */
			if (cm_ctrlBlock.role == IS_SERVER) {
				DBG_INFO("remove onboarding list");
				cm_removeOnboardingList();
			}

			/* change mode of mac filter if needed */
			wl_set_macfilter_mode(0);

#ifdef BCM_BSD
			/* avoid bsd to change filter mode */
			if (nvram_get_int("smart_connect_x")) {
				if (!pids("bsd")) {
					DBG_INFO("restart the daemon of smart connect");
					notify_rc("start_bsd");
				}
			}
#endif

#ifdef RTCONFIG_ETHOBD
			/* for ethernet */
			if (pids("obd_monitor"))
				//notify_rc("stop_obd_monitor");
				killall("obd_monitor", SIGTERM);
#endif
		}
		else if (type == OB_TYPE_AVAILABLE) {
			pthread_t obAvailableThread;
			int obAvailSelection = 0;

			/* for onboarding selection */
			if (newReMacObj) {
				if (cm_ctrlBlock.role == IS_SERVER)
					DBG_LOG("onboarding selection for new RE (%s)", (char *)json_object_get_string(newReMacObj));
				obAvailSelection = 1;
			}
			else
			{
				if (cm_ctrlBlock.role == IS_SERVER)
					DBG_LOG("start onboarding search");
			}

			if (obAvailSelection) {
				if (obPath == FROM_WIRELESS) {
					/* del beacon vsie first */
					if (strlen(beaconVsie))
						del_beacon_vsie(beaconVsie);

					memset(beaconVsie, 0, sizeof(beaconVsie));

					DBG_INFO("set beacon's vsie for OB_AVAILABLE selection (%s)",
							(char *)json_object_get_string(newReMacObj));
					snprintf(beaconVsie, sizeof(beaconVsie), "%s",
							cm_geneateBeaconVsie(type, (char *)json_object_get_string(newReMacObj), INF_TYPE_ROOT));

					add_beacon_vsie(beaconVsie);

					/* update onboarding status */
					cm_updateOnboardingStatus(type, beaconVsie);
				}
#ifdef RTCONFIG_ETHOBD
				else
				{
					/* for ethernet */
					amas_set_peermac((unsigned char *)json_object_get_string(newReMacObj));
				}
#endif

				/* start onboarding available */
				if (cm_ctrlBlock.role == IS_SERVER) {
					if (obAvailableSelStopped) {
						if (!strcmp(UNDEF_RE_MAC, json_object_get_string(newReMacObj)))
							DBG_INFO("back to OB_AVAILABLE");
						else
						{
							if (pthread_create(&obAvailableThread, attrp, cm_startOnboardingAvailableSelection, NULL) != 0)
								DBG_ERR("could not create thread for onboarding available selection");
						}
					}
					else		/* select another new re, reset selection timeout */
					{
						if (!strcmp(UNDEF_RE_MAC, json_object_get_string(newReMacObj))) {
							DBG_LOG("cancel new re selection");
							cm_cancelOnboardingAvailableSelection();
						}
						else
						{
							DBG_LOG("select another new re (%s), reset selection timeout",
								(char *)json_object_get_string(newReMacObj));
							obAvailableSelTimeout = 0;
						}
					}
				}
			}
			else
			{
#ifdef ONBOARDING_VIA_VIF
				cm_obVifDownUp(OB_VIF_DOWN);
#endif
				if (cm_ctrlBlock.role == IS_SERVER) {
					/* reset fail reslt, ob stage */
					cm_updateOnboardingFailResult(OB_FAIL_NONE);
					cm_updateOnboardingStage(OB_INIT_STAGE);

					if (tsObj && obTimeStamp == json_object_get_int(tsObj))
						DBG_INFO("OB_AVAILABLE do nothing");
					else	/* remove onboarding list */
					{
						DBG_LOG("remove onboarding list");
						cm_removeOnboardingList();
					}
				}
				else if (cm_ctrlBlock.role == IS_CLIENT)	/* for client, update timestamp for onboarding */
				{
					if (tsObj)
						obTimeStamp = json_object_get_int(tsObj);
				}

				/* del beacon vsie first */
				if (strlen(beaconVsie))
					del_beacon_vsie(beaconVsie);

				memset(beaconVsie, 0, sizeof(beaconVsie));

				DBG_INFO("set beacon's vsie for OB_AVAILABLE");
				snprintf(beaconVsie, sizeof(beaconVsie), "%s", cm_geneateBeaconVsie(type, NULL, INF_TYPE_ROOT));

				add_beacon_vsie(beaconVsie);

				/* update onboarding status */
				cm_updateOnboardingStatus(type, beaconVsie);

				/* start onboarding available */
				if (cm_ctrlBlock.role == IS_SERVER) {
					if (obAvailableStopped) {
						if (pthread_create(&obAvailableThread, attrp, cm_startOnboardingAvailable, NULL) != 0)
							DBG_ERR("could not create thread for onboarding available");
					}
				}

#ifdef RTCONFIG_ETHOBD
				/* for ethernet */
				if (!pids("obd_monitor"))
					notify_rc("restart_obd_monitor");
#endif
			}
		}
		else if (type == OB_TYPE_LOCKED) {
			pthread_t wpsThread;

			/* stop onboarding available */
			if (cm_ctrlBlock.role == IS_SERVER) {
				cm_stopOnboardingAvailable();
			}
			else if (cm_ctrlBlock.role == IS_CLIENT)	/* for client, update timestamp for onboarding */
			{
				if (tsObj)
					obTimeStamp = json_object_get_int(tsObj);
			}

			memset(obReMac, 0, sizeof(obReMac));
			memset(obNewReMac, 0, sizeof(obNewReMac));
			if (reMacObj)
				snprintf(obReMac, sizeof(obReMac), "%s", (char *)json_object_get_string(reMacObj));

			if (newReMacObj)
				snprintf(obNewReMac, sizeof(obNewReMac), "%s", (char *)json_object_get_string(newReMacObj));

			if (cm_ctrlBlock.role == IS_SERVER) {
				DBG_LOG("re (%s) onboarding lock for new re (%s) via %s", obReMac, obNewReMac,
					obPath == FROM_WIRELESS ? "wireless": "ethernet");
			}

			if (obPath == FROM_WIRELESS) {
				/* del beacon vsie first */
				if (strlen(beaconVsie))
					del_beacon_vsie(beaconVsie);

				memset(beaconVsie, 0, sizeof(beaconVsie));

				//set beacon
				DBG_INFO("set beacon's vsie for OB_LOCKED");
				if (newReMacObj) {
					snprintf(beaconVsie, sizeof(beaconVsie), "%s",
						cm_geneateBeaconVsie(type, (char *)json_object_get_string(newReMacObj), INF_TYPE_ROOT));
				}
				else
					snprintf(beaconVsie, sizeof(beaconVsie), "%s", cm_geneateBeaconVsie(type, NULL, INF_TYPE_ROOT));

				DBG_INFO("obReMac(%s), obNewReMac(%s)", obReMac, obNewReMac);
				add_beacon_vsie(beaconVsie);

				/* update onboarding status */
				cm_updateOnboardingStatus(type, beaconVsie);

#ifdef BCM_BSD
				/* avoid bsd to change filter mode */
				if (nvram_get_int("smart_connect_x")) {
					if (pids("bsd")) {
						DBG_LOG("stop the daemon of smart connect");
						notify_rc("stop_bsd");
					}
				}
#endif

				/* change mode of mac filter if needed */
				wl_set_macfilter_mode(1);

				/* start wps registrar */
				if (!strcasecmp(obReMac, get_re_hwaddr())) {
					DBG_LOG("start wps registrar");
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
					notify_rc("start_wps_method_ob");
#else
					notify_rc("start_wps_method");
#endif
					if (newReMacObj)
						nvram_set("cfg_obnewre", (char *)json_object_get_string(newReMacObj));
					if (pthread_create(&wpsThread, attrp, cm_monitorWpsStatus, NULL) != 0)
						DBG_LOG("could not create thread for monitor wps status");
				}
				else
				{
					DBG_LOG("don't need to start wps registrar");
					if (cm_ctrlBlock.role == IS_SERVER) {
						obOnRe = 1;
						wpsStartTime = uptime();
						wpsStopTime = 0;
					}
				}

				/* for ethernet */
				//notify_rc("stop_obd_monitor");
				killall("obd_monitor", SIGTERM);
			}
#ifdef RTCONFIG_ETHOBD
			else
			{
				/* for ethernet */
				if (obGroupObj)
					amas_set_group((unsigned char *)json_object_get_string(obGroupObj));

				if (!strcasecmp(obReMac, get_unique_mac())) {
					DBG_LOG("start to negotiate ob key");
					if (newReMacObj)
						nvram_set("cfg_obnewre", (char *)json_object_get_string(newReMacObj));
				}
				else
				{
					DBG_LOG("don't need to negotiate ob key, stop obd_monitor");
					//notify_rc("stop_obd_monitor");
					killall("obd_monitor", SIGTERM);
				}

				wpsStartTime = uptime();
				wpsStopTime = 0;
				nvram_set_int("cfg_obstatus", type);
			}
#endif

			/* start onboarding status monitor */
			if (cm_ctrlBlock.role == IS_SERVER) {
				/* update ob related time/timeout for new RE */
				json_object_object_get_ex(root, CFG_STR_REBOOT_TIME, &rTimeObj);
				json_object_object_get_ex(root, CFG_STR_CONN_TIMEOUT, &cTimeoutObj);
				json_object_object_get_ex(root, CFG_STR_TRAFFIC_TIMEOUT, &tTimeoutObj);

				if (rTimeObj && cTimeoutObj && tTimeoutObj) {
					rTime = json_object_get_int(rTimeObj);
					cTimeout = json_object_get_int(cTimeoutObj);
					tTimeout =  json_object_get_int(tTimeoutObj);
				}

				cm_selectOnboardingTimeout(obReMac, obNewReMac, rTime, cTimeout, tTimeout,
					strlen(nvram_safe_get("cfg_obvif_mac")) > 0 ? 0 : 1);	/* select onboarding timeout for RE */
				cm_startOnboardingMonitor(obOnRe);
			}
		}
#ifdef ONBOARDING_VIA_VIF
		else if (type == OB_TYPE_VIF_CHECK) {
			pthread_t obVifThread;

			/* update ob related time/timeout for new RE */
			json_object_object_get_ex(root, CFG_STR_REBOOT_TIME, &rTimeObj);
			json_object_object_get_ex(root, CFG_STR_CONN_TIMEOUT, &cTimeoutObj);
			json_object_object_get_ex(root, CFG_STR_TRAFFIC_TIMEOUT, &tTimeoutObj);

			if (rTimeObj && cTimeoutObj && tTimeoutObj) {
				rTime = json_object_get_int(rTimeObj);
				cTimeout = json_object_get_int(cTimeoutObj);
				tTimeout =  json_object_get_int(tTimeoutObj);
			}

			/* stop onboarding available */
			if (cm_ctrlBlock.role == IS_SERVER) {
				cm_stopOnboardingAvailable();

				if (reMacObj && newReMacObj) {
					DBG_LOG("check onboarding vif for %s", json_object_get_string(reMacObj));

					nvram_set_int("cfg_obstatus", OB_TYPE_LOCKED);

					cm_selectOnboardingTimeout((char *)json_object_get_string(reMacObj), (char *)json_object_get_string(newReMacObj),
						rTime, cTimeout, tTimeout, 1);	/* select onboarding timeout for RE */
				}
			}

			if (!strcasecmp(json_object_get_string(reMacObj), get_re_hwaddr())) {
				cm_computeVifDownTimeout(rTime, cTimeout, tTimeout);
				if (pthread_create(&obVifThread, attrp, cm_upOnboardingVif, NULL) != 0)
					DBG_ERR("could not create thread for up onboarding vif");
			}
		}
#endif
		else
			DBG_INFO("unknown onboarding type");
	}

	json_object_put(root);
} /* End of cm_processOnboarding */

/*
========================================================================
Routine Description:
	Process onboarding list (common).

Arguments:
	*fileRoot	- json object from file
	*reMac		- the mac of re
	*newReMac		- the mac of new re
	*modelName		- model name of new re
	rssi			- rssi
	source		- from wireless or ethernet
	rTime		- reboot time
	cTimeout		- connection timeout
	tTimeout		- traffic timeout
	tCode		- territory code
	type			- type from where
	miscInfo		- miscellaneous infomation

Return Value:
	None

Note:
========================================================================
*/
void cm_processOnboardingCommon(json_object *fileRoot, char *reMac, char *newReMac, char *modelName,
	int rssi, int source, int rTime, int cTimeout, int tTimeout, char *tCode, int type, char *miscInfo)
{
	json_object *reMacObj = NULL;
	json_object *newReObj = NULL;
	json_object *statusObj = NULL;
	json_object *rssiObj = NULL;
	json_object *sourceObj = NULL;
	json_object *rTimeObj = NULL, *cTimeoutObj = NULL, *tTimeoutObj = NULL;
	json_object *tsObj = NULL, *tsEthObj = NULL;
	json_object *tCodeObj = NULL, *typeObj = NULL;
	json_object *miscInfoObj = NULL;
	int status = 0;
	int found = 0;
	time_t now;
	int newReRssi = 0;
	int newReSource = 0;
	int rTimeTemp = 0, cTimeoutTemp = 0, tTimeoutTemp = 0, newType = ETH_TYPE_NONE;
	long ts = 0, tsEth = 0;
	char tCodeTemp[16] = {0};
	char miscInfoTemp[256] = {0};

	time(&now);

	if (!reMac || !newReMac)
		DBG_ERR("invalid parameters");

	if (fileRoot != NULL) {
		json_object_object_foreach(fileRoot, key, val) {
			if (strcmp(reMac, key))
				continue;
			reMacObj = val;

			json_object_object_foreach(reMacObj, key, val) {
				if (!strcmp(newReMac, key)) {
					newReObj = val;
					found = 1;
					break;
				}
			}
		}

		if (found) {
			//{"D8:50:E6:5A:3F:C0":{"78:24:AF:D3:3F:C0":{"status":0,"model_name":"", "ts": 183838828}}}
			DBG_INFO("found(%s)", newReMac);
			json_object_object_get_ex(newReObj, CFG_STR_STATUS, &statusObj);
			json_object_object_get_ex(newReObj, CFG_STR_RSSI, &rssiObj);
			json_object_object_get_ex(newReObj, CFG_STR_SOURCE, &sourceObj);
			json_object_object_get_ex(newReObj, CFG_STR_REBOOT_TIME, &rTimeObj);
			json_object_object_get_ex(newReObj, CFG_STR_CONN_TIMEOUT, &cTimeoutObj);
			json_object_object_get_ex(newReObj, CFG_STR_TRAFFIC_TIMEOUT, &tTimeoutObj);
			json_object_object_get_ex(newReObj, CFG_STR_TIMESTAMP, &tsObj);
			json_object_object_get_ex(newReObj, CFG_STR_TIMESTAMP_ETH, &tsEthObj);
			json_object_object_get_ex(newReObj, CFG_STR_TCODE, &tCodeObj);
			json_object_object_get_ex(newReObj, CFG_STR_TYPE, &typeObj);
			json_object_object_get_ex(newReObj, CFG_STR_MISC_INFO, &miscInfoObj);
			if (statusObj)
				status = json_object_get_int(statusObj);

			/* record the rssi */
			if (rssiObj) {
				if (source == FROM_WIRELESS)
					newReRssi = rssi;
				else
					newReRssi = json_object_get_int(rssiObj);
			}

			/* record the source */
			if (sourceObj)
				newReSource = json_object_get_int(sourceObj) | source;
			else
				newReSource = source;

			/* record reboot time */
			if (rTimeObj)
				rTimeTemp = json_object_get_int(rTimeObj);
			else if (rTime)
				rTimeTemp = rTime;

			/* record connection timeout */
			if (cTimeoutObj)
				cTimeoutTemp = json_object_get_int(cTimeoutObj);
			else if (cTimeout)
				cTimeoutTemp = cTimeout;

			/* record traffic timeout */
			if (tTimeoutObj)
				tTimeoutTemp = json_object_get_int(tTimeoutObj);
			else if (tTimeout)
				tTimeoutTemp = tTimeout;

			/* record timestamp */
			if (tsObj)
				ts = json_object_get_int64(tsObj);

			if (tsEthObj)
				tsEth = json_object_get_int64(tsEthObj);

			/* record tcode */
			if (tCodeObj)
				snprintf(tCodeTemp, sizeof(tCodeTemp), "%s", json_object_get_string(tCodeObj));
			else if (tCode && strlen(tCode))
				snprintf(tCodeTemp, sizeof(tCodeTemp), "%s", tCode);

			/* record type */
			if (typeObj)
				newType = json_object_get_int(typeObj) | type;
			else
				newType = type;

			/* record misc info */
			if (miscInfoObj)
				snprintf(miscInfoTemp, sizeof(miscInfoTemp), "%s", json_object_to_json_string_ext(miscInfoObj, 0));
			else if (miscInfo && strlen(miscInfo))
				snprintf(miscInfoTemp, sizeof(miscInfoTemp), "%s", convert_misc_info_to_json_str(miscInfo));

			newReObj = json_object_new_object();
			if (newReObj) {
				DBG_INFO("update timestamp(%ld)", now);
				json_object_object_add(newReObj, CFG_STR_STATUS,
					json_object_new_int(status));
				json_object_object_add(newReObj, CFG_STR_MODEL_NAME,
					json_object_new_string(modelName));
				json_object_object_add(newReObj, CFG_STR_RSSI,
					json_object_new_int(newReRssi));
				if (source == FROM_WIRELESS) {
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP,
						json_object_new_int64(now));
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP_ETH,
						json_object_new_int64(tsEth));
				}
				else
				{
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP,
						json_object_new_int64(ts));
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP_ETH,
						json_object_new_int64(now));
				}
				json_object_object_add(newReObj, CFG_STR_SOURCE,
					json_object_new_int(newReSource));
				if (rTimeTemp)
					json_object_object_add(newReObj, CFG_STR_REBOOT_TIME,
						json_object_new_int(rTimeTemp));
				if (cTimeoutTemp)
					json_object_object_add(newReObj, CFG_STR_CONN_TIMEOUT,
						json_object_new_int(cTimeoutTemp));
				if (tTimeoutTemp)
					json_object_object_add(newReObj, CFG_STR_TRAFFIC_TIMEOUT,
						json_object_new_int(tTimeoutTemp));
				if (strlen(tCodeTemp))
					json_object_object_add(newReObj, CFG_STR_TCODE,
						json_object_new_string(tCodeTemp));
				json_object_object_add(newReObj, CFG_STR_TYPE,
					json_object_new_int(newType));
				if (strlen(miscInfoTemp))
					json_object_object_add(newReObj, CFG_STR_MISC_INFO,
						json_tokener_parse(miscInfoTemp) ? : json_object_new_object());

				if (reMacObj) {
					json_object_object_del(reMacObj, newReMac);
					json_object_object_add(reMacObj, newReMac, newReObj);
				}
				else
					json_object_put(newReObj);
			}
		}
		else
		{
			DBG_INFO("not found(%s)", newReMac);
			newReObj = json_object_new_object();
			if (newReObj) {
				DBG_INFO("add status, model name(%s), tcode (%s), timestamp(%ld)", modelName, tCode, now);
				json_object_object_add(newReObj, CFG_STR_STATUS,
					json_object_new_int(OB_STATUS_REQ));
				json_object_object_add(newReObj, CFG_STR_MODEL_NAME,
					json_object_new_string(modelName));
				json_object_object_add(newReObj, CFG_STR_RSSI,
					json_object_new_int(rssi));
				if (source == FROM_WIRELESS) {
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP,
						json_object_new_int64(now));
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP_ETH,
						json_object_new_int64(0));
				}
				else
				{
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP,
						json_object_new_int64(0));
					json_object_object_add(newReObj, CFG_STR_TIMESTAMP_ETH,
						json_object_new_int64(now));
				}
				json_object_object_add(newReObj, CFG_STR_SOURCE,
					json_object_new_int(source));
				if (rTime)
					json_object_object_add(newReObj, CFG_STR_REBOOT_TIME,
						json_object_new_int(rTime));
				if (cTimeout)
					json_object_object_add(newReObj, CFG_STR_CONN_TIMEOUT,
						json_object_new_int(cTimeout));
				if (tTimeout)
					json_object_object_add(newReObj, CFG_STR_TRAFFIC_TIMEOUT,
						json_object_new_int(tTimeout));
				if (tCode && strlen(tCode))
					json_object_object_add(newReObj, CFG_STR_TCODE,
						json_object_new_string(tCode));
				json_object_object_add(newReObj, CFG_STR_TYPE,
					json_object_new_int(type));
				if (miscInfo && strlen(miscInfo)) {
					snprintf(miscInfoTemp, sizeof(miscInfoTemp), "%s", convert_misc_info_to_json_str(miscInfo));
					if (strlen(miscInfoTemp))
						json_object_object_add(newReObj, CFG_STR_MISC_INFO,
							json_tokener_parse(miscInfoTemp) ? : json_object_new_object());
				}

				if (reMacObj)
					json_object_object_add(reMacObj, newReMac, newReObj);
				else
				{
					reMacObj = json_object_new_object();

					if (reMacObj) {
						json_object_object_add(reMacObj, newReMac, newReObj);
						json_object_object_add(fileRoot, reMac, reMacObj);
					}
					else
						json_object_put(newReObj);
				}
			}
		}
	}
} /* End of cm_processOnboardingCommon */

/*========================================================================
Routine Description:
	Process onboarding list.

Arguments:
	*msg	- onboarding list

Return Value:
	None

Note:
==========================================================================
*/
void cm_processOnboardingList(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	int lock;
	char reMac[32] = {0};
	char newReMac[32] ={0};
	char newReId[32] = {0};
	char modelName[32] = {0};
	json_object *fileRoot = NULL;
	json_object *reMacObj = NULL;
	json_object *newReMacObj = NULL;
	json_object *newReIdObj = NULL;
	json_object *modelNameObj = NULL;
	json_object *rssiObj = NULL;
	json_object *sourceObj = NULL;
	json_object *etherListObj = NULL;
	json_object *rebootObj = NULL, *connectionObj = NULL, *trafficObj = NULL;
	json_object *tCodeObj = NULL,  *typeObj = NULL;
	json_object *miscInfoObj = NULL;
	int rssi = 0;
#ifdef RSSI_LIST
	char rssiList[256] = {0};
	unsigned char hexRssiList[256] = {0};
	int i = 0;
#endif
	int source = 0;
	int rTime = 0, cTimeout = 0, tTimeout = 0, type = ETH_TYPE_NONE;
	char tCode[16] = {0};
	char miscInfo[256] = {0};

	DBG_INFO("msg(%s)", msg);

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	if (!cm_isOnboardingAvailable()) {
		DBG_INFO("ob status is not available, don't update onboarding list");
		json_object_put(root);
		return;
	}

	pthread_mutex_lock(&onboardingLock);
	lock = file_lock(ONBOARDING_FILE_LOCK);

	fileRoot = json_object_from_file(ONBOARDING_LIST_JSON_PATH);
	if (!fileRoot) {
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			json_object_put(root);
			file_unlock(lock);
			pthread_mutex_unlock(&onboardingLock);
			return;
		}
	}

	json_object_object_foreach(root, key, val) {
		if (!strcmp(key, CFG_STR_STATUS))
			continue;

		if (!val)
			continue;

		memset(reMac, 0, sizeof(reMac));
		snprintf(reMac, sizeof(reMac), "%s", key);
		reMacObj = val;

		json_object_object_get_ex(reMacObj, CFG_STR_MAC, &newReMacObj);
		json_object_object_get_ex(reMacObj, CFG_STR_ID, &newReIdObj);
		json_object_object_get_ex(reMacObj, CFG_STR_MODEL_NAME, &modelNameObj);
		json_object_object_get_ex(reMacObj, CFG_STR_RSSI, &rssiObj);
		json_object_object_get_ex(reMacObj, CFG_STR_SOURCE, &sourceObj);
		json_object_object_get_ex(reMacObj, CFG_STR_ETHER_LIST, &etherListObj);
		json_object_object_get_ex(reMacObj, CFG_STR_REBOOT_TIME, &rebootObj);
		json_object_object_get_ex(reMacObj, CFG_STR_CONN_TIMEOUT, &connectionObj);
		json_object_object_get_ex(reMacObj, CFG_STR_TRAFFIC_TIMEOUT, &trafficObj);
		json_object_object_get_ex(reMacObj, CFG_STR_TCODE, &tCodeObj);
		json_object_object_get_ex(reMacObj, CFG_STR_MISC_INFO, &miscInfoObj);

		if (newReMacObj)
			snprintf(newReMac, sizeof(newReMac), "%s", json_object_get_string(newReMacObj));

		if (newReIdObj)
			snprintf(newReId, sizeof(newReId), "%s", json_object_get_string(newReIdObj));

		if (modelNameObj)
			snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(modelNameObj));

		if (sourceObj)
			source = json_object_get_int(sourceObj);

		if (rebootObj)
			rTime = json_object_get_int(rebootObj);

		if (connectionObj)
			cTimeout = json_object_get_int(connectionObj);

		if (trafficObj)
			tTimeout = json_object_get_int(trafficObj);

		if (tCodeObj)
			snprintf(tCode, sizeof(tCode), "%s", json_object_get_string(tCodeObj));

		if (miscInfoObj)
			snprintf(miscInfo, sizeof(miscInfo), "%s", json_object_get_string(miscInfoObj));

#ifdef RSSI_LIST
#define RSSI_ENTRY_LEN	7
		if (rssiObj) {
			memset(rssiList, 0, sizeof(rssiList));
			memset(hexRssiList, 0, sizeof(hexRssiList));
			i = 0;

			snprintf(rssiList, sizeof(rssiList), "%s", json_object_get_string(rssiObj));
			if (str2hex(rssiList, hexRssiList, strlen(rssiList))) {
				for (i = 1; i <= (hexRssiList[0] * RSSI_ENTRY_LEN); i+=RSSI_ENTRY_LEN) {
					memset(reMac, 0, sizeof(reMac));
					snprintf(reMac, sizeof(reMac), "%02X:%02X:%02X:%02X:%02X:%02X",
										hexRssiList[i], hexRssiList[i+1], hexRssiList[i+2],
										hexRssiList[i+3], hexRssiList[i+4], hexRssiList[i+5]);
					rssi = (signed char)hexRssiList[i+6];

					/* fix RSSI value from some platform */
					if(rssi > 0) {
						char *qcaModelList[] = {"Lyra", "LyraMini", "Lyra_Mini", "Lyra_Trio", "LYRA_VOICE"};
						int i;
						for(i=0; i < ARRAY_SIZE(qcaModelList); i++) {
							if(strcmp(modelName, qcaModelList[i]) == 0) {
								#define QCA_DEFAULT_NOISE_FLOOR (-96)	/* via QCA case #03626623 */
								rssi += QCA_DEFAULT_NOISE_FLOOR;
							}
						}
					}

					/* check RE's mac is valid or not */
					if (cm_validateOnboardingRe(reMac)) {
						DBG_INFO("From wireless: reMac(%s), newReMac(%s), modelName(%s), rssi(%d), rTime(%d), cTimeout(%d), tTimeout(%d), type(%d), miscInfo(%s)",
							reMac, newReMac, modelName, rssi, rTime, cTimeout, tTimeout, type, miscInfo);
						cm_processOnboardingCommon(fileRoot, reMac, newReMac, modelName, rssi,
							FROM_WIRELESS, rTime, cTimeout, tTimeout, tCode, type, miscInfo);
					}
				}
			}
		}
#else
		if (rssiObj)
			rssi = json_object_get_int(rssiObj);

		DBG_INFO("reMac(%s), newReMac(%s), modelName(%s), rssi(%d)", reMac, newReMac, modelName, rssi);
		cm_processOnboardingCommon(fileRoot, reMac, newReMac, modelName, rssi);
#endif

		if (source == FROM_ETHERNET) {
			/* check RE's mac is valid or not */
			if (cm_validateOnboardingRe(reMac) && etherListObj) {
				json_object_object_foreach(etherListObj, key, val) {
					rTime = 0;
					cTimeout = 0;
					tTimeout = 0;
					memset(newReMac, 0, sizeof(newReMac));
					memset(modelName, 0, sizeof(modelName));
					memset(tCode, 0, sizeof(tCode));
					memset(miscInfo, 0, sizeof(miscInfo));
					snprintf(newReMac, sizeof(newReMac), "%s", key);
					if (json_object_is_type(val, json_type_string)) {
						snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(val));
						DBG_INFO("From ethernet: reMac(%s), newReMac(%s), modelName(%s), tCode(%s)", reMac, newReMac, modelName, tCode);
						cm_processOnboardingCommon(fileRoot, reMac, newReMac, modelName, 0,
							FROM_ETHERNET, 0, 0, 0, tCode, 0, miscInfo);
					}
					else
					{
						json_object_object_get_ex(val, CFG_STR_MODEL_NAME, &modelNameObj);
						json_object_object_get_ex(val, CFG_STR_REBOOT_TIME, &rebootObj);
						json_object_object_get_ex(val, CFG_STR_CONN_TIMEOUT, &connectionObj);
						json_object_object_get_ex(val, CFG_STR_TRAFFIC_TIMEOUT, &trafficObj);
						json_object_object_get_ex(val, CFG_STR_TCODE, &tCodeObj);
						json_object_object_get_ex(val, CFG_STR_TYPE, &typeObj);
						json_object_object_get_ex(val, CFG_STR_MISC_INFO, &miscInfoObj);

						if (modelNameObj) snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(modelNameObj));
						if (rebootObj) rTime = json_object_get_int(rebootObj);
						if (connectionObj) cTimeout = json_object_get_int(connectionObj);
						if (trafficObj) tTimeout = json_object_get_int(trafficObj);
						if (tCodeObj) snprintf(tCode, sizeof(tCode), "%s", json_object_get_string(tCodeObj));
						if (typeObj) type = json_object_get_int(typeObj);
						if (miscInfoObj) snprintf(miscInfo, sizeof(miscInfo), "%s", json_object_get_string(miscInfoObj));

						DBG_INFO("From ethernet: reMac(%s), newReMac(%s), modelName(%s), rTime(%d), cTimeout(%d), tTimeout(%d), tCode(%s), type(%d), miscInfo(%s)",
							reMac, newReMac, modelName, rTime, cTimeout, tTimeout, tCode, type, miscInfo);
						cm_processOnboardingCommon(fileRoot, reMac, newReMac, modelName, 0,
							FROM_ETHERNET, rTime, cTimeout, tTimeout, tCode, type, miscInfo);
					}
				}
			}
			else
				DBG_INFO("no ethernet list for onboarding");
		}
	}

	/* write to file */
	if (cm_isOnboardingAvailable() && fileRoot)
		json_object_to_file(ONBOARDING_LIST_JSON_PATH, fileRoot);
	json_object_put(fileRoot);
	json_object_put(root);
	file_unlock(lock);
	pthread_mutex_unlock(&onboardingLock);
} /* End of cm_processOnboarding */

/*========================================================================
Routine Description:
	Update onboarding list status.

Arguments:
	reMac		- RE's mac
	newReMac	- New RE's mac
	obStatus		- onboarding status

Return Value:
	None

Note:
==========================================================================
*/
void cm_updateOnboardingListStatus(char *reMac, char *newReMac, int obStatus)
{
	int lock;
	json_object *fileRoot = NULL;
	json_object *reMacObj = NULL;
	json_object *newReMacObj = NULL;
	json_object *newReStatusObj = NULL;
	json_object *modelNameObj = NULL;
	json_object *rssiObj = NULL;
	json_object  *tsObj = NULL, *tsEthObj = NULL;
	json_object *sourceObj = NULL;
	json_object *rTimeObj = NULL, *cTimeoutObj = NULL, *tTimeoutObj = NULL;
	json_object *tCodeObj = NULL;
	json_object *typeObj = NULL;
	json_object *miscInfoObj = NULL;
	char modelName [32] = {0};
	int found = 0;
	long ts = 0, tsEth = 0;
	int rssi = 0;
	int source = 0;
	char tCode [32] = {0};
	int rTime = 0, cTimeout = 0, tTimeout = 0, type = 0;
	char miscInfo[256] = {0};

	DBG_INFO("reMac(%s), newReMac(%s), obStatus(%d)", reMac, newReMac, obStatus);

	pthread_mutex_lock(&onboardingLock);
	lock = file_lock(ONBOARDING_FILE_LOCK);

	fileRoot = json_object_from_file(ONBOARDING_LIST_JSON_PATH);
	if (!fileRoot) {
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			file_unlock(lock);
			pthread_mutex_unlock(&onboardingLock);
			return;
		}
	}

	/* delete new re entry first and then add again */
	json_object_object_foreach(fileRoot, key, val) {
		if (!strcmp(reMac, CFG_STR_RE_MAC)) {	/* no real re mac */
			reMacObj = val;
			found = 0;

			json_object_object_foreach(reMacObj, key, val) {
				if (strcmp(key, newReMac))
					continue;
				newReMacObj = val;

				json_object_object_get_ex(newReMacObj, CFG_STR_STATUS, &newReStatusObj);

				//if (json_object_get_int(newReStatusObj) == OB_STATUS_START) {
					found = 1;
					break;
				//}

			}

			if (found) {
				/* update ob result for this special onboarding*/
				cm_updateOnboardingResult(obStatus, newReMac);

				/* temp store for add later */
				json_object_object_get_ex(newReMacObj, CFG_STR_MODEL_NAME, &modelNameObj);
				if (modelNameObj)
					snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(modelNameObj));

				json_object_object_get_ex(newReMacObj, CFG_STR_RSSI, &rssiObj);
				if (rssiObj)
					rssi = json_object_get_int(rssiObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TIMESTAMP, &tsObj);
				if (tsObj)
					ts = json_object_get_int64(tsObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_SOURCE, &sourceObj);
				if (sourceObj)
					source = json_object_get_int(sourceObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TIMESTAMP_ETH, &tsEthObj);
				if (tsEthObj)
					tsEth = json_object_get_int64(tsEthObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_REBOOT_TIME, &rTimeObj);
				if (rTimeObj)
					rTime = json_object_get_int(rTimeObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_CONN_TIMEOUT, &cTimeoutObj);
				if (cTimeoutObj)
					cTimeout = json_object_get_int(cTimeoutObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TRAFFIC_TIMEOUT, &tTimeoutObj);
				if (tTimeoutObj)
					tTimeout = json_object_get_int(tTimeoutObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TCODE, &tCodeObj);
				if (tCodeObj)
					snprintf(tCode, sizeof(tCode), "%s", json_object_get_string(tCodeObj));

				json_object_object_get_ex(newReMacObj, CFG_STR_TYPE, &typeObj);
				if (typeObj)
					type = json_object_get_int(typeObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_MISC_INFO, &miscInfoObj);
				if (miscInfoObj)
					snprintf(miscInfo, sizeof(miscInfo), "%s", json_object_to_json_string_ext(miscInfoObj, 0));

				json_object_object_del(reMacObj, newReMac);
				newReMacObj = json_object_new_object();

				if (newReMacObj) {
					json_object_object_add(newReMacObj, CFG_STR_STATUS, json_object_new_int(obStatus));
					/* update info */
					if (strlen(modelName))
						json_object_object_add(newReMacObj, CFG_STR_MODEL_NAME, json_object_new_string(modelName));
					else
						json_object_object_add(newReMacObj, CFG_STR_MODEL_NAME, json_object_new_string(""));

					json_object_object_add(newReMacObj, CFG_STR_RSSI, json_object_new_int(rssi));

					if (ts)
						json_object_object_add(newReMacObj, CFG_STR_TIMESTAMP, json_object_new_int64(ts));

					if (source)
						json_object_object_add(newReMacObj, CFG_STR_SOURCE, json_object_new_int(source));

					if (tsEth >= 0)
						json_object_object_add(newReMacObj, CFG_STR_TIMESTAMP_ETH, json_object_new_int64(tsEth));

					if (rTime >= 0)
						json_object_object_add(newReMacObj, CFG_STR_REBOOT_TIME, json_object_new_int(rTime));

					if (cTimeout >= 0)
						json_object_object_add(newReMacObj, CFG_STR_CONN_TIMEOUT, json_object_new_int(cTimeout));

					if (tTimeout >= 0)
						json_object_object_add(newReMacObj, CFG_STR_TRAFFIC_TIMEOUT, json_object_new_int(tTimeout));

					if (strlen(tCode))
						json_object_object_add(newReMacObj, CFG_STR_TCODE, json_object_new_string(tCode));
					else
						json_object_object_add(newReMacObj, CFG_STR_TCODE, json_object_new_string(""));

					if (type >= 0)
						json_object_object_add(newReMacObj, CFG_STR_TYPE, json_object_new_int(type));

					if (strlen(miscInfo))
						json_object_object_add(newReMacObj, CFG_STR_MISC_INFO, json_tokener_parse(miscInfo));

					json_object_object_add(reMacObj, newReMac, newReMacObj);
				}
				break;
			}
		}
		else		/* have real re mac */
		{
			if (strcmp(key, reMac))
				continue;
			reMacObj = val;

			json_object_object_get_ex(reMacObj, newReMac, &newReMacObj);

			if (newReMacObj) {
				/* update ob result for this special onboarding*/
				cm_updateOnboardingResult(obStatus, newReMac);

				/* temp store for add later */
				json_object_object_get_ex(newReMacObj, CFG_STR_MODEL_NAME, &modelNameObj);
				if (modelNameObj)
					snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(modelNameObj));

				json_object_object_get_ex(newReMacObj, CFG_STR_RSSI, &rssiObj);
				if (rssiObj)
					rssi = json_object_get_int(rssiObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TIMESTAMP, &tsObj);
				if (tsObj)
					ts = json_object_get_int64(tsObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_SOURCE, &sourceObj);
				if (sourceObj)
					source = json_object_get_int(sourceObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TIMESTAMP_ETH, &tsEthObj);
				if (tsEthObj)
					tsEth = json_object_get_int64(tsEthObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_REBOOT_TIME, &rTimeObj);
				if (rTimeObj)
					rTime = json_object_get_int(rTimeObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_CONN_TIMEOUT, &cTimeoutObj);
				if (cTimeoutObj)
					cTimeout = json_object_get_int(cTimeoutObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TRAFFIC_TIMEOUT, &tTimeoutObj);
				if (tTimeoutObj)
					tTimeout = json_object_get_int(tTimeoutObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_TCODE, &tCodeObj);
				if (tCodeObj)
					snprintf(tCode, sizeof(tCode), "%s", json_object_get_string(tCodeObj));

				json_object_object_get_ex(newReMacObj, CFG_STR_TYPE, &typeObj);
				if (typeObj)
					type = json_object_get_int(typeObj);

				json_object_object_get_ex(newReMacObj, CFG_STR_MISC_INFO, &miscInfoObj);
				if (miscInfoObj)
					snprintf(miscInfo, sizeof(miscInfo), "%s", json_object_to_json_string_ext(miscInfoObj, 0));

				json_object_object_del(reMacObj, newReMac);
				newReMacObj = json_object_new_object();

				if (newReMacObj) {
					json_object_object_add(newReMacObj, CFG_STR_STATUS, json_object_new_int(obStatus));
					/* update info */
					if (strlen(modelName))
						json_object_object_add(newReMacObj, CFG_STR_MODEL_NAME, json_object_new_string(modelName));
					else
						json_object_object_add(newReMacObj, CFG_STR_MODEL_NAME, json_object_new_string(""));

					json_object_object_add(newReMacObj, CFG_STR_RSSI, json_object_new_int(rssi));

					if (ts)
						json_object_object_add(newReMacObj, CFG_STR_TIMESTAMP, json_object_new_int64(ts));

					if (source)
						json_object_object_add(newReMacObj, CFG_STR_SOURCE, json_object_new_int(source));

					if (tsEth >= 0)
						json_object_object_add(newReMacObj, CFG_STR_TIMESTAMP_ETH, json_object_new_int64(tsEth));

					if (rTime >= 0)
						json_object_object_add(newReMacObj, CFG_STR_REBOOT_TIME, json_object_new_int(rTime));

					if (cTimeout >= 0)
						json_object_object_add(newReMacObj, CFG_STR_CONN_TIMEOUT, json_object_new_int(cTimeout));

					if (tTimeout >= 0)
						json_object_object_add(newReMacObj, CFG_STR_TRAFFIC_TIMEOUT, json_object_new_int(tTimeout));

					if (strlen(tCode))
						json_object_object_add(newReMacObj, CFG_STR_TCODE, json_object_new_string(tCode));
					else
						json_object_object_add(newReMacObj, CFG_STR_TCODE, json_object_new_string(""));

					if (type >= 0)
						json_object_object_add(newReMacObj, CFG_STR_TYPE, json_object_new_int(type));

					if (strlen(miscInfo))
						json_object_object_add(newReMacObj, CFG_STR_MISC_INFO, json_tokener_parse(miscInfo));

					json_object_object_add(reMacObj, newReMac, newReMacObj);
				}
				break;
			}
		}
	}

	/* write to file */
	if (fileRoot)
		json_object_to_file(ONBOARDING_LIST_JSON_PATH, fileRoot);
	json_object_put(fileRoot);
	file_unlock(lock);
	pthread_mutex_unlock(&onboardingLock);
} /* End of cm_updateOnboardingListStatus */


/*
========================================================================
Routine Description:
	Update onboarding success.

Arguments:
	msg		- decrypted message

Return Value:
	0		- no need to update
	1		- need to update

========================================================================
*/
int cm_updateOnboardingSuccess(int keyType, unsigned char *msg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)msg);
	json_object *newReMacObj = NULL, *sta2gObj = NULL, *sta5gObj = NULL, *sta6gObj = NULL;
	json_object *sta2gTrafficObj = NULL, *sta5gTrafficObj = NULL, *sta6gTrafficObj = NULL;
	json_object *bandNumObj = NULL;
	char data[128] = {0};
	int reObSuccessCount = nvram_get_int("cfg_obcount");
	char newReMac[18] = {0}, sta2gMac[18] = {0}, sta5gMac[18] = {0}, sta6gMac[18] = {0};
	int ret  = 0;
	char sta2gMacTraffic[18] = {0}, sta5gMacTraffic[18] = {0}, sta6gMacTraffic[18] = {0};
	char sta2gMacList[128] = {0}, sta5gMacList[128] = {0}, sta6gMacList[128] = {0};
	int reSupportedBandNum = 0;

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		goto err;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_NEW_RE_MAC, &newReMacObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA2G, &sta2gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA5G, &sta5gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA6G, &sta6gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA2G_TRAFFIC, &sta2gTrafficObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA5G_TRAFFIC, &sta5gTrafficObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA6G_TRAFFIC, &sta6gTrafficObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_BANDNUM, &bandNumObj);

	if (newReMacObj == NULL) {
		DBG_ERR("newReMacObj is null");
		goto err;
	}
	else
		snprintf(newReMac, sizeof(newReMac), "%s", json_object_get_string(newReMacObj));

	if (sta2gObj) {
		snprintf(sta2gMac, sizeof(sta2gMac), "%s", json_object_get_string(sta2gObj));
		strlcat(sta2gMacList, sta2gMac, sizeof(sta2gMacList));
	}
	if (sta5gObj) {
		snprintf(sta5gMac, sizeof(sta5gMac), "%s", json_object_get_string(sta5gObj));
		strlcat(sta5gMacList, sta5gMac, sizeof(sta5gMacList));
	}
	if (sta6gObj) {
		snprintf(sta6gMac, sizeof(sta6gMac), "%s", json_object_get_string(sta6gObj));
		strlcat(sta6gMacList, sta6gMac, sizeof(sta6gMacList));
	}
	if (sta2gTrafficObj) {
		if (strlen(sta2gMacList))
			strlcat(sta2gMacList, ",", sizeof(sta2gMacList));
		snprintf(sta2gMacTraffic, sizeof(sta2gMacTraffic), "%s", json_object_get_string(sta2gTrafficObj));
		strlcat(sta2gMacList, sta2gMacTraffic, sizeof(sta2gMacList));
	}
	if (sta5gTrafficObj) {
		if (strlen(sta5gMacList))
			strlcat(sta5gMacList, ",", sizeof(sta5gMacList));
		snprintf(sta5gMacTraffic, sizeof(sta5gMacTraffic), "%s", json_object_get_string(sta5gTrafficObj));
		strlcat(sta5gMacList, sta5gMacTraffic, sizeof(sta5gMacList));
	}
	if (sta6gTrafficObj) {
		if (strlen(sta6gMacList))
			strlcat(sta6gMacList, ",", sizeof(sta6gMacList));
		snprintf(sta6gMacTraffic, sizeof(sta6gMacTraffic), "%s", json_object_get_string(sta6gTrafficObj));
		strlcat(sta6gMacList, sta6gMacTraffic, sizeof(sta6gMacList));
	}
	if (bandNumObj)	reSupportedBandNum = json_object_get_int(bandNumObj);

	nvram_set_int("cfg_obcount", ++reObSuccessCount);
	DBG_INFO("the count of re onboarding success (%d)", reObSuccessCount);

	if ((ret = cm_checkReListUpdate(newReMac, sta2gMacList, sta5gMacList, sta6gMacList))) {
		cm_updateTribandReList(newReMac, reSupportedBandNum, nvram_safe_get("cfg_obmodel"), RELIST_ADD, 0);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		cm_updateReObList(newReMac, RELIST_ADD, 0);
#endif
		cm_updateReList(newReMac, sta2gMacList, sta5gMacList, sta6gMacList, RELIST_ADD);
	}

#ifdef ONBOARDING_VIA_VIF
	if (nvram_get_int("cfg_obvif_ready") == 1 && cm_checkObVifReListUpdate(newReMac)) {
		cm_updateObVifReList(newReMac, nvram_safe_get("cfg_obvif_mac"), RELIST_ADD);
	}
#endif

	if (keyType == KEY_IS_ONBOARDING) {
		/* unset ob key */
		if (nvram_get("cfg_obkey"))
			nvram_unset("cfg_obkey");

		snprintf(data, sizeof(data), "{\"%s\": %d, \"%s\": {\"%s\": \"%s\"} }",
					CFG_STR_STATUS, OB_STATUS_SUCCESS,
					obReMac, CFG_STR_MAC,
					json_object_get_string(newReMacObj));
		cm_processOnboardingMsg(data);
	}

#ifdef RTCONFIG_DWB
	cm_AutoDetect_Dedicated_Wifi_Backhaul(1, 1);
#endif

err:

	json_object_put(decryptedRoot);

	return ret;
} /* End of cm_updateOnboardingSuccess */

/*========================================================================
Routine Description:
	Check new RE's valid or not.

Arguments:
	msg		- decrypted message

Return Value:
	0		- invalid
	1		- valid

Note:
==========================================================================
*/
int cm_checkOnboardingNewReValid(unsigned char *msg)
{
	struct json_object *decryptedRoot = json_tokener_parse((char *)msg);
	json_object *fileRoot = NULL;
	json_object *reMacObj = NULL;
	json_object *newReMacObj = NULL;
	json_object *newReStatusObj = NULL;
	int valid = 0;
	char newReMac[32] = {0};

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		goto err;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_NEW_RE_MAC, &newReMacObj);

	if (newReMacObj == NULL) {
		DBG_ERR("reMacObj is null");
		goto err;
	}

	snprintf(newReMac, sizeof(newReMac), "%s", json_object_get_string(newReMacObj));
	DBG_INFO("newReMac(%s)", newReMac);

	pthread_mutex_lock(&onboardingLock);

	fileRoot = json_object_from_file(ONBOARDING_LIST_JSON_PATH);
	if (fileRoot) {
		json_object_object_foreach(fileRoot, key, val) {
			reMacObj = val;

			json_object_object_foreach(reMacObj, key, val) {
				if (strcmp(key, newReMac))
					continue;
				newReMacObj = val;

				json_object_object_get_ex(newReMacObj, CFG_STR_STATUS, &newReStatusObj);

				if (json_object_get_int(newReStatusObj) == OB_STATUS_WPS_SUCCESS) {
					valid = 1;
					break;
				}
			}

			if (valid)
				break;
		}
	}
	pthread_mutex_unlock(&onboardingLock);

err:

	json_object_put(decryptedRoot);
	json_object_put(fileRoot);

	return valid;
} /* End of cm_checkOnboardingNewReValid */

/*========================================================================
Routine Description:
	Update onboarding vsie for beacon and probe response.

Arguments:
	obStatus		- onboarding status

Return Value:
	None

Note:
==========================================================================
*/
void cm_updateOnboardingVsie(int obStatus)
{
	char data[64] = {0};

	DBG_INFO("update onboarding vsie, obStatus(%d), cfg_obstatus(%d)", obStatus, nvram_get_int("cfg_obstatus"));

	//if (obStatus != nvram_get_int("cfg_obstatus")) {
		snprintf(data, sizeof(data), "{\"%s\": %d}", CFG_STR_TYPE, obStatus);
		cm_processOnboardingEvent(data);
	//}
} /* End of cm_updateOnboardingVsie */

/*========================================================================
Routine Description:
	Update onboarding result.

Arguments:
	obResult		- onboarding result
	newReMac	- new re mac

Return Value:
	None

Note:
==========================================================================
*/
void cm_updateOnboardingResult(int obResult, char *newReMac)
{
	if (newReMac) {
		nvram_set("cfg_newre", newReMac);
		DBG_INFO("update onboarding result, newReMac(%s), cfg_newre(%s)", newReMac, nvram_safe_get("cfg_newre"));
	}
	DBG_INFO("update onboarding result, obResult(%d), cfg_obresult(%d)", obResult, nvram_get_int("cfg_obresult"));
	nvram_set_int("cfg_obresult", obResult);
} /* End of cm_updateOnboardingResult */

/*========================================================================
Routine Description:
	Select onboarding path (wireless/ethernet).

Arguments:
	*newReMac	- new re mac

Return Value:
	onboarding path
	0		- any error

Note:
==========================================================================
*/
int cm_selectOnboardingPath(char *newReMac)
{
	json_object *fileRoot = NULL;
	json_object *reMacObj = NULL;
	json_object *sourceObj = NULL;
	int lock;
	int ethPath = 0;
	int ret = 0;

	if (!newReMac) {
		DBG_ERR("newReMac is NULL");
		return ret;
	}

	DBG_INFO("newReMac (%s)", newReMac);

	pthread_mutex_lock(&onboardingLock);
	lock = file_lock(ONBOARDING_FILE_LOCK);

	fileRoot = json_object_from_file(ONBOARDING_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		file_unlock(lock);
		pthread_mutex_unlock(&onboardingLock);
		return ret;
	}

	json_object_object_foreach(fileRoot, key, val) {
		reMacObj = val;

		json_object_object_foreach(reMacObj, key, val) {
			if (strcmp(newReMac, key) == 0) {
				json_object_object_get_ex(val, CFG_STR_SOURCE, &sourceObj);
				if (sourceObj) {
					if ((json_object_get_int(sourceObj) & FROM_ETHERNET) == FROM_ETHERNET) {
						ethPath = 1;
						break;
					}
				}
			}
		}
	}

	ret = (ethPath ==1) ? FROM_ETHERNET: FROM_WIRELESS;

	json_object_put(fileRoot);
	file_unlock(lock);
	pthread_mutex_unlock(&onboardingLock);

	DBG_INFO("onboarding path is via %s", (ret == FROM_ETHERNET) ? "ethernet": "wireless");
	nvram_set_int("cfg_obpath", ret);

	return ret;
} /* End of cm_selectOnboardingPath */

/*========================================================================
Routine Description:
	Get onboarding path (wireless/ethernet).

Arguments:
	None

Return Value:
	onboarding path

Note:
==========================================================================
*/
int cm_getOnboardingPath()
{
	return nvram_get_int("cfg_obpath");
} /* End of cm_getOnboardingPath */

/*========================================================================
Routine Description:
	Set onboarding path (wireless/ethernet).

Arguments:
	None

Return Value:
	None

Note:
==========================================================================
*/
void cm_setOnboardingPath(int obPath)
{
	nvram_set_int("cfg_obpath", obPath);
} /* End of cm_setOnboardingPath */

/*
========================================================================
Routine Description:
	Process onboarding status from ethevent.

Arguments:
	data		- received data

Return Value:
	None

Note:
========================================================================
*/
void cm_processEthOnboardingStatus(unsigned char *data)
{
	json_object *eventRoot = json_tokener_parse((char *)data);
	json_object *ethEventObj = NULL;
	json_object *obStatusObj = NULL;
	json_object *obKeyObj = NULL;
	unsigned char msg[256] = {0};

	if (!eventRoot) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_get_ex(eventRoot, ETHEVENT_PREFIX, &ethEventObj);
	json_object_object_get_ex(ethEventObj, OB_STATUS, &obStatusObj);

	if (!obStatusObj)  {
		DBG_ERR("obStatusObj is null");
		json_object_put(eventRoot);
		return;
	}

	if (json_object_get_int(obStatusObj) == OB_STATUS_WPS_SUCCESS) {
		json_object_object_get_ex(ethEventObj, OB_KEY, &obKeyObj);
		if (!obKeyObj) {
			DBG_ERR("obKeyObj is null");
			json_object_put(eventRoot);
			return;
		}
	}

	/* update status */
	if (json_object_get_int(obStatusObj) == OB_STATUS_WPS_SUCCESS) {
		snprintf((char *)msg, sizeof(msg), "{\"%s\": %d, \"%s\": {\"%s\": \"%s\", \"%s\": \"%s\"} }",
			CFG_STR_STATUS, json_object_get_int(obStatusObj),
			get_unique_mac(), CFG_STR_MAC, obNewReMac,
			CFG_STR_OB_KEY, json_object_get_string(obKeyObj));
	}
	else
	{
		snprintf((char *)msg, sizeof(msg), "{\"%s\": %d, \"%s\": {\"%s\": \"%s\"} }",
			CFG_STR_STATUS, json_object_get_int(obStatusObj),
			get_unique_mac(), CFG_STR_MAC, obNewReMac);
	}

	DBG_INFO("msg(%s)", msg);

	if (cm_ctrlBlock.role == IS_CLIENT) {
		/* send TCP packet */
		if (cm_sendTcpPacket(REQ_ONBOARDING, &msg[0]) == 0)
			DBG_ERR("Fail to send TCP packet!");
	}
	else
		cm_processOnboardingMsg((char *)msg);

	json_object_put(eventRoot);
} /* End of cm_processEthOnboardingStatus */

/*========================================================================
Routine Description:
	Delete onboarding list.

Arguments:
	None

Return Value:
	None

Note:
==========================================================================
*/
void cm_removeOnboardingList()
{
	int lock;

	pthread_mutex_lock(&onboardingLock);
	lock = file_lock(ONBOARDING_FILE_LOCK);

	unlink(ONBOARDING_LIST_JSON_PATH);

	file_unlock(lock);
	pthread_mutex_unlock(&onboardingLock);
} /* End of cm_removeOnboardingList */

#ifdef PRELINK
/*
========================================================================
Routine Description:
	Update RE prelink status.

Arguments:
	reMac		- RE's mac
	status	- status

Return Value:
	None

Note:
========================================================================
*/
void cm_updatePrelinkStatus(char *reMac, int status)
{
	json_object *fileRoot = NULL, *reMacObj = NULL, *statusObj = NULL;
	int lock, update = 0;

	if (!reMac) {
		DBG_ERR("reMac is NULL");
		return;
	}

	DBG_INFO("reMac (%s)", reMac);

	pthread_mutex_lock(&prelinkLock);
	lock = file_lock(PRELINK_FILE_LOCK);

	fileRoot = json_object_from_file(PRELINK_LIST_JSON_PATH);
	if (!fileRoot) {
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			file_unlock(lock);
			pthread_mutex_unlock(&prelinkLock);
			return;
		}
	}

	json_object_object_get_ex(fileRoot, reMac, &reMacObj);
	if (reMacObj) {
		if (status == PRELINK_JOIN) {
			json_object_object_get_ex(reMacObj, CFG_STR_STATUS, &statusObj);
			if (statusObj) {
				if (json_object_get_int(statusObj) == PRELINK_JOIN)
					goto exit;

				if (status > json_object_get_int(statusObj)) {
					update = 1;
					DBG_LOG("Prelink RE (%s) join", reMac);
				}
			}
		}
		else
			update = 1;

		if (update)
		{
			json_object_object_del(reMacObj, CFG_STR_STATUS);
			json_object_object_add(reMacObj, CFG_STR_STATUS, json_object_new_int(status));
		}
	}
	else
	{
		if (status == PRELINK_JOIN)
			goto exit;

		reMacObj = json_object_new_object();
		if (reMacObj) {
			json_object_object_add(reMacObj, CFG_STR_STATUS, json_object_new_int(status));
			json_object_object_add(fileRoot, reMac, reMacObj);
		}
	}

	if (fileRoot)
		json_object_to_file(PRELINK_LIST_JSON_PATH, fileRoot);

exit:

	json_object_put(fileRoot);
	file_unlock(lock);
	pthread_mutex_unlock(&prelinkLock);
} /* End of cm_updatePrelinkStatus */
#endif

/*
========================================================================
Routine Description:
	Update info in vsie.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void update_vsie_info()
{
#if defined(RTCONFIG_QCA)
	int i = 0;
	int wifi_count = nvram_get("cfg_wifi_count") ? nvram_get_int("cfg_wifi_count") : 10;		//times
	int wifi_wait = nvram_get("cfg_wifi_wait") ? nvram_get_int("cfg_wifi_wait") : 5;		//sec
#endif

#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{

#if defined(RTCONFIG_QCA)
	/* check wifi ready or not */
	while (!nvram_get_int("wlready")) {
		if (i > wifi_count) break;
		sleep(wifi_wait);
		i++;
	}
#endif

	cm_updateOnboardingVsie(nvram_get_int("cfg_obstatus"));	/* update vsie hash bundle key */
	}
}

#ifdef ONBOARDING_VIA_VIF
/*
========================================================================
Routine Description:
	Check capability for onboarding via vif.

Arguments:
	mac		- Cap/Re unique mac

Return Value:
	0		- onboarding via main i/f
	1		- onboarding via virtual i/f

Note:
========================================================================
*/
int cm_checkOnboardingVifCapability(char *mac)
{
	int ret = 0, unit = WL_2G_BAND;
	char tmp[64], prefix[] = "wlXXXXX_";

	/* check security is setting WPA3-Personal */
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "sae")) {
		if (strcmp(mac, get_re_hwaddr()) == 0) {	/* For CAP */
			if (strstr(nvram_safe_get("rc_support"), "wpa3") != NULL)
				ret = 1;
		}
		else		/* for RE */
		{
			ret = cm_isCapSupported(mac, RC_SUPPORT, VIF_ONBOARDING);
		}
	}

	return ret;
} /* End of cm_checkOnboardingViaVif */

/*
========================================================================
Routine Description:
	Wait onboarding vif ready

Arguments:
	mac		- CAP/RE mac address

Return Value:
	0		- wait fail
	1		- wait success

Note:
========================================================================
*/
int cm_waitOnboardingVifReady(char *mac)
{
	int t = 0, ret = 0;
	int timeout = nvram_get("cfg_vif_check_tm") ? nvram_get_int("cfg_vif_check_tm") : TIMEOUT_FOR_VIF_CHECK;

	while (t <= timeout) {
		/* check vif ready or not from report */
		if (nvram_get_int("cfg_obvif_ready") == 1) {	/* ready */
			nvram_set_int("cfg_obvif_time", t);
			ret = 1;
			break;
		}
		else if (nvram_get_int("cfg_obvif_ready") == 0) {	/* fail or not ready */
			ret = 0;
			break;
		}
		sleep(ONBOARDING_CHECK_TIME);
		t += ONBOARDING_CHECK_TIME;
	}

	if (ret)
		DBG_INFO("%s vif is ready", mac);
	else
		DBG_INFO("%s vif is not ready", mac);

	return ret;
} /* End of cm_waitOnboardingVifReady */

/*
========================================================================
Routine Description:
	Thread for up onboarding vif.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void *cm_upOnboardingVif(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());

	int vifStatus = 0, t = 0;
	unsigned char data[128] = {0};
	int unit = WL_2G_BAND, subunit =nvram_get_int("obvif_cap_subunit");
	char tmp[64], prefix[] = "wlXXXXX_";

	if (nvram_get_int("re_mode") == 1)	/* for RE */
		subunit =nvram_get_int("obvif_re_subunit");

	snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);

	if (cm_obVifDownUp(OB_VIF_UP)) {
		vifStatus = 1;
		nvram_set_int("wps_via_vif", 1);
	}

	snprintf((char *)data, sizeof(data), "{\"%s\":%d,\"%s\":%d,\"%s\":\"%s\"}",
		CFG_STR_STATUS, OB_STATUS_REPORT_VIF_STATUS,
		CFG_STR_VIF_STATUS, vifStatus, CFG_STR_OB_KEY, nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)));

	if (cm_ctrlBlock.role == IS_SERVER) {
		cm_processOnboardingMsg((char *)data);
	}
	else
	{
		/* send TCP packet */
		if (cm_sendTcpPacket(REQ_ONBOARDING, &data[0]) == 0) {
			DBG_ERR("Fail to send TCP packet!");
			if (vifStatus) {
				nvram_unset("wps_via_vif");
				cm_obVifDownUp(OB_VIF_DOWN);
			}
		}
	}

	if (vifStatus) {
		/* wait vif down */
		DBG_INFO("start to wait vif down (%d)", vifDownTimeout);
		while (t <= vifDownTimeout) {
			if (vifIsUp == 0) {
				DBG_INFO("vif is down, stop to wait");
				break;
			}
			sleep(ONBOARDING_CHECK_TIME);
			t += ONBOARDING_CHECK_TIME;
		}

		if (vifIsUp)
			cm_obVifDownUp(OB_VIF_DOWN);
	}

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_upOnboardingVif */

/*
========================================================================
Routine Description:
	Compute timeout for down vif.

Arguments:
	rtime		- reboot time
	cTimeout		- connection timeout
	tTimeout		- traffic timeout

Return Value:
	None

========================================================================
*/
void cm_computeVifDownTimeout(int rTime, int cTimeout, int tTimeout)
{
	vifDownTimeout = 0;
	vifDownTimeout += TIMEOUT_CONFIG_SYNC + WPS_TIMEOUT;
	if (rTime == 0 || cTimeout == 0 || tTimeout == 0)
		vifDownTimeout += REBOOT_DEF_TIME + CONNECTION_DEF_TIMEOUT + TRAFFIC_DEF_TIMEOUT;
	else
		vifDownTimeout += rTime + cTimeout + tTimeout;
	DBG_INFO("the timeout(%d) for down vif", vifDownTimeout);
} /* End of cm_computeVifDownTimeout */

/*
========================================================================
Routine Description:
	Update the status of vif up.

Arguments:
	status		- the down(0)/up(1) status

Return Value:
	None

========================================================================
*/
void cm_updateVifUpStatus(int status)
{
	DBG_INFO("change the status of vif up from %d  to %d", vifIsUp, status);
	vifIsUp = status;
	nvram_set_int("cfg_obvif_up", status);
} /* End of cm_updateVifStatus */

/*
========================================================================
Routine Description:
	Down/up ob vif.

Arguments:
	action		- action for ob vif

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_obVifDownUp(int action)
{
	int ret = 0;
	int unit = WL_2G_BAND, subunit =nvram_get_int("obvif_cap_subunit");

	if (vifIsUp == action) {
		DBG_INFO("action (%d) is same as vifIsUp (%d), do nothing", action, vifIsUp);
		return 1;
	}

	if (nvram_get_int("re_mode") == 1)	/* for RE */
		subunit =nvram_get_int("obvif_re_subunit");

	if (action == OB_VIF_DOWN) {
		DBG_INFO("down ob vif");
		//down vif
		set_wlan_service_status(unit, subunit, 0);
		if (get_wlan_service_status(unit, subunit) == 0)
			ret = 1;
	}
	else if (action == OB_VIF_UP) {
		DBG_INFO("up ob vif");
		//up vif
		set_wlan_service_status(unit, subunit, 1);
		if (get_wlan_service_status(unit, subunit) > 0)
			ret = 1;
	}

	if (ret)
		cm_updateVifUpStatus(action);

	return ret;
} /* End of cm_obVifDownUp */
#endif
