#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_slavelist.h"
#include "cfg_wevent.h"
#ifdef RTCONFIG_BHCOST_OPT
#include "cfg_clientlist.h"
#include <wlioctl.h>
#include <wlutils.h>
#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#endif

/*
========================================================================
Routine Description:
	Check whether RE is on relist.

Arguments:
	mac		- mac for the MAC is be checked

Return Value:
	0			- The MAC isn't on relist
	1			- The MAC is on relist

========================================================================
*/
int cm_checkReListExist(char *mac)
{
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	int exist = 0;
	int ret = 0;

	//DBG_INFO("Mac (%s)", Mac);

	if (mac == NULL) {
		DBG_LOG("mac is null");
		return 0;
	}

	if (strlen(mac) == 0) {
		DBG_LOG("the length of mac is 0");
		return 0;
	}

	if (!isValidMacAddress(mac)) {
		DBG_LOG("mac (%s) is invalid", mac);
		return 0;
	}

	pthread_mutex_lock(&reListLock);
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if (strlen(b) == 0)
				continue;

			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			if (strlen(reMac) == 0)
				continue;

			if (strcmp(mac, reMac) == 0)
				exist = 1;
		}
		free(nv);
	}
	pthread_mutex_unlock(&reListLock);

	if (exist)
		ret = 1;

	return ret;	
}

/*
========================================================================
Routine Description:
	Check whether need to update RE list.

Arguments:
	newReMac		- mac for new RE
	sta2gMac			- 2G upstream mac for new RE
	sta5gMac			- 5G upstream mac for new RE
	sta6gMac			- 6G upstream mac for new RE

Return Value:
	0			- no need to update the information of re list
	1			- need to update the information of re list

========================================================================
*/
int cm_checkReListUpdate(char *newReMac, char *sta2gMac, char *sta5gMac, char *sta6gMac)
{
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	char *mac6g, *reserved1, *reserved2;
	int exist = 0;
	int update = 0;
	int ret = 0;

	DBG_INFO("newReMac (%s), sta2gMac (%s), sta5gMac (%s), sta6gMac (%s)",
		newReMac, sta2gMac, sta5gMac, sta6gMac);

	if (newReMac == NULL) {
		DBG_LOG("newReMac is null");
		return 0;
	}

	if (strlen(newReMac) == 0) {
		DBG_LOG("the length of newReMac is 0");
		return 0;
	}

	if (!isValidMacAddress(newReMac)) {
		DBG_LOG("newReMac (%s) is invalid", newReMac);
		return 0;
	}

	if (newReMac == NULL) {
		DBG_LOG("newReMac is null");
		return 0;
	}

	if (strlen(newReMac) == 0) {
		DBG_LOG("the length of newReMac is 0");
		return 0;
	}

	if (!isValidMacAddress(newReMac)) {
		DBG_LOG("newReMac (%s) is invalid", newReMac);
		return 0;
	}

	pthread_mutex_lock(&reListLock);
	/* in cfg_relist */
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			if (strcmp(newReMac, reMac) == 0) {
				exist = 1;
				/* check whether need to update for 2G/5G */
				if (strcmp(sta2gMac, mac2g) != 0 || 
					strcmp(sta5gMac, mac5g) != 0)
					update = 1;
			}
		}
		free(nv);
	}

	/* in cfg_relist_x */
	nv = nvp = strdup(nvram_safe_get("cfg_relist_x"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &reMac, &mac6g, &reserved1, &reserved2) != 4))
				continue;

			if (strcmp(newReMac, reMac) == 0) {
				exist = 1;
				/* check whether need to update for 6G */
				if (strcmp(sta6gMac, mac6g) != 0)
					update = 1;
			}
		}
		free(nv);
	}
	pthread_mutex_unlock(&reListLock);

	if (update == 1 || exist == 0)
		ret = 1;

	return ret;
} /* End of cm_checkReListUpdate */

/*
========================================================================
Routine Description:
	Remove expired RE.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_removeExpiredRe()
{
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	char *mac6g, *reserved1, *reserved2;
	char reEntry[128] = {0};
	char reList[RE_LIST_MAX_LEN] = {0};
	long expiredTs = 0;
	char expiredRe[18] = {0};
	int count = 0, update = 0;
	
	/* find expired RE */
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			if (expiredTs == 0 || expiredTs > strtol(timestamp, NULL, 10)) {
				expiredTs = strtol(timestamp, NULL, 10);
				memset(expiredRe, 0, sizeof(expiredRe));
				snprintf(expiredRe, sizeof(expiredRe), "%s", reMac);
			}
		}
		free(nv);
	}

	/* remove expired RE */
	if (strlen(expiredRe)) {
		DBG_INFO("the expired re (%s) and timestamp (%ld)", expiredRe, expiredTs);

		/* in cfg_relist */
		nv = nvp = strdup(nvram_safe_get("cfg_relist"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
					continue;

				if (strcmp(expiredRe, reMac) == 0)
					continue;

				count++;

				memset(reEntry, 0, sizeof(reEntry));
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%s",
							reMac, mac2g, mac5g, timestamp);

				strncat(reList, reEntry, strlen(reEntry));
			}
			free(nv);

			nvram_set("cfg_relist", reList);
			nvram_set_int("cfg_recount", count);
			update = 1;
		}

		/* in cfg_relist_x */
		memset(reList, 0, sizeof(reList));
		nv = nvp = strdup(nvram_safe_get("cfg_relist_x"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &reMac, &mac6g, &reserved1, &reserved2) != 4))
					continue;

				if (strcmp(expiredRe, reMac) == 0)
					continue;

				count++;

				memset(reEntry, 0, sizeof(reEntry));
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>>", reMac, mac6g);

				strncat(reList, reEntry, strlen(reEntry));
			}
			free(nv);

			nvram_set("cfg_relist_x", reList);
			update = 1;
		}

		if (update)
			nvram_commit();
	}
} /* End of cm_removeExpiredRe */

/*
========================================================================
Routine Description:
	Update RE list.

Arguments:
	newReMac		- mac for new RE
	sta2gMac			- 2G upstream mac for new RE
	sta5gMac			- 5G upstream mac for new RE
	sta6gMac			- 6G upstream mac for new RE
	action			- add/del

Return Value:
	None

========================================================================
*/
void cm_updateReList(char *newReMac, char *sta2gMac, char *sta5gMac, char *sta6gMac, int action)
{
	json_object *root = NULL;
	json_object *reEntryObj = NULL;
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	char *mac6g, *reserved1, *reserved2;
	int exist = 0;
	int update = 0;
	int count = 0;
	char reEntry[128] = {0};
	char reList[RE_LIST_MAX_LEN] = {0};
	time_t ts;
	int configUpdate = 0;

	if (newReMac == NULL) {
		DBG_LOG("newReMac is null");
		return;
	}

	if (strlen(newReMac) == 0) {
		DBG_LOG("the length of newReMac is 0");
		return;
	}

	if (!isValidMacAddress(newReMac)) {
		DBG_LOG("newReMac (%s) is invalid", newReMac);
		return;
	}

	time(&ts);

	DBG_LOG("newReMac (%s), sta2gMac (%s), sta5gMac (%s), sta6gMac (%s)",
		newReMac, sta2gMac, sta5gMac, sta6gMac);

	root = json_object_new_object();

	if (!root) {
		DBG_LOG("root is NULL");
		return;
	}

	pthread_mutex_lock(&reListLock);
	if (action != RELIST_DEL && nvram_get_int("cfg_recount") > MAX_RELIST_COUNT)
		cm_removeExpiredRe();

	/* in cfg_relist */
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			update = 0;

			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			if (strcmp(newReMac, reMac) == 0) {
				if (action == RELIST_DEL)
					continue;

				exist = 1;

				/* check whether need to update for 2G/5G */
				if (strcmp(sta2gMac, mac2g) != 0 || 
					strcmp(sta5gMac, mac5g) != 0)
					update = 1;		
			}

			memset(reEntry, 0, sizeof(reEntry));
			if (update)
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%ld",
						reMac, sta2gMac, sta5gMac, ts);
			else
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%s",
						reMac, mac2g, mac5g, timestamp);

			reEntryObj = json_object_new_object();
			if (reEntryObj) {
				json_object_object_add(reEntryObj, CFG_STR_STA2G,
						update ? json_object_new_string(sta2gMac) : json_object_new_string(mac2g));
				json_object_object_add(reEntryObj, CFG_STR_STA5G,
						update ? json_object_new_string(sta5gMac) : json_object_new_string(mac5g));
				json_object_object_add(root, reMac, reEntryObj);
			}

			strncat(reList, reEntry, strlen(reEntry));
			count++;
		}
		free(nv);

		if (exist == 0 && (action == RELIST_ADD || action == RELIST_UPDATE)) {
			memset(reEntry, 0, sizeof(reEntry));
			snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%ld",
						newReMac, sta2gMac, sta5gMac, ts);
			strncat(reList, reEntry, strlen(reEntry));

			reEntryObj = json_object_new_object();
			
			if (reEntryObj) {
				json_object_object_add(reEntryObj, CFG_STR_STA2G, json_object_new_string(sta2gMac));
				json_object_object_add(reEntryObj, CFG_STR_STA5G, json_object_new_string(sta5gMac));
				json_object_object_add(root, newReMac, reEntryObj);
			}
#if defined(RTCONFIG_QCA_LBD)
			int add_lbd_list(const char *mac, const char *sta2g, const char *sta5g);
			add_lbd_list(newReMac,sta2gMac,sta5gMac);
#endif
			count++;
		}
		nvram_set("cfg_relist", reList);
		nvram_set_int("cfg_recount", count);
		configUpdate = 1;
	}

	/* in cfg_relist_x */
	exist = 0;
	memset(reList, 0, sizeof(reList));
	nv = nvp = strdup(nvram_safe_get("cfg_relist_x"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			update = 0;

			if ((vstrsep(b, ">", &reMac, &mac6g, &reserved1, &reserved2) != 4))
				continue;

			if (strcmp(newReMac, reMac) == 0) {
				if (action == RELIST_DEL)
					continue;

				exist = 1;

				/* check whether need to update for 6G */
				if (strcmp(sta6gMac, mac6g) != 0)
					update = 1;
			}

			memset(reEntry, 0, sizeof(reEntry));
			if (update)
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>>", reMac, sta6gMac);
			else
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>>", reMac, mac6g);

			json_object_object_get_ex(root, reMac, &reEntryObj);
			if (reEntryObj) {
				json_object_object_add(reEntryObj, CFG_STR_STA6G,
						update ? json_object_new_string(sta6gMac) : json_object_new_string(mac6g));
			}

			strncat(reList, reEntry, strlen(reEntry));
		}
		free(nv);

		if (exist == 0 && (action == RELIST_ADD || action == RELIST_UPDATE)) {
			memset(reEntry, 0, sizeof(reEntry));
			snprintf(reEntry, sizeof(reEntry), "<%s>%s>>", newReMac, sta6gMac);
			strncat(reList, reEntry, strlen(reEntry));

			json_object_object_get_ex(root, newReMac, &reEntryObj);
			if (reEntryObj) {
				json_object_object_add(reEntryObj, CFG_STR_STA6G, json_object_new_string(sta6gMac));
			}
		}
		nvram_set("cfg_relist_x", reList);
	}

	if (configUpdate) {
		nvram_commit();
		json_object_to_file(RE_LIST_JSON_FILE, root);
	}

	json_object_put(root);
	pthread_mutex_unlock(&reListLock);

	/* remove sta connected history */
	if (action == RELIST_DEL) {
		if (strlen(sta2gMac))
			cm_removeReWifiConnectedHistory(sta2gMac);
		if (strlen(sta5gMac))
			cm_removeReWifiConnectedHistory(sta5gMac);
		if (strlen(sta6gMac))
			cm_removeReWifiConnectedHistory(sta6gMac);
	}
} /* End of cm_updateReList */

/*
========================================================================
Routine Description:
	Handle RE list update notification.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
void cm_handleReListUpdate(unsigned char *decodeMsg)
{
	json_object *root = json_tokener_parse((char *)decodeMsg);
	json_object *sta2gObj = NULL, *sta5gObj = NULL, *sta6gObj = NULL;
	char reEntry[128] = {0};
	char reList[RE_LIST_MAX_LEN] = {0}, reListX[RE_LIST_MAX_LEN] = {0};
	char sta2gMacList[128] = {0}, sta5gMacList[128] = {0}, sta6gMacList[128] = {0};

	DBG_INFO("msg(%s)", (char *)decodeMsg);
	
	if (root == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	/* remove uncessary item */
	json_object_object_del(root, CFG_STR_NOTIFY_TYPE);

	/* update to file */

	json_object_to_file(RE_LIST_JSON_FILE, root);

	/* update to nvram */
	json_object_object_foreach(root, key, val) {
		/* for cfg_relist */
		json_object_object_get_ex(val, CFG_STR_STA2G, &sta2gObj);
		json_object_object_get_ex(val, CFG_STR_STA5G, &sta5gObj);

		memset(reEntry, 0, sizeof(reEntry));
		memset(sta2gMacList, 0, sizeof(sta2gMacList));
		memset(sta5gMacList, 0, sizeof(sta5gMacList));

		if (sta2gObj)
			snprintf(sta2gMacList, sizeof(sta2gMacList), "%s", json_object_get_string(sta2gObj));
		if (sta5gObj)
			snprintf(sta5gMacList, sizeof(sta5gMacList), "%s", json_object_get_string(sta5gObj));

		snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>0", key, sta2gMacList, sta5gMacList);
		strncat(reList, reEntry, strlen(reEntry));
#if defined(RTCONFIG_QCA_LBD)
		int add_lbd_list(const char *mac, const char *sta2g, const char *sta5g);
		add_lbd_list(key,sta2gMacList,sta5gMacList);
#endif

		/* for cfg_relist_x */
		json_object_object_get_ex(val, CFG_STR_STA6G, &sta6gObj);

		memset(reEntry, 0, sizeof(reEntry));
		memset(sta6gMacList, 0, sizeof(sta6gMacList));

		if (sta6gObj)
			snprintf(sta6gMacList, sizeof(sta6gMacList), "%s", json_object_get_string(sta6gObj));

		snprintf(reEntry, sizeof(reEntry), "<%s>%s>>", key, sta6gMacList);
		strncat(reListX, reEntry, strlen(reEntry));
	}

	if (strlen(reList))
		f_write_string(CFG_RELIST_FILE, reList, 0, 0);

	if (strlen(reListX))
		f_write_string(CFG_RELIST_X_FILE, reListX, 0, 0);

	json_object_put(root);

	wl_set_macfilter_list();
} /* End of cm_handleReListUpdate */

/*
========================================================================
Routine Description:
	Check whether RE wifi upstream mac or not.

Arguments:
	staMac			- 2G/5G upstream mac for new RE

Return Value:
	0			- It's not RE wifi upstream mac
	1			- It's RE wifi upstream mac

========================================================================
*/
int cm_isReWifiUpstreamMac(char *staMac)
{
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	char *mac6g, *reserved1, *reserved2;
	int ret = 0;

	if (staMac == NULL) {
		DBG_ERR("staMac is NULL");
		return ret;
	}

	pthread_mutex_lock(&reListLock);
	/* in cfg_relist */
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			/* check whether RE wifi upstream mac */
			if (strstr(staMac, mac2g) && cm_reExistInClientList(reMac) == 1) {
				DBG_INFO("%s is RE (%s) 2G upstream mac", staMac, reMac);
				ret = 1;
				break;
			}

			if (ret == 0 && strstr(staMac, mac5g) && cm_reExistInClientList(reMac) == 1) {
				DBG_INFO("%s is RE (%s) 5G upstream mac", staMac, reMac);
				ret = 1;
				break;
			}
		}
		free(nv);
	}

	/* in cfg_relist_x */
	if (ret == 0) {
		nv = nvp = strdup(nvram_safe_get("cfg_relist_x"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &reMac, &mac6g, &reserved1, &reserved2) != 4))
					continue;

				if (strlen(mac6g) == 0)
					continue;

				/* check whether RE wifi upstream mac */
				if (strstr(staMac, mac6g) && cm_reExistInClientList(reMac) == 1) {
					DBG_INFO("%s is RE (%s) 6G upstream mac", staMac, reMac);
					ret = 1;
					break;
				}
			}
			free(nv);
		}
	}
	pthread_mutex_unlock(&reListLock);

	return ret;
} /* End of cm_isReWifiUpstreamMac */

#ifdef RTCONFIG_BCN_RPT
/*
========================================================================
Routine Description:
	Handle RE list update notification.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
void cm_handleAPListUpdate(unsigned char *decodeMsg)
{
	json_object *root = json_tokener_parse((char *)decodeMsg);
	if(!root) goto err;
	/* update to file */

	json_object_to_file(AP_LIST_JSON_FILE, root);

#ifdef RTCONFIG_NBR_RPT
	DBG_INFO("reset nbr");
	nvram_unset("channel_2g");
#endif

err:
	json_object_put(root);

} /* End of cm_handleAPListUpdate */

/*
========================================================================
Routine Description:
	Prepare message for AP list.

Arguments:
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
int cm_prepareAPListMsg(char *msg, int msgLen)
{
	json_object *fileRoot = NULL;

	if ((fileRoot = json_object_from_file(AP_LIST_JSON_FILE)) != NULL) {
		snprintf(msg, msgLen, "%s", json_object_to_json_string(fileRoot));
		DBG_INFO("msg(%s)", msg);
		json_object_put(fileRoot);
	}

	return strlen(msg);
} /* End of cm_prepareAPListMsg */
#endif
/*
========================================================================
Routine Description:
	Prepare message for RE list.

Arguments:
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
int cm_prepareReListMsg(char *msg, int msgLen)
{
	json_object *fileRoot = NULL;
	
	if ((fileRoot = json_object_from_file(RE_LIST_JSON_FILE)) != NULL) {
		snprintf(msg, msgLen, "%s", json_object_to_json_string(fileRoot));
		DBG_INFO("msg(%s)", msg);
		json_object_put(fileRoot);
	}

	return strlen(msg);
} /* End of cm_prepareReListMsg */

/*
========================================================================
Routine Description:
	Generate RE list.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_generateReList()
{
	json_object *root = NULL;
	json_object *reEntryObj = NULL;
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	char *mac6g, *reserved1, *reserved2;

	cm_reorganizeReList();	/* reorganize re list if needed */

	root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return;
	}

	pthread_mutex_lock(&reListLock);
	/* in cfg_relist */
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			reEntryObj = json_object_new_object();
			if (reEntryObj) {
				json_object_object_add(reEntryObj, CFG_STR_STA2G, json_object_new_string(mac2g));
				json_object_object_add(reEntryObj, CFG_STR_STA5G, json_object_new_string(mac5g));
				json_object_object_add(root, reMac, reEntryObj);
			}
		}
		free(nv);
	}

	/* in cfg_relist_x */
	nv = nvp = strdup(nvram_safe_get("cfg_relist_x"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &reMac, &mac6g, &reserved1, &reserved2) != 4))
				continue;

			json_object_object_get_ex(root, reMac, &reEntryObj);
			if (reEntryObj) {
				json_object_object_add(reEntryObj, CFG_STR_STA6G, json_object_new_string(mac6g));
			}
		}
		free(nv);
	}

	json_object_to_file(RE_LIST_JSON_FILE, root);

	json_object_put(root);
	pthread_mutex_unlock(&reListLock);
} /* End of cm_generateReList */

/*
========================================================================
Routine Description:
	Update the timestamp of RE list.

Arguments:
	decodeMsg		- decrypted message

Return Value:
	None

========================================================================
*/
void cm_updateReListTimestamp(unsigned char *decodeMsg)
{
	json_object *root = json_tokener_parse((char *)decodeMsg);
	json_object *reMacObj = NULL;
	char *nv, *nvp, *b;
	char *rMac, *mac2g, *mac5g, *timestamp;
	char reEntry[128] = {0};
	char reList[RE_LIST_MAX_LEN] = {0};
	time_t ts;
	char reMac[18] = {0};
	int updateTs = 0;

	if (root == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(root, CFG_STR_MAC, &reMacObj);
	if (reMacObj) {
		snprintf(reMac, sizeof(reMac), "%s", json_object_get_string(reMacObj));
		if (strlen(reMac) == 0) {
			DBG_ERR("reMac is NULL!");
			json_object_put(root);
			return;
		}
	}
	else
	{
		DBG_ERR("reMacObj is NULL!");
		json_object_put(root);
		return;
	}
	json_object_put(root);
	
	time(&ts);

	pthread_mutex_lock(&reListLock);
	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			updateTs = 0;

			if ((vstrsep(b, ">", &rMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			if (strcmp(reMac, rMac) == 0) {
				if (ts > strtol(timestamp, NULL, 10))
					updateTs = 1;
			}

			memset(reEntry, 0, sizeof(reEntry));
			if (updateTs)
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%ld",
						rMac, mac2g, mac5g, ts);
			else
				snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%s",
						rMac, mac2g, mac5g, timestamp);

			strncat(reList, reEntry, strlen(reEntry));
		}
		free(nv);

		nvram_set("cfg_relist", reList);
	}
	pthread_mutex_unlock(&reListLock);
} /* End of cm_updateReListTimestamp */

/*
========================================================================
Routine Description:
	Check slave is online or not.

Arguments:
	None

Return Value:
	0		- offline
	1		- online

========================================================================
*/
int cm_isSlaveOnline(time_t startTime)
{
	return ((int) difftime(time(NULL), startTime) < OFFLINE_THRESHOLD) ? 1 : 0;
} /* End of cm_isReOnline */

/*
========================================================================
Routine Description:
	Update tri-band RE list.

Arguments:
	newReMac		- mac for new RE
	bandNum		- RE supported band number
	modelName		- model name
	action			- add/del
	commit		- commit nvram

Return Value:
	None

========================================================================
*/
void cm_updateTribandReList(const char *newReMac, int bandNum, char *modelName, int action, int commit)
{
	char *tribandModelList[] = {"RT-AC5300", "GT-AC5300", "RT-AX92U", "GT-AX11000", "GT-AXE11000", "GT-AX11000_PRO"
					"MAP-AC2200", "RT-AC95U", "MAP-AC2200V", "ET12", "XT12", "GT-AXE16000"};
	int i, ret = 0, isTribandRe = 0, update = 0;
	char *nv, *nvp, *b;
	char reEntry[64] = {0};
	char reList[1024] = {0};

	if (bandNum == 3) {
		DBG_INFO("band number (%d) matched, it's tri-band RE", bandNum);
		isTribandRe = 1;
	}

	if (ret == 0 && modelName) {
		for (i = 0; i < ARRAY_SIZE(tribandModelList); i++) {
			if (strcasecmp(modelName, tribandModelList[i]) == 0) {
				DBG_INFO("model name (%s) matched, it's tri-band RE", modelName);
				isTribandRe = 1;
				break;
			}
		}
	}

	/* update tri-band RE list */
	if (isTribandRe && action == RELIST_ADD && !strstr(nvram_safe_get("cfg_tbrelist"), newReMac)) {
		snprintf(reList, sizeof(reList), "%s<%s", nvram_safe_get("cfg_tbrelist"), newReMac);
		update = 1;
	}
	else if (action == RELIST_DEL && strstr(nvram_safe_get("cfg_tbrelist"), newReMac))
	{
		nv = nvp = strdup(nvram_safe_get("cfg_tbrelist"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (strlen(b) == 0)
					continue;

				if (strcasecmp(newReMac, b) == 0) {
					update = 1;
					continue;
				}

				memset(reEntry, 0, sizeof(reEntry));
				snprintf(reEntry, sizeof(reEntry), "<%s", b);
				strncat(reList, reEntry, strlen(reEntry));
			}
			free(nv);
		}
	}

	if (update) {
		nvram_set("cfg_tbrelist", reList);
		if (commit)
			nvram_commit();
	}
} /* End of cm_updateTribandReList */

#ifdef RTCONFIG_BHCOST_OPT
/*
========================================================================
Routine Description:
	Update RE entry to RE list array.

Arguments:
	reArray		- re list array
	mac		- mac need to be added

Return Value:
	none

========================================================================
*/
void cm_addReEntryToList(json_object *reArray, char *mac)
{
	int i = 0, reArrayLen = 0, foundEntry = 0;
	json_object *reEntry = NULL;

	reArrayLen = json_object_array_length(reArray);
	for (i = 0; i < reArrayLen; i++) {
		reEntry = json_object_array_get_idx(reArray, i);
		if (strcmp((char *)json_object_get_string(reEntry), mac) == 0) {
			foundEntry = 1;
			break;
		}
	}

	if (!foundEntry)
		json_object_array_add(reArray, json_object_new_string(mac));
}

/*
========================================================================
Routine Description:
	Update RE list array.

Arguments:
	root		- root json object for check
	reArray		- re list array
	mac		- mac need to be checked
	from		- from wireless/wired onnection info

Return Value:
	0		- mac doesn't be added
	1		- mac be added

========================================================================
*/
int cm_updateReListArray(json_object *root, json_object *reArray, char *mac, int from)
{
	json_object *brMacObj = NULL, *staObj = NULL;
	int ret = 0;
	char brMac[18];

	if (root == NULL) {
		DBG_ERR("root is NULL");
		return 0;
	}

	json_object_object_foreach(root, key, val) {
		brMacObj = val;
		memset(brMac, 0, sizeof(brMac));
		snprintf(brMac, sizeof(brMac), "%s", key);

		if (from == 0) {		/* from wireless connection info */
			/* check by band */
			json_object_object_foreach(brMacObj, key, val) {
				json_object_object_get_ex(val, mac, &staObj);
				if (staObj) {
					cm_addReEntryToList(reArray, brMac);
					ret = 1;
					break;
				}
			}
		}
		else if (from == 1)		/* from wired connection info */
		{
			json_object_object_get_ex(brMacObj, mac, &staObj);
			if (staObj) {
				cm_addReEntryToList(reArray, brMac);
				ret = 1;
				break;
			}
		}
	}

	return ret;
}/* End of cm_updateReListArray */

/*
========================================================================
Routine Description:
	Prepare message for RE list.

Arguments:
	clientTbl		- client table
	reMac		- Notified RE's mac

Return Value:
	re list array

========================================================================
*/
json_object *cm_recordReListArray(CM_CLIENT_TABLE *clientTbl, char *reMac)
{
	int lock, i = 0, j = 0, k = 0, reArrayLen = 0, foundRE = 0, foundEntry = 0, rePath = 0;
	json_object *wiredRoot = NULL;
	json_object *reArray = NULL, *reEntry = NULL;
	char mac[18];
	unsigned char pap2g[MAC_LEN], pap5g[MAC_LEN], ea[MAC_LEN], pap6g[MAC_LEN];
	int wirelessPath = WL_2G | WL_5G | WL_5G_1 | WL_6G;
	int wirelessPathNew = WL2G_U | WL5G1_U | WL5G2_U | WL6G_U;
	int wiredPath = ETH | ETH_2 | ETH_3 | ETH_4;
	int bandsupport = 0;
	unsigned char nullMAC[MAC_LEN] = {0};

	/* create new object for reArray */
	if (!(reArray = json_object_new_array())) {
		DBG_ERR("reArray is NULL");
		return NULL;
	}

	/* find new RE related info */
	DBG_INFO("find new RE related info");
	ether_atoe(reMac, ea);
	for (i = 1; i < clientTbl->count; i++) {
		if (memcmp(clientTbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			memcpy(pap2g, clientTbl->pap2g[i], MAC_LEN);
			memcpy(pap5g, clientTbl->pap5g[i], MAC_LEN);
			memcpy(pap6g, clientTbl->pap6g[i], MAC_LEN);
			rePath = clientTbl->activePath[i];
			bandsupport = cm_getBandTypeSupport();
			foundRE = 1;
			DBG_INFO("found new RE (%02X:%02X:%02X:%02X:%02X:%02X), "
				"pap 2g (%02X:%02X:%02X:%02X:%02X:%02X), "
				"pap 5g (%02X:%02X:%02X:%02X:%02X:%02X), "
				"pap 6g (%02X:%02X:%02X:%02X:%02X:%02X), re path (%d), bandsupport (%d)",
				clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
				clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
				clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5],
				pap2g[0], pap2g[1], pap2g[2], pap2g[3], pap2g[4], pap2g[5],
				pap5g[0], pap5g[1], pap5g[2], pap5g[3], pap5g[4], pap5g[5],
				pap6g[0], pap6g[1], pap6g[2], pap6g[3], pap6g[4], pap6g[5],
				rePath, bandsupport);
			break;
		}
	}

	/* get the RE's mac of upper level based on new RE related info */
	if (foundRE) {
		/* get all wired connection info */
		pthread_mutex_lock(&wiredClientListLock);
		lock = file_lock(WIREDCLIENTLIST_FILE_LOCK);
		wiredRoot = json_object_from_file(WIRED_CLIENT_LIST_JSON_PATH);
		file_unlock(lock);
		pthread_mutex_unlock(&wiredClientListLock);

		/* for wireless */
		DBG_INFO("rePath & wirelessPathNew (%X), rePath & wirelessPath(%X)",
			(rePath & wirelessPathNew), (rePath & wirelessPath));
		if ((rePath & wirelessPathNew) || (rePath & wirelessPath))
		{
			DBG_INFO("check for wireless");
			for (i = 0; i < clientTbl->count; i++) {
				foundEntry = 0;
				if (((bandsupport & WL_2G) && (memcmp(pap2g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap2g[i], pap2g, MAC_LEN) == 0) ||
					((bandsupport & (WL_5G | WL_5G_1)) && (memcmp(pap5g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap5g[i], pap5g, MAC_LEN) == 0) ||
					((bandsupport & (WL_5G | WL_5G_1)) && (memcmp(pap5g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap5g1[i], pap5g, MAC_LEN) == 0) ||
					((bandsupport & (WL_5G | WL_5G_1)) && (memcmp(pap5g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->apDwb[i], pap5g, MAC_LEN) == 0) ||
					((bandsupport & WL_6G) && (memcmp(pap6g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap6g[i], pap6g, MAC_LEN) == 0) ||
					((bandsupport & WL_6G) && (memcmp(pap6g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->apDwb[i], pap6g, MAC_LEN) == 0))
				{
					foundEntry = 1;
					memset(mac, 0, sizeof(mac));
					snprintf(mac, sizeof(mac),  "%02X:%02X:%02X:%02X:%02X:%02X",
						clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
						clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
						clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5]);
					DBG_INFO("found RE (%s)", mac);
				}

				if (foundEntry)
					cm_addReEntryToList(reArray, mac);
			}
		}
		DBG_INFO("rePath & wiredPath(%X)", (rePath & wiredPath));
		/* for wired */
		if (rePath & wiredPath)
		{
			DBG_INFO("check for wired");
			/* check and record the notified RE's wired connection */
			for (i = 0; i < clientTbl->count; i++) {
				memset(mac, 0, sizeof(mac));
				snprintf(mac, sizeof(mac),  "%02X:%02X:%02X:%02X:%02X:%02X",
					clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
					clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
					clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5]);
				if (cm_updateReListArray(wiredRoot, reArray, mac, 1))
					break;
			}
		}

		for (i = clientTbl->maxLevel; i >= 0; i--) {
			/* check and record the notified RE's wireless connection */
			reArrayLen = json_object_array_length(reArray);
			for (j = 0; j < reArrayLen; j++) {
				reEntry = json_object_array_get_idx(reArray, j);
				ether_atoe((char *)json_object_get_string(reEntry), ea);
				foundRE = 0;
				for (k = 1; k < clientTbl->count; k++) {
					if (memcmp(clientTbl->realMacAddr[k], ea, MAC_LEN) == 0) {
						memcpy(pap2g, clientTbl->pap2g[k], MAC_LEN);
						memcpy(pap5g, clientTbl->pap5g[k], MAC_LEN);
						memcpy(pap6g, clientTbl->pap6g[k], MAC_LEN);
						rePath = clientTbl->activePath[k];
						foundRE = 1;
						break;
					}
				}

				if (foundRE) {
					/* for wireless */
					if ((rePath & wirelessPathNew) || (rePath & wirelessPath))
					{
						for (k = 0; k < clientTbl->count; k++) {
							foundEntry = 0;
							if (((bandsupport & WL_2G) && (memcmp(pap2g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap2g[k], pap2g, MAC_LEN) == 0) ||
								((bandsupport & (WL_5G | WL_5G_1)) && (memcmp(pap5g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap5g[k], pap5g, MAC_LEN) == 0) ||
								((bandsupport & (WL_5G | WL_5G_1)) && (memcmp(pap5g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap5g1[k], pap5g, MAC_LEN) == 0) ||
								((bandsupport & (WL_5G | WL_5G_1)) && (memcmp(pap5g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->apDwb[k], pap5g, MAC_LEN) == 0) ||
								((bandsupport & WL_6G) && (memcmp(pap6g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->ap6g[k], pap6g, MAC_LEN) == 0) ||
								((bandsupport & WL_6G) && (memcmp(pap6g, nullMAC, sizeof(nullMAC))) && memcmp(clientTbl->apDwb[k], pap6g, MAC_LEN) == 0))
							{
								foundEntry = 1;
								memset(mac, 0, sizeof(mac));
								snprintf(mac, sizeof(mac),  "%02X:%02X:%02X:%02X:%02X:%02X",
									clientTbl->realMacAddr[k][0], clientTbl->realMacAddr[k][1],
									clientTbl->realMacAddr[k][2], clientTbl->realMacAddr[k][3],
									clientTbl->realMacAddr[k][4], clientTbl->realMacAddr[k][5]);
								DBG_INFO("found notified RE (%s)", mac);
							}

							if (foundEntry)
								cm_addReEntryToList(reArray, mac);
						}
					}

					/* for wired */
					if (rePath & wiredPath)
					{
						/* check and record the notified RE's wired connection */
						for (k = 0; k < clientTbl->count; k++) {
							memset(mac, 0, sizeof(mac));
							snprintf(mac, sizeof(mac),  "%02X:%02X:%02X:%02X:%02X:%02X",
								clientTbl->realMacAddr[k][0], clientTbl->realMacAddr[k][1],
								clientTbl->realMacAddr[k][2], clientTbl->realMacAddr[k][3],
								clientTbl->realMacAddr[k][4], clientTbl->realMacAddr[k][5]);
							if (cm_updateReListArray(wiredRoot, reArray, mac, 1))
								break;
						}
					}
				}
			}
		}

		json_object_put(wiredRoot);

		reArrayLen = json_object_array_length(reArray);
		DBG_INFO("the count of re list array (%d)", reArrayLen);
		for (i = 0; i < reArrayLen; i++) {
			reEntry = json_object_array_get_idx(reArray, i);
			DBG_INFO("RE %d: %s", i, (char *)json_object_get_string(reEntry));
		}
	}

	return reArray;
} /* End of cm_recordReListArray */
#endif /* RTCONFIG_BHCOST_OPT */

/*
========================================================================
Routine Description:
	Get re unique mac by ip.

Arguments:
	clientTbl		- client table
	reIp			- RE's ip
	reMac		- RE's mac
	macLen		- the max length of re mac

Return Value:
	length of re mac

========================================================================
*/
int cm_getReMacByIp(CM_CLIENT_TABLE *clientTbl, char *reIp, char *reMac, int macLen)
{
	char ip[18] = {0};
	int i = 0;

	memset(reMac, 0, macLen);
	for (i = 1; i < clientTbl->count; i++) {
		memset(ip, 0, sizeof(ip));
		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", clientTbl->ipAddr[i][0],
			clientTbl->ipAddr[i][1], clientTbl->ipAddr[i][2],
			clientTbl->ipAddr[i][3]);

		if (strcmp(reIp, ip) == 0) {
			snprintf(reMac, macLen, "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
				clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
				clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5]);
			break;
		}
	}

	return strlen(reMac);
} /* End of cm_getReMacByIp */

/*
========================================================================
Routine Description:
	Get re traffic mac by ip.

Arguments:
	clientTbl		- client table
	reIp			- RE's ip
	reMac		- RE's mac
	macLen		- the max length of re mac

Return Value:
	length of re mac

========================================================================
*/
int cm_getReTrafficMacByIp(CM_CLIENT_TABLE *clientTbl, char *reIp, char *reMac, int macLen)
{
	char ip[18] = {0};
	int i = 0;

	memset(reMac, 0, macLen);
	for (i = 1; i < clientTbl->count; i++) {
		memset(ip, 0, sizeof(ip));
		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", clientTbl->ipAddr[i][0],
			clientTbl->ipAddr[i][1], clientTbl->ipAddr[i][2],
			clientTbl->ipAddr[i][3]);

		if (strcmp(reIp, ip) == 0) {
			snprintf(reMac, macLen, "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->macAddr[i][0], clientTbl->macAddr[i][1],
				clientTbl->macAddr[i][2], clientTbl->macAddr[i][3],
				clientTbl->macAddr[i][4], clientTbl->macAddr[i][5]);
			break;
		}
	}

	return strlen(reMac);
} /* End of cm_getReTrafficMacByIp */

/*
========================================================================
Routine Description:
	Get re ip by re mac.

Arguments:
	clientTbl		- client table
	reMac		- RE's mac
	reIp		- RE's ip
	ipLen		- the max length of re mac

Return Value:
	length of re mac

========================================================================
*/
int cm_getReIpByReMac(CM_CLIENT_TABLE *clientTbl, char *reMac, char *reIp, int ipLen)
{
	char mac[18] = {0};
	int i = 0;

	memset(reIp, 0, ipLen);
	for (i = 1; i < clientTbl->count; i++) {
		memset(mac, 0, sizeof(mac));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
				clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
				clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5]);

		if (strcmp(reMac, mac) == 0) {
			snprintf(reIp, ipLen, "%d.%d.%d.%d", clientTbl->ipAddr[i][0],
				clientTbl->ipAddr[i][1], clientTbl->ipAddr[i][2],
				clientTbl->ipAddr[i][3]);
			break;
		}
	}

	return strlen(reIp);
} /* End of cm_getReIpByReMac */

/*
========================================================================
Routine Description:
	Get re traffic mac by re mac.

Arguments:
	clientTbl		- client table
	reMac		- RE's mac
	reTrafficMac		- RE's traffic mac
	macLen		- the max length of re traffic mac

Return Value:
	length of re mac

========================================================================
*/
int cm_getReTrafficMacByReMac(CM_CLIENT_TABLE *clientTbl, char *reMac, char *reTrafficMac, int macLen)
{
	char mac[18] = {0};
	int i = 0;

	memset(reTrafficMac, 0, macLen);
	for (i = 1; i < clientTbl->count; i++) {
		memset(mac, 0, sizeof(mac));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
				clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
				clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5]);

		if (strcmp(reMac, mac) == 0) {
			snprintf(reTrafficMac, macLen, "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->macAddr[i][0], clientTbl->macAddr[i][1],
				clientTbl->macAddr[i][2], clientTbl->macAddr[i][3],
				clientTbl->macAddr[i][4], clientTbl->macAddr[i][5]);
			break;
		}
	}

	return strlen(reTrafficMac);
} /* End of cm_getReTrafficMacByReMac */

/*
========================================================================
Routine Description:
	Get re unique mac by mac.

Arguments:
	clientTbl		- client table
	mac2g		- RE's 2g mac
	reMac		- RE's mac
	macLen		- the max length of re mac

Return Value:
	length of re mac

========================================================================
*/
int cm_getReMacBy2gMac(CM_CLIENT_TABLE *clientTbl, char *mac2g, char *reMac, int macLen)
{
	char mac[18] = {0};
	int i = 0;

	memset(reMac, 0, macLen);
	for (i = 1; i < clientTbl->count; i++) {
		memset(mac, 0, sizeof(mac));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->ap2g[i][0], clientTbl->ap2g[i][1],
				clientTbl->ap2g[i][2], clientTbl->ap2g[i][3],
				clientTbl->ap2g[i][4], clientTbl->ap2g[i][5]);

		if (strcmp(mac2g, mac) == 0) {
			snprintf(reMac, macLen, "%02X:%02X:%02X:%02X:%02X:%02X",
				clientTbl->realMacAddr[i][0], clientTbl->realMacAddr[i][1],
				clientTbl->realMacAddr[i][2], clientTbl->realMacAddr[i][3],
				clientTbl->realMacAddr[i][4], clientTbl->realMacAddr[i][5]);
			break;
		}
	}

	return strlen(reMac);
} /* End of cm_getReMacBy2gMac */

#ifdef ONBOARDING_VIA_VIF
/*
========================================================================
Routine Description:
	Check whether need to update RE list via vif.

Arguments:
	newReMac		- mac for new RE

Return Value:
	0			- no need to update the information of re list
	1			- need to update the information of re list

========================================================================
*/
int cm_checkObVifReListUpdate(char *newReMac)
{
	char *nv, *nvp, *b;
	char *newReMacTmp, *obReMacTmp;
	int exist = 0, ret = 0;

	DBG_INFO("newReMac (%s)", newReMac);

	nv = nvp = strdup(nvram_safe_get("cfg_obvif_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &newReMacTmp, &obReMacTmp) != 2))
				continue;

			if (strcmp(newReMac, newReMacTmp) == 0) {
				exist = 1;
				break;
			}
		}
		free(nv);
	}

	if (exist == 0)
		ret = 1;

	return ret;
} /* End of cm_checkObVifReListUpdate */

/*
========================================================================
Routine Description:
	Get mac for onboarding new RE.

Arguments:
	newReMac		- mac for new RE
	obReMac			- mac for onboarding new RE
	macLen		- the max length of mac

Return Value:
	the lenght of re mac

========================================================================
*/
int cm_getObVifReByNewReMac(char *newReMac, char *obReMac, int macLen)
{
	char *nv, *nvp, *b;
	char *newReMacTmp, *obReMacTmp;

	memset(obReMac, 0, macLen);
	nv = nvp = strdup(nvram_safe_get("cfg_obvif_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &newReMacTmp, &obReMacTmp) != 2))
				continue;

			if (strcmp(newReMac, newReMacTmp) == 0) {
				snprintf(obReMac, macLen, "%s", obReMacTmp);
				break;
			}
		}
		free(nv);
	}

	return strlen(obReMac);
} /* End of cm_getObVifReByNewReMac */

/*
========================================================================
Routine Description:
	Update RE list via vif.

Arguments:
	newReMac		- mac for new RE
	obReMac			- mac for onboarding new RE
	action			- add/del

Return Value:
	None

========================================================================
*/
void cm_updateObVifReList(char *newReMac, char *obReMac, int action)
{
	int update = 0;
	char *nv, *nvp, *b;
	char *newReMacTmp, *obReMacTmp;
	char reEntry[64] = {0};
	char reList[1024] = {0};

	/* update RE list */
	if (action == RELIST_ADD && !strstr(nvram_safe_get("cfg_obvif_relist"), newReMac)) {
		snprintf(reList, sizeof(reList), "%s<%s>%s", nvram_safe_get("cfg_obvif_relist"), newReMac, obReMac);
		update = 1;
	}
	else if (action == RELIST_DEL && strstr(nvram_safe_get("cfg_obvif_relist"), newReMac))
	{
		nv = nvp = strdup(nvram_safe_get("cfg_obvif_relist"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &newReMacTmp, &obReMacTmp) != 2))
					continue;

				if (strcmp(newReMac, newReMacTmp) == 0) {
					update = 1;
					continue;
				}

				memset(reEntry, 0, sizeof(reEntry));
				snprintf(reEntry, sizeof(reEntry), "<%s>%s", newReMacTmp, obReMacTmp);
				strncat(reList, reEntry, strlen(reEntry));
			}
			free(nv);
		}
	}

	if (update) {
		nvram_set("cfg_obvif_relist", reList);
		nvram_commit();
	}
} /* End of cm_updateObVifReList */
#endif

/*
========================================================================
Routine Description:
	Set RE offline.

Arguments:
	startTime		- RE's timestamp for reporting

Return Value:
	None

========================================================================
*/
void cm_setReOffline(time_t *startTime)
{
	*startTime -= OFFLINE_THRESHOLD;
} /* End of cm_setReOffline */

/*
========================================================================
Routine Description:
	Reorganize re list.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_reorganizeReList()
{
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	int count = 0;
	char reEntry[128] = {0};
	char reList[RE_LIST_MAX_LEN] = {0};

	pthread_mutex_lock(&reListLock);

	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if (strlen(b) == 0)
				continue;

			if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4))
				continue;

			if (strlen(reMac) == 0) {
				DBG_LOG("the length of reMac is 0");
				continue;
			}

			if (!isValidMacAddress(reMac)) {
				DBG_LOG("reMac (%s) is invalid", reMac);
				continue;
			}

			memset(reEntry, 0, sizeof(reEntry));
			snprintf(reEntry, sizeof(reEntry), "<%s>%s>%s>%s",
				reMac, mac2g, mac5g, timestamp);
			strncat(reList, reEntry, strlen(reEntry));
			count++;
		}
		free(nv);

		if (nvram_get_int("cfg_recount") != count || strcmp(nvram_safe_get("cfg_relist"), reList) != 0) {
			DBG_LOG("update re list due count or list updated");
			nvram_set("cfg_relist", reList);
			nvram_set_int("cfg_recount", count);
			nvram_commit();
		}
	}

	pthread_mutex_unlock(&reListLock);
} /* End of cm_reorganizeReList */

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
/*
========================================================================
Routine Description:
	Update RE onboarding list.

Arguments:
	reMac		- mac for RE
	action		- add/del
	commit		- commit nvram

Return Value:
	None

========================================================================
*/
void cm_updateReObList(char *reMac, int action, int commit)
{
	int update = 0;
	char *nv, *nvp, *b, reEntry[64] = {0}, reList[1024] = {0};


	if (reMac == NULL) {
		DBG_LOG("reMac is null");
		return;
	}

	if (strlen(reMac) == 0) {
		DBG_LOG("the length of reMac is 0");
		return;
	}

	if (!isValidMacAddress(reMac)) {
		DBG_LOG("reMac (%s) is invalid", reMac);
		return;
	}

	pthread_mutex_lock(&reListLock);

	/* update RE list */
	if (action == RELIST_ADD && !strstr(nvram_safe_get("cfg_reoblist"), reMac)) {
		snprintf(reList, sizeof(reList), "%s<%s", nvram_safe_get("cfg_reoblist"), reMac);
		update = 1;
	}
	else if (action == RELIST_DEL && strstr(nvram_safe_get("cfg_reoblist"), reMac))
	{
		nv = nvp = strdup(nvram_safe_get("cfg_reoblist"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (strlen(b) == 0)
					continue;

				if (strcmp(reMac, b) == 0) {
					update = 1;
					continue;
				}

				memset(reEntry, 0, sizeof(reEntry));
				snprintf(reEntry, sizeof(reEntry), "<%s", b);
				strncat(reList, reEntry, strlen(reEntry));
			}
			free(nv);
		}
	}

	if (update) {
		nvram_set("cfg_reoblist", reList);
		if (commit)
			nvram_commit();
	}

	pthread_mutex_unlock(&reListLock);
} /* End of cm_updateReObList */
#endif /* RTCONFIG_AMAS_CENTRAL_CONTROL */
