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
#include "cfg_wevent.h"
#include "cfg_event.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#ifdef DUAL_BAND_DETECTION
#include "cfg_dualbandlist.h"
#endif
#include "cfg_string.h"
#ifdef RTCONFIG_NOTIFICATION_CENTER
#include "cfg_eventnotify.h"
#endif
#include "cfg_slavelist.h"

/*
========================================================================
Routine Description:
	Prepare sta list message.

Arguments:
	msg		- output message arrary
	msgLen		- the length of output message array

Return Value:
	message length

========================================================================
*/
int cm_prepareStaListMsg(char *msg, int msgLen)
{
	if (!wl_sta_list(msg, msgLen))
		return 0;

	DBG_INFO("msg(%s)", msg);
	
	return strlen(msg);
} /* End of cm_prepareStaListMsg */

/*
========================================================================
Routine Description:
	Prepare wireless event message.

Arguments:
	msg		- output message array
	msgLen		- the length of output message array

Return Value:
	message length

========================================================================
*/
int cm_prepareWeventMsg(char *msg, int msgLen)
{
	json_object *fileRoot = NULL;
#ifdef DUAL_BAND_DETECTION
	json_object *brMacObj = NULL, *bandObj = NULL, *staObj = NULL, *eventObj = NULL;
	char staMac[18] = {0};
#endif

	/* check WCLIENT_LIST_JSON_PATH exist or not */
	if (fileExists(WCLIENT_LIST_JSON_PATH) == 0)
		return 0;

	if ((fileRoot = json_object_from_file(WCLIENT_LIST_JSON_PATH)) != NULL) {
#ifdef DUAL_BAND_DETECTION
		/* set dual band capability for sta */
		json_object_object_foreach(fileRoot, key, val) {
			brMacObj = val;
			json_object_object_foreach(brMacObj, key, val) {
				bandObj = val;
				json_object_object_foreach(bandObj, key, val) {
					memset(staMac, 0, sizeof(staMac));
					snprintf(staMac, sizeof(staMac), "%s", key);
					staObj = val;

					json_object_object_get_ex(staObj, WEVENT_EVENT, &eventObj);
					if (eventObj && json_object_get_int(eventObj) == EID_WEVENT_DEVICE_CONNECTED) {
						/* check and add dual band capability */
						if (cm_checkDualBandCapability(staMac))
							json_object_object_add(staObj, CFG_STR_DUAL_BAND_CAP,
								json_object_new_int(1));
					}
				}
			}
		}
#endif
		snprintf(msg, msgLen, "%s", json_object_to_json_string(fileRoot));
		DBG_INFO("msg(%s)", msg);
		json_object_put(fileRoot);
	}

	return strlen(msg);
} /* End of cm_prepareWeventMsg */

/*
========================================================================
Routine Description:
	Process wireless event (common).

Arguments:
	*fileRoot	- json object from file
	*brMac		- the mac of bridge
	*band		- band info
	*staMac		- the mac of sta
	ts		- timestamp

Return Value:
	None

Note:
========================================================================
*/
void cm_processStaListCommon(json_object *fileRoot, char *brMac, char *band,
	char *staMac, time_t ts)
{
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int needAdd = 1;

	if (!brMac || !band || !staMac)
		DBG_ERR("invalid parameters");

 	DBG_INFO("brMac(%s), band(%s), staMac(%s), ts(%ld)",
			brMac, band, staMac, ts);

	if (fileRoot != NULL) {
		json_object_object_foreach(fileRoot, key, val) {
			brMacObj = val;
			json_object_object_foreach(brMacObj, key, val) {
				bandObj = val;
				/* process band */
				json_object_object_get_ex(bandObj, staMac, &staObj);
				if (staObj)
					json_object_object_del(bandObj, staMac);
			}
		}

		/* add sta */
		if (needAdd) {
			json_object_object_get_ex(fileRoot, brMac, &brMacObj);	

			if (!brMacObj) {
				DBG_INFO("brMacObj is NULL!");
				brMacObj = json_object_new_object();
				if (brMacObj)
					json_object_object_add(fileRoot, brMac, brMacObj);
				else
					DBG_ERR("brMacObj is NULL!");
			}

			if (brMacObj) {
				json_object_object_get_ex(brMacObj, band, &bandObj);

				if (!bandObj) {
					DBG_INFO("bandObj is NULL!");
					bandObj = json_object_new_object();
					if (bandObj)
						json_object_object_add(brMacObj, band, bandObj);
					else
						DBG_ERR("bandObj is NULL!");
				}
			
				if (bandObj) {
					staObj = json_object_new_object();
					if (staObj) {
						json_object_object_add(staObj, WEVENT_TIMESTAMP,
							json_object_new_int64(ts));
						json_object_object_add(bandObj, staMac, staObj);
					}
					else
						DBG_INFO("staObj is NULL!");
				}
			}	
			
		}
	}
	else
	{
		fileRoot = json_object_new_object();
		brMacObj = json_object_new_object();
		bandObj = json_object_new_object();
		staObj = json_object_new_object();

		if (fileRoot && brMacObj && bandObj && staObj) {
			json_object_object_add(staObj, WEVENT_TIMESTAMP,
				json_object_new_int64(ts));
			
			json_object_object_add(bandObj, staMac, staObj);
			json_object_object_add(brMacObj, band, bandObj);
			json_object_object_add(fileRoot, brMac, brMacObj);
		}
		else
		{
			json_object_put(fileRoot);
			json_object_put(brMacObj);
			json_object_put(bandObj);
			json_object_put(staObj);
			DBG_INFO("can't create obj for sta");
		}
	}
} /* End of cm_prepareStaListCommon */

/*
========================================================================
Routine Description:
	Process wireless event (common).

Arguments:
	*fileRoot	- json object from file
	*brMac		- the mac of bridge
	*band		- band info
	*staMac		- the mac of sta
	event		- event type
	ts		- timestamp

Return Value:
	0		- no update
	1		- update

Note:
========================================================================
*/
int cm_processWeventCommon(json_object *fileRoot, char *brMac, char *band,
	char *staMac, int event, long ts)
{
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	json_object *tsObj = NULL;
	int needAdd = 1;
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	char exapmac[18]={0};
	char exapip[18]={0};
#endif
	int update = 0;

	if (!brMac || !band || !staMac) {
		DBG_ERR("invalid parameters");
		return 0;
	}

 	DBG_INFO("brMac(%s), band(%s), staMac(%s), event(%d), ts(%ld)",
			brMac, band, staMac, event, ts);

	if (fileRoot != NULL) {
		json_object_object_foreach(fileRoot, key, val) {
			if (strcmp(brMac, key))
				continue;
			brMacObj = val;
			json_object_object_foreach(brMacObj, key, val) {
				bandObj = val;
				/* process band */
				json_object_object_get_ex(bandObj, staMac, &staObj);
				if (staObj) {
					json_object_object_get_ex(staObj, WEVENT_TIMESTAMP, &tsObj);
					if (tsObj) {
						if (ts > json_object_get_int(tsObj)) {
							json_object_object_del(bandObj, staMac);
							update = 1;
						}
						else
							needAdd = 0;
					}
				}
			}
		}

		/* add sta */
		if (needAdd) {
			if (event == EID_WEVENT_DEVICE_CONNECTED) {
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
				json_object_object_foreach(fileRoot, key, val) {
					if (strcmp(brMac, key))
					{
						memset(exapmac,0,18);
						memcpy(exapmac,key,sizeof(exapmac)-1);

						brMacObj = val;
						json_object_object_foreach(brMacObj, key, val) {
							bandObj = val;
							/* process band */
							json_object_object_get_ex(bandObj, staMac, &staObj);
							if (staObj) {
								//send connect msg to this AP
								cm_mac2ip(exapmac,exapip,sizeof(exapip));
								DBG_ERR("sent connect event to exapip %s exapmac %s\n",exapip,exapmac);
								cm_sendConnEventToExAp(staMac,exapmac,exapip,brMac);
								break;
							}
						}			
					}
				}
#endif	//end of #ifdef RTCONFIG_CONN_EVENT_TO_EX_AP	
				json_object_object_get_ex(fileRoot, brMac, &brMacObj);	

				if (!brMacObj) {
					DBG_INFO("brMacObj is NULL!");
					brMacObj = json_object_new_object();
					if (brMacObj) {
						json_object_object_add(fileRoot, brMac, brMacObj);
						update = 1;
					}
					else
						DBG_ERR("brMacObj is NULL!");
				}

				if (brMacObj) {
					json_object_object_get_ex(brMacObj, band, &bandObj);

					if (!bandObj) {
						DBG_INFO("bandObj is NULL!");
						bandObj = json_object_new_object();
						if (bandObj) {
							json_object_object_add(brMacObj, band, bandObj);
							update = 1;
						}
						else
							DBG_ERR("bandObj is NULL!");
					}
			
					if (bandObj) {
						staObj = json_object_new_object();
						if (staObj) {
							json_object_object_add(staObj, WEVENT_TIMESTAMP,
								json_object_new_int64(ts));
							json_object_object_add(bandObj, staMac, staObj);
							update = 1;
						}
						else
							DBG_INFO("staObj is NULL!");
					}
				}
			}
			else
				DBG_INFO("Don't need to add sta entry");
		}
	}
	else
	{
		if (event == EID_WEVENT_DEVICE_CONNECTED) {
			fileRoot = json_object_new_object();
			brMacObj = json_object_new_object();
			bandObj = json_object_new_object();
			staObj = json_object_new_object();

			if (fileRoot && brMacObj && bandObj && staObj) {
				json_object_object_add(staObj, WEVENT_TIMESTAMP,
					json_object_new_int64(ts));
			
				json_object_object_add(bandObj, staMac, staObj);
				json_object_object_add(brMacObj, band, bandObj);
				json_object_object_add(fileRoot, brMac, brMacObj);
				update = 1;
			}
			else
			{
				json_object_put(fileRoot);
				json_object_put(brMacObj);
				json_object_put(bandObj);
				json_object_put(staObj);
				DBG_INFO("can't create obj for wireless client");
			}
		}
	}

	return update;
} /* End of cm_processWeventCommon */

/*========================================================================
Routine Description:
	Process sta list.

Arguments:
	*e	- wireless event

Return Value:
	None

Note:
========================================================================
*/
void cm_processStaList(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	int lock;
	char staMac[32] = {0};
	char band[16] = {0};
	char brMac[32] = {0};
	json_object *fileRoot = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	json_object *tsObj = NULL;
	
	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("msg(%s)", msg);


	pthread_mutex_lock(&allWeventLock);
	lock = file_lock(ALLWEVENT_FILE_LOCK);

	fileRoot = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);
	if (!fileRoot)
		fileRoot = json_object_new_object();

	/* update & filter wireless client on differnt DUT */
	json_object_object_foreach(root, key, val) {
		memset(brMac, 0, sizeof(brMac));
		snprintf(brMac, sizeof(brMac), "%s", key);
		brMacObj = val;

		DBG_INFO("delete old wireless client list for %s", brMac);
		json_object_object_del(fileRoot, brMac);

		/* update new wirless client list */
		json_object_object_foreach(brMacObj, key, val) {
			memset(band, 0, sizeof(band));
			snprintf(band, sizeof(band), "%s", key);
			bandObj = val;
			json_object_object_foreach(bandObj, key, val) {
				memset(staMac, 0, sizeof(staMac));
				snprintf(staMac, sizeof(staMac), "%s", key);
#ifdef ONBOARDING
				if (nvram_get_int("cfg_obstatus") == OB_TYPE_LOCKED) {
					if (strcmp(staMac, nvram_safe_get("cfg_newre")) == 0) {
						DBG_INFO("sta (%s) is new RE, pass it", staMac);
						continue;
					}
				}
#endif

				staObj = val;

				json_object_object_get_ex(staObj, WEVENT_TIMESTAMP, &tsObj);
				if (tsObj) {
					long ts = json_object_get_int64(tsObj);
					DBG_INFO("brMac(%s), band(%s), sta(%s), ts(%ld)",
						brMac, band, staMac, ts);
					cm_processStaListCommon(fileRoot, brMac, band,
						staMac, ts);
				}				
			}
		}
	}

	/* write to file */
	if (fileRoot)
		json_object_to_file(ALLWCLIENT_LIST_JSON_PATH, fileRoot);
	json_object_put(fileRoot);
	json_object_put(root);
	file_unlock(lock);
	pthread_mutex_unlock(&allWeventLock);
} /* End of cm_processStaList */

/*
========================================================================
Routine Description:
	Revmoe wireless client list by mac.

Arguments:
	mac		- mac

Return Value:
	None

Note:
========================================================================
*/
void cm_removeWirelessClientListByMac(char *mac)
{
	json_object *fileRoot = NULL;
	int lock = 0;

	pthread_mutex_lock(&allWeventLock);
	lock = file_lock(ALLWEVENT_FILE_LOCK);

	fileRoot = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		file_unlock(lock);
		pthread_mutex_unlock(&allWeventLock);
		return;
	}

	/* remove wired client list by mac */
	DBG_INFO("remove wired client list by %s", mac);
	json_object_object_del(fileRoot, mac);

	/* write to file */
	if (fileRoot)
		json_object_to_file(ALLWCLIENT_LIST_JSON_PATH, fileRoot);

	json_object_put(fileRoot);

	file_unlock(lock);
	pthread_mutex_unlock(&allWeventLock);
} /* End of cm_removeWirelessClientListByMac */

/*
========================================================================
Routine Description:
	Process wireless event.

Arguments:
	msg		- decrypted message

Return Value:
	0		- no update
	1		- update

Note:
========================================================================
*/
int cm_processWevent(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	int lock;
	char staMac[32] = {0};
	char band[16] = {0};
	char brMac[32] = {0};
	json_object *fileRoot = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	json_object *eventObj = NULL;
	json_object *tsObj = NULL;
	int ret = 0;
#ifdef DUAL_BAND_DETECTION
	json_object *dualBandRoot = NULL, *dualBandCapObj = NULL;
	int dualBandSta = 0, dbStaUpdate = 0;
#endif
	int event = 0;
	int update = 0;
	
	if (!root) {
		DBG_ERR("error for json parse");
		return ret;
	}

	DBG_INFO("msg(%s)", msg);

	pthread_mutex_lock(&allWeventLock);
	lock = file_lock(ALLWEVENT_FILE_LOCK);

	fileRoot = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);
	if (!fileRoot)
		fileRoot = json_object_new_object();

#ifdef DUAL_BAND_DETECTION
	dualBandRoot = json_object_from_file(CLIENT_ASSOCIATED_LIST_JSON_PATH);
	if (!dualBandRoot) {
		dualBandRoot = json_object_new_object();
		if (dualBandRoot) {
			json_object_object_add(dualBandRoot, CFG_STR_2G, json_object_new_object());
			json_object_object_add(dualBandRoot, CFG_STR_5G, json_object_new_object());
		}
	}
#endif

	/* get br0 mac */
	json_object_object_foreach(root, key, val) {
		memset(brMac, 0, sizeof(brMac));
		snprintf(brMac, sizeof(brMac), "%s", key);
		brMacObj = val;
		json_object_object_foreach(brMacObj, key, val) {
			memset(band, 0, sizeof(band));
			snprintf(band, sizeof(band), "%s", key);
			bandObj = val;
			json_object_object_foreach(bandObj, key, val) {
				memset(staMac, 0, sizeof(staMac));
				snprintf(staMac, sizeof(staMac), "%s", key);
				staObj = val;

#ifdef ONBOARDING
				if (nvram_get_int("cfg_obstatus") == OB_TYPE_LOCKED) {
					if (strcmp(staMac, nvram_safe_get("cfg_newre")) == 0) {
						DBG_INFO("sta (%s) is new RE, pass it", staMac);
						continue;
					}
				}
#endif

#ifdef DUAL_BAND_DETECTION
				dualBandSta = 0;
#endif
				json_object_object_get_ex(staObj, WEVENT_EVENT, &eventObj);
				json_object_object_get_ex(staObj, WEVENT_TIMESTAMP, &tsObj);
				if (eventObj && tsObj) {
					long ts = json_object_get_int64(tsObj);
					event = json_object_get_int(eventObj);
					DBG_INFO("brMac(%s), band(%s), sta(%s), event(%d), ts(%ld)",
						brMac, band, staMac, event, ts);
					update = cm_processWeventCommon(fileRoot, brMac, band, staMac, event, ts);

#ifdef DUAL_BAND_DETECTION
					if (json_object_get_int(eventObj) == EID_WEVENT_DEVICE_CONNECTED) {
						dbStaUpdate = cm_checkDualBandListUpdate(staMac);

						/* update sta's timestamp */
						if (dbStaUpdate) {
							cm_updateDualBandStaTimestamp(staMac);
							continue;
						}

						/* check from event info */
						json_object_object_get_ex(staObj, CFG_STR_DUAL_BAND_CAP, &dualBandCapObj);
						if (dualBandCapObj) {
							if (!dbStaUpdate) {
								cm_updateDualBandList(staMac);
								ret = 1;
								dualBandSta = 1;
							}
						}

						/* check from associated list */
						if (dualBandSta == 0) {
							if (!dbStaUpdate && cm_staSupportDualBandCapability(dualBandRoot, band, staMac, ts)) {
								cm_updateDualBandList(staMac);
								ret = 1;
							}
						}
					}
#endif
				}				
			}
		}
	}

	/* write to file */
	if (fileRoot && update)
		json_object_to_file(ALLWCLIENT_LIST_JSON_PATH, fileRoot);
	json_object_put(fileRoot);

	file_unlock(lock);
	pthread_mutex_unlock(&allWeventLock);

#ifdef RTCONFIG_NOTIFICATION_CENTER
	/* send wifi connect/disconnect event to wlc_nt */
	json_object_object_foreach(root, rootKey, rootVal) {
		memset(brMac, 0, sizeof(brMac));
		snprintf(brMac, sizeof(brMac), "%s", rootKey);
		brMacObj = rootVal;
		json_object_object_foreach(brMacObj, key, val) {
			memset(band, 0, sizeof(band));
			snprintf(band, sizeof(band), "%s", key);
			bandObj = val;
			json_object_object_foreach(bandObj, key, val) {
				memset(staMac, 0, sizeof(staMac));
				snprintf(staMac, sizeof(staMac), "%s", key);
				staObj = val;

#ifdef ONBOARDING
				if (nvram_get_int("cfg_obstatus") == OB_TYPE_LOCKED) {
					if (strcmp(staMac, nvram_safe_get("cfg_newre")) == 0) {
						DBG_INFO("sta (%s) is new RE, pass it", staMac);
						continue;
					}
				}
#endif
				json_object_object_get_ex(staObj, WEVENT_EVENT, &eventObj);
				if (eventObj) {
					event = json_object_get_int(eventObj);
					DBG_INFO("brMac(%s), band(%s), sta(%s), event(%d) for sending event to wlc_nt",
						brMac, band, staMac, event);

					cm_forwardWifiEventToNtCenter(
						(event == EID_WEVENT_DEVICE_CONNECTED) ? WIFI_DEVICE_ONLINE: WIFI_DEVICE_OFFLINE, staMac, band);
				}
			}
		}
	}
#endif

	json_object_put(root);
#ifdef DUAL_BAND_DETECTION
	/* write to file */
	if (dualBandRoot)
		json_object_to_file(CLIENT_ASSOCIATED_LIST_JSON_PATH, dualBandRoot);
	json_object_put(dualBandRoot);
#endif

	return ret;
} /* End of cm_processWevent */

/*
========================================================================
Routine Description:
	Process wireless event (server).

Arguments:
	*e	- wireless event

Return Value:
	None

Note:
========================================================================
*/
void cm_processWeventServer(unsigned char *msg)
{
	json_object *fileRoot = NULL;
	json_object *eventRoot = NULL;
	json_object *weventObj = NULL;
	json_object *eidObj = NULL;
	json_object *macObj = NULL;
	json_object *ifObj = NULL;
	char staMac[32] = {0};
	char band[16] = {0};
	char brMac[32] = {0};
	int event = -1;
	time_t ts;
	unsigned char ea[6] = {0};

 	DBG_INFO("event msg(%s)", msg);
	time(&ts);

	eventRoot = json_tokener_parse((char *)msg);
	json_object_object_get_ex(eventRoot, WEVENT_PREFIX, &weventObj);
	json_object_object_get_ex(weventObj, EVENT_ID, &eidObj);
	json_object_object_get_ex(weventObj, MAC_ADDR, &macObj);
	json_object_object_get_ex(weventObj, IF_NAME, &ifObj);

	if (eventRoot && eidObj && macObj && ifObj) {
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		char word[256], *next;
		int unit = 0;
		char pap[18] = {0};
#endif

		/* for staMac */
		ether_atoe(json_object_get_string(macObj), ea);
		memset(staMac, 0, sizeof(staMac));
		snprintf(staMac, sizeof(staMac), "%02X:%02X:%02X:%02X:%02X:%02X",
			ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]); 

		/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			if (!strcmp(staMac, get_pap_bssid(unit, &pap[0], sizeof(pap)))) {
				DBG_INFO("staMac(%s) is same, don't process it", staMac);
				goto err;
			}
			unit++;
		}
#endif

		/* for brMac */
		snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

		/* for band */
		if_nametoalias((char *)json_object_get_string(ifObj), band, sizeof(band));

		/* for event */
		event = atoi(json_object_get_string(eidObj));

		DBG_INFO("brMac(%s), band(%s), staMac(%s), event(%d), ts(%ld)",
				 brMac, band, staMac, event, ts);
	
		pthread_mutex_lock(&weventLock);

		fileRoot = json_object_from_file(WCLIENT_LIST_JSON_PATH);
		if (!fileRoot)
			fileRoot = json_object_new_object();
		cm_processWeventCommon(fileRoot, brMac, band, staMac, event, ts);
		/* write to file */
		if (fileRoot)
			json_object_to_file(WCLIENT_LIST_JSON_PATH, fileRoot);
		json_object_put(fileRoot);
	
		pthread_mutex_unlock(&weventLock);
	}
	else
		DBG_INFO("no or invalid content");

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
err:
#endif

	json_object_put(eventRoot);
} /* End of cm_processWeventServer */

/*
========================================================================
Routine Description:
	Process wireless event (client).

Arguments:
	*e		- wireless event

Return Value:
	None

Note:
========================================================================
*/
void cm_processWeventClient(unsigned char *msg)
{
	json_object *eventRoot = NULL;
	json_object *weventObj = NULL;
	json_object *eidObj = NULL;
	json_object *macObj = NULL;
	json_object *ifObj = NULL;
	char ifAlias[16] = {0};
	char staMac[32] = {0};
	char brMac[32] = {0};
	time_t ts;
	unsigned char ea[6] = {0};

	DBG_INFO("event msg (%s)", msg);

	time(&ts);
	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	eventRoot = json_tokener_parse((char *)msg);
	json_object_object_get_ex(eventRoot, WEVENT_PREFIX, &weventObj);
	json_object_object_get_ex(weventObj, EVENT_ID, &eidObj);
	json_object_object_get_ex(weventObj, MAC_ADDR, &macObj);
	json_object_object_get_ex(weventObj, IF_NAME, &ifObj);

	if (eventRoot && eidObj && macObj && ifObj) {
		json_object *fileRoot = NULL;
		json_object *brMacObj = NULL;
		json_object *bandObj = NULL;
		json_object *staObj = NULL;
		json_object *eventObj = NULL;
		int event = -1;
		int needAdd = 1;
		int processed = 0;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		char word[256], *next;
		int unit = 0;
		char pap[18] = {0};
#endif

		/* for staMac */
		ether_atoe(json_object_get_string(macObj), ea);
		memset(staMac, 0, sizeof(staMac));
		snprintf(staMac, sizeof(staMac), "%02X:%02X:%02X:%02X:%02X:%02X",
			ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);

		/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			if (!strcmp(staMac, get_pap_bssid(unit, &pap[0], sizeof(pap)))) {
				DBG_INFO("staMac(%s) is same, don't process it", staMac);
				goto err;
			}
			unit++;
		}
#endif

		event = atoi(json_object_get_string(eidObj));

		/* convert ifname to alias */
		if_nametoalias((char *)json_object_get_string(ifObj), &ifAlias[0], sizeof(ifAlias));
		DBG_INFO("ifAlias(%s)", ifAlias);

		pthread_mutex_lock(&weventLock);
		if ((fileRoot = json_object_from_file(WCLIENT_LIST_JSON_PATH)) != NULL) {
			/* delete sta first for all band */
			json_object_object_foreach(fileRoot, key, val) {
				brMacObj = val;
				json_object_object_foreach(brMacObj, key, val) {
					bandObj = val;
					/* process band */
					json_object_object_get_ex(bandObj, staMac, &staObj);
					if (staObj) {
						json_object_object_get_ex(staObj, WEVENT_EVENT, &eventObj);
						if (eventObj) {
							if (event != json_object_get_int(eventObj)) {
								if (!processed)
									needAdd = 0;

								if (event == EID_WEVENT_DEVICE_CONNECTED &&
									json_object_get_int(eventObj) == EID_WEVENT_DEVICE_DISCONNECTED) {
									needAdd = 1;
									processed = 1;
								}
							}
						}
						DBG_INFO("delete sta (%s)", staMac);
						json_object_object_del(bandObj, staMac);
					}
				}
			}

			DBG_INFO("need to add sta (%d)", needAdd);

			/* add sta */
			if (needAdd) {
				json_object_object_get_ex(fileRoot, brMac, &brMacObj);	

				if (!brMacObj) {
					DBG_INFO("brMacObj is NULL!");
					brMacObj = json_object_new_object();
					if (brMacObj)
						json_object_object_add(fileRoot, brMac, brMacObj);
					else
						DBG_ERR("brMacObj is NULL!");
				}

				if (brMacObj) {	
					json_object_object_get_ex(brMacObj, ifAlias, &bandObj);

					if (!bandObj) {
						DBG_INFO("bandObj is NULL!");
						bandObj = json_object_new_object();
						if (bandObj)
							json_object_object_add(brMacObj, ifAlias, bandObj);
						else
							DBG_ERR("bandObj is NULL!");
					}
			
					if (bandObj) {
						staObj = json_object_new_object();
						if (staObj) {
							json_object_object_add(staObj, WEVENT_TIMESTAMP,
								json_object_new_int64(ts));
							json_object_object_add(staObj, WEVENT_EVENT,
								json_object_new_int(event));
							json_object_object_add(bandObj, staMac, staObj);
						}
						else
							DBG_INFO("staObj is NULL!");
					}
				}
			}
		}
		else
		{
			fileRoot = json_object_new_object();
			brMacObj = json_object_new_object();
			bandObj = json_object_new_object();
			staObj = json_object_new_object();

			if (fileRoot && brMacObj && bandObj && staObj) {
				json_object_object_add(staObj, WEVENT_TIMESTAMP,
					json_object_new_int64(ts));
				json_object_object_add(staObj, WEVENT_EVENT,
					json_object_new_int(event));
			
				json_object_object_add(bandObj, staMac, staObj);
				json_object_object_add(brMacObj, ifAlias, bandObj);
				json_object_object_add(fileRoot, brMac, brMacObj);
			}
			else {
				json_object_put(fileRoot);
				json_object_put(brMacObj);
				json_object_put(bandObj);
				json_object_put(staObj);
				DBG_INFO("can't create obj for wireless client");
			}
		}

		/* write to file */
		if (fileRoot) {
			DBG_INFO("timestamp(%ld), wireless client list(%s)", ts, json_object_to_json_string(fileRoot));
			json_object_to_file(WCLIENT_LIST_JSON_PATH, fileRoot);
		}
		json_object_put(fileRoot);
		pthread_mutex_unlock(&weventLock);
	}
	else
		DBG_INFO("no or invalid content");

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
err:
#endif

	json_object_put(eventRoot);
} /* End of cm_processWeventClient */

#ifdef ONBOARDING
/*
========================================================================
Routine Description:
	Extract tlv data.

Arguments:
	hexData		- hex data
	hexDataLen	- the length of hex data
	type		- which type need to extract
	hexLen		- hex length

Return Value:
	extracted tlv data

========================================================================
*/
unsigned char *cm_extractTlvData(unsigned char *hexData, int hexDataLen, int tlvType, int *hexLen)
{
	unsigned char *data = NULL;
	unsigned char *pData = NULL;
	int i = 0;
	int type = 0;
	int len = 0; 

	pData = hexData;

	for (i = 0; i < hexDataLen; ) {
		type = (int)hexData[i++];
		len = (int)hexData[i++];
		pData += 2;
		if (type == tlvType) {
			DBG_INFO("type(%d), len(%d)", type, len);
			if ((data = (unsigned char *)malloc(len + 1)) != NULL) {
				memset(data, 0, len + 1);
				memcpy(data, pData, len);
				*hexLen = len;
				break;
			}
		}
		i += len;
		pData += len;
	}

#if 0
	if (data) {
		for (i = 0; i < len; i++)
			DBG_PRINTF("%02X ", data[i]);
		DBG_PRINTF("\n");
	}
	else
		DBG_INFO("data is null");
#endif

	return data;
} /* End of cm_extractTlvData */

/*
========================================================================
Routine Description:
	Process probe request from wevent.

Arguments:
	data		- received data

Return Value:
	None

Note:
========================================================================
*/
void cm_processProbeReq(unsigned char *data)
{
	json_object *eventRoot = json_tokener_parse((char *)data);
	json_object *weventObj = NULL;
	json_object *vsieObj = NULL;
	unsigned char *hexVsie = NULL;
	int hexVsieLen = 0;
	unsigned char *hexId = NULL;
	unsigned char *hexReMac = NULL;
	unsigned char *hexModelName = NULL;
	unsigned char *hexRssi = NULL;
	unsigned char *hexrTime = NULL, *hexcTimeout = NULL, * hextTimeout = NULL;
	unsigned char *hexMiscInfo = NULL;
	char idStr[41] = {0};
	char reMacStr[18] = {0};
	char modelNameStr[32] = {0};
	unsigned char vsieStr[256] = {0};
	unsigned char msg[512] = {0};
	int hexLen = 0;
	char rssiListStr[256] = {0};
	short rTime = 0, cTimeout = 0, tTimeout = 0;
	unsigned char *hexTcode = NULL;
	char tCodeStr[16] = {0}, dataTmp[512];
	char miscInfoStr[128] = {0};

	if (!eventRoot) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_get_ex(eventRoot, WEVENT_PREFIX, &weventObj);
	json_object_object_get_ex(weventObj, VSIE, &vsieObj);

	if (!vsieObj) {
		DBG_ERR("vsieObj is null");
		return;
	}

	snprintf((char *)vsieStr, sizeof(vsieStr), "%s", (char *)json_object_get_string(vsieObj));

	if ((hexVsie = (unsigned char *)malloc(strlen((char *)vsieStr)/2)) == NULL) {
		DBG_ERR("memory allocate failed");
		return;
	}
	
	hexVsieLen = strlen((char *)vsieStr)/2;

	DBG_INFO("viseStr(%s), hexVsielen(%d)", vsieStr, hexVsieLen);

	if (str2hex((char *)vsieStr, hexVsie, strlen((char *)vsieStr))) {
		hexId = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_ID, &hexLen);
		if (hexId) {
			if (hex2str(hexId, &idStr[0], sizeof(idStr)/2))
				DBG_INFO("id(%s) hexLen(%d)", idStr, hexLen);
		}

		hexReMac = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_RE_MAC, &hexLen);
		if (hexReMac) {
			snprintf(reMacStr, sizeof(reMacStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				hexReMac[0], hexReMac[1], hexReMac[2], hexReMac[3],
				hexReMac[4], hexReMac[5]);    
			DBG_INFO("reMac(%s) hexLen(%d)", reMacStr, hexLen);
		}

		hexModelName = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_MODEL_NAME, &hexLen);
		if (hexModelName) {
			snprintf(modelNameStr, sizeof(modelNameStr), "%s", hexModelName);
			DBG_INFO("model name(%s) hexLen(%d)", modelNameStr, hexLen);
		}

		hexRssi = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_RSSI, &hexLen);
		if (hexRssi) {
			hex2str(hexRssi, &rssiListStr[0], hexLen);
			DBG_INFO("rssi list(%s) hexLen(%d)", rssiListStr, hexLen);
		}

		hexrTime = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_REBOOT_TIME, &hexLen);
		if (hexrTime && hexLen == sizeof(rTime)) {
			memcpy(&rTime, hexrTime, sizeof(rTime));
			DBG_INFO("reboot time(%d) hex(%X) hexLen(%d)", ntohs(rTime), ntohs(rTime), hexLen);
		}

		hexcTimeout = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_CONN_TIMEOUT, &hexLen);
		if (hexcTimeout && hexLen == sizeof(cTimeout)) {
			memcpy(&cTimeout, hexcTimeout, sizeof(cTimeout));
			DBG_INFO("connection timeout(%d) hex(%X) hexLen(%d)", ntohs(cTimeout), ntohs(cTimeout), hexLen);
		}

		hextTimeout = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_TRAFFIC_TIMEOUT, &hexLen);
		if (hextTimeout && hexLen == sizeof(tTimeout)) {
			memcpy(&tTimeout, hextTimeout, sizeof(tTimeout));
			DBG_INFO("traffic timeout(%d) hex(%X) hexLen(%d)", ntohs(tTimeout), ntohs(tTimeout), hexLen);
		}

		hexTcode = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_TCODE, &hexLen);
		if (hexTcode) {
			snprintf(tCodeStr, sizeof(tCodeStr), "%s", hexTcode);
			DBG_INFO("territory code (%s) hexLen(%d)", tCodeStr, hexLen);
		}

		hexMiscInfo = cm_extractTlvData(hexVsie, hexVsieLen, VSIE_TYPE_MISC_INFO, &hexLen);
		if (hexMiscInfo) {
			hex2str(hexMiscInfo, &miscInfoStr[0], hexLen);
			DBG_INFO("misc info(%s) hexLen(%d)", miscInfoStr, hexLen);
		}

#if 0
		if (hexrTime && hexcTimeout && hextTimeout) {
			snprintf((char *)msg, sizeof(msg), "{\"%s\":%d,\"%s\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%d"
					",\"%s\":%d,\"%s\":%d,\"%s\":%d}}",
				CFG_STR_STATUS, OB_STATUS_REQ, get_unique_mac(), CFG_STR_MAC,
				reMacStr, CFG_STR_ID, idStr, CFG_STR_MODEL_NAME, modelNameStr,
				CFG_STR_RSSI, rssiListStr, CFG_STR_SOURCE, FROM_WIRELESS,
				CFG_STR_REBOOT_TIME, ntohs(rTime), CFG_STR_CONN_TIMEOUT, ntohs(cTimeout),
				CFG_STR_TRAFFIC_TIMEOUT, ntohs(tTimeout));
		}
		else
		{
			snprintf((char *)msg, sizeof(msg), "{\"%s\":%d,\"%s\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%d}}",
				CFG_STR_STATUS, OB_STATUS_REQ, get_unique_mac(), CFG_STR_MAC,
				reMacStr, CFG_STR_ID, idStr, CFG_STR_MODEL_NAME, modelNameStr,
				CFG_STR_RSSI, rssiListStr, CFG_STR_SOURCE, FROM_WIRELESS);
		}
#endif

		strlcat((char *)msg, "{", sizeof(msg));
		snprintf(dataTmp, sizeof(dataTmp), "\"%s\":%d,\"%s\":{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%d",
				CFG_STR_STATUS, OB_STATUS_REQ, get_unique_mac(), CFG_STR_MAC,
				reMacStr, CFG_STR_ID, idStr, CFG_STR_MODEL_NAME, modelNameStr,
				CFG_STR_RSSI, rssiListStr, CFG_STR_SOURCE, FROM_WIRELESS);
		strlcat((char *)msg, dataTmp, sizeof(msg));
		if (hexrTime && hexcTimeout && hextTimeout) {
			snprintf((char *)dataTmp, sizeof(dataTmp), ",\"%s\":%d,\"%s\":%d,\"%s\":%d",
				CFG_STR_REBOOT_TIME, ntohs(rTime), CFG_STR_CONN_TIMEOUT, ntohs(cTimeout),
				CFG_STR_TRAFFIC_TIMEOUT, ntohs(tTimeout));
			strlcat((char *)msg, dataTmp, sizeof(msg));
		}
		if (hexTcode) {
			snprintf((char *)dataTmp, sizeof(dataTmp), ",\"%s\":\"%s\"", CFG_STR_TCODE, tCodeStr);
			strlcat((char *)msg, dataTmp, sizeof(msg));
		}
		if (hexMiscInfo) {
			snprintf((char *)dataTmp, sizeof(dataTmp), ",\"%s\":\"%s\"", CFG_STR_MISC_INFO, miscInfoStr);
			strlcat((char *)msg, dataTmp, sizeof(msg));
		}
		strlcat((char *)msg, "}}", sizeof(msg));

		DBG_INFO("msg(%s)", msg);

		if (cm_isOnboardingAvailable()) {
			if (cm_ctrlBlock.role == IS_CLIENT) {
				/* send TCP packet */
				if (cm_sendTcpPacket(REQ_ONBOARDING, &msg[0]) == 0)
					DBG_ERR("Fail to send TCP packet!");
			}
			else
				cm_processOnboardingMsg((char *)msg);
		}
	}

	if (hexVsie) free(hexVsie);
	if (hexId) free(hexId);
	if (hexReMac) free(hexReMac);
	if (hexModelName) free(hexModelName);
	if (hexRssi) free(hexRssi);
	if (hexrTime) free(hexrTime);
	if (hexcTimeout) free(hexcTimeout);
	if (hextTimeout) free(hextTimeout);
	if (hexTcode) free(hexTcode);
	if (hexMiscInfo) free(hexMiscInfo);

	json_object_put(eventRoot);
} /* End of cm_processProbeReq */
#endif

/*
========================================================================
Routine Description:
	Process packets from wevent.

Arguments:
	data		- received data

Return Value:
	None

Note:
========================================================================
*/
void cm_weventPacketProcess(unsigned char *data)
{
	json_object *eventRoot = json_tokener_parse((char *)data);
	json_object *weventObj = NULL;
	json_object *eidObj = NULL;
	int eid = 0;

	DBG_INFO("enter");

	if (!eventRoot) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_get_ex(eventRoot, WEVENT_PREFIX, &weventObj);
	json_object_object_get_ex(weventObj, EVENT_ID, &eidObj);

	if (!weventObj || !eidObj) {
		DBG_ERR("weventObj or eidObj is NULL!");
		return;
	}

	eid = atoi(json_object_get_string(eidObj));
	json_object_put(eventRoot);
	
	if (eid == EID_WEVENT_DEVICE_CONNECTED ||
		eid == EID_WEVENT_DEVICE_DISCONNECTED)	/* connect or disconnect event */
	{
		cm_processWeventClient(data);
	}
#ifdef ONBOARDING
	else if (eid == EID_WEVENT_DEVICE_PROBE_REQ) { /* probe req event */
#if defined(RTCONFIG_WIFI_SON)
		if(!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
		{
		if (cm_isOnboardingAvailable())
			cm_processProbeReq(data);
		} /* !wifison_ready */
	}
#endif
#ifdef RADAR_DET
	else if (eid == EID_WEVENT_DEVICE_RADAR_DETECTED) { /* radar detected event */
#if defined(RTCONFIG_WIFI_SON)
		if (!nvram_match("wifison_ready","1"))
#endif
		{
		cm_processRadarDetection();
		} /* !wifison_ready */
	}
#endif
	else
		DBG_INFO("unknown event id");

	DBG_INFO("leave");
} /* End of cm_weventPacketProcess */

/*
========================================================================
Routine Description:
	Check RE's wifi connected or not.

Arguments:
	reMac		- RE's mac
	modelName		- RE's model name

Return Value:
	0		- doesn't connected
	1		- connected

Note:
========================================================================
*/
int cm_checkReWifiConnected(char *reMac, char *modelName)
{
	int lock;
	json_object *fileRoot = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	int ret = 0;
	unsigned char eaRe[6], eaReLocal[6], eaSta[6], eaStaLocal[6];

	if (!reMac) {
		DBG_ERR("reMac is NULL");
		return ret;
	}

	DBG_INFO("reMac (%s)", reMac);
	ether_atoe(reMac, eaRe);
	/* shade low bits of last byte(5) for RE mac */
	eaRe[5] = eaRe[5] & 0xF0;
	/* copy eaRe and shade first byte of RE mac */
	memcpy(&eaReLocal[0], &eaRe[0], 6);
	eaReLocal[0] = eaReLocal[0] & 0x0;
	/* shade high bits of 2nd byte of RE mac for mtk's apcliX */
	eaReLocal[1] = eaReLocal[1] & 0xF;

	DBG_INFO("eaRe[0]=%02X, eaRe[1]=%02X, eaRe[2]=%02X, eaRe[3]=%02X, eaRe[4]=%02X, eaRe[5]=%02X",
		eaRe[0], eaRe[1], eaRe[2], eaRe[3], eaRe[4], eaRe[5]);
	DBG_INFO("eaReLocal[0]=%02X, eaReLocal[1]=%02X, eaReLocal[2]=%02X, eaReLocal[3]=%02X, eaReLocal[4]=%02X, eaReLocal[5]=%02X",
                eaReLocal[0], eaReLocal[1], eaReLocal[2], eaReLocal[3], eaReLocal[4], eaReLocal[5]);

	pthread_mutex_lock(&allWeventLock);
	lock = file_lock(ALLWEVENT_FILE_LOCK);
	fileRoot = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);
	file_unlock(lock);
	pthread_mutex_unlock(&allWeventLock);

	if (fileRoot) {
		json_object_object_foreach(fileRoot, key, val) {
			brMacObj = val;
			json_object_object_foreach(brMacObj, key, val) {
				bandObj = val;
				json_object_object_foreach(bandObj, key, val) {
					if (cm_isReWifiUpstreamMac(key))
						continue;

					ether_atoe(key, eaSta);
					/* shade low bits of last byte(5) for sta mac */
					eaSta[5] = eaSta[5] & 0xF0;
					/* copy eaSta and shade first byte of RE mac */
					memcpy(&eaStaLocal[0], &eaSta[0], 6);
					eaStaLocal[0] = eaStaLocal[0] & 0x0;
					/* shade high bits of 2nd byte of RE mac for mtk's apcliX */
					eaStaLocal[1] = eaStaLocal[1] & 0xF;

					DBG_INFO("eaSta[0]=%02X, eaSta[1]=%02X, eaSta[2]=%02X, eaSta[3]=%02X, eaSta[4]=%02X, eaSta[5]=%02X",
						eaSta[0], eaSta[1], eaSta[2], eaSta[3], eaSta[4], eaSta[5]);
					DBG_INFO("eaStaLocal[0]=%02X, eaStaLocal[1]=%02X, eaStaLocal[2]=%02X, eaStaLocal[3]=%02X, eaStaLocal[4]=%02X, eaStaLocal[5]=%02X",
						eaStaLocal[0], eaStaLocal[1], eaStaLocal[2], eaStaLocal[3], eaStaLocal[4], eaStaLocal[5]);

					if (memcmp(eaRe, eaSta, 6) == 0 ||
						memcmp(eaReLocal, eaStaLocal, 6) == 0) {
						DBG_INFO("found, sta mac (%s)", key);
						ret = 1;
						goto FOUND;
					}
				}
			}
		}
	}

FOUND:

	json_object_put(fileRoot);

	return ret;
} /* End of cm_checkReWifiConnected */

/*
========================================================================
Routine Description:
	Remove RE's wifi connected history.

Arguments:
	reMac		- RE's mac
	modelName		- RE's model name

Return Value:
	none

Note:
========================================================================
*/
void cm_removeReWifiConnectedHistory(char *reMac)
{
	int lock;
	json_object *fileRoot = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int update = 0;

	if (!reMac) {
		DBG_ERR("reMac is NULL");
		return;
	}

	DBG_INFO("reMac (%s)", reMac);

	pthread_mutex_lock(&allWeventLock);
	lock = file_lock(ALLWEVENT_FILE_LOCK);
	fileRoot = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH);

	if (fileRoot) {
		json_object_object_foreach(fileRoot, key, val) {
			brMacObj = val;
			json_object_object_foreach(brMacObj, key, val) {
				bandObj = val;

				json_object_object_get_ex(bandObj, reMac, &staObj);
				if (staObj) {
					DBG_INFO("delete sta (%s), it's RE", reMac);
					json_object_object_del(bandObj, reMac);
					update = 1;
				}
			}
		}
	}

	/* write to file */
	if (fileRoot && update)
		json_object_to_file(ALLWCLIENT_LIST_JSON_PATH, fileRoot);

	json_object_put(fileRoot);

	file_unlock(lock);
	pthread_mutex_unlock(&allWeventLock);
} /* End of cm_removeReWifiConnectedHistory */
