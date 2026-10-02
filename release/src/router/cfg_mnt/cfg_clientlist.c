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
#include <networkmap.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_clientlist.h"
#include "cfg_slavelist.h"
#include "cfg_eventnotify.h"

/*
========================================================================
Routine Description:
	Prepare client list message.

Arguments:
	msg		- output message arrary
	msgLen		- the length of output message array

Return Value:
	message length

========================================================================
*/
int cm_prepareClientListMsg(char *msg, int msgLen)
{
	char portNo[32] = {0};
	json_object *clientListObj = json_object_new_object();
	json_object *clientRoot = json_object_new_object();
	json_object *prefixObj = NULL;
	json_object *brMacObj = json_object_new_object();
	json_object *clientObj = NULL;
	json_object *macEntry = NULL;
	json_object *clientItemObj = NULL;
	json_object *rssiObj = NULL;
	int wiredMacListLen = 0;
	int i, shm_client_info_id;
	int j = 0;
	int lock;
	P_CLIENT_DETAIL_INFO_TABLE p_client_info_tab;
	void *shared_client_info = (void *) 0;
	char brMac[18] = {0};
	char prefixStr[16] = {0};
	char macBuf[18] = {0};
	char ipBuf[16] = {0};
	char rssiBuf[16] = {0};
	int found = 0;

	DBG_INFO("enter");

	if (!clientListObj && !clientRoot && !brMacObj) {
		DBG_ERR("clientListObj, clientRoot or brMacObj is NULL");
		json_object_put(clientListObj);
		json_object_put(clientRoot);
		json_object_put(brMacObj);
		return 0;
	}

	/* get mac and rssi for wireless client on different band */
	wl_sta_rssi_list(clientListObj);
	//DBG_INFO("msg(%s)", json_object_to_json_string(clientListObj));

	/* get mac for wired client */
	snprintf(portNo, sizeof(portNo), "%s", get_portno_by_ifname());
	if (strlen(portNo) > 0)
		add_brforward_entry_by_port(clientListObj, portNo);

	//DBG_INFO("msg(%s)", json_object_to_json_string(clientListObj));

	/* prepare client list */
	lock = file_lock("networkmap");
	shm_client_info_id = shmget((key_t)SHMKEY_LAN, sizeof(CLIENT_DETAIL_INFO_TABLE), 0666|IPC_CREAT);
	if (shm_client_info_id == -1){
		DBG_ERR("shmget failed");
		json_object_put(clientListObj);
		json_object_put(clientRoot);
		json_object_put(brMacObj);
		file_unlock(lock);
		return 0;
	}

	shared_client_info = shmat(shm_client_info_id, (void *) 0,0);
	if (shared_client_info == (void *)-1){
		DBG_ERR("shmat failed");
		json_object_put(clientListObj);
		json_object_put(clientRoot);
		json_object_put(brMacObj);
		file_unlock(lock);
		return 0;
	}

	p_client_info_tab = (P_CLIENT_DETAIL_INFO_TABLE)shared_client_info;

	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	json_object_object_foreach(clientListObj, key, val) {
		clientItemObj = val;
		prefixObj = NULL;
		memset(prefixStr, 0, sizeof(prefixStr));
		snprintf(prefixStr, sizeof(prefixStr), "%s", key);

		if (!strcmp(key, CFG_STR_WIRED_MAC)) {	/* for wired */
			wiredMacListLen = json_object_array_length(clientItemObj);
			
			for (i = 0; i < wiredMacListLen; i++) {
				found = 0;
				macEntry = json_object_array_get_idx(clientItemObj, i);
				memset(ipBuf, 0, sizeof(ipBuf));
				
				for (j = 0; j < p_client_info_tab->ip_mac_num; j++) {
					memset(macBuf, 0, sizeof(macBuf));

					snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_info_tab->mac_addr[j][0],p_client_info_tab->mac_addr[j][1],
							p_client_info_tab->mac_addr[j][2],p_client_info_tab->mac_addr[j][3],
							p_client_info_tab->mac_addr[j][4],p_client_info_tab->mac_addr[j][5]);
					
					if (!strcmp(macBuf, json_object_get_string(macEntry))) {
						found = 1;
						snprintf(ipBuf, sizeof(ipBuf), "%d.%d.%d.%d", p_client_info_tab->ip_addr[j][0],
								p_client_info_tab->ip_addr[j][1], p_client_info_tab->ip_addr[j][2],
								p_client_info_tab->ip_addr[j][3]);
						break;
					}
				}

				clientObj = json_object_new_object();
				if (clientObj) {
					if (found)
						json_object_object_add(clientObj, CFG_STR_IP, json_object_new_string(ipBuf));
					else
						json_object_object_add(clientObj, CFG_STR_IP, json_object_new_string(""));

					if (!prefixObj)
						prefixObj = json_object_new_object();

					if (prefixObj)
						json_object_object_add(prefixObj, json_object_get_string(macEntry), clientObj);
					else
						json_object_put(clientObj);
				}
			}

			if (prefixObj)
				json_object_object_add(brMacObj, prefixStr, prefixObj);
		}
		else		/* for wireless */
		{
			json_object_object_foreach(clientItemObj, key, val) {
				found = 0;
				memset(ipBuf, 0, sizeof(ipBuf));
				json_object_object_get_ex(val, CFG_STR_RSSI, &rssiObj);
				
				for (j = 0; j < p_client_info_tab->ip_mac_num; j++) {
					memset(macBuf, 0, sizeof(macBuf));

					snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_info_tab->mac_addr[j][0],p_client_info_tab->mac_addr[j][1],
							p_client_info_tab->mac_addr[j][2],p_client_info_tab->mac_addr[j][3],
							p_client_info_tab->mac_addr[j][4],p_client_info_tab->mac_addr[j][5]);

					if (!strcmp(macBuf, key)) {
						found = 1;
						snprintf(ipBuf, sizeof(ipBuf), "%d.%d.%d.%d", p_client_info_tab->ip_addr[j][0],
								p_client_info_tab->ip_addr[j][1], p_client_info_tab->ip_addr[j][2],
								p_client_info_tab->ip_addr[j][3]);
						break;
					}
				}

				clientObj = json_object_new_object();
				if (clientObj) {
					if (found)
						json_object_object_add(clientObj, CFG_STR_IP, json_object_new_string(ipBuf));
					else
						json_object_object_add(clientObj, CFG_STR_IP, json_object_new_string(""));

					if (rssiObj) {
						memset(rssiBuf, 0, sizeof(rssiBuf));
						snprintf(rssiBuf, sizeof(rssiBuf), "%d", json_object_get_int(rssiObj));
						json_object_object_add(clientObj, CFG_STR_RSSI, json_object_new_string(rssiBuf));
					}
					else
						json_object_object_add(clientObj, CFG_STR_RSSI, json_object_new_string(""));

					if (!prefixObj)
						prefixObj = json_object_new_object();

					if (prefixObj)
						json_object_object_add(prefixObj, key, clientObj);
					else
						json_object_put(clientObj);
				}
			}

			if (prefixObj)
				json_object_object_add(brMacObj, prefixStr, prefixObj);
		}
	}

	json_object_object_add(clientRoot, brMac, brMacObj);
	
	snprintf(msg, msgLen, "%s", json_object_to_json_string(clientRoot));
	//DBG_INFO("msg(%s)", msg);
	DBG_INFO("leave");
	json_object_put(clientListObj);
	json_object_put(clientRoot);

	shmdt(shared_client_info);
	file_unlock(lock);

	return strlen(msg);
} /* End of cm_prepareClientListMsg */

/*========================================================================
Routine Description:
	Process client list.

Arguments:
	*msg	- client list

Return Value:
	None

Note:
========================================================================
*/
void cm_processClientList(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	int lock;
	char brMac[18] = {0};
	char band[16] = {0};
	char clientMac[18] = {0};
	json_object *fileRoot = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *clientObj = NULL;
	json_object *brMacObjTemp = NULL;
	json_object *bandObjTemp = NULL;
	json_object *clientObjTemp = NULL;
	
	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	//DBG_INFO("msg(%s)", msg);

	pthread_mutex_lock(&clientListLock);
	DBG_INFO("enter");

	fileRoot = json_object_from_file(CLIENT_LIST_JSON_PATH);
	if (!fileRoot)
		fileRoot = json_object_new_object();

	/* update & filter wireless client on differnt DUT */
	json_object_object_foreach(root, key, val) {
		memset(brMac, 0, sizeof(brMac));
		snprintf(brMac, sizeof(brMac), "%s", key);
		brMacObj = val;

		if (!brMacObj)
			continue;

		brMacObjTemp = json_object_new_object();

		if (fileRoot && brMacObjTemp) {
			DBG_INFO("delete old client list for %s on fileRoot", brMac);
			json_object_object_del(fileRoot, brMac);

			json_object_object_foreach(brMacObj, key, val) {
				memset(band, 0, sizeof(band));
				snprintf(band, sizeof(band), "%s", key);
				bandObj = val;

				bandObjTemp = json_object_new_object();

				if (bandObjTemp) {
					json_object_object_foreach(bandObj, key, val) {
						memset(clientMac, 0, sizeof(clientMac));
						snprintf(clientMac, sizeof(clientMac), "%s", key);
						clientObj = val;

						clientObjTemp = json_object_new_object();

						if (clientObjTemp) {
							json_object_object_foreach(clientObj, key, val) {
								json_object_object_add(clientObjTemp, key,
									json_object_new_string(json_object_get_string(val)));
							}

							json_object_object_add(bandObjTemp, clientMac, clientObjTemp);
						}
					}
					json_object_object_add(brMacObjTemp, band, bandObjTemp);
				}
			}
			json_object_object_add(fileRoot, brMac, brMacObjTemp);
		}
	}

	/* write to file */
	lock = file_lock(CLIENTLIST_FILE_LOCK);
	if (fileRoot)
		json_object_to_file(CLIENT_LIST_JSON_PATH, fileRoot);
	file_unlock(lock);

	json_object_put(fileRoot);
	json_object_put(root);
	DBG_INFO("leave");
	pthread_mutex_unlock(&clientListLock);
} /* End of cm_processStaList */

/*
========================================================================
Routine Description:
	Check RE's wired connected or not.

Arguments:
	reMac		- RE's mac
	modelName		- RE's model name

Return Value:
	0		- doesn't connected
	1		- connected

Note:
========================================================================
*/
int cm_checkReWiredConnected(char *reMac, char *modelName)
{
	int lock;
	json_object *fileRoot = NULL;
	json_object *brMacObj = NULL;
	int ret = 0;
	unsigned char eaRe[6], eaWired[6];

	if (!reMac) {
		DBG_ERR("reMac is NULL");
		return ret;
	}

	DBG_INFO("reMac (%s)", reMac);
	ether_atoe(reMac, eaRe);
	/* filter low bits of last byte(5) for RE mac */
	eaRe[5] = eaRe[5] & 0xF0;

	pthread_mutex_lock(&wiredClientListLock);
	lock = file_lock(WIREDCLIENTLIST_FILE_LOCK);
	fileRoot = json_object_from_file(WIRED_CLIENT_LIST_JSON_PATH);
	file_unlock(lock);
	pthread_mutex_unlock(&wiredClientListLock);

	if (fileRoot) {
		json_object_object_foreach(fileRoot, key, val) {
			brMacObj = val;

			json_object_object_foreach(brMacObj, key, val) {
				ether_atoe(key, eaWired);
				/* filter low bits of last byte(5) for wired mac */
				eaWired[5] = eaWired[5] & 0xF0;

				if (memcmp(eaRe, eaWired, 6) == 0) {
					DBG_INFO("found, wired mac (%s)", key);
					ret = 1;
					goto FOUND;
				}
			}
		}
	}

FOUND:

	json_object_put(fileRoot);

	return ret;
} /* End of cm_checkReWiredConnected */

/*
========================================================================
Routine Description:
	Compare new and current wired client list is difference or not.

Arguments:
	None

Return Value:
	0		- no difference
	1		- difference

Note:
========================================================================
*/
int cm_compareWiredClientlLst(json_object *curClientList, json_object *newClientList)
{
	json_object *entryObj = NULL;
	int i = 0, ret = 0, newClientListLen = 0, curClientListLen = 0;

	curClientListLen = json_object_array_length(curClientList);
	newClientListLen = json_object_array_length(newClientList);

	/* check new client list based on currenet one */
	for (i = 0; i < newClientListLen; i++) {
		entryObj = json_object_array_get_idx(newClientList, i);
		if (entryObj) {
			if (curClientListLen == 0 || !search_in_array_list((char *)json_object_get_string(entryObj), curClientList, curClientListLen)) {
				ret = 1;
				break;
			}
		}
	}

	/* check current client list based on new one */
	if (ret == 0) {
		for (i = 0; i < curClientListLen; i++) {
			entryObj = json_object_array_get_idx(curClientList, i);
			if (entryObj) {
				if (newClientListLen == 0 || !search_in_array_list((char *)json_object_get_string(entryObj), newClientList, newClientListLen)) {
					ret = 1;
					break;
				}
			}
		}
	}

	return ret;
} /* End of cm_compareWiredClientlLst */

/*
========================================================================
Routine Description:
	Check wired client list need to update or not.

Arguments:
	None

Return Value:
	0		- don't need to update
	1		- need to update

Note:
========================================================================
*/
int cm_needUpdateWiredClientlLst(json_object *wiredClientList)
{
	char portNo[32] = {0};
	json_object *newClientListRoot = NULL, *newClientList = NULL, *entryObj = NULL;
	json_object *curClientList = json_object_from_file(CURRENT_WIRED_CLIENT_LIST_JSON_PATH);
	int i = 0, ret = 0, newClientListLen = 0, curClientListLen = 0;

	snprintf(portNo, sizeof(portNo), "%s", get_portno_by_ifname());
	if (strlen(portNo) > 0) {
		/* get mac addr by interface (br0) */
		newClientListRoot = json_object_new_object();
		if (newClientListRoot) {
			add_brforward_entry_by_port(newClientListRoot, portNo);
			json_object_object_get_ex(newClientListRoot, CFG_STR_WIRED_MAC, &newClientList);
			if (wiredClientList) {
				if (newClientList) {
					if (curClientList)
						ret = cm_compareWiredClientlLst(curClientList, newClientList);
					else
						ret = 1;

					if (ret == 1) {	/* need update, output to wiredClientList */
						newClientListLen = json_object_array_length(newClientList);
						for (i = 0; i < newClientListLen; i++) {
							entryObj = json_object_array_get_idx(newClientList, i);
							json_object_array_add(wiredClientList, json_object_new_string(json_object_get_string(entryObj)));
						}
						json_object_to_file(CURRENT_WIRED_CLIENT_LIST_JSON_PATH, wiredClientList);
					}
				}
				else
				{
					if (curClientList) {
						curClientListLen = json_object_array_length(curClientList);
						if (curClientListLen > 0)
							ret = 1;
					}
					else
						ret = 1;

					if (ret == 1)
						json_object_to_file(CURRENT_WIRED_CLIENT_LIST_JSON_PATH, wiredClientList);
				}
			}
			json_object_put(newClientListRoot);
		}
		else
			DBG_INFO("clientListObj is NULL");
	}
	else
	{
		if (wiredClientList) {
			if (curClientList) {
				curClientListLen = json_object_array_length(curClientList);
				if (curClientListLen > 0)
					ret = 1;
			}
			else
				ret = 1;

			if (ret == 1)
				json_object_to_file(CURRENT_WIRED_CLIENT_LIST_JSON_PATH, wiredClientList);
		}
	}

	json_object_put(curClientList);

	return ret;
} /* End of cm_needUpdateWiredClientlLst */

/*
========================================================================
Routine Description:
	Revmoe wired client list by mac.

Arguments:
	mac		- mac

Return Value:
	None

Note:
========================================================================
*/
void cm_removeWireledClientListByMac(char *mac)
{
	json_object *fileRoot = NULL;
	int lock = 0;

	pthread_mutex_lock(&wiredClientListLock);
	lock = file_lock(WIREDCLIENTLIST_FILE_LOCK);

	fileRoot = json_object_from_file(WIRED_CLIENT_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		file_unlock(lock);
		pthread_mutex_unlock(&wiredClientListLock);
		return;
	}

	/* remove wired client list by mac */
	DBG_INFO("remove wired client list by %s", mac);
	json_object_object_del(fileRoot, mac);

	/* write to file */
	if (fileRoot)
		json_object_to_file(WIRED_CLIENT_LIST_JSON_PATH, fileRoot);

	json_object_put(fileRoot);

	file_unlock(lock);
	pthread_mutex_unlock(&wiredClientListLock);
} /* End of cm_removeWireledClientListByMac */

/*========================================================================
Routine Description:
	Notify online/offline wired client

Arguments:
	onlineListObj	- online list
	offlineListObj	- offline list

Return Value:
	None

Note:
========================================================================
*/
void cm_notifyWiredClientEvent(json_object *onlineListObj, json_object *offlineListObj)
{
	int i = 0, clientListLen = 0;
	json_object *entryObj = NULL;

	/* output message for online devices */
	if (onlineListObj) {
		clientListLen = json_object_array_length(onlineListObj);
		for (i = 0; i < clientListLen; i++) {
			entryObj = json_object_array_get_idx(onlineListObj, i);
			if (entryObj) {
				DBG_INFO("%s is online", json_object_get_string(entryObj));
#ifdef RTCONFIG_NOTIFICATION_CENTER
				cm_forwardEthEventToNtCenter(ETH_DEVICE_ONLINE, (char *)json_object_get_string(entryObj));
#endif
			}
		}
	}

	/* output message for offline devices */
	if (offlineListObj) {
		clientListLen = json_object_array_length(offlineListObj);
		for (i = 0; i < clientListLen; i++) {
			entryObj = json_object_array_get_idx(offlineListObj, i);
			if (entryObj) {
				DBG_INFO("%s is offline", json_object_get_string(entryObj));
#ifdef RTCONFIG_NOTIFICATION_CENTER
				cm_forwardEthEventToNtCenter(ETH_DEVICE_OFFLINE, (char *)json_object_get_string(entryObj));
#endif
			}
		}
	}
} /* End of cm_notifyWiredClientEvent */