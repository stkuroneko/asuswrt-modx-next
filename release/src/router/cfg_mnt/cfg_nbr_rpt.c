#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_string.h"
#include "cfg_nbr_rpt.h"

static char oldNbrData[MAX_NBR_DATA_BUFLEN] = {0};
static char nbrListVer[9] = {0};

/*
========================================================================
Routine Description:
	Get neighbor data.

Arguments:
	buf		- buffer for return
	len		- the length of buffer

Return Value:
	0		- neighbor info not updated
	1		- neighbor info updated
	-1		- error

========================================================================
*/
int cm_getNbrData(char *buf, size_t len)
{
	if (wl_get_nbr_info(buf, len) < 0) {
		DBG_ERR("get nbr info failed");
		return -1;
	}

	if (strcmp(oldNbrData, buf)) {
		DBG_INFO("nbr info updated");
		strlcpy(oldNbrData, buf, sizeof(oldNbrData));
		return 1;
	}
	else
	{
		DBG_INFO("nbr info not updated");
		return 0;
	}
} /* End of cm_getNbrData */

/*
========================================================================
Routine Description:
	Update NBR version.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_updateNbrListVersion()
{
	memset(nbrListVer, 0, sizeof(nbrListVer));
	srand(time(NULL));
	snprintf(nbrListVer, sizeof(nbrListVer), "%d%d", rand(), rand());
	DBG_INFO("nbr list version (%s)", nbrListVer);
} /* End of cm_updateNbrVersion */

/*
========================================================================
Routine Description:
	Update neighbor data.

Arguments:
	msg		- neighbor data

Return Value:
	None

Note:
========================================================================
*/
void cm_updateNbrData(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	char uMac[18] = {0};
	json_object *fileRoot = NULL, *uMacObj = NULL, *nbrDataObj = NULL, *nbrDataTempObj = NULL, *nbrDataUpdataObj = NULL;

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("msg(%s)", msg);

	json_object_object_get_ex(root, CFG_STR_MAC, &uMacObj);
	json_object_object_get_ex(root, CFG_STR_NBR_DATA, &nbrDataObj);

	pthread_mutex_lock(&nbrRptLock);

	fileRoot = json_object_from_file(NBR_LIST_JSON_FILE);
	if (!fileRoot) {
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			json_object_put(root);
			pthread_mutex_unlock(&nbrRptLock);
			return;
		}
	}

	/* update nbr data on differnt DUT */
	if (uMacObj && nbrDataObj) {
		snprintf(uMac, sizeof(uMac), "%s", json_object_get_string(uMacObj));

		nbrDataTempObj = json_tokener_parse(json_object_get_string(nbrDataObj));
		if (nbrDataTempObj) {
			nbrDataUpdataObj = json_object_new_object();

			if (nbrDataUpdataObj) {
				/* add online */
				json_object_object_add(nbrDataUpdataObj, CFG_STR_ONLINE, json_object_new_int(1));

				/* add nbr data */
				json_object_object_add(nbrDataUpdataObj, CFG_STR_NBR_DATA, nbrDataTempObj);

				/* delete nbr data based on cap/re mac */
				DBG_INFO("delete old nbr data for %s", uMac);
				json_object_object_del(fileRoot, uMac);

				/* add nbr data based on cap/re mac */
				DBG_INFO("add new nbr data for %s", uMac);
				json_object_object_add(fileRoot, uMac, nbrDataUpdataObj);

				/* udpate nbr version for late cap & re update new nbr list by itself */
				cm_updateNbrListVersion();
			}
			else
				json_object_put(nbrDataTempObj);
		}
	}

	/* write to file */
	if (fileRoot)
		json_object_to_file(NBR_LIST_JSON_FILE, fileRoot);
	json_object_put(fileRoot);
	json_object_put(root);
	pthread_mutex_unlock(&nbrRptLock);
} /* End of cm_updateNbrData */

/*
========================================================================
Routine Description:
	Prepare neighbor list.

Arguments:
	msg		- report data
	outRoot		- json object for output message

Return Value:
	0		- no nbr list updated
	1		- nbr list updated

Note:
========================================================================
*/
int cm_prepareNbrList(unsigned char *msg, json_object *outRoot)
{
	json_object *root = json_tokener_parse((char *)msg);
	char uMac[18] = {0};
	json_object *fileRoot = NULL, *uMacObj = NULL, *nbrVerObj = NULL, *nbrListObj = NULL, *nbrDataObj = NULL;
	int nbrListUpdated = 0;

	if (!outRoot) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("msg (%s)", msg);

	json_object_object_get_ex(root, CFG_STR_MAC, &uMacObj);
	json_object_object_get_ex(root, CFG_STR_NBR_VERSION, &nbrVerObj);

	pthread_mutex_lock(&nbrRptLock);

	if (uMacObj && nbrVerObj) {
		/* compare nbr version */
		if (strcmp(nbrListVer, json_object_get_string(nbrVerObj)) != 0) {
			snprintf(uMac, sizeof(uMac), "%s", json_object_get_string(uMacObj));
			fileRoot = json_object_from_file(NBR_LIST_JSON_FILE);
			if (fileRoot) {
				nbrListObj = json_object_new_object();
				if (nbrListObj) {
					json_object_object_foreach(fileRoot, key, val) {
						if (strcmp(key, uMac) != 0) {
							nbrDataObj = json_tokener_parse((char *)json_object_get_string(val));
							if (nbrDataObj) {
								json_object_object_add(nbrListObj, key, nbrDataObj);
								nbrListUpdated = 1;
							}
						}
					}

					json_object_object_add(outRoot, CFG_STR_NBR_LIST, nbrListObj);
					json_object_object_add(outRoot, CFG_STR_NBR_VERSION, json_object_new_string(nbrListVer));
				}
			}
		}
	}
	else
		DBG_ERR("uMacObj or nbrVerObj is NULL");

	json_object_put(fileRoot);
	json_object_put(root);
	pthread_mutex_unlock(&nbrRptLock);

	return nbrListUpdated;
} /* End of cm_updateNbrData */

/*
========================================================================
Routine Description:
	Update neighbor list.

Arguments:
	msg		- decrypted message

Return Value:
	None

========================================================================
*/
void cm_updateNbrList(unsigned char *msg)
{
	json_object *root = NULL, *nbrListObj = NULL, *nbrListVerObj = NULL;

	root = json_tokener_parse((char *)msg);

	if (!root) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(root, CFG_STR_NBR_LIST, &nbrListObj);
	json_object_object_get_ex(root, CFG_STR_NBR_VERSION, &nbrListVerObj);

	pthread_mutex_lock(&nbrRptLock);
	/* get nbr list and version, then update it */
	if (nbrListObj && nbrListVerObj) {
		nvram_set("cfg_nbr_ver", json_object_get_string(nbrListVerObj));
		json_object_to_file(NBR_LIST_PRIVATE_JSON_FILE, nbrListObj);
	}
	else
		DBG_INFO("no nbr list or version");
	
	pthread_mutex_unlock(&nbrRptLock);
	
	json_object_put(root);
} /* End of cm_updateNbrList */

/*
========================================================================
Routine Description:
	Update re online/offline in neighbor data.

Arguments:
	mac			- re mac
	online		- online/offline

Return Value:
	0		- not update
	1		- update

Note:
========================================================================
*/
int cm_updateOnlineInNbrData(char *mac, int online)
{
	json_object *fileRoot = NULL, *uMacObj = NULL, *nbrDataObj = NULL, *nbrDataTempObj = NULL, *nbrDataUpdataObj = NULL;
	json_object *onlineObj = NULL;
	int update = 0;

	if (!mac) {
		DBG_ERR("mac is NULL");
		return 0;
	}

	DBG_INFO("mac (%s), online (%d)", mac, online);

	pthread_mutex_lock(&nbrRptLock);

	fileRoot = json_object_from_file(NBR_LIST_JSON_FILE);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&nbrRptLock);
		return 0;
	}

	json_object_object_get_ex(fileRoot, mac, &uMacObj);
	if (uMacObj) {
		json_object_object_get_ex(uMacObj, CFG_STR_ONLINE, &onlineObj);
		json_object_object_get_ex(uMacObj, CFG_STR_NBR_DATA, &nbrDataObj);
		if (onlineObj && nbrDataObj) {
			if (online !=  json_object_get_int(onlineObj)) {
				nbrDataTempObj = json_tokener_parse(json_object_get_string(nbrDataObj));
				if (nbrDataTempObj) {
					nbrDataUpdataObj = json_object_new_object();

					if (nbrDataUpdataObj) {
						/* add online */
						json_object_object_add(nbrDataUpdataObj, CFG_STR_ONLINE, json_object_new_int(online));

						/* add nbr data */
						json_object_object_add(nbrDataUpdataObj, CFG_STR_NBR_DATA, nbrDataTempObj);

						/* delete nbr data based on cap/re mac */
						DBG_INFO("delete old nbr data for %s", mac);
						json_object_object_del(fileRoot, mac);

						/* add nbr data based on cap/re mac */
						DBG_INFO("add new nbr data for %s", mac);
						json_object_object_add(fileRoot, mac, nbrDataUpdataObj);

						/* udpate nbr version for late cap & re update new nbr list by itself */
						cm_updateNbrListVersion();

						update = 1;
					}
					else
						json_object_put(nbrDataTempObj);
				}
			}
		}	
	}

	/* write to file */
	if (fileRoot && update)
		json_object_to_file(NBR_LIST_JSON_FILE, fileRoot);
	json_object_put(fileRoot);
	pthread_mutex_unlock(&nbrRptLock);

	return update;
} /* End of cm_updateOnlineInNbrData */
