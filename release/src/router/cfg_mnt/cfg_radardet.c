#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <pthread.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_radardet.h"

/*
========================================================================
Routine Description:
	Update available channel.

Arguments:
	msg		- availabel wireless channel

Return Value:
	None

Note:
========================================================================
*/
void cm_updateAvailableChannel(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	char uMac[18] = {0};
	json_object *fileRoot = NULL;
	json_object *uMacObj = NULL;
	json_object *channelObj = NULL;

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("msg(%s)", msg);

	json_object_object_get_ex(root, CFG_STR_MAC, &uMacObj);
	json_object_object_get_ex(root, CFG_STR_CHANNEL, &channelObj);

	pthread_mutex_lock(&radarDetLock);

	fileRoot = json_object_from_file(RADARDET_LIST_JSON_PATH);
	if (!fileRoot) {
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			json_object_put(root);
			pthread_mutex_unlock(&radarDetLock);
			return;
		}
	}

	/* update wireless channel on differnt DUT */
	if (uMacObj && channelObj) {
		memset(uMac, 0, sizeof(uMac));
		snprintf(uMac, sizeof(uMac), "%s", json_object_get_string(uMacObj));

		uMacObj = json_object_new_object();

		if (uMacObj) {
			/* delete object */
			DBG_INFO("delete old wireless channel list for %s", uMac);
			json_object_object_del(fileRoot, uMac);

			/* re-create object */
			json_object_object_add(uMacObj, CFG_STR_CHANNEL,
				json_object_new_string(json_object_get_string(channelObj)));

			/* add object */
			json_object_object_add(fileRoot, uMac, uMacObj);
		}
	}

	/* write to file */
	if (fileRoot)
		json_object_to_file(RADARDET_LIST_JSON_PATH, fileRoot);
	json_object_put(fileRoot);
	json_object_put(root);
	pthread_mutex_unlock(&radarDetLock);
} /* End of cm_updateAvailableChannel */

