#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_string.h"
#include "cfg_event.h"
#include "cfg_action.h"
#include "cfg_roaming.h"
#include "cfg_capability.h"

static struct action_s action_list[] = {
	{ EID_HTTPD_RE_RECONNECT,	ACTION_RE_RECONNECT,	0,		RE_RECONNECT },
	{ EID_HTTPD_FORCE_ROAMING,		ACTION_FORCE_ROAMING,		1,		FORCE_ROAMING },
	{ EID_HTTPD_REBOOT,			ACTION_REBOOT,			1,		REBOOT_CTL  },
	{ 0,	0, 0, 0 }
};

int cm_actReboot(json_object *dataObj);
int cm_actReReconnect(json_object *dataObj);
int cm_actForceRomaing(json_object *dataObj);

struct actionHandler_s actionHandlers[] = {
	{ ACTION_RE_RECONNECT,		cm_actReReconnect },
	{ ACTION_FORCE_ROAMING,		cm_actForceRomaing },
	{ ACTION_REBOOT,			cm_actReboot },
	{ 0,		NULL }
};

/*
========================================================================
Routine Description:
	Find action related information.

Arguments:
	eid		- event id
	action		- action
	capAction		- cap can do action
	capType		- capability type

Return Value:
	0		- not found
	1		- found

Note:
========================================================================
*/
int cm_findActionInfo(int eid, int *action, int *capAction, int *capType)
{
	struct action_s *pAction = NULL;
	int ret = 0;

	for (pAction = &action_list[0]; pAction->event_id > EID_HTTPD_NONE; pAction++) {
		if (eid == pAction->event_id) {
			ret = 1;
			*action = pAction->action;
			*capAction = pAction->cap_action;
			*capType =  pAction->cap_type;
			break;
		}
	}

	return ret;
} /* End of cm_findActionInfo */

/*
========================================================================
Routine Description:
	Do action from CAP notify.

Arguments:
	msg		- decrypted message

Return Value:
	None

========================================================================
*/
void cm_actionHandler(unsigned char *msg)
{
	json_object *root = NULL, *actionObj = NULL, *dataObj = NULL;
	struct actionHandler_s *handler = NULL;
	int action = ACTION_NONE;

	root = json_tokener_parse((char *)msg);
	if (root == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(root, CFG_ACTION_ID, &actionObj);
	json_object_object_get_ex(root, CFG_DATA, &dataObj);
	if (actionObj && dataObj) {
		action = json_object_get_int(actionObj);
		for (handler = &actionHandlers[0]; handler->action > ACTION_NONE; handler++) {
			if (action == handler->action) {
				handler->func(dataObj);
				break;
			}
		}
	}

	json_object_put(root);
} /* End of cm_actionHandler */

/*
========================================================================
Routine Description:
	Action for reboot.

Arguments:
	dataObj		- data for action

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
int cm_actReboot(json_object *dataObj)
{
	notify_rc("reboot");

	return 1;
} /* End of cm_actReboot */

/*
========================================================================
Routine Description:
	Action for re reconnect.

Arguments:
	dataObj		- data for action

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
int cm_actReReconnect(json_object *dataObj)
{
	notify_rc("restart_wireless");
	cm_setStatePending();
	return 1;
} /* End of cm_actReReconnect */

/*
========================================================================
Routine Description:
	Action for sta force roaming.

Arguments:
	data		- data for action

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
int cm_actForceRomaing(json_object *dataObj)
{
	char buf[512] = {0};
	json_object *staObj = NULL, *blockTimeObj = NULL, *targetApObj = NULL;
	int ret = 0;
	char value[128];

	if (dataObj == NULL) {
		DBG_ERR("dataObj is NULL");
		return 0;
	}

	json_object_object_get_ex(dataObj, CFG_STR_STA, &staObj);
	json_object_object_get_ex(dataObj, CFG_BLOCK_TIME, &blockTimeObj);
	json_object_object_get_ex(dataObj, CFG_TARGET_AP, &targetApObj);
	if (staObj) {
		strlcat(buf, "{", sizeof(buf));
		memset(value, 0, sizeof(value));
		snprintf(value, sizeof(value), "\"%s\":{\"%s\":\"%d\",\"%s\":\"%s\"",
			CFG_PREFIX, RAST_EVENT_ID, EID_RM_STA_FORCE_ROAMING, RAST_STA, json_object_get_string(staObj));
		strlcat(buf, value, sizeof(buf));
		if (blockTimeObj) {
			memset(value, 0, sizeof(value));
			snprintf(value, sizeof(value), ",\"%s\":%s",
				RAST_BLOCK_TIME, json_object_get_string(blockTimeObj));
			strlcat(buf, value, sizeof(buf));
		}

		if (targetApObj) {
			memset(value, 0, sizeof(value));
			snprintf(value, sizeof(value), ",\"%s\":\"%s\"",
				RAST_AP_TARGET_MAC, json_object_get_string(targetApObj));
			strlcat(buf, value, sizeof(buf));
		}
		strlcat(buf, "}}", sizeof(buf));

		DBG_INFO("data of force roaming sta (%s) for roamast", buf);
		cm_sendEventToRast((unsigned char *)&buf[0]);  /* send force roaming event to rast */
		ret = 1;
	}

	return ret;
} /* End of cm_actForceRomaing */
