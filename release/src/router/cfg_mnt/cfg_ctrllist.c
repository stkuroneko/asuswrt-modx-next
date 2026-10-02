/*
**	cfg_ctrllist.c
**
**
**
*/
#include <string.h>
#include "cfg_ctrllist.h"

int addCtrlParam(
	struct json_object *cfgRoot, 
	char *feature_name, 
	char *key, 
	char *value, 
	char *rc_services)
{
	struct json_object *outRoot = cfgRoot;
	struct json_object *ctrlObj = NULL;
	struct json_object *featureObj = NULL;
	struct json_object *keyParam = NULL;
	struct json_object *actionScriptObj = NULL;
	
	const char *actionScript = NULL;
	char *buffer = NULL; 
	
	size_t alloc_size = 0;

	int new_ctrlObj = 0;
	int new_featureObj = 0;

	if (!cfgRoot)
		goto cm_addCtrlParam_err;

	if (!feature_name || strlen(feature_name) <= 0)
		goto cm_addCtrlParam_err;

	if (!key || strlen(key) <= 0 || !value || strlen(value) <= 0)
		goto cm_addCtrlParam_err;
	
	json_object_object_get_ex(outRoot, CFG_STR_CONTROL_FEATURE, &ctrlObj);
	if (!ctrlObj) {
		ctrlObj = json_object_new_object();
		if (!ctrlObj)
			goto cm_addCtrlParam_err;
		else
			new_ctrlObj = 1;
	} 

	json_object_object_get_ex(ctrlObj, feature_name, &featureObj);
	if (!featureObj) {
		featureObj = json_object_new_object();
		if (!featureObj)
			goto cm_addCtrlParam_err;
		else
			new_featureObj = 1;		
	}

	json_object_object_get_ex(featureObj, key, &keyParam);
	if (keyParam)
		json_object_object_del(featureObj, key);
	json_object_object_add(featureObj, key, json_object_new_string(value));

	if (rc_services && strlen(rc_services) > 0) {
		json_object_object_get_ex(featureObj, CFG_ACTION_SCRIPT, &actionScriptObj);
		if (actionScriptObj)
			actionScript = json_object_to_json_string(actionScriptObj);
		if (actionScript)
			alloc_size += strlen(actionScript);	
		alloc_size += strlen(rc_services);
		alloc_size += 1; 	// ";"
		
		buffer = (char *)malloc(alloc_size);
		if (!buffer)
			goto cm_addCtrlParam_err;
		
		memset(buffer, 0, alloc_size);
		if (actionScript)
			snprintf(buffer, alloc_size, "%s;%s", actionScript, rc_services);
		else
			snprintf(buffer, alloc_size, "%s", rc_services);
		
		if (actionScriptObj)
			json_object_object_del(featureObj, CFG_ACTION_SCRIPT);
		json_object_object_add(featureObj, CFG_ACTION_SCRIPT, json_object_new_string(buffer));
		free(buffer);
		buffer = NULL;
	}

	if (new_featureObj)
		json_object_object_add(ctrlObj, feature_name, featureObj);

	if (new_ctrlObj)
		json_object_object_add(outRoot, CFG_STR_CONTROL_FEATURE, ctrlObj);
	
	return 0;

cm_addCtrlParam_err:
	if (ctrlObj && new_ctrlObj) json_object_put(ctrlObj);
	if (featureObj && new_featureObj) json_object_put(featureObj);
	if (buffer) free(buffer);
	return -1;
}

void cm_transCtrlParam(
	struct json_object *outRoot)
{
	if (!outRoot)
		return;

#ifdef RTCONFIG_AMAS_WGN
	if (wgn_guest_is_enabled() == 1) {
		addCtrlParam(
			outRoot,
			CFG_STR_WGN_CTRL_FEATURE, 
			CFG_STR_WGN_WO_VLAN, 
			((nvram_get_int("sw_mode")==SW_MODE_ROUTER)?"0":"1"), 
			"restart_wireless"); 
    }
#endif	// RTCONFIG_AMAS_WGN	

	return;	
}

void cm_applyCtrlAction(
	struct json_object *cfgRoot,
	int *cfgChanged,
	char *action_script, 
	size_t action_script_size)
{
	struct json_object *ctrlObj = NULL;
	struct json_object *ftObj = NULL;
	struct json_object *actionScriptObj = NULL;

	int doAction = 0;
		
	char *pch = NULL;
	const char *action = NULL;

	if (!cfgRoot || !cfgChanged || !action_script || action_script_size <= 0)
		return;

	json_object_object_get_ex(cfgRoot, CFG_STR_CONTROL_FEATURE, &ctrlObj);
	if (!ctrlObj)
		return;

	json_object_object_foreach(ctrlObj, key, val) {
		doAction = 0;
		json_object_object_get_ex(ctrlObj, key, &ftObj);
		if (!ftObj)
			continue;
#ifdef RTCONFIG_AMAS_WGN
		if (strncmp(key, CFG_STR_WGN_CTRL_FEATURE, strlen(CFG_STR_WGN_CTRL_FEATURE)))
			continue;
		json_object_object_foreach(ftObj, k, v) {
			if (strncmp(k, CFG_STR_WGN_WO_VLAN, strlen(CFG_STR_WGN_WO_VLAN)))
				continue;
			if (nvram_get_int(CFG_STR_WGN_WO_VLAN) != json_object_get_int(v)) {
				nvram_set_int(CFG_STR_WGN_WO_VLAN, json_object_get_int(v));
				doAction = 1;
			}			
			break;
		}
#endif	// RTCONFIG_AMAS_WGN	
		if (doAction)
			*(cfgChanged) = 1;
		else 
			continue;
		//DBG_INFO(">>>>>MAX<<<<< %s(LINE:%d) --> doAction: %d", __func__, __LINE__, doAction);
		json_object_object_get_ex(ftObj, CFG_ACTION_SCRIPT, &actionScriptObj);
		//DBG_INFO(">>>>>MAX<<<<< %s(LINE:%d) --> actionScriptObj is NULL:%s", __func__, __LINE__, (actionScriptObj==NULL)?"yes":"no");
		if (actionScriptObj) {
			action = json_object_get_string(actionScriptObj);
			//DBG_INFO(">>>>>MAX<<<<< %s(LINE:%d) --> action:%s", __func__, __LINE__, action);
			if (!action)
				continue;
			pch = strtok(action, ";");
			while (pch != NULL) {
				if (!strstr(action_script, pch)) {
					if (strlen(action_script) > 0)
						snprintf(action_script, action_script_size, ";%s", pch);
					else
						snprintf(action_script, action_script_size, "%s", pch);	
				}
				pch = strtok(NULL, ";");
			}
			//DBG_INFO(">>>>>MAX<<<<< %s(LINE:%d) --> action_script:%s", __func__, __LINE__, action_script);
		}
	}

	return;
}

