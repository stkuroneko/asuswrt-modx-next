#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_centralcontrol.h"
#include "cfg_param.h"

/*
========================================================================
Routine Description:
	Get subfeature name by config parameter name.

Arguments:
	param		- config parameter name

Return Value:
	subfeature name
========================================================================
*/
char *cm_getSubfeatureByParam(char *param)
{
	struct param_mapping_s *pParam = NULL;
	struct subfeature_mapping_s *pSubFeature = NULL;
	static char subft[64];

	memset(subft, 0, sizeof(subft));

	for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
		if (strcmp(pParam->param, param) == 0) {
			for (pSubFeature = &subfeature_mapping_list[0]; pSubFeature->index != 0; pSubFeature++) {
				if (pParam->subfeature == pSubFeature->index) {
					strlcpy(subft, pSubFeature->name, sizeof(subft));
					break;
				}
			}
			break;
		}
	}

	return subft;
} /* End of cm_getSubfeatureByParam */

/*
========================================================================
Routine Description:
	Check subfeature exist in feature list or not.

Arguments:
	ft	- feature name
	ftList		- RE's feature list

Return Value:
	0		- doesn't exist in feature list
	1		- exist in feature list
========================================================================
*/
int cm_existInFeatureList(char *ft, json_object *ftList)
{
	int i = 0, ret = 0, ftListLen = 0;
	json_object *ftEntry = NULL;

	if (!ftList) {
		DBG_INFO("ftList is NULL");
		return 0;
	}

	ftListLen = json_object_array_length(ftList);
	for (i = 0; i < ftListLen; i++) {
		ftEntry = json_object_array_get_idx(ftList, i);
		if (ftEntry && strcmp(ft, json_object_get_string(ftEntry)) == 0) {
			ret = 1;
			break;
		}
	}

	return ret;
} /* End of cm_existInFeatureList */

/*
========================================================================
Routine Description:
	Transform cfg object to array obj.

Arguments:
	cfgObj		- config
	arrayObj		- array object

Return Value:
	-1		- error
	0		- not transform
	1		- transform
========================================================================
*/
int cm_transformCfgToArray(json_object *cfgObj, json_object *arrayObj)
{
	int ret = 0;
	json_object *paramObj = NULL;

	if (!cfgObj) {
		DBG_ERR("cfgObj is NULL");
		return -1;
	}

	if (!arrayObj) {
		DBG_ERR("arrayObj is NULL");
		return -1;
	}

	json_object_object_foreach(cfgObj, cfgKey, cfgVal) {
		paramObj = cfgVal;
		json_object_object_foreach(paramObj, paramKey, paramVal) {
			if (strcmp(paramKey, CFG_ACTION_SCRIPT) == 0)
				continue;
			json_object_array_add(arrayObj, json_object_new_string(paramKey));
			ret = 1;
		}
	}

	return ret;
} /* End of cm_transformCfgToArray */

/*
========================================================================
Routine Description:
	Update changed common config to RE's private config.

Arguments:
	mac			- slave's mac
	param		- changed parameter name

Return Value:
	0               - not upate
	1               - update
========================================================================
*/
int cm_updateCommonConfigToPrivateByMac(char *mac, json_object *cfgObj)
{
	json_object *cfgFileObj = NULL, *paramObj = NULL, *cfgArrayObj = NULL;
	char cfgTmpPath[64] = {0}, cfgMntPath[64] = {0}, param[64], value[128];
	int update = 0;

	snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/%s.json", mac);
	snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", mac);
	cfgFileObj = json_object_from_file(cfgTmpPath);
	cfgArrayObj = json_object_new_array();
	if (cfgFileObj && cfgArrayObj) {
		json_object_object_foreach(cfgObj, cfgKey, cfgVal) {
			memset(param, 0, sizeof(param));
			memset(value, 0, sizeof(value));
			strlcpy(param, cfgKey, sizeof(param));
			strlcpy(value, json_object_get_string(cfgVal), sizeof(value));
			DBG_INFO("param(%s) value(%s)", param, value);

			json_object_object_foreach(cfgFileObj, cfgFileKey, cfgFileVal) {
				json_object_object_get_ex(cfgFileVal, param, &paramObj);
				/* delete matched parameter first and then add new value */
				if (paramObj) {
					json_object_object_del(cfgFileVal, param);
					json_object_object_add(cfgFileVal, param, json_object_new_string(value));
					json_object_array_add(cfgArrayObj, json_object_new_string(param));
					DBG_INFO("update %s=%s", param, value);
					update = 1;
				}
			}
		}
	}

	/* update to file */
	if (update) {
#ifdef PRIVATE_SYNC_COMMON
		json_object_to_file(cfgTmpPath, cfgFileObj);
		json_object_to_file(cfgMntPath, cfgFileObj);
#endif
		cm_updatePrivateRuleByMac(mac, cfgArrayObj, FOLLOW_CAP, RULE_UPDATE);
	}

	json_object_put(cfgFileObj);
	json_object_put(cfgArrayObj);

	return update;
} /* End of cm_updateCommonConfigToPrivateByMac */

/*
========================================================================
Routine Description:
	Update common config to RE's private config if it needed.

Arguments:
	mac		- RE's mac
	ftList		- RE's feature list
	cfgRoot		- json object for config

Return Value:
	-1		- error
	0		- no update
	1		- update
========================================================================
*/
int cm_updateCommonToPrivateConfig(char *mac, unsigned char *ftList, json_object *cfgRoot)
{
	json_object *ftListObj = NULL, *ftObj = NULL, *priFtObj = NULL, *cfgObj = NULL;
	char param[64], subft[64];
	int ftExist = 0, subFtExist = 0, update = 0;

	if (!ftList || strlen((char *)ftList) == 0) {
		DBG_INFO("ftList is NULL or empty");
		return -1;
	}

	if (!cfgRoot) {
		DBG_INFO("cfgRoot is null");
		return -1;
	}

	ftListObj = json_tokener_parse((char *)ftList);
	cfgObj = json_object_new_object();

	if (ftListObj && cfgObj) {
		json_object_object_get_ex(ftListObj, CFG_STR_FEATURE, &ftObj);
		json_object_object_get_ex(ftListObj, CFG_STR_PRIVATE_FEATURE, &priFtObj);

		json_object_object_foreach(cfgRoot, cfgRootKey, cfgRootVal) {
			strlcpy(param, cfgRootKey, sizeof(param));
			ftExist = subFtExist = 0;
			if (strcmp(param, CFG_ACTION_SCRIPT) == 0)
				continue;

			memset(subft, 0, sizeof(subft));
			strlcpy(subft, cm_getSubfeatureByParam(param), sizeof(subft));
			DBG_INFO("subft (%s)", subft);
			if (strlen(subft) > 0) {
				ftExist = cm_existInFeatureList(subft, ftObj);
				if (ftExist) {	/* in common feature list */
					subFtExist = cm_existInFeatureList(subft, priFtObj);
					if (subFtExist) {	/* in private feature list */
						update = 1;
						json_object_object_add(cfgObj, param,
							json_object_new_string(nvram_decrypt_get(param)));
					}
				}
			}
		}

		if (update)
			cm_updateCommonConfigToPrivateByMac(mac, cfgObj);
	}

	if (cfgObj) json_object_put(cfgObj);
	if (ftListObj) json_object_put(ftListObj);

	return update;
} /* End of cm_updateCommonToPrivateConfig */

/*
========================================================================
Routine Description:
	Update RE's private rule.

Arguments:
	mac			- slave's mac
	cfgObj		- config
	follow		- follow rule
	action		- action for rule

Return Value:
	-1		- error
	0		- not upate
	1		- update
========================================================================
*/
int cm_updatePrivateRuleByMac(char *mac, json_object *cfgObj, int follow, int action)
{
	json_object *ruleFileObj = NULL, *cfgEntry = NULL;
	char ruleMntPath[64];
	int update = 0, i = 0, cfgLen = 0;

	if (!cfgObj) {
		DBG_ERR("cfgObj is NULL");
		return -1;
	}

	snprintf(ruleMntPath, sizeof(ruleMntPath), CFG_MNT_FOLDER"%s.rule", mac);
	ruleFileObj = json_object_from_file(ruleMntPath);

	if (ruleFileObj) {
		cfgLen = json_object_array_length(cfgObj);
		for (i = 0; i < cfgLen; i++) {
			if ((cfgEntry = json_object_array_get_idx(cfgObj, i))) {
				json_object_object_del(ruleFileObj, json_object_get_string(cfgEntry));
				if (action == RULE_ADD || action == RULE_UPDATE)
					json_object_object_add(ruleFileObj, json_object_get_string(cfgEntry), json_object_new_int(follow));
				update = 1;
			}
		}
	}
	else
	{
		if ((action == RULE_ADD || action == RULE_UPDATE) &&
			(ruleFileObj = json_object_new_object())) {
			cfgLen = json_object_array_length(cfgObj);
			for (i = 0; i < cfgLen; i++) {
				if ((cfgEntry = json_object_array_get_idx(cfgObj, i))) {
					json_object_object_add(ruleFileObj, json_object_get_string(cfgEntry), json_object_new_int(follow));
					update = 1;
				}
			}
		}
	}

	/* update to file */
	if (update) {
		json_object_to_file(ruleMntPath, ruleFileObj);
	}

	json_object_put(ruleFileObj);

	return update;
} /* End of cm_updatePrivateRuleByMac */

/*
========================================================================
Routine Description:
	Check the parameter of RE (mac) whether follow rule.

Arguments:
	mac			- RE's mac
	param		- parameter name
	rule		- follow rule
	
Return Value:
	-1		- error
	0		- not follow
	1		- follow
========================================================================
*/
int cm_checkParamFollowRule(char *mac, char *param, int rule)
{
	int ret = 0;
	json_object *ruleFileObj = NULL, *ruleObj = NULL;
	char ruleMntPath[64];

	snprintf(ruleMntPath, sizeof(ruleMntPath), CFG_MNT_FOLDER"%s.rule", mac);
	
	if ((ruleFileObj = json_object_from_file(ruleMntPath))) {
		json_object_object_get_ex(ruleFileObj, param, &ruleObj);
		if (ruleObj) {
			if (json_object_get_int(ruleObj) == rule) {
				DBG_INFO("param(%s) match rule(%d) for mac(%s)", param, rule, mac);
				ret = 1;
			}
			else
				DBG_INFO("param(%s) is not match rule(%d) for mac(%s)", param, rule, mac);
		}
		else
			DBG_INFO("no rule on param(%s) for mac", param, mac);

		json_object_put(ruleFileObj);
	}

	return ret;
} /* End of cm_checkParamFollowRule */

/*
========================================================================
Routine Description:
	Update common config.

Arguments:
	
Return Value:
	-1		- error
	0		- not update
	1		- update
========================================================================
*/
int cm_updateCommonConfig()
{
	json_object *cfgFileObj = NULL, *paramObj = NULL, *paramEntry = NULL, *paramListObj = NULL;
	struct param_mapping_s *pParam = NULL;
	char cfgMntPath[64] = {0}, param[32];
	int i = 0, update = 0, paramLen = 0, needDel = 0;

	snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", COMMON_CONFIG);

	if (strlen(cfgMntPath)){
		if (check_if_file_exist(cfgMntPath)) {	/* add/del config if needed */
			cfgFileObj = json_object_from_file(cfgMntPath);
			if (cfgFileObj ) {
				DBG_INFO("check & record parameter for add");
				if ((paramListObj = json_object_new_array())) {
					for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {	
						json_object_object_get_ex(cfgFileObj, pParam->param, &paramObj);
						if (!paramObj) {
							DBG_INFO("new parameter(%s) for add", pParam->param);
							json_object_array_add(paramListObj, json_object_new_string(pParam->param));
						}
					}

					paramLen = json_object_array_length(paramListObj);
					if (paramLen > 0) {
						for (i = 0; i < paramLen; i++) {
							if ((paramEntry = json_object_array_get_idx(paramListObj, i))) {
								strlcpy(param, json_object_get_string(paramEntry), sizeof(param));
								DBG_INFO("add parameter(%s) in cfgFileObj", param);

								/* update from default */
								for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
									if (strcmp(param, pParam->param) == 0) {
										/* need to get default */
										json_object_object_add(cfgFileObj, param, json_object_new_string(pParam->value));
										update = 1;
										break;
									}
								}

								/* update from nvram */
								if (nvram_get(param)) {
									DBG_INFO("update value from nvram for %s", param);
									json_object_object_add(cfgFileObj, param,
										json_object_new_string(nvram_safe_get(param)));
									update = 1;
								}
							}
						}
					}

					json_object_put(paramListObj);
				}

				DBG_INFO("check & record parameter for delete");
				if ((paramListObj = json_object_new_array())) {
					json_object_object_foreach(cfgFileObj, cfgKey, cfgVal) {
						needDel = 1;
						for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
							if (strcmp(cfgKey, pParam->param) == 0) {
								needDel = 0;
								break;
							}
						}

						if (needDel) {
							DBG_INFO("parameter(%s) for delete", cfgKey);
							json_object_array_add(paramListObj, json_object_new_string(cfgKey));
						}
					}

					paramLen = json_object_array_length(paramListObj);
					if (paramLen > 0) {
						for (i = 0; i < paramLen; i++) {
							if ((paramEntry = json_object_array_get_idx(paramListObj, i))) {
								strlcpy(param, json_object_get_string(paramEntry), sizeof(param));
								DBG_INFO("delete parameter(%s) in cfgFileObj", param);
								json_object_object_del(cfgFileObj, param);
								update = 1;
							}
						}
					}

					json_object_put(paramListObj);
				}
			}
		}
		else	/* no common config, need to generate it */
		{
			DBG_INFO("need to generate common config");
			cfgFileObj = json_object_new_object();
			if (cfgFileObj ) {
				for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
					strlcpy(param, pParam->param, sizeof(param));
					/* update from default */
					json_object_object_add(cfgFileObj, param, json_object_new_string(pParam->value));

					/* update from nvram */
					if (nvram_get(param)) {
						json_object_object_add(cfgFileObj, param, json_object_new_string(nvram_safe_get(param)));
						update = 1;
					}
				}
			}
			else
			{
				DBG_ERR("cfgFileObj is NULL");
				update = -1;
			}			
		}
	}
	else
	{
		DBG_ERR("cfgMntPath(%s) is invalid", cfgMntPath);
		return - 1;
	}

	/* update to file */
	if (update) {
		json_object_to_file(cfgMntPath, cfgFileObj);
	}

	json_object_put(cfgFileObj);

	return update;
} /* End of cm_updateCommonConfig */

#ifdef UPDATE_COMMON_CONFIG
/*
========================================================================
Routine Description:
	Update common config to file.

Arguments:
	cfgRoot		- json object for config

Return Value:
	-1		- error
	0		- no update
	1		- update
========================================================================
*/
int cm_updateCommonConfigToFile(json_object *cfgRoot)
{
	json_object *cfgFileObj = NULL, *paramObj = NULL;
	char cfgMntPath[64], param[64];
	int update = 0;
	struct param_mapping_s *pParam = NULL;

	snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", COMMON_CONFIG);
	cfgFileObj = json_object_from_file(cfgMntPath);
	if (cfgFileObj) {
		if (cfgRoot) {	/* update for special based on cfgRoot */
			DBG_INFO("update for special based on cfgRoot");
			json_object_object_foreach(cfgRoot, cfgKey, cfgVal) {
				strlcpy(param, cfgKey, sizeof(param));
				json_object_object_get_ex(cfgFileObj, param, &paramObj);
				if (paramObj) {
					DBG_INFO("update value(%s) for %s", nvram_safe_get(param), param);
					json_object_object_add(cfgFileObj, param,
						json_object_new_string(nvram_safe_get(param)));
					update = 1;
				}
			}
		}
		else	/* update for all */
		{
			DBG_INFO("update for all");
			for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
				strlcpy(param, pParam->param, sizeof(param));
				json_object_object_get_ex(cfgFileObj, param, &paramObj);
				if (paramObj && nvram_get(param) &&
					strcmp(nvram_safe_get(param), json_object_get_string(paramObj)) != 0) {
					DBG_INFO("update value(%s) for %s", nvram_safe_get(param), param);
					json_object_object_add(cfgFileObj, param,
						json_object_new_string(nvram_safe_get(param)));
					update = 1;
				}
			}
		}
	}

	/* update to file */
	if (update) {
		json_object_to_file(cfgMntPath, cfgFileObj);
	}

	json_object_put(cfgFileObj);

	return update;
} /* End of cm_updateCommonConfigToFile */
#endif
