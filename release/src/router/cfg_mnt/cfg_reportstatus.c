#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/shm.h>
#include <shared.h>
#include <shutils.h>
#include <json.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_slavelist.h"
#include "cfg_wevent.h"
#include "cfg_clientlist.h"

#define CFGMNT_FILE		TEMP_ROOT_PATH"/cfgmnt_log.txt"

/*
========================================================================
Routine Description:
	Report status for master/slave.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_reportStatus()
{
	int shm_client_tbl_id;
	P_CM_CLIENT_TABLE p_client_tbl;
	void *shared_client_info=(void *) 0;
	int i = 0;
	int j = 0;
	int master = 0;
	json_object *statusObj = json_object_new_object();
	json_object *wifiClientObj = NULL, *wiredClientObj = NULL;

	if (!statusObj) {
		DBG_ERR("statusObj is null");
		goto err;
	}

	DBG_INFO("start to report status");

#ifdef MASTER_DET
	master = nvram_get_int("cfg_master");
#else
	if (is_router_mode())
		master =1;
#endif

	json_object_object_add(statusObj, "role", master ? json_object_new_string("master"): json_object_new_string("slave"));
	json_object_object_add(statusObj, CFG_STR_MAC, json_object_new_string(get_unique_mac()));
	//json_object_object_add(statusObj, CFG_STR_GROUPID, json_object_new_string(nvram_safe_get("cfg_group")));

	/* for master */
	if (master) {
		int lock = 0;
		char ip_buf[16] = {0};
		char alias_buf[33] = {0};
		char rmac_buf[18] = {0};
		char ap2g_buf[18], ap5g_buf[18], ap5g1_buf[18], ap6g_buf[18];
		char pap2g_buf[18], pap5g_buf[18], pap6g_buf[18];
		char rssi2g_buf[8], rssi5g_buf[8], rssi6g_buf[8];
		char model_name_buf[33] = {0}, product_id_buf[33] = {0}, frs_model_name_buf[33] = {0};
		char fwver_buf[33] = {0};
		char newfwver_buf[33] = {0};
		char re_mac_filename[64] = {0};
		char capability_filename[64] = {0};
		char plc_status_filename[64] = {0};
		char misc_info_filename[64] = {0};
		char wired_port_filename[64] = {0};
		char lldp_wlc_stat[LLDP_STAT_LEN] = {};
		char lldp_eth_stat[LLDP_STAT_LEN] = {};
		json_object *clientObj = NULL;
		json_object *clientArrayObj = json_object_new_array();;
		json_object *allBrMacListObj = NULL;
		json_object *macEntryObj = NULL;
		json_object *macArrayObj = NULL;
		json_object *entryObj = NULL;
		json_object *reMacFileObj = NULL;
		json_object *reMacMiscObj = NULL;
		json_object *reMacMiscCfgAlias = NULL;
		json_object *capabilityObj = NULL;
		json_object *plcStatusObj = NULL;
		json_object *miscInfoObj = NULL;
		json_object *wiredPortObj = NULL;
		int online = 0;
		int level = 0;
		int rePath = 0;
		int bandNum = 0;

		/* for maste/slave list */
		lock = file_lock(CFG_FILE_LOCK);
		shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
		if (shm_client_tbl_id == -1){
			DBG_ERR("shmget failed");
			file_unlock(lock);
			goto err;
		}

		shared_client_info = shmat(shm_client_tbl_id,(void *) 0,0);
		if (shared_client_info == (void *)-1){
			DBG_ERR("shmat failed");
			file_unlock(lock);
			goto err;
		}

		if (f_exists(MAC_LIST_JSON_FILE))
			allBrMacListObj = json_object_from_file(MAC_LIST_JSON_FILE);

		p_client_tbl = (P_CM_CLIENT_TABLE)shared_client_info;

		DBG_INFO("add status for client list");
		for(i = 0; i < p_client_tbl->count; i++) {
			memset(alias_buf, 0, sizeof(alias_buf));
			memset(ip_buf, 0, sizeof(ip_buf));
			memset(rmac_buf, 0, sizeof(rmac_buf));
			memset(ap2g_buf, 0, sizeof(ap2g_buf));
			memset(ap5g_buf, 0, sizeof(ap5g_buf));
			memset(ap5g1_buf, 0, sizeof(ap5g1_buf));
			memset(ap6g_buf, 0, sizeof(ap6g_buf));
			memset(pap2g_buf, 0, sizeof(pap2g_buf));
			memset(pap5g_buf, 0, sizeof(pap5g_buf));
			memset(pap6g_buf, 0, sizeof(pap6g_buf));
			memset(rssi2g_buf, 0, sizeof(rssi2g_buf));
			memset(rssi5g_buf, 0, sizeof(rssi5g_buf));
			memset(rssi6g_buf, 0, sizeof(rssi6g_buf));
			memset(re_mac_filename, 0, sizeof(re_mac_filename));
			memset(capability_filename, 0, sizeof(capability_filename));
			memset(plc_status_filename, 0, sizeof(plc_status_filename));
			memset(misc_info_filename, 0, sizeof(misc_info_filename));
			memset(wired_port_filename, 0, sizeof(wired_port_filename));
			macArrayObj = json_object_new_array();
			wiredPortObj = NULL;

			if (i == 0) /* master */
				snprintf(alias_buf, sizeof(alias_buf), "%s", nvram_safe_get("cfg_alias"));
			else
				snprintf(alias_buf, sizeof(alias_buf), "%s", p_client_tbl->alias[i]);

			snprintf(ip_buf, sizeof(ip_buf), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0], p_client_tbl->ipAddr[i][1],
				p_client_tbl->ipAddr[i][2], p_client_tbl->ipAddr[i][3]);

			snprintf(rmac_buf, sizeof(rmac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
				p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
				p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

			if (p_client_tbl->rssi2g[i] != 0) {
				snprintf(pap2g_buf, sizeof(pap2g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->pap2g[i][0], p_client_tbl->pap2g[i][1],
					p_client_tbl->pap2g[i][2], p_client_tbl->pap2g[i][3],
					p_client_tbl->pap2g[i][4], p_client_tbl->pap2g[i][5]);
				snprintf(rssi2g_buf, sizeof(rssi2g_buf), "%d", p_client_tbl->rssi2g[i]);
			}

			if (p_client_tbl->rssi5g[i] != 0) {
				snprintf(pap5g_buf, sizeof(pap5g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->pap5g[i][0], p_client_tbl->pap5g[i][1],
					p_client_tbl->pap5g[i][2], p_client_tbl->pap5g[i][3],
					p_client_tbl->pap5g[i][4], p_client_tbl->pap5g[i][5]);
				snprintf(rssi5g_buf, sizeof(rssi5g_buf), "%d", p_client_tbl->rssi5g[i]);
			}

			if (p_client_tbl->rssi6g[i] != 0) {
				snprintf(pap6g_buf, sizeof(pap6g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->pap6g[i][0], p_client_tbl->pap6g[i][1],
					p_client_tbl->pap6g[i][2], p_client_tbl->pap6g[i][3],
					p_client_tbl->pap6g[i][4], p_client_tbl->pap6g[i][5]);
				snprintf(rssi6g_buf, sizeof(rssi6g_buf), "%d", p_client_tbl->rssi6g[i]);
			}

			snprintf(ap2g_buf, sizeof(ap2g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap2g[i][0], p_client_tbl->ap2g[i][1],
				p_client_tbl->ap2g[i][2], p_client_tbl->ap2g[i][3],
				p_client_tbl->ap2g[i][4], p_client_tbl->ap2g[i][5]);

			snprintf(ap5g_buf, sizeof(ap5g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap5g[i][0], p_client_tbl->ap5g[i][1],
				p_client_tbl->ap5g[i][2], p_client_tbl->ap5g[i][3],
				p_client_tbl->ap5g[i][4], p_client_tbl->ap5g[i][5]);

			snprintf(ap5g1_buf, sizeof(ap5g1_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap5g1[i][0], p_client_tbl->ap5g1[i][1],
				p_client_tbl->ap5g1[i][2], p_client_tbl->ap5g1[i][3],
				p_client_tbl->ap5g1[i][4], p_client_tbl->ap5g1[i][5]);

			snprintf(ap6g_buf, sizeof(ap6g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->ap6g[i][0], p_client_tbl->ap6g[i][1],
				p_client_tbl->ap6g[i][2], p_client_tbl->ap6g[i][3],
				p_client_tbl->ap6g[i][4], p_client_tbl->ap6g[i][5]);

			/* modle name */
			snprintf(model_name_buf, sizeof(model_name_buf), "%s", p_client_tbl->modelName[i]);

			/* product id */
			snprintf(product_id_buf, sizeof(product_id_buf), "%s", p_client_tbl->productId[i]);

			/* frs model name */
			snprintf(frs_model_name_buf, sizeof(frs_model_name_buf), "%s", p_client_tbl->frsModelName[i]);

			/* firmware version */
			snprintf(fwver_buf, sizeof(fwver_buf), "%s", p_client_tbl->fwVer[i]);

			/* new firmware version */
			snprintf(newfwver_buf, sizeof(newfwver_buf), "%s", p_client_tbl->newFwVer[i]);

			if (allBrMacListObj) {
				json_object_object_get_ex(allBrMacListObj, rmac_buf, &macEntryObj);
				if (macEntryObj) {
					for (j = 0; j < json_object_array_length(macEntryObj); j++) {
						entryObj = json_object_array_get_idx(macEntryObj, j);
						if (entryObj)
							json_object_array_add(macArrayObj, json_object_new_string(json_object_get_string(entryObj)));
					}
				}
			}

			if (i == 0)	/* DUT info */
				online = 1;
			else
				online = ((int) difftime(time(NULL), p_client_tbl->reportStartTime[i]) < OFFLINE_THRESHOLD) ? 1 : 0;

			/* level */
			level = p_client_tbl->level[i];

			/* re path */
			rePath = p_client_tbl->activePath[i];

			/* band num */
			bandNum = p_client_tbl->bandnum[i];

			/* private config */
			snprintf(re_mac_filename, sizeof(re_mac_filename), TEMP_ROOT_PATH"/%s.json", rmac_buf);
			if (f_exists(re_mac_filename)) {
				if ((reMacFileObj = json_object_from_file(re_mac_filename))) {
					json_object_object_foreach(reMacFileObj, key, val) {
						reMacMiscObj = val;
						json_object_object_del(reMacMiscObj, "action_script"); /* filter unnecessary info */
						json_object_object_get_ex(reMacMiscObj, "cfg_alias", &reMacMiscCfgAlias);
						if (reMacMiscCfgAlias) {
							if (strcmp(json_object_get_string(reMacMiscCfgAlias), "") != 0) {
								memset(alias_buf, 0, sizeof(alias_buf));
								strlcpy(alias_buf, json_object_get_string(reMacMiscCfgAlias), sizeof(alias_buf));
							}
						}
					}
				}
			}

			/* capability */
			snprintf(capability_filename, sizeof(capability_filename), TEMP_ROOT_PATH"/%s.cap", rmac_buf);
			if (f_exists(capability_filename))
				capabilityObj = json_object_from_file(capability_filename);

			/* lldp stat */
			strncpy(lldp_wlc_stat, p_client_tbl->lldp_wlc_stat[i], sizeof(lldp_wlc_stat));
			strncpy(lldp_eth_stat, p_client_tbl->lldp_eth_stat[i], sizeof(lldp_eth_stat));

			/* plc status */
			snprintf(plc_status_filename, sizeof(plc_status_filename), TEMP_ROOT_PATH"/%s.plc", rmac_buf);
			if (f_exists(plc_status_filename))
				plcStatusObj = json_object_from_file(plc_status_filename);

			/* misc info */
			if (i == 0)
				snprintf(misc_info_filename, sizeof(misc_info_filename), "%s", MISC_INFO_JSON_PATH);
			else
				snprintf(misc_info_filename, sizeof(misc_info_filename), TEMP_ROOT_PATH"/%s.misc", rmac_buf);
			if (f_exists(misc_info_filename))
				miscInfoObj = json_object_from_file(misc_info_filename);

			/* wired port */
			snprintf(wired_port_filename, sizeof(wired_port_filename), TEMP_ROOT_PATH"/%s.port", rmac_buf);
			if (f_exists(wired_port_filename))
				wiredPortObj = json_object_from_file(wired_port_filename);

			clientObj = json_object_new_object();
			if (clientObj) {
				if (strlen(alias_buf))
					json_object_object_add(clientObj, CFG_STR_ALIAS, json_object_new_string(alias_buf));
				else
					json_object_object_add(clientObj, CFG_STR_ALIAS, json_object_new_string(rmac_buf));
				json_object_object_add(clientObj, CFG_STR_MODEL_NAME, json_object_new_string(model_name_buf));
				json_object_object_add(clientObj, CFG_STR_PRODUCT_ID, json_object_new_string(product_id_buf));
				json_object_object_add(clientObj, CFG_STR_FRS_MODEL_NAME, json_object_new_string(frs_model_name_buf));
				json_object_object_add(clientObj, CFG_STR_FWVER, json_object_new_string(fwver_buf));
				json_object_object_add(clientObj, CFG_STR_NEW_FWVER, json_object_new_string(newfwver_buf));
				json_object_object_add(clientObj, CFG_STR_IP, json_object_new_string(ip_buf));
				json_object_object_add(clientObj, CFG_STR_MAC, json_object_new_string(rmac_buf));
				json_object_object_add(clientObj, CFG_STR_ONLINE, json_object_new_int(online));
				json_object_object_add(clientObj, CFG_STR_AP2G,
					strcmp(ap2g_buf, "00:00:00:00:00:00") ? json_object_new_string(ap2g_buf):  json_object_new_string(""));
				json_object_object_add(clientObj, CFG_STR_AP5G,
					strcmp(ap5g_buf, "00:00:00:00:00:00") ? json_object_new_string(ap5g_buf):  json_object_new_string(""));
				json_object_object_add(clientObj, CFG_STR_AP5G1,
					strcmp(ap5g1_buf, "00:00:00:00:00:00") ? json_object_new_string(ap5g1_buf):  json_object_new_string(""));
				json_object_object_add(clientObj, CFG_STR_AP6G,
					strcmp(ap6g_buf, "00:00:00:00:00:00") ? json_object_new_string(ap6g_buf):  json_object_new_string(""));
				json_object_object_add(clientObj, CFG_STR_WIRED_MAC, macArrayObj);
				json_object_object_add(clientObj, CFG_STR_PAP2G, json_object_new_string(pap2g_buf));
				json_object_object_add(clientObj, CFG_STR_RSSI2G, json_object_new_string(rssi2g_buf));
				json_object_object_add(clientObj, CFG_STR_PAP5G, json_object_new_string(pap5g_buf));
				json_object_object_add(clientObj, CFG_STR_RSSI5G, json_object_new_string(rssi5g_buf));
				json_object_object_add(clientObj, CFG_STR_PAP6G, json_object_new_string(pap6g_buf));
				json_object_object_add(clientObj, CFG_STR_RSSI6G, json_object_new_string(rssi6g_buf));
				json_object_object_add(clientObj, CFG_STR_LEVEL, json_object_new_int(level));
				json_object_object_add(clientObj, CFG_STR_PATH, json_object_new_int(rePath));
				if (reMacFileObj)
					json_object_object_add(clientObj, CFG_STR_CONFIG, reMacFileObj);
				else
					json_object_object_add(clientObj, CFG_STR_CONFIG, json_object_new_string(""));

				if (capabilityObj)
					json_object_object_add(clientObj, CFG_STR_CAPABILITY, capabilityObj);
				else
					json_object_object_add(clientObj, CFG_STR_CAPABILITY, json_object_new_string("{}"));

				json_object_object_add(clientObj, CFG_STR_WLC_LLDP_COST_STAT, json_object_new_string(lldp_wlc_stat));
				json_object_object_add(clientObj, CFG_STR_ETH_LLDP_COST_STAT, json_object_new_string(lldp_eth_stat));
				json_object_object_add(clientObj, CFG_STR_BAND_NUM, json_object_new_int(bandNum));

				if (plcStatusObj)
					json_object_object_add(clientObj, CFG_STR_PLC_STATUS, plcStatusObj);

				if (miscInfoObj)
					json_object_object_add(clientObj, CFG_STR_MISC_INFO, miscInfoObj);
				else
					json_object_object_add(clientObj, CFG_STR_MISC_INFO, json_object_new_string(""));

				if (wiredPortObj)
					json_object_object_add(clientObj, CFG_STR_WIRED_PORT, wiredPortObj);
				else
					json_object_object_add(clientObj, CFG_STR_WIRED_PORT, json_object_new_string(""));

				json_object_array_add(clientArrayObj, clientObj);
			}
			else
				json_object_put(reMacFileObj);
		}

		json_object_object_add(statusObj, "client_list", clientArrayObj);
		shmdt(shared_client_info);
		json_object_put(allBrMacListObj);
		file_unlock(lock);

		/* for wireless cleint list */
		lock = file_lock(ALLWEVENT_FILE_LOCK);
		if ((wifiClientObj = json_object_from_file(ALLWCLIENT_LIST_JSON_PATH)))
			json_object_object_add(statusObj, "wclient_list", wifiClientObj);
		file_unlock(lock);

		/* for wired client list */
		lock = file_lock(WIREDCLIENTLIST_FILE_LOCK);
		if ((wiredClientObj = json_object_from_file(WIRED_CLIENT_LIST_JSON_PATH)))
			json_object_object_add(statusObj, "wired_client_list", wiredClientObj);
		file_unlock(lock);
	}
	else		/* for slave */
	{
		//TODO
	}

	json_object_to_file(CFGMNT_FILE, statusObj);

err:
	json_object_put(statusObj);
}

/*
========================================================================
Routine Description:
	User space main function.

Arguments:
	argc		- argument number
	*pArgv[]	- arguments

Return Value:
	0		- exit daemon
	-1		- fork fail

Note:
========================================================================
*/
int main(int argc, char *pArgv[])
{
#ifdef RTCONFIG_SW_HW_AUTH
	/* auth check for daemon */
	if (!check_auth()) {
		DBG_ERR("auth check failed, exit");
		goto err;
	}
	else
		DBG_INFO("auth check success");
#endif	/* RTCONFIG_SW_HW_AUTH */

#ifdef MASTER_DET
	if (((nvram_get_int("cfg_master") == 1) && (is_router_mode() || access_point_mode())) ||
		(nvram_get_int("cfg_master") == 0 && nvram_get_int("re_mode") == 1))
		DBG_ERR("need to prepare info.");
	else
	{
		DBG_ERR("don't need to prepare info.");
		goto err;
	}
#endif

	cm_reportStatus();

err:

	return 0;
}
