/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <wlutils.h>
#include <shutils.h>
#include <shared.h>
#include <wlioctl.h>
#include <rc.h>


#if defined(RTCONFIG_AMAS)
#include <json.h>
#include <amas_ssd.h>
#include <amas_ipc.h>
#include <encrypt.h>

#include <wlscan.h>
#include <bcmendian.h>

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID	"33716237"
#define APP_KEY	"g2hkhuig238789ajkhc"
#endif

#if defined(RTCONFIG_AMAS_WDS)
#include <json.h>
#include <cfg_event.h>
#endif

#define ID_LEN		20
#define SHAR256_KEY_LEN	16

extern int str2hex(const char *str, unsigned char *data, size_t size);
static void close_ipc_socket();
static void ipc_event_handler(char *event);
static int amas_ssd_start_site_survey(int unit, ssid_list_t *ssid_list);
void amas_ssd_stop_site_survey();
static void amas_ssd_signal_handler(int sig);

int ssd_msglevel = 0; //OBD_DEBUG_ERROR | OBD_DEBUG_INFO | OBD_DEBUG_EVENT | OBD_DEBUG_DETAIL;

int ipc_socket = -1;		/* socket for IPC */
int *child_pid = NULL;		/* child pid for band supported */
static int wlif_count = 0;		/* count for band supported */
int cancel_site_survey = 0;		/* for stop site survey or not */
int ss_count[8] = {0}; /* for number of sitesurvey. Allocate 4 for 2.4G/5G/5G1, others is reserve. */

static void free_site_survey_result(site_survey_result_t *list) {
	site_survey_result_t *tmp;
	while(list) {
		tmp = list->next;
		free(list);
		list = tmp;
	}
}

static int open_ipc_socket()
{
	struct sockaddr_un sock_addr_ipc;

	/* IPC Socket */
	if ((ipc_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		SSD_ERROR("failed to IPC socket create!\n");
		goto err;
	}

	memset(&sock_addr_ipc, 0, sizeof(sock_addr_ipc));
	sock_addr_ipc.sun_family = AF_UNIX;
	snprintf(sock_addr_ipc.sun_path, sizeof(sock_addr_ipc.sun_path), "%s", AMAS_SSD_IPC_SOCKET_PATH);
	unlink(AMAS_SSD_IPC_SOCKET_PATH);

	if (bind(ipc_socket, (struct sockaddr*)&sock_addr_ipc, sizeof(sock_addr_ipc)) < -1) {
		SSD_ERROR("failed to IPC socket bind!\n");
		goto err;
	}

	if (listen(ipc_socket, AMAS_SSD_IPC_MAX_CONNECTION) == -1) {
		SSD_ERROR("failed to IPC socket listen!\n");
		goto err;
	}

	return 1;

err:

	close_ipc_socket();
	return 0;
}

static void close_ipc_socket()
{
	if (ipc_socket >= 0)
		close(ipc_socket);
}

static void ipc_receive_handler()
{
	int sockfd = -1;
	char buf[512];

	/* accept socket */
	sockfd = accept(ipc_socket, NULL, NULL);
	if (sockfd < 0) {
		SSD_ERROR("failed to socket accept()!\n");
		return;
	}

	/* read socket */
	if (read_msg_from_ipc_socket(sockfd, buf, sizeof(buf), "Received", 3000) < 0) {
		SSD_DBG("read socket error!\n");
		return;
	}

	ipc_event_handler(&buf[0]);
}

static void
gen_ssid_list(json_object *ssid_list_obj, ssid_list_t *ssid_list)
{
	int i = 0, ssid_list_len = 0;
	json_object *ssid_entry = NULL;

	if (ssid_list_obj) {
		ssid_list_len = json_object_array_length(ssid_list_obj);

		for (i = 0; i < ssid_list_len; i++) {
			ssid_entry = json_object_array_get_idx(ssid_list_obj, i);

			if (ssid_entry) {
				snprintf(ssid_list->ssid[ssid_list->ssid_count], SSID_LEN, "%s",
						(char *)json_object_get_string(ssid_entry));
				ssid_list->ssid_count++;
			}
		}
	}
}

static void ipc_event_handler(char *event)
{
	json_object *root = json_tokener_parse(event);
	json_object *event_obj = NULL, *unit_obj = NULL, *ssid_list_obj;
	int pid, event_id = 0, unit = -1;
	ssid_list_t *ssid_list = NULL;

	SSD_DBG("event (%s)\n", event);

	json_object_object_get_ex(root, SSD_STR_EVENT_ID, &event_obj);
	json_object_object_get_ex(root, SSD_STR_BAND_UNIT, &unit_obj);
	json_object_object_get_ex(root, SSD_STR_SSID_LIST, &ssid_list_obj);

	if (event_obj)
		event_id = json_object_get_int(event_obj);

	if (unit_obj)
		unit = json_object_get_int(unit_obj);

	/* check unit */
	if (unit < 0 || unit > wlif_count) {
		SSD_ERROR("unit (%d) is invalid\n", unit);
		return;
	}

	if (event_id == SS_EVENT_START && ssid_list_obj &&
		json_object_is_type(ssid_list_obj, json_type_array))
	{
		if ((ssid_list = (ssid_list_t *)malloc(sizeof(ssid_list_t))) != NULL) {
			memset(ssid_list, 0, sizeof(ssid_list_t));
			gen_ssid_list(ssid_list_obj, ssid_list);
			SSD_DBG("unit(%d) - ssid count (%d)\n", unit, ssid_list->ssid_count);
		}
		else
		{
			SSD_ERROR("unit(%d) - ssid_lst is NULL\n", unit);
			return;
		}
	}

	json_object_put(root);

	/* event for start site survey */
	if (event_id == SS_EVENT_START && unit >= 0) {
		if ((pid = fork()) < 0) {
			SSD_ERROR("fork fail\n");
			return;
		} else {
			if (pid == 0) {	/* child */
				close(ipc_socket);
				ipc_socket = -1;

				/* reset signal */
				signal(SIGUSR1, amas_ssd_signal_handler);

				/* do site survey */
				amas_ssd_start_site_survey(unit, ssid_list);

				exit(0);
			}
			else		/* parent */
			{
				/* record child pid */
				child_pid[unit] = pid;
				SSD_DBG("child_pid[%d] = %d\n", unit, child_pid[unit]);
				if (ssid_list) free(ssid_list);
			}
		}
	}
	else if (event_id == SS_EVENT_CANCEL && unit >= 0) { 	/* event for cancel site survey */
		SSD_DBG("send SIGUSR1 to child pid (%d)\n", child_pid[unit]);
		kill(child_pid[unit], SIGUSR1);
		child_pid[unit] = 0;
	}
}

static void
update_site_survey_status(int unit, int status)
{
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "amas_wlc%d_", unit);
	SSD_LOG("unit(%d) - change site survey status to %d\n", unit, status);
	nvram_set_int(strcat_r(prefix, "ss_status", tmp), status);
}

static site_survey_result_t *
update_site_sruvey_temp_result(int unit, site_survey_result_t *sst_list, site_survey_result_t *ssr)
{
	site_survey_result_t *sst = NULL, *sst_new = NULL, *sst_cur = NULL;
	int found = 0, rssi = 0, ss_count_tmp = 0;
	char eaddr[18];

	/* serach temp result of site survey and update rssi */
	for (sst = sst_list; sst; sst = sst->next) {
		if (memcmp(&sst->bssid, &ssr->bssid, ETHER_ADDR_LEN) == 0) {
			found = 1;

			/* update rssi and ss count */
			ether_etoa((const unsigned char *) (uint8 *)&sst->bssid, eaddr);
			SSD_LOG("unit(%d) - update entry with bssid (%s)\n", unit, eaddr);
			SSD_LOG("unit(%d) - rssi (before) = %d, ss_count (before) = %d\n", unit, (signed char)sst->rssi, sst->ss_count);
			ss_count_tmp = sst->ss_count;
			sst->ss_count++;
			rssi = ((signed char)sst->rssi * ss_count_tmp + (signed char)ssr->rssi) /sst->ss_count;
			SSD_LOG("unit(%d) - rssi (after) = %d, ss_count (after) = %d\n", unit, rssi, sst->ss_count);
			sst->rssi = (unsigned char)rssi;
			break;
		}

		if (sst->next == NULL)
			sst_cur = sst;
	}

	if (!found) {
		if ((sst_new = malloc(sizeof(site_survey_result_t))) != NULL) {
			ether_etoa((const unsigned char *) (uint8 *)&ssr->bssid, eaddr);
			SSD_LOG("unit(%d) - add new entry with bssid (%s)\n", unit, eaddr);
			memset(sst_new, 0, sizeof(site_survey_result_t));
			memcpy(sst_new, ssr, sizeof(site_survey_result_t));
			sst_new->next = NULL;
			sst_new->ss_count++;

			if (sst_cur)
				sst_cur->next = sst_new;
			sst_cur = sst_new;

			if (sst_list == NULL)
				sst_list = sst_new;
		}
	}

	return sst_list;
}

static int validate_site_survey_result_by_ssid(int unit, char *ssid, ssid_list_t *ssid_list)
{
	int i = 0, valid = 0;

	for (i = 0; i < ssid_list->ssid_count; i++) {
		if (strcmp(ssid, ssid_list->ssid[i]) == 0) {
			SSD_DBG("unit(%d) - valid ssid (%s)\n", unit, ssid_list->ssid[i]);
			valid = 1;
			break;
		}
	}

	return valid;
}

static site_survey_result_t *
do_site_survey_by_unit(int unit, ssid_list_t *ssid_list)
{
	site_survey_result_t *ssr_list = NULL, *ssr = NULL, *sst_list = NULL;
	int i = 0;
	char eaddr[18];
	char prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "amas_wlc%d_", unit);

	update_site_survey_status(unit, SS_STATUS_EXECUTING);
	SSD_LOG("unit(%d) - the count of site survey is %d\n", unit, ss_count[unit]);

	/* based on the count of site survey */
	for (i = 0; i < ss_count[unit]; i++) {
		if (cancel_site_survey) {
			SSD_LOG("unit(%d) - cancel site survey\n", unit);
			break;
		}

		SSD_LOG("unit(%d) - #%d site survey\n", unit, i + 1);

		if ((ssr_list = do_site_survey(get_unit_by_wlc_bandindex(unit), ssid_list)) == NULL)
			continue;

		for (ssr = ssr_list; ssr; ssr = ssr->next) {
			ether_etoa((const unsigned char *) (uint8 *)&ssr->bssid, eaddr);
			SSD_LOG("unit(%d) - bssid=%s, rssi=%d, vsie_len=%d, ssid=%s, ssid_len=%d, channel=%d, bandwidth=%d\n",
				unit, eaddr, (signed char)ssr->rssi, ssr->vsie_len, ssr->ssid, ssr->ssid_len, ssr->channel, ssr->bw);
			if (validate_site_survey_result_by_ssid(unit, (char *)&ssr->ssid[0], ssid_list) == 0) {
				SSD_LOG("unit(%d) - invalid ssid (%s) of site survey result\n", unit, ssr->ssid);
				continue;
			}

			sst_list = update_site_sruvey_temp_result(unit, sst_list, ssr);
		}

		free_site_survey_result(ssr_list);
	}

	if (ssid_list) free(ssid_list);
	
	return sst_list;
}

#if 0
static int
check_ap_backward_compatible(int unit, site_survey_result_t *sst_list)
{
	site_survey_result_t *sst = NULL;
	int backward = 0;
	
	/* check vsie of each ap exist or not, if not, backward to old */
	for (sst = sst_list; sst; sst = sst->next) {
		if (sst->vsie_len == 0) {
			backward = 1;
			break;
		}
	}

	if (backward)
		SSD_LOG("unit(%d) - need to backward compatible\n", unit);
	else
		SSD_LOG("unit(%d) - don't need to backward compatible\n", unit);

	return backward;
}
#endif

unsigned char *gen_group_id(int ts)
{
	unsigned char hex_id[16] = {0};
	char id[33] = {0};
	unsigned char *out_id = NULL, *sha256Key = NULL;
	size_t sha256KeyLen = 0;
	int i = 0;

	snprintf(id, sizeof(id), "%s", nvram_safe_get("cfg_group"));
	SSD_INFO("timestamp(%d, %04X)\n", ts, ts);

	if (str2hex(id, hex_id, strlen(id))) {
		/* each 4 bytes of hexId & (And) timestamp */
		for (i = 0; i < sizeof(hex_id); i += 4) {
			hex_id[i] = hex_id[i] & ts >> 24;
			hex_id[i+1] = hex_id[i+1] & ts >> 16;
			hex_id[i+2] = hex_id[i+2] & ts >> 8;
			hex_id[i+3] = hex_id[i+3] & ts;

			SSD_DBG("%02X%02X%02X%02X\n", hex_id[i], hex_id[i+1], hex_id[i+2], hex_id[i+3]);
		}
		
		if ((sha256Key = gen_sha256_key(hex_id, sizeof(hex_id), &sha256KeyLen)) == NULL) {
			SSD_ERROR("gen sha256 key failed\n");
			return NULL;
		}

		if ((out_id = (unsigned char *)malloc(ID_LEN)) == NULL) {
			SSD_ERROR("malloc failed\n");
			free(sha256Key);
			return NULL;
		}
		
		memcpy(out_id, sha256Key, SHAR256_KEY_LEN);
		out_id[SHAR256_KEY_LEN] = (unsigned char)(ts >> 24);
		out_id[SHAR256_KEY_LEN + 1] = (unsigned char)(ts >> 16);
		out_id[SHAR256_KEY_LEN + 2] = (unsigned char)(ts >> 8);
		out_id[SHAR256_KEY_LEN + 3] = (unsigned char)ts;

		free(sha256Key);
	}
	
	return out_id;
}

static unsigned char *
extract_data_from_vsie(uint8 *hex_data, int hex_data_len, int vsie_type, int *hex_len)
{
	unsigned char *data = NULL, *pdata = NULL;
	int i = 0, type = 0, len = 0; 

	pdata = hex_data;

	for (i = 0; i < hex_data_len; ) {
		type = (int)hex_data[i++];
		len = (int)hex_data[i++];
		pdata += 2;
		if (type == vsie_type) {
			SSD_INFO("type(%d), len(%d)\n", type, len);
			if ((data = (unsigned char *)malloc(len + 1)) != NULL) {
				memset(data, 0, len + 1);
				memcpy(data, pdata, len);
				*hex_len = len;
				break;
			}
		}
		i += len;
		pdata += len;
	}

	return data;
}

static void
save_site_survey_result(int unit, site_survey_result_t *sso_list)
{
	site_survey_result_t *sso = NULL;
	char bssid[18], file_path[64];
	json_object *file_obj = NULL, *ap_obj = NULL;
	unsigned char *hex_cost = NULL, *hex_last_byte = NULL, *hex_cap_role = NULL, *hex_infType = NULL;
	int vsie_type_len = 0;
	unsigned char cost, byte_buf, cap_role, infType;
	int i = 0;
#if defined(RTCONFIG_AMAS_WDS)
	unsigned char *hex_wds=NULL;
	unsigned char wds_capab;

#endif	

	if ((file_obj = json_object_new_object()) == NULL) {
		SSD_ERROR("unit(%d) - file_obj s NULL\n", unit);
		return;
	}
	
	for (sso = sso_list; sso; sso = sso->next) {
		if ((ap_obj = json_object_new_object())) {
			memset(bssid, 0, sizeof(bssid));
			ether_etoa((const unsigned char *) (uint8 *)&sso->bssid, bssid);
			SSD_LOG("unit(%d) - bssid=%s, rssi=%d, vsie_len=%d, ssid=%s, ssid_len=%d, channel=%d, bandwidth=%d\n",
				unit, bssid, (signed char)sso->rssi, sso->vsie_len, sso->ssid, sso->ssid_len, sso->channel, sso->bw);

			json_object_object_add(ap_obj, SSD_STR_SSID, json_object_new_string((char *)sso->ssid));
			json_object_object_add(ap_obj, SSD_STR_RSSI, json_object_new_int((signed char)sso->rssi));
			json_object_object_add(ap_obj, SSD_STR_CHANNEL, json_object_new_int(sso->channel));
			json_object_object_add(ap_obj, SSD_STR_BANDWIDTH, json_object_new_int(sso->bw));

			if (sso->vsie_len) {
				hex_cost = extract_data_from_vsie(sso->vsie, sso->vsie_len, VSIE_TYPE_COST, &vsie_type_len);
				if (hex_cost && vsie_type_len == ONE_BYTE_VSIE_TYPE) {	/* cost, 1 byte */
					cost = (unsigned char)hex_cost[0];
					json_object_object_add(ap_obj, SSD_STR_COST, json_object_new_int(cost));
				}

				hex_last_byte = extract_data_from_vsie(sso->vsie, sso->vsie_len,
										VSIE_TYPE_AP_LAST_BYTE, &vsie_type_len);
				if (hex_last_byte && vsie_type_len <= LEN_VSIE_TYPE_AP_LAST_BYTE) {	/* last byte, dynamic bytes */
					for (i = 0; i < vsie_type_len; i++) {
						byte_buf = (unsigned char)hex_last_byte[i];

						if (i == byte_index_2G)
							json_object_object_add(ap_obj, SSD_STR_2G_LAST_BYTE, json_object_new_int(byte_buf));
						else if (i == byte_index_5G)
							json_object_object_add(ap_obj, SSD_STR_5G_LAST_BYTE, json_object_new_int(byte_buf));
						else if (i == byte_index_5G1)
							json_object_object_add(ap_obj, SSD_STR_5G1_LAST_BYTE, json_object_new_int(byte_buf));
						else if (i == byte_index_6G)
							json_object_object_add(ap_obj, SSD_STR_6G_LAST_BYTE, json_object_new_int(byte_buf));
					}
				}

				hex_cap_role = extract_data_from_vsie(sso->vsie, sso->vsie_len, VSIE_TYPE_CAP_ROLE, &vsie_type_len);
				if (hex_cap_role && vsie_type_len == ONE_BYTE_VSIE_TYPE) {	/* cap role, 1 byte */
					cap_role = (unsigned char)hex_cap_role[0];
					json_object_object_add(ap_obj, SSD_STR_CAP_ROLE, json_object_new_int(cap_role));
				}

				/* VSIE_TYPE_INF_TYPE */
				hex_infType = extract_data_from_vsie(sso->vsie, sso->vsie_len, VSIE_TYPE_INF_TYPE, &vsie_type_len);
				if (hex_infType && vsie_type_len == ONE_BYTE_VSIE_TYPE) {
					for (i = 0; i < vsie_type_len; i++) {
						infType = (unsigned char)hex_infType[0];
						json_object_object_add(ap_obj, "infType", json_object_new_int(infType));
					}
				}

#if defined(RTCONFIG_AMAS_WDS)
				hex_wds = extract_data_from_vsie(sso->vsie, sso->vsie_len, VSIE_TYPE_WDS, &vsie_type_len);
				if (hex_wds && vsie_type_len == ONE_BYTE_VSIE_TYPE) {	/* wds, 1 byte */
					wds_capab = (unsigned char)hex_wds[0];
					json_object_object_add(ap_obj, SSD_STR_WDS, json_object_new_int(wds_capab));
				}
				else
					json_object_object_add(ap_obj, SSD_STR_WDS, json_object_new_int(0));
#endif				
				
			}
#if defined(RTCONFIG_AMAS_WDS)  //if (sso->vsie_len)..
			else //no vsie for aimesh 1.0
					json_object_object_add(ap_obj, SSD_STR_WDS, json_object_new_int(0));
#endif			
			json_object_object_add(file_obj, bssid, ap_obj);
		}
	}

	if (file_obj) {
		snprintf(file_path, sizeof(file_path), SURVEY_RESULT_FILE_NAME, unit);
		SSD_LOG("unit(%d) - save site survey result to %s\n", unit, file_path);
		json_object_to_file(file_path, file_obj);
	}

	json_object_put(file_obj);
}

static void
filter_site_survey_result(int unit, site_survey_result_t *sst_list)
{
	site_survey_result_t *sst = NULL, *sso_list = NULL, *sso_new = NULL, *sso_cur = NULL;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	int vsie_valid = 0;
	unsigned char *vsie_id = NULL, *local_id = NULL;
	char vsie_id_str[41] = {0}, local_id_str[41];
	int vsie_id_len = 0, ts = 0;
	char eaddr[18];

	snprintf(prefix, sizeof(prefix), "amas_wlc%d_", unit);

	/* need to check vsie valid or not based on cfg_group exist or not */
	if (strlen(nvram_safe_get("cfg_group")) > 0
		&& nvram_get_int(strcat_r(prefix, "check_vsie", tmp)))
	{
		for (sst = sst_list; sst; sst = sst->next) {
			vsie_valid = 0;
			if (sst->vsie_len != 0) { // AiMesh 2.0 AP
				vsie_id = extract_data_from_vsie(sst->vsie, sst->vsie_len, VSIE_TYPE_ID, &vsie_id_len);
				if (vsie_id && vsie_id_len == LEN_VSIE_TYPE_ID) {	/* id, 20 bytes */
					ts = vsie_id[vsie_id_len - sizeof(int)] << 24 | vsie_id[vsie_id_len - sizeof(int) + 1] << 16 |
						vsie_id[vsie_id_len - sizeof(int) + 2] << 8 | vsie_id[vsie_id_len - sizeof(int) + 3];	
					local_id = gen_group_id(ts);

					if (hex2str(vsie_id, &vsie_id_str[0], sizeof(vsie_id_str)/2))
						SSD_INFO("unit(%d) - vsie_id_str(%s)\n", unit, vsie_id_str);

					if (hex2str(local_id, &local_id_str[0], sizeof(local_id_str)/2))
						SSD_INFO("unit(%d) - local_id_str(%s)\n", unit, local_id_str);

					if (vsie_id) {
						if (memcmp(vsie_id, local_id, vsie_id_len) == 0)
							vsie_valid = 1;
					}

					if (vsie_id) free(vsie_id);
					if (local_id) free(local_id);
				}

				ether_etoa((const unsigned char *) (uint8 *)&sst->bssid, eaddr);
				SSD_LOG("unit(%d) - check vsie valid (%d) for bssid (%s)\n", unit, vsie_valid, eaddr);
			}

			if (vsie_valid || sst->vsie_len == 0) {	/* update AiMesh 2.0 valid vsie AP or AiMesh 1.0 AP to sso list */
				if ((sso_new = malloc(sizeof(site_survey_result_t))) != NULL) {
					SSD_INFO("unit(%d) - add new entry with bssid (%s)\n", unit, eaddr);
					memset(sso_new, 0, sizeof(site_survey_result_t));
					memcpy(sso_new, sst, sizeof(site_survey_result_t));
					sso_new->next = NULL;

					if (sso_cur)
						sso_cur->next = sso_new;
					sso_cur = sso_new;

					if (sso_list == NULL)
						sso_list = sso_new;
				}
			}
		}

		save_site_survey_result(unit, sso_list);
		free_site_survey_result(sso_list);
	}
	else
	{
		//sso_list = sst_list;
		save_site_survey_result(unit, sst_list);
	}

}

static int
amas_ssd_start_site_survey(int unit, ssid_list_t *ssid_list)
{
	site_survey_result_t *sst_list = NULL, *sst = NULL;
	char eaddr[18];
	char tmp[32], prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "amas_wlc%d_", unit);
	nvram_set_int(strcat_r(prefix, "ss_pid", tmp), getpid());

	SSD_LOG("unit(%d) - start site survey (%d)\n", unit, getpid());
	update_site_survey_status(unit, SS_STATUS_START);
	sst_list = do_site_survey_by_unit(unit, ssid_list);

	for (sst = sst_list; sst; sst = sst->next) {
		ether_etoa((const unsigned char *) (uint8 *)&sst->bssid, eaddr);
		SSD_DBG("unit(%d) - bssid=%s, rssi=%d, vsie_len=%d, ssid=%s, ssid_len=%d, channel=%d, bandwidth=%d, ss_count=%d\n",
			unit, eaddr, (signed char)sst->rssi, sst->vsie_len, sst->ssid, sst->ssid_len, sst->channel, sst->bw, sst->ss_count);
	}

	filter_site_survey_result(unit, sst_list);

	free_site_survey_result(sst_list);

	update_site_survey_status(unit, cancel_site_survey ? SS_STATUS_CANCELED: SS_STATUS_FINISHED);

	return 0;
}

void
amas_ssd_stop_site_survey()
{
	cancel_site_survey = 1;
	SSD_LOG("stop site survey for pid (%d)\n", getpid());
	stop_site_survey();
}

static void
amas_ssd_signal_handler(int sig)
{
	int i = 0;

	if (sig == SIGTERM) {
		/* free */
		if (child_pid) {
			for (i = 0; i < wlif_count; i++) {
				if (child_pid[i] > 1)
					kill(child_pid[i], SIGUSR1);
			}

			free(child_pid);
		}

		/* close socket */
		close_ipc_socket();

		/* remove file */
		remove("/var/run/amas_ssd.pid");

		exit(0);
	}
	else if (sig == SIGUSR1) {
		amas_ssd_stop_site_survey();
	}
}

int amas_ssd_init()
{
	wlif_count = num_of_wl_if();

	/* init socket */
	if (open_ipc_socket(&ipc_socket) == 0) {
		return 0;
	}

	/* init child pid */
	child_pid = (int *)malloc(sizeof(int) * wlif_count);
	if (child_pid == NULL) {
		SSD_DBG("malloc failed for child pid\\n");
		return 0;
	}

	/* init sitesurvey count */
	int i;
	char prefix[] = "wlXXXXXXXXXX_", tmp[32] = {0};
	for (i = 0; i < wlif_count; i++) {
		snprintf(prefix, sizeof(prefix), "amas_wlc%d_", i);
		ss_count[i] = nvram_get_int(strcat_r(prefix, "ss_count", tmp));
		if (ss_count[i] <= 0) ss_count[i] = SSD_SITESURVEY_COUNT;
	}

	return 1;
}

int
amas_ssd_main()
{

#ifdef RTCONFIG_SW_HW_AUTH
    time_t timestamp = time(NULL);
    char in_buf[48];
    char out_buf[65];
    char hw_out_buf[65];
    char *hw_auth_code = NULL;

    if (!(getAmasSupportMode() & AMAS_RE)) {
        dbG("not support RE\n");
        return 0;
    }

    // initial
    memset(in_buf, 0, sizeof(in_buf));
    memset(out_buf, 0, sizeof(out_buf));
    memset(hw_out_buf, 0, sizeof(hw_out_buf));

    // use timestamp + APP_KEY to get auth_code
    snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, APP_KEY);

    hw_auth_code = hw_auth_check(APP_ID, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

    // use timestamp + APP_KEY + APP_ID to get auth_code
    snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, APP_KEY, APP_ID);

    // if check fail, return
    if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
        dbG("This is ASUS router\n");
    }
    else {
        dbG("This is not ASUS router\n");
        return 0;
    }
#else
    dbG("auth check is disabled\n");
    return 0;
#endif

	FILE *fp;
	//sigset_t sigs_to_catch;
	char *val;
	fd_set fdSet;

	/* write pid */
	if ((fp = fopen("/var/run/amas_ssd.pid", "w")) != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* create temp folder */
	if(!check_if_dir_exist(AMAS_FOLDER)) {
		SSD_INFO("create temp folder for amas_ssd (%s)\n", AMAS_FOLDER);
		mkdir(AMAS_FOLDER, 0755);
	}

#ifdef AMAS_JFFS_FOLDER
	/* create jffs folder */
	if(!check_if_dir_exist(AMAS_JFFS_FOLDER)) {
		SSD_INFO("create jffs folder for amas_ssd (%s)\n", AMAS_JFFS_FOLDER);
		mkdir(AMAS_JFFS_FOLDER, 0755);
	}
#endif

	/* init */
	if (amas_ssd_init() == 0)
		goto err;
		
	/* signal */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGTERM, amas_ssd_signal_handler);

	/* debug */
	val = nvram_safe_get("ssd_msglevel");
	if (strcmp(val, ""))
		ssd_msglevel = strtoul(val, NULL, 0);
	
	/* Most of time it goes to sleep */
	/* waiting for any packet */
	while (1) {
		/* must re- FD_SET before each select() */
		FD_ZERO(&fdSet);

		FD_SET(ipc_socket, &fdSet);

		/* must use ipc_socket+1, not ipc_socket */
		if (select(ipc_socket+1, &fdSet, NULL, NULL, NULL) < 0)
			break;

		/* handle packets from IPC */
		if (FD_ISSET(ipc_socket, &fdSet))
			ipc_receive_handler(ipc_socket);
	}

err:

	return 0;
}

#if defined(RTCONFIG_AMAS_WDS)
int get_wds_from_ssd_result(int band,char *ap_mac)
{
	int find = 0;
	char site_survey_file_path[64];
	json_object *root = NULL, *wds_obj = NULL;
	int wds_cap = 0;

	snprintf(site_survey_file_path, sizeof(site_survey_file_path),
		SURVEY_RESULT_FILE_NAME, band);

	//_dprintf("Getting Band(%d) Site Survey result from (%s)\n", band, site_survey_file_path);
	root = json_object_from_file(site_survey_file_path);
	if (!root) {
		_dprintf("wds:root is NULL\n");
		return find; //run extap mode
	}

	json_object_object_foreach(root, key, val) {
		json_object_object_get_ex(val, SSD_STR_WDS, &wds_obj);
		if (wds_obj)
			wds_cap = json_object_get_int(wds_obj);
		if (!strcmp(ap_mac,key) && wds_cap)
			find = 1;
	}
	json_object_put(root);

	return find;
}

#define wds_subtype	"55"
#define wds_oui_info	"66,77,88,99"
void set_wds_lldpd(int wds) //for CAP & RE
{
	char *argv[] = {"lldpcli", "configure", "lldp", "custom-tlv", "oui", "F8,32,E4", "subtype", wds_subtype, "oui-info", wds_oui_info, 0};

	//unset
	eval("lldpcli", "unconfigure", "lldp", "custom-tlv", "oui", "F8,32,E4", "subtype", wds_subtype);
	//set
	if (wds)
		_eval(argv, NULL, 0, NULL);
	//_dprintf("%s lldpd wds-tlv for eth-backhaul.....\n", wds?"Set":"Clear");
}

int detect_wds_lldpd(void)
{
	char buf[2048];
	FILE *fp;
	int len;
	char *pt1;
	char word[64], *next = NULL;

	if (nvram_get_int("re_mode") == 1) {
		foreach (word, nvram_safe_get("eth_ifnames"), next) {
			sprintf(buf, "lldpcli show neighbors ports %s", word);
			fp = popen(buf, "r");
			if (fp) {
				memset(buf, 0, sizeof(buf));
				len = fread(buf, 1, sizeof(buf), fp);
				pclose(fp);
				if (len > 1) {
					buf[len-1] = '\0';
					pt1 = strstr(buf, wds_oui_info);
					if (pt1)
						return 1;
				}
			}
		}
	}

	return 0;
}

void update_beacon(int wds)
{
	char word[64], *next;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		if (wds)
			nvram_set("amas_wds", "1");
		else
			nvram_set("amas_wds", "0");

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_VIF_ONBOARDING)
		set_onboarding_vif_status();
#endif
		send_event_to_cfgmnt(EID_RC_RESTART_WIRELESS);
	}
}

/*
 * option:
 * 0: extap
 * 1: wds
 */
void connect_mode(int option)
{
	int mode;

	switch (option) {
	case 0:
		mode = 0; //disable wds
		break;
	case 1:
		mode = 1;
		break;
	default:
		mode = 0;
	}

	set_wds_lldpd(mode);
	set_apmode(mode);
	set_stamode(mode);
	update_beacon(mode);
	//_dprintf("run %s mode\n", mode?"wds":"extap");
}

static char wds_pap[17] = "00:00:00:00:00:00";
static int wds_eth = -1;
#ifdef RTCONFIG_SPF11_4_QSDK
static int wds_wait = 3;
#endif
int detect_pap_wds(void)
{
	int band;
	char word[64], *next, temp[100];
	char *amas_ifname = nvram_safe_get("amas_ifname");
	char wlc_pap[17];
	int eth_wds_status;

#ifdef RTCONFIG_SPF11_4_QSDK
	if (wds_wait > 0) {
		wds_wait--;
		goto ETH_MODE;
	}
#else
	if (nvram_get_int("cfg_alive") == 0) {
		//_dprintf("RE: cfg_alive=0\n");
		wds_eth = -1;
		goto EXTAP_MODE;
	}
#endif
	if (strlen(amas_ifname)) {
		//eth-backhaul
		if (strstr(nvram_safe_get("eth_ifnames"), amas_ifname)) {
#if 0 //RE detects whether pap has the wds capability.
			eth_wds_status = detect_wds_lldpd(); //1:wds
#else
			eth_wds_status = 1;
#endif
			if (wds_eth != eth_wds_status || wds_eth == -1) {
				connect_mode(eth_wds_status);
				wds_eth = eth_wds_status;
				set_stamode(0); //set extap , for general connect
				strcpy(wds_pap, "00:00:00:00:00:00"); //reset wds_mac
				nvram_set("amas_qca_mode", "2");
			}
			goto ETH_MODE;
		}
		//wifi-backhaul
		else {
			band = 0;
			wds_eth = -1;
			foreach (word, nvram_safe_get("sta_ifnames"), next) {
				if (!strcmp(word, amas_ifname)) {
					memset(temp, 0, sizeof(temp));
					snprintf(temp, sizeof(temp), "amas_wlc%d_pap", band);
					strcpy(wlc_pap, nvram_safe_get(temp));
					if (strcmp(wds_pap, wlc_pap)) { //diff
						//_dprintf("wds-pap:%s   now-pap:%s\n",wds_pap,wlc_pap);
						if (get_wds_from_ssd_result(band, wlc_pap)) {
							strcpy(wds_pap, wlc_pap); //renew wds_mac
							goto WDS_MODE;
						}
						else
							goto EXTAP_MODE;
					}
					else
						goto WDS_MODE;
				}
				band++;
			}
		}
	}
	else {
		//_dprintf("RE: backhaul is not established  => extap\n");
		wds_eth = -1;
		goto EXTAP_MODE;
	}

EXTAP_MODE:
	if (nvram_get_int("amas_qca_mode") != 0) {
		connect_mode(0); //extap mode
		strcpy(wds_pap, "00:00:00:00:00:00"); //reset wds_mac
		nvram_set("amas_qca_mode", "0");
	}
	return 0;
WDS_MODE:
	if (nvram_get_int("amas_qca_mode") != 1) {
		connect_mode(1); //wds mode
		nvram_set("amas_qca_mode", "1");
	}
#ifdef RTCONFIG_SPF11_4_QSDK
	if (nvram_get_int("cfg_alive") == 0) {
		//_dprintf("WDS_MODE: wpa_cli -i sta%d disconnect/reconnect...\n", band);
		set_wpa_cli_cmd(band, "disconnect", 0);
		set_wpa_cli_cmd(band, "reconnect", 0);
		wds_wait = 3;
	}
#endif
	return 0;
ETH_MODE:
	return 0;
}

#endif /* RTCONFIG_AMAS_WDS */
#endif
