/*
 * This program is sm_free software; you can redistribute it and/or
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
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <shared.h>
#include <rc.h>
#if defined(RTCONFIG_RALINK)
#include <bcmnvram.h>
#include <ralink.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include  <float.h>
#include  <wlinfo_utils.h>
#ifdef RTCONFIG_WIRELESSREPEATER
#include <ap_priv.h>
#endif
#elif defined(RTCONFIG_QCA)
#include <bcmnvram.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#elif defined(RTCONFIG_ALPINE)
#include <bcmnvram.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#else
#include <wlioctl.h>
#include <bcmendian.h>
#endif
#include <wlutils.h>
#ifdef RTCONFIG_ADV_RAST
#include <sys/un.h>
#include <sys/stat.h>
#include <json.h>
#include <math.h>
#ifdef RTCONFIG_CFGSYNC
#include <cfg_ipc.h>
#endif
#endif
#include <pthread.h>
#include "roamast.h"

#if defined(RTCONFIG_SW_HW_AUTH) && defined(RTCONFIG_AMAS)
#include <auth_common.h>
#define APP_ID    "33716237"
#define APP_KEY   "g2hkhuig238789ajkhc"
#endif

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
extern int check_if_support_kv(int unit, int subunit, rast_sta_info_t *sta);
int rssi_info_gather_method(void);
int is_rssi_method_default_k(void);
#endif

#ifdef RTCONFIG_BCN_RPT
void rast_bcn_rpt_init(void);
#endif

#ifdef RTCONFIG_BTM_11V
int rast_send_11v_req(int bssidx,int vifidx,char *sta_mac, char *candidate_ap_mac);
#endif

#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_get_driver_maclist(int idx,int vidx,char *maclist_buf_local,int buf_size,int *static_macmode);
int rast_check_driver_maclist(char *maclist_buf_local,int static_macmode,struct ether_addr *addr);
int sta_binding_list_check(struct ether_addr *addr);
int sta_roaming_bypass_status_update(int bssidx, int vifidx, struct ether_addr *addr,int action);
void rast_deauth_sta_no_syslog(int bssidx, int vifidx, struct ether_addr *addr);
#endif

void get_sta_rssi_and_apmac_form_json(char *sta,char *rssi,char *apmac);

static uint8 init = 1;
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
static uint8 rast_nonmesh_kvonly = 0;
struct roaming_list_entry *roaming_list=NULL;
pthread_mutex_t roaminglistLock;
void rast_nonmesh_kv_thread_create(void);
static int kv_thread_term = 0;
#endif
#ifdef RTCONFIG_FORCE_ROAMING
pthread_mutex_t forceroaminglistLock;
struct force_roaming_list *fr_head=NULL;
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
struct staapbandbind_sta_list *staapbandbind_sta_list_g=NULL;
int cfg_rejoin_pre=0;
int cfg_rejoin_pre_done=0;
#endif

pthread_mutex_t maclistLock;

static uint8 wlif_count = 0;
static struct itimerval itv;
char* strcat_buf = NULL;
int strcat_buf_length = 256;

#ifdef RTCONFIG_CONNDIAG
static int TYPE_tbl = 1;

static int shm_tg_roaming_tid = 0;
static TG_ROAMING_TABLE *p_tg_roaming_tbl = NULL;

#ifdef KEY_ROAMING_EVENT
static int shm_roaming_tid = 0;
static ROAMING_TABLE *p_roaming_tbl = NULL;
#endif

static void _update_tg_roaming_tbl(int order, char *sta, int band_unit, int sta_rssi, int user_low_rssi, int rssi_cnt, int idle_period, int idle_start);
static void _add_tg_roaming_tbl(char *sta, int band_unit, int sta_rssi, int user_low_rssi, int rssi_cnt, int idle_period, int idle_start);
static void _assign_tg_roaming_tbl(char *sta, int band_unit, int sta_rssi, int user_low_rssi, int rssi_cnt, int idle_period, int idle_start);
static void _del_tg_roaming_tbl(int sig);
static void _wipe_tg_roaming_tbl(int sig);
static void _show_tg_roaming_tbl(int sig);

#ifdef KEY_ROAMING_EVENT
static void _update_roaming_tbl(int order, char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	, const char *present_ap
#endif
#endif	
);
static void _add_roaming_tbl(char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	, const char *present_ap
#endif
#endif
);
static void _assign_roaming_tbl(char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	, const char *present_ap
#endif
#endif	
);
static void _del_roaming_tbl(int sig);
static void _wipe_roaming_tbl(int sig);
static void _show_roaming_tbl(int sig);
#endif
#endif

#ifdef RTCONFIG_ADV_RAST
int alarm_count = 0;
//struct ether_addr* rast_ether_atoe(char *a,struct ether_addr *ret_ea);
pthread_mutex_t roamastBssinfoLock;
static void rast_adv_init();

// maclist
static void rast_add_to_maclist(int bssidx, int vifidx, struct ether_addr *addr
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming_blocktime
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
	,int sta_ap_band_bind_action //0:ignore 1:block 2:unblock
#endif
	);
static void rast_timeout_maclist();

// IPC
static int thread_term = 0;
void rast_ipc_socket_thread(void);
static int rast_Proc_STA_MON(char *data);
static int rast_Proc_CANDIDATE(char *data);
static int rast_Proc_STA_ACL(char *data);
static int rast_Proc_STA_STATIC(char *data);
static int rast_ipc_send_event(const char *ipc_path, char *data);
static int rast_req_stamon(int bssidx, int vifidx, char *sta_mac, int rssi, char *band
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int support_kv,int stamon_or_11k
#endif
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming, int force_roaming_blocktime, char *target
#endif	
	);
static int rast_rsp_stamon(char *sta_mac, int rssi, char *pap_ip, char *pap_mac, char *band, int rssi_criteria
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,char *target_mac
#endif
	);
static int rast_req_candidate(char *sta_mac, char *candidate_ap_mac, char *band
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming_blocktime
#endif
	);
static int rast_event_random_interval();
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
static int rast_Proc_STA_EX_AP_CHECK(char *data);
#endif
#ifdef RTCONFIG_FORCE_ROAMING
static int rast_Proc_STA_FORCE_ROAMING(char *data);
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
static int rast_Proc_STA_BINDING_UPDATE(char *data);
#endif
void rast_deauth_sta(int bssidx, int vifidx, struct ether_addr *addr);
struct eventHandler
{
    int event_id;
    int (*func)(char *data);
};

struct eventHandler CFG_EVENTS[] = {
	{ EID_RM_STA_MON, rast_Proc_STA_MON },		// handle sta monitor request
	{ EID_RM_STA_CANDIDATE, rast_Proc_CANDIDATE },	// handle candidate peer response
	{ EID_RM_STA_ACL, rast_Proc_STA_ACL },		// handle acl request
	{ EID_RM_STA_FILTER, rast_Proc_STA_STATIC },	// handle static sta request
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP	
	{ EID_RM_STA_EX_AP_CHECK, rast_Proc_STA_EX_AP_CHECK },	// handle ex ap info
#endif
#ifdef RTCONFIG_FORCE_ROAMING	
	{ EID_RM_STA_FORCE_ROAMING, rast_Proc_STA_FORCE_ROAMING }, // handle force roaming event
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
	{ EID_RM_STA_BINDING_UPDATE, rast_Proc_STA_BINDING_UPDATE }, // handle force roaming event
#endif
	{-1, NULL }
};

#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
#define EID_CONNDIAG_RAST_EXAP_BEFORE 	1
#define EID_CONNDIAG_RAST_EXAP_RECEIVED 2
#define RAST_RET_11V		"RET_11V"
#define RAST_STA_EXAP 		"STA_EXAP"
#define RAST_STA_PRESENT_AP "PRESENT_AP"

#ifdef RTCONFIG_CONNDIAG
#ifdef KEY_ROAMING_EVENT
ROAMING_TABLE tmp_roaming_tbl;
int tmp_roaming_tbl_used[MAX_STA_COUNT];
int tmp_roaming_tbl_tstamp_reflash[MAX_STA_COUNT];
static int _assign_roaming_tbl_recv_exap_info( char *sta, const char *present_ap );
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
static int rast_start_internal_ipc_socket(void);
static int _assign_roaming_tbl_before_recv_exap_info(char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi, int ret_11v, char *target_mac );
#endif
static int rast_Proc_INTERNAL_EXAP_BEFORE(char *data);
static int rast_Proc_INTERNAL_EXAP_RECEIVED(char *data);
struct eventHandler RAST_INTERNAL_EVENT[] ={
	{ EID_CONNDIAG_RAST_EXAP_BEFORE, 	rast_Proc_INTERNAL_EXAP_BEFORE },
	{ EID_CONNDIAG_RAST_EXAP_RECEIVED, 	rast_Proc_INTERNAL_EXAP_RECEIVED },
	{-1, NULL }
};
#endif
#endif
#endif


// static client list
static int rast_add_static_client(int bssidx, struct ether_addr *addr, uint8 mesh_node);
static int rast_is_static_client(int bssidx, struct ether_addr *addr);
static void rast_save_mesh_node(int bssidx, char* addr);
static void rast_retrieve_mesh_nodes(int bssidx);
#endif
#ifdef RTCONFIG_BCN_RPT
void rast_create_beacon_report(int bssidx, int vifidx, struct ether_addr *sta
#ifdef RTCONFIG_11K_RCPI_CHECK
,int ap_rssi
#endif
);
void rast_send_beacon_request(int bssidx, int vifidx, struct ether_addr *sta);
#endif
char *strcat_safe(const char *s1, const char *s2){
	int str_len = strlen(s1) + strlen(s2) + 1;

	if(!strcat_buf) {
		strcat_buf = malloc(strcat_buf_length);
		if(!strcat_buf) {
			_dprintf("stacat alloc memory failed\n");
			return NULL;
		}
	}

	if(strcat_buf_length < str_len) {
		strcat_buf_length = str_len;
		strcat_buf = realloc(strcat_buf, strcat_buf_length);
		if(!strcat_buf) {
			_dprintf("stacat realloc memory failed\n");
			return NULL;
		}
	}

	snprintf(strcat_buf, strcat_buf_length, "%.*s%.*s", (int)strlen(s1), s1, (int)strlen(s2), s2);

	return strcat_buf;
}

#ifdef RTCONFIG_ADV_RAST
#define MULTICAST_BIT  0x0001
static int isValidUnicastMacAddr(const char* mac)
{
	int sec_byte;
	int i = 0, s = 0;

	if (strlen(mac) != 17 || !strcmp("00:00:00:00:00:00", mac))
		return 0;

	while (*mac && i < 12) {
		if (isxdigit(*mac)) {
			if (i == 1) {
				sec_byte= strtol(mac, NULL, 16);
				if ((sec_byte & MULTICAST_BIT))
					break;
			}
			i++;
		}
		else if (*mac == ':') {
			if (i == 0 || i/2-1 != s)
				break;
			++s;
		}
		++mac;
	}
	return (i == 12 && s == 5);
}
#endif

static void
alarmtimer(unsigned long sec, unsigned long usec)
{
	itv.it_value.tv_sec  = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

void rast_init_bssinfo(void){
	char ifname[128], *next;
	int idx = 0, idxList = 0, senslevel=0;
	char prefix[32];

	memset(bssinfo, 0, sizeof(bssinfo));

	foreach(ifname, nvram_safe_get("wl_ifnames"), next) {
		snprintf(bssinfo[idx].wlif_name, sizeof(bssinfo[idx].wlif_name), "%s", ifname);
		bssinfo[idx].user_low_rssi = 0;
		snprintf(bssinfo[idx].prefix, sizeof(bssinfo[idx].prefix), "%s", "");
#ifdef RTCONFIG_FRONTHAUL_DWB
		bssinfo[idx].user_low_rssi_for_fhdwb_if = 0;
#endif

		for(idxList = 0; idxList < MAX_SUBIF_NUM; idxList++){
			bssinfo[idx].assoclist[idxList] = NULL;
			if(idxList > 0)
				snprintf(prefix, sizeof(prefix), "wl%d.%d_", idx, idxList);
			else
				snprintf(prefix, sizeof(prefix), "wl%d_", idx);

			bssinfo[idx].bss_enable[idxList] = nvram_get_int(strcat_safe(prefix, "bss_enabled"));
#ifdef RTCONFIG_FRONTHAUL_DWB
			bssinfo[idx].fhdwb_if_enable[idxList] = 0;
#endif
		}

#if defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_LANTIQ)
		if (idx >= MAX_NR_WL_IF)
			break;

		SKIP_ABSENT_BAND_AND_INC_UNIT(idx);

#if defined(RTCONFIG_REALTEK)
		if (repeater_mode() && nvram_get_int("wlc_express") != 0) {
			if (nvram_get_int("wlc_express") -1 == idx) // wlc interface
				bssinfo[idx].user_low_rssi = 0;
			else {
				snprintf(bssinfo[idx].prefix, sizeof(bssinfo[idx].prefix), "wl%d_", idx);
				bssinfo[idx].user_low_rssi = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "user_rssi"));
			}
		}
		else
#endif
		{
			snprintf(bssinfo[idx].prefix, sizeof(bssinfo[idx].prefix), "wl%d_", idx);
			bssinfo[idx].user_low_rssi = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "user_rssi"));
		}
		_dprintf("[%s]: WI[%s], idx[%d] \n", __FUNCTION__, bssinfo[idx].wlif_name, idx);
#else
		int ret, unit;

		ret = wl_ioctl(bssinfo[idx].wlif_name, WLC_GET_INSTANCE, &unit, sizeof(unit));
		if(ret < 0)
			_dprintf("[WARNING] get instance %s error!!!\n", bssinfo[idx].wlif_name);
		else {
			snprintf(bssinfo[idx].prefix, sizeof(bssinfo[idx].prefix), "wl%d_", unit);
			bssinfo[idx].user_low_rssi = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "user_rssi"));
		}
#endif

		bssinfo[idx].band = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "nband"));
		senslevel = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "rast_sens_level"));
		if(senslevel == 2) {
			bssinfo[idx].rssi_cnt = RAST_COUNT_RSSI_SENSITIVE;
			bssinfo[idx].idle_period = RAST_PERIOD_IDLE_SENSITIVE;
			bssinfo[idx].idle_rate = RAST_DFT_IDLE_RATE_SENSITIVE;
		}
		else if(senslevel == 1) {
			bssinfo[idx].rssi_cnt = RAST_COUNT_RSSI_NORMAL;
			bssinfo[idx].idle_period = RAST_PERIOD_IDLE_NORMAL;
			bssinfo[idx].idle_rate = RAST_DFT_IDLE_RATE_NORMAL;
		}
		else {
			bssinfo[idx].rssi_cnt = RAST_COUNT_RSSI_LAZY;
			bssinfo[idx].idle_period = RAST_PERIOD_IDLE_LAZY;
			bssinfo[idx].idle_rate = RAST_DFT_IDLE_RATE_LAZY;
		}

		if (nvram_get_int("sw_mode") == SW_MODE_REPEATER && idx == nvram_get_int("wlc_band")
#if defined (RTCONFIG_REALTEK) && defined(RTCONFIG_CONCURRENTREPEATER)
				/* Realtek wlc interfaces are different from wl_ifnames in repeater mode. So skip to set upstream_if is 1. */
				&& nvram_get_int("wlc_express") != 0
#endif
				)
			bssinfo[idx].upstream_if = 1;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		else if (/*is_psta(idx) || */is_psr(idx))
			bssinfo[idx].upstream_if = 1;
#endif
#if defined(RTCONFIG_AMAS) && (defined(RTCONFIG_QCA) || defined(RTCONFIG_LANTIQ) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_RALINK))
		else if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1"))
			bssinfo[idx].upstream_if = 1;
#endif	/* AMAS && (QCA || LANTIQ) */
		else
			bssinfo[idx].upstream_if = 0;

		//for debug purpose
		if(nvram_get_int(strcat_safe(bssinfo[idx].prefix, "idle_rate")) > 0)
			bssinfo[idx].idle_rate = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "idle_rate"));

		_dprintf("[%s]: WIF[%s], idx[%d] \n", __FUNCTION__, bssinfo[idx].wlif_name, idx);
		_dprintf("rssi threshold: [%d]\n", bssinfo[idx].user_low_rssi);
		_dprintf("rssi hit count: [%d]\n", bssinfo[idx].rssi_cnt);
		_dprintf("idle period: [%d]\n", bssinfo[idx].idle_period);
		_dprintf("idle rate: [%d]\n", bssinfo[idx].idle_rate);

		idx++;
	}
	wlif_count = idx;

#ifdef RTCONFIG_FRONTHAUL_DWB
	/* only 5g-high */
	if( wlif_count > 2 ) {
		idxList = 0;
		if( nvram_get_int("re_mode") == 1 && nvram_get_int("fh_re_mssid_subunit") > 0 ) {
			idxList = nvram_get_int("fh_re_mssid_subunit");
			if(idxList > 0 && idxList < MAX_SUBIF_NUM) {
				bssinfo[2].fhdwb_if_enable[idxList] = 1;
				bssinfo[2].user_low_rssi_for_fhdwb_if = bssinfo[1].user_low_rssi;
			}
		} else if( nvram_get_int("re_mode") == 0 && nvram_get_int("fh_cap_mssid_subunit") > 0 ) {
			idxList = nvram_get_int("fh_cap_mssid_subunit");
			if(idxList > 0 && idxList < MAX_SUBIF_NUM) {
				bssinfo[2].fhdwb_if_enable[idxList] = 1;
				bssinfo[2].user_low_rssi_for_fhdwb_if = bssinfo[1].user_low_rssi;
			}
		}
	}
#endif

	_dprintf("[%s]: TotalWI[%d] \n\n", __FUNCTION__, wlif_count);
}

rast_sta_info_t *rast_add_to_assoclist(int bssidx, int vifidx, struct ether_addr *addr)
{
	rast_sta_info_t *sta, *head;
	char wlif_name[32];
	char cmd[128];

	sta = bssinfo[bssidx].assoclist[vifidx];
	while(sta){
		/* find sta in assoclist */
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_LANTIQ))
		if(memcmp(&(sta->addr), addr, ETHER_ADDR_STR_LEN/3) == 0)
#else
		if(eacmp(&(sta->addr), addr) == 0)
#endif
		{

			break;
		}
		sta = sta->next;
	}

	if(!sta){
		sta = malloc(sizeof(rast_sta_info_t));
		if(!sta){
			_dprintf("[%s]: Malloc failure!\n", __FUNCTION__);
			return NULL;
		}

		memset(sta, 0, sizeof(rast_sta_info_t));
		memcpy(&sta->addr, addr, sizeof(struct ether_addr));
		sta->timestamp = uptime();
		sta->active = uptime();

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_RALINK) || defined(RTCONFIG_LANTIQ)
		sta->last_txrx_bytes = 0;
#else
#ifndef RTCONFIG_BCMARM
 		sta->prepkts = 0;
#endif
		sta->rx_bytes = 0;
#endif
		sta->rssi_hit_count = 0;
		sta->rssi = 0;
		sta->tx_rate = 0;
		sta->rx_rate = 0;
#if defined(RTCONFIG_BCMARM) || defined(RTCONFIG_LANTIQ) || defined(RTCONFIG_QCA)
		sta->tx_byte = 0;
		sta->rx_byte = 0;
#endif
		sta->datarate = 0;
		sta->idle_state = 0;

#ifdef RTCONFIG_ADV_RAST
		sta->trigger = uptime();
		sta->next_trigger_interval = 0;
		sta->stamon_event_count = 0;
		sta->previous_rssi = 0;
		sta->wnm_cap = 0;
#ifdef RTCONFIG_BCN_RPT
		sta->rrm_bcn_passive_cap = 0;
#endif
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
		sta->in_binding_list = sta_binding_list_check(addr);
#endif
		/* insert sta in the front of assoclist */
		head = bssinfo[bssidx].assoclist[vifidx];
		if(head)
			head->prev = sta;

		sta->next = head;
		sta->prev = (struct rast_sta_info *)&(bssinfo[bssidx].assoclist[vifidx]);
		bssinfo[bssidx].assoclist[vifidx] = sta;

		if(vifidx > 0){
			snprintf(cmd, sizeof(cmd), "wl%d.%d_ifname", bssidx, vifidx);
			strcpy(wlif_name, nvram_safe_get(cmd));
		}
		else
			strcpy(wlif_name, bssinfo[bssidx].wlif_name);

		_dprintf("%s: add sta ["MACF"] to assoclist\n", wlif_name, ETHERP_TO_MACF(addr));
		_dprintf("%s: add client ["MACF"] to monitor list\n", wlif_name, ETHERP_TO_MACF(addr));
	}

	return sta;
}

rast_sta_info_t *rast_remove_from_assoclist(int bssidx, int vifidx, struct ether_addr *addr
#ifdef RTCONFIG_STA_AP_BAND_BIND
,int deauth
#endif
)
{
	bool found = FALSE;
	rast_sta_info_t *assoclist = NULL, *prev, *head, *next_sta = NULL;
	char wlif_name[32];
	char cmd[128];
#ifdef RTCONFIG_ADV_RAST	
	pthread_mutex_lock(&roamastBssinfoLock);
#endif
	assoclist = bssinfo[bssidx].assoclist[vifidx];
	if(assoclist == NULL) {
		goto rast_remove_from_assoclist_exit;
	}

	/* found at 1st element, update pointer */
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_LANTIQ))
      	if(memcmp(&(assoclist->addr), addr, ETHER_ADDR_STR_LEN/3) == 0) {
#else
	if(eacmp(&(assoclist->addr), addr) == 0) {
#endif
		head = assoclist->next;
		bssinfo[bssidx].assoclist[vifidx] = head;
		if(head) {
			head->prev = (struct rast_sta_info *)&(bssinfo[bssidx].assoclist[vifidx]);
			next_sta = head;
		}
		found = TRUE;
	}
	else {
		prev = assoclist;
		assoclist = prev->next;

		while(assoclist) {
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_LANTIQ))
		    if(memcmp(&(assoclist->addr), addr, ETHER_ADDR_STR_LEN/3) == 0)
#else
			if(eacmp(&(assoclist->addr), addr) == 0)
#endif
			{
				head = assoclist->next;
				prev->next = head;
				if(head) {
					head->prev = prev;
					next_sta = head;
				}

				found = TRUE;
				break;
			}

			prev = assoclist;
			assoclist = prev->next;
		}
	}

	if(found) {
		if (vifidx > 0) {
			snprintf(cmd, sizeof(cmd), "wl%d.%d_ifname", bssidx, vifidx);
			strcpy(wlif_name, nvram_safe_get(cmd));
		}
		else
			strcpy(wlif_name, bssinfo[bssidx].wlif_name);

#ifdef RTCONFIG_STA_AP_BAND_BIND
		if(deauth)
			RAST_SYSLOG("%s: sta-ap-band-bind deauth ["MACF"]\n", wlif_name, ETHERP_TO_MACF(addr));
#endif

		RAST_SYSLOG("%s: remove client ["MACF"] from monitor list\n", wlif_name, ETHERP_TO_MACF(addr));

		free(assoclist);
	}
rast_remove_from_assoclist_exit:

#ifdef RTCONFIG_STA_AP_BAND_BIND
	if(deauth){
		rast_deauth_sta_no_syslog(bssidx, vifidx, addr);
	}
#endif

#ifdef RTCONFIG_ADV_RAST
	pthread_mutex_unlock(&roamastBssinfoLock);
#endif
	return next_sta;
}

#ifdef RTCONFIG_STA_AP_BAND_BIND
void rast_deauth_sta_no_syslog(int bssidx, int vifidx, struct ether_addr *addr)
{
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_LANTIQ))
	int found = 1;
	char wlif_name[32];
	char cmd[128], mac[sizeof("00:00:00:00:00:00XXX")];
	
	if (vifidx > 0) {
#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
		/* For QCA/MTK models, 1st guest network of node is start at wlX.2 */
		if (aimesh_re_node())
			vifidx++;
#endif
		snprintf(cmd, sizeof(cmd), "wl%d.%d_ifname", bssidx, vifidx);
		strcpy(wlif_name, nvram_safe_get(cmd));
	}
	else
		strcpy(wlif_name, bssinfo[bssidx].wlif_name);

	snprintf(mac, sizeof(mac), MACF, ETHERP_TO_MACF(addr));
#if defined(RTCONFIG_RALINK)
	snprintf(cmd, sizeof(cmd), "iwpriv %s set DisConnectSta="MACF, wlif_name, ETHERP_TO_MACF(addr));
#elif defined(RTCONFIG_QCA)
	found = find_vap_by_sta(mac, wlif_name);
#if defined(RTCONFIG_CFG80211)
	snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s disassociate "MACF, wlif_name, ETHERP_TO_MACF(addr));
#else
	snprintf(cmd, sizeof(cmd), IWPRIV " %s kickmac "MACF, wlif_name, ETHERP_TO_MACF(addr));
#endif
#elif defined(RTCONFIG_REALTEK)
	snprintf(cmd, sizeof(cmd), "iwpriv %s del_sta %02x%02x%02x%02x%02x%02x", wlif_name, ETHERP_TO_MACF(addr));
#elif defined(RTCONFIG_LANTIQ)
	snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s disassociate %s "MACF, wlif_name, wlif_name, ETHERP_TO_MACF(addr));
#endif
	if (found) {
		system(cmd);
	}
#else /* BCM */
	int ret;
	scb_val_t scb_val;
	char wlif_name[32];

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	memcpy(&scb_val.ea, addr, ETHER_ADDR_LEN);
	scb_val.val = 8; /* reason code: Disassociated because sending STA is leaving BSS */

	ret = wl_ioctl(wlif_name, WLC_SCB_DEAUTHENTICATE_FOR_REASON, &scb_val, sizeof(scb_val));
	if(ret < 0) {
		RAST_INFO("[WARNING] error to deauthticate ["MACF"] !!!\n", ETHERP_TO_MACF(addr));
	}
#endif
}
#endif

void rast_deauth_sta(int bssidx, int vifidx, struct ether_addr *addr)
{
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_LANTIQ))
	char wlif_name[32];
	char cmd[128];
	
	if (vifidx > 0) {
		snprintf(cmd, sizeof(cmd), "wl%d.%d_ifname", bssidx, vifidx);
		strcpy(wlif_name, nvram_safe_get(cmd));
	}
	else
		strcpy(wlif_name, bssinfo[bssidx].wlif_name);

#if defined(RTCONFIG_RALINK)
	RAST_SYSLOG("%s: disconnect weak signal strength station ["MACF"]\n", wlif_name, ETHERP_TO_MACF(addr));
	snprintf(cmd, sizeof(cmd), "iwpriv %s set DisConnectSta="MACF, wlif_name, ETHERP_TO_MACF(addr));
#elif defined(RTCONFIG_QCA)
	RAST_SYSLOG("%s: disconnect weak signal strength station ["MACF"]\n", wlif_name, ETHERP_TO_MACF(addr));
	snprintf(cmd, sizeof(cmd), IWPRIV " %s kickmac "MACF, wlif_name, ETHERP_TO_MACF(addr));
#elif defined(RTCONFIG_REALTEK)
	RAST_SYSLOG("%s: disconnect weak signal strength station ["MACF"]\n", wlif_name, ETHERP_TO_MACF(addr));
	snprintf(cmd, sizeof(cmd), "iwpriv %s del_sta %02x%02x%02x%02x%02x%02x", wlif_name, ETHERP_TO_MACF(addr));
#elif defined(RTCONFIG_LANTIQ)
	RAST_SYSLOG("%s: disconnect weak signal strength station ["MACF"]\n", wlif_name, ETHERP_TO_MACF(addr));
	snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s disassociate %s "MACF, wlif_name, wlif_name, ETHERP_TO_MACF(addr));
#endif
	system(cmd);
#else /* BCM */
	int ret;
	scb_val_t scb_val;
	char wlif_name[32];

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	RAST_SYSLOG("%s: disconnect weak signal strength station ["MACF"]\n", wlif_name, ETHERP_TO_MACF(addr));
	memcpy(&scb_val.ea, addr, ETHER_ADDR_LEN);
	scb_val.val = 8; /* reason code: Disassociated because sending STA is leaving BSS */

	ret = wl_ioctl(wlif_name, WLC_SCB_DEAUTHENTICATE_FOR_REASON, &scb_val, sizeof(scb_val));
	if(ret < 0) {
		RAST_INFO("[WARNING] error to deauthticate ["MACF"] !!!\n", ETHERP_TO_MACF(addr));
	}
#endif
}

#ifdef RTCONFIG_FORCE_ROAMING
void rast_check_criteria(int bssidx, int vifidx, struct force_roaming_list *fr_tmp,int no_normal_roaming)
#else
void rast_check_criteria(int bssidx, int vifidx)
#endif
{
	int idx=0,i;
	int flag_rssi, flag_idle;
	time_t now = uptime();
	rast_sta_info_t *sta = bssinfo[bssidx].assoclist[vifidx];
	int w_idlerate = 1;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	int support_kv=0;
	int stamon_or_11k=0;
#endif	
#ifdef RTCONFIG_ADV_RAST
	int rssi_delta;
	int video_rssi_wpow;
	char wnmcap[32];
#endif
#ifdef RTCONFIG_FRONTHAUL_DWB
	/* 
		The fhdwb interface user_rssi follows 5g-1 setting but this interface is 5g-2 interface.
		So add user_rssi_tmp for this interface.
	 */
	int user_rssi_tmp;
#endif
#ifdef RTCONFIG_FORCE_ROAMING
	int force_roaming = 0;
	int force_roaming_blocktime = 0;
	char macaddr_str[18];

	if(fr_tmp){
		for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
			fr_tmp->stamac[i]=toupper(fr_tmp->stamac[i]);
		RAST_DBG("got a force roaming sta %s\n",fr_tmp->stamac);
	}

#endif	

#ifdef RTCONFIG_ADV_RAST	
	char* str = nvram_safe_get("rast_video_rssi");
	if (strlen(str) > 0)
		video_rssi_wpow = atoi(str);
	else
		video_rssi_wpow = RAST_DFT_RSSI_VIDEO_CALL;
#endif
	
	while(sta) {
		flag_rssi = 0;
		flag_idle = 0;
		idx++;
		
#ifdef RTCONFIG_FORCE_ROAMING
		force_roaming = 0;

		if(fr_tmp){
			snprintf( macaddr_str, 18 ,MACF, ETHERP_TO_MACF( &(sta->addr) ) );
			//TOUPPER
			for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
				macaddr_str[i]=toupper(macaddr_str[i]);
			
			if( !strcmp(macaddr_str,fr_tmp->stamac) ) 
			{
				force_roaming_blocktime = fr_tmp->blocktime;
				force_roaming =1;
				//if(strlen(fr_tmp->target)){
				//	force_roaming_target = 1;
				//}
			} else {
				if(no_normal_roaming)
				{
					sta = sta->next;
					continue;
				}
			}
		}
#endif
		
#ifdef RTCONFIG_ADV_RAST
		if( 
#ifdef RTCONFIG_FORCE_ROAMING
			!force_roaming &&
#endif
			rast_is_static_client(bssidx, &(sta->addr))){
			sta = sta->next;
			continue;
		}
#endif

#ifdef RTCONFIG_STA_AP_BAND_BIND
		if(sta->in_binding_list)
		{
			RAST_DBG("sta "MACF" is in binding list,no roaming\n",ETHER_TO_MACF(sta->addr));
			sta = sta->next;
			continue;
		}
#endif

#ifdef RTCONFIG_FORCE_ROAMING
		if( !force_roaming ) {
#endif
#ifdef RTCONFIG_FRONTHAUL_DWB
		user_rssi_tmp = (vifidx > 0 && bssinfo[bssidx].fhdwb_if_enable[vifidx]) 
						? bssinfo[bssidx].user_low_rssi_for_fhdwb_if : bssinfo[bssidx].user_low_rssi;

		if(sta->rssi < user_rssi_tmp)
#else
		if(sta->rssi < bssinfo[bssidx].user_low_rssi)
#endif
		{
#ifdef RTCONFIG_FRONTHAUL_DWB
#ifdef RTCONFIG_ADV_RAST
			if (!(sta->rssi > video_rssi_wpow))
				w_idlerate = (1 + abs(user_rssi_tmp - sta->rssi)) * 2;
			else
#endif
				w_idlerate = 1 + abs(user_rssi_tmp - sta->rssi);
#else //RTCONFIG_FRONTHAUL_DWB
#ifdef RTCONFIG_ADV_RAST
			if (!(sta->rssi > video_rssi_wpow))
				w_idlerate = (1 + abs(bssinfo[bssidx].user_low_rssi - sta->rssi)) * 2;
			else
#endif
				w_idlerate = 1 + abs(bssinfo[bssidx].user_low_rssi - sta->rssi);
#endif //RTCONFIG_FRONTHAUL_DWB
			sta->rssi_hit_count++;
			if(sta->rssi_hit_count >= bssinfo[bssidx].rssi_cnt)
				flag_rssi = 1;
		}
		else {
			sta->rssi_hit_count = 0;
		}

		if(sta->datarate < (bssinfo[bssidx].idle_rate * w_idlerate)) {
			if(!sta->idle_state) {
				sta->idle_state = 1;
				sta->idle_start = now;
			}
			if((now - sta->idle_start) >= bssinfo[bssidx].idle_period)
				flag_idle = 1;
		}
		else {
			sta->idle_state = 0;
		}
#ifdef RTCONFIG_FORCE_ROAMING
		}
#endif

#ifdef RTCONFIG_ADV_RAST
		snprintf(wnmcap, sizeof(wnmcap), "wnm_cap: 0x%x", sta->wnm_cap);
#endif

#if defined(RTCONFIG_RALINK)
#ifdef RTCONFIG_FRONTHAUL_DWB
	RAST_DBG("[%s][%d][%s]:(%d) RSSI Avg = %d RSSI[C:%d/F:%d] DATA[R:%f/L:%d/F:%d]  %s \n",
		__FUNCTION__,idx, sta->mac_addr, user_rssi_tmp, 
		sta->rssi,sta->rssi_hit_count , flag_rssi, sta->datarate, 
		bssinfo[bssidx].idle_rate * w_idlerate, flag_idle, (flag_rssi & flag_idle) ? " *** Weak Station *** " : "");
#else		
	RAST_DBG("[%s][%d][%s]:(%d) RSSI Avg = %d RSSI[C:%d/F:%d] DATA[R:%f/L:%d/F:%d]  %s \n",__FUNCTION__,idx, sta->mac_addr, bssinfo[bssidx].user_low_rssi, sta->rssi,sta->rssi_hit_count , flag_rssi, sta->datarate, bssinfo[bssidx].idle_rate * w_idlerate, flag_idle, (flag_rssi & flag_idle) ? " *** Weak Station *** " : "");
#endif
#else
	RAST_DBG("[%d]sta ["MACF"]: rssi = %d dBm [Hit=%d],datarate = %.1f Kbps [Thrs:%d], active = %lu [idle start = %lu, period = %lu] %s %s\n",
			idx,
			ETHER_TO_MACF(sta->addr),
			sta->rssi,
			sta->rssi_hit_count,
			sta->datarate,
			bssinfo[bssidx].idle_rate * w_idlerate,	
			sta->active,
			sta->idle_state ? sta->idle_start : 0,
			sta->idle_state ? now - sta->idle_start : 0,
#ifdef RTCONFIG_ADV_RAST 
			wnmcap,
#else
			"",
#endif
			(flag_rssi & flag_idle) ? " *** Weak Station *** " : "");
#endif
#ifdef RTCONFIG_BCN_RPT
	if (nvram_match("11k_support", "1"))
	{
		rast_send_beacon_request(bssidx, vifidx, &sta->addr);
		nvram_unset("11k_support");
	}
#endif
		if(
#ifdef RTCONFIG_FORCE_ROAMING
			force_roaming ||
#endif
			(flag_rssi & flag_idle) ) {
#ifdef RTCONFIG_ADV_RAST
			if(bssinfo[bssidx].rast_mode == RAST_MODE_LEGACY)
			{
				/* send STA_MON event and wait response */
				if(
#ifdef RTCONFIG_FORCE_ROAMING
					force_roaming ||
#endif
					(now - sta->trigger > sta->next_trigger_interval) )
				{
					/* if event counter reach freeze condition, skip event util obvious rssi changes */
					if(
#ifdef RTCONFIG_FORCE_ROAMING
						!force_roaming &&
#endif
						sta->stamon_event_count >= RAST_EVENT_FREEZE)
					{
						rssi_delta = sta->rssi - sta->previous_rssi;
						if(abs(rssi_delta) >= RAST_OBVS_RSSI_DELTA || now - sta->trigger > RAST_EVENT_FREEZE_MAX_TIME) {
							RAST_DBG("Reset ["MACF"] sta monitor event count, rssi delta=%d, trigger offset time=%d\n",
								ETHER_TO_MACF(sta->addr),
								abs(rssi_delta),
								now - sta->trigger);
							sta->stamon_event_count = 0;
						}
						else {
							RAST_DBG("["MACF"] sta monitor event is freezed [previous: %ddBm / now: %ddBm]\n",
								ETHER_TO_MACF(sta->addr),
								sta->previous_rssi,
								sta->rssi);
							goto next;
						}
					}

					sta->trigger = now;
					sta->next_trigger_interval = RAST_EVENT_TIMEOUT + rast_event_random_interval();
					RAST_DBG("Trigger ["MACF"] sta monitor event, next event interval is [%d] sec.\n",
							ETHER_TO_MACF(sta->addr),
							sta->next_trigger_interval);

#ifdef RTCONFIG_CONNDIAG
					char buff[32];
					snprintf(buff, sizeof(buff), MACF_UP, ETHER_TO_MACF(sta->addr));
#ifdef RTCONFIG_FRONTHAUL_DWB
					_assign_tg_roaming_tbl(buff, bssidx, sta->rssi, user_rssi_tmp, 
						bssinfo[bssidx].rssi_cnt, bssinfo[bssidx].idle_period, sta->idle_start);					
#else
					_assign_tg_roaming_tbl(buff, bssidx, sta->rssi, bssinfo[bssidx].user_low_rssi, bssinfo[bssidx].rssi_cnt, bssinfo[bssidx].idle_period, sta->idle_start);
#endif
#endif

#if 0
					snprintf(prefix, sizeof(prefix),"wl%d.%d", bssidx, vifidx);
					RAST_SYSLOG("%s: detect weak signal strength station ["MACF"][signal strength: %ddBm]\n", 
						vifidx > 0 ? nvram_safe_get(strcat_safe(prefix, "_ifname")) : bssinfo[bssidx].wlif_name,
						ETHER_TO_MACF(sta->addr),
						sta->rssi);
#endif

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifdef RTCONFIG_FORCE_ROAMING
					if(force_roaming) support_kv = 0; //force roaming use only stamon and legacy deauth
					else {
#endif				

					support_kv = check_if_support_kv(bssidx, vifidx, sta);

					/* if default rssi method is 11k, we do not use stamon */
					if( is_rssi_method_default_k() && !(support_kv & RAST_SUPPORT_K_PASSIVE_SCAN) )
					{
						RAST_DBG("["MACF"] sta monitor event is passed [not support 11k]\n",
								ETHER_TO_MACF(sta->addr));
							goto next;
					}

#ifdef RTCONFIG_FORCE_ROAMING
					}
#endif

					stamon_or_11k= rssi_info_gather_method();

					if( (support_kv & RAST_SUPPORT_K_PASSIVE_SCAN) && ( (stamon_or_11k == RSSI_INFO_GATHER_BY_11K)
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
					||(rast_nonmesh_kvonly)
#endif
					) ) {//11k pasive beacon request and 11v btm request
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
						if(!rast_nonmesh_kvonly)
#endif

						rast_create_beacon_report(bssidx, vifidx, &sta->addr
#ifdef RTCONFIG_11K_RCPI_CHECK
							,sta->rssi
#endif
						);
						rast_send_beacon_request(bssidx, vifidx, &sta->addr);
						sleep(1);
					}
#endif

#ifdef RTCONFIG_RAST_NONMESH_KVONLY
					/* if rast_nonmesh_kvonly is set and a sta does not support 11k and 11v, do nothing */
					if( rast_nonmesh_kvonly )
					{
						if( support_kv & RAST_SUPPORT_K_PASSIVE_SCAN ) {
							add_to_roaming_list(bssidx, vifidx, &sta->addr,sta->rssi);
							sta->stamon_event_count++;
							sta->previous_rssi = sta->rssi;
							RAST_DBG("add_to_roaming_list ["MACF"] stamon trigger %d times, previous rssi = %d\n",
								ETHER_TO_MACF(sta->addr),
								sta->stamon_event_count,
								sta->previous_rssi);
						}
					} else {
#endif
					if(rast_req_stamon( bssidx, vifidx, wl_ether_etoa(&sta->addr),
							sta->rssi,
							bssinfo[bssidx].band == WL_NBAND_2G ? RAST_JVALUE_BAND_2G : RAST_JVALUE_BAND_5G
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
						,support_kv, stamon_or_11k
#endif
#ifdef RTCONFIG_FORCE_ROAMING
						,force_roaming , force_roaming_blocktime, fr_tmp->target
#endif						
						))
					{
						sta->stamon_event_count++;
						sta->previous_rssi = sta->rssi;
						RAST_DBG("["MACF"] stamon trigger %d times, previous rssi = %d\n",
							ETHER_TO_MACF(sta->addr),
							sta->stamon_event_count,
							sta->previous_rssi);
					}
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
					}
#endif

				}
				goto next;
			}
			else
#endif//end of RTCONFIG_ADV_RAST
			{
				rast_deauth_sta(bssidx, vifidx, &sta->addr);
				sta = rast_remove_from_assoclist(bssidx, vifidx, &sta->addr
#ifdef RTCONFIG_STA_AP_BAND_BIND
						,0
#endif
					);
			}
			continue;
		}
#ifdef RTCONFIG_ADV_RAST
next:
#endif
		sta = sta->next;
	}

	return;
}

void rast_timeout_sta(int bssidx, int vifidx){
	time_t now = uptime();
	rast_sta_info_t *sta, *prev, *next, *head;
	sta = bssinfo[bssidx].assoclist[vifidx];
	head = NULL;
	prev = NULL;

	while(sta) {
		if(now - sta->active > RAST_TIMEOUT_STA) {
#if defined(RTCONFIG_RALINK)
			RAST_DBG("[%s]: Free Mac[%s], TIME[N:%lu/A:%lu]\n", __FUNCTION__, sta->mac_addr , now , sta->active);
#else
			RAST_DBG("free ["MACF"] from assoclist [now = %lu][active = %lu]\n",
					ETHER_TO_MACF(sta->addr),
					now,
					sta->active);
#endif
			next = sta->next;
			free(sta);
			sta = next;
			if(prev)
				prev->next = sta;
			continue;
		}

		if(head == NULL)
			head = sta;

		prev = sta;
		sta = sta->next;
	}
	bssinfo[bssidx].assoclist[vifidx] = head;
}

#ifdef RTCONFIG_FORCE_ROAMING
void rast_update_sta_info(int bssidx, int vifidx,int roaming_enable, struct force_roaming_list *fr_tmp,int no_normal_roaming){
#else
void rast_update_sta_info(int bssidx, int vifidx,int roaming_enable){
#endif
/* lock for add client to asslist*/
#ifdef RTCONFIG_ADV_RAST	
	pthread_mutex_lock(&roamastBssinfoLock);
#endif
#if defined(RTCONFIG_RALINK) || defined(RTCONFIG_LANTIQ) || defined(CONFIG_BCMWL5) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_QCA)
	get_stainfo(bssidx, vifidx);
#endif

#if defined(RTCONFIG_BCMARM) || defined(RTCONFIG_BCMWL6)
	rast_retrieve_bs_data(bssidx, vifidx, RAST_POLL_INTV_NORMAL);
#endif

	rast_timeout_sta(bssidx, vifidx);

	if(roaming_enable==0)
	{
#ifdef RTCONFIG_ADV_RAST	
		pthread_mutex_unlock(&roamastBssinfoLock);
#endif
		return;
	}

#ifdef RTCONFIG_FORCE_ROAMING
	rast_check_criteria(bssidx, vifidx, fr_tmp,no_normal_roaming);
#else
	rast_check_criteria(bssidx, vifidx);
#endif
#ifdef RTCONFIG_ADV_RAST	
	pthread_mutex_unlock(&roamastBssinfoLock);
#endif
}

struct ether_addr* rast_ether_atoe(char *a,struct ether_addr *ret_ea)
{
	//struct ether_addr *ea;
	char *c = NULL;
	int i = 0;
	//ea = malloc(sizeof(struct ether_addr));
	//RAST_INFO("%s %d,malloc:%x",__FUNCTION__,__LINE__,ea);
	if(ret_ea == NULL)
		return NULL;
	memset(ret_ea, 0, sizeof(struct ether_addr));
	for (;;) {
#if ( defined(RTCONFIG_RALINK) || defined(RTCONFIG_LANTIQ) || defined(RTCONFIG_QCA) )
		ret_ea->ether_addr_octet[i++] = (uint8)strtoul(a, &c, 16);
#else
		ret_ea->octet[i++] = (uint8)strtoul(a, &c, 16);
#endif
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
		a = c;
	}
	return (i == ETHER_ADDR_LEN) ? ret_ea : NULL;
}

#ifdef RTCONFIG_ADV_RAST
void rast_adv_init() {
	char ifname[128], *next;
	int idx = 0, vidx;
	int legacy_ipc = 0;
	char *nv, *nvp, *b;
	struct ether_addr ea_tmp;

	adv_conf.aclist_timeout = nvram_get_int("rast_aclist_timeout");
	RAST_DBG("aclist_timeout = %d\n",adv_conf.aclist_timeout);

	if(nvram_safe_get("rast_weak_rssi_diff") == NULL)
		nvram_set_int("rast_weak_rssi_diff", RAST_DFT_WEAK_RSSI_DIFF);
	adv_conf.weak_rssi_diff = nvram_get_int("rast_weak_rssi_diff");
	RAST_DBG("weak_rssi_diff: [%d]\n", adv_conf.weak_rssi_diff);

	foreach(ifname, nvram_safe_get("wl_ifnames"), next) {
		RAST_DBG("[%s]: WIF[%s], idx[%d] \n", __FUNCTION__, bssinfo[idx].wlif_name, idx);
		bssinfo[idx].rast_mode = atoi(nvram_safe_get(strcat_safe(bssinfo[idx].prefix, "rast_mode")));
		if(bssinfo[idx].rast_mode != RAST_MODE_RSSI && bssinfo[idx].rast_mode != RAST_MODE_LEGACY)
			bssinfo[idx].rast_mode = RAST_MODE_RSSI;

		RAST_DBG("[%s] mode: %s\n", bssinfo[idx].wlif_name, bssinfo[idx].rast_mode == RAST_MODE_LEGACY ? "LEGACY" : "RSSI");
		if(bssinfo[idx].rast_mode == RAST_MODE_LEGACY)
			legacy_ipc = 1;
		bssinfo[idx].static_client = NULL;
		snprintf( bssinfo[idx].tmp_static_client_path,
			  sizeof(bssinfo[idx].tmp_static_client_path),
			  "/tmp/rast_stc_idx%d",
			  idx);

		// static client list
		bssinfo[idx].static_cli_enable = nvram_get_int("rast_static_cli_enable");
		RAST_DBG("[%s] static client: %s\n", bssinfo[idx].wlif_name, bssinfo[idx].static_cli_enable ? "ENABLE" : "DISABLE");
		nv = nvp = strdup(nvram_safe_get(strcat_safe(bssinfo[idx].prefix, "rast_static_client")));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (strlen(b) == 0) continue;
				rast_add_static_client(idx, rast_ether_atoe(b,&ea_tmp), 0);
			}
			free(nv);
		}
		rast_retrieve_mesh_nodes(idx);

		for(vidx=0; vidx < MAX_SUBIF_NUM; vidx++) {

			bssinfo[idx].maclist[vidx] = NULL;
			bssinfo[idx].static_maclist[vidx] = NULL;
			bssinfo[idx].static_macmode[vidx] = WLC_MACMODE_DISABLED;

			if(bssinfo[idx].bss_enable[vidx]) {
				rast_retrieve_static_maclist(idx, vidx);				
			}
		}

		idx++;
	}

	if(legacy_ipc){
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
		if(rast_nonmesh_kvonly)
			rast_nonmesh_kv_thread_create();
		else
#endif
		rast_ipc_socket_thread();
	}
}

static void rast_add_to_maclist(int bssidx, int vifidx, struct ether_addr *addr
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming_blocktime
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
	,int sta_ap_band_bind_action //0:ignore 1:block 2:unblock
#endif
	)
{
	char prefix[32];
	rast_maclist_t *ptr;

	pthread_mutex_lock(&maclistLock);

	ptr = bssinfo[bssidx].maclist[vifidx];

	snprintf(prefix, sizeof(prefix), "wl%d.%d", bssidx, vifidx);
	
	while(ptr) {
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_LANTIQ))
		if(memcmp(&(ptr->addr), addr, ETHER_ADDR_STR_LEN/3) == 0)
#else		
		if (eacmp(&(ptr->addr), addr) == 0)
#endif			
			break;
		ptr = ptr->next;
	}

#ifdef RTCONFIG_STA_AP_BAND_BIND
	if(!ptr && sta_ap_band_bind_action == RAST_STAAPBANDBIND_ACTION_UNBLOCK){
		pthread_mutex_unlock(&maclistLock);
		return; //donothing
	}
#endif

	if(!ptr) {
		// add sta to maclist
		ptr = malloc(sizeof(rast_maclist_t));
		if(!ptr) {
			RAST_INFO("[%s]: Err: Exiting %d malloc failure", __FUNCTION__, __LINE__);
			pthread_mutex_unlock(&maclistLock);
			return;
		}
		memset(ptr, 0, sizeof(rast_maclist_t));
		ptr->addr = *addr;
		ptr->timestamp = uptime();
		ptr->mesh_node = 0;
		ptr->next = bssinfo[bssidx].maclist[vifidx];
#ifdef RTCONFIG_FORCE_ROAMING
		ptr->force_roaming_blocktime = force_roaming_blocktime;
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
		ptr->sta_ap_band_bind_action = sta_ap_band_bind_action;
#endif
		bssinfo[bssidx].maclist[vifidx] = ptr;

		RAST_DBG("[%s] add mac: "MACF" to maclist (timestamp:%ld)\n",
			vifidx > 0 ? prefix : bssinfo[bssidx].wlif_name,
			ETHER_TO_MACF(ptr->addr),
			ptr->timestamp);
#ifdef RTCONFIG_STA_AP_BAND_BIND
		if( sta_ap_band_bind_action==RAST_NOT_A_STAAPBANDBIND_ACTION || 
			sta_ap_band_bind_action==RAST_STAAPBANDBIND_ACTION_BLOCK )
#endif
		rast_set_maclist(bssidx, vifidx);
	} 	else {
#ifdef RTCONFIG_FORCE_ROAMING
		ptr->timestamp = uptime();
		RAST_DBG("[%s] already in acl list: "MACF" to maclist (timestamp:%ld) force_roaming_blocktime %d\n",
			vifidx > 0 ? prefix : bssinfo[bssidx].wlif_name,
			ETHER_TO_MACF(ptr->addr),
			ptr->timestamp,force_roaming_blocktime);
		ptr->force_roaming_blocktime = force_roaming_blocktime;
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
		if( sta_ap_band_bind_action != RAST_NOT_A_STAAPBANDBIND_ACTION ){
			RAST_DBG("[%s] already in acl list: "MACF" to maclist (timestamp:%ld) sta_ap_band_bind_action %d\n",
				vifidx > 0 ? prefix : bssinfo[bssidx].wlif_name,
				ETHER_TO_MACF(ptr->addr),
				ptr->timestamp,sta_ap_band_bind_action);
			ptr->sta_ap_band_bind_action = sta_ap_band_bind_action;
		}
#endif
	}
	pthread_mutex_unlock(&maclistLock);
	return;

}
#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_timeout_maclist_count=0;
#endif
static void rast_timeout_maclist()
{
	int idx, vidx;
	char prefix[32];
	rast_maclist_t *r_maclist, *prev, *head, *next;
	time_t now = uptime();
	int set_maclist = 0;

	pthread_mutex_lock(&maclistLock);

#ifdef RTCONFIG_STA_AP_BAND_BIND
	if(rast_timeout_maclist_count >=0 && rast_timeout_maclist_count <=30 )
		rast_timeout_maclist_count++;
	else
		rast_timeout_maclist_count = 0;

	int maclist_driver_ret=0;
	int static_macmode=0;
	char maclist_buf[4096]={0};

	//RAST_INFO("rast_timeout_maclist_count %d\n",rast_timeout_maclist_count);

#endif

	for(idx = 0; idx < wlif_count; idx++) {
#if 0		
#ifdef RTCONFIG_FRONTHAUL_DWB
		if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)  {
			if(!r_maclist)
				;
			else
				_dprintf("idx %d %d\n",idx,__LINE__);
		}
#else		
		if(!bssinfo[idx].user_low_rssi) {
			if(!r_maclist)
				;
			else
				_dprintf("idx %d %d\n",idx,__LINE__);
		}
#endif
#endif
		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++) {

			r_maclist = bssinfo[idx].maclist[vidx];

			snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);
			if(!bssinfo[idx].bss_enable[vidx])
				continue;

#if 0
#ifdef RTCONFIG_FRONTHAUL_DWB
			if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
			{
				if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx]){
			if(!r_maclist)
				continue;
			else
				_dprintf("idx %d vidx %d %d\n",idx,vidx,__LINE__);
		}
				if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx]){
			if(!r_maclist)
				continue;
			else
				_dprintf("idx %d vidx %d %d\n",idx,vidx,__LINE__);
		}
			}
#endif
#endif

			//r_maclist = bssinfo[idx].maclist[vidx];
			if(!r_maclist)
				continue;

			head = NULL;
			prev = NULL;
#ifdef RTCONFIG_STA_AP_BAND_BIND
			/* get driver maclist here */
			if(rast_timeout_maclist_count > 30){
				maclist_driver_ret = 0;
				static_macmode=0;
				memset(maclist_buf,0,sizeof(maclist_buf));
				maclist_driver_ret = rast_get_driver_maclist(idx,vidx,maclist_buf,sizeof(maclist_buf),&static_macmode);
			}
#endif

			while(r_maclist) {
				RAST_DBG("[%s] maclist check mac: "MACF" now:%ld, start:%ld, delta:(%ld/%u)\n",
				vidx > 0 ? prefix : bssinfo[idx].wlif_name,
				ETHER_TO_MACF(r_maclist->addr),
				now,
				r_maclist->timestamp,
				now - r_maclist->timestamp,
				adv_conf.aclist_timeout);
#ifdef RTCONFIG_STA_AP_BAND_BIND
				if( r_maclist->sta_ap_band_bind_action ) {//0 = not a sta-ap-band bind action
					if( r_maclist->sta_ap_band_bind_action == RAST_STAAPBANDBIND_ACTION_UNBLOCK )
					{
						RAST_DBG("[%s] maclist unblock(sta ap band bind), remove mac: "MACF"\n",
							vidx > 0 ? prefix : bssinfo[idx].wlif_name,
							ETHER_TO_MACF(r_maclist->addr));

						next = r_maclist->next;
						free(r_maclist);
						r_maclist = next;

						if (prev)
							prev->next = r_maclist;

						set_maclist = 1;
						continue;						
					}
					else {
						if( nvram_get_int("not_restart_rast") == 1 || maclist_driver_ret == 0)
							;//donothing
						else if(rast_timeout_maclist_count > 30)
						{
							if(rast_check_driver_maclist(maclist_buf,static_macmode,&r_maclist->addr) != 0){
								RAST_INFO("\n[ERROR]maclist mis-match\n\n");
								RAST_SYSLOG("[ERROR]maclist mis-match");
								notify_rc("restart_roamast");
							}
						}
					}
				} else
#endif
#ifdef RTCONFIG_FORCE_ROAMING
				if( r_maclist->force_roaming_blocktime ) {
					if( now - r_maclist->timestamp >= r_maclist->force_roaming_blocktime ) {
						RAST_DBG("[%s] maclist timeout(force roaming), remove mac: "MACF"\n",
							vidx > 0 ? prefix : bssinfo[idx].wlif_name,
							ETHER_TO_MACF(r_maclist->addr));

						next = r_maclist->next;
						free(r_maclist);
						r_maclist = next;

						if (prev)
							prev->next = r_maclist;

						set_maclist = 1;
						continue;
					}
				} else
#endif

				if(now - r_maclist->timestamp >= adv_conf.aclist_timeout ) {

					RAST_DBG("[%s] maclist timeout, remove mac: "MACF"\n",
						vidx > 0 ? prefix : bssinfo[idx].wlif_name,
						ETHER_TO_MACF(r_maclist->addr));

					next = r_maclist->next;
					free(r_maclist);
					r_maclist = next;

					if (prev)
						prev->next = r_maclist;

					set_maclist = 1;
					continue;
				}

				if (head == NULL)
					head = r_maclist;

				prev = r_maclist;
				r_maclist = r_maclist->next;
			}
			bssinfo[idx].maclist[vidx] = head;

			if(set_maclist)
				rast_set_maclist(idx, vidx);
		}
	}

	pthread_mutex_unlock(&maclistLock);
}

static int rast_add_static_client(int bssidx, struct ether_addr *addr, uint8 mesh_node)
{
	int ret = 0;
	rast_maclist_t *ptr;
	ptr = bssinfo[bssidx].static_client;

	while(ptr) {
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA)|| defined(RTCONFIG_LANTIQ))
		if(memcmp(&(ptr->addr), addr, ETHER_ADDR_STR_LEN/3) == 0)
#else
		if (eacmp(&(ptr->addr), addr) == 0)
#endif
		{
			if(ptr->mesh_node != mesh_node) 
				ptr->mesh_node = mesh_node;
			break;
		}
		ptr = ptr->next;
	}

	if(!ptr) {
		// add sta to static list
		ptr = malloc(sizeof(rast_maclist_t));
		if(!ptr) {
			RAST_INFO("[%s]: Err: Exiting %d malloc failure", __FUNCTION__, __LINE__);
			return ret;
		}
		memset(ptr, 0, sizeof(rast_maclist_t));
		memcpy(&ptr->addr, addr, sizeof(struct ether_addr));
		ptr->next = bssinfo[bssidx].static_client;
		bssinfo[bssidx].static_client = ptr;
		ptr->timestamp = uptime();
		ptr->mesh_node = mesh_node;
		ret = 1;

		RAST_DBG("[%s] add mac: "MACF" %sto static list (timestamp:%ld)\n",
			bssinfo[bssidx].wlif_name,
			ETHER_TO_MACF(ptr->addr),
			mesh_node ? "<Mesh Node> " : "",
			ptr->timestamp);
	}
	
	return ret;
}

static int rast_is_static_client(int bssidx, struct ether_addr *addr)
{
	rast_maclist_t *ptr;
	ptr = bssinfo[bssidx].static_client;

	while(ptr) {
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA)|| defined(RTCONFIG_LANTIQ))
		if(memcmp(&(ptr->addr), addr, ETHER_ADDR_STR_LEN/3) == 0)
#else
		if (eacmp(&(ptr->addr), addr) == 0)
#endif
			return (ptr->mesh_node || bssinfo[bssidx].static_cli_enable) ? 1 : 0;

		ptr = ptr->next;
	}

	return 0;
}
static void rast_save_mesh_node(int bssidx, char* addr)
{
	FILE *fp;

	if ((fp = fopen(bssinfo[bssidx].tmp_static_client_path, "a")) == NULL) {
                RAST_INFO("Open %s failed!\n", bssinfo[bssidx].tmp_static_client_path);
                return;
        }

        fprintf(fp, addr);
	fprintf(fp,"\n");
	fclose(fp);
}

static void rast_retrieve_mesh_nodes(int bssidx) {

	FILE *fp;
	char buf[32];
	char addr[18];
	struct stat status;
	struct ether_addr ea_tmp; 

	if(stat(bssinfo[bssidx].tmp_static_client_path, &status) != 0)
		return;

	if ((fp = fopen(bssinfo[bssidx].tmp_static_client_path, "r")) == NULL) {
                RAST_INFO("Open %s failed!\n", bssinfo[bssidx].tmp_static_client_path);
                return;
        }

	while (fgets(buf, sizeof(buf), fp)) {
		memset(addr, 0, sizeof(addr));
		sscanf(buf, "%s%*u", addr);
		if (strlen(addr)) {
			rast_add_static_client(bssidx, rast_ether_atoe(addr,&ea_tmp), 1);
		}
	}

	fclose(fp);
}

int rast_event_random_interval()
{
	/* return a random number between 0 and RAST_EVENT_INTERVAL_MAX inclusive */
	int div = RAND_MAX/(RAST_EVENT_INTERVAL_MAX + 1);
	int rval;

	do {
		rval = rand() / div;
	} while(rval > RAST_EVENT_INTERVAL_MAX);

	return rval;
}

// IPC
int rast_ipc_send_event(const char *ipc_path, char *data)
{
	int fd, length;
	int ret = -1;
	struct sockaddr_un addr_un;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		RAST_INFO("ipc socket error!\n");
		goto error;
	}

	memset(&addr_un, 0, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	snprintf(addr_un.sun_path, sizeof(addr_un.sun_path), ipc_path);
	if (connect(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) < 0) {
		RAST_INFO("ipc connect error\n");
		goto error;
	}

	RAST_DBG("IPC Send: %s  <<< SEND EVENT >>>\n", data);

	length = write(fd, data, strlen(data));

        if(length < 0) {
                RAST_INFO("[%s:(%d)] ERROR writing:%s.\n", __FUNCTION__, __LINE__, strerror(errno));
                goto error;
        }

	ret = 1;

error:
        close(fd);
        return ret;
}

static void rast_ipc_receive(int sockfd)
{
	int length = 0;
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	if ((length = read(sockfd, buf, sizeof(buf))) <= 0)
	{
		RAST_DBG("ipc read socket error!\n");
		return;
	}

	RAST_DBG("IPC Receive: %s <<< RCV EVENT >>>\n", buf);

	json_object *rootObj = json_tokener_parse(buf);
	json_object *cfgObj = NULL;
	json_object *eidObj = NULL;
	json_object_object_get_ex(rootObj, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_EVENT_ID, &eidObj);

	int EID = 0;
	struct eventHandler *handler = NULL;

	if(eidObj) {
		EID = atoi(json_object_get_string(eidObj));
		for(handler = &CFG_EVENTS[0]; handler->event_id > 0; handler++)
		{
			if (handler->event_id == EID)
			break;
		}

		if (handler == NULL || handler->event_id < 0)
			RAST_DBG("no corresponding function pointer(%d)", EID);
		else
		{
			RAST_DBG("process event (%d)\n", EID);
#ifdef RTCONFIG_STA_AP_BAND_BIND
			if(EID_RM_STA_BINDING_UPDATE == EID) sleep(2);
#endif


 			if (!handler->func(buf)) {
				RAST_DBG("fail to process event(%d)\n", EID);
			}
		}
	}

	json_object_put(rootObj);
}

static int rast_start_ipc_socket(void)
{
	
#if defined(RTCONFIG_RALINK_MT7621)    
       Set_RAST_CPU();
#endif	
        struct sockaddr_un addr;
        int sockfd, newsockfd;

        if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		RAST_INFO("ipc create socket error!\n");
                exit(-1);
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, RAST_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);

        unlink(RAST_IPC_SOCKET_PATH);

        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
                RAST_INFO("ipc bind socket error!\n");
		exit(-1);
        }

        if (listen(sockfd, RAST_IPC_MAX_CONNECTION) == -1) {
                RAST_INFO("ipc listen socket error!\n");
		exit(-1);
        }

        while (!thread_term) {

		RAST_INFO("ipc accept socket...\n");
                if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			RAST_INFO("ipc accept socket error!\n");
                        continue;
                }

                rast_ipc_receive(newsockfd);
                close(newsockfd);

	}

	return 0;
}

void rast_ipc_socket_thread(void)
{
        pthread_t thread;
        pthread_attr_t attr;

        RAST_DBG("Start ipc socket thread.\n");

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&thread,NULL,(void *)&rast_start_ipc_socket,NULL);
        pthread_attr_destroy(&attr);
#ifdef RTCONFIG_CONNDIAG
#ifdef KEY_ROAMING_EVENT
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
        sleep(1);

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&thread,NULL,(void *)&rast_start_internal_ipc_socket,NULL);
        pthread_attr_destroy(&attr);
#endif
#endif
#endif
#endif  
}


static int rast_req_stamon(int bssidx, int vifidx, char *sta_mac, int rssi, char *band
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	, int support_kv, int stamon_or_11k
#endif
#ifdef RTCONFIG_FORCE_ROAMING
	, int force_roaming , int force_roaming_blocktime, char *target
#endif		
	)
{

	char _RSSI[8], _EID[8], json_data[256], prefix[32], ap_bssid[18];
	unsigned char bssid[ETHER_ADDR_LEN];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	snprintf(_EID, sizeof(_EID), "%d", EID_RM_STA_MON);
	snprintf(_RSSI, sizeof(_RSSI), "%d", rssi);

	/* get served ap bssid */
	if(vifidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d", bssidx, vifidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d", bssidx);

	memset(ap_bssid, 0, sizeof(ap_bssid));
	if (get_iface_hwaddr(nvram_safe_get(strcat_safe(prefix, "_ifname")), bssid) == 0)
		snprintf(ap_bssid, sizeof(ap_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
			bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

	//{RAST:{"EID":"X","STA":"xx:xx:xx:xx:xx:xx","RSSI":"-XX","PIP","xxx.xxx.xxx.xxx","BAND":"XX","RAST_SERVED_AP_BSSID":"xx:xx:xx:xx:xx:xx"}}
	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta_mac));
	json_object_object_add(param, RAST_RSSI, json_object_new_string(_RSSI));
	json_object_object_add(param, RAST_BAND, json_object_new_string(band));
#ifdef RTCONFIG_FRONTHAUL_DWB
	json_object_object_add(param, RAST_BSSIDX, json_object_new_int(bssidx));
	json_object_object_add(param, RAST_VIFIDX, json_object_new_int(vifidx));
#endif
	if (strlen(ap_bssid))
		json_object_object_add(param, RAST_SERVED_AP_BSSID, json_object_new_string(ap_bssid));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)	
	if( support_kv & RAST_SUPPORT_K_PASSIVE_SCAN )
		json_object_object_add(param, RAST_SUPPORT_11K, json_object_new_string("1"));
	if(stamon_or_11k == RSSI_INFO_GATHER_BY_11K)
		json_object_object_add(param, RAST_RSSI_INFO_GATHER_METHOD, json_object_new_string("1"));
	else if(stamon_or_11k == RSSI_INFO_GATHER_BY_STAMON)
		json_object_object_add(param, RAST_RSSI_INFO_GATHER_METHOD, json_object_new_string("2"));
#endif
#ifdef RTCONFIG_FORCE_ROAMING
	if( force_roaming ){
		json_object_object_add(param, RAST_FORCE_ROAMING, json_object_new_string("1"));
		json_object_object_add(param, RAST_FORCE_ROAMING_BLOCKTIME, json_object_new_int(force_roaming_blocktime));
		json_object_object_add(param, RAST_FORCE_ROAMING_TARGET, json_object_new_string(target));
	}
#endif	
	json_object_object_add(root, RAST_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return rast_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);

}

static int rast_rsp_stamon(char *sta_mac, int rssi, char *pap_ip, char *pap_mac, char *band, int rssi_criteria
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,char *target_mac
#endif
	)
{
	char _RSSI[8], _EID[8], _RSSI_CRITERIA[8], json_data[256];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	snprintf(_EID, sizeof(_EID), "%d", EID_RM_STA_MON_REPORT);
	snprintf(_RSSI, sizeof(_RSSI), "%d", rssi);
	snprintf(_RSSI_CRITERIA, sizeof(_RSSI_CRITERIA), "%d", rssi_criteria);

	//{RAST:{"EID":"X","STA":"xx:xx:xx:xx:xx:xx","RSSI":"-XX","PIP","xxx.xxx.xxx.xxx","BAND":"XX","AP_RSSI_CRITERIA":"-XX"}}
	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta_mac));
	json_object_object_add(param, RAST_RSSI, json_object_new_string(_RSSI));
	json_object_object_add(param, RAST_PEERIP, json_object_new_string(pap_ip));
	json_object_object_add(param, RAST_AP, json_object_new_string(pap_mac));
	json_object_object_add(param, RAST_BAND, json_object_new_string(band));
	json_object_object_add(param, RAST_CANDIDATE_AP_RSSI_CRITERIA, json_object_new_string(_RSSI_CRITERIA));
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	json_object_object_add(param, RAST_AP_TARGET_MAC, json_object_new_string(target_mac));
#endif
	json_object_object_add(root, RAST_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return rast_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);

}

static int rast_req_candidate(char *sta_mac, char *candidate_ap_mac, char *band
#ifdef RTCONFIG_FORCE_ROAMING
	,int force_roaming_blocktime
#endif
	)
{
	struct json_object *root = NULL;
	struct json_object *param = NULL;
	char _EID[8], json_data[256];

	snprintf(_EID, sizeof(_EID), "%d", EID_RM_STA_ACL);

	//{RAST:{"EID":"x","STA":"xx:xx:xx:xx:xx:xx","EXCLUDE":"xx:xx:xx:xx:xx:xx","BAND":"XX"}}
	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta_mac));
	json_object_object_add(param, RAST_CANDIDATE_AP, json_object_new_string(candidate_ap_mac));
	json_object_object_add(param, RAST_BAND, json_object_new_string(band));

#ifdef RTCONFIG_FORCE_ROAMING
	//force_roaming_blocktime may not be 0 only in force romaing
	json_object_object_add(param, RAST_FORCE_ROAMING_BLOCKTIME, json_object_new_int(force_roaming_blocktime));
#endif	

	json_object_object_add(root, RAST_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return rast_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);
}

static int rast_Proc_STA_MON(char *data)
{
	// Report sta monitor result
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *staObj = NULL;
	json_object *pipObj = NULL;
	json_object *bandObj = NULL;
	json_object *bssidObj = NULL;
	int idx;
	char staMAC[18], pip[16], band[8], bssid[18];
	int stamon_rssi = 0, rssi_criteria = 0;
	int ret = 0;
	struct ether_addr ea_tmp;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	char targetMAC[18];
#endif
#ifdef RTCONFIG_FRONTHAUL_DWB
	json_object *bssidxObj = NULL;
	json_object *vifidxObj = NULL;
	int bssidx=0,vifidx=0;
	char hwaddr_tmp[32];
#endif

	RAST_DBG("Process STAMON event\n");
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_STA, &staObj);
	json_object_object_get_ex(cfgObj, RAST_PEERIP, &pipObj);
	json_object_object_get_ex(cfgObj, RAST_BAND, &bandObj);
	json_object_object_get_ex(cfgObj, RAST_SERVED_AP_BSSID, &bssidObj);

#ifdef RTCONFIG_FRONTHAUL_DWB
	json_object_object_get_ex(cfgObj, RAST_BSSIDX, &bssidxObj);
	if(bssidxObj) bssidx = json_object_get_int(bssidxObj);
	json_object_object_get_ex(cfgObj, RAST_VIFIDX, &vifidxObj);
	if(vifidxObj) vifidx = json_object_get_int(vifidxObj);
#endif

	if ((staObj && strlen(json_object_get_string(staObj)) > 0) &&
		(pipObj && strlen(json_object_get_string(pipObj)) > 0) &&
		(bandObj && strlen(json_object_get_string(bandObj)) > 0))
	{
		snprintf(staMAC, sizeof(staMAC), "%s", json_object_get_string(staObj));
		snprintf(pip, sizeof(pip), "%s", json_object_get_string(pipObj));
		snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));
		snprintf(bssid, sizeof(bssid), "%s", json_object_get_string(bssidObj));
		nvram_set("nac_bssid", bssid);

		for(idx=0; idx < wlif_count; idx++)
		{
			if( ((bssinfo[idx].band == WL_NBAND_2G) && !strncmp(band, RAST_JVALUE_BAND_2G, strlen(band))) ||
			    ((bssinfo[idx].band == WL_NBAND_5G) && !strncmp(band, RAST_JVALUE_BAND_5G, strlen(band))) )
			{
				if(bssinfo[idx].rast_mode != RAST_MODE_LEGACY)
					continue;
#ifdef RTCONFIG_FRONTHAUL_DWB
				//bssidx==2 vifidx<2 means ssid will different from the main aimesh ssid
				if(idx < 2 && bssidx == 2 && vifidx < 2)
					continue; 
#endif
				RAST_DBG("[%s] perform sta monitor...\n",bssinfo[idx].wlif_name);
				stamon_rssi = rast_stamon_get_rssi(idx, rast_ether_atoe(staMAC,&ea_tmp));
				if(stamon_rssi != 0) {
#ifdef RTCONFIG_FRONTHAUL_DWB
					if( idx > 2 && bssidx == 2 )
					rssi_criteria = (vifidx > 0 && bssinfo[idx].fhdwb_if_enable[vifidx]) 
						? bssinfo[bssidx].user_low_rssi_for_fhdwb_if : bssinfo[bssidx].user_low_rssi;
#else					
					rssi_criteria = bssinfo[idx].user_low_rssi;
#endif
					break;
				}
			}
		}

		if(!stamon_rssi) {
			stamon_rssi = -99; //ensure to feedback result to cfgmnt
			rssi_criteria = -99;
		}

		if(stamon_rssi != 0) {
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			/* get related target 2g/5g mac */
			if(nvram_get_int("re_mode")) 
#if !defined(RTCONFIG_QCA)	
			{	
				if( !strncmp(band, RAST_JVALUE_BAND_2G, strlen(band)) )
					snprintf(targetMAC, sizeof(targetMAC), "%s", nvram_safe_get("wl0.1_hwaddr") );
				else
					snprintf(targetMAC, sizeof(targetMAC), "%s", nvram_safe_get("wl1.1_hwaddr") );
			} else
#endif			       	
			{
				if( !strncmp(band, RAST_JVALUE_BAND_2G, strlen(band)) )
					snprintf(targetMAC, sizeof(targetMAC), "%s", nvram_safe_get("wl0_hwaddr") );
				else
					snprintf(targetMAC, sizeof(targetMAC), "%s", nvram_safe_get("wl1_hwaddr") );
			}
#ifdef RTCONFIG_FRONTHAUL_DWB
			if( idx == 2 && bssidx == 2 && vifidx < 2 ) {
#if !defined(RTCONFIG_QCA)				
				if(nvram_get_int("re_mode"))
					snprintf(hwaddr_tmp,sizeof(hwaddr_tmp),"wl2.1_hwaddr");
				else
#endif					
					snprintf(hwaddr_tmp,sizeof(hwaddr_tmp),"wl2_hwaddr");
				snprintf(targetMAC, sizeof(targetMAC), "%s", nvram_safe_get(hwaddr_tmp) );
			} else if ( idx == 2 && bssidx > 0 && vifidx > 1) {
				if(nvram_get_int("re_mode"))
					vifidx = nvram_get_int("fh_re_mssid_subunit");
				else
					vifidx = nvram_get_int("fh_cap_mssid_subunit");
				
				snprintf(hwaddr_tmp,sizeof(hwaddr_tmp),"wl%d.%d_hwaddr",bssidx,vifidx);
				snprintf(targetMAC, sizeof(targetMAC), "%s", nvram_safe_get(hwaddr_tmp) );				
			} 
#endif

			rast_rsp_stamon(&staMAC[0], stamon_rssi, &pip[0], nvram_safe_get("lan_hwaddr"), &band[0], rssi_criteria, targetMAC);
#else
			rast_rsp_stamon(&staMAC[0], stamon_rssi, &pip[0], nvram_safe_get("lan_hwaddr"), &band[0], rssi_criteria);
#endif
			ret = 1;
		}
	}
	else
	{
		RAST_DBG("incorrect data format!!\n");
	}

	json_object_put(root);

	return ret;
}

static int rast_Proc_CANDIDATE(char *data)
{
	/*
	RAST sent STAMON event, CFGMNT collect stamon result from other AP/RE, then inform adaptive candidate is exist or not
	1. Send out ACL event
	2. Set ACL
	3. Deauth STA
	*/
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *staObj = NULL;
	json_object *candidateObj = NULL;
	json_object *bandObj = NULL;
	json_object *starssiObj = NULL;
	json_object *candidaterssiObj = NULL;
	json_object *candidaterssicriteriaObj = NULL;

	int idx, vidx;
	rast_sta_info_t *sta;
	char staMAC[18], candidate[18], band[8];
	int sta_idx = 0, sta_vidx = 0, found = 0;
	int sta_rssi=0, candidate_rssi=0, candidate_rssi_criteria=0;

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	json_object *candidatetargetmacObj = NULL;
	char candidatetargetmac[18];
	int ignore_legacy=0,ret_11v=-1;
	rast_sta_info_t *sta_tmp;
#ifdef RTCONFIG_FORCE_ROAMING		
	json_object *forceroamingObj=NULL;
	json_object *forceroamingblocktimeObj=NULL;
#endif
#endif

#ifdef RTCONFIG_FORCE_ROAMING
	int force_roaming=0;
	int force_roaming_blocktime=0;
#endif

	struct ether_addr ea_tmp;

	RAST_DBG("Process CANDIDATE event\n");
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_STA, &staObj);
	json_object_object_get_ex(cfgObj, RAST_CANDIDATE_AP, &candidateObj);
	json_object_object_get_ex(cfgObj, RAST_BAND, &bandObj);
	json_object_object_get_ex(cfgObj, RAST_STA_RSSI, &starssiObj);
	json_object_object_get_ex(cfgObj, RAST_CANDIDATE_AP_RSSI, &candidaterssiObj);
	json_object_object_get_ex(cfgObj, RAST_CANDIDATE_AP_RSSI_CRITERIA, &candidaterssicriteriaObj);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	json_object_object_get_ex(cfgObj, RAST_AP_TARGET_MAC, &candidatetargetmacObj);
#ifdef RTCONFIG_FORCE_ROAMING		
	json_object_object_get_ex(cfgObj, RAST_FORCE_ROAMING, &forceroamingObj);
	if(forceroamingObj)
		force_roaming = json_object_get_int(forceroamingObj);
	if(force_roaming) {
		json_object_object_get_ex(cfgObj, RAST_FORCE_ROAMING_BLOCKTIME, &forceroamingblocktimeObj);
		if(forceroamingblocktimeObj)
			force_roaming_blocktime = json_object_get_int(forceroamingblocktimeObj);		
	}
#endif	
#endif

	if ((staObj && strlen(json_object_get_string(staObj)) > 0) &&
			(candidateObj && strlen(json_object_get_string(candidateObj)) > 0) &&
			(bandObj && strlen(json_object_get_string(bandObj)) > 0))
	{
		snprintf(staMAC, sizeof(staMAC), "%s", json_object_get_string(staObj));
		snprintf(candidate, sizeof(candidate), "%s", json_object_get_string(candidateObj));

		if( !isValidUnicastMacAddr(&staMAC[0]) ) {
			RAST_INFO("mac addr format error[%s]\n",staMAC);
			return found;
		}
		if( !isValidUnicastMacAddr(&candidate[0]) ) {
			RAST_INFO("mac addr format error %s\n",candidate);
			return found;
		}

		snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));
		sta_rssi = json_object_get_int(starssiObj);
		candidate_rssi = json_object_get_int(candidaterssiObj);
		if(candidaterssicriteriaObj)
			candidate_rssi_criteria = json_object_get_int(candidaterssicriteriaObj);
		else {
			if(!strcmp(band, RAST_JVALUE_BAND_2G))
				candidate_rssi_criteria = bssinfo[0].user_low_rssi;
			else
				candidate_rssi_criteria = bssinfo[1].user_low_rssi;
		}

		RAST_DBG("discover candidate node [%s](rssi: %ddbm) for weak signal strength client [%s](rssi: %ddbm)\n", 
				candidate, candidate_rssi, staMAC, sta_rssi);

		if(candidate_rssi <= candidate_rssi_criteria) {
			if((candidate_rssi - sta_rssi) > adv_conf.weak_rssi_diff) { //allow to roam
				RAST_DBG("allow to roam [%s] due to weak rssi delta (delta:%d, threshold:%d)\n", staMAC, candidate_rssi - sta_rssi, adv_conf.weak_rssi_diff);
			}
			else {  // reject to roam
				RAST_DBG("reject to roam [%s] due to candidate rssi over threshold(%ddbm)\n", staMAC, candidate_rssi_criteria);
				goto reject;
			}
		}

		RAST_SYSLOG("determine candidate node [%s](rssi: %ddbm) for client [%s](rssi: %ddbm) to roam\n",
			candidate, candidate_rssi, staMAC, sta_rssi);

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		for(idx=0; idx < wlif_count; idx++)
		{		
#ifdef RTCONFIG_FRONTHAUL_DWB
			if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)  continue;
#else		
			if(!bssinfo[idx].user_low_rssi) continue;
#endif
			{
				for(vidx=0; vidx < MAX_SUBIF_NUM; vidx++) {
					if(!vidx && bssinfo[idx].upstream_if) {
						RAST_DBG("ACL skip upstream interface [%s]\n", bssinfo[idx].wlif_name);
						continue;
					}
#ifdef RTCONFIG_FRONTHAUL_DWB
					if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
					{
						if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx])
							continue;
						if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx])
							continue;
					}
#endif
					if(bssinfo[idx].bss_enable[vidx]) {
						sta = bssinfo[idx].assoclist[vidx];
						while(sta && !found) {
							/* find sta in assoclist */
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA)|| defined(RTCONFIG_LANTIQ))
							if(memcmp(&(sta->addr), rast_ether_atoe(staMAC,&ea_tmp), ETHER_ADDR_STR_LEN/3) == 0)
#else
							if(eacmp(&(sta->addr), rast_ether_atoe(staMAC,&ea_tmp)) == 0)
#endif
							{
								sta_idx = idx;
								sta_vidx = vidx;
								sta_tmp = sta;
								found = 1;
								break;
							}
							sta = sta->next;
						}
					}
					if(found)
						break;
				}
			}
			if(found)
				break;
		}

		if(found) {

		/* if we use stamon to gather rssi info and candidate AP do not support KV(old fw or do not open flag) 
		   candidatetargetmacObj will not appear
			*/
		if( 
#ifdef RTCONFIG_FORCE_ROAMING
			!force_roaming &&
#endif
			(check_if_support_kv(sta_idx,sta_vidx,sta_tmp) & RAST_SUPPORT_V) &&
			(candidatetargetmacObj) && (strlen(json_object_get_string(candidatetargetmacObj)))
			) {
			ignore_legacy = 1;			
		}

		if(!ignore_legacy) {
#endif			
		rast_req_candidate(&staMAC[0], &candidate[0], &band[0]
#ifdef RTCONFIG_FORCE_ROAMING
				,force_roaming_blocktime
#endif			
			);

		for(idx=0; idx < wlif_count; idx++)
		{			
#ifdef RTCONFIG_FRONTHAUL_DWB
		if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)  continue;
#else		
		if(!bssinfo[idx].user_low_rssi) continue;
#endif
#if 0
			if( ((bssinfo[idx].band == WL_NBAND_2G) && !strncmp(band, RAST_JVALUE_BAND_2G, strlen(band))) ||
					((bssinfo[idx].band == WL_NBAND_5G) && !strncmp(band, RAST_JVALUE_BAND_5G, strlen(band))) )
#endif
			{
				for(vidx=0; vidx < MAX_SUBIF_NUM; vidx++) {
					if(!vidx && bssinfo[idx].upstream_if) {
						RAST_DBG("ACL skip upstream interface [%s]\n", bssinfo[idx].wlif_name);
						continue;
					}
#ifdef RTCONFIG_FRONTHAUL_DWB
					if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
					{
						if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx])
							continue;
						if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx])
							continue;
					}
#endif					
					if(bssinfo[idx].bss_enable[vidx]) {
						rast_add_to_maclist(idx, vidx, rast_ether_atoe(staMAC,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
							,force_roaming_blocktime
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
							,RAST_NOT_A_STAAPBANDBIND_ACTION
#endif
						); // set acl in all enabled bss
						sta = bssinfo[idx].assoclist[vidx];
						while(sta && !found) {
							/* find sta in assoclist */
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA)|| defined(RTCONFIG_LANTIQ))
							if(memcmp(&(sta->addr), rast_ether_atoe(staMAC,&ea_tmp), ETHER_ADDR_STR_LEN/3) == 0)
#else
							if(eacmp(&(sta->addr), rast_ether_atoe(staMAC,&ea_tmp)) == 0)
#endif
							{
								sta_idx = idx;
								sta_vidx = vidx;
								found = 1;
								break;
							}
							sta = sta->next;
						}
					}
				}
			}
		}
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		}
		}
#endif	

		if(found) {
#if 0
#ifdef CONFIG_BCMWL5
			/* send 11v BSS Transition Managemen frame */
			rast_send_bsstrans_req(sta_idx, sta_vidx, rast_ether_atoe(staMAC), rast_ether_atoe(candidate));
#endif
#endif
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			if( ignore_legacy && strlen(candidate) )
			{
				if( candidatetargetmacObj ) 
					snprintf(candidatetargetmac, sizeof(candidatetargetmac), "%s", json_object_get_string(candidatetargetmacObj));
				else {
					RAST_INFO("error, no target ap mac\n");
					goto reject;
				}

				if( !isValidUnicastMacAddr(&candidatetargetmac[0]) )
				{
					RAST_INFO("mac format error [%s]\n",candidatetargetmac);
					goto reject;
				}

				if( (ret_11v = rast_send_11v_req( sta_idx, sta_vidx, &staMAC[0], &candidatetargetmac[0])) != BTM_RET_ACCEPT_TARGETMAC_NOTSELF) {
					//goto reject;
					RAST_INFO("11v ret = %d\n",ret_11v);
				}

				RAST_SYSLOG("Roam a client [%s], status [%d]\n", staMAC, ret_11v);
			}
#endif

#ifdef RTCONFIG_CONNDIAG
#ifdef KEY_ROAMING_EVENT
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifndef RTCONFIG_CONN_EVENT_TO_EX_AP
			_assign_roaming_tbl(&staMAC[0], sta_rssi, candidate_rssi_criteria, &candidate[0], candidate_rssi, ret_11v);
#else
			_assign_roaming_tbl_before_recv_exap_info(&staMAC[0], sta_rssi, candidate_rssi_criteria, &candidate[0], candidate_rssi,ret_11v,candidatetargetmac);
#endif //#ifndef RTCONFIG_CONN_EVENT_TO_EX_AP
#else
			_assign_roaming_tbl(&staMAC[0], sta_rssi, candidate_rssi_criteria, &candidate[0], candidate_rssi );
#endif //#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#endif //KEY_ROAMING_EVENT
#endif //RTCONFIG_CONNDIAG

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			if(!ignore_legacy){
#endif			
			rast_deauth_sta(sta_idx, sta_vidx, rast_ether_atoe(staMAC,&ea_tmp));
			rast_remove_from_assoclist(sta_idx, sta_vidx, rast_ether_atoe(staMAC,&ea_tmp)
#ifdef RTCONFIG_STA_AP_BAND_BIND
						,0
#endif
				);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
			}
#endif
		}
	}

reject:
	json_object_put(root);

	return found;

}

static int rast_Proc_STA_ACL(char *data)
{
	// Set ACL
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *staObj = NULL;
	json_object *bandObj = NULL;
	char staMAC[18], band[8];
	int idx, vidx;
	int ret = 0;
	struct ether_addr ea_tmp;
	RAST_DBG("Process ACL event\n");
#ifdef RTCONFIG_FORCE_ROAMING
	json_object *forceroamingblocktimeObj = NULL;
	int force_roaming_blocktime=0;
#endif
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_STA, &staObj);
	json_object_object_get_ex(cfgObj, RAST_BAND, &bandObj);
#ifdef RTCONFIG_FORCE_ROAMING
	json_object_object_get_ex(cfgObj, RAST_FORCE_ROAMING_BLOCKTIME, &forceroamingblocktimeObj);
	if(forceroamingblocktimeObj) force_roaming_blocktime = json_object_get_int(forceroamingblocktimeObj);
#endif
	if ((staObj && strlen(json_object_get_string(staObj)) > 0) &&
			(bandObj && strlen(json_object_get_string(bandObj)) > 0))
	{
		snprintf(staMAC, sizeof(staMAC), "%s", json_object_get_string(staObj));
		snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));

		for(idx=0; idx < wlif_count; idx++) {
		
#ifdef RTCONFIG_FRONTHAUL_DWB
		if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)  continue;
#else		
		if(!bssinfo[idx].user_low_rssi) continue;
#endif
#if 0
			if( ((bssinfo[idx].band == WL_NBAND_2G) && !strncmp(band, RAST_JVALUE_BAND_2G, strlen(band))) ||
					((bssinfo[idx].band == WL_NBAND_5G) && !strncmp(band, RAST_JVALUE_BAND_5G, strlen(band))) )
#endif
			{
				for(vidx=0; vidx < MAX_SUBIF_NUM; vidx++) {
					if(!vidx && bssinfo[idx].upstream_if) {
						RAST_DBG("ACL skip upstream interface [%s]\n", bssinfo[idx].wlif_name);
						continue;
					}
#ifdef RTCONFIG_FRONTHAUL_DWB
					if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
					{
						if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx])
							continue;
						if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx])
							continue;
					}
#endif					
					if(bssinfo[idx].bss_enable[vidx])
						rast_add_to_maclist(idx, vidx, rast_ether_atoe(staMAC,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
							,force_roaming_blocktime
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
							,RAST_NOT_A_STAAPBANDBIND_ACTION
#endif
						); // set acl in all enabled bss
				}
			}
		}
		ret = 1;
	}

	json_object_put(root);

	return ret;
}

static int rast_Proc_STA_STATIC(char *data)
{
	// Set static client
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *sta_2gObj = NULL;
	json_object *sta_5gObj = NULL;
	char staMAC_2G[18], staMAC_5G[18];
	int idx;
	int ret = 0;
	struct ether_addr ea_tmp;

	RAST_DBG("Process STA STATIC event\n");
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_STA_2G, &sta_2gObj);
	json_object_object_get_ex(cfgObj, RAST_STA_5G, &sta_5gObj);

	if ((sta_2gObj && strlen(json_object_get_string(sta_2gObj)) > 0) ||
		(sta_5gObj && strlen(json_object_get_string(sta_5gObj)) > 0))
	{
		if(sta_2gObj) snprintf(staMAC_2G, sizeof(staMAC_2G), "%s", json_object_get_string(sta_2gObj));
		if(sta_5gObj) snprintf(staMAC_5G, sizeof(staMAC_5G), "%s", json_object_get_string(sta_5gObj));

		for(idx=0; idx < wlif_count; idx++) {
			if((sta_2gObj) && bssinfo[idx].band == WL_NBAND_2G)
			{
				if(rast_add_static_client(idx, rast_ether_atoe(staMAC_2G,&ea_tmp), 1) > 0)
					rast_save_mesh_node(idx, &staMAC_2G[0]);
				ret = 1;
			}

			if((sta_5gObj) && bssinfo[idx].band == WL_NBAND_5G)
			{
				if(rast_add_static_client(idx, rast_ether_atoe(staMAC_5G,&ea_tmp), 1) > 0)
					rast_save_mesh_node(idx, &staMAC_5G[0]);
				ret = 1;
			}

		}
	}

	json_object_put(root);

	return ret;
}

static char *print_rate_buf(int raw_rate, char *buf, int buf_len){
	if (!buf) return NULL;

	if (raw_rate == -1) memset(buf, 0, buf_len);
	else if ((raw_rate % 1000) == 0)
		snprintf(buf, buf_len, "%d", raw_rate / 1000);
	else
		snprintf(buf, buf_len, "%.1f", (double) raw_rate / 1000);

	return buf;
}

#if 0
static int rast_trigger_staapbandbind(int sig)
{
	struct json_object *root = NULL;
	struct json_object *param = NULL;
	char _EID[8], json_data[256];

	snprintf(_EID, sizeof(_EID), "%d", EID_RM_STA_BINDING_UPDATE);

	//{RAST:{"EID":"x","STA":"xx:xx:xx:xx:xx:xx","EXCLUDE":"xx:xx:xx:xx:xx:xx","BAND":"XX"}}
	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));

	json_object_object_get_ex(param, RAST_TRIGGER_STA_AP_BAND_BIND, json_object_new_int(1));

	json_object_object_add(root, CFG_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return rast_ipc_send_event(RAST_IPC_SOCKET_PATH, &json_data[0]);
}
#endif
static void print_sta_info(int sig){
	int idx, vidx;
	rast_sta_info_t *sta;
	char buff[32], tx_rate[32], rx_rate[32];

	for(idx = 0; idx < wlif_count; idx++){		
#ifdef RTCONFIG_FRONTHAUL_DWB
		if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)  continue;
#else		
		if(!bssinfo[idx].user_low_rssi) continue;
#endif

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++){
			if(vidx > 0){
				if(!bssinfo[idx].bss_enable[vidx])
					continue;
			}
#ifdef RTCONFIG_FRONTHAUL_DWB
			if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
			{
				if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx])
					continue;
				if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx])
					continue;
			}
#endif
			sta = bssinfo[idx].assoclist[vidx];
			while(sta){
				snprintf(buff, sizeof(buff), MACF_UP, ETHER_TO_MACF(sta->addr));

				_dprintf("%s(%d)(%d) sta [%s]: %d RSSI %d, Tx rate %s M, Rx rate %s M\n",
						(bssinfo[idx].band == WL_NBAND_2G)? "2G" : "5G",
						idx,
						bssinfo[idx].user_low_rssi,
						buff,
						sta->active,
						sta->rssi,
						print_rate_buf(sta->tx_rate, tx_rate, sizeof(tx_rate)),
						print_rate_buf(sta->rx_rate, rx_rate, sizeof(rx_rate))
						);

				sta = sta->next;
			}
		}
	}
#ifdef RTCONFIG_CONNDIAG
	_show_tg_roaming_tbl(sig);
#ifdef KEY_ROAMING_EVENT
	_show_roaming_tbl(sig);
#endif
#endif
}
static void usr2_processer(int sig)
{
#if 0	
	if( nvram_get_int("trigger_staapbandbind") == 1 )
	{
		//send a event to roamast
		nvram_unset("trigger_staapbandbind");
		RAST_INFO("process rast_trigger_staapbandbind\n");
		rast_trigger_staapbandbind(sig);
		return;
	}
#endif
	print_sta_info(sig);
}

#endif

#ifdef RTCONFIG_MULTILAN_CFG
static int check_interface_in_multi_lan_cfg(idx, vidx) {

	char word[64];
	char *next = NULL;
	int j, total = 0;
	int multilan_unit = -1, multilan_subunit = -1;

	ap_wifi_rule_st ap_wifi_rl[MAX_AP_RULE_LIST];
	memset(ap_wifi_rl, 0, (sizeof(ap_wifi_rule_st) * MAX_AP_RULE_LIST));

	if (get_ap_wifi_rl_from_nvram(ap_wifi_rl, MAX_AP_RULE_LIST, &total) && total > 0) {

		for (j=0; j<total; j++) {

			foreach_44(word, ap_wifi_rl[j].wlif_set, next) {

				sscanf(word, "wl%d.%d", &multilan_unit, &multilan_subunit);
				
				if (idx==multilan_unit && vidx==multilan_subunit) {
					return 1;
				}
			}
		}
	}

	return 0;
}
#endif

static void rast_watchdog(int sig)
{
	int idx,vidx;
	char prefix[32];
	int roaming_enable;
	int mesh_primary = 0;
#ifdef RTCONFIG_FORCE_ROAMING
	struct force_roaming_list *fr_tmp=NULL;
#endif
#if defined(RTCONFIG_STA_AP_BAND_BIND) || defined(RTCONFIG_FORCE_ROAMING)
	int no_normal_roaming;
#endif	
#ifdef RTCONFIG_LANTIQ
	if(!nvram_get_int("wave_ready"))
#elif defined(RTCONFIG_QCA)
	if(!nvram_get_int("wlready") || !nvram_match("relist_ready", "1"))
#else
	if(!nvram_get_int("wlready"))
#endif
		return;

#ifdef RTCONFIG_AMAS
	mesh_primary = !nvram_get_int("re_mode");
#endif

	if(init) {
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
		int cfg_master = nvram_get_int("cfg_master");
		int re_mode = nvram_get_int("re_mode");
		/* not CAP,not RE,but need roamast */
		if( cfg_master == 0 && re_mode == 0 && is_support_rast_nonmesh() ){
			RAST_INFO("roamast non-mesh with kv\n");
			rast_nonmesh_kvonly=1;
		}
#endif

		rast_init_bssinfo();
#ifdef RTCONFIG_ADV_RAST
		rast_adv_init();
		if (pthread_mutex_init(&roamastBssinfoLock, NULL) != 0) {
			_dprintf("mutex init failed for roamastBssinfoLock");
			init = 1;
			return;
		}		
#endif
#ifdef RTCONFIG_BCN_RPT
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
		if(!rast_nonmesh_kvonly)//in this mode, do not need to create 11k receive thread
#endif
		rast_bcn_rpt_init();
#endif

#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
#ifdef RTCONFIG_CONNDIAG
#ifdef KEY_ROAMING_EVENT
		memset(&tmp_roaming_tbl,0,sizeof(ROAMING_TABLE));
		memset(tmp_roaming_tbl_used,0,sizeof(tmp_roaming_tbl_used));
		memset(tmp_roaming_tbl_tstamp_reflash,0,sizeof(tmp_roaming_tbl_tstamp_reflash));
#endif
#endif
#endif
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
		if (pthread_mutex_init(&roaminglistLock, NULL) != 0) {
			_dprintf("mutex init failed for roaminglistLock");
			init = 1;
			return;
		}
#endif
#ifdef RTCONFIG_FORCE_ROAMING
		if (pthread_mutex_init(&forceroaminglistLock, NULL) != 0) {
			_dprintf("mutex init failed for forceroaminglistLock");
			init = 1;
			return;
		}
#endif
		if (pthread_mutex_init(&maclistLock, NULL) != 0) {
			_dprintf("mutex init failed for maclistLock");
			init = 1;
			return;
		}

#ifdef RTCONFIG_STA_AP_BAND_BIND
		rast_Proc_STA_BINDING_UPDATE(NULL);
		cfg_rejoin_pre=0;
		cfg_rejoin_pre_done=0;
#endif
		init = 0;
		return;
	}

#ifdef RTCONFIG_ADV_RAST
	if(!nvram_match("cfg_rejoin", "1")
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
	 && (rast_nonmesh_kvonly == 0) 
#endif
	)
#ifdef RTCONFIG_STA_AP_BAND_BIND
	{
		if(cfg_rejoin_pre_done == 1)
		{
			RAST_DBG("cfg_rejoin_pre_done=1\n");
			//cfg_rejoin_pre = 0;
			//cfg_rejoin_pre_done = 0;
		} else
#endif	 
		;//_dprintf("test only\n");//return;//
#ifdef RTCONFIG_STA_AP_BAND_BIND
	} else {
		//RAST_DBG("cfg_rejoin_pre=1\n");
		cfg_rejoin_pre = 1;
	}

	if(cfg_rejoin_pre_done == 1)
	{
		RAST_DBG("cfg_rejoin_pre_done=1 run one more time\n");
		cfg_rejoin_pre = 0;
		cfg_rejoin_pre_done = 0;
	}else{
#endif	
	alarm_count = (alarm_count + 1) % RAST_POLL_INTV_NORMAL;
#ifdef RTCONFIG_STA_AP_BAND_BIND
	}
#endif

	rast_timeout_maclist();
	if(alarm_count) return;
#endif

#ifdef RTCONFIG_FORCE_ROAMING
		pthread_mutex_lock(&forceroaminglistLock);
		//RAST_DBG("checking if we have force roaming sta\n");
		if(fr_head){
			RAST_DBG("got one force roaming sta\n");
			fr_tmp = fr_head;
			fr_head = fr_head->next;
		}
		pthread_mutex_unlock(&forceroaminglistLock);
#endif

	for(idx=0; idx < wlif_count; idx++) {

		roaming_enable=1;//will be modified to 0 if needed

#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_LANTIQ))
#ifdef RTCONFIG_FRONTHAUL_DWB
		if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)
#else		
		if(!bssinfo[idx].user_low_rssi)
#endif
#if defined(RTCONFIG_STA_AP_BAND_BIND) || defined(RTCONFIG_FORCE_ROAMING)
		{
			if(fr_tmp == NULL) roaming_enable=0;
			no_normal_roaming = 1;
		}
#else
			roaming_enable=0;
#endif

#if defined(RTCONFIG_REALTEK)
		if (!get_radio(idx, 0)) {
			RAST_DBG("%s radio is disabled!\n", bssinfo[idx].wlif_name);
			continue;
		}
#endif

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++) {
			//skip upstream interface
			if( vidx == 0 && bssinfo[idx].upstream_if)
				continue;
#ifdef RTCONFIG_FRONTHAUL_DWB
			if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
			{
				if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx])
					roaming_enable=0;
				if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx])
					roaming_enable=0;
			}
#endif
			if(vidx > 0
#ifdef RTCONFIG_FRONTHAUL_DWB
				&& (bssinfo[idx].fhdwb_if_enable[vidx] == 0)
#endif
#ifdef RTCONFIG_AMAS_WGN
				//amas wgn now support first guest network only
				&& ( (mesh_primary && vidx != 1) || (!mesh_primary && vidx != 2) )
#endif
				) {
#ifdef RTCONFIG_AMAS
				if ( (
					//if RTCONFIG_AMAS_WGNis not enabled, only fhdwb will be accepted
					( mesh_primary || (!mesh_primary && vidx > 1) )
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
					&& !rast_nonmesh_kvonly
#endif
					) && bssinfo[idx].rast_mode == RAST_MODE_LEGACY){
					continue;
					}
#endif
				if (repeater_mode() || psr_mode()) continue;
			}
			if (!bssinfo[idx].bss_enable[vidx]) continue;
            snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);
			RAST_DBG("[%s]: StaInfo[%s], RssiCriteria[%d]\n", __FUNCTION__,
					vidx > 0 ? nvram_safe_get(strcat_safe(prefix, "_ifname")) : bssinfo[idx].wlif_name,
					bssinfo[idx].user_low_rssi );
#ifdef RTCONFIG_FORCE_ROAMING
			rast_update_sta_info(idx,vidx,roaming_enable,fr_tmp,no_normal_roaming);
#else			
			rast_update_sta_info(idx,vidx,roaming_enable);
#endif
	       	}
#else /* BCM */
		int val;
#ifdef RTCONFIG_AMAS_WGN
		int amas_wgn_enabled;
		char nvram_tmp[32];
#endif
#ifdef RTCONFIG_FRONTHAUL_DWB
		if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].user_low_rssi_for_fhdwb_if)
#else
		if(!bssinfo[idx].user_low_rssi) 
#endif
#if defined(RTCONFIG_STA_AP_BAND_BIND) || defined(RTCONFIG_FORCE_ROAMING)
		{
			if(fr_tmp == NULL) roaming_enable=0;
			no_normal_roaming = 1;
		}
#else
			roaming_enable=0;
#endif
//#ifdef RTCONFIG_PROXYSTA
//#ifndef RTCONFIG_ADV_RAST
//		if(psta_exist_except(idx) || psr_exist_except(idx)) continue;
//		else if(is_psta(idx) || is_psr(idx))	continue;
//#endif
//#endif

		wl_ioctl(bssinfo[idx].wlif_name, WLC_GET_RADIO, &val, sizeof(val));
		val &= WL_RADIO_SW_DISABLE | WL_RADIO_HW_DISABLE;
		if(val) {
			RAST_DBG("%s radio is disabled!\n", bssinfo[idx].wlif_name);
			continue;
		}

		if ((repeater_mode() || psr_mode()) &&
			(nvram_get_int("wlc_band")) == idx)
		{
			RAST_DBG("### Check stainfo [wl%d.%d][rssi criteria = %d] ###\n",
			idx,
			1,
			bssinfo[idx].user_low_rssi);

#ifdef RTCONFIG_FORCE_ROAMING
			rast_update_sta_info(idx,1,roaming_enable,fr_tmp,no_normal_roaming);
#else			
			rast_update_sta_info(idx,1,roaming_enable);
#endif
			continue;
		}

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++) {

			//skip upstream interface
			if( vidx == 0 && bssinfo[idx].upstream_if)
				continue;

#ifdef RTCONFIG_FRONTHAUL_DWB
			if( idx > 1 && ((!bssinfo[idx].user_low_rssi || !bssinfo[idx].user_low_rssi_for_fhdwb_if)) )
			{
				if(!bssinfo[idx].user_low_rssi && !bssinfo[idx].fhdwb_if_enable[vidx])
					roaming_enable=0;
				if(!bssinfo[idx].user_low_rssi_for_fhdwb_if && bssinfo[idx].fhdwb_if_enable[vidx])
					roaming_enable=0;
			}
#endif
			
#ifdef RTCONFIG_AMAS_WGN
			//amas wgn now support first guest network only
			if( ( mesh_primary && vidx == 1 ) || (!mesh_primary && vidx == 2 ) ){
				snprintf(nvram_tmp,sizeof(nvram_tmp),"wl%d.%d_bss_enabled",idx,vidx);
				amas_wgn_enabled = nvram_get_int(nvram_tmp);
			} else
				amas_wgn_enabled = 0;
#endif

			if( vidx > 0
#ifdef RTCONFIG_FRONTHAUL_DWB
				&& (bssinfo[idx].fhdwb_if_enable[vidx] == 0 )
#endif
#ifdef RTCONFIG_AMAS_WGN
				&& ( !amas_wgn_enabled )
#endif
				) {
#ifdef RTCONFIG_AMAS
				if ( (
					//if RTCONFIG_AMAS_WGNis not enabled, only fhdwb will be accepted
					( mesh_primary || (!mesh_primary && vidx > 1) )
#ifdef RTCONFIG_MULTILAN_CFG
					&& !check_interface_in_multi_lan_cfg(idx, vidx) 
#endif
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
					&& !rast_nonmesh_kvonly
#endif
					) && bssinfo[idx].rast_mode == RAST_MODE_LEGACY) {

					continue;
				}
#endif
				if(!bssinfo[idx].bss_enable[vidx])
					continue;
			}

			if(vidx > 0) snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);

			RAST_DBG("### Check stainfo [%s][rssi criteria = %d] ###\n",
				vidx > 0 ? prefix : bssinfo[idx].wlif_name,
#ifdef RTCONFIG_FRONTHAUL_DWB
				(vidx > 0 && bssinfo[idx].fhdwb_if_enable[vidx]) 
				? bssinfo[idx].user_low_rssi_for_fhdwb_if : bssinfo[idx].user_low_rssi);
#else
				bssinfo[idx].user_low_rssi);
#endif

#ifdef RTCONFIG_FORCE_ROAMING
			rast_update_sta_info(idx,vidx,roaming_enable,fr_tmp,no_normal_roaming);
#else			
			rast_update_sta_info(idx,vidx,roaming_enable);
#endif
		}
#endif
	}
#ifdef RTCONFIG_FORCE_ROAMING
	if(fr_tmp) {
		RAST_DBG("free fr_tmp\n");
		free(fr_tmp);
		fr_tmp=NULL;
	}
#endif	
}

static void rast_exit(int sig)
{
	/* free assoclist */
	int i, vi;
	rast_sta_info_t *assoclist, *next;
#ifdef RTCONFIG_ADV_RAST
	rast_maclist_t *maclist_r, *m_next;
	thread_term = 1;
#endif
#ifdef RTCONFIG_RAST_NONMESH_KVONLY
	kv_thread_term = 1;
#endif
	alarmtimer(0, 0);

	for(i = 0; i < wlif_count; i++) {
#ifdef RTCONFIG_ADV_RAST
		maclist_r = bssinfo[i].static_client;
		while(maclist_r) {
			m_next = maclist_r->next;
			free(maclist_r);
			maclist_r = m_next;
		}
#endif
		for(vi = 0; vi < MAX_SUBIF_NUM; vi++) {
			assoclist = bssinfo[i].assoclist[vi];
			while(assoclist) {
				next = assoclist->next;
				free(assoclist);
				assoclist = next;
			}
#ifdef RTCONFIG_ADV_RAST
			maclist_r = bssinfo[i].maclist[vi];
			while(maclist_r) {
				m_next = maclist_r->next;
				free(maclist_r);
				maclist_r = m_next;
			}

			bssinfo[i].static_maclist[vi] = NULL;
#endif
		}
	}

	if(strcat_buf){
		free(strcat_buf);
	}

#ifdef RTCONFIG_CONNDIAG
	_del_tg_roaming_tbl(sig);
#ifdef KEY_ROAMING_EVENT
	_del_roaming_tbl(sig);
#endif
#endif

	RAST_INFO("ROAMAST Exit...\n");
	remove("/var/run/roamast.pid");
	exit(0);
}

#if 0
/*** routines for testing ***/
void rast_test_send_bss_trans_req() {
	char* sta_mac;
	char* candidate_mac;
	int idx=0, vidx=0;

	sta_mac = nvram_get("rast_11vtest_sta");
	candidate_mac = nvram_get("rast_11vtest_ap");
	idx = nvram_get_int("rast_11vtest_idx");
	vidx = nvram_get_int("rast_11vtest_vidx");

	if(strlen(sta_mac) != 17 ) {
		RAST_INFO("[RAST_TEST] Station MAC invalid!!!\n");
		return;
	}

	if(strlen(candidate_mac) != 17 ) {
		RAST_INFO("[RAST_TEST] AP MAC invalid!!!\n");
		return;
	}

	RAST_INFO("[RAST_TEST] Send bss transition management frame sta:%s, ap:%s, idx:%d, vidx:%d\n",
			sta_mac, candidate_mac, idx, vidx);
	rast_send_bsstrans_req(idx, vidx, rast_ether_atoe(sta_mac), rast_ether_atoe(candidate_mac));

	return;
}
#endif

#ifdef RTCONFIG_CONNDIAG
static void _update_tg_roaming_tbl(int order, char *sta, int band_unit, int sta_rssi, int user_low_rssi, int rssi_cnt, int idle_period, int idle_start){
#if 0
	int lock;

	if(order < 0){
		_assign_tg_roaming_tbl(sta, band_unit, sta_rssi, user_low_rssi, rssi_cnt, idle_period, idle_start);
		return;
	}

	lock = file_lock(TG_ROAMING_LOCK);

	memcpy(p_tg_roaming_tbl->sta[order], sta, MAC_LEN);
	p_tg_roaming_tbl->band_unit[order] = band_unit;
	p_tg_roaming_tbl->sta_rssi[order] = sta_rssi;
	p_tg_roaming_tbl->tstamp[order] = time(NULL);
	p_tg_roaming_tbl->user_low_rssi[order] = user_low_rssi;
	p_tg_roaming_tbl->rssi_cnt[order] = rssi_cnt;
	p_tg_roaming_tbl->idle_period[order] = idle_period;
	p_tg_roaming_tbl->idle_start[order] = idle_start;

	file_unlock(lock);
#endif	
}

static void _add_tg_roaming_tbl(char *sta, int band_unit, int sta_rssi, int user_low_rssi, int rssi_cnt, int idle_period, int idle_start){
#if 0
	int lock;

	if(p_tg_roaming_tbl->total >= MAX_STA_COUNT){
		if(TYPE_tbl == 1)
			_update_tg_roaming_tbl((p_tg_roaming_tbl->total % MAX_STA_COUNT), sta, band_unit, sta_rssi, user_low_rssi, rssi_cnt, idle_period, idle_start);
		else
			RAST_INFO("client table was full");
		return;
	}

	lock = file_lock(TG_ROAMING_LOCK);

	memcpy(p_tg_roaming_tbl->sta[p_tg_roaming_tbl->total], sta, MAC_LEN);
	p_tg_roaming_tbl->band_unit[p_tg_roaming_tbl->total] = band_unit;
	p_tg_roaming_tbl->sta_rssi[p_tg_roaming_tbl->total] = sta_rssi;
	p_tg_roaming_tbl->tstamp[p_tg_roaming_tbl->total] = time(NULL);
	p_tg_roaming_tbl->user_low_rssi[p_tg_roaming_tbl->total] = user_low_rssi;
	p_tg_roaming_tbl->rssi_cnt[p_tg_roaming_tbl->total] = rssi_cnt;
	p_tg_roaming_tbl->idle_period[p_tg_roaming_tbl->total] = idle_period;
	p_tg_roaming_tbl->idle_start[p_tg_roaming_tbl->total] = idle_start;

	++(p_tg_roaming_tbl->total);

	file_unlock(lock);
#endif
}

static void _assign_tg_roaming_tbl(char *sta, int band_unit, int sta_rssi, int user_low_rssi, int rssi_cnt, int idle_period, int idle_start){
#if 0
	int i = 0, found = 0;

	//RAST_INFO("sta %s, band_unit %d, sta_rssi %d.\n",
	//		sta, band_unit, sta_rssi);

	if(TYPE_tbl == 0){
		for(i = 0, found = 0; i < p_tg_roaming_tbl->total; i++){
			if(!memcmp(p_tg_roaming_tbl->sta[i], sta, MAC_LEN) && p_tg_roaming_tbl->band_unit[i] == band_unit){
				_update_tg_roaming_tbl(i, sta, band_unit, sta_rssi, user_low_rssi, rssi_cnt, idle_period, idle_start);
				found = 1;
				break;
			}
		}
	}

	if(!found)
		_add_tg_roaming_tbl(sta, band_unit, sta_rssi, user_low_rssi, rssi_cnt, idle_period, idle_start);
#endif
}

static void _del_tg_roaming_tbl(int sig){
#if 0	
	int lock;

	lock = file_lock(TG_ROAMING_LOCK);

	/* detach shared memory */
	if(shmdt(p_tg_roaming_tbl) == -1)
		RAST_INFO("detach shared memory failed");

	/* destroy shared memory */
	if(shmctl(shm_tg_roaming_tid, IPC_RMID, 0) == -1)
		RAST_INFO("destroy shared memory failed");

	file_unlock(lock);
#endif
}

static void _wipe_tg_roaming_tbl(int sig){
#if 0	
	int lock;

	lock = file_lock(TG_ROAMING_LOCK);

	memset(p_tg_roaming_tbl, 0, sizeof(TG_ROAMING_TABLE));
	p_tg_roaming_tbl->total = 0;

	file_unlock(lock);
#endif	
}

static void _show_tg_roaming_tbl(int sig){
#if 0	
	int lock;
	int i;

	lock = file_lock(TG_ROAMING_LOCK);

	_dprintf("ROAMING: tg_roaming count %d.\n", p_tg_roaming_tbl->total);
	for(i = 0; i < p_tg_roaming_tbl->total; i++){
		_dprintf("ROAMING: tg_roaming %s, %d, %d, %lu, %d, %d, %d, %lu.\n",
				p_tg_roaming_tbl->sta[i], p_tg_roaming_tbl->band_unit[i], p_tg_roaming_tbl->sta_rssi[i],
				p_tg_roaming_tbl->tstamp, p_tg_roaming_tbl->user_low_rssi[i], p_tg_roaming_tbl->rssi_cnt[i],
				p_tg_roaming_tbl->idle_period[i], p_tg_roaming_tbl->idle_start[i]
				);
	}

	file_unlock(lock);
#endif
}

#ifdef KEY_ROAMING_EVENT
static void _update_roaming_tbl(int order, char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	, const char *present_ap
#endif
#endif
	){
#if 0	
	int lock;

	if(order < 0){
		_assign_roaming_tbl(sta, sta_rssi, candidate_rssi_criteria, candidate, candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		,ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
		,present_ap
#endif
#endif	
			);
		return;
	}

	lock = file_lock(ROAMING_LOCK);

	memcpy(p_roaming_tbl->sta[order], sta, MAC_LEN);
	p_roaming_tbl->sta_rssi[order] = sta_rssi;
	p_roaming_tbl->tstamp[order] = time(NULL);
	p_roaming_tbl->candidate_rssi_criteria[order] = candidate_rssi_criteria;
	memcpy(p_roaming_tbl->candidate[order], candidate, MAC_LEN);
	p_roaming_tbl->candidate_rssi[order] = candidate_rssi;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	p_roaming_tbl->ret_11v[order] = ret_11v;
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	memcpy(p_roaming_tbl->present_ap[order], present_ap, MAC_LEN);
#endif
#endif
	file_unlock(lock);
#endif
}

static void _add_roaming_tbl(char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	, const char *present_ap
#endif
#endif	
	){
#if 0
	int lock;

	if(p_roaming_tbl->total >= MAX_STA_COUNT){
		if(TYPE_tbl == 1)
			_update_roaming_tbl((p_roaming_tbl->total % MAX_STA_COUNT), sta, sta_rssi, candidate_rssi_criteria, candidate, candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
				,ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
				,present_ap
#endif
#endif
				);
		else
			RAST_INFO("client table was full");
		return;
	}

	lock = file_lock(ROAMING_LOCK);

	memcpy(p_roaming_tbl->sta[p_roaming_tbl->total], sta, MAC_LEN);
	p_roaming_tbl->sta_rssi[p_roaming_tbl->total] = sta_rssi;
	p_roaming_tbl->tstamp[p_roaming_tbl->total] = time(NULL);
	p_roaming_tbl->candidate_rssi_criteria[p_roaming_tbl->total] = candidate_rssi_criteria;
	memcpy(p_roaming_tbl->candidate[p_roaming_tbl->total], candidate, MAC_LEN);
	p_roaming_tbl->candidate_rssi[p_roaming_tbl->total] = candidate_rssi;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	p_roaming_tbl->ret_11v[p_roaming_tbl->total] = ret_11v;
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	memcpy(p_roaming_tbl->present_ap[p_roaming_tbl->total], present_ap, MAC_LEN);
#endif
#endif
	++(p_roaming_tbl->total);

	file_unlock(lock);
#endif
}

static void _assign_roaming_tbl(char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
	,int ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	, const char *present_ap
#endif
#endif
	){
#if 0
	int i = 0, found = 0;

	//RAST_INFO("sta %s, sta_rssi %d, candidate_rssi_criteria %d, candidate %s, candidate_rssi %d.\n",
	//		sta, sta_rssi, candidate_rssi_criteria, candidate, candidate_rssi);

	if(TYPE_tbl == 0){
		for(i = 0, found = 0; i < p_roaming_tbl->total; i++){
			if(!memcmp(p_roaming_tbl->sta[i], sta, MAC_LEN)){
				_update_roaming_tbl(i, sta, sta_rssi, candidate_rssi_criteria, candidate, candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
					,ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
					,present_ap
#endif
#endif	
					);
				found = 1;
				break;
			}
		}
	}

	if(!found)
		_add_roaming_tbl(sta, sta_rssi, candidate_rssi_criteria, candidate, candidate_rssi
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
				,ret_11v
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
				,present_ap
#endif
#endif	
			);
#endif
}

static void _del_roaming_tbl(int sig){
#if 0
	int lock;

	lock = file_lock(ROAMING_LOCK);

	/* detach shared memory */
	if(shmdt(p_roaming_tbl) == -1)
		RAST_INFO("detach shared memory failed");

	/* destroy shared memory */
	if(shmctl(shm_roaming_tid, IPC_RMID, 0) == -1)
		RAST_INFO("destroy shared memory failed");

	file_unlock(lock);
#endif
}

static void _wipe_roaming_tbl(int sig){
#if 0
	int lock;

	lock = file_lock(ROAMING_LOCK);

	memset(p_roaming_tbl, 0, sizeof(ROAMING_TABLE));
	p_roaming_tbl->total = 0;

	file_unlock(lock);
#endif
}

static void _show_roaming_tbl(int sig){
#if 0	
	int lock;
	int i;

	lock = file_lock(ROAMING_LOCK);

	_dprintf("ROAMING: roaming count %d.\n", p_roaming_tbl->total);
	for(i = 0; i < p_roaming_tbl->total; i++){
		_dprintf("ROAMING: %s, %d, %lu, %d, %s, %d.\n",
				p_roaming_tbl->sta[i], p_roaming_tbl->sta_rssi[i],
				p_roaming_tbl->tstamp[i], p_roaming_tbl->candidate_rssi_criteria[i], p_roaming_tbl->candidate[i], p_roaming_tbl->candidate_rssi[i]
				);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
			_dprintf("%s\n",p_roaming_tbl->present_ap[i]);
#endif
#endif		
	}

	file_unlock(lock);
#endif
}
#endif

static void _wipe_tbl(int sig){
#if 0	
	_wipe_tg_roaming_tbl(sig);
	_wipe_roaming_tbl(sig);
#endif	
}
#endif

int roam_assistant_main(int argc, char *argv[])
{

	if(nvram_get_int("roamast_delay")>0 && nvram_get_int("roamast_delay")<50)
		sleep(nvram_get_int("roamast_delay"));
	else
		sleep(10);

#if defined(RTCONFIG_WIFI_SON)
	if (nvram_match("wifison_ready", "1"))
		return 0;
#endif

#if defined(RTCONFIG_RALINK_MT7621)    
	Set_RAST_CPU();
#endif	
	FILE *fp;

#if defined(RTCONFIG_SW_HW_AUTH) && defined(RTCONFIG_AMAS)
	time_t timestamp = time(NULL);
	char in_buf[48];
	char out_buf[65];
	char hw_out_buf[65];
	char *hw_auth_code = NULL;

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
	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf)))) {
		return 0;
	}
#endif

	/* write pid */
	if ((fp = fopen("/var/run/roamast.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	rast_dbg = nvram_get_int("rast_dbg");
	rast_syslog = nvram_get_int("rast_syslog");
	rast_force_syslog = nvram_get_int("rast_force_syslog");

	RAST_INFO("ROAMAST Start...\n");
	RAST_SYSLOG("ROAMING Start...\n");

#ifdef RTCONFIG_CONNDIAG
#if 0	
	// initial the shared memory
	shm_tg_roaming_tid = shmget((key_t)KEY_TG_ROAMING_EVENT, sizeof(TG_ROAMING_TABLE), 0666|IPC_CREAT);
	if(shm_tg_roaming_tid == -1){
		RAST_INFO("event table shmget failed");
		return 0;
	}

	p_tg_roaming_tbl = (P_TG_ROAMING_TABLE)shmat(shm_tg_roaming_tid, NULL, 0);
	_wipe_tg_roaming_tbl(-1);

#ifdef KEY_ROAMING_EVENT
	shm_roaming_tid = shmget((key_t)KEY_ROAMING_EVENT, sizeof(ROAMING_TABLE), 0666|IPC_CREAT);
	if(shm_roaming_tid == -1){
		RAST_INFO("event table shmget failed");
		return 0;
	}

	p_roaming_tbl = (P_ROAMING_TABLE)shmat(shm_roaming_tid, NULL, 0);
	_wipe_roaming_tbl(-1);
#endif
#endif
#endif

#if 0
	sigset_t sigs_to_catch;

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGUSR2);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);
#endif

	signal(SIGTERM, rast_exit);
	signal(SIGINT, rast_exit);
	signal(SIGKILL, rast_exit);
	signal(SIGALRM, rast_watchdog);
#ifdef RTCONFIG_ADV_RAST
	signal(SIGUSR2, usr2_processer);
#endif
#ifdef RTCONFIG_CONNDIAG
	//signal(SIGUSR1, _wipe_tbl);
#endif

#if 0
	int c
	if (argc > 1) {
		rast_dbg=1;
		rast_init_bssinfo();
#ifdef RTCONFIG_ADV_RAST
		rast_adv_init();
#endif

		while ((c = getopt(argc, argv, "vV")) != -1) {
			switch (c) {
				case 'v':
				case 'V':
					rast_test_send_bss_trans_req();
					break;
			}
		}
		exit(0);
	}
#endif

#ifdef RTCONFIG_ADV_RAST
	alarmtimer(RAST_POLL_INTV_DETECT, 0);
#else
	alarmtimer(RAST_POLL_INTV_NORMAL, 0);
#endif

	/* Most of time it goes to sleep */
	while (1)
	{
		pause();
	}
	return 0;
}

#ifdef RTCONFIG_BCN_RPT
void rast_create_beacon_report(int bssidx, int vifidx, struct ether_addr *sta
#ifdef RTCONFIG_11K_RCPI_CHECK
,int ap_rssi
#endif
) {
	char *ap_str, *band;
	char prefix[8];
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt";
	json_object *root = NULL;

	snprintf(path, sizeof(path), "/tmp/"MACF_UP"_bcn_rpt", ETHERP_TO_MACF(sta));
#if defined(RTCONFIG_LYRA_5G_SWAP) 
	bssidx=swap_5g_band(bssidx);
#endif
	/* get served ap bssid */
	if(vifidx > 0)
	{	
#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
		if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1") && vifidx == 1) 
				snprintf(prefix, sizeof(prefix), "wl%d", bssidx);
		else
#endif		
		snprintf(prefix, sizeof(prefix), "wl%d.%d", bssidx, vifidx);
	}	
	else
		snprintf(prefix, sizeof(prefix), "wl%d", bssidx);

	ap_str = nvram_safe_get(strcat_safe(prefix, "_hwaddr"));
	band = (bssinfo[bssidx].band == WL_NBAND_2G ? RAST_JVALUE_BAND_2G : RAST_JVALUE_BAND_5G);

	root = json_object_new_object();

	if (!root) {
		RAST_DBG("root or bandObj is NULL");
		goto end;
	}

	json_object_object_add(root, RAST_BAND, json_object_new_string(band));
	json_object_object_add(root, RAST_AP, json_object_new_string(ap_str));
#ifdef RTCONFIG_11K_RCPI_CHECK
	json_object_object_add(root, RAST_RSSI, json_object_new_int(ap_rssi));
#endif

	/* write to file */
	json_object_to_file(path, root);
end:
	json_object_put(root);

}

int rssi_info_gather_method(void)
{
	int method =  nvram_get_int("rssi_method");

	if( (method == RSSI_INFO_GATHER_BY_STAMON) || (method == RSSI_INFO_GATHER_BY_11K) )
		return method;

	return RSSI_INFO_GATHER_DEFAULT;//RSSI_INFO_GATHER_11K_ONLY
}

int is_rssi_method_default_k(void)
{
	int default_rssi_method = RSSI_INFO_GATHER_DEFAULT;

	if( default_rssi_method == RSSI_INFO_GATHER_BY_11K )
		return 1;
	return 0;
}

#endif //RTCONFIG_BCN_RPT

#ifdef RTCONFIG_FORCE_ROAMING

static int rast_Proc_STA_FORCE_ROAMING(char *data) {
	
	// Report sta monitor result
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *staObj = NULL;
	json_object *blockTimeObj = NULL;
	json_object *targetObj = NULL;

	struct force_roaming_list *fr_tmp=NULL;
	int blocktime=0;
	int ret = 0;

	//_dprintf("Process rast_Proc_STA_EX_AP_CHECK event\n");
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_STA, &staObj);
	json_object_object_get_ex(cfgObj, RAST_BLOCK_TIME,  &blockTimeObj );
	json_object_object_get_ex(cfgObj, RAST_AP_TARGET_MAC, &targetObj);

	if(!staObj) return ret;
	if(!blockTimeObj) blocktime=0;
	else blocktime = json_object_get_int(blockTimeObj);

	//need lock
	pthread_mutex_lock(&forceroaminglistLock);
	if(!fr_head) {
		fr_head = malloc(sizeof(struct force_roaming_list));
		if(!fr_head){
			RAST_INFO("MAOOLC ERROR\n");
			goto fr_exit;
		}
		memset(fr_head,0,sizeof(struct force_roaming_list));
		strncpy(fr_head->stamac,json_object_get_string(staObj),18);
		//if(nvram_safe_get("force_roaming_test_target"))
			//strncpy(fr_head->target,nvram_safe_get("force_roaming_test_target"),18);
		//else
		if(targetObj)
			strncpy(fr_head->target,json_object_get_string(targetObj),18);
		fr_head->blocktime = blocktime;
		fr_head->next = NULL;

		ret = 1;
	} else {
		fr_tmp = fr_head;
		while(fr_tmp->next) fr_tmp = fr_tmp->next;
		fr_tmp->next = malloc(sizeof(struct force_roaming_list));
		if(!fr_tmp->next){
			RAST_INFO("MAOOLC ERROR\n");
			goto fr_exit;
		}
		memset(fr_tmp->next,0,sizeof(struct force_roaming_list));
		strncpy(fr_tmp->next->stamac,json_object_get_string(staObj),18);
		//if(nvram_safe_get("force_roaming_test_target"))
			//strncpy(fr_tmp->next->target,nvram_safe_get("force_roaming_test_target"),18);
		//else
		if(targetObj)
			strncpy(fr_tmp->next->target,json_object_get_string(targetObj),18);
		fr_tmp->next->blocktime = blocktime;
		fr_tmp->next->next = NULL;

		ret = 1;
	}

fr_exit:

	pthread_mutex_unlock(&forceroaminglistLock);

	return ret;

}
#endif

#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
static int rast_Proc_STA_EX_AP_CHECK(char *data)
{
	// Report sta monitor result
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *staObj = NULL;
	json_object *apObj = NULL;

	int idx,vidx;
	char staMAC[18];
	int ret = 0;
	rast_sta_info_t *sta;
	struct ether_addr ea_tmp;

	//_dprintf("Process rast_Proc_STA_EX_AP_CHECK event\n");
	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_STA, &staObj);
	json_object_object_get_ex(cfgObj, RAST_AP,  &apObj );


	if ((staObj && strlen(json_object_get_string(staObj)) > 0) )
	{
		snprintf(staMAC, sizeof(staMAC), "%s", json_object_get_string(staObj));
		//find sta and.....

		for(idx=0; idx < wlif_count; idx++)
		{
			if(bssinfo[idx].user_low_rssi == 0)
				continue;
			{
				for(vidx=0; vidx < MAX_SUBIF_NUM; vidx++) {
					if(!vidx && bssinfo[idx].upstream_if) {
						RAST_DBG("ACL skip upstream interface [%s]\n", bssinfo[idx].wlif_name);
						continue;
					}
					if(bssinfo[idx].bss_enable[vidx]) {
						sta = bssinfo[idx].assoclist[vidx];
						//_dprintf("%d %d\n",idx,vidx);
						while( sta ) {
							/* find sta in assoclist */
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA)|| defined(RTCONFIG_LANTIQ))
							if(memcmp(&(sta->addr), rast_ether_atoe(staMAC,&ea_tmp), ETHER_ADDR_STR_LEN/3) == 0)
#else
							if(eacmp(&(sta->addr), rast_ether_atoe(staMAC,&ea_tmp)) == 0)
#endif
							{
								if( rast_is_static_client(idx,&(sta->addr) ) ){
									RAST_DBG("[EXAP]ignore static clients %d %d: %s\n",idx,vidx,staMAC);
									RAST_SYSLOG("[EXAP]ignore static clients %s\n",staMAC);
									ret = 1;
									break;
								}

								RAST_INFO("[EXAP]sta in %d %d: %s %d\n",idx,vidx,staMAC,sta->rssi);
								if(nvram_get_int("disable_exap") == 0){
									RAST_DBG("[EXAP]Deauth old sta in %d %d: %s\n",idx,vidx,staMAC);
									RAST_SYSLOG("[EXAP]Deauth old sta in %d %d: %s\n",idx,vidx,staMAC);
									rast_deauth_sta(idx, vidx, rast_ether_atoe(staMAC,&ea_tmp));
									rast_remove_from_assoclist(idx, vidx, rast_ether_atoe(staMAC,&ea_tmp)
#ifdef RTCONFIG_STA_AP_BAND_BIND
						,0
#endif
										);
#ifdef RTCONFIG_CONNDIAG
#ifdef KEY_ROAMING_EVENT
									_assign_roaming_tbl_recv_exap_info(staMAC,json_object_get_string(apObj));
#endif
#endif
								} else {
									RAST_DBG("[EXAP]Receive a old sta info in %d %d: %s but do nothing[disable_exap = %d]\n",idx,vidx,staMAC,nvram_get_int("disable_exap"));
								}
								ret = 1;
								break;
							}
							sta = sta->next;
						}
					}
				}
			}
		}	
	}
	else
	{
		RAST_DBG("incorrect data format!!\n");
	}

	json_object_put(root);

	return ret;
}

#ifdef RTCONFIG_CONNDIAG
#ifdef KEY_ROAMING_EVENT
static int rast_Proc_INTERNAL_EXAP_RECEIVED(char *data)
{
#if 0
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *staObj = NULL;
	json_object *presentapObj = NULL;
	int i,found=0;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP	
	char null_mac[] = "00:00:00:00:00:00";
#endif
#endif
	time_t now_tmp = uptime();

	//RAST_INFO("rast_Proc_INTERNAL_EXAP_RECEIVED\n");

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_STA, &staObj);
	json_object_object_get_ex(rastObj, RAST_STA_PRESENT_AP, &presentapObj);

	for( i=0;i<MAX_STA_COUNT;i++ ) 
	{
		if( !tmp_roaming_tbl_used[i] ) {
			continue;
		}

		if( !strcmp((char *)&tmp_roaming_tbl.sta[i],json_object_get_string(staObj)) )
		{
			found = 1;
			// set to roaming shm
			_assign_roaming_tbl((char *)&tmp_roaming_tbl.sta[i] 
								,tmp_roaming_tbl.sta_rssi[i] 
								,tmp_roaming_tbl.candidate_rssi_criteria[i] 
								,(char *)&tmp_roaming_tbl.candidate[i] 
								,tmp_roaming_tbl.candidate_rssi[i]
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
								,tmp_roaming_tbl.ret_11v[i]
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP				
								,json_object_get_string(presentapObj)
#endif
#endif
								);

			RAST_DBG("%s set to conndiag table ,clean it\n",tmp_roaming_tbl.sta[i]);
			tmp_roaming_tbl_used[i]=0;
			continue;
		}

		if( now_tmp - tmp_roaming_tbl_tstamp_reflash[i] > 3 ) //need?
		{
			RAST_DBG("%s timeout and does not receive exap info ,clean it\n",tmp_roaming_tbl.sta[i]);
			/* timeout means that we do not receive ex-ap info */
			_assign_roaming_tbl((char *)&tmp_roaming_tbl.sta[i]
								,tmp_roaming_tbl.sta_rssi[i] 
								,tmp_roaming_tbl.candidate_rssi_criteria[i] 
								,(char *)&tmp_roaming_tbl.candidate[i] 
								,tmp_roaming_tbl.candidate_rssi[i]
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
								,tmp_roaming_tbl.ret_11v[i]
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
								,null_mac
#endif
#endif								
								);

			tmp_roaming_tbl_used[i]=0;
		}

	}

	if( !found ) {
		RAST_DBG("Error: exap info do not match related table %s\n",json_object_get_string(staObj));

	}

	json_object_put(root);
	return 0;
#endif
}


static int rast_Proc_INTERNAL_EXAP_BEFORE(char *data)
{
#if 0
	int empty_entry_idx=-1,ret=0,i;
	int found = 0;
	json_object *root = NULL;
	json_object *rastObj = NULL;
	json_object *staObj = NULL;
	json_object *rssiObj = NULL;
	json_object *candidateaprssiObj = NULL;
	json_object *candidateapObj = NULL;
	json_object *candidateaprssicriteriaObj = NULL;
	json_object *aptargetmacObj = NULL;
	json_object *ret11vObj = NULL;
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP		
	char null_mac[] = "00:00:00:00:00:00";
#endif
#endif	
	//RAST_INFO("rast_Proc_INTERNAL_EXAP_BEFORE\n");

	time_t now_tmp = uptime();

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_STA, &staObj);
	json_object_object_get_ex(rastObj, RAST_RSSI, &rssiObj);
	json_object_object_get_ex(rastObj, RAST_CANDIDATE_AP_RSSI, &candidateaprssiObj);
	json_object_object_get_ex(rastObj, RAST_CANDIDATE_AP, &candidateapObj);
	json_object_object_get_ex(rastObj, RAST_CANDIDATE_AP_RSSI_CRITERIA, &candidateaprssicriteriaObj);
	json_object_object_get_ex(rastObj, RAST_AP_TARGET_MAC, &aptargetmacObj);
	json_object_object_get_ex(rastObj, RAST_RET_11V, &ret11vObj);

	for( i=0;i<MAX_STA_COUNT;i++ ) 
	{
		if( !tmp_roaming_tbl_used[i] ) {
			if(empty_entry_idx == -1)
				empty_entry_idx = i;
			continue;
		}

		if( now_tmp - tmp_roaming_tbl_tstamp_reflash[i] > 3 )
		{
			//RAST_DBG("%s timeout ,clean it\n",tmp_roaming_tbl.sta[i]);
			tmp_roaming_tbl_used[i]=0;
			RAST_DBG("%s timeout and does not receive exap info ,clean it\n",tmp_roaming_tbl.sta[i]);
			/* timeout means that we do not receive ex-ap info */
			_assign_roaming_tbl((char *)&tmp_roaming_tbl.sta[i] 
								,tmp_roaming_tbl.sta_rssi[i] 
								,tmp_roaming_tbl.candidate_rssi_criteria[i] 
								,(char *)&tmp_roaming_tbl.candidate[i] 
								,tmp_roaming_tbl.candidate_rssi[i]
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
								,tmp_roaming_tbl.ret_11v[i]
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
								,null_mac
#endif
#endif
								);
			continue;
		}

		if( !strcmp((char *)&tmp_roaming_tbl.sta[i],json_object_get_string(staObj)) )
		{
			found = 1;
			RAST_DBG("%s reflashing\n",tmp_roaming_tbl.sta[i]);
			tmp_roaming_tbl_tstamp_reflash[i] = uptime();
		}
	}

	if( !found )
	{
		if( empty_entry_idx == -1 )
		{
			RAST_INFO("roaming pre table full\n");
			ret = -1;
			goto error_ret;
		}

		memcpy(tmp_roaming_tbl.sta[empty_entry_idx], json_object_get_string(staObj), MAC_LEN);
		tmp_roaming_tbl.sta_rssi[empty_entry_idx] = json_object_get_int(rssiObj);
		tmp_roaming_tbl.candidate_rssi_criteria[empty_entry_idx] = json_object_get_int(candidateaprssicriteriaObj);
		memcpy(tmp_roaming_tbl.candidate[empty_entry_idx], json_object_get_string(candidateapObj), MAC_LEN);
		tmp_roaming_tbl.candidate_rssi[empty_entry_idx] = json_object_get_int(candidateaprssiObj);
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
		tmp_roaming_tbl.ret_11v[empty_entry_idx] = json_object_get_int(ret11vObj);
#endif
		tmp_roaming_tbl.tstamp[empty_entry_idx] = uptime();
		tmp_roaming_tbl_tstamp_reflash[empty_entry_idx] = uptime();

		tmp_roaming_tbl_used[empty_entry_idx] = 1;
		//tmp_roaming_tbl.total++;

	}
error_ret:

	json_object_put(root);
	return ret;
#endif
}

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
static void rast_internal_ipc_receive(int sockfd)
{
#if 0	
	int length = 0;
	char buf[2048];
	memset(buf, 0, sizeof(buf));
	if ((length = read(sockfd, buf, sizeof(buf))) <= 0)
	{
		RAST_DBG("internal ipc read socket error!\n");
		return;
	}

	RAST_DBG("internal IPC Receive: %s <<< RCV EVENT >>>\n", buf);

	json_object *rootObj = json_tokener_parse(buf);
	json_object *rastObj = NULL;
	json_object *eidObj = NULL;
	json_object_object_get_ex(rootObj, RAST_PREFIX, &rastObj);
	json_object_object_get_ex(rastObj, RAST_EVENT_ID, &eidObj);

	int EID = 0;
	struct eventHandler *handler = NULL;

	if(eidObj) {
		EID = json_object_get_int(eidObj);
		//RAST_INFO("EID %d\n",EID);
		for(handler = &RAST_INTERNAL_EVENT[0]; handler->event_id > 0; handler++)
		{
			if (handler->event_id == EID)
			break;
		}

		if (handler == NULL || handler->event_id < 0)
			RAST_DBG("no corresponding function pointer(%d)", EID);
		else
		{
			RAST_DBG("process event (%d)\n", EID);
 			if (!handler->func(buf)) {
				RAST_DBG("fail to process event(%d)\n", EID);
			}
		}
	} else 
		RAST_DBG("eidObj NULL\n");

	json_object_put(rootObj);
#endif
}

static int rast_start_internal_ipc_socket(void)
{
#if 0
#if defined(RTCONFIG_RALINK_MT7621)    
	Set_RAST_CPU();
#endif	
	struct sockaddr_un addr;
	int sockfd, newsockfd;

	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		RAST_INFO("internal ipc create socket error!\n");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, RAST_INTERNAL_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);

	unlink(RAST_INTERNAL_IPC_SOCKET_PATH);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		RAST_INFO("internal ipc bind socket error!\n");
		exit(-1);
	}

	if (listen(sockfd, RAST_IPC_MAX_CONNECTION) == -1) {
		RAST_INFO("internal ipc listen socket error!\n");
		exit(-1);
	}

	while (!thread_term) {
		RAST_INFO("internal ipc accept socket...\n");
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			RAST_INFO("internal ipc accept socket error!\n");
			continue;
		}
		rast_internal_ipc_receive(newsockfd);
		close(newsockfd);

	}

	return 0;
#endif
}

/* send ipc to conn diag wait thread to wait exap info received */
static int _assign_roaming_tbl_before_recv_exap_info(char *sta, int sta_rssi, int candidate_rssi_criteria, char *candidate, int candidate_rssi, int ret_11v, char *target_mac )
{
#if 0	
	char json_data[256];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	//snprintf(_EID, sizeof(_EID), "%d", EID_CONNDIAG_RAST);
	//snprintf(_RSSI, sizeof(_RSSI), "%d", sta_rssi);
	//snprintf(_RSSI_CRITERIA, sizeof(_RSSI_CRITERIA), "%d", candidate_rssi);
	//snprintf(_RET_11V, sizeof(_RET_11V), "%d", ret_11v);

	//{RAST:{"EID":"X","STA":"xx:xx:xx:xx:xx:xx","RSSI":"-XX","PIP","xxx.xxx.xxx.xxx","BAND":"XX","AP_RSSI_CRITERIA":"-XX"}}
	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_int(EID_CONNDIAG_RAST_EXAP_BEFORE));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta));
	json_object_object_add(param, RAST_RSSI, json_object_new_int(sta_rssi));
	json_object_object_add(param, RAST_CANDIDATE_AP_RSSI, json_object_new_int(candidate_rssi));
	json_object_object_add(param, RAST_CANDIDATE_AP, json_object_new_string(candidate));
	json_object_object_add(param, RAST_CANDIDATE_AP_RSSI_CRITERIA, json_object_new_int(candidate_rssi_criteria));
	json_object_object_add(param, RAST_AP_TARGET_MAC, json_object_new_string(target_mac));
	json_object_object_add(param, RAST_RET_11V, json_object_new_int(ret_11v));
	json_object_object_add(root, RAST_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	//RAST_INFO("rast_ipc_send_event _assign_roaming_tbl_before_recv_exap_info [%s]\n",&json_data[0]);

	return rast_ipc_send_event(RAST_INTERNAL_IPC_SOCKET_PATH, &json_data[0]);
#endif
}
#endif //#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
static int _assign_roaming_tbl_recv_exap_info( char *sta, const char *present_ap )
{
#if 0
	char json_data[256];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	//snprintf(_EID, sizeof(_EID), "%d", EID_CONNDIAG_RAST);
	//snprintf(_RSSI, sizeof(_RSSI), "%d", sta_rssi);
	//snprintf(_RSSI_CRITERIA, sizeof(_RSSI_CRITERIA), "%d", candidate_rssi);
	//snprintf(_RET_11V, sizeof(_RET_11V), "%d", ret_11v);

	//{RAST:{"EID":"X","STA":"xx:xx:xx:xx:xx:xx","RSSI":"-XX","PIP","xxx.xxx.xxx.xxx","BAND":"XX","AP_RSSI_CRITERIA":"-XX"}}
	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_int(EID_CONNDIAG_RAST_EXAP_RECEIVED));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta));
	json_object_object_add(param, RAST_STA_PRESENT_AP, json_object_new_string(present_ap));
	json_object_object_add(root, RAST_PREFIX, param);

	memset(json_data, 0, sizeof(json_data));
	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	//RAST_INFO("rast_ipc_send_event _assign_roaming_tbl_recv_exap_info [%s]\n",&json_data[0]);

	return rast_ipc_send_event(RAST_INTERNAL_IPC_SOCKET_PATH, &json_data[0]);
#endif
}
#endif //#ifdef RTCONFIG_CONNDIAG
#endif //#ifdef KEY_ROAMING_EVENT

#endif //#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP

#ifdef RTCONFIG_RAST_NONMESH_KVONLY
int add_to_roaming_list(int idx,int vidx ,struct ether_addr *sta,int rssi){
	struct roaming_list_entry *tmp;
	int ret;
	//_dprintf("add%d %d ["MACF"]\n",idx,vidx,ETHERP_TO_MACF(sta));
	pthread_mutex_lock(&roaminglistLock);
	tmp = roaming_list;
	if(tmp == NULL) {
		roaming_list = malloc(sizeof(struct roaming_list_entry));
		if(!roaming_list) {
			_dprintf("malloc error\n");
			ret = -1;
			goto exit;
		}
		memset(roaming_list,0,sizeof(struct roaming_list_entry));
		roaming_list->idx = idx;
		roaming_list->vidx = vidx;
		memcpy(&roaming_list->sta,sta,sizeof(struct ether_addr));
		roaming_list->trigger_time = uptime();
		roaming_list->rssi = rssi;
		roaming_list->next = NULL;
		ret = 0;
		goto exit;
	} else {
		while(tmp->next != NULL)
			tmp = tmp->next;
		if(tmp->next) _dprintf("coding error\n");
		tmp->next = malloc(sizeof(struct roaming_list_entry));
		if(!tmp->next) {
			_dprintf("malloc error\n");
			ret = -1;
			goto exit;
		}
		tmp = tmp->next;
		memset(tmp,0,sizeof(struct roaming_list_entry));
		tmp->idx = idx;
		tmp->vidx = vidx;
		memcpy(&tmp->sta,sta,sizeof(struct ether_addr));
		tmp->trigger_time = uptime();
		tmp->rssi = rssi;
		tmp->next = NULL;
		ret = 0;
		goto exit;		
	}
exit:
	pthread_mutex_unlock(&roaminglistLock);
	return ret;
}
int remove_from_roaming_list(int idx,int vidx ,struct ether_addr *sta){
	struct roaming_list_entry *tmp,*pre=NULL;
	int ret,i=0;

	pthread_mutex_lock(&roaminglistLock);
	tmp = roaming_list;
	while(1) {
		if(!tmp) {
			ret = 0;
			goto exit;
		}
		//_dprintf("remove %d %d ["MACF"]\n",idx,vidx,ETHERP_TO_MACF(sta));
		if( (tmp->idx == idx) && (tmp->vidx == vidx) && !memcmp(sta,&tmp->sta,sizeof(struct ether_addr)) ) {
			//_dprintf("found anad remove\n");
			if(!pre) { //head
				roaming_list = tmp->next;
				free(tmp);
				ret = 0;
				goto exit;
			} else {
				pre->next = tmp->next;
				free(tmp);
				ret = 0;
				goto exit;
			}
		}

		tmp = tmp->next;
	}

exit:
	pthread_mutex_unlock(&roaminglistLock);
	return ret;
}

int thread_kv_handler()
{
	struct roaming_list_entry *tmp,*pre=NULL;
	time_t now_tmp;
	int sock_for_k_resp=0;
	struct report_list_entry *rplist=NULL,*rplist_tmp=NULL,*rpentry_pre=NULL;
	int num = 0;
	char staMac[18];
	char candidate[18];
	int ret=0;

	ret = kv_handler_init();
	if(ret < 0) {
		_dprintf("kv init error\n stop kv resp related thread\n");
		return -1;
	}

	while(!kv_thread_term) {
		//wait 1 sec
		wait_k_resp(&rplist,&num);

		pthread_mutex_lock(&roaminglistLock);
		now_tmp = uptime();
		tmp = roaming_list;
		pre = NULL;
/*
		_dprintf("==================\n");
		_dprintf("num %d\n",num);
		{
			rplist_tmp = rplist;
			int i=0;
			for(i=0;i<num;i++) {
				_dprintf(" ["MACF"]\n",ETHERP_TO_MACF(&rplist->sta));
				rplist_tmp = rplist_tmp->next;
			}

		}
		_dprintf("==================\n");
*/
		while(1){
			if(!tmp)
				break;
			if( (now_tmp - tmp->trigger_time) > 2 )//need define
			{
				//_dprintf("remove %d %d ["MACF"]\n",tmp->idx,tmp->vidx,ETHERP_TO_MACF(&tmp->sta));
				//check rplist if any related packets
/*{
	//show rplist
	rplist_tmp = rplist;
	rpentry_pre = NULL;	
	while(1)
	{
		if(rplist_tmp == NULL){
			_dprintf("%s %d\n",__FUNCTION__,__LINE__);
			break;
		}
		_dprintf("%x ["MACF"]\n",rplist_tmp,ETHERP_TO_MACF(&rplist_tmp->bssid));
		rplist_tmp = rplist_tmp->next;
	}
}	*/			
				//need checkt token??
				rplist_tmp = rplist;
				rpentry_pre = NULL;
				while(1) { //always check all entries for cleaning timeout entries
					if(rplist_tmp == NULL){
						//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
						break;
					}
					//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
					if( !memcmp(&rplist_tmp->sta,&tmp->sta,sizeof(struct ether_addr)) ) 
					{
						//send 11v
						//_dprintf("%d %d\n",rplist_tmp->rcpi,tmp->rssi);
						if(rplist_tmp->rcpi - tmp->rssi > 3) {//ROAMING_RSSI_TOLERANCE, should move to shared?
							//_dprintf("\n\nsend 11v\n\n\n");
							snprintf(&staMac[0],sizeof(staMac),MACF,ETHERP_TO_MACF(&tmp->sta));
							snprintf(&candidate[0],sizeof(candidate),MACF,ETHERP_TO_MACF(&rplist_tmp->bssid));
							rast_send_11v_req(tmp->idx,tmp->vidx,&staMac[0],&candidate[0]);
						}
						//remove this entry
						if( !rpentry_pre ) {
							//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
							rplist = rplist_tmp->next;
							free(rplist_tmp);
							rplist_tmp = rplist;
							num --;
						} else {
							//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
							rpentry_pre->next = rplist_tmp->next;
							free(rplist_tmp);
							rplist_tmp = rpentry_pre->next;
							num --;
						} 
					} else if( now_tmp - rplist_tmp->recv_time > 3 ) {
						//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
						//remove this entry
						if( !rpentry_pre ) {
							//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
							rplist = rplist_tmp->next;
							free(rplist_tmp);
							rplist_tmp = rplist;
							num --;
						} else {
							//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
							rpentry_pre->next = rplist_tmp->next;
							free(rplist_tmp);
							rplist_tmp = rpentry_pre->next;
							num --;
						} 
					} else {
						//next
						//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
						rpentry_pre = rplist_tmp;
						rplist_tmp = rplist_tmp->next;
					}
					//_dprintf("%s %d\n",__FUNCTION__,__LINE__);
				}

				if(!pre) { //head
					roaming_list = tmp->next;
					free(tmp);
					tmp = roaming_list;
				} else {
					pre->next = tmp->next;
					free(tmp);
					tmp = pre->next;
				}			
			} else {
				pre = tmp;
				tmp = tmp->next;
			}
		}
		//_dprintf("unlock %s %d\n",__FUNCTION__,__LINE__);
		pthread_mutex_unlock(&roaminglistLock);
	}

	kv_handler_deinit();
}

void rast_nonmesh_kv_thread_create(void)
{
	pthread_t thread;
	pthread_attr_t attr;

	RAST_DBG("Start non-mesh kv-related thread.\n");

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread,NULL,(void *)&thread_kv_handler,NULL);
	pthread_attr_destroy(&attr);
}
#endif //end of RTCONFIG_RAST_NONMESH_KVONLY

#ifdef RTCONFIG_11K_RCPI_CHECK
//struct rcpi_checklist *rcpi_checklist_global=NULL;

/*
void init_rcpi_checklist_global(void)
{
	if(rcpi_checklist_global != NULL){
		RAST_INFO("\n\n\n[ERROR]rcpi check list init\n\n");
		return ;
	}

	rcpi_checklist_global = malloc(sizeof(struct rcpi_checklist));
	if( !rcpi_checklist_global ){
		RAST_INFO("\n\n\n[MALLOC]rcpi check list init\n\n");
		return ;
	}

	memset(rcpi_checklist_global,0,sizeof(struct rcpi_checklist));

}
*/

/* for now -36 */
uint8 check_if_follow_spec(int8 rssi,int8 rcpi)
{
	if( (uint8)rssi - (uint8)rcpi > 36)
		return 1;
	return 0;
}

void check_rcpilist_and_translate_to_rssi(struct rcpi_checklist *rcpi_list)
{
	int i;
	char rssi_tmp;
	uint8 follow_spec=0;
	//struct rcpi_checklist *tmp_rcpi_checklist=NULL;
	struct report_entry   *tmp_rcpi_entry_list=NULL;

	char oriap_mac[MAC_STR_LEN+1];

	/* check if the ori ap mac is in rcpi list */
	while(1)
	{
		rssi_tmp = 0;
		follow_spec=0;
		memset(oriap_mac,0,MAC_STR_LEN+1);
		if(!rcpi_list) break;
		tmp_rcpi_entry_list = rcpi_list->rplist;
		get_sta_rssi_and_apmac_form_json(rcpi_list->sta_mac,&rssi_tmp,oriap_mac);
		while(1){
			if(!tmp_rcpi_entry_list) break;

			//TOUPPER
			for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
				oriap_mac[i]=toupper(oriap_mac[i]);
			for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
				tmp_rcpi_entry_list->ap_mac[i]=toupper(tmp_rcpi_entry_list->ap_mac[i]);

			RAST_DBG("[%s][%s]\n",oriap_mac,tmp_rcpi_entry_list->ap_mac);

			if( !strcmp(oriap_mac,tmp_rcpi_entry_list->ap_mac) ) {
				if(rssi_tmp == 0) break;
				rcpi_list->report_ok = 1;
				if(check_if_follow_spec(rssi_tmp,tmp_rcpi_entry_list->rcpi)){
					// rcpi follow spec, need translate to rssi
					RAST_DBG("rcpi follow spec\n");
					follow_spec =1;
					break;
				}
				break;
			}
			tmp_rcpi_entry_list = tmp_rcpi_entry_list->next;
		}
		/* check if the rcpi follows spec */
		if(follow_spec){
			tmp_rcpi_entry_list = rcpi_list->rplist;
			while(1)
			{
				if(!tmp_rcpi_entry_list) break;
				uint8 org_rcpi = tmp_rcpi_entry_list->rcpi;
				//RAST_DBG("sta %s ap %s rcpi %hhu\n", rcpi_list->sta_mac, tmp_rcpi_entry_list->ap_mac, tmp_rcpi_entry_list->rcpi);
				//RAST_SYSLOG("sta %s ap %s rcpi %hhu\n", rcpi_list->sta_mac, tmp_rcpi_entry_list->ap_mac, tmp_rcpi_entry_list->rcpi);
				tmp_rcpi_entry_list->rcpi = (tmp_rcpi_entry_list->rcpi / 2) - 110;
				//RAST_DBG("after rssi %hhd\n", tmp_rcpi_entry_list->rcpi);
				//RAST_SYSLOG("after rssi %hhd\n", tmp_rcpi_entry_list->rcpi);
				
				RAST_DBG("sta[%s] on ap[%s], rcpi is %hhu and rssi is %hhd\n", rcpi_list->sta_mac, tmp_rcpi_entry_list->ap_mac, org_rcpi, tmp_rcpi_entry_list->rcpi);
				RAST_SYSLOG("sta[%s] on ap[%s], rcpi is %hhu and rssi is %hhd\n", rcpi_list->sta_mac, tmp_rcpi_entry_list->ap_mac, org_rcpi, tmp_rcpi_entry_list->rcpi);

				tmp_rcpi_entry_list=tmp_rcpi_entry_list->next;
			}
		} else {

			//RAST_DBG("sta %s report do not include %s\n",rcpi_list->sta_mac,tmp_rcpi_entry_list->ap_mac);
		}

		rcpi_list = rcpi_list->next;
	}


}
void add_to_rcpi_checklist(char *sta, char *ap_mac, char rcpi,struct rcpi_checklist **rcpi_list)
{
	struct rcpi_checklist *tmp_rcpi_checklist=NULL;
	struct rcpi_checklist *tmp_rcpi_checklist_pre=NULL;
	struct report_entry   *tmp_rcpi_entry_list=NULL;

	tmp_rcpi_checklist = *rcpi_list;

	RAST_DBG("add_to_rcpi_checklist %s %s\n",sta,ap_mac);


	while(1)
	{
		if(!tmp_rcpi_checklist){
			if(*rcpi_list == NULL) {
				*rcpi_list = malloc(sizeof(struct rcpi_checklist));
				tmp_rcpi_checklist = *rcpi_list;
			}
			else {
				tmp_rcpi_checklist = malloc(sizeof(struct rcpi_checklist));
				tmp_rcpi_checklist_pre->next = tmp_rcpi_checklist;
			}
			if( !tmp_rcpi_checklist ){
				RAST_INFO("\n\n\n[MALLOC]rcpi check list\n\n");
				return ;
			}
			memset(tmp_rcpi_checklist,0,sizeof(struct rcpi_checklist));	

			strncpy(tmp_rcpi_checklist->sta_mac,sta,sizeof(tmp_rcpi_checklist->sta_mac));

			tmp_rcpi_checklist->rplist = malloc(sizeof(struct report_entry));
			if( !tmp_rcpi_checklist->rplist ){
				RAST_INFO("\n\n\n[MALLOC]rcpi check list\n\n");
				return ;
			}
			memset(tmp_rcpi_checklist->rplist,0,sizeof(struct report_entry));	

			strncpy(tmp_rcpi_checklist->rplist->ap_mac,ap_mac,sizeof(tmp_rcpi_checklist->rplist->ap_mac));
			tmp_rcpi_checklist->rplist->rcpi = rcpi;

			RAST_DBG("new rcpi_list head:%s\n",tmp_rcpi_checklist->sta_mac);

			break;
		}

		if( !strcmp(sta,tmp_rcpi_checklist->sta_mac) )
		{
			tmp_rcpi_entry_list = tmp_rcpi_checklist->rplist;
			if(!tmp_rcpi_entry_list) {
				RAST_INFO("ERROR:rp list empty\n");
				break;
			}
			while(tmp_rcpi_entry_list->next)
			{
				tmp_rcpi_entry_list = tmp_rcpi_entry_list->next;
			}
			tmp_rcpi_entry_list->next = malloc(sizeof(struct report_entry));
			if( !(tmp_rcpi_entry_list->next) ){
				RAST_INFO("\n\n\n[MALLOC]rcpi check list\n\n");
				return ;
			}
			memset((tmp_rcpi_entry_list->next),0,sizeof(struct report_entry));	

			strncpy((tmp_rcpi_entry_list->next)->ap_mac,ap_mac,sizeof(tmp_rcpi_entry_list->ap_mac));
			(tmp_rcpi_entry_list->next)->rcpi = rcpi;

			RAST_DBG("found in rcpi_list:%s\n",tmp_rcpi_checklist->sta_mac);

			break;
		} 

		if(tmp_rcpi_checklist->next == NULL) tmp_rcpi_checklist_pre = tmp_rcpi_checklist;

		tmp_rcpi_checklist = tmp_rcpi_checklist->next;

	}

}

void get_sta_rssi_and_apmac_form_json(char *sta,char *rssi,char *apmac)
{
	int i;
	int lock;

	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt\0";
	json_object *root = NULL;
	json_object *rssiObj = NULL;
	json_object *apmacObj = NULL;

	*rssi = 0;
	//TOUPPER
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		sta[i]=toupper(sta[i]);

	snprintf(path, sizeof(path), "/tmp/%s_bcn_rpt", sta);
	RAST_DBG("path %s\n",path);
	lock = file_lock(path+5);
	root = json_object_from_file(path);
	if(!root) {
		RAST_DBG("%s,no file or valid content\n", path);
		goto get_sta_rssi_form_json_end;
	}

	json_object_object_get_ex(root, RAST_RSSI, &rssiObj);
	if(!rssiObj) {
		RAST_DBG("%s,no file or valid content[rssi]\n", path);
		goto get_sta_rssi_form_json_end;
	}

	json_object_object_get_ex(root, RAST_AP, &apmacObj);
	if(!apmacObj) {
		RAST_DBG("%s,no file or valid content[mac]\n", path);
		goto get_sta_rssi_form_json_end;
	}

	*rssi = json_object_get_int(rssiObj);
	strncpy(apmac,json_object_get_string(apmacObj),MAC_STR_LEN);

get_sta_rssi_form_json_end:
	RAST_DBG("get sta rssi %s %s %d\n",sta,apmac,*rssi);

	json_object_put(root);
	file_unlock(lock);
}
#endif //#ifdef RTCONFIG_11K_RCPI_CHECK

#ifdef RTCONFIG_STA_AP_BAND_BIND
static int rast_Proc_STA_BINDING_UPDATE(char *data) {

	RAST_DBG("Process STA BINDING event data=%s\n", data);
	int ret = 0;
	int max_band_num=wlif_count;
	int rast_sta_bind_action=0;
	int start_subunit=0;
	int fh_mssid_subunit=0;
	int first_wgn_subunit=0;

	struct staapbandbind_sta_list *staapbandbind_sta_list_tmp=NULL,*staapbandbind_sta_list_tmp_pre=NULL;
	char nvram_buf[4096]={0},allowband_str[8]={0},stamac[MAC_STR_LEN+1];
	char *nvp, *b;
	int found,stalist_len,stalist_idx,allowband_str_len,allowband,i,j;
	char *remac,*enable,*stalist;
	struct ether_addr ea_tmp;

	strncpy(nvram_buf, nvram_safe_get("sta_binding_list"), sizeof(nvram_buf));

	nvp = nvram_buf;

	/* set global list status to REMOVE */
	if( staapbandbind_sta_list_g){
		staapbandbind_sta_list_tmp = staapbandbind_sta_list_g;
		while(1)
		{
			if(!staapbandbind_sta_list_tmp)
				break;
			RAST_DBG("%s init ACL status\n",staapbandbind_sta_list_tmp->stamac);
			staapbandbind_sta_list_tmp->status = RAST_ACL_STAAPBANDBIND_REMOVE;
			staapbandbind_sta_list_tmp = staapbandbind_sta_list_tmp->next;

		}
	}

	if ( strlen(nvram_buf) ) {
		//maintain a global list
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ( (vstrsep(b, ">", &remac, &enable, &stalist) != 3) )
				continue;

			RAST_DBG("got sta-ap-band bind list %s %s %s\n",remac, enable, stalist);

			stalist_len = strlen(stalist);
			stalist_idx = 0;
			allowband_str_len = 0;

			while(1)// break when stalist len = 0 
			{
				if(stalist_idx + MAC_STR_LEN+2 > stalist_len)//MAC_STR_LEN+2 => STA1 mac,Band index
					break;
				memset(stamac,0,MAC_STR_LEN+1);
				strncpy(stamac,stalist+stalist_idx,MAC_STR_LEN);
				stalist_idx += MAC_STR_LEN;

				if( stalist[stalist_idx] != ',' )
				{
					RAST_INFO("AP STA BAND BIND format error[%s]\n",stalist);
					break;
				}
				stalist_idx++;

				while(1){
					//RAST_DBG("%c\n",stalist[stalist_idx]);
					if(stalist_idx+allowband_str_len >= stalist_len)
						break;
					if(stalist[stalist_idx+allowband_str_len] == '|')
						break;
					allowband_str_len++;
				}
				memset(allowband_str,0,sizeof(allowband_str));
				strncpy(allowband_str,&stalist[stalist_idx],allowband_str_len);

				stalist_idx += allowband_str_len;

				allowband = atoi(allowband_str);

				//RAST_INFO("test only [%d] [%s] %d\n",allowband,allowband_str,allowband_str_len);

				if( strcmp(remac,nvram_safe_get("lan_hwaddr")) ){
					if( strcmp(enable,"0") ) RAST_DBG("block sta %s in all bands\n",stamac);
					allowband = 0;
				}

				if( staapbandbind_sta_list_g ){
					found = 0;
					staapbandbind_sta_list_tmp = staapbandbind_sta_list_g;
					while(1){
						if( !staapbandbind_sta_list_tmp )
							break;
						//RAST_DBG("[%s][%s]\n",staapbandbind_sta_list_tmp->stamac, stamac);
						if( !strcmp( staapbandbind_sta_list_tmp->stamac, stamac ) ){
							found = 1;
							if( !strcmp(enable,"0") ){
								staapbandbind_sta_list_tmp->status = RAST_ACL_STAAPBANDBIND_REMOVE;
							} else if( staapbandbind_sta_list_tmp->allowband != allowband ) {
								staapbandbind_sta_list_tmp->allowband = allowband;
								staapbandbind_sta_list_tmp->status = RAST_ACL_STAAPBANDBIND_CHANGE;
							} else {
								staapbandbind_sta_list_tmp->status = RAST_ACL_STAAPBANDBIND_NOTHING;
							}
							break;
						}
						staapbandbind_sta_list_tmp = staapbandbind_sta_list_tmp->next;
					}
					if(!found){
						if( !strcmp(enable,"1") ){
							staapbandbind_sta_list_tmp = malloc(sizeof(struct staapbandbind_sta_list));
							if(staapbandbind_sta_list_tmp){
								memset(staapbandbind_sta_list_tmp,0,sizeof(struct staapbandbind_sta_list));
								strncpy( staapbandbind_sta_list_tmp->stamac,stamac,MAC_STR_LEN);
								staapbandbind_sta_list_tmp->allowband = allowband;
								staapbandbind_sta_list_tmp->status = RAST_ACL_STAAPBANDBIND_NEW;

								staapbandbind_sta_list_tmp->next = staapbandbind_sta_list_g;
								staapbandbind_sta_list_g = staapbandbind_sta_list_tmp;
							} else {
								RAST_INFO("MALLOC ERROR in sta ap band bind func\n");
								goto rast_Proc_STA_BINDING_UPDATE_end;
							}
						}
					}

				} else {
					if( !strcmp(enable,"1") ){
						staapbandbind_sta_list_g = malloc(sizeof(struct staapbandbind_sta_list));
						if(staapbandbind_sta_list_g){
							memset(staapbandbind_sta_list_g,0,sizeof(struct staapbandbind_sta_list));
							strncpy( staapbandbind_sta_list_g->stamac,stamac,MAC_STR_LEN+1);
							staapbandbind_sta_list_g->allowband = allowband;
							staapbandbind_sta_list_g->status = RAST_ACL_STAAPBANDBIND_NEW;
						} else {
							RAST_INFO("MALLOC ERROR in sta ap band bind func\n");
							goto rast_Proc_STA_BINDING_UPDATE_end;
						}
					}
				}

				if( stalist_idx + 1 >= stalist_len || stalist[stalist_idx] != '|' )
					break;
				stalist_idx++;
			}
		}

		//free(nv);
	}

	/* process list */
	if( !staapbandbind_sta_list_g )
		goto rast_Proc_STA_BINDING_UPDATE_end;

	staapbandbind_sta_list_tmp = staapbandbind_sta_list_g;
	staapbandbind_sta_list_tmp_pre = NULL;

	while(1){
		if( !staapbandbind_sta_list_tmp )
			break;

		RAST_DBG("%s ACL status %d\n",staapbandbind_sta_list_tmp->stamac,staapbandbind_sta_list_tmp->status);

		switch(staapbandbind_sta_list_tmp->status){

			case RAST_ACL_STAAPBANDBIND_NEW:
			case RAST_ACL_STAAPBANDBIND_CHANGE:

				RAST_DBG("%s new or changed ACL \n",staapbandbind_sta_list_tmp->stamac);
				allowband = staapbandbind_sta_list_tmp->allowband;

				for (i=0; i<max_band_num; i++) {

					if ( (allowband>>i)&1 )
						rast_sta_bind_action = RAST_STAAPBANDBIND_ACTION_UNBLOCK;
					else
						rast_sta_bind_action = RAST_STAAPBANDBIND_ACTION_BLOCK;

					if (nvram_safe_get("re_mode") && nvram_get_int("re_mode") == 1) {
						start_subunit = 1;
						first_wgn_subunit = 2;
						fh_mssid_subunit = nvram_get_int("fh_re_mssid_subunit");
					}
					else {
						start_subunit = 0;
						first_wgn_subunit = 1;
						fh_mssid_subunit = nvram_get_int("fh_cap_mssid_subunit");
					}

					rast_add_to_maclist(i, start_subunit, 
						rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
						,0
#endif
						,rast_sta_bind_action);

					if (rast_sta_bind_action == RAST_STAAPBANDBIND_ACTION_BLOCK) {
						rast_remove_from_assoclist(i, start_subunit, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), 1);
					}
					else {
						sta_roaming_bypass_status_update(i, start_subunit, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), ROAMING_BYPASS);
					}

#ifdef RTCONFIG_FRONTHAUL_DWB
					if( i > 1 && fh_mssid_subunit > 0 ) {
						// fh_cap_mssid_subunit or fh_re_mssid_subunit
						rast_add_to_maclist(i, fh_mssid_subunit, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
							,0
#endif
							,rast_sta_bind_action);	
					}					
#endif

#ifdef RTCONFIG_AMAS_WGN
					char first_wgn_prefix[32];
					char first_wgn_enable[32];
					snprintf(first_wgn_prefix, sizeof(first_wgn_prefix), "wl%d.%d", i, first_wgn_subunit);
					snprintf(first_wgn_enable, sizeof(first_wgn_enable), "%s_bss_enabled", first_wgn_prefix);

					if (nvram_get_int(first_wgn_enable)==1) {
						RAST_DBG("rast_add_to_maclist , interface=%s, action=%d\n", first_wgn_prefix, rast_sta_bind_action);

						rast_add_to_maclist(i, first_wgn_subunit, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
							,0
#endif
							,rast_sta_bind_action);
						
						if (rast_sta_bind_action == RAST_STAAPBANDBIND_ACTION_BLOCK) {
							rast_remove_from_assoclist(i, first_wgn_subunit, 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), 1);
						}
						else {
							sta_roaming_bypass_status_update(i, first_wgn_subunit, 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), ROAMING_BYPASS);
						}
					}
#endif

#ifdef RTCONFIG_MULTILAN_CFG
					char word[64];
					char *next = NULL;
					int total = 0;
					int multilan_unit = -1, multilan_subunit = -1;

					ap_wifi_rule_st ap_wifi_rl[MAX_AP_RULE_LIST];
					memset(ap_wifi_rl, 0, (sizeof(ap_wifi_rule_st) * MAX_AP_RULE_LIST));

					if (get_ap_wifi_rl_from_nvram(ap_wifi_rl, MAX_AP_RULE_LIST, &total) && total > 0) {

						for (j=0; j<total; j++) {

							foreach_44(word, ap_wifi_rl[j].wlif_set, next) {

								sscanf(word, "wl%d.%d", &multilan_unit, &multilan_subunit);
								
								if (multilan_unit==i && multilan_subunit>start_subunit) {

									RAST_DBG("rast_add_to_maclist , interface=%s, action=%d\n", word, rast_sta_bind_action);

									rast_add_to_maclist(i, multilan_subunit, 
										rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
										,0
#endif
										,rast_sta_bind_action);
									
									if (rast_sta_bind_action == RAST_STAAPBANDBIND_ACTION_BLOCK) {
										rast_remove_from_assoclist(i, multilan_subunit, 
											rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), 1);
									}
									else {
										sta_roaming_bypass_status_update(i, multilan_subunit, 
											rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), ROAMING_BYPASS);
									}
								}
							}
						}
					}
#endif

#if 0
					if(nvram_safe_get("re_mode") && nvram_get_int("re_mode") == 1)
					{ //RE

						rast_add_to_maclist(i, 1, rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
						,0
#endif
						,rast_sta_bind_action);
						if(rast_sta_bind_action == RAST_STAAPBANDBIND_ACTION_BLOCK)
							rast_remove_from_assoclist(i, 1, 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp),1);
						else{
							sta_roaming_bypass_status_update(i, 1, 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp),ROAMING_BYPASS);
						}

#ifdef RTCONFIG_FRONTHAUL_DWB
						if( i > 1 && (nvram_get_int("fh_re_mssid_subunit") > 0) )//fh_re_mssid_subunit
							rast_add_to_maclist(i, nvram_get_int("fh_re_mssid_subunit"), 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
								,0
#endif
								,rast_sta_bind_action);						
#endif

					} else { //CAP

						rast_add_to_maclist(i, 0, rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
						,0
#endif
						,rast_sta_bind_action);

#ifdef RTCONFIG_FRONTHAUL_DWB
						if( i > 1 && (nvram_get_int("fh_cap_mssid_subunit") > 0) )//fh_re_mssid_subunit
							rast_add_to_maclist(i, nvram_get_int("fh_cap_mssid_subunit"), 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
								,0
#endif
								,rast_sta_bind_action);						
#endif


						if(rast_sta_bind_action == RAST_STAAPBANDBIND_ACTION_BLOCK)
							rast_remove_from_assoclist(i, 0, 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp),1);
						else{
							sta_roaming_bypass_status_update(i, 0, 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp),ROAMING_BYPASS);
						}

					}
#endif
					
				}

				staapbandbind_sta_list_tmp_pre = staapbandbind_sta_list_tmp;
				staapbandbind_sta_list_tmp = staapbandbind_sta_list_tmp->next;
				break;

			case RAST_ACL_STAAPBANDBIND_REMOVE:

				RAST_DBG("%s remove ACL \n",staapbandbind_sta_list_tmp->stamac);
				for (i=0; i<max_band_num; i++) {

					if(nvram_safe_get("re_mode") && nvram_get_int("re_mode") == 1) {
						start_subunit = 1;
						first_wgn_subunit = 2;
						fh_mssid_subunit = nvram_get_int("fh_re_mssid_subunit");
					}
					else {
						start_subunit = 0;
						first_wgn_subunit = 1;
						fh_mssid_subunit = nvram_get_int("fh_cap_mssid_subunit");
					}

					rast_add_to_maclist(i, start_subunit, 
						rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
						,0
#endif
						,RAST_STAAPBANDBIND_ACTION_UNBLOCK);

					sta_roaming_bypass_status_update(i, start_subunit, 
						rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), ROAMING_NOT_BYPASS);

#ifdef RTCONFIG_FRONTHAUL_DWB
					if( i > 1 && fh_mssid_subunit > 0 ) {
						rast_add_to_maclist(i, fh_mssid_subunit,
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
							,0
#endif
							,RAST_STAAPBANDBIND_ACTION_UNBLOCK);
					}
#endif

#ifdef RTCONFIG_AMAS_WGN
					char first_wgn_prefix[32];
					char first_wgn_enable[32];
					snprintf(first_wgn_prefix, sizeof(first_wgn_prefix), "wl%d.%d", i, first_wgn_subunit);
					snprintf(first_wgn_enable, sizeof(first_wgn_enable), "%s_bss_enabled", first_wgn_prefix);
					
					if (nvram_get_int(first_wgn_enable)==1) {
						RAST_DBG("rast_add_to_maclist , interface=%s, action=%d\n", first_wgn_prefix, RAST_STAAPBANDBIND_ACTION_UNBLOCK);

						rast_add_to_maclist(i, first_wgn_subunit, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
							,0
#endif
							,RAST_STAAPBANDBIND_ACTION_UNBLOCK);
						
						sta_roaming_bypass_status_update(i, first_wgn_subunit, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), ROAMING_NOT_BYPASS);
					}
#endif

#ifdef RTCONFIG_MULTILAN_CFG
					char word[64];
					char *next = NULL;
					int total = 0;
					int multilan_unit = -1, multilan_subunit = -1;

					ap_wifi_rule_st ap_wifi_rl[MAX_AP_RULE_LIST];
					memset(ap_wifi_rl, 0, (sizeof(ap_wifi_rule_st) * MAX_AP_RULE_LIST));

					if (get_ap_wifi_rl_from_nvram(ap_wifi_rl, MAX_AP_RULE_LIST, &total) && total > 0) {
						
						for (j=0; j<total; j++) {

							foreach_44(word, ap_wifi_rl[j].wlif_set, next) {
									
								sscanf(word, "wl%d.%d", &multilan_unit, &multilan_subunit);

								if (multilan_unit==i && multilan_subunit>start_subunit) {
									
									RAST_DBG("rast_add_to_maclist , interface=%s, action=%d\n", word, RAST_STAAPBANDBIND_ACTION_UNBLOCK);
									
									rast_add_to_maclist(i, multilan_subunit, 
										rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
										,0
#endif
										,RAST_STAAPBANDBIND_ACTION_UNBLOCK);

									sta_roaming_bypass_status_update(i, multilan_subunit, 
										rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp), ROAMING_NOT_BYPASS);

								}
							}
						}
					}
#endif
						
#if 0
					if(nvram_safe_get("re_mode") && nvram_get_int("re_mode") == 1)
					{ //RE
						rast_add_to_maclist(i, 1, rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
						,0
#endif
						,RAST_STAAPBANDBIND_ACTION_UNBLOCK);

						sta_roaming_bypass_status_update(i, 1, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp),ROAMING_NOT_BYPASS);
#ifdef RTCONFIG_FRONTHAUL_DWB
						if( i > 1 && (nvram_get_int("fh_re_mssid_subunit") > 0) )
							rast_add_to_maclist(i, nvram_get_int("fh_re_mssid_subunit"), 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
								,0
#endif
								,RAST_STAAPBANDBIND_ACTION_UNBLOCK);						
#endif

					} else { //CAP
						rast_add_to_maclist(i, 0, rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
						,0
#endif
						,RAST_STAAPBANDBIND_ACTION_UNBLOCK);

#ifdef RTCONFIG_FRONTHAUL_DWB
						if( i > 1 && (nvram_get_int("fh_cap_mssid_subunit") > 0) )
							rast_add_to_maclist(i, nvram_get_int("fh_cap_mssid_subunit"), 
								rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp)
#ifdef RTCONFIG_FORCE_ROAMING
								,0
#endif
								,RAST_STAAPBANDBIND_ACTION_UNBLOCK);						
#endif

						sta_roaming_bypass_status_update(i, 0, 
							rast_ether_atoe(staapbandbind_sta_list_tmp->stamac,&ea_tmp),ROAMING_NOT_BYPASS);

					}
#endif
				}

				if(!staapbandbind_sta_list_tmp_pre){
					staapbandbind_sta_list_g = staapbandbind_sta_list_tmp->next;
					free(staapbandbind_sta_list_tmp);
					staapbandbind_sta_list_tmp = staapbandbind_sta_list_g;
				} else {
					staapbandbind_sta_list_tmp_pre->next = staapbandbind_sta_list_tmp->next;
					free(staapbandbind_sta_list_tmp);
					staapbandbind_sta_list_tmp = staapbandbind_sta_list_tmp_pre->next;
				}
				break;

			case RAST_ACL_STAAPBANDBIND_NOTHING:

				RAST_DBG("%s ACL has no changes, do nothing\n",staapbandbind_sta_list_tmp->stamac);
				staapbandbind_sta_list_tmp_pre = staapbandbind_sta_list_tmp;
				staapbandbind_sta_list_tmp = staapbandbind_sta_list_tmp->next;
				break;

			default:

				RAST_DBG("%s ACL has invaild status %d\n",staapbandbind_sta_list_tmp->stamac,
												staapbandbind_sta_list_tmp->status);
				staapbandbind_sta_list_tmp_pre = staapbandbind_sta_list_tmp;
				staapbandbind_sta_list_tmp = staapbandbind_sta_list_tmp->next;
				break;
		}
	} 

	ret = 1;

rast_Proc_STA_BINDING_UPDATE_end:

	if(cfg_rejoin_pre) cfg_rejoin_pre_done=1;

	return ret;

}

int sta_roaming_bypass_status_update(int bssidx, int vifidx, struct ether_addr *addr,int action)
{
	//bool found = FALSE;
	rast_sta_info_t *assoclist = NULL;
	//char wlif_name[32];
	//char cmd[128];
	pthread_mutex_lock(&roamastBssinfoLock);

	assoclist = bssinfo[bssidx].assoclist[vifidx];
	if(assoclist == NULL) {
		pthread_mutex_unlock(&roamastBssinfoLock);
		return 0;
	}

	/* found at 1st element, update pointer */
	while(assoclist) {
		if(!memcmp(&(assoclist->addr), addr, sizeof(struct ether_addr)))
		{
			if(action == ROAMING_BYPASS)
				assoclist->in_binding_list = 1;
			else
				assoclist->in_binding_list = 0;
			break;
		}
		assoclist = assoclist->next;
	}

	pthread_mutex_unlock(&roamastBssinfoLock);

	return 0;
}

int sta_binding_list_check(struct ether_addr *addr)
{
	char nvram_buf[4096]={0},stamac[MAC_STR_LEN+1];
	char *nvp, *b;
	int stalist_len,stalist_idx,allowband_str_len,i;
	char *remac,*enable,*stalist;
	struct ether_addr ea_tmp;

	char remac_tmp[18];
	char lanmac_tmp[18];

	strncpy(nvram_buf,nvram_safe_get("sta_binding_list"),sizeof(nvram_buf));

	strncpy(lanmac_tmp,nvram_safe_get("lan_hwaddr"),sizeof(lanmac_tmp));
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		lanmac_tmp[i]=toupper(lanmac_tmp[i]);	


	nvp = nvram_buf;

	if ( strlen(nvram_buf) ) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ( (vstrsep(b, ">", &remac, &enable, &stalist) != 3) )
				continue;
			if( !strcmp(enable,"0") )
				continue;
			else if( !strcmp(enable,"1") )
				;
			else {
				RAST_INFO("incorrect para\n");
				continue;
			}

			strncpy(remac_tmp,remac,sizeof(remac_tmp));

			RAST_INFO("%s %s\n",remac,lanmac_tmp);

			for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
				remac_tmp[i]=toupper(remac_tmp[i]);

			if( strcmp(remac,lanmac_tmp) )
				continue;

			stalist_len = strlen(stalist);
			stalist_idx = 0;
			allowband_str_len = 0;

			while(1)// break when stalist len = 0 
			{
				if(stalist_idx + MAC_STR_LEN+2 > stalist_len)//MAC_STR_LEN+2 => STA1 mac,Band index
					break;
				memset(stamac,0,MAC_STR_LEN+1);
				strncpy(stamac,stalist+stalist_idx,MAC_STR_LEN);

				if( !memcmp(rast_ether_atoe(stamac,&ea_tmp),addr,sizeof(struct ether_addr)) )
				{
					RAST_DBG("match binding list entry\n");
					return 1;
				}

				stalist_idx += MAC_STR_LEN;

				if( stalist[stalist_idx] != ',' )
				{
					RAST_INFO("AP STA BAND BIND format error[%s]\n",stalist);
					break;
				}
				stalist_idx++;

				while(1){
					//RAST_DBG("%c\n",stalist[stalist_idx]);
					if(stalist_idx+allowband_str_len >= stalist_len)
						break;
					if(stalist[stalist_idx+allowband_str_len] == '|')
						break;
					allowband_str_len++;
				}
				//memset(allowband_str,0,sizeof(allowband_str));
				//strncpy(allowband_str,&stalist[stalist_idx],allowband_str_len);

				stalist_idx += allowband_str_len;

				//allowband = atoi(allowband_str);

				if( stalist_idx + 1 >= stalist_len || stalist[stalist_idx] != '|' )
					break;
				stalist_idx++;
			}
		}
	}

	return 0;
}
#endif//end of RTCONFIG_STA_AP_BAND_BIND
