#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <syslog.h>
#include <signal.h>

#include <shared.h>
#ifdef SW_HW_AUTH
/* common header */
#include <auth_common.h>
#endif
#include "aaeuac.h"

#include "log.h"
#include "ssl_api.h"
#include "ws_api.h"
#include "time_util.h"

#include "queue_manager.h"
#include "sync.h"
#include "natapi.h"
#include "common.h"
#include "nat_nvram.h"

#include "nw_util.h"
#include "ws_caller.h"

#define UAC_DBG 1

#define PROTO_PPTP "PPTP"
#define PROTO_L2TP "L2TP"
#define PROTO_OVPN "OpenVPN"
#define PROTO_IPSec "IPSec"
#define PROTO_WG "WireGuard"
#define PROTO_HMA "HMA"
#define PROTO_NORDVPN "NordVPN"
#define PROTO_HTTPD "HTTPD"
#define PROTO_AWSIOT "AWSIOT"

typedef enum{
	AAEUAC_PROTO_UNDEF,
	AAEUAC_PROTO_HTTPD,
	AAEUAC_PROTO_PPTP,
	AAEUAC_PROTO_L2TP,
	AAEUAC_PROTO_OVPN,
	AAEUAC_PROTO_IPSEC,
	AAEUAC_PROTO_WG,
	AAEUAC_PROTO_HMA,
	AAEUAC_PROTO_NORDVPN,
	AAEUAC_PROTO_AWSIOT,
}AAEUAC_PROTO;

#define PROC_NAME "aaeuac"
#define AAEUAC_LOG_PATH "/tmp/aaeuac_log"
#define	INIT_EVENT_NAME "UAC_NAT_INIT"
#define	DEINIT_EVENT_NAME "UAC_NAT_DEINIT"
#define AIHOME_API_LEVEL EXTEND_AIHOME_API_LEVEL // From shared/shared.h
#define DEVICE_TYPE "93"
#define ASUS_DEVICE_SERVICE "1001"

// event queue related
pthread_mutex_t lock;
pthread_t queue_tid;
sem_t* p_ginit_sem;
sem_t* p_gdeinit_sem;
sem_t* queue_sem;
QUEUE* ev_queue_list;

// asusnatnl related
struct natnl_config g_natnl_cfg;
struct natnl_callback g_natnl_callback;
NAT_INIT3		nat_init3;
NAT_DEINIT		nat_deinit;
NAT_MAKECALL3	nat_makecall3;
NAT_HANG_UP		nat_hangup;
NAT_READ_TNL_INFO	nat_read_tnl_info;

// aaeuac related
int g_is_terminate = 0;

int g_main_deinit_alert = 0;
int g_event_queue_inited = 0;
char *g_portal_server = NULL;
char *g_login_server = NULL;
int g_vpn_type = 0;
int g_vpn_idx = -1;
int g_call_id = -1;
char g_vpn_prefix[16] = {0};
char g_device_id[64] = {0};
char g_callee_id[64] = {0};
char g_device_port[64] = {0};

static server_map_t server_list[] = {
    {".com", SERVER, LOGIN_SERVER},
    {".cn", "aae-spweb.asuscomm.cn", "aae-sgweb086-1.asuscomm.cn"},
    {NULL, NULL, NULL}
};

static void reset_vpn_nvram(int type, char *prefix) {
	if (!type || !prefix)
		return;
	if (type == AAEUAC_PROTO_WG) {
		if (nvram_pf_get_int(prefix, "ep_tnl_active") == 1)
			nvram_pf_set(prefix, "ep_addr_r", "");
		nvram_pf_set(prefix, "ep_tnl_active", "0");
		//nvram_pf_set(prefix, "ep_tnl_addr", "");
		nvram_pf_set(prefix, "ep_tnl_port", "");
	}
}

static void set_tnl_active(int type, char *prefix, struct natnl_tnl_info *tnl_info, natnl_tnl_port *tnl_port) {
	char *s2s_aaeuac_port_path = NULL;
	if (!type || !prefix || !tnl_info || !tnl_port)
		return;

	Cdbg(UAC_DBG, "lport = %s,\nrport = %s,\nqos_priority = %d,\ndisable_flow_control = %d,\nspeed_limit = %d,\nrip = %s,\ntnl_type = %d,\napp_data = %p\n", 
		tnl_port->lport, tnl_port->rport, tnl_port->qos_priority, tnl_port->disable_flow_control, 
		tnl_port->speed_limit, tnl_port->rip, tnl_info->tnl_type, tnl_info->app_data);
	s2s_aaeuac_port_path = (char *)tnl_info->app_data;
	if (s2s_aaeuac_port_path) {
		if (type == AAEUAC_PROTO_AWSIOT) {
			char result[256];
			char *tnl_type = "unknown";
			if (tnl_info->tnl_type == 2)
				tnl_type = "relay";
			else if (tnl_info->tnl_type == 3)
				tnl_type = "p2p";
			snprintf(result, sizeof(result), AAE_TUNNEL_TEST_RES, tnl_info->para.local_info.device_id, 
				tnl_info->para.remote_info.device_id, tnl_type, (tnl_info->status_code == 200 ? 0 : tnl_info->status_code));
			f_write_string(s2s_aaeuac_port_path, result, 0, 0);
			kill_all_proc(PROC_NAME);
		} else {
			f_write_string(s2s_aaeuac_port_path, tnl_port->lport, 0, 0);
		}
	}
	if (type == AAEUAC_PROTO_WG) {
		if (nvram_pf_match(g_vpn_prefix, "ep_port", tnl_port->rport)) {
			nvram_pf_set(prefix, "ep_tnl_active", "1");
			/*if (address) {
				char prefix[8] = {0};
				char wan_addr[64] = {0};
				char wan_mask[64] = {0};
				snprintf(prefix, sizeof(prefix), "wan%d_", wan_primary_ifunit());
				snprintf(wan_addr, sizeof(wan_addr), "%s", nvram_pf_safe_get(prefix, "_ipaddr"));
				snprintf(wan_mask, sizeof(wan_mask), "%s", nvram_pf_safe_get(prefix, "_netmask"));
				if (!is_same_subnet(wan_addr, address, wan_mask))
					nvram_pf_set(prefix, "ep_tnl_addr", address);
			}*/
			nvram_pf_set(prefix, "ep_tnl_port", tnl_port->lport);
		}
	}
}

static char *get_vpn_ep_device_id(int type, char *prefix) {
	if (!type || !prefix)
		return "";
	if (type == AAEUAC_PROTO_WG)
		return nvram_pf_safe_get(prefix, "ep_device_id");
	return "";
}

static char *get_vpn_ep_port(int type, char *prefix) {
	if (!type || !prefix)
		return "";
	if (type == AAEUAC_PROTO_WG)
		return nvram_pf_safe_get(prefix, "ep_port");
	return "";
}

static char *get_vpn_ep_area(int type, char *prefix) {
	if (!type || !prefix)
		return "";
	if (type == AAEUAC_PROTO_WG)
		return nvram_pf_safe_get(prefix, "ep_area");
	return "";
}

static int get_server(char *area, char **portal, char **login)
{
	if (!portal || !login)
		return -1;
	server_map_t *list = server_list;
	while (list && list->area) {
		if(!strcmp(list->area, area) || 
			!strcmp(list->portal, area)) {
			*portal = list->portal;
			*login = list->login;
			return 0;
		}
		list++;
	}
	return -2;
}

static void aaeuac_errlog(char *buf)
{
	openlog("aaeuac", 0, 0);
	syslog(0, buf);
	closelog();

	fprintf(stderr,"[aaeuac]%s\n",buf);
}

int kill_all_proc(const char* appname)
{
#define WAIT_TIME 10
	pid_t *pidList;
	pid_t *pl;
	char cmd [32];
	int wait_count = 0;

	// Request the process termination
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "killall %s", appname);
	system(cmd);

	// Wait the process termination
	while (pids((char *)appname) && wait_count < WAIT_TIME) {
		sleep(1);
        Cdbg(UAC_DBG, "Wait %s stopping.", appname);
        wait_count++;
	}

	// kill with -9 forcely if any.
	pidList = find_pid_by_name(appname);
    for (pl = pidList; *pl; pl++) {
		sprintf(cmd, "kill -9 %d", *pl);
		//fprintf(stderr, "kill %s %d", appname, *pl);
		system(cmd);
	}
    return 0;
}

#ifdef  TNL_CALLBACK_ENABLE
void dispatch_tunnel_event(struct natnl_tnl_event* tnl_event)
{
	Cdbg(UAC_DBG, "tnl_event =%d, post to tmp data list", tnl_event->event_code);
	//PostDataToQueue(tnl_event, sizeof(struct natnl_tnl_event));
	int struct_size = sizeof(struct natnl_tnl_event);
	struct natnl_tnl_event* event_clone = malloc(struct_size);
	memset(event_clone, 0, struct_size);
	memcpy(event_clone, tnl_event, struct_size);
	Cdbg(UAC_DBG, "Push Queue to List event_clone =%p", event_clone);
	PushQueue(&lock, ev_queue_list, event_clone );
	sem_post(queue_sem);
}

void* deal_cb_event(void* userdata)
{
	Cdbg(UAC_DBG, ">>>>>>>> starts userdata=%p", userdata);
	struct natnl_tnl_event* tnl_event = (struct natnl_tnl_event*)userdata;
	if (tnl_event->event_code != 60114)
		Cdbg(UAC_DBG, ">>>>>>>> event_code =========================> %d ", tnl_event->event_code);

	if (tnl_event->event_code == NATNL_TNL_EVENT_INIT_OK) {
		Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_INIT_OK" );
		nvram_set_int("aaeuac_sdk_inited", 1);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_DEINIT_OK) {
		Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_DEINIT_OK" );
		nvram_set_int("aaeuac_sdk_inited", 0);
#if 0
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		clr_all_tnl_state();
#endif
#endif
#if 0
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_REG_FAILED) {
		Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_REG_FAILED" );
		//if(tnl_event > 0) nat_hangup(tnl_event->call_id);
		nvram_set_aaeuac_sip_connected("0");
		if (tnl_event->status_code == 401) {
			Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event authenticate fail.");
			kill_all_proc(PROC_NAME);
		}
		// Save server status to nvram
		nvram_set_server_status("sip", tnl_event->status_code, tnl_event->status_text);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_REG_OK) {
		nvram_set_aaeuac_sip_connected("1");
		Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_REG_OK" );
		// Save server status to nvram
		nvram_set_server_status("sip", tnl_event->status_code, tnl_event->status_text);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_UNREG_OK) {
		nvram_set_aaeuac_sip_connected("0");
		Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_UNREG_OK" );
		// Save server status to nvram
		// nvram_set_server_status("sip", tnl_event->status_code, tnl_event->status_text);
#endif
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_OK) {
		logmessage(PROC_NAME, "Tunnel built successfully.");
		Cdbg(UAC_DBG, "remote_address = %s", tnl_event->para.remote_info.address);
		g_call_id = tnl_event->call_id;

		if (nat_read_tnl_info) {
			struct natnl_tnl_info tnl_info = {0};
			natnl_tnl_port *tnl_port = NULL;
			int i;
			nat_read_tnl_info(tnl_event->call_id, &tnl_info);
			for (i=0; i < tnl_info.tnl_port_cnt; i++) {
				//set_tnl_active(g_vpn_type, g_vpn_prefix, tnl_info.para.remote_info.address, tnl_port->lport, tnl_port->rport, tnl_info.app_data);
				set_tnl_active(g_vpn_type, g_vpn_prefix, &tnl_info, &tnl_info.tnl_ports[i]);
			}
		}
#if 0
		// Save server status to nvram
		nvram_set_server_status("stun", tnl_event->stun_last_status, tnl_event->stun_status_text);
		nvram_set_server_status("turn", tnl_event->turn_last_status, tnl_event->turn_status_text);*/
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_ACTIVE);
#endif
#endif
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_FAILED) {
		logmessage(PROC_NAME, "Tunnel built failed. status code=[%d]", tnl_event->status_code);
		reset_vpn_nvram(g_vpn_type, g_vpn_prefix);
#if 0
		// Save server status to nvram
		nvram_set_server_status("stun", tnl_event->stun_last_status, tnl_event->stun_status_text);
		nvram_set_server_status("turn", tnl_event->turn_last_status, tnl_event->turn_status_text);
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
#endif
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_KA_TIMEOUT) {
	    Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_KA_TIMEOUT" );

		if (nat_read_tnl_info) {
			struct natnl_tnl_info tnl_info = {0};
			natnl_tnl_port *tnl_port = NULL;
			int i;
			nat_read_tnl_info(tnl_event->call_id, &tnl_info);
			for (i=0; i < tnl_info.tnl_port_cnt; i++) {
				tnl_port = &tnl_info.tnl_ports[i];
				reset_vpn_nvram(g_vpn_type, g_vpn_prefix);
				Cdbg(UAC_DBG, "lport = %s,\nrport = %s,\nqos_priority = %d,\ndisable_flow_control = %d,\nspeed_limit = %d,\nrip = %s,\ntnl_type = %d\n", 
					tnl_port->lport, tnl_port->rport, tnl_port->qos_priority, tnl_port->disable_flow_control, 
					tnl_port->speed_limit, tnl_port->rip, tnl_info.tnl_type);
			}
		}
#if 0
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
#endif
	    //if(tnl_event > 0) nat_hangup(tnl_event->call_id);
#if 0
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_NAT_TYPE_DETECTED) {
		if(g_enable_ws){
			Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_NAT_TYPE_DETECTED" );
			DECLARE_CLEAR_MEM(char, status_t, 8);
			sprintf(status_t, "%d", tnl_event->status_code);
			st_UpdateProfile(status_t, tnl_event->nat_type,  tnl_event->mac_address, &gsa, &lg);
		}
		//st_ListProfile( &gsa, &lg, &lp, &pP );
#endif
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_DEADLOCK) {
		// Suicide
		Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_DEADLOCK" );
		aaeuac_errlog(">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_DEADLOCK");
		//kill(getpid(), SIGKILL);
		kill_all_proc(PROC_NAME);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_HANGUP_OK) {

		if (nat_read_tnl_info) {
			struct natnl_tnl_info tnl_info = {0};
			natnl_tnl_port *tnl_port = NULL;
			int i;
			nat_read_tnl_info(tnl_event->call_id, &tnl_info);
			for (i=0; i < tnl_info.tnl_port_cnt; i++) {
				tnl_port = &tnl_info.tnl_ports[i];
				reset_vpn_nvram(g_vpn_type, g_vpn_prefix);
				Cdbg(UAC_DBG, "lport = %s,\nrport = %s,\nqos_priority = %d,\ndisable_flow_control = %d,\nspeed_limit = %d,\nrip = %s,\ntnl_type = %d\n", 
					tnl_port->lport, tnl_port->rport, tnl_port->qos_priority, tnl_port->disable_flow_control, 
					tnl_port->speed_limit, tnl_port->rip, tnl_info.tnl_type);
			}
		}
#if 0
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
#endif
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_HANGUP_FAILED) {

		if (nat_read_tnl_info) {
			struct natnl_tnl_info tnl_info = {0};
			natnl_tnl_port *tnl_port = NULL;
			int i;
			nat_read_tnl_info(tnl_event->call_id, &tnl_info);
			for (i=0; i < tnl_info.tnl_port_cnt; i++) {
				tnl_port = &tnl_info.tnl_ports[i];
				reset_vpn_nvram(g_vpn_type, g_vpn_prefix);
				Cdbg(UAC_DBG, "lport = %s,\nrport = %s,\nqos_priority = %d,\ndisable_flow_control = %d,\nspeed_limit = %d,\nrip = %s,\ntnl_type = %d\n", 
					tnl_port->lport, tnl_port->rport, tnl_port->qos_priority, tnl_port->disable_flow_control, 
					tnl_port->speed_limit, tnl_port->rip, tnl_info.tnl_type);
			}
		}
#if 0
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
#endif
	} else {
		Cdbg(UAC_DBG, "Bypass the event = %d", tnl_event->event_code);
	}

	Cdbg(UAC_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event return " );

	free(tnl_event);
	return NULL;
}

void* pop_queue_thread(void* data)
{
	QUEUE* q = (QUEUE*) data;
	void* p = NULL;
	Cdbg(UAC_DBG, "pop queue thread starts .....q =%p ",q);
	while(!g_main_deinit_alert){
		if(-1 == wait_event(queue_sem)){
			Cdbg(UAC_DBG, "sem_wait failed..... =%p ");
			break;
		}
		Cdbg(UAC_DBG, "Queue alert ");
		if(!QueueIsEmpty(&lock, q))	{
			p = PopQueue(&lock, q);
			if(p){
				Cdbg(UAC_DBG, " Pop data point =%p ", p);
				deal_cb_event(p);
			}
		}
	}
	Cdbg(UAC_DBG, "pop queue thread stops .....q =%p ",q);
	pthread_exit("stop pop queue thread");
}

int create_watch_queue_thread(QUEUE* q)
{
	int status;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	status = pthread_create(&queue_tid, &attr, pop_queue_thread, q);
	pthread_attr_destroy(&attr);
	return status;
}

int remove_watch_queue_thread()
{
	char* ret =NULL;
	if(queue_tid) {
		set_event(queue_sem);
		pthread_join(queue_tid, (void **)&ret);
		deinit_semaphore(queue_sem,"QUEUE_SEM2" );
	}
	if(g_main_deinit_alert){
		pthread_mutex_destroy(&lock);
	}
	return 0;
}

int nat_deinit_sync()
{
	init_semaphore(&p_gdeinit_sem, DEINIT_EVENT_NAME);
	nat_deinit();
	wait_event(p_gdeinit_sem);
	deinit_semaphore(p_gdeinit_sem, DEINIT_EVENT_NAME);

	return 0;
}

#endif

void load_default_config(struct natnl_config *config)
{
	char* ts;
	int max_tunnels = nvram_get_int("aae_max_tunnels");
	config->max_calls = (max_tunnels <= 0 || max_tunnels >= MAX_CALLS) ? MAX_CALLS : max_tunnels;
	config->tnl_timeout_sec = 60;
	config->disable_sdp_compress = 1;
	config->bandwidth_KBs_limit	= 0;
	config->is_server_side_app	= 0;
	config->fast_init = 1;

	// sdk log related
	config->log_cfg.log_level = nvram_get_int("aaeuac_sdk_log_level");
	config->log_cfg.log_file_size = 512;
	config->log_cfg.log_rotate_number = 5;
	config->log_cfg.log_file_flags = 0;
	config->log_cfg.syslog_facility = 0;

	alloc_time_string("%Y-%m-%d_%H:%M:%S", 0, &ts);
	snprintf(config->log_cfg.log_filename, sizeof(config->log_cfg.log_filename), "%s/aaeuac_sdk_%s.txt", SDK_LOG_PATH, ts);
	dealloc_time_string(ts);
	snprintf(config->log_cfg.log_flag_file, sizeof(config->log_cfg.log_flag_file), "%s",SDK_LOG_FLAG_FILE);
}

void save_config(Login login, struct natnl_config *config)
{
	SrvInfo* p;
	memset(config, 0, sizeof(natnl_config));
	load_default_config(config);
	snprintf(g_device_id, sizeof(g_device_id), "%s", login.deviceid);
	snprintf(config->device_id, sizeof(config->device_id), "%s@aaerelay.asuscomm.com", login.deviceid);
	snprintf(config->device_pwd, sizeof(config->device_pwd), "%s", login.deviceticket);
	for(p=login.relayinfoList;p;p=p->next){
		snprintf(config->sip_srv[config->sip_srv_cnt], sizeof(config->sip_srv[config->sip_srv_cnt]), "%s", p->srv_ip);
		config->sip_srv_cnt++;
	}
	for(p=login.stuninfoList;p;p=p->next){
		snprintf(config->stun_srv[config->stun_srv_cnt], sizeof(config->stun_srv[config->stun_srv_cnt]), "%s", p->srv_ip);
		config->stun_srv_cnt++;
	}
	for(p=login.turninfoList;p;p=p->next){
		snprintf(config->turn_srv[config->turn_srv_cnt], sizeof(config->turn_srv[config->turn_srv_cnt]), "%s", p->srv_ip);
		config->turn_srv_cnt++;
	}

	if (config->stun_srv_cnt)
		config->use_stun = 1;
	if (config->turn_srv_cnt)
		config->use_turn = nvram_pf_get(g_vpn_prefix, "tnl_use_turn") ? nvram_pf_get_int(g_vpn_prefix, "tnl_use_turn") : 2;
}

int get_uac_config_shared_link_mode(int vpn_type, char *area, struct natnl_config *config)
{
	int ret, status = -1, unsupported_area = 0, retry_cnt = 0, random_delay = 0;
	char *portal_server = NULL, *login_server = NULL;
	char userid[32] = {0}, userpwd[32] ={0}, cusid[32] = {0}, user_ticket[32] = {0}, md5string[MD_STR_LEN+1] = {0}, device_desc[32] = {0},
		fwver[128] = {0};
	Login login;
	GetServiceArea getservicearea;
    char dev_desc_buf[ASUS_DEVICE_DESC_LEN];

	if (!config)
		return -1;
	snprintf(userid, sizeof(userid), "%s@asuscomm.com", nvram_safe_get(ROUTER_MAC));
	int rand_value = rand()%100 +2000;
	snprintf(userpwd, sizeof(userpwd), "%d", rand_value);

	if (vpn_type == AAEUAC_PROTO_AWSIOT) {
		while (1) { // retry util sucess
			ret = st_Login(&getservicearea, &login, userid, userpwd, 
				generate_device_desc(is_private_ip(11) ? 0 : 1, NULL, dev_desc_buf, sizeof(dev_desc_buf)));
			if (ret == 0)
				break;
			random_delay = get_random_delay(retry_cnt, RETRY_DELAY_BASE_SECONDS, MAX_RETRY_DELAY_DELAYED_SECONDS);
			if (retry_cnt < RETRY_MAX_TIMES)
				retry_cnt++;
			sleep(random_delay);
		}
	} else {
		ret = get_server(area, &portal_server, &login_server);
		if (ret != 0) // TODO need to get area dynamically.
			return ret;

		Cdbg(UAC_DBG, "portal=%s, login=%s", portal_server, login_server);

		ret = -3;
		while (1) { // retry util sucess
			snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
			if (unsupported_area) {
				memset(&getservicearea, 0, sizeof(GetServiceArea));
				status = send_getservicearea_req(
					portal_server,
					ASUS_DEVICE_SERVICE,
					userid,
					userpwd,
					DEVICE_TYPE,
					fwver,
					AIHOME_API_LEVEL,
					nvram_safe_get(NVRAM_MODEL_NAME),
					&getservicearea);
				if (status != 0 || strcmp(getservicearea.status, "0")) {
					random_delay = get_random_delay(retry_cnt, RETRY_DELAY_BASE_SECONDS, MAX_RETRY_DELAY_DELAYED_SECONDS);
					if (retry_cnt < RETRY_MAX_TIMES)
						retry_cnt++;
					sleep(random_delay);
					continue;
				}
				login_server = getservicearea.servicearea;
			}

			memset(&login, 0, sizeof(Login));
			get_md5_string(nvram_safe_get(ROUTER_MAC), md5string);
			status = send_login_req(login_server, userid, userpwd, cusid, user_ticket, md5string,
				ASUS_DEVICE_NAME, ASUS_DEVICE_SERVICE, DEVICE_TYPE, PERMISSION, device_desc,
				fwver, AIHOME_API_LEVEL, nvram_safe_get(NVRAM_MODEL_NAME), &login);

			//snprintf(login.status, sizeof(login.status), "%d", 10);

			if (status == 0 && !strcmp(login.status, "0"))
				break;

			if (!strcmp(login.status, "9") && strcmp(login.apilevel_status, APILEVEL_STATUS_SUPPORT)) { // need to check apilevel
				if (!strcmp(login.apilevel_status, APILEVEL_STATUS_END_OF_LIFE)) {
					nvram_set(AAE_SUPPORT_LEVEL, "-1");
					nvram_commit();
					return -3;
				}
				else if (!strcmp(login.apilevel_status, APILEVEL_STATUS_APILEVEL_NOT_SUPPORT) || 
					!strcmp(login.apilevel_status, APILEVEL_STATUS_FW_VERSION_NOT_SUPPORT)) {
					nvram_set(AAE_SUPPORT_LEVEL, login.apilevel);
					nvram_commit();
					return -4;
				}
			} else if (!strcmp(login.status, "10")) { // unsupported area
				Cdbg(UAC_DBG, "Login failed status =%s", login.status);
				unsupported_area = 1;
				continue;
			}

			random_delay = get_random_delay(retry_cnt, RETRY_DELAY_BASE_SECONDS, MAX_RETRY_DELAY_DELAYED_SECONDS);
			if (retry_cnt < RETRY_MAX_TIMES)
				retry_cnt++;
			sleep(random_delay);
		}
	}

	// save information into nat_config
	save_config(login, config);

	return 0;
}

int get_uac_config_acc_based_mode(struct natnl_config *config)
{
	return 0;
}

int init_event_queue()
{
	int ret = pthread_mutex_init(&lock, NULL);
	if(ret)
		return -1;
	ev_queue_list = malloc(sizeof(QUEUE));
	//Cdbg(UAC_DBG, ">>>>>>> 11 -2 lock=%p" , &lock);
	ret = init_semaphore(&queue_sem, "QUEUE_SEM2");
	if(ret){
		Cdbg(UAC_DBG, ">>>> 11-2-1 Init Sem failed");
		return -2;
	}
	//Cdbg(UAC_DBG, "queue_sem = %p", queue_sem);
	ret = InitQueue(&lock, ev_queue_list);
	if(ret) {
		if(ev_queue_list)
			free(ev_queue_list);
		return -4;
	}
	//Cdbg(UAC_DBG, ">>>>>>> 11 -3" , ret);
	ret = create_watch_queue_thread(ev_queue_list);
	if(ret)
		return -5;

	return 0;
}

int deinit_event_queue()
{
	return remove_watch_queue_thread();
}

int nat_sdk_init(void *app_data)
{
	int ret;
	if (!g_event_queue_inited && init_event_queue() == 0)
		g_event_queue_inited = 1;

	g_natnl_callback.on_natnl_tnl_event = &dispatch_tunnel_event;

    ret = nat_init3(&g_natnl_cfg, &g_natnl_callback, app_data);
	Cdbg(APP_DBG, ">>>>> nat_init. ret=%d", ret);
	return ret;
}

int nat_make_tunnel(char *ep_device_id, char *ep_port, int disable_flow_control)
{
	if (!ep_device_id || !ep_port)
		return -1;
	natnl_tnl_port tnl_ports[1] = {0};
	snprintf(tnl_ports[0].lport, sizeof(tnl_ports[0].lport), "0");
	snprintf(tnl_ports[0].rport, sizeof(tnl_ports[0].rport), "%s",  ep_port);  // should perform validate checking.
	//snprintf(tnl_ports[0].rip, sizeof(tnl_ports[0].rip), "192.168.50.1");
	tnl_ports[0].disable_flow_control = disable_flow_control;//nvram_get_int("s2s_disable_flow_ctl");
	struct natnl_tnl_info tnl_info = {0};
	int ret = nat_makecall3(ep_device_id, sizeof(tnl_ports)/sizeof(natnl_tnl_port), 
		tnl_ports, "aaeuac", 30, 0, 1, g_natnl_cfg.device_pwd, &tnl_info);
	//Cdbg(UAC_DBG, "nat_makecall3 ret = %d", ret);
	return ret;
}
static void sigaction_handler(int sig)
{
    Cdbg(UAC_DBG, "sigaction_handler sig=%d.", sig);

    if (sig == SIGTERM || sig == SIGINT) {
        if (sig == SIGTERM)
            aaeuac_errlog("Got SIGTERM");
        if (sig == SIGINT)
            aaeuac_errlog("Got SIGINT");

        sleep(1);
        g_is_terminate = 1;
        //g_keepalive_terminate = 1;
        //aae_keepalive_thread_exit();
    } else if (sig == SIGABRT) {
        aaeuac_errlog("Got SIGABRT");
        sleep(1);
        g_is_terminate = 1;
        //g_keepalive_terminate = 1;
        //aae_keepalive_thread_exit();
	} else if (sig == SIGUSR1) {
		if (g_call_id < 0)
			Cdbg(APP_DBG, "tunnel is not ready.");
		else {
			if (nat_read_tnl_info) {
				struct natnl_tnl_info tnl_info = {0};
				natnl_tnl_port *tnl_port = NULL;
				int i;
				nat_read_tnl_info(g_call_id, &tnl_info);
				Cdbg(UAC_DBG, "\ntnl_type = %d\n", tnl_info.tnl_type);
				for (i=0; i < tnl_info.tnl_port_cnt; i++) {
					tnl_port = &tnl_info.tnl_ports[i];
					Cdbg(UAC_DBG, "\nlport = %s,\nrport = %s,\nqos_priority = %d,\ndisable_flow_control = %d,\nspeed_limit = %d,\nrip = %s,\n", 
						tnl_port->lport, tnl_port->rport, tnl_port->qos_priority, tnl_port->disable_flow_control, 
						tnl_port->speed_limit, tnl_port->rip);
				}
			}
		}
	}
}

int nat_make_vpn_tunnel(int type, char *prefix) {
	char *vpn_ep_device_id;
	char *vpn_ep_port;
	if (!type || !prefix)
		return -1;

	vpn_ep_device_id = get_vpn_ep_device_id(type, prefix);
	vpn_ep_port = get_vpn_ep_port(type, prefix);

	if (strlen(vpn_ep_device_id) == 0) {
		return -2;
	}

	return nat_make_tunnel(vpn_ep_device_id, vpn_ep_port, 1);
}

int go_to_end()
{
#ifdef TNL_CALLBACK_ENABLE
	g_main_deinit_alert = 1;
	//nat_deinit(); // it takes too much time, don't do it temporarily.
	deinit_event_queue();
#else
	nat_deinit();
#endif
	reset_vpn_nvram(g_vpn_type, g_vpn_prefix);
	return 0;
}

int main(int argc, char* argv[])
{
	sigset_t sigs_to_catch;
	int ret = 0;
	char *device_id = NULL;
	char *device_port = NULL;
	char area[128] = {0};
	char *s2s_aaeuac_port_path = NULL;

#ifdef SW_HW_AUTH

#define APP_ID    "89347542"
#define APP_KEY   "jidf0924ij4pdfg54as"
	// ===================== sw-hw-auth check start =====================
	time_t timestamp = time(NULL);
	char in_buf[128];
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

	// debug
	//printf("hw_auth_code1=%s\n", hw_auth_code);
	//printf("hw_auth_code2=%s\n", get_auth_code(in_buf, out_buf, sizeof(out_buf)));

	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0)
		;//printf("This is ASUS Router\n");
	else {
		aaeuac_errlog("exit.");//printf("This is not ASUS Router\n");
		return 0;
	}
	// ===================== sw-hw-auth check end =====================
#endif
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigaddset(&sigs_to_catch, SIGINT);
	sigaddset(&sigs_to_catch, SIGABRT);
	sigaddset(&sigs_to_catch, SIGKILL);
	sigaddset(&sigs_to_catch, SIGUSR1);
	//sigaddset(&sigs_to_catch, AAE_SIG_EULA_FLAG_SIGNED);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

    /* Set signal handler */
	signal(SIGTERM, sigaction_handler);
    signal(SIGINT, sigaction_handler);
    signal(SIGABRT, sigaction_handler);
    signal(SIGKILL, sigaction_handler);
    signal(SIGUSR1, sigaction_handler);
    //signal(AAE_SIG_REMOTE_CONNECTION_TURNED_ON, sigaction_handler);
    //signal(AAE_SIG_EULA_FLAG_SIGNED, sigaction_handler);
    CF_OPEN(AAEUAC_LOG_PATH, SYSLOG_TYPE | FILE_TYPE | CONSOLE_TYPE | STDOUT_TYPE);

	fprintf(stderr, "argc=%d\n", argc);
	// prepare vpn related variables
	if (argc > 1) {
		char *proto = argv[1];
		if (!strcmp(proto, PROTO_WG))
			g_vpn_type = AAEUAC_PROTO_WG;
		else if (!strcmp(proto, PROTO_HTTPD))
			g_vpn_type = AAEUAC_PROTO_HTTPD;
		else if (!strcmp(proto, PROTO_AWSIOT))
			g_vpn_type = AAEUAC_PROTO_AWSIOT;
	}
	if (argc > 2) {
		if (g_vpn_type == AAEUAC_PROTO_HTTPD) {
			if (argc < 5) 
				return 0;
			device_id = argv[2];
			device_port = argv[3];
			snprintf(g_callee_id, sizeof(g_callee_id), "%s", device_id);
			snprintf(area, sizeof(area), "%s", argv[4]);
			s2s_aaeuac_port_path = argv[5];
		} else if (g_vpn_type == AAEUAC_PROTO_AWSIOT) {
			if (argc < 4)
				return 0;
			device_id = argv[2];
			s2s_aaeuac_port_path = argv[3];
			snprintf(g_callee_id, sizeof(g_callee_id), "%s", device_id);
			//device_port = argv[3];
			//snprintf(area, sizeof(area), "%s", argv[4]);
		} else {
			g_vpn_idx = atoi(argv[2]);
			s2s_aaeuac_port_path = argv[3];
			/*if (g_vpn_idx < 5)
				g_vpn_idx = -1;*/
		}
	}

	if (g_vpn_type == AAEUAC_PROTO_HTTPD) {
		if (!device_id || !device_port || !strlen(area) || !s2s_aaeuac_port_path) {
			aaeuac_errlog("HTTPD invalid parameter.");
			return 0;
		}
	} else if (g_vpn_type == AAEUAC_PROTO_AWSIOT) {
		if (!device_id || !s2s_aaeuac_port_path) {
			aaeuac_errlog("AWSIOT invalid parameter.");
			return 0;
		}
		snprintf(area, sizeof(area), "%s", nvram_safe_get("aae_area"));
	} else {
		if (!g_vpn_type || g_vpn_idx == -1 || !s2s_aaeuac_port_path) {
			aaeuac_errlog("invalid parameter.");
			return 0;
		}

		if (g_vpn_type == AAEUAC_PROTO_WG) {
			snprintf(g_vpn_prefix, sizeof(g_vpn_prefix), "%s%d_", WG_CLIENT_NVRAM_PREFIX, g_vpn_idx);
		}

		reset_vpn_nvram(g_vpn_type, g_vpn_prefix);
		snprintf(area, sizeof(area), "%s", get_vpn_ep_area(g_vpn_type, g_vpn_prefix));
	}
	Cdbg(UAC_DBG, "g_vpn_type=%d, g_vpn_prefix=%s, area=%s", g_vpn_type, g_vpn_prefix, area);

	if (get_uac_config_shared_link_mode(g_vpn_type, area, &g_natnl_cfg) == 0) {
#if 0
		int i;
		Cdbg(UAC_DBG, "deviceid = %s", g_natnl_cfg.device_id);
		Cdbg(UAC_DBG, "devicepwd = %s", g_natnl_cfg.device_pwd);
		Cdbg(UAC_DBG, "sip_srv_cnt = %d", g_natnl_cfg.sip_srv_cnt);
		for(i = 0; i < g_natnl_cfg.sip_srv_cnt; i++)
			Cdbg(UAC_DBG, "sip_srv[%d] = %s", i, g_natnl_cfg.sip_srv[i]);
		Cdbg(UAC_DBG, "stun_srv_cnt = %d", g_natnl_cfg.stun_srv_cnt);
		for(i = 0; i < g_natnl_cfg.turn_srv_cnt; i++)
			Cdbg(UAC_DBG, "stun_srv[%d] = %s", i, g_natnl_cfg.stun_srv[i]);
		Cdbg(UAC_DBG, "turn_srv_cnt = %d", g_natnl_cfg.turn_srv_cnt);
		for(i = 0; i < g_natnl_cfg.turn_srv_cnt; i++)
			Cdbg(UAC_DBG, "turn_srv[%d] = %s", i, g_natnl_cfg.turn_srv[i]);
#endif

		// TODO : tunnel sdk flow.
		if (init_natnl_api(&nat_init3, &nat_deinit, NULL, &nat_hangup, 
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, &nat_makecall3, &nat_read_tnl_info) != 0 ) {
			Cdbg(UAC_DBG, "Failed to laod libasusnatnl.so.");
			goto END_PROC;
		}
		if ((ret = nat_sdk_init((void *)s2s_aaeuac_port_path)) != 0) {
			Cdbg(UAC_DBG, "Failed to init natnl sdk. err=%d", ret);
			goto END_PROC;
		} else {
			if (g_vpn_type == AAEUAC_PROTO_HTTPD) {
				if ((ret = nat_make_tunnel(device_id, device_port, 0)) != 0) {
					Cdbg(UAC_DBG, "Failed to make tunnel. err=%d", ret);
					goto END_PROC;
				}
			} else if (g_vpn_type == AAEUAC_PROTO_AWSIOT) {
				if ((ret = nat_make_tunnel(device_id, "8443", 0)) != 0) {
					char result[256];
					snprintf(result, sizeof(result), AAE_TUNNEL_TEST_RES, g_device_id, g_callee_id, "unknown", ret);
					f_write_string(s2s_aaeuac_port_path, result, 0, 0);
					Cdbg(UAC_DBG, "Failed to make tunnel. err=%d", ret);
					goto END_PROC;
				}
			} else {
				if ((ret = nat_make_vpn_tunnel(g_vpn_type, g_vpn_prefix)) != 0) {
					Cdbg(UAC_DBG, "Failed to make tunnel. err=%d", ret);
					goto END_PROC;
				}
			}
			while (!g_is_terminate) {
				pause();
			}
			go_to_end();
		}
	} else {
		Cdbg(UAC_DBG, "Failed to save natnl config.");
	}

END_PROC:
	return 0;
}