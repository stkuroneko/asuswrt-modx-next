#include <tunnel_proc.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <syslog.h>
#include <natapi.h>
#include <ws_api.h>
#include <log.h>
#include <sync.h>
#include <assert.h>
#include <m_queue.h>
#include <queue_manager.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <rtconfig.h>
#include "im_ipc.h" // asusnatnl/natnl
#include <nat_nvram.h>
#include <common.h>
#include <time_util.h>		// alloc_time_string() in wb/ws_src/time_util.h
#include "ws_caller.h"		// st_UpdateProfile()
#include "info_report.h"	// write_login_info()
#include "nw_util.h"

#define APP_DBG 1

#define DECLARE(type, x ) \
			type x ; \
			memset(&x, 0, sizeof(type));

#define CALL_CFG(type, x) \
	DECLARE(type ## _CFG, x ##_cfg)\
	if(fp_set_ ## x){\
		ret = (*fp_set_ ## x)(&x ## _cfg);\
	}else{\
		ret = default_set_## x ## _cfg(&x ## _cfg);\
	}\
	if(ret<0) {\
		ue = SET_ ## type ##_ERROR; \
		goto _INIT_PEER_ERROR;\
	}

#define SET_NATNL_CFG(DST ,SRC, member) \
	strcpy( DST->member , SRC->member); 

#define SET_NATNL_INT(DST, SRC, member) \
	DST->member= SRC->member;	

#define SET_NATNL_LOG_INT(DST, SRC, member) \
	DST->log_cfg.member= SRC->member;

#define SET_NATNL_LOG_CFG(DST ,SRC, member) \
	if(SRC->member) \
		strcpy( DST->log_cfg.member , SRC->member); 

#define SET_NATNL_UPNP(DST, SRC, FLAG, CNT) \
	DST-> SRC ## _cfg.FLAG	= SRC->FLAG; \
	DST-> SRC ## _cfg.CNT	= SRC->CNT; \
	int i = 0; \
	for(i =0; i<SRC->CNT; i++){ \
		strcpy(DST-> SRC ## _cfg.user_ports[i].local_data,	SRC->user_ports[i].local_data); \
		strcpy(DST-> SRC ## _cfg.user_ports[i].external_data,SRC->user_ports[i].external_data); \
		strcpy(DST-> SRC ## _cfg.user_ports[i].local_ctl,	SRC->user_ports[i].local_ctl); \
		strcpy(DST-> SRC ## _cfg.user_ports[i].external_ctl, SRC->user_ports[i].external_ctl); \
	}

#define SET_NATNL_SRV_CFG(DST, SRC) \
	j=0; \
	DST->SRC ## _srv_cnt				= SRC->SRC ## _srv_cnt; \
	for(p=SRC->SRC ## _srv; p; p=p->next){ \
		memset(DST->SRC ##_srv[j], 0, 128); \
		strcpy(DST->SRC ##_srv[j], p->srv_ip); \
		j++; \
	}

#define CLEAN_HEAP(x) \
	if(x) 	free(x); x=NULL;

#define LOG_DEFAULT_PATH(x, y) #x#y 
#define TP_DBG 1 

#define DECLARE_CLEAR_MEM(type, var, len) \
	type var[len]; \
	memset(var, 0, len );

#define DEV_ID_LEN 	128
#define LOG_NAME_LEN	64
#define LOG_DEF_NAME	"/tmp/tunnel_sdk_%s.txt"
#define UPNP_CTL_LEN	7
#define UPNP_DATA_LEN	7

GetServiceArea	gsa; 
Login			lg; 
ListProfile		lp; 
pProfile		pP; 
ACCOUNT_CFG		gAcc;
int		g_enable_ws=0;
static int		g_login_success=0;
struct natnl_config gNatnl_cfg;
NAT_VERSION	nat_version;
NAT_INIT3		nat_init3;
NAT_DEINIT		nat_deinit;
NAT_MAKECALL	nat_makecall;
NAT_HANG_UP		nat_hangup;
NAT_POOL_DUMP	nat_dump;
NAT_DETECT	nat_detect;
NAT_READ_IM_MSG  nat_read_im_msg;
NAT_WRITE_IM_RESP  nat_write_im_resp;
NAT_REG_DEVICE  nat_reg_device;
NAT_UNREG_DEVICE  nat_unreg_device;
static int g_random_retry_cnt = 0;
#ifdef TNL_CALLBACK_ENABLE
struct natnl_callback gNatCallback;

// event object declare
//sem_t init_sem;
sem_t					cb_sem;
struct natnl_tnl_event  g_init_tnl_event;
//int						g_init_alert =0; // this is bad method to wait event
#define					INIT_EVENT_NAME "NAT_INIT"
sem_t*					p_ginit_sem;
#define					QUEUE_SEM		"tnl_queue_sem"
#define					TMP_DATA_SEM	"tnl_data_sem"
sem_t*					p_gdeinit_sem;
#define					DEINIT_EVENT_NAME "NAT_DEINIT"

int						g_main_deinit_alert=0;
int						IN_TUNNEL_STATE_MACHINE=0;  

pthread_mutex_t			lock;
pthread_mutex_t			tnl_state_lock=PTHREAD_MUTEX_INITIALIZER;
sem_t*		queue_sem;
QUEUE*		ev_queue_list;
pthread_t	queue_tid ;
natnl_tnl_state			g_tnl_state[MAX_CALLS] = { 0 };
#endif

int util_copy_str(char* src, char** dst)
{
	if(!src) return -1;
	if(!strlen(src)) return -1;
	int len = strlen(src)+1;
	*dst = malloc(len);
	memset(*dst, 0, len);
	strcpy(*dst, src);
	return 0;
}

int read_mac(char* ret_mac)
{
	DECLARE_CLEAR_MEM(unsigned char, mac_addr, 7);	
	DECLARE_CLEAR_MEM(char, mac_str, 20);
	int status = -1;
//	const char aae_pwd[16]	={0} ;
//	const char aae_account[64]={0};
#if NVRAM
	if(nvram_get_mac_addr(mac_str)<0){
 		goto _DEFAULT_READ_MAC;	
	}
#else
	int get_mac_status = get_mac(mac_addr);
	sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
	if(get_mac_status<0){
		goto _DEFAULT_READ_MAC;
	}
	status = 0;
#endif
	strcpy(ret_mac, mac_str);
_DEFAULT_READ_MAC:
	return status ;
}

int default_set_account_cfg(ACCOUNT_CFG* account_cfg)
{
	int ret =-1;
	if(!account_cfg) goto _DEFAULT_SET_ACC_CFG;
	DECLARE_CLEAR_MEM(unsigned char, mac_addr, 7);
	DECLARE_CLEAR_MEM(char, mac_str, 20);
	DECLARE_CLEAR_MEM(char, aae_pwd, 16);
	DECLARE_CLEAR_MEM(char, aae_account, 64);
	read_mac(mac_str);
/*#if NVRAM
	if(nvram_get_mac_addr(mac_str)<0) goto _DEFAULT_SET_ACC_CFG;	
#else
	int get_mac_status = get_mac(mac_addr);
	sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
	if(get_mac_status<0) goto _DEFAULT_SET_ACC_CFG;
#endif*/
	sprintf(aae_account, "%s@asuscomm.com", mac_str);
	srand( time(NULL));
	int rand_value = rand()%100 +2000;
	sprintf(aae_pwd, "%d", rand_value);
	if(!strlen(aae_account) || !strlen(aae_pwd)) 
		goto _DEFAULT_SET_ACC_CFG;
	util_copy_str(aae_account, &account_cfg->account);
	util_copy_str(aae_pwd, &account_cfg->password);
	ret= 0;
_DEFAULT_SET_ACC_CFG:
	return ret;
}

int	default_set_device_info_cfg(DEVICE_INFO_CFG* device_info_cfg)
{
	int ret=-1;
	char* tmp_devid;
	if(!device_info_cfg) goto _DEFAULT_SET_DEV_INFO_ERROR;
	if(!strlen(lg.deviceid)|| !strlen(lg.deviceticket)) 
	   goto _DEFAULT_SET_DEV_INFO_ERROR;
//	if(ret = util_copy_str(lg.deviceid , &device_info_cfg->device_id)<0) 
	if((ret = util_copy_str(lg.deviceid , &tmp_devid))<0)
	   goto _DEFAULT_SET_DEV_INFO_ERROR;
	if((ret = util_copy_str(lg.deviceticket, &device_info_cfg->device_pwd))<0)
	   goto _DEFAULT_SET_DEV_INFO_ERROR;

	//char tmp_devid2 [128]={0};
	DECLARE_CLEAR_MEM(char, tmp_devid2, DEV_ID_LEN);
	sprintf(tmp_devid2,"%s@%s",tmp_devid,"aaerelay.asuscomm.com");
	if(tmp_devid) free(tmp_devid);
	int devid_len = strlen(tmp_devid2)+1;
	if(device_info_cfg->device_id) free(device_info_cfg->device_id);
	device_info_cfg->device_id = malloc(devid_len); memset(device_info_cfg->device_id, 0, devid_len);
	strcpy(device_info_cfg->device_id, tmp_devid2);

	ret = 0;
_DEFAULT_SET_DEV_INFO_ERROR:
	return ret;
}

int default_set_log_cfg(LOG_CFG* log_cfg)
{
	int ret= -1;
	if(!log_cfg) goto  _DEFAULT_SET_DEV_INFO_ERROR;
	log_cfg->log_level = 0;
	log_cfg->log_file_flags = 0x1110; // default set 0 to replace the log file
	log_cfg->log_file_size = 512; 
	log_cfg->log_rotate_number = 5;
	// need to modified to multiple platforms
	DECLARE_CLEAR_MEM(char, log_name, LOG_NAME_LEN);
	char* ts;
	alloc_time_string("%Y-%m-%d_%H:%M:%S", 0, &ts);
	sprintf(log_name, LOG_DEF_NAME, ts);
	dealloc_time_string(ts);
	//sprintf(log_name, "./natlog_%d.txt", time(NULL));
	if((ret = util_copy_str(log_name , &log_cfg->log_filename ))<0)
		goto _DEFAULT_SET_DEV_INFO_ERROR;
	ret = 0;
_DEFAULT_SET_DEV_INFO_ERROR:
	return ret;

}

int default_set_media_cfg(MEDIA_CFG* media_cfg)
{
	int ret =-1;
	int max_tunnels = nvram_get_int("aae_max_tunnels");
	if(!media_cfg) goto _DEFAULT_SET_MEDIA_ERROR;
	media_cfg->max_calls			= (max_tunnels <= 0 || max_tunnels >= MAX_CALLS) ? MAX_CALLS : max_tunnels;
	media_cfg->tnl_timeout_sec		= 60;
	media_cfg->disable_sdp_compress = 0;
	media_cfg->bandwidth_KBs_limit	= 0;	
	media_cfg->is_server_side_app	= 1;
	ret = 0;
_DEFAULT_SET_MEDIA_ERROR:
	return ret;
}

int	default_set_upnp_cfg(UPNP_CFG* upnp_cfg)
{
	int ret=-1;
	int i =0;
	if(!upnp_cfg) goto _DEFAULT_SET_UPNP_ERROR;
	upnp_cfg->flag = 1;
	upnp_cfg->user_port_count = 2;

	DECLARE_CLEAR_MEM(char, local_data, 	UPNP_DATA_LEN); 
	DECLARE_CLEAR_MEM(char, local_ctl, 	UPNP_CTL_LEN); 
	DECLARE_CLEAR_MEM(char, external_data, 	UPNP_DATA_LEN); 
	DECLARE_CLEAR_MEM(char, external_ctl, 	UPNP_CTL_LEN); 
//	char local_data[7]={0};
//	char local_ctl[7]={0};
//	char external_data[7]={0};
//	char external_ctl[7]={0};
	int	 upnp_base_port = 4000; 
	for(i = 0; i<upnp_cfg->user_port_count;i++){
		sprintf(local_data,"%d",upnp_base_port+i);
		sprintf(external_data,"%d",upnp_base_port+i);
		sprintf(local_ctl,"%d",upnp_base_port+i+1);
		sprintf(external_ctl,"%d",upnp_base_port+i+1);
		strcpy(upnp_cfg->user_ports[i].local_data,local_data);
		strcpy(upnp_cfg->user_ports[i].external_data,external_data);
		strcpy(upnp_cfg->user_ports[i].local_ctl,local_ctl);
		strcpy(upnp_cfg->user_ports[i].external_ctl	,external_ctl);
	}
	ret =0;
_DEFAULT_SET_UPNP_ERROR:
	return ret;
}

int default_set_ice_cfg(ICE_CFG* ice_cfg)
{
	int ret = -1;
	if(!ice_cfg) goto _DEFAULT_SET_ICE_ERROR;
	ice_cfg->use_turn = 2;
	ice_cfg->use_stun = 1;	
	ice_cfg->force_to_use_ice= 1;	
	ret =0;
_DEFAULT_SET_ICE_ERROR:
	return ret;
}

int	default_set_sip_cfg(SIP_CFG* sip_cfg)
{
	int ret = -1;
	if(!sip_cfg) goto _DEFAULT_SET_SIP_ERROR;
	sip_cfg->sip_srv_cnt = 0; 
	SrvInfo* p;
	for(p=lg.relayinfoList;p;p=p->next){
		sip_cfg->sip_srv_cnt ++;
	} sip_cfg->sip_srv = lg.relayinfoList; 
	if(!sip_cfg->sip_srv_cnt)
		goto _DEFAULT_SET_SIP_ERROR;
	ret =0;
_DEFAULT_SET_SIP_ERROR:
	return ret;
}

int	default_set_stun_cfg(STUN_CFG* stun_cfg)
{
	int ret = -1;
	if(!stun_cfg) goto _DEFAULT_SET_STUN_ERROR;
	stun_cfg->stun_srv_cnt = 0; 
	SrvInfo* p;
	for(p=lg.stuninfoList;p;p=p->next){
		stun_cfg->stun_srv_cnt ++;
	} stun_cfg->stun_srv = lg.stuninfoList; 
	if(!stun_cfg->stun_srv_cnt)
		goto _DEFAULT_SET_STUN_ERROR;
	ret =0;
_DEFAULT_SET_STUN_ERROR:
	return ret;
}

int	default_set_turn_cfg(TURN_CFG* turn_cfg)
{
	int ret = -1;
	if(!turn_cfg) goto _DEFAULT_SET_TURN_ERROR;
	turn_cfg->turn_srv_cnt = 0; 
	SrvInfo* p;
	for(p=lg.turninfoList;p;p=p->next){
		turn_cfg->turn_srv_cnt ++;
	} turn_cfg->turn_srv = lg.turninfoList; 
	if(!turn_cfg->turn_srv_cnt)
		goto _DEFAULT_SET_TURN_ERROR;
	ret =0;
_DEFAULT_SET_TURN_ERROR:
	return ret;
}

int clean_srv_cfg(SrvInfo* srv)
{	
	SrvInfo* p =srv;
	SrvInfo* tmpp =NULL;
	while(p){
		tmpp = p->next;
		free(p); 
		p = tmpp;
	}
	return 0;
}

int clean_cfg_data(ACCOUNT_CFG*		account, 
		LOG_CFG*			log,
		DEVICE_INFO_CFG*	device_info,
		MEDIA_CFG*			media,
		UPNP_CFG*			upnp,
		ICE_CFG*			ice,
		SIP_CFG*			sip,
		STUN_CFG*			stun,
		TURN_CFG*			turn
)
{
	CLEAN_HEAP(account->account);
	CLEAN_HEAP(account->password);
	CLEAN_HEAP(log->log_filename);
	CLEAN_HEAP(device_info->device_id);
	CLEAN_HEAP(device_info->device_pwd);
	clean_srv_cfg(sip->sip_srv);
	clean_srv_cfg(stun->stun_srv);
	clean_srv_cfg(turn->turn_srv);
	return 0;
}

int save_all_cfg(
		ACCOUNT_CFG*		account, 
		LOG_CFG*			log,
		DEVICE_INFO_CFG*	device_info,
		MEDIA_CFG*			media,
		UPNP_CFG*			upnp,
		ICE_CFG*			ice,
		SIP_CFG*			sip,
		STUN_CFG*			stun,
		TURN_CFG*			turn,
		struct natnl_config*		natcfg
		 )
{
	int ret = -1;
	if(!account || !log || !device_info || !media ||
		  !upnp || !ice || !sip || !stun || !turn|| 
		  !natcfg) 
	  goto _SAVE_ALL_CFG_ERROR; 
	// set asus account
	//ACCOUNT_CFG* pAcc = &gAcc;
	//SET_NATNL_CFG(pAcc, account , account);
	//SET_NATNL_CFG(pAcc, account , password);
	// set device id, pwd
	SET_NATNL_CFG(natcfg, device_info , device_id);
	SET_NATNL_CFG(natcfg, device_info , device_pwd);
	// set log 
	SET_NATNL_LOG_INT(natcfg, log, log_level);
	SET_NATNL_LOG_INT(natcfg, log, log_file_flags);
	SET_NATNL_LOG_CFG(natcfg, log, log_filename);
	SET_NATNL_LOG_INT(natcfg, log, log_file_size);
	SET_NATNL_LOG_INT(natcfg, log, log_rotate_number);
	SET_NATNL_LOG_CFG(natcfg, log, log_flag_file);
	// set media
	SET_NATNL_INT(natcfg, media, max_calls); 
	SET_NATNL_INT(natcfg, media, tnl_timeout_sec); 
	SET_NATNL_INT(natcfg, media, disable_sdp_compress); 
	SET_NATNL_INT(natcfg, media, bandwidth_KBs_limit); 
	natcfg->is_server_side_app = 1;
#if defined(RTCONFIG_ACCOUNT_BINDING)
	if (is_account_bound() && !nvram_get_int("aae_disable_fast_init"))
		natcfg->fast_init = 1;
	if(nvram_get_int("aae_disable_fast_init"))
		nvram_set_int("aae_disable_fast_init", 0);
#endif
	// set UPNP
	SET_NATNL_UPNP(natcfg, upnp, flag, user_port_count) ;
	// set ICE
	SET_NATNL_INT(natcfg, ice, use_turn); 
	SET_NATNL_INT(natcfg, ice, use_stun); 
	SET_NATNL_INT(natcfg, ice, force_to_use_ice); 
	// set server configurations
	SrvInfo* p = NULL; int j = 0; 
	// set SIP
	SET_NATNL_SRV_CFG(natcfg, sip) ;
	// set STUN
	SET_NATNL_SRV_CFG(natcfg, stun) ;
	// set TURN
	SET_NATNL_SRV_CFG(natcfg, turn) ;
	ret =0;
	Cdbg(APP_DBG, " dst use_turn =%d, use_stun=%d", natcfg->use_turn, natcfg->use_stun);
	Cdbg(APP_DBG, " org use_turn =%d, use_stun=%d", ice->use_turn, ice->use_stun);
	Cdbg(APP_DBG, " sip link p =%p,stun link=%p , turn_link=%p", sip->sip_srv, stun->stun_srv, turn->turn_srv );
	clean_cfg_data(	account, 
			log,
			device_info,
			media,
			upnp,
			ice,
			sip,
			stun,
			turn
			);
_SAVE_ALL_CFG_ERROR:
	return ret;
}

void GetNatCfg(struct natnl_config* cfg)
{
	memcpy(cfg, &gNatnl_cfg, sizeof(struct natnl_config));
}

int invoke_api()
{
	return init_natnl_api(&nat_init3, &nat_deinit, &nat_makecall, &nat_hangup, &nat_dump, 
		&nat_detect, &nat_version, &nat_read_im_msg, &nat_write_im_resp, 
		&nat_reg_device, &nat_unreg_device, NULL, NULL);
}


#ifdef  TNL_CALLBACK_ENABLE
void dispatch_tunnel_event(struct natnl_tnl_event* tnl_event)
{
   	Cdbg(APP_DBG, "tnl_event =%d, post to tmp data list", tnl_event->event_code);
	//PostDataToQueue(tnl_event, sizeof(struct natnl_tnl_event));
	int struct_size = sizeof(struct natnl_tnl_event);
	struct natnl_tnl_event* event_clone = malloc(struct_size);
	memset(event_clone, 0, struct_size);
	memcpy(event_clone, tnl_event, struct_size);
   	Cdbg(APP_DBG, "Push Queue to List event_clone =%p", event_clone);
	PushQueue(&lock, ev_queue_list, event_clone );
	sem_post(queue_sem);	
}


int nat_init_sync(void* result)
{
	gNatCallback.on_natnl_tnl_event = &dispatch_tunnel_event;
	init_semaphore(&p_ginit_sem, INIT_EVENT_NAME);
	Cdbg(APP_DBG,"p_ginit_sem =%p", p_ginit_sem);
	nat_init3(&gNatnl_cfg, &gNatCallback, NULL);
	wait_event(p_ginit_sem);
	Cdbg(APP_DBG,"wait p_ginit_sem =%p end <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", p_ginit_sem);
	deinit_semaphore(p_ginit_sem, INIT_EVENT_NAME);
	return 0;
}

static void aaews_errlog(char *buf)
{
        openlog("Aaews", 0, 0);
        syslog(0, buf);
        closelog();

        fprintf(stderr,"[Aaews]%s\n",buf);
}


int kill_all_proc(const char* appname)
{
	char cmd [32];
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "killall -9 %s", appname);
	aaews_errlog(cmd);
	system(cmd);
    return 0;
}

#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
static void set_tnl_state(int call_id, natnl_tnl_state state) {
	pthread_mutex_lock(&tnl_state_lock);
	g_tnl_state[call_id] = state;
	pthread_mutex_unlock(&tnl_state_lock);
}

static void clr_all_tnl_state() {
	int i;
	pthread_mutex_lock(&tnl_state_lock);
	for (i = 0; i < MAX_CALLS; i++)
		g_tnl_state[i] = TNL_STATE_UNKNOWN;
	pthread_mutex_unlock(&tnl_state_lock);
}

int is_any_tnl_active() {
	int i, ret = 0;
	pthread_mutex_lock(&tnl_state_lock);
	for (i = 0; i < MAX_CALLS; i++) {
		if (g_tnl_state[i] == TNL_STATE_ACTIVE) {
			ret = 1;
			break;
		}
	}
	pthread_mutex_unlock(&tnl_state_lock);
	return ret;
}
#endif

void* deal_cb_event(void* userdata)
{
	Cdbg(APP_DBG, ">>>>>>>> starts userdata=%p", userdata);
	struct natnl_tnl_event* tnl_event = (struct natnl_tnl_event*)userdata;
	if (tnl_event->event_code != 60114)
		Cdbg(APP_DBG, ">>>>>>>> event_code =========================> %d ", tnl_event->event_code);

	if (tnl_event->event_code == NATNL_TNL_EVENT_INIT_OK) {
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_INIT_OK" );
		nvram_set_int("aae_sdk_inited", 1);
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_DEINIT_OK) {
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_DEINIT_OK" );
		nvram_set_int("aae_sdk_inited", 0);
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		clr_all_tnl_state();
#endif
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_REG_FAILED) {
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_REG_FAILED" );
		//if(tnl_event > 0) nat_hangup(tnl_event->call_id);
		nvram_set_aae_sip_connected("0");
		if (tnl_event->status_code == 401) {
			Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event authenticate fail.");
			kill_all_proc("aaews");
		}
		// Save server status to nvram
		nvram_set_server_status("sip", tnl_event->status_code, tnl_event->status_text);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_REG_OK) {
		nvram_set_aae_sip_connected("1");
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_REG_OK" );
		// Save server status to nvram
		nvram_set_server_status("sip", tnl_event->status_code, tnl_event->status_text);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_UNREG_OK) {
		nvram_set_aae_sip_connected("0");
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_UNREG_OK" );
		// Save server status to nvram
		// nvram_set_server_status("sip", tnl_event->status_code, tnl_event->status_text);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_OK) {
		Cdbg2(APP_DBG, 1, "Tunnel built successfully.");
		// Save server status to nvram
		nvram_set_server_status("stun", tnl_event->stun_last_status, tnl_event->stun_status_text);
		nvram_set_server_status("turn", tnl_event->turn_last_status, tnl_event->turn_status_text);
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_ACTIVE);
#endif
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_MAKECALL_FAILED) {
		Cdbg2(APP_DBG, 1, "Tunnel built failed. status code=[%d]", tnl_event->status_code);
		// Save server status to nvram
		nvram_set_server_status("stun", tnl_event->stun_last_status, tnl_event->stun_status_text);
		nvram_set_server_status("turn", tnl_event->turn_last_status, tnl_event->turn_status_text);
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_KA_TIMEOUT) {
	    Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_KA_TIMEOUT" );
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
	    //if(tnl_event > 0) nat_hangup(tnl_event->call_id);
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_NAT_TYPE_DETECTED) {
		if(g_enable_ws){
			Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_NAT_TYPE_DETECTED" );
			DECLARE_CLEAR_MEM(char, status_t, 8);
			sprintf(status_t, "%d", tnl_event->status_code);
			st_UpdateProfile(status_t, tnl_event->nat_type,  tnl_event->mac_address, &gsa, &lg);
		}
		//st_ListProfile( &gsa, &lg, &lp, &pP );
	} else if (tnl_event->event_code == NATNL_TNL_EVENT_DEADLOCK) {
		// Suicide
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_DEADLOCK" );
		aaews_errlog(">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event event_code = NATNL_TNL_EVENT_DEADLOCK");
		//kill(getpid(), SIGKILL);
		kill_all_proc("aaews");
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_HANGUP_OK) {
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
	} else if(tnl_event->event_code == NATNL_TNL_EVENT_HANGUP_FAILED) {
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		set_tnl_state(tnl_event->call_id, TNL_STATE_INACTIVE);
#endif
	} else {
		Cdbg(APP_DBG, "Bypass the event = %d", tnl_event->event_code);
	}

	Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>>>>>>dispatch_tunnel_event return " );

	free(tnl_event);
	return NULL;
}

void* pop_queue_thread(void* data)
{
	QUEUE* q = (QUEUE*) data;
	void* p = NULL;
	Cdbg(APP_DBG, "pop queue thread starts .....q =%p ",q);
	while(!g_main_deinit_alert){
		if(-1 == wait_event(queue_sem)){
			Cdbg(APP_DBG, "sem_wait failed..... =%p ");
			break;
		}
		Cdbg(APP_DBG, "Queue alert ");
		if(!QueueIsEmpty(&lock, q))	{
			p = PopQueue(&lock, q);	
			if(p){
				Cdbg(APP_DBG, " Pop data point =%p ", p);
				deal_cb_event(p);
			}
		}
	}
	Cdbg(APP_DBG, "pop queue thread stops .....q =%p ",q);
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

#if USE_IM_IPC
void im_ipc_handler(int sig)
{
    char *msg;
    char *resp_msg = "OK!!";
    Cdbg(APP_DBG, "im_ipc_handler(), im signal=%d", sig);
    nat_read_im_msg(&msg);
    Cdbg(APP_DBG, "im_ipc_handler(), im message=%s", msg);
    nat_write_im_resp(resp_msg);
    free(msg); // !!!! Import free msg.
}
#endif

int DeletePeer()
{
#ifdef TNL_CALLBACK_ENABLE
	g_main_deinit_alert =1;
	#ifndef TNL_2_X
	if(IN_TUNNEL_STATE_MACHINE) {
		nat_deinit_sync();
	}
	#else
	nat_deinit();
	#endif
	remove_watch_queue_thread();	
	IN_TUNNEL_STATE_MACHINE=0;

///	RemoveWatchQueue(QUEUE_SEM, TMP_DATA_SEM);
#else
	nat_deinit();
#endif
	return 0;
	// RemoveWatchQueue
}

int nat_sdk_deinit() {
	DeletePeer();
	nvram_set_int("aae_sdk_inited", 0);
	return 0;
}

int nat_sdk_init(int *ue, int do_update_profile) {
	int ret;
    char dev_desc_buf[ASUS_DEVICE_DESC_LEN];
	g_main_deinit_alert=0;
	if (!g_login_success)  // If login is not success, bypass it.
		return 0;

	if (!IN_TUNNEL_STATE_MACHINE) {
		ret = pthread_mutex_init(&lock, NULL);
		if(ret) goto _INIT_PEER_ERROR;
		ev_queue_list = malloc(sizeof(QUEUE));
		Cdbg(APP_DBG, ">>>>>>> 11 -2 lock=%p" , &lock);
		ret = init_semaphore(&queue_sem, "QUEUE_SEM2");
		if(ret){
			Cdbg(APP_DBG, ">>>> 11-2-1 Init Sem failed");
			goto _INIT_PEER_ERROR;
		}
		Cdbg(APP_DBG, "queue_sem = %p", queue_sem);
		ret = InitQueue(&lock, ev_queue_list);
		if(ret){
			if(ev_queue_list) free(ev_queue_list);
			goto _INIT_PEER_ERROR;
		}
		Cdbg(APP_DBG, ">>>>>>> 11 -3" , ret);
		ret = create_watch_queue_thread(ev_queue_list);
		if(ret) goto _INIT_PEER_ERROR;

	#if USE_IM_IPC
	    // install im ipc handler
	    signal(IM_MSG_SIG_REQ, im_ipc_handler);
	#endif
		IN_TUNNEL_STATE_MACHINE=1;
	}
	// stp :  Tunnel init Peer
	Cdbg(APP_DBG, ">>>>>>> 12", ret);

	gNatCallback.on_natnl_tnl_event = &dispatch_tunnel_event;

NAT_INIT:
    ret = nat_init3(&gNatnl_cfg, &gNatCallback, NULL);
    if (ue)
		*ue = ret;
	if (!ret) {
		nvram_set_int("aae_sdk_inited", 1);
		if (do_update_profile) {
		    DECLARE_CLEAR_MEM(char, status_t, 8);
		    sprintf(status_t, "%d", *ue);
		    Cdbg(APP_DBG, ">>>>> 13 stun srv = %s, nat_detect=%p", gNatnl_cfg.stun_srv[0], nat_detect);
		    int nat_type = nat_detect(gNatnl_cfg.stun_srv[0]);
			char* tnl_sdk_version = nat_version();
			Cdbg(APP_DBG, ">>>>> 14 tnl_sdk_version=%s, natnl_type=%d", tnl_sdk_version, nat_type);
		    Cdbg(APP_DBG, ">>>>> 15 Call Update profile");
			//nvram_set_int("aae_enable", (nvram_get_int("aae_enable") | 1));
			DECLARE_CLEAR_MEM(char, ret_mac, 20);
		    read_mac(ret_mac);
			st_UpdateProfile2(status_t, nat_type, ret_mac, &gsa, &lg, 
				generate_device_desc(is_private_ip(9) ? 0 : 1, tnl_sdk_version, dev_desc_buf, sizeof(dev_desc_buf)));
		}
	} else {
		Cdbg(APP_DBG, ">>>>> nat_init failed. ret=%d", ret);
		if (do_update_profile) {
			if (ret != 401) {
				int random_delay = get_random_delay(g_random_retry_cnt, RETRY_DELAY_BASE_SECONDS, MAX_RETRY_DELAY_DELAYED_SECONDS);
				Cdbg(APP_DBG, ">>>>> retry nat_init after %d seconds.", random_delay);
				sleep(random_delay);
				if (g_random_retry_cnt < RETRY_MAX_TIMES)
					g_random_retry_cnt++;
				goto NAT_INIT;
			} else {
				int retry_cnt = nvram_get_int(NVRAM_RETRY_COUNT);
				if (retry_cnt < RETRY_MAX_TIMES)
					nvram_set_int(NVRAM_RETRY_COUNT, ++retry_cnt);
			}
		} else
			Cdbg(APP_DBG, ">>>>> no need to retry due to do_update_profile=0.");
	}

_INIT_PEER_ERROR:
	return ret;
}

int InitPeer(
		SET_ACCOUNT_CFG		fp_set_account,
		SET_DEVICE_INFO_CFG fp_set_device_info,
		SET_LOG_CFG			fp_set_log,
		SET_MEDIA_CFG		fp_set_media,
		SET_UPNP_CFG		fp_set_upnp,
		SET_ICE_CFG			fp_set_ice,
		SET_SIP_CFG			fp_set_sip,
		SET_STUN_CFG		fp_set_stun,
		SET_TURN_CFG		fp_set_turn,
#ifdef TNL_CALLBACK_ENABLE
		TNL_CB				fp_tnl_cb, 
		struct natnl_tnl_event* tnl_event,
#endif
		int					enable_ws
		)
{
	int ret =-1;
    char dev_desc_buf[ASUS_DEVICE_DESC_LEN];
	UA_ERROR ue = UNKOWN_ERROR; 
//	ret = init_event(&init_sem); 
	//ret = init_event(&cb_sem);

	// invoke tunnel sdk function pointer
	if( invoke_api()<0){
		  ue = NOT_FOUND_SDK_LIB_ERROR;
		goto _INIT_PEER_ERROR; 
	}

	Cdbg(APP_DBG, ">>>>>>> 0", ret);	
	DECLARE_CLEAR_MEM(char, ret_mac, 20);
    read_mac(ret_mac);

	// step : Set ASUS VIP Account 
	CALL_CFG(ACCOUNT, account);
	Cdbg(APP_DBG, ">>>>>>> 1", ret);	
	nvram_set_int("aae_enable", (nvram_get_int("aae_enable") | 1));

	g_login_success = 0;
	if(enable_ws && st_Login(&gsa, &lg, account_cfg.account, account_cfg.password, 
		generate_device_desc(is_private_ip(10) ? 0 : 1, nat_version(), dev_desc_buf, sizeof(dev_desc_buf)))<0){
		int retry_cnt = nvram_get_int(NVRAM_RETRY_COUNT);
		g_enable_ws =1;
		ue = AAE_LOGIN_ERROR;
#ifdef RTCONFIG_NOTIFICATION_CENTER
		write_login_info(lg.status, "", "", "", "", "");
#endif
		// Fail to login ,increase retry count until it is greater than RETRY_MAX_TIMES.
		if (retry_cnt < RETRY_MAX_TIMES)
			nvram_set_int(NVRAM_RETRY_COUNT, ++retry_cnt);
		goto _INIT_PEER_ERROR;
	}
	g_login_success = 1;

	//TODO Save login info for notification center.
#ifdef RTCONFIG_NOTIFICATION_CENTER
	fprintf(stderr, "pnsinfoList=%p\n", lg.pnsinfoList);
	write_login_info(lg.status, 
		lg.pnsinfoList ? lg.pnsinfoList->srv_ip : "", 
		lg.psrinfoList ? lg.psrinfoList->srv_ip : "", 
		lg.cusid, lg.deviceid, lg.deviceticket);
	write_mac_info(ret_mac);
#endif

	// step : set device info
	Cdbg(APP_DBG, ">>>>>>> 3", ret);	
	CALL_CFG(DEVICE_INFO, device_info);

	// setp : set log info
	Cdbg(APP_DBG, ">>>>>>> 4", ret);
	CALL_CFG(LOG, log);

	// step : set media_info 
	Cdbg(APP_DBG, ">>>>>>> 5", ret);	
	CALL_CFG(MEDIA, media);

	// step : set upnp info 
	Cdbg(APP_DBG, ">>>>>>> 6", ret);	
	CALL_CFG(UPNP, upnp);
	
	// step : set ice info	
	Cdbg(APP_DBG, ">>>>>>> 7", ret);	
	CALL_CFG(ICE, ice);

	// step : set sip cfg 
	Cdbg(APP_DBG, ">>>>>>> 8", ret);	
	CALL_CFG(SIP, sip);

	// step : set stun cfg 
	Cdbg(APP_DBG, ">>>>>>> 9", ret);	
	CALL_CFG(STUN, stun);

	// step : set turn cfg 
	Cdbg(APP_DBG, ">>>>>>> 10", ret);	
	CALL_CFG(TURN, turn);

//	set_all_cfg(); save all cfg arg to gNatnl_Cfg;
	Cdbg(APP_DBG, ">>>>>>> 11", ret);	
	ret= save_all_cfg(
		&account_cfg, 
		&log_cfg,
		&device_info_cfg,
		&media_cfg,
		&upnp_cfg,
		&ice_cfg,
		&sip_cfg,
		&stun_cfg,
		&turn_cfg,
		&gNatnl_cfg
		);
	// set queue mechanism before init
//	ret = InitWatchQueue(deal_cb_event, QUEUE_SEM, TMP_DATA_SEM);
//	Cdbg(APP_DBG, ">>>>>>>init watch queue ret =%d", ret);	
	// init lock
	Cdbg(APP_DBG, ">>>>>>> 11 -1" , ret);
	ret = nat_sdk_init(&ue, 1);
	Cdbg(APP_DBG, ">>>>> 16 ret=%d", ret);
	if (ret != 0) {
		ue = AAE_UP_ERROR;  
		goto _INIT_PEER_ERROR;
	}

// for test
//#ifdef RTCONFIG_ACCOUNT_BINDING
	//st_PnsSendMsgFcm(&gsa, &lg, "test fcm");
//#endif
	// Success to login and nat_init ,reset retry count
	nvram_set_int(NVRAM_RETRY_COUNT, 0);
	return ue;
		
_INIT_PEER_ERROR:
	
	return ue;
}



