#include <stdio.h>
#include "log.h"
#include "tcp_server.h"
#include "ws_caller.h"
#include "nw_util.h"
#include "tunnel_proc.h"
#include "aicloud_io.h"
#include "natnl_lib.h"
#include "natapi.h"
#include <assert.h>
#include "parse_arg.h"
#include <sys/stat.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "mastiff.h"
#include "time_util.h"
#if NVRAM
#ifdef __cplusplus  
extern "C" {  
#endif
#include <bcmnvram.h>
#ifdef __cplusplus  
}
#endif
#include <nat_nvram.h>
#include <shared.h>
#endif

#ifdef SW_HW_AUTH
/* common header */
#include <auth_common.h>
#endif

#include "aae_ipc_handler.h"

#include <time_util.h>	/* wb/ws_src/time_util.h */
/* tunnel_proc.c */
void GetNatCfg(struct natnl_config* cfg);
int util_copy_str(char* src, char** dst);

#define APP_DBG 1

//#define MASTIFF_EN 1

#define GetCurrTID() ((unsigned int)pthread_self())

#ifdef NVRAM
#define NVRAM_SET_AAE(x) nvram_set_aae_info(x)
#define NVRAM_WATCH_AAE() WatchingNVram()
#define NVRAM_GET_SDK_LOG_LEVEL() nvram_get_aae_sdk_log_level()
#define NVRAM_SET_SDK_LOG_LEVEL(x) nvram_set_aae_sdk_log_level(x)
#else
#define NVRAM_SET_AAE(x) 0
#define NVRAM_WATCH_AAE()
#define NVRAM_GET_SDK_LOG_LEVEL() -1
#define NVRAM_SET_SDK_LOG_LEVEL(x) 0
#endif

#define KAL_TIME		43200	
#define APP_LOG_PATH	"/tmp/aaews_log"
#define SDK_LOG_PATH	"/tmp"
#define SDK_LOG_FLAG_FILE "/tmp/tnl_log_on.txt" 
#define PATH_LEN	128
#define ID_MAX_LEN	64
#define PWD_MAX_LEN	64
#define URL_MAX_LEN	128
#define FLAG_LEN	2

#define DECLARE_CLEAR_MEM(type, var, len) \
	type var[len]; \
	memset(var, 0, len );
//#define TEST_CODE 1
int is_terminate = 0;
char g_aaews_log_path[PATH_LEN];
char g_vip_id[ID_MAX_LEN]	;
char g_vip_pwd[PWD_MAX_LEN]	;
char g_dev_id[ID_MAX_LEN]	;
char g_dev_pwd[PWD_MAX_LEN]	;
char g_sip_srvs[URL_MAX_LEN]	;
char g_stun_srvs[URL_MAX_LEN]	;
char g_turn_srvs[URL_MAX_LEN]	;
char g_disable_aae[FLAG_LEN]	;
char g_sdk_log_dir[PATH_LEN]	;
char g_sdk_log_level[FLAG_LEN]  ;
char g_sdk_control_port[PORT_LEN];

#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
extern int aae_sendIpcMsg(char *ipcPath, char *data, int dataLen);
int g_is_in_awsiot_trigger_mode = 0;
#endif


extern NAT_REG_DEVICE  nat_reg_device;
extern NAT_UNREG_DEVICE  nat_unreg_device;

int is_valid_dir_path(char* dir_path)
{
	if (!dir_path) 		return 0 ;
	if (!strlen(dir_path)) 	return 0 ;
	struct stat sb; 
	Cdbg(APP_DBG,  "%s, dir_path = %s \n", __func__, dir_path);
	if (stat(dir_path, &sb) == 0 && S_ISDIR(sb.st_mode))
	{
		return 1;	   		 
	}
	Cdbg(APP_DBG, "INVALID DIR PATH");
	return 0;
}

int debug_set_log_cfg(LOG_CFG* log_cfg)
{
	Cdbg(APP_DBG,  "CALL DEFAUT %s^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^====> \n", __func__);
	DECLARE_CLEAR_MEM(char, sdk_log_filename, PATH_LEN);
#ifdef NVRAM
	if (strlen(g_sdk_log_level)) {
		log_cfg->log_level = atoi(g_sdk_log_level);
		NVRAM_SET_SDK_LOG_LEVEL(g_sdk_log_level);
	} else {
		int log_level = NVRAM_GET_SDK_LOG_LEVEL();
		Cdbg(APP_DBG, "log_level=%d\n", log_level);
		if (log_level != -1)
			log_cfg->log_level = log_level;
		else
			log_cfg->log_level = 0;
	}

	log_cfg->log_file_size = 512;
	log_cfg->log_rotate_number = 5; 

	memset(g_sdk_log_dir, '\0', sizeof(g_sdk_log_dir));
	if (log_cfg->log_level > 0) {
		memcpy(g_sdk_log_dir, SDK_LOG_PATH, strlen(SDK_LOG_PATH));
	}
#endif

	if(is_valid_dir_path(g_sdk_log_dir)){
		int dir_path_len = strlen(g_sdk_log_dir);
		if(g_sdk_log_dir[dir_path_len-1] != '/'){
			g_sdk_log_dir[dir_path_len] ='/' ;
			g_sdk_log_dir[dir_path_len+1] ='\0' ;
		}
		char* ts;
		alloc_time_string("%Y-%m-%d_%H:%M:%S", 0, &ts);
		Cdbg(APP_DBG, "g_sdk_log_dir1=%s", g_sdk_log_dir);
		sprintf(sdk_log_filename, "%stunnel_sdk_%s.txt",g_sdk_log_dir, ts);
		log_cfg->log_filename = malloc(strlen(sdk_log_filename)+1); 
		memset(log_cfg->log_filename, 0, strlen(sdk_log_filename)+1);
		strcpy(log_cfg->log_filename, sdk_log_filename);
		dealloc_time_string(ts);

		// log_flag_file
		log_cfg->log_flag_file = (char *)malloc(strlen(SDK_LOG_FLAG_FILE)+1);
		memset(log_cfg->log_flag_file, 0, strlen(SDK_LOG_FLAG_FILE)+1);
		strcpy(log_cfg->log_flag_file, SDK_LOG_FLAG_FILE);

		// log_file_flags
		log_cfg->log_file_flags = 0;

		// syslog_facility
		log_cfg->syslog_facility = 0;
	}else{
		Cdbg(APP_DBG, "g_sdk_log_dir2=%s", g_sdk_log_dir);
		log_cfg->log_file_flags = 0x1110; // default set 0 to replace the log file
		log_cfg->syslog_facility = LOG_USER;
	}
	
	return 0;
}

void set_terminate()
{
	is_terminate =1;
}

void get_device_id(char* device_id)
{
	struct natnl_config* cfg = malloc(sizeof(natnl_config));
	memset(cfg, 0, sizeof(struct natnl_config));
	GetNatCfg(cfg);
	if(device_id && cfg->device_id) strlcpy(device_id, cfg->device_id, ID_MAX_LEN);
	if(cfg) free(cfg);
}

#define MAX_SEG 8 
struct str_segment{
	char* start_pos;
	char* end_pos;
};
struct _srv_cfg
{
	int			srv_cnt;
	SrvInfo*	srv;
};
struct _srv_cfg* parse_ip(char* srv_ips)
{
	int len=0;
	char* pch=NULL;
	char* last_pch=srv_ips;
//	char* last_pch = malloc(strlen(srv_ips)+1); memset(last_pch , 0, strlen(srv_ips)+1);
//	strcpy(last_pch, srv_ips);
	char* end_pch = srv_ips + strlen(srv_ips)-1;
	SrvInfo* p=NULL, *phead=NULL; 
	struct _srv_cfg* cfg;
	int seg_cnt =0;
	if(!srv_ips )		goto _PARSE_IP; 
	if(!strlen(srv_ips)) 	goto _PARSE_IP;
	struct str_segment ss[MAX_SEG];
	memset(ss, 0, sizeof(ss));
	while((pch = strchr(last_pch, ','))){
//	Cdbg(APP_DBG, " %s found pch =%p  \n", __func__, pch);
		//ss.dot_pos_array[i] = pch;
		ss[seg_cnt].end_pos = (char*) ((size_t)pch -1);
		ss[seg_cnt].start_pos = last_pch;
//	Cdbg(APP_DBG, " %s found last start_pos = %p, end_pos=%p  \n", __func__, ss[seg_cnt].start_pos, ss[seg_cnt].end_pos);
		last_pch = (char*)((size_t)pch+1);
		seg_cnt ++;
		if(last_pch > end_pch || seg_cnt>=MAX_SEG ) break;
	}
	if(last_pch == srv_ips){
		ss[seg_cnt].start_pos 	= srv_ips;
		ss[seg_cnt].end_pos	= end_pch;	
		seg_cnt = 1;
	}else if (seg_cnt < MAX_SEG){
		//  parse like this  => 192.168.1.1,192.168.1.2
		ss[seg_cnt].end_pos 	= end_pch;
		ss[seg_cnt].start_pos 	= last_pch;
		seg_cnt ++;
	}

	int i =0;
	Cdbg(APP_DBG, " copy to struct SrvInfo , count =%d \n",  seg_cnt);
	for(i =0; i< seg_cnt; i++){
		if(!p){
			p=malloc(sizeof(SrvInfo)); memset(p, 0, sizeof(SrvInfo));
			phead = p;
			Cdbg(APP_DBG, "phead =%p", phead);
		}else{
			p->next =malloc(sizeof(SrvInfo)); memset(p->next, 0,sizeof(SrvInfo) ); 
			p = p->next;
		}
		len =(size_t)ss[i].end_pos - (size_t)ss[i].start_pos+1; 
		Cdbg(APP_DBG, " len = %d, start-pos =%s", len, ss[i].start_pos);
		strncpy(p->srv_ip, ss[i].start_pos, len);
		p->srv_ip[len]='\0';
		Cdbg(APP_DBG, "copy to srv ip =%s", p->srv_ip);
	}
_PARSE_IP:
	Cdbg(APP_DBG, " srv_cnt=%d  ", seg_cnt);
	cfg = malloc(sizeof(struct _srv_cfg));
	memset(cfg, 0, sizeof(struct _srv_cfg));
	cfg->srv_cnt 	= seg_cnt;
	cfg->srv	= phead;
	return cfg;
}

int	debug_set_stun_cfg(STUN_CFG* stun_cfg)
{
	if(!stun_cfg) goto _DEFAULT_SET_STUN_ERROR;
	Cdbg(APP_DBG, "CALL DEFAUT %s^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^====> \n", __func__);
	int ret;
	STUN_CFG* tmp_cfg =  (STUN_CFG*)parse_ip(g_stun_srvs);
	if(tmp_cfg){
		memcpy(stun_cfg, tmp_cfg, sizeof(STUN_CFG));
		free(tmp_cfg);
	}
	Cdbg(APP_DBG, "stun srv cnt =%d, stun-head =%p \n", stun_cfg->stun_srv_cnt, stun_cfg->stun_srv);
	ret =0;
_DEFAULT_SET_STUN_ERROR:
	return ret;
}

int	debug_set_sip_cfg(SIP_CFG* sip_cfg)
{
	if(!sip_cfg) goto _DEFAULT_SET_SIP_ERROR;
	Cdbg(APP_DBG,  "CALL DEFAUT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^====> \n");
	int ret;
	SIP_CFG* tmp_cfg =  (SIP_CFG*)parse_ip(g_sip_srvs);
	if(tmp_cfg){
		memcpy(sip_cfg, tmp_cfg, sizeof(SIP_CFG));
		free(tmp_cfg);
	}
	Cdbg(APP_DBG, "sip srv cnt =%d, sip-head=%p \n", sip_cfg->sip_srv_cnt, sip_cfg->sip_srv);
	ret =0;
_DEFAULT_SET_SIP_ERROR:
	return ret;
}

int	debug_set_turn_cfg(TURN_CFG* turn_cfg)
{
	if(!turn_cfg) goto _DEFAULT_SET_TURN_ERROR;
	int ret;
 	Cdbg(APP_DBG,  "CALL DEFAUT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^====> \n");
	TURN_CFG* tmp_cfg = (TURN_CFG*)parse_ip(g_turn_srvs);
	if(tmp_cfg){
		memcpy(turn_cfg, tmp_cfg, sizeof(TURN_CFG));
		free(tmp_cfg);
	}
	Cdbg(APP_DBG, "turn srv cnt =%d , turn-head=%p", turn_cfg->turn_srv_cnt, turn_cfg->turn_srv);
	ret =0;
_DEFAULT_SET_TURN_ERROR:
	return ret;
}

int	debug_set_device_info_cfg(DEVICE_INFO_CFG* device_info_cfg)
{
	char* reg_devid = g_dev_id;
	char* reg_devpwd = g_dev_pwd;
	int ret=-1;
	int	devid_len = strlen(reg_devid)+1;
	int	devpwd_len = strlen(reg_devpwd)+1;
 	Cdbg(APP_DBG, "CALL DEFAUT %s^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^====> \n", __func__);
	device_info_cfg->device_id = malloc(devid_len);
   	memset(device_info_cfg->device_id, 0, devid_len);
	strcpy(device_info_cfg->device_id, reg_devid);

	int g_device_pwd_len = strlen(g_dev_pwd)+1;
	Cdbg(APP_DBG, "g_device_pwd_len = %d", g_device_pwd_len);
	if(g_device_pwd_len>20){ 
		device_info_cfg->device_pwd = malloc(g_device_pwd_len);
		memset(device_info_cfg->device_pwd, 0, g_device_pwd_len);
		strcpy(device_info_cfg->device_pwd, g_dev_pwd);
	}else{
		device_info_cfg->device_pwd = malloc(devpwd_len);
		memset(device_info_cfg->device_pwd, 0, devpwd_len);
		strcpy(device_info_cfg->device_pwd, reg_devpwd);
	}
	ret = 0;
	return ret;
}

int debug_set_account_cfg(ACCOUNT_CFG* account_cfg)
{
	Cdbg(APP_DBG, "CALL DEFAUT %s^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^====> \n", __func__);
	int ret = -1;
	DECLARE_CLEAR_MEM(char, aae_pwd, PWD_MAX_LEN);
	DECLARE_CLEAR_MEM(char, aae_account,ID_MAX_LEN);
	sprintf(aae_account, "%s", 	g_vip_id );
	sprintf(aae_pwd, "%s" 	,	g_vip_pwd);
	if(!strlen(aae_account) || !strlen(aae_pwd)) 
		goto _DEFAULT_SET_ACC_CFG;
	util_copy_str(aae_account, &account_cfg->account);
	util_copy_str(aae_pwd, &account_cfg->password);
	ret= 0;
_DEFAULT_SET_ACC_CFG:
	return ret;
}

void zero_arg()
{
	memset(g_aaews_log_path, 0, PATH_LEN);
	memset(g_vip_id, 0, ID_MAX_LEN);
	memset(g_vip_pwd, 0, PWD_MAX_LEN);
	memset(g_dev_id, 0, ID_MAX_LEN)	;
	memset(g_dev_pwd, 0, PWD_MAX_LEN);
	memset(g_sip_srvs, 0, URL_MAX_LEN);
	memset(g_stun_srvs, 0, URL_MAX_LEN);
	memset(g_turn_srvs, 0, URL_MAX_LEN);
	memset(g_disable_aae, 0, FLAG_LEN);
	memset(g_sdk_log_dir, 0, PATH_LEN);
	memset(g_sdk_log_level, 0, FLAG_LEN);
	memset(g_sdk_control_port, 0, PORT_LEN);
}

void copy_arg(int argc)
{
	if(argc<2) return;
	zero_arg();
	get_arg_field("--aaews_log_path",g_aaews_log_path );
	get_arg_field("--asus_vip_id", 	g_vip_id );
	get_arg_field("--asus_vip_pwd", g_vip_pwd );
	get_arg_field("--device_id", 	g_dev_id );
	get_arg_field("--device_pwd", 	g_dev_pwd );
	get_arg_field("--sip_srvs", 	g_sip_srvs);
	get_arg_field("--stun_srvs", 	g_stun_srvs);
	get_arg_field("--turn_srvs", 	g_turn_srvs);
	get_arg_field("--disable_aae", 	g_disable_aae);
	get_arg_field("--sdk_log_dir",	g_sdk_log_dir);
	get_arg_field("--sdk_log_level",  g_sdk_log_level);
	get_arg_field("--sdk_control_port",  g_sdk_control_port);
}

void print_arg()
{
	if (!nvram_get_int("debug_aaews"))
		return;
#if 0
	fprintf(stderr, "--aaews_log_path=>%s\n",	g_aaews_log_path );
	fprintf(stderr,"--asus_vip_id=>%s\n", 	g_vip_id );
	fprintf(stderr,"--asus_vip_pwd=>%s\n", g_vip_pwd );
	fprintf(stderr,"--device_id=>%s\n", 	g_dev_id );
	fprintf(stderr,"--device_pwd=>%s\n", 	g_dev_pwd );
	fprintf(stderr,"--sip_srvs=>%s\n", 	g_sip_srvs);
	fprintf(stderr,"--stun_srvs=>%s\n", 	g_stun_srvs);
	fprintf(stderr,"--turn_srvs=>%s\n", 	g_turn_srvs);
	fprintf(stderr,"--disable_aae=>%s\n", 	g_disable_aae);
	fprintf(stderr,"--sdk_log_dir=>%s\n", 	g_sdk_log_dir);
	fprintf(stderr,"--sdk_log_level=>%s\n",   g_sdk_log_level);
	fprintf(stderr,"--sdk_control_port=>%s\n",   g_sdk_control_port);
#endif
}

extern int errno;
#if 0
void thread_control_message_handler(void)
{
	fd_set  fds;
	int maxfd = 0,from_len=0;
	struct timeval timeout;
	char buf[128]={0};
	char resp[] = "aaews:ok";
	int len = 0;
	while( 1 ) {
		timeout.tv_sec = 60;
		timeout.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(g_control_sockfd,&fds);
		maxfd = g_control_sockfd+1;

		switch( select(maxfd,&fds,NULL,NULL,&timeout) )
		{
			case -1:
				aaews_errlog("[aaews]Select error");
			break;

			case 0:
				aaews_errlog("[aaews]Do not receive messages from mastiff about 60s");
			break;

			default:
				if( FD_ISSET(g_control_sockfd,&fds) )
				{
					struct sockaddr_in from;
					memset(&from,0,sizeof(from));
					//fprintf(stderr,"[aaews]recvfrom\n");
					if(  (len = recvfrom (g_control_sockfd,buf,128,0,&from,&from_len) ) <= 0 ) {
						fprintf(stderr,"[aaews]Receive error\n");
						break;
					} else {
						//fprintf(stderr,"[aaews]recvfrom good %d\n",len);
						/* aaews:resp */
						if( len < 9 || strncmp( buf, "aaews:req", 9 ))
						{
							fprintf(stderr,"[aaews]Receive an unexpectd request[%s]\n",buf);
							break;
						}
						//fprintf(stderr,"[aaews]send  <%s>%d %d\n",resp,sizeof(resp),from_len);
						//fprintf(stderr,"[aaews]g_control_sockfd %d\n",g_control_sockfd);
						//fprintf(stderr,"[aaews]resp %s\n",resp);
						//fprintf(stderr,"[aaews]strlen(resp) %d\n",strlen(resp));
						//fprintf(stderr,"[aaews]from.sin_addr.s_addr %d\n",from.sin_addr.s_addr);
						//fprintf(stderr,"[aaews]from.sin_port %d\n",ntohs(from.sin_port));
						//fprintf(stderr,"[aaews]sizeof(from) %d\n",sizeof(from));
						len = sendto( g_control_sockfd,	resp, strlen(resp), 0,(struct sockaddr *)&from,from_len);
						if( len != strlen(resp) ){
							fprintf(stderr,"[aaews]Send  a response error[%d]\n",len);
							//printf("Oh dear, something went wrong with read()! %s\n", strerror(errno));
						}
						//fprintf(stderr,"[aaews]sendto good\n");
					}
				}
		}
	}
}

int create_thread_control_message_handler(void) {
	unsigned short tmp_port;
	struct sockaddr_in loacl_addr;
	const int on = 1;
	tmp_port = atoi(g_sdk_control_port);
	if(tmp_port == 0)
		tmp_port = AAEWS_CHECK_PORT;
	g_control_sockfd=socket(AF_INET,SOCK_DGRAM,0);
	if( g_control_sockfd == 0 ){
		aaews_errlog("[aaews]Create socket error");
		return -1;
	}

	bzero(&loacl_addr,sizeof(loacl_addr));
	loacl_addr.sin_family = AF_INET;
	loacl_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
	loacl_addr.sin_port=htons(tmp_port);
	setsockopt(g_control_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if( bind( g_control_sockfd,(struct sockaddr *)&loacl_addr,sizeof(loacl_addr) ) )
	{
		char buf[128]={0};
		fprintf(buf,"[aaews]Bind port %d error, keep trying",tmp_port);
		aaews_errlog(buf);
		close(g_control_sockfd);
		return -1;
	}

	if ( pthread_create(&thread_control_message,NULL,(void *) thread_control_message_handler ,NULL) !=0) 
	{
		fprintf(stderr,"[aaews]Create thraed error\n");
		close(g_control_sockfd);
		return -1;		
	}

	return 0;
}
#endif

static void send_status_to_mastiff(int status)
{
	
	unsigned short tmp_port;
	struct sockaddr_in loacl_addr;
	int fd=0,len=0;
	char buf[128] = {0};

	tmp_port = MASTIFF_DEF_PORT;

	fd=socket(AF_INET,SOCK_DGRAM,0);
	if( fd == 0 ){
		Cdbg(APP_DBG, "[aaews]Create socket error");
		return ;
	}
	
	bzero(&loacl_addr,sizeof(loacl_addr));
	loacl_addr.sin_family = AF_INET;
	loacl_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
	loacl_addr.sin_port=htons(tmp_port);

	sprintf(buf,"aaews:%d",status);

	len = sendto( fd, buf, strlen(buf), 0,(struct sockaddr *)&loacl_addr,sizeof(loacl_addr));
	if(len != strlen(buf))
		Cdbg(APP_DBG, "sendto error:len %d %d\n",len ,strlen(buf));
}

static void aae_sig_action(int sig) {
	if (sig == SIGSEGV) {
		Cdbg(APP_DBG, "SIGSEGV get");
		send_status_to_mastiff(SEGMENTATION_FAULT);
	}
	else if (sig == SIGABRT) {
		Cdbg(APP_DBG, "SIGABRT get");
		send_status_to_mastiff(SIGABRT_GET);
	}
	else if (sig == SIGTERM) {
		Cdbg(APP_DBG, "SIGTERM get");
	}

	set_terminate();
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
	remove(AAEWS_PID_PATH);
	nvram_set_int("aae_enable", (nvram_get_int("aae_enable") & ~1));
}

static void aae_sig_handler(int sig)
{
	Cdbg(APP_DBG, "AAE SIG HANDLER BEGINS");
	switch (sig) {
		case SIGSEGV:
		case SIGABRT:
			aae_sig_action(sig);
			break;
		case SIGTERM:
			DeletePeer();
			aae_sig_action(sig);
			break;
		case AAEWS_SIG_ACTION:
			{
				int action = nvram_get_int("aae_action");
				Cdbg(APP_DBG, "AAEWS_SIG_ACTION get action=%d", action);
				if (action == AAEWS_ACTION_SIP_UNREGISTER) {
					if (nvram_get_int("aae_sip_connected") == 1)
						nat_unreg_device();
				}
				else if (action == AAEWS_ACTION_SIP_REGISTER) {
					if (nvram_get_int("aae_sip_connected") == 0)
						nat_reg_device();
				}
				else if (action == AAEWS_ACTION_SDK_DEINIT) {
					if (nvram_get_int("aae_sdk_inited") == 1)
						nat_sdk_deinit();
				}
				else if (action == AAEWS_ACTION_SDK_INIT) {
					if (nvram_get_int("aae_sdk_inited") == 0)
						nat_sdk_init(NULL, 0);
				}
				nvram_set_int("aae_action", 0);
			}
			break;
	}
}

#ifdef NVRAM
#define DEFAULT_IDLE_TIMEOUT_SEC	1800;
#define MAIN_THREAD_SLEEP 1
int g_idle_time = 0;

void WatchingNVram()
{
	int aae_idle_timeout_sec = nvram_get_int("aae_idle_timeout_sec");
	aae_idle_timeout_sec = aae_idle_timeout_sec ? aae_idle_timeout_sec : DEFAULT_IDLE_TIMEOUT_SEC;
	while(1)
	{
#ifdef TNL_CALLBACK_ENABLE
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		if (nvram_get_int("aae_sip_connected") == 1
			&& is_account_bound()
#ifdef RTCONFIG_IG_SITE2SITE
			&& !vpns_use_tunnel()
#endif
		) {
			if (!is_any_tnl_active())
				g_idle_time += MAIN_THREAD_SLEEP;
			else
				g_idle_time = 0;
				//Cdbg(APP_DBG, "WatchingNVram : g_idle_time=%d" , g_idle_time);

			if (g_idle_time > aae_idle_timeout_sec)  // idle time exceeds
			{
// send ipc to [awsiot]
#if 0 //def RTCONFIG_AWSIOT
				{
					Cdbg(NV_DBG, "time exceeds, aae_sip_connected = 0");

					char status_str[256];
					snprintf(status_str, sizeof(status_str), AAE_TUNNEL_STATUS_RES, 0);
					aae_sendIpcMsg(AWSIOT_IPC_SOCKET_PATH, status_str, strlen(status_str));

					Cdbg(NV_DBG, "aae_sendIpcMsg end");
					nvram_set_aae_sip_connected("0");

				}
#endif
				//break;
				Cdbg(NV_DBG, "time exceeds, stop sip connection!!!");
				g_idle_time = 0;
				nat_unreg_device();
			}
		}
#endif
#endif
		if(!nvram_is_aae_enable()){
//			set_event(&p_gAAE_sem);
			break; // aaenable = 0;
		}
		sleep(MAIN_THREAD_SLEEP);
	}
}
#endif

int main (int argc, char* argv[])
{
	int status = -1;
    char cmd_save_pid[40];
#ifdef TNL_CALLBACK_ENABLE
	struct natnl_tnl_event tnl_event;
#endif
	parse_arg(argc, argv);
	copy_arg(argc);	
	print_arg();
#if 0 	// test for printf arg
//	dump_arg();
	print_arg();
	return 0;	
#endif
	signal(SIGSEGV, aae_sig_handler);
	signal(SIGABRT, aae_sig_handler);
	signal(SIGTERM, aae_sig_handler);
	signal(AAEWS_SIG_ACTION, aae_sig_handler);

#ifdef NVRAM
	// clear aae_enable and aae_sip_connected flag
	nvram_set_int("aae_enable", (nvram_get_int("aae_enable") & ~1));
	nvram_set_aae_sip_connected("0");
#endif

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
		;//printf("This is not ASUS Router\n");
		return 0;
	}
	// ===================== sw-hw-auth check end =====================
#endif

	aae_support_check(&is_terminate);

    snprintf(cmd_save_pid, sizeof(cmd_save_pid), "echo %d > %s",  getpid(), AAEWS_PID_PATH);
    system(cmd_save_pid);

#if 0
	if ( create_thread_control_message_handler() ){
		//printf("[aaews]create_thread_control_message_handler fail\n");
		return -1;
	}
#endif
	/** The InitPeer function could be invoked callback routine for customized settings					**/
	/** ex , the log path should be located depend on OS, so just set SET_LOG_CFG callback as arguments **/
	/*if(strlen(g_aaews_log_path)){
		CF_OPEN(APP_LOG_PATH, FILE_TYPE );
	} else if( strlen(g_sdk_log_level) ) {
		CF_OPEN(NULL, SYSLOG_TYPE );
	}*/

	// Prepare LOG, Currently support syslog, file and console type
	CF_OPEN(APP_LOG_PATH, SYSLOG_TYPE | FILE_TYPE | CONSOLE_TYPE | STDOUT_TYPE);

	//int ret = st_IftttNotification("nwep.asus.com", "/router/ifttt/v1/triggers/webhook_device_connect", 
	//	"{\"cname\":\"\",\"macaddr\":\"xx:xx:xx:xx:xx:xx\",\"ip\":\"\",\"ifname\":\"eth1\",\"RMacAddr\":\"74:D0:2B:64:EE:E8\"}");
	

#ifdef TNL_CALLBACK_ENABLE
	status = InitPeer(
			strlen(g_vip_id)&&strlen(g_vip_pwd)	? debug_set_account_cfg:NULL,
			strlen(g_dev_id)&&strlen(g_dev_pwd)	? debug_set_device_info_cfg : NULL,
			//is_valid_dir_path(g_sdk_log_dir)	? debug_set_log_cfg:NULL,
			debug_set_log_cfg,
			NULL,
			NULL,
			NULL,
			strlen(g_sip_srvs)	?debug_set_sip_cfg:NULL ,//ipcam_set_sip_cfg,	//NULL,
			strlen(g_stun_srvs)	?debug_set_stun_cfg:NULL,//ipcam_set_stun_cfg, //NULL,
			strlen(g_turn_srvs)	?debug_set_turn_cfg:NULL, //ipcam_set_turn_cfg,//NULL,
			NULL,
			&tnl_event,
			(g_disable_aae[0]=='1')?0:1	

		);
#else
	status = InitPeer(
			strlen(g_vip_id)&&strlen(g_vip_pwd)	? debug_set_account_cfg:NULL,
			strlen(g_dev_id)&&strlen(g_dev_pwd)	? debug_set_device_info_cfg : NULL,
			//is_valid_dir_path(g_sdk_log_dir)	? debug_set_log_cfg:NULL,
			debug_set_log_cfg,
			NULL,
			NULL,
			NULL,
			strlen(g_sip_srvs)	?debug_set_sip_cfg:NULL ,//ipcam_set_sip_cfg,	//NULL,
			strlen(g_stun_srvs)	?debug_set_stun_cfg:NULL,//ipcam_set_stun_cfg, //NULL,
			strlen(g_turn_srvs)	?debug_set_turn_cfg:NULL, //ipcam_set_turn_cfg,//NULL,
			(g_disable_aae[0]=='1')?0:1	

		);

#endif
	if(status != 0 && status !=200)
	{
		send_status_to_mastiff(status);
		goto _MAIN_ERROR;
	}
	DECLARE_CLEAR_MEM(char, deviceid, ID_MAX_LEN);
	get_device_id(deviceid);
	Cdbg(APP_DBG, "InitPeer ............. Set nvram aae info " );
	status = NVRAM_SET_AAE(deviceid);
	if(status)goto _MAIN_ERROR;
	
	Cdbg(APP_DBG, "InitPeer ............. Call KeepAlive loop " );

	if(g_disable_aae[0]!='1') st_KeepAlive_threading(KAL_TIME, &is_terminate );	

#if TEST_CODE
	start_test_srv();
//	start_aicloud_message_srv();
#endif

#ifdef NVRAM
	NVRAM_WATCH_AAE();
	set_terminate();
#else
	Cdbg(APP_DBG, "Get CHAR >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
	//gets(input);
	char ch = getchar();
	Cdbg(APP_DBG, "Get CHAR >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> input =%c", ch);
	if(ch == 'q') {
		Cdbg(APP_DBG, "Set Terminate");
		set_terminate();
	}
#endif
	status = st_KeepAlive_thread_exit();
_MAIN_ERROR:
	remove(AAEWS_PID_PATH);

	DeletePeer();
	
	CF_CLOSE();
	return 0;
}


