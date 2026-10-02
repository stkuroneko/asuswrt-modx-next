#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>	//openlog(), syslog()
//#include <utils.h>
//#include <shutils.h>
#include <shared.h>
#include <shutils.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <stddef.h>
#include <sys/stat.h>
#include <syslog.h>
#include "bcmnvram.h"
#include "natapi.h"
#include "ws_api.h"
#include "nw_util.h"
#include "log.h"
#include "nat_nvram.h"
#include "tunnel_proc.h"

#include <string.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <rtconfig.h>
#include <syslog.h>
#include "common.h"
#include "mastiff.h"
#include "ws_caller.h"		// st_Login()
#include "info_report.h"	// write_login_info()
#include "time_util.h"		// is_device_ticket_expired() in wb/ws_src/time_util.h


//#include <endian.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#ifdef SW_HW_AUTH
/* common header */
#include <auth_common.h>
#endif

#include "aae_ipc_handler.h"

/* nat_nvram.c */
int nvram_save_value(const char* name, const char* value);
/* this mastiff.c */
int is_dual_wan(void);
int sw_mode_check(void);
int set_device_id_and_keep_login(int caller);
void run_aae(void);
void start_aae_sdk_init( void );
void stop_aae( void );
int aae_keepalive_loop(int sec, int* is_terminate, int* is_ddns_name_uploaded);
int aae_keepalive(GetServiceArea* gsa, Login* lg);

/* DEFINE */
#define MASTIFF_DBG 1

#define MASTIFF_EN 1
#define MASTIFF_LOG_PATH    "/tmp/mastiff_log"

#define MAIN_THREAD_SLEEP_10_SEC 10
#define MAIN_THREAD_SLEEP_5_SEC 5
#define KAL_TIME        43200   
#define TIMER_SEC      2
#define LAUNCHED_PROC "aaews"
//#include <nat_nvram.h>
//#include "nat_nvram.h"
#define UNUSED(x) ( (void)(x) )
#define DEFAULT_STUN_PORT 3478
#define GOOGLE_STUN_PORT 19302
#define MAX_STUN_SERVER  5
#define PROCPS_BUFSIZE 1024
#ifndef ROUTER
#define ULLONG_MAX     (~0ULL)
#define UINT_MAX       (~0U)
#endif
#define PORT_LEN    6
#define DDNS_LEN    64
#define LINK_INTERNET   "link_internet"

#define AIHOME_API_LEVEL    EXTEND_AIHOME_API_LEVEL // From shared/shared.h
#define DEVICE_TYPE     "93"
#define ASUS_DEVICE_SERVICE "1001"

#define NVRAM_CN        "computer_name"

// --
typedef struct list {
    int data;
    struct list *next;
} LIST;

#define AAEWS_STATUS_INIT 0
#define AAEWS_STATUS_STOP 1
#define AAEWS_STATUS_RUN  2
#define AAEWS_CHECK_TIMES 2

#define TMP_PATH "/tmp/"

pthread_t thread_control_message;

/* GLOBAL */

/* LOCAL */
pthread_mutex_t stun_url_mutex;
char stun_srv[80];
int  stun_srv_get;
int is_terminate = 0;
LIST *head = NULL;
LIST *tail = NULL;
int g_org_eth0_ip = 0;
int g_have_device_id = 0;
int g_ddns_name_uploaded = 0;
int g_wan_ip_changed = 0;
int g_need_to_retry_aae = 0;
int g_need_to_retry_unreg = 0;  // not implemeted retry unregister
int g_asus_eula_flag = 0;
int g_has_ddns_name = 0;
pid_t g_pid;
GetServiceArea  g_getservicearea; 
Login       g_login;
int g_keepalive_terminate = 0;
int g_update_profile_thread_created = 0;
int g_sip_disconnect_time = 0;
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
int g_is_in_awsiot_trigger_mode=0;
#endif

int set_device_id_and_keep_login(int caller);
int is_dual_wan(void);
int sw_mode_check(void);
void start_aae_sdk_init( void );
void run_aae( void );
void stop_aae( void );
int aae_keepalive_loop(int sec, int* is_terminate, int* is_ddns_name_uploaded);
int aae_keepalive(GetServiceArea* gsa, Login* lg);

/* FUNCTIONS */

static void mastiff_errlog(char *buf)
{
	openlog("Mastiff", 0, 0);
	syslog(0, buf);
	closelog();

	fprintf(stderr,"[Mastiff]%s\n",buf);
}


void list_insert(int data) {
	LIST *tmp;
	
	tmp = malloc(sizeof(LIST));
	tmp->data = data;
	tmp->next = NULL;
	
	if(head == NULL)
		head = tail = tmp;
	else {
		tail->next = tmp;
		tail = tmp;
	}
}

void list_print() {
	LIST *tmp;
	tmp = head;
	
	while(tmp != NULL) {
		//printf("%d\n", tmp->data);
		tmp = tmp->next;
	}
}

void list_clear() {
	LIST *tmp;
	tmp = head;
	
	while(tmp != NULL) {
		head = head->next;
		free(tmp);
		tmp = head;
	}
	
	head = tail = NULL;
}

void div_ip(const char *ip) {
	
	int num;
	int len = strlen(ip);
	char *tmp;
	char ip_prc[len+1];
	memset(ip_prc, 0, sizeof(ip_prc));
	memcpy(ip_prc, ip, len);
	tmp = strtok(ip_prc, ".");
	num = atoi(tmp);
	list_insert(num);
	
	while (tmp != NULL) {
		tmp = strtok(NULL, ".");
		if(tmp == NULL)
			break;
		
		num = atoi(tmp);
		list_insert(num);
	}
	
}

int process_ip(const char *ip) {
	
	int legit0, legit1, legit2, legit3;
	LIST *tmp;
	
	legit0 = legit1 = legit2 = legit3 = 0;
	div_ip(ip);
//	list_print();

	if(head->data == 0) {
		list_clear();
		return 0;
	}
	
	if(head->data == 10) {	
		legit0 = 1;
		tmp = head->next;
		if(tmp->data >= 0 && tmp->data <=255) {
			legit1 = 1;
			tmp = tmp->next;
		}
		if(tmp->data >= 0 && tmp->data <=255) {
			legit2 = 1;
			tmp = tmp->next;
		}
		if(tmp->data >= 0 && tmp->data <=255) {
			legit3 = 1;
			tmp = tmp->next;
		}
	} else if (head->data == 172) {
		legit0 = 1;
		tmp = head->next;
		if(tmp->data >= 16 && tmp->data <=31) {
			legit1 = 1;
			tmp = tmp->next;
		}
		if(tmp->data >= 0 && tmp->data <=255) {
			legit2 = 1;
			tmp = tmp->next;
		}
		if(tmp->data >= 0 && tmp->data <=255) {
			legit3 = 1;
			tmp = tmp->next;
		}
	} else if (head->data == 192) {
		legit0 = 1;
		tmp = head->next;
		if(tmp->data ==168) {
			legit1 = 1;
			tmp = tmp->next;
		}
		if(tmp->data >= 0 && tmp->data <=255) {
			legit2 = 1;
			tmp = tmp->next;
		}
		if(tmp->data >= 0 && tmp->data <=255) {
			legit3 = 1;
			tmp = tmp->next;
		}
	}
	
	list_clear();
	if(legit0 && legit1 && legit2 && legit3)
		return 1;
	
	return 0;
}

unsigned int swap_endian(unsigned int num) {
    return  ((num>>24)&0xff) |          // move byte 3 to byte 0
            ((num<<8)&0xff0000) |       // move byte 1 to byte 2
            ((num>>8)&0xff00) |         // move byte 2 to byte 1
            ((num<<24)&0xff000000) ;    // byte 0 to byte 3
}

static int is_sdk_inited()
{
	return nvram_get_int("aae_sdk_inited");
}

static int is_sip_connection_alive()
{
#if 1
	return nvram_get_int("aae_sip_connected") ? 1 : 0;
#else
	char *cmd = "netstat -na | grep :5061 2>/dev/null";
	FILE *fp = NULL;
	char buf[256];

	if((fp = popen(cmd, "r")) == NULL){
		Cdbg(MASTIFF_DBG, "Cannot execute command. cmd=[%s]", cmd);
		g_sip_disconnect_time = 0;
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	while(fgets(buf, sizeof(buf), fp) != NULL){
		//Cdbg(MASTIFF_DBG, "result buf=[%s]", buf);
		if (strstr(buf, "ESTABLISHED") || strstr(buf, "SYN_SENT")) {
		//Cdbg(MASTIFF_DBG, "SIP is connected or connecting.");
			pclose(fp);
			g_sip_disconnect_time = 0;
			return 1;
		}
	}
	pclose(fp);

	// If The total period of sip disconnected is less than 1800 seconds, report sip alive.
	if (g_sip_disconnect_time > 1800) {
		Cdbg(MASTIFF_DBG, "SIP is disconnected.");
		g_sip_disconnect_time = 0;
		return 0;
	}
	else {
		Cdbg(MASTIFF_DBG, "SIP is disconnecting with high probability.");
		g_sip_disconnect_time += MAIN_THREAD_SLEEP_10_SEC;
		return 1;
	}
#endif
}

static int is_mesh_re_mode()
{
	int re_mode = 0;
#if defined(RTCONFIG_AMAS) // aimesh
    	re_mode |= nvram_get_int(NVARM_AIMESH_RE_MODE);
#if defined(RTCONFIG_WIFI_SON)  // Lyra
	if(nvram_match("wifison_ready", "1")) {
		re_mode = 0; /* overwrite AMAS */
	    	re_mode |= !nvram_get_int(NVARM_LYRA_MASTER_MODE);
	}
#endif
#endif
	return re_mode;
}

unsigned int s_org_wan_ip_int=0;
//char* g_org_wan_ip2=NULL;
int wan_ip_change_for_stable(void)
{
	int is_change = 0;
	const char* s_cur_wan_ip = get_wanip();

	if( !s_org_wan_ip_int ) {

		is_change = 1;
		goto _CHECK_WAN_IP_CHANGE_EXIT;
	} else if( s_cur_wan_ip && ( s_org_wan_ip_int != inet_addr(s_cur_wan_ip)) ) {

		is_change = 1;
		goto _CHECK_WAN_IP_CHANGE_EXIT;
	}

	_CHECK_WAN_IP_CHANGE_EXIT:

	s_org_wan_ip_int = inet_addr(s_cur_wan_ip);

	return is_change;
}

void ip_stable_check(char *ip_stable_flag)
{    
    if( internet_ready() != 1 )
        *ip_stable_flag = -1;
    else
        *ip_stable_flag = *ip_stable_flag << 1;

    //printf("ip_stable_check out %d\n",*ip_stable_flag);
    Cdbg(MASTIFF_DBG, "ip_stable_check out %d\n",*ip_stable_flag);
}

void update_profile_thread(void *arg)
{
    //g_update_profile_thread_created = 1;
    pthread_detach(pthread_self());
    Cdbg(MASTIFF_DBG, "update_profile_thread created.");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
    IFTTT_DEBUG("update_profile_thread created.\n");
#endif

    if ((!is_dual_wan() && !sw_mode_check() && !is_private_ip(1)) || is_mesh_re_mode()) {
        set_device_id_and_keep_login(1);
    } else {
        /*Cdbg(MASTIFF_DBG, "update_profile_thread. no need to update profile.");
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
        IFTTT_DEBUG("update_profile_thread. no need to update profile.\n");
#endif*/
		set_device_id(9, 0); // login for update device desc.
        if (!g_has_ddns_name) {
            g_has_ddns_name = strlen(nvram_safe_get(DDNS_HOSTNAME)) != 0;
            if (g_has_ddns_name) {                
                if( !pids(LAUNCHED_PROC)){
                    // printf("aae is not running,run aae now\n");
                    Cdbg(MASTIFF_DBG, "aae is not running,run aae now...5");
                    run_aae();
                } else if (!is_sdk_inited()) { // If SDK is not inited, init it.
                    Cdbg(MASTIFF_DBG, "SDK is not inited. reinit sdk...5");
                    start_aae_sdk_init();
				} else if (!is_sip_connection_alive()) { // If SIP is not connected, stop aaews. Let next checking round to run aaews.
                    Cdbg(MASTIFF_DBG, "SIP is not connected. Restart aaews...5");
                    stop_aae();
                }
                g_ddns_name_uploaded = 0; // Reset flag. Consider the situation of private to public.
            }
        }
    }
    g_update_profile_thread_created = 0;
}

static void sigaction_handler(int sig)
{
	//printf("SIGACTION HANDLER BEGINS\n");
    Cdbg(MASTIFF_DBG, "sigaction_handler sig=%d.", sig);

    if (sig == SIGTERM || sig == SIGINT) {
        if (sig == SIGTERM)
            mastiff_errlog("Got SIGTERM");
        if (sig == SIGINT)
            mastiff_errlog("Got SIGINT");

        sleep(1);
        is_terminate = 1;
        //g_keepalive_terminate = 1;
        //aae_keepalive_thread_exit();
    } else if (sig == SIGABRT) {
        mastiff_errlog("Got SIGABRT");
        sleep(1);
        is_terminate = 1;
        //g_keepalive_terminate = 1;
        //aae_keepalive_thread_exit();
    } else if (sig == AAE_SIG_REMOTE_CONNECTION_TURNED_ON) {
        mastiff_errlog("Got AAE_SIG_REMOTE_CONNECTION_TURNED_ON");
        if (!g_update_profile_thread_created) {
            pthread_attr_t attr;
            pthread_t tid;
            g_update_profile_thread_created = 1;
            pthread_attr_init(&attr);
        #ifdef PTHREAD_STACK_SIZE
            pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
        #endif
            if ( pthread_create(&tid, &attr, (void *) update_profile_thread, NULL) !=0)
            {
                mastiff_errlog("Create thread error");
                pthread_attr_destroy(&attr);
                return;
            }
            pthread_attr_destroy(&attr);
        }
    } else if (sig == AAE_SIG_EULA_FLAG_SIGNED) {
        mastiff_errlog("Got AAE_SIG_EULA_FLAG_SIGNED");
        if (g_asus_eula_flag != nvram_get_int(ASUS_EULA_FLAG_NANE)) {
            g_asus_eula_flag = nvram_get_int(ASUS_EULA_FLAG_NANE);
#if defined(RTCONFIG_ACCOUNT_BINDING)
			if (is_account_bound()) {
				if (!g_asus_eula_flag) {
					if (pids(LAUNCHED_PROC)) {
						Cdbg(MASTIFF_DBG, "aae is running,stop aae now...8");
						stop_aae();
					}
				} else {
					if (!is_mesh_re_mode()) {
						if( !pids(LAUNCHED_PROC)){
							// checking awsiot trigger mode and whether aaews is ready.
	#ifdef RTCONFIG_IG_SITE2SITE
							if (vpns_use_tunnel())
								nvram_set_int("aae_disable_fast_init", 1);
	#endif
							Cdbg(MASTIFF_DBG, "aae is not running,run aae now...8");
							run_aae();
						} else {
	#ifdef RTCONFIG_IG_SITE2SITE
							if (vpns_use_tunnel() && !is_sip_connection_alive())
							{
								Cdbg(MASTIFF_DBG, "SIP is not connected. start sip connect...2");
								start_sip_conn();
							}
	#endif
						}
					} // if (!is_mesh_re_mode())
				}
			} else 
#endif
			{  // if (is_account_bound())
				if ((!is_dual_wan() && !sw_mode_check() && !is_private_ip(2)) || is_mesh_re_mode()) { // public
					if (!g_asus_eula_flag) // withdraw
						kill(g_pid, SIGUSR1); // try to check public and update profile
				} else {  // private
					if (g_asus_eula_flag == 0) {
						if( pids(LAUNCHED_PROC) ){
							//printf("aae is running,stop aae now\n");
							Cdbg(MASTIFF_DBG, "aae is running,stop aae now...9");
							stop_aae();
							//do_unregister(); // don't impplement this currently.
						}
					} else {
						if( !pids(LAUNCHED_PROC) && !is_mesh_re_mode()){
							// printf("aae is not running,run aae now\n");
							Cdbg(MASTIFF_DBG, "aae is not running,run aae now...6");
							run_aae();
						} else if (!is_sdk_inited()) { // If SDK is not inited, init it.
							Cdbg(MASTIFF_DBG, "SDK is not inited. reinit sdk...6");
							start_aae_sdk_init();
						} else if (!is_sip_connection_alive()) { // If SIP is not connected, stop aaews. Let next checking round to run aaews.
							Cdbg(MASTIFF_DBG, "SIP is not connected. Restart aaews...6");
							stop_aae();
						}
					}
					g_ddns_name_uploaded = 0; // Reset flag. Consider the situation of private to public.
				}
			}
        }
    } else if (sig == AAE_SIG_CHECK_ACCOUNT_LINKING_STATUS) {
        mastiff_errlog("Got AAE_SIG_CHECK_ACCOUNT_LINKING_STATUS");
    }
}

int aae_login(GetServiceArea *gsa, Login *lg)
{
    int status = -9999;

    char aae_account[ACCOUNT_LEN];
    memset(aae_account, 0, sizeof(aae_account));
    
    char aae_pwd[PWD_LEN] ;
    memset(aae_pwd, 0, sizeof(aae_pwd));
    
//  unsigned char mac_addr[7]={0};
    char mac_str[MAC_LEN];
    memset(mac_str, 0, sizeof(mac_str));

    char dev_desc_buf[ASUS_DEVICE_DESC_LEN];

#if NVRAM
    int get_mac_status = nvram_get_mac_addr(mac_str);
#else
    unsigned char mac_addr[7]={0};
    int get_mac_status = get_mac(mac_addr);
    sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
#endif
    if(get_mac_status<0) 
        goto _GET_STUN_URL_EXIT;
    
    sprintf(aae_account, "%s@asuscomm.com", mac_str);
    //printf("aae_login() >>>>>>>>>>>> aae-account = %s\n", aae_account);
    Cdbg(MASTIFF_DBG, "aae_login() >>>>>>>>>>>> aae-account = %s\n", aae_account);
    srand(time(NULL));
    int rand_value = rand()%100 +2000;
    sprintf(aae_pwd, "%d", rand_value);
    
    status = st_Login(gsa, lg, aae_account, aae_pwd, 
		generate_device_desc(is_private_ip(3) ? 0 : 1, NULL, dev_desc_buf, sizeof(dev_desc_buf)));
    if(status < 0) {
        //printf("aae_login() >>>>>>>>>>>Login web service failed >>>>>>>>>\n");
        Cdbg(MASTIFF_DBG, "aae_login() >>>>>>>>>>>Login web service failed >>>>>>>>>");
#ifdef RTCONFIG_NOTIFICATION_CENTER
        write_login_info(lg->status, "", "", "", "", "");
#endif
        goto _GET_STUN_URL_EXIT;
    }

    Cdbg(MASTIFF_DBG, "aae_login() lg->status=%s", lg->status);
    //TODO Save login info for notification center.
#ifdef RTCONFIG_NOTIFICATION_CENTER
    write_login_info(lg->status, 
    	lg->pnsinfoList ? lg->pnsinfoList->srv_ip : "", 
    	lg->psrinfoList ? lg->psrinfoList->srv_ip : "", 
    	lg->cusid, lg->deviceid, lg->deviceticket);
    write_mac_info(mac_str);
#endif

#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
	if (is_account_bound() && strstr(dev_desc_buf, "\"awsiot_tunnel_support\":\"1\"")) {
		nvram_set_int("aae_awsiot_desc_updated", 1);
		nvram_commit();
	}
#endif
_GET_STUN_URL_EXIT:
    return status;
}

pthread_t kal_tid;

struct _kal_info
{
   int     sec;
   int*    is_terminate;
   int*    is_ddns_name_uploaded;
};
struct _kal_info ki;

void do_aae_keep_alive(void* data)
{
    struct _kal_info* pki = (struct _kal_info* ) data;
    pthread_detach(pthread_self());
    aae_keepalive_loop(pki->sec, pki->is_terminate, pki->is_ddns_name_uploaded);
}

int aae_keepalive_threading(int sec, int* is_terminate, int* is_ddns_name_uploaded)
{
    int status = -1;
    ki.sec          = sec;
    ki.is_terminate = is_terminate;
    ki.is_ddns_name_uploaded = is_ddns_name_uploaded;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
    if(pthread_create(&kal_tid, &attr, (void *) do_aae_keep_alive, &ki ) != 0){
//      assert(0);
        status =  -1;
        pthread_attr_destroy(&attr);
        goto KAL_EXIT;
    }
KAL_EXIT:
    status = 0;
    pthread_attr_destroy(&attr);
    return status;
}

int aae_keepalive_loop(int sec, int* is_terminate, int* is_ddns_name_uploaded)
{
//  if(sec <10 || sec >179)
//     sec = KAL_SEC;
//#define MAX_TIMEOUT_COUNT 24
    int count = 0;
    int count_max = sec/TIMER_SEC;
    //int count_timeout = 0;
    Cdbg(MASTIFF_DBG, "aae_keepalive_loop started.");
    while(!*is_terminate){
        if (!(*is_ddns_name_uploaded)) {
            sleep(TIMER_SEC);
            count = 0;
            //Cdbg(MASTIFF_DBG, "aae_keepalive_loop doesn't work.");
            continue;
        }

        if(count >= count_max){
            int ret = aae_keepalive(&g_getservicearea, &g_login);
            Cdbg(MASTIFF_DBG, "aae_keepalive ret=%d", ret);
            if (ret == 1) { // auth fail. Suicide to relogin and reinitialize ANT SDK.
                Cdbg(MASTIFF_DBG, "aae_keepalive with auth fail.");
                set_device_id_and_keep_login(2);
            } else if (ret == -1) {  // timeout, set interval to 1 hr.
                count_max = 1800;
                //count_timeout++;
                //Cdbg(MASTIFF_DBG, "aae_keepalive timeout. count_timeout=%d", count_timeout);
                if (is_device_ticket_expired(g_login.deviceticketexpiretime)) {
                    Cdbg(MASTIFF_DBG, "timeout and deviceitcket expired.");
                    set_device_id_and_keep_login(3);
                }

            } else if (ret == 0) {  // success, set interval to half of day and reset timeout count
                count_max = sec/TIMER_SEC;
                //count_timeout = 0;
                Cdbg(MASTIFF_DBG, "aae_keepalive success.");
            }
            /*if (count_timeout >= MAX_TIMEOUT_COUNT) {
                Cdbg(MASTIFF_DBG, "timeout exceeds limit times %d.", MAX_TIMEOUT_COUNT);
                kill_all_proc("aaews");
            }*/
            count = 0;
        }
        sleep(TIMER_SEC);
        count++;
		//Cdbg(MASTIFF_DBG, "aae_keepalive_loop works.");
    }
    return 0;
}

int aae_keepalive(GetServiceArea* gsa, Login* lg)
{
    int status;
    Keepalive ka;
    memset(&ka, 0, sizeof(Keepalive));
    status = send_keepalive_req(gsa->servicearea, lg->cusid, lg->deviceid, lg->deviceticket, &ka);
#if NVRAM
    nvram_set_aae_status("keepalive", status, ka.status);
#endif
    // update device ticket expire time to lg
    if (strlen(ka.deviceticketexpiretime)) {
        memset(&lg->deviceticketexpiretime, 0, sizeof(lg->deviceticketexpiretime));
        strcpy(lg->deviceticketexpiretime, ka.deviceticketexpiretime);
    }
    return strlen(ka.status) == 0 ? -1 : atoi(ka.status);
}

int aae_unregister(GetServiceArea* gsa, Login* lg)
{
    int status;
    UnregisterDevice ud; 
    memset(&ud, 0 , sizeof(ud));
    status = send_unregister_device_req(gsa->servicearea, lg->cusid, lg->deviceid, lg->deviceticket, &ud);
    Cdbg(APP_DBG, "send unregister device req");
#if NVRAM
    nvram_set_aae_status("unregister", status, ud.status);
#endif
    return status;
}


int set_device_id(int caller, int keep_login)
{
	int status = -1;
	int random_delay;

	Cdbg(MASTIFF_DBG, "set_device_id_and_keep_login caller(%d).", caller);

	aae_support_check(&is_terminate);
	memset(&g_getservicearea, 0, sizeof(g_getservicearea));
	memset(&g_login, 0, sizeof(g_login));

	// Perform a random deley to avoid DDoS attack for DM server.
	random_delay = get_random_delay(nvram_get_int(NVRAM_RETRY_COUNT), RETRY_DELAY_BASE_SECONDS, MAX_RETRY_DELAY_DELAYED_SECONDS);
	Cdbg(MASTIFF_DBG, "login random_delay=[%d]", random_delay);
	sleep(random_delay);

#if 1
	status = aae_login(&g_getservicearea, &g_login);
	if (status < 0) {
		int retry_cnt = nvram_get_int(NVRAM_RETRY_COUNT);
		Cdbg(MASTIFF_DBG, "set_device_id_and_keep_login aae_login failed.");
		g_need_to_retry_aae = 1;

		// Fail to login ,increase retry count until it is greater than RETRY_MAX_TIMES.
		if (retry_cnt < RETRY_MAX_TIMES)
			nvram_set_int(NVRAM_RETRY_COUNT, ++retry_cnt);

		goto _GET_STUN_URL_EXIT1;
	}

	// If device_id is already set and with same value. Skip the phase.
	if(g_login.deviceid != NULL && ( strcmp(g_login.deviceid,"") ) ) {
		if (!nvram_set_aae_info(g_login.deviceid)) {
			status = 0;
			g_have_device_id = 1;
		}
	}

	/*// If device_id is already set. Skip the phase.
	if (g_have_device_id == 0) {
		if(g_login.deviceid != NULL && ( strcmp(g_login.deviceid,"") ) ) {
			nvram_save_value("aae_deviceid", g_login.deviceid);
			status = 0;
			g_have_device_id = 1;
		}
	}*/
#else
			g_have_device_id = 1;
#endif
	if (keep_login)
		g_ddns_name_uploaded = 1; // If this flag is set the keepalive thread will run.
	g_need_to_retry_aae = 0;
	nvram_set_int(NVRAM_RETRY_COUNT, 0);

	// For notification center we should keep the login session.
	/*if (st_Logout(&gsa, &lg))
	    printf("set_device_id_and_keep_login() >>>>>>>>>>>Logout web service failed >>>>>>>>>\n");*/

_GET_STUN_URL_EXIT1:
	Cdbg(MASTIFF_DBG, "set_device_id_and_keep_login exit.");
	return status;
}

int set_device_id_and_keep_login(int caller)
{
	return set_device_id(caller, 1);
}

int do_unregister(void)
{
    int status = -1;
    memset(&g_getservicearea, 0, sizeof(g_getservicearea));
    
    memset(&g_login, 0, sizeof(g_login));

    status = aae_login(&g_getservicearea, &g_login);
    if (status < 0) {
        Cdbg(MASTIFF_DBG, "set_device_id_and_keep_login aae_login failed.");
        if (status == -2) // timeout
            g_need_to_retry_unreg = 1;
        goto _GET_STUN_URL_EXIT2;
    }

    // Dean : Update Proflie for ddns/https_port/http_port
    status = aae_unregister(&g_getservicearea, &g_login);
    if (status != 0) {
        Cdbg(MASTIFF_DBG, "set_device_id_and_keep_login aae_unregister failed.");
        g_need_to_retry_unreg = 1;
        goto _GET_STUN_URL_EXIT2;
    }

    g_need_to_retry_unreg = 0;
	nvram_save_value("aae_deviceid", "");

    // For notification center we should keep the login session.
    /*if (st_Logout(&gsa, &lg))
        printf("set_device_id_and_keep_login() >>>>>>>>>>>Logout web service failed >>>>>>>>>\n");*/

_GET_STUN_URL_EXIT2:
    return status;
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
	while (pids(LAUNCHED_PROC) && wait_count < WAIT_TIME) {
		sleep(1);
        Cdbg(MASTIFF_DBG, "Wait %s stopping.", LAUNCHED_PROC);
        wait_count++;
	}

	// kill with -9 forcely if any.
	pidList = find_pid_by_name(appname);
    for (pl = pidList; *pl; pl++) {
		sprintf(cmd, "kill -9 %d", *pl);
		//fprintf(stderr, "kill %s %d", LAUNCHED_PROC, *pl);
		system(cmd);
	}
    return 0;
}

int is_vpnc(void)
{
#ifdef RTCONFIG_VPNC
	if (nvram_invmatch("vpnc_proto", "disable"))
		return 1;
	else
#ifdef RTCONFIG_VPN_FUSION
	if (nvram_invmatch("vpnc_default_wan", "0")) {
		char tmp[100];
		char prefix[12];
		snprintf(prefix, sizeof(prefix), "vpnc%d_", nvram_get_int("vpnc_default_wan"));
		if (nvram_get_int(strlcat_r(prefix, "state_t", tmp, sizeof(tmp))) == WAN_STATE_CONNECTED)
			return 1;
		else
			return 0;
	} else
#endif
#endif
		return 0;
}

int is_dual_wan(void)
{
    const char* var = nvram_safe_get("wans_dualwan");
    if (var) {
        if (strlen(var) == 0 || strstr(var, "none"))
            return is_vpnc();
        else
            return 1;
    } else
        return is_vpnc();
}

int sw_mode_check(void)
{
	int sw_mode = sw_mode();

	if(sw_mode==SW_MODE_REPEATER||sw_mode==SW_MODE_AP||sw_mode==SW_MODE_HOTSPOT)
		return 1;

	return 0;
}

void start_aae_sdk_init( void )
{
#define WAIT_TIMEOUT 5
	int time_count = 0;
	if (pids("aaews")) {
		nvram_set_int("aae_action", AAEWS_ACTION_SDK_INIT);
		killall("aaews", AAEWS_SIG_ACTION);
		while(time_count < WAIT_TIMEOUT && nvram_invmatch("aae_sip_connected", "1")) {
			sleep(1);
			_dprintf("%s: wait sip register...\n", __FUNCTION__);
			time_count++;
		}
	}
}

void run_aae( void )
{
	char cmd[128] = {0};

	// Perform a random deley to avoid DDoS attack to DM server.
	int retry_cnt = nvram_get_int(NVRAM_RETRY_COUNT);
	int random_delay = get_random_delay(retry_cnt, RETRY_DELAY_BASE_SECONDS, MAX_RETRY_DELAY_DELAYED_SECONDS);
	Cdbg(MASTIFF_DBG, "login random_delay=[%d]", random_delay);
	sleep(random_delay);

	g_ddns_name_uploaded = 0;
	//nvram_set_int("aae_enable", (nvram_get_int("aae_enable") | 1));
	sprintf( cmd , "%s --sdk_log_dir=/tmp &",LAUNCHED_PROC );
	system( cmd );
}


void stop_aae( void )
{
	//mastiff_errlog("stop aae");
	nvram_set_int("aae_enable", (nvram_get_int("aae_enable") & ~1));
    nvram_set_aae_sip_connected("0");
	kill_all_proc(LAUNCHED_PROC);
	return;
}

void start_sip_conn()
{
	int time_count = 0;
	if ((nvram_get_int("aae_sip_connected") == 0) && pids(LAUNCHED_PROC)) {
		nvram_set_int("aae_action", AAEWS_ACTION_SIP_REGISTER);
		killall(LAUNCHED_PROC, AAEWS_SIG_ACTION);
	}
}

void stop_sip_conn()
{
	int time_count = 0;
	if ((nvram_get_int("aae_sip_connected") == 1) && pids(LAUNCHED_PROC)) {
		nvram_set_int("aae_action", AAEWS_ACTION_SIP_UNREGISTER);
		killall(LAUNCHED_PROC, AAEWS_SIG_ACTION);
	}
}

#ifdef MASTIFF_EN
int aae_action( struct nlmsghdr *nlh ,char *ip_stable_flag)
{
	int len,rtl;
	struct ifaddrmsg *ifa;
	struct rtattr *rth;
	
	for (;(NLMSG_OK (nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len))
	{
		if (nlh->nlmsg_type != RTM_NEWADDR && nlh->nlmsg_type != RTM_DELADDR)
			continue;

		ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);

		rth = IFA_RTA (ifa);
		rtl = IFA_PAYLOAD (nlh);
		for (;rtl && RTA_OK (rth, rtl); rth = RTA_NEXT (rth,rtl))
		{
			//char name[IFNAMSIZ];
			uint32_t ipaddr;
			if (rth->rta_type != IFA_LOCAL)
				continue;

			ipaddr = * ((uint32_t *)RTA_DATA(rth));
			ipaddr = htonl(ipaddr);

			//fprintf (stdout,"%s is now %X\n",if_indextoname(ifa->ifa_index,name),ipaddr);
			//printf(if_indextoname(ifa->ifa_index,name));
			if (nlh->nlmsg_type == RTM_NEWADDR) {
				//printf("RTM_NEWADDR");

                //ip_stable_check(ip_stable_flag);
                *ip_stable_flag = -1;
                break;
/*
				if ( is_private_ip(4) )
				{
                    if ( !pids(LAUNCHED_PROC) ){
					   stop_aae();
					   run_aae();
                    }
					break;
				} else { 
                    if ( pids(LAUNCHED_PROC) )
					   stop_aae();
					break;
				} 
*/                
			} else {
				//printf("RTM_DELADDR %s %s\n",if_indextoname(ifa->ifa_index,name),name);
				/* check interface primary, if no, do nothing */
				//if( check_interface(if_indextoname(ifa->ifa_index,name)) )
				//{
				/* if yes, (re)start aaews  */
				//}
				/* if yes, check 
				1. dual wan? 
				2. dual wan mode? 
				3. second interface active?
				4. kill aaews.(depend on result of 1,2,3 ) 
				*/
			}

		}
	}
	return 0;
}
#endif

void message_handler(void)
{
    
    fd_set  fds;
    int maxfd = 0,from_len=0;
    struct timeval timeout;
    char buf[128]={0};
    char xbuf[32]={0};
    int len = 0;
    unsigned short tmp_port;
    int sfd=0;
    struct sockaddr_in loacl_addr;
    const int on = 1;
    int status_old=-1,seg_fault_count=0,abort_count=0;
    int status_count=0;
    tmp_port = MASTIFF_DEF_PORT;

    pthread_detach(pthread_self());

    sfd=socket(AF_INET,SOCK_DGRAM,0);
    if( sfd == 0 ){
        mastiff_errlog("Create socket error");
        return ;
    }

    bzero(&loacl_addr,sizeof(loacl_addr));
    loacl_addr.sin_family = AF_INET;
    loacl_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    loacl_addr.sin_port=htons(tmp_port);
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if( bind( sfd,(struct sockaddr *)&loacl_addr,sizeof(loacl_addr) ) )
    {
        mastiff_errlog("Bind socket error");
        close(sfd);
        return ;
    }
    
    while( !is_terminate ) {
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(sfd,&fds);
        maxfd = sfd+1;
#if 1
        switch( select(maxfd,&fds,NULL,NULL,&timeout) )
        {
            case -1:
                mastiff_errlog("Select error");
            break;

            case 0:
            break;

            default:
                //printf("[aaews]thread_control_message_handler\n");
                if( FD_ISSET(sfd,&fds) )
                {
                    struct sockaddr_in from;
                    int tmp_i32=0;
                    memset(&from,0,sizeof(from));
                    memset(buf,0,sizeof(buf));
                    memset(xbuf,0,sizeof(xbuf));
                    if(  (len = recvfrom (sfd,buf,128,0, (struct sockaddr *)&from,&from_len) ) <= 0 ) {
                        fprintf(stderr,"[mastiff]Receive error\n");
                        break;
                    } else {
                        /* aaews:resp */
                        if( len < 6 || strncmp( buf, "aaews:", 6 ))
                        {
                            fprintf(stderr,"[mastiff]Receive an unexpectd request[%s]\n",buf);
                            break;
                        }

            			if (nvram_get_int("debug_mastiff")) {
            				//printf("[mastiff][%s]\n",buf);
            				tmp_i32 = atoi(buf+6);
            				//printf("[mastiff][%d]\n",tmp_i32);
            			}

                        if( tmp_i32 == 0 || tmp_i32 == 200 ){
                            status_count = 0;
                            status_old = tmp_i32;
                        } else if ( tmp_i32 == SEGMENTATION_FAULT ) {
                            if( (seg_fault_count%10) == 0 )
                            {
                                if(!seg_fault_count)
                                    sprintf(xbuf,"aae ret %d",SEGMENTATION_FAULT);
                                else    
                                    sprintf(xbuf,"aae ret %d[%d]",SEGMENTATION_FAULT,seg_fault_count);
                                mastiff_errlog(xbuf); 
                            }   
                            seg_fault_count++;

                        } else if ( tmp_i32 == SIGABRT_GET ) {
                            if( (abort_count%10) == 0 )
                            {
                                if(!abort_count)
                                    sprintf(xbuf,"aae ret %d",SIGABRT_GET);
                                else    
                                    sprintf(xbuf,"aae ret %d[%d]",SIGABRT_GET,abort_count);
                                mastiff_errlog(xbuf); 
                            }   
                            abort_count++;

                        } else if(tmp_i32 != status_old) {
                            status_count = 0;
                            status_old = tmp_i32;

                            sprintf(xbuf,"aae ret %d",status_old);
                            mastiff_errlog(xbuf); 
                        } else {
                            if( status_count <= 1024 )
                                status_count++;
                            if( (status_count == 1024) )
                            {
                                sprintf(xbuf,"aae ret %d[%d]",status_old,status_count);
                                mastiff_errlog(xbuf); 
                            }
                        }
                    }
                }
            break;
        }
#endif
    }
}

int create_thread_message_handler(void) {
    
    pthread_attr_t attr;

    pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
    if ( pthread_create(&thread_control_message, &attr, (void *) message_handler, NULL) !=0) 
    {
        mastiff_errlog("Create thread error");
        pthread_attr_destroy(&attr);
        return -1;      
    }
    pthread_attr_destroy(&attr);
    return 0;
}

int main(int argc, char **argv)
{
	sigset_t sigs_to_catch;
	//int debug_mode = 0;
    char cmd_save_pid[40];
#ifdef MASTIFF_EN	
	struct sockaddr_nl addr;
	int nls=0,maxfd=0,len=0;
	char buffer[4096];
	struct nlmsghdr *nlh;
	//int aaews_status=AAEWS_STATUS_INIT;
	struct timeval timeout;
	fd_set fds;
#endif

    CF_OPEN(MASTIFF_LOG_PATH, SYSLOG_TYPE | FILE_TYPE | CONSOLE_TYPE | STDOUT_TYPE);
    nvram_set_int(NVRAM_RETRY_COUNT, 0);





#ifdef SW_HW_AUTH

#define APP_ID    "14354641"
#define APP_KEY   "mg8rla5fj94kq0kcm2z"
#define AUTN_MAX_RETRY 6
    // ===================== sw-hw-auth check start =====================
    time_t timestamp = time(NULL);
    char in_buf[128];
    char out_buf[65];
    char hw_out_buf[65];
    char *hw_auth_code = NULL;
    int auth_retry_cnt = 0;

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

    while(1) {
		if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
			//mastiff_errlog("This is ASUS Router");
			break;
		}
		else {
			//mastiff_errlog("This is not ASUS Router");
			if (auth_retry_cnt >= AUTN_MAX_RETRY) {
				sigemptyset(&sigs_to_catch);
				sigaddset(&sigs_to_catch, SIGTERM);
				sigaddset(&sigs_to_catch, SIGINT);
				sigaddset(&sigs_to_catch, SIGABRT);
				sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

				/* Set signal handler */
				signal(SIGTERM, sigaction_handler); 
				signal(SIGINT, sigaction_handler); 
				signal(SIGABRT, sigaction_handler); 
				mastiff_errlog("exit.");
				while( !is_terminate )  {
					sleep(10);
				}
				return 0;
			} else
				auth_retry_cnt++;
		}
		sleep(10);
	};
    // ===================== sw-hw-auth check end =====================
#endif


// start awsiot ipc
#ifdef RTCONFIG_AWSIOT
	Cdbg(MASTIFF_DBG, "ipc start");
    ipc_start();
#endif


    int netlink_timeout_counter=0;
	char ip_stable_flag=-1;

    g_pid = getpid();
    snprintf(cmd_save_pid, sizeof(cmd_save_pid), "echo %d > %s", g_pid, MASTIFF_PID_PATH);
    system(cmd_save_pid);

    mastiff_errlog("init");

    // read eula flag
    g_asus_eula_flag = nvram_get_int(ASUS_EULA_FLAG_NANE);
    g_has_ddns_name = (strlen(nvram_safe_get(DDNS_HOSTNAME)) != 0);
    Cdbg(MASTIFF_DBG, "%d %d", g_asus_eula_flag, g_has_ddns_name);

	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigaddset(&sigs_to_catch, SIGINT);
	sigaddset(&sigs_to_catch, SIGABRT);
	sigaddset(&sigs_to_catch, SIGCHLD);
	sigaddset(&sigs_to_catch, AAE_SIG_REMOTE_CONNECTION_TURNED_ON);
	sigaddset(&sigs_to_catch, AAE_SIG_EULA_FLAG_SIGNED);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

    /* Set signal handler */
	signal(SIGTERM, sigaction_handler); 
    signal(SIGINT, sigaction_handler); 
    signal(SIGABRT, sigaction_handler); 
    signal(AAE_SIG_REMOTE_CONNECTION_TURNED_ON, sigaction_handler); 
    signal(AAE_SIG_EULA_FLAG_SIGNED, sigaction_handler);
	signal(SIGCHLD, chld_reap);
    //signal(AAE_SIG_CHECK_ACCOUNT_LINKING_STATUS, sigaction_handler); 
	
	/*if(argc >1) {
		//printf("argc = %d, arg1 = %s\n", argc, argv[1]);
		
		if(!strcmp(argv[1],"--debug"))
			debug_mode = 1;
	}*/

#ifdef MASTIFF_EN
	if ((nls = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1){
		mastiff_errlog("netlink socket create failure");
		return -1;
	}

	memset (&addr,0,sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV4_IFADDR;

	if (bind(nls, (struct sockaddr *)&addr, sizeof(addr)) == -1){
		close(nls);
		mastiff_errlog("bind failure");
		return -1;
	}

	nlh = (struct nlmsghdr *)buffer;
#endif
	//mastiff_errlog("enter loop");

    const char* rd_devid = nvram_get("aae_deviceid");
    if(rd_devid != NULL && ( strcmp(rd_devid,"") ) )
        g_have_device_id = 1;

    create_thread_message_handler();
    aae_keepalive_threading(KAL_TIME, &is_terminate, &g_ddns_name_uploaded);

	aae_support_check(&is_terminate);
	while( !is_terminate )  {
#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
		// If account binding is ready, don't check status of aaews.
		// But we should get device id from DM server by login.
		if (is_account_bound()) {
			if (g_asus_eula_flag && internet_ready() == 1) {
				/*if (g_have_device_id == 0 || g_need_to_retry_aae)
					set_device_id(8, 0);*/

				// run aaews always if it is not running.
				if (!is_mesh_re_mode()) {
					if( !pids(LAUNCHED_PROC)){
						// checking awsiot trigger mode and whether aaews is ready.
						if (g_is_in_awsiot_trigger_mode
#ifdef RTCONFIG_IG_SITE2SITE
							|| vpns_use_tunnel()
#endif
						) {
							nvram_set_int("aae_disable_fast_init", 1);
						}
						Cdbg(MASTIFF_DBG, "aae is not running,run aae now...7");
						run_aae();
					} else {
						if (g_is_in_awsiot_trigger_mode
#ifdef RTCONFIG_IG_SITE2SITE
							|| vpns_use_tunnel()
#endif
						) {
							if(is_sip_connection_alive())
								g_is_in_awsiot_trigger_mode = 0;
							else {
								// notify aaews to re-reg

								//system("killall -9 aaews");
								//system("aaews --sdk_log_dir=/tmp &");
								Cdbg(MASTIFF_DBG, "SIP is not connected. start sip connect...1");
								start_sip_conn();
							}
						}
					}
				} // if (!is_mesh_re_mode())

				if (nvram_get_int("aws_ca_download_status")==0 ||
					nvram_get_int("aae_awsiot_desc_updated")==0) {
					if (nvram_get_int("aws_ca_download_status")==0)
						Cdbg(MASTIFF_DBG, "The AWS IoT CA file has not been downloaded yet, call login to get CA files again.");
					if (nvram_get_int("aae_awsiot_desc_updated")==0)
						Cdbg(MASTIFF_DBG, "The device description awsiot_tunnel_support has not been udpated, call login again.");
					aae_login(&g_getservicearea, &g_login);
				}
			}

			sleep(MAIN_THREAD_SLEEP_5_SEC);
			continue;
		} else
#endif
		{
#ifdef MASTIFF_EN
		timeout.tv_sec = 2;
		timeout.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(nls,&fds);
		maxfd = nls+1;
        //sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);
		switch( select(maxfd,&fds,NULL,NULL,&timeout) )
		{
			case -1:
				Cdbg(MASTIFF_DBG, "select error");
			break;

			case 0:
				//Cdbg(MASTIFF_DBG, "[mastiff]receive a 0 message");
                if( ip_stable_flag ) {
					//Cdbg(MASTIFF_DBG, "ip_stable_check remain unstable");
                    netlink_timeout_counter = 0;
                    ip_stable_check( &ip_stable_flag );
                    if(ip_stable_flag == 0)
                    {
                        /* check wan mode , dual wan always runs aaews*/
                        if( (is_dual_wan() || sw_mode_check() || is_private_ip(5)) && !is_mesh_re_mode())
                        {
                            if (!g_asus_eula_flag && !g_has_ddns_name)
                                continue;

			                if (g_asus_eula_flag == 0) {
			                    if( pids(LAUNCHED_PROC) ){
			                        //printf("aae is running,stop aae now\n");
			                        Cdbg(MASTIFF_DBG, "aae is running,stop aae now...1");
			                        stop_aae();
			                    }
			                } else {
					            if( !pids(LAUNCHED_PROC) && !is_mesh_re_mode()){
					                // printf("aae is not running,run aae now\n");
					                Cdbg(MASTIFF_DBG, "aae is not running,run aae now...1");
					                run_aae();
				                } else if (!is_sdk_inited()) { // If SDK is not inited, init it.
				                    Cdbg(MASTIFF_DBG, "SDK is not inited. reinit sdk...1");
				                    start_aae_sdk_init();
								} else if (!is_sip_connection_alive()) { // If SIP is not connected, stop aaews. Let next checking round to run aaews.
				                    Cdbg(MASTIFF_DBG, "SIP is not connected. Restart aaews...1");
				                    stop_aae();
				                }
			                }
                        } else {
                            if( pids(LAUNCHED_PROC) ){
                                //printf("aae is running,stop aae now\n");
                                Cdbg(MASTIFF_DBG, "aae is running,stop aae now...2");
                                stop_aae();
                            }
                        }
                    }
                } else {
					//Cdbg(MASTIFF_DBG, "ip_stable_check remain stable");
                    if( netlink_timeout_counter < 5 ) //10s
                        netlink_timeout_counter++;
                    else {
                        netlink_timeout_counter = 0;

                        #if 0
                        Cdbg(MASTIFF_DBG, "is_dual_wan=%d", is_dual_wan());
                        Cdbg(MASTIFF_DBG, "sw_mode_check=%d", sw_mode_check());
                        Cdbg(MASTIFF_DBG, "is_private_ip=%d", is_private_ip(6));
                        Cdbg(MASTIFF_DBG, "is_mesh_re_mode=%d", is_mesh_re_mode());
                        Cdbg(MASTIFF_DBG, "g_have_device_id=%d", g_have_device_id);
                        Cdbg(MASTIFF_DBG, "g_ddns_name_uploaded=%d", g_ddns_name_uploaded);
                        Cdbg(MASTIFF_DBG, "g_need_to_retry_aae=%d", g_need_to_retry_aae);
                        #endif
                        if( (is_dual_wan() || sw_mode_check() || is_private_ip(7)) && !is_mesh_re_mode())
                        {
                            if (!g_asus_eula_flag && !g_has_ddns_name)
                                continue;

			                if (g_asus_eula_flag == 0) {
			                    if( pids(LAUNCHED_PROC) ){
			                        //printf("aae is running,stop aae now\n");
			                        Cdbg(MASTIFF_DBG, "aae is running,stop aae now...3");
			                        stop_aae();
			                    }
			                } else {
					            if( !pids(LAUNCHED_PROC) && !is_mesh_re_mode()){
					                // printf("aae is not running,run aae now\n");
					                Cdbg(MASTIFF_DBG, "aae is not running,run aae now...2");
					                run_aae();
				                } else if (!is_sdk_inited()) { // If SDK is not inited, init it.
				                    Cdbg(MASTIFF_DBG, "SDK is not inited. reinit sdk...2");
				                    start_aae_sdk_init();
								} else if (!is_sip_connection_alive()) { // If SIP is not connected, stop aaews. Let next checking round to run aaews.
				                    Cdbg(MASTIFF_DBG, "SIP is not connected. Restart aaews...2");
				                    stop_aae();
				                }
			                }
                            g_ddns_name_uploaded = 0; // Reset flag. Consider the situation of private to public.
                        } else {
                            if( pids(LAUNCHED_PROC) ){
                                //printf("aae is running,stop aae now\n");
                                Cdbg(MASTIFF_DBG, "aae is running,stop aae now...4");
                                stop_aae();
                                if (g_asus_eula_flag)
                                    set_device_id_and_keep_login(4);
                            }

                            if (g_asus_eula_flag && 
                                (g_have_device_id == 0 || g_ddns_name_uploaded == 0 || g_need_to_retry_aae || check_wan_ip_change())) {
                                set_device_id_and_keep_login(5);
                            }
                        }
                    }
                }
			break;

			default:
				//Cdbg(MASTIFF_DBG, "[mastiff]receive a default message");

				if( FD_ISSET(nls,&fds) )
				{
					memset(buffer,0,sizeof(buffer));

					if(  (len = recv (nls,nlh,4096,0) ) <= 0 ) {
						mastiff_errlog("recv unsepected result");
						break;
					}

					/* check wan mode , dual wan always runs aaews*/
					if( internet_ready()  == 1 && (is_dual_wan() || sw_mode_check()) && !is_mesh_re_mode())
					{                           
                        if ((!g_asus_eula_flag && !g_has_ddns_name) || is_mesh_re_mode())
                            continue;

		                if (g_asus_eula_flag == 0) {
		                    if( pids(LAUNCHED_PROC) ){
		                        //printf("aae is running,stop aae now\n");
		                        Cdbg(MASTIFF_DBG, "aae is running,stop aae now...5");
		                        stop_aae();
		                    }
		                } else {
				            if( !pids(LAUNCHED_PROC) && !is_mesh_re_mode()){
				                // printf("aae is not running,run aae now\n");
				                Cdbg(MASTIFF_DBG, "aae is not running,run aae now...3");
				                run_aae();
			                } else if (!is_sdk_inited()) { // If SDK is not inited, init it.
			                    Cdbg(MASTIFF_DBG, "SDK is not inited. reinit sdk...3");
			                    start_aae_sdk_init();
							} else if (!is_sip_connection_alive()) { // If SIP is not connected, stop aaews. Let next checking round to run aaews.
			                    Cdbg(MASTIFF_DBG, "SIP is not connected. Restart aaews...3");
			                    stop_aae();
			                }
		                }
						break;
					}
					if ( aae_action( nlh , &ip_stable_flag ) ) {
						mastiff_errlog("aae action error");
						break;
					}
				}
				sleep(1);
			break;
		}
#else
		/* check wan mode , dual wan always runs aaews*/
		
		//system("free");
		if( (is_dual_wan() || sw_mode_check() || is_private_ip(8)) && !is_mesh_re_mode())
		{
            if (!g_asus_eula_flag && !g_has_ddns_name)
                continue;

            if (g_asus_eula_flag == 0) {
                if( pids(LAUNCHED_PROC) ){
                    //printf("aae is running,stop aae now\n");
                    Cdbg(MASTIFF_DBG, "aae is running,stop aae now...6");
                    stop_aae();
                }
            } else {
	            if( !pids(LAUNCHED_PROC) && !is_mesh_re_mode()){
	                // printf("aae is not running,run aae now\n");
	                Cdbg(MASTIFF_DBG, "aae is not running,run aae now...4");
	                run_aae();
                } else if (!is_sdk_inited()) { // If SDK is not inited, init it.
                    Cdbg(MASTIFF_DBG, "SDK is not inited. reinit sdk...4");
                    start_aae_sdk_init();
				} else if (!is_sip_connection_alive()) { // If SIP is not connected, stop aaews. Let next checking round to run aaews.
                    Cdbg(MASTIFF_DBG, "SIP is not connected. Restart aaews...4");
                    stop_aae();
                }
            }
            g_ddns_name_uploaded = 0; // Reset flag. Consider the situation of private to public.
			
		} else {
			
			if( pids(LAUNCHED_PROC) ){
				//printf("aae is running,stop aae now\n");
                Cdbg(MASTIFF_DBG, "aae is running,stop aae now...7);
				stop_aae();

                if (g_asus_eula_flag)
                    set_device_id_and_keep_login(6);
			}

            if (g_asus_eula_flag && 
                (g_have_device_id == 0 || g_ddns_name_uploaded == 0 || g_need_to_retry_aae || check_wan_ip_change()))
                set_device_id_and_keep_login(7);
			
		}

		sleep(MAIN_THREAD_SLEEP_10_SEC);
#endif		
		}
	}
#ifdef MASTIFF_EN	
    close(nls);
#endif    
    CF_CLOSE();
	return 0;
}

 
