#include <log.h>
#include <nw_util.h>
#include <nat_nvram.h>
#include <ws_caller.h>
#include <stdio.h>
#include <openssl/md5.h>
#include <ssl_api.h>
#include <errno.h>
#include <pthread.h>
#include "common.h"
#include "wb.h"
#include "time_util.h"	// is_device_ticket_expired() in wb/ws_src/time_util.h

/* tunnel_proc.c */
int kill_all_proc(const char* appname);

#define MAC_MAX_LEN		18
 
GetServiceArea* g_gsa;
Login* g_lg;
pthread_t kal_tid;
extern int kill_all_proc(const char* appname);

struct _kal_info
{																																						
	int		sec;
	int*	is_terminate;
};
struct _kal_info ki;

void* do_keep_alive(void* data)
{
	struct _kal_info* pki = (struct _kal_info* ) data;
	st_KeepAlive_loop(pki->sec, pki->is_terminate);
	pthread_exit("TERMINATE");
//	return NULL;
}

int st_KeepAlive_threading(int sec, int* is_terminate)
{
	int status = -1;
	ki.sec			= sec;
	ki.is_terminate = is_terminate;	
    pthread_attr_t attr;

	pthread_attr_init(&attr);
#ifdef PTHREAD_STACK_SIZE
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
	if((status = pthread_create(&kal_tid, &attr, do_keep_alive, &ki ))){
//		assert(0);
		status =  -1;
		pthread_attr_destroy(&attr);
		goto KAL_EXIT;	
	}
KAL_EXIT:
	status = 0;
	pthread_attr_destroy(&attr);
	return status;
}

int st_KeepAlive_loop(int sec, int* is_terminate)
{
//	if(sec <10 || sec >179)
//	   sec = KAL_SEC;
//#define MAX_TIMEOUT_COUNT 24
	int count = 0;
	int count_max = sec/TIMER_SEC;
	//int count_timeout = 0;
	while(!*is_terminate){
		if(count >= count_max){
            int ret = st_KeepAlive(g_gsa, g_lg);
            Cdbg(APP_DBG, "st_KeepAlive ret=%d", ret);
            if (ret == 1) { // auth fail. Suicide to relogin and reinitialize ANT SDK.
                Cdbg(APP_DBG, "st_KeepAlive with auth fail.");
                kill_all_proc("aaews");
            } else if (ret == -1) {  // timeout, set interval to 1 hr.
            	count_max = 1800;
            	//count_timeout++;
                //Cdbg(APP_DBG, "st_KeepAlive timeout. count_timeout=%d", count_timeout);
                if (is_device_ticket_expired(g_lg->deviceticketexpiretime)) {
                	Cdbg(APP_DBG, "timeout and deviceitcket expired.");
                	kill_all_proc("aaews");
                }

            } else if (ret == 0) {  // success, set interval to half of day and reset timeout count
            	count_max = sec/TIMER_SEC;
            	//count_timeout = 0;
                Cdbg(APP_DBG, "st_KeepAlive success.");
            }
            /*if (count_timeout >= MAX_TIMEOUT_COUNT) {
                Cdbg(APP_DBG, "timeout exceeds limit times %d.", MAX_TIMEOUT_COUNT);
                kill_all_proc("aaews");
            }*/
			count = 0;
		}
		sleep(TIMER_SEC);			
		count++;
	}	   
	return 0;
}

int st_KeepAlive_thread_exit()
{
	int err = -1;
	Cdbg(APP_DBG, "Wait KAL thread exit .........");
	void* ret =NULL;
	if ( (err = pthread_join(kal_tid, &ret)) != 0) {
		Cdbg(APP_DBG, "Keep Alive thread join failed with =%d", errno);
	}
	Cdbg(APP_DBG, "KAL thread exit with %s", ret);
	return err; 
}

int st_KeepAlive(GetServiceArea* gsa, Login* lg)
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


#define NAT_DESC_LEN 	128
#define DEVICE_DES_LEN 	128 
int st_UpdateProfile(const char* update_status, int nat_type, char* mac_addr, GetServiceArea* gsa, Login* lg)
{
	return st_UpdateProfile2(update_status, nat_type, mac_addr, gsa, lg, NULL);
}

int st_UpdateProfile2(const char* update_status, int nat_type, char* mac_addr, GetServiceArea* gsa, Login* lg, char *dev_desc)
{
	int status;
	UpdateProfile up;
	char fwver[128];
	memset(&up, 0, sizeof(up));
	snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
//	sprintf(devicenat_content,"\"public-ip\":\"%s\",\"macaddr\":\"%s\"",public_ip, mac_addr);
	DECLARE_CLEAR_MEM(char, devicenat_content, NAT_DESC_LEN);
	sprintf(devicenat_content, NAT_JSON,nat_type);
	Cdbg(APP_DBG,"devicenat =%s, length =%d\n", devicenat_content, strlen(devicenat_content));
		
	char* permission	= PERMISSION; 
#if GEMTEK
	char* device_name 	= GEMTEK_DEVICE_NAME;
	char* device_service 	= GEMTEK_DEVICE_SERVICE;
	char* device_desc	= GEMTEK_DEVICE_DESC;
#else
	char* device_name	= ASUS_DEVICE_NAME;
	char* device_service	= ASUS_DEVICE_SERVICE;
	DECLARE_CLEAR_MEM(char, device_desc, ASUS_DEVICE_DESC_LEN);

	sprintf(device_desc, "%s", dev_desc ? dev_desc : ""); // TODO use snprintf
	Cdbg(APP_DBG, "Update profile devdesc =%s", device_desc);
#endif
#if defined(RTCONFIG_NOTIFICATION_CENTER) && (defined(RTCONFIG_IFTTT) || defined(RTCONFIG_ALEXA))
	IFTTT_DEBUG("device_desc=%s\n", device_desc);
#endif
	status = send_update_profile_req(gsa->servicearea, lg->cusid, lg->deviceid, lg->deviceticket,  		
				device_name, device_service, update_status, permission, devicenat_content, device_desc, &up); 
    Cdbg(APP_DBG,"send_update_profile_req return status =%s \n",up.status);
#if NVRAM
	nvram_set_aae_status("updateprofile", status, up.status);
#endif
	return 0;
}

int st_ListProfile( GetServiceArea* gsa, Login* lg, ListProfile* lp, pProfile* pP  )
{
	int status;
	memset(lp, 0, sizeof(ListProfile));
	status = send_list_profile_req(gsa->servicearea, lg->cusid, lg->userticket, lg->deviceticket, "", lg->deviceid, lp);
    Cdbg(APP_DBG,"send_list_profile_req return status =%s \n",lp->status); 
    if (strcmp(lp->status, "1") == 0) { // auth fail. Suicide to relogin and reinitialize ANT SDK.
        Cdbg(APP_DBG, "send_list_profile_req with auth fail.");
        kill_all_proc("aaews");
    }
	*pP = lp->pProfileList;
#if NVRAM
	nvram_set_aae_status("listprofile", status, lp->status);
#endif
	return status;
}

int st_Logout(GetServiceArea* gsa, Login* lg)
{
	int status;
	Logout lgo; memset(&lgo, 0 , sizeof(lgo));
	status = send_logout_req(gsa->servicearea, lg->cusid, lg->deviceid, lg->deviceticket, &lgo);
	Cdbg(APP_DBG, "send logout req");
#if NVRAM
	nvram_set_aae_status("logout", status, lgo.status);
#endif
	return status;
}

int st_Login(GetServiceArea* gsa, Login* lg, char* vip_id, char* vip_pwd, char* dev_desc)
{
	int				status =-1;
	char *area;
	char fwver[128];
	char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
	snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
	memset(gsa, 0, sizeof(GetServiceArea));

	area = nvram_safe_get("aae_area");
	if (!strlen(area)) {  // If area is empty, write a default login server 
		area = LOGIN_SERVER;
		nvram_set("aae_area", area);
		nvram_commit();
		snprintf(gsa->servicearea, sizeof(gsa->servicearea), "%s", area);
	} else if (!strcmp(area, "unsupported_area")) {  // If area is "unspported_area", request it from DM server.
		char *aae_portal = nvram_safe_get("aae_portal");
		status = send_getservicearea_req(
			strlen(aae_portal) ? aae_portal : SERVER,
			ASUS_DEVICE_SERVICE,
			vip_id,
			vip_pwd,
			DEVICE_TYPE,
			fwver,
			AIHOME_API_LEVEL,
			model_name,
			gsa);	
	#if NVRAM
		nvram_set_aae_status("getservicearea", status, gsa->status);
	#endif
	#if 0
		if (nvram_get_int("aae_dbg")) {
			snprintf(gsa->status, sizeof(gsa->status), "%s", nvram_safe_get("aae_dbg_ga_status2"));
			snprintf(gsa->retrytime, sizeof(gsa->retrytime), "%s", nvram_safe_get("aae_dbg_retrytime"));
			status = nvram_get_int("aae_dbg_ga_status1");
		}
	#endif

		if (status != 0) { // Not 200 OK, retry after 3600 seconds.
			Cdbg(APP_DBG, "Get Service Area failed status value=%d, retry after 3600 seconds.", status);
			sleep(3600); // retry after 1 hour.
			return -1;
		}

		if (strlen(gsa->retrytime)) { // Retrytime assigned, retry after retrytim*3600 seconds.
			unsigned int wait = atoi(gsa->retrytime)*3600;
			Cdbg(APP_DBG, "Get Service Area failed status value=%s, retry after %d seconds.", gsa->status, wait);
			sleep(wait);
			return -1;
		}

		if(strcmp ((const char*)gsa->status, "0")){
			Cdbg(APP_DBG, "Get Service Area failed status value=%s", gsa->status);
			if (status != 28)
				return -1;
			else
				return -2;
		}
		area = &gsa->servicearea[0];
		nvram_set("aae_area", area);
		nvram_commit();
	} else {
		snprintf(gsa->servicearea, sizeof(gsa->servicearea), "%s", area);
	}
	//	call_state= GotServiceArea;
	// login webservice	
	unsigned char mac_addr[6];
	get_mac(mac_addr);
	Cdbg(APP_DBG, "start login...");	
	DECLARE_CLEAR_MEM(char, md5string, MD_STR_LEN);
	DECLARE_CLEAR_MEM(char, mac_str, MAC_MAX_LEN);
#if NVRAM
	if(nvram_get_mac_addr(mac_str)<0) 
		sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
#else
	sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
#endif
	get_md5_string(mac_str, md5string);	
	char* device_type=DEVICE_TYPE; // 	Linux PC
	char* permission=PERMISSION; 	//	public:0, private:1
#if GEMTEK
	char* devicename=GEMTEK_DEVICE_NAME;
	char* deviceservice=GEMTEK_DEVICE_SERVICE;
	char* device_desc	= GEMTEK_DEVICE_DESC;
#else
	char* devicename=ASUS_DEVICE_NAME;
	char* deviceservice=ASUS_DEVICE_SERVICE;
	DECLARE_CLEAR_MEM(char, device_desc, ASUS_DEVICE_DESC_LEN);
	sprintf(device_desc, "%s", dev_desc ? dev_desc : ""); // TODO use snprintf
	Cdbg(APP_DBG, "profile devdesc=%s", device_desc);
#endif
	
	char* cusid = "";
	char* user_ticket = "";
	char* refresh_ticket = "";
	
#ifdef RTCONFIG_ACCOUNT_BINDING

	GetUserTicketByRefresh ut;
	int re_login_after_update_userticket_count = 0;

re_login_after_update_userticket:
	
	cusid = nvram_safe_get("oauth_dm_cusid");
	user_ticket = nvram_safe_get("oauth_dm_user_ticket");
	refresh_ticket = nvram_safe_get("oauth_dm_refresh_ticket");

	Cdbg(APP_DBG, "login cusid=%s, user_ticket=%s, refresh_ticket=%s", cusid, user_ticket, refresh_ticket);

	if(strlen(cusid)>0 && strlen(refresh_ticket)>0 && strlen(user_ticket)==0) {
		memset(&ut, 0, sizeof(GetUserTicketByRefresh));
		GetUserTicketByRefresh* gut = &ut;
		if (st_GetUserTicketByRefresh(gsa->servicearea, gut, cusid, md5string, refresh_ticket)==0) {
			nvram_set("oauth_dm_user_ticket", gut->userticket);

			if (strlen(gut->userrefreshticket)>0) {
				nvram_set("oauth_dm_refresh_ticket", gut->userrefreshticket);
			}

			nvram_commit();
		}
		
		cusid = nvram_safe_get("oauth_dm_cusid");
		user_ticket = nvram_safe_get("oauth_dm_user_ticket");
		refresh_ticket = nvram_safe_get("oauth_dm_refresh_ticket");
	}
	else if(strlen(cusid)>0 && strlen(refresh_ticket)==0) {
		Cdbg(APP_DBG, "Because refresh_ticket is empty, reset to unbinding status.");
		clear_binding_data();
		return -1;
	}
	
	if(strlen(cusid)>0 && strlen(refresh_ticket)>0 && strlen(user_ticket)>0) {
		deviceservice = ASUS_DEVICE_ACCOUNT_BINDING_SERVICE;
	}

//- endf of RTCONFIG_ACCOUNT_BINDING
#endif

	// login service area
	memset(lg, 0, sizeof(Login));
	
	status = send_login_req(gsa->servicearea, vip_id, vip_pwd, cusid, user_ticket, md5string,
		 devicename, deviceservice, device_type, permission, device_desc, 
		 fwver, AIHOME_API_LEVEL, model_name, lg);
		 
#if NVRAM
	nvram_set_aae_status("login", status, lg->status);
#endif
#if 0
	if (nvram_get_int("aae_dbg")) {
		snprintf(lg->status, sizeof(lg->status), "%s", nvram_safe_get("aae_dbg_login_status"));
		snprintf(lg->apilevel_status, sizeof(lg->apilevel_status), "%s", nvram_safe_get("aae_dbg_apilevel_status"));
		snprintf(lg->apilevel, sizeof(lg->apilevel), "%s", nvram_safe_get("aae_dbg_apilevel"));
	}
#endif
	if(strcmp(lg->status, "0")){
		Cdbg(APP_DBG, "Login failed status =%s", lg->status);
		if (!strcmp(lg->status, "9") && strcmp(lg->apilevel_status, APILEVEL_STATUS_SUPPORT)) { // need to check apilevel
			if (!strcmp(lg->apilevel_status, APILEVEL_STATUS_END_OF_LIFE)) {
				nvram_set(AAE_SUPPORT_LEVEL, "-1");
				nvram_commit();
			}
			else if (!strcmp(lg->apilevel_status, APILEVEL_STATUS_APILEVEL_NOT_SUPPORT) || 
				!strcmp(lg->apilevel_status, APILEVEL_STATUS_FW_VERSION_NOT_SUPPORT)) {
				nvram_set(AAE_SUPPORT_LEVEL, lg->apilevel);
				nvram_commit();
			}
		} else if (!strcmp(lg->status, "10")) { // unsupported area
			Cdbg(APP_DBG, "Login failed status =%s", lg->status);
			nvram_set("aae_area", "unsupported_area");
			nvram_commit();
			return -3; // need to getservicearea again.
		} else if (!strcmp(lg->status, "1")) {
			//- Authentication Fail
#ifdef RTCONFIG_ACCOUNT_BINDING
			//- update user ticket by refresh ticket
			if(strlen(cusid)>0 && strlen(refresh_ticket)>0) {
				memset(&ut, 0, sizeof(GetUserTicketByRefresh));
				GetUserTicketByRefresh* gut = &ut;
				if (st_GetUserTicketByRefresh(gsa->servicearea, gut, cusid, md5string, refresh_ticket)==0) {
					nvram_set("oauth_dm_user_ticket", gut->userticket);

					if (strlen(gut->userrefreshticket)>0) {
						nvram_set("oauth_dm_refresh_ticket", gut->userrefreshticket);
					}

					nvram_commit();

					re_login_after_update_userticket_count++;

					Cdbg(APP_DBG, "Get user ticket by refresh ticket, gut->userticket=%s, gut->userrefreshticket=%s", gut->userticket, gut->userrefreshticket);

					if (re_login_after_update_userticket_count<=5) {
						goto re_login_after_update_userticket;
					}
					else {
						Cdbg(APP_DBG, "Because of excess retry count %d, reset to unbinding status.", re_login_after_update_userticket_count);
						clear_binding_data();
					}
				}
			}
#endif
		}

#ifdef RTCONFIG_ACCOUNT_BINDING
		if (nvram_get_int("oauth_auth_status")==1) {
			//- account binding fail, clear all binding data
			Cdbg(APP_DBG, "Because login fail, reset to unbinding status.");
			clear_binding_data();
		}
#endif

		if (status != 28) {
			return -1;
		} else {
			return -2;
		}
	}
	g_gsa = gsa;
	g_lg = lg;

#ifdef RTCONFIG_ACCOUNT_BINDING
	if (nvram_get_int("oauth_auth_status")==1) {

		//- force to get ca file because account binding
		nvram_set("aws_ca_download_status", "0");

		nvram_set("oauth_auth_status", "2");
		
		nvram_set("aae_deviceticket", lg->deviceticket);
		nvram_set("aae_pnsinfo", lg->pnsinfoList ? lg->pnsinfoList->srv_ip : "");
		nvram_set("aae_webstorageinfo", lg->webstorageinfoList ? lg->webstorageinfoList->srv_ip : "");
		nvram_set("aae_ddnsinfo", lg->ddnsinfoList ? lg->ddnsinfoList->srv_ip : "");

		nvram_commit();

		do_GetAWSCertificate(gsa, lg);
	}
	else if (is_account_bound()) {
		do_GetAWSCertificate(gsa, lg);

		nvram_set("aae_deviceticket", lg->deviceticket);
		nvram_set("aae_pnsinfo", lg->pnsinfoList ? lg->pnsinfoList->srv_ip : "");
		nvram_set("aae_webstorageinfo", lg->webstorageinfoList ? lg->webstorageinfoList->srv_ip : "");
		nvram_set("aae_ddnsinfo", lg->ddnsinfoList ? lg->ddnsinfoList->srv_ip : "");
		nvram_commit();
	}
	else if (nvram_get_int("oauth_auth_status")==0) {
		nvram_set("aae_pnsinfo", lg->pnsinfoList ? lg->pnsinfoList->srv_ip : "");
		nvram_set("aae_webstorageinfo", lg->webstorageinfoList ? lg->webstorageinfoList->srv_ip : "");

		//- Depend on nvram ddns_server_x
		//- ddns_server_x=WWW.ASUS.COM, aae_ddnsinfo=ns1.asuscomm.com
		//- ddns_server_x=WWW.ASUS.COM.CN, aae_ddnsinfo=ns1.asuscomm.cn
		nvram_set("aae_ddnsinfo", "");
		nvram_commit();
	}
#endif

	return 0;
}

void clear_binding_data() {
	
	//- clear all oauth data.
	nvram_set("oauth_dm_refresh_ticket", "");
	nvram_set("oauth_dm_user_ticket", "");
	nvram_set("oauth_dm_cusid", "");
	nvram_set("oauth_auth_status", "0");
	nvram_set("oauth_user_email", "");
	nvram_set("oauth_type", "");
	
	nvram_set("awsiotendpoint", "");
	nvram_set("awsiotclientid", "");
	nvram_set("aae_awsiot_desc_updated", "0");
	nvram_set("aws_ca_download_status", "0");

	nvram_set("ddns_replace_status", "0");

	nvram_set("amazon_alexa_skill_user_id", "");
	
	nvram_set("aae_portal", "");
	nvram_set("aae_area", "");

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
#else		
	nvram_commit();
#endif
}

int do_GetAWSCertificate(GetServiceArea* gsa, Login* lg)
{
	//- aws_ca_download_status:
	//- 0: not download
	//- 1: already download
	//- 2: donloading
	
	if (gsa==NULL || lg==NULL) {
		return -1;
	}

#ifdef RTCONFIG_ACCOUNT_BINDING
	if (!is_account_bound())
#endif
		return -1;
	if (nvram_get_int("aws_ca_download_status")==1 &&
		isFileExist(AWS_CERTS_CA_FILE) &&
		isFileExist(AWS_CERTS_CRT_FILE) &&
		isFileExist(AWS_CERTS_KEY_FILE)) {
		//- Already get aws ca files.
		return 0;
	}
	else if (nvram_get_int("aws_ca_download_status")==2) {
		return -1;
	}

	nvram_set("aws_ca_download_status", "2");

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
#else		
	nvram_commit();
#endif

	GetAWSCertificate act;
	memset(&act, 0, sizeof(GetAWSCertificate));
	GetAWSCertificate* gact = &act;

	if (st_GetAWSCertificate(gsa->servicearea, lg, gact)==0) {
		
		struct stat sb;
		if (stat(AWS_CERTS_PATH, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		}
		else {
			mkdir(AWS_CERTS_PATH, 0755);
		}

		unlink(AWS_CERTS_CA_FILE);
		unlink(AWS_CERTS_CRT_FILE);
		unlink(AWS_CERTS_KEY_FILE);

		FILE *fp = NULL;
		
		fp = fopen(AWS_CERTS_CA_FILE, "w");
		if(NULL != fp) {
			fprintf(fp, "%s", gact->rootca);
			fclose(fp);
		}

		fp = fopen(AWS_CERTS_CRT_FILE, "w");
		if(NULL != fp) {
			fprintf(fp, "%s", gact->certificate);
			fclose(fp);
		}

		fp = fopen(AWS_CERTS_KEY_FILE, "w");
		if(NULL != fp) {
			fprintf(fp, "%s", gact->privatekey);
			fclose(fp);
		}

		nvram_set("aws_ca_download_status", "1");

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
#else		
		nvram_commit();
#endif

		return 0;
	}

	Cdbg(APP_DBG, "Fail to get ca file!");
	
	nvram_set("aws_ca_download_status", "0");

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
#else
	nvram_commit();
#endif

	return -1;
}

int st_Unregister(GetServiceArea* gsa, Login* lg)
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

int st_PnsSendMsg(GetServiceArea* gsa, Login* lg, char *token, char *serviceid, char *msg)
{
    int status;
    char apilevel[8];
    PnsSendMsg psm; 
	char fwver[128];
	const char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
	snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
    memset(&psm, 0 , sizeof(psm));
    snprintf(apilevel, sizeof(apilevel), "%d", AIHOME_API_LEVEL);
    status = send_pns_sendmsg_req(gsa->servicearea, 
    								lg->cusid, 
    								lg->deviceid, 
    								lg->deviceticket, 
    								serviceid, 
    								token, 
									DEVICE_TYPE,
									fwver,
									apilevel,
									model_name,
    								msg, &psm);
    Cdbg(APP_DBG,"send_pns_sendmsg_req return status = %s \n", psm.status); 
    if (strcmp(psm.status, "1") == 0) { // auth fail. Suicide to relogin and reinitialize ANT SDK.
        Cdbg(APP_DBG, "send_pns_sendmsg_req with auth fail.");
    }
#if NVRAM
    nvram_set_aae_status("pns_sendmsg", status, psm.status);
#endif
    return status;
}

int st_IftttNotification(char *server, char *api, char *msg)
{
    int status;
    IftttNotification ifttt; 
    memset(&ifttt, 0 , sizeof(ifttt));
    status = send_ifttt_notification_req(server, api, msg, &ifttt);
    Cdbg(APP_DBG,"send_ifttt_notification_req return status = %s \n", ifttt.status); 
    if (strcmp(ifttt.status, "0")) {
        if (strcmp(ifttt.status, "1") == 0) { // auth fail. Suicide to relogin and reinitialize ANT SDK.
            Cdbg(APP_DBG, "send_ifttt_notification_req with auth fail.");
        }
    }
#if NVRAM
    nvram_set_aae_status("ifff_notification", status, ifttt.status);
#endif
    return status;
}

int st_GetUserTicketByRefresh(char *server, GetUserTicketByRefresh* ut, char* cusid, char* devicemd5mac, char* refresh_ticket)
{
    int status;
	// char* serviceid = ASUS_DEVICE_SERVICE;
	char* serviceid = ASUS_DEVICE_ACCOUNT_BINDING_SERVICE;
	char* device_type = DEVICE_TYPE; // 	Linux PC
	char fwver[128];
	char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
	snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));

	status = send_getuserticketbyrefresh_req(
		server, 
		serviceid, 
		cusid, 
		devicemd5mac,
		refresh_ticket,
		device_type, 
		fwver, 
		AIHOME_API_LEVEL,
		model_name,
		ut
	);

    Cdbg(APP_DBG, "send get user ticket by refresh req, server=%s, status=%d, ut->status=%s", server, status, ut->status);

	if (status==0 && strcmp(ut->status, "0") == 0) {
		return 0;
	}
	else if (status==0 && strcmp(ut->status, "1") == 0) {
		//- fail to update refresh ticket, clear all oauth data.
		Cdbg(APP_DBG, "Because get user ticket by refresh fail, reset to unbinding status.");
		clear_binding_data();
	}

    return 1;
}

int st_GetAWSCertificate(char *server, Login* lg, GetAWSCertificate* gact)
{
    int status;
	char* serviceid = ASUS_DEVICE_SERVICE;
	char* device_type = DEVICE_TYPE; // 	Linux PC
	char fwver[128];
	char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
	snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
	
	nvram_set("awsiotendpoint", "");
	nvram_set("awsiotclientid", "");
	nvram_commit();

	status = send_getawscertificate_req(
		server, 
		serviceid, 
		lg->cusid,
		lg->userticket,
		lg->deviceid,
		lg->deviceticket,
		device_type, 
		fwver, 
		AIHOME_API_LEVEL,
		model_name,
		gact
	);

    Cdbg(APP_DBG, "send get aws certificate, server=%s, status=%d, gact->status=%s", server, status, gact->status);

	if (status==0 && strcmp(gact->status, "0") == 0) {
		nvram_set("awsiotendpoint", gact->awsiotendpoint);

		//- awsiot client id
		unsigned char cusid_and_device_id_str[100] = { 0 };
		strncpy(cusid_and_device_id_str, lg->cusid, strlen(lg->cusid));
		strncat(cusid_and_device_id_str, lg->deviceid, strlen(lg->deviceid));

		nvram_set("awsiotclientid", cusid_and_device_id_str);
		nvram_commit();

		//- restart awsiot
		kill_all_proc("awsiot");

		return 0;
	}

    return 1;
}

#ifdef RTCONFIG_ACCOUNT_BINDING
int st_PnsSendMsgFcm(GetServiceArea* gsa, Login* lg, char *msg)
{
    int status;
    char apilevel[8];
    PnsSendMsgFcm psm; 
	char fwver[128];
	const char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
	snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
    memset(&psm, 0 , sizeof(psm));
    snprintf(apilevel, sizeof(apilevel), "%d", AIHOME_API_LEVEL);
    status = send_pns_sendmsg_fcm_req("aae-sgweb001-1.asuscomm.com", 
    								lg->cusid, 
    								lg->deviceid, 
    								lg->deviceticket, 
    								"", 
									DEVICE_TYPE,
									fwver,
									apilevel,
									model_name,
    								msg, &psm);
    Cdbg(APP_DBG,"send_pns_sendmsg_fcm_req return status = %s \n", psm.status); 
    if (strcmp(psm.status, "1") == 0) { // auth fail. Suicide to relogin and reinitialize ANT SDK.
        Cdbg(APP_DBG, "send_pns_sendmsg_fcm_req with auth fail.");
    }
#if NVRAM
    nvram_set_aae_status("pns_sendmsg_fcm", status, psm.status);
#endif
    return status;
}
#endif
