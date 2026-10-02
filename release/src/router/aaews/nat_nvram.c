#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <log.h>
#include "ws_api.h"
#include "nat_nvram.h"
#include "common.h"
#include "aae_ipc_handler.h"
#ifdef NVRAM

#include <bcmnvram.h>

#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
#include <aae_ipc.h>
extern int aae_sendIpcMsg(char *ipcPath, char *data, int dataLen);
#endif

//sem_t* p_gAAE_sem;
int nvram_get_link_internet()
{
	int enable=0;
	char* str_link_internet = nvram_get(LINK_INTERNET);

	if(str_link_internet) {
		enable = atoi(str_link_internet);	
	}
	return enable;
}

int nvram_get_mac_addr(char* mac_addr)
{
	const char* var = nvram_get(ROUTER_MAC);
	if(var){
		strcpy(mac_addr, var);
		return 0;
	}else return -1;
}

int nvram_is_aae_enable()
{
	int enable=0;
	char* aae_enable = nvram_get(AAE_ENABLE);
	if(aae_enable) {
		enable = atoi(aae_enable);
	}
	return (enable & 1);
}

int nvram_set_aae_status(const char* api, const int curl_status, const char* aae_status )
{
	char status_str[256];
	int aae_status_num = (aae_status || strlen(aae_status)) ? atoi(aae_status) : 0;
	snprintf(status_str, sizeof(status_str), "[api=%s][curl=%d (%s)][aae=%d (%s)]", api, 
		curl_status, get_curl_status_string(curl_status), 
		aae_status_num, get_aae_status_string(aae_status_num));

	return nvram_set(AAE_STATUS, status_str);
}



int nvram_set_server_status(const char* server, const int status, const char* status_text )
{
	char status_str[128];
	char name[32];
	snprintf(name, sizeof(name), "aae_%s_last_status", server);
	snprintf(status_str, sizeof(status_str), "[%d (%s)]", status, status_text);
	return nvram_set(name, status_str);
}

int nvram_set_aae_sip_connected(const char* aae_sip_connected)
{

// send ipc to [awsiot]
#ifdef RTCONFIG_AWSIOT

	if( (is_account_bound() && strcmp(aae_sip_connected, "1") == 0) ) {

		Cdbg(NV_DBG, "aae_sip_connected = %s", aae_sip_connected);
		char status_str[256];
		// snprintf(status_str, sizeof(status_str), "{\"api\":\"%s\",\"curl_status\":%d,\"curl\":\"%s\",\"aae_status\":%d,\"aae\":\"%s\"}", api, 
		// 	curl_status, get_curl_status_string(curl_status), 
		// 	aae_status_num, get_aae_status_string(aae_status_num));
		snprintf(status_str, sizeof(status_str), AAE_TUNNEL_STATUS_RES, 1);

	    aae_sendIpcMsg(AWSIOT_IPC_SOCKET_PATH, status_str, strlen(status_str));
	}
#endif


	return nvram_set(AAE_SIP_CONNECTED, aae_sip_connected);
}

int nvram_get_aae_pwd(char** aae_pwd)
{
	const char* var = nvram_get(AAE_ENABLE);
	if(var){
		size_t pwdlen = strlen(var)+1;	
		*aae_pwd = (char*)malloc(pwdlen); 
		memset(*aae_pwd, 0 , pwdlen);
		strcpy(*aae_pwd, var);
		return 0;
	}else return -1;
}


int nvram_get_aae_username(char** aae_username)
{
	const char* var = nvram_get(AAE_USERNAME);
	if(var){
		size_t usrlen = strlen(var)+1;	
		*aae_username = (char*)malloc(usrlen); 
		memset(*aae_username, 0 , usrlen);
		strcpy(*aae_username, var);
		return 0;
	}else return -1;
}

int nvram_save_value(const char* name, const char* value)
{
	return nvram_set(name, value);
}

int nvram_set_aae_info(const char* deviceid)
{
	int status =-1; 
	Cdbg(NV_DBG, "nvram set aae info ..........1, deviceid =%s",deviceid );
	if(!deviceid) {
		goto __NVRAM_SET_AAE_INFO;
	}
	const char* rd_devid = nvram_get("aae_deviceid");
	Cdbg(NV_DBG, "nvram set aae info .......... rd_devid =%s", rd_devid);
	/** if the exist deviceid in nvram is equal deviceid get from webservice,	**/
	/** dont need to save to nvram												**/
	if(rd_devid) {
		if(!strcmp(rd_devid, deviceid) && strlen(rd_devid)>16) {
			status =0;
			goto __NVRAM_SET_AAE_INFO;
		}
	}	   
	/** if not equal , update deviceid to nvram **/
	int pos=0;
	char w_devid[MAX_DEVICEID_LEN]; memset(w_devid, 0, MAX_DEVICEID_LEN);
	/**	check device id is exist character '@', if yes , strip  **/ 
	if((pos = (int)strchr(deviceid, '@'))) {
		Cdbg(NV_DBG, "nvram set aae info .......... found @ at =%d", pos);
		strncpy(w_devid, deviceid, ((int)pos-(int)deviceid));
	}else strcpy(w_devid, deviceid);
	
	Cdbg(NV_DBG, "nvram set aae info .......... write devid %s to nvram", w_devid);
	nvram_save_value("aae_deviceid", w_devid);
	nvram_set_int("aae_enable", (nvram_get_int("aae_enable") | 1));
	status = 0;
__NVRAM_SET_AAE_INFO:
	return status;
}

int nvram_get_aae_sdk_log_level()
{
        const char* var = nvram_get(AAE_SDK_LOG_LEVEL);
        if(var)
                return atoi(var);
        else
                return -1;
}

int nvram_set_aae_sdk_log_level(const char* aae_sdk_log_level)
{
        return nvram_set(AAE_SDK_LOG_LEVEL, aae_sdk_log_level);
}

int nvram_get_wan_access(char* wan_access)
{
	const char* var = nvram_get(WAN_ACCESS);
	if (var) {
		strcpy(wan_access, var);
		return 0;
	} else 
		return -1;
}

int nvram_get_ddns_name(char* ddns_hostname)
{
	const char* var = nvram_get(DDNS_HOSTNAME);
	if (var) {
		strcpy(ddns_hostname, var);
		return 0;
	} else
		return -1;
}

int nvram_get_ddns_enable(char* ddns_enable)
{
	const char* var = nvram_get(DDNS_ENABLE);
	if (var) {
		strcpy(ddns_enable, var);
		return 0;
	} else
		return -1;
}

int nvram_get_https_wan_port(char* https_wan_port)
{
	const char* var = nvram_get(HTTPS_WAN_PORT);
	if (var) {
		strcpy(https_wan_port, var);
		return 0;
	} else 
		return -1;
}

/*int nvram_get_http_wan_port(char* http_wan_port)
{
	const char* var = nvram_get(HTTP_WAN_PORT);
	if (var) {
		strcpy(http_wan_port, var);
		return 0;
	} else 
		return -1;
}

int nvram_get_http_enable(char* http_enable)
{
	const char* var = nvram_get(HTTP_ENABLE);
	if (var) {
		strcpy(http_enable, var);
		return 0;
	} else 
		return -1;
}*/

void aae_support_check(int *is_terminate) {
	int aae_support_level;
	if (!nvram_get(AAE_SUPPORT_LEVEL))
		return;

	aae_support_level = nvram_get_int(AAE_SUPPORT_LEVEL);
	if (aae_support_level == -1 || 
		aae_support_level > AIHOME_API_LEVEL) {
		while (!(*is_terminate)) {
			sleep(10);
		}
	} else if (aae_support_level != -1 && 
		aae_support_level <= AIHOME_API_LEVEL) {
		nvram_unset(AAE_SUPPORT_LEVEL);
		nvram_commit();
	}
}

/*
	If MAX_COUNT=4, random_base=240 and random_max=3840, the return range will be.
	count=0, return 0
	count=1, return 240~480
	count=2, return 480~960
	count=3, return 960~1920
	count=4, return 1920~3840. This range is always chosen if the count is greater than 4.
*/
int get_random_delay(int count, int random_base, int random_max) {
	int real_base;
	int random_delay;

	if (count < 1)
		return 0;

	if ((random_base<<count) > random_max)
		real_base = random_max - (random_base<<(count-1));
	else
		real_base = random_base<<(count-1);

	srand(time(NULL));
	random_delay = (rand() % real_base) + (random_base<<(count-1));
	Cdbg(NV_DBG, "get_random_delay, count=[%d], real_base=[%d], random_delay=[%d]", count, real_base, random_delay);
	return random_delay;
}
#endif
