 /*
 * Copyright 2015, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */
 
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <ctype.h>
/* -- */
#include <nt_nvram.h>
#include <nt_center.h>
#include <nt_eInfo.h>
#include <libnt.h>
#include <json.h>

#if defined(RTCONFIG_DMALLOC)
#include <dmalloc.h>
#endif

#if defined(RTCONFIG_CHINATEL_GUANGDONG)
#include <gd_api_msg.h>
#endif
#if defined(RTCONFIG_CHINATEL_EOS)
#include "libubox/blobmsg_json.h"
#include "libubus.h"
#endif

#define MyDBG(fmt,args...) \
	if(isFileExist(NOTIFY_CENTER_DEBUG) > 0) { \
		Debug2Console("[Notification_Center][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	} \
	if(isFileExist(COMMON_IFTTT_DEBUG) > 0) { \
		Debug2File(COMMON_IFTTT_LOG_FILE, "[Notification_Center][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}
#define ErrorMsg(fmt,args...) \
	Debug2Console("[Notification_Center][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	if(isFileExist(COMMON_IFTTT_DEBUG) > 0) { \
		Debug2File(COMMON_IFTTT_LOG_FILE, "[Notification_Center][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}


#define PRINT_DEBUG_TO_FILE 1

#define MUTEX pthread_mutex_t
#define MUTEXINIT(m) pthread_mutex_init(m, NULL)
#define MUTEXLOCK(m) pthread_mutex_lock(m)
#define MUTEXTRYLOCK(m) pthread_mutex_trylock(m)
#define MUTEXUNLOCK(m) pthread_mutex_unlock(m)
#define MUTEXDESTROY(m) pthread_mutex_destroy(m)

/* Globals */
static NT_CHECK_ACTION_T *pEsw = NULL;

enum {
	NT_OFF=0,
	NT_ON
};

static MUTEX event_list_lock;
struct list *event_list=NULL;
static int terminated = 1;

static int send_cnt = 0;
static int rec_cnt = 0;
static int CONFIG_UPDATE = NT_OFF;

static void load_esw_info();

NOTIFY_EVENT_T *event_listcreate(NOTIFY_EVENT_T input)
{
	NOTIFY_EVENT_T *new=malloc(sizeof(*new));
	
	memcpy(new,&input,sizeof(*new));
	return new;
}

static void receive_s(int newsockfd)
{
	int    n;
	time_t now;
	char   date[30];
	NOTIFY_EVENT_T event_t;
	NOTIFY_EVENT_T *sevent_t;
	
	memset(&event_t, 0, sizeof(NOTIFY_EVENT_T));
	
	n = read( newsockfd, &event_t, sizeof(NOTIFY_EVENT_T));
	if( n < 0 )
	{
		ErrorMsg("ERROR reading from socket.\n");
		return;
	}
	
	
	/* Check Event */
	if(eInfo_get_idx_by_evalue(event_t.event) < 0) {
		
		MyDBG("Warning!!! receive undefined event, drop [%x] event.\n", event_t.event );
		return;
	}
	
	event_t.tstamp = time(&now);
	StampToDate(event_t.tstamp, date);
	rec_cnt++;
	
	MyDBG("[%s] event:[%s (%x)] msg:[%s] Num:[%d]\n", date, eInfo_get_eName(event_t.event), event_t.event, event_t.msg, rec_cnt);
	
#if PRINT_DEBUG_TO_FILE
	if(GetDebugValue(NOTIFY_CENTER_DEBUG)) {
		char info[200];
		snprintf(info, sizeof(info), "echo \"[Notification_Center][receive event] [%s] event:[%s (%x)] msg:[%s] Num:[%d]\" >> %s", 
			date, eInfo_get_eName(event_t.event), event_t.event, event_t.msg, rec_cnt, NOTIFY_CENTER_LOG_FILE);
		system(info);
	}
#endif
	
	MUTEXLOCK(&event_list_lock);
	if(event_list) {
		sevent_t=NULL;
		sevent_t=event_listcreate(event_t);
		if(sevent_t)
			listnode_add(event_list,(void*)sevent_t);
	
	}
	MUTEXUNLOCK(&event_list_lock);
	
}
static int start_local_socket(void)
{
	struct sockaddr_un addr;
	int sockfd, newsockfd;
	
	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ErrorMsg("socket error\n");
		perror("socket error");
		exit(-1);
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, NOTIFY_CENTER_SOCKET_PATH, sizeof(addr.sun_path)-1);
	
	unlink(NOTIFY_CENTER_SOCKET_PATH);
	
	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		ErrorMsg("socket bind error\n");
		perror("socket bind error");
		exit(-1);
	}
	
	if (listen(sockfd, MAX_NOTIFY_SOCKET_CLIENT) == -1) {
		ErrorMsg("listen error\n");
		perror("listen error");
		exit(-1);
	}
	
	while (1) {
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			ErrorMsg("accept error\n");
			perror("accept error");
			continue;
		}
		
		receive_s(newsockfd);
		close(newsockfd);
	}
}

static void local_socket_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start unix socket thread.\n");
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&start_local_socket, NULL);
	pthread_attr_destroy(&attr);
}

static int get_event_action(int e)
{
	int i;
	for(i=0; i < MAX_NOTIFY_EVENT_NUM; i++) {
		if(pEsw[i].event == e) {
			return pEsw[i].action;
		}
	}
	return -1;
}
#ifdef SUPPORT_PUSH_MSG
static int pnsInfo_get_idx_by_evalue(int e)
{
	int i;
	for(i=0; mapInfo[i].value != 0; i++) {
		if( mapInfo[i].value == e)
			return i;
	}
	return -1;
}

static char *pnsInfo_get_title(int e)
{
	int idx;
	idx = pnsInfo_get_idx_by_evalue(e);
	if (idx < 0)
		return NULL;
	else
		return mapPushInfo[idx].title;
}
static char *pnsInfo_get_iftttMsg(int e)
{
	int idx;
	idx = pnsInfo_get_idx_by_evalue(e);
	if (idx < 0)
		return NULL;
	else
		return mapPushInfo[idx].iftttMsg;
}
static int pnsInfo_get_argnum(int e)
{
	int idx;
	idx = pnsInfo_get_idx_by_evalue(e);
	if (idx < 0)
		return -1;
	else
		return mapPushInfo[idx].argNum;
}
void delspace(char *str1, char *str2)
{
	int mark = 0;
	while (*str1 != '\0' )
	{
		if(*str1 == '"') {
			if(mark) 
				mark = 0; 
			else 
				mark = 1;
		}
		if (!mark) {
			if (!isspace(*str1)) {
				*str2 = *str1;
				str2++;
			}
		} else {
			*str2 = *str1;
			str2++;
		}
		str1++;
	}
	
	*str2 = '\0';
}
static char *get_json_value(json_object *obj, char *name)
{
	json_object *json_value = NULL;
	json_value = json_object_object_get(obj, name);
	
	if(json_value != NULL)
		return (char *)json_object_get_string(json_value);
	else
		return NULL;
}
static int push_msg_parser()
{
	FILE *fp;
	char JsonStr[1024];
	char cmd[64];
	char *value;
	json_object *Get_json   = NULL;
	
	if (!isFileExist(PUSH_CONF_PATH)) {
		ErrorMsg("[Error] %s : No such file\n", PUSH_CONF_PATH);
		goto END;
	}
	
	snprintf(cmd, sizeof(cmd), "cat %s", PUSH_CONF_PATH);
	
	if ((fp = popen(cmd, "r")) != NULL) {
		fgets(JsonStr, sizeof(JsonStr), fp);
		MyDBG("Config:%s\n", JsonStr);
		pclose(fp);
	} else {
		ErrorMsg("fp = %p\n", fp);
		perror(cmd);
		goto END;
	}
	/* JSON FORMAT: {"login_status" : "0","server" : "","cusid" : "","deviceid" : "","deviceticket" : ""} */
	Get_json = json_tokener_parse(JsonStr);
	
	if(Get_json == NULL) {
		MyDBG("json_tokener_parse error\n");
		goto END;
	}
	
	value = get_json_value(Get_json, "login_status");
	if(value) {
		if(atoi(value) != 0) {
			MyDBG("AAE Login Error, status:[%s]\n", value);
			goto END;
		}
		strncpy(PushConf.status, value, sizeof(PushConf.status)-1);
		MyDBG("PushConf.status:[%s]\n",PushConf.status);
	}
	
	value = get_json_value(Get_json, "server");
	if(value) {
		strncpy(PushConf.server, value, sizeof(PushConf.server)-1);
		MyDBG("PushConf.server:[%s]\n",PushConf.server);
	} else goto END;
	
#if defined(RTCONFIG_ACCOUNT_BINDING)
	value = get_json_value(Get_json, "psr_server");
	if(value) {
		strncpy(PushConf.psr_server, value, sizeof(PushConf.psr_server)-1);
		MyDBG("PushConf.psr_server:[%s]\n",PushConf.psr_server);
	} else goto END;
#endif
	value = get_json_value(Get_json, "cusid");
	if(value) {
		strncpy(PushConf.cusid, value, sizeof(PushConf.cusid)-1);
		MyDBG("PushConf.cusid:[%s]\n",PushConf.cusid);
	} else goto END;
	
	value = get_json_value(Get_json, "deviceid");
	if(value) {
		strncpy(PushConf.deviceid, value, sizeof(PushConf.deviceid)-1);
		MyDBG("PushConf.deviceid:[%s]\n",PushConf.deviceid);
	} else goto END;
	
	value = get_json_value(Get_json, "deviceticket");
	if(value) {
		strncpy(PushConf.deviceticket, value, sizeof(PushConf.deviceticket)-1);
		MyDBG("PushConf.deviceticket:[%s]\n",PushConf.deviceticket);
	} else goto END;
	
	value = get_json_value(Get_json, "devicetype");
	if(value) {
		strncpy(PushConf.devicetype, value, sizeof(PushConf.devicetype)-1);
		MyDBG("PushConf.devicetype:[%s]\n",PushConf.devicetype);
	} else goto END;
	
	value = get_json_value(Get_json, "fwver");
	if(value) {
		strncpy(PushConf.fwver, value, sizeof(PushConf.fwver)-1);
		MyDBG("PushConf.fwver:[%s]\n",PushConf.fwver);
	} else goto END;
	
	value = get_json_value(Get_json, "apilevel");
	if(value) {
		strncpy(PushConf.apilevel, value, sizeof(PushConf.apilevel)-1);
		MyDBG("PushConf.apilevel:[%s]\n",PushConf.apilevel);
	} else goto END;
	
	value = get_json_value(Get_json, "modelname");
	if(value) {
		strncpy(PushConf.modelname, value, sizeof(PushConf.modelname)-1);
		MyDBG("PushConf.modelname:[%s]\n",PushConf.modelname);
	} else goto END;
	
	json_object_put(Get_json);
	return 1;
	

END:
	json_object_put(Get_json);
	MyDBG("Parser Error.\n");
	return 0;
	
}
static json_object *generate_push_obj(NOTIFY_EVENT_T *eInfo)
{
	int  i = 0;
	int  argchk = 0;
	int  argNum;
	char eID[16];
	char macStr[20];
	char path[256];
	char model[64];
	char ver[8];
	
	enum json_type type;
	
	json_object *root = NULL;
	root = json_object_new_object();
	
	json_object *aps   = NULL;
	json_object *alert = NULL;
	json_object *arg   = NULL;
	json_object *nc    = NULL;
	json_object *msg   = NULL;
	
	aps   = json_object_new_object();
	alert = json_object_new_object();
	nc    = json_object_new_object();
	arg   = json_object_new_array();
	
	msg = json_tokener_parse(eInfo->msg);
	
	if (root == NULL || aps == NULL || alert == NULL || 
	    arg  == NULL ||  nc == NULL) {
		ErrorMsg("json object error\n");
		goto FREE_JSON;
	}
	
	/* alert object */
	json_object_object_add(alert, "loc-key", json_object_new_string(pnsInfo_get_title(eInfo->event)));
	
	argNum = pnsInfo_get_argnum(eInfo->event);
	
	if (argNum > 0 && msg != NULL) {
		if (arg == NULL) {
			ErrorMsg("json object error\n");
			goto FREE_JSON;
		}
		
		json_object_object_foreach(msg, key, val) {
			if (i < argNum) {
				type = json_object_get_type(val);
				switch (type) {
					case json_type_int :
						json_object_array_add(arg, json_object_new_int(json_object_get_int(val)));
						i++;
						break;
					case json_type_string :
						json_object_array_add(arg, json_object_new_string(json_object_get_string(val)));
						i++;
						break;
					default :
						break;
				}
			}
		}
		
		if ( i != argNum ) {
			ErrorMsg("[Error] Trigger Msg arg does NOT match with PushMsg define.\n");
			goto FREE_JSON;
		}
		json_object_object_add(alert, "loc-args", arg);
		argchk = 1;
	}
	
	/* nc object */
	snprintf(eID, sizeof(eID), "%X", eInfo->event);
	
	if (f_read_string(PUSH_MAC_PATH, macStr, sizeof(macStr)) < 0) {
		ErrorMsg("Get mac Error via %s.\n", PUSH_MAC_PATH);
		goto FREE_JSON;
	}
	
	snprintf(path, sizeof(path), NOTIFY_CENTER_TEMP_DIR"/ModelName");
	if (f_read_string(path, model, sizeof(model)) < 0) {
		MyDBG("Get Model Name Error.\n");
		snprintf(model, sizeof(model), "%s", "Router");
	}
	
	f_read_string(APP_API_LEVEL_PATH, ver, sizeof(ver));
	
	json_object_object_add(nc, "dev"   , json_object_new_string(model));
	json_object_object_add(nc, "mac"   , json_object_new_string(macStr));
	json_object_object_add(nc, "appver", json_object_new_int(atoi(ver)));
	json_object_object_add(nc, "ncver" , json_object_new_int(NC_VERSION));
	json_object_object_add(nc, "eid"   , json_object_new_string(eID));
	
	if (msg != NULL) {
		json_object_object_add(nc, "msg", msg);
	}
	
	/* aps object */
	json_object_object_add(aps, "alert", alert);
	json_object_object_add(aps, "sound", json_object_new_string("default"));
	json_object_object_add(aps, "content-available", json_object_new_int(1));
	json_object_object_add(aps, "mutable-content"  , json_object_new_int(1));
	json_object_object_add(aps, "category", json_object_new_string(eID));
	
	/* root */
	json_object_object_add(root, "aps", aps);
	json_object_object_add(root, "nc", nc);
	
	if (!argchk)
		json_object_put(arg);
	
	return root;

FREE_JSON:
	
	if (!argchk)
		json_object_put(arg);
	
	json_object_put(aps);
	json_object_put(alert);
	json_object_put(nc);
	json_object_put(msg);
	json_object_put(root);
	return NULL;
}
static char *get_appsid_info(int eID)
{
	static char Info[256];
	char *ret = NULL;
	int  i, x;
	int  act;
	
	act = eInfo_get_eAppsid(eID);
	
	/* Send to all Apps */
	if (act == 0) {
		snprintf(Info, sizeof(Info), "%s", "");
		ret = Info;
		return ret; 
	}
	x = NT_OFF;
	for(i = 0; i < MAX_APPS_NUM; i++) {
		if ((act & 1 << i) && !x) {
			snprintf(Info, sizeof(Info), "%s", appInfo[i].sid);
			ret = Info;
			x = NT_ON;
			continue;
		}
		if ((act & 1 << i) && x) {
			strcat(Info, ",");
			ret = strcat(Info, appInfo[i].sid);
		}
	}
	return ret;
}
static int do_push_msg(void *eInfo)
{
	
	pthread_detach(pthread_self());
	
	int  i = 0;
	int  eID;
	char MsgBuf[PUSH_MSG_MAX_LEN];
	char SendMsgBuf[PUSH_MSG_MAX_LEN];
	PnsSendMsg Psm;
	
	json_object *Push_json = NULL;
	
	NOTIFY_EVENT_T *e = eInfo;
	
	eID = e->event;
	
	if(push_msg_parser()) {
		
		Push_json = generate_push_obj((NOTIFY_EVENT_T *)eInfo);
		
		if(Push_json == NULL) {
			return PSM_PASER_ERR;
		}
		
		snprintf(MsgBuf, sizeof(MsgBuf), "%s",  json_object_to_json_string(Push_json));
		json_object_put(Push_json);
		delspace(MsgBuf, SendMsgBuf);
		MyDBG("[%s][%s][%s][%s]\n", PushConf.server, PushConf.cusid, PushConf.deviceid, PushConf.deviceticket);
		MyDBG("[%s][%s][%s][%s]\n", PushConf.devicetype, PushConf.fwver, PushConf.apilevel, PushConf.modelname);
		MyDBG("<Message>:[%s]\n", SendMsgBuf);
		MyDBG("[AppInfo:[%s]\n", get_appsid_info(eID));
		while(i < 3) {
			memset(&Psm, 0, sizeof(Psm));
			send_pns_sendmsg_req(
				PushConf.server,             /* const char *server       */
				PushConf.cusid,              /* const char *cusid        */
				PushConf.deviceid,           /* const char *deviceid     */
				PushConf.deviceticket,       /* const char *deviceticket */
				get_appsid_info(e->event),   /* const char *appids       */
				"",                          /* const char *todeviceid   */
				PushConf.devicetype,         /* const char *devicetype   */
				PushConf.fwver,              /* const char *fwver        */
				PushConf.apilevel,           /* const char *apilevel     */
				PushConf.modelname,          /* const char *modelname    */
				SendMsgBuf,                  /* const char *msg          */
				&Psm);                       /* PnsSendMsg *pPsm         */
			
			if (!strcmp(Psm.status, "")) { 
				/* No any return value
				   Suspect WAN lose internet */
				MyDBG("[Suspect WAN Disconnect...] Can't get return vaule\n");
				MyDBG("[eID:%x][retry(%d).....]\n", eID, i+1);
				i++;
			} else if (atoi(Psm.status) == PSM_SUCCESS || atoi(Psm.status) == PSM_NO_DEVICE) {
				MyDBG("[eID:%x][RETURN] status:[%d]\n", eID, atoi(Psm.status));
				return atoi(Psm.status);
			} else { 
				/* Other Error on Device Manager Server */
				MyDBG("[eID:%x][RETURN] status:[%d]\n", eID, atoi(Psm.status));
				i++;
			}
		}
	}
	
	return PSM_PASER_ERR;
	
}

static int do_push_ifttt(void *eInfo)
{
	pthread_detach(pthread_self());
	
	int  i = 0;
	int  eID;
	char MsgBuf[PUSH_MSG_MAX_LEN];
	char SendMsgBuf[PUSH_MSG_MAX_LEN];
	char IftttHookBuf[IFTTT_HOOK_MAX_LEN];
	IftttNotification Iftttn;
	
	json_object *ifttt_json = NULL;
	
	NOTIFY_EVENT_T *e = eInfo;
	
	eID = e->event;

	if(!strcmp(pnsInfo_get_iftttMsg(eID), "")) {
		ErrorMsg("[IFTTT HOOK INFO EMPTY]\n");
		return PSM_PASER_ERR;
	} else {
		snprintf(IftttHookBuf, sizeof(IftttHookBuf), "%s", pnsInfo_get_iftttMsg(eID));
		MyDBG("HookInfo:[%s]\n", IftttHookBuf);
	}
	
	ifttt_json = json_tokener_parse(e->msg);
	
	if(ifttt_json != NULL) {
		snprintf(MsgBuf, sizeof(MsgBuf), "%s",  json_object_to_json_string(ifttt_json));
		json_object_put(ifttt_json);
		delspace(MsgBuf, SendMsgBuf);
		MyDBG("<IFTTT Message>:[%s]\n", SendMsgBuf);
	} else {
		ErrorMsg("[TRIGGER MSG FORMAT WRONG]\n");
		json_object_put(ifttt_json);
		return PSM_PASER_ERR;
	}
	
	while(i < 3) {
		memset(&Iftttn, 0, sizeof(Iftttn));
		send_ifttt_notification_req(
			IFTTT_PUSH_SERVER,           /* const char *server       */
			IftttHookBuf,                /* const char *trigger      */
			SendMsgBuf,                  /* const char *msg          */
			&Iftttn);                    /* IftttNotification *pIFTN */
		
		if (!strcmp(Iftttn.status, "")) { 
			/* No any return value
			   Suspect WAN lose internet */
			MyDBG("[Suspect WAN Disconnect...] Can't get return vaule\n");
			MyDBG("[eID:%x][retry(%d).....]\n", eID, i+1);
			i++;
		} else if (atoi(Iftttn.status) == PSM_SUCCESS || atoi(Iftttn.status) == PSM_NO_DEVICE) {
			MyDBG("[eID:%x][RETURN] status:[%d]\n", eID, atoi(Iftttn.status));
			return atoi(Iftttn.status);
		} else { 
			/* Other Error on Device Manager Server */
			MyDBG("[eID:%x][RETURN] status:[%d]\n", eID, atoi(Iftttn.status));
			i++;
		}
	}
	
	return PSM_MATCH_RETRY;
}
#if defined(RTCONFIG_ACCOUNT_BINDING)
static json_object *generate_psr_push_obj(NOTIFY_EVENT_T *eInfo)
{
	enum json_type type;
	
	json_object *root    = NULL;
	json_object *payload = NULL;
	json_object *dev_mac = NULL;
	json_object *msg     = NULL;

	root = json_object_new_object();
	payload = json_object_new_object();
	
	msg = json_tokener_parse(eInfo->msg);
	if(msg == NULL) {
		MyDBG("json_tokener_parse error\n");
		goto FREE_PSR_JSON;
	}
	
	if(root == NULL || payload == NULL) {
		ErrorMsg("json object error\n");
		goto FREE_PSR_JSON;
	}

	dev_mac = json_object_object_get(msg, "device_mac");

	/* root object */
	json_object_object_add(root, "fw_mac", json_object_new_string(get_label_mac()));
	json_object_object_add(root, "state", json_object_new_string(pnsInfo_get_title(eInfo->event)));
	
	if (eInfo->event == GENERAL_DEV_UPDATE) {
		return root;
	} else if (eInfo->event == GENERAL_DEV_DELETED) {
		if(dev_mac != NULL && json_object_is_type(dev_mac, json_type_array)) {
			json_object_object_add(payload, "device_mac", dev_mac);
			json_object_object_add(root, "payload", payload);
		} else {
			ErrorMsg("Error, Msg 'device_mac' is missing or not array type.\n");
			goto FREE_PSR_JSON;
		}
	} else if (eInfo->event == GENERAL_DEV_ACCESS_CHANGE) {
		if(dev_mac != NULL) {
			json_object_object_add(root, "payload", msg);
		} else {
			ErrorMsg("Error, Msg 'device_mac' is missing.\n");
			goto FREE_PSR_JSON;
		}
	}
	return root;

FREE_PSR_JSON:
	
	if(dev_mac != NULL) {
		json_object_put(dev_mac);
	}
	json_object_put(payload);
	json_object_put(msg);
	json_object_put(root);
	return NULL;
}

static int do_push_alexa(void *eInfo)
{
	pthread_detach(pthread_self());
	
	int  i = 0;
	int  eID;
	char MsgBuf[PUSH_MSG_MAX_LEN];
	char SendMsgBuf[PUSH_MSG_MAX_LEN];
	PsrSendMsg Psm;
	
	json_object *Push_json = NULL;
	
	NOTIFY_EVENT_T *e = eInfo;
	
	eID = e->event;
	
	if(push_msg_parser()) {
		
		Push_json = generate_psr_push_obj((NOTIFY_EVENT_T *)eInfo);
		
		if(Push_json == NULL) {
			return PSM_PASER_ERR;
		}
		
		snprintf(MsgBuf, sizeof(MsgBuf), "%s",  json_object_to_json_string(Push_json));
		json_object_put(Push_json);
		delspace(MsgBuf, SendMsgBuf);
		MyDBG("[%s][%s][%s][%s]\n", PushConf.psr_server, PushConf.cusid, PushConf.deviceid, PushConf.deviceticket);
		MyDBG("[%s][%s][%s][%s]\n", PushConf.devicetype, PushConf.fwver, PushConf.apilevel, PushConf.modelname);
		MyDBG("<Message>:[%s]\n", SendMsgBuf);
		while(i < 3) {
			memset(&Psm, 0, sizeof(Psm));
			send_psr_sendmsg_req(
				PushConf.psr_server,         /* const char *psr_server   */
				PushConf.cusid,              /* const char *cusid        */
				PushConf.deviceid,           /* const char *deviceid     */
				PushConf.deviceticket,       /* const char *deviceticket */
				"",                          /* const char *appids       */
				PushConf.devicetype,         /* const char *devicetype   */
				PushConf.fwver,              /* const char *fwver        */
				PushConf.apilevel,           /* const char *apilevel     */
				PushConf.modelname,          /* const char *modelname    */
				SendMsgBuf,                  /* const char *msg          */
				&Psm);                       /* PsrSendMsg *pPsm         */
			
			if (!strcmp(Psm.status, "")) {
				/* No any return value
				   Suspect WAN lose internet */
				MyDBG("[Suspect WAN Disconnect...] Can't get return vaule\n");
				MyDBG("[eID:%x][retry(%d).....]\n", eID, i+1);
				i++;
			} else if (atoi(Psm.status) == PSM_SUCCESS || atoi(Psm.status) == PSM_NO_DEVICE) {
				MyDBG("[eID:%x][RETURN] status:[%d]\n", eID, atoi(Psm.status));
				return atoi(Psm.status);
			} else {
				/* Other Error on Device Manager Server */
				MyDBG("[eID:%x][RETURN] status:[%d]\n", eID, atoi(Psm.status));
				i++;
			}
		}
	}
	
	return PSM_PASER_ERR;
}
#endif

static void do_push_msg_thread(void *eInfo)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start Push Msg thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&do_push_msg, eInfo);
}

static void do_push_ifttt_thread(void *eInfo)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start Push IFTTT thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&do_push_ifttt, eInfo);
}
#if defined(RTCONFIG_ACCOUNT_BINDING)
static void do_push_alexa_thread(void *eInfo)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start Push ALEXA thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&do_push_alexa, eInfo);
}
#endif
#endif

#if defined(RTCONFIG_CHINATEL_EOS)
static void EOSapi(char *type, char *content, char *val)
{
	struct ubus_context *ctx = NULL;
	struct blob_buf b = {};
	ctx = ubus_connect(NULL);
	if(ctx) {
		blobmsg_buf_init(&b);
		blobmsg_add_string(&b, content, val);
		ubus_send_event(ctx, type, b.head);
		blob_buf_free(&b);
		ubus_free(ctx);
	}
}
static int push_EOS_event(NOTIFY_EVENT_T e)
{
	char content[20];
	char val[20];
	char *value;
	json_object *eMsg_json = NULL;

	eMsg_json = json_tokener_parse(e.msg);
	if(eMsg_json == NULL) {
		MyDBG("json_tokener_parse error\n");
		goto EOSEND;
	}
	if(e.event == GENERAL_ETH_DEV_REFUSED) {
		value = get_json_value(eMsg_json, "MacAddr");
		if(value) {
			snprintf(val, sizeof(val), "%s", value);
			MyDBG("MacAddr:[%s]\n", val);
		} else goto EOSEND;
		EOSapi("passworderror", "stamac", val);
	} else if(e.event == GENERAL_SYS_STATES) {
		value = get_json_value(eMsg_json, "content");
		if(value) {
			snprintf(content, sizeof(content), "%s", value);
			MyDBG("content:[%s]\n", content);
		} else goto EOSEND;
		value = get_json_value(eMsg_json, "val");
		if(value) {
			snprintf(val, sizeof(val), "%s", value);
			MyDBG("val:[%s]\n", val);
		} else goto EOSEND;
		EOSapi("propertieschanged", content, val);
	}
	json_object_put(eMsg_json);
	return 1;
EOSEND:
	json_object_put(eMsg_json);
	MyDBG("Parser Error.\n");
	return 0;
}
#endif
static void action_handler(int action, NOTIFY_EVENT_T e)
{
	if((e.event & RESERVATION_EVENT_PREFIX)
	   || ((e.event & GENERAL_EVENT_PREFIX) == GENERAL_EVENT_PREFIX)
	   ) {
		//TODO
	} else {
		/* Write event into NT_DB */
		MyDBG("[IMPORT EVENT INTO DATABASE]\n");
		json_object *root = NULL;
		root = json_tokener_parse(e.msg);
		NOTIFY_DATABASE_T *input_t = initial_db_input();
		input_t->tstamp = e.tstamp;
		input_t->event = e.event;
		input_t->status = 0;
		/* Trigger msg json format validity check */
		if (root != NULL) {
			strncpy(input_t->msg, e.msg, sizeof(input_t->msg)-1);
		} else {
			if (strlen(e.msg)) {
				ErrorMsg("[TRIGGER MSG FORMAT WRONG, WRITE EMPTY INTO DB]\n");
			} else {
				MyDBG("[TRIGGER MSG EMPTY]\n");
			}
			strncpy(input_t->msg, "", sizeof(input_t->msg)-1);
		}
		NT_DBCommand("write", input_t);
		db_input_free(input_t);
		json_object_put(root);
		
	}
	if((action & ACTION_NOTIFY_EMAIL) || (e.event & RESERVATION_EVENT_PREFIX)) {
		MyDBG("[SEND_EMAIL_NOTIFY]\n");
		send_notify_event(&e, NOTIFY_MAIL_SERVICE_SOCKET_PATH);
	}
#ifdef SUPPORT_PUSH_MSG
	if((action & ACTION_NOTIFY_APP)) {
		MyDBG("[PUSH DMS NOTIFY]\n");
		do_push_msg_thread((void *)&e);
	}
	
	if((action & ACTION_NOTIFY_IFTTT)) {
		MyDBG("[PUSH IFTTT NOTIFY]\n");
		do_push_ifttt_thread((void *)&e);
	}
#if defined(RTCONFIG_ACCOUNT_BINDING)
	if(action & ACTION_NOTIFY_ALEXA) {
		MyDBG("[PUSH_ALEXA_NOTIFY]\n");
		char *ptr;
		if((ptr = nvram_get("ifttt_token")) != NULL && *ptr) {
			do_push_alexa_thread((void *)&e);
		} else {
			MyDBG("[skip since ifttt_token as NULL]\n");
		}
	}
#endif
#endif
#if defined(RTCONFIG_CHINATEL_GUANGDONG)
	if(action & ACTION_NOTIFY_GENERAL) {
		MyDBG("[SEND CHINA TELECOM NOTIFY]\n");
		MyDBG("Msg:[%s] strlen:[%d]\n", e.msg, strlen(e.msg));
		send_gd_msg(e.msg, strlen(e.msg));
	}
#endif
#if defined(RTCONFIG_CHINATEL_EOS)
	if(action & ACTION_NOTIFY_GENERAL) {
		MyDBG("[SEND CHINA TELECOM NOTIFY]\n");
		MyDBG("Msg:[%s] strlen:[%d]\n", e.msg, strlen(e.msg));
		push_EOS_event(e);
	}
#endif
}

static void event_handler()
{
	NOTIFY_EVENT_T *listevent;
	NOTIFY_EVENT_T  actevent;
	struct listnode *ln, *next = NULL;
	time_t now;
	char date[30];
	
	listevent = NULL;
	StampToDate(time(&now), date);
	MUTEXLOCK(&event_list_lock);
	for (ln = event_list->head; ln; ln = next)
	{
		next = ln->next;
		if (!(listevent = ln->data)) {
			__listnode_delete(event_list, ln);
			continue;
		}

		send_cnt++;
		MyDBG("[%s]NOTIFY_EVENT[%s (%x)] Action:[%x] MSG:[%s] Num:[%d]\n", date, eInfo_get_eName(listevent->event), listevent->event,
			get_event_action(listevent->event), listevent->msg, send_cnt);
#if PRINT_DEBUG_TO_FILE
		if(GetDebugValue(NOTIFY_CENTER_DEBUG)) {
			char info[200];
			snprintf(info, sizeof(info), "echo \"[Notification_Center][  send  event] [%s] event:[%s (%x)] Action:[%x] MSG:[%s] Num:[%d]\" >> %s",
				date, eInfo_get_eName(listevent->event), listevent->event,
				get_event_action(listevent->event), listevent->msg, send_cnt, NOTIFY_CENTER_LOG_FILE);
			system(info);
		}
#endif
		actevent.event  = listevent->event;
		actevent.tstamp = listevent->tstamp;
		strncpy(actevent.msg, listevent->msg, sizeof(actevent.msg)-1);
		action_handler(get_event_action(listevent->event), actevent);
		__listnode_delete(event_list, ln);
	}
	
	MUTEXUNLOCK(&event_list_lock);
}

static void handlesignal(int signum)
{
	if (signum == SIGUSR1) {
		CONFIG_UPDATE = NT_ON;
	} else if (signum == SIGTERM) {
		terminated = 0;
	} else
		MyDBG("Unknown SIGNAL\n");
	
}

static void signal_register(void) {
	
	struct sigaction sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handlesignal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);    
}

static int esw_init(void)
{
	pEsw = (NT_CHECK_ACTION_T *) malloc(sizeof(NT_CHECK_ACTION_T)* MAX_NOTIFY_EVENT_NUM);
	if(pEsw == NULL) {
		ErrorMsg("pEsw malloc error\n");
		return -1;
	}
	memset(pEsw, 0, sizeof(NT_CHECK_ACTION_T));
	return 0;
}
static void free_esw()
{
	if(pEsw) {
		free(pEsw);
	}
}
static void generate_script_conf()
{
	int i;
	FILE *fp;
	
	system("mkdir -p " NOTIFY_CENTER_TEMP_DIR);

	fp = fopen(EVENTID_SCRIPT_DEFINE_PATH, "w");
	if (fp) {
		fputs("### DO NOT CHANGE THIS CONFIG FILE.\n",fp);
		fputs("### This config have been dynamic generate by nt_center!\n###\n", fp);
		for(i=0; mapInfo[i].value != 0; i++) {
			fprintf(fp, "%s=\"0x%X\"\n", eInfo_get_eName(mapInfo[i].value), mapInfo[i].value);
		}
		fclose(fp);
	} else {
		ErrorMsg("Error, Generate %s failed.\n", EVENTID_SCRIPT_DEFINE_PATH);
		system("touch " EVENTID_SCRIPT_DEFINE_PATH);
	}
	
}
static void load_esw_info()
{
	FILE *fp;
	char *nv = NULL, *nvp = NULL, *b = NULL;
	char *q, *value = NULL;
	char s[2048];
	int  i = 0, subcnt = 0;
	
	/* Clear pEsw */
	memset(pEsw, 0, sizeof(NT_CHECK_ACTION_T));
	
	if ((fp = fopen(NOTIFY_SETTING_CONF, "r")) == NULL) {
		ErrorMsg("[Error] Fail to open %s\n", NOTIFY_SETTING_CONF);
		goto Error_Hanlder;
	}
	
	if (fgets(s, sizeof(s), fp) != NULL) {
		nvp = nv = xstrdup(s);
		while (nv && (b = strsep(&nvp, "<")) != NULL) {
			if (!strlen(b)) 
				continue;
			value = q = b;
			while (b && (value = strsep(&q, ">")) != NULL) {
				if (subcnt == 0 ) { /* eID */
					pEsw[i].event  = strtol(value, NULL, 16);
				} else if (subcnt == 1) { /* Action */
					pEsw[i].action = atoi(value);
				}
				subcnt++;
			}
			//MyDBG("%2d. [e=%X][act=%d] %s\n", i, pEsw[i].event, pEsw[i].action, eInfo_get_eName(pEsw[i].event));
			i++;
			subcnt = 0;
			
		}
		MyDBG("Update Done. Total Event Num: %d\n", i);
		xfree(nv);
		CONFIG_UPDATE = NT_OFF;
		return;
		
	} else {
		ErrorMsg("[Error] fgets return NULL.\n");
		goto Error_Hanlder;
	}
	
Error_Hanlder:
	/* Force Set Default Data */
	for (i=0; mapInfo[i].value != 0 && i < MAX_NOTIFY_EVENT_NUM; i++) {
		pEsw[i].event  = mapInfo[i].value;
		pEsw[i].action = mapInfo[i].action;
	}
	ErrorMsg("[Error] Force Update Done. Total Event Num: %d\n", i);
	CONFIG_UPDATE = NT_OFF;
	return;

}

int  main(void)
{
	char pid[8];
	
	MyDBG("[Start Notification_Center]\n");
	
	/* write pid */
	snprintf(pid, sizeof(pid), "%d", getpid());
	f_write_string(NOTIFY_CENTER_PID_PATH, pid, 0, 0);
	
	/* Signal */
	signal_register();
	
	/* generate config for script */
	generate_script_conf();
	
	/* start unix socket */
	local_socket_thread();
	
	/* record event info*/
	event_list=list_new();
	
	/* init mutex lock switch */
	MUTEXINIT(&event_list_lock);
	
	/* malloc pEsw */
	if(esw_init() < 0) return -1;
	
	/* Get event notify action value */
	load_esw_info();
	
	while(terminated) {
		if(CONFIG_UPDATE) {
			load_esw_info();
		} else {
			event_handler();
		}
		sleep(1);
	}
	
	/* free memory */
	free_esw();
	
	MUTEXDESTROY(&event_list_lock);
	
	MyDBG("Notification_Center Terminated\n");
	
	return 0;
}
