#ifndef __CFG_COMMON_H__
#define __CFG_COMMON_H__
#include <json.h>
#include "cfg_lib.h"
#ifdef CONN_DIAG
#include "linklist.h"
#endif

#if defined(RTCONFIG_RALINK_MT7621)
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <sched.h>

#if defined(RTCONFIG_DMALLOC)
#include <dmalloc.h>
#endif

#ifdef __USE_GNU
#ifndef MUSL_LIBC
/* Access macros for `cpu_set'.  */
#define CPU_SETSIZE __CPU_SETSIZE
#define CPU_SET(cpu, cpusetp)   __CPU_SET (cpu, cpusetp)
#define CPU_CLR(cpu, cpusetp)   __CPU_CLR (cpu, cpusetp)
#define CPU_ISSET(cpu, cpusetp) __CPU_ISSET (cpu, cpusetp)
#define CPU_ZERO(cpusetp)       __CPU_ZERO (cpusetp)
#endif 	// !MUSL_LIBC

#ifdef MUSL_LIBC
typedef pid_t __pid_t;
#endif	// MUSL_LIBC

/* Set the CPU affinity for a task */
extern int sched_setaffinity (__pid_t __pid, size_t __cpusetsize,
                              __const cpu_set_t *__cpuset) __THROW;

/* Get the CPU affinity for a task */
extern int sched_getaffinity (__pid_t __pid, size_t __cpusetsize,
                              cpu_set_t *__cpuset) __THROW;
#endif
#endif

typedef struct _CM_CTRL {
	int flagIsTerminated;           /* if terminate CM daemon */
	int flagIsRunning;           	/* if handler is running */
	int flagIsFirmwareCheck;	/* if check firmware */
	int socketTCPSend;              /* used to send/rcv TCP frame */
	int socketUdpSendRcv;           /* used to send/rcv UDP frame */
	int socketIpcSendRcv;		/* used to send/rcv frame from IPC */
	struct in_addr ownAddr;         /* IP address of ethernet interface */
	struct in_addr broadcastAddr;   /* broadcast address of ethernet interface */
	char brIfMac[32];		/* br0 mac address */
	pid_t pid;                      /* CM task PID */
	unsigned char *publicKey;       /* used to save public key for CM */
	size_t publicKeyLen;            /* used to save the length of public key for CM */
	unsigned char *privateKey;      /* used to save private key for CM */
	size_t privateKeyLen;           /* used to save the length of private key for CM */
	unsigned char *sessionKey;	/* used to save session key for CM */
	time_t sessionKeyStartTime;	/* the start time of session key */
	unsigned char *sessionKey1;	/* used to save session key 1 for CM */
	time_t sessionKey1StartTime;	/* the start time of session key 1 */
	size_t sessionKeyLen;		/* used to save the length of public key for CM */
	int sessionKeyReady;		/* used to check session key is ready or not */
 	unsigned char *groupKey;        /* used to save group key for CM */
	time_t groupKeyStartTime;       /* the start time of group key */
 	unsigned char *groupKey1;        /* used to save group key 1 for CM */
	time_t groupKey1StartTime;       /* the start time of group key 1 */
	size_t groupKeyLen;             /* used to save the length of group key for CM */
	int groupKeyReady;		/* used to check group key is ready or not */
	unsigned int role;		/* role for server or client */
	int cost;		/* used to save the cost of network topology */
} CM_CTRL, *P_CM_CTRL;

extern int port;
extern CM_CTRL cm_ctrlBlock;
#ifdef ONBOARDING
extern int obTimeStamp;
#endif

#ifdef RTCONFIG_DWB
extern int dwb_reSync;
#endif

extern pthread_attr_t attr;
extern pthread_attr_t *attrp;
#if defined(PTHREAD_STACK_SIZE_4M) || defined(PTHREAD_STACK_SIZE_2M) || defined(PTHREAD_STACK_SIZE_1M) || defined(PTHREAD_STACK_SIZE_512K) || defined(PTHREAD_STACK_SIZE_256K)
#if defined(PTHREAD_STACK_SIZE_4M)
#define PTHREAD_STACK_SIZE	0x400000
#elif defined(PTHREAD_STACK_SIZE_1M)
#define PTHREAD_STACK_SIZE      0x100000
#elif defined(PTHREAD_STACK_SIZE_512K)
#define PTHREAD_STACK_SIZE      0x80000
#elif defined(PTHREAD_STACK_SIZE_256K)
#define PTHREAD_STACK_SIZE      0x40000
#else
#define PTHREAD_STACK_SIZE	0x200000
#endif
#endif

typedef struct TLV_Header_t
{
	unsigned int type;
	unsigned int len;
	unsigned int crc;
} __attribute__((__packed__)) TLV_Header;

enum packetType {
	REQ_KU = 1,
	RES_KU,
	REQ_NC,
	RES_NC,
	REP_OK,
	ACK_OK,
	RES_NAK,
	REQ_CHK,
	RSP_CHK,
	ACK_CHK,
	REQ_REK,
	REP_REK,
	REQ_NTF,
	RSP_NTF,
	REQ_JOIN,
	RSP_JOIN,
	ACK_JOIN,
	REQ_RPT,
	RSP_RPT,
	REQ_GKEY,
	RSP_GKEY,
	ACK_GKEY,
	REQ_GREKEY,
	RSP_GREKEY,
	REQ_WEVENT,
	RSP_WEVENT,
	REQ_STALIST,
	RSP_STALIST,
	REQ_FWSTAT,
	RSP_FWSTAT,
	REQ_CHANSYNC,
	RSP_CHANSYNC,
	ACK_CHANSYNC,
	REQ_COST,
	RSP_COST,
	REQ_CLIENTLIST,
	RSP_CLIENTLIST,
	REQ_ONBOARDING,
	RSP_ONBOARDING,
	REQ_GROUPID,
	RSP_GROUPID,
	ACK_GROUPID,
	REQ_SREKEY,
	RSP_SREKEY,
	REQ_TOPOLOGY,
	RSP_TOPOLOGY,
	REQ_RADARDET,
	RSP_RADARDET,
	REQ_RELIST,
	RSP_RELIST,
	REQ_APLIST,
	RSP_APLIST,
	REQ_DBLIST,
	RSP_DBLIST,
	REQ_CHANGED_CONFIG,
	RSP_CHANGED_CONFIG,
	REQ_BACKHUALSTATUS,
	RSP_BACKHUALSTATUS,
	REQ_LEVEL,
	RSP_LEVEL,
	REP_MSG = 98,
	ACK_MSG = 99
};

enum udpPktType {
	/* for roaming */
	REQ_STAMON = 1,
	RSP_STAMON,
	REQ_ACL,
	REQ_STAFILTER,
	REQ_CHKSTA,
	RSP_CHKSTA,
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
	REQ_EXAPCHECK,
#endif
	REQ_MAX
};

#define KEY_LENGTH		32
#define MAX_PACKET_SIZE		16384
#define MAX_MESSAGE_SIZE	16368	// 16384(MAX_PACKET_SIZE) - tlv size(12) - 4 (16 remainder)
#define SESSION_KEY_EXPIRE_TIME		3600//(12 * 60 * 60)	// 12 hours
#define REKEY_TIME(x)			x*7/8
#define GROUP_KEY_EXPIRE_TIME		3600
#define CFG_ACTION_TIMEOUT	1
#define KEY_CHECK_TIMES		10
#define REPORT_STALIST_INTERVAL	150	// second
#define REPORT_CLIENTLIST_INTERVAL		30 // second
#define CHECK_KEY_INTERVAL	60
#ifdef RADAR_DET
#define UPDATE_AVAIL_CHANNEL_INTERVAL	30 // second
#endif /* RADAR_DET */
#define REPORT_WEVENT_INTERVAL	2
#define DEFAULT_AGEING_TIMER	20
#define DEFAULT_RE_AGEING_TIMER	45
#define UPDATE_CHANSPEC_INTERVAL	30 // second
#define CHECK_RE_STATUS_INTERVAL        30 // second
#define CHECK_CLIENTLIST_INTERVAL		10 // second
#ifdef RTCONFIG_BHCOST_OPT
#define CHECK_RE_SELF_OPT_INTERVAL        60 // second
#endif

/* type in the content of packet */
#if 0
#define MASTER_KEY	1
#define SERVER_NONCE	2
#define CLIENT_NONCE 	3
#endif
enum messageType {
	/* for session key */
	MASTER_KEY = 1,
	SERVER_NONCE,
	CLIENT_NONCE,

	/* for notification */
	NOTIFY_CHECK,
	NOTIFY_REKEY,
	NOTIFY_CFGACT,
	NOTIFY_GREKEY,
	NOTIFY_FWCHECK,
	NOTIFY_FWDOWNLOAD,
	NOTIFY_FWCHECKSTATUS,
	NOTIFY_FWDOWNLOADSTATUS,
	NOTIFY_FWUPGRADE,
	NOTIFY_CANCELFWCHECK,
	NOTIFY_CANCELFWUPGRADE,
	NOTIFY_FWCHECKSUCCESS,
	NOTIFY_RESETDEFAULT,
	NOTIFY_ONBOARDING,
	NOTIFY_REQUESTCOST,
	NOTIFY_CFGCHANGED,
	NOTIFY_STARTWPS,
	NOTIFY_REQUESTTOPOLOGY,
	NOTIFY_WLCRECONNECT,
	NOTIFY_FEEDBACK,
	NOTIFY_UPDATERELIST,
	NOTIFY_UPDATEAPLIST,
	NOTIFY_UPDATEDBLIST,
	NOTIFY_SELF_OPTIMIZATION,
	NOTIFY_REBOOT,
	NOTIFY_ACTION,
	NOTIFY_UPDATE_STA_BINDING,
	NOTIFY_REQUESTBACKHUALSTATUS,
	NOTIFY_ONBOARDING_VIF_DOWN = 32,
	NOTIFY_REQUESTLEVEL = 33,
	NOTIFY_MAX
};

/**
 * @brief Interface type. Root/Guest/...
 *
 */
enum infType {
	INF_TYPE_ROOT = 0,
	INF_TYPE_GUEST = 1,
	INF_TYPE_MAX
};

struct STINFO_t { int st; char *name; };
static struct STINFO_t STINFO_TBL[] =
{
	{ REQ_KU,	"REQ_KU" },
	{ RES_KU,	"RES_KU" },
	{ REQ_NC,	"REQ_NC" },
	{ RES_NC,	"RES_NC" },
	{ REP_OK,	"REP_OK" },
	{ REP_OK,	"REP_OK" },
	{ ACK_OK,	"ACK_OK" },
	{ RES_NAK,	"RES_NAK" },
	{ REQ_CHK,	"REQ_CHK" },
	{ RSP_CHK,	"RSP_CHK" },
	{ ACK_CHK,	"ACK_CHK" },
	{ REQ_REK,	"REQ_REK" },
	{ REP_REK,	"REP_REK" },
	{ REQ_NTF,	"REQ_NTF" },
	{ RSP_NTF,	"RSP_NTF" },
	{ REQ_JOIN,	"REQ_JOIN" },
	{ RSP_JOIN,	"RSP_JOIN" },
	{ ACK_JOIN,	"ACK_JOIN" },
	{ REQ_RPT,	"REQ_RPT" },
	{ RSP_RPT,	"RSP_RPT" },
	{ REQ_GKEY,	"REQ_GKEY" },
	{ RSP_GKEY,	"RSP_GKEY" },
	{ ACK_GKEY,	"ACK_GKEY" },
	{ REQ_GREKEY,	"REQ_GREKEY" },
	{ RSP_GREKEY,	"RSP_GREKEY" },
	{ REQ_WEVENT,	"REQ_WEVENT" },
	{ RSP_WEVENT,	"RSP_WEVENT" },
	{ REQ_STALIST,	"REQ_STALIST" },
	{ RSP_STALIST,	"RSP_STALIST"},
	{ REQ_FWSTAT,	"REQ_FWSTAT" },
	{ RSP_FWSTAT,	"RSP_FWSTAT" },
	{ REQ_CHANSYNC,	"REQ_CHANSYNC" },
	{ RSP_CHANSYNC, "RSP_CHANSYNC" },
	{ ACK_CHANSYNC,	"ACK_CHANSYNC" },
	{ REQ_COST,	"REQ_COST" },
	{ RSP_COST,	"RSP_COST" },
	{ REQ_CLIENTLIST,	"REQ_CLIENTLIST" },
	{ RSP_CLIENTLIST,	"RSP_CLIENTLIST" },
	{ REQ_ONBOARDING,	"REQ_ONBOARDING" },
	{ RSP_ONBOARDING,	"RSP_ONBOARDING" },
	{ REQ_GROUPID,	"REQ_GROUPID" },
	{ RSP_GROUPID,	"RSP_GROUPID" },
	{ ACK_GROUPID,	"ACK_GROUPID" },
	{ REQ_SREKEY,	"REQ_SREKEY" },
	{ RSP_SREKEY,	"RSP_SREKEY" },
	{ REP_MSG,	"REP_MSG" },
	{ ACK_MSG,	"ACK_MSG" },
	{ REQ_TOPOLOGY, "REQ_TOPOLOGY"},
	{ RSP_TOPOLOGY, "RSP_TOPOLOGY"},
	{ REQ_RADARDET, "REQ_RADARDET"},
	{ RSP_RADARDET, "RSP_RADARDET"},
	{ REQ_RELIST, "REQ_RELIST"},
	{ RSP_RELIST, "RSP_RELIST"},
	{ REQ_APLIST, "REQ_APLIST"},
	{ RSP_APLIST, "RSP_APLIST"},
	{ REQ_DBLIST, "REQ_DBLIST"},
	{ RSP_DBLIST, "RSP_DBLIST"},
	{ REQ_CHANGED_CONFIG,	"REQ_CHANGED_CONFIG" },
	{ RSP_CHANGED_CONFIG,	"RSP_CHANGED_CONFIG" },
	{ REQ_BACKHUALSTATUS, "REQ_BACKHUALSTATUS"},
	{ RSP_BACKHUALSTATUS, "RSP_BACKHUALSTATUS"},
	{ REQ_LEVEL,	"REQ_LEVEL" },
	{ RSP_LEVEL,	"RSP_LEVEL" },
	{ -1,		NULL }
};

#define ENDOF_STINFO(__STINFO__) (__STINFO__->st == -1 || __STINFO__->name == NULL)
#define ST_NAME	(getStname(ntohl(tlv.type)))

static __attribute__ ((unused)) char *getStname(int state)
{
	struct STINFO_t *P = (struct STINFO_t *)&STINFO_TBL[0];
	while (!ENDOF_STINFO(P))
	{
		if (P->st == state)
		{
			return P->name;
		}
		P++;
	}
	return NULL;
}

/* cfg_common.c */
extern char *get_hwaddr(const char *ifname);
extern char *get_lan_ipaddr();
extern char *get_portno_by_ifname();
extern void add_brforward_entry_by_port(json_object *root, char *portIndex);
extern int key_atoe(const char *a, unsigned char *e);
extern char * key_etoa(const unsigned char *e, char *a);
extern int ip_atoe(const char *a, unsigned char *e);
extern unsigned long getFileSize(char *FileName);
extern int fileExists(char *FileName);
extern char *AdvTrim(char *szSource);
extern char* dumpHEX(unsigned char *src, unsigned long src_size);
extern char *wl_ifindex_to_ifnames(char *ifindex, int *out_len);
extern char *wl_ifnames_to_ifindex(char *ifnames, int *out_len);
extern int wl_macfilter_is_allow_mode();
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
extern void convert_smac_for_traffic(int unit, unsigned char *smac);
#endif
extern int get_re_unique_mac(unsigned char *msg, char *mac, int macLen);
extern int get_join_unique_mac(unsigned char *msg, char *mac, int macLen);
extern int get_wired_port_status(json_object *wired_port_status);
extern int search_in_array_list(char *key, json_object *list, int list_count);
extern void add_all_to_array_list(json_object *input, json_object *list);
#ifdef PLC_STATUS
extern int get_plc_status(json_object *plc_status);
#endif	/* PLC_STATUS */
extern void set_channel_sync_status(int unit, int status);
extern int check_radio_status_by_unit(int unit);
extern char *convert_misc_info_to_json_str(char *miscInfo);
extern char *get_fh_ap_ifname_by_unit(int unit);
extern char *get_fh_ap_ssid_by_unit(int unit);
extern int  check_band_unit(int bandtype);
extern void check_band_type();
extern int check_have_XG(int target_type);
extern char *cap_get_final_paramname(char *mac, char *input_param,int reBandNum , char *finalparamname, int finalparamnamelen);
extern char *cap_get_re_final_paramname(char *mac, char *input_param,int reBandNum , char *finalparamname, int finalparamnamelen);
extern char *get_rebandtype_chanspc_by_unit (char *mac, int unit ,int reBandNum , char *rebandtype, int rebandtypeLen);
extern int get_unit_chanspc_by_bandtype (char *mac, char *bandtype);
extern int check_match_6G(char *mac);
extern int check_own_unit(int bandtype);
extern int Add_missing_parameter(json_object *outRoot, int private,char *mac,int reBandNum, int cfgband_Ver,json_object *cfgAllObj,json_object *fileRoot);
extern int Add_missing_parameter_patch(json_object *outRoot, int private,char *mac,int reBandNum, int cfgband_Ver,json_object *cfgAllObj,json_object *fileRoot);
extern int get_wl_bandindex_by_unit(json_object *cfgRoot, int unit, int cfgbandType_num, int cfgband_Ver);
extern int get_5g_unit();

//extern char *if_nametoalias(char *name, char *alias, int alias_len);
extern int str2hex(const char *a, unsigned char *e, int len);
#ifdef ONBOARDING
extern unsigned char *get_onboarding_key();
#endif
extern void update_lldp_cost(int cost);
#ifdef PRELINK
extern void update_lldp_hash_bundle_key();
extern int check_default_hash_bundle_key();
extern unsigned char *get_prelink_key();
extern void regen_hash_bundle_key();
extern int verify_hash_bundle_key(char *key);
#endif
#ifdef RTCONFIG_SW_HW_AUTH
extern int check_auth();
#endif	/* RTCONFIG_SW_HW_AUTH */
extern char *get_re_hwaddr();
extern char *nvram_decrypt_get(const char *name);
extern void nvram_encrypt_set(const char *name, char *value);
extern int read_tcp_message(int sock, void *pBuf, int bufLen);
extern char *get_unique_mac();
extern char *wl_ifindex_to_bsd_ifnames(char *ifindex, int *out_len);

/* sysdeps */
extern int wl_sta_list(char *msg, int msg_len);
extern int wl_sta_rssi_list(json_object *root);
extern void wl_control_channel(int unit, int *channel, int *bw, int *nctrlsb);
#if defined(SYNC_WCHANNEL)
extern void sync_control_channel(int unit, int channel, int bw, int nctrlsb);
#endif
extern int get_wsc_status(int *fail_result);
//extern void add_beacon_vsie(char *oui, char *hexdata);
//extern void del_beacon_vsie(char *oui, char *hexdata);
extern char *get_pap_bssid(int unit, char *bssid_buf, int buf_len);
extern int get_pap_rssi(int unit);
extern char *get_sta_mac(int unit);
extern void wl_set_macfilter_list();
extern void wl_set_macfilter_mode(int allow);
#ifdef RTCONFIG_DWB
extern char *get_dwb_bssid(int bandnum, int unit, int subunit);
#endif
extern int wl_get_chans_info(int unit, char* buf, size_t len);
extern void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec);
extern char *get_pap_ssid(int unit, char *ssid_buf, int buf_len);
extern char *get_ap_ssid(int unit, char *ssid_buf, int buf_len);
#if defined(RTCONFIG_QCA)
extern int wl_set_ch_bw(const char *ifname, int channel, int bw, int nctrlsb);
#endif
extern int get_uplinkport_describe(char *ifname);
#ifdef RTCONFIG_NBR_RPT
extern int wl_get_nbr_info(char* buf, size_t len);
#endif
extern int delClientArp(char *clientIp);

/* cfg_cliet.c/cfg_server.c */
unsigned char *cm_selectGroupKey(int keyIndex);
extern int cm_checkGroupKeyExpire();
extern int cm_sendTcpPacket(int pktType, unsigned char *msg);
extern void cm_handleFirmwareCheck();
extern void cm_handleFirmwareDownload();
extern void cm_removeSlave(char *mac);
extern void cm_resetDefault(char *mac);
extern void cm_handleOnboarding(char *data);
extern void cm_startWps(char *ip);
#ifdef ONBOARDING
extern void cm_processOnboardingMsg(char *msg);
extern int cm_validateOnboardingRe(char *reMac);
#endif /* ONBOARDING */
extern void cm_notifyConfigChanged(char *mac);
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
extern void cm_mac2ip(char *mac,char *ip, int len);
#endif
extern int cm_requestTopology(void);
extern int cm_reportConnStatus(void);
extern void cm_updateTopology(void);
#ifdef RADAR_DET
extern void cm_processRadarDetection(void);
#endif	/* RADAR_DET */
extern void cm_updateFirmwareVersion(char *firmVer);
extern int cm_checkClientStatus(char *mac);
extern void cm_feedback();
extern void cm_configChanged(unsigned char *data);
#ifdef RTCONFIG_DWB
extern void cm_updateDwbInfo();
#endif
extern void cm_updateDutChanspecs();
#ifdef RTCONFIG_BHCOST_OPT
extern void cm_selfOptimize(char *mac);
#endif
extern void cm_notifyReboot(json_object *macListObj);
extern void cm_notifyAction(int eid, json_object *macListObj, json_object *dataObj);
extern void cm_setStatePending();
extern int cm_reExistInClientList(char *reMac);
extern void cm_updateDutInfo();

/* cfg_wevent.c */
extern void cm_processStaList(char *msg);
extern int cm_prepareStaListMsg(char *msg, int msgLen);
extern int cm_prepareWeventMsg(char *msg, int msgLen);
extern int cm_processWevent(char *msg);

/*cfg_dwb.c*/
extern int cm_Dedicated_Wifi_Backhaul_Parameter();
extern void cm_transDedicated_Wifi_Backhaul_Parameter(char *mac, int reBandNum, json_object *outRoot);
extern int Do_Setting_WiFi_Backhual_Parameter(struct json_object *cfgRoot);
extern void Set_transDedicated_Wifi_Backhaul_Parameter(json_object *cfgRoot, int *dwb_change);
extern int cm_AutoDetect_Dedicated_Wifi_Backhaul(int checkpoint, int doAction);
extern int Is_dwb_para(json_object *cfgRoot, char *prefix,  char *parameter);
#ifdef SMART_CONNECT
extern void cm_resetRESmartConnectBsdifnames(struct json_object *cfgRoot, char *bsd_ifnames, int bsd_ifnames_len);
extern void cm_resetRESmartConnectIfPolicy(struct json_object *cfgRoot, char *key, char **if_select_policy);
#endif
#ifdef RTCONFIG_FRONTHAUL_DWB
extern int Process_DWB_Fronthaul_AP(void);
extern void check_fronthaul_dwb_value(void);
#endif

#ifdef RTCONFIG_BCN_RPT
extern void cm_updateAPList();
#endif
#if defined(RTCONFIG_RALINK_MT7621)
extern void Set_CPU(void);
#endif

/* for role */
#define SERVER_PROGNAME		"cfg_server"
#define CLIENT_PROGNAME		"cfg_client"
enum cfgRole {
	IS_UNKNOWN = 0,
	IS_SERVER,
	IS_CLIENT
};

#include "cfg_string.h"

/* temp info for stored */
#define TEMP_ROOT_PATH		"/tmp"

/* for lan ifname */
#define LAN_IFNAME	"br0"

/* for vendor name */
#define VENDOR_BCM	"BCM"
#define VENDOR_MTK	"MTK"
#define VENDOR_RTK	"RTK"
#define VENDOR_QCA	"QCA"
#define VENDOR_ITL	"ITL"
#define VENDOR_LTQ	"LTQ"
#if defined(CONFIG_BCMWL5)
#define VENDOR_NAME	VENDOR_BCM
#elif defined(RTCONFIG_RALINK)
#define VENDOR_NAME	VENDOR_MTK
#elif defined(RTCONFIG_QCA)
#define VENDOR_NAME	VENDOR_QCA
#elif defined(RTCONFIG_REALTEK)
#define VENDOR_NAME	VENDOR_RTK
#elif defined(RTCONFIG_INTEL)
#define VENDOR_NAME	VENDOR_ITL
#elif defined(RTCONFIG_LANTIQ)
#define VENDOR_NAME     VENDOR_LTQ
#else
#error "TODO for define VENDOR_NAME"
#endif

/* for bandwidth capability */
#if defined(RTCONFIG_BCMWL6)
#define BW_CAP		1	/* new, 0/1/2/3 auto/20/40/80MHz */
#else
#define BW_CAP		0	/* old, 1/0/2/3 auto/20/40/80MHz */
#endif

#ifdef PRELINK
/* for prelink */
#define HASH_BUNDLE_KEY_HEX_LEN		20
#define HASH_BUNDLE_KEY_STR_LEN		41
#endif
enum keyType {
	KEY_IS_UNKNOWN = 0,
	KEY_IS_ONBOARDING,
	KEY_IS_PRELINK
};


#ifdef ROAMING_INFO
/* for sta roaming info */
extern json_object *staRoamingInfo;
#endif

/* for thread lock */
extern pthread_mutex_t weventLock;		/* for wireless event */
extern pthread_mutex_t allWeventLock;		/* for all wireless event */
extern pthread_mutex_t wiredClientListLock;		/* for wired client list */
extern pthread_mutex_t clientListLock;		/* for client list */
#ifdef ONBOARDING
extern pthread_mutex_t onboardingLock;		/* for onboarding */
#endif
extern pthread_mutex_t radarDetLock;		/* for radar detect */
#ifdef ROAMING_INFO
extern pthread_mutex_t roamingInfoLock;		/* for romaing info */
#endif
#ifdef LEGACY_ROAMING
extern pthread_mutex_t roamingLock;		/* for romaing */
#endif
extern pthread_mutex_t reListLock;		/* for re list */
extern pthread_mutex_t chanspecLock;		/* for chanspec */
#ifdef DUAL_BAND_DETECTION
extern pthread_mutex_t dualBandLock;		/* for wireless dual band */
#endif
#ifdef PRELINK
extern pthread_mutex_t prelinkLock;		/* for prelink */
#endif
extern pthread_mutex_t changedConfigLock;	/* for changed config */
#ifdef RTCONFIG_NBR_RPT
extern pthread_mutex_t nbrRptLock;		/* for neighbor report */
#endif
#ifdef CONN_DIAG
extern pthread_mutex_t connDiagLock;	/* for conn diag from udp */
#endif

/* for band number */
extern int supportedBandNum;

/* for 5g low/high band selection */
extern int selected5gBand;
#define THRESHOLD_5G_LOW_HIGH	100
enum selection5gBand {
	NO_SELECTION = 0,
	LOW_BAND_5G,
	HIGH_BAND_5G
};

/* cfg_nvram_set */
#ifndef cfg_nvram_set
#define cfg_nvram_set(__KEY__, __STRVAL__) do {\
	if (nvram_get(__KEY__) != NULL) nvram_set(__KEY__, __STRVAL__);\
}while(0)
#endif 	/* !cfg_nvram_set */

/* cfg_nvram_set_int */
#ifndef cfg_nvram_set_int
#define cfg_nvram_set_int(__KEY__, __INTVAL__) do {\
	if (nvram_get(__KEY__) != NULL) nvram_set_int(__KEY__, __INTVAL__);\
}while(0)
#endif 	/* !cfg_nvram_set_int */

#ifdef RTCONFIG_BCN_RPT
#define AP_LIST_JSON_FILE	"/tmp/aplist.json"
#endif
#if (defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS))
#define CFG_MNT_FOLDER		"/jffs/.sys/cfg_mnt/"
#else
#define CFG_MNT_FOLDER		"/tmp/cfg_mnt/"
#endif
#define MISC_INFO_JSON_PATH	"/tmp/misc.json"

enum wifLastByte {
	LAST_BYTE_2G = 0,
	LAST_BYTE_5G = 1,
	LAST_BYTE_5G1 = 2,
	LAST_BYTE_6G = 3
};

#ifdef CONN_DIAG
extern struct list *connDiagUdpList;
#endif

struct wlsuffix_mapping_s {
	char *name;
	char *converted_name;
};

static struct wlsuffix_mapping_s wlsuffix_mapping_list[] __attribute__ ((unused)) = {
	{ "ssid",		NULL },
	{ "wpa_psk",	NULL },
	{ "crypto",	NULL },
	{ "auth_mode_x",	"auth_mode" },
	{ "wep_x",		"wep" },
	{ "key",		NULL },
	{ "key1",		NULL },
	{ "key2",		NULL },
	{ "key3",		NULL },
	{ "key4",		NULL },
	{ "macmode", NULL },
	{ "maclist_x", NULL },
	{ "closed", NULL },
	{ "radius_ipaddr", NULL },
	{ "radius_key", NULL },
	{ "radius_port", NULL },
	{ NULL, 		NULL }
};

struct wlsuffix_guess_mapping_s {
	char *name;
	char *converted_name;
};

static struct wlsuffix_guess_mapping_s wlsuffix_guess_mapping_list[] __attribute__ ((unused)) = {
	{ "ssid",		NULL },
	{ "closed",	NULL },
	{ "wpa_psk",	NULL },
	{ "auth_mode_x",	"auth_mode" },
	{ "bss_enabled",	NULL },
	{ "crypto",		NULL },
	{ "expire",		NULL },
	{ "lanaccess",		NULL },
	{ "macmode",		NULL },
	{ "maclist_x",		NULL },
	{ "bw_enabled",		NULL },
	{ "bw_ul",		NULL },
	{ "bw_dl",		NULL },
	{ "ap_isolate",		NULL },
	{ "sync_node",		NULL },
	{ NULL, 		NULL }
};

#endif /* __CFG_COMMON_H__ */
/* End of cfg_common.h */
