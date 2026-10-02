/* Comment for ASUS Comp. */

#ifndef _AMAS_WLCCONNECT_H_
#define _AMAS_WLCCONNECT_H_

#include "amas_ssd.h"

extern int wlc_dbg;

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#define AMAS_DBG_LOG    "amas_wlcconnect.log"
#define WLC_DBG(fmt, arg...) \
	do {    \
		if(wlc_dbg) \
			dbG("WLC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("wlcconnect_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#define AMAS_BH_LOG    "/jffs/amas_wlcconnect.log"
#define WLC_RUNTIME_LOG(fmt, arg...) \
	do {    \
		if(wlc_dbg) \
			dbG("WLC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("wlcconnect_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
        asusdebuglog(LOG_INFO, AMAS_BH_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#else
#define WLC_DBG(fmt, arg...) \
        do {    \
               if(wlc_dbg) \
                dbG("WLC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("wlcconnect_syslog"), "1")) \
					logmessage("WLC", fmt, ##arg); \
        } while (0)
#define WLC_RUNTIME_LOG(fmt, arg...) \
        do {    \
               if(wlc_dbg) \
                dbG("WLC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("wlcconnect_syslog"), "1")) \
					logmessage("WLC", fmt, ##arg); \
			logmessage("WLC", fmt, ##arg); \
        } while (0)
#endif

#define AMAS_WLCCONNECT_SITESURVEY_TIMEOUT 120  // 2 mins.
#define AMAS_TOTAL_CONNECTION_TIMEOUT 180       // 3 mins.
#define AMAS_GLOBAL_PROFILE_TIMEOUT 30          // 30 seconds.
#define AMAS_CONNECTION_PROFILE_TIMEOUT 180     // 180 seconds.
#define AMAS_DFS_WATTING_TIMEOUT 90             // 90 seconds
#define AMAS_GOOD_AP_RSSI_THRESHOLD -91

#define AMAS_CONNECTION_PROFILE_LOCAL "/jffs/amas_connection_profile"

#define AMAS_WLCCONNECT_IPC_MAX_CONNECTION  10

#define AMAS_SSD_EXIT_WATTING_TIMEOUT	30	// 30 seconds

/**
 * @brief JSON Key for connection profile
 *
 */
#define WLC_CONNECT_STR_PROFILE_NAME    "name"
#define WLC_CONNECT_STR_PROFILE_PRIORITY    "priority"
#define WLC_CONNECT_STR_BANDINDEX    "bandindex"
#define WLC_CONNECT_STR_BAND    "band"
#define WLC_CONNECT_STR_SSID    "ssid"
#define WLC_CONNECT_STR_BSS_ENABLED    "bss_enabled"
#define WLC_CONNECT_STR_WPAPSK    "wpa_psk"
#define WLC_CONNECT_STR_AUTH_MODE_X    "auth_mode_x"
#define WLC_CONNECT_STR_CRYPTO  "crypto"
#define WLC_CONNECT_STR_WEP_X   "wep_x"
#define WLC_CONNECT_STR_MBSS    "mbss"
#define WLC_CONNECT_STR_CLOSED    "closed"
#define WLC_CONNECT_STR_KEY    "key"
#define WLC_CONNECT_STR_KEY1    "key1"
#define WLC_CONNECT_STR_KEY2    "key2"
#define WLC_CONNECT_STR_KEY3    "key3"
#define WLC_CONNECT_STR_KEY4    "key4"
#define WLC_CONNECT_STR_RETRY_COUNT "retry_count"
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
#define WLC_CONNECT_STR_WDS    "amas_wds"
#endif

#ifndef MAC_STR_LEN
#define MAC_STR_LEN	17
#endif

typedef struct amas_ap_cost_s {
    float cost;
    int cost_band;
    float pap_cost;
    float cost_2g;
    float cost_5g;
    float cost_5g1;
    float cost_6g;
} amas_ap_cost_s;
typedef struct amas_sitesurvey_ap_s {
    unsigned int uuid;
    int bandindex;
    int band;
    char ssid[33];
    char bssid[MAC_STR_LEN + 1];
    int cap_role;
    int prefer_device;
    int manual_mode;
    int last_byte_2g;
    int last_byte_5g;
    int last_byte_5g1;
    int last_byte_6g;
    int rssi;
    int channel;
    amas_ap_cost_s cost;
    int RSSIscore;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
    int wds;
#endif
    uint8 bw;
    uint8 connected;
    struct amas_sitesurvey_ap_s *next;
} amas_sitesurvey_ap_s;

/**
 * @brief Kind of amas_wlcconnect process
 *
 */
enum {
    AMAS_WLC_PROCESS_MAIN = 0,
    AMAS_WLC_PROCESS_REQUEST_HANDLER = 1,
    AMAS_WLC_PROCESS_CONNECT_HANDLER = 2
};

/**
 * @brief Process info structure
 *
 */
typedef struct amas_wlc_process_info_s {
    int pid;
    int ppid;
    int type;
    int child_pid[3]; // for wlc0/wlc1/wlc2
} amas_wlc_process_info_s;

extern amas_sitesurvey_ap_s *sitesurvey_ap;

typedef struct amas_ap_profile_s {
    int bandindex;
    int band;
    int priority;
    int connection_fail;
    char ssid[33];
    int bss_enabled;
    char wpa_psk[128];
    char auth_mode_x[128];
    char crypto[128];
    int mbss;
    int closed;
    int wep_x;
    char key[128];
    char key1[128];
    char key2[128];
    char key3[128];
    char key4[128];
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
    int wds;
#endif
    struct amas_ap_profile_s *next;
} amas_ap_profile_s;

extern amas_ap_profile_s *ap_profiles;

typedef struct amas_wlcconnect_bandindex_s {
    int bandindex;
    int use;
    int unit;
    int action;
    int sitesurveying;
    int priority;
    int try_count;
    int dfs_status;
    int dfs_waitting_time;
} amas_wlcconnect_bandindex_s;

typedef enum {
    AMAS_WLCCONNECT_EVENT_CONNECT_2G = 1,   // 0000 0001
    AMAS_WLCCONNECT_EVENT_CONNECT_5G_1 = 2, // 0000 0010
    AMAS_WLCCONNECT_EVENT_CONNECT_5G_2 = 4, // 0000 0100
    AMAS_WLCCONNECT_EVENT_STOP = 64,        // 0100 0000
    AMAS_WLCCONNECT_EVENT_CONNECT_NONE = 0
} amas_wlcconnect_event;

typedef enum {
    AMAS_SITESURVEY_SUCCESS = 0,
    AMAS_SITESURVEY_TIMEOUT = -1,
    AMAS_SITESURVEY_UNEXPECTED_ERROR
} amas_sitesurvey_result;

typedef enum {
    AMAS_WLCCONNECT_STATUS_IDLE = 0,
    AMAS_WLCCONNECT_STATUS_PROCESSING = 1,
    AMAS_WLCCONNECT_STATUS_FINISHED,
    AMAS_WLCCONNECT_STATUS_KEEP_PROCESSING,
    AMAS_WLCCONNECT_STATUS_READY_PROCESSING
} amas_wlcconnect_status;

typedef enum {
    AMAS_WLCCONNECT_WLC_STATUS_INIT = 0, // amas_wlcconnect init.
    AMAS_WLCCONNECT_WLC_STATUS_STOPPED = 1, // No use band
    AMAS_WLCCONNECT_WLC_STATUS_CONN_FAIL = 2, // Tried to connect but fail.
    AMAS_WLCCONNECT_WLC_STATUS_PROCESSING, // Connecting...
    AMAS_WLCCONNECT_WLC_STATUS_CONN_SUCCESS // Connect success
} amas_wlcconnect_wlc_status;

typedef enum {
    AMAS_WLCCONNECT_SUCCESS = 0,
    AMAS_WLCCONNECT_SITESURVEY_FAIL = -1,
    AMAS_WLCCONNECT_CONNECTING_FAIL = -2,
    AMAS_WLCCONNECT_UNEXPECTED_ERROR
} amas_wlcconnect_result;

enum {
    AMAS_WLCCONNECT_CONNECTION_SUCCESS = 0,
    AMAS_WLCCONNECT_CONNECTION_FAIL = 1,
    AMAS_WLCCONNECT_CONNECTION_NO_AP = 2,
    AMAS_WLCCONNECT_CONNECTION_ALLAP_CONNECTED = 3
};

enum {
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_START = 1,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_START_OPTIMIZATION = 2,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_RESTART,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP_OPTIMIZATION,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_DISCONNECT,
    AMAS_WLCCONNECT_ACTION_MODE_KEEP_ALL_CONNECTING,
    AMAS_WLCCONNECT_ACTION_MODE_KEEP_HIGH_PRIORITY_CONNECTING,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_CONNECTING_BY_DRIVER,
    AMAS_WLCCONNECT_ACTION_MODE_ACTION_FOLLOW_CONNECTION
};
#endif
