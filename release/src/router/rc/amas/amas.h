#include <net/ethernet.h>
#include <netinet/ether.h>


#define STATUS_TIMER					2
#define WLC_STATUS_FAIL_COUNT			3
#define WLC_RSSI_FAIL_COUNT				3
#define ETH_STATUS_FAIL_COUNT			3
#define MONITOR_BACKHAUL_TIMER			2
#define DISCONNECT_LOG_TIME			300	/* second */

#define MAX_WIFI_WAIT_TIME	120
#define MAX_WIFI_BAND_WAIT_TIME	180
#define MAX_PLC_WIFI_WAIT_TIME	600

#if defined (RTAC3200) || defined (RTAC5300) || defined (GTAC5300)
#define DEFAULT_BAND_PRIORITY "2 0 5 1 5 1 4 0 5 2 3 1" //2.4G:2 index:0, priority:4 use:1 ; 5G1:5 index:1, priority:3 use:0 ; 5G2:5 index:2, priority:1 use:1
#else
#define DEFAULT_BAND_PRIORITY "2 0 4 1 5 1 3 1" //2.4G:2 index:0, priority:2 use:1 ; 5G:5 index:1, priority:1 use:1
#endif
#define DEFAULT_ETH_PRIORITY "0 1 1" // eth index:0, priority:1 use:1


#define WIFI_PARA_COUNT	4
#define ETH_PARA_COUNT	3

/*BAND_2G and BAND_5G is for backward compatible*/
#define BAND_2G		2
#define BAND_5G		5

#define BAND_5G1	51
#define BAND_5G2	52


#define ERROR_CODE  -999
#define INIT_CODE	-1000

#define DETECT_NOT_LOOPED_PORT_TIME 60  // 60s

int get_psta_rssi(int unit);
int Pty_get_wlc_status(char *wif);
void Pty_start_wlc_connect(int band, char *bssid);
void post_wlc_connected(int band);
void Pty_stop_wlc_connect(int band);
int amas_dfs_status(int band);
int get_uplinkports_status(char *ifname);

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID    "33716237"
#define APP_KEY   "g2hkhuig238789ajkhc"
#endif

#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
#define AMAS_CHECK_ETH_TIMEOUT		40 // seconds
typedef enum {
	ETH_STATE_INITIALIZING = 0,
	ETH_STATE_PLUGIN = 1,
	ETH_STATE_CONNECTED = 2
} amas_eth_state;
#endif

/**
 * @brief Ethernet port role.
 *
 */
enum {
	ROLE_NONE = 0,
	ROLE_LAN = 1,
	ROLE_WAN = 2,
	ROLE_NOT_DETERMINED,
	ROLE_LAN_LOOP,
	ROLE_PLC_1ST,
	ROLE_MAX
};

enum {
	ETH_CLIENT_TYPE_NONE = 0,
	ETH_CLIENT_TYPE_AIMESH_DEVICE = 1,
	ETH_CLIENT_TYPE_NORMAL_DEVICE
};

enum {
	ETH_LOOP_DETECT_NONE = 0,
	ETH_LOOP_DETECTING = 1,
	ETH_LOOP_DETECTED,
	ETH_LOOP_NOT_DETECTED
};

enum {
	UPIF_TYPE_ETH = 0,
	UPIF_TYPE_WIFI = 1
};

enum {
	BRIDGE_STATUS_SUCCESS = 0,
	BRIDGE_STATUS_FAIL = 1,
	BRIDGE_STATUS_NEED_PROCESS
};

typedef struct _br_status {
	int status;
	int in_br;
} br_status_s, *pbr_status_s;

typedef struct _wl_br_status{
	int defif;
	int band; 		//	2:2.4G,5:5G
	int bandIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char wlcif[32];
	char pap_bssid[18];
	int rssi;
	int optmz_base_rssi;
	int optmz_match_count;
	int state;
	float cost;
	int rssiscore;
	int use; 		// 0:stop connection. 1: try to connect to P-AP
	int isfirst;
	int role;
	br_status_s br_status; // add/del ifname from bridge state
	int keep_conn;
	int unit;
}wl_br_status,*pwl_br_status;

typedef struct _loop_detect {
	int status;
	int loop_detect_count;
	int loop_detect_time;
	int no_find_cap_detect_count;
} loop_detect_s, *ploop_detect_s;

typedef struct _eth_br_status{
	int defif;
	int ethIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char ethif[32];
	int ethType;
	int state;
	float cost;
	int rssiscore;
	int use; 		//0:skip this interface
	int isfirst;
	int isFixedWan;
	int role; // Role
	int role_determine_time;
	int client_type;
	loop_detect_s loop_detect;
	int dest_eth_role; // Destination Ethernet port role.
	br_status_s br_status; // add/del ifname from bridge state
}eth_br_status,*peth_br_status;

typedef struct _wifi_ifinfo {
  int band; 		// 2:2.4G,5:5G
  int bandIndex;	// 0,1,2...
  int priority; 	// 1,2,3...
  int use; 			// 0:stop connection. 1: try to connect to P-AP
}wifi_info;

typedef struct pap_bssid_s {
    char bssid[18];
    char last_bssid[18];
    char bssid_2g[18];
    char bssid_5g[18];
    char bssid_5g1[18];
    char bssid_6g[18];
} pap_bssid_s;

typedef struct _wlc_status{
	int defif;
	int band; 		//	2:2.4G,5:5G
	int bandIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char wlcif[32];
	int use;
	int unit;
	pap_bssid_s pap_bssid;
	int last_state;
	int state;
	int last_rssi;
	int rssi;
	float last_cost;
	float cost;
	float papcost;
	uint8 renew_cost;
	int get_cost_result;
	int last_rssiscore;
	int rssiscore;
	int get_paplastbyte_result;
	int last_get_paplastbyte_result;
	int getpap_fail_count;
	int getstate_fail_count;
	int getrssi_fail_count;
	int getrssiscore_fail_count;
	int getpaplastbyte_fail_count;
	int befollow_bandindex[8];
}wlc_status,*pwlc_status;

typedef struct _eth_ifinfo {
  int ethIndex;		// 0,1,2...
  int priority; 	// 1,2,3...
  int use; 			// 0:stop connection. 1: try to connect to P-AP
}eth_info;

typedef struct _eth_status{
	int defif;
	int ethIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char ethif[32];
	int ethType;
	int use;
	int last_state;
	int state;
	int linkrate;
	int last_linkrate;
	float last_cost;
	float cost;
	float papcost;
	int last_get_cost_result;
	int get_cost_result;
	int last_rssiscore;
	int rssiscore;
	int last_get_rssiscore_result;
	int get_rssiscore_result;
	int getstate_fail_count;
	int getcost_fail_count;
	int getrssiscore_fail_count;
	int isFixedWan;
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
	int chk_internet_timeout;
#endif
}eth_status,*peth_status;


typedef struct _ifi_priority{
	int type;
	int defif;
	int index;
	int priority;
	float cost;
	int rssiscore;
	int isfirst;
}ifi_priority,*pifi_priority;

typedef struct _upstream_default_priority {
  int defif;
  int priority;
}upstream_default_priority;

typedef struct _amas_bhctl_mode {
  char mode_string[64];
  int  mode_mask;
}amas_bhctl_mode;

typedef struct amas_follow_rule_s {
	int band;
	int follow_band;
} amas_follow_rule_s;

extern int cal_space(char *s1);
