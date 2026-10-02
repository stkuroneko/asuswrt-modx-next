#include <net/ethernet.h>
#include <netinet/ether.h>

// if 2.4G or 5G connected to P-AP, retry rules for another band.
#define WLC_RETRY_INTERVAL	2		// seconds
#define WLC_RETRY_COUNT 	3		// retry 3 times, per 2 seconds
#define WLC_BACKOFF_COUNT 	30		// retry > 3 times, start BACKOFF count.
#define WLC_STOP_COUNT		90		// stop reconnect for another band.
#define MAX_WIFI_WAIT_TIME	100		// WLC_STOP_COUNT + 10 for amas_bhctrl
#define WLC_CHKSTABLE_COUNT	60		// for stability check.
#define WLC_RESET_COUNT		5		// Waiting seconds for ready to reset connections.
#define WLC_MONITOR_PROFILE_INTERVAL	5 		// seconds

#define WLC_TRY_SECOND_PROFILE_COUNT	10  // start try second profile, if first profile can't connect to P-AP.
/*try to connect to second profile at 10, 40, 70 rounds. retry 3 times. */
#define WLC_RETRY_FH_COUNT 	3		// retry 3 times, per 2 seconds
#define WLC_STATUS_TIMER				2
#define WLC_STATUS_FAIL_COUNT			3
#define WLC_RSSI_FAIL_COUNT				3
#define ETH_STATUS_FAIL_COUNT			3


/*
RETRY_COUNT[j] ==> 0:inital or reset.
				  -1: don't retry start_wlc_connect.
				  -2: wlc_connect has been stopped already, don't call stop_wlc_connect again.
*/
#define RESET_COUNT    0
#define STOP_RETRY    -1
#define STOP_RECONN   -2
#define STOP_BAND     -3
#define STOP_KEEP     -4
#define STOP_WIFI     -5

#define NOTIFY_IDLE 0
#define NOTIFY_CONN 1
#define NOTIFY_DISCONN -1

#if defined(RTCONFIG_DWB)
#define DWB_PROFILE			1  //random generate by cfg_server
#define USER_PROFILE		2  //config by end user
#endif

#if defined (RTAC3200) || defined (RTAC5300) || defined (GTAC5300) || defined (RPAC92)
#define DEFAULT_BAND_PRIORITY "2 0 2 1 5 1 3 0 5 2 1 1" //2.4G index:0, priority:2 use:1 ; 5G1 index:1, priority:3 use:0 ; 5G2 index:2, priority:1 use:1
#else
#define DEFAULT_BAND_PRIORITY "2 0 2 1 5 1 1 1" //2.4G index:0, priority:2 use:1 ; 5G index:1, priority:1 use:1
#endif
#define PARA_COUNT	4

#define BAND_5G		5
#define BAND_2G		2

#define RSSI_SELECT_ABOVE       -75
#define RSSI_SELECT_BELOW       -80
#define RSSI_THRESHOLD          -90

#define FAIL_RATE			0.3
#define SUCCESS_RATE		0.8

#define WORST_SIGNAL_COUNT_THRESHOLD   10

int Pty_get_wlc_status(char *wif);
int Pty_get_upstream_rssi(int band);
void Pty_start_wlc_connect(int band);
void Pty_stop_wlc_connect(int band);
int get_psta_rssi(int unit);

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID    "33716237"
#define APP_KEY   "g2hkhuig238789ajkhc"
#endif

extern pthread_attr_t attr;
extern pthread_attr_t *attrp;

#if defined(PTHREAD_STACK_SIZE_4M)
#define PTHREAD_STACK_SIZE			0x400000
#elif defined(PTHREAD_STACK_SIZE_1M)
#define PTHREAD_STACK_SIZE      	0x100000
#elif defined(PTHREAD_STACK_SIZE_2M)
#define PTHREAD_STACK_SIZE			0x200000
#else
#define PTHREAD_STACK_SIZE  		0x20000
#endif



typedef struct _wl_br_status{
	int defif;
	int band; 		//	2:2.4G,5:5G
	int bandIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char wlcif[32];
	int rssi;
	int state;
	int hop;
	int use; 			// 0:stop connection. 1: try to connect to P-AP
	int RETRY_COUNT;
	int RECORD_COUNT;
	float RETRY_FAILED_COUNT;
	float RETRY_SUCCESS_COUNT;
	float RETRY_FAILED_RATE;
	float RETRY_SUCCESS_RATE;
}wl_br_status,*pwl_br_status;

typedef struct _eth_br_status{
	int defif;
	int ethIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char ethif[32];
	int ethType;
	int state;
	int hop;
}eth_br_status,*peth_br_status;

typedef struct _dpsta_ifinfo {
  int band; 		// 2:2.4G,5:5G
  int bandIndex;	// 0,1,2...
  int priority; 	// 1,2,3...
  int use; 			// 0:stop connection. 1: try to connect to P-AP
}dpsta_info;

typedef struct _signal_handler {
  int bandIndex;
  int bandWidth;
  int rssi_threshold;
}signal_handler;

typedef struct _wlc_status{
	int defif;
	int band; 		//	2:2.4G,5:5G
	int bandIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char wlcif[32];
	int use;
	char last_pap_bssid[18];
	char pap_bssid[18];
	int last_state;
	int state;
	int last_rssi;
	int rssi;
	int last_cost;
	int cost;
	int last_get_cost_result;
	int get_cost_result;
	float getpap_fail_count;
	float getstate_fail_count;
	float getrssi_fail_count;
	float getcost_fail_count;
}wlc_status,*pwlc_status;

typedef struct _eth_status{
	int defif;
	int ethIndex;	// 	0,1,2...
	int priority; 	//	1,2,3...
	char ethif[32];
	int last_state;
	int state;
	int last_cost;
	int cost;
	int last_get_cost_result;
	int get_cost_result;
	float getstate_fail_count;
	float getcost_fail_count;
}eth_status,*peth_status;

extern void init_wlc_status(wl_br_status *wlbrs_list, int SUMband);

extern int Is_dpsta;

extern int cal_space(char *s1);


