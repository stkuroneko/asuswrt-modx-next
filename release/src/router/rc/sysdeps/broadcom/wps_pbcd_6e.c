/*
 * Application to monitor the board PBC button
 * for WPS operation, it will interact with
 * HOSTAPD for wps processing.
 *
 * Copyright (C) 2021, Broadcom. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: wps_pbcd.c 795731 2021-02-12 12:51:25Z $
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include <bcmutils.h>
#include <bcmnvram.h>
#include <wlutils.h>
#include <shutils.h>
#include <common_utils.h>
#include <wlif_utils.h>
#include <wpa_ctrl.h>
#include <bcm_usched.h>

#ifdef BCA_HNDROUTER
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <board.h>
#endif	/* BCA_HNDROUTER */

#include <hostapd_config.h>

#include <arpa/inet.h>
#include <security_ipc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <wlioctl.h>
#include <ctype.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ				16
#endif	/* IFNAMSIZ */

#ifdef HAPD_WDS
#define WDS_DEV_NAME				"wds"
#endif /* HAPD_WDS */

#define MAX_OCE_RRM_NBR_ELMNTS			5 /* max no of rrm_nbr entries added to an iface */
#define SSID_FMT_BUF_LEN			((4 * 32) + 1)	/* Length for SSID format string */

struct escan_bss {
	struct escan_bss *next;
	wl_bss_info_t bss[1];
};

#define PBCD_ERR_MSG				0x0001
#define PBCD_INFO_MSG				0x0002
#define PBCD_DBG_MSG				0x0004
#define PBCD_EVT_MSG				0x0008
#define PBCD_DBG_DETAIL_MSG			0x0010

int wps_pbcd_msglevel = PBCD_ERR_MSG;

#define PBCD_PRINT(label, fmt, arg...)	printf(label"PBCD %s "fmt, __func__, ##arg)

#define PBCD_ERR(fmt, arg...) \
	if (wps_pbcd_msglevel & PBCD_ERR_MSG) \
		PBCD_PRINT("Error: ", fmt, ##arg)

#define PBCD_INFO(fmt, arg...) \
	if (wps_pbcd_msglevel & PBCD_INFO_MSG) \
		PBCD_PRINT("Info: ", fmt, ##arg)

#define PBCD_DBG(fmt, arg...) \
	if (wps_pbcd_msglevel & PBCD_DBG_MSG) \
		PBCD_PRINT("Debug: ", fmt, ##arg)

#define PBCD_EVT_DBG(fmt, arg...) \
	if (wps_pbcd_msglevel & PBCD_EVT_MSG) \
		PBCD_PRINT("Debug: ", fmt, ##arg)

#define PBCD_DBG_DETAIL(fmt, arg...) \
	if (wps_pbcd_msglevel & PBCD_DBG_DETAIL_MSG) \
		PBCD_PRINT("Debug: ", fmt, ##arg)

#define PBCD_INV_SOCK				-1
#define PBCD_SEC_MICROSEC(x)			((unsigned long long)(x) * 1000 * 1000)

#define WPS_PBCD_MSG_M4				"msg=8"
#define WPS_PBCD_MSG_M7				"msg=11"
#define WPS_PBCD_CFG_NO_ERR			"config_error=0"
#define WPS_PBCD_CFG_PIN_VALIDATION_ERR		"config_error=18"
#define DPP_CONNECTOR_PREFIX			"<3>DPP-CONNECTOR "
#define DPP_C_SIGN_KEY_PREFIX			"<3>DPP-C-SIGN-KEY "
#define DPP_NET_ACCESS_KEY_PREFIX		"<3>DPP-NET-ACCESS-KEY "
#define DPP_SSID_PREFIX				"<3>DPP-CONFOBJ-SSID "
#define DPP_AKM_PREFIX				"<3>DPP-CONFOBJ-AKM "

#define WPS_PBCD_CTRL_DIR_PREFIX		"/var/run"
#define	WPS_PBCD_MAX_BUF_SIZE			256
#define	WPS_PBCD_MIN_BUF_SIZE			128
#define WPS_PBCD_NVNAME_BUF_SIZE		64
#define	WPS_PBCD_THREAD_POOL_SIZE		16
#define WPS_PBCD_LONG_PRESSTIME			5
#define WPS_PBCD_BTNSAMPLE_PERIOD		(500 * 1000)
#define WPS_PBCD_MAP_BH_BSS_NVVAL		0x2	// Multiap Backhaul BSS
#define	WPS_PBCD_PKT_BUF_SIZE			4096
#define	WPS_PBCD_RNR_BUF_SIZE			8192

// Wps auth types
#define WPS_PBCD_WPS_AUTH_OPEN		0x01
#define WPS_PBCD_WPS_AUTH_WPAPSK	0x02
#define WPS_PBCD_WPS_AUTH_WPA2PSK	0x20

//Wps encryption types
#define WPS_PBCD_WPS_ENCR_NONE		0x01
#define WPS_PBCD_WPS_ENCR_TKIP		0x04
#define WPS_PBCD_WPS_ENCR_AES		0x08

// type and length both are 2 bytes each for hex value it needs to double
#define WPS_PBCD_WPS_ATTR_TYPE_LEN_SIZE		8

#define WPS_PBCD_MONITOR_THREAD_SLEEP_DURATION		100	// In msecs
#define WPS_PBCD_NOTIFICATION_THREAD_SLEEP_DURATION	500	// In msecs

#define WPS_PBCD_MAX_BUF	512

#define MAX_RADIO_NUM			4

#define WPS_PBCD_ESCAN_TIMEOUT		10	// In seconds

typedef enum wps_pbcd_wps_behaviour {
	WPS_SIMULTANEOUS = 1,		// Wps will start simultaneously
	WPS_SEQUENTIAL_AUTO = 2,	// Wps will start sequentially in each interface
	WPS_SEQUENTIAL_MANUAL = 3,	// User needs to start wps manually in each interface
	WPS_INVALID_BEHAVIOUR
} wps_pbcd_wps_behaviour_t;

// Wps attribute types
enum wps_pbcd_wps_attributes {
	WPS_ATTR_AUTH_TYPE = 0x1003,
	WPS_ATTR_CRED = 0x100e,
	WPS_ATTR_ENCR_TYPE = 0x100f,
	WPS_ATTR_MAC_ADDR = 0x1020,
	WPS_ATTR_NETWORK_INDEX = 0x1026,
	WPS_ATTR_NETWORK_KEY = 0x1027,
	WPS_ATTR_SSID = 0x1045
};

typedef enum wps_pbcd_button_press_type {
	WPS_PBCD_BUTTON_PRESS_TYPE_UNKNOWN = 0,
	WPS_PBCD_BUTTON_PRESS_TYPE_SHORT = 1,
	WPS_PBCD_BUTTON_PRESS_TYPE_LONG = 2,
	WPS_PBCD_BUTTON_PRESS_TYPE_TIMEOUT = 3
} wps_pbcd_button_press_type_t;

typedef struct {
	int board_fp;			/* Handle for wps gpio led */
	char pbc_ifname[IFNAMSIZ];	/* selected interface name using pbc press where
					 * current wps session is active.
					 */
	uint8 notification_flags;	/* Bitflag to be set on specific wps events on request */
	uint8 wlunit_bitflag;		/* Bitflag to track the pbc ifname unit */
} wps_pbcd_wps_t;

static wps_pbcd_wps_t g_wps_data;	// Wps data shared between the main loop and thread pool

static pthread_mutex_t g_wps_pbcd_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_wps_pbcd_gpio_led_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct wps_pbcd_info wps_pbcd_info_t;

// Custom notification bits
typedef enum wps_pbcd_notification_id {
	WPS_SUCCESS = 0,
	WPS_TIMEOUT = 1
} wps_pbcd_notification_id_t;

typedef struct wps_pbcd_notification_data {
	wps_pbcd_notification_id_t notification_id;	// Notification Id
	void *notification_handler_arg;			// Data for notification handler
	void (*notification_handler)(void *arg);	// Notification handler routine
} wps_pbcd_notification_data_t;

#if !defined(STB)
static void wps_pbcd_stop_wps_led(void *arg);
static void wps_pbcd_stop_wps(void *arg);
static void* wps_custom_notification_handler(void *arg);
static int wps_pbcd_add_notification_handler(wps_pbcd_notification_id_t id,
	void *notification_handler, void *notification_handler_arg);
static void wps_pbcd_set_notification_flags(uint8 bit);
static bool wps_pbcd_isset_notification_flags(uint8 bit);
static void wps_pbcd_clear_notification_flag(uint8 bit);
static void wps_pbcd_register_for_wps_success_notification(char *wps_ifnames);
static void wps_pbcd_register_for_wps_timeout_notification(int board_fp);
static wps_pbcd_wps_behaviour_t wps_pbcd_get_wps_behaviour();
#endif	/* !STB */

// Callback to check whether configuration is required or not
typedef bool (*wps_pbcd_is_configuration_required)(char *ifname, wlif_wps_mode_t mode);
// Callback to set device as configured
typedef void (*wps_pbcd_set_device_configured)(char *ifname);
// Callback to receive the network configuration settings
typedef int (*wps_pbcd_get_configuration_settings)(wps_pbcd_info_t *pbcd_info);
// Callback to update the nvram values with the network settings
typedef int (*wps_pbcd_apply_network_settings)(wlif_bss_t *bss, wlif_wps_nw_creds_t *creds);
// Callback to process the wpa control events data
typedef int (*wps_pbcd_process_wpa_ctrl_events)(wps_pbcd_info_t *obj);
// Callback to cleanup the wps gpio led
typedef void (*wps_pbcd_gpio_led_cleanup)(int board_fp);
// Callback to update the wps gpio led and ui status
typedef void (*wps_pbcd_update_led_and_ui_status)(wps_pbcd_info_t *info);
// Callback to reset the wps ifnames data which is being shared between threads and main thread
typedef void (*wps_pbcd_reset_wps_ifnames_data)(char *data);
typedef int (*non_wps_process_wpa_ctrl_events)(wps_pbcd_info_t *info);
typedef int (*dpp_wpa_ctrl_events)(wps_pbcd_info_t *info);

#ifdef MULTIAP
static void wps_pbcd_sys_restart(char *ifname);
#endif	/* MULTIAP */

static void wps_pbcd_set_ap_as_configured(char *ifname);
static int wps_pbcd_fetch_ap_config_settings(wps_pbcd_info_t *pbcd_info);
static int wps_pbcd_process_hostapd_wpasupplicant_ctrl_events(wps_pbcd_info_t *info);
static int wps_pbcd_gpio_led_init_handler();
static void wps_pbcd_gpio_board_cleanup();
static void wps_pbcd_led_and_ui_status_update_handler(wps_pbcd_info_t *info);
static void wps_pbcd_reset_wps_ifnames_data_handler(char *data);
static bool wps_pbcd_does_dev_needs_to_be_configured(char *ifname, wlif_wps_mode_t wps_mode);
static int wps_pbcd_fetch_config_settings(wps_pbcd_info_t *pbcd_info);
static void wps_pbcd_free_info_object(wps_pbcd_info_t **pbcd_info);
static int wps_pbcd_get_radio_unit(char *ifname, int *out_unit);
static bool wps_pbcd_is_wps_possible_on_interface(char *ifname, char *nvifname, int unit);
static int non_wps_process_hostapd_wpa_supplicant_ctrl_events(wps_pbcd_info_t *pbcd_info);
static int hostapd_wpa_supplicant_dpp_ctrl_events(wps_pbcd_info_t *pbcd_info);

#ifdef BCA_HNDROUTER
static wps_pbcd_button_press_type_t wps_pbcd_wps_gpio_btn_pressed(int board_fp);
static int wps_pbcd_get_wps_sequential_auto_timeout(char *wps_ifnames);
#else
#define wps_pbcd_wps_gpio_btn_pressed(a)		(0)
#define wps_pbcd_get_wps_sequential_auto_timeout(a)	(0)
#endif	/* BCA_HNDROUTER */

struct wps_pbcd_info {
	struct wpa_ctrl *wpa_ctrl_handle;	// Wpa control interface handle
	char wpa_ctrl_dir[WPS_PBCD_MIN_BUF_SIZE];	// Wpa control dir path
	wlif_bss_t bss;				// Bss data currently holds ifname and nvifname
	char reply_buf[WPS_PBCD_MAX_BUF_SIZE * 2]; // Buf to get the data from wpa contrl interface
	size_t reply_len;			// Length of received data
	int gpio_board_fp;			// Wps gpio board handle
	wlif_wps_nw_creds_t creds;		// Network settings received after successful wps
	wlif_wps_mode_t wps_mode;		// Wps mode can be either enrollee or registrar
	wlif_dpp_creds_t dpp_creds;		// Network settings received after successful wps
	wps_pbcd_is_configuration_required is_configuration_required;
	wps_pbcd_set_device_configured	set_device_configured;
	wps_pbcd_get_configuration_settings get_network_settings;
	wps_pbcd_apply_network_settings apply_network_settings;
	wps_pbcd_update_led_and_ui_status led_and_ui_status_update_handler;
	wps_pbcd_reset_wps_ifnames_data reset_wps_ifnames_data_handler;
	wps_pbcd_process_wpa_ctrl_events process_ctrl_event_data;
	non_wps_process_wpa_ctrl_events non_wps_wpa_ctrl_events_handler;
	dpp_wpa_ctrl_events dpp_wpa_ctrl_events_handler;
	pthread_t monitor_thread_id;
	int wpa_ctrl_fd;
	void *arg;
	bool skip_ui_update;
};

typedef struct bss_list {
	struct bss_list *next;
	char ifname[16];
	nbr_rpt_elem_t self_nbr_rpt;
} bss_list_t;

/*
 * per radio rnr info
 */
typedef struct {
	char ifname[IFNAMSIZ];
	bool enabled;
	int ifidx;
	int bandlist[3];
	int band_type;
	int bss_info_count; /* no of rrm_nbr elements updated */
	char rnr_src_iflist[WPS_PBCD_MIN_BUF_SIZE];
	char oob_nbr_radio_list[WPS_PBCD_MIN_BUF_SIZE];
	struct escan_bss *escan_bss_head;
	bool escan_timer;
	bool is_ap;
	uint8 unit;
	bss_list_t *bss_list; /* each bss ifname + nbr_rpt_elem with self info */
	bool oob_nbr_discovery;
} wps_pbcd_radio_rnr_info_t;

// List of wps_pbcd_info_t pointers
typedef struct {
	int count;
	wps_pbcd_info_t *wps_pbcd_info_objects[WPS_PBCD_THREAD_POOL_SIZE];
	char *wps_ap_ifnames;	// List of all wps capable ap interfaces
	char *wps_sta_ifnames;	// List of all wps capable sta interfaces
	int rgd_sockfd;
	wps_pbcd_radio_rnr_info_t radio_rnr_info[MAX_RADIO_NUM];
	bcm_usched_handle *usched_hdl;
} wps_pbcd_info_list_t;

static int wps_pbcd_schedule_drv_events(wps_pbcd_info_list_t *list);
static void wps_pbcd_drv_events_cb(bcm_usched_handle *hdl, void *arg,
	bcm_usched_fds_entry_t *entry);
static void wps_pbcd_update_rnr_list(char *nv_ifname, wps_pbcd_radio_rnr_info_t *ri);
static int wps_pbcd_get_rnr_list(char *nv_ifname, char *rnr_list_buf, char *outbuf, size_t olen);
static int wps_pbcd_set_rnr_list(char *nv_ifname, char *outbuf, size_t outbuf_len);
static int wps_pbcd_get_band_type(char *ifname);
static void wps_pbcd_get_wl_radio_iflist(char *wl_radio_iflist, int rlistsz);
static int wps_pbcd_init_radio_rnr_info(wps_pbcd_info_list_t  *g_wpi_list);
static int wps_pbcd_fill_rrm_nbr_info(char *ifname, wl_bss_info_t *bi, nbr_rpt_elem_t *nre);
static int wps_pbcd_add_rrm_nbr(char *ifname, nbr_rpt_elem_t *nbr_elt);
static int wps_pbcd_remove_rrm_nbr(char *ifname, struct ether_addr *bssid);
static int wps_pbcd_init_co_host_nbr_info();
static int wps_pbcd_set_co_host_nbr_info();
static void wps_pbcd_copy_bss_nbr_list(bss_list_t *dst_bss_list, bss_list_t *scr_bss_list);
// Utility functions
static void wps_pbcd_dump_ri_info(wps_pbcd_info_list_t *g_wpi_list, char *wl_radio_iflist);
static void wps_pbcd_dump_bandlist(int bandlist[]);
static void wps_pbcd_dump_min_bss_info(void * bi_generic);
int wps_pbcd_bcmp(const void *b1, const void *b2, int len);
int wps_pbcd_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len);

// event handlers
static void wps_pbcd_scan_cmplt_evt_hndlr(char *evt_ifname);
static void wps_pbcd_e_link_evt_hndlr(char *evt_ifname, wl_event_msg_t *event);
static void wps_pbcd_escanresults_evt_hndlr(bcm_event_t *be, char *ifname);

// list of wps_pbcd_info_t
wps_pbcd_info_list_t *g_wps_pbcd_info_list = NULL;

/* Struct to hold the timer data arg */
typedef struct {
	char prev_pbc_ifname[IFNAMSIZ];	/* Previous interface where wps started */
	wlif_wps_op_type_t wps_op;	/* WPS operation type */
} wps_pbcd_tm_arg_t;

static void
wps_pbcd_free_escan_list(struct escan_bss **phead)
{
	struct escan_bss *next;
	struct escan_bss *head = *phead;

	while (head) {
		next = head->next;
		free(head);
		head = next;
	}

	*phead = NULL;
}
/* Wrapper function to schedule the socket fd's using usched lib */
static int
wps_pbcd_add_fd_to_schedule(bcm_usched_handle *hdl, int fd, void *arg, bcm_usched_fdscbfn *cbfn)
{
	int ret = 0;
	int fdbits = 0;
	BCM_USCHED_STATUS status = 0;

	if (fd != PBCD_INV_SOCK) {
		BCM_USCHED_SETFDMASK(fdbits, BCM_USCHED_MASK_READFD);
		status = bcm_usched_add_fd_schedule(hdl, fd, fdbits, cbfn, arg);
		if (status != BCM_USCHEDE_OK) {
			PBCD_ERR("failed to add FD[%d] %s\n", fd, bcm_usched_strerror(status));
			ret = -1;
		}
	}

	return ret;
}

/* Timer callback function to do dpp specific provision */
static void
wps_pbcd_dpp_init_tm_cb(bcm_usched_handle *hdl, void *arg)
{
	start_hapd_dpp_self_provision();
}

/* Wrapper function to add timers to usched lib */
static BCM_USCHED_STATUS
wps_pbcd_add_timers(bcm_usched_handle *hdl, void *arg, unsigned long long timeout,
	bcm_usched_timerscbfn *cbfn, int repeat_flag)
{
	BCM_USCHED_STATUS status = 0;

	status = bcm_usched_add_timer(hdl, timeout, repeat_flag, cbfn, arg);

	if (status != BCM_USCHEDE_OK) {
		PBCD_ERR("failed to add timer because %s timeout[%llu]Msec arg[%p] cbfn[%p]\n",
			bcm_usched_strerror(status), timeout, arg, cbfn);
	}

	return status;
}

/* Wrapper function to remove timers from usched lib */
static BCM_USCHED_STATUS
wps_pbcd_remove_timers(bcm_usched_handle *hdl, bcm_usched_timerscbfn *cbfn, void *arg)
{
	BCM_USCHED_STATUS status = 0;

	status = bcm_usched_remove_timer(hdl, cbfn, arg);

	if (status != BCM_USCHEDE_OK) {
		PBCD_ERR("failed to remove timer because %s arg[%p] cbfn[%p]\n",
			bcm_usched_strerror(status), arg, cbfn);
	}

	return status;
}

#if !defined(STB)
/* Returns the pbcd info object matching the ifname */
static wps_pbcd_info_t*
wps_pbcd_get_info_obj(char *ifname)
{
	int idx;
	wps_pbcd_info_t *obj;

	for (idx = 0; idx < g_wps_pbcd_info_list->count; idx++) {
		obj = g_wps_pbcd_info_list->wps_pbcd_info_objects[idx];
		if (!strcmp(obj->bss.ifname, ifname)) {
			return obj;
		}
	}

	return NULL;
}

/* Timer callback function to start the wps session */
static void
wps_pbcd_tm_cb(bcm_usched_handle *hdl, void *arg)
{
	wps_pbcd_info_t *obj = (wps_pbcd_info_t*)arg;
	wps_pbcd_tm_arg_t *tm_arg = (wps_pbcd_tm_arg_t *)obj->arg;
	int status;

	status = wl_wlif_get_wps_status_code();
	if (status == WLIF_WPS_UI_FIND_PBC_AP || status == WLIF_WPS_UI_FINDING_PBC_STA) {
		wl_wlif_wps_stop_session(tm_arg->prev_pbc_ifname, TRUE);
		if (tm_arg->wps_op == WLIF_WPS_START)
			wl_wlif_wps_pbc_hdlr(obj->bss.ifname, NULL);
	}

	free(obj->arg);
	obj->arg = NULL;
}

/* Sets up the timer to first stop wps on prev pbc ifname and start wps on pbc ifname */
static void
wps_pbcd_set_timer(char *prev_pbc_ifname, char *pbc_ifname,
	wlif_wps_op_type_t wps_op, int tm_val)
{
	wps_pbcd_tm_arg_t *tm_arg = NULL;
	wps_pbcd_info_t *obj = NULL;

	obj = wps_pbcd_get_info_obj(pbc_ifname);
	if (!obj) {
		PBCD_ERR("did not find any pbcd info obj for ifname %s \n", pbc_ifname);
		return;
	}
	if (obj->arg) {
		if (wps_pbcd_remove_timers(g_wps_pbcd_info_list->usched_hdl,
				wps_pbcd_tm_cb, obj)) {
			PBCD_ERR("failed to remove timer\n");
			return;
		}

		free(obj->arg);
	}

	tm_arg = (wps_pbcd_tm_arg_t *)calloc(1, sizeof(*tm_arg));
	if (!tm_arg) {
		PBCD_ERR("failed to allocate memory of %zu bytes\n", sizeof(*tm_arg));
		return;
	}

	WLIF_STRNCPY(tm_arg->prev_pbc_ifname, prev_pbc_ifname, sizeof(tm_arg->prev_pbc_ifname));
	tm_arg->wps_op = wps_op;
	obj->arg = tm_arg;
	wps_pbcd_add_timers(g_wps_pbcd_info_list->usched_hdl, obj,
		PBCD_SEC_MICROSEC(tm_val), wps_pbcd_tm_cb, 0);
}

/* Sequential wps will be performed in sequential order on each interface during wps session.
 * Eg: If wps_ifnames has "wl0 wl1 wl2" listed as ifnames than wps will be sequantially active on
 * each interface listed in wps_ifnames for (WPS_SESSION_TIME/No of interfaces 120/3) 40 secs.
 * Which means for first 40 secs wps will be active on wl0, than for next 40 secs it will be
 * active on wl1 and for final 40 secs on wl2.
 * If wps is successful in any interface the remaining interfaces will be skipped.
 */
static void
wps_pbcd_perform_seq_wps(char *wps_ifnames)
{
	char ifname[IFNAMSIZ] = {0}, *next = NULL;
	char def_ifname[IFNAMSIZ] = {0}, prev_pbc_ifname[IFNAMSIZ] = {0};
	int tm_val = 0, count = 0;

	tm_val = wps_pbcd_get_wps_sequential_auto_timeout(wps_ifnames);

	foreach(ifname, wps_ifnames, next) {
		if (count == 0) {
			WLIF_STRNCPY(def_ifname, ifname, sizeof(def_ifname));
			WLIF_STRNCPY(prev_pbc_ifname, ifname, sizeof(prev_pbc_ifname));
			wl_wlif_wps_pbc_hdlr(ifname, NULL);
		} else if (tm_val > 0) {
			wps_pbcd_set_timer(prev_pbc_ifname, ifname, WLIF_WPS_START, tm_val*count);
			WLIF_STRNCPY(prev_pbc_ifname, ifname, sizeof(prev_pbc_ifname));
		}

		count++;
	}

	if (count && (tm_val > 0))
		wps_pbcd_set_timer(prev_pbc_ifname, def_ifname, WLIF_WPS_STOP, tm_val*count);
}

/* Routine to iterate and start wps manually on each interface using hardware button
 * eg: Suppose wps_ifnames are set to "wl0 wl1 wl2"
 * One press will envoke wps on wl0, 2 times pbc press will start wps on wl2.
 * To iterate the wps_ifnames on each button press we are storing the selected ifname in the
 * pbc_ifname variable and the wlunit of the interface is being tracked using wlunit_bitflag.
 */
static void
wps_pbcd_perform_seq_manual_wps(char *wps_ifnames)
{
	char ifname[IFNAMSIZ] = {0}, *next;
	char *pbc_ifname = NULL, def_ifname[IFNAMSIZ] = {0};
	int unit = 0, def_wlunit = 0;

	foreach(ifname, wps_ifnames, next) {
		wps_pbcd_get_radio_unit(ifname, &unit);
		if (def_ifname[0] == '\0') {
			WLIF_STRNCPY(def_ifname, ifname, sizeof(def_ifname));
			def_wlunit = unit;
		}
		if (isset(&g_wps_data.wlunit_bitflag, unit)) {
			continue;
		}
		pbc_ifname = ifname;
		setbit(&g_wps_data.wlunit_bitflag, unit);
		break;
	}

	/* Once all the ifnames are iterated, start over again */
	if (def_ifname[0] != '\0' && !pbc_ifname) {
		pbc_ifname = def_ifname;
		g_wps_data.wlunit_bitflag = 0;
		setbit(&g_wps_data.wlunit_bitflag, def_wlunit);
	}

	if (!pbc_ifname) {
		PBCD_ERR("did not find any interface from %s to start wps, wps is already done "
			"for ifnames whose ifr unit is set in bitflag 0x%x\n",
			wps_ifnames, g_wps_data.wlunit_bitflag);
		return;
	}

	if (g_wps_data.pbc_ifname[0] != '\0') {
		wl_wlif_wps_stop_session(g_wps_data.pbc_ifname, TRUE);
	}

	WLIF_STRNCPY(g_wps_data.pbc_ifname, pbc_ifname, sizeof(g_wps_data.pbc_ifname));
	wl_wlif_wps_pbc_hdlr(pbc_ifname, NULL);
}

/* Callback routine to process the events received on gpio fd */
static void
wps_pbcd_process_gpio_fd_cb(bcm_usched_handle *hdl, void *arg, bcm_usched_fds_entry_t *entry)
{
	wps_pbcd_info_list_t *list = (wps_pbcd_info_list_t *)arg;
	wps_pbcd_button_press_type_t btn_evt = WPS_PBCD_BUTTON_PRESS_TYPE_UNKNOWN;
	wps_pbcd_wps_behaviour_t wps_behaviour;
	char ifname[IFNAMSIZ] = {0}, *wps_ifnames = NULL, *next = NULL;
	int wps_on_sta = 0;

	btn_evt = wps_pbcd_wps_gpio_btn_pressed(g_wps_data.board_fp);
	if (btn_evt != WPS_PBCD_BUTTON_PRESS_TYPE_SHORT &&
		btn_evt != WPS_PBCD_BUTTON_PRESS_TYPE_LONG) {
		PBCD_ERR("received unknown gpio button press %d event\n", btn_evt);
		return;
	}

	wps_on_sta = atoi(nvram_safe_get("wps_on_sta"));
	if (wps_on_sta) {
		wps_ifnames = list->wps_sta_ifnames;
	} else {
		wps_ifnames = list->wps_ap_ifnames;
	}

	if (wps_ifnames == NULL) {
		PBCD_ERR("did not find any interface to start wps "
			"wps_ap_ifnames=%s wps_sta_ifnames=%s wps_on_sta=%d\n",
			list->wps_ap_ifnames ? list->wps_ap_ifnames : "NULL",
			list->wps_sta_ifnames ? list->wps_sta_ifnames : "NULL", wps_on_sta);
		return;
	}

	wps_behaviour = wps_pbcd_get_wps_behaviour();
	switch (wps_behaviour) {
	case WPS_SIMULTANEOUS:
		/* Register for wps success notification so that once wps succeeds in any single
		 * interface it can be stopped on other interfaces.
		 */
		wps_pbcd_register_for_wps_success_notification(wps_ifnames);
		 /* Start wps on all the interfaces listed in wps_ifnames */
		foreach(ifname, wps_ifnames, next) {
			wl_wlif_wps_pbc_hdlr(ifname, NULL);
		}
		break;

	case WPS_SEQUENTIAL_AUTO:
		wps_pbcd_register_for_wps_timeout_notification(g_wps_data.board_fp);
		wps_pbcd_perform_seq_wps(wps_ifnames);
		break;

	case WPS_SEQUENTIAL_MANUAL:
		wps_pbcd_perform_seq_manual_wps(wps_ifnames);
		break;

	default:
		break;
	}
}
#endif	/* !STB */

/* Callback routine to process the events received on hapd/wpa ctrl fd */
static void
wps_pbcd_process_ctrl_evt_fd_cb(bcm_usched_handle *hdl, void *arg, bcm_usched_fds_entry_t *entry)
{
	int ret = 0;
	wps_pbcd_info_t *pbcd_info = (wps_pbcd_info_t*)arg;

	ret = wpa_ctrl_pending(pbcd_info->wpa_ctrl_handle);
	if (ret == 1) {
		pbcd_info->reply_len = sizeof(pbcd_info->reply_buf);
		memset(pbcd_info->reply_buf, 0, pbcd_info->reply_len);
		ret = wpa_ctrl_recv(pbcd_info->wpa_ctrl_handle, pbcd_info->reply_buf,
			&pbcd_info->reply_len);
		if (ret >= 0) {
			pbcd_info->process_ctrl_event_data(pbcd_info);
		}
	}
}

#if !defined(STB)
/* Add the gpio fd to scheduler lib */
static int
wps_pbcd_schedule_gpio(wps_pbcd_info_list_t *list)
{
	int board_fp = 0;
	int trigger = SES_EVENTS;
	int ret = -1;
	BOARD_IOCTL_PARMS ioctl_parms = {0};

	board_fp = wps_pbcd_gpio_led_init_handler();
	if (board_fp <= 0) {
		PBCD_ERR("invalid wps gpio board_fp %d\n", board_fp);
		goto fail;
	}

	ioctl_parms.result = -1;
	ioctl_parms.string = (char *)&trigger;
	ioctl_parms.strLen = sizeof(trigger);

	if (ioctl(board_fp, BOARD_IOCTL_SET_TRIGGER_EVENT, &ioctl_parms) < 0) {
		PBCD_ERR("ioctl call failed for wps gpio fd %d\n", board_fp);
		goto fail;
	}

	if (ioctl_parms.result < 0) {
		PBCD_ERR("invalid ioctl call result for wps gpio fd %d\n", board_fp);
		goto fail;
	}

	if ((ret = wps_pbcd_add_fd_to_schedule(list->usched_hdl, board_fp,
		list, wps_pbcd_process_gpio_fd_cb))) {
		PBCD_ERR("failed to add wps gpio fd %d to schedule\n", board_fp);
	}

fail:

	return ret;
}
#endif	/* !STB */

/*
 * Fetch rnr_list on iface from iovar into user supplier buffer.
 */
static int
wps_pbcd_get_rnr_list(char *nv_ifname, char *rnr_list_buf, char *outbuf, size_t outbuf_len)
{
	int err = BCME_OK;
	rnr_list_req_t *req =  NULL;
#ifdef RNR_LIST_DBG
	int i, j;
	rnr_list_req_t *results = (rnr_list_req_t *)outbuf;
	wlc_scan_wlioctl_prof_list_t *prof_list = results->prof_list;
	wlc_scan_wlioctl_prof_t *profile;
	char ea[ETHER_ADDR_STR_LEN] = {0};
#endif // endif

	/* set up the rnr_list req */
	req = (rnr_list_req_t *) rnr_list_buf;
	req->ver = 0;
	req->len = 0;
	req->count = 0;
	req->cmd_type = RNR_LIST_GET;

	if ((err = wl_iovar_getbuf(nv_ifname, "rnr_list",
			(void *)req, sizeof(*req), (void *)outbuf,
			outbuf_len)) < 0) {
		PBCD_ERR("wl_iovar_getbuf(): err %d\n", err);
		return err;
	}

#ifdef RNR_LIST_DBG
	/* dump the fetched rnr_list */
	for (i = 0; i < results->count; i++) {
		printf("----------------------%d------------------\n", i);
		printf("chanspec:0x%x, 20TU:%d, rnr:%d, count:%d\n",
				prof_list->chanspec, prof_list->prbres_20tu_set,
				prof_list->rnr, prof_list->profile_count);
		profile = prof_list->profile;
		for (j = 0; j < prof_list->profile_count; j++) {
			printf("*********%d*************\n", j);
			if (profile->ssid_length) {
				printf("SSID:%s\n", (char *)profile->SSID);
			}
			if (profile->is_short_ssid) {
				printf("short_ssid:0x%x\n", profile->short_ssid);
			}
			if (profile->bssid_valid) {
				printf("BSSID: %s\n",
					ether_etoa((unsigned char *)&profile->bssid, ea));
			}
			printf("BSS_PARAMS:0x%x\n", profile->bss_params);
			profile++;
		}
		prof_list = (wlc_scan_wlioctl_prof_list_t *)profile;
	}
#endif /* RNR_LIST_DBG */

	return BCME_OK;
}

/*
 * set the rnr_list on 6G radio interface
 */
static int
wps_pbcd_set_rnr_list(char *nv_ifname, char *outbuf, size_t outbuf_len)
{
	int err = BCME_OK;
	char output[WPS_PBCD_RNR_BUF_SIZE] = {0};
	rnr_list_req_t *req = NULL;

	req = (rnr_list_req_t *)outbuf;
	req->cmd_type = RNR_LIST_SET;

	if ((err = wl_iovar_setbuf(nv_ifname, "rnr_list",
			(void *)req, req->len, output, outbuf_len)) < 0) {
		PBCD_ERR("wl_iovar_setbuf(): err %d\n", err);
	}

	return err;
}

/*
 * update the rnr_list from 2G/5G radio to 6G radio
 */
static void
wps_pbcd_update_rnr_list(char *nv_ifname, wps_pbcd_radio_rnr_info_t *ri)
{
	char rnr_list_buf[WPS_PBCD_MAX_BUF] = {0}, outbuf[WPS_PBCD_RNR_BUF_SIZE] = {0};

	if (ri->enabled != TRUE) {
		PBCD_EVT_DBG("radio %s disabled\n", ri->ifname);
		return;
	}

	if (ri->band_type != WLC_BAND_6G) {
		PBCD_EVT_DBG("radio %s on 6G band\n", ri->ifname);
		return;
	}

	/* get rnr_list from src 2G/5G iface */
	if (wps_pbcd_get_rnr_list(nv_ifname, rnr_list_buf, outbuf, sizeof(outbuf)) < 0) {
		PBCD_EVT_DBG("fetching rnr_list on %s\n",  nv_ifname);
		return;
	}

	/* set rnr_list on dest 6G iface */
	if (wps_pbcd_set_rnr_list(ri->ifname, outbuf, sizeof(outbuf)) < 0) {
		PBCD_EVT_DBG("set rnr_list on %s\n", ri->ifname);
		return;
	}
}

static int
wps_pbcd_init_co_host_nbr_info()
{
	wps_pbcd_radio_rnr_info_t *ri = NULL;
	wl_bss_info_t *bi;
	bss_list_t *bss = NULL;
 	int err = BCME_OK;
	int idx = 0;
	int unit, subunit;
	char *ifnames = NULL;
	char nv_ifname[IFNAMSIZ] = {0};
	char ifname[IFNAMSIZ] = {0}, *next;
	char *lan_ifnames = nvram_safe_get("lan_ifnames");
 	char ioctl_buf[WLC_IOCTL_MAXLEN] = {0};
 
	ifnames = lan_ifnames;

	if (ifnames[0] == '\0') {
		PBCD_PRINT("Info: ", "did not find any interface to add to ifnames"
			" from lan_ifnames=[%s]\n", lan_ifnames);
		return 0;
	}

	/* prepare nbr info for all ap bss presents */
	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		ri = &(g_wps_pbcd_info_list->radio_rnr_info[idx]);
		if (!ri->enabled) {
			PBCD_EVT_DBG("radio %s disabled\n", ri->ifname);
			continue;
		}
		foreach(ifname, ifnames, next) {
			if (osifname_to_nvifname(ifname, nv_ifname, IFNAMSIZ) < 0) {
				PBCD_EVT_DBG("%s: error converting osifname to nvifname()\n",
					ifname);
				continue;
			}
			if (get_ifname_unit(nv_ifname, &unit, &subunit) < 0) {
				PBCD_EVT_DBG("%s: get_ifname_unit() failed \n", nv_ifname);
				continue;
			}
			if (ri->unit != unit) {
				continue;
			}
			bss = (bss_list_t*)malloc(sizeof(bss_list_t));
			if (!bss) {
				PBCD_ERR("bss_list_t malloc failed for size[%zu] \n",
					sizeof(bss_list_t));
				goto finish;
			}
			memcpy(bss->ifname, ifname, sizeof(bss->ifname));

			*(uint32*)ioctl_buf = htod32(WLC_IOCTL_MAXLEN);
			err = wl_ioctl(ifname, WLC_GET_BSS_INFO, ioctl_buf, WLC_IOCTL_MAXLEN);
			if (err) {
				PBCD_EVT_DBG("%s failed to get bss info.\n", ifname);
				goto finish;
			}
			bi = (wl_bss_info_t*)(ioctl_buf + sizeof(uint32));

			memset(&bss->self_nbr_rpt, 0, sizeof(bss->self_nbr_rpt));

			err = wps_pbcd_fill_rrm_nbr_info(ifname, bi, &bss->self_nbr_rpt);
			if (err) {
				PBCD_EVT_DBG("%s failed to fill bss info into rrm_nbr\n", ifname);
				goto finish;
			}
			bss->next = ri->bss_list;
			ri->bss_list = bss;
		}
	}

finish:
	return err;
}

static int
wps_pbcd_set_co_host_nbr_info()
{
	wps_pbcd_radio_rnr_info_t *ri = NULL, *rj = NULL;
	bss_list_t *ri_bss_list = NULL, *rj_bss_list = NULL;
	int i, j;

	/* populate nbr entries across bands presents */
	for (i = 0; i < MAX_RADIO_NUM; i++) {
		bool no_nbr_radio_list = FALSE;

		ri = &(g_wps_pbcd_info_list->radio_rnr_info[i]);
		if (!ri->enabled) {
			continue;
		}
		if (ri->oob_nbr_radio_list[0] == '\0') {
			no_nbr_radio_list = TRUE;
		}
		ri_bss_list = ri->bss_list;

		for (j = 0; j < MAX_RADIO_NUM; j++) {
			rj = &(g_wps_pbcd_info_list->radio_rnr_info[j]);
			if (!rj->enabled) {
				continue;
			}

			ri_bss_list = ri->bss_list;
			rj_bss_list = rj->bss_list;

			if (no_nbr_radio_list) {
				/* only add 6G bss nbrs to 2G and 5G */
				if ((ri->band_type != WLC_BAND_6G) &&
					(rj->band_type == WLC_BAND_6G)) {
					wps_pbcd_copy_bss_nbr_list(ri_bss_list, rj_bss_list);
				}
			} else {
				if (!find_in_list(ri->oob_nbr_radio_list, rj->ifname)) {
					PBCD_EVT_DBG("%s not in rnr_src_iflist, skip\n",
						rj->ifname);
					continue;
				}

				wps_pbcd_copy_bss_nbr_list(ri_bss_list, rj_bss_list);
			}
		}
	}
	return BCME_OK;
}

#if defined(RTCONFIG_BCM_502L07P2)
#define WLC_RRM_NBR_FLAG_BAND_AUTO	0X00
#define WLC_RRM_NBR_FLAG_BAND_2G	0X01
#define WLC_RRM_NBR_FLAG_BAND_5G	0X02
#define WLC_RRM_NBR_FLAG_BAND_6G	0X04
#define WLC_RRM_NBR_FLAG_BAND_ALL	0X08
#define WLC_RRM_NBR_FLAG_HIDDEN_SSID	0X10
#define WLC_RRM_NBR_FLAG_SAME_SSID	0X20

#define WLC_NBR_DISCOVERY_CAP_6G_UPR			32
#define TBTT_INFO_BSS_PARAMS_OCT_RECOMMENDED		0X01
#define TBTT_INFO_BSS_PARAMS_SAME_SSID			0X02
#define TBTT_INFO_BSS_PARAMS_MBSSID			0X04
#define TBTT_INFO_BSS_PARAMS_TRANSMITTED_BSSID		0X08
#define TBTT_INFO_BSS_PARAMS_ESS_MEMBER_WITH_2G_5G	0X10
#define TBTT_INFO_BSS_PARAMS_UPR_ACTIVE			0X20
#define TBTT_INFO_BSS_PARAMS_COLOCATED_AP		0X40
#define TBTT_INFO_BSS_RESERVED				0X80
#endif

/*
 * get rrm_nbr bss specific info from driver into nbr_rpt element
 */
static int
wps_pbcd_fill_rrm_nbr_info(char *ifname, wl_bss_info_t *bi, nbr_rpt_elem_t *nre)
{
	int err = BCME_OK;
	uint8 rclass = 0;
	uint8 phytype = 0;
	chanspec_t chanspec = 0;
#if 0 // TODO: wlan 17.10.157.60
	int closed = 0;
	int band_type = 0;
	int nbr_discovery_cap = 0;
	int rnr_tbtt_len = 0;
#endif
	char outbuf[WPS_PBCD_RNR_BUF_SIZE] = {0};

	if (dtoh32(bi->version) == WL_BSS_INFO_VERSION) {
		chanspec = dtohchanspec(bi->chanspec);
		if ((err = wl_iovar_getbuf(ifname, "rclass", &chanspec,
				sizeof(chanspec_t), outbuf,  sizeof(outbuf))) < 0) {
			PBCD_ERR("%s failed getting rclass. err %d\n", ifname, err);
			return err;
		}

		memcpy(&rclass, outbuf, sizeof(rclass));

		if ((err = wl_ioctl(ifname, WLC_GET_PHYTYPE, &phytype, sizeof(phytype))) < 0) {
			PBCD_ERR("%s failed getting phytype. err %d\n", ifname, err);
			return err;
		}

#if 0 // TODO: wlan 17.10.157.60
		wl_ioctl(ifname, WLC_GET_CLOSED, &closed, sizeof(closed));

		wl_iovar_getint(ifname, "rnr_tbtt_len", &rnr_tbtt_len);
#endif

		/* Fill neigbor report element structure */
		nre->version = WL_RRM_NBR_RPT_VER;
		nre->id = DOT11_MNG_NEIGHBOR_REP_ID;
		nre->len = sizeof(nbr_rpt_elem_t);
		memcpy(&(nre->bssid), &(bi->BSSID), sizeof(struct ether_addr));
		nre->bssid_info = 0xFF;
		nre->reg  =  rclass;
		nre->channel = bi->ctl_ch;
		nre->phytype = phytype;
		nre->addtype = NBR_ADD_STATIC;
		hapd_wpasupp_strncpy((char *)nre->ssid.SSID, (const char *)bi->SSID,
			(bi->SSID_len + 1));
		nre->ssid.SSID_len = bi->SSID_len;
		nre->chanspec = chanspec;
		nre->bss_trans_preference = 254; // max value
#if 0 // TODO: wlan 17.10.157.60
		if (closed) {
			nre->flags |= WLC_RRM_NBR_FLAG_HIDDEN_SSID;
		}
		band_type = wps_pbcd_get_band_type(ifname);
		if (band_type == WLC_BAND_6G) {
			nre->flags |= WLC_RRM_NBR_FLAG_BAND_6G;
			wl_iovar_getint(ifname, "nbr_discovery_cap", &nbr_discovery_cap);
			if (nbr_discovery_cap == WLC_NBR_DISCOVERY_CAP_6G_UPR) {
				nre->bss_params |= TBTT_INFO_BSS_PARAMS_UPR_ACTIVE; /* UPR ACTIVE */
			}
		} else if (band_type == WLC_BAND_5G) {
			nre->flags |= WLC_RRM_NBR_FLAG_BAND_5G;
		} else if (band_type == WLC_BAND_2G) {
			nre->flags |= WLC_RRM_NBR_FLAG_BAND_2G;
		}

		/* BSS PARAM represents bss parameters subfield of TBTT information field
		 * -------------------------------------------------------------------------------
		 * | OCT |same | Mbssid | transmit |member of ess with|UPR   | colocated | reserve|
		 * | bit0|ssid |        | bssid    |2/5g colocated AP |active| AP        |  bit7  |
		 * -------------------------------------------------------------------------------
		 */

		nre->bss_params |= (TBTT_INFO_BSS_PARAMS_COLOCATED_AP |
				TBTT_INFO_BSS_PARAMS_ESS_MEMBER_WITH_2G_5G);
		nre->tbtt_len = rnr_tbtt_len;
#else
		nre->flags = 0;
		nre->bss_params = 64;
		nre->tbtt_len = 13;
#endif
		/* TODO:6GHZ For now it is hard coded. As we only support LPI PSD(-1),
		 * granularity of 0.5 db
		 */
		nre->tpe_psd = -2;

		PBCD_EVT_DBG(""MACF", 0x%X, %u, %u, %u, %s, %u, %s, 0x%4X, %u, %u, %u %u \n",
			ETHER_TO_MACF(nre->bssid), nre->bssid_info, nre->reg, nre->channel,
			nre->phytype, (nre->addtype == NBR_ADD_STATIC ? "STATIC" : "DYNAMIC"),
			nre->ssid.SSID_len, nre->ssid.SSID, nre->chanspec,
			nre->bss_trans_preference, nre->flags, nre->bss_params, nre->tpe_psd);
	} else {
		err = BCME_VERSION;
		PBCD_ERR("%s bss info version: %u\n", ifname, dtoh32(bi->version));
	}

	return err;
}

static int
wps_pbcd_remove_rrm_nbr(char *ifname, struct ether_addr *bssid)
{
	char outbuf[WPS_PBCD_PKT_BUF_SIZE] = {0};
	int err = BCME_OK;

	assert(ifname);
	assert(bssid);

	err = wl_iovar_setbuf(ifname, "rrm_nbr_del_nbr", (void *)bssid,
		sizeof(struct ether_addr), (void *)&outbuf, sizeof(outbuf));
	if (err != BCME_OK) {
		PBCD_EVT_DBG("%s failed to delete rrm nbr "MACF" err %d\n", ifname,
			ETHERP_TO_MACF(bssid), err);
		return err;
	}

	PBCD_EVT_DBG("%s removed rrm_nbr "MACF" \n", ifname, ETHERP_TO_MACF(bssid));

	return err;
}

static int
wps_pbcd_add_rrm_nbr(char *ifname, nbr_rpt_elem_t *nbr_elt)
{
	int err = BCME_OK;
	char ioctl_buf[WLC_IOCTL_MAXLEN] = {0};

	assert(ifname);
	assert(nbr_elt);

	err = wl_iovar_setbuf(ifname, "rrm_nbr_add_nbr", (void *)nbr_elt,
		sizeof(*nbr_elt), (void *)&ioctl_buf, sizeof(ioctl_buf));

	if (err != BCME_OK) {
		PBCD_EVT_DBG("%s failed to add rrm_nbr info err %d\n", ifname, err);
		return err;
	}

	PBCD_EVT_DBG("%s Successfully addded rrm_nbr info.\n", ifname);

	return err;
}

int
wps_pbcd_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len)
{
	int i, c;
	char *p = ssid_buf;

	if (ssid_len > 32) ssid_len = 32;

	for (i = 0; i < ssid_len; i++) {
		c = (int)ssid[i];
		if (c == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (isprint((uchar)c)) {
			*p++ = (char)c;
		} else {
			p += sprintf(p, "\\x%02X", c);
		}
	}
	*p = '\0';

	return p - ssid_buf;
}

static void
wps_pbcd_dump_min_bss_info(void *bi_generic)
{
	char ssidbuf[SSID_FMT_BUF_LEN] = {0};
	char ea[ETHER_ADDR_STR_LEN] = {0};
	wl_bss_info_v109_1_t *bi;
	bi = (wl_bss_info_v109_1_t*)bi_generic;
	wps_pbcd_format_ssid(ssidbuf, bi->SSID, bi->SSID_len);
	PBCD_EVT_DBG("wps_pbcd: SSID: \"%s\", BSSID: %s, chanspec: 0x%04x\n",
		ssidbuf, ether_etoa((uchar *) &bi->BSSID, ea), dtohchanspec(bi->chanspec));
}

/* Returns the rnr info matching the ifname */
static wps_pbcd_radio_rnr_info_t*
wps_pbcd_get_rnr_info(char *ifname)
{
	int idx;
	wps_pbcd_radio_rnr_info_t *rnr_info;

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		rnr_info = &g_wps_pbcd_info_list->radio_rnr_info[idx];
		if (!strcmp(rnr_info->ifname, ifname)) {
			return rnr_info;
		}
	}

	return NULL;
}

/* Timer callback function to free escanresults memory if E_STATUS_SUCCESS not received */
static void
wps_pbcd_escanresults_tm_cb(bcm_usched_handle *hdl, void *arg)
{
	int idx;
	char *ifname = NULL;
	struct escan_bss **phead;
	struct escan_bss *result;
	nbr_rpt_elem_t nbr_elt;
	wps_pbcd_radio_rnr_info_t *ri = NULL;
	wps_pbcd_radio_rnr_info_t *rnr_info;

	rnr_info = (wps_pbcd_radio_rnr_info_t *)arg;
	rnr_info->escan_timer = FALSE;
	ifname = rnr_info->ifname;

	phead = &rnr_info->escan_bss_head;
	assert(phead);

	/* dump escanresults */
	for (result = *phead; result; result = result->next) {
		wps_pbcd_dump_min_bss_info(result->bss);
	}

	/* add RRM_NBR into 2G/5G ifaces */
	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		ri = &g_wps_pbcd_info_list->radio_rnr_info[idx];
		if (!ri->enabled || !strncmp(ifname, ri->ifname, IFNAMSIZ) ||
			(ri->band_type == WLC_BAND_6G) ||
			(ri->bss_info_count >= MAX_OCE_RRM_NBR_ELMNTS)) {
			PBCD_DBG("%s skipped source ifname %s enabled %d band type %d"
					" bss info count %d\n", ri->ifname, ifname, ri->enabled,
					ri->band_type, ri->bss_info_count);
			continue;
		}

		for (result = *phead; result && ri->bss_info_count < MAX_OCE_RRM_NBR_ELMNTS;
			result = result->next) {
			memset(&nbr_elt, 0, sizeof(nbr_elt));
			if (wps_pbcd_fill_rrm_nbr_info(ifname, result->bss, &nbr_elt)) {
				PBCD_ERR("%s failed to fill rrm_nbr\n", ifname);
				continue;
			}

			if (wps_pbcd_add_rrm_nbr(ri->ifname, &nbr_elt) == BCME_OK) {
				ri->bss_info_count++;
			}
		}
	}

	wps_pbcd_free_escan_list(phead);
}

/*
 * OCE RNR element addition between 2G and 5G iface on escanresults
 * MAX 5 RNR elemtents added in beacons/probe_responses.
 */
static void
wps_pbcd_escanresults_evt_hndlr(bcm_event_t *be, char *ifname)
{
	int idx = -1;
	uint32 status;
	wl_escan_result_t *escan_data = NULL;
	struct escan_bss *result;
	struct escan_bss **phead;
	wl_bss_info_t *bss;
	wl_bss_info_t *bi;
	wps_pbcd_radio_rnr_info_t *rnr_info;
	int oce_enable = 0;

	rnr_info = wps_pbcd_get_rnr_info(ifname);
	if (!rnr_info) {
		PBCD_EVT_DBG("%s is not present in the rnr info list\n", ifname);
		return;
	}

	/* handle escan results only for nvram oce_cert_test=1 */
	oce_enable = wl_iovar_xtlv_getint(ifname, "oce", WL_OCE_IOV_VERSION, WL_OCE_CMD_ENABLE,
		WL_OCE_XTLV_ENABLE, BCM_XTLV_OPTION_ALIGN32);
	if (!oce_enable) {
		PBCD_EVT_DBG("%s oce is not enable, skip adding nbr\n", ifname);
		return;
	}

	if (!atoi(nvram_safe_get("oce_cert_test"))) {
		PBCD_EVT_DBG("oce cert is not enable, skip adding nbr\n");
		return;
	}

	if (!rnr_info->is_ap) {
		PBCD_EVT_DBG("%s skip escanresults radio is not operating in  ap mode\n", ifname);
		return;
	}

	phead = &rnr_info->escan_bss_head;
	assert(phead);

	/* register a timer cb fn to add avialble BSS info from partial escanresults
	 * into rrm_nbr info and free alloced memory after ESCAN_TIMEOUT seconds if
	 * STATUS_SUCCESS is not rxed for escanresults.
	 */
	if (rnr_info->escan_timer == FALSE) {
		if (wps_pbcd_add_timers(g_wps_pbcd_info_list->usched_hdl,
			rnr_info, PBCD_SEC_MICROSEC(WPS_PBCD_ESCAN_TIMEOUT),
			wps_pbcd_escanresults_tm_cb, 0) == BCM_USCHEDE_OK) {
			PBCD_EVT_DBG("%s: escanresults timer added\n", ifname);
			rnr_info->escan_timer = TRUE;
		}
	}

	escan_data = (wl_escan_result_t*)(be + 1);

	status = ntoh32(be->event.status);

	if (status == WLC_E_STATUS_PARTIAL) {
		bi = &escan_data->bss_info[0];
		/* check if we've received info of same BSSID */
		for (result = *phead; result; result = result->next) {
			bss =  (wl_bss_info_t *)result->bss;
			if (memcmp(bi->BSSID.octet, bss->BSSID.octet, ETHER_ADDR_LEN) ||
				(CHSPEC_BAND(bi->chanspec) != CHSPEC_BAND(bss->chanspec)) ||
				(bi->SSID_len != bss->SSID_len) ||
				memcmp(bi->SSID, bss->SSID, bi->SSID_len)) {
				continue;
			}

			if (bi->RSSI == WLC_RSSI_INVALID || bi->RSSI <= bss->RSSI) {
				break;
			}

			/* Update only when RSSI is valid, its on-channel or from probe resp */
			if ((bss->RSSI == WLC_RSSI_INVALID) ||
				((bi->flags & WL_BSS_FLAGS_RSSI_ONCHANNEL) &&
				!(bss->flags & WL_BSS_FLAGS_RSSI_ONCHANNEL)) ||
				(!(bi->flags & WL_BSS_FLAGS_FROM_BEACON) &&
				(bss->flags & WL_BSS_FLAGS_FROM_BEACON))) {
				bss->RSSI = bi->RSSI;
				bss->SNR = bi->SNR;
				bss->phy_noise = bi->phy_noise;
				bss->flags = bi->flags;
			}
			break;
		}

		if (!result) {
			/* New BSS. Allocate memory and save it */
			int size = OFFSETOF(struct escan_bss, bss) + bi->length;
			struct escan_bss *ebss = (struct escan_bss*)calloc(1, size);

			if (!ebss) {
				PBCD_ERR("failed to allocate memory of %d bytes\n", size);
				wps_pbcd_free_escan_list(phead);
				return;
			}

			memcpy(&ebss->bss, bi, bi->length);
			ebss->next = *phead;
			*phead = ebss;
		}
	} else if (status == WLC_E_STATUS_SUCCESS) {
		PBCD_EVT_DBG("%s: WLC_E_STATUS_SUCCESS received. remove timer\n", ifname);

		if (wps_pbcd_remove_timers(g_wps_pbcd_info_list->usched_hdl,
			wps_pbcd_escanresults_tm_cb, rnr_info) != BCME_OK) {
			PBCD_DBG("%s: failed to remove escanresults timer\n", ifname);
		}
		rnr_info->escan_timer = FALSE;

		nbr_rpt_elem_t nbr_elt;
		wps_pbcd_radio_rnr_info_t *ri = NULL;

		/* dump escanresults */
		for (result = *phead; result; result = result->next) {
			wps_pbcd_dump_min_bss_info(result->bss);
		}

		/* add RRM_NBR into 2G/5G ifaces */
		for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
			ri = &g_wps_pbcd_info_list->radio_rnr_info[idx];
			if (!ri->enabled ||(ri->band_type == WLC_BAND_6G) ||
				(ri->bss_info_count >= MAX_OCE_RRM_NBR_ELMNTS)) {
				PBCD_EVT_DBG("%s skipped source ifname %s enabled %d band type %d"
					" bss info count %d\n", ri->ifname, ifname, ri->enabled,
					ri->band_type, ri->bss_info_count);
				continue;
			}

			for (result = *phead; result && ri->bss_info_count < MAX_OCE_RRM_NBR_ELMNTS;
				result = result->next) {
				memset(&nbr_elt, 0, sizeof(nbr_elt));
				if (wps_pbcd_fill_rrm_nbr_info(ifname, result->bss, &nbr_elt)) {
					PBCD_EVT_DBG("%s failed to fill  rrm_nbr\n", ifname);
					continue;
				}

				if (wps_pbcd_add_rrm_nbr(ri->ifname, &nbr_elt) == BCME_OK) {
					ri->bss_info_count++;
				}
			}
		}

		/* add self info also to address OCE AP test case 4.5 AP channel report */
		wps_pbcd_set_co_host_nbr_info();

		wps_pbcd_free_escan_list(phead);
	} else {
		PBCD_EVT_DBG("sync_id: %d, status:%d  error/abort\n", escan_data->sync_id, status);
	}
}

static void
wps_pbcd_scan_cmplt_evt_hndlr(char *evt_ifname)
{
	int idx = -1;
	wps_pbcd_radio_rnr_info_t *ri = NULL;

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		ri = &(g_wps_pbcd_info_list->radio_rnr_info[idx]);
		if (!strncmp(evt_ifname, ri->ifname, IFNAMSIZ)) {
			PBCD_EVT_DBG("dest iface same as src %s, skip\n", ri->ifname);
			continue;
		}
		if (ri->enabled != TRUE) {
			PBCD_EVT_DBG("radio %s disabled, skip\n", ri->ifname);
			continue;
		}
		if (ri->rnr_src_iflist[0] == '\0') {
			PBCD_EVT_DBG("%s: no rnr_src_list, skip", ri->ifname);
			continue;
		}

		if (!find_in_list(ri->rnr_src_iflist, evt_ifname)) {
			PBCD_EVT_DBG("%s not in rnr_src_iflist, skip\n", evt_ifname);
			continue;
		}
		wps_pbcd_update_rnr_list(evt_ifname, ri);
	}
}

static void
wps_pbcd_e_link_evt_hndlr(char *evt_ifname, wl_event_msg_t *event)
{
	bss_list_t *ri_bss_list = NULL;
	int idx = -1;
	struct ether_addr bssid;
	wps_pbcd_radio_rnr_info_t *ri = NULL;
	nbr_rpt_elem_t nbr_elt;
	char ioctl_buf[WLC_IOCTL_MAXLEN] = {0};
	char *primary_ifname_for_event = NULL;
	wl_bss_info_t *bi;
	uint8 band_type = 0;

	band_type = wps_pbcd_get_band_type(evt_ifname);

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		ri = &(g_wps_pbcd_info_list->radio_rnr_info[idx]);

		if (!ri->enabled) {
			continue;
		}
		if (ri->band_type == band_type) {
			primary_ifname_for_event = ri->ifname;
			break;
		}
	}

	if (!primary_ifname_for_event) {
		/* no radio holding this bss, return */
		return;
	}

	memcpy(&bssid, &(event->addr), sizeof(struct ether_addr));

	if (ntoh16(event->flags) & WLC_EVENT_MSG_LINK) {
		*(uint32*)ioctl_buf = htod32(WLC_IOCTL_MAXLEN);
		if (wl_ioctl(evt_ifname, WLC_GET_BSS_INFO, ioctl_buf, WLC_IOCTL_MAXLEN)) {
			PBCD_ERR("%s failed to get bss info.\n", evt_ifname);
			return;
		}
		bi = (wl_bss_info_t*)(ioctl_buf + sizeof(uint32));

		memset(&nbr_elt, 0, sizeof(nbr_elt));
		if (wps_pbcd_fill_rrm_nbr_info(evt_ifname, bi, &nbr_elt) != BCME_OK) {
			PBCD_ERR("%s failed to fill bss info into rrm_nbr\n", evt_ifname);
			return;
		}
	}

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		ri = &(g_wps_pbcd_info_list->radio_rnr_info[idx]);

		if (!ri->enabled) {
			continue;
		}

		if (ri->oob_nbr_radio_list[0] == '\0') {
			/* no nbr list present for radio, only update 6G's info if present
			 * to 2G and 5G
			 */
			if (ri->band_type == WLC_BAND_6G) {
				continue;
			}
			if (band_type != WLC_BAND_6G) {
				/* this is not required, as for no_nbr_radio_list
				 * radio contains only 6G as nbrs
				 */
				continue;
			}
			ri_bss_list = ri->bss_list;
			while (ri_bss_list) {
				if (!strncmp(evt_ifname, ri_bss_list->ifname, IFNAMSIZ)) {
					ri_bss_list = ri_bss_list->next;
					continue;
				}

				if (ntoh16(event->flags) & WLC_EVENT_MSG_LINK) {
					wps_pbcd_add_rrm_nbr(ri_bss_list->ifname, &nbr_elt);
				} else {
					wps_pbcd_remove_rrm_nbr(ri_bss_list->ifname, &bssid);
				}
				ri_bss_list = ri_bss_list->next;
			}
		} else {
			wps_pbcd_remove_rrm_nbr(ri->ifname, &bssid);
			if (!find_in_list(ri->oob_nbr_radio_list, primary_ifname_for_event)) {
				PBCD_EVT_DBG("%s not in oob_nbr_radio_list[%s], skip\n",
					primary_ifname_for_event, ri->oob_nbr_radio_list);
				continue;
			}
			ri_bss_list = ri->bss_list;
			while (ri_bss_list) {
				if (!strncmp(evt_ifname, ri_bss_list->ifname, IFNAMSIZ)) {
					ri_bss_list = ri_bss_list->next;
					continue;
				}

				if (ntoh16(event->flags) & WLC_EVENT_MSG_LINK) {
					wps_pbcd_add_rrm_nbr(ri_bss_list->ifname, &nbr_elt);
				} else {
					wps_pbcd_remove_rrm_nbr(ri_bss_list->ifname, &bssid);
				}
				ri_bss_list = ri_bss_list->next;
			}
		}
	}
}

/*
 * dispatch driver event from EAPD to corresponding handler
 */
static void
wps_pbcd_drv_events_cb(bcm_usched_handle *hdl, void *arg, bcm_usched_fds_entry_t *entry)
{
	static char pkt[WPS_PBCD_PKT_BUF_SIZE] = {0};
	char ifname[IFNAMSIZ] = {0};
	struct sockaddr_in from;
	bcm_event_t *dpkt = NULL;
	int event_type = -1, sock = -1, sock_len = -1;
	ssize_t nbytes = -1;

	if ((hdl == NULL) || (arg == NULL)) {
		PBCD_ERR("hdl or arg NULL\n");
		return;
	}

	sock = *((int *)arg);
	sock_len = sizeof(struct sockaddr_in);

	if ((nbytes = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&from,
			(socklen_t *)&sock_len)) < 0) {
		PBCD_ERR("recvfrom()\n");
		return;
	}

	dpkt = (bcm_event_t *)(pkt + IFNAMSIZ);
	event_type = ntohl(dpkt->event.event_type);

	if (event_type >= WLC_E_LAST) {
		PBCD_ERR("unknown event %d\n", event_type);
		return;
	}

	/* copy interface name prepended to driver event. */
	hapd_wpasupp_strncpy(ifname, pkt, IFNAMSIZ);

	PBCD_EVT_DBG("ifname %s received on sock %d event %d size %zu bytes\n", ifname, sock,
		event_type, (size_t)nbytes);

	switch (event_type) {
	case WLC_E_LINK:
#ifdef HAPD_WDS
		if (!strncmp(ifname, WDS_DEV_NAME, strlen(WDS_DEV_NAME))) {
			hapd_wpasupp_wds_hndlr(pkt);
		}
#endif /* HAPD_WDS */
		wps_pbcd_e_link_evt_hndlr(ifname, &(dpkt->event));
		break;
	case WLC_E_SCAN_COMPLETE:
		wps_pbcd_scan_cmplt_evt_hndlr(ifname);
		break;
	case WLC_E_ESCAN_RESULT:
		wps_pbcd_escanresults_evt_hndlr(dpkt, ifname);
		break;
	default:
		PBCD_EVT_DBG("default case: event %d, ifname %s\n", event_type, ifname);
		break;
	}
}

/*
 * schedule the callback for driver events from EAPD
 */
static int
wps_pbcd_schedule_drv_events(wps_pbcd_info_list_t *list)
{
	int reuse = 1, ret = -1;
	list->rgd_sockfd = -1;
	struct sockaddr_in sockaddr;

	/* open loopback socket to communicate with EAPD */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_RGD_UDP_SPORT);

	if ((list->rgd_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		PBCD_ERR("failed to create socket\n");
		goto end;
	}

	if ((ret = setsockopt(list->rgd_sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse,
			sizeof(reuse))) < 0) {
		PBCD_ERR("failed to setsockopt to loopback socket %d\n", list->rgd_sockfd);
		close(list->rgd_sockfd);
		goto end;
	}

	if ((ret = bind(list->rgd_sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0) {
		PBCD_ERR("failed to bind to loopback socket %d\n", list->rgd_sockfd);
		close(list->rgd_sockfd);
		goto end;
	}

	ret = wps_pbcd_add_fd_to_schedule(list->usched_hdl, list->rgd_sockfd,
		&(list->rgd_sockfd), wps_pbcd_drv_events_cb);

	PBCD_DBG_DETAIL("opened loopback socket %d\n", list->rgd_sockfd);

end:
	return ret;
}

/* Initialize the pbcd */
static int
wps_pbcd_init(wps_pbcd_info_list_t *list)
{
	int idx;
	wps_pbcd_info_t *pbcd_info = NULL;
	int ret = 0;

	list->usched_hdl = bcm_usched_init();
	if (list->usched_hdl == NULL) {
		PBCD_ERR("failed to create usched handle\n");
		return -1;
	}

	if (wps_pbcd_schedule_drv_events(list) != 0) {
		PBCD_ERR("failed to schedule fd for WDS e_link handler\n");

	}

	for (idx = 0; idx < list->count; idx++) {
		pbcd_info = list->wps_pbcd_info_objects[idx];
		pbcd_info->wpa_ctrl_handle = wpa_ctrl_open(pbcd_info->wpa_ctrl_dir);

		if (!pbcd_info->wpa_ctrl_handle) {
			PBCD_ERR("failed to open connection to %s\n", pbcd_info->wpa_ctrl_dir);
			continue;
		}

		if ((ret = wpa_ctrl_attach(pbcd_info->wpa_ctrl_handle))) {
			PBCD_ERR("failed to attach to %s ret %d\n", pbcd_info->wpa_ctrl_dir, ret);
			wpa_ctrl_close(pbcd_info->wpa_ctrl_handle);
			pbcd_info->wpa_ctrl_handle = NULL;
			continue;
		}

		pbcd_info->wpa_ctrl_fd = wpa_ctrl_get_fd(pbcd_info->wpa_ctrl_handle);
		ret = wps_pbcd_add_fd_to_schedule(list->usched_hdl, pbcd_info->wpa_ctrl_fd,
			pbcd_info, wps_pbcd_process_ctrl_evt_fd_cb);
		if (ret) {
			PBCD_ERR("failed to add fd of %s to schedule\n", pbcd_info->wpa_ctrl_dir);
			continue;
		}
	}

	return 0;
}

static void
wps_pbcd_run(bcm_usched_handle *hdl)
{
	BCM_USCHED_STATUS status = BCM_USCHEDE_OK;

	BCM_REFERENCE(status);

	status = bcm_usched_run(hdl);

	PBCD_DBG_DETAIL("status code %d: %s\n", status, bcm_usched_strerror(status));
}

#if !defined(STB)
// Gets the timeout value for sequential auto behaviour
static int
wps_pbcd_get_wps_sequential_auto_timeout(char *wps_ifnames)
{
	int count = 0, timeout = -1;
	char ifname[IFNAMSIZ] = {0}, *next;

	foreach(ifname, wps_ifnames, next) {
		count++;
	}

	if (count > 1) {
		timeout = WLIF_WPS_TIMEOUT/count;
	}

	PBCD_DBG("wps will be active for %d secs each on interfaces %s\n", timeout, wps_ifnames);

	return timeout;
}
#endif	/* !STB */

#if !defined(STB)
// Gets the default wps behaviour when user press the button
static wps_pbcd_wps_behaviour_t
wps_pbcd_get_wps_behaviour()
{
	wps_pbcd_wps_behaviour_t wps_behaviour;
	int nvval = atoi(nvram_safe_get("wps_behaviour"));

	// If nvram is not present or having incorrect values
	// than use WPS_SIMULTANEOUS for AP and WPS_SEQUENTIAL_AUTO for STA
	// WPS_SIMULTANEOUS is not allowed for the STA interfaces
	if (nvval <= WPS_SIMULTANEOUS || nvval >= WPS_INVALID_BEHAVIOUR) {
		if (nvram_match("wps_on_sta", "1")) {
			wps_behaviour = WPS_SEQUENTIAL_AUTO;
		} else {
			wps_behaviour = WPS_SIMULTANEOUS;
		}
	} else {
		wps_behaviour = nvval;
	}

	return wps_behaviour;
}
#endif	/* !STB */
// Initializes the board_fp for wps gpio led updates
static int
wps_pbcd_gpio_led_init_handler()
{
	int board_fp = 0;

	pthread_mutex_lock(&g_wps_pbcd_gpio_led_lock);
	board_fp = g_wps_data.board_fp;
	if (board_fp <= 0) {
		board_fp = g_wps_data.board_fp = wl_wlif_wps_gpio_init();
	}
	pthread_mutex_unlock(&g_wps_pbcd_gpio_led_lock);

	return board_fp;
}

// Cleanup routine for board_fp
static void
wps_pbcd_gpio_board_cleanup()
{
	pthread_mutex_lock(&g_wps_pbcd_gpio_led_lock);
	wl_wlif_wps_gpio_cleanup(g_wps_data.board_fp);
	pthread_mutex_unlock(&g_wps_pbcd_gpio_led_lock);
}

// WPS reference UI displays a brute-force attacker warning message when pin validation fails.
// This function updates nvram wps_pinfail_state and wps_pinfail_mac which are used in UI for
// displaing the attacker warning msg.
static void
wps_pbcd_update_pin_validation_state(char *mac, char *state)
{
	if (mac) {
		nvram_set("wps_pinfail_mac", mac);
	} else {
		nvram_set("wps_pinfail_mac", "");
	}

	if (state) {
		nvram_set("wps_pinfail_state", state);
	} else {
		nvram_set("wps_pinfail_state", "");
	}
}

/* Update the UI (wps_proc_status nvram) and wps led based on the various wps events
 * received at wpa control interface.
 */
static void
wps_pbcd_led_and_ui_status_update_handler(wps_pbcd_info_t *pbcd_info)
{
	char *data = pbcd_info->reply_buf;
	wlif_wps_ui_status_code_id_t idx = WLIF_WPS_UI_INVALID;
	wlif_wps_blinktype_t blink_type = WLIF_WPS_BLINKTYPE_INVALID;
	char peer_mac[18] = {0};
	bool pin_validation_failure = FALSE;
	int pin_fail_detected_in_m4 = 0;

	if (strstr(data, WPS_EVENT_ACTIVE)) {	// PBC is active
		idx = (pbcd_info->wps_mode == WLIF_WPS_REGISTRAR) ? WLIF_WPS_UI_FINDING_PBC_STA :
			WLIF_WPS_UI_FIND_PBC_AP;
		blink_type = WLIF_WPS_BLINKTYPE_INPROGRESS;
	} else if (strstr(data, WPS_EVENT_SUCCESS)) {	// Wps is successful
		idx = WLIF_WPS_UI_OK;
		blink_type = WLIF_WPS_BLINKTYPE_STOP;
	} else if (strstr(data, WPS_EVENT_OVERLAP)) {	// PBC overlap detected during wps
		idx = WLIF_WPS_UI_PBCOVERLAP;
		blink_type = WLIF_WPS_BLINKTYPE_OVERLAP;
	} else if (strstr(data, WPS_EVENT_TIMEOUT)) {	// Wps session timedout
		idx = WLIF_WPS_UI_TIMEOUT;
		blink_type = WLIF_WPS_BLINKTYPE_STOP;
	} else if (strstr(data, WPS_EVENT_FAIL)) { // Wps session failed
		idx = WLIF_WPS_UI_ERR;
		blink_type = WLIF_WPS_BLINKTYPE_STOP;
		/* While using Jumpstart ER to configure aput with the same existing credentials,
		 * wps exits after M7 msg and hostapd returns WPS-FAIL to the control interface but
		 * Jumpstart UI shows as success.
		 * For keeping the behaviour same across nas and hostapd updating UI with success.
		 */
		if (strstr(data, WPS_PBCD_MSG_M7) && strstr(data, WPS_PBCD_CFG_NO_ERR)) {
			idx = WLIF_WPS_UI_OK;
		}

		// Check if wps failure is due to the pin validation error
		if (strstr(data, WPS_PBCD_CFG_PIN_VALIDATION_ERR)) {
			char *ptr, *mac_token = "peer_macaddr=";

			if (strstr(data, WPS_PBCD_MSG_M4)) {
				pin_fail_detected_in_m4 = 1;
			}

			ptr = strstr(data, mac_token);
			if (ptr) {
				ptr += strlen(mac_token);
				WLIF_STRNCPY(peer_mac, ptr, sizeof(peer_mac));
			}
			pin_validation_failure = TRUE;
		}
	}

	pthread_mutex_lock(&g_wps_pbcd_gpio_led_lock);

	if (idx != WLIF_WPS_UI_INVALID && !pbcd_info->skip_ui_update) {
		wl_wlif_update_wps_ui(idx);
	}

	if (pbcd_info->skip_ui_update) {
		pbcd_info->skip_ui_update = FALSE;
	}

	if (blink_type != WLIF_WPS_BLINKTYPE_INVALID) {
		wl_wlif_wps_gpio_led_blink(pbcd_info->gpio_board_fp, blink_type);
	}

	// In GUI display the brute-force attack warning msg when pin validation gets failed.
	// Once wps is successful remove any previously displayed brute-force attack warning msg.
	if (pin_validation_failure) {
		wps_pbcd_update_pin_validation_state(peer_mac,
			pin_fail_detected_in_m4 ? "M4" : "M6");
	} else if (idx == WLIF_WPS_UI_OK) {
		wps_pbcd_update_pin_validation_state(NULL, NULL);
	}
	pthread_mutex_unlock(&g_wps_pbcd_gpio_led_lock);
}

// Resets the wps_data ifname when wps session either fails or succeeds
static void
wps_pbcd_reset_wps_ifnames_data_handler(char *data)
{
	if (strstr(data, WPS_EVENT_SUCCESS) || strstr(data, WPS_EVENT_OVERLAP) ||
		strstr(data, WPS_EVENT_TIMEOUT) || strstr(data, WPS_EVENT_FAIL)) {
		pthread_mutex_lock(&g_wps_pbcd_lock);
		memset(&g_wps_data.pbc_ifname, 0, sizeof(g_wps_data.pbc_ifname));
		g_wps_data.wlunit_bitflag = 0;
		pthread_mutex_unlock(&g_wps_pbcd_lock);
	}
}

/* For the Registrar case need to check whether device is oob or not
 * While in case of Enrollee it always needs to be configured
 */
static bool
wps_pbcd_does_dev_needs_to_be_configured(char *ifname, wlif_wps_mode_t wps_mode)
{
	if (wps_mode == WLIF_WPS_REGISTRAR) {
		return wl_wlif_does_ap_needs_to_be_configured(ifname);
	}

	return TRUE;
}

#ifdef MULTIAP
// System restart routine for different platforms
static void
wps_pbcd_sys_restart(char *ifname)
{
#if 0
#ifdef BCA_CPEROUTER
	system("nvram commit restart");
#elif defined(STB)
	sleep(1);
	do {
	       char signal[] = "XXXX";
	       snprintf(signal, sizeof(signal), "-%d", SIGHUP);
	       eval("killall", signal, "rc");
	} while (0);
#else
	kill(1, SIGHUP);
#endif /* BCA_CPEROUTER */
#else
	notify_rc("restart_wireless");
#endif
}
#endif /* MULTIAP */

// Routine to parse the uint16 data from the hex string.
static void
wps_pbcd_parse_short(char *src, uint16 *dst)
{
	char strbuf[5] = {0};

	WLIF_STRNCPY(strbuf, src, sizeof(strbuf));
	*dst = (uint16) strtoul(strbuf, NULL, 16);
}

/* Routine to parse the encryption settings received at the control interface as hex string.
 * Hex string contains the data in wps tlv format where attribute type and length both are of
 * two bytes. eg data: 100e0033... here 100e is the attribute type of credentials (WPS_ATTR_CRED)
 * and 0033 is the length of WPS_ATTR_CRED.
 */
static int
wps_pbcd_parse_encr_settings_buf(char *buf, int total_len, wlif_wps_nw_creds_t *creds)
{
	char *start = NULL, *end = NULL;
	uint16 type = 0, len = 0, parse_len = 0;
	uint16 auth_val = 0, encr_val = 0;
	long int tot_len = 0;

	start = buf;
	end = start + total_len;

	memset(creds, 0, sizeof(*creds));
	while (start < end) {
		// Length check before parsing wps attribute type and length
		tot_len = end - start;
		if (tot_len < WPS_PBCD_WPS_ATTR_TYPE_LEN_SIZE) {
			PBCD_ERR("at line %d buffer size %ld is big expected < %d\n",
				__LINE__, tot_len, WPS_PBCD_WPS_ATTR_TYPE_LEN_SIZE);
			return -1;
		}

		// Parse wps attribute type of 2 bytes
		wps_pbcd_parse_short(start, &type);
		start += 4;

		// Parse wps attribute len type of 2 bytes
		wps_pbcd_parse_short(start, &len);
		start += 4;

		// Buf is hex string the length need to be parsed to the double of the length
		parse_len = len * 2;

		tot_len = end - start;
		if (tot_len < parse_len) {
			PBCD_ERR("at line %d buffer size %ld is big expected < %d \n",
				__LINE__, tot_len, parse_len);
			return -1;
		}

		switch (type) {
		// All the other attributes are encapsulated inside the WPS_ATTR_CRED
		// Skip parsing the WPS_ATTR_CRED.
		case WPS_ATTR_CRED:
			break;

		// Parse wps attribute ssid type
		case WPS_ATTR_SSID:
			if (len > WLIF_SSID_MAX_SZ) {
				PBCD_ERR("received invalid ssid of len %d max ssid len %d\n ",
					len, WLIF_SSID_MAX_SZ);
				creds->invalid = TRUE;
				return -1;
			}
			hex_to_bytes((unsigned char*)creds->ssid, sizeof(creds->ssid),
				(unsigned char*)start, parse_len);
			creds->ssid[len] = '\0';
			start += parse_len;
			break;

		// Parse wps attribute network key type
		case WPS_ATTR_NETWORK_KEY:
			if (len > WLIF_PSK_MAX_SZ) {
				PBCD_ERR("received invalid psk of len %d max psk len %d\n ",
					len, WLIF_PSK_MAX_SZ);
				creds->invalid = TRUE;
				return -1;
			}
			hex_to_bytes((unsigned char*)creds->nw_key, sizeof(creds->nw_key),
				(unsigned char*)start, parse_len);
			creds->nw_key[len] = '\0';
			start += parse_len;
			break;

		// Parse wps attribute auth type
		case WPS_ATTR_AUTH_TYPE:
			if (len != 2) {
				PBCD_ERR("received invalid auth length %d expected 2\n ", len);
				creds->invalid = TRUE;
				return -1;
			}

			wps_pbcd_parse_short(start, &auth_val);
			if (auth_val & WPS_PBCD_WPS_AUTH_WPAPSK) {
				creds->akm |= WLIF_WPA_AKM_PSK;
			}
			if (auth_val & WPS_PBCD_WPS_AUTH_WPA2PSK) {
				creds->akm |= WLIF_WPA_AKM_PSK2;
			}
			start += parse_len;
			break;

		// Parse wps attribute auth type
		case WPS_ATTR_ENCR_TYPE:
			if (len != 2) {
				PBCD_ERR("received invalid encr length %d expected 2\n ", len);
				creds->invalid = TRUE;
				return -1;
			}

			wps_pbcd_parse_short(start, &encr_val);
			if (encr_val & WPS_PBCD_WPS_ENCR_TKIP) {
				creds->encr |= WLIF_WPA_ENCR_TKIP;
			}
			if (encr_val & WPS_PBCD_WPS_ENCR_AES) {
				creds->encr |= WLIF_WPA_ENCR_AES;
			}
			start += parse_len;
			break;

		default:
			start += parse_len;
			break;
		}
	}

	return 0;
}

// Sets ap as configured
static void
wps_pbcd_set_ap_as_configured(char *ifname)
{
	wl_wlif_set_ap_as_configured(ifname);
}

// For ap parse the config settings received at the control interface
static int
wps_pbcd_fetch_ap_config_settings(wps_pbcd_info_t *pbcd_info)
{
	int header = strlen(WPS_EVENT_NEW_AP_SETTINGS) + 3 /* <x> */;
	char *data = pbcd_info->reply_buf;
	int len = pbcd_info->reply_len;
	int ret = 0;

	ret = wps_pbcd_parse_encr_settings_buf(data + header, len - header, &pbcd_info->creds);

	PBCD_PRINT("Info: ", "ssid %s psk %s akm %d encr %d\n", pbcd_info->creds.ssid,
		pbcd_info->creds.nw_key, pbcd_info->creds.akm, pbcd_info->creds.encr);

	return ret;
}

// For wps enrollee mode parse network settings received at the control interface
static int
wps_pbcd_fetch_config_settings(wps_pbcd_info_t *pbcd_info)
{
	int header = strlen(WPS_EVENT_CRED_RECEIVED) + 3 /* <x> */;
	char *data = pbcd_info->reply_buf;
	int len = pbcd_info->reply_len;
	int ret = 0;

	ret = wps_pbcd_parse_encr_settings_buf(data + header, len - header, &pbcd_info->creds);

	PBCD_PRINT("Info: ", "ssid %s psk %s akm %d encr %d\n", pbcd_info->creds.ssid,
		pbcd_info->creds.nw_key, pbcd_info->creds.akm, pbcd_info->creds.encr);

	return ret;
}

// Process non wps events received in the hostapd/wpa-supplicant control interface
static int
non_wps_process_hostapd_wpa_supplicant_ctrl_events(wps_pbcd_info_t *pbcd_info)
{
	return -1;
}

// Process dpp events received in the hostapd control interface
static int hostapd_wpa_supplicant_dpp_ctrl_events(wps_pbcd_info_t *pbcd_info)
{
	char *cptr = NULL;
	char dpp_connector[WPS_PBCD_MAX_BUF] = {0}, dpp_csign[WPS_PBCD_MAX_BUF] = {0};
	char dpp_netaccesskey[WPS_PBCD_MAX_BUF] = {0}, cmd[2*WPS_PBCD_MAX_BUF] = {0};
	char dpp_ssid[WPS_PBCD_MAX_BUF] = {0}, dpp_akm[WPS_PBCD_MAX_BUF] = {0};
	char tmp[WPS_PBCD_NVNAME_BUF_SIZE] = {0};
	bool ap = 0;

	PBCD_INFO("\nInfo: wps_pbcd %s %d received on %s len [%zu] and data [%s] \n", __func__,
		__LINE__, pbcd_info->wpa_ctrl_dir, pbcd_info->reply_len, pbcd_info->reply_buf);

	snprintf(tmp, sizeof(tmp), "%s_mode", pbcd_info->bss.nvifname);
	ap = nvram_match(tmp, "ap");

	/* Sample event : <3>DPP-CONFOBJ-AKM dpp */
	if ((cptr = strstr(pbcd_info->reply_buf, DPP_EVENT_CONNECTOR))) {
		strncpy(dpp_connector, cptr + strlen(DPP_CONNECTOR_PREFIX) - 3 /* '<3>' */,
				pbcd_info->reply_len - strlen(DPP_CONNECTOR_PREFIX));
		dpp_connector[pbcd_info->reply_len - strlen(DPP_CONNECTOR_PREFIX)] = '\0';
		strncpy(pbcd_info->dpp_creds.dpp_connector, dpp_connector,
				pbcd_info->reply_len - strlen(DPP_CONNECTOR_PREFIX));
		if (ap) {
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set dpp_connector %s",
					pbcd_info->bss.ifname, dpp_connector);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
		}
	} else if ((cptr = strstr(pbcd_info->reply_buf, DPP_EVENT_C_SIGN_KEY))) {
		strncpy(dpp_csign,  cptr + strlen(DPP_C_SIGN_KEY_PREFIX) - 3 /* '<3>' */,
				pbcd_info->reply_len - strlen(DPP_C_SIGN_KEY_PREFIX));
		dpp_csign[pbcd_info->reply_len - strlen(DPP_C_SIGN_KEY_PREFIX)] = '\0';
		strncpy(pbcd_info->dpp_creds.dpp_csign, dpp_csign,
				pbcd_info->reply_len - strlen(DPP_C_SIGN_KEY_PREFIX));
		if (ap) {
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set dpp_csign %s",
					pbcd_info->bss.ifname, dpp_csign);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
		}
	} else if ((cptr = strstr(pbcd_info->reply_buf, DPP_EVENT_NET_ACCESS_KEY))) {
		strncpy(dpp_netaccesskey, cptr + strlen(DPP_NET_ACCESS_KEY_PREFIX) - 3,
				pbcd_info->reply_len - strlen(DPP_NET_ACCESS_KEY_PREFIX));
		dpp_netaccesskey[pbcd_info->reply_len -
			strlen(DPP_NET_ACCESS_KEY_PREFIX)] = '\0';
		strncpy(pbcd_info->dpp_creds.dpp_netaccess_key, dpp_netaccesskey,
				pbcd_info->reply_len - strlen(DPP_NET_ACCESS_KEY_PREFIX));
		if (ap) {
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set dpp_netaccesskey %s",
					pbcd_info->bss.ifname, dpp_netaccesskey);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
			sleep(1);
			/* This is the last DPP event received during configuration response
			 * processing
			 */
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s reload",
					pbcd_info->bss.ifname);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
		}
		wl_wlif_apply_dpp_creds(&pbcd_info->bss, &pbcd_info->dpp_creds);
	} else if ((cptr = strstr(pbcd_info->reply_buf, DPP_EVENT_CONFOBJ_SSID))) {
		strncpy(dpp_ssid, cptr + strlen(DPP_SSID_PREFIX) - 3 /* '<3>' */,
				pbcd_info->reply_len - strlen(DPP_SSID_PREFIX));
		dpp_ssid[pbcd_info->reply_len - strlen(DPP_SSID_PREFIX)] = '\0';
		strncpy(pbcd_info->dpp_creds.ssid, dpp_ssid,
				pbcd_info->reply_len - strlen(DPP_SSID_PREFIX));
		if (ap) {
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set ssid %s",
					pbcd_info->bss.ifname, dpp_ssid);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
		}
	} else if ((cptr = strstr(pbcd_info->reply_buf, DPP_EVENT_CONFOBJ_AKM))) {
		strncpy(dpp_akm, cptr + strlen(DPP_AKM_PREFIX) - 3 /* '<3>' */,
				pbcd_info->reply_len - strlen(DPP_AKM_PREFIX));
		dpp_akm[pbcd_info->reply_len - strlen(DPP_AKM_PREFIX)] = '\0';
		strncpy(pbcd_info->dpp_creds.akm, dpp_akm,
				pbcd_info->reply_len - strlen(DPP_AKM_PREFIX));

		/* If akm is dpp, set dpp specific parameters */
		if (ap && (strncmp(dpp_akm, DPP_AKM, strlen(DPP_AKM)) == 0)) {
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set wpa 2",
					pbcd_info->bss.ifname);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set wpa_key_mgmt DPP",
					pbcd_info->bss.ifname);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set wpa_pairwise CCMP",
					pbcd_info->bss.ifname);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set rsn_pairwise CCMP",
					pbcd_info->bss.ifname);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s set ieee80211w 2",
					pbcd_info->bss.ifname);
			system(cmd);
			PBCD_INFO("\n %s: %d, cmd = %s\n", __func__, __LINE__, cmd);
		}
	}

	return 0;
}

// Process the wps and dpp related events received in the hostapd/wpa-supplicant control interface
static int
wps_pbcd_process_hostapd_wpasupplicant_ctrl_events(wps_pbcd_info_t *pbcd_info)
{
	char *data = pbcd_info->reply_buf;

	PBCD_INFO("\nInfo: wps_pbcd %s %d received on %s len [%zu] and data [%s] \n", __func__,
		__LINE__, pbcd_info->wpa_ctrl_dir, pbcd_info->reply_len, pbcd_info->reply_buf);

	/* Set dpp_connector, dpp_csign and dpp_netaccesskey on AP.
	 * These are generated as output of dpp_configurator_sign,
	 * which is used on AP to provision itself while acting as
	 * configurator.
	 */
	if (pbcd_info->dpp_wpa_ctrl_events_handler) {
		pbcd_info->dpp_wpa_ctrl_events_handler(pbcd_info);
	}

	// Skip any non wps and unwanted wps messages
	if (!strstr(data, "WPS") || strstr(data, WPS_EVENT_ENROLLEE_SEEN) ||
		strstr(data, WPS_EVENT_AP_AVAILABLE) ||
		strstr(data, WPS_EVENT_AP_AVAILABLE_PIN) ||
		strstr(data, WPS_EVENT_AP_AVAILABLE_PBC) ||
		strstr(data, WPS_EVENT_AP_AVAILABLE_AUTH) ||
		/* Even thoght the pbc session is not active in device itself, hostapd can still
		 * detect pbc session overlap based on the probe requests it received from nearby
		 * devices.Led and ui status should be updated only when user starts pbc session
		 * in device, hence skipping the ui and led status update on receiving pbc overlap
		 * event without starting of pbc session in device.
		 */
		(strstr(data, WPS_EVENT_OVERLAP) && wl_wlif_get_wps_status_code() <= 0)) {
		if (pbcd_info->non_wps_wpa_ctrl_events_handler)
			return pbcd_info->non_wps_wpa_ctrl_events_handler(pbcd_info);
		else
			return -1;
	}

	PBCD_PRINT("Info: ", "\nreceived on %s len [%zu] and data [%s] \n",
		pbcd_info->wpa_ctrl_dir, pbcd_info->reply_len, pbcd_info->reply_buf);

	// On receiving the wps active event update the pbc ifname
	if (strstr(data, WPS_EVENT_ACTIVE)) {
		pthread_mutex_lock(&g_wps_pbcd_lock);
		WLIF_STRNCPY(g_wps_data.pbc_ifname, pbcd_info->bss.ifname,
			sizeof(g_wps_data.pbc_ifname));
		pthread_mutex_unlock(&g_wps_pbcd_lock);
	}

	pbcd_info->led_and_ui_status_update_handler(pbcd_info);

	/*
	 * In case of multiap onboarding after successful wps session supplicant config file
	 * will not be updated instead The backhaul credentials will be received at the
	 * control interface.
	 * In other cases the network config will be received at control interface and
	 * supplicant config file will also be updated.
	 *
	 */
	if (strstr(data, WPS_EVENT_CRED_RECEIVED)) {
		pbcd_info->get_network_settings(pbcd_info);
	}

	/*
	 * In case of ap configuration using the external registrar after successful wps
	 * session the credentials are received at the control interface.
	 */
	if (strstr(data, WPS_EVENT_NEW_AP_SETTINGS)) {
		if (pbcd_info->get_network_settings(pbcd_info) == 0) {
			if (pbcd_info->apply_network_settings(&pbcd_info->bss,
				&pbcd_info->creds) == 0) {
				if (pbcd_info->set_device_configured != NULL) {
					pbcd_info->set_device_configured(pbcd_info->bss.ifname);
				}
			}
		}
	}

	/*
	 * In case of internal registrar after successful wps session the credentials are fetched
	 * from the control interface and nvram are updated.
	 */
	if (strstr(data, WPS_EVENT_SUCCESS)) {
		if (pbcd_info->is_configuration_required(pbcd_info->bss.ifname,
			pbcd_info->wps_mode)) {
			if (pbcd_info->apply_network_settings(&pbcd_info->bss,
				&pbcd_info->creds) == 0) {
				if (pbcd_info->set_device_configured != NULL) {
					pbcd_info->set_device_configured(pbcd_info->bss.ifname);
				}
			}
		}

#if !defined(STB)
		// Set the WPS_SUCCESS bit in notification flags so that any monitoring thread
		// can perform specific operations.
		wps_pbcd_set_notification_flags(WPS_SUCCESS);
#endif	/* !STB */
	}

	pbcd_info->reset_wps_ifnames_data_handler(data);

	return 0;
}

#if !defined(STB)
/* Poll for wps push btm press */
static wps_pbcd_button_press_type_t
wps_pbcd_wps_gpio_btn_pressed(int board_fp)
{
	int trigger = SES_EVENTS;
	wps_pbcd_button_press_type_t btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_UNKNOWN;
	int len = 0;
	int val = 0;

	if ((len = read(board_fp, (char*)&val, sizeof(val))) > 0 && (val & trigger)) {
		if (val & SES_EVENT_BTN_LONG) {
			btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_LONG;
		} else if (val & SES_EVENT_BTN_SHORT) {
			btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_SHORT;
		} else {
			/* Button management interface: Keep reading from the board driver until
			 * button is released and count the press time here
			 */
			int count = 0;
			int lbpcount = 0;
			struct timeval time;

			lbpcount = (WPS_PBCD_LONG_PRESSTIME * 1000000) / WPS_PBCD_BTNSAMPLE_PERIOD;

			while ((len = read(board_fp, (char *)&val,
				sizeof(val))) > 0) {
				time.tv_sec = 0;
				time.tv_usec = WPS_PBCD_BTNSAMPLE_PERIOD;
				select(0, NULL, NULL, NULL, &time);

				if (val & trigger) {
					count++;
				}

				if (count >= lbpcount) {
					break;
				}
			}

			if (count < lbpcount) {
				btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_SHORT;
			} else {
				btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_LONG;
			}
		}
	}

	PBCD_DBG("wps gpio button press type is %s\n",
		btn_event == WPS_PBCD_BUTTON_PRESS_TYPE_LONG ? "LONG" :
		btn_event == WPS_PBCD_BUTTON_PRESS_TYPE_SHORT ? "SHORT" : "UNKNOWN");

	return btn_event;
}
#endif /* !defined(STB) */

#if !defined(STB)
// Registers the callback function to stop the wps led when wps timeout happens.
// This is required only for repeater cases since when wps times out the control interface does
// not receive timeout notification from the wpa_supplicant.
static void
wps_pbcd_register_for_wps_timeout_notification(int board_fp)
{
	int *arg;

	arg = (int*)calloc(1, sizeof(*arg));
	if (arg == NULL) {
		return;
	}
	*arg = board_fp;

	if (wps_pbcd_add_notification_handler(WPS_TIMEOUT, wps_pbcd_stop_wps_led, arg)) {
		PBCD_DBG_DETAIL("registration of notification handler for WPS_TIMEOUT failed\n");
		free(arg);
	}
}

// Registers the callback function to stop the wps when wps gets successful in any interface.
// This is requied only when wps behaviour is to start the wps on all the interfaces simultaneously
static void
wps_pbcd_register_for_wps_success_notification(char *wps_ifnames)
{
	char *arg = strdup(wps_ifnames);

	if (arg == NULL) {
		return;
	}

	if (wps_pbcd_add_notification_handler(WPS_SUCCESS, wps_pbcd_stop_wps, arg)) {
		PBCD_DBG_DETAIL("registration of notification handler for WPS_SUCCESS failed\n");
		free(arg);
	}
}
#endif	/* !STB */

static int
wps_pbcd_get_band_type(char *ifname)
{
	int band_type = 0;

	wl_ioctl(ifname, WLC_GET_BAND, &band_type, sizeof(band_type));

	// If band type is auto than update band type from band list
	if (band_type == WLC_BAND_AUTO) {
		int list[3];    // list[0] is the count, values at index 1, 2 contains band type.
		int j;

		wl_ioctl(ifname, WLC_GET_BANDLIST, list, sizeof(list));
		if (list[0] > 2) {
			list[0] = 2;
		}

		band_type = 0;
		for (j = 1; j < list[0]; j++) {
			if ((list[j] == WLC_BAND_5G) || (list[j] == WLC_BAND_2G) ||
					(list[j] == WLC_BAND_6G)) {
				band_type |= list[j];
			}
		}
	}

	PBCD_INFO("ifname %s, band_type %d\n", ifname, band_type);

	return band_type;
}

/*
 * Fn to fetch all wireless primary radio interfaces in nvram ifname format.
 */
static void
wps_pbcd_get_wl_radio_iflist(char *wl_radio_iflist, int rlistsz)
{
	int unit = -1, subunit = -1;
	char *ifnames_list = NULL; /* concatenated ifnames on br0, br1 etc. with space in between */
	char nv_ifname[IFNAMSIZ] = {0};
	char ifname[IFNAMSIZ] = {0}, *next;

	ifnames_list = calloc(1, rlistsz);
	if (!ifnames_list) {
		PBCD_ERR("calloc failed for %d bytes\n", rlistsz);
		return;
	}

	hapd_wpasupp_get_all_lanifnames_list(ifnames_list, rlistsz);

	foreach(ifname, ifnames_list, next) {
		if (wl_probe(ifname)) {
			PBCD_EVT_DBG("%s: non wireless interface, skip\n", ifname);
			continue;
		}
		if (osifname_to_nvifname(ifname, nv_ifname, IFNAMSIZ) < 0) {
			PBCD_EVT_DBG("%s: error converting osifname to nvifname()\n", ifname);
			continue;
		}
		if (get_ifname_unit(nv_ifname, &unit, &subunit) < 0) {
			PBCD_EVT_DBG("%s: get_ifname_unit() failed \n", nv_ifname);
			continue;
		}

		if (subunit > 0) {
			PBCD_EVT_DBG("%s: secondary BSS, skip\n", ifname);
			continue;
		}

		add_to_list(ifname, wl_radio_iflist, rlistsz);
	}

	PBCD_EVT_DBG("wl_radio_iflist: %s\n", wl_radio_iflist);

	free(ifnames_list);
}

static void
wps_pbcd_dump_bandlist(int bandlist[])
{
	int i;

	for (i = 1; i <= bandlist[0]; i++) {
		if (bandlist[i] == WLC_BAND_6G) {
			PBCD_INFO("6g ");
		} else if (bandlist[i] == WLC_BAND_5G) {
			PBCD_INFO("a ");
		} else if (bandlist[i] == WLC_BAND_2G) {
			PBCD_INFO("b ");
		} else {
			PBCD_INFO("? ");
		}
	}
	PBCD_INFO("\n");
}

static void
wps_pbcd_dump_ri_info(wps_pbcd_info_list_t *g_wpi_list, char *wl_radio_iflist)
{
	int idx = 0;
	char ifname[IFNAMSIZ] = {0}, *next = NULL;
	wps_pbcd_radio_rnr_info_t *ri = NULL;

	foreach(ifname, wl_radio_iflist, next) {
		ri = &(g_wpi_list->radio_rnr_info[idx]);
		PBCD_INFO("%s, %-8s, ", ri->ifname, (ri->enabled == TRUE) ? "ENABLED" : "DISABLED");
		wps_pbcd_dump_bandlist(ri->bandlist);
		idx++;
	}
}

/*
 * popluate idx, ifname and band info, rnr src ifces for all radio interfaces
 */
static int
wps_pbcd_init_radio_rnr_info(wps_pbcd_info_list_t  *g_wpi_list)
{
	int idx = 0, err = BCME_OK;
	char ifname[IFNAMSIZ] = {0}, *next = NULL;
	char nv_name[WPS_PBCD_MIN_BUF_SIZE] = {0};
	char *wl_radio_iflist = NULL; // list of all enabled wireless radio interfaces.
	wps_pbcd_radio_rnr_info_t *ri = NULL;
	int rlistsz = 0; // concatenated list size
	int oob_nbr_discovery = 0;

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		ri = &(g_wpi_list->radio_rnr_info[idx]);
		memset(ri->ifname, 0, sizeof(ri->ifname));
		ri->enabled = FALSE;
		ri->ifidx = -1;
		memset(ri->bandlist, 0, sizeof(ri->bandlist));
		ri->band_type = 0;
		memset(ri->rnr_src_iflist, 0, sizeof(ri->rnr_src_iflist));
		ri->escan_bss_head = NULL;
		ri->escan_timer = FALSE;
		ri->is_ap = FALSE;
		ri->bss_list = NULL;
	}

	rlistsz = hapd_wpasupp_get_all_lanifnames_listsz();

	wl_radio_iflist = calloc(1, rlistsz);
	if (!wl_radio_iflist) {
		PBCD_ERR("calloc() failed to allocate %d bytes\n", rlistsz);
		return BCME_ERROR;
	}

	wps_pbcd_get_wl_radio_iflist(wl_radio_iflist, rlistsz);

	idx = 0;
	foreach(ifname, wl_radio_iflist, next) {
		char *ret = NULL, nv_ifname[IFNAMSIZ] = {0};
		char tmp_ifname[IFNAMSIZ] = {0}, *tmp_next = NULL;
		int unit = -1;

		ri = &(g_wpi_list->radio_rnr_info[idx]);
		ri->ifidx = idx;
		idx++;

		wl_endian_probe(ifname);
		hapd_wpasupp_strncpy(ri->ifname, ifname, IFNAMSIZ);

		if (osifname_to_nvifname(ifname, nv_ifname, IFNAMSIZ) < 0) {
			PBCD_EVT_DBG("%s: error converting osifname to nvifname()\n", ifname);
			continue;
		}

		snprintf(nv_name, sizeof(nv_name), "%s_radio", nv_ifname);
		if ((nvram_match(nv_name, "1"))) {
			ri->enabled = TRUE;
			PBCD_EVT_DBG("radio iface %s enabled\n", ri->ifname);
		} else if ((nvram_match(nv_name, "0"))) {
			ri->enabled = FALSE;
			PBCD_EVT_DBG("radio iface %s disabled\n", ri->ifname);
		} else {
			PBCD_EVT_DBG("radio iface %s does not exist\n", ri->ifname);
		}

		snprintf(nv_name, sizeof(nv_name), "%s_mode", nv_ifname);
		if (nvram_match(nv_name, "ap")) {
			ri->is_ap = TRUE;
		}

		if ((err = wl_ioctl(ri->ifname, WLC_GET_BANDLIST,
			ri->bandlist, sizeof(ri->bandlist))) < 0) {
			PBCD_ERR("%s: get bandlist failed err %d\n", ri->ifname, err);
			goto free_memory;
		}

		ri->band_type |= wps_pbcd_get_band_type(ri->ifname);

		wl_iovar_getint(ri->ifname, "nbr_discovery_cap", &oob_nbr_discovery);

		ri->oob_nbr_discovery = (oob_nbr_discovery & 0x01) ? TRUE : FALSE;

		if (get_ifname_unit(nv_ifname, &unit, NULL) < 0) {
			PBCD_EVT_DBG("%s: get_ifname_unit() failed \n", nv_ifname);
			continue;
		}
		ri->unit = unit;

		/* update iface list to read rnr_list from */
		memset(nv_name, 0, sizeof(nv_name));
		snprintf(nv_name, sizeof(nv_name), "%s_oob_rnr_list_src", nv_ifname);

		ret = nvram_safe_get(nv_name);
		if (ret[0] == '\0') {
			PBCD_EVT_DBG("%s: empty rnr_src iflist, skip\n", ri->ifname);
		} else {
			foreach(tmp_ifname, ret, tmp_next) {
				if (add_to_list(tmp_ifname, ri->rnr_src_iflist,
					sizeof(ri->rnr_src_iflist)) != 0) {
					PBCD_ERR("error adding %s to rnr_src_list of %s\n",
						tmp_ifname, ri->ifname);
				}
			}		
		}
		PBCD_EVT_DBG("%s: rnr_src_iflist: \"%s\"\n", ri->ifname, ri->rnr_src_iflist);

		/* update radio list to populate rnr entries */
		memset(nv_name, 0, sizeof(nv_name));
		snprintf(nv_name, sizeof(nv_name), "%s_oob_nbr_radio_list", nv_ifname);

		ret = nvram_safe_get(nv_name);
		if (ret[0] == '\0') {
			PBCD_EVT_DBG("%s: empty oob_nbr_radio iflist, skip\n", ri->ifname);
		} else {
			foreach(tmp_ifname, ret, tmp_next) {
				if (add_to_list(tmp_ifname, ri->oob_nbr_radio_list,
					sizeof(ri->oob_nbr_radio_list)) != 0) {
					PBCD_ERR("error adding %s to rnr_src_list of %s\n",
						tmp_ifname, ri->ifname);
				}			
			}
		}
		PBCD_EVT_DBG("%s: oob_nbr_radio_list: \"%s\"\n", ri->ifname,
			ri->oob_nbr_radio_list);
	}

	wps_pbcd_dump_ri_info(g_wpi_list, wl_radio_iflist);

free_memory:
	free(wl_radio_iflist);

	return BCME_OK;
}

// Fills the pbcd_info list from lan_ifnames and lan1_ifnames
static int
wps_pbcd_fill_info_objects_list(wps_pbcd_info_list_t *list)
{
	char *ifnames;
	char ifname[IFNAMSIZ], *next;
	char nvifname[IFNAMSIZ] = {0};
	char tmp[WPS_PBCD_NVNAME_BUF_SIZE] = {0};
	size_t ifnames_size;
	wps_pbcd_info_t *pbcd_info;
	int unit = -1;

	ifnames_size = hapd_wpasupp_get_all_lanifnames_listsz();
	ifnames = (char *)calloc(1, ifnames_size);
	if (!ifnames) {
		PBCD_ERR("failed to allocate memory of %zu bytes\n", ifnames_size);
		return -1;
	}

	hapd_wpasupp_get_all_lanifnames_list(ifnames, ifnames_size);

	if (wps_pbcd_init_radio_rnr_info(list) < 0) {
		PBCD_ERR("error initializing radio_rnr_info\n");
	}

	foreach(ifname, ifnames, next) {
		// Get radio unit
		if (wps_pbcd_get_radio_unit(ifname, &unit)) {
			PBCD_INFO("get radio unit failed for %s\n", ifname);
			continue;
		}

		// Get nvifname from osifname
		if (osifname_to_nvifname(ifname, nvifname, sizeof(nvifname))) {
			PBCD_INFO("osifname to nvifname failed for %s\n", ifname);
			continue;
		}

		// Check if wps is possible on the interface
		if (wps_pbcd_is_wps_possible_on_interface(ifname, nvifname, unit) == FALSE) {
			continue;
		}

		if (list->count >= WPS_PBCD_THREAD_POOL_SIZE) {
			PBCD_PRINT("Info: ", "there is no space in the list to add info for %s "
				"list max size is %d, list count reached %d\n",
				ifname, WPS_PBCD_THREAD_POOL_SIZE, list->count);
			break;
		}

		pbcd_info = (wps_pbcd_info_t*)calloc(1, sizeof(wps_pbcd_info_t));
		if (!pbcd_info) {
			PBCD_ERR("failed to allocate memory of %zu bytes\n",
				sizeof(wps_pbcd_info_t));
			break;
		}

		WLIF_STRNCPY(pbcd_info->bss.ifname, ifname, sizeof(pbcd_info->bss.ifname));
		WLIF_STRNCPY(pbcd_info->bss.nvifname, nvifname, sizeof(pbcd_info->bss.nvifname));
		snprintf(tmp, sizeof(tmp), "%s_mode", nvifname);
		if (nvram_match(tmp, "ap")) {
			pbcd_info->wps_mode = WLIF_WPS_REGISTRAR;
			snprintf(pbcd_info->wpa_ctrl_dir, sizeof(pbcd_info->wpa_ctrl_dir),
				"%s/hostapd/%s", WPS_PBCD_CTRL_DIR_PREFIX, ifname);
			pbcd_info->get_network_settings = wps_pbcd_fetch_ap_config_settings;
			pbcd_info->apply_network_settings = wl_wlif_apply_creds;
			pbcd_info->set_device_configured = wps_pbcd_set_ap_as_configured;
			pbcd_info->non_wps_wpa_ctrl_events_handler =
				non_wps_process_hostapd_wpa_supplicant_ctrl_events;
		} else {
			pbcd_info->wps_mode = WLIF_WPS_ENROLLEE;
			snprintf(pbcd_info->wpa_ctrl_dir, sizeof(pbcd_info->wpa_ctrl_dir),
				"%s/%s_wpa_supplicant/%s", WPS_PBCD_CTRL_DIR_PREFIX,
				nvifname, ifname);
#ifdef MULTIAP
			if (wl_wlif_is_map_onboarding(nvifname)) {
				pbcd_info->apply_network_settings =
					wl_wlif_map_configure_backhaul_sta_interface;
				pbcd_info->set_device_configured = wps_pbcd_sys_restart;
			} else
#endif	/* MULTIAP */
			{
				pbcd_info->apply_network_settings = wl_wlif_apply_creds;
			}
			pbcd_info->get_network_settings = wps_pbcd_fetch_config_settings;
		}
		pbcd_info->dpp_wpa_ctrl_events_handler = hostapd_wpa_supplicant_dpp_ctrl_events;
		pbcd_info->is_configuration_required = wps_pbcd_does_dev_needs_to_be_configured;
		pbcd_info->process_ctrl_event_data =
			wps_pbcd_process_hostapd_wpasupplicant_ctrl_events;
		pbcd_info->led_and_ui_status_update_handler =
			wps_pbcd_led_and_ui_status_update_handler;
		pbcd_info->reset_wps_ifnames_data_handler = wps_pbcd_reset_wps_ifnames_data_handler;
		pbcd_info->wpa_ctrl_fd = PBCD_INV_SOCK;
		pbcd_info->arg = NULL;
		pbcd_info->gpio_board_fp = wps_pbcd_gpio_led_init_handler();
		list->wps_pbcd_info_objects[list->count] = pbcd_info;
		list->count++;
	}

	wps_pbcd_init_co_host_nbr_info();
	wps_pbcd_set_co_host_nbr_info();

	free(ifnames);
	return 0;
}

// Function to free the pbcd_info object data
static void
wps_pbcd_free_info_object(wps_pbcd_info_t **p_pbcd_info)
{
	wps_pbcd_info_t *pbcd_info = NULL;

	if (!p_pbcd_info) {
		PBCD_DBG("info object is already freed\n");
		return;
	}

	pbcd_info = *p_pbcd_info;
	if (pbcd_info != NULL) {
		if (pbcd_info->wpa_ctrl_handle != NULL) {
			wpa_ctrl_detach(pbcd_info->wpa_ctrl_handle);
			wpa_ctrl_close(pbcd_info->wpa_ctrl_handle);
		}

		if (pbcd_info->arg != NULL) {
			free(pbcd_info->arg);
		}

		free(pbcd_info);
	}

	*p_pbcd_info = NULL;	// sets list array item value to NULL.
}

// Function to free the memory allocated previously
static void
wps_pbcd_free_info_objects_list(wps_pbcd_info_list_t *list)
{
	int idx;
	wps_pbcd_radio_rnr_info_t *rnr_info;
	bss_list_t *bss, *iter;

	if (list) {
		if (list->usched_hdl) {
			bcm_usched_stop(list->usched_hdl);
			bcm_usched_deinit(list->usched_hdl);
		}

		for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
			rnr_info = &list->radio_rnr_info[idx];
			wps_pbcd_free_escan_list(&rnr_info->escan_bss_head);
			/* release bss list holding nbr info */
			bss = rnr_info->bss_list;
			while (bss) {
				iter = bss->next;
				free(bss);
				bss = iter;
			}
		}

		for (idx = 0; idx < list->count; idx++) {
			wps_pbcd_free_info_object(&list->wps_pbcd_info_objects[idx]);
		}

		if (list->wps_ap_ifnames != NULL) {
			free(list->wps_ap_ifnames);
		}

		if (list->wps_sta_ifnames != NULL) {
			free(list->wps_sta_ifnames);
		}

		if (list->rgd_sockfd >= 0) {
			close(list->rgd_sockfd);
		}

		free(list);
		list = NULL;
	}
}

// Gets the radio unit for interface
static int
wps_pbcd_get_radio_unit(char *ifname, int *out_unit)
{
	int unit = -1;

	if (wl_probe(ifname) || wl_ioctl(ifname, WLC_GET_INSTANCE, &unit, sizeof(unit))) {
		PBCD_DBG_DETAIL("wl_probe failed for %s\n", ifname);
		return -1;
	}

	if (out_unit != NULL) {
		*out_unit = unit;
	}

	return 0;
}

// Returns TRUE if wps is possible for the input interface
static bool
wps_pbcd_is_wps_possible_on_interface(char *ifname, char *nvifname, int unit)
{
	char tmp[WPS_PBCD_NVNAME_BUF_SIZE] = {0};

	snprintf(tmp, sizeof(tmp), "%s_wps_mode", nvifname);
	if (!nvram_match("SG_mode", "1") && !nvram_match(tmp, "enabled")) {
		PBCD_INFO("wps is not possible on %s because wps is disabled on it\n", ifname);
		goto exit;
	}

	// Skip if primary radio is disabled
	snprintf(tmp, sizeof(tmp), "wl%d_radio", unit);
	if (nvram_match(tmp, "0")) {
		PBCD_INFO("wps is not possible on %s because primary radio is disabled\n", ifname);
		goto exit;
	}

	// Skip if bss is not enabled
	snprintf(tmp, sizeof(tmp), "%s_bss_enabled", nvifname);
	if (!nvram_match(tmp, "1")) {
		PBCD_INFO("wps is not possible on %s because bss is disabled \n", ifname);
		goto exit;
	}
#ifdef MULTIAP
	/*
	 * In case of multiap backhaul only bss the wps will not be enabled.
	 * Hence skip it from adding to the list.
	 */
	{
		char *ptr = NULL;
		uint16 map = 0;

		snprintf(tmp, sizeof(tmp), "%s_map", nvifname);
		ptr = nvram_safe_get(tmp);
		if (ptr[0] != '\0') {
			map = (uint16)strtoul(ptr, NULL, 0);
		}
		if (map == WPS_PBCD_MAP_BH_BSS_NVVAL) {
			PBCD_INFO("wps is not possible on %s because it is "
				"multiap backhaul bss \n", ifname);
			goto exit;
		}
	}
#endif	/* MULTIAP */

	return TRUE;

exit:
	return FALSE;
}

// Updates wps ifnames for ap and sta interfaces
static int
wps_pbcd_update_wps_ifnames(char *wps_ifnames, char *mode_compare_str, char **out_list)
{
	char nvifname[IFNAMSIZ] = {0};
	char ifname[IFNAMSIZ], *next;
	char *list;
	char *ifnames = NULL;
	char *lan_ifnames = nvram_safe_get("lan_ifnames");
	char tmp[WPS_PBCD_NVNAME_BUF_SIZE] = {0};
	int list_size = 0;
	int unit = -1;
	uint8 bitflags = 0x0;	// can accomodate radio units from 0 to 7

	// if nvram value is set use the interface names listed in that nvram
	if (wps_ifnames[0] != '\0') {
		ifnames = wps_ifnames;
	} else {
		ifnames = lan_ifnames;
	}

	if (ifnames[0] == '\0') {
		PBCD_PRINT("Info: ", "did not find any interface to add to wps %s ifnames "
			"list wps_ifnames=[%s] lan_ifnames=[%s]\n",
			mode_compare_str, wps_ifnames, lan_ifnames);
		return 0;
	}

	list_size = strlen(ifnames) +  1 /* '\0' */;
	list = (char *)calloc(1, list_size);
	if (!list) {
		PBCD_ERR("failed to allocate memory of %d bytes\n", list_size);
		return -1;
	}

	foreach(ifname, ifnames, next) {
		// Get radio unit
		if (wps_pbcd_get_radio_unit(ifname, &unit)) {
			PBCD_DBG_DETAIL("get radio unit failed for %s\n", ifname);
			continue;
		}

		// Check whether ifname is already added to the list for the radio
		if (isset(&bitflags, unit)) {
			continue;
		}

		// Get nvifname from osifname
		if (osifname_to_nvifname(ifname, nvifname, sizeof(nvifname))) {
			PBCD_DBG_DETAIL("osifname to nvifname failed for %s\n", ifname);
			continue;
		}

		// Check if wps is possible on the interface
		if (wps_pbcd_is_wps_possible_on_interface(ifname, nvifname, unit) == FALSE) {
			continue;
		}

		// Add either AP/STA interfaces to the wps_ifnames list based on the mode
		snprintf(tmp, sizeof(tmp), "%s_mode", nvifname);
		if (nvram_match(tmp, mode_compare_str)) {
			if (add_to_list(ifname, list, list_size)) {
				PBCD_INFO("failed to add %s to wps_%s_ifnames\n",
					ifname, mode_compare_str);
			} else {
				// Set unit bit to indicate ifname is already added for radio
				setbit(&bitflags, unit);
			}
		} else {
			PBCD_DBG_DETAIL("interface %s is operating in %s mode hence not adding "
				"it to wps_%s_ifnames list\n", ifname, nvram_safe_get(tmp),
				mode_compare_str);
		}
	}

	PBCD_DBG_DETAIL("wps_%s_ifnames are [%s] \n", mode_compare_str, list);
	// Store the wps ifnames to out_list
	if (list[0] != '\0') {
		*out_list = strdup(list);
	}

	free(list);

	return 0;
}

#if !defined(STB)
// Callback function to stop wps led in repeater modes on wps timeout
static void
wps_pbcd_stop_wps_led(void *arg)
{
	int *board_fp = (int*)arg;

	wl_wlif_wps_gpio_led_blink(*board_fp, WLIF_WPS_BLINKTYPE_STOP);

	free(board_fp);
}

// Callback function to stop active wps in remaining interfaces while wps is sumultaneously running
// on interfaces present in wps ifnames and succeeded  in any one interface.
static void
wps_pbcd_stop_wps(void *arg)
{
	char ifname[IFNAMSIZ] = {0}, *next = NULL;
	char *wps_ifnames = (char*)arg;
	wps_pbcd_info_t *obj = NULL;

	foreach(ifname, wps_ifnames, next) {
		PBCD_DBG_DETAIL("stoping wps session on ifname %s \n", ifname);
		obj = wps_pbcd_get_info_obj(ifname);
		if (obj) {
			obj->skip_ui_update = TRUE;
		}
		wl_wlif_wps_stop_session(ifname, FALSE);
	}

	free(wps_ifnames);
}

// Function to add custom wps notification handler callbacks
static int
wps_pbcd_add_notification_handler(wps_pbcd_notification_id_t id,
	void *notification_handler, void *notification_handler_arg)
{
	pthread_t thread_id;
	wps_pbcd_notification_data_t *arg = (wps_pbcd_notification_data_t*)calloc(1, sizeof(*arg));

	if (arg == NULL) {
		PBCD_ERR("failed to allocate memory of %zu bytes\n", sizeof(*arg));
		return -1;
	}

	// Close any previously running thread which is monitoring this notification Id.
	wps_pbcd_set_notification_flags(id);
	usleep(WPS_PBCD_NOTIFICATION_THREAD_SLEEP_DURATION * 1000);
	wps_pbcd_clear_notification_flag(id);

	// Start a new thread to monitor the notification Id
	arg->notification_id = id;
	arg->notification_handler = notification_handler;
	arg->notification_handler_arg = notification_handler_arg;
	if (wl_wlif_create_thrd(&thread_id, wps_custom_notification_handler, arg, TRUE)) {
		PBCD_ERR("thread creation failed for notification id %d\n", id);
		free(arg);
		return -1;
	}

	return 0;
}

// Sets the notification flags bit
static void
wps_pbcd_set_notification_flags(uint8 bit)
{
	pthread_mutex_lock(&g_wps_pbcd_lock);
	setbit(&g_wps_data.notification_flags, bit);
	pthread_mutex_unlock(&g_wps_pbcd_lock);
}

// Returns true is the notification flags bit is set otherwise returns false
static bool
wps_pbcd_isset_notification_flags(uint8 bit)
{
	bool ret = FALSE;

	pthread_mutex_lock(&g_wps_pbcd_lock);
	ret = isset(&g_wps_data.notification_flags, bit);
	pthread_mutex_unlock(&g_wps_pbcd_lock);

	return ret;
}

// Clears notification flags and request bit
static void
wps_pbcd_clear_notification_flag(uint8 bit)
{
	pthread_mutex_lock(&g_wps_pbcd_lock);
	clrbit(&g_wps_data.notification_flags, bit);
	pthread_mutex_unlock(&g_wps_pbcd_lock);
}

// Function to run the notification handler routines
static void*
wps_custom_notification_handler(void *arg)
{
	wps_pbcd_notification_data_t *notification = (wps_pbcd_notification_data_t *)arg;
	time_t start, end;

	end = start = time(NULL);

	while ((end -start) <= WLIF_WPS_TIMEOUT)
	{
		if (wps_pbcd_isset_notification_flags(notification->notification_id)) {
			PBCD_DBG_DETAIL("wps notification %d is set\n",
				notification->notification_id);
			break;
		}

		usleep(WPS_PBCD_NOTIFICATION_THREAD_SLEEP_DURATION * 1000); // Sleep for 500 msecs

		end = time(NULL);
	}

	// Execute the notification handler routine
	notification->notification_handler(notification->notification_handler_arg);

	// Clear the notification flag
	wps_pbcd_clear_notification_flag(notification->notification_id);

	free(notification);

	return NULL;
}
#endif	/* !STB */

/* Signal handler function to free the memory allocated previously */
static void
wps_pbcd_exit_signal_handler(int signum)
{
	wps_pbcd_gpio_board_cleanup();
	wps_pbcd_free_info_objects_list(g_wps_pbcd_info_list);
	exit(EXIT_SUCCESS);
}

static void wps_pbcd_sigusr1_handler(int sig)
{
	wps_pbcd_register_for_wps_success_notification(nvram_safe_get("wl_ifnames"));
}

int
main(void)
{
	char *dbg;
	FILE *fp;

	if (daemon(1, 1) == -1) {
		PBCD_ERR("daemonize failed\n");
		return -1;
	}

	if ((dbg = nvram_get("wps_pbcd_msglevel"))) {
		wps_pbcd_msglevel = (uint)strtoul(dbg, NULL, 0);
	}

	/* write pid */
	if ((fp = fopen("/var/run/wps_pbcd.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	signal(SIGHUP, wps_pbcd_exit_signal_handler);
	signal(SIGINT, wps_pbcd_exit_signal_handler);
	signal(SIGTERM, wps_pbcd_exit_signal_handler);
	signal(SIGUSR1, wps_pbcd_sigusr1_handler);
		memset(&g_wps_data, 0, sizeof(g_wps_data));
		g_wps_pbcd_info_list = (wps_pbcd_info_list_t *)calloc(1,
			sizeof(*g_wps_pbcd_info_list));
		if (!g_wps_pbcd_info_list) {
			PBCD_ERR("failed to allocate memory of %zu bytes\n",
				sizeof(*g_wps_pbcd_info_list));
			goto fail;
		}

		// Save wps ifnames for each radio operating in ap mode
		(void)wps_pbcd_update_wps_ifnames(nvram_safe_get("wps_ap_ifnames"), "ap",
			&g_wps_pbcd_info_list->wps_ap_ifnames);

		// Save wps ifnames for each radio operating in sta mode
		(void)wps_pbcd_update_wps_ifnames(nvram_safe_get("wps_sta_ifnames"), "sta",
			&g_wps_pbcd_info_list->wps_sta_ifnames);

		wps_pbcd_fill_info_objects_list(g_wps_pbcd_info_list);

		if (wps_pbcd_init(g_wps_pbcd_info_list)) {
			goto fail;
		}
#if !defined(STB)
		if (wps_pbcd_schedule_gpio(g_wps_pbcd_info_list)) {
			goto fail;
		}
#endif	/* !STB */
		wps_pbcd_add_timers(g_wps_pbcd_info_list->usched_hdl, NULL, PBCD_SEC_MICROSEC(5),
			wps_pbcd_dpp_init_tm_cb, 0);
		wps_pbcd_run(g_wps_pbcd_info_list->usched_hdl);

fail:
	wps_pbcd_gpio_board_cleanup();
	wps_pbcd_free_info_objects_list(g_wps_pbcd_info_list);
	return 0;
}

static void
wps_pbcd_copy_bss_nbr_list(bss_list_t *dst_bss_list, bss_list_t *src_bss_list)
{
	bss_list_t *from_bss_list;
	bss_list_t *to_bss_list;

	to_bss_list = dst_bss_list;

	while (to_bss_list) {
		from_bss_list = src_bss_list;
		while (from_bss_list) {
			if (!strncmp(to_bss_list->ifname, from_bss_list->ifname,
				sizeof(to_bss_list->ifname))) {

				from_bss_list = from_bss_list->next;
				continue;
			}

			(void)wps_pbcd_add_rrm_nbr(to_bss_list->ifname,
				&from_bss_list->self_nbr_rpt);

			from_bss_list = from_bss_list->next;
		}
		to_bss_list = to_bss_list->next;
	}
}
