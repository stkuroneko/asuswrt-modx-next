/*
 * Application to monitor the board PBC button
 * for WPS operation, it will interact with
 * HOSTAPD for wps processing.
 *
 * Copyright (C) 2020, Broadcom. All Rights Reserved.
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
 * $Id: wps_pbcd.c 784430 2020-02-27 05:33:40Z $
 */

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include <bcmutils.h>
#include <bcmnvram.h>
#include <wlutils.h>
#include <shutils.h>
#include <common_utils.h>
#include <wlif_utils.h>
#include <wpa_ctrl.h>

#ifdef BCA_HNDROUTER
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <board.h>
#endif	/* BCA_HNDROUTER */

#ifndef IFNAMSIZ
#define IFNAMSIZ				16
#endif	/* IFNAMSIZ */

#define WPS_PBCD_MSG_M4				"msg=8"
#define WPS_PBCD_MSG_M7				"msg=11"
#define WPS_PBCD_CFG_NO_ERR			"config_error=0"
#define WPS_PBCD_CFG_PIN_VALIDATION_ERR		"config_error=18"

#define WPS_PBCD_CTRL_DIR_PREFIX		"/var/run"
#define	WPS_PBCD_MAX_BUF_SIZE			256
#define	WPS_PBCD_MIN_BUF_SIZE			128
#define WPS_PBCD_NVNAME_BUF_SIZE		64
#define	WPS_PBCD_THREAD_POOL_SIZE		16
#define WPS_PBCD_LONG_PRESSTIME			5
#define WPS_PBCD_BTNSAMPLE_PERIOD		(500 * 1000)
#define WPS_PBCD_MAP_BH_BSS_NVVAL		0x2	// Multiap Backhaul BSS

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

#define HAPD_WPS_MAX_BRIDGE_NUM 16

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

typedef struct wps_pbcd_wps {
	int board_fp;			/* Handle for wps gpio led */
	char pbc_ifname[IFNAMSIZ];	/* selected interface name using pbc press where
					 * current wps session is active.
					 */
	char first_pbc_ifname[IFNAMSIZ];
					/* In case of multiap the first selected pbc ifname will
					 * be stored in it.
					 * In each multiap timeout event first_pbc_ifname will be
					 * compared with current ifname.If both are same it means
					 * the whole wps session is over so timeout will be reset
					 * to -1 which means wait for next pbc press.
					 */
	uint8 notification_flags;	/* Bitflag to be set on specific wps events on request */
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
// Callback to initialize the wps gpio led
typedef int (*wps_pbcd_gpio_led_init)();
// Callback to cleanup the wps gpio led
typedef void (*wps_pbcd_gpio_led_cleanup)(int board_fp);
// Callback to update the wps gpio led and ui status
typedef void (*wps_pbcd_update_led_and_ui_status)(wps_pbcd_info_t *info);
// Callback to reset the wps ifnames data which is being shared between threads and main thread
typedef void (*wps_pbcd_reset_wps_ifnames_data)(char *data);
typedef int (*non_wps_process_wpa_ctrl_events)(wps_pbcd_info_t *info);

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
static wps_pbcd_wps_behaviour_t wps_pbcd_get_wps_behaviour();
static int non_wps_process_hostapd_wpa_supplicant_ctrl_events(wps_pbcd_info_t *pbcd_info);

#ifdef BCA_HNDROUTER
static wps_pbcd_button_press_type_t wps_pbcd_wps_gpio_btn_pressed(int board_fp, int timeout);
#else
#define wps_pbcd_wps_gpio_btn_pressed(a, b)	(0)
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
	wps_pbcd_is_configuration_required is_configuration_required;
	wps_pbcd_set_device_configured	set_device_configured;
	wps_pbcd_get_configuration_settings get_network_settings;
	wps_pbcd_apply_network_settings apply_network_settings;
	wps_pbcd_gpio_led_init gpio_led_init;
	wps_pbcd_update_led_and_ui_status led_and_ui_status_update_handler;
	wps_pbcd_reset_wps_ifnames_data reset_wps_ifnames_data_handler;
	wps_pbcd_process_wpa_ctrl_events process_ctrl_event_data;
	non_wps_process_wpa_ctrl_events non_wps_wpa_ctrl_events_handler;
	pthread_t monitor_thread_id;
};

// List of wps_pbcd_info_t pointers
typedef struct wps_pbcd_info_list {
	int count;
	wps_pbcd_info_t *wps_pbcd_info_objects[WPS_PBCD_THREAD_POOL_SIZE];
	char *wps_ap_ifnames;	// List of all wps capable ap interfaces
	char *wps_sta_ifnames;	// List of all wps capable sta interfaces
} wps_pbcd_info_list_t;

// list of wps_pbcd_info_t
wps_pbcd_info_list_t g_wps_pbcd_info_list;

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

	dprintf("Info: wps_pbcd %s wps will be active for %d secs each on interfaces %s\n",
		__func__, timeout, wps_ifnames);

	return timeout;
}

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

	if (idx != WLIF_WPS_UI_INVALID) {
		wl_wlif_update_wps_ui(idx);
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
	do { \
	       char signal[] = "XXXX"; \
	       snprintf(signal, sizeof(signal), "-%d", SIGHUP); \
	       eval("killall", signal, "rc"); \
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

	start = buf;
	end = start + total_len;

	memset(creds, 0, sizeof(*creds));
	while (start < end) {
		// Length check before parsing wps attribute type and length
		if ((end - start) < WPS_PBCD_WPS_ATTR_TYPE_LEN_SIZE) {
			cprintf("Info: wps_pbcd %s %d buffer size is small \n", __func__, __LINE__);
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

		if ((end - start) < parse_len) {
			cprintf("Info: wps_pbcd %s %d buffer size is small \n", __func__, __LINE__);
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
				cprintf("Info: wps_pbcd %s ignore ssid of len %d\n ",
					__func__, len);
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
				cprintf("Info: wps_pbcd %s ignore psk of len %d\n ",
					__func__, len);
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
				cprintf("Info: wps_pbcd %s invalid auth type length %d\n ",
					__func__, len);
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
				cprintf("Info: wps_pbcd %s invalid encr type length %d\n ",
					__func__, len);
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

	cprintf("Info: wps_pbcd %s %d ssid %s psk %s akm %d encr %d\n", __func__, __LINE__,
		pbcd_info->creds.ssid, pbcd_info->creds.nw_key,
		pbcd_info->creds.akm, pbcd_info->creds.encr);

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

	cprintf("Info: wps_pbcd %s %d ssid %s psk %s akm %d encr %d\n", __func__, __LINE__,
		pbcd_info->creds.ssid, pbcd_info->creds.nw_key,
		pbcd_info->creds.akm, pbcd_info->creds.encr);

	return ret;
}

// Process non wps events received in the hostapd/wpa-supplicant control interface
static int
non_wps_process_hostapd_wpa_supplicant_ctrl_events(wps_pbcd_info_t *pbcd_info)
{
	return -1;
}

// Process the wps events received in the hostapd/wpa-supplicant control interface
static int
wps_pbcd_process_hostapd_wpasupplicant_ctrl_events(wps_pbcd_info_t *pbcd_info)
{
	char *data = pbcd_info->reply_buf;

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

	cprintf("\nInfo: wps_pbcd %s %d received on %s len [%zu] and data [%s] \n", __func__,
		__LINE__, pbcd_info->wpa_ctrl_dir, pbcd_info->reply_len, pbcd_info->reply_buf);

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
		// Set the WPS_SUCCESS bit in notification flags so that any monitoring thread
		// can perform specific operations.
		wps_pbcd_set_notification_flags(WPS_SUCCESS);
	}

	pbcd_info->reset_wps_ifnames_data_handler(data);

	return 0;
}

// Thread function to monitor the hostapd/wpa-supplicant control events for each interface
static void*
wps_pbcd_wpa_ctrl_interface_monitor(void *arg)
{
	int ret;
	wps_pbcd_info_t **p_pbcd_info = (wps_pbcd_info_t **)arg;
	wps_pbcd_info_t *pbcd_info = *p_pbcd_info;

	pbcd_info->gpio_board_fp = pbcd_info->gpio_led_init();

	pthread_mutex_lock(&g_wps_pbcd_lock);
	pbcd_info->wpa_ctrl_handle = wpa_ctrl_open(pbcd_info->wpa_ctrl_dir);

	dprintf("Info: wps_pbcd thread is running for %s\n", pbcd_info->wpa_ctrl_dir);
	if (!pbcd_info->wpa_ctrl_handle) {
		cprintf("Err: wps_pbcd %s %d failed to open connection to %s\n",
			__func__, __LINE__, pbcd_info->wpa_ctrl_dir);
		pthread_mutex_unlock(&g_wps_pbcd_lock);
		goto exit;
	}

	if ((ret = wpa_ctrl_attach(pbcd_info->wpa_ctrl_handle))) {
		cprintf("Err: wps_pbcd %s %d failed to attach to %s ret %d\n",
			__func__, __LINE__, pbcd_info->wpa_ctrl_dir, ret);
		wpa_ctrl_close(pbcd_info->wpa_ctrl_handle);
		pbcd_info->wpa_ctrl_handle = NULL;
		pthread_mutex_unlock(&g_wps_pbcd_lock);
		goto exit;
	}
	pthread_mutex_unlock(&g_wps_pbcd_lock);

	while (1) {
		usleep(WPS_PBCD_MONITOR_THREAD_SLEEP_DURATION * 1000);	// Sleep for 100 msecs
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

exit:
	dprintf("Info: wps_pbcd thread is exiting for %s\n", pbcd_info->wpa_ctrl_dir);

	return NULL;
}

#if !defined(STB)
/* Poll for wps push btm press */
static wps_pbcd_button_press_type_t
wps_pbcd_wps_gpio_btn_pressed(int board_fp, int timeout)
{
	int trigger = SES_EVENTS;
	int poll_ret = 0;
	wps_pbcd_button_press_type_t btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_UNKNOWN;
	struct pollfd gpiofd = {0};

	BOARD_IOCTL_PARMS ioctl_parms = {0};

	if (board_fp <= 0) {
		dprintf("Err: wps_pbcd %s invalid board_fp %d\n", __func__, board_fp);
		goto fail;
	}

	ioctl_parms.result = -1;
	ioctl_parms.string = (char *)&trigger;
	ioctl_parms.strLen = sizeof(trigger);

	if (ioctl(board_fp, BOARD_IOCTL_SET_TRIGGER_EVENT, &ioctl_parms) < 0) {
		dprintf("Err: wps_pbcd %s ioctl call failed for %d\n", __func__, board_fp);
		goto fail;
	}

	if (ioctl_parms.result < 0) {
		dprintf("Err: wps_pbcd %s invalid ioctl call result for %d\n", __func__,
			board_fp);
		goto fail;
	}

	gpiofd.fd = board_fp;
	gpiofd.events |= POLLIN;

	poll_ret = poll(&gpiofd, 1, timeout);

	// poll system call timed out without detecting any events
	if (poll_ret == 0) {
		int status = wl_wlif_get_wps_status_code();
		if (status == WLIF_WPS_UI_FIND_PBC_AP || status == WLIF_WPS_UI_FINDING_PBC_STA) {
			btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_TIMEOUT;
		}
		goto fail;
	}

	if (poll_ret < 0) {
		dprintf("Err: wps_pbcd %s  poll ret %d\n", __func__, poll_ret);
		goto fail;
	}

	if (poll_ret > 0) {
		int len = 0;
		int val = 0;
		if ((len = read(board_fp, (char*)&val, sizeof(val))) > 0 && (val & trigger)) {
			if (val & SES_EVENT_BTN_LONG) {
				dprintf("Info: wps_pbcd %s WPS long button press \n", __func__);
				btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_LONG;
			} else if (val & SES_EVENT_BTN_SHORT) {
				dprintf("Info: wps_pbcd  %s WPS short button press \n", __func__);
				btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_SHORT;
			} else {
				/* Button management interface: Keep reading
				 * from the board driver until button is released
				 * and count the press time here
				 */
				int count = 0;
				int lbpcount = 0;
				struct timeval time;

				lbpcount = (WPS_PBCD_LONG_PRESSTIME * 1000000) /
						WPS_PBCD_BTNSAMPLE_PERIOD;

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
					dprintf("Info: wps_pbcd %s WPS short button press \n",
						__func__);
					btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_SHORT;
				} else {
					dprintf("Info: wps_pbcd %s WPS long button press \n",
						__func__);
					btn_event = WPS_PBCD_BUTTON_PRESS_TYPE_LONG;
				}
			}
		}
	}

fail :
    return btn_event;
}
#endif // endif

/* Continously poll for wps push button event */
void
wps_pbcd_poll_button_press()
{
	wps_pbcd_button_press_type_t press;
	int timeout = -1;
	int board_fp = 0;
	char wps_ifname[IFNAMSIZ] = {0}, curr_ifname[IFNAMSIZ] = {0};
	char first_pbc_ifname[IFNAMSIZ] = {0};
	char *wps_ifnames = NULL;
	wps_pbcd_wps_behaviour_t wps_behaviour;
	char *wps_on_sta = NULL;
	BCM_REFERENCE(timeout);

	if (nvram_match("hapd_enable", "0")) {
		goto end;
	}

	board_fp = wps_pbcd_gpio_led_init_handler();

	if (board_fp <= 0) {
		cprintf("Err: wps_pbcd %s open /dev/brcmboard failed!\n", __func__);
		goto end;
	}

	while (1) {
		// poll needs timeout in msecs.
		press = wps_pbcd_wps_gpio_btn_pressed(board_fp, timeout * 1000);

		wps_behaviour = wps_pbcd_get_wps_behaviour();
		wps_on_sta = nvram_safe_get("wps_on_sta");
		// Check where to run wps ap interfaces or sta interfaces
		if (strcmp(wps_on_sta, "1") == 0) {
			wps_ifnames = g_wps_pbcd_info_list.wps_sta_ifnames;
		} else {
			wps_ifnames = g_wps_pbcd_info_list.wps_ap_ifnames;
		}

		if (wps_ifnames == NULL) {
			char *sta_ifnames = g_wps_pbcd_info_list.wps_sta_ifnames;
			char *ap_ifnames = g_wps_pbcd_info_list.wps_ap_ifnames;

			BCM_REFERENCE(sta_ifnames);
			BCM_REFERENCE(ap_ifnames);

			dprintf("Err: wps_pbcd %s did not find any interface to start wps "
				"wps_ap_ifnames=%s wps_sta_ifnames=%s wps_on_sta=%s\n", __func__,
				ap_ifnames ? ap_ifnames : "NULL",
				sta_ifnames ? sta_ifnames : "NULL",
				wps_on_sta[0] != '\0' ? wps_on_sta : "Undefined");
			continue;
		}

		/* For the sta interface if wps times out, control interface do not receive
		 * any timeout event and wps led keeps on blinking even after wps session
		 * times out (120 seconds).
		 * While in AP case if hostapd detects the pbc overlap and user presses pbc
		 * button, the led will be updated to show pbc pverlap which needs to be closed
		 * after 120 secs.
		 * Hence registering for WPS_TIMEOUT notification so that after timeout duration
		 * is over wps led can be stopped.
		 */
		if (press > WPS_PBCD_BUTTON_PRESS_TYPE_UNKNOWN &&
			press < WPS_PBCD_BUTTON_PRESS_TYPE_TIMEOUT) {
			wps_pbcd_register_for_wps_timeout_notification(board_fp);
		}

		if (wps_behaviour == WPS_SEQUENTIAL_AUTO) {
			timeout = wps_pbcd_get_wps_sequential_auto_timeout(wps_ifnames);
		}

		dprintf("Info: wps_pbcd %s wps behaviour is %s timeout = %d\n", __func__,
			wps_behaviour == WPS_SIMULTANEOUS ? "Simultaneous" :
			(wps_behaviour == WPS_SEQUENTIAL_AUTO ? " Sequential Auto" : "Manual"),
			timeout);

		switch (press) {
		/*
		 * When press returned as WPS_PBCD_BUTTON_PRESS_TYPE_TIMEOUT
		 * that time we can have three cases
		 * In all cases first select the next interface from the list.
		 * 1: Unlikely confition first_pbc_ifname and current_ifname both are empty.
		 * This unlikely condition implies timeout happened even without
		 * any active wps session.
		 * We are setting the timeout value to -1 (means wait for next PBC press).
		 *
		 * 2: first_pbc_ifname is empty.
		 * This is the case where during active wps session timeout occured.
		 * a) We are storing the current pbc ifname into first_pbc_ifname.
		 * c) Stopping wps session on current interface.
		 * d) Starting wps on the next interface from the nvram list.
		 *
		 * 3: first_pbc_ifname and next wps_ifname both are same.
		 * This is the case where whole wps session is timed-out.
		 * For eg: "eth6 eth7" are present in wps_ifnames, Intially wps was active
		 * for 60 secs on eth6 than timeout occured and eth7 was selected for wps.
		 * Now again timeout happened while wps was still active on eth7
		 * from last 60 secs. WPS has ran for toatal of 120 secs.(in both the
		 * interfaces for 60 secs each).
		 * a) Stop wps session on the current interface
		 * b) Reset g_wps_data to 0 and set timeout to -1
		 */
		case WPS_PBCD_BUTTON_PRESS_TYPE_TIMEOUT:
		pthread_mutex_lock(&g_wps_pbcd_lock);
		find_next_in_list(wps_ifnames, g_wps_data.pbc_ifname,
			wps_ifname, sizeof(wps_ifname));
		WLIF_STRNCPY(curr_ifname, g_wps_data.pbc_ifname, sizeof(curr_ifname));
		WLIF_STRNCPY(first_pbc_ifname, g_wps_data.first_pbc_ifname,
			sizeof(first_pbc_ifname));
		pthread_mutex_unlock(&g_wps_pbcd_lock);

		if (first_pbc_ifname[0] == '\0' && curr_ifname[0] == '\0') {
			timeout = -1;
		} else if (!strcmp(first_pbc_ifname, wps_ifname)) {
			wl_wlif_wps_stop_session(curr_ifname);
			pthread_mutex_lock(&g_wps_pbcd_lock);
			memset(&g_wps_data.pbc_ifname, 0, sizeof(g_wps_data.pbc_ifname));
			memset(&g_wps_data.first_pbc_ifname, 0,
				sizeof(g_wps_data.first_pbc_ifname));
			pthread_mutex_unlock(&g_wps_pbcd_lock);
			timeout = -1;
		} else {
			pthread_mutex_lock(&g_wps_pbcd_lock);
			if (g_wps_data.first_pbc_ifname[0] == '\0') {
				WLIF_STRNCPY(g_wps_data.first_pbc_ifname, curr_ifname,
					sizeof(g_wps_data.first_pbc_ifname));
			}
			pthread_mutex_unlock(&g_wps_pbcd_lock);

			// Before staring wps in next interface stop ongoing wps session
			// and sleep for 100 msecs so that the thread monitoring control
			// interface receives the wps stop event from hostapd/supplicant
			wl_wlif_wps_stop_session(curr_ifname);
			usleep(WPS_PBCD_MONITOR_THREAD_SLEEP_DURATION * 1000);
			wl_wlif_wps_pbc_hdlr(wps_ifname, NULL);
		}
			break;
		/*
		 * When press returned as either short or long
		 * 1) For ap interfaces wps behaviour can be to run simultaneously on
		 * all AP interfaces in case of sta interfaces it is sequential auto or
		 * manually run in each interface.
		 * For Simultaneous case wps will be started in each interface.
		 * 2) In case of sequential auto or manaul:
		 * a) First get the next interface from the list and store it in wps_ifname.
		 * b) Stop wps session on current interface.
		 * c) Start new wps session on the next interface listed on the nvram.
		 */
		case WPS_PBCD_BUTTON_PRESS_TYPE_SHORT:
		case WPS_PBCD_BUTTON_PRESS_TYPE_LONG:
		if (wps_behaviour == WPS_SIMULTANEOUS) {
			char ifname[IFNAMSIZ] = {0}, *next = NULL;
			// Register for wps success notification so that once wps succeeds
			// in any single interface it can be stopped on other interfaces
			wps_pbcd_register_for_wps_success_notification(wps_ifnames);
			// Start wps on all the interfaces listed in wps_ifnames
			foreach(ifname, wps_ifnames, next) {
				wl_wlif_wps_pbc_hdlr(ifname, NULL);
			}

		} else {
			pthread_mutex_lock(&g_wps_pbcd_lock);
			find_next_in_list(wps_ifnames, g_wps_data.pbc_ifname,
				wps_ifname, sizeof(wps_ifname));
			WLIF_STRNCPY(curr_ifname, g_wps_data.pbc_ifname, sizeof(curr_ifname));
			pthread_mutex_unlock(&g_wps_pbcd_lock);

			if (curr_ifname[0] != '\0') {
				// Before staring wps in next interface stop ongoing wps session
				// and sleep for 100 msecs so that the thread monitoring control
				// interface receives the wps stop event from hostapd/supplicant
				wl_wlif_wps_stop_session(curr_ifname);
				usleep(WPS_PBCD_MONITOR_THREAD_SLEEP_DURATION * 1000);
			}

			wl_wlif_wps_pbc_hdlr(wps_ifname, NULL);
		}
			break;

		default:
			timeout = -1;
			break;
		}
	}

end:
	dprintf("Info: wps_pbcd %s %d exiting\n", __func__, __LINE__);
	return;
}

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
		cprintf("Info: wps_pbcd %s registration of notification handler for "
			"WPS_TIMEOUT failed\n", __func__);
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
		cprintf("Info: wps_pbcd %s registration of notification handler for "
			"WPS_SUCCESS failed\n", __func__);
		free(arg);
	}
}

// Fills the pbcd_info list from lan_ifnames and lan1_ifnames
static int
wps_pbcd_fill_info_objects_list(wps_pbcd_info_list_t *list)
{
	char *ifnames;
	char *lan_ifnames[HAPD_WPS_MAX_BRIDGE_NUM];
	int i = 0, size = 0;
	char ifname[IFNAMSIZ], *next;
	char nvifname[IFNAMSIZ] = {0};
	char tmp[WPS_PBCD_NVNAME_BUF_SIZE] = {0};
	size_t ifnames_size;
	wps_pbcd_info_t *pbcd_info;
	int unit = -1;

	ifnames_size = 0;
	for (i = 0; i < HAPD_WPS_MAX_BRIDGE_NUM; ++i) {
		if (i == 0)
			WLIF_STRNCPY(tmp, "lan_ifnames", sizeof(tmp));
		else
			snprintf(tmp, sizeof(tmp), "lan%d_ifnames", i);
		lan_ifnames[i] = nvram_safe_get(tmp);
		if (lan_ifnames[i][0] != '\0') {
			ifnames_size += strlen(lan_ifnames[i]);
			ifnames_size += 2; /* space + '\0' */
		}
	}
	ifnames = (char *)calloc(1, ifnames_size);
	if (!ifnames) {
		cprintf("Err: wps_pbcd %s %d failed to allocate memory of size %zu\n",
			__func__, __LINE__, ifnames_size);
		return -1;
	}
	/* ifnames = lan_ifnames + space + lan1_ifnames */
	size = 0;
	for (i = 0; i < HAPD_WPS_MAX_BRIDGE_NUM; ++i) {
		if (lan_ifnames[i][0] != '\0') {
			size += snprintf(ifnames + size, ifnames_size - size,
					"%s%s", lan_ifnames[i], " ");
		}
	}

	foreach(ifname, ifnames, next) {
		// Get radio unit
		if (wps_pbcd_get_radio_unit(ifname, &unit)) {
/*
			cprintf("Info: wps_pbcd %s get radio unit "
				"failed for %s\n", __func__, ifname);
*/
			continue;
		}

		// Get nvifname from osifname
		if (osifname_to_nvifname(ifname, nvifname, sizeof(nvifname))) {
			cprintf("Info: wps_pbcd %s osifname_to_nvifname failed for %s\n",
				__func__, ifname);
			continue;
		}

		// Check if wps is possible on the interface
		if (wps_pbcd_is_wps_possible_on_interface(ifname, nvifname, unit) == FALSE) {
			dprintf("Info: wps_pbcd %s wps is not possible on ifname %s\n",
				__func__, ifname);
			continue;
		}

		if (list->count >= WPS_PBCD_THREAD_POOL_SIZE) {
			cprintf("Info: wps_pbcd %s %d max thread pool size is reached\n",
				__func__, __LINE__);
			break;
		}

		pbcd_info = (wps_pbcd_info_t*)calloc(1, sizeof(wps_pbcd_info_t));
		if (!pbcd_info) {
			cprintf("Err: wps_pbcd %s %d failed to allocate memory of size %zu\n",
				__func__, __LINE__, sizeof(wps_pbcd_info_t));
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
		pbcd_info->is_configuration_required = wps_pbcd_does_dev_needs_to_be_configured;
		pbcd_info->process_ctrl_event_data =
			wps_pbcd_process_hostapd_wpasupplicant_ctrl_events;
		pbcd_info->gpio_led_init = wps_pbcd_gpio_led_init_handler;
		pbcd_info->led_and_ui_status_update_handler =
			wps_pbcd_led_and_ui_status_update_handler;
		pbcd_info->reset_wps_ifnames_data_handler = wps_pbcd_reset_wps_ifnames_data_handler;
		list->wps_pbcd_info_objects[list->count] = pbcd_info;
		list->count++;
	}

	free(ifnames);
	return 0;
}

// Function to start the monitor threads for each interface
static void
wps_pbcd_run_wps_monitor_threads(wps_pbcd_info_list_t *list)
{
	int idx;
	wps_pbcd_info_t **p_pbcd_info = NULL;

	for (idx = 0; idx < list->count; idx++) {
		p_pbcd_info = &list->wps_pbcd_info_objects[idx];
		if (wl_wlif_create_thrd(&((*p_pbcd_info)->monitor_thread_id),
			wps_pbcd_wpa_ctrl_interface_monitor, p_pbcd_info, FALSE)) {
			cprintf("Info: wps_pbcd %s %d monitor thread creation is failed for "
				"control interface %s\n", __func__, __LINE__,
				(*p_pbcd_info)->wpa_ctrl_dir);
			continue;
		}
	}
}

// Function to free the pbcd_info object data
static void
wps_pbcd_free_info_object(wps_pbcd_info_t **p_pbcd_info)
{
	wps_pbcd_info_t *pbcd_info = NULL;

	if (!p_pbcd_info) {
		cprintf("Info: %s %d wps_pbcd pbcd info is already freed\n", __func__, __LINE__);
		return;
	}

	pbcd_info = *p_pbcd_info;
	if (pbcd_info != NULL) {
		if (pbcd_info->wpa_ctrl_handle != NULL) {
			wpa_ctrl_detach(pbcd_info->wpa_ctrl_handle);
			wpa_ctrl_close(pbcd_info->wpa_ctrl_handle);
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

	for (idx = 0; idx < list->count; idx++) {
		wps_pbcd_free_info_object(&list->wps_pbcd_info_objects[idx]);
	}

	if (list->wps_ap_ifnames != NULL) {
		free(list->wps_ap_ifnames);
	}

	if (list->wps_sta_ifnames != NULL) {
		free(list->wps_sta_ifnames);
	}
	memset(list, 0, sizeof(*list));
}

// Gets the radio unit for interface
static int
wps_pbcd_get_radio_unit(char *ifname, int *out_unit)
{
	int unit = -1;

	if (wl_probe(ifname) || wl_ioctl(ifname, WLC_GET_INSTANCE, &unit, sizeof(unit))) {
/*
		dprintf("Info: wps_pbcd %s wl_probe failed for %s\n", __func__, ifname);
*/
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
		cprintf("Info: wps_pbcd %s wps is not enabled for %s\n", __func__, ifname);
		goto exit;
	}

	// Skip if primary radio is disabled
	snprintf(tmp, sizeof(tmp), "wl%d_radio", unit);
	if (nvram_match(tmp, "0")) {
		goto exit;
	}

	// Skip if bss is disabled
	snprintf(tmp, sizeof(tmp), "%s_bss_enabled", nvifname);
	if (nvram_match(tmp, "0")) {
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
	char *list, list_size = 0;
	char *ifnames = NULL;
	char *lan_ifnames = nvram_safe_get("lan_ifnames");
	char tmp[WPS_PBCD_NVNAME_BUF_SIZE] = {0};
	int unit = -1;
	uint8 bitflags = 0x0;	// can accomodate radio units from 0 to 7

	// if nvram value is set use the interface names listed in that nvram
	if (wps_ifnames[0] != '\0') {
		ifnames = wps_ifnames;
	} else {
		ifnames = lan_ifnames;
	}

	if (ifnames[0] == '\0') {
		cprintf("Info: wps_pbcd %s did not find any interface to add to wps %s ifnames"
			" list wps_ifnames=[%s] lan_ifnames=[%s]\n",
			__func__, mode_compare_str, wps_ifnames, lan_ifnames);
		return 0;
	}

	list_size = strlen(ifnames) +  1 /* '\0' */;
	list = (char *)calloc(1, list_size);
	if (!list) {
		cprintf("Err: wps_pbcd %s memory allocation failed for size %d\n",
			__func__, list_size);
		return -1;
	}

	foreach(ifname, ifnames, next) {
		// Get radio unit
		if (wps_pbcd_get_radio_unit(ifname, &unit)) {
/*
			dprintf("Info: wps_pbcd %s get radio unit "
				"failed for %s\n", __func__, ifname);
*/
			continue;
		}

		// Check whether ifname is already added to the list for the radio
		if (isset(&bitflags, unit)) {
			continue;
		}

		// Get nvifname from osifname
		if (osifname_to_nvifname(ifname, nvifname, sizeof(nvifname))) {
			dprintf("Info: wps_pbcd %s osifname_to_nvifname failed for %s\n",
				__func__, ifname);
			continue;
		}

		// Check if wps is possible on the interface
		if (wps_pbcd_is_wps_possible_on_interface(ifname, nvifname, unit) == FALSE) {
			dprintf("Info: wps_pbcd %s wps is not possible on ifname %s\n",
				__func__, ifname);
			continue;
		}

		// Add either AP/STA interfaces to the wps_ifnames list based on the mode
		snprintf(tmp, sizeof(tmp), "%s_mode", nvifname);
		if (nvram_match(tmp, mode_compare_str)) {
			if (add_to_list(ifname, list, list_size)) {
				cprintf("Info: wps_pbcd %s failed to add %s to"
					" wps_%s_ifnames\n", __func__, ifname, mode_compare_str);
			} else {
				// Set unit bit to indicate ifname is already added for radio
				setbit(&bitflags, unit);
			}
		} else {
			dprintf("Info: wps_pbcd %s interface %s is operating in %s mode "
				"hence not adding it to wps_%s_ifnames list\n", __func__, ifname,
				nvram_safe_get(tmp), mode_compare_str);
		}
	}

	dprintf("Info: wps_pbcd %s wps_%s_ifnames are [%s] \n", __func__, mode_compare_str, list);
	// Store the wps ifnames to out_list
	if (list[0] != '\0') {
		if (*out_list != NULL) {
			free(*out_list);
		}

		*out_list = strdup(list);
	}

	free(list);

	return 0;
}

/* Join wpa control monitor threads */
static void
wps_pbcd_join_monitor_threads()
{
	int idx = 0;
	wps_pbcd_info_t *pbcd_info = NULL;

	for (idx = 0; idx < g_wps_pbcd_info_list.count; idx++) {
		pbcd_info = g_wps_pbcd_info_list.wps_pbcd_info_objects[idx];
		dprintf("Info: wps_pbcd %s join monitor thread for %s \n",
			__func__, pbcd_info->wpa_ctrl_dir);
		pthread_cancel(pbcd_info->monitor_thread_id);
		pthread_join(pbcd_info->monitor_thread_id, NULL);
	}
}

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

	foreach(ifname, wps_ifnames, next) {
		dprintf("Info: wps_pbcd %s stoping wps session on ifname %s \n", __func__, ifname);
		wl_wlif_wps_stop_session(ifname);
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
		cprintf("Err: wps_pbcd %s memory allocation failed for size %zu\n",
			__func__, sizeof(*arg));
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
		cprintf("Err: wps_pbcd %s thread creation failed for notification id %d\n",
			__func__, id);
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
			dprintf("Info: wps_pbcd %s id %d is set\n",
				__func__, notification->notification_id);
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

/* Dummy function for signal handler */
static void
wps_pbcd_dummy_signal_handler(int signum)
{
	/* Do nothing */
}

/* Attaches the signal handler routine */
static void
wps_pbcd_install_signal_handler(int signal)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = wps_pbcd_dummy_signal_handler;

	if (sigaction(signal, &action, NULL) < 0) {
		cprintf("Err: wps_pbcd %s sigaction failed for signal %d\n", __func__, signal);
	}
}

/* Dedicated thread to handle the received signals */
static void*
wps_pbcd_signal_handler(void *arg)
{
	sigset_t set;
	int signum;

	wps_pbcd_install_signal_handler(SIGHUP);
	wps_pbcd_install_signal_handler(SIGINT);
	wps_pbcd_install_signal_handler(SIGTSTP);
	wps_pbcd_install_signal_handler(SIGSEGV);
	wps_pbcd_install_signal_handler(SIGTERM);
	wps_pbcd_install_signal_handler(SIGQUIT);
	wps_pbcd_install_signal_handler(SIGFPE);
	wps_pbcd_install_signal_handler(SIGUSR1);
	for (;;) {
		/* Wait for all the signals */
		sigfillset(&set);
		sigwait(&set, &signum);

		switch (signum) {
		case SIGHUP:
		case SIGINT:
		case SIGTSTP:
		case SIGSEGV:
		case SIGTERM:
		case SIGQUIT:
		case SIGFPE:
			wps_pbcd_gpio_board_cleanup();
			wps_pbcd_join_monitor_threads();
			wps_pbcd_free_info_objects_list(&g_wps_pbcd_info_list);
			exit(EXIT_SUCCESS);
		case SIGUSR1:
			wps_pbcd_register_for_wps_success_notification(nvram_safe_get("wl_ifnames"));
		default:
			dprintf("Info: %s caught signal %d\n", __func__, signum);
		}
	}
}

int
main(void)
{
	sigset_t set;
	pthread_t thread_id;
	FILE *fp;

	if (daemon(1, 1) == -1) {
		cprintf("Err: wps_pbcd %s %d daemonize failed\n", __func__, __LINE__);
		return -1;
	}

	/* write pid */
	if ((fp = fopen("/var/run/wps_pbcd.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* Create a separate thread to handle the signals */
	wl_wlif_create_thrd(&thread_id, wps_pbcd_signal_handler, NULL, FALSE);

	/* Block sigals on all other threads */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTSTP);
	sigaddset(&set, SIGSEGV);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGFPE);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, NULL);

		memset(&g_wps_data, 0, sizeof(g_wps_data));
		memset(&g_wps_pbcd_info_list, 0, sizeof(g_wps_pbcd_info_list));

		// Save wps ifnames for each radio operating in ap mode
		(void)wps_pbcd_update_wps_ifnames(nvram_safe_get("wps_ap_ifnames"), "ap",
			&g_wps_pbcd_info_list.wps_ap_ifnames);

		// Save wps ifnames for each radio operating in sta mode
		(void)wps_pbcd_update_wps_ifnames(nvram_safe_get("wps_sta_ifnames"), "sta",
			&g_wps_pbcd_info_list.wps_sta_ifnames);

		wps_pbcd_fill_info_objects_list(&g_wps_pbcd_info_list);

		wps_pbcd_run_wps_monitor_threads(&g_wps_pbcd_info_list);

		wps_pbcd_poll_button_press();

#ifdef STB
	while (1) {
		sleep(1);
	}
#endif /* STB */
	return 0;
}
