/*
 * Router hostapd control script
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
 * $Id: hostapd_config.c 793857 2020-12-12 01:14:57Z $
 */

#ifdef CONFIG_HOSTAPD

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <wlutils.h>
#include <common_utils.h>
#include <wlif_utils.h>
#include <bcmutils.h>
#include <time.h>
#include <md5.h>
#ifdef BCA_HNDROUTER
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <board.h>
#endif /* BCA_HNDROUTER */
#include <pthread.h>
#include <dirent.h>
#include <ctype.h>
#include <typedefs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ			16
#endif	/* IFNAMSIZ */

#ifdef HAPD_WDS_DRAFT
//#define HAPD_WDS_DBG
#endif /* HAPD_WDS_DRAFT */

#ifndef MAX_RADIO_NUM
#define MAX_RADIO_NUM			4	// Max 4 radio interfaces on router platform
#endif /* MAX_RADIO_NUM */

#define MAX_WDS_IF			16	// Max 16 WDS interfaces per radio. TODO: revisit

#ifndef MAX
#define MAX(X, Y)			((X) > (Y) ? (X) : (Y))
#endif	/* MAX */

#ifndef MIN
#define MIN(X, Y)			((X) < (Y) ? (X) : (Y))
#endif	/* MIN */

/* Swap the bytes in a 16-bits word */
#define swap16(x) (\
	(uint16)(((uint16)(x) & 0xff) << 8 | ((uint16)(x) & 0xff00) >> 8)  \
)

#define	HAPD_MAX_BUF			512
#define	HAPD_MIN_BUF			128
#define HAPD_WPA2_PSK_HEXLEN		64	/* 32 bytes hex-digit PSK */
#define HAPD_PASSPH_MIN_LEN		8	/* passphrase min length */
#define HAPD_PASSPH_MAX_LEN		63	/* passphrase max length */

#define HAPD_DIR			"/var/run/hostapd"
#define HAPD_FILE_DIR			"/tmp"
#define HAPD_FILENAME_SUFFIX		"hapd.conf"
#define HAPD_PSKFILE_SUFFIX		"hapd.psk"
#define HAPD_PINFILE_SUFFIX		"hapd.pin-req"

// Config flags
#define HAPD_CFG_DEFER			0x1	// Flag to handle a prev entry to defer
#define HAPD_CFG_IFR			0x2	// Flag to indicate interface specific settings
#define	HAPD_CFG_BSS			0x4	// Flag to indicate bss specific settings
#define HAPD_CFG_PERBSS			0x8	// Flag to indicate that nvram is per bss
#define HAPD_CFG_USEDEFAULT		0x10	// Flag to write the default value in config file
#define HAPD_CFG_COMMON			(HAPD_CFG_BSS | HAPD_CFG_IFR)
#define HAPD_CFG_LRG_BUF		0x20	// Flag to allocate large size buffer to write to
						//  conf file
#define WPA_SUP_CFG_GBL			0x40	// Flag to indicate global settings for supplicant

// auth algo
#define HAPD_AUTH_OPEN_SYSTEM		1
#define HAPD_AUTH_SHARED_KEY		2

// Operation mode or hw_mode
#define	HAPD_HW_MODE_80211_A		"a"	// When operating in 5G and HT or VHT phy
#define HAPD_HW_MODE_80211_G		"g"	// when Operating in 2.4G for 802.11n phy
#define HAPD_HW_MODE_80211_B		"b"	// When operating in 2.4G for 802.11n phy

// Internal akm value bitflags
#define HAPD_AKM_OPEN			0x0
#define HAPD_AKM_WEP			0x1
#define HAPD_AKM_PSK			0x2
#define HAPD_AKM_PSK2			0x4
#define HAPD_AKM_WPA3_SAE		0x8
#define HAPD_AKM_WPA3_SAE_FT		0x10
#define HAPD_AKM_WPA3_DPP		0x20
#define HAPD_AKM_PSK2_FT		0x40
#define HAPD_AKM_OWE			0x80

/* Start of Enterprise akm */
#define HAPD_AKM_WPA			0x100
#define HAPD_AKM_WPA2			0x200
#define HAPD_AKM_WPA2_OSEN		0x400
#define HAPD_AKM_WPA3_SUITE_B           0x800

// Security type
#define	HAPD_SEC_OPEN			0	// Open Security system
#define	HAPD_SEC_WPA			1	// IEEE 802.11i/D3.0
#define HAPD_SEC_WPA2			2	// Full  IEEE 802.11i/RSN

// Set of accepted key management algorithms WPA-PSK, WPA-EAP, or both
#define HAPD_KEY_MGMT_WPA			"WPA-PSK"
#define HAPD_KEY_MGMT_EAP			"WPA-EAP"
#define HAPD_KEY_MGMT_WPA_PSK_FT		"WPA-PSK FT-PSK"
#define HAPD_KEY_MGMT_EAP_FT			"WPA-EAP FT-EAP"
#define HAPD_KEY_MGMT_WPA_SHA256		"WPA-PSK-SHA256"
#define HAPD_KEY_MGMT_WPA_SHA256_PSK		"WPA-PSK-SHA256 WPA-PSK"
#define HAPD_KEY_MGMT_EAP_SHA256		"WPA-EAP-SHA256"
#define HAPD_KEY_MGMT_SAE			"SAE"
#define HAPD_KEY_MGMT_WPA_PSK_SAE		"WPA-PSK SAE"
#define HAPD_KEY_MGMT_WPA_SHA256_SAE		"WPA-PSK-SHA256 SAE"
#define HAPD_KEY_MGMT_WPA_FT_PSK_SAE		"WPA-PSK FT-PSK SAE"
#define HAPD_KEY_MGMT_FT_SAE			"FT-SAE"
#define HAPD_KEY_MGMT_OSEN			"OSEN"
#define HAPD_KEY_MGMT_DPP			"DPP"
#define HAPD_KEY_MGMT_SUITE_B                   "WPA-EAP-SUITE-B-192"
#define HAPD_KEY_MGMT_OWE			"OWE"

#define	HAPD_CIPHER_SUITE_CCMP		"CCMP"
#define	HAPD_CIPHER_SUITE_TKIP		"TKIP"
#define	HAPD_CIPHER_SUITE_SUITE_B	"GCMP-256"

#define HAPD_IEEE8021X_SUPPORTED	"1"
#define HAPD_SUPPORTED			"1"
#define HAPD_UNSUPPORTED		"0"

// Wps device pin default value
#define HAPD_WPS_DEVICE_PIN_DEFAULT_VAL	"12345670"
#define HAPD_WPS_DEVICE_PIN_LEN		8

// Wps states
#define	HAPD_WPS_DISABLED		0
#define	HAPD_WPS_UNCONFIGURED		1
#define HAPD_WPS_CONFIGURED		2

// Wps configuration methods
#define HAPD_WPS_CONFIG_LABEL		0x0004	/* Label */
#define HAPD_WPS_CONFIG_DISPLAY		0x0008	/* Display */
#define HAPD_WPS_CONFIG_PBC		0x0080	/* Push btn either physical or virtual */
#define HAPD_WPS_CONFIG_KEYPAD		0x0100	/* Keypad */
#define HAPD_WPS_CONFIG_VPBC		0x0280	/* Virtual push button */
#define HAPD_WPS_CONFIG_PHYPBC		0x0480	/* Physical push button */
#define HAPD_WPS_CONFIG_VPIN		0x2008	/* Virtual display pin */
#define HAPD_WPS_CONFIG_PHYPIN		0x4008	/* Physical display pin */

// Wps auth types
#define HAPD_WPS_AUTH_OPEN		0x01
#define HAPD_WPS_AUTH_WPAPSK		0x02
#define HAPD_WPS_AUTH_WPA2PSK		0x20

//Wps encryption types
#define HAPD_WPS_ENCR_NONE		0x01
#define HAPD_WPS_ENCR_TKIP		0x04
#define HAPD_WPS_ENCR_AES		0x08

// Wps cred processing attribute values
#define HAPD_WPS_DO_NOT_PROCESS_CREDS_PASS_TO_CTRL_INTERFACE		"1"
#define HAPD_WPS_PROCESS_CREDS_AND_PASS_TO_CTRL_INTERFACE		"2"

#define WPA_SUPP_APP			"wpa_supplicant-2.7"

#define WPA_SUPP_FILE_DIR		"/tmp"
#define WPA_SUPP_FILENAME_SUFFIX	"wpa_supplicant.conf"

/* WPA-PSK mode ASCII passphrase length */
#define	WPA_SUPP_PASSPH_MIN_LEN		HAPD_PASSPH_MIN_LEN
#define	WPA_SUPP_PASSPH_MAX_LEN		HAPD_PASSPH_MAX_LEN

/* 32 bytes hex-digit PSK */
#define  WPA_SUPP_WPA2_PSK_HEXLEN	HAPD_WPA2_PSK_HEXLEN
// Security type
#define	WPA_SUPP_SEC_OPEN_OR_WEP	"NONE"	// Open Security or WEP
#define	WPA_SUPP_SEC_WPA		"WPA"	// IEEE 802.11i/D3.0
#define WPA_SUPP_SEC_WPA2		"WPA2"  // Full  IEEE 802.11i/RSN

#define WPA_SUPP_PROTO_WPA		"WPA"   // WPA/IEEE 802.11i/D3.0
#define WPA_SUPP_PROTO_RSN		"RSN"   // WPA2/IEEE 802.11i

#define HAPD_START_DEFER		4	// Defer hostapd start by so much sec

#ifdef HAPD_WDS
#define WDS_DEV_NAME			"wds"
#define CTRL_IF_DIR			"/var/run"			  // ctrl if socket dir
#define GLOBAL_CTRL_IF			"/var/run/wpa_supplicant-global"  // global ctrl if socket
#define SUPPLICANT_NAME			"wpa_supplicant"
#define WDS_WPA_ROLE_AUTH		0
#define WDS_WPA_ROLE_SUP		1
#define WDS_WPA_ROLE_ERR		-1
#endif /* HAPD_WDS */

#ifndef HAPD_WPASUPP_DBG
#define HAPD_WPASUPP_DBG
#endif /* HAPD_WPASUPP_DBG */

#define HSFLG_DGAF_DS			10      /* DGAF BIT in HS FLAG.
						* Should be in sync with passpoint
						*/
#define HAPD_ENABLE			1
#define HAPD_DISABLE			0

#define HAPD_MFP_OFF			0	// PMF Off
#define HAPD_MFP_CAP			1	// PMF Capable
#define HAPD_MFP_REQ			2	// PMF Required

#ifdef HAPD_WPASUPP_DBG
#define PRINT_IFLIST(iflist)	do {		\
	char ifname[IFNAMSIZ] = {0};		\
	char *next = NULL;			\
	foreach(ifname, iflist, next) {		\
		printf("%s ", ifname);		\
	}					\
	printf("\n");				\
} while (0);
#endif /* HAPD_WPASUPP_DBG */

#define HAPD_ON_PRIMARY_IFACE		0x0	/* run hostapd on primary interface */
#define HAPD_ON_VIRTUAL_IFACE		0x1	/* run hostapd on virtual interface */

#define WPAX_FIELDS_NUM			6	/* Non WEP - WPA/WPA2/WPA3 and ptk,gtk rekey */
#define SAE_FIELDS_NUM			5
#define FBT_FIELDS_NUM			9
#define RADIUS_FIELDS_NUM		11
#define PREAUTH_FIELDS_NUM		1
#define WPS_FIELDS_NUM			19
#define MAP_FIELDS_NUM			5
#define WPASUPP_WPS_FIELDS_NUM		10
#define DPP_FIELDS_NUM			3
#define OWE_FIELDS_NUM			2

#define HAPD_MAX_BRIDGE_NUM 16

/* Per radio structure to hold info on WDS interfaces with role as SUPPLICANT.
 * Max 4 WDS interfaces per radio.A WDS ifce is assigned the role of SUPPLICANT if its
 * primary radio ifce MAC address < MAC addresss of its WDS peer.
 */
struct hapd_wpasupp_wds_info {
	uint8 wds_if_count; // No of WDS interfaces with role as supplicant for the radio.
	uint8 wds_idx[MAX_WDS_IF]; // array to hold the index of WDS ifce(s) with SUPPLICANT role.
	char wds_ifname[MAX_WDS_IF][IFNAMSIZ]; // wdsx.y.1, wdsx.y.2, wdsx.y.3, wdsx.y.4
	char wds_peers_mac_arr[MAX_WDS_IF][ETHER_ADDR_LEN]; // MAC address of WDS peer(s)
};

typedef struct hapd_wpasupp_wds_info  hapd_wpasupp_wds_info_t;

#define WPA_PSK_FLAG_IS_WPASUPP 		(0)
#define WPA_PSK_FLAG_IS_HAPD			(1 << 0)
#define WPA_PSK_FLAG_IS_SAE_ONLY		(1 << 1)

extern void RAND_bytes(unsigned char *buf, int num);

typedef struct hapd_nvram_config hapd_nvram_config_t;

/* Fn ptr for the conversion functions
 * @param nv_ifname		interface name in the format as stored in nvram (wlX / wlX.Y / ...)
 * @param cfg_arr_nvname	nvram name as in cfg_arr, without iface/bss prefix.
 * @param placeholder		placeholder string as in cfg_arr to be written into hostapd or
				wpa_supplicant conf file. Can be over-written by conv callback fn.
 * @out_val			output value after conversion. To be filled against placeholder in
				hostapd/wpa_supplicant conf file.
 * @out_sz			length of the out_val buffer.
 * @return			0 on success -1 on error.Any +ve value implies next defer count.
 */
typedef int (*hapd_convert_fn)
	(char *nv_ifname, char *cfg_arr_nvname, char **placeholder, char *out_val, int out_sz);

/* hostapd callbacks */
static int hapd_br_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_phytype_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_channel_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_auth_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_wep_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_wep_key_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_fbt_mdid_conv_fn(char *nv_if, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_r1kh_id_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_fbtap_r0kh_conv_fn(char *nv_if, char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_fbtap_r1kh_conv_fn(char *nv_if, char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_key_mgmt_conv_fn(char *nv_if, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_preauth_conv_fn(char *nv_if, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_preauth_interfaces_conv_fn(char *nvif, char *carr_nv, char **ph, char *out, int sz);
static int hapd_own_ip_addr_conv_fn(char *nvif, char *carr_nv, char **ph, char *out, int sz);
static int hapd_radius_akm_conv_fn(char *nv_if, char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_secondary_radius_server_conv_fn(char *nv_if,
		char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_wpsstate_conv_fn(char *nv_if, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_wps_aplockdown_conv_fn(char *nvif, char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_wps_device_pin_conv_fn(char *nvif, char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_wps_rf_bands_conv_fn(char *nv_if, char *cfg_arr_nv, char **ph, char *out, int sz);
static int hapd_wpsuuid_conv_fn(char *nv_if, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_wpsconfig_method_conv_fn(char *nvif, char *carr_nv, char **ph, char *out, int sz);
static int hapd_mfp_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_mfp_cipher_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz);
#if defined(MULTIAP)
static int hapd_map_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_wpsmap_conv_fn(char *nvif, char *cfg_arr_nv, char **placeholder, char *out, int sz);
static int wpa_supp_map_conv_fn(char *nv_ifnm, char *cfg_arr_nvname, char **ph, char *out, int sz);
#endif	/* MULTIAP */
static int hapd_wmmconfig_conv_fn(char *nv_if, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_osen_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_dgaf_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_11d_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_11h_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_cc_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out, int sz);
static int hapd_dtim_conv_fn(char *nvif, char *cfg_arr_nv, char **placeholder, char *out, int sz);
static int hapd_bi_conv_fn(char *nv_if, char *cfg_arr_nv, char **placeholder, char *out, int sz);
static int hapd_dpp_connector_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz);
static int wpa_supp_dpp_connector_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz);
static int hapd_owe_groups_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz);
static int hapd_owe_trans_ifname_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz);

/* hostapd, wpa_supplicant common helper functions */
static bool hapd_wpasupp_hex_validate(const char *s);
static bool hapd_wpasupp_is_ifce_ap(const char *ifname);
static bool hapd_wpasupp_is_bss_enabled(const char* ifname);
static bool hapd_wpasupp_is_primary_ifce(const char *ifname);
static void hapd_wpasupp_get_security_details(char *nv_ifname, int *out_akm);
static void hapd_wpasupp_set_deferred(int cur_pos, int count);
static void hapd_wpasupp_get_filtered_ifnames_list(char *iflist, char *fltrd_iflist, int flist_sz);
static void hapd_wpasupp_get_primary_virtual_iflist(char *flist, char *plist, char *slist, int sz);
static void hapd_wpasupp_get_radio_list(char *ifnames_list, char *rlist, int rlistsz, int idx);
static int hapd_wpasupp_get_primary_ifce(char *nv_ifname, char *wlpr_ifname, int sz);
static void hapd_wpasupp_fill_pairwise(char *nv_ifname, char *name, char *out_val, int sz);
static void hapd_wpasupp_get_key_mgmt(char *nv_ifname, int fbt_enabled, int akm, char *key_mgmt);
static void hapd_wpasupp_psk_key_hndlr(char *nv_name, char **ph, char *out, int out_sz, int flags, int akm);
static bool hapd_wpasupp_is_wps_possible(char *nv_ifname);
static bool hapd_wpasupp_is_ifce_monitormode(const char *ifname);

/* hostapd helper functions */
static void hapd_fill_nvrams_to_config_file(FILE *fp, char *nv_ifname, uint32 flags);
int hapd_get_config_filename(char *nv_ifname, char *o_fname, int sz,
		uint32 *o_flgs, int mode);
int hapd_create_config_file(char *nv_ifname, char *filename, uint32 flags);
static int hapd_fbt_enabled(char *nv_ifname);
static int wpa_supp_fbt_enabled(char *nv_ifname);
static int hapd_wps_add_sae_enabled(char *nv_ifname);

/* wpa_supplicant helper functions */
static bool wpa_supp_is_join_bssid_available(char *nvif);
int wpa_supp_create_config_file(char *nv_ifname, char *filename, uint32 flags,
		int idx, hapd_wpasupp_wds_info_t *wdsi_ptr);

int wpa_supp_get_config_filename(char *nv_ifname, char *o_fname, int size, uint32 *o_flgs);
static void wpa_supp_set_deferred(hapd_nvram_config_t *cfg_arr, int cur_pos, int count);
static void wpa_supp_fill_nvrams_to_config_file(FILE *fp, char *nv_ifname, uint32 flags,
	hapd_nvram_config_t *cfg_arr);

/* wpa_supplicant callbacks */
static int wpa_supp_wps_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
	char **placeholder, char *out_val, int out_sz);
static int wpa_supp_wps_cred_processing_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
	char **placeholder, char *out_val, int out_sz);
static int wpa_supp_key_mgmt_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz);
static int wpa_supp_ssid_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz);

static int start_hostapd(char *fltrd_iflist, char *pri_iflist, char *vr_iflist);
static int start_wpa_supplicant(int idx, char *iflist, hapd_wpasupp_wds_info_t *wdsi_ptr);

#define WAIT_HOSTAPD_MAX_TIME 5 /* seconds */
int stop_hostapd_per_radio(int radio_idx);
int start_hostapd_per_radio(int radio_idx);
static void stop_wpa_supplicant_per_radio(int radio_idx);
static int get_hostapd_pid(int radio_idx, pid_t *pid);

#ifdef HAPD_WDS_DRAFT
static void hapd_wpasupp_init_wds_info_arr(hapd_wpasupp_wds_info_t wdsi_arr[]);
static int hapd_wpasupp_get_pr_if_mac_addr(unsigned char pr_if_mac_arr[][ETHER_ADDR_LEN]);
static int hapd_wpasupp_get_wds_peer_mac_list(unsigned char wds_peer_mac_list_arr[][HAPD_MAX_BUF]);
static int hapd_wpasupp_cp_peer_mac(const char *a, unsigned char *e);
static int hapd_wpasupp_fill_wds_info(hapd_wpasupp_wds_info_t wdsi_arr[],
		unsigned char wds_peer_mac_list_arr[][HAPD_MAX_BUF],
		unsigned char pr_if_mac_arr[][ETHER_ADDR_LEN]);
#ifdef HAPD_WDS_DBG
void hapd_wpasupp_print_wds_peer_mac_list(unsigned char wds_peer_mac_list_arr[][HAPD_MAX_BUF]);
int hapd_wpasupp_print_wds_info(hapd_wpasupp_wds_info_t wdsi_arr[MAX_RADIO_NUM]);
#endif /* HAPD_WDS_DBG */
#endif /* HAPD_WDS_DRAFT */

#ifdef HAPD_WDS
void hapd_wpasupp_wds_hndlr(const char *pkt);
bool hapd_wpasupp_is_ps_running(const char *ps_name);
void wpasupp_add_and_enable_network(char *ifname);
#endif /* HAPD_WDS */

int start_hapd_wpasupp(int skip);
void stop_hapd_wpasupp();
int start_hapd_wpasupp_per_radio(int radio_idx);
void stop_hapd_wpasupp_per_radio(int radio_idx);
static void hapd_wpasupp_get_radio_ifnames_list(char *radio_iflist[]);

struct hapd_nvram_config
{
	char *nv_name;			/* nvram name without iface/bss prefix */
	char *placeholder;		/* If this changes dynamically, reassign on each call */
	uint32 flags;			/* flags of type CFG_XXX */
	char *def_val;			/* default value. Can be used for testing and in some cases
					 * we can directly write into hostapd config file
					 */
	hapd_convert_fn cb_fn;		/* convertion callback function ptr */
};

/* In a repeater with multiple virtual/secondary interfaces as BSS' AP, the radio parameters such as
 * interface, hw_mode and channel fields of hostapd.conf file are to be filled only once for the
 * first virtual interface. Rest of BSS specific settings are filled as usual for all the BSS'.
 * In this case, the first virtual interface acts like a regualr primary interface (ethX)
 */

bool radio_params_set[MAX_RADIO_NUM] = {FALSE};

/* cache primary ifname's in wlX format */
char ifname_arr[MAX_RADIO_NUM][IFNAMSIZ] = {{0}};

/*
 * Presently the nvram order is important as for nvram's some specific value
 * we are defering the next array elements.
 * For exp: when wep is disabled we are defering key1, key2 key3 and key4 entries.
 */
static hapd_nvram_config_t cfg_arr[] =
{
	{"ifname", "interface", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "eth0", NULL},
	{"phytype", "hw_mode", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "g", hapd_phytype_conv_fn},
	{"chanspec", "channel", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "11", hapd_channel_conv_fn},
	{"country_code", "country_code", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "US", hapd_cc_conv_fn},
	{"reg_mode", "ieee80211d", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "1", hapd_11d_conv_fn},
	{"reg_mode", "ieee80211h", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "1", hapd_11h_conv_fn},
	{"bcn", "beacon_int", (HAPD_CFG_IFR | HAPD_CFG_PERBSS), "100", hapd_bi_conv_fn},
	{"ifname", "bss", (HAPD_CFG_BSS | HAPD_CFG_PERBSS), "wl0.1", NULL},
	{"lan_ifname", "bridge", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "br0", hapd_br_conv_fn},
	{"dtim", "dtim_period", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "2", hapd_dtim_conv_fn},
	{"", "ctrl_interface", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS | HAPD_CFG_USEDEFAULT),
		HAPD_DIR, NULL},
	{"hwaddr", "bssid", (HAPD_CFG_BSS | HAPD_CFG_PERBSS), "00:00:00:00:00:00", NULL},
	{"ssid", "ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "ASUS", NULL},
	{"auth", "auth_algs", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1", hapd_auth_conv_fn},
	{"ap_isolate", "ap_isolate", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	{"closed", "ignore_broadcast_ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	// wep_def_key and from key0 till key4 vals are dependent on the wep nvram.
	{"key", "wep_default_key", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_wep_conv_fn},
	{"key1", "wep_key0", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"key2", "wep_key1", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"key3", "wep_key2", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"key4", "wep_key3", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	// wpa, akm rsn and wpa_psk vals fbt are dependent on the akm and wep nvram.
	{"wpa",	"wpa", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_key_mgmt_conv_fn},
	{"akm",	"wpa_key_mgmt",	(HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"WPA-PSK", hapd_key_mgmt_conv_fn},
	{"crypto", "wpa_pairwise", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"CCMP", hapd_key_mgmt_conv_fn},
	{"wpa_gtk_rekey", "wpa_group_rekey", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	{"wpa_ptk_rekey", "wpa_ptk_rekey", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	// The placeholder field is modified run-time based on passphrase or PSK in psk_key_hndlr()
	{"wpa_psk", "wpa_passphrase", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "12345678",
		hapd_key_mgmt_conv_fn},
	{"mfp",	"sae_require_mfp", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_key_mgmt_conv_fn},
	{"sae_anti_clog_threshold", "sae_anti_clogging_threshold",
		(HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "5", NULL},
	{"sae_sync", "sae_sync", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "5", NULL},
	{"sae_groups", "sae_groups", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "19", NULL},
	{"sae_pwe", "sae_pwe", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	{"mfp",	"ieee80211w", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_mfp_conv_fn},
	{"fbt_mdid", "mobility_domain", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), NULL,
			hapd_fbt_mdid_conv_fn},
	{"r0kh_id", "nas_identifier", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), NULL, NULL},
	{"r1kh_id", "r1_key_holder", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), NULL,
			hapd_r1kh_id_conv_fn},
	{"fbt_reassoc_time", "reassociation_deadline", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
			"1000", NULL},
	{"fbtoverds", "ft_over_ds", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), NULL, NULL},
	{"r0kh", "r0kh", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS | HAPD_CFG_LRG_BUF), NULL,
			hapd_fbtap_r0kh_conv_fn},
	{"r1kh", "r1kh", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS | HAPD_CFG_LRG_BUF), NULL,
			hapd_fbtap_r1kh_conv_fn},
	{"fbt_generate_local", "ft_psk_generate_local", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0",
			NULL},
	{"", "pmk_r1_push", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS | HAPD_CFG_USEDEFAULT), "1", NULL},
	// Setting for radius server
	{"akm", "ieee8021x", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_radius_akm_conv_fn},
	{"preauth", "rsn_preauth", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1", hapd_preauth_conv_fn},
	{"preauth", "rsn_preauth_interfaces", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "",
		hapd_preauth_interfaces_conv_fn},
	{"", "own_ip_addr", (HAPD_CFG_COMMON), "127.0.0.1", hapd_own_ip_addr_conv_fn},
	{"radius_ipaddr", "auth_server_addr", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0.0.0.0", NULL},
	{"radius_port", "auth_server_port", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1812", NULL},
	{"radius_key", "auth_server_shared_secret", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"12345678", NULL},
	{"radius2_ipaddr", "auth_server_addr", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0.0.0.0",
		hapd_secondary_radius_server_conv_fn},
	{"radius2_port", "auth_server_port", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1812", NULL},
	{"radius2_key", "auth_server_shared_secret", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"12345678", NULL},
	{"mfp", "group_mgmt_cipher", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "AES-128-CMAC",
			hapd_mfp_cipher_conv_fn},
	{"hsflag", "disable_dgaf", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_dgaf_conv_fn},
	{"hs20_deauth_req_timeout", "hs20_deauth_req_timeout",
			(HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	{"akm", "osen", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_osen_conv_fn},
	// Settings for wps
	{"wps_mode", "wps_state", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "2", hapd_wpsstate_conv_fn},
	{"", "wps_independent", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT), "1", NULL},
	{"wps_aplockdown", "ap_setup_locked", (HAPD_CFG_COMMON), "0", hapd_wps_aplockdown_conv_fn},
	{"", "uuid", (HAPD_CFG_COMMON), "", hapd_wpsuuid_conv_fn},
	{"wps_device_name", "device_name", (HAPD_CFG_COMMON), "Wi-Fi Protected Setup Router", NULL},
	{"wps_mfstring", "manufacturer", (HAPD_CFG_COMMON), "ASUSTeK Computer Inc.", NULL},
	{"wps_modelname", "model_name", (HAPD_CFG_COMMON), "Wi-Fi Protected Setup Router", NULL},
	{"wps_modelnum", "model_number", (HAPD_CFG_COMMON), "Wi-Fi Protected Setup Router", NULL},
	{"boardnum", "serial_number", (HAPD_CFG_COMMON), "267", NULL},
	{"", "os_version", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT), "134217728", NULL},
	{"", "device_type", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT), "6-0050F204-1", NULL},
	{"wps_config_method", "config_methods", (HAPD_CFG_COMMON),
		"label display push_button keypad", hapd_wpsconfig_method_conv_fn},
	{"wps_device_pin", "ap_pin", (HAPD_CFG_COMMON), "", hapd_wps_device_pin_conv_fn},
	{"", "wps_cred_processing", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT),
		HAPD_WPS_PROCESS_CREDS_AND_PASS_TO_CTRL_INTERFACE, NULL},
	{"", "wps_rf_bands", (HAPD_CFG_COMMON), "", hapd_wps_rf_bands_conv_fn},
	{"", "upnp_iface", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "ethx", hapd_br_conv_fn},
	{"", "friendly_name", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT), "WPS Access Point", NULL},
	{"", "eap_server", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT), "1", NULL},
	{"wps_cred_add_sae", "wps_cred_add_sae", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
#if defined(MULTIAP)
	{"map", "map", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1", hapd_map_conv_fn},
	{"bh_ssid", "map_bh_ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "BH_SSID",
		hapd_wpsmap_conv_fn},
	{"bh_akm", "map_bh_auth", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "CCMP",
		hapd_wpsmap_conv_fn},
	{"bh_crypto", "map_bh_encr", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "WPA-PSK",
		hapd_wpsmap_conv_fn},
	{"bh_psk", "map_bh_psk", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1@sa^hg_z",
		hapd_wpsmap_conv_fn},
#endif	/* MULTIAP */
	{"wme_bss_disable", "wmm_enabled", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0",
		hapd_wmmconfig_conv_fn},
	{"dpp_connector", "dpp_connector", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "",
		hapd_dpp_connector_conv_fn},
	{"dpp_csign", "dpp_csign", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "", NULL},
	{"dpp_netaccess_key", "dpp_netaccesskey", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "", NULL},
	{"owe_groups", "owe_groups", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "19",
		hapd_owe_groups_conv_fn},
	{"owe_ptk_workaround", "owe_ptk_workaround", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"1", NULL},
	{"owe_transition_ifname", "owe_transition_ifname", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"", hapd_owe_trans_ifname_conv_fn},
	{"beacon_prot", "beacon_prot", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS),
		"0", NULL},
	{0, 0, 0, 0, 0}
};

/* wpa_supplicant config array */
static hapd_nvram_config_t wpa_supp_cfg_arr[] =
{
	{"wps_device_name", "device_name", (WPA_SUP_CFG_GBL), "Wi-Fi Protected Setup Router", wpa_supp_wps_conv_fn},
	{"wps_mfstring", "manufacturer", (WPA_SUP_CFG_GBL), "ASUSTeK Computer Inc.", NULL},
	{"wps_modelname", "model_name", (WPA_SUP_CFG_GBL), "Wi-Fi Protected Setup Router", NULL},
	{"wps_modelnum", "model_number", (WPA_SUP_CFG_GBL), "Wi-Fi Protected Setup Router", NULL},
	{"boardnum", "serial_number", (WPA_SUP_CFG_GBL), "267", NULL},
	{"", "os_version", (WPA_SUP_CFG_GBL | HAPD_CFG_USEDEFAULT), "134217728", NULL},
	{"", "device_type", (WPA_SUP_CFG_GBL | HAPD_CFG_USEDEFAULT), "6-0050F204-1", NULL},
	{"wps_config_method", "config_methods", (WPA_SUP_CFG_GBL),
		"label display push_button keypad", hapd_wpsconfig_method_conv_fn},
	{"", "wps_cred_processing", (WPA_SUP_CFG_GBL | HAPD_CFG_PERBSS), "",
		wpa_supp_wps_cred_processing_conv_fn},
	{"wps_cred_add_sae", "wps_cred_add_sae", (WPA_SUP_CFG_GBL | HAPD_CFG_PERBSS), "0", NULL},
#ifdef MULTIAP
	{"map", "map_bh_sta", (WPA_SUP_CFG_GBL | HAPD_CFG_PERBSS), "", wpa_supp_map_conv_fn},
#endif	/* MULTIAP */
	{"mfp", "pmf", (WPA_SUP_CFG_GBL | HAPD_CFG_PERBSS), "0", hapd_mfp_conv_fn},
	{"", "dpp_config_processing", (WPA_SUP_CFG_GBL | HAPD_CFG_USEDEFAULT), "2", NULL},
	{"sae_groups", "sae_groups", (WPA_SUP_CFG_GBL | HAPD_CFG_PERBSS), "19", NULL},
	{"sae_pwe", "sae_pwe", (WPA_SUP_CFG_GBL | HAPD_CFG_PERBSS), "0", NULL},
	{0, 0, 0, 0, 0}
};

/* wpa_supplicant network block config array */
static hapd_nvram_config_t wpa_supp_nw_cfg_arr[] =
{
	{"ssid", "ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "ASUS", wpa_supp_ssid_conv_fn},
	{"akm", "key_mgmt", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "NONE", wpa_supp_key_mgmt_conv_fn},
	{"proto", "proto", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "RSN", wpa_supp_key_mgmt_conv_fn},
	{"crypto", "pairwise", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "CCMP TKIP",
		wpa_supp_key_mgmt_conv_fn},
	{"wpa_psk", "psk", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		wpa_supp_key_mgmt_conv_fn},
	{"mfp",	"ieee80211w", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_mfp_conv_fn},
	{"key", "wep_tx_keyidx", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_wep_conv_fn},
	{"key1", "wep_key0", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"key2", "wep_key1", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"key3", "wep_key2", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"key4", "wep_key3", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		hapd_wep_key_conv_fn},
	{"", "scan_ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS | HAPD_CFG_USEDEFAULT), "1", NULL},
	{"dpp_connector", "dpp_connector", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "",
		wpa_supp_dpp_connector_conv_fn},
	{"dpp_csign", "dpp_csign", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "", NULL},
	{"dpp_netaccess_key", "dpp_netaccesskey", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "", NULL},
	{0, 0, 0, 0, 0}
};
#ifdef HAPD_WDS_DRAFT
/*  wpa_supplicant network block for each WDS interface of the radio */
static hapd_nvram_config_t wpa_supp_wds_cfg_arr[] =
{
	{"ssid", "ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "Broadcom", wpa_supp_ssid_conv_fn},
	{"akm", "key_mgmt", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "NONE", wpa_supp_key_mgmt_conv_fn},
	{"proto", "proto", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "RSN", wpa_supp_key_mgmt_conv_fn},
	{"crypto", "pairwise", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "CCMP TKIP",
		wpa_supp_key_mgmt_conv_fn},
	{"wpa_psk", "psk", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		wpa_supp_key_mgmt_conv_fn},
	{"mfp",	"ieee80211w", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_mfp_conv_fn},
	{0, 0, 0, 0, 0}
};
#endif /* HAPD_WDS_DRAFT */

/* wpa_supplicant extended network block config array */
static hapd_nvram_config_t wpa_supp_ext_nw_cfg_arr[] =
{
	{"ssid", "ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "ASUS", wpa_supp_ssid_conv_fn},
	{"akm", "key_mgmt", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "NONE", wpa_supp_key_mgmt_conv_fn},
	{"proto", "proto", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "RSN", wpa_supp_key_mgmt_conv_fn},
	{"crypto", "pairwise", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "CCMP TKIP",
		wpa_supp_key_mgmt_conv_fn},
	{"wpa_psk", "psk", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "1234567890",
		wpa_supp_key_mgmt_conv_fn},
	{"mfp",	"ieee80211w", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", hapd_mfp_conv_fn},
	{"", "scan_ssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS | HAPD_CFG_USEDEFAULT), "1", NULL},
	{"bssid", "bssid", (HAPD_CFG_COMMON | HAPD_CFG_PERBSS), "0", NULL},
	{"", "priority", (HAPD_CFG_COMMON | HAPD_CFG_USEDEFAULT), "1", NULL},
	{0, 0, 0, 0, 0}
};

/* Helper function to get size of all lan_ifname */
int
hapd_wpasupp_get_all_lanifname_sz(void)
{
	char tmp[HAPD_MAX_BUF];
	int ifnames_sz = 0;
	int i;

	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		char *p = NULL;

		if (i == 0) {
			snprintf(tmp, sizeof(tmp), "lan_ifname");
		} else {
			snprintf(tmp, sizeof(tmp), "lan%d_ifname", i);
		}

		if ((p = nvram_get(tmp)) != NULL) {
			ifnames_sz += strlen(p) + 1; /* 1 for space */
		}
	}

	if (ifnames_sz == 0)
		return 0;

	ifnames_sz ++; /* For null termination */
	return ifnames_sz;
}

/* Helper function to get concatenated lan_ifname */
int
hapd_wpasupp_get_all_lanifname(char *ifnames, int ifnames_sz)
{
	char tmp[HAPD_MAX_BUF];
	int i;

	ifnames[0] = 0;
	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		char *p = NULL;

		if (i == 0) {
			snprintf(tmp, sizeof(tmp), "lan_ifname");
		} else {
			snprintf(tmp, sizeof(tmp), "lan%d_ifname", i);
		}

		if ((p = nvram_get(tmp)) != NULL) {
			if (strlen(p) + strlen(ifnames) < (ifnames_sz-1)) {
				strcat(ifnames, p);
				strcat(ifnames, " ");
			}
		}
	}

	return strlen(ifnames);
}

/* Helper function to get size of all lan_ifnames (list) */
int
hapd_wpasupp_get_all_lanifnames_listsz(void)
{
	char tmp[HAPD_MAX_BUF];
	int ifnames_listsz = 0;
	int i;

	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		char *p = NULL;

		if (i == 0) {
			snprintf(tmp, sizeof(tmp), "lan_ifnames");
		} else {
			snprintf(tmp, sizeof(tmp), "lan%d_ifnames", i);
		}

		if ((p = nvram_get(tmp)) != NULL) {
			ifnames_listsz += strlen(p) + 1; /* 1 for space */
		}
	}

	if (ifnames_listsz == 0)
		return 0;

	ifnames_listsz ++; /* For null termination */

	return ifnames_listsz;
}

/* Helper function to get concatenated lan_ifnames (list) */
int
hapd_wpasupp_get_all_lanifnames_list(char *ifnames_list, int ifnames_listsz)
{
	char tmp[HAPD_MAX_BUF];
	int i;

	ifnames_list[0] = 0;
	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		char *p = NULL;

		if (i == 0) {
			snprintf(tmp, sizeof(tmp), "lan_ifnames");
		} else {
			snprintf(tmp, sizeof(tmp), "lan%d_ifnames", i);
		}

		if ((p = nvram_get(tmp)) != NULL) {
			if (strlen(p) + strlen(ifnames_list) < (ifnames_listsz-1)) {
				strcat(ifnames_list, p);
				strcat(ifnames_list, " ");
			}
		}
	}
	return strlen(ifnames_list);
}

/* Helper fn to get security info */
static void
hapd_wpasupp_get_security_details(char *nv_ifname, int *out_akm)
{
	char nv_name[HAPD_MAX_BUF] = {0}, tmp[HAPD_MIN_BUF] = {0}, *akm_val, *next;
	int akm = HAPD_AKM_OPEN;

	// Check for wep security
	snprintf(nv_name, sizeof(nv_name), "%s_wep", nv_ifname);
	if (!strcmp(nvram_safe_get(nv_name), "enabled")) {
		akm = HAPD_AKM_WEP;
	} else {
		snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);
		akm_val = nvram_safe_get(nv_name);

		foreach(tmp, akm_val, next) {
#ifndef CMWIFI_RDKB
			if (akm < HAPD_AKM_WPA && !strcmp(tmp, "psk")) { /* WPA-PSK */
				akm |= HAPD_AKM_PSK;
			}
#endif /* CMWIFI_RDKB */
			if (akm < HAPD_AKM_WPA && !strcmp(tmp, "psk2")) { /* WPA2-PSK */
				akm |= HAPD_AKM_PSK2;
			}
			/* WPA-EAP/1x */
			if (!strcmp(tmp, "wpa") && (!akm || akm == HAPD_AKM_WPA2)) {
				akm |= HAPD_AKM_WPA;
			}
			/* WPA2-EAP/1x */
			if (!strcmp(tmp, "wpa2") && (!akm || akm == HAPD_AKM_WPA)) {
				akm |= HAPD_AKM_WPA2;
			}
			if (!strcmp(tmp, "psk2ft")) {
				akm |= HAPD_AKM_PSK2_FT;
			}
			if (!strcmp(tmp, "sae")) {
				akm |= HAPD_AKM_WPA3_SAE;
			}
			if (!strcmp(tmp, "saeft")) {
				akm |= HAPD_AKM_WPA3_SAE_FT;
			}
			if (!strcmp(tmp, "osen")) {
				akm = HAPD_AKM_WPA2_OSEN;
			}
			if (!strcmp(tmp, "dpp")) {
				akm = HAPD_AKM_WPA3_DPP;
			}
			if (!strcmp(tmp, "owe")) {
				akm = HAPD_AKM_OWE;
			}
			if (!strcmp(tmp, "suite-b")) {
				akm |= HAPD_AKM_WPA3_SUITE_B;
			}
		}
	}

	/* WFA cert req: WPA, PSK should not supported when SAE enabled.
	 * So clear  WPA, PSK bits to disable TKIP
	 */
	if ((akm & HAPD_AKM_WPA3_SAE) ||
		(akm & HAPD_AKM_WPA3_SUITE_B)) {
		dprintf("Info: rc: %d: WPA3-Ent/SAE set: Unset WPA/PSK to disable TKIP\n",
			__LINE__);
		if (akm & HAPD_AKM_WPA)
			akm &= ~HAPD_AKM_WPA;
		if (akm & HAPD_AKM_PSK)
			akm &= ~HAPD_AKM_PSK;
	}

	*out_akm = akm;
}

/* Helper function to check possiblity of wps on the interface */
static bool
hapd_wpasupp_is_wps_possible(char *nv_ifname)
{
	char wps_mode[HAPD_MIN_BUF] = {0}, tmp[HAPD_MIN_BUF] = {0};
	int akm = 0, closed_nw = 0;

	closed_nw = atoi(nvram_safe_get(strcat_r(nv_ifname, "_closed", tmp)));
	snprintf(wps_mode, sizeof(wps_mode), "%s_wps_mode", nv_ifname);

	/* Wps is not allowed if network type is closed or wps mode is not enabled */
	/* SG_mode matching for AMAS RE OB support */
	if (closed_nw || (!(nvram_match("SG_mode", "1") && nvram_match("x_Setting", "0")) && !nvram_match(wps_mode, "enabled"))) {
	    return FALSE;
	}

	hapd_wpasupp_get_security_details(nv_ifname, &akm);

	/* Wps is supported when security is set to either open or contains psk/psk2 */
	if ((akm == HAPD_AKM_OPEN) || (akm & (HAPD_AKM_PSK | HAPD_AKM_PSK2))) {
		return TRUE;
	}

	return FALSE;
}

/* Fn to identify the bridge corresponding to wireless interface *
 */
static int
hapd_br_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	char tmp[HAPD_MAX_BUF] = {0};
	char tmplist[HAPD_MAX_BUF] = {0};
	char *wl_name = nvram_safe_get(strcat_r(nv_ifname, "_ifname", tmp));
	char *lan_ifnames[HAPD_MAX_BRIDGE_NUM];
	char *lan_ifname[HAPD_MAX_BRIDGE_NUM];
	int i = 0;

	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		if (i == 0) {
			snprintf(tmp, sizeof(tmp), "lan_ifname");
			snprintf(tmplist, sizeof(tmplist), "lan_ifnames");
		} else {
			snprintf(tmp, sizeof(tmp), "lan%d_ifname", i);
			snprintf(tmplist, sizeof(tmplist), "lan%d_ifnames", i);
		}
		lan_ifname[i] = nvram_safe_get(tmp);
		lan_ifnames[i] = nvram_safe_get(tmplist);
	}

	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		if (lan_ifnames[i][0] != '\0' && find_in_list(lan_ifnames[i], wl_name)) {
			if (lan_ifname[i][0] == '\0') {
				snprintf(out_val, out_sz, "%s%d", "br", i);
			} else {
				snprintf(out_val, out_sz, "%s", lan_ifname[i]);
			}
			dprintf("Info: rc: %d: %s %s\n", __LINE__, nv_ifname, out_val);
			return 0;
		}
	}

	cprintf("Err: rc: %s %s\n", __FUNCTION__, nv_ifname);

	return -1;
}

/* Callback fn to get the hw_mode from phytype nvram and band info. */
static int
hapd_phytype_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, os_ifname[IFNAMSIZ] = {0}, *phy_type;
	uint16 chanspec = 0;

	if (nvifname_to_osifname(nv_ifname, os_ifname, sizeof(os_ifname))) {
		dprintf("Err: rc: %d: converting %s to os name \n", __LINE__, nv_ifname);
		return -1;
	}

	if (wl_iovar_get(os_ifname, "chanspec", &chanspec, sizeof(chanspec)) < 0) {
		cprintf("Err: rc: %d: chanspec iovar cmd failed for %s\n", __LINE__, os_ifname);
		return -1;
	}

	if (!wf_chspec_valid(chanspec)) {
		cprintf("Err: rc: %d: invalid chanspec %x for %s\n", __LINE__, chanspec, os_ifname);
		return -1;
	}

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
	phy_type = nvram_safe_get(nv_name);

	if (CHSPEC_IS2G(chanspec)) {
		snprintf(out_val, out_sz, "%s", HAPD_HW_MODE_80211_G);
	} else if (CHSPEC_IS5G(chanspec) || strchr(phy_type, 'v') || strchr(phy_type, 'h') ||
			CHSPEC_IS6G(chanspec)) {
		snprintf(out_val, out_sz, "%s", HAPD_HW_MODE_80211_A);
	} else {
		cprintf("Err: rc: %d: invalid hw mode for %s\n", __LINE__, os_ifname);
		return -1;
	}

	return 0;
}

/* Callback funtion to get the channel info */
static int
hapd_channel_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	uint16 chanspec = 0x0;
	char os_ifname[IFNAMSIZ] = {0};

	if (nvifname_to_osifname(nv_ifname, os_ifname, sizeof(os_ifname))) {
		dprintf("Err: rc: %d: converting %s to os name \n", __LINE__, nv_ifname);
		return -1;
	}

	if (wl_iovar_get(os_ifname, cfg_arr_nvname, &chanspec, sizeof(chanspec)) < 0) {
		cprintf("Err: rc: %d: %s iovar cmd failed for %s\n",
				__LINE__, cfg_arr_nvname, os_ifname);
		return -1;
	}

	if (!wf_chspec_valid(chanspec)) {
		cprintf("Err: rc: %d invalid chanspec %x for %s\n", __LINE__, chanspec, os_ifname);
		return -1;
	}

	snprintf(out_val, out_sz, "%d", wf_chspec_ctlchan(chanspec));

	return 0;
}

/* Callback fn to get the auth_algs info. */
static int
hapd_auth_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	int auth_val;
	char nv_name[HAPD_MAX_BUF] = {0};

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
	auth_val = atoi(nvram_safe_get(nv_name));

	if (auth_val == 0) {
		snprintf(out_val, out_sz, "%d", HAPD_AUTH_OPEN_SYSTEM);
	} else if (auth_val == 1) {
		snprintf(out_val, out_sz, "%d", HAPD_AUTH_SHARED_KEY);
	}

	return 0;
}

/* Callback funtion to get the wep security info */
static int
hapd_wep_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, *wep = NULL;
	int ret = -1, def_key_index = 0;

	snprintf(nv_name, sizeof(nv_name), "%s_wep", nv_ifname);
	wep = nvram_safe_get(nv_name);

	if (!strcmp(wep, "enabled")) {
		/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
		snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
		def_key_index = atoi(nvram_safe_get(nv_name));
		if (def_key_index > 0) {
			snprintf(out_val, out_sz, "%d", def_key_index - 1);
		}
		ret = 0;
	} else {
			/* skip next 4 indexes key1 key2 key3 and key4 */
			ret = 4;
	}

	return ret;
}

/* Callback fn to get WEP keys. The keys can be 5 or 13 ASCII characters in which case they should
 * be enclosed in quotes in conf file or they can be unquoted hexadecimal number of 10 or 26 digits.
 */
static int
hapd_wep_key_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *wep_key = NULL;
	size_t length; /* key length */

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram. wlX_keyN, N = [1-4] */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	wep_key = nvram_safe_get(nv_name);

	if (wep_key[0] != '\0') {
		length = strlen(wep_key);

		switch (length)
		{
			case 5:
			case 13: /* ASCII characters -  Enclose in quotes */
				snprintf(out_val, out_sz, "\"%s\"", wep_key);
				break;
			case 10:
			case 26:
				if (hapd_wpasupp_hex_validate(wep_key)) {
					/* Unquoted hex digits */
					snprintf(out_val, out_sz, "%s", wep_key);
				}
				break;
			default:
				cprintf("Err: rc: %d: default: key len: %zu\n", __LINE__, length);
				break;
		}
	}

	return 0;
}

static int
hapd_fbt_mdid_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *mdid;
	uint16 mdie, swp_mdie;
	int fbt_enabled = 0;

	fbt_enabled = hapd_fbt_enabled(nv_ifname);

	if (!fbt_enabled) {
		//skip next 8 nvrams since mdid is accounted for
		return FBT_FIELDS_NUM - 1;
	}

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_fbt_mdid", nv_ifname);
	mdid = nvram_safe_get(nv_name);

	mdie = (uint16)atoi(mdid);

	/* swap the bytes in 2-octet mdie */
	swp_mdie = swap16(mdie);

	/* 2 octet MDID as hex string */
	snprintf(out_val, out_sz, "%04x", swp_mdie);

	return 0;
}

static int
hapd_r1kh_id_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *r1_key_holder;
	unsigned char ea[ETHER_ADDR_LEN];
	int err = 0;

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_r1kh_id", nv_ifname);
	r1_key_holder = nvram_safe_get(nv_name);

	if (r1_key_holder != NULL) {
		err = ether_atoe(r1_key_holder, ea);
		if (err < 0)
			return err;
	}
	snprintf(out_val, out_sz, "%02x%02x%02x%02x%02x%02x",
		ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);

	return 0;
}

static int
hapd_fbtap_r0kh_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char fbt_name[HAPD_MIN_BUF], tar_name[HAPD_MIN_BUF];
	char *fbt_aps, *next;
	char r0kh[HAPD_MAX_BUF * 4];
	int repeat = 0;
	char *fbt_r0_key, fbt_r0_hex_key[33];
	char *addr, *r0kh_id;

	/*
	 * Preparing the r0kh string
	 */
	snprintf(nv_name, sizeof(nv_name), "%s_fbt_aps", nv_ifname);
	fbt_aps = nvram_safe_get(nv_name);

	memset(fbt_name, 0, sizeof(fbt_name));
	memset(r0kh, 0, sizeof(r0kh));

	foreach(fbt_name, fbt_aps, next)
	{
		memset(tar_name, 0, sizeof(tar_name));
		memcpy(tar_name, fbt_name, sizeof(tar_name));
		memset(nv_name, 0, sizeof(nv_name));
		memset(fbt_r0_hex_key, 0, sizeof(fbt_r0_hex_key));
		/*
		 * r0kh
		 */
		snprintf(nv_name, sizeof(nv_name), "%s_addr", tar_name);
		if (nvram_safe_get(nv_name) == NULL) {
			continue;
		}

		snprintf(nv_name, sizeof(nv_name), "%s_addr", tar_name);
		addr = nvram_safe_get(nv_name);

		snprintf(nv_name, sizeof(nv_name), "%s_r0kh_id", tar_name);
		r0kh_id = nvram_safe_get(nv_name);

		snprintf(nv_name, sizeof(nv_name), "%s_r0kh_key", tar_name);
		fbt_r0_key = nvram_safe_get(nv_name);

		if (addr == NULL || r0kh_id == NULL || fbt_r0_key == NULL) {
			continue;
		}

		if (repeat != 0) {
			strcat(r0kh, "\nr0kh=");
		}

		strcat(r0kh, addr);
		strcat(r0kh, " ");
		strcat(r0kh, r0kh_id);
		strcat(r0kh, " ");
		snprintf(nv_name, sizeof(nv_name), "%s_r0kh_key", tar_name);

		if ((fbt_r0_key != NULL) && (strlen(fbt_r0_key) == 16)) {
			bytes_to_hex((uchar *) fbt_r0_key, strlen(fbt_r0_key),
					(uchar *) fbt_r0_hex_key, sizeof(fbt_r0_hex_key));
			strcat(r0kh, fbt_r0_hex_key);
		}
		repeat++;
	}

	snprintf(out_val, out_sz, "%s", r0kh);
	return 0;
}

static int
hapd_fbtap_r1kh_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char fbt_name[HAPD_MIN_BUF], tar_name[HAPD_MIN_BUF];
	char *fbt_aps, *next;
	char r1kh[HAPD_MAX_BUF * 4];
	int repeat = 0;
	char *fbt_r1_key, fbt_r1_hex_key[33];
	char *addr, *r1kh_id;

	/*
	 * Preparing the r1kh string
	 */
	snprintf(nv_name, sizeof(nv_name), "%s_fbt_aps", nv_ifname);
	fbt_aps = nvram_safe_get(nv_name);

	memset(fbt_name, 0, sizeof(fbt_name));
	memset(r1kh, 0, sizeof(r1kh));

	foreach(fbt_name, fbt_aps, next)
	{
		memset(tar_name, 0, sizeof(tar_name));
		memcpy(tar_name, fbt_name, sizeof(tar_name));
		memset(nv_name, 0, sizeof(nv_name));
		memset(fbt_r1_hex_key, 0, sizeof(fbt_r1_hex_key));
		/*
		 * r1kh
		 */
		snprintf(nv_name, sizeof(nv_name), "%s_addr", tar_name);
		addr = nvram_safe_get(nv_name);

		snprintf(nv_name, sizeof(nv_name), "%s_r1kh_id", tar_name);
		r1kh_id = nvram_safe_get(nv_name);

		snprintf(nv_name, sizeof(nv_name), "%s_r1kh_key", tar_name);
		fbt_r1_key = nvram_safe_get(nv_name);

		if (addr == NULL || r1kh_id == NULL || fbt_r1_key == NULL) {
			continue;
		}

		if (repeat) {
			strcat(r1kh, "\nr1kh=");
		}

		strcat(r1kh, addr);
		strcat(r1kh, " ");

		strcat(r1kh, r1kh_id);
		strcat(r1kh, " ");

		if ((fbt_r1_key != NULL) && (strlen(fbt_r1_key) == 16)) {
			bytes_to_hex((uchar *) fbt_r1_key, strlen(fbt_r1_key),
					(uchar *) fbt_r1_hex_key, sizeof(fbt_r1_hex_key));
			strcat(r1kh, fbt_r1_hex_key);
		}
		repeat++;
	}

	snprintf(out_val, out_sz, "%s", r1kh);

	return 0;
}

static int hapd_fbt_enabled(char *nv_ifname)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	int fbt = 0, fbt_ap = 0, wbd_fbt = 0;
	int fbt_enabled = 0;
	int map_mode = 0;
	char *ptr = NULL;

	map_mode = (int)strtol(nvram_safe_get("multiap_mode"), NULL, 0);

	if (map_mode > 0) {
		/* WBD enabled. FBT by WBD */
		snprintf(nv_name, sizeof(nv_name), "%s_wbd_fbt", nv_ifname);
		ptr  = nvram_safe_get(nv_name);
		if (ptr != NULL) {
			wbd_fbt = atoi(ptr);
		}
	}

	snprintf(nv_name, sizeof(nv_name), "%s_fbt", nv_ifname);
	ptr  = nvram_safe_get(nv_name);
	if (ptr != NULL) {
		fbt = atoi(ptr);
	}

	snprintf(nv_name, sizeof(nv_name), "%s_fbt_ap", nv_ifname);
	ptr = nvram_safe_get(nv_name);
	if (ptr != NULL) {
		fbt_ap = atoi(ptr);
	}

	if ((wbd_fbt || fbt) && fbt_ap) {
		fbt_enabled = 1;
	}

	return fbt_enabled;
}

static int wpa_supp_fbt_enabled(char *nv_ifname)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	int fbt = 0;
	char *ptr = NULL;

	snprintf(nv_name, sizeof(nv_name), "%s_fbt", nv_ifname);
	ptr  = nvram_safe_get(nv_name);
	if (ptr != NULL) {
		fbt = atoi(ptr);
	}

	return fbt;
}

static int hapd_wps_add_sae_enabled(char *nv_ifname)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	snprintf(nv_name, sizeof(nv_name), "%s_wps_cred_add_sae", nv_ifname);
	return nvram_match(nv_name, "1");
}

/* Helper fn to get key mgmt info */
static void
hapd_wpasupp_get_key_mgmt(char *nv_ifname, int fbt_enabled, int akm, char *key_mgmt)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	snprintf(nv_name, sizeof(nv_name), "%s_mfp", nv_ifname);
	bool mfp_required = nvram_match(nv_name, "2");
	bool mfp_capable = nvram_match(nv_name, "1");

        snprintf(nv_name, sizeof(nv_name),  "%s_mode", nv_ifname);
	bool ap_mode = nvram_match(nv_name, "ap");

	if (mfp_required) { /* MFP is REQUIRED */
		if (akm == HAPD_AKM_WPA || akm == HAPD_AKM_WPA2 ||
				(akm == (HAPD_AKM_WPA | HAPD_AKM_WPA2))) {
			/* wpa, wpa2 and mixed mode enterprise security */
			snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
				(fbt_enabled ? HAPD_KEY_MGMT_EAP_FT : HAPD_KEY_MGMT_EAP_SHA256));
		} else if (akm == HAPD_AKM_PSK || akm == HAPD_AKM_PSK2 ||
			(akm == (HAPD_AKM_PSK | HAPD_AKM_PSK2)) ||
			(akm == (HAPD_AKM_PSK2 | HAPD_AKM_PSK2_FT)) ||
			(akm == HAPD_AKM_PSK2_FT)) {
			/* wpa, wpa2 and mixed mode psk security */
			if (ap_mode) { /* AP mode */
				snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
						(fbt_enabled ? HAPD_KEY_MGMT_WPA_PSK_FT :
						 HAPD_KEY_MGMT_WPA_SHA256));
			} else { /*non AP mode */
				snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
						(fbt_enabled ? HAPD_KEY_MGMT_WPA_PSK_FT :
						 HAPD_KEY_MGMT_WPA_SHA256_PSK));
			}
		}
	} else {
		if (akm == HAPD_AKM_WPA || akm == HAPD_AKM_WPA2 ||
				(akm == (HAPD_AKM_WPA | HAPD_AKM_WPA2))) {
			/* wpa, wpa2 and mixed mode enterprise security */
			snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
				(fbt_enabled ? HAPD_KEY_MGMT_EAP_FT : HAPD_KEY_MGMT_EAP));
		} else if (akm == HAPD_AKM_PSK || akm == HAPD_AKM_PSK2 ||
				(akm == (HAPD_AKM_PSK | HAPD_AKM_PSK2)) ||
				(akm == (HAPD_AKM_PSK2 | HAPD_AKM_PSK2_FT)) ||
				(akm == HAPD_AKM_PSK2_FT)) {
			/* wpa, wpa2 and mixed mode psk security */
			if (ap_mode) { /* AP mode */
				snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
						(fbt_enabled ? HAPD_KEY_MGMT_WPA_PSK_FT : HAPD_KEY_MGMT_WPA));
			} else {
				snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
						(fbt_enabled ? HAPD_KEY_MGMT_WPA_PSK_FT : (mfp_capable ?
											   HAPD_KEY_MGMT_WPA_SHA256_PSK : HAPD_KEY_MGMT_WPA)));
			}
		} else if (akm == HAPD_AKM_WPA2_OSEN) {
			snprintf(key_mgmt, HAPD_MAX_BUF, "%s", HAPD_KEY_MGMT_OSEN);
		}
	}
	if (akm & HAPD_AKM_WPA3_SAE) {
		/* WPA3SAE */
		snprintf(key_mgmt, HAPD_MAX_BUF, "%s",
			((akm & HAPD_AKM_PSK2) ? (((akm & HAPD_AKM_PSK2_FT) && fbt_enabled) ?
			HAPD_KEY_MGMT_WPA_FT_PSK_SAE :
			(mfp_required ? HAPD_KEY_MGMT_WPA_SHA256_SAE : HAPD_KEY_MGMT_WPA_PSK_SAE)) :
			HAPD_KEY_MGMT_SAE));
		if (akm & HAPD_AKM_WPA3_SAE_FT) {
			/* Copy strlen(HAPD_KEY_MGMT_FT_SAE) + 2 to accomodate space and \0 */
			strncat(key_mgmt, " "HAPD_KEY_MGMT_FT_SAE,
					strlen(HAPD_KEY_MGMT_FT_SAE) + 2);
		}
	}
	if (akm == HAPD_AKM_WPA3_SAE_FT) {
		/* WPA3FTSAE */
		snprintf(key_mgmt, HAPD_MAX_BUF, "%s", HAPD_KEY_MGMT_FT_SAE);
	}
	if (akm & HAPD_AKM_WPA3_SUITE_B) {
		/* WPA3 SUITE-B overrides other combinations */
		snprintf(key_mgmt, HAPD_MAX_BUF, "%s", HAPD_KEY_MGMT_SUITE_B);
	}

	if (akm == HAPD_AKM_WPA3_DPP) {
		/* WPA3DPP */
		snprintf(key_mgmt, HAPD_MAX_BUF, "%s", HAPD_KEY_MGMT_DPP);
	}
	if (akm == HAPD_AKM_OWE) {
		/* OWE */
		snprintf(key_mgmt, HAPD_MAX_BUF, "%s", HAPD_KEY_MGMT_OWE);
	}
}

/* Common fn to validate and fill WPA pre-shared key for WPA-PSK for both hostapd and
 * wpa_supplicant in resepctive conf files. The key can be ASCII passhrase of 8..63 characters
 * (inclusive) or a 64 hex-digit PSK (of 32 bytes). In hostapd conf file,the placeholder is
 * "wpa_passphrase" for passphrase and "wpa_psk" for hex-digit PSK. In wpa_supplicant conf file,
 * the placeholder is same - "psk" for both passphrase and PSK but passphrase is quoted and
 * hex PSK is unquoted.
 * @param hapd: TRUE if called from hostapd context, FALSE for wpa_supplicant.
 */
static void
hapd_wpasupp_psk_key_hndlr(char *nv_name, char **placeholder, char *out_val, int out_sz, int flags, int akm)
{
	char *key = NULL;
	size_t length = 0;	// key length
	char tmp[256];
	bool hapd = flags & WPA_PSK_FLAG_IS_HAPD;
	key = nvram_safe_get(nv_name);

	if (key[0] != '\0') {
		length = strlen(key);

		*placeholder = "psk";
		if (flags & WPA_PSK_FLAG_IS_SAE_ONLY) {
			*placeholder = "sae_password";
			snprintf(out_val, out_sz, (hapd ? "%s": "\"%s\""), key);
		} else if ((length >= HAPD_PASSPH_MIN_LEN) && (length <= HAPD_PASSPH_MAX_LEN)) {
			/* ASCII passphrase */
			if(hapd && strcmp(*placeholder, "wpa_passphrase")) {
				*placeholder = "wpa_passphrase";
			}
			snprintf(out_val, out_sz, (hapd ? "%s": "\"%s\""), key);
		} else if (length == HAPD_WPA2_PSK_HEXLEN && hapd_wpasupp_hex_validate(key)) {
			/* 64 hex-digit PSK(of 32 bytes) */
			if (hapd) {
				switch (akm) {
					case HAPD_AKM_WPA3_SAE:
						*placeholder = "sae_password";
						break;
					case (HAPD_AKM_WPA3_SAE | HAPD_AKM_PSK2):
						*placeholder = "wpa_psk";
						snprintf(tmp, sizeof(tmp), "%s\n%s=%s", key, "sae_password", key);
						key = tmp;
						break;
					default:
						*placeholder = "wpa_psk";
				}
			}
			snprintf(out_val, out_sz, "%s", key);
		} else {
			cprintf("Err: rc: %d, Invalid key %s, length %zu\n", __LINE__, key, length);
		}
	} else {
		cprintf("Err: rc: %d, Empty key\n", __LINE__);
	}
}

static void
hapd_wpasupp_fill_pairwise(char *nv_ifname, char *cfg_arr_nvname, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	if (!nv_ifname || !cfg_arr_nvname || !out_val || (out_sz <= 0)) {
		dprintf("Err: rc: %d, wrong input\n", __LINE__);
		return;
	}

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	if (nvram_match(nv_name, "tkip")) {
		snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_TKIP);
	}
#ifdef CMWIFI_RDKB
	else if (strstr(nvram_safe_get(nv_name), "aes")) {
		snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
	}
#else /* CMWIFI_RDKB */
	else if (nvram_match(nv_name, "aes")) {
		snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
	} else if (nvram_match(nv_name, "tkip+aes") || nvram_match(nv_name, "aes+tkip")) {
		snprintf(out_val, out_sz, "%s %s", HAPD_CIPHER_SUITE_TKIP, HAPD_CIPHER_SUITE_CCMP);
	}
#endif /* CMWIFI_RDKB */
	else if (nvram_match(nv_name, "suite-b")) {
		snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_SUITE_B);
	}
	else {
		cprintf("Err: rc: %d: %s = '%s'\n", __LINE__, nv_name, nvram_safe_get(nv_name));
	}

}
/* Callback fn to fill key mgmt details */
static int
hapd_key_mgmt_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, key_mgmt[HAPD_MAX_BUF] = {0};
	int sae_require_mfp = 0;
	int akm = 0, ret = 0;
	bool psk_required;
	int fbt_enabled = 0;
	int wps_add_sae = 0;
	wlc_rev_info_t rev;

	hapd_wpasupp_get_security_details(nv_ifname, &akm);

	if (akm & HAPD_AKM_WPA3_SUITE_B) {
		memset(&rev, 0, sizeof(rev));
		wl_ioctl(nv_ifname, WLC_GET_REVINFO, &rev, sizeof(rev));
		if (rev.corerev < 130) {
			cprintf("Err: rc: %d: WPA3 SUITEB is not supported "
			"in corerev < 130 \n", __LINE__);
			return -1;
		}
	}
	psk_required = ((akm & HAPD_AKM_PSK2) || (akm & HAPD_AKM_PSK) ||
			(akm & HAPD_AKM_WPA3_SAE) || (akm & HAPD_AKM_WPA3_SAE_FT)) ? TRUE : FALSE;

	fbt_enabled = hapd_fbt_enabled(nv_ifname);

	wps_add_sae = hapd_wps_add_sae_enabled(nv_ifname);

	hapd_wpasupp_get_key_mgmt(nv_ifname, fbt_enabled, akm, key_mgmt);

	switch (akm) {
		/* open | wep security in both the cases wpa should be 0 */
		case HAPD_AKM_OPEN:
		case HAPD_AKM_WEP:
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_OPEN);
				if (wps_add_sae) {
					/* preserve SAE Fields, next is sae_require_mfp */
					ret = WPAX_FIELDS_NUM - 1;
				} else {
					// skip akm, crypto, wpa_psk, mfp plus SAE, FBT
					// and RADIUS fields.
					ret = WPAX_FIELDS_NUM + SAE_FIELDS_NUM + FBT_FIELDS_NUM
						  + RADIUS_FIELDS_NUM;
				}
			} else if (wps_add_sae && !strcmp(cfg_arr_nvname, "mfp")) {
				/* wps_add_sae is true, set sae_require_mfp */
				sae_require_mfp = 1;
				snprintf(out_val, out_sz, "%d", sae_require_mfp);
			}
			break;

		/* HAPD_SEC_WPA */
		case HAPD_AKM_PSK:
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz, WPA_PSK_FLAG_IS_HAPD, akm);

				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			break;

			/* WPA2PSK | WPA2PSK_FT */
		case HAPD_AKM_PSK2:
		case (HAPD_AKM_PSK2 | HAPD_AKM_PSK2_FT):
			if (!strcmp(cfg_arr_nvname, "wpa")) {
#ifdef CMWIFI_RDKB
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA2);
#else /* CMWIFI_RDKB */
				snprintf(nv_name, sizeof(nv_name), "%s_crypto", nv_ifname);
				// Set wpa based on crypto
				if (nvram_match(nv_name, "tkip+aes")) {
					snprintf(out_val, out_sz, "%d",
						(HAPD_SEC_WPA | HAPD_SEC_WPA2));
				} else if (nvram_match(nv_name, "aes")) {
					snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA2);
				}
#endif /* CMWIFI_RDKB */
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (psk_required &&
					!strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz, WPA_PSK_FLAG_IS_HAPD, akm);
				if (!wps_add_sae) {
					// skip SAE fields
					ret = SAE_FIELDS_NUM;
				}
			} else if (wps_add_sae && !strcmp(cfg_arr_nvname, "mfp")) {
				/* wps_add_sae is true, set sae_require_mfp */
				sae_require_mfp = 1;
				snprintf(out_val, out_sz, "%d", sae_require_mfp);
			}
			break;

		/* HAPD_SEC_WPA-HAPD_SEC_WPA2 */
		case (HAPD_AKM_PSK | HAPD_AKM_PSK2):
		case (HAPD_AKM_WPA | HAPD_AKM_WPA2):
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", (HAPD_SEC_WPA | HAPD_SEC_WPA2));
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz, WPA_PSK_FLAG_IS_HAPD, akm);
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			else if (!psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			break;

		case HAPD_AKM_WPA:
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz, WPA_PSK_FLAG_IS_HAPD, akm);
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			else if (!psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			break;

		case HAPD_AKM_WPA2:
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA2);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz, WPA_PSK_FLAG_IS_HAPD, akm);
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			else if (!psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			break;
		case HAPD_AKM_WPA3_SAE:
		case HAPD_AKM_WPA3_SAE_FT:
		case (HAPD_AKM_WPA3_SAE | HAPD_AKM_WPA3_SAE_FT):
		case (HAPD_AKM_WPA3_SAE | HAPD_AKM_PSK2):
		case (HAPD_AKM_WPA3_SAE | HAPD_AKM_PSK2 | HAPD_AKM_WPA3_SAE_FT):
		case (HAPD_AKM_WPA3_SAE | HAPD_AKM_PSK2 | HAPD_AKM_PSK2_FT):
		case (HAPD_AKM_WPA3_SAE | HAPD_AKM_PSK2 | HAPD_AKM_PSK2_FT | HAPD_AKM_WPA3_SAE_FT):
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA2);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				if (nvram_match(nv_name, "aes")) {
					snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
				} else {
					cprintf("Err: rc: %d: unsupported crypto for SAE\n",
							__LINE__);
				}
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (psk_required && !strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz,
						WPA_PSK_FLAG_IS_HAPD | ((akm == HAPD_AKM_WPA3_SAE) ?
						WPA_PSK_FLAG_IS_SAE_ONLY : 0), akm);
			} else if (!strcmp(cfg_arr_nvname, "mfp")) {
				/* Set sae_require_mfp to 1, irrespective of MFP nvram */
				sae_require_mfp = 1;
				snprintf(out_val, out_sz, "%d", sae_require_mfp);
			}
			break;
		case HAPD_AKM_WPA2_OSEN:
			/* MFP  FBT not valid for OSEN */
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_OPEN);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				if (nvram_match(nv_name, "aes")) {
					snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
				} else {
					cprintf("Err: %d, unsupported crypto for OSEN\n", __LINE__);
				}
			} else  if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			}
			break;
		case HAPD_AKM_WPA3_DPP:
		case HAPD_AKM_OWE:
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA2);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				if (!strcmp(nvram_safe_get(nv_name), "aes")) {
					snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
				}
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (!strcmp(cfg_arr_nvname, "mfp")) {
				// skip next SAE fields
				ret = SAE_FIELDS_NUM - 1;
			}
			break;
		case HAPD_AKM_WPA3_SUITE_B:
			if (!strcmp(cfg_arr_nvname, "wpa")) {
				snprintf(out_val, out_sz, "%d", HAPD_SEC_WPA2);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set wpa_pairwise based on crypto
				/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			}
			else if (!psk_required) {
				// skip SAE fields
				ret = SAE_FIELDS_NUM;
			}
			break;
		default:
			cprintf("Err: rc: %d: Invalid akm %d\n", __LINE__, akm);
			return -1;
	}; /* switch */

	if (out_val[0] == '\0' && !ret) {
		return -1;
	}

	return ret;
}

/* Callback fn to get fill pre-authentication capability */
static int
hapd_preauth_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *ptr;

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
	ptr = nvram_get(nv_name);

	/* Set preauth to disable, if it is explicitly disabled */
	if (ptr != NULL && (atoi(ptr) == 0)) {
		snprintf(out_val, out_sz, "%d", HAPD_DISABLE);
		return PREAUTH_FIELDS_NUM;
	} else {
		snprintf(out_val, out_sz, "%d", HAPD_ENABLE);
	}

	return 0;
}

static int
hapd_own_ip_addr_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val,
		int out_sz) {
	char *wan_ifname;
	int fd;
	struct ifreq ifr;

	/* default value */
	snprintf(out_val, out_sz, "%s", "127.0.0.1");

	/* Get IP addr of WAN port.
	 * If fails, still use default IP addr.
	 */
	wan_ifname = nvram_get("wan_ifname");
	if (wan_ifname && *wan_ifname != '\0') {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1) {
			cprintf("%s:%d fail to get ip addr of %s\n",
				__FUNCTION__, __LINE__, wan_ifname);
			return 0;
		}
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", wan_ifname);
		if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
			close(fd);
			cprintf("%s:%d fail to get ip addr of %s\n",
				__FUNCTION__, __LINE__, wan_ifname);
			return 0;
		}
		close(fd);
		snprintf(out_val, out_sz, "%s",
			inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	}
	return 0;
}

static int
hapd_preauth_interfaces_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *ptr;

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
	ptr = nvram_get(nv_name);

	/* Set preauth_interfaces to all bridge interfaces if enabled */
	if (ptr != NULL && (atoi(ptr) == 1)) {
		hapd_wpasupp_get_all_lanifname(out_val, out_sz);
	} else {
		snprintf(out_val, out_sz, "%s", "");
	}

	return 0;
}

/* Callback fn to get fill RADIUS details */
static int
hapd_radius_akm_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	/* string match successfull only with trailing space */
	if (nvram_match(nv_name, "wpa2") ||
		nvram_match(nv_name, "wpa2 ") ||	/* trailing space */
		nvram_match(nv_name, "wpa") ||
		nvram_match(nv_name, "wpa ")||		/* trailing space */
		nvram_match(nv_name, "wpa2 wpa") ||
		nvram_match(nv_name, "wpa wpa2") ||
		nvram_match(nv_name, "wpa2 wpa ") ||	/* trailing space */
		nvram_match(nv_name, "wpa wpa2 ") ||	/* trailing space */
		nvram_match(nv_name, "osen") ||
		nvram_match(nv_name, "suite-b") ||
		nvram_match(nv_name, "wpa2 suite-b")) {
		snprintf(out_val, out_sz, "%s", HAPD_IEEE8021X_SUPPORTED);
	} else {
		/* skip RADIUS settings */
		return RADIUS_FIELDS_NUM - 1;
	}

	return 0;
}

static int
hapd_secondary_radius_server_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *ptr = NULL;

	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
	ptr = nvram_get(nv_name);
	if (!ptr) {
		/* skip rest of secondary RADIUS server settings */
		return 2;
	} else {
		snprintf(out_val, out_sz, "%s", ptr);
	}

	return 0;
}

/* Callback funtion to get the wps state setting
 * lan_wps_oob/lan1_wps_oob = disabled => Configured
 * lan_wps_oob/lan1_wps_oob = enabled => Unconfigured
 * default nvram value is enabled
 */
static int
hapd_wpsstate_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char tmp[HAPD_MAX_BUF] = {0};
	char *lan_ifnames[HAPD_MAX_BRIDGE_NUM];
	uint8 wps_state = 0;
	char *wl_name;
	int i;

#if defined(MULTIAP)
	{
		uint16 map = 0, map_mode = 0;
		char *ptr = NULL;

		ptr = nvram_safe_get("multiap_mode");
		if (ptr[0] != '\0') {
			map_mode = (uint16)strtoul(ptr, NULL, 0);
		}

		ptr = nvram_safe_get(strcat_r(nv_ifname, "_map", tmp));
		if (ptr[0] != '\0') {
			map = (uint16)strtoul(ptr, NULL, 0);
		}
		/* wps should be disabled for multiap backhaul bss */
		if (map_mode != 0 && map == 2) {
			/* Skip remaining wps and multiap settings. */
			return (WPS_FIELDS_NUM + MAP_FIELDS_NUM - 1);
		}
	}
#endif	/* MULTIAP */

	if (hapd_wpasupp_is_wps_possible(nv_ifname) == FALSE) {
		/* Skip remaining wps settings. */
#if defined(MULTIAP)
		return (WPS_FIELDS_NUM + MAP_FIELDS_NUM - 1);
#else
		return (WPS_FIELDS_NUM - 1);
#endif	/* MULTIAP */
	}

	wl_name = nvram_safe_get(strcat_r(nv_ifname, "_ifname", tmp));

	for (i = 0; i < HAPD_MAX_BRIDGE_NUM; ++i) {
		if (i == 0) {
			snprintf(tmp, sizeof(tmp), "lan_ifnames");
		} else {
			snprintf(tmp, sizeof(tmp), "lan%d_ifnames", i);
		}

		lan_ifnames[i] = nvram_safe_get(tmp);

		if (find_in_list(lan_ifnames[i], wl_name)) {
			if (i == 0) {
				snprintf(tmp, sizeof(tmp), "lan_wps_oob");
			} else {
				snprintf(tmp, sizeof(tmp), "lan%d_wps_oob", i);
			}

			if (nvram_match(tmp, "disabled")) {
				wps_state = HAPD_WPS_CONFIGURED;
			} else {
				wps_state = HAPD_WPS_UNCONFIGURED;
			}
			break;
		}
	}

	snprintf(out_val, out_sz, "%d", wps_state);

	return 0;
}

/* Callback fn to fill wps ap lockdown field */
static int
hapd_wps_aplockdown_conv_fn(char *nv_ifname, char *name, char **ph, char *out_val, int out_sz)
{
	// If nvram wps_aplockdown is set to 1 or wps_wer_mode is deny than enable aplockdown
	if (nvram_match(name, "1") || nvram_match("wps_wer_mode", "deny")) {
		snprintf(out_val, out_sz, "%d", HAPD_ENABLE);
	}

	return 0;
}

/* Callback fn to fill wps uuid field */
static int
hapd_wpsuuid_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	const unsigned char dev_type[] = "urn:schemas-wifialliance-org:device:WFADevice";
	char *mac_str;
	unsigned char mac[6] = {0}, uuid[16] = {0};
	MD5_CTX md_context;

	mac_str = nvram_safe_get("lan_hwaddr");
	if (!ether_atoe(mac_str, mac)) {
		cprintf("Err: rc: %d ether_atoe failed for mac (%s) \n", __LINE__, mac_str);
		return -1;
	}

	/* Generate hash */
	MD5Init(&md_context);
	MD5Update(&md_context, mac, sizeof(mac));
	MD5Update(&md_context, dev_type, strlen((const char *)dev_type));
	MD5Final(uuid, &md_context);

	snprintf(out_val, out_sz, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		"%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);

	return 0;
}

/* Function to generate the wps device pin */
static int
hapd_wps_generate_device_pin(char *device_pin, int device_pin_len)
{
	unsigned long PIN;
	unsigned long int accum = 0;
	unsigned char rand_bytes[HAPD_WPS_DEVICE_PIN_LEN];
	int digit;
	char temp_pin[HAPD_WPS_DEVICE_PIN_LEN + 1];

	/* Generate random bytes and compute the checksum */
	RAND_bytes(rand_bytes, sizeof(rand_bytes));

	snprintf(temp_pin, sizeof(temp_pin), "%08u", *(uint32 *)rand_bytes);
	temp_pin[HAPD_WPS_DEVICE_PIN_LEN - 1] = '\0';
	PIN = strtoul(temp_pin, NULL, 10);

	PIN *= 10;
	accum += 3 * ((PIN / 10000000) % 10);
	accum += 1 * ((PIN / 1000000) % 10);
	accum += 3 * ((PIN / 100000) % 10);
	accum += 1 * ((PIN / 10000) % 10);
	accum += 3 * ((PIN / 1000) % 10);
	accum += 1 * ((PIN / 100) % 10);
	accum += 3 * ((PIN / 10) % 10);

	digit = (accum % 10);
	accum = (10 - digit) % 10;

	PIN += accum;
	snprintf(temp_pin, sizeof(temp_pin), "%08u", (unsigned int)PIN);
	temp_pin[HAPD_WPS_DEVICE_PIN_LEN] = '\0';

	/* Output result */
	WLIF_STRNCPY(device_pin, temp_pin, device_pin_len);

	return 0;
}

/* Callback fn to fill wps pin method field */
static int
hapd_wps_device_pin_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char *ptr;
	char wps_device_pin[HAPD_WPS_DEVICE_PIN_LEN +  2] = {0};

	ptr = nvram_safe_get(cfg_arr_nvname);

#if 0
	// If wps_device_pin nvram is not present or it contains default value
	// Than generate the pin and update the same in nvram.
	if (ptr[0] == '\0' || !strcmp(ptr, HAPD_WPS_DEVICE_PIN_DEFAULT_VAL)) {
		hapd_wps_generate_device_pin(wps_device_pin, sizeof(wps_device_pin));
		snprintf(out_val, out_sz, "%s", wps_device_pin);
		nvram_set(cfg_arr_nvname, wps_device_pin);
		nvram_commit();
		return 0;
	}
#endif

	snprintf(out_val, out_sz, "%s", ptr);

	return 0;
}

// Helper function to get the band type for wireless interface
static int
hapd_wps_get_band_type(char *ifname)
{
	int band_type = 0;

	wl_ioctl(ifname, WLC_GET_BAND, &band_type, sizeof(band_type));

	// If band type is auto than update band type from band list
	if (band_type == WLC_BAND_AUTO) {
		int list[3];	// list[0] is the count, values at index 1, 2 contains band type.
		int j;

		wl_ioctl(ifname, WLC_GET_BANDLIST, list, sizeof(list));
		if (list[0] > 2) {
			list[0] = 2;
		}
		band_type = 0;
		for (j = 0; j < list[0]; j++) {
			if (list[j] == WLC_BAND_5G || list[j] == WLC_BAND_2G) {
				band_type |= list[j];
			}
		}
	}

	dprintf("Info: rc: %d: ifname %s band type %d\n", __LINE__, ifname, band_type);

	return band_type;
}

/* Callback fn to fill the wps rf bands field */
static int
hapd_wps_rf_bands_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char ifname[IFNAMSIZ] = {0};
	char *next;
	char *ifnames_list;
	int ifnames_listsz = 0;
	int band_type = 0, device_band_type = 0;

	ifnames_listsz = hapd_wpasupp_get_all_lanifnames_listsz();
	if (ifnames_listsz == 0) {
		dprintf("Err: rc: %d: all lan ifnames are empty\n", __LINE__);
		return -1;
	}

	ifnames_list = (char *) calloc(1, ifnames_listsz);
	if (!ifnames_list) {
		cprintf("Info: rc: %d: calloc failed for %d bytes\n", __LINE__, ifnames_listsz);
		return -1;
	}

	hapd_wpasupp_get_all_lanifnames_list(ifnames_list, ifnames_listsz);

	// Traverse the list of interfaces in all lan ifnames
	foreach(ifname, ifnames_list, next) {
		// Skip non wireless interfaces
		if (wl_probe(ifname)) {
			dprintf("Info: rc: %d: skipping non wireless iface %s\n", __LINE__, ifname);
			continue;
		}

		// Get the band type for interface
		band_type = hapd_wps_get_band_type(ifname);

		// Aggregate the valid band type to get the device band type
		if (band_type != 0) {
			device_band_type |= band_type;
		}
	}

	switch (device_band_type) {
	case WLC_BAND_ALL:	// Dual band case
		snprintf(out_val, out_sz, "%s%s", HAPD_HW_MODE_80211_A, HAPD_HW_MODE_80211_G);
		break;
	case WLC_BAND_5G:	// 5G only
		snprintf(out_val, out_sz, "%s", HAPD_HW_MODE_80211_A);
		break;
	case WLC_BAND_2G:	// 2.4 G only
		snprintf(out_val, out_sz, "%s", HAPD_HW_MODE_80211_G);
		break;
	default:
		cprintf("Info rc: %d unknown device band type %d\n", __LINE__, device_band_type);
		break;

	}

	free(ifnames_list);

	return 0;
}

/* Callback fn to fill wps config method field */
static int
hapd_wpsconfig_method_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	uint16 config_methods = 0;
	char *ptr;

	ptr = nvram_safe_get(cfg_arr_nvname);

	if (ptr[0] == '\0') {
		if (nvram_match("wps_version2", "enabled")) {
			snprintf(out_val, out_sz, "display virtual_push_button "
				"physical_push_button push_button virtual_display");
		} else {
			snprintf(out_val, out_sz, "%s", "display push_button");
		}

		return 0;
	} else {
		config_methods = (uint16)strtoul(ptr, NULL, 16);

		if (HAPD_WPS_CONFIG_LABEL == (config_methods & HAPD_WPS_CONFIG_LABEL)) {
			strncat(out_val, "label ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_DISPLAY == (config_methods & HAPD_WPS_CONFIG_DISPLAY)) {
			strncat(out_val, "display ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_PBC == (config_methods & HAPD_WPS_CONFIG_PBC)) {
			strncat(out_val, "push_button ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_KEYPAD == (config_methods & HAPD_WPS_CONFIG_KEYPAD)) {
			strncat(out_val, "keypad ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_VPBC == (config_methods & HAPD_WPS_CONFIG_VPBC)) {
			strncat(out_val, "virtual_push_button ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_PHYPBC == (config_methods & HAPD_WPS_CONFIG_PHYPBC)) {
			strncat(out_val, "physical_push_button ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_VPIN == (config_methods & HAPD_WPS_CONFIG_VPIN)) {
			strncat(out_val, "virtual_display ", out_sz);
			out_sz -= strlen(out_val);
		}
		if (HAPD_WPS_CONFIG_PHYPIN == (config_methods & HAPD_WPS_CONFIG_PHYPIN)) {
			strncat(out_val, "physical_display ", out_sz);
			out_sz -= strlen(out_val);
		}

		if (!(config_methods &
			(HAPD_WPS_CONFIG_LABEL|HAPD_WPS_CONFIG_DISPLAY|
				HAPD_WPS_CONFIG_KEYPAD)))
			return 1; //skip wps_device_pin if no PIN method is enabled
		else
			return 0;
	}
}

#if defined(MULTIAP)
#define HAPD_MAP_FH_BSS			0x20
#define HAPD_MAP_BH_BSS			0x40
#define HAPD_MAP_BH_STA			0x80

// Nvram values for fronthaul, backhaul bss and backhaul sta
#define HAPD_MAP_FH_BSS_NVVAL		0x1	// Fronthaul BSS
#define HAPD_MAP_BH_BSS_NVVAL		0x2	// Backhaul BSS
#define HAPD_MAP_BH_STA_NVVAL		0x4	// Backhaul STA

#define IS_HAPD_MAP_FH_BSS(val)		(val & HAPD_MAP_FH_BSS_NVVAL)
#define IS_HAPD_MAP_BH_BSS(val)		(val & HAPD_MAP_BH_BSS_NVVAL)
#define IS_HAPD_MAP_BH_STA(val)		(val & HAPD_MAP_BH_STA_NVVAL)

/* Callback fn to fill the multiap attribute */
static int
hapd_map_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char tmp[HAPD_MIN_BUF] = {0}, *mode, *ptr = NULL;
	uint16 map_mode = 0, map = 0;
	uint16 val = 0;

	ptr = nvram_safe_get("multiap_mode");
	if (ptr[0] != '\0') {
		map_mode = (uint16)strtoul(ptr, NULL, 0);
	}

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(tmp, sizeof(tmp), "%s_%s", nv_ifname, cfg_arr_nvname);

	ptr = nvram_safe_get(tmp);
	if (ptr[0] != '\0') {
		map = (uint16)strtoul(ptr, NULL, 0);
	}

	if (!map_mode || !map) {
		return (MAP_FIELDS_NUM - 1);	/* Skip remaining multiap settings */
	}

	snprintf(tmp, sizeof(tmp), "%s_mode", nv_ifname);
	mode = nvram_safe_get(tmp);

	if ((IS_HAPD_MAP_FH_BSS(map) || IS_HAPD_MAP_BH_BSS(map)) && strcmp(mode, "ap")) {
		cprintf("Err: rc: %s Multi-AP Fronthaul or Backhaul AP setting (%d) "
			"on a non AP interface\n", __FUNCTION__, map);
		return (MAP_FIELDS_NUM - 1);	/* Skip remaining multiap settings */
	}

	if (IS_HAPD_MAP_FH_BSS(map)) {
		val |= HAPD_MAP_FH_BSS;
	}

	if (IS_HAPD_MAP_BH_BSS(map)) {
		val |= HAPD_MAP_BH_BSS;
	}

	if (val) {
		snprintf(out_val, out_sz, "%d", val);
	} else {
		cprintf("Err: rc: %d Multi-AP Unsupported setting\n", __LINE__);
		return (MAP_FIELDS_NUM - 1);
	}

	return 0;
}

/* Callback fn to fill multiap backhaul settings to be used by wps in hostapd */
static int
hapd_wpsmap_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	uint16 map = 0;
	char *ptr, *next, tmp[HAPD_MIN_BUF] = {0}, prefix[IFNAMSIZ] = {0};
	char *val = NULL, ifname[IFNAMSIZ];
	int akm = 0, auth = 0, encr = 0;

	ptr = nvram_safe_get("wbd_ifnames");
	foreach(ifname, ptr, next) {
		if (osifname_to_nvifname(ifname, prefix, sizeof(prefix))) {
			continue;
		}
		snprintf(tmp, sizeof(tmp), "%s_map", prefix);
		val = nvram_safe_get(tmp);
		if (val[0] != '\0') {
			map = (uint16)strtoul(val, NULL, 0);
		}
		if (IS_HAPD_MAP_BH_BSS(map)) {
			break;
		}
	} /* foreach */

	if (prefix[0] == '\0') {
		return 3;	// skip map related backhaul settings.
	}

	hapd_wpasupp_get_security_details(prefix, &akm);

	switch (akm) {
		case HAPD_AKM_PSK:
			auth = HAPD_WPS_AUTH_WPAPSK;
			break;
		/* Multiap backhaul can be operating on sae, psk2+sae or psk2 */
		case HAPD_AKM_WPA3_SAE:
		case HAPD_AKM_PSK2 | HAPD_AKM_WPA3_SAE:
		case HAPD_AKM_PSK2:
			auth = HAPD_WPS_AUTH_WPA2PSK;
			break;
		case HAPD_AKM_PSK | HAPD_AKM_PSK2:
			auth = HAPD_WPS_AUTH_WPAPSK | HAPD_WPS_AUTH_WPA2PSK;
			break;
		case HAPD_AKM_OPEN:
			auth = HAPD_WPS_AUTH_OPEN;
			break;
		default:
			cprintf("Err: rc: %d Multi-AP unsupported auth value %d "
				"for backhaul settings \n", __LINE__, akm);
			return 3;	/* Skip remaining multiap settings */
	} /* switch */

	if (!strcmp(cfg_arr_nvname, "bh_ssid")) {
		snprintf(tmp, sizeof(tmp), "%s_ssid", prefix);
		snprintf(out_val, out_sz, "%s", nvram_safe_get(tmp));
	} else if (!strcmp(cfg_arr_nvname, "bh_akm")) {
		snprintf(out_val, out_sz, "%d", auth);
	} else if (!strcmp(cfg_arr_nvname, "bh_crypto")) {
		/* For sae and sae transition mode encr must be aes */
		if (akm & HAPD_AKM_WPA3_SAE) {
			encr = HAPD_WPS_ENCR_AES;
		} else {
			char *crypto;

			snprintf(tmp, sizeof(tmp), "%s_crypto", prefix);
			crypto = nvram_safe_get(tmp);
			if (auth == HAPD_WPS_AUTH_OPEN) {
				encr = HAPD_WPS_ENCR_NONE;
			} else {
				if (!strcmp(crypto, "aes")) {
					encr = HAPD_WPS_ENCR_AES;
				} else if (!strcmp(crypto, "tkip")) {
					encr = HAPD_WPS_ENCR_TKIP;
				} else if (!strcmp(crypto, "tkip+aes")) {
					encr = HAPD_WPS_ENCR_TKIP | HAPD_WPS_ENCR_AES;
				}
			}
		}

		snprintf(out_val, out_sz, "%d", encr);
	} else if (!strcmp(cfg_arr_nvname, "bh_psk")) {
		char *psk;
		snprintf(tmp, sizeof(tmp), "%s_wpa_psk", prefix);
		psk = nvram_safe_get(tmp);
		if (psk[0] != '\0') {
			snprintf(out_val, out_sz, "%s", psk);
		} else {
			return -1;
		}
	} else {
		return -1;
	}

	return 0;
}

/* Callback fn to fill multiap backhaul sta attribute to be used by wps in wpa supplicant */
static int
wpa_supp_map_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	char tmp[HAPD_MIN_BUF] = {0}, *ptr = NULL;
	uint16 map_mode = 0, map = 0;

	ptr = nvram_safe_get("multiap_mode");
	if (ptr[0] != '\0') {
		map_mode = (uint16)strtoul(ptr, NULL, 0);
	}

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(tmp, sizeof(tmp), "%s_%s", nv_ifname, cfg_arr_nvname);

	ptr = nvram_safe_get(tmp);
	if (ptr[0] != '\0') {
		map = (uint16)strtoul(ptr, NULL, 0);
	}

	if (!map_mode || !map) {
		*out_val = '\0';
		return 0;
	}

	if (IS_HAPD_MAP_BH_STA(map)) {
		snprintf(out_val, out_sz, "1");
	} else {
		return -1;
	}

	return 0;
}

#endif	/* MULTIAP */

/* Helper function to check whether any AP bssid is provided for sta to join */
static bool
wpa_supp_is_join_bssid_available(char *nv_ifname)
{

	char tmp[HAPD_MIN_BUF] = {0}, *ptr = NULL;
	unsigned char bssid[ETHER_ADDR_LEN] = {0};

	snprintf(tmp, sizeof(tmp), "%s_bssid", nv_ifname);
	ptr = nvram_safe_get(tmp);
	if (strlen(ptr) < 17 || !ether_atoe(ptr, bssid)) {
		dprintf("Err: rc: %d: ifname[%s] NVRAM[%s=%s].No valid BSSID\n",
				__LINE__, nv_ifname, tmp, ptr);
		return FALSE;
	}

	return TRUE;
}

/* Callback fn to fill dpp_connector attribute to be used by sta */
static int
wpa_supp_dpp_connector_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);

	/* If akm is not DPP, skip DPP specific fields */
	if (!nvram_match(nv_name, "dpp")) {
		return DPP_FIELDS_NUM - 1;
	}

	memset(nv_name, 0, sizeof(nv_name));
	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);
	snprintf(out_val, out_sz, "\"%s\"", nvram_safe_get(nv_name));

	return 0;
}
/* Callback fn to fill osen authentication */
static int
hapd_osen_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	if (nvram_match(nv_name, "osen")) {
		snprintf(out_val, out_sz, "%d", HAPD_ENABLE);
	} else {
		snprintf(out_val, out_sz, "%d", HAPD_DISABLE);
	}

	return 0;
}

static int
hapd_dgaf_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	char *ptr;

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	ptr = nvram_get_bitflag(nv_name, HSFLG_DGAF_DS);

	if (ptr != NULL && atoi(ptr)) {
		snprintf(out_val, out_sz, "%d", HAPD_ENABLE);
	} else {
		snprintf(out_val, out_sz, "%d", HAPD_DISABLE);
	}

	return 0;
}

static int
hapd_mfp_cipher_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	int akm = 0;

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	hapd_wpasupp_get_security_details(nv_ifname, &akm);

	if (nvram_match(nv_name, "2")) {
		if (akm & HAPD_AKM_WPA3_SUITE_B) {
			snprintf(out_val, out_sz, "%s", "BIP-GMAC-256");
		} else {
			snprintf(out_val, out_sz, "%s", "AES-128-CMAC");
		}
	}

	return 0;
}
/* Callback fn to fill mfp parameters */
static int
hapd_mfp_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};
	int akm = 0;

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	hapd_wpasupp_get_security_details(nv_ifname, &akm);

	if (akm & (HAPD_AKM_WPA3_SAE | HAPD_AKM_WPA3_SAE_FT | HAPD_AKM_WPA3_DPP | HAPD_AKM_OWE)) {
		if (akm & (HAPD_AKM_WEP | HAPD_AKM_PSK)) {
			/* Do not allow SAE combination with these modes */
			dprintf("Err: rc: %d: wrong akm setting for %s\n", __LINE__, nv_ifname);
			return -1;
		}
		if ((akm & HAPD_AKM_PSK2) && !nvram_match(nv_name, "2")) {
			/* In mixed SAE case, set MFP to be capable,
			 * if MFP is not set to required.
			 */
			snprintf(out_val, out_sz, "%d", HAPD_MFP_CAP);
			return 0;
		}
		/* In other cases, MFP should be required */
		snprintf(out_val, out_sz, "%d", HAPD_MFP_REQ);
		return 0;
	}
	/* In case of pure WPA-PSK/WPA-Enterprise, MFP should be disabled */
	if (akm & (HAPD_AKM_PSK | HAPD_AKM_WPA)) {
		snprintf(out_val, out_sz, "%d", HAPD_MFP_OFF);
		return 0;
	}

	if (akm == HAPD_AKM_OPEN || akm == HAPD_AKM_WEP) {
		/* wps_cred_add_sae: do not add ieee80211w for open/wep */
		return -1;
	}

	if (nvram_match(nv_name, "0")) {
		snprintf(out_val, out_sz, "%d", HAPD_MFP_OFF);
	} else if (nvram_match(nv_name, "2")) {
		snprintf(out_val, out_sz, "%d", HAPD_MFP_REQ);
	} else { /* PMF Capable by default */
		snprintf(out_val, out_sz, "%d", HAPD_MFP_CAP);
	}

	return 0;
}

/* Callback fn to fill wmm parameters */
static int
hapd_wmmconfig_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	if (nvram_match(nv_name, "1")) {
		snprintf(out_val, out_sz, "%s", HAPD_UNSUPPORTED);
	} else {
		snprintf(out_val, out_sz, "%s", HAPD_SUPPORTED);
	}

	return 0;
}

/* Callback fn to fill dpp specific parameters */
static int
hapd_dpp_connector_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);

	/* If akm is not DPP, skip DPP specific fields */
	if (!nvram_match(nv_name, "dpp")) {
		return DPP_FIELDS_NUM - 1;
	}

	memset(nv_name, 0, sizeof(nv_name));

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", nvram_safe_get(nv_name));

	return 0;
}

/* Callback fn to fill owe specific parameters */
static int
hapd_owe_groups_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);

	/* If akm is not OWE, skip OWE specific fields */
	if (!nvram_match(nv_name, "owe")) {
		return OWE_FIELDS_NUM - 1;
	}

	memset(nv_name, 0, sizeof(nv_name));

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", nvram_safe_get(nv_name));

	return 0;
}

/* Callback fn to fill owe transition ifname */
static int
hapd_owe_trans_ifname_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph,
		char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0};

	/* build interface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", nv_ifname, cfg_arr_nvname);

	/* If owe_transition_ifname is not set */
	if (nvram_match(nv_name, "")) {
		/* Do not add owe_transition_ifname */
		return -1;
	}

	snprintf(out_val, out_sz, "%s", nvram_safe_get(nv_name));

	return 0;
}

/* Callback fn to fill dtim period */
static int
hapd_dtim_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, wl_pri_ifname[IFNAMSIZ] = {0};

	/* dtim is per radio setting.Get primary ifname from nv_ifname to build nvram */
	if (hapd_wpasupp_get_primary_ifce(nv_ifname, wl_pri_ifname, sizeof(wl_pri_ifname)) < 0) {
		dprintf("Err: rc: %d: fetching primary iface name for %s\n", __LINE__, nv_ifname);
		return -1;
	}

	 /* build primary iface specific nvram - wlX_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", wl_pri_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", nvram_safe_get(nv_name));

	return 0;
}

/* Callback fn to fill beacon interval */
static int
hapd_bi_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{

	char nv_name[HAPD_MAX_BUF] = {0}, wl_pri_ifname[IFNAMSIZ] = {0};

	/* Bcn interval is per radio setting. Get primary ifname from nv_ifname to build nvram */
	if (hapd_wpasupp_get_primary_ifce(nv_ifname, wl_pri_ifname, sizeof(wl_pri_ifname)) < 0) {
		dprintf("Err: rc: %d: fetching primary iface name for %s\n", __LINE__, nv_ifname);
		return -1;
	}

	/* build primary iface specific nvram - wlX_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", wl_pri_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", nvram_safe_get(nv_name));

	return 0;
}

/* Callback fn to fill country code - mandatory for 11d */
static int
hapd_cc_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, wl_pri_ifname[IFNAMSIZ] = {0};

	/* Country code is per radio setting. Get primary ifname from nv_ifname to build nvram */
	if (hapd_wpasupp_get_primary_ifce(nv_ifname, wl_pri_ifname, sizeof(wl_pri_ifname)) < 0) {
		dprintf("Err: rc: %d: fetching primary iface name for %s\n", __LINE__, nv_ifname);
		return -1;
	}

	 /* build primary iface speific nvram - wlX_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", wl_pri_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", nvram_safe_get(nv_name));

	return 0;
}

/* Callback fn to fill 11d parameters */
static int
hapd_11d_conv_fn(char *nv_ifname, char *cfg_arr_nvname, char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, wl_pri_ifname[IFNAMSIZ] = {0};

	/* 11d is per radio setting. Get primary ifname from nv_ifname to build nvram */
	if (hapd_wpasupp_get_primary_ifce(nv_ifname, wl_pri_ifname, sizeof(wl_pri_ifname)) < 0) {
		dprintf("Err: rc: %d: fetching primary iface name for %s\n", __LINE__, nv_ifname);
		return -1;
	}

	/* build primary iface specific nvram - wlX_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", wl_pri_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", HAPD_SUPPORTED);

	return 0;
}

/* Callback fn to fill 11h parameters */
static int
hapd_11h_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, wl_pri_ifname[IFNAMSIZ] = {0};

	/* 11h is per radio setting. Get primary ifname from nv_ifname to build nvram */
	if (hapd_wpasupp_get_primary_ifce(nv_ifname, wl_pri_ifname, sizeof(wl_pri_ifname)) < 0) {
		dprintf("Err: rc: %d: fetching primary iface name for %s\n", __LINE__, nv_ifname);
		return -1;
	}

	/* build  primary iface specific nvram - wlX_nvram */
	snprintf(nv_name, sizeof(nv_name), "%s_%s", wl_pri_ifname, cfg_arr_nvname);

	snprintf(out_val, out_sz, "%s", HAPD_SUPPORTED);

	return 0;
}

/* Settings deferred flag skips particular setting to config file */
static void
hapd_wpasupp_set_deferred(int cur_pos, int count)
{
	int idx = 0;
	while (cfg_arr[cur_pos + idx].nv_name != NULL && idx < count) {
		cfg_arr[cur_pos + idx].flags |= HAPD_CFG_DEFER;
		idx++;
	}
}

/* Fills the nvram settings to the config file */
static void
hapd_fill_nvrams_to_config_file(FILE *fp, char *nv_ifname, uint32 flags)
{
	int idx, buflen;
	char *buf;
	char **ph;
	char nvram_name[HAPD_MAX_BUF] = {0};

	buflen = HAPD_MAX_BUF * 8;
	buf = calloc(1, buflen);
	if (!buf) {
		cprintf("Err: rc: %d: failed to allocate memory of size %d\n", __LINE__, buflen);
		return;
	}

	for (idx = 0; cfg_arr[idx].nv_name != NULL; idx++) {
		ph = &(cfg_arr[idx].placeholder);
		char *val = NULL, *val2 = NULL, cb_out[HAPD_MAX_BUF] = {0};
		if (!(cfg_arr[idx].flags & flags)) {
			continue;
		}
		// If defer flag is set, first clear it than continue.
		if (cfg_arr[idx].flags & HAPD_CFG_DEFER) {
			cfg_arr[idx].flags &= (~HAPD_CFG_DEFER);
			continue;
		}
		if (cfg_arr[idx].flags & HAPD_CFG_USEDEFAULT) {
			val = cfg_arr[idx].def_val;
		} else {
			int len = 0;
			 // If large buf is set allocate dynamic memory.
			if (cfg_arr[idx].flags & HAPD_CFG_LRG_BUF) {
				val2 = (char *) malloc((8 * (sizeof(char)) * HAPD_MAX_BUF));
				if (val2 != NULL) {
					memset(val2, 0, 8 * HAPD_MAX_BUF);
					len = 8 * HAPD_MAX_BUF;
					val = val2;
				}
			} else {
				val = cb_out;
				len = sizeof(cb_out);
			}
			cfg_arr[idx].flags &= (~HAPD_CFG_DEFER);
			if (cfg_arr[idx].cb_fn != NULL) {
				/* ph repalced with "wpa_psk" in key_hndlr() fn if key is PSK. */
				int ret = cfg_arr[idx].cb_fn(nv_ifname, cfg_arr[idx].nv_name,
						ph, val, len);
			       if (ret < 0) {
					cprintf("Err: rc: %d: conversion fn returned err"
						" for %s in iface %s\n", __LINE__,
						cfg_arr[idx].nv_name, nv_ifname);
					goto free_mem;
				}
				// A +ve means we need to set the defered flags for next ret vals
				if (ret > 0) {
					hapd_wpasupp_set_deferred(idx + 1, ret);
				}
			} else {
				if (cfg_arr[idx].flags & HAPD_CFG_PERBSS) {
					snprintf(nvram_name, sizeof(nvram_name), "%s_%s",
						nv_ifname, cfg_arr[idx].nv_name);
				} else {
					snprintf(nvram_name, sizeof(nvram_name), "%s",
						cfg_arr[idx].nv_name);
				}
				val = nvram_safe_get(nvram_name);

				if (val[0] == '\0') {
					// Use default value if not exist in nvram
					val = cfg_arr[idx].def_val;
				}
			}
		}

		if (val[0] == '\0') {
			goto free_mem;
		}

		memset(buf, 0, buflen);

		snprintf(buf, buflen, "%s=%s\n", *ph, val);

		/* Explicitly terminate the buffer with '\n\0' */
		buf[buflen - 2] = '\n';
		buf[buflen - 1] = '\0';

		fprintf(fp, "%s",  buf);
free_mem:
		if (val2) {
			free(val2);
		}
	} /* for */

	free(buf);
}

/* Append the fixed settings to the config file */
static void
hapd_fixed_strs_to_config_file(FILE *fp)
{
	fprintf(fp, "## General configurations\n");
	fprintf(fp, "driver=nl80211\n");
	fprintf(fp, "ctrl_interface_group=0\n");
}

/* File filename and flags based on the interface name */
int
hapd_get_config_filename(char *nv_ifname, char *out_filename, int size, uint32 *out_flags, int mode)
{
	int unit = -1, subunit = -1;
	uint32 flags = HAPD_CFG_IFR;

	if (get_ifname_unit(nv_ifname, &unit, &subunit)) {
		dprintf("Err: rc: %d: get_ifname_unit %s \n", __LINE__, nv_ifname);
		return -1;
	}

	if (unit >= MAX_RADIO_NUM) {
		dprintf("Err: rc: %d: invalid radio unit %d, MAX_RADIO_NUM is %d \n",
				__LINE__, unit, MAX_RADIO_NUM);
		return -1;
	}

	if (subunit > 0 && mode == HAPD_ON_PRIMARY_IFACE) {
		flags = HAPD_CFG_BSS;
	}

	if (subunit > 0 && mode != HAPD_ON_PRIMARY_IFACE) { /* repeater mode */
		if (radio_params_set[unit] == FALSE) { /* radio params not set initially */
			/*  hostapd.conf file of the form - wlX.Y_hapd.conf */
			snprintf(out_filename, size, "%s/wl%d.%d_%s",
				HAPD_FILE_DIR, unit, subunit, HAPD_FILENAME_SUFFIX);

			/* Set flags to fill the radio params - interface, hw_mode, channel,
			 * only for the first virtual interface in the virtual iflist while
			 * populating hostapd.conf file.
			 */
			flags = HAPD_CFG_IFR;
			radio_params_set[unit] = TRUE;
		} else {
			flags = HAPD_CFG_BSS;
		}

	} else {
		snprintf(out_filename, size, "%s/wl%d_%s",
			HAPD_FILE_DIR, unit, HAPD_FILENAME_SUFFIX);
	}

	if (out_flags != NULL) {
		*out_flags = flags;
	}

	return 0;
}

/* Creates the hostapd config file for nv_ifname */
int
hapd_create_config_file(char *nv_ifname, char *filename, uint32 flags)
{
	char *mode = "w";
	FILE *fp = NULL;

	if (flags == HAPD_CFG_BSS) {
		mode = "a";
	}

	fp = fopen(filename, mode);
	if (fp == NULL) {
		cprintf("Err: rc: %d: failed to open the file %s \n", __LINE__, filename);
		return -1;
	}

	if (flags & HAPD_CFG_IFR) {
		hapd_fixed_strs_to_config_file(fp);
	}

	if (flags & HAPD_CFG_IFR) {
		fprintf(fp, "## Interface configurations\n");
	} else if (flags & HAPD_CFG_BSS) {
		fprintf(fp, "## BSS configurations\n");
	}

	hapd_fill_nvrams_to_config_file(fp, nv_ifname, flags);

	fclose(fp);

	return 0;
}

/* Pass an ifce (primary/virtual/WDS) of the form wlX/wlX.Y/wdsX.Y.Z to get corresponding
 * primary ifce wlX.
 */
static int
hapd_wpasupp_get_primary_ifce(char *nv_ifname, char *wl_pri_ifname, int sz)
{
	int unit = -1;
	char wl_ifname[IFNAMSIZ] = {0};

	if (!nv_ifname || !wl_pri_ifname) {
		dprintf("Err: rc: %d: Empty buffer\n", __LINE__);
		return -1;
	}

	if (get_ifname_unit(nv_ifname, &unit, NULL) < 0) {
		dprintf("Err: rc: %d: get_ifname_unit %s\n", __LINE__, nv_ifname);
		return -1;
	}

	if (*ifname_arr[unit] == '\0') {
		snprintf(wl_ifname, sizeof(wl_ifname), "wl%d", unit);
		memcpy(ifname_arr[unit], wl_ifname, sizeof(wl_ifname));
		ifname_arr[unit][sizeof(wl_ifname) - 1] = '\0';
	}

	memset(wl_pri_ifname, 0, sz);

	strncpy(wl_pri_ifname, ifname_arr[unit], MIN(IFNAMSIZ, sz) -  1);
	wl_pri_ifname[MIN(IFNAMSIZ, sz) - 1] = '\0';

	return 0;
}

/* Check if interface is primary or not */
static bool
hapd_wpasupp_is_primary_ifce(const char *ifname)
{
	int unit = -1, subunit = -1;
	char nv_ifname[IFNAMSIZ] = {0};

	if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
		dprintf("Err: rc: %d: converting os ifname %s to nv ifname\n", __LINE__, ifname);
		return FALSE;
	}

	if (get_ifname_unit(nv_ifname, &unit, &subunit) < 0) {
		dprintf("Err: rc: %d: get_ifname_unit %s\n", __LINE__, nv_ifname);
		return FALSE;
	}

	if (subunit > 0) {
		dprintf("Err: rc: %d: Non primary interface %s\n", __LINE__, nv_ifname);
		return FALSE;
	}

	return TRUE;
}

static bool
hapd_wpasupp_is_bss_enabled(const char* ifname)
{
	char nv_ifname[IFNAMSIZ] = {0};
	char nvram_name[HAPD_MAX_BUF] = {0};
	bool ret = FALSE;

	if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
		dprintf("Err: rc: %d: converting os ifname %s to nv ifname\n", __LINE__, ifname);
		return -1;
	}

	snprintf(nvram_name, sizeof(nvram_name),  "%s_bss_enabled", nv_ifname);

	ret =  nvram_match(nvram_name, "1");

	return ret;
}

/* Given a list of ifnames, the fn returns two lists - one containing primary radio ifces
 * and other containing secondary (virtual) ifces.
 */
static void
hapd_wpasupp_get_primary_virtual_iflist(char *filtered_list,
	char *pr_iflist, char *sec_iflist, int listsz)
{
	char ifname[IFNAMSIZ] = {0}, *next;

	foreach(ifname, filtered_list, next) {
		((hapd_wpasupp_is_primary_ifce(ifname) == TRUE) ?
			add_to_list(ifname, pr_iflist, listsz) :
			add_to_list(ifname, sec_iflist, listsz));
	}
}

/* Given a list of ifnames, the fn returns a filtered list of wireless interfaces on
 * which BSS is enabled.
 */
static void
hapd_wpasupp_get_filtered_ifnames_list(char *ifnames_list, char *filtered_list, int flist_sz)
{
	char pr_ifname[IFNAMSIZ+1] = {0}; /* primary ifname */
	char ifname[IFNAMSIZ] = {0}, tmp_list[HAPD_MAX_BUF] = {0};
	char *next;

	foreach(ifname, ifnames_list, next) {
		if (!wl_probe(ifname)) { /* only wireless interfaces */
			if (hapd_wpasupp_is_primary_ifce(ifname) == TRUE) {
				/* copy primary BSS ifname */
				strncpy(pr_ifname, ifname, IFNAMSIZ);
			} else { /* add all vritual BSS' to temporary list */
				add_to_list(ifname, tmp_list, HAPD_MAX_BUF);
			}
		}
	}

	/* if BSS on primary ifce is enabled, add it to filtered list */
	if (hapd_wpasupp_is_bss_enabled(pr_ifname)) {
		add_to_list(pr_ifname, filtered_list, flist_sz);
	}

	/* Check virtual BSS'. If any of the virtual BSS' enabled, then, blindly
	 * add the primary BSS to the filtered list even if it is not enabled.
	 */
	foreach(ifname, tmp_list, next) {
		if (hapd_wpasupp_is_bss_enabled(ifname)) {
			add_to_list(ifname, filtered_list, flist_sz);
		}
	}
}

/* Fn to check if the string (without 0x prefix) represents a
 * hexadecimal number. Returns TRUE for valid hex number.
 */
static bool
hapd_wpasupp_hex_validate(const char *s)
{
	int i;

	for  (i = 0; i < strlen(s); i++) {
		if (!isxdigit(s[i]))
			break;
	}

	return (i < strlen(s) ? FALSE : TRUE);
}

static bool
hapd_wpasupp_is_ifce_ap(const char *ifname)
{
	char nv_ifname[IFNAMSIZ] = {0}, nvram_name[HAPD_MAX_BUF] = {0};
	bool ret = FALSE;

	if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
		dprintf("Err: rc: %d: converting os ifname %s to nv ifname\n", __LINE__, ifname);
		return -1;
	}

	snprintf(nvram_name, sizeof(nvram_name),  "%s_mode", nv_ifname);

	ret = nvram_match(nvram_name, "ap");

	return ret;
}

static bool
hapd_wpasupp_is_ifce_monitormode(const char *ifname)
{
	char nv_ifname[IFNAMSIZ] = {0}, nvram_name[HAPD_MAX_BUF] = {0};
	bool ret = FALSE;

	if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
		dprintf("Err: rc: %d: converting os ifname %s to nv ifname\n", __LINE__, ifname);
		return -1;
	}

	snprintf(nvram_name, sizeof(nvram_name),  "%s_mode", nv_ifname);
	ret = nvram_match(nvram_name, "monitor");
	return ret;
}

/* Starts the hostapd.
 * If AP, run hostapd on all fileterd interfaces (ethX, wlX.Y...)
 * If non-AP/repeater, run hostapd on secondary/virtual ifce (wlX.Y).
 */
static int
start_hostapd(char *filtered_iflist, char *primary_iflist, char *virtual_iflist)
{
	uint32 flags = 0;
	int mode = HAPD_ON_PRIMARY_IFACE;
	char filename[HAPD_MAX_BUF] = {0}, cmd[HAPD_MAX_BUF * 4] = {0};
	char ifname[IFNAMSIZ] = {0};
	char nv_ifname[IFNAMSIZ] = {0}; /* wlX, wlX.Y */
	char *next, *filelist;
	char *ifnames_list = filtered_iflist; /* if AP, run hostapd on primary ifces */
	int listsz = HAPD_MAX_BUF * 4, usedsz = 0, num_primary = 0;
	char nv_name[HAPD_MIN_BUF] = {0};

	if (!filtered_iflist) {
		cprintf("Err: rc: %d: empty filtered iface list\n", __LINE__);
		return -1;
	}

	filelist = (char *)calloc(1, listsz);
	if (!filelist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		return -1;
	}

	foreach(ifname, primary_iflist, next) {
		if (hapd_wpasupp_is_ifce_monitormode(ifname) == TRUE) {
			dprintf("start_hostapd  %d: %s monitor skip hostapd \n",
					__LINE__, ifname);
			free(filelist);
			return -1;
		}
		if (hapd_wpasupp_is_ifce_ap(ifname) == FALSE) { /* non AP mode */
			if (!virtual_iflist) {
				dprintf("Err: rc: %d: empty secondary ifce list\n", __LINE__);
				free(filelist);
				return -1;
			}
			ifnames_list = virtual_iflist; /* run hostapd on virtual ifces */
			mode = HAPD_ON_VIRTUAL_IFACE;
		}
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		else {
			if (nvram_get_int("sw_mode") == SW_MODE_AP && nvram_get_int("wlc_psta") == 1) { // media bridge mode
				dprintf("start_hostapd  %d: media bridge mode, %s skip hostapd \n", __LINE__, ifname);
				free(filelist);
				return -1;
			}
		}
#endif
		num_primary++;
	}

	if (num_primary == 0) {
		/* If primary is not enabled, run hostapd on virtual ifces */
		ifnames_list = virtual_iflist;
		mode = HAPD_ON_VIRTUAL_IFACE;
	}

#ifdef HAPD_WPASUPP_DBG
	PRINT_IFLIST(ifnames_list);
#endif /* HAPD_WPASUPP_DBG */

	foreach(ifname, ifnames_list, next) {
		/* convert interface name from eth to wl prefixed */
		if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
			cprintf("Err: rc: %d: converting os ifname %s to nv ifname\n",
					__LINE__, ifname);
			free(filelist);
			return -1;
		}

		if (hapd_get_config_filename(nv_ifname, filename,
				sizeof(filename), &flags, mode) < 0) {
			cprintf("Err: rc: %d: get config file name for %s failed. skip\n",
					__LINE__, nv_ifname);
			continue;
		}

		if (hapd_create_config_file(nv_ifname, filename, flags) < 0) {
			cprintf("Err: rc: %d: config file %s creation for %s failed. skip\n",
					__LINE__, filename, nv_ifname);
			continue;
		}

		// Store all the filenames into the list.
		if ((usedsz + strlen(filename) + 1 /* Space */ + 1 /* NULL */) > listsz) {
			char *tmp = (char *)calloc(2, listsz);
			if (!tmp) {
				cprintf("Err: rc: %d: calloc()\n", __LINE__);
				goto end;
			}
			memcpy(tmp, filelist, usedsz);
			free(filelist);
			filelist = tmp;
			listsz *= 2;
		}
		add_to_list(filename, filelist, listsz);
		usedsz = strlen(filelist);
	}

end:
	foreach(filename, filelist, next) {
		dprintf("Info: rc: %d: Running hostapd instance using %s configuration\n",
				__LINE__, filename);
		snprintf(cmd, sizeof(cmd), "hostapd %s %s &",
				nvram_match("hapd_dbg", "4") ? "-sss" :
				nvram_match("hapd_dbg", "3") ? "-ss" :
				nvram_match("hapd_dbg", "2") ? "-s" :
				nvram_match("hapd_dbg", "1") ? "-ddt" : "-B", filename);
		system(cmd);
	}

	foreach(ifname, ifnames_list, next) {

		if (hapd_wpasupp_is_ifce_ap(ifname) == FALSE)  {
			dprintf("Err: rc: %d: %s non-AP interface. skip\n",
					__LINE__, ifname);
			continue;
		}

		/* convert interface name from eth to wl prefixed */
		if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
			cprintf("Err: rc: %d: converting os ifname %s to nv ifname\n",
					__LINE__, ifname);
			free(filelist);
			return -1;
		}

		memset(nv_name, 0, sizeof(nv_name));
		snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);
		if (nvram_match(nv_name, "dpp")) {
			char dpp_priv_key[HAPD_MAX_BUF] = {0};
			char mac[HAPD_MAX_BUF] = {0};
			char *cptr = NULL;
			snprintf(nv_name, sizeof(nv_name), "%s_hwaddr", nv_ifname);
			cptr = nvram_safe_get(nv_name);
			strncpy(mac, cptr, strlen(cptr));
			mac[strlen(cptr)] = '\0';

			cptr = NULL;

			memset(nv_name, 0, sizeof(nv_name));
			snprintf(nv_name, sizeof(nv_name), "%s_dpp_priv_key", nv_ifname);
			cptr = nvram_safe_get(nv_name);
			strncpy(dpp_priv_key, cptr, strlen(cptr));
			dpp_priv_key[strlen(cptr)] = '\0';

			sleep(2);

			memset(cmd, 0x0, sizeof(cmd));
			/* Generate QR code DPP bootstrap information */
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s "
					"dpp_bootstrap_gen type=qrcode mac=%s key=%s",
					nv_ifname, mac, dpp_priv_key);
			system(cmd);
			sleep(2);
			memset(cmd, 0x0, sizeof(cmd));
			/* Store QR code in nvram */
			snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s "
					"dpp_bootstrap_get_uri 1", nv_ifname);
			FILE *fp = popen(cmd, "r");
			char result[256] = {0x0};
			memset(nv_name, 0, sizeof(nv_name));
			snprintf(nv_name, sizeof(nv_name), "%s_dpp_qrcode", nv_ifname);
			while (fgets(result, sizeof(result), fp) != NULL)
				nvram_set(nv_name, result);
			pclose(fp);

			memset(nv_name, 0x0, sizeof(nv_name));
			snprintf(nv_name, sizeof(nv_name), "%s_dpp_role", nv_ifname);
			if (nvram_match(nv_name, "configurator")) {
				memset(cmd, 0x0, sizeof(cmd));
				/* Add a DPP configurator */
				snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s "
						"dpp_configurator_add key=%s",
						nv_ifname, dpp_priv_key);
				system(cmd);
			}
		}
	}
	free(filelist);

	return 0;
}

/* Stops the hostapd */
int
stop_hostapd()
{
	int ret = 0, i;
	char cmd[HAPD_MAX_BUF * 2] = {0};

	ret = eval("killall", "-9", "hostapd");

	snprintf(cmd, sizeof(cmd), "rm -f /tmp/*_hapd.conf");
	system(cmd);

	memset(cmd, 0, sizeof(cmd));

	snprintf(cmd, sizeof(cmd), "rm -rf /var/run/hostapd");
	system(cmd);

	for (i = 0; i < MAX_RADIO_NUM; i++)
		radio_params_set[i] = FALSE;

	return ret;
}

int
stop_hostapd_per_radio(int radio_idx)
{
	pid_t pid;
	char nv_ifname[IFNAMSIZ];
	char cmd[HAPD_MAX_BUF * 2] = {0};
	int i = 0;
	int ret = -1;

	snprintf(nv_ifname, sizeof(nv_ifname), "wl%d", radio_idx);
	if (get_hostapd_pid(radio_idx, &pid) != BCME_OK) {
		cprintf("Err: %s hostapd instance for %s does not exist\n",
			__FUNCTION__, nv_ifname);
		ret = 0;
	}
	else {
		dm_unregister_app_restart_info(pid);
		dprintf("%s kill hostapd instance %d for %s\n",
			__FUNCTION__, pid, nv_ifname);
#if 0
		snprintf(cmd, sizeof(cmd), "kill -9 %d", pid);
		system(cmd);
#else
		snprintf(cmd, sizeof(cmd), "%d", pid);
		eval("kill", "-9", cmd);
#endif
		/* wait for hostapd to exit */
		for (i = 0; i < WAIT_HOSTAPD_MAX_TIME; ++i) {
			if (get_hostapd_pid(radio_idx, &pid) != BCME_OK) {
				break;
			}
			cprintf("%s hostapd is still alive, pid=%d, radio_idx=%d, "
				"keep waiting\n", __FUNCTION__, pid, radio_idx);
			sleep(1);
		}
		if (WAIT_HOSTAPD_MAX_TIME == i) {
			cprintf("Err: %s exit with hostapd still alive\n", __FUNCTION__);
		}
		else {
			cprintf("%s hostapd on radio %d exited\n",
				__FUNCTION__, radio_idx);
			ret = 0;
		}
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rm -f /tmp/%s_hapd.conf", nv_ifname);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rm -f /tmp/%s.*_hapd.conf", nv_ifname);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rm -rf /var/run/hostapd/%s", nv_ifname);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rm -rf /var/run/hostapd/%s.*", nv_ifname);
	system(cmd);

	/* /var/run/hostapd to be removed when it is empty */
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rmdir /var/run/hostapd");
	system(cmd);

	radio_params_set[radio_idx] = FALSE;

	return ret;
}

/* Callback funtion to get the wps settings */
static int
wpa_supp_wps_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	if (hapd_wpasupp_is_wps_possible(nv_ifname) == FALSE) {
		/* Skip remaining wps settings. */
		return (WPASUPP_WPS_FIELDS_NUM - 1);
	}

	snprintf(out_val, out_sz, "%s", nvram_safe_get(cfg_arr_nvname));

	return 0;
}

/* Callback fn to fill wps cred processing field */
static int
wpa_supp_wps_cred_processing_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	/*
	 * When multiap is enabled and the enrollee is backhaul sta WPS
	 * should not process the received credentials instead it has to
	 * pass them over to the control interface. In all other cases wps
	 * should process the credentials as well as pass them over to the
	 * control interface for processing to external programs.
	 */
#ifdef MULTIAP
	char tmp[HAPD_MIN_BUF] = {0}, *ptr = NULL;
	uint16 map_mode = 0, map = 0;

	ptr = nvram_safe_get("multiap_mode");
	if (ptr[0] != '\0') {
		map_mode = (uint16)strtoul(ptr, NULL, 0);
	}

	if (map_mode > 0) {
		snprintf(tmp, sizeof(tmp), "%s_map", nv_ifname);
		ptr = nvram_safe_get(tmp);
		if (ptr[0] != '\0') {
			map = (uint16)strtoul(ptr, NULL, 0);
		}
	}

	if (IS_HAPD_MAP_BH_STA(map)) {
		snprintf(out_val, out_sz, "%s",
			HAPD_WPS_DO_NOT_PROCESS_CREDS_PASS_TO_CTRL_INTERFACE);
	} else
#endif /* MULTIAP */
	{
		snprintf(out_val, out_sz, "%s",
			HAPD_WPS_PROCESS_CREDS_AND_PASS_TO_CTRL_INTERFACE);
	}

	return 0;
}

/* This fn is invoked by new_cfg_arr, wds_cfg_arr, map_new_cfg_arr etc.
 * So be catious while modifying this fn as non-zero positive return value
 * indicates the array tuples to be skipped. Chances of exceeding array bounds
 * if return values is > no of array entries.
 */
static int
wpa_supp_key_mgmt_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **ph, char *out_val, int out_sz)
{
	char nv_name[HAPD_MAX_BUF] = {0}, key_mgmt[HAPD_MAX_BUF] = {0};
	int akm = 0, ret = 0;
	bool psk_required;
	int fbt_enabled = 0;

	hapd_wpasupp_get_security_details(nv_ifname, &akm);

	psk_required = ((akm & HAPD_AKM_PSK2) || (akm & HAPD_AKM_PSK) || (akm & HAPD_AKM_PSK2_FT) ||
			(akm & HAPD_AKM_WPA3_SAE) || (akm & HAPD_AKM_WPA3_SAE_FT)) ? TRUE : FALSE;

	fbt_enabled = wpa_supp_fbt_enabled(nv_ifname);

	hapd_wpasupp_get_key_mgmt(nv_ifname, fbt_enabled, akm, key_mgmt);

	switch (akm) {
		/* open | wep security in both the cases wpa should be 0 */
		case HAPD_AKM_OPEN:
		case HAPD_AKM_WEP:
			if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s",
						WPA_SUPP_SEC_OPEN_OR_WEP);
			}
			// skip akm, crypto, wpa_psk and mfp
			ret = 3;
			break;

			/* HAPD_SEC_WPA */
		case HAPD_AKM_PSK:
			if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (!strcmp(cfg_arr_nvname, "proto")) {
				snprintf(out_val, out_sz, "%s",
						WPA_SUPP_SEC_WPA);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// pairwise based on crypto
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (psk_required &&
					!strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build iface/bss specific nvram -
				 * wlX_nvram or wlX.Y_nvram.
				 */
				snprintf(nv_name, sizeof(nv_name),
					"%s_%s", nv_ifname, cfg_arr_nvname);
				if (ph) {
					hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz,
							WPA_PSK_FLAG_IS_WPASUPP, akm);
				}
			}
			break;

			/* WPA2-PSK */
		case HAPD_AKM_PSK2:
		case HAPD_AKM_PSK2_FT:
			if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (!strcmp(cfg_arr_nvname, "proto")) {
				snprintf(out_val, out_sz, "%s",
						WPA_SUPP_PROTO_RSN);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set pairwise based on crypto
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (psk_required &&
					!strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build iface/bss specific nvram -
				 * wlX_nvram or wlX.Y_nvram.
				 */
				snprintf(nv_name, sizeof(nv_name),
					"%s_%s", nv_ifname, cfg_arr_nvname);
				if (ph) {
					hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz,
							WPA_PSK_FLAG_IS_WPASUPP, akm);
				}
			}
			break;

			/* Mixed Mode: (WPA-PSK + WPA2-PSK) */
		case (HAPD_AKM_PSK | HAPD_AKM_PSK2):
			if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (!strcmp(cfg_arr_nvname, "proto")) {
				snprintf(nv_name, sizeof(nv_name),
						"%s_crypto", nv_ifname);
				if (nvram_match(nv_name, "aes")) {
					snprintf(out_val, out_sz, "%s",
							WPA_SUPP_PROTO_RSN);
				} else {  /* default */
					snprintf(out_val, out_sz, "%s",
						WPA_SUPP_PROTO_WPA" "
						WPA_SUPP_PROTO_RSN);
				}
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set pairwise based on crypto
				hapd_wpasupp_fill_pairwise(nv_ifname,
					cfg_arr_nvname, out_val, out_sz);
			} else if (psk_required &&
					!strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build iface/bss specific nvram -
				 * wlX_nvram or wlX.Y_nvram.
				 */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				if (ph) {
					hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz,
							WPA_PSK_FLAG_IS_WPASUPP, akm);
				}
			}
			break;

			/* WPA2-SAE or (WPA2-SAE + WPA2-PSK) */
		case HAPD_AKM_WPA3_SAE:
		case HAPD_AKM_WPA3_SAE_FT:
		case (HAPD_AKM_WPA3_SAE | HAPD_AKM_PSK2):
			if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (!strcmp(cfg_arr_nvname, "proto")) {
				snprintf(out_val, out_sz, "%s",
						WPA_SUPP_PROTO_RSN);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set pairwise based on crypto
				/* build iface/bss specific nvram -
				 * wlX_nvram or wlX.Y_nvram.
				 */
				snprintf(nv_name, sizeof(nv_name),
					"%s_%s", nv_ifname, cfg_arr_nvname);
				if (!strcmp(nvram_safe_get(nv_name), "aes")) {
					snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
				} else {
					cprintf("Err: %d: unsupported crypto for SAE\n", __LINE__);
				}
			} else if (psk_required &&
					!strcmp(cfg_arr_nvname, "wpa_psk")) {
				/* build iface/bss specific nvram -
				 * wlX_nvram or wlX.Y_nvram.
				 */
				snprintf(nv_name, sizeof(nv_name), "%s_%s",
						nv_ifname, cfg_arr_nvname);
				if (ph) {
					hapd_wpasupp_psk_key_hndlr(nv_name, ph, out_val, out_sz,
							WPA_PSK_FLAG_IS_WPASUPP | ((akm == HAPD_AKM_WPA3_SAE) ?
								WPA_PSK_FLAG_IS_SAE_ONLY : 0), akm);
				}
			}
			break;
		case HAPD_AKM_WPA3_DPP:
			if (!strcmp(cfg_arr_nvname, "akm")) {
				snprintf(out_val, out_sz, "%s", key_mgmt);
			} else if (!strcmp(cfg_arr_nvname, "proto")) {
				snprintf(out_val, out_sz, "%s",
						WPA_SUPP_PROTO_RSN);
			} else if (!strcmp(cfg_arr_nvname, "crypto")) {
				// Set pairwise based on crypto
				/* build iface/bss specific nvram -
				 * wlX_nvram or wlX.Y_nvram.
				 */
				snprintf(nv_name, sizeof(nv_name),
					"%s_%s", nv_ifname, cfg_arr_nvname);
				if (!strcmp(nvram_safe_get(nv_name), "aes")) {
					snprintf(out_val, out_sz, "%s", HAPD_CIPHER_SUITE_CCMP);
				} else {
					cprintf("Err: %d: unsupported crypto for DPP\n", __LINE__);
				}
			}
			break;
		default:
			return -1;
	};

	if (out_val[0] == '\0') {
		return -1;
	}

	return ret;
}

static int
wpa_supp_ssid_conv_fn(char *nv_ifname, char *cfg_arr_nvname,
		char **placeholder, char *out_val, int out_sz)
{
	char nvram_name[HAPD_MAX_BUF] = {0};
	char *val = NULL;

	/* build iface/bss specific nvram - wlX_nvram or wlX.Y_nvram */
	snprintf(nvram_name, sizeof(nvram_name), "%s_%s",
			nv_ifname, cfg_arr_nvname);
	val = nvram_safe_get(nvram_name);

	snprintf(out_val, out_sz, "\"%s\"", val);

	return 0;
}

/* Settings deferred flag skips particular setting to config file */
static void
wpa_supp_set_deferred(hapd_nvram_config_t *cfg_arr, int cur_pos, int count)
{
	int idx = 0;
	while (cfg_arr[cur_pos + idx].nv_name != NULL && idx < count) {
		cfg_arr[cur_pos + idx].flags |= HAPD_CFG_DEFER;
		idx++;
	}
}

static void
wpa_supp_fill_nvrams_to_config_file(FILE *fp, char *nv_ifname, uint32 flags,
	hapd_nvram_config_t *cfg_arr)
{
	int idx;
	char tmp[HAPD_MAX_BUF + 4] = {0};
	char nvram_name[HAPD_MAX_BUF] = {0};

	for (idx = 0; cfg_arr[idx].nv_name != NULL; idx++) {
		char *val = NULL, cb_out[HAPD_MAX_BUF] = {0};

		if (!(cfg_arr[idx].flags & flags)) {
			continue;
		}

		// If defer flag is set, first clear it than continue.
		if (cfg_arr[idx].flags & HAPD_CFG_DEFER) {
			cfg_arr[idx].flags &= (~HAPD_CFG_DEFER);
			continue;
		}

		if (cfg_arr[idx].flags & HAPD_CFG_USEDEFAULT) {
			val = cfg_arr[idx].def_val;
		} else {
			if (cfg_arr[idx].cb_fn != NULL) {
				/* do something */
				int ret = cfg_arr[idx].cb_fn(
						nv_ifname,
						cfg_arr[idx].nv_name,
						&(cfg_arr[idx].placeholder),
						cb_out,
						sizeof(cb_out));
			       if (ret < 0) {
					cprintf("Err: rc: %d: conversion fn returned err"
						" for %s in ifce %s\n", __LINE__,
						cfg_arr[idx].nv_name, nv_ifname);
					continue;
				}
				val = cb_out;
				// A +ve means we need to set the defered flags for next ret vals
				if (ret > 0) {
					wpa_supp_set_deferred(cfg_arr, idx + 1, ret);
				}
			} else {
				if (cfg_arr[idx].flags & HAPD_CFG_PERBSS) {
					snprintf(nvram_name, sizeof(nvram_name), "%s_%s",
						nv_ifname, cfg_arr[idx].nv_name);
				} else {
					snprintf(nvram_name, sizeof(nvram_name), "%s",
						cfg_arr[idx].nv_name);
				}
				val = nvram_safe_get(nvram_name);
			}
		}

		if (flags == WPA_SUP_CFG_GBL) {
			if (val[0] == '\0') {
				continue;
			}
			snprintf(tmp, sizeof(tmp), "%s=%s\n",
				cfg_arr[idx].placeholder, val);
		} else {
			if (val[0] == '\0') {
				val = cfg_arr[idx].def_val;
			}
			snprintf(tmp, sizeof(tmp), "\t%s=%s\n",
					cfg_arr[idx].placeholder, val);
		}

		fprintf(fp, "%s", tmp);
	}
}

int
wpa_supp_get_config_filename(char *nv_ifname, char *out_filename, int size, uint32 *out_flags)
{
	uint32 flags = HAPD_CFG_IFR; /* per radio */

	snprintf(out_filename, size, "%s/%s_%s",
		WPA_SUPP_FILE_DIR, nv_ifname, WPA_SUPP_FILENAME_SUFFIX);

	if (out_flags != NULL) {
		*out_flags = flags;
	}

	return 0;
}
int
wpa_supp_create_config_file(char *nv_ifname, char *filename, uint32 flags,
		int idx, hapd_wpasupp_wds_info_t *wdsi_ptr)
{
	char *mode = "w";
	FILE *fp = NULL;
	char nv_name[HAPD_MAX_BUF] = {0};
	char tmp[HAPD_MAX_BUF] = {0};

	fp = fopen(filename, mode);
	if (fp == NULL) {
		fprintf(stderr, "Failed to open file: %s\n", filename);
		return -1;
	}

	fprintf(fp, "update_config=1\n");
	fprintf(fp, "ctrl_interface=/var/run/%s_wpa_supplicant\n", nv_ifname);
	fprintf(fp, "ctrl_interface_group=0\n");

#ifdef HAPD_WDS_DRAFT
	if (wdsi_ptr == NULL)
#endif /* HAPD_WDS_DRAFT */
	{	/* Non-WDS interface */
		/* Fills the global config values eg: wps config */
		wpa_supp_fill_nvrams_to_config_file(fp, nv_ifname, WPA_SUP_CFG_GBL,
				wpa_supp_cfg_arr);

		snprintf(nv_name, sizeof(nv_name), "%s_ap_scan", nv_ifname);
		if (nvram_match(nv_name, "0")) {
			/* driver performs ap scanning/selection */
			fprintf(fp, "\nap_scan=0\n");
		}

		/* Add extra network block configuration which has some more parameters like bssid,
		 * priority etc. Let it be the first network block so that,
		 * it gets highest priority.
		 */
		if (wpa_supp_is_join_bssid_available(nv_ifname)) {
			fprintf(fp, "\nnetwork={\n");

			wpa_supp_fill_nvrams_to_config_file(fp, nv_ifname, flags,
					wpa_supp_ext_nw_cfg_arr);

			fprintf(fp, "}\n");
		}
	} /* Non-WDS interface */

	/* Add network block in case of DPP, only if dpp configuration is available.
	 * WPA supplicant conf file gets updated automatically once DPP connector
	 * information is received.
	 */
	snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);
	snprintf(tmp, sizeof(tmp), "%s_dpp_conf_recvd", nv_ifname);
	if (nvram_match(nv_name, "dpp") && !nvram_match(tmp, "1")) {
		fclose(fp);
		return 0;
	}

	/* Add common network block configuration. This network block will be selected if the
	 * above network block fails to connect
	 */
	fprintf(fp, "\nnetwork={\n");

#ifdef HAPD_WDS_DRAFT
	 /* Atlease one or more WDS interface(s) of radio is in SUPPLICANT role.
	  * Fill conf file of the WDS interface
	  */
	if ((wdsi_ptr != NULL) && (wdsi_ptr[idx].wds_if_count >  0)) {
		int radio_idx = -1, bsscfg_idx = -1, wds_idx = -1;
		char wlifname[IFNAMSIZ] = {0};
		char mac_addr_str[ETHER_ADDR_STR_LEN] = {0};

		sscanf(nv_ifname, "wds%d.%d.%d", &radio_idx, &bsscfg_idx, &wds_idx);

		fprintf(fp, "\tbssid=%s\n",
				ether_etoa((unsigned char *)
					wdsi_ptr[idx].wds_peers_mac_arr[wds_idx - 1],
					mac_addr_str));

		/* nv_ifname is of the form wlx.y.z where x is the radio interface idx.
		 * Get the corresponding wl interface name.
		 */
		memset(nv_ifname, '\0', IFNAMSIZ);
		snprintf(wlifname, IFNAMSIZ, "wl%d", idx);
		WLIF_STRNCPY(nv_ifname, wlifname, sizeof(nv_ifname));

		/* Fill the conf file with tuples in WDS cfg arr */
		wpa_supp_fill_nvrams_to_config_file(fp, nv_ifname, flags, wpa_supp_wds_cfg_arr);
	} else
#endif /* HAHD_WDS */
	{
		wpa_supp_fill_nvrams_to_config_file(fp, nv_ifname, flags, wpa_supp_nw_cfg_arr);
	}

	fprintf(fp, "}\n");

	fclose(fp);

	return 0;
}

/* In repeater/non-AP mode, run one instance of wpa_supplicant per primary interface.
 * In WDS mode, run only one instance of wpa_supplicant on all WDS interfaces in SUPPLICANT
 * role with their corresponding conf files.
 */
static int
start_wpa_supplicant(int idx, char *supplicant_iflist, hapd_wpasupp_wds_info_t *wdsi_ptr)
{
	uint32 flags = 0;
	char ifname[IFNAMSIZ] = {0};
	char nv_ifname[IFNAMSIZ] = {0};
	char filename[HAPD_MAX_BUF] = {0}, cmd[HAPD_MAX_BUF * 4] = {0};
	char *next;
	char *lan_ifname = NULL;
	int ret = -1;
	char nv_name[HAPD_MIN_BUF] = {0};
#if defined(RTCONFIG_AMAS)
	char dpsta_if[IFNAMSIZ] = {0};
	char *next_dpsta;
	int apply = 0;
	char nv_upifs[32] = {0};
#endif

#ifdef HAPD_WDS_DRAFT
	char wds_conf_files_list[HAPD_MAX_BUF] = {0};
	char cmd_args[HAPD_MAX_BUF * 2] = {0}, tmp[HAPD_MAX_BUF] = {0};
	int wds_if_count = 0;
#endif /* HAPD_WDS_DRAFT */

	if (!supplicant_iflist) {
		dprintf("Err: rc: %d: empty supplicant iflist\n", __LINE__);
		return -1;
	}
#ifdef HAPD_WPASUPP_DBG
	printf("supplicant iflist: ");
	PRINT_IFLIST(supplicant_iflist);
#endif /* HAPD_WPASUPP_DBG */

	foreach(ifname, supplicant_iflist, next) {
		if (hapd_wpasupp_is_ifce_monitormode(ifname) == TRUE) {
			dprintf("start_wpa_supplicant  %d: %s monitor skip wpa_supplicant \n",
					__LINE__, ifname);
			return -1;
		}
		/* skip if interface is non-WDS ifce in AP mode */
		if (
#ifdef HAPD_WDS_DRAFT
			(wdsi_ptr == NULL) &&
#endif /* HAPD_WDS_DRAFT */
			hapd_wpasupp_is_ifce_ap(ifname) == TRUE)  {
			dprintf("Err: rc: %d: %s AP or non-WDS interface. skip\n",
					__LINE__, ifname);
			continue;
		}
#if defined(RTCONFIG_AMAS)
#if defined(RTCONFIG_DPSTA)
#if (defined(RTCONFIG_WIFI6E) && defined(RTCONFIG_HAS_5G_2)) || defined(RTCONFIG_BCM_502L07P2)
		snprintf(nv_upifs, sizeof(nv_upifs), "dpsta_all_ifnames");
#else
		snprintf(nv_upifs, sizeof(nv_upifs), "dpsta_ifnames");
#endif
#else
		snprintf(nv_upifs, sizeof(nv_upifs), "dpsr_wpasupp_ifnames");
#endif
		if (dpsta_mode() || dpsr_mode()) {
			apply = 0;
			foreach(dpsta_if, nvram_safe_get(nv_upifs), next_dpsta) {
			if (!strcmp(dpsta_if, ifname)) {
					apply = 1;
					break;
				}
			}
			if(!apply) {
				cprintf("%s: skip %s since not in %s\n", __FUNCTION__, ifname, nv_upifs);
				continue;
			}
		}
#endif

		/* convert interface name from eth to wl prefixed */
		if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
			dprintf("Err: rc: %d: converting os ifname %s to nv ifname. skip\n",
					__LINE__, ifname);
			continue;
		}

		if (wpa_supp_get_config_filename(nv_ifname, filename, sizeof(filename), &flags)
				< 0) {
			cprintf("Err: rc: %d: get config file name for %s failed. skip\n",
					__LINE__, nv_ifname);
			continue;
		}

		if (wpa_supp_create_config_file(nv_ifname, filename, flags, idx, wdsi_ptr) < 0) {
			cprintf("Err: rc: %d: wpa_supplicant conf file %s creation for %s failed\n",
					__LINE__, filename, nv_ifname);
			continue;
		}

#ifdef HAPD_WDS_DRAFT
		if ((wdsi_ptr != NULL) && wdsi_ptr[idx].wds_if_count > 0) {
			wds_if_count++;
			snprintf(tmp, sizeof(tmp), "%s -i %s -c %s", (wds_if_count > 1 ? "-N" : ""),
					ifname, filename);
			strcat(cmd_args, tmp);
			add_to_list(filename, wds_conf_files_list, sizeof(wds_conf_files_list));
		}
#endif /* HAPD_WDS_DRAFT */

		lan_ifname = nvram_safe_get("lan_ifname");
		if (lan_ifname[0] == '\0') {
			lan_ifname = "br0";
		}

		/* for non WDS interfaces, run one instance of wpa_supplicant for every interface
		 * in the supplicant_list.
		 */
#ifdef HAPD_WDS_DRAFT
		if ((wdsi_ptr == NULL))
#endif /* HAPD_WDS_DRAFT */
		{
			cprintf("Info: rc: %d: running wpa_supplicant instance on ifce %s"
					" using %s configuration\n", __LINE__, ifname, filename);
			snprintf(cmd, sizeof(cmd),
					"%s %s -i %s -Dnl80211 -c %s -b %s &",
					WPA_SUPP_APP, (nvram_match("wpasupp_dbg", "1") ? "-ddK" : ""),
					ifname, filename, lan_ifname);
		}
	} /* foreach inteface in supplicant_iflist */

#ifdef HAPD_WDS_DRAFT
	/* In WDS case, with one or more WDS interfaces in SUPPLICANT role, only one instance of
	 * wpa_supplicant is run per radio ifce  with relavant WDS ifnames and their corresponding
	 * config files as arguments to wpa_supplicant cmd.
	 */
	if ((wdsi_ptr != NULL) && wdsi_ptr[idx].wds_if_count > 0) {
		/* create a wpa_supplicant cmd with relevant WDS ifnames and thier corresponding
		 * config files as arguments.
		 */
		snprintf(cmd, (HAPD_MAX_BUF * 2),
			"%s %s -Dnl80211 %s -b br0 -g /tmp/wpa_wlan0 &\n",
			WPA_SUPP_APP, (nvram_match("wpasupp_dbg", "1") ? "-ddK" : ""), cmd_args);

		/* wait for 10s for WDS interfaces to be UP before starting wpa_supplicant */
		sleep(10);
	}
#endif /* HAPD_WDS_DRAFT */

	if (cmd[0] != '\0') {
		ret = system(cmd);
	}

	if (ret < 0) {
		dprintf("Err: rc: %d: system()\n", __LINE__);
	}

	foreach(ifname, supplicant_iflist, next) {
		if (hapd_wpasupp_is_ifce_ap(ifname) == TRUE)  {
			dprintf("Err: rc: %d: %s AP interface. skip\n",
					__LINE__, ifname);
			continue;
		}
		/* convert interface name from eth to wl prefixed */
		if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
			dprintf("Err: rc: %d: converting os ifname %s to nv ifname. skip\n",
					__LINE__, ifname);
			continue;
		}
		snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);
		if (nvram_match(nv_name, "dpp")) {
			char dpp_priv_key[HAPD_MAX_BUF] = {0};
			char mac[HAPD_MAX_BUF] = {0};
			char *cptr = NULL;
			FILE *fp;
			char result[256] = {0x0};
			memset(nv_name, 0, sizeof(nv_name));
			snprintf(nv_name, sizeof(nv_name), "%s_hwaddr", nv_ifname);
			cptr = nvram_safe_get(nv_name);
			strncpy(mac, cptr, strlen(cptr));
			mac[strlen(cptr)] = '\0';

			cptr = NULL;

			memset(nv_name, 0, sizeof(nv_name));
			snprintf(nv_name, sizeof(nv_name), "%s_dpp_priv_key", nv_ifname);
			cptr = nvram_safe_get(nv_name);
			strncpy(dpp_priv_key, cptr, strlen(cptr));
			dpp_priv_key[strlen(cptr)] = '\0';

			sleep(2);
			/* Generate QR code DPP bootstrap information */
			snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p /var/run/%s_wpa_supplicant/ "
					"dpp_bootstrap_gen type=qrcode mac=%s key=%s",
					nv_ifname, nv_ifname, mac, dpp_priv_key);
			system(cmd);
			sleep(2);
			memset(cmd, 0x0, sizeof(cmd));
			/* Store QR code in nvram */
			snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p /var/run/%s_wpa_supplicant/ "
					"dpp_bootstrap_get_uri 1", nv_ifname, nv_ifname);
			fp = popen(cmd, "r");
			memset(nv_name, 0, sizeof(nv_name));
			snprintf(nv_name, sizeof(nv_name), "%s_dpp_qrcode", nv_ifname);
			while (fgets(result, sizeof(result), fp) != NULL)
				nvram_set(nv_name, result);
			pclose(fp);
		}
	} /* foreach inteface in supplicant_iflist */

	return ret;
}

/* Stops the wpa_supplicant */
int
stop_wpa_supplicant()
{
	int ret = 0;
	char cmd[HAPD_MAX_BUF * 2] = {0};

	ret = eval("killall", "-9", WPA_SUPP_APP);

	snprintf(cmd, sizeof(cmd), "rm -f /tmp/wl*_wpa_supplicant.conf");
	system(cmd);

	memset(cmd, 0, sizeof(cmd));

	snprintf(cmd, sizeof(cmd), "rm -rf /var/run/wl*_wpa_supplicant");
	system(cmd);

	return ret;
}

void
stop_wpasupp(int band)
{
        char cmd[128];
        int i;

        _dprintf("%s, band:%d\n", __func__, band);

        if(band >= 0) {
                        snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ sta_autoconnect 0", band);
                        system(cmd);
                        snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ disconnect", band);
                        system(cmd);
        } else {
                for(i=0; i<num_of_wl_if(); ++i) {
                        snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ sta_autoconnect 0", i);
                        system(cmd);
                        snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ disconnect", i);
                        system(cmd);
                }
        }
}

void
start_wpasupp(int band)
{
	char cmd[128];
	int i;

	_dprintf("%s, band:%d\n", __func__, band);

	if(band >= 0) {
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ sta_autoconnect 1", band);
			system(cmd);
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ reconnect", band);
			system(cmd);
	} else {
		for(i=0; i<num_of_wl_if(); ++i) {
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ sta_autoconnect 1", i);
			system(cmd);
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p /var/run/wl%d_wpa_supplicant/ reconnect", i);
			system(cmd);
		}
	}
}

static void
stop_wpa_supplicant_per_radio(int radio_idx)
{
	DIR *dir;
	struct dirent *ent;
	char path[PATH_MAX];
	FILE *fp = NULL;
	bool bFound = FALSE;
	char nv_ifname[IFNAMSIZ];
	char *pStrTmp = NULL;
	char cmd[HAPD_MAX_BUF * 2] = {0};
	int size = 0;

	snprintf(nv_ifname, sizeof(nv_ifname), "wl%d", radio_idx);

	if ((dir = opendir("/proc")) == NULL) {
		dprintf("Err: rc: %d: fail to open /proc\n", __LINE__);
	}
	else {
		while ((ent = readdir(dir)) != NULL) {
			if (!strspn(ent->d_name, "0123456789"))
				continue;

			path[0] = '\0';
			strcat(path, "/proc/");
			strcat(path, ent->d_name);
			strcat(path, "/");
			strcat(path, "cmdline");
			fp = fopen(path, "r");
			if (!fp)
				continue;

			if (fgets(cmd, sizeof(cmd), fp) != NULL) {
			/*
			* hexdump -c /proc/4361/cmdline
			* 0000000   w   p   a   _   s   u   p   p   l   i   c   a   n   t  \0  /
			* 0000010   -   i  \0   w   l   0  \0
			*/
				if (!strstr(cmd, WPA_SUPP_APP)) {
					fclose(fp);
					continue;
				}

				size = ftell(fp);
				pStrTmp = cmd;

				while (pStrTmp < cmd + size) {
					if (!strcmp(pStrTmp, "-i")) {
						break;
					}
					else {
						pStrTmp += strlen(pStrTmp);
						++pStrTmp;
					}
				}

				if (pStrTmp < cmd + size) {
					pStrTmp += strlen(pStrTmp);
					++pStrTmp;

					/* pStrTmp now points to interface name */
					if (!strcmp(pStrTmp, nv_ifname)) {
						bFound = TRUE;
						dprintf("Err: rc: %d kill wpa_supplicant instance",
							__LINE__);
						dprintf(" %s for %s \n", ent->d_name, nv_ifname);
						eval("kill", "-9", ent->d_name);
					}
				}
			}
			fclose(fp);

			if (bFound) {
				break;
			}
		}
		closedir(dir);
	}

	if (!bFound) {
		dprintf("Err: rc: %d: hostapd instance for %s does not exist\n",
				__LINE__, nv_ifname);
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rm -f /tmp/%s_wpa_supplicant.conf", nv_ifname);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "rm -rf /var/run/%s_wpa_supplicant", nv_ifname);
	system(cmd);

	return;
}
/* Fn to fetch the list of primary and virtual interfaces for a radio */
static void
hapd_wpasupp_get_radio_list(char *ifnames_list, char *radio_iflist, int rlistsz, int idx)
{
	char ifname[IFNAMSIZ] = {0}, *next;
	char nv_ifname[IFNAMSIZ] = {0}, nvram_name[HAPD_MAX_BUF] = {0};
	int unit = -1;

	snprintf(nvram_name, sizeof(nvram_name),  "wl%d_radio", idx);

	if ((nvram_match(nvram_name, "0")) == TRUE) {
		cprintf("Err: rc: %d: radio %d disabled\n", __LINE__, idx);
		return;
	}

	foreach(ifname, ifnames_list, next) {
		if (wl_probe(ifname)) {
			dprintf("Err: rc: %d: Skipping %s - non wireless interface\n",
					__LINE__, ifname);
			continue;
		}
		if (osifname_to_nvifname(ifname, nv_ifname, IFNAMSIZ) < 0) {
			cprintf("Err: rc: %d: osname to ifname\n", __LINE__);
			return;
		}
		if (get_ifname_unit(nv_ifname, &unit, NULL) < 0) {
			cprintf("Err: rc: %d: get_ifname_unit\n", __LINE__);
			return;
		}

		if (unit == idx) {
			add_to_list(ifname, radio_iflist, rlistsz);
		} else {
			dprintf("Info: rc: %d: skipped adding %s to radio_iflist[%d]\n",
					__LINE__, ifname, idx);
		}
	} /* foreach */

#ifdef HAPD_WPASUPP_DBG
	printf("radio_iflist[%d]: ", idx);
	PRINT_IFLIST(radio_iflist);
#endif /* HAPD_WPASUPP_DBG */

	return;
}

int
start_hapd_wpasupp_per_radio(int radio_idx)
{
	char *ifnames_list = NULL;  /* concatenated ifnames on br0 and br1 with space in between */
	char *primary_iflist = NULL; /* primary radio interfaces on the board - ethX, ethY... */
	char *filtered_iflist = NULL; /* interfaces on which BSS' are enabled - ethX, wlX.Y... */
	char *virtual_iflist = NULL; /* virtual interfaces  - wlX.Y... */
	char *radio_iflist = NULL; /* primay and virtual ifces on a radio */
	int ifnames_listsz = 0; /* concatenated list size */
	int ret = -1;
	pid_t pid;

	ifnames_listsz = hapd_wpasupp_get_all_lanifnames_listsz();
	if (ifnames_listsz <= 0) {
		cprintf("Err: rc: %d:  No interfaces in LAN and GUEST bridges\n", __LINE__);
		return -1;
	}

	ifnames_list = calloc(1, ifnames_listsz);
	if (!ifnames_list) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}
	filtered_iflist = calloc(1, ifnames_listsz);
	if (!filtered_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}
	primary_iflist = calloc(1, ifnames_listsz);
	if (!primary_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}
	virtual_iflist = calloc(1, ifnames_listsz);
	if (!virtual_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}

	radio_iflist = calloc(1, ifnames_listsz);
	if (!radio_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}

	hapd_wpasupp_get_all_lanifnames_list(ifnames_list, ifnames_listsz);

	hapd_wpasupp_get_radio_list(ifnames_list, radio_iflist, ifnames_listsz, radio_idx);

	/* Iterate over each radio. Fetch the radio's secondary BSS' */
	if (*radio_iflist == '\0') {
		cprintf("Info: rc: %d: radio_iflist[%d] is empty. continue\n", __LINE__, radio_idx);
		goto end;
	}

	memset(filtered_iflist, 0, ifnames_listsz);
	memset(primary_iflist, 0, ifnames_listsz);
	memset(virtual_iflist, 0, ifnames_listsz);

	hapd_wpasupp_get_filtered_ifnames_list(radio_iflist,
		filtered_iflist, ifnames_listsz);
	hapd_wpasupp_get_primary_virtual_iflist(filtered_iflist, primary_iflist,
		virtual_iflist, ifnames_listsz);

#ifdef HAPD_WPASUPP_DBG
	printf("radio_iflist: ");
	PRINT_IFLIST(radio_iflist);

	printf("filtered_iflist: ");
	PRINT_IFLIST(filtered_iflist);

	printf("primary_iflist: ");
	PRINT_IFLIST(primary_iflist);

	printf("virtual_iflist: ");
	PRINT_IFLIST(virtual_iflist);
#endif /* HAPD_WPASUPP_DBG */

	ret = start_wpa_supplicant(radio_idx, primary_iflist, NULL);
	if (ret == 0) {
		/* if wpa_supp successfully launched, wait before starting hostapd */
		sleep(HAPD_START_DEFER);
	}

	ret = start_hostapd(filtered_iflist, primary_iflist, virtual_iflist);

	pid = radio_idx - MAX_RADIO_NUM;
	if (!ret) {
		int i = 0;

		for (i = 0; i < WAIT_HOSTAPD_MAX_TIME; ++i) {
			if (BCME_OK == get_hostapd_pid(radio_idx, &pid))
				break;
			sleep(1);
		}
		if (i >= WAIT_HOSTAPD_MAX_TIME) {
			cprintf("Err: %s Fail to start hostapd, radio_idx=%d\n",
				__FUNCTION__, radio_idx);
		}
		else {
			cprintf("Info: %s hostapd is running pid=%d, radio_idx=%d\n",
				__FUNCTION__, pid, radio_idx);
		}
	}

end:
	if (ifnames_list) {
		free(ifnames_list);
	}
	if (filtered_iflist) {
		free(filtered_iflist);
	}
	if (primary_iflist) {
		free(primary_iflist);
	}
	if (virtual_iflist) {
		free(virtual_iflist);
	}

	if (radio_iflist) {
		free(radio_iflist);
	}

	return ret;
}


int
start_hostapd_per_radio(int radio_idx)
{
	char *ifnames_list = NULL;  /* concatenated ifnames on br0 and br1 with space in between */
	char *primary_iflist = NULL; /* primary radio interfaces on the board - ethX, ethY... */
	char *filtered_iflist = NULL; /* interfaces on which BSS' are enabled - ethX, wlX.Y... */
	char *virtual_iflist = NULL; /* virtual interfaces  - wlX.Y... */
	char *radio_iflist = NULL; /* primay and virtual ifces on a radio */
	int ifnames_listsz = 0; /* concatenated list size */
	int ret = -1;
	pid_t pid;

	ifnames_listsz = hapd_wpasupp_get_all_lanifnames_listsz();
	if (ifnames_listsz <= 0) {
		cprintf("Err: rc: %d:  No interfaces in LAN and GUEST bridges\n", __LINE__);
		return -1;
	}

	ifnames_list = calloc(1, ifnames_listsz);
	if (!ifnames_list) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}
	filtered_iflist = calloc(1, ifnames_listsz);
	if (!filtered_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}
	primary_iflist = calloc(1, ifnames_listsz);
	if (!primary_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}
	virtual_iflist = calloc(1, ifnames_listsz);
	if (!virtual_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}

	radio_iflist = calloc(1, ifnames_listsz);
	if (!radio_iflist) {
		cprintf("Err: rc: %d: calloc()\n", __LINE__);
		goto end;
	}

	hapd_wpasupp_get_all_lanifnames_list(ifnames_list, ifnames_listsz);
	
	hapd_wpasupp_get_radio_list(ifnames_list, radio_iflist, ifnames_listsz, radio_idx);

	/* Iterate over each radio. Fetch the radio's secondary BSS' */
	if (*radio_iflist == '\0') {
		cprintf("Info: rc: %d: radio_iflist[%d] is empty. continue\n", __LINE__, radio_idx);
		goto end;
	}

	memset(filtered_iflist, 0, ifnames_listsz);
	memset(primary_iflist, 0, ifnames_listsz);
	memset(virtual_iflist, 0, ifnames_listsz);

	hapd_wpasupp_get_filtered_ifnames_list(radio_iflist,
		filtered_iflist, ifnames_listsz);
	hapd_wpasupp_get_primary_virtual_iflist(filtered_iflist, primary_iflist,
		virtual_iflist, ifnames_listsz);

#ifdef HAPD_WPASUPP_DBG
	printf("radio_iflist: ");
	PRINT_IFLIST(radio_iflist);

	printf("filtered_iflist: ");
	PRINT_IFLIST(filtered_iflist);

	printf("primary_iflist: ");
	PRINT_IFLIST(primary_iflist);

	printf("virtual_iflist: ");
	PRINT_IFLIST(virtual_iflist);
#endif /* HAPD_WPASUPP_DBG */

	ret = start_hostapd(filtered_iflist, primary_iflist, virtual_iflist);

	pid = radio_idx - MAX_RADIO_NUM;
	if (!ret) {
		int i = 0;

		for (i = 0; i < WAIT_HOSTAPD_MAX_TIME; ++i) {
			if (BCME_OK == get_hostapd_pid(radio_idx, &pid))
				break;
			sleep(1);
		}
		if (i >= WAIT_HOSTAPD_MAX_TIME) {
			cprintf("Err: %s Fail to start hostapd, radio_idx=%d\n",
				__FUNCTION__, radio_idx);
			ret = -1;
		}
		else {
			cprintf("Info: %s hostapd is running pid=%d, radio_idx=%d\n",
				__FUNCTION__, pid, radio_idx);
		}
	}

end:
	if (ifnames_list) {
		free(ifnames_list);
	}
	if (filtered_iflist) {
		free(filtered_iflist);
	}
	if (primary_iflist) {
		free(primary_iflist);
	}
	if (virtual_iflist) {
		free(virtual_iflist);
	}

	if (radio_iflist) {
		free(radio_iflist);
	}

	return ret;
}

#ifdef HAPD_WDS_DRAFT
/* Fn to initialize each per radio wds_info struct */
void
hapd_wpasupp_init_wds_info_arr(hapd_wpasupp_wds_info_t wdsi_arr[])
{
	int idx = -1, i = -1;

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		memset(&wdsi_arr[idx], 0, sizeof(wdsi_arr[idx]));
		wdsi_arr[idx].wds_if_count = 0;

		for (i = 0; i < MAX_WDS_IF; i++) {
			wdsi_arr[idx].wds_idx[i] = 0;
			memset(&(wdsi_arr[idx].wds_ifname), '\0', sizeof(wdsi_arr[idx].wds_ifname));
			memset(&(wdsi_arr[idx].wds_peers_mac_arr[i]), '\0',
					sizeof(wdsi_arr[idx].wds_peers_mac_arr[i]));
		} /* for each WDS interface of the radio */
	} /* for each radio */
}

/* Fn to get the MAC addr of primary interface of the MAX_RADIO_NUM's radios */
int
hapd_wpasupp_get_pr_if_mac_addr(unsigned char pr_if_mac_arr[][ETHER_ADDR_LEN])
{
	int idx = -1;
	char *mac_str = NULL;
	char nv_name[HAPD_MIN_BUF] = {0};

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		snprintf(nv_name, sizeof(nv_name), "wl%d_hwaddr", idx);

		mac_str = nvram_safe_get(nv_name);

		if (mac_str[0] == '\0') {
			dprintf("Info: rc: %d: No MAC address for wl%d interface"
				"- radio might be DISABLED/not present\n",
				__LINE__, idx);
			continue;
		}

		if (!ether_atoe(mac_str, pr_if_mac_arr[idx])) {
			dprintf("Info: rc: %d: ether_atoe() failed for mac (%s) \n",
				__LINE__, mac_str);
			return -1;
		}
	} /* for  each radio/primary ifce */

	return 0;
}

/* Fn to get the MAC address of all the WDS peer(s) of each radio interface */
int
hapd_wpasupp_get_wds_peer_mac_list(unsigned char wds_peer_mac_list_arr[][HAPD_MAX_BUF])
{
	int idx = -1;
	char *next = NULL;
	char nv_name[HAPD_MIN_BUF] = {0};
	char *wds_peer_mac_str_list = NULL; // space separated list of MAC addrs in hex-colons
	char peer_mac_str[ETHER_ADDR_STR_LEN] = {0};

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		snprintf(nv_name, sizeof(nv_name), "wl%d_wds", idx);

		wds_peer_mac_str_list = nvram_safe_get(nv_name);

		if (wds_peer_mac_str_list[0] == '\0') {
			dprintf("Info: rc: %d: No WDS peer(s)for wl%d interface\n", __LINE__, idx);
			continue;
		}

#ifdef HAPD_WDS_DBG
		printf("Info: rc: %d: wl%d_wds = \"%s\"\n", __LINE__, idx, wds_peer_mac_str_list);
#endif /* HAPD_WDS_DBG */

		memset(wds_peer_mac_list_arr[idx], '\0', HAPD_MAX_BUF);

		foreach(peer_mac_str, wds_peer_mac_str_list, next) {
			if (add_to_list(((char *)peer_mac_str),
				((char *)wds_peer_mac_list_arr[idx]), HAPD_MAX_BUF) != 0) {
				dprintf("Err: rc: %d: adding peer_mac to list[%d]\n", __LINE__,
						idx);
			}

		} /* foreach WDS peer MAC address of the radio */
	} /* for each radio interface */

	return 0;
}

int
hapd_wpasupp_cp_peer_mac(const char *a, unsigned char *e)
{
	char *c = (char *) a;
	int i = 0;

	memset(e, 0, ETHER_ADDR_LEN);
	for (;;) {
		e[i++] = (unsigned char) strtoul(c, &c, 16);
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
	}
	return (i == ETHER_ADDR_LEN);
}

/* Fn to fill the wds_info struct. Check if the WDS ifce is in SUPPLICANT role by
 * comapring the its peer MAC addr with primary ifce MAC addr. If one of more WDS
 * interfaces of the radio is in SUPPLICANT role, then fill its details in the
 * corresponding wds_info struct.
 */
int
hapd_wpasupp_fill_wds_info(hapd_wpasupp_wds_info_t wdsi_arr[],
		unsigned char wds_peer_mac_list_arr[][HAPD_MAX_BUF],
		unsigned char pr_if_mac_arr[][ETHER_ADDR_LEN])
{
	int idx = -1, i = -1;
	char *next = NULL;
	char wds_ifname[IFNAMSIZ] = {0};
	char peer_mac_str[ETHER_ADDR_STR_LEN] = {0};
	unsigned char peer_mac[ETHER_ADDR_LEN] = {0};

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		i = 0;

		foreach(peer_mac_str, ((char *)wds_peer_mac_list_arr[idx]), next) {
			if (*wds_peer_mac_list_arr[idx] == '\0') {
				dprintf("Info: rc: %d: wl%d: No WDS peer(s). skip\n",
						__LINE__, idx);
				continue;
			}

			/* Convert MAC address of WDS peer from hex-colon string to binary */
			if (!ether_atoe(peer_mac_str, peer_mac)) {
				dprintf("Err: rc: ether_atoe() failed for mac (%s)\n",
						__LINE__, peer_mac_str);
				return -1;
			}
			/* Comapre MAC address to decide role of WDS ifce */
			if ((memcmp(peer_mac, &(pr_if_mac_arr[idx]), ETHER_ADDR_LEN)) > 0) {
				/* WDS ifce is in SUPPLICANT role */
				wdsi_arr[idx].wds_if_count++;
				wdsi_arr[idx].wds_idx[i] = (i + 1);

				/* create WDS interface name of form wdsx.y.z */
				snprintf(wds_ifname, IFNAMSIZ, "wds%d.0.%d", idx, (i + 1));
				WLIF_STRNCPY((wdsi_arr[idx].wds_ifname[i]),
						wds_ifname, sizeof(wds_ifname));

				/* Convert MAC addr of WDS peer to binary and cp into wds_info */
				if (!hapd_wpasupp_cp_peer_mac((char *)peer_mac_str,
					(unsigned char *)(&(wdsi_arr[idx].wds_peers_mac_arr[i])))) {
					dprintf("Err: rc: copying peer_mac to wdsi\n", __LINE__);
					return -1;
				}
			} else {
				/* placeholder for WDS ifce in AUTHENTICATOR role */
			}
			i++;
		} /* foreach WDS peer(s) of the radio ifce */
	} /* for each radio interface */

	return 0;
}

/* Fn to retrieve the WDS ifnames from wds_info struct and create a per
 * radio space separated interface list.
 */
void
hapd_wpasupp_get_wds_supplicant_iflist(int idx, char *wds_supplicant_iflist,
		hapd_wpasupp_wds_info_t wdsi_arr[MAX_RADIO_NUM])
{
	int i = -1;

	if (wdsi_arr[idx].wds_if_count == 0) {
		dprintf("Info: rc: %d: wl%d: No WDS interface(s) in supplicant role. skip\n",
				__LINE__, idx);
		return;
	}
	for (i = 0; i < MAX_WDS_IF; i++) {
		if (*wdsi_arr[idx].wds_ifname[i] == '\0') {
			dprintf("Info: rc: %d: wl%d: Empty WDS ifname. skip\n",
					__LINE__, idx);
			continue;
		}
		add_to_list(wdsi_arr[idx].wds_ifname[i],
				wds_supplicant_iflist, HAPD_MAX_BUF);
	} /* for each WDS inteface in wds_info struct */
}

#ifdef HAPD_WDS_DBG
/* Fn to print the MAC address of all WDS peers on all the radio's. */
void
hapd_wpasupp_print_wds_peer_mac_list(unsigned char wds_peer_mac_list_arr[][HAPD_MAX_BUF])
{
	int idx = -1;

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		if (*wds_peer_mac_list_arr[idx] == '\0') {
			dprintf("Info: rc: %d: No WDS peer(s)for wl%d interface.skip\n",
					__LINE__, idx);
			continue;
		}
		printf("wl%d WDS peer(s): ", idx);
		printf("wds_peer_mac_list[%d]: \"%s\"\n", idx,
				(unsigned char *)wds_peer_mac_list_arr[idx]);
	} /* for each radio interface */
}

/* Fn to print the contents of wds_info struct */
int
hapd_wpasupp_print_wds_info(hapd_wpasupp_wds_info_t wdsi_arr[MAX_RADIO_NUM])
{
	int idx = -1, i = -1;
	char ea[ETHER_ADDR_STR_LEN] = {0};

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		printf("====== wl%d: wds_info =====\n", idx);
		printf("%d", wdsi_arr[idx].wds_if_count);
		printf("\n");

		for (i = 0; i < MAX_WDS_IF; i++) {
			printf("%d\t", wdsi_arr[idx].wds_idx[i]);
		}
		printf("\n");

		for (i = 0; i < MAX_WDS_IF; i++) {
			if (wdsi_arr[idx].wds_if_count == 0) {
				printf("-------- ");
				printf("0x**********");
				printf("\n");
				continue;
			}
			if (*wdsi_arr[idx].wds_ifname[i] == '\0')  {
				printf("-------- ");
			} else {
				printf("%s ", wdsi_arr[idx].wds_ifname[i]);
			}
			printf("%s\n", ether_etoa((unsigned char *)
					wdsi_arr[idx].wds_peers_mac_arr[i], ea));
		} /* for each WDS interface */
	} /* for each radio */
	return 0;
}
#endif /* HAPD_WDS_DBG */
#endif /* HAPD_WDS_DRAFT */

/* Get all radio list */
static void hapd_wpasupp_get_radio_ifnames_list(char *radio_iflist[])
{
	char *ifnames_list = NULL; /* concatenated ifnames on br0, br1 etc. with space in between */
	int ifnames_listsz = 0;
	int idx;

	ifnames_listsz = hapd_wpasupp_get_all_lanifnames_listsz();
	if (ifnames_listsz <= 0)
		return;

	ifnames_list = calloc(1, ifnames_listsz);
	if (!ifnames_list) {
		dprintf("Err: rc: %d: calloc()\n",  __LINE__);
		return;
	}

	hapd_wpasupp_get_all_lanifnames_list(ifnames_list, ifnames_listsz);

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		hapd_wpasupp_get_radio_list(ifnames_list, radio_iflist[idx], ifnames_listsz, idx);
	}

	if (ifnames_list) {
		free(ifnames_list);
	}

	return;
}

/* AP acting as configurator should provision itself */
int
start_hapd_dpp_self_provision()
{
	char *radio_iflist[MAX_RADIO_NUM]; /* primay and virtual ifces on a radio */
	char *next;
	char ifname[IFNAMSIZ] = {0};
	char *filtered_iflist = NULL; /* interfaces on which BSS' are enabled - ethX, wlX.Y... */
	int ifnames_listsz = 0; /* concatenated list size */
	char nv_ifname[IFNAMSIZ] = {0};
	char nv_name[HAPD_MIN_BUF] = {0};
	char cmd[HAPD_MAX_BUF * 2] = {0};
	int idx;

	ifnames_listsz = hapd_wpasupp_get_all_lanifnames_listsz();

	if (ifnames_listsz == 0) {
		cprintf("Info: rc: %d: ifnames list size is zero.\n", __LINE__);
		return 0;
	}

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		radio_iflist[idx] = calloc(1, ifnames_listsz + 1);

		if (!radio_iflist[idx]) {
			cprintf("Err: rc: %d: calloc()\n",  __LINE__);
			return -1;
		}
	}

	hapd_wpasupp_get_radio_ifnames_list(radio_iflist);

	filtered_iflist = calloc(1, ifnames_listsz);
	if (!filtered_iflist) {
		dprintf("Err: rc: %d: calloc()\n",  __LINE__);
		goto end;
	}

	/* Sleep for 2 seconds to allow wps_pbcd to be ready */
	sleep(2);

	/* Iterate over each radio. Fetch the radio's secondary BSS' */
	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		memset(filtered_iflist, 0, ifnames_listsz);

		if (*radio_iflist[idx] == '\0') {
			dprintf("Info: rc: %d: radio_iflist[%d] is empty. continue\n",
					__LINE__, idx);
			continue;
		}

		hapd_wpasupp_get_filtered_ifnames_list(radio_iflist[idx],
			filtered_iflist, ifnames_listsz);

		foreach(ifname, filtered_iflist, next) {

			if (hapd_wpasupp_is_ifce_ap(ifname) == FALSE)  {
				cprintf("Err: rc: %d: %s non-AP interface. skip\n",
						__LINE__, ifname);
				continue;
			}

			/* convert interface name from eth to wl prefixed */
			if (osifname_to_nvifname(ifname, nv_ifname, sizeof(nv_ifname))) {
				cprintf("Err: rc: %d: converting os ifname %s to nv ifname\n",
						__LINE__, ifname);
				continue;
			}

			snprintf(nv_name, sizeof(nv_name), "%s_akm", nv_ifname);
			if (nvram_match(nv_name, "dpp")) {
				char ssid[HAPD_MAX_BUF] = {0};
				char *cptr = NULL;

				memset(nv_name, 0x0, sizeof(nv_name));
				snprintf(nv_name, sizeof(nv_name), "%s_ssid", nv_ifname);
				if ((cptr = nvram_safe_get(nv_name))) {
					strncpy(ssid, cptr, strlen(cptr));
					ssid[strlen(cptr)] = '\0';
				}

				memset(nv_name, 0x0, sizeof(nv_name));
				snprintf(nv_name, sizeof(nv_name), "%s_dpp_role", nv_ifname);

				if (nvram_match(nv_name, "configurator")) {
					snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s "
							"dpp_configurator_sign conf=ap-dpp ssid=%s "
							"configurator=1",
							nv_ifname, ssid);
					system(cmd);
				}
			}
		} /* for each filtered list */
	}

end:
	if (filtered_iflist) {
		free(filtered_iflist);
	}
	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		if (radio_iflist[idx]) {
			free(radio_iflist[idx]);
		}
	}

	return 0;
}

int
start_hapd_wpasupp(int skip_wpasupp)
{
	char *primary_iflist = NULL; /* primary radio interfaces on the board - ethX, ethY... */
	char *filtered_iflist = NULL; /* interfaces on which BSS' are enabled - ethX, wlX.Y... */
	char *virtual_iflist = NULL; /* virtual interfaces  - wlX.Y... */
	char *wpa_supplicant_iflist = NULL; /* list of interfaces to run wpa_supplicant on */
	char *radio_iflist[MAX_RADIO_NUM]; /* primay and virtual ifces on a radio */
	int ifnames_listsz = 0; /* concatenated list size */
	int idx, ret = -1;
	hapd_wpasupp_wds_info_t *wdsi_ptr = NULL;

#ifdef HAPD_WDS_DRAFT
	unsigned char pr_if_mac_arr[MAX_RADIO_NUM][ETHER_ADDR_LEN] = {{0}, {0}};
	unsigned char wds_peer_mac_list_arr[MAX_RADIO_NUM][HAPD_MAX_BUF] = {{0}, {0}};
	hapd_wpasupp_wds_info_t wds_info_arr[MAX_RADIO_NUM]; // array of wds_info
	char *wds_ifnames_list = NULL; //  WDS interfaces in SUPPLICANT role

	/* Initialize the array of wds_info struct */
	hapd_wpasupp_init_wds_info_arr(wds_info_arr);

	/* Get MAC address of the primary ifce for each radio */
	ret = hapd_wpasupp_get_pr_if_mac_addr(pr_if_mac_arr);
	if (ret == -1) {
		goto end;
	}

	/* Get MAC address of WDS peer's of all radio interfaces */
	ret = hapd_wpasupp_get_wds_peer_mac_list(wds_peer_mac_list_arr);
	if (ret == -1) {
		goto end;
	}

#ifdef HAPD_WDS_DBG
	/* Print all WDS peers on each radio */
	hapd_wpasupp_print_wds_peer_mac_list(wds_peer_mac_list_arr);
#endif /* HAPD_WDS_DBG */

	/* Fill per radio wds_info struct with WDS peer(s) and other relavent info */
	hapd_wpasupp_fill_wds_info(wds_info_arr, wds_peer_mac_list_arr, pr_if_mac_arr);

#ifdef HAPD_WDS_DBG
	hapd_wpasupp_print_wds_info(wds_info_arr);
#endif /* HAPD_WDS_DBG */

	wds_ifnames_list = calloc(1, HAPD_MAX_BUF);
	if (!wds_ifnames_list) {
		dprintf("Err: rc: %d: calloc()\n",  __LINE__);
		goto end;
	}
#endif /* HAPD_WDS_DRAFT */

	ifnames_listsz = hapd_wpasupp_get_all_lanifnames_listsz();

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		radio_iflist[idx] = calloc(1, ifnames_listsz);

		if (!radio_iflist[idx]) {
			dprintf("Err: rc: %d: calloc()\n",  __LINE__);
			goto end;
		}
	}

	hapd_wpasupp_get_radio_ifnames_list(radio_iflist);

	filtered_iflist = calloc(1, ifnames_listsz);
	if (!filtered_iflist) {
		dprintf("Err: rc: %d: calloc()\n",  __LINE__);
		goto end;
	}
	primary_iflist = calloc(1, ifnames_listsz);
	if (!primary_iflist) {
		dprintf("Err: rc: %d: calloc()\n",  __LINE__);
		goto end;
	}
	virtual_iflist = calloc(1, ifnames_listsz);
	if (!virtual_iflist) {
		dprintf("Err: rc: %d: calloc()\n",  __LINE__);
		goto end;
	}

	/* Iterate over each radio. Fetch the radio's secondary BSS' */
	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		memset(filtered_iflist, 0, ifnames_listsz);
		memset(primary_iflist, 0, ifnames_listsz);
		memset(virtual_iflist, 0, ifnames_listsz);

		if (*radio_iflist[idx] == '\0') {
			dprintf("Info: rc: %d: radio_iflist[%d] is empty. continue\n",
					__LINE__, idx);
			continue;
		}

		hapd_wpasupp_get_filtered_ifnames_list(radio_iflist[idx],
			filtered_iflist, ifnames_listsz);
		hapd_wpasupp_get_primary_virtual_iflist(filtered_iflist, primary_iflist,
			virtual_iflist, ifnames_listsz);

#ifdef HAPD_WDS_DRAFT
		/* Get per radio WDS ifnames list to run wpa_supplicant. */
		hapd_wpasupp_get_wds_supplicant_iflist(idx, wds_ifnames_list, wds_info_arr);
#endif /* HAPD_WDS_DRAFT */

#ifdef HAPD_WPASUPP_DBG
		printf("radio_iflist[%d]: ", idx);
		PRINT_IFLIST(radio_iflist[idx]);

		printf("filtered_iflist: ");
		PRINT_IFLIST(filtered_iflist);

		printf("primary_iflist: ");
		PRINT_IFLIST(primary_iflist);

		printf("virtual_iflist: ");
		PRINT_IFLIST(virtual_iflist);
#if (defined(HAPD_WDS_DRAFT) && defined(HAPD_WDS_DBG))
		printf("wds_ifnames_list: ");
		PRINT_IFLIST(wds_ifnames_list);
#endif /* HAPD_WDS_DRAFT && HAPD_WDS_DBG */
#endif /* HAPD_WPASUPP_DBG */

#ifdef HAPD_WDS_DRAFT
		if (wds_info_arr[idx].wds_if_count > 0) {
			wpa_supplicant_iflist =  wds_ifnames_list;
			wdsi_ptr = wds_info_arr;
		} else
#endif /* HAPD_WDS_DRAFT */
		{
			wpa_supplicant_iflist =  primary_iflist;
			wdsi_ptr = NULL;
		}

		if(!skip_wpasupp) {
			ret = start_wpa_supplicant(idx, wpa_supplicant_iflist, wdsi_ptr);
			if (ret == 0) {
				/* if wpa_supp successfully launched, wait before starting hostapd */
				sleep(HAPD_START_DEFER);
			}
		}

		ret = start_hostapd(filtered_iflist, primary_iflist, virtual_iflist);

		sleep(2);

	} /* for each radio */

end:
	if (filtered_iflist) {
		free(filtered_iflist);
	}
	if (primary_iflist) {
		free(primary_iflist);
	}
	if (virtual_iflist) {
		free(virtual_iflist);
	}

#ifdef HAPD_WDS_DRAFT
	if (wds_ifnames_list) {
		free(wds_ifnames_list);
	}
#endif /* HAPD_WDS_DRAFT */

	for (idx = 0; idx < MAX_RADIO_NUM; idx++) {
		if (radio_iflist[idx]) {
			free(radio_iflist[idx]);
		}
	}

	return ret;
}

void
stop_hapd_wpasupp()
{
	stop_hostapd();
	stop_wpa_supplicant();
}

void
stop_hapd_wpasupp_per_radio(int radio_idx)
{
	stop_hostapd_per_radio(radio_idx);
	stop_wpa_supplicant_per_radio(radio_idx);
}

/* In gcc version 8.2 using std library function strncpy() results in error when copying few bytes
 * to dest buffer from larger src buffer because of '-Werror=stringop-truncation -O2' flag set.
 * This is a workaround to circumvent the error.
 */
char *hapd_wpasupp_strncpy(char *dest, const char *src, size_t n)
{
	memcpy((char *)dest, (const char *)src, (n - 1));
	dest[n - 1] = '\0';

	return dest;
}

#ifdef HAPD_WDS
static bool
hapd_wpasupp_is_ifce_wds(const char *ifname)
{
	if (strncmp(ifname, WDS_DEV_NAME, strlen(WDS_DEV_NAME)) == 0) {
		return TRUE;
	}

	return FALSE;
}

/* check if a process(hostapd, wpa_supplicant etc) is already running by
 * peeping into the /proc directory
 */
bool
hapd_wpasupp_is_ps_running(const char *ps_name)
{
	DIR *dir;
	struct dirent *ent;
	char path[PATH_MAX] = {0}, cmd[HAPD_MAX_BUF] = {0};
	FILE *fp = NULL;
	bool ps_found = FALSE;

	if ((dir = opendir("/proc")) == NULL) {
		cprintf("Err: rc: %d: fail to open /proc\n", __LINE__);
	} else {
		while ((ent = readdir(dir)) != NULL) {
			if (!strspn(ent->d_name, "0123456789"))
				continue;

			path[0] = '\0';
			strcat(path, "/proc/");
			strcat(path, ent->d_name);
			strcat(path, "/");
			strcat(path, "cmdline");

			fp = fopen(path, "r");
			if (!fp) {
				continue;
			}

			if (fgets(cmd, sizeof(cmd), fp) != NULL) {
				if ((strstr(cmd, ps_name)) != NULL) {
					ps_found = TRUE;
					break;
				}
			} /* fgets */
			fclose(fp);
		} /* while */
		closedir(dir);
	} /* else */

	dprintf("Info: rc: %d: %s instance is %s running\n", __LINE__, ps_name,
			((ps_found == TRUE) ? "" : "NOT"));

	return ps_found;
}

/* Add interface and enable network from wpa_cli for WDS interface.
 */
void
wpasupp_add_and_enable_network(char *ifname)
{
	FILE *fp = NULL;
	int sz = 0, ret = 0;
	unsigned long int network_id;
	char cmd[HAPD_MAX_BUF] = {0}, ctrl_if[HAPD_MIN_BUF] = {0}, buf[HAPD_MIN_BUF] = {0};
	char nv_name[HAPD_MIN_BUF] = {0}, out_buf[HAPD_MIN_BUF] = {0};
	char wl_ifname[IFNAMSIZ] = {0}; // wdsX.Y.Z -> wlX

	snprintf(ctrl_if, sizeof(ctrl_if), "%s/wpa_supplicant-%s", CTRL_IF_DIR, ifname);

	dprintf("Info: rc: %d: ctrl_if: %s\n", __LINE__, ctrl_if);

	/* Add the WDS interface wtih its ctrl iface to wpa_supplicant */
	snprintf(cmd, sizeof(cmd), "wpa_cli -g %s interface_add %s \"\" nl80211 %s \"\" br0",
			GLOBAL_CTRL_IF, ifname, ctrl_if);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);

	/* A regular supplicant interface can have multiple networks added/configured to it.
	 * Each network will have a unique network_id starting from 0. However, In WDS case,
	 * we restirct each WDS interface to have only one network corresponding to the WDS
	 * peer mac to connect to.
	 * List the networks on WDS interface and check if a network with network_id 0 already
	 * exists on the WDS interface
	 */
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s list_networks | grep ^0", ifname, ctrl_if);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);

	ret = system(cmd);

	if (ret == 0) {
		dprintf("Info: rc: %d: network 0 already exists on %s. return.\n",
				__LINE__, ifname);
		return;
	}

	/* Add network to wpa_supplicant. prints network_id on terminal.
	 * Fetch the network_id from terminal and save for subsequent use.
	 */
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s add_network", ifname, ctrl_if);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);

	fp = popen(cmd, "r");
	if (fp == NULL) {
		fprintf(stderr, "popen(): %s\n", strerror(errno));
		return;
	}

	while (!feof(fp)) {
		sz = sizeof(buf) - 1;
		if (fgets(buf, sz, fp)) {
			buf[strcspn(buf, "\r\n")] = 0;
		}
	}
	pclose(fp);

	network_id = strtoul(buf, NULL, 0);

	dprintf("Info: rc: %d: network_id %lu\n", __LINE__, network_id);

	/* convert ifname wdsX.Y.Z to corresponing primary wl ifname of form wlX.
	 * wlX ifname is passed as 1st arg of key_mgmt functions invoked below.
	 */
	if (hapd_wpasupp_get_primary_ifce(ifname, wl_ifname, sizeof(wl_ifname)) < 0) {
		dprintf("Err: rc: %d: converting WDS ifname %s into wl ifname\n", __LINE__, ifname);
		return;
	}

	snprintf(nv_name, sizeof(nv_name), "%s_ssid", wl_ifname);
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s set_network %lu ssid \'\"%s\"\'",
			ifname, ctrl_if, network_id, nvram_safe_get(nv_name));
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);

	wpa_supp_key_mgmt_conv_fn(wl_ifname, "akm", NULL, out_buf, sizeof(out_buf));
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s set_network %lu key_mgmt %s",
			ifname, ctrl_if, network_id, out_buf);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);

	snprintf(nv_name, sizeof(nv_name), "%s_wpa_psk", wl_ifname);
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s set_network %lu psk \'\"%s\"\'",
			ifname, ctrl_if, network_id, nvram_safe_get(nv_name));
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);

	wpa_supp_key_mgmt_conv_fn(wl_ifname, "crypto", NULL, out_buf, sizeof(out_buf));
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s set_network %lu pairwise %s",
			ifname, ctrl_if, network_id, out_buf);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);

	/* Broadcom WDS is propeitary. So the Group Cipher Suite is NONE for WDS.
	 * The IE field is filled with BCM OUI.
	 * Hence, the below command fails which tries to set Group Cipher SUITE as AES.
	 * snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s set_network 0 group AES", ifname,
	 * ctrl_if);
	 * dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	 * system(cmd);
	 */

	wpa_supp_key_mgmt_conv_fn(wl_ifname, "proto", NULL, out_buf, sizeof(out_buf));
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s set_network %lu proto %s",
			ifname, ctrl_if, network_id, out_buf);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);

	/* enable network */
	snprintf(cmd, sizeof(cmd), "wpa_cli -i %s -p %s enable_network %lu",
			ifname, ctrl_if, network_id);
	dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
	system(cmd);
} /* wlevet_enable_network */

/* get mac address of the passed interface in binary form
 */
static int
hapd_wpasupp_get_mac_addr(char *ifname, unsigned char self_mac[])
{
	char wl_ifname[IFNAMSIZ] = {0}; // wdsX.Y.Z -> wlX
	char nv_name[HAPD_MAX_BUF] = {0};
	char *self_mac_str = NULL;

	/* convert ifname wdsX.X.Y to corresponing primary wl ifname of form wlX, which
	 * is used to get MAC address from nvram
	 */
	if (hapd_wpasupp_get_primary_ifce(ifname, wl_ifname, sizeof(wl_ifname)) < 0) {
		dprintf("Err: rc: %d: converting WDS ifname %s into wl ifname\n", __LINE__, ifname);
		return -1;
	}

	snprintf(nv_name, sizeof(nv_name), "%s_hwaddr", wl_ifname);

	self_mac_str = nvram_safe_get(nv_name);

	if (self_mac_str[0] == '\0') {
		dprintf("Err: rc: %d: MAC address not found for %s\n", __LINE__, wl_ifname);
		return -1;
	}

	if (!ether_atoe(self_mac_str, self_mac)) {
		dprintf("Err: rc: %d: ether_atoe() failed for mac (%s)\n", __LINE__, self_mac_str);
		return -1;
	}

	return 0;
}

/* get WDS role by comparing self mac address with WDS peer's mac address.
 * return role as AUTHENTICATOR if self_wds_mac > peer_wds_mac, else SUPPLICANT.
 */
static int
hapd_wpasupp_get_wds_wpa_role(char *ifname, struct ether_addr wds_peer_ea)
{
	unsigned char self_mac[ETHER_ADDR_LEN] = {0};
	char wds_peer_mac_str[ETHER_ADDR_STR_LEN] = {0};
	int role = WDS_WPA_ROLE_ERR;
	int ret = -1;

	if (ifname == NULL) {
		dprintf("Err: rc: %d: NULL ifname.\n", __LINE__);
		return ret;
	}

	ether_etoa((unsigned char *)wds_peer_ea.octet, wds_peer_mac_str);

	if ((hapd_wpasupp_get_mac_addr(ifname, self_mac)) == -1) {
		dprintf("Err: rc: %d: error getting mac_addr.\n", __LINE__);
		return ret;
	}

	ret = memcmp(self_mac, &(wds_peer_ea.octet), ETHER_ADDR_LEN);

	/* Comapre MAC addresses to decide role of WDS ifce */
	if (ret > 0) {
		dprintf("Info: rc: %d: authenticator.\n", __LINE__);
		role = WDS_WPA_ROLE_AUTH;
	} else if (ret < 0) { /* SUPPLICANT */
		dprintf("Info: rc: %d: supplicant.\n", __LINE__);
		role = WDS_WPA_ROLE_SUP;
	} else {
		dprintf("Err: rc: %d: same mac address comparison.\n", __LINE__);
		role = WDS_WPA_ROLE_ERR;
	}

	return role;
}

void
hapd_wpasupp_wds_hndlr(const char *pkt)
{
	bool ret = FALSE;
	bcm_event_t *dpkt = NULL;
	int  event_type = -1;
	char ifname[IFNAMSIZ] = {0}; // For WDS, ifname is of form wdsx.y.z
	char cmd[HAPD_MIN_BUF] = {0};

	if (pkt == NULL) {
		dprintf("Err: rc: %d: pkt NULL.return\n", __LINE__);
		return;
	}

	/* driver event is prepended with interface name on which the event is generated.
	 * copy interface name.
	 */
	hapd_wpasupp_strncpy(ifname, pkt, IFNAMSIZ);
	dprintf("Info: wps_pbcd: %d: ifname: %s\n", __LINE__, ifname);

	/* check if the driver event is generated on WDS interface */
	if (hapd_wpasupp_is_ifce_wds(ifname) == FALSE) {
		dprintf("Info: rc: %d: Non WDS interface %s.\n", __LINE__, ifname);
		return;
	}

	dpkt = (bcm_event_t *)(pkt + IFNAMSIZ);

	event_type = ntohl(dpkt->event.event_type);

	if (event_type != WLC_E_LINK) {
		dprintf("Info: rc: %d:  event_type: %d\n", __LINE__, event_type);
		return;
	}

	if ((hapd_wpasupp_get_wds_wpa_role(ifname, dpkt->event.addr)) != WDS_WPA_ROLE_SUP) {
		dprintf("Info: not a supplicant.\n");
		return;
	}

	/* check if supplicant is already running */
	ret = hapd_wpasupp_is_ps_running(SUPPLICANT_NAME);

	if (ret == FALSE) {
		dprintf("Info: rc: %d: start wpa_supplicant with global cntrl iface.\n", __LINE__);
		snprintf(cmd, sizeof(cmd), "%s -Dnl80211 %s -b br0 -g %s",
				WPA_SUPP_APP, nvram_match("wpasupp_dbg", "1") ? "-B -ddK" : "-B", GLOBAL_CTRL_IF);
		/* start wpa_supplicant on global cntrl interface */
		dprintf("Info: rc: %d: %s\n", __LINE__, cmd);
		system(cmd);
	} else {
		dprintf("Info: rc: %d: wpa_supplicant already running with global cntrl iface %s\n",
				__LINE__, GLOBAL_CTRL_IF);
	}

	wpasupp_add_and_enable_network(ifname);
}
#endif /*  HAPD_WDS */

static int
get_hostapd_pid(int radio_idx, pid_t *pid)
{
	DIR *dir;
	struct dirent *ent;
	char path[PATH_MAX];
	FILE *fp = NULL;
	char *pStr = NULL, *pStrTmp = NULL;
	char cmdline[HAPD_MAX_BUF] = {0};
	bool bFound = FALSE;
	char nvi_ifname[IFNAMSIZ];

	snprintf(nvi_ifname, sizeof(nvi_ifname), "wl%d", radio_idx);

	dir = opendir("/proc");
	if (dir == NULL) {
		cprintf("Err: %s fail to open /proc\n", __FUNCTION__);
		return -1;
	}

	/* loops over all dir entries in /proc */
	while (NULL != (ent = readdir(dir))) {
		/* proceed only when dir name is a number, i.e., pid */
		if (strlen(ent->d_name) != strspn(ent->d_name, "0123456789"))
			continue;

		/* open file /proc/<pid>/cmdline */
		snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
		fp = fopen(path, "r");
		if (!fp) {
			continue;
		}

		/* read from the file /proc/<pid>/cmdline */
		memset(cmdline, '\0', sizeof(cmdline));
		if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
			/* go further only if the process name is 'hostapd' */
			if (strcmp(cmdline, "hostapd")) {
				fclose(fp);
				continue;
			}
			pStr = cmdline;

			/*
			 * cmdline holds command-line arguments of process seperated by
			 * null byte '\0', loop on each argument here.
			 */
			while (TRUE) {
				if ((pStr >= (cmdline + sizeof(cmdline))) || (*pStr == '\0'))
					break;

				/* keep skipping to the next argument till the one for
				 * hostapd config filename.
				 */
				if (!strstr(pStr, ".conf")) {
					pStr += strlen(pStr);
					/* skip '\0' */
					++pStr;
				}
				else {
					/* proceed if config filename has wl<radio_num> in it */
					pStrTmp = strstr(pStr, nvi_ifname);
					if (!pStrTmp)
						break;
					pStr = pStrTmp + strlen(nvi_ifname);
					/*
					 * hostapd config filename is wlx_hapd.conf or
					 * wlx.y_hapd.conf, pStr points to the character after
					 * wl<radio_num> must be a '.' or '_'
					 */
					if (*pStr == '.' || *pStr == '_') {
						bFound = TRUE;
						*pid = atoi(ent->d_name);
					}
					break;
				}
			}
		}
		fclose(fp);
		if (bFound)
			break;
	}
	closedir(dir);
	return bFound ? BCME_OK : BCME_ERROR;
}
#endif	/* CONFIG_HOSTAPD */
