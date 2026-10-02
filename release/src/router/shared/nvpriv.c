#include <limits.h>
#include <unistd.h>

#include "shared.h"

#ifdef RTCONFIG_JFFS_NVRAM
#define JFFS_PATH		"/jffs"
#define JFFS_NVRAM_PATH		"/jffs/nvram"
#define JFFS_NVRAM_WAR_FILE	"/jffs/nvram_war"

#if defined(RTCONFIG_BCMARM) && !defined(HND_ROUTER)
extern char *dev_nvram_get(const char* name);
extern int dev_nvram_set(const char* name, const char *value);
#define internal_nvram_get(param) dev_nvram_get(param)
#define internal_nvram_set(param1, param2) dev_nvram_set(param1, param2)
#elif defined(HND_ROUTER)
extern char *wlcsm_nvram_get(char *name);
#define internal_nvram_get(param) wlcsm_nvram_get(param)
#define internal_nvram_set(param1, param2) nvram_set(param1, param2)
#else
#error internal nvram set/get function
#endif

static char jffs_nvram_buf[16384];

char * jffs_nvram_get(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", JFFS_NVRAM_PATH, name);
	memset(jffs_nvram_buf, 0 , sizeof(jffs_nvram_buf));

	if (!d_exists(JFFS_NVRAM_PATH))
		mkdir(JFFS_NVRAM_PATH, 0777);

	if (f_exists(path)) {
		if (f_read_string(path, jffs_nvram_buf, sizeof(jffs_nvram_buf)) > 0)
			return jffs_nvram_buf;
		else
			return "";
	}
	else
		return NULL;
}

int jffs_nvram_set(const char *name, const char *value)
{
	char path[PATH_MAX];

	if(!value) return jffs_nvram_unset(name);

	snprintf(path, PATH_MAX, "%s/%s", JFFS_NVRAM_PATH, name);

	if (!d_exists(JFFS_NVRAM_PATH))
		mkdir(JFFS_NVRAM_PATH, 0777);

	return f_write_string(path, value, 0, 0);
}

int jffs_nvram_unset(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", JFFS_NVRAM_PATH, name);

	if (!d_exists(JFFS_NVRAM_PATH))
		mkdir(JFFS_NVRAM_PATH, 0777);

	return unlink(path);
}

static char *large_nvram_list[] = {
	"MULTIFILTER_MAC",
	"MULTIFILTER_DEVICENAME",
	"MULTIFILTER_MACFILTER_DAYTIME",
	"MULTIFILTER_MACFILTER_DAYTIME_V2",
	"MULTIFILTER_TMP",
	"OPTUS_MULTIFILTER_MAC",
	"optus_url_whitelist",
#ifdef RTCONFIG_TOR
	"Tor_redir_list",
#endif
	"asus_device_list",
	"autofw_rulelist",
#ifdef RTCONFIG_CAPTIVE_PORTAL
	"captive_portal",
	"captive_portal_adv_local_clientlist",
	"captive_portal_adv_profile",
#endif
	"cloud_sync",
	"custom_clientlist",
	"custom_usericon",
	"custom_usericon_del",
	"dhcp1_staticlist",
	"dhcp_staticlist",
	"dsltmp_cfg_iptv_pvclist",
	"fb_comment",
	"filter_lwlist",
	"game_vts_rulelist",
	"gvlan_rulelist",
#ifdef RTCONFIG_IPSEC
	"ipsec_client_list_1",
	"ipsec_client_list_2",
	"ipsec_client_list_3",
	"ipsec_client_list_4",
	"ipsec_client_list_5",
	"ipsec_profile_1",
	"ipsec_profile_1_ext",
	"ipsec_profile_2",
	"ipsec_profile_2_ext",
	"ipsec_profile_3",
	"ipsec_profile_3_ext",
	"ipsec_profile_4",
	"ipsec_profile_4_ext",
	"ipsec_profile_5",
	"ipsec_profile_5_ext",
	"ipsec_profile_client_1",
	"ipsec_profile_client_1_ext",
	"ipsec_profile_client_2",
	"ipsec_profile_client_2_ext",
	"ipsec_profile_client_3",
	"ipsec_profile_client_3_ext",
	"ipsec_profile_client_4",
	"ipsec_profile_client_4_ext",
	"ipsec_profile_client_5",
	"ipsec_profile_client_5_ext",
#endif
	"ipv6_fw_rulelist",
#ifdef RTCONFIG_SOFTWIRE46
	"ipv6_s46_fmrs",
	"ipv6_s46_ports",
#endif
	"keyword_rulelist",
	"keyword_sched",
	"kg_devicename",
	"kg_mac",
	"lb_skip_port",
#ifdef RTCONFIG_LP5523
	"lp55xx_lp5523_sch",
#endif
	"nc_setting_conf",
	"pptpd_clientlist",
	"pptpd_sr_rulelist",
	"qos_bw_rulelist",
	"qos_orates",
	"qos_rulelist",
	"share_link_host",
	"share_link_param",
	"share_link_result",
	"sr_rulelist",
	"sshd_authkeys",
	"sshd_hostkey",
	"sshd_dsskey",
	"sshd_ecdsakey",
	"subnet_rulelist",
	"tl_cycle",
#if defined(RTCONFIG_TR069)
	"tr_ca_cert",
	"tr_client_cert",
	"tr_client_key",
#endif
	"url_rulelist",
	"url_sched",
	"vlan_pvid_list",
	"vlan_rulelist",
#ifdef RTCONFIG_OPENVPN
	"vpn_client1_custom",
	"vpn_client2_custom",
	"vpn_client3_custom",
	"vpn_client4_custom",
	"vpn_client5_custom",
	"vpn_crt_client_ca",
	"vpn_crt_client_crl",
	"vpn_crt_client_crt",
	"vpn_crt_client_key",
	"vpn_crt_client_static",
	"vpn_crt_server_ca",
	"vpn_crt_server_client_crt",
	"vpn_crt_server_client_key",
	"vpn_crt_server_crl",
	"vpn_crt_server_crt",
	"vpn_crt_server_dh",
	"vpn_crt_server_key",
	"vpn_crt_server_static",
	"vpn_server_ccd_val",
	"vpn_server_custom",
	"vpn_server1_ccd_val",
	"vpn_server1_custom",
	"vpn_server2_ccd_val",
	"vpn_server2_custom",
	"vpn_serverx_clientlist",
#endif
#if defined(RTCONFIG_VPNC)
	"vpnc_clientlist",
	"vpnc_pptp_options_x_list",
#endif
#if defined(RTCONFIG_VPN_FUSION)
	"vpnc_dev_policy_list",
	"vpnc_dev_policy_list_tmp",
#endif
	"vpnc_pptp_options_x_list",
	"vts1_rulelist",
	"vts_rulelist",
	"wans_routing_rulelist",
	"wl0.1_maclist",
	"wl0.2_maclist",
	"wl0.3_maclist",
	"wl0.4_maclist",
	"wl0_maclist",
	"wl0.1_maclist_x",
	"wl0.2_maclist_x",
	"wl0.3_maclist_x",
	"wl0.4_maclist_x",
	"wl0_maclist_x",
	"wl0_rast_static_client",
	"wl0_sched",
	"wl0_sched_v2",
	"wl1.1_maclist",
	"wl1.2_maclist",
	"wl1.3_maclist",
	"wl1.4_maclist",
	"wl1_maclist",
	"wl1.1_maclist_x",
	"wl1.2_maclist_x",
	"wl1.3_maclist_x",
	"wl1.4_maclist_x",
	"wl1_maclist_x",
	"wl1_rast_static_client",
	"wl1_sched",
	"wl1_sched_v2",
	"wl2.1_maclist",
	"wl2.2_maclist",
	"wl2.3_maclist",
	"wl2.4_maclist",
	"wl2_maclist",
	"wl2.1_maclist_x",
	"wl2.2_maclist_x",
	"wl2.3_maclist_x",
	"wl2.4_maclist_x",
	"wl2_maclist_x",
	"wl2_rast_static_client",
	"wl2_sched",
	"wl2_sched_v2",
	"wl_maclist",
	"wl_maclist_x",
	"wl_rast_static_client",
	"wl_sched",
	"wl_sched_v2",
	"wollist",
	"wrs_app_rulelist",
	"wrs_rulelist",
	"wtf_rulelist",
	"yadns_rulelist",
#ifdef AMASDB
	"amas_dbsta",
	"amas_dbsta_all",
#endif
	"wl0_chansps",
	"wl1_chansps",
	"wl2_chansps",
#ifdef RTCONFIG_ACCOUNT_BINDING
	"oauth_dm_refresh_ticket",
	"http_oauth_clientlist",
#endif
#ifdef RTCONFIG_GN_WBL
	"wl0.2_gn_wbl_rule",
#endif
#ifdef RTCONFIG_WEBDAV
	"share_link",
#endif
#ifdef RTCONFIG_BWDPI
	"bwdpi_game_list",
	"bwdpi_stream_list",
#endif
#ifdef RTCONFIG_CFGSYNC
	"cfg_device_list",
#if RTCONFIG_MAX_RE > MAX_RELIST_NUM
	"cfg_relist",
	"cfg_relist_x",
#endif
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
	"sta_binding_list",
#endif
#ifdef RTCONFIG_DNSFILTER
	"dnsfilter_rulelist",
#endif
	NULL
};

static char *large_nvram_list_t[] = {
#ifdef RTCONFIG_CFGSYNC
#if RTCONFIG_MAX_RE > MAX_RELIST_NUM
	"cfg_relist",
	"cfg_relist_x",
#endif
#endif
        NULL
};

int large_nvram(const char *name)
{
	int i;

	if (!d_exists(JFFS_PATH)) return 0;

	if (!f_exists(JFFS_NVRAM_WAR_FILE)) return 0;

	for (i = 0; large_nvram_list[i] != NULL; i++) {
		if (!strcmp(name, large_nvram_list[i]))
			return 1;
	}

	return 0;
}

int large_nvram_t(const char *name)
{
	int i;

	for (i = 0; large_nvram_list_t[i] != NULL; i++) {
		if (!strcmp(name, large_nvram_list_t[i]))
			return 1;
	}

	return 0;
}

#define internal_nvram_safe_get(name) (internal_nvram_get(name) ? : "")

int internal_nvram_get_int(const char *key)
{
        return atoi(internal_nvram_safe_get(key));
}

void jffs_nvram_init()
{
	int i, modified = 0;
	char *p;
	char nvname[256];

	if (!d_exists(JFFS_PATH)) return;

	for (i = 0; large_nvram_list[i] != NULL; i++) {
		if ((p = internal_nvram_get(large_nvram_list[i]))) {
			if (strlen(p)) {
				snprintf(nvname, sizeof(nvname), "%s_t", large_nvram_list[i]);
				if (!(large_nvram_t(large_nvram_list[i]) && internal_nvram_get_int(nvname)))
				{
					jffs_nvram_set(large_nvram_list[i], p);
					if (large_nvram_t(large_nvram_list[i]))
						internal_nvram_set(nvname, "1");
					else
						internal_nvram_set(large_nvram_list[i], "");
					if (!modified) modified = 1;
				}
			}
		}
	}

	if (modified) nvram_commit();
}

int jffs_nvram_getall(int len_nvram, char *buf, int count)
{
	int len, i;

	len = len_nvram;

	for (i = 0; large_nvram_list[i] != NULL; i++) {
		if (jffs_nvram_get(large_nvram_list[i]) &&
			((count - len) > (strlen(large_nvram_list[i]) + 1 + strlen(jffs_nvram_get(large_nvram_list[i])) + 1)))
			len += sprintf(buf + len, "%s=%s", large_nvram_list[i], jffs_nvram_get(large_nvram_list[i])) + 1;
	}

	return len;
}
#endif

#ifdef RTCONFIG_VAR_NVRAM
#define VAR_PATH           "/tmp/var"
#define VAR_NVRAM_PATH     "/tmp/var/nvram"

#if defined(RTCONFIG_BCM4708)
extern char *dev_nvram_get(const char* name);
extern int dev_nvram_set(const char* name, const char *value);
#define internal_nvram_get(param) dev_nvram_get(param)
#define internal_nvram_unset(param) dev_nvram_set(param, NULL)
#elif defined(HND_ROUTER)
extern char *wlcsm_nvram_get(char *name);
extern int wlcsm_nvram_unset (char *name);
#define internal_nvram_get(param) wlcsm_nvram_get(param)
#define internal_nvram_unset(param) wlcsm_nvram_unset(param)
#else
#error internal nvram get/unset function
#endif
extern struct nvram_tuple router_state_defaults[];

static char var_nvram_buf[8192];

int var_nvram_unset(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", VAR_NVRAM_PATH, name);

	return unlink(path);
}

int var_nvram_set(const char *name, const char *value)
{
	char path[PATH_MAX];

	if(!value) return var_nvram_unset(name);

	snprintf(path, PATH_MAX, "%s/%s", VAR_NVRAM_PATH, name);

	return f_write_string(path, value, 0, 0);
}

char* var_nvram_get(const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", VAR_NVRAM_PATH, name);
	memset(var_nvram_buf, 0 , sizeof(var_nvram_buf));

	if (f_exists(path)) {
		if (f_read_string(path, var_nvram_buf, sizeof(var_nvram_buf)) > 0)
			return var_nvram_buf;
		else
			return "";
	}
	else
		return NULL;
}

static char *var_nvram_list[] = {
	"rc_support",
#if defined(RTCONFIG_MULTISERVICE_WAN)
	"wan0_state_t", "wan0_sbstate_t", "wan0_auxstate_t", "wan0_realip_ip", "wan0_realip_state",
	"wan1_state_t", "wan1_sbstate_t", "wan1_auxstate_t", "wan1_realip_ip", "wan1_realip_state",
	"wan101_state_t", "wan101_sbstate_t", "wan101_auxstate_t", "wan101_realip_ip", "wan101_realip_state",
	"wan102_state_t", "wan102_sbstate_t", "wan102_auxstate_t", "wan102_realip_ip", "wan102_realip_state",
	"wan103_state_t", "wan103_sbstate_t", "wan103_auxstate_t", "wan103_realip_ip", "wan103_realip_state",
	"wan104_state_t", "wan104_sbstate_t", "wan104_auxstate_t", "wan104_realip_ip", "wan104_realip_state",
	"wan105_state_t", "wan105_sbstate_t", "wan105_auxstate_t", "wan105_realip_ip", "wan105_realip_state",
	"wan106_state_t", "wan106_sbstate_t", "wan106_auxstate_t", "wan106_realip_ip", "wan106_realip_state",
	"wan107_state_t", "wan107_sbstate_t", "wan107_auxstate_t", "wan107_realip_ip", "wan107_realip_state",
	"wan108_state_t", "wan108_sbstate_t", "wan108_auxstate_t", "wan108_realip_ip", "wan108_realip_state",
	"wan109_state_t", "wan109_sbstate_t", "wan109_auxstate_t", "wan109_realip_ip", "wan109_realip_state",
	"wan111_state_t", "wan111_sbstate_t", "wan111_auxstate_t", "wan111_realip_ip", "wan111_realip_state",
	"wan112_state_t", "wan112_sbstate_t", "wan112_auxstate_t", "wan112_realip_ip", "wan112_realip_state",
	"wan113_state_t", "wan113_sbstate_t", "wan113_auxstate_t", "wan113_realip_ip", "wan113_realip_state",
	"wan114_state_t", "wan114_sbstate_t", "wan114_auxstate_t", "wan114_realip_ip", "wan114_realip_state",
	"wan115_state_t", "wan115_sbstate_t", "wan115_auxstate_t", "wan115_realip_ip", "wan115_realip_state",
	"wan116_state_t", "wan116_sbstate_t", "wan116_auxstate_t", "wan116_realip_ip", "wan116_realip_state",
	"wan117_state_t", "wan117_sbstate_t", "wan117_auxstate_t", "wan117_realip_ip", "wan117_realip_state",
	"wan118_state_t", "wan118_sbstate_t", "wan118_auxstate_t", "wan118_realip_ip", "wan118_realip_state",
	"wan119_state_t", "wan119_sbstate_t", "wan119_auxstate_t", "wan119_realip_ip", "wan119_realip_state",
#endif
	NULL
};

int is_var_nvram(const char *name)
{
	int i;
	struct nvram_tuple *t;

	for (i = 0; var_nvram_list[i] != NULL; i++) {
		if (!strcmp(name, var_nvram_list[i]))
			return 1;
	}
	for (t = router_state_defaults; t->name; t++) {
		if (!strcmp(name, t->name))
			return 1;
	}

	return 0;
}

void var_nvram_init()
{
	int i = 0;
	char *p = NULL;
	struct nvram_tuple *t = NULL;
	int modified = 0;

	mkdir(VAR_NVRAM_PATH, 0777);

	for (i = 0; var_nvram_list[i] != NULL; i++) {
		if ((p = internal_nvram_get(var_nvram_list[i]))) {
			var_nvram_set(var_nvram_list[i], p);
			internal_nvram_unset(var_nvram_list[i]);
			if (!modified) modified = 1;
		}
	}
	for (t = router_state_defaults; t->name; t++) {
		if ((p = internal_nvram_get(t->name))) {
			var_nvram_set(t->name, p);
			internal_nvram_unset(t->name);
			if (!modified) modified = 1;
		}
	}

	if (modified) nvram_commit();
}

int var_nvram_getall(char *buf, size_t n)
{
	int i = 0;
	struct nvram_tuple *t = NULL;
	int len = 0;

	for (i = 0; var_nvram_list[i] != NULL; i++) {
		if (var_nvram_get(var_nvram_list[i])
		 && (n - len) > (strlen(var_nvram_list[i]) + 1 + strlen(var_nvram_buf) + 1)
		)
			len += snprintf(buf + len, n - len, "%s=%s", var_nvram_list[i], var_nvram_buf) + 1;
	}
	for (t = router_state_defaults; t->name; t++) {
		if (var_nvram_get(t->name)
		 && (n - len) > (strlen(t->name) + 1 + strlen(var_nvram_buf) + 1)
		)
			len += snprintf(buf + len, n - len, "%s=%s", t->name, var_nvram_buf) + 1;
	}

	return len;
}

#endif //RTCONFIG_VAR_NVRAM
