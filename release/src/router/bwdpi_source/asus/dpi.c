/*
	dpi.c for TrendMicro DPI engine usage
	- all DPI function control and service control
*/

#include "bwdpi.h"

#ifdef RTCONFIG_VPN_FUSION
VPNC_PROFILE vpnc_profile[MAX_VPNC_PROFILE] = {{0}};
int vpnc_profile_num = 0;
#endif

int is_sig_wrs_models_aqos()
{
	int ret = 0;

	switch (get_model()) {
		// add new models here : wrs version / lite version
		case MODEL_RTAX55:
			ret = 1;
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

int is_sig_wrs_models()
{
	int ret = 0;

	switch (get_model()) {
		// add new models here : wrs version / lite version
		case MODEL_MAPAC1750:
#if defined(RTCONFIG_BCMARM)
		case MODEL_RTAX56_XD4:
		case MODEL_CTAX56_XD4:
		case MODEL_XD4PRO:
#endif
#if defined(RTCONFIG_QCA956X)
		case MODEL_RTAC59CD6R:
#endif
#if defined(RTCONFIG_RALINK)
		case MODEL_RT4GAX56:
		case MODEL_RTAX53U:
		case MODEL_XD4S:
#endif
			ret = 1;
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

int model_disable_tdts()
{
	int ret = 0;
	switch (get_model()) {
		default:
			ret = 0;
			break;
	}

	return ret;
}

extern int model_disable_qos()
{
	int ret = 0;
	switch (get_model()) {
		default:
			ret = 0;
			break;
	}

	if (ret) BWDPI_DBG(" MODEL is disabled QoS bit!\n");
	return ret;
}

int check_tdts_module_exist()
{
	int ret = 0;

	if (d_exists(KTDTS) && d_exists(KTDTS_UDB) && d_exists(KTDTS_UDBFW)) ret = 1;
	return ret;
}

int check_daulwan_mode()
{
	if (nvram_match("wans_mode", "lb"))
		return 0;
	else
		return 1;
}

int tdts_check_wan_changed()
{
	int changed = 0;
	char buf[8] = {0};
	char dev_wan[8] = {0};
	char wan_buf[16] = {0};
	char tmp[100] = {0};
	char prefix[sizeof("wanX_XXXXXXX")];
	char wan_proto[8] = {0};
	char ppp_sec_wan[8] = {0};

	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	// the first wan interface
	strlcpy(dev_wan, get_wan_ifname(wan_primary_ifunit()), sizeof(dev_wan));

	// get prefix and wanX_proto
	snprintf(prefix, sizeof(prefix), "wan%d_", wan_primary_ifunit());
	snprintf(wan_proto, sizeof(wan_proto), "%s", nvram_safe_get(strcat_r(prefix, "proto", tmp)));

	// if wan_proto is pppoe / pptp / l2tp, dev_wan = pppX,ethX
	if (!strcmp(wan_proto, "pppoe") || !strcmp(wan_proto, "pptp") || !strcmp(wan_proto, "l2tp")) {
		/* ppp need two interfaces */
		snprintf(ppp_sec_wan, sizeof(ppp_sec_wan), "%s", nvram_safe_get(strcat_r(prefix, "ifname", tmp)));
		snprintf(wan_buf, sizeof(wan_buf), "%s,%s", dev_wan, ppp_sec_wan);
	}
	else {
		snprintf(wan_buf, sizeof(wan_buf), "%s", dev_wan);
	}

	if (f_read_string(WAN_TMP, buf, sizeof(buf)) <= 0)
	{
		// if WAN_TMP = NULL
		f_write_string(WAN_TMP, wan_buf, 0, 0);
		BWDPI_DBG("update WAN_TMP=%s\n", wan_buf);
		changed = -1;
	}
	else
	{
		// if WAN_TMP != NULL
		if (dev_wan != NULL && strcmp(buf, wan_buf)) changed = 1;
		BWDPI_DBG("wan changed!\n");
	}

	BWDPI_DBG("dev_wan=%s, WAN_TMP=%s, changed=%d\n", dev_wan, wan_buf, changed);
	return changed;
}

void save_version_of_bwdpi()
{
	char buf[12], tmp[12];
	memset(buf, 0, sizeof(buf));
	memset(tmp, 0, sizeof(tmp));

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (is_sig_wrs_models() || is_sig_wrs_models_aqos()) {
		// workaround for wrs version
		int n = 0;
		char u[8] = {0};
		char v[8] = {0};
		if (nvram_match("bwdpi_sig_ver", "")) {
			nvram_set("bwdpi_sig_ver", "2.080");
		}
		else {
			system("sig_update.sh");
			if (nvram_match("sig_state_info", "")) {
				nvram_set("bwdpi_sig_ver", "2.082");
			}
			else {
				snprintf(u, sizeof(u), "%s", nvram_safe_get("sig_state_info"));
				for (n = 0; n < sizeof(v); n++) {
					printf("%c\n", u[n]);
					if (n == 0) v[n] = u[n];
					if (n == 1) v[n] = '.';
					if (n > 1) v[n] = u[n-1];
				}
				nvram_set("bwdpi_sig_ver", v);
			}
		}
	}
	else {
		char *i = NULL, *j = NULL;
		int num = 0;
		int sig = 0;
		if (f_exists(SIG_VER))
		{
			system("echo -n `cat /proc/nk_policy | grep Ver | cut -d: -f1 | sed s/Ver-//g | sed s/\\ #\\ policies//g` > /tmp/SIGVER");
			system("cat /tmp/SIGVER");

			if (f_read_string("/tmp/SIGVER", buf, sizeof(buf)) > 0)
			{
				if (vstrsep(buf, ".", &i, &j) != 2) {
					nvram_set("bwdpi_sig_ver", "wrong-signature");
					return;
				}
				sig = atoi(i);
				num = atoi(j);

				if (num < 10)
					snprintf(tmp, sizeof(tmp), "00%d",num);
				else if (num < 100 && num >= 10)
					snprintf(tmp, sizeof(tmp), "0%d",num);
				else if (num < 1000 && num >= 100)
					snprintf(tmp, sizeof(tmp), "%d",num);

				snprintf(buf, sizeof(buf), "%d.%s", sig, tmp);
				nvram_set("bwdpi_sig_ver", buf);
			}

			unlink("/tmp/SIGVER");
		}
	}

	if (f_exists(DPI_VER))
	{
		system("echo -n `cat /proc/ips_info  | grep \"Engine version\" | cut -d: -f2 | sed 's/^[ \t]*//g'` > /tmp/DPIVER");
		if (f_read_string("/tmp/DPIVER", buf, sizeof(buf)) > 0)
			nvram_set("bwdpi_dpi_ver", buf);

		unlink("/tmp/DPIVER");
	}
}

void stop_bwdpi_wred_alive()
{
	eval("killall", "-9", "bwdpi_wred_alive");
}

void start_bwdpi_wred_alive()
{
	char *cmd[] = {"bwdpi_wred_alive", NULL};
	int pid;

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (!is_router_mode())
		return;

	if (!pids("bwdpi_wred_alive"))
		_eval(cmd, NULL, 0, &pid);
}

void stop_dpi_engine_service(int forced)
{
	/*
		forced = 0, not to remove tdts module
		forced = 1, force to remove tdts module and need to recover fc
		forced = 2, force to remove tdts module and never to recover fc
		forced = 3, service : stop_wrs_force
	*/
	if (!check_tdts_module_exist() && forced != 3) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	int enabled = check_bwdpi_nvram_setting();
	BWDPI_DBG("forced=%d, enabled=%d\n", forced, enabled);

	// qosd, tc rule must be clean
	if (dump_dpi_support(INDEX_ADAPTIVE_QOS)) stop_qosd();

	// app patrol must re-configure
	if (!forced) {
		if (dump_dpi_support(INDEX_APPS_FILTER)) wrs_app_service(0);
	}

	// if bwdpi function is disabled or force to stop, kill all serivces
	if (!enabled || forced) {
#if defined(RTCONFIG_HND_ROUTER_AX)
		logmessage("BWDPI", "force to flush flowcache entries\n");
		doSystem("fc disable");
		doSystem("fc flush");
#endif
		stop_bwdpi_wred_alive();
		stop_dc();
		stop_wrs();
		stop_tm_qos();

		/* after remove all modules, need to remove signature, too */
		if (f_exists(APPDB) || f_exists(CATDB) || f_exists(RULEV)) {
			system("rm /tmp/bwdpi/*.db -f"); // can't use eval
		}

#if defined(RTCONFIG_HND_ROUTER_AX)
		if (nvram_get_int("fc_disable") == 0 && forced != 2) {
			logmessage("BWDPI", "rollback fc\n");
			doSystem("fc flush");
			doSystem("fc enable");
		}
#endif
	}
}

static void start_vlan_rule()
{
	// only for vlanX case
	int unit;
	char word[16], tmp[32], prefix[] = "wanXXXXXXXXXX_";

	for (unit = 0; unit < 2; unit++)
	{
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);
		strlcpy(word, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(word));
		if (strstr(word, "vlan"))
			eval("tc", "qdisc", "add", "dev", word, "root", "pfifo");
	}
}

static void start_bwdpi_db_10()
{
	// save database when traffic analyzer is enabled in 10 mins
	char *cmd[] = {"bwdpi_db_10", NULL};
	char *path = NULL;
	int pid;
	int is_run = 1;
	struct stat st;
	off_t cursize;

	/* file exists or not */
	if (!f_exists(BWDPI_ANA_DB)) {
		is_run = 1;
		goto final;
	}

	/* file size */
	path = BWDPI_ANA_DB;
	stat(path, &st);
	cursize = st.st_size;

	if (cursize == 0 || cursize < 5)
		is_run = 1;
	else
		is_run = 0;

	BWDPI_DBG("path=%s, cursize=%ld, is_run=%d\n", path, cursize, is_run);

final:
	if (!pids("bwdpi_db_10") && is_run) {
		_eval(cmd, NULL, 0, &pid);
		logmessage("BWDPI", "start_bwdpi_db_10 for traffic analyzer\n");
	}
}

void setup_pctrl_lib()
{
	/* to avoid some module can't find the right libshn_pctrl.so */
	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	if (!f_exists(SHN_LIB))
		eval("ln", "-sf", "/usr/lib/libshn_pctrl.so", SHN_LIB);
}

#if defined(RTCONFIG_BWDPI) && (defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK))
		/* It's a workaround for QCA / MTK platform due to accelerator / module / vpn can't work together */

#ifdef RTCONFIG_VPN_FUSION
static int vpnc_fusion_active_service_num()
{
	VPNC_PROFILE prof[MAX_VPNC_PROFILE] = {{0}};
	int prof_cnt = 0;
	int i = 0;
	int ret = 0;

	prof_cnt = vpnc_load_profile(prof, MAX_VPNC_PROFILE, VPNC_LOAD_CLIENT_LIST);
	for (i = 0; i < prof_cnt; ++i)
	{
		if (prof[i].active) ret++;
	}

	BWDPI_DBG("prof_cnt=%d, ret=%d\n", prof_cnt, ret);
	return ret;
}
#endif

static check_active_vpn_service()
{
	int ret = 0;

	// PPTP VPN server -> no issue found
	// if (nvram_get_int("pptpd_enable")) ret = 1;

	// OPENVPN VPN server -> no issue found
	// if (nvram_get_int("VPNServer_enable")) ret = 1;

	// IPSec VPN server
	if (nvram_get_int("ipsec_server_enable")) ret = 1;

	// PPTP / L2TP VPN client
	if (!nvram_match("vpnc_proto", "disable")) ret = 1;

	// OPENVPN VPN client
	if (nvram_get_int("VPNClient_enable")) ret = 1;

	// IPSec VPN client
	if (nvram_get_int("ipsec_client_enable")) ret = 1;

	// InstantGuard (IG) IPSec VPN
	if (nvram_get_int("ipsec_ig_enable")) ret = 1;

#ifdef RTCONFIG_VPN_FUSION
	if (vpnc_fusion_active_service_num()) ret = 1;
#endif

	return ret;
}
#endif

/*
	To turn on/off DPI features, echo with these HEX values
	APP_ID      : 0x001
	DEV_ID      : 0x002
	VIRT_PATCH  : 0x004
	WRS_APP     : 0x008
	WRS_CC      : 0x010
	WRS_SEC     : 0x020
	ANOMALY     : 0x040
	QOS         : 0x080
	APP_PATROL  : 0x100
	PATROL_TQ   : 0x200
	WBL         : 0x400
	APP_WBL     : 0x800
*/
#define APP_ID     0
#define DEV_ID     1
#define VP_ID      2
#define WRS_APP    3
#define WRS_CC     4
#define WRS_SEC    5
#define ANOMALY    6
#define QOS_ID     7
#define APP_PATROL 8
#define TIME_QUOTA 9
#define WBL        10
#define APP_WBL    11

void run_dpi_engine_service()
{
	unsigned int cmd = 0;
	char buf[8];
	int illegal_mode = 0;
	int blacklist = 0;

	BWDPI_DBG("DO run_dpi_engine_service()\n");

	/* illegal mode */
	if (repeater_mode() || mediabridge_mode() || access_point_mode() || nvram_get_int("re_mode") == 1) illegal_mode = 1;

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	if (psr_mode()) illegal_mode = 1;
#endif

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_DPSTA)
	if (dpsta_mode() && !nvram_get_int("re_mode") && nvram_get_int("x_Setting")) illegal_mode = 1;
#endif

	if (illegal_mode) {
		BWDPI_DBG("Under illegal mode!\n");
		logmessage("BWDPI", "Under illegal mode!");
		return;
	}

	/* special case : workaround to disable feature for certain reason */
	if (model_disable_tdts()) {
		nvram_set_int("bwdpi_stop", 1);
	}

	blacklist = check_tcode_blacklist();
	if (blacklist) {
		nvram_set_int("bwdpi_stop", 1);
		BWDPI_DBG(" this tcode is under blacklist!\n");
	}

	/*
		For debug mode only : force to stop dpi engine
		bwdpi_stop       : normal to stop dpi engine, it will be reset by init()
		bwdpi_stop_force : debug only 
	*/
	if (nvram_get_int("bwdpi_stop") || nvram_get_int("bwdpi_stop_force")) {
		BWDPI_DBG(" blocked by bwdpi_stop!!!\n");
		return;
	}

	if (model_protection() == 0) {
		BWDPI_DBG("Illegal model!\n");
		logmessage("BWDPI", "Illegal model!");
		return;
	}

	if (check_daulwan_mode() == 0) {
		BWDPI_DBG("DPI engine doesm't support load-balance mode!\n");
		logmessage("BWDPI", "TrendMicro function can't use under load-balance mode!");
		return;
	}

	int FULL = nvram_get_int("wrs_protect_enable");
	int MALS = nvram_get_int("wrs_mals_enable");
	int VP = nvram_get_int("wrs_vp_enable");
	int CC = nvram_get_int("wrs_cc_enable");

	// insert dpi engine
	start_tm_qos();

	// workaround for libshn_pctrl.so
	setup_pctrl_lib();

	// default
#if !defined(RTCONFIG_QCA956X)
	cmd = (1 << APP_ID) | (1 << DEV_ID);
#endif

	// wrs (web filter)
	if (nvram_get_int("wrs_enable") && dump_dpi_support(INDEX_WEBS_FILTER))
		cmd |= (1 << WRS_APP) | (1 << WBL);

	// C&C
	if ((FULL & CC) && dump_dpi_support(INDEX_CC))
		cmd |= (1 << WRS_CC) | (1 << WRS_APP) | (1 << WBL);

	// wrs mals (web filter)
	if ((FULL & MALS) && dump_dpi_support(INDEX_MALS))
		cmd |= (1 << WRS_SEC) | (1 << WBL);

	// enable wrs for wrs_url
	if (nvram_get_int("bwdpi_wh_enable") && dump_dpi_support(INDEX_WEB_HISTORY)) {
		cmd |= (1 << WRS_SEC);
	}

	setup_wrs_conf();

	// VP and Anomaly
	if (FULL & VP && dump_dpi_support(INDEX_VP))
		cmd |= (1 << VP_ID) | (1 << ANOMALY);

	// APP filters
	if (nvram_get_int("wrs_app_enable") && dump_dpi_support(INDEX_APPS_FILTER)) {
		cmd |= (1 << APP_PATROL);
		wrs_app_service(1);
	}
	else {
		wrs_app_service(0);
	}

	// adaptive qos
	if (IS_AQOS() && dump_dpi_support(INDEX_ADAPTIVE_QOS) && (model_disable_qos() == 0)) {
#if defined(RTCONFIG_BWDPI) && (defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK))
		/* It's a workaround for QCA / MTK platform due to accelerator / module / vpn can't work together */
		if (check_active_vpn_service() == 0)
#endif
		cmd |= (1 << QOS_ID);
	}

	// debug mode will overwrite the bitmap
	char *debug_bit = nvram_safe_get("bwdpi_debug_bit");
	int new_bit = -1;
	
	if (strcmp(debug_bit, "")) {
		new_bit = strtol(debug_bit, NULL, 16);
		if (new_bit >= 0) cmd = new_bit;
		BWDPI_DBG(" debug_bit=%d(%x)\n", new_bit, new_bit);
	}

	// set dpi engine conf
	snprintf(buf, sizeof(buf), "%x", cmd);
	f_write_string(BW_DPI_SET, buf, 0, 0);
	BWDPI_DBG("buf=%s, cmd=%d(%x)\n", buf, cmd, cmd);
	logmessage("BWDPI", "fun bitmap = %s\n", buf);

	// run data_colld
	start_dc(NULL);

	// run wred and wred_set_conf
	start_wrs();

	// check EULA
	tm_eula_check();

	// get engine and signature version
	save_version_of_bwdpi();

	// check wred alive
	start_bwdpi_wred_alive();

	if (is_sig_wrs_models() == 0) {
		// non-wrs version

		// adaptive qos
		if (IS_AQOS() && dump_dpi_support(INDEX_ADAPTIVE_QOS) && (model_disable_qos() == 0)) {
#if defined(RTCONFIG_BWDPI) && (defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK))
		/* It's a workaround for QCA / MTK platform due to accelerator / module / vpn can't work together */
			if (check_active_vpn_service() == 0)
#endif
			start_qosd();
		}
		else if (IS_NON_AQOS()) {
			// do nothing
		}
		else {
			stop_qosd();
		}

		// fix dead loop message when use vlanX
		if (check_tdts_module_exist()) start_vlan_rule();

		// save database when traffic analyzer is enabled in 10 mins
		if (nvram_get_int("bwdpi_db_enable") && check_tdts_module_exist()) {
			start_bwdpi_db_10();
		}
	}

	// for autotest
	setup_dpi_support_bitmap();

#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
	// MTK7621 workaround : disable TSO to improve NAT performance
	system("ethtool -K br0 tso off");
	system("ethtool -K eth1 tso off");
	logmessage("BWDPI", "disable TSO ...\n");
	// MTK7621 workaround : dcd is abnormal
	sleep(5);
	system("bwdpi dc restart");
	logmessage("BWDPI", "restart dcd ...\n");
#endif

}

void start_dpi_engine_service()
{
	if (check_bwdpi_nvram_setting()) {
		run_dpi_engine_service();
	}
}

void setup_dpi_conf_bit(int input)
{
	unsigned int cmd = 0;
	char buf[8];

	int FULL = nvram_get_int("wrs_protect_enable");
	int MALS = nvram_get_int("wrs_mals_enable");
	int VP = nvram_get_int("wrs_vp_enable");
	int CC = nvram_get_int("wrs_cc_enable");

	if (input < -2 || input > 10) return;

	// default
	cmd = (1 << APP_ID) | (1 << DEV_ID);

	// wrs (web filter)
	if (nvram_get_int("wrs_enable") && dump_dpi_support(INDEX_WEBS_FILTER) && input != 0)
		cmd |= (1 << WRS_APP);

	// C&C
	if ((FULL & CC) && dump_dpi_support(INDEX_CC) && input != 4)
		cmd |= (1 << WRS_CC) | (1 << WRS_APP);

	// wrs mals (web filter)
	if ((FULL & MALS) && dump_dpi_support(INDEX_MALS) && input != 5)
		cmd |= (1 << WRS_SEC);

	// VP and Anomaly
	if (FULL & VP && dump_dpi_support(INDEX_VP) && input != 2)
		cmd |= (1 << VP_ID) | (1 << ANOMALY);

	// APP filters
	if (nvram_get_int("wrs_app_enable") && dump_dpi_support(INDEX_APPS_FILTER) && input != 8)
		cmd |= (1 << APP_PATROL);

	// adaptive qos
	if (IS_AQOS() && dump_dpi_support(INDEX_ADAPTIVE_QOS) && input != 7) {
		cmd |= (1 << QOS_ID);
	}

	// set dpi engine conf
	snprintf(buf, sizeof(buf), "%x", cmd);
	f_write_string(BW_DPI_SET, buf, 0, 0);
	BWDPI_DBG("buf=%s, cmd=%d(%x)\n", buf, cmd, cmd);
}

/*
	the service only trigger to setup_wrs_conf()
*/
void start_wrs_wbl_service()
{
	if (check_bwdpi_nvram_setting() == 0) {
		BWDPI_DBG(" dpi engine is disabled\n");
		return;
	}

	if (IS_IDPFW() == 0 || check_tdts_module_exist() == 0) {
		BWDPI_DBG(" fail to get /dev/idpfw\n");
		return;
	}

	setup_wrs_conf();
}

void MobileDevMode_restart()
{
	if (IS_NON_AQOS()) {
		BWDPI_DBG(" A.QoS mode is disabled\n");
		return;
	}

	if (IS_IDPFW() == 0 || check_tdts_module_exist() == 0) {
		BWDPI_DBG(" fail to get /dev/idpfw\n");
		return;
	}

	// generate config
	setup_qos_conf();

	// iqos off
	doSystem("%s -a set_qos_off", SHN_CTRL);

	// load conf into tdts
	doSystem("%s -a set_qos_conf -R %s", SHN_CTRL, QOS_CONF);

	// iqos on
	doSystem("%s -a set_qos_on", SHN_CTRL);
}
