/*
	iqos.c for TrendMicro iQoS / qosd
	iqos :
		only run DPI engine related services
	qosd :
		only run qosd and build tc rule
*/

#include "bwdpi.h"

/* static global var */
static int qos_check = 0; // check qos status success or fail
static int qos_count = 0; // qos retry times

/* rule buffer */
#define MOBILE_DEV_BUF 2048

/*
	check dpi moudle exists or not
*/
static int dpi_module_check()
{
	if (!f_exists(DEV_WAN) || !f_exists(QOS_WAN))
		return 0;
	else
		return 1;
}

static int MoibleRuleCheck(const char *key)
{
	char *p = NULL;
	char *g = NULL;
	char tmp[MOBILE_DEV_BUF] = {0};
	int count = 0;

	strlcpy(tmp, nvram_safe_get(key), sizeof(tmp));
	g = &tmp[0];

	while (g) {
		if ((p = strsep(&g, "<")) == NULL) break;
		toUpperCase(p); // make sure MAC format is upper
		if (isValidMacAddress(p) == 0) continue;  // MAC validation
		count++;
	}

	return count;
}

#define GAME_LIST     0x01
#define STREAM_LIST   0x02
static int MobileDevMode_enable()
{
	int ret = 0;

	// Game Mode
	if (MoibleRuleCheck("bwdpi_game_list")) {
		BWDPI_DBG(" bwdpi_game_list exists\n");
		ret |= GAME_LIST;
	}

	// Stream Mode
	if (MoibleRuleCheck("bwdpi_stream_list")) {
		BWDPI_DBG(" bwdpi_stream_list exists\n");
		ret |= STREAM_LIST;
	}

	return ret;
}

static void MobileDevRule(FILE *fp, const char *key)
{
	char *p = NULL;
	char *g = NULL;
	char tmp[MOBILE_DEV_BUF] = {0};

	strlcpy(tmp, nvram_safe_get(key), sizeof(tmp));
	g = &tmp[0];

	while (g) {
		if ((p = strsep(&g, "<")) == NULL) break;
		BWDPI_DBG(" p=%s\n", p);
		toUpperCase(p); // make sure MAC format is upper
		if (isValidMacAddress(p) == 0) continue;  // MAC validation
		fprintf(fp, "mac=%s\n", p);
	}
}

static void set_prio_appcat(FILE *fp, char *buf, int count)
{
	char *g = NULL, *p = NULL;
	int cat_rate[8] = {5, 20, 10, 5, 4, 3, 2, 1}; // initial value

	// reserved rate
	fprintf(fp, "[%d, %d%s]\n", count, cat_rate[count], "%");

	// app catid
	g = buf;

	// fixed app rule
	if (count == 0) fputs("rule=18\nrule=19\n", fp);
	if (count == 4) fputs("rule=28\nrule=29\nrule=30\nrule=31\nrule=32\nrule=33\nrule=34\nrule=35\nrule=36\nrule=37\nrule=38\nrule=39\nrule=40\nrule=41\nrule=42\nrule=43\n", fp);
	if (count == 5) fputs("rule=12\n", fp);

	if (!strcmp(buf, "")) {
		fprintf(fp, "rule=na\n");
	}
	else {
		while (g) {
			if ((p = strsep(&g, ",")) != NULL) {
				fprintf(fp, "rule=%s\n", p);
			}
		}
	}
}

/* Move the key value into the first order */
void AppRuleModify(char *in, char *key, char *out)
{
	char *a = NULL;
	char *b = NULL;
	char *c = NULL;
	char *d = NULL;
	char *e = NULL;
	char *f = NULL;
	char *g = NULL;
	char *h = NULL;
	char *i = NULL;
	int len_s = 0;

	if (in == NULL || !strcmp(in, "")) return;
	len_s = strlen(in) + 1;

	BWDPI_DBG(" 1. in=%s, key=%s, out=%s, len_s=%d\n", in, key, out, len_s);
	if ((vstrsep(in, "<", &a, &b, &c, &d, &e, &f, &g, &h, &i)) != 9) return;

	if (!strcmp(a, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", a, b, c, d, e, f, g, h, i);
	else if (!strcmp(b, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", b, a, c, d, e, f, g, h, i);
	else if (!strcmp(c, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", c, a, b, d, e, f, g, h, i);
	else if (!strcmp(d, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", d, a, b, c, e, f, g, h, i);
	else if (!strcmp(e, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", e, a, b, c, d, f, g, h, i);
	else if (!strcmp(f, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", f, a, b, c, d, e, g, h, i);
	else if (!strcmp(g, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", g, a, b, c, d, e, f, h, i);
	else if (!strcmp(h, key)) snprintf(out, len_s, "%s<%s<%s<%s<%s<%s<%s<%s<%s", h, a, b, c, d, e, f, g, i);
	else strlcpy(out, "", sizeof(out));

	BWDPI_DBG(" 2. out=%s\n", out);
}

static void set_prio_app(FILE *fp)
{
	char *p = NULL;
	char *g = NULL;
	int count = 0;
	char in[100] = {0};
	char tmp[100] = {0};
	char out[100] = {0};
	int enable = MobileDevMode_enable();

	/* ASUSWRT
		bwdpi_app_rulelist :
		[PRIO 0]<[PRIO 1]<[PRIO 2]<[PRIO 3]<[PRIO 4]<[PRIO 5]<[PRIO 6]<[PRIO 7]<[PRIO8]<[type]
		[PRIO x] = cat1,cat2,...
		ex. 9,20<8<4<0,5,6,15,17<4,13<13,24<1,3,14<7,10,11,21,23<
	*/
	strlcpy(in, nvram_safe_get("bwdpi_app_rulelist"), sizeof(in));

	g = &in[0];
	while (g) {
		if ((p = strsep(&g, "<")) == NULL) break;
		count++;
	}

	if (count != 9) {
		BWDPI_DBG(" bwdpi_app_rulelist is broken, revert this nvram!!\n");
		logmessage("A.QoS", "bwdpi_app_rulelist is broken, revert this nvram!!\n");
		nvram_set("bwdpi_app_rulelist", "9,20<8<4<0,5,6,15,17<4,13<13,24<1,3,14<7,10,11,21,23<");
		strlcpy(in, nvram_safe_get("bwdpi_app_rulelist"), sizeof(in));
	}

	// reset
	strlcpy(in, nvram_safe_get("bwdpi_app_rulelist"), sizeof(in));
	count = 0;

	/*
		GAME   CAT ID = 8
		STREAM CAT ID = 4
	*/

	// STREAM
	if (enable & STREAM_LIST) {
		AppRuleModify(in, "4", out);  // string "4"
	}

	if (strcmp(out, "")) strlcpy(in, out, sizeof(in));

	// GAME
	if (enable & GAME_LIST) {
		AppRuleModify(in, "8", out);  // string "8"
	}

	if (strcmp(out, "")) strlcpy(tmp, out, sizeof(tmp));
	BWDPI_DBG(" enable=%d, in=%s, out=%s, tmp=%s\n", enable, in, out, tmp);

	if (enable == 0 || !strcmp(tmp, "")) {
		strlcpy(tmp, nvram_safe_get("bwdpi_app_rulelist"), sizeof(tmp));
	}
	g = &tmp[0];

	while (g && count < 8) {
		if ((p = strsep(&g, "<")) == NULL) break;
		BWDPI_DBG(" set_prio_app = %s\n", p);
		set_prio_appcat(fp, p, count);
		count++;
	}
}

static void set_prio_dev(FILE *fp)
{
	fputs("{0}\n", fp);
	fputs("{1}\n", fp);
	if (MobileDevMode_enable()) {
		MobileDevRule(fp, "bwdpi_game_list");
		MobileDevRule(fp, "bwdpi_stream_list");
	}
	fputs("{2}\nfam=1\nfam=2\nfam=3\nfam=4\nfam=5\nfam=6\nfam=7\nfam=8\n", fp);
	fputs("{3}\nfam=na\n", fp);
	fputs("{4}\n", fp);
}

void setup_qos_conf()
{
	FILE *fp = NULL;
	double ibw ,obw;

	// because of UI is kbps, but setting file is KBps
#ifdef RTCONFIG_MULTIWAN_CFG
	if (wan_primary_ifunit()) {
		ibw = strtoul(nvram_safe_get("qos_ibw1"), NULL, 10) / 8;
		obw = strtoul(nvram_safe_get("qos_obw1"), NULL, 10) / 8;
	}
	else {
		ibw = strtoul(nvram_safe_get("qos_ibw"), NULL, 10) / 8;
		obw = strtoul(nvram_safe_get("qos_obw"), NULL, 10) / 8;
	}
#else
	ibw = strtoul(nvram_safe_get("qos_ibw"), NULL, 10) / 8;
	obw = strtoul(nvram_safe_get("qos_obw"), NULL, 10) / 8;
#endif

	// For AiHome APP spec
	if (ibw == 0) {
		ibw = 10 * 1024 * 1024 / 8; // 10Gbps = 1.25GBps
		printf("set ibw into 10Gbps due to unlimited\n");
	}

	// For AiHome APP spec
	if (obw == 0) {
		obw = 10 * 1024 * 1024 / 8; // 10Gbps = 1.25GBps
		printf("set ibw obw into 10Gbps due to unlimited\n");
	}

	if ((fp = fopen(QOS_CONF, "w")) == NULL) {
		printf("FAIL to open %s\n", QOS_CONF);
		return;
	}

	fprintf(fp, "ceil_down=%.3fkbps\n", ibw);
	fprintf(fp, "ceil_up=%.3fkbps\n", obw);

	// set app rule
	set_prio_app(fp);

	// set dev rule (cat or fam)
	set_prio_dev(fp);

	// close file
	if (fp) fclose(fp);
}

void stop_tm_qos()
{
#if defined(RTCONFIG_SOC_IPQ8064) || defined(RTCONFIG_SOC_IPQ8074)
	// need to setup pcc_stop to unregister
	f_write_string("/proc/pcc_stop", "1", 0, 0);
	BWDPI_DBG("echo 1 > /proc/pcc_stop\n");
#endif

	// step1. remove module
	eval("rmmod", "tdts_udbfw.ko", ">", "/dev/null", "2>&1");
	eval("rmmod", "tdts_udb.ko", ">", "/dev/null", "2>&1");
	eval("rmmod", "tdts.ko", ">", "/dev/null", "2>&1");

	// step2. remove dev nodes
	eval("rm", "-f", DEVNODE);
	eval("rm", "-f", "/dev/idpfw");

	// step3. clean DPI engine mangle rule
	eval("iptables", "-t", "mangle", "-F", "BWDPI_FILTER");
	eval("iptables", "-t", "mangle", "-F", "PREROUTING");
}

static void hw_qos_workaround()
{
#if defined(RTCONFIG_RALINK_MT7622)
	doSystem("echo 1 65535 >/sys/kernel/debug/hnat/hnat_setting");
	BWDPI_DBG("MTK7622 hwnat qos workaround!\n");
#endif
}

/*
	update sig_type : FULL / PART / WRS
*/
#define SIG_TYPE "/tmp/sig_type"
static void update_sig_type()
{
	char buf[12];

	doSystem("grep MemTotal /proc/meminfo | awk \'{print $2}\' > %s", SIG_TYPE);
	if (f_read_string(SIG_TYPE, buf, sizeof(buf)) > 0) {
		if (atoi(buf) > 128000)
			nvram_set("sig_type", "FULL");
		else 
			nvram_set("sig_type", "PART");
	}
	else {
		nvram_set("sig_type", "FULL");
	}

	if (is_sig_wrs_models() || is_sig_wrs_models_aqos()) {
		nvram_set("sig_type", "WRS");
	}

	/* special case */
	if (nvram_match("productid", "RT-ACRH26")) {
		nvram_set("sig_type", "PART");
	}

	if (f_exists(SIG_TYPE)) unlink(SIG_TYPE);
}

/*
	check signature update or not
	if NO , tar original source; if YES, tar new source.
*/
static void run_signature_check()
{
	int checked = nvram_get_int("bwdpi_rsa_check");
	char *path = DATABASE;

	/* update sig_type */
	update_sig_type();

	// step1. check debug mode or not
	if (nvram_get_int("bwdpi_debug_path")) {
		BWDPI_DBG("1 - run signature from %s\n", path);
		chdir(TMP_BWDPI);
		eval(AGENT, "-g", "-r", path);
		chdir("/");
		goto final;
	}

	// step2. signature update or not
	if (checked && (f_exists("/jffs/signature/rule.trf"))) {
		path = "/jffs/signature/rule.trf";
		BWDPI_DBG("2 - run signature from %s\n", path);
		chdir(TMP_BWDPI);
		eval(AGENT, "-g", "-r", path);
		chdir("/");
	}

final:
	// step3. check signature exist or not
	if (!f_exists(APPDB) || !f_exists(CATDB) || !f_exists(RULEV)) {
		path = "/usr/bwdpi/rule.trf";
		BWDPI_DBG("3 - run signature from %s\n", path);
		chdir(TMP_BWDPI);
		eval(AGENT, "-g", "-r", path);
		chdir("/");
	}
}

int check_lan_status()
{
	int s;
	int ret = 0;
        struct ifreq ifr;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return -1;

        memset(&ifr, 0x0, sizeof(ifr));
	strlcpy(ifr.ifr_name, nvram_safe_get("lan_ifname"), IFNAMSIZ);

	if (ioctl(s, SIOCGIFFLAGS, &ifr)) {
		ret = -1;
		goto error;
	}

        if (!(ifr.ifr_flags & IFF_UP)) {
		ret = -1;
		goto error;
        }

error:
	close(s);
	return ret;
}

void ProgControl3_PEM()
{
	if (!f_exists(KEYENC) || !f_exists(MODELENC)) {
		eval("cp", "/usr/bwdpi/key.enc", TMP_BWDPI, "-f");
		eval("cp", "/usr/bwdpi/model.enc", TMP_BWDPI, "-f");
		BWDPI_DBG("copy *.enc ...\n");
	}

	if (!f_exists(SHNPEM)) {
		eval("cp", "/usr/bwdpi/shn.pem", TMP_BWDPI, "-f");
		BWDPI_DBG("copy *.pem ...\n");
	}
}

void start_tm_qos()
{
	char buf[256];
	char dev_wan[8] = {0};
	char dev_wan_phy[8] = {0};
	char dev_lan[8] = {0};
	char *qos_wan = dev_wan;
	char tmp[100] = {0};
	char prefix[sizeof("wanX_XXXXXXX")];
	char wan_proto[8] = {0};
	char ppp_sec_wan[8] = {0};
	char wan_buf[200] = {0};
	char *p = NULL;

	strlcpy(dev_wan, get_wan_ifname(wan_primary_ifunit()), sizeof(dev_wan));
	strlcpy(dev_wan_phy, ((p = nvram_get("wan_ifname")) != NULL && *p != 0) ? p : "eth0" , sizeof(dev_wan_phy));
	strlcpy(dev_lan, nvram_safe_get("lan_ifname"), sizeof(dev_lan));
	snprintf(prefix, sizeof(prefix), "wan%d_", wan_primary_ifunit());
	snprintf(wan_proto, sizeof(wan_proto), "%s", nvram_safe_get(strcat_r(prefix, "proto", tmp)));

	memset(buf, 0, sizeof(buf));

	if (!is_router_mode())
		return;

	if (check_lan_status() != 0)
		return;

#if defined(RTCONFIG_DSL_BCM)
	{
		int pri_unit = wan_primary_ifunit();
		char word[16] = {0};
		char wan_ifnames[32] = {0};
		char *p = NULL;
		int unit = WAN_UNIT_FIRST;
		nvram_safe_get_r("wan_ifnames", wan_ifnames, sizeof(wan_ifnames));
		foreach (word, wan_ifnames, p) {
			if (unit == pri_unit) {
				strlcpy(dev_wan_phy, word , sizeof(dev_wan_phy));
				break;
			}
			unit++;
		}

		if (get_dualwan_by_unit(pri_unit) == WANS_DUALWAN_IF_WAN
		 && nvram_get_int("fc_disable") == 0
		) {
			doSystem("fc enable");
		}
		else {
			doSystem("fc flush");
			doSystem("fc disable");
		}
	}
#endif

	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	/* ProgControl3 : *.pem / *.enc */
	ProgControl3_PEM();

	// step1. create dev node
	if (!f_exists(DEVNODE))
		eval("mknod", DEVNODE, "c", "190", "0");
	if (!f_exists("/dev/idpfw"))
		eval("mknod", "/dev/idpfw", "c", "191", "0");

#if 0
	/* remove mangle rules due to RU ISP DHCP issue */
	// step2. setup iptables rules
	eval("iptables", "-t", "mangle", "-N", "BWDPI_FILTER");
	eval("iptables", "-t", "mangle", "-F", "BWDPI_FILTER");
	eval("iptables", "-t", "mangle", "-A", "BWDPI_FILTER", "-i", dev_wan, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "DROP");

	/*
		workaround to solve DHCP IPoE issue by removing mangle rule, customer will lost Internet ability for the second 10 mins.
	*/
	//eval("iptables", "-t", "mangle", "-A", "BWDPI_FILTER", "-i", dev_wan, "-p", "udp", "--sport", "67", "--dport", "68", "-j", "DROP");
	eval("iptables", "-t", "mangle", "-A", "PREROUTING", "-i", dev_wan, "-p", "udp", "-j", "BWDPI_FILTER");
#endif

	// step3. insert DPI engine
	eval("insmod", TDTS);

	// step4. run bwdpi-rule-agent
	run_signature_check();

	// step5. insert UDB and Forward module
	memset(wan_buf, 0, sizeof(wan_buf));
	if (!strcmp(dev_wan, "")) {
		snprintf(wan_buf, sizeof(wan_buf), dev_wan_phy);
	}

	// if wan_proto is pppoe / pptp / l2tp, dev_wan = pppX,ethX
	if (!strcmp(wan_proto, "pppoe") || !strcmp(wan_proto, "pptp") || !strcmp(wan_proto, "l2tp")
#ifdef RTCONFIG_SOFTWIRE46
	    || is_s46_service()
#endif
	) {
		/* ppp need two interfaces */
		snprintf(ppp_sec_wan, sizeof(ppp_sec_wan), "%s", nvram_safe_get(strcat_r(prefix, "ifname", tmp)));
		snprintf(wan_buf, sizeof(wan_buf), "%s,%s", dev_wan, ppp_sec_wan);
	}
	else {
		snprintf(wan_buf, sizeof(wan_buf), "%s", dev_wan);
	}

#ifdef RTCONFIG_WIREGUARD
	/* wireguard vpn client */
	strlcat(wan_buf, ",wgc1,wgc2,wgc3,wgc4,wgc5", sizeof(wan_buf));
#endif

	// lite signature workaround for pptp / openvpn can't surf Internet issue 
	if (is_sig_wrs_models()) {
		strlcat(wan_buf, ",pptp0,pptp1,pptp2,pptp3,pptp4,pptp5,pptp6,pptp7,pptp8,pptp9,tun21,wgs1,wgs2", sizeof(wan_buf));
	}

	// step6. special case for low memory models
	// TODO : if found some models with low memory, need to adjust the parameters
	int sess = 30000;
	switch (get_model()) {
		case MODEL_RTAC85U:
		case MODEL_RTAC85P:
		case MODEL_RTACRH26:
			sess = 3000;
			break;
		default:
			sess = 30000;
			break;
	}

#ifdef RTCONFIG_BCMARM
	// if BRCM platform use "eth0" for all wan proto
	qos_wan = dev_wan_phy;
#endif

#if (defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X))
	snprintf(buf, sizeof(buf),"dev_wan=%s dev_lan=%s sess_num=%d user_timeout=3600 app_timeout=3600", wan_buf, dev_lan, sess);
#else
	snprintf(buf, sizeof(buf),"dev_wan=%s qos_wan=%s qos_lan=%s sess_num=%d user_timeout=3600 app_timeout=3600", wan_buf, qos_wan, dev_lan, sess);
#endif
	BWDPI_DBG("buf=%s\n", buf);
	eval("insmod", UDB, buf);
	eval("insmod", UDBFW);

	// step6. chmod 644 for parameters
	eval("chmod", "0644", TDTSFW_PARA, "-R");

	// update dev_wan for next checking in tdts_check_wan_changed()
	f_write_string(WAN_TMP, wan_buf, 0, 0);
}

int tm_qos_main(char *cmd)
{
	if (!strcmp(cmd, "restart")) {
		stop_tm_qos();
		start_tm_qos();
	}
	else if (!strcmp(cmd, "stop")) {
		stop_tm_qos();
	}
	else if (!strcmp(cmd, "start")) {
		start_tm_qos();
	}
	return 1;
}

void stop_qosd()
{
	int ret = 0;

	// avoid to clean tc rule in T.QoS or BW limiter
	if (IS_NON_AQOS()) {
		BWDPI_DBG("T.QoS or BW limiter is running, shouldn't remove tc rule\n");
		return;
	}

	// flush wan_ifname
	ret = doSystem("tc qdisc del dev %s root 2>/dev/null", get_wan_ifname(wan_primary_ifunit()));
	BWDPI_DBG("flush wan_ifname, ret=%d\n", ret);

	// flush lan_ifname
	ret = doSystem("tc qdisc del dev %s root 2>/dev/null", nvram_safe_get("lan_ifname"));
	BWDPI_DBG("flush lan_ifname, ret=%d\n", ret);

	// set qos off
	ret = doSystem("%s -a set_qos_off", SHN_CTRL);
	BWDPI_DBG("set_qos_off, ret=%d\n", ret);
	sleep(1);
	if (ret > 0) {
		logmessage("A.QoS", "set_qos_off, ret=%d\n", ret);
	}

	// kill tcd
	if (pids(TCD)) {
		eval("killall", "-9", TCD);
	}
}

static int check_qosd_restart()
{
	BWDPI_DBG("qos_count=%d, qos_check=%d\n", qos_count, qos_check);
	logmessage("A.QoS", "qos_count=%d, qos_check=%d\n", qos_count, qos_check);

	// initial
	int ret = 0, ret1 = 0, ret2 = 0;
	int reconfig = 0;

	// step1. run tcd daemon
	char *cmd1[] = {TCD, NULL};
	int pid;
	if (!pids(TCD)) {
		chdir(TMP_BWDPI);
		_eval(cmd1, "/dev/null", 0, &pid);
		chdir("/");
	}

	// step2. setup QOS_CONF
	setup_qos_conf();

	// step3. read conf via ioctl
	ret1 = doSystem("%s -a set_qos_conf -R %s", SHN_CTRL, QOS_CONF);
	BWDPI_DBG("set_qos_conf, ret1=%d\n", ret1);
	if (ret1 > 0) {
		logmessage("A.QoS", "set_qos_conf fails\n");
		reconfig = 1;
		goto final;
	}

	// step4. set_qos_on
	ret2 = doSystem("%s -a set_qos_on", SHN_CTRL);
	BWDPI_DBG("set_qos_on, ret2=%d\n", ret2);
	if (ret2 > 0) {
		logmessage("A.QoS", "set_qos_on fails\n");
		reconfig = 1;
		goto final;
	}

	// step5. check A.QoS rule can't be less than 22 rules
	char buf[4];
	sleep(3);
	ret = doSystem("tc qdisc show | wc -l > %s", QOS_TMP);
	BWDPI_DBG("tc qdisc show | wc -l, ret=%d\n", ret);

	if (f_read_string(QOS_TMP, buf, sizeof(buf)) > 0) {
		if (atoi(buf) < 22) {
			logmessage("A.QoS", "qos rule is less than 22\n");
			reconfig = 1;
			goto final;
		}
	}

final:
	if (reconfig == 1) {
		BWDPI_DBG("restart A.QoS because set_qos_conf / set_qos_on / setup rule fail\n");
		logmessage("A.QoS", "restart A.QoS because set_qos_conf / set_qos_on / setup rule fail\n");
	}

	/* hw qos workaround */
	hw_qos_workaround();

	return reconfig;
}

/*
	HND / AXHND : tc rule can't be established well once, need to clean and re-establish
	In BCM6750/6755, tc rule is established via netlink, it's too slow (10~15 secs), so we adjust to check 1 time
*/
#define QOS_RESTART_COUNT  1

void start_qosd()
{
	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (!is_router_mode())
		return;

	if (nvram_get_int("qos_enable") == 0 || nvram_get_int("qos_type") == 0 || dump_dpi_support(INDEX_ADAPTIVE_QOS) == 0) {
		BWDPI_DBG("Adaptive QoS is disabled!!\n");
		return;
	}

	if (check_daulwan_mode() == 0) {
		BWDPI_DBG("Adaptive QoS doesn't support load-balance mode!\n");
		return;
	}

	if (!f_exists(TMP_BWDPI))
		mkdir(TMP_BWDPI, 0666);

	if (dpi_module_check() == 0) {
		BWDPI_DBG("DPI engine module doesn't exist!!\n");
		return;
	}

	// check result to decide whether restart qos again
	qos_check = check_qosd_restart();
	while (qos_count < QOS_RESTART_COUNT && qos_check == 1) {
		stop_qosd();
		qos_check = check_qosd_restart();
		qos_count++;
	}
	qos_count = 0;
}

int qosd_main(char *cmd)
{
	if (!strcmp(cmd, "restart")) {
		stop_qosd();
		start_qosd();
	}
	else if (!strcmp(cmd, "stop")) {
		stop_qosd();
	}
	else if (!strcmp(cmd, "start")) {
		start_qosd();
	}
	return 1;
}
