/*
	Copyright 2005, Broadcom Corporation
	All Rights Reserved.

	THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
	KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
	SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
	FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.

*/

#include "rc.h"

#include <termios.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <time.h>
#include <errno.h>
#include <paths.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <sys/klog.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <linux/mii.h>
#include <wlutils.h>
#include <bcmdevs.h>

#include <shared.h>

#ifdef RTCONFIG_LANTIQ
#include <lantiq.h>
#include <flash_mtd.h>
#endif

#if defined(RTCONFIG_NEW_REGULATION_DOMAIN)
#error !!!!!!!!!!!QCA driver must use country code!!!!!!!!!!!
#endif
static struct load_wifi_kmod_seq_s {
	char *kmod_name;
	int stick;
	unsigned int load_sleep;
	unsigned int remove_sleep;
} load_wifi_kmod_seq[] = {
	// { "mem_manager", 1, 0, 0 },	/* If QCA WiFi configuration file has WIFI_MEM_MANAGER_SUPPORT=1 */
	{ "asf", 0, 0, 0 },
	{ "adf", 0, 0, 0 },
	{ "ath_hal", 0, 0, 0 },
	{ "ath_rate_atheros", 0, 0, 0 },
	{ "ath_dfs", 0, 0, 0 },
	{ "ath_spectral", 0, 0, 0 },
	{ "hst_tx99", 0, 0, 0 },
	{ "ath_dev", 0, 0, 0 },
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
	{ "umac", 0, 0, 2 },
#else
	{ "umac", 0, 0, 2 },
#endif
	// { "ath_pktlog", 0, 0, 0 },
	// { "smart_antenna", 0, 0, 0 },
};

int is_if_up(char *ifname)
{
	int s;
	struct ifreq ifr;

	/* Open a raw socket to the kernel */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return -1;

	/* Set interface name */
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	/* Get interface flags */
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0){
		fprintf(stderr, "SIOCGIFFLAGS error\n");
	}else{
		if(ifr.ifr_flags & IFF_UP){
			fprintf(stderr, "%s is up\n", ifname);
			close(s);
			return 1;
		}
	}
	close(s);
	return 0;
}

static void __mknod(char *name, mode_t mode, dev_t dev)
{
	if (mknod(name, mode, dev)) {
		printf("## mknod %s mode 0%o fail! errno %d (%s)", name, mode, errno, strerror(errno));
	}
}

void init_devs(void)
{
}

void init_devs_defer(void)
{
	int status;

	__mknod("/dev/nvram", S_IFCHR | 0666, makedev(228, 0));
	if ((status = WEXITSTATUS(modprobe("nvram_linux"))))
		printf("## modprove(nvram_linux) fail status(%d)\n", status);

	fprintf(stderr, "BLUECAVE: init gpio\n");
	/* reset button */
	gpio_dir(0, GPIO_DIR_IN);
	/* wps button */
	gpio_dir(30, GPIO_DIR_IN);

	/* LED */
	gpio_dir(1, GPIO_DIR_OUT);
	set_gpio(1, 0);
	gpio_dir(4, GPIO_DIR_OUT);
	set_gpio(4, 0);
	gpio_dir(6, GPIO_DIR_OUT);
	set_gpio(6, 1);
	gpio_dir(8, GPIO_DIR_OUT);
	set_gpio(8, 0);
	system("mem -s 0x16c80128 -uw 0x00; mem -s 0x16c80194 -uw 0x00000003");
	gpio_dir(42, GPIO_DIR_OUT);
	set_gpio(42, 0);

	/* Bluetooth */
	gpio_dir(43, GPIO_DIR_OUT);
	set_gpio(43, 1);

	check_ubi_partition();
	_dprintf("start_jffs2() start\n");
	start_jffs2();
	_dprintf("start_jffs2() end\n");
}

void init_gpio_again(void)
{
	fprintf(stderr, "BLUECAVE: init gpio again\n");
	/* reset button */
	gpio_dir(0, GPIO_DIR_IN);
	/* wps button */
	gpio_dir(30, GPIO_DIR_IN);

	/* LED */
	gpio_dir(1, GPIO_DIR_OUT);
	set_gpio(1, 0);
	gpio_dir(4, GPIO_DIR_OUT);
	set_gpio(4, 0);
	gpio_dir(6, GPIO_DIR_OUT);
	set_gpio(6, 1);
	gpio_dir(8, GPIO_DIR_OUT);
	set_gpio(8, 0);
	system("mem -s 0x16c80128 -uw 0x00; mem -s 0x16c80194 -uw 0x00000003");
	gpio_dir(42, GPIO_DIR_OUT);
	set_gpio(42, 0);

	/* Bluetooth */
	gpio_dir(43, GPIO_DIR_OUT);
	set_gpio(43, 1);
}

void generate_switch_para(void)
{
	fprintf(stderr, "Raymond: skip generate_switch_para()\n");
}

int write_default_cal(void)
{
	system("cp -f /opt/lantiq/wave/images/backup/cal_wlan0.bin /tmp/cal_wlan0.bin");
	system("cp -f /opt/lantiq/wave/images/backup/cal_wlan1.bin /tmp/cal_wlan1.bin");
	system("rm -f /tmp/cal_eeprom.tar.gz");
	system("cd /tmp; tar czf cal_eeprom.tar.gz cal_wlan0.bin cal_wlan1.bin");
	system("upgrade /tmp/cal_eeprom.tar.gz wlanconfig 0 0");
	system("rm -f /tmp/cal_eeprom.tar.gz");

	return 0;
}

void init_others(void)
{
	pid_t pid;
	char *udev_argv[] = { "udevd", "--daemon", NULL };
	struct stat st;

	gen_config_sh();
	init_gpio_again();
	system("cp -R /lib/firmware/ar3k /tmp/");
	_dprintf("--------- create link /tmp/wireless/ to /rom/opt/ -----------\n");
	// system("cp -R /rom/opt/* /tmp/wireless/");
	system("cd /tmp/wireless; ln -s /rom/opt/beerocks beerocks");
	system("cd /tmp/wireless; ln -s /rom/opt/errorhd.cfg errorhd.cfg");
	system("cd /tmp/wireless; ln -s /rom/opt/lantiq lantiq");
	_dprintf("--------- extract fapi database -----------\n");
	system("cd /tmp/; rm -rf lantiq_wave; tar zxf /rom/opt/lantiq/wave.tgz; mv wave lantiq_wave");
	_dprintf("--------- create link /tmp/wireless/ to /rom/opt/ done -----------\n");
	system("cp /opt/lantiq/wave/scripts/fapi_wlan_wave_lib_common.sh /tmp/");
	// system("cp /opt/lantiq/wave/scripts/wave_wlan_lib_common.sh /tmp/");
	system("cp /opt/lantiq/wave/images/* /tmp/");
	system("cp /rom/opt/lantiq/etc/wave_components.ver /etc/");
	// system("cd /tmp/; tar zxf /rom/wlan_wave.tgz");
	system("read_img wlanconfig /tmp/cal_eeprom.tar.gz");
	if(stat("/tmp/cal_eeprom.tar.gz", &st) == 0){
		if(st.st_size > 800){
			system("rm -f /tmp/cal_wlan*.bin");
			system("tar zxf /tmp/cal_eeprom.tar.gz -C /tmp/");
		}else{
			/* incorrect calibration */
			write_default_cal();
		}
	}else{
		/* calibration is not existed */
		write_default_cal();
	}
	system("rm -f /tmp/cal_eeprom.tar.gz");
	if(stat("/tmp/cal_wlan1.bin", &st) == 0){
		system("rm -f /tmp/cal_wlan2.bin; mv /tmp/cal_wlan1.bin /tmp/cal_wlan2.bin");
	}
	// system("insmod ltq_regulator_cpufreq");
	// system("insmod ltq_pmcu");
	if (mknod("/dev/switch_api/0", S_IFCHR | 0640, makedev(81, 0)))
		perror("## mknod " "/dev/switch_api/0");
	if (mknod("/dev/switch_api/1", S_IFCHR | 0640, makedev(81, 1)))
		perror("## mknod " "/dev/switch_api/1");
	system("load_gphy_firmware_preinit.sh");
	if (mknod("/dev/ifx_mei", S_IFCHR | 0666, makedev(105, 0)))
		perror("## mknod " "/dev/ifx_mei");
	if (mknod("/dev/ifx_ppa", S_IFCHR | 0666, makedev(181, 0)))
		perror("## mknod " "/dev/ifx_ppa");
	system("insmod drv_ifxos");
	system("insmod drv_event_logger");
	system("insmod directconnect_datapath");
	system("insmod ltq_eth_drv_xrx500");
	system("insmod dc_mode0-xrx500");
	system("insmod mcast_helper");
	system("insmod macvlan");
	system("insmod ltq_pae_hal");
	system("insmod ltq_tmu_hal_drv");
	system("insmod ltq_directpath_datapath");
	system("insmod ppa_api");
	system("insmod ppa_api_proc");
	system("insmod ltq_mpe_hal_drv");
	system("insmod ppa_api_tmplbuf");
	system("insmod ppa_api_sw_accel_mod");
	// system("insmod swa_stack_al");
	system("insmod ltq_temp");
	system("insmod ltq_pmcu");
	// system("insmod ltq_directconnect_datapath");
	// system("insmod /rom/opt/lantiq/lib/modules/3.10.104/directconnect_datapath.ko");
	// system("insmod /rom/lib/modules/3.10.12/pecostat_noIRQ.ko");
	// system("insmod /rom/lib/modules/3.10.12/pecoevent_collect.ko");

#if defined(RTCONFIG_TUXERA_NTFS)
	modprobe("tntfs");
#endif

	if (!pids("udevd")) {
		_eval(udev_argv, NULL, 0, &pid);
		logmessage("udevd", "daemon is started");
	}

	/* 
		if traditional qos and bandwidth limiter, ppa disable
		ppa will take effect by wan_up(), it depends on ppa_support(wan_if)
		no need to check ppa status here, only help to setup nvram here
	*/
	nvram_set("ctf_disable", nvram_safe_get("ctf_disable_force"));

	/* init ppa, but wan_up() will control ppa wan interface to make ppa take effect */
	system("ppacmd init -n 30");
	system("ppacmd addlan -i eth0_1");
	system("ppacmd addlan -i eth0_2");
	system("ppacmd addlan -i eth0_3");
	system("ppacmd addlan -i eth0_4");
	system("ppacmd addlan -i br0");
	/* used for samba fast path */
	if(aimesh_re_mode()){
	}else{
	eval("iptables", "-t", "mangle", "-A", "INPUT",
	     "-p", "tcp", "-m", "state", "--state", "ESTABLISHED",
			"-j", "EXTMARK", "--set-mark", "0x80000000/0x80000000");
	}
	nvram_set("wave_action", "1");

#ifdef RTCONFIG_WIRELESSREPEATER
	if(sw_mode() == SW_MODE_REPEATER || mediabridge_mode()
#ifdef RTCONFIG_AMAS
		|| (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1"))
#endif			
	)
	{
		modprobe("l2nat");
		f_write_string("/proc/sys/net/bridge/bridge-nf-call-iptables", "0", 0, 0);
	}
#endif

	if(nvram_get_int(ATE_FACTORY_MODE_STR()) != 1){
		_dprintf("poweroff usb\n");
		usb_pwr_ctl(0);
	}
	fprintf(stderr, "init_others() End.\n");
}

void init_others_defer(void)
{
	return ;
}

void enable_jumbo_frame(void)
{
	int mtu = 1518;	/* default value */
	char mtu_str[] = "8000XXX";

	if (!nvram_contains_word("rc_support", "switchctrl"))
		return;

	if (nvram_get_int("jumbo_frame_enable"))
		mtu = 8000;
	else
		return; /* no need set again here */

	sprintf(mtu_str, "%d", mtu);
	eval("ifconfig", "eth0_1", "mtu", mtu_str);
	eval("ifconfig", "eth0_2", "mtu", mtu_str);
	eval("ifconfig", "eth0_3", "mtu", mtu_str);
	eval("ifconfig", "eth0_4", "mtu", mtu_str);
}

void init_switch(void)
{
	_dprintf("init_switch: for now handle jumbo frame only\n");
	enable_jumbo_frame();

}

/**
 * Setup a VLAN.
 * @vid:	VLAN ID
 * @prio:	VLAN PRIO
 * @mask:	bit31~16:	untag mask
 * 		bit15~0:	port member mask
 * @return:
 * 	0:	success
 *  otherwise:	fail
 *
 * bit definition of untag mask/port member mask
 * 0:	Port 0, LANx port which is closed to WAN port in visual.
 * 1:	Port 1
 * 2:	Port 2
 * 3:	Port 3
 * 4:	Port 4, WAN port
 * 9:	Port 9, RGMII/MII port that is used to connect CPU and WAN port.
 * 	a. If you only have one RGMII/MII port and it is shared by WAN/LAN ports,
 * 	   you have to define two VLAN interface for WAN/LAN ports respectively.
 * 	b. If your switch chip choose another port as same feature, convert bit9
 * 	   to your own port in low-level driver.
 */
static int __setup_vlan(int vid, int prio, unsigned int mask)
{
	char vlan_str[] = "4096XXX";
	char prio_str[] = "7XXX";
	char mask_str[] = "0x00000000XXX";
	char *set_vlan_argv[] = { "rtkswitch", "36", vlan_str, NULL };
	char *set_prio_argv[] = { "rtkswitch", "37", prio_str, NULL };
	char *set_mask_argv[] = { "rtkswitch", "39", mask_str, NULL };

	if (vid > 4096) {
		_dprintf("%s: invalid vid %d\n", __func__, vid);
		return -1;
	}

	if (prio > 7)
		prio = 0;

	_dprintf("%s: vid %d prio %d mask 0x%08x\n", __func__, vid, prio, mask);

	if (vid >= 0) {
		sprintf(vlan_str, "%d", vid);
		_eval(set_vlan_argv, NULL, 0, NULL);
	}

	if (prio >= 0) {
		sprintf(prio_str, "%d", prio);
		_eval(set_prio_argv, NULL, 0, NULL);
	}

	sprintf(mask_str, "0x%08x", mask);
	_eval(set_mask_argv, NULL, 0, NULL);

	return 0;
}

int switch_exist(void)
{
	int i;
	char *switch_ifnames[5] = {
		"eth1" /* wan */,
		"eth0_1" /* lan */,
		"eth0_2" /* lan */,
		"eth0_3" /* lan */,
		"eth0_4" /* lan */
	};

	for( i = 0 ; i < 5; i++){
		if(is_if_up(switch_ifnames[i]) == 0)
			return 0;
	}

	return 1;
}

/**
 * Low level function to load QCA WiFi driver.
 * @testmode:	if true, load WiFi driver as test mode which is required in ATE mode.
 */
static void __load_wifi_driver(int testmode)
{
	char country[FACTORY_COUNTRY_CODE_LEN + 1], code_str[6];
	const char *umac_params[] = {
		"vow_config", "OL_ACBKMinfree", "OL_ACBEMinfree", "OL_ACVIMinfree",
		"OL_ACVOMinfree", "ar900b_emu", "frac", "intval",
		"fw_dump_options", "enableuartprint", "ar900b_20_targ_clk",
		"max_descs", "qwrap_enable", "otp_mod_param", "max_active_peers",
		"enable_smart_antenna", "max_vaps", "enable_smart_antenna_da",
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
		"qca9888_20_targ_clk", "lteu_support",
		"atf_msdu_desc", "atf_peers", "atf_max_vdevs",
#endif
#if defined(RTCONFIG_SOC_IPQ40XX)
		"low_mem_system",
#endif
		NULL
	}, **up;
	int i, code;
	char param[512], *s = &param[0], umac_nv[64], *val;
	char *argv[30] = {
		"modprobe", "-s", NULL
	}, **v;
	struct load_wifi_kmod_seq_s *p = &load_wifi_kmod_seq[0];
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
	int olcfg = 0;
	char buf[16];
	const char *extra_pbuf_core0 = "0", *n2h_high_water_core0 = "8704", *n2h_wifi_pool_buf = "8576";
	int r, r0, r1, r2, l0, l1, l2;
#endif

#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
	/* Always wait NSS ready whether NSS WiFi offloading is enabled or not. */
	for (i = 0, *buf = '\0'; i < 10; ++i) {
		r0 = f_read_string("/proc/sys/dev/nss/n2hcfg/n2h_high_water_core0", buf, sizeof(buf));
		if (r0 > 0 && strlen(buf) > 0)
			break;
		else {
			dbg(".");
			sleep(1);
		}
	}

	olcfg = (!!nvram_get_int("wl0_hwol") << 0) | (!!nvram_get_int("wl1_hwol") << 1);
	if (olcfg)
		f_write_string("/proc/sys/vm/min_free_kbytes", "23916", 0, 0);
	else
		f_write_string("/proc/sys/vm/min_free_kbytes", "4096", 0, 0);

	/* Always use maximum extra_pbuf_core0.
	 * Because it can't be changed if it is allocated, write non-zero value.
	 */
	extra_pbuf_core0 = "5939200";
	if (olcfg == 1 || olcfg == 2) {
		n2h_high_water_core0 = "43008";
		n2h_wifi_pool_buf = "20224";
	} else if (olcfg) {
		n2h_high_water_core0 = "59392";
		n2h_wifi_pool_buf = "36608";
	}
	l0 = strlen(extra_pbuf_core0);
	l1 = strlen(n2h_high_water_core0);
	l2 = strlen(n2h_wifi_pool_buf);
	for (i = 0; olcfg && i < 10; ++i) {
		f_read_string("/proc/sys/dev/nss/n2hcfg/n2h_high_water_core0", buf, sizeof(buf));

		*buf = '\0';
		r0 = l0;
		r = f_read_string("/proc/sys/dev/nss/general/extra_pbuf_core0", buf, sizeof(buf));
		if (r > 0 && atol(buf)) {
			dbg("%s: extra_pbuf_core0 is allocated!!! [%s]\n", __func__, buf);
		}
		if (r <= 0 || (r > 0 && atol(buf) != atol(extra_pbuf_core0)))
			r0 = f_write_string("/proc/sys/dev/nss/general/extra_pbuf_core0", extra_pbuf_core0, 0, 0);

		r1 = f_write_string("/proc/sys/dev/nss/n2hcfg/n2h_high_water_core0", n2h_high_water_core0, 0, 0);
		r2 = f_write_string("/proc/sys/dev/nss/n2hcfg/n2h_wifi_pool_buf", n2h_wifi_pool_buf, 0, 0);
		if (r0 < l0 || r1 < l1 || r2 < l2) {
			dbg(".");
			sleep(1);
			continue;
		}
		break;
	}
#endif

	for (i = 0, p = &load_wifi_kmod_seq[i]; i < ARRAY_SIZE(load_wifi_kmod_seq); ++i, ++p) {
		if (module_loaded(p->kmod_name))
			continue;

		v = &argv[2];
		*v++ = p->kmod_name;
		*param = '\0';
		s = &param[0];
#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X)
		if (!strcmp(p->kmod_name, "ath_hal")) {
			int ce_level = nvram_get_int("ce_level");
			if (ce_level <= 0)
				ce_level = 0xce;

			*v++ = s;
			s += sprintf(s, "ce_level=%d", ce_level);
			s++;
		}
#endif
		if (!strcmp(p->kmod_name, "umac")) {
			if (!testmode) {
				*v++ = "msienable=0";	/* FIXME: Enable MSI interrupt in future. */
				for (up = &umac_params[0]; *up != NULL; up++) {
					snprintf(umac_nv, sizeof(umac_nv), "qca_%s", *up);
					if (!(val = nvram_get(umac_nv)))
						continue;
					*v++ = s;
					s += sprintf(s, "%s=%s", *up, val);
					s++;
				}

#ifdef RTCONFIG_AIR_TIME_FAIRNESS
				if (nvram_match("wl0_atf", "1") || nvram_match("wl1_atf", "1")) {
					*v++ = s;
					s += sprintf(s, "atf_mode=1");
					s++;
				}
#endif

#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
				*v++ = s;
				s += sprintf(s, "nss_wifi_olcfg=%d", olcfg);
				s++;
#endif

#if defined(RTCONFIG_SOC_IPQ40XX)
				if (get_meminfo_item("MemTotal") <= 131072) {
					f_write_string("/proc/net/skb_recycler/flush", "1", 0, 0);
					f_write_string("/proc/net/skb_recycler/max_skbs", "1", 0, 0);
					f_write_string("/proc/net/skb_recycler/max_spare_skbs", "1", 0, 0);
					*v++ = "low_mem_system=1";
				}
#endif
			}
#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
			else {
				*v++ = "testmode=1";
				*v++ = "ahbskip=1";
			}
#endif
		}

#if defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
		if (!strcmp(p->kmod_name, "adf")) {
			if (nvram_get("qca_prealloc_disabled") != NULL) {
				*v++ = s;
				s += sprintf(s, "prealloc_disabled=%d", nvram_get_int("qca_prealloc_disabled"));
				s++;
			}
		}
#endif

		*v++ = NULL;
		_eval(argv, NULL, 0, NULL);

		if (p->load_sleep)
			sleep(p->load_sleep);
	}

	if (!testmode) {
		//sleep(2);
#if defined(RTCONFIG_WIFI_QCA9557_QCA9882) || defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X)
		eval("iwpriv", (char*) VPHY_2G, "disablestats", "0");
		eval("iwpriv", (char*) VPHY_5G, "enable_ol_stats", "0");
#elif defined(RTCONFIG_WIFI_QCA9990_QCA9990) || defined(RTCONFIG_WIFI_QCA9994_QCA9994)
		eval("iwpriv", (char*) VPHY_2G, "enable_ol_stats", "0");
		eval("iwpriv", (char*) VPHY_5G, "enable_ol_stats", "0");
#endif

		strncpy(country, nvram_safe_get("wl0_country_code"), FACTORY_COUNTRY_CODE_LEN);
		country[FACTORY_COUNTRY_CODE_LEN] = '\0';
		code = country_to_code(country, 2);
		if (code < 0)
			code = country_to_code("DB", 2);
		sprintf(code_str, "%d", code);
		eval("iwpriv", (char*) VPHY_2G, "setCountryID", code_str);

		strncpy(country, nvram_safe_get("wl1_country_code"), FACTORY_COUNTRY_CODE_LEN);
		country[FACTORY_COUNTRY_CODE_LEN] = '\0';
		code = country_to_code(country, 5);
		if (code < 0)
			code = country_to_code("DB", 5);
		sprintf(code_str, "%d", code);
		eval("iwpriv", (char*) VPHY_5G, "setCountryID", code_str);

#if defined(BRTAC828)
		set_irq_smp_affinity(68, 1);	/* wifi0 = 2G ==> CPU0 */
		set_irq_smp_affinity(90, 2);	/* wifi1 = 5G ==> CPU1 */
#endif
#if defined(RTCONFIG_SOC_IPQ8064)
		tweak_wifi_ps(VPHY_2G);
		tweak_wifi_ps(VPHY_5G);
#endif
	}
}

void load_wifi_driver(void)
{
	__load_wifi_driver(0);
}

void load_testmode_wifi_driver(void)
{
	__load_wifi_driver(1);
}

void set_uuid(void)
{
	int len;
	char *p, uuid[60];
	FILE *fp;

	fp = popen("cat /proc/sys/kernel/random/uuid", "r");
	 if (fp) {
	    memset(uuid, 0, sizeof(uuid));
	    fread(uuid, 1, sizeof(uuid), fp);
	    for (len = strlen(uuid), p = uuid; len > 0; len--, p++) {
		    if (isxdigit(*p) || *p == '-')
			    continue;
		    *p = '\0';
		    break;
	    }
	    nvram_set("uuid",uuid);
	    pclose(fp);
	 }   
}

void init_wl(void)
{
	_dprintf("[%s][%d] skip\n", __func__, __LINE__);
}

void fini_wl(void)
{
	_dprintf("[%s][%d] skip\n", __func__, __LINE__);
}

static void chk_valid_country_code(char *country_code)
{
	if ((unsigned char)country_code[0]!=0xff)
	{
		//
	}
	else
	{
		strcpy(country_code, "DB");
	}
}

void init_syspara(void)
{
	unsigned char buffer[16];
	unsigned char *dst;
	unsigned int bytes;
	char macaddr[] = "00:11:22:33:44:55";
	char macaddr2[] = "00:11:22:33:44:58";
	char country_code[FACTORY_COUNTRY_CODE_LEN+1];
	char pin[9];
	char productid[13];
	char fwver[8];
	char blver[20];
#ifdef RTCONFIG_ODMPID
	char modelname[16];
#endif
	char ipaddr_lan[16];

	set_basic_fw_name();

	/* /dev/mtd/2, RF parameters, starts from 0x40000 */
	dst = buffer;
	bytes = 6;
	memset(buffer, 0, sizeof(buffer));
	memset(country_code, 0, sizeof(country_code));
	memset(pin, 0, sizeof(pin));
	memset(productid, 0, sizeof(productid));
	memset(fwver, 0, sizeof(fwver));

	if (FRead(dst, OFFSET_MAC_ADDR_2G, bytes) < 0) {  // ET0/WAN is same as 2.4G
		_dprintf("READ MAC address 2G: Out of scope\n");
	} else {
		if (buffer[0] != 0xff)
			ether_etoa(buffer, macaddr);
	}

	if (FRead(dst, OFFSET_MAC_ADDR, bytes) < 0) { // ET1/LAN is same as 5G
		_dprintf("READ MAC address : Out of scope\n");
	} else {
		if (buffer[0] != 0xff)
			ether_etoa(buffer, macaddr2);
	}

	if (!mssid_mac_validate(macaddr) || !mssid_mac_validate(macaddr2))
		nvram_set("wl_mssid", "0");
	else
		nvram_set("wl_mssid", "1");

	//TODO: separate for different chipset solution
	nvram_set("et0macaddr", macaddr);
	nvram_set("wl0_hwaddr", macaddr);
	nvram_set("et1macaddr", macaddr2);
	nvram_set("wl1_hwaddr", macaddr2);
	if (aimesh_re_mode()){
		/*todo:in RE mode,wl0_hwaddr/wl1_hwaddr should be wlan1/wlan3 mac*/
		nvram_set("wl0.1_hwaddr", macaddr);
		nvram_set("wl1.1_hwaddr", macaddr2);
	}

	dst = (unsigned char*) country_code;
	bytes = FACTORY_COUNTRY_CODE_LEN;
	if (FRead(dst, OFFSET_COUNTRY_CODE, bytes)<0)
	{
		_dprintf("READ ASUS country code: Out of scope\n");
		nvram_set("wl_country_code", "us");
		nvram_set("wl0_country_code", "us");
		nvram_set("wl1_country_code", "us");
	}
	else
	{
		dst[FACTORY_COUNTRY_CODE_LEN]='\0';
		chk_valid_country_code(country_code);
		nvram_set("wl_country_code", country_code);
		nvram_set("wl0_country_code", country_code);
		nvram_set("wl1_country_code", country_code);
	}

	/* reserved for Ralink. used as ASUS pin code. */
	dst = (char *)pin;
	bytes = 8;
	if (FRead(dst, OFFSET_PIN_CODE, bytes) < 0) {
		_dprintf("READ ASUS pin code: Out of scope\n");
		nvram_set("wl_pin_code", "");
	} else {
		if ((unsigned char)pin[0] != 0xff)
			nvram_set("secret_code", pin);
		else
			nvram_set("secret_code", "12345670");
	}

	dst = buffer;
	bytes = 16;
	if (linuxRead(dst, 0x20, bytes) < 0) {	/* The "linux" MTD partition, offset 0x20. */
		fprintf(stderr, "READ firmware header: Out of scope\n");
		nvram_set("productid", "Bluecave");
		nvram_set("firmver", "3.0.0.4");
	} else {
		strncpy(productid, buffer + 4, 12);
		productid[12] = 0;
		sprintf(fwver, "%d.%d.%d.%d", buffer[0], buffer[1], buffer[2],
			buffer[3]);
		nvram_set("productid", trim_r(productid));
		nvram_set("firmver", trim_r(fwver));
	}

#if defined(RTCONFIG_TCODE)
	/* Territory code */
	memset(buffer, 0, sizeof(buffer));
	if (FRead(buffer, OFFSET_TERRITORY_CODE, 5) < 0) {
		_dprintf("READ ASUS territory code: Out of scope\n");
		nvram_unset("territory_code");
	} else {
		/* [A-Z][A-Z]/[0-9][0-9] */
		if (buffer[2] != '/' ||
		    !isupper(buffer[0]) || !isupper(buffer[1]) ||
		    !isdigit(buffer[3]) || !isdigit(buffer[4]))
		{
			nvram_unset("territory_code");
		} else {
			nvram_set("territory_code", buffer);
		}
	}

	/* PSK */
	memset(buffer, 0, sizeof(buffer));
	if (FRead(buffer, OFFSET_PSK, 14) < 0) {
		_dprintf("READ ASUS PSK: Out of scope\n");
		nvram_set("wifi_psk", "");
	} else {
		if ((buffer[0] == 0xff)|| !strcmp(buffer,"NONE"))
			nvram_set("wifi_psk", "");
		else
			nvram_set("wifi_psk", buffer);
	}
#endif

	memset(buffer, 0, sizeof(buffer));
	FRead(buffer, OFFSET_BOOT_VER, 4);
	sprintf(blver, "%s-0%c-0%c-0%c-0%c", trim_r(productid), buffer[0],
		buffer[1], buffer[2], buffer[3]);
	nvram_set("blver", trim_r(blver));

	system("nvram set blver=`uboot_env --get --name bl_ver`");
	_dprintf("bootloader version: %s\n", nvram_safe_get("blver"));
	_dprintf("firmware version: %s\n", nvram_safe_get("firmver"));

	nvram_set("wl1_txbf_en", "0");

#ifdef RTCONFIG_ODMPID
	FRead(modelname, OFFSET_ODMPID, sizeof(modelname));
	modelname[sizeof(modelname) - 1] = '\0';
	if (modelname[0] != 0 && (unsigned char)(modelname[0]) != 0xff
	    && is_valid_hostname(modelname)
	    && strcmp(modelname, "ASUS")) {
		if(strcmp(modelname, "BLUECAVE") == 0){
			nvram_set("odmpid", "BLUE_CAVE");
		}
		else{
			nvram_set("odmpid", modelname);
		}
	} else
#endif
		nvram_unset("odmpid");

	nvram_set("firmver", rt_version);
	nvram_set("productid", rt_buildname);

#if !defined(RTCONFIG_TCODE) // move the verification later bcz TCODE/LOC
	verify_ctl_table();
#endif

#ifdef RTCONFIG_QCA_PLC_UTILS
	getPLC_MAC(macaddr);
	nvram_set("plc_macaddr", macaddr);
#endif

#ifdef RTCONFIG_DEFAULT_AP_MODE
	char dhcp = '0';

	if (FRead(&dhcp, OFFSET_FORCE_DISABLE_DHCP, 1) < 0) {
		_dprintf("READ Disable DHCP: Out of scope\n");
	} else {
		if (dhcp == '1')
			nvram_set("ate_flag", "1");
		else
			nvram_set("ate_flag", "0");
	}
#endif
	FRead(ipaddr_lan, OFFSET_IPADDR_LAN, sizeof(ipaddr_lan));
	ipaddr_lan[sizeof(ipaddr_lan)-1] = '\0';
	if ((unsigned char)(ipaddr_lan[0]) != 0xff && !illegal_ipv4_address(ipaddr_lan))
		nvram_set("IpAddr_Lan", ipaddr_lan);
	else
		nvram_unset("IpAddr_Lan");
}

#ifdef RTCONFIG_ATEUSB3_FORCE
void post_syspara(void)
{
	unsigned char buffer[16];
	buffer[0]='0';
	if (FRead(&buffer[0], OFFSET_FORCE_USB3, 1) < 0) {
		fprintf(stderr, "READ FORCE_USB3 address: Out of scope\n");
	}
	if (buffer[0]=='1')
		nvram_set("usb_usb3", "1");
}
#endif

void generate_wl_para(int unit, int subunit)
{
	char tmp[100],tmp2[100], prefix[]="wlXXXXXXX_",prefix2[]="wlXXXXXXX_";

	if (aimesh_re_mode()) {
		wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
		nvram_set(strcat_r(prefix, "bss_enabled", tmp), "1");

		if (subunit == -1) {
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			snprintf(prefix2, sizeof(prefix2), "wlc%d_", unit);

			nvram_set(strcat_r(prefix, "ssid", tmp), nvram_safe_get(strcat_r(prefix2, "ssid", tmp2)));
			nvram_set(strcat_r(prefix, "auth_mode_x", tmp), nvram_safe_get(strcat_r(prefix2, "auth_mode", tmp2)));
			nvram_set(strcat_r(prefix, "wep_x", tmp), nvram_safe_get(strcat_r(prefix2, "wep", tmp2)));
			if (nvram_get_int(strcat_r(prefix2, "wep", tmp))) {
				nvram_set(strcat_r(prefix, "key", tmp), nvram_safe_get(strcat_r(prefix2, "key", tmp2)));
				nvram_set(strcat_r(prefix, "key1", tmp), nvram_safe_get(strcat_r(prefix2, "wep_key", tmp2)));
				nvram_set(strcat_r(prefix, "key2", tmp), nvram_safe_get(strcat_r(prefix2, "wep_key", tmp2)));
				nvram_set(strcat_r(prefix, "key3", tmp), nvram_safe_get(strcat_r(prefix2, "wep_key", tmp2)));
				nvram_set(strcat_r(prefix, "key4", tmp), nvram_safe_get(strcat_r(prefix2, "wep_key", tmp2)));
			}
			nvram_set(strcat_r(prefix, "crypto", tmp), nvram_safe_get(strcat_r(prefix2, "crypto", tmp2)));
			nvram_set(strcat_r(prefix, "wpa_psk", tmp), nvram_safe_get(strcat_r(prefix2, "wpa_psk", tmp2)));
			nvram_set(strcat_r(prefix, "radius_ipaddr", tmp), nvram_safe_get(strcat_r(prefix2, "radius_ipaddr", tmp2)));
			nvram_set(strcat_r(prefix, "radius_key", tmp), nvram_safe_get(strcat_r(prefix2, "radius_key", tmp2)));
			nvram_set(strcat_r(prefix, "radius_port", tmp), nvram_safe_get(strcat_r(prefix2, "radius_port", tmp2)));
		}

	}
}

int wl_exist(char *ifname, int band)
{
	int i;

	for(i = 0 ; i < 2; i++){
		if(is_if_up(get_wififname(i)) == 0)
			return 0;
	}

	return 1;
}

void
set_wan_tag(char *interface) {
	int model, wan_vid, iptv_vid, voip_vid, switch_stb;
	char wan_dev[10], port_id[7], vid_dev[10];
	
	model = get_model();
	wan_vid = nvram_get_int("switch_wan0tagid");
	iptv_vid = nvram_get_int("switch_wan1tagid");
	voip_vid = nvram_get_int("switch_wan2tagid");

	switch_stb = nvram_get_int("switch_stb_x");
	
	switch(model) {
	case MODEL_BLUECAVE:
				/*					*/
				/* eth1 eth0_4 eth0_3 eth0_2 eth0_1	*/
				/* WAN  L1     L2     L3     L4 	*/
		if(wan_vid && !nvram_match("switch_wantag", "none")) { /* config wan port */
			sprintf(port_id, "%d", wan_vid);
			eval("vconfig", "add", "eth1", port_id);
			sprintf(wan_dev, "eth1.%d", wan_vid);
			/* Set Wan port PRIO */
			if(nvram_invmatch("switch_wan0prio", "0"))
				eval("vconfig", "set_egress_map", wan_dev, "0", nvram_get("switch_wan0prio"));
			set_wan_phy("");
			add_wan_phy(wan_dev);
			nvram_set("wan0_ifname", wan_dev);
			nvram_set("wan0_gw_ifname", wan_dev);
		}
		/* handle IPTV profile "none" to bridge WAN and LAN */
		if (nvram_match("switch_stb_x", "1") && nvram_match("switch_wantag", "none")) {
			/* bridge WAN and L1 (untag) */
			set_wan_phy("");
			add_wan_phy("br1");
			nvram_set("wan0_ifname", "br1");
			nvram_set("wan0_gw_ifname", "br1");
			eval("brctl", "addbr", "br1");
			eval("ifconfig", "br1", "up");
			eval("brctl", "addif", "br1", "eth1");
			eval("brctl", "delif", "br0", "eth0_4");
			eval("brctl", "addif", "br1", "eth0_4");
		}
		else if (nvram_match("switch_stb_x", "2") && nvram_match("switch_wantag", "none")) {
			/* bridge WAN and L2 (untag) */
			set_wan_phy("");
			add_wan_phy("br1");
			nvram_set("wan0_ifname", "br1");
			nvram_set("wan0_gw_ifname", "br1");
			eval("brctl", "addbr", "br1");
			eval("ifconfig", "br1", "up");
			eval("brctl", "addif", "br1", "eth1");
			eval("brctl", "delif", "br0", "eth0_3");
			eval("brctl", "addif", "br1", "eth0_3");
		}
		else if (nvram_match("switch_stb_x", "3")) {
			if (nvram_match("switch_wantag", "vodafone")) {
				/* bridge WAN and L4 (leave tag) */
				/* handle WAN vid 100 */
				set_wan_phy("");
				add_wan_phy("br1");
				nvram_set("wan0_ifname", "br1");
				nvram_set("wan0_gw_ifname", "br1");
				eval("brctl", "addbr", "br1");
				eval("ifconfig", "br1", "up");
				eval("brctl", "delif", "br0", "eth0_1");
				sprintf(vid_dev, "eth1.%d", wan_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br1", vid_dev);
				eval("vconfig", "add", "eth0_1", port_id);
				sprintf(vid_dev, "eth0_1.%d", wan_vid);
				eval("ifconfig", vid_dev, "up");
				eval("brctl", "delif", "br0", "eth0_1");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "addif", "br1", vid_dev);
				/* handle bridge vid 101 */
				sprintf(port_id, "%d", 101);
				eval("brctl", "addbr", "br2");
				eval("ppacmd", "addlan", "-i", "br2");
				eval("brctl", "stp", "br2", "on");
				eval("ifconfig", "br2", "up");
				eval("vconfig", "add", "eth1", port_id);
				sprintf(vid_dev, "eth1.%d", 101);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br2", vid_dev);
				eval("vconfig", "add", "eth0_1", port_id);
				sprintf(vid_dev, "eth0_1.%d", 101);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "addif", "br2", vid_dev);
				/* handle voip vid 105 */
				sprintf(port_id, "%d", voip_vid);
				eval("brctl", "addbr", "br3");
				eval("ppacmd", "addlan", "-i", "br3");
				eval("brctl", "stp", "br3", "on");
				eval("ifconfig", "br3", "up");
				eval("vconfig", "add", "eth1", port_id);
				sprintf(vid_dev, "eth1.%d", voip_vid);
				if(nvram_invmatch("switch_wan2prio", "0"))
					eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan2prio"));
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br3", vid_dev);
				eval("vconfig", "add", "eth0_1", port_id);
				sprintf(vid_dev, "eth0_1.%d", voip_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "addif", "br3", vid_dev);
				/* untag in L3 */
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", "br3", "eth0_2");
			}
			else if (nvram_match("switch_wantag", "m1_fiber")
				|| nvram_match("switch_wantag", "maxis_fiber_sp")
				|| nvram_match("switch_wantag", "maxis_cts")
				|| nvram_match("switch_wantag", "maxis_sacofa")
				|| nvram_match("switch_wantag", "maxis_tnb")
			) {
				/* Just forward packets between WAN & L3, without untag */
				sprintf(port_id, "%d", voip_vid);
				_dprintf("vlan entry: %s\n", port_id);
				eval("vconfig", "add", "eth1", port_id);
				eval("brctl", "addbr", "br1");
				eval("ppacmd", "addlan", "-i", "br1");
				eval("brctl", "stp", "br1", "on");
				eval("ifconfig", "br1", "up");
				sprintf(vid_dev, "eth1.%d", voip_vid);
				if(nvram_invmatch("switch_wan2prio", "0"))
					eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan2prio"));
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br1", vid_dev);
				eval("vconfig", "add", "eth0_2", port_id);
				sprintf(vid_dev, "eth0_2.%d", voip_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", "br1", vid_dev);
			}
			else if (nvram_match("switch_wantag", "maxis_fiber")) {
				/* Just forward packets between WAN & L3, without untag */
				sprintf(port_id, "%d", 821);
				_dprintf("vlan entry: %s\n", port_id);
				eval("vconfig", "add", "eth1", port_id);
				eval("brctl", "addbr", "br1");
				eval("ppacmd", "addlan", "-i", "br1");
				eval("brctl", "stp", "br1", "on");
				eval("ifconfig", "br1", "up");
				sprintf(vid_dev, "eth1.%d", 821);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br1", vid_dev);
				eval("vconfig", "add", "eth0_2", port_id);
				sprintf(vid_dev, "eth0_2.%d", 821);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", "br1", vid_dev);
				sprintf(port_id, "%d", 822);
				_dprintf("vlan entry: %s\n", port_id);
				eval("vconfig", "add", "eth1", port_id);
				eval("brctl", "addbr", "br2");
				eval("ppacmd", "addlan", "-i", "br2");
				eval("brctl", "stp", "br2", "on");
				eval("ifconfig", "br2", "up");
				sprintf(vid_dev, "eth1.%d", 822);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br2", vid_dev);
				eval("vconfig", "add", "eth0_2", port_id);
				sprintf(vid_dev, "eth0_2.%d", 822);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "addif", "br2", vid_dev);
			}
			else if (nvram_match("switch_wantag", "none")) {
				/* bridge WAN and L3 (untag) */
				set_wan_phy("");
				add_wan_phy("br1");
				nvram_set("wan0_ifname", "br1");
				nvram_set("wan0_gw_ifname", "br1");
				eval("brctl", "addbr", "br1");
				eval("ifconfig", "br1", "up");
				eval("brctl", "addif", "br1", "eth1");
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", "br1", "eth0_2");
			}
			else {  /* Nomo case. */
				sprintf(port_id, "%d", voip_vid);
				_dprintf("vlan entry: %s\n", port_id);
				/* Forward packets to L3 (untag) */
				eval("vconfig", "add", "eth1", port_id);
				eval("brctl", "addbr", "br1");
				eval("ppacmd", "addlan", "-i", "br1");
				eval("brctl", "stp", "br1", "on");
				eval("ifconfig", "br1", "up");
				sprintf(vid_dev, "eth1.%d", voip_vid);
				if(nvram_invmatch("switch_wan2prio", "0"))
					eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan2prio"));
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br1", vid_dev);
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", "br1", "eth0_2");
			}
		}
		else if (nvram_match("switch_stb_x", "4")) {
			/* config LAN 4 = IPTV */
			if (nvram_match("switch_wantag", "meo")) {
				/* Just forward packets between wan & L4, without untag */
				set_wan_phy("");
				add_wan_phy("br1");
				nvram_set("wan0_ifname", "br1");
				nvram_set("wan0_gw_ifname", "br1");
				eval("brctl", "addbr", "br1");
				eval("ifconfig", "br1", "up");
				sprintf(vid_dev, "eth1.%d", wan_vid);
				eval("ifconfig", vid_dev, "up");
				eval("brctl", "addif", "br1", vid_dev);
				eval("vconfig", "add", "eth0_1", port_id);
				sprintf(vid_dev, "eth0_1.%d", wan_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "delif", "br0", "eth0_1");
				eval("brctl", "addif", "br1", vid_dev);
			}
			else if (nvram_match("switch_wantag", "none") || nvram_match("switch_wantag", "hinet")) {
				set_wan_phy("");
				add_wan_phy("br1");
				nvram_set("wan0_ifname", "br1");
				nvram_set("wan0_gw_ifname", "br1");
				eval("brctl", "addbr", "br1");
				eval("ifconfig", "br1", "up");
				eval("brctl", "addif", "br1", "eth1");
				eval("brctl", "delif", "br0", "eth0_1");
				eval("brctl", "addif", "br1", "eth0_1");
			}
			else {  /* Nomo case, untag it. */
				/* config LAN 4 = IPTV */
				sprintf(port_id, "%d", iptv_vid);
				_dprintf("vlan entry: %s\n", port_id);
				/* Forward packets to L4 (untag) */
				eval("vconfig", "add", "eth1", port_id);
				eval("brctl", "addbr", "br1");
				eval("ppacmd", "addlan", "-i", "br1");
				if (!nvram_match("switch_wantag", "unifi_home"))
					eval("brctl", "stp", "br1", "on");
				eval("ifconfig", "br1", "up");
				sprintf(vid_dev, "eth1.%d", iptv_vid);
				if(nvram_invmatch("switch_wan1prio", "0"))
					eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan1prio"));
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", "br1", vid_dev);
				eval("brctl", "delif", "br0", "eth0_1");
				eval("brctl", "addif", "br1", "eth0_1");
			}
		}
		/* handle LAN1 & LAN2 brdige WAN */
		else if (nvram_match("switch_stb_x", "5") && nvram_match("switch_wantag", "none")) {
			set_wan_phy("");
			add_wan_phy("br1");
			nvram_set("wan0_ifname", "br1");
			nvram_set("wan0_gw_ifname", "br1");
			eval("brctl", "addbr", "br1");
			eval("ifconfig", "br1", "up");
			eval("brctl", "addif", "br1", "eth1");
			eval("brctl", "delif", "br0", "eth0_3");
			eval("brctl", "addif", "br1", "eth0_3");
			eval("brctl", "delif", "br0", "eth0_4");
			eval("brctl", "addif", "br1", "eth0_4");
		}
		else if (nvram_match("switch_stb_x", "6")) {
			
			int br_index = 1;
			char br_name[3];

			/* config LAN 3 = VoIP */
			if (nvram_match("switch_wantag", "singtel_mio")) {

				sprintf(br_name, "br%d", br_index++);

				/* Just forward packets between WAN & L3, without untag */
				sprintf(port_id, "%d", voip_vid);
				_dprintf("vlan entry: %s\n", port_id);
				eval("vconfig", "add", "eth1", port_id);
				eval("brctl", "addbr", br_name);
				eval("ppacmd", "addlan", "-i", br_name);
				eval("brctl", "stp", br_name, "on");
				eval("ifconfig", br_name, "up");
				sprintf(vid_dev, "eth1.%d", voip_vid);
				if(nvram_invmatch("switch_wan2prio", "0"))
					eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan2prio"));
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				eval("brctl", "addif", br_name, vid_dev);
				eval("vconfig", "add", "eth0_2", port_id);
				sprintf(vid_dev, "eth0_2.%d", voip_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addlan", "-i", vid_dev);
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", br_name, vid_dev);
			}
			else if (nvram_match("switch_wantag", "none")) {

				sprintf(br_name, "br%d", br_index++);

				set_wan_phy("");
				add_wan_phy(br_name);
				nvram_set("wan0_ifname", br_name);
				nvram_set("wan0_gw_ifname", br_name);
				eval("brctl", "addbr", br_name);
				eval("ifconfig", br_name, "up");
				eval("brctl", "addif", br_name, "eth1");
				eval("brctl", "delif", "br0", "eth0_1");
				eval("brctl", "addif", br_name, "eth0_1");
				eval("brctl", "delif", "br0", "eth0_2");
				eval("brctl", "addif", br_name, "eth0_2");
			}
			else {
				if (voip_vid) {

					sprintf(br_name, "br%d", br_index++);

					/* Forward packets from wan to L3 (untag) */
					sprintf(port_id, "%d", voip_vid);
					_dprintf("vlan entry: %s\n", port_id);
					eval("vconfig", "add", "eth1", port_id);
					eval("brctl", "addbr", br_name);
					eval("ppacmd", "addlan", "-i", br_name);
					eval("brctl", "stp", br_name, "on");
					eval("ifconfig", br_name, "up");
					sprintf(vid_dev, "eth1.%d", voip_vid);
					if(nvram_invmatch("switch_wan2prio", "0"))
						eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan2prio"));
					eval("ifconfig", vid_dev, "up");
					eval("ppacmd", "addwan", "-i", vid_dev);
					eval("brctl", "addif", br_name, vid_dev);
					
					eval("brctl", "delif", "br0", "eth0_2");
					eval("brctl", "addif", br_name, "eth0_2");
				}
			}
			/* config LAN 4 = IPTV */
			if (iptv_vid) {
				/* Forward packets from wan to L4 (untag) */
				if (iptv_vid!=voip_vid) {

					sprintf(br_name, "br%d", br_index++);

					sprintf(port_id, "%d", iptv_vid);
					_dprintf("vlan entry: %s\n", port_id);
					eval("vconfig", "add", "eth1", port_id);
					eval("brctl", "addbr", br_name);
					eval("ppacmd", "addlan", "-i", br_name);
					eval("brctl", "stp", br_name, "on");
					eval("ifconfig", br_name, "up");
					sprintf(vid_dev, "eth1.%d", iptv_vid);
					if(nvram_invmatch("switch_wan1prio", "0"))
						eval("vconfig", "set_egress_map", vid_dev, "0", nvram_get("switch_wan1prio"));
					eval("ifconfig", vid_dev, "up");
					eval("ppacmd", "addwan", "-i", vid_dev);
					eval("brctl", "addif", br_name, vid_dev);
				}

				eval("brctl", "delif", "br0", "eth0_1");
				eval("brctl", "addif", br_name, "eth0_1");
			}
		}
#ifdef RTCONFIG_MULTICAST_IPTV
		if (switch_stb >= 7) {
			if (iptv_vid) { /* config IPTV on wan port */
_dprintf("*** Multicast IPTV: config IPTV on wan port ***\n");
				/* Handle wan(IPTV) vlan traffic */
				sprintf(port_id, "%d", iptv_vid);
				eval("vconfig", "add", "eth1", port_id);
				sprintf(vid_dev, "eth1.%d", iptv_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				nvram_set("wan10_ifname", vid_dev);
			}
		}
		if (switch_stb >= 8) {
			if (voip_vid) { /* config voip on wan port */
_dprintf("*** Multicast IPTV: config VOIP on wan port ***\n");
				/* Handle wan(VOIP) vlan traffic */
				sprintf(port_id, "%d", voip_vid);
				eval("vconfig", "add", "eth1", port_id);
				sprintf(vid_dev, "eth1.%d", voip_vid);
				eval("ifconfig", vid_dev, "up");
				eval("ppacmd", "addwan", "-i", vid_dev);
				nvram_set("wan11_ifname", vid_dev);
			}
		}
#endif
		break;
	}
}

int start_thermald(void)
{
	char *thermald_argv[] = {"thermald", "-c", "/etc/thermal/ipq-thermald-8064.conf", NULL};
	pid_t pid;

	return _eval(thermald_argv, NULL, 0, &pid);
}

