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

#ifdef RTCONFIG_ALPINE
#include <alpine.h>
#include <flash_mtd.h>
#endif

#if defined(RTCONFIG_NEW_REGULATION_DOMAIN)
#error !!!!!!!!!!!QCA driver must use country code!!!!!!!!!!!
#endif


#ifdef RTCONFIG_QSR10G
int start_qsr10g(void);
#endif

int is_if_up(char *ifname)
{
	int s;
	struct ifreq ifr;

	/* Open a raw socket to the kernel */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return 0;

	/* Set interface name */
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	/* Get interface flags */
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0){
		fprintf(stderr, "SIOCGIFFLAGS error\n");
	}else{
		if(ifr.ifr_flags & IFF_UP){
			fprintf(stderr, "%s is up\n", ifname);
			return 1;
		}
	}

	return 0;
}

static void __mknod(char *name, mode_t mode, dev_t dev)
{
	if (mknod(name, mode, dev)) {
		printf("## mknod %s mode 0%o fail! errno %d (%s)", name, mode, errno, strerror(errno));
	}
}

void init_gpios(void)
{
	/* reset button */
	gpio_dir(39, GPIO_DIR_IN);
	/* wps button */
	gpio_dir(38, GPIO_DIR_IN);
	/* WIFI ON/OFF button */
	gpio_dir(3, GPIO_DIR_IN);
	/* LED ON/OFF button */
	gpio_dir(22, GPIO_DIR_IN);

	/* LED */
	/* WAN0 white */
	gpio_dir(0, GPIO_DIR_OUT);
	set_gpio(0, 1);

	/* WAN0 red */
	gpio_dir(1, GPIO_DIR_OUT);
	set_gpio(1, 1);

	/* LAN LED (RTL8370MB) */
	gpio_dir(4, GPIO_DIR_OUT);
	set_gpio(4, 1);

	/* Board LED */
	gpio_dir(2, GPIO_DIR_OUT);
	set_gpio(2, 1);

	/* SFP LED */
	gpio_dir(29, GPIO_DIR_OUT);
	set_gpio(29, 1);

	/* 10G LED */
	gpio_dir(44, GPIO_DIR_OUT);
	set_gpio(44, 1);

	/* Power LED */
	gpio_dir(46, GPIO_DIR_OUT);
	set_gpio(46, 1);

}

void init_devs(void)
{
	int status;

	if ((status = WEXITSTATUS(modprobe("nvram_linux"))))
		printf("## modprove(nvram_linux) fail status(%d)\n", status);
	__mknod("/dev/rtkswitch", S_IFCHR | 0666, makedev(206, 0));
	init_gpios();
	// modprobe("rtl8370_drv");

	check_ubi_partition();
	start_jffs2();

#ifdef RTCONFIG_NVRAM_FILEBAK
	start_nvram_txt();
#endif
}

void generate_switch_para(void)
{
#if defined(RTCONFIG_DUALWAN)
	int model;
	int wans_cap = get_wans_dualwan() & WANSCAP_WAN;
	int wanslan_cap = get_wans_dualwan() & WANSCAP_LAN;

	// generate nvram nvram according to system setting
	model = get_model();

	switch (model) {
		nvram_unset("vlan3hwname");
		if ((wans_cap && wanslan_cap)
		    )
			nvram_set("vlan3hwname", "et0");
		break;
	}
#endif
}

void tweak_lan_wan_ps(void)
{
}

void init_others(void)
{
	f_write_string("/proc/irq/152/smp_affinity", "1", 0, 0);

	f_write_string("/proc/irq/167/smp_affinity", "6", 0, 0);
	f_write_string("/proc/irq/168/smp_affinity", "6", 0, 0);
	f_write_string("/proc/irq/169/smp_affinity", "6", 0, 0);
	f_write_string("/proc/irq/170/smp_affinity", "6", 0, 0);

	f_write_string("/proc/irq/171/smp_affinity", "6", 0, 0);
	f_write_string("/proc/irq/172/smp_affinity", "6", 0, 0);
	f_write_string("/proc/irq/173/smp_affinity", "6", 0, 0);
	f_write_string("/proc/irq/174/smp_affinity", "6", 0, 0);
	system("cp /sbin/fw_env.config /etc/");
	system("cp /sbin/fw_print /tmp/fw_printenv");
	system("cp /sbin/fw_print /tmp/fw_setenv");
	system("nvram set bl_version=`/tmp/fw_printenv bl_ver|cut -d= -f 2`");
	system("rm -f /etc/fw_env.config");
	system("rm -f /tmp/fw_printenv");
	system("rm -f /tmp/fw_setenv");
}

void enable_jumbo_frame(void)
{
	_dprintf("Raymond: [%s][%d] skip\n", __func__, __LINE__);
}

void init_switch(void)
{
	char calstate[3] = {0};
#ifdef RTCONFIG_QSR10G
	start_qsr10g();
#endif
#ifdef RTCONFIG_ALPINE
	start_aqr107();
#endif
#ifdef RTCONFIG_QSR10G
	nvram_set("qtn_ready", "0");
	_dprintf("waiting qsr10g booting, qtn_ready=0\n");
	sleep(30);
	nvram_set("qtn_ready", "1");
#endif
	nvram_set("rtl8370mb_startup", "0");
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

int config_switch_for_first_time = 1;
void config_switch(void)
{
	int model = get_model();
	int stbport;
	int controlrate_unknown_unicast;
	int controlrate_unknown_multicast;
	int controlrate_multicast;
	int controlrate_broadcast;
	int merge_wan_port_into_lan_ports;

	dbG("link down all ports\n");
	eval("rtkswitch", "17");	// link down all ports

	switch (model) {
	case MODEL_GTAC9600:	/* fall through */
		merge_wan_port_into_lan_ports = 1;
		break;
	default:
		merge_wan_port_into_lan_ports = 0;
	}

	if (config_switch_for_first_time)
		config_switch_for_first_time = 0;
	else {
		dbG("software reset\n");
		eval("rtkswitch", "27");	// software reset
	}

#if defined(RTCONFIG_SWITCH_RTL8370M_PHY_QCA8033_X2) || \
    defined(RTCONFIG_SWITCH_RTL8370MB_PHY_QCA8033_X2)
	if (is_routing_enabled()) {
		int wanscap_wanlan = get_wans_dualwan() & (WANSCAP_WAN | WANSCAP_LAN);
		int wans_lanport = nvram_get_int("wans_lanport");
		int wan_mask, unit;
		char cmd[64];
		char prefix[8], nvram_ports[20];

		if ((wanscap_wanlan & WANSCAP_LAN) && (wans_lanport < 0 || wans_lanport > 8)) {
			_dprintf("%s: invalid wans_lanport %d!\n", __func__, wans_lanport);
			wanscap_wanlan &= ~WANSCAP_LAN;
		}

		wan_mask = 0;
		if(wanscap_wanlan & WANSCAP_WAN)
			wan_mask |= 0x1 << 0;
		if(wanscap_wanlan & WANSCAP_LAN)
			wan_mask |= 0x1 << wans_lanport;
		sprintf(cmd, "rtkswitch 44 0x%08x", wan_mask);
		system(cmd);

		for (unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; ++unit) {
			sprintf(prefix, "%d", unit);
			sprintf(nvram_ports, "wan%sports_mask", (unit == WAN_UNIT_FIRST)? "" : prefix);
			nvram_unset(nvram_ports);
			if (get_dualwan_by_unit(unit) == WANS_DUALWAN_IF_LAN) {
				/* BRT-AC828 LAN1 = P0, LAN2 = P1, etc */
				nvram_set_int(nvram_ports, (1 << (wans_lanport - 1)));
			}
		}
	}
#endif

#ifdef RTCONFIG_DEFAULT_AP_MODE
	if (sw_mode() != SW_MODE_ROUTER)
		system("rtkswitch 8 7"); // LLLLL
	else
#endif
	system("rtkswitch 8 0"); // init, rtkswitch 114,115,14,15 need it
	if (is_routing_enabled()) {
		char parm_buf[] = "XXX";

		stbport = atoi(nvram_safe_get("switch_stb_x"));
		if (stbport < 0 || stbport > 6) stbport = 0;
		dbG("ISP Profile/STB: %s/%d\n", nvram_safe_get("switch_wantag"), stbport);
		/* stbport:	Model-independent	unifi_malaysia=1	otherwise
		 * 		IPTV STB port		(RT-N56U)		(RT-N56U)
		 * -----------------------------------------------------------------------
		 *	0:	N/A			LLLLW
		 *	1:	LAN1			LLLTW			LLLWW
		 *	2:	LAN2			LLTLW			LLWLW
		 *	3:	LAN3			LTLLW			LWLLW
		 *	4:	LAN4			TLLLW			WLLLW
		 *	5:	LAN1 + LAN2		LLTTW			LLWWW
		 *	6:	LAN3 + LAN4		TTLLW			WWLLW
		 */

		/* portmask in rtkswitch
		 * 	P9	P8	P7	P6	P5	P4	P3	P2	P1	P0
		 * 	MII-W	MII-L	-	-	-	WAN	LAN1	LAN2	LAN3	LAN4
		 */

		if (!nvram_match("switch_wantag", "none")&&!nvram_match("switch_wantag", "")) {
			//2012.03 Yau modify
			char tmp[128];
			char *p;
			int voip_port = 0;
			int t, vlan_val = -1, prio_val = -1;
			unsigned int mask = 0;

//			voip_port = atoi(nvram_safe_get("voip_port"));
			voip_port = 3;
			if (voip_port < 0 || voip_port > 4)
				voip_port = 0;		

			/* Fixed Ports Now*/
			stbport = 4;	
			voip_port = 3;
	
			sprintf(tmp, "rtkswitch 29 %d", voip_port);	
			system(tmp);	

			if (!strncmp(nvram_safe_get("switch_wantag"), "unifi", 5)) {
				/* Added for Unifi. Cherry Cho modified in 2011/6/28.*/
				if(strstr(nvram_safe_get("switch_wantag"), "home")) {
					system("rtkswitch 38 1");		/* IPTV: P0 */
					/* Internet:	untag: P9;   port: P4, P9 */
					__setup_vlan(500, 0, 0x02000210);
					/* IPTV:	untag: P0;   port: P0, P4 */
					__setup_vlan(600, 0, 0x00010011);
				}
				else {
					/* No IPTV. Business package */
					/* Internet:	untag: P9;   port: P4, P9 */
					system("rtkswitch 38 0");
					__setup_vlan(500, 0, 0x02000210);
				}
			}
			else if (!strncmp(nvram_safe_get("switch_wantag"), "singtel", 7)) {
				/* Added for SingTel's exStream issues. Cherry Cho modified in 2011/7/19. */
				if(strstr(nvram_safe_get("switch_wantag"), "mio")) {
					/* Connect Singtel MIO box to P3 */
					system("rtkswitch 40 1");		/* admin all frames on all ports */
					system("rtkswitch 38 3");		/* IPTV: P0  VoIP: P1 */
					/* Internet:	untag: P9;   port: P4, P9 */
					__setup_vlan(10, 0, 0x02000210);
					/* VoIP:	untag: N/A;  port: P1, P4 */
					//VoIP Port: P1 tag
					__setup_vlan(30, 4, 0x00000012);
				}
				else {
					//Connect user's own ATA to lan port and use VoIP by Singtel WAN side VoIP gateway at voip.singtel.com
					system("rtkswitch 38 1");		/* IPTV: P0 */
					/* Internet:	untag: P9;   port: P4, P9 */
					__setup_vlan(10, 0, 0x02000210);
				}

				/* IPTV */
				__setup_vlan(20, 4, 0x00010011);		/* untag: P0;   port: P0, P4 */
			}
			else if (!strcmp(nvram_safe_get("switch_wantag"), "m1_fiber")) {
				//VoIP: P1 tag. Cherry Cho added in 2012/1/13.
				system("rtkswitch 40 1");			/* admin all frames on all ports */
				system("rtkswitch 38 2");			/* VoIP: P1  2 = 0x10 */
				/* Internet:	untag: P9;   port: P4, P9 */
				__setup_vlan(1103, 1, 0x02000210);
				/* VoIP:	untag: N/A;  port: P1, P4 */
				//VoIP Port: P1 tag
				__setup_vlan(1107, 1, 0x00000012);
			}
			else if (!strcmp(nvram_safe_get("switch_wantag"), "maxis_fiber")) {
				//VoIP: P1 tag. Cherry Cho added in 2012/11/6.
				system("rtkswitch 40 1");			/* admin all frames on all ports */
				system("rtkswitch 38 2");			/* VoIP: P1  2 = 0x10 */
				/* Internet:	untag: P9;   port: P4, P9 */
				__setup_vlan(621, 0, 0x02000210);
				/* VoIP:	untag: N/A;  port: P1, P4 */
				__setup_vlan(821, 0, 0x00000012);

				__setup_vlan(822, 0, 0x00000012);		/* untag: N/A;  port: P1, P4 */ //VoIP Port: P1 tag
			}
			else if (!strcmp(nvram_safe_get("switch_wantag"), "maxis_fiber_sp")) {
				//VoIP: P1 tag. Cherry Cho added in 2012/11/6.
				system("rtkswitch 40 1");			/* admin all frames on all ports */
				system("rtkswitch 38 2");			/* VoIP: P1  2 = 0x10 */
				/* Internet:	untag: P9;   port: P4, P9 */
				__setup_vlan(11, 0, 0x02000210);
				/* VoIP:	untag: N/A;  port: P1, P4 */
				//VoIP Port: P1 tag
				__setup_vlan(14, 0, 0x00000012);
			}
			else if (!strcmp(nvram_safe_get("switch_wantag"), "movistar")) {
				system("rtkswitch 38 3");			/* IPTV/VoIP: P1/P0 */
				/* Internet:	untag: P9;   port: P4, P9 */
				__setup_vlan(6, 0, 0x02000210);
				/* IPTV:	untag: P1;   port: P1, P4 */
				__setup_vlan(3, 0, 0x00020012);
				/* VoIP:	untag: P0;   port: P0, P4 */
				__setup_vlan(2, 0, 0x00010011);
			}
			else if (!strcmp(nvram_safe_get("switch_wantag"), "meo")) {
				system("rtkswitch 40 1");			/* admin all frames on all ports */
				system("rtkswitch 38 1");			/* VoIP: P0 */
				/* Internet/VoIP:	untag: P9;   port: P0, P4, P9 */
				__setup_vlan(12, 0, 0x02000211);
			}
			else {
				/* Cherry Cho added in 2011/7/11. */
				/* Initialize VLAN and set Port Isolation */
				if(strcmp(nvram_safe_get("switch_wan1tagid"), "") && strcmp(nvram_safe_get("switch_wan2tagid"), ""))
					system("rtkswitch 38 3");		// 3 = 0x11 IPTV: P0  VoIP: P1
				else if(strcmp(nvram_safe_get("switch_wan1tagid"), ""))
					system("rtkswitch 38 1");		// 1 = 0x01 IPTV: P0
				else if(strcmp(nvram_safe_get("switch_wan2tagid"), ""))
					system("rtkswitch 38 2");		// 2 = 0x10 VoIP: P1
				else
					system("rtkswitch 38 0");		//No IPTV and VoIP ports

				/*++ Get and set Vlan Information */
				if(strcmp(nvram_safe_get("switch_wan0tagid"), "") != 0) {
					// Internet on WAN (port 4)
					if ((p = nvram_get("switch_wan0tagid")) != NULL) {
						t = atoi(p);
						if((t >= 2) && (t <= 4094))
							vlan_val = t;
					}

					if((p = nvram_get("switch_wan0prio")) != NULL && *p != '\0')
						prio_val = atoi(p);

					__setup_vlan(vlan_val, prio_val, 0x02000210);
				}

				if(strcmp(nvram_safe_get("switch_wan1tagid"), "") != 0) {
					// IPTV on LAN4 (port 0)
					if ((p = nvram_get("switch_wan1tagid")) != NULL) {
						t = atoi(p);
						if((t >= 2) && (t <= 4094))
							vlan_val = t;
					}

					if((p = nvram_get("switch_wan1prio")) != NULL && *p != '\0')
						prio_val = atoi(p);

					if(!strcmp(nvram_safe_get("switch_wan1tagid"), nvram_safe_get("switch_wan2tagid")))
						mask = 0x00030013;	//IPTV=VOIP
					else
						mask = 0x00010011;	//IPTV Port: P0 untag 65553 = 0x10 011

					__setup_vlan(vlan_val, prio_val, mask);
				}	

				if(strcmp(nvram_safe_get("switch_wan2tagid"), "") != 0) {
					// VoIP on LAN3 (port 1)
					if ((p = nvram_get("switch_wan2tagid")) != NULL) {
						t = atoi(p);
						if((t >= 2) && (t <= 4094))
							vlan_val = t;
					}

					if((p = nvram_get("switch_wan2prio")) != NULL && *p != '\0')
						prio_val = atoi(p);

					if(!strcmp(nvram_safe_get("switch_wan1tagid"), nvram_safe_get("switch_wan2tagid")))
						mask = 0x00030013;	//IPTV=VOIP
					else
						mask = 0x00020012;	//VoIP Port: P1 untag

					__setup_vlan(vlan_val, prio_val, mask);
				}

			}
		}
		else
		{
			sprintf(parm_buf, "%d", stbport);
			if (stbport)
				eval("rtkswitch", "8", parm_buf);
#if defined(RTCONFIG_SWITCH_RTL8370M_PHY_QCA8033_X2) || \
    defined(RTCONFIG_SWITCH_RTL8370MB_PHY_QCA8033_X2)
			{
				char *str;

				str = nvram_get("lan_trunk_0");
				if(str != NULL && str[0] != '\0')
				{
					eval("rtkswitch", "45", "0");
					eval("rtkswitch", "46", str);
				}

				str = nvram_get("lan_trunk_1");
				if(str != NULL && str[0] != '\0')
				{
					eval("rtkswitch", "45", "1");
					eval("rtkswitch", "46", str);
				}
			}
#endif
		}

		/* unknown unicast storm control */
		if (!nvram_get("switch_ctrlrate_unknown_unicast"))
			controlrate_unknown_unicast = 0;
		else
			controlrate_unknown_unicast = atoi(nvram_get("switch_ctrlrate_unknown_unicast"));
		if (controlrate_unknown_unicast < 0 || controlrate_unknown_unicast > 1024)
			controlrate_unknown_unicast = 0;
		if (controlrate_unknown_unicast)
		{
			sprintf(parm_buf, "%d", controlrate_unknown_unicast);
			eval("rtkswitch", "22", parm_buf);
		}
	
		/* unknown multicast storm control */
		if (!nvram_get("switch_ctrlrate_unknown_multicast"))
			controlrate_unknown_multicast = 0;
		else
			controlrate_unknown_multicast = atoi(nvram_get("switch_ctrlrate_unknown_multicast"));
		if (controlrate_unknown_multicast < 0 || controlrate_unknown_multicast > 1024)
			controlrate_unknown_multicast = 0;
		if (controlrate_unknown_multicast) {
			sprintf(parm_buf, "%d", controlrate_unknown_multicast);
			eval("rtkswitch", "23", parm_buf);
		}
	
		/* multicast storm control */
		if (!nvram_get("switch_ctrlrate_multicast"))
			controlrate_multicast = 0;
		else
			controlrate_multicast = atoi(nvram_get("switch_ctrlrate_multicast"));
		if (controlrate_multicast < 0 || controlrate_multicast > 1024)
			controlrate_multicast = 0;
		if (controlrate_multicast)
		{
			sprintf(parm_buf, "%d", controlrate_multicast);
			eval("rtkswitch", "24", parm_buf);
		}
	
		/* broadcast storm control */
		if (!nvram_get("switch_ctrlrate_broadcast"))
			controlrate_broadcast = 0;
		else
			controlrate_broadcast = atoi(nvram_get("switch_ctrlrate_broadcast"));
		if (controlrate_broadcast < 0 || controlrate_broadcast > 1024)
			controlrate_broadcast = 0;
		if (controlrate_broadcast) {
			sprintf(parm_buf, "%d", controlrate_broadcast);
			eval("rtkswitch", "25", parm_buf);
		}
	}
	else if (access_point_mode())
	{
		if (merge_wan_port_into_lan_ports)
			eval("rtkswitch", "8", "100");
	}
#if defined(RTCONFIG_WIRELESSREPEATER) && defined(RTCONFIG_PROXYSTA)
	else if (mediabridge_mode())
	{
		if (merge_wan_port_into_lan_ports)
			eval("rtkswitch", "8", "100");
	}
#endif

	dbG("link up wan port(s)\n");
	eval("rtkswitch", "114");	// link up wan port(s)

	enable_jumbo_frame();

#if defined(RTCONFIG_BLINK_LED)
	if (is_swports_bled("led_lan_gpio")) {
		update_swports_bled("led_lan_gpio", nvram_get_int("lanports_mask"));
	}
	if (is_swports_bled("led_wan_gpio")) {
		update_swports_bled("led_wan_gpio", nvram_get_int("wanports_mask"));
	}
#if defined(RTCONFIG_WANLEDX2)
	if (is_swports_bled("led_wan2_gpio")) {
		update_swports_bled("led_wan2_gpio", nvram_get_int("wan1ports_mask"));
	}
#endif
#endif
}

int switch_exist(void)
{
	int i;
	char *switch_ifnames[4] = {
			"eth0" /* AQR107 */,
			"eth1" /* AR8035 */,
			"eth2" /* SFP+ */,
			"eth3" /* RTL8370MB */
		};

	for( i = 0 ; i < 4; ++i){
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
	_dprintf("Raymond: [%s][%d] skip\n", __func__, __LINE__);
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

//static int create_node=0;
void init_wl(void)
{
	_dprintf("[%s][%d] skip init_wl()\n", __func__, __LINE__);
}

void fini_wl(void)
{
	_dprintf("Raymond: [%s][%d] skip\n", __func__, __LINE__);
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
	char ethaddr[] = "00:11:22:33:44:55";
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
		if (buffer[0] != 0xff){
			ether_etoa(buffer, ethaddr);
			ether_etoa(buffer, macaddr);
		}
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
	inc_mac(macaddr, 1);
	nvram_set("et0macaddr", ethaddr);
	nvram_set("wl0_hwaddr", macaddr);
	nvram_set("et1macaddr", macaddr2);
	nvram_set("wl1_hwaddr", macaddr2);

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
		nvram_set("wl_pin_code", "12345670");
		nvram_set("secret_code", "12345670");
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
		nvram_set("productid", "GT-AC9600");
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

	_dprintf("bootloader version: %s\n", nvram_safe_get("blver"));
	_dprintf("firmware version: %s\n", nvram_safe_get("firmver"));

	nvram_set("wl1_txbf_en", "0");

#ifdef RTCONFIG_ODMPID
	FRead(modelname, OFFSET_ODMPID, sizeof(modelname));
	modelname[sizeof(modelname) - 1] = '\0';
	if (modelname[0] != 0 && (unsigned char)(modelname[0]) != 0xff
	    && is_valid_hostname(modelname)
	    && strcmp(modelname, "ASUS")) {
		nvram_set("odmpid", modelname);
	} else
#endif
		nvram_unset("odmpid");

	nvram_set("firmver", rt_version);
	nvram_set("productid", rt_buildname);

#if !defined(RTCONFIG_TCODE) // move the verification later bcz TCODE/LOC
	verify_ctl_table();
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
	_dprintf("Raymond: [%s][%d] skip\n", __func__, __LINE__);
}

char *get_staifname(int band)
{
	return (char*) ((!band)? STA_2G:STA_5G);
}

char *get_vphyifname(int band)
{
	return (char*) ((!band)? VPHY_2G:VPHY_5G);
}

/**
 * Generate interface name based on @band and @subunit. (@subunit is NOT y in wlX.Y)
 * @band:
 * @subunit:
 * @buf:
 * @return:
 */
char *__get_wlifname(int band, int subunit, char *buf)
{
	if (!buf)
		return buf;

	if (!subunit)
		strcpy(buf, (!band)? WIF_2G:WIF_5G);
	else
		sprintf(buf, "%s%02d", (!band)? WIF_2G:WIF_5G, subunit);

	return buf;
}

/**
 * Input @band and @ifname and return Y of wlX.Y.
 * Last digit of VAP interface name of guest is NOT always equal to Y of wlX.Y,
 * if guest network is not enabled continuously.
 * @band:
 * @ifname:	ath0, ath1, ath001, ath002, ath103, etc
 * @return:	index of guest network configuration. (wlX.Y: X = @band, Y = @return)
 * 		If both main 2G/5G, 1st/3rd 2G guest network, and 2-nd 5G guest network are enabled,
 * 		return value should as below:
 * 		ath0:	0
 * 		ath001:	1
 * 		ath002: 3
 * 		ath1:	0
 * 		ath101: 2
 */
int get_wlsubnet(int band, const char *ifname)
{
	int subnet, sidx;
	char buf[32];

	for (subnet = 0, sidx = 0; subnet < MAX_NO_MSSID; subnet++)
	{
		if(!nvram_match(wl_nvname("bss_enabled", band, subnet), "1")) {
			if (!subnet)
				sidx++;
			continue;
		}

		if(strcmp(ifname, __get_wlifname(band, sidx, buf)) == 0)
			return subnet;

		sidx++;
	}
	return -1;
}

#if defined(RTCONFIG_SOC_IPQ8064)
#define IPV46_CONN	4096
/**
 * Tell caller whether ecm should be loaded (non-zero value) or unloaded (zero value).
 * @return
 * 	0:	ecm should be unloaded
 *  otherwise:	ecm should be loaded
 */
int ecm_selection(void)
{
	int act = nvram_get_int("qca_sfe");	/* -1/0/otherwise: ignore/remove ecm/load ecm */

	/* If QoS is enabled, disable ecm.
	 * Including AiProtection due to BWDPI dep. module
	 * doesn't compatible to IPQ806x NSS NAT acceleration.
	 */
	if (nvram_get_int("qos_enable") == 1)
		act = 0;

	/* If Webs & APP, APPS analysis, Block Malicious Sites,
	 * Protect Against Vulnerabilities, or Block Infected Devices
	 * is enabled, disable ecm.
	 */
	if (nvram_match("apps_analysis", "1") ||
	    nvram_match("wrs_app_enable", "1") ||
	    nvram_match("wrs_mals_enable", "1") ||
	    nvram_match("wrs_cc_enable", "1") ||
	    nvram_match("wrs_vp_enable", "1"))
		act = 0;

	/* If IPSec is enabled, disable ecm. */
	if (nvram_get_int("ipsec_server_enable") == 1 || nvram_get_int("ipsec_client_enable") == 1
#ifdef RTCONFIG_INSTANT_GUARD
		 || nvram_get_int("ipsec_ig_enable") == 1
#endif
	 )
		act = 0;

	/* URL filter and keyword filter are not compatible to IPQ806x NSS NAT acceleration and IPQ40XX shortcut-fe.
	 * But they do works with QCA955X shortcut-fe.
	 */
	if ((nvram_match("url_enable_x", "1") && !nvram_match("url_rulelist", "")) ||
	    (nvram_match("keyword_enable_x", "1") && !nvram_match("keyword_rulelist", "")))
		act = 0;

	if (act > 0) {
		/* FIXME: IPTV, ISP profile, USB modem, etc. */
	}

	dbg("%s: nat_x %d qos %d: action %d.\n", __func__,
		nvram_get_int("wan0_nat_x"), nvram_get_int("qos_enable"), act);

	return act? 1 : 0;
}

void init_ecm(void)
{
	/* Always enable NSS RPS */
	f_write_string("/proc/sys/dev/nss/general/rps", "1", 0, 0);

	/* Turn off bridge firewall first. */
	f_write_string("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "0", 0, 0);
	f_write_string("/proc/sys/net/bridge/bridge-nf-call-iptables", "0", 0, 0);
}

// ecm kernel module must be loaded before bonding interface creation!
// only qca solution can reload it dynamically
// only happened when qca_sfe=1
// only loaded when unloaded, and unloaded when loaded
// in restart_firewall for fw_pt_l2tp/fw_pt_ipsec
// in restart_qos for qos_enable
// in restart_wireless for wlx_mrate_x, etc
void reinit_ecm(int unit)
{
	int i, act;
	struct load_nat_accel_kmod_seq_s *p = &load_nat_accel_kmod_seq[0];

	act = ecm_selection();
	if (!act) {
		/* remove ecm */
		for (i = ARRAY_SIZE(load_nat_accel_kmod_seq) - 1, p = &load_nat_accel_kmod_seq[i]; i >= 0; --i, --p) {
			if (!module_loaded(p->kmod_name))
				continue;

			dbg("%s: Remove %s\n", __func__, p->kmod_name);
			modprobe_r(p->kmod_name);
			if (p->remove_sleep)
				sleep(p->load_sleep);
		}
	} else {
		/* load ecm */
		for (i = 0, p = &load_nat_accel_kmod_seq[i]; i < ARRAY_SIZE(load_nat_accel_kmod_seq); ++i, ++p) {
			if (module_loaded(p->kmod_name))
				continue;

			dbg("%s: Load %s\n", __func__, p->kmod_name);
			modprobe(p->kmod_name);
			if (p->load_sleep)
				sleep(p->load_sleep);
		}
	}

	post_ecm();
}

void post_ecm(void)
{
	int act, r;
	char val[4], tmp[16], ipv46_conn[16];

	snprintf(ipv46_conn, sizeof(ipv46_conn), "%d", IPV46_CONN);
	*tmp = '\0';
	r = f_read_string("/proc/sys/dev/nss/ipv4cfg/ipv4_conn", tmp, sizeof(tmp));
	if (r > 0 && atoi(tmp) != IPV46_CONN)
		r = f_write_string("/proc/sys/dev/nss/ipv4cfg/ipv4_conn", ipv46_conn, 0, 0);
	*tmp = '\0';
	r = f_read_string("/proc/sys/dev/nss/ipv6cfg/ipv6_conn", tmp, sizeof(tmp));
	if (r > 0 && atoi(tmp) != IPV46_CONN)
		r = f_write_string("/proc/sys/dev/nss/ipv6cfg/ipv6_conn", ipv46_conn, 0, 0);

	act = ecm_selection();
	snprintf(val, sizeof(val), "%d", !!act);
	f_write_string("/proc/sys/dev/nss/general/redirect", val, 0, 0);
	f_write_string("/proc/sys/net/bridge/bridge-nf-call-ip6tables", val, 0, 0);
	f_write_string("/proc/sys/net/bridge/bridge-nf-call-iptables", "0"/*val*/, 0, 0);

	/* Limit ecm db usage */
	if (act) {
		f_write_string("/sys/kernel/debug/ecm/ecm_nss_ipv4/db_limit_mode", "1", 0, 0);
		f_write_string("/sys/kernel/debug/ecm/ecm_nss_ipv6/db_limit_mode", "1", 0, 0);
	}
}
#endif	/* RTCONFIG_SOC_IPQ8064 */

char *get_wlifname(int unit, int subunit, int subunit_x, char *buf)
{
#if 1
	char wifbuf[32];
	char prefix[] = "wlXXXXXX_", tmp[100];
#if defined(RTCONFIG_WIRELESSREPEATER)
	if (sw_mode() == SW_MODE_REPEATER
	    && nvram_get_int("wlc_band") == unit && subunit == 1) {
		strcpy(buf, get_staifname(unit));
	} else
#endif /* RTCONFIG_WIRELESSREPEATER */
	{
		__get_wlifname(unit, 0, wifbuf);
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
		if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
			sprintf(buf, "%s0%d", wifbuf, subunit_x);
		else
			sprintf(buf, "%s", "");
	}
	return buf;
#else
	return __get_wlifname(unit, subunit, buf);
#endif
}

int wl_exist(char *ifname, int band)
{
	int i;
	char *wl_ifnames[2] = {
		"host0" /* 2G */,
		"host0" /* 5G */
	};

	for( i = 0 ; i < 2; i++){
		if(is_if_up(wl_ifnames[i]) == 0)
			return 0;
	}

	return 1;
}

void
set_wan_tag(char *interface) {
	int model, wan_vid; //, iptv_vid, voip_vid, wan_prio, iptv_prio, voip_prio;
	char wan_dev[10], port_id[7];

	model = get_model();
	wan_vid = nvram_get_int("switch_wan0tagid");
//	iptv_vid = nvram_get_int("switch_wan1tagid");
//	voip_vid = nvram_get_int("switch_wan2tagid");
//	wan_prio = nvram_get_int("switch_wan0prio");
//	iptv_prio = nvram_get_int("switch_wan1prio");
//	voip_prio = nvram_get_int("switch_wan2prio");

	sprintf(wan_dev, "vlan%d", wan_vid);

	switch(model) {
	case MODEL_GTAC9600:
		ifconfig(interface, IFUP, 0, 0);
		if(wan_vid) { /* config wan port */
			eval("vconfig", "rem", "vlan2");
			sprintf(port_id, "%d", wan_vid);
			eval("vconfig", "add", interface, port_id);
		}
		/* Set Wan port PRIO */
		if(nvram_invmatch("switch_wan0prio", "0"))
			eval("vconfig", "set_egress_map", wan_dev, "0", nvram_get("switch_wan0prio"));
		break;
	}
}

int start_thermald(void)
{
	char *thermald_argv[] = {"thermald", "-c", "/etc/thermal/ipq-thermald-8064.conf", NULL};
	pid_t pid;

	return _eval(thermald_argv, NULL, 0, &pid);
}

#ifdef RTCONFIG_TAGGED_BASED_VLAN

/* set all ports accept all packets(tagged or untagged) */
void vlan_switch_accept_all(void)
{
	eval("rtkswitch","300",NULL);
}

void vlan_switch_setup(int vlan_id, int vlan_prio, int lanportset)
{
	char vlan_id_str[12]={0},vlan_prio_str[12]={0};
	char lanportset_str[16]={0};

	sprintf(vlan_id_str,"%d",vlan_id);
	sprintf(vlan_prio_str,"%d",vlan_prio);
	//lanportset |= ( 1<<15 );
	sprintf(lanportset_str,"0x%x",lanportset);

	eval("rtkswitch","301",vlan_id_str);
	eval("rtkswitch","302",vlan_prio_str);
	eval("rtkswitch","303",lanportset_str);
}

int vlan_switch_pvid_setup(int *pvid_list, int *pprio_list, int size)
{
	int i=0;
	char port_str[8]={0};
	char pvid_str[8]={0};
	char pprio_str[8]={0};

	if(!pvid_list && !pprio_list)
		return -1;

	for(i=0;i<size;i++)
	{
		memset(port_str,0,8);
		memset(pvid_str,0,8);
		memset(pprio_str,0,8);
		sprintf(port_str,"%d",i);
		sprintf(pvid_str,"%d",pvid_list[i]);
		sprintf(pprio_str,"%d",pprio_list[i]);

		eval("rtkswitch","305",pvid_str);
		eval("rtkswitch","306",pprio_str);
		eval("rtkswitch","307",port_str);
	}

	return 0;
}

#endif

