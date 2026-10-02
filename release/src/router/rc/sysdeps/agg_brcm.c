#include <string.h>
#include "rc.h"
#include "tcode.h"

#if defined(RTCONFIG_LACP)

#if defined(RTAC88U)
#define MODEL_PROTECT "RT-AC88U"
#endif

#if defined(RTAC86U)
#define MODEL_PROTECT "RT-AC86U"
#endif

#if defined(GTAC2900)
#define MODEL_PROTECT "GT-AC2900"
#endif

#if defined(RTAC3100)
#define MODEL_PROTECT "RT-AC3100"
#endif

#if defined(RTAC5300)
#define MODEL_PROTECT "RT-AC5300"
#endif

#if defined(GTAC5300)
#define MODEL_PROTECT "GT-AC5300"
#endif

#if defined(RTAX88U)
#define MODEL_PROTECT "RT-AX88U"
#endif

#if defined(GTAX11000)
#define MODEL_PROTECT "GT-AX11000"
#endif

#if defined(RTAX92U)
#define MODEL_PROTECT "RT-AX92U"
#endif

#if defined(RTAX58U) || defined(TUFAX3000) || defined(TUFAX5400) || defined(RTAX82U) || defined(GSAX3000) || defined(GSAX5400)
#define MODEL_PROTECT "RT-AX58U"
#endif

#if defined(RTAX86U) || defined(RTAX5700)
#define MODEL_PROTECT "RT-AX86U"
#endif

#if defined(RTAX68U)
#define MODEL_PROTECT "RT-AX68U"
#endif

#if defined(RTAC87U)
#define MODEL_PROTECT "RT-AC87U"
#endif

#if defined(GTAXE11000)
#define MODEL_PROTECT "GT-AXE11000"
#endif

#if defined(GTAX6000)
#define MODEL_PROTECT "GT-AX6000"
#endif

#if defined(GTAX11000_PRO)
#define MODEL_PROTECT "GT-AX11000 PRO"
#endif

#if defined(GTAXE16000)
#define MODEL_PROTECT "GT-AXE16000"
#endif

#if defined(ET12)
#define MODEL_PROTECT "ET12"
#endif

#if defined(XT12)
#define MODEL_PROTECT "XT12"
#endif

#if defined(XT8PRO)
#define MODEL_PROTECT "ZenWiFi_XT8P"
#endif

#if defined(ET8PRO)
#define MODEL_PROTECT "ZenWiFi_ET8P"
#endif

#ifndef MODEL_PROTECT
#define MODEL_PROTECT "NOT_SUPPORT"
#endif

#if defined(RTAC88U) || defined(RTAC3100)
#define LACP_DEV "vlan1"
#define LACP_PORTS "2 3"
#endif

#if defined(RTAC87U) || defined(RTAC5300)
#define LACP_DEV "vlan1"
#define LACP_PORTS "1 2"
#endif

#if defined(GTAC5300) || defined(RTAC86U) || defined(GTAC2900)
#define LACP_DEV "bond0"
#define LACP_PORTS "3 4"
#define LACP_IFNAMES "eth3 eth4"
#endif

#if defined(RTAX88U) || defined(GTAX11000) || defined(RTAX92U) || defined(RTAX86U) || defined(RTAX5700) || defined(RTAX68U)
#define LACP_DEV "bond0"
#define LACP_PORTS "2 3"
#define LACP_IFNAMES "eth3 eth4"
#define LACP_PORTS_4PORTS "0 1 2 3"
#define LACP_IFNAMES_4PORTS "eth1 eth2 eth3 eth4"
#if defined(RTAX88U) || defined(RTAX92U) || defined(RTAX68U)
#define LACP_WAN_IFNAMES "eth0 eth1"
#define LACP_WAN_PORTS "7 0"
#elif defined(GTAX11000) || defined(RTAX86U) || defined(RTAX5700)
#define LACP_WAN_IFNAMES "eth0 eth1"
#ifdef RTCONFIG_EXTPHY_BCM84880
#define LACP_WAN_PORTS "4 0"
#else
#define LACP_WAN_PORTS "7 0"
#endif
#endif
#endif

#if defined(RTAX58U) || defined(TUFAX3000) || defined(TUFAX5400) || defined(RTAX82U) || defined(GSAX3000) || defined(GSAX5400)
#define LACP_DEV "bond0"
#define LACP_PORTS "2 3"
#define LACP_IFNAMES "eth2 eth3"
#define LACP_PORTS_4PORTS "0 1 2 3"
#define LACP_IFNAMES_4PORTS "eth0 eth1 eth2 eth3"
#define LACP_WAN_PORTS "0 4"
#define LACP_WAN_IFNAMES "eth0 eth4"
#endif

#if defined(GTAXE11000)
#define LACP_DEV "bond0"
#define LACP_PORTS "0 3"
#define LACP_IFNAMES "eth1 eth4"
#define LACP_PORTS_4PORTS "0 1 2 3"
#define LACP_IFNAMES_4PORTS "eth1 eth2 eth3 eth4"
#define LACP_WAN_PORTS "4 2"
#define LACP_WAN_IFNAMES "eth0 eth3"
#endif

#if defined(GTAX6000)
#define LACP_DEV "bond0"
#define LACP_PORTS "1 2"
#define LACP_IFNAMES "eth1 eth2"
#define LACP_PORTS_4PORTS "1 2 3 4"
#define LACP_IFNAMES_4PORTS "eth1 eth2 eth3 eth4"
#define LACP_WAN_PORTS "0 4"
#define LACP_WAN_IFNAMES "eth0 eth4"
#endif

#if defined(GTAX11000_PRO)
#define LACP_DEV "bond0"
#define LACP_PORTS "1 2"
#define LACP_IFNAMES "eth1 eth2"
#define LACP_PORTS_4PORTS "1 2 3 4"
#define LACP_IFNAMES_4PORTS "eth1 eth2 eth3 eth4"
#define LACP_WAN_PORTS "0 4"
#define LACP_WAN_IFNAMES "eth0 eth4"
#endif

#if defined(GTAXE16000)
#define LACP_DEV "bond0"
#define LACP_PORTS "1 2"
#define LACP_IFNAMES "eth1 eth2"
#define LACP_PORTS_4PORTS "1 2 3 4"
#define LACP_IFNAMES_4PORTS "eth1 eth2 eth3 eth4"
#define LACP_WAN_PORTS "0 4"
#define LACP_WAN_IFNAMES "eth0 eth4"
#endif

#if defined(ET12) || defined(XT12)
#define LACP_DEV "bond0"
#define LACP_PORTS "1 2"
#define LACP_IFNAMES "eth1 eth2"
#define LACP_WAN_PORTS "0 3"
#define LACP_WAN_IFNAMES "eth0 eth3"
#endif

#if defined(TUFAX3000_V2) || defined(RTAXE7800)
#define LACP_DEV "bond0"
#define LACP_PORTS "1 2"
#define LACP_IFNAMES "eth1 eth2"
#define LACP_WAN_PORTS "0 4"
#define LACP_WAN_IFNAMES "eth0 eth4"
#endif

#if defined(XT8PRO) || defined(ET8PRO)
#ifdef RTCONFIG_BONDING
#define LACP_DEV "bond0"
#define LACP_PORTS "0 3"
#define LACP_IFNAMES "eth2 eth3"
#endif
#endif

#define POLICY_DEF	0
#define POLICY_DST	1
#define POLICY_SRC	2

#define MAX_LACP_PORTS	4
int get_bonding_enabled(void);

/* BRCM 802.3ad (LACP) */
void config_lacp(void)
{
#if defined(RTCONFIG_CFEZ) && defined(RTCONFIG_BCMARM)
#if defined(RTAX58U) || defined(TUFAX3000) || defined(TUFAX5400) || defined(RTAX82U) || defined(GSAX3000) || defined(GSAX5400)
        if (strncmp(nvram_safe_get("model"), MODEL_PROTECT, sizeof(MODEL_PROTECT)) != 0){
#else
	if (strcmp(nvram_safe_get("model"), MODEL_PROTECT) != 0){
#endif
#else
	if (strcmp(cfe_nvram_safe_get("model"), MODEL_PROTECT) != 0){
#endif
		_dprintf("illegal, cannot enable LACP\n");
		return;
	}else{
		_dprintf("[%s][%d] %s could enable LACP\n", __func__, __LINE__, nvram_safe_get("model"));
	}

	if(get_bonding_enabled() == 1){
#ifdef RTCONFIG_BCMARM
		switch(atoi(nvram_safe_get("bonding_policy"))) {
		case POLICY_DST:	// source bonding
#ifdef HND_ROUTER
#ifndef RTCONFIG_BONDING_WAN
			eval("ethswctl", "-c", "regaccess", "-v", "0x3200", "-l", "1", "-d", "0x9");
#endif
#else
			eval("et", "-i", "eth0", "robowr", "0x32", "0", "0x9");
#endif
			break;
		case POLICY_SRC:	// dst bonding
#ifdef HND_ROUTER
#ifndef RTCONFIG_BONDING_WAN
			eval("ethswctl", "-c", "regaccess", "-v", "0x3200", "-l", "1", "-d", "0xa");
#endif
#else
			eval("et", "-i", "eth0", "robowr", "0x32", "0", "0xa");
#endif
			break;
		default:		// policy is src^dst
#ifdef HND_ROUTER
#ifndef RTCONFIG_BONDING_WAN
			eval("ethswctl", "-c", "regaccess", "-v", "0x3200", "-l", "1", "-d", "0x8");
#endif
#else
			eval("et", "-i", "eth0", "robowr", "0x32", "0", "0x8");
#endif
			break;
		}
#endif
		nvram_set("lacp", "1");
		nvram_set("lacpdev", LACP_DEV);
		nvram_set("lacpmode", "1");
		nvram_set("lacpdebug", "0");
#ifdef RTCONFIG_HND_ROUTER_AX
		nvram_set("lacpports", LACP_PORTS);
		nvram_set("lacp_rate", "1");
		if(!strlen(nvram_safe_get("lacp_ifnames_x")))
			nvram_set("lacp_ifnames", LACP_IFNAMES);
		else
			nvram_set("lacp_ifnames", nvram_safe_get("lacp_ifnames_x"));
#ifdef RTCONFIG_BONDING_WAN
		if(!strlen(nvram_safe_get("bond_wan_ifnames_x")))
			nvram_set("bond_wan_ifnames", LACP_WAN_IFNAMES);
		else
			nvram_set("bond_wan_ifnames", nvram_safe_get("bond_wan_ifnames_x"));
#ifdef RTAX86U
		if(!strcmp(get_productid(), "RT-AX86S"))
			nvram_set("wanports_bond", "7 0");
		else
#endif
		nvram_set("wanports_bond", LACP_WAN_PORTS);
#endif
#else
		nvram_set("lacpports", LACP_PORTS);
#ifdef HND_ROUTER
		nvram_set("lacp_rate", "1");
		if(!strlen(nvram_safe_get("lacp_ifnames_x")))
			nvram_set("lacp_ifnames", LACP_IFNAMES);
		else
			nvram_set("lacp_ifnames", nvram_safe_get("lacp_ifnames_x"));
#else
		modprobe("lacp");
#endif
#endif
	}else{
		nvram_unset("lacp");
		nvram_unset("lacpdev");
		nvram_unset("lacpmode");
		nvram_unset("lacpgrp0ports");
		nvram_unset("lacpdebug");
#ifdef HND_ROUTER
		nvram_unset("lacp_rate");
		nvram_unset("lacp_ifnames");
		eval("brctl", "delif", "br0", "bond0");
		eval("ifconfig", "bond0", "down");
		modprobe_r("bonding");
#else
		modprobe_r("lacp");
#endif
	}
}

int
get_bonding_enabled(void)
{
	int enable = 0;

	if (nvram_match("lacp_enabled", "1"))
		enable= 1;
#ifdef RTCONFIG_BONDING_WAN
	if (nvram_match("bond_wan", "1"))
		enable= 1;
#endif
	return enable;
}

uint32
get_bonding_ports(void)
{
	char port[] = "XXXX", *next;
	char ports[128], *cur;
	int pid, len;
	uint32 portmask = 0;

	/* get lacp ports defeinitions from nvram */
	snprintf(ports, sizeof(ports), "%s", nvram_safe_get("lacpports"));
	printf("lacpports %s\n", ports);
	if(strlen(ports) > 0){
		for (cur = ports; cur; cur = next) {
			/* tokenize the port list */
			while (*cur == ' ')
				cur ++;
			next = strstr(cur, " ");
			len = next ? next - cur : strlen(cur);
			if (!len)
				break;
			if (len > sizeof(port) - 1)
				len = sizeof(port) - 1;
			strncpy(port, cur, len);
			port[len] = 0;

			/* make sure port # is within the range */
			/* TOF: suppor port1 ~ port4 now */
			pid = atoi(port);
			if (pid == 0 || pid > MAX_LACP_PORTS) {
				printf("ERROR: port %d is out of range[1-%d]\n",
					pid, MAX_LACP_PORTS);
				continue;
			}
			portmask |= (1 << pid);
		}
	}
	/* WAN port can't be lacp ports now */
	portmask >>= 1;
	printf("lacp portmask 0x%4.4x\n", portmask);

	return portmask;
}

#define SYS_BONDING_IF			"/sys/class/net/%s/bonding/slaves"
#define LAN_BONDING_IFNAME		"bond0"
#ifdef RTCONFIG_BONDING_WAN
#define WAN_BONDING_IFNAME		"bond1"
#endif
#define MAX_BONDIF				4

#ifdef RTCONFIG_HND_ROUTER_AX
static void
start_lan_bonding(void)
{
	char *bond_lan_ifnames;
	char *lan_ifname = nvram_safe_get("lan_ifname");
	char *wan_ifname = nvram_safe_get("wan_ifname");
	char name[80], *next;
	char ifname[MAX_BONDIF][IFNAMSIZ];
	char confbuf[64] = {0};
	char cmdbuf[64] = {0};
	int i, count;

	/* Setup LAN bonding: bond0 */
	if (nvram_match("lacp_enabled", "1")) {
		bond_lan_ifnames = nvram_safe_get("lacp_ifnames");
		/* Set default bond_lan_ifnames if it doesn't set */
		if (strcmp(bond_lan_ifnames, "") == 0) {
			if(!strlen(nvram_safe_get("lacp_ifnames_x")))
				nvram_set("lacp_ifnames", LACP_IFNAMES);
			else
				nvram_set("lacp_ifnames", nvram_safe_get("lacp_ifnames_x"));
			bond_lan_ifnames = nvram_safe_get("lacp_ifnames");
		}

#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
		doSystem("echo +%s > /sys/class/net/bonding_masters", LAN_BONDING_IFNAME);
		set_hwaddr(LAN_BONDING_IFNAME, (const char *) get_lan_hwaddr());
#endif
#if defined(BCM4912)
		doSystem("echo 1 > /sys/class/net/%s/bonding/async_linkspeed", LAN_BONDING_IFNAME);
#endif
		count = 0;
		foreach(name, bond_lan_ifnames, next) {
			if ((strncmp(name, "eth", 3) != 0) && (strncmp(name, wan_ifname, 4) == 0)) {
				fprintf(stderr, "[%s][%d] %s can't be the interface for bonding\n", __func__, __LINE__, name);
				return;
			}
			strncpy(ifname[count], name, IFNAMSIZ);
			count++;
			if (count > MAX_BONDIF) {
				fprintf(stderr, "[%s][%d] Too much port for LAN bonding: %d\n", __func__, __LINE__, count);
				return;
			}
		}

		for (i = 0; i < count; i++) {
			/* Bring down LAN interface */
			ifconfig(ifname[i], 0, NULL, NULL);

			eval("brctl", "delif", lan_ifname, ifname[i]);

			snprintf(confbuf, sizeof(confbuf), SYS_BONDING_IF, LAN_BONDING_IFNAME);
			snprintf(cmdbuf, sizeof(cmdbuf), "echo +%s > %s", ifname[i], confbuf);
			system(cmdbuf);

			ifconfig(ifname[i], IFUP | IFF_ALLMULTI, NULL, NULL);
		}
		ifconfig(LAN_BONDING_IFNAME, IFUP | IFF_ALLMULTI, NULL, NULL);
		eval("brctl", "addif", lan_ifname, LAN_BONDING_IFNAME);
	}
	_dprintf("[%s][%d]\n", __func__, __LINE__);

	return;
}

#ifdef RTCONFIG_BONDING_WAN
void start_wan_bonding(void)
{
	char *bond_wan_ifnames;
	char *lan_ifname = nvram_safe_get("lan_ifname");
	char *wan_ifname = nvram_safe_get("wan_ifname");
	char name[80], *next;
	char ifname[MAX_BONDIF][IFNAMSIZ];
	char confbuf[64] = {0};
	char cmdbuf[64] = {0};
	int i, count;

	if (nvram_get_int("sw_mode") != 1) {
		fprintf(stderr, "WAN bonding support router mode only\n");
		return ;
	}

	if (nvram_match("wan_ifname", WAN_BONDING_IFNAME)) {
		fprintf(stderr, "WAN bonding is already enabled\n");
		return ;
	}

	if (nvram_match("bond_wan", "1")) {
		bond_wan_ifnames = nvram_safe_get("bond_wan_ifnames");
		/* Set default bond_wan_ifnames if it doesn't set */
		if (strcmp(bond_wan_ifnames, "") == 0) {
			if(!strlen(nvram_safe_get("bond_wan_ifnames_x")))
				nvram_set("bond_wan_ifnames", LACP_WAN_IFNAMES);
			else
				nvram_set("bond_wan_ifnames", nvram_safe_get("bond_wan_ifnames_x"));
			bond_wan_ifnames = nvram_safe_get("bond_wan_ifnames");
		}

		count = 0;
		foreach(name, bond_wan_ifnames, next) {
			strncpy(ifname[count], name, IFNAMSIZ);
			count++;
		}

		if (count != 2) {
			fprintf(stderr, "WAN bonding support two ports only: %d\n", count);
			return;
		}
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
		doSystem("echo +%s > /sys/class/net/bonding_masters", WAN_BONDING_IFNAME);
		set_hwaddr(WAN_BONDING_IFNAME, (const char *) get_wan_hwaddr());
#endif
#if defined(BCM4912)
		doSystem("echo 1 > /sys/class/net/%s/bonding/async_linkspeed", WAN_BONDING_IFNAME);
#endif
		/* Bring down bond interface */
		ifconfig(WAN_BONDING_IFNAME, 0, NULL, NULL);
		for (i = 0; i < count; i++) {
			ifconfig(ifname[i], 0, NULL, NULL);

			if (strncmp(ifname[i], wan_ifname, 4) != 0) {
				eval("brctl", "delif", lan_ifname, ifname[i]);
			}

			snprintf(confbuf, sizeof(confbuf), SYS_BONDING_IF, WAN_BONDING_IFNAME);
			snprintf(cmdbuf, sizeof(cmdbuf), "echo +%s > %s", ifname[i], confbuf);
			system(cmdbuf);

			ifconfig(ifname[i], IFUP, NULL, NULL);
		}
		/* Bring up bond interface */
		ifconfig(WAN_BONDING_IFNAME, IFUP, NULL, NULL);

		nvram_set("wan_ifnames_bk", nvram_safe_get("wan_ifnames"));

		nvram_set("wan_ifnames", WAN_BONDING_IFNAME);
		nvram_set("wan0_ifnames", WAN_BONDING_IFNAME);
		nvram_set("wan_ifname", WAN_BONDING_IFNAME);
		nvram_set("wan0_ifname", WAN_BONDING_IFNAME);
	}
	_dprintf("[%s][%d]\n", __func__, __LINE__);
}
#endif

static void
stop_lan_bonding(void)
{
	char *lan_ifname = nvram_safe_get("lan_ifname");
	char bond_lan_ifnames[80];
	char name[80], *next;
	char ifname[MAX_BONDIF][IFNAMSIZ];
	char confbuf[64] = {0};
	char cmdbuf[64] = {0};
	int i, count;

	/* Stop LAN bonding: bond0 */
	memset(bond_lan_ifnames, 0, sizeof(bond_lan_ifnames));
	snprintf(bond_lan_ifnames, sizeof(bond_lan_ifnames), "%s",
				nvram_safe_get("lacp_ifnames"));

	if (strnlen(bond_lan_ifnames, sizeof(bond_lan_ifnames)) != 0){
		count = 0;
		foreach(name, bond_lan_ifnames, next) {
			strncpy(ifname[count], name, IFNAMSIZ);
			count++;
		}

		/* Bring down bond interface */
		ifconfig(LAN_BONDING_IFNAME, 0, NULL, NULL);
		eval("brctl", "delif", lan_ifname, LAN_BONDING_IFNAME);
		for (i = 0; i < count; i++) {
			/* Bring down LAN interface */
			ifconfig(ifname[i], 0, NULL, NULL);

			snprintf(confbuf, sizeof(confbuf), SYS_BONDING_IF, LAN_BONDING_IFNAME);
			snprintf(cmdbuf, sizeof(cmdbuf), "echo -%s > %s", ifname[i], confbuf);
			system(cmdbuf);

			eval("brctl", "addif", lan_ifname, ifname[i]);
			ifconfig(ifname[i], IFUP | IFF_ALLMULTI, NULL, NULL);
		}
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
		doSystem("echo -%s > /sys/class/net/bonding_masters", LAN_BONDING_IFNAME);
#endif
	}
	_dprintf("[%s][%d]\n", __func__, __LINE__);

	return;
}

#ifdef RTCONFIG_BONDING_WAN
void stop_wan_bonding(void)
{
	char *lan_ifname = nvram_safe_get("lan_ifname");
	char wan_ifnames_bk[128] = {0};
	char bond_wan_ifnames[80];
	char name[80], *next;
	char ifname[MAX_BONDIF][IFNAMSIZ];
	char confbuf[64] = {0};
	char cmdbuf[64] = {0};
	int i, count;
	char wan_ifnames[128] = {0};

	if (nvram_get_int("sw_mode") != 1) {
		fprintf(stderr, "WAN bonding support router mode only\n");
		return ;
	}

	if (!nvram_match("wan_ifname", WAN_BONDING_IFNAME)) {
		fprintf(stderr, "WAN bonding is already disabled\n");
		return ;
	}

	memset(bond_wan_ifnames, 0, sizeof(bond_wan_ifnames));
	snprintf(bond_wan_ifnames, sizeof(bond_wan_ifnames), "%s",
				nvram_safe_get("bond_wan_ifnames"));

	snprintf(wan_ifnames, sizeof(wan_ifnames), "%s",
		nvram_safe_get("wan_ifnames"));

	snprintf(wan_ifnames_bk, sizeof(wan_ifnames_bk), "%s",
		nvram_safe_get("wan_ifnames_bk"));

	if (strcmp(nvram_safe_get("wan_ifnames_bk"), "") == 0){
		nvram_set("wan_ifnames_bk", wan_ifnames);
		snprintf(wan_ifnames_bk, sizeof(wan_ifnames_bk), "%s",
			nvram_safe_get("wan_ifnames_bk"));
	}

	if (strnlen(bond_wan_ifnames, sizeof(bond_wan_ifnames)) != 0){
		count = 0;

		foreach(name, bond_wan_ifnames, next) {
			strncpy(ifname[count], name, IFNAMSIZ);
			count++;
		}

		/* Bring down bond interface */
		ifconfig(WAN_BONDING_IFNAME, 0, NULL, NULL);
		for (i = 0; i < count; i++) {
			/* Bring down WAN interfaces */
			ifconfig(ifname[i], 0, NULL, NULL);

			snprintf(confbuf, sizeof(confbuf), SYS_BONDING_IF, WAN_BONDING_IFNAME);
			snprintf(cmdbuf, sizeof(cmdbuf), "echo -%s > %s", ifname[i], confbuf);
			system(cmdbuf);

			if (strncmp(ifname[i], wan_ifnames_bk, 4) != 0)
				eval("brctl", "addif", lan_ifname, ifname[i]);

			ifconfig(ifname[i], IFUP | IFF_ALLMULTI, NULL, NULL);
		}
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
		doSystem("echo -%s > /sys/class/net/bonding_masters", WAN_BONDING_IFNAME);
#endif
	}

	_dprintf("[%s][%d]\n", __func__, __LINE__);
}
#endif

void
start_bonding(void)
{
	/* Setup LAN bonding: bond0 */
	if(nvram_get_int("lacp_enabled") == 1)
		start_lan_bonding();
	else
		stop_lan_bonding();

	return;
}
#endif // RTCONFIG_HND_ROUTER_AX

void bonding_init(void)
{
	char tmp[200];
	char lacp_rate = 0, bonding_ifnames[80];
	int bonding_enabled = 0;

	bonding_enabled = get_bonding_enabled();
	_dprintf("lacp %s\n", bonding_enabled ? "enabled" : "disabled");
	if (bonding_enabled) {
#ifdef RTCONFIG_HND_ROUTER_AX
		lacp_rate = nvram_match("lacp_rate", "1") ? 1 : 0;
		//100ms MII monitor event, IEEE 802.3ad, count select logic,layer3+4 hash policy, duplicate frames are delivered
		sprintf(tmp, "insmod /lib/modules/*/kernel/drivers/net/bonding/bonding.ko" \
			" miimon=100 mode=4 ad_select=2 xmit_hash_policy=1 all_slaves_active=1 lacp_rate=%d", lacp_rate);
#else
		if (nvram_match("lacp_rate", "1")) {
			lacp_rate= 1;
		}
		sprintf(tmp, "insmod /lib/modules/*/kernel/drivers/net/bonding/bonding.ko" \
			" mode=4 miimon=100 lacp_rate=%d", lacp_rate);
#endif
		system(tmp);
		memset(bonding_ifnames, 0, sizeof(bonding_ifnames));
		strlcpy(bonding_ifnames, nvram_safe_get("lacp_ifnames"), strlen(nvram_safe_get("lacp_ifnames"))+1);
		_dprintf("[%s][%d] bonding ifnames is %s\n", __func__, __LINE__, bonding_ifnames);
	}
}

void bonding_uninit(void)
{
}

void bonding_config(void)
{
	int bonding_enabled = 0;
#if !defined(RTCONFIG_HND_ROUTER_AX) || !defined(RTCONFIG_BONDING_WAN)
	char tmp[200];
	char bonding_ifnames[80];
	char word[256], *next;
#endif
#ifndef RTCONFIG_HND_ROUTER_AX
	uint32 bonding_portmask = 0;
#endif
	char slaves[32];
#if defined(XT8PRO)
	char confbuf[64] = {0};
	char cmdbuf[64] = {0};
#endif

#ifndef RTCONFIG_BONDING_WAN
	memset(tmp, 0, sizeof(tmp));
	memset(bonding_ifnames, 0, sizeof(bonding_ifnames));
	strlcpy(bonding_ifnames, nvram_safe_get("lacp_ifnames"),
			strlen(nvram_safe_get("lacp_ifnames"))+1);
	_dprintf("[%s][%d] bonding ifnames is %s\n", __func__, __LINE__,
			bonding_ifnames);
#endif
	memset(slaves, 0, sizeof(slaves));

	bonding_enabled = get_bonding_enabled();

	/* Configure Bonding */
	if (bonding_enabled) {
#ifdef RTCONFIG_HND_ROUTER_AX
#ifdef RTCONFIG_BONDING_WAN
		start_bonding();
#else
		foreach(word, nvram_safe_get("lacp_ifnames"), next)
			eval("brctl", "delif", "br0", word);

		ifconfig("bond0", IFUP, NULL, NULL);

		f_read_string("/sys/devices/virtual/net/bond0/bonding/slaves", slaves, sizeof(slaves));
		foreach(word, bonding_ifnames, next)
			if (!strstr(slaves, word))
				doSystem("ifenslave bond0 %s", word);

		eval("brctl", "addif", nvram_safe_get("lan_ifname"), "bond0");

#if defined(XT8PRO)
		eval("brctl", "delif", nvram_safe_get("lan_ifname"), LAN_BONDING_IFNAME);
		foreach(word, nvram_safe_get("lacp_ifnames"), next){
			memset(confbuf, 0, sizeof(confbuf));
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(confbuf, sizeof(confbuf), SYS_BONDING_IF, LAN_BONDING_IFNAME);
			snprintf(cmdbuf, sizeof(cmdbuf), "echo -%s > %s", word, confbuf);
			system(cmdbuf);
		}

		eval("brctl", "addif", nvram_safe_get("lan_ifname"), LAN_BONDING_IFNAME);

		foreach(word, nvram_safe_get("lacp_ifnames"), next){
			memset(confbuf, 0, sizeof(confbuf));
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(confbuf, sizeof(confbuf), SYS_BONDING_IF, LAN_BONDING_IFNAME);
			snprintf(cmdbuf, sizeof(cmdbuf), "echo +%s > %s", word, confbuf);
			system(cmdbuf);
		}
#endif

#endif
#else
		/* Bring up bond0 interface */
		ifconfig("bond0", IFUP, NULL, NULL);

		f_read_string("/sys/devices/virtual/net/bond0/bonding/slaves", slaves, sizeof(slaves));
		foreach(word, bonding_ifnames, next)
			if (!strstr(slaves, word))
				doSystem("ifenslave bond0 %s", word);

		eval("brctl", "addif", nvram_safe_get("lan_ifname"), "bond0");
		/* remap imp port */
		bonding_portmask = get_bonding_ports();
		sprintf(tmp, "ethswctl -c bondingports -v 0x%x", bonding_portmask);
		system(tmp);
#endif
	}
#ifdef RTCONFIG_HND_ROUTER_AX
#ifdef RTCONFIG_BONDING_WAN
	else{
		stop_lan_bonding();
		stop_wan_bonding();
	}
#endif
#endif
}

#endif
