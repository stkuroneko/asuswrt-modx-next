/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */
#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <arpa/inet.h>
#include <errno.h>
#include <etioctl.h>
#include <rc.h>
typedef u_int64_t __u64;
typedef u_int32_t __u32;
typedef u_int16_t __u16;
typedef u_int8_t __u8;
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <ctype.h>
#include <wlutils.h>
#include <shared.h>
#include <wlscan.h>
#include <bcmdevs.h>
#ifdef RTCONFIG_HND_ROUTER_AX
#include <wlc_types.h>
#endif
#include <sys/reboot.h>

#include <bcmendian.h>
#if defined(__CONFIG_DHDAP__) || defined(RTCONFIG_AMAS)
#include <bcmutils.h>
#endif
#include <security_ipc.h>
#ifdef HND_ROUTER
#include <linux/if_bridge.h>
#include "ethswctl.h"
#include "ethctl.h"
#ifdef RTCONFIG_HND_ROUTER_AX
#include <proto/wps.h>
#endif
#endif
#ifdef RTCONFIG_QTN
#include "web-qtn.h"
#endif
#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#ifdef RTCONFIG_CFGSYNC
#include <json.h>
#include <cfg_slavelist.h>
#include <cfg_string.h>
#endif
#if defined(RTCONFIG_RGBLED)
#include <aura_rgb.h>
#endif
#include "ate.h"

//This define only used for switch 53125
#define SWITCH_PORT_0_UP	0x0001
#define SWITCH_PORT_1_UP	0x0002
#define SWITCH_PORT_2_UP	0x0004
#define SWITCH_PORT_3_UP	0x0008
#define SWITCH_PORT_4_UP	0x0010

#define SWITCH_PORT_0_GIGA	0x0002
#define SWITCH_PORT_1_GIGA	0x0008
#define SWITCH_PORT_2_GIGA	0x0020
#define SWITCH_PORT_3_GIGA	0x0080
#define SWITCH_PORT_4_GIGA	0x0200
//End

//Defined for switch 5325
//#define SWITCH_ACCESS_CMD		SIOCGETCROBORD
#define SWITCH_ACCESS_PAGE		"0x1"
#define SWITCH_ACCESS_REG_LINKSTATUS	"0x0"
#define SWITCH_ACCESS_REG_LINKSPEED	"0x4"

/* hardware-dependent */
#define ETH_WAN_PORT "4"
#define ETH_LAN1_PORT "3"
#define ETH_LAN2_PORT "2"
#define ETH_LAN3_PORT "1"
#define ETH_LAN4_PORT "0"

/* RT-N53 */
/* WAN Port=4 */
#define MASK_PHYPORT 0x0010

#define ETH_WAN_PORT_UP 0x0010
#define ETH_LAN1_PORT_UP 0x0001
#define ETH_LAN2_PORT_UP 0x0002
#define ETH_LAN3_PORT_UP 0x0004
#define ETH_LAN4_PORT_UP 0x0008

#define ETH_WAN_PORT_GIGA 0x0200
#define ETH_LAN1_PORT_GIGA 0x0002
#define ETH_LAN2_PORT_GIGA 0x0008
#define ETH_LAN3_PORT_GIGA 0x0020
#define ETH_LAN4_PORT_GIGA 0x0080

#define ETH_PHY_REG_LAN_ADDR "0x1e"
#define ETH_PHY_REG_LAN_DISCONN_VALUE "0x80a8"
#define ETH_PHY_REG_LAN_CONN_VALUE "0x80a0"
//End
char cmd[32];
struct apinfo apinfos[MAX_NUMBER_OF_APINFO];
bool g_swap = FALSE;
#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
extern int ext_rtk_phyState(int v, char* BCMPorts, phy_info_list *list);
#endif
#ifdef RTCONFIG_BRCM_HOSTAPD
int Pty_exec_wpasupp_cmd(char* cmd);
#endif

int
set40M_Channel_2G(char *channel)
{
#ifdef RTCONFIG_BCMWL6
	char str[8];
#endif

	if (channel==NULL || !isValidChannel(1, channel))
		return 0;

#ifdef RTCONFIG_BCMWL6
	if (atoi(channel) >= 5) sprintf(str, "%su", channel);
	else sprintf(str, "%sl", channel);
	nvram_set("wl0_chanspec", str);
	nvram_set("wl0_bw_cap", "3");
#else
	nvram_set("wl0_channel", channel);
	nvram_set("wl0_nbw_cap", "1");
	nvram_set("wl0_nctrlsb", "lower");
#endif
	nvram_set("wl0_obss_coex", "0");
	eval("wlconf", "eth1", "down");
	eval("wlconf", "eth1", "up");
	eval("wlconf", "eth1", "start");
	puts("1");
	return 1;
}

int
set40M_Channel_5G(char *channel)
{
#ifdef RTCONFIG_BCMWL6
	char str[8];
	int ch = 0;
#endif

	if (channel==NULL || !isValidChannel(0, channel))
		return 0;

#ifdef RTCONFIG_BCMWL6
	ch = atoi(channel);
	sprintf(str, "0");
	if (ch==40||ch==48||ch==56||ch==64||ch==104||ch==112||ch==120||ch==128||ch==136||ch==153||ch==161)
		sprintf(str, "%su", channel);
	else if (ch==36||ch==44||ch==52||ch==60||ch==100||ch==108||ch==116||ch==124||ch==132||ch==149||ch==157)
		sprintf(str, "%sl", channel);
	nvram_set("wl1_chanspec", str);
	nvram_set("wl1_bw_cap", "3");
#else
	nvram_set("wl1_channel", channel);
	nvram_set("wl1_nbw_cap", "1");
	nvram_set("wl1_nctrlsb", "lower");
#endif
	eval("wlconf", "eth2", "down");
	eval("wlconf", "eth2", "up");
	eval("wlconf", "eth2", "start");
	puts("1");
	return 1;
}

int
set80M_Channel_5G(char *channel)
{
#ifdef RTCONFIG_BCMWL6
	char str[8];
	int ch = 0;
#endif

	if (channel==NULL || !isValidChannel(0, channel))
		return 0;

#ifdef RTCONFIG_BCMWL6
	ch = atoi(channel);
	sprintf(str, "0");
	if (ch==36||ch==40||ch==44||ch==48||ch==52||ch==56||ch==60||ch==64||
		ch==100||ch==104||ch==108||ch==112||ch==149||ch==153||ch==157||ch==161)
		sprintf(str, "%s/80", channel);
	nvram_set("wl1_chanspec", str);
	nvram_set("wl1_bw_cap", "7");
#else
	nvram_set("wl1_channel", channel);
	nvram_set("wl1_nbw_cap", "1");
	nvram_set("wl1_nctrlsb", "lower");
#endif
	eval("wlconf", "eth2", "down");
	eval("wlconf", "eth2", "up");
	eval("wlconf", "eth2", "start");
	puts("1");
	return 1;
}

int
ResetDefault(void)
{
#ifndef RTCONFIG_BCMARM
	eval("mtd-erase","-d","nvram");
	puts("1");
#else
	int ret=0;
	if (nvram_contains_word("rc_support", "nandflash"))	/* RT-AC56S,U/RT-AC68U/RT-N18U */
#ifdef RTAC87U
		ret = mtd_erase("nvram");
#elif defined(HND_ROUTER)
		ret = eval("hnd-erase", "nvram");
#else
		ret = eval("mtd-erase2", "nvram");
#endif
	else
#if defined(RTAC1200G) || defined(RTAC1200GP)
		ret = eval("mtd-erase2", "nvram");
#else
		ret = eval("mtd-erase","-d","nvram");
#endif
#ifdef RTAC87U
	if (ret == 0) {
		return 0;
	} else {
		return -1;
	}
#else
	if (ret >= 0) {
		sleep(3);
		puts("1");
	}
	else
		puts("0");
#endif
#endif
	return 0;
}

//#if defined(RTCONFIG_HND_ROUTER_AX_675X)
#if 0
/**
 * @link:
 * 	0:	no-link
 * 	1:	link-up
 * @speed:
 * 	0,10:	10Mbps
 * 	1,100:	100Mbps
 * 	2,1000:	1000Mbps
 */
static char conv_speed(unsigned int link, unsigned int speed)
{
	char ret = 'X';

	if (link != 1)
		return ret;

	if (speed == 2 || speed == 1000)
		ret = 'G';
	else
		ret = 'M';

	return ret;
}

typedef struct {
	unsigned int link[5];
	unsigned int speed[5];
} phyState;

int
GetPhyStatus(int verbose)
{
	/* WAN, L1, L2, L3, L4 */
#if defined(RTAX95Q)
	int ports[] = {0, 1, 2, 3};
#elif defined(RTAX58U) || defined(TUFAX3000) || defined(RTAX82U)
	int ports[] = {4, 0, 1, 2, 3};
#elif defined(RTAX56U)
	int ports[] = {4, 3, 2, 1, 0};
#endif
	int i, fd;
	char buf[32];
	phyState pS;
	char sys_path[40] = {0};
	int num_of_ports = sizeof(ports)/sizeof(ports[0]);

	memset(&pS, 0, sizeof(pS));

	for ( i = 0 ; i < num_of_ports; i++){
		/* link status */
		snprintf(sys_path, sizeof(sys_path),
			"/sys/class/net/eth%d/operstate" , ports[i]);
		f_read_string(sys_path, buf, sizeof(buf));
		if(strncmp(buf, "up", 2)==0) pS.link[i] = 1;
		else pS.link[i] = 0;

		/* speed */
		snprintf(sys_path, sizeof(sys_path),
			"/sys/class/net/eth%d/speed" , ports[i]);
		f_read_string(sys_path, buf, sizeof(buf));
		pS.speed[i] = atoi(buf);
	}

	if(num_of_ports == 4){
		sprintf(buf, "W0=%C;L1=%C;L2=%C;L3=%C;",
			conv_speed(pS.link[0], pS.speed[0]),
			conv_speed(pS.link[1], pS.speed[1]),
			conv_speed(pS.link[2], pS.speed[2]),
			conv_speed(pS.link[3], pS.speed[3]));
	}else if(num_of_ports == 5){
		sprintf(buf, "W0=%C;L1=%C;L2=%C;L3=%C;L4=%C;",
			conv_speed(pS.link[0], pS.speed[0]),
			conv_speed(pS.link[1], pS.speed[1]),
			conv_speed(pS.link[2], pS.speed[2]),
			conv_speed(pS.link[3], pS.speed[3]),
			conv_speed(pS.link[4], pS.speed[4]));
	}else{
		fprintf(stderr, "[%s] no options\n", __func__);
	}

	puts(buf);
	return 1;
}
#else
#ifdef RTCONFIG_NEW_PHYMAP
int
GetPhyStatus(int verbose, phy_info_list *list)
{
	int i, ret;
	char out_buf[64] = {0};
	char cap_buf[64] = {0};
	int lret=0;
	int len;

#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
	phy_port_mapping port_mapping = get_phy_port_mapping();
	if (list)
		list->count = 0;
	for (i = 0; i < port_mapping.count; i++) {
		if (list)
			memset(&list->phy_info[list->count], 0, sizeof(list->phy_info[list->count]));

		ret = hnd_get_phy_status(port_mapping.port[i].ifname);
		if(ret == 0) {
			snprintf(out_buf+strlen(out_buf), sizeof(out_buf)-strlen(out_buf), "%s=X;", 
				port_mapping.port[i].label_name);
			if (list) {
				snprintf(list->phy_info[list->count].state, sizeof(list->phy_info[list->count].state), "down");
				snprintf(list->phy_info[list->count].duplex, sizeof(list->phy_info[list->count].duplex), "none");
				list->phy_info[list->count].link_rate = 0;
			}
		}
		else{
			ret = hnd_get_phy_speed(port_mapping.port[i].ifname);
			switch(ret) {
				case 10000:
				    snprintf(out_buf+strlen(out_buf), sizeof(out_buf)-strlen(out_buf), "%s=%s;",
					    port_mapping.port[i].label_name, "T");
				    break;
				case 5000:
				    snprintf(out_buf+strlen(out_buf), sizeof(out_buf)-strlen(out_buf), "%s=%s;",
					    port_mapping.port[i].label_name, "F");
				    break;
				case 2500:
				    snprintf(out_buf+strlen(out_buf), sizeof(out_buf)-strlen(out_buf), "%s=%s;",
					    port_mapping.port[i].label_name, "Q");

				    break;
				case 1000:
				    snprintf(out_buf+strlen(out_buf), sizeof(out_buf)-strlen(out_buf), "%s=%s;",
					    port_mapping.port[i].label_name, "G");
				    break
				case 100:
				default:
				    snprintf(out_buf+strlen(out_buf), sizeof(out_buf)-strlen(out_buf), "%s=%s;",
					    port_mapping.port[i].label_name, "M");
    					break;
			}

			lret |= 1;
			if (list) {
				snprintf(list->phy_info[list->count].state, sizeof(list->phy_info[list->count].state), "up");
				snprintf(list->phy_info[list->count].duplex, sizeof(list->phy_info[list->count].duplex), "%s", 
					hnd_get_phy_duplex(port_mapping.port[i].ifname) ? "full" : "half");
				list->phy_info[list->count].link_rate = ret;
				list->phy_info[list->count].tx_bytes = hnd_get_phy_mib(port_mapping.port[i].ifname, "tx_bytes");
				list->phy_info[list->count].rx_bytes = hnd_get_phy_mib(port_mapping.port[i].ifname, "rx_bytes");
				list->phy_info[list->count].tx_packets = hnd_get_phy_mib(port_mapping.port[i].ifname, "tx_packets");
				list->phy_info[list->count].rx_packets = hnd_get_phy_mib(port_mapping.port[i].ifname, "rx_packets");
				list->phy_info[list->count].crc_errors = hnd_get_phy_mib(port_mapping.port[i].ifname, "rx_crc_errors");
			}
		}

		if (list) {
			list->phy_info[list->count].phy_port_id = port_mapping.port[i].phy_port_id;
			snprintf(list->phy_info[list->count].label_name, sizeof(list->phy_info[list->count].label_name), "%s", 
				port_mapping.port[i].label_name);
			snprintf(list->phy_info[list->count].cap_name, sizeof(list->phy_info[list->count].cap_name), 
				"%s", get_phy_port_cap_name(port_mapping.port[i].cap, cap_buf, sizeof(cap_buf)));
			list->count++;
		}
	}
	if (verbose == 1)
		puts(out_buf);

	return lret;
#else // RTCONFIG_HND_ROUTER_AX_6710
#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)
	unsigned int regv=0, pmdv=0, regv2=0, pmdv2=0, regv3=0, pmdv3=0;
#endif
	int ext_lret=0, model, mask;
	int extra_p0=0;
	model = get_model();
	switch(model) {
#ifdef HND_ROUTER
#if !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)
	case MODEL_RTAC86U:
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3= hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
		break;
	case MODEL_GTAC5300:
		extra_p0 = S_53134;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
#ifdef RTCONFIG_EXT_BCM53134
		pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0); // status
		pmdv2 = hnd_ethswctl(PMDIOACCESS, 0x0104, 4, 0, 0); // speed
		pmdv3 = hnd_ethswctl(PMDIOACCESS, 0x0108, 2, 0, 0); // duplex
#endif
		break;
	case MODEL_GTAX11000:
		extra_p0 = S_53134;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
#ifdef RTCONFIG_EXT_BCM53134
		pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0); // status
		pmdv2 = hnd_ethswctl(PMDIOACCESS, 0x0104, 4, 0, 0); // speed
		pmdv3 = hnd_ethswctl(PMDIOACCESS, 0x0108, 2, 0, 0); // duplex
#endif
		break;
	case MODEL_RTAX88U:
		extra_p0 = S_53134;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
#ifdef RTCONFIG_EXT_BCM53134
		pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0); // status
		pmdv2 = hnd_ethswctl(PMDIOACCESS, 0x0104, 4, 0, 0); // speed
		pmdv3 = hnd_ethswctl(PMDIOACCESS, 0x0108, 2, 0, 0); // duplex
#endif
		break;
	case MODEL_RTAX92U:
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0) & 0xf; // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0) & 0xf; // duplex
		break;
#endif
#endif
	}

#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
	char PStatus[5]="XXXXX";
#endif
	phy_port_mapping port_mapping = get_phy_port_mapping();

	memset(out_buf, 0, 64);
	if (list)
		list->count = 0;

	for (i=0; i<(port_mapping.count-port_mapping.extsw_count); i++) {
		int port_id = port_mapping.port[i].phy_port_id;
		mask = 0;
		mask |= 0x0001<<port_id;

		if (list) {
			memset(&list->phy_info[i], 0, sizeof(list->phy_info[i]));
			list->count++;
			list->phy_info[i].phy_port_id = port_id;
			snprintf(list->phy_info[i].label_name, sizeof(list->phy_info[i].label_name), "%s", 
				port_mapping.port[i].label_name);
			snprintf(list->phy_info[i].cap_name, sizeof(list->phy_info[i].cap_name), "%s", 
				get_phy_port_cap_name(port_mapping.port[i].cap, cap_buf, sizeof(cap_buf)));
		}

#ifndef HND_ROUTER
		if (get_phy_status(mask)==0) /*Disconnect*/
#else
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
		if (hnd_get_phy_status(port_id)==0) /*Disconnect*/
#else
		if (hnd_get_phy_status(port_id, extra_p0, regv, pmdv)==0) /*Disconnect*/
#endif
#endif
		{
			if (i==0) {
				sprintf(out_buf, "W0=X;");
			}
			else {
				sprintf(out_buf, "%sL%d=X;", out_buf, i);
			}

			if (list) {
				snprintf(list->phy_info[i].state, sizeof(list->phy_info[i].state), "down");
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "none");
				list->phy_info[i].link_rate = 0;
			}
		}
		else { /*Connect, keep check speed*/
			mask = 0;
			mask |= (0x0003<<(port_id*2));
#ifndef HND_ROUTER
			ret=get_phy_speed(mask);
			ret>>=(port_id*2);
#else
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
			ret = hnd_get_phy_speed(port_id);
#else
			ret = hnd_get_phy_speed(port_id, extra_p0, regv2, pmdv2);
#endif
#endif
			if (i==0) {
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
				sprintf(out_buf, "W0=%s;", (ret == 2500) ? "Q" : ((ret == 1000) ? "G" : "M"));
#else
				sprintf(out_buf, "W0=%s;",
#ifdef RTCONFIG_EXTPHY_BCM84880
						(ret & 4)? "Q" :
#endif
						(ret & 2)
						? "G" : "M");
#endif
#ifdef HND_ROUTER
				lret = 1;
#endif
				if (list) {
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
					list->phy_info[i].link_rate = ret;
#else
					list->phy_info[i].link_rate = 
#ifdef RTCONFIG_EXTPHY_BCM84880
							(ret & 4)? 2000 :
#endif
							(ret & 2)
							? 1000 : 100;
#endif
				}
			}
			else {
				lret = 1;

				if (port_id >= extra_p0)
					ext_lret = 1;

#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
				sprintf(out_buf, "%sL%d=%s;", out_buf, i, (ret == 2500) ? "Q" : ((ret == 1000) ? "G" : "M"));
#else
				sprintf(out_buf, "%sL%d=%s;", out_buf, i,
#ifdef RTCONFIG_EXTPHY_BCM84880
					(ret & 4)? "Q" :
#endif
					(ret & 2)
					? "G" : "M");
#endif
				if (list) {
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
					list->phy_info[i].link_rate = ret;
#else
					list->phy_info[i].link_rate = 
#ifdef RTCONFIG_EXTPHY_BCM84880
							(ret & 4)? 2000 :
#endif
							(ret & 2)
							? 1000 : 100;
#endif
				}
			}

			if (list) {
				snprintf(list->phy_info[i].state, sizeof(list->phy_info[i].state), "up");
#ifndef HND_ROUTER
				mask = 0;
				mask |= 0x0001<<port_id;
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "%s", 
					get_phy_duplex(mask) ? "full" : "half");
				list->phy_info[i].tx_bytes = get_phy_mib(port_id, "tx_bytes");
				list->phy_info[i].rx_bytes = get_phy_mib(port_id, "rx_bytes");
				list->phy_info[i].tx_packets = get_phy_mib(port_id, "tx_packets");
				list->phy_info[i].rx_packets = get_phy_mib(port_id, "rx_packets");
				list->phy_info[i].crc_errors = get_phy_mib(port_id, "rx_crc_errors");
#else
#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "%s", 
					hnd_get_phy_duplex(port_id, extra_p0, regv3, pmdv3) ? "full" : "half");
				list->phy_info[i].tx_bytes = hnd_get_phy_mib(port_id, extra_p0, "tx_bytes");
				list->phy_info[i].rx_bytes = hnd_get_phy_mib(port_id, extra_p0, "rx_bytes");
				list->phy_info[i].tx_packets = hnd_get_phy_mib(port_id, extra_p0, "tx_packets");
				list->phy_info[i].rx_packets = hnd_get_phy_mib(port_id, extra_p0, "rx_packets");
				list->phy_info[i].crc_errors = hnd_get_phy_mib(port_id, extra_p0, "rx_crc_errors");
#else
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "%s", 
					hnd_get_phy_duplex(port_id) ? "full" : "half");
				list->phy_info[i].tx_bytes = hnd_get_phy_mib(port_id, "tx_bytes");
				list->phy_info[i].rx_bytes = hnd_get_phy_mib(port_id, "rx_bytes");
				list->phy_info[i].tx_packets = hnd_get_phy_mib(port_id, "tx_packets");
				list->phy_info[i].rx_packets = hnd_get_phy_mib(port_id, "rx_packets");
				list->phy_info[i].crc_errors = hnd_get_phy_mib(port_id, "rx_crc_errors");
#endif
#endif
			}
		}
	}

#ifdef RTCONFIG_QTN
	if (model == MODEL_RTAC87U) {
		ports[1] = GetPhyStatus_qtn();
		if (ports[1] == 1000) {
			out_buf[8] = 'G';
		} else if (ports[1] == 100) {
			out_buf[8] = 'M';
		} else if (ports[1] == 10) {
			out_buf[8] = 'M';
		} else {
			out_buf[8] = 'X';
		}
	}
#endif

	if (verbose == 1)
#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
		printf("%s", out_buf);
#else
		puts(out_buf);
#endif

#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
	if (port_mapping.extsw_count) {
		ext_lret = ext_rtk_phyState(verbose, PStatus, list);
		lret |= ext_lret;
	}
#endif

	if (verbose == 53134 || verbose == 8365) return ext_lret;
	return lret;
#endif // RTCONFIG_HND_ROUTER_AX_6710
}
#else //#ifdef RTCONFIG_NEW_PHYMAP
int
GetPhyStatus(int verbose, phy_info_list *list)
{
	int i, ret;
	char out_buf[64] = {0};
	int lret=0;
	int len;
#if defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(BCM4912)
	// MODEL_RTAX86U, MODEL_RTAX68U, MODEL_RTAC68U_V4
#if defined(RTCONFIG_EXTPHY_BCM84880)
	// L5(2.5G) W0 L1 L2 L3 L4
	// eth5 eth0 eth4 eth3 eth2 eth1
#ifdef GTAXE16000
	int lan_ports = 6;
#else
	int lan_ports = 5;
#endif
#else
	// W0 L1 L2 L3 L4
	// eth0 eth4 eth3 eth2 eth1
	int lan_ports = 4;
#endif
	char word[256], *next;
#if defined(GTAXE11000)
	char lanports_seq[64] = {"eth1 eth4 eth2 eth3 eth5"};	/* L1 L2 L3 L4 L5 */
#elif defined(RTAX86U) || defined(RTAX5700)
	char wanports_seq[64] = {"eth0"};	/* W0 */
	char lanports_seq1[64] = {"eth4 eth3 eth2 eth1 eth5"};	/* L1 L2 L3 L4 L5 */
	char lanports_seq2[64] = {"eth4 eth3 eth2 eth1"};	/* L1 L2 L3 L4 */
	char *lanports_seq;
#elif defined(RTAX68U)
	char wanports_seq[64] = {"eth0"};	/* W0 */
	char lanports_seq[64] = {"eth4 eth3 eth2 eth1"};	/* L1 L2 L3 L4 */
#elif defined(GTAX6000)
	char lanports_seq[64] = {"eth1 eth2 eth3 eth4 eth5"};   /* L1 L2 L3 L4 L5 */
#elif defined(GTAX11000_PRO)
	char lanports_seq[64] = {"eth1 eth2 eth3 eth4 eth5"};   /* L1 L2 L3 L4 L5 */
#elif defined(GTAXE16000)
	char lanports_seq[64] = {"eth1 eth2 eth3 eth4 eth5 eth6"};   /* L1 L2 L3 L4 L5 L6 */
#elif defined(ET12) || defined(XT12)
	char lanports_seq[64] = {"eth1 eth2 eth3"};   /* L1 L2 L3 W */
#endif

#if !defined(BCM4912)
	hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0);
	hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0);
#endif

	if (list)
		list->count = 0;

	char wan_ifname[32];

#if defined(RTAX86U) || defined(RTAX5700)
	snprintf(wan_ifname, sizeof(wan_ifname), "%s", wanports_seq);
	if(!strcmp(get_productid(), "RT-AX86S"))
		lanports_seq = lanports_seq2;
	else
		lanports_seq = lanports_seq1;
#else
#ifdef RTCONFIG_BONDING_WAN
	if(nvram_get_int("bond_wan"))
		snprintf(wan_ifname, sizeof(wan_ifname), "%s", nvram_safe_get("wan_ifnames_bk"));
	else
#endif
		snprintf(wan_ifname, sizeof(wan_ifname), "%s", nvram_safe_get("wan_ifname"));
#endif

	foreach(word, wan_ifname, next){
		if (list)
			memset(&list->phy_info[list->count], 0, sizeof(list->phy_info[list->count]));

		ret = hnd_get_phy_status(word);
		if(ret == 0) {
			sprintf(out_buf, "W0=X;");
			if (list) {
				snprintf(list->phy_info[list->count].cap_name, sizeof(list->phy_info[list->count].cap_name), "wan");
				snprintf(list->phy_info[list->count].label_name, sizeof(list->phy_info[list->count].label_name), "W0");
				snprintf(list->phy_info[list->count].state, sizeof(list->phy_info[list->count].state), "down");
				snprintf(list->phy_info[list->count].duplex, sizeof(list->phy_info[list->count].duplex), "none");
				list->phy_info[list->count].link_rate = 0;
			}
		}
		else{
			ret = hnd_get_phy_speed(word);
			switch(ret) {
				case 10000:
				    sprintf(out_buf, "W0=T;");
				    break;
				case 5000:
				    sprintf(out_buf, "W0=F;");
				    break;
				case 2500:
				    sprintf(out_buf, "W0=Q;");
				    break;
				case 1000:
				    sprintf(out_buf, "W0=G;");
				    break;
				case 100:
				default:
				    sprintf(out_buf, "W0=M;");
				    break;
			}

			lret |= 1;
			if (list) {
				snprintf(list->phy_info[list->count].cap_name, sizeof(list->phy_info[list->count].cap_name), "wan");
				snprintf(list->phy_info[list->count].label_name, sizeof(list->phy_info[list->count].label_name), "W%d", list->count);
				snprintf(list->phy_info[list->count].state, sizeof(list->phy_info[list->count].state), "up");
				snprintf(list->phy_info[list->count].duplex, sizeof(list->phy_info[list->count].duplex), "%s", 
					hnd_get_phy_duplex(word) ? "full" : "half");
				list->phy_info[list->count].link_rate = ret;
				list->phy_info[list->count].tx_bytes = hnd_get_phy_mib(word, "tx_bytes");
				list->phy_info[list->count].rx_bytes = hnd_get_phy_mib(word, "rx_bytes");
				list->phy_info[list->count].tx_packets = hnd_get_phy_mib(word, "tx_packets");
				list->phy_info[list->count].rx_packets = hnd_get_phy_mib(word, "rx_packets");
				list->phy_info[list->count].crc_errors = hnd_get_phy_mib(word, "rx_crc_errors");
			}
		}

		if (list) {
			list->phy_info[list->count].phy_port_id = list->count;
			list->count++;
		}

		break;
	}

	len = strlen(out_buf);
	i = 1;
#if defined(GTAXE11000) || defined(RTAX86U) || defined(RTAX5700) || defined(RTAX68U) || defined(ET12) || defined(XT12) || defined(GTAX6000) || defined(GTAX11000_PRO) || defined(GTAXE16000)
	foreach(word, lanports_seq, next){
#else
	foreach(word, nvram_safe_get("lan_ifnames"), next){
#endif
		if (list)
			memset(&list->phy_info[list->count], 0, sizeof(list->phy_info[list->count]));

		ret = hnd_get_phy_status(word);
		if(ret == 0) {
			len += sprintf(out_buf + len, "L%d=X;", i);
			if (list) {
				snprintf(list->phy_info[list->count].cap_name, sizeof(list->phy_info[list->count].cap_name), "lan");
				snprintf(list->phy_info[list->count].label_name, sizeof(list->phy_info[list->count].label_name), "L%d", list->count);
				snprintf(list->phy_info[list->count].state, sizeof(list->phy_info[list->count].state), "down");
				snprintf(list->phy_info[list->count].duplex, sizeof(list->phy_info[list->count].duplex), "none");
				list->phy_info[list->count].link_rate = 0;
			}
		}
		else{
			ret = hnd_get_phy_speed(word);
			switch(ret) {
				case 10000:
				    len += sprintf(out_buf + len, "L%d=%s;", i, "T");
				    break;
				case 5000:
				    len += sprintf(out_buf + len, "L%d=%s;", i, "F");
				    break;
				case 2500:
				    len += sprintf(out_buf + len, "L%d=%s;", i, "Q");
				    break;
				case 1000:
				    len += sprintf(out_buf + len, "L%d=%s;", i, "G");
				    break;
				case 100:
				default:
				    len += sprintf(out_buf + len, "L%d=%s;", i, "M");
				    break;
			}

			lret |= 1 << i;
			if (list) {
				snprintf(list->phy_info[list->count].cap_name, sizeof(list->phy_info[list->count].cap_name), "lan");
				snprintf(list->phy_info[list->count].label_name, sizeof(list->phy_info[list->count].label_name), "L%d", list->count);
				snprintf(list->phy_info[list->count].state, sizeof(list->phy_info[list->count].state), "up");
				snprintf(list->phy_info[list->count].duplex, sizeof(list->phy_info[list->count].duplex), "%s", 
					hnd_get_phy_duplex(word) ? "full" : "half");
				list->phy_info[list->count].link_rate = ret;
				list->phy_info[i].tx_bytes = hnd_get_phy_mib(word, "tx_bytes");
				list->phy_info[i].rx_bytes = hnd_get_phy_mib(word, "rx_bytes");
				list->phy_info[i].tx_packets = hnd_get_phy_mib(word, "tx_packets");
				list->phy_info[i].rx_packets = hnd_get_phy_mib(word, "rx_packets");
				list->phy_info[i].crc_errors = hnd_get_phy_mib(word, "rx_crc_errors");
			}
		}

		if (list) {
			list->phy_info[list->count].phy_port_id = i;
			list->count++;
		}

		++i;

		if(i > lan_ports) break;
	}
	if (verbose == 1)
		puts(out_buf);

	return lret;
#else // RTCONFIG_HND_ROUTER_AX_6710
#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)
	unsigned int regv=0, pmdv=0, regv2=0, pmdv2=0, regv3=0, pmdv3=0;
#endif
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
	int lan_ports=3;
#elif defined(RTAX56_XD4)
	int lan_ports=1;
#elif defined(XD4PRO)
	int lan_ports=1;
#elif defined(CTAX56_XD4)
	int lan_ports=1;
#elif defined(RTAX56U) || defined(RTAX55)
	int lan_ports=4;
#elif defined(RPAX56) || defined(RPAX58)
        int lan_ports=0;
#elif defined(RTCONFIG_EXT_BCM53134)
	int lan_ports=8;
#elif defined(RTAX56U) || defined(RTAX55)
	int lan_ports=4;
#elif defined(RTCONFIG_EXTPHY_BCM84880)
	int lan_ports=5;
#elif defined(RTAX82_XD6)
	int lan_ports=3;
#elif defined(RTAX82_XD6S)
	int lan_ports=1;
#else
	int lan_ports=4;
#endif

#if defined(RTAX56_XD4)
	if(nvram_match("HwId", "A") || nvram_match("HwId", "C")){
		lan_ports = 1;
	} else {
		lan_ports = 0;
	}
#endif
	int *ports = malloc((lan_ports+1) * sizeof(int));
#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
	int ext = 0;
#endif
	int ext_lret=0, model, mask;
	int extra_p0=0;

	model = get_model();
	switch(model) {
#ifndef HND_ROUTER
	case MODEL_RTN14UHP:
		/* WAN L1 L2 L3 L4 */
		ports[0]=4; ports[1]=0; ports[2]=1, ports[3]=2; ports[4]=3;
		break;
	case MODEL_RTN53:
	case MODEL_RTN15U:
	case MODEL_RTN12:
	case MODEL_RTN12B1:
	case MODEL_RTN12C1:
	case MODEL_RTN12D1:
	case MODEL_RTN12VP:
	case MODEL_RTN12HP:
	case MODEL_RTN12HP_B1:
	case MODEL_APN12HP:
	case MODEL_RTN10P:
	case MODEL_RTN10D1:
	case MODEL_RTN10PV2:
		/* WAN L1 L2 L3 L4 */
		ports[0]=4; ports[1]=3; ports[2]=2, ports[3]=1; ports[4]=0;
		break;
	case MODEL_RTN16:
	case MODEL_RTN10U:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=4; ports[2]=3, ports[3]=2; ports[4]=1;
		break;
	case MODEL_RTAC88U:
	case MODEL_RTAC3100:
		/* WAN L1 L2 L3 L4 */
		ports[0]=4; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
		ext = 1;
#endif
		break;
	case MODEL_RTAC56S:
	case MODEL_RTAC56U:
		/* WAN L1 L2 L3 L4 */
		ports[0]=4; ports[1]=0; ports[2]=1; ports[3]=2; ports[4]=3;
		break;

	case MODEL_RTAC87U:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=5; ports[2]=3; ports[3]=2; ports[4]=1;
		break;

	case MODEL_DSLAC68U:
	case MODEL_RTAC68U:
	case MODEL_RTN18U:
	case MODEL_RTAC53U:
	case MODEL_RTN66U:
	case MODEL_RTAC66U:
	case MODEL_RTAC1200G:
	case MODEL_RTAC1200GP:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=1; ports[2]=2; ports[3]=3; ports[4]=4;
		break;
	case MODEL_RTAC3200:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=4; ports[2]=3; ports[3]=2; ports[4]=1;
		break;
	case MODEL_RTAC5300:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=1; ports[2]=2; ports[3]=3; ports[4]=4;
#ifdef RTCONFIG_EXT_RTL8365MB
		ext = 1;
#endif
		break;
#else
#if !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM6756)
	case MODEL_RTAC86U:
		/* WAN L4 L3 L2 L1 */
		ports[0]=7; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3= hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
//		printf("phystatus: [%x][%x]\n", regv, regv2);
		break;
	case MODEL_GTAC5300:
		/*
			  1 0 s3 s2	   L1 L2 L3 L4
			7 3 2 s1 s0	W0 L5 L6 L7 L8
 		 */
		extra_p0 = S_53134;
		ports[0]=7; ports[1]=1; ports[2]=0; ports[3]=3+extra_p0; ports[4]=2+extra_p0;
		ports[5]=3; ports[6]=2; ports[7]=1+extra_p0; ports[8]=extra_p0;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
#ifdef RTCONFIG_EXT_BCM53134
		pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0); // status
		pmdv2 = hnd_ethswctl(PMDIOACCESS, 0x0104, 4, 0, 0); // speed
		pmdv3 = hnd_ethswctl(PMDIOACCESS, 0x0108, 2, 0, 0); // duplex
#endif
//		printf("phystatus: [%x][%x][%x][%x]\n", regv, pmdv, regv2, pmdv2);
		break;
	case MODEL_GTAX11000:
#ifdef RTCONFIG_EXT_BCM53134
		/*
			  1 0 s3 s2	   L1 L2 L3 L4
			7 3 2 s1 s0	W0 L5 L6 L7 L8
 		 */
		extra_p0 = S_53134;
		ports[0]=7; ports[1]=1; ports[2]=0; ports[3]=3+extra_p0; ports[4]=2+extra_p0;
		ports[5]=3; ports[6]=2; ports[7]=1+extra_p0; ports[8]=extra_p0;
#elif defined(RTCONFIG_EXTPHY_BCM84880)
		/*
			7 4 3 2 1 0 	L5(2.5G) W0 L1 L2 L3 L4
		*/
		ports[0]=4; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
		ports[5]=7;
#endif
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
#ifdef RTCONFIG_EXT_BCM53134
		pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0); // status
		pmdv2 = hnd_ethswctl(PMDIOACCESS, 0x0104, 4, 0, 0); // speed
		pmdv3 = hnd_ethswctl(PMDIOACCESS, 0x0108, 2, 0, 0); // duplex
#endif
		break;
	case MODEL_RTAX88U:
		/*
			7 3 2 1 0 s3 s2 s1 s0	W0 L1 L2 L3 L4 L5 L6 L7 L8
 		 */
		extra_p0 = S_53134;
		ports[0]=7; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
		ports[5]=3+extra_p0; ports[6]=2+extra_p0; ports[7]=1+extra_p0; ports[8]=extra_p0;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0); // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0); // duplex
#ifdef RTCONFIG_EXT_BCM53134
		pmdv = hnd_ethswctl(PMDIOACCESS, 0x0100, 2, 0, 0); // status
		pmdv2 = hnd_ethswctl(PMDIOACCESS, 0x0104, 4, 0, 0); // speed
		pmdv3 = hnd_ethswctl(PMDIOACCESS, 0x0108, 2, 0, 0); // duplex
#endif
//		printf("phystatus: [%x][%x][%x][%x]\n", regv, pmdv, regv2, pmdv2);
		break;
	case MODEL_RTAX92U:
		/* WAN L4 L3 L2 L1 */
		ports[0]=7; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
		regv = hnd_ethswctl(REGACCESS, 0x0100, 2, 0, 0) & 0xf; // status
		regv2 = hnd_ethswctl(REGACCESS, 0x0104, 4, 0, 0); // speed
		regv3 = hnd_ethswctl(REGACCESS, 0x0108, 2, 0, 0) & 0xf; // duplex
//		printf("phystatus: [%x][%x]\n", regv, regv2);
		break;
#else
	case MODEL_RTAX95Q:
	case MODEL_XT8PRO:
	case MODEL_XT8_V2:
	case MODEL_RTAXE95Q:
	case MODEL_ET8PRO:
		/*
			0 1 2 3 W0 L1 L2 L3
 		 */
		ports[0]=0; ports[1]=1; ports[2]=2; ports[3]=3;
		break;
	case MODEL_RTAX56_XD4:
		/*
			0 1 W0 L1
 		 */
		if(nvram_match("HwId", "A") || nvram_match("HwId", "C")){
			ports[0]=0; ports[1]=1;
		} else {
			ports[0]=0;;
		}
		break;
	case MODEL_XD4PRO:
		/*
			0 1 W0 L1
		 */
		ports[0]=0; ports[1]=1;
		break;
	case MODEL_CTAX56_XD4:
		/*
			0 1 W0 L1
 		 */
		ports[0]=0; ports[1]=1;
		break;
	case MODEL_DSLAX82U:
		/* WAN L4 L3 L2 L1 */
		ports[0]=4; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
		break;
	case MODEL_RTAX58U:
#ifdef RTAX82_XD6
		/* WAN L1 L2 L3 */
		ports[0]=4; ports[1]=2; ports[2]=1; ports[3]=0;
#else
		/* WAN L1 L2 L3 L4 */
		ports[0]=4; ports[1]=3; ports[2]=2; ports[3]=1; ports[4]=0;
#endif
		break;
	case MODEL_RTAX82_XD6S:
		/* WAN L1 */
		ports[0]=1; ports[1]=0;
		break;
	case MODEL_RTAX58U_V2:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=4; ports[2]=3; ports[3]=2; ports[4]=1;
		break;
	case MODEL_TUFAX3000_V2:
	case MODEL_RTAXE7800:
		/* WAN L1 L2 L3 L4 */
		ports[0]=0; ports[1]=1; ports[2]=2; ports[3]=3; ports[4]=4;
		break;
	case MODEL_RTAX55:
#ifdef RTAX1800
		/* WAN L4 L3 L2 L1 */
		ports[0]=0; ports[1]=1; ports[2]=2; ports[3]=3; ports[4]=4;
#else
		/* WAN L1 L2 L3 L4 */
                ports[0]=0; ports[1]=4; ports[2]=3; ports[3]=2; ports[4]=1;
#endif
		break;
	case MODEL_RTAX56U:
		/* WAN L4 L3 L2 L1 */
		ports[0]=0; ports[1]=4; ports[2]=3; ports[3]=2; ports[4]=1;
		break;
	case MODEL_RPAX56:
	case MODEL_RPAX58:
		/* LAN */
		ports[0]=0;
		break;
#endif
#endif
	}

#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
	char PStatus[5]="XXXXX";
#endif

	len = 0;
	memset(out_buf, 0, 64);
	if (list)
		list->count = 0;

	for (i=0; i<lan_ports+1; i++) {
		mask = 0;
		mask |= 0x0001<<ports[i];

		if (list) {
			memset(&list->phy_info[i], 0, sizeof(list->phy_info[i]));
			list->count++;
			list->phy_info[i].phy_port_id = ports[i];
			if (i==0)
				snprintf(list->phy_info[i].label_name, sizeof(list->phy_info[i].label_name), "W0");
			else
				snprintf(list->phy_info[i].label_name, sizeof(list->phy_info[i].label_name), "L%d", i);
		}

#ifndef HND_ROUTER
		if (get_phy_status(mask)==0) /*Disconnect*/
#else
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
		if (hnd_get_phy_status(ports[i])==0) /*Disconnect*/
#else
		if (hnd_get_phy_status(ports[i], extra_p0, regv, pmdv)==0) /*Disconnect*/
#endif
#endif
		{
			if (i==0) {
#if defined(RPAX56) || defined(RPAX58)
				len = sprintf(out_buf, "L0=X;");
#else
				len = sprintf(out_buf, "W0=X;");
#endif
				if (list)
					snprintf(list->phy_info[i].cap_name, sizeof(list->phy_info[i].cap_name), "wan");
			}
			else {
				len += sprintf(out_buf + len, "L%d=X;", i);
				if (list)
					snprintf(list->phy_info[i].cap_name, sizeof(list->phy_info[i].cap_name), "lan");
			}

			if (list) {
				snprintf(list->phy_info[i].state, sizeof(list->phy_info[i].state), "down");
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "none");
				list->phy_info[i].link_rate = 0;
			}
		}
		else { /*Connect, keep check speed*/
			mask = 0;
			mask |= (0x0003<<(ports[i]*2));
#ifndef HND_ROUTER
			ret=get_phy_speed(mask);
			ret>>=(ports[i]*2);
#else
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
			ret = hnd_get_phy_speed(ports[i]);
#else
			ret = hnd_get_phy_speed(ports[i], extra_p0, regv2, pmdv2);
#endif
#endif
			if (i==0) {
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
#if defined(RPAX56) || defined(RPAX58)
				len = sprintf(out_buf, "L0=%s;", (ret == 2500) ? "Q" : ((ret == 1000) ? "G" : "M"));
#else
				len = sprintf(out_buf, "W0=%s;", (ret == 2500) ? "Q" : ((ret == 1000) ? "G" : "M"));
#endif
#else
				len = sprintf(out_buf, "W0=%s;",
#ifdef RTCONFIG_EXTPHY_BCM84880
						(ret & 4)? "Q" :
#endif
						(ret & 2)
						? "G" : "M");
#endif
#ifdef HND_ROUTER
				lret = 1;
#endif
				if (list) {
					snprintf(list->phy_info[i].cap_name, sizeof(list->phy_info[i].cap_name), "wan");
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
					list->phy_info[i].link_rate = ret;
#else
					list->phy_info[i].link_rate = 
#ifdef RTCONFIG_EXTPHY_BCM84880
							(ret & 4)? 2000 :
#endif
							(ret & 2)
							? 1000 : 100;
#endif
				}
			}
			else {
				lret |= 1 << i;

				if (ports[i] >= extra_p0)
					ext_lret = 1;

#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
				len += sprintf(out_buf + len, "L%d=%s;", i, (ret == 2500) ? "Q" : ((ret == 1000) ? "G" : "M"));
#else
				len += sprintf(out_buf + len, "L%d=%s;", i,
#ifdef RTCONFIG_EXTPHY_BCM84880
					(ret & 4)? "Q" :
#endif
					(ret & 2)
					? "G" : "M");
#endif
				if (list) {
					snprintf(list->phy_info[i].cap_name, sizeof(list->phy_info[i].cap_name), "lan");
#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(BCM6756)
					list->phy_info[i].link_rate = ret;
#else
					list->phy_info[i].link_rate = 
#ifdef RTCONFIG_EXTPHY_BCM84880
							(ret & 4)? 2000 :
#endif
							(ret & 2)
							? 1000 : 100;
#endif
				}
			}

			if (list) {
				snprintf(list->phy_info[i].state, sizeof(list->phy_info[i].state), "up");
#ifndef HND_ROUTER
				mask = 0;
				mask |= 0x0001<<ports[i];
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "%s", 
					get_phy_duplex(mask) ? "full" : "half");
				list->phy_info[i].tx_bytes = get_phy_mib(ports[i], "tx_bytes");
				list->phy_info[i].rx_bytes = get_phy_mib(ports[i], "rx_bytes");
				list->phy_info[i].tx_packets = get_phy_mib(ports[i], "tx_packets");
				list->phy_info[i].rx_packets = get_phy_mib(ports[i], "rx_packets");
				list->phy_info[i].crc_errors = get_phy_mib(ports[i], "rx_crc_errors");
#else
#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(BCM4912) && !defined(BCM6756)
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "%s", 
					hnd_get_phy_duplex(ports[i], extra_p0, regv3, pmdv3) ? "full" : "half");
				list->phy_info[i].tx_bytes = hnd_get_phy_mib(ports[i], extra_p0, "tx_bytes");
				list->phy_info[i].rx_bytes = hnd_get_phy_mib(ports[i], extra_p0, "rx_bytes");
				list->phy_info[i].tx_packets = hnd_get_phy_mib(ports[i], extra_p0, "tx_packets");
				list->phy_info[i].rx_packets = hnd_get_phy_mib(ports[i], extra_p0, "rx_packets");
				list->phy_info[i].crc_errors = hnd_get_phy_mib(ports[i], extra_p0, "rx_crc_errors");
#else
				snprintf(list->phy_info[i].duplex, sizeof(list->phy_info[i].duplex), "%s", 
					hnd_get_phy_duplex(ports[i]) ? "full" : "half");
				list->phy_info[i].tx_bytes = hnd_get_phy_mib(ports[i], "tx_bytes");
				list->phy_info[i].rx_bytes = hnd_get_phy_mib(ports[i], "rx_bytes");
				list->phy_info[i].tx_packets = hnd_get_phy_mib(ports[i], "tx_packets");
				list->phy_info[i].rx_packets = hnd_get_phy_mib(ports[i], "rx_packets");
				list->phy_info[i].crc_errors = hnd_get_phy_mib(ports[i], "rx_crc_errors");
#endif
#endif
			}
		}
	}

#ifdef RTCONFIG_QTN
	if (model == MODEL_RTAC87U) {
		ports[1] = GetPhyStatus_qtn();
		if (ports[1] == 1000) {
			out_buf[8] = 'G';
		} else if (ports[1] == 100) {
			out_buf[8] = 'M';
		} else if (ports[1] == 10) {
			out_buf[8] = 'M';
		} else {
			out_buf[8] = 'X';
		}
	}
#endif

	if (verbose == 1)
#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
		printf("%s", out_buf);
#else
		puts(out_buf);
#endif

#if defined(RTCONFIG_EXT_RTL8365MB) || defined(RTCONFIG_EXT_RTL8370MB)
#ifdef RTCONFIG_NEW_PHYMAP
	if (port_mapping.extsw_count) {
#else
	if (ext) {
#endif
		ext_lret = ext_rtk_phyState(verbose, PStatus, list);
		lret |= ext_lret;
	}
#endif

	if(ports) free(ports);

	if (verbose == 53134 || verbose == 8365) return ext_lret;
	return lret;
#endif // RTCONFIG_HND_ROUTER_AX_6710
}
#endif //#ifdef RTCONFIG_NEW_PHYMAP
#endif

#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_LAN4WAN_LED)
int LanWanLedCtrl(void)
{
#ifndef HND_ROUTER
#ifdef RTCONFIG_LANWAN_LED
	if(get_lanports_status() && !inhibit_led_on())
		led_control(LED_LAN, LED_ON);
	else
		led_control(LED_LAN, LED_OFF);
#elif defined(RTCONFIG_LAN4WAN_LED)
	int ports[5];
	int i, ret, model, mask;
	char out_buf[30];

	model = get_model();
	switch(model) {
	case MODEL_RTN14UHP:
		/* WAN L1 L2 L3 L4 */
		ports[0]=4; ports[1]=0; ports[2]=1, ports[3]=2; ports[4]=3;
		break;
	}

	memset(out_buf, 0, 30);
	for (i=0; i<5; i++) {
		mask = 0;
		mask |= 0x0001<<ports[i];
		if (get_phy_status(mask)==0) {/*Disconnect*/
			if (i==0) {
				led_control(LED_WAN, LED_OFF);
			} else {
				if (i == 1) led_control(LED_LAN1, LED_OFF);
				if (i == 2) led_control(LED_LAN2, LED_OFF);
				if (i == 3) led_control(LED_LAN3, LED_OFF);
				if (i == 4) led_control(LED_LAN4, LED_OFF);
			}
		}
		else { /*Connect, keep check speed*/
			mask = 0;
			mask |= (0x0003<<(ports[i]*2));
			ret=get_phy_speed(mask);
			ret>>=(ports[i]*2);
			if (i==0) {
				led_control(LED_WAN, LED_ON);
			} else {
				if (i == 1) led_control(LED_LAN1, LED_ON);
				if (i == 2) led_control(LED_LAN2, LED_ON);
				if (i == 3) led_control(LED_LAN3, LED_ON);
				if (i == 4) led_control(LED_LAN4, LED_ON);
			}
		}
	}
#endif
#endif	/* HND_ROUTER */

	return 1;
}
#endif

#if defined(RTAX58U_V2) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
void wan_phy_led_pinmux(int force)
{
	eval("sw", "0xff800554", "0");
#if defined(GTAX6000)
	eval("sw", "0xff800558", force ? "0x4011" : "0x2011");
#elif defined(TUFAX3000_V2)
	eval("sw", "0xff800558", force ? "0x4012" : "0x2012");
#elif defined(RTAXE7800)
	eval("sw", "0xff800558", force ? "0x4003" : "0x2003");
#else
	eval("sw", "0xff800558", force ? "0x4000" : "0x2000");
#endif
	eval("sw", "0xff80055c", "0x21");
}
#endif

#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_HND_ROUTER) || defined(RTCONFIG_HND_ROUTER_AX)
#if defined(RTCONFIG_HND_ROUTER) || defined(RTCONFIG_HND_ROUTER_AX)
// if LED_WAN_NORMAL is only activated by the WAN port.
void set_specific_wan_white_led(int wan_unit, int action){
#ifdef RTCONFIG_DUALWAN
	char *wans_mode = nvram_safe_get("wans_mode");
#endif
#if defined(RTAX86U)
	if(strcmp(get_productid(), "RT-AX86S") && nvram_get_int("ext_phy_model") == EXT_PHY_BCM54991 && nvram_get_int("wans_extwan")){
		if(action)
			eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a835", "0x40");
		else
			eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a835", "0x0");	// CTL LED4 MASK LOW

		return;
	}
#endif

	if(get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_WAN
#ifdef RTCONFIG_DUALWAN
			|| (!strcmp(wans_mode, "lb") && (get_wans_dualwan() & WANSCAP_WAN))
#endif
			)
	{
#if defined(RTAX58U_V2) || defined(GTAX6000)
		wan_phy_led_pinmux((action == LED_OFF) ? 1 : 0);
#endif
		led_control(LED_WAN_NORMAL, action);
	}
}
#endif

int update_wan_leds(int wan_unit, int link_wan_unit)
{
	int link_internet = nvram_get_int("link_internet");

#ifdef DSL_AX82U
	return 0;
#endif

#if defined(RTCONFIG_HND_ROUTER) || defined(RTCONFIG_HND_ROUTER_AX)
#if defined(RTCONFIG_LED_BTN) || defined(RTCONFIG_TURBO_BTN) || !defined(RTCONFIG_WIFI_TOG_BTN)
	if(!nvram_match("AllLED", "1"))
		return 0;
#endif

	if(!nvram_get_int("x_Setting")){
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
		// ZenWiFi: no matter what state the network is, always light the white LED default
		led_control(LED_WAN, LED_OFF);
		set_specific_wan_white_led(wan_unit, LED_ON);
#elif defined(RTCONFIG_WANRED_LED)
		led_control(LED_WAN, LED_OFF);
		led_control(LED_WAN_RED, LED_ON);
#else
		led_control(LED_WAN, LED_ON);
		set_specific_wan_white_led(wan_unit, LED_OFF);
#endif
	}
	else if(link_internet == 2){
#if defined(RTCONFIG_WANRED_LED)
		led_control(LED_WAN, LED_ON);
		led_control(LED_WAN_RED, LED_OFF);
#else
		led_control(LED_WAN, LED_OFF);
		set_specific_wan_white_led(wan_unit, LED_ON);
#endif
	}
	else{
#if defined(RTCONFIG_WANRED_LED)
		led_control(LED_WAN, LED_OFF);
		led_control(LED_WAN_RED, LED_ON);
#else
		led_control(LED_WAN, LED_ON);
		set_specific_wan_white_led(wan_unit, LED_OFF);
#endif
	}
#elif defined(RTCONFIG_LANWAN_LED)
#ifdef RT4GAC68U
	int other_wan = 0;
	char *wans_mode = nvram_safe_get("wans_mode");

	if(wan_unit != wan_primary_ifunit()
#ifdef RTCONFIG_DUALWAN
			&& strcmp(wans_mode, "lb")
#endif
			)
		return 0;

	// let WAN's LED be on always during the load-balance mode.
	if(get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_USB || get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_LAN
#ifdef RTCONFIG_DUALWAN
			|| !strcmp(wans_mode, "lb")
#endif
			)
		other_wan = 1;

	if(link_internet == 2){
		// turn on the WAN led
		eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x1");
		if(other_wan)
			// the WAN led be on static
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x0");
		else
			// the WAN led be flickering
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x1");
	}
	else{
		// turn off the WAN led
		eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x0");
		eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x0");
	}
#else // RT4GAC68U
	/* Turn on/off WAN LED in accordance with link status of WAN port */
	if (link_wan_unit && !inhibit_led_on())
		led_control(LED_WAN, LED_ON);
	else{
		if(link_internet != 2)
			led_control(LED_WAN, LED_OFF);
	}
#endif // RT4GAC68U
#endif

	return 0;
}
#endif

#if defined(HND_ROUTER)
void
setLANLedOn(void)
{
#ifdef RTCONFIG_LAN4WAN_LED
	led_control(LED_LAN1, LED_ON);
	led_control(LED_LAN2, LED_ON);
	led_control(LED_LAN3, LED_ON);
	led_control(LED_LAN4, LED_ON);
#elif defined(RTAX56U)
	eval("ethswctl", "-c", "pmdioaccess", "-x", "0x0014", "-l", "2", "-d", "15");
#else
#if !defined(RTAX82_XD6) && !defined(RTAX82_XD6S)
	led_control(LED_LAN, LED_ON);
#endif
#endif
}

void
setLANLedOff(void)
{
#ifdef RTCONFIG_LAN4WAN_LED
	led_control(LED_LAN1, LED_OFF);
	led_control(LED_LAN2, LED_OFF);
	led_control(LED_LAN3, LED_OFF);
	led_control(LED_LAN4, LED_OFF);
#else
	led_control(LED_LAN, LED_OFF);
#endif
}
#endif // HND_ROUTER

#if defined(RTAX82U) || defined(DSL_AX82U) || defined(GSAX3000) || defined(GSAX5400) || defined(TUFAX5400) || defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
void
setLEDGroupOn(void)
{
	led_control(LED_GROUP1_RED, LED_ON);
	led_control(LED_GROUP1_GREEN, LED_ON);
	led_control(LED_GROUP1_BLUE, LED_ON);
#ifndef TUFAX5400
	led_control(LED_GROUP2_RED, LED_ON);
	led_control(LED_GROUP2_GREEN, LED_ON);
	led_control(LED_GROUP2_BLUE, LED_ON);
	led_control(LED_GROUP3_RED, LED_ON);
	led_control(LED_GROUP3_GREEN, LED_ON);
	led_control(LED_GROUP3_BLUE, LED_ON);
#if !defined(GTAXE11000_PRO) && !defined(GTAXE16000) && !defined(GTAX6000)
	led_control(LED_GROUP4_RED, LED_ON);
	led_control(LED_GROUP4_GREEN, LED_ON);
	led_control(LED_GROUP4_BLUE, LED_ON);
#endif
#endif
#if defined(GSAX3000) || defined(GSAX5400)
	led_control(LED_GROUP5_RED, LED_ON);
	led_control(LED_GROUP5_GREEN, LED_ON);
	led_control(LED_GROUP5_BLUE, LED_ON);
#endif
}

void
setLEDGroupOff(void)
{
	led_control(LED_GROUP1_RED, LED_OFF);
	led_control(LED_GROUP1_GREEN, LED_OFF);
	led_control(LED_GROUP1_BLUE, LED_OFF);
#ifndef TUFAX5400
	led_control(LED_GROUP2_RED, LED_OFF);
	led_control(LED_GROUP2_GREEN, LED_OFF);
	led_control(LED_GROUP2_BLUE, LED_OFF);
	led_control(LED_GROUP3_RED, LED_OFF);
	led_control(LED_GROUP3_GREEN, LED_OFF);
	led_control(LED_GROUP3_BLUE, LED_OFF);
#if !defined(GTAXE11000_PRO) && !defined(GTAXE16000) && !defined(GTAX6000)
	led_control(LED_GROUP4_RED, LED_OFF);
	led_control(LED_GROUP4_GREEN, LED_OFF);
	led_control(LED_GROUP4_BLUE, LED_OFF);
#endif
#endif
#if defined(GSAX3000) || defined(GSAX5400)
	led_control(LED_GROUP5_RED, LED_OFF);
	led_control(LED_GROUP5_GREEN, LED_OFF);
	led_control(LED_GROUP5_BLUE, LED_OFF);
#endif
}

static int
cled_match(int gpio, uint32_t config0, uint32_t config1, uint32_t config2, uint32_t config3)
{
	char path[64];
	char config0_str[16], config1_str[16], config2_str[16], config3_str[16];
	uint32_t config0_cur, config1_cur, config2_cur, config3_cur;
	struct cled_config0 cc0;

	*(uint32_t *)&cc0 = config0;
	if (cc0.mode != 0)
		return 0;

#if (defined(BCM4912) && defined(RTCONFIG_BCM_CLED)) || defined(GTAX6000) || defined(GT10)
	FILE *fp = NULL;
	char *ptr;
	char cmd[64], buf[64];
	int i, found;

	for(i = 0; i < 4; i++) {
		found = 0;
		snprintf(path, sizeof(path), "0xff80%04x", 0x3220 + (16 * gpio + 4 * i));
		snprintf(cmd, sizeof(cmd), "dw %s", path);
		fp = popen(cmd, "r");
		if (fp) {
			memset(buf, 0, sizeof(buf));
			while(fgets(buf, sizeof(buf), fp) != NULL) {
			    if((ptr = strchr(buf, ':')) != NULL) {
				found = 1;
				break;
			    }
			}
			pclose(fp);
		}

		if (found) {
			ptr++;
			switch(i) {
				case 0:
					config0_cur = strtoul(ptr, NULL, 16);
					break;
				case 1:
					config1_cur = strtoul(ptr, NULL, 16);
					break;
				case 2:
					config2_cur = strtoul(ptr, NULL, 16);
					break;
				case 3:
					config3_cur = strtoul(ptr, NULL, 16);
					break;
				default:
					break;
			}
		}
	}

#else
	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config0", gpio);
	f_read_string(path, config0_str, sizeof(config0_str));
	config0_cur = strtoul(config0_str, NULL, 16);

	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config1", gpio);
	f_read_string(path, config1_str, sizeof(config1_str));
	config1_cur = strtoul(config1_str, NULL, 16);

	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config2", gpio);
	f_read_string(path, config2_str, sizeof(config2_str));
	config2_cur = strtoul(config2_str, NULL, 16);

	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config3", gpio);
	f_read_string(path, config3_str, sizeof(config3_str));
	config3_cur = strtoul(config3_str, NULL, 16);
#endif
	if ((config0 == config0_cur) && (config1 == config1_cur) &&
	    (config2 == config2_cur) && (config3 == config3_cur))
		return 1;
	else
		return 0;
}

void
cled_set(int gpio, uint32_t config0, uint32_t config1, uint32_t config2, uint32_t config3)
{
	char path[64], tmp[32];

	if (gpio < 0)
		return;

	if (cled_match(gpio, config0, config1, config2, config3))
		return;

#if (defined(BCM4912) && defined(RTCONFIG_BCM_CLED)) || defined(GTAX6000) || defined(GT10)
	char c0[16], c1[16], c2[16], c3[16];

	snprintf(path, sizeof(path), "0xff80%04x", 0x3020 + 16 * gpio);
	snprintf(c0, sizeof(c0), "0x%08x", config0);
	snprintf(c1, sizeof(c1), "0x%08x", config1);
	snprintf(c2, sizeof(c2), "0x%08x", config2);
	snprintf(c3, sizeof(c3), "0x%08x", config3);
	eval("sw", path, c0, c1, c2, c3);
	snprintf(tmp, sizeof(tmp), "0x%08x", 1 << gpio);
	eval("sw", "0xff80301c", tmp);
#else
	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config0", gpio);
	snprintf(tmp, sizeof(tmp), "0x%08x", config0);
	f_write_string(path, tmp, 0, 0);

	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config1", gpio);
	snprintf(tmp, sizeof(tmp), "0x%08x", config1);
	f_write_string(path, tmp, 0, 0);

	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config2", gpio);
	snprintf(tmp, sizeof(tmp), "0x%08x", config2);
	f_write_string(path, tmp, 0, 0);

	snprintf(path, sizeof(path), "/proc/bcm_cled/led%d/config3", gpio);
	snprintf(tmp, sizeof(tmp), "0x%08x", config3);
	f_write_string(path, tmp, 0, 0);

	snprintf(path, sizeof(path), "/proc/bcm_cled/activate");
	snprintf(tmp, sizeof(tmp), "0x%08x", 1 << gpio);
	f_write_string(path, tmp, 0, 0);
#endif
}

#if defined(GTAXE16000) || defined(GTAX11000_PRO)
#define CLED_GROUP_NUM 4
#else
#define CLED_GROUP_NUM 3
#endif

enum {
	COLOR_R = 0,
	COLOR_G,
	COLOR_B,
	COLOR_MAX
};

void
LEDGroupColor(enum ate_led_color color)
{
	int group;
#if defined(GTAXE16000) || defined(GTAX11000_PRO)
	int cled_gpio[COLOR_MAX][CLED_GROUP_NUM] = {{2, 5, 14, 21}, {4, 8, 16, 22}, {3, 7, 15, 23}}; //{{R},{G},{B}}
#else
	int cled_gpio[COLOR_MAX][CLED_GROUP_NUM] = {{-1, -1, -1}, {-1, -1, -1}, {-1, -1, -1}}; //{{R},{G},{B}
#endif

	LEDGroupReset(LED_OFF);

	for (group = 0; group < CLED_GROUP_NUM; group++) {
		switch(color) {
			case LED_COLOR_WHITE:
				cled_set(cled_gpio[COLOR_R][group],  0xa000, 0x0, 0x0, 0x0);
				cled_set(cled_gpio[COLOR_G][group],  0xa000, 0x0, 0x0, 0x0);
				cled_set(cled_gpio[COLOR_B][group],  0xa000, 0x0, 0x0, 0x0);
				break;
			case LED_COLOR_BLUE:
				cled_set(cled_gpio[COLOR_B][group],  0xa000, 0x0, 0x0, 0x0);
				break;
			case LED_COLOR_RED:
				cled_set(cled_gpio[COLOR_R][group],  0xa000, 0x0, 0x0, 0x0);
				break;
			case LED_COLOR_GREEN:
				cled_set(cled_gpio[COLOR_G][group],  0xa000, 0x0, 0x0, 0x0);
				break;
			default:
				break;
		}
	}
}

void
LEDGroupReset(int mode)
{
	int i;
#if defined(GSAX3000) || defined(GSAX5400)
	int cled_gpio[15] = { 1, 3, 4, 7, 8, 9, 10, 12, 15, 23, 17, 16, 14, 27, 30 };
#elif defined(GTAXE16000) || defined(GTAX11000_PRO)
	int cled_gpio[12] = { 2, 4, 3, 5, 8, 7, 14, 16, 15, 21, 22, 23};
#elif defined(DSL_AX82U)
	int cled_gpio[12] = { 28, 30, 10, 13, 14, 19, 7, 8, 9, 4, 27, 2 };
#elif defined(TUFAX5400)
	int cled_gpio[12] = { 12, 13, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
#elif defined(GTAX6000)
	int cled_gpio[12] = { 2, 4, 3, 5, 8, 7, 14, 16, 15, -1, -1, -1 };
#else
	int cled_gpio[12] = { 1, 3, 4, 7, 8, 9, 10, 12, 15, 23, 17, 16 };
#endif
	for (i = 0; i < sizeof(cled_gpio)/sizeof(int); i++)
		cled_set(cled_gpio[i], (mode == LED_ON) ? 0xa000 : 0x0, 0x0, 0x0, 0x0);
}

#ifdef GTAX6000
void setAntennaGroupOn()
{
	led_control(LED_GROUP_ANT1, LED_ON);
	led_control(LED_GROUP_ANT2, LED_ON);
	led_control(LED_GROUP_ANT3, LED_ON);
	led_control(LED_GROUP_ANT4, LED_ON);
}

void setAntennaGroupOff()
{
	led_control(LED_GROUP_ANT1, LED_ON);
	led_control(LED_GROUP_ANT2, LED_ON);
	led_control(LED_GROUP_ANT3, LED_ON);
	led_control(LED_GROUP_ANT4, LED_ON);
}

void AntennaGroupReset(int mode)
{
	int i;
	int cled_gpio[4] = { 18, 19, 20, 21 };

	for (i = 0; i < 4; i++)
		cled_set(cled_gpio[i], (mode == LED_ON) ? 0xa000 : 0x0, 0x0, 0x0, 0x0);
}
#endif
#endif

#if defined(HND_ROUTER)
void activateLANLed(){
#ifdef RTAX88U
	// activate: LED be off automatically when the cable isn't plugged.
	// activate: LED be on automatically when the cable is plugged.
	// not activate: LED be off no matter the calbe is plugged or not.
	setLANLedOn();
#else
	// fully control by watchdog
#endif
}
#endif //HND_ROUTER

int
setAllLedOn(void)
{
	int model;

	led_control(LED_POWER, LED_ON);

	// generate nvram nvram according to system setting
	model = get_model();
	switch(model) {
		case MODEL_RTN16:
		case MODEL_RTN66U:
		{
			/* LAN, WAN Led On */
			eval("et", "robowr", "0", "0x18", "0x01ff");
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("radio", "on"); /* wireless */
			led_control(LED_USB, LED_ON);
			break;
		}
		case MODEL_RTN18U:
		{
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
			led_control(LED_POWER, LED_ON);
			led_control(LED_WAN, LED_ON);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			eval("wl", "-i", "eth1", "ledbh", "10", "7");
			break;
		}
		case MODEL_DSLAC68U:
		{
			led_control(LED_USB3, LED_ON);
			led_control(LED_WAN, LED_ON);
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "ledbh", "10", "1");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "10", "1");	// wl 5G
			/* 4360's fake 5g led */
			led_control(LED_5G, LED_ON);
			eval("adslate", "led", "on");
			break;
		}
#ifdef DSL_AX82U
		case MODEL_DSLAX82U:
		{
			led_control(LED_WAN, LED_ON);
#ifdef RTCONFIG_WANRED_LED
			led_control(LED_WAN_RED, LED_ON);
#else
			led_control(LED_WAN_NORMAL, LED_ON);
#endif
			led_control(LED_POWER, LED_ON);
			led_control(LED_POWER_RED, LED_ON);
			led_control(LED_LAN, LED_ON);
			led_control(LED_WIFI, LED_ON);
			LEDGroupReset(LED_ON);
			setLEDGroupOn();
		}
#endif
		case MODEL_RTAC87U:
		{
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "ledbh", "10", "1");			// wl 2.4G
			led_control(LED_WPS, LED_ON);
			led_control(LED_WAN, LED_ON);
#ifdef RTCONFIG_QTN
			setAllLedOn_qtn();
#endif
			break;
		}
		case MODEL_RTAC68U:
		case MODEL_RTAC3200:
		case MODEL_RTAC88U:
		case MODEL_RTAC3100:
		case MODEL_RTAC5300:
		case MODEL_RTAC86U:
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_RTAX55:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAXE7800:
		case MODEL_RTAX86U:
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		{
#if defined(RTAC68U) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
#endif
#ifdef RTCONFIG_LOGO_LED
			led_control(LED_LOGO, LED_ON);
#endif
#ifdef RT4GAC68U
			led_control(LED_WPS, LED_ON);
#endif
#ifdef RTCONFIG_INTERNAL_GOBI
#ifdef RT4GAC68U
			led_control(LED_3G, LED_ON);
#endif
			led_control(LED_LTE, LED_ON);
			led_control(LED_SIG1, LED_ON);
			led_control(LED_SIG2, LED_ON);
			led_control(LED_SIG3, LED_ON);
#endif
#ifdef RTAX58U_V2
			system("rtkswitch 42");
#endif
#ifdef HND_ROUTER
#ifndef GTAC2900
#if defined(RTAX58U_V2) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
			wan_phy_led_pinmux(1);
#endif
			led_control(LED_WAN_NORMAL, LED_ON);
			setLANLedOn();
#endif
#else
			eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x01e0");
#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_BCM_7114)
			led_control(LED_LAN, LED_ON);
#endif
#endif
#if defined(RTAC3200)
			eval("wl", "ledbh", "10", "1");			// wl 5G low
			eval("wl", "-i", "eth2", "ledbh", "10", "1");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "10", "1");	// wl 5G high
#elif defined(RTAC5300)
			eval("wl", "ledbh", "9", "1");			// wl 5G low
			eval("wl", "-i", "eth2", "ledbh", "9", "1");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "9", "1");	// wl 5G high
#elif defined(GTAC5300) || defined(GTAXE11000)
			eval("wl", "-i", "eth6", "ledbh", "9", "1");	// wl 5G high
			eval("wl", "-i", "eth7", "ledbh", "9", "1");	// wl 2.4G
			eval("wl", "-i", "eth8", "ledbh", "9", "1");	// wl 5G low
#elif defined(RTAX88U)
			eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G
#elif defined(GTAX11000)
			eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "15", "1");	// wl 5G high
#elif defined(RTAX92U)
			eval("wl", "-i", "eth5", "ledbh", "10", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "10", "1");	// wl 5G low
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G high
#elif defined(GTAX6000)
			eval("wl", "-i", "eth6", "ledbh", "13", "1");   // wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "13", "1");   // wl 5G low
#elif defined(GTAX11000_PRO)
			eval("wl", "-i", "eth6", "ledbh", "13", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "13", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "13", "1");	// wl 5G high
#elif defined(GTAXE16000)
			eval("wl", "-i", "eth7", "ledbh", "13", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "13", "1");	// wl 5G high
			eval("wl", "-i", "eth9", "ledbh", "13", "1");	// wl 6G
			eval("wl", "-i", "eth10", "ledbh", "13", "1");   // wl 2.4G
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
			eval("wl", "-i", "eth2", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "0", "1");	// wl 5G
#elif defined(TUFAX3000_V2)
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 5G
#elif defined(RTAXE7800)
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G
			eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 6G
#elif defined(RTAX82_XD6S)
			eval("wl", "-i", "eth2", "ledbh", "0", "1");	// wl 2.4G
#elif defined(BCM6750)
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
			if (!nvram_get_int("LED_order"))
				led_control(LED_5G, LED_ON);
			if (!nvram_get_int("LED_order"))
				eval("wl", "-i", "eth6", "ledbh", "15", "0");
			else
#endif
			eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 5G
#elif defined(RTAX86U) || defined(RTAX5700)
			if(!strcmp(get_productid(), "RT-AX86S")){
				eval("wl", "-i", "eth5", "ledbh", "7", "1");	// wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 5G
			} else {
				eval("wl", "-i", "eth6", "ledbh", "7", "1");	// wl 2.4G
				eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G
			}
#elif defined(RTAX68U)
			eval("wl", "-i", "eth5", "ledbh", "7", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "7", "1");	// wl 5G
#elif defined(RTAC86U) || defined(GTAC2900)
			eval("wl", "ledbh", "9", "1");			// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "9", "1");	// wl 5G
#elif defined(RTAC88U) || defined(RTAC3100)
			eval("wl", "ledbh", "9", "1");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "9", "1");	// wl 5G
#elif defined(RTAC68U_V4)
			eval("wl", "-i", "eth5", "ledbh", "10", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "10", "1");	// wl 5G
#else
			eval("wl", "ledbh", "10", "1");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "10", "1");	// wl 5G
#endif

#if defined(RTAC3200) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
			led_control(LED_WPS, LED_ON);
			led_control(LED_WAN, LED_ON);
#endif
#if defined(RTAX82U) || defined(GSAX3000) || defined(GSAX5400) || defined(TUFAX5400) || defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
			LEDGroupReset(LED_ON);
			setLEDGroupOn();
#endif
#ifdef GTAX6000
			AntennaGroupReset(LED_ON);
			setAntennaGroupOn();
#endif
#if defined(GTAXE16000) || (GTAX11000_PRO)
			led_control(LED_WAN_RGB_GREEN, LED_ON);
			led_control(LED_WAN_RGB_BLUE, LED_ON);
			led_control(LED_10G_WHITE, LED_ON);
			led_control(LED_10G_RGB_RED, LED_ON);
			led_control(LED_10G_RGB_GREEN, LED_ON);
			led_control(LED_10G_RGB_BLUE, LED_ON);
#endif
#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
			bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
#endif

#ifdef RTCONFIG_EXTPHY_BCM84880
#if defined(RTAX86U) || defined(GTAX11000) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
			int ext_phy_model = nvram_get_int("ext_phy_model");

			if(strcmp(get_productid(), "RT-AX86S"))
				led_control(LED_EXTPHY, LED_ON);

			if(!strcmp(get_productid(), "RT-AX86S")) ;
			else if(ext_phy_model == EXT_PHY_GPY211)
				eval("ethctl", "phy", "ext", EXTPHY_GPY_ADDR_STR, "0x1e0001", "0xf0");
			else if(ext_phy_model == EXT_PHY_RTL8226)
				eval("ethctl", "phy", "ext", EXTPHY_RTL_ADDR_STR, "0x1fd032", "0x0027");	// RTL LCR2 LED Control Reg
			else
#endif
			{
#if defined(PHY_ID_54991E)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x7fff0", "0x11");	// 2.5G LED (1000M/100M)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a832", "0x21");	// 2.5G LED (2500M)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a83b", "0xa490");
#elif defined(PHY_ID_54991EL) || defined(PHY_ID_50991EL)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a832", "0x0");	// CTL LED3 MASK LOW
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a835", "0xffff");	// CTL LED4 MASK LOW
#endif
			}
#endif // RTCONFIG_EXTPHY_BCM84880

#ifdef RTAC68U
			if (is_ac66u_v2_series() || is_ac68u_v3_series())
				led_control(LED_WAN, LED_ON);
#endif
#ifdef RTCONFIG_RGBLED
			setRogRGBLedTest(5);
#endif
			break;
		}
#if defined(RTAX56U)
		case MODEL_RTAX56U:
		{
			led_control(LED_WAN, LED_ON);
			led_control(LED_WAN_RED, LED_ON);
			led_control(LED_POWER, LED_ON);
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 5G
			eval("ethswctl", "-c", "pmdioaccess", "-x", "0x0014", "-l", "2", "-d", "15");
			break;
		}
#endif
#if defined(RPAX56) || defined(RPAX58)
		case MODEL_RPAX58:
		{
			eval("sw", "0xff803070", "0x3e000");
			eval("sw", "0xff803090", "0x3e000");
			eval("sw", "0xff8030d0", "0x3e000");
			eval("sw", "0xff8030e0", "0x3e000");
			eval("sw", "0xff803100", "0x3e000");
			eval("sw", "0xFF80301c", "0x58a0");
			break;
		}
		case MODEL_RPAX56:
		{
			eval("sw", "0xFF803014", "0xffff");
#ifdef RPAX58
			eval("sw", "0xff803010", "0x58a0");
#else
			eval("sw", "0xff803010", "0xd8a0");
#endif
			eval("sw", "0xFF803018", "0");
			eval("sw", "0xff803070", "0x3e000");
			eval("sw", "0xff803090", "0x3e000");
			eval("sw", "0xff8030d0", "0x3e000");
			eval("sw", "0xff8030e0", "0x3e000");
			eval("sw", "0xff803100", "0x3e000");
			eval("sw", "0xff803110", "0x3e000");
			eval("sw", "0xFF80301c", "0xc8a0");
			break;
		}
#endif
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		{
			led_control(LED_RGB1_RED, LED_ON);
			led_control(LED_RGB1_GREEN, LED_ON);
			led_control(LED_RGB1_BLUE, LED_ON);
			break;
		}
#endif
#if defined(ET12) || defined(XT12)
		case MODEL_ET12:
		case MODEL_XT12:
		{
			led_control(LED_RGB1_RED, LED_ON);
			led_control(LED_RGB1_GREEN, LED_ON);
			led_control(LED_RGB1_BLUE, LED_ON);
			led_control(LED_RGB2_RED, LED_ON);
			led_control(LED_RGB2_GREEN, LED_ON);
			led_control(LED_RGB2_BLUE, LED_ON);
			led_control(LED_RGB3_RED, LED_ON);
			led_control(LED_RGB3_GREEN, LED_ON);
			led_control(LED_RGB3_BLUE, LED_ON);
			led_control(LED_SIDE1_WHITE, LED_ON);
			led_control(LED_SIDE2_WHITE, LED_ON);
			led_control(LED_SIDE3_WHITE, LED_ON);
			break;
		}
#endif
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		{
#ifdef RTCONFIG_LED_ALL
			led_control(LED_ALL, LED_ON);
#endif
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
			led_control(LED_WAN, LED_ON);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "ledbh", "3", "1");			// wl 2.4G
			eval("wl", "-i", "eth2","ledbh", "10", "1");
			/* 4352's fake 5g led */
			led_control(LED_5G, LED_ON);
			break;
		}
		case MODEL_RTAC66U:
		{
			/* LAN, WAN Led On */
			eval("et", "robowr", "0", "0x18", "0x01ff");
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("radio", "on"); /* 2G led */
			led_control(LED_5G, LED_ON);
			led_control(LED_USB, LED_ON);
			break;
		}
		case MODEL_RTN14UHP:
		{
			led_control(LED_POWER, LED_ON);
			/* convert from shared, boardapi.c */
			led_control(LED_WPS, LED_ON);
			led_control(LED_USB, LED_ON);
			eval("radio", "on"); /* 2G led */
			if (nvram_contains_word("rc_support", "lanwan_led2")) {
				led_control(LED_WAN, LED_ON);
#ifdef RTCONFIG_LAN4WAN_LED
				led_control(LED_LAN1, LED_ON);
				led_control(LED_LAN2, LED_ON);
				led_control(LED_LAN3, LED_ON);
				led_control(LED_LAN4, LED_ON);
#endif
			} else {
				eval("et", "robowr", "00", "0x12", "0xfd55");
			}
			break;
		}
		case MODEL_APN12HP:
		{
			led_control(LED_POWER, LED_ON);
			/* convert from shared, boardapi.c */
			nvram_set_int("led_2g_gpio", 4099);
			led_control(LED_2G, LED_ON);
			led_control(LED_WAN, LED_ON);
			break;
		}
		case MODEL_RTN10P:
		case MODEL_RTN10D1:
		case MODEL_RTN10PV2:
		{
			led_control(LED_WPS, LED_ON);
		}
		case MODEL_RTN12B1:
		case MODEL_RTN12C1:
		case MODEL_RTN12D1:
		case MODEL_RTN12VP:
		case MODEL_RTN12HP:
		case MODEL_RTN12HP_B1:
		{
			eval("et", "robowr", "00", "0x12", "0xfd55");
			eval("radio", "on"); /* wireless */
			break;
		}
		case MODEL_RTN10U:
		{
			led_control(LED_WPS, LED_ON);
			led_control(LED_USB, LED_ON);
			eval("et", "robowr", "00", "0x12", "0xfd55");
			eval("radio", "on"); /* wireless */
			break;
		}
		case MODEL_RTN15U:
		{
			//LAN, WAN Led On
			led_control(LED_POWER, LED_ON);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			led_control(LED_WAN, LED_ON);
			led_control(LED_USB, LED_ON);
			eval("radio", "on"); /* wireless */
			break;
		}
		case MODEL_RTN53:
		{
			//LAN, WAN Led On
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			led_control(LED_WAN, LED_ON);
			led_control(LED_2G, LED_ON);
			led_control(LED_5G, LED_ON);
			break;
		}
		case MODEL_RTAC53U:
		{
			led_control(LED_POWER, LED_ON);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			led_control(LED_WAN, LED_ON);
			led_control(LED_USB, LED_ON);
			eval("wl", "-i", "eth1", "ledbh", "3", "1");	// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "9", "1");	// wl 5G
			break;
		}
		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
		{
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "-i", "eth1", "ledbh", "3", "1");	// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "11", "1");	// wl 5G
			led_control(LED_WPS, LED_ON);
			led_control(LED_USB, LED_ON);
			break;
		}
	}

	puts("1");
	return 0;
}

int setAllOrangeLedOn(void) {
	int model = get_model();
	switch (model) {
		case MODEL_RTAC68U:
#ifdef RTCONFIG_INTERNAL_GOBI
#ifdef RT4GAC68U
			led_control(LED_3G, LED_ON);
#endif
#endif
			break;
	};

	puts("1");
	return 0;
}

int
setWlOffLed(void)
{
	int model;
	int wlon_unit = nvram_get_int("wlc_band");
	int wlon_unit_sec = -1;
#ifdef RTCONFIG_DPSTA
	char name[80], *next;
	int unit, count;
	char dpsta_ifnames[32] = { 0 };

	strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));
	if (strlen(dpsta_ifnames)) {
		count = 0;
		foreach(name, dpsta_ifnames, next) {
			count++;
			unit = -1;
			wl_ioctl(name, WLC_GET_INSTANCE, &unit, sizeof(unit));
			if (count == 1)
				wlon_unit = unit;
			else if (count == 2)
				wlon_unit_sec = unit;
			else
				break;
		}
	}
#endif

	model = get_model();
	switch(model) {
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		{
			if (wlon_unit != 0) {
				eval("wl", "ledbh", "3", "0");			// wl 2.4G
			} else {
				eval("wl", "-i", "eth2", "ledbh", "10", "0");	// wl 5G
				led_control(LED_5G, LED_OFF);
			}
			break;
		}
		case MODEL_RTAC68U:
			if (wlon_unit != 0) {
				eval("wl", "ledbh", "10", "0");			// wl 2.4G
			} else {
				eval("wl", "-i", "eth2", "ledbh", "10", "0");	// wl 5G
			}
			break;

		case MODEL_RTAC88U:
		case MODEL_RTAC86U:
		case MODEL_RTAC3100:
			if (wlon_unit != 0) {
				eval("wl", "ledbh", "9", "0");			// wl 2.4G
			} else {						// wl 5G
				if (model == MODEL_RTAC86U)
					eval("wl", "-i", "eth6", "ledbh", "9", "0");
				else
					eval("wl", "-i", "eth2", "ledbh", "9", "0");
			}
			break;

		case MODEL_RTAC5300:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth1", "ledbh", "9", "0");	// wl 2.4G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth2", "ledbh", "9", "0");	// wl 5G low
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth3", "ledbh", "9", "0");	// wl 5G high
			break;
		}
		case MODEL_GTAC5300:
		case MODEL_GTAXE11000:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth6", "ledbh", "9", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth7", "ledbh", "9", "0");	// wl 5G low
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth8", "ledbh", "9", "0");	// wl 5G high
			break;
		}
		
		case MODEL_GTAX11000:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G low
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth8", "ledbh", "15", "0");	// wl 5G high
			break;
		}

		case MODEL_GTAX6000:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth6", "ledbh", "13", "0");   // wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth7", "ledbh", "13", "0");   // wl 5G low
			break;
		}

		case MODEL_GTAX11000_PRO:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth6", "ledbh", "13", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth7", "ledbh", "13", "0");	// wl 5G low
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth8", "ledbh", "13", "0");	// wl 5G high
			break;
		}

		case MODEL_GTAXE16000:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth7", "ledbh", "13", "0");	// wl 5G low
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth8", "ledbh", "13", "0");	// wl 5G high
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth9", "ledbh", "13", "0");	// wl 6G
			if (wlon_unit != 3 && wlon_unit_sec != 3)
				eval("wl", "-i", "eth10", "ledbh", "13", "0");	// wl 2G
			break;
		}


		case MODEL_RTAX92U:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "10", "0");	// wl 5G high
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth6", "ledbh", "10", "0");	// wl 2G
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G low
			break;
		}
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth4", "ledbh", "10", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth5", "ledbh", "10", "0");	// wl 5G
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 5G high
			break;
		}
		case MODEL_RTAX55:
		case MODEL_RTAX58U_V2:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth2", "ledbh", "0", "21");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth3", "ledbh", "0", "21");	// wl 5G
			break;
		}
		case MODEL_TUFAX3000_V2:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "0", "21");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth6", "ledbh", "0", "21");	// wl 5G
			break;
		}
		case MODEL_RTAXE7800:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "0", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth6", "ledbh", "0", "0");	// wl 6G
			break;
		}
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "wl0", "ledbh", "10", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "wl1", "ledbh", "10", "0");	// wl 5G
			break;
		}
		case MODEL_RTAX58U:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "0", "21");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1) {
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
				if (!nvram_get_int("LED_order"))
					led_control(LED_5G, LED_OFF);
				else
#endif
				eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 5G
			}
			break;
		}
		case MODEL_RTAX82_XD6S:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth2", "ledbh", "0", "21");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth3", "ledbh", "15", "0");	// wl 5G
			break;
		}
		case MODEL_RTAX56U:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "0", "21");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth6", "ledbh", "0", "21");	// wl 5G
			break;
		}
		case MODEL_RPAX58:
			break;
		case MODEL_RPAX56:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth1", "ledbh", "0", "21");   // wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth2", "ledbh", "0", "21");   // wl 5G
			break;
		}
		case MODEL_RTAX88U:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G
			break;
		}
		case MODEL_RTAX86U:
		{
			if(!strcmp(get_productid(), "RT-AX86S")){
				if (wlon_unit != 0 && wlon_unit_sec != 0)
					eval("wl", "-i", "eth5", "ledbh", "7", "0");	// wl 2G
				if (wlon_unit != 1 && wlon_unit_sec != 1)
					eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 5G
			} else {
				if (wlon_unit != 0 && wlon_unit_sec != 0)
					eval("wl", "-i", "eth6", "ledbh", "7", "0");	// wl 2G
				if (wlon_unit != 1 && wlon_unit_sec != 1)
					eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G
			}
			break;
		}
		case MODEL_RTAX68U:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "7", "0");	// wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth6", "ledbh", "7", "0");	// wl 5G
			break;
		}
		case MODEL_RTAC68U_V4:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth5", "ledbh", "10", "0");    // wl 2G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "-i", "eth6", "ledbh", "10", "0");    // wl 5G
			break;
		}
		case MODEL_RTAC3200:
		{
			if (wlon_unit != 0 && wlon_unit_sec != 0)
				eval("wl", "-i", "eth2", "ledbh", "10", "0");	// wl 2.4G
			if (wlon_unit != 1 && wlon_unit_sec != 1)
				eval("wl", "ledbh", "10", "0");			// wl 5G low
			if (wlon_unit != 2 && wlon_unit_sec != 2)
				eval("wl", "-i", "eth3", "ledbh", "10", "0");	// wl 5G high
			break;
		}
		case MODEL_RTAC53U:
		{
			if (wlon_unit != 0) {
				eval("wl", "-i", "eth1", "ledbh", "3", "0");	// wl 2.4G
			} else {
				eval("wl", "-i", "eth2", "ledbh", "9", "0");	// wl 5G
			}
			break;
		}
		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
		{
			eval("wl", "ledbh", "10", "0"); // wl 2.4G
			led_control(LED_5G, LED_OFF);
			break;
		}
	}

	return 0;
}

int
setAllLedOff(void)
{
	int model;

#if defined(RTCONFIG_LED_BTN) || defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_TURBO_BTN) || !defined(RTCONFIG_WIFI_TOG_BTN)
	nvram_set_int("AllLED", 0);
#endif
	led_control(LED_POWER, LED_OFF);

	// generate nvram nvram according to system setting
	model = get_model();
	switch(model) {
		case MODEL_RTN16:
		case MODEL_RTN66U:
		{
			/* LAN, WAN Led Off */
			eval("et", "robowr", "0", "0x18", "0x01e0");
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("radio", "off"); /* wireless */
			led_control(LED_USB, LED_OFF);
			break;
		}
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		{
#ifdef RTCONFIG_LED_ALL
			led_control(LED_ALL, LED_OFF);
#endif
			eval("et", "robowr", "0", "0x18", "0x01e0");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "ledbh", "3", "0");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "10", "0");
			/* 4352's fake 5g led */
			led_control(LED_5G, LED_OFF);
			break;
		}
		case MODEL_RTN18U:
		{
			led_control(LED_USB, LED_OFF);
			led_control(LED_USB3, LED_OFF);
			led_control(LED_POWER, LED_OFF);
			led_control(LED_WAN, LED_OFF);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_OFF);
#endif
			led_control(LED_2G, LED_OFF);
			eval("wl", "-i", "eth1", "ledbh", "10", "0");
			break;
		}
		case MODEL_DSLAC68U:
		{
			char *ledcmd_argv[] = {"adslate", "led", "off", NULL};
			led_control(LED_USB3, LED_OFF);
			led_control(LED_WAN, LED_OFF);
			eval("et", "robowr", "0", "0x18", "0x01e0");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "ledbh", "10", "0");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "10", "0");
			/* 4360's fake 5g led */
			led_control(LED_5G, LED_OFF);
			_eval(ledcmd_argv, NULL, 5, NULL);
			break;
		}
#ifdef DSL_AX82U
		case MODEL_DSLAX82U:
		{
			led_control(LED_WAN, LED_OFF);
#ifdef RTCONFIG_WANRED_LED
			led_control(LED_WAN_RED, LED_OFF);
#else
			led_control(LED_WAN_NORMAL, LED_OFF);
#endif
			led_control(LED_POWER, LED_OFF);
			led_control(LED_POWER_RED, LED_OFF);
			led_control(LED_LAN, LED_OFF);
			led_control(LED_WIFI, LED_OFF);
			stop_ledg();
			setLEDGroupOff();
			break;
		}
#endif
		case MODEL_RTAC87U:
		{
			eval("et", "robowr", "0", "0x18", "0x01e0");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "ledbh", "10", "0");			// wl 2.4G
			led_control(LED_WPS, LED_OFF);
			led_control(LED_WAN, LED_OFF);
#ifdef RTCONFIG_QTN
			setAllLedOff_qtn();
#endif
			break;
		}
		case MODEL_RTAC68U:
		case MODEL_RTAC3200:
		case MODEL_RTAC88U:
		case MODEL_RTAC3100:
		case MODEL_RTAC5300:
		case MODEL_RTAC86U:
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_RTAX55:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAXE7800:
		case MODEL_RTAX86U:
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		{
#if defined(RTAC68U) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
			led_control(LED_USB, LED_OFF);
			led_control(LED_USB3, LED_OFF);
#endif
#ifdef RTCONFIG_LOGO_LED
			led_control(LED_LOGO, LED_OFF);
#endif
#ifdef RT4GAC68U
			led_control(LED_WPS, LED_OFF);
#endif
#ifdef RTCONFIG_INTERNAL_GOBI
#ifdef RT4GAC68U
			led_control(LED_3G, LED_OFF);
#endif
			led_control(LED_LTE, LED_OFF);
			led_control(LED_SIG1, LED_OFF);
			led_control(LED_SIG2, LED_OFF);
			led_control(LED_SIG3, LED_OFF);
#endif
#ifdef RTAX58U_V2
			system("rtkswitch 41");
#endif
#ifdef HND_ROUTER
#ifndef GTAC2900
#if defined(RTAX58U_V2) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
			wan_phy_led_pinmux(1);
#endif
			led_control(LED_WAN_NORMAL, LED_OFF);
			setLANLedOff();
#endif
#else
			eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x01e0");	// lan/wan ethernet/giga led
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x01e0");
#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_BCM_7114)
			led_control(LED_LAN, LED_OFF);
#endif
#endif
#if defined(RTAC3200)
			eval("wl", "ledbh", "10", "0");			// wl 5G low
			eval("wl", "-i", "eth2", "ledbh", "10", "0");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "10", "0");	// wl 5G high
#elif defined (RTAC5300)
			eval("wl", "ledbh", "9", "0");			// wl 5G low
			eval("wl", "-i", "eth2", "ledbh", "9", "0");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "9", "0");	// wl 5G high
#elif defined(GTAC5300) || defined(GTAXE11000)
			eval("wl", "-i", "eth6", "ledbh", "9", "0");	// wl 5G high
			eval("wl", "-i", "eth7", "ledbh", "9", "0");	// wl 2.4G
			eval("wl", "-i", "eth8", "ledbh", "9", "0");	// wl 5G low
#elif defined(RTAX88U)
			eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5g
#elif defined(GTAX11000)
			eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "15", "0");	// wl 5G high
#elif defined(RTAX92U)
			eval("wl", "-i", "eth5", "ledbh", "10", "0");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "10", "0");	// wl 5G low
			eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G high
#elif defined(GTAX6000)
			eval("wl", "-i", "eth6", "ledbh", "13", "0");   // wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "13", "0");   // wl 5G low
#elif defined(GTAX11000_PRO)
			eval("wl", "-i", "eth6", "ledbh", "13", "0");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "13", "0");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "13", "0");	// wl 5G high
#elif defined(GTAXE16000)
			eval("wl", "-i", "eth7", "ledbh", "13", "0");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "13", "0");	// wl 5G high
			eval("wl", "-i", "eth9", "ledbh", "13", "0");	// wl 6G
			eval("wl", "-i", "eth10", "ledbh", "13", "0");  // wl 2.4G
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
			eval("wl", "-i", "eth2", "ledbh", "0", "21");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "0", "21");	// wl 5G
#elif defined(TUFAX3000_V2)
			eval("wl", "-i", "eth5", "ledbh", "0", "21");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "0", "21");	// wl 5G
#elif defined(RTAXE7800)
			eval("wl", "-i", "eth5", "ledbh", "0", "0");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G
			eval("wl", "-i", "eth6", "ledbh", "0", "0");	// wl 6G
#elif defined(RTAX82_XD6S)
			eval("wl", "-i", "eth2", "ledbh", "0", "21");	// wl 2.4G
#elif defined(BCM6750)
			eval("wl", "-i", "eth5", "ledbh", "0", "21");	// wl 2.4G
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
			if (!nvram_get_int("LED_order"))
				led_control(LED_5G, LED_OFF);
			if (!nvram_get_int("LED_order"))
				eval("wl", "-i", "eth6", "ledbh", "15", "1");
			else
#endif
			eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 5G
#elif defined(RTAX86U) || defined(RTAX5700)
			if(!strcmp(get_productid(), "RT-AX86S")){
				eval("wl", "-i", "eth5", "ledbh", "7", "0");	// wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "15", "0");	// wl 5G
			} else {
				eval("wl", "-i", "eth6", "ledbh", "7", "0");	// wl 2.4G
				eval("wl", "-i", "eth7", "ledbh", "15", "0");	// wl 5G
			}
#elif defined(RTAX68U)
			eval("wl", "-i", "eth5", "ledbh", "7", "0");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "7", "0");	// wl 5G
#elif defined(RTAC86U) || defined(GTAC2900)
			eval("wl", "ledbh", "9", "0");			// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "9", "0");	// wl 5G
#elif defined (RTAC88U) || defined (RTAC3100)
			eval("wl", "ledbh", "9", "0");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "9", "0");	// wl 5G
#elif defined(RTAC68U_V4)
			eval("wl", "-i", "eth5", "ledbh", "10", "0");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "10", "0");	// wl 5G
#else
			eval("wl", "ledbh", "10", "0");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "10", "0");	// wl 5G
#endif

#if defined(RTAC3200) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
			led_control(LED_WPS, LED_OFF);
			led_control(LED_WAN, LED_OFF);
#endif
#ifdef DSL_AX82U
			stop_ledg();
#endif
#if defined(RTAX82U) || defined(DSL_AX82U) || defined(GSAX3000) || defined(GSAX5400) || defined(TUFAX5400) || defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
			LEDGroupReset(LED_OFF);
#endif
#ifdef GTAX6000
			AntennaGroupReset(LED_OFF);
#endif
#if defined(GTAXE16000) || defined(GTAX11000_PRO)
			led_control(LED_WAN_RGB_GREEN, LED_OFF);
			led_control(LED_WAN_RGB_BLUE, LED_OFF);
			led_control(LED_10G_WHITE, LED_OFF);
#endif

#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
			bcm_cled_ctrl(BCM_CLED_OFF, BCM_CLED_STEADY_NOBLINK);
#endif

#ifdef RTCONFIG_EXTPHY_BCM84880
#if defined(RTAX86U) || defined(GTAX11000) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
			int ext_phy_model = nvram_get_int("ext_phy_model");

			if(strcmp(get_productid(), "RT-AX86S"))
				led_control(LED_EXTPHY, LED_OFF);

			if(!strcmp(get_productid(), "RT-AX86S")) ;
			else if(ext_phy_model == EXT_PHY_GPY211)
				eval("ethctl", "phy", "ext", EXTPHY_GPY_ADDR_STR, "0x1e0001", "0x0");
			else if(ext_phy_model == EXT_PHY_RTL8226)
				eval("ethctl", "phy", "ext", EXTPHY_RTL_ADDR_STR, "0x1fd032", "0x0000");	// RTL LCR2 LED Control Reg
			else
#endif
			{
#if defined(PHY_ID_54991E)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x7fff0", "0x9"); //2.5G LED
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a832", "0x0");
#elif defined(PHY_ID_54991EL) || defined(PHY_ID_50991EL)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a835", "0x0");	// CTL LED4 MASK LOW
#endif
			}
#endif // RTCONFIG_EXTPHY_BCM84880

#ifdef RTAC68U
			if (is_ac66u_v2_series() || is_ac68u_v3_series())
				led_control(LED_WAN, LED_OFF);
#endif
#ifdef RTCONFIG_RGBLED
			setRogRGBLedTest(4);
#endif
			break;
		}
#if defined(RTAX56U)
		case MODEL_RTAX56U:
		{
			led_control(LED_WAN, LED_OFF);
			led_control(LED_WAN_RED, LED_OFF);
			led_control(LED_WAN_NORMAL, LED_OFF);
			led_control(LED_POWER, LED_OFF);
			eval("wl", "-i", "eth5", "ledbh", "0", "21");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "0", "21");	// wl 5G
			eval("ethswctl", "-c", "pmdioaccess", "-x", "0x0014", "-l", "2", "-d", "0");
			break;
		}
#endif
#if defined(RPAX56) || defined(RPAX58)
		case MODEL_RPAX58:
		{
			eval("sw", "0xff803070", "0");
			eval("sw", "0xff803090", "0");
			eval("sw", "0xff8030d0", "0");
			eval("sw", "0xff8030e0", "0");
			eval("sw", "0xff803100", "0");
			eval("sw", "0xFF80301c", "0x58a0");
			break;
		}
		case MODEL_RPAX56:
		{
			eval("sw", "0xFF803014", "0x1000");
			eval("sw", "0xff803010", "0");
			eval("sw", "0xFF803018", "0x1000");
			eval("sw", "0xff803070", "0");
			eval("sw", "0xff803090", "0");
			eval("sw", "0xff8030d0", "0");
			eval("sw", "0xff8030e0", "0");
			eval("sw", "0xff803100", "0");
			eval("sw", "0xff803110", "0");
			eval("sw", "0xFF80301c", "0xc8a0");
			break;
		}
#endif
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		{
			bcm_cled_ctrl(BCM_CLED_OFF, BCM_CLED_STEADY_NOBLINK);
			break;
		}
#endif
#if defined(ET12) || defined(XT12)
		case MODEL_ET12:
		case MODEL_XT12:
		{
			bcm_cled_ctrl(BCM_CLED_OFF, BCM_CLED_STEADY_NOBLINK);
			bcm_cled_ctrl_single_white(BCM_CLED_OFF, BCM_CLED_STEADY_NOBLINK);
			break;
		}
#endif
		case MODEL_RTAC66U:
		{
			/* LAN, WAN Led Off */
			eval("et", "robowr", "0", "0x18", "0x01e0");
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("radio", "off"); /* 2G led*/
			led_control(LED_5G, LED_OFF);
			led_control(LED_USB, LED_OFF);
			break;
		}
		case MODEL_RTN14UHP:
		{
			led_control(LED_POWER, LED_OFF);
			/* convert from shared, boardapi.c */
			led_control(LED_WPS, LED_OFF);
			led_control(LED_USB, LED_OFF);
			eval("radio", "off"); /* 2G led */
			if (nvram_contains_word("rc_support", "lanwan_led2")) {
				led_control(LED_WAN, LED_OFF);
#ifdef RTCONFIG_LAN4WAN_LED
				led_control(LED_LAN1, LED_OFF);
				led_control(LED_LAN2, LED_OFF);
				led_control(LED_LAN3, LED_OFF);
				led_control(LED_LAN4, LED_OFF);
#endif
			} else {
				eval("et", "robowr", "00", "0x12", "0xf800");
			}
			break;
		}
		case MODEL_APN12HP:
		{
			led_control(LED_POWER, LED_OFF);
			/* convert from shared, boardapi.c */
			nvram_set_int("led_2g_gpio", 4099);
			led_control(LED_2G, LED_OFF);
			led_control(LED_WAN, LED_OFF);
			break;
		}
		case MODEL_RTN10P:
		case MODEL_RTN10D1:
		case MODEL_RTN10PV2:
		{
			led_control(LED_WPS, LED_OFF);
		}
		case MODEL_RTN12B1:
		case MODEL_RTN12C1:
		case MODEL_RTN12D1:
		case MODEL_RTN12VP:
		case MODEL_RTN12HP:
		case MODEL_RTN12HP_B1:
		{
			eval("et", "robowr", "00", "0x12", "0xf800");
			eval("radio", "off"); /* wireless */
			break;
		}
		case MODEL_RTN10U:
		{
			led_control(LED_WPS, LED_OFF);
			led_control(LED_USB, LED_OFF);
			eval("et", "robowr", "00", "0x12", "0xf800");
			eval("radio", "off"); /* wireless */
			break;
		}
		case MODEL_RTN15U:
		{
			//LAN, WAN Led Off
			led_control(LED_POWER, LED_OFF);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_OFF);
#endif
			led_control(LED_WAN, LED_OFF);
			led_control(LED_USB, LED_OFF);
			eval("radio", "off"); /* wireless */
			break;
		}
		case MODEL_RTN53:
		{
			//LAN, WAN Led Off
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_OFF);
#endif
			led_control(LED_WAN, LED_OFF);
			led_control(LED_2G, LED_OFF);
			led_control(LED_5G, LED_OFF);
			break;
		}
		case MODEL_RTAC53U:
		{
			led_control(LED_POWER, LED_OFF);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_OFF);
#endif
			led_control(LED_WAN, LED_OFF);
			led_control(LED_USB, LED_OFF);
			eval("wl", "-i", "eth1", "ledbh", "3", "0");	// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "9", "0");	// wl 5G
			break;
		}
		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
		{
			eval("et", "robowr", "0", "0x18", "0x01e0");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("wl", "-i", "eth1", "ledbh", "3", "0");	// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "11", "0");	// wl 5G
			led_control(LED_WPS, LED_OFF);
			led_control(LED_USB, LED_OFF);
			break;
		}
	}

	puts("1");
	return 0;
}

#if defined(RTCONFIG_RGBLED)
void start_aurargb(void);
#endif

#if defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_SW_CTRL_ALLLED) || defined(RTAX82U) || defined(DSL_AX82U) || defined(GSAX3000) || defined(GSAX5400) || defined(TUFAX5400) || defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
void setAllLedNormal(void)
{
#ifdef RTCONFIG_BCMWL6
	int wlonunit = -1;

	if (mediabridge_mode())
		wlonunit = nvram_get_int("wlc_band");
#endif
#if defined(RTAX86U) || defined(RTAX68U)
	char productid[16], *wifi_2g, *wifi_5g;
	snprintf(productid, sizeof(productid), "%s", get_productid());
	if(!strcmp(productid, "RT-AX86S") || !strcmp(productid, "RT-AX68U")){
		wifi_2g = "eth5";
		wifi_5g = "eth6";
	} else {
		wifi_2g = "eth6";
		wifi_5g = "eth7";
	}
#endif

#if defined(GTAX11000) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
	char productid[16];
	snprintf(productid, sizeof(productid), "%s", get_productid());
#endif

#if defined(RTCONFIG_RGBLED)
	start_aurargb();
#endif

	led_control(LED_POWER, LED_ON);

#ifdef RTAX58U_V2
	system("rtkswitch 43");
#endif
#ifdef HND_ROUTER
#if defined(TUFAX3000_V2) || defined(RTAXE7800)
	wan_phy_led_pinmux(0);
#endif
	setLANLedOn();
#else
#ifdef RTCONFIG_LAN4WAN_LED
	LanWanLedCtrl();
#endif
	eval("et", "robowr", "0", "0x18", "0x01ff");
	eval("et", "robowr", "0", "0x1a", "0x01ff");
#endif
	kill_pidfile_s("/var/run/wanduck.pid", SIGUSR2);

	if (wlonunit == -1 || wlonunit == 0) {
#if defined(RTAC68U) || defined(DSL_AC68U)
		eval("wl", "ledbh", "10", "7");
#elif defined(RTAC3200)
		eval("wl", "-i", "eth2", "ledbh", "10", "7");
#elif defined(RTAC1200G) || defined(RTAC1200GP)
		eval("wl", "-i", "eth1", "ledbh", "3", "7");
#elif defined(GTAC5300) || defined(GTAXE11000)
		eval("wl", "-i", "eth6", "ledbh", "9", "7");
#elif defined(RTAX88U) || defined(GTAX11000)
		eval("wl", "-i", "eth6", "ledbh", "15", "7");
#elif defined(RTAX92U)
		eval("wl", "-i", "eth5", "ledbh", "10", "7");
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
		eval("wl", "-i", "eth4", "ledbh", "10", "7");
#elif defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
		eval("wl", "-i", "wl0", "ledbh", "10", "7");
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
		eval("wl", "-i", "eth2", "ledbh", "0", "25");
#elif defined(TUFAX3000_V2) || defined(RTAXE7800)
		eval("wl", "-i", "eth5", "ledbh", "0", "25");
#elif defined(GTAX6000)
		eval("wl", "-i", "eth6", "ledbh", "13", "7");
#elif defined(GTAX11000_PRO)
		eval("wl", "-i", "eth6", "ledbh", "13", "7");
#elif defined(GTAXE16000)
		eval("wl", "-i", "eth7", "ledbh", "13", "7");
#elif defined(RTAX82_XD6S)
		eval("wl", "-i", "eth2", "ledbh", "0", "25");
#elif defined(BCM6750)
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
		if (!nvram_get_int("LED_order"))
			eval("wl", "-i", "eth5", "ledbh", "0", "1");
		else
#endif
		eval("wl", "-i", "eth5", "ledbh", "0", "25");
#elif defined(RTAX86U) || defined(RTAX5700)
		eval("wl", "-i", wifi_2g, "ledbh", "7", "7");
#elif defined(RTAX68U)
		eval("wl", "-i", "eth5", "ledbh", "7", "7");
#elif defined(RTAC68U_V4)
		eval("wl", "-i", "eth5", "ledbh", "10", "7");
#elif defined(RTAX56U)
		eval("wl", "-i", "eth5", "ledbh", "0", "25");
#elif defined(RTCONFIG_BCM_7114) || defined(RTAC86U)
		eval("wl", "ledbh", "9", "7");
#elif defined(GTAC2900)
		eval("wl", "ledbh", "9", "1");
#endif
	}
	if (wlonunit == -1 || wlonunit == 1) {
#ifdef RTAC68U
		eval("wl", "-i", "eth2", "ledbh", "10", "7");
#elif defined(DSL_AC68U)
		eval("wl", "-i", "eth2", "ledbh", "10", "7");
		if (nvram_match("wl1_radio", "1")) {
			nvram_set("led_5g", "1");
			led_control(LED_5G, LED_ON);
		}
#elif defined(RTAC3200)
		eval("wl", "ledbh", "10", "7");
#elif defined(RTAC1200G) || defined(RTAC1200GP)
		eval("wl", "-i", "eth2", "ledbh", "11", "7");
#elif defined(GTAC5300) || defined(GTAXE11000)
		eval("wl", "-i", "eth7", "ledbh", "9", "7");
#elif defined(RTAX88U) || defined(GTAX11000)
		eval("wl", "-i", "eth7", "ledbh", "15", "7");
#elif defined(RTAX92U)
		eval("wl", "-i", "eth6", "ledbh", "10", "7");
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
		eval("wl", "-i", "eth5", "ledbh", "10", "7");
#elif defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
		eval("wl", "-i", "wl1", "ledbh", "10", "7");
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
		eval("wl", "-i", "eth3", "ledbh", "0", "25");
#elif defined(TUFAX3000_V2)
		eval("wl", "-i", "eth6", "ledbh", "0", "25");
#elif defined(RTAXE7800)
		eval("wl", "-i", "eth7", "ledbh", "15", "7");
#elif defined(GTAX6000)
		eval("wl", "-i", "eth7", "ledbh", "13", "7");
#elif defined(GTAX11000_PRO)
		eval("wl", "-i", "eth7", "ledbh", "13", "7");
#elif defined(GTAXE16000)
		eval("wl", "-i", "eth8", "ledbh", "13", "7");
#elif defined(RTAX82_XD6S)
		eval("wl", "-i", "eth3", "ledbh", "15", "7");
#elif defined(BCM6750)
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
		if (!nvram_get_int("LED_order")) {
			led_control(LED_5G, LED_ON);
			kill_pidfile_s("/var/run/ledbtn.pid", SIGUSR1);
		} else
#endif
		eval("wl", "-i", "eth6", "ledbh", "15", "7");
#elif defined(RTAX86U) || defined(RTAX5700)
		eval("wl", "-i", wifi_5g, "ledbh", "15", "7");
#elif defined(RTAX68U)
		eval("wl", "-i", "eth6", "ledbh", "7", "7");
#elif defined(RTAC68U_V4)
		eval("wl", "-i", "eth6", "ledbh", "10", "7");
#elif defined(RTAX56U)
		eval("wl", "-i", "eth6", "ledbh", "0", "25");
#elif defined(RTAC86U)
		eval("wl", "-i", "eth6", "ledbh", "9", "7");
#elif defined(GTAC2900)
		eval("wl", "-i", "eth6", "ledbh", "9", "1");
#elif defined(RTCONFIG_BCM_7114)
		eval("wl", "-i", "eth2", "ledbh", "9", "7");
#endif
	}
#ifdef RTCONFIG_HAS_5G_2
	if (wlonunit == -1 || wlonunit == 2) {
#if defined(RTAC3200)
		eval("wl", "-i", "eth3", "ledbh", "10", "7");
#elif defined(GTAC5300) || defined(GTAXE11000)
		eval("wl", "-i", "eth8", "ledbh", "9", "7");
#elif defined(GTAX11000)
		eval("wl", "-i", "eth8", "ledbh", "15", "7");
#elif defined(RTAX92U)
		eval("wl", "-i", "eth7", "ledbh", "15", "7");
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
		eval("wl", "-i", "eth6", "ledbh", "15", "7");
#elif defined(RTAC5300)
		eval("wl", "-i", "eth3", "ledbh", "9", "7");
#elif defined(GTAX11000_PRO)
		eval("wl", "-i", "eth8", "ledbh", "13", "7");
#elif defined(GTAXE16000)
		eval("wl", "-i", "eth9", "ledbh", "13", "7");
#elif defined(RTAXE7800)
		eval("wl", "-i", "eth6", "ledbh", "0", "25");
#endif
	}
#endif
#ifdef RTCONFIG_EXTPHY_BCM84880
#if defined(RTAX86U) || defined(GTAX11000) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
	int ext_phy_model = nvram_get_int("ext_phy_model");

	if(!strcmp(productid, "RT-AX86S")) ;
	else if(ext_phy_model == EXT_PHY_GPY211)
		eval("ethctl", "phy", "ext", EXTPHY_GPY_ADDR_STR, "0x1e0001", "0x3f0");
	else if(ext_phy_model == EXT_PHY_RTL8226)
		eval("ethctl", "phy", "ext", EXTPHY_RTL_ADDR_STR, "0x1fd032", "0x0027");	// RTL LCR2 LED Control Reg
	else if(ext_phy_model == EXT_PHY_BCM54991){
		eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a832", "0x6");	// default. CTL LED3 MASK LOW
		eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a835", "0x40");	// default. CTL LED4 MASK LOW
	}
#endif
#endif
#ifdef RTCONFIG_LOGO_LED
	led_control(LED_LOGO, LED_ON);
#endif
	kill_pidfile_s("/var/run/usbled.pid", SIGTSTP); // inform usbled to reset status
#ifdef DSL_AC68U
	char *dslledcmd_argv[] = {"adslate", "led", "normal", NULL};
	_eval(dslledcmd_argv, NULL, 5, NULL);
#endif
#if defined(RTAX82U) || defined(GSAX3000) || defined(GSAX5400) || defined(TUFAX5400) || defined(GTAX11000_PRO) || defined(GTAXE16000) || defined(GTAX6000)
	if (nvram_default_get("ledg_scheme"))
	nvram_set("ledg_scheme", nvram_default_get("ledg_scheme"));
	kill_pidfile_s("/var/run/ledg.pid", SIGTSTP);
#endif
#ifdef GTAX6000
	AntennaGroupReset(LED_ON);
	setAntennaGroupOn();
	eval("sw", "0xff803140", "0x0000e002", "0x00c34a24", "0x00000a24", "0x00800080");
	eval("sw", "0xff80301c", "0x00040000");
	eval("sw", "0xff803150", "0x0000e002", "0x00c34a24", "0x00000a24", "0x00800080");
	eval("sw", "0xff80301c", "0x00080000");
	eval("sw", "0xff803160", "0x0000e002", "0x00c34a24", "0x00000a24", "0x00800080");
	eval("sw", "0xff80301c", "0x00100000");
	eval("sw", "0xff803170", "0x0000e002", "0x00c34a24", "0x00000a24", "0x00800080");
	eval("sw", "0xff80301c", "0x00200000");
#endif
#if defined(DSL_AX82U)
	start_ledg();
	LEDGroupReset(LED_OFF);
	setLEDGroupOn();
	if (nvram_match("wl0_radio", "0") && nvram_match("wl1_radio", "0"))
		led_control(LED_WIFI, LED_OFF);
	else
		led_control(LED_WIFI, LED_ON);
	led_DSLWAN(1);
#endif
}
#endif

#ifdef RTCONFIG_SW_CTRL_ALLLED
void setAllLedBrightness(void)
{
}
#endif

int
setATEModeLedFail(void) {
	int model;

	model = get_model();

	switch(model) {
#if defined(ET12) || defined(XT12)
		case MODEL_ET12:
		case MODEL_XT12:
		{
			led_control(LED_RGB1_RED, LED_ON);
			led_control(LED_RGB1_GREEN, LED_OFF);
			led_control(LED_RGB1_BLUE, LED_OFF);
			led_control(LED_RGB2_RED, LED_ON);
			led_control(LED_RGB2_GREEN, LED_OFF);
			led_control(LED_RGB2_BLUE, LED_OFF);
			led_control(LED_RGB3_RED, LED_ON);
			led_control(LED_RGB3_GREEN, LED_OFF);
			led_control(LED_RGB3_BLUE, LED_OFF);
			led_control(LED_SIDE1_WHITE, LED_OFF);
			led_control(LED_SIDE2_WHITE, LED_OFF);
			led_control(LED_SIDE3_WHITE, LED_OFF);
			break;
		}
#endif
		default:
			break;
	}
}

int
setATEModeLedOn(void) {
	int model;

	led_control(LED_POWER, LED_ON);
	model = get_model();

	switch(model) {
		case MODEL_RTN16:
		case MODEL_RTN66U:
		{
			/* LAN, WAN Led On */
			eval("et", "robowr", "0", "0x18", "0x01ff");
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			led_control(LED_USB, LED_ON);
			break;
		}
		case MODEL_RTN18U:
		{
			led_control(LED_USB, LED_ON);
			led_control(LED_POWER, LED_ON);
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			break;
		}
		case MODEL_DSLAC68U:
		{
			led_control(LED_USB3, LED_ON);
			led_control(LED_WAN, LED_ON);
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			eval("adslate", "led", "on");
			break;
		}
		case MODEL_RTAC87U:
		{
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			led_control(LED_WPS, LED_ON);
#ifdef RTCONFIG_QTN
			setAllLedOn_qtn();
#endif
			break;
		}
		case MODEL_RTAC68U:
		case MODEL_RTAC3200:
		{
			led_control(LED_WPS, LED_ON);
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
#ifdef RTCONFIG_LOGO_LED
			led_control(LED_LOGO, LED_ON);
#endif
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			break;
		}
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		{
			led_control(LED_RGB1_RED, LED_OFF);
			led_control(LED_RGB1_GREEN, LED_ON);
			led_control(LED_RGB1_BLUE, LED_OFF);
			break;
		}
#endif
#if defined(ET12) || defined(XT12)
		case MODEL_ET12:
		case MODEL_XT12:
		{
			led_control(LED_RGB1_RED, LED_OFF);
			led_control(LED_RGB1_GREEN, LED_ON);
			led_control(LED_RGB1_BLUE, LED_OFF);
			led_control(LED_RGB2_RED, LED_OFF);
			led_control(LED_RGB2_GREEN, LED_ON);
			led_control(LED_RGB2_BLUE, LED_OFF);
			led_control(LED_RGB3_RED, LED_OFF);
			led_control(LED_RGB3_GREEN, LED_ON);
			led_control(LED_RGB3_BLUE, LED_OFF);
			led_control(LED_SIDE1_WHITE, LED_OFF);
			led_control(LED_SIDE2_WHITE, LED_OFF);
			led_control(LED_SIDE3_WHITE, LED_OFF);
			break;
		}
#endif
		case MODEL_RPAX58:
			break;
		case MODEL_RTAC88U:
		case MODEL_RTAC3100:
		case MODEL_RTAC5300:
		case MODEL_RTAC86U:
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAXE7800:
		case MODEL_RTAX55:
		case MODEL_RTAX56U:
		case MODEL_RPAX56:
		case MODEL_RTAX86U:
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		{
#if !defined(RPAX56) && !defined(RPAX58)
			led_control(LED_WPS, LED_ON);
			led_control(LED_WAN, LED_ON);
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
#endif
#ifdef RTAC68U_V4
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
#endif
#ifdef RTAX58U_V2
			system("rtkswitch 42");
#endif
#ifdef HND_ROUTER
#ifdef GTAC2900
			eval("sw", "0x800c00a0", "0");	// disable event on tx/rx activity
#else
#if defined(RTAX58U_V2) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
			wan_phy_led_pinmux(1);
#endif
			led_control(LED_WAN_NORMAL, LED_ON);
			setLANLedOn();
#if defined(RTAX82_XD6) || defined(RTAX82_XD6S)
			bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
#endif
#endif

#ifdef RTCONFIG_EXTPHY_BCM84880
#if defined(RTAX86U) || defined(GTAX11000) || defined(GTAX6000) || defined(TUFAX3000_V2) || defined(RTAXE7800)
			int ext_phy_model = nvram_get_int("ext_phy_model");

			if(strcmp(get_productid(), "RT-AX86S"))
				led_control(LED_EXTPHY, LED_ON);

			if(!strcmp(get_productid(), "RT-AX86S")) ;
			else if(ext_phy_model == EXT_PHY_GPY211)
				eval("ethctl", "phy", "ext", EXTPHY_GPY_ADDR_STR, "0x1e0001", "0xf0");
			else if(ext_phy_model == EXT_PHY_RTL8226)
				eval("ethctl", "phy", "ext", EXTPHY_RTL_ADDR_STR, "0x1fd032", "0x0027");	// RTL LCR2 LED Control Reg
			else
#endif
			{
#if defined(PHY_ID_54991E)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x7fff0", "0x11");	// 2.5G LED (1000M/100M)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a832", "0x21");	// 2.5G LED (2500M)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a83b", "0xa490");
#elif defined(PHY_ID_54991EL) || defined(PHY_ID_50991EL)
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a832", "0x0");	// CTL LED3 MASK LOW
				eval("ethctl", "phy", "ext", EXTPHY_ADDR_STR, "0x1a835", "0xffff");	// CTL LED4 MASK LOW
#endif
			}
#endif
#else // HND_ROUTER
			eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x01e0");
#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_BCM_7114)
			led_control(LED_LAN, LED_ON);
#endif
#endif // HND_ROUTER
#if defined(RTAC5300)
			eval("wl", "ledbh", "9", "1");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "9", "1");	// wl 5G low
			eval("wl", "-i", "eth3", "ledbh", "9", "1");	// wl 5G high
#elif defined(GTAC5300) || defined(GTAXE11000)
			eval("wl", "-i", "eth6", "ledbh", "9", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "9", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "9", "1");	// wl 5G high
#elif defined(GTAX11000)
			eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "15", "1");	// wl 5G high
#elif defined(RTAX88U)
			eval("wl", "-i", "eth6", "ledbh", "9", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "9", "1");	// wl 5G
#elif defined(RTAX92U)
			eval("wl", "-i", "eth5", "ledbh", "10", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "10", "1");	// wl 5G low
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G high
#elif defined(GTAX6000)
			eval("wl", "-i", "eth6", "ledbh", "13", "1");   // wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "13", "1");   // wl 5G low
#elif defined(GTAX11000_PRO)
			eval("wl", "-i", "eth6", "ledbh", "13", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "13", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "13", "1");	// wl 5G high
#elif defined(GTAXE16000)
			eval("wl", "-i", "eth7", "ledbh", "13", "1");	// wl 5G low
			eval("wl", "-i", "eth8", "ledbh", "13", "1");	// wl 5G high
			eval("wl", "-i", "eth9", "ledbh", "13", "1");	// wl 6G
			eval("wl", "-i", "eth10", "ledbh", "13", "1");  // wl 2.4G
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
			eval("wl", "-i", "eth4", "ledbh", "10", "1");	// wl 2.4G
			eval("wl", "-i", "eth5", "ledbh", "10", "1");	// wl 5G low
			eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 5G high
#elif defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
			eval("wl", "-i", "wl0", "ledbh", "10", "1");	// wl 2.4G
			eval("wl", "-i", "wl1", "ledbh", "10", "1");	// wl 5G low
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
			eval("wl", "-i", "eth2", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth3", "ledbh", "0", "1");	// wl 5G
#elif defined(TUFAX3000_V2)
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 5G
#elif defined(RTAXE7800)
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G
			eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 6G
#elif defined(RTAX82_XD6S)
			eval("wl", "-i", "eth2", "ledbh", "0", "1");	// wl 2.4G
#elif defined(BCM6750)
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
			if (!nvram_get_int("LED_order"))
				led_control(LED_5G, LED_ON);
			else
#endif
			eval("wl", "-i", "eth6", "ledbh", "15", "1");   // wl 5G
#elif defined(RTAX56U)
			led_control(LED_WAN, LED_ON);
			led_control(LED_WAN_RED, LED_ON);
			led_control(LED_POWER, LED_ON);
			eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 5G
#elif defined(RPAX56)
			led_control(LED_RED_GPIO, LED_ON);
			led_control(LED_GREEN_GPIO, LED_ON);
			led_control(LED_BLUE_GPIO, LED_ON);
			led_control(LED_WHITE_GPIO, LED_ON);
			led_control(LED_YELLOW_GPIO, LED_ON);
			led_control(LED_PURPLE_GPIO, LED_ON);
			eval("wl", "-i", "eth1", "ledbh", "0", "1");    // wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "0", "1");    // wl 5G
#elif defined(RTAX86U) || defined(RTAX5700)
			if(!strcmp(get_productid(), "RT-AX86S")){
				eval("wl", "-i", "eth5", "ledbh", "7", "1");	// wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 5G
			} else {
				eval("wl", "-i", "eth6", "ledbh", "7", "1");	// wl 2.4G
				eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G
			}
#elif defined(RTAX68U)
			eval("wl", "-i", "eth5", "ledbh", "7", "1");	// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "7", "1");	// wl 5G
#elif defined(RTAC68U_V4)
			eval("wl", "-i", "eth5", "ledbh", "10", "1");    // wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "10", "1");    // wl 5G
#elif defined(RTAC86U) || defined(GTAC2900)
			eval("wl", "ledbh", "9", "1");			// wl 2.4G
			eval("wl", "-i", "eth6", "ledbh", "9", "1");	// wl 5G
#elif defined(RTAC88U) || defined(RTAC3100)
			eval("wl", "ledbh", "9", "1");			// wl 2.4G
			eval("wl", "-i", "eth2", "ledbh", "9", "1");	// wl 5G
#endif
			break;
		}
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
		{
#ifdef RTCONFIG_LED_ALL
			led_control(LED_ALL, LED_ON);
#endif
			led_control(LED_USB, LED_ON);
			led_control(LED_USB3, LED_ON);
			led_control(LED_WAN, LED_ON);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			break;
		}
		case MODEL_RTAC66U:
		{
			/* LAN, WAN Led On */
			eval("et", "robowr", "0", "0x18", "0x01ff");
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			led_control(LED_USB, LED_ON);
			break;
		}
		case MODEL_RTN10P:
		case MODEL_RTN10D1:
		case MODEL_RTN10PV2:
		{
			led_control(LED_WPS, LED_ON);
			break;
		}
		case MODEL_APN12HP:
		{
			led_control(LED_POWER, LED_ON);
			/* convert from shared, boardapi.c */
			led_control(LED_WAN, LED_ON);
			break;
		}
		case MODEL_RTN12B1:
		case MODEL_RTN12C1:
		case MODEL_RTN12D1:
		case MODEL_RTN12VP:
		case MODEL_RTN12HP:
		case MODEL_RTN12HP_B1:
		{
			eval("et", "robowr", "00", "0x12", "0xfd55");
			break;
		}
		case MODEL_RTN10U:
		{
			led_control(LED_WPS, LED_ON);
			led_control(LED_USB, LED_ON);
			eval("et", "robowr", "00", "0x12", "0xfd55");
			break;
		}
		case MODEL_RTN53:
		{
			/* LAN, WAN Led On */
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			led_control(LED_WAN, LED_ON);
			break;
		}
		case MODEL_RTAC53U:
		{
			led_control(LED_POWER, LED_ON);
#ifdef RTCONFIG_LANWAN_LED
			led_control(LED_LAN, LED_ON);
#endif
			led_control(LED_WAN, LED_ON);
			led_control(LED_USB, LED_ON);
			break;
		}
		case MODEL_RTAC1200G:
		case MODEL_RTAC1200GP:
		{
			eval("et", "robowr", "0", "0x18", "0x01ff");	// lan/wan ethernet/giga led
			eval("et", "robowr", "0", "0x1a", "0x01e0");
			led_control(LED_WPS, LED_ON);
			led_control(LED_USB, LED_ON);
			break;
		}
	}

	return 0;
}

#ifdef RTCONFIG_BCMARM
int
setWanLedMode1(void)
{
	int model = get_model();
	switch(model) {
		case MODEL_RTAC68U:
		case MODEL_RTAC87U:
		case MODEL_RTAC3200:
		case MODEL_RTAC88U:
		case MODEL_RTAC3100:
		case MODEL_RTAC5300:
		case MODEL_RTAC86U:
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAXE7800:
		case MODEL_RTAX55:
		case MODEL_RTAX56U:
		case MODEL_RTAX86U:
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
#ifdef RTAC68U
			if (!is_ac66u_v2_series() && !is_ac68u_v3_series())
				goto exit;
#endif
#ifndef HND_ROUTER
			eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x01e0");	// lan/wan ethernet/giga led
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x01e0");
#endif
			led_control(LED_WAN, LED_ON);

#ifdef RTCONFIG_EXTPHY_BCM84880
#ifdef RTAX86U
			if(strcmp(get_productid(), "RT-AX86S"))
				led_control(LED_EXTPHY, LED_ON);
#endif
#endif

			break;
	}
#ifdef RTAC68U
exit:
#endif
	puts("1");
	return 0;
}

int
setWanLedMode2(void)
{
	int model = get_model();
	switch(model) {
		case MODEL_RTAC68U:
		case MODEL_RTAC87U:
		case MODEL_RTAC3200:
		case MODEL_RTAC88U:
		case MODEL_RTAC3100:
		case MODEL_RTAC5300:
		case MODEL_RTAC86U:
		case MODEL_GTAC5300:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAXE7800:
		case MODEL_RTAX55:
		case MODEL_RTAX56U:
		case MODEL_RTAX86U:
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		case MODEL_ET12:
		case MODEL_XT12:
#ifdef RTAC68U
			if (!is_ac66u_v2_series() && !is_ac68u_v3_series())
				goto exit;
#endif
#ifndef HND_ROUTER
			eval("et", "-i", "eth0", "robowr", "0", "0x18", "0x0101");	// lan/wan ethernet/giga led
			eval("et", "-i", "eth0", "robowr", "0", "0x1a", "0x01e0");
#endif
			led_control(LED_WAN, LED_OFF);

#ifdef RTCONFIG_EXTPHY_BCM84880
#ifdef RTAX86U
			if(strcmp(get_productid(), "RT-AX86S"))
				led_control(LED_EXTPHY, LED_OFF);
#endif
#endif

			break;
	}
#ifdef RTAC68U
exit:
#endif
	puts("1");
	return 0;
}
#endif

#ifdef RTCONFIG_FANCTRL
int
setFanOn(void)
{
	led_control(FAN, FAN_ON);
	if (button_pressed(BTN_FAN))
		puts("1");
	else
		puts("ATE_ERROR");
}

int
setFanOff(void)
{
	led_control(FAN, FAN_OFF);
	if (!button_pressed(BTN_FAN))
		puts("1");
	else
		puts("ATE_ERROR");
}
#endif

int
setWiFi2G(const char *act)
{
	if (!strcmp(act, "on"))
		eval("wl", "radio", "on");
	else if (!strcmp(act, "off"))
		eval("wl", "radio", "off");
	else
		return 0;

	puts(act);
	return 1;
}

int
setWiFi5G(const char *act)
{
	if (!strcmp(act, "on"))
		eval("wl", "-i", "eth2", "radio", "on");
	else if (!strcmp(act, "off"))
		eval("wl", "-i", "eth2", "radio", "off");
	else
		return 0;
	puts(act);
	return 1;
}

#define	IW_MAX_FREQUENCIES	32

int Get_channel_list(int unit)
{
	int i, retval = 0;
	int channels[MAXCHANNEL+1];
	wl_uint32_list_t *list = (wl_uint32_list_t *) channels;
	char tmp[TMPBUFSMSIZ];
	char prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	uint ch;
	int len;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	memset(tmp, 0x0, sizeof(tmp));

	memset(channels, 0, sizeof(channels));
	list->count = htod32(MAXCHANNEL);
	if (wl_ioctl(ifname, WLC_GET_VALID_CHANNELS , channels, sizeof(channels)) < 0)
	{
		dbg("error doing WLC_GET_VALID_CHANNELS\n");
		sprintf(tmp, "%d", 0);
		goto ERROR;
	}

	if (dtoh32(list->count) == 0)
	{
		sprintf(tmp, "%d", 0);
		goto ERROR;
	}

	len = strlen(tmp);
	retval = 1;
#ifdef RTCONFIG_WIFI6E
	for (i = 0; i < dtoh32(list->count) && i < MAXCHANNEL; i++)
#else
	for (i = 0; i < dtoh32(list->count) && i < IW_MAX_FREQUENCIES; i++)
#endif
	{
		ch = dtoh32(list->element[i]);

		if (i == 0)
			len = sprintf(tmp, "%d", ch);
		else
			len += sprintf(tmp+len, ", %d", ch);
	}
ERROR:
	puts(tmp);
	return retval;
}

int Get_ChannelList_2G(void)
{
#ifdef GTAXE16000
	return Get_channel_list(3);
#else
	return Get_channel_list(0);
#endif
}

int Get_ChannelList_5G(void)
{
#ifdef GTAXE16000
	return Get_channel_list(0);
#else
	return Get_channel_list(1);
#endif
}

#ifdef RTCONFIG_HAS_5G_2
int Get_ChannelList_5G_2(void)
{
#ifdef GTAXE16000
	return Get_channel_list(1);
#else
	return Get_channel_list(2);
#endif
}
#endif

#ifdef RTCONFIG_WIFI6E
int Get_ChannelList_6G(void)
{
	return Get_channel_list(2);
}
#endif


static const unsigned char WPA_OUT_TYPE[] = { 0x00, 0x50, 0xf2, 1 };

char *wlc_nvname(char *keyword)
{
	return(wl_nvname(keyword, nvram_get_int("wlc_band"), -1));
}

int wpa_key_mgmt_to_bitfield(const unsigned char *s)
{
	if (memcmp(s, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X, WPA_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_IEEE8021X_;
	if (memcmp(s, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X, WPA_SELECTOR_LEN) ==
	    0)
		return WPA_KEY_MGMT_PSK_;
	if (memcmp(s, WPA_AUTH_KEY_MGMT_NONE, WPA_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_WPA_NONE_;
	return 0;
}

int rsn_key_mgmt_to_bitfield(const unsigned char *s)
{
	if (memcmp(s, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X, RSN_SELECTOR_LEN) == 0)
		return WPA_KEY_MGMT_IEEE8021X2_;
	if (memcmp(s, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X, RSN_SELECTOR_LEN) ==
	    0)
		return WPA_KEY_MGMT_PSK2_;
	return 0;
}

int wpa_selector_to_bitfield(const unsigned char *s)
{
	if (memcmp(s, WPA_CIPHER_SUITE_NONE, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_NONE_;
	if (memcmp(s, WPA_CIPHER_SUITE_WEP40, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP40_;
	if (memcmp(s, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_TKIP_;
	if (memcmp(s, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_CCMP_;
	if (memcmp(s, WPA_CIPHER_SUITE_WEP104, WPA_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP104_;
	return 0;
}

int rsn_selector_to_bitfield(const unsigned char *s)
{
	if (memcmp(s, RSN_CIPHER_SUITE_NONE, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_NONE_;
	if (memcmp(s, RSN_CIPHER_SUITE_WEP40, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP40_;
	if (memcmp(s, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_TKIP_;
	if (memcmp(s, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_CCMP_;
	if (memcmp(s, RSN_CIPHER_SUITE_WEP104, RSN_SELECTOR_LEN) == 0)
		return WPA_CIPHER_WEP104_;
	return 0;
}

int wpa_parse_wpa_ie_wpa(const unsigned char *wpa_ie, size_t wpa_ie_len, struct wpa_ie_data *data)
{
	const struct wpa_ie_hdr *hdr;
	const unsigned char *pos;
	int left;
	int i, count;

	data->proto = WPA_PROTO_WPA_;
	data->pairwise_cipher = WPA_CIPHER_TKIP_;
	data->group_cipher = WPA_CIPHER_TKIP_;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X_;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;

	if (wpa_ie_len == 0) {
		/* No WPA IE - fail silently */
		return -1;
	}

	if (wpa_ie_len < sizeof(struct wpa_ie_hdr)) {
//		fprintf(stderr, "ie len too short %lu", (unsigned long) wpa_ie_len);
		return -1;
	}

	hdr = (const struct wpa_ie_hdr *) wpa_ie;

	if (hdr->elem_id != DOT11_MNG_WPA_ID ||
	    hdr->len != wpa_ie_len - 2 ||
	    memcmp(&hdr->oui, WPA_OUI_TYPE_ARR, WPA_SELECTOR_LEN) != 0 ||
	    WPA_GET_LE16(hdr->version) != WPA_VERSION_) {
//		fprintf(stderr, "malformed ie or unknown version");
		return -1;
	}

	pos = (const unsigned char *) (hdr + 1);
	left = wpa_ie_len - sizeof(*hdr);

	if (left >= WPA_SELECTOR_LEN) {
		data->group_cipher = wpa_selector_to_bitfield(pos);
		pos += WPA_SELECTOR_LEN;
		left -= WPA_SELECTOR_LEN;
	} else if (left > 0) {
//		fprintf(stderr, "ie length mismatch, %u too much", left);
		return -1;
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
//			fprintf(stderr, "ie count botch (pairwise), "
//				   "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= wpa_selector_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
//		fprintf(stderr, "ie too short (for key mgmt)");
		return -1;
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
//			fprintf(stderr, "ie count botch (key mgmt), "
//				   "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= wpa_key_mgmt_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
//		fprintf(stderr, "ie too short (for capabilities)");
		return -1;
	}

	if (left >= 2) {
		data->capabilities = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
	}

	if (left > 0) {
//		fprintf(stderr, "ie has %u trailing bytes", left);
		return -1;
	}

	return 0;
}

int wpa_parse_wpa_ie_rsn(const unsigned char *rsn_ie, size_t rsn_ie_len, struct wpa_ie_data *data)
{
	const struct rsn_ie_hdr *hdr;
	const unsigned char *pos;
	int left;
	int i, count;

	data->proto = WPA_PROTO_RSN_;
	data->pairwise_cipher = WPA_CIPHER_CCMP_;
	data->group_cipher = WPA_CIPHER_CCMP_;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X2_;
	data->capabilities = 0;
	data->pmkid = NULL;
	data->num_pmkid = 0;

	if (rsn_ie_len == 0) {
		/* No RSN IE - fail silently */
		return -1;
	}

	if (rsn_ie_len < sizeof(struct rsn_ie_hdr)) {
//		fprintf(stderr, "ie len too short %lu", (unsigned long) rsn_ie_len);
		return -1;
	}

	hdr = (const struct rsn_ie_hdr *) rsn_ie;

	if (hdr->elem_id != DOT11_MNG_RSN_ID ||
	    hdr->len != rsn_ie_len - 2 ||
	    WPA_GET_LE16(hdr->version) != RSN_VERSION_) {
//		fprintf(stderr, "malformed ie or unknown version");
		return -1;
	}

	pos = (const unsigned char *) (hdr + 1);
	left = rsn_ie_len - sizeof(*hdr);

	if (left >= RSN_SELECTOR_LEN) {
		data->group_cipher = rsn_selector_to_bitfield(pos);
		pos += RSN_SELECTOR_LEN;
		left -= RSN_SELECTOR_LEN;
	} else if (left > 0) {
//		fprintf(stderr, "ie length mismatch, %u too much", left);
		return -1;
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
//			fprintf(stderr, "ie count botch (pairwise), "
//				   "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
//		fprintf(stderr, "ie too short (for key mgmt)");
		return -1;
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
//			fprintf(stderr, "ie count botch (key mgmt), "
//				   "count %u left %u", count, left);
			return -1;
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= rsn_key_mgmt_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
//		fprintf(stderr, "ie too short (for capabilities)");
		return -1;
	}

	if (left >= 2) {
		data->capabilities = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
	}

	if (left >= 2) {
		data->num_pmkid = WPA_GET_LE16(pos);
		pos += 2;
		left -= 2;
		if (left < data->num_pmkid * PMKID_LEN) {
//			fprintf(stderr, "PMKID underflow "
//				   "(num_pmkid=%d left=%d)", data->num_pmkid, left);
			data->num_pmkid = 0;
		} else {
			data->pmkid = pos;
			pos += data->num_pmkid * PMKID_LEN;
			left -= data->num_pmkid * PMKID_LEN;
		}
	}

	if (left > 0) {
//		fprintf(stderr, "ie has %u trailing bytes - ignored", left);
	}

	return 0;
}

int wpa_parse_wpa_ie(const unsigned char *wpa_ie, size_t wpa_ie_len,
		     struct wpa_ie_data *data)
{
	if (wpa_ie_len >= 1 && wpa_ie[0] == DOT11_MNG_RSN_ID)
		return wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
	else
		return wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, data);
}

static const char * wpa_key_mgmt_txt(int key_mgmt, int proto)
{
	switch (key_mgmt) {
	case WPA_KEY_MGMT_IEEE8021X_:
/*
		return proto == WPA_PROTO_RSN_ ?
			"WPA2/IEEE 802.1X/EAP" : "WPA/IEEE 802.1X/EAP";
*/
		return "WPA-Enterprise";
	case WPA_KEY_MGMT_IEEE8021X2_:
		return "WPA2-Enterprise";
	case WPA_KEY_MGMT_PSK_:
/*
		return proto == WPA_PROTO_RSN_ ?
			"WPA2-PSK" : "WPA-PSK";
*/
		return "WPA-Personal";
	case WPA_KEY_MGMT_PSK2_:
		return "WPA2-Personal";
	case WPA_KEY_MGMT_NONE_:
		return "NONE";
	case WPA_KEY_MGMT_IEEE8021X_NO_WPA_:
//		return "IEEE 802.1X (no WPA)";
		return "IEEE 802.1X";
	default:
		return "Unknown";
	}
}

static const char * wpa_cipher_txt(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_NONE_:
		return "NONE";
	case WPA_CIPHER_WEP40_:
		return "WEP-40";
	case WPA_CIPHER_WEP104_:
		return "WEP-104";
	case WPA_CIPHER_TKIP_:
		return "TKIP";
	case WPA_CIPHER_CCMP_:
//		return "CCMP";
		return "AES";
	case (WPA_CIPHER_TKIP_|WPA_CIPHER_CCMP_):
		return "TKIP+AES";
	default:
		return "Unknown";
	}
}

char buf[WLC_IOCTL_MAXLEN];

int
wl_control_channel(int unit)
{
	int ret;
	struct ether_addr bssid;
	wl_bss_info_t *bi;
	wl_bss_info_107_t *old_bi;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
#ifdef RTCONFIG_QTN
	qcsapi_unsigned_int channel;
#endif

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	if ((ret = wl_ioctl(ifname, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN)) == 0) {
		/* The adapter is associated. */
		*(uint32*)buf = htod32(WLC_IOCTL_MAXLEN);
		if ((ret = wl_ioctl(ifname, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN)) < 0)
			return 0;

		bi = (wl_bss_info_t*)(buf + 4);
		if (dtoh32(bi->version) == WL_BSS_INFO_VERSION ||
		    dtoh32(bi->version) == LEGACY2_WL_BSS_INFO_VERSION ||
		    dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION)
		{
			/* Convert version 107 to 109 */
			if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
				old_bi = (wl_bss_info_107_t *)bi;
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
				bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel, WL_CHANNEL_2G5G_BAND(old_bi->channel));
#else
				bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
#endif
				bi->ie_length = old_bi->ie_length;
				bi->ie_offset = sizeof(wl_bss_info_107_t);
			}

			if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap)
				return bi->ctl_ch;
			else
				return (bi->chanspec & WL_CHANSPEC_CHAN_MASK);
		}
	}

#ifdef RTCONFIG_QTN
	ret = rpc_qcsapi_get_channel(&channel);
	if (ret < 0) return 0;
	else return channel;
#else
	return 0;
#endif
}

#ifdef RTCONFIG_HND_ROUTER_AX
/* Is this body of this tlvs entry a WPA entry? If */
/* not update the tlvs buffer pointer/length */
static bool
wlu_is_wpa_ie(uint8 **wpaie, uint8 **tlvs, uint *tlvs_len)
{
	uint8 *ie = *wpaie;

	/* If the contents match the WPA_OUI and type=1 */
	if ((ie[1] >= 6) && !memcmp(&ie[2], WPA_OUI "\x01", 4)) {
		return TRUE;
	}

	/* point to the next ie */
	ie += ie[1] + 2;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return FALSE;
}

/*
 * Traverse a string of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches tag
 */
static uint8 *
wlu_parse_tlvs(uint8 *tlv_buf, int buflen, uint key)
{
	uint8 *cp;
	int totlen;

	cp = tlv_buf;
	totlen = buflen;

	/* find tagged parameter */
	while (totlen >= 2) {
		uint tag;
		int len;

		tag = *cp;
		len = *(cp +1);

		/* validate remaining totlen */
		if ((tag == key) && (totlen >= (len + 2)))
			return (cp);

		cp += (len + 2);
		totlen -= (len + 2);
	}

	return NULL;
}

/* Validates and parses the RSN or WPA IE contents into a rsn_parse_info_t structure
 * Returns 0 on success, or 1 if the information in the buffer is not consistant with
 * an RSN IE or WPA IE.
 * The buf pointer passed in should be pointing at the version field in either an RSN IE
 * or WPA IE.
 */
static int
wl_rsn_ie_parse_info(uint8* rsn_buf, uint len, struct apinfo *info, int rsn)
{
	rsn_parse_info_t *rsn_info = &info->rsn_info;
	struct wpa_ie_data *data = &info->wid;
	uint16 count;
	uint8 std_oui[3];
	int i;
	wpa_suite_t *suite;

	memset(rsn_info, 0, sizeof(rsn_parse_info_t));

	if (rsn)
		memcpy(std_oui, WPA2_OUI, WPA_OUI_LEN);
	else
		memcpy(std_oui, WPA_OUI, WPA_OUI_LEN);

	/* version */
	if (len < sizeof(uint16))
		return 1;

	rsn_info->version = ltoh16_ua(rsn_buf);
	len -= sizeof(uint16);
	rsn_buf += sizeof(uint16);

	/* Multicast Suite */
	if (len < sizeof(wpa_suite_mcast_t))
		return 0;

	rsn_info->mcast = (wpa_suite_mcast_t*)rsn_buf;
	len -= sizeof(wpa_suite_mcast_t);
	rsn_buf += sizeof(wpa_suite_mcast_t);

	/* Unicast Suite */
	if (len < sizeof(uint16))
		return 0;

	count = ltoh16_ua(rsn_buf);

	if (len < (sizeof(uint16) + count * sizeof(wpa_suite_t)))
		return 1;

	rsn_info->ucast = (wpa_suite_ucast_t*)rsn_buf;

	data->pairwise_cipher = 0;
	for (i = 0; i < count; i++) {
		suite = &rsn_info->ucast->list[i];
		if (!memcmp(suite->oui, std_oui, 3)) {
			switch (suite->type) {
			case WPA_CIPHER_NONE:
				data->pairwise_cipher |= _WPA_CIPHER_NONE_;
				break;
			case WPA_CIPHER_WEP_40:
				data->pairwise_cipher |= _WPA_CIPHER_WEP_40_;
				break;
			case WPA_CIPHER_WEP_104:
				data->pairwise_cipher |= _WPA_CIPHER_WEP_104_;
				break;
			case WPA_CIPHER_TKIP:
				data->pairwise_cipher |= _WPA_CIPHER_TKIP_;
				break;
			case WPA_CIPHER_AES_CCM:
				data->pairwise_cipher |= _WPA_CIPHER_AES_CCM_;
				break;
			}
		}
	}

	len -= (sizeof(uint16) + count * sizeof(wpa_suite_t));
	rsn_buf += (sizeof(uint16) + count * sizeof(wpa_suite_t));

	/* AKM Suite */
	if (len < sizeof(uint16))
		return 0;

	count = ltoh16_ua(rsn_buf);

	if (len < (sizeof(uint16) + count * sizeof(wpa_suite_t)))
		return 1;

	rsn_info->akm = (wpa_suite_auth_key_mgmt_t*)rsn_buf;

	data->key_mgmt = 0;
	for (i = 0; i < count; i++) {
		suite = &rsn_info->akm->list[i];
		if (!memcmp(suite->oui, std_oui, 3)) {
			switch (suite->type) {
			case RSN_AKM_UNSPECIFIED:
				data->key_mgmt |= _RSN_AKM_UNSPECIFIED_;
				break;
			case RSN_AKM_PSK:
				data->key_mgmt |= _RSN_AKM_PSK_;
				break;
			case RSN_AKM_SHA256_1X:
				data->key_mgmt |= _RSN_AKM_SHA256_1X_;
				break;
			case RSN_AKM_SHA256_PSK:
				data->key_mgmt |= _RSN_AKM_SHA256_PSK_;
				break;
			case RSN_AKM_SAE_PSK:
				data->key_mgmt |= _RSN_AKM_SAE_PSK_;
				break;
#ifdef RTCONFIG_WIFI6E
			case RSN_AKM_OWE:
				data->key_mgmt |= _RSN_AKM_OWE_;
				break;
#endif
			}
		}
	}

	len -= (sizeof(uint16) + count * sizeof(wpa_suite_t));
	rsn_buf += (sizeof(uint16) + count * sizeof(wpa_suite_t));

	/* Capabilites */
	if (len < sizeof(uint16))
		return 0;

	rsn_info->capabilities = rsn_buf;

	if (rsn)
		data->proto = WPA_PROTO_RSN_;
	else
		data->proto = WPA_PROTO_WPA_;

	return 0;
}

static uint
wl_rsn_ie_decode_cntrs(uint cntr_field)
{
	uint cntrs;

	switch (cntr_field) {
	case RSN_CAP_1_REPLAY_CNTR:
		cntrs = 1;
		break;
	case RSN_CAP_2_REPLAY_CNTRS:
		cntrs = 2;
		break;
	case RSN_CAP_4_REPLAY_CNTRS:
		cntrs = 4;
		break;
	case RSN_CAP_16_REPLAY_CNTRS:
		cntrs = 16;
		break;
	default:
		cntrs = 0;
		break;
	}

	return cntrs;
}

static int
wl_rsn_ie_parse(bcm_tlv_t *ie, struct apinfo *info)
{
	rsn_parse_info_t *rsn_info = &info->rsn_info;
	wpa_ie_fixed_t *wpa = NULL;
	int err;

	if (ie->id == DOT11_MNG_RSN_ID) {
		err = wl_rsn_ie_parse_info(ie->data, ie->len, info, 1);
	} else {
		wpa = (wpa_ie_fixed_t*)ie;
		err = wl_rsn_ie_parse_info((uint8*)&wpa->version, wpa->length - WPA_IE_OUITYPE_LEN,
		                           info, 0);
	}

	if (err || rsn_info->version != WPA_VERSION)
		return -1;

	info->wpa = 1;

	return 0;
}

static void
wl_rsn_ie_dump(rsn_parse_info_t *rsn_info, int rsn)
{
	int i;
	wpa_suite_t *suite;
	uint8 std_oui[3];
	int unicast_count = 0;
	int akm_count = 0;
	uint16 capabilities;
	uint cntrs;

	if (!nvram_get_int("debug_wl"))
		return;

	if (rsn)
		memcpy(std_oui, WPA2_OUI, WPA_OUI_LEN);
	else
		memcpy(std_oui, WPA_OUI, WPA_OUI_LEN);

	if (rsn)
		printf("RSN (WPA2):\n");
	else
		printf("WPA:\n");

	/* Check for multicast suite */
	if (rsn_info->mcast) {
		printf("\tmulticast cipher: ");
		if (!memcmp(rsn_info->mcast->oui, std_oui, 3)) {
			switch (rsn_info->mcast->type) {
			case WPA_CIPHER_NONE:
				printf("NONE\n");
				break;
			case WPA_CIPHER_WEP_40:
				printf("WEP64\n");
				break;
			case WPA_CIPHER_WEP_104:
				printf("WEP128\n");
				break;
			case WPA_CIPHER_TKIP:
				printf("TKIP\n");
				break;
			case WPA_CIPHER_AES_OCB:
				printf("AES-OCB\n");
				break;
			case WPA_CIPHER_AES_CCM:
				printf("AES-CCMP\n");
				break;
			case WPA_CIPHER_AES_GCM:
				printf("AES-GCMP\n");
				break;
			case WPA_CIPHER_AES_GCM256:
				printf("AES-GCMP256\n");
				break;
			default:
				printf("Unknown-%s(#%d)\n", rsn ? "RSN" : "WPA",
				       rsn_info->mcast->type);
				break;
			}
		}
		else {
			printf("Unknown-%02X:%02X:%02X(#%d) ",
			       rsn_info->mcast->oui[0], rsn_info->mcast->oui[1],
			       rsn_info->mcast->oui[2], rsn_info->mcast->type);
		}
	}

	/* Check for unicast suite(s) */
	if (rsn_info->ucast) {
		unicast_count = ltoh16_ua(&rsn_info->ucast->count);
		printf("\tunicast ciphers(%d): ", unicast_count);
		for (i = 0; i < unicast_count; i++) {
			suite = &rsn_info->ucast->list[i];
			if (!memcmp(suite->oui, std_oui, 3)) {
				switch (suite->type) {
				case WPA_CIPHER_NONE:
					printf("NONE ");
					break;
				case WPA_CIPHER_WEP_40:
					printf("WEP64 ");
					break;
				case WPA_CIPHER_WEP_104:
					printf("WEP128 ");
					break;
				case WPA_CIPHER_TKIP:
					printf("TKIP ");
					break;
				case WPA_CIPHER_AES_OCB:
					printf("AES-OCB ");
					break;
				case WPA_CIPHER_AES_CCM:
					printf("AES-CCMP ");
					break;
				case WPA_CIPHER_AES_GCM:
					printf("AES-GCMP ");
					break;
				case WPA_CIPHER_AES_GCM256:
					printf("AES-GCMP256 ");
					break;
				default:
					printf("WPA-Unknown-%s(#%d) ", rsn ? "RSN" : "WPA",
					       suite->type);
					break;
				}
			}
			else {
				printf("Unknown-%02X:%02X:%02X(#%d) ",
					suite->oui[0], suite->oui[1], suite->oui[2],
					suite->type);
			}
		}
		printf("\n");
	}
	/* Authentication Key Management */
	if (rsn_info->akm) {
		akm_count = ltoh16_ua(&rsn_info->akm->count);
		printf("\tAKM Suites(%d): ", akm_count);
		for (i = 0; i < akm_count; i++) {
			suite = &rsn_info->akm->list[i];
			if (!memcmp(suite->oui, std_oui, 3)) {
				switch (suite->type) {
				case RSN_AKM_NONE:
					printf("None ");
					break;
				case RSN_AKM_UNSPECIFIED:
					printf("%s ", rsn ? "WPA2" : "WPA");
					break;
				case RSN_AKM_PSK:
					printf("%s ", rsn ? "WPA2-PSK" : "WPA-PSK");
					break;
				case RSN_AKM_FBT_1X:
					printf("FT-802.1x ");
					break;
				case RSN_AKM_FBT_PSK:
					printf("FT-PSK ");
					break;
				case RSN_AKM_SHA256_PSK:
					printf("WPA2-PSK ");
					break;
				case RSN_AKM_SAE_PSK:
					printf("SAE ");
					break;
				case RSN_AKM_SAE_FBT:
					printf("SAE-FT ");
					break;
#ifdef RTCONFIG_WIFI6E
				case RSN_AKM_OWE:
					printf("OWE ");
					break;
#endif
				default:
					printf("Unknown-%s(#%d)  ",
					       rsn ? "RSN" : "WPA", suite->type);
					break;
				}
			}
			else {
				printf("Unknown-%02X:%02X:%02X(#%d)  ",
					suite->oui[0], suite->oui[1], suite->oui[2],
					suite->type);
			}
		}
		printf("\n");
	}

	/* Capabilities */
	if (rsn_info->capabilities) {
		capabilities = ltoh16_ua(rsn_info->capabilities);
		printf("\tCapabilities(0x%04x): ", capabilities);
		if (rsn)
			printf("%sPre-Auth, ", (capabilities & RSN_CAP_PREAUTH) ? "" : "No ");

		printf("%sPairwise, ", (capabilities & RSN_CAP_NOPAIRWISE) ? "No " : "");

		cntrs = wl_rsn_ie_decode_cntrs((capabilities & RSN_CAP_PTK_REPLAY_CNTR_MASK) >>
		                               RSN_CAP_PTK_REPLAY_CNTR_SHIFT);

		printf("%d PTK Replay Ctr%s", cntrs, (cntrs > 1)?"s":"");

		if (rsn) {
			cntrs = wl_rsn_ie_decode_cntrs(
				(capabilities & RSN_CAP_GTK_REPLAY_CNTR_MASK) >>
				RSN_CAP_GTK_REPLAY_CNTR_SHIFT);

			printf("%d GTK Replay Ctr%s, ", cntrs, (cntrs > 1)?"s":"");
			printf("MFP: %s\n", (capabilities & (RSN_CAP_MFPR | RSN_CAP_MFPC)) ?
					((capabilities & RSN_CAP_MFPR) ? "Required" : "Capable"): "Disabled");
		} else {
			printf("\n");
		}
	} else {
		printf("\tNo %s Capabilities advertised\n", rsn ? "RSN" : "WPA");
	}

}

static const char *wpa_unicast_txt(int cipher)
{
	static char buf[32];

	switch (cipher) {
	case _WPA_CIPHER_NONE_:
		return "NONE";
	case _WPA_CIPHER_WEP_40_:
		return "WEP64";
	case _WPA_CIPHER_WEP_104_:
		return "WEP128";
	case _WPA_CIPHER_TKIP_:
		return "TKIP";
	case _WPA_CIPHER_AES_CCM_:
		return "AES";
	case (_WPA_CIPHER_TKIP_ | _WPA_CIPHER_AES_CCM_):
		return "TKIP+AES";
	default:
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "Unknown (%x)", cipher);
		return buf;
	}
}

static const char * wpa_akm_txt(int akm, int proto)
{
	static char buf[32];

	switch (akm) {
	case _RSN_AKM_UNSPECIFIED_:
	case _RSN_AKM_SHA256_1X_:
		return ((proto == WPA_PROTO_RSN_) ? "WPA2" : "WPA");
	case _RSN_AKM_PSK_:
		return ((proto == WPA_PROTO_RSN_) ? "WPA2-PSK" : "WPA-PSK");
	case _RSN_AKM_SHA256_PSK_:
		return "WPA2-PSK";
	case _RSN_AKM_SAE_PSK_:
	case (_RSN_AKM_PSK_ | _RSN_AKM_SAE_PSK_):
		return "WPA3-PSK";
	case _RSN_AKM_OWE_:
		return "OWE";
	default:
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "Unknown (%x %x)", akm, proto);
		return buf;
	}
}

static void
wl_dump_wpa_rsn_ies(uint8* cp, uint len, struct apinfo *info)
{
	uint8 *parse = cp;
	uint parse_len = len;
	uint8 *wpaie = NULL;
	uint8 *rsnie = NULL;

	while ((wpaie = wlu_parse_tlvs(parse, parse_len, DOT11_MNG_WPA_ID)))
		if (wlu_is_wpa_ie(&wpaie, &parse, &parse_len))
			break;

	rsnie = wlu_parse_tlvs(cp, len, DOT11_MNG_RSN_ID);

	if (rsnie && !wl_rsn_ie_parse((bcm_tlv_t*)rsnie, info))
	{
		wl_rsn_ie_dump(&info->rsn_info, 1);
	}
	else if (wpaie && !wl_rsn_ie_parse((bcm_tlv_t*)wpaie, info))
	{
		wl_rsn_ie_dump(&info->rsn_info, 0);
	}

	return;
}
#endif

static char scan_result[WLC_SCAN_RESULT_BUF_LEN];

int wlcscan_core(char *ofile, char *wif)
{
	int ret, i, k, left, ht_extcha, ctl_ch;
	int retval = 0, ap_count = 0, idx_same = -1, count, unit = -1;
	unsigned char rate;
	unsigned char bssid[6];
	unsigned char bssid_null[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	char macstr[18];
	char ure_mac[18];
	char ssid_str[256];
	wl_scan_results_t *result;
	wl_bss_info_t *info;
	wl_bss_info_107_t *old_info;
#ifdef RTCONFIG_HND_ROUTER_AX
	wl_bss_info_v109_1_t *new_info;
#endif
	struct bss_ie_hdr *ie;
	NDIS_802_11_NETWORK_TYPE NetWorkType;
	struct maclist *authorized;
	int maclist_size;
	int max_sta_count = 128;
	int wl_authorized = 0;
	wl_scan_params_t *params;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + NUMCHANS * sizeof(uint16);
	FILE *fp;
	int org_scan_time = 20, scan_time = 40;
	int wait_time = 3;
	char tmp[256], prefix[] = "wlXXXXXXXXXX_";
#ifdef RTCONFIG_AMAS
	struct vndr_ie *ie_vs;
	struct tlvbase *tlv;
	int left2;
	int match_1, match_2, match_3, match_7;
#endif
	char chanbuf[CHANSPEC_STR_LEN];
#ifdef RTCONFIG_BCMWL6
	chanspec_t chspec_cur = 0;
#endif
	chanspec_t chanspec = 0;
	chanspec_t chspec_tmp = 0;
#ifndef RTCONFIG_HND_ROUTER_AX
	int ctl_ch_tmp;
#endif
#if defined(RTCONFIG_DHDAP) && !defined(RTCONFIG_BCM7)
	chanspec_t chspec_tar = 0;
	char buf_sm[WLC_IOCTL_SMLEN];
	wl_dfs_ap_move_status_t *status = (wl_dfs_ap_move_status_t*) buf_sm;
#endif
#ifdef __CONFIG_DHDAP__
	int is_dhd = !dhd_probe(wif);
#endif

	if (wl_ioctl(wif, WLC_GET_INSTANCE, &unit, sizeof(unit)))
		return retval;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ctl_ch = wl_control_channel(unit);
#ifdef RTCONFIG_BCMWL6
	if (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") && !is_psta(unit)) {
		if (wl_iovar_get(wif, "chanspec", &chspec_cur, sizeof(chanspec_t)) < 0) {
			dbg("get current chanpsec failed\n");
			return retval;
		}

		if (((ctl_ch > 48) && (ctl_ch < 149))
#ifdef RTCONFIG_BW160M
			|| ((ctl_ch <= 48) && CHSPEC_IS160(chspec_cur))
#endif
		) {
			if (!with_non_dfs_chspec(wif))
			{
				dbg("%s scan rejected under DFS mode\n", wif);
				return retval;
			}
			else
			{
				dbg("current chanspec: %s (0x%x)\n", wf_chspec_ntoa(chspec_cur, chanbuf), chspec_cur);

				chspec_tmp = (((nvram_get_hex(strcat_r(prefix, "band5grp", tmp)) & WL_5G_BAND_4) && (ctl_ch < 100)) ? select_chspec_with_band_bw(wif, 4, 3, chspec_cur) : select_chspec_with_band_bw(wif, 1, 3, chspec_cur));
				if (!chspec_tmp && (nvram_get_hex(strcat_r(prefix, "band5grp", tmp)) & WL_5G_BAND_4))
					chspec_tmp = select_chspec_with_band_bw(wif, 4, 3, chspec_cur);

				if (chspec_tmp != 0) {
					dbg("switch to chanspec: %s (0x%x)\n", wf_chspec_ntoa(chspec_tmp, chanbuf), chspec_tmp);
					wl_iovar_setint(wif, "chanspec", chspec_tmp);
					wl_iovar_setint(wif, "acs_update", -1);

					chanspec = chspec_cur;
				}
			}
		}
#if defined(RTCONFIG_DHDAP) && !defined(RTCONFIG_BCM7)
		else if (wl_cap(unit, "bgdfs")) {
			if (wl_iovar_get(wif, "dfs_ap_move", &buf_sm[0], WLC_IOCTL_SMLEN) < 0) {
				dbg("get dfs_ap_move status failure\n");
				return retval;
			}

			if (status->version != WL_DFS_AP_MOVE_VERSION)
				return retval;

			if (status->move_status != (int8) DFS_SCAN_S_IDLE) {
				chspec_tar = status->chanspec;
				if (chspec_tar != 0 && chspec_tar != INVCHANSPEC) {
					chanspec = chspec_tar;
					wf_chspec_ntoa(chspec_tar, chanbuf);
					dbg("AP Target Chanspec %s (0x%x)\n", chanbuf, chspec_tar);
				}

				if (status->move_status == (int8) DFS_SCAN_S_INPROGESS)
					wl_iovar_setint(wif, "dfs_ap_move", -1);
			}
		}
#endif
	}
#endif

	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL)
		return retval;

	memset(params, 0, params_size);
	params->bss_type = DOT11_BSSTYPE_INFRASTRUCTURE;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") && !is_psta(unit)) ? WL_SCANFLAGS_PASSIVE : 0;
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
#ifdef __CONFIG_DHDAP__
	if (is_dhd) {
		int band = WLC_BAND_ALL;
		wl_ioctl(wif, WLC_GET_BAND, &band, sizeof(band));
#ifdef RTCONFIG_WIFI6E
		if (band == WLC_BAND_6G) {
		}
		else
#endif
		if (band == WLC_BAND_5G)
		{
			if (wl_subband(wif, nvram_get_int("wlcscan_idx")+1) == 1)
			{
				params->channel_num = 4;
				params->channel_list[0] = 36;
				params->channel_list[1] = 40;
				params->channel_list[2] = 44;
				params->channel_list[3] = 48;
			}
			else if (wl_subband(wif, nvram_get_int("wlcscan_idx")+1) == 2)
			{
				params->channel_num = 4;
				params->channel_list[0] = 52;
				params->channel_list[1] = 56;
				params->channel_list[2] = 60;
				params->channel_list[3] = 64;
				}
			else if (wl_subband(wif, nvram_get_int("wlcscan_idx")+1) == 3)
			{
				if (wl_channel_valid(wif, 120))
				{
					params->channel_num = 11;
					params->channel_list[0] = 100;
					params->channel_list[1] = 104;
					params->channel_list[2] = 108;
					params->channel_list[3] = 112;
					params->channel_list[4] = 116;
					params->channel_list[5] = 120;
					params->channel_list[6] = 124;
					params->channel_list[7] = 128;
					params->channel_list[8] = 132;
					params->channel_list[9] = 136;
					params->channel_list[10] = 140;
				}
				else
				{
					params->channel_num = 8;
					params->channel_list[0] = 100;
					params->channel_list[1] = 104;
					params->channel_list[2] = 108;
					params->channel_list[3] = 112;
					params->channel_list[4] = 116;
					params->channel_list[5] = 132;
					params->channel_list[6] = 136;
					params->channel_list[7] = 140;
				}
			}
			else if (wl_subband(wif, nvram_get_int("wlcscan_idx")+1) == 4)
			{
				params->channel_num = 5;
				params->channel_list[0] = 165;
				params->channel_list[1] = 161;
				params->channel_list[2] = 157;
				params->channel_list[3] = 153;
				params->channel_list[4] = 149;
			}
			else
			{
				free(params);
				return retval;
			}
		}
		else
		{
			if (nvram_get_int("wlcscan_idx") == 0)
			{
				params->channel_num = 6;
				params->channel_list[0] = 1;
				params->channel_list[1] = 2;
				params->channel_list[2] = 3;
				params->channel_list[3] = 4;
				params->channel_list[4] = 5;
				params->channel_list[5] = 6;
			}
			else if (nvram_get_int("wlcscan_idx") == 1)
			{
				if (wl_channel_valid(wif, 13))
				{
					params->channel_num = 7;
					params->channel_list[0] = 7;
					params->channel_list[1] = 8;
					params->channel_list[2] = 9;
					params->channel_list[3] = 10;
					params->channel_list[4] = 11;
					params->channel_list[5] = 12;
					params->channel_list[6] = 13;
				}
				else
				{
					params->channel_num = 5;
					params->channel_list[0] = 7;
					params->channel_list[1] = 8;
					params->channel_list[2] = 9;
					params->channel_list[3] = 10;
					params->channel_list[4] = 11;
				}
			}
			else
			{
				free(params);
				return retval;
			}
		}
	} else
#endif
	params->channel_num = 0;

	/* extend scan channel time to get more AP probe resp */
	wl_ioctl(wif, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
	if (org_scan_time < scan_time)
		wl_ioctl(wif, WLC_SET_SCAN_CHANNEL_TIME, &scan_time, sizeof(scan_time));

	count = 0;
	while ((ret = wl_ioctl(wif, WLC_SCAN, params, params_size)) < 0 &&
		count++ < 2) {
		dbg("[rc] set scan command failed, retry %d\n", count);
		sleep(1);
	}

	free(params);

	/* restore original scan channel time */
	wl_ioctl(wif, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));

#ifdef __CONFIG_DHDAP__
	wait_time = 2;
#endif
	dbg("[rc] Please wait %d seconds ", wait_time);
	do {
		sleep(1);
		dbg(".");
	} while (--wait_time > 0);
	dbg("\n\n");

	if (ret == 0) {
		result = (wl_scan_results_t *)scan_result;
		result->buflen = htod32(WLC_SCAN_RESULT_BUF_LEN);

		count = 0;
		while ((ret = wl_ioctl(wif, WLC_SCAN_RESULTS, result, WLC_SCAN_RESULT_BUF_LEN)) < 0 && count++ < 2)
		{
			dbg("[rc] set scan results command failed, retry %d\n", count);
			sleep(1);
		}

		if (ret == 0)
		{
			info = &(result->bss_info[0]);
#ifdef RTCONFIG_HND_ROUTER_AX
			new_info = (wl_bss_info_v109_1_t *)&(result->bss_info[0]);
#endif

			/* Convert version 107 to 109 */
			if (dtoh32(info->version) == LEGACY_WL_BSS_INFO_VERSION) {
				old_info = (wl_bss_info_107_t *)info;
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
				info->chanspec = CH20MHZ_CHSPEC(old_info->channel, WL_CHANNEL_2G5G_BAND(old_info->channel));
#else
				info->chanspec = CH20MHZ_CHSPEC(old_info->channel);
#endif
				info->ie_length = old_info->ie_length;
				info->ie_offset = sizeof(wl_bss_info_107_t);
			}

			for (i = 0; i < result->count; i++)
			{
				if (info->SSID_len > 32/* || info->SSID_len == 0*/)
					goto next_info;

				ether_etoa((const unsigned char *) &info->BSSID, macstr);

				idx_same = -1;
				for (k = 0; k < ap_count; k++) {
					/* deal with old version of Broadcom Multiple SSID
						(share the same BSSID) */
					if (strcmp(apinfos[k].BSSID, macstr) == 0 &&
						strcmp(apinfos[k].SSID, (const char *) info->SSID) == 0) {
						idx_same = k;
						break;
					}
				}

				if (idx_same != -1)
				{
					if (info->RSSI >= -50)
						apinfos[idx_same].RSSI_Quality = 100;
					else if (info->RSSI >= -80)	// between -50 ~ -80dbm
						apinfos[idx_same].RSSI_Quality = (int)(24 + ((info->RSSI + 80) * 26)/10);
					else if (info->RSSI >= -90)	// between -80 ~ -90dbm
						apinfos[idx_same].RSSI_Quality = (int)(((info->RSSI + 90) * 26)/10);
					else					// < -84 dbm
						apinfos[idx_same].RSSI_Quality = 0;
				}
				else
				{
					strcpy(apinfos[ap_count].BSSID, macstr);
//					strcpy(apinfos[ap_count].SSID, info->SSID);
					memset(apinfos[ap_count].SSID, 0x0, 33);
					memcpy(apinfos[ap_count].SSID, info->SSID, info->SSID_len);
					apinfos[ap_count].channel = (uint8)(info->chanspec & WL_CHANSPEC_CHAN_MASK);
					if (info->ctl_ch == 0)
					{
						apinfos[ap_count].ctl_ch = apinfos[ap_count].channel;
					} else
					{
						apinfos[ap_count].ctl_ch = info->ctl_ch;
					}

					if (info->RSSI >= -50)
						apinfos[ap_count].RSSI_Quality = 100;
					else if (info->RSSI >= -80)	// between -50 ~ -80dbm
						apinfos[ap_count].RSSI_Quality = (int)(24 + ((info->RSSI + 80) * 26)/10);
					else if (info->RSSI >= -90)	// between -80 ~ -90dbm
						apinfos[ap_count].RSSI_Quality = (int)(((info->RSSI + 90) * 26)/10);
					else					// < -84 dbm
						apinfos[ap_count].RSSI_Quality = 0;

					if (info->capability & DOT11_CAP_PRIVACY)
						apinfos[ap_count].wep = 1;
					else
						apinfos[ap_count].wep = 0;
					apinfos[ap_count].wpa = 0;

/*
					unsigned char *RATESET = &info->rateset;
					for (k = 0; k < 18; k++)
						dbg("%02x ", (unsigned char)RATESET[k]);
					dbg("\n");
*/

					NetWorkType = Ndis802_11DS;
					if ((uint8)(info->chanspec & WL_CHANSPEC_CHAN_MASK) <= 14)
					{
						for (k = 0; k < info->rateset.count; k++)
						{
							rate = info->rateset.rates[k] & 0x7f;	// Mask out basic rate set bit
							if ((rate == 2) || (rate == 4) || (rate == 11) || (rate == 22))
								continue;
							else
							{
								NetWorkType = Ndis802_11OFDM24;
								break;
							}
						}
					}
					else
						NetWorkType = Ndis802_11OFDM5;

					if (info->n_cap)
					{
						if (NetWorkType == Ndis802_11OFDM5)
						{
#ifdef RTCONFIG_BCMWL6
							if (info->vht_cap)
							{
#ifdef RTCONFIG_HND_ROUTER_AX
							if (new_info->he_cap)
								NetWorkType = Ndis802_11OFDMA5_HE;
							else
#endif
								NetWorkType = Ndis802_11OFDM5_VHT;
							}
							else
#endif
								NetWorkType = Ndis802_11OFDM5_N;
						}
						else
						{
#ifdef RTCONFIG_HND_ROUTER_AX
							if (new_info->he_cap)
								NetWorkType = Ndis802_11OFDMA24_HE;
							else
#endif
								NetWorkType = Ndis802_11OFDM24_N;
						}
					}

					apinfos[ap_count].NetworkType = NetWorkType;

					ap_count++;
					if (ap_count >= MAX_NUMBER_OF_APINFO)
						break;
				}

#ifdef RTCONFIG_AMAS
				apinfos[ap_count - 1].amas = 0;
				ie = (struct bss_ie_hdr *) ((unsigned char *) info + info->ie_offset);
				for (left = info->ie_length; left > 0; // look for ASUS VS IE
					left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len))
				{
					if (ie->elem_id != DOT11_MNG_VS_ID)
						continue;

					if (memcmp(ie->oui, OUI_ASUS, DOT11_OUI_LEN))
						continue;

					ie_vs = (struct vndr_ie *) ie;
					tlv = (struct tlvbase *) &(ie_vs->data[0]);
					match_1 = match_2 = match_3 = match_7 = 0;

					for (left2 = ie->len - DOT11_OUI_LEN; left2 > 0;
						left2 -= (tlv->len + 2), tlv = (struct tlvbase *) ((unsigned char *) tlv + 2 + tlv->len)) {
						switch (tlv->type) {
						case 1:
							if (tlv->len == 1) match_1 = 1;
							break;
						case 2:
							if (tlv->len == 1) match_2 = 1;
							break;
						case 3:
							if (tlv->len == 20) match_3 = 1;
							break;
						case 7:
							if (tlv->len == 4) match_7 = 1;
							break;
						case 4:
						case 5:
						case 6:
							break;
						default:
							goto rsn_wpa_check;
						}
					}

					if (match_1 && match_2 && match_3 && match_7)
						apinfos[ap_count - 1].amas = 1;

					break;
				}
rsn_wpa_check:
#endif
#ifdef RTCONFIG_HND_ROUTER_AX
				if (dtoh32(new_info->ie_length)) {
					wl_dump_wpa_rsn_ies((uint8 *)(((uint8 *)new_info) + dtoh16(new_info->ie_offset)), dtoh32(new_info->ie_length), &apinfos[ap_count - 1]);
				}
#else
				ie = (struct bss_ie_hdr *) ((unsigned char *) info + info->ie_offset);
				for (left = info->ie_length; left > 0; // look for RSN IE first
					left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len))
				{
					if (ie->elem_id != DOT11_MNG_RSN_ID)
						continue;

					if (wpa_parse_wpa_ie(&ie->elem_id, ie->len + 2, &apinfos[ap_count - 1].wid) == 0)
					{
						apinfos[ap_count - 1].wpa = 1;
						goto next_info;
					}
				}

				ie = (struct bss_ie_hdr *) ((unsigned char *) info + info->ie_offset);
				for (left = info->ie_length; left > 0; // then look for WPA IE
					left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len))
				{
					if (ie->elem_id != DOT11_MNG_WPA_ID)
						continue;

					if (wpa_parse_wpa_ie(&ie->elem_id, ie->len + 2, &apinfos[ap_count - 1].wid) == 0)
					{
						apinfos[ap_count - 1].wpa = 1;
						break;
					}
				}
#endif
next_info:
				info = (wl_bss_info_t *) ((unsigned char *) info + info->length);
#ifdef RTCONFIG_HND_ROUTER_AX
				new_info = (wl_bss_info_v109_1_t*) ((uint8 *) new_info + new_info->length);
#endif
			}
		}
	}

	if (chanspec != 0) {
		dbg("restore original chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec, chanbuf), chanspec);
#ifndef RTCONFIG_HND_ROUTER_AX
		ctl_ch_tmp = wf_chspec_ctlchan(chspec_tmp);
#endif
		if (wl_cap(unit, "bgdfs")
#ifndef RTCONFIG_HND_ROUTER_AX
			&& (((ctl_ch >= 100) && (ctl_ch_tmp <= 48)) || ((ctl_ch < 100) && (ctl_ch_tmp >= 149)))
#endif
		)
			wl_iovar_setint(wif, "dfs_ap_move", chanspec);
		else
		{
			wl_iovar_setint(wif, "chanspec", chanspec);
			wl_iovar_setint(wif, "acs_update", -1);
		}
	}

	/* Print scanning result to console */
	if (ap_count == 0) {
		dbg("[wlc] No AP found!\n");
	} else {
#ifdef RTCONFIG_AMAS
		printf("%-4s%4s%-33s%-18s%-9s%-16s%-9s%8s%3s%3s%3s\n",
				"idx", "CH ", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode", "CC", "EC", "AN");
#else
		printf("%-4s%4s%-33s%-18s%-9s%-16s%-9s%8s%3s%3s\n",
				"idx", "CH ", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode", "CC", "EC");
#endif
		for (k = 0; k < ap_count; k++)
		{
			printf("%2d. ", k + 1);
			printf("%3d ", apinfos[k].ctl_ch);
			printf("%-33s", apinfos[k].SSID);
			printf("%-18s", apinfos[k].BSSID);

			if (apinfos[k].wpa == 1)
#ifdef RTCONFIG_HND_ROUTER_AX
				printf("%-9s%-16s", wpa_unicast_txt(apinfos[k].wid.pairwise_cipher), wpa_akm_txt(apinfos[k].wid.key_mgmt, apinfos[k].wid.proto));
#else
				printf("%-9s%-16s", wpa_cipher_txt(apinfos[k].wid.pairwise_cipher), wpa_key_mgmt_txt(apinfos[k].wid.key_mgmt, apinfos[k].wid.proto));
#endif
			else if (apinfos[k].wep == 1)
				printf("WEP      Unknown         ");
			else
				printf("NONE     Open System     ");
			printf("%9d ", apinfos[k].RSSI_Quality);

			if (apinfos[k].NetworkType == Ndis802_11FH || apinfos[k].NetworkType == Ndis802_11DS)
				printf("%-7s", "11b");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM5)
				printf("%-7s", "11a");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM5_N)
				printf("%-7s", "11a/n");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM5_VHT)
				printf("%-7s", "11ac");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM24)
				printf("%-7s", "11b/g");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM24_N)
				printf("%-7s", "11b/g/n");
			else if (apinfos[k].NetworkType == Ndis802_11OFDMA5_HE ||
				apinfos[k].NetworkType == Ndis802_11OFDMA24_HE)
				printf("%-7s", "11ax");
			else
				printf("%-7s", "unknown");

			printf("%3d", apinfos[k].ctl_ch);

			if (	((apinfos[k].NetworkType == Ndis802_11OFDM5_VHT) ||
				 (apinfos[k].NetworkType == Ndis802_11OFDM5_N) ||
				 (apinfos[k].NetworkType == Ndis802_11OFDM24_N)) &&
					(apinfos[k].channel != apinfos[k].ctl_ch)) {
				if (apinfos[k].ctl_ch < apinfos[k].channel)
					ht_extcha = 1;
				else
					ht_extcha = 0;

				printf("%3d", ht_extcha);
			}
#ifdef RTCONFIG_AMAS
			else printf("%3s", "");

			if (apinfos[k].amas)
				printf("%3d", 1);
#endif
			printf("\n");
		}
	}

	ret = wl_ioctl(wif, WLC_GET_BSSID, bssid, sizeof(bssid));
	memset(ure_mac, 0x0, 18);
	if (!ret && memcmp(bssid, bssid_null, ETHER_ADDR_LEN))
		ether_etoa((const unsigned char *) &bssid, ure_mac);

	if (strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk")) {
		maclist_size = sizeof(authorized->count) + max_sta_count * sizeof(struct ether_addr);
		authorized = malloc(maclist_size);

		// query wl for authorized sta list
		strcpy((char*)authorized, "autho_sta_list");
		if (!wl_ioctl(wif, WLC_GET_VAR, authorized, maclist_size)) {
			if (authorized->count > 0) wl_authorized = 1;
		}

		if (authorized) free(authorized);
	}

	/* Print scanning result to web format */
	if (ap_count > 0) {
		/* write pid */
		if ((fp = fopen(ofile, "a")) == NULL) {
			printf("[wlcscan] Output %s error\n", ofile);
		} else {
#ifdef RTCONFIG_HAS_5G_2
			int unit = 0;
			char prefix[] = "wlXXXXXXXXXX_", tmp[100];
			wl_ioctl(wif, WLC_GET_INSTANCE, &unit, sizeof(unit));
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
#endif
			for (i = 0; i < ap_count; i++) {
#ifdef RTCONFIG_HAS_5G_2
#if defined(GTAC5300) || defined(GTAX11000)
				if (!strcmp(wif, "eth7") && (apinfos[i].ctl_ch > 64))
#elif defined(RTAX92U)
				if (!strcmp(wif, "eth6") && (apinfos[i].ctl_ch > 64))
#elif defined(RTAC5300)
				if (!strcmp(wif, "eth1") && (apinfos[i].ctl_ch > 64))
#elif defined(GTAX11000_PRO)
				if (!strcmp(wif, "eth7") && (apinfos[i].ctl_ch > 64))
#elif defined(GTAXE16000)
				if (!strcmp(wif, "eth8") && (apinfos[i].ctl_ch > 64))
#elif defined(XT12)
				if (!strcmp(wif, "eth5") && (apinfos[i].ctl_ch > 64))
#else
				if (!strcmp(wif, "eth1") && (apinfos[i].ctl_ch > 48))
#endif
					continue;
#if defined(GTAC5300) || defined(GTAX11000)
				if (!strcmp(wif, "eth8")) {
#elif defined(RTAX92U)
				if (!strcmp(wif, "eth7")) {
#elif defined(GTAX11000_PRO)
				if (!strcmp(wif, "eth8")) {
#elif defined(GTAXE16000)
				if (!strcmp(wif, "eth9")) {
#elif defined(XT12)
				if (!strcmp(wif, "eth6")) {
#else
				if (!strcmp(wif, "eth3")) {
#endif
					if (nvram_match(strcat_r(prefix, "country_code", tmp), "E0") ||
					    nvram_match(strcat_r(prefix, "country_code", tmp), "JP")) {
						if (apinfos[i].ctl_ch < 100)
							continue;
					} else {
						if (apinfos[i].ctl_ch < 149)
							continue;
					}
				}
#if defined(GTAXE11000)
				//TODO
#endif

#endif
#ifdef RTCONFIG_WIFI6E
				if (apinfos[i].ctl_ch > 0 && apinfos[i].ctl_ch < 14) {
					if(nvram_match(strcat_r(prefix, "nband", tmp), "4"))
						fprintf(fp, "\"6G\",");
					else
						fprintf(fp, "\"2G\",");
				} else if (apinfos[i].ctl_ch > 14 && apinfos[i].ctl_ch < 166) {
					if(nvram_match(strcat_r(prefix, "nband", tmp), "4"))
						fprintf(fp, "\"6G\",");
					else
						fprintf(fp, "\"5G\",");
				} else if (apinfos[i].ctl_ch > 166 && apinfos[i].ctl_ch < 234) {
					fprintf(fp, "\"6G\",");
				} else {
					fprintf(fp, "\"ERR_BAND\",");
				}
#else
				/*if (apinfos[i].ctl_ch < 0 ) {
					fprintf(fp, "\"ERR_BAND\",");
				} else */if (apinfos[i].ctl_ch > 0 &&
							 apinfos[i].ctl_ch < 14) {
					fprintf(fp, "\"2G\",");
				} else if (apinfos[i].ctl_ch > 14 &&
							 apinfos[i].ctl_ch < 166) {
					fprintf(fp, "\"5G\",");
				} else {
					fprintf(fp, "\"ERR_BAND\",");
				}
#endif
				if (strlen(apinfos[i].SSID) == 0) {
					fprintf(fp, "\"\",");
				} else {
					memset(ssid_str, 0, sizeof(ssid_str));
#if defined(RTCONFIG_UTF8_SSID)
					char_to_ascii_with_utf8(ssid_str, apinfos[i].SSID);
#else
					char_to_ascii(ssid_str, apinfos[i].SSID);
#endif
					fprintf(fp, "\"%s\",", ssid_str);
				}

				fprintf(fp, "\"%d\",", apinfos[i].ctl_ch);

				if (apinfos[i].wpa == 1) {
#ifdef RTCONFIG_HND_ROUTER_AX
					if (apinfos[i].wid.key_mgmt == _RSN_AKM_UNSPECIFIED_ ||
					    apinfos[i].wid.key_mgmt == _RSN_AKM_SHA256_1X_)
					{
						if (apinfos[i].wid.proto == WPA_PROTO_RSN_)
							fprintf(fp, "\"%s\",", "WPA2-Enterprise");
						else
							fprintf(fp, "\"%s\",", "WPA-Enterprise");
					}
					else if (apinfos[i].wid.key_mgmt == _RSN_AKM_PSK_)
					{
						if (apinfos[i].wid.proto == WPA_PROTO_RSN_)
							fprintf(fp, "\"%s\",", "WPA2-Personal");
						else
							fprintf(fp, "\"%s\",", "WPA-Personal");
					}
					else if (apinfos[i].wid.key_mgmt == _RSN_AKM_SHA256_PSK_)
						fprintf(fp, "\"%s\",", "WPA2-Personal");
					else if (apinfos[i].wid.key_mgmt & _RSN_AKM_SAE_PSK_)
						fprintf(fp, "\"%s\",", "WPA3-Personal");
					else if (apinfos[i].wid.key_mgmt & _RSN_AKM_OWE_)
						fprintf(fp, "\"%s\",", "OWE");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#else
					if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X_)
						fprintf(fp, "\"%s\",", "WPA-Enterprise");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X2_)
						fprintf(fp, "\"%s\",", "WPA2-Enterprise");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_PSK_)
						fprintf(fp, "\"%s\",", "WPA-Personal");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_PSK2_)
						fprintf(fp, "\"%s\",", "WPA2-Personal");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_NONE_)
						fprintf(fp, "\"%s\",", "NONE");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA_)
						fprintf(fp, "\"%s\",", "IEEE 802.1X");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#endif
				} else if (apinfos[i].wep == 1) {
					fprintf(fp, "\"%s\",", "Unknown");
				} else {
					fprintf(fp, "\"%s\",", "Open System");
				}

				if (apinfos[i].wpa == 1) {
#ifdef RTCONFIG_HND_ROUTER_AX
					if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_NONE_)
						fprintf(fp, "\"%s\",", "NONE");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_WEP_40_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_WEP_104_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_TKIP_)
						fprintf(fp, "\"%s\",", "TKIP");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_AES_CCM_)
						fprintf(fp, "\"%s\",", "AES");
					else if (apinfos[i].wid.pairwise_cipher == (_WPA_CIPHER_TKIP_ | _WPA_CIPHER_AES_CCM_))
						fprintf(fp, "\"%s\",", "TKIP+AES");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#else
					if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_NONE_)
						fprintf(fp, "\"%s\",", "NONE");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_WEP40_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_WEP104_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_TKIP_)
						fprintf(fp, "\"%s\",", "TKIP");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_CCMP_)
						fprintf(fp, "\"%s\",", "AES");
					else if (apinfos[i].wid.pairwise_cipher == (WPA_CIPHER_TKIP_|WPA_CIPHER_CCMP_))
						fprintf(fp, "\"%s\",", "TKIP+AES");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#endif
				} else if (apinfos[i].wep == 1) {
					fprintf(fp, "\"%s\",", "WEP");
				} else {
					fprintf(fp, "\"%s\",", "NONE");
				}

				fprintf(fp, "\"%d\",", apinfos[i].RSSI_Quality);
				fprintf(fp, "\"%s\",", apinfos[i].BSSID);

				if (apinfos[i].NetworkType == Ndis802_11FH || apinfos[i].NetworkType == Ndis802_11DS)
					fprintf(fp, "\"%s\",", "b");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM5)
					fprintf(fp, "\"%s\",", "a");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM5_N)
					fprintf(fp, "\"%s\",", "an");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM5_VHT)
					fprintf(fp, "\"%s\",", "ac");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM24)
					fprintf(fp, "\"%s\",", "bg");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM24_N)
					fprintf(fp, "\"%s\",", "bgn");
				else if (apinfos[i].NetworkType == Ndis802_11OFDMA5_HE ||
					apinfos[i].NetworkType == Ndis802_11OFDMA24_HE)
					fprintf(fp, "\"%s\",", "ax");
				else
					fprintf(fp, "\"%s\",", "");

				if (strcmp(nvram_safe_get(wl_nvname("ssid", unit, 0)), apinfos[i].SSID)) {
					if (strcmp(apinfos[i].SSID, ""))
						fprintf(fp, "\"%s\"", "0");				// none
					else if (!strcmp(ure_mac, apinfos[i].BSSID)) {
						// hidden AP (null SSID)
						if (strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk")) {
							if (wl_authorized) {
								// in profile, connected
								fprintf(fp, "\"%s\"", "4");
							} else {
								// in profile, connecting
								fprintf(fp, "\"%s\"", "5");
							}
						} else {
							// in profile, connected
							fprintf(fp, "\"%s\"", "4");
						}
					} else {
						// hidden AP (null SSID)
						fprintf(fp, "\"%s\"", "0");				// none
					}
				} else if (!strcmp(nvram_safe_get(wl_nvname("ssid", unit, 0)), apinfos[i].SSID)) {
					if (!strlen(ure_mac)) {
						// in profile, disconnected
						fprintf(fp, "\"%s\"", "1");
					} else if (!strcmp(ure_mac, apinfos[i].BSSID)) {
						if (strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk")) {
							if (wl_authorized) {
								// in profile, connected
								fprintf(fp, "\"%s\"", "2");
							} else {
								// in profile, connecting
								fprintf(fp, "\"%s\"", "3");
							}
						} else {
							// in profile, connected
							fprintf(fp, "\"%s\"", "2");
						}
					} else {
						fprintf(fp, "\"%s\"", "0");				// impossible...
					}
				} else {
					// wl0_ssid is empty
					fprintf(fp, "\"%s\"", "0");
				}
#ifdef RTCONFIG_AMAS
				fprintf(fp, ",\"%d\"", apinfos[i].amas);
#endif
				fprintf(fp, "\n");
			}	/* for */
			fclose(fp);
		}
	}	/* if */

	return retval;
}

#ifdef __CONFIG_DHDAP__
#define WL_EVENT_TIMEOUT 10

typedef struct escan_wksp_s {
	uint8 packet[4096];
	fd_set fdset;
	int fdmax;
	int event_fd;
} escan_wksp_t;

static escan_wksp_t *d_info;

static bool escan_swap = FALSE;
#define htod16(i) (escan_swap?bcmswap16(i):(uint16)(i))

static bool escan_inprogress;

struct escan_bss {
	struct escan_bss *next;
	wl_bss_info_t bss[1];
};

static struct escan_bss *escan_bss_head; /* raw escan results */
static struct escan_bss *escan_bss_tail;

/* open a UDP packet to event dispatcher for receiving/sending data */
static int
escan_open_eventfd()
{
	int reuse = 1;
	struct sockaddr_in sockaddr;
	int fd = -1;

	/* open loopback socket to communicate with event dispatcher */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_WLEVENT_UDP_SPORT);

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		dbg("Unable to create loopback socket\n");
		goto exit;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		dbg("Unable to setsockopt to loopback socket %d.\n", fd);
		goto exit;
	}

	if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		dbg("Unable to bind to loopback socket %d\n", fd);
		goto exit;
	}

	d_info->event_fd = fd;

	return 0;

	/* error handling */
exit:
	if (fd != -1) {
		close(fd);
	}

	return errno;
}

static int
validate_wlpvt_message(int bytes, uint8 *dpkt)
{
	bcm_event_t *pvt_data;

	/* the message should be at least the header to even look at it */
	if (bytes < sizeof(bcm_event_t) + 2) {
		dbg("Invalid length of message\n");
		goto error_exit;
	}
	pvt_data = (bcm_event_t *)dpkt;
	if (ntohs(pvt_data->bcm_hdr.subtype) != BCMILCP_SUBTYPE_VENDOR_LONG) {
		dbg("%s: not vendor specifictype\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	if (pvt_data->bcm_hdr.version != BCMILCP_BCM_SUBTYPEHDR_VERSION) {
		dbg("%s: subtype header version mismatch\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	if (ntohs(pvt_data->bcm_hdr.length) < BCMILCP_BCM_SUBTYPEHDR_MINLENGTH) {
		dbg("%s: subtype hdr length not even minimum\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	if (bcmp(&pvt_data->bcm_hdr.oui[0], BRCM_OUI, DOT11_OUI_LEN) != 0) {
		dbg("%s: validate_wlpvt_message: not BRCM OUI\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	/* check for wl dcs message types */
	switch (ntohs(pvt_data->bcm_hdr.usr_subtype)) {
		case BCMILCP_BCM_SUBTYPE_EVENT:
			break;
		default:
			goto error_exit;
			break;
	}
	return 0; /* good packet may be this is destined to us */
error_exit:
	return -1;
}

static void
escan_main_loop(struct timeval *tv)
{
	fd_set fdset;
	int width, status = 0, bytes, len;
	uint8 *pkt;
	bcm_event_t *pvt_data;
	int err;
	uint32 escan_event_status;
	wl_escan_result_t *escan_data = NULL;
	struct escan_bss *result;

	/* init file descriptor set */
	FD_ZERO(&d_info->fdset);
	d_info->fdmax = -1;

	/* build file descriptor set now to save time later */
	if (d_info->event_fd != -1) {
		FD_SET(d_info->event_fd, &d_info->fdset);
		d_info->fdmax = d_info->event_fd;
	}

	pkt = d_info->packet;
	len = sizeof(d_info->packet);
	width = d_info->fdmax + 1;
	fdset = d_info->fdset;

	/* listen to data availible on all sockets */
	status = select(width, &fdset, NULL, NULL, tv);

	if ((status == -1 && errno == EINTR) || (status == 0))
		return;

	if (status <= 0) {
		dbg("err from select: %s", strerror(errno));
		return;
	}

	/* handle brcm event */
	if (d_info->event_fd != -1 && FD_ISSET(d_info->event_fd, &fdset)) {
		char *ifname = (char *)pkt;
		struct ether_header *eth_hdr = (struct ether_header *)(ifname + IFNAMSIZ);
		uint16 ether_type = 0;
		uint32 evt_type;

		if ((bytes = recv(d_info->event_fd, pkt, len, 0)) <= 0)
			return;

		bytes -= IFNAMSIZ;

		if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
			return;
		}

		if ((err = validate_wlpvt_message(bytes, (uint8 *)eth_hdr)))
			return;

		pvt_data = (bcm_event_t *)(ifname + IFNAMSIZ);
		evt_type = ntoh32(pvt_data->event.event_type);

		switch (evt_type) {
			case WLC_E_ESCAN_RESULT:
				{
					if (!escan_inprogress) {
						dbg("Escan not triggered from rc\n");
						return;
					}

					escan_event_status = ntoh32(pvt_data->event.status);
					escan_data = (wl_escan_result_t*)(pvt_data + 1);

					if (escan_event_status == WLC_E_STATUS_PARTIAL) {
						wl_bss_info_t *bi = &escan_data->bss_info[0];
						wl_bss_info_t *bss;

						/* check if we've received info of same BSSID */
						for (result = escan_bss_head;
								result;	result = result->next) {
							bss = result->bss;

							if (!memcmp(bi->BSSID.octet,
								bss->BSSID.octet,
								ETHER_ADDR_LEN) &&
								CHSPEC_BAND(bi->chanspec) ==
								CHSPEC_BAND(bss->chanspec) &&
								bi->SSID_len ==	bss->SSID_len &&
								! memcmp(bi->SSID, bss->SSID,
								bi->SSID_len)) {
								break;
							}
						}

						if (!result) {
							/* New BSS. Allocate memory and save it */
							struct escan_bss *ebss = (struct escan_bss *)malloc(
								OFFSETOF(struct escan_bss, bss)
								+ bi->length);

							if (!ebss) {
								dbg("can't allocate memory"
										"for escan bss");
								break;
							}

							ebss->next = NULL;
							memcpy(&ebss->bss, bi, bi->length);

							if (escan_bss_tail) {
								escan_bss_tail->next = ebss;
							} else {
								escan_bss_head =
								ebss;
							}

							escan_bss_tail = ebss;
						} else if (bi->RSSI != WLC_RSSI_INVALID) {
							/* We've got this BSS. Update RSSI
							   if necessary
							   */
							bool preserve_maxrssi = FALSE;
							if (((bss->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL) ==
								(bi->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL)) &&
								((bss->RSSI == WLC_RSSI_INVALID) ||
								(bss->RSSI < bi->RSSI))) {
								/* Preserve max RSSI if the
								   measurements are both
								   on-channel or both off-channel
								   */
								preserve_maxrssi = TRUE;
							} else if ((bi->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL) &&
								(bss->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL) == 0) {
								/* Preserve the on-channel RSSI
								   measurement if the
								   new measurement is off channel
								   */
								preserve_maxrssi = TRUE;
								bss->flags |=
								WL_BSS_FLAGS_RSSI_ONCHANNEL;
							}

							if (preserve_maxrssi) {
								bss->RSSI = bi->RSSI;
								bss->SNR = bi->SNR;
								bss->phy_noise = bi->phy_noise;
							}
						}
					} else if (escan_event_status == WLC_E_STATUS_SUCCESS) {
						escan_inprogress = FALSE;
					} else {
						dbg("sync_id: %d, status:%d, misc."
							"error/abort\n",
							escan_data->sync_id, status);

						escan_bss_head = NULL;
						escan_bss_tail = NULL;
						escan_inprogress = FALSE;
					}
					break;
				}
			default:
				break;
		}
	}
}

/* listen to sockets and receive escan results */
static int
get_scan_escan(char *scan_buf, uint buf_len)
{
	int err;
	struct timeval tv, tv_tmp;
	time_t timeout;
	int len;
	struct escan_bss *result;
	struct escan_bss *next;
	wl_scan_results_t* s_result = (wl_scan_results_t*)scan_buf;
	wl_bss_info_t *bi = s_result->bss_info;
	wl_bss_info_t *bss;

	d_info = (escan_wksp_t*)malloc(sizeof(escan_wksp_t));
	d_info->fdmax = -1;
	d_info->event_fd = -1;
	err = escan_open_eventfd();
	if (err) return -1;

	tv.tv_usec = 0;
	tv.tv_sec = WL_EVENT_TIMEOUT;
	timeout = uptime() + WL_EVENT_TIMEOUT;

	escan_inprogress = TRUE;

	escan_bss_head = NULL;
	escan_bss_tail = NULL;

	while ((uptime() < timeout) && escan_inprogress) {
		memcpy(&tv_tmp, &tv, sizeof(tv));
		escan_main_loop(&tv_tmp);
	}

	escan_inprogress = FALSE;

	s_result->count = 0;
	len = buf_len - WL_SCAN_RESULTS_FIXED_SIZE;
	for (result = escan_bss_head; result; result = result->next) {
		bss = result->bss;
		if (len < bss->length) {
			dbg("Memory not enough for scan results\n");
			break;
		}
		memcpy(bi, bss, bss->length);
		bi = (wl_bss_info_t*)((int8*)bi + bss->length);
		len -= bss->length;
		s_result->count++;
	}

	for (result = escan_bss_head; result; result = next) {
		next = result->next;
		free(result);
	}

	/* close event dispatcher socket */
	if (d_info->event_fd != -1) {
		close(d_info->event_fd);
	}

	if (d_info)
		free(d_info);

	return 0;
}

int wlcscan_core_escan(char *ofile, char *wif)
{
	int ret, i, k, left, ht_extcha, ctl_ch;
	int retval = 0, ap_count = 0, idx_same = -1, count, unit = -1;
	unsigned char rate;
	unsigned char bssid[6];
	unsigned char bssid_null[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	char macstr[18];
	char ure_mac[18];
	char ssid_str[256];
	wl_scan_results_t *result;
	wl_bss_info_t *info;
	wl_bss_info_107_t *old_info;
#ifdef RTCONFIG_HND_ROUTER_AX
	wl_bss_info_v109_1_t *new_info;
#endif
	struct bss_ie_hdr *ie;
	NDIS_802_11_NETWORK_TYPE NetWorkType;
	struct maclist *authorized;
	int maclist_size;
	int max_sta_count = 128;
	int wl_authorized = 0;
	wl_escan_params_t *params = NULL;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params) + NUMCHANS * sizeof(uint16);
	int scount = 0;
	wl_uint32_list_t *list;
	char data_buf[WLC_IOCTL_MAXLEN];
	chanspec_t c = WL_CHANSPEC_BW_20;
	FILE *fp;
	int org_scan_time = 20, scan_time = 40;
	char tmp[256], prefix[] = "wlXXXXXXXXXX_";
#ifdef RTCONFIG_AMAS
	struct vndr_ie *ie_vs;
	struct tlvbase *tlv;
	int left2;
	int match_1, match_2, match_3, match_7;
#endif
	char chanbuf[CHANSPEC_STR_LEN];
	chanspec_t chspec_cur = 0, chanspec = 0;
	chanspec_t chspec_tmp = 0;
#ifndef RTCONFIG_HND_ROUTER_AX
	int ctl_ch_tmp;
#endif
#ifndef RTCONFIG_BCM7
	chanspec_t chspec_tar = 0;
	char buf_sm[WLC_IOCTL_SMLEN];
	wl_dfs_ap_move_status_t *status = (wl_dfs_ap_move_status_t*) buf_sm;
#endif
	int band;

	if (wl_ioctl(wif, WLC_GET_INSTANCE, &unit, sizeof(unit)))
		return retval;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ctl_ch = wl_control_channel(unit);
#ifdef RTCONFIG_BCMWL6
	if (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") && !is_psta(unit)) {
		if (wl_iovar_get(wif, "chanspec", &chspec_cur, sizeof(chanspec_t)) < 0) {
			dbg("get current chanpsec failed\n");
			return retval;
		}

		if (((ctl_ch > 48) && (ctl_ch < 149))
#ifdef RTCONFIG_BW160M
			|| ((ctl_ch <= 48) && CHSPEC_IS160(chspec_cur))
#endif
		) {
			if (!with_non_dfs_chspec(wif))
			{
				dbg("%s scan rejected under DFS mode\n", wif);
				return retval;
			}
			else
			{
				dbg("current chanspec: %s (0x%x)\n", wf_chspec_ntoa(chspec_cur, chanbuf), chspec_cur);

				chspec_tmp = (((nvram_get_hex(strcat_r(prefix, "band5grp", tmp)) & WL_5G_BAND_4) && (ctl_ch < 100)) ? select_chspec_with_band_bw(wif, 4, 3, chspec_cur) : select_chspec_with_band_bw(wif, 1, 3, chspec_cur));
				if (!chspec_tmp && (nvram_get_hex(strcat_r(prefix, "band5grp", tmp)) & WL_5G_BAND_4))
					chspec_tmp = select_chspec_with_band_bw(wif, 4, 3, chspec_cur);

				if (chspec_tmp != 0) {
					dbg("switch to chanspec: %s (0x%x)\n", wf_chspec_ntoa(chspec_tmp, chanbuf), chspec_tmp);
					wl_iovar_setint(wif, "chanspec", chspec_tmp);
					wl_iovar_setint(wif, "acs_update", -1);

					chanspec = chspec_cur;
				}
			}
		}
#ifndef RTCONFIG_BCM7
		else if (wl_cap(unit, "bgdfs")) {
			if (wl_iovar_get(wif, "dfs_ap_move", &buf_sm[0], WLC_IOCTL_SMLEN) < 0) {
				dbg("get dfs_ap_move status failure\n");
				return retval;
			}

			if (status->version != WL_DFS_AP_MOVE_VERSION)
				return retval;

			if (status->move_status != (int8) DFS_SCAN_S_IDLE) {
				chspec_tar = status->chanspec;
				if (chspec_tar != 0 && chspec_tar != INVCHANSPEC) {
					chanspec = chspec_tar;
					wf_chspec_ntoa(chspec_tar, chanbuf);
					dbg("AP Target Chanspec %s (0x%x)\n", chanbuf, chspec_tar);
				}

				if (status->move_status == (int8) DFS_SCAN_S_INPROGESS)
					wl_iovar_setint(wif, "dfs_ap_move", -1);
			}
		}
#endif
	}
#endif

	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL)
		return retval;

	memset(params, 0, params_size);
	params->params.bss_type = DOT11_BSSTYPE_INFRASTRUCTURE;
	memcpy(&params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->params.scan_type = (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") && !is_psta(unit)) ? WL_SCANFLAGS_PASSIVE : 0;
	params->params.nprobes = -1;
	params->params.active_time = -1;
	params->params.passive_time = -1;
	params->params.home_time = -1;
	params->params.channel_num = 0;

	wl_ioctl(wif, WLC_GET_BAND, &band, sizeof(band));
	if (band == WLC_BAND_5G)
		c |= WL_CHANSPEC_BAND_5G;
#ifdef RTCONFIG_WIFI6E
	else if(band == WLC_BAND_6G)
		c |= WL_CHANSPEC_BAND_6G;
#endif
	else
		c |= WL_CHANSPEC_BAND_2G;

	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(wif, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0)
		dbg("failed to get valid chanspec list\n");
	else {
		list = (wl_uint32_list_t *)data_buf;
		count = dtoh32(list->count);

		if (count && !(count > (data_buf + sizeof(data_buf) - (char *)&list->element[0])/sizeof(list->element[0]))) {
			for (i = 0; i < count; i++) {
				c = (chanspec_t)dtoh32(list->element[i]);
				params->params.channel_list[scount++] = c;
			}

			params->params.channel_num = htod32(scount & WL_SCAN_PARAMS_COUNT_MASK);
			params_size = WL_SCAN_PARAMS_FIXED_SIZE + scount * sizeof(uint16);
		}
	}

	params->version = htod32(ESCAN_REQ_VERSION);
	params->action = htod16(WL_SCAN_ACTION_START);

	srand((unsigned int)uptime());
	params->sync_id = htod16(rand() & 0xffff);

	params_size += OFFSETOF(wl_escan_params_t, params);

	/* extend scan channel time to get more AP probe resp */
	wl_ioctl(wif, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
	if (org_scan_time < scan_time)
		wl_ioctl(wif, WLC_SET_SCAN_CHANNEL_TIME, &scan_time, sizeof(scan_time));

	count = 0;
	while ((ret = wl_iovar_set(wif, "escan", params, params_size)) < 0 &&
		count++ < 2) {
		dbg("[rc] set escan command failed, retry %d\n", count);
		sleep(1);
	}

	free(params);

	/* restore original scan channel time */
	wl_ioctl(wif, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));

	if (ret == 0) {
		ret = get_scan_escan(scan_result, WLC_SCAN_RESULT_BUF_LEN);
		if (ret == 0)
		{
			result = (wl_scan_results_t *)scan_result;

			info = &(result->bss_info[0]);
#ifdef RTCONFIG_HND_ROUTER_AX
			new_info = (wl_bss_info_v109_1_t *)&(result->bss_info[0]);
#endif

			/* Convert version 107 to 109 */
			if (dtoh32(info->version) == LEGACY_WL_BSS_INFO_VERSION) {
				old_info = (wl_bss_info_107_t *)info;
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
				info->chanspec = CH20MHZ_CHSPEC(old_info->channel, WL_CHANNEL_2G5G_BAND(old_info->channel));
#else
				info->chanspec = CH20MHZ_CHSPEC(old_info->channel);
#endif
				info->ie_length = old_info->ie_length;
				info->ie_offset = sizeof(wl_bss_info_107_t);
			}

			for (i = 0; i < result->count; i++)
			{
				if (info->SSID_len > 32/* || info->SSID_len == 0*/)
					goto next_info;

				ether_etoa((const unsigned char *) &info->BSSID, macstr);

				idx_same = -1;
				for (k = 0; k < ap_count; k++) {
					/* deal with old version of Broadcom Multiple SSID
						(share the same BSSID) */
					if (strcmp(apinfos[k].BSSID, macstr) == 0 &&
						strcmp(apinfos[k].SSID, (const char *) info->SSID) == 0) {
						idx_same = k;
						break;
					}
				}

				if (idx_same != -1)
				{
					if (info->RSSI >= -50)
						apinfos[idx_same].RSSI_Quality = 100;
					else if (info->RSSI >= -80)	// between -50 ~ -80dbm
						apinfos[idx_same].RSSI_Quality = (int)(24 + ((info->RSSI + 80) * 26)/10);
					else if (info->RSSI >= -90)	// between -80 ~ -90dbm
						apinfos[idx_same].RSSI_Quality = (int)(((info->RSSI + 90) * 26)/10);
					else					// < -84 dbm
						apinfos[idx_same].RSSI_Quality = 0;
				}
				else
				{
					strcpy(apinfos[ap_count].BSSID, macstr);
//					strcpy(apinfos[ap_count].SSID, info->SSID);
					memset(apinfos[ap_count].SSID, 0x0, 33);
					memcpy(apinfos[ap_count].SSID, info->SSID, info->SSID_len);
					apinfos[ap_count].channel = (uint8)(info->chanspec & WL_CHANSPEC_CHAN_MASK);
					if (info->ctl_ch == 0)
					{
						apinfos[ap_count].ctl_ch = apinfos[ap_count].channel;
					} else
					{
						apinfos[ap_count].ctl_ch = info->ctl_ch;
					}

					if (info->RSSI >= -50)
						apinfos[ap_count].RSSI_Quality = 100;
					else if (info->RSSI >= -80)	// between -50 ~ -80dbm
						apinfos[ap_count].RSSI_Quality = (int)(24 + ((info->RSSI + 80) * 26)/10);
					else if (info->RSSI >= -90)	// between -80 ~ -90dbm
						apinfos[ap_count].RSSI_Quality = (int)(((info->RSSI + 90) * 26)/10);
					else					// < -84 dbm
						apinfos[ap_count].RSSI_Quality = 0;

					if (info->capability & DOT11_CAP_PRIVACY)
						apinfos[ap_count].wep = 1;
					else
						apinfos[ap_count].wep = 0;
					apinfos[ap_count].wpa = 0;

/*
					unsigned char *RATESET = &info->rateset;
					for (k = 0; k < 18; k++)
						dbg("%02x ", (unsigned char)RATESET[k]);
					dbg("\n");
*/

					NetWorkType = Ndis802_11DS;
					if ((uint8)(info->chanspec & WL_CHANSPEC_CHAN_MASK) <= 14)
					{
						for (k = 0; k < info->rateset.count; k++)
						{
							rate = info->rateset.rates[k] & 0x7f;	// Mask out basic rate set bit
							if ((rate == 2) || (rate == 4) || (rate == 11) || (rate == 22))
								continue;
							else
							{
								NetWorkType = Ndis802_11OFDM24;
								break;
							}
						}
					}
					else
						NetWorkType = Ndis802_11OFDM5;

					if (info->n_cap)
					{
						if (NetWorkType == Ndis802_11OFDM5)
						{
#ifdef RTCONFIG_BCMWL6
							if (info->vht_cap)
							{
#ifdef RTCONFIG_HND_ROUTER_AX
							if (new_info->he_cap)
								NetWorkType = Ndis802_11OFDMA5_HE;
							else
#endif
								NetWorkType = Ndis802_11OFDM5_VHT;
							}
							else
#endif
								NetWorkType = Ndis802_11OFDM5_N;
						}
						else
						{
#ifdef RTCONFIG_HND_ROUTER_AX
							if (new_info->he_cap)
								NetWorkType = Ndis802_11OFDMA24_HE;
							else
#endif
								NetWorkType = Ndis802_11OFDM24_N;
						}
					}

					apinfos[ap_count].NetworkType = NetWorkType;

					ap_count++;
					if (ap_count >= MAX_NUMBER_OF_APINFO)
						break;
				}

#ifdef RTCONFIG_AMAS
				apinfos[ap_count - 1].amas = 0;
				ie = (struct bss_ie_hdr *) ((unsigned char *) info + info->ie_offset);
				for (left = info->ie_length; left > 0; // look for ASUS VS IE
					left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len))
				{
					if (ie->elem_id != DOT11_MNG_VS_ID)
						continue;

					if (memcmp(ie->oui, OUI_ASUS, DOT11_OUI_LEN))
						continue;

					ie_vs = (struct vndr_ie *) ie;
					tlv = (struct tlvbase *) &(ie_vs->data[0]);
					match_1 = match_2 = match_3 = match_7 = 0;

					for (left2 = ie->len - DOT11_OUI_LEN; left2 > 0;
						left2 -= (tlv->len + 2), tlv = (struct tlvbase *) ((unsigned char *) tlv + 2 + tlv->len)) {
						switch (tlv->type) {
						case 1:
							if (tlv->len == 1) match_1 = 1;
							break;
						case 2:
							if (tlv->len == 1) match_2 = 1;
							break;
						case 3:
							if (tlv->len == 20) match_3 = 1;
							break;
						case 7:
							if (tlv->len == 4) match_7 = 1;
							break;
						case 4:
						case 5:
						case 6:
							break;
						default:
							goto rsn_wpa_check;
						}
					}

					if (match_1 && match_2 && match_3 && match_7)
						apinfos[ap_count - 1].amas = 1;

					break;
				}
rsn_wpa_check:
#endif
#ifdef RTCONFIG_HND_ROUTER_AX
				if (dtoh32(new_info->ie_length)) {
					wl_dump_wpa_rsn_ies((uint8 *)(((uint8 *)new_info) + dtoh16(new_info->ie_offset)), dtoh32(new_info->ie_length), &apinfos[ap_count - 1]);
				}
#else
				ie = (struct bss_ie_hdr *) ((unsigned char *) info + info->ie_offset);
				for (left = info->ie_length; left > 0; // look for RSN IE first
					left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len))
				{
					if (ie->elem_id != DOT11_MNG_RSN_ID)
						continue;

					if (wpa_parse_wpa_ie(&ie->elem_id, ie->len + 2, &apinfos[ap_count - 1].wid) == 0)
					{
						apinfos[ap_count - 1].wpa = 1;
						goto next_info;
					}
				}

				ie = (struct bss_ie_hdr *) ((unsigned char *) info + info->ie_offset);
				for (left = info->ie_length; left > 0; // then look for WPA IE
					left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len))
				{
					if (ie->elem_id != DOT11_MNG_WPA_ID)
						continue;

					if (wpa_parse_wpa_ie(&ie->elem_id, ie->len + 2, &apinfos[ap_count - 1].wid) == 0)
					{
						apinfos[ap_count - 1].wpa = 1;
						break;
					}
				}
#endif
next_info:
				info = (wl_bss_info_t *) ((unsigned char *) info + info->length);
#ifdef RTCONFIG_HND_ROUTER_AX
				new_info = (wl_bss_info_v109_1_t*) ((uint8 *) new_info + new_info->length);
#endif
			}
		}
	}

	if (chanspec != 0) {
		dbg("restore original chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec, chanbuf), chanspec);
#ifndef RTCONFIG_HND_ROUTER_AX
		ctl_ch_tmp = wf_chspec_ctlchan(chspec_tmp);
#endif
		if (wl_cap(unit, "bgdfs")
#ifndef RTCONFIG_HND_ROUTER_AX
			&& (((ctl_ch >= 100) && (ctl_ch_tmp <= 48)) || ((ctl_ch < 100) && (ctl_ch_tmp >= 149)))
#endif
		)
			wl_iovar_setint(wif, "dfs_ap_move", chanspec);
		else
		{
			wl_iovar_setint(wif, "chanspec", chanspec);
			wl_iovar_setint(wif, "acs_update", -1);
		}
	}

	/* Print scanning result to console */
	if (ap_count == 0) {
		dbg("[wlc] No AP found!\n");
	} else {
#ifdef RTCONFIG_AMAS
		printf("%-4s%4s%-33s%-18s%-9s%-16s%-9s%8s%3s%3s%3s\n",
				"idx", "CH ", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode", "CC", "EC", "AN");
#else
		printf("%-4s%4s%-33s%-18s%-9s%-16s%-9s%8s%3s%3s\n",
				"idx", "CH ", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode", "CC", "EC");
#endif
		for (k = 0; k < ap_count; k++)
		{
			printf("%2d. ", k + 1);
			printf("%3d ", apinfos[k].ctl_ch);
			printf("%-33s", apinfos[k].SSID);
			printf("%-18s", apinfos[k].BSSID);

			if (apinfos[k].wpa == 1)
#ifdef RTCONFIG_HND_ROUTER_AX
				printf("%-9s%-16s", wpa_unicast_txt(apinfos[k].wid.pairwise_cipher), wpa_akm_txt(apinfos[k].wid.key_mgmt, apinfos[k].wid.proto));
#else
				printf("%-9s%-16s", wpa_cipher_txt(apinfos[k].wid.pairwise_cipher), wpa_key_mgmt_txt(apinfos[k].wid.key_mgmt, apinfos[k].wid.proto));
#endif
			else if (apinfos[k].wep == 1)
				printf("WEP      Unknown         ");
			else
				printf("NONE     Open System     ");
			printf("%9d ", apinfos[k].RSSI_Quality);

			if (apinfos[k].NetworkType == Ndis802_11FH || apinfos[k].NetworkType == Ndis802_11DS)
				printf("%-7s", "11b");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM5)
				printf("%-7s", "11a");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM5_N)
				printf("%-7s", "11a/n");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM5_VHT)
				printf("%-7s", "11ac");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM24)
				printf("%-7s", "11b/g");
			else if (apinfos[k].NetworkType == Ndis802_11OFDM24_N)
				printf("%-7s", "11b/g/n");
			else if (apinfos[k].NetworkType == Ndis802_11OFDMA5_HE ||
				apinfos[k].NetworkType == Ndis802_11OFDMA24_HE)
				printf("%-7s", "11ax");
			else
				printf("%-7s", "unknown");

			printf("%3d", apinfos[k].ctl_ch);

			if (	((apinfos[k].NetworkType == Ndis802_11OFDM5_VHT) ||
				 (apinfos[k].NetworkType == Ndis802_11OFDM5_N) ||
				 (apinfos[k].NetworkType == Ndis802_11OFDM24_N)) &&
					(apinfos[k].channel != apinfos[k].ctl_ch)) {
				if (apinfos[k].ctl_ch < apinfos[k].channel)
					ht_extcha = 1;
				else
					ht_extcha = 0;

				printf("%3d", ht_extcha);
			}
#ifdef RTCONFIG_AMAS
			else printf("%3s", "");

			if (apinfos[k].amas)
				printf("%3d", 1);
#endif
			printf("\n");
		}
	}

	ret = wl_ioctl(wif, WLC_GET_BSSID, bssid, sizeof(bssid));
	memset(ure_mac, 0x0, 18);
	if (!ret && memcmp(bssid, bssid_null, ETHER_ADDR_LEN))
		ether_etoa((const unsigned char *) &bssid, ure_mac);

	if (strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk")) {
		maclist_size = sizeof(authorized->count) + max_sta_count * sizeof(struct ether_addr);
		authorized = malloc(maclist_size);

		// query wl for authorized sta list
		strcpy((char*)authorized, "autho_sta_list");
		if (!wl_ioctl(wif, WLC_GET_VAR, authorized, maclist_size)) {
			if (authorized->count > 0) wl_authorized = 1;
		}

		if (authorized) free(authorized);
	}

	/* Print scanning result to web format */
	if (ap_count > 0) {
		/* write pid */
		if ((fp = fopen(ofile, "a")) == NULL) {
			printf("[wlcscan] Output %s error\n", ofile);
		} else {
			for (i = 0; i < ap_count; i++) {
#ifdef RTCONFIG_WIFI6E
				if (apinfos[i].ctl_ch > 0 && apinfos[i].ctl_ch < 14) {
					if(nvram_match(strcat_r(prefix, "nband", tmp), "4"))
						fprintf(fp, "\"6G\",");
					else
						fprintf(fp, "\"2G\",");
				} else if (apinfos[i].ctl_ch > 14 && apinfos[i].ctl_ch < 166) {
					if(nvram_match(strcat_r(prefix, "nband", tmp), "4"))
						fprintf(fp, "\"6G\",");
					else
						fprintf(fp, "\"5G\",");
				} else if (apinfos[i].ctl_ch > 166 && apinfos[i].ctl_ch < 234) {
					fprintf(fp, "\"6G\",");
				} else {
					fprintf(fp, "\"ERR_BAND\",");
				}
#else
				/*if (apinfos[i].ctl_ch < 0 ) {
					fprintf(fp, "\"ERR_BAND\",");
				} else */if (apinfos[i].ctl_ch > 0 &&
							 apinfos[i].ctl_ch < 14) {
					fprintf(fp, "\"2G\",");
				} else if (apinfos[i].ctl_ch > 14 &&
							 apinfos[i].ctl_ch < 166) {
					fprintf(fp, "\"5G\",");
				} else {
					fprintf(fp, "\"ERR_BAND\",");
				}
#endif
				if (strlen(apinfos[i].SSID) == 0) {
					fprintf(fp, "\"\",");
				} else {
					memset(ssid_str, 0, sizeof(ssid_str));
#if defined(RTCONFIG_UTF8_SSID)
					char_to_ascii_with_utf8(ssid_str, apinfos[i].SSID);
#else
					char_to_ascii(ssid_str, apinfos[i].SSID);
#endif
					fprintf(fp, "\"%s\",", ssid_str);
				}

				fprintf(fp, "\"%d\",", apinfos[i].ctl_ch);

				if (apinfos[i].wpa == 1) {
#ifdef RTCONFIG_HND_ROUTER_AX
					if (apinfos[i].wid.key_mgmt == _RSN_AKM_UNSPECIFIED_ ||
					    apinfos[i].wid.key_mgmt == _RSN_AKM_SHA256_1X_)
					{
						if (apinfos[i].wid.proto == WPA_PROTO_RSN_)
							fprintf(fp, "\"%s\",", "WPA2-Enterprise");
						else
							fprintf(fp, "\"%s\",", "WPA-Enterprise");
					}
					else if (apinfos[i].wid.key_mgmt == _RSN_AKM_PSK_)
					{
						if (apinfos[i].wid.proto == WPA_PROTO_RSN_)
							fprintf(fp, "\"%s\",", "WPA2-Personal");
						else
							fprintf(fp, "\"%s\",", "WPA-Personal");
					}
					else if (apinfos[i].wid.key_mgmt == _RSN_AKM_SHA256_PSK_)
						fprintf(fp, "\"%s\",", "WPA2-Personal");
					else if (apinfos[i].wid.key_mgmt & _RSN_AKM_SAE_PSK_)
						fprintf(fp, "\"%s\",", "WPA3-Personal");
					else if (apinfos[i].wid.key_mgmt & _RSN_AKM_OWE_)
						fprintf(fp, "\"%s\",", "OWE");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#else
					if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X_)
						fprintf(fp, "\"%s\",", "WPA-Enterprise");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X2_)
						fprintf(fp, "\"%s\",", "WPA2-Enterprise");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_PSK_)
						fprintf(fp, "\"%s\",", "WPA-Personal");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_PSK2_)
						fprintf(fp, "\"%s\",", "WPA2-Personal");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_NONE_)
						fprintf(fp, "\"%s\",", "NONE");
					else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA_)
						fprintf(fp, "\"%s\",", "IEEE 802.1X");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#endif
				} else if (apinfos[i].wep == 1) {
					fprintf(fp, "\"%s\",", "Unknown");
				} else {
					fprintf(fp, "\"%s\",", "Open System");
				}

				if (apinfos[i].wpa == 1) {
#ifdef RTCONFIG_HND_ROUTER_AX
					if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_NONE_)
						fprintf(fp, "\"%s\",", "NONE");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_WEP_40_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_WEP_104_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_TKIP_)
						fprintf(fp, "\"%s\",", "TKIP");
					else if (apinfos[i].wid.pairwise_cipher == _WPA_CIPHER_AES_CCM_)
						fprintf(fp, "\"%s\",", "AES");
					else if (apinfos[i].wid.pairwise_cipher == (_WPA_CIPHER_TKIP_ | _WPA_CIPHER_AES_CCM_))
						fprintf(fp, "\"%s\",", "TKIP+AES");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#else
					if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_NONE_)
						fprintf(fp, "\"%s\",", "NONE");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_WEP40_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_WEP104_)
						fprintf(fp, "\"%s\",", "WEP");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_TKIP_)
						fprintf(fp, "\"%s\",", "TKIP");
					else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_CCMP_)
						fprintf(fp, "\"%s\",", "AES");
					else if (apinfos[i].wid.pairwise_cipher == (WPA_CIPHER_TKIP_|WPA_CIPHER_CCMP_))
						fprintf(fp, "\"%s\",", "TKIP+AES");
					else
						fprintf(fp, "\"%s\",", "Unknown");
#endif
				} else if (apinfos[i].wep == 1) {
					fprintf(fp, "\"%s\",", "WEP");
				} else {
					fprintf(fp, "\"%s\",", "NONE");
				}

				fprintf(fp, "\"%d\",", apinfos[i].RSSI_Quality);
				fprintf(fp, "\"%s\",", apinfos[i].BSSID);

				if (apinfos[i].NetworkType == Ndis802_11FH || apinfos[i].NetworkType == Ndis802_11DS)
					fprintf(fp, "\"%s\",", "b");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM5)
					fprintf(fp, "\"%s\",", "a");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM5_N)
					fprintf(fp, "\"%s\",", "an");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM5_VHT)
					fprintf(fp, "\"%s\",", "ac");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM24)
					fprintf(fp, "\"%s\",", "bg");
				else if (apinfos[i].NetworkType == Ndis802_11OFDM24_N)
					fprintf(fp, "\"%s\",", "bgn");
				else if (apinfos[i].NetworkType == Ndis802_11OFDMA5_HE ||
					apinfos[i].NetworkType == Ndis802_11OFDMA24_HE)
					fprintf(fp, "\"%s\",", "ax");
				else
					fprintf(fp, "\"%s\",", "");

				if (strcmp(nvram_safe_get(wl_nvname("ssid", unit, 0)), apinfos[i].SSID)) {
					if (strcmp(apinfos[i].SSID, ""))
						fprintf(fp, "\"%s\"", "0");				// none
					else if (!strcmp(ure_mac, apinfos[i].BSSID)) {
						// hidden AP (null SSID)
						if (strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk")) {
							if (wl_authorized) {
								// in profile, connected
								fprintf(fp, "\"%s\"", "4");
							} else {
								// in profile, connecting
								fprintf(fp, "\"%s\"", "5");
							}
						} else {
							// in profile, connected
							fprintf(fp, "\"%s\"", "4");
						}
					} else {
						// hidden AP (null SSID)
						fprintf(fp, "\"%s\"", "0");				// none
					}
				} else if (!strcmp(nvram_safe_get(wl_nvname("ssid", unit, 0)), apinfos[i].SSID)) {
					if (!strlen(ure_mac)) {
						// in profile, disconnected
						fprintf(fp, "\"%s\"", "1");
					} else if (!strcmp(ure_mac, apinfos[i].BSSID)) {
						if (strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk")) {
							if (wl_authorized) {
								// in profile, connected
								fprintf(fp, "\"%s\"", "2");
							} else {
								// in profile, connecting
								fprintf(fp, "\"%s\"", "3");
							}
						} else {
							// in profile, connected
							fprintf(fp, "\"%s\"", "2");
						}
					} else {
						fprintf(fp, "\"%s\"", "0");				// impossible...
					}
				} else {
					// wl0_ssid is empty
					fprintf(fp, "\"%s\"", "0");
				}
#ifdef RTCONFIG_AMAS
				fprintf(fp, ",\"%d\"", apinfos[i].amas);
#endif
				fprintf(fp, "\n");
			}	/* for */
			fclose(fp);
		}
	}	/* if */

	return retval;
}
#endif

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
#define	MAX_STA_COUNT	128
#define	NVRAM_BUFSIZE	100
#define	WL_IW_RSSI_NO_SIGNAL	-91	/* NDIS RSSI link quality cutoffs */

int get_psta_rssi(int unit)
{
	char tmp[256], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	char word[256], *next;
	int unit_max = 0, unit_cur = -1;
	char *mode = NULL;
	int sta = 0, wet = 0, psta = 0, psr = 0;
	int rssi = WL_IW_RSSI_NO_SIGNAL;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next)
		unit_max++;

	if (unit > (unit_max - 1))
		goto ERROR;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	mode = nvram_safe_get(strcat_r(prefix, "mode", tmp));
	sta = !strcmp(mode, "sta");
	wet = !strcmp(mode, "wet");
	psta = !strcmp(mode, "psta");
	psr = !strcmp(mode, "psr");

	wl_ioctl(ifname, WLC_GET_INSTANCE, &unit_cur, sizeof(unit_cur));
	if (unit != unit_cur)
		goto ERROR;
	else if (!(wet || sta || psta || psr))
		goto ERROR;
	else if (wl_ioctl(ifname, WLC_GET_RSSI, &rssi, sizeof(rssi))) {
		dbg("can not get rssi info of %s\n", ifname);
		goto ERROR;
	} else {
		rssi = dtoh32(rssi);
	}

ERROR:
	return rssi;
}
#endif

#ifdef RTCONFIG_WIRELESSREPEATER
/*
 *  Return value:
 *  	2 = successfully connected to parent AP
 */
int get_wlc_status(char *wif)
{
	char ure_mac[18];
	unsigned char bssid[6];
	unsigned char bssid_null[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	struct maclist *authorized;
	int maclist_size;
	int max_sta_count = 128;
	int wl_authorized = 0;
	int wl_associated = 0;
	int wl_psk = 0;
	wlc_ssid_t wst = { 0, "" };
	int unit = -1;

	wl_ioctl(wif, WLC_GET_INSTANCE, &unit, sizeof(unit));
	wl_psk = strstr(nvram_safe_get(wl_nvname("akm", unit, 0)), "psk") ? 1 : 0;

	if (wl_ioctl(wif, WLC_GET_SSID, &wst, sizeof(wst))) {
		//dbg("[wlc] WLC_GET_SSID error\n");
		goto wl_ioctl_error;
	}

	memset(ure_mac, 0x0, 18);
	if (!wl_ioctl(wif, WLC_GET_BSSID, bssid, sizeof(bssid))
		&& memcmp(bssid, bssid_null, ETHER_ADDR_LEN)) {
		wl_associated = 1;
		ether_etoa((const unsigned char *) &bssid, ure_mac);
	} else {
		//dbg("[wlc] WLC_GET_BSSID error\n");
		goto wl_ioctl_error;
	}

	if (wl_psk) {
		maclist_size = sizeof(authorized->count) +
							max_sta_count * sizeof(struct ether_addr);
		authorized = malloc(maclist_size);

		if (authorized) {
			// query wl for authorized sta list
			strcpy((char*)authorized, "autho_sta_list");

			if (!wl_ioctl(wif, WLC_GET_VAR, authorized, maclist_size)) {
				if (authorized->count > 0) wl_authorized = 1;
				free(authorized);
			} else {
				free(authorized);
				dbg("[wlc] Authorized failed\n");
				goto wl_ioctl_error;
			}
		}
	}

	if (!wl_associated) {
		dbg("[wlc] not wl_associated\n");
	}

	//dbg("[wlc] wl-associated [%d]\n", wl_associated);
	//dbg("[wlc] %s\n", wst.SSID);
	//dbg("[wlc] %s\n", nvram_safe_get(wl_nvname("ssid", unit, 0)));
	if (wl_associated &&
		!strncmp((const char *) wst.SSID, nvram_safe_get(wl_nvname("ssid", unit, 0)), wst.SSID_len))
	{
		if (wl_psk
			&& !dpsr_mode()
#ifdef RTCONFIG_DPSTA
			&& !(dpsta_mode()||rp_mode())
#endif
			) {
			if (wl_authorized)
			{
				dbg("[wlc] wl_authorized\n");
				return 2;
			} else {
				dbg("[wlc] not wl_authorized\n");
				return 1;
			}
		} else {
			//dbg("[wlc] wl_psk:[%d]\n",wl_psk);
			return 2;
		}
	} else {
		dbg("[wlc] Not associated\n");
		return 0;
	}

wl_ioctl_error:
	return 0;
}


// TODO: wlcconnect_main
//	wireless ap monitor to connect to ap
//	when wlc_list, then connect to it according to priority
int wlcconnect_core(void)
{
	int ret = 0;
	char word[256], *next;
	unsigned char SEND_NULLDATA[]={ 0x73, 0x65, 0x6e, 0x64,
					0x5f, 0x6e, 0x75, 0x6c,
					0x6c, 0x64, 0x61, 0x74,
					0x61, 0x00, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xff};
	unsigned char bssid[6];
	int unit = 0;
	char wl_ifnames[32] = { 0 };

	/* return WLC connection status */
	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		// only one client in a system
		if (is_ure(unit)) {
			//dbg("[rc] [%s] is URE mode\n", word);
			memset(bssid, 0xff, 6);
			if (!wl_ioctl(word, WLC_GET_BSSID, bssid, sizeof(bssid))) {
				memcpy(SEND_NULLDATA + 14, bssid, 6);

				// wl send_nulldata xx:xx:xx:xx:xx:xx
				wl_ioctl(word, WLC_SET_VAR, SEND_NULLDATA,
					sizeof(SEND_NULLDATA));
			}
			ret = get_wlc_status(word);
			dbg("[wlc][%s] get_wlc_status:[%d]\n", word, ret);

			break;
		}

		unit++;
	}

	return ret;
}
#endif

#if 0
bool
wl_check_assoc_scb(char *ifname)
{
	bool connected = TRUE;
	int result = 0;
	int ret = 0;

	ret = wl_iovar_getint(ifname, "scb_assoced", &result);
	if (ret) {
		dbg("failed to get scb_assoced\n");
		return connected;
	}

	connected = dtoh32(result) ? TRUE : FALSE;
	return connected;
}

int
wl_phy_rssi_ant(char *ifname)
{
	char buf[WLC_IOCTL_MAXLEN];
	int ret = 0;
	uint i;
	wl_rssi_ant_t *rssi_ant_p;

	if (!ifname)
		return -1;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, "phy_rssi_ant");

	if ((ret = wl_ioctl(ifname, WLC_GET_VAR, &buf[0], WLC_IOCTL_MAXLEN)) < 0)
		return ret;

	rssi_ant_p = (wl_rssi_ant_t *)buf;
	rssi_ant_p->version = dtoh32(rssi_ant_p->version);
	rssi_ant_p->count = dtoh32(rssi_ant_p->count);

	if (rssi_ant_p->count == 0) {
		dbg("not supported on this chip\n");
	} else {
		if ((rssi_ant_p->rssi_ant[0]) &&
		    (rssi_ant_p->rssi_ant[1] < -100) &&
		    ((rssi_ant_p->count > 2)?(rssi_ant_p->rssi_ant[2] < -100) : 1))
		{
			for (i = 0; i < rssi_ant_p->count; i++)
				dbg("rssi[%d] %d  ", i, rssi_ant_p->rssi_ant[i]);
			dbg("\n");
		}
	}

	return ret;
}
#endif

#ifdef RTAC3200
extern struct nvram_tuple router_defaults[];

void
bsd_defaults(void)
{
	char extendno_org[14];
	int ext_num;
	char ext_commit_str[8];
	struct nvram_tuple *t;

	if (!strlen(nvram_safe_get("extendno_org")) ||
		nvram_match("extendno_org", nvram_safe_get("extendno")))
		return;

	strcpy(extendno_org, nvram_safe_get("extendno_org"));
	if (!strlen(extendno_org) ||
		sscanf(extendno_org, "%d-g%s", &ext_num, ext_commit_str) != 2)
		return;

	for (t = router_defaults; t->name; t++)
		if (strstr(t->name, "bsd"))
			nvram_set(t->name, t->value);
}
#endif

#ifdef RTCONFIG_BCMWL6
int
wl_check_chanspec()
{
	wl_uint32_list_t *list;
	chanspec_t c, cur, chansp_40m, chansp_80m;
	int ret = 0, i;
	char data_buf[WLC_IOCTL_MAXLEN];
	char chanbuf[CHANSPEC_STR_LEN];
	char word[256], *next;
	char tmp[256], tmp2[256], prefix[] = "wlXXXXXXXXXX_";
	int unit = 0;
	int ctrl_ch_cur;
	int match;
	int match_ctrl_ch;
	int match_40m_ch;
	int match_80m_ch;
	unsigned int count;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		snprintf(prefix, sizeof(prefix), "wl%d_", unit++);
		c = 0;
		ctrl_ch_cur = -1;
		chansp_40m = 0;
		chansp_80m = 0;
		match = 0;
		match_ctrl_ch = 0;
		match_40m_ch = 0;
		match_80m_ch = 0;

		if (!nvram_get_int(strcat_r(prefix, "chanspec", tmp)))
			continue;

		memset(data_buf, 0, WLC_IOCTL_MAXLEN);
		ret = wl_iovar_getbuf(word, "chanspecs", &c, sizeof(chanspec_t),
			data_buf, WLC_IOCTL_MAXLEN);
		if (ret < 0) {
			dbg("failed to get valid chanspec list\n");
			continue;
		}

		list = (wl_uint32_list_t *)data_buf;
		count = dtoh32(list->count);

		if (!count) {
			dbg("number of valid chanspec is 0\n");
			continue;
		} else if (count > (data_buf + sizeof(data_buf) - (char *)&list->element[0])/sizeof(list->element[0])) {
			dbg("number of valid chanspec %d is invalid\n", count);
			continue;
		} else {
			cur = wf_chspec_aton(nvram_safe_get(strcat_r(prefix, "chanspec", tmp)));

			if (wf_chspec_ntoa(cur, chanbuf) != NULL)
				for (i = 0; i < count; i++) {
					c = (chanspec_t)dtoh32(list->element[i]);
					if (c == cur) {
						match = 1;
						break;
					}
				}

			if (match) continue;

			dbg("chanspec %s is invalid\n", nvram_safe_get(strcat_r(prefix, "chanspec", tmp)));

			ctrl_ch_cur = nvram_get_int(tmp);
			for (i = 0; i < count; i++) {
				c = (chanspec_t)dtoh32(list->element[i]);
				if (wf_chspec_ctlchan(c) == ctrl_ch_cur) {
					if (!match_ctrl_ch)
					{
						match_ctrl_ch = 1;
					}

					if (!match_40m_ch && CHSPEC_IS40(c)) {
						match_40m_ch = 1;
						chansp_40m = c;
					}

					if (!match_80m_ch && CHSPEC_IS80(c)) {
						match_80m_ch = 1;
					chansp_80m = c;
					}
				}
			}
		}

		if (match_80m_ch) {
			dbg("downgraded to 80M chanspec\n");
			nvram_set(strcat_r(prefix, "chanspec", tmp), wf_chspec_ntoa(chansp_80m, chanbuf));
		} else if (match_40m_ch) {
			dbg("downgraded to 40M chanspec\n");
			nvram_set(strcat_r(prefix, "chanspec", tmp), wf_chspec_ntoa(chansp_40m, chanbuf));
		} else if (match_ctrl_ch) {
			dbg("downgraded to 20M chanspec\n");
			nvram_set_int(strcat_r(prefix, "chanspec", tmp), wf_chspec_ctlchan(wf_chspec_aton(nvram_safe_get(strcat_r(prefix, "chanspec", tmp2)))));
		} else {
			dbg("downgraded to auto chanspec\n");
			nvram_set_int(strcat_r(prefix, "chanspec", tmp), 0);
			nvram_set_int(strcat_r(prefix, "bw", tmp), 0);
		}

		dbg("fixed chanspec: %s\n", nvram_safe_get(strcat_r(prefix, "chanspec", tmp)));
	}

	return ret;
}

#define CHANNEL_5G_BAND_GROUP(c) \
	(((c) < 52) ? 1 : (((c) < 100) ? 2 : (((c) < 149) ? 3 : (((c) < 169) ? 4 : 5))))

void
wl_check_5g_band_group()
{
	wl_uint32_list_t *list;
	chanspec_t c;
	int ret = 0, i;
	char data_buf[WLC_IOCTL_MAXLEN];
	char word[256], *next;
	char tmp[100], tmp2[100], prefix[] = "wlXXXXXXXXXX_";
	int unit = 0;
	unsigned int count, band5grp;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		snprintf(prefix, sizeof(prefix), "wl%d_", unit++);
		c = 0;

		if (!nvram_match(strcat_r(prefix, "nband", tmp), "1")) continue;
#if defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
		if (nvram_get_int(strcat_r(prefix, "failed", tmp)) >= 3) continue;
#endif
		memset(data_buf, 0, WLC_IOCTL_MAXLEN);
		ret = wl_iovar_getbuf(word, "chanspecs", &c, sizeof(chanspec_t),
			data_buf, WLC_IOCTL_MAXLEN);
		if (ret < 0) {
			dbg("failed to get valid chanspec list\n");
			continue;
		}

		list = (wl_uint32_list_t *)data_buf;
		count = dtoh32(list->count);

		if (!count) {
			dbg("number of valid chanspec is 0\n");
			continue;
		} else if (count > (data_buf + sizeof(data_buf) - (char *)&list->element[0])/sizeof(list->element[0])) {
			dbg("number of valid chanspec %d is invalid\n", count);
			continue;
		} else
			for (i = 0, band5grp = 0; i < count; i++) {
				c = (chanspec_t)dtoh32(list->element[i]);
				band5grp |= 1 << (CHANNEL_5G_BAND_GROUP(wf_chspec_ctlchan(c)) - 1);
			}

		sprintf(tmp2, "%x", band5grp);
		nvram_set(strcat_r(prefix, "band5grp", tmp), tmp2);
	}
}
#endif

#ifdef __CONFIG_DHDAP__
int wl_channel_valid(char *wif, int channel)
{
	int channels[MAXCHANNEL+1];
	wl_uint32_list_t *list = (wl_uint32_list_t *) channels;
	int i;

	memset(channels, 0, sizeof(channels));
	list->count = htod32(MAXCHANNEL);
	if (wl_ioctl(wif, WLC_GET_VALID_CHANNELS , channels, sizeof(channels)) < 0)
	{
		dbg("error doing WLC_GET_VALID_CHANNELS\n");
		return 0;
	}

	if (dtoh32(list->count) == 0)
		return 0;

	for (i = 0; i < dtoh32(list->count) && i < IW_MAX_FREQUENCIES; i++)
		if (channel == dtoh32(list->element[i]))
			return 1;

	return 0;
}

int wl_subband(char *wif, int idx)
{
	int count = 0;
	int band;

	wl_ioctl(wif, WLC_GET_BAND, &band, sizeof(band));
	if (band != WLC_BAND_5G)
		return -1;

	if (wl_channel_valid(wif, 36))
	{
		if (++count == idx)
			return 1;
	}

	if (wl_channel_valid(wif, 52))
	{
		if (++count == idx)
			return 2;
	}

	if (wl_channel_valid(wif, 100))
	{
		if (++count == idx)
			return 3;
	}

	if (wl_channel_valid(wif, 149))
	{
		if (++count == idx)
			return 4;
	}

	return -1;
}
#endif

#define DOT11_MAX_SSID_LEN	32	/* d11 max ssid length */
#define SSID_FMT_BUF_LEN	((4 * DOT11_MAX_SSID_LEN) + 1)

int
wl_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len)
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

int
getSSID(int unit)
{
	char tmp[100], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	wlc_ssid_t ssid;
	char ssidbuf[SSID_FMT_BUF_LEN];

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	ssid.SSID_len = 0;
	wl_ioctl(ifname, WLC_GET_SSID, &ssid, sizeof(wlc_ssid_t));

	memset(ssidbuf, 0, sizeof(ssidbuf));
	wl_format_ssid(ssidbuf, ssid.SSID, dtoh32(ssid.SSID_len));

	puts(ssidbuf);

	return 0;
}

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_BCMARM)
/* workaround for BCMWL6 only */
static void set_mrate(const char* ifname, const char* prefix)
{
	float mrate = 0;
	char tmp[100];

	switch (nvram_get_int(strcat_r(prefix, "mrate_x", tmp))) {
	case 0: /* Auto */
		mrate = 0;
		break;
	case 1: /* Legacy CCK 1Mbps */
		mrate = 1;
		break;
	case 2: /* Legacy CCK 2Mbps */
		mrate = 2;
		break;
	case 3: /* Legacy CCK 5.5Mbps */
		mrate = 5.5;
		break;
	case 4: /* Legacy OFDM 6Mbps */
		mrate = 6;
		break;
	case 5: /* Legacy OFDM 9Mbps */
		mrate = 9;
		break;
	case 6: /* Legacy CCK 11Mbps */
		mrate = 11;
		break;
	case 7: /* Legacy OFDM 12Mbps */
		mrate = 12;
		break;
	case 8: /* Legacy OFDM 18Mbps */
		mrate = 18;
		break;
	case 9: /* Legacy OFDM 24Mbps */
		mrate = 24;
		break;
	case 10: /* Legacy OFDM 36Mbps */
		mrate = 36;
		break;
	case 11: /* Legacy OFDM 48Mbps */
		mrate = 48;
		break;
	case 12: /* Legacy OFDM 54Mbps */
		mrate = 54;
		break;
	default: /* Auto */
		mrate = 0;
		break;
	}

	sprintf(tmp, "wl -i %s mrate %.1f", ifname, mrate);
	system(tmp);
}
#endif

#ifdef RTCONFIG_HND_ROUTER_AX
#if defined(RPAX56) || defined(RPAX58)
#define DY_ED_SETUP_INC_STEP 6
#else
#define DY_ED_SETUP_INC_STEP 2
#endif
#define DY_ED_SETUP_DEC_STEP 2
#define DY_ED_SETUP_TH_HIGH -45
#define DY_ED_SETUP_TH_LOW -65
#define DY_ED_SETUP_SED_UPPER 30
#define DY_ED_SETUP_SED_LOWER 5
#define DY_ED_SETUP_SED_DIS 90
#define DY_RD_SETUP_MON_WIN 2
void enable_dy_ed_thresh(char *ifname)
{
	wlc_rev_info_t revinfo;
	dynamic_ed_setup_t setup;
	int ret, setcnt=0;
	uint chipid;

	memset(&revinfo, 0, sizeof(revinfo));
	if ((ret = wl_ioctl(ifname, WLC_GET_REVINFO, &revinfo, sizeof(revinfo))) < 0) {
		dbg("%s: failed to get revinfo\n", ifname);
	}
	else {
		chipid = revinfo.chipnum;
		if (BCM43684_CHIP(chipid) || BCM4365_CHIP(chipid) || BCM6710_CHIP(chipid)
#ifdef RTCONFIG_HND_ROUTER_AX_6756
			|| BCM6715_CHIP(chipid)
#endif
		) {	// enable dynamic ed thresh run in phy + ucode
			_dprintf("%s: %s set dy_ed_thresh\n", __func__, ifname);
			eval("wl", "-i", (char *) ifname, "dy_ed_thresh", (nvram_get_int("no_dy_ed_thresh_ctrl") == -1) ? "0" : "1");
			eval("wl", "-i", (char *) ifname, "dy_ed_thresh_acphy", (nvram_get_int("no_dy_ed_thresh_ctrl") == -1) ? "0" : "1");

			memset(&setup, 0, sizeof(dynamic_ed_setup_t));
			while(setcnt < 10) {
				usleep(200000);
				setcnt++;
				ret = wl_iovar_getbuf(ifname, "dy_ed_setup", NULL, 0, &setup, sizeof(dynamic_ed_setup_t));
				if (ret < 0)
					dbg("failed to get dy_ed_setup\n");
				else {
					if (setup.ed_th_high != DY_ED_SETUP_TH_HIGH || setup.ed_th_low != DY_ED_SETUP_TH_LOW ||
							setup.ed_inc_step != DY_ED_SETUP_INC_STEP || setup.ed_dec_step != DY_ED_SETUP_DEC_STEP ||
							setup.sed_upper_bound != DY_ED_SETUP_SED_UPPER || setup.sed_lower_bound != DY_ED_SETUP_SED_LOWER ||
							setup.ed_monitor_window != DY_RD_SETUP_MON_WIN || setup.sed_dis != DY_ED_SETUP_SED_DIS) {
						setup.ed_th_high = DY_ED_SETUP_TH_HIGH;
						setup.ed_th_low = DY_ED_SETUP_TH_LOW;
						setup.ed_inc_step = DY_ED_SETUP_INC_STEP;
						setup.ed_dec_step = DY_ED_SETUP_DEC_STEP;
						setup.sed_upper_bound = DY_ED_SETUP_SED_UPPER;
						setup.sed_lower_bound = DY_ED_SETUP_SED_LOWER;
						setup.ed_monitor_window = DY_RD_SETUP_MON_WIN;
						setup.sed_dis = DY_ED_SETUP_SED_DIS;
						ret = wl_iovar_set(ifname, "dy_ed_setup", &setup, sizeof(setup));
						if (ret) {
							dbg("failed to set dy_ed_setup on %s\n",  ifname);
						}
						continue;
					}
					break;
				}
			}
		}
		else {	// enable dynamic ed thresh run in wlc_ap_watchdog()
			eval("wl", "-i", (char *) ifname, "dy_ed_thresh_wdg", (nvram_get_int("no_dy_ed_thresh_ctrl") == -1) ? "0" : "1");
		}
	}
}
#endif

#if defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
#ifndef	FFSCHED_FLOW_RING_RESET_DELAY
#define	FFSCHED_FLOW_RING_RESET_DELAY	"350"
#endif
#endif

int wlconf(char *ifname, int unit, int subunit)
{
	int r;
	char wl[24];
	int txpower;
	int model = get_model();
	char tmp[100], prefix[] = "wlXXXXXXXXXXXXXX";
#ifdef __CONFIG_DHDAP__
	int is_dhd = !dhd_probe(ifname);
#endif
#if defined(RTCONFIG_AMAS) && (defined(RTCONFIG_FRONTHAUL_DWB) || defined(RTCONFIG_MSSID_PRELINK) || defined(RTCONFIG_VIF_ONBOARDING) || defined(RTCONFIG_FRONTHAUL_DBG))
	int max_no_vifs = wl_max_no_vifs(unit);
#endif

#ifdef RTCONFIG_QTN
	if (!strcmp(ifname, "wifi0"))
		unit = 1;
#else
	if (wl_probe(ifname)) return -1;
#endif
	if (unit < 0) return -1;

	if (subunit < 0)
	{
#ifdef RTCONFIG_QTN
		if (unit == 1)
			goto GEN_CONF;
#endif
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

#if 0
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		if (psta_exist_except(unit) || psr_exist_except(unit))
		{
			eval("wlconf", ifname, "down");
			eval("wl", "-i", ifname, "radio", "off");
			return -1;
		}
#endif
#endif

#ifdef RTCONFIG_QTN
GEN_CONF:
#endif
#if defined(RTCONFIG_BCMWL6) && !defined(RTCONFIG_BCM_MFG)
#ifdef RTCONFIG_MFGFW
		if(!nvram_match("mfgfw", "1"))
#endif
		wl_check_chanspec();
#endif
		generate_wl_para(ifname, unit, subunit);

#if defined(RTCONFIG_AMAS) && (defined(RTCONFIG_FRONTHAUL_DWB) || defined(RTCONFIG_MSSID_PRELINK) || defined(RTCONFIG_VIF_ONBOARDING) || defined(RTCONFIG_FRONTHAUL_DBG))
		for (r = 1; r < max_no_vifs; r++)
#else
		for (r = 1; r < MAX_NO_MSSID; r++)	// early convert for wlx.y
#endif
			generate_wl_para(ifname, unit, r);

		if (nvram_match(strcat_r(prefix, "radio", tmp), "0"))
		{
			eval("wlconf", ifname, "down");
			eval("wl", "-i", ifname, "radio", "off");
			return -1;
		}
	}

#if 0
	if (/* !wl_probe(ifname) && */ unit >= 0) {
		// validate nvram settings foa wireless i/f
		snprintf(wl, sizeof(wl), "--wl%d", unit);
		eval("nvram", "validate", wl);
	}
#endif

#ifdef RTCONFIG_QTN
	if (unit == 1)
		return -1;
#endif

	if (unit >= 0 && subunit < 0)
	{
#ifdef RTCONFIG_OPTIMIZE_XBOX
		if (nvram_match(strcat_r(prefix, "optimizexbox", tmp), "1"))
			eval("wl", "-i", ifname, "ldpc_cap", "0");
		else
			eval("wl", "-i", ifname, "ldpc_cap", "1");	// driver default setting
#endif
#ifdef RTCONFIG_BCMWL6
#if !defined(RTCONFIG_BCM7) && !defined(RTCONFIG_BCM_7114) && !defined(RTCONFIG_BCM9) && !defined(HND_ROUTER)
		if (nvram_match(strcat_r(prefix, "ack_ratio", tmp), "1"))
			eval("wl", "-i", ifname, "ack_ratio", "4");
		else
			eval("wl", "-i", ifname, "ack_ratio", "2");	// driver default setting
#endif
		if (nvram_match(strcat_r(prefix, "ampdu_mpdu", tmp), "1"))
			eval("wl", "-i", ifname, "ampdu_mpdu", "64");
		else
#if !defined(RTCONFIG_BCM7)
			eval("wl", "-i", ifname, "ampdu_mpdu", "-1");	// driver default setting
#else
			eval("wl", "-i", ifname, "ampdu_mpdu", "32");	// driver default setting
#endif
#ifdef RTCONFIG_BCMARM
		if (nvram_match(strcat_r(prefix, "ampdu_rts", tmp), "1"))
			eval("wl", "-i", ifname, "ampdu_rts", "1");	// driver default setting
		else
			eval("wl", "-i", ifname, "ampdu_rts", "0");
#if 0
		if (nvram_match(strcat_r(prefix, "itxbf", tmp), "1"))
			eval("wl", "-i", ifname, "txbf_imp", "1");	// driver default setting
		else
			eval("wl", "-i", ifname, "txbf_imp", "0");
#endif
#if defined(RTCONFIG_BCM_7114)
		if (nvram_match(strcat_r(prefix, "atf", tmp), "1")) {
			if (nvram_match(strcat_r(prefix, "atf_delay_disable", tmp), "1"))
				eval("wl", "-i", ifname, "bus:ffsched_flr_rst_delay", "0");				// disable atf delay scheme
			else
				eval("wl", "-i", ifname, "bus:ffsched_flr_rst_delay", FFSCHED_FLOW_RING_RESET_DELAY);	// driver default setting
		}

#if defined(RTAC5300)
		if (!strcmp(ifname, "eth1"))
			eval("wl", "-i", ifname, "txcore", "-k", "0x7");
#endif
#endif

#if defined(HND_ROUTER)
		if (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") &&
		    nvram_match(strcat_r(prefix, "dfs_bw_fallback", tmp), "1"))
			eval("wl", "-i", ifname, "dfs_bw_fallback", "1");
#endif
#if (defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX)) || defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)
		if (!nvram_match("no_dy_ed_thresh_ctrl", "1"))
		eval("wl", "-i", ifname, "dy_ed_thresh", (nvram_get_int("no_dy_ed_thresh_ctrl") == -1) ? "0" : "1");
#endif
#ifndef RTCONFIG_BCM_MFG
#if defined(RTCONFIG_BCM7) || defined(HND_ROUTER)
#if defined(__CONFIG_DHDAP__) && !(defined(RTAX86U) || defined(RTAX5700))
		if (is_dhd)
#endif
		eval("wl", "-i", ifname, "msglevel", "+err", "+assoc");
#endif
#endif
#if defined(RTCONFIG_HND_ROUTER_AX)
		if (nvram_match(strcat_r(prefix, "twt", tmp), "1"))
		    eval("wl", "-i", ifname, "twt", "1");
		else
		    eval("wl", "-i", ifname, "twt", "0");
#endif
#endif /* RTCONFIG_BCMARM */
#else
		eval("wl", "-i", ifname, "ampdu_density", "6");		// resolve IOT with Intel STA for BRCM SDK 5.110.27.20012
#endif /* RTCONFIG_BCMWL6 */
	}

	r = eval("wlconf", ifname, "up");
	if (r == 0) {
		if (unit >= 0 && subunit < 0) {
#ifdef REMOVE
			// setup primary wl interface
			nvram_set("rrules_radio", "-1");
			eval("wl", "-i", ifname, "antdiv", nvram_safe_get(wl_nvname("antdiv", unit, 0)));
			eval("wl", "-i", ifname, "txant", nvram_safe_get(wl_nvname("txant", unit, 0)));
			eval("wl", "-i", ifname, "txpwr1", "-o", "-m", nvram_get_int(wl_nvname("txpwr", unit, 0)) ? nvram_safe_get(wl_nvname("txpwr", unit, 0)) : "-1");
			eval("wl", "-i", ifname, "interference", nvram_safe_get(wl_nvname("interfmode", unit, 0)));
#endif
#ifndef RTCONFIG_BCMARM
			switch (model) {
				default:
					if ((unit == 0) &&
						nvram_match(strcat_r(prefix, "noisemitigation", tmp), "1"))
					{
						eval("wl", "-i", ifname, "interference_override", "4");
						eval("wl", "-i", ifname, "phyreg", "0x547", "0x4444");
						eval("wl", "-i", ifname, "phyreg", "0xc33", "0x280");
					}
					break;
			}
#else
#ifdef RTCONFIG_PROXYSTA
			if (psta_exist_except(unit)/* || psr_exist_except(unit)*/)
			{
				eval("wl", "-i", ifname, "closed", "1");
				eval("wl", "-i", ifname, "maxassoc", "0");
			}
#endif
			set_mrate(ifname, prefix);

			if (nvram_match(strcat_r(prefix, "ampdu_rts", tmp), "0") &&
				nvram_match(strcat_r(prefix, "nmode", tmp), "-1"))
				eval("wl", "-i", ifname, "rtsthresh", "65535");

			if (nvram_match(strcat_r(prefix, "frameburst_disable", tmp), "1"))
				eval("wl", "-i", ifname, "frameburst", "0");

			wl_dfs_radarthrs_config(ifname, unit);

#endif /* RTCONFIG_BCMWL6 */
			txpower = nvram_get_int(wl_nvname("txpower", unit, 0));

			dbG("unit: %d, txpower: %d%\n", unit, txpower);

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_DPSTA) && defined(RTCONFIG_HAS_5G_2) && !defined(RTCONFIG_HND_ROUTER_AX)
			if (dpsta_mode() && unit == 1 && nvram_get_int("re_mode") == 1) {	/* for 5G low, fixed channel is 36 and bandwidth 80Mhz */
				chanspec_t fixed_36_80m = wf_chspec_aton("36/80");

				wl_iovar_setint(ifname, "chanspec", (uint32)fixed_36_80m);
			}
			else
#endif
			{
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
			/* workaround client CSA 80m chanspec support */
			if (unit && is_psr(unit) && nvram_match(strcat_r(prefix, "reg_mode", tmp), "h")) {
				chanspec_t chanspec = 0;
				if (nvram_get_hex(wl_nvname("band5grp", unit, subunit)) & WL_5G_BAND_2)
					chanspec = wf_chspec_aton("52/80");
				else if (nvram_get_hex(wl_nvname("band5grp", unit, subunit)) & WL_5G_BAND_3)
					chanspec = wf_chspec_aton("100/80");
				if (chanspec)
					wl_iovar_setint(ifname, "chanspec", (uint32)chanspec);
			}
#endif
			}

			switch (model) {
				default:
					eval("wl", "-i", ifname, "txpwr1", "-1");

					break;
			}
		}

		if (wl_client(unit, subunit)) {
			if (nvram_match(wl_nvname("mode", unit, subunit), "wet")) {
				ifconfig(ifname, IFUP | IFF_ALLMULTI, NULL, NULL);
			}
			if (nvram_get_int(wl_nvname("radio", unit, 0))) {
				snprintf(wl, sizeof(wl), "%d", unit);
				xstart("radio", "join", wl);
			}
		}
	}
	return r;
}

void wlconf_pre()
{
#ifdef RTCONFIG_BCMWL6
	int unit = 0;
	char word[256], *next;
#if (!defined(RTCONFIG_BCM_7114) && !defined(HND_ROUTER)) || (defined(RTCONFIG_HSPOT) && defined(RTCONFIG_HND_ROUTER_AX)) || defined(RTCONFIG_WIFI6E)
	char tmp[128], tmp2[128], prefix[] = "wlXXXXXXXXXX_";
#endif
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		// early convertion for nmode setting
		generate_wl_para(word, unit, -1);
#ifdef RTCONFIG_QTN
		if (!strcmp(word, "wifi0")) break;
#endif
#if !defined(RTCONFIG_BCM_7114) && !defined(HND_ROUTER)
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (hw_vht_cap() &&
		   ((nvram_match(strcat_r(prefix, "nband", tmp), "1") &&
		     nvram_match(strcat_r(prefix, "vreqd", tmp2), "1"))
#if !defined(RTCONFIG_BCM9) && !defined(RTAC56U) && !defined(RTAC56S)
		 || (nvram_match(strcat_r(prefix, "nband", tmp), "2") &&
		     nvram_get_int(strcat_r(prefix, "turbo_qam", tmp2)))
#endif
		)) {
#ifdef RTCONFIG_BCMARM
#if !defined(RTCONFIG_BCM9) && !defined(RTAC56U) && !defined(RTAC56S)
			if (nvram_match(strcat_r(prefix, "nband", tmp), "2"))
			{
				if (nvram_match(strcat_r(prefix, "turbo_qam", tmp), "1"))
					eval("wl", "-i", word, "vht_features", "3");
			}
#endif
#endif // RTCONFIG_BCMARM
			dbG("set vhtmode 1\n");
			eval("wl", "-i", word, "vhtmode", "1");
		}
		else
		{
			dbG("set vhtmode 0\n");
			eval("wl", "-i", word, "vht_features", "0");
			eval("wl", "-i", word, "vhtmode", "0");
		}
#endif

#if defined(RTCONFIG_HSPOT) && defined(RTCONFIG_HND_ROUTER_AX)
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (nvram_match(strcat_r(prefix, "mbo_enable", tmp), "1"))
			nvram_set(strcat_r(prefix, "hsflag", tmp), "1aa4");
		else
			nvram_set(strcat_r(prefix, "hsflag", tmp), "1aa0");
		nvram_commit();
#endif
#if defined(RTCONFIG_WIFI6E)
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (nvram_match(strcat_r(prefix, "nband", tmp), "4")) {
			nvram_set(strcat_r(prefix, "upr_fd_enable", tmp), "0");
			nvram_set(strcat_r(prefix, "nbr_discovery_cap", tmp), "0");
			 nvram_commit();
		}
#endif
		unit++;
	}
#endif	// RTCONFIG_BCMWL6
}

#if defined(RTCONFIG_WIFI6E)
#define IS_6G_PSC_CHAN(channel) (((channel) % 16u) == 5u)
void apply_oob_scan_6g(char *ifname, int unit)
{
	char prefix[] = "wlXXXXXXXXXX_";
	char tmp[64];
	char bssid_6g[18] = {0};
	char rclass_6g[16] = {0};
	char channel_6g[16] = {0};
	char phytype_6g[16] = {0};
	char ssid_6g[128] = {0};
	char chanspec_6g[16] = {0};

	char ioctl_buf[256];
	char *cmd_rclass = "rclass";
	int cmd_len;
	char *param;
	int buflen;
	channel_info_t ci;
	int phytype;
	wlc_ssid_t ssid;
	chanspec_t chanspec = 0;
	char word[256], *next;
	char cmd[1024];

	//BSSID
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	snprintf(bssid_6g, sizeof(bssid_6g), nvram_safe_get(strcat_r(prefix, "hwaddr", tmp)));

	//CHANNEL
	if (wl_ioctl(ifname, WLC_GET_CHANNEL, &ci, sizeof(ci)))
		return;
	snprintf(channel_6g, sizeof(channel_6g), "%d", ci.target_channel);
	/* remove oob scan configuration if operates at PSC channel */
	if(IS_6G_PSC_CHAN(ci.target_channel) || nvram_match(strcat_r(prefix, "chanspec", tmp), "0")) {
		_dprintf("Operating under PSC channel, skip apply oob scan\n");
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
		    if (wl_get_band(word) != WLC_BAND_6G) {
			eval("wl", "-i", word, "nbr_discovery_cap", "0");
			eval("wl", "-i", word, "oce", "enable", "0");
			eval("wl", "-i", word, "rrm_nbr_del_nbr", bssid_6g);
		    }
		}
		return;
	}

	//CHANSPEC & RCLASS
	if (wl_iovar_get(ifname, "chanspec", &chanspec, sizeof(chanspec_t)))
	    return;
	snprintf(chanspec_6g, sizeof(chanspec_6g), "0x%x", chanspec);
	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	cmd_len = strlen(cmd_rclass);
	memcpy(ioctl_buf, cmd_rclass, cmd_len);
	memcpy(ioctl_buf + cmd_len + 1, &chanspec, sizeof(chanspec_t));
	if (wl_ioctl(ifname, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf)))
		return;
	snprintf(rclass_6g, sizeof(rclass_6g), "%d", (uint8)(*((uint32 *)ioctl_buf)));

	//PHYTYPE
	if (wl_ioctl(ifname, WLC_GET_PHYTYPE, &phytype, sizeof(phytype)))
		return;
	snprintf(phytype_6g, sizeof(phytype_6g), "%d", phytype);

	//SSID
	if (wl_ioctl(ifname, WLC_GET_SSID, &ssid, sizeof(ssid)))
		return;
	snprintf(ssid_6g, sizeof(ssid_6g), "%s", ssid.SSID);

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
	    if (wl_get_band(word) != WLC_BAND_6G) {
		snprintf(cmd, sizeof(cmd), "wl -i %s rrm_nbr_add_nbr %s 255 %s %s %s %s %s 1 110", 
				word, bssid_6g, rclass_6g, channel_6g, phytype_6g, ssid_6g, chanspec_6g);
		_dprintf("[%s]\n", cmd);
		eval("wl", "-i", word, "rrm_nbr_add_nbr", bssid_6g, "255", rclass_6g, channel_6g, phytype_6g, ssid_6g, chanspec_6g, "1", "110");
		eval("wl", "-i", word, "nbr_discovery_cap", "1");
		eval("wl", "-i", word, "oce", "enable", "1");
	    }
	}
}
#endif

void wlconf_post(const char *ifname)
{
	int unit = -1;
	char prefix[] = "wlXXXXXXXXXX_";
	char tmp[100];

	if (ifname == NULL) return;

	// get the instance number of the wl i/f
	if (wl_ioctl((char *) ifname, WLC_GET_INSTANCE, &unit, sizeof(unit)))
		return;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

#ifdef RTAC66U
	char tmp[100];
	if (!strcmp(ifname, "eth2")) {
		if (nvram_match(strcat_r(prefix, "country_code", tmp), "Q2") &&
			nvram_match(strcat_r(prefix, "country_rev", tmp), "33"))
		eval("wl", "-i", (char *) ifname, "radioreg", "0x892", "0x5068", "cr0");
	}
#endif

#ifdef RTAC68U
	if (is_ac66u_v2_series()) {
		if (unit) eval("wl", "-i", (char *) ifname, "radioreg", "0x892", "0x4068");
		eval("wl", "-i", (char *) ifname, "aspm", "3");
	}
#endif

#ifdef TUFAX5400
	if (unit &&
		(!strncmp(nvram_safe_get("territory_code"), "EU", 2) ||
		 !strncmp(nvram_safe_get("territory_code"), "IL", 2) ||
		 !strncmp(nvram_safe_get("territory_code"), "UK", 2)))
		eval("dhd", "-i", "eth6", "aspm", "3");
#endif

#ifdef RTCONFIG_BCMWL6
	if (is_ure(unit))
		eval("wl", "-i", (char *) ifname, "allmulti", "1");
#endif
	if (nvram_match(strcat_r(prefix, "nband", tmp), "2") &&
	    nvram_match(strcat_r(prefix, "rateset", tmp), "ofdm")) {
		doSystem("wl -i %s down", ifname);
		doSystem("wl -i %s rateset 6b 9 12b 18 24b 36 48 54", ifname);
		doSystem("wl -i %s up", ifname);
	}
#if defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
	if (nvram_match(strcat_r(prefix, "vhtmode", tmp), "0"))
	{
		eval("wl", "-i", (char *) ifname, "down");
		eval("wl", "-i", (char *) ifname, "vhtmode", "0");
		eval("wl", "-i", (char *) ifname, "up");
	}
#endif

#ifdef RTCONFIG_HND_ROUTER_AX
	if (!nvram_match("no_dy_ed_thresh_ctrl", "1") && 
		strncmp(nvram_safe_get("territory_code"), "JP", 2) &&
#ifdef RTCONFIG_WIFI6E
		!nvram_match(strcat_r(prefix, "nband", tmp), "4") &&
#endif
		wl_check_is_primary_ifce(ifname)) {
			enable_dy_ed_thresh((char *) ifname);
	}

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_DPSTA)
	char dpsta_if[IFNAMSIZ] = {0};
	char *next_dpsta;
	int enable = 1;
	char dpsta_ifnames[32] = { 0 };

	if (dpsta_mode() && nvram_get_int("re_mode") == 1 && find_in_list(nvram_safe_get("sta_ifnames"), ifname)) {
		eval("wl", "-i", (char *) ifname, "down");

		strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));
		foreach(dpsta_if, dpsta_ifnames, next_dpsta) {
			/* disable keep_ap_up for 5G backhaul interface only */
			if (!strcmp(dpsta_if, ifname) && nvram_match(strcat_r(prefix, "nband", tmp), "1")) {
				enable = 0;
				break;
			}
		}
		if(enable)
			eval("wl", "-i", (char *) ifname, "keep_ap_up", "1");
		else
			eval("wl", "-i", (char *) ifname, "keep_ap_up", "0");

		eval("wl", "-i", (char *) ifname, "up");
	}
#endif

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_AMAS_ADTBW)
	char nvifname[32];
	if(num_of_wl_if() > 2)
		unit = 2;
	else
		unit = 1;

	snprintf(nvifname, sizeof(nvifname), "wl%d_ifname", unit);
	if (!strcmp(ifname, nvram_safe_get(nvifname))) {
		eval("wl", "-i", (char *) ifname, "down");
		eval("wl", "-i", (char *) ifname, "bw_switch_160", "1");
		eval("wl", "-i", (char *) ifname, "up");
	}
#endif
#endif
#if defined(RTAX56_XD4)
	if(nvram_match("HwId", "B") || nvram_match("HwId", "D")){
		if(nvram_get_int("x_Setting") == 0){
			if(strcmp(ifname, "wl0") == 0 || strcmp(ifname, "wl1") == 0){
				eval("wl", "-i", (char *) ifname, "closed", "1");
			}
		}
	}
#endif

#if 0
#if defined(RTCONFIG_WIFI6E)
	/* while 6G is operating under non PSC channel, apply neighbor report to 2.4G/5G for OOB Scan */
	if (wl_get_band(ifname) == WLC_BAND_6G)
		apply_oob_scan_6g(ifname, unit);
#endif
#endif

#ifdef RTCONFIG_HND_ROUTER_AX_6756
	wlc_rev_info_t revinfo;
	int band = WLC_BAND_ALL;
	memset(&revinfo, 0, sizeof(revinfo));
	wl_ioctl(ifname, WLC_GET_REVINFO, &revinfo, sizeof(revinfo));
	wl_ioctl(ifname, WLC_GET_BAND, &band, sizeof(band));
	if (BCM6715_CHIP(revinfo.chipnum) && band == WLC_BAND_5G) {
		char *str = nvram_safe_get(strcat_r(prefix, "hwaddr", tmp));
		char eaddr[32], bsscolor[32];
		ether_atoe(str, (unsigned char *)eaddr);
		snprintf(bsscolor, sizeof(bsscolor), "%d", (eaddr[5] & 0x7));
		eval("wl", "-i", (char *) ifname, "he", "bsscolor", bsscolor);
	}
#endif
}

/*
 * Carry out a socket request including openning and closing the socket
 * Return -1 if failed to open socket (and perror); otherwise return
 * result of ioctl
 */
static int
soc_req(const char *name, int action, struct ifreq *ifr)
{
	int s;
	int rv = 0;

	if (name == NULL) return -1;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket");
		return -1;
	}
	strncpy(ifr->ifr_name, name, IFNAMSIZ);
	ifr->ifr_name[IFNAMSIZ-1] = '\0';
	rv = ioctl(s, action, ifr);
	close(s);

	return rv;
}

/* Set the HW address for interface "name" if present in NVRam */
void
wl_vif_hwaddr_set(const char *name)
{
	int rc;
	char *ea;
	char hwaddr[20];
	struct ifreq ifr;
	int retry = 0;
	unsigned char comp_mac_address[ETHER_ADDR_LEN];
#ifdef RTCONFIG_HND_ROUTER_AX
        int was_up;
#endif
	snprintf(hwaddr, sizeof(hwaddr), "%s_hwaddr", name);
	ea = nvram_get(hwaddr);
	if (ea == NULL) {
		fprintf(stderr, "NET: No hw addr found for %s\n", name);
		return;
	}

#ifdef RTCONFIG_QTN
	if (strcmp(name, "wl1.1") == 0 ||
		strcmp(name, "wl1.2") == 0 ||
		strcmp(name, "wl1.3") == 0)
		return;
#endif
	fprintf(stderr, "NET: Setting %s hw addr to %s\n", name, ea);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	ether_atoe(ea, (unsigned char *)ifr.ifr_hwaddr.sa_data);
	ether_atoe(ea, comp_mac_address);
#ifdef RTCONFIG_HND_ROUTER_AX
        wl_ioctl((char *) name, WLC_GET_UP, &was_up, sizeof(was_up));
        if (was_up)
                wl_ioctl((char *) name, WLC_DOWN, NULL, 0);
#endif
	if ((rc = soc_req(name, SIOCSIFHWADDR, &ifr)) < 0) {
		fprintf(stderr, "NET: Error setting hw for %s; returned %d\n", name, rc);
	}
	memset(&ifr, 0, sizeof(ifr));
	while (retry < 100) { /* maximum 100 millisecond waiting */
		usleep(1000); /* 1 ms sleep */
		if ((rc = soc_req(name, SIOCGIFHWADDR, &ifr)) < 0) {
			if (retry == 99)
				fprintf(stderr, "\nNET: Error Getting hw for %s; returned %d\n", name, rc);
			else
				fprintf(stderr, ".");
		}
		if (memcmp(comp_mac_address, (unsigned char *)ifr.ifr_hwaddr.sa_data,
			ETHER_ADDR_LEN) == 0) {
			break;
		}
		retry++;
	}
	if (retry >= 100) {
		fprintf(stderr, "Unable to check if mac was set properly for %s\n", name);
	}
#ifdef RTCONFIG_HND_ROUTER_AX
        if (was_up)
                wl_ioctl((char *) name, WLC_UP, NULL, 0);
#endif
}

/* Set initial QoS mode for all et interfaces that are up. */
void
set_et_qos_mode(void)
{
	int i, s, qos = 0;
	struct ifreq ifr;
	struct ethtool_drvinfo info;
	char tmp[100], prefix[] = "wlXXXXXXXXXXXXXX";

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return;

	for (i = 0; i < num_of_wl_if(); i++) {
		snprintf(prefix, sizeof(prefix), "wl%d_", i);
		if (!nvram_match(strcat_r(prefix, "wme", tmp), "off")) {
			qos = 1;
			break;
		}
	}

	for (i = 1; i <= DEV_NUMIFS; i ++) {
		ifr.ifr_ifindex = i;
		if (ioctl(s, SIOCGIFNAME, &ifr))
			continue;
		if (ioctl(s, SIOCGIFHWADDR, &ifr))
			continue;
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
			continue;
		if (ioctl(s, SIOCGIFFLAGS, &ifr))
			continue;
		if (!(ifr.ifr_flags & IFF_UP))
			continue;
		/* Set QoS for et & bcm57xx devices */
		memset(&info, 0, sizeof(info));
		info.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&info;
		if (ioctl(s, SIOCETHTOOL, &ifr) < 0)
			continue;
		if ((strncmp(info.driver, "et", 2) != 0) &&
		    (strncmp(info.driver, "bcm57", 5) != 0))
			continue;
		ifr.ifr_data = (caddr_t)&qos;
		ioctl(s, SIOCSETCQOS, &ifr);
	}

	close(s);
}

#ifndef REMOVE
int set_wlmac(int idx, int unit, int subunit, void *param)
{
	char *ifname;

	ifname = nvram_safe_get(wl_nvname("ifname", unit, subunit));

	// skip disabled wl vifs
	if (strncmp(ifname, "wl", 2) == 0 && strchr(ifname, '.') &&
		!nvram_get_int(wl_nvname("bss_enabled", unit, subunit)))
		return 0;

	set_mac(ifname, wl_nvname("macaddr", unit, subunit),
		2 + unit + ((subunit > 0) ? ((unit + 1) * 0x10 + subunit) : 0));

	return 1;
}

void check_afterburner(void)
{
	char *p;

	if (nvram_match("wl_afterburner", "off")) return;
	if ((p = nvram_get("boardflags")) == NULL) return;

	if (strcmp(p, "0x0118") == 0) {			// G 2.2, 3.0, 3.1
		p = "0x0318";
	}
	else if (strcmp(p, "0x0188") == 0) {	// G 2.0
		p = "0x0388";
	}
	else if (strcmp(p, "0x2558") == 0) {	// G 4.0, GL 1.0, 1.1
		p = "0x2758";
	}
	else {
		return;
	}

	nvram_set("boardflags", p);

	if (!nvram_match("debug_abrst", "0")) {
		modprobe_r("wl");
		modprobe("wl");
	}


/*	safe?

	unsigned long bf;
	char s[64];

	bf = strtoul(p, &p, 0);
	if ((*p == 0) && ((bf & BFL_AFTERBURNER) == 0)) {
		sprintf(s, "0x%04lX", bf | BFL_AFTERBURNER);
		nvram_set("boardflags", s);
	}
*/
}
#endif

/*
 * EAP module
 */

int
wl_send_dif_event(const char *ifname, uint32 event)
{
	static int s = -1;
	int len, n;
	struct sockaddr_in to;
	char data[IFNAMSIZ + sizeof(uint32)];

	if (ifname == NULL) return -1;

	/* create a socket to receive dynamic i/f events */
	if (s < 0) {
		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0) {
			perror("socket");
			return -1;
		}
	}

	/* Init the message contents to send to eapd. Specify the interface
	 * and the event that occured on the interface.
	 */
	strncpy(data, ifname, IFNAMSIZ);
	*(uint32 *)(data + IFNAMSIZ) = event;
	len = IFNAMSIZ + sizeof(uint32);

	/* send to eapd */
	to.sin_addr.s_addr = inet_addr(EAPD_WKSP_UDP_ADDR);
	to.sin_family = AF_INET;
	to.sin_port = htons(EAPD_WKSP_DIF_UDP_PORT);

	n = sendto(s, data, len, 0, (struct sockaddr *)&to,
		sizeof(struct sockaddr_in));

	if (n != len) {
		perror("udp send failed\n");
		return -1;
	}

	_dprintf("hotplug_net(): sent event %d\n", event);

	return n;
}

static int is_same_addr(struct ether_addr *addr1, struct ether_addr *addr2)
{
	int i;
	for (i = 0; i < 6; i++) {
		if (addr1->octet[i] != addr2->octet[i])
			return 0;
	}
	return 1;
}

#define WL_MAX_ASSOC	128
int check_wl_client(char *ifname, int unit, int subunit)
{
	struct ether_addr bssid;
	wl_bss_info_t *bi;
	char buf[WLC_IOCTL_MAXLEN];
	struct maclist *mlist;
	int mlsize, i;
	int associated, authorized;

	*(uint32*)buf = htod32(WLC_IOCTL_MAXLEN);
	if (wl_ioctl(ifname, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN) < 0 ||
	    wl_ioctl(ifname, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN) < 0)
		return 0;

	bi = (wl_bss_info_t *)(buf + 4);
	if ((bi->SSID_len == 0) ||
	    (bi->BSSID.octet[0] + bi->BSSID.octet[1] + bi->BSSID.octet[2] +
	     bi->BSSID.octet[3] + bi->BSSID.octet[4] + bi->BSSID.octet[5] == 0))
		return 0;

	associated = 0;
	authorized = strstr(nvram_safe_get(wl_nvname("akm", unit, subunit)), "psk") == 0;

	mlsize = sizeof(struct maclist) + (WL_MAX_ASSOC * sizeof(struct ether_addr));
	if ((mlist = malloc(mlsize)) != NULL) {
		mlist->count = WL_MAX_ASSOC;
		if (wl_ioctl(ifname, WLC_GET_ASSOCLIST, mlist, mlsize) == 0) {
			for (i = 0; i < mlist->count; ++i) {
				if (is_same_addr(&mlist->ea[i], &bi->BSSID)) {
					associated = 1;
					break;
				}
			}
		}

		if (associated && !authorized) {
			memset(mlist, 0, mlsize);
			mlist->count = WL_MAX_ASSOC;
			strcpy((char*)mlist, "autho_sta_list");
			if (wl_ioctl(ifname, WLC_GET_VAR, mlist, mlsize) == 0) {
				for (i = 0; i < mlist->count; ++i) {
					if (is_same_addr(&mlist->ea[i], &bi->BSSID)) {
						authorized = 1;
						break;
					}
				}
			}
		}
		free(mlist);
	}
	return (associated && authorized);
}

#ifdef RTCONFIG_BCMWL6
void led_bh_prep(int post)
{
#if defined(RTAX86U) || defined(RTAX68U)
	char productid[16], *wifi_2g, *wifi_5g;
	snprintf(productid, sizeof(productid), "%s", get_productid());
	if(!strcmp(productid, "RT-AX86S") || !strcmp(productid, "RT-AX68U")){
		wifi_2g = "eth5";
		wifi_5g = "eth6";
	} else {
		wifi_2g = "eth6";
		wifi_5g = "eth7";
	}
#endif

	switch (get_model()) {
		case MODEL_RTAC56S:
		case MODEL_RTAC56U:
			if (post)
			{
				eval("wl", "ledbh", "3", "7");
				eval("wl", "-i", "eth2", "ledbh", "10", "7");
			}
			else
			{
				eval("wl", "ledbh", "3", "1");
				eval("wl", "-i", "eth2", "ledbh", "10", "1");
				led_control(LED_5G, LED_ON);
				eval("wlconf", "eth1", "up");
				eval("wl", "maxassoc", "0");
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
			}
			break;
		case MODEL_RTAC5300:
		case MODEL_GTAC5300:
		case MODEL_RTAC88U:
		case MODEL_RTAC86U:
		case MODEL_RTAC3100:
		case MODEL_RTAX88U:
		case MODEL_GTAX11000:
		case MODEL_RTAX92U:
		case MODEL_RTAX95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_RTAXE95Q:
		case MODEL_ET8PRO:
		case MODEL_RTAX56_XD4:
		case MODEL_XD4PRO:
		case MODEL_CTAX56_XD4:
		case MODEL_RTAX58U:
		case MODEL_RTAX82_XD6S:
		case MODEL_RTAX58U_V2:
		case MODEL_TUFAX3000_V2:
		case MODEL_RTAXE7800:
		case MODEL_RTAX55:
		case MODEL_RTAX56U:
		case MODEL_RPAX56:
		case MODEL_RPAX58:
		case MODEL_RTAX86U:
		case MODEL_RTAX68U:
		case MODEL_RTAC68U_V4:
		case MODEL_GTAXE11000:
		case MODEL_GTAX6000:
		case MODEL_GTAX11000_PRO:
		case MODEL_GTAXE16000:
		case MODEL_ET12:
		case MODEL_XT12:
			if (post)
			{
#if defined(GTAC5300) || defined(GTAXE11000)
				eval("wl", "-i", "eth6", "ledbh", "9", "7");
				eval("wl", "-i", "eth7", "ledbh", "9", "7");
				eval("wl", "-i", "eth8", "ledbh", "9", "7");
#elif defined(GTAX11000)
				eval("wl", "-i", "eth6", "ledbh", "15", "7");
				eval("wl", "-i", "eth7", "ledbh", "15", "7");
				eval("wl", "-i", "eth8", "ledbh", "15", "7");
#elif defined(RTAX88U)
				eval("wl", "-i", "eth6", "ledbh", "15", "7");
				eval("wl", "-i", "eth7", "ledbh", "15", "7");
#elif defined(RTAX92U)
				eval("wl", "-i", "eth5", "ledbh", "9", "7");    // wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "9", "7");    // wl 5G low
				eval("wl", "-i", "eth7", "ledbh", "9", "7");    // wl 5G high
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
				eval("wl", "-i", "eth4", "ledbh", "9", "7");    // wl 2.4G
				eval("wl", "-i", "eth5", "ledbh", "9", "7");    // wl 5G low
				eval("wl", "-i", "eth6", "ledbh", "9", "7");    // wl 5G high
//#elif defined(RPAX56)
//				eval("wl", "-i", "eth1", "ledbh", "0", "25");    // wl 2.4G
//				eval("wl", "-i", "eth2", "ledbh", "0", "25");    // wl 5G
#elif defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
				eval("wl", "-i", "wl0", "ledbh", "9", "7");    // wl 2.4G
				eval("wl", "-i", "wl1", "ledbh", "9", "7");    // wl 5G low
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
				eval("wl", "-i", "eth2", "ledbh", "0", "25");	// wl 2.4G
				eval("wl", "-i", "eth3", "ledbh", "0", "25");	// wl 5G
#elif defined(TUFAX3000_V2)
				eval("wl", "-i", "eth5", "ledbh", "0", "25");	// wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "0", "25");	// wl 5G
#elif defined(RTAXE7800)
				eval("wl", "-i", "eth5", "ledbh", "0", "25");	// wl 2.4G
				eval("wl", "-i", "eth7", "ledbh", "15", "7");	// wl 5G
				eval("wl", "-i", "eth6", "ledbh", "0", "25");	// wl 6G
#elif defined(GTAX6000)
				eval("wl", "-i", "eth6", "ledbh", "13", "7");
				eval("wl", "-i", "eth7", "ledbh", "13", "7");
#elif defined(GTAX11000_PRO)
				eval("wl", "-i", "eth6", "ledbh", "13", "7");
				eval("wl", "-i", "eth7", "ledbh", "13", "7");
				eval("wl", "-i", "eth8", "ledbh", "13", "7");
#elif defined(GTAXE16000)
				eval("wl", "-i", "eth7", "ledbh", "13", "7");
				eval("wl", "-i", "eth8", "ledbh", "13", "7");
				eval("wl", "-i", "eth9", "ledbh", "13", "7");
				eval("wl", "-i", "eth10", "ledbh", "13", "7");
#elif defined(RTAX82_XD6S)
				eval("wl", "-i", "eth2", "ledbh", "0", "25");	// wl 2.4G
#elif defined(BCM6750)
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
				if (!nvram_get_int("LED_order"))
					eval("wl", "-i", "eth5", "ledbh", "0", "1");
				else
#endif
				eval("wl", "-i", "eth5", "ledbh", "0", "25");	// wl 2.4G
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
				if (!nvram_get_int("LED_order"))
					;
				else
#endif
				eval("wl", "-i", "eth6", "ledbh", "15", "7");	// wl 5G low
#elif defined(RTAX56U)
				eval("wl", "-i", "eth5", "ledbh", "0", "25");    // wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "0", "25");    // wl 5G
#elif defined(RTAX86U) || defined(RTAX5700)
				eval("wl", "-i", wifi_2g, "ledbh", "7", "7");    // wl 2.4G
				eval("wl", "-i", wifi_5g, "ledbh", "15", "7");    // wl 5G
#elif defined(RTAX68U)
				eval("wl", "-i", "eth5", "ledbh", "7", "7");    // wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "7", "7");    // wl 5G
#elif defined(RTAC68U_V4)
				eval("wl", "-i", "eth5", "ledbh", "10", "7");
				eval("wl", "-i", "eth6", "ledbh", "10", "7");
#elif defined(RTAC86U)
				eval("wl", "ledbh", "9", "7");
				eval("wl", "-i", "eth6", "ledbh", "9", "7");
#elif defined(GTAC2900)
				eval("wl", "ledbh", "9", "1");
				eval("wl", "-i", "eth6", "ledbh", "9", "1");
#else
				eval("wl", "ledbh", "9", "7");
				eval("wl", "-i", "eth2", "ledbh", "9", "7");
#ifdef RTAC5300
				eval("wl", "-i", "eth3", "ledbh", "9", "7");
#endif
#endif
			}
			else
			{
#if defined(GTAC5300) || defined(GTAXE11000)
				eval("wl", "-i", "eth6", "ledbh", "9", "1");
				eval("wl", "-i", "eth7", "ledbh", "9", "1");
				eval("wl", "-i", "eth8", "ledbh", "9", "1");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
				eval("wlconf", "eth7", "up");
				eval("wl", "-i", "eth7", "maxassoc", "0");
				eval("wlconf", "eth8", "up");
				eval("wl", "-i", "eth8", "maxassoc", "0");
#elif defined(GTAX11000)
				eval("wl", "-i", "eth6", "ledbh", "15", "1");
				eval("wl", "-i", "eth7", "ledbh", "15", "1");
				eval("wl", "-i", "eth8", "ledbh", "15", "1");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
				eval("wlconf", "eth7", "up");
				eval("wl", "-i", "eth7", "maxassoc", "0");
				eval("wlconf", "eth8", "up");
				eval("wl", "-i", "eth8", "maxassoc", "0");
#elif defined(RTAX88U)
				eval("wl", "-i", "eth6", "ledbh", "15", "1");
				eval("wl", "-i", "eth7", "ledbh", "15", "1");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
				eval("wlconf", "eth7", "up");
				eval("wl", "-i", "eth7", "maxassoc", "0");
#elif defined(RTAX92U)
				eval("wl", "-i", "eth5", "ledbh", "9", "1");    // wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "9", "1");    // wl 5G low
				eval("wl", "-i", "eth7", "ledbh", "9", "1");    // wl 5G high
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
				eval("wlconf", "eth7", "up");
				eval("wl", "-i", "eth7", "maxassoc", "0");
#elif defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO)
				eval("wl", "-i", "eth4", "ledbh", "9", "1");    // wl 2.4G
				eval("wl", "-i", "eth5", "ledbh", "9", "1");    // wl 5G low
				eval("wl", "-i", "eth6", "ledbh", "9", "1");    // wl 5G high
				eval("wlconf", "eth4", "up");
				eval("wl", "-i", "eth4", "maxassoc", "0");
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(RTAX56_XD4) || defined(XD4PRO) || defined(CTAX56_XD4)
				eval("wl", "-i", "wl0", "ledbh", "9", "1");    // wl 2.4G
				eval("wl", "-i", "wl1", "ledbh", "9", "1");    // wl 5G low
				eval("wlconf", "wl0", "up");
				eval("wl", "-i", "wl0", "maxassoc", "0");
				eval("wlconf", "wl1", "up");
				eval("wl", "-i", "wl1", "maxassoc", "0");
#elif defined(RTAX55) || defined(RTAX1800) || defined(RTAX58U_V2)
				eval("wl", "-i", "eth2", "ledbh", "0", "1");    // wl 2.4G
				eval("wl", "-i", "eth3", "ledbh", "0", "1");    // wl 5G
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
				eval("wlconf", "eth3", "up");
				eval("wl", "-i", "eth3", "maxassoc", "0");
#elif defined(TUFAX3000_V2)
				eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 5G
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(RTAXE7800)
				eval("wl", "-i", "eth5", "ledbh", "0", "1");	// wl 2.4G
				eval("wl", "-i", "eth7", "ledbh", "15", "1");	// wl 5G
				eval("wl", "-i", "eth6", "ledbh", "0", "1");	// wl 6G
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth7", "maxassoc", "0");
				eval("wlconf", "eth7", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(GTAX11000)
				eval("wl", "-i", "eth7", "ledbh", "15", "1");
				eval("wl", "-i", "eth8", "ledbh", "15", "1");
				eval("wl", "-i", "eth9", "ledbh", "15", "1");
				eval("wlconf", "eth7", "up");
				eval("wl", "-i", "eth7", "maxassoc", "0");
				eval("wlconf", "eth8", "up");
				eval("wl", "-i", "eth8", "maxassoc", "0");
				eval("wlconf", "eth9", "up");
				eval("wl", "-i", "eth9", "maxassoc", "0");
#elif defined(RTAX82_XD6S)
				eval("wl", "-i", "eth2", "ledbh", "0", "1");	// wl 2.4G
				eval("wl", "-i", "eth3", "ledbh", "15", "1");	// wl 5G
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
				eval("wlconf", "eth3", "up");
				eval("wl", "-i", "eth3", "maxassoc", "0");
#elif defined(BCM6750)
				eval("wl", "-i", "eth5", "ledbh", "0", "1");    // wl 2.4G
#if defined(RTAX82U) && !defined(RTCONFIG_BCM_MFG)
				if (!nvram_get_int("LED_order"))
					;
				else
#endif
				eval("wl", "-i", "eth6", "ledbh", "15", "1");	// wl 5G
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(RTAX86U) || defined(RTAX5700)
				eval("wl", "-i", wifi_2g, "ledbh", "7", "1");
				eval("wl", "-i", wifi_5g, "ledbh", "15", "1");
				eval("wlconf", wifi_2g, "up");
				eval("wl", "-i", wifi_2g, "maxassoc", "0");
				eval("wlconf", wifi_5g, "up");
				eval("wl", "-i", wifi_5g, "maxassoc", "0");
#elif defined(RTAX68U)
				eval("wl", "-i", "eth5", "ledbh", "7", "1");
				eval("wl", "-i", "eth6", "ledbh", "7", "1");
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(RTAC68U_V4)
				eval("wl", "-i", "eth5", "ledbh", "10", "1");
				eval("wl", "-i", "eth6", "ledbh", "10", "1");
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(RTAX56U)
				eval("wl", "-i", "eth5", "ledbh", "0", "1");    // wl 2.4G
				eval("wl", "-i", "eth6", "ledbh", "0", "1");    // wl 5G
				eval("wlconf", "eth5", "up");
				eval("wl", "-i", "eth5", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#elif defined(RPAX56) || defined(RPAX58)
//				eval("wl", "-i", "eth1", "ledbh", "0", "1");    // wl 2.4G
//				eval("wl", "-i", "eth2", "ledbh", "0", "1");    // wl 5G
				eval("wlconf", "eth1", "up");
				eval("wl", "-i", "eth1", "maxassoc", "0");
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
#elif defined(RTAC86U) || defined(GTAC2900)
				eval("wl", "ledbh", "9", "1");
				eval("wl", "-i", "eth6", "ledbh", "9", "1");
				eval("wlconf", "eth5", "up");
				eval("wl", "maxassoc", "0");
				eval("wlconf", "eth6", "up");
				eval("wl", "-i", "eth6", "maxassoc", "0");
#else
				eval("wl", "ledbh", "9", "1");
				eval("wl", "-i", "eth2", "ledbh", "9", "1");
#ifdef RTAC5300
				eval("wl", "-i", "eth3", "ledbh", "9", "1");
#endif
				eval("wlconf", "eth1", "up");
				eval("wl", "maxassoc", "0");
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
#ifdef RTAC5300
				eval("wlconf", "eth3", "up");
				eval("wl", "-i", "eth3", "maxassoc", "0");
#endif
#endif
			}
			break;
		case MODEL_RTAC3200:
		case MODEL_DSLAC68U:
		case MODEL_RTAC68U:
		case MODEL_RTAC87U:
			if (post)
			{
				eval("wl", "ledbh", "10", "7");
				eval("wl", "-i", "eth2", "ledbh", "10", "7");

#if defined(RTAC3200)
				eval("wl", "-i", "eth3", "ledbh", "10", "7");
#endif
			}
			else
			{
				eval("wl", "ledbh", "10", "1");
				eval("wl", "-i", "eth2", "ledbh", "10", "1");
#if defined(RTAC3200)
				eval("wl", "-i", "eth3", "ledbh", "10", "1");
#endif
#ifdef DSL_AC68U
				led_control(LED_5G, LED_ON);
#endif
#ifdef RTCONFIG_LOGO_LED
				led_control(LED_LOGO, LED_ON);
#endif
				eval("wlconf", "eth1", "up");
				eval("wl", "maxassoc", "0");
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
#if defined(RTAC3200)
				eval("wlconf", "eth3", "up");
				eval("wl", "-i", "eth3", "maxassoc", "0");
#endif
			}
			break;
		case MODEL_RTAC53U:
			if (post)
			{
				eval("wl", "-i", "eth1", "ledbh", "3", "7");
				eval("wl", "-i", "eth2", "ledbh", "9", "7");
			}
			else
			{
				eval("wl", "-i", "eth1", "ledbh", "3", "1");
				eval("wl", "-i", "eth2", "ledbh", "9", "1");
				eval("wlconf", "eth1", "up");
				eval("wl", "maxassoc", "0");
				eval("wlconf", "eth2", "up");
				eval("wl", "-i", "eth2", "maxassoc", "0");
			}
			break;
		default:
			break;
	}
}
#endif

#if defined(RTCONFIG_AMAS)

/**
 * @brief Disassociate from the current BSS/IBSS.
 *
 * @param wif Interface name.
 * @return int Zero is success. Others is fail.
 */
static int wlc_disassoc(char* wif)
{
	int ret = -1;
	if ((ret = wl_ioctl(wif, WLC_DISASSOC, NULL, 0)) != 0)
		dbg("Interface %s disassoc fail. ret=%d\n", wif, ret);

	return ret;
}

#ifdef RTCONFIG_BRCM_HOSTAPD
void apply_config_to_driver_wlc(int band)
{
	char tmp[NVRAM_BUFSIZE], prefix[16], prefix2[16];
	char command[128];
	char wif[IFNAMSIZ] = { 0 };
	char wpa_cli_path[64];
	char filename[128] = {0};
	char wpa_supp_prefix[16] = {0};
	uint32 flags = 0;

	if(band >= 0)
	{
		snprintf(prefix, sizeof(prefix), "wl%d_", band);
		snprintf(prefix2, sizeof(prefix2), "wlc%d_", band);

		if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "psk"))
			nvram_set(strcat_r(prefix, "akm", tmp), "psk");
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "psk2"))
		{
#if defined(HND_ROUTER) && defined(WLHOSTFBT)
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2 psk2ft");
#else
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2");
#endif
		}
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "pskpsk2"))
#if defined(HND_ROUTER) && defined(WLHOSTFBT)
			nvram_set(strcat_r(prefix, "akm", tmp), "psk psk2 psk2ft");
#else
			nvram_set(strcat_r(prefix, "akm", tmp), "psk psk2");
#endif
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "sae"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "sae");
		}
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "psk2sae"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2 sae");
		}
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "wpa"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa");
		}
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "wpa2"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa2");
		}
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "wpawpa2"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa wpa2");
		}
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "owe"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "owe");
		}
#ifdef RTCONFIG_OWE_TRANS
		else if (nvram_match(strcat_r(prefix2, "auth_mode", tmp), "openowe")) //OWE-Trainsition mode
		{
			// TBD
		}
#endif
		else nvram_set(strcat_r(prefix, "akm", tmp), "");

		char *config_val;
		config_val = nvram_safe_get(strcat_r(prefix2, "wpa_psk", tmp));
		nvram_set(strcat_r(prefix, "wpa_psk", tmp), config_val);

		config_val = nvram_safe_get(strcat_r(prefix2, "ssid", tmp));
		nvram_set(strcat_r(prefix, "ssid", tmp), config_val);

		config_val = nvram_safe_get(strcat_r(prefix2, "crypto", tmp));
		nvram_set(strcat_r(prefix, "crypto", tmp), config_val);

		config_val = nvram_safe_get(strcat_r(prefix2, "wep", tmp));
		nvram_set(strcat_r(prefix, "wep", tmp), config_val);

		config_val = nvram_safe_get(strcat_r(prefix2, "wep_key", tmp));
		nvram_set(strcat_r(prefix, "wep_key", tmp), config_val);


		snprintf(wpa_supp_prefix, sizeof(wpa_supp_prefix), "wl%d", band);
		if (wpa_supp_get_config_filename(wpa_supp_prefix, filename, sizeof(filename), &flags) < 0) {
			dbg("Error to get wpa_supplicant config filename\n");
			return;
		}
#if defined(RTCONFIG_WIFI6E) || defined(RTCONFIG_BCM_502L07P2)
		if (wpa_supp_create_config_file(wpa_supp_prefix, filename, flags, band, NULL) < 0) {
#else
		if (wpa_supp_create_config_file(wpa_supp_prefix, filename, flags) < 0) {
#endif
			dbg("Error to create wpa_supplicant config file\n");
			return;
		}

		_dprintf("%s reload %s\n", __func__, filename);
		snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%s_wpa_supplicant/", wpa_supp_prefix);
		eval("wpa_cli-2.7", "-p", wpa_cli_path,"reconfigure"); //reload configuration
	}
}
#endif

#ifdef RTCONFIG_BHCOST_OPT
#ifdef RTCONFIG_BRCM_HOSTAPD
#if defined(RTCONFIG_WIFI6E) || defined(RTCONFIG_BCM_502L07P2)
typedef struct hapd_wpasupp_wds_info  hapd_wpasupp_wds_info_t;
extern int wpa_supp_create_config_file(char *nv_ifname, char *filename, uint32 flags,
		int idx, hapd_wpasupp_wds_info_t *wdsi_ptr);
#else
extern int wpa_supp_create_config_file(char *prefix, char *filename, uint32 flags);
#endif
extern int wpa_supp_get_config_filename(char *prefix, char *o_fname, int size, uint32 *o_flgs);
#endif
void apply_config_to_driver(int band)
{
	char tmp[NVRAM_BUFSIZE], prefix[16];
	char command[128];
	char wif[IFNAMSIZ] = { 0 };
#ifdef RTCONFIG_BRCM_HOSTAPD
	char wpa_cli_path[64];
	char filename[128] = {0};
	char wpa_supp_prefix[16] = {0};
	uint32 flags = 0;
#endif

	if(band >= 0)
	{
		snprintf(prefix, sizeof(prefix), "wl%d_", band);
		if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "psk"))
			nvram_set(strcat_r(prefix, "akm", tmp), "psk");
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "psk2"))
		{
#if defined(HND_ROUTER) && defined(WLHOSTFBT)
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2 psk2ft");
#else
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2");
#endif
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "pskpsk2"))
#if defined(HND_ROUTER) && defined(WLHOSTFBT)
			nvram_set(strcat_r(prefix, "akm", tmp), "psk psk2 psk2ft");
#else
			nvram_set(strcat_r(prefix, "akm", tmp), "psk psk2");
#endif
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "sae"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "sae");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "psk2sae"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2 sae");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "wpa"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "wpa2"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa2");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "wpawpa2"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa wpa2");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "owe"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "owe");
		}
#ifdef RTCONFIG_OWE_TRANS
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "openowe")) //OWE-Trainsition mode
		{
			// TBD
		}
#endif
		else nvram_set(strcat_r(prefix, "akm", tmp), "");

		strlcpy(wif, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(wif));
		wlc_disassoc(wif);
#ifdef RTCONFIG_BRCM_HOSTAPD
		if(!nvram_match("hapd_enable", "1")) {
#endif
		/* eval() is not safe in threaded environment */
		snprintf(command, sizeof(command), "wlconf %s down", wif);
		system(command);
		snprintf(command, sizeof(command), "wlconf %s up", wif);
		system(command);
		snprintf(command, sizeof(command), "wlconf %s start", wif);
		system(command);
#ifdef RTCONFIG_BRCM_HOSTAPD
		}
#endif
#ifdef RTCONFIG_BRCM_HOSTAPD
		if(nvram_match("hapd_enable", "1")) {
			snprintf(wpa_supp_prefix, sizeof(wpa_supp_prefix), "wl%d", band);
			if (wpa_supp_get_config_filename(wpa_supp_prefix, filename, sizeof(filename), &flags) < 0) {
				dbg("Error to get wpa_supplicant config filename\n");
				return;
			}
#if defined(RTCONFIG_WIFI6E) || defined(RTCONFIG_BCM_502L07P2)
			if (wpa_supp_create_config_file(wpa_supp_prefix, filename, flags, band, NULL) < 0) {
#else
			if (wpa_supp_create_config_file(wpa_supp_prefix, filename, flags) < 0) {
#endif
				dbg("Error to create wpa_supplicant config file\n");
				return;
			}

			dbg("reload %s\n", filename);
			snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%s_wpa_supplicant/", wpa_supp_prefix);
			eval("wpa_cli-2.7", "-p", wpa_cli_path,"reconfigure"); //reload configuration
		}
		else {
#endif
			stop_nas();
			system("nas"); // sync with start_nas
#ifdef RTCONFIG_BRCM_HOSTAPD
		}
#endif
	}
}
#else
#if defined(RTCONFIG_DWB)
#ifdef RTCONFIG_BRCM_HOSTAPD
extern int wpa_supp_create_config_file(char *prefix, char *filename, uint32 flags);
extern int wpa_supp_get_config_filename(char *prefix, char *o_fname, int size, uint32 *o_flgs);
#endif
void apply_config_to_driver()
{
	char tmp[NVRAM_BUFSIZE], prefix[16];
	char command[64];
	char wif[IFNAMSIZ] = { 0 };
#ifdef RTCONFIG_BRCM_HOSTAPD
	char wpa_cli_path[64];
	char filename[128] = {0};
	char wpa_supp_prefix[16] = {0};
	uint32 flags = 0;
#endif

	if(nvram_get_int("dwb_band") > 0)
	{
		snprintf(prefix, sizeof(prefix), "wl%d_", nvram_get_int("dwb_band"));
		if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "psk"))
			nvram_set(strcat_r(prefix, "akm", tmp), "psk");
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "psk2"))
		{
#if defined(HND_ROUTER) && defined(WLHOSTFBT)
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2 psk2ft");
#else
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2");
#endif
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "pskpsk2"))
#if defined(HND_ROUTER) && defined(WLHOSTFBT)
			nvram_set(strcat_r(prefix, "akm", tmp), "psk psk2 psk2ft");
#else
			nvram_set(strcat_r(prefix, "akm", tmp), "psk psk2");
#endif
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "sae"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "sae");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "psk2sae"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "psk2 sae");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "wpa"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "wpa2"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa2");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "wpawpa2"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "wpa wpa2");
		}
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "owe"))
		{
			nvram_set(strcat_r(prefix, "akm", tmp), "owe");
		}
#ifdef RTCONFIG_OWE_TRANS
		else if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "openowe")) //OWE-Trainsition mode
		{
			// TBD
		}
#endif
		else nvram_set(strcat_r(prefix, "akm", tmp), "");

		strlcpy(wif, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(wif));
		wlc_disassoc(wif);
#ifdef RTCONFIG_BRCM_HOSTAPD
	if(!nvram_match("hapd_enable", "1")) {
#endif
		/* eval() is not safe in threaded environment */
		snprintf(command, sizeof(command), "wlconf %s down", wif);
		system(command);
		snprintf(command, sizeof(command), "wlconf %s up", wif);
		system(command);
		snprintf(command, sizeof(command), "wlconf %s start", wif);
		system(command);
#ifdef RTCONFIG_BRCM_HOSTAPD
	}
#endif

#ifdef RTCONFIG_BRCM_HOSTAPD
	if(nvram_match("hapd_enable", "1")) {
		snprintf(wpa_supp_prefix, sizeof(wpa_supp_prefix), "wl%d", nvram_get_int("dwb_band"));
		if (wpa_supp_get_config_filename(wpa_supp_prefix, filename, sizeof(filename), &flags) < 0) {
			dbg("Error to get wpa_supplicant config filename\n");
			return;
		}
		if (wpa_supp_create_config_file(wpa_supp_prefix, filename, flags) < 0) {
			dbg("Error to create wpa_supplicant config file\n");
			return;
		}

		dbg("reload %s\n", filename);
		snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%s_wpa_supplicant/", wpa_supp_prefix);
		snprintf(command, sizeof(command), "wpa_cli-2.7 -p %s reconfigure", wpa_cli_path); // reload configuration
		system(command);
	}
	else {
#endif
	    stop_nas();
	    system("nas"); // sync with start_nas
#ifdef RTCONFIG_BRCM_HOSTAPD
	}
#endif
   }
}
#endif
#endif

int wl_ether_atoe(const char *a, struct ether_addr *n)
{
	char *c = NULL;
	int i = 0;

	memset(n, 0, ETHER_ADDR_LEN);
	for (;;) {
		n->octet[i++] = (uint8)strtoul(a, &c, 16);
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
		a = c;
	}
	return (i == ETHER_ADDR_LEN);
}

#ifdef RTCONFIG_BRCM_HOSTAPD
#define WPASUPP_CTRL_TIMEOUT 90
#endif

#ifdef RTCONFIG_BHCOST_OPT
void Pty_start_wlc_connect(int band, char *bssid)
{
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	int ret = 0;
	wl_join_params_t *join_params = NULL;
	int join_params_size = 0;
	struct ether_addr ether_bcast = {{255, 255, 255, 255, 255, 255}};
	char ssid[33] = { 0 };
	char sec[16] = { 0 };
#ifdef RTCONFIG_BRCM_HOSTAPD
	char wpa_cli_path[64];
	char cmd[128];
	int wait_wpasupp = WPASUPP_CTRL_TIMEOUT;
	DIR* dir;
#endif

	if (band < 0) return;

	if (!get_radio(band, 0)) {
		//dbg("band (%d) is radio off\n", band);
		return;
	}
#if 0
#ifdef RTCONFIG_HND_ROUTER_AX
	int vidx;
	int chansp = 0;
	int bandgrp = 0;
	chanspec_t chanspec = 0;

	for(vidx = 1; vidx < wl_max_no_vifs(band); vidx++) {
		if (!strncmp(nvram_safe_get(wl_nvname("bss_enabled", band, vidx)), "1", 1)) {
			if (wl_iovar_getint(nvram_safe_get(wl_nvname("ifname", band, vidx)), "chanspec", &chansp) < 0)
			    continue;
			else
			    chanspec = (chanspec_t)dtoh32(chansp);

			bandgrp = CHANNEL_5G_BAND_GROUP(wf_chspec_ctlchan(chanspec));
			/* disable bss if channel is located at dfs channel */
			if((bandgrp == 2 || bandgrp == 3 || CHSPEC_IS160(chanspec)) && get_wlan_service_status(band, vidx) > 0)
				set_wlan_service_status(band, vidx, 0);
		}
	}
#endif
#endif

	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	wlc_disassoc(ifname);

#ifdef RTCONFIG_BRCM_HOSTAPD
	if(nvram_match("hapd_enable", "1")) {
		snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%swpa_supplicant/", prefix);
		while(wait_wpasupp) {
			if (wait_wpasupp != WPASUPP_CTRL_TIMEOUT)
			    sleep(1);

			if ((--wait_wpasupp) == 0)
				return;

			if ((dir = opendir(wpa_cli_path)) == NULL) {
				continue;
			}
			else
				closedir(dir);


			if (bssid != NULL) {
				snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s bssid 0 %s", wpa_cli_path, bssid); //connect to specific bssid
				if (!Pty_exec_wpasupp_cmd(cmd))
				    continue;
			}
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s sta_autoconnect 1", wpa_cli_path); //enable autimatic reconnection
			if (!Pty_exec_wpasupp_cmd(cmd))
				continue;
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s reconnect", wpa_cli_path); //trigger reconnection
			if (!Pty_exec_wpasupp_cmd(cmd))
				continue;
			break;
		}

		return;
	}
#endif

	/* allocate the max storage */
	join_params_size = WL_JOIN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(chanspec_t);
	if ((join_params = malloc(join_params_size)) == NULL) {
		dbg("Error allocating %d bytes for assoc params\n", join_params_size);
		goto PTY_START_WLC_CONNECT_EXIT;
	}
	memset(join_params, 0, join_params_size);
	memcpy(&join_params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);

	wlc_disassoc(ifname);
	strlcpy(sec, nvram_safe_get(strcat_r(prefix, "akm", tmp)), sizeof(sec));
	unsigned char ea[ETHER_ADDR_LEN];

	strlcpy(ssid, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), sizeof(ssid));
	join_params->ssid.SSID_len = strlen(ssid);
	memcpy(join_params->ssid.SSID, ssid, join_params->ssid.SSID_len);
	/* default to plain old ioctl */
	join_params_size = sizeof(wlc_ssid_t);

	int auth = 0, wpa_auth = WPA_AUTH_DISABLED;
	if (strstr(sec, "psk2"))
		wpa_auth = WPA2_AUTH_PSK;
	else if (strstr(sec, "psk"))
		wpa_auth = WPA_AUTH_PSK;
	else if (strstr(sec, "wpa2"))
		wpa_auth = WPA2_AUTH_UNSPECIFIED;
	else if (strstr(sec, "wpa"))
		wpa_auth = WPA_AUTH_UNSPECIFIED;
	else if (nvram_get_int(strcat_r(prefix, "auth", tmp)))
		auth = WL_AUTH_SHARED_KEY;
	else
		auth = WL_AUTH_OPEN_SYSTEM;

	/* set authentication mode */
	auth = htod32(auth);
	if ((ret = wl_ioctl(ifname, WLC_SET_AUTH, &auth, sizeof(int))) < 0) {
		dbG("Ifname: %s WLC_SET_AUTH failed. auth val=%d ret=%d\n", ifname, auth, ret);
		goto PTY_START_WLC_CONNECT_EXIT;
	}

	/* set WPA_auth mode */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wl_ioctl(ifname, WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0) {
		dbG("Ifname: %s WLC_SET_WPA_AUTH failed. wpa_auth val=%d ret=%d\n", ifname, wpa_auth, ret);
		goto PTY_START_WLC_CONNECT_EXIT;
	}

	/* set ssid with extend assoc params (BSSID) */
    if (bssid != NULL) {
        if (ether_atoe(bssid, ea)) {
            if (!wl_ether_atoe(bssid, &join_params->params.bssid)) {
                dbG("could not parse as an ethernet MAC address\n");
                goto PTY_START_WLC_CONNECT_EXIT;
            }
            join_params_size = WL_JOIN_PARAMS_FIXED_SIZE +
                dtoh32(join_params->params.chanspec_num) * sizeof(chanspec_t);
        }
    }
	join_params->ssid.SSID_len = htod32(join_params->ssid.SSID_len);
	if ((ret = wl_ioctl(ifname, WLC_SET_SSID, join_params, join_params_size)) < 0) {
		dbG("Ifname: %s WLC_SET_SSID failed. ret=%d\n", ifname, ret);
		goto PTY_START_WLC_CONNECT_EXIT;
	}

PTY_START_WLC_CONNECT_EXIT:
	if (join_params)
		free(join_params);

	return;
}

/**
 * @brief amas_wlcconnect conneced to node successfully.
 *
 * @param band Band index
 */
void post_wlc_connected(int band) {
#ifdef RTCONFIG_BRCM_HOSTAPD
	char prefix[] = "wlXXXXXXXXXX_";
	char wpa_cli_path[64];
	char cmd[128];
	if(nvram_match("hapd_enable", "1")) {
		snprintf(prefix, sizeof(prefix), "wl%d_", band);
		snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%swpa_supplicant/", prefix);
		snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s sta_autoconnect 0", wpa_cli_path); //disable autimatic reconnection
		if (!Pty_exec_wpasupp_cmd(cmd))
			dbG("band(%d) Set sta_autoconnect 0 fail.", band);
	}
#endif
	return;
}

void pre_addif_bridge(int iftype)
{
#ifdef RTCONFIG_DPSTA
	int s = 0;
	struct ifreq ifr;

	if (dpsta_mode() && nvram_get_int("re_mode") == 1) {
		if (iftype > 0 && iftype <= ETH_MAX_BASE) {
			/* Assign hw address, change to locally administered addresses.*/
			if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
				strncpy(ifr.ifr_name, "dpsta", IFNAMSIZ);

				if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
						if ((ifr.ifr_hwaddr.sa_data[0] & 0x02) == 0x00) {
							ifr.ifr_hwaddr.sa_data[0] = ifr.ifr_hwaddr.sa_data[0] | 0x02;
							ioctl(s, SIOCSIFHWADDR, &ifr);
						}
				}
				close(s);
			}
		}
		else {
			/* Assign hw address, change to locally administered addresses.*/
			if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
				strncpy(ifr.ifr_name, "dpsta", IFNAMSIZ);

				if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
						if ((ifr.ifr_hwaddr.sa_data[0] & 0x02) == 0x02) {
							ifr.ifr_hwaddr.sa_data[0] = ifr.ifr_hwaddr.sa_data[0] & ~0x02;
							ioctl(s, SIOCSIFHWADDR, &ifr);
						}
				}
				close(s);
			}
		}
		eval("ifconfig", "dpsta", (iftype > ETH_MAX_BASE && iftype <= WL_MAX_BASE) ? "arp" : "-arp");
	}
#endif
}

/**
 * @brief Get the uplinkports status
 *
 * @param ifname ethernet uplink ifname
 * @return int connnected(1) or not(0)
 */
int get_uplinkports_status(char *ifname)
{
#ifdef HND_ROUTER
	return ethctl_get_link_status(ifname) == 1 ? 1 : 0;
#else
	int wan_unit = wan_primary_ifunit();
	return get_wanports_status(wan_unit);
#endif
}

/**
 * @brief Get DFS status
 *
 * @param band Band
 * @return int Status. 1: CAC 0: Idle
 */
int amas_dfs_status(int band)
{
	int ret = 0;

	if (band == WL_2G_BAND)
		return ret;

    wl_dfs_status_t *dfs_status;
    char buf[WLC_IOCTL_SMLEN], nvram_buf[32] = {}, ifname[16] = {};

    memset(buf, 0, sizeof(buf));
    strcpy(buf, "dfs_status");

	if (nvram_get_int("re_mode") == 1) {
		snprintf(nvram_buf, sizeof(nvram_buf), "wl%d.1_ifname", band);
		strncpy(ifname, nvram_safe_get(nvram_buf), sizeof(ifname));
	} else {
		snprintf(nvram_buf, sizeof(nvram_buf), "wl%d_ifname", band);
		strncpy(ifname, nvram_safe_get(nvram_buf), sizeof(ifname));
	}

    if (!wl_ioctl(ifname, WLC_GET_VAR, buf, sizeof(buf))) {
		dfs_status = (wl_dfs_status_t *) buf;
		dfs_status->state = dtoh32(dfs_status->state);
		dfs_status->duration = dtoh32(dfs_status->duration);

		if (dfs_status->state == WL_DFS_CACSTATE_PREISM_CAC) {
			ret = 1;
		}
    }
    return ret;
}

#else
void Pty_start_wlc_connect(int band)
{
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	int ret = 0;
	wl_join_params_t *join_params = NULL;
	int join_params_size = 0;
	struct ether_addr ether_bcast = {{255, 255, 255, 255, 255, 255}};
	char ssid[33] = { 0 };
	char sec[16] = { 0 };
#ifdef RTCONFIG_BRCM_HOSTAPD
	char wpa_cli_path[64];
	char cmd[128];
	int wait_wpasupp = WPASUPP_CTRL_TIMEOUT;
	DIR* dir;
#endif
	if (band < 0) return;

	if (!get_radio(band, 0)) {
		//dbg("band (%d) is radio off\n", band);
		return;
	}
#if 0
#ifdef RTCONFIG_HND_ROUTER_AX
	int vidx;
	int chansp = 0;
	int bandgrp = 0;
	chanspec_t chanspec = 0;

	for(vidx = 1; vidx < wl_max_no_vifs(band); vidx++) {
	    if (!strncmp(nvram_safe_get(wl_nvname("bss_enabled", band, vidx)), "1", 1)) {
			if (wl_iovar_getint(nvram_safe_get(wl_nvname("ifname", band, vidx)), "chanspec", &chansp) < 0)
			    continue;
			else
			    chanspec = (chanspec_t)dtoh32(chansp);

			bandgrp = CHANNEL_5G_BAND_GROUP(wf_chspec_ctlchan(chanspec));
			/* disable bss if channel is located at dfs channel */
			if((bandgrp == 2 || bandgrp == 3 || CHSPEC_IS160(chanspec)) && get_wlan_service_status(band, vidx) > 0)
				set_wlan_service_status(band, vidx, 0);
		}
	}
#endif
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	wlc_disassoc(ifname);
#ifdef RTCONFIG_BRCM_HOSTAPD
	if(nvram_match("hapd_enable", "1")) {
		snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%swpa_supplicant/", prefix);
		while(wait_wpasupp) {
			if (wait_wpasupp != WPASUPP_CTRL_TIMEOUT)
			    sleep(1);

			if ((--wait_wpasupp) == 0)
			    return;

			if ((dir = opendir(wpa_cli_path)) == NULL) {
				continue;
			}
			else
				closedir(dir);

			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s sta_autoconnect 1", wpa_cli_path); //enable autimatic reconnection
			if (!Pty_exec_wpasupp_cmd(cmd))
			    continue;
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s reconnect", wpa_cli_path); //trigger reconnection
			if (!Pty_exec_wpasupp_cmd(cmd))
			    continue;

			break;
		};

		wait_connection_finished(band);
		return;
	}
#endif

	/* allocate the max storage */
	join_params_size = WL_JOIN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(chanspec_t);
	if ((join_params = malloc(join_params_size)) == NULL) {
		dbg("Error allocating %d bytes for assoc params\n", join_params_size);
		goto PTY_START_WLC_CONNECT_EXIT;
	}
	memset(join_params, 0, join_params_size);
	memcpy(&join_params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);

	strlcpy(sec, nvram_safe_get(strcat_r(prefix, "akm", tmp)), sizeof(sec));
	unsigned char ea[ETHER_ADDR_LEN];

	strlcpy(ssid, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), sizeof(ssid));
	join_params->ssid.SSID_len = strlen(ssid);
	memcpy(join_params->ssid.SSID, ssid, join_params->ssid.SSID_len);
	/* default to plain old ioctl */
	join_params_size = sizeof(wlc_ssid_t);

	int auth = 0, wpa_auth = WPA_AUTH_DISABLED;
	if (strstr(sec, "psk2"))
		wpa_auth = WPA2_AUTH_PSK;
	else if (strstr(sec, "psk"))
		wpa_auth = WPA_AUTH_PSK;
	else if (strstr(sec, "wpa2"))
		wpa_auth = WPA2_AUTH_UNSPECIFIED;
	else if (strstr(sec, "wpa"))
		wpa_auth = WPA_AUTH_UNSPECIFIED;
	else if (nvram_get_int(strcat_r(prefix, "auth", tmp)))
		auth = WL_AUTH_SHARED_KEY;
	else
		auth = WL_AUTH_OPEN_SYSTEM;

	/* set authentication mode */
	auth = htod32(auth);
	if ((ret = wl_ioctl(ifname, WLC_SET_AUTH, &auth, sizeof(int))) < 0) {
		dbG("Ifname: %s WLC_SET_AUTH failed. auth val=%d ret=%d\n", ifname, auth, ret);
		goto PTY_START_WLC_CONNECT_EXIT;
	}

	/* set WPA_auth mode */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wl_ioctl(ifname, WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0) {
		dbG("Ifname: %s WLC_SET_WPA_AUTH failed. wpa_auth val=%d ret=%d\n", ifname, wpa_auth, ret);
		goto PTY_START_WLC_CONNECT_EXIT;
	}

	/* set ssid with extend assoc params (BSSID) */
	if (ether_atoe(nvram_safe_get(strcat_r(prefix, "ap_bssid", tmp)), ea)) {
		if (!wl_ether_atoe(nvram_safe_get(strcat_r(prefix, "ap_bssid", tmp)), &join_params->params.bssid)) {
			dbG("could not parse as an ethernet MAC address\n");
			goto PTY_START_WLC_CONNECT_EXIT;
		}
		join_params_size = WL_JOIN_PARAMS_FIXED_SIZE +
			dtoh32(join_params->params.chanspec_num) * sizeof(chanspec_t);
	}
	join_params->ssid.SSID_len = htod32(join_params->ssid.SSID_len);
	if ((ret = wl_ioctl(ifname, WLC_SET_SSID, join_params, join_params_size)) < 0) {
		dbG("Ifname: %s WLC_SET_SSID failed. ret=%d\n", ifname, ret);
		goto PTY_START_WLC_CONNECT_EXIT;
	}

    wait_connection_finished(band);

PTY_START_WLC_CONNECT_EXIT:
	if (join_params)
		free(join_params);

	return;
}

void pre_addif_bridge(int iftype)
{
#ifdef RTCONFIG_DPSTA
	int s = 0;
	struct ifreq ifr;

	if (dpsta_mode() && nvram_get_int("re_mode") == 1) {
		if (iftype == ETH) {
			/* Assign hw address, change to locally administered addresses.*/
			if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
				strncpy(ifr.ifr_name, "dpsta", IFNAMSIZ);

				if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
						if ((ifr.ifr_hwaddr.sa_data[0] & 0x02) == 0x00) {
							ifr.ifr_hwaddr.sa_data[0] = ifr.ifr_hwaddr.sa_data[0] | 0x02;
							ioctl(s, SIOCSIFHWADDR, &ifr);
						}
				}
				close(s);
			}
		}
		else {
			/* Assign hw address, change to locally administered addresses.*/
			if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
				strncpy(ifr.ifr_name, "dpsta", IFNAMSIZ);

				if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
						if ((ifr.ifr_hwaddr.sa_data[0] & 0x02) == 0x02) {
							ifr.ifr_hwaddr.sa_data[0] = ifr.ifr_hwaddr.sa_data[0] & ~0x02;
							ioctl(s, SIOCSIFHWADDR, &ifr);
						}
				}
				close(s);
			}
		}
		eval("ifconfig", "dpsta", iftype != ETH ? "arp" : "-arp");
	}
#endif
}

#endif

void Pty_stop_wlc_connect(int band)
{
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
#ifdef RTCONFIG_BRCM_HOSTAPD
	char wpa_cli_path[64];
	char cmd[128];
	int wait_wpasupp = WPASUPP_CTRL_TIMEOUT;
	DIR* dir;
	int wpa_supplicant_up = 0;
	char nv_upifs[32] = {0};
	char dpsta_if[IFNAMSIZ] = {0};
	char *next_dpsta;
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", band);

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	wlc_disassoc(ifname);
	sleep(2);
#ifdef RTCONFIG_BRCM_HOSTAPD
#if defined(RTCONFIG_DPSTA)
#if (defined(RTCONFIG_WIFI6E) && defined(RTCONFIG_HAS_5G_2)) || defined(RTCONFIG_BCM_502L07P2)
		snprintf(nv_upifs, sizeof(nv_upifs), "dpsta_all_ifnames");
#else
		snprintf(nv_upifs, sizeof(nv_upifs), "dpsta_ifnames");
#endif
	if (dpsta_mode() || dpsr_mode()) {
		foreach(dpsta_if, nvram_safe_get(nv_upifs), next_dpsta) {
		if (!strcmp(dpsta_if, ifname)) {
				wpa_supplicant_up = 1;
				break;
			}
		}
	}
#else
	snprintf(nv_upifs, sizeof(nv_upifs), "dpsr_wpasupp_ifnames");
	if (dpsr_mode()) {
		foreach(dpsta_if, nvram_safe_get(nv_upifs), next_dpsta) {
			if (!strcmp(dpsta_if, ifname)) {
				wpa_supplicant_up = 1;
				break;
			}
		}
	}
#endif
	if(nvram_match("hapd_enable", "1") && wpa_supplicant_up == 1) {
		snprintf(wpa_cli_path, sizeof(wpa_cli_path), "/var/run/%swpa_supplicant/", prefix);
		while(wait_wpasupp) {
			if (wait_wpasupp != WPASUPP_CTRL_TIMEOUT)
				sleep(1);

			if ((--wait_wpasupp) == 0)
				return;

			if ((dir = opendir(wpa_cli_path)) == NULL) {
				continue;
			}
			else
				closedir(dir);

			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s sta_autoconnect 0", wpa_cli_path); //disable autimatic reconnection
			if (!Pty_exec_wpasupp_cmd(cmd))
				continue;
			sleep(2);
			snprintf(cmd, sizeof(cmd), "wpa_cli-2.7 -p %s disconnect", wpa_cli_path); //disconnect and wait reassociate/reconnect comamnd
			if (!Pty_exec_wpasupp_cmd(cmd))
				continue;
			break;
		};
	}
#endif
	return;
}

char buf[WLC_IOCTL_MAXLEN];
int Pty_get_upstream_rssi(int band)
{
	int ret = 0;
	struct ether_addr bssid;
	wl_bss_info_t *bi = NULL;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };

	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	if ((ret = wl_ioctl(ifname, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN)) == 0) {
		/* The adapter is associated. */
		*(uint32*)buf = htod32(WLC_IOCTL_MAXLEN);
		if ((ret = wl_ioctl(ifname, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN)) < 0)
			return 0;

		bi = (wl_bss_info_t*)(buf + 4);
		if (dtoh32(bi->version) == WL_BSS_INFO_VERSION ||
		    dtoh32(bi->version) == LEGACY2_WL_BSS_INFO_VERSION ||
		    dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
			//dbG("RSSI: %d dBm\t", (int16)(dtoh16(bi->RSSI)));
			return (int16)(dtoh16(bi->RSSI));
		}
#if 0
		else
			dbG("Sorry, your driver has bss_info_version %d "
				"but this program supports only version %d.\n",
				bi->version, WL_BSS_INFO_VERSION);
#endif
	} else {
		;
			//dbG("Not associated. Last associated with ");
	}

	return 0;
}

/**
 * @brief Post sent action to amas_wlcconnect
 *
 */
void post_sent_action() {
#if defined(RTCONFIG_HND_ROUTER_AX)
	char dpsta_if[IFNAMSIZ] = {0};
	char *next_dpsta;
	int unit = -1;
	char prefix[] = "wlXXXXXXXXXX_";
	char tmp[32];
	char dpsta_ifnames[32] = { 0 };
	int conn_status = CH_SYNC_INIT_STATE;

	strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));

	/* loop all wifi backhaul interfaces and decide the keep_ap_up setting by wlcx_status */
	foreach(dpsta_if, dpsta_ifnames, next_dpsta) {
		if (dpsta_if == NULL)
			continue;

		if (wl_ioctl((char *) dpsta_if, WLC_GET_INSTANCE, &unit, sizeof(unit)))
			continue;
		else {
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			snprintf(tmp, sizeof(tmp), "wlc%d_status", get_wlc_bandindex_by_unit(unit));
			conn_status = nvram_get_int(tmp);

			/* apply keep_ap_up setting for 5G backhaul interface only */
			if(nvram_match(strcat_r(prefix, "nband", tmp), "1") || nvram_match(strcat_r(prefix, "nband", tmp), "4")) {
				if(conn_status!= CH_SYNC_CONNECTING)
					eval("wl", "-i", (char *) dpsta_if, "keep_ap_up", "1");
				else
					eval("wl", "-i", (char *) dpsta_if, "keep_ap_up", "0");
			}
		}
	}
#endif
}

/**
 * @brief After updated wlcX_status
 *
 */
void post_update_status(void) {
#if defined(RTCONFIG_HND_ROUTER_AX)
	char dpsta_if[IFNAMSIZ] = {0};
	char *next_dpsta;
	int unit = -1;
	char prefix[] = "wlXXXXXXXXXX_";
	char tmp[32];
	char dpsta_ifnames[32] = { 0 };
	int conn_status = CH_SYNC_INIT_STATE;

	strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));

	/* loop all wifi backhaul interfaces and decide the keep_ap_up setting by wlcx_status */
	foreach(dpsta_if, dpsta_ifnames, next_dpsta) {
		if (dpsta_if == NULL)
			continue;

		if (wl_ioctl((char *) dpsta_if, WLC_GET_INSTANCE, &unit, sizeof(unit)))
			continue;
		else {
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			snprintf(tmp, sizeof(tmp), "wlc%d_status", get_wlc_bandindex_by_unit(unit));
			conn_status = nvram_get_int(tmp);

			/* apply keep_ap_up setting for 5G backhaul interface only */
			if(nvram_match(strcat_r(prefix, "nband", tmp), "1") || nvram_match(strcat_r(prefix, "nband", tmp), "4")) {
				if(conn_status!= CH_SYNC_CONNECTING)
					eval("wl", "-i", (char *) dpsta_if, "keep_ap_up", "1");
				else
					eval("wl", "-i", (char *) dpsta_if, "keep_ap_up", "0");
			}
		}
	}
#endif
}

void post_addif_bridge(int iftype)
{

}

void pre_delif_bridge(int iftype)
{

}

void post_delif_bridge(int iftype)
{

}

/**
 * @brief Backhaul changed sysdeps function
 *
 * @param iftype BH defif
 */
void post_bh_changed(int iftype) {

#if defined(RTCONFIG_AMAS_WGN)
	char word[64], *next = NULL;
    char br_name[64], *br_next = NULL;
    char if_name[64], *if_next = NULL;
	char amas_ifname[64];
    char s[64], ss[64], iface[20];
    char *s1 = NULL, *s2 = NULL, *lan_ifnames = NULL;
    int eth_bh = 0;
	int found = 0;

	if (nvram_get_int("wgn_enabled") == 0)
		return;
	
	if (nvram_get_int("re_mode") == 0)
		return;

#if defined(RTCONFIG_BHCOST_OPT)
    eth_bh = (iftype >= ETH1_U && iftype <= ETH_MAX_BASE) ? 1 : 0;
#else
    eth_bh = (iftype==ETH || iftype==ETH_2 || iftype==ETH_3 || iftype==ETH_4) ? 1 : 0;
#endif	
	
	memset(amas_ifname, 0, sizeof(amas_ifname));
	strlcpy(amas_ifname, nvram_safe_get("amas_ifname"), sizeof(amas_ifname));
	if (strlen(amas_ifname) > 0) 
	{
		// delif 
		foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next) 
		{
            // wgn_brX_eth_ifnames
			memset(ss, 0, sizeof(ss));
			snprintf(ss, sizeof(ss), "wgn_%s_lan_ifnames", br_name);
			lan_ifnames = nvram_safe_get(ss);
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_eth_ifnames", br_name);
			foreach (if_name, nvram_safe_get(s), if_next) {
				found = 0;
				foreach (word, lan_ifnames, next) {
					if ((found = (strcmp(word, if_name) == 0))) 
						break;
				}
				if (found == 0)
					eval("brctl", "delif", br_name, if_name);
			}

            // wgn_brX_sta_ifnames
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_sta_ifnames", br_name);
            foreach (if_name, nvram_safe_get(s), if_next)
                eval("brctl", "delif", br_name, if_name);				
		}

		// addif 
		foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next) 
		{
			memset(s, 0, sizeof(s));
			snprintf(s, sizeof(s),  "wgn_%s_%s_ifnames", br_name, (eth_bh==1) ? "eth" : "sta");
            if (eth_bh == 1)
            {
				foreach (if_name, nvram_safe_get(s), if_next) {
					memset(iface, 0, sizeof(iface));
					if (wgn_check_vlan_invalid(amas_ifname, iface)) {
						if (!strncmp(iface, if_name, strlen(iface)))
							eval("brctl", "addif", br_name, if_name);
					}
					else {
						if (!strncmp(amas_ifname, if_name, strlen(amas_ifname)))
							eval("brctl", "addif", br_name, if_name);
					}
				}
            }
            else
            {
				if (strlen(amas_ifname) > 3) {
					if (strncmp(&amas_ifname[strlen(amas_ifname)-3], ".0", 2) == 0)
						amas_ifname[strlen(amas_ifname)-3] = '\0';
				}
				foreach (if_name, nvram_safe_get(s), if_next)
				{
					if (strncmp(amas_ifname, if_name, strlen(amas_ifname)) == 0)
					{
						eval("brctl", "addif", br_name, if_name);
						break;
					}
				}
            }
		}
	}
	else 
	{
		// delif 
		foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next)
		{
            // wgn_brX_eth_ifnames
			memset(ss, 0, sizeof(ss));
			snprintf(ss, sizeof(ss), "wgn_%s_lan_ifnames", br_name);
			lan_ifnames = nvram_safe_get(ss);
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_eth_ifnames", br_name);
			foreach (if_name, nvram_safe_get(s), if_next) {
				found = 0;
				foreach (word, lan_ifnames, next) {
					if ((found = (strcmp(word, if_name) == 0)))
						break;
				}
				if (found == 0)
					eval("brctl", "delif", br_name, if_name);
			}

			// wgn_brX_sta_ifnames
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_sta_ifnames", br_name);
            foreach (if_name, nvram_safe_get(s), if_next)
                eval("brctl", "delif", br_name, if_name);
		}
	}	
#endif	// RTCONFIG_AMAS_WGN
}

#if defined(RTCONFIG_AMAS_WGN)
void wgn_sysdep_swtich_unset(int vid)
{
	switch (get_model())
	{
		case MODEL_RTAC68U:
		case MODEL_RTAC3100:
		case MODEL_RTAC88U:
		case MODEL_RTAC5300:
		case MODEL_DSLAC68U:
		{
			char cmd[256];
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd)-1, "robocfg vlan %d ports \"\"", vid);
			system(cmd);
			break;
		}
		case MODEL_RTAX55:
		case MODEL_RTAX58U_V2:
		{
			break;
		}
	}

	return;
}

void wgn_sysdep_swtich_set(int vid)
{
	int gmac3_enable = 0;

#ifdef RTCONFIG_GMAC3
	gmac3_enable = nvram_get_int("gmac3_enable");
#endif	/* RTCONFIG_GMAC3 */		

	switch (get_model())
	{
		/* P0  P1 P2 P3 P4 P5 */
		/* WAN L1 L2 L3 L4 CPU */
		case MODEL_RTAC68U: 
		{  
			char cmd[256];
			memset(cmd, 0, sizeof(cmd));
			if (nvram_get_int("re_mode") == 1)
				snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"0t 1t 2t 3t 4t 5t\"", vid);
            else
				snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"1t 2t 3t 4t 5t\"", vid);
			system(cmd);
			break;
		}

		case MODEL_DSLAC68U:
		{
			/* L1 L2 L3 L4 CPU */
			char cmd[256];
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"1t 2t 3t 4t 5t\"", vid);
			system(cmd);
			break;
		}
		
		case MODEL_RTAC5300:
		{
			/* If enable gmac3, CPU port is 8 */
			char cmd[256];
			memset(cmd, 0, sizeof(cmd));

			if (gmac3_enable)
			{
#ifdef RTCONFIG_EXT_RTL8365MB
				/* P0  P1 P2 P3 P4 P5 		P7 */
				/* WAN L1 L2 L3 L4 L5 L6 L7 L8 	CPU*/
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"0t 1t 2t 3t 4t 5t 7t 8t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"1t 2t 3t 4t 5t 7t 8t\"", vid);
#else	/* RTCONFIG_EXT_RTL8365MB */
				/* P0  P1 P2 P3 P4 P5 */
				/* WAN L1 L2 L3 L4 CPU*/
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"0t 1t 2t 3t 4t 7t 8t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"1t 2t 3t 4t 7t 8t\"", vid);
#endif	/* RTCONFIG_EXT_RTL8365MB */		
			}
			else
			{
#ifdef RTCONFIG_EXT_RTL8365MB
				/* P0  P1 P2 P3 P4 P5 		P7 */
				/* WAN L1 L2 L3 L4 L5 L6 L7 L8 	CPU*/
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"0t 1t 2t 3t 4t 5t 7t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"1t 2t 3t 4t 5t 7t\"", vid);
#else	/* RTCONFIG_EXT_RTL8365MB */
				/* P0  P1 P2 P3 P4 P5 */
				/* WAN L1 L2 L3 L4 CPU*/
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"0t 1t 2t 3t 4t 7t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"1t 2t 3t 4t 7t\"", vid);
#endif	/* RTCONFIG_EXT_RTL8365MB */		
			}
			system(cmd);
			break;
		}
		
		case MODEL_RTAC3100:
		case MODEL_RTAC88U:
		{
			/* If enable gmac3, CPU port is 8 */
			char cmd[256];
			memset(cmd, 0, sizeof(cmd));
#ifdef RTCONFIG_RGMII_BRCM5301X
			/* P4  P3 P2 P1 P0 P5 		P7 */
			/* WAN L1 L2 L3 L4 L5 L6 L7 L8 	CPU*/
#else	/* RTCONFIG_RGMII_BRCM5301X */
			/* P4  P3 P2 P1 P0 P5 */
			/* WAN L1 L2 L3 L4 CPU*/
#endif	/* RTCONFIG_RGMII_BRCM5301X */
			
			if (gmac3_enable) 
			{
#ifdef RTCONFIG_RGMII_BRCM5301X
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"4t 3t 2t 1t 0t 5t 7t 8t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"3t 2t 1t 0t 5t 7t 8t\"", vid);
#else	/* RTCONFIG_RGMII_BRCM5301X */
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"4t 3t 2t 1t 0t 5t 8t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"3t 2t 1t 0t 5t 8t\"", vid);
#endif	/* RTCONFIG_RGMII_BRCM5301X */
			}
			else 
			{
#ifdef RTCONFIG_RGMII_BRCM5301X
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"4t 3t 2t 1t 0t 5t 7t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"3t 2t 1t 0t 5t 7t\"", vid);
#else	/* RTCONFIG_RGMII_BRCM5301X */
				if (nvram_get_int("re_mode") == 1)
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"4t 3t 2t 1t 0t 5t\"", vid);
				else
					snprintf(cmd, sizeof(cmd), "robocfg vlan %d ports \"3t 2t 1t 0t 5t\"", vid);
#endif	/* RTCONFIG_RGMII_BRCM5301X */
			}
			system(cmd);
			break;
		}

		case MODEL_RTAX55:
		case MODEL_RTAX58U_V2:
		{
			// set wgn vid port mask ( leave tag ) 
			snprintf(cmd, sizeof(cmd)-1, "rtkswitch 36 0x%04x", vid);
			system(cmd);
			snprintf(cmd, sizeof(cmd)-1, "rtkswitch 37 0");
			system(cmd);
			snprintf(cmd, sizeof(cmd)-1, "rtkswitch 39 0x0000000f");
			system(cmd);
			// reset for no tag traffic
			snprintf(cmd, sizeof(cmd)-1, "rtkswitch 40 1");
			system(cmd);
			snprintf(cmd, sizeof(cmd)-1, "rtkswitch 38 0");
			system(cmd);
			break;
		}
	}

	return;
}

void wgn_sysdep_wl_unset(int vid)
{
}

void wgn_sysdep_wl_set(int vid)
{
}
#endif	/* RTCONFIG_AMAS_WGN */

#ifdef RTCONFIG_AMAS
/**
 * @brief Set AMAS relate features interface index
 *
 */
#if defined(RTCONFIG_FRONTHAUL_DWB) || defined(RTCONFIG_MSSID_PRELINK) || defined(RTCONFIG_VIF_ONBOARDING) || defined(RTCONFIG_FRONTHAUL_DBG)
void init_amas_subunit()
{
	char name[8], tmp[128];
	char wl_vifnames_5g[128];
#ifdef GTAXE16000
	int unit = WL_5G_2_BAND;
#else
	int unit = num_of_wl_if() - 1;
#endif
	int max_mssid = num_of_mssid_support(unit);
	int re_guest_subunit = max_mssid + 1; // reserve for RE 3rd guest network
	int subidx_guest = 0, subidx_fh = 0, subidx_plk = 0;

#ifdef RTCONFIG_FRONTHAUL_DWB
	int re_fh_subunit, cap_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
	int re_prelink_subunit, cap_prelink_subunit;
#endif
#ifdef RTCONFIG_VIF_ONBOARDING
	int cap_obvif_subunit = 0, re_obvif_subunit = 0;
#endif
#ifdef RTCONFIG_FRONTHAUL_DBG
	int re_fh_dbg_subunit;
#endif
	char wl_vifnames_2g[128];
	int unit_2g = WL_2G_BAND;
	int max_mssid_2g = num_of_mssid_support(unit_2g);
	int re_guest_subunit_2g = max_mssid_2g + 1;
	int subidx_guest_2g = 0, subidx_obvif = 0, subidx_fh_dbg = 0;

#if defined(RTCONFIG_FRONTHAUL_DWB) && defined(RTCONFIG_MSSID_PRELINK)
	cap_fh_subunit = max_mssid + 1;
	cap_prelink_subunit = max_mssid + 2;

	re_fh_subunit = re_guest_subunit + 1;
	re_prelink_subunit = re_guest_subunit + 2;
#elif defined(RTCONFIG_FRONTHAUL_DWB)
	cap_fh_subunit = max_mssid + 1;
	re_fh_subunit = re_guest_subunit + 1;
#elif defined(RTCONFIG_MSSID_PRELINK)
	cap_prelink_subunit = max_mssid + 1;
	re_prelink_subunit = re_guest_subunit + 1;
#endif

	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit);
	strcpy(wl_vifnames_5g, nvram_safe_get(tmp));

#if defined(RTCONFIG_VIF_ONBOARDING) && defined(RTCONFIG_FRONTHAUL_DBG)
	cap_obvif_subunit = max_mssid + 1;
	re_obvif_subunit = re_guest_subunit_2g + 1;
	re_fh_dbg_subunit = re_guest_subunit_2g + 2;
#elif defined(RTCONFIG_VIF_ONBOARDING)
	cap_obvif_subunit = max_mssid + 1;
	re_obvif_subunit = re_guest_subunit_2g + 1;
#elif defined(RTCONFIG_FRONTHAUL_DBG)
	re_fh_dbg_subunit = re_guest_subunit_2g + 1;
#endif
	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit_2g);
	strcpy(wl_vifnames_2g, nvram_safe_get(tmp));

	if(!nvram_match("re_mode", "1")) {
		subidx_guest = 0;
#ifdef RTCONFIG_FRONTHAUL_DWB
		subidx_fh = cap_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
		subidx_plk = cap_prelink_subunit;
#endif
#ifdef RTCONFIG_VIF_ONBOARDING
		subidx_guest_2g = 0;
		subidx_obvif = cap_obvif_subunit;
#endif
		_dprintf("init_amas_subunit: Set default value.\n");
	}
	else {
		subidx_guest = re_guest_subunit;
#ifdef RTCONFIG_FRONTHAUL_DWB
		subidx_fh = re_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
		subidx_plk = re_prelink_subunit;
#endif
#ifdef RTCONFIG_VIF_ONBOARDING
		subidx_guest_2g = re_guest_subunit_2g;
		subidx_obvif = re_obvif_subunit;
#endif
#ifdef RTCONFIG_FRONTHAUL_DBG
		subidx_fh_dbg = re_fh_dbg_subunit;
#endif
	}

	if(subidx_guest) {
		snprintf(name, sizeof(name), "wl%d.%d", unit, subidx_guest);
		add_to_list(name, wl_vifnames_5g, sizeof(wl_vifnames_5g));
	}

	if(subidx_fh) {
		snprintf(name, sizeof(name), "wl%d.%d", unit, subidx_fh);
		add_to_list(name, wl_vifnames_5g, sizeof(wl_vifnames_5g));
	}

	if(subidx_plk) {
		snprintf(name, sizeof(name), "wl%d.%d", unit, subidx_plk);
		add_to_list(name, wl_vifnames_5g, sizeof(wl_vifnames_5g));
	}

#ifdef RTCONFIG_FRONTHAUL_DWB
	nvram_set_int("fh_cap_mssid_subunit", cap_fh_subunit);
	nvram_set_int("fh_re_mssid_subunit", re_fh_subunit);
#endif
#ifdef RTCONFIG_MSSID_PRELINK
	nvram_set_int("plk_cap_subunit", cap_prelink_subunit);
	nvram_set_int("plk_re_subunit", re_prelink_subunit);
#endif
#if defined(RTCONFIG_FRONTHAUL_DWB) || defined(RTCONFIG_MSSID_PRELINK)
	_dprintf("%s(%d): update wl%d_vifnames [%s] \n", __FUNCTION__, __LINE__, unit, wl_vifnames_5g);
	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit);
	nvram_set(tmp, wl_vifnames_5g);
#endif

#ifdef RTCONFIG_VIF_ONBOARDING
	if(subidx_guest_2g) {
		snprintf(name, sizeof(name), "wl%d.%d", unit_2g, subidx_guest_2g);
		add_to_list(name, wl_vifnames_2g, sizeof(wl_vifnames_2g));
	}

	if(subidx_obvif) {
		snprintf(name, sizeof(name), "wl%d.%d", unit_2g, subidx_obvif);
		add_to_list(name, wl_vifnames_2g, sizeof(wl_vifnames_2g));
	}

	nvram_set_int("obvif_cap_subunit", cap_obvif_subunit);
	nvram_set_int("obvif_re_subunit", re_obvif_subunit);
#endif

#ifdef RTCONFIG_FRONTHAUL_DBG
	if(subidx_fh_dbg){
		snprintf(name, sizeof(name), "wl%d.%d", unit_2g, subidx_fh_dbg);
		add_to_list(name, wl_vifnames_2g, sizeof(wl_vifnames_2g));
		nvram_set_int("fh_re_dbg_subunit", re_fh_dbg_subunit);
	}
#endif
	_dprintf("%s(%d): update wl%d_vifnames [%s] \n", __FUNCTION__, __LINE__, unit_2g, wl_vifnames_2g);
	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit_2g);
	nvram_set(tmp, wl_vifnames_2g);

	if (subidx_guest || subidx_fh || subidx_plk ||
		subidx_guest_2g || subidx_obvif || subidx_fh_dbg)
		nvram_commit();
}
#endif
#endif

static int _wl_chan_info(char *ifname, uint32_t* chan_info, size_t n)
{
	union ioval_u {
		char buf[WLC_IOCTL_MAXLEN];
		uint32_t val;
	} u;
	int i = 0, last = 0;
	uint32_t chanspec_arg = 0;
	uint32_t bitmap = 0;

	if (n < MAXCHANNEL)
	{
		last = n;
	}
	else
	{
		last = MAXCHANNEL;
	}

	for (i = 0; i <= last; i++)
	{
		strcpy(u.buf, "per_chan_info");
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
		chanspec_arg = CH20MHZ_CHSPEC(i, WL_CHANNEL_2G5G_BAND(i));
#else
		chanspec_arg = CH20MHZ_CHSPEC(i);
#endif
		memcpy(u.buf + strlen(u.buf) + 1, (void *)&chanspec_arg, sizeof(chanspec_arg));

		if (wl_ioctl(ifname, WLC_GET_VAR, u.buf, sizeof(u.buf)) < 0)
		{
			return (-1);
		}

		bitmap = dtoh32(u.val);

		if (!(bitmap & WL_CHAN_VALID_HW))
		{
			continue;
		}

		if (!(bitmap & WL_CHAN_VALID_SW))
		{
			continue;
		}

		*(chan_info + i) = bitmap;
	}

	return (0);
}

int get_radar_status(int bssidx)
{

	uint32_t chan_info[MAXCHANNEL] = {0};
	int i = 0;
	char tmp[128]={0}, prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	int det = 0;
	snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	if (_wl_chan_info(ifname, chan_info, sizeof(chan_info)) < 0) {
		return det;
	}


	for(i=0; i<MAXCHANNEL; i++)
	{
		if (chan_info[i])
		{
			if (chan_info[i] & WL_CHAN_INACTIVE)
			{
				dbG("%s Channel %d get radar signal.\n",__FUNCTION__, i);
				logmessage("lanctrl-radar detected", "Channel %d get radar signal.", i);
				det = 1;
				//break;
			}
		}
	}

	return det;
}

#ifdef RTCONFIG_BCMARM
	struct ether_addr bssid;
	struct ether_addr bssid_org;
#endif
int Pty_procedure_check(int unit, int wlif_count)
{

#ifdef RTCONFIG_BCMARM
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	unsigned char bssid_null[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	if (unit == -1) return -1;

	if (!is_psta(unit) && !is_psr(unit))
		return 0;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	memset(&bssid, 0x00, ETHER_ADDR_LEN);

	if (wl_ioctl(ifname, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN) != 0)
		return -1;
	else if (!memcmp(&bssid, bssid_null, ETHER_ADDR_LEN))
		return -1;


	if ((wlif_count == 2) && is_psr(unit) && nvram_match(strcat_r(prefix, "reg_mode", tmp), "h"))
	{
		if (memcmp(&bssid_org, &bssid, ETHER_ADDR_LEN) != 0)
		{
			if ((bssid.octet[5] % 16) == 8) {

				eval("wl", "-i", ifname, "dfs_channel_forced", "-l", "+112/80 +136u +108l +100l +140 +132 +116");
			}
			else{
				eval("wl", "-i", ifname, "dfs_channel_forced", "0");
			}
		}

		memcpy(&bssid_org, &bssid, ETHER_ADDR_LEN);
	}
#endif
	return 0;
}
#endif

#ifdef HND_ROUTER
#define SYSFS_BRPORT_STATE	"/sys/class/net/%s/brport/state"

int wait_to_forward_state(char *ifname)
{
	FILE *fp;
	char brport_state[64] = {0};
	int timeout, state;

	timeout = 5;
	state = BR_STATE_DISABLED;

	while (timeout-- && (state != BR_STATE_FORWARDING)) {
		sprintf(brport_state, SYSFS_BRPORT_STATE, ifname);
		if ((fp = fopen(brport_state, "r")) != NULL) {
			fscanf(fp, "%d", &state);
			fclose(fp);
		}
		if (state == BR_STATE_FORWARDING)
			break;
		sleep(1);
	}

	if (!timeout)
		return 1;

	return 0;
}
#endif

#ifdef RTAC68U
#ifdef RTCONFIG_JFFSV1
#define JFFS_NAME	"jffs"
#else
#define JFFS_NAME	"jffs2"
#endif
#define SECOND_JFFS2_PARTITION	"asus"

int
ether_atoe2(const char *a, unsigned char *e)
{
	char *c = (char *) a, *err;
	int i = 0;
	char tmp[3] = { 0 };

	memset(e, 0, ETHER_ADDR_LEN);
	for (; c[0] && c[1]; c += 2) {
		memcpy(tmp, c, 2);
		e[i] = (unsigned char) strtoul(tmp, &err, 16);
		if (err == tmp || *err)
			break;
		if (++i == ETHER_ADDR_LEN)
			break;
	}

	return (i == ETHER_ADDR_LEN);
}

static int mount_tmo_jffs2(char *path)
{
	char s[32];
	int part, size, i;

	for (i = 0;;) {
		if (wait_action_idle(10))
			break;
		if (++i >= 10)
			return -1;
	}

	if (!mtd_getinfo(SECOND_JFFS2_PARTITION, &part, &size))
		return -1;

	sprintf(s, MTD_BLKDEV(%d), part);
	for (i = 0;;) {
		if (mount(s, path, JFFS_NAME, MS_RDONLY, "") == 0)
			break;
		if (++i >= 10)
			return -1;
	}

	return 0;
}

void check_asus_jffs(void)
{
	unsigned char hwaddr[6];
	char macaddr[13], ext[5], *path, template[] = "/tmp/jffs_XXXXXX";
	DIR *dp;
	struct dirent *entry;
	int count, match = 0;
	char unlock_file[] = {'/', 'j', 'f', 'f', 's', '/', '.', 's', 'y', 's', '/', 'R', 'T', '-', 'A', 'C', '6', '8', 'U', '/', 'u', 'n', 'l', 'o', 'c', 'k', '\0'};
	char jffs_ac68u_dir[] = {'/', 'j', 'f', 'f', 's', '/', '.', 's', 'y', 's', '/', 'R', 'T', '-', 'A', 'C', '6', '8', 'U', '\0'};

	path = mkdtemp(template);
	if (path == NULL)
		return;

	if (mount_tmo_jffs2(path))
		return;

	if ((dp = opendir(path))) {
		while ((entry = readdir(dp)) != NULL) {
			if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
				continue;

			count = sscanf(entry->d_name, "tmo-%12[^.].%4s", macaddr, ext);
			if (count < 2)
				break;;

			if (ether_atoe2(macaddr, hwaddr) && !strcmp(ext, "tgz"))
				match = 1;

			break;
		}

		closedir(dp);
	}

	if (umount(path))
		umount2(path, MNT_DETACH);
	rmdir(path);

	if (match) {
		if (!f_exists(unlock_file)) {
			eval("mkdir", "-p", jffs_ac68u_dir);
			eval("touch", unlock_file);
		}

		nvram_set("fw_check", "1");
	}
}

char fw_trx_enc[] = {'/', 't', 'm', 'p', '/', 'l', 'i', 'n', 'u', 'x', '_', 'e', 'n', 'c', '.', 't', 'r', 'x', '\0'};
char fw_trx[] = {'/', 't', 'm', 'p', '/', 'l', 'i', 'n', 'u', 'x', '.', 't', 'r', 'x', '\0'};
char rsa[] = {'/', 't', 'm', 'p', '/', 'r', 's', 'a', 's', 'i', 'g', 'n', '.', 'b', 'i', 'n', '\0'};

static void fw_dec(void)
{
	char ks_url[] = {'f', 'i', 'l', 'e', ':', '/', 'u', 's', 'r', '/', 's', 'b', 'i', 'n', '/', 't', 'm', 'k', 's', '\0'};

	eval("openssl", "enc", "-d", "-aes-256-cbc", "-in", fw_trx_enc, "-out", fw_trx, "-pass", ks_url);
}

extern void update_cfe_tmo(int force);

void fw_check_pre(void)
{
	if (nvram_match("fw_check", "1")) {
		fw_dec();
		sleep(2);
		unlink(fw_trx_enc);

		nvram_set("restore_defaults", "1");
		nvram_set(ASUS_STOP_COMMIT, "1");
		system("nvram erase");

		update_cfe_tmo(1);
	}
}

int
fw_check_main(int argc, char *argv[])
{
	if (argc != 1)
		return -1;

	fw_check();

	return 0;
}
#else
void check_asus_jffs(void)
{
}

void fw_check_pre(void)
{
}
#endif

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_BCMWL6)
extern int g_upgrade;
int no_need_obd(void)
{
#ifdef RTCONFIG_SW_HW_AUTH
	if (!(getAmasSupportMode() & AMAS_RE))
		return -1;
#endif
	if (g_reboot || g_upgrade)
		return -1;

	if (ATE_BRCM_FACTORY_MODE())
		return -1;

	if (!(is_router_mode()
		|| dpsr_mode()
#ifdef RTCONFIG_DPSTA
		|| ((dpsta_mode()||rp_mode()) && nvram_get_int("re_mode") == 0)
#endif
		) || (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1))
		return -1;

	if (nvram_get_int("wlready") == 0)
		return -1;

	return pids("obd");
}

int no_need_obdeth(void)
{
#ifdef RTCONFIG_SW_HW_AUTH
	if (!(getAmasSupportMode() & AMAS_RE))
		return -1;
#endif
	if (g_reboot || g_upgrade)
		return -1;

	if (ATE_BRCM_FACTORY_MODE())
		return -1;

	if (!(is_router_mode()
		|| dpsr_mode()
#ifdef RTCONFIG_DPSTA
		|| ((dpsta_mode()||rp_mode()) && nvram_get_int("re_mode") == 0)
#endif
		) || (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1))
		return -1;

	if (nvram_get_int("wlready") == 0)
		return -1;

	return pids("obd_eth");
}
#endif

#if defined(RTCONFIG_AMAS)
void amas_wait_wifi_ready(void)
{
	return; //no need to checking wifi ready on boardcom platform.
}
#endif

#ifdef RTCONFIG_DPSTA
void set_dpsta_ifnames()
{
	char word[256], *next;
	char list[128];
	int idx = 0;
	char wl_ifnames[32] = { 0 };

	memset(list, 0, sizeof(list));

	if (dpsta_mode()) {
		idx = 0;
		strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
		foreach (word, wl_ifnames, next) {
			if ((num_of_wl_if() == 2) || !idx || idx == nvram_get_int("dpsta_band"))
				add_to_list(word, list, sizeof(list));

			idx++;
		}
	}

	nvram_set("dpsta_ifnames", list);

	strlcpy(list, nvram_safe_get("wl_ifnames"), sizeof(list));
	nvram_set("dpsta_all_ifnames", list);	/* for upstream all ifnames */
}
#endif

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
void set_dpsr_ifnames()
{
    char list[128];
    int model;
#if !defined(RTCONFIG_WIFI6E)
    char word[64], *next;
    int unit = 0;
#endif

	_dprintf("%s, mode:%d\n", __func__, dpsr_mode());

    if (!dpsr_mode())
	return;

    memset(list, 0, sizeof(list));
    strlcpy(list, nvram_safe_get("wl_ifnames"), sizeof(list));
    nvram_set("dpsr_ifnames", list);   /* for upstream all ifnames */

    /* upstream all ifnames for dual-band and tri-band dpsr mode */
    if (num_of_wl_if() == 2) {
		nvram_set("dpsr_wpasupp_ifnames", list);   /* for upstream all ifnames */
    }
    else if(num_of_wl_if() == 3) {
#ifdef RTCONFIG_WIFI6E
		nvram_set("dpsr_wpasupp_ifnames", list);   /* for upstream all ifnames */
#else
		memset(list, 0, sizeof(list));
		foreach(word, nvram_safe_get("wl_ifnames"), next){
			if(unit != WL_5G_BAND)
				add_to_list(word, list, sizeof(list));
			unit++;
		}
		nvram_set("dpsr_wpasupp_ifnames", list);
#endif
    }
    /* quad-band */
    else if (num_of_wl_if() > 3) {
		model = get_model();
		switch(model) {
			case MODEL_GTAXE16000:
				nvram_set("dpsr_wpasupp_ifnames", "eth8 eth9 eth10");   /* for upstream all ifnames */
				break;
		}
    }
}
#endif

#ifdef RTCONFIG_EXTPHY_BCM84880
#define CROSSBAR_PORT_GPHY "10"
#define CORSSBAR_PORT_SERDES "9"
void config_ext_wan_port()
{
#ifdef RTAX86U
	if(!strcmp(get_productid(), "RT-AX86S"))
		return;
#endif

	int wanport = nvram_get_int("wans_extwan");

	if (wanport) {
		eval("ifconfig", "eth0", "down");
		eval("ifconfig", "eth5", "down");
		eval("ethctl", "eth0", "phy-crossbar", "port", CORSSBAR_PORT_SERDES);
		eval("ethctl", "eth5", "phy-crossbar", "port", CROSSBAR_PORT_GPHY);
		eval("ifconfig", "eth0", "up");
		eval("ifconfig", "eth5", "up");
		_dprintf("config SerDes(eth0) and GPHY(eth5)...\n");

#if defined(RTAX86U) || defined(RTAX5700)
		eval("sw", "0xff800564", "0x0");
		eval("sw", "0xff800568", "0x4015");
		eval("sw", "0xff80056c", "0x21");
		eval("sw", "0xff800500", "0x200000");

		config_ext_wan_led(0);
#endif
	}
	else {
		eval("ifconfig", "eth0", "down");
		eval("ifconfig", "eth5", "down");
		eval("ethctl", "eth0", "phy-crossbar", "port", CROSSBAR_PORT_GPHY);
		eval("ethctl", "eth5", "phy-crossbar", "port", CORSSBAR_PORT_SERDES);
		eval("ifconfig", "eth0", "up");
		eval("ifconfig", "eth5", "up");
		_dprintf("config SerDes(eth5) and GPHY(eth0)...\n");
	}
}
#endif

#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)
#ifdef RTCONFIG_MEDIA_SERVER
extern int find_dms_dbdir_candidate(char *dbdir);
#endif

void dump_WlGetDriverStats(int fb, int count)
{
	time_t now;
	char *timestamp;
	char word[256], *next;
	int i;
	static char dir[128];
	static char dir_wifilog[128];
	static int found = 0;
	int unit = -1, subunit = 0;
	int dmode = 0;
	char tmp[256], vif_name[] = "wlXXXXXXXXXX";
	int max_no_vifs = 0;
	char wl_ifnames[32] = { 0 };
	char cmd[128];

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	if (nvram_get_int("log_wlstat") || fb)
	foreach (word, wl_ifnames, next) {
		unit++;
		max_no_vifs = wl_max_no_vifs(unit);

		snprintf(tmp, sizeof(tmp), "wlradio_dmode_%d", unit);
		dmode = nvram_match(tmp, "DGL");

		for (subunit = 0; subunit < max_no_vifs; subunit++) {
			snprintf(vif_name, sizeof(vif_name), "wl%d.%d", unit, subunit);
			if(subunit && !nvram_get_int(strcat_r(vif_name, "_bss_enabled", tmp)))
				continue;

			if(fb) {
				strcpy(dir, "/tmp");
				doSystem("WlGetDriverStats.sh %s %s %d &> %s/WlGetDriverStats_%s.log",
						subunit?vif_name:word, dmode?"dhd":"nic", count?count:1, dir, subunit?vif_name:word);
			}
			else {
#ifdef RTCONFIG_MEDIA_SERVER
				if (!found && find_dms_dbdir_candidate(dir)) {
					found = 1;
				}
#endif
				if (!found) strcpy(dir, "/jffs");

				if (nvram_get("log_wlstat") && !nvram_get("log_wlstat_starttime")) {
					if (strlen(nvram_safe_get("log_wlstat_dir")) && d_exists(nvram_safe_get("log_wlstat_dir"))) {
						snprintf(cmd, sizeof(cmd), "rm -rf %s", nvram_safe_get("log_wlstat_dir"));
						system(cmd);
					}
					sprintf(tmp, "%lu", uptime());
					nvram_set("log_wlstat_starttime", tmp);
				} else {
					time_t cur = uptime();
					time_t starttime = strtoul(nvram_safe_get("log_wlstat_starttime"), NULL, 10);
					if (!starttime || ((cur - starttime) > 3600)) {
						nvram_unset("log_wlstat");
						nvram_unset("log_wlstat_starttime");
						break;
					}
				}

				snprintf(dir_wifilog, sizeof(dir_wifilog), "%s/%s", dir, "wifi");
				if (strcmp(dir_wifilog, nvram_safe_get("log_wlstat_dir"))) {
					nvram_set("log_wlstat_dir", dir_wifilog);
				}
				mkdir_if_none(dir_wifilog);

				time(&now);
				timestamp = ctime(&now) + 4;    /* skip day of week */
				timestamp[15] = '\0';
				for (i = 0; i < 15; i++)
					if (timestamp[i] == 0x20 || timestamp[i] == 0x3a)
						timestamp[i] = 0x5f;

				doSystem("WlGetDriverStats.sh %s %s %d &> %s/wifi/WlGetDriverStats_%s_%s.log",
						subunit?vif_name:word, dmode?"dhd":"nic", count?count:1, dir, subunit?vif_name:word, timestamp);
			}
		}
	}
}
#endif

#if defined(RTCONFIG_TURBO_BTN)
/**
 * Enable/disable DFS channels in ACS.
 * @onoff:
 * 	0: 	Disable DFS channels in ACS.
 *  otherwise:	Enable DFS channels in ACS.
 * @return:
 * 	0:	success
 */
int toggle_dfs_in_acs(int onoff)
{
	char prefix[]="wlXXXXXX_", tmp[100];
	char word[256], *next;
	int unit;
	int count_dfs_if = 0;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		wl_ioctl(word, WLC_GET_INSTANCE, &unit, sizeof(unit));
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

		if (!unit) continue;

		if (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h"))
			count_dfs_if++;
	}

	if (!count_dfs_if) return -1;

	nvram_set_int("acs_dfs", !!onoff);

	if (onoff) {
#if defined(RTCONFIG_RGBLED) && defined(GTAC2900)
		nvram_set("dfs_aura_nt_ctrl", "1");
		send_aura_event("BOOST_ACS_DFS_SW");
#elif defined(RTCONFIG_LOGO_LED)
		led_control(LED_LOGO, LED_ON);
#endif
	}
	else {
#ifdef RTCONFIG_LOGO_LED
		led_control(LED_LOGO, LED_OFF);
#endif
	}

#ifdef GTAC2900
	notify_rc("restart_wireless");
#endif

	return 0;
}
#endif

#ifdef CONFIG_BCMWL5
int wl_if_check()
{
	char word[256], *next;
	int unit;
	int idx = 0;
	int band;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		unit = -1;
		wl_ioctl(word, WLC_GET_INSTANCE, &unit, sizeof(unit));

		if (unit == -1 || unit != idx)
			return -1;

		band = -1;
		wl_ioctl(word, WLC_GET_BAND, &band, sizeof(band));

		if (!unit && band != WLC_BAND_2G)
			return -1;

		if (unit &&
#ifdef RTCONFIG_WIFI6E
			band != WLC_BAND_6G &&
#endif
			band != WLC_BAND_5G)
		    return -1;

		idx++;
	}

	return 0;
}
#endif

#ifdef RTCONFIG_HND_ROUTER_AX
extern int timecheck_item(char *activeTime);

const char *dfs_cacstate_str[WL_DFS_CACSTATES] = {
	"IDLE",
	"PRE-ISM Channel Availability Check(CAC)",
	"In-Service Monitoring(ISM)",
	"Channel Switching Announcement(CSA)",
	"POST-ISM Channel Availability Check",
	"PRE-ISM Ouf Of Channels(OOC)",
	"POST-ISM Out Of Channels(OOC)"
};

void dfs_cac_check(void)
{
	char prefix[]="wlXXXXXX_", tmp[100];
	char word[256], *next;
	int unit;
	wl_dfs_status_t *dfs_status;
	char buf[WLC_IOCTL_SMLEN];
	static int once = 0;
	char ifname[16];
	int radio_status;
	int count_ism_if = 0;
	int count_cac_if = 0;
	static int no_check = 0;
	char wl_ifnames[32] = { 0 };

	if (no_check)
		return;

	if (wl_if_check() != 0) {
		dbg("invalid wireless interface state!\n");
		no_check = 1;
		return;
	}

	if (!is_router_mode() && !access_point_mode())
		return;

	if (!nvram_match("wlready", "1"))
		return;

	if (nvram_match("wl0_radio", "0"))
		return;

	if (nvram_match("wl0_radio", "1") &&
		nvram_match("svc_ready", "1") &&
		nvram_match("wl0_timesched", "1") && !timecheck_item(nvram_safe_get("wl0_sched")))
		return;

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		wl_ioctl(word, WLC_GET_INSTANCE, &unit, sizeof(unit));
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

		if (!unit) continue;

		if (nvram_match(strcat_r(prefix, "radio", tmp), "1") &&
			(nvram_match(strcat_r(prefix, "timesched", tmp), "0") ||
			(nvram_match(strcat_r(prefix, "timesched", tmp), "1") &&
			 nvram_match("svc_ready", "1") &&
			 timecheck_item(nvram_safe_get(strcat_r(prefix, "sched", tmp)))))) {
			if (!nvram_match(strcat_r(prefix, "reg_mode", tmp), "h"))
				count_ism_if++;
		} else continue;

		memset(buf, 0, sizeof(buf));
		strcpy(buf, "dfs_status");

		if (!wl_ioctl(word, WLC_GET_VAR, buf, sizeof(buf))) {
			dfs_status = (wl_dfs_status_t *) buf;
			dfs_status->state = dtoh32(dfs_status->state);
			dfs_status->duration = dtoh32(dfs_status->duration);

			if (dfs_status->state == WL_DFS_CACSTATE_IDLE)
				count_ism_if++;
			else if (dfs_status->state == WL_DFS_CACSTATE_PREISM_CAC)
				count_cac_if++;
			else if (dfs_status->state == WL_DFS_CACSTATE_ISM)
				count_ism_if++;
			else
				continue;

			dbg("%s: DFS status: state %s time elapsed %dms radar channel cleared by DFS\n",
				word, dfs_cacstate_str[dfs_status->state], dfs_status->duration);
		}
	}

	if (count_ism_if && !once) {
		no_check = 1;
		return;
	}

	wl_ifname(0, 0, ifname);
	wl_ioctl(ifname, WLC_GET_RADIO, &radio_status, sizeof (radio_status));
	radio_status &= WL_RADIO_SW_DISABLE | WL_RADIO_HW_DISABLE;

	if (count_cac_if && !once && !radio_status) {
		once = 1;

		dbg("disable 2.4GHz radio for 5GHz CAC state\n");
		eval("radio", "off", "0");
	} else if (count_ism_if && once) {
		no_check = 1;

		if (!radio_status)
			return;

		if (nvram_match("svc_ready", "1") && nvram_match("wl0_timesched", "1") &&
			!timecheck_item(nvram_safe_get("wl0_sched")))
			return;

		dbg("enable 2.4GHz radio for 5GHz ISM state\n");
		eval("radio", "on", "0");
	}
}
#endif

#if (defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX)) || defined(RTCONFIG_BCM_7114)
void wl_fail_db(int unit, int state, int count)
{
	char tmp[100], prefix[]="wlXXXXXXX_";
	char wl_state_idx_buf[4];
	char wl_state_buf[200];
	char wl_state_init[] = "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0 "
			       "0 0 0 0 0 0 0 0 0 0";
	int wl_state_idx = 0;
	int wl_state[100];
	char cmd[256];

	if (count < 1) return;

	if (!pids("envrams")) {
		system("/usr/sbin/envrams >/dev/null");
		usleep(100000);
	}

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(wl_state_idx_buf, cfe_nvram_safe_get_raw(strcat_r(prefix, "state_idx", tmp)), sizeof(wl_state_idx_buf));
	strlcpy(wl_state_buf, cfe_nvram_safe_get_raw(strcat_r(prefix, "state", tmp)), sizeof(wl_state_buf));
	if (!strlen(wl_state_buf))
		strlcpy(wl_state_buf, wl_state_init, sizeof(wl_state_buf));

	sscanf(wl_state_idx_buf, "%d", &wl_state_idx);

	sscanf(wl_state_buf, "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
			     &wl_state[0], &wl_state[1], &wl_state[2], &wl_state[3], &wl_state[4], &wl_state[5], &wl_state[6], &wl_state[7], &wl_state[8], &wl_state[9],
			     &wl_state[10], &wl_state[11], &wl_state[12], &wl_state[13], &wl_state[14], &wl_state[15], &wl_state[16], &wl_state[17], &wl_state[18], &wl_state[19],
			     &wl_state[20], &wl_state[21], &wl_state[22], &wl_state[23], &wl_state[24], &wl_state[25], &wl_state[26], &wl_state[27], &wl_state[28], &wl_state[29],
			     &wl_state[30], &wl_state[31], &wl_state[32], &wl_state[33], &wl_state[34], &wl_state[35], &wl_state[36], &wl_state[37], &wl_state[38], &wl_state[39],
			     &wl_state[40], &wl_state[41], &wl_state[42], &wl_state[43], &wl_state[44], &wl_state[45], &wl_state[46], &wl_state[47], &wl_state[48], &wl_state[49],
			     &wl_state[50], &wl_state[51], &wl_state[52], &wl_state[53], &wl_state[54], &wl_state[55], &wl_state[56], &wl_state[57], &wl_state[58], &wl_state[59],
			     &wl_state[60], &wl_state[61], &wl_state[62], &wl_state[63], &wl_state[64], &wl_state[65], &wl_state[66], &wl_state[67], &wl_state[68], &wl_state[69],
			     &wl_state[70], &wl_state[71], &wl_state[72], &wl_state[73], &wl_state[74], &wl_state[75], &wl_state[76], &wl_state[77], &wl_state[78], &wl_state[79],
			     &wl_state[80], &wl_state[81], &wl_state[82], &wl_state[83], &wl_state[84], &wl_state[85], &wl_state[86], &wl_state[87], &wl_state[88], &wl_state[89],
			     &wl_state[90], &wl_state[91], &wl_state[92], &wl_state[93], &wl_state[94], &wl_state[95], &wl_state[96], &wl_state[97], &wl_state[98], &wl_state[99]);

#if 0
	dbg("wl_state_idx: %d\n", wl_state_idx);
	dbg("wl_state:\n");
	int i;
	for (i = 0; i < 100; i++) {
		dbg("%d %d\n", i, wl_state[i]);
	}
#endif

LOOP:
	wl_state[wl_state_idx] = state;

	wl_state_idx++;
	wl_state_idx %= 100;

	while (--count > 0)
		goto LOOP;

	sprintf(wl_state_idx_buf, "%d", wl_state_idx);
	sprintf(cmd, "%s=%s", strcat_r(prefix, "state_idx", tmp), wl_state_idx_buf);
	eval("envram", "set", cmd);
	eval("nvram", "set", cmd);

	sprintf(wl_state_buf, "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
			      wl_state[0], wl_state[1], wl_state[2], wl_state[3], wl_state[4], wl_state[5], wl_state[6], wl_state[7], wl_state[8], wl_state[9],
			      wl_state[10], wl_state[11], wl_state[12], wl_state[13], wl_state[14], wl_state[15], wl_state[16], wl_state[17], wl_state[18], wl_state[19],
			      wl_state[20], wl_state[21], wl_state[22], wl_state[23], wl_state[24], wl_state[25], wl_state[26], wl_state[27], wl_state[28], wl_state[29],
			      wl_state[30], wl_state[31], wl_state[32], wl_state[33], wl_state[34], wl_state[35], wl_state[36], wl_state[37], wl_state[38], wl_state[39],
			      wl_state[40], wl_state[41], wl_state[42], wl_state[43], wl_state[44], wl_state[45], wl_state[46], wl_state[47], wl_state[48], wl_state[49],
			      wl_state[50], wl_state[51], wl_state[52], wl_state[53], wl_state[54], wl_state[55], wl_state[56], wl_state[57], wl_state[58], wl_state[59],
			      wl_state[60], wl_state[61], wl_state[62], wl_state[63], wl_state[64], wl_state[65], wl_state[66], wl_state[67], wl_state[68], wl_state[69],
			      wl_state[70], wl_state[71], wl_state[72], wl_state[73], wl_state[74], wl_state[75], wl_state[76], wl_state[77], wl_state[78], wl_state[79],
			      wl_state[80], wl_state[81], wl_state[82], wl_state[83], wl_state[84], wl_state[85], wl_state[86], wl_state[87], wl_state[88], wl_state[89],
			      wl_state[90], wl_state[91], wl_state[92], wl_state[93], wl_state[94], wl_state[95], wl_state[96], wl_state[97], wl_state[98], wl_state[99]);
	sprintf(cmd, "%s=%s", strcat_r(prefix, "state", tmp), wl_state_buf);
	eval("envram", "set", cmd);
	eval("nvram", "set", cmd);

	eval("envram", "commit");
	eval("nvram", "commit");
	sync(); sync(); sync();
}

int dummy_alert_led_pwr() {
    return (atoi(cfe_nvram_safe_get("wl0_dummy")) | atoi(cfe_nvram_safe_get("wl1_dummy"))
#if defined(RTCONFIG_HAS_5G_2)
	    | atoi(cfe_nvram_safe_get("wl2_dummy"))
#endif
	    );
}

void dummy_alert_led_wifi() {
	static int count = 0;
	static int stop_chk = 0;
	int twinkle_0 = nvram_get_int("wl0_tcount");
	int twinkle_1 = nvram_get_int("wl1_tcount");
	char ifname_5G[8];
	char state[2];
#if defined(RTCONFIG_HAS_5G_2)
	int twinkle_2 = nvram_get_int("wl2_tcount");
	char ifname_5G2[8];
#endif

	if (!nvram_match("success_start_service", "1"))
	    return;

	if(stop_chk)
	    return;

#if defined(GTAC5300)
	snprintf(ifname_5G, sizeof(ifname_5G), "eth7");
#elif defined(RTAC86U) || defined(GTAC2900)
	snprintf(ifname_5G, sizeof(ifname_5G), "eth6");
#elif defined(RTAC88U) || defined(RTAC3100) || defined(RTAC5300)
	snprintf(ifname_5G, sizeof(ifname_5G), "eth2");
#else
	snprintf(ifname_5G, sizeof(ifname_5G), "eth2");
#endif

#if defined(RTCONFIG_HAS_5G_2)
#if defined(GTAC5300)
	snprintf(ifname_5G2, sizeof(ifname_5G2), "eth8");
#elif defined(RTAC5300)
	snprintf(ifname_5G2, sizeof(ifname_5G2), "eth3");
#else
	snprintf(ifname_5G2, sizeof(ifname_5G2), "eth3");
#endif
#endif
	snprintf(state, sizeof(state), "%d", count % 2);

	if(twinkle_0) {
		eval("wl", "ledbh", "9", state);
		if(!atoi(state))
		nvram_set_int("wl0_tcount", twinkle_0-1);
	} else {
#ifdef GTAC2900
		eval("wl", "ledbh", "9", "1");
#else
		eval("wl", "ledbh", "9", "7");
#endif
	}

	if(twinkle_1) {
	    eval("wl", "-i", ifname_5G, "ledbh", "9", state);    // 5G
	    if(!atoi(state))
		nvram_set_int("wl1_tcount", twinkle_1-1);
	}
	else
	{
#ifdef GTAC2900
	    eval("wl", "-i", ifname_5G, "ledbh", "9", "1");
#else
	    eval("wl", "-i", ifname_5G, "ledbh", "9", "7");
#endif
	}

#if defined(RTCONFIG_HAS_5G_2)
	if(twinkle_2) {
	    eval("wl", "-i", ifname_5G2, "ledbh", "9", state);
	    if(!atoi(state))
		nvram_set_int("wl2_tcount", twinkle_2-1);
	}
	else
	{
	    eval("wl", "-i", ifname_5G2, "ledbh", "9", "7");
	}
#endif


	if(!twinkle_0 && !twinkle_1
#if defined(RTCONFIG_HAS_5G_2)
		&& !twinkle_2
#endif
	)
	    stop_chk = 1;

	count++;
}
#endif

#if defined(RTCONFIG_HND_ROUTER_AX_675X)
void update_cfe_675x()
{
	char mac[32], mac_et[32];
	char macaddr_path[] = { '/', 'p', 'r', 'o', 'c', '/', 'n', 'v', 'r', 'a', 'm', '/', 'B', 'a', 's', 'e', 'M', 'a', 'c', 'A', 'd', 'd', 'r', '\0' };

	if (f_read_string(macaddr_path, mac, sizeof(mac)) > 0)
	{
		if (!pids("envrams")) {
			system("/usr/sbin/envrams");
			usleep(100000);
		}

		strcpy(mac_et, cfe_nvram_safe_get_raw("et0macaddr"));

		if (strcmp(mac, mac_et))
			doSystem("echo %s > %s", mac_et, macaddr_path);
	}
}
#endif

#if defined(GTAX11000) || defined(RTAX88U)
void update_cfe_basemac()
{
	char mac[32], mac_et[32];
	char macaddr_path[] = { '/', 'p', 'r', 'o', 'c', '/', 'n', 'v', 'r', 'a', 'm', '/', 'B', 'a', 's', 'e', 'M', 'a', 'c', 'A', 'd', 'd', 'r', '\0' };

	if (f_read_string(macaddr_path, mac, sizeof(mac)) > 0)
	{
		if (!pids("envrams")) {
			system("/usr/sbin/envrams");
			usleep(100000);
		}

		strcpy(mac_et, cfe_nvram_safe_get_raw("et0macaddr"));

		if (strcmp(mac, mac_et) && strstr(mac, "10:18:1:0:1")) {
			doSystem("echo %s > %s", mac_et, macaddr_path);
			reboot(RB_AUTOBOOT);
		}
	}
}
#endif

#ifdef HND_ROUTER
void hnd_set_hwstp(void)
{
	char *lan_ifnames, *ifname, *p;

	if (is_routing_enabled() && nvram_get_int("lan_stp"))
		return;

	if ((lan_ifnames = strdup(nvram_safe_get("lan_ifnames"))) != NULL) {
		p = lan_ifnames;
		while ((ifname = strsep(&p, " ")) != NULL) {
			while (*ifname == ' ') ++ifname;

			if (*ifname == 0) break;

			if (!find_in_list(nvram_safe_get("wl_ifnames"), ifname))
				eval("ethswctl", "-c", "hwstp",  "-i",  ifname, "-o",  "disable");
		}

		free(lan_ifnames);
	}
}
#endif

#if defined(RTAX88U) || defined(RTAX92U) || defined(GTAX11000)
void update_11ax_config(void)
{
    int unit = 0;
    char word[256], *next;
    char tmp[32];
    char prefix[8];
    char wl_ifnames[32] = { 0 };

    strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
    foreach (word, wl_ifnames, next) {
	sprintf(prefix, "wl%d_", unit);
	/* update wlx_11ax according to he_features settings to be compatible with previous firmware */
	if( nvram_match("w_Setting","1") &&
		nvram_match(strcat_r(prefix, "11ax", tmp), "0") &&
		!nvram_match(strcat_r(prefix, "he_features", tmp), "0")) {
	    nvram_set(strcat_r(prefix, "11ax", tmp), "1");
	}
	unit++;
    }
}
#endif

#ifdef RTCONFIG_HSPOT
void update_hspotap_config(void)
{
    int unit = 0;
    char word[256], *next;
    char tmp[32];
    char prefix[8];
    char wl_ifnames[32] = { 0 };
    char hwaddr[18] = { 0 };

    strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
    foreach (word, wl_ifnames, next) {
	sprintf(prefix, "wl%d_", unit);
	/* override interworking netwrok type from chargeable public to private with guest */
	if(nvram_match(strcat_r(prefix, "iwnettype", tmp), "2")) {
	    nvram_set(strcat_r(prefix, "iwnettype", tmp), "1");
	}

	if(!nvram_match(strcat_r(prefix, "venuegrp", tmp), "7")) {
	    nvram_set(strcat_r(prefix, "venuegrp", tmp), "7");
	}

	snprintf(hwaddr, sizeof(hwaddr), nvram_safe_get(strcat_r(prefix, "hwaddr", tmp)));
	nvram_set(strcat_r(prefix, "hessid", tmp), hwaddr);

	unit++;
    }
}
#endif

#if defined(RTCONFIG_BCM_CLED) && defined(RTCONFIG_SINGLE_LED)
void remode_cled(int is_cfg_alive, int wlc_band_5g, int wlc_weak_rssi, int ready_for_brightness_dim, int cled_mode)
{
	int amas_path_stat = 0;
	int dbg = nvram_match("dbg", "1");
	static int re_retry_wait = 0;
	int retry_max = nvram_get_int("re_conn_t")?:3;
	int is_eap_mode = nvram_get_int("amas_eap_bhmode");

	if(dbg) _dprintf("->> %s chk is_cfg_alive=%d, amas_path_stat=%d, retry:%d(%d)\nconfig:[%s]\n\n", __func__, is_cfg_alive, nvram_get_int("amas_path_stat"), re_retry_wait, retry_max, nvram_safe_get("cfg_group"));

	if(is_cfg_alive == 1){
		re_retry_wait = 0;
		amas_path_stat = nvram_get_int("amas_path_stat");
		if(amas_path_stat != 1){	/* 2.4G or 5G */
			if(amas_path_stat == 4 || amas_path_stat == 8){
				if(get_psta_rssi(wlc_band_5g) < wlc_weak_rssi){
					/* 5G backhaul and weak signal */
					if(dbg) _dprintf(" ..%s-r1, set led as BCM_CLED_YELLOW\n", __func__);
					bcm_cled_ctrl(BCM_CLED_YELLOW, cled_mode);
				}else{
					if(dbg) _dprintf(" ..%s-r2, set led as BCM_CLED_WHITE\n", __func__);
					/* 5G backhaul and strong signal */
					bcm_cled_ctrl(BCM_CLED_WHITE, cled_mode);
				}
			}else{
				if(dbg) _dprintf(" ..%s-r3, set led as BCM_CLED_YELLOW\n", __func__);
				/* 2.4 backhaul */
				bcm_cled_ctrl(BCM_CLED_YELLOW, cled_mode);
			}
		}else{
			/* strong wireless signal or Ethernet backhaul */
			if(ready_for_brightness_dim == 1){
				if(dbg) _dprintf(" ..%s-r4, set led as BCM_CLED_WHITE\n", __func__);
				bcm_cled_ctrl(BCM_CLED_WHITE, (cled_mode==BCM_CLED_STEADY_NOBLINK)?BCM_CLED_STEADY_NOBLINK_DIM:BCM_CLED_STEADY_BLINK);
			}else{
				if(dbg) _dprintf(" ..%s-r5, set led as BCM_CLED_WHITE\n", __func__);
				bcm_cled_ctrl(BCM_CLED_WHITE, cled_mode);
			}
		}
	} else {
#if defined(RPAX56) || defined(RPAX58)
		if(dbg) _dprintf(" ..%s-r6, (rssi:%d) set led as BCM_CLED_RED, BCM_CLED_STEADY_NOBLINK\n", __func__, get_psta_rssi(wlc_band_5g));
		if(re_retry_wait++ < retry_max)
			bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
		else {
			re_retry_wait = 0;
			bcm_cled_ctrl(BCM_CLED_RED, BCM_CLED_STEADY_NOBLINK);
		}
#else
		if(dbg) _dprintf(" ..%s-r6, (rssi:%d) set led as BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK\n", __func__, get_psta_rssi(wlc_band_5g));
		if(is_eap_mode)
			bcm_cled_ctrl(BCM_CLED_RED, BCM_CLED_STEADY_BLINK);
		else
			bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);

#endif
	}
}

#if defined(RPAX56) || defined(RPAX58)
static int reset12 = 0;
#endif
#ifdef RTCONFIG_BCM_MFG
static int once = 0;
#endif

#if defined(RPAX56) || defined(RPAX58)
int is_weak_rssi(int rssi_2g, int rssi_5g, int weak_2g, int weak_5g)
{
	int ret = 0;

	if(rssi_2g>WL_IW_RSSI_NO_SIGNAL && rssi_5g>WL_IW_RSSI_NO_SIGNAL && (rssi_2g<weak_2g || rssi_5g<weak_5g))
		ret = 1;
	else if(rssi_2g<=WL_IW_RSSI_NO_SIGNAL && rssi_5g>WL_IW_RSSI_NO_SIGNAL && rssi_5g<weak_5g)
		ret = 1;
	else if(rssi_5g<=WL_IW_RSSI_NO_SIGNAL && rssi_2g>WL_IW_RSSI_NO_SIGNAL && rssi_2g<weak_2g)
		ret = 1;

	if(nvram_match("dbg", "1")) _dprintf("%s, 2g:%d, 5g:%d, weak_2g:%d, weak_5g:%d, ret:%d\n", __func__, rssi_2g, rssi_5g, weak_2g, weak_5g, ret);

	return ret;
}
#endif

int single_led_status(void)
{
	static int led_change_countdown = 0;
	int cled_mode = 0;
#ifdef RTCONFIG_BROOP_LED
	static int led_change2_countdown = 0;
	char *brif = nvram_safe_get("lan_ifname");
	char *ethif = nvram_safe_get("eth_ifnames");
#endif
	static int led_status_off = 0;
	int link_internet = nvram_get_int("link_internet");
	int wan_state_t;
	int is_re_mode = nvram_get_int("re_mode");
	int is_cfg_alive = nvram_get_int("cfg_alive");
	const int wait_time_for_brightness_dim = 5;
	int wait_time_for_led_status_change = 20;
#ifdef RTCONFIG_BROOP_LED
	const int wait_time_for_led_status2_change = 6;
#endif
	static int wait_for_brightness_dim = 0;
	int ready_for_brightness_dim = 0;
	static struct timeval tv_start, tv_end;
	int amas_path_stat = 0;
#if defined(RPAX56) || defined(RPAX58)
	int wlc_weak_rssi = nvram_get_int("wl1_user_rssi")?:-72;	// 5g
	int wlc_weak_rssi_2g = nvram_get_int("wl0_user_rssi")?:-70;	// 2g
#else
	int wlc_weak_rssi = -80;	// 5g
#endif
#if defined(RTCONFIG_HAS_5G_2)
	const int wlc_band_5g = 2;
#else
	const int wlc_band_5g = 1;
#endif
#if defined(RPAX56) || defined(RPAX58)
	const int wlc_band_2g = 0;
	int rssi_5g, rssi_2g;
        static int retry_wait = 0;
        int retry_max = nvram_get_int("re_conn_t")?:2;
#endif
	static int do_once=0;
	int link_rate = 0;

	if(nvram_match("stop_watchdog", "1"))	return 0;

	wan_state_t = nvram_get_int("wan0_state_t");

#ifndef RTCONFIG_BCM_MFG
	if (nvram_get_int("asus_mfg") == 1)
#endif
	{
#ifdef RTCONFIG_BCM_MFG
		if (!once) {
			once = 1;
			if (nvram_get_int("Ate_power_on_off_ret") == 2)
				bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
			else
				bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_NOBLINK);
		}
#endif
		led_change_countdown = 0;
		return 1;
	}

#if defined(RPAX56) || defined(RPAX58)
	if(!reset12 && !ATE_BRCM_FACTORY_MODE()) {
		_dprintf("\n rc: reset led12 ah/al\n");
		eval("sw", "0xff803018", "0x00001000");
#ifdef RPAX58
		eval("sw", "0xff803014", "0x58a0");
		eval("sw", "0xff803010", "0x58a0");
#else
		eval("sw", "0xff803014", "0xffffa75f");
#endif
		eval("sw", "0xff8030e0", "0");
		eval("sw", "0xff803100", "0");
		eval("sw", "0xff80301c", "0x58a0");

		reset12 = 1;
		return 1;
	}

	if(sw_mode() == SW_MODE_AP && nvram_get_int("wlc_psta") == 0)
		wait_time_for_led_status_change = 7;

	if(reset12==1 && (is_re_mode || rp_mode() || dpsr_mode())) {
		led_change_countdown = wait_time_for_led_status_change;
		reset12 = 2;
	}
#endif
        if(do_once==0 && nvram_match("x_Setting", "0")) {
                do_once++;
                led_change_countdown = wait_time_for_led_status_change;
        }

	if(nvram_get_int("AllLED") == 0){
		bcm_cled_ctrl(BCM_CLED_OFF, BCM_CLED_STEADY_NOBLINK);
		led_change_countdown = 0;
		led_status_off = 1;
		return 1;
	}

	if(nvram_get_int("cfg_obstatus") == 4 && strlen(nvram_safe_get("cfg_obnewre"))){ /* OB_LOCKED and ob new re */
		bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
		led_change_countdown = 0;
		return 1;
	}


	if(nvram_get_int("re_mode") == 1) 
	{
		if(nvram_match("cfg_group", "")) {
			bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
			led_change_countdown = 0;
			return 1;
		}
	}
/*
#ifdef RPAX56
	if(is_rp_configured() && nvram_match("wlc_state", "1") && !nvram_match("wlc_mode", "1"))
	{
		bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
		led_change_countdown = 0;
		return 1;
	}
#endif
*/

#ifdef RTCONFIG_AMAS_ADTBW
	if(nvram_get_int("amas_adtbw_led")) {
		bcm_cled_ctrl(BCM_CLED_GREEN, BCM_CLED_STEADY_NOBLINK);
		led_change_countdown = 0;
		return 1;
	}
#endif

	if(nvram_get_int("bcm_cled_in_wps") == 1){
		led_change_countdown = 0;
		return 1;
	}

	if(nvram_get_int("bcm_cled_in_reset") == 1){
		led_change_countdown = 0;
		return 1;
	}

	if(nvram_get_int("ble_dut_con") == 1){
		bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
		led_change_countdown = 0;
		return 1;
	}
/*
	if(nvram_get_int("x_Setting") == 0){
		bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_NOBLINK);
		led_change_countdown = 0;
		return 1;
	}
*/
#ifndef RPAX58
	if(wait_for_brightness_dim == 0 ||
		nvram_get_int("wlready") == 0){
		gettimeofday(&tv_start, NULL);
		wait_for_brightness_dim = 1;
		ready_for_brightness_dim = 0;
	} else{
		gettimeofday(&tv_end, NULL);
		if((tv_end.tv_sec - tv_start.tv_sec) > wait_time_for_brightness_dim){
			ready_for_brightness_dim = 1;
		}
	}
#endif

	if(nvram_get_int("AllLED") == 1 && led_status_off == 1){
		led_status_off = 0;
		led_change_countdown = wait_time_for_led_status_change + 1;
	}

#ifdef RTCONFIG_BROOP_LED
	/* none? */
	if(is_re_mode == 1){
		if(led_change2_countdown < wait_time_for_led_status2_change){
			led_change2_countdown++;
			if(is_bridged(brif, ethif) && led_change2_countdown == wait_time_for_led_status2_change-1)
				cled_mode = BCM_CLED_STEADY_BLINK;
			else
				return 1;
		}else{
			led_change2_countdown = 0;
			cled_mode = BCM_CLED_STEADY_NOBLINK;
		}

		remode_cled(is_cfg_alive, wlc_band_5g, wlc_weak_rssi, ready_for_brightness_dim, cled_mode);

		return 1;
	}
#endif

	if(led_change_countdown < wait_time_for_led_status_change /* seconds */){
		led_change_countdown++;
		return 1;
	}else{
		led_change_countdown = 0;
	}

	if(nvram_get_int("x_Setting") == 0){
		bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_NOBLINK);
		//led_change_countdown = 0;
		return 1;
	}

#ifndef RTCONFIG_BROOP_LED
	/* These are checked every wait_time_for_led_status_change seconds */
	if(is_re_mode == 1){
		cled_mode = BCM_CLED_STEADY_NOBLINK;

		remode_cled(is_cfg_alive, wlc_band_5g, wlc_weak_rssi, ready_for_brightness_dim, cled_mode);

		return 1;
	}
#endif

	if (sw_mode() == SW_MODE_AP){
		if(nvram_get_int("wlc_psta") == 0){
			/* AP mode */
#if defined(RTAX95Q) || defined(XT8PRO) || defined(XT8_V2) || defined(RTAXE95Q) || defined(ET8PRO) || defined(RTAX56_XD4) || defined(CTAX56_XD4) || defined(XD4PRO)
			/* LED spec. 20191212 */
			bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
#else
			/* LED spec. 20191126 */
			link_rate = get_uplinkports_linkrate(wan_if_eth());
			if(link_rate > 0) {
				bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
			} else {
				bcm_cled_ctrl(BCM_CLED_RED, BCM_CLED_STEADY_NOBLINK);
			}
#endif
		}else if(nvram_get_int("wlc_psta") == 1){
			/* media bridge */
			if(nvram_get_int("wlc_mode") == 1){
				if(ready_for_brightness_dim == 1){
					bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK_DIM);
				}else{
					bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
				}
			}else{
				bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
			}
		}else if(nvram_get_int("wlc_psta") == 2){
			/* repeater */
			if(nvram_get_int("wlc_mode") == 1){
#if defined(RPAX56) || defined(RPAX58)
				retry_wait = 0;
				rssi_2g = get_psta_rssi(wlc_band_2g);
				rssi_5g = get_psta_rssi(wlc_band_5g);

				if(ready_for_brightness_dim == 1){
					if(is_weak_rssi(rssi_2g, rssi_5g, wlc_weak_rssi_2g, wlc_weak_rssi)) {
						bcm_cled_ctrl(BCM_CLED_YELLOW, BCM_CLED_STEADY_NOBLINK);	// chk dim
					} else {
						bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK_DIM);
					}
				}else{
					if(is_weak_rssi(rssi_2g, rssi_5g, wlc_weak_rssi_2g, wlc_weak_rssi)) {
						bcm_cled_ctrl(BCM_CLED_YELLOW, BCM_CLED_STEADY_NOBLINK);
					} else {
						bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
					}
				}
#else
				if(ready_for_brightness_dim == 1)
						bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK_DIM);
				else
						bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
#endif
			}else{
#if defined(RPAX56) || defined(RPAX58)
				if(retry_wait++ < retry_max)
					bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
				else {
					retry_wait = 0;
					bcm_cled_ctrl(BCM_CLED_RED, BCM_CLED_STEADY_NOBLINK);
				}
#else
				bcm_cled_ctrl(BCM_CLED_BLUE, BCM_CLED_STEADY_BLINK);
#endif
			}
		}
		return 1;
	}

	if(link_internet == 2){
		if(wan_state_t == WAN_STATE_CONNECTED){
			if(ready_for_brightness_dim == 1){
				bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK_DIM);
			}else{
				bcm_cled_ctrl(BCM_CLED_WHITE, BCM_CLED_STEADY_NOBLINK);
			}
		}else{
			bcm_cled_ctrl(BCM_CLED_RED, BCM_CLED_STEADY_NOBLINK);
		}
	}else{
		bcm_cled_ctrl(BCM_CLED_RED, BCM_CLED_STEADY_NOBLINK);
	}

	return 1;
}
#endif
#ifdef RTCONFIG_NBR_RPT
uint8 nbr_get_rclass_str(int bssidx,int vifidx,char *chanspec_str)
{
	char wlif_name[16]={0};
	char prefix[16]={0};
	char tmp[32]={0};
	char ioctl_buf[256];
	char *param;
	int buflen;
	uint8 rclass = 0;
	chanspec_t chanspec;

	chanspec = wf_chspec_aton(chanspec_str);

	//_dprintf("chanspec: 0x%x\n", chanspec);

	if(nvram_get_int("re_mode")==1){
		if(vifidx > 0)
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx+1);
		else
			snprintf(prefix, sizeof(prefix), "wl%d.1_", bssidx);
	} else {
		if(vifidx > 0)
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx);
		else
			snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);	
	}

	strncpy(wlif_name, nvram_safe_get(strcat_r(prefix, "ifname", tmp)) ,sizeof(wlif_name) );

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "rclass");
	buflen = strlen(ioctl_buf) + 1;
	param = (char *)(ioctl_buf + buflen);
	memcpy(param, &chanspec, sizeof(chanspec_t));

	if(wl_ioctl(wlif_name, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf))){
		_dprintf("Error to read rclass: %s\n", wlif_name);
		rclass = 255;
	} else 
		rclass = (uint8)(*((uint32 *)ioctl_buf));
	//_dprintf("[%s] rclass: 0x%x\n", wlif_name, rclass);

	return rclass;
}
uint8 nbr_get_rclass_cht(int bssidx,int vifidx,chanspec_t chanspec)
{
	char wlif_name[16]={0};
	char ioctl_buf[256];
	char *param;
	int buflen;
	uint8 rclass = 0;
	char prefix[16]={0};
	char tmp[32]={0};
	//chanspec_t chanspec;

	//chanspec = wf_chspec_aton(chanspec_str);

	//_dprintf("chanspec: 0x%x\n", chanspec);

	if(nvram_get_int("re_mode")==1){
		if(vifidx > 0)
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx+1);
		else
			snprintf(prefix, sizeof(prefix), "wl%d.1_", bssidx);
	} else {
		if(vifidx > 0)
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx);
		else
			snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);	
	}

	strncpy(wlif_name, nvram_safe_get(strcat_r(prefix, "ifname", tmp)) ,sizeof(wlif_name) );

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "rclass");
	buflen = strlen(ioctl_buf) + 1;
	param = (char *)(ioctl_buf + buflen);
	memcpy(param, &chanspec, sizeof(chanspec_t));

	if(wl_ioctl(wlif_name, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf))){
		_dprintf("Error to read rclass: %s\n", wlif_name);
		rclass = 255;
	} else 
		rclass = (uint8)(*((uint32 *)ioctl_buf));
	//_dprintf("[%s] rclass: 0x%x\n", wlif_name, rclass);

	return rclass;
}

void r_wl_control_channel(int unit, int *channel, int *bw, int *nctrlsb)
{
	int ret;
	struct ether_addr bssid;
	wl_bss_info_t *bi;
	wl_bss_info_107_t *old_bi;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	char buf[WLC_IOCTL_MAXLEN];

#ifdef RTCONFIG_DPSTA
        if (dpsta_mode())
		snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
        else
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if ((ret = wl_ioctl(name, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN)) == 0) {
		/* The adapter is associated. */
		*(uint32*)buf = htod32(WLC_IOCTL_MAXLEN);
		if ((ret = wl_ioctl(name, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN)) < 0)
			return;

		bi = (wl_bss_info_t*)(buf + 4);
		if (dtoh32(bi->version) == WL_BSS_INFO_VERSION ||
			dtoh32(bi->version) == LEGACY2_WL_BSS_INFO_VERSION ||
			dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION)
		{
			/* Convert version 107 to 109 */
			if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
				old_bi = (wl_bss_info_107_t *)bi;
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
				bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel, WL_CHANNEL_2G5G_BAND(old_bi->channel));
#else
				bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
#endif
				bi->ie_length = old_bi->ie_length;
				bi->ie_offset = sizeof(wl_bss_info_107_t);
			}

			if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap)
				*channel = bi->ctl_ch;
			else
				*channel = bi->chanspec & WL_CHANSPEC_CHAN_MASK;

			if (CHSPEC_IS20(bi->chanspec))
				*bw = 20;
			else if (CHSPEC_IS40(bi->chanspec)) {
				*bw = 40;
				if (CHSPEC_SB_UPPER(bi->chanspec))
					*nctrlsb = 1;
			}
			else if (CHSPEC_IS80(bi->chanspec))
				*bw = 80;
#if defined(RTCONFIG_HND_ROUTER_AX) || defined(RTCONFIG_BW160M)
			else if (CHSPEC_IS160(bi->chanspec))
				*bw = 160;
#endif
		}
	}
}

void wl_set_nbr_info(void)
{
	int  idx           = 0;
	char *next         = NULL;
	char *next_nbr_pre = NULL;
	char nbr_bssid[18] = {0};
	char prefix[18]    = {0};
	char ifname[32]    = {0};
	char ifname_tmp[32]= {0};
	char bssid_2g[18]  = {0};
	//char channel_2g[6] = {0};
	char ssid_2g[33]   = {0};
	char bssid_5g[18]  = {0};
	//char channel_5g[6] = {0};
	char ssid_5g[33]   = {0};
	char bssid_5g1[18]  = {0};
	//char channel_5g1[6] = {0};
	char ssid_5g1[33]   = {0};
	char tmp[32];
	char index_str[6]  = {0};
	int relist_index=0;
	int channel,tmp_int1,tmp_int2;
	int bandnum=0;
	int cap_band_num = nvram_get_int("r_wl_band_num_cap");
	json_object *aplist=NULL;
	json_object *apentryObj=NULL;
	json_object *ap2gObj=NULL;
	json_object *ap5gObj=NULL;
	json_object *ap5g1Obj=NULL;

	char channel_2g[6] = {0};
	char channelspec_2g[12] = {0};
	char channelclass_2g[6] = {0};
	char channel_5g[6] = {0};
	char channelspec_5g[12] = {0};
	char channelclass_5g[6] = {0};
	char channel_5g1[6] = {0};
	char channelspec_5g1[12] = {0};
	char channelclass_5g1[6] = {0};

	chanspec_t chanspec_2g,chanspec_5g,chanspec_5g1;
	//int channel = 0;
	//nt bw = 0;
	//int nctrlsb = 0;
	char chanspec_str[16];
	//int channel = 0;
	int bw = 0;
	int nctrlsb = 0;
	int is_re = nvram_get_int("re_mode");
	chanspec_t chspec_cur = 0;
	char chanbuf[CHANSPEC_STR_LEN];
	int selected5gband;
	int i;
	int dualtriband_mix=0;
	//int dualband_5g_is_high = 0;

	char nbuf_wl_ifnames[4096]={0};
	char nbuf_nbr_list_pre[4096]={0};

	int nbr_dbg = nvram_get_int("nbr_dbg");
	if(nbr_dbg != 1) nbr_dbg = 0;

	if(uptime()<300)
		return;

	if(cap_band_num == 0 && is_re ) {
		_dprintf("cap_band_num 0\n");
		return;
	}

	strncpy(nbuf_wl_ifnames,nvram_safe_get("wl_ifnames"),sizeof(nbuf_wl_ifnames));
	foreach(ifname_tmp, nbuf_wl_ifnames, next) {
		bandnum++;
	}

	if( is_re == 1 ){
		if(bandnum != cap_band_num){
			dualtriband_mix=1;
			if( cap_band_num == 3 && bandnum == 2 ){
				for(i=0;i<cap_band_num;i++) {
					if(i==0){
						channel = nvram_get_int("r_wl0_channel");
						bw = nvram_get_int("r_wl0_bw");
						nctrlsb = nvram_get_int("r_wl0_nctrlsb");
						snprintf(channel_2g,sizeof(channel_2g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_2g,sizeof(channelclass_2g),"%d", nbr_get_rclass_str(0,0,chanspec_str) );
						snprintf(channelspec_2g,sizeof(channelspec_2g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_2g);
					}else if(i==1){
						channel = nvram_get_int("r_wl1_channel");
						bw = nvram_get_int("r_wl1_bw");
						nctrlsb = nvram_get_int("r_wl1_nctrlsb");
						snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g,sizeof(channelclass_5g),"%d", nbr_get_rclass_str(1,0,chanspec_str) );
						snprintf(channelspec_5g,sizeof(channelspec_5g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g);
					} else if(i==2){
						channel = nvram_get_int("r_wl2_channel");
						bw = nvram_get_int("r_wl2_bw");
						nctrlsb = nvram_get_int("r_wl2_nctrlsb");
						snprintf(channel_5g1,sizeof(channel_5g1),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g1,sizeof(channelclass_5g1),"%d", nbr_get_rclass_str(1,0,chanspec_str) );
						snprintf(channelspec_5g1,sizeof(channelspec_5g1),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g1);
					}
				}
			} else if( cap_band_num == 2 && bandnum == 3 ){
				//ignore_5g=1;
				for(i=0;i<bandnum;i++) {
					selected5gband = nvram_get_int("r_selected5gband");//1 low,2 high
					if(i==0){
						channel = nvram_get_int("r_wl0_channel");
						bw = nvram_get_int("r_wl0_bw");
						nctrlsb = nvram_get_int("r_wl0_nctrlsb");
						snprintf(channel_2g,sizeof(channel_2g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_2g,sizeof(channelclass_2g),"%d", nbr_get_rclass_str(0,0,chanspec_str) );
						snprintf(channelspec_2g,sizeof(channelspec_2g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_2g);
					}else if(i==1){
						channel = nvram_get_int("r_wl1_channel");
						bw = nvram_get_int("r_wl1_bw");
						nctrlsb = nvram_get_int("r_wl1_nctrlsb");
						snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g,sizeof(channelclass_5g),"%d", nbr_get_rclass_str(2,0,chanspec_str) );
						snprintf(channelspec_5g,sizeof(channelspec_5g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g);
					} else {
						channel = nvram_get_int("r_wl2_channel");
						bw = nvram_get_int("r_wl2_bw");
						nctrlsb = nvram_get_int("r_wl2_nctrlsb");
						snprintf(channel_5g1,sizeof(channel_5g1),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g1,sizeof(channelclass_5g1),"%d", nbr_get_rclass_str(2,0,chanspec_str) );
						snprintf(channelspec_5g1,sizeof(channelspec_5g1),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g1);
					}
				}
			} else{
				_dprintf("unexcept band num case %d %d\n",cap_band_num,bandnum);
				return;
			}
		} else {
			if(nvram_get_int("r_selected5gband") == 1 || nvram_get_int("r_selected5gband") == 2)
				dualtriband_mix=1;
			for(i=0;i<cap_band_num;i++) {
				if(i==0){
					channel = nvram_get_int("r_wl0_channel");
					bw = nvram_get_int("r_wl0_bw");
					nctrlsb = nvram_get_int("r_wl0_nctrlsb");
					snprintf(channel_2g,sizeof(channel_2g),"%d",channel);
					snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
					if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
					snprintf(channelclass_2g,sizeof(channelclass_2g),"%d", nbr_get_rclass_str(0,0,chanspec_str) );
					snprintf(channelspec_2g,sizeof(channelspec_2g),"0x%04x",wf_chspec_aton(chanspec_str));
					if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_2g);
				}else if(i==1){
					channel = nvram_get_int("r_wl1_channel");
					bw = nvram_get_int("r_wl1_bw");
					nctrlsb = nvram_get_int("r_wl1_nctrlsb");
					snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
					snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
					if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
					snprintf(channelclass_5g,sizeof(channelclass_5g),"%d", nbr_get_rclass_str(1,0,chanspec_str) );
					snprintf(channelspec_5g,sizeof(channelspec_5g),"0x%04x",wf_chspec_aton(chanspec_str));
					if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g);
				}else {
					channel = nvram_get_int("r_wl2_channel");
					bw = nvram_get_int("r_wl2_bw");
					nctrlsb = nvram_get_int("r_wl2_nctrlsb");
					snprintf(channel_5g1,sizeof(channel_5g1),"%d",channel);
					snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
					if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
					snprintf(channelclass_5g1,sizeof(channelclass_5g1),"%d", nbr_get_rclass_str(2,0,chanspec_str) );
					snprintf(channelspec_5g1,sizeof(channelspec_5g1),"0x%04x",wf_chspec_aton(chanspec_str));
					if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g1);
				}
			}
		}
	} else { //cap
		selected5gband = nvram_get_int("r_selected5gband");
		if(bandnum == 2 && (selected5gband == 1 || selected5gband == 2) )
			dualtriband_mix=1;
		if( selected5gband && bandnum == 2 ) {
			if( selected5gband == 1 ) { //dual band CAP use 5g-high
				for(i=0;i<3;i++) {
					if(i==0){
						r_wl_control_channel(0, &channel,  &bw, &nctrlsb);
						snprintf(channel_2g,sizeof(channel_2g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_2g,sizeof(channelclass_2g),"%d", nbr_get_rclass_str(0,0,chanspec_str) );
						snprintf(channelspec_2g,sizeof(channelspec_2g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_2g);
					}else if(i==1){
						channel = nvram_get_int("r_selected5gchannel");
						bw = nvram_get_int("r_selected5gbw");
						nctrlsb = nvram_get_int("r_selected5gnctrlsb");
						snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g,sizeof(channelclass_5g),"%d", nbr_get_rclass_str(1,0,chanspec_str) );
						snprintf(channelspec_5g,sizeof(channelspec_5g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g);
					}else {
						r_wl_control_channel(2, &channel,  &bw, &nctrlsb);
						snprintf(channel_5g1,sizeof(channel_5g1),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g1,sizeof(channelclass_5g1),"%d", nbr_get_rclass_str(2,0,chanspec_str) );
						snprintf(channelspec_5g1,sizeof(channelspec_5g1),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g1);
					}
				}
			} else {
				for(i=0;i<3;i++) {
					if(i==0){
						r_wl_control_channel(0, &channel,  &bw, &nctrlsb);
						snprintf(channel_2g,sizeof(channel_2g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_2g,sizeof(channelclass_2g),"%d", nbr_get_rclass_str(0,0,chanspec_str) );
						snprintf(channelspec_2g,sizeof(channelspec_2g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_2g);
					}else if(i==1){
						r_wl_control_channel(1, &channel,  &bw, &nctrlsb);
						snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g,sizeof(channelclass_5g),"%d", nbr_get_rclass_str(1,0,chanspec_str) );
						snprintf(channelspec_5g,sizeof(channelspec_5g),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g);
					}else {
						channel = nvram_get_int("r_selected5gchannel");
						bw = nvram_get_int("r_selected5gbw");
						nctrlsb = nvram_get_int("r_selected5gnctrlsb");
						snprintf(channel_5g1,sizeof(channel_5g1),"%d",channel);
						snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
						if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
						snprintf(channelclass_5g1,sizeof(channelclass_5g1),"%d", nbr_get_rclass_str(2,0,chanspec_str) );
						snprintf(channelspec_5g1,sizeof(channelspec_5g1),"0x%04x",wf_chspec_aton(chanspec_str));
						if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g1);
					}
				}
			}		
		} else {
			for(i=0;i<bandnum;i++) {
				if(i==0) {
					r_wl_control_channel(0, &channel,  &bw, &nctrlsb);
					snprintf(channel_2g,sizeof(channel_2g),"%d",channel);
					snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
					if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
					snprintf(channelclass_2g,sizeof(channelclass_2g),"%d", nbr_get_rclass_str(0,0,chanspec_str) );
					snprintf(channelspec_2g,sizeof(channelspec_2g),"0x%04x",wf_chspec_aton(chanspec_str));
					if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_2g);
				} else if(i==1){
					r_wl_control_channel(1, &channel,  &bw, &nctrlsb);
					snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
					snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
					if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
					snprintf(channelclass_5g,sizeof(channelclass_5g),"%d", nbr_get_rclass_str(1,0,chanspec_str) );
					snprintf(channelspec_5g,sizeof(channelspec_5g),"0x%04x",wf_chspec_aton(chanspec_str));
					if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g);
				} else {
					r_wl_control_channel(2, &channel,  &bw, &nctrlsb);
					snprintf(channel_5g1,sizeof(channel_5g1),"%d",channel);
					snprintf(chanspec_str,sizeof(chanspec_str),"%d/%d",channel,bw);
					if(nbr_dbg) _dprintf("chanspec_str %s\n",chanspec_str);
					snprintf(channelclass_5g1,sizeof(channelclass_5g1),"%d", nbr_get_rclass_str(2,0,chanspec_str) );
					snprintf(channelspec_5g1,sizeof(channelspec_5g1),"0x%04x",wf_chspec_aton(chanspec_str));
					if(nbr_dbg) _dprintf("chanspec %s\n",channelspec_5g1);
				}
			}
		}
	}

	//if(!ignore_5g){
		if( !strcmp(channel_2g,nvram_safe_get("channel_2g")) && 
			!strcmp(channelclass_2g,nvram_safe_get("channelclass_2g")) &&
			!strcmp(channelspec_2g,nvram_safe_get("channelspec_2g")) &&
			!strcmp(channel_5g,nvram_safe_get("channel_5g")) && 
			!strcmp(channelclass_5g,nvram_safe_get("channelclass_5g")) &&
			!strcmp(channelspec_5g,nvram_safe_get("channelspec_5g")) &&
			!strcmp(channel_5g1,nvram_safe_get("channel_5g1")) && 
			!strcmp(channelclass_5g1,nvram_safe_get("channelclass_5g1")) &&
			!strcmp(channelspec_5g1,nvram_safe_get("channelspec_5g1"))  )
		{
			if(nbr_dbg) _dprintf("channel info no change\n");
			return;
		} else {//need unset in init
			nvram_set("channel_2g",channel_2g);
			nvram_set("channelclass_2g",channelclass_2g);
			nvram_set("channelspec_2g",channelspec_2g);
			nvram_set("channel_5g",channel_5g);
			nvram_set("channelclass_5g",channelclass_5g);
			nvram_set("channelspec_5g",channelspec_5g);
			nvram_set("channel_5g1",channel_5g1);
			nvram_set("channelclass_5g1",channelclass_5g1);
			nvram_set("channelspec_5g1",channelspec_5g1);
		}

    if( ( aplist = json_object_from_file("/tmp/aplist.json")) == NULL ){
    	_dprintf("aplist is not exist\n");
    	return;
    }

	idx=0;

	foreach(ifname_tmp, nbuf_wl_ifnames, next) {
/*
wl rrm_nbr_add_nbr [bssid] [bssid info] [regulatory] [channel] [phytype] [ssid] [chanspec] [prefence]
wl -i eth5 rrm_nbr_add_nbr 74:D0:2B:64:F3:CC 3 255 153 2 !xt8_nbr_test_5G-1 0 0
*/
		//if(idx > 1) break; //for now only 2G and 5g-1

		if(nvram_get_int("re_mode") == 1)
			snprintf(prefix,sizeof(prefix),"wl%d.1_",idx);
		else
			snprintf(prefix,sizeof(prefix),"wl%d_",idx);

		strncpy(ifname,nvram_safe_get(strcat_r(prefix, "ifname", tmp)),sizeof(ifname));
		strncpy(nbuf_nbr_list_pre,nvram_safe_get(strcat_r(prefix, "nbr_list_pre", tmp)),sizeof(nbuf_nbr_list_pre));

		/* delete old list */
		foreach(nbr_bssid, nbuf_nbr_list_pre, next_nbr_pre) {
			eval("wl", "-i", ifname, "rrm_nbr_del_nbr",nbr_bssid);
		}

		memset(nbuf_nbr_list_pre,0,sizeof(nbuf_nbr_list_pre));

		//channel = wl_control_channel(idx);

		/* set new list CFG_STR_AP2G */
		relist_index=0;
		while(1) {
			snprintf(index_str,sizeof(index_str),"%d",relist_index);
				//root = json_tokener_parse((char *)data);
			json_object_object_get_ex(aplist, index_str, &apentryObj);
			if(apentryObj == NULL)
				break;
			json_object_object_get_ex(apentryObj , CFG_STR_AP2G, &ap2gObj);
			json_object_object_get_ex(apentryObj , CFG_STR_AP5G, &ap5gObj);
			json_object_object_get_ex(apentryObj , CFG_STR_AP5G1, &ap5g1Obj);

			if(ap2gObj && idx == 0){
				if( ap2gObj && !strcasecmp( nvram_safe_get(strcat_r(prefix, "hwaddr", tmp)), 
								 json_object_get_string(ap2gObj) ) ) {
					relist_index++;
					continue;
				}
				strncpy(bssid_2g, json_object_get_string(ap2gObj),sizeof(bssid_2g) );
				strncpy(ssid_2g, nvram_safe_get(strcat_r(prefix, "ssid", tmp)),sizeof(ssid_2g) );
				if(nbr_dbg) _dprintf("rrm_nbr_add_nbr [%d] %s %s %s %s\n",__LINE__,ifname,bssid_2g,channel_2g,ssid_2g);
				eval("wl", "-i", ifname, "rrm_nbr_add_nbr",bssid_2g,"6287",channelclass_2g,channel_2g
					,"9",ssid_2g,channelspec_2g,"1");

				if(strlen(nbuf_nbr_list_pre) == 0) {
					snprintf(nbuf_nbr_list_pre,sizeof(nbuf_nbr_list_pre),"%s",bssid_2g);
				} else {
					snprintf(nbuf_nbr_list_pre+strlen(nbuf_nbr_list_pre),
						sizeof(nbuf_nbr_list_pre)-strlen(nbuf_nbr_list_pre)," %s",bssid_2g);
				}

			} else if( idx == 1 ) {
				if( ap5gObj && !strcasecmp( nvram_safe_get(strcat_r(prefix, "hwaddr", tmp)), 
								 json_object_get_string(ap5gObj) ) ) {
					relist_index++;
					continue;
				}

				if( (dualtriband_mix) || ( bandnum == 3 ) )
				{
					if( ap5g1Obj != NULL && (strlen(json_object_get_string(ap5g1Obj)) > 16) ) {
						if( ap5gObj != NULL && (strlen(json_object_get_string(ap5gObj)) > 16) ) {
							strncpy(bssid_5g, json_object_get_string(ap5gObj),sizeof(bssid_5g) );
							strncpy(ssid_5g, nvram_safe_get(strcat_r(prefix, "ssid", tmp)),sizeof(ssid_5g) );
							//strncpy(bssid_2g, json_object_get_string(ap2gObj),sizeof(bssid_2g) );
							//wl1.1 D4:5D:64:92:50:D4 40 !xd4_test_5G
							//wl -i wl1.1 rrm_nbr_add_nbr D4:5D:64:92:50:D4 6287 
							if(nbr_dbg) _dprintf("rrm_nbr_add_nbr [%d] %s %s %s %s\n",__LINE__,ifname,bssid_5g,channel_5g,ssid_5g);
							eval("wl", "-i", ifname, "rrm_nbr_add_nbr",bssid_5g,"6287",channelclass_5g,channel_5g
								,"9",ssid_5g,channelspec_5g,"1");

							if(strlen(nbuf_nbr_list_pre) == 0) {
								snprintf(nbuf_nbr_list_pre,sizeof(nbuf_nbr_list_pre),"%s",bssid_5g);
							} else {
								snprintf(nbuf_nbr_list_pre+strlen(nbuf_nbr_list_pre),
									sizeof(nbuf_nbr_list_pre)-strlen(nbuf_nbr_list_pre)," %s",bssid_5g);
							}
						}
					} else {
						/*
						if( ap5gObj != NULL && (strlen(json_object_get_string(ap5gObj)) > 16) ) {
							strncpy(bssid_5g, json_object_get_string(ap5gObj),sizeof(bssid_5g) );
							snprintf(channel_5g,sizeof(channel_5g),"%d",channel);
							strncpy(ssid_5g, nvram_safe_get(strcat_r(prefix, "ssid", tmp)),sizeof(ssid_5g) );
							//strncpy(bssid_2g, json_object_get_string(ap2gObj),sizeof(bssid_2g) );
							//wl1.1 D4:5D:64:92:50:D4 40 !xd4_test_5G
							//wl -i wl1.1 rrm_nbr_add_nbr D4:5D:64:92:50:D4 6287 
							_dprintf("rrm_nbr_add_nbr [%d] %s %s %s %s\n",__LINE__,ifname,bssid_5g,channel_5g,ssid_5g);
							eval("wl", "-i", ifname, "rrm_nbr_add_nbr",bssid_5g,"6287",channelclass_5g,channel_5g
								,"9",ssid_5g,"0","1");

							if(strlen(nbuf_nbr_list_pre) == 0) {
								snprintf(nbuf_nbr_list_pre,sizeof(nbuf_nbr_list_pre),"%s",bssid_5g);
							} else {
								snprintf(nbuf_nbr_list_pre+strlen(nbuf_nbr_list_pre),
									sizeof(nbuf_nbr_list_pre)-strlen(nbuf_nbr_list_pre)," %s",bssid_5g);
							}
						}
						*/
					}
				} else { //cap and self-band both 2
					if( ap5gObj != NULL && (strlen(json_object_get_string(ap5gObj)) > 16) ) {
						if( !dualtriband_mix ||
							( ap5g1Obj != NULL && (strlen(json_object_get_string(ap5g1Obj)) > 16) )) {
							strncpy(bssid_5g, json_object_get_string(ap5gObj),sizeof(bssid_5g) );
							strncpy(ssid_5g, nvram_safe_get(strcat_r(prefix, "ssid", tmp)),sizeof(ssid_5g) );
							//strncpy(bssid_2g, json_object_get_string(ap2gObj),sizeof(bssid_2g) );
							//wl1.1 D4:5D:64:92:50:D4 40 !xd4_test_5G
							//wl -i wl1.1 rrm_nbr_add_nbr D4:5D:64:92:50:D4 6287 
							if(nbr_dbg) _dprintf("rrm_nbr_add_nbr [%d] %s %s %s %s\n",__LINE__,ifname,bssid_5g,channel_5g,ssid_5g);
							eval("wl", "-i", ifname, "rrm_nbr_add_nbr",bssid_5g,"6287",channelclass_5g,channel_5g
								,"9",ssid_5g,channelspec_5g,"1");

							if(strlen(nbuf_nbr_list_pre) == 0) {
								snprintf(nbuf_nbr_list_pre,sizeof(nbuf_nbr_list_pre),"%s",bssid_5g);
							} else {
								snprintf(nbuf_nbr_list_pre+strlen(nbuf_nbr_list_pre),
									sizeof(nbuf_nbr_list_pre)-strlen(nbuf_nbr_list_pre)," %s",bssid_5g);
							}
						}
					}
				}
			} else if( idx == 2 ) {
				if( ap5g1Obj != NULL && (strlen(json_object_get_string(ap5g1Obj)) > 16) ) {
					if( !strcasecmp( nvram_safe_get(strcat_r(prefix, "hwaddr", tmp)), 
									 json_object_get_string(ap5g1Obj) ) ) {
						relist_index++;
						continue;
					}
					strncpy(bssid_5g1, json_object_get_string(ap5g1Obj),sizeof(bssid_5g1) );
					strncpy(ssid_5g1, nvram_safe_get(strcat_r(prefix, "ssid", tmp)),sizeof(ssid_5g1) );
					if(nbr_dbg) _dprintf("rrm_nbr_add_nbr [%d] %s %s %s %s\n",__LINE__,ifname,bssid_5g1,channel_5g1,ssid_5g1);
					eval("wl", "-i", ifname, "rrm_nbr_add_nbr",bssid_5g1,"6287",channelclass_5g1,channel_5g1
						,"9",ssid_5g1,channelspec_5g1,"1");

					if(strlen(nbuf_nbr_list_pre) == 0) {
						snprintf(nbuf_nbr_list_pre,sizeof(nbuf_nbr_list_pre),"%s",bssid_5g);
					} else {
						snprintf(nbuf_nbr_list_pre+strlen(nbuf_nbr_list_pre),
							sizeof(nbuf_nbr_list_pre)-strlen(nbuf_nbr_list_pre)," %s",bssid_5g);
					}
				}
			}

			relist_index++;
		}

		nvram_set(strcat_r(prefix, "nbr_list_pre", tmp),nbuf_nbr_list_pre);

		idx++;
	}

nbr_exit:
	json_object_put(aplist);
}
#endif //RTCONFIG_NBR_RPT

#ifdef RTCONFIG_FAST_ACL_SET
void check_stop_flag(int *stop_flag)
{
	*stop_flag = STOP_BSD | STOP_ROAMAST;
}
/*
nvram set wl1_maclist_x="<11:22:33:44:55:66<11:22:33:44:55:67<b6:64:14:32:60:65"
nvram set acl_tmp_bssidx=1
nvram set acl_tmp_vifidx=-1
rc rc_service start_fastaclset
wl -i eth2 mac
*/
void set_acl_and_remove_sta(int bssidx, int vifidx)
{
	struct maclist *maclist;
	char wlif_name[64];
	char macmode[16]={0};
	char tmp[64]={0};
	char maclist_buf[4096]={0};	
	int ret;
	int val;
	int mcnt;
	struct maclist *sta_mac_list;
	char sta_mac_list_buf[4096]={0};	
	int stamcnt;
	int match;
	struct ether_addr *ea;
	char var[80], *next;
	scb_val_t scb_val;
	char *nv, *nvp, *b;
	char prefix[16]={0};

	if(vifidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);

	(void) strcat_r(prefix, "macmode", tmp);

	//_dprintf("tmp %s\n",tmp);

	strncpy(macmode,nvram_safe_get(tmp),sizeof(macmode));
	//_dprintf("macmode %s\n",macmode);
	if ( !strcmp(macmode, "deny") )
		val = WLC_MACMODE_DENY;
	else if (!strcmp(macmode, "allow"))
		val = WLC_MACMODE_ALLOW;
	else
		val = WLC_MACMODE_DISABLED;

	//_dprintf("val %d\n",val);

	memset(tmp,0,sizeof(tmp));
	strlcpy(wlif_name, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(wlif_name));

	//_dprintf("wlif_name %s\n",wlif_name);

	if(!strlen(wlif_name)) {
		_dprintf("interface name error!!!\n");
		return;
	}

	memset(maclist_buf, 0, sizeof(maclist_buf));
	maclist = (struct maclist *)maclist_buf;
	maclist->count = 0;

	retrieve_static_maclist_from_nvram(bssidx,maclist,sizeof(maclist_buf));
/*
	memset(maclist_buf, 0, sizeof(maclist_buf));
	maclist = (struct maclist *)maclist_buf;
	maclist->count = 0;
	if (!nvram_match(strcat_r(prefix, "macmode", tmp), "disabled")) {
		nv = nvp = strdup(nvram_safe_get(strcat_r(prefix, "maclist_x", tmp)));

		if (nv) {
			ea = maclist->ea;
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (strlen(b) == 0) continue;
				if (ether_atoe(b, ea)) {
					if (wl_ether_atoe(b, ea)) {
						maclist->count++;
						ea++;
					}
				}
			}
		free(nv);
		}
	}
*/
	ret = wl_ioctl(wlif_name, WLC_SET_MACMODE, &val, sizeof(val));
	if(ret < 0) {
		_dprintf("[%s]set macmode error.\n", wlif_name);
		return;
	}

	if(val == WLC_MACMODE_DISABLED)
		return;

	ret = wl_ioctl(wlif_name, WLC_SET_MACLIST, maclist, sizeof(maclist_buf));
	if (ret < 0) {
		_dprintf("[%s]set maclist error.\n", wlif_name);
		return;
	}

	if(val == WLC_MACMODE_DISABLED)
		return;

	memset(sta_mac_list_buf, 0, sizeof(sta_mac_list_buf));

	/* Set the MAC list */
	sta_mac_list = (struct maclist *)sta_mac_list_buf;
	sta_mac_list->count = 0;

	/* query authentication sta list */
	strncpy((char*) sta_mac_list, "authe_sta_list",sizeof(sta_mac_list_buf));
	if( wl_ioctl(wlif_name, WLC_GET_VAR, sta_mac_list, sizeof(sta_mac_list_buf)) ){
		_dprintf("get station list error\n");
		return;
	}

	//_dprintf("start deauth\n");

	for(stamcnt=0; stamcnt < sta_mac_list->count; stamcnt++) {
		match = 0;
		for(mcnt=0; mcnt < maclist->count; mcnt++) {
			if( !memcmp(&sta_mac_list->ea[stamcnt],&maclist->ea[mcnt],sizeof(struct ether_addr)) ) {
				match = 1;
				break;
			}
		}

		if( val == WLC_MACMODE_DENY ){
			if(match)
			{
				memset(&scb_val,0,sizeof(scb_val));
				memcpy(&scb_val.ea, &sta_mac_list->ea[stamcnt], ETHER_ADDR_LEN);
				scb_val.val = 8; /* reason code: Disassociated because sending STA is leaving BSS */

				_dprintf("deauthticate ["MACF"] !!!\n", ETHERP_TO_MACF(&sta_mac_list->ea[stamcnt]));
				

				ret = wl_ioctl(wlif_name, WLC_SCB_DEAUTHENTICATE_FOR_REASON, &scb_val, sizeof(scb_val));
				if(ret < 0) {
					_dprintf("[WARNING] error to deauthticate ["MACF"] !!!\n", ETHERP_TO_MACF(&sta_mac_list->ea[stamcnt]));
				}
			}
		} else { //allow mode
			if(!match)
			{
				memset(&scb_val,0,sizeof(scb_val));
				memcpy(&scb_val.ea, &sta_mac_list->ea[stamcnt], ETHER_ADDR_LEN);
				scb_val.val = 8; /* reason code: Disassociated because sending STA is leaving BSS */

				_dprintf("deauthticate ["MACF"] !!!\n", ETHERP_TO_MACF(&sta_mac_list->ea[stamcnt]));

				ret = wl_ioctl(wlif_name, WLC_SCB_DEAUTHENTICATE_FOR_REASON, &scb_val, sizeof(scb_val));
				if(ret < 0) {
					_dprintf("[WARNING] error to deauthticate ["MACF"] !!!\n", ETHERP_TO_MACF(&sta_mac_list->ea[stamcnt]));
				}
			}
		}
	}

}
#endif

#ifdef RTCONFIG_BCMARM
void config_mssid_isolate(char *ifname, int vif)
{
	int unit = -1, mode = 0;
	char prefix[] = "wlXXXXXXXXXX_", tmp[32], path[64];

	if (!is_router_mode()) return;

	if (!ifname) return;

	if (!vif && wl_ioctl(ifname, WLC_GET_INSTANCE, &unit, sizeof(unit)))
		return;

	if (vif)
		snprintf(prefix, sizeof(prefix), "%s_", ifname);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	if (nvram_get_int(strcat_r(prefix, "ap_isolate", tmp)) ||
		(vif && nvram_match(strcat_r(prefix, "lanaccess", tmp), "off")))
		mode = 1;

	snprintf(path, sizeof(path), "/sys/class/net/%s/brport/isolate_mode", ifname);
	if (f_exists(path))
		f_write_string(path, mode ? "1" : "0", 0, 0);
}
#endif

#ifdef RTCONFIG_BCM_OAM
void start_oam_service(oam_srv_t* param)
{
	char cmd[512] = {0};
	int i;
	char oam_id[16] = {0};
	char level[4] = {0};
	char local_mep_id[8] = {0};
	char local_mep_vid[8] = {0};
	char remote_mep_id[8] = {0};
	char ccm_interval[4] = {0};
	int num_1ag = 0;
	int num_1731 = 0;

	strlcat(cmd, "tmsctl", sizeof(cmd));
	if (param->oam_3ah_enable > 0 && param->id_3ah > 0)
	{
		strlcat(cmd, " 3ah start -i ", sizeof(cmd));
		strlcat(cmd, param->ifname, sizeof(cmd));

		// OAM ID
		snprintf(oam_id, sizeof(oam_id), " -m %d", param->id_3ah);
		strlcat(cmd, oam_id, sizeof(cmd));

		if (param->auto_event)
			strlcat(cmd, " -e", sizeof(cmd));

		if (param->variable_retrieval
		 || param->link_event
		 || param->remote_loopback
		 || param->active_mode
		) {
			strlcat(cmd, " -f ", sizeof(cmd));
			if (param->variable_retrieval)
				strlcat(cmd, "+vr", sizeof(cmd));
			if (param->link_event)
				strlcat(cmd, "+le", sizeof(cmd));
			if (param->remote_loopback)
				strlcat(cmd, "+lb", sizeof(cmd));
			if (param->active_mode)
				strlcat(cmd, "+ac", sizeof(cmd));
		}
	}

	for (i = 0; i < OAM_MODE_MAX; i++)
	{
		if (!param->srv_enable[i])
			continue;

		// transfer mode setting, only support 2.
		if (param->mode[i] == OAM_MODE_1AG || param->mode[i] == OAM_MODE_1AG_2)
		{
			num_1ag++;
			if (num_1ag == 1)
				param->mode[i] = OAM_MODE_1AG;
			else if (num_1ag == 2)
				param->mode[i] = OAM_MODE_1AG_2;
			else
				continue;
		}
		if (param->mode[i] == OAM_MODE_1731 || param->mode[i] == OAM_MODE_1731_2)
		{
			num_1731++;
			if (num_1731 == 1)
				param->mode[i] = OAM_MODE_1731;
			else if (num_1731 == 2)
				param->mode[i] = OAM_MODE_1731_2;
			else
				continue;
		}
		switch (param->mode[i])
		{
			case OAM_MODE_1AG:
				strlcat(cmd, " 1ag", sizeof(cmd));
				break;
			case OAM_MODE_1731:
				strlcat(cmd, " 1731", sizeof(cmd));
				break;
			case OAM_MODE_1AG_2:
				strlcat(cmd, " 1ag-2", sizeof(cmd));
				break;
			case OAM_MODE_1731_2:
				strlcat(cmd, " 1731-2", sizeof(cmd));
				break;
		}

		strlcat(cmd, " start -i ", sizeof(cmd));
		strlcat(cmd, param->ifname, sizeof(cmd));

		// 802.1ag MD Name
		if (param->mode[i] == OAM_MODE_1AG || param->mode[i] == OAM_MODE_1AG_2)
		{
			strlcat(cmd, " -d ", sizeof(cmd));
			strlcat(cmd, param->md_name[i], sizeof(cmd));
		}

		// MEG ID, MA ID
		strlcat(cmd, " -a ", sizeof(cmd));
		strlcat(cmd, param->id[i], sizeof(cmd));

		// MEG Level, MA Level
		snprintf(level, sizeof(level), "%d", param->level[i]);
		strlcat(cmd, " -l ", sizeof(cmd));
		strlcat(cmd, level, sizeof(cmd));

		// Local MEP ID
		snprintf(local_mep_id, sizeof(local_mep_id), "%d", param->local_mep_id[i]);
		strlcat(cmd, " -m ", sizeof(cmd));
		strlcat(cmd, local_mep_id, sizeof(cmd));

		// Local MEP VLAN ID
		if (param->local_mep_vid[i] > 0)
		{
			snprintf(local_mep_vid, sizeof(local_mep_vid), "%d", param->local_mep_vid[i]);
			strlcat(cmd, " -v ", sizeof(cmd));
			strlcat(cmd, local_mep_vid, sizeof(cmd));
		}

		// Remote MEP ID
		if (param->remote_mep_id[i] > 0)
		{
			snprintf(remote_mep_id, sizeof(remote_mep_id), "%d", param->remote_mep_id[i]);
			strlcat(cmd, " -r ", sizeof(cmd));
			strlcat(cmd, remote_mep_id, sizeof(cmd));
		}

		// CCM Transmission Interval
		if (param->ccm_interval[i] > 0)
		{
			snprintf(ccm_interval, sizeof(ccm_interval), "%d", param->ccm_interval[i]);
			strlcat(cmd, " -s ccm -t ", sizeof(cmd));
			strlcat(cmd, ccm_interval, sizeof(cmd));
		}
	}

	strlcat(cmd, " &", sizeof(cmd));
	_dprintf("\n=====\n%s\n=====\n", cmd);
	system(cmd);
}

void stop_oam_service()
{
	killall_tk("tmsctl");
	eval("tmsctl", "1ag", "stop");
	eval("tmsctl", "1731", "stop");
	eval("tmsctl", "1ag-2", "stop");
	eval("tmsctl", "1731-2", "stop");
	eval("tmsctl", "3ah", "stop");
}

#endif

#ifdef HND_ROUTER
// Do QoS by using Broadcom Traffic Manager Utility, tmctl.
static void config_eth_port_shaper(char *intf, QOS_Q_PARAM *p)
{
	char max_rate[16] = {0};
	char min_rate[16] = {0};
	char burst[16] = {0};
	char *argv[] = {"tmctl", "setportshaper", "--devtype", "0"
			, "--if", intf
			, "--shapingrate", max_rate
			, NULL, NULL	// --burstsize xx
			, NULL, NULL	// --minrate xx
			, NULL };
	int idx = 8;

	snprintf(max_rate, sizeof(max_rate), "%d", p->max_rate);
	if (p->burst)
	{
		snprintf(burst, sizeof(burst), "%d", p->burst);
		argv[idx++] = "--burstsize";
		argv[idx++] = min_rate;
	}
	if (p->min_rate)
	{
		snprintf(min_rate, sizeof(min_rate), "%d", p->min_rate);
		argv[idx++] = "--minrate";
		argv[idx++] = min_rate;
	}
	_eval(argv, NULL, 0, NULL);
}

void config_obw()
{
	QOS_Q_PARAM qparam;
	int unit = wan_primary_ifunit();
#ifdef RTCONFIG_DUALWAN
	int wantype = get_dualwan_by_unit(unit);
#else
	int wantype = WANS_DUALWAN_IF_WAN;
#endif

	memset(&qparam, 0, sizeof(qparam));

#ifdef DSL_AX82U
	if (is_ax5400_i1())
	{
		int xobw, xobw1;
		int pri_wan = get_dualwan_primary();
		int sec_wan = get_dualwan_secondary();
		int update = 0;

		// convert settings
		if (pri_wan == WANS_DUALWAN_IF_DSL)
			xobw = nvram_get_int("qos_xobw_dsl");
		else
			xobw = nvram_get_int("qos_xobw_wan");
		if (sec_wan == WANS_DUALWAN_IF_DSL)
			xobw1 = nvram_get_int("qos_xobw_dsl");
		else
			xobw1 = nvram_get_int("qos_xobw_wan");

		if (xobw1 != nvram_get_int("qos_xobw1"))
		{
			nvram_set_int("qos_xobw1", xobw1);
			if (unit == 1)
			{
				qparam.max_rate = xobw1;
				update = 1;
			}
		}
		if (xobw != nvram_get_int("qos_xobw"))
		{
			nvram_set_int("qos_xobw", xobw);
			if (unit == 0)
			{
				qparam.max_rate = xobw;
				update = 1;
			}
		}

		// Gear Accelerator, No UI to configure UL BW, always follow shaping rate if it is set.
		if(IS_ROG_QOS())
		{
			if (xobw1 > 0)
				nvram_set_int("qos_obw1", xobw1);
			if (xobw > 0)
				nvram_set_int("qos_obw", xobw);
		}

		// Gear Accelerator, shaping rate not set, use default UL BW by UI
		if (IS_ROG_QOS() && wantype == WANS_DUALWAN_IF_WAN)
		{
			int obw = nvram_get_int("qos_obw");
			int obw1 = nvram_get_int("qos_obw1");

			if (unit == 1 && (xobw1 == 0 && obw1 != 0))
			{
				qparam.max_rate = obw1;
				update = 1;
			}
			else if (unit == 0 && (xobw == 0 && obw != 0))
			{
				qparam.max_rate = obw;
				update = 1;
			}
		}

		if (update)
		{
			if (wantype == WANS_DUALWAN_IF_DSL)
				config_ptm_queue(&qparam);
			else if (wantype == WANS_DUALWAN_IF_WAN) {
				config_eth_port_shaper(wan_if_eth(), &qparam);
			}
		}
		else if (nvram_get_int("success_start_service") == 0)
		{// boot up, config eth wan
			qparam.max_rate = nvram_get_int("qos_xobw_wan");
			config_eth_port_shaper(wan_if_eth(), &qparam);
		}
	}
	else if (IS_ROG_QOS())	//since call this function even QoS disabled.
#endif
	{
#if defined(RTCONFIG_DUALWAN) && defined(RTCONFIG_MULTIWAN_CFG)
		qparam.max_rate = unit ? nvram_get_int("qos_obw1") : nvram_get_int("qos_obw");
#else
		qparam.max_rate = nvram_get_int("qos_obw");
#endif
		if (wantype == WANS_DUALWAN_IF_WAN) {
			config_eth_port_shaper(wan_if_eth(), &qparam);
		}
		else
			_dprintf("%s: not support wantype %d\n", __FUNCTION__, wantype);
	}
}

void config_obw_off()
{
	QOS_Q_PARAM qparam;
	int unit = wan_primary_ifunit();
#ifdef RTCONFIG_DUALWAN
	int wantype = get_dualwan_by_unit(unit);
#else
	int wantype = WANS_DUALWAN_IF_WAN;
#endif

	memset(&qparam, 0, sizeof(qparam));

#ifdef DSL_AX82U
	if (is_ax5400_i1()) return;
#endif

	if (wantype == WANS_DUALWAN_IF_WAN)
		config_eth_port_shaper(wan_if_eth(), &qparam);
	else
		_dprintf("%s: not support wantype %d\n", __FUNCTION__, wantype);
}
#endif

#ifdef RTCONFIG_BRCM_HOSTAPD
int Pty_exec_wpasupp_cmd(char* cmd) {
	FILE *fp = NULL;
	char buf[128];
	int success = 0;

       fp = popen(cmd, "r");
       if (fp) {
		memset(buf, 0, sizeof(buf));
		while(fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "OK") != NULL) {
				success = 1;
				break;
			}
		}
		pclose(fp);
	}

       if (nvram_get_int("pty_dbg")) {
	   if (success)
		logmessage("PtyConn", "[SUCCESS] %s",  cmd);
	   else
		logmessage("PtyConn", "[FAIL] %s",  cmd);
       }

       return success;
}
#endif

#if defined(RTCONFIG_FRONTHAUL_DBG)
void set_fh_dbg_config(int unit, int subunit) {
    char prefix1[] = "wlXXXXXXXXXX_", prefix2[] = "wlXXXXXXXXXX_";
    char tmp1[64], tmp2[64];
    char value[128], vifs[128];

    snprintf(prefix1, sizeof(prefix1), "wl%d_", unit);
    snprintf(prefix2, sizeof(prefix2), "wl%d.%d_", unit, subunit);

    snprintf(tmp1, sizeof(tmp1), "wl%d_vifs", unit);
    strcpy(vifs, nvram_safe_get(tmp1));
    snprintf(value, sizeof(value), "wl%d.%d",unit, subunit);
    add_to_list(value, vifs, sizeof(vifs));
    nvram_set(strcat_r(prefix1, "vifs", tmp1), vifs);

    strcpy(vifs, nvram_safe_get("lan_ifnames"));
    snprintf(value, sizeof(value), "wl%d.%d",unit, subunit);
    add_to_list(value, vifs, sizeof(vifs));
    nvram_set("lan_ifnames", vifs);

    snprintf(value, sizeof(value), "%s_DBG", get_default_ssid(unit, 0));
    nvram_set(strcat_r(prefix2, "ssid", tmp2), value);

    snprintf(prefix1, sizeof(prefix1), "wl%d.1_", unit);
    nvram_set(strcat_r(prefix2, "bss_enabled", tmp2), "1");
    nvram_set(strcat_r(prefix2, "auth_mode_x", tmp2), nvram_safe_get(strcat_r(prefix1, "auth_mode_x", tmp1)));
    nvram_set(strcat_r(prefix2, "akm", tmp2), nvram_safe_get(strcat_r(prefix1, "akm", tmp1)));
    nvram_set(strcat_r(prefix2, "wpa_psk", tmp2), nvram_safe_get(strcat_r(prefix1, "wpa_psk", tmp1)));
    nvram_set(strcat_r(prefix2, "closed", tmp2), "1");
}
#endif

#ifdef RTCONFIG_OWE_TRANS
void config_owe_transition(int unit, int subunit) {
	char tmp[64] = {0}, prefix_open[] = "wlXXXXX_", prefix_owe[] = "wlXXXXX_";
	char if_open[16] = {0};

	snprintf(prefix_open, sizeof(prefix_open), "wl%d_", unit);
	snprintf(prefix_owe, sizeof(prefix_owe), "%s_", nvram_safe_get(strcat_r(prefix_open, "owe_transition_ifname", tmp)));

	snprintf(if_open, sizeof(if_open), "%s", nvram_safe_get(strcat_r(prefix_open, "ifname", tmp)));
	nvram_unset(strcat_r(prefix_open, "akm", tmp));
	nvram_unset(strcat_r(prefix_open, "crypto", tmp));
	nvram_set(strcat_r(prefix_owe, "owe_transition_ifname", tmp), if_open);
	nvram_set(strcat_r(prefix_owe, "bss_enabled", tmp), "1");
	nvram_set(strcat_r(prefix_owe, "closed", tmp), "1");
	nvram_set(strcat_r(prefix_owe, "auth_mode_x", tmp), "owe");
	nvram_set(strcat_r(prefix_owe, "akm", tmp), "owe");
	nvram_set(strcat_r(prefix_owe, "crypto", tmp), "aes");
	nvram_set(strcat_r(prefix_owe, "mfp", tmp), "2");
}

void deconfig_owe_transition(int unit, int subunit) {
	char tmp[64] = {0}, prefix[] = "wlXXXXX_", prefix_owe[] = "wlXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	snprintf(prefix_owe, sizeof(prefix_owe), "%s_", nvram_safe_get(strcat_r(prefix, "owe_transition_ifname", tmp)));
	if(!strlen(nvram_safe_get(strcat_r(prefix_owe, "owe_transition_ifname", tmp))))
		return;

	nvram_unset(strcat_r(prefix_owe, "owe_transition_ifname", tmp));
	nvram_set(strcat_r(prefix_owe, "bss_enabled", tmp), "0");
	nvram_set(strcat_r(prefix_owe, "closed", tmp), "0");
	nvram_set(strcat_r(prefix_owe, "auth_mode_x", tmp), "");
	nvram_set(strcat_r(prefix_owe, "akm", tmp), "");
	nvram_set(strcat_r(prefix_owe, "crypto", tmp), "");
	nvram_set(strcat_r(prefix_owe, "mfp", tmp), "0");
}

void set_owe_transition_bss_enabled(int unit, int subunit) {
	char tmp[64] = {0}, prefix[] = "wlXXXXX_", vif[] = "wlXXXXX";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	if(nvram_get_int(strcat_r(prefix, "nband", tmp)) == 4) // 6GHz band
		return;

	snprintf(vif, sizeof(vif), "wl%d.%d", unit, subunit);
	if(strcmp(nvram_safe_get(strcat_r(prefix, "owe_transition_ifname", tmp)), vif))
		return;

	if(!strcmp(nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)), "openowe"))
			config_owe_transition(unit, subunit);
	else
			deconfig_owe_transition(unit,subunit);
}
#endif
extern int get_wifi_country_code_tmp(char *ori_countrycode, char *output, int len){
	char cmd[128] = {0};
	FILE *fp = NULL;
	int count;
	int i;
	char out_tmp[256];

	snprintf(cmd, sizeof(cmd), "wl country list");
	if((fp = popen(cmd, "r")) == NULL){
		_dprintf("\tCannot execute wl.");
		_dprintf("... Failed\n");
		if(output != NULL) output[0] = '\0';

		return -1;
	}

	memset(out_tmp,0,256);
	i=0;
	while(fgets(out_tmp, 256, fp) != NULL) {
		if(i<4){
			i++;
			continue;
		}
		memset(output,0,len);
		output[0] = out_tmp[0];
		output[1] = out_tmp[1];
		//_dprintf("[test]%s\n",out_tmp);

		if(strcmp(output,ori_countrycode))
			break;
		i++;
		memset(out_tmp,0,256);
	}

	pclose(fp);
	//count = strlen(output);
	//output[count-1] = '\0';

	return 0;
}

#if defined(RTCONFIG_BCM_HND_CRASHLOG) && defined(RTCONFIG_HND_ROUTER_AX_6756)
#define MTDOOPS_SLOT_SIZE 0x10000
int mtd_export_crashlog()
{
	FILE *fp;
	char path[32], line[256], size[32], dev[32], erasesize[32], name[32];
	char cmd[256];
	int  retval = 0, count = 0;

#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2)
	snprintf(path, sizeof(path), "/jffs/crashlog.log");
#else
	snprintf(path, sizeof(path), "/tmp/crashlog.log");
#endif

	if ((fp = fopen("/proc/mtd", "r")) != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (sscanf(line, "%s %s %s %s", dev, size, erasesize, name) != 4)
				continue;

			if (!strcmp(name, "\"crashlog\"")) {
				dev[strlen(dev) - 1] = 0;
retry:
				snprintf(cmd, sizeof(cmd), "mtd_debug read /dev/%s 0 0x%x /tmp/crashlog.log", dev, MTDOOPS_SLOT_SIZE);
				dbg("cmd: %s\n", cmd);
				retval = system(cmd);
				if (retval != 0 && ++count < 3)
					goto retry;
				break;
			}
		}
		fclose(fp);

		if ((fp = fopen(path, "r")) != NULL) {
			if(fgets(line, sizeof(line), fp) != NULL) {
				if(strlen(line) && line[0] != 0xff && line[5] == 0x5d && line[7] == 0x5d) { // mtdoops magic numbe matchr
					dbg("mtdoops crashlog export!\n");
					snprintf(cmd, sizeof(cmd), "mtd_debug erase /dev/%s 0 0x%x ", dev, strtoul(size, NULL, 16));
					dbg("cmd: %s\n", cmd);
					retval = system(cmd);
				}
				else
				    unlink(path);
			}
			else
				unlink(path);
			fclose(fp);
		}
	}

	return retval;
}
#endif

uint32
wps_gen_pin(char *devPwd, int devPwd_len)
{
	unsigned long PIN;
	unsigned long int accum = 0;
	unsigned char rand_bytes[8];
	int digit;
	char local_devPwd[32];

	/*
	 * buffer size needs to big enough to hold 8 digits plus the string terminition
	 * character '\0'
	*/
	if (devPwd_len < 9)
		return 0;

	/* Generate random bytes and compute the checksum */
	f_read("/dev/urandom", rand_bytes, sizeof(rand_bytes));
	sprintf(local_devPwd, "%08u", *(uint32 *)rand_bytes);
	local_devPwd[7] = '\0';
	PIN = strtoul(local_devPwd, NULL, 10);

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
	sprintf(local_devPwd, "%08u", (unsigned int)PIN);
	local_devPwd[8] = '\0';

	/* Output result */
	strncpy(devPwd, local_devPwd, devPwd_len);

	return 1;
}
