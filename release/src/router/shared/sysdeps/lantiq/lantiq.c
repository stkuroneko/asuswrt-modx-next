#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcmnvram.h>
#include <wlutils.h>
#include "utils.h"
#include "shutils.h"
#include "shared.h"

#ifdef RTCONFIG_AMAS
#include <net/ethernet.h>
#include <amas_path.h>
#endif

#ifdef LINUX26
#define GPIO_IOCTL
#endif

//in rc/sysdeps/lantiq/lantiq_common.h
#define VAP_2G_START 5
#define VAP_5G_START 8

// --- move begin ---
#ifdef GPIO_IOCTL

#include <sys/ioctl.h>
#include <linux_gpio.h>

static int _gpio_ioctl(int f, int gpioreg, unsigned int mask, unsigned int val)
{

}

static int _gpio_open()
{

}

int gpio_open(uint32_t mask)
{

}

void gpio_write(uint32_t bitvalue, int en)
{

}

uint32_t _gpio_read(int f)
{

}

uint32_t gpio_read(void)
{

}

#else

int gpio_open(uint32_t mask)
{

}

void gpio_write(uint32_t bitvalue, int en)
{

}

uint32_t _gpio_read(int f)
{

}

uint32_t gpio_read(void)
{

}

#endif

#ifdef RTCONFIG_AMAS
char *get_pap_bssid(int unit, char bssid_str[])
{
	char buf[8192];
	FILE *fp;
	int len;
	char *pt1, *pt2;

	memset(bssid_str, 0, 18);

	snprintf(buf, sizeof(buf), "iwconfig %s", get_staifname(unit));
	fp = popen(buf, "r");
	if(fp){
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if(len > 1){
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Access Point:");
			if(pt1){
				pt2 = pt1 + strlen("Access Point: ");
				pt1 = strstr(pt2, "Not-Associated");
				if(!pt1)
				{
					strncpy(bssid_str,pt2,17);
				}
			}
		}
	}

	//_dprintf("[get_pap_bssid in shared]%s:[%s]\n",get_staifname(unit),bssid_str);

	return bssid_str;

}

//int get_maxassoc(char *ifname)
//{
#if 0
	FILE *fp = NULL;
	char maxassoc_file[128]={0};
	char buf[64]={0};
	char maxassoc[64]={0};

	snprintf(maxassoc_file, sizeof(maxassoc_file), "/tmp/maxassoc.%s", ifname);

	doSystem("wl -i %s maxassoc > %s", ifname, maxassoc_file);

	if ((fp = fopen(maxassoc_file, "r")) != NULL) {
		fscanf(fp, "%s", buf);
		fclose(fp);
	}
	sscanf(buf, "%s", maxassoc);

	return atoi(maxassoc);
#endif
//}

int get_psta_status(int unit)
{
	char buf[8192];
	FILE *fp;
	int len;
	char *pt1, *pt2;

	snprintf(buf, sizeof(buf), "iwconfig %s", get_staifname(unit));
	fp = popen(buf, "r");
	if(fp){
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if(len > 1){
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Access Point:");
			if(pt1){
				pt2 = pt1 + strlen("Access Point:");
				pt1 = strstr(pt2, "Not-Associated");
				if(pt1)
				{
					snprintf(buf, sizeof(buf), "ifconfig | grep %s", get_staifname(unit));
					fp = popen(buf, "r");
					if(fp)
					{
						memset(buf, 0, sizeof(buf));
						len = fread(buf, 1, sizeof(buf), fp);
						pclose(fp);
						if(len>=1)
							return 0;
						else
							return 3;
					}
					else
						return 0; //init
				}
				else
					return 2; //connect and auth ?????
			}
		}
	}

	return 3; // stop
}

/**
 * @brief add beacon vise by unit and subunit
 *
 * @param unit band index
 * @param subunit mssid index
 * @param hexdata vise string
 */
void add_beacon_vsie_by_unit(int unit, int subunit, char *hexdata)
{
	; // TODO
}

/**
 * @brief add guest vsie
 *
 * @param hexdata vsie string
 */
void add_beacon_vsie_guest(char *hexdata)
{
	; // TODO
}

void add_beacon_vsie(char *hexdata)
{
	// 0: Beacon
	// 1: ProbeRequest
	// 2: ProbeResponse
	// 3: AuthenticationRequest
	// 4: AuthenticationRespnse
	// 5: AssocationRequest
	// 6: AssociationResponse
	// 7: ReassociationRequest
	// 8: ReassociationResponse
#if 0
	char cmd[300] = {0};
	int pktflag = 0x0;
	int len = 0;
	char *ifname = NULL;
	strlen(ifname);

	len = 3 + strlen(hexdata)/2;	/* 3 is oui's len */

	ifname = get_wififname(0); // TODO: Should we get the band from nvram?

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s set_vsie %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)len, (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], hexdata);
		_dprintf("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
#endif
	nvram_set("amas_add_beacon_vsie", hexdata);
	trigger_wave_monitor_and_wait(__func__, __LINE__, WAVE_ACTION_ADD_BEACON_VSIE, 1);
}

/**
 * @brief remove beacon vsie by unit and subunit
 *
 * @param unit band index
 * @param subunit mssid index
 * @param hexdata vsie string
 */
void del_beacon_vsie_by_unit(int unit, int subunit, char *hexdata)
{
	; // TODO
}

/**
 * @brief remove guest beacon vsie
 *
 * @param hexdata vsie string
 */
void del_beacon_vsie_guest(char *hexdata)
{
	; // TODO
}

void del_beacon_vsie(char *hexdata)
{
	// 0: Beacon
	// 1: ProbeRequest
	// 2: ProbeResponse
	// 3: AuthenticationRequest
	// 4: AuthenticationRespnse
	// 5: AssocationRequest
	// 6: AssociationResponse
	// 7: ReassociationRequest
	// 8: ReassociationResponse
#if 0
	char cmd[300] = {0};
	int pktflag = 0x0;
	int len = 0;
	char *ifname = NULL;

	len = 3 + strlen(hexdata)/2;	/* 3 is oui's len */

	ifname = get_wififname(0); // TODO: Should we get the band from nvram?

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s del_vsie %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)len,  (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], hexdata);
		_dprintf("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
#endif
	nvram_set("amas_del_beacon_vsie", hexdata);
	trigger_wave_monitor_and_wait(__func__, __LINE__, WAVE_ACTION_DEL_BEACON_VSIE, 1);
}

int wl_get_bw(int unit)
{
	if (unit == 0)
		return 40;
	if (unit > 0)
		return 80;

	return 0;
}

/*
bwcap
0x01 = 20 MHz
0x02 = 40 MHz
0x04 = 80 MHz
0x08 = 160 MHz

ex: bluecave 5G support 20,40,80

*bwcap = 0x01 | 0x02 | 0x04
 */
int wl_get_bw_cap(int unit, int *bwcap)
{
	if(unit == 0)
		*bwcap = 0x01 | 0x02;
	else if(unit == 1)
		*bwcap = 0x01 | 0x02 | 0x04;
	else
		return -1;

	return 0;
}

#ifdef RTCONFIG_BHCOST_OPT
unsigned int get_uplinkports_linkrate(char *ifname)
{
	unsigned int link_rate = 1000;

	//TODO for getting link rate

	return link_rate;
}
#endif	/* RTCONFIG_BHCOST_OPT */

#endif /* RTCONFIG_AMAS */


#ifdef RTCONFIG_CFGSYNC
static void mac_allow_list_add(int unit, struct ether_addr *addr)
{
	char mac[]= "XX:XX:XX:XX:XX:XX\0";
	char *maclist_x=NULL,*maclist_all=NULL;
	char empty[1]={0};

	sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",	addr->ether_addr_octet[0],
										  	addr->ether_addr_octet[1],
											addr->ether_addr_octet[2],
											addr->ether_addr_octet[3],
											addr->ether_addr_octet[4],
											addr->ether_addr_octet[5]);

	if(unit == 0) maclist_x  = nvram_safe_get("aimesh_macacl_2g_mac");
	else maclist_x  = nvram_safe_get("aimesh_macacl_5g_mac");

	if(!maclist_x) maclist_x = empty;

	if(strstr(maclist_x,mac)){
		//_dprintf("mac %s already in list\n",mac);
		return;
	}

	maclist_all=calloc(1,strlen(maclist_x) + strlen(mac) + 2 );//  "maclist_x" "," "mac"

	if(!maclist_all){
		_dprintf("malloc error\n");
		return;
	}

	strcpy(maclist_all,maclist_x);
	maclist_all[strlen(maclist_x)] = '<';
	strcpy(maclist_all+strlen(maclist_x)+1,mac);

	if(unit == 0) nvram_set("aimesh_macacl_2g_mac",maclist_all);
	else nvram_set("aimesh_macacl_5g_mac",maclist_all);

	free(maclist_all);
}

static void mac_allow_list_event_sent(int unit)
{
	int i;

	while(nvram_get_int("wave_ready") == 0)
	{
		//_dprintf("rc_mac_allow_list_add wait\n");
		sleep(1);
	}

	while(nvram_get_int("wave_action")!=WAVE_ACTION_IDLE){
		_dprintf("wave_action != IDLE, waint. [rc_mac_allow_list_event_sent]\n");
		sleep(1);
	}

	if(!unit)
	{
		trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_SETALLOWACL_2G);
	} else {
		trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_SETALLOWACL_5G);
	}
}

void update_macfilter_relist()
{
	char maclist_buf[4096] = {0};
	struct maclist *maclist = NULL;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char word[256], *next;
	int unit = 0;

	struct ether_addr ea_tmp;
	int wave_unit=0;
	char ifnames_tmp[128]={0};


	unsigned char sta_ea[6] = {0};
	int ret = 0;
	char *nv, *nvp, *b;
	char mac2g[32], mac5g[32], *next_mac;
	char *reMac, *maclist2g, *maclist5g, *timestamp;

	nvram_unset("aimesh_macacl_2g_mac");
	nvram_unset("aimesh_macacl_5g_mac");

	if (is_cfg_relist_exist())
	{
		strncpy(ifnames_tmp,nvram_safe_get("wl_ifnames"),128);

		foreach (word, ifnames_tmp, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);

#ifdef RTCONFIG_AMAS
			if (nvram_get_int("re_mode") == 1)
				snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
			else
#endif
				snprintf(prefix, sizeof(prefix), "wl%d_", unit);

			wave_unit = wl_wave_unit(unit);

			if (nvram_match(strcat_r(prefix, "macmode", tmp), "allow")) {
				if (is_cfg_relist_exist()) {
					nv = nvp = get_cfg_relist(0);
					if (nv) {
						while ((b = strsep(&nvp, "<")) != NULL) {
							if ((vstrsep(b, ">", &reMac, &maclist2g, &maclist5g, &timestamp) != 4))
								continue;

							if (strcmp(reMac, get_lan_hwaddr()) == 0)
								continue;

							if (unit == 0) {
								foreach_44 (mac2g, maclist2g, next_mac) {
									if (check_re_in_macfilter(unit, mac2g))
										continue;

									ether_atoe(mac2g, sta_ea);
									memcpy(&ea_tmp, sta_ea, sizeof(struct ether_addr));
									mac_allow_list_add(unit,&ea_tmp);//add to allow list
								}
							}
							else
							{
								foreach_44 (mac5g, maclist5g, next_mac) {
									if (check_re_in_macfilter(unit, mac5g))
										continue;

									ether_atoe(mac5g, sta_ea);
									memcpy(&ea_tmp, sta_ea, sizeof(struct ether_addr));
									mac_allow_list_add(unit,&ea_tmp);//add to allow list
								}
							}
						}
						free(nv);
					}
					mac_allow_list_event_sent(unit);
				}
			}

			unit++;
		}
	}
}
#endif /* RTCONFIG_CFGSYNC */

#ifdef RTCONFIG_NEW_PHYMAP
/* phy port related start */
phy_port_mapping get_phy_port_mapping(void)
{
	static const phy_port_mapping port_mapping = {
#if 0
#if defined(MAPAC1300) || defined(MAPAC2200) || defined(VZWAC1300) || defined(SHAC1300) /* for Lyra */
		.count = 2, 
		.port[0] = { .phy_port_id = WAN_PORT, .cap = PHY_PORT_CAP_WAN, .max_rate = 1000 }, 
		.port[1] = { .phy_port_id = LAN4_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }
#elif defined(RTAC95U)
		.count = 4, 
		.port[0] = { .phy_port_id = WAN_PORT, .cap = PHY_PORT_CAP_WAN, .max_rate = 1000 }, 
		.port[1] = { .phy_port_id = LAN1_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }, 
		.port[2] = { .phy_port_id = LAN2_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }, 
		.port[3] = { .phy_port_id = LAN3_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }
#else
		.count = 5, 
		.port[0] = { .phy_port_id = WAN_PORT, .cap = PHY_PORT_CAP_WAN, .max_rate = 1000 }, 
		.port[1] = { .phy_port_id = LAN1_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }, 
		.port[2] = { .phy_port_id = LAN2_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }, 
		.port[3] = { .phy_port_id = LAN3_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }, 
		.port[4] = { .phy_port_id = LAN4_PORT, .cap = PHY_PORT_CAP_LAN, .max_rate = 1000 }
#endif
#endif
	};
	return port_mapping;
}
#endif


#ifdef RTCONFIG_AMAS
double get_wifi_maxpower(int band_type)
{
	return 0;
} 
double get_wifi_5G_maxpower()
{
	return 0;
}
double get_wifi_5GH_maxpower()
{
	return 0;
}
double get_wifi_6G_maxpower()
{
	return 0;
}
#endif


