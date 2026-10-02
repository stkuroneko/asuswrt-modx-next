#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shared.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <wlioctl.h>
#include <realtek_common.h>

#include "cfg_common.h"
#include "cfg_wevent.h"
#include "chmgmt.h"
#include "encrypt_main.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#include <sys/ioctl.h>
#include <net/if_arp.h>

#define ETHER_ADDR_STR_LEN 	18
#define MAX_STA_COUNT  128

char *get_pap_bssid(int unit, char *bssid_buf, int buf_len)
{
	unsigned char bssid[6];

	memset(bssid_buf, 0, buf_len);

	if (wl_ioctl(get_staifname(unit), WLC_GET_BSSID, bssid, sizeof(bssid)) == 0) {

		if ( !(!bssid[0] && !bssid[1] && !bssid[2] && !bssid[3] && !bssid[4] && !bssid[5]) ) {
			sprintf(bssid_buf, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)bssid[0],
			(unsigned char)bssid[1],
			(unsigned char)bssid[2],
			(unsigned char)bssid[3],
			(unsigned char)bssid[4],
			(unsigned char)bssid[5]);
		}
		else
			snprintf(bssid_buf, buf_len, "Not-Associated");
	}
	else
		snprintf(bssid_buf, buf_len, "Not-Associated");

	return bssid_buf;
}

int get_pap_rssi(int unit)
{
	char *ifname = get_staifname(unit);
	struct maclist *mac_list = NULL;
	int mac_list_size;
	scb_val_t scb_val;

	int rssi = 0;


	mac_list_size = sizeof(mac_list->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	mac_list = malloc(mac_list_size);
	if (!mac_list)
		goto ERROR;

	memset(mac_list, 0, mac_list_size);
	/* query wl for authenticated sta list */
	strcpy((char*) mac_list, "authe_sta_list");

	if (wl_ioctl(ifname, WLC_GET_VAR, mac_list, mac_list_size))
		goto ERROR;

	if (mac_list->count == 0)
		goto ERROR;

	memcpy(&scb_val.ea, &mac_list->ea[0], ETHER_ADDR_LEN);
	if (wl_ioctl(ifname, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t))) {
		dbg("can not get rssi info of %s\n", ifname);
		goto ERROR;
	}

	if (scb_val.val - 100 > rssi)
		rssi = scb_val.val - 100;

ERROR:
	if (mac_list)
		free(mac_list);

	return rssi;
}

int wl_sta_list(char *msg, int msg_len)
{
	char word[32], *next;
	int unit = 0, i = 0;
	char *ifname;
	char brMac[32] = {0}, ifAlias[16];
	char prefix[16], tmp[128];
	char ea[ETHER_ADDR_STR_LEN];

	json_object *root = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;

	WLAN_STA_INFO_T staInfoList[MAX_STA_NUM + 1];
	time_t ts;

	time(&ts);

	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	brMacObj = json_object_new_object();
	if(brMacObj == NULL)
		return 0;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		bandObj = NULL;

		memset(staInfoList, 0, sizeof(staInfoList));

		if(getWlStaInfo(word, staInfoList) < 0)
			continue;

		memset(ifAlias, 0, sizeof(ifAlias));
		if_nametoalias(word, &ifAlias[0], sizeof(ifAlias));

		for (i = 1; i <= MAX_STA_NUM; i++) {
			if (staInfoList[i].aid && (staInfoList[i].flag & STA_INFO_FLAG_ASOC)) {

				ether_etoa(staInfoList[i].addr, ea);
				if (!bandObj)
					bandObj = json_object_new_object();

				if (bandObj) {
					staObj = json_object_new_object();
					if(staObj) {
						json_object_object_add(staObj, WEVENT_TIMESTAMP, json_object_new_int64(ts));
						json_object_object_add(bandObj, ea, staObj);
					}
				}
			}
		}

		if (bandObj)
			json_object_object_add(brMacObj, ifAlias, bandObj);

		for (i = 0; i < num_of_mssid_support(unit); i++) {
			bandObj = NULL;
			//wl0.1 is used for root AP
			if(nvram_get_int("re_mode") && (i == 0))
				continue;

			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i+1);
			if (!nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
				continue;
		
			ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
			
			if(getWlStaInfo(ifname, staInfoList) < 0)
				continue;

			memset(ifAlias, 0, sizeof(ifAlias));
			if_nametoalias(ifname, ifAlias, sizeof(ifAlias));

			for (i = 1; i <= MAX_STA_NUM; i++) {
				if (staInfoList[i].aid && (staInfoList[i].flag & STA_INFO_FLAG_ASOC)) {
					ether_etoa(staInfoList[i].addr, ea);
					if (!bandObj)
						bandObj = json_object_new_object();
					if (bandObj) {
						staObj = json_object_new_object();
						if(staObj) {
							json_object_object_add(staObj, WEVENT_TIMESTAMP, json_object_new_int64(ts));
							json_object_object_add(bandObj, ea, staObj);
						}
					}
				}
			}

			if (bandObj)
				json_object_object_add(brMacObj, ifAlias, bandObj);
		}

		unit++;
	}

	root = json_object_new_object();
	if (root) {
		json_object_object_add(root, brMac, brMacObj);
		snprintf(msg, msg_len, "%s", json_object_to_json_string(root));
		json_object_put(root);
		return 1;
	} else {
		json_object_put(brMacObj);
		return 0;
	}
}

int wl_sta_rssi_list(json_object *root)
{

	char word[256], *next;
	int unit = 0,i = 0;
	char *ifname;
	char ea[ETHER_ADDR_STR_LEN];
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	char alias[16] = {0};
	WLAN_STA_INFO_T staInfoList[MAX_STA_NUM + 1] = {0};

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		ifname = get_wififname(unit);

		memset(staInfoList, 0, sizeof(staInfoList));
		memset(alias, 0, sizeof(alias));
		snprintf((char*)staInfoList, sizeof(staInfoList),"rtk_sta_info");

		if (wl_ioctl(ifname, WLC_GET_VAR, staInfoList, sizeof(staInfoList)))
			return 0;

		snprintf(alias, sizeof(alias), "%s", unit ? (unit == 2 ? "5G1" : "5G") : "2G");

		bandObj = json_object_new_object();
		if(bandObj == NULL)
			continue;

		for (i = 1; i <= MAX_STA_NUM; i++) {
			if (staInfoList[i].aid && (staInfoList[i].flag & STA_INFO_FLAG_ASOC)) {
				ether_etoa((void *) &(staInfoList[i].addr), ea);
				staObj = json_object_new_object();
				if(staObj == NULL)
					continue;

				json_object_object_add(staObj, CFG_STR_RSSI, json_object_new_int(staInfoList[i].rssi - 100));
				json_object_object_add(bandObj, ea, staObj);
			}
		}
		if (bandObj)
			json_object_object_add(root, alias, bandObj);

		unit++;
	}

	return 1;
}

char *get_sta_mac(int unit)
{
	char *aif;
	char *pMac;
	static char mac_buf[sizeof("00:00:00:00:00:00XXX")];

	aif = get_staifname(unit);

	memset(mac_buf, 0, sizeof(mac_buf));

	pMac = get_hwaddr(aif);
	if (pMac) {
		snprintf(mac_buf, sizeof(mac_buf), "%s", pMac);
		free(pMac);
		pMac = NULL;
	}

	return mac_buf;
}

/*
 * wl_control_channel(unit, *channel, *bw, *nctrlsb)
 *	*channel:
 *		Current channel
 *
 *	*bw:
 * 	return the bandwitdh value, could be 20/40/80/160.
 *
 * nctrlsb:
 * 	return the side band when in HT40 mode
 * 	1: the control sideband is upper
 * 	0: the control sideband is lower
 * 	-1: invalid
 *
 */
void wl_control_channel(int unit, int *channel, int *bw, int *nctrlsb)
{
	*channel = get_channel(get_wififname(unit));
	get_bw_nctrlsb(get_wififname(unit), bw, nctrlsb);
}

void sync_control_channel(int unit, int channel, int bw, int nctrlsb)
{
	char *ifname;
	ifname = get_wififname(unit);
	eval("ifconfig", ifname, "down");
	set_channel(ifname, channel);
	set_bw_nctrlsb(ifname, bw, nctrlsb);
	eval("ifconfig", ifname, "up");
}

int get_wsc_status(int *fail_result)
{
	int status = nvram_get_int("wps_status");
	if(status == 3)
		return 1;
	else 
		return -1;
}

int wl_get_chans_info(int unit, char* buf, size_t len)
{
#define CH_NUM (32)
    char *p;
    unsigned char ch_list[CH_NUM];
    unsigned int radar_list[CH_NUM];
    int ret = 0, ch_cnt = 0, radar_cnt = 0;
    int i = 0, j = 0;
    int ch_stat;

    if(buf == NULL || len <= 0)
        return -1;

    if(unit < 0) {
#ifdef SUPPORT_TRI_BAND
		unit = 2;
#else
        unit = 1;
#endif
    }
    if((ch_cnt = get_channel_list_via_driver(unit, ch_list, CH_NUM)) < 0) {
        _dprintf("get_channel_list_via_driver fail ret %d\n", ch_cnt);
        return ch_cnt;
    }
    if((radar_cnt = get_radar_channel_list(get_wififname(unit), radar_list, sizeof(radar_list))) < 0) {
        _dprintf("get_radar_channel_list fail ret %d\n", radar_cnt);
        return radar_cnt;
    }
    radar_cnt = radar_cnt/sizeof(unsigned int);
    // set version
    ret = snprintf(buf, len, "%d ", CHINFO_CMNFMT_V1);
    p = buf + ret;
    len -= ret;

    for(i = 0; i < ch_cnt && len > 0; i++) {
		ch_stat = CHINFO_AVBL;
        for(j = 0; j < radar_cnt; j++) {
            if(ch_list[i] == radar_list[j]) {
				ch_stat = CHINFO_BLK;
                break;
            }
        }

        ret = snprintf(p, len, "%05u%03u ", ch_stat, ch_list[i]);
        p += ret;
        len -= ret;
    }
    return 0;

}
int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
{
	int channel, bw, nctrlsb;
	int ret;

	if(ifname == NULL || chconf == NULL)
		return -1;

	*chconf = 0;

	channel = get_channel(ifname);
	if((ret = get_bw_nctrlsb(ifname, &bw, &nctrlsb)) < 0) {
		cprintf("%s: get_bw_nctrlsb ret(%d)\n", __func__, ret);
		return ret;
	}

	switch (bw) {
	case 20:
		CHCONF_BW_SET20(*chconf);
		break;
	case 40:
		CHCONF_BW_SET40(*chconf);
		break;
	case 80:
		CHCONF_BW_SET80(*chconf);
		break;
	case 160:
		CHCONF_BW_SET160(*chconf);
		break;
	default:
		cprintf("%s: INVALID bw(%d)\n", bw);
		return -1;
	}

	CHCONF_CH_SET(*chconf, channel);
	CHCONF_SB_SET(*chconf, (nctrlsb << CHCONF_SB_SHIFT));

	return 0;

}
int wl_set_chconf(const char *ifname, chmgmt_chconf_t chconf)
{
	int channel, bw, nctrlsb;
	channel = chmgmt_get_ctl_ch(chconf);

	if(CHCONF_BW_IS20(chconf))
		bw = 20;
	else if(CHCONF_BW_IS40(chconf))
		bw = 40;
	else if(CHCONF_BW_IS80(chconf))
		bw = 80;
	else if(CHCONF_BW_IS160(chconf))
		bw = 160;
	else
		return -1;

	nctrlsb = -1;
	eval("ifconfig", ifname, "down");
	set_channel(ifname, channel);
	set_bw_nctrlsb(ifname, bw, nctrlsb);
	eval("ifconfig", ifname, "up");
}

void wl_set_macfilter_list()
{
	update_macfilter_relist();

	if (wl_macfilter_is_allow_mode() && pids("roamast")) {
		DBG_INFO("restart roamast");
		notify_rc("restart_roamast");
	}
}

/*
 * wl_set_macfilter_mode(allow)
 *
 * when mac filter is in allow mode
 * set NOT to block the newRE to connect to 2G
 * allow:
 * 	0: restore (set to allow mode)
 * 	1: allow the newRE to connect to 2G
 */
void wl_set_macfilter_mode(int allow)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *wlif_name;
	int ret = 0;
	int val = 1;	/* allow mode */
	int unit = 0;

#ifdef RTCONFIG_AMAS
	if (nvram_get_int("re_mode") == 1)
		snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	else
#endif
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	wlif_name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (nvram_match(strcat_r(prefix, "macmode", tmp), "allow")) {
		if (allow == 1)
			val = 0;	/* disabled */

		ret = doSystem("iwpriv %s set_mib aclmode=%d", wlif_name, val);
		if(ret)
			DBG_ERR("[%s] set_mib aclmode=%d failed", wlif_name, val);
	}
}

void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
	//TODO
}

char *get_pap_ssid(int unit, char *ssid_buf, int buf_len)
{
	//TODO
	return ssid_buf;
}

char *get_ap_ssid(int unit, char *ssid_buf, int buf_len)
{
	//TODO
	return ssid_buf;
}

/**
 * @brief Get the uplinkport describe object
 *
 * How to use gen_uplinkport_describe(char *port_def, char *type, char *subtype, int index)
 * port_def: WAN/LAN or NONE. Please ref shared/amas_utils.h uplinkport_capval_s port_define[]
 * type: ETH/WIFI/PLC or NONE. Please ref shared/amas_utils.h uplinkport_capval_s phy_type[]
 * subtype: ETH:100/1000/... WIFI:2.4G/5G/6G... Please ref shared/amas_utils.h uplinkport_capval_s phy_subtype[]
 * index: Port number. LAN"1", "2",... or if just only 1, please set NULL or 0.
 *
 * @param ifname uplink port interface name
 * @return int uplink port describe
 */
int get_uplinkport_describe(char *ifname) {
	// TODO
	int model = get_model();
	int result = 0;

	switch (model) {
		default:
			result = gen_uplinkport_describe("WAN", "ETH", "1000", NULL);
			break;
	}

    return result;
}

#ifdef RTCONFIG_NBR_RPT
int wl_get_nbr_info(char* buf, size_t len)
{
	//TODO
	return 0;
}
#endif

int delClientArp(char *clientIp)
{
	int s;
	struct arpreq req;
	struct sockaddr_in *sin;

	if (clientIp == NULL) {
		DBG_ERR("client's ip is NULL");
		return 0;
	}

	DBG_INFO("enter");

	bzero((caddr_t)&req, sizeof(req));

	sin = (struct sockaddr_in *)&req.arp_pa;
	sin->sin_family = AF_INET; /* Address Family: Internet */
	sin->sin_addr.s_addr = inet_addr(clientIp);

	if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		DBG_ERR("socket() failed");
		return 0;
	} /* Socket is opened.*/

	snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", LAN_IFNAME);

	if(ioctl(s, SIOCDARP, (caddr_t)&req) <0) {
		DBG_ERR("SIOCDARP");
		close(s);
		return 0;
	}
	close(s); /* Close the socket, we don't need it anymore. */

	DBG_INFO("leave");

	return 1;
}