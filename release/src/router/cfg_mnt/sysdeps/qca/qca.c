#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shared.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <qca.h>
#include "cfg_common.h"
#include "cfg_wevent.h"

#include "chmgmt.h"
#include "cfg_slavelist.h"
#include "encrypt_main.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#include <sys/ioctl.h>
#include <net/if_arp.h>

const char *get_wifname(int band)
{
	if (band == 2)
		return WIF_5G2;
	if (band)
		return WIF_5G;
	else
		return WIF_2G;
}

int chk_wifi_sched(int band)
{
	char tmp[20],tmp2[20];
        snprintf(tmp, sizeof(tmp), "wl%d_qca_sched", band);
        snprintf(tmp2, sizeof(tmp2), "wl%d_timesched", band);
	if(nvram_get_int(tmp2)==1 ) //wifi sched is enabled
	{
		if(nvram_get_int(tmp)==0) //sched is radio-off
		{
			//_dprintf("cfgmnt: radio[%d] should be left to wifi-sched\n",band);
			return 0;
		}
        }
	return 1;
}

/**
 * @unit:
 * @sta_info:
 * @ifname:
 * @subunit_id:
 * 	'B':	Facebook Wi-Fi
 * 	'F':	Free Wi-Fi
 * 	'C':	Captive Portal
 * otherwise:	Main or guest network.
 * @return:
 */
static int __getSTAInfo(int unit, WIFI_STA_TABLE *sta_info, char *ifname, char id)
{
	int subunit;
	char subunit_str[4] = "0", wlif[sizeof("wlX.Yxxx")];

	if (absent_band(unit))
		return -1;
	if (!ifname || *ifname == '\0')
		return -1;

	subunit = get_wlsubnet(unit, ifname);
	if (subunit < 0)
		subunit = 0;
	if (subunit >= 10) {
		printf("%s: invalid subunit %d\n", __func__, subunit);
		return -2;
	}

	snprintf(wlif, sizeof(wlif), "wl%d.%d", unit, subunit);
	if (subunit >= 0 && subunit < MAX_NO_MSSID)
		snprintf(subunit_str, sizeof(subunit_str), "%d", subunit);
	if (id == 'B' || id == 'F' || id == 'C')
		snprintf(subunit_str, sizeof(subunit_str), "%c", id);

	return get_qca_sta_info_by_ifname(ifname, subunit_str[0], sta_info);
}

static int getSTAInfo(int unit, WIFI_STA_TABLE *sta_info)
{
	int ret = 0;
	char *unit_name;
	char *p, *ifname;
	char *wl_ifnames;

	memset(sta_info, 0, sizeof(*sta_info));
	unit_name = strdup(get_wifname(unit));
	if (!unit_name)
		return ret;
#if defined(RTCONFIG_AMAS_WGN)	
	extern char* get_all_lan_ifnames(void);
	wl_ifnames = get_all_lan_ifnames();
#else	
	wl_ifnames = strdup(nvram_safe_get("lan_ifnames"));
#endif	
	if (!wl_ifnames) {
		free(unit_name);
		return ret;
	}
	p = wl_ifnames;
	while ((ifname = strsep(&p, " ")) != NULL) {
		while (*ifname == ' ') ++ifname;
		if (*ifname == 0) break;
		if (strncmp(ifname, unit_name, strlen(unit_name)))
			continue;

		__getSTAInfo(unit, sta_info, ifname, 0);
	}
	free(wl_ifnames);
	free(unit_name);

	return ret;
}

char *get_pap_bssid(int unit, char *bssid_buf, int buf_len)
{
	char buf[512] = {0};
	FILE *fp;
	int len;
	char *pt1, *pt2;

	memset(bssid_buf, 0, buf_len);

	snprintf(buf, sizeof(buf), "iwconfig %s", get_staifname(swap_5g_band(unit)));
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Access Point:");
			/* check whether connected to PAP */
			if (pt1) {
				pt2 = pt1 + strlen("Access Point:") + 1;
				pt1 = strstr(pt2, "Not-Associated");
				if (pt1)
					return bssid_buf; /* not connected to PAP */

				pt1 = pt2;
				/* strlen("XX:XX:XX:XX:XX:XX") = 17 */
				*(pt2 + 17) = '\0';
				snprintf(bssid_buf, buf_len, "%s", pt1);
				//printf("get_pap_bssid: bssid_buf(%s)\n", bssid_buf);
			}
		}
	}

	return bssid_buf;
}

int get_pap_rssi(int unit)
{
	char buf[512] = {0};
	FILE *fp;
	int len;
	char *pt1, *pt2;
	int rssi = 0;

	snprintf(buf, sizeof(buf), "iwconfig %s", get_staifname(swap_5g_band(unit)));
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Access Point:");
			/* check whether connected to PAP */
			if (pt1) {
				pt2 = pt1 + strlen("Access Point:") + 1;
				pt1 = strstr(pt2, "Not-Associated");
				if (pt1)
					return 0; /* not connected to PAP */

				/* get signal leve (rssi) */
				pt1 = strstr(buf, "Signal level=");
				if (pt1) {
					pt2 = pt1 + strlen("Signal level=");
					pt1 = strstr(pt2, " dBm");
					if (pt1) {
						*pt1 = 0;
						//printf("Link Quality(%d)=%s\n", unit, pt2);
						rssi = atoi(pt2);
						if (rssi >= 0)
							rssi = -1;
					}
				}
			}
		}
	}

	return rssi;
}

/* reference from if_nametoalias() of shared/misc.c */
static void ifname2alias(int unit, int subunit, char *alias, int alias_len)
{
	int band, nband = 0;
	char tmp[8], prefix[] = "wlXXXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
#if defined(RTCONFIG_LYRA_5G_SWAP)
	band = swap_5g_band(unit);
#else
	band = unit;
#endif

	if (nband == 2)
		strlcpy(tmp, CFG_WL_STR_2G, sizeof(tmp));
	else if (nband == 1)
		strlcpy(tmp, band == 2 ? CFG_WL_STR_5G1 : CFG_WL_STR_5G, sizeof(tmp));
#if defined(RTCONFIG_WIFI6E)
	else if (nband == 4)
		strlcpy(tmp, CFG_WL_STR_6G, sizeof(tmp));
#endif

	if (subunit == 0)
		snprintf(alias, alias_len, "%s", tmp);
	else
		snprintf(alias, alias_len, "%s_%d", tmp, subunit);
	//_dprintf("%s: alias %s\n", __func__, alias);
}

int wl_sta_list(char *msg, int msg_len)
{
	char word[64], *next;
	int unit = 0;
	json_object *root = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	time_t ts;
	char brMac[32] = {0};
	int i, j;
	char s, alias[16];

	time(&ts);

	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	root = json_object_new_object();
	brMacObj = json_object_new_object();

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		WIFI_STA_TABLE *sta_info;
		WLANCONFIG_LIST *r;

		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);

		if ((sta_info = malloc(sizeof(*sta_info))) == NULL) {
			json_object_put(root);
			json_object_put(brMacObj);
			return 0;
		}

		getSTAInfo(unit, sta_info);
		for (i = 0; i < num_of_mssid_support(unit); i++) {
			bandObj = NULL;
			memset(alias, 0, sizeof(alias));
			ifname2alias(unit, i, alias, sizeof(alias));

			for(j = 0, r = &sta_info->Entry[0]; j < sta_info->Num; j++, r++) {
				s = r->subunit_id;
				if (s < '0' || s  >= ('0' + MAX_NO_MSSID - 1))
					s = '0';

				if (i != (s - '0'))
					continue;

				if (!bandObj)
					bandObj = json_object_new_object();

				if (bandObj) {
					staObj = json_object_new_object();
					if (staObj) {
						json_object_object_add(staObj, WEVENT_TIMESTAMP,
							json_object_new_int64(ts));

						json_object_object_add(bandObj, r->addr, staObj);
					}
				}
			}

			if (bandObj) {
				if (brMacObj && strlen(alias))
					json_object_object_add(brMacObj, alias, bandObj);
				else
					json_object_put(bandObj);
			}
		}
		free(sta_info);
		unit++;
	}

	if (brMacObj) {
		if (root) {
			json_object_object_add(root, brMac, brMacObj);
			snprintf(msg, msg_len, "%s", json_object_to_json_string(root));
		}
		else
			json_object_put(brMacObj);
	}

	json_object_put(root);

	return 1;
}

int wl_sta_rssi_list(json_object *root)
{
	char word[64], *next;
	int unit = 0;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int i, j;
	char s, alias[16];

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		WIFI_STA_TABLE *sta_info;
		WLANCONFIG_LIST *r;

		if ((sta_info = malloc(sizeof(*sta_info))) == NULL) {
			return 0;
		}

		getSTAInfo(unit, sta_info);
		for (i = 0; i < num_of_mssid_support(unit); i++) {
			bandObj = NULL;
			memset(alias, 0, sizeof(alias));
			ifname2alias(unit, i, alias, sizeof(alias));

			for(j = 0, r = &sta_info->Entry[0]; j < sta_info->Num; j++, r++) {
				s = r->subunit_id;
				if (s < '0' || s  >= ('0' + MAX_NO_MSSID - 1))
					s = '0';

				if (i != (s - '0'))
					continue;

				if (!bandObj)
					bandObj = json_object_new_object();

				if (bandObj) {
					staObj = json_object_new_object();
					if (staObj) {
						json_object_object_add(staObj, CFG_STR_RSSI,
							json_object_new_int(r->rssi));

						json_object_object_add(bandObj, r->addr, staObj);
					}
					else
						json_object_put(staObj);
				}
			}

			if (bandObj)
				json_object_object_add(root, alias, bandObj);
		}
		free(sta_info);
		unit++;
	}

	return 1;
}

char *get_sta_mac(int unit)
{
	char *pMac;
	static char mac_buf[sizeof("00:00:00:00:00:00XXX")];

	memset(mac_buf, 0, sizeof(mac_buf));

	pMac = get_hwaddr(get_staifname(swap_5g_band(unit)));
	if (pMac) {
		snprintf(mac_buf, sizeof(mac_buf), "%s", pMac);
		free(pMac);
		pMac = NULL;
        }

        return mac_buf;
}

/*
 * wl_control_channel(unit, *channel, *bw, *nctrlsb)
 *
 * *bw:
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
	char athfix[8];
	int ret __attribute__ ((unused));

	if (unit < 0 || unit >= MAX_NR_WL_IF)
		return;
	if (channel == NULL || bw == NULL || nctrlsb == NULL)
		return;

	__get_wlifname(swap_5g_band(unit), 0, athfix);
	*channel = get_channel(athfix);

	ret = get_bw_nctrlsb(athfix, bw, nctrlsb);
}

#if defined(SYNC_WCHANNEL)
void sync_control_channel(int unit, int channel, int bw, int nctrlsb)
{
	char athfix[IFNAMSIZ];
	int ret __attribute__ ((unused));

	if (unit < 0 || unit >= MAX_NR_WL_IF)
		return;

	__get_wlifname(swap_5g_band(unit), 0, athfix);
	int wl_set_ch_bw(const char *ifname, int channel, int bw, int nctrlsb);
	ret = wl_set_ch_bw(athfix, channel, bw, nctrlsb);
}
#endif

int get_wifname_num(char *name)
{
	if (strcmp(WIF_5G, name) == 0)
		return 1;
#ifdef RTCONFIG_HAS_5G_2
	else if (strcmp(WIF_5G2, name) == 0)
		return 2;
#endif
	else if (strcmp(WIF_2G, name) == 0)
		return 0;
	else
		return -1;
}
/*
========================================================================
Routine Description:
	check all vif radio status.

Arguments:
	None

Return Value:
	0 : all vifs disable
	1 : one of vifs enable
========================================================================
*/
int check_vif_bss_enabled()
{
	char word[64], *next;
	int enabled=0, unit=0, sunit;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		unit = get_wifname_num(word);

		for (sunit = 1; sunit <= num_of_mssid_support(unit); sunit++) {
			if (nvram_match(wl_nvname("bss_enabled", unit, sunit), "1")) {
				logmessage("QCA CFG", "[%s] wl%d.%d_bss_enable: %d", __func__, unit, sunit, nvram_get_int(wl_nvname("bss_enabled", unit, sunit)));
				enabled = 1;
				break;
			}
		}
	}

	return enabled;
}

/*
========================================================================
Routine Description:
	check all vif nvram variable.

Arguments:
	None

Return Value:
	0 : do not excute script
	1 : excute vif's script
========================================================================
*/
int sync_vif_bss_enabled(char *key, char *pre, char *now)
{
	char word[64], *next;
	char vword[64], *vnext;
	char vifnames[] = "wlx_vifnames";
	int enabled=0, unit=0;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		unit = get_wifname_num(word);
		snprintf(vifnames, sizeof(vifnames), "wl%d_vifnames", unit);

		foreach (vword, nvram_safe_get(vifnames), vnext) {
			if (!strncmp(key, vword, 5)) {
				enabled = 1;			// guest network param

				if (strstr(key, "bss_enabled"))
					enabled = 2;		// guest network interface enabled
				break;
			}
		}
	}

	logmessage("QCA CFG", "[%s]  %s status changed! %s => %s", __func__, key, pre, now);

	return enabled;
}

char *getWscStatusStr(int unit)
{
	char buf[512] = {0};
	FILE *fp;
	int len;
	char *pt1,*pt2;

	snprintf(buf, sizeof(buf), "hostapd_cli -i%s wps_get_status", get_wifname(unit));
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Last WPS result: ");
			if (pt1) {
				pt2 = pt1 + strlen("Last WPS result: ");
				pt1 = strstr(pt2, "Peer Address: ");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
				}
				return pt2;
			}
		}
	}

	return "";	/* FIXME */
}

int get_wsc_status(int *fail_result)
{
	char buf[512] = {0};
        FILE *fp;
        int len;
        char *pt1,*pt2;
        int unit = 0;
        int state=-1; //analysis fail

	snprintf(buf, sizeof(buf), "hostapd_cli -i%s wps_get_status", get_wifname(unit));
        fp = popen(buf, "r");
        if (fp) {
                memset(buf, 0, sizeof(buf));
                len = fread(buf, 1, sizeof(buf), fp);
                pclose(fp);
                if (len > 1) {
                        state=0; //analysis ok  
                        buf[len-1] = '\0';
                        pt1 = strstr(buf, "Last WPS result: ");
                        if (pt1) {
                                pt2 = pt1 + strlen("Last WPS result: ");
                                pt1 = strstr(pt2, "Peer Address: ");
                                if (pt1) {
                                        *pt1 = '\0';
                                        chomp(pt2);
                                }

                                if (strstr(pt2, "Success") != NULL) 
                                        state= 1; //WPS OK
                                else if (strstr(pt2, "Timed-out") != NULL || strstr(pt2, "Idle") != NULL) //Fail, timeout
                                        *fail_result = OB_WPS_TIMEOUT_FAIL;
                                else if (strstr(pt2, "Overlap")!= NULL )//Fail, overlap
                                        *fail_result = OB_WPS_OVERLAP_FAIL;
                                else if (strstr(pt2, "Failed") != NULL) //Fail
                                         *fail_result = OB_WPS_UNKNOWN_FAIL;
				else
                                         *fail_result = OB_WPS_UNKNOWN_FAIL; //others
                        }
                }
	}
        return state;
}


#if 0
void add_beacon_vsie(char *oui, char *hexdata)
{
	char cmd[300] = {0};
	//#define IEEE80211_VENDORIE_INCLUDE_IN_BEACON        0x10
	//#define IEEE80211_VENDORIE_INCLUDE_IN_ASSOC_REQ     0x01
	//#define IEEE80211_VENDORIE_INCLUDE_IN_ASSOC_RES     0x02
	//#define IEEE80211_VENDORIE_INCLUDE_IN_PROBE_REQ     0x04
	//#define IEEE80211_VENDORIE_INCLUDE_IN_PROBE_RES     0x08
	int ftype = 0x18;
	int len = 0;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *ifname = NULL;

	len = 3 + strlen(hexdata)/2;	/* 3 is oui's len */

	if (is_router_mode() || access_point_mode())
		snprintf(prefix, sizeof(prefix), "wl0_");
	else
		snprintf(prefix, sizeof(prefix), "wl0.1_");

	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "wlanconfig %s vendorie add len %d oui %s pcap_data %s ftype_map %02X",
						ifname, len, oui, hexdata, ftype);
		system(cmd);
	}
}

void del_beacon_vsie(char *oui, char *hexdata)
{
	char cmd[300] = {0};
	int len = 4;	/* 3 is oui's len + first byte */
	char firstByte[3] = {0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *ifname = NULL;

	snprintf(firstByte, sizeof(firstByte), "%s", hexdata);
	firstByte[2] = '\0';

	if (is_router_mode() || access_point_mode())
		snprintf(prefix, sizeof(prefix), "wl0_");
	else
		snprintf(prefix, sizeof(prefix), "wl0.1_");

	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "wlanconfig %s vendorie remove len %d oui %s pcap_data %s",
						ifname, len, oui, firstByte);
		system(cmd);
	}
}
#endif

/*
 * wl_get_chans_info(unit, buf, len)
 *
 * getting the channel information including DFS state.
 *
 * unit:
 * 	0/1/2...: normal case
 * 	-1      : use the 5G (for dual band) OR 5G high band (for TRI_BAND) unit
 */

int wl_get_chans_info(int unit, char* buf, size_t len)
{
#if defined(RTCONFIG_WIFI6E)
#define MAX_NRCHANNELS (64)
#else
#define MAX_NRCHANNELS (32)
#endif
	static char old_blk_ch_lists[MAX_NR_WL_IF][4 * MAX_NRCHANNELS + 10] = {{ 0 }};
	static int old_radar_lists[MAX_NR_WL_IF][MAX_NRCHANNELS] = {{ 0 }};
	int ch_list[MAX_NRCHANNELS];
	int radar_list[MAX_NRCHANNELS] = { 0 }, *old_radar_list;
	int ch_cnt, radar_cnt;
	char athfix[8], vphy[8];
	int i, j, *pch;
	int ch_stat;
	int ret;
	char ch[6], blk_ch_list[4 * MAX_NRCHANNELS], radar_list_str[4 * MAX_NRCHANNELS];
	char *p, *old_blk_ch_list;

#ifdef RTCONFIG_AVBLCHAN
	int block_ch[MAX_NRCHANNELS],k,blk_cnt;
	char tmpch[256],*tmplist,*dtmp,*data,tmp[128];
	char prefix[]="wlxxxxxxxxx_";
#endif

	if(buf == NULL || len <= 0)
		return -1;

	*buf = '\0';
	if(unit < 0) {
#if defined(SUPPORT_TRI_BAND) &&  !defined(RTCONFIG_LYRA_5G_SWAP)
                unit=2; //5G high band
#else
		unit = swap_5g_band(1);	//5G OR 5G high band
#endif
	}

	if (unit >= MAX_NR_WL_IF)
		return -1;

	old_blk_ch_list = &old_blk_ch_lists[unit][0];
	old_radar_list = &old_radar_lists[unit][0];
	__get_wlifname(swap_5g_band(unit), 0, athfix);
	if((ch_cnt = get_channel_list(athfix, ch_list, MAX_NRCHANNELS)) < 0) {
		cprintf("get_channel_list: fail %d\n", ch_cnt);
		return ch_cnt;
	}

	strcpy(vphy, get_vphyifname(swap_5g_band(unit)));
	if((radar_cnt = get_radar_channel_list(vphy, radar_list, MAX_NRCHANNELS)) < 0) {
		cprintf("get_radar_channel_list: fail %d\n", radar_cnt);
		return radar_cnt;
	}


#ifdef RTCONFIG_AVBLCHAN
	blk_cnt=0;
	tmplist=NULL;
	dtmp=NULL;
	memset(tmpch,0,sizeof(tmpch));
	memset(block_ch,0,sizeof(block_ch));
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(tmpch, nvram_safe_get(strcat_r(prefix, "block_ch", tmp)), sizeof(tmpch));
	tmplist=strdup(tmpch);
	dtmp=tmplist;
	while(dtmp && (data= strsep(&dtmp,",")) != NULL)
	{
			block_ch[blk_cnt]=atoi(data);
			blk_cnt++;
	}
	free(tmplist);
#endif

	// set version
	ret = snprintf(buf, len, "%d ", CHINFO_CMNFMT_V1);
	p = buf + ret;
	len -= ret;

	*blk_ch_list = '\0';
	*radar_list_str = '\0';
	for(i = 0; i < ch_cnt && len > 0; i++) {
		for(j = 0; j < radar_cnt; j++) {
			if(ch_list[i] == radar_list[j])
				break;
		}

#ifdef RTCONFIG_AVBLCHAN
		//according to countrycode, find block-channel and mark it as CHINFO_BLK
		for(k = 0; k < blk_cnt; k++) {
			if(ch_list[i]==block_ch[k])
				break;
		}
#endif

//cprintf("# ch_list[%02d](%d) j(%d) radar_cnt(%d)\n", i, ch_list[i], j, radar_cnt);
		if(j != radar_cnt 
#ifdef RTCONFIG_AVBLCHAN
		  || k != blk_cnt
#endif
		) {
			ch_stat = CHINFO_BLK;
			if (*blk_ch_list != '\0')
				strlcat(blk_ch_list, ",", sizeof(blk_ch_list));
			snprintf(ch, sizeof(ch), "%d", ch_list[i]);
			strlcat(blk_ch_list, ch, sizeof(blk_ch_list));
		}
		else
			ch_stat = CHINFO_AVBL;
		ret = snprintf(p, len, "%05u%03u ", ch_stat, ch_list[i]);
		p += ret;
		len -= ret;
	}

	/* If rader/unavailable channel list changed, print it to console/syslog. */
	if (memcmp(old_radar_list, radar_list, sizeof(radar_list))) {
		for (i = 0, pch = radar_list; i < radar_cnt; ++i, ++pch) {
			if (*radar_list_str != '\0')
				strlcat(radar_list_str, ",", sizeof(radar_list_str));
			snprintf(ch, sizeof(ch), "%d", *pch);
			strlcat(radar_list_str, ch, sizeof(radar_list_str));
		}
		if (*radar_list != '\0') {
			_dprintf("%s: report band %d radar list [%s]\n", __func__, unit, radar_list_str);
			logmessage("CFG_MNT", "report band %d radar list[%s]\n", unit, radar_list_str);
		}
		memcpy(old_radar_list, radar_list, sizeof(radar_list));
	}
	if (strcmp(old_blk_ch_list, blk_ch_list)) {
		if (*blk_ch_list != '\0') {
			_dprintf("%s: report band %d unavailable channel list [%s]\n", __func__, unit, blk_ch_list);
			logmessage("CFG_MNT", "report band %d unavailable channel list [%s]\n", unit, blk_ch_list);
		}
		strlcpy(old_blk_ch_list, blk_ch_list, 4 * MAX_NRCHANNELS + 10);
	}
	return 0;
}

/*
 * int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
 *
 * chconf:
 * 	CHCONF_CH_MASK  0x00FF: channel number
 * 	CHCONF_SB_MASK  0x0700: control channel location (shift number from first channel)
 * 	CHCONF_BW_MASK  0x7000: bandwidth information
 *
 */
int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
{
	int base = 0, channel, bw, nctrlsb;
	int centra_ch;
	int ret;
#if defined(RTCONFIG_WIFI6E)
	int unit, subunit;
	char prefix[] = "wlXXXXXXXXXXXX_";
#endif

	if(ifname == NULL || chconf == NULL)
		return -1;

	*chconf = 0;

	channel = get_channel(ifname);
	if((ret = get_bw_nctrlsb(ifname, &bw, &nctrlsb)) < 0) {
		cprintf("%s: get_bw_nctrlsb ret(%d)\n", __func__, ret);
		return ret;
	}

#if defined(RTCONFIG_WIFI6E)
	if (get_wlif_unit(ifname, &unit, &subunit) < 0)
		return -1;
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
#endif

	if (bw == 20) {
		centra_ch = channel;
		nctrlsb = 0;
		CHCONF_BW_SET20(*chconf);
	}
	else if (bw == 40 && nctrlsb >= 0) {
		centra_ch = channel + 2 - (nctrlsb << 2);
		CHCONF_BW_SET40(*chconf);
	}
	else if (bw == 80) {
#if defined(RTCONFIG_WIFI6E)
		if (nvram_pf_match(prefix, "nband", "4"))
			base = 33;
		else
#endif
			base = (channel >= 149) ? 149 : 36;
		nctrlsb = ((channel - base) % 16) / 4;
		centra_ch = channel + 6 - (nctrlsb << 2);
		CHCONF_BW_SET80(*chconf);
	}
	else if (bw == 160) {
#if defined(RTCONFIG_WIFI6E)
		if (nvram_pf_match(prefix, "nband", "4"))
			base = 33;
		else
#endif
			base = (channel >= 149) ? 149 : 36;
		nctrlsb = ((channel - base) % 32) / 4;
		centra_ch = channel + 14 - (nctrlsb << 2);
		CHCONF_BW_SET160(*chconf);
	}
	else {
		cprintf("%s: INVALID bw(%d)\n", bw);
		return -6;
	}

	CHCONF_CH_SET(*chconf, centra_ch);
	CHCONF_SB_SET(*chconf, (nctrlsb << CHCONF_SB_SHIFT));

	return 0;
}

int wl_set_ch_bw(const char *ifname, int channel, int bw, int nctrlsb)
{
	char mode[32], *p = mode, *orig_mode;
	int apply_mode = 0, apply_ch = 0, bwcap;
	int unit, subunit, old_channel = 0;
	char prefix[] = "wlXXXXXXXXXXXX_", ch_str[8] = "auto";
	char cmd[sizeof("hostapd_cli -i XXX status") + IFNAMSIZ], state[16] = { 0 }; /* ref. state string in hostapd_state_text() */
#if !defined(RTCONFIG_SPF11_4_QSDK)
	int led, is_up;
#if defined(RTCONFIG_CFG80211)
	char *radio_on[] = { "hostapd_cli", "-p", "/var/run/hostapd", "-i", (char*) ifname, "enable", NULL };
	char *radio_off[] = { "hostapd_cli", "-p", "/var/run/hostapd", "-i", (char*) ifname, "disable", NULL };
#else
	char *radio_on[] = { "ifconfig", (char*) ifname, "up", NULL };
	char *radio_off[] = { "ifconfig", (char*) ifname, "down", NULL };
#endif
#endif

	if (ifname == NULL)
		return -1;

#if !defined(RTCONFIG_SPF11_4_QSDK)
#if defined(RTCONFIG_CFG80211)
	snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s status", ifname);
	if (!exec_and_parse(cmd, "state=", "%*[^=]=%[^ \n]s", 1, state)) {
		if (!strcmp(state, "UNINITIALIZED")) {
			_eval(radio_off, NULL, 0, NULL);
		}
	} else {
		dbg("%s: Can't get %s hostapd state!\n", __func__, ifname);
		return -1;
	}
#endif
#endif

	if (get_wlif_unit(ifname, &unit, &subunit) < 0)
		return -1;

	if (wl_get_bw_cap(unit, &bwcap) < 0)
		return -1;

	/* set mode via bwcap and band */
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
	if (unit == 0)
		p += sprintf(p, "11GHE%d", bw);
	else
		p += sprintf(p, "11AHE%d", bw);
#else
	if (bwcap & (0x08 | 0x04)) {				/* support BW160 || BW80 for AC */
		p += sprintf(p, "11ACVHT%d", bw);
	}
	else if (bwcap & (0x02)) {				/* support  BW40 for NG OR NA */
		if(unit == 0)
			p += sprintf(p, "11NGHT%d", bw);
		else
			p += sprintf(p, "11NAHT%d", bw);
	}
	else {							/* support  BW20 for A OR G */
		if(unit == 0)
			p += sprintf(p, "11G");
		else
			p += sprintf(p, "11A");
	}
#endif

	/* set extension channel when bw==40 and valid nctrlsb */
	if (bw == 40 && nctrlsb >= 0) {
		if(nctrlsb == 1)
			p += sprintf(p, "MINUS");
		else
			p += sprintf(p, "PLUS");
	}

	orig_mode = iwpriv_get(ifname, "get_mode");
	if (orig_mode && strcmp(orig_mode, mode))
		apply_mode++;

	if (channel > 0) {
		snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s status", ifname);
		exec_and_parse(cmd, "channel=", "%*[^=]=%d", 1, &old_channel);
		if (old_channel != channel) {
			snprintf(ch_str, sizeof(ch_str), "%d", channel);
			apply_ch++;
		}
	}

	if (apply_mode || apply_ch) {
#if defined(RTCONFIG_SPF11_1_QSDK)
		/* Make sure staX down before changing mode/channel */
		int is_sta_up;
		char sta[IFNAMSIZ];

		strlcpy(sta, get_staifname(unit), sizeof(sta));
		is_sta_up = is_intf_up(sta);
		if (is_sta_up > 0)
			eval("ifconfig", sta, "down");
#endif

#if !defined(RTCONFIG_SPF11_4_QSDK)
		led = get_wl_led_id(unit);
		is_up = is_intf_up(ifname);
		if (is_up > 0) {
			_eval(radio_off, NULL, 0, NULL);
			led_control(led, LED_OFF);
		}
#endif

#if defined(RTCONFIG_LYRA_5G_SWAP)
		snprintf(prefix, sizeof(prefix), "wl%d_", swap_5g_band(unit));
#else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
#endif

		if (apply_mode) {
			doSystem(IWPRIV " %s mode %s", ifname, mode);
		}
		if (apply_ch) {
#if defined(RTCONFIG_WIFI6E)
			if (nvram_pf_match(prefix, "nband", "4"))
				doSystem(IWPRIV " %s channel %s 3", ifname, ch_str);
			else
#endif
				doSystem("iwconfig %s channel %s", ifname, ch_str);
		}

#if !defined(RTCONFIG_SPF11_4_QSDK)
		//RadioOn
#if defined(RTCONFIG_CFG80211)
		/* To apply setting, always enable radio first. */
		_eval(radio_on, NULL, 0, NULL);

		/* If VAP is not able to be enabled for unknown reason, remove and add it again to workaround. */
		snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s status", ifname);
		if (!exec_and_parse(cmd, "state=", "%*[^=]=%[^ \n]s", 1, state) && !strcmp(state, "DISABLED")) {
			char bss_config[IFNAMSIZ + sizeof("bss_config=XXX:/etc/Wireless/conf/hostapd_XXX.conf") + IFNAMSIZ];
			char *radio_remove[] = { QWPA_CLI, "-g", QHOSTAPD_CTRL_IFACE, "raw", "REMOVE", (char*) ifname , NULL };
			char *radio_add[] = { QWPA_CLI, "-g", QHOSTAPD_CTRL_IFACE, "raw", "ADD", bss_config, NULL };

			snprintf(bss_config, sizeof(bss_config), "bss_config=%s:/etc/Wireless/conf/hostapd_%s.conf", ifname, ifname);
			_eval(radio_remove, NULL, 0, NULL);
			_eval(radio_add, NULL, 0, NULL);
			logmessage("CFG", "Add %s to hostapd again! (channel %d bw %d nctrlsb %d mode [%s -> %s] apply %d/%d)",
				ifname, channel, bw, nctrlsb, orig_mode, mode, apply_mode, apply_ch);
		}

		if (!is_up || !nvram_pf_match(prefix, "radio", "1") || !chk_wifi_sched(unit)) {
			_eval(radio_off, NULL, 0, NULL);
		} else {
			led_control(led, inhibit_led_on()? LED_OFF : LED_ON);
		}
#else
		if(nvram_pf_get_int(prefix, "radio")) {
			if(chk_wifi_sched(unit) && is_up > 0)
			{
				_eval(radio_on, NULL, 0, NULL);
				led_control(led, inhibit_led_on()? LED_OFF : LED_ON);
			}
		}
#endif
#endif	/* !RTCONFIG_SPF11_4_QSDK */
#if defined(RTCONFIG_SPF11_1_QSDK)
		if (is_sta_up > 0)
			eval("ifconfig", sta, "up");
#endif
	}

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
	return wl_set_ch_bw(ifname, channel, bw, nctrlsb);
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
	char *wlif_name __attribute__ ((unused));
	char qca_maccmd[32];
	char *sec = "";
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

#ifdef RTCONFIG_QCA_LBD
		if (nvram_match("smart_connect_x", "1"))
			sec = "_sec";
#endif
		sprintf(qca_maccmd, "%s%s", QCA_MACCMD, sec);
		ret = doSystem(IWPRIV " %s %s %d", get_wifname(unit), qca_maccmd, val);
		if(ret)
			DBG_ERR("[%s] set %s %d failed", get_wifname(unit), qca_maccmd, val);
	}
}

#ifdef RTCONFIG_AVBLCHAN

/* Whether @ch exist in @str.
 * @str:	comma-seperate channel list
 * @ch:		channel number
 * @return:
 * 	1:	@ch exist in @str
 * 	0:	@ch doesn't exist in @str or @str = NULL
 */
int ch_match(char* str, int ch)
{
	char *tmplist,*dtmp,*data;
	if(str!=NULL)
	{
		tmplist=NULL;
		dtmp=NULL;
		tmplist=strdup(str);
		dtmp=tmplist;
		while(dtmp && (data= strsep(&dtmp,",")) != NULL)
		{
			if(atoi(data)== ch)
			{
				free(tmplist);
				return 1;
			}
		}
		free(tmplist);
	}
	return 0;
}


/* If @c exist in @avbl2g or @avbl5g, return true.
 * @unit:	enum wl_band_id
 * @avbl2g:
 * @avgl5g:
 * @return:
 * 	1:	@c exist in @avbl2g or @avbl5g
 * 	0:	@c doesn't exist in @avbl2g and @avbl5g
 */
typedef uint16_t chanspec_t; 
int is_avbl(unsigned int unit, chanspec_t  c, chanspec_t *avbl2g, chanspec_t *avbl5g, chanspec_t *avbl6g)
{
        int i=0, avbl=0;
        if(unit == 0) {
                for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
                        if(avbl2g[i] == c) {
                                avbl = 1;
                                break;
                        }
                }
#if defined(RTCONFIG_WIFI6E)
        } else if (is_6g(unit)) {
                for(i=0; i<MAX_6G_CHANNEL_LIST_NUM; ++i) {
                        if(avbl6g[i] == c) {
                                avbl = 1;
				break;
                        }
                }
#endif
        } else {
                for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
                        if(avbl5g[i] == c) {
                                avbl = 1;
				break;
                        }
                }
        }
        return avbl;
}

/* Get channel list from driver, remove channels listed in wlX_block_ch from it, and generate comma-seperate channel list.
 * @unit:		enum wl_band_id
 * @p_avbl_ch_mask:	bitmask of available channel list, remove wlX_block_ch from supported channel list
 * @p_all_ch_mask:	bitmask of whole channel list of @unit.
 */
void get_avb_ch(int unit, uint64_t *p_avbl_ch_mask, uint64_t *p_all_ch_mask)
{
	uint64_t block_ch_mask;
	char chList[128] = "", prefix[sizeof("wlxxx_")];

	if (!p_avbl_ch_mask || !p_all_ch_mask)
		return;

	get_channel_list_via_driver(swap_5g_band(unit), chList, sizeof(chList));
	*p_all_ch_mask = chlist2bitmask(unit, chList, ",");

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	block_ch_mask = chlist2bitmask(unit, nvram_pf_safe_get(prefix, "block_ch"), ",");

	*p_avbl_ch_mask = *p_all_ch_mask & ~block_ch_mask;
}

void dump_avblchanspecs(chanspec_t *avbl2g, chanspec_t *avbl5g, chanspec_t *avbl6g)
{
        int i=0;

        for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
                DBG_INFO("[%d]=(%d) ", i, avbl2g[i]);
                if(!i%10) DBG_INFO("\n");
        }

        for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
                DBG_INFO("[%d]=(%d) ", i, avbl5g[i]);
                if(!i%10) DBG_INFO("\n");
        }

#if defined(RTCONFIG_WIFI6E)
        for(i=0; i<MAX_6G_CHANNEL_LIST_NUM; ++i) {
                DBG_INFO("[%d]=(%d) ", i, avbl6g[i]);
                if(!i%10) DBG_INFO("\n");
        }
#endif

        DBG_INFO("\n");
}


void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
	static uint64_t old_unavbl_ch_mask[WL_NR_BANDS] = { 0 };
	uint64_t i, tmpch, all_ch_mask[WL_NR_BANDS] = { 0 }, avbl_ch_mask[WL_NR_BANDS] = { 0 };
	uint64_t *p_all_ch_mask, *p_avbl_ch_mask, pre_unavbl_ch_mask, unavbl_ch_mask, block_ch_mask, m, ch_mask;
	char unavbl_ch[128], sum_block[128] /* block_ch + unavbl_ch */;
	int b, ch = 0, unit = -1, exist5ghighch = 0;
	char word[256]={0}, *next = NULL, prefix[]="wlxxx";
	chanspec_t avblchanspec2g[MAX_2G_CHANNEL_LIST_NUM];
	chanspec_t avblchanspec5g[MAX_5G_CHANNEL_LIST_NUM];
#if defined(RTCONFIG_WIFI6E)
	chanspec_t avblchanspec6g[MAX_6G_CHANNEL_LIST_NUM];
#else
	chanspec_t *avblchanspec6g = NULL;
#endif

	if(!*nvram_safe_get("cfg_rejoin") && !*nvram_safe_get("cfg_test"))
		return;

	if(!nvram_match("wlready", "1")) {
		DBG_ERR("no chanspec chgact due wl not ready.\n");
		return;
	}

	if(nvram_match("avblchan_disable", "1"))
		return;

	memset(avblchanspec2g, 0, sizeof(avblchanspec2g));
	memset(avblchanspec5g, 0, sizeof(avblchanspec5g));
#if defined(RTCONFIG_WIFI6E)
	memset(avblchanspec6g, 0, sizeof(avblchanspec6g));
#endif

	for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList2g[i];
		if(tmpch > 0 && tmpch < 14)
			avblchanspec2g[i] = tmpch;
	}

	//dual-band CAP: for common bands, discard available 5G lowband if RE has dual-5G bands.
	if ((num_of_wl_if() == 2) && avblChanspec->existDual5gRe)
	{ 
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
			tmpch = avblChanspec->channelList5g[i];
			if (tmpch >= 100) {
				exist5ghighch = 1;
				break;
			}
		}
	}

	for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList5g[i]; 
		if(tmpch > 14 && tmpch < 166)
		{
			if(exist5ghighch && (tmpch < 100)) // mask-off low band 
				continue;
			avblchanspec5g[i] = tmpch; 
		}
	}

#if defined(RTCONFIG_WIFI6E)
	for(i=0; i<MAX_6G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList6g[i]; 
		if(tmpch > 32 && tmpch < 234)
			avblchanspec6g[i] = tmpch; 
	}
#endif

	dump_avblchanspecs(avblchanspec2g, avblchanspec5g, avblchanspec6g);
	
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		if(!strcmp(word,WIF_2G))
			unit=0;
		else if(!strcmp(word,WIF_5G))
			unit=swap_5g_band(1);
		else if(!strcmp(word,WIF_5G2))
			unit=swap_5g_band(2);
		else
		{
			unit=-1;
			continue;
		}

		if (unit < 0 || unit >= ARRAY_SIZE(all_ch_mask))
			continue;

		unavbl_ch_mask = 0;
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		p_all_ch_mask = &all_ch_mask[unit];
		p_avbl_ch_mask = &avbl_ch_mask[unit];
		get_avb_ch(unit, p_avbl_ch_mask, p_all_ch_mask);	/* discard mask-channel according to countrycode */
		pre_unavbl_ch_mask = chlist2bitmask(unit, nvram_pf_safe_get(prefix, "unavbl_ch"), ",");

		/* Update wlX_unavbl_ch channel list. */
		m = *p_avbl_ch_mask;
		while ((b = ffsl(m)) > 0) {
			b--;
			ch_mask = 1L << b;
			m &= ~ch_mask;
			ch = bit2ch(unit, b);
			if (is_avbl(unit, ch, avblchanspec2g, avblchanspec5g, avblchanspec6g))
				continue;

			if (!(unavbl_ch_mask & ch_mask)) {
				DBG_INFO("<%2x> is newly unavbl channel\n", ch);
				unavbl_ch_mask |= ch_mask;
			}
		}
		__bitmask2chlist(unit, unavbl_ch_mask, ",", unavbl_ch, sizeof(unavbl_ch));
		nvram_pf_set(prefix, "unavbl_ch", unavbl_ch);

		if (old_unavbl_ch_mask[unit] != unavbl_ch_mask) {
			_dprintf("Latest unavailable channels of band %d: [%s]\n", unit, unavbl_ch);
			logmessage("CFG_MNT", "Latest unavailable channels of band %d: [%s]\n", unit, unavbl_ch);
			old_unavbl_ch_mask[unit] = unavbl_ch_mask;
		}

		//dynamically adjust channels that are not available
		block_ch_mask = chlist2bitmask(unit, nvram_pf_safe_get(prefix, "block_ch"), ",");
		if (pre_unavbl_ch_mask != unavbl_ch_mask) {
			/* Update block_acs_channel if and only if not all channels are blocked. */
			m = block_ch_mask | unavbl_ch_mask;
			__bitmask2chlist(unit, m, ",", sum_block, sizeof(sum_block));
			if (m != *p_all_ch_mask) {
				eval("wifitool", word, "block_acs_channel", "0");

				if (*sum_block != '\0')
					eval("wifitool", word, "block_acs_channel", sum_block);
			} else {
				_dprintf("Skip unavailable channels [%s] of band %d due to it equal to supported channel list!\n", sum_block, unit);
			}
		}

		if ((ch = get_channel(word)) < 0)
			continue;
		ch_mask = ch2bitmask(unit, ch);
		if (unavbl_ch_mask & ch_mask) { //switch to another channel, because it is unavbl ch
			_dprintf("Need to select new channel due to current one [%d] unavailable [%s]\n", ch, unavbl_ch);
			logmessage("CFG_MNT", "Need to select new channel due to current one [%d] unavailable [%s]\n", ch, unavbl_ch);
			eval("iwconfig", word, "channel", "0");
		}
	}
}
#else

/* 
 * wl_chanspec_changed_action()
 *
 * Ham:
 * It’s a callback whenever chanspec changed detected by cfg_mnt.
 * Could be used for free purposes, I guess.
 * Just use it to count current available chanspecs
 * (sync w/ CAP and RE, due RE could be tribands and CAP be dualbands 
 *  and maybe w/ different chanspec policies) at current mesh env.
 *
 * In bcm models, if no avblchan enabled, it does nothing.
 */

void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
}
#endif

#if defined(RTCONFIG_QCA_LBD)
int add_lbd_list(const char *mac, const char *sta2g, const char *sta5g)
{
	if(pids("lbd"))
	{
		set_steer(mac,1);
		set_steer(sta2g,1);
		set_steer(sta5g,1);
	}
	return 0;
}
#endif

char *get_ssid(char *ifname, char *ssid_buf, int buf_len)
{
	char buf[8192] = "";
	FILE *fp;
	int len;
	char *pt1, *pt2, *pt3;

	if (!ifname || *ifname == '\0') {
		DBG_ERR("got invalid ifname %p", __func__, ifname);
		return ssid_buf;
	}

	snprintf(buf, sizeof(buf), "iwconfig %s", ifname);
	if (!(fp = popen(buf, "r")))
		return ssid_buf;

	len = fread(buf, 1, sizeof(buf), fp);
	pclose(fp);
	if (len <= 0)
		return ssid_buf;

	buf[len] = '\0';
	pt1 = strstr(buf, "ESSID:");
	if (!pt1)
		return ssid_buf;

	pt2 = pt1 + strlen("ESSID:") + 1;	/* skip leading " */
	pt1 = strchr(pt2, '\n');
	if (!pt1 || (pt1 - pt2) <= 1)
		return ssid_buf;

	/* Remove trailing " */
	*pt1 = '\0';
	pt3 = strrchr(pt2, '"');
	if (pt3)
		*pt3 = '\0';

	strlcpy(ssid_buf, pt2, buf_len);

	return ssid_buf;
}

char *get_pap_ssid(int unit, char *ssid_buf, int buf_len)
{
	return get_ssid(get_staifname(swap_5g_band(unit)), ssid_buf, buf_len);
}

char *get_ap_ssid(int unit, char *ssid_buf, int buf_len)
{
	char ifname[8];

	__get_wlifname(swap_5g_band(unit), 0, ifname);

	return get_ssid(ifname, ssid_buf, buf_len);
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

	//  TODO
	int model = get_model();
	int result = 0;

	switch (model) {
#ifdef RTAC59_CD6N
		case MODEL_RTAC59CD6N:
			if (!strcmp("vlan1", ifname))
				result = gen_uplinkport_describe("LAN", "ETH", "1000", 1);
			else if	(!strcmp("vlan4", ifname))
				result = gen_uplinkport_describe("LAN", "ETH", "1000", 2);
			break;
#endif	/* RTAC59_CD6N */
#ifdef PLAX56_XP4
		case MODEL_PLAX56XP4:
			if (!strcmp("eth1", ifname))
				result = gen_uplinkport_describe("WAN", "PLC", "NONE", 0);
			else if (nvram_match("HwId", "B")) //node
			{
				if (!strcmp("eth2", ifname))
					result = gen_uplinkport_describe("LAN", "ETH", "1000", 1);
				else if (!strcmp("eth3", ifname))
					result = gen_uplinkport_describe("LAN", "ETH", "1000", 2);
			}
			else if (!strcmp("eth4", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "1000", 0);
			break;
#endif	/* PLAX56_XP4 */
#ifdef RTAX89U
		case MODEL_RTAX89U:
			if (!strcmp("eth3", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "1000", 0);
			else if (!strcmp("eth5", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "10G", 0);
			else if (!strcmp("eth4", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "10GSFP+", 0);
			break;
#endif	/* RTAX89U */
		default:
			result = gen_uplinkport_describe("WAN", "ETH", "1000", 0);
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
