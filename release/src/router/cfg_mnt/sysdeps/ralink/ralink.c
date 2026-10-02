#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shared.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <wlutils.h>
#include <ralink.h>
#include "cfg_common.h"
#include "cfg_wevent.h"
#include "encrypt_main.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#include "chmgmt.h"

#define MAX_NRCHANNELS (32)
#define IW_ESSID_MAX_SIZE     32

int wl_set_ch_bw(const char *ifname, int channel, int bw, int nctrlsb);

char *get_pap_bssid(int unit, char *bssid_buf, int buf_len)
{
	struct iwreq wrq;
	unsigned char ether_zero[ETH_ALEN] = {0x00};

	if (wl_ioctl(get_staifname(unit), SIOCGIWAP, &wrq) < 0) {
		DBG_ERR("errors in getting pap bssid");
		return bssid_buf;
	}

	wrq.u.ap_addr.sa_family = ARPHRD_ETHER;
	if (memcmp(&wrq.u.ap_addr.sa_data[0], &ether_zero[0], ETH_ALEN))
	{
		snprintf(bssid_buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)wrq.u.ap_addr.sa_data[0],
			(unsigned char)wrq.u.ap_addr.sa_data[1],
			(unsigned char)wrq.u.ap_addr.sa_data[2],
			(unsigned char)wrq.u.ap_addr.sa_data[3],
			(unsigned char)wrq.u.ap_addr.sa_data[4],
			(unsigned char)wrq.u.ap_addr.sa_data[5]);
	}

	DBG_INFO("unit(%d), bssid(%s)", unit, bssid_buf);

	return bssid_buf;
}

int get_pap_rssi(int unit)
{
	int rssi_ret = 0, i = 0, stream_num = 0, rssi[8];
	char data[24], tmp[128], prefix[] = "wlXXXXXXXXXX_";
	struct iwreq wrq;
	char *pt1, *p_rssi, *rssi_val;
	int xTxR;
	char *aif = get_staifname(unit);

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_CLRSSI;

	if (wl_ioctl(aif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting ASUS_SUBCMD_CLRSSI result\n");
		return 0;
	}

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp));
	DBG_INFO("xTxR (%d)", xTxR);

	if (wrq.u.data.length > 0) {
		DBG_INFO("data (%s)", wrq.u.data.pointer);
		if ((p_rssi = strdup(wrq.u.data.pointer)) != NULL) {
			pt1 = p_rssi;
			memset(rssi, 0, sizeof(rssi));
			while ((rssi_val = strsep(&pt1, " ")) != NULL) {
				while (*rssi_val == ' ') ++rssi_val;
				if (*rssi_val == 0 || stream_num >= xTxR) break;

				rssi[stream_num] = atoi(rssi_val);
				stream_num++;
			}
			free(p_rssi);

			DBG_INFO("stream_num(%d)", stream_num);
			/* summarize rssi */
			for (i = 0; i < stream_num; i++) {
				DBG_INFO("rssi[%d] = %d", i, rssi[i]);
				rssi_ret += rssi[i];
			}

			/* compute average rssi */
			if (rssi_ret != 0 && stream_num != 0) {
				rssi_ret = rssi_ret / stream_num;
				if (rssi_ret == -127)	/* -127 is not assocated pap */
					rssi_ret = 0;
			}
			else
				rssi_ret = 0;
		}
	}
	return rssi_ret;
}

int wl_sta_list(char *msg, int msg_len)
{
	char *sp, *op;
	char header[128], data[2048];
	struct iwreq wrq;
	int hdrLen, staCount=0, getLen;
	char header_t[128]={0};
	sta_entry *ssap;
	char rssinum[16]={0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	int unit = 0;
	char word[256], *next;
	char brMac[32] = {0};
	char ifAlias[16] = {0};
	json_object *root = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int ret = 0;
	int xTxR = 0;
	int stream = 0;
	int i = 0;
	time_t ts;
	int pass_entry = 0;
	char pap[18] = {0};

	time(&ts);

	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	brMacObj = json_object_new_object();
	if (!brMacObj) {
		DBG_ERR("brMacObj is NULL");
		return 0;
	}

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		bandObj = NULL;
		staCount = 0;
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
#ifdef RTCONFIG_AMAS
		if (nvram_get_int("re_mode") == 1) {
			memset(pap, 0, sizeof(pap));
			get_pap_bssid(unit, &pap[0], sizeof(pap));
		}
#endif

		if (!strlen(name))
			goto exit;

		if (!(xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp))))
			goto exit;

		if(xTxR > xR_MAX)
			xTxR = xR_MAX;

		memset(ifAlias, 0, sizeof(ifAlias));
		if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

		/* get MAC of station */
		memset(data, 0x00, sizeof(data));
		wrq.u.data.length = sizeof(data);
		wrq.u.data.pointer = (caddr_t) data;
		wrq.u.data.flags = ASUS_SUBCMD_GROAM;

		if (wl_ioctl(name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
			dbg("[%s]: WI[%s] Access to StaInfo failure\n", __FUNCTION__, name);
			goto exit;
		}

		memset(header, 0, sizeof(header));
		memset(header_t, 0, sizeof(header_t));
		hdrLen = snprintf(header_t, sizeof(header_t), "%-19s", "MAC");
		strlcpy(header, header_t, sizeof(header));

		for (stream = 0; stream < xR_MAX; stream++) {
			snprintf(rssinum, sizeof(rssinum), "RSSI%d", stream);
			memset(header_t, 0, sizeof(header_t));
			hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", rssinum);
			strncat(header, header_t, strlen(header_t));
		}
		hdrLen += snprintf(header_t, sizeof(header_t), "%-21s", "TxBytes");
		strncat(header, header_t, strlen(header_t));
		hdrLen += snprintf(header_t, sizeof(header_t), "%-21s", "RxBytes");
		strncat(header, header_t, strlen(header_t));
		hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "WnmCap");
		strncat(header, header_t, strlen(header_t));
		hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "BcnCap");
		strncat(header, header_t, strlen(header_t));
		strcat(header,"\n");
		hdrLen++;

		if (wrq.u.data.length > 0 && data[0] != 0) {
			getLen = strlen(wrq.u.data.pointer + hdrLen);

			ssap = (sta_entry *)(wrq.u.data.pointer + hdrLen);
			op = sp = wrq.u.data.pointer + hdrLen;
			while (*sp && ((getLen - (sp-op)) >= 0)) {
				pass_entry = 0;
				ssap->sta[staCount].mac[17]='\0';
#ifdef RTCONFIG_AMAS
				if (nvram_get_int("re_mode") == 1 && strncmp(ssap->sta[staCount].mac, pap, sizeof(pap)-1) == 0)
					pass_entry = 1;
#endif
				if (!pass_entry && strlen(ssap->sta[staCount].mac)) {
					if (!bandObj)
						bandObj = json_object_new_object();
					staObj = json_object_new_object();
					json_object_object_add(staObj, WEVENT_TIMESTAMP,
						json_object_new_int64(ts));
					json_object_object_add(bandObj, ssap->sta[staCount].mac, staObj);
				}
				sp += hdrLen;
				staCount++;
			}
		}

		if (bandObj)
			json_object_object_add(brMacObj, ifAlias, bandObj);

		for (i = 1; i < 4; i++) {
			bandObj = NULL;
			staCount = 0;
			memset(prefix, 0, sizeof(prefix));
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
			if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))  {
				snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
				name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

				if (!strlen(name))
					goto exit;

				memset(ifAlias, 0, sizeof(ifAlias));
				if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

				/* get MAC of station */
				memset(data, 0x00, sizeof(data));
				wrq.u.data.length = sizeof(data);
				wrq.u.data.pointer = (caddr_t) data;
				wrq.u.data.flags = ASUS_SUBCMD_GROAM;

				if (wl_ioctl(name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
					dbg("[%s]: WI[%s] Access to StaInfo failure\n", __FUNCTION__, name);
					goto exit;
				}

				if (wrq.u.data.length > 0 && data[0] != 0) {
					getLen = strlen(wrq.u.data.pointer + hdrLen);

					ssap = (sta_entry *)(wrq.u.data.pointer + hdrLen);
					op = sp = wrq.u.data.pointer + hdrLen;
					while (*sp && ((getLen - (sp-op)) >= 0)) {
						pass_entry = 0;
						ssap->sta[staCount].mac[17]='\0';
#ifdef RTCONFIG_AMAS
						if (nvram_get_int("re_mode") == 1 && strncmp(ssap->sta[staCount].mac, pap, sizeof(pap)-1) == 0)
							pass_entry = 1;
#endif
						if (!pass_entry && strlen(ssap->sta[staCount].mac)) {
							if (!bandObj)
								bandObj = json_object_new_object();
							staObj = json_object_new_object();
							json_object_object_add(staObj, WEVENT_TIMESTAMP,
								json_object_new_int64(ts));
							json_object_object_add(bandObj, ssap->sta[staCount].mac, staObj);
						}
						sp += hdrLen;
						staCount++;
					}
				}

				if (bandObj)
					json_object_object_add(brMacObj, ifAlias, bandObj);
			}
		}

		unit++;
	}

	root = json_object_new_object();
	if (root) {
		json_object_object_add(root, brMac, brMacObj);
		snprintf(msg, msg_len, "%s", json_object_to_json_string(root));
	}

	ret = 1;
	/* error/exit */
exit:

	if (root)
		json_object_put(root);
	else if (brMacObj)
		json_object_put(brMacObj);
	else if (bandObj)
		json_object_put(bandObj);

	return ret;
}

int wl_sta_rssi_list(json_object *root)
{
	char *sp, *op;
	char header[128], data[2048];
	struct iwreq wrq;
	int hdrLen, staCount=0, getLen;
	char header_t[128]={0};
	sta_entry *ssap;
	char rssinum[16]={0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	int unit = 0;
	char word[256], *next, ifAlias[16] = {0};
	json_object *bandObj = NULL, *staObj = NULL;
	int ret = 0, xTxR = 0, stream = 0, i = 0, added = 0, rssi_total = 0, sta_rssi = 0;
	int32 rssi_xR[xR_MAX] = {0};
	int pass_entry = 0;
	char pap[18] = {0};

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		bandObj = NULL;
		staCount = 0;
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
#ifdef RTCONFIG_AMAS
		if (nvram_get_int("re_mode") == 1) {
			memset(pap, 0, sizeof(pap));
			get_pap_bssid(unit, &pap[0], sizeof(pap));
		}
#endif

		if (!strlen(name))
			goto exit;

		if (!(xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp))))
			goto exit;

		if(xTxR > xR_MAX)
			xTxR = xR_MAX;

		memset(ifAlias, 0, sizeof(ifAlias));
		if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

		/* get MAC of station */
		memset(data, 0x00, sizeof(data));
		wrq.u.data.length = sizeof(data);
		wrq.u.data.pointer = (caddr_t) data;
		wrq.u.data.flags = ASUS_SUBCMD_GROAM;

		if (wl_ioctl(name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
			dbg("[%s]: WI[%s] Access to StaInfo failure\n", __FUNCTION__, name);
			goto exit;
		}

		memset(header, 0, sizeof(header));
		memset(header_t, 0, sizeof(header_t));
		hdrLen = snprintf(header_t, sizeof(header_t), "%-19s", "MAC");
		strlcpy(header, header_t, sizeof(header));

		for (stream = 0; stream < xR_MAX; stream++) {
			snprintf(rssinum, sizeof(rssinum), "RSSI%d", stream);
			memset(header_t, 0, sizeof(header_t));
			hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", rssinum);
			strncat(header, header_t, strlen(header_t));
		}
		hdrLen += snprintf(header_t, sizeof(header_t), "%-21s", "TxBytes");
		strncat(header, header_t, strlen(header_t));
		hdrLen += snprintf(header_t, sizeof(header_t), "%-21s", "RxBytes");
		strncat(header, header_t, strlen(header_t));
		hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "WnmCap");
		strncat(header, header_t, strlen(header_t));
		hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "BcnCap");
		strncat(header, header_t, strlen(header_t));
		strcat(header,"\n");
		hdrLen++;

		if (wrq.u.data.length > 0 && data[0] != 0) {
			getLen = strlen(wrq.u.data.pointer + hdrLen);

			ssap = (sta_entry *)(wrq.u.data.pointer + hdrLen);
			op = sp = wrq.u.data.pointer + hdrLen;
			while (*sp && ((getLen - (sp-op)) >= 0)) {
				pass_entry = 0;
				ssap->sta[staCount].mac[17]='\0';

				/* rssi */
				rssi_total = 0;
				for (stream = 0; stream < xR_MAX; stream++) {
					ssap->sta[staCount].rssi_xR[stream][6]='\0';
					rssi_xR[stream] = !atoi(ssap->sta[staCount].rssi_xR[stream]) ? -100 : atoi(ssap->sta[staCount].rssi_xR[stream]);
					if (stream < xTxR)
						rssi_total += rssi_xR[stream];
				}
				sta_rssi = rssi_total / xTxR ;

#ifdef RTCONFIG_AMAS
				if (nvram_get_int("re_mode") == 1 && strncmp(ssap->sta[staCount].mac, pap, sizeof(pap)-1) == 0)
					pass_entry = 1;
#endif
				if (!pass_entry && strlen(ssap->sta[staCount].mac)) {
					if (!bandObj)
						bandObj = json_object_new_object();

					if (bandObj) {
						staObj = json_object_new_object();
						if (bandObj) {
							json_object_object_add(staObj, CFG_STR_RSSI,
								json_object_new_int(sta_rssi));
							json_object_object_add(bandObj, ssap->sta[staCount].mac, staObj);
						}
					}
				}

				sp += hdrLen;
				staCount++;
			}
		}

		if (bandObj) {
			added = 1;
			json_object_object_add(root, ifAlias, bandObj);
		}

		for (i = 1; i < 4; i++) {
			bandObj = NULL;
			staCount = 0;
			memset(prefix, 0, sizeof(prefix));
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
			if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))  {
				snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
				name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

				if (!strlen(name))
					goto exit;

				memset(ifAlias, 0, sizeof(ifAlias));
				if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

				/* get MAC of station */
				memset(data, 0x00, sizeof(data));
				wrq.u.data.length = sizeof(data);
				wrq.u.data.pointer = (caddr_t) data;
				wrq.u.data.flags = ASUS_SUBCMD_GROAM;

				if (wl_ioctl(name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
					dbg("[%s]: WI[%s] Access to StaInfo failure\n", __FUNCTION__, name);
					goto exit;
				}

				if (wrq.u.data.length > 0 && data[0] != 0) {
					getLen = strlen(wrq.u.data.pointer + hdrLen);

					ssap = (sta_entry *)(wrq.u.data.pointer + hdrLen);
					op = sp = wrq.u.data.pointer + hdrLen;
					while (*sp && ((getLen - (sp-op)) >= 0)) {
						pass_entry = 0;
						ssap->sta[staCount].mac[17]='\0';

						/* rssi */
						rssi_total = 0;
						for (stream = 0; stream < xR_MAX; stream++) {
							ssap->sta[staCount].rssi_xR[stream][6]='\0';
							rssi_xR[stream] = !atoi(ssap->sta[staCount].rssi_xR[stream]) ? -100 : atoi(ssap->sta[staCount].rssi_xR[stream]);
							if (stream < xTxR)
								rssi_total += rssi_xR[stream];
						}
						sta_rssi = rssi_total / xTxR ;

#ifdef RTCONFIG_AMAS
						if (nvram_get_int("re_mode") == 1 && strncmp(ssap->sta[staCount].mac, pap, sizeof(pap)-1) == 0)
							pass_entry = 1;
#endif
						if (!pass_entry && strlen(ssap->sta[staCount].mac)) {
							if (!bandObj)
								bandObj = json_object_new_object();

							if (bandObj) {
								staObj = json_object_new_object();
								if (bandObj) {
									json_object_object_add(staObj, CFG_STR_RSSI,
										json_object_new_int(sta_rssi));
									json_object_object_add(bandObj, ssap->sta[staCount].mac, staObj);
								}
							}
						}

						sp += hdrLen;
						staCount++;
					}
				}

				if (bandObj) {
					added = 1;
					json_object_object_add(root, ifAlias, bandObj);
				}
			}
		}

		unit++;
	}

	ret = 1;
	/* error/exit */
exit:

	if (!added) {
		if (bandObj)
			json_object_put(bandObj);
	}

	return ret;
}

#if defined(RTCONFIG_RALINK_MT7621)
#define IDLE_CPU 2
void Set_CPU(void)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(IDLE_CPU, &cpuset);
	DBG_INFO("set cur_mask = %08lx", cpuset);
	sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}
#endif

char *get_sta_mac(int unit)
{
	char *aif;
	char *pMac;
	static char mac_buf[sizeof("00:00:00:00:00:00XXX")];

#if defined(RTCONFIG_RALINK_MT7620) || defined(RTCONFIG_RALINK_MT7621)
	if(unit == 0)
#else
	if(unit == 1)
#endif
		aif = "apcli0";
	else
		aif = "apclii0";

	memset(mac_buf, 0, sizeof(mac_buf));

	pMac = get_hwaddr(aif);
	if (pMac) {
		snprintf(mac_buf, sizeof(mac_buf), "%s", pMac);
		free(pMac);
		pMac = NULL;
	}

	return mac_buf;
}

void wl_control_channel(int unit, int *channel, int *bw, int *nctrlsb)
{
	char ifname[IFNAMSIZ];
	int ret __attribute__ ((unused));

	if (unit < 0 || unit >= MAX_NR_WL_IF)
		return;
	if (channel == NULL || bw == NULL || nctrlsb == NULL)
		return;

	__get_wlifname(unit, 0, ifname);

	ret = get_channel_info(ifname, channel, bw, nctrlsb);
}

void sync_control_channel(int unit, int channel, int bw, int nctrlsb)
{
	char ifname[IFNAMSIZ];
	int ret __attribute__ ((unused));

	if (unit < 0 || unit >= MAX_NR_WL_IF)
		return;

	__get_wlifname(unit, 0, ifname);
	ret = wl_set_ch_bw(ifname, channel, bw, nctrlsb);
}

int get_wsc_status(int *fail_result)
{

	int status = 0, ret = 0;
	status = atoi(nvram_safe_get("wps_proc_status"));

	switch (status) {
		case 1:
			*fail_result = OB_WPS_TIMEOUT_FAIL;
			break;
		case 34:		/* Configured */
			ret = 1;
			break;
		case 0x109:	/* PBC_SESSION_OVERLAP */
			*fail_result = OB_WPS_OVERLAP_FAIL;
			break;
		default:
			*fail_result = OB_WPS_UNKNOWN_FAIL;
			break;
	}

	return ret;
}

#if 0
void add_beacon_vsie(char *oui, char *hexdata)
{
}

void del_beacon_vsie(char *oui, char *hexdata)
{
}
#endif

int wl_get_chans_info(int unit, char* buf, size_t len)
{
	char *p;
	int ch_list[MAX_NRCHANNELS];
	int radar_list[MAX_NRCHANNELS];
	int ret = 0, ch_cnt = 0, radar_cnt = 0;
	int i = 0, j = 0;
	int ch_stat;

#ifdef AVBLCHAN
	int block_ch[MAX_NRCHANNELS], k, blk_cnt;
	char tmpch[256], *tmplist, *data, tmp[128];
	char prefix[]="wlxxxxxxxxx_";
	char *p_tmplist = NULL;
#endif

	if(buf == NULL || len <= 0)
		return -1;

	if(unit < 0) {
#ifdef SUPPORT_TRI_BAND
		unit = 2;
#else
		unit = 1;
#endif
	}

	if((ch_cnt = get_channel_list(unit, ch_list, MAX_NRCHANNELS)) < 0) {
		_dprintf("get_channel_list fail ret %d\n", ch_cnt);
		return ch_cnt;
	}

	if((radar_cnt = get_radar_channel_list(unit, radar_list, MAX_NRCHANNELS)) < 0) {
		_dprintf("get_radar_channel_list fail ret %d\n", radar_cnt);
		return radar_cnt;
	}

#ifdef AVBLCHAN
	blk_cnt=0;
	tmplist=NULL;
	memset(tmpch,0,sizeof(tmpch));
	memset(block_ch,0,sizeof(block_ch));
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(tmpch, nvram_safe_get(strcat_r(prefix, "block_ch", tmp)), sizeof(tmpch));
	p_tmplist = tmplist = strdup(tmpch);

	if (p_tmplist) {
		while (tmplist && (data = strsep(&tmplist,",")) != NULL) {
			block_ch[blk_cnt] = atoi(data);
			blk_cnt++;
		}
		free(p_tmplist);
	}
#endif

	// set version
	ret = snprintf(buf, len, "%d ", CHINFO_CMNFMT_V1);
	p = buf + ret;
	len -= ret;

	for(i = 0; i < ch_cnt && len > 0; i++) {
		for (j = 0; j < radar_cnt; j++) {
			if (ch_list[i] == radar_list[j]) {
				break;
			}
		}

#ifdef AVBLCHAN
		//according to countrycode, find block-channel and mark it as CHINFO_BLK
		for(k = 0; k < blk_cnt; k++) {
			if(ch_list[i]==block_ch[k])
				break;
		}
#endif

		if(j != radar_cnt
#ifdef AVBLCHAN
		  || k != blk_cnt
#endif
		)
			ch_stat = CHINFO_BLK;
		else
			ch_stat = CHINFO_AVBL;

		ret = snprintf(p, len, "%05u%03u ", ch_stat, ch_list[i]);
		p += ret;
		len -= ret;
	}

	return 0;
}

/*
 * int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
 *
 * chconf:
 * 	CHCONF_CH_MASK  0x00FF: center channel number
 * 	CHCONF_SB_MASK  0x0700: control channel location (shift number from first channel)
 * 	CHCONF_BW_MASK  0x7000: bandwidth information
 *
 */
int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
{
	int channel = 0, bw = 0, nctrlsb = 0;
	int centra_ch, base = 0;
	int ret;

	if (ifname == NULL || chconf == NULL)
		return -1;

	*chconf = 0;

	if ((ret = get_channel_info(ifname, &channel, &bw, &nctrlsb)) < 0) {
		_dprintf("%s: get_channel_info ret(%d)\n", __func__, ret);
		return ret;
	}

	switch (bw) {
		case 20:
			centra_ch = channel;
			nctrlsb = 0;
			CHCONF_BW_SET20(*chconf);
			break;
		case 40:
			centra_ch = channel + 2 - (nctrlsb << 2);
			CHCONF_BW_SET40(*chconf);
			break;
		case 80:
			base = (channel >= 149) ? 149 : 36;
			nctrlsb = ((channel - base) % 16) / 4;
			centra_ch = channel + 6 - (nctrlsb << 2);
			CHCONF_BW_SET80(*chconf);
			break;
		case 160:
			base = (channel >= 149) ? 149 : 36;
			nctrlsb = ((channel - base) % 32) / 4;
			centra_ch = channel + 14 - (nctrlsb << 2);
			CHCONF_BW_SET160(*chconf);
			break;
		default:
			_dprintf("%s: INVALID bw(%d)\n", bw);
			return -1;
	}

	CHCONF_CH_SET(*chconf, centra_ch);
	CHCONF_SB_SET(*chconf, (nctrlsb << CHCONF_SB_SHIFT));

	return 0;
}

int wl_set_ch_bw(const char *ifname, int channel, int bw, int nctrlsb)
{
	if (set_bw_nctrlsb(ifname, bw, nctrlsb) < 0) {
		DBG_ERR("set %s bw (%d) or nctrlsb (%d) failed", ifname, bw, nctrlsb);
		return -1;
	}

	if (set_channel(ifname, channel) < 0) {
		DBG_ERR("set %s channel (%d) failed", ifname, channel);
		return -1;
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

void wl_set_macfilter_mode(int allow)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *wlif_name;
	int val = 1;	/* allow mode */
	int unit = 0;
	struct iwreq wrq;
	char data[256];

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

		snprintf(data, sizeof(data), "AccessPolicy=%d", val);
		wrq.u.data.length = strlen(data) + 1;
		wrq.u.data.pointer = data;
		wrq.u.data.flags = 0;

		if (wl_ioctl(wlif_name, RTPRIV_IOCTL_SET, &wrq) < 0) {
			DBG_ERR("[%s] set AccessPolicy=%d failed", wlif_name, val);
		}
	}
}

#ifdef AVBLCHAN

typedef uint16_t chanspec_t;
int is_avbl(unsigned int unit, chanspec_t  c, chanspec_t *avbl2g, chanspec_t *avbl5g)
{
	int i=0, avbl=0;
	if(unit == 0) {
		for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
			if(avbl2g[i] == c) {
				avbl = 1;
				break;
			}
		}
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

void get_avb_ch(int unit,char *buf)
{
	char avb[800];
	char chList[256],*tmpch,*data,wlnvram[800], chStr[16];
	char prefix[]="wlxxxxx_",tmp[128],*var,*sp;
	char *p_tmpch = NULL;
	unsigned int block_ch_list[MAX_NRCHANNELS];
	int ch = 0, i = 0, block = 0, block_ch_count = 0;

	tmpch=NULL;
	memset(chList,0,sizeof(chList));
	memset(wlnvram,0,sizeof(wlnvram));
	memset(avb,0,sizeof(avb));
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	var = strcat_r(prefix, "block_ch", tmp);
	strlcpy(wlnvram, nvram_safe_get(var), sizeof(wlnvram));
	/* gen array for block channel list */
	memset(block_ch_list, 0, sizeof(block_ch_list));
	if (strlen(wlnvram) > 0) {
		p_tmpch = tmpch = strdup(wlnvram);
		if (p_tmpch) {
			while (tmpch && (data = strsep(&tmpch, ",")) != NULL) {
				if (strlen(data) == 0)
					continue;

				block_ch_list[block_ch_count] = atoi(data);
				block_ch_count++;
			}
			free(p_tmpch);
		}
	}

	get_channel_list_via_driver(unit, chList, sizeof(chList));
	p_tmpch = tmpch = strdup(chList);

	if (p_tmpch) {
		while(tmpch && (data= strsep(&tmpch,",")) != NULL)
		{
			if (strlen(data) == 0)
				continue;
			sp = avb;
			ch = atoi(data);
			block = 0;
			/* check channel is block or not */
			for (i = 0; i < block_ch_count; i++) {
				if (block_ch_list[i] == ch) {
					block = 1;
					break;
				}
			}

			if (!block) {
				if(strlen(avb) < sizeof(avb)) {
					if(strlen(sp) != 0)
						strlcat(avb, ",", sizeof(avb));
					strlcat(avb, data, sizeof(avb));
				} else
					DBG_INFO("error!! avb list is full!");
			}
		}
		free(p_tmpch);
	}
	memcpy(buf,avb,sizeof(avb));
}

void dump_avblchanspecs(chanspec_t *avbl2g, chanspec_t *avbl5g)
{
        int i=0;

        for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
                DBG_INFO("[%d]=(%d)", i, avbl2g[i]);
        }

        for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
                DBG_INFO("[%d]=(%d)", i, avbl5g[i]);
        }
}

int check_ch_in_unavbl(int cur_ch, char *unavbl_ch)
{
	unsigned int unavbl_ch_list[MAX_NRCHANNELS];
	int ret = 0, i = 0, unavbl_ch_count = 0;
	char *tmp_ch, *data;
	char *p_tmp_ch = NULL;

	memset(unavbl_ch_list, 0, sizeof(unavbl_ch_list));
	if (strlen(unavbl_ch) > 0) {
		p_tmp_ch = tmp_ch = strdup(unavbl_ch);
		if (p_tmp_ch) {
			while (tmp_ch && (data = strsep(&tmp_ch, ",")) != NULL) {
				if (strlen(data) == 0)
					continue;

				unavbl_ch_list[unavbl_ch_count] = atoi(data);
				unavbl_ch_count++;
			}
			free(p_tmp_ch);
		}
	}

	for (i = 0; i < unavbl_ch_count; i++) {
		if (unavbl_ch_list[i] == cur_ch) {
			ret = 1;
			break;
		}
	}

	return ret;
}

void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
	char avb[800];
	char chList[256],*tmplist,*data;
	int c = 0, cur_in_excl = 0, ret = 0, unit = -1;
	unsigned int i, tmpch;
	char word[256]={0}, *next = NULL, prefix[]="wlxxx", tmp[128], *sp;
	chanspec_t avblchanspec2g[MAX_2G_CHANNEL_LIST_NUM];
	chanspec_t avblchanspec5g[MAX_5G_CHANNEL_LIST_NUM];
	char unavbl_ch[128], *pre_unavbl_ch;
	//char *block_ch;
	int channel = 0, bw = 0, nctrlsb = 0;
	int exist5ghighch = 0;
	char *p_tmplist = NULL;

	if (!nvram_match("cfg_rejoin", "1") && !nvram_match("cfg_test", "1"))
		return;

	if (!nvram_match("wlready", "1")) {
		DBG_ERR("no chanspec chgact due wl not ready.");
		return;
	}
	memset(avblchanspec2g, 0, sizeof(avblchanspec2g));
	memset(avblchanspec5g, 0, sizeof(avblchanspec5g));

	for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList2g[i];
		if(tmpch > 0 && tmpch < 14)
			avblchanspec2g[i] = tmpch;
	}
#if 1
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
#else	
	/* checking 5g high channel exists in 5g available channel list */
	for (i = 0; i < MAX_5G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList5g[i];
		if (tmpch >= 100) {
			exist5ghighch = 1;
			break;
		}
	}

	for (i = 0; i < MAX_5G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList5g[i];
		if(supportedBandNum == 2 && exist5ghighch && (tmpch < 100)) // mask-off low band
			continue;

		if(tmpch > 14 && tmpch < 166)
			avblchanspec5g[i] = tmpch;
	}
#endif 
	dump_avblchanspecs(avblchanspec2g, avblchanspec5g);

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		c = 0;
		tmplist = NULL;
		memset(chList,0,sizeof(chList));
		memset(avb, 0, sizeof(avb));
		memset(unavbl_ch, 0, sizeof(unavbl_ch));
		if(!strcmp(word, WIF_2G))
			unit = 0;
		else if(!strcmp(word, WIF_5G))
			unit = 1;
#ifdef SUPPORT_TRI_BAND
		else if(!strcmp(word, WIF_5G2))
			unit = 2;
#endif
		else
		{
			unit=-1;
			continue;
		}

		get_avb_ch(unit, avb); //discard mask-channel according to countrycode
		p_tmplist = tmplist = strdup(avb);

		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		pre_unavbl_ch=nvram_safe_get(strcat_r(prefix, "unavbl_ch", tmp));
		//block_ch=nvram_safe_get(strcat_r(prefix, "block_ch", tmp));

		while(tmplist && (data= strsep(&tmplist,",")) != NULL)
		{
			c=atoi(data);
			sp = unavbl_ch;
			if(!is_avbl(unit, c, avblchanspec2g, avblchanspec5g))
			{
				if (!check_ch_in_unavbl(c, unavbl_ch)) {
					DBG_INFO("<%2x> is newly unavbl channel", c);
					if(strlen(unavbl_ch) < sizeof(unavbl_ch)) {
						if(strlen(sp) != 0)
							strlcat(unavbl_ch, ",", sizeof(unavbl_ch));
						strlcat(unavbl_ch, data, sizeof(unavbl_ch));
					} else
						DBG_INFO("unavbl_ch is full!");
				} else
					DBG_INFO("%d is avable", c);
			}
		}
		free(p_tmplist);
		nvram_set(strcat_r(prefix, "unavbl_ch", tmp), unavbl_ch);

		if ((ret = get_channel_info(word, &channel, &bw, &nctrlsb)) < 0) {
			DBG_ERR("get_channel_info ret(%d)", ret);
			return;
		}

		if (check_ch_in_unavbl(channel, unavbl_ch))	//switch to another channel, because it is unavbl ch.
			cur_in_excl = 1;
#if 0
		else
		{
			//dynamically adjust channels that are not available
			if(strcmp(pre_unavbl_ch,unavbl_ch)!=0)
			{
				//do nothing, acs will be executed after restart wireless
			}
		}
#endif
       }

	if (cur_in_excl) {
		DBG_INFO("Need to restart wireless due current chanspec is un-available");
		notify_rc("restart_wireless");
	}
}
#else
void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
	// do nothing
}
#endif

char *get_ssid(char *ifname, char *ssid_buf, int buf_len)
{
	struct iwreq wrq;
	char buffer[IW_ESSID_MAX_SIZE + 1];

	memset(buffer, 0, sizeof(buffer));
	memset(ssid_buf, 0, sizeof(ssid_buf));
	wrq.u.data.flags = 0;
	wrq.u.essid.pointer = (caddr_t) buffer;
	wrq.u.essid.length = sizeof(buffer);
	wrq.u.essid.flags = 0;

	if (wl_ioctl(ifname, SIOCGIWESSID, &wrq) < 0) {
                DBG_ERR("errors in getting SSID");
		return ssid_buf;
	}

	if (wrq.u.essid.length > 0)
		memcpy(ssid_buf, wrq.u.essid.pointer, buf_len);

	return ssid_buf;
}

char *get_pap_ssid(int unit, char *ssid_buf, int buf_len)
{
	return get_ssid(get_staifname(unit), ssid_buf, buf_len);
}

char *get_ap_ssid(int unit, char *ssid_buf, int buf_len)
{
	char ifname[8];

	__get_wlifname(unit, 0, ifname);

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
	// TODO
	int model = get_model();
	int result = 0;

	switch (model) {
#if defined(TUFAX4200) || defined(AX6000)
		case MODEL_TUFAX4200:	// fall-through
		case MODEL_TUFAX6000:
			if (!strcmp("eth1", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "2.5G", 0);
			break;
#endif
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
	DBG_INFO("enter");
	// Do Noting
	DBG_INFO("leave");
	return 1;
}
