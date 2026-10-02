#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shared.h>
#include <wlioctl.h>
#include <bcmnvram.h>
#include <bcmendian.h>
#include <shutils.h>
#include <wlutils.h>
#include <bcmwifi_channels.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_wevent.h"
#include "chmgmt.h"
#include "cfg_slavelist.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#ifdef RTCONFIG_HND_ROUTER_AX
#include <wlc_types.h>
#endif
#include <sys/ioctl.h>
#include <net/if_arp.h>

#define ETHER_ADDR_STR_LEN	18
#define	MAX_STA_COUNT	128

#if defined(RTCONFIG_WIFI6E) || defined(RTCONFIG_HND_ROUTER_AX_6756) || defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
#if defined(RTCONFIG_SDK502L07P1_121_37)
#define CHANNELSPEC_V1	/* SDK5072L07P1_121_37 */
#else
#define CHANNELSPEC_V2	/* new SDK */
#endif
#else
#define CHANNELSPEC_V1	/* other */
#endif

static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh16(i) (g_swap?bcmswap16(i):(uint16)(i))

static int _wl_get_chanspec(char* ifname, chanspec_t* chanspec);

char *get_pap_bssid(int unit, char *bssid_buf, int buf_len)
{
	unsigned char bssid[6] = {0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	static char bssid_str[sizeof("00:00:00:00:00:00XXX")];

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	memset(bssid_str, 0, sizeof(bssid_str));
	if (wl_ioctl(name, WLC_GET_BSSID, bssid, sizeof(bssid)) == 0) {
		if ( !(!bssid[0] && !bssid[1] && !bssid[2] && !bssid[3] && !bssid[4] && !bssid[5]) ) {
			snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
				(unsigned char)bssid[0], (unsigned char)bssid[1],
				(unsigned char)bssid[2], (unsigned char)bssid[3],
				(unsigned char)bssid[4], (unsigned char)bssid[5]);
		}
	}

	return bssid_str;
}

int get_pap_rssi(int unit)
{
	char tmp[256], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	char word[256], *next;
	int unit_max = 0, unit_cur = -1;
	char *mode = NULL;
	int sta = 0, wet = 0, psta = 0, psr = 0;
	int rssi = 0, ret;

	foreach (word, nvram_safe_get("wl_ifnames"), next)
		unit_max++;

	if (unit > (unit_max - 1))
		goto ERROR;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
	mode = nvram_safe_get(strcat_r(prefix, "mode", tmp));
	sta = !strcmp(mode, "sta");
	wet = !strcmp(mode, "wet");
	psta = !strcmp(mode, "psta");
	psr = !strcmp(mode, "psr");

	if (wet || sta || psta || psr) {
		ret = wl_ioctl(name, WLC_GET_RSSI, &rssi, sizeof(rssi));
		if (ret < 0)
			DBG_ERR("Err: reading intf:%s RSSI", name);
	}

	wl_ioctl(name, WLC_GET_INSTANCE, &unit_cur, sizeof(unit_cur));
	if (unit != unit_cur)
		goto ERROR;
	else if (!(wet || sta || psta || psr))
		goto ERROR;
	else if (wl_ioctl(name, WLC_GET_RSSI, &rssi, sizeof(rssi))) {
		DBG_ERR("can not get rssi info of %s", name);
		goto ERROR;
	} else {
		rssi = dtoh32(rssi);
	}

ERROR:

	return rssi;
}

sta_info_t *wl_sta_info(char *ifname, struct ether_addr *ea)
{
	static char buf[sizeof(sta_info_t)];
	sta_info_t *sta = NULL;

	strcpy(buf, "sta_info");
	memcpy(buf + strlen(buf) + 1, (void *)ea, ETHER_ADDR_LEN);

	if (!wl_ioctl(ifname, WLC_GET_VAR, buf, sizeof(buf))) {
		sta = (sta_info_t *)buf;
		sta->ver = dtoh16(sta->ver);

		/* Report unrecognized version */
		if (sta->ver > WL_STA_VER) {
			DBG_ERR("ERROR: unknown driver station info version %d", sta->ver);
			return NULL;
		}

		sta->len = dtoh16(sta->len);
		sta->cap = dtoh16(sta->cap);
#ifdef RTCONFIG_BCMARM
		sta->aid = dtoh16(sta->aid);
#endif
		sta->flags = dtoh32(sta->flags);
		sta->idle = dtoh32(sta->idle);
		sta->rateset.count = dtoh32(sta->rateset.count);
		sta->in = dtoh32(sta->in);
		sta->listen_interval_inms = dtoh32(sta->listen_interval_inms);
#ifdef RTCONFIG_BCMARM
		sta->ht_capabilities = dtoh16(sta->ht_capabilities);
		sta->vht_flags = dtoh16(sta->vht_flags);
#endif
	}

	return sta;
}

int wl_sta_list(char *msg, int msg_len)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	struct maclist *auth = NULL;
	int mac_list_size;
	int i;
	char ea[ETHER_ADDR_STR_LEN];
	char name_vif[] = "wlX.Y_XXXXXXXXXX";
	int ii;
	sta_info_t *sta;
	int unit = 0;
	int unit_in = 0;
	char word[256], *next;
	char word_in[256], *next_in;
	char brMac[32] = {0};
	char ifAlias[16] = {0};
	json_object *root = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int ret = 0;
	time_t ts;
	char pap[18] = {0};
	int pass_entry = 0;

	time(&ts);

	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	brMacObj = json_object_new_object();

	if (!brMacObj) {
		DBG_ERR("brMacObj is NULL");
		return 0;
	}

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		bandObj = NULL;
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

#ifdef RTCONFIG_WIRELESSREPEATER
		if ((sw_mode() == SW_MODE_REPEATER)
			&& (nvram_get_int("wlc_band") == unit))
		{
			memset(name_vif, 0, sizeof(name_vif));
			snprintf(name_vif, sizeof(name_vif), "wl%d.%d", unit, 1);
			name = name_vif;
		}
#endif

		if (!strlen(name)) {
			DBG_ERR("can't get ifname");
			goto exit;
		}

		/* buffers and length */
		mac_list_size = sizeof(auth->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
		auth = malloc(mac_list_size);

		if (!auth) {
			DBG_ERR("auth is NULL");
			goto exit;
		}

		memset(auth, 0, mac_list_size);

		/* query wl for authenticated sta list */
		strcpy((char*)auth, "authe_sta_list");
		if (wl_ioctl(name, WLC_GET_VAR, auth, mac_list_size)) {
			DBG_ERR("can not get authe sta list of %s", name);
			goto exit;
		}

		memset(ifAlias, 0, sizeof(ifAlias));
		if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

		/* build authenticated sta list */
		for (i = 0; i < auth->count; ++i) {
			sta = wl_sta_info(name, &auth->ea[i]);
			if (!sta) continue;
			if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

			ether_etoa((void *)&auth->ea[i], ea);

			/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
			unit_in = 0;
			pass_entry = 0;
			foreach (word_in, nvram_safe_get("wl_ifnames"), next_in) {
				SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
				if (!strcmp(ea, get_pap_bssid(unit_in, &pap[0], sizeof(pap)))) {
					pass_entry = 1;
					break;
				}
				unit_in++;
			}

			if (pass_entry) continue;
#endif

			if (!bandObj)
				bandObj = json_object_new_object();

			if (bandObj) {
				staObj = json_object_new_object();

				if (staObj) {
					json_object_object_add(staObj, WEVENT_TIMESTAMP,
						json_object_new_int64(ts));
					json_object_object_add(bandObj, ea, staObj);
				}
			}
		}

		if (bandObj)
			json_object_object_add(brMacObj, ifAlias, bandObj);

		for (i = 1; i <= num_of_mssid_support(unit); i++) {
			bandObj = NULL;
#ifdef RTCONFIG_WIRELESSREPEATER
			if ((sw_mode() == SW_MODE_REPEATER)
				&& (unit == nvram_get_int("wlc_band")) && (i == 1))
				break;
#endif
			memset(prefix, 0, sizeof(prefix));
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
			if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
			{
				memset(name_vif, 0, sizeof(name_vif));
				snprintf(name_vif, sizeof(name_vif), "wl%d.%d", unit, i);

				memset(auth, 0, mac_list_size);

				memset(ifAlias, 0, sizeof(ifAlias));
       		 		if_nametoalias(name_vif, &ifAlias[0], sizeof(ifAlias));

				/* query wl for authenticated sta list */
				strcpy((char*)auth, "authe_sta_list");
				if (wl_ioctl(name_vif, WLC_GET_VAR, auth, mac_list_size)) {
					DBG_ERR("can not get authe sta list of %s", name_vif);
					goto exit;
				}

				for (ii = 0; ii < auth->count; ii++) {
					sta = wl_sta_info(name_vif, &auth->ea[ii]);
					if (!sta) continue;
					if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

					ether_etoa((void *)&auth->ea[ii], ea);

					/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					unit_in = 0;
					pass_entry = 0;
					foreach (word_in, nvram_safe_get("wl_ifnames"), next_in) {
						SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
						if (!strcmp(ea, get_pap_bssid(unit_in, &pap[0], sizeof(pap)))) {
							pass_entry = 1;
							break;
						}
						unit_in++;
					}

					if (pass_entry) continue;
#endif

					if (!bandObj)
						bandObj = json_object_new_object();

					if (bandObj) {
						staObj = json_object_new_object();
						if (staObj) {
							json_object_object_add(staObj, WEVENT_TIMESTAMP,
								json_object_new_int64(ts));
							json_object_object_add(bandObj, ea, staObj);
						}
					}
				}

				if (bandObj)
					json_object_object_add(brMacObj, ifAlias, bandObj);
			}
		}

		if (auth) {
			free(auth);
			auth = NULL;
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

	if (auth) free(auth);

	return ret;
}

int wl_sta_rssi_list(json_object *root)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	struct maclist *auth = NULL;
	int mac_list_size;
	int i;
	char ea[ETHER_ADDR_STR_LEN];
	char name_vif[] = "wlX.Y_XXXXXXXXXX";
	int ii;
	sta_info_t *sta;
	int unit = 0;
	int unit_in = 0;
	char word[256], *next;
	char word_in[256], *next_in;
	char ifAlias[16] = {0};
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int ret = 0;
	char pap[18] = {0};
	int pass_entry = 0;
	int added = 0;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		scb_val_t scb_val;
		int rssi;

		bandObj = NULL;
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

#ifdef RTCONFIG_WIRELESSREPEATER
		if ((sw_mode() == SW_MODE_REPEATER)
			&& (nvram_get_int("wlc_band") == unit))
		{
			memset(name_vif, 0, sizeof(name_vif));
			snprintf(name_vif, sizeof(name_vif), "wl%d.%d", unit, 1);
			name = name_vif;
		}
#endif

		if (!strlen(name)) {
			DBG_ERR("can't get ifname");
			goto exit;
		}

		/* buffers and length */
		mac_list_size = sizeof(auth->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
		auth = malloc(mac_list_size);

		if (!auth)
			goto exit;

		memset(auth, 0, mac_list_size);

		/* query wl for authenticated sta list */
		strcpy((char*)auth, "authe_sta_list");
		if (wl_ioctl(name, WLC_GET_VAR, auth, mac_list_size)) {
			DBG_ERR("can not get authe sta list of %s", name);
			goto exit;
		}

		memset(ifAlias, 0, sizeof(ifAlias));
		if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

		/* build authenticated sta list */
		for (i = 0; i < auth->count; ++i) {
			sta = wl_sta_info(name, &auth->ea[i]);
			if (!sta) continue;
			if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

			ether_etoa((void *)&auth->ea[i], ea);

			/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
			unit_in = 0;
			pass_entry = 0;
			foreach (word_in, nvram_safe_get("wl_ifnames"), next_in) {
				SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
				if (!strcmp(ea, get_pap_bssid(unit_in, &pap[0], sizeof(pap)))) {
					pass_entry = 1;
					break;
				}
				unit_in++;
			}

			if (pass_entry) continue;
#endif

			memcpy(&scb_val.ea, &auth->ea[i], ETHER_ADDR_LEN);
			if (wl_ioctl(name, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t)))
				rssi = 0;
			else
				rssi =  scb_val.val;

			if (!bandObj)
				bandObj = json_object_new_object();

			if (bandObj) {
				staObj = json_object_new_object();

				if (staObj) {
					json_object_object_add(staObj, CFG_STR_RSSI,
						json_object_new_int(rssi));
					json_object_object_add(bandObj, ea, staObj);
				}
			}
		}

		if (bandObj) {
			added = 1;
			json_object_object_add(root, ifAlias, bandObj);
		}

		for (i = 1; i <= num_of_mssid_support(unit); i++) {
			bandObj = NULL;
#ifdef RTCONFIG_WIRELESSREPEATER
			if ((sw_mode() == SW_MODE_REPEATER)
				&& (unit == nvram_get_int("wlc_band")) && (i == 1))
				break;
#endif
			memset(prefix, 0, sizeof(prefix));
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
			if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
			{
				memset(name_vif, 0, sizeof(name_vif));
				snprintf(name_vif, sizeof(name_vif), "wl%d.%d", unit, i);

				memset(auth, 0, mac_list_size);

				memset(ifAlias, 0, sizeof(ifAlias));
				if_nametoalias(name_vif, &ifAlias[0], sizeof(ifAlias));

				/* query wl for authenticated sta list */
				strcpy((char*)auth, "authe_sta_list");
				if (wl_ioctl(name_vif, WLC_GET_VAR, auth, mac_list_size)) {
					DBG_ERR("can not get authe sta list of %s", name_vif);
					goto exit;
				}

				for (ii = 0; ii < auth->count; ii++) {
					sta = wl_sta_info(name_vif, &auth->ea[ii]);
					if (!sta) continue;
					if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

					ether_etoa((void *)&auth->ea[ii], ea);

					/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
					unit_in = 0;
					pass_entry = 0;
					foreach (word_in, nvram_safe_get("wl_ifnames"), next_in) {
						SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
						if (!strcmp(ea, get_pap_bssid(unit_in, &pap[0], sizeof(pap)))) {
							pass_entry = 1;
							break;
						}
						unit_in++;
					}

					if (pass_entry) continue;
#endif

					memcpy(&scb_val.ea, &auth->ea[ii], ETHER_ADDR_LEN);
					if (wl_ioctl(name_vif, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t)))
						rssi = 0;
					else
						rssi =  scb_val.val;

					if (!bandObj)
						bandObj = json_object_new_object();

					if (bandObj) {
						staObj = json_object_new_object();

						if (staObj) {
							json_object_object_add(staObj, CFG_STR_RSSI,
								json_object_new_int(rssi));
							json_object_object_add(bandObj, ea, staObj);
						}
					}
				}

				if (bandObj) {
					added = 1;
					json_object_object_add(root, ifAlias, bandObj);
				}
			}
		}

		if (auth) {
			free(auth);
			auth = NULL;
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

	if (auth) free(auth);

	return ret;
}

char *get_sta_mac(int unit)
{
	char *aif;
	char *pMac;
        char tmp[256], prefix[] = "wlXXXXXXXXXX_";
	char *mode = NULL;
	int sta = 0, wet = 0, psta = 0, psr = 0;
	static char mac_buf[sizeof("00:00:00:00:00:00XXX")];

        snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	aif = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
	mode = nvram_safe_get(strcat_r(prefix, "mode", tmp));
	sta = !strcmp(mode, "sta");
	wet = !strcmp(mode, "wet");
	psta = !strcmp(mode, "psta");
	psr = !strcmp(mode, "psr");

        if (wet || sta || psta || psr) {
		memset(mac_buf, 0, sizeof(mac_buf));

		pMac = get_hwaddr(aif);
		if (pMac) {
			snprintf(mac_buf, sizeof(mac_buf), "%s", pMac);
			free(pMac);
			pMac = NULL;
		}
        }

	return mac_buf;
}

void wl_control_channel(int unit, int *channel, int *bw, int *nctrlsb)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	chanspec_t chanspec = 0;

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	if (dpsr_mode()
#ifdef RTCONFIG_DPSTA
		|| dpsta_mode()
#endif
	)
		snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	else
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (_wl_get_chanspec(name, &chanspec) < 0) {
		DBG_ERR("get chanspec failed on %s", name);
		return;
	}
	
	if (wf_chspec_valid(chanspec)) {
		*channel = wf_chspec_ctlchan(chanspec);
		if (CHSPEC_IS20(chanspec))
			*bw = 20;
		else if (CHSPEC_IS40(chanspec)) {
			*bw = 40;
			if (CHSPEC_SB_UPPER(chanspec))
				*nctrlsb = 1;
		}
		else if (CHSPEC_IS80(chanspec))
			*bw = 80;
#if defined(RTCONFIG_HND_ROUTER_AX) || defined(RTCONFIG_BW160M)
		else if (CHSPEC_IS160(chanspec))
			*bw = 160;
#endif
	}
}

void sync_control_channel(int unit, int channel, int bw, int nctrlsb)
{
	char *ifname = NULL;
	char tmp[128], prefix[sizeof("wlXXXXX_")], wl_prefix[sizeof("wlXXXXX_")];
#ifdef RTCONFIG_BCMWL6
	char chanspec_str[16] = {0};
	char buf[WLC_IOCTL_MAXLEN] = {0};
	chanspec_t c;
#else
	char channel_str[16] = {0};
#endif
	int nband = 0;

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	if (dpsr_mode()
#ifdef RTCONFIG_DPSTA
		|| dpsta_mode()
#endif
	)
		snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	else
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
	nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));

#ifdef RTCONFIG_BCMWL6
	if (bw == 20) {
		if (nband == 4)
			snprintf(chanspec_str, sizeof(chanspec_str), "6g%d", channel);
		else
			snprintf(chanspec_str, sizeof(chanspec_str), "%d", channel);
	}
	else if (bw == 40) {
		if (nband == 4)
			snprintf(chanspec_str, sizeof(chanspec_str), "6g%d/40", channel);
		else
			snprintf(chanspec_str, sizeof(chanspec_str), "%d%s", channel, nctrlsb ? "u" : "l");
	}
	else if (bw == 80) {
		if (nband == 4)
			snprintf(chanspec_str, sizeof(chanspec_str), "6g%d/80", channel);
		else
			snprintf(chanspec_str, sizeof(chanspec_str), "%d/80", channel);
	}
#if defined(RTCONFIG_HND_ROUTER_AX) || defined(RTCONFIG_BW160M)
	else if (bw == 160) {
		if (nband == 4)
			snprintf(chanspec_str, sizeof(chanspec_str), "6g%d/160", channel);
		else
			snprintf(chanspec_str, sizeof(chanspec_str), "%d/160", channel);
	}
#endif
	c = wf_chspec_aton(chanspec_str);
	strlcpy(buf, "chanspec", sizeof(buf));
	memcpy(buf + strlen(buf) + 1, (void *)&c, sizeof(chanspec_t));
	wl_ioctl(ifname, WLC_SET_VAR, buf, sizeof(buf));
#else
	snprintf(channel_str, sizeof(channel_str), "%d", channel);
	eval("wl", "-i", ifname, "channel", chanspec_str);
#endif
	wl_iovar_setint(ifname, "acs_update", -1);
}

int get_wsc_status(int *fail_result)
{
	char *status = nvram_safe_get("wps_proc_status");
	int ret = 0;

	switch (atoi(status)) {
		case 2: /* WPS_OK */
		case 7: /* WPS_MSGDONE */
			ret = 1;
			break;
		case 3: /* WPS_MSG_ERR */
			*fail_result = OB_WPS_UNKNOWN_FAIL;
			break;
		case 0: /* WPS_TIMEOUT w/o starting state machine */
		case 4: /* WPS_TIMEOUT w/ starting state machine*/
			*fail_result = OB_WPS_TIMEOUT_FAIL;
			break;
		case 8: /* WPS_PBCOVERLAP */
			*fail_result = OB_WPS_OVERLAP_FAIL;
			break;
		default:
			*fail_result = OB_WPS_UNKNOWN_FAIL;
			ret = -1;
			break;
	}

	return ret;
}

#if 0
void add_beacon_vsie(char *oui, char *hexdata)
{
	char cmd[300] = {0};
	//Bit 0 - Beacons, Bit 1 - Probe Rsp, Bit 2 - Assoc/Reassoc Rsp
	//Bit 3 - Auth Rsp, Bit 4 - Probe Req, Bit 5 - Assoc/Reassoc Req
	int pktflag = 0x3;
	int len = 0;
	unsigned char hexOui[3] = {0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *ifname = NULL;

	len = 3 + strlen(hexdata)/2;	/* 3 is oui's len */

	if (strlen(oui)/2 > sizeof(hexOui))
		dbg("the length of oui is over hexOui");

	str2hex(oui, hexOui, strlen(oui));

	if (is_router_mode() || access_point_mode())
		snprintf(prefix, sizeof(prefix), "wl0_");
	else
		snprintf(prefix, sizeof(prefix), "wl0.1_");

	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "wl -i %s add_ie %d %d %02X:%02X:%02X %s",
			ifname, pktflag, len, hexOui[0], hexOui[1], hexOui[2], hexdata);
		system(cmd);
	}
}

void del_beacon_vsie(char *oui, char *hexdata)
{
	char cmd[300] = {0};
	int pktflag = 0x3;
	int len = 0;
	unsigned char hexOui[3] = {0};
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *ifname = NULL;

	len = 3 + strlen(hexdata)/2;	/* 3 is oui's len */

	if (strlen(oui)/2 > sizeof(hexOui))
		dbg("the length of oui is over hexOui");

	str2hex(oui, hexOui, strlen(oui));

	if (is_router_mode() || access_point_mode())
		snprintf(prefix, sizeof(prefix), "wl0_");
	else
		snprintf(prefix, sizeof(prefix), "wl0.1_");

	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "wl -i %s del_ie %d %d %02X:%02X:%02X %s",
			ifname, pktflag, len, hexOui[0], hexOui[1], hexOui[2], hexdata);
		system(cmd);
	}
}
#endif

static int _wl_chan_info(char *ifname, int nband, uint32_t* chan_info, size_t n)
{
	union ioval_u {
		char buf[WLC_IOCTL_MAXLEN];
		uint32_t val;
	} u;
	int i, last;
	uint32_t chanspec_arg;
	uint32_t bitmap;

	if(n < MAXCHANNEL)
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
#ifdef RTCONFIG_WIFI6E
		if (nband == 4)
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
			chanspec_arg = CH20MHZ_CHSPEC(i, WL_CHANSPEC_BAND_6G);
#else
			chanspec_arg = CH20MHZ_CHSPEC2(i, WL_CHANSPEC_BAND_6G);
#endif
		else
#endif
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
			chanspec_arg = CH20MHZ_CHSPEC(i, WL_CHANNEL_2G5G_BAND(i));
#else
			chanspec_arg = CH20MHZ_CHSPEC(i);
#endif
		memcpy(u.buf + strlen(u.buf) + 1, (void *)&chanspec_arg, sizeof(chanspec_arg));

		if(wl_ioctl(ifname, WLC_GET_VAR, u.buf, sizeof(u.buf)) < 0)
		{
			return (-1);
		}

		bitmap = dtoh32(u.val);

		if (!(bitmap & WL_CHAN_VALID_HW))
		{
			//printf("Channel %d Invalid\n", i);
			continue;
		}

		if (!(bitmap & WL_CHAN_VALID_SW))
		{
			//printf("Channel %d Not supported in current locale\n", i);
			continue;
		}

		*(chan_info + i) = bitmap;
	}

	return (0);
}

//transfer to string format: SSSSSCCC
int wl_get_chans_info(int unit, char* buf, size_t len)
{
	char ifname[IFNAMSIZ];
	uint32_t chan_info[MAXCHANNEL] = {0};
	int i;
	char cmnfmt[16];
	char prefix[16] = {0};
	char tmp[64] = {0};
	char word[256], *next, wl_ifnames[64], amas_wlc_prefix[sizeof("amas_wlcXXXX_")];
	int nband = 0;

	if (unit >= 0) {
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
		nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
	}
	else
	{
	//TODO: how to get working uplink interface
#if 0
#ifdef SUPPORT_TRI_BAND
		strlcpy(ifname, nvram_safe_get("wl2_ifname"), sizeof(ifname));
#else
		strlcpy(ifname, nvram_safe_get("wl1_ifname"), sizeof(ifname));
#endif
#endif
		strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
		i = 0;
		if (nvram_get_int("re_mode") == 1) {
			/* get 5g uplink interface */
			foreach (word, wl_ifnames, next) {
				SKIP_ABSENT_BAND_AND_INC_UNIT(i);
				snprintf(prefix, sizeof(prefix), "wl%d_", i);
				snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(i));
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				if (nvram_get_int(strcat_r(amas_wlc_prefix, "use", tmp)) && nband == 1) {
					strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
					break;
				}

				i++;
			}
		}
		else
		{
			foreach (word, wl_ifnames, next) {
				SKIP_ABSENT_BAND_AND_INC_UNIT(i);
				snprintf(prefix, sizeof(prefix), "wl%d_", i);
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				if (nband == 1)
					strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
				i++;
			}
		}

		nband = 1;
	}

	if(_wl_chan_info(ifname, nband, chan_info, sizeof(chan_info)) < 0)
		return (-1);

	memset(buf, 0, len);
	//v1
	snprintf(cmnfmt, sizeof(cmnfmt), "%d ", CHINFO_CMNFMT_V1);
	strlcat(buf, cmnfmt, len);
	for(i=0; i<MAXCHANNEL; i++)
	{
		if(chan_info[i])
		{
			if (chan_info[i] & WL_CHAN_INACTIVE)
			{
				snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_BLK, i);
				strlcat(buf, cmnfmt, len);
			}
			else if (chan_info[i] & WL_CHAN_PASSIVE)
			{
				snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_UAVL, i);
				strlcat(buf, cmnfmt, len);
			}
			else if (chan_info[i] & WL_CHAN_RADAR)
			{
				snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_AVBL, i);
				strlcat(buf, cmnfmt, len);
			}
			else if (chan_info[i] & WL_CHAN_BAND_5G)
			{
				snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_5G, i);
				strlcat(buf, cmnfmt, len);
			}
			else
			{
				snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_2G, i);
				strlcat(buf, cmnfmt, len);
			}
		}
	}

	return (0);
}

static int _wl_get_chanspec(char* ifname, chanspec_t* chanspec)
{
	union ioval_u {
		char buf[WLC_IOCTL_MAXLEN];
		uint32_t val;
	} u;

	strlcpy(u.buf, "chanspec", sizeof(u.buf));
	if(wl_ioctl(ifname, WLC_GET_VAR, u.buf, sizeof(u.buf)) < 0)
	{
		return (-1);
	}

	*chanspec = (chanspec_t)dtoh32(u.val);

	return (0);
}

static int _wl_set_chanspec(char* ifname, chanspec_t chanspec)
{
	char buf[WLC_IOCTL_MAXLEN] = {0};

	strlcpy(buf, "chanspec", sizeof(buf));
	memcpy(buf + strlen(buf) + 1, (void *)&chanspec, sizeof(chanspec_t));

	return (wl_ioctl(ifname, WLC_SET_VAR, buf, sizeof(buf)));
}

int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
{
	chanspec_t chanspec = 0;
	char itf[IFNAMSIZ];

	strlcpy(itf, ifname, sizeof(itf));
	if(_wl_get_chanspec(itf, &chanspec) < 0)
	{
		return (-1);
	}

	CHCONF_CH_SET(*chconf, chanspec);
	CHCONF_SB_SET(*chconf, (CHSPEC_CTL_SB(chanspec)>>WL_CHANSPEC_CTL_SB_SHIFT)<<CHCONF_SB_SHIFT);
	if(CHSPEC_IS20(chanspec))
		CHCONF_BW_SET20(*chconf);
	else if(CHSPEC_IS40(chanspec))
		CHCONF_BW_SET40(*chconf);
	else if(CHSPEC_IS80(chanspec))
		CHCONF_BW_SET80(*chconf);
	else if(CHSPEC_IS160(chanspec))
		CHCONF_BW_SET160(*chconf);

	return (0);
}

int wl_set_chconf(const char *ifname, chmgmt_chconf_t chconf)
{
	char itf[IFNAMSIZ];
	char chbw[16]={0};
	chanspec_t chanspec = 0;

	strlcpy(itf, ifname, sizeof(itf));

	snprintf(chbw, sizeof(chbw), "%d/%d", chmgmt_get_ctl_ch(chconf),  chmgmt_get_bw(chconf));
	chanspec = wf_chspec_aton(chbw);

	wl_iovar_setint(itf, "chanspec", (uint32)chanspec);
	wl_iovar_setint(itf, "acs_update", -1);

	return (0);
}

void wl_set_macfilter_list()
{
#ifdef BCM_BSD
	/* avoid bsd to change maclist */
	if (nvram_get_int("smart_connect_x") && wl_macfilter_is_allow_mode()) {
		if (pids("bsd")) {
			DBG_INFO("stop the daemon of smart connect");
			notify_rc("stop_bsd");
		}
	}
#endif

	update_macfilter_relist();

	if (wl_macfilter_is_allow_mode() && pids("roamast")) {
		DBG_INFO("restart roamast");
		notify_rc("restart_roamast");
	}

#ifdef BCM_BSD
	/* avoid bsd to change maclist */
	if (nvram_get_int("smart_connect_x") && wl_macfilter_is_allow_mode()) {
		if (!pids("bsd")) {
			DBG_INFO("restart the daemon of smart connect");
			notify_rc("start_bsd");
		}
	}
#endif
}

void wl_set_macfilter_mode(int allow)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *wlif_name = NULL;
	int ret = 0;
	int val = 2;	/* allow mode */
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

		ret = wl_ioctl(wlif_name, WLC_SET_MACMODE, &val, sizeof(val));
		if(ret < 0)
			DBG_ERR("[%s] set macmode failed", wlif_name);
	}
}

#ifdef AVBLCHAN

int is_avbl(unsigned int band_type, chanspec_t c, chanspec_t *avbl2g, chanspec_t *avbl5g, chanspec_t *avbl6g) 
{
	int i=0, avbl=0;

	if(band_type == WLC_BAND_2G) {
		for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
			if(avbl2g[i] == c) {
				avbl = 1;
				break;
			}
		}
		/* skip 2/4G 40MHz chanspecs */
		if(i == MAX_2G_CHANNEL_LIST_NUM && ((c&0x0800) || (c&0x0900)==0x0900))
				avbl = 1;
	} else if(band_type == WLC_BAND_5G) {
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM*4; ++i) {
			if(avbl5g[i] == c) {
				avbl = 1;
			}
		}
#ifdef RTCONFIG_WIFI6E
	} else if(band_type == WLC_BAND_6G) {
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM*4; ++i) {
			if(avbl5g[i] == c) {
				avbl = 1;
			}
		}
#endif
	}

	return avbl;
}

void dump_avblchanspecs(chanspec_t *avbl2g, chanspec_t *avbl5g, chanspec_t *avbl6g) 
{
	int i=0;
	char chan[20], buf[200];
	int n=0;

	if(!nvram_match("cfg_abl", "1"))
		return;

	DBG_ABL("> Go dump:%s\n", __func__);

	//if(nvram_match("cfg_syslog", "1")) {
		DBG_ABL("<%s> dump avbl 2g:\n", __func__);
		n = MAX_2G_CHANNEL_LIST_NUM;
		for(i=0; i<n; ++i) {
			sprintf(chan, "[%d]=(%2x) ", i, avbl2g[i]);
			if(!(i%10)) {
				memset(buf, 0, sizeof(buf));
			}
			memcpy(buf+strlen(buf), chan, strlen(chan));

			if(i && !(i%9) || (i==n-1)) {
				DBG_ABL(">> %s <<\n", buf);
			}
		}

		DBG_ABL("\n<%s> dump avbl 5g:\n", __func__);
		n = MAX_5G_CHANNEL_LIST_NUM*4;
		for(i=0; i<n; ++i) {
			sprintf(chan, "[%d]=(%2x) ", i, avbl5g[i]);
			if(!(i%10)) {
				memset(buf, 0, sizeof(buf));
			}
			memcpy(buf+strlen(buf), chan, strlen(chan));

			if(i && !(i%9) || (i==n-1)) {
				DBG_ABL(">> %s <<\n", buf);
			}
		}
	//} 
/*
	{
		_dprintf("dump avbl to console:\nAvbl 2g:\n");
		for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
			_dprintf("%2x, ", avbl2g[i]);
			if(!(i%10)) 
				_dprintf("\n");
		}

		_dprintf("\nAvbl 5g:\n");
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM*4; ++i) {
			_dprintf("%2x, ", avbl5g[i]);
			if(!(i%10)) 
				_dprintf("\n");
		}
		_dprintf("\n");
	}
*/
}

#define MAXCHANSPECS_NUM	25

void adjust_excl(char *nv, int size)
{
	char *src = nv;
	char *end = nv + strnlen(nv, size);

	while (src < end && strchr(", ", *src))
		src++;
	if (src > nv) {
		memmove(nv, src, end - src);
		nv[end - src] = '\0';
	}
}

/* restart_wl reasons */
char *rewl_desc[] = 
{
	"never",
	"current 2G chanspec is un-available",
	"current 5G chanspec is un-available",
	"Both 2G/5G chanspecs are un-available",
	"current 6G chanspec is un-available",
	//"all RE leaves",
	NULL
};

static AVBL_CHANSPEC_T *plast = NULL, last_avblChanspec;

int chanlist_update(AVBL_CHANSPEC_T *avblChanspec)
{
	int new_2g = 0, new_5g = 0, new_dual5gre = 0;
	unsigned int i, j, tmpch;

	if(!plast) {
		new_2g = 1;
		new_5g = 1;
		goto plast;
	}

	if(plast->bw2g != avblChanspec->bw2g)
		new_2g = 1;
	if(plast->bw5g != avblChanspec->bw5g)
		new_5g = 1;
	if(plast->existDual5gRe != avblChanspec->existDual5gRe)
		new_dual5gre = 1;

	for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList2g[i];
		if(tmpch <= 0)
			continue;
		for(j=0; j<MAX_2G_CHANNEL_LIST_NUM; ++j) {
			if(tmpch == last_avblChanspec.channelList2g[j])
				break;
		}
		if(j == MAX_2G_CHANNEL_LIST_NUM)
			new_2g = 1;
	}

	for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList5g[i];
		if(!tmpch) continue;
		for(j=0; j<MAX_5G_CHANNEL_LIST_NUM; ++j) {
			if(tmpch == last_avblChanspec.channelList5g[j])
				break;
		}
		if(j == MAX_5G_CHANNEL_LIST_NUM)
			new_5g = 1;
	}

	if(new_2g && nvram_match("cfg_abl", "1")) {
		DBG_ABL("2g chan updated:\n");
		DBG_ABL("bw2g:%d/%d\n", plast->bw2g, avblChanspec->bw2g);
		DBG_ABL("old chanlist\n");
		for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
			DBG_ABL("[%d]", last_avblChanspec.channelList2g[i]);
		}
		DBG_ABL("\nnew chanlist\n");
		for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
			DBG_ABL("[%d]", avblChanspec->channelList2g[i]);
		}
		DBG_ABL("\n");
	}
	if(new_5g && nvram_match("cfg_abl", "1")) {
		DBG_ABL("5g chan updated:\n");
		DBG_ABL("bw5g:%d/%d\n", plast->bw5g, avblChanspec->bw5g);
		DBG_ABL("old chanlist\n");
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
			DBG_ABL("[%d]", last_avblChanspec.channelList5g[i]);
		}
		DBG_ABL("\nnew chanlist\n");
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
			DBG_ABL("[%d]", avblChanspec->channelList5g[i]);
		}
		DBG_ABL("\n");
	}
plast:
	memcpy(&last_avblChanspec, avblChanspec, sizeof(AVBL_CHANSPEC_T));
	plast = &last_avblChanspec;

	return new_2g|new_5g|new_dual5gre;
}

uint16 avbl_wf_channel2chspec(uint ctl_ch, uint bw, uint wl_chanspec_band) 
{
// this should go w/ sdk ver.
#if defined(CHANNELSPEC_V2)
	return wf_channel2chspec(ctl_ch, bw, wl_chanspec_band);
#else
	return wf_channel2chspec(ctl_ch, bw);
#endif
}

void free_acs_tmp(char **tmp, int size)
{
	int i = 0;

	for(i=0; i<size; ++i) {
		if(tmp[i])
			free(tmp[i]);
	}
}

int is_unii4_chan(int tmpch, unsigned int bw)
{
	if ((bw&0x1 && (tmpch==169 || tmpch==173 || tmpch==177))
	 || (bw&0x2 && (tmpch==167 || tmpch==175))
	 || (bw&0x4 && (tmpch==171))
	 || (bw&0x8 && (tmpch==163))
	)
		return 1;
	
	return 0;
}

void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
	chanspec_t c = 0, chansp = 0;
	unsigned int i, j, k, tmpch;
	int restart_wl = 0, update = 0, ret = 0, count = 0, unit = -1;
	int unavl_2g = 0, unavl_5g = 0;
	int _5g_bands = 0;
	int unavl_6g = 0;
	char data_buf[WLC_IOCTL_MAXLEN];
	wl_uint32_list_t *list;
	char word[256]={0}, *next = NULL, prefix[]="wlxxx", tmp[128], cstmp[7], *sp, *sp2, *wlx_nvname, *sp_tmp=NULL;
	chanspec_t avblchanspec2g[MAX_2G_CHANNEL_LIST_NUM];
	chanspec_t avblchanspec5g[MAX_5G_CHANNEL_LIST_NUM*4];
#ifdef RTCONFIG_WIFI6E
	chanspec_t avblchanspec6g[MAX_6G_CHANNEL_LIST_NUM*4];
#else
	chanspec_t *avblchanspec6g = NULL;
#endif
#ifdef RTCONFIG_WIFI6E
	char acsexcl_wlx[2000], *pre_acsexcl;
	char acsexcl_wlx_cfg[2000];
#else
	char acsexcl_wlx[1000], *pre_acsexcl;
	char acsexcl_wlx_cfg[1000];
#endif

	char *acs_tmp[10], nvname[24];
	unsigned int acs_band_type[10], ifnum = 0;
	int restart_acsd = 0;
	int exist5ghighch = 0;
	int avbl_unii4 = 0;
	int avblchans = 0;
	char ifname[NVRAM_MAX_PARAM_LEN];
	char *p, tmp2[51];
	int band;

	syslog(LOG_NOTICE, "\nevent: wl_chanspec_changed_action\n");
	DBG_ABL("\nevent: wl_chanspec_changed_action\n");

	if(nvram_match("avblchan_disable", "1")) {
		syslog(LOG_NOTICE, "skip event due disabled\n");
		DBG_ABL("skip event due disabled\n");
		return;
	}
	if(!nvram_match("cfg_rejoin", "1") && !nvram_match("cfg_test", "1")) {
		syslog(LOG_NOTICE, "skip event due no re\n");
		DBG_ABL("skip event due no re\n");
		return;
	}
	if(!nvram_match("wlready", "1")) {
		syslog(LOG_NOTICE, "skip event due wl not ready\n");
		DBG_ABL("skip event due wl not ready\n");
		return;
	}

	memset(avblchanspec2g, 0, sizeof(avblchanspec2g));
	memset(avblchanspec5g, 0, sizeof(avblchanspec5g));
#ifdef RTCONFIG_WIFI6E
	memset(avblchanspec6g, 0, sizeof(avblchanspec6g));
#endif
	memset(acsexcl_wlx, 0, sizeof(acsexcl_wlx));
	memset(acsexcl_wlx_cfg, 0, sizeof(acsexcl_wlx_cfg));

	for(i=0; i<10; ++i)
		acs_tmp[i] = 0;
	i = 0;
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		wl_ioctl(word, WLC_GET_BAND, &band, sizeof(band));
		acs_band_type[i] = band;
		if(band == WLC_BAND_5G)
			_5g_bands++;
#ifdef RTCONFIG_WIFI6E
		if(band == WLC_BAND_6G){
			acs_tmp[i] = malloc(2000);
		} else
#endif
		acs_tmp[i] = malloc(1000);
		DBG_ABL("\navbl: lookup wl_if:%s, b:%d\n", word, band);
		i++;
	}
	ifnum = i;

	if (!nvram_match("wl1_chanspec", "0") || (_5g_bands == 2 && !nvram_match("wl2_chanspec", "0"))) {
		syslog(LOG_NOTICE, "skip event due static chan\n");
		DBG_ABL("skip event due static chan\n");
		free_acs_tmp(acs_tmp, ifnum);
		return;
	}

	DBG_ABL("\navblchans ifnum:(%d), 5gbands:(%d).\n", ifnum, _5g_bands);
	for(i=0; i<ifnum; ++i) {
		sprintf(nvname, "wl%d_acs_excl_chans", i);
		sprintf(acs_tmp[i], "%s", nvram_safe_get(nvname));
	}

	for(i=0; i<MAX_2G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList2g[i];
		if(tmpch <= 0)
			continue;
		if(avblChanspec->bw2g > 0) {	// 20
			avblchanspec2g[i] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_20, WL_CHANSPEC_BAND_2G);
			avblchans++;
		}
	}

	if(!nvram_match("allavbl", "1") && avblChanspec->existDual5gRe && _5g_bands==1) {
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
			tmpch = avblChanspec->channelList5g[i];
			if (tmpch >= 100) {
				exist5ghighch = 1;
				//break;
			}
			if (is_unii4_chan(tmpch, avblChanspec->bw5g))
				avbl_unii4 = 1;
		}
	}

	// adjust exist5ghighch
	int exist_band4_ch = 0;
	if((nvram_match("acs_dfs", "0")) && (exist5ghighch == 1 || nvram_match("cfg_test_5gh", "1"))) {
		for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
			tmpch = avblChanspec->channelList5g[i];
			if(!tmpch) continue;
			if(tmpch >= 149) {
				exist_band4_ch = 1;
				break;
			}
		}
		if(exist_band4_ch == 0) {
			exist5ghighch = 0;
			DBG_ABL("Not avoid choosing low band chan due no highband/dfs chan exist.\n");
		}
	}

	DBG_ABL("\navblchans filter:(%d)(Tri:%d)(Daul:%d)(avbl_unii4=%d) >>>\n", !nvram_match("allavbl", "1"), avblChanspec->existTribandRe, avblChanspec->existDual5gRe, avbl_unii4);

	for(i=0; i<MAX_5G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList5g[i];
		if(!tmpch) continue;
		DBG_ABL("Chk chan5g(%d)(bw:%x)\n", tmpch, avblChanspec->bw5g);
		if(exist5ghighch && (tmpch < 100)) { // skip selecting low band chan when cap-high5g/dual5g-re exist
			DBG_ABL("Skip selecting low band chan(%d) due high band chan exist and existDual5gRe", tmpch);
			continue;
		}
		if(avbl_unii4 && !is_unii4_chan(tmpch, avblChanspec->bw5g)) { // skip selecting non-unii4 chan when ual5g-re exist
			DBG_ABL("Skip selecting non-unii4 band chan(%d) due unii4 chan exist", tmpch);
			continue;
		}
		if(avblChanspec->bw5g & 0x1) {	// 20
			avblchanspec5g[4*i] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_20, WL_CHANSPEC_BAND_5G);
			avblchans++;
			//DBG_ABL("let [%d]=[%x]\n", 4*i, avblchanspec5g[4*i]);
		}
		if(avblChanspec->bw5g & 0x2) {	// 40
			avblchanspec5g[4*i+1] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_40, WL_CHANSPEC_BAND_5G);
			avblchans++;
			//DBG_ABL("let [%d]=[%x]\n", 4*i+1, avblchanspec5g[4*i+1]);
		}
		if(avblChanspec->bw5g & 0x4) {	// 80
			avblchanspec5g[4*i+2] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_80, WL_CHANSPEC_BAND_5G);
			avblchans++;
			//DBG_ABL("let [%d]=[%x]\n", 4*i+2, avblchanspec5g[4*i+2]);
		}
		if(avblChanspec->bw5g & 0x8) {	// 160
			avblchanspec5g[4*i+3] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_160, WL_CHANSPEC_BAND_5G);
			avblchans++;
			//DBG_ABL("let [%d]=[%x]\n", 4*i+3, avblchanspec5g[4*i+3]);
		}
	}
#ifdef RTCONFIG_WIFI6E
	DBG_ABL("\navblchans filter 6g >>>\n");
	for(i=0; i<MAX_6G_CHANNEL_LIST_NUM; ++i) {
		tmpch = avblChanspec->channelList6g[i];
		if(!tmpch) continue;
		DBG_ABL("Chk chan6g(%d)(bw:%x)\n", tmpch, avblChanspec->bw6g);

		if(avblChanspec->bw6g & 0x1) {	// 20
			avblchanspec6g[4*i] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_20, WL_CHANSPEC_BAND_6G);
			avblchans++;
		}
		if(avblChanspec->bw6g & 0x2) {	// 40
			avblchanspec6g[4*i+1] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_40, WL_CHANSPEC_BAND_6G);
			avblchans++;
		}
		if(avblChanspec->bw6g & 0x4) {	// 80
			avblchanspec6g[4*i+2] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_80, WL_CHANSPEC_BAND_6G);
			avblchans++;
		}
		if(avblChanspec->bw6g & 0x8) {	// 160
			avblchanspec6g[4*i+3] = avbl_wf_channel2chspec(tmpch, WL_CHANSPEC_BW_160, WL_CHANSPEC_BAND_6G);
			avblchans++;
		}
	}

#endif

	if(!avblchans) {
		syslog(LOG_NOTICE, "skip event due no avblchans\n");
		DBG_ABL("skip event due no avblchans\n");
		free_acs_tmp(acs_tmp, ifnum);
		return;
	}

	if(!chanlist_update(avblChanspec)) {
		syslog(LOG_NOTICE, "skip event due no chanlist update\n");
		DBG_ABL("skip event due no chan-list update\n");
		free_acs_tmp(acs_tmp, ifnum);
		return;
	}

	dump_avblchanspecs(avblchanspec2g, avblchanspec5g, avblchanspec6g);

	k=0;
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
        	c = 0;
        	memset(data_buf, 0, WLC_IOCTL_MAXLEN);

		wl_ioctl(word, WLC_GET_BAND, &band, sizeof(band));
#ifdef RTCONFIG_WIFI6E
		if(band == WLC_BAND_6G && !nvram_match("avbl_6g_enable", "1")) {
			_dprintf("skip case of 6g_if:%s\n", word);
			k++;
			continue;
		}
#endif
		DBG_ABL("\n\n --> avbl: lookup wl_if:%s, b:%d\n", word, band);

		ret = wl_iovar_get(word, "chanspec", &chansp, sizeof(chanspec_t));
        	if (ret < 0)
                	DBG_ABL("failed to get current chanspec\n");

        	ret = wl_iovar_getbuf(word, "chanspecs", &c, sizeof(chanspec_t),
                	data_buf, WLC_IOCTL_MAXLEN);
		unit = -1;
		if (wl_ioctl(word, WLC_GET_INSTANCE, &unit, sizeof(unit))) {
			DBG_ABL("%s get wl instance failed\n", word);;
			k++;
			continue;
		}
        	if (ret < 0)
                	DBG_ABL("failed to get valid chanspec list\n");
        	else {
                	list = (wl_uint32_list_t *)data_buf;
                	count = list->count;

			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			wlx_nvname = strcat_r(prefix, "acs_excl_chans_base", tmp);
			strlcpy(acsexcl_wlx, nvram_safe_get(wlx_nvname), sizeof(acsexcl_wlx));
                        if(acsexcl_wlx[0]==',') {
				DBG_ABL("\n\n! invalid acs_excl_chans val(%s)\n", acsexcl_wlx);
				adjust_excl(acsexcl_wlx, sizeof(acsexcl_wlx));
				DBG_ABL("adjusted:[%s]\n", acsexcl_wlx);
                        }
			DBG_ABL("chk %s_excl_base:%s\n", prefix, acsexcl_wlx);
			memset(acsexcl_wlx_cfg, 0, sizeof(acsexcl_wlx_cfg));

                	if (count && !(count > (data_buf + sizeof(data_buf) - (char *)&list->element[0])/sizeof(list->element[0]))) {
                        	for (i = 0; i < count; i++) {
                                	c = (chanspec_t)(list->element[i]);
					snprintf(cstmp, sizeof(cstmp), "0x%x", c);
					if(!is_avbl(acs_band_type[k], c, avblchanspec2g, avblchanspec5g, avblchanspec6g)) {
						if(!strstr(acsexcl_wlx, cstmp)) {
							//DBG_ABL("<%2x> is newly unavbl, pick to excl\n", c);
							if(strlen(acsexcl_wlx) + 6 < sizeof(acsexcl_wlx) - 1) {
								sp = acsexcl_wlx[0] ? ",":"";
                                        			strncat(acsexcl_wlx, sp, sizeof(acsexcl_wlx)-strlen(acsexcl_wlx)-1);
                                        			strncat(acsexcl_wlx, cstmp, sizeof(acsexcl_wlx)-strlen(acsexcl_wlx)-1);
							} else
								DBG_ABL("acsexcl_wlx full!\n");
						}
						if(!strstr(acsexcl_wlx_cfg, cstmp)) {
							//DBG_ABL("<%2x> is newly unavbl, pick to excl_cfg\n", c);
							if(strlen(acsexcl_wlx_cfg) + 6 < sizeof(acsexcl_wlx_cfg) - 1) {
								sp = acsexcl_wlx_cfg[0] ? ",":"";
                                        			strncat(acsexcl_wlx_cfg, sp, sizeof(acsexcl_wlx_cfg)-strlen(acsexcl_wlx_cfg)-1);
                                        			strncat(acsexcl_wlx_cfg, cstmp, sizeof(acsexcl_wlx_cfg)-strlen(acsexcl_wlx_cfg)-1);
							} else
								DBG_ABL("acsexcl_wlx_cfg full!\n");
						}
					} else if(strstr(acsexcl_wlx, cstmp)) {
						DBG_ABL("%2x should be avable, remove it from excl.\n", c);
						_remove_from_list(cstmp, acsexcl_wlx, sizeof(acsexcl_wlx), ',');
					} //else
					//	DBG_ABL("%2x is avable, chked not in excl\n", c);
                        	}
				//DBG_ABL("\nnow, acsexcl_wlx is \n");
				for(j=0; j<strlen(acsexcl_wlx); j+=sizeof(tmp2)-1) {
					p = acsexcl_wlx+j;
					strlcpy(tmp2, p, sizeof(tmp2)<=strlen(p)?sizeof(tmp2):strlen(p)+1);
					//DBG_ABL("%s\n", tmp2);
				}

				//DBG_ABL("\nnow, acsexcl_wlx_cfg is %s\n", acsexcl_wlx_cfg);

				if(nvram_match(strcat_r(prefix, "chanspec", tmp), "0")) {
					pre_acsexcl = nvram_safe_get(strcat_r(prefix, "acs_excl_chans", tmp));
					if(strncmp(pre_acsexcl, acsexcl_wlx, strlen(acsexcl_wlx)) != 0) {
						nvram_set(strcat_r(prefix, "acs_excl_chans", tmp), acsexcl_wlx);
						restart_acsd = 1;
					}
				}
				nvram_set(strcat_r(prefix, "acs_excl_chans_base", tmp), acsexcl_wlx);
				nvram_set(strcat_r(prefix, "acs_excl_chans_cfg", tmp), acsexcl_wlx_cfg);
                	}
			snprintf(cstmp, sizeof(cstmp), "%x", chansp);
			if(strstr(acsexcl_wlx, cstmp)) {
				if(acs_band_type[k] == WLC_BAND_2G)
					unavl_2g = 1;
				else if(acs_band_type[k] == WLC_BAND_5G)
					unavl_5g++;
#ifdef RTCONFIG_WIFI6E
				else if(acs_band_type[k] == WLC_BAND_6G)
					unavl_6g++;
#endif
			}
			syslog(LOG_NOTICE, "current chansp(unit%d) is %s\n", unit, cstmp);
			DBG_ABL("\nCheck unavl_2g:(%d), unavl_5g(%d), unavl_6g(%d): current chan:[%s]\nacsexcl=[%s]\nacsexcl_wlx_cfg=[%s]\n", unavl_2g, unavl_5g, unavl_6g, cstmp, acsexcl_wlx, acsexcl_wlx_cfg);
        	}
		k++;
    	}
	
	/* chk 6g here */
	if((_5g_bands==1 && unavl_5g) || (_5g_bands==2 && unavl_5g==2))
		unavl_5g = 1;
	else
		unavl_5g = 0;

	if(unavl_2g)
		restart_wl = 1;
	if(unavl_5g)
		restart_wl = 2;
	if(unavl_2g && unavl_5g)
		restart_wl = 3;
#ifdef RTCONFIG_WIFI6E
	if(unavl_6g && nvram_match("avbl_6g_enable", "1"))
		restart_wl = 4;
#endif

	DBG_ABL("Decide if restart_wl:%d, restart_acsd:%d\n", restart_wl, restart_acsd);
	for(i=0; i<ifnum; ++i) {
		sprintf(nvname, "wl%d_acs_excl_chans", i);
		DBG_ABL("wl%d_acs_excl_chans:%s\n", i, nvram_safe_get(nvname));
		sprintf(nvname, "wl%d_acs_excl_chans_cfg", i);
		DBG_ABL("wl%d_acs_excl_chans_cfg:%s\n", i, nvram_safe_get(nvname));	
	}

restartwl:
	if(restart_wl || restart_acsd) {
		syslog(LOG_NOTICE,"dump exclchans:\n");
		for(i=0; i<ifnum; ++i) {
			syslog(LOG_NOTICE,"old wl%d_acs_excl_chans:%s\n", i, acs_tmp[i]);
			sprintf(nvname, "wl%d_acs_excl_chans", i);
			syslog(LOG_NOTICE,"new wl%d_acs_excl_chans:%s\n", i, nvram_safe_get(nvname));
		}
	}

	free_acs_tmp(acs_tmp, ifnum);

	if (restart_wl) {
		syslog(LOG_NOTICE,"\n %s: Need to restart wireless due %s\n", __func__, rewl_desc[restart_wl]);
		DBG_ABL("\nWe Need to restart wireless due %s\n", rewl_desc[restart_wl]);
		notify_rc("restart_wireless");
	} else if(restart_acsd){
		syslog(LOG_NOTICE," %s: Need to restart acsd for AVBL update\n", __func__);
		DBG_ABL(" Need to restart acsd for AVBL update\n");
		nvram_set_int("acs_skip_init_acs", 1);
		notify_rc("restart_acsd");
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
	wlc_ssid_t ssid;

	ssid.SSID_len = 0;
	if (wl_ioctl(ifname, WLC_GET_SSID, &ssid, sizeof(wlc_ssid_t)) < 0) {
		DBG_ERR("get ssid failed");
		return ssid_buf;
	}

	memset(ssid_buf, 0, buf_len);
	strlcpy(ssid_buf, ssid.SSID, buf_len);

	return ssid_buf;
}

char *get_pap_ssid(int unit, char *ssid_buf, int buf_len)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *ifname;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (!ifname)
		return ssid_buf;

	return get_ssid(ifname, ssid_buf, buf_len);
}

char *get_ap_ssid(int unit, char *ssid_buf, int buf_len)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *ifname;

#ifdef RTCONFIG_AMAS
	if (nvram_get_int("re_mode") == 1)
		snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	else
#endif
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	if (!ifname)
		return ssid_buf;

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
		case MODEL_GTAX11000:
		case MODEL_GTAXE11000:
			if (!strcmp("eth0", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "1000", NULL);
			else if (!strcmp("eth5", ifname))
				result = gen_uplinkport_describe("NONE", "ETH", "2500", NULL);
			break;
		case MODEL_RTAX86U:
			if (!strcmp("eth0", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "1000", NULL);
			else if (!strcmp("eth5", ifname))
				result = gen_uplinkport_describe("NONE", "ETH", "2500", NULL);
			break;
		case MODEL_RTAX95Q:
		case MODEL_RTAXE95Q:
		case MODEL_XT8PRO:
		case MODEL_XT8_V2:
		case MODEL_ET8PRO:
			if (!strcmp("eth0", ifname))
				result = gen_uplinkport_describe("WAN", "ETH", "2.5G", NULL);
			break;
		case MODEL_ET12:
		case MODEL_XT12:
		if (!strcmp("eth0", ifname))
			result = gen_uplinkport_describe("WAN", "ETH", "2.5G", NULL);
		else if (!strcmp("eth3", ifname))
			result = gen_uplinkport_describe("LAN", "ETH", "2.5G", NULL);
			break;
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