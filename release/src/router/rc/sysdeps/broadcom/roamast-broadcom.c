#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <shared.h>
#include <rc.h>
#include <wlioctl.h>
#include <bcmendian.h>
#include <wlutils.h>
#include <roamast.h>
#if defined(RTCONFIG_HND_ROUTER_AX)
#include <bcmwifi_rspec.h>
#endif
#ifdef RTCONFIG_BCN_RPT
#include <pthread.h>
#include <json.h>
#include <security_ipc.h>
#define EVENTD_BUFSIZE_4K	4096
#endif
#if 0
#ifdef RTCONFIG_ADV_RAST
static uint8 bss_token = 0;
#endif
#endif

#ifdef RTCONFIG_HND_ROUTER_AX
#define htod16(i) (g_swap?bcmswap16(i):(uint16)(i))
#define htodenum(i) (g_swap?((sizeof(i) == 4) ? htod32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)
#endif

extern void retrieve_static_maclist_from_nvram(int idx,struct maclist *maclist,int maclist_buf_size);

#ifdef RTCONFIG_BCN_RPT
#define WL_STA_RRM_CAP			0x10000000	/* RRM CAP */
#define WL_STA_RRM_BCN_PASSIVE_CAP	0x20000000	/* Beacon Passive Measurement CAP */
void rast_update_beacon_report(struct ether_addr *sta, struct ether_addr *bssid, int8 rcpi);
#endif

void get_wifi_ifname(char *wlif_name, int len, int bssidx, int vifidx){
	if(vifidx > 0)
		snprintf(wlif_name, len, "wl%d.%d", bssidx, vifidx);
	else
		strncpy(wlif_name, bssinfo[bssidx].wlif_name, len);
}

#if defined(RTCONFIG_HND_ROUTER_AX)
/* Format a ratespec for "nrate" output
 * Will handle both current wl_ratespec and legacy (ioctl_version 1) nrate ratespec
 */
void
wl_nrate_print(uint32 rspec, int ioctl_version, char *buf, int buflen)
{
	const char * rspec_auto = "auto";
	uint encode, rate, txexp = 0, bw_val;
	const char* stbc = "";
	const char* ldpc = "";
	const char* bw = "";
	int stf;

	if (rspec == 0) {
		encode = WL_RSPEC_ENCODE_RATE;
	} else if (ioctl_version == 1) {
		encode = (rspec & OLD_NRATE_MCS_INUSE) ? WL_RSPEC_ENCODE_HT : WL_RSPEC_ENCODE_RATE;
		stf = (int)((rspec & OLD_NRATE_STF_MASK) >> OLD_NRATE_STF_SHIFT);
		rate = (rspec & OLD_NRATE_RATE_MASK);

		if (rspec & OLD_NRATE_OVERRIDE) {
			if (rspec & OLD_NRATE_OVERRIDE_MCS_ONLY)
				rspec_auto = "fixed mcs only";
			else
				rspec_auto = "fixed";
		}
	} else {
		int siso;
		encode = (rspec & WL_RSPEC_ENCODING_MASK);
		rate = (rspec & WL_RSPEC_RATE_MASK);
		txexp = (rspec & WL_RSPEC_TXEXP_MASK) >> WL_RSPEC_TXEXP_SHIFT;
		stbc  = ((rspec & WL_RSPEC_STBC) != 0) ? " stbc" : "";
		ldpc  = ((rspec & WL_RSPEC_LDPC) != 0) ? " ldpc" : "";
		bw_val = (rspec & WL_RSPEC_BW_MASK);

		if (bw_val == WL_RSPEC_BW_20MHZ) {
			bw = "bw20";
		} else if (bw_val == WL_RSPEC_BW_40MHZ) {
			bw = "bw40";
		} else if (bw_val == WL_RSPEC_BW_80MHZ) {
			bw = "bw80";
		} else if (bw_val == WL_RSPEC_BW_160MHZ) {
			bw = "bw160";
		}
#if !defined(RTCONFIG_WIFI6E) && !defined(RTCONFIG_HND_ROUTER_AX_675X) && !defined(RTCONFIG_HND_ROUTER_AX_6756) && !defined(RTCONFIG_HND_ROUTER_AX_6710) && !defined(RTCONFIG_BCM_502L07P2)
		else if (bw_val == WL_RSPEC_BW_10MHZ) {
			bw = "bw10";
		} else if (bw_val == WL_RSPEC_BW_5MHZ) {
			bw = "bw5";
		} else if (bw_val == WL_RSPEC_BW_2P5MHZ) {
			bw = "bw2.5";
		}
#endif

		/* initialize stf mode to an illegal value and
		 * fix to a backward compatable value if possible
		 */
		stf = -1;
		/* for stf calculation, determine if the rate is single stream.
		 * Legacy rates WL_RSPEC_ENCODE_RATE are single stream, and
		 * HT rates for mcs 0-7 are single stream
		 */
		siso = (encode == WL_RSPEC_ENCODE_RATE) ||
			((encode == WL_RSPEC_ENCODE_HT) && rate < 8);

		/* calc a value for nrate stf mode */
		if (txexp == 0) {
			if ((rspec & WL_RSPEC_STBC) && siso) {
				/* STF mode STBC */
				stf = OLD_NRATE_STF_STBC;
			} else {
				/* STF mode SISO or SDM */
				stf = (siso) ? OLD_NRATE_STF_SISO : OLD_NRATE_STF_SDM;
			}
		} else if (txexp == 1 && siso) {
			/* STF mode CDD */
			stf = OLD_NRATE_STF_CDD;
		}

		if (rspec & WL_RSPEC_OVERRIDE_RATE) {
			rspec_auto = "fixed";
		}
	}

	if (encode == WL_RSPEC_ENCODE_RATE) {
		if (rspec == 0) {
			snprintf(buf, buflen, "auto");
		} else {
			snprintf(buf, buflen, "legacy rate %d%s Mbps stf mode %d %s", rate/2, (rate % 2)?".5":"", stf, rspec_auto);
		}
	} else if (encode == WL_RSPEC_ENCODE_HT) {
		snprintf(buf, buflen, "mcs index %d stf mode %d %s", rate, stf, rspec_auto);
	} else if (encode == WL_RSPEC_ENCODE_VHT) {
		const char* sgi = "";
		uint vht = (rspec & WL_RSPEC_VHT_MCS_MASK);
		uint Nss = (rspec & WL_RSPEC_VHT_NSS_MASK) >> WL_RSPEC_VHT_NSS_SHIFT;

		sgi   = ((rspec & WL_RSPEC_SGI)  != 0) ? " sgi"  : "";

		snprintf(buf, buflen, "vht mcs %d Nss %d Tx Exp %d %s%s%s%s %s", vht, Nss, txexp, bw, stbc, ldpc, sgi, rspec_auto);
	} else if (encode == WL_RSPEC_ENCODE_HE) {
		const char* gi_ltf[] = {" 1xLTF GI 0.8us", " 2xLTF GI 0.8us", " 2xLTF GI 1.6us", " 4xLTF GI 3.2us"};
		uint8 gi_int = RSPEC_HE_LTF_GI(rspec);
		uint he = (rspec & WL_RSPEC_HE_MCS_MASK);
		uint Nss = (rspec & WL_RSPEC_HE_NSS_MASK) >> WL_RSPEC_HE_NSS_SHIFT;

		snprintf(buf, buflen, "he mcs %d Nss %d Tx Exp %d %s%s%s%s %s", he, Nss, txexp, bw, stbc, ldpc, gi_ltf[gi_int], rspec_auto);
	}
	else
		memset(buf, 0, buflen);
}
#endif

void get_stainfo(int bssidx, int vifidx)
{
	struct maclist *mac_list;
	int mac_list_size;
	scb_val_t scb_val;
	int mcnt;
	char wlif_name[32];
	int32 rssi;
	sta_info_t *sta_info = NULL;
	rast_sta_info_t *sta = NULL;
	uint32 pkt_diff = 0;

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	mac_list_size = sizeof(mac_list->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	mac_list = malloc(mac_list_size);

	if(!mac_list)
		goto exit;

	memset(mac_list, 0, mac_list_size);

	/* query authentication sta list */
	strcpy((char*) mac_list, "authe_sta_list");
	if(wl_ioctl(wlif_name, WLC_GET_VAR, mac_list, mac_list_size))
		goto exit;

	for(mcnt=0; mcnt < mac_list->count; mcnt++) {
		sta_info = wl_sta_info(wlif_name, &mac_list->ea[mcnt]);
		if(!sta_info) continue;
		if(!(sta_info->flags & WL_STA_ASSOC) && !sta_info->in) continue;

		memcpy(&scb_val.ea, &mac_list->ea[mcnt], ETHER_ADDR_LEN);
		if(wl_ioctl(wlif_name, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t))) continue;

		rssi = scb_val.val;

		/* add to assoclist */
		sta = rast_add_to_assoclist(bssidx, vifidx, &(mac_list->ea[mcnt]));
		sta->rssi = rssi;
		sta->tx_rate = sta_info->tx_rate;
		sta->rx_rate = sta_info->rx_rate;

		pkt_diff = sta_info->rx_tot_bytes - sta->rx_byte;
		sta->rx_bytes = pkt_diff > 0 ? pkt_diff : 0;

		sta->tx_byte = dtoh64(sta_info->tx_tot_bytes);
		sta->rx_byte = dtoh64(sta_info->rx_tot_bytes);

#ifdef RTCONFIG_ADV_RAST
		sta->wnm_cap = sta_info->wnm_cap;
#endif

#ifdef RTCONFIG_BCN_RPT
#if defined(RTCONFIG_HND_ROUTER_AX)
		if(sta_info->ver >= WL_STA_VER_8){
			sta_info_v8_t *sta_v8 = (sta_info_v8_t *)sta_info;
			uint8 rrm_cap[DOT11_RRM_CAP_LEN];
			memcpy(rrm_cap, sta_v8->rrm_capabilities, DOT11_RRM_CAP_LEN);
			sta->rrm_bcn_passive_cap = (rrm_cap[0] & (1 << DOT11_RRM_CAP_BCN_PASSIVE)) ? 1 : 0; /* Beacon_Passive: bit4 */
			wl_nrate_print(dtoh32(sta_v8->tx_rspec), WLC_IOCTL_VERSION, sta->tx_nrate, sizeof(sta->tx_nrate));
			wl_nrate_print(dtoh32(sta_v8->rx_rspec), WLC_IOCTL_VERSION, sta->rx_nrate, sizeof(sta->rx_nrate));
		}
		else
			sta->rrm_bcn_passive_cap = (sta_info->flags & WL_STA_RRM_BCN_PASSIVE_CAP) ? 1 : 0;
#elif defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
			sta->rrm_bcn_passive_cap = (sta_info->flags & WL_STA_RRM_BCN_PASSIVE_CAP) ? 1 : 0;
#elif defined(RTCONFIG_BCM4708)
			sta->rrm_bcn_passive_cap = (sta_info->rrm_cap[0] >> DOT11_RRM_CAP_BCN_PASSIVE) & 0x1;
#endif
		RAST_DBG("rrm cap %d\n",sta->rrm_bcn_passive_cap);
#endif
		sta->active = uptime();
	}

exit:
	if(mac_list) free(mac_list);

	return;
}

sta_info_t *
wl_sta_info(char *ifname, struct ether_addr *ea)
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
			RAST_DBG("ERROR: unknown driver station info version %d\n", sta->ver);
			return NULL;
		}

		sta->len = dtoh16(sta->len);
		sta->cap = dtoh16(sta->cap);
		sta->flags = dtoh32(sta->flags);
		sta->idle = dtoh32(sta->idle);
		sta->rateset.count = dtoh32(sta->rateset.count);
		sta->in = dtoh32(sta->in);
		sta->listen_interval_inms = dtoh32(sta->listen_interval_inms);
#ifdef RTCONFIG_BCMARM
		sta->ht_capabilities = dtoh16(sta->ht_capabilities);
		sta->vht_flags = dtoh16(sta->vht_flags);
		sta->wnm_cap = dtoh32(sta->wnm_cap);
		sta->aid = dtoh16(sta->aid);
		sta->tx_rate = dtoh32(sta->tx_rate);
		sta->rx_rate = dtoh32(sta->rx_rate);
#endif
	}

	return sta;
}

#if defined(RTCONFIG_BCMARM) || defined(RTCONFIG_BCMWL6)
void rast_retrieve_bs_data(int bssidx, int vifidx, int interval){
#ifdef RTCONFIG_BCMARM
	int ret;
	int argn;
	char ioctl_buf[4096];
	iov_bs_data_struct_t *data = (iov_bs_data_struct_t *)ioctl_buf;
	iov_bs_data_record_t *rec;
	iov_bs_data_counters_t *ctr;
	float datarate_tx = 0, datarate_rx = 0;
	rast_sta_info_t *sta = NULL;
	char wlif_name[32];

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "bs_data");
	ret = wl_ioctl(wlif_name, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf));
	if(ret < 0) {
		return;
	}

	for(argn = 0; argn < data->structure_count; argn++) {
		rec = &data->structure_record[argn];
		ctr = &rec->station_counters;

		sta = rast_add_to_assoclist(bssidx, vifidx, &(rec->station_address));
		if(sta) {
			datarate_rx = ((float)sta->rx_bytes * 8) / ((float)interval * 1000);
			sta->datarate = datarate_rx;
		}

		if(ctr->acked == 0) continue;
		else {
			datarate_tx = (ctr->time_delta) ? (float)ctr->throughput * 8000.0 / (float)ctr->time_delta : 0.0;
			if(sta) {
				sta->datarate += datarate_tx;
			}

		}
	}
#else   //BRCM MIPS platform
	rast_sta_info_t *sta;
	sta_info_t *sta_info = NULL;
	char wlif_name[32];
	float datarate = 0;
	uint32 curpkts;

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	sta = bssinfo[bssidx].assoclist[vifidx];
	while(sta) {
		sta_info = wl_sta_info(wlif_name, &sta->addr);
		if(sta_info) {
			_dprintf("sta "MACF": idle:%d, tx_packets:%d, prepkts=%d\n",
					ETHERP_TO_MACF(&sta->addr),
					dtoh32(sta_info->idle),
					dtoh32(sta_info->tx_pkts),
					sta->prepkts);

			curpkts = dtoh32(sta_info->tx_pkts);
			datarate = (float)(curpkts - sta->prepkts)/(float)interval;     //using pkt rate for mips platform
			sta->prepkts = curpkts;
			sta->datarate = datarate;
		}

		sta = sta->next;
	}
#endif
}
#endif

#ifdef RTCONFIG_ADV_RAST
int rast_stamon_get_rssi(int bssidx, struct ether_addr *addr)
{
	wlc_stamon_sta_config_t stamon_cfg;
        stamon_info_t *pbuf;
        char data_buf[WLC_IOCTL_MAXLEN];
        char wlif_name[64];
        int ret=0, i=0;
        int sta_rssi=0;

        snprintf(wlif_name, sizeof(wlif_name), "%s", bssinfo[bssidx].wlif_name);
        memset(&stamon_cfg, 0, sizeof(wlc_stamon_sta_config_t));
        memset(data_buf, 0, WLC_IOCTL_MAXLEN);

#ifdef RTCONFIG_HND_ROUTER_AX
	stamon_cfg.version = htod16(STAMON_STACONFIG_VER);
	stamon_cfg.length = htod16(STAMON_STACONFIG_LENGTH);
#endif

        // enable sta_monitor feature
#ifdef RTCONFIG_HND_ROUTER_AX
	stamon_cfg.cmd = htodenum(STAMON_CFG_CMD_ENB);
#else
        stamon_cfg.cmd = STAMON_CFG_CMD_ENB;
#endif
        ret = wl_iovar_set(wlif_name, "sta_monitor", &stamon_cfg, sizeof(wlc_stamon_sta_config_t));
        if (ret < 0) {
                RAST_INFO("stamon enable failure\n");
                return sta_rssi;
        }

        // add sta into sta_monitor list
#ifdef RTCONFIG_HND_ROUTER_AX
        stamon_cfg.cmd = htodenum(STAMON_CFG_CMD_ADD);
#else
        stamon_cfg.cmd = STAMON_CFG_CMD_ADD;
#endif
        stamon_cfg.ea = *addr;
        ret = wl_iovar_set(wlif_name, "sta_monitor", &stamon_cfg, sizeof(wlc_stamon_sta_config_t));
        if (ret < 0) {
                RAST_INFO("stamon add failure\n");
                return sta_rssi;
        }

        // retrieve sta rssi
#ifdef RTCONFIG_HND_ROUTER_AX
	stamon_cfg.cmd = htodenum(STAMON_CFG_CMD_GET_STATS);
#else
        stamon_cfg.cmd = STAMON_CFG_CMD_GET_STATS;
#endif
        for (i=0; i<3; i++)
        {
		usleep(500000);
                ret = wl_iovar_getbuf(wlif_name, "sta_monitor", &stamon_cfg, sizeof(wlc_stamon_sta_config_t), data_buf, WLC_IOCTL_MAXLEN);
                pbuf = (stamon_info_t*)data_buf;
                if (pbuf->count != 0) {
                        if(pbuf->sta_data[0].rssi < 0) {
                                sta_rssi = (sta_rssi == 0 ? pbuf->sta_data[0].rssi : (pbuf->sta_data[0].rssi > sta_rssi ? pbuf->sta_data[0].rssi : sta_rssi));
                                RAST_DBG("[%d]sta: "MACF" rssi = %d dBm\n", i,ETHER_TO_MACF(pbuf->sta_data[0].ea), sta_rssi);
                        }
                }
        }

        // remove sta from sta_monitor list
#ifdef RTCONFIG_HND_ROUTER_AX
	stamon_cfg.cmd = htodenum(STAMON_CFG_CMD_DEL);
#else
        stamon_cfg.cmd = STAMON_CFG_CMD_DEL;
#endif
        ret = wl_iovar_set(wlif_name, "sta_monitor", &stamon_cfg, sizeof(wlc_stamon_sta_config_t));
        if (ret < 0) {
                RAST_INFO("stamon del failure\n");
        }

	usleep(500000);

        // disable sta_monitor
#ifdef RTCONFIG_HND_ROUTER_AX
	stamon_cfg.cmd = htodenum(STAMON_CFG_CMD_DSB);
#else
        stamon_cfg.cmd = STAMON_CFG_CMD_DSB;
#endif
        ret = wl_iovar_set(wlif_name, "sta_monitor", &stamon_cfg, sizeof(wlc_stamon_sta_config_t));
        if (ret < 0) {
                RAST_INFO("stamon disable failure\n");
        }

        return sta_rssi;
}

void rast_retrieve_static_maclist(int bssidx, int vifidx)
{
	int ret, size;
	char wlif_name[64];
	struct maclist *maclist = (struct maclist *) maclist_buf;

#ifdef RTCONFIG_AMAS
	if (nvram_get_int("re_mode") == 1 && vifidx == 0)
		return;
#endif
	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	ret = wl_ioctl(wlif_name, WLC_GET_MACMODE, &(bssinfo[bssidx].static_macmode[vifidx]), sizeof(bssinfo[bssidx].static_macmode[vifidx]));
	if(ret < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", wlif_name);
		return;
	}


	RAST_DBG("[%s] macmode = %s\n",
	wlif_name,
	bssinfo[bssidx].static_macmode[vifidx]==WLC_MACMODE_DISABLED ? "DISABLE" :
	bssinfo[bssidx].static_macmode[vifidx]==WLC_MACMODE_DENY ? "DENY" : "ALLOW");
#if 1
	retrieve_static_maclist_from_nvram(bssidx,maclist,sizeof(maclist_buf));
#else
	ret = wl_ioctl(wlif_name, WLC_GET_MACLIST, (void *)maclist, sizeof(maclist_buf));
	if(ret < 0) {
	RAST_INFO("[WARNING] %s get macmode error!!!\n", wlif_name);
	return;
	}
#endif
	if (maclist->count > 0 && maclist->count < 128) {
		size = sizeof(uint) + sizeof(struct ether_addr) * (maclist->count + 1);

		RAST_DBG("count[%d] size[%d]\n", maclist->count, size);

		bssinfo[bssidx].static_maclist[vifidx] = (struct maclist *)malloc(size);
		if (!(bssinfo[bssidx].static_maclist[vifidx])) {
			RAST_INFO("%s malloc [%d] failure... \n", __FUNCTION__, size);
			return;
		}
		memcpy(bssinfo[bssidx].static_maclist[vifidx], maclist, size);
		maclist = bssinfo[bssidx].static_maclist[vifidx];
		for (size = 0; size < maclist->count; size++) {
			RAST_DBG("[%s] (%d)mac:"MACF"\n",wlif_name, size, ETHER_TO_MACF(maclist->ea[size]));
		}
	} else if (maclist->count != 0) {
		RAST_INFO("Err: %s maclist cnt [%d] too large\n",
		wlif_name, maclist->count);
		return;
	}
}

void rast_set_maclist(int bssidx, int vifidx)
{
	char wlif_name[64];
	rast_maclist_t *r_maclist = bssinfo[bssidx].maclist[vifidx];
	struct maclist *maclist = (struct maclist *)maclist_buf;
	struct maclist *static_maclist = bssinfo[bssidx].static_maclist[vifidx];
	int static_macmode = bssinfo[bssidx].static_macmode[vifidx];
	int ret, val;
	struct ether_addr *ea;
	int cnt, match;

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED)
		val = WLC_MACMODE_DENY;
	else
		val = WLC_MACMODE_ALLOW;

	ret = wl_ioctl(wlif_name, WLC_SET_MACMODE, &val, sizeof(val));
	if(ret < 0) {
		RAST_INFO("[WARNING] %s set macmode error!!!\n", wlif_name);
		return;
	}

	memset(maclist_buf, 0, sizeof(maclist_buf));

	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED) {
		if (static_maclist && static_macmode == WLC_MACMODE_DENY) {
			RAST_DBG("Deny mode: Adding static maclist\n");
			maclist->count = static_maclist->count;
			memcpy(maclist_buf, static_maclist,
			sizeof(uint) + ETHER_ADDR_LEN * (maclist->count));
		}

		ea = &(maclist->ea[maclist->count]);
		while (r_maclist) {
			memcpy(ea, &(r_maclist->addr), sizeof(struct ether_addr));
			maclist->count++;
			RAST_DBG("Deny mode: cnt[%d] mac:"MACF"\n",
					maclist->count, ETHERP_TO_MACF(ea));
					ea++;
					r_maclist = r_maclist->next;
		}
	}
	else {  //ALLOW MODE
		ea = &(maclist->ea[0]);

		if (!static_maclist) {
			RAST_INFO("[ERROR] %s macmode:%d static_list is NULL\n",
			wlif_name, static_macmode);
			return;
		}

		for (cnt = 0; cnt < static_maclist->count; cnt++) {
			RAST_DBG("Allow mode: static mac[%d] addr:"MACF"\n", cnt,
					ETHER_TO_MACF(static_maclist->ea[cnt]));
			/* if mac in static maclist match rast maclist, skip it */
			r_maclist = bssinfo[bssidx].maclist[vifidx];
			match = 0;
			while(r_maclist) {
				RAST_DBG("Checking "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
				if (eacmp(&(r_maclist->addr), &(static_maclist->ea[cnt])) == 0) {
					RAST_DBG("MATCH maclist "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
					match = 1;
					break;
				}
				r_maclist = r_maclist->next;
			}
			if (!match) {
				memcpy(ea, &(static_maclist->ea[cnt]), sizeof(struct ether_addr));
				maclist->count++;
				RAST_DBG("Adding to Allow list: cnt[%d] addr:"MACF"\n",
				maclist->count, ETHERP_TO_MACF(ea));
				ea++;
			}
		}
	}

	RAST_DBG("maclist count[%d] \n", maclist->count);
	for (cnt = 0; cnt < maclist->count; cnt++) {
		RAST_DBG("maclist: "MACF"\n",
		ETHER_TO_MACF(maclist->ea[cnt]));
	}

	ret = wl_ioctl(wlif_name, WLC_SET_MACLIST, maclist, sizeof(maclist_buf));
	if (ret < 0) {
		RAST_DBG("Err: [%s] set maclist...\n", wlif_name);
	}

#if defined(RTCONFIG_BCM4708) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER) || defined(RTCONFIG_HND_ROUTER_AX)
	/* enable SW probe response */
        wl_iovar_setint(wlif_name, "probresp_sw", 1);

	/* enable MAC filter based Probe Response */
	val = (val == WLC_MACMODE_DENY) ? 1 : 0;
	RAST_DBG("set %s probresp_mac_filter to %d\n", wlif_name, val);
	if (wl_iovar_setint(wlif_name, "probresp_mac_filter", val)) {
		RAST_DBG("Err: [%s] setting iovar probresp_mac_filter.\n", wlif_name);
	}
#endif
}

uint8 rast_get_rclass(int bssidx, int vifidx)
{
	char wlif_name[32];
	char ioctl_buf[256];
	char *param;
	int buflen;
	uint8 rclass = 0;
	chanspec_t chanspec;

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	if (wl_iovar_get(wlif_name, "chanspec", &chanspec, sizeof(chanspec_t))) {
		RAST_INFO("Error to read chanspec: %s\n", wlif_name);
	}
	else {
		RAST_DBG("[%s] chanspec: 0x%x\n", wlif_name, chanspec);

		memset(ioctl_buf, 0, sizeof(ioctl_buf));
		strcpy(ioctl_buf, "rclass");
		buflen = strlen(ioctl_buf) + 1;
		param = (char *)(ioctl_buf + buflen);
		memcpy(param, &chanspec, sizeof(chanspec_t));

		if(wl_ioctl(wlif_name, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf))){
			RAST_INFO("Error to read rclass: %s\n", wlif_name);
		}
		rclass = (uint8)(*((uint32 *)ioctl_buf));
		RAST_DBG("[%s] rclass: 0x%x\n", wlif_name, rclass);
	}

	return rclass;
}
#if 0
int rast_send_bsstrans_req(int bssidx, int vifidx, struct ether_addr *sta_addr, struct ether_addr *nbr_bssid)
{
#if 0
/* BSS Management Transition Request frame header */
BWL_PRE_PACKED_STRUCT struct dot11_bsstrans_req {
        uint8 category;                 /* category of action frame (10) */
        uint8 action;                   /* WNM action: trans_req (7) */
        uint8 token;                    /* dialog token */
        uint8 reqmode;                  /* transition request mode */
        uint16 disassoc_tmr;            /* disassociation timer */
        uint8 validity_intrvl;          /* validity interval */
        uint8 data[1];                  /* optional: BSS term duration, ... */
                                                /* ...session info URL, candidate list */
} BWL_POST_PACKED_STRUCT;

/* Neighbor Report element (11k & 11v) */
BWL_PRE_PACKED_STRUCT struct dot11_neighbor_rep_ie {
        uint8 id;
        uint8 len;
        struct ether_addr bssid;
        uint32 bssid_info;
        uint8 reg;              /* Operating class */
        uint8 channel;
        uint8 phytype;
        uint8 data[1];          /* Variable size subelements */
} BWL_POST_PACKED_STRUCT;
#endif
	char wlif_name[32];
	char ioctl_buf[4096];
	int buflen;
	char *param;

	dot11_bsstrans_req_t *transreq;		/* BSS Management Transition Request frame header */
	dot11_neighbor_rep_ie_t *nbr_ie;	/* Neighbor Report element */

	wl_af_params_t *af_params;
	wl_action_frame_t *action_frame;	/* action frame */

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
        strcpy(ioctl_buf, "actframe");
        buflen = strlen(ioctl_buf) + 1;
        param = (char *)(ioctl_buf + buflen);

	af_params = (wl_af_params_t *)param;
        action_frame = &af_params->action_frame;

	af_params->channel = 0;
        af_params->dwell_time = -1;

        memcpy(&action_frame->da, (char *)(sta_addr), ETHER_ADDR_LEN);
        action_frame->packetId = (uint32)(uintptr)action_frame;
        action_frame->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN + TLV_HDR_LEN + DOT11_BSSTRANS_REQ_LEN;

        transreq = (dot11_bsstrans_req_t *)&action_frame->data[0];
        transreq->category = DOT11_ACTION_CAT_WNM;
        transreq->action = DOT11_WNM_ACTION_BSSTRANS_REQ;
        if (++bss_token == 0)
                bss_token = 1;
        transreq->token = bss_token;
        transreq->reqmode = DOT11_BSSTRANS_REQMODE_PREF_LIST_INCL;
        /* set bit1 to tell STA the BSSID in list recommended */
        transreq->reqmode |= DOT11_BSSTRANS_REQMODE_ABRIDGED;
        /*
                remove bit2 DOT11_BSSTRANS_REQMODE_DISASSOC_IMMINENT
                because bsd will deauth sta based on BSS response
        */
        transreq->disassoc_tmr = 0x0000;
        transreq->validity_intrvl = 0x00;

	nbr_ie = (dot11_neighbor_rep_ie_t *)&transreq->data[0];
        nbr_ie->id = DOT11_MNG_NEIGHBOR_REP_ID;
        nbr_ie->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN;
	memcpy(&nbr_ie->bssid, nbr_bssid, ETHER_ADDR_LEN);
        nbr_ie->bssid_info = 0x00000000;
        nbr_ie->reg = rast_get_rclass(bssidx, vifidx);		// assume the same as cueernt ap
	nbr_ie->channel = rast_get_channel(bssidx, vifidx);	// assume the same as current ap
        nbr_ie->phytype = 0x00;

	RAST_DBG("[%s] Sending 11v bss transition frame to sta "MACF" with candicate ap "MACF"\n", 
			wlif_name, ETHER_TO_MACF(*sta_addr), ETHER_TO_MACF(nbr_ie->bssid));

	if(wl_ioctl(wlif_name, WLC_SET_VAR, ioctl_buf, WL_WIFI_AF_PARAMS_SIZE)){
		RAST_INFO("Error to send action frame: %s\n", wlif_name);
		return 0;
	}

        return 1;
}
#endif
#endif
#ifdef RTCONFIG_BCN_RPT
uint8 rast_get_channel(int bssidx, int vifidx)
{
	char wlif_name[32];
	uint8 channel = 0;
	chanspec_t chanspec;

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	if (wl_iovar_get(wlif_name, "chanspec", &chanspec, sizeof(chanspec_t))) {
		RAST_INFO("Error to read chanspec: %s\n", wlif_name);
	}
	else {
		RAST_DBG("[%s] chanspec: 0x%x\n", wlif_name, chanspec);

		channel = wf_chspec_ctlchan(chanspec);
		RAST_DBG("[%s] channel: 0x%x\n", wlif_name, channel);
	}

	return channel;
}
/*
	get regulation class by ioctl
*/
uint8
wl_rclass(char* ifname) {
	char ioctl_buf[256];
	char *cmd_rclass = "rclass";
	int cmd_len;
	chanspec_t chanspec;

	if (wl_iovar_get(ifname, "chanspec", &chanspec, sizeof(chanspec_t)))
		return 0;
	
	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	cmd_len = strlen(cmd_rclass);
	memcpy(ioctl_buf, cmd_rclass, cmd_len);
	memcpy(ioctl_buf + cmd_len + 1, &chanspec, sizeof(chanspec_t));
	if(wl_ioctl(ifname, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf)))
		return 0;
	else 
		return (uint8)(*((uint32 *)ioctl_buf));
}

struct action_filed{
	uint8 category;
	uint8 action;
	uint8 token;
	uint16 repetitions;
};
#define BCN_ACT_LEN 5

struct measurement_request {
	uint8 ele_ID;
	uint8 length;
	uint8 token;
	uint8 req_mode;
	uint8 type;
};
#define BCN_MSE_REQ_LEN 5

struct beacon_request {
	uint8 req_class;
	uint8 channel;
	uint16 rand_int;
	uint16 dur;
	uint8 mode;
	uint8 bssid[6];
};
#define BCN_BCN_REQ_LEN 13

struct subelement {
	uint8 ID;
	uint8 length;
	uint8 data;
};
#define BCN_SUB_BASE_LEN 2

/*	generate beacon request action frame
	
*/
void
rast_send_beacon_request(int bssidx, int vifidx, struct ether_addr *sta)
{
	char tmp[32];
	char wlif_name[32];
	char prefix[16];

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);
	
	if(vifidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);

	char *hw_addr = nvram_safe_get(strcat_r(prefix, "hwaddr", tmp));
	char *ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));

	uint8 ssid_len = strlen(ssid);
	uint8 channel  = rast_get_channel(bssidx, vifidx);
	//uint8 channel2 = 0;

	static uint8 action_token = 0;
	static uint8 measurement_token = 0;
	uint8 data[1024];
	uint8 *p = data;
	int i;
	struct action_filed *action;
	struct measurement_request *measurement;
	struct beacon_request *beacon;
	struct subelement *ssid_ele;
	//struct subelement *rep_info;
	struct subelement *rep_detail;
	//struct subelement *multi_channel;
	struct subelement *request;
	
	memset(data, 0, sizeof(data));
	action = (struct action_filed *)p;
	p = p + BCN_ACT_LEN;
	action->category = 5;
	action->action = 0;
	action->token = action_token++;
	action->repetitions = 0;

	measurement = (struct measurement_request *)p;
	p += BCN_MSE_REQ_LEN;
	measurement->ele_ID = 0x26;
	measurement->length = 3 + BCN_BCN_REQ_LEN +BCN_SUB_BASE_LEN + ssid_len + BCN_SUB_BASE_LEN + 1 + BCN_SUB_BASE_LEN + 1;
	measurement->token = measurement_token++;
	measurement->req_mode = 0;
	measurement->type = 5;

	beacon = (struct beacon_request *)p;
	p = p + BCN_BCN_REQ_LEN;
	//beacon->req_class = wl_rclass(wlif_name);
	//RAST_DBG("%s: channel %d, req_class %d\n", __FUNCTION__, channel, beacon->req_class);
	//beacon->channel = channel;
	beacon->req_class = 0;
	beacon->channel = channel;
	beacon->rand_int = 0;
	beacon->dur = 500;
	beacon->mode = 0;//1;  //0 = passive
	for(i=0; i<6; i++)
		beacon->bssid[i]=0xFF;
	
	ssid_ele = (struct subelement *)p;
	p = p + BCN_SUB_BASE_LEN + ssid_len;	
	ssid_ele->ID = 0;
	ssid_ele->length = ssid_len;
	memcpy(&(ssid_ele->data), (unsigned char*)ssid, ssid_len);
	
//	rep_info = (struct subelement *)p;
//	p = p + BCN_SUB_BASE_LEN + 2;
//	rep_info->ID = 1;
//	rep_info->length = 2;
//	rep_info->data = 0;	
//	*(&(rep_info->data)+1) = 0;	

	rep_detail = (struct subelement *)p;
	p = p + BCN_SUB_BASE_LEN + 1;	
	rep_detail->ID = 2;
	rep_detail->length = 1;
	rep_detail->data = 0;

	request = (struct subelement *)p;
	p = p + BCN_SUB_BASE_LEN + 1;	
	request->ID = 10;
	request->length = 1;
	request->data = 0;
/*
	multi_channel = (struct subelement *)p;
	multi_channel->ID = 51;
	//multi_channel->length = 1;
	multi_channel->data = 0; //operating class

	int num = 0;
	if(bssidx > 0) {
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			num++;
		}
		//For Dual Band Device 
		if(num == 2) {
			channel2 = nvram_get_int("multi_channel_5g");
		} else if(num == 3) {
			if(bssidx == 1) {
				channel2 = rast_get_channel(2, vifidx);
			} else if(bssidx == 2){
				channel2 = rast_get_channel(1, vifidx);
			}
		}
		if(channel2 > 0) {
			*(&(multi_channel->data)+2) = channel2;
			i = 2;
		}
	}
	*(&(multi_channel->data)+1) = channel;
	multi_channel->length = 1 + i;
	p = p + BCN_SUB_BASE_LEN + 1 + i;
	measurement->length += BCN_SUB_BASE_LEN + 1 + i;
*/

	int data_len = p - data;
#if 0
	_dprintf("actframe len %d actframe:\n", data_len);
	for(i = 0; i<data_len; i++)
		_dprintf("%02x", data[i]);
	_dprintf("\n");
#endif
	wl_af_params_t * af_params;
	wl_action_frame_t * action_frame;
	struct ether_addr ea;
	char ioctl_buf[4096];
	int buflen;
	char *param;

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "actframe");
	buflen = strlen(ioctl_buf) + 1;
	param = (char *)(ioctl_buf + buflen);

	af_params = (wl_af_params_t *)param;
	action_frame = &af_params->action_frame;
	memcpy(&action_frame->da, sta, ETHER_ADDR_LEN);
	action_frame->packetId = (uint32)(uintptr)action_frame;
	action_frame->len = data_len;
	af_params->channel = 0;
	af_params->dwell_time = -1; // use broadcom default value
	
	if (!ether_atoe(hw_addr, (unsigned char *)&ea)) {
		_dprintf(" ERROR: no valid ether addr provided\n");
		return ;
	}

	memcpy(&af_params->BSSID, &ea, ETHER_ADDR_LEN);
	memcpy(action_frame->data, data, action_frame->len);

	wl_ioctl(wlif_name, WLC_SET_VAR, ioctl_buf, WL_WIFI_AF_PARAMS_SIZE);
}
int rast_start_bcn_rpt();
//create thread for listen udp port to receive bcn report event
void rast_bcn_rpt_init(void) {
	pthread_t thread;
	pthread_attr_t attr;

	RAST_DBG("Start beacon report thread.\n");

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread,NULL,(void *)&rast_start_bcn_rpt,NULL);
	pthread_attr_destroy(&attr);

}

static int eventd_eapd_socket_init(void)
{
	int reuse = 1;
	struct sockaddr_in sockaddr;
	int event_socket = -1;

	/* open loopback socket to communicate with EAPD */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_EVENTD_UDP_SPORT);

	if ((event_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		RAST_DBG("Unable to create loopback socket\n");
		return -1;
	}

	if (setsockopt(event_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		RAST_DBG("Unable to setsockopt to loopback socket %d.\n", event_socket);
		goto exit1;
	}

	if (bind(event_socket, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		RAST_DBG("Unable to bind to loopback socket %d\n", event_socket);
		goto exit1;
	}

	RAST_DBG("opened loopback socket %d\n", event_socket);
	return event_socket;

	/* error handling */
exit1:
	close(event_socket);
	return -1;
}
#if 0
static void eventd_hexdump_ascii(const char *title, char *buf, int len)
{
	int i;

	_dprintf("%s[%d]:", title, len);
	for (i = 0; i < len; i++) {
		if ((i&0xf) == 0)
			_dprintf("\n%04x: ", i);
		_dprintf("%02X ", buf[i]);
	}
	_dprintf("\n\n");
}
#endif
#ifdef RTCONFIG_11K_RCPI_CHECK
struct bcn_rpt_entry {
	struct ether_addr addr;
	struct rcpi_checklist *rcpi_list;
	int first_rcv_time;
	struct bcn_rpt_entry *next;
};

struct bcn_rpt_entry *bcn_rpt_list_head;
#endif
static void eventd_main_loop(int sock)
{
	struct timeval tv = {1, 0};    /* timed out every second */
	fd_set fdset;
	int status, fdmax;

	char tmp[32];
	char pkt[EVENTD_BUFSIZE_4K];
	int bytes, len;

	bcm_event_t *pvt_data;
	wl_rrm_event_t *evt;
	struct ether_header *eth_hdr = (struct ether_header *)(pkt + IFNAMSIZ);
	uint16 ether_type = 0;
	uint32 evt_type;

	dot11_rm_ie_t *ie;
	dot11_rmrep_bcn_t *rmrep_bcn;

#ifdef RTCONFIG_11K_RCPI_CHECK
	char tmp_stamac[32],tmp_apmac[32];
	struct rcpi_checklist *rcpi_list=NULL;
	struct rcpi_checklist *rcpi_list_tmp=NULL;
	struct report_entry   *report_entry_tmp=NULL;
	int i,rpt_found;
	struct bcn_rpt_entry *bcn_rpt_list_tmp;
	struct bcn_rpt_entry *bcn_rpt_list_pre;
	struct ether_addr ea_tmp,sta_tmp,ap_tmp;
#endif

	FD_ZERO(&fdset);
	fdmax = -1;

	if (sock >= 0) {
		FD_SET(sock, &fdset);
		if (sock > fdmax)
			fdmax = sock;
	}
	else {
		RAST_DBG("Err: wrong socket\n");
		return;
	}
#ifdef RTCONFIG_11K_RCPI_CHECK
//	RAST_DBG("RCPI_CHECK\n");
	bcn_rpt_list_tmp = bcn_rpt_list_head;
	bcn_rpt_list_pre = NULL;
	while(1) {
		if(!bcn_rpt_list_tmp)
			break;

		if( uptime() - bcn_rpt_list_tmp->first_rcv_time > 1 ) {
			rcpi_list = bcn_rpt_list_tmp->rcpi_list;

			check_rcpilist_and_translate_to_rssi(rcpi_list);

			while(1){
				if(!rcpi_list)
					break;
				while(1) {
					if(!rcpi_list->rplist)
						break;
					if(rcpi_list->report_ok) {
						RAST_DBG("set to json file %s %s %d\n",
							rcpi_list->sta_mac,rcpi_list->rplist->ap_mac,rcpi_list->rplist->rcpi);

						memcpy(&sta_tmp,rast_ether_atoe(rcpi_list->sta_mac,&ea_tmp),sizeof(struct ether_addr));
						memcpy(&ap_tmp,rast_ether_atoe(rcpi_list->rplist->ap_mac,&ea_tmp),sizeof(struct ether_addr));

						rast_update_beacon_report(&sta_tmp, &ap_tmp, (int8)rcpi_list->rplist->rcpi);
					}
					report_entry_tmp = rcpi_list->rplist;
					rcpi_list->rplist = rcpi_list->rplist->next;
					free(report_entry_tmp);
				}
				//lantiq_rast_update_beacon_report_ret(rcpi_list->sta_mac,rcpi_list->rplist->ap_mac,rcpi_list->rplist->rcpi);
				rcpi_list_tmp = rcpi_list;
				rcpi_list = rcpi_list->next;
				free(rcpi_list_tmp);
			}
			if(bcn_rpt_list_pre != NULL) {
				bcn_rpt_list_pre->next = bcn_rpt_list_tmp->next;
				free(bcn_rpt_list_tmp);
				bcn_rpt_list_tmp = bcn_rpt_list_pre->next;
			} else {//head release
				bcn_rpt_list_head = bcn_rpt_list_tmp->next;
				free(bcn_rpt_list_tmp);
				bcn_rpt_list_tmp = bcn_rpt_list_head;
			}

		} else {
			bcn_rpt_list_pre = bcn_rpt_list_tmp;
			bcn_rpt_list_tmp = bcn_rpt_list_tmp->next;
		}


	}
#endif //RTCONFIG_11K_RCPI_CHECK

	status = select(fdmax+1, &fdset, NULL, NULL, &tv);
	if ((status > 0) && FD_ISSET(sock, &fdset)) {
		if ((bytes = recv(sock, pkt, EVENTD_BUFSIZE_4K, 0)) > IFNAMSIZ) {
			if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
				RAST_DBG("recved ether type %x\n", ether_type);
				return;
			}


			pvt_data = (bcm_event_t *)(pkt + IFNAMSIZ);
			evt_type = ntoh32(pvt_data->event.event_type);

			RAST_DBG("Received event %d, MAC=%s\n",
				evt_type, ether_etoa(pvt_data->event.addr.octet, tmp));
			len = bytes - IFNAMSIZ - sizeof(*pvt_data);

			evt = (wl_rrm_event_t *)(pvt_data + 1);
			RAST_DBG("version:0x%02x len:0x%02x cat:0x%02x subversion:0x%02x\n",
				evt->version, evt->len, evt->cat, evt->subevent);

			if (evt->cat == DOT11_RM_ACTION_LM_REP) {
				return;
			}

			if (evt->cat == DOT11_RM_ACTION_NR_REP) {
				return;
			}

			if (evt->cat != DOT11_RM_ACTION_RM_REP) {
				return;
			}
			switch (evt->subevent) {
				case DOT11_MEASURE_TYPE_BEACON:
					RAST_DBG("DOT11_MEASURE_TYPE_BEACON\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_bcn = (dot11_rmrep_bcn_t *)&ie[1];
#ifdef RTCONFIG_11K_RCPI_CHECK

					if( bcn_rpt_list_head ) {
						bcn_rpt_list_tmp = bcn_rpt_list_head;
						rpt_found=0;
						while(1) {
							if(bcn_rpt_list_tmp == NULL)
								break;
							if( !memcmp(&bcn_rpt_list_tmp->addr,&pvt_data->event.addr,sizeof(struct ether_addr)) ) {
								rpt_found = 1;
								break;
							}
							if(bcn_rpt_list_tmp->next == NULL)
								break;
							bcn_rpt_list_tmp = bcn_rpt_list_tmp->next;
						}

						if( !rpt_found ){
							bcn_rpt_list_tmp->next = malloc(sizeof(struct bcn_rpt_entry));
							if(bcn_rpt_list_tmp->next == NULL) {
								RAST_INFO("malloc error\n");
								break;
							}
							memset(bcn_rpt_list_tmp->next,0,sizeof(struct bcn_rpt_entry));
							bcn_rpt_list_tmp = bcn_rpt_list_tmp->next;
							memcpy(&bcn_rpt_list_tmp->addr,&pvt_data->event.addr,sizeof(struct ether_addr));
							bcn_rpt_list_tmp->first_rcv_time = uptime();
						}

					} else {
						bcn_rpt_list_head = malloc(sizeof(struct bcn_rpt_entry));
						if(bcn_rpt_list_head == NULL) {
							RAST_INFO("malloc error\n");
							break;
						}
						memset(bcn_rpt_list_head,0,sizeof(struct bcn_rpt_entry));
						bcn_rpt_list_tmp = bcn_rpt_list_head;
						memcpy(&bcn_rpt_list_tmp->addr,&pvt_data->event.addr,sizeof(struct ether_addr));
						bcn_rpt_list_tmp->first_rcv_time = uptime();						
					}

					strncpy(tmp_stamac,ether_etoa(pvt_data->event.addr.octet, tmp),sizeof(tmp_stamac));
					strncpy(tmp_apmac,ether_etoa((uchar *)&rmrep_bcn->bssid, tmp),sizeof(tmp_apmac));
					add_to_rcpi_checklist( 
						tmp_stamac,
						tmp_apmac,
						(char)rmrep_bcn->rcpi,
						&bcn_rpt_list_tmp->rcpi_list
					);
#else //RTCONFIG_11K_RCPI_CHECK
					rast_update_beacon_report(&pvt_data->event.addr, &rmrep_bcn->bssid, (int8)rmrep_bcn->rcpi);
#endif //RTCONFIG_11K_RCPI_CHECK
					RAST_DBG("%s: channel: %d, duration: %d, "
						"frame info: %d, rcpi: %d, rsni: %d, bssid: %s, "
						"antenna id: %d, parent tsf: %u\n",
						__FUNCTION__, rmrep_bcn->channel,
						rmrep_bcn->duration, rmrep_bcn->frame_info,
						(int8)rmrep_bcn->rcpi, rmrep_bcn->rsni,
						ether_etoa((uchar *)&rmrep_bcn->bssid, tmp),
						rmrep_bcn->antenna_id, rmrep_bcn->parent_tsf);
					break;
				default:
					RAST_DBG("unhandled subtype: 0x%2X\n", evt->subevent);
					break;
			}
		}
	}

	return;
}

int rast_start_bcn_rpt(void) {
	int sock;

	/* UDP socket to eapd init */
	if ((sock = eventd_eapd_socket_init()) < 0) {
		RAST_DBG("Err: fail to init socket\n");
		return sock;
	}

#ifdef RTCONFIG_11K_RCPI_CHECK
	bcn_rpt_list_head = NULL;
#endif

	/* receive wl event from event-eap via UDP */
	while (1) {
		eventd_main_loop(sock);	
	}

	close(sock);
	return 0;
}


void rast_update_beacon_report(struct ether_addr *sta, struct ether_addr *bssid, int8 rcpi) {
	json_object *root = NULL;
	json_object *existApObj = NULL;
	json_object *reportApObj = NULL;
	int lock;
	char rcpiStr[4];
	char ap_mac[]="xx:xx:xx:xx:xx:xx";
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt";

	snprintf(path, sizeof(path), "/tmp/"MACF_UP"_bcn_rpt", ETHERP_TO_MACF(sta));
	snprintf(rcpiStr, sizeof(rcpiStr), "%d", rcpi);
	snprintf(ap_mac, sizeof(ap_mac), MACF_UP, ETHERP_TO_MACF(bssid));

	lock = file_lock(path+5);
	root = json_object_from_file(path);
	if(!root) {
		RAST_DBG("%s,no file or valid content\n", path);
		goto end;
	}

	json_object_object_get_ex(root, ap_mac, &existApObj);
	if (existApObj) {
		RAST_DBG("report AP is exist\n");
		goto end;
	}

	reportApObj = json_object_new_object();
	if (!reportApObj) {
		RAST_DBG("reportApObj is NULL\n");
		goto end;
	}

	json_object_object_add(reportApObj, RAST_RCPI, json_object_new_string(rcpiStr));
	json_object_object_add(root, ap_mac, reportApObj);
	json_object_to_file(path, root);

end:
	json_object_put(root);
	file_unlock(lock);

}
#endif

#if defined(RTCONFIG_BTM_11V)

static int rast_open_eventfd_11v(int *ret_fd)
{
	int reuse = 1;
	struct sockaddr_in sockaddr;
	int fd = -1;

	//BSD_ENTER();
	/* open loopback socket to communicate with event dispatcher */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_WLCEVENTD_UDP_SPORT);

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		RAST_INFO("Unable to create loopback socket\n");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		RAST_INFO("Unable to setsockopt to loopback socket %d.\n", fd);
		goto error;
	}

	if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		RAST_INFO("Unable to bind to loopback socket %d\n", fd);
		goto error;
	}

	//RAST_INFO("test v1 opened loopback socket %d EAPD_WKSP_BTM_UDP_SPORT %d\n", fd,EAPD_WKSP_BTM_UDP_SPORT);

	*ret_fd = fd;

	return 0;

	/* error handling */
error:
	close(fd);

	return -1;
}
/* listen to sockets for bss response event */

/*
#define BTM_RET_ACCEPT_TARGETMAC_NOTSELF	0
#define BTM_RET_ACCEPT_TARGETMAC_SELF		1
#define BTM_RET_REJECT	2
#define BTM_CMD_FAIL	3
#define BTM_TIMEOUT		4
#define BTM_OTHER		5
*/
static int receive_11v_ret_pkt(int fd_11v, struct timeval *tv, char *ifreq, uint8 token,
	struct ether_addr *bssid)
{
	fd_set fdset;
	int fdmax;
	int width, status = 0, bytes;
	char buf_ptr[4096], *pkt = buf_ptr;
	char ifname[IFNAMSIZ+1];
	int pdata_len;
	dot11_bsstrans_resp_t *bsstrans_resp;
	bcm_event_t *dpkt;
	uint32 event_id;
	struct ether_addr *addr;

	/* init file descriptor set */
	FD_ZERO(&fdset);
	fdmax = -1;

	/* build file descriptor set now to save time later */
	FD_SET(fd_11v, &fdset);
	fdmax = fd_11v;
	width = fdmax + 1;

	/* listen to data availible on all sockets */
	status = select(width, &fdset, NULL, NULL, tv);

	if ((status == -1 && errno == EINTR) || (status == 0)) {
		RAST_INFO("No event\n");
		return BTM_OTHER;
	}

	if (status <= 0) {
		RAST_INFO("err from select: %s", strerror(errno));
		return BTM_OTHER;
	}

	/* handle brcm event */
	if (fd_11v !=  -1 && FD_ISSET(fd_11v, &fdset)) {

		memset(pkt, 0, sizeof(buf_ptr));
		if ((bytes = recv(fd_11v, pkt, sizeof(buf_ptr), 0)) <= IFNAMSIZ) {
			RAST_INFO("BSS Transit Response: recv err\n");
			return BTM_OTHER;
		}

/*{
	int i=0;
	for(i=0;i<bytes;i++)
		RAST_INFO("%X ",pkt[i]);
	if( i%13 == 0)
		RAST_INFO("\n");
}*/

		strncpy(ifname, pkt, IFNAMSIZ);
		ifname[IFNAMSIZ] = '\0';

		pkt = pkt + IFNAMSIZ;
		pdata_len = bytes - IFNAMSIZ;

		if (pdata_len <= sizeof(bcm_event_t))
			RAST_INFO("BSS Transit Response: data_len %d too small\n", pdata_len);

		dpkt = (bcm_event_t *)pkt;
		event_id = ntohl(dpkt->event.event_type);

		pkt += sizeof(bcm_event_t); /* payload (bss response) */
		pdata_len -= sizeof(bcm_event_t);

		bsstrans_resp = (dot11_bsstrans_resp_t *)pkt;
		addr = (struct ether_addr *)(bsstrans_resp->data);
		RAST_INFO("BSS Transit Response: ifname=%s, event=%d, "
			"token=%x, status=%d, mac="MACF"\n",
			ifname, event_id, bsstrans_resp->token,
			bsstrans_resp->status, ETHERP_TO_MACF(addr));

		if (bssid == NULL) {
			RAST_INFO("BSS Transit Response: TEST Only\n");
			return BTM_OTHER;
		}

		/* check interface */
		if (strncmp(ifname, ifreq, strlen(ifreq)) != 0) {
			/* not for the requested interface */
			RAST_INFO("BSS Transit Response: not for interface %s\n", ifreq);
			return BTM_OTHER;
		}

		/* check token */
		if (bsstrans_resp->token != token) {
			/* not for the requested interface */
			RAST_INFO("BSS Transit Response: not for token %x\n", token);
			return BTM_OTHER;
		}

		/* reject */
		if (bsstrans_resp->status) {
			RAST_INFO("BSS Transit Response: STA reject\n");
			return BTM_RET_REJECT;
		}

		/* accept, but use another target bssid (original bssid) */
		if (eacmp(bssid, addr) != 0) {
			RAST_INFO("BSS Transit Response: target bssid not same\n");
			return BTM_RET_ACCEPT_TARGETMAC_SELF;
		}
	}

	return BTM_RET_ACCEPT_TARGETMAC_NOTSELF;
}

static uint8 bss_token = 0;
//revi part not finish yat, need add event form driver
int rast_send_11v_req(int bssidx,int vifidx,char *sta_mac, char *candidate_ap_mac)
{
	int ret;
	char *param;
	int buflen;
	int fd;
	struct ether_addr ea_tmp;
	struct ether_addr sta_addr;
	struct ether_addr nbr_bssid;
	char wlif_name[32];
	char ioctl_buf[4096];
	dot11_bsstrans_req_t *transreq;
	dot11_neighbor_rep_ie_t *nbr_ie;
	struct timeval tv; /* timed out for bss response */

	memcpy(&sta_addr,rast_ether_atoe(sta_mac,&ea_tmp),sizeof(struct ether_addr));
	memcpy(&nbr_bssid,rast_ether_atoe(candidate_ap_mac,&ea_tmp),sizeof(struct ether_addr));

	get_wifi_ifname(wlif_name, sizeof(wlif_name), bssidx, vifidx);

	wl_af_params_t *af_params;
	wl_action_frame_t *action_frame;

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "actframe");
	buflen = strlen(ioctl_buf) + 1;
	param = (char *)(ioctl_buf + buflen);

	af_params = (wl_af_params_t *)param;
	action_frame = &af_params->action_frame;

	af_params->channel = 0;
	af_params->dwell_time = -1;

	memcpy(&action_frame->da, (char *)&(sta_addr), ETHER_ADDR_LEN);//sta_mac
	action_frame->packetId = (uint32)(uintptr)action_frame;//??
	/*diff with bsd*/action_frame->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN + 15 + TLV_HDR_LEN + DOT11_BSSTRANS_REQ_LEN;//+3 is Subelement ID: BSS Transition Candidate Preference
	//action_frame->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN + TLV_HDR_LEN + DOT11_BSSTRANS_REQ_LEN;//+3 is Subelement ID: BSS Transition Candidate Preference


	transreq = (dot11_bsstrans_req_t *)&action_frame->data[0];
	transreq->category = DOT11_ACTION_CAT_WNM;
	transreq->action = DOT11_WNM_ACTION_BSSTRANS_REQ;
	if (++bss_token == 0)
		bss_token = 1;
	transreq->token = bss_token;//random?
	transreq->reqmode = DOT11_BSSTRANS_REQMODE_PREF_LIST_INCL;
	/* set bit1 to tell STA the BSSID in list recommended */
	transreq->reqmode |= DOT11_BSSTRANS_REQMODE_ABRIDGED;
	/*diff with bsd*/transreq->reqmode |= DOT11_BSSTRANS_REQMODE_DISASSOC_IMMINENT;
	/*diff with bsd*/transreq->reqmode |= DOT11_BSSTRANS_REQMODE_BSS_TERM_INCL;

	transreq->disassoc_tmr = 0x0000;
	transreq->validity_intrvl = 0x01;//diff with bsd0x01;


	/*diff with bsd*/transreq->data[0] = 0x04;
	/*diff with bsd*/transreq->data[1] = 0x0a;
	/*diff with bsd*/transreq->data[2] = 0x02;
	/*diff with bsd*/transreq->data[3] = 0x00;
	/*diff with bsd*/transreq->data[4] = 0x00;
	/*diff with bsd*/transreq->data[5] = 0x00;
	/*diff with bsd*/transreq->data[6] = 0x00;
	/*diff with bsd*/transreq->data[7] = 0x00;
	/*diff with bsd*/transreq->data[8] = 0x00;
	/*diff with bsd*/transreq->data[9] = 0x00;
	/*diff with bsd*/transreq->data[10] = 0x03;
	/*diff with bsd*/transreq->data[11] = 0x00;
	nbr_ie = (dot11_neighbor_rep_ie_t *)&transreq->data[12];
	nbr_ie->id = DOT11_MNG_NEIGHBOR_REP_ID;
	nbr_ie->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN+3;//16?
	memcpy(&nbr_ie->bssid, &nbr_bssid, ETHER_ADDR_LEN);
	nbr_ie->bssid_info = 0x00000000;
	nbr_ie->reg = rast_get_rclass(bssidx, vifidx);		// assume the same as cueernt ap
	nbr_ie->channel = rast_get_channel(bssidx, vifidx);	// assume the same as current ap
	nbr_ie->phytype = 0x00;//??
	/*diff with bsd*/transreq->data[27] = 0x03;//Subelement ID: BSS Transition Candidate Preference (0x03)
	/*diff with bsd*/transreq->data[28] = 0x01;
	/*diff with bsd*/transreq->data[29] = 0x01;

	rast_open_eventfd_11v(&fd);

	if(wl_ioctl(wlif_name, WLC_SET_VAR, ioctl_buf, WL_WIFI_AF_PARAMS_SIZE)){
		RAST_INFO("Error to send action frame: %s\n", wlif_name);
		close(fd);
		return 0;
	}

	RAST_DBG("send 11v request to %s to move to %s\n",sta_mac,candidate_ap_mac);

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	/* wait for bss response and compare token/ifname/status/bssid etc  */
	//TODO
	//ret = (receive_11v_ret_pkt(fd, &tv, wlif_name, bss_token, &sta_addr));

	close(fd);

	return ret;
}
#endif

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
/* sta_mac & sta is for different platform */
int check_if_support_kv(int unit, int subunit, rast_sta_info_t *sta)
{
	int ret=0;
	if( sta->wnm_cap  )
		ret |= RAST_SUPPORT_V;
	if( sta->rrm_bcn_passive_cap )
		ret |= RAST_SUPPORT_K_PASSIVE_SCAN;
	return ret;
}
#endif//RTCONFIG_BTM_11V

#ifdef RTCONFIG_RAST_NONMESH_KVONLY
int sock_k_resp;

int kv_handler_init(void)
{
	sock_k_resp=-1;

	/* UDP socket to eapd init */
	if ((sock_k_resp = eventd_eapd_socket_init()) < 0) {
		RAST_DBG("Err: fail to init k resp socket\n");
		return -1;
	}
	return 0;
}

int kv_handler_deinit(void)
{
	if(sock_k_resp >= 0) {
		close(sock_k_resp);
		sock_k_resp = -1;
	}
}

void wait_k_resp(struct report_list_entry **rplist,int *num)
{
	struct timeval tv = {1, 0};    /* timed out every second */
	fd_set fdset;
	int status, fdmax;
	int sock = sock_k_resp;

	char tmp[32];
	char pkt[EVENTD_BUFSIZE_4K];
	int bytes, len, i;

	bcm_event_t *pvt_data;
	wl_rrm_event_t *evt;
	struct ether_header *eth_hdr = (struct ether_header *)(pkt + IFNAMSIZ);
	uint16 ether_type = 0;
	uint32 evt_type;

	dot11_rm_ie_t *ie;
	dot11_rmrep_bcn_t *rmrep_bcn;

	FD_ZERO(&fdset);
	fdmax = -1;

	struct report_list_entry *list=*rplist;
	struct report_list_entry *pre=NULL;

	if (sock >= 0) {
		FD_SET(sock, &fdset);
		if (sock > fdmax)
			fdmax = sock;
	}
	else {
		RAST_DBG("Err: wrong socket\n");
		return;
	}
	status = select(fdmax+1, &fdset, NULL, NULL, &tv);
	if ((status > 0) && FD_ISSET(sock, &fdset)) {
		if ((bytes = recv(sock, pkt, EVENTD_BUFSIZE_4K, 0)) > IFNAMSIZ) {
			if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
				RAST_DBG("recved ether type %x\n", ether_type);
				return;
			}


			pvt_data = (bcm_event_t *)(pkt + IFNAMSIZ);
			evt_type = ntoh32(pvt_data->event.event_type);

			RAST_DBG("Received event %d, MAC=%s\n",
				evt_type, ether_etoa(pvt_data->event.addr.octet, tmp));
			len = bytes - IFNAMSIZ - sizeof(*pvt_data);

			evt = (wl_rrm_event_t *)(pvt_data + 1);
			RAST_DBG("version:0x%02x len:0x%02x cat:0x%02x subversion:0x%02x\n",
				evt->version, evt->len, evt->cat, evt->subevent);

			if (evt->cat == DOT11_RM_ACTION_LM_REP) {
				return;
			}

			if (evt->cat == DOT11_RM_ACTION_NR_REP) {
				return;
			}

			if (evt->cat != DOT11_RM_ACTION_RM_REP) {
				return;
			}
			switch (evt->subevent) {
				case DOT11_MEASURE_TYPE_BEACON:
					RAST_DBG("DOT11_MEASURE_TYPE_BEACON\n");
					ie = (dot11_rm_ie_t *)(evt->payload);
					rmrep_bcn = (dot11_rmrep_bcn_t *)&ie[1];
					//rast_update_beacon_report(&pvt_data->event.addr, &rmrep_bcn->bssid, (int8)rmrep_bcn->rcpi);
					i=0;
					while(1) //if rplist , *num is 0
					{
						if( !(*rplist) ) //empty list
						{
							*rplist = malloc(sizeof(struct report_list_entry));
							if( (*rplist) == NULL)
							{
								_dprintf("malloc error\n");
								break;
							}
							memset((*rplist),0,sizeof(sizeof(struct report_list_entry)));
							memcpy(&(*rplist)->sta,&pvt_data->event.addr,sizeof(struct ether_addr));
							memcpy(&(*rplist)->bssid,&rmrep_bcn->bssid,sizeof(struct ether_addr));
							(*rplist)->rcpi = (int8)rmrep_bcn->rcpi;
							(*rplist)->recv_time = uptime();
							(*rplist)->next = NULL;
							(*num)++;
							break;
						}

						if( !memcmp(&list->sta,&pvt_data->event.addr,sizeof(struct ether_addr)) )
						{
							if((int8)list->rcpi < (int8)rmrep_bcn->rcpi) {

								memcpy(&list->bssid,&rmrep_bcn->bssid,sizeof(struct ether_addr));
								list->rcpi = (int8)rmrep_bcn->rcpi;
							}
							list->recv_time = uptime();
							break;
						}

						if( list->next == NULL )
						{
							list->next = malloc(sizeof(struct report_list_entry));
							if(list->next == NULL)
							{
								_dprintf("malloc error\n");
								break;
							}
							list = list->next;
							memset(list,0,sizeof(sizeof(struct report_list_entry)));
							memcpy(&list->sta,&pvt_data->event.addr,sizeof(struct ether_addr));
							memcpy(&list->bssid,&rmrep_bcn->bssid,sizeof(struct ether_addr));
							list->rcpi = (int8)rmrep_bcn->rcpi;
							list->recv_time = uptime();
							list->next = NULL;
							(*num)++;
							break;
						}

						list = list->next;
					}

					RAST_DBG("%s: channel: %d, duration: %d, "
						"frame info: %d, rcpi: %d, rsni: %d, bssid: %s, "
						"antenna id: %d, parent tsf: %u\n",
						__FUNCTION__, rmrep_bcn->channel,
						rmrep_bcn->duration, rmrep_bcn->frame_info,
						rmrep_bcn->rcpi, rmrep_bcn->rsni,
						ether_etoa((uchar *)&rmrep_bcn->bssid, tmp),
						rmrep_bcn->antenna_id, rmrep_bcn->parent_tsf);
					break;
				default:
					RAST_DBG("unhandled subtype: 0x%2X\n", evt->subevent);
					break;
			}
		}
	}

	return;
}
int is_support_rast_nonmesh(void)
{
	if( !strcmp( nvram_safe_get("odmpid"),"RP-AC1900" ) )
		return 1;

	return 0;
}
#endif//RTCONFIG_RAST_NONMESH_KVONLY

#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_get_driver_maclist(int idx,int vidx,char *maclist_buf_local,int buf_size,int *static_macmode)
{
	int ret=0;
	char wlif_name[64];
	struct maclist *maclist = (struct maclist *) maclist_buf_local;

	get_wifi_ifname(wlif_name, sizeof(wlif_name), idx, vidx);

	ret = wl_ioctl(wlif_name, WLC_GET_MACMODE, static_macmode, sizeof(int));
	if(ret < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", wlif_name);
		return 0;
	}

	RAST_DBG("check driver mac list[%s] mac mode = %s\n",
	wlif_name,
	*static_macmode==WLC_MACMODE_DISABLED ? "DISABLE" :
	*static_macmode==WLC_MACMODE_DENY ? "DENY" : "ALLOW");

	ret = wl_ioctl(wlif_name, WLC_GET_MACLIST, (void *)maclist, buf_size );
	if(ret < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", wlif_name);
		return 0;
	}

	return 1;
}

int rast_check_driver_maclist(char *maclist_buf_local,int static_macmode,struct ether_addr *addr)
{
	int  size;
	int maclist_match=0;
	struct maclist *maclist = (struct maclist *) maclist_buf_local;

	if( static_macmode == 0 )
		return -1;

	if (maclist->count > 0 && maclist->count < 128) {
		size = sizeof(uint) + sizeof(struct ether_addr) * (maclist->count + 1);

		RAST_DBG("count[%d] size[%d]\n", maclist->count, size);

		for (size = 0; size < maclist->count; size++) {
			if(!memcmp(&maclist->ea[size],addr,sizeof(struct ether_addr))){
				//RAST_DEBUG("match\n");
				maclist_match=1;
			}
		}
		if(!maclist_match && static_macmode == WLC_MACMODE_DENY)
			return -1;
		else if(maclist_match && static_macmode != WLC_MACMODE_DENY )
			return -1;
	} else if (maclist->count != 0) {
		RAST_INFO("Err: maclist cnt [%d] too large\n", maclist->count);
		return 0;
	}
	return 0; 
}
#endif
