#include <sys/reboot.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <rc.h>
#include <shared.h>
#ifdef HND_ROUTER
#include <sys/stat.h>
#endif
#ifdef RTCONFIG_CFGSYNC
#include <sys/shm.h>
#include <cfg_ipc.h>
#include <cfg_slavelist.h>
#include <cfg_string.h>
#endif

#include <bcmendian.h>
#include <wlioctl.h>
#include <wlutils.h>
#include <json.h>
#include <amas_path.h>
#include <amas_adtbw.h>

#define MAX_STA_COUNT 128
#define MAX_SUBIF_NUM 4

#define CHANSPEC_LIST_JSON_PATH "/tmp/chanspec_all.json"

//static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))

#if defined(RTCONFIG_HND_ROUTER_AX_675X) || defined(RTCONFIG_HND_ROUTER_AX_6710) || defined(RTCONFIG_BCM_502L07P2)
#if defined(RTCONFIG_SDK502L07P1_121_37)
#define CHANNELSPEC_V1	/* SDK5072L07P1_121_37 */
extern uint16 wf_channel2chspec(uint ctl_ch, uint bw);
#else
#define CHANNELSPEC_V2	/* new SDK */
extern uint16 wf_channel2chspec(uint ctl_ch, uint bw, uint wl_chanspec_band);
#endif
#elif defined(RTCONFIG_HND_ROUTER_AX_6756)
#define CHANNELSPEC_V3	/* new SDK */
extern uint16 wf_channel2chspec(uint ctl_ch, uint bw, uint wl_chanspec_band);
#else
#define CHANNELSPEC_V1	/* other */
extern uint16 wf_channel2chspec(uint ctl_ch, uint bw);
#endif

#ifdef RTCONFIG_ADTBW_AFTER_RADARDETECTED

int check_chanspec_if_match_usersetting(int idx,chanspec_t current_chanspec,chanspec_t *user_chanspec)
{
	char buf[256];
	char chanspec_nvram[32];

	snprintf(chanspec_nvram,sizeof(chanspec_nvram),"wl%d_chanspec",idx);

	snprintf(buf,sizeof(buf),"%s",nvram_safe_get(chanspec_nvram));

	if(strlen(buf))
	{
		*user_chanspec = wf_chspec_aton(buf);
		return (current_chanspec == *user_chanspec);
	}

	return 0;

}
#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED

chanspec_t amas_adtbw_get_chanspec(char* ifname)
{
	char buf[256] = {0};
	int chansp = 0;
	chanspec_t chanspec = 0;

	if (wl_iovar_getint(ifname, "chanspec", &chansp) < 0) {
		AMAS_ADTBW_DBG("Get chanspec iovar failed...\n");
	}
	else {
		chanspec = (chanspec_t)dtoh32(chansp);
		wf_chspec_ntoa(chanspec, buf);
		AMAS_ADTBW_DBG("%s: %s (0x%x)\n", ifname, buf, chanspec);
	}

	return chanspec;
}

static int amas_adtbw_check_re_bh_conn_path(char* MacAddr)
{
	int node_order;
	int lock;
	int shm_client_tbl_id;
	P_CM_CLIENT_TABLE p_client_tbl;
	void *shared_client_info = (void *)0;
	char mac_5g[32] = {0};
	char mac_5g1[32] = {0};
	char mac_dwb[32] = {0};
	int activePath = -1;

	lock = file_lock(CFG_FILE_LOCK);
	shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
	if (shm_client_tbl_id == -1){
		AMAS_ADTBW_DBG("shmget failed\n");
		file_unlock(lock);
		return 0;
	}

	shared_client_info = shmat(shm_client_tbl_id, (void *)0, 0);
	if (shared_client_info == (void *)-1){
		AMAS_ADTBW_DBG("shmat failed");
		file_unlock(lock);
		return 0;
	}

	p_client_tbl = (P_CM_CLIENT_TABLE)shared_client_info;
	for(node_order = 0; node_order < p_client_tbl->count; node_order++){
		snprintf(mac_5g, sizeof(mac_5g), MACF_UP,
			p_client_tbl->ap5g[node_order][0], p_client_tbl->ap5g[node_order][1],
			p_client_tbl->ap5g[node_order][2], p_client_tbl->ap5g[node_order][3],
			p_client_tbl->ap5g[node_order][4], p_client_tbl->ap5g[node_order][5]);

		snprintf(mac_5g1, sizeof(mac_5g1), MACF_UP,
			p_client_tbl->ap5g1[node_order][0], p_client_tbl->ap5g1[node_order][1],
			p_client_tbl->ap5g1[node_order][2], p_client_tbl->ap5g1[node_order][3],
			p_client_tbl->ap5g1[node_order][4], p_client_tbl->ap5g1[node_order][5]);


		snprintf(mac_dwb, sizeof(mac_dwb), MACF_UP,
			p_client_tbl->apDwb[node_order][0], p_client_tbl->apDwb[node_order][1],
			p_client_tbl->apDwb[node_order][2], p_client_tbl->apDwb[node_order][3],
			p_client_tbl->apDwb[node_order][4], p_client_tbl->apDwb[node_order][5]);

		if(!strcmp(mac_5g, MacAddr) || !strcmp(mac_5g1, MacAddr) || !strcmp(mac_dwb, MacAddr))
		{
    			activePath = p_client_tbl->activePath[node_order];
			AMAS_ADTBW_DBG("MAC:%s activePath:%d\n", MacAddr, activePath);
			break;
		}
	}

	shmdt(shared_client_info);
	file_unlock(lock);

	return activePath;
}


static int amas_adtbw_check_re_backhaul_5g(char* MacAddr)
{
	char *nv, *nvp, *b;
	char *reMac, *mac2g, *mac5g, *timestamp;
	int state = -1;
	int activePath = 0;

	nv = nvp = strdup(nvram_safe_get("cfg_relist"));
	if (nv) {
	    while ((b = strsep(&nvp, "<")) != NULL) {
		if ((vstrsep(b, ">", &reMac, &mac2g, &mac5g, &timestamp) != 4)) {
		    continue;
		}
		if (strstr(mac5g, MacAddr) != NULL) {
		    activePath = amas_adtbw_check_re_bh_conn_path(MacAddr);
			if (!activePath) /* backhaul active path does not update */
			    state = 0;
			else if (activePath & (WL_5G | WL_5G_1)) { /* skip 2.4G and ethernet backhaul */
			    state = 1;
			    break;
			}
		}
	    }
	    free(nv);
	}

	return state;
}

static int amas_adtbw_check_bw160_cap_re(char* MacAddr)
{
    json_object *fileRoot = NULL;
    json_object *bandObj = NULL;
    json_object *bandNumObj = NULL;
    json_object *isReObj = NULL;
    json_object *bwObj = NULL;
    char uMac[18] = {0};
    int wlif_num = 0;
    int bw_cap = 0;

    fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
    if (!fileRoot) {
	AMAS_ADTBW_DBG("error of chanspec file");
	return 0;
    }

    json_object_object_foreach(fileRoot, key, val){
	strlcpy(uMac, key, sizeof(uMac));
	bandObj = val;
	json_object_object_get_ex(bandObj, CFG_STR_BANDNUM, &bandNumObj);
	json_object_object_get_ex(bandObj, CFG_STR_IS_RE, &isReObj);
	
	if (isReObj && !json_object_get_int(isReObj)) {
	    continue;
	}
	
	if(bandNumObj) {
	    wlif_num = json_object_get_int(bandNumObj);
	}

	json_object_object_foreach(bandObj, key, val) {
		if ((wlif_num > 2 && !strcmp(key, CFG_STR_5G1)) || (wlif_num == 2 && !strcmp(key, CFG_STR_5G))) {
			json_object_object_get_ex(val, CFG_STR_BANDWIDTH, &bwObj);
			if (bwObj) {
			    	bw_cap = json_object_get_int(bwObj);
				AMAS_ADTBW_DBG("MAC: %s, bw_cap:%d\n", uMac, bw_cap);
			}
		}
	}

    }

    json_object_put(fileRoot);

    return bw_cap & WLC_BW_CAP_160MHZ;

}

static int amas_adtbw_check_bw160_cap()
{
    uint32_t bw_cap;
    union ioval_u {
	char buf[WLC_IOCTL_MAXLEN];
	uint32_t val;
    } u;

    struct {
	uint32_t band;
	uint32_t bw_cap;
    } param = { 0, 0 };

    strcpy(u.buf, "bw_cap");
    param.band = 1;
    memcpy(u.buf + strlen(u.buf) + 1, (void *)&param, sizeof(param));

    if (wl_ioctl(adtbw_config.ifname, WLC_GET_VAR, u.buf, sizeof(u.buf)) < 0) {
	AMAS_ADTBW_DBG("error to read bw_cap\n");
	return 0;
    }

    bw_cap = dtoh32(u.val);
    return bw_cap & WLC_BW_CAP_160MHZ;

}

static int amas_adtbw_get_dfs_chan_stats(uint8 *remain)
{
    char buf[32];
	int channel, first, last = MAXCHANNEL, minutes;
	uint32 chanspec;
	uint bitmap;
	int det_oos = 0;

	memset(buf, 0, sizeof(buf));

	for (first = 0; first <= last; first++) {
		channel = first;
#if defined(CHANNELSPEC_V3)
		chanspec = CH20MHZ_CHSPEC(channel, WL_CHANSPEC_BAND_5G);
#else
		chanspec = CH20MHZ_CHSPEC(channel);
#endif
		strcpy(buf, "per_chan_info");
		memcpy((char *)(buf + strlen(buf) + 1), (char*)&chanspec, sizeof(chanspec));

		if (wl_ioctl(adtbw_config.ifname, WLC_GET_VAR, buf, sizeof(buf)) < 0)
			break;
		
		bitmap = dtoh32(*(uint *)buf);
		minutes = (bitmap >> 24) & 0xff;

		if (bitmap & WL_CHAN_INACTIVE) {
			AMAS_ADTBW_DBG("[CH%d] Out Of Service %d minutes\n", channel, minutes);
			*remain = minutes > 0 ? minutes : 1;
			det_oos = 1;
			break;
		}
	}

    return det_oos;
}

int amas_adtbw_dont_check(chanspec_t chsp)
{
	int idx = 0;
	int val = -1;

	if (!nvram_match("wlready", "1"))
		return 1;

	if(!nvram_match("cfg_rejoin", "1") && CHSPEC_IS80(chsp)) {
		/* Reset stop switch 160MHz flag once RE is offline */
		if(adtbw_state.stop_switch_160m)
			adtbw_state.stop_switch_160m = 0;
		if(adtbw_state.first_re_assoc)
			adtbw_state.first_re_assoc = 0;

		return 1;
	}

	if(!adtbw_config.multiple_re && nvram_get_int("cfg_recount") > 1 && !CHSPEC_IS160(chsp))
		return 1;

    wl_ioctl(adtbw_config.ifname, WLC_GET_INSTANCE, &idx, sizeof(idx));
    if (adtbw_config.unit != idx)
	return 1;

    wl_ioctl(adtbw_config.ifname, WLC_GET_BAND, &val, sizeof(val));
    if (val != WLC_BAND_5G)
	return 1;

    wl_ioctl(adtbw_config.ifname, WLC_GET_UP, &val, sizeof(val));
    if(!val)
	return 1;
    
    return 0;
}

#ifdef RTCONFIG_ADTBW_AFTER_RADARDETECTED
int amas_adtbw_enable_after_radar(void)
{
	if (!is_router_mode() && !access_point_mode())
		return 0;
	if(!adtbw_config.unit)
		return 0;
	if(adtbw_config.sku == AMAS_ADTBW_SKU_UNSUPPORT)
		return 0;
}
#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED

int amas_adtbw_enable(void)
{
    char tmp[32];

    if (nvram_match("amas_adtbw_stop", "1"))
	return 0;

    if (!is_router_mode() && !access_point_mode())
	return 0;

    if(!adtbw_config.unit)
	return 0;

    /* only support US SKU currently */
    if(adtbw_config.sku == AMAS_ADTBW_SKU_UNSUPPORT)
	return 0;

    /* does not support 5G band3 or band4 */
    snprintf(tmp, sizeof(tmp), "wl%d_band5grp", adtbw_config.unit);
    if(!(nvram_get_hex(tmp) & WL_5G_BAND_3))
	return 0;

    /* does not enable 160MHz bandwidth */
    if(!amas_adtbw_check_bw160_cap())
	return 0;

    /* using fixed bandwidth or fixed channel */
    snprintf(tmp, sizeof(tmp), "wl%d_bw", adtbw_config.unit);
    if(nvram_get_int(tmp) != 0)
	return 0;

    snprintf(tmp, sizeof(tmp), "wl%d_chanspec", adtbw_config.unit);
    if(nvram_get_int(tmp) != 0)
	return 0;

    return 1;
}

int amas_adtbw_check_bw_switch(chanspec_t chanspec, int *do_imdtly)
{
	struct maclist *mac_list;
	int mac_list_size;
	int mcnt;
	scb_val_t scb_val;
	int rssi;
	int bw_switch = 0;
	uint8 channel_cur;
	int re_count = 0;
	char chanbuf[CHANSPEC_STR_LEN];
	int re_state = -1;

	mac_list_size = sizeof(mac_list->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	mac_list = malloc(mac_list_size);
	if(!mac_list) {
	    goto exit;
	}

	/* query authentication sta list */
	strcpy((char*) mac_list, "authe_sta_list");
	if(wl_ioctl(adtbw_config.ifname, WLC_GET_VAR, mac_list, mac_list_size)) {
	    goto exit;
	}

	channel_cur = wf_chspec_ctlchan(chanspec);

	for(mcnt=0; mcnt < mac_list->count; mcnt++) {

	    /* check if RE and 5G backhaul*/
	    re_state = amas_adtbw_check_re_backhaul_5g(wl_ether_etoa(&mac_list->ea[mcnt]));
	    if (re_state == -1)
		continue;
	    else {
		/* first RE is associated, start LED solid green */
		if(!adtbw_state.first_re_assoc) {
		    adtbw_state.first_re_assoc = 1;
		    adtbw_state.time_first_re_assoc = uptime();
		}

		if(!re_state)	/* RE 5G is associated but backhaul active path does not update */
			continue;
	    }

	    /* if RE but w/o 160MHz capability, using Band4/BW80 */
	    if(!amas_adtbw_check_bw160_cap_re(wl_ether_etoa(&mac_list->ea[mcnt])))
	    {
		if(CHSPEC_IS160(chanspec))
		    bw_switch = 1;
		else
		    bw_switch = 0;

		break;
	    }

	    re_count++;

	    /* get rssi of authenticated RE node */
	    memcpy(&scb_val.ea, &mac_list->ea[mcnt], ETHER_ADDR_LEN);
	    if(wl_ioctl(adtbw_config.ifname, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t))) continue;
	    rssi = scb_val.val;
	    AMAS_ADTBW_DBG("%s: rssi: %d\n", wl_ether_etoa(&mac_list->ea[mcnt]), rssi);

	    /* check bw switch:
	     * If Band4/BW80: rssi > rssi_bw80, then switch Band3/BW160
	     * If Band3/BW160: if rssi < rssi_bw160, then switch Band4/BW80
	     */
	    if(rssi < 0 &&
		    ((CHSPEC_IS80(chanspec) && channel_cur >= 100 && rssi > adtbw_config.rssi_bw80) ||
		    (CHSPEC_IS160(chanspec) && (channel_cur >= 100 && channel_cur <= 144) && rssi < adtbw_config.rssi_bw160))) {
			bw_switch = 1;
	    }
	}

	adtbw_state.re_count = re_count;

	/* If there is no RE connected and CAP locate at 160MHz BW, then then switch Band4/BW80 */
	if(re_count == 0) {
	       	if(nvram_get_int("cfg_rejoin") == 0 && CHSPEC_IS160(chanspec)) {
			    bw_switch = 1;
			    *do_imdtly = 1;
		}
	}
	else if(re_count == 1) {
	/* Stop to attempt switch bw160 if ever performed */
	    	if(CHSPEC_IS80(chanspec) && bw_switch && adtbw_state.stop_switch_160m)
		    	bw_switch = 0;
	}
	else {
	/* If there are more than 1 RE connected, using Band4/BW80 */
	    	if (CHSPEC_IS160(chanspec))
		    	bw_switch = 1;
		else
		    	bw_switch = 0;
	}


	AMAS_ADTBW_DBG("chanspec = %s re_count = %d, bw_switch = %d %s\n",
		wf_chspec_ntoa(chanspec, chanbuf), re_count, bw_switch, adtbw_state.stop_switch_160m ? "(STOP SWITCH 160M)":"");

exit:
	if(mac_list) free(mac_list);

	return bw_switch;
}

int amas_adtbw_do_bw_switch(chanspec_t chanspec_cur, int switch_bw160)
{
	char tmp[64];
	chanspec_t chanspec;
	char chanbuf[CHANSPEC_STR_LEN];
	char chanbuf1[CHANSPEC_STR_LEN];
	bool param = TRUE;
	uint8 channel_cur;

	channel_cur = wf_chspec_ctlchan(chanspec_cur);

	if(switch_bw160) {
		/* switch to 160MHz chanspec, perform ZWDFS */
		AMAS_ADTBW_DBG("current chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec_cur, chanbuf), chanspec_cur);

#if defined(CHANNELSPEC_V2) || defined(CHANNELSPEC_V3)
		if(channel_cur >= 100 && channel_cur < 149)
			chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_160, WL_CHANSPEC_BAND_5G);
		else
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B3, WL_CHANSPEC_BW_160, WL_CHANSPEC_BAND_5G);
#else
		if(channel_cur >= 100 && channel_cur < 149)
			chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_160);
		else
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B3, WL_CHANSPEC_BW_160);
#endif
		AMAS_ADTBW_DBG("selected chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec, chanbuf), chanspec);
		if(amas_adtbw_get_dfs_chan_stats(&adtbw_state.dfs_block_remain)) {
			AMAS_ADTBW_DBG("!!! radar signal detect, stop bandwidth switch in %d minutes...\n", adtbw_state.dfs_block_remain);
			return AMAS_ADTBW_BW_SWITCH_RADAR_DET;
		}

		if (wl_cap(adtbw_config.unit, "bgdfs")) {
			if(wl_iovar_setint(adtbw_config.ifname, "dfs_ap_move", chanspec))
				return AMAS_ADTBW_BW_SWITCH_FAILURE;
			else
				logmessage("amas_adtbw", "switch channel spec from %s to %s",
					wf_chspec_ntoa(chanspec_cur, chanbuf), wf_chspec_ntoa(chanspec, chanbuf1));
		}
	}
	else {
		/* switch to 80MHz chanspec */
		AMAS_ADTBW_DBG("current chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec_cur, chanbuf), chanspec_cur);
		snprintf(tmp, sizeof(tmp), "wl%d_band5grp", adtbw_config.unit);
#if defined(CHANNELSPEC_V2) || defined(CHANNELSPEC_V3)
		if(!(nvram_get_hex(tmp) & WL_5G_BAND_4))
		    	chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_80, WL_CHANSPEC_BAND_5G);
		else
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B4, WL_CHANSPEC_BW_80, WL_CHANSPEC_BAND_5G);
#else
		if(!(nvram_get_hex(tmp) & WL_5G_BAND_4))
		    	chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_80);
		else
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B4, WL_CHANSPEC_BW_80);
#endif
		if(wl_iovar_setint(adtbw_config.ifname, "chanspec", chanspec))
		    	return AMAS_ADTBW_BW_SWITCH_FAILURE;
		if(wl_iovar_setint(adtbw_config.ifname, "acs_update", htod32((uint)param)))
		    	return AMAS_ADTBW_BW_SWITCH_FAILURE;
		AMAS_ADTBW_DBG("switch to chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec, chanbuf), chanspec);
		logmessage("amas_adtbw", "switch channel spec from %s to %s",
			wf_chspec_ntoa(chanspec_cur, chanbuf), wf_chspec_ntoa(chanspec, chanbuf1));
    }

    return AMAS_ADTBW_BW_SWITCH_SUCCESS;
}

#ifdef RTCONFIG_ADTBW_AFTER_RADARDETECTED
int amas_adtbw_check_radar_stat(void){
	if(amas_adtbw_get_dfs_chan_stats(&adtbw_state.dfs_block_remain)) {
		AMAS_ADTBW_DBG("!!! radar signal detect, stop bandwidth switch in %d minutes...\n", adtbw_state.dfs_block_remain);
		return AMAS_ADTBW_BW_SWITCH_RADAR_DET;
	}
	return AMAS_ADTBW_BW_SWITCH_RADAR_NOT_DET;
}

int amas_adtbw_do_bw_switch_after_radar(chanspec_t chanspec_cur,uint8 specific_channel, int switch_bw160){
	char tmp[64];
	chanspec_t chanspec;
	char chanbuf[CHANSPEC_STR_LEN];
	char chanbuf1[CHANSPEC_STR_LEN];
	bool param = TRUE;
	uint8 channel_cur;
	char chansps_tmp[4096];
	char chanspec_str[16];
	char abtbw_prefix[16];
	channel_cur = wf_chspec_ctlchan(chanspec_cur);

	snprintf(abtbw_prefix, sizeof(abtbw_prefix), "wl%d_", adtbw_config.unit);

	if(switch_bw160) {
		/* switch to 160MHz chanspec, perform ZWDFS */
		_dprintf("current chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec_cur, chanbuf), chanspec_cur);

		//if( !specific_channel ) {
			snprintf(chanspec_str,sizeof(chanspec_str),"%d/160",channel_cur);
		//} else {
		//	snprintf(chanspec_str,sizeof(chanspec_str),"%d/160",specific_channel);
		//}
		_dprintf("chanspec_str %s\n",chanspec_str);
		snprintf(chansps_tmp,sizeof(chansps_tmp),"%s",nvram_safe_get(strcat_safe(abtbw_prefix, "chansps")));
#if defined(CHANNELSPEC_V2) || defined(CHANNELSPEC_V3)
		if(strstr(chansps_tmp,chanspec_str)!=NULL){//check if cur channel is supprot 160
			//if( !specific_channel )
				chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_160, WL_CHANSPEC_BAND_5G);
			//else
			//	chanspec = wf_channel2chspec(specific_channel, WL_CHANSPEC_BW_160);
		} else {
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B3, WL_CHANSPEC_BW_160, WL_CHANSPEC_BAND_5G);
		}
#else
		if(strstr(chansps_tmp,chanspec_str)!=NULL){//check if cur channel is supprot 160
			//if( !specific_channel )
				chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_160);
			//else
			//	chanspec = wf_channel2chspec(specific_channel, WL_CHANSPEC_BW_160);
		} else {
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B3, WL_CHANSPEC_BW_160);
		}
#endif

		_dprintf("selected chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec, chanbuf), chanspec);

		if (wl_cap(adtbw_config.unit, "bgdfs")) {
			_dprintf("bgdfs\n");
			if(wl_iovar_setint(adtbw_config.ifname, "dfs_ap_move", chanspec))
				return AMAS_ADTBW_BW_SWITCH_FAILURE;
			else
				_dprintf("amas_adtbw ,switch channel spec from %s to %s",
				wf_chspec_ntoa(chanspec_cur, chanbuf), wf_chspec_ntoa(chanspec, chanbuf1));
		}
	} else {
		/* switch to 80MHz chanspec */
		AMAS_ADTBW_DBG("current chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec_cur, chanbuf), chanspec_cur);
		//if( !specific_channel )
			snprintf(chanspec_str,sizeof(chanspec_str),"%d/80",channel_cur);
		//else
		//	snprintf(chanspec_str,sizeof(chanspec_str),"%d/80",specific_channel);
		AMAS_ADTBW_DBG("chanspec_str %s\n",chanspec_str);
		snprintf(chansps_tmp,sizeof(chansps_tmp),"%s",nvram_safe_get(strcat_safe(abtbw_prefix, "chansps")));
#if defined(CHANNELSPEC_V2) || defined(CHANNELSPEC_V3)
		if(strstr(chansps_tmp,chanspec_str)!=NULL){//check if cur channel is supprot 80
			//if( !specific_channel )
				chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_80, WL_CHANSPEC_BAND_5G);
			//else
			//	chanspec = wf_channel2chspec(specific_channel, WL_CHANSPEC_BW_80);
		} else {
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B3, WL_CHANSPEC_BW_80, WL_CHANSPEC_BAND_5G);
		}
#else
		if(strstr(chansps_tmp,chanspec_str)!=NULL){//check if cur channel is supprot 80
			//if( !specific_channel )
				chanspec = wf_channel2chspec(channel_cur, WL_CHANSPEC_BW_80);
			//else
			//	chanspec = wf_channel2chspec(specific_channel, WL_CHANSPEC_BW_80);
		} else {
			chanspec = wf_channel2chspec(AMAS_ADTBW_DFT_CTRLCH_B3, WL_CHANSPEC_BW_80);
		}
#endif

		if(wl_iovar_setint(adtbw_config.ifname, "chanspec", chanspec))
			return AMAS_ADTBW_BW_SWITCH_FAILURE;
		if(wl_iovar_setint(adtbw_config.ifname, "acs_update", htod32((uint)param)))
			return AMAS_ADTBW_BW_SWITCH_FAILURE;
		AMAS_ADTBW_DBG("switch to chanspec: %s (0x%x)\n", wf_chspec_ntoa(chanspec, chanbuf), chanspec);
		logmessage("amas_adtbw", "switch channel spec from %s to %s",
			wf_chspec_ntoa(chanspec_cur, chanbuf), wf_chspec_ntoa(chanspec, chanbuf1));
	}

	return AMAS_ADTBW_BW_SWITCH_SUCCESS;
}
#endif //RTCONFIG_ADTBW_AFTER_RADARDETECTED


extern const char *dfs_cacstate_str[WL_DFS_CACSTATES];

int amas_adtbw_conduct_cac(void)
{
    wl_dfs_status_t *dfs_status;
    char buf[WLC_IOCTL_SMLEN];
    int ret = 0;
    
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "dfs_status");
    
    if (!wl_ioctl(adtbw_config.ifname, WLC_GET_VAR, buf, sizeof(buf))) {
	dfs_status = (wl_dfs_status_t *) buf;
	dfs_status->state = dtoh32(dfs_status->state);
	dfs_status->duration = dtoh32(dfs_status->duration);

	if (dfs_status->state == WL_DFS_CACSTATE_PREISM_CAC) {
	    ret = 1;
	}
    }
#if 0
    if(dfs_status->duration > 50000)
	AMAS_ADTBW_DBG("%s: DFS status: state %s time elapsed %dms radar channel cleared by DFS\n",
			adtbw_config.ifname, dfs_cacstate_str[dfs_status->state], dfs_status->duration);
#endif
    return ret;
}
