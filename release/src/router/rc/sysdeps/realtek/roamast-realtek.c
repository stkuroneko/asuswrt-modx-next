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
#include "roamast.h"

void get_stainfo(int bssidx, int vifidx)
{
	struct maclist *mac_list;
	int mac_list_size;
	scb_val_t scb_val;
	int mcnt;
    char wlif_name[32];
	int32 rssi;
	rast_sta_info_t *sta = NULL;

#ifdef RTCONFIG_AMAS
    if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")) {
        if(vifidx <= 0)
            return;
        __get_wlifname(bssidx, vifidx-1, wlif_name);
    }
    else
#endif
    __get_wlifname(bssidx, vifidx, wlif_name);

	mac_list_size = sizeof(mac_list->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	mac_list = malloc(mac_list_size);

	if (!mac_list)
		return;

	memset(mac_list, 0, mac_list_size);

	/* query authentication sta list */
	strcpy((char*) mac_list, "authe_sta_list");
	if (wl_ioctl(wlif_name, WLC_GET_VAR, mac_list, mac_list_size))
		goto exit;

	for (mcnt = 0; mcnt < mac_list->count; mcnt++) {
		memcpy(&scb_val.ea, &mac_list->ea[mcnt], ETHER_ADDR_LEN);


		if (wl_ioctl(wlif_name, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t)))
			continue;

		rssi = scb_val.val;

		/* add to assoclist */
		sta = rast_add_to_assoclist(bssidx, vifidx, &(mac_list->ea[mcnt]));
		sta->rssi = rssi - 100;
		sta->active = uptime();
		/* get Tx/Rx bytes of station */
		union get_txrx {
			char command[64];
			unsigned long long txrx_bytes;
		} buf;
		buf.txrx_bytes = 0;
		unsigned long long cur_txrx_bytes = 0;
		snprintf(buf.command, sizeof(buf.command), "sta_txrx_bytes");
		memcpy(buf.command + strlen(buf.command) + 1, &mac_list->ea[mcnt], ETHER_ADDR_LEN);

		if (wl_ioctl(wlif_name, WLC_GET_VAR, buf.command, sizeof(buf.command)))
			goto exit;

		cur_txrx_bytes = buf.txrx_bytes;
		sta->datarate = (float)((cur_txrx_bytes - sta->last_txrx_bytes) >> 7/* bytes to Kbits*/) / RAST_POLL_INTV_NORMAL/* Kbps */;
		sta->last_txrx_bytes = cur_txrx_bytes;
	}

exit:
	if (mac_list) free(mac_list);
}

#ifdef RTCONFIG_ADV_RAST
int rast_stamon_get_rssi(int bssidx, struct ether_addr *addr)
{
	char command[64] = {0}, tmp[64] = {0};
	char *pkeyword = NULL;
	int sta_rssi = 0, sta_rssi_lastest = 0;
	int i = 0;

	char wlif_name[64] = {0};
	snprintf(wlif_name, sizeof(wlif_name), "%s", bssinfo[bssidx].wlif_name);

	char buf[13] = {0};
	snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", ETHERP_TO_MACF(addr));

	/* Enable monitor feature. */
	doSystem("iwpriv %s set_mib monitor_sta_enabled=1", wlif_name);

	/* add STA into monitor table. */
	RAST_DBG("MAC: %02x%02x%02x%02x%02x%02x\n", ETHERP_TO_MACF(addr));
	doSystem("iwpriv %s add_monitor_tbl %02x%02x%02x%02x%02x%02x", wlif_name, ETHERP_TO_MACF(addr));

	/* Get RSSI */

	for (i = 0; i < 3; i++)
	{
		FILE *fp = NULL;
		unsigned char rssitmp = 0;
		usleep(500000);
		
		if (wl_ioctl(wlif_name, WLC_GET_MONITOR_STA_RSSI, (void *)buf, strlen(buf)+1))
			goto exit;

		memcpy(&rssitmp, buf, sizeof(rssitmp));
		RAST_DBG("RSSI: %d \n", rssitmp - 100);
		sta_rssi_lastest = rssitmp - 100;
		sta_rssi = (sta_rssi == 0 ? sta_rssi_lastest : (sta_rssi_lastest > sta_rssi ? sta_rssi_lastest : sta_rssi));
	}
exit:
	/* Clear monitor table. */
	doSystem("iwpriv %s clr_monitor_tbl", wlif_name);

	/* Disable monitor feature. */
	doSystem("iwpriv %s set_mib monitor_sta_enabled=0", wlif_name);

	return sta_rssi;
}

void rast_retrieve_static_maclist(int bssidx, int vifidx)
{
	int ret, size;
	char wlif_name[64];
	struct maclist *maclist = (struct maclist *) maclist_buf;

	if (vifidx > 0)
		snprintf(wlif_name, sizeof(wlif_name), "wl%d.%d", bssidx, vifidx);
	else
		snprintf(wlif_name, sizeof(wlif_name), "%s", bssinfo[bssidx].wlif_name);

	ret = wl_ioctl(wlif_name, WLC_GET_MACMODE, &(bssinfo[bssidx].static_macmode[vifidx]), sizeof(bssinfo[bssidx].static_macmode[vifidx]));

	if (ret < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", wlif_name);
		return;
	}

	RAST_DBG("[%s] macmode = %s\n",
	wlif_name,
	bssinfo[bssidx].static_macmode[vifidx] == WLC_MACMODE_DISABLED ? "DISABLE" :
	bssinfo[bssidx].static_macmode[vifidx] == WLC_MACMODE_DENY ? "DENY" : "ALLOW");

	ret = wl_ioctl(wlif_name, WLC_GET_MACLIST, (void *)maclist, sizeof(maclist_buf));
	if (ret < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", wlif_name);
		return;
	}

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
			RAST_DBG("[%s] (%d)mac:"MACF"\n", wlif_name, size, ETHER_TO_MACF(maclist->ea[size]));
		}
	} else if (maclist->count != 0) {
		RAST_INFO("Err: %s maclist cnt [%d] too large\n",
		          wlif_name, maclist->count);
		return;
	}
}

#define MAX_NUMBER_OF_ACL	128
void rast_set_maclist(int bssidx, int vifidx)
{
	rast_maclist_t *r_maclist = bssinfo[bssidx].maclist[vifidx];
	struct maclist *maclist = (struct maclist *)maclist_buf;
	struct maclist *static_maclist = bssinfo[bssidx].static_maclist[vifidx];
	int static_macmode = bssinfo[bssidx].static_macmode[vifidx];
	int val;
	struct ether_addr *ea;
	int cnt;
	char macAddr[9] = {0};
	char wlif_name[64] = {0};

	if (vifidx > 0)
		sprintf(wlif_name, "wl%d.%d", bssidx, vifidx);
	else
		strcpy(wlif_name, bssinfo[bssidx].wlif_name);

	doSystem("iwpriv %s clr_acl_set", wlif_name);
	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED)
		val = WLC_MACMODE_DENY;
	else
		val = WLC_MACMODE_ALLOW;

	doSystem("iwpriv %s set_mib aclmode=%d", wlif_name, val);

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
	else {	//ALLOW MODE
		ea = &(maclist->ea[0]);

		if (!static_maclist) {
			RAST_INFO("[ERROR] %s macmode:%d static_list is NULL\n",
			__FUNCTION__, static_macmode);
			return;
		}

		for (cnt = 0; cnt < static_maclist->count; cnt++) {
			RAST_DBG("Allow mode: static mac[%d] addr:"MACF"\n", cnt,
			ETHER_TO_MACF(static_maclist->ea[cnt]));
			/* if mac in static maclist match rast maclist, skip it */
			int match = 0;
			while (r_maclist) {
				RAST_DBG("Checking "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
				if (eacmp(&(r_maclist->addr), &(static_maclist->ea[cnt])) == 0)
				{
					RAST_DBG("MATCH maclist "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
					match = 1;
					break;
				}
				r_maclist++;
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
    for (cnt = 0; cnt < maclist->count; cnt++) {
    	sprintf(macAddr, "%02x%02x%02x%02x%02x%02x", ETHER_TO_MACF(maclist->ea[cnt]));
		RAST_DBG("maclist: "MACF"\n", ETHER_TO_MACF(maclist->ea[cnt]));
		doSystem("iwpriv %s set_mib acladdr=%s", wlif_name, macAddr);
    }
}
#ifdef RTCONFIG_BCN_RPT


void
rast_send_beacon_request(int bssidx, int vifidx, struct ether_addr *sta)
{
	char prefix[16], tmp[128];
	char word[32], *next;
	int num = 0, len = 0, channel2 = 0;
	struct dot11k_beacon_measurement_req beacon_req;

	if(vifidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);

	char *ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));


	memset(&beacon_req, 0, sizeof(struct dot11k_beacon_measurement_req));

	beacon_req.op_class = 0;
	beacon_req.channel = 255;
	beacon_req.random_interval = 0;
	beacon_req.measure_duration = 500;
	beacon_req.mode = 1;

	beacon_req.ap_channel_report[0].op_class = 0;
	len = 2;

	if(bssidx > 0) {
		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			num++;
		}
		//For Dual Band Device
		if(num == 2) {
			channel2 = nvram_get_int("multi_channel_5g");
		} else if(num == 3) {
			if(bssidx == 1) {
				channel2 = get_channel(get_wififname(2));
			} else if(bssidx == 2){
				channel2 = get_channel(get_wififname(1));
			}
		}
		if(channel2 > 0) {
			beacon_req.ap_channel_report[0].channel[1] = channel2;
			len ++;
		}
	}
	beacon_req.ap_channel_report[0].channel[0] = get_channel(get_wififname(bssidx));
	beacon_req.ap_channel_report[0].len = len;
	memcpy(beacon_req.ssid, ssid, MAX_SSID_LEN);

	issue_beacon_measurement(get_wififname(bssidx), ((struct ether_addr *) (sta))->octet, &beacon_req);
}

void rast_bcn_rpt_init(){
	return;
}
#endif
#endif

#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_check_driver_maclist(int bssidx,int vifidx,struct ether_addr *addr){
	//do nothing
}
#endif