#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <shared.h>
#include <rc.h>
#include <bcmnvram.h>
#include <ralink.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include  <float.h>
#include <ap_priv.h>
#include <wlutils.h>
#include <roamast.h>
#ifdef RTCONFIG_RALINK
#include <wlioctl.h>
#endif

#ifdef RTCONFIG_BCN_RPT
#include <pthread.h>
#include <json.h>
#include <security_ipc.h>
#endif

#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#include <json.h>

int xTxR = 0;

typedef struct _rrm_info {
	char sta_mac[19];
	char ap_mac[19];
	char rcpi[7];
	char dump;
} rrm;

typedef struct _rrm_sta {
    rrm sta[128];
} rrm_sta;

#define MAX_NUMBER_OF_ACL				64

void get_stainfo(int bssidx, int vifidx)
{
	char *sp = NULL, *op = NULL;
	char wlif_name[32] = {0}, header[128] = {0}, data[2048] = {0};
	int hdrLen = 0, staCount = 0, getLen = 0;
	struct iwreq wrq;
	sta_entry *ssap = NULL;
	struct rast_sta_info *staInfo = NULL;
	char prefix[] = "wlXXXXXXXXXX_";
	char header_t[128] = {0};
	int stream = 0;
	char tmp[128] = {0};
	char rssinum[16] = {0};
	unsigned long long cur_txrx_bytes = 0;
	int i = 0;
	int32 rssi_xR[xR_MAX] = {0};
	int rssi_total = 0;

	snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);
	if (!(xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp))))
		return;

	if(xTxR > xR_MAX)
		xTxR = xR_MAX;

	if (vifidx > 0) {
		snprintf(data, sizeof(data), "wl%d.%d_ifname", bssidx, vifidx);
		strlcpy(wlif_name, nvram_safe_get(data), sizeof(wlif_name));
	}
	else {
		strlcpy(wlif_name, bssinfo[bssidx].wlif_name, sizeof(wlif_name));
	}

		memset(data, 0x00, sizeof(data));
       	wrq.u.data.length = sizeof(data);
       	wrq.u.data.pointer = (caddr_t) data;
       	wrq.u.data.flags = ASUS_SUBCMD_GROAM;

	if (wl_ioctl(wlif_name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		RAST_INFO("[%s]: (%d,%d) WI[%s] ASUS_SUBCMD_GROAM failure\n", __FUNCTION__, bssidx, vifidx, wlif_name);
		return;
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
			ssap->sta[staCount].mac[18]='\0';
			for (stream = 0; stream < xR_MAX; stream++) {
				ssap->sta[staCount].rssi_xR[stream][6]='\0';
			}
			ssap->sta[staCount].TxByte[20]='\0';
			ssap->sta[staCount].RxByte[20]='\0';
			ssap->sta[staCount].wnm_cap[6]='\0';
			ssap->sta[staCount].rrm_cap[6]='\0';
			sp += hdrLen;
			staCount++;
		}

		struct ether_addr ea;
#ifdef RTCONFIG_WIRELESSREPEATER
#if defined(RTCONFIG_CONCURRENTREPEATER) || defined(RTCONFIG_AMAS)
		char word[256], *next;
		int unit = 0;
		int skip = 0;
		const char *ifName = NULL;
		unsigned char pap_bssid[2][18];
		struct iwreq wrq1;

		if(sw_mode() == SW_MODE_REPEATER
#if defined(RTCONFIG_AMAS)
			|| (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1"))
#endif
		) {
			foreach (word, nvram_safe_get("wl_ifnames"), next) {

#if defined(RTCONFIG_RALINK_MT7620) || defined(RTCONFIG_RALINK_MT7621)
				if(unit == 0)
#else
				if(unit == 1)
#endif
					ifName = APCLI_2G;
				else
					ifName = APCLI_5G;

				if (wl_ioctl(ifName, SIOCGIWAP, &wrq1)>=0) {
					wrq1.u.ap_addr.sa_family = ARPHRD_ETHER;
					snprintf(pap_bssid[unit], sizeof(pap_bssid[unit]), "%02X:%02X:%02X:%02X:%02X:%02X",
							(unsigned char)wrq1.u.ap_addr.sa_data[0], (unsigned char)wrq1.u.ap_addr.sa_data[1],
							(unsigned char)wrq1.u.ap_addr.sa_data[2], (unsigned char)wrq1.u.ap_addr.sa_data[3],
							(unsigned char)wrq1.u.ap_addr.sa_data[4], (unsigned char)wrq1.u.ap_addr.sa_data[5]  );
				}
				unit++;
			}	
		}
#else		
		char *aif;
		unsigned char pap_bssid[18];
		struct iwreq wrq1;
		if(sw_mode() == SW_MODE_REPEATER && nvram_get_int("wlc_band") == bssidx) {
			memset(header, 0, sizeof(header));
			aif = nvram_get( strcat_r(bssinfo[bssidx].prefix, "vifs", header) );
			if(wl_ioctl(aif, SIOCGIWAP, &wrq1)>=0) {
				wrq1.u.ap_addr.sa_family = ARPHRD_ETHER;
				snprintf(pap_bssid, sizeof(pap_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
						(unsigned char)wrq1.u.ap_addr.sa_data[0], (unsigned char)wrq1.u.ap_addr.sa_data[1],
						(unsigned char)wrq1.u.ap_addr.sa_data[2], (unsigned char)wrq1.u.ap_addr.sa_data[3],
						(unsigned char)wrq1.u.ap_addr.sa_data[4], (unsigned char)wrq1.u.ap_addr.sa_data[5]  );
			}
		}
#endif	       	
#endif



		if( !staCount ) return;
		// add to assoclist //
		for(hdrLen=0; hdrLen< staCount; hdrLen++) {
#ifdef RTCONFIG_WIRELESSREPEATER
#if defined(RTCONFIG_CONCURRENTREPEATER) || defined(RTCONFIG_AMAS)
			if(sw_mode() == SW_MODE_REPEATER
#if defined(RTCONFIG_AMAS)
				|| (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1"))
#endif
			) {
				unit = 0;
				skip = 0;
				foreach (word, nvram_safe_get("wl_ifnames"), next) {
					// pap bssid,skip //
					if( !strncmp(pap_bssid[unit], ssap->sta[hdrLen].mac, strlen(pap_bssid[unit]))) {
						RAST_DBG("======SKIP======= [%s]: P-AP BSSID[(band:%d)%s]\n", __FUNCTION__, unit, pap_bssid[unit]);
						skip = 1;
						break;
					}
					unit++;
				}
			}	
			if (skip == 1)
				continue;		
#else			
			// pap bssid,skip //
			if( !strncmp(pap_bssid, ssap->sta[hdrLen].mac, sizeof(pap_bssid))) {
				RAST_DBG("[%s]: P-AP BSSID[%s]\n", __FUNCTION__, pap_bssid);
				continue;
			}
#endif			
#endif
			//RAST_DBG("ssap->sta[%d].mac= (%s)\n", hdrLen, ssap->sta[hdrLen].mac);
			staInfo = rast_add_to_assoclist(bssidx, vifidx, rast_ether_atoe(ssap->sta[hdrLen].mac, &ea));
			//RAST_DBG("[%s(%d)] mac:"MACF"\n",__FUNCTION__, __LINE__, ETHER_TO_MACF(ea));
		    rssi_total = 0;
			for( getLen=0; getLen<xTxR; getLen++ ) {
				rssi_xR[getLen] = !atoi(ssap->sta[hdrLen].rssi_xR[getLen]) ? -100 : atoi(ssap->sta[hdrLen].rssi_xR[getLen]);
				rssi_total = rssi_total + rssi_xR[getLen];
			}
			memcpy(staInfo->mac_addr, ssap->sta[hdrLen].mac, strlen(ssap->sta[hdrLen].mac));

			staInfo->rssi = rssi_total / xTxR ;
			staInfo->tx_byte = atoi(ssap->sta[hdrLen].TxByte);
			staInfo->rx_byte = atoi(ssap->sta[hdrLen].RxByte);
			cur_txrx_bytes = staInfo->tx_byte + staInfo->rx_byte;
			staInfo->datarate = (float)((cur_txrx_bytes - staInfo->last_txrx_bytes) >> 7/* bytes to Kbits*/) / RAST_POLL_INTV_NORMAL/* Kbps */;
			staInfo->last_txrx_bytes = cur_txrx_bytes;
			staInfo->active = uptime();

#ifdef RTCONFIG_BCN_RPT
			staInfo->rrm_bcn_passive_cap = atoi(ssap->sta[hdrLen].rrm_cap);
#endif
#ifdef RTCONFIG_ADV_RAST
			staInfo->wnm_cap = atoi(ssap->sta[hdrLen].wnm_cap);
#endif
#if 0
		if (rast_dbg) {
			RAST_DBG("[%s]: [%s][%d][%s] RATE[%f]\t", __FUNCTION__, wlif_name, hdrLen,
					       	staInfo->mac_addr, staInfo->datarate);
			for (i=0;i<xTxR;i++) {
				RAST_DBG("RSSI[%d:%d]\t", i, rssi_xR[i]);
			}
			RAST_DBG(" RSSI Avg = %d\n", staInfo->rssi );
		}
#endif
		}
	}

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = 0;
	if (wl_ioctl(wlif_name, RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT, &wrq) < 0) {
		RAST_INFO("[%s]: WI[%s] Access to MacTableStruct failure\n", __FUNCTION__, wlif_name);
		return;
	}

	if(bssidx == 0) {
		RT_802_11_MAC_TABLE_2G* mp2=(RT_802_11_MAC_TABLE_2G*)wrq.u.data.pointer;
		RAST_DBG("%s: staCount(%d) Num(%d)\n", "2G", staCount, mp2->Num);
		for(i=0; i< mp2->Num; i++) {
			if((staInfo = rast_add_to_assoclist(bssidx, vifidx, (struct ether_addr*)mp2->Entry[i].Addr)) == NULL)
				continue;
#ifdef RTCONFIG_ADV_RAST
//			staInfo->connected_time = mp2->Entry[i].ConnectedTime;
#endif
			staInfo->rx_rate = mp2->Entry[i].LastRxRate * 1000;		//rx_rate is kbps
			staInfo->tx_rate = getRate_2g(mp2->Entry[i].TxRate) * 1000;	//tx_rate is kbps
			RAST_DBG("i(%d) mac_addr(%s) conn_time(%u) rx_rate(%u) tx_rate(%u)\n", i, staInfo->mac_addr, 0 /*staInfo->connected_time*/, staInfo->rx_rate, staInfo->tx_rate);
		}
	} else {
		RT_802_11_MAC_TABLE_5G* mp =(RT_802_11_MAC_TABLE_5G*)wrq.u.data.pointer;
		RAST_DBG("%s: staCount(%d) Num(%d)\n", "5G", staCount, mp->Num);
		for(i=0; i< mp->Num; i++) {
			if((staInfo = rast_add_to_assoclist(bssidx, vifidx, (struct ether_addr*)mp->Entry[i].Addr)) == NULL)
				continue;
#ifdef RTCONFIG_ADV_RAST
//			staInfo->connected_time = mp->Entry[i].ConnectedTime;
#endif
			staInfo->rx_rate = mp->Entry[i].LastRxRate * 1000;		//rx_rate is kbps
			staInfo->tx_rate = getRate(mp->Entry[i].TxRate) * 1000;		//tx_rate is kbps
			RAST_DBG("i(%d) mac_addr(%s) conn_time(%u) rx_rate(%u) tx_rate(%u)\n", i, staInfo->mac_addr, 0 /*staInfo->connected_time*/, staInfo->rx_rate, staInfo->tx_rate);
		}
	}
	return;
}


#ifdef RTCONFIG_ADV_RAST
int rast_stamon_get_rssi(int bssidx, struct ether_addr *addr)
{
	char *sp = NULL, *op = NULL;
	char wlif_name[32] = {0}, header[128] = {0}, data[2048] = {0};
	int hdrLen = 0, staCount = 0, getLen = 0;
	struct iwreq wrq;
	grssi_sta *ssap = NULL;
	char prefix[] = "wlXXXXXXXXXX_";
	char header_t[128] = {0};
	int stream = 0;
	char tmp[128] = {0};
	char rssinum[16] = {0};
	int i = 0, j = 0;
	int32 rssi_xR[xR_MAX] = {0};
	int rssi_total = 0;
	int sta_rssi = -100;
	char tr_mac[32] ={0};

	snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);
	if (!(xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp))))
		return 0;

	if(xTxR > xR_MAX)
		xTxR = xR_MAX;
	
	// enable sta_monitor feature
	memset(data, 0x00, sizeof(data));
    strcpy(data, "mnt_en=1");
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_SET, &wrq) < 0) {
        RAST_INFO("Setting mnt_en=1 fail.\n");
        goto done;
    }
    // set sta monitor rule
	memset(data, 0x00, sizeof(data));
    strcpy(data, "mnt_rule=1:1:1");
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_SET, &wrq) < 0) {
        RAST_INFO("Setting mnt_rule=1:1:1 fail.\n");
        goto done;
    }
	// add sta into sta_monitor list
	snprintf(tr_mac, sizeof(tr_mac), ""MACF"", ETHERP_TO_MACF(addr));
	memset(data, 0x00, sizeof(data));
    snprintf(data, sizeof(data), "mnt_sta0=%s", tr_mac);
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_SET, &wrq) < 0) {
        RAST_INFO("Setting mnt_sta0=%s fail.\n", tr_mac);
        goto done;
    }

	for (i = 0; i<3; i++) {
		snprintf(wlif_name, sizeof(wlif_name), "%s", bssinfo[bssidx].wlif_name);

		memset(data, 0x00, sizeof(data));
       	wrq.u.data.length = sizeof(data);
       	wrq.u.data.pointer = (caddr_t) data;
       	wrq.u.data.flags = ASUS_SUBCMD_GMONITOR_RSSI;

    	
		usleep(500000);
		if (wl_ioctl(wlif_name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
			RAST_INFO("[%s]: (%d) WI[%s] ASUS_SUBCMD_GMONITOR_RSSI failure\n", __FUNCTION__, bssidx, wlif_name);
			goto done;
		}

		memset(header, 0, sizeof(header));
		memset(header_t, 0, sizeof(header_t));
		hdrLen = sprintf(header_t, "%-19s", "MAC");
		strcpy(header, header_t);

		for (stream = 0; stream < xR_MAX; stream++) {
			snprintf(rssinum, sizeof(rssinum), "RSSI%d", stream);
			memset(header_t, 0, sizeof(header_t));
			hdrLen += sprintf(header_t, "%-7s", rssinum);
			strncat(header, header_t, strlen(header_t));
		}
		hdrLen += sprintf(header_t, "%-21s", "Count");
		strncat(header, header_t, strlen(header_t));
		strcat(header,"\n");
		hdrLen++;

		if (wrq.u.data.length > 0 && data[0] != 0) {

			getLen = strlen(wrq.u.data.pointer + hdrLen);

			ssap = (grssi_sta *)(wrq.u.data.pointer + hdrLen);
			op = sp = wrq.u.data.pointer + hdrLen;
			while (*sp && ((getLen - (sp-op)) >= 0)) {
				ssap->sta[staCount].mac[18]='\0';
				for (stream = 0; stream < xR_MAX; stream++) {
					ssap->sta[staCount].rssi_xR[stream][6]='\0';
				}
				ssap->sta[staCount].Count[20]='\0';
				sp += hdrLen;
				staCount++;
			}

			if( !staCount ) goto done;

			//translate to capital.
			for(j = 0; j < sizeof(tr_mac); j++)
				tr_mac[j] = toupper(tr_mac[j]);

			// add to assoclist //
			for(hdrLen=0; hdrLen< staCount; hdrLen++) {
				//if (addr == ether_aton(ssap->sta[hdrLen].mac))
				if (strncmp(tr_mac, ssap->sta[hdrLen].mac, strlen(tr_mac)) == 0)
				{
					rssi_total = 0;

					for( getLen=0; getLen<xTxR; getLen++ ) {
						rssi_xR[getLen] = !atoi(ssap->sta[hdrLen].rssi_xR[getLen]) ? -100 : atoi(ssap->sta[hdrLen].rssi_xR[getLen]);
						rssi_total = rssi_total + rssi_xR[getLen];
					}
					RAST_DBG("count %d : RSSI Avg = %d\n",i, (rssi_total / xTxR));
					if ((sta_rssi < (rssi_total / xTxR))  && ((rssi_total / xTxR) < 0))
						sta_rssi = rssi_total / xTxR ;

					if (rast_dbg) {
						for (j=0;j<xTxR;j++) {
							RAST_DBG("RSSI[%d:%d]\t", j, rssi_xR[j]);
						}
						RAST_DBG(" RSSI Avg = %d\n",sta_rssi);
					}
					//goto done;
				}
			} // for(hdrLen=0
		} //if (wrq.u.data.length >
	} //for (i = 0; i<3; i++) {
done:

    // Clear data.
	memset(data, 0x00, sizeof(data));
    strcpy(data, "mnt_clr=1");
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_SET, &wrq) < 0) {
        RAST_INFO("Setting mnt_clr=1 fail.\n");
    }

    // Remove STA from monitor list.
	memset(data, 0x00, sizeof(data));
    strcpy(data, "mnt_sta0=00:00:00:00:00:00");
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_SET, &wrq) < 0) {
        RAST_INFO("Setting mnt_sta0=00:00:00:00:00:00 fail.\n");
    }

    // Disable monitor function.
	memset(data, 0x00, sizeof(data));
    strcpy(data, "mnt_en=0");
    wrq.u.data.length = strlen(data)+1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_SET, &wrq) < 0) {
        RAST_INFO("Setting mnt_en=0 fail.\n");
    }

	RAST_DBG("#### return sta_rssi= %d  ######\n",sta_rssi);
	return sta_rssi;
}

void rast_retrieve_static_maclist(int bssidx, int vifidx)
{
	char *sp = NULL, *op = NULL;
	struct iwreq wrq;
	char data[2048] = {0}, header[128] = {0};
	unsigned long macmode = 0;
	int staCount = 0, getLen = 0, hdrLen = 0, size = 0;
	acl_sta *ssap = NULL;
	struct maclist *maclist = (struct maclist *) maclist_buf;
	struct ether_addr *ea = NULL;
	
	wrq.u.data.length = sizeof(macmode);
	wrq.u.data.pointer = (caddr_t)&macmode;
	wrq.u.data.flags = ASUS_SUBCMD_MACMODE;

    if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", get_wifname(bssidx));
		return;
	}



	bssinfo[bssidx].static_macmode[vifidx] = macmode;
	RAST_DBG("[%s] macmode = %s\n",
		__FUNCTION__,
		bssinfo[bssidx].static_macmode[vifidx]==WLC_MACMODE_DISABLED ? "DISABLE" :
		bssinfo[bssidx].static_macmode[vifidx]==WLC_MACMODE_DENY ? "DENY" : "ALLOW");
	
	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t)data;
	wrq.u.data.flags = ASUS_SUBCMD_MACLIST;
	
	if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		RAST_INFO("[%s]: WI[%s] Get ACL List failure\n", __FUNCTION__, get_wifname(bssidx));
		return;
	}
	
	
	memset(header, 0, sizeof(header));
	//hdrLen = sprintf(header, "%-7s%-19s\n", "COUNT", "MAC");
	hdrLen = sprintf(header, "%-19s","MAC");
	
	if (wrq.u.data.length > 0 && data[0] != 0) {

		getLen = strlen(wrq.u.data.pointer + hdrLen);

		ssap = (acl_sta *)(wrq.u.data.pointer + hdrLen);
		op = sp = wrq.u.data.pointer + hdrLen;
			
		while (*sp && ((getLen - (sp-op)) >= 0)) {
			ssap->list[staCount].mac[18]='\0';			
			RAST_DBG("ssap->list[staCount].mac= (%s)\n", ssap->list[staCount].mac);
			ea = &(maclist->ea[staCount]);
			rast_ether_atoe(ssap->list[staCount].mac, ea);
			sp += hdrLen;
			staCount++;
			ea++;
		}
		
		maclist->count = staCount;
#if 0		
		for (i=0; i< staCount;i++){					
		RAST_DBG("[%s] (%d)mac:"MACF"\n",__FUNCTION__, __LINE__, ETHER_TO_MACF(maclist->ea[i]));
		}		
#endif		
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
			RAST_DBG("[%s] (%d)mac:"MACF"\n",__FUNCTION__, size, ETHER_TO_MACF(maclist->ea[size]));
		}
	} else if (maclist->count != 0) {
		RAST_INFO("Err: %s maclist cnt [%d] too large\n",
		__FUNCTION__, maclist->count);
		return;
	}
	return;
}

void rast_set_maclist(int bssidx, int vifidx)
{
	rast_maclist_t *r_maclist = bssinfo[bssidx].maclist[vifidx];
	struct maclist *maclist = (struct maclist *)maclist_buf;
	struct maclist *static_maclist = bssinfo[bssidx].static_maclist[vifidx];
	int static_macmode = bssinfo[bssidx].static_macmode[vifidx];
	int val;
	struct ether_addr *ea;
	int cnt, match;
	char ether_tmp[19] = {0};
	char list_entry[2048] = {0};
	
	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED)
		val = WLC_MACMODE_DENY;
	else
		val = WLC_MACMODE_ALLOW;
	

	doSystem("iwpriv %s set AccessPolicy=%d", get_wifname(bssidx), val);

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
			match = 0;
			while(r_maclist) {
				RAST_DBG("Checking "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
#if (defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA))
				if(memcmp(&(r_maclist->addr), &(static_maclist->ea[cnt]), ETHER_ADDR_STR_LEN/3) == 0)
#else				
				if (eacmp(&(r_maclist->addr), &(static_maclist->ea[cnt])) == 0) 
#endif					
				{
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
	memset(list_entry, 0x00, sizeof(list_entry));		
	for (cnt = 0; cnt < maclist->count; cnt++) {
		if (cnt == 0){
				snprintf(list_entry, sizeof(list_entry), "%02x:%02x:%02x:%02x:%02x:%02x;", ETHER_TO_MACF(maclist->ea[cnt]));
		}
		else if (cnt < MAX_NUMBER_OF_ACL) {	
				memset(ether_tmp, 0x00, sizeof(ether_tmp));		
				snprintf(ether_tmp, sizeof(ether_tmp), "%02x:%02x:%02x:%02x:%02x:%02x;", ETHER_TO_MACF(maclist->ea[cnt]));
				strlcat(list_entry, ether_tmp, sizeof(list_entry));
		}

		RAST_DBG("list_entry =[%s] \n", list_entry);

		RAST_DBG("maclist: "MACF"\n",
				ETHER_TO_MACF(maclist->ea[cnt]));
	}
	
	if(!strcmp(list_entry, ""))
		doSystem("iwpriv %s set ACLClearAll=1", get_wifname(bssidx));
	else
		doSystem("iwpriv %s set ACLAddEntry=\"%s\"", get_wifname(bssidx), list_entry);
	
}

#endif

#if defined(RTCONFIG_RALINK_MT7621)
#define IDLE_CPU 2
int Set_RAST_CPU(void)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	//sched_getaffinity(0, sizeof(cpuset), &cpuset);
	//dbg(" %s:%d, pid=%d  ori_cur_mask = %08lx\n", __FUNCTION__,__LINE__,  pid2, cpuset);	
	
	CPU_SET(IDLE_CPU, &cpuset);
	//dbg(" ##### %s:%d, set cur_mask = %08lx\n", __FUNCTION__,__LINE__, cpuset);					
	sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	
	//sched_getaffinity(0, sizeof(cpuset), &cpuset);
	//dbg(" ##### %s:%d, confirm set cur_mask = %08lx\n", __FUNCTION__,__LINE__, cpuset);		
}
#endif
#ifdef RTCONFIG_STA_AP_BAND_BIND
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
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
int check_if_support_kv(int unit,int subunit, rast_sta_info_t *sta)
{
	int ret=0;
	if(sta->wnm_cap)
		ret |= RAST_SUPPORT_V;
	if(sta->rrm_bcn_passive_cap)
		ret |= RAST_SUPPORT_K_PASSIVE_SCAN;
	RAST_INFO("[%s(%d)] mac:"MACF" ret=%d\n",__FUNCTION__, __LINE__, ETHER_TO_MACF(sta->addr), ret);
	return ret;
}
#endif
#ifdef RTCONFIG_BTM_11V
int rast_send_11v_req(int idx,int vidx,char *sta_mac, char *candidate_ap_mac)
{
	return amas_11v(idx, vidx, sta_mac, candidate_ap_mac);
}
#endif //#ifdef RTCONFIG_BTM_11V
#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_get_driver_maclist(int idx,int vidx,char *maclist_buf_local,int buf_size,int *static_macmode){

	char *sp = NULL, *op = NULL;
	struct iwreq wrq;
	char data[2048] = {0}, header[128] = {0};
	int staCount = 0, getLen = 0, hdrLen = 0;
	acl_sta *ssap = NULL;
	struct maclist *maclist = (struct maclist *) maclist_buf_local;
	struct ether_addr *ea = NULL;

	wrq.u.data.length = sizeof(static_macmode);
	wrq.u.data.pointer = (caddr_t)static_macmode;
	wrq.u.data.flags = ASUS_SUBCMD_MACMODE;

	if (wl_ioctl(get_wifname(idx), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		RAST_INFO("[WARNING] %s get macmode error!!!\n", get_wifname(idx));
		return 0;
	}

	RAST_DBG("[%s] check driver mac list[%s] macmode = %s\n",
		__FUNCTION__, get_wifname(idx),
		*static_macmode==WLC_MACMODE_DISABLED ? "DISABLE" :
		*static_macmode==WLC_MACMODE_DENY ? "DENY" : "ALLOW");

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t)data;
	wrq.u.data.flags = ASUS_SUBCMD_MACLIST;

	if (wl_ioctl(get_wifname(idx), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		RAST_INFO("[%s]: WI[%s] Get ACL List failure\n", __FUNCTION__, get_wifname(idx));
		return 0;
	}

	memset(header, 0, sizeof(header));
	//hdrLen = sprintf(header, "%-7s%-19s\n", "COUNT", "MAC");
	hdrLen = sprintf(header, "%-19s","MAC");

	if (wrq.u.data.length > 0 && data[0] != 0) {

		getLen = strlen(wrq.u.data.pointer + hdrLen);

		ssap = (acl_sta *)(wrq.u.data.pointer + hdrLen);
		op = sp = wrq.u.data.pointer + hdrLen;

		while (*sp && ((getLen - (sp-op)) >= 0)) {
			ssap->list[staCount].mac[18]='\0';
			RAST_DBG("ssap->list[staCount].mac= (%s)\n", ssap->list[staCount].mac);
			ea = &(maclist->ea[staCount]);
			rast_ether_atoe(ssap->list[staCount].mac, ea);
			sp += hdrLen;
			staCount++;
			ea++;
		}

		maclist->count = staCount;
	}

	return 1;
}
#endif

uint8 rast_get_rclass(int bssidx, int vifidx)
{
	return get_regular_class(get_wifname(bssidx));
}

#ifdef RTCONFIG_BCN_RPT
/*
generate beacon request action frame
*/
void
rast_send_beacon_request(int bssidx, int vifidx, struct ether_addr *sta)
{
	char prefix[16], tmp[128], data[2048] = {0};
#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_RALINK_MT7621)
        char hex_ssid[80]; // SSID max 32 bytes
        int i, tmp_offset;
#endif
	struct iwreq wrq;
	char sta_mac[32];
	const char *wlif_name;
	int regulatory_class=128;
	int channel=0;
	int measurement_duration=50;
	int mode=1; //0; //0:passive 1:active 2:beacon table
	int bw = 0, nctrlsb = 0;

	snprintf(sta_mac, sizeof(sta_mac), MACF_UP, ETHERP_TO_MACF( sta ));

	if(vifidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", bssidx, vifidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", bssidx);

	char *ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));

	wlif_name = get_wifname(bssidx);
	/* Channel */
	get_channel_info(wlif_name, &channel, &bw, &nctrlsb);
	regulatory_class = rast_get_rclass(bssidx, vifidx);

#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_RALINK_MT7621)
        tmp_offset = sprintf(hex_ssid, "0x");
        for (i=0; i<strlen(ssid); i++)
                tmp_offset += sprintf(hex_ssid+tmp_offset, "%02X", ssid[i]);
#endif

	memset(data, 0x00, sizeof(data));
	/* iwpriv ra0 set BcnReq=<Aid>-<Duration>-<RegulatoryClass>-<BSSID>-<SSID>-<MeasureCh>-<MeasureMode>-<ChRegClass>-<ChReptList> */
#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_RALINK_MT7621)
        snprintf(data, sizeof(data), "BcnReq=%s!%d!%d!FF:FF:FF:FF:FF:FF!%s!%d!%d!", sta_mac, measurement_duration, regulatory_class, hex_ssid, channel, mode);
#else
	snprintf(data, sizeof(data), "BcnReq=%s!%d!%d!FF:FF:FF:FF:FF:FF!%s!%d!%d!", sta_mac, measurement_duration, regulatory_class, ssid, channel, mode);
#endif	
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;
	RAST_INFO("[%s %d] Setting %s %s.\n", __FUNCTION__, __LINE__, wlif_name, data);

	if (wl_ioctl(wlif_name, RTPRIV_IOCTL_SET, &wrq) < 0) {
		RAST_INFO("Setting %s fail.\n", data);
	}
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
	snprintf(rcpiStr, sizeof(rcpiStr), "%hhd", rcpi);
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

int report_check_11k(int unit)
{
	char data[4096];
	struct iwreq wrq;
	int cnt;
	char header_t[128] = {0}, header[128] = {0};
	int hdrLen = 0, staCount = 0, getLen = 0;
	rrm_sta *ssap = NULL;
	char *sp = NULL, *op = NULL;
	int8 rcpi;
	struct ether_addr ea_tmp, sta_tmp, ap_tmp;

#ifdef RTCONFIG_11K_RCPI_CHECK
	struct rcpi_checklist *rcpi_list=NULL;
	struct rcpi_checklist *rcpi_list_tmp=NULL;
	struct report_entry   *report_entry_tmp=NULL;
#endif

	memset(data, 0x00, 4096);
	wrq.u.data.length = 4096;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_RRM_BCN_RESP;

	if (wl_ioctl(get_wifname(unit), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting RRM_BCN_RESP result\n");
		return 0;
	}

	memset(header, 0, sizeof(header));
	memset(header_t, 0, sizeof(header_t));
	hdrLen = snprintf(header_t, sizeof(header_t), "%-19s", "STA_MAC");
	strlcpy(header, header_t, sizeof(header));
	hdrLen += snprintf(header_t, sizeof(header_t), "%-19s", "AP_MAC");
	strncat(header, header_t, sizeof(header));
	hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "RCPI");
	strncat(header, header_t, strlen(header_t));
	strcat(header,"\n");
	hdrLen++;

	if (wrq.u.data.length > 0 && data[0] != 0) {

		getLen = strlen(wrq.u.data.pointer + hdrLen);

		ssap = (rrm_sta *)(wrq.u.data.pointer + hdrLen);
		op = sp = wrq.u.data.pointer + hdrLen;
		while (*sp && ((getLen - (sp-op)) >= 0)) {
			ssap->sta[staCount].sta_mac[17]='\0';
			ssap->sta[staCount].ap_mac[17]='\0';
			ssap->sta[staCount].rcpi[6]='\0';
			sp += hdrLen;
			//RAST_DBG("[%s(%d)] (%d) sta_mac(%s) ap_mac(%s) rcpi(%s)\n", __FUNCTION__, __LINE__, staCount, ssap->sta[staCount].sta_mac, ssap->sta[staCount].ap_mac, ssap->sta[staCount].rcpi);
			staCount++;
		}
	}
	cnt=0;
	for (cnt=0; cnt<staCount; cnt++) {
#ifdef RTCONFIG_11K_RCPI_CHECK
		rcpi=(int8)atoi(ssap->sta[cnt].rcpi);
		add_to_rcpi_checklist(
			ssap->sta[cnt].sta_mac,
			ssap->sta[cnt].ap_mac,
			(char)rcpi,
			&rcpi_list
		);
#else
		rast_update_beacon_report(ssap->sta[staCount].sta_mac, ssap->sta[staCount].ap_mac, ssap->sta[staCount].rcpi);
#endif
	}

#ifdef RTCONFIG_11K_RCPI_CHECK
	/* check if rcpi follow spec(in 802.11,rcpi = (rssi+110)*2) */
	check_rcpilist_and_translate_to_rssi(rcpi_list);
	/* update to cfg_mnt json file here */
	while(1){
		if(!rcpi_list)
			break;
		while(1){
			if(!rcpi_list->rplist)
				break;
			if(rcpi_list->report_ok) {
				RAST_DBG("set to json file %s %s %hhd\n", rcpi_list->sta_mac, rcpi_list->rplist->ap_mac, rcpi_list->rplist->rcpi);
				memcpy(&sta_tmp, rast_ether_atoe(rcpi_list->sta_mac,&ea_tmp), sizeof(struct ether_addr));
				memcpy(&ap_tmp, rast_ether_atoe(rcpi_list->rplist->ap_mac,&ea_tmp), sizeof(struct ether_addr));
				rast_update_beacon_report(&sta_tmp, &ap_tmp, (int8)rcpi_list->rplist->rcpi);
			}
			report_entry_tmp = rcpi_list->rplist;
			rcpi_list->rplist = rcpi_list->rplist->next;
			free(report_entry_tmp);
		}
		rcpi_list_tmp = rcpi_list;
		rcpi_list = rcpi_list->next;
		free(rcpi_list_tmp);
	}
#endif

	return 0;
}

int rast_start_bcn_rpt_wifiX(void *data)
{
	int max;
	if(!data)
	{
		_dprintf("create 11k thread input parameter empty\n");
		return -1;
	}

	int unit = *(int *)data;
	max = num_of_wl_if();
	if( unit < 0 || unit >=max)
	{
		_dprintf("create 11k thread unit error\n");
		return -1;
	}

	free(data);
	/* Main event loop */
	while (1)
	{
		//RAST_INFO("rast_start_bcn_rpt_wlanX %d report_check_11k in\n",unit);
		if( nvram_get_int("wlready") )
			report_check_11k(unit);
		sleep(1);
	}
	return 0;
}

pthread_t thread_11k_wifi0,thread_11k_wifi1;
void rast_bcn_rpt_init(void)
{
	pthread_attr_t attr_0, attr_1;
	int *args = NULL;

	RAST_DBG("Start beacon report thread.\n");

	args = malloc(sizeof(int));
	if(args == NULL)
	{
		RAST_INFO("malloc error\n");
		return;
	}
	*args = 0;

	pthread_attr_init(&attr_0);
	pthread_attr_setdetachstate(&attr_0, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_11k_wifi0,&attr_0,(void *)&rast_start_bcn_rpt_wifiX,args);
	pthread_attr_destroy(&attr_0);

	sleep(3);

	args = malloc(sizeof(int));
	if(args == NULL)
	{
		RAST_INFO("malloc error\n");
		return;
	}
	*args = 1;

	pthread_attr_init(&attr_1);
	pthread_attr_setdetachstate(&attr_1, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_11k_wifi1,&attr_1,(void *)&rast_start_bcn_rpt_wifiX,args);
	pthread_attr_destroy(&attr_1);
}
#endif
