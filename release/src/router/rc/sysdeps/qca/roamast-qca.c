#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <shared.h>
#include <rc.h>
#include <netinet/ether.h>
#include <roamast.h>
#include <qca.h>


#ifdef RTCONFIG_BCN_RPT
#include <pthread.h>
#include <json.h>
#include <security_ipc.h>
#endif

#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#include <json.h>

#ifdef RTCONFIG_ADV_RAST
static rast_maclist_t *r_maclist_old_table[MAX_IF_NUM][MAX_SUBIF_NUM] = {{ NULL }};
#endif

struct get_stainfo_priv_s {
	int bssidx;
	int vifidx;
	char *wlif_name;
};

/* Helper of get_stainfo()
 * @src:	pointer to WLANCONFIG_LIST
 * @arg:
 * @return:
 * 	0:	success
 *  otherwise:	error
 */
static int handle_get_stainfo(const WLANCONFIG_LIST *src, void *arg)
{
	struct get_stainfo_priv_s *priv = arg;
	int cur_txrx_bytes = 0;
	FILE *fp;
	char line_buf[300], *ptr;
	char cmd[sizeof("80211stats -i XXX XX:XX:XX:XX:XX:XX") + IFNAMSIZ];
	rast_sta_info_t *sta = NULL;

	if (!src || !arg)
		return -1;

	RAST_DBG("[%s][%u][%u][%s][%s][%u][%s][%s]\n",
		src->addr, src->aid, src->chan, src->txrate,
		src->rxrate, src->rssi, src->conn_time, src->mode);

	/* add to assoclist */
	sta = rast_add_to_assoclist(priv->bssidx, priv->vifidx, ether_aton(src->addr));
	sta->rssi = src->rssi;
	sta->active = uptime();
	sta->tx_rate = safe_atoi(src->txrate) * 1000; /* Kbps */
	sta->rx_rate = safe_atoi(src->rxrate) * 1000; /* Kbps */

	/* get Tx/Rx bytes of station */
	snprintf(cmd, sizeof(cmd), "80211stats -i %s %s", priv->wlif_name, src->addr);
	if (!(fp = popen(cmd, "r")))
		return 0;

	while (fgets(line_buf, sizeof(line_buf), fp)) {
		if ((ptr = strstr(line_buf, "rx_bytes ")) || (ptr = strstr(line_buf, "tx_bytes "))) {
			ptr += strlen("rx_bytes ");
			cur_txrx_bytes += safe_atoi(ptr);
			if (strstr(line_buf, "rx_bytes "))
				sta->rx_byte = safe_atoi(ptr);
			else if (strstr(line_buf, "tx_bytes "))
				sta->tx_byte = safe_atoi(ptr);
		}
	}
	sta->datarate = (float)((cur_txrx_bytes - sta->last_txrx_bytes) >> 7/* bytes to Kbits*/) / RAST_POLL_INTV_NORMAL/* Kbps */;
	sta->last_txrx_bytes = cur_txrx_bytes;
	pclose(fp);

	return 0;
}

void get_stainfo(int bssidx, int vifidx)
{
	char wlif_name[IFNAMSIZ];
	struct get_stainfo_priv_s priv = { .bssidx = bssidx, .vifidx = vifidx, .wlif_name = wlif_name };

#ifdef RTCONFIG_AMAS
	if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")) {
		if(vifidx <= 0)
			return;
		__get_wlifname(swap_5g_band(bssidx), vifidx-1, wlif_name);
	}
	else
#endif
		__get_wlifname(swap_5g_band(bssidx), vifidx, wlif_name);

	/* get MAC and RSSI of station */
	__get_qca_sta_info_by_ifname(wlif_name, 0, handle_get_stainfo, &priv);
}

#ifdef RTCONFIG_ADV_RAST
/*
 * rast_stamon_get_rssi(bssidx, addr)
 *
 * to get the RSSI value of an Non-Associated Client assigned by addr.
 *
 * In QCA platform, the bssid of the AP that the client connecting is required.
 * And is got by "nac_bssid" variable that set in caller.
 *
 * The return value should be a negative value in dBm or a 0 meaning NO data.
 *
 */
int rast_stamon_get_rssi(int bssidx, struct ether_addr *addr)
{
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_SOC_QCA9557) || defined(RTCONFIG_QCA956X) || defined(RTCONFIG_QCN550X) \
 || (defined(RTCONFIG_WIFI_QCN5024_QCN5054) && !defined(RTCONFIG_GLOBAL_INI))
	return 0;
#else
	char athfix[8];
	int ch;
	int rssi = 0;
	FILE *fp;
	char line[256];
	int size;
	char mac[18];
	char *bssid;
	char tmp_bssid[32], tmp_client[32];
	int tmp_ch, tmp_rssi;
	int i;
	int channf;

	bssid = nvram_get("nac_bssid");

	size = sizeof(line)-1;
	line[size] = '\0';
	//strcpy(mac, ether_ntoa(addr));
	snprintf(mac,sizeof(mac),MACF,ETHERP_TO_MACF(addr));
	//RAST_DBG("%s %d ether_ntoa %s\n",__FUNCTION__,__LINE__,mac);

	if(bssid == NULL || strlen(bssid) != 17 || strcmp(bssid, "00:00:00:00:00:00") == 0)
		return 0;

	__get_wlifname(swap_5g_band(bssidx), 0, athfix);
	ch = get_channel(athfix);
	channf = get_channf(-1, athfix);

	doSystem("wlanconfig %s rssi_nac add bssid %s client %s channel %d", athfix, bssid, mac, ch);
	sleep(1);
	for(i = 0; i < (2*2) && rssi == 0; i++) {
		usleep(500*1000);
		snprintf(line, size, "wlanconfig %s rssi_nac show_rssi", athfix);
		if((fp = popen(line, "r")) != NULL) {
			int init = 0;
			int len;
			while(fgets(line, size, fp)) {
				strip_new_line(line);
				len = strlen(line);
				if (len > 58) {	/* 10 + 17 + 2 + 17 + 3 + ch + 8 + rssi = 58~60 + rssi */
					if(init == 0)
						init = len;
					else {
						sscanf(line, "%s %s %d %d", tmp_bssid, tmp_client, &tmp_ch, &tmp_rssi);
						/* If wlanconfig reports QCA_RSSI (0 ~ 115), adjust it with channf.
						 * But it's not accurate as long as client bandwidth different.
						 * If wlanconfig reports normal RSSI, negative value, don't adjust it again.
						 */
						if(tmp_rssi > 0) {
							rssi = tmp_rssi + channf;
							if (rssi >= 0)
								rssi = -1;
						}
						break;
					}
				}
			}
			pclose(fp);
		}
	}
	doSystem("wlanconfig %s rssi_nac del bssid %s client %s", athfix, bssid, mac);
	return rssi;
#endif
}

#if 1
struct maclist {
	uint count;
	struct ether_addr ea[0];
};
#endif

/* 
 * rast_retrieve_static_maclist(bssidx, vifidx)
 *
 * getting the mac filter mode and mac list that has set in wifi interface(bssidx,vifidx).
 * and save to the struct in bssinfo[bssidx].static_maclist[vifidx].
 *
 * The list may include the mac filter the set in web UI and the RE list (when in allow mode).
 * The saved list is used in rast_set_maclist().
 * And tread as a basic list to handle add/del in bssinfo[bssidx].maclist[vifidx].
 *
 */
void rast_retrieve_static_maclist(int bssidx, int vifidx)
{
	int size;
	char athfix[8];
	char cmd[128];
	char line[256];
	FILE *fp;
	int len;
	char *p;
	char *sec = "";
	struct maclist *static_maclist;

	/* init r_maclist_table */
	if(bssidx < MAX_IF_NUM && vifidx < MAX_SUBIF_NUM){
		rast_maclist_t *r_maclist_tmp;
		while((r_maclist_tmp = r_maclist_old_table[bssidx][vifidx])) {
			r_maclist_old_table[bssidx][vifidx] = r_maclist_tmp->next;
			free(r_maclist_tmp);
		}
	}

	/* init r_maclist_table */
	if(bssidx < MAX_IF_NUM && vifidx < MAX_SUBIF_NUM){
		if(r_maclist_old_table[bssidx][vifidx])
			RAST_INFO("r_maclist_old_table[%d][%d] %x\n",bssidx,vifidx, r_maclist_old_table[bssidx][vifidx]);
		r_maclist_old_table[bssidx][vifidx] = NULL;
	}

#ifdef RTCONFIG_AMAS
	if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")) {
		if(vifidx <= 0)
			return;
		__get_wlifname(swap_5g_band(bssidx), vifidx-1, athfix);
	}
	else
#endif
	__get_wlifname(bssidx, vifidx, athfix);

	size = sizeof(line)-1;
	line[size] = '\0';

	/* get current mac filter mode */
#ifdef RTCONFIG_QCA_LBD
	if (nvram_match("smart_connect_x", "1"))
		sec = "_sec";
#endif
	snprintf(cmd, sizeof(cmd), "iwpriv %s %s%s", athfix, QCA_GETCMD, sec);
	if((fp = popen(cmd, "r")) == NULL)
		return;

	if(fgets(line, size, fp) != NULL && (p = strchr(line, ':')) != NULL) {
		bssinfo[bssidx].static_macmode[vifidx] = atoi(p+1);	/* 0: disable, 1: allow, 2: deny */
	}
	pclose(fp);

	/* get current mac filter list */
#ifdef RTCONFIG_QCA_LBD
	if (nvram_match("smart_connect_x", "1"))
		sec = "_sec";
#endif
	snprintf(cmd, sizeof(cmd), "iwpriv %s %s%s", athfix, QCA_GETMAC, sec);
	if((fp = popen(cmd, "r")) == NULL)
		return;

	if(bssinfo[bssidx].static_maclist[vifidx] == NULL) {
		int msize = sizeof(uint) + sizeof(struct ether_addr) * 128;
		if((bssinfo[bssidx].static_maclist[vifidx] = (struct maclist *)malloc(msize)) == NULL) {
			pclose(fp);
			return;
		}
	}

	static_maclist = bssinfo[bssidx].static_maclist[vifidx];
	static_maclist->count = 0;
	p = NULL;
	while(fgets(line, size, fp)) {
		if(p == NULL) {
			p = strchr(line, ':');
			if(p != NULL) {
				p += 1;	//point to the head of mac address
			}
		}
		if(p != NULL && (len = strlen(line)) >= (p - line) + 17) {
			struct ether_addr *addr;
			*(p + 17) = '\0';		//cut the string of mac address
			if((addr = ether_aton(p)) != NULL) {
				memcpy((void*)&static_maclist->ea[static_maclist->count], (void*)addr, 6);
				static_maclist->count++;
			}
		}
		else
		{
			_dprintf("## invalid line (%s)\n", line);
		}
	}
	pclose(fp);
}

/*
 * rast_set_maclist(bssidx, vifidx)
 *
 * use the basic maclist in bssinfo[bssidx].static_maclist[vifidx]
 * And handle the add/del maclist in bssinfo[bssidx].maclist[vifidx].
 *
 * The r_maclist_old_table[bssidx][vifidx] is used to check which mac is add/del in bssinfo[bssidx].maclist[vifidx].
 *
 * Since the QCA platform can add/del alone, without all list as Broadcom platform.
 * If the rast_set_maclist_add() and rast_set_maclist_del() are used in caller of roamast.c, the functions are easier to be understood.
 *
 */
void rast_set_maclist(int bssidx, int vifidx)
{
	rast_maclist_t *r_maclist = bssinfo[bssidx].maclist[vifidx];
	rast_maclist_t *r_maclist_old = r_maclist_old_table[bssidx][vifidx];
	struct maclist *static_maclist = bssinfo[bssidx].static_maclist[vifidx];
	int static_macmode = bssinfo[bssidx].static_macmode[vifidx];
	int ret, val;
	int cnt, match, exist;
	char athfix[8];
	//char *p;
	char mac[18];
	char *sec = "";
	rast_maclist_t *r_maclist_tmp;


#ifdef RTCONFIG_AMAS
	if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")) {
		if(vifidx <= 0)
			return;
		__get_wlifname(swap_5g_band(bssidx), vifidx-1, athfix);
	}
	else
#endif
	__get_wlifname(swap_5g_band(bssidx), vifidx, athfix);


	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED)
		val = WLC_MACMODE_DENY;
	else
		val = WLC_MACMODE_ALLOW;

#ifdef RTCONFIG_QCA_LBD
	if (nvram_match("smart_connect_x", "1"))
		sec = "_sec";
#endif
	ret = doSystem("iwpriv %s %s%s %d", athfix, QCA_MACCMD, sec, val);
	if(ret < 0) {
		RAST_INFO("[WARNING] %s %s%s error!!!\n", athfix, QCA_MACCMD, sec);
		return;
	}

	/* handle del in maclist */
	while(r_maclist_old)
	{		
		match = 0;
		exist = 0;
		r_maclist = bssinfo[bssidx].maclist[vifidx];
		while(r_maclist) {
			RAST_DBG("%x %x\n",(r_maclist),(r_maclist_old));
			RAST_DBG("%x %x\n",&(r_maclist->addr),&(r_maclist_old->addr));
			if ( memcmp( &(r_maclist->addr), &(r_maclist_old->addr) ,sizeof(struct ether_addr)) == 0) {
				match = 1;
				break;
			}
			r_maclist = r_maclist->next;
		}

		if(!match) {
			if(static_maclist) {
				for (cnt = 0; cnt < static_maclist->count; cnt++) {
					if (memcmp(&(r_maclist_old->addr), &(static_maclist->ea[cnt]),sizeof(struct ether_addr)) == 0) {
						exist = 1;
						break;
					}
				}
			}

			/* action for remove */
			//p = ether_ntoa(&(r_maclist_old->addr));
			snprintf(mac,sizeof(mac),MACF,ETHERP_TO_MACF(&(r_maclist_old->addr)));
			//RAST_INFO("%s %d ether_ntoa %s\n",__FUNCTION__,__LINE__,mac);
			if (static_macmode == WLC_MACMODE_DISABLED || static_macmode == WLC_MACMODE_DENY) {
				RAST_INFO("%s %d \n",__FUNCTION__,__LINE__);
				if(!exist){
					set_maclist_del_kick(athfix, 2, mac);
				}
			}
			else {
				if(exist){
					set_maclist_add_kick(athfix, 1, mac);	/* add back */
				}
			}

			/* release current r_maclist_old */
			if(r_maclist_old == r_maclist_old_table[bssidx][vifidx]){
				r_maclist_old_table[bssidx][vifidx] = r_maclist_old->next;
			}
			r_maclist_tmp = r_maclist_old;
			r_maclist_old = r_maclist_old->next;
			free(r_maclist_tmp);
			continue;
		}

		r_maclist_old = r_maclist_old->next;
	}
	/* handle add in maclist */
	r_maclist = bssinfo[bssidx].maclist[vifidx];
	while (r_maclist) {

		match = 0;
		exist = 0;
		r_maclist_old = r_maclist_old_table[bssidx][vifidx];
		while(r_maclist_old) {
			if (memcmp( &(r_maclist->addr), &(r_maclist_old->addr) ,sizeof(struct ether_addr)) == 0) {
				match = 1;
				break;
			}
			r_maclist_old = r_maclist_old->next;
		}
		if(!match) {
			if( static_maclist ) {
				for (cnt = 0; cnt < static_maclist->count; cnt++) {
					RAST_DBG("Checking "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
					if (memcmp(&(r_maclist->addr), &(static_maclist->ea[cnt]),sizeof(struct ether_addr)) == 0) {
						RAST_DBG("MATCH maclist "MACF"\n", ETHER_TO_MACF(r_maclist->addr));
						exist = 1;
						break;
					}
				}
			}
			/* action for new */
			//p = ether_ntoa(&(r_maclist->addr));
			snprintf(mac,sizeof(mac),MACF,ETHERP_TO_MACF(&(r_maclist->addr)));
			//RAST_INFO("%s %d ether_ntoa %s\n",__FUNCTION__,__LINE__,mac);
			if (static_macmode == WLC_MACMODE_DISABLED || static_macmode == WLC_MACMODE_DENY) {
				if(!exist){
					set_maclist_add_kick(athfix, 2, mac);	/* add to deny */
				}
			}
			else {
				if(exist){
					set_maclist_del_kick(athfix, 1, mac);	/* remove for block */
				}
			}
			/* add to list */
			r_maclist_tmp = calloc(1,sizeof(rast_maclist_t));
			memcpy(&r_maclist_tmp->addr, &r_maclist->addr, sizeof(struct ether_addr));
			r_maclist_tmp->next = r_maclist_old_table[bssidx][vifidx];
			r_maclist_old_table[bssidx][vifidx] = r_maclist_tmp;
		}
		r_maclist = r_maclist->next;
	}
}

#if 0
uint8 rast_get_rclass(int bssidx, int vifidx)
{

}

uint8 rast_get_channel(int bssidx, int vifidx)
{

}

int rast_send_bsstrans_req(int bssidx, int vifidx, struct ether_addr *sta_addr, struct ether_addr *nbr_bssid)
{

}
#endif
#endif

#ifdef RTCONFIG_BCN_RPT
//check the RRM Capable station's Mac address 
int check_rrm_sta(int unit, int subunit,char* mac)
{
	char cmd[100],buf[256];
        FILE *fp;
	int i,cnt,find;
        char ifname[10]={0};
        char prefix[7]={0};
	char mac_addr[18];
        if(subunit > 0)
                snprintf(prefix, sizeof(prefix), "wl%d.%d", unit, subunit);
        else
                snprintf(prefix, sizeof(prefix), "wl%d", unit);

        strncpy(ifname,nvram_safe_get(strcat_safe(prefix, "_ifname")),sizeof(ifname));
	if( !strlen(ifname) ) {
		_dprintf("ifname get error\n");
		return 0;
	}

        snprintf(cmd, sizeof(cmd), "wifitool %s rrm_sta_list", ifname);
        if ((fp = popen(cmd, "r")) == NULL)
                return 0;

        buf[0] = '\0';
	cnt=0;
	find=0;

	if(mac==NULL)
                memset(mac_addr,0,sizeof(mac_addr));
        else
                strcpy(mac_addr,mac);

	if (strlen(mac_addr))
                for (i = 0; i < strlen(mac_addr); i++)
                        mac_addr[i] = tolower(mac_addr[i]);

        while (fgets(buf, sizeof(buf), fp)) {
		cnt++;	
		if(strlen(mac_addr) && strstr(buf,mac_addr))
			find=1;		
        }
        pclose(fp);

	if(strlen(mac_addr))  //find specified sta with rrm
	{
		//_dprintf("rrm:check sta[%s] on %s => [%s]\n",mac_addr,ifname,find?"ok":"fail");
		return find;
	}
	else if(cnt>1) //athX' has client with rrm?
		return 1;
	else
        	return 0;
	
}
#ifdef RTCONFIG_11K_RCPI_CHECK
void qca_11k_ret_parse_for_rcpi_check(char *buf,struct rcpi_checklist **rcpi_list) {
	int i;
	char ap_mac[]="xx:xx:xx:xx:xx:xx";
	char sta_mac[]="xx:xx:xx:xx:xx:xx";
	int chnum __attribute__((unused));
	int8 rcpi = 0; //rssi, ref by lbd
	char *p1=NULL,*b=NULL,*value=NULL;
	i=0;
	p1=strstr(buf,"[");
	if(p1)
	{
		while ((b = strsep(&p1, "[")) != NULL) {
			if((vstrsep(b, "]", &value) != 1)) continue;
			if(strlen(value))
			{
				//_dprintf("value[%d]=%s\n",i,value);
				switch(i)
				{
					case 0:
						strcpy(sta_mac,value);
						break;
					case 1:
						strcpy(ap_mac,value);
						break;
					case 2:
						chnum=atoi(value);
						break;
					case 3:
						rcpi=(int8)atoi(value);
						break;
					default:
						break;
				}
				i++;
			}
		}
		if(i!=4) //incorrect 
			return;
	}
	else
		return;

	//TOUPPER
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		sta_mac[i]=toupper(sta_mac[i]);
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		ap_mac[i]=toupper(ap_mac[i]);	
	RAST_DBG("sta_mac=%s,ap_mac=%s,rssi=%hhd\n",sta_mac,ap_mac,rcpi);
	add_to_rcpi_checklist(sta_mac,ap_mac,(char)rcpi,rcpi_list);

}

static void qca_rast_update_beacon_report_ret_for_rcpi_check(char *sta_mac, char *ap_mac, char rcpi) {
	json_object *root = NULL;
	json_object *existApObj = NULL;
	json_object *reportApObj = NULL;
	int lock,i;
	char rssiStr[4];
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt\0";
	//TOUPPER
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		sta_mac[i]=toupper(sta_mac[i]);
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		ap_mac[i]=toupper(ap_mac[i]);

	snprintf(path, sizeof(path), "/tmp/%s_bcn_rpt", sta_mac);

	//RAST_INFO("rcpi_to_rssi %d\n", rcpi_to_rssi(rcpi) );

	snprintf(rssiStr, sizeof(rssiStr), "%hhd", rcpi );

	RAST_DBG("sta_mac=%s,ap_mac=%s,rssi=%hhd\n", sta_mac, ap_mac, rcpi);

	lock = file_lock(path+5);
	root = json_object_from_file(path);
	if(!root) {
		RAST_DBG("%s,no file or valid content\n", path);
		goto qca_rast_update_beacon_report_ret_end;
	}

	json_object_object_get_ex(root, ap_mac, &existApObj);
	if (existApObj) {
		RAST_DBG("report AP is exist\n");
		goto qca_rast_update_beacon_report_ret_end;
	}

	reportApObj = json_object_new_object();
	if (!reportApObj) {
		RAST_DBG("reportApObj is NULL\n");
		goto qca_rast_update_beacon_report_ret_end;
	}

	json_object_object_add(reportApObj, RAST_RCPI, json_object_new_string(rssiStr));
	json_object_object_add(root, ap_mac, reportApObj);
	json_object_to_file(path, root);

qca_rast_update_beacon_report_ret_end:
	json_object_put(root);
	file_unlock(lock);	
}
#endif
void qca_rast_update_beacon_report_ret(char *buf) {
	json_object *root = NULL;
	json_object *existApObj = NULL;
	json_object *reportApObj = NULL;
	int lock;
	char rssiStr[4];
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt\0";
	int i;
	
	char ap_mac[]="xx:xx:xx:xx:xx:xx";
	char sta_mac[]="xx:xx:xx:xx:xx:xx";
	int chnum __attribute__((unused));
	int8 rcpi; //rssi, ref by lbd
	char *p1=NULL,*b=NULL,*value=NULL;
	i=0;
	p1=strstr(buf,"[");
	if(p1)
	{
		while ((b = strsep(&p1, "[")) != NULL) {
			if((vstrsep(b, "]", &value) != 1)) continue;
			if(strlen(value))
			{
				//_dprintf("value[%d]=%s\n",i,value);
				switch(i)
				{
					case 0:
						strcpy(sta_mac,value);
						break;
					case 1:
						strcpy(ap_mac,value);
						break;
					case 2:
						chnum=atoi(value);
						break;
					case 3:
						rcpi=(int8)atoi(value);
						break;
					default:
						break;
				}
				i++;
			}
		}
		if(i!=4) //incorrect 
			return;
	}
	else
		return;

	//TOUPPER
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		sta_mac[i]=toupper(sta_mac[i]);
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		ap_mac[i]=toupper(ap_mac[i]);

	snprintf(path, sizeof(path), "/tmp/%s_bcn_rpt", sta_mac);

	//RAST_INFO("rcpi_to_rssi %d\n", rcpi_to_rssi(rcpi) );

	snprintf(rssiStr, sizeof(rssiStr), "%d", rcpi );
	//snprintf(ap_mac, sizeof(ap_mac), %s, bssid);
	
	RAST_DBG("sta_mac=%s,ap_mac=%s,rssi=%d\n",sta_mac,ap_mac,rcpi);

	lock = file_lock(path+5);
	root = json_object_from_file(path);
	if(!root) {
		RAST_DBG("%s,no file or valid content\n", path);
		goto qca_rast_update_beacon_report_ret_end;
	}

	json_object_object_get_ex(root, ap_mac, &existApObj);
	if (existApObj) {
		RAST_DBG("report AP is exist\n");
		goto qca_rast_update_beacon_report_ret_end;
	}

	reportApObj = json_object_new_object();
	if (!reportApObj) {
		RAST_DBG("reportApObj is NULL\n");
		goto qca_rast_update_beacon_report_ret_end;
	}

	json_object_object_add(reportApObj, RAST_RCPI, json_object_new_string(rssiStr));
	json_object_object_add(root, ap_mac, reportApObj);
	json_object_to_file(path, root);

qca_rast_update_beacon_report_ret_end:
	json_object_put(root);
	file_unlock(lock);
}

int report_check_11k(int unit)
{
	char cmdbuf[100],var[256];
	FILE *fp;
	int cnt;
	int swap_unit=swap_5g_band(unit);

#ifdef RTCONFIG_11K_RCPI_CHECK
	struct rcpi_checklist *rcpi_list=NULL;
	struct rcpi_checklist *rcpi_list_tmp=NULL;
	struct report_entry   *report_entry_tmp=NULL;
#endif


	if(check_rrm_sta(swap_unit,0,NULL)==0)
	{
		return 0;
	}

	snprintf(cmdbuf, sizeof(cmdbuf), "wifitool %s bcnrpt", get_wififname(swap_unit));
	if ((fp = popen(cmdbuf, "r")) == NULL)
		return 0;
	var[0] = '\0';
	cnt=0;
	while (fgets(var, sizeof(var), fp)) {
		if(cnt)
		{
#ifdef RTCONFIG_11K_RCPI_CHECK
			qca_11k_ret_parse_for_rcpi_check(var, &rcpi_list);
#else
			//_dprintf("bcn report ==> %s\n", var);
			qca_rast_update_beacon_report_ret(var);
#endif
		}		
		cnt++;
	}
	pclose(fp);

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
				RAST_DBG("set to json file %s %s %d\n",rcpi_list->sta_mac,rcpi_list->rplist->ap_mac,rcpi_list->rplist->rcpi);
				qca_rast_update_beacon_report_ret_for_rcpi_check(rcpi_list->sta_mac,rcpi_list->rplist->ap_mac,rcpi_list->rplist->rcpi);
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
#endif

	return 0;
}

pthread_t thread_11k_wifi0,thread_11k_wifi1,thread_11k_wifi2;

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


void rast_bcn_rpt_init(void) 
{
	pthread_attr_t attr_0,attr_1;
#if defined(RTCONFIG_HAS_5G_2)
	pthread_attr_t attr_2;
#endif
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
#if defined(RTCONFIG_HAS_5G_2)
        sleep(3);

        args = malloc(sizeof(int));
        if(args == NULL)
        {
                RAST_INFO("malloc error\n");
                return;
        }
        *args = 2;

        pthread_attr_init(&attr_2);
        pthread_attr_setdetachstate(&attr_2, PTHREAD_CREATE_DETACHED);
        pthread_create(&thread_11k_wifi2,&attr_2,(void *)&rast_start_bcn_rpt_wifiX,args);
        pthread_attr_destroy(&attr_2);
#endif
}

int get_channel_number(char *wifname,int *width,int *primary_channel)
{
	*primary_channel = get_channel(wifname);
	return 0;
}

int regclass(int channel)
{
	if ((channel >= 1) && (channel <= 13)) 
		return 81;
	else if(channel==14)
		return 82;
	else if ((channel >= 36) && (channel <= 48))
		return 115; 
	else if ((channel >= 52) && (channel <= 64))
		return 118;
	else if ((channel >= 100) && (channel <= 140))
		return 121;
	else if (channel >= 149)
		return 125;

	return 0;
}

void
rast_send_beacon_request(int unit, int vifidx, struct ether_addr *addr)
{
	char 	*ifname=NULL;
	char 	macaddr_str[32]={0};
	int 	width=0;
	char 	command[1024];

	int regulatory_class=0;
	int channel=0;
	int random_interval=0;
	//non-DFS: active mode 0 + duration 50
	//DFS: passive mode 1 + duration 200
	int measurement_duration=50; //200;
	int mode=1; //0; //0:passive 1:active 2:beacon table
	int req_ssid=1; //match ath'x ssid 
	int report_condition=0;
	int report_detail=0;
	int req_ie=0;
	int chanrpt_mode=0;
	char bssid[]="ff:ff:ff:ff:ff:ff";
	int tmpch=0,multi_channel_5g=0;
	
	ifname = strdup( get_wififname( swap_5g_band(unit) ) );
	if ( !ifname )
	 	goto rast_send_beacon_request;

	/* MAC address */
	sprintf( macaddr_str, MACF, ETHERP_TO_MACF( addr ) );
	if(check_rrm_sta(swap_5g_band(unit),0,macaddr_str)==0)
	{
	//	_dprintf("stop to send 802.11k request\n");
	 	goto rast_send_beacon_request;
	}
	
	/* Channel */
	if( get_channel_number( ifname, &width, &channel ) )
		goto rast_send_beacon_request;
	
	multi_channel_5g=nvram_get_int("multi_channel_5g");
	tmpch=channel;
	while(1)
	{
		regulatory_class=regclass(tmpch);
		sprintf(command,"wifitool %s sendbcnrpt %s %d %d %d %d %d %d %d %d %d %d %s",
			get_wififname(swap_5g_band(unit)),macaddr_str,regulatory_class,tmpch,
			random_interval,measurement_duration,
			mode,req_ssid,report_condition,
			report_detail,req_ie,chanrpt_mode,
			bssid);
		doSystem(command);
		sleep(2);
		//_dprintf("command=%s\n",command);
		if(multi_channel_5g!=0 && tmpch!=multi_channel_5g)
		{
			tmpch=multi_channel_5g;
			//_dprintf("switch to multichannel 5g\n");
		}
		else
			break;
	}
rast_send_beacon_request:
	if(ifname)
		free(ifname);
	return;
}


#ifdef RTCONFIG_BTM_11V	
int rast_send_11v_req(int idx,int vidx,char *sta_mac, char *candidate_ap_mac)
{
	int unit = 0,width=0,channel=0;
	char command[1024];
	int ret = BTM_CMD_FAIL;
	char ifname[10]={0};
	char prefix[7]={0};
 	int candidate_preference=255;
        int regulatory_class=0;
	char *tmp=NULL;
	int status=0,unfriendly=0;
	/* if guest network supports roamast, here might need to check  */
	unit = idx;

	/* get served ap bssid */
	if(vidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d", swap_5g_band(unit), vidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d", swap_5g_band(unit));

	strncpy(ifname,nvram_safe_get(strcat_safe(prefix, "_ifname")),sizeof(ifname));

	if( !strlen(ifname) ) {
		_dprintf("ifname get error\n");
		ret = BTM_OTHER;
		goto rast_send_11v_req_failed;
	}

	/* send command to hostapd to send 11v packet */
	if( get_channel_number( ifname, &width, &channel ) ){
		ret = BTM_OTHER;
		goto rast_send_11v_req_failed;
	}

	status=0;unfriendly=0;
	while(1) {
		regulatory_class=regclass(channel);
		sprintf(command,"wifitool %s sendbstmreq_target %s %s %d %d %d %d",
			ifname, sta_mac, candidate_ap_mac,channel,candidate_preference,regulatory_class,swap_5g_band(unit)?9:7);
		//_dprintf("=> 11v command =%s\n",command);
		doSystem(command);
		sleep(3);
        	if ((tmp=get_qca_iwpriv(ifname, "g_bss_status")))
        	{
               	 	status= atoi(tmp);
                	free(tmp);
			if(status==0)
			{
				ret=BTM_RET_ACCEPT_TARGETMAC_NOTSELF; //change to another ap
				break;
			}
			else if (status==15)
			{
				ret = BTM_TIMEOUT;
				unfriendly++;
				if(unfriendly<2)
					continue;
			}
			else
				ret = BTM_RET_ACCEPT_TARGETMAC_SELF; //reject to transmison
		}
		else
			ret = BTM_OTHER;
		goto rast_send_11v_req_failed;
	}		
rast_send_11v_req_failed:
	return ret;
}
#endif //#ifdef RTCONFIG_BTM_11V


#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
char * mac_to_string(const u_int8_t mac[6])
{
    static char a[18];
    int i;

    i = snprintf(a, sizeof(a), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (i < 17 ? NULL : a);
}

int check_btm_sta(int unit, int subunit, char* mac_addr)
{
#define IEEE80211_IOC_BTM 			0xFFA0
#define IEEE80211_EXTCAPIE_BSSTRANSITION        0x00080000
#define IEEE80211_IOCTL_STA_INFO        (SIOCDEVPRIVATE+6)
        char ifname[10]={0};
        char prefix[7]={0};
        struct iwreq wrq;
	u_int8_t buf[6*1024];
	u_int8_t tmp[6];
	char *mac_string = NULL;
	size_t len=0;
	int i,cnt=0,cmp=0;
        /* get served ap bssid */
        if(subunit > 0)
                snprintf(prefix, sizeof(prefix), "wl%d.%d", unit, subunit);
        else
                snprintf(prefix, sizeof(prefix), "wl%d", unit);
	memset(buf,0,sizeof(buf));
        strncpy(ifname,nvram_safe_get(strcat_safe(prefix, "_ifname")),sizeof(ifname));
	memset(&wrq,0,sizeof(wrq));

	wrq.u.data.flags= IEEE80211_IOC_BTM;
	wrq.u.data.pointer = buf;
	wrq.u.data.length = sizeof(buf);


	if( !strlen(ifname) ) {
		_dprintf("ifname get error\n");
		return -1;
	}

	if (wl_ioctl(ifname, IEEE80211_IOCTL_STA_INFO, &wrq) < 0)
	{
		//_dprintf("%s: errors in getting %s IEEE80211_IOCTL_STA_INFO result\n", __func__, ifname);
		return -1;
	}

	if (wrq.u.data.length < ETHER_ADDR_LEN)
	{
		//_dprintf("%s: errors in getting %s IEEE80211_IOCTL_STA_INFO length\n", __func__, ifname);
        	return -1;
    	}

	len=wrq.u.data.length;
	cnt=0;
	while(len>=ETHER_ADDR_LEN)
        {
		memcpy(tmp,buf+ETHER_ADDR_LEN*cnt,ETHER_ADDR_LEN);
		mac_string = mac_to_string(tmp);

		if(mac_addr!=NULL)
		{
			for(i=0;i<17;i++)
			{
				cmp=abs(*(mac_addr+i)-*(mac_string+i));
				if(cmp != 0 && cmp!=32) //upper or lower 
					break; // mismatch 
				if(i==16)
					return 1; //11v client
			}
		}
		len-=ETHER_ADDR_LEN;
		cnt++;
	}
        return 0;

}
	

int check_if_support_kv(int unit,int subunit,rast_sta_info_t *sta)
{
	int ret=0;
	char sta_mac[32];
	snprintf(sta_mac, sizeof(sta_mac), MACF_UP, ETHER_TO_MACF(sta->addr));

	int swap_unit=swap_5g_band(unit);

	if(check_rrm_sta(swap_unit,subunit,sta_mac)!=0)
		ret |= RAST_SUPPORT_K_PASSIVE_SCAN;

	if(check_btm_sta(swap_unit,subunit,sta_mac)==1)
		ret |= RAST_SUPPORT_V;

	//_dprintf("sta %s is support 11k & 11v\n",sta_mac);		
	return ret;

}
#endif
#endif /* RTCONFIG_BCN_RPT */

#ifdef RTCONFIG_RAST_NONMESH_KVONLY
int kv_handler_init(void){
	return 0;
}

int kv_handler_deinit(void){
	return 0;
}

void wait_k_resp(struct report_list_entry **rplist,int *num){
	return 0;
}

int is_support_rast_nonmesh(void){
	return 0;
}
#endif //RTCONFIG_RAST_NONMESH_KVONLY

#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_get_driver_maclist(int idx,int vidx,char *maclist_buf_local,int buf_size,int *static_macmode){
	return 0;
}

int rast_check_driver_maclist(int bssidx,int vifidx,struct ether_addr *addr){
	return 0;
}
#endif
