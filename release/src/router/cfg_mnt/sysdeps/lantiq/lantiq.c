#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <shared.h>
#include <signal.h>
#include <wlioctl.h>
#include <bcmnvram.h>
#include <bcmendian.h>
#include <shutils.h>
#include <wlutils.h>
#include "cfg_common.h"
#include "cfg_wevent.h"
#include "chmgmt.h"
#include <unistd.h>
#include "cfg_slavelist.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#include <net/if_arp.h>

const char WIF_5G[] = "wlan2";
const char WIF_2G[] = "wlan0";

#define ETHER_ADDR_STR_LEN	18
#define	MAX_STA_COUNT	128

#define CFG_MNT_STA_INFO_PATH "/tmp/ltq_cfgmnt_channel"

static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh16(i) (g_swap?bcmswap16(i):(uint16)(i))

#define STA_RSSI_INFO_PATH "/tmp/ltq_rast_sta_rssi"
#define STA_INFO_PATH_CFG "/tmp/ltq_rast_sta_cfg"

//extern int wlan_setChannel(int index, uint32 channel);
//extern int wlan_setChannelMode(int index, char *channelMode, bool gOnlyFlag, bool nOnlyFlag, bool acOnlyFlag);

//extern int wlan_getChannelMode(int index, char *channelMode);

int get_chans_info(char* buf, size_t len)
{
return 0;
}

char *get_pap_bssid(int unit, char *bssid_buf, int buf_len)
{
	char buf[8192];
	FILE *fp;
	int len;
	char *pt1, *pt2;
	static char bssid_str[sizeof("00:00:00:00:00:00XXX")];

	memset(bssid_str,0,sizeof("00:00:00:00:00:00XXX"));

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
					strncpy(bssid_str,pt2,17 );
				}
			}
		}
	}

	//_dprintf("[cfg_mnt:get_pap_bssid]%s:%s\n",get_staifname(unit),bssid_str);

	return bssid_str;

}

int get_pap_rssi(int unit)
{
	char buf[8192];
	FILE *fp;
	int len,ret=0;
	char *pt1;

	snprintf(buf, sizeof(buf), "iwconfig %s", get_staifname(unit));
	fp = popen(buf, "r");
	if(fp){
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if(len > 1){
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Signal level=");
			if(pt1){
				pt1+=strlen("Signal level=");
				sscanf(pt1,"%d",&ret);
			}
		}
	}

	return ret;
}

/*
struct maclist {
        uint count;                      number of MAC addresses
        struct ether_addr ea[1];         variable length array of MAC addresses
};
*/

int get_sta_list_by_ifname(char *name,struct maclist *clist)
{
	char buf[8192]={0};
	FILE *fp;
	int len;
	char *pt1;

	char mac_tmp[]="xx:xx:xx:xx:xx:xx\0";

	if(!strlen(name) || !clist)
		return -1;

	clist->count=0;

	snprintf(buf, sizeof(buf), "iwlist %s peers", name);
	fp = popen(buf, "r");
	if(fp){
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);

		//_dprintf("len = %d\n",len);

		if(len > 1){
			buf[len-1] = '\0';  //need to check if need?
			pt1 = strstr(buf, "Peers/Access-Points in range:");
			if(pt1){
					pt1+=strlen("Peers/Access-Points in range:");
				while(1){
					if( pt1[0] < 48 || pt1[0] > 122)
					{
						//_dprintf("skip\n");
						pt1 ++ ;
						len --;
						if( len<=0 ) break;
						continue;
					}
					memset(mac_tmp,0,sizeof(mac_tmp));
					sscanf(pt1,"%s",mac_tmp);
					pt1+=strlen("xx:xx:xx:xx:xx:xx");
					len = len - strlen("xx:xx:xx:xx:xx:xx");
					//pt1+=2;//?? \n and tab?
					//memcpy(&clist->ea[clist->count],mac_tmp,strlen(mac_tmp));
					ether_atoe(mac_tmp, &clist->ea[clist->count]);
					clist->count++;
					if( len<0) break;
					//sscanf(pt1,"%s",mac_tmp);
				}
			}
		}
	}

	return 0;
}

int get_sta_list_with_rssi_by_ifname(char *ifname,struct maclist *clist, int *rssi_list)
{
	FILE *fp;
	//char *ifname;
//	char wif_buf[32];
	char line_buf[300];
	char mac_tmp[18];
	char rssi_str[5];
	//char txbytes[32];
	//char rxbytes[32];
	//unsigned long totalbytes;
	//rast_sta_info_t *sta = NULL;
	//time_t now = uptime();

	if(!strlen(ifname) || !clist)
		return -1;

	clist->count=0;

	doSystem("iw dev %s station dump > %s", ifname, STA_INFO_PATH_CFG);
	fp = fopen(STA_INFO_PATH_CFG, "r");
	if (fp) {
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			if(strstr(line_buf, "Station")) {
				memset(mac_tmp,0,sizeof(mac_tmp));
				sscanf(line_buf, "%*s%s", mac_tmp);
				while ( fgets(line_buf, sizeof(line_buf), fp) ) {
					if(strstr(line_buf, "signal")) {
						memset(rssi_str,0,sizeof(rssi_str));
						sscanf(line_buf, "%*s%s", rssi_str);
						break;
					}
				}

				//_dprintf("%s %s %s\n",ifname,mac_tmp,rssi_str);

				rssi_list[clist->count] = atoi(rssi_str);
				//memcpy(&clist->ea[clist->count],mac_tmp,strlen(mac_tmp));
				ether_atoe(mac_tmp, &clist->ea[clist->count]);
				clist->count++;
			}
		}

		fclose(fp);
		unlink(STA_INFO_PATH_CFG);
	}

	return 0;
}
#if 0
void get_sta_rssi_by_mac(char *ifname, char *macaddr, int *rssi)
{
	FILE *fp;
	char line_buf[300];
	char rssi_str[5];
/*
/ # iw dev wlan2 station get  xx:xx:xx:xx:xx:xx
Station xx:xx:xx:xx:xx:xx (on wlan2)
        inactive time:  16720 ms
        signal:         -29 dBm
*/
	if (!macaddr || strlen(macaddr)!=17)
		return ;
//
//
//
//
//
//
// the ret of "iw dev wlan2 station get  xx:xx:xx:xx:xx:xx" is not right.
//
//
//
//
//
//
	doSystem("iw dev %s station get %s > %s", ifname,macaddr,STA_RSSI_INFO_PATH);
	fp = fopen(STA_RSSI_INFO_PATH, "r");
	if (fp) {
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			if( strstr(line_buf, "Station") ) {
				//sscanf(line_buf, "%*s%s", addr);
				while ( fgets(line_buf, sizeof(line_buf), fp) ) {
					if(strstr(line_buf, "signal")) {
						sscanf(line_buf, "%*s%s", rssi_str);
						break;
					}
				}
				*rssi = atoi(rssi_str);
				_dprintf("%s %s rssi %d\n",ifname,macaddr,*rssi);
			}
		}

		fclose(fp);
		unlink(STA_RSSI_INFO_PATH);
	}

	return;
}
#endif
int wl_sta_list(char *msg, int msg_len)
{
#if 1
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	struct maclist *auth = NULL;
	int mac_list_size;
	int i;
	char ea[ETHER_ADDR_STR_LEN];
	char name_vif[] = "wlX.Y_XXXXXXXXXX";
	int ii;
	int unit = 0;
	char word[256], *next;
	char brMac[32] = {0};
	char ifAlias[16] = {0};
	json_object *root = NULL;
	json_object *brMacObj = NULL;
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int ret = 0;
	time_t ts;
	//char pap[18] = {0};
	//int pass_entry = 0;

	time(&ts);

	snprintf(brMac, sizeof(brMac), "%s", get_unique_mac());

	root = json_object_new_object();
	brMacObj = json_object_new_object();

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

		if (!strlen(name))
			goto exit;

		/* buffers and length */
		mac_list_size = sizeof(auth->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
		auth = malloc(mac_list_size);

		if (!auth)
			goto exit;

		memset(auth, 0, mac_list_size);

	 	if(get_sta_list_by_ifname(name,auth)<0)
	 		goto exit;

		memset(ifAlias, 0, sizeof(ifAlias));
		if(!strcmp(name,"wlan0")) strcpy(ifAlias,"2G");
		else if(!strcmp(name,"wlan2")) strcpy(ifAlias,"5G");

		/* build authenticated sta list */
		for (i = 0; i < auth->count; ++i) {
			//sta = wl_sta_info(name, &auth->ea[i]);
			//if (!sta) continue;
			//if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

			ether_etoa((void *)&auth->ea[i], ea);

			if (!bandObj)
				bandObj = json_object_new_object();
			staObj = json_object_new_object();
			json_object_object_add(staObj, WEVENT_TIMESTAMP,
			json_object_new_int64(ts));
			json_object_object_add(bandObj, ea, staObj);
		}

		if (bandObj)
			json_object_object_add(brMacObj, ifAlias, bandObj);

		for (i = 1; i < 4; i++) {
			bandObj = NULL;
#ifdef RTCONFIG_WIRELESSREPEATER
			if ((sw_mode() == SW_MODE_REPEATER)
				&& (unit == nvram_get_int("wlc_band")) && (i == 1))
				break;
#endif
			memset(prefix, 0, sizeof(prefix));
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
			name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
			snprintf(name_vif,sizeof(name_vif),"%s",name);

			if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
			{
				memset(auth, 0, mac_list_size);
				memset(ifAlias, 0, sizeof(ifAlias));

				/* guest network interface in bluecave is wlanx.x */
				if(!strncmp(name_vif,"wlan0",5)) strcpy(ifAlias,"2G");
				else if(!strncmp(name_vif,"wlan2",5)) strcpy(ifAlias,"5G");

       		 	if(get_sta_list_by_ifname(name_vif,auth)<0)
       		 		goto exit;
				for (ii = 0; ii < auth->count; ii++) {
					//sta = wl_sta_info(name_vif, &auth->ea[ii]);
					//if (!sta) continue;
					//if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

					ether_etoa((void *)&auth->ea[ii], ea);

					/* filter sta's mac is same as ours */

					if (!bandObj)
						bandObj = json_object_new_object();
					staObj = json_object_new_object();
					json_object_object_add(staObj, WEVENT_TIMESTAMP,
					json_object_new_int64(ts));
					json_object_object_add(bandObj, ea, staObj);
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

	if (brMacObj) {
		json_object_object_add(root, brMac, brMacObj);
		snprintf(msg, msg_len, "%s", json_object_to_json_string(root));
	}
	ret = 1;
	/* error/exit */

exit:
	json_object_put(root);

	if (auth) free(auth);

	return ret;
#else
	return 0;
#endif
}

int wl_sta_rssi_list(json_object *root)
{
#if 1
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	struct maclist *auth = NULL;
	int mac_list_size;
	int i;
	char ea[ETHER_ADDR_STR_LEN];
	char name_vif[] = "wlX.Y_XXXXXXXXXX";
	int ii;
	int unit = 0;
	char word[256], *next;
	char ifAlias[16] = {0};
	json_object *bandObj = NULL;
	json_object *staObj = NULL;
	int ret = 0;
	int *rssi_list=NULL;

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

		if (!strlen(name))
			goto exit;

		/* buffers and length */
		mac_list_size = sizeof(auth->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
		auth = malloc(mac_list_size);
		if (!auth)
			goto exit;

		rssi_list = malloc(MAX_STA_COUNT*sizeof(int));
		if (!rssi_list)
			goto exit;

		memset(auth, 0, mac_list_size);
		memset(rssi_list, 0, MAX_STA_COUNT*sizeof(int));
		/* query wl for authenticated sta list */
		//strcpy((char*)auth, "authe_sta_list");
		//if (wl_ioctl(name, WLC_GET_VAR, auth, mac_list_size))
		//	goto exit;
       	if(get_sta_list_with_rssi_by_ifname(name,auth,rssi_list)<0)
       		goto exit;
		memset(ifAlias, 0, sizeof(ifAlias));
		if(!strcmp(name,"wlan0")) strcpy(ifAlias,"2G");
		else if(!strcmp(name,"wlan2")) strcpy(ifAlias,"5G");
		//if_nametoalias(name, &ifAlias[0], sizeof(ifAlias));

		/* build authenticated sta list */
		for (i = 0; i < auth->count; ++i) {
			//sta = wl_sta_info(name, &auth->ea[i]);
			//if (!sta) continue;
			//if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

			ether_etoa((void *)&auth->ea[i], ea);

			/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMARM) && defined(RTCONFIG_PROXYSTA) && defined(RTCONFIG_DPSTA)
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

			//get_sta_rssi_by_mac(name,&auth->ea[i],&rssi);

			//memcpy(&scb_val.ea, &auth->ea[i], ETHER_ADDR_LEN);
			//if (wl_ioctl(name, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t)))
			//	rssi = 0;
			//else
			//	rssi =  scb_val.val;

			//_dprintf("rssi list %d\n",rssi_list[i]);

			if (!bandObj)
				bandObj = json_object_new_object();
			staObj = json_object_new_object();
			json_object_object_add(staObj, CFG_STR_RSSI,
			json_object_new_int(rssi_list[i]));
			json_object_object_add(bandObj, ea, staObj);
		}

		if (bandObj)
			json_object_object_add(root, ifAlias, bandObj);

		for (i = 1; i < 4; i++) {
			bandObj = NULL;
#ifdef RTCONFIG_WIRELESSREPEATER
			if ((sw_mode() == SW_MODE_REPEATER)
				&& (unit == nvram_get_int("wlc_band")) && (i == 1))
				break;
#endif
			memset(prefix, 0, sizeof(prefix));
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);
			name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
			snprintf(name_vif,sizeof(name_vif),"%s",name);

			if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
			{
				memset(auth, 0, mac_list_size);
				memset(ifAlias, 0, sizeof(ifAlias));
				memset(rssi_list, 0, MAX_STA_COUNT*sizeof(int));

				/* guest network interface in bluecave is wlanx.x */
				if(!strncmp(name_vif,"wlan0",5)) strcpy(ifAlias,"2G");
				else if(!strncmp(name_vif,"wlan2",5)) strcpy(ifAlias,"5G");
				//if_nametoalias(name_vif, &ifAlias[0], sizeof(ifAlias));

				/* query wl for authenticated sta list */
				//strcpy((char*)auth, "authe_sta_list");
				//if (wl_ioctl(name_vif, WLC_GET_VAR, auth, mac_list_size))
				//	goto exit;
       			if(get_sta_list_with_rssi_by_ifname(name_vif,auth,rssi_list)<0)
       				goto exit;

				for (ii = 0; ii < auth->count; ii++) {
					//sta = wl_sta_info(name_vif, &auth->ea[ii]);
					//if (!sta) continue;
					//if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;

					ether_etoa((void *)&auth->ea[ii], ea);

					/* filter sta's mac is same as ours */
#if defined(RTCONFIG_BCMARM) && defined(RTCONFIG_PROXYSTA) && defined(RTCONFIG_DPSTA)
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

					//get_sta_rssi_by_mac(name,&auth->ea[ii],&rssi);

					//memcpy(&scb_val.ea, &auth->ea[i], ETHER_ADDR_LEN);
					//if (wl_ioctl(name, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t)))
					//	rssi = 0;
					//else
					//		rssi =  scb_val.val;
					//_dprintf("name_vif %s rssi list %d ii\n",name_vif,rssi_list[ii]);
					if (!bandObj)
						bandObj = json_object_new_object();
					staObj = json_object_new_object();
					json_object_object_add(staObj, CFG_STR_RSSI,
					json_object_new_int(rssi_list[ii]));
					json_object_object_add(bandObj, ea, staObj);
				}

				if (bandObj)
					json_object_object_add(root, ifAlias, bandObj);
			}
		}

		if (auth) {
			free(auth);
			auth = NULL;
		}
		if (rssi_list) {
			free(rssi_list);
			rssi_list = NULL;
		}
		unit++;
	}

	ret = 1;
	/* error/exit */
exit:

	if (auth) free(auth);
	if (rssi_list) free(rssi_list);
	return ret;
#else
	return 0;
#endif
}

char *get_sta_mac(int unit)
{
#if 1
	char *aif;
	char *pMac;
    //char tmp[256];//prefix[] = "wlXXXXXXXXXX_";
	//char *mode = NULL;
	//int sta = 0, wet = 0, psta = 0, psr = 0;
	static char mac_buf[sizeof("00:00:00:00:00:00XXX")];

	aif = get_staifname(unit);
	//mode = nvram_safe_get(strcat_r(prefix, "mode", tmp));
	//sta = !strcmp(mode, "sta");
	//wet = !strcmp(mode, "wet");
	//psta = !strcmp(mode, "psta");
	//psr = !strcmp(mode, "psr");

        if (nvram_get_int("re_mode")) {
			memset(mac_buf, 0, sizeof(mac_buf));

			pMac = get_hwaddr(aif);
			if (pMac) {
				snprintf(mac_buf, sizeof(mac_buf), "%s", pMac);
				free(pMac);
				pMac = NULL;
			}
        }

	return mac_buf;
#else
	return NULL;
#endif
}

int cfgmnt_get_channel(char *wifname,int *width, int *channel_from, int *channel_to, int *primary_channel)
{
	FILE *fp;
	char line_buf[300];
	int ret_conut=0;

	doSystem("cat /proc/net/mtlk/%s/channel > %s", wifname, CFG_MNT_STA_INFO_PATH);
	fp = fopen(CFG_MNT_STA_INFO_PATH, "r");
	if (fp) {
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			if(strstr(line_buf, "width")) {
				sscanf(line_buf, "%*s%d", width);
				ret_conut++;
			} else	if(strstr(line_buf, "channum_from")) {
				sscanf(line_buf, "%*s%d", channel_from);
				ret_conut++;
			} else	if(strstr(line_buf, "channum_to")) {
				sscanf(line_buf, "%*s%d", channel_to);
				ret_conut++;
			} else	if(strstr(line_buf, "primary_channel")) {
				sscanf(line_buf, "%*s%d", primary_channel);
				ret_conut++;
			}
		}

		fclose(fp);
		unlink(CFG_MNT_STA_INFO_PATH);
	}

	if(ret_conut == 4){
		return 0;
	}

	*width = 0;
	*channel_from = 0;
	*channel_to = 0;
	*primary_channel = 0;

	return -1;
}

/* get channel info */
void wl_control_channel(int unit, int *channel, int *bw, int *nctrlsb)
{
	int ch_from=0,ch_to=0,ch_pri=0;
	char ifname[8]={0};

	*nctrlsb=0;

	/* bluecave only have one 5G band */
	if(unit == 0) strcpy(ifname,"wlan0");
	else if(unit == 1) strcpy(ifname,"wlan2");

	if(cfgmnt_get_channel(ifname, bw, &ch_from, &ch_to, &ch_pri) == -1)
		return;

	*channel = ch_pri;

	if( *bw == 40 && *channel == ch_to )
		*nctrlsb=0;
	else if (*bw == 40 && *channel != ch_to)
		*nctrlsb=1;
	else
		*nctrlsb=0;

}

int cfg_is_if_up(char *ifname)
{
	int s;
	struct ifreq ifr;

	/* Open a raw socket to the kernel */
	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		_dprintf("Open socket error, out\n");
		return -1;
	}

	/* Set interface name */
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	/* Get interface flags */
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0){
		_dprintf("Get interface flags error, out\n");
		close(s);
		return -1;
	}else{
		if(ifr.ifr_flags & IFF_UP){
			close(s);
			return 1;
		}
	}
	close(s);
	return 0;
}

int cfg_is_radio_good_to_go(int unit, int subunit)
{
	int ret =0;

	if(unit == 0) ret = cfg_is_if_up("wlan1");
	else if(unit == 1) ret = cfg_is_if_up("wlan3");
	else return 0;
	if(ret == 0){
		if(unit == 0) ret = cfg_is_if_up("wlan0");
		else if(unit == 1) ret = cfg_is_if_up("wlan2");

		return ret;
	}else if(ret == 1){
		return 0;
	} else {
		//_dprintf("cfg_is_radio_on out %d\n",__LINE__);
	}

	return 0;
}

void sync_control_channel(int unit, int channel, int bw, int nctrlsb)
{
	int wave_unit = 0;
	char channelMode[128]={0};
	char channel_str[10]={0};
	char nctrlsb_str[10]={0};
	sprintf(channel_str,"%d",channel);
	sprintf(nctrlsb_str,"%d",nctrlsb);

	_dprintf("%s channel:%d,bw:%d,nctrlsb:%d\n",__FUNCTION__,channel,bw,nctrlsb);

	if(unit != 0 && unit != 1)
	{
		_dprintf("unit error\n");
		return;
	}

	if(cfg_is_radio_good_to_go(unit,-1) != 1)
	{
		_dprintf("interface for unit %d is not ready to set channel.\n",unit);
		return;
	}

	if(bw == 20) {
		//strcpy(channelMode,"11ACVHT20");
		if(unit == 0) {
			nvram_set("aimesh_setchannel_bw_0","1");
			//nvram_set("wl0.1_bw","1");
		}
		else if(unit == 1){
			nvram_set("aimesh_setchannel_bw_1","1");
			//nvram_set("wl1.1_bw","1");
		}
	} else if(bw == 40) {
		#if 0
		if ((channel >= 36) && (channel <= 64)){
			if (((channel - 36) % 8) == 0){
				snprintf(channelMode, sizeof(channelMode), "11NAHT40PLUS");
			}else{
				snprintf(channelMode, sizeof(channelMode), "11NAHT40MINUS");
			}
		}
		else if ((channel >= 100) && (channel <= 144))
		{
			if (((channel - 100) % 8) == 0){
				snprintf(channelMode, sizeof(channelMode), "11NAHT40PLUS");
			}else{
				snprintf(channelMode, sizeof(channelMode), "11NAHT40MINUS");
			}
		}
		else if ((channel >= 149) && (channel <= 161))
		{
			if (((channel - 149) % 8) == 0){
				fprintf(stderr, "5G channel here\n");
				snprintf(channelMode, sizeof(channelMode), "11NAHT40PLUS");
			}else{
				snprintf(channelMode, sizeof(channelMode), "11NAHT40MINUS");
			}
		}
		#endif
		if(unit == 0){
			nvram_set("aimesh_setchannel_bw_0","2");
			//nvram_set("wl0.1_bw","2");
		}
		else if(unit == 1){
			nvram_set("aimesh_setchannel_bw_1","2");
			//nvram_set("wl1.1_bw","2");
		}
	} else if(bw == 80) {
		//strcpy(channelMode,"11ACVHT80");
		if(unit == 0){
			//nvram_set("wl0.1_bw","3");
			nvram_set("aimesh_setchannel_bw_0","3");
		}
		else if(unit == 1){
			//nvram_set("wl1.1_bw","3");
			nvram_set("aimesh_setchannel_bw_1","3");
		}
	} else  {
		return (0);
	}

	while(nvram_get_int("wave_action")!=WAVE_ACTION_IDLE){
		_dprintf("wave_action != IDLE, waint. [%s]\n",__FUNCTION__);
		sleep(1);
	}
	if(unit == 0)
	{
		//nvram_set("wl0.1_channel",channel_str);
		nvram_set("aimesh_setchannel_channel_0",channel_str);
		nvram_set("aimesh_setchannel_nctrlsb_0",nctrlsb_str);
		trigger_wave_monitor(__func__, __LINE__,
			WAVE_ACTION_SET_CHANNEL_2G);
	} else {
		//nvram_set("wl1.1_channel",channel_str);
		nvram_set("aimesh_setchannel_channel_1",channel_str);
		nvram_set("aimesh_setchannel_nctrlsb_1",nctrlsb_str);
		trigger_wave_monitor(__func__, __LINE__,
			WAVE_ACTION_SET_CHANNEL_5G);
	}
	sleep(10);
}

char *get_wififname(int band)
{
	const char *wif[] = { WIF_2G, WIF_5G };
	if (band < 0 || band >= ARRAY_SIZE(wif)) {
		dbg("%s: Invalid wl%d band!\n", __func__, band);
		band = 0;
	}
	return (char*) wif[band];
}

int get_wsc_status(int *fail_result)
{
	char buf[512] = {0};
	FILE *fp;
	int len;
	char *pt1,*pt2,*pt3;
	int unit = 0;

	snprintf(buf, sizeof(buf), "hostapd_cli -i%s wps_get_status %s", get_wififname(unit), get_wififname(unit));
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			/*buf[len-1] = '\0';
			pt1 = strstr(buf, "Last WPS result: ");
			if (pt1) {
				pt2 = pt1 + strlen("Last WPS result: ");
				pt1 = strstr(pt2, "Peer Address: ");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
				}

				if (!strcmp(pt2, "Success"))
					return 1;
				else if (!strcmp(pt2, "Failed") ||
					!strcmp(pt2, "Timed-out"))
					return 0;
			}*/
			buf[len-1] = '\0';
			pt1 = strstr(buf, "PBC Status: ");
			pt3 = strstr(buf, "Last WPS result: ");

			if (pt1) {
				pt2 = pt1 + strlen("PBC Status: ");
				pt1 = strstr(pt2, "Last WPS result: ");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
				}

				if (!strcmp(pt2, "Disabled")){
					// Check Last WPS result
					if (pt3) {
						pt2 = pt3 + strlen("Last WPS result: ");
						pt1 = strstr(pt2, "Peer Address: ");
						if (pt1) {
							*pt1 = '\0';
							chomp(pt2);
						}
						if (!strcmp(pt2, "Success")) {
							return 1;
						}
					}
					return 0;
				}
				else
					return 0;
			}
		}
	}
}
/*
36	5180	Indoors	✔	✔
40	5200	Indoors	✔	✔
44	5220	Indoors	✔	✔
48	5240	Indoors	✔	✔
52	5260	Indoors / DFS / TPC	DFS	DFS / TPC
56	5280	Indoors / DFS / TPC	DFS	DFS / TPC
60	5300	Indoors / DFS / TPC	DFS	DFS / TPC
64	5320	Indoors / DFS / TPC	DFS	DFS / TPC

100	5500	DFS / TPC	DFS	DFS / TPC
104	5520	DFS / TPC	DFS	DFS / TPC
108	5540	DFS / TPC	DFS	DFS / TPC
112	5560	DFS / TPC	DFS	DFS / TPC
116	5580	DFS / TPC	DFS	DFS / TPC

120	5600	DFS / TPC	No Access	DFS / TPC
124	5620	DFS / TPC	No Access	DFS / TPC
128	5640	DFS / TPC	No Access	DFS / TPC
132	5660	DFS / TPC	DFS	DFS / TPC
136	5680	DFS / TPC	DFS	DFS / TPC

140	5700	DFS / TPC	DFS	DFS / TPC
149	5745	SRD	✔	No Access
153	5765	SRD	✔	No Access
157	5785	SRD	✔	No Access
161	5805	SRD	✔	No Access
165	5825	SRD
*/
int freq_to_channel_num(int channel_freq)
{
	if(channel_freq == 5180) return 36;
	else if(channel_freq == 5180) return 36;
	else if(channel_freq == 5200) return 40;
	else if(channel_freq == 5220) return 44;
	else if(channel_freq == 5240) return 48;
	else if(channel_freq == 5260) return 52;
	else if(channel_freq == 5280) return 56;
	else if(channel_freq == 5300) return 60;
	else if(channel_freq == 5320) return 64;
	else if(channel_freq == 5500) return 100;
	else if(channel_freq == 5520) return 104;
	else if(channel_freq == 5540) return 108;
	else if(channel_freq == 5560) return 112;
	else if(channel_freq == 5580) return 116;
	else if(channel_freq == 5600) return 120;
	else if(channel_freq == 5620) return 124;
	else if(channel_freq == 5640) return 128;
	else if(channel_freq == 5660) return 132;
	else if(channel_freq == 5680) return 136;
	else if(channel_freq == 5700) return 140;
	else if(channel_freq == 5745) return 149;
	else if(channel_freq == 5765) return 153;
	else if(channel_freq == 5785) return 157;
	else if(channel_freq == 5805) return 161;
	else if(channel_freq == 5825) return 165;
	else return 0;
}

/*
//2462	#define WL_CHAN_VALID_HW        (1 << 0)         valid with current HW
//2463	#define WL_CHAN_VALID_SW        (1 << 1)         valid with current country setting
//2464	#define WL_CHAN_BAND_5G         (1 << 2)         5GHz-band channel
//2465	#define WL_CHAN_RADAR           (1 << 3)         radar sensitive  channel
//2466	#define WL_CHAN_INACTIVE        (1 << 4)         temporarily inactive due to radar
//2467	#define WL_CHAN_PASSIVE         (1 << 5)         channel is in passive mode
//2468	#define WL_CHAN_RESTRICTED      (1 << 6)         restricted use channel
*/
#define DFS_TIMEOUT 1800
#define DFS_TIMEOUT_12x 86400
struct dfs_record
{
	int channel;
	time_t time;
	struct dfs_record *next;
};

static int get_all_support_channels(int unit,int **out,int *num)
{
	int len;
	char tmp_buf[512]={0},*possible_chan_list=NULL;
	char *delim = ",";
	char * pch;
	int *tmp_int_list;
	int i =0;
	int wave_unit;

	*num=0;

	if(unit == 0)
		possible_chan_list = nvram_safe_get("pc_list_2g");
	else if(unit == 1)
		possible_chan_list = nvram_safe_get("pc_list_5g");
	else
		return -1;
	//_dprintf("%s\n",possible_chan_list);

	if(!possible_chan_list)
	{
		_dprintf("get channel list error\n");
		return -1;
	}

	strcpy(tmp_buf,possible_chan_list);

	len = strlen(tmp_buf);
	if(len <= 0)
		return -1;

	for(i=0;i<len;i++)
	{
		if(tmp_buf[i] == ',')
			(*num)++;
	}

	(*num)++; //tatal number

	*out = calloc(1,sizeof(int)*(*num));
	if(*out == NULL)
		return -1;

	tmp_int_list = *out;

	i=0;
	pch = strtok(tmp_buf,delim);
	while (pch != NULL)
	{
		//_dprintf ("%s\n",pch);
		tmp_int_list[i]=atoi(pch);
		i++;
		pch = strtok (NULL, delim);
	}

	return 0;

}

int wl_get_chans_info(int unit, char* buf, size_t len)
{
	char *nv,*nvp,*b,*nvram_str=NULL;
	char *t1,*t2;
	struct dfs_record *ch_list=NULL,*ch_list_head=NULL,*ch_list_prev=NULL;
	int num=0,nvram_ptr=0;
	char cmnfmt[16];
	int wave_unit=0,i;
	int *channel_list_val=NULL,channel_num_val=0,found_radar=0;
	time_t now_t = time(NULL);

	memset(buf, 0, len);
	//v1
	snprintf(cmnfmt, sizeof(cmnfmt), "%d ", CHINFO_CMNFMT_V1);
	strlcat(buf, cmnfmt, len);

	// -1 means get highest 5g band
	if(unit == -1)
		unit = 1;

	if ( get_all_support_channels(unit,&channel_list_val,&channel_num_val) )
	{
		return -1;
	}

	if(!channel_list_val || !channel_num_val)
	{
		_dprintf("channel_list_val %d channel_num_val %d\n",channel_list_val,channel_num_val);
		return -1;
	}

	/* load from nvram and remove timeout list */
	if(unit == 1){
		nv = nvp = strdup(nvram_safe_get("dfschinfo"));
		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ( vstrsep(b, ">",	&t1, &t2 ) != 2 )
					continue;

				if(!ch_list)
				{
					ch_list = malloc(sizeof(struct dfs_record));
					if(!ch_list)
						goto update_dfs_info_error;
					ch_list_head = ch_list;
					ch_list_prev = NULL;
				} else {
					ch_list->next = malloc(sizeof(struct dfs_record));
					if(!ch_list->next)
						goto update_dfs_info_error;
					ch_list_prev = ch_list;
					ch_list = ch_list->next;
				}

				memset(ch_list,0,sizeof(struct dfs_record));
				ch_list->channel = atoi(t1);
				ch_list->time = atoi(t2);

				//_dprintf("t1 %s t2 %s\n",t1,t2);
				//_dprintf("ch_list->channel %u ch_list->time %u\n",ch_list->channel,ch_list->time);

				if( (ch_list->channel == 5600 || ch_list->channel == 5620 || ch_list->channel == 5640) &&
					( (now_t-ch_list->time) > DFS_TIMEOUT_12x ) )
				{
					//_dprintf("remove %d %d\n",ch_list->channel,ch_list->time);
					//remove this entry
					if(!ch_list_prev) {
						ch_list_head=NULL;
					}
					free(ch_list);
					ch_list = ch_list_prev;
				} else if((now_t-ch_list->time) > DFS_TIMEOUT) {
					//_dprintf("remove %d %d\n",ch_list->channel,ch_list->time);
					//remove this entry
					if(!ch_list_prev) {
						ch_list_head=NULL;
					}
					free(ch_list);
					ch_list = ch_list_prev;
				} else {
					num++;
				}

			}
			free(nv);
		}

		/* update list */
		nvram_str = malloc((num+1)*20);
		if(!nvram_str)
			goto update_dfs_info_error;

		memset(nvram_str,0,(num+1)*20);

		for(i=0;i<channel_num_val;i++)
		{
			ch_list = ch_list_head;
			found_radar = 0;
			while(ch_list){
				if(freq_to_channel_num(ch_list->channel) == channel_list_val[i])
				{
					found_radar = 1;
					break;
				}
				ch_list = ch_list->next;
			}

			if(!found_radar)
			{
				snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_AVBL, channel_list_val[i] );
				//_dprintf("cmnfmt (%s)\n",cmnfmt);
				strlcat(buf, cmnfmt, len);
				//_dprintf("buf (%s)\n",buf);
			}

		}

		ch_list = ch_list_head;
		while(ch_list)//CHINFO_AVBL
		{
			snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", CHINFO_BLK, freq_to_channel_num(ch_list->channel) );
			//_dprintf("cmnfmt (%s)\n",cmnfmt);
			strlcat(buf, cmnfmt, len);
			//_dprintf("buf (%s)\n",buf);
			sprintf(nvram_str+nvram_ptr,"<%u>%lu",(unsigned int)ch_list->channel,(unsigned long)ch_list->time);
			nvram_ptr=strlen(nvram_str);

			ch_list = ch_list->next;
		}

		//if(!ch_list)
		//	sprintf(nvram_str+nvram_ptr,"<%u>%lu",(unsigned int)channel,(unsigned long)now_t);
		/* save list to nvram */
		//_dprintf("nvram_str (%s)\n",nvram_str);
		//_dprintf("buf (%s)\n",buf);
		/* do not need to commit nvram */
		nvram_set("dfschinfo",nvram_str);

		if(strlen(nvram_str))
			nvram_set("radar_status","1");
		else
			nvram_set("radar_status","0");

	} else {
		for(i=0;i<channel_num_val;i++)
		{
			snprintf(cmnfmt, sizeof(cmnfmt), "%05u%03u ", 0, channel_list_val[i] );
			//_dprintf("cmnfmt (%s)\n",cmnfmt);
			strlcat(buf, cmnfmt, len);
			//_dprintf("buf (%s)\n",buf);
		}
	}

		//_dprintf("buf (%s)\n",buf);

update_dfs_info_error:

	while(ch_list_head)
	{
		ch_list = ch_list_head->next;
		free(ch_list);
		ch_list_head = ch_list;
	}
	if(nvram_str)
		free(nvram_str);
	if(channel_list_val)
		free(channel_list_val);


	return (0);
}


//chmgmt_chconf_t format
// byte  3  2  1  0
//		BW SB CHANNEL
// CHANNEL = center channel, for example: 52 56 60 64(80) -> 58
//
int wl_get_chconf(const char *ifname, chmgmt_chconf_t *chconf)
{
	int i=0;
	char channelMode[128]={0};
	uint32_t channel=0;
	char *wlif_name = NULL;
	int width=0,ch_from=0,ch_to=0,ch_primary=0;

	/* bluecave only have one 5G band */
	wlif_name = get_wififname(1);
	if(!wlif_name || strlen(wlif_name) == 0)
		return -1;

	while(1){
		if( i>5 )
			break;
		cfgmnt_get_channel(wlif_name,&width,&ch_from,&ch_to,&ch_primary);
		if( !width || !ch_from || !ch_to || !ch_primary )
		{
			_dprintf("get channel info error,retry\n");
			i++;
			sleep(1);
			continue;
		}
		break;
	}

	if( !width || !ch_from || !ch_to || !ch_primary )
	{
		_dprintf("get channel info error,break\n");
		return -1;
	}

	*chconf = 0;

	*chconf = ( (ch_from + ch_to)/2 ) & 0x00FF;

	if( width == 80 )
	{
		// for example 52 56 60 64
		if(ch_primary == ch_from) CHCONF_SB_SET(*chconf, (CHCONF_SB_LL));  		//primary channel == 52
		else if(ch_primary == ch_to) CHCONF_SB_SET(*chconf, (CHCONF_SB_UU));	//primary channel == 64
		else if(ch_primary < ( (ch_from + ch_to)/2 ) ) CHCONF_SB_SET(*chconf, (CHCONF_SB_LU));	//primary channel == 56
		else if(ch_primary > ( (ch_from + ch_to)/2 ) ) CHCONF_SB_SET(*chconf, (CHCONF_SB_UL)); 	//primary channel == 60

		CHCONF_BW_SET80(*chconf);

		return (0);
	}
	else if( width == 20 )
	{
		CHCONF_BW_SET20(*chconf);
		return (0);
	}
	else if( width == 40 && ch_primary == ch_from) //check here
	{
		CHCONF_SB_SET(*chconf, (CHCONF_SB_LO));
		CHCONF_BW_SET40(*chconf);
		return (0);
	}
	else if( width == 40 && ch_primary == ch_to )
	{
		CHCONF_SB_SET(*chconf, (CHCONF_SB_UP));
		CHCONF_BW_SET40(*chconf);
		return (0);
	} else
	{
		return (-1);
	}

	return (0);
}

/*
This function is only called by radar detected event, only 5G band has radar events
*/
int wl_set_chconf(const char *ifname, chmgmt_chconf_t chconf)
{
	int wave_unit = 0;
	uint32_t channel=0;
	char channelMode[128]={0};
	char channel_str[10]={0};

	/* bluecave only have one 5G band */
	wave_unit = wl_wave_unit(1);

	channel = chmgmt_get_ctl_ch(chconf);
	if(channel <= 0)
		return (-1);
	sprintf(channel_str,"%d",channel);
	if(CHCONF_BW_IS20(chconf))
	{
		nvram_set("aimesh_setchannel_bw_1","1");
	} else if(CHCONF_BW_IS40(chconf)) {
		nvram_set("aimesh_setchannel_bw_1","2");
	} else if(CHCONF_BW_IS80(chconf)) {
		nvram_set("aimesh_setchannel_bw_1","3");
	} else {
		return (0);
	}
	while(nvram_get_int("wave_action")!=WAVE_ACTION_IDLE){
		_dprintf("wave_action != IDLE, waint. [%s]\n",__FUNCTION__);
		sleep(1);
	}

	nvram_set("aimesh_setchannel_channel_1",channel_str);
	trigger_wave_monitor(__func__, __LINE__,
		WAVE_ACTION_SET_CHANNEL_5G);

	return (0);
}

void wl_set_macfilter_list()
{
	//_dprintf("%s %d\n",__FUNCTION__,__LINE__);	
	update_macfilter_relist();

	if (wl_macfilter_is_allow_mode() && pids("roamast")) {
		//DBG_INFO("restart roamast");
		notify_rc("restart_roamast");
	}
}

void wl_set_macfilter_mode(int allow)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	int unit = 0;    //obd use only 2G

	while(nvram_get_int("wave_ready") == 0)
	{
		//_dprintf("rc_mac_allow_list_add wait\n");
		sleep(1);
	}

#ifdef RTCONFIG_AMAS
	if (nvram_get_int("re_mode") == 1)
		snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
	else
#endif
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	if (nvram_match(strcat_r(prefix, "macmode", tmp), "allow")) {

		while(nvram_get_int("wave_action")!=WAVE_ACTION_IDLE){
			_dprintf("wave_action != IDLE, waint. [wl_set_macfilter_mode]\n");
			sleep(1);
		}
		if( allow )
		{
			trigger_wave_monitor(__func__, __LINE__,
				WAVE_ACTION_OPENACL_FOR_OBD);
			sleep(1);
		} else {
			trigger_wave_monitor(__func__, __LINE__,
				WAVE_ACTION_RECOVERACL_FOR_OBD);
			sleep(1);
		}
	}

}

void wl_chanspec_changed_action(AVBL_CHANSPEC_T *avblChanspec)
{
	//TODO
}

char *get_ssid(char *ifname, char *ssid_buf, int buf_len)
{
	static char ssid[33] = "";
	char buf[8192] = "";
	FILE *fp;
	int len;
	char *pt1, *pt2, *pt3;

	if (!ifname || *ifname == '\0') {
		_dprintf("got invalid ifname %p", __func__, ifname);
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

	if(!strncmp("ff/any",ssid_buf,6))
		memset(ssid_buf,0,buf_len);

	return ssid_buf;
}

char *get_pap_ssid(int unit, char *ssid_buf, int buf_len)
{
	return get_ssid(get_staifname(unit), ssid_buf, buf_len);
}

char *get_ap_ssid(int unit, char *ssid_buf, int buf_len)
{
	return get_ssid(get_wififname(unit), ssid_buf, buf_len);
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