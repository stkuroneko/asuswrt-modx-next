#include <amas_ssd.h>
#include <ap_priv.h>

#include <qca.h>

#if defined(RTCONFIG_AMAS)
int stop_scan = 0;
#define max_count 10
int wl_parse_ssid_list(ssid_list_t *ssid_list, wlc_ssid_t* ssid, int idx, int max)
{
        char str[50];
        int i = 0;
        for (i = 0; i < ssid_list->ssid_count; i++) {
                memset(str, 0, sizeof(str));
                snprintf(str, sizeof(str), "%s", ssid_list->ssid[i]);
                if (strlen(str) == 0)
                        ssid[idx].SSID_len = 0;

                if (idx < max) {
                        strcpy((char*)ssid[idx].SSID, str);
                        ssid[idx].SSID_len = strlen(str);
                }
                idx++;
        }
        return idx;
}

struct site_survey_result *do_site_survey(int unit, ssid_list_t *ssid_list)
{
	char line[2048];
	char ctrl_sk[32];
	char *staifname;
	FILE *fp;
	int ret;
	char cmp[100];
	struct site_survey_result *bss_list = NULL;
        int nssid = 0, i = 0, nc=0;
        wlc_ssid_t ssids[max_count]; //for multi-ssid
	memset(ssids, 0, max_count * sizeof(wlc_ssid_t));

        /* for ssid list */
        nssid = wl_parse_ssid_list(ssid_list, ssids, nssid, max_count);
	/* 
	for (i = 0; i < nssid; i++) 
		_dprintf("ssid[%d]=%s,len=%d\n",i,ssids[i].SSID,ssids[i].SSID_len);
	*/

	if(stop_scan)
	{
	     	SSD_DBG("stop scan for unit (%d)\n", unit);
                return NULL;
	}			

	set_wpa_cli_cmd(unit, "scan", 1); /* scan before get scan_results */

	get_wpa_ctrl_sk(unit, ctrl_sk, sizeof(ctrl_sk));
	staifname = get_staifname(unit);
	snprintf(line, sizeof(line), "/usr/bin/wpa_cli -p %s -i %s scan_results", ctrl_sk, staifname);
	if ((fp = popen(line, "r")) != NULL) {
		struct site_survey_result *bss;
		char *mac, *freq, *signal, *proto, *ssid, *aimesh;
		char *p;
#if 1		
		char *bw,*pt1;
		char chbw[10];
		int bw_info=1,band=0;
#endif		
		int RSSI;
		struct ether_addr *BSSID;
		int vsie_len,vsie_info=1;
		unsigned char vsie[512];
		int channf = get_channf(unit, NULL);
		
		freq = NULL;
		while(fgets(line, sizeof(line)-1, fp) != NULL) {
			vsie_info=1;
			strip_new_line(line);
			p = line;
			if((mac = strsep(&p, "\t")) == NULL || *mac == '\0' || (BSSID = ether_aton(mac)) == NULL ) {
				/*
				if(freq != NULL)
					_dprintf("# INVALID MAC #\n");
				*/	
				continue;
			}
			if((freq = strsep(&p, "\t")) == NULL) {
				//_dprintf("# NO FREQ #\n");
				continue;
			}
			if((signal = strsep(&p, "\t")) == NULL || (!isdigit(*signal) && *signal != '-') || (RSSI = atoi(signal)) < -128) {
				//_dprintf("# INVALID SIGNAL #\n");
				continue;
			}
			if((proto = strsep(&p, "\t")) == NULL) {
				//_dprintf("# NO PROTO #\n");
				continue;
			}
			if((ssid = strsep(&p, "\t")) == NULL) {
				//_dprintf("# NO SSID #\n");
				continue;
			}

//for test
			nc=0;
			for (i = 0; i < nssid; i++) 
			{
				memset(cmp,0,sizeof(cmp));
				strncpy(cmp,ssids[i].SSID,ssids[i].SSID_len);
                		if(strcmp(ssid,cmp)!=0)
				{	
					nc++;
					//_dprintf("# NOT TARGET SSID #\n");
				}
			}

			if(nc==nssid)
				continue;

			if((aimesh = strsep(&p, "\t")) == NULL || *aimesh == '\0' || strncmp(aimesh, "#f832e4", 7) != 0) {
				//_dprintf("# NO AIMESH #\n");
				vsie_info=0;
				//continue;
			}
			
			if(vsie_info)
			{	
				aimesh += 7;
				vsie_len = strlen(aimesh);
				vsie_len >>= 1;
	
				extern int str2hex(const char *str, unsigned char *data, size_t size);
				ret = str2hex(aimesh, vsie, vsie_len);
				if(ret != vsie_len) {
					SSD_DBG("str2hex fail ret(%d) vsie_len(%d) aimesh(%s)\n", ret, vsie_len, aimesh);
					continue;
				}
			}	
#if 1			
                       if((bw = strsep(&p, "\t")) == NULL) {
                               //_dprintf("# NO BW #\n");
			       bw_info=0;
			      // continue;
                       }
#endif		       

			if (RSSI > 0) {
				RSSI += channf;
				if (RSSI >= 0)
					RSSI = -1;
			}

			if((bss = malloc(sizeof(struct site_survey_result))) == NULL)
				continue;
			memset(bss, 0, sizeof(struct site_survey_result));
			//channel
			bss->channel = (uint8)ieee80211_mhz2ieee((u_int)atoi(freq));
			//bssid
			memcpy(&bss->bssid, BSSID, sizeof(struct ether_addr));
			//rssi
			bss->rssi = (unsigned char) RSSI;
			//ssid
			strncpy((char *)bss->ssid, ssid, strlen(ssid));
                        bss->ssid[strlen(ssid)] = '\0';
                        bss->ssid_len = strlen(ssid);			
			//vsie
			if(vsie_info)
                        {
                                bss->vsie_len = vsie_len;
                                memcpy(bss->vsie, vsie, bss->vsie_len);
                        }
                        else
                                bss->vsie_len = 0;
#if 1			
			//bw
			if(bw_info)
			{	
			 	pt1 = strstr(bw, "MHZ");
                                if(pt1)
                                {
					memset(chbw,0,sizeof(chbw));
					strncpy(chbw,bw,pt1-bw);
					bss->bw=atoi(chbw);
                                }
			}	
			else
			{
				band=swap_5g_band(unit);
				if(band==1)	
					bss->bw=80; //5G default
				else if(band==2)	
					bss->bw=160; //6G default
				else
					bss->bw=20;
			}	
#endif			
			bss->next = bss_list;
                        bss_list = bss;
			/*
			_dprintf("bss ssid=%s\n",bss->ssid);
			_dprintf("bss ssid_len=%d\n",bss->ssid_len);
			_dprintf("bss bssid =%s\n",mac);
			_dprintf("bss rssi=%d,%d\n",bss->rssi,RSSI);
			if(vsie_info)
			{
				_dprintf("bss vsie=%x\n",bss->vsie);
				_dprintf("bss vsie len=%d\n",bss->vsie_len);
			}			
			if(bw_info)
				_dprintf("bss bw=%d\n",bss->bw);

			*/

		}
		pclose(fp);
	}
	return bss_list;
  
}

void stop_site_survey()
{
	//_dprintf("stop site survey\n");
	stop_scan=1;
}

#if defined(RTCONFIG_AMAS_WDS)
/* all sta */
void set_stamode(int wds)
{
	char word[64], *next;
	char line[128], *get_str = NULL;
	int band = 0;

	foreach (word, nvram_safe_get("sta_ifnames"), next) {
		get_str = qca_iwpriv_one_line(word, "get_extap", line, sizeof(line));
		doSystem(IWPRIV " %s wds %d", word, wds);
		doSystem(IWPRIV " %s extap %d", word, !wds);
		/* RE mode stax/athx should be independent, athnewind=0 when extap=0 */
		if (wds)
			doSystem(IWPRIV " %s athnewind 1", word);

		if(get_str && get_str[0] == '0' && wds==0) {
			// Connecting to BRCM with (wds=1 & extap=0), the traffic may not past.
			// Have to change to (wds=0 & extap=1) and force reassociate to avoid network block.
			set_wpa_cli_cmd(swap_5g_band(band), "reassociate", 0);
		}
		band++;
	}
}

/* all ap */
void set_apmode(int wds)
{
	char word[64], *next;
#ifdef RTCONFIG_AMAS_WGN
	char wl_vifs[256];

	sprintf(wl_vifs, "%s %s %s", nvram_safe_get("wl0_vifs"), nvram_safe_get("wl1_vifs"), nvram_safe_get("wl2_vifs"));
	if (strlen(wl_vifs)) {
		foreach (word, wl_vifs, next)
			doSystem(IWPRIV " %s wds %d", word, wds);
	}
#endif
	foreach (word, nvram_safe_get("lan_ifnames"), next) {
		if (strstr(word, "ath"))
			doSystem(IWPRIV " %s wds %d", word, wds);
	}
}
#endif //#if defined(RTCONFIG_AMAS_WDS)
#endif //#if defined(RTCONFIG_AMAS)
