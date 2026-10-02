#include <amas_ssd.h>

#if defined(RTCONFIG_AMAS)
extern int startScan(int band);
extern int getSiteSurveyVSIEcount(int band);
extern int getSiteSurveyVSIE(int band, struct _SITESURVEY_VSIE *result, int length);
int stop_scan = 0;

struct site_survey_result *do_site_survey(int unit, ssid_list_t *ssid_list)
{
  //TODO
  //1. site survey by band
  //2. get the result of site surveiy and rturn.
	char vsie_str[MAX_VSIE_LEN];
	char bssid[18];
	struct site_survey_result *bss_list = NULL, *current_bss = NULL, *bss = NULL;
	struct _SITESURVEY_VSIE *vsie_list = NULL;
	int i = 0, j = 0, found = 0, length = 0, cnt = 0;

	startScan(unit);
	cnt = getSiteSurveyVSIEcount(unit);
	length = ((cnt/6)+1)*1024; // 1024 can store 6*170(size of _SITESURVEY_VSIE)
	vsie_list = (struct _SITESURVEY_VSIE *)calloc(length, sizeof(char));
	if (vsie_list == NULL)
	{
		SSD_ERROR("vsie_list calloc failed\n");
		return NULL;
	}

	if (getSiteSurveyVSIE(unit, vsie_list, length) == 0) {
		SSD_ERROR("getSiteSurveyVSIE failed\n");
        free(vsie_list);
		return NULL;
	}

	while ((vsie_list + i)->Channel != 0) {
		if (((i + 1) * sizeof(*vsie_list)) > length) {
			dbg("%s: vsie_list[%d]->Channel %hhu out of range, length %d/%d.)\n",
				__func__, i, (vsie_list + i)->Channel, (i + 1) * sizeof(*vsie_list), length);
			break;
		}
		found = 0;
		if (ssid_list && ssid_list->ssid_count > 0) {
			for (j=0; j<ssid_list->ssid_count; j++) {
				if (stop_scan==1)
					break;
				if (strcmp((vsie_list+i)->Ssid, ssid_list->ssid[j]) == 0) {
					found = 1;
					break;
				}
			}
		}
		else {
			found = 1;
		}

		if (stop_scan==1)
			break;

		bss = (struct site_survey_result *)malloc(sizeof(struct site_survey_result));
		if (found && bss) {
			memset(bss, 0, sizeof(struct site_survey_result));

			// channel
			bss->channel = (vsie_list + i)->Channel;
			SSD_DBG("channel=%d\n", bss->channel);

			// bssid
			memcpy(&bss->bssid, &(vsie_list + i)->Bssid, sizeof(bss->bssid));
			ether_etoa((const unsigned char *)&bss->bssid, bssid);
			SSD_DBG("bssid=%s\n", bssid);

			// rssi
			bss->rssi = (vsie_list + i)->Rssi;
			SSD_DBG("rssi=%d\n", bss->rssi);

			// ssid
			strncpy((char *)bss->ssid, (char *)(vsie_list + i)->Ssid, strlen((vsie_list + i)->Ssid));
			SSD_DBG("ssid=%s\n", bss->ssid);

			// vsie_len
			bss->vsie_len = (vsie_list + i)->vendor_ie_len - OUI_LEN;

			// vsie
			memcpy(bss->vsie, (vsie_list + i)->vendor_ie + OUI_LEN, (vsie_list + i)->vendor_ie_len - OUI_LEN);
			memset(vsie_str, 0, sizeof(vsie_str));
			hex2str(&bss->vsie[0], vsie_str, bss->vsie_len);
			SSD_DBG("%s vsie_len=%d\n", vsie_str, bss->vsie_len);

			if (current_bss) current_bss->next = bss;
			current_bss = bss;
			if (bss_list == NULL) bss_list = bss;
		}

		i++;
	}

	free(vsie_list);

	return bss_list;
}


void stop_site_survey()
{
	//TODO - stop site survey
	stop_scan=1;
}

#if defined(RTCONFIG_AMAS_WDS)
static int wds_state[WL_NR_BANDS] = { 0 };
/* all sta */
void set_stamode(int wds)
{
	char word[64], *next;
	int band = 0;

	foreach (word, nvram_safe_get("sta_ifnames"), next) {
		doSystem("iwpriv %s set force4=%d", word, wds);

		if (wds_state[band] != wds && wds == 0) {
			/* force apcliX to reassociate after switching force4 from 1 to 0 */
			doSystem("iwpriv %s set ApCliEnable=0", word);
			doSystem("iwpriv %s set ApCliEnable=1", word);
		}
		wds_state[band] = wds;

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
			doSystem("iwpriv %s set force4=%d", word, wds);
	}
#endif
	foreach (word, nvram_safe_get("lan_ifnames"), next) {
		if (strstr(word, "ra"))
			doSystem("iwpriv %s set force4=%d", word, wds);
	}
}
#endif //#if defined(RTCONFIG_AMAS_WDS)
#endif //#if defined(RTCONFIG_AMAS)
