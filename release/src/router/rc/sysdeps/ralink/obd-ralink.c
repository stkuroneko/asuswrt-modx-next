#include <obd.h>
#include <shared.h>

#if defined(RTCONFIG_AMAS)
int obd_init()
{
    char *ifname = get_staifname(0);
    ifconfig(ifname, IFUP, NULL, NULL);  // Up apcli0 for WPS
    nvram_set("wl0_vifs", ifname);
    return 0;
}

void obd_final(int clean_vsie)
{
    char *ifname = get_staifname(0);
    nvram_unset("wps_enrollee");
    nvram_unset("wps_e_success");
    if (is_if_up(ifname)) ifconfig(ifname, 0, NULL, NULL);  // Down apcli0
    nvram_unset("wl0_vifs");
}

void obd_start_active_scan()
{
    startScan(0);
}

void obd_save_para()
{
	nvram_set("sw_mode", "3");
	nvram_set("wlc_psta", "2");
	nvram_set("wlc_dpsta", "1");
	nvram_set("lan_proto", "dhcp");
	nvram_set("lan_dnsenable_x", "1");
	nvram_set("x_Setting", "1");
	nvram_set("w_Setting", "1");
	nvram_set("re_mode", "1");
	nvram_unset("cfg_group");
	nvram_unset("wps_enrollee");
	nvram_unset("wps_e_success");
	nvram_commit();
}

struct scanned_bss *obd_get_bss_scan_result()
{
    int i = 0, length = 0, cnt = 0;
    struct _SITESURVEY_VSIE *result = NULL;
    struct scanned_bss *bss_list = NULL, *current_bss = NULL;

    startScan(0);
    cnt = getSiteSurveyVSIEcount(0);
    length = ((cnt/6)+1)*1024; // 1024 can store 6*170(size of _SITESURVEY_VSIE)
    result = (struct _SITESURVEY_VSIE *)calloc(length, sizeof(char));

    if (result == NULL)
    {
        OBD_ERROR("result calloc failed\n");
        return NULL;
    }

    if (getSiteSurveyVSIE(0, result, length) == 0) {  // Error
        free(result);
        return NULL;
    }

    while ((result + i)->Channel != 0) {
        struct scanned_bss *bss;

	if (((i + 1) * sizeof(*result)) > length) {
		dbg("%s: result[%d]->Channel %hhu out of range, length %d/%d.)\n",
			__func__, i, (result + i)->Channel, (i + 1) * sizeof(*result), length);
		break;
	}

        bss = malloc(sizeof(struct scanned_bss));
        memset(bss, 0, sizeof(struct scanned_bss));

        bss->vsie_len = (result + i)->vendor_ie_len - OUI_LEN;
        bss->channel = (result + i)->Channel;
        bss->RSSI = (result + i)->Rssi;
        memcpy(bss->vsie, (result + i)->vendor_ie + OUI_LEN,
               (result + i)->vendor_ie_len - OUI_LEN);
        memcpy(&bss->BSSID, (result + i)->Bssid, sizeof(bss->BSSID));
        OBD_DBG("bss->BSSID %d\n", sizeof(bss->BSSID));

        if (current_bss) current_bss->next = bss;

        current_bss = bss;

        if (bss_list == NULL) bss_list = bss;
        i++;
    }

    free(result);
    return bss_list;
}

void obd_start_wps_enrollee()
{
    nvram_set_int("wps_enrollee", 1);
	start_wps_method();
}

void obd_add_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
    char vsie_str[1024] = {};

    hex2str(ie_data, vsie_str, len);
    OBD_DBG("vsie_str: %s\n", vsie_str);
    add_probe_req_vsie(vsie_str);
}

void obd_del_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
    char vsie_str[1024] = {};

    hex2str(ie_data, vsie_str, len);
    OBD_DBG("vsie_str: %s\n", vsie_str);
    del_probe_req_vsie(vsie_str);
}

void obd_led_blink()
{
    OBD_DBG("TBD\n");
}

void obd_led_off()
{
    OBD_DBG("TBD\n");
}

#ifdef RTCONFIG_PRELINK
void obd_save_prelink_profile()
{
	int i = 0;
	char tmp[128], tmp2[128], prefix[] = "wlcXXXXXXXXX_", prefix2[] = "wlXXXXXXXXX_", word[256], *next, ifnames[128];

	int unit_total = num_of_wl_if();
#ifdef RTCONFIG_MSSID_PRELINK
	snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit_total-1, nvram_get_int("plk_cap_subunit")); //last band and last mssid
#else
	snprintf(prefix, sizeof(prefix), "wl%d_", unit_total-1); //last band
#endif

	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		//wlcx
		snprintf(prefix2, sizeof(prefix2), "wlc%d_", i);
		nvram_set(strcat_r(prefix2, "ssid", tmp), nvram_safe_get(strcat_r(prefix, "ssid", tmp2)));
		nvram_set(strcat_r(prefix2, "auth_mode", tmp), nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp2)));
		nvram_set(strcat_r(prefix2, "crypto", tmp), nvram_safe_get(strcat_r(prefix, "crypto", tmp2)));
		nvram_set(strcat_r(prefix2, "wpa_psk", tmp), nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp2)));

		if (i < unit_total-1) {
			//wlx
			snprintf(prefix2, sizeof(prefix2), "wl%d_", i);
			nvram_set(strcat_r(prefix2, "ssid", tmp), nvram_safe_get(strcat_r(prefix, "ssid", tmp2)));
			nvram_set(strcat_r(prefix2, "auth_mode_x", tmp), nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp2)));
			nvram_set(strcat_r(prefix2, "crypto", tmp), nvram_safe_get(strcat_r(prefix, "crypto", tmp2)));
			nvram_set(strcat_r(prefix2, "wpa_psk", tmp), nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp2)));
		}
		++i;
	}

	nvram_set("wlc_band", "1");
	nvram_set("prelink", "1");
	nvram_set("obd_Setting", "1");
}

void obd_switch_re(int wifi)
{
	kill(1, SIGTERM);
}
#endif
#endif //#if defined(RTCONFIG_AMAS)
