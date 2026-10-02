#include <obd.h>

#if defined(RTCONFIG_AMAS)

int obd_init()
{
	obd_clear_probe_req_vsie(0);
#ifdef RTCONFIG_RTL8198D
    if(!isFileExist("/var/wscd-wlan2-vxd.fifo")){
        rtk_start_wsc();
    }
#else
	if(!isFileExist("/var/run/wscd-wl0-vxd.pid"))
		start_vxd_wsc("wl0-vxd");
#endif
	return 0;
}

void obd_final(int clean_vsie)
{
	if (clean_vsie)
		obd_clear_probe_req_vsie(0);
}

void obd_save_para()
{
	nvram_set("sw_mode", "3");
	nvram_set("wlc_psta", "2");
	nvram_set("wlc_dpsta", "1");
	nvram_set("lan_proto", "dhcp");
	nvram_set("lan_dnsenable_x", "1");
#ifdef RTCONFIG_DHCP_OVERRIDE
	nvram_set("dnsqmode", "1");
#endif
	nvram_set("x_Setting", "1");
    nvram_set("w_Setting", "1");
	nvram_set("re_mode", "1");
	nvram_unset("cfg_group");
	nvram_commit();
}

extern int getWlSiteSurveyRequest(char *interface, int *pStatus);
int start_scan(char* ifname) 
{
	int status=0;
	if(getWlSiteSurveyRequest(ifname,&status)<0)
	{
		OBD_DBG("%s getWlSiteSurveyRequest fail!\n",ifname);
		return -1;
	}
	if(status!=0)
		return -1;
	return 1;
}

void obd_start_active_scan()
{
	int ret = 0, count = 0;
	char *ifname = NULL;
	ifname = get_wififname(0); 
	OBD_DBG("Send probe-req\n\n");
	while ((ret = start_scan(ifname)) < 0 && count++ < 15){
		OBD_DBG("[rc] set scan command failed, retry %d\n", count);
		sleep(1);
	}
}


struct scanned_bss *obd_get_bss_scan_result()
{
OBD_DBG("%s(%d)", __FUNCTION__, __LINE__);
	char *ifname = NULL;
	ifname = get_wififname(0); 
	int ret = 0, count = 0;
	struct scanned_bss *bss_list = NULL, *current_bss = NULL;

	while ((ret = start_scan(ifname)) < 0 && count++ < 15){
		OBD_DBG("[rc] set scan command failed, retry %d\n", count);
		sleep(1);
	}
	if(count == 15)
		return NULL;

	SS_STATUS_T scan_status={0};
	int i=0,wait=0;
	while(wait++<15)
	{
		scan_status.number = 0;
		if(getWlSiteSurveyResult(ifname,&scan_status)<0) {
			OBD_DBG("%s getWlSiteSurveyRequest fail!\n",ifname);
			return NULL;
		}
		if(scan_status.number==0xff)
		{
			sleep(1);
			continue;
		}
		break;
	}
	
	if(scan_status.number==0xff) {
		OBD_DBG("%s getWlSiteSurveyRequest fail!\n",ifname);
		return NULL;
	}

	for (i = 0; i < scan_status.number; i++) {
		//donnot record when the is len is 0
		if(scan_status.bssdb[i].asus_ie_len <= OUI_LEN)
			continue;

		struct scanned_bss *bss;

		bss = malloc(sizeof(struct scanned_bss));
		memset(bss, 0, sizeof(struct scanned_bss));

		bss->vsie_len= scan_status.bssdb[i].asus_ie_len - OUI_LEN;
		bss->channel = scan_status.bssdb[i].channel;
		bss->RSSI	 = scan_status.bssdb[i].rssi;

		memcpy(bss->vsie, scan_status.bssdb[i].asus_ie + OUI_LEN,
				 scan_status.bssdb[i].asus_ie_len - OUI_LEN);
		memcpy(&bss->BSSID, scan_status.bssdb[i].bssid, sizeof(bss->BSSID));
		OBD_DBG("bss->BSSID %d\n",sizeof(bss->BSSID));

		if (current_bss)
			current_bss->next = bss;

		current_bss = bss;

		if (bss_list == NULL)
			bss_list = bss;
	}

	return bss_list;
}

void obd_start_wps_enrollee()
{
	// use nvram wps_amas_enrollee to indicate wps as enrollee mode
	nvram_set_int("wps_amas_enrollee", 1);
	notify_rc_and_wait("start_wps_method");
}

void obd_set_probe_req_vsie(DOT11_SET_USERIE* Set_USERIE,int unit, \
							int len, unsigned char *ie_data)
{
	Set_USERIE->EventId = DOT11_EVENT_USER_SETIE;

	memset(Set_USERIE->USERIE,0 ,sizeof(Set_USERIE->USERIE));
	Set_USERIE->USERIE[0] = 221;
	Set_USERIE->USERIE[1] = len;
	Set_USERIE->USERIE[2] = OUI_ASUS[0];
	Set_USERIE->USERIE[3] = OUI_ASUS[1];
	Set_USERIE->USERIE[4] = OUI_ASUS[2];

	if((len+2) > sizeof(Set_USERIE->USERIE))
		return;

	memcpy(Set_USERIE->USERIE+5, ie_data, len-3);

	Set_USERIE->USERIELen = len + 2;

	update_vsie(get_wififname(unit), (void *)Set_USERIE);
}

void obd_clear_probe_req_vsie(int unit)
{
	DOT11_SET_USERIE Set_USERIE;

	Set_USERIE.Flag = SET_IE_FLAG_CLEAR;
	Set_USERIE.EventId = DOT11_EVENT_USER_SETIE;

	update_vsie(get_wififname(unit), (void *)&Set_USERIE);
}

void obd_add_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
	DOT11_SET_USERIE Set_USERIE;

	Set_USERIE.Flag = SET_IE_FLAG_INSERT;
	obd_set_probe_req_vsie(&Set_USERIE, unit, len, ie_data);
	
}

void obd_del_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
	DOT11_SET_USERIE Set_USERIE;

	Set_USERIE.Flag = SET_IE_FLAG_DELETE_WITH_OUI;
	obd_set_probe_req_vsie(&Set_USERIE, unit, len, ie_data);
}

void obd_led_blink()
{
	nvram_set_int("led_status", LED_WPS_START);
}

void obd_led_off()
{
	nvram_set_int("led_status", LED_BOOTED_APMODE);
}

#ifdef RTCONFIG_PRELINK
void obd_save_prelink_profile()
{
	
}

void obd_switch_re(int wifi)
{
	kill(1, SIGTERM);
}
#endif
#endif //#if defined(RTCONFIG_AMAS)
