#include <obd.h>

#if defined(RTCONFIG_AMAS)

int obd_init()
{
	return 0;
}

void obd_final(int clean_vsie)
{

}

void obd_start_active_scan()
{

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
	nvram_commit();
}

struct scanned_bss *obd_get_bss_scan_result()
{
	
}

void obd_start_wps_enrollee()
{
	
}

void obd_add_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
	
}

void obd_del_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{

}

void obd_led_blink()
{

}

void obd_led_off()
{
	
}
#endif //#if defined(RTCONFIG_AMAS)
