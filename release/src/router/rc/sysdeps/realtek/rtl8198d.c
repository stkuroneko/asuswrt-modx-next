#include <string.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <realtek_common.h>
#include <realtek.h>
#include <rtstate.h>
#include <shutils.h>
#include <shared.h>
#include <shutils.h>
#include <dirent.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rtconfig.h>
#include <wlioctl.h>



#define IWCONTROL_PID_FILE "/var/run/iwcontrol.pid"
#define NVRAM_GET(str, nvram_suffix)		str = nvram_safe_get(strcat_r(prefix, nvram_suffix, tmp))
#define NVRAM_GET_INT(val, nvram_suffix)	val = nvram_get_int(strcat_r(prefix, nvram_suffix, tmp))

int set_mac_to_nvram()
{
	unsigned char mac2g[6], mac5g[6];
	char macaddr2g[18], macaddr5g[18];
#if defined(RPAC92)
	unsigned char mac5g2[6];
	char macaddr5g2[18];
#endif

	memset(mac2g, 0, sizeof(mac2g));
	memset(macaddr2g, 0, sizeof(macaddr2g));
	memset(mac5g, 0, sizeof(mac5g));
	memset(macaddr5g, 0, sizeof(macaddr5g));
#if defined(RPAC92)
	memset(mac5g2, 0, sizeof(mac5g2));
	memset(macaddr5g2, 0, sizeof(macaddr5g2));
#endif

	if(get_mac_2g(mac2g) < 0) {
		_dprintf("mac2g is wrong\n");
		return -1;
	}
	if(get_mac_5g(mac5g) < 0) {
		_dprintf("mac5g is wrong\n");
		return -1;
	}
#if defined(RPAC92)
	if(get_mac_5g_2(mac5g2) < 0) {
		_dprintf("mac5g2 is wrong\n");
		return -1;
	}
#endif

	ether_etoa(mac2g, macaddr2g);
	ether_etoa(mac5g, macaddr5g);
	nvram_set("lan_hwaddr", macaddr2g);
	nvram_set("et0macaddr", macaddr2g);
	nvram_set("wl0_hwaddr", macaddr2g);
	nvram_set("wl1_hwaddr", macaddr5g);
	nvram_set("wan0_hwaddr", macaddr2g);
	nvram_set("et1macaddr", macaddr2g);
#if defined(RPAC92)
	ether_etoa(mac5g2, macaddr5g2);
	nvram_set("wl2_hwaddr", macaddr5g2);
#endif
	return 0;
}
/*
	For hw setting releated
*/
int wlconf_rtk(const char* wif)
{
	int unit = 0;
	char *next;
	char tmp[64], prefix[] = "wlXXXXXXXXXX_";
	char* macaddr;

	foreach (tmp, nvram_safe_get("wl_ifnames"), next) {
		if(strcmp(tmp, wif) == 0) {
			break;
		}
		unit++;
	}

	if(unit > MAX_NR_WL_IF) {
		return -1;
	}
	
	_dprintf("%s:%s hw setting configuration\n", __func__, wif);
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	macaddr =  nvram_safe_get(strcat_r(prefix, "hwaddr", tmp));
	if(strlen(macaddr) == 17) {
// configure mac addr of wireless interface
		doSystem("ifconfig %s hw ether %s",wif,macaddr);
		doSystem("ifconfig %s-vxd hw ether %.*s%1X",wif, 16, macaddr, atoi(macaddr+16)+1);
	}

	switch(unit) {
	case WL_2G_BAND:
		setup8197Wlan();
		setupWlanDPK_2G();
		break;
	case WL_5G_BAND:
	case WL_5G_2_BAND:
		setup8812Wlan(unit);
		break;
	default:
		break;
	}
	set_txpwr_lmt_index(unit);

	return 0;
}

// For ssid password etc.
void gen_base_config(char* prefix, char* ifname, int unit) {

	char tmp[128];
	char* str, *str2;
	int val = 0, val2 = 0, val3 = 0;
	str = nvram_safe_get(strcat_r(prefix, "ssid", tmp));
	if(strlen(str))
		iwpriv_set_mib_string(ifname, "ssid", str);
	else
		iwpriv_set_mib_string(ifname, "ssid", "ASUS00");

	str = nvram_safe_get(strcat_r(prefix, "crypto", tmp));
	if(strcmp(str, "aes")==0){
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 8);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 8);
	}else if(strcmp(str, "tkip")==0){
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 2);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 2);
	}else if(strcmp(str, "tkip+aes")==0 || strcmp(str, "aes+tkip")==0){
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 10);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 10);
	}else if(strcmp(str, "none") == 0 || str[0] == '\0'){
		iwpriv_set_mib_int(ifname, "encmode", 0);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 0);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 0);
	}

	char *auth_mode, *wep;
	if(strncmp(prefix, "wlc", 3) == 0) {
		auth_mode = "auth_mode";
		wep ="wep";
	} else {
		auth_mode = "auth_mode_x";
		wep = "wep_x";
	}

	str = nvram_safe_get(strcat_r(prefix, auth_mode, tmp));

	if(strcmp(str, "open")==0){
		iwpriv_set_mib_int(ifname, "authtype", 0);
		iwpriv_set_mib_int(ifname, "encmode", 0);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 0);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 0);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 0);

		str2 = nvram_safe_get(strcat_r(prefix, wep, tmp));
		if(str2 && str2[0]!='\0') {
			int value = atoi(str2);
			if(value==1){
				iwpriv_set_mib_int(ifname, "encmode", 1);
			}else if(value==2){
				iwpriv_set_mib_int(ifname, "encmode", 5);
			}
		}
	}else if(strcmp(str, "shared")==0){
		iwpriv_set_mib_int(ifname, "authtype", 1);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 0);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 0);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 0);
		str2 = nvram_safe_get(strcat_r(prefix, wep, tmp));
		if(str2 && str2[0]!='\0')
		{
			int value = atoi(str2);
			if(value==1)
				iwpriv_set_mib_int(ifname, "encmode", 1); //40
			else if(value==2)
				iwpriv_set_mib_int(ifname, "encmode", 5); //104
		}else{
			iwpriv_set_mib_int(ifname, "encmode", 5);
		}
	}else if(strcmp(str, "psk")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "psk_enable", 1);
		iwpriv_set_mib_int(ifname, "802_1x", 0);
	}else if(strcmp(str, "psk2")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "psk_enable", 2);
		iwpriv_set_mib_int(ifname, "802_1x", 0);
	}else if(strcmp(str, "pskpsk2")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "psk_enable", 3);
		iwpriv_set_mib_int(ifname, "802_1x", 0);
	}else if(strcmp(str, "wpa")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 1);
	}else if(strcmp(str, "wpa2")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 1);
	}else if(strcmp(str, "wpawpa2")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 2);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 1);
	}else if(strcmp(str, "radius")==0){
		iwpriv_set_mib_int(ifname, "authtype", 2);
		iwpriv_set_mib_int(ifname, "encmode", 1);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 1);
	} else{
		iwpriv_set_mib_int(ifname, "authtype", 0);
		iwpriv_set_mib_int(ifname, "encmode", 0);
		iwpriv_set_mib_int(ifname, "psk_enable", 0);
		iwpriv_set_mib_int(ifname, "802_1x", 0);
		iwpriv_set_mib_int(ifname, "wpa_cipher", 0);
		iwpriv_set_mib_int(ifname, "wpa2_cipher", 0);
	}

	if(strcmp(str, "psk2")==0 || strcmp(str, "pskpsk2")==0 || strcmp(str, "psk")==0){
		str2 = nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp));
		if(str2[0] != '\0')
			iwpriv_set_mib_string(ifname, "passphrase", str2);
		else
			iwpriv_set_mib_string(ifname, "passphrase", "11111111");
	}

	str = nvram_safe_get(strcat_r(prefix, "key", tmp));
	if(str[0] != '\0'){
		int value = atoi(str);
		iwpriv_set_mib_int(ifname, "wepdkeyid", value-1);
	}else{
		iwpriv_set_mib_int(ifname, "wepdkeyid", 0);
	}

	str = nvram_safe_get(strcat_r(prefix, auth_mode, tmp));
	str2 = nvram_safe_get(strcat_r(prefix, "wpa_gtk_rekey", tmp));
	if((strcmp(str, "psk2")==0 || strcmp(str, "pskpsk2")==0) &&
		(str2[0] != '\0'))
		iwpriv_set_mib_int(ifname, "gk_rekey", atoi(str2));
	else
		iwpriv_set_mib_int(ifname, "gk_rekey", 0);
	//Network Mode

	NVRAM_GET_INT(val, "nmode_x");
	switch(val){
	case 0://auto
	default:
		val2 = unit?76:11;
		val3 = 0;
		break;
	case 1:// n only
		val2 = unit?12:8;
		val3 = unit?4:3;
		break;
	case 2://legacy bg
		val2 = unit?4:3;
		val3 = 0;
		break;
	case 8://AC/N mixed,2G should not go here
		val2 = unit?76:11;
		val3 = unit?12:0;
		break;
	}
	iwpriv_set_mib_int(ifname, "band", val2);
	iwpriv_set_mib_int(ifname, "deny_legacy", val3);
}
/*
Some config of vxd interface need to sync with root ap, but nvram only deined root ap.
*/
void gen_shared_config(char* ifname, int unit)
{
	char* str, tmp[32];
	char prefix[] = "wlcxxxx_";
	int val = 0;

	if(unit == 1)
		iwpriv_set_mib_int(ifname, "band5GSelected", 3);
	else if(unit == 2)
		iwpriv_set_mib_int(ifname, "band5GSelected", 12);

	snprintf(prefix,sizeof(prefix), "wl%d_", unit); //use the setting of root AP
	str = nvram_safe_get(strcat_r(prefix,"country_code",tmp));
	val = get_regdomain_from_countrycode(str, unit);
	iwpriv_set_mib_int(ifname, "regdomain", val);
	switch(val) {
	case DOMAIN_ETSI:
	case DOMAIN_MKK:
	case DOMAIN_AU:
		iwpriv_set_mib_int(ifname, "disable_DFS", 0);
		break;
	default:
		iwpriv_set_mib_int(ifname, "disable_DFS", 1);
	}

	//BGProtection
	NVRAM_GET(str, "gmode_protection");
	if (!strcmp(str, "auto"))
		val = 0;
	else
		val = 1;
	iwpriv_set_mib_int(ifname, "disable_protection", val);

	//ShortGI
	NVRAM_GET_INT(val, "HT_GI");
	iwpriv_set_mib_int(ifname, "shortGI20M", val);
	iwpriv_set_mib_int(ifname, "shortGI40M", val);
	iwpriv_set_mib_int(ifname, "shortGI80M", val);

	//ampdu
	NVRAM_GET(str, "ampdu");
	if(strcmp(str, "off")==0)
		val = 0;
	else // for auto, on and default
		val = 1;
	iwpriv_set_mib_int(ifname, "ampdu", val);

	//amsdu
	NVRAM_GET(str, "amsdu");
	if(unit == 0){
		val = 0;
	}
	else{
		if(strcmp(str, "off")==0)
			val = 0;
		else // for auto, on and default
			val = 2;
	}
	iwpriv_set_mib_int(ifname, "amsdu", val);

}

void gen_opmode_config(char* prefix, char* ifname) {

	int opmode = 8;
	//str = nvram_safe_get(strcat_r(prefix, "mode_x", tmp));

	if(strstr(ifname, "vxd") || (!strncmp(prefix, "wlc", 3))) {
		opmode = 8; // client mode
	} else {
		opmode = 16; //ap mode
	}
	iwpriv_set_mib_int(ifname, "opmode", opmode);
}

static int radio_rtk_mediabridge(const char *wif, int band)
{
	char tmp[100], prefix[]="wlcXXXXX_";

	snprintf(prefix, sizeof(prefix), "wlc%d_ssid", band);

	if (wif == NULL) return -1;

	if(chk_wlc_ssid_by_unit(band)==0)
		iwpriv_set_mib_int(wif, "func_off", 1);
	else
		iwpriv_set_mib_int(wif, "func_off", 0);
	return 0;
}

void gen_root_config(char* prefix, char* ifname, int band) {
	char *str, tmp[64];
	char mac[13],*next;
	int val = 0, val2 = 0, val3 = 0;

	NVRAM_GET(str, "channel");
	if(str[0] != '\0')
		iwpriv_set_mib_string(ifname, "channel", str);
	else
		iwpriv_set_mib_int(ifname, "channel", 0);

	if(!band) {
		NVRAM_GET(str, "rateset");
		if(!strcmp(str, "all"))
		{
			val = 0xff0;
		} else if(!strcmp(str, "12")) {
			val = 0x3;
		} else {
			// for default and other
			val = 0xf;
		}
		iwpriv_set_mib_int(ifname, "basicrates", val);
	}

	//BeaconPeriod
	NVRAM_GET(str, "bcn");
	val = atoi(str);
	if (val > 1024 || val < 20){
		nvram_set(strcat_r(prefix, "bcn", tmp), "100");
		val = 100;
	}
	iwpriv_set_mib_int(ifname, "bcnint", val);

	//DTIM Period
	NVRAM_GET_INT(val, "dtim");
	if(val < 1 || val > 255) {
		val = 1;
	}
	iwpriv_set_mib_int(ifname, "dtimperiod", val);

	NVRAM_GET_INT(val, "radio");
	if (mediabridge_mode()){
		radio_rtk_mediabridge(ifname, band);
	}else
		iwpriv_set_mib_int(ifname, "func_off", val?0:1);

	//TxPreamble
	NVRAM_GET(str, "plcphdr");
	if (strcmp(str, "short") == 0)
		val = 1;
	else // for long and other
		val = 0;

	//RTSThreshold	Default=2347
	NVRAM_GET_INT(val, "rts");
	if(val < 0 || val > 2347)
		val = 2347;
	iwpriv_set_mib_int(ifname, "rtsthres", val);

	//FragThreshold  Default=2346
	NVRAM_GET(str, "frag");
	if(val < 0 || val > 2346)
		val = 2346;
	iwpriv_set_mib_int(ifname, "fragthres", val);

	NVRAM_GET(str, "wme");
	if(strcmp(str, "off")==0)
		val = 0;
	else// for on and default value
		val = 1;
	iwpriv_set_mib_int(ifname, "qos_enable", val);

	NVRAM_GET(str, "wme_apsd");
	if(strcmp(str, "off")==0)
		val = 0;
	else //for on and default value
		val = 1;
	iwpriv_set_mib_int(ifname, "apsd_enable", val);

	NVRAM_GET(str, "wme_no_ack");
	if(strcmp(str, "on")==0)
		val = 1;
	else // for off and default value
		val = 0;
	iwpriv_set_mib_int(ifname, "txnoack", val);

	NVRAM_GET_INT(val, "nmode_x");
	if(val == 1)
		iwpriv_set_mib_int(ifname, "qos_enable", 1); //N mode force enable QOS

	//PktAggregate
	NVRAM_GET(str, "PktAggregate");
	if(str[0] != '\0') {
		val = atoi(str);
		iwpriv_set_mib_int(ifname, "ampdu", val);
	}

	NVRAM_GET_INT(val, "bss_enabled");
	iwpriv_set_mib_int(ifname, "vap_enable", val);

	NVRAM_GET_INT(val, "closed");
	iwpriv_set_mib_int(ifname, "hiddenAP", val);

	NVRAM_GET_INT(val, "bw");
	switch(val) {
		case 0://20
			val2 = 0;
			break;
		case 1: //auto
			if(band)
				val2 = 2;
			else
				val2 = 1;
			break;
		case 2: //40
			val2 = 1;
		case 3: //80
			val2 = 2;
	}
	iwpriv_set_mib_int(ifname, "use40M", val2);

	if(val == 1)
		val2 = 1;
	else
		val2 = 0;
	iwpriv_set_mib_int(ifname, "coexist", val2);

	NVRAM_GET_INT(val2, "channel"); //0 auto
	NVRAM_GET(str, "nctrlsb");
	if(!band && val2 && (val == 2 || val == 1)) {
		if(val2 >= 1 && val2 <= 4) {
			val3 = 2;
		} else if( val2 >= 10 && val2 <= 14) {
			val3 = 1;
		} else {
			val3 = strcmp(str, "lower") ? 2 : 1;
		}
		iwpriv_set_mib_int(ifname, "2ndchoffset", val3);
	}

	NVRAM_GET_INT(val, "ap_isolate");
	iwpriv_set_mib_int(ifname, "block_relay", val);

	/*	ASUS UI Mrate definition
	 *	HTMIX 6.5/15	14
	 *	HTMIX 13/30	15
	 * 	HTMIX 19.5/45	16
	 *  	HTMIX 13/30	17
	 *   	HTMIX 26/60	18
	 *    	HTMIX 130/144	13
	 *     	OFDM 6		4
	 *     	OFDM 9		5
	 *      OFDM 12		7
	 *	OFDM 18		8
	 *	OFDM 24		9
	 *	OFDM 36		10
	 *	OFDM 48		11
	 *	OFDM 54		12
	 *	CCK 1		1
	 *	CCK 2		2
	 *	CCK 5.5		3
	 *	CCK 11		6
	 */

	NVRAM_GET_INT(val, "mrate_x");

	if( val > 0 && val < 12)
		val2 = 1 << (val-1);
	else if (val >= 14 && val <= 16)
		val2 = 1 << (val-2);
	else if (val == 17 || val ==18)
		val2 = 1 << (val+3);
	else if (val == 13)
		val2 = 1 << 27;
	else // default and 0
		val2 = 0;
	iwpriv_set_mib_int(ifname, "lowestMlcstRate", val2);

	// ACL
	NVRAM_GET(str, "macmode");
	if(strcmp(str, "accept")==0 || strcmp(str, "allow")==0)
		val = 1;
	else if(strcmp(str, "deny")==0)
		val = 2;
	else
		val = 0;
	iwpriv_set_mib_int(ifname, "aclmode", val);

	NVRAM_GET(str, "maclist_x");

	foreach_62(tmp, str, next) {
		memset(mac, 0, sizeof(mac));
		val2 = 0;
		for(val = 0; val < 16 && val2 < 12; val++) {
			if(tmp[val] != ':') {
				mac[val2] = tmp[val];
				val2++;
			}
		}
		mac[12] = '\0';
		iwpriv_set_mib_string(ifname, "acladdr", mac);
	}

	/* TxBF */
	NVRAM_GET_INT(val, "txbf");
	switch(val){
	case 1:
	case 2:
		val2 = 1;
		val3 = 1;
		break;
	default:
		val = 0;
		val2 = 0;
		val2 = 0;
		break;
	}
	iwpriv_set_mib_int(ifname, "txbf", val);
	iwpriv_set_mib_int(ifname, "txbfer", val);
	iwpriv_set_mib_int(ifname, "txbfee", val);


#if defined(RTCONFIG_MUMIMO_2G) || defined(RTCONFIG_MUMIMO_5G)
	/* MU-MIMO */
	NVRAM_GET_INT(val, "mumimo");
	if(val != 1)
		val = 0;
	iwpriv_set_mib_int(ifname, "txbf_mu", val);
#endif

	/* igmp snooping */
	NVRAM_GET_INT(val, "igs");
	iwpriv_set_mib_int(ifname, "mc2u_disable", val?0:1);

	/* WiFi proxy */
	NVRAM_GET_INT(val, "wifipxy");
	iwpriv_set_mib_int(ifname, "macclone_enable", (val==1)?1:0);

	if (band) {
		if (nvram_match("dfsdbgmode", "1")) {
			iwpriv_set_mib_int(ifname, "dfsdbgmode", 1);
			sleep(1);
		}
	}

	/*  realtek mesh*/
	iwpriv_set_mib_int(ifname, "mesh_enable", 0);

	/*set realtek default wlan mib value that nvram setting don't defined.
		sync from realtek.c
	*/
	iwpriv_set_mib_int(ifname, "shortretry", 0);
	iwpriv_set_mib_int(ifname, "expired_time", 30000);
	iwpriv_set_mib_int(ifname, "stbc", 1);
	iwpriv_set_mib_int(ifname, "ldpc", 1);
	iwpriv_set_mib_int(ifname, "tdls_prohibited", 0);
	iwpriv_set_mib_int(ifname, "tdls_cs_prohibited", 0);
	iwpriv_set_mib_int(ifname, "ack_timeout", 0);
	iwpriv_set_mib_int(ifname, "iapp_enable", 1);
	iwpriv_set_mib_int(ifname, "wifi_specific", 2);
	iwpriv_set_mib_int(ifname, "autoRate", 1);
	iwpriv_set_mib_int(ifname, "guest_access", 0);
	iwpriv_set_mib_int(ifname, "acct_enabled", 0);
	iwpriv_set_mib_int(ifname, "GBWCMode", 0);
	iwpriv_set_mib_int(ifname, "gbwcthrd_tx", 0);
	iwpriv_set_mib_int(ifname, "GBWCThrd_rx", 0);
	
}

void gen_rtk_config(char* wif) {
	int unit = 0, root_ap = 0;
	//int sw_mode = sw_mode();
	char word[128], *next;//, *str;
	char prefix[] = "wlXXXXXXXXXX_";

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		if(strncmp(word, wif, strlen(word)) == 0)
			break;
		unit++;
	}
	if(unit > 2) {
		_dprintf("%s is not wireless interface\n", wif);
		return;
	}
	//TODO:// AMAS related need to be update
#ifdef RTCONFIG_AMAS
	if (nvram_match("re_mode", "1")) {
		if(strstr(wif,"vxd")){
			root_ap = 0;
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		} else {
			root_ap = 1;
			snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
		}
	} else
#endif
	if(access_point_mode()) {
		root_ap = 1;
		/* vxd should not work in ap mode */
		if(strstr(wif,"vxd"))
			return;
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	} else if(repeater_mode()) {
		if(strstr(wif,"vxd")){
			root_ap = 0;
			snprintf(prefix, sizeof(prefix), "wlc%d_", unit);
		} else {
			root_ap = 1;
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		}
	} else if(mediabridge_mode()) {
		if(strstr(wif,"vxd"))
			return;
		snprintf(prefix, sizeof(prefix), "wlc%d_", unit);
		root_ap = 1;
	} else {
		_dprintf("cannot get operate mode\n");
		return;
	}

	gen_base_config(prefix, wif, unit);
	gen_shared_config(wif, unit);
	gen_opmode_config(prefix, wif);
	if(root_ap)
		gen_root_config(prefix, wif, unit);

}

struct connect_info {
	char *ifname;
	int enable;
	int status;
	unsigned int rssi;
	int bridge;
	int radio;
};

extern int get_wlc_status(char* ifname);
extern unsigned int get_conn_link_quality(int unit);
struct connect_info pap_connect_info[MAX_NR_WL_IF];
int pap_connect_init = 0;
#define WL_WAIT_TIME 24 //24*5=120
int wlcconnect_core(void) {

	char prefix[32], tmp[128];
	int i = 0;
	int band = nvram_get_int("wlc_band");
	//int ret  = WLC_STATE_CONNECTING;
	int select_band = -1;
	int backup_band = -1;
	static int connect_wait_count = WL_WAIT_TIME;
	static int switch_wait_count = 0;

	if(!((repeater_mode() && (nvram_get_int("wlc_express") == 0))
		 || mediabridge_mode()))
		return WLC_STATE_INITIALIZING;


	if(pap_connect_init == 0) {
		for(i = 0; i < MAX_NR_WL_IF; i++) {
			snprintf(prefix, sizeof(prefix), "wlc%d_", i);
			if(strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp))) > 0)
				pap_connect_info[i].enable = 1;
			else
				pap_connect_info[i].enable = 0;
		}
		pap_connect_init = 1;
	}

	/* update basic connection info
	 *
	 * Link quality on realtek is 0~100
	*/
	for(i = 0; i < MAX_NR_WL_IF; i++) {
		if(repeater_mode())
			pap_connect_info[i].ifname = get_staifname(i);
		else if(mediabridge_mode())
			pap_connect_info[i].ifname = get_wififname(i);

		snprintf(prefix, sizeof(prefix), "wlc%d_", i);

		if(pap_connect_info[i].enable == 0) {
			nvram_set_int(strcat_r(prefix, "state", tmp), 0);
			continue;
		}

		pap_connect_info[i].status = get_wlc_status(pap_connect_info[i].ifname);
		nvram_set_int(strcat_r(prefix, "state", tmp), pap_connect_info[i].status);

		if(pap_connect_info[i].status == WLC_STATE_CONNECTED) {
			pap_connect_info[i].rssi = get_conn_link_quality(i);
			//_dprintf("%s: the rssi of ifname %s is %d\n", __func__, pap_connect_info[i].ifname, pap_connect_info[i].rssi);
		}
	}

	/*Link status changed*/
	do {
		SKIP_ABSENT_BAND(band);
		if(pap_connect_info[band].status != WLC_STATE_CONNECTED) {

			//if(retry_count < 2) {
			//	retry_count ++;
			//	_dprintf("%s: PAP disconnected, status %d\n", __func__, pap_connect_info[band].status);
			//	return pap_connect_info[band].status;
			//}
			_dprintf("%s: PAP disconnected, enable all sta interface...\n", __func__);
			for(i = 0; i < MAX_NR_WL_IF; i++) {
				if(pap_connect_info[i].enable) {
					_dprintf("%s: Ready to start wlcconnect %s\n", __func__, pap_connect_info[i].ifname);
					start_wlc_connect(i);
				}
			}
			connect_wait_count = WL_WAIT_TIME;
		}
	} while(0);

	/*
	 * Select the best one interface for bridge
	 */
	for(i = MAX_NR_WL_IF-1; i >= 0; i--) {
		//_dprintf("%s: now checking band %d\n", __func__, i);
		if(pap_connect_info[i].enable == 0)
			continue;

		if(pap_connect_info[i].status != WLC_STATE_CONNECTED)
			continue;

		if(pap_connect_info[i].rssi > 15) {
			/* IF signal of 5G H is OK, then check 5G L */
			if(i == WL_5G_2_BAND) {
				select_band = i;
				continue;
			}
			/* if signal of 5G L is better than 5G, use 5G Low else break;
			 * if 5G H is not best band, but 5G L is best, use 5G L
			 */
			if(i == WL_5G_BAND) {
				if(select_band == WL_5G_2_BAND) {
					if((pap_connect_info[i].rssi - 5) > pap_connect_info[select_band].rssi)
						select_band = i;
				} else {
					select_band = i;
				}
				//_dprintf("%s: The best select band is %d\n", __func__,select_band);
				break;
			}
			/* When signal of 5G is bad or no signal of 5GL, come here to check 2G*/
			if((i == WL_2G_BAND) && (select_band <= WL_2G_BAND)) {
				select_band = i;
				//_dprintf("%s: The best select band is %d\n", __func__,select_band);
				break;
			}
		}

		if(select_band > -1)
			continue;

		if(i == WL_5G_2_BAND) {
			backup_band = i;
			continue;
		}
		/* if signal of 5G L is better than 5G, use 5G Low else break;
		 * if 5G H is not best band, but 5G L is best, use 5G L
		 */
		if(i == WL_5G_BAND) {
			if(backup_band == WL_5G_2_BAND) {
				if(pap_connect_info[i].rssi > pap_connect_info[backup_band].rssi)
					backup_band = i;
			} else {
				backup_band = i;
			}
			//_dprintf("%s: The less select band is %d\n", __func__,backup_band);
			break;
		}
		/* When signal of 5G is bad, come here to check 2G*/
		if(i == WL_2G_BAND) {
			backup_band = i;
			//_dprintf("%s: The less select band is %d\n", __func__,backup_band);
			break;
		}
	}

	if(select_band < 0 && backup_band > -1)
		select_band = backup_band;

	if(select_band < 0) {
		for(i = MAX_NR_WL_IF-1; i >= 0; i--) {
			if(pap_connect_info[i].enable)
				return pap_connect_info[i].status;
		}
	}

	if(pap_connect_info[select_band].bridge) {
		//_dprintf("%s: select band already in bridge %d\n", __func__,select_band);
		switch_wait_count = 0;
		goto connection_check;
	}

	if(mediabridge_mode()) {
		switch_wait_count++;

		do {
			SKIP_ABSENT_BAND(band);
			if(switch_wait_count < 6) { //wait 5*5s when switch to another band
				select_band = band;
				goto end;
			}
		} while(0);
	}

	nvram_set_int("wlc_band", select_band);
	nvram_set_int("wlc_triBand", select_band);
	//_dprintf("%s: Final select band is %d\n", __func__,select_band);

//	_dprintf("%s: clear all sta interface from bridge\n",__func__);
	for(i = 0; i < MAX_NR_WL_IF; i++) {
		//remove all vxd interface from bridge
		pap_connect_info[i].bridge = 0;
		doSystem("brctl delif %s %s", nvram_safe_get("lan_ifname"), pap_connect_info[i].ifname);
	}

	_dprintf("%s: addif %s into bridge\n",__func__, pap_connect_info[select_band].ifname);
	doSystem("brctl addif %s %s", nvram_safe_get("lan_ifname"), pap_connect_info[select_band].ifname);
	pap_connect_info[select_band].bridge = 1;
	switch_wait_count = 0;

	if(mediabridge_mode())
		goto end;
	//Disable AP of 5G select band
	if(select_band != WL_2G_BAND) {
		snprintf(prefix, sizeof(prefix), "wl%d_", select_band);
		pap_connect_info[select_band].radio = 0;
		nvram_set_int(strcat_r(prefix, "radio_rp", tmp), 0);
		set_wlan_status(select_band, 0);
		_dprintf("%s:Disable 5G band %d as AP\n", __func__, select_band);
	}

	for(i = 0; i < MAX_NR_WL_IF; i++) {
		if((i == select_band) && (i != WL_2G_BAND))
			continue;

		snprintf(prefix, sizeof(prefix), "wl%d_", i);
		pap_connect_info[i].radio = 1;
		nvram_set_int(strcat_r(prefix, "radio_rp", tmp), 1);

		if(!get_wlan_status(i))
			set_wlan_status(i, 1);
	}

	//_dprintf("%s: wait count %d\n", __func__, wait_count);
connection_check:
	if((connect_wait_count < 0) ||  (
		(pap_connect_info[WL_5G_2_BAND].status == WLC_STATE_CONNECTED) &&
			((pap_connect_info[WL_5G_BAND].status == WLC_STATE_CONNECTED)))) {

		switch(select_band) {
		//wlx_radio
		case WL_5G_BAND:
			if(is_intf_up(pap_connect_info[WL_5G_2_BAND].ifname) > 0) {
				_dprintf("%s:Disable 5G H sta connection\n", __func__);
				doSystem("ifconfig %s down\n", pap_connect_info[WL_5G_2_BAND].ifname);
			}
			break;
		case WL_5G_2_BAND:
			if(is_intf_up(pap_connect_info[WL_5G_BAND].ifname) > 0) {
				_dprintf("%s:Disable 5G L sta connection\n", __func__);
				doSystem("ifconfig %s down\n", pap_connect_info[WL_5G_BAND].ifname);
			}
			break;
		case WL_2G_BAND:
			//stop_wlc_connect(WL_5G_BAND);
			//stop_wlc_connect(WL_5G_2_BAND);
			break;
		default:
			break;
		}
	}

	connect_wait_count--;
end:
	return pap_connect_info[select_band].status;

}
/* WPS mode: client mode and AP mode
 *
 *
 */
enum {
	WPS_AP_MODE		= 0,
	WPS_CLIENT_MODE = 1
};

#define WRITE_WSC_PARAM(dst, tmp, str, val) {	\
	sprintf(tmp, str, val); \
	memcpy(dst, tmp, strlen(tmp)); \
	dst += strlen(tmp); \
}

static int updateWscConf(char *in, char *out, int mode, char *wl2g, char *wl5g, char *wl5g2)
{
	int fh;
	struct stat status;
	char *buf, *ptr;
	char tmp[32] = {0};
	unsigned char mac[6] = {0};
	int intVal, len;
	int wsc_auth, wsc_enc;
	char tmpbuf[100];
	/*for detial mixed mode info*/

	if(!wl2g && !wl5g && !wl5g2)
		return -1;

	if (stat(in, &status) < 0) {
		printf("stat() error [%s]!\n", in);
		return -1;
	}

	buf = malloc(status.st_size+2048);
	if (buf == NULL) {
		printf("malloc() error [%d]!\n", (int)status.st_size+2048);
		return -1;
	}
	ptr = buf;

	if(mode == WPS_CLIENT_MODE) {
		intVal = MODE_CLIENT_UNCONFIG;
	} else if(mode == WPS_AP_MODE){
		if(nvram_get_int("w_Setting")) {
			intVal = MODE_AP_PROXY_REGISTRAR;
		} else {
			intVal = MODE_AP_UNCONFIG;
		}
	}

	if(mode == WPS_CLIENT_MODE) {
	WRITE_WSC_PARAM(ptr, tmpbuf, "mode = %d\n", intVal);
	WRITE_WSC_PARAM(ptr, tmpbuf, "upnp = %d\n", 0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "config_method = %d\n", 134);
	WRITE_WSC_PARAM(ptr, tmpbuf, "connection_type = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "manual_config = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "pin_code = %s\n", nvram_safe_get("secret_code"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "rf_band = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan0 start==========%d\n", 0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan0_wsc_disabled = %d\n", 0);
	get_wsc_auth(2, &wsc_auth, &wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type = %d\n", wsc_auth);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type = %d\n", wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode = %d\n", (wsc_auth == WSC_AUTH_WPA2PSKMIXED)?1:0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "network_key = \"%s\"\n", nvram_get("wl2_wpa_psk"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid = \"%s\"\n", nvram_safe_get("wl2_ssid"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan0 end==========:%d\n", 0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan1 start==========%d\n",1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid2 = \"%s\"\n", nvram_safe_get("wl1_ssid"));
	get_wsc_auth(1, &wsc_auth, &wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type2 = %d\n", wsc_auth);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type2 = %d\n", wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode2 = %d\n", (wsc_auth == WSC_AUTH_WPA2PSKMIXED)?1:0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan1_wsc_disabled = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "network_key2 = \"%s\"\n", nvram_get("wl1_wpa_psk"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan1 end==========%d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan2 start==========%d\n",1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid3 = \"%s\"\n", nvram_safe_get("wl0_ssid"));
	get_wsc_auth(0, &wsc_auth, &wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type3 = %d\n", wsc_auth);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type3 = %d\n", wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode3 = %d\n", (wsc_auth == WSC_AUTH_WPA2PSKMIXED)?1:0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan2_wsc_disabled = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "network_key3 = \"%s\"\n", nvram_get("wl0_wpa_psk"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan2 end==========%d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wps_one_cli_one_daemon = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "device_name = \"%s\"\n", nvram_safe_get("wps_device_name"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "config_by_ext_reg = %d\n", 0);	

	}
	else{
	WRITE_WSC_PARAM(ptr, tmpbuf, "mode = %d\n", intVal);
	WRITE_WSC_PARAM(ptr, tmpbuf, "upnp = %d\n", 0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "config_method = %d\n",\
					(CONFIG_METHOD_KEYPAD | CONFIG_METHOD_VIRTUAL_PIN | CONFIG_METHOD_PHYSICAL_PBC | CONFIG_METHOD_VIRTUAL_PBC));
	WRITE_WSC_PARAM(ptr, tmpbuf, "connection_type = %d\n", 1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "manual_config = %d\n", 0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "pin_code = %s\n", nvram_safe_get("secret_code"));

	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan0 start==========%d\n", wl5g2?0:1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan0_wsc_disabled = %d\n", wl5g2?0:1);
	get_wsc_auth(2, &wsc_auth, &wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type = %d\n", wsc_auth);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type = %d\n", wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode = %d\n", (wsc_auth == WSC_AUTH_WPA2PSKMIXED)?1:0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "network_key = \"%s\"\n", nvram_get("wl2_wpa_psk"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid = \"%s\"\n", nvram_safe_get("wl2_ssid"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan0 end==========:%d\n", wl5g2?0:1);

	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan1 start==========%d\n",wl5g?0:1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan1_wsc_disabled = %d\n", wl5g?0:1);
	get_wsc_auth(1, &wsc_auth, &wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type2 = %d\n", wsc_auth);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type2 = %d\n", wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode2 = %d\n", (wsc_auth == WSC_AUTH_WPA2PSKMIXED)?1:0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "network_key2 = \"%s\"\n", nvram_get("wl1_wpa_psk"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid2 = \"%s\"\n", nvram_safe_get("wl1_ssid"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan1 end==========%d\n", wl5g?0:1);

	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan2 start==========%d\n",wl2g?0:1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "wlan2_wsc_disabled = %d\n", wl2g?0:1);
	WRITE_WSC_PARAM(ptr, tmpbuf, "ssid3 = \"%s\"\n", nvram_safe_get("wl0_ssid"));
	get_wsc_auth(0, &wsc_auth, &wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "auth_type3 = %d\n", wsc_auth);
	WRITE_WSC_PARAM(ptr, tmpbuf, "encrypt_type3 = %d\n", wsc_enc);
	WRITE_WSC_PARAM(ptr, tmpbuf, "mixedmode3 = %d\n", (wsc_auth == WSC_AUTH_WPA2PSKMIXED)?1:0);
	WRITE_WSC_PARAM(ptr, tmpbuf, "network_key3 = \"%s\"\n", nvram_get("wl0_wpa_psk"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "#=====wlan2 end==========%d\n", wl2g?0:1);

	WRITE_WSC_PARAM(ptr, tmpbuf, "device_name = \"%s\"\n", nvram_safe_get("wps_device_name"));
	WRITE_WSC_PARAM(ptr, tmpbuf, "config_by_ext_reg = %d\n", 0);	
	}

	len = (int)(((long)ptr)-((long)buf));

	fh = open(in, O_RDONLY);
	if (fh == -1) {
		printf("open() error [%s]!\n", in);
		return -1;
	}

	lseek(fh, 0L, SEEK_SET);
	if (read(fh, ptr, status.st_size) != status.st_size) {
		printf("read() error [%s]!\n", in);
		return -1;
	}
	close(fh);

	// search UUID field, replace last 12 char with hw mac address
	ptr = strstr(ptr, "uuid =");
	if (ptr) {
		if(get_mac_2g(mac) > 0) {
			convert_bin_to_str(mac, 6, tmp);
			memcpy(ptr+27, tmp, 12);
		}
	}

	fh = open(out, O_RDWR|O_CREAT|O_TRUNC);
	if (fh == -1) {
		printf("open() error [%s]!\n", out);
		return -1;
	}

	if (write(fh, buf, len+status.st_size) != len+status.st_size ) {
		printf("Write() file error [%s]!\n", out);
		return -1;
	}
	close(fh);
	free(buf);

	return 0;

}
/*
 * wscd -start -c /var/wsc-wlan2.conf -w3 wlan2 -fi3 /var/wscd-wlan2.fifo -daemon
 *
 *
 */
static int start_wsc_deamon(int mode, char *wl2g, char *wl5g, char *wl5g2)
{
	int cmd_cnt = 0, pid = 0;
	char *cmd_opt[20]={0};
	char wscConfFile[64] = "/var/wsc";
	char wscFifiFile2g[32] = {0};
	char wscFifiFile5g[32] = {0};
	char wscFifiFile5g2[32] = {0};
	int len;

	if(!wl2g && !wl5g && !wl5g2)
		return -1;

	cmd_opt[cmd_cnt++] = "/usr/sbin/wscd";

	switch(mode) {
	case WPS_AP_MODE:
		cmd_opt[cmd_cnt++] = "-start";
		break;
	case WPS_CLIENT_MODE:
		cmd_opt[cmd_cnt++] = "-mode";
		cmd_opt[cmd_cnt++] = "2";
		break;
	default:
		_dprintf("undefined WPS mode %d\n", mode);
		return -1;
	}

	len = strlen(wscConfFile);
	if(wl2g) {
		snprintf(wscConfFile + len, sizeof(wscConfFile) - len, "-%s", wl2g);
	}

	if(wl5g) {
		snprintf(wscConfFile + len, sizeof(wscConfFile) - len, "-%s", wl5g);
	}

	if(wl5g2) {
		snprintf(wscConfFile + len, sizeof(wscConfFile) - len, "-%s", wl5g2);
	}

	strncat(wscConfFile, ".conf", sizeof(wscConfFile));
	_dprintf("%s: wscconffile %s\n", __FUNCTION__, wscConfFile);

	updateWscConf("/etc/wscd.conf",wscConfFile, mode, wl2g, wl5g, wl5g2);

	cmd_opt[cmd_cnt++] = "-c";
	cmd_opt[cmd_cnt++] = wscConfFile;

	if(wl5g2) { //wlan0
		cmd_opt[cmd_cnt++] = "-w";
		cmd_opt[cmd_cnt++] = wl5g2;
		cmd_opt[cmd_cnt++] = "-fi";
		snprintf(wscFifiFile5g2, sizeof(wscFifiFile5g2), "/var/wscd-%s.fifo", wl5g2);
		cmd_opt[cmd_cnt++] = wscFifiFile5g2;
	}

	if(wl5g) { //wlan1
		if(mode==WPS_CLIENT_MODE){
			cmd_opt[cmd_cnt++] = "-w";
		}
		else{
			cmd_opt[cmd_cnt++] = "-w2";
		}
		cmd_opt[cmd_cnt++] = wl5g;
		if(mode==WPS_CLIENT_MODE){
			cmd_opt[cmd_cnt++] = "-fi";
		}
		else{
			cmd_opt[cmd_cnt++] = "-fi2";
		}
		snprintf(wscFifiFile5g, sizeof(wscFifiFile5g), "/var/wscd-%s.fifo", wl5g);
		cmd_opt[cmd_cnt++] = wscFifiFile5g;
	}

	if(wl2g) { //wlan2
		if(mode==WPS_CLIENT_MODE){
			cmd_opt[cmd_cnt++] = "-w";
		}
		else{
			cmd_opt[cmd_cnt++] = "-w3";
		}
		cmd_opt[cmd_cnt++] = wl2g;
		if(mode==WPS_CLIENT_MODE){
			cmd_opt[cmd_cnt++] = "-fi";
		}
		else{
			cmd_opt[cmd_cnt++] = "-fi3";
		}
		snprintf(wscFifiFile2g, sizeof(wscFifiFile2g), "/var/wscd-%s.fifo", wl2g);
		cmd_opt[cmd_cnt++] = wscFifiFile2g;
	}

	cmd_opt[cmd_cnt++] = "-daemon";

	_eval(cmd_opt, NULL, 0, NULL);

	int	wait_fifo=5;
	do{
		if((wscFifiFile2g[0] == 0 || isFileExist(wscFifiFile2g)) &&
		   (wscFifiFile5g[0] == 0 || isFileExist(wscFifiFile5g)) &&
		   (wscFifiFile5g2[0] == 0 || isFileExist(wscFifiFile5g2))) {
			wait_fifo=0;
		} else {
			wait_fifo--;
			sleep(1);
		}
	} while(wait_fifo > 0);

	return 1;
}

void rtk_stop_wsc(void) {
	DIR *dir;
	struct dirent *next;
	char filename[512];

	//stop iwcontrol
	kill_pidfile_s_rm(IWCONTROL_PID_FILE, SIGKILL, 1);

	//stop wscd
	dir = opendir("/var/run");
	if (!dir) {
		_dprintf("%s: fail to opendir /var/run\n");
		return;
	}

	while ((next = readdir(dir)) != NULL) {
		if (!strncmp(next->d_name, "wscd", strlen("wscd"))) {
			snprintf(filename, sizeof(filename), "/var/run/%s", next->d_name);
			kill_pidfile_s_rm(filename, SIGKILL, 1);
		}
	}
	closedir(dir);

	doSystem("rm -f /var/*.fifo");
}

void rtk_start_wsc(void) {
	int ret = 0;
	char* iwcmd[] = {"iwcontrol", NULL, NULL, NULL, NULL};
	int wlc_express = nvram_get_int("wlc_express");
	int multi_band = 0;
	int wps_band = 0;
	rtk_stop_wsc();

	if(repeater_mode())
	{
#ifdef RTCONFIG_CONCURRENTREPEATER
		if (wlc_express == 0) {

			ret = start_wsc_deamon(WPS_CLIENT_MODE, get_staifname(0), NULL,NULL);
			ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, get_staifname(1), NULL);
#ifdef RTCONFIG_HAS_5G_2
			ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, NULL, get_staifname(2));
#endif
			if(ret) {
				iwcmd[1] = get_staifname(0);
				_eval(iwcmd, NULL, 0, NULL);
				iwcmd[2] = get_staifname(1);
				_eval(iwcmd, NULL, 0, NULL);
#ifdef RTCONFIG_HAS_5G_2
				iwcmd[3] = get_staifname(2);
				_eval(iwcmd, NULL, 0, NULL);
#endif
			}
		}
		else if (wlc_express == 1) {
			ret = start_wsc_deamon(WPS_CLIENT_MODE, get_staifname(0), NULL,NULL);

			if(ret) {
				iwcmd[1] = get_staifname(0);
				_eval(iwcmd, NULL, 0, NULL);
			}
		}
		else if (wlc_express == 2) {
			ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, get_staifname(1), NULL);
#ifdef RTCONFIG_HAS_5G_2
			ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, NULL, get_staifname(2));
#endif
			if(ret) {
				iwcmd[1] = get_staifname(1);
				_eval(iwcmd, NULL, 0, NULL);
#ifdef RTCONFIG_HAS_5G_2
				iwcmd[2] = get_staifname(2);
				_eval(iwcmd, NULL, 0, NULL);
#endif
			}
		}
#endif
	}
	else if(access_point_mode()) {
		ret = start_wsc_deamon(WPS_AP_MODE, get_wififname(0), get_wififname(1),
					   #ifdef RTCONFIG_HAS_5G_2
							   get_wififname(2)
					   #else
							   NULL
					   #endif
							   );
		if(ret) {
			iwcmd[1] = get_wififname(0);
			_eval(iwcmd, NULL, 0, NULL);
			iwcmd[2] = get_wififname(1);
			_eval(iwcmd, NULL, 0, NULL);
#ifdef RTCONFIG_HAS_5G_2
			iwcmd[3] = get_wififname(2);
			_eval(iwcmd, NULL, 0, NULL);
#endif
		}
	}
	else if(mediabridge_mode()){
		wps_band = nvram_get_int("wps_band_x");
		multi_band = nvram_get_int("wps_multiband");	
		if(multi_band == 1)
		{
			ret = start_wsc_deamon(WPS_CLIENT_MODE, get_wififname(0), NULL,NULL);
			ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, get_wififname(1), NULL);
#ifdef RTCONFIG_HAS_5G_2
			ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, NULL, get_wififname(2));
#endif
			if(ret) {
				iwcmd[1] = get_wififname(0);
				_eval(iwcmd, NULL, 0, NULL);
				iwcmd[2] = get_wififname(1);
				_eval(iwcmd, NULL, 0, NULL);
#ifdef RTCONFIG_HAS_5G_2
				iwcmd[3] = get_wififname(2);
				_eval(iwcmd, NULL, 0, NULL);
#endif
			}
		}
		else
		{
			if(wps_band)
			{
				ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, get_wififname(1), NULL);
#ifdef RTCONFIG_HAS_5G_2
				ret = start_wsc_deamon(WPS_CLIENT_MODE, NULL, NULL, get_wififname(2));
#endif
				if(ret) {
				iwcmd[1] = get_wififname(1);
				_eval(iwcmd, NULL, 0, NULL);
#ifdef RTCONFIG_HAS_5G_2
				iwcmd[2] = get_wififname(2);
				_eval(iwcmd, NULL, 0, NULL);
#endif
				}
			}
			else
			{
				ret = start_wsc_deamon(WPS_CLIENT_MODE, get_wififname(0), NULL,NULL);
				if(ret) {
				iwcmd[1] = get_wififname(0);
				_eval(iwcmd, NULL, 0, NULL);
				}
			}

		}
	}
}

int init_smp() {
#if defined(RPAC92)
	//f_write_string("/proc/fc/ctrl/disableWifiTxDistributed", "1", 0, 0);
	system("echo 1 > /proc/fc/ctrl/disableWifiTxDistributed");
	set_irq_smp_affinity(59, 2); //eth0
	set_irq_smp_affinity(61, 1); //eth0
	set_irq_smp_affinity(63, 8); //eth0
	set_irq_smp_affinity(72, 8); //wlan0 5G H
	set_irq_smp_affinity(73, 4); //wlan1 5G L
	set_irq_smp_affinity(74, 1); //usb	 2.4G
#endif
}

void start_thermal_control() {
	system("mkdir -p /var/ther;cp -f /etc/ther.conf /var/ther/conf");
	system("ther_control > /dev/console &");
}
