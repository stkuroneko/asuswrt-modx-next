#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bcmnvram.h>
#include <wlioctl.h>
#include <shutils.h>

#include <rc.h>
#include <shared.h>
// #include "web-qtn.h"
#include "qcsapi_output.h"
#include "qcsapi_rpc_common/client/find_host_addr.h"

#include "qcsapi.h"
#include "qcsapi_rpc/client/qcsapi_rpc_client.h"
#include "qcsapi_rpc/generated/qcsapi_rpc.h"
#include <qcsapi_rpc_common/common/rpc_raw.h>
#include <qcsapi_rpc_common/common/rpc_pci.h>
#include "qcsapi_driver.h"
#include "call_qcsapi.h"
#include "net80211/ieee80211_dfs_reentry.h"

#define WIFINAME_MAX_LEN 20

#ifdef RTCONFIG_JFFS2ND_BACKUP
#include <sys/mount.h>
#include <sys/statfs.h>
#endif

static int lock_qtn_apscan = -1;

#define	WIFINAME	"wifi0_0"
#if 0
void inc_mac(char *mac, int plus);
#endif

struct txpower_ac_qtn_s {
	uint16 min;
	uint16 max;
	uint8 pwr;
};

static const struct txpower_ac_qtn_s txpower_list_qtn_rtac87u[] = {
#if !defined(RTCONFIG_RALINK)
	/* 1 ~ 25% */
	{ 1, 25, 14},
	/* 26 ~ 50% */
	{ 26, 50, 17},
	/* 51 ~ 75% */
	{ 51, 75, 20},
	/* 76 ~ 100% */
	{ 76, 100, 23},
#endif	/* !RTCONFIG_RALINK */
	{ 0, 0, 0x0}
};

typedef uint16 chanspec_t;
extern uint8 wf_chspec_ctlchan(chanspec_t chspec);
extern chanspec_t wf_chspec_aton(char *a);

/* shared/bcmwifi.c */
/* given a chanspec string, convert to a chanspec.
 * On error return 0
 */
chanspec_t
wf_chspec_aton(char *a)
{
	char *endp;
	uint channel, band, bw, ctl_sb;
	char c;

	channel = strtoul(a, &endp, 10);

	/* check for no digits parsed */
	if (endp == a)
		return 0;

	if (channel > MAXCHANNEL)
		return 0;

	band = ((channel <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G : WL_CHANSPEC_BAND_5G);
	bw = WL_CHANSPEC_BW_20;
	ctl_sb = WL_CHANSPEC_CTL_SB_NONE;

	a = endp;

	c = tolower(a[0]);
	if (c == '\0')
		goto done;

	/* parse the optional ['A' | 'B'] band spec */
	if (c == 'a' || c == 'b') {
		band = (c == 'a') ? WL_CHANSPEC_BAND_5G : WL_CHANSPEC_BAND_2G;
		a++;
		c = tolower(a[0]);
		if (c == '\0')
			goto done;
	}

	/* parse bandwidth 'N' (10MHz) or 40MHz ctl sideband ['L' | 'U'] */
	if (c == 'n') {
		bw = WL_CHANSPEC_BW_10;
	} else if (c == 'l') {
		bw = WL_CHANSPEC_BW_40;
		ctl_sb = WL_CHANSPEC_CTL_SB_LOWER;
		/* adjust channel to center of 40MHz band */
		if (channel <= (MAXCHANNEL - CH_20MHZ_APART))
			channel += CH_10MHZ_APART;
		else
			return 0;
	} else if (c == 'u') {
		bw = WL_CHANSPEC_BW_40;
		ctl_sb = WL_CHANSPEC_CTL_SB_UPPER;
		/* adjust channel to center of 40MHz band */
		if (channel > CH_20MHZ_APART)
			channel -= CH_10MHZ_APART;
		else
			return 0;
	} else {
		return 0;
	}

done:
	return (channel | band | bw | ctl_sb);
}

/* src-rt-6.x.4708/wl/exe/wlu.c */
char *
wl_ether_etoa(const struct ether_addr *n)
{
	static char etoa_buf[ETHER_ADDR_LEN * 3];
	char *c = etoa_buf;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", n->ether_addr_octet[i] & 0xff);
	}
	return etoa_buf;
}

/* include/bcmwifi.h */
#ifndef ASSERT
#define ASSERT(exp)
#endif

/* shared/bcmwifi.c */
/*
 * This function returns the channel number that control traffic is being sent on, for legacy
 * channels this is just the channel number, for 40MHZ channels it is the upper or lowre 20MHZ
 * sideband depending on the chanspec selected
 */
uint8
wf_chspec_ctlchan(chanspec_t chspec)
{
	uint8 ctl_chan;

	/* Is there a sideband ? */
	if (CHSPEC_CTL_SB(chspec) == WL_CHANSPEC_CTL_SB_NONE) {
		return CHSPEC_CHANNEL(chspec);
	} else {
		/* we only support 40MHZ with sidebands */
		ASSERT(CHSPEC_BW(chspec) == WL_CHANSPEC_BW_40);
		/* chanspec channel holds the centre frequency, use that and the
		 * side band information to reconstruct the control channel number
		 */
		if (CHSPEC_CTL_SB(chspec) == WL_CHANSPEC_CTL_SB_UPPER) {
			/* control chan is the upper 20 MHZ SB of the 40MHZ channel */
			ctl_chan = UPPER_20_SB(CHSPEC_CHANNEL(chspec));
		} else {
			ASSERT(CHSPEC_CTL_SB(chspec) == WL_CHANSPEC_CTL_SB_LOWER);
			/* control chan is the lower 20 MHZ SB of the 40MHZ channel */
			ctl_chan = LOWER_20_SB(CHSPEC_CHANNEL(chspec));
		}
	}

	return ctl_chan;
}

int
setCountryCode_5G_qtn(const char *cc)
{
	int ret;
	char value[20] = {0};

	if( cc==NULL || !isValidCountryCode(cc) )
		return 0;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_update_parameter("ccode_5g", cc);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_get_parameter("ccode_5g", value, sizeof(value));
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	if (!IS_ATE_FACTORY_MODE()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	nvram_set("1:ccode", cc);
	puts(nvram_safe_get("1:ccode"));

	return 1;
}

int
getCountryCode_5G_qtn(void)
{
	puts(nvram_safe_get("1:ccode"));

	return 0;
}

int setRegrev_5G_qtn(const char *regrev)
{
	int ret;
	char value[20] = {0};

	if( regrev==NULL || !isValidRegrev((char *)regrev) )
		return 0;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_update_parameter("regrev_5g", regrev);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_get_parameter("regrev_5g", value, sizeof(value));
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	if (!IS_ATE_FACTORY_MODE()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	nvram_set("1:regrev", regrev);
	puts(nvram_safe_get("1:regrev"));
	return 1;
}

int
getRegrev_5G_qtn(void)
{
	puts(nvram_safe_get("1:regrev"));
	return 0;
}

int setMAC_5G_qtn(const char *mac)
{
	int ret;
	char value[20] = {0};

	if( mac==NULL || !isValidMacAddr(mac) )
		return 0;

	if (!rpc_qtn_ready())
	{
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_update_parameter("ethaddr", mac);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
#if 0
	inc_mac(mac, 1);
#endif
	ret = qcsapi_bootcfg_update_parameter("wifiaddr", mac);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_get_parameter("ethaddr", value, sizeof(value));
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	if (!IS_ATE_FACTORY_MODE()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	nvram_set("1:macaddr", mac);
	// puts(nvram_safe_get("1:macaddr"));

	puts(value);
	return 1;
}

int getMAC_5G_qtn(void)
{
	int ret;
	char value[20] = {0};

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_get_parameter("ethaddr", value, sizeof(value));
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	puts(value);
	return 1;
}

int setAllLedOn_qtn(void)
{
	int ret;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_led_set(1, 1);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_wifi_run_script("router_command.sh", "lan4_led_ctrl on");
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	return 0;
}

int setAllLedOff_qtn(void)
{
	int ret;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_wifi_run_script("router_command.sh", "wifi_led_off");
	if (ret < 0) {
		fprintf(stderr, "[led] router_command.sh: wifi_led_off error\n");
		return -1;
	}

	ret = qcsapi_led_set(1, 0);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	ret = qcsapi_wifi_run_script("router_command.sh", "lan4_led_ctrl off");
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	return 0;
}

int Get_channel_list_qtn(int unit)
{
	int ret;
	string_1024 list_of_channels;
	char cur_ccode[20] = {0};

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_wifi_get_regulatory_region("wifi0", cur_ccode);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_regulatory_get_list_regulatory_channels(cur_ccode, 20 /* bw */, list_of_channels);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	puts(list_of_channels);

	return 1;
}

int Get_ChannelList_5G_qtn(void)
{
	return Get_channel_list_qtn(1);
}

// format : [Band, SSID, channel, security, encryption, RSSI, MAC, 802.11xx, hidden]
void show_ap_properties(const qcsapi_unsigned_int index, const qcsapi_ap_properties *params, char *buff)
{
	int channel 	= params->ap_channel;
	int wpa_mask	= params->ap_protocol;
	int psk_mask	= params->ap_authentication_mode;
	int tkip_mask	= params->ap_encryption_modes;
	int proto 	= params->ap_80211_proto;
	int hidden;
	char band[8], ssid[256], security[32], auth[16], crypto[32], wmode[8];
	char mac[24];

	// MAC
	sprintf(&mac[0], "%02X:%02X:%02X:%02X:%02X:%02X", 
		params->ap_mac_addr[0],
		params->ap_mac_addr[1],
		params->ap_mac_addr[2],
		params->ap_mac_addr[3],
		params->ap_mac_addr[4],
		params->ap_mac_addr[5]
	);

	// Band
	if(channel > 15)
		strcpy(band, "5G");
	else
		strcpy(band, "2G");

	// SSID
	if(!strcmp(params->ap_name_SSID, ""))
		strcpy(ssid, "");
	else{	
		memset(ssid, 0, sizeof(ssid));
#if defined(RTCONFIG_UTF8_SSID)
		char_to_ascii_with_utf8(ssid, params->ap_name_SSID);
#else
		char_to_ascii(ssid, params->ap_name_SSID);
#endif
	}

	// security and authentication : check wpa_mask and psk_mask
	// 	wpa_mask : 0x01 = WPA, 0x02 = WPA2
	// 	psk_mask : 0x01 = psk, 0x02 = enterprise
	if((wpa_mask == 0x1) && (psk_mask == 0x01)){
		strcpy(security, "WPA-Personal");
		strcpy(auth, "PSK");
	}
	else if((wpa_mask == 0x2) && (psk_mask == 0x01)){
		strcpy(security, "WPA2-Personal");
		strcpy(auth, "PSK");
	}
	else if((wpa_mask == 0x3) && (psk_mask == 0x01)){
		strcpy(security, "WPA-Auto-Personal");
		strcpy(auth, "PSK");
	}
	else if((wpa_mask == 0x0) && (psk_mask == 0x0)){
		strcpy(security, "Open System");
		strcpy(auth, "NONE");
	}
	else{
		strcpy(security, "");
		strcpy(auth, "");
	}
		
	// encryption : check tkip_mask
	// 	tkip_mask : 0x01 = tkip, 0x02 = aes, 0x03 = tkip+aes
	if(tkip_mask == 0x01)
		strcpy(crypto, "TKIP");
	else if(tkip_mask == 0x02)
		strcpy(crypto, "AES");
	else if(tkip_mask == 0x03)
		strcpy(crypto, "TKIP+AES");
	else
		strcpy(crypto, "NONE");

	// Wmode : b/a/an/bg/bgn
	// 0x01 : b
	// 0x02 : g
	// 0x04 : a
	// 0x08 : n
	if(proto == 0x01)
		strcpy(wmode, "b");
	else if(proto == 0x04)
		strcpy(wmode, "a");
	else if(proto == 0x0C)
		strcpy(wmode, "an");
	else if(proto == 0x03)
		strcpy(wmode, "bg");
	else if(proto == 0x0B)
		strcpy(wmode, "bgn");
	else if(proto == 0x1C)
		strcpy(wmode, "ac");
	else{
		strcpy(wmode, "");
		fprintf(stderr, "[%s][%d]dp: [%d]\n", __FUNCTION__, __LINE__, proto);
	}

	// hidden SSID : if get MAC but not get SSID, it should be a hidden SSID
	if((&mac[0] != NULL) && !strcmp(params->ap_name_SSID, ""))
		hidden = 1;
	else if((&mac[0] != NULL) && !strcmp(params->ap_name_SSID, ""))
		hidden = 0;
	else
		hidden = 0;

#if 0
	dbg("band=%s,SSID=%s,channel=%d,security=%s,crypto=%s,RSSI=%d,MAC=%s,wmode=%s,hidden=%d\n", 
		band, ssid, params->ap_channel, security, crypto, params->ap_RSSI, &mac[0], wmode, hidden);
#endif

	sprintf(buff, "\"%s\",\"%s\",\"%d\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\",\"%d\"", 
		band, ssid, params->ap_channel, security, crypto, params->ap_RSSI, &mac[0], wmode, hidden);
}

int wlcscan_core(char *ofile, char *ifname)
{
	int i;
	int scanstatus = -1;
	uint32_t count;
	qcsapi_ap_properties	params;
	char buff[256];
	FILE *fp_apscan;

	if (!rpc_qtn_ready()) {
		_dprintf("5 GHz radio is not ready\n");
		return -1;
	}

	logmessage("wlcscan", "start wlcscan scan\n");

	// start scan AP
	// if(qcsapi_wifi_start_scan(ifname)){
	if(qcsapi_wifi_start_scan_ext(ifname, IEEE80211_PICK_ALL | IEEE80211_PICK_NOPICK_BG)){
		dbg("fail to start AP scan\n");
		return 0;
	}
	fprintf(stderr, "ok to start AP scan\n");

	// loop for check scan status
	while(1){
		if(qcsapi_wifi_get_scan_status(ifname, &scanstatus) < 0){
			dbg("scan error occurs\n");
			return 0;
		}
		
		// if scanstatus = 0 , no scan is running
		if(scanstatus == 0) break;
		else{
			dbg("scan is running...\n");
			sleep(1);
		}
	}

	// check AP scan
	if(qcsapi_wifi_get_results_AP_scan(ifname, &count) < 0){
		dbg("fail to get AP scan results, ifname=%s, count=%d\n", ifname, (int)count);
		return 0;
	}

	if(count > 0){
		lock_qtn_apscan = file_lock("sitesurvey");

		if((fp_apscan = fopen(ofile, "a")) == NULL){
			dbg("fail to write to [%s]\n", ofile);
			file_unlock(lock_qtn_apscan);
			return 0;
		}

		// for loop
		for(i = 0; i < (int)count; i++){
			// get properties of AP
			if(!qcsapi_wifi_get_properties_AP(ifname, (uint32_t)i, &params)){
				show_ap_properties((uint32_t)i, &params, buff);
				fprintf(fp_apscan, "%s", buff);
			}
			else{
				dbg("fail to get AP properties\n");
			}

			fprintf(fp_apscan, "\n");
		}
		fclose(fp_apscan);

		file_unlock(lock_qtn_apscan);
	}

	return 1;
}

int GetPhyStatus_qtn(void)
{
	int ret;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_wifi_run_script("router_command.sh", "get_eth_1000m");
	if (ret < 0) {
		ret = qcsapi_wifi_run_script("router_command.sh", "get_eth_100m");
		if (ret < 0) {
			ret = qcsapi_wifi_run_script("router_command.sh", "get_eth_10m");
			if (ret < 0) {
				// fprintf(stderr, "ATE command error\n");
				return 0;
			}else{
				return 10;
			}
		}else{
			return 100;
		}
		return -1;
	}else{
		return 1000;
	}
	return 0;
}

int start_ap_qtn(void)
{
	char ssid[65];

	if (!rpc_qtn_ready()) {
		_dprintf("5 GHz radio is not ready\n");
		return -1;
	}

	logmessage("start_ap", "AP is running...");

#if 0
	qcsapi_retval = qcsapi_wifi_reload_in_mode(WIFINAME, qcsapi_access_point);

	if (qcsapi_retval >= 0) {
		fprintf(stderr, "reload to AP mode successfuly\n" );
	} else {
		fprintf(stderr, "reload to AP mode failed\n" );
	}
#endif
	snprintf(ssid, sizeof(ssid), "%s", nvram_safe_get("wl1_ssid"));
	qcsapi_wifi_set_SSID(WIFINAME, ssid);

	// check security
	char auth[8];
	char crypto[16];
	char beacon[] = "WPAand11i";
	char encryption[] = "TKIPandAESEncryption";
	char key[65];
	uint32_t index = 0;

	strncpy(auth, nvram_safe_get("wl1_auth_mode_x"), sizeof(auth));
	strncpy(crypto, nvram_safe_get("wl1_crypto"), sizeof(crypto));
	strncpy(key, nvram_safe_get("wl1_wpa_psk"), sizeof(key));

	if(!strcmp(auth, "psk2") && !strcmp(crypto, "aes")){
		memcpy(beacon, "11i", strlen("11i") + 1);
		memcpy(encryption, "AESEncryption", strlen("AESEncryption") + 1);
	}
	else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "aes") ){
		memcpy(beacon, "WPAand11i", strlen("WPAand11i") + 1);
		memcpy(encryption, "AESEncryption", strlen("AESEncryption") + 1);
	}
	else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "tkip+aes") ){
		memcpy(beacon, "WPAand11i", strlen("WPAand11i") + 1);
		memcpy(encryption, "TKIPandAESEncryption", strlen("TKIPandAESEncryption") + 1);
	}
	else{
		logmessage("start_ap", "No security in use\n");
		memcpy(beacon, "Basic", strlen("Basic") + 1);
	}

	logmessage("start_ap", "ssid=%s, auth=%s, crypto=%s, encryption=%s, key=%s\n", ssid, auth, crypto, encryption, key);
	if(!strcmp(auth, "open")){
		if(qcsapi_wifi_set_WPA_authentication_mode(WIFINAME, "NONE") < 0)
			logmessage("start_ap", "fail to setup a open-none ap\n");
		if(qcsapi_wifi_set_beacon_type(WIFINAME, beacon) < 0)
			logmessage("start_ap", "fail to setup beacon type in ap\n");
	}
	else{
		if(qcsapi_wifi_set_beacon_type(WIFINAME, beacon) < 0)
			logmessage("start_ap", "fail to setup beacon type in ap\n");
		if(qcsapi_wifi_set_WPA_authentication_mode(WIFINAME, "PSKAuthentication") < 0)
			logmessage("start_ap", "fail to setup authentiocation type in ap\n");
		if(qcsapi_wifi_set_key_passphrase(WIFINAME, index, key) < 0)
			logmessage("start_ap", "fail to set key in ap\n");
		if(qcsapi_wifi_set_WPA_encryption_modes(WIFINAME, encryption) < 0)
			logmessage("start_ap", "fail to set encryption mode in ap\n");
	}

	logmessage("start_ap", "start_ap done!\n");

	return 1;
}

int start_psta_qtn(void)
{
	static qcsapi_SSID	 array_ssids[10 /* MAX_SSID_LIST_SIZE */];
	int			 qcsapi_retval;
	unsigned int		 iter;
	qcsapi_unsigned_int	 sizeof_list = 2 /* DEFAULT_SSID_LIST_SIZE */ ;
	char			*list_ssids[10 /* MAX_SSID_LIST_SIZE */ + 1];
	int ret;
	char ifname[10] = "wifi0_0";
	char ifname_disable[10] = "wifi2_0";
	int band;

	if (!rpc_qtn_ready()) {
		_dprintf("wifi is not ready\n");
		return -1;
	}

	band = nvram_get_int("wlc_band");
	logmessage("start_psta", "media bridge is running...");
	if(band == 0){
		snprintf(ifname, sizeof(ifname), "wifi2_0");
		/* disable another band */
		snprintf(ifname_disable, sizeof(ifname_disable), "wifi0_0");
	}else if(band == 1){
		snprintf(ifname, sizeof(ifname), "wifi0_0");
		/* disable another band */
		snprintf(ifname_disable, sizeof(ifname_disable), "wifi2_0");
	}else{
		snprintf(ifname, sizeof(ifname), "wifi0_0");
		/* disable another band */
		snprintf(ifname_disable, sizeof(ifname_disable), "wifi2_0");
	}

	qcsapi_retval = qcsapi_wifi_reload_in_mode(ifname, qcsapi_station);
	fprintf(stderr, "wait 20 seconds to start psta mode\n");
	sleep(20);

	if (qcsapi_retval >= 0) {
		fprintf(stderr, "reload to STA mode successfuly\n" );
	} else {
		fprintf(stderr, "reload to STA mode failed\n" );
	}
	qcsapi_radio_rfenable(ifname_disable, 0);

	for (iter = 0; iter < sizeof_list; iter++) {
		list_ssids[iter] = array_ssids[iter];
		*(list_ssids[iter]) = '\0';
	}

	qcsapi_retval = qcsapi_SSID_get_SSID_list(ifname, sizeof_list, &list_ssids[0]);
	if (qcsapi_retval >= 0) {
		for (iter = 0; iter < sizeof_list; iter++) {
			if ((list_ssids[iter] == NULL) || strlen(list_ssids[iter]) < 1) {
				break;
			}
			fprintf(stderr, "remove [%s]\n", list_ssids[iter]);
			qcsapi_SSID_remove_SSID(ifname, array_ssids[iter]);
		}
	}

	// verify ssid, if not exists, create new one
	char ssid[33];
	strncpy(ssid, nvram_safe_get("wlc_ssid"), sizeof(ssid));
	logmessage("start_psta", "verify ssid [%s]", ssid);
	if(qcsapi_SSID_verify_SSID(ifname, ssid) < 0){
		logmessage("start_psta", "Not such SSID in sta mode\n");
		if(qcsapi_SSID_create_SSID(ifname, ssid) < 0)
			logmessage("start_psta", "fail to create SSID in sta mode\n");
	}

	// check security
	char auth[8];
	char crypto[16];
	char beacon[] = "WPAand11i";
	char encryption[] = "TKIPandAESEncryption";
	char key[65];
	uint32_t index = 0;

	strncpy(auth, nvram_safe_get("wlc_auth_mode"), sizeof(auth));
	strncpy(crypto, nvram_safe_get("wlc_crypto"), sizeof(crypto));
	strncpy(key, nvram_safe_get("wlc_wpa_psk"), sizeof(key));

	if(!strcmp(auth, "psk2") && !strcmp(crypto, "aes")){
		memcpy(beacon, "11i", strlen("11i") + 1);
		memcpy(encryption, "AESEncryption", strlen("AESEncryption") + 1);
	}
	else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "aes") ){
		memcpy(beacon, "WPAand11i", strlen("WPAand11i") + 1);
		memcpy(encryption, "AESEncryption", strlen("AESEncryption") + 1);
	}
	else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "tkip+aes") ){
		memcpy(beacon, "WPAand11i", strlen("WPAand11i") + 1);
		memcpy(encryption, "TKIPandAESEncryption", strlen("TKIPandAESEncryption") + 1);
	}
	else{
		logmessage("start_psta", "not support such authentication & encryption\n");
	}

	logmessage("start_psta", "ssid=%s, auth=%s, crypto=%s, encryption=%s, key=%s\n", ssid, auth, crypto, encryption, key);
	if(!strcmp(auth, "open")){
		if(qcsapi_SSID_set_authentication_mode(ifname, ssid, "NONE") < 0)
			logmessage("start_psta", "fail to setup a open-none sta\n");
	}
	else{
		if(qcsapi_SSID_set_protocol(ifname, ssid, beacon) < 0)
			logmessage("start_psta", "fail to setup protocol in sta\n");
		if(qcsapi_SSID_set_authentication_mode(ifname, ssid, "PSKAuthentication") < 0)
			logmessage("start_psta", "fail to setup authentiocation type in sta\n");
		if(qcsapi_SSID_set_key_passphrase(ifname, ssid, index, key) < 0)
			logmessage("start_psta", "fail to set key in sta\n");
	}

	// eval("wpa_cli", "reconfigure");
	ret = qcsapi_wifi_run_script("router_command.sh", "wpa_cli_reconfigure");
	if (ret < 0) {
		fprintf(stderr, "[psta] router_command.sh: wpa_cli_reconfigure error\n");
		return -1;
	}

	logmessage("start_psta", "start_psta done!\n");

	return 1;
}

int start_nodfs_scan_qtn(void)
{
	int		 qcsapi_retval;
	int pick_flags = 0;

	logmessage("dfs", "start dfs scan\n");

	pick_flags = IEEE80211_PICK_CLEAREST;
	pick_flags |= IEEE80211_PICK_NONDFS;

	if (!rpc_qtn_ready()) {
		_dprintf("5 GHz radio is not ready\n");
		return -1;
	}
	qcsapi_retval = qcsapi_wifi_start_scan_ext(WIFINAME, pick_flags);
	if (qcsapi_retval >= 0) {
		logmessage("nodfs_scan", "complete");
	}else{
		logmessage("nodfs_scan", "scan not complete");
	}

	return 1;
}

int enable_qtn_telnetsrv(int enable_flag)
{
	int ret;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	if(enable_flag == 0){
		nvram_set("QTNTELNETSRV", "0");
		ret = qcsapi_wifi_run_script("router_command.sh", "enable_telnet_srv 0");
	}else{
		nvram_set("QTNTELNETSRV", "1");
		ret = qcsapi_wifi_run_script("router_command.sh", "enable_telnet_srv 1");
	}
	if (ret < 0) {
		fprintf(stderr, "[ate] set telnet server error\n");
		return -1;
	}
	nvram_commit();
	return 0;
}

int getstatus_qtn_telnetsrv(void)
{
	if(nvram_get_int("QTNTELNETSRV") == 1)
		puts("1");
	else
		puts("0");

	return 0;
}

int del_qtn_cal_files(void)
{
	int ret;

	if (!rpc_qtn_ready()) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_wifi_run_script("router_command.sh", "del_cal_files");
	if (ret < 0) {
		fprintf(stderr, "[ate] delete calibration files error\n");
		return -1;
	}
	return 0;
}

int get_tx_power_qtn(void)
{
	const struct txpower_ac_qtn_s *p_to_table;
	int txpower = 80;

	p_to_table = &txpower_list_qtn_rtac87u[0];
	txpower = nvram_get_int("wl1_txpower");

	for(; p_to_table->min != 0; ++p_to_table) {
		if(txpower >= p_to_table->min && txpower <= p_to_table->max) {
			_dprintf("txpoewr between: min:[%d] to max:[%d]\n", p_to_table->min, p_to_table->max);
			return p_to_table->pwr;
		}
	}

	if( p_to_table->min == 0 )
		_dprintf("no correct power offset!\n");

	/* default max power */
	return 23;
}

void fix_script_err(char *orig_str, char *new_str)
{
	unsigned i = 0, j = 0;
	unsigned int str_len = 0;
	str_len = strlen(orig_str);

	for ( i = 0; i < str_len; i++ ){
		if(orig_str[i] == '$' ||
			orig_str[i] == '`' ||
			orig_str[i] == '"' ||
			orig_str[i] == '\\'){
			new_str[j] = '\\';
			new_str[j+1] = orig_str[i];
			j = j + 2;
		}else{
			new_str[j] = orig_str[i];
			j++;
		}
	}
}

int gen_stateless_conf(void)
{
	FILE *fp;

	int l_len;
	// check security
	char auth[8];
	char crypto[16];
	//char beacon[] = "WPAand11i";
	char encryption[] = "TKIPandAESEncryption";
	char key[130];
	char tmpkey[130];
	char ssid[66];
	char tmpssid[66];
	char region[5] = {0};
	int channel = wf_chspec_ctlchan(wf_chspec_aton(nvram_safe_get("wl1_chanspec")));
	int bw = atoi(nvram_safe_get("wl1_bw"));

	snprintf(ssid, sizeof(ssid), "%s", nvram_safe_get("wl1_ssid"));
	memset(tmpssid, 0, sizeof(tmpssid));
	fix_script_err(ssid, tmpssid);
	strncpy(ssid, tmpssid, sizeof(ssid));

	snprintf(region, sizeof(region), "%s", nvram_safe_get("wl1_country_code"));
	if(strlen(region) == 0)
		snprintf(region, sizeof(region), "%s", nvram_safe_get("1:ccode"));
	dbg("[stateless] channel:[%d]\n", channel);
	dbg("[stateless] bw:[%d]\n", bw);

	fp = fopen("/tmp/stateless_slave_config", "w");

	if(sw_mode() == SW_MODE_AP &&
		nvram_get_int("wlc_psta") == 1 &&
		nvram_get_int("wlc_band") == 1){
		/* media bridge mode */
		fprintf(fp, "wifi0_mode=sta\n");

		strncpy(auth, nvram_safe_get("wlc_auth_mode"), sizeof(auth));
		strncpy(crypto, nvram_safe_get("wlc_crypto"), sizeof(crypto));
		strncpy(key, nvram_safe_get("wlc_wpa_psk"), sizeof(key));
		memset(tmpkey, 0, sizeof(tmpkey));
		fix_script_err(key, tmpkey);
		strncpy(key, tmpkey, sizeof(key));

		strncpy(ssid, nvram_safe_get("wlc_ssid"), sizeof(ssid));
		memset(tmpssid, 0, sizeof(tmpssid));
		fix_script_err(ssid, tmpssid);
		strncpy(ssid, tmpssid, sizeof(ssid));
		fprintf(fp, "wifi0_SSID=\"%s\"\n", ssid);

		logmessage("start_psta", "ssid=%s, auth=%s, crypto=%s, encryption=%s, key=%s\n", ssid, auth, crypto, encryption, key);

		/* convert security from nvram to qtn */
		if(!strcmp(auth, "psk2") && !strcmp(crypto, "aes")){
			fprintf(fp, "wifi0_auth_mode=PSKAuthentication\n");
			fprintf(fp, "wifi0_beacon=11i\n");
			fprintf(fp, "wifi0_encryption=AESEncryption\n");
			fprintf(fp, "wifi0_passphrase=\"%s\"\n", key);
		}
		else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "aes") ){
			fprintf(fp, "wifi0_auth_mode=PSKAuthentication\n");
			fprintf(fp, "wifi0_beacon=WPAand11i\n");
			fprintf(fp, "wifi0_encryption=AESEncryption\n");
			fprintf(fp, "wifi0_passphrase=\"%s\"\n", key);
		}
		else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "tkip+aes") ){
			fprintf(fp, "wifi0_auth_mode=PSKAuthentication\n");
			fprintf(fp, "wifi0_beacon=WPAand11i\n");
			fprintf(fp, "wifi0_encryption=TKIPandAESEncryption\n");
			fprintf(fp, "wifi0_passphrase=\"%s\"\n", key);
		}
		else{
			logmessage("start_psta", "No security in use\n");
			fprintf(fp, "wifi0_auth_mode=NONE\n");
			fprintf(fp, "wifi0_beacon=Basic\n");
		}

		/* auto channel for media bridge mode */
		channel = 0;
	}else{
		/* not media bridge mode */
		fprintf(fp, "wifi0_mode=ap\n");

		strncpy(auth, nvram_safe_get("wl1_auth_mode_x"), sizeof(auth));
		strncpy(crypto, nvram_safe_get("wl1_crypto"), sizeof(crypto));
		strncpy(key, nvram_safe_get("wl1_wpa_psk"), sizeof(key));
		memset(tmpkey, 0, sizeof(tmpkey));
		fix_script_err(key, tmpkey);
		strncpy(key, tmpkey, sizeof(key));


		strncpy(ssid, nvram_safe_get("wl1_ssid"), sizeof(ssid));
		memset(tmpssid, 0, sizeof(tmpssid));
		fix_script_err(ssid, tmpssid);
		strncpy(ssid, tmpssid, sizeof(ssid));
		fprintf(fp, "wifi0_SSID=\"%s\"\n", ssid);

		if(!strcmp(auth, "psk2") && !strcmp(crypto, "aes")){
			fprintf(fp, "wifi0_auth_mode=PSKAuthentication\n");
			fprintf(fp, "wifi0_beacon=11i\n");
			fprintf(fp, "wifi0_encryption=AESEncryption\n");
			fprintf(fp, "wifi0_passphrase=\"%s\"\n", key);
		}
		else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "aes") ){
			fprintf(fp, "wifi0_auth_mode=PSKAuthentication\n");
			fprintf(fp, "wifi0_beacon=WPAand11i\n");
			fprintf(fp, "wifi0_encryption=AESEncryption\n");
			fprintf(fp, "wifi0_passphrase=\"%s\"\n", key);
		}
		else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "tkip+aes") ){
			fprintf(fp, "wifi0_auth_mode=PSKAuthentication\n");
			fprintf(fp, "wifi0_beacon=WPAand11i\n");
			fprintf(fp, "wifi0_encryption=TKIPandAESEncryption\n");
			fprintf(fp, "wifi0_passphrase=\"%s\"\n", key);
		}
		else{
			logmessage("start_ap", "No security in use\n");
			fprintf(fp, "wifi0_beacon=Basic\n");
		}
	}

	for( l_len = 0 ; l_len < strlen(region); l_len++){
		region[l_len] = tolower(region[l_len]);
	}
	fprintf(fp, "wifi0_region=%s\n", region);
	// nvram_set("wl1_country_code", nvram_safe_get("1:ccode"));
	fprintf(fp, "wifi0_vht=1\n");
	if(bw==1) fprintf(fp, "wifi0_bw=20\n");
	else if(bw==2) fprintf(fp, "wifi0_bw=40\n");
	else if(bw==3) fprintf(fp, "wifi0_bw=80\n");
	else fprintf(fp, "wifi0_bw=80\n");

	/* if media bridge mode, always auto channel */
	fprintf(fp, "wifi0_channel=%d\n", channel);
	fprintf(fp, "wifi0_pwr=%d\n", get_tx_power_qtn());
	if(nvram_get_int("wl1_itxbf") == 1 || nvram_get_int("wl1_txbf") == 1){
		fprintf(fp, "wifi0_bf=1\n");
	}else{
		fprintf(fp, "wifi0_bf=0\n");
	}
	if(nvram_get_int("wl1_mumimo") == 1){
		fprintf(fp, "wifi0_mu=1\n");
	}else{
		fprintf(fp, "wifi0_mu=0\n");
	}
	fprintf(fp, "wifi0_staticip=1\n");
	fprintf(fp, "slave_ipaddr=\"192.168.1.111/16\"\n");
	fprintf(fp, "server_ipaddr=\"%s\"\n", nvram_safe_get("QTN_RPC_SERVER"));
	fprintf(fp, "client_ipaddr=\"%s\"\n", nvram_safe_get("QTN_RPC_CLIENT"));

	if(nvram_match("wl1.1_lanaccess", "off") && !nvram_match("wl1.1_lanaccess", ""))
		fprintf(fp, "wifi1_lanaccess=off\n");
	else
		fprintf(fp, "wifi1_lanaccess=on\n");

	if(nvram_match("wl1.2_lanaccess", "off") && !nvram_match("wl1.2_lanaccess", ""))
		fprintf(fp, "wifi2_lanaccess=off\n");
	else
		fprintf(fp, "wifi2_lanaccess=on\n");

	if(nvram_match("wl1.3_lanaccess", "off") && !nvram_match("wl1.3_lanaccess", ""))
		fprintf(fp, "wifi3_lanaccess=off\n");
	else
		fprintf(fp, "wifi3_lanaccess=on\n");

	fclose(fp);

	return 1;
}

int rpc_qcsapi_set_SSID(int unit, int subunit)
{
	int ret = 0;
	char *ssid;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_ssid", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_ssid", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;
_dprintf("[%s] test 1. nvram=%s, ifname=%s.\n", __func__, prefix, ifname);

	ssid = nvram_safe_get(prefix);

	ret = qcsapi_wifi_set_SSID(ifname, ssid);
	if (ret < 0) {
		_dprintf("set_SSID %s error, return: %d\n", ifname, ret);
		return ret;
	}
	_dprintf("%s ssid as: %s\n", ifname, ssid);

	return 0;
}

int rpc_qcsapi_set_SSID_broadcast(int unit, int subunit)
{
	int ret;
	int OPTION;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_closed", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_closed", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	OPTION = 1 - atoi(nvram_safe_get(prefix));


	ret = qcsapi_wifi_set_option(ifname, qcsapi_SSID_broadcast, OPTION);
	if (ret < 0) {
		_dprintf("set_option::SSID_broadcast %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s ssid broadcast as: %s\n", ifname, OPTION ? "TRUE" : "FALSE");

	return 0;
}

int rpc_qcsapi_set_vht(int unit, int subunit)
{
	int ret;
	int VHT;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_nmode_x", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_nmode_x", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	switch (atoi(nvram_safe_get(prefix)))
	{
		case 0:
			VHT = 1;
			break;
		default:
			VHT = 0;
			break;
	}

	ret = qcsapi_wifi_set_vht(ifname, VHT);
	if (ret < 0) {
		_dprintf("set_vht %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s vht as: %s\n", ifname, VHT ? "11ac" : "11n");

	return 0;
}

int rpc_qcsapi_set_bw(int unit, int subunit)
{
	int ret;
	int BW = 20;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_bw", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_bw", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	switch (atoi(nvram_safe_get(prefix)))
	{
		case 1:
			BW = 20;
			break;
		case 2:
			BW = 40;
			break;
		case 3:
			BW = 80;
			break;
		case 0:
		case 4:
			BW = 160;
			break;
	}

	ret = qcsapi_wifi_set_bw(ifname, BW);
	if (ret < 0) {
		_dprintf("set_bw %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s bw as: %d MHz\n", ifname, BW);

	return 0;
}

int rpc_qcsapi_set_channel(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int channel = 0;
	char str_ch[] = "149";
	char ifname[WIFINAME_MAX_LEN] = {0};
	int ch_pri[] = { 40, 56, 104, 116, 120, 124, 128, 136, 140, 144, 149, 153};
	int ch_pri_inact ;
	int i;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_channel", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_channel", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	channel = atoi(nvram_safe_get(prefix));

	if(unit == 1){
		if(channel == 0) ch_pri_inact = 1;
		else ch_pri_inact = 0;
	}
	if(unit == 1){
		for( i = 0 ; i < (int)(sizeof(ch_pri)/sizeof(ch_pri[0])) ; i++){
			qcsapi_wifi_set_chan_pri_inactive(ifname, ch_pri[i], ch_pri_inact);
		}
	}

	ret = qcsapi_wifi_set_channel(ifname, channel);
	if (ret < 0) {
		_dprintf("set_channel %s error, return: %d\n", ifname, ret);
		return ret;
	}
	_dprintf("%s channel as: %d\n", ifname, channel);

	snprintf(str_ch, sizeof(str_ch), "%d", channel);
	ret = qcsapi_config_update_parameter(ifname, "channel", str_ch);
	if (ret < 0) {
		_dprintf("config_update_parameter %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("update wireless_conf.txt %s as: %s\n", ifname, str_ch);

	return 0;
}

int rpc_qcsapi_set_beacon_type(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char *p_new_beacon = NULL;
	char *auth_mode;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_auth_mode_x", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_auth_mode_x", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	auth_mode = nvram_safe_get(prefix);
	
	if (!rpc_qtn_ready())
		return -1;

	if (!strcmp(auth_mode, "open"))
		p_new_beacon = strdup("Basic");
	else if (!strcmp(auth_mode, "psk"))
		p_new_beacon = strdup("WPA");
	else if (!strcmp(auth_mode, "psk2"))
		p_new_beacon = strdup("11i");
	else if (!strcmp(auth_mode, "pskpsk2"))
		p_new_beacon = strdup("WPAand11i");
	else
		p_new_beacon = strdup("Basic");

	ret = qcsapi_wifi_set_beacon_type(ifname, p_new_beacon);
	if (ret < 0) {
		_dprintf("wifi_set_beacon_type %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s beacon type as: %s\n", ifname, p_new_beacon);

	if (p_new_beacon) free(p_new_beacon);

	return 0;
}

int rpc_qcsapi_set_WPA_encryption_modes(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	string_32 encryption_modes;
	char ifname[WIFINAME_MAX_LEN] = {0};
	char *crypto;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_crypto", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_crypto", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	crypto = nvram_safe_get(prefix);

	if (!strcmp(crypto, "tkip"))
		strcpy(encryption_modes, "TKIPEncryption");
	else if (!strcmp(crypto, "aes"))
		strcpy(encryption_modes, "AESEncryption");
	else if (!strcmp(crypto, "tkip+aes"))
		strcpy(encryption_modes, "TKIPandAESEncryption");
	else
		strcpy(encryption_modes, "AESEncryption");

	ret = qcsapi_wifi_set_WPA_encryption_modes(ifname, encryption_modes);
	if (ret < 0) {
		_dprintf("wifi_set_WPA_encryption_modes %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s wpa encryption mode as: %s\n", ifname, encryption_modes);

	return 0;
}

int rpc_qcsapi_set_key_passphrase(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char ifname[WIFINAME_MAX_LEN] = {0};
	char *wpa_psk;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_wpa_psk", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_wpa_psk", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));


	if (!rpc_qtn_ready())
		return -1;

	wpa_psk = nvram_safe_get(prefix);

	ret = qcsapi_wifi_set_key_passphrase(ifname, 0, wpa_psk);
	if (ret < 0) {
		_dprintf("%s set_key_passphrase error[%d]\n", ifname, ret);

		ret = qcsapi_wifi_set_pre_shared_key(ifname, 0, wpa_psk);
		if (ret < 0)
			_dprintf("%s set_pre_shared_key error[%d]\n", ifname, ret);

		return ret;
	}
	_dprintf("%s key passphrase as: %s\n", ifname, wpa_psk);

	return 0;
}

int rpc_qcsapi_set_dtim(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int DTIM;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (!rpc_qtn_ready())
		return -1;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_dtim", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_dtim", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	DTIM = atoi(nvram_safe_get(prefix));

	ret = qcsapi_wifi_set_dtim(ifname, DTIM);
	if (ret < 0) {
		_dprintf("set_dtim %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s dtim as: %d\n", ifname, DTIM);

	return 0;
}

int rpc_qcsapi_set_beacon_interval(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int BCN;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_bcn", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_bcn", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	BCN = atoi(nvram_safe_get(prefix));
	ret = qcsapi_wifi_set_beacon_interval(ifname, BCN);
	if (ret < 0) {
		_dprintf("set_beacon_interval %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s beacon interval as: %d\n", ifname, BCN);

	return 0;
}

void rpc_set_radio(int unit, int subunit)
{
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int ret;
	char interface_status = 0;
	qcsapi_mac_addr wl_macaddr;
	char macbuf[13], macaddr_str[18];
	unsigned long long macvalue;
	unsigned char *macp;
	char ifname[WIFINAME_MAX_LEN] = {0};
	int on;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_radio", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_radio", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	on = nvram_get_int(prefix);
	if (subunit > 0)
	{
		ret = qcsapi_interface_get_status(ifname, &interface_status);
//		if (ret < 0)
//			_dprintf("Qcsapi qcsapi_interface_get_status %s error, return: %d\n", wl_vifname_qtn(unit, subunit), ret);

		if (on)
		{
			if (interface_status){
				_dprintf("vif %s has existed already\n", ifname);
				return;
			}

			memset(&wl_macaddr, 0, sizeof(wl_macaddr));
			ret = qcsapi_interface_get_mac_addr(ifname, (uint8_t *) wl_macaddr);
			if (ret < 0)
				_dprintf("get_mac_addr %s error[%d]\n", ifname, ret);

			sprintf(macbuf, "%02X%02X%02X%02X%02X%02X",
				wl_macaddr[0],
				wl_macaddr[1],
				wl_macaddr[2],
				wl_macaddr[3],
				wl_macaddr[4],
				wl_macaddr[5]);
			macvalue = strtoll(macbuf, (char **) NULL, 16);
			macvalue += subunit;
			macp = (unsigned char*) &macvalue;
			memset(macaddr_str, 0, sizeof(macaddr_str));
			sprintf(macaddr_str, "%02X:%02X:%02X:%02X:%02X:%02X",
				*(macp+5),
				*(macp+4),
				*(macp+3),
				*(macp+2),
				*(macp+1),
				*(macp+0));
			ether_atoe(macaddr_str, wl_macaddr);

			ret = qcsapi_wifi_create_bss(ifname, wl_macaddr);
			if (ret < 0)
			{
				_dprintf("wifi_create_bss %s error[%d]\n", ifname, ret);
				return;
			}

			ret = rpc_qcsapi_set_SSID(unit, subunit);
			if (ret < 0)
				_dprintf("rpc_qcsapi_set_SSID %s error[%d]\n", ifname, ret);

			ret = rpc_qcsapi_set_SSID_broadcast(unit, subunit);
			if (ret < 0)
				_dprintf("rpc_qcsapi_set_SSID_broadcast %s error[%d]\n", ifname, ret);

			ret = rpc_qcsapi_set_beacon_type(unit, subunit);
			if (ret < 0)
				_dprintf("rpc_qcsapi_set_beacon_type %s error[%d]\n",
					ifname, ret);

			ret = rpc_qcsapi_set_WPA_encryption_modes(unit, subunit);
			if (ret < 0)
				_dprintf("set_WPA_encryption_modes %s error[%d]\n",
					ifname, ret);

			ret = rpc_qcsapi_set_key_passphrase(unit, subunit);
			if (ret < 0)
				_dprintf("set_key_passphrase %s error[%d]\n",
					ifname, ret);
		}
		else
		{
			ret = qcsapi_wifi_remove_bss(ifname);
			if (ret < 0)
				_dprintf("wifi_remove_bss %s error[%d]\n", ifname, ret);
		}
	}
	else {
		ret = qcsapi_radio_rfenable(ifname, (qcsapi_unsigned_int) on);
		if (ret < 0)
			_dprintf("wifi_rfenable %s, error[%d]\n", ifname, ret);
	}
}

int rpc_update_ap_isolate(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char tmp[100];
	int isolate;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if(!rpc_qtn_ready())
		return -1;

	isolate = nvram_get_int(strcat_r(prefix, "ap_isolate", tmp));

	qcsapi_radio_rfenable(ifname, (qcsapi_unsigned_int) 0 /* off */);
	ret = qcsapi_wifi_set_ap_isolate(ifname, isolate);
	if(ret < 0){
		_dprintf("set_ap_isolate %s error[%d]\n", ifname, ret);
		return ret;
	}else{
		_dprintf("%s set_ap_isolate OK\n", ifname);
	}
	if(nvram_get_int(strcat_r(prefix, "radio", tmp)) == 1)
		qcsapi_radio_rfenable(ifname, (qcsapi_unsigned_int) 1 /* on */);

	return 0;
}

int rpc_qcsapi_get_mac_address_filtering(const char* ifname, qcsapi_mac_address_filtering *p_mac_address_filtering)
{
	int ret;

	if (!rpc_qtn_ready())
		return -1;

	ret = qcsapi_wifi_get_mac_address_filtering(ifname, p_mac_address_filtering);
	if (ret < 0) {
		_dprintf("get_mac_address_filtering %s error[%d]\n", ifname, ret);
		return ret;
	}

	return 0;
}

int rpc_qcsapi_set_mac_address_filtering(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	qcsapi_mac_address_filtering MAF;
	qcsapi_mac_address_filtering orig_mac_address_filtering;
	char ifname[WIFINAME_MAX_LEN] = {0};
	char *mac_address_filtering;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_macmode", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_macmode", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	ret = rpc_qcsapi_get_mac_address_filtering(ifname, &orig_mac_address_filtering);
	if (ret < 0) {
		_dprintf("get_mac_address_filtering %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s: %d\n", ifname, orig_mac_address_filtering);

	if (!strcmp(mac_address_filtering, "disabled"))
		MAF = qcsapi_disable_mac_address_filtering;
	else if (!strcmp(mac_address_filtering, "deny"))
		MAF = qcsapi_accept_mac_address_unless_denied;
	else if (!strcmp(mac_address_filtering, "allow"))
		MAF = qcsapi_deny_mac_address_unless_authorized;
	else
		MAF = qcsapi_disable_mac_address_filtering;

	ret = qcsapi_wifi_set_mac_address_filtering(ifname, MAF);
	if (ret < 0) {
		_dprintf("set_mac_address_filtering %s error[%d]\n", ifname, ret);
		return ret;
	}
	_dprintf("%s mac filtering as: %d (%s)\n", ifname, MAF, mac_address_filtering);

	if ((MAF != orig_mac_address_filtering) &&
		(MAF != qcsapi_disable_mac_address_filtering))
		rpc_qcsapi_set_wlmaclist(unit, subunit);

	return 0;
}

void rpc_update_macmode(int unit, int subunit)
{
	int ret;
	char tmp[100];
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int i;
	char ifname[WIFINAME_MAX_LEN] = {0};

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return;

	ret = rpc_qcsapi_set_mac_address_filtering(unit, subunit);
	if (ret < 0) {
		_dprintf("set_mac_address_filtering %s error, return: %d\n", ifname, ret);
	}

	if (sw_mode() == SW_MODE_REPEATER && nvram_get_int("wlc_band"))
		return;

	for (i = 1; i < 4; i++)
	{
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);

		if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
		{
			ret = rpc_qcsapi_set_mac_address_filtering(unit, subunit);
			if (ret < 0)
				_dprintf("set_mac_address_filtering %s error[%d]\n", ifname, ret);
		}
	}
}

int rpc_qcsapi_get_denied_mac_addresses(const char *ifname, char *list_mac_addresses, const unsigned int sizeof_list)
{
	int ret;

	if (!rpc_qtn_ready())
		return -1;

	ret = qcsapi_wifi_get_denied_mac_addresses(ifname, list_mac_addresses, sizeof_list);
	if (ret < 0) {
		_dprintf("wifi_get_denied_mac_addresses %s error[%d]\n", ifname, ret);
		return ret;
	}

	return 0;
}

int rpc_qcsapi_deny_mac_address(const char *ifname, const char *macaddr)
{
	int ret;
	qcsapi_mac_addr address_to_deny;

	if (!rpc_qtn_ready())
		return -1;

	ether_atoe(macaddr, address_to_deny);
	ret = qcsapi_wifi_deny_mac_address(ifname, address_to_deny);
	if (ret < 0) {
		_dprintf("wifi_deny_mac_address %s error[%d]\n", ifname, ret);
		return ret;
	}
//	_dprintf("deny MAC addresss of interface %s: %s\n", ifname, macaddr);

	return 0;
}

int rpc_qcsapi_authorize_mac_address(const char *ifname, const char *macaddr)
{
	int ret;
	qcsapi_mac_addr address_to_authorize;

	if (!rpc_qtn_ready())
		return -1;

	ether_atoe(macaddr, address_to_authorize);
	ret = qcsapi_wifi_authorize_mac_address(ifname, address_to_authorize);
	if (ret < 0) {
		_dprintf("authorize_mac_address %s error[%d]\n", ifname, ret);
		return ret;
	}
//	_dprintf("authorize MAC addresss of interface %s: %s\n", ifname, macaddr);

	return 0;
}

int rpc_qcsapi_get_authorized_mac_addresses(const char *ifname, char *list_mac_addresses, const unsigned int sizeof_list)
{
	int ret;

	if (!rpc_qtn_ready())
		return -1;

	ret = qcsapi_wifi_get_authorized_mac_addresses(ifname, list_mac_addresses, sizeof_list);
	if (ret < 0) {
		_dprintf("get_authorized_mac_addresses %s error[%d]\n", ifname, ret);
		return ret;
	}

	return 0;
}

int rpc_qcsapi_set_wlmaclist(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	qcsapi_mac_address_filtering mac_address_filtering;
	char list_mac_addresses[1024];
	char *m = NULL;
	char *p, *pp;
	char ifname[WIFINAME_MAX_LEN] = {0};

	snprintf(prefix, sizeof(prefix), "wl%d_maclist_x", unit);
	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	ret = rpc_qcsapi_get_mac_address_filtering(ifname, &mac_address_filtering);
	if (ret < 0)
	{
		_dprintf("get_mac_address_filtering %s error[%d]\n", ifname, ret);
		return ret;
	}
	else
	{
		if (mac_address_filtering == qcsapi_accept_mac_address_unless_denied)
		{
			ret = qcsapi_wifi_clear_mac_address_filters(ifname);
			if (ret < 0)
			{
				_dprintf("clear_mac_address_filters %s, error[%d]\n", ifname, ret);
				return ret;
			}

			pp = p = strdup(nvram_safe_get(prefix));
			if (pp) {
				while ((m = strsep(&p, "<")) != NULL) {
					if (!strlen(m)) continue;
					ret = rpc_qcsapi_deny_mac_address(ifname, m);
					if (ret < 0)
						_dprintf("rpc_qcsapi_deny_mac_address %s error[%d]\n", ifname, ret);
				}
				free(pp);
			}

			ret = rpc_qcsapi_get_denied_mac_addresses(ifname, list_mac_addresses, sizeof(list_mac_addresses));
			if (ret < 0)
				_dprintf("get_denied_mac_addresses %s error, return: %d\n", ifname, ret);
			else
				_dprintf("current denied MAC addresses of interface %s: %s\n", ifname, list_mac_addresses);
		}
		else if (mac_address_filtering == qcsapi_deny_mac_address_unless_authorized)
		{
			ret = qcsapi_wifi_clear_mac_address_filters(ifname);
			if (ret < 0)
			{
				_dprintf("Qcsapi qcsapi_wifi_clear_mac_address_filters %s error, return: %d\n", ifname, ret);
				return ret;
			}

			pp = p = strdup(nvram_safe_get(prefix));
			if (pp) {
				while ((m = strsep(&p, "<")) != NULL) {
					if (!strlen(m)) continue;
					ret = rpc_qcsapi_authorize_mac_address(ifname, m);
					if (ret < 0)
						_dprintf("rpc_qcsapi_authorize_mac_address %s error, return: %d\n", ifname, ret);
				}
				free(pp);
			}

			ret = rpc_qcsapi_get_authorized_mac_addresses(ifname, list_mac_addresses, sizeof(list_mac_addresses));
			if (ret < 0)
				_dprintf("get_authorized_mac_addresses %s error, return: %d\n", ifname, ret);
			else
				_dprintf("current authorized MAC addresses of interface %s: %s\n", ifname, list_mac_addresses);
		}
	}

	return ret;
}

void rpc_update_wlmaclist(int unit, int subunit)
{
	int ret;
	char tmp[100];
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int i;
	char ifname[WIFINAME_MAX_LEN] = {0};

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return;

	ret = rpc_qcsapi_set_wlmaclist(unit, subunit);
	if (ret < 0)
		_dprintf("set_wlmaclist %s error, return: %d\n", ifname, ret);

	if (sw_mode() == SW_MODE_REPEATER &&
			nvram_get_int("wlc_band"))
                return;

	for (i = 1; i < 4; i++)
	{
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, i);

		if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
		{
			ret = rpc_qcsapi_set_wlmaclist(unit, i);
			if (ret < 0)
				_dprintf("set_wlmaclist %s error, return: %d\n", ifname, ret);
		}
	}
}

int rpc_qcsapi_wds_set_psk(const char *ifname, const char *macaddr, const char *wpa_psk)
{
	int ret;
	qcsapi_mac_addr peer_address;

	if (!rpc_qtn_ready())
		return -1;

	ether_atoe(macaddr, peer_address);
	ret = qcsapi_wds_set_psk(ifname, peer_address, wpa_psk);
	if (ret < 0) {
		_dprintf("wds_set_psk %s error, return: %d\n", ifname, ret);
		return ret;
	}
	_dprintf("remove WDS Peer of interface %s: %s\n", ifname, macaddr);

	return 0;
}

void rpc_update_wdslist(int unit, int subunit)
{
	int ret, i;
	char tmp[100];
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	qcsapi_mac_addr peer_address;
	char *m = NULL;
	char *p, *pp;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return;

	for (i = 0; i < 8; i++)
	{
		ret = qcsapi_wds_get_peer_address(ifname, 0, (uint8_t *) &peer_address);
		if (ret < 0){
			if (ret == -19) break;	// No such device
			_dprintf("wds_get_peer_address %s error[%d]\n", ifname, ret);
		}else{
//			_dprintf("current WDS peer index 0 addresse: %s\n", wl_ether_etoa((struct ether_addr *) &peer_address));
			ret = qcsapi_wds_remove_peer(ifname, peer_address);
			if (ret < 0)
				_dprintf("wds_remove_peer %s error, return: %d\n", ifname, ret);
		}
	}

	if (nvram_match(strcat_r(prefix, "mode_x", tmp), "0"))
		return;

	pp = p = strdup(nvram_safe_get(strcat_r(prefix, "wdslist", tmp)));
	if (pp) {
		while ((m = strsep(&p, "<")) != NULL) {
			if (!strlen(m)) continue;

			ether_atoe(m, peer_address);
			ret = qcsapi_wds_add_peer(ifname, peer_address);
			if (ret < 0)
				_dprintf("wds_add_peer %s error, return: %d\n", ifname, ret);
			else{
				ret = rpc_qcsapi_wds_set_psk(ifname, m,
							nvram_safe_get(strcat_r(prefix, "wds_psk", tmp)));
				if (ret < 0)
					_dprintf("wds_set_psk %s error, return: %d\n", ifname, ret);
			}
		}
		free(pp);
	}

	for (i = 0; i < 8; i++)
	{
		ret = qcsapi_wds_get_peer_address(ifname, i, (uint8_t *) &peer_address);
		if (ret < 0){
			if (ret == -19) break;	// No such device
			_dprintf("get_peer_address %s error, return: %d\n", ifname, ret);
		}else
			_dprintf("current WDS peer index 0 addresse: %s\n", wl_ether_etoa((struct ether_addr *) &peer_address));
	}
}


void rpc_update_wds_psk(int unit, int subunit)
{
	int ret, i;
	char tmp[100] = {0};
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	qcsapi_mac_addr peer_address;
	char *wds_psk;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return;

	if (nvram_match(strcat_r(prefix, "mode_x", tmp), "0"))
		return;

	wds_psk = nvram_safe_get(strcat_r(prefix, "wds_psk", tmp));

	for (i = 0; i < 8; i++)
	{
		ret = qcsapi_wds_get_peer_address(ifname, i, (uint8_t *) &peer_address);
		if (ret < 0){
			if (ret == -19) break;	// No such device
			_dprintf("get_peer_address %s error, return: %d\n", ifname, ret);
		}else{
//			_dprintf("current WDS peer index 0 addresse: %s\n", wl_ether_etoa((struct ether_addr *) &peer_address));
			ret = rpc_qcsapi_wds_set_psk(ifname, wl_ether_etoa((struct ether_addr *) &peer_address), wds_psk);
			if (ret < 0)
				_dprintf("wds_set_psk %s error, return: %d\n", ifname, ret);
		}
	}
}

int rpc_qcsapi_wifi_disable_wps(int unit, int subunit)
{
	int ret;
	char ifname[WIFINAME_MAX_LEN] = {0};
	int disable_wps = 1 - nvram_get_int("wps_enable");

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	ret = qcsapi_wifi_disable_wps(ifname, disable_wps);
	if (ret < 0) {
		_dprintf("disable_wps[%d] %s error[%d]\n", disable_wps, ifname, ret);
		return ret;
	}

	if(disable_wps == 0){
		ret = qcsapi_wps_set_ap_pin(ifname, nvram_safe_get("wps_device_pin"));
		if (ret < 0)
			_dprintf("wps_set_ap_pin %s error[%d]\n", ifname, ret);

		ret = qcsapi_wps_registrar_set_pp_devname(ifname, 0, (const char *) get_productid());
		if (ret < 0)
			_dprintf("wps_registrar_set_pp_devname %s error[%d]\n", ifname, ret);

	}
	return 0;
}

int wifi_enable_mumimo_qtn(int unit, int subunit)
{
	int ret;
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char ifname[WIFINAME_MAX_LEN] = {0};
	int enable_mu = 0;

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_mumimo", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_mumimo", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return -1;

	enable_mu = nvram_get_int(prefix);

	ret = qcsapi_wifi_set_enable_mu(ifname, enable_mu);
	_dprintf("%s set mu-mimo[%d]\n", ifname, enable_mu);

	if (ret < 0)
		_dprintf("%s set mu-mimo[%d], error[%s]\n", ifname, enable_mu, ret);
	return 0;
}

#define SET_SSID	0x01
#define SET_CLOSED	0x02
#define SET_AUTH	0x04
#define	SET_CRYPTO	0x08
#define	SET_WPAPSK	0x10
#define	SET_MACMODE	0x20
#define SET_ALL		0x3F

static void rpc_reload_mbss(int unit, int subunit)
{
	char tmp[100];
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	unsigned char set_type = 0;
	int ret;
	char *auth_mode;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (!rpc_qtn_ready())
		return;

#if 0 
	if (!strcmp(name_mbss, "ssid"))
		set_type = SET_SSID;
	else if (!strcmp(name_mbss, "closed"))
		set_type = SET_CLOSED;
	else if (!strcmp(name_mbss, "auth_mode_x"))
		set_type = SET_AUTH;
	else if (!strcmp(name_mbss, "crypto"))
		set_type = SET_CRYPTO;
	else if (!strcmp(name_mbss, "wpa_psk"))
		set_type = SET_WPAPSK;
	else if (!strcmp(name_mbss, "macmode"))
		set_type = SET_MACMODE;
	else if (!strcmp(name_mbss, "all"))
		set_type = SET_ALL;
#else
	set_type = SET_ALL;
#endif

	if (set_type & SET_SSID)
	{
		ret = rpc_qcsapi_set_SSID(unit, subunit);
		if (ret < 0)
			_dprintf("rpc_qcsapi_set_SSID %s error[%d]\n",
				ifname, ret);
	}

	if (set_type & SET_CLOSED)
	{
		ret = rpc_qcsapi_set_SSID_broadcast(unit, subunit);
		if (ret < 0)
			_dprintf("rpc_qcsapi_set_SSID_broadcast %s error[%d]\n",
				ifname, ret);
	}

	if (set_type & SET_AUTH)
	{
		ret = rpc_qcsapi_set_beacon_type(unit, subunit);
		if (ret < 0)
			_dprintf("rpc_qcsapi_set_beacon_type %s error[%d]\n",
				ifname, ret);
	}

	if (set_type & SET_CRYPTO)
	{
		auth_mode = nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp));
		if (!strcmp(auth_mode, "psk")  ||
		    !strcmp(auth_mode, "psk2") ||
		    !strcmp(auth_mode, "pskpsk2"))
		{
			ret = rpc_qcsapi_set_WPA_encryption_modes(unit, subunit);
			if (ret < 0)
				_dprintf("rpc_qcsapi_set_WPA_encryption_modes %s error[%d]\n",
					ifname, ret);
		}
	}

	if (set_type & SET_WPAPSK)
	{
		auth_mode = nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp));
		if (!strcmp(auth_mode, "psk")  ||
		    !strcmp(auth_mode, "psk2") ||
		    !strcmp(auth_mode, "pskpsk2"))
		{
			ret = rpc_qcsapi_set_key_passphrase(unit, subunit);
			if (ret < 0)
				_dprintf("set_key_passphrase %s error[%d]\n",
					ifname, ret);
		}
	}

	if (set_type & SET_MACMODE)
	{
		ret = rpc_qcsapi_set_mac_address_filtering(unit, subunit);
		if (ret < 0)
		{
			_dprintf("set_mac_address_filtering %s error[%d]\n",
				ifname, ret);

			return;
		}
		else
			rpc_qcsapi_set_wlmaclist(unit, subunit);
	}
}

// void rpc_update_mbss(const char* name, const char *value)
void rpc_update_mbss(int unit, int subunit)
{
	int ret;
	char tmp[100];
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	char interface_status = 0;
	qcsapi_mac_addr wl_macaddr;
	char macbuf[13], macaddr_str[18];
	unsigned long long macvalue;
	unsigned char *macp;
	char ifname[WIFINAME_MAX_LEN] = {0};
	char ifname_main[WIFINAME_MAX_LEN] = {0};
	char script_cmd[30] = "router_command.sh";
	char script_arg[30] = "";

	if (subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));
	snprintf(ifname_main, sizeof(ifname_main), "%s", wl_vifname_qtn(unit, -1));

	if (sw_mode() == SW_MODE_REPEATER &&
		nvram_get_int("wlc_band"))
		return;

	if (!rpc_qtn_ready())
		return;

	// if(nvram_get_int("wl1.1_bss_enabled") == 1){
	if(nvram_get_int(strcat_r(prefix, "bss_enabled", tmp)) == 0){
		qcsapi_wifi_remove_bss(ifname);
		_dprintf("removing vif %s \n", ifname);
		return;
	}
#if 0
	/* wl1.1_wpa_psk: unit=1, subunit=1, name_mbss=wpa_psk */
	if (sscanf(name, "wl%d.%d_%s", &unit, &subunit, name_mbss) != 3)
		return;
#endif

	if ((subunit < 1) || (subunit > 3))
		return;

	ret = qcsapi_interface_get_status(ifname, &interface_status);
//	if (ret < 0)
//		_dprintf("qcsapi_interface_get_status %s error, return: %d\n", wl_vifname_qtn(unit, subunit), ret);

	if (interface_status){
		_dprintf("vif %s has existed already\n", ifname);
	}else{
		memset(&wl_macaddr, 0, sizeof(wl_macaddr));
		ret = qcsapi_interface_get_mac_addr(ifname, (uint8_t *) wl_macaddr);
		if (ret < 0)
			_dprintf("interface_get_mac_addr %s error[%d]\n", ifname, ret);
	
		sprintf(macbuf, "%02X%02X%02X%02X%02X%02X",
			wl_macaddr[0], wl_macaddr[1], wl_macaddr[2],
				wl_macaddr[3], wl_macaddr[4], wl_macaddr[5]);
			macvalue = strtoll(macbuf, (char **) NULL, 16);
			macvalue += subunit;
			macp = (unsigned char*) &macvalue;
			memset(macaddr_str, 0, sizeof(macaddr_str));
			sprintf(macaddr_str, "%02X:%02X:%02X:%02X:%02X:%02X",
				*(macp+5), *(macp+4), *(macp+3),
				*(macp+2), *(macp+1), *(macp+0));
			ether_atoe(macaddr_str, wl_macaddr);

		ret = qcsapi_wifi_create_bss(ifname, wl_macaddr);
		if (ret < 0){
			_dprintf("create_bss %s error[%d]\n", ifname, ret);
			return;
		}else{
			_dprintf("create_bss %s successfully\n", ifname);
		}
	}
	rpc_reload_mbss(unit, subunit);

	if(sw_mode() == SW_MODE_ROUTER){
		if(nvram_match(strcat_r(prefix, "lanaccess", tmp), "off")){
			_dprintf("[lanaccess] [%s] lanaccess off\n", ifname);
			// libqcsapi_client/qtn/qtn_vlan.h
			// QVLAN_VID_ALL: 0xffff
			qcsapi_wifi_vlan_config(ifname_main, e_qcsapi_vlan_enable, 0xffff /* QVLAN_VID_ALL */);
			qcsapi_wifi_vlan_config(ifname, e_qcsapi_vlan_add, 4000 + unit + subunit /* vid */);
		}else{
			qcsapi_wifi_vlan_config(ifname, e_qcsapi_vlan_del, 4000 + unit + subunit /* vid */);
		}
	}
#ifdef RTCONFIG_IPV6
	if (get_ipv6_service() == IPV6_DISABLED){
		snprintf(script_arg, sizeof(script_arg), "ipv6_off %s", ifname);
		qcsapi_wifi_run_script(script_cmd, script_arg);
	}else{
		snprintf(script_arg, sizeof(script_arg), "ipv6_on %s", ifname);
		qcsapi_wifi_run_script(script_cmd, script_arg);
	}
#endif
}

/* #565: Access Intranet off */
void create_mbssid_vlan(void)
{
	return;
}

void rpc_parse_nvram_from_httpd(int unit, int subunit)
{
	char ifname[WIFINAME_MAX_LEN] = {0};

	if (!rpc_qtn_ready())
		return;

	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_qtn(unit, subunit));

	if (subunit == -1){
_dprintf("[%s] test 1. unit=%d, subunit=%d.\n", __func__, unit, subunit);
		rpc_qcsapi_set_SSID(unit, subunit);
		rpc_qcsapi_set_SSID_broadcast(unit, subunit);
		rpc_qcsapi_set_vht(unit, subunit);
#if 1	/* workaround */
		rpc_qcsapi_set_bw(unit, subunit);
		rpc_qcsapi_set_channel(unit, subunit);
		rpc_qcsapi_set_beacon_type(unit, subunit);
		rpc_qcsapi_set_WPA_encryption_modes(unit, subunit);
		rpc_qcsapi_set_key_passphrase(unit, subunit);
		rpc_qcsapi_set_dtim(unit, subunit);
		rpc_qcsapi_set_beacon_interval(unit, subunit);
		rpc_set_radio(unit, subunit);
#if 0
		rpc_qcsapi_set_bw(unit, subunit);
		// rpc_qcsapi_set_channel(unit, subunit);
		rpc_qcsapi_set_beacon_type(unit, subunit);
		rpc_qcsapi_set_WPA_encryption_modes(unit, subunit);
		rpc_qcsapi_set_key_passphrase(unit, subunit);
		rpc_qcsapi_set_dtim(unit, subunit);
		rpc_qcsapi_set_beacon_interval(unit, subunit);
		rpc_set_radio(unit, subunit);
#endif
#if 0
		rpc_update_macmode(unit, subunit);
		rpc_update_wlmaclist(unit, subunit);
		rpc_update_wdslist(unit, subunit);
		/* workaround ?? */
		rpc_update_wdslist(unit, subunit);
		rpc_update_wds_psk(unit, subunit);
		rpc_update_ap_isolate(unit, subunit);
		ret = rpc_qcsapi_wifi_disable_wps(unit, subunit);
		if(sw_mode() == SW_MODE_ROUTER ||
			(sw_mode() == SW_MODE_AP &&
			nvram_get_int("wlc_psta") == 1)){
			wifi_enable_mumimo_qtn(unit, subunit);
		}
#endif
#ifdef RTCONFIG_IPV6
		if (get_ipv6_service() == IPV6_DISABLED)
			qcsapi_wifi_run_script("router_command.sh", "ipv6_off wifi0_0");
		else
			qcsapi_wifi_run_script("router_command.sh", "ipv6_on wifi0_0");
#endif
#endif
	}else if (subunit == 1 || subunit == 2 || subunit == 3){
		// rpc_update_mbss(unit, subunit);
	}else{
		_dprintf("no such wifi interface:[%d][%d]\n", unit, subunit);
	}
	if(sw_mode() == SW_MODE_ROUTER){
		// create_mbssid_vlan();
	}

//	rpc_show_config();
}

#if defined(RTCONFIG_JFFS2ND_BACKUP)
#define JFFS_NAME	"jffs2"
#define SECOND_JFFS2_PARTITION  "asus"
#define SECOND_JFFS2_PATH	"/asus_jffs"
void check_2nd_jffs(void)
{
	char s[256];
	int size;
	int part;
	struct statfs sf;

	_dprintf("2nd jffs2: %s\n", SECOND_JFFS2_PARTITION);

	if (!mtd_getinfo(SECOND_JFFS2_PARTITION, &part, &size)) {
		_dprintf("Can not get 2nd jffs2 information!");
		return;
	}
	mount_2nd_jffs2();

	if(access("/asus_jffs/bootcfg.tgz", R_OK ) != -1 ) {
		logmessage("qtn", "bootcfg.tgz exists");
		system("rm -f /tmp/bootcfg.tgz");
	} else {
		logmessage("qtn", "bootcfg.tgz does not exist");
		snprintf(s, sizeof(s), MTD_BLKDEV(%d), part);
		umount("/asus_jffs");
		if (mount(s, SECOND_JFFS2_PATH , JFFS_NAME, MS_NOATIME, "") != 0) {
			logmessage("qtn", "cannot store bootcfg.tgz");
		}else{
			system("cp /tmp/bootcfg.tgz /asus_jffs");
			system("rm -f /tmp/bootcfg.tgz");
			logmessage("qtn", "backup bootcfg.tgz ok");
		}
	}

	if (umount(SECOND_JFFS2_PATH)){
		_dprintf("umount asus_jffs failed\n");
	}else{
		_dprintf("umount asus_jffs ok\n");
	}

	// format_mount_2nd_jffs2();
}
#endif
#ifdef RTCONFIG_QSR10G
int start_qsr10g(void)
{
	system("cd /lib/firmware; insmod qsr10g-pcie.ko");
	return 0;
}

#endif
#define	MAX_RETRY_TIMES	30
#define	MAX_TOTAL_TIME	120
int test_qcsapi(void)
{
	// const char *host;
	char host[18];
	CLIENT *clnt;
	int retry = 0;
	time_t start_time = uptime();

	/* pcie */
	snprintf(host, sizeof(host), "localhost");

	/* setup RPC based on udp protocol */
	do {
		if (1)
			_dprintf("[%s][%d] #%d attempt to create RPC connection\n",
						__func__, __LINE__, retry + 1);

		clnt = clnt_pci_create(host, QCSAPI_PROG, QCSAPI_VERS, NULL);

		if (clnt == NULL) {
			_dprintf("[%s][%d] clnt_pci_create() error\n", __func__, __LINE__);
			clnt_pcreateerror(host);
			sleep(1);
			continue;
		} else {
			_dprintf("[%s][%d] clnt_pci_create() OK, set_rpcclient()\n", __func__, __LINE__);
			client_qcsapi_set_rpcclient(clnt);
			break;
		}
	} while ((retry++ < MAX_RETRY_TIMES) && ((uptime() - start_time) < MAX_TOTAL_TIME));

	//clnt_destroy(clnt);

	return -1;
}

int rpc_qcsapi_init(int verbose)
{
	// const char *host;
	char host[18];
	CLIENT *clnt;
	int retry = 0;
	time_t start_time = uptime();

	/* pcie */
	snprintf(host, sizeof(host), "localhost");

	/* setup RPC based on udp protocol */
	do {
		if (verbose)
			_dprintf("#%d attempt to create RPC connection\n", retry + 1);

		clnt = clnt_pci_create(host, QCSAPI_PROG, QCSAPI_VERS, NULL);

		if (clnt == NULL) {
			_dprintf("clnt_pci_create() error\n");
			clnt_pcreateerror(host);
			sleep(1);
			continue;
		} else {
			_dprintf("clnt_pci_create() OK, set_rpcclient()\n");
			client_qcsapi_set_rpcclient(clnt);
#if 0	/* remove */
			qtn_qcsapi_init = 1;
#endif
			return 0;
		}
	} while ((retry++ < MAX_RETRY_TIMES) && ((uptime() - start_time) < MAX_TOTAL_TIME));

	// clnt_destroy(clnt);

	return -1;
}

int rpc_qtn_ready()
{
#if 0
	int ret, qtn_ready;
	int lock;

	qtn_ready = nvram_get_int("qtn_ready");

	lock = file_lock("qtn");

	if (qtn_ready && !qtn_init)
	{
		ret = rpc_qcsapi_init(0);
		if (ret < 0){
			qtn_ready = 0;
			_dprintf("rpc_qcsapi_init error, return: %d\n", ret);
		}else
		{
			ret = qcsapi_init();
			if (ret < 0){
				qtn_ready = 0;
				_dprintf("Qcsapi qcsapi_init error, return: %d\n", ret);
			}else
				qtn_init = 1;
		}
	}

	file_unlock(lock);

	nvram_set("wl1_country_code", nvram_safe_get("1:ccode"));
	return qtn_ready;
#else
	return 1;
#endif
}

int start_ate_mode_qsr10g(void)
{
	system("qcsapi_pcie update_bootcfg_param calstate 1");
	system("qcsapi_pcie set_GPIO_config 1 2");
	system("qcsapi_pcie set_GPIO_config 13 2");
	system("qcsapi_pcie update_bootcfg_param calstate 3");
	system("qcsapi_pcie commit_bootcfg");

	return 0;
}

#if 1
int qtn_monitor_main(void)
{
	int retval = 0;
	char host[18];
	CLIENT *clnt;
	time_t start_time = uptime();
	int retry = 0;

	/* pcie */
	snprintf(host, sizeof(host), "localhost");
	if (nvram_match("Ate_power_on_off_enable", "1")) {
		return 1;
	}

	/* setup RPC based on udp protocol */
	do {
		if (1)
			_dprintf("[%s][%d] #%d attempt to create RPC connection\n",
						__func__, __LINE__, retry + 1);

		clnt = clnt_pci_create(host, QCSAPI_PROG, QCSAPI_VERS, NULL);

		if (clnt == NULL) {
			_dprintf("[%s][%d] clnt_pci_create() error\n", __func__, __LINE__);
			clnt_pcreateerror(host);
			sleep(1);
			continue;
		} else {
			_dprintf("[%s][%d] clnt_pci_create() OK, set_rpcclient()\n", __func__, __LINE__);
			client_qcsapi_set_rpcclient(clnt);
			break;
		}
	} while ((retry++ < MAX_RETRY_TIMES) && ((uptime() - start_time) < MAX_TOTAL_TIME));

	// _dprintf("[QTN] update router_command.sh from brcm to qtn\n");
	// qcsapi_wifi_run_script("set_test_mode", "update_router_command");

#if 1	/* STATELESS */
	if(sw_mode() == SW_MODE_AP &&
		nvram_get_int("wlc_psta") == 1){
		_dprintf("[sw_mode] start_psta_qtn...\n");
		start_psta_qtn();
		system("ifconfig eth1 down");
	}else{
		_dprintf("[%s][%d] call rpc_parse_nvram_from_httpd\n", __func__, __LINE__);
		rpc_parse_nvram_from_httpd(0,-1);	/* wifi2_0 */
_dprintf("[%s] test 1.\n", __func__);
		rpc_parse_nvram_from_httpd(0,1);	/* wifi2_1 */
_dprintf("[%s] test 2.\n", __func__);
		rpc_parse_nvram_from_httpd(0,2);	/* wifi2_2 */
_dprintf("[%s] test 3.\n", __func__);
		rpc_parse_nvram_from_httpd(0,3);	/* wifi2_3 */
_dprintf("[%s] test 4.\n", __func__);
		rpc_parse_nvram_from_httpd(1,-1);	/* wifi0_0 */
_dprintf("[%s] test 5.\n", __func__);
		rpc_parse_nvram_from_httpd(1,1);	/* wifi0_1 */
_dprintf("[%s] test 6.\n", __func__);
		rpc_parse_nvram_from_httpd(1,2);	/* wifi0_2 */
_dprintf("[%s] test 7.\n", __func__);
		rpc_parse_nvram_from_httpd(1,3);	/* wifi0_3 */
		_dprintf("[sw_mode] skip start_ap_qtn, QTN will run scripts automatically\n");
#ifndef RTCONFIG_QSR10G
		// start_ap_qtn();
		qcsapi_mac_addr wl_mac_addr;
		ret = rpc_qcsapi_interface_get_mac_addr(WIFINAME, &wl_mac_addr);
		if (ret < 0)
			_dprintf("rpc_qcsapi_interface_get_mac_addr, return: %d\n", ret);
		else{
			nvram_set("1:macaddr", wl_ether_etoa((struct ether_addr *) &wl_mac_addr));
			nvram_set("wl1_hwaddr", wl_ether_etoa((struct ether_addr *) &wl_mac_addr));
		}

		rpc_update_wdslist();

		if(nvram_get_int("wps_enable") == 1){
			ret = rpc_qcsapi_wifi_disable_wps(WIFINAME, 0);
			if (ret < 0)
				_dprintf("disable_wps %s error[%d]\n", WIFINAME, ret);

			ret = qcsapi_wps_set_ap_pin(WIFINAME, nvram_safe_get("wps_device_pin"));
			if (ret < 0)
				_dprintf("qcsapi_wps_set_ap_pin %s error[%d]\n", WIFINAME, ret);

			ret = qcsapi_wps_registrar_set_pp_devname(WIFINAME, 0, (const char *) get_productid());
			if (ret < 0)
				_dprintf("qcsapi_wps_registrar_set_pp_devname %s error[%d]\n", WIFINAME, ret);
		}else{
			ret = rpc_qcsapi_wifi_disable_wps(WIFINAME, 1);
			if (ret < 0)
				_dprintf("rpc_qcsapi_wifi_disable_wps %s error, return: %d\n", WIFINAME, ret);
		}

		rpc_set_radio(1, 0, nvram_get_int("wl1_radio"));
#endif	/* not RTCONFIG_QSR10G */
	}
#endif

#ifndef RTCONFIG_QSR10G
	if(nvram_get_int("wl1_80211h") == 1){
		_dprintf("[80211h] set_80211h_on\n");
		qcsapi_wifi_run_script("router_command.sh", "80211h_on");
	}else{
		_dprintf("[80211h] set_80211h_off\n");
		qcsapi_wifi_run_script("router_command.sh", "80211h_off");
	}

	if(sw_mode() == SW_MODE_ROUTER ||
		(sw_mode() == SW_MODE_AP &&
			nvram_get_int("wlc_psta") == 0)){
		if(nvram_get_int("wl1_chanspec") == 0){
			if (nvram_match("1:ccode", "EU")){
				if(nvram_get_int("acs_dfs") != 1){
					_dprintf("[dfs] start nodfs scanning and selection\n");
					start_nodfs_scan_qtn();
				}
			}else{
				/* all country except EU */
				_dprintf("[dfs] start nodfs scanning and selection\n");
				start_nodfs_scan_qtn();
			}
		}
	}
	if(sw_mode() == SW_MODE_AP &&
		nvram_get_int("wlc_psta") == 1 &&
		nvram_get_int("wlc_band") == 0){
		ret = qcsapi_wifi_reload_in_mode(WIFINAME, qcsapi_station);
		if (ret < 0)
			_dprintf("qtn reload_in_mode STA fail\n");
	}
	if(nvram_get_int("QTNTELNETSRV") == 1 && sw_mode() == SW_MODE_ROUTER){
		_dprintf("[QTN] enable telnet server\n");
		qcsapi_wifi_run_script("router_command.sh", "enable_telnet_srv 1");
	}

	_dprintf("[dbg] qtn_monitor startup\n");
#endif	/* not RTCONFIG_QSR10G */

	_dprintf("Raymond: [%s][%d] \n", __func__, __LINE__);
	remove("/var/run/qtn_monitor.pid");

	// clnt_destroy(clnt);

	_dprintf("[%s][%d] end of qtn_monitor_main()\n", __func__, __LINE__);

	if(nvram_get_int(ATE_FACTORY_MODE_STR()) == 1 /* calibration */){
		sleep(1);
		eval("qcsapi_pcie", "set_ip", "br0", "ipaddr", "1.1.1.2", "netmask", "255.255.255.0");
		sleep(1);
	}else if(nvram_get_int(ATE_FACTORY_MODE_STR()) == 2 /* debug */){
		sleep(1);
		eval("qcsapi_pcie", "set_ip", "br0", "ipaddr", "192.168.1.200", "netmask", "255.255.255.0");
		sleep(1);
	}else{	/* normal */
		sleep(1);
		eval("qcsapi_pcie", "set_ip", "br0", "ipaddr", "0.0.0.0", "netmask", "255.255.255.0");
		sleep(1);
	}

	return retval;
}
#endif
