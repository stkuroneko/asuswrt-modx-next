/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <rc.h>
#ifdef RTCONFIG_ALPINE
#include <inttypes.h>	/* PRIx64 */
#include <stdio.h>
#include <fcntl.h>		//      for restore175C() from Ralink src
#include <alpine.h>
#include <asm/byteorder.h>
#include <bcmnvram.h>
//#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <mtd/ubi-user.h>
#include <dirent.h>
#include <sys/mount.h>
#include <net/if.h>
#include <linux/mii.h>
//#include <linux/if.h>
#include <iwlib.h>
//#include <wps.h>
//#include <stapriv.h>
#include <shared.h>
#include "flash_mtd.h"
#include "ate.h"
#include <mtd/mtd-user.h>
#include <mtd/jffs2-user.h>

#define MAX_FRW 64
#define MACSIZE 12

#define	DEFAULT_SSID_2G	"ASUS"
#define	DEFAULT_SSID_5G	"ASUS_5G"

#define RTKSWITCH_DEV  "/dev/rtkswitch"

#define LED_CONTROL(led, flag) ralink_gpio_write_bit(led, flag)

#ifdef RTCONFIG_WIRELESSREPEATER
char *wlc_nvname(char *keyword);
#endif

#if defined(RTCONFIG_ALPINE)
#define VHT_SUPPORT		/* 11AC */
#endif

int g_wsc_configured = 0;
int g_isEnrollee[MAX_NR_WL_IF] = { 0, };

int getCountryRegion5G(const char *countryCode, int *warning);

char *get_wscd_pidfile(void)
{
	static char tmpstr[32] = "/var/run/wscd.pid.";
	char wif[8];

	__get_wlifname(nvram_get_int("wps_band_x"), 0, wif);
	sprintf(tmpstr, "/var/run/wscd.pid.%s", wif);
	return tmpstr;
}

char *get_wscd_pidfile_band(int wps_band)
{
	static char tmpstr[32] = "/var/run/wscd.pid.";
	char wif[8];

	__get_wlifname(wps_band, 0, wif);
	sprintf(tmpstr, "/var/run/wscd.pid.%s", wif);
	return tmpstr;
}

int get_wifname_num(char *name)
{
	if (strcmp(WIF_5G, name) == 0)
		return 1;
	else if (strcmp(WIF_2G, name) == 0)
		return 0;
	else
		return -1;
}

const char *get_wifname(int band)
{
	if (band)
		return WIF_5G;
	else
		return WIF_2G;
}

const char *get_wpsifname(void)
{
	int wps_band = nvram_get_int("wps_band_x");

	if (wps_band)
		return WIF_5G;
	else
		return WIF_2G;
}

#if 0
char *get_non_wpsifname()
{
	int wps_band = nvram_get_int("wps_band_x");

	if (wps_band)
		return WIF_2G;
	else
		return WIF_5G;
}
#endif

static unsigned char nibble_hex(char *c)
{
	int val;
	char tmpstr[3];

	tmpstr[2] = '\0';
	memcpy(tmpstr, c, 2);
	val = strtoul(tmpstr, NULL, 16);
	return val;
}

static int atoh(const char *a, unsigned char *e)
{
	char *c = (char *)a;
	int i = 0;

	memset(e, 0, MAX_FRW);
	for (i = 0; i < MAX_FRW; ++i, c += 3) {
		if (!isxdigit(*c) || !isxdigit(*(c + 1)) || isxdigit(*(c + 2)))	// should be "AA:BB:CC:DD:..."
			break;
		e[i] = (unsigned char)nibble_hex(c);
	}

	return i;
}

char *htoa(const unsigned char *e, char *a, int len)
{
	char *c = a;
	int i;

	for (i = 0; i < len; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", e[i] & 0xff);
	}
	return a;
}

int FREAD(unsigned int addr_sa, int len)
{
	unsigned char buffer[MAX_FRW];
	char buffer_h[128];
	memset(buffer, 0, sizeof(buffer));
	memset(buffer_h, 0, sizeof(buffer_h));

	if (FRead(buffer, addr_sa, len) < 0)
		dbg("FREAD: Out of scope\n");
	else {
		if (len > MAX_FRW)
			len = MAX_FRW;
		htoa(buffer, buffer_h, len);
		puts(buffer_h);
	}
	return 0;
}

/*
 * 	write str_hex to offset da
 *	console input:	FWRITE 0x45000 00:11:22:33:44:55:66:77
 *	console output:	00:11:22:33:44:55:66:77
 *
 */
int FWRITE(const char *da, const char *str_hex)
{
	unsigned char ee[MAX_FRW];
	unsigned int addr_da;
	int len;

	addr_da = strtoul(da, NULL, 16);
	if (addr_da && (len = atoh(str_hex, ee))) {
		FWrite(ee, addr_da, len);
		FREAD(addr_da, len);
	}
	return 0;
}

//End of new ATE Command
//Ren.B
int check_macmode(const char *str)
{

	if ((!str) || (!strcmp(str, "")) || (!strcmp(str, "disabled"))) {
		return 0;
	}

	if (strcmp(str, "allow") == 0) {
		return 1;
	}

	if (strcmp(str, "deny") == 0) {
		return 2;
	}
	return 0;
}

//Ren.E

//Ren.B
void gen_macmode(int mac_filter[], int band, char *prefix)
{
	char temp[128];

	sprintf(temp,"%smacmode", prefix);
	mac_filter[0] = check_macmode(nvram_get(temp));
	_dprintf("mac_filter[0] = %d\n", mac_filter[0]);
}

//Ren.E

static inline void __choose_mrate(char *prefix, int *mcast_phy, int *mcast_mcs, int *rate)
{
	int phy = 3, mcs = 7;	/* HTMIX 65/150Mbps */
	*rate=150000;
	char tmp[128];

#ifdef RTCONFIG_IPV6
	switch (get_ipv6_service()) {
	default:
		if (!nvram_get_int(ipv6_nvname("ipv6_radvd")))
			break;
		/* fall through */
#ifdef RTCONFIG_6RELAYD
	case IPV6_PASSTHROUGH:
#endif
		if (!strncmp(prefix, "wl0", 3)) {
			phy = 2;
			mcs = 2;	/* 2G: OFDM 12Mbps */
			*rate=12000;
		} else {
			phy = 3;
			mcs = 1;	/* 5G: HTMIX 13/30Mbps */
			*rate=30000;
		}
		/* fall through */
	case IPV6_DISABLED:
		break;
	}
#endif

	if (nvram_match(strcat_r(prefix, "nmode_x", tmp), "2") ||	/* legacy mode */
	    strstr(nvram_safe_get(strcat_r(prefix, "crypto", tmp)), "tkip")) {	/* tkip */
		/* In such case, choose OFDM instead of HTMIX */
		phy = 2;
		mcs = 4;	/* OFDM 24Mbps */
		*rate=24000;
	}

	*mcast_phy = phy;
	*mcast_mcs = mcs;
}

int bw40_channel_check(int band,char *ext)
{
   	int ch;
 	if(!band)
 	   	ch=nvram_get_int("wl0_channel");
	else
 	   	ch=nvram_get_int("wl1_channel");
	if(ch)
	{
	  if(!band) //2.4G	
	  {   
		if((ch==1) ||(ch==2) ||(ch==3)||(ch==4))
		{
			if(!strcmp(ext,"MINUS"))
		 	{
				dbG("stage 1: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"PLUS");
			}	   
		  
		}	
		else if(ch>=8)
		{
			if(!strcmp(ext,"PLUS"))
		 	{
				dbG("stage 2: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"MINUS");
			}	   
		}
		//ch5,6,7:both
	  }	
	  else //5G
	  {
		  if ((ch == 36) || (ch == 44) || (ch == 52) || (ch == 60) || (ch == 100)
		     || (ch == 108) ||(ch == 116) || (ch == 124) || (ch == 132) || (ch == 149) || (ch ==157))
		  {
			if(!strcmp(ext,"MINUS"))
		 	{
				dbG("stage 1: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"PLUS");
			}	   
		  
		  }
		  else if ((ch == 40) || (ch == 48) || (ch == 56) || (ch == 64) || (ch == 104) || (ch == 112) ||
		         (ch == 120) || (ch == 128) || (ch == 136) || (ch == 153) ||(ch == 161))
	  	  {
		  
			if(!strcmp(ext,"PLUS"))
		 	{
				dbG("stage 2: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"MINUS");
			}	   
		  
		  }
		 
	  }   

	}
	return 1; //pass
}   
   

#define MAX_NO_GUEST 3
/************************ CONSTANTS & MACROS ************************/

/*
 * Constants fof WE-9->15
 */
#define IW15_MAX_FREQUENCIES	16
#define IW15_MAX_BITRATES	8
#define IW15_MAX_TXPOWER	8
#define IW15_MAX_ENCODING_SIZES	8
#define IW15_MAX_SPY		8
#define IW15_MAX_AP		8


int __need_to_start_wps_band(char *prefix)
{
	char *p, tmp[128];

	if (!prefix || *prefix == '\0')
		return 0;

	p = nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp));
	if ((!strcmp(p, "open")
	     && !nvram_match(strcat_r(prefix, "wep_x", tmp), "0"))
	    || !strcmp(p, "shared") || !strcmp(p, "psk") || !strcmp(p, "wpa")
	    || !strcmp(p, "wpa2") || !strcmp(p, "wpawpa2")
	    || !strcmp(p, "radius")
	    || nvram_match(strcat_r(prefix, "radio", tmp), "0")
	    || !((sw_mode() == SW_MODE_ROUTER)
		 || (sw_mode() == SW_MODE_AP)))
		return 0;

	return 1;
}

int need_to_start_wps_band(int wps_band)
{
	int ret = 1;
	char prefix[] = "wlXXXXXXXXXX_";

	switch (wps_band) {
	case 0:		/* fall through */
	case 1:
		snprintf(prefix, sizeof(prefix), "wl%d_", wps_band);
		ret = __need_to_start_wps_band(prefix);
		break;
	default:
		ret = 0;
	}

	return ret;
	return 1;	/* FIXME */
}

int wps_pin(int pincode)
{
	int i;
	char word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x"), multiband = get_wps_multiband();

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}
//              dbg("WPS: PIN\n");

		if (pincode == 0) {
			;
		} else {
			doSystem("hostapd_cli -i%s wps_pin any %08d", get_wifname(i), pincode);
		}

		++i;
	}

	return 0;
}

static int __wps_pbc(const int multiband)
{
	int i;
	char word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x");

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}
//              dbg("WPS: PBC\n");
		g_isEnrollee[i] = 1;
		eval("hostapd_cli", "-i", (char*)get_wifname(i), "wps_pbc");
		eval("hostapd_cli", "-i", (char*)get_wifname(i), "wps_ap_pin", "disable");

		++i;
	}

	return 0;
}

int wps_pbc(void)
{
	return __wps_pbc(get_wps_multiband());
}

int wps_pbc_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	return __wps_pbc(1);
#endif
}

extern void wl_default_wps(int unit);

void __wps_oob(const int multiband)
{
#ifndef RTCONFIG_ALPINE
	int i, wps_band = nvram_get_int("wps_band_x");
	char word[256], *next;
	char ifnames[128];

	if (nvram_match("lan_ipaddr", ""))
		return;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}

		nvram_set("w_Setting", "0");
		wl_default_wps(i);

		qca_wif_up(word);
		g_isEnrollee[i] = 0;

		++i;
	}

#ifdef RTCONFIG_TCODE
	restore_defaults_wifi(0);
#endif
	nvram_commit();

	gen_qca_wifi_cfgs();
#else
#endif
}

void wps_oob(void)
{
	__wps_oob(get_wps_multiband());
}

void wps_oob_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	__wps_oob(1);
#else
	wps_oob();
#endif /* RTCONFIG_WPSMULTIBAND */
}

void start_wsc(void)
{
	int i;
	char *wps_sta_pin = nvram_safe_get("wps_sta_pin");
	char word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x"), multiband = get_wps_multiband();

	if (nvram_match("lan_ipaddr", ""))
		return;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		dbg("%s: start wsc(%d)\n", __func__, i);
		doSystem("hostapd_cli -i%s wps_cancel", get_wifname(i));	// WPS disabled

		if (strlen(wps_sta_pin) && strcmp(wps_sta_pin, "00000000")
		    && (wl_wpsPincheck(wps_sta_pin) == 0)) {
			dbg("WPS: PIN\n");	// PIN method
			g_isEnrollee[i] = 0;
			doSystem("hostapd_cli -i%s wps_pin any %s", get_wifname(i), wps_sta_pin);
		} else {
			dbg("WPS: PBC\n");	// PBC method
			g_isEnrollee[i] = 1;
			eval("hostapd_cli", "-i", (char*)get_wifname(i), "wps_pbc");
			eval("hostapd_cli", "-i", (char*)get_wifname(i), "wps_ap_pin", "disable");
		}

		++i;
	}
}

static void __stop_wsc(int multiband)
{
	int i;
	char word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x");

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		doSystem("hostapd_cli -i%s wps_cancel", get_wifname(i));	// WPS disabled

		++i;
	}
}

void stop_wsc(void)
{
	__stop_wsc(get_wps_multiband());
}

void stop_wsc_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	__stop_wsc(1);
#endif
}

#ifdef RTCONFIG_WPS_ENROLLEE
void start_wsc_enrollee(void)
{
	int i;
	char word[256], *next, ifnames[128];
	char conf[64];
	FILE *fp;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;

		dbg("%s: start wsc enrollee(%d)\n", __func__, i);

		if (sw_mode() == SW_MODE_ROUTER
				|| sw_mode() == SW_MODE_AP) {
			sprintf(conf, "/etc/Wireless/conf/wpa_supplicant-sta%d.conf", i);
			if ((fp = fopen(conf, "w+")) < 0) {
				_dprintf("%s: Can't open %s\n", __func__, conf);
				continue;
			}
			fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
			fprintf(fp, "update_config=1\n");
			fclose(fp);

			doSystem("wlanconfig sta%d create wlandev wifi%d wlanmode sta nosbeacon", i, i);
			sleep(1);
			doSystem("ifconfig sta%d up", i);
			doSystem("wpa_supplicant -B -P /var/run/wifi-sta%d.pid -D athr -i sta%d -b br0 -c /etc/Wireless/conf/wpa_supplicant-sta%d.conf", i, i, i);
		}

		doSystem("wpa_cli -i sta%d wps_pbc", i);
		i++;
	}
}

void stop_wsc_enrollee(void)
{
	int i;
	char word[256], *next, ifnames[128];
	char fpath[32];

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;

		doSystem("wpa_cli -i sta%d wps_cancel", i);

		if (sw_mode() == SW_MODE_ROUTER
				|| sw_mode() == SW_MODE_AP) {
			sprintf(fpath, "/var/run/wifi-sta%d.pid", i);
			kill_pidfile_tk(fpath);
			unlink(fpath);
			sprintf(fpath, "/etc/Wireless/conf/wpa_supplicant-sta%d.conf", i);
			unlink(fpath);

			doSystem("ifconfig sta%d down", i);
			doSystem("wlanconfig sta%d destroy", i);
		}

		i++;
	}
}

#ifdef RTCONFIG_WIFI_CLONE
void wifi_clone(int unit)
{
	char buf[512];
	FILE *fp;
	int len;
	char *pt1, *pt2;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	sprintf(buf, "/etc/Wireless/conf/wpa_supplicant-sta%d.conf", unit);
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	fp = fopen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		fclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			//SSID
			pt1 = strstr(buf, "ssid=\"");
			if (pt1) {
				pt2 = pt1 + strlen("ssid=\"");
				pt1 = strstr(pt2, "\"");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
					nvram_set(strcat_r(prefix, "ssid", tmp), pt2);
				}
			}
					nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
			//PSK
			pt2 = pt1 + 1;
			pt1 = strstr(pt2, "psk=\"");
			if (pt1) {	//WPA2-PSK
				pt2 = pt1 + strlen("psk=\"");
				pt1 = strstr(pt2, "\"");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
					nvram_set(strcat_r(prefix, "wpa_psk", tmp), pt2);
					nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "psk2");
					nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
				}
			}
			else {		//OPEN
				nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "open");
				nvram_set(strcat_r(prefix, "wep_x", tmp), "0");
			}
			nvram_set("x_Setting", "1");
			nvram_commit();
		}
	}
}
#endif

char *getWscStatus_enrollee(int unit, char *buf, int buflen)
{
	char cmdbuf[512];
	FILE *fp;
	int len;
	char *pt1, *pt2;

	snprintf(cmdbuf, sizeof(cmdbuf), "wpa_cli -i sta%d status", unit);
	fp = popen(cmdbuf, "r");
	if (fp) {
		memset(buf, 0, buflen);
		len = fread(buf, 1, buflen, fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "wpa_state=");
			if (pt1) {
				pt2 = pt1 + strlen("wpa_state=");
				pt1 = strstr(pt2, "address=");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
				}
				return pt2;
			}
		}
	}

	return "";
}
#endif

char *getWscStatus(int unit, char *buf, int buflen)
{
	char cmdbuf[512];
	FILE *fp;
	int len;
	char *pt1,*pt2;

	snprintf(cmdbuf, sizeof(cmdbuf), "hostapd_cli -i%s wps_get_status", get_wifname(unit));
	fp = popen(cmdbuf, "r");
	if (fp) {
		memset(buf, 0, buflen);
		len = fread(buf, 1, buflen, fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Last WPS result: ");
			if (pt1) {
				pt2 = pt1 + strlen("Last WPS result: ");
				pt1 = strstr(pt2, "Peer Address: ");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
				}
				return pt2;
			}
		}
	}

	return "";	/* FIXME */
}

void wsc_user_commit(void)
{
}


void Get_fail_log(char *buf, int size, unsigned int offset)
{
	struct FAIL_LOG fail_log, *log = &fail_log;
	char *p = buf;
	int x, y;

	memset(buf, 0, size);
	FRead((char *)&fail_log, offset, sizeof(fail_log));
	if (log->num == 0 || log->num > FAIL_LOG_MAX) {
		return;
	}
	for (x = 0; x < (FAIL_LOG_MAX >> 3); x++) {
		for (y = 0; log->bits[x] != 0 && y < 7; y++) {
			if (log->bits[x] & (1 << y)) {
				p += snprintf(p, size - (p - buf), "%d,",
					      (x << 3) + y);
			}
		}
	}
}


void ate_commit_bootlog(char *err_code)
{
	unsigned char fail_buffer[OFFSET_SERIAL_NUMBER - OFFSET_FAIL_RET];

	nvram_set("Ate_power_on_off_enable", err_code);
	nvram_commit();

	memset(fail_buffer, 0, sizeof(fail_buffer));
	strncpy(fail_buffer, err_code,
		OFFSET_FAIL_BOOT_LOG - OFFSET_FAIL_RET - 1);
	Gen_fail_log(nvram_get("Ate_reboot_log"),
		     nvram_get_int("Ate_boot_check"),
		     (struct FAIL_LOG *)&fail_buffer[OFFSET_FAIL_BOOT_LOG -
						     OFFSET_FAIL_RET]);
	Gen_fail_log(nvram_get("Ate_dev_log"), nvram_get_int("Ate_boot_check"),
		     (struct FAIL_LOG *)&fail_buffer[OFFSET_FAIL_DEV_LOG -
						     OFFSET_FAIL_RET]);

	FWrite(fail_buffer, OFFSET_FAIL_RET, sizeof(fail_buffer));
}
#endif  //RTCONFIG_QCA

#ifdef RTCONFIG_USER_LOW_RSSI
typedef struct _WLANCONFIG_LIST {
         char addr[18];
         unsigned int aid;
         unsigned int chan;
         char txrate[6];
         char rxrate[6];
         unsigned int rssi;
         unsigned int idle;
         unsigned int txseq;
         unsigned int rcseq;
         char caps[12];
         char acaps[10];
         char erp[7];
         char state_maxrate[20];
         char wps[4];
         char rsn[4];
         char wme[4];
         char mode[31];
} WLANCONFIG_LIST;

void rssi_check_unit(int unit)
{
	#define STA_LOW_RSSI_PATH "/tmp/low_rssi"
   	int rssi_th;
	FILE *fp;
	char line_buf[300],cmd[300],tmp[128],wif[8]; // max 14x
	char prefix[] = "wlXXXXXXXXXX_";
	WLANCONFIG_LIST *result;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	if (!(rssi_th= nvram_get_int(strcat_r(prefix, "user_rssi", tmp))))
		return;

	result=malloc(sizeof(WLANCONFIG_LIST));
	memset(result, 0, sizeof(WLANCONFIG_LIST));
	__get_wlifname(unit, 0, wif);
	doSystem("wlanconfig %s list > %s", wif, STA_LOW_RSSI_PATH);
	fp = fopen(STA_LOW_RSSI_PATH, "r");
		if (fp) {
			//fseek(fp, 131, SEEK_SET);	// ignore header
			fgets(line_buf, sizeof(line_buf), fp); // ignore header
			while ( fgets(line_buf, sizeof(line_buf), fp) ) {
				sscanf(line_buf, "%s%u%u%s%s%u%u%u%u%s%s%s%s%s%s%s%s", 
							result->addr, 
							&result->aid, 
							&result->chan, 
							result->txrate, 
							result->rxrate, 
							&result->rssi, 
							&result->idle, 
							&result->txseq, 
							&result->rcseq, 
							result->caps, 
							result->acaps, 
							result->erp, 
							result->state_maxrate, 
							result->wps, 
							result->rsn, 
							result->wme,
							result->mode);

#if 0
				dbg("[%s][%u][%u][%s][%s][%u][%u][%u][%u][%s][%s][%s][%s][%s][%s][%s]\n", 
					result->addr, 
					result->aid, 
					result->chan, 
					result->txrate, 
					result->rxrate, 
					result->rssi, 
					result->idle, 
					result->txseq, 
					result->rcseq, 
					result->caps, 
					result->acaps, 
					result->erp, 
					result->state_maxrate, 
					result->wps, 
					result->rsn, 
					result->wme);
#endif
				if(rssi_th>-result->rssi)
				{
				    	memset(cmd,0,sizeof(cmd));
					sprintf(cmd,"iwpriv %s kickmac %s", wif, result->addr);
					doSystem(cmd);
					dbg("=====>Roaming with %s:Disconnect Station: %s  RSSI: %d\n",
						wif, result->addr,-result->rssi);
				}   
			}
			free(result);
			fclose(fp);
			unlink(STA_LOW_RSSI_PATH);
		}
}
#endif

void platform_start_ate_mode(void)
{
	int model = get_model();

	switch (model) {
	case MODEL_GTAC9600:
		break;

	default:
		_dprintf("%s: model %d\n", __func__, model);
	}
}


#define target 9
char str[target][40]={"Address:","ESSID:","Frequency:","Quality=","Encryption key:","IE:","Authentication Suites","Pairwise Ciphers","phy_mode="};
int
getSiteSurvey(int band,char* ofile)
{
   	int apCount=0;
	char header[128];
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char cmd[300];
	FILE *fp,*ofp;
	char buf[target][200],set_flag[target];
	int i;
	char *pt1,*pt2;
	char a1[10],a2[10];
	char ssid_str[256];
	char ch[4],ssid[33],address[18],enc[9],auth[16],sig[9],wmode[8];
	int  lock;
	char ure_mac[18];
	int wl_authorized = 0;
//////
	int is_ready;
	char temp1[200];
	char prefix_header[]="Cell xx - Address:";
/////
	dbG("site survey...\n");
	lock = file_lock("sitesurvey");
	system("rm -f /tmp/apscan_wlist");
	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	sprintf(cmd,"iwlist %s scanning >> /tmp/apscan_wlist",nvram_safe_get(strcat_r(prefix, "ifname", tmp)));
	ifconfig(nvram_safe_get(strcat_r(prefix, "ifname", tmp)), IFUP, NULL, NULL);
	system(cmd);
	file_unlock(lock);
	
	if((fp= fopen("/tmp/apscan_wlist", "r"))==NULL) 
	   return 0;
	
	memset(header, 0, sizeof(header));
	sprintf(header, "%-4s%-33s%-18s%-9s%-16s%-9s%-8s\n", "Ch", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode");

	dbg("\n%s", header);

	if ((ofp = fopen(ofile, "a")) == NULL)
	{
	   fclose(fp);
	   return 0;
	}

	apCount=1;
	while(1)
	{
	   	is_ready=0;
		memset(set_flag,0,sizeof(set_flag));
		memset(buf,0,sizeof(buf));
		memset(temp1,0,sizeof(temp1));
		snprintf(prefix_header, sizeof(prefix_header), "Cell %02d - Address:",apCount);

  		if(feof(fp)) 
		   break;

		while(fgets(temp1,sizeof(temp1),fp))
		{
			if(strstr(temp1,prefix_header)!=NULL)
			{
				if(is_ready)
				{   
					fseek(fp,-sizeof(temp1), SEEK_CUR);   
					break;
				}
				else
			   	{	   
					is_ready=1;
					snprintf(prefix_header, sizeof(prefix_header),"Cell %02d - Address:",apCount+1);
				}	
			}
			if(is_ready)
	   		{		   
				for(i=0;i<target;i++)
				{
					if(strstr(temp1,str[i])!=NULL && set_flag[i]==0)
				  	{   
						set_flag[i]=1;
					     	memcpy(buf[i],temp1,sizeof(temp1));
						break;
					}		
				}
			}	

		}


		dbg("\napCount=%d\n",apCount);
		apCount++;

		//ch
	        pt1 = strstr(buf[2], "Channel ");	
		if(pt1)
		{

			pt2 = strstr(pt1,")");
		   	memset(ch,0,sizeof(ch));
			strncpy(ch,pt1+strlen("Channel "),pt2-pt1-strlen("Channel "));
		}   

		//ssid
	        pt1 = strstr(buf[1], "ESSID:");	
		if(pt1)
		{
		   	memset(ssid,0,sizeof(ssid));
			strncpy(ssid,pt1+strlen("ESSID:")+1,strlen(buf[1])-2-(pt1+strlen("ESSID:")+1-buf[1]));
		}   


		//bssid
	        pt1 = strstr(buf[0], "Address: ");	
		if(pt1)
		{
		   	memset(address,0,sizeof(address));
			strncpy(address,pt1+strlen("Address: "),strlen(buf[0])-(pt1+strlen("Address: ")-buf[0])-1);
		}   
	

		//enc
		pt1=strstr(buf[4],"Encryption key:");
		if(pt1)
		{   
			if(strstr(pt1+strlen("Encryption key:"),"on"))
			{
				pt2=strstr(buf[7],"Pairwise Ciphers");
				if(pt2)
	  			{
					if(strstr(pt2,"CCMP TKIP") || strstr(pt2,"TKIP CCMP"))
				   		sprintf(enc,"TKIP+AES");
					else if(strstr(pt2,"CCMP"))
					   	sprintf(enc,"AES");
					else
					   	sprintf(enc,"TKIP");
				}
				else
					sprintf(enc,"WEP");
			}   
			else
				sprintf(enc,"NONE");
		}


		//auth
		memset(auth,0,sizeof(auth));
		pt1=strstr(buf[5],"IE:");
		if(pt1 && strstr(buf[5],"Unknown")==NULL)
		{   			 
			if(strstr(pt1+strlen("IE:"),"WPA2")!=NULL)
		   		sprintf(auth,"WPA2-");
			else if(strstr(pt1+strlen("IE:"),"WPA")!=NULL) 
		   		sprintf(auth,"WPA-");
		
			pt2=strstr(buf[6],"Authentication Suites");
			if(pt2)
	  		{
				if(strstr(pt2+strlen("Authentication Suites"),"PSK")!=NULL)
			   		strcat(auth,"Personal");
				else //802.1x
				   	strcat(auth,"Enterprise");
			}
		}
		else
		   	sprintf(auth,"Open System");
		   		  
		//sig
	        pt1 = strstr(buf[3], "Quality=");	
		pt2 = strstr(pt1,"/");
		if(pt1 && pt2)
		{
			memset(sig,0,sizeof(sig));
			memset(a1,0,sizeof(a1));
			memset(a2,0,sizeof(a2));
			strncpy(a1,pt1+strlen("Quality="),pt2-pt1-strlen("Quality="));
			strncpy(a2,pt2+1,strstr(pt2," ")-(pt2+1));
			sprintf(sig,"%d",100*(atoi(a1)+6)/(atoi(a2)+6));

		}   

		//wmode
		memset(wmode,0,sizeof(wmode));
		pt1=strstr(buf[8],"phy_mode=");
		if(pt1)
		{   

			if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11AC_VHT"))!=NULL)
		   	   	sprintf(wmode,"ac");
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11A"))!=NULL
			        || (pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_TURBO_A"))!=NULL)
				sprintf(wmode,"a");
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11B"))!=NULL)
				sprintf(wmode,"b");
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11G"))!=NULL
			        || (pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_TURBO_G"))!=NULL)
				sprintf(wmode,"bg");
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11NA"))!=NULL)
		   	   	sprintf(wmode,"an");
			else if(strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11NG"))
		   	   	sprintf(wmode,"bgn");
		}
		else
		   	sprintf(wmode,"unknown");

#if 1
		dbg("%-4s%-33s%-18s%-9s%-16s%-9s%-8s\n",ch,ssid,address,enc,auth,sig,wmode);
#endif	

//////
		if(atoi(ch)<0)
			fprintf(ofp, "\"ERR_BAND\",");
		else if(atoi(ch)>0 && atoi(ch)<14)
			fprintf(ofp, "\"2G\",");
		else if(atoi(ch)>14 && atoi(ch)<166)
			fprintf(ofp, "\"5G\",");
		else
			fprintf(ofp, "\"ERR_BAND\",");


		memset(ssid_str, 0, sizeof(ssid_str));
		char_to_ascii(ssid_str, trim_r(ssid));
		
		if(strlen(ssid)==0)
			fprintf(ofp, "\"\",");
		else
			fprintf(ofp, "\"%s\",", ssid_str);

		fprintf(ofp, "\"%d\",", atoi(ch));

		fprintf(ofp, "\"%s\",",auth);
		
		fprintf(ofp, "\"%s\",", enc); 

		fprintf(ofp, "\"%d\",", atoi(sig));

		fprintf(ofp, "\"%s\",", address);

		fprintf(ofp, "\"%s\",", wmode); 

#ifdef RTCONFIG_WIRELESSREPEATER		
		//memset(ure_mac, 0x0, 18);
		//sprintf(ure_mac, "%02X:%02X:%02X:%02X:%02X:%02X",xxxx);
		if (strcmp(nvram_safe_get(wlc_nvname("ssid")), ssid)){
			if (strcmp(ssid, ""))
				fprintf(ofp, "\"%s\"", "0");				// none
			else if (!strcmp(ure_mac, address)){
				// hidden AP (null SSID)
				if (strstr(nvram_safe_get(wlc_nvname("akm")), "psk")!=NULL){
					if (wl_authorized){
						// in profile, connected
						fprintf(ofp, "\"%s\"", "4");
					}else{
						// in profile, connecting
						fprintf(ofp, "\"%s\"", "5");
					}
				}else{
					// in profile, connected
					fprintf(ofp, "\"%s\"", "4");
				}
			}else{
				// hidden AP (null SSID)
				fprintf(ofp, "\"%s\"", "0");				// none
			}
		}else if (!strcmp(nvram_safe_get(wlc_nvname("ssid")), ssid)){
			if (!strlen(ure_mac)){
				// in profile, disconnected
				fprintf(ofp, "\"%s\",", "1");
			}else if (!strcmp(ure_mac, address)){
				if (strstr(nvram_safe_get(wlc_nvname("akm")), "psk")!=NULL){
					if (wl_authorized){
						// in profile, connected
						fprintf(ofp, "\"%s\"", "2");
					}else{
						// in profile, connecting
						fprintf(ofp, "\"%s\"", "3");
					}
				}else{
					// in profile, connected
					fprintf(ofp, "\"%s\"", "2");
				}
			}else{
				fprintf(ofp, "\"%s\"", "0");				// impossible...
			}
		}else{
			// wl0_ssid is empty
			fprintf(ofp, "\"%s\"", "0");
		}
#else
		fprintf(ofp, "\"%s\"", "0");      
#endif		
		fprintf(ofp, "\n");
		
//////

	}

	fclose(fp);
	fclose(ofp);
	return 1;
}   


#ifdef RTCONFIG_WIRELESSREPEATER
char *wlc_nvname(char *keyword)
{
	return(wl_nvname(keyword, nvram_get_int("wlc_band"), -1));
}
#endif

char *getStaMAC(char *buf, int buflen)
{
	char cmdbuf[512];
	FILE *fp;
	int len,unit;
	char *pt1,*pt2;
	unit=nvram_get_int("wlc_band");

	snprintf(cmdbuf, sizeof(cmdbuf), "ifconfig sta%d", unit);

	fp = popen(cmdbuf, "r");
	if (fp) {
		memset(buf, 0, buflen);
		len = fread(buf, 1, buflen, fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "HWaddr ");
			if (pt1) 
			{
				pt2 = pt1 + strlen("HWaddr ");
				*(pt2+17)='\0';
				return pt2;
			}
		}
	}
	return NULL;
}


unsigned int getPapState(int unit)
{
	char buf[8192];
	FILE *fp;
	int len;
	char *pt1, *pt2;
	sprintf(buf, "iwconfig sta%d", unit);
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Access Point:");
			if (pt1) {
				pt2 = pt1 + strlen("Access Point:");
				pt1 = strstr(pt2, "Not-Associated");
				if (pt1) 
				{
					sprintf(buf, "ifconfig | grep sta%d", unit);
				     	fp = popen(buf, "r");
					if(fp)
				   	{
						 memset(buf, 0, sizeof(buf));
						 len = fread(buf, 1, sizeof(buf), fp);
						 pclose(fp);
						 if(len>=1)
						    return 0;
						 else
						    return 3;
					}	
				     	else	
				   		return 0; //init
				}	
				else
				   	return 2; //connect and auth ?????
					
				}
			}
		}
	
	return 3; // stop
}

// TODO: wlcconnect_main
// TODO: wlcconnect_main
//	wireless ap monitor to connect to ap
//	when wlc_list, then connect to it according to priority
#define FIND_CHANNEL_INTERVAL	15
int wlcconnect_core(void)
{
   int unit,ret;
   unit=nvram_get_int("wlc_band");
   ret=getPapState(unit);
   if(ret!=2) //connected
   	dbG("check..wlconnect=%d \n",ret);
   return ret;
}


#define UBIFS_VOL_NAME	"jffs2"

int ubi_remove_dev(const char *node, int ubi_dev)
{
	int fd, ret;

	fd = open(node, O_RDONLY);
	if (fd == -1){
		fprintf(stderr, "[%s][%d] cannot open", node, ubi_dev);
		return -1;
	}
	ret = ioctl(fd, UBI_IOCDET, &ubi_dev);
	if (ret == -1)
		goto out_close;

#ifdef UDEV_SETTLE_HACK
//	if (system("udevsettle") == -1)
//		return -1;
	usleep(100000);
#endif

out_close:
	close(fd);
	return ret;
}

int check_ubi_partition(void)
{
	int dev, part, size;
	int ret = 0;

	/* UBIFS_VOL_NAME: jffs2 */
	fprintf(stderr, "... check_ubi_partition() ...\n");
#if 1
	if (mknod("/dev/ubi0", S_IFCHR | 0660, makedev(248, 0)))
		perror("## mknod " "/dev/ubi0");
	if (mknod("/dev/ubi0_0", S_IFCHR | 0660, makedev(248, 1)))
		perror("## mknod " "/dev/ubi0_0");
	fprintf(stderr, "... start ubiattach ...\n");
	system("ubiattach /dev/ubi_ctrl -m 6");
	while (pids("ubiattach")){
		fprintf(stderr, "... waiting ubiattach finished ...\n");
		sleep(1);
	}
	fprintf(stderr, "... ubiattach finished ...\n");
#endif
	ret = ubi_getinfo(UBIFS_VOL_NAME, &dev, &part, &size);
	if (ret < 0 || ret == 1){
		fprintf(stderr, "... detach mtd6 ...\n");
		system("ubidetach -p /dev/mtd6");
		fprintf(stderr, "... start flash_erase ...\n");
		system("flash_erase /dev/mtd6 0 0");
		while (pids("flash_erase")){
			fprintf(stderr, "... waiting flash_erase finished ...\n");
			sleep(1);
		}
		fprintf(stderr, "... flash_erase finished ...\n");

		fprintf(stderr, "... start ubiattach ...\n");
		system("ubiattach /dev/ubi_ctrl -m 6");
		while (pids("ubiattach")){
			fprintf(stderr, "... waiting ubiattach finished ...\n");
			sleep(1);
		}
		fprintf(stderr, "... ubiattach finished ...\n");

		fprintf(stderr, "... start ubimkvol ...\n");
		system("ubimkvol /dev/ubi0 -N jffs2 -m");
		while (pids("ubimkvol")){
			fprintf(stderr, "... waiting ubimkvol finished ...\n");
			sleep(1);
		}
		fprintf(stderr, "... ubimkvol finished ...\n");
	}

	return 0;
}

int start_aqr107(void)
{
	system("ifconfig eth0 up");
	system("/sbin/aq-fw-download /lib/firmware/aqr_firmware.cld eth0 0x1" );
	_dprintf("... start start_aqr107() ...\n");
	while (pids("aq-fw-download"))
	{
		_dprintf("... waiting start_aqr107() finished ...\n");
		sleep(1);
	}
	_dprintf("... start_aqr107() finished ...\n");
	return 1;
}

#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_LAN4WAN_LED)
int LanWanLedCtrl(void)
{
#ifdef RTCONFIG_LANWAN_LED
	if(get_lanports_status() && !inhibit_led_on())
		led_control(LED_LAN, LED_ON);
	else
		led_control(LED_LAN, LED_OFF);
#endif

	return 1;
}
#endif
extern int get_wifi_country_code_tmp(char *ori_countrycode, char *output, int len){
	return -1;
}
