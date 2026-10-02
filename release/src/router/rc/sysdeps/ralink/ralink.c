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
#ifdef RTCONFIG_RALINK
#include <stdio.h>
#include <fcntl.h>		//	for restore175C() from Ralink src
#include <ralink.h>
#include <bcmnvram.h>
//#include <linux/ethtool.h>
#if !defined(__GLIBC__) && !defined(__UCLIBC__) /* musl */
#else
#include <linux/sockios.h>
#endif
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
//#include <linux/if.h>
#include <iwlib.h>
#include <wps.h>
#include <stapriv.h>
#include <shared.h>
#include "flash_mtd.h"
#include "ate.h"
#ifdef RTCONFIG_CFGSYNC
#include <json.h>
#include <cfg_slavelist.h>
#include <cfg_string.h>
#endif
#ifdef RTCONFIG_AMAS
#include <amas-utils.h>
#include <amas_path.h>
#endif
#ifdef RTCONFIG_NEW_USER_LOW_RSSI
#include "roamast.h"
#endif

#ifdef RTCONFIG_WIRELESSREPEATER
#include <ap_priv.h>
#endif
#define MAX_FRW 64
#define MACSIZE 12

#define	DEFAULT_SSID_2G	"ASUS"
#define	DEFAULT_SSID_5G	"ASUS_5G"

#if 0
#define RTKSWITCH_DEV  "/dev/rtkswitch"
#endif

//#ifdef RTCONFIG_WIRELESSREPEATER
char *wlc_nvname(char *keyword);
//#endif

#if defined(RTAC52U) || defined(RTAC51U) || defined(RTAC1200HP) || defined(RTN56UB1) || defined(RTAC54U) || defined(RTN56UB2) || defined(RTAC1200GA1)  || defined(RTAC1200GU) || defined(RTAC1200) || defined(RTAC1200V2) || defined(RTCONFIG_MTK_REP) || defined(RTAC51UP) || defined(RTAC53) || defined(RTAC85U) || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750) || defined(RTACRH18) || defined(RT4GAC86U) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
#define VHT_SUPPORT /* 11AC */
#endif

#if defined(RTCONFIG_MTK_BSD)
extern void start_mtk_bs20(void);
extern void stop_mtk_bs20(void);
#endif	/* RTCONFIG_MTK_BSD */

int g_wsc_configured = 0;
int g_isEnrollee[MAX_NR_WL_IF] = { 0, };

int getCountryRegion5G(const char *countryCode, int *warning, int IEEE80211H);
#if defined(RTCONFIG_AMAS)
int get_wlc_func_enable(char *wif);
int Pty_get_wlc_status(char *wif);
#endif

int getWscStatusCli(char *aif);

static void
iwprivSet(const char *ifname, const char *name, const char *value)
{
	char tmpBuf[256];
	snprintf(tmpBuf, sizeof(tmpBuf), "%s=%s", name, value);
	_dprintf("[%s] %s (%s)\n", __func__, ifname, tmpBuf);
	eval("iwpriv", (char*) ifname, "set", tmpBuf);
}


char *
get_wscd_pidfile(void)
{
	static char tmpstr[32] = "/var/run/wscd.pid.";

	sprintf(tmpstr, "/var/run/wscd.pid.%s", (!nvram_get_int("wps_band_x"))? WIF_2G:WIF_5G);
	return tmpstr;
}

char *
get_wscd_pidfile_band(int wps_band)
{
	static char tmpstr[32] = "/var/run/wscd.pid.";

	sprintf(tmpstr, "/var/run/wscd.pid.%s", (!wps_band)? WIF_2G:WIF_5G);
	return tmpstr;
}

int
get_wifname_num(char *name)
{
	if(strcmp(WIF_5G,name)==0)
	   	return 1;
	else if (strcmp(WIF_2G,name)==0)
	   	return 0;
	else
		return -1;
}

const char *
get_wifname(int band)
{
	if (band)
		return WIF_5G;
	else
		return WIF_2G;
}

const char *
get_wpsifname(void)
{
	int wps_band = nvram_get_int("wps_band_x");

	if (wps_band)
		return WIF_5G;
	else
		return WIF_2G;
}

#if 0
char *
get_non_wpsifname()
{
	int wps_band = nvram_get_int("wps_band_x");

	if (wps_band)
		return WIF_2G;
	else
		return WIF_5G;
}
#endif

#ifdef RTCONFIG_DSL
// used by rc
void get_country_code_from_rc(char* country_code)
{
	unsigned char CC[3];
	memset(CC, 0, sizeof(CC));
	FRead(CC, OFFSET_COUNTRY_CODE, 2);

	if (CC[0] == 0xff && CC[1] == 0xff)
	{
		*country_code++ = 'T';
		*country_code++ = 'W';
		*country_code = 0;
	}
	else
	{
		*country_code++ = CC[0];
		*country_code++ = CC[1];
		*country_code = 0;
	}
}
#endif

static unsigned char nibble_hex(char *c)
{
	int val;
	char tmpstr[3];

	tmpstr[2]='\0';
	memcpy(tmpstr,c,2);
	val= strtoul(tmpstr, NULL, 16);
	return val;
}

static int atoh(const char *a, unsigned char *e)
{
	char *c = (char *) a;
	int i = 0;

	memset(e, 0, MAX_FRW);
	for (i = 0; i < MAX_FRW; ++i, c += 3) {
		if (!isxdigit(*c) || !isxdigit(*(c+1)) || isxdigit(*(c+2))) // should be "AA:BB:CC:DD:..."
			break;
		e[i] = (unsigned char) nibble_hex(c);
	}

	return i;
}

char *
htoa(const unsigned char *e, char *a, int len)
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

int
FREAD(unsigned int addr_sa, int len)
{
	unsigned char buffer[MAX_FRW];
	char buffer_h[ MAX_FRW * 3 ];
	memset(buffer, 0, sizeof(buffer));
	memset(buffer_h, 0, sizeof(buffer_h));

	if (len > MAX_FRW)
	{
		dbg("FREAD: cut to %d bytes\n", MAX_FRW);
		len = MAX_FRW;
	}
	if (FRead(buffer, addr_sa, len)<0)
		dbg("FREAD: Out of scope\n");
	else
	{
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
int
FWRITE(const char *da, const char* str_hex)
{
	unsigned char ee[MAX_FRW];
	unsigned int addr_da;
	int len;

	addr_da = strtoul(da, NULL, 16);
	if (addr_da && (len = atoh(str_hex, ee)))
	{
		FWrite(ee, addr_da, len);
		FREAD(addr_da, len);
	}
	return 0;
}
//End of new ATE Command

int getCountryRegion2G(const char *countryCode)
{
	if (countryCode == NULL)
	{
		return 5;	// 1-14
	}
	else if((strcasecmp(countryCode, "CA") == 0) || (strcasecmp(countryCode, "CO") == 0) ||
		(strcasecmp(countryCode, "DO") == 0) || (strcasecmp(countryCode, "GT") == 0) ||
		(strcasecmp(countryCode, "MX") == 0) || (strcasecmp(countryCode, "NO") == 0) ||
		(strcasecmp(countryCode, "PA") == 0) || (strcasecmp(countryCode, "PR") == 0) ||
		(strcasecmp(countryCode, "TW") == 0) || (strcasecmp(countryCode, "US") == 0) ||
		(strcasecmp(countryCode, "UZ") == 0) ||
		(strcasecmp(countryCode, "Z1") == 0) || (strcasecmp(countryCode, "Z3") == 0) ||
		(strcasecmp(countryCode, "IN") == 0)
#if !defined(RT4GAX56)
		|| (strcasecmp(countryCode, "AA") == 0)
#endif
#if defined(RTAC85U)  || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750)
		|| (strcasecmp(countryCode, "SG") == 0)
#endif
		)
	{
		return 0;	// 1-11
	}
	else if (strcasecmp(countryCode, "DB") == 0  || strcasecmp(countryCode, "") == 0)
	{
		return 5;	// 1-14
	}

	return 1;	// 1-13
}

int getChannelNumMax2G(int region)
{
	switch(region)
	{
		case 0: return 11;
		case 1: return 13;
		case 5: return 14;
	}
	return 14;
}

#if defined(RTCONFIG_MT798X)
static char *getCountryCode() {
	char *tcode = nvram_safe_get("territory_code");
	if (nvram_contains_word("rc_support", "loclist") && nvram_match("location_code", "XX"))
		return "AU";	//for wifi performance

	if (strncmp(tcode, "US", 2) == 0)
		return "US";
	else if (strncmp(tcode, "CN", 2) == 0)
		return "CN";
	else if (strncmp(tcode, "TW", 2) == 0)
		return "US"; // keep ASUSWRT original config
	else if (strncmp(tcode, "JP", 2) == 0)
		return "JP";
	else if (strncmp(tcode, "UK", 2) == 0)
		return "GB"; // United Kingdom
	else if (strncmp(tcode, "EU", 2) == 0)
		return "DE"; // Germany, channel is same with GB
	else if (strncmp(tcode, "AA", 2) == 0)
		return "US"; // keep ASUSWRT original config
	else if (strncmp(tcode, "KR", 2) == 0)
		return "KR"; // new, TBC.
	else if (strncmp(tcode, "RU", 2) == 0)
		return "RU"; // new, TBC.
	else { // empty or invalid
		if (tcode[0] != '\0')
			_dprintf("XXXXXXXXX invalid Tcode? [%s] XXXXXXXXX\n", tcode);
		return "US"; // default value
	}
}

int getCountryRegion5G(const char *countryCode, int *warning, int IEEE80211H)
{	/* value for CountryRegionABand */
#ifdef RTCONFIG_RALINK_DFS
	if (IEEE80211H) {
		if ( (!strcasecmp(countryCode, "EH")) )
			return 22;	//100,104,108,112,116,120,124,128,132,136,140
		if ( (!strcasecmp(countryCode, "EU")) )
			return 23;	//36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140
		if ( (!strcasecmp(countryCode, "JP")) )
			return 12;	//36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144
		if ( (!strcasecmp(countryCode, "AA")) )
			return 9;	//36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140,149,153,157,161,165
		if ( (!strcasecmp(countryCode, "TW")) || (!strcasecmp(countryCode, "US")) )
			return 13;	//36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165
		if ( (!strcasecmp(countryCode, "CN")) )
			return 4;	//36,40,44,48,52,56,60,64,149,153,157,161,165
		if ( (!strcasecmp(countryCode, "GB")) )
			return 18;	//36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140
	}
#endif

		if ( (!strcasecmp(countryCode, "US")) )
			return 0;	//36,40,44,48,149,153,157,161,165
		if ( (!strcasecmp(countryCode, "GB")) )
			return 1;	//36,40,44,48
		if ( (!strcasecmp(countryCode, "TW")) )
			return 3;	//56,60,64,149,153,157,161,165
		if ( (!strcasecmp(countryCode, "CN")) )
			return 5;	//149,153,157,161 (need 165 ?)

	if (warning)
		*warning = 2;
	return 13;	//ALL: 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165
}
#else
int getCountryRegion5G(const char *countryCode, int *warning, int IEEE80211H)
{
#ifdef RTCONFIG_RALINK_DFS
	if (IEEE80211H)
	{
		if(	(!strcasecmp(countryCode, "GB")) )
			return 18;
		if(	(!strcasecmp(countryCode, "JP")) )
			return 23;
	}
#endif	/* RTCONFIG_RALINK_DFS */

	if (		(!strcasecmp(countryCode, "AE")) ||
			(!strcasecmp(countryCode, "AL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "AU")) ||
			(!strcasecmp(countryCode, "BH")) ||
			(!strcasecmp(countryCode, "BY")) ||
			(!strcasecmp(countryCode, "CA")) ||
			(!strcasecmp(countryCode, "CL")) ||
			(!strcasecmp(countryCode, "CO")) ||
			(!strcasecmp(countryCode, "CR")) ||
			(!strcasecmp(countryCode, "DO")) ||
			(!strcasecmp(countryCode, "DZ")) ||
			(!strcasecmp(countryCode, "EC")) ||
			(!strcasecmp(countryCode, "GT")) ||
			(!strcasecmp(countryCode, "HK")) ||
			(!strcasecmp(countryCode, "HN")) ||
			(!strcasecmp(countryCode, "IL")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "IN")) ||
#endif
			(!strcasecmp(countryCode, "JO")) ||
			(!strcasecmp(countryCode, "KW")) ||
			(!strcasecmp(countryCode, "KZ")) ||
			(!strcasecmp(countryCode, "LB")) ||
			(!strcasecmp(countryCode, "MA")) ||
			(!strcasecmp(countryCode, "MK")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
			(!strcasecmp(countryCode, "MX")) ||
#endif
			(!strcasecmp(countryCode, "MY")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "NZ")) ||
			(!strcasecmp(countryCode, "OM")) ||
			(!strcasecmp(countryCode, "PA")) ||
			(!strcasecmp(countryCode, "PK")) ||
			(!strcasecmp(countryCode, "PR")) ||
			(!strcasecmp(countryCode, "QA")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
			(!strcasecmp(countryCode, "RU")) ||
#endif
			(!strcasecmp(countryCode, "SA")) ||
			(!strcasecmp(countryCode, "SG")) ||
			(!strcasecmp(countryCode, "SV")) ||
			(!strcasecmp(countryCode, "SY")) ||
			(!strcasecmp(countryCode, "TH")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UA")) ||
#endif
			(!strcasecmp(countryCode, "US")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "UY")) ||
#endif
			(!strcasecmp(countryCode, "VN")) ||
			(!strcasecmp(countryCode, "YE")) ||
			(!strcasecmp(countryCode, "ZW")) ||
			(!strcasecmp(countryCode, "AA")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z1"))
#else
			0
#endif
	)
	{
#if defined(RTAC51UP)
		if (nvram_contains_word("rc_support", "loclist") && !strcasecmp(countryCode, "SG"))
			return 9;
		if (nvram_contains_word("rc_support", "loclist") && !strcasecmp(countryCode, "AU"))
			return 22;
#else
		if (nvram_contains_word("rc_support", "loclist") && !strcasecmp(countryCode, "AU"))
			return 9;
#endif
#if defined(RTAC53)
		if (nvram_contains_word("rc_support", "loclist") && !strcasecmp(countryCode, "SG"))
			return 18;
#endif
#if defined(RTAC1200V2) || defined(RTAC85P) || defined(RTCONFIG_MT798X)
		if (!strcasecmp(countryCode, "RU"))
			return 24;
		if (!strcasecmp(countryCode, "IL"))
			return 25;		
#endif
#if defined(RT4GAX56)
		if (!strcasecmp(countryCode, "AA"))
			return 26;
#endif
		if (nvram_get_int("ID_mode")==1) {
			return 17;
		}

		return 0;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
#endif
			(!strcasecmp(countryCode, "AT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AZ")) ||
#endif
			(!strcasecmp(countryCode, "BE")) ||
			(!strcasecmp(countryCode, "BG")) ||
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "CH")) ||
			(!strcasecmp(countryCode, "CY")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "CZ")) ||
#endif
			(!strcasecmp(countryCode, "DE")) ||
			(!strcasecmp(countryCode, "DK")) ||
			(!strcasecmp(countryCode, "EE")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "EG")) ||
#endif
			(!strcasecmp(countryCode, "ES")) ||
			(!strcasecmp(countryCode, "FI")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "FR")) ||
#endif
			(!strcasecmp(countryCode, "GB")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "GE")) ||
#endif
			(!strcasecmp(countryCode, "GR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "HR")) ||
#endif
			(!strcasecmp(countryCode, "HU")) ||
			(!strcasecmp(countryCode, "IE")) ||
			(!strcasecmp(countryCode, "IS")) ||
			(!strcasecmp(countryCode, "IT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP")) ||
			(!strcasecmp(countryCode, "KP")) ||
			(!strcasecmp(countryCode, "KR")) ||
#endif
			(!strcasecmp(countryCode, "LI")) ||
			(!strcasecmp(countryCode, "LT")) ||
			(!strcasecmp(countryCode, "LU")) ||
			(!strcasecmp(countryCode, "LV")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MC")) ||
#endif
			(!strcasecmp(countryCode, "NL")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "NO")) ||
#endif
			(!strcasecmp(countryCode, "PL")) ||
			(!strcasecmp(countryCode, "PT")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "RO")) ||
#endif
			(!strcasecmp(countryCode, "SE")) ||
			(!strcasecmp(countryCode, "SI")) ||
			(!strcasecmp(countryCode, "SK")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT")) ||
#endif
			(!strcasecmp(countryCode, "UZ")) ||
			(!strcasecmp(countryCode, "ZA")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z2"))
#else
			0
#endif
	)
	{
		return 1;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AM")) ||
			(!strcasecmp(countryCode, "AZ")) ||
			(!strcasecmp(countryCode, "CZ")) ||
			(!strcasecmp(countryCode, "EG")) ||
			(!strcasecmp(countryCode, "FR")) ||
			(!strcasecmp(countryCode, "GE")) ||
			(!strcasecmp(countryCode, "HR")) ||
			(!strcasecmp(countryCode, "MC")) ||
			(!strcasecmp(countryCode, "TN")) ||
			(!strcasecmp(countryCode, "TR")) ||
			(!strcasecmp(countryCode, "TT"))
#else
			(!strcasecmp(countryCode, "IN")) ||
			(!strcasecmp(countryCode, "MX"))
#endif
	)
	{
		return 2;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "AR")) ||
#endif
			(!strcasecmp(countryCode, "TW")) ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z3"))
#else
			0
#endif
	)
	{
		return 3;
	}
	else if (
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "BR")) ||
#endif
			(!strcasecmp(countryCode, "BZ")) ||
			(!strcasecmp(countryCode, "BO")) ||
			(!strcasecmp(countryCode, "BN")) ||
			(!strcasecmp(countryCode, "CN")) ||
			(!strcasecmp(countryCode, "ID")) ||
			(!strcasecmp(countryCode, "IR")) ||
#ifdef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "MO")) ||
#endif
			(!strcasecmp(countryCode, "PE")) ||
			(!strcasecmp(countryCode, "PH"))
#ifdef RTCONFIG_LOCALE2012
						 ||
			(!strcasecmp(countryCode, "VE"))
#endif
						 ||
#if defined(RTN65U)
			//for specific power
			(!strcasecmp(countryCode, "Z4"))
#else
			0
#endif
	)
	{
		return 4;
	}
#ifndef RTCONFIG_LOCALE2012
	else if (	(!strcasecmp(countryCode, "KP")) ||
			//(!strcasecmp(countryCode, "KR")) ||
			(!strcasecmp(countryCode, "UY")) ||
			(!strcasecmp(countryCode, "VE"))
	)
	{
		return 5;
	}
#else
	else if (!strcasecmp(countryCode, "RU"))
	{
		return 6;
	}
#endif
	else if (!strcasecmp(countryCode, "DB"))
	{
		return 7;
	}
	else if (
#ifndef RTCONFIG_LOCALE2012
			(!strcasecmp(countryCode, "JP"))
#else
			(!strcasecmp(countryCode, "UA"))
#endif
	)
	{
		return 9;
	}
	else if (!strcasecmp(countryCode, "KR"))
	{
		return 13;
	}
	else
	{
		if (warning)
			*warning = 2;
		return 7;
	}
}
#endif

//Ren.B
int check_macmode(const char *str)
{
	if((!str)||(!strcmp(str, ""))||(!strcmp(str, "disabled")))
	{
		return 0;
	}

	if(strcmp(str, "allow")==0)
	{
		return 1;
	}

	if(strcmp(str, "deny")==0)
	{
		return 2;
	}
	return 0;
}
//Ren.E

//Ren.B
void gen_macmode(int mac_filter[], int band)
{
	int i,j;
	char temp[128], prefix_mssid[] = "wlXXXXXXXXXX_mssid_";
	for (i = 0,j = 0; i < MAX_NO_MSSID; i++)
	{
#if defined(RTCONFIG_AMAS)
		if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1") && i == 0)
			continue;
#endif

		if (i)
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
		else
			sprintf(prefix_mssid, "wl%d_", band);

		if (!nvram_match(strcat_r(prefix_mssid, "bss_enabled", temp), "1"))
			continue;

		mac_filter[j] = check_macmode(nvram_safe_get(strcat_r(prefix_mssid, "macmode", temp)));
		j++;
	}
}
//Ren.E

static inline void __choose_mrate(char *prefix, int *mcast_phy, int *mcast_mcs)
{
	int phy = 3, mcs = 7;			/* HTMIX 65/150Mbps */
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
			phy = 2; mcs = 2;	/* 2G: OFDM 12Mbps */
		} else {
			phy = 3; mcs = 1;	/* 5G: HTMIX 13/30Mbps */
		}
		/* fall through */
	case IPV6_DISABLED:
		break;
	}
#endif

	if (nvram_match(strcat_r(prefix, "nmode_x", tmp), "2") ||		/* legacy mode */
	    strstr(nvram_safe_get(strcat_r(prefix, "crypto", tmp)), "tkip"))	/* tkip */
	{
		/* In such case, choose OFDM instead of HTMIX */
		phy = 2; mcs = 4;		/* OFDM 24Mbps */
	}

	*mcast_phy = phy;
	*mcast_mcs = mcs;
}

int get_bw_via_channel(int band, int channel)
{
	int wl_bw;
	char buf[32];

	snprintf(buf, sizeof(buf), "wl%d_bw", band);
	wl_bw = nvram_get_int(buf);

	if(band == 0 || channel < 14 || channel > 165 || wl_bw != 1)  {
		return wl_bw;
	}

	if (channel == 165)
		return 0;	// 20 MHz
#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
	/*
	 * ignore this mechanism because the new model will support all
	 * channels in BAND23.
	 */
#else
	else if (channel == 116 || channel == 140) {
		return 0;	// 20 MHz
	}
	else if (channel == 132 || channel == 136) {
		if(wl_bw == 0)
			return 0;
		return 2;		// 40 MHz
	}

	//check for TW band2
	snprintf(buf, sizeof(buf), "wl%d_country_code", band);
	if(nvram_match(buf, "TW")) {
		if(channel == 56)
			return 0;
		if(channel == 60 || channel == 64) {
			if(wl_bw == 0)
				return 0;
			return 2;		// 40 MHz
		}
	}
#endif

	return wl_bw;
}

/* Helper function that generate @prefix and return enable status of BSS.
 * Main WiFi is assumed always enabled due to replaced source code have same logic.
 * x:           x of wlx.y, same as band
 * y:           y of wlx.y
 * prefix:      pointer to char array
 * prefix_len:  max. size of @prefix
 * return:
 * 0:           the guest_network should be skipped due to it's not enabled, shouldn't be process,
 * 		e.g., wlx.1 on RE node that is used to keep settings for WiFi upstream connection,
 * 		or invalid parameter, @prefix may not be initialized in this case.
 * 1:           the bss should be processed, @prefix is updated.
 */
static inline int main_wifi_or_enabled_guest_network(int x, int y, char *prefix, size_t prefix_len)
{
        if (x < 0 || x >= MAX_NR_WL_IF || y < 0 || !prefix || !prefix_len)
                return 0;

        if (y == 1 && aimesh_re_node())
                return 0;

        if (y) {
                snprintf(prefix, prefix_len, "wl%d.%d_", x, y);
        } else {
                snprintf(prefix, prefix_len, "wl%d_", x);
        }

        if (y && (!y || !is_bss_enabled(prefix)))
                return 0;

        return 1;
}

/* Dump @fn content to @fp.
 * @fp:	FILE pointer
 * @fn: filename
 * @return:
 * 	0:	success
 *  otherwise:	error
 */
static int dump_file(FILE *fp, const char *fn)
{
	FILE *fp_res;
	char line[512];

	if (!fp || !fn)
		return -1;

	if (!(fp_res = fopen(fn, "r")))
		return -2;

	while (fgets(line, sizeof(line), fp_res) != NULL) {
		fprintf(fp, "%s", line);
	}
	fprintf(fp, "\n");
	fclose(fp_res);

	return 0;
}

/* Exec @cmd and dump output to @fp
 * @fp:	FILE pointer
 * @cmd: command
 * @return:
 * 	0:	success
 *  otherwise:	error
 */
static int exec_and_dump(FILE *fp, const char *cmd)
{
	FILE *fp_res;
	char line[512];

	if (!fp || !cmd || *cmd == '\0')
		return -1;

	if (!(fp_res = popen(cmd, "r")))
		return -2;

	while (fgets(line, sizeof(line), fp_res) != NULL) {
		fprintf(fp, "%s", line);
	}
	fprintf(fp, "\n");
	pclose(fp_res);

	return 0;
}

void __gen_wifi_ap_stats_log(char *fn)
{
	const int re_mode = aimesh_re_node();
	FILE *fp;
	char *c;
#if defined(RTCONFIG_ASUSCTRL)
	unsigned char ccode[2][10 + 1] = { 0 }, regspec[4 + 1] = { 0 };
	unsigned char tcode[5 + 1] = { 0 };
	unsigned char asusctrl_flags[ASUSCTRL_FLAGS_LENGTH + 1] = { 0 };
	unsigned char asusctrl_chg_sku[ASUSCTRL_CHG_SKU_LENGTH + 1] = { 0 };
	char asusctrl_flags_hex_str[3 * sizeof(asusctrl_flags)], one_hex[sizeof(" XX")];
	char asusctrl_chg_sku_hex_str[3 * sizeof(asusctrl_chg_sku)];
	struct factory_to_buf_s {
		unsigned int offset, length;
		unsigned char *buffer;
		char *hex_buf;
		unsigned int hex_buf_len;
	} factory_to_buf_tbl[] = {
		{ REG2G_EEPROM_ADDR,		10,				&ccode[0][0], NULL, 0 },
		{ REG5G_EEPROM_ADDR,		10,				&ccode[1][0], NULL, 0 },
		{ REGSPEC_ADDR,			4,				regspec, NULL, 0 },
		{ OFFSET_TERRITORY_CODE,	5,				tcode, NULL, 0 },
		{ OFFSET_ASUSCTRL_FLAGS,	ASUSCTRL_FLAGS_LENGTH,		asusctrl_flags, asusctrl_flags_hex_str, sizeof(asusctrl_flags_hex_str) },
		{ OFFSET_ASUSCTRL_CHG_SKU,	ASUSCTRL_CHG_SKU_LENGTH,	asusctrl_chg_sku, asusctrl_chg_sku_hex_str, sizeof(asusctrl_chg_sku_hex_str) },

		{ 0, 0, NULL, NULL, 0 }
	}, *f2b_ptr;
#endif

	if (!fn || *fn == '\0')
		return;

	if (!(fp = fopen(fn, "w")))
		return;

	fprintf(fp, "sw_mode [%s] wlready [%s] re_mode %d amas_ifname [%s] wlc_psta [%s] wlc_band [%s]\n",
		nvram_get("sw_mode")? : "NULL", nvram_get("wlready")? : "NULL", re_mode,
		nvram_safe_get("amas_ifname"), nvram_get("wlc_psta")? : "NULL", nvram_get("wlc_band")? : "NULL");

	if (f_exists("/proc/net/skb_recycler/count")) {
		fprintf(fp, "\n\n________________ SKB recycler ________________\n");
		fprintf(fp, "max_skbs: ");
		dump_file(fp, "/proc/net/skb_recycler/max_skbs");
		f_write_string("/proc/net/skb_recycler/count", "True", 0, 0);	/* Switch to modified view temporary */
		dump_file(fp, "/proc/net/skb_recycler/count");
	}

	/* FIXME: AP stats of each VAP. */

#if defined(RTCONFIG_ASUSCTRL)
	/* Report asusctrl related information */
	fprintf(fp, "\n\n________________ ASUSCTRL ________________\n");
	for (f2b_ptr = &factory_to_buf_tbl[0]; f2b_ptr->buffer != NULL; ++f2b_ptr) {
		if (f2b_ptr->hex_buf)
			*f2b_ptr->hex_buf = '\0';
		if (FRead(f2b_ptr->buffer, f2b_ptr->offset, f2b_ptr->length)) {
			fprintf(fp, "Read factory offset 0x%x length %d fail!\n", f2b_ptr->offset, f2b_ptr->length);
			continue;
		}
		for (c = &f2b_ptr->buffer[0]; f2b_ptr->hex_buf && f2b_ptr->hex_buf_len && *c != '\0' ; ++c) {
			snprintf(one_hex, sizeof(one_hex), "%s%2X", *f2b_ptr->hex_buf? " " : "", *c);
			strlcat(f2b_ptr->hex_buf, one_hex, f2b_ptr->hex_buf_len);
		}
	}

	fprintf(fp, "asusctrl_flags [%s]/[%s] asusctrl_chg_sku [%s]/[%s]\n",
		nvram_get("asusctrl_flags")? : "NULL", asusctrl_flags_hex_str,
		nvram_get("asusctrl_chg_sku")? : "NULL", asusctrl_chg_sku_hex_str);
	fprintf(fp, "webs_chg_sku [%s] webs_SG_mode [%s] EG_mode [%s] SG_mode [%s]\n",
		nvram_get("webs_chg_sku")? : "NULL", nvram_get("webs_SG_mode")? : "NULL",
		nvram_get("EG_mode")? : "NULL", nvram_get("SG_mode")? : "NULL");

	/* Report country name, country id of each band. */
	fprintf(fp, "regspec [%s]/[%s] regulation domain [%s]/[%s] [%s/%s] territory_code [%s]/[%s] location_code [%s]\n",
		regspec, nvram_get("reg_spec")? : "NULL", ccode[0], nvram_get("wl_reg_2g")? : "NULL",
		ccode[1], nvram_get("wl_reg_5g")? : "NULL", tcode, nvram_get("territory_code")? : "NULL",
		nvram_get("location_code")? : "NULL");
	exec_and_dump(fp, "grep -r \"\\(RegSpec\\|Country\\)\" /etc/Wireless/*");
#endif	/* RTCONFIG_ASUSCTRL */

	/* FIXME: Blocked ACS channel list. */

	/* FIXME: Wireless client list. */

	/* FIXME: Misc. statistics */

	/* FIXME: Driver settings. */

	/* FIXME: Site-survey result. */

	fclose(fp);
}

/* Test response of __gen_wifi_stats_log()
 */
int test_wifi_stats_log_main(int argc, char *argv[])
{
	if (__gen_wifi_ap_stats_log) {
		__gen_wifi_ap_stats_log("/tmp/wifi_ap_stats.log");
	}
	if (__gen_wifi_sta_stats_log) {
		__gen_wifi_sta_stats_log("/tmp/wifi_sta_stats.log");
	}

	return 0;
}

/* Test response of __gen_switch_log()
 */
int test_switch_log_main(int argc, char *argv[])
{
	if (__gen_switch_log) {
		__gen_switch_log("/tmp/switch.log");
	}

	return 0;
}

/* Enumerate a fixed value to multiple setting with @name, started at @start and repeat @cnt times. wlx.y_bss_enable won't be checked.
 * @fp:
 * @cnt:
 * @name:	%d must be included.
 * @value:
 * @return:
 *      0:      success
 *     -1:      invalid parameter
 * otherwise:   error
 */
static int __enum_mname_svalue_w_fixed_value(FILE *fp, int cnt, char *name, char *value, int start)
{
	int i;
	char tmp[64];

	if (!fp || cnt < 1 || !name || !strstr(name, "%d") || !value)
		return -1;

	for (i = 0; i < cnt; i++) {
		snprintf(tmp, sizeof(tmp), name, i + start);
		fprintf(fp, "%s=%s\n", tmp, value);
	}
	return 0;
}

static inline int enum_mname_s0_svalue_w_fixed_value(FILE *fp, int cnt, char *name, char *value) { return __enum_mname_svalue_w_fixed_value(fp, cnt, name, value, 0); }
static inline int enum_mname_s1_svalue_w_fixed_value(FILE *fp, int cnt, char *name, char *value) { return __enum_mname_svalue_w_fixed_value(fp, cnt, name, value, 1); }

/* Enumerate fixed value @cnt times, semicolon seperated string, to a single setting with @name. wlx.y_bss_enable won't be checked.
 * @fp:
 * @cnt:
 * @name:
 * @value:
 * @return:
 *      0:      success
 *     -1:      invalid parameter
 * otherwise:   error
 */
static int enum_sname_mvalue_w_fixed_value(FILE *fp, int cnt, char *name, char *value)
{
	int i;
	char tmp[128], tmpstr[256];

	if (!fp || cnt < 0 || !name || !value)
		return -1;

	for (i = 0, *tmpstr = '\0'; i < cnt; i++) {
		snprintf(tmp, sizeof(tmp), "%s%s", i? ";" : "", value);
		strlcat(tmpstr, tmp, sizeof(tmpstr));
	}
	fprintf(fp, "%s=%s\n", name, tmpstr);
	return 0;
}

/* Enumerate multiple per-BSS value, semicolon seperated string, of enabled BSS to a single setting @name. Setting of disabled guest-network is not enumerated.
 * In theory, ssid_num values are added to @fp totally.
 * @fp:
 * @band:
 * @max_y:
 * @name:
 * @nv:		XXX of wlx_XXX or wlx.y_XXX
 * @dval:       default value if wlx_XXX or wlx.y_XXX doesn't exist
 * @return:
 *      0:      success
 *     -1:      invalid parameter
 *     -2:	if wlx_XXX or wlx.y_XXX doesn't exist and @dval = NULL
 * otherwise:   error
 *
 * NOTE:
 * Main WiFi setting of RE node is expected to be saved in wlx_XXX due to wlx.1_XXX is used to save setting for upstream WiFi.
 * If a main WiFi setting of RE node is saved in wlx.1_XXX, e.g., wlx.1_closed (Hide SSID), don't use this function!
 */
static int enum_sname_mvalue_w_per_bss_value(FILE *fp, int band, int max_y, char *name, char *nv, char *dval)
{
	int i, ret = 0;
	char tmp[128], tmpstr[128], prefix[sizeof("wlXXXXXX_")];

	if (!fp || band < 0 || band >= MAX_NR_WL_IF || max_y < 0 || !name)
		return -1;

	for (i = 0, *tmpstr = '\0'; i < max_y; i++) {
		if (!main_wifi_or_enabled_guest_network(band, i, prefix, sizeof(prefix)))
			continue;

		if (nvram_pf_get(prefix, nv)) {
			snprintf(tmp, sizeof(tmp), "%s%s", i? ";" : "", nvram_pf_get(prefix, nv));
		} else {
			dbg("%s%s doesn't exist, default value [%s]\n", prefix, nv, dval? : "NULL");
			snprintf(tmp, sizeof(tmp), "%s%s", i? ";" : "", dval? : "");
			if (!dval)
				ret = -2;
		}
		strlcat(tmpstr, tmp, sizeof(tmpstr));
	}
	fprintf(fp, "%s=%s\n", name, tmpstr);
	return ret;
}

#if defined(RTCONFIG_MT798X)
#define MAX_WDS_PER_BAND	(8)	/* Max. number of WDS interface per band. */
#else
#define MAX_WDS_PER_BAND	(4)
#endif

#if defined(RTCONFIG_AVBLCHAN)
static inline void update_chlist_mask(uint64_t src_chlist_mask, uint64_t *target_chlist_mask)
{
	if (target_chlist_mask)
		*target_chlist_mask |= src_chlist_mask;
}
#else
static inline void update_chlist_mask(uint64_t src_chlist_mask, uint64_t *target_chlist_mask) { }
#endif

/* Below nvram variables are copied to wlX.1_xxx of RE node.
 * wlX_ssid
 * wlX_wpa_psk
 * wlX_crypto
 * wlX_auth_mode_x
 * wlX_wep_x
 * wlX_key
 * wlX_key1
 * wlX_key2
 * wlX_key3
 * wlX_key4
 * wlX_radius_ipaddr
 * wlX_radius_key
 * wlX_radius_port)
 * wlX_closed
 * wlX_macmode
 * wlX_maclist_x
 * wlX_ap_iolate
 *
 * The rest of wlX_xxx nvram variables are copied to wlX_xxx of RE node.
 */
int gen_ralink_config(int band, int is_iNIC)
{
#ifdef RTCONFIG_RALINK_DFS
	const int dfs_support = 1;
#else
	const int dfs_support = 0;
#endif
	int backoff[4] = { 1, 1, 1, 0 };
	char tcode[sizeof("XX/01")] = "";
	FILE *fp;
	char *str = NULL, *str2 = NULL, *str3;
	char *str_tcode __attribute__((unused)) = NULL;
	int i, j, val, bw, mssid_bw, wl_bw, ch, extcha, vbw, vbw_val;
	int cht = 0, ssid_num = 1, EXTCHA = 0, EXTCHA_MAX = 0, HTBW_MAX = 1;
	char list[2048];
	int flag_8021x = 0, txbf = 0, nmode, wds_mode, wds_count = 0;
	int wsc_configure = 0, update_unavbl_ch __attribute__((unused)) = 0;
	int warning = 0, region = 7;
	int ChannelNumMax_2G = 11;
	char tmp[128], prefix[] = "wlXXXXXXX_";
	char temp[128], prefix_mssid[] = "wlXXXXXXXXXX_mssid_";
	char tmpstr[128], tmpstr1[128] __attribute__((unused)), tmpstr2[128] __attribute__((unused));
	char *p, *p1 __attribute__((unused)), *p2 __attribute__((unused));
	char *nv, *nvp, *b;
	char *radius_server, *radius_port, *radius_key;
	int wl_key_type[MAX_NO_MSSID];
	int mcast_phy = 0, mcast_mcs = 0;
	int mac_filter[MAX_NO_MSSID];
#if defined(VHT_SUPPORT)
	int VHTBW_MAX __attribute__((unused)) = 0;
#endif
	int sw_mode  = sw_mode();
	int wlc_band = nvram_get_int("wlc_band");
	int IEEE80211H = 0;
	uint64_t blk_chlist_mask = 0;
#if defined(RTCONFIG_MUMIMO_2G) || defined(RTCONFIG_MUMIMO_5G)
	int mumimo = 0;
#endif
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	char *dl_ofdma = "0", *ul_ofdma = "0", *dl_mumimo = "0", *ul_mumimo = "0";
#endif
#if defined(RTCONFIG_AMAS) || defined(RTCONFIG_CONCURRENTREPEATER)
	char prefix_wlc[] = "wlcXXXXXX_";
#endif
#if defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
	unsigned char buffer[6] = { 0 };
	char macaddr[18] = { 0 };
	char macbuf[13] = { 0 };
#endif
#if defined(RTCONFIG_RALINK_BUILDIN_WIFI)
	char macaddr_2G[18] = { 0 };
	char macaddr_5G[18] = { 0 };
#endif
#if defined(RTCONFIG_NO_SELECT_CHANNEL)
	char *t_code_noselect_2G[]={"EU", "RU", "EE", "UK", "DE", "TR", "CZ", "JP", "SG", "CN", "UA", "KR", "AU"};
	char *t_code_noselect_5G[]={"CA", "TW", "EU", "RU", "EE", "UK", "DE", "TR", "CZ", "JP", "KR", "AA", "AU", "US"};
	char *t_code_noselect3_5G[]={"UA"}; //5G_BAND123, Skip Band3 only
#endif
#if defined(RTCONFIG_CONCURRENTREPEATER)
	int wlc_express = nvram_get_int("wlc_express");
#endif
#if defined(RTCONFIG_MFP)
	int ieee80211w = 1;
#endif
#ifdef RTCONFIG_AVBLCHAN
	uint64_t excl_chlist_mask = 0, unavbl_chlist_mask = 0;
#endif
	int unavbl_chlist_band12 = 0;
	int acs_dfs __attribute__((unused)) = nvram_get_int("acs_dfs");

	if (band < 0 || band >= ARRAY_SIZE(backoff))
		return 0;

	/* Channel listed in AutoChannelSkipList never been used even it's
	 * overlapped by control channel. If DFS channel is disabled in 160MHz,
	 * 5G is not up correctly and channel in result of iwconfig rax0 is 0.
	 * Fix acs_dfs setting in this case.
	 */
	if (!nvram_match("acs_dfs", "1")
	 && ((band == WL_5G_BAND && nvram_match("wl1_bw_160", "1"))
	  || (band == WL_5G_2_BAND && nvram_match("wl2_bw_160", "1")))) {
		nvram_set("acs_dfs", "1");
		acs_dfs = 1;
	}

 	if (nvram_match("x_Setting", "0"))  // Don't use DFS channel in default state.
		acs_dfs = 0;

	if (!is_iNIC)
	{
		_dprintf("gen ralink config\n");
		system("mkdir -p /etc/Wireless/RT2860");
#if defined(RTCONFIG_MT798X)
		if ( nvram_get_int("wifidat_dbg") == 1 ) {
			if (!(fp=fopen("/tmp/2G_gen.dat", "w+")))
				return 0;
		} else
#endif
		if (!(fp=fopen("/etc/Wireless/RT2860/RT2860.dat", "w+")))
			return 0;
	}
	else
	{
		_dprintf("gen ralink iNIC config\n");
		system("mkdir -p /etc/Wireless/iNIC");
#if defined(RTCONFIG_MT798X)
		if ( nvram_get_int("wifidat_dbg") == 1 ) {
			if (!(fp=fopen("/tmp/5G_gen.dat", "w+")))
				return 0;
		} else
#endif
		if (!(fp=fopen("/etc/Wireless/iNIC/iNIC_ap.dat", "w+")))
			return 0;
	}

	fprintf(fp, "#The word of \"Default\" must not be removed\n");
	fprintf(fp, "Default\n");
#if defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
	fprintf(fp, "DBDC_MODE=1\n");
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	nmode = nvram_pf_get_int(prefix, "nmode_x");
	bw = nvram_pf_get_int(prefix, "bw");
#ifdef RTCONFIG_AVBLCHAN
	unavbl_chlist_mask = chlist2bitmask(band, nvram_pf_get(prefix, "unavbl_ch"), ",");
	if (unavbl_chlist_mask == (unavbl_chlist_mask | CH36_M | CH40_M | CH44_M | CH48_M | CH52_M | CH56_M | CH60_M | CH64_M))
		unavbl_chlist_band12 = 1;
#endif
	strlcpy(tcode, nvram_safe_get("territory_code"), sizeof(tcode));

	/* CountryRegion: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	if (!(str = nvram_pf_get(prefix, "country_code")) || *str == '\0') {
		warning = 1;
		region = 5;
	} else {
		region = getCountryRegion2G(str);
		ChannelNumMax_2G = getChannelNumMax2G(region);
	}
	fprintf(fp, "CountryRegion=%d\n", region);

	if (dfs_support && band && nvram_pf_match(prefix, "IEEE80211H", "1"))
		IEEE80211H = 1;

	/* CountryRegion for A band: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	if (!(str = nvram_pf_get(prefix, "country_code")) || *str == '\0') {
		warning = 3;
		region = 7;
	} else {
		if (dfs_support && nvram_match("reg_spec", "JP") && nvram_pf_match(prefix, "IEEE80211H", "1"))
			str = nvram_safe_get("reg_spec");
		region = getCountryRegion5G(str, &warning, IEEE80211H);
	}
	fprintf(fp, "CountryRegionABand=%d\n", region);

	//CountryCode
	str = nvram_pf_safe_get(prefix, "country_code");
#ifdef RTN800HP
	/* EDCCAEnable: DBDC_BAND_NUM parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	if(!nvram_match("reg_spec", "CE")) {
		fprintf(fp, "EDCCAEnable=0;0\n");
	}
#endif
	if ((str2 = nvram_get("force_wifi_CC")) && *str2 != '\0'){
		fprintf(fp, "CountryCode=%s\n", str2);
	}
	else
#ifdef CE_ADAPTIVITY
	if (nvram_match("reg_spec", "CE")) {
#if defined(RTAC51U) || defined(RTAC51UP) || defined(RTAC53)
		if ((nvram_match("wl_reg_2g", "2G_CH11"))) //IN using 2G_CH11
			fprintf(fp, "CountryCode=%s\n", "IN");
		else
#endif
		{ // regular CE with 2G ch 1~13
			fprintf(fp, "CountryCode=FR\n");
#ifndef RTCONFIG_RALINK_EDCCA
			/* ED_XXX, src-ra-4300 and src-ra-mt7620 only.
			 * TxBurst and HT_RDG: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
			 */
			fprintf(fp, "ED_MODE=1\n");
			fprintf(fp, "EDCCA_AP_STA_TH=255\n");
			fprintf(fp, "EDCCA_AP_AP_TH=255\n");
			fprintf(fp, "EDCCA_FALSE_CCA_TH=3000\n");
			fprintf(fp, "TxBurst=0\n");
			fprintf(fp, "HT_RDG=0\n");
			fprintf(fp, "EDCCA_ED_TH=90\n");
			fprintf(fp, "EDCCA_BLOCK_CHECK_TH=2\n");
			fprintf(fp, "EDCCA_AP_RSSI_TH=-80\n");
#endif
		}
	} else
#endif	/* CE_ADAPTIVITY */
	{
		if (str && strlen(str)) {
#if defined(RTAC1200HP) || defined(RTCONFIG_WLMODULE_MT7615E_AP) || defined(RTAC85U) || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750) || defined(RTAX53U)
			if (nvram_match("JP_CS","1"))
				fprintf(fp, "CountryCode=JP\n");
			else
#endif
#if defined(RTCONFIG_MT798X)
				fprintf(fp, "CountryCode=%s\n", getCountryCode());
#else
				fprintf(fp, "CountryCode=%s\n", str);
#endif
		} else {
			warning = 4;
			fprintf(fp, "CountryCode=DB\n");
		}
	}

#if defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
	if (band) {
		if (nvram_match("et0macaddr", "00:11:22:33:44:55"))
			strlcpy(macaddr, "00:11:22:33:44:55", sizeof(macaddr));	//default 5G macaddress
		else {
			if (FRead(buffer, OFFSET_MAC_ADDR, 6) < 0)
				dbg("READ MAC address: Out of scope\n");
			else {
				ether_etoa(buffer, macaddr);		// 5G MAC: N+4

				if(!strcmp(macaddr, "FF:FF:FF:FF:FF:FF")) {	// In MT7629, default E2P only have 2G MAC, given a default MAC for 5G.
					if (FRead(buffer, OFFSET_MAC_ADDR_2G, 6)<0) {
						strcpy(macaddr, "00:0C:43:26:60:2C");
					}
					else
						ether_cal_b(buffer, macaddr, 4);
				}
			}
		}
	} else {
		if (nvram_match("et1macaddr", "00:11:22:33:44:58"))
			strlcpy(macaddr, "00:11:22:33:44:58", sizeof(macaddr));	//default 2G macaddress
		else {
			if (FRead(buffer, OFFSET_MAC_ADDR_2G, 6)<0) {
				dbg("READ MAC address 2G: Out of scope\n");
			} else
				ether_etoa(buffer, macaddr);
		}
	}
	fprintf(fp, "MacAddress=%s\n", macaddr); // 2G/WAN/LAN MAC: N
#if defined(RTCONFIG_RALINK_BUILDIN_WIFI)
	if (band)
		strncpy( macaddr_5G, macaddr, strlen(macaddr));
	else
		strncpy( macaddr_2G, macaddr, strlen(macaddr));
#endif

	/* guest network mac = N +1/2/3 */
	for (i = 1, j = 1; i < 4; i++) {
		sprintf(prefix_mssid, "wl%d.%d_", band, i);
		if (is_bss_enabled(prefix_mssid)) {
			ether_cal(macaddr, macbuf, i);
			fprintf(fp, "MacAddress%d=%s\n", j, macbuf);
			j++;
		}
	}
#endif  /* RTCONFIG_WLMODULE_MT7629_AP || RTCONFIG_WLMODULE_MT7915D_AP */

	//SSID Num. [MSSID Only]
#if defined(RTCONFIG_RALINK_BUILDIN_WIFI)
	if (!mssid_mac_validate(band? macaddr_5G:macaddr_2G))
#elif defined(RTCONFIG_MT798X)
	if (0)
#else
	if (!mssid_mac_validate(nvram_pf_get(prefix, "hwaddr")))
#endif
	{
		dbG("Main BSSID is not multiple of 4s!");
		ssid_num = 1;
	} else {
		for (i = 0; i < MAX_NO_MSSID; i++) {
			if (i == 1 && __aimesh_re_node(sw_mode))
				continue;

			if (i)
				snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d.%d_", band, i);
			else
				snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d_", band);

			if (i && is_bss_enabled(prefix_mssid))
				ssid_num++;
		}
	}

	if ((ssid_num < 1) || (ssid_num > MAX_NO_MSSID)) {
		warning = 0;
		ssid_num = 1;
	}

	if (__aimesh_re_node(sw_mode) || __is_rp_wlc_band(sw_mode, band)) {
		acs_dfs=0; //do not enable DFS channel for repeater/aimesh RE
		if (!__aimesh_re_node(sw_mode))
			ssid_num = 1;

		/* BssidNum, one paramter @ kernel 2.6, 3.10, 4.4, 5.4 */
		fprintf(fp, "BssidNum=%d\n", ssid_num);
		if (__aimesh_re_node(sw_mode)) {
			for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
				if (i) {
					snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d.%d_", band, i);
					if (!is_bss_enabled(prefix_mssid))
						continue;
					else
						j++;
				}
				else
					continue;

				if (strlen(nvram_pf_safe_get(prefix_mssid, "ssid")))
					snprintf(tmpstr, sizeof(tmpstr), "SSID%d=%s\n", j, nvram_pf_safe_get(prefix_mssid, "ssid"));
				else {
					warning = 5;
					snprintf(tmpstr, sizeof(tmpstr), "SSID%d=%s%d\n", j, "ASUS", j + 1);
				}
				fprintf(fp, "%s", tmpstr);
			}
		} else {
			if (band == 0)
				snprintf(tmpstr, sizeof(tmpstr), "SSID1=%s\n",  nvram_safe_get("wl0.1_ssid"));
			else
				snprintf(tmpstr, sizeof(tmpstr), "SSID1=%s\n",  nvram_safe_get("wl1.1_ssid"));
			fprintf(fp, "%s", tmpstr);
		}
	} else {
#if defined(RTCONFIG_CONCURRENTREPEATER)
		if (sw_mode == SW_MODE_AP)
			ssid_num = 1;
#endif
		fprintf(fp, "BssidNum=%d\n", ssid_num);
		//SSID
		for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
			if (i) {
				snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
				else
					j++;
			}
			else
				snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d_", band);

			if (strlen(nvram_pf_safe_get(prefix_mssid, "ssid")))
				snprintf(tmpstr, sizeof(tmpstr), "SSID%d=%s\n", j + 1, nvram_pf_safe_get(prefix_mssid, "ssid"));
			else {
				warning = 5;
				snprintf(tmpstr, sizeof(tmpstr), "SSID%d=%s%d\n", j + 1, "ASUS", j + 1);
			}
			fprintf(fp, "%s", tmpstr);
		}
	}
	for (i = ssid_num; i < 8; i++) {
		snprintf(tmpstr, sizeof(tmpstr), "SSID%d=\n", i + 1);
		fprintf(fp, "%s", tmpstr);
	}
#ifdef RTCONFIG_AIR_TIME_FAIRNESS	// Airtime Fairness
	/* VOW_Airtime_Fairness_En: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one set of parameters and follow band0's parameter!
	 */
	if (nvram_pf_match(prefix, "atf", "1"))
		fprintf(fp, "VOW_Airtime_Fairness_En=%d\n", 1);
	else
		fprintf(fp, "VOW_Airtime_Fairness_En=%d\n", 0);
#endif

#if defined(RTCONFIG_MT798X)
	/* WHNAT: kernel 4.4+: one parameter @ kernel 4.4, 5.4 */
#if defined(CE_ADAPTIVITY)
	if (nvram_match("reg_spec", "CE") && (sw_mode()==SW_MODE_REPEATER && nvram_get_int("wlc_psta") == 1))
		fprintf(fp, "WHNAT=0\n");
	else
#endif
	fprintf(fp, "WHNAT=1\n");

	/* AMSDU_NUM: BssidNum parameters
	 *      src-ra-openwrt-4110's mt7915
	 *      src-ra-openwrt-4210's mt7915_v7400
	 *      kernel 5.4
	 */
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "AMSDU_NUM", "8");

	/* BSSColorValue: kernel 5.4 only: one or two parameters depends DBDC_MODE is enabled or not! */
	enum_sname_mvalue_w_fixed_value(fp, 1, "BSSColorValue", "255");

	/* HT_LDPC:
	 * BssidNum parameters:
	 *      kernel 3.10: src-mtk3.5's mt7663, mt7663_v6020, mt7663e
	 *      kernel 3.10: src-ra-5010's mt7615e, mt7615e_4410, mt7615e_4221
	 *      kernel 4.4: src-ra-openwrt-4110, src-ra-openwrt-4210
	 *      kernel 5.4:
	 * one parameter
	 *      kernel 2.6:
	 *      kernel 3.10: src-mtk3.5's mt7628, src-ra-5010's mt7615e_4402, mt7615e_5040, mt7615e_man
	 */
#if (LINUX_KERNEL_VERSION > KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_LDPC", "1");
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_LDPC", "1");
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_LDPC", "1");
#endif

	/* PPEnable: one or two parameters, depends on DBDC_MODE
	 *      kernel 4.4: src-ra-openwrt-4110's mt7915, src-ra-openwrt-4210's mt7915_v7400
	 *      kernel 5.4
	 */
	if (band)
		fprintf(fp, "PPEnable=1\n");
	else
		fprintf(fp, "PPEnable=0\n");
#endif
	//Network Mode
	/* WirelessMode: BssidNum parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * kernel 5.4:
	 *      1. Parse parameter of each BSS respectively.
	 *      2. Copy parameter of 1st BSS to another BSS if it doesn't have valid parameter.
	 * kernel 2.6 ~ 4.4:
	 *      1. Parse parameter of 1st BSS and copy it to 2~BssidNum BSS.
	 *      2. Parse parameters of 2~BssidNum BSS.
	 */
	if (!(str = nvram_pf_get(prefix, "nmode_x")) || *str == '\0')
		warning = 7;
	if (band) {
		if (nmode == 0) {	// Auto
#if defined(VHT_SUPPORT)
#if defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
			if (nvram_match("wl1_11ax", "1"))
				fprintf(fp, "WirelessMode=%d\n", 17);	// A + AN + AC + AX mixed
			else
#endif
				fprintf(fp, "WirelessMode=%d\n", 14);	// A + AN + AC mixed

			VHTBW_MAX = 1;
#else
			fprintf(fp, "WirelessMode=%d\n", 8);	// A + AN mixed
#endif
		}
		else if (nmode == 1) {	// N Only
			fprintf(fp, "WirelessMode=%d\n", 11);	// N in 5G
		}
#if defined(VHT_SUPPORT)
		else if (nmode == 8) {	// AN/AC Mixed
			fprintf(fp, "WirelessMode=%d\n", 15);	// AN + AC mixed
			VHTBW_MAX = 1;
		}
#endif
		else if (nmode == 2)	// A
			fprintf(fp, "WirelessMode=%d\n", 2);
		else {			// A,N[,AC]
#if defined(VHT_SUPPORT)
			fprintf(fp, "WirelessMode=%d\n", 14);
			VHTBW_MAX = 1;
#else
			fprintf(fp, "WirelessMode=%d\n", 8);
#endif
		}
	} else {
		if (nmode == 0)		// B,G,N
#if defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
			if (nvram_match("wl0_11ax", "1"))
				fprintf(fp, "WirelessMode=%d\n", 16); // bgn + AX mixed
			else
#endif
				fprintf(fp, "WirelessMode=%d\n", 9);
		else if (nmode == 2)	// B,G
			fprintf(fp, "WirelessMode=%d\n", 0);
		else if (nmode == 1)	// N
			fprintf(fp, "WirelessMode=%d\n", 6);
		else			// B,G,N
			fprintf(fp, "WirelessMode=%d\n", 9);
	}

#if defined(RTCONFIG_AMAS_MTK_EZWDS)
	if (nvram_match("cfg_master", "1") || nvram_match("re_mode", "1")) {
		/* MapMode: one parameter, kernel 4.4+ */
		fprintf(fp, "MapMode=%d\n", 1); //turnkey mode:1 ; api mode:3
	}
#endif
#if defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
	/* TxCmdMode: one parameter, kernel 4.4+ */
	/* TWTSupport: DBDC_NUM parameters, kernel 4.4+, copy to all BssidNum BSS */
	fprintf(fp, "TxCmdMode=%d\n", 1);

	if (nvram_pf_match(prefix, "twt", "1")) {
		fprintf(fp, "TWTSupport=%d\n", 1);
	} else {
		fprintf(fp, "TWTSupport=%d\n", 0);
	}

	/* MboSupport, kernel 3.10+: BssidNum parameters. */
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "MboSupport", nvram_pf_get(prefix, "mbo_enable")? : "0");
#endif

	/* MuOfdmaDlEnable, MuOfdmaUlEnable, MuMimoDlEnable, MuMimoUlEnable
	 * BssidNum parameters: kernel 4.4+
	 *      last parameter is reuse for the rest of BSS if number of parameter is not enough.
	 */
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	if (nvram_pf_match(prefix, "11ax", "1")) {
		if (nvram_pf_match(prefix, "ofdma", "1")) {		// DL OFDMA Only
			dl_ofdma = "1";
		}
		else if (nvram_pf_match(prefix, "ofdma", "2")) {	// DL+UL OFDMA
			dl_ofdma = ul_ofdma = "1";
		}
		else if (nvram_pf_match(prefix, "ofdma", "3")) {	// DL+UL OFDMA + HE MU-MIMO
			dl_ofdma = ul_ofdma = dl_mumimo = ul_mumimo = "1";
		}
		else if (nvram_pf_match(prefix, "ofdma", "4")) {	// DL OFDMA + HE MU-MIMO
			dl_ofdma = dl_mumimo = "1";
		}
	}

	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "MuOfdmaDlEnable", dl_ofdma);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "MuOfdmaUlEnable", ul_ofdma);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "MuMimoDlEnable", dl_mumimo);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "MuMimoUlEnable", ul_mumimo);
#endif	/* kernel 4.4+ */

	/* RRMEnable, max MAX_MBSSID_NUM parameters
	 * BssidNum parameters:
	 *      kernel 3.10+
	 *      src-ra-4300 (kernel 2.6)
	 * Another kernel 2.6 based WiFi driver doesn't support it!
	 */
#if defined(RTCONFIG_AMAS)
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RRMEnable", "1");
#else
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RRMEnable", "0");
#endif
#endif  /* RTCONFIG_WLMODULE_MT7915D_AP || RTCONFIG_MT798X */

	/* FIXME: FixedTxMode: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * parameter is not specified!
	 */
	fprintf(fp, "FixedTxMode=\n");

#if (LINUX_KERNEL_VERSION < KERNEL_VERSION(3,10,0))
	/* TxRate, parsing code not found, maybe obsoleted */
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "TxRate", "0");
#endif

	/* Channel
	 * BssidNum parameters: kernel 3.10
	 * DBDC_BAND_NUM parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 * See RTMPChannelCfg() if it available.
	 */
	for (i = 0; i < MAX_NO_MSSID; i++) {
		if (__is_rp_wlc_band(sw_mode, band) && i != 1)
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i && sw_mode == SW_MODE_REPEATER) {
			snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			cht =  nvram_pf_get_int(prefix_mssid, "channel");
		} else {
			snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d_", band);
			cht =  nvram_pf_get_int(prefix_mssid, "channel");
		}
	}
	fprintf(fp, "Channel=%d\n", cht);

#if defined(RTCONFIG_MT798X)
	/* mgmrateset: BssidNum parameters @ kernel 4.4+
	 * Turn on CONFIG_RA_PHY_RATE_SUPPORT for mgmrateset command.
	 */
        if (band == WL_2G_BAND) {
                /* If legacy and Disable 11b = true or N-only and Disable 11b = false, fix-up Disable 11b.
                 * Because Disable 11b checkbox is not available in legacy/N-only.
                 */
                if (nvram_pf_match(prefix, "nmode_x", "2") && !nvram_pf_match(prefix, "rateset", "default"))
                        nvram_pf_set(prefix, "rateset", "default");
                else if (nvram_pf_match(prefix, "nmode_x", "1") && !nvram_pf_match(prefix, "rateset", "ofdm"))
                        nvram_pf_set(prefix, "rateset", "ofdm");
        }
	if (band == WL_2G_BAND && !nvram_pf_match(prefix, "nmode_x", "2") && nvram_pf_match(prefix, "rateset", "ofdm")) {
                /* disable 802.11b rate and use 6Mbps to send mgmt frame.
                 * mgmrateset[1-2]=[ratetype]-[phymode]-[mcs]
                 * ratetype: 1: beacon, 2: mgmt
                 * phymode: 1: CCK, 2: OFDM, 3: HT, 4: VHT
                 * mcs: MCS value
                 */
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "mgmrateset1", "1-2-0");	/* Use 6Mbps (MCS0) to send beacon frame. */
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "mgmrateset2", "2-2-0");	/* Use 6Mbps (MCS0) to seng mgmt. frame. */
	}
#endif

	/* BasicRate: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * wlX_rateset doesn't exist in GUI anymore, we don't need below code.
	 */
	if (!band) {
		/*
		 * not supported in 5G mode
		 */
#if defined(RTCONFIG_MT798X)
                if (nvram_pf_match(prefix, "rateset", "ofdm")) {
			fprintf(fp, "BasicRate=%d\n", 0);
                }
#else
		if (!(str = nvram_pf_get(prefix, "rateset")) || *str == '\0') {
			warning = 9;
			str = "15";
		}
		if (!strcmp(str, "default"))	// 1, 2, 5.5, 11
			fprintf(fp, "BasicRate=%d\n", 15);
		else if (!strcmp(str, "all"))	// 1, 2, 5.5, 6, 11, 12, 24
			fprintf(fp, "BasicRate=%d\n", 351);
		else if (!strcmp(str, "12"))	// 1, 2
			fprintf(fp, "BasicRate=%d\n", 3);
		else
			fprintf(fp, "BasicRate=%d\n", 15);
#endif
	}

	/* BeaconPeriod
	 * DBDC_BAND_NUM parameter: kernel 5.4
	 * one parameter: kernel 2.6 ~ 4.4
	 */
	if (!(str = nvram_pf_get(prefix, "bcn")) || *str == '\0') {
		warning = 10;
		str = "100";
	}
	val = safe_atoi(str);
	if (val > 1000 || val < 20) {
		nvram_pf_set(prefix, "bcn", "100");
		val = 100;
	}
	fprintf(fp, "BeaconPeriod=%d\n", val);

	/* DTIM Period:
	 * BssidNum parameter:
	 *      kernel 4.4: (src-ra-openwrt-4110's mt_wifi_5050, mt_wifi_7915, src-ra-openwrt-4210)
	 *		mt7915's driver copied 1st BSS's parameter to another BSS if it's zero.
	 *		But mt5050 doesn't have similiar logic.
	 *      kernel 5.4: 1st BSS's parameter is copied to another BSS if it doesn't have parameter
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 4.4: (src-ra-openwrt-4110's mt_wifi)
	 */
	if (!(str = nvram_pf_get(prefix, "dtim")) || *str == '\0') { /* Only wlX_dtim available. */
		warning = 11;
		str = "1";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "DtimPeriod", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "DtimPeriod", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "DtimPeriod", str);
#endif

	/* TxPower
	 * DBDC_BAND_NUM parameters: kernel 3.10, 4.4, 5.4
	 * one parmaeter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "txpower")) || *str == '\0') {
		warning = 12;
		str = "100";
	}
	fprintf(fp, "TxPower=%d\n", nvram_pf_match(prefix, "radio", "0")? 0 : safe_atoi(str));

	/* DisableOLBC: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	fprintf(fp, "DisableOLBC=%d\n", 0);

	/* BGProtection: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	if (!(str = nvram_pf_get(prefix, "gmode_protection")) || *str == '\0') {
		warning = 13;
		str = "auto";
	}
	fprintf(fp, "BGProtection=%d\n", (!strcmp(str, "auto"))? 0 : 2);

	/* TxPreamble: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	if (!(str = nvram_pf_get(prefix, "plcphdr")))
		str = "long";
	fprintf(fp, "TxPreamble=%d\n", (!strcmp(str, "short"))? 1 : 0);

	/* RTSThreshold, Default=2347
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * DBDC_BAND_NUM parameters: kernel 3.10
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "rts")) || *str == '\0') {	/* Only wlX_rts available. */
		warning = 14;
		str = "2347";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RTSThreshold", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "RTSThreshold", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "RTSThreshold", str);
#endif

	/* FragThreshold  Default=2346
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, kernel 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "frag")) || *str == '\0') {       /* Only wlX_frag available. */
		warning = 15;
		str = "2346";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "FragThreshold", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "FragThreshold", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "FragThreshold", str);
#endif

	/* TxBurst: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	if (!(str = nvram_pf_get(prefix, "frameburst")) || *str == '\0') {
		warning = 16;
		str = "on";
	}
#ifdef CE_ADAPTIVITY
	if (nvram_match("reg_spec", "CE") || nvram_match("reg_spec", "EAC"))
#if defined(RTCONFIG_MT798X) // control this value in Tcode
		fprintf(fp, "TxBurst=0\n");
#else
		;
#endif
	else
#endif	/* CE_ADAPTIVITY */
		fprintf(fp, "TxBurst=%d\n", strcmp(str, "off") ? 1 : 0);

	/* PktAggregate: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	if (!(str = nvram_pf_get(prefix, "PktAggregate")) || *str == '\0') {
		warning = 17;
		str = "1";
	}
	fprintf(fp, "PktAggregate=%d\n", safe_atoi(str));

	/* FreqDelta: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	fprintf(fp, "FreqDelta=%d\n", 0);

	/* WmmCapable
	 * BssidNum parameters: kernel 2.6, 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, kernel 3.10
	 */
	/* always enable WMM as long as legacy client inhibited, e.g., N only, AN/AC(/AX) Mixed. */
	val = nvram_pf_get_int(prefix, "nmode_x");
	if ((val == 1 || val == 8) && !nvram_pf_match(prefix, "wme", "on"))
		nvram_pf_set(prefix, "wme", "on");

	str = nvram_pf_match(prefix, "wme", "off")? "0" : "1";
	/* Original code always repeat parameter ssid_num times. Forget those driver that take first one only. */
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "WmmCapable", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "WmmCapable", str);
#endif

	/* APAifsn, APCwmin, APCwmax, APTxop, APACM, BSSAifsn, BSSCwmin, BSSCwmax, BSSTxop, BSSACM
	 * four parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 */
	fprintf(fp, "APAifsn=3;7;1;1\n");
	fprintf(fp, "APCwmin=4;4;3;2\n");
	fprintf(fp, "APCwmax=6;10;4;3\n");
	fprintf(fp, "APTxop=0;0;94;47\n");
	fprintf(fp, "APACM=0;0;0;0\n");
	fprintf(fp, "BSSAifsn=3;7;2;2\n");
	fprintf(fp, "BSSCwmin=4;4;3;2\n");
	fprintf(fp, "BSSCwmax=10;10;4;3\n");
	fprintf(fp, "BSSTxop=0;0;94;47\n");
	fprintf(fp, "BSSACM=0;0;0;0\n");

	/* AckPolicy: four parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one set of parameters and follow band0's parameter!
	 */
	enum_sname_mvalue_w_fixed_value(fp, 4, "AckPolicy", !nvram_pf_match(prefix, "wme_no_ack", "on")? "0" : "1");

	snprintf(prefix, sizeof(prefix), "wl%d_", band);

	/* APSDCapable
	 * BssidNum parameters: kernel 4.4, 5.4
	 * HW_BEACON_MAX_NUM parameters: kernel 2.6, 3.10
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "wme_apsd")) || *str == '\0')	/* Only wlX_wme_apsd available. */
		warning = 18;
	str = !nvram_pf_match(prefix, "wme_apsd", "off")? "1" : "0";
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "APSDCapable", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "APSDCapable", str);
#endif

	/* DLSDCapable
	 * BssidNum parameters: kernel 2.6, 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "DLSCapable")) || *str == '\0') { /* Only wlx_XXX available. */
		warning = 19;
		str = "0";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "DLSCapable", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "DLSCapable", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "DLSCapable", str);
#endif

	/* NoForwarding pre SSID: BssidNum parameters: kernel 2.6, 3.10, 4.4, 5.4 */
	/* AiMesh guest network is supported:
	 * 1. Both CAP/RE use wlx_ap_isolate for main WiFi.
	 * 2. CAP use wlx.[1-3]_ap_isolate for guest network, RE use wlx.[2-4]_ap_isolate for guest_network.
	 *    So far, only one guest network per band is supported on RE, wlx.2.
	 *    GUI set wlx.[1-3]_ap_isolate based on wlx.[1-3]_lanaccess.
	 * AiMesh is not supported:
	 * 1. Main WiFi and all guest network use wlx_ap_isolate.
	 */
#if !defined(RTCONFIG_AMAS) || !defined(RTCONFIG_AMAS_WGN)
	if (!(str = nvram_pf_get(prefix, "ap_isolate")) || *str == '\0')
		str = "0";
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "NoForwarding", str);
#else
#if 1
        for (i = 0, *tmpstr = '\0', p = tmpstr; i < MAX_NO_MSSID; i++) {
                if (i == 0 && __aimesh_re_node(sw_mode))
                        continue;
                if (i) {
                        sprintf(prefix_mssid, "wl%d.%d_", band, i);
                        if (!is_bss_enabled(prefix_mssid))
                                continue;
                        if(p != tmpstr)
                                p += sprintf(p, ";");
                }
                else
                        sprintf(prefix_mssid, "wl%d_", band);
                str = nvram_pf_safe_get(prefix_mssid, "ap_isolate");
		if(strlen(str)==0) //default value
			str = "0";

                if (sw_mode == SW_MODE_REPEATER) {
                        if(i == 1)
                                p = tmpstr + sprintf(tmpstr, "%s", str);
                        else if (i > 1)
                                p += sprintf(p, "%s", str);
                } else
                        p += sprintf(p, "%s", str);
        }
        fprintf(fp, "NoForwarding=%s\n", tmpstr);
#else	
	enum_sname_mvalue_w_per_bss_value(fp, band, MAX_NO_MSSID, "NoForwarding", "ap_isolate", "0");
#endif
#endif
	/* NoForwardingBTNBSSID: one parameter @ kernel 2.6, 3.10, 4.4, and 5.4 */
	//fprintf(fp, "NoForwardingBTNBSSID=%d\n", safe_atoi(str));  // handle by ebtables.

	/* HideSSID: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < MAX_NO_MSSID; i++) {
		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;
		if (i) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if(p != tmpstr)
				p += sprintf(p, ";");
		}
		else
			sprintf(prefix_mssid, "wl%d_", band);

		str = nvram_pf_safe_get(prefix_mssid, "closed");
		if (sw_mode == SW_MODE_REPEATER) {
			if(i == 1)
				p = tmpstr + sprintf(tmpstr, "%s", str);
			else if (i > 1)
				p += sprintf(p, "%s", str);
		} else
			p += sprintf(p, "%s", str);
	}
	fprintf(fp, "HideSSID=%s\n", tmpstr);

	/* ShortSlot: Backward compatible to 802.11b client.
	 * DBDC_BAND_NUM parameters: kernel 5.4
	 * one parameter: kernel 2.6, 3.10, 4.4
	 * Set it as zero if N only mode that inhibit legacy client.
	 */
	fprintf(fp, "ShortSlot=%d\n", nvram_pf_match(prefix, "nmode_x", "1")? 0 : 1);
	/* AutoChannelSelect
	 * DBDC_BAND_NUM parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "channel")) || *str == '\0')
		warning = 21;
	ch = nvram_pf_get_int(prefix, "channel");
	if (__is_rp_wlc_band(sw_mode, band)) {
#if defined(RTCONFIG_WLMODULE_MT7615E_AP) || defined(RTCONFIG_WLMODULE_MT7622_AP) || defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
		fprintf(fp, "AutoChannelSelect=%d\n", 3);	// MT7615 CSA(Busy Time)
#elif defined(RTCONFIG_WLMODULE_MT7663E_AP)
		if (band)
			fprintf(fp, "AutoChannelSelect=%d\n", 3);	// MT7615 CSA(Busy Time), not support for MT7628
#if defined(RTCONFIG_WLMODULE_MT7628_AP)
		else
			fprintf(fp, "AutoChannelSelect=%d\n", 1);
#endif
#else
		fprintf(fp, "AutoChannelSelect=%d\n", 1);
#endif

		if (dfs_support && band) {
			mssid_bw = nvram_pf_get_int(prefix_mssid, "bw");
			snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d.1_", band);
			if (nvram_pf_get_int(prefix_mssid, "channel") == 0) {
				if (mssid_bw == 1 || mssid_bw == 3) {
					if (band && IEEE80211H)
						blk_chlist_mask = CH165_M | CH116_M | CH132_M | CH136_M | CH140_M;
				}
				else if (mssid_bw == 2) {
					if (band && IEEE80211H)
						blk_chlist_mask = CH165_M | CH116_M | CH140_M;
				}

				fprintf(fp,"AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
			}
		}
	} else {
		if (ch == 0) {
			if (dfs_support && band && IEEE80211H) {
#if defined(RTCONFIG_WLMODULE_MT7615E_AP) \
 || defined(RTCONFIG_WLMODULE_MT7663E_AP) \
 || defined(RTCONFIG_WLMODULE_MT7622_AP) \
 || defined(RTCONFIG_WLMODULE_MT7629_AP) \
 || defined(RTCONFIG_WLMODULE_MT7915D_AP) \
 || defined(RTCONFIG_MT798X)
				fprintf(fp, "AutoChannelSelect=%d\n", 3);		// MT7615 CSA(Busy Time)
#else
				fprintf(fp, "AutoChannelSelect=%d\n", 1);		//NEED rule 1 for DFS
#endif
			} else {
#if defined(RTCONFIG_WLMODULE_MT7615E_AP) \
 || defined(RTCONFIG_WLMODULE_MT7622_AP) \
 || defined(RTCONFIG_WLMODULE_MT7629_AP) \
 || defined(RTCONFIG_WLMODULE_MT7915D_AP) \
 || defined(RTCONFIG_MT798X)
				fprintf(fp, "AutoChannelSelect=%d\n", 3);		// MT7615 CSA(Busy Time)
#elif defined(RTCONFIG_WLMODULE_MT7663E_AP)
				if (band)
					fprintf(fp, "AutoChannelSelect=%d\n", 3);	// MT7615 CSA(Busy Time), not support for MT7628
#if defined(RTCONFIG_WLMODULE_MT7628_AP)
				else
					fprintf(fp, "AutoChannelSelect=%d\n", 2);
#endif
#else
				fprintf(fp, "AutoChannelSelect=%d\n", 2);
#endif
			}

			blk_chlist_mask = 0;
			if (band && bw > 0) {
#ifdef RTN56U
				if (nvram_pf_match(prefix, "country_code", "TW"))
					blk_chlist_mask |= CH56_M | CH165_M;
				else
#endif
				if ((p = nvram_get("wl_reg_5g")) && (strchr(p, '4') || strcmp(p, "5G_ALL")==0))
					blk_chlist_mask |= CH165_M;	// skip 165 in A band when bw setting to 20/40Mhz or 40Mhz.

				if (dfs_support && band && IEEE80211H) {
#if defined(RTCONFIG_MT798X)
					/* wl_bw: 0/1/2/3/5: 20MHz/Auto/40MHz/80MHz/160MHz */
					if (nvram_match("reg_spec", "CE")) { //BAMD123
						uint64_t wheather    = CH116_M | CH120_M | CH124_M | CH128_M; //bw > 20MHz
						if (bw == 2) // 40MHz
							blk_chlist_mask |= wheather | CH140_M;
						else if (nvram_pf_match(prefix, "bw_160", "1") && (bw == 5 || bw == 1)) { //160MHz
							if (unavbl_chlist_band12 == 0) // 160MHz and band12 available. use band12
								blk_chlist_mask |= wheather | CH100_M | CH104_M | CH108_M | CH112_M | CH132_M | CH136_M | CH140_M;
							else
								blk_chlist_mask |= CH132_M | CH136_M | CH140_M;
						}
						else if (bw > 0)  // auto/80MHz
						{
							if (unavbl_chlist_band12 && (unavbl_chlist_mask & (CH100_M | CH104_M | CH108_M | CH112_M)))
								blk_chlist_mask |= CH132_M | CH136_M | CH140_M;
							else
								blk_chlist_mask |= wheather | CH132_M | CH136_M | CH140_M;
						}
					}
					else if (is_tcode_country("AA")) { //ALL
						if (bw == 2) // 40MHz
							blk_chlist_mask |= CH116_M | CH140_M | CH165_M;
						else if (bw == 1 || bw == 3) // auto/80MHz
							blk_chlist_mask |= CH116_M | CH132_M | CH136_M | CH140_M | CH165_M;
						else if (bw == 5) // 160MHz
							blk_chlist_mask |= CH100_M | CH104_M | CH108_M | CH112_M | CH116_M | CH132_M | CH136_M | CH140_M | CH149_M | CH153_M | CH157_M | CH161_M | CH165_M;
					}
					else if (is_tcode_country("JP")) { //BAND123
						if (bw == 5) // 160MHz
							blk_chlist_mask |= CH132_M | CH136_M | CH140_M | CH144_M;
					}
					else if (is_tcode_country("CN")) { //BAND124, ALL
						if (bw == 5) // 160MHz
							blk_chlist_mask |= CH149_M | CH153_M | CH157_M | CH161_M | CH165_M;
						else if (bw > 0)
							blk_chlist_mask |= CH165_M;
					}
					else if (nvram_match("wl_reg_5g", "5G_ALL")) { //TW, US
						if (bw == 5) // 160MHz
							blk_chlist_mask |= CH149_M | CH153_M | CH157_M | CH161_M | CH165_M;
						else if (bw > 0)
							blk_chlist_mask |= CH165_M;
					}
#else
					/* wl_bw: 0/1/2/3/5: 20MHz/Auto/40MHz/80MHz/160MHz */
					if (bw == 1 || bw == 3) {
						if (nvram_match("reg_spec", "EAC"))
							blk_chlist_mask |= CH116_M;	// EAC_RU doesn't need to skip 132,136,140 under auto mode
						else {
							if (is_tcode_country("JP"))
								blk_chlist_mask |= CH132_M | CH136_M | CH140_M ;		// skip  132 136 140 under auto mode ,JP SKU
							else
								blk_chlist_mask |= CH116_M | CH132_M | CH136_M | CH140_M;	// skip 116 132 136 140 under auto mode
						}
					}
					else if (bw == 2) {
						if (is_tcode_country("JP"))
							blk_chlist_mask |= CH140_M;		// skip 140
						else
							blk_chlist_mask |= CH116_M | CH140_M;	// skip 116 140
					}
#endif // MT798X
				}
			}
#if defined(RTCONFIG_MT798X)
			else if (band && dfs_support && IEEE80211H && nvram_match("reg_spec", "CE")) { //20MHz in EU
				blk_chlist_mask |= CH120_M | CH124_M | CH128_M;	// skip whether channel
			}
#endif

#if defined(RTCONFIG_ASUSCTRL)
			if (band == WL_5G_BAND || band == WL_5G_2_BAND) {
				if (asus_ctrl_en(ASUSCTRL_ACS_IGNORE_BAND1))
					blk_chlist_mask |= CH36_M | CH40_M | CH44_M | CH48_M;
				if (asus_ctrl_en(ASUSCTRL_ACS_IGNORE_BAND2))
					blk_chlist_mask |= CH52_M | CH56_M | CH60_M | CH64_M;
				if (asus_ctrl_en(ASUSCTRL_ACS_IGNORE_BAND3))
					blk_chlist_mask |= CH100_M | CH104_M | CH108_M | CH112_M | CH116_M | CH120_M
						         | CH124_M | CH128_M | CH132_M | CH136_M | CH140_M | CH144_M;
				if (asus_ctrl_en(ASUSCTRL_ACS_IGNORE_BAND4))
					blk_chlist_mask |= CH149_M | CH153_M | CH157_M | CH161_M | CH165_M;
			}
#endif

#if defined(RTCONFIG_MT798X)
			if (band == WL_2G_BAND && nvram_match("acs_ch13", "0"))
				blk_chlist_mask |= CH12_M | CH13_M;
			if (dfs_support && band && !acs_dfs) {
				uint64_t dfs = 0;

				if (nvram_match("wl_reg_5g", "5G_BAND123") || nvram_match("wl_reg_5g", "5G_ALL")) {
					dfs =  CH52_M |  CH56_M |  CH60_M |  CH64_M | CH100_M | CH104_M | CH108_M | CH112_M
					    | CH116_M | CH120_M | CH124_M | CH128_M | CH132_M | CH136_M | CH140_M | CH144_M;
				} else if (nvram_match("wl_reg_5g", "5G_BAND24") || nvram_match("wl_reg_5g", "5G_BAND124")) {
					dfs = CH52_M | CH56_M | CH60_M | CH64_M;
				}
				blk_chlist_mask |= dfs;
			}
#endif	/* RTCONFIG_MT798X */

#ifdef RTCONFIG_MTK_TW_AUTO_BAND4 //NCC: for 5G BAND24 & BAND14
			if (band) {
				//autochannel selection  but skip 5G band1 & band2, TW only
				if (
				  is_tcode_country("TW") ||
#ifdef RTCONFIG_HAS_5G
				   nvram_match("wl_reg_5g","5G_BAND24") ||
#endif
#if defined(RTCONFIG_NEW_REGULATION_DOMAIN)
				   (nvram_match("reg_spec","NCC")  ||
				    nvram_match("reg_spec","NCC2"))
#else
				   (nvram_pf_match(prefix, "country_code", "TW") ||
				    nvram_pf_match(prefix, "country_code", "Z3"))
#endif
				 )
					blk_chlist_mask |= CH36_M | CH40_M | CH44_M | CH48_M | CH52_M | CH56_M | CH60_M | CH64_M;
			}
#endif
#if defined(RTCONFIG_NO_SELECT_CHANNEL)
			if (!band) {
				nvram_set("skip_channel_2g", "0");	//for GUI checkbox
				//2G_CH13, 2G No Selection T-Code, Skip channel 12, 13
				if (nvram_match("wl_reg_2g", "2G_CH13")) {
					for (i = 0; i < ARRAY_SIZE(t_code_noselect_2G); i++) {
						if (!is_tcode_country(t_code_noselect_2G[i]))
							continue;
#if !defined(RTCONFIG_AMAS)
						nvram_set("skip_channel_2g", "CH13");
						if (nvram_match("acs_ch13", "0"))
							blk_chlist_mask = CH12_M | CH13_M;
#endif /* !RTCONFIG_AMAS */
						update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
						update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
						update_unavbl_ch = 1;
						fprintf(fp,"AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
					}
				}
			} else {
				nvram_set("skip_channel_5g", "0");	//for GUI checkbox
				//5G_BAND14, 5G No Selection T-Code, skip band1
				if (nvram_match("wl_reg_5g", "5G_BAND14")) {
					for (i = 0; i < ARRAY_SIZE(t_code_noselect_5G); i++) {
						if (!is_tcode_country(t_code_noselect_5G[i]))
							continue;
#if !defined(RTCONFIG_AMAS)
						nvram_set("skip_channel_5g", "band1");
						if (nvram_match("acs_band1", "0")) {
							blk_chlist_mask = 0;
							if (nvram_match("location_code", "AU"))
								blk_chlist_mask |= CH116_M | CH132_M | CH136_M | CH140_M | CH165_M;
							else if (nvram_match("location_code", "AA"))
								blk_chlist_mask |= CH165_M;
							else
								blk_chlist_mask |= CH36_M | CH40_M | CH44_M | CH48_M | CH165_M;
						}
#endif	/* !RTCONFIG_AMAS */
						update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
						update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
						update_unavbl_ch = 1;
						fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
					}
				}

				//5G_BAND123, 5G No Selection T-Code
				if (nvram_match("wl_reg_5g", "5G_BAND123")) {
					//skip band3
					for (i = 0; i < ARRAY_SIZE(t_code_noselect3_5G); i++) {
						if (!is_tcode_country(t_code_noselect3_5G[i]))
							continue;
#if !defined(RTCONFIG_AMAS)
						nvram_set("skip_channel_5g", "band3");
						if (safe_atoi(nvram_safe_get("acs_band3")) == 0) {
							blk_chlist_mask = CH100_M | CH104_M | CH108_M | CH112_M | CH116_M | CH120_M
									| CH124_M | CH128_M | CH132_M | CH136_M | CH140_M;
						}
#endif	/* !RTCONFIG_AMAS */
						update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
						update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
						update_unavbl_ch = 1;
						fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
					}
					//skip band2,band3
					for (i = 0; i < ARRAY_SIZE(t_code_noselect_5G); i++) {
						if (!is_tcode_country(t_code_noselect_5G[i]))
							continue;

						blk_chlist_mask = 0;
#if !defined(RTCONFIG_AMAS)
						nvram_set("skip_channel_5g", "band23");
						if (nvram_match("location_code", "RU") && acs_dfs && nvram_match("acs_band3", "0")) {
							blk_chlist_mask |= CH100_M | CH104_M | CH108_M | CH112_M | CH116_M | CH120_M
									| CH124_M | CH128_M | CH132_M | CH136_M | CH140_M;
							update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
						}
						else
#endif //AMAS
						{
							if (!acs_dfs) {
								blk_chlist_mask |= CH52_M | CH56_M | CH60_M | CH64_M | CH100_M | CH104_M
										| CH108_M | CH112_M | CH116_M | CH120_M | CH124_M
										| CH128_M | CH132_M | CH136_M | CH140_M;
								update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
							} else {
								if (dfs_support && band && IEEE80211H) {
									if (bw == 1 || bw == 3) {	// 20/40/80MHz or 80MHz
										blk_chlist_mask |= CH116_M | CH132_M | CH136_M | CH140_M;	// skip 116 132 136 140 under auto mode
										update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
									} else if (bw == 2) {		// 40 MHz
										blk_chlist_mask |= CH116_M | CH140_M;	// skip 116 140 under auto mode
										update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
									}
								}
							}
						}
						update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
						update_unavbl_ch = 1;
						fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
						break;
					}
				}

				//5G_BAND24 & 5G_BAND4 & 5G_BAND124 skip 165
				if (nvram_match("wl_reg_5g", "5G_BAND24")
				 || nvram_match("wl_reg_5g", "5G_BAND4")
				 || nvram_match("wl_reg_5g", "5G_BAND124"))
				{
					blk_chlist_mask = CH165_M;
					update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
					update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
					update_unavbl_ch = 1;
					fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
				}

				//5G_ALL skip 116,120,124,128,165
				if (nvram_match("wl_reg_5g", "5G_ALL")) {
					for (i = 0; i < ARRAY_SIZE(t_code_noselect_5G); i++) {
						if (!is_tcode_country(t_code_noselect_5G[i]))
							continue;
						if (band && IEEE80211H) {
							if (nvram_pf_match(prefix, "bw", "1")
							 || nvram_pf_match(prefix, "bw", "3")) {	// 20/40/80MHz or 80MHz
								if (nvram_match("location_code", "KR"))
									blk_chlist_mask = CH132_M | CH136_M | CH140_M | CH165_M;
								else
									blk_chlist_mask = CH116_M | CH132_M | CH136_M | CH140_M | CH165_M;	// skip 116 132 136 140 under auto mode
								update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
							}
							else if (nvram_pf_match(prefix, "bw", "2")) {	// 40 MHz
								if (nvram_match("location_code", "KR"))
									blk_chlist_mask = CH132_M | CH136_M | CH140_M | CH165_M;
								else
									blk_chlist_mask = CH116_M | CH140_M | CH165_M;				// skip 116 140 under auto mode
								update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
							}
						} else {
							blk_chlist_mask = CH116_M | CH120_M | CH124_M | CH128_M | CH165_M;
							update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
						}
						update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
						update_unavbl_ch = 1;
						fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
						break;
					}
				}
			} /* !band */

#ifdef RTCONFIG_AVBLCHAN
			if (!update_unavbl_ch) {
				update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
				fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
			}

			if (excl_chlist_mask && !__aimesh_re_node(sw_mode))
				nvram_pf_set(prefix, "block_ch", bitmask2chlist(band, excl_chlist_mask, ","));
			else
				nvram_pf_unset(prefix, "block_ch");
#endif

#else	/* !RTCONFIG_NO_SELECT_CHANNEL */

#if !defined(RTCONFIG_MT798X)
			//only band 4 for auto channel select if support band 4
			if (band) {
				if (strchr(nvram_safe_get("wl_reg_5g"), '4')) {	//check band4 support?
					if (strchr(nvram_safe_get("wl_reg_5g"), '1')){	//skip band 1
						blk_chlist_mask |= CH36_M | CH40_M | CH44_M | CH48_M;
					}
					if (strchr(nvram_safe_get("wl_reg_5g"), '2')) {	//skip band 2
						blk_chlist_mask |= CH52_M | CH56_M | CH60_M | CH64_M;
					}
				}
			}
#endif

#ifdef RTCONFIG_AVBLCHAN
			update_chlist_mask(blk_chlist_mask, &excl_chlist_mask);
			update_chlist_mask(unavbl_chlist_mask, &blk_chlist_mask); //combine
			if (excl_chlist_mask && !__aimesh_re_node(sw_mode))
				nvram_pf_set(prefix, "block_ch", bitmask2chlist(band, excl_chlist_mask, ","));
			else
				nvram_pf_unset(prefix, "block_ch");
#endif
			fprintf(fp, "AutoChannelSkipList=%s\n", bitmask2chlist(band, blk_chlist_mask, ";"));
#endif	/* RTCONFIG_NO_SELECT_CHANNEL */
		} else {
			/* wlX_channel != 0 */
			fprintf(fp, "AutoChannelSelect=%d\n", 0);
#ifdef RTCONFIG_AVBLCHAN
			nvram_pf_unset(prefix, "block_ch");
#endif
#if defined(RALINK_DBDC_MODE)
			fprintf(fp, "AutoChannelSkipList=\n");
#endif
		}
	}

	/* IEEE8021X
	 * BssidNum parameters: kernel 2.6, 3.10, 4.4, 5.4
	 */
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
		}
		else
			sprintf(prefix_mssid, "wl%d_", band);

		if (nvram_pf_match(prefix_mssid, "auth_mode_x", "radius"))
			p += sprintf(p, "%s", "1;");
		else
			p += sprintf(p, "%s", "0;");
	}
	if(p != tmpstr)
		*(p-1) = '\0';
	fprintf(fp, "IEEE8021X=%s\n", tmpstr);

	/* IEEE80211H: one parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * If multiple parameters are specified, last one is used.
	 */
	fprintf(fp, "IEEE80211H=%d\n", IEEE80211H);

	/* DfsEnable: one parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
#ifdef RTCONFIG_RALINK_DFS
#if defined (RTCONFIG_WLMODULE_MT7615E_AP) || defined (RTCONFIG_WLMODULE_MT7663E_AP) || defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7622_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
	if (band) {
		if (IEEE80211H)
			fprintf(fp, "DfsEnable=%d\n", 1);
		else
			fprintf(fp, "DfsEnable=%d\n", 0);
	}
#endif
#endif

	/* RDRegion, CarrierDetect: one parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * MT798X: FCC, CE, JAP, JAP_W53, JAP_W56, and KR (undocument).
	 * Another WiFi driver: FCC, CE, JAP, JAP_W53, JAP_W56.
	 * "CE" is chosen if invalid parameter is given.
	 * NOTE: Merged DBDC*.dat has only one parameter for CarrierDetect and follow band0's parameter!
	 * NOTE: Merged DBDC*.dat has only one parameter for RDRegion and follow band1's parameter!
	 */
#ifdef RTCONFIG_AP_CARRIER_DETECTION
#if defined(RTAC1200HP)
	if(nvram_match("JP_CS","1"))
#else
	if (nvram_pf_match(prefix, "country_code", "JP"))
#endif
	{
		fprintf(fp, "RDRegion=%s\n", "JAP");
		fprintf(fp, "CarrierDetect=%d\n", 1);
	}
	else
#endif
	{
#ifdef RTCONFIG_RALINK_DFS
#if defined(RTCONFIG_MT798X)
		char tmp[MAX_REGSPEC_LEN+1];
		char *reg_val = nvram_safe_get("reg_spec");
		if (nvram_contains_word("rc_support", "loclist")) {
			// fetch original regspec
			if(FRead(tmp, REGSPEC_ADDR, MAX_REGSPEC_LEN) >= 0) {
				int i;
				tmp[MAX_REGSPEC_LEN] = '\0';
				for (i = 0; i < MAX_REGSPEC_LEN; i++) {
					if (tmp[i] == 0xFF)
						tmp[i] = '\0';
					if (tmp[i] == '\0')
						break;
				}
				if (strcmp(reg_val, tmp)) {
					dbg("RDRegion use org regspec:%s, loc:%s\n", tmp, reg_val);
					reg_val = tmp;
				}
			}
		}
		if (!strcmp(reg_val, "JP"))
			fprintf(fp, "RDRegion=%s\n", "JAP");
		else if (!strcmp(reg_val, "NCC"))
			fprintf(fp, "RDRegion=%s\n", "FCC");
		else if (!strcmp(reg_val, "CN"))
			fprintf(fp, "RDRegion=%s\n", "CE");
		else
			fprintf(fp, "RDRegion=%s\n", reg_val);
#else
		if (nvram_match("reg_spec", "JP"))
			fprintf(fp, "RDRegion=%s\n", "JAP");
#if defined (RTCONFIG_WLMODULE_MT7615E_AP) || defined (RTCONFIG_WLMODULE_MT7663E_AP)
		else if((band && nvram_match("reg_spec", "EAC")) || (band && nvram_match("reg_spec", "KCC")))
			fprintf(fp, "RDRegion=%s\n", "CE");
#elif defined(RTCONFIG_WLMODULE_MT7915D_AP)	// DBDC mode
		else if(nvram_match("reg_spec", "EAC") || nvram_match("reg_spec", "AU") || nvram_match("reg_spec", "KCC"))
			fprintf(fp, "RDRegion=%s\n", "CE");
#endif
		else
			fprintf(fp, "RDRegion=%s\n",nvram_get("reg_spec"));
#endif // MT798X
#if defined (RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
		/* for Zero-Wait DFS */
		/* DfsZeroWaitDefault, DfsDedicatedZeroWait: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
		fprintf(fp, "DfsZeroWaitDefault=%d\n", 0);
		fprintf(fp, "DfsDedicatedZeroWait=%d\n", 0);
#endif
#else // RALINK_DFS
		fprintf(fp, "RDRegion=\n");
#endif
		fprintf(fp, "CarrierDetect=%d\n", 0);
	}
	/* ChannelGeography, PreAntSwitch
	 * one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 */
	fprintf(fp, "PreAntSwitch=\n");
#if (LINUX_KERNEL_VERSION < KERNEL_VERSION(3,10,0))
	/* PhyRateLimit, FineAGC
	 * one parameter @ kernel 2.6, only src-ra-4300 and src-ra-mt7620 have parsing code.
	 */
	fprintf(fp, "PhyRateLimit=%d\n", 0);
	fprintf(fp, "FineAGC=%d\n", 0);
#endif
	/* DebugFlags, StreamMode
	 * one parameter @ kernel 2.6, 3.4, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter for DebugFlags,StreamMode and follow band0's parameter!
	 */
	fprintf(fp, "DebugFlags=%d\n", 0);
	if (band) {
#if defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
		fprintf(fp, "StreamMode=%d\n", 0);
#else
		fprintf(fp, "StreamMode=%d\n", 3);	// from RT3883_EVT.TXT for test 5G in factory. But the meaning of value is unknown.
#endif
	} else {
		fprintf(fp, "StreamMode=%d\n", 0);
	}

	/* StreamModeMac%d
	 * one parameter @ kernel 2.6, 3.10, 4.4, 5.4, should be a MAC address.
	 */
	fprintf(fp, "StreamModeMac0=\n");
	fprintf(fp, "StreamModeMac1=\n");
	fprintf(fp, "StreamModeMac2=\n");
	fprintf(fp, "StreamModeMac3=\n");
	/* StationKeepAlive: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "StationKeepAlive", "0");
	/* CSPeriod: channel switch period (beacon count)
	 * one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	fprintf(fp, "CSPeriod=10\n");
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
 && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,11,0))
	/* DfsLowerLimit, DfsUpperLimit, FCCParamCh%d, CEParamCh%d, JAPParamCh%d, JAPW53ParamCh%d
	 * kernel 2.6 ~ 3.10 only: one parameter @ kernel 2.6, 3.10
	 */
	fprintf(fp, "DfsLowerLimit=%d\n", 0);
	fprintf(fp, "DfsUpperLimit=%d\n", 0);
	/* DfsIndoor, DFSParamFromConfig, kernel 2.6 ~ 3.10 only
	 * one parameter @ kernel 2.6, 3.10
	 */
	fprintf(fp, "DfsIndoor=%d\n", 0);
	fprintf(fp, "DFSParamFromConfig=%d\n", 0);
	fprintf(fp, "FCCParamCh0=\n");
	fprintf(fp, "FCCParamCh1=\n");
	fprintf(fp, "FCCParamCh2=\n");
	fprintf(fp, "FCCParamCh3=\n");
	fprintf(fp, "CEParamCh0=\n");
	fprintf(fp, "CEParamCh1=\n");
	fprintf(fp, "CEParamCh2=\n");
	fprintf(fp, "CEParamCh3=\n");
	fprintf(fp, "JAPParamCh0=\n");
	fprintf(fp, "JAPParamCh1=\n");
	fprintf(fp, "JAPParamCh2=\n");
	fprintf(fp, "JAPParamCh3=\n");
	fprintf(fp, "JAPW53ParamCh0=\n");
	fprintf(fp, "JAPW53ParamCh1=\n");
	fprintf(fp, "JAPW53ParamCh2=\n");
	fprintf(fp, "JAPW53ParamCh3=\n");
#endif  /* kernel 2.6 ~ 3.10 */

	/* GreenAP: one parameter @ kernel 2.6, 3.10, 4.4, 5.4, Only wlx_GreenAP available.
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
#if defined(RTN65U)
	fprintf(fp, "GreenAP=%d\n", 1);
#elif defined(RTN14U) || defined(RTAC52U) || defined(RTAC51U) || defined(RTAC51UP) || defined(RTAC53) || defined(RTN11P) || defined(RTN300) || defined(RTN54U) || defined(RTAC1200HP) || defined(RTN56UB1) || defined(RTAC54U) || defined(RTN56UB2) || defined(RTAC1200GA1)  || defined(RTAC1200GU) || defined(RTCONFIG_MTK_REP)
	/// MT7620 GreenAP will impact TSSI, force to disable GreenAP here..
	//  MT7620 GreenAP cause bad site survey result on RTAC52 2G.
	fprintf(fp, "GreenAP=%d\n", 0);
#else
	if (!(str = nvram_pf_get(prefix, "GreenAP")) || *str == '\0') {
		warning = 22;
		str = "0";
	}
	fprintf(fp, "GreenAP=%d\n", safe_atoi(str));
#endif

	/* PreAuth: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	for (i = 0, *tmpstr = '\0'; i < MAX_NO_MSSID; i++) {
		if (!main_wifi_or_enabled_guest_network(band, i, prefix_mssid, sizeof(prefix_mssid)))
			continue;
		snprintf(tmp, sizeof(tmp), "%s;", strstr(nvram_pf_safe_get(prefix_mssid, "auth_mode_x"), "wpa")? "1" : "0");
		strlcat(tmpstr, tmp, sizeof(tmpstr));
	}
	if (*tmpstr != '\0')
		*(tmpstr + strlen(tmpstr) - 1) = '\0';
	fprintf(fp, "PreAuth=%s\n", tmpstr);

	/* AuthMode: BssidNum parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if (p != tmpstr)
				p += sprintf(p, ";");
		}
		else
			sprintf(prefix_mssid, "wl%d_", band);

		if (!(str = nvram_pf_get(prefix_mssid, "auth_mode_x")) || *str == '\0') {
			warning = 24;
			str = "open";
		}
		if (!strcmp(str, "open")) {
			p += sprintf(p, "%s", "OPEN");
		}
		else if (!strcmp(str, "shared")) {
			p += sprintf(p, "%s", "SHARED");
		}
		else if (!strcmp(str, "psk")) {
			p += sprintf(p, "%s", "WPAPSK");
		}
		else if (!strcmp(str, "psk2")) {
			p += sprintf(p, "%s", "WPA2PSK");
		}
		else if (!strcmp(str, "pskpsk2")) {
			p += sprintf(p, "%s", "WPAPSKWPA2PSK");
		}
		else if (!strcmp(str, "wpa")) {
			p += sprintf(p, "%s", "WPA");
			flag_8021x = 1;
		}
		else if (!strcmp(str, "wpa2")) {
			p += sprintf(p, "%s", "WPA2");
			flag_8021x = 1;
		}
		else if (!strcmp(str, "sae")) {
			p += sprintf(p, "%s", "WPA3PSK");
		}
		else if (!strcmp(str, "psk2sae")) {
			p += sprintf(p, "%s", "WPA2PSKWPA3PSK");
		}
		else if (!strcmp(str, "wpawpa2")) {
			p += sprintf(p, "%s", "WPA1WPA2");
			flag_8021x = 1;
		}
		else if ((!strcmp(str, "radius"))) {
			p += sprintf(p, "%s", "OPEN");
			flag_8021x = 1;
		}
		else {
			warning = 23;
			p += sprintf(p, "%s", "OPEN");
		}
	}
	fprintf(fp, "AuthMode=%s\n", tmpstr);

	/* EncrypType: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if (p != tmpstr)
				p += sprintf(p, ";");
		}
		else
			sprintf(prefix_mssid, "wl%d_", band);

		if ((nvram_pf_match(prefix_mssid, "auth_mode_x", "open")
			&& nvram_pf_match(prefix_mssid, "wep_x", "0")))
			p += sprintf(p, "%s", "NONE");
		else if ((nvram_pf_match(prefix_mssid, "auth_mode_x", "open") && nvram_pf_invmatch(prefix_mssid, "wep_x", "0"))
		      || nvram_pf_match(prefix_mssid, "auth_mode_x", "shared")
		      || nvram_pf_match(prefix_mssid, "auth_mode_x", "radius"))
			p += sprintf(p, "%s", "WEP");
		else if (nvram_pf_match(prefix_mssid, "crypto", "tkip")) {
			p += sprintf(p, "%s", "TKIP");
		}
		else if (nvram_pf_match(prefix_mssid, "crypto", "aes")) {
			p += sprintf(p, "%s", "AES");
		}
		else if (nvram_pf_match(prefix_mssid, "crypto", "tkip+aes")) {
			p += sprintf(p, "%s", "TKIPAES");
		}
		else {
			warning = 25;
			p += sprintf(p, "%s", "NONE");
		}
	}
	fprintf(fp, "EncrypType=%s\n", tmpstr);

#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
 && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,11,0))
	/* WapiPsk%d, WapiPskType, Wapiifname, kernel 2.6 ~ 3.10 only: one parameter.
	 * WapiAsCertPath, WapiUserCertPath, WapiAsIpAddr, WapiAsPort, kernel 2.6 ~ 3.10 only
	 * BssidNum parameters: kernel 3.10
	 * one parameter: kernel 2.6, 3.10
	 */
	fprintf(fp, "WapiPsk1=\n");
	fprintf(fp, "WapiPsk2=\n");
	fprintf(fp, "WapiPsk3=\n");
	fprintf(fp, "WapiPsk4=\n");
	fprintf(fp, "WapiPsk5=\n");
	fprintf(fp, "WapiPsk6=\n");
	fprintf(fp, "WapiPsk7=\n");
	fprintf(fp, "WapiPsk8=\n");
	fprintf(fp, "WapiPskType=\n");
	fprintf(fp, "Wapiifname=\n");
	fprintf(fp, "WapiAsCertPath=\n");
	fprintf(fp, "WapiUserCertPath=\n");
	fprintf(fp, "WapiAsIpAddr=\n");
	fprintf(fp, "WapiAsPort=\n");
#endif  /* kernel 2.6 ~ 3.10 */

	/* RekeyMethod: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * FIXME: wlx_guest_num are not sync to RE node.
	 */
	for (i = 0, *tmpstr = '\0'; i < MAX_NO_MSSID; i++) {
		if (!main_wifi_or_enabled_guest_network(band, i, prefix_mssid, sizeof(prefix_mssid)))
			continue;

		if (!nvram_pf_get(prefix_mssid, "wpa_gtk_rekey"))
			warning = 26;
		snprintf(tmp, sizeof(tmp), "%s;", nvram_pf_get_int(prefix_mssid, "wpa_gtk_rekey")? "TIME" : "DISABLE");
		strlcat(tmpstr, tmp, sizeof(tmpstr));
	}
	if (*tmpstr != '\0')
		*(tmpstr + strlen(tmpstr) - 1) = '\0';
	fprintf(fp, "RekeyMethod=%s\n", tmpstr);

	/* RekeyInterval: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * FIXME: wlx_guest_num are not sync to RE node.
	 */
	for (i = 0, *tmpstr = '\0'; i < MAX_NO_MSSID; i++) {
		if (!main_wifi_or_enabled_guest_network(band, i, prefix_mssid, sizeof(prefix_mssid)))
			continue;

		snprintf(tmp, sizeof(tmp), "%d;", nvram_pf_get_int(prefix_mssid, "wpa_gtk_rekey"));
		strlcat(tmpstr, tmp, sizeof(tmpstr));
	}
	if (*tmpstr != '\0')
		*(tmpstr + strlen(tmpstr) - 1) = '\0';
	fprintf(fp, "RekeyInterval=%s\n", tmpstr);

#if defined(RTCONFIG_MFP)
	ieee80211w = nvram_pf_get_int(prefix, "mfp");
	if (__aimesh_re_node(sw_mode)) {	//RE
		if (nvram_pf_match(prefix, "auth_mode_x", "sae")) {
			if (ieee80211w != 2)
				ieee80211w = 2; //for SAE client/PMF client
		} else if (nvram_pf_match(prefix, "auth_mode_x", "psk2sae")) {
			if (ieee80211w != 1)
				ieee80211w = 1; //for SAE client/PMF client/Non PMF client.
		}
		else
			if (ieee80211w != 0)
				ieee80211w = 0;
	}
	else {
		//skip psk2sae & sae
		if (nvram_pf_match(prefix,"auth_mode_x", "open")
		 || nvram_pf_match(prefix,"auth_mode_x", "shared")
		 || nvram_pf_match(prefix,"auth_mode_x", "radius"))
		{
			if(ieee80211w != 0)
				ieee80211w=0;
		}
		else if (nvram_pf_match(prefix,"auth_mode_x", "wpa")
		      || nvram_pf_match(prefix,"auth_mode_x", "wpa2")
		      || nvram_pf_match(prefix,"auth_mode_x", "wpawpa2")
		      || nvram_pf_match(prefix,"auth_mode_x", "psk")
		      || nvram_pf_match(prefix,"auth_mode_x", "psk2")
		      || nvram_pf_match(prefix,"auth_mode_x", "pskpsk2"))
		{
			if(ieee80211w ==2)
				ieee80211w=1;
		}
	}

     	if (nvram_pf_get_int(prefix, "mfp") != ieee80211w)
		nvram_pf_set_int(prefix, "mfp", ieee80211w);

	/* PMFMFPC, PMFMFPR, PMFSHA256: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	for (i = 0, *tmpstr = '\0', *tmpstr1 = '\0', *tmpstr2 = '\0', p = tmpstr, p1 = tmpstr1, p2 = tmpstr2; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if (p != tmpstr)
				p += sprintf(p, ";");
			if (p1 != tmpstr1)
				p1 += sprintf(p1, ";");
			if (p2 != tmpstr2)
				p2 += sprintf(p2, ";");
		}
		else
			sprintf(prefix_mssid, "wl%d_", band);

		if (!(str = nvram_pf_get(prefix_mssid, "auth_mode_x")))
			str = "UNKNOWN";
		if (!(str2 = nvram_pf_get(prefix, "mfp")))
			str2 = "0";
		if (!strcmp(str2, "2")) {       // Required
			if (!strcmp(str, "sae")) {      // wpa3 use reuqired
				p += sprintf(p, "%d", 1);
				p1 += sprintf(p1, "%d", 1);
				p2 += sprintf(p2, "%d", 1);
			}
			else if ((!strcmp(str, "wpa")) || (!strcmp(str, "wpa2")) || (!strcmp(str, "wpawpa2"))
			      || (!strcmp(str, "psk")) || (!strcmp(str, "psk2")) || (!strcmp(str, "pskpsk2"))
			      || (!strcmp(str, "psk2sae")))
			{
				p += sprintf(p, "%d", 1);
				p1 += sprintf(p1, "%d", 0);
				p2 += sprintf(p2, "%d", 0);
			}
			else {  // open,shared,radius
				p += sprintf(p, "%d", 0);
				p1 += sprintf(p1, "%d", 0);
				p2 += sprintf(p2, "%d", 0);
			}
		}
		else if (!strcmp(str2, "1")) {  // Capable
			if (!strcmp(str, "sae")) {      // wpa3 use reuqired
				p += sprintf(p, "%d", 1);
				p1 += sprintf(p1, "%d", 1);
				p2 += sprintf(p2, "%d", 1);
			}
			else if ((!strcmp(str, "wpa")) || (!strcmp(str, "wpa2")) || (!strcmp(str, "wpawpa2"))
			      || (!strcmp(str, "psk")) || (!strcmp(str, "psk2")) || (!strcmp(str, "pskpsk2"))
			      || (!strcmp(str, "psk2sae")))
			{
				p += sprintf(p, "%d", 1);
				p1 += sprintf(p1, "%d", 0);
				p2 += sprintf(p2, "%d", 0);
			}
			else {  // open,shared,radius
				p += sprintf(p, "%d", 0);
				p1 += sprintf(p1, "%d", 0);
				p2 += sprintf(p2, "%d", 0);
			}
		}
		else {  // Disable
			if (!strcmp(str, "sae")) {      // wpa3 use reuqired
				p += sprintf(p, "%d", 1);
				p1 += sprintf(p1, "%d", 1);
				p2 += sprintf(p2, "%d", 1);
			}
			else {
				p += sprintf(p, "%d", 0);
				p1 += sprintf(p1, "%d", 0);
				p2 += sprintf(p2, "%d", 0);
			}
		}
	}
	fprintf(fp, "PMFMFPC=%s\n", tmpstr);
	fprintf(fp, "PMFMFPR=%s\n", tmpstr1);
	fprintf(fp, "PMFSHA256=%s\n", tmpstr2);
#endif

	/* PMKCachePeriod (in minutes): BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * Only wlx_pmk_cache available.
	 */
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "PMKCachePeriod", nvram_pf_get(prefix, "pmk_cache")? : "10");

	if (__is_rp_wlc_band(sw_mode, band)) {
		if (band == 0)
			sprintf(tmpstr, "WPAPSK1=%s\n", nvram_safe_get("wl0.1_wpa_psk"));
		else
			sprintf(tmpstr, "WPAPSK1=%s\n", nvram_safe_get("wl1.1_wpa_psk"));
	 	fprintf(fp, "%s", tmpstr);
	} else {
		/* WPAPSK%d: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
		for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
			if (i == 0 && __aimesh_re_node(sw_mode))
				continue;

			if (i) {
				sprintf(prefix_mssid, "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
				else
					j++;
			}
			else
				sprintf(prefix_mssid, "wl%d_", band);

			if (__aimesh_re_node(sw_mode))
				sprintf(tmpstr, "WPAPSK%d=%s\n", j, nvram_pf_safe_get(prefix_mssid, "wpa_psk"));
			else
				sprintf(tmpstr, "WPAPSK%d=%s\n", j + 1, nvram_pf_safe_get(prefix_mssid, "wpa_psk"));
			fprintf(fp, "%s", tmpstr);
		}
	}
	for (i = ssid_num; i < 8; i++) {
		sprintf(tmpstr, "WPAPSK%d=\n", i + 1);
		fprintf(fp, "%s", tmpstr);
	}

	/* DefaultKeyID: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if (p != tmpstr)
				p += sprintf(p, ";");
		}
		else
			sprintf(prefix_mssid, "wl%d_", band);

		str = nvram_pf_safe_get(prefix_mssid, "key");
		p += sprintf(p, "%s", str);
	}
	fprintf(fp, "DefaultKeyID=%s\n", tmpstr);

	memset(wl_key_type, 0, sizeof(wl_key_type));
	for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i)
			snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d.%d_", band, i);
		else
			snprintf(prefix_mssid, sizeof(prefix_mssid), "wl%d_", band);

		if ((!i) || (i && is_bss_enabled(prefix_mssid))) {
			str = strcat_r(prefix_mssid, "key", temp);
			str2 = nvram_safe_get(str);
			sprintf(list, "%s%s", str, str2);

			if ((strlen(nvram_safe_get(list)) == 5) || (strlen(nvram_safe_get(list)) == 13)) {
				wl_key_type[j] = 1;
				warning = 271;
			}
			else if ((strlen(nvram_safe_get(list)) == 10) || (strlen(nvram_safe_get(list)) == 26)) {
				wl_key_type[j] = 0;
				warning = 272;
			}
			else if ((strlen(nvram_safe_get(list)) != 0)) {
				warning = 273;
			}

			j++;
		}
	}

	/* Key1Type(0 -> Hex, 1->Ascii)
	 * Key%dType: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 */
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < ssid_num; i++) {
		p += sprintf(p, "%d;", wl_key_type[i]);
	}
	if(p != tmpstr)
		*(p-1) = '\0';
	fprintf(fp, "Key1Type=%s\n", tmpstr);

	// Key1Str
	if (__is_rp_wlc_band(sw_mode, band)) {
		if (band == 0)
			sprintf(tmpstr, "Key1Str1=%s\n", nvram_safe_get("wl0.1_key1"));
		else
			sprintf(tmpstr, "Key1Str1=%s\n", nvram_safe_get("wl1.1_key1"));
	 	fprintf(fp, "%s", tmpstr);
	} else {
		for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
			if (i == 0 && __aimesh_re_node(sw_mode))
				continue;

			if (i) {
				sprintf(prefix_mssid, "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
				else
					j++;
			}
			else
				sprintf(prefix_mssid, "wl%d_", band);

			if (__aimesh_re_node(sw_mode))
				sprintf(tmpstr, "Key1Str%d=%s\n", j, nvram_pf_safe_get(prefix_mssid, "key1"));
			else
				sprintf(tmpstr, "Key1Str%d=%s\n", j + 1, nvram_pf_safe_get(prefix_mssid, "key1"));
			fprintf(fp, "%s", tmpstr);
		}
	}
	for (i = ssid_num; i < 8; i++) {
		sprintf(tmpstr, "Key1Str%d=\n", i + 1);
		fprintf(fp, "%s", tmpstr);
	}

	// Key2Type
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < ssid_num; i++) {
		p += sprintf(p, "%d;", wl_key_type[i]);
	}
	if(p != tmpstr)
		*(p-1) = '\0';
	fprintf(fp, "Key2Type=%s\n", tmpstr);

	// Key2Str
	if (__is_rp_wlc_band(sw_mode, band)) {
		if (band == 0)
			sprintf(tmpstr, "Key2Str1=%s\n", nvram_safe_get("wl0.1_key2"));
		else
			sprintf(tmpstr, "Key2Str1=%s\n", nvram_safe_get("wl1.1_key2"));
	 	fprintf(fp, "%s", tmpstr);
	} else {
		for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
			if (i == 0 && __aimesh_re_node(sw_mode))
				continue;

			if (i) {
				sprintf(prefix_mssid, "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
				else
					j++;
			}
			else
				sprintf(prefix_mssid, "wl%d_", band);

			if (__aimesh_re_node(sw_mode))
				sprintf(tmpstr, "Key2Str%d=%s\n", j, nvram_pf_safe_get(prefix_mssid, "key2"));
			else
				sprintf(tmpstr, "Key2Str%d=%s\n", j + 1, nvram_pf_safe_get(prefix_mssid, "key2"));
			fprintf(fp, "%s", tmpstr);
		}
	}
	for (i = ssid_num; i < 8; i++) {
		sprintf(tmpstr, "Key2Str%d=\n", i + 1);
		fprintf(fp, "%s", tmpstr);
	}

	// Key3Type
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < ssid_num; i++) {
		p += sprintf(p, "%d;", wl_key_type[i]);
	}
	if(p != tmpstr)
		*(p-1) = '\0';
	fprintf(fp, "Key3Type=%s\n", tmpstr);

	// Key3Str
	if (__is_rp_wlc_band(sw_mode, band)) {
		if (band == 0)
			sprintf(tmpstr, "Key3Str1=%s\n", nvram_safe_get("wl0.1_key3"));
		else
			sprintf(tmpstr, "Key3Str1=%s\n", nvram_safe_get("wl1.1_key3"));
	 	fprintf(fp, "%s", tmpstr);
	} else {
		for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
			if (i == 0 && __aimesh_re_node(sw_mode))
				continue;

			if (i) {
				sprintf(prefix_mssid, "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
				else
					j++;
			}
			else
				sprintf(prefix_mssid, "wl%d_", band);

			if (__aimesh_re_node(sw_mode))
				sprintf(tmpstr, "Key3Str%d=%s\n", j, nvram_pf_safe_get(prefix_mssid, "key3"));
			else
				sprintf(tmpstr, "Key3Str%d=%s\n", j + 1, nvram_pf_safe_get(prefix_mssid, "key3"));
			fprintf(fp, "%s", tmpstr);
		}
	}
	for (i = ssid_num; i < 8; i++) {
		sprintf(tmpstr, "Key3Str%d=\n", i + 1);
		fprintf(fp, "%s", tmpstr);
	}

	// Key4Type
	for (i = 0, *tmpstr = '\0', p = tmpstr; i < ssid_num; i++) {
		p += sprintf(p, "%d;", wl_key_type[i]);
	}
	if(p != tmpstr)
		*(p-1) = '\0';
	fprintf(fp, "Key4Type=%s\n", tmpstr);

	// Key4Str
	if (__is_rp_wlc_band(sw_mode, band)) {
		if (band == 0)
			sprintf(tmpstr, "Key4Str1=%s\n", nvram_safe_get("wl0.1_key4"));
		else
			sprintf(tmpstr, "Key4Str1=%s\n", nvram_safe_get("wl1.1_key4"));
	 	fprintf(fp, "%s", tmpstr);
	} else {
		for (i = 0, j = 0; i < MAX_NO_MSSID; i++) {
			if (i == 0 && __aimesh_re_node(sw_mode))
				continue;

			if (i) {
				sprintf(prefix_mssid, "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
				else
					j++;
			}
			else
				sprintf(prefix_mssid, "wl%d_", band);

			if (__aimesh_re_node(sw_mode))
				sprintf(tmpstr, "Key4Str%d=%s\n", j, nvram_pf_safe_get(prefix_mssid, "key4"));
			else
				sprintf(tmpstr, "Key4Str%d=%s\n", j + 1, nvram_pf_safe_get(prefix_mssid, "key4"));
			fprintf(fp, "%s", tmpstr);
		}
	}
	for (i = ssid_num; i < 8; i++) {
		sprintf(tmpstr, "Key4Str%d=\n", i + 1);
		fprintf(fp, "%s", tmpstr);
	}

	/* VLANTag, kernel 3.10+
	 * BssidNum parameters:
	 *      kernel 4.4: src-ra-openwrt-4110's mt5050
	 *      kernel 3.10: src-ra-5010's mt7615e_5040
	 * one parameter: kernel 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
#if defined(RTCONFIG_MT798X)
#if defined(RTCONFIG_AMAS_WGN)
	fprintf(fp, "VLANTag=%d\n", is_wgn_enabled() ? 1 : 0);
	if (sw_mode == SW_MODE_AP && nvram_match("re_mode", "1"))
		fprintf(fp, "STAVLANTag=%d\n", is_wgn_enabled() ? 1 : 0);
#else
	fprintf(fp, "VLANTag=0\n");
#endif
#endif

#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
 && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,11,0))
	/* HT_HTC, src-ra-4300 and src-ra-mt7620 only, kernel 2.6: one parameter. */
	if (!(str = nvram_pf_get(prefix, "HT_HTC")) || *str == '\0') {
		warning = 28;
		str = "1";
	}
	fprintf(fp, "HT_HTC=%d\n", safe_atoi(str));
#endif

	/* HT_RDG: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	if (!(str = nvram_pf_get(prefix, "HT_RDG")) || *str == '\0') {
		warning = 29;
		str = "0";
	}
#ifdef CE_ADAPTIVITY
	if (nvram_match("reg_spec", "CE"))
#if defined(RTCONFIG_MT798X)
		fprintf(fp, "HT_RDG=0\n");
#else
		;
#endif
	else
#endif	/* CE_ADAPTIVITY */
	fprintf(fp, "HT_RDG=%d\n", safe_atoi(str));

	/* HT_OpMode
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "mimo_preamble")) || *str == '\0') {
		warning = 31;
		str = "mm";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_OpMode", (strcmp(str, "mm"))? "1" : "0");
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_OpMode", (strcmp(str, "mm"))? "1" : "0");
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_OpMode", (strcmp(str, "mm"))? "1" : "0");
#endif

	/* HT_MpduDensity
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "HT_MpduDensity")) || *str == '\0') {
		warning = 32;
		str = "5";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_MpduDensity", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_MpduDensity", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_MpduDensity", str);
#endif

	bw = nvram_pf_get_int(prefix, "bw");
	wl_bw = get_bw_via_channel(band, ch);
	if (band) {
		if (ch != 0) {
			if ((ch ==  36) || (ch ==  44) || (ch ==  52) || (ch ==  60) || (ch == 100) || (ch == 108)
			 || (ch == 116) || (ch == 124) || (ch == 132) || (ch == 140) || (ch == 149) || (ch == 157)) {
				EXTCHA = 1;
			}
			else if ((ch ==  40) || (ch ==  48) || (ch ==  56) || (ch ==  64) || (ch == 104) || (ch == 112)
			      || (ch == 120) || (ch == 128) || (ch == 136) || (ch == 144) || (ch == 153) || (ch == 161)) {
				EXTCHA = 0;
			} else {
				HTBW_MAX = 0;
			}
		}
	} else {
		if (ch == 0)
			EXTCHA_MAX = 1;
		else if ((ch >=1) && (ch <= 4))
			EXTCHA_MAX = 1;
		else if ((ch >= 5) && (ch <= 7))
			EXTCHA_MAX = 1;
		else if ((ch >= 8) && (ch <= 14)) {
			if ((ChannelNumMax_2G - ch) < 4)
				EXTCHA_MAX = 0;
			else
				EXTCHA_MAX = 1;
		}
		else
			HTBW_MAX = 0;
	}

	/* HT_EXTCHA
	 * BssidNum parameters: kernel 3.10, 4.4
	 * one parameter: kernel 2.6, 3.10, 4.4, 5.4
	 * Parameter of 1st BSS is copied to the rest of BSS if it doesn't have parameter.
	 */
	if (band) {
		fprintf(fp, "HT_EXTCHA=%d\n", EXTCHA);
	}
	else {
		if (!(str = nvram_pf_get(prefix, "nctrlsb")) || *str == '\0') {
			warning = 33;
			str = "UNKNOWN";
		}
		extcha = strcmp(str, "lower") ? 0 : 1;
		if ((ch >=1 ) && (ch <= 4))
			fprintf(fp, "HT_EXTCHA=%d\n", 1);
		else if (extcha <= EXTCHA_MAX)
			fprintf(fp, "HT_EXTCHA=%d\n", extcha);
		else
			fprintf(fp, "HT_EXTCHA=%d\n", 0);
	}

	/* HT_BW
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 * Parameter of 1st BSS is copied to another BSS, kernel 5.4 only.
	 */
	for (i = 0; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		/* FIXME: Find out wlx_bw of CAP is copied to wlx_bw or wlx.1_bw on RE node. */
		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i && sw_mode == SW_MODE_REPEATER) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if(!strcmp(nvram_pf_safe_get(prefix_mssid, "bw"), ""))
				wl_bw = get_bw_via_channel(band, ch);
			else
				wl_bw = nvram_pf_get_int(prefix_mssid, "bw");
		}
		else {
			sprintf(prefix_mssid, "wl%d_", band);
			wl_bw = get_bw_via_channel(band, ch);
		}
	} // for

	if(wl_bw == 0)
#if defined(RTCONFIG_WLMODULE_MT7663E_AP)
		if (sw_mode == SW_MODE_REPEATER)
			str = "1";
		else
#endif
			str = "0";
	else if ((wl_bw > 0) && (HTBW_MAX == 1))
		str = "1";
#if defined(RTCONFIG_WIRELESSREPEATER) && defined(RTCONFIG_CONCURRENTREPEATER)
	else if ((wlc_express - 1) == band)   //express way (apclii0)
		str = "1";
#endif
	else
		str = "0";
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_BW", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_BW", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_BW", str);
#endif

	/* HT_BSSCoexistence: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	if ((wl_bw > 1) && (HTBW_MAX == 1)
#if defined(RTCONFIG_WIRELESSREPEATER) && defined(RTCONFIG_CONCURRENTREPEATER)
		&& (wlc_express == 0 || (wlc_express - 1) != band)
#else
		&& !((sw_mode == SW_MODE_REPEATER) && (wlc_band == band))
#endif
	) {
		fprintf(fp, "HT_BSSCoexistence=%d\n", 0);
	}
	else
		fprintf(fp, "HT_BSSCoexistence=%d\n", 1);


	/* HT_AutoBA
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 4.4 (src-ra-openwrt-4110's mt_wifi_5050)
	 * BssidNum parameters:
	 *      kernel 4.4 (src-ra-openwrt-4110's mt_wifi_7915, src-ra-openwrt-4210)
	 *      kernel 5.4
	 */
	if (!(str = nvram_pf_get(prefix, "HT_AutoBA")) || *str == '\0') {
		warning = 35;
		str = "1";
	}
#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_AutoBA", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_AutoBA", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_AutoBA", str);
#endif

	//HT_BADecline
	if (!(str = nvram_pf_get(prefix, "HT_BADecline")) || *str == '\0') {
		warning = 36;
		str = "0";
	}
	fprintf(fp, "HT_BADecline=%d\n", safe_atoi(str));

	//HT_AMSDU
	if (!(str = nvram_pf_get(prefix, "HT_AMSDU")) || *str == '\0') {
		warning = 37;
		str = "0";
	}
	fprintf(fp, "HT_AMSDU=%d\n", safe_atoi(str));

	/* HT_BAWinSize
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 4.4 (src-ra-openwrt-4110's mt_wifi_5050)
	 * BssidNum parameters:
	 *      kernel 4.4 (src-ra-openwrt-4110's mt_wifi_7915, src-ra-openwrt-4210)
	 *      kernel 5.4
	 */
	if (!(str = nvram_pf_get(prefix, "HT_BAWinSize")) || *str == '\0') {
		warning = 38;
		str = "64";
	}
#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_BAWinSize", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_BAWinSize", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_BAWinSize", str);
#endif

	/* HT_GI
	 * BssidNum parameters:
	 *      kernel 3.10: src-mtk3.5's mt7663, mt7663_v6020, mt7663e
	 *      kernel 4.4: src-ra-5010's mt7615e, mt7615e_4411, mt7615e_5040
	 *      kernel 5.4
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 3.10: src-mtk3.5's mt7628 and src-ra-5010's mt7615e, mt7615e_4402, mt7615e_4421, mt7615e_man
	 */
	if (!(str = nvram_pf_get(prefix, "HT_GI")) || *str == '\0') {
		warning = 39;
		str = "1";
	}
#if defined(RTCONFIG_MT798X)
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_GI", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_GI", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_GI", str);
#endif

	/* VHT_SGI, VHT_STBC, VHT_LDPC
	 * BssidNum parameters:
	 *      kernel 3.10: src-mtk3.5
	 *      kernel 4.4 and kernel 5.4
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 3.10: src-ra-5010
	 */
#if defined(RTN54U) || defined(RTAC1200HP) || defined(RTN56UB1) || defined(RTAC54U) || defined(RTN56UB2) \
 || defined(RTAC1200GA1) || defined(RTAC1200GU) || defined(RTAC1200) || defined(RTAC1200V2) || defined(RTCONFIG_MTK_REP) \
 || defined(RTAC85U) || defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750) || defined(RTACRH18) \
 || defined(RT4GAC86U) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
#if defined(VHT_SUPPORT)
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "VHT_SGI", str);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "VHT_STBC", "1");
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "VHT_LDPC", "1");
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_SGI", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_STBC", "1");
	enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_LDPC", "1");
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_SGI", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_STBC", "1");
	enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_LDPC", "1");
#endif
#endif  /* VHT_SUPPORT */
#endif

	/* HT_STBC
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 */
	if (!(str = nvram_pf_get(prefix, "HT_STBC")) || *str == '\0') {
		warning = 40;
		str = "1";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_STBC", str);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_STBC", str);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_STBC", str);
#endif

	/* HT_MCS: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4 */
	if (!(str = nvram_pf_get(prefix, "HT_MCS")) || *str == '\0') {
		warning = 41;
		str = "33";
	}
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_MCS", str);

	/* HT_TxStream, HT_RxStream, HT_PROTECT
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 * Only wlx_HT_TxStream, wlx_HT_RxStream, wlx_nmode_protection available.
	 */
	if (!(str = nvram_pf_get(prefix, "HT_TxStream")) || *str == '\0') {
		warning = 42;
		str = "2";
	}
	if (!(str2 = nvram_pf_get(prefix, "HT_RxStream")) || *str2 == '\0') {
		warning = 43;
		str2 = "3";
	}
	if (!(str3 = nvram_pf_get(prefix, "nmode_protection")) || *str3 == '\0') {
		warning = 44;
		str3 = "auto";
	}
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_TxStream", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_RxStream", str2);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "HT_PROTECT", strcmp(str3, "auto")? "0" : "1");
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_TxStream", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_RxStream", str2);
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_PROTECT", strcmp(str3, "auto")? "0" : "1");
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_TxStream", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_RxStream", str2);
	enum_sname_mvalue_w_fixed_value(fp, 1, "HT_PROTECT", strcmp(str3, "auto")? "0" : "1");
#endif

	/* HT_DisallowTKIP: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	fprintf(fp, "HT_DisallowTKIP=%d\n", 1);

#if defined(VHT_SUPPORT)
	for (i = 0, vbw = 0; i < MAX_NO_MSSID; i++) {
		if (i != 1 && __is_rp_wlc_band(sw_mode, band))
			continue;

		/* FIXME: Find out wlx_bw of CAP is copied to wlx_bw or wlx.1_bw on RE node. */
		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i && sw_mode == SW_MODE_REPEATER) {
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if (!strcmp(nvram_pf_safe_get(prefix_mssid, "bw"), ""))
#if defined(RTCONFIG_VHT160)
				vbw = 5; //160MHZ or Auto
#else
				vbw = 3; // 80MHz or Auto
#endif
			else
				vbw = nvram_pf_get_int(prefix_mssid, "bw");
		}
		else {
			sprintf(prefix_mssid, "wl%d_", band);
			vbw = nvram_pf_get_int(prefix_mssid, "bw");
		}
	}

	/* VHT_BW
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10, 4.4
	 */
	vbw_val = -1;
	if (band) {
		if (vbw > 0) {
			if (vbw == 2)
				vbw_val = 0;
			else if (vbw == 3)
				vbw_val = 1;
			else if (vbw == 5)
				vbw_val = 2;
			else {
				 if (nvram_pf_match(prefix, "bw_160", "1"))
					 vbw_val = 2;
				 else //str == 3, 1
					 vbw_val = 1;
			}
		} else {
			warning = 8;
			vbw_val = 0;
		}

		/* If 160MHz, DFS channel disabled and default settings, use 80MHz instead. */
		if (vbw_val == 2 && !acs_dfs && nvram_match("x_Setting", "0"))
			vbw_val = 1;

		/* VHT_DisallowNonVHT: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
		 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
		 */
		if (!(str = nvram_pf_get(prefix_mssid, "VHT_DisallowNonVHT")))
			str = "0";
		fprintf(fp, "VHT_DisallowNonVHT=%d\n", safe_atoi(str));
	}
#if defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
	else {
		/* for DBDC mode, Both 2G & 5G need add same para or it would not add into DBDC profile */
		vbw_val = 0;
		fprintf(fp, "VHT_DisallowNonVHT=%d\n", 0);
	}
#endif
	if (vbw_val >= 0) {
		snprintf(tmp, sizeof(tmp), "%d", vbw_val);
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5,4,0))
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "VHT_BW", tmp);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
		enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_BW", tmp);
#else
		/* FIXME */
		enum_sname_mvalue_w_fixed_value(fp, 1, "VHT_BW", tmp);
#endif
	}
#endif  /* VHT_SUPPORT */

	//TxBF, MU-MIMO
#if defined(RTCONFIG_MT798X)
	/* Don't turn on 2G/5G back-off on CN,EU,AA,UK sku for WiFi performance. */
	if (__is_tcode_country(tcode, "CN") || __is_tcode_country(tcode, "EU") || __is_tcode_country(tcode, "AA") || __is_tcode_country(tcode, "UK"))
		memset(backoff, 0, sizeof(backoff));

	/* MUTxRxEnable, ITxBfEn, ETxBfIncapable, ETxBfEnCond:
	 * one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * Some driver take multiple parameters and bit-wise OR all of them as one parameter.
	 * Merged DBDC*.dat has only one parameter for MUTxRxEnable,BFBACKOFFenable and follow band1's parameter!
	 * BFBACKOFFenable: one parameter per band.
	 */
	fprintf(fp, "BFBACKOFFenable=%d\n", backoff[band]);
#if defined(CE_ADAPTIVITY)
	if (nvram_match("reg_spec", "CE") && (sw_mode()==SW_MODE_REPEATER && nvram_get_int("wlc_psta") == 1))
		fprintf(fp, "ITxBfEn=0\n");
	else
#endif
	fprintf(fp, "ITxBfEn=%d\n", nvram_pf_get_int(prefix, "itxbf"));
	txbf = (nmode != 2)? nvram_pf_get_int(prefix, "txbf") : 0;
#if defined(CE_ADAPTIVITY)
	if (nvram_match("reg_spec", "CE") && (sw_mode()==SW_MODE_REPEATER && nvram_get_int("wlc_psta") == 1))
		fprintf(fp, "ETxBfEnCond=0\n");
	else
#endif
	fprintf(fp, "ETxBfEnCond=%d\n", txbf);
#if defined(RTCONFIG_MUMIMO_2G) || defined(RTCONFIG_MUMIMO_5G)
	mumimo = txbf? nvram_pf_get_int(prefix, "mumimo") : 0;
	fprintf(fp, "MUTxRxEnable=%d\n", (mumimo ? 1 : 0));
#endif
#else	/* !RTCONFIG_MT798X */
#if !defined (RTCONFIG_WLMODULE_MT7615E_AP) && !defined(RTCONFIG_WLMODULE_MT7629_AP) && !defined(RTCONFIG_WLMODULE_MT7622_AP) && !defined(RTCONFIG_WLMODULE_MT7915D_AP)
	// TxBF
	if (band)
#endif
	{
		/* mu-mimo */
#if defined(RTCONFIG_MUMIMO_2G) || defined(RTCONFIG_MUMIMO_5G)
		mumimo = safe_atoi(nvram_pf_safe_get(prefix, "mumimo"));
#endif
#ifdef RTCONFIG_TXBF_BAND3ONLY
		if (sw_mode == SW_MODE_AP) {
			cht =  nvram_pf_get_int(prefix, "channel");
			if (cht >= 100 && cht <= 144) { // BAND3
				nvram_pf_set(prefix, "txbf", "1");
				nvram_pf_set(prefix, "txbf_en", "1");
			}
			else {
				nvram_pf_set(prefix, "txbf", "0");
				nvram_pf_set(prefix, "txbf_en", "0");
			}
		} else {
			nvram_pf_set(prefix, "txbf", "0");
			nvram_pf_set(prefix, "txbf_en", "0");
		}
#endif
#if defined(RTCONFIG_WLMODULE_MT7663E_AP)
		nvram_pf_set(prefix, "txbf_en", "1");
#endif
		str = nvram_pf_safe_get(prefix, "txbf");
		if ((safe_atoi(str) > 0) && nvram_pf_match(prefix, "txbf_en", "1"))
		{
#if defined (RTCONFIG_WLMODULE_MT7615E_AP)
#if defined(RTAC85P) ||	 defined(RTACRH26) || defined(TUFAC1750) || defined(RT4GAC86U)
			if (strlen(nvram_safe_get("territory_code")) != 0)
				fprintf(fp, "BFBACKOFFenable=%d\n", 1);
			else
				fprintf(fp, "BFBACKOFFenable=%d\n", 0);
#else
			fprintf(fp, "BFBACKOFFenable=%d\n", 1);
#endif
#if defined(RTAC85P) || defined(RTACRH26) || defined(TUFAC1750)
			str_tcode=nvram_safe_get("territory_code");
			if ((strlen(nvram_safe_get("territory_code")) == 0) || !strcmp(str_tcode+strlen(str_tcode)-3,"/01")) {
				fprintf(fp, "ITxBfEn=%d\n", 0);
			} else {
				fprintf(fp, "ITxBfEn=%d\n", 1);
			}
#elif defined(RT4GAC86U)
				if (nvram_pf_get_int(prefix, "itxbf"))
					fprintf(fp, "ITxBfEn=%d\n", 1);
				else
					fprintf(fp, "ITxBfEn=%d\n", 0);
#else
				fprintf(fp, "ITxBfEn=%d\n", 0);
#endif
				fprintf(fp, "ETxBfIncapable=%d\n", 0);
#elif defined (RTCONFIG_WLMODULE_MT7663E_AP)
#if defined(RTAC1200V2)
				fprintf(fp, "BFBACKOFFenable=%d\n", 1);
				fprintf(fp, "ITxBfEn=%d\n", 0);
#endif
#elif defined(RTCONFIG_WLMODULE_MT7629_AP)
				fprintf(fp, "BFBACKOFFenable=%d\n", 1);
				fprintf(fp, "ITxBfEn=%d\n", 1);
#elif defined(RTCONFIG_WLMODULE_MT7915D_AP)
			if (strlen(nvram_safe_get("territory_code")) != 0)
				fprintf(fp, "BFBACKOFFenable=%d\n", 1);
			else
				fprintf(fp, "BFBACKOFFenable=%d\n", 0);

			if (nvram_pf_get_int(prefix, "itxbf"))
				fprintf(fp, "ITxBfEn=%d\n", 1);
			else
				fprintf(fp, "ITxBfEn=%d\n", 0);
#else
				fprintf(fp, "ITxBfEn=%d\n", 1);
#endif

#if defined(RT4GAC86U) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
			if (band) {
#if defined(RT4GAC86U)
				fprintf(fp, "WHNAT=%d\n", 1);
#endif
				fprintf(fp, "ETxBfEnCond=%d\n", 1);
			}
			else
				fprintf(fp, "ETxBfEnCond=%d\n", 0);
#else
			fprintf(fp, "ETxBfEnCond=%d\n", 1);
#endif
#if defined(RTCONFIG_MUMIMO_2G) || defined(RTCONFIG_MUMIMO_5G)
			if (band)
				fprintf(fp, "MUTxRxEnable=%d\n", (mumimo ? 1 : 0));
#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
			else
				fprintf(fp, "MUTxRxEnable=%d\n", (mumimo ? 1 : 0));
#endif
#endif
		} else {
#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
			fprintf(fp, "BFBACKOFFenable=%d\n", 0);	/* driver default value. */
#endif
#if defined(RT4GAC86U) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
			if (nvram_pf_get_int(prefix, "itxbf"))
				fprintf(fp, "ITxBfEn=%d\n", 1);
			else
				fprintf(fp, "ITxBfEn=%d\n", 0);
#else
			fprintf(fp, "ITxBfEn=%d\n", 0);
#endif
#if defined(RTCONFIG_MUMIMO_2G) || defined(RTCONFIG_MUMIMO_5G)
			if (band) {
				if (mumimo) {
					fprintf(fp, "ETxBfEnCond=%d\n", 1);
					fprintf(fp, "MUTxRxEnable=%d\n", 1);
				}
				else {
					fprintf(fp, "ETxBfEnCond=%d\n", 0);
					fprintf(fp, "MUTxRxEnable=%d\n", 0);
				}
			}
			else {
#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
				fprintf(fp, "MUTxRxEnable=%d\n", (mumimo ? 1 : 0));
#endif
				fprintf(fp, "ETxBfEnCond=%d\n", 0);
			}
#else
			fprintf(fp, "ETxBfEnCond=%d\n", 0);
#endif
#if defined (RTCONFIG_WLMODULE_MT7615E_AP)
			fprintf(fp, "ETxBfIncapable=%d\n", 1);
#endif
		}
	}
#endif	/* RTCONFIG_MT798X */

	/* WscConfMode, WscConfStatus: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 * WscVendorPinCode:
	 * BssidNum parameters: kernel 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10, 4.4
	 */
	wsc_configure = nvram_get_int("w_Setting");
	if (wsc_configure == 0) {
		str = "0";      /* disabled */
		str2 = "1";     /* AP is unconfigured */
		g_wsc_configured = 0;						// AP is unconfigured
		nvram_pf_set(prefix, "wsc_config_state", "0");
	} else {
		str = "0";      /* disabled */
		str2 = "2";     /* AP is configured */
		g_wsc_configured = 1;						// AP is configured
		nvram_pf_set(prefix, "wsc_config_state", "1");
	}
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "WscConfMode", str);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "WscConfStatus", str2);
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "WscVendorPinCode", nvram_safe_get("secret_code"));
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "WscVendorPinCode", nvram_safe_get("secret_code"));
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "WscVendorPinCode", nvram_safe_get("secret_code"));
#endif

	/* AccessPolicy0: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	memset(mac_filter,0,sizeof(mac_filter));
	gen_macmode(mac_filter, band); //Ren
	for (i = 0; i < MAX_NO_MSSID; i++)
		fprintf(fp, "AccessPolicy%d=%d\n", i, mac_filter[i]);

	for (i = 0,j = 0; i < MAX_NO_MSSID; i++) {
		if (i == 0 && __aimesh_re_node(sw_mode))
			continue;

		if (i)
			sprintf(prefix_mssid, "wl%d.%d_", band, i);
		else
			sprintf(prefix_mssid, "wl%d_", band);

		if (!is_bss_enabled(prefix_mssid))
			continue;
		*list = '\0';
		if (!nvram_pf_match(prefix_mssid, "macmode", "disabled")) {
			nv = nvp = strdup(nvram_pf_safe_get(prefix_mssid, "maclist_x"));
			if (nv) {
				while ((b = strsep(&nvp, "<")) != NULL) {
					if (strlen(b)==0) continue;
					snprintf(tmp, sizeof(tmp), "%s;", b);
					strlcat(list, tmp, sizeof(list));
				}
				free(nv);
			}
			if (*list != '\0')
				*(list + strlen(list) - 1) = '\0';
			fprintf(fp, "AccessControlList%d=%s\n", j, list);
		}
		else
			fprintf(fp, "AccessControlList%d=%s\n", j, "");
		j++;
	} //for loop

	if (sw_mode != SW_MODE_REPEATER && !nvram_pf_match(prefix, "mode_x", "0")) {
		/* WdsEnable:
		 * DBDC_BAND_NUM parameters: kernel 4.4, 5.4
		 * one parameter: kernel 2.6, 3.10, 4.4
		 */
		if (!(str = nvram_pf_get(prefix, "mode_x")) || *str == '\0')
			warning = 49;
		wds_mode = 0;
		if ((nvram_pf_match(prefix, "auth_mode_x", "open")
		 || (nvram_pf_match(prefix, "auth_mode_x", "psk2") && nvram_pf_match(prefix, "crypto", "aes")))
		) {
			if (safe_atoi(str) == 0)
				wds_mode = 0;
			else if (safe_atoi(str) == 1)
				wds_mode = 2;
			else if (safe_atoi(str) == 2) {
				if (nvram_pf_match(prefix, "wdsapply_x", "0"))
					wds_mode = 4;
				else
					wds_mode = 3;
			}

			/* Choose lazy mode if WdsEnable is bridge/repeater mode and WdsList empty.
			 * Otherwise, another AP is not able to connect to this one due to WDS are
			 * disabled by driver. Check output of private ioctl "show wdsinfo", none of
			 * any WDS interface occupied. According to profile_wds_reg(), all WDS
			 * interfaces of the band are used in lazy mode, thus, we have to fill
			 * configuration for all WDS interface.
			 */
			if ((wds_mode == 2 || wds_mode == 3) && *nvram_pf_safe_get(prefix, "wdslist") == '\0')
				wds_mode = 4;
		}
		fprintf(fp, "WdsEnable=%d\n", wds_mode);

		/* Count number of entry in wdslist. */
		if ((nv = nvp = strdup(nvram_pf_safe_get(prefix, "wdslist"))) != NULL) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if (*b != '\0')
					wds_count++;
			}
			free(nv);
		}

		/* WdsPhyMode: MAX_WDS_PER_BAND parameters @ kernel 2.6, 3.10, 4.4, 5.4
		 * MAX_WDS_PER_BAND=4: kernel 2.6, 3.10, 4.4
		 * MAX_WDS_PER_BAND=8: kernel 4.4, 5.4
		 */
		str2 = "";
		str = nvram_pf_get(prefix, "mode_x");
		if (str && strlen(str)) {
			if (nmode == 0 || nmode == 8) {
				/* Auto Wireless mode or N/AC[/AX] mixed */
				if (find_word(nvram_safe_get("rc_support"), "11AX"))
					str2 = "HE";
				else if ((band == WL_5G_BAND || band == WL_5G_2_BAND)
				      && find_word(nvram_safe_get("rc_support"), "11AC"))
					str2 = "VHT";
				else
					str2 = "HTMIX";
			} else if (nmode == 1) {
				/* N only */
				str2 = "GREENFIELD";
			} else if (nmode == 2) {
				/* Legacy */
				str2 = "OFDM";	/* OFDM: 11B/G or 11A; CCK: 11B only */
			}
		}
		enum_sname_mvalue_w_fixed_value(fp, (wds_mode == 4)? MAX_WDS_PER_BAND : wds_count, "WdsPhyMode", str2);

		/* WdsEncrypType: MAX_WDS_PER_BAND parameters @ kernel 2.6, 3.10, 4.4, 5.4
		 * MAX_WDS_PER_BAND=4: kernel 2.6, 3.10, 4.4
		 * MAX_WDS_PER_BAND=8: kernel 4.4, 5.4
		 */
		str2 = "NONE";
		if (nvram_pf_match(prefix, "auth_mode_x", "open")
		 && nvram_pf_match(prefix, "wep_x", "0"))
			str2 = "NONE";
		else if (nvram_pf_match(prefix, "auth_mode_x", "open")
		      && nvram_pf_invmatch(prefix, "wep_x", "0"))
			str2 = "WEP";
		else if (nvram_pf_match(prefix, "auth_mode_x", "psk2")
		      && nvram_pf_match(prefix, "crypto", "aes"))
			str2 = "AES";
		enum_sname_mvalue_w_fixed_value(fp, (wds_mode == 4)? MAX_WDS_PER_BAND : wds_count, "WdsEncrypType", str2);

		/* WdsList: MAX_WDS_PER_BAND parameters @ kernel 2.6, 3.10, 4.4, 5.4
		 * MAX_WDS_PER_BAND=4: kernel 2.6, 3.10, 4.4
		 * MAX_WDS_PER_BAND=8: kernel 4.4, 5.4
		 * Number of WDS entry of each band is calculated with this parameter,
		 * don't add extra settings to it.
		 * If number of WDS entry exceeds maximum number of WdsList, WDS is disabled!
		 */
		*list = '\0';
		if ((nvram_pf_match(prefix, "mode_x", "1")
		  || (nvram_pf_match(prefix, "mode_x", "2") && nvram_pf_match(prefix, "wdsapply_x", "1")))
		 && (nvram_pf_match(prefix, "auth_mode_x", "open")
		  || (nvram_pf_match(prefix, "auth_mode_x", "psk2") && nvram_pf_match(prefix, "crypto", "aes")))
		) {
			nv = nvp = strdup(nvram_pf_safe_get(prefix, "wdslist"));
			if (nv) {
				i = 0;
				while (i < MAX_WDS_PER_BAND && (b = strsep(&nvp, "<")) != NULL) {
					if (strlen(b)==0) continue;
					snprintf(tmp, sizeof(tmp), "%s;", b);
					strlcat(list, tmp, sizeof(list));
					++i;
				}
				free(nv);
			}
		}
		if (*list != '\0')
			*(list + strlen(list) - 1) = '\0';
		fprintf(fp, "WdsList=%s\n", list);

		/* WdsKey: MAX_WDS_PER_BAND parameters @ kernel 2.6, 3.10, 4.4, 5.4
		 * MAX_WDS_PER_BAND=4: kernel 2.6, 3.10, 4.4
		 * MAX_WDS_PER_BAND=8: kernel 4.4, 5.4
		 * Wds%dKey: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
		 * If WdsKey exist, Wds%dKey are ignored. But merged WdsKey only have eight set of key
		 * for MT7986 which have 8+8=16 WDS interfaces. If WDS is enabled on 2G, 5G WDS
		 * interfaces don't have key and can't transmit/receive data between peer WDS AP even
		 * MAC address of peer AP already in output of "iwpriv rax0 show wdsinfo" command.
		 */
		if (nvram_pf_match(prefix, "auth_mode_x", "open") && nvram_pf_match(prefix, "wep_x", "0")) {
			fprintf(fp, "WdsDefaultKeyID=\n");
			enum_mname_s0_svalue_w_fixed_value(fp, (wds_mode == 4)? MAX_WDS_PER_BAND : wds_count, "Wds%dKey", "");
		}
		else if (nvram_pf_match(prefix, "auth_mode_x", "open") && nvram_pf_invmatch(prefix, "wep_x", "0")) {
			enum_sname_mvalue_w_fixed_value(fp, MAX_WDS_PER_BAND, "WdsDefaultKeyID", nvram_pf_safe_get(prefix, "key"));
			str = strcat_r(prefix, "key", tmp);
			str2 = nvram_safe_get(str);
			sprintf(list, "%s%s", str, str2);
			enum_mname_s0_svalue_w_fixed_value(fp, (wds_mode == 4)? MAX_WDS_PER_BAND : wds_count, "Wds%dKey", nvram_safe_get(list));
		}
		else if (nvram_pf_match(prefix, "auth_mode_x", "psk2") && nvram_pf_match(prefix, "crypto", "aes")) {
			enum_mname_s0_svalue_w_fixed_value(fp, (wds_mode == 4)? MAX_WDS_PER_BAND : wds_count, "Wds%dKey", nvram_pf_safe_get(prefix, "wpa_psk"));
		}
	} // sw_mode
#if defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
	else
	{
		fprintf(fp, "WdsEnable=0\n");
		fprintf(fp, "WdsPhyMode=0\n");
		fprintf(fp, "WdsEncrypType=\n");
		fprintf(fp, "WdsList=\n");
		enum_mname_s0_svalue_w_fixed_value(fp, MAX_WDS_PER_BAND, "Wds%dKey", "");
	}
#endif

	/* RADIUS_Key%d: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * RADIUS_Server, RADIUS_Port: BssidNum parameters @ kernel 2.6, 3.10, 4.4, 5.4
	 */
	if (flag_8021x) {
		radius_server = nvram_pf_safe_get(prefix, "radius_ipaddr");
		radius_port   = nvram_pf_safe_get(prefix, "radius_port");
		radius_key    = nvram_pf_safe_get(prefix, "radius_key");
		for (i = 0, val = 0; i < MAX_NO_MSSID; i++) {
			if (i != 1 && __is_rp_wlc_band(sw_mode, band))
				continue;
			if (i) {
				sprintf(prefix_mssid, "wl%d.%d_", band, i);
				if (!is_bss_enabled(prefix_mssid))
					continue;
			}
			val++;
		}
		enum_mname_s1_svalue_w_fixed_value(fp, val, "RADIUS_Key%d", radius_key);
		enum_sname_mvalue_w_fixed_value(fp, val, "RADIUS_Server", radius_server);
		enum_sname_mvalue_w_fixed_value(fp, val, "RADIUS_Port", radius_port);
	} else {
		enum_mname_s1_svalue_w_fixed_value(fp, ssid_num, "RADIUS_Key%d", "");
#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RADIUS_Server", "0");
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RADIUS_Port", "1812");
#else
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RADIUS_Server", "");
		enum_sname_mvalue_w_fixed_value(fp, ssid_num, "RADIUS_Port", "");	//default 1812
#endif
	}

	/* RADIUS_Acct_Server: kernel 3.10+
	 * 	Parsing BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * 	Only first two parameters are saved.
	 * RADIUS_Acct_Port, RADIUS_Acct_Key: kernel 3.10+
	 * 	Parsing BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * 	All parameter saved to same place.
	 * Merged DBDC*.dat only has per band parameters for RADIUS_Acct_Port.
	 */
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "RADIUS_Acct_Server", "");
	enum_sname_mvalue_w_fixed_value(fp, 1, "RADIUS_Acct_Port", "1813");
	enum_sname_mvalue_w_fixed_value(fp, 1, "RADIUS_Acct_Key", "");
#endif

	/* own_ip_addr, EAPifname, PreAuthifname, session_timeout_interval:
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 * Merged DBDC*.dat only has per band parameters for own_ip_addr and session_timeout_interval.
	 */
	str = str2 = "";
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	if (1)
#else
	if (flag_8021x == 1)
#endif
	{
		str = nvram_safe_get("lan_ipaddr");
		str2 = "br0";
	}

#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "own_ip_addr", str);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "EAPifname", str2);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "PreAuthifname", str2);
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "session_timeout_interval", "0");
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "own_ip_addr", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "EAPifname", str2);
	enum_sname_mvalue_w_fixed_value(fp, 1, "PreAuthifname", str2);
	enum_sname_mvalue_w_fixed_value(fp, 1, "session_timeout_interval", "0");
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "own_ip_addr", str);
	enum_sname_mvalue_w_fixed_value(fp, 1, "EAPifname", str2);
	enum_sname_mvalue_w_fixed_value(fp, 1, "PreAuthifname", str2);
	enum_sname_mvalue_w_fixed_value(fp, 1, "session_timeout_interval", "0");
#endif

	/* TGnWifiTest: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	fprintf(fp, "TGnWifiTest=0\n");

#ifdef RTCONFIG_WIRELESSREPEATER
#if defined(RTCONFIG_AMAS) || defined(RTCONFIG_CONCURRENTREPEATER)
	if (0
#if defined(RTCONFIG_AMAS)
	 || __aimesh_re_node(sw_mode)
	 || (sw_mode == SW_MODE_REPEATER && wlc_band == band && nvram_invmatch("wlc_ssid", ""))
#endif
#if defined(RTCONFIG_CONCURRENTREPEATER)
	 || (sw_mode == SW_MODE_REPEATER && (wlc_express == 0 || (wlc_express - 1) == band))
#endif
	) {
		int flag_wep = 0;
		int p;
		// convert wlc_xxx to wlX_ according to wlc_band == band
		nvram_set("ure_disable", "0");
		if (sw_mode == SW_MODE_REPEATER)
			snprintf(prefix_wlc, sizeof(prefix_wlc), "wlc_");
		else
			snprintf(prefix_wlc, sizeof(prefix_wlc), "wlc%d_", band);
		nvram_pf_set(prefix, "ssid", nvram_pf_safe_get(prefix_wlc, "ssid"));
		nvram_pf_set(prefix, "auth_mode_x", nvram_pf_safe_get(prefix_wlc, "auth_mode"));
		nvram_pf_set(prefix, "wep_x", nvram_pf_safe_get(prefix_wlc, "wep"));
		nvram_pf_set(prefix, "key", nvram_pf_safe_get(prefix_wlc, "key"));
		for (p = 1; p <= 4; p++) {
			char prekey[16];
			snprintf(prekey, sizeof(prekey), "key%d", p);
			if (nvram_pf_get_int(prefix_wlc, "key") == p)
				nvram_pf_set(prefix, prekey, nvram_pf_safe_get(prefix_wlc, "wep_key"));
		}

		nvram_pf_set(prefix, "crypto", nvram_pf_safe_get(prefix_wlc, "crypto"));
		nvram_pf_set(prefix, "wpa_psk", nvram_pf_safe_get(prefix_wlc, "wpa_psk"));
		if (!__aimesh_re_node(sw_mode)) {
			if (!strcmp(nvram_pf_safe_get(prefix_wlc, "nbw_cap"), ""))
				nvram_pf_set(prefix, "bw", "2");
			else
				nvram_pf_set(prefix, "bw", nvram_pf_safe_get(prefix_wlc, "nbw_cap"));
			nvram_pf_set(prefix, "hide_pap", nvram_pf_safe_get(prefix_wlc, "hide_pap"));
			nvram_pf_set(prefix, "wifipxy", nvram_pf_safe_get(prefix_wlc, "wifipxy"));
		}

		/* ApCliEnable, ApCliBssid, ApCliAuthMode, ApCliEncrypType, ApCliPMFMFPC, ApCliPMFMFPR, ApCliPMFSHA256:
		 * 	MAX_APCLI_NUM parameters, it's 1 unless DBDC_MODE is enabled: kernel 2.6, 3.10, 4.4, 5.4
		 * ApCliSsid%d, ApCliWPAPSK%d:
		 * 	one parameter: kernel 2.6, 3.10, 4.4, 5.4
		 * MACRepeaterEn:
		 * 	DBDC_BAND_NUM parameters: kernel 4.4, 5.4
		 * 	one parameter: kernel 2.6, 3.10, 4.4
		 */
		fprintf(fp, "ApCliEnable=0\n");
		fprintf(fp, "ApCliSsid%d=%s\n", 1, nvram_pf_safe_get(prefix_wlc, "ssid"));
		fprintf(fp, "ApCliBssid=\n");
		fprintf(fp, "MACRepeaterEn=%s\n", nvram_pf_safe_get(prefix_wlc, "wifipxy"));

		str = nvram_pf_safe_get(prefix_wlc, "auth_mode");
		if (str && strlen(str)) {
			if (!strcmp(str, "open") && nvram_match(strcat_r(prefix_wlc, "wep", tmp), "0")) {
				fprintf(fp, "ApCliAuthMode=%s\n", "OPEN");
				fprintf(fp, "ApCliEncrypType=%s\n", "NONE");
			}
			else if (!strcmp(str, "open") || !strcmp(str, "shared")) {
				flag_wep = 1;
				fprintf(fp, "ApCliAuthMode=%s\n", "WEPAUTO");
				fprintf(fp, "ApCliEncrypType=%s\n", "WEP");
			}
			else if (!strcmp(str, "psk") || !strcmp(str, "psk2") || !strcmp(str, "pskpsk2")
			      || !strcmp(str, "sae") || !strcmp(str, "psk2sae"))
			{
				if (!strcmp(str, "psk"))
					fprintf(fp, "ApCliAuthMode=%s\n", "WPAPSK");
				else if (!strcmp(str, "psk2")) {
					fprintf(fp, "ApCliAuthMode=%s\n", "WPA2PSK");
#if defined(RTCONFIG_MFP)
					fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
					fprintf(fp, "ApCliPMFMFPR=%s\n", "0");
					fprintf(fp, "ApCliPMFSHA256=%s\n", "0");
#endif
				}
				else if (!strcmp(str, "pskpsk2")) {
					fprintf(fp, "ApCliAuthMode=%s\n", "WPAPSKWPA2PSK");
#if defined(RTCONFIG_MFP)
					fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
					fprintf(fp, "ApCliPMFMFPR=%s\n", "0");
					fprintf(fp, "ApCliPMFSHA256=%s\n", "0");
#endif
				}
				else if (!strcmp(str, "sae")) {
					fprintf(fp, "ApCliAuthMode=%s\n", "WPA3PSK");
#if defined(RTCONFIG_MFP)
					fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
					fprintf(fp, "ApCliPMFMFPR=%s\n", "1");
					fprintf(fp, "ApCliPMFSHA256=%s\n", "1");
#endif
				}
				else if (!strcmp(str, "psk2sae")) {
					fprintf(fp, "ApCliAuthMode=%s\n", "WPA2PSKWPA3PSK");
#if defined(RTCONFIG_MFP)
					fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
					fprintf(fp, "ApCliPMFMFPR=%s\n", "0");
					fprintf(fp, "ApCliPMFSHA256=%s\n", "0");
#endif
				}

				//EncrypType
				if (nvram_match(strcat_r(prefix_wlc, "crypto", tmp), "tkip"))
					fprintf(fp, "ApCliEncrypType=%s\n", "TKIP");
				else if (nvram_match(strcat_r(prefix_wlc, "crypto", tmp), "aes"))
					fprintf(fp, "ApCliEncrypType=%s\n", "AES");
				else if (nvram_match(strcat_r(prefix_wlc, "crypto", tmp), "tkip+aes"))
					fprintf(fp, "ApCliEncrypType=%s\n", "TKIPAES");

				//WPAPSK
				fprintf(fp, "ApCliWPAPSK%d=%s\n", 1, nvram_pf_safe_get(prefix_wlc, "wpa_psk"));
			} else {
				fprintf(fp, "ApCliAuthMode=%s\n", "OPEN");
				fprintf(fp, "ApCliEncrypType=%s\n", "NONE");
			}
		} else {
			fprintf(fp, "ApCliAuthMode=%s\n", "OPEN");
			fprintf(fp, "ApCliEncrypType=%s\n", "NONE");
		}

		/* ApCliDefaultKeyID: MAX_APCLI_NUM parameters @ kernel 2.6, 3.10, 4.4, 5.4
		 * ApCliKey%dType, ApCliKey%dStr: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
		 */
		//EncrypType
		if (flag_wep) {
			//DefaultKeyID
			fprintf(fp, "ApCliDefaultKeyID=%s\n", nvram_pf_safe_get(prefix_wlc, "key"));

			//KeyType (0 -> Hex, 1->Ascii)
			for (p = 1 ; p <= 4; p++) {
				if (nvram_pf_get_int(prefix_wlc, "key") == p) {
					if ((strlen(nvram_pf_safe_get(prefix_wlc, "wep_key")) == 5)
					 || (strlen(nvram_pf_safe_get(prefix_wlc, "wep_key")) == 13))
						fprintf(fp, "ApCliKey%dType=1\n",p);
					else if((strlen(nvram_pf_safe_get(prefix_wlc, "wep_key")) == 10)
					     || (strlen(nvram_pf_safe_get(prefix_wlc, "wep_key")) == 26))
						fprintf(fp, "ApCliKey%dType=0\n",p);
					else
					   	fprintf(fp, "ApCliKey%dType=\n",p);
				}
				else
				   	 fprintf(fp, "ApCliKey%dType=\n",p);
			}

			//KeyStr
			for (p = 1 ; p <= 4; p++) {
				if (nvram_pf_get_int(prefix_wlc, "key") == p)
					fprintf(fp, "ApCliKey%dStr=%s\n",p,nvram_pf_safe_get(prefix_wlc, "wep_key"));
				else
					fprintf(fp, "ApCliKey%dStr=\n",p);
			}
		} else {
			fprintf(fp, "ApCliDefaultKeyID=0\n");
			fprintf(fp, "ApCliKey1Type=0\n");
			fprintf(fp, "ApCliKey1Str=\n");
			fprintf(fp, "ApCliKey2Type=0\n");
			fprintf(fp, "ApCliKey2Str=\n");
			fprintf(fp, "ApCliKey3Type=0\n");
			fprintf(fp, "ApCliKey3Str=\n");
			fprintf(fp, "ApCliKey4Type=0\n");
			fprintf(fp, "ApCliKey4Str=\n");
		}
	}
	else
#else /* !(RTCONFIG_AMAS || RTCONFIG_CONCURRENTREPEATER) */
		if (sw_mode == SW_MODE_REPEATER && wlc_band == band && nvram_invmatch("wlc_ssid", "")) {
			int flag_wep = 0;
			int p;
			// convert wlc_xxx to wlX_ according to wlc_band == band
			nvram_set("ure_disable", "0");

			nvram_set("wl_ssid", nvram_safe_get("wlc_ssid"));
			nvram_set(strcat_r(prefix, "ssid", tmp), nvram_safe_get("wlc_ssid"));
			nvram_set(strcat_r(prefix, "auth_mode_x", tmp), nvram_safe_get("wlc_auth_mode"));

			nvram_set(strcat_r(prefix, "wep_x", tmp), nvram_safe_get("wlc_wep"));

			nvram_set(strcat_r(prefix, "key", tmp), nvram_safe_get("wlc_key"));
			for (p = 1; p <= 4; p++) {
				char prekey[16];
				snprintf(prekey, sizeof(prekey), "key%d", p);
				if (nvram_get_int("wlc_key") == p)
					nvram_set(strcat_r(prefix, prekey, tmp), nvram_safe_get("wlc_wep_key"));
			}

			nvram_set(strcat_r(prefix, "crypto", tmp), nvram_safe_get("wlc_crypto"));
			nvram_set(strcat_r(prefix, "wpa_psk", tmp), nvram_safe_get("wlc_wpa_psk"));
			if (!strcmp(nvram_safe_get("wlc_nbw_cap"), ""))
				nvram_set(strcat_r(prefix, "bw", tmp), "2");
			else
				nvram_set(strcat_r(prefix, "bw", tmp), nvram_safe_get("wlc_nbw_cap"));

			fprintf(fp, "ApCliEnable=0\n");
			fprintf(fp, "ApCliSsid%d=%s\n", 1, nvram_safe_get("wlc_ssid"));
			fprintf(fp, "ApCliBssid=\n");

			str = nvram_safe_get("wlc_auth_mode");
			if (str && strlen(str)) {
				if (!strcmp(str, "open") && nvram_match("wlc_wep", "0")) {
					fprintf(fp, "ApCliAuthMode=%s\n", "OPEN");
					fprintf(fp, "ApCliEncrypType=%s\n", "NONE");
				}
				else if (!strcmp(str, "open") || !strcmp(str, "shared")) {
					flag_wep = 1;
					fprintf(fp, "ApCliAuthMode=%s\n", "WEPAUTO");
					fprintf(fp, "ApCliEncrypType=%s\n", "WEP");
				}
				else if (!strcmp(str, "psk") || !strcmp(str, "psk2") || !strcmp(str, "pskpsk2")
				      || !strcmp(str, "sae") || !strcmp(str, "psk2sae"))
				{
					if (!strcmp(str, "psk")) {
						fprintf(fp, "ApCliAuthMode=%s\n", "WPAPSK");
					}
					else if (!strcmp(str, "psk2")) {
						fprintf(fp, "ApCliAuthMode=%s\n", "WPA2PSK");
#if defined(RTCONFIG_MFP)
						fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
						fprintf(fp, "ApCliPMFMFPR=%s\n", "0");
						fprintf(fp, "ApCliPMFSHA256=%s\n", "0");
#endif
					}
					else if (!strcmp(str, "pskpsk2")) {
						fprintf(fp, "ApCliAuthMode=%s\n", "WPAPSKWPA2PSK");
#if defined(RTCONFIG_MFP)
						fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
						fprintf(fp, "ApCliPMFMFPR=%s\n", "0");
						fprintf(fp, "ApCliPMFSHA256=%s\n", "0");
#endif
					}
					else if (!strcmp(str, "sae")){
						fprintf(fp, "ApCliAuthMode=%s\n", "WPA3PSK");
#if defined(RTCONFIG_MFP)
						fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
						fprintf(fp, "ApCliPMFMFPR=%s\n", "1");
						fprintf(fp, "ApCliPMFSHA256=%s\n", "1");
#endif
					}
					else if (!strcmp(str, "psk2sae")){
						fprintf(fp, "ApCliAuthMode=%s\n", "WPA2PSKWPA3PSK");
#if defined(RTCONFIG_MFP)
						fprintf(fp, "ApCliPMFMFPC=%s\n", "1");
						fprintf(fp, "ApCliPMFMFPR=%s\n", "0");
						fprintf(fp, "ApCliPMFSHA256=%s\n", "0");
#endif
					}
					//EncrypType
					if (nvram_match("wlc_crypto", "tkip"))
						fprintf(fp, "ApCliEncrypType=%s\n", "TKIP");
					else if (nvram_match("wlc_crypto", "aes"))
						fprintf(fp, "ApCliEncrypType=%s\n", "AES");
					else if (nvram_match("wlc_crypto", "tkip+aes"))
						fprintf(fp, "ApCliEncrypType=%s\n", "TKIPAES");

#if defined(RTCONFIG_WLMODULE_MT7629_AP)
					//WPAPSK
					fprintf(fp, "ApCliWPAPSK=%s\n", nvram_safe_get("wlc_wpa_psk"));
					//WPAPSK
					fprintf(fp, "ApCliWPAPSK%d=%s\n", 1, "");
#else
					//WPAPSK
					fprintf(fp, "ApCliWPAPSK%d=%s\n", 1, nvram_safe_get("wlc_wpa_psk"));
#endif
				} else {
					fprintf(fp, "ApCliAuthMode=%s\n", "OPEN");
					fprintf(fp, "ApCliEncrypType=%s\n", "NONE");
				}
			} else {
				fprintf(fp, "ApCliAuthMode=%s\n", "OPEN");
				fprintf(fp, "ApCliEncrypType=%s\n", "NONE");
			}

			//EncrypType
			if (flag_wep) {
				//DefaultKeyID
				fprintf(fp, "ApCliDefaultKeyID=%s\n", nvram_safe_get("wlc_key"));

				//KeyType (0 -> Hex, 1->Ascii)
				for(p = 1 ; p <= 4; p++) {
					if (nvram_get_int("wlc_key") == p) {
						if ((strlen(nvram_safe_get("wlc_wep_key")) == 5)
						 || (strlen(nvram_safe_get("wlc_wep_key")) == 13))
							fprintf(fp, "ApCliKey%dType=1\n",p);
						else if ((strlen(nvram_safe_get("wlc_wep_key")) == 10)
						      || (strlen(nvram_safe_get("wlc_wep_key")) == 26))
							fprintf(fp, "ApCliKey%dType=0\n",p);
						else
							fprintf(fp, "ApCliKey%dType=\n",p);
					}
					else
						 fprintf(fp, "ApCliKey%dType=\n",p);
				}

				//KeyStr
				for(p = 1 ; p <= 4; p++) {
					if (nvram_get_int("wlc_key") == p)
						fprintf(fp, "ApCliKey%dStr=%s\n",p,nvram_safe_get("wlc_wep_key"));
					else
						fprintf(fp, "ApCliKey%dStr=\n",p);
				}
			} else {
				fprintf(fp, "ApCliDefaultKeyID=0\n");
				fprintf(fp, "ApCliKey1Type=0\n");
				fprintf(fp, "ApCliKey1Str=\n");
				fprintf(fp, "ApCliKey2Type=0\n");
				fprintf(fp, "ApCliKey2Str=\n");
				fprintf(fp, "ApCliKey3Type=0\n");
				fprintf(fp, "ApCliKey3Str=\n");
				fprintf(fp, "ApCliKey4Type=0\n");
				fprintf(fp, "ApCliKey4Str=\n");
			}

			/* MACRepeaterOuiMode: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
			 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
			 */
#if defined(MAC_REPEATER)
			fprintf(fp, "MACRepeaterEn=1\n");
			fprintf(fp, "MACRepeaterOuiMode=2\n");
#else
			fprintf(fp, "MACRepeaterEn=0\n");
			fprintf(fp, "MACRepeaterOuiMode=0\n");
#endif
		}
		else
#endif	/* RTCONFIG_AMAS || RTCONFIG_CONCURRENTREPEATER */
#endif // RTCONFIG_WIRELESSREPEATER
		{
			fprintf(fp, "ApCliEnable=0\n");
			fprintf(fp, "ApCliSsid=\n");
			fprintf(fp, "ApCliBssid=\n");
			fprintf(fp, "ApCliAuthMode=\n");
			fprintf(fp, "ApCliEncrypType=\n");
			fprintf(fp, "ApCliWPAPSK=\n");
			fprintf(fp, "ApCliDefaultKeyID=0\n");
			fprintf(fp, "ApCliKey1Type=0\n");
			fprintf(fp, "ApCliKey1Str=\n");
			fprintf(fp, "ApCliKey2Type=0\n");
			fprintf(fp, "ApCliKey2Str=\n");
			fprintf(fp, "ApCliKey3Type=0\n");
			fprintf(fp, "ApCliKey3Str=\n");
			fprintf(fp, "ApCliKey4Type=0\n");
			fprintf(fp, "ApCliKey4Str=\n");
			fprintf(fp, "MACRepeaterEn=0\n");
			fprintf(fp, "MACRepeaterOuiMode=0\n");
		}

	/* RadioOn
	 * Only two cmm_profile.c of kernel 3.10, 4.4 parse it, one parameter.
	 * NOTE: Merged DBDC*.dat has only one set of parameters and follow band0's parameter!
	 * Seems not work parameter on MT798X, kernel 5.4
	 */
	fprintf(fp, "RadioOn=%d\n", 1);
#if defined(RTCONFIG_MTK_BSD)
#if defined(RTCONFIG_WLMODULE_MT7915D_AP)
	fprintf(fp, "MapMode=%d\n", 2);
#endif			
#endif	
	/* IgmpSnEnable:
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 3.10 (mt7628, mt7615e_4402, mt7615e_man)
	 * DBDC_BAND_NUM parameter:
	 *      kernel 3.10 (mt7663, mt7663_v6020, mt7663e, mt7615e, mt7615e_4411, mt7615e_4421, mt7615e_5040)
	 *      kernel 4.4 (src-ra-openwrt-4110's mt_wifi, mt5050)
	 * BssidNum parameter:
	 *      kernel 4.4 (src-ra-openwrt-4110's mt7915, mt7915_v7400)
	 *      kernel 5.4
	 */

#if defined(RTCONFIG_MT798X) || defined(RTCONFIG_WLMODULE_MT7915D_AP)
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "IgmpSnEnable", nvram_pf_get(prefix, "igs")? : "0");
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "IgmpSnEnable", nvram_pf_get(prefix, "igs")? : "0");
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "IgmpSnEnable", nvram_pf_get(prefix, "igs")? : "0");
#endif

	/*	McastPhyMode, PHY mode for Multicast frames
	 *	McastMcs, MCS for Multicast frames
	 *
	 *	MODE=1, MCS=0: Legacy CCK 1Mbps
	 *	MODE=1, MCS=1: Legacy CCK 2Mbps
	 *	MODE=1, MCS=2: Legacy CCK 5.5Mbps
	 *	MODE=1, MCS=3: Legacy CCK 11Mbps
	 *	MODE=2, MCS=0: Legacy OFDM 6Mbps
	 *	MODE=2, MCS=1: Legacy OFDM 9Mbps
	 *	MODE=2, MCS=2: Legacy OFDM 12Mbps
	 *	MODE=2, MCS=3: Legacy OFDM 18Mbps
	 *	MODE=2, MCS=4: Legacy OFDM 24Mbps
	 * 	MODE=2, MCS=5: Legacy OFDM 36Mbps
	 *	MODE=2, MCS=6: Legacy OFDM 48Mbps
	 *	MODE=2, MCS=7: Legacy OFDM 54Mbps
	 *	MODE=3, MCS=0: HTMIX 6.5/15Mbps
	 *	MODE=3, MCS=1: HTMIX 13/30Mbps
	 *	MODE=3, MCS=2: HTMIX 19.5/45Mbps
	 *	MODE=3, MCS=7: HTMIX 65/150Mbps
	 *	MODE=3, MCS=8: HTMIX 13/30Mbps 2S
	 *	MODE=3, MCS=9: HTMIX 26/60Mbps 2S
	 *	MODE=3, MCS=10: HTMIX 39/90Mbps 2S
	 *	MODE=3, MCS=15: HTMIX 130/300Mbps 2S
	 */
	i = nvram_pf_get_int(prefix, "mrate_x");
next_mrate:
	switch (i++) {
	default:
	case 0:/* Driver default setting: Disable, means automatic rate instead of fixed rate
		* Please refer to #ifdef MCAST_RATE_SPECIFIC section in
		* file linuxxxx/drivers/net/wireless/rtxxxx/common/mlme.c
		*/
		mcast_phy = 0, mcast_mcs = 0;
		break;
	case 1: /* Legacy CCK 1Mbps */
		mcast_phy = 1, mcast_mcs = 0;
		break;
	case 2: /* Legacy CCK 2Mbps */
		mcast_phy = 1, mcast_mcs = 1;
		break;
	case 3: /* Legacy CCK 5.5Mbps */
		mcast_phy = 1, mcast_mcs = 2;
		break;
	case 4: /* Legacy OFDM 6Mbps */
		mcast_phy = 2, mcast_mcs = 0;
		break;
	case 5: /* Legacy OFDM 9Mbps */
		mcast_phy = 2, mcast_mcs = 1;
		break;
	case 6: /* Legacy CCK 11Mbps */
		mcast_phy = 1, mcast_mcs = 3;
		break;
	case 7: /* Legacy OFDM 12Mbps */
		mcast_phy = 2, mcast_mcs = 2;
		break;
	case 8: /* Legacy OFDM 18Mbps */
		mcast_phy = 2, mcast_mcs = 3;
		break;
	case 9: /* Legacy OFDM 24Mbps */
		mcast_phy = 2, mcast_mcs = 4;
		break;
	case 10:/* Legacy OFDM 36Mbps */
		mcast_phy = 2, mcast_mcs = 5;
		break;
	case 11:/* Legacy OFDM 48Mbps */
		mcast_phy = 2, mcast_mcs = 6;
		break;
	case 12:/* Legacy OFDM 54Mbps */
		mcast_phy = 2, mcast_mcs = 7;
		break;
	case 13:/* HTMIX 130/300Mbps 2S */
		mcast_phy = 3, mcast_mcs = 15;
		break;
	case 14:/* HTMIX 6.5/15Mbps */
		mcast_phy = 3, mcast_mcs = 0;
		break;
	case 15:/* HTMIX 13/30Mbps */
		mcast_phy = 3, mcast_mcs = 1;
		break;
	case 16:/* HTMIX 19.5/45Mbps */
		mcast_phy = 3, mcast_mcs = 2;
		break;
	case 17:/* HTMIX 13/30Mbps 2S */
		mcast_phy = 3, mcast_mcs = 8;
		break;
	case 18:/* HTMIX 26/60Mbps 2S */
		mcast_phy = 3, mcast_mcs = 9;
		break;
	case 19:/* HTMIX 39/90Mbps 2S */
		mcast_phy = 3, mcast_mcs = 10;
		break;
	case 20:
		/* Choose multicast rate base on mode, encryption type, and IPv6 is enabled or not. */
		__choose_mrate(prefix, &mcast_phy, &mcast_mcs);
		break;
	}
#if defined(RTCONFIG_MT798X)
	/* No CCK for 2GHz if Disable 11B is enabled. */
	if (band == WL_2G_BAND && mcast_phy == 1 && nvram_pf_match(prefix, "rateset", "ofdm")) {
		/* If Disable 11B is enabled, don't use 11B rate, CCK 1/2/5.5/11Mbps. */
		goto next_mrate;
	}
#endif
	/* No CCK for 5Ghz band */
	if (band && mcast_phy == 1)
		goto next_mrate;

	/* McastPhyMode:
	 * BssidNum parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: 2.6, 3.10
	 */
	snprintf(tmp, sizeof(tmp), "%d", mcast_phy);
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "McastPhyMode", tmp);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "McastPhyMode", tmp);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "McastPhyMode", tmp);
#endif

	/* McastMcs
	 * BssidNum parameters: kernel 4.4, 5.4
	 * one parameter:
	 *      kernel 2.6
	 *      kernel 3.10 (mt7628 and 7615E_4402)
	 * two parameters:
	 *      kernel 3.10 (mt7663, mt7663_v6020, mt7663e, 7615E, 7615E_4410, 7615E_4421, 7615E_5040, 7615E_MAN)
	 */
	snprintf(tmp, sizeof(tmp), "%d", mcast_mcs);
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,4,0))
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "McastMcs", tmp);
#elif (LINUX_KERNEL_VERSION >= KERNEL_VERSION(2,6,0)) \
   && (LINUX_KERNEL_VERSION <  KERNEL_VERSION(3,10,0))
	enum_sname_mvalue_w_fixed_value(fp, 1, "McastMcs", tmp);
#else
	/* FIXME */
	enum_sname_mvalue_w_fixed_value(fp, 1, "McastMcs", tmp);
#endif

	/* Set WSC/WPS variables */
	if(band)
		str = " (5G)";
	else
		str = "";
	/* WscManufacturer, WscModelName, WscModelNumber, WscSerialNumber:
	 * 	one parameter: kernel 2.6, 3.10, 4.4, 5.4
	 * WscDeviceName:
	 * 	DBDC_BAND_NUM parameters: kernel 4.4, 5.4
	 * 	one parameter: kernel 2.6, 3.10, 4.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	/* WscV2Support:
	 * 	BssidNum parameters: kernel 2.6, 3.10, 4.4, 5.4
	 */
	fprintf(fp, "WscManufacturer=%s\n", "ASUSTeK Computer Inc.");
	fprintf(fp, "WscModelName=%s%s\n", "WPS Router", str);
	fprintf(fp, "WscDeviceName=%s%s\n", "ASUS WPS Router", str);
	fprintf(fp, "WscModelNumber=%s\n", get_productid());
	fprintf(fp, "WscSerialNumber=%s\n", "00000000");

	/* WPS/WSC v2 feature allows client to create connection via the PinCode of AP.
	 * Disable this feature causes longer detection time (click AP till show dialog box) on WIN7 client when WSC disabled either.
	 */
	enum_sname_mvalue_w_fixed_value(fp, ssid_num, "WscV2Support", "0");

	/* Set number of clients of guest network. */
	/* MaxStaNum: BssidNum parameters @ kernel 2.6, 3.10; kernel 4.4, 5.4, and another 3.10 doesn't support it.
	 * MbssMaxStaNum: BssidNum parameter @ kernel 3.10, 4.4, 5.4
	 * FIXME: wlx.y_guest_num doesn't exist.
	 */
#if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(3,10,0))
	fprintf(fp, "MbssMaxStaNum=0");
#else
	fprintf(fp, "MaxStaNum=0");
#endif
	for (i = 1; i < MAX_NO_MSSID; i++) {
		int maxsta;

		if (!main_wifi_or_enabled_guest_network(band, i, prefix_mssid, sizeof(prefix_mssid)))
			continue;

		maxsta = nvram_pf_get_int(prefix_mssid, "guest_num");
		/* If maxsta illegal, disable MaxStaNum. */
		if (maxsta < 0 || maxsta > 255)
			maxsta = 0;
		fprintf(fp, ";%d", maxsta);
	}
	fprintf(fp, "\n");

#if defined (RTCONFIG_WLMODULE_RT3352_INIC_MII)
	if (is_iNIC)
		fprintf(fp, "ExtEEPROM=%d\n", 1);

	if (is_iNIC && sw_mode() == SW_MODE_ROUTER)	// Only limite access of Guest network in Router mode
	{
		int vlan_id_1st = INIC_VLAN_ID_START;
		int vlan_id;
		char buf1[32], buf2[32], buf3[32];
		char *p1, *p2, *p3;

		p1 = buf1;
		p2 = buf2;
		p3 = buf3;
		memset(buf1, 0, sizeof(buf1));
		memset(buf2, 0, sizeof(buf2));
		memset(buf3, 0, sizeof(buf3));

		for (i = 1; i < MAX_NO_MSSID; i++)
		{
			vlan_id = 0;	// vlan id 1 for LAN access

			sprintf(prefix_mssid, "wl%d.%d_", band, i);
			if (!is_bss_enabled(prefix_mssid))
				continue;
			if (nvram_match(strcat_r(prefix_mssid, "lanaccess", temp), "off"))
				vlan_id = vlan_id_1st++;	// vlan id for no LAN access

			p1 += sprintf(p1, ";%d", vlan_id);
			p2 += sprintf(p2, ";%d", 0);
			p3 += sprintf(p3, ";%d", 0);
		}

		if(vlan_id_1st != INIC_VLAN_ID_START)
		{ //has vlan-based MBSSID for LAN access control but would make the wifi QoS field fixed at 0 (Best Effort).
			fprintf(fp, "VLAN_ID=0%s\n", buf1);
			fprintf(fp, "VLAN_TAG=0%s\n", buf2);
			fprintf(fp, "VLAN_Priority=0%s\n", buf3);
			fprintf(fp, "SwitchRemoveTag=1;1;1;1;1;0;0\n");
		}
	}
#endif

#if defined(RTAC1200) || defined(RTAC1200V2) || defined(RTN11P_B1) || defined(RTACRH18)
	/* Set 2.4G's LED variables */
	/* LEDMethod: one parameter @ kernel 2.6, 3.10, MT7628 only.
	 */
	if(!band)
		fprintf(fp, "LEDMethod=1\n");
#endif

#if defined (RTCONFIG_WLMODULE_MT7615E_AP) || defined(RTCONFIG_WLMODULE_MT7663E_AP) || defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7622_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)
#if !defined(RTCONFIG_MT798X)
	/* EfuseBufferMode: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	fprintf(fp, "EfuseBufferMode=0\n");
#endif
	/* E2pAccessMode: one parameter @ kernel 2.6, 3.10, 4.4, 5.4 */
	fprintf(fp, "E2pAccessMode=2\n");
	/* 256,1024-QAM can't be enabled, if HT mode is not enabled. */
#if defined (RTCONFIG_QAM256_2G)
	/* 2.4G 256QAM */
	/* G_BAND_256QAM: kernel 3.10+, one parameter @ kernel 3.10, 4.4, 5.4 */
	if(!band) {
		str = (nvram_pf_get_int(prefix, "nmode_x") != 2)? nvram_pf_safe_get(prefix, "turbo_qam") : 0;
		if (str && strlen(str))
			fprintf(fp, "G_BAND_256QAM=%d\n", safe_atoi(str));
	}
#endif
#if defined(RTCONFIG_QAM1024_5G)
	/* Vht1024QamSupport: kernel 4.10+, one parameter @ kernel 4.10 (mt7915_v7400), 5.4 */
	if(band) {
		str = (nvram_pf_get_int(prefix, "nmode_x") != 2)? nvram_pf_safe_get(prefix, "turbo_qam") : 0;
		if (str && strlen(str))
			fprintf(fp, "Vht1024QamSupport=%d\n", safe_atoi(str));
	}
#endif
	/* SKUenable:
	 * DBDC_BAND_NUM parameters: kernel 3.10, 4.4, 5.4
	 * one parameter: kernel 2.6, 3.10
	 */
#if defined(RTAC85P) ||	 defined(RTACRH26) || defined(TUFAC1750) || defined(RT4GAC86U) || defined(RTCONFIG_MT798X)
	/* MFG: SKUenable always zero. */
	if (strlen(nvram_safe_get("territory_code")) != 0)
		fprintf(fp, "SKUenable=1\n");
	else
		fprintf(fp, "SKUenable=0\n");
#else
	fprintf(fp, "SKUenable=1\n");
#endif
	/* WirelessEvent: one parameter @ kernel 2.6, 3.10, 4.4, 5.4
	 * NOTE: Merged DBDC*.dat has only one parameter and follow band0's parameter!
	 */
	fprintf(fp, "WirelessEvent=1\n");
#endif

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_BLINK_LED)
	if (aimesh_re_node()) {
		append_netdev_bled_if(get_wl_led_gpio_nv(band), get_staifname(band));
	}
#endif

	if (warning) {
		printf("warning: %d!!!!\n", warning);
		printf("Miss some configuration, please check!!!!\n");
	}

	fclose(fp);
	return 0;
}


PAIR_CHANNEL_FREQ_ENTRY ChannelFreqTable[] = {
	//channel Frequency
	{1,     2412000},
	{2,     2417000},
	{3,     2422000},
	{4,     2427000},
	{5,     2432000},
	{6,     2437000},
	{7,     2442000},
	{8,     2447000},
	{9,     2452000},
	{10,    2457000},
	{11,    2462000},
	{12,    2467000},
	{13,    2472000},
	{14,    2484000},
	{34,    5170000},
	{36,    5180000},
	{38,    5190000},
	{40,    5200000},
	{42,    5210000},
	{44,    5220000},
	{46,    5230000},
	{48,    5240000},
	{52,    5260000},
	{56,    5280000},
	{60,    5300000},
	{64,    5320000},
	{100,   5500000},
	{104,   5520000},
	{108,   5540000},
	{112,   5560000},
	{116,   5580000},
	{120,   5600000},
	{124,   5620000},
	{128,   5640000},
	{132,   5660000},
	{136,   5680000},
	{140,   5700000},
	{149,   5745000},
	{153,   5765000},
	{157,   5785000},
	{161,   5805000},
};

char G_bRadio = 1;
int G_nChanFreqCount = sizeof (ChannelFreqTable) / sizeof(PAIR_CHANNEL_FREQ_ENTRY);

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

/****************************** TYPES ******************************/

/*
 *	Struct iw_range up to WE-15
 */
struct	iw15_range
{
	__u32		throughput;
	__u32		min_nwid;
	__u32		max_nwid;
	__u16		num_channels;
	__u8		num_frequency;
	struct iw_freq	freq[IW15_MAX_FREQUENCIES];
	__s32		sensitivity;
	struct iw_quality	max_qual;
	__u8		num_bitrates;
	__s32		bitrate[IW15_MAX_BITRATES];
	__s32		min_rts;
	__s32		max_rts;
	__s32		min_frag;
	__s32		max_frag;
	__s32		min_pmp;
	__s32		max_pmp;
	__s32		min_pmt;
	__s32		max_pmt;
	__u16		pmp_flags;
	__u16		pmt_flags;
	__u16		pm_capa;
	__u16		encoding_size[IW15_MAX_ENCODING_SIZES];
	__u8		num_encoding_sizes;
	__u8		max_encoding_tokens;
	__u16		txpower_capa;
	__u8		num_txpower;
	__s32		txpower[IW15_MAX_TXPOWER];
	__u8		we_version_compiled;
	__u8		we_version_source;
	__u16		retry_capa;
	__u16		retry_flags;
	__u16		r_time_flags;
	__s32		min_retry;
	__s32		max_retry;
	__s32		min_r_time;
	__s32		max_r_time;
	struct iw_quality	avg_qual;
};

/*
 * Union for all the versions of iwrange.
 * Fortunately, I mostly only add fields at the end, and big-bang
 * reorganisations are few.
 */
union	iw_range_raw
{
	struct iw15_range	range15;	/* WE 9->15 */
	struct iw_range		range;		/* WE 16->current */
};

/*
 * Offsets in iw_range struct
 */
#define iwr15_off(f)	( ((char *) &(((struct iw15_range *) NULL)->f)) - \
			  (char *) NULL)
#define iwr_off(f)	( ((char *) &(((struct iw_range *) NULL)->f)) - \
			  (char *) NULL)

/* Disable runtime version warning in ralink_get_range_info() */
int iw_ignore_version_sp = 0;

/*------------------------------------------------------------------*/
/*
 * Get the range information out of the driver
 */
int
ralink_get_range_info(iwrange *	range, char* buffer, int length)
{
  union iw_range_raw *	range_raw;

  /* Point to the buffer */
  range_raw = (union iw_range_raw *) buffer;

  /* For new versions, we can check the version directly, for old versions
   * we use magic. 300 bytes is a also magic number, don't touch... */
  if (length < 300)
    {
      /* That's v10 or earlier. Ouch ! Let's make a guess...*/
      range_raw->range.we_version_compiled = 9;
    }

  /* Check how it needs to be processed */
  if (range_raw->range.we_version_compiled > 15)
    {
      /* This is our native format, that's easy... */
      /* Copy stuff at the right place, ignore extra */
      memcpy((char *) range, buffer, sizeof(iwrange));
    }
  else
    {
      /* Zero unknown fields */
      bzero((char *) range, sizeof(struct iw_range));

      /* Initial part unmoved */
      memcpy((char *) range,
	     buffer,
	     iwr15_off(num_channels));
      /* Frequencies pushed futher down towards the end */
      memcpy((char *) range + iwr_off(num_channels),
	     buffer + iwr15_off(num_channels),
	     iwr15_off(sensitivity) - iwr15_off(num_channels));
      /* This one moved up */
      memcpy((char *) range + iwr_off(sensitivity),
	     buffer + iwr15_off(sensitivity),
	     iwr15_off(num_bitrates) - iwr15_off(sensitivity));
      /* This one goes after avg_qual */
      memcpy((char *) range + iwr_off(num_bitrates),
	     buffer + iwr15_off(num_bitrates),
	     iwr15_off(min_rts) - iwr15_off(num_bitrates));
      /* Number of bitrates has changed, put it after */
      memcpy((char *) range + iwr_off(min_rts),
	     buffer + iwr15_off(min_rts),
	     iwr15_off(txpower_capa) - iwr15_off(min_rts));
      /* Added encoding_login_index, put it after */
      memcpy((char *) range + iwr_off(txpower_capa),
	     buffer + iwr15_off(txpower_capa),
	     iwr15_off(txpower) - iwr15_off(txpower_capa));
      /* Hum... That's an unexpected glitch. Bummer. */
      memcpy((char *) range + iwr_off(txpower),
	     buffer + iwr15_off(txpower),
	     iwr15_off(avg_qual) - iwr15_off(txpower));
      /* Avg qual moved up next to max_qual */
      memcpy((char *) range + iwr_off(avg_qual),
	     buffer + iwr15_off(avg_qual),
	     sizeof(struct iw_quality));
    }

  /* We are now checking much less than we used to do, because we can
   * accomodate more WE version. But, there are still cases where things
   * will break... */
  if (!iw_ignore_version_sp)
    {
      /* We don't like very old version (unfortunately kernel 2.2.X) */
      if (range->we_version_compiled <= 10)
	{
	  dbg("Warning: Driver for the device has been compiled with an ancient version\n");
	  dbg("of Wireless Extension, while this program support version 11 and later.\n");
	  dbg("Some things may be broken...\n\n");
	}

      /* We don't like future versions of WE, because we can't cope with
       * the unknown */
      if (range->we_version_compiled > WE_MAX_VERSION)
	{
	  dbg("Warning: Driver for the device has been compiled with version %d\n", range->we_version_compiled);
	  dbg("of Wireless Extension, while this program supports up to version %d.\n", WE_VERSION);
	  dbg("Some things may be broken...\n\n");
	}

      /* Driver version verification */
      if ((range->we_version_compiled > 10) &&
	 (range->we_version_compiled < range->we_version_source))
	{
	  dbg("Warning: Driver for the device recommend version %d of Wireless Extension,\n", range->we_version_source);
	  dbg("but has been compiled with version %d, therefore some driver features\n", range->we_version_compiled);
	  dbg("may not be available...\n\n");
	}
      /* Note : we are only trying to catch compile difference, not source.
       * If the driver source has not been updated to the latest, it doesn't
       * matter because the new fields are set to zero */
    }

  /* Don't complain twice.
   * In theory, the test apply to each individual driver, but usually
   * all drivers are compiled from the same kernel. */
  iw_ignore_version_sp = 1;

  return (0);
}

int
getSSID(int band)
{
	struct iwreq wrq;
	wrq.u.data.flags = 0;
	char buffer[33];
	bzero(buffer, sizeof(buffer));
	wrq.u.essid.pointer = (caddr_t) buffer;
	wrq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
	wrq.u.essid.flags = 0;

	if (wl_ioctl(get_wifname(band), SIOCGIWESSID, &wrq) < 0)
	{
		dbg("!!!\n");
		return 0;
	}

	if (wrq.u.essid.length>0)
	{
		unsigned char SSID[33];
		memset(SSID, 0, sizeof(SSID));
		memcpy(SSID, wrq.u.essid.pointer, wrq.u.essid.length);
		puts(SSID);
	}

	return 0;
}

int
getChannel(int band)
{
	int channel;
	struct iw_range	range;
	double freq;
	struct iwreq wrq1;
	struct iwreq wrq2;
	char ch_str[3];

	if (wl_ioctl(get_wifname(band), SIOCGIWFREQ, &wrq1) < 0)
		return 0;

	char buffer[sizeof(iwrange) * 2];
	bzero(buffer, sizeof(buffer));
	wrq2.u.data.pointer = (caddr_t) buffer;
	wrq2.u.data.length = sizeof(buffer);
	wrq2.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), SIOCGIWRANGE, &wrq2) < 0)
		return 0;

	if (ralink_get_range_info(&range, buffer, wrq2.u.data.length) < 0)
		return 0;

	freq = iw_freq2float(&(wrq1.u.freq));
	if (freq < KILO)
		channel = (int) freq;
	else
	{
		channel = iw_freq_to_channel(freq, &range);
		if (channel < 0)
			return 0;
	}

	memset(ch_str, 0, sizeof(ch_str));
	sprintf(ch_str, "%d", channel);
	puts(ch_str);
	return 0;
}

int startScan(int band)
{
    struct iwreq wrq;
    int lock, chk_hidden_ap;
    char data[255];
    char tmp[128], prefix[] = "wlXXXXXXXXXX_";
    char *ssid;
    const char *aif;
    int channel;

    if ((sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")))
    {
        snprintf(prefix, sizeof(prefix), "wlc%d_", band);
        chk_hidden_ap = nvram_get_int(strcat_r(prefix, "closed", tmp));
        aif = get_staifname(band);
	channel=ra_get_channel(band);
	if(!channel)
		eval("iwpriv", (char*)aif, "set", "Channel=0");
    }
    else
    {
        snprintf(prefix, sizeof(prefix), "wl%d_", band);
        chk_hidden_ap = 0;
        aif = get_wifname(band);
    }
    ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));

    memset(data, 0x00, 255);
    if (chk_hidden_ap == 1)
    {
        sprintf(data, "SiteSurvey=%s", ssid);
    } else
    {
        strcpy(data, "SiteSurvey=1");
    }
    wrq.u.data.length = strlen(data) + 1;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;

    lock = file_lock("sitesurvey");
    if (wl_ioctl(aif, RTPRIV_IOCTL_SET, &wrq) < 0) {
        file_unlock(lock);
        dbg("Site Survey fails\n");
        return 0;
    }
    file_unlock(lock);
    sleep(4);

    return 1;
}

int getSiteSurveyVSIEcount(int band)
{
    struct iwreq wrq;
    char data[255];
    const char *aif;

    if ((sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")))
    {
        aif = get_staifname(band);
    }
    else
    {
        aif = get_wifname(band);
    }

    memset(data, 0, 255);
    strcpy(data, "");
    wrq.u.data.length = 255;
    wrq.u.data.pointer = data;
    wrq.u.data.flags = ASUS_SUBCMD_GETSITESURVEY_VSIE_COUNT;

    if (wl_ioctl(aif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
    {
        dbg("errors in getting site survey vie result\n");
        return 0;
    }

    /*dbg("******* count = %s(%d)\n", wrq.u.data.pointer, atoi(wrq.u.data.pointer));*/
    sleep(2);
    return atoi(wrq.u.data.pointer);
}

int getSiteSurveyVSIE(int band, struct _SITESURVEY_VSIE *result, int length)
{
	char data[length];
	struct iwreq wrq;
	const char *aif;

	if ((sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")))
	{
		aif = get_staifname(band);
	}
	else
	{
		aif = get_wifname(band);
	}

	memset(data, 0, length);
	strcpy(data, "");
	wrq.u.data.length = length;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = ASUS_SUBCMD_GETSITESURVEY_VSIE;

	if (wl_ioctl(aif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting site survey vie result\n");
		return 0;
	}

    if (wrq.u.data.length <= 0) {
        dbg("errors in getting site survey vie result. length: %d\n", wrq.u.data.length);
        return 0;
    }

    if (result)
        memcpy(result, wrq.u.data.pointer, wrq.u.data.length);
    else {
        dbg("The output var result is NULL\n");
        return 0;
    }

    return 1;
}

int
getSiteSurvey(int band,char* ofile)
{
	int i = 0, apCount = 0;
	char data[8192*2];
	char header[128];
	struct iwreq wrq;
	SSA *ssap;
	int lock;
	FILE *fp;
	char ssid_str[256],tmp[256];
	char ure_mac[18] = { 0 };
	int wl_authorized = 0;
	memset(data, 0x00, 255);
	strcpy(data, "SiteSurvey=1");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;
#if defined(RTCONFIG_MTK_BSD)
	int restart_bs20 = 0;
#endif


#ifdef RTCONFIG_MTK_REP
	    char folder_path[] = "/tmp/ssidList";
	    char file_ssidlist[30]={0};
		char *fp_list = NULL;
		memset(file_ssidlist, 0x0, sizeof(file_ssidlist));

 		if ( access(folder_path, F_OK) != 0 )
		if (ENOENT == errno)
			mkdir(folder_path, 0755);

		sprintf(file_ssidlist, "/tmp/ssidList/ssid%d.txt", band );

		fp_list=fopen(file_ssidlist, "w+");
#endif

#if defined(RTCONFIG_MTK_BSD)
	if (nvram_match("smart_connect_x", "1") && pids("bs20")) {
		stop_mtk_bs20();
		restart_bs20 = 1;
	}
#endif
	lock = file_lock("sitesurvey");
	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0)
	{
		file_unlock(lock);

		dbg("Site Survey fails\n");
		return 0;
	}
	file_unlock(lock);

	dbg("Please wait");
	sleep(1);
	dbg(".");
	sleep(1);
	dbg(".");
	sleep(1);
	dbg(".");
	sleep(1);
	dbg(".\n\n");

	memset(data, 0, sizeof(data));
	strcpy(data, "");
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_GSITESURVEY, &wrq) < 0)
	{
		dbg("errors in getting site survey result\n");
		return 0;
	}

#if defined(RTCONFIG_MTK_BSD)
	if (restart_bs20)
		start_mtk_bs20();
#endif

	memset(header, 0, sizeof(header));
	//sprintf(header, "%-3s%-33s%-18s%-8s%-15s%-9s%-8s%-2s\n", "Ch", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode", "NT");
	sprintf(header, "%-4s%-33s%-18s%-9s%-16s%-9s%-8s\n", "Ch", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode");
	dbg("\n%s", header);

	if (wrq.u.data.length > 0 && strlen(wrq.u.data.pointer)>0)
	{
		ssap=(SSA *)(wrq.u.data.pointer+strlen(header)+1);
		int len = strlen(wrq.u.data.pointer+strlen(header))-1;
		char *sp, *op;
		int stlen = strlen(header) -1; /* the header is one byte more than struct SiteSurvey[] */
 		op = sp = wrq.u.data.pointer+strlen(header)+1;

		while (*sp && (sp +stlen -op) <= len)
		{
			ssap->SiteSurvey[i].channel[3] = '\0';
			ssap->SiteSurvey[i].ssid[32] = '\0';
			ssap->SiteSurvey[i].bssid[17] = '\0';
			ssap->SiteSurvey[i].encryption[8] = '\0';
			ssap->SiteSurvey[i].authmode[15] = '\0';
			ssap->SiteSurvey[i].signal[8] = '\0';
			ssap->SiteSurvey[i].wmode[7] = '\0';
#if 0
			ssap->SiteSurvey[i].wps[3] = '\0';
			ssap->SiteSurvey[i].dpid[4] = '\0';
#endif
			sp+=stlen;
			apCount=++i;
		}

		for (i=0;i<apCount;i++)
		{
			dbg("%-4s%-33s%-18s%-9s%-16s%-9s%-8s\n",
				ssap->SiteSurvey[i].channel,
				(char*)ssap->SiteSurvey[i].ssid,
				ssap->SiteSurvey[i].bssid,
				ssap->SiteSurvey[i].encryption,
				ssap->SiteSurvey[i].authmode,
				ssap->SiteSurvey[i].signal,
				ssap->SiteSurvey[i].wmode
//				ssap->SiteSurvey[i].bsstype,
//				ssap->SiteSurvey[i].centralchannel
			);
#ifdef RTCONFIG_MTK_REP
		trim_r((char*)ssap->SiteSurvey[i].ssid);
		fprintf(fp_list, "%s\n", (char*)ssap->SiteSurvey[i].ssid );
#endif
		}
#ifdef RTCONFIG_MTK_REP
		fclose(fp_list);
#endif
		dbg("\n");

		if (apCount > 0){
			/* write pid */
			if ((fp = fopen(ofile, "a")) == NULL){
				printf("[wlcscan] Output %s error\n", ofile);
			}else{
				for (i = 0; i < apCount; i++){
					if(atoi(ssap->SiteSurvey[i].channel) < 0 )
					{
						fprintf(fp, "\"ERR_BAND\",");
					}else if( atoi(ssap->SiteSurvey[i].channel) > 0 && atoi(ssap->SiteSurvey[i].channel) < 14)
					{
						fprintf(fp, "\"2G\",");
					}else if( atoi(ssap->SiteSurvey[i].channel) > 14 && atoi(ssap->SiteSurvey[i].channel) < 166)
					{
						fprintf(fp, "\"5G\",");
					}
					else{
						fprintf(fp, "\"ERR_BAND\",");
					}

					if (strlen(ssap->SiteSurvey[i].ssid) == 0){
						fprintf(fp, "\"\",");
					}else{
						//memset(ssid_str, 0, sizeof(ssid_str));
						//char_to_ascii(ssid_str, ssap->SiteSurvey[i].ssid);
						//fprintf(fp, "\"%s\",", ssid_str);

						memset(tmp, 0, sizeof(tmp));
						memset(ssid_str, 0, sizeof(ssid_str));

						strncpy(tmp,ssap->SiteSurvey[i].ssid,strlen(trim_r(ssap->SiteSurvey[i].ssid)));
#if defined(RTCONFIG_UTF8_SSID)
						char_to_ascii_with_utf8(ssid_str, tmp);
#else
						char_to_ascii(ssid_str, tmp);
#endif
						//strncpy(ssid_str,ssap->SiteSurvey[i].ssid,strlen(trim_r(ssap->SiteSurvey[i].ssid)));
						fprintf(fp, "\"%s\",", ssid_str);
					}

					fprintf(fp, "\"%d\",", atoi(ssap->SiteSurvey[i].channel));

					if(strstr(ssap->SiteSurvey[i].authmode,"WPA-Enterprise"))
						fprintf(fp, "\"%s\",","WPA-Enterprise");
					else if(strstr(ssap->SiteSurvey[i].authmode,"WPA2-Enterprise"))
						fprintf(fp, "\"%s\",","WPA2-Enterprise");
					else if(strstr(ssap->SiteSurvey[i].authmode,"WPA-Personal"))
						fprintf(fp, "\"%s\",","WPA-Personal");
					else if(strstr(ssap->SiteSurvey[i].authmode,"WPA2-Personal"))
						fprintf(fp, "\"%s\",","WPA2-Personal");
					else if(strstr(ssap->SiteSurvey[i].authmode,"WPA3-Personal"))
						fprintf(fp, "\"%s\",","WPA3-Personal");
					else if(strstr(ssap->SiteSurvey[i].authmode,"WPA2PSKWPA3PSK"))
						fprintf(fp, "\"%s\",","WPA2PSKWPA3PSK");
					else if(strstr(ssap->SiteSurvey[i].authmode,"Open System")) {
						if(strstr(ssap->SiteSurvey[i].encryption, "WEP"))
							fprintf(fp, "\"%s\",","Unknown");
						else
							fprintf(fp, "\"%s\",","Open System");
					}
					else
						fprintf(fp, "\"%s\",","Unknown");

					if(strstr(ssap->SiteSurvey[i].encryption, "NONE"))
						fprintf(fp, "\"%s\",", "NONE");
					else if(strstr(ssap->SiteSurvey[i].encryption, "WEP"))
						fprintf(fp, "\"%s\",", "WEP");
					else if(strstr(ssap->SiteSurvey[i].encryption, "TKIP"))
						fprintf(fp, "\"%s\",", "TKIP");
					else if(strstr(ssap->SiteSurvey[i].encryption, "AES"))
						fprintf(fp, "\"%s\",", "AES");
					else
						fprintf(fp, "\"%s\",", "UNKNOW");

#if 0
					if (apinfos[i].wpa == 1){
						if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X_)
							fprintf(fp, "\"%s\",", "WPA");
						else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X2_)
							fprintf(fp, "\"%s\",", "WPA2");
						else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_PSK_)
							fprintf(fp, "\"%s\",", "WPA-PSK");
						else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_PSK2_)
							fprintf(fp, "\"%s\",", "WPA2-PSK");
						else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_NONE_)
							fprintf(fp, "\"%s\",", "NONE");
						else if (apinfos[i].wid.key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA_)
							fprintf(fp, "\"%s\",", "IEEE 802.1X");
						else
							fprintf(fp, "\"%s\",", "Unknown");
					}else if (apinfos[i].wep == 1){
						fprintf(fp, "\"%s\",", "Unknown");
					}else{
						fprintf(fp, "\"%s\",", "Open System");
					}

					if (apinfos[i].wpa == 1){
						if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_NONE_)
							fprintf(fp, "\"%s\",", "NONE");
						else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_WEP40_)
							fprintf(fp, "\"%s\",", "WEP");
						else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_WEP104_)
							fprintf(fp, "\"%s\",", "WEP");
						else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_TKIP_)
							fprintf(fp, "\"%s\",", "TKIP");
						else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_CCMP_)
							fprintf(fp, "\"%s\",", "AES");
						else if (apinfos[i].wid.pairwise_cipher == WPA_CIPHER_TKIP_|WPA_CIPHER_CCMP_)
							fprintf(fp, "\"%s\",", "TKIP+AES");
						else
							fprintf(fp, "\"%s\",", "Unknown");
					}else if (apinfos[i].wep == 1){
						fprintf(fp, "\"%s\",", "WEP");
					}else{
						fprintf(fp, "\"%s\",", "NONE");
					}
#endif
					fprintf(fp, "\"%d\",", atoi(ssap->SiteSurvey[i].signal));
					fprintf(fp, "\"%s\",", ssap->SiteSurvey[i].bssid);
					if(strcmp(ssap->SiteSurvey[i].wmode,"11b    ")==0)
						fprintf(fp, "\"%s\",", "b");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11a    ")==0)
						fprintf(fp, "\"%s\",", "a");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11a/n  ")==0)
						fprintf(fp, "\"%s\",", "an");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11b/g  ")==0)
						fprintf(fp, "\"%s\",", "bg");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11b/g/n")==0)
						fprintf(fp, "\"%s\",", "bgn");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11ac   ")==0)
						fprintf(fp, "\"%s\",", "ac");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11bgnax")==0)
						fprintf(fp, "\"%s\",", "ax");
					else if(strcmp(ssap->SiteSurvey[i].wmode,"11ax   ")==0)
						fprintf(fp, "\"%s\",", "ax");
					else
						fprintf(fp, "\"%s\",", "");




#if 0
					if (apinfos[i].NetworkType == Ndis802_11FH || apinfos[i].NetworkType == Ndis802_11DS)
						fprintf(fp, "\"%s\",", "b");
					else if (apinfos[i].NetworkType == Ndis802_11OFDM5)
						fprintf(fp, "\"%s\",", "a");
					else if (apinfos[i].NetworkType == Ndis802_11OFDM5_N)
						fprintf(fp, "\"%s\",", "an");
					else if (apinfos[i].NetworkType == Ndis802_11OFDM5_VHT)
						fprintf(fp, "\"%s\",", "ac");
					else if (apinfos[i].NetworkType == Ndis802_11OFDM24)
						fprintf(fp, "\"%s\",", "bg");
					else if (apinfos[i].NetworkType == Ndis802_11OFDM24_N)
						fprintf(fp, "\"%s\",", "bgn");
					else
						fprintf(fp, "\"%s\",", "");
#endif
					if (strcmp(nvram_safe_get(wlc_nvname("ssid")), ssap->SiteSurvey[i].ssid)){
						if (strcmp(ssap->SiteSurvey[i].ssid, ""))
							fprintf(fp, "\"%s\"", "0");				// none
						else if (!strcmp(ure_mac, ssap->SiteSurvey[i].bssid)){
							// hidden AP (null SSID)
							if (strstr(nvram_safe_get(wlc_nvname("akm")), "psk")){
								if (wl_authorized){
									// in profile, connected
									fprintf(fp, "\"%s\"", "4");
								}else{
									// in profile, connecting
									fprintf(fp, "\"%s\"", "5");
								}
							}else{
								// in profile, connected
								fprintf(fp, "\"%s\"", "4");
							}
						}else{
							// hidden AP (null SSID)
							fprintf(fp, "\"%s\"", "0");				// none
						}
					}else if (!strcmp(nvram_safe_get(wlc_nvname("ssid")), ssap->SiteSurvey[i].ssid)){
						if (!strlen(ure_mac)){
							// in profile, disconnected
							fprintf(fp, "\"%s\"", "1");
						}else if (!strcmp(ure_mac, ssap->SiteSurvey[i].bssid)){
							if (strstr(nvram_safe_get(wlc_nvname("akm")), "psk")){
								if (wl_authorized){
									// in profile, connected
									fprintf(fp, "\"%s\"", "2");
								}else{
									// in profile, connecting
									fprintf(fp, "\"%s\"", "3");
								}
							}else{
								// in profile, connected
								fprintf(fp, "\"%s\"", "2");
							}
						}else{
							fprintf(fp, "\"%s\"", "0");				// impossible...
						}
					}else{
						// wl0_ssid is empty
						fprintf(fp, "\"%s\"", "0");
					}

					if (i == apCount - 1){
						fprintf(fp, "\n");
					}else{
						fprintf(fp, "\n");
					}
				}	/* for */
				fclose(fp);
			}
		}	/* if */



	}
	else
	{
		dbg("no ap!!\n");
		return 0;
	}

	return 1;
}

int getBSSID(int band)	// get AP's BSSID
{
	unsigned char data[MACSIZE];
	char macaddr[18];
	struct iwreq wrq;

	memset(data, 0x00, MACSIZE);
	wrq.u.data.length = MACSIZE;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = OID_802_11_BSSID;

	if (wl_ioctl(get_wifname(band), RT_PRIV_IOCTL, &wrq) < 0)
	{
		dbg("errors in getting bssid!\n");
		return -1;
	}
	else
	{
		ether_etoa(data, macaddr);
		puts(macaddr);
		return 0;
	}
}

#if defined(RTCONFIG_WIRELESSREPEATER)
int site_survey_for_channel(int n, const char *wif, int *HT_EXT)
{
	char tmp[128], header[128],prefix[] = "wlXXXXXXXXXX_";
	char *ssid;

	snprintf(prefix, sizeof(prefix), "wl%d_", n);
	ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));

	if (!ssid || !strcmp(ssid, "")) {
		return -1;
	}

	int i = 0, apCount = 0;
	char data[16384];
	struct iwreq wrq;
	SSA *ssap;
#ifdef RTCONFIG_RALINK_MT7629
    int chk_hidden_ap = 1;
#else    
	int chk_hidden_ap = nvram_get_int(strcat_r(prefix, "hide_pap", tmp));
#endif    
#if defined(RTCONFIG_AMAS)
	if ((sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")))
	{
		chk_hidden_ap = nvram_get_int(strcat_r(prefix, "closed", tmp));
	}
#ifdef RTCONFIG_PRELINK
	if ((sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1") && nvram_match("prelink", "1")))
	{
		chk_hidden_ap = 1;
	}
#endif
#endif
	int commonchannel, ht_extcha = 1;
	int wep __attribute__((unused)) = 0;

	if (nvram_invmatch(strcat_r(prefix, "wep_x", tmp), "0")
			|| nvram_match(strcat_r(prefix, "auth_mode", tmp), "psk"))
		wep = 1;

	memset(data, 0x00, sizeof(data));
	if (chk_hidden_ap == 1) {
		sprintf(data, "SiteSurvey=%s", ssid);
	}else
		strcpy(data, "SiteSurvey=1");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(wif, RTPRIV_IOCTL_SET, &wrq) < 0) {
		fprintf(stderr, "Site Survey fails\n");
		return -1;
	}

	fprintf(stderr, "Look for SSID: %s\n", ssid);
	fprintf(stderr, "Please wait");
	sleep(1);
	fprintf(stderr, ".");
	sleep(1);
	fprintf(stderr, ".");
	sleep(1);
	fprintf(stderr, ".");
	sleep(1);
	fprintf(stderr, ".\n");

	memset(data, 0x0, sizeof(data));
	strcpy(data, "");
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(wif, RTPRIV_IOCTL_GSITESURVEY, &wrq) < 0) {
		fprintf(stderr, "errors in getting site survey result\n");
		return -1;
	}

	memset(header, 0, sizeof(header));
	sprintf(header, "%-4s%-33s%-18s%-9s%-16s%-9s%-8s\n", "Ch", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode");
	//dbg("\n%s", header);
	if (wrq.u.data.length > 0) {
		char commch[4];
		int signal_max = -1, signal_tmp = -1, idx = -1;
		ssap = (SSA *)(wrq.u.data.pointer + strlen(header)+1);
		int len = strlen(wrq.u.data.pointer + strlen(header))-1;
		char *sp, *op;
 		op = sp = wrq.u.data.pointer + strlen(header)+1;

		while (*sp && ((len - (sp-op)) >= 0)) {
			ssap->SiteSurvey[i].channel[3] = '\0';
			ssap->SiteSurvey[i].ssid[32] = '\0';
			ssap->SiteSurvey[i].bssid[17] = '\0';
			ssap->SiteSurvey[i].encryption[8] = '\0';
			ssap->SiteSurvey[i].authmode[15] = '\0';
			ssap->SiteSurvey[i].signal[8] = '\0';
			ssap->SiteSurvey[i].wmode[7] = '\0';

			sp += strlen(header);
			apCount = ++i;
		}

		if (apCount) {
			for (i = 0; i < apCount; i++) {
				memset(commch,0,sizeof(commch));
				memcpy(commch,ssap->SiteSurvey[i].channel,3);
				commonchannel=atoi(commch);

				//fprintf(stderr, "##common ch=%d##\n",commonchannel);
#if 0
				memset(cench,0,sizeof(cench));
				memcpy(cench,ssap->SiteSurvey[i].centralchannel,3);
				centralchannel = atoi(cench);
				if (strstr(ssap->SiteSurvey[i].bsstype, "n")
						&& (commonchannel != centralchannel)) {
					if (n) {
						if (centralchannel < commonchannel)
							ht_extcha = 0;
						else
							ht_extcha = 1;
					}
					else {
						if (commonchannel <= 4)
							ht_extcha = 1;
						else if (commonchannel > 4 && commonchannel < 8) {
							if (centralchannel < commonchannel)
								ht_extcha = 0;
							else
								ht_extcha = 1;
						}
						else if (commonchannel >= 8) {
							char *value = nvram_safe_get("wl0_reg");

							if (!strcmp(value,"2G_CH11"))
								channellistnum = 11;
							else if (!strcmp(value,"2G_CH14"))
								channellistnum = 14;
							else	// 2G_CH13
								channellistnum = 13;

							if ((channellistnum - commonchannel) < 4)
								ht_extcha = 0;
							else {
								if (centralchannel < commonchannel)
									ht_extcha = 0;
								else
									ht_extcha = 1;
							}
						}
					}
				}
				else
#endif
					ht_extcha = -1;
/*
				_dprintf(
					"%-4s%-33s%-18s%-9s%-16s%-9s%-8s\n",
					ssap->SiteSurvey[i].channel,
					(char*)ssap->SiteSurvey[i].ssid,
					ssap->SiteSurvey[i].bssid,
					ssap->SiteSurvey[i].encryption,
					ssap->SiteSurvey[i].authmode,
					ssap->SiteSurvey[i].signal,
					ssap->SiteSurvey[i].wmode);

*/
				if ((ssid && !strcmp(ssid, trim_r(ssap->SiteSurvey[i].ssid)))/*non-hidden AP*/
				 ) {

					if (chk_hidden_ap == 1) {
							nvram_set(strcat_r(prefix, "bssid", tmp), ssap->SiteSurvey[i].bssid);
					}

					if (!strncmp(ssap->SiteSurvey[i].bssid, nvram_safe_get(strcat_r(prefix, "bssid", tmp)), 17)) {
						*HT_EXT = ht_extcha;
						return commonchannel;
					}
					else if ((signal_tmp = atoi(trim_r(ssap->SiteSurvey[i].signal))) > signal_max) {
						signal_max = signal_tmp;
						//ht_extcha_max = ht_extcha;
						idx = commonchannel;
					}
				}
			}
			fprintf(stderr, "\n");

		}

		if (idx != -1) {
			//*HT_EXT = ht_extcha_max;
			return idx;
		}
	}

	return -1;
}
#endif	/* RTCONFIG_WIRELESSREPEATER */

int
ra_get_channel(int band)
{
	int channel;
	struct iw_range	range;
	double freq;
	struct iwreq wrq1;
	struct iwreq wrq2;

	if (wl_ioctl(get_wifname(band), SIOCGIWFREQ, &wrq1) < 0)
		return 0;

	char buffer[sizeof(iwrange) * 2];
	bzero(buffer, sizeof(buffer));
	wrq2.u.data.pointer = (caddr_t) buffer;
	wrq2.u.data.length = sizeof(buffer);
	wrq2.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), SIOCGIWRANGE, &wrq2) < 0)
		return 0;

	if (ralink_get_range_info(&range, buffer, wrq2.u.data.length) < 0)
		return 0;

	freq = iw_freq2float(&(wrq1.u.freq));
	if (freq < KILO)
		channel = (int) freq;
	else
	{
		channel = iw_freq_to_channel(freq, &range);
		if (channel < 0)
			return 0;
	}

	return channel;
}

int
asuscfe(const char *PwqV, const char *IF)
{
	if (strcmp(PwqV, "stat") == 0)
	{
		eval("iwpriv", (char*) IF, "stat");
	}
	else if (strstr(PwqV, "=") && strstr(PwqV, "=")!=PwqV)
	{
		eval("iwpriv", (char*) IF, "set", (char*) PwqV);
		puts("1");
	}
	return 0;
}

int
__need_to_start_wps_band(char *prefix)
{
	char *p, tmp[128];

	if (!prefix || *prefix == '\0')
		return 0;

	p = nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp));
	if ((!strcmp(p, "open") && !nvram_match(strcat_r(prefix, "wep_x", tmp), "0")) ||
	    !strcmp(p, "shared") || !strcmp(p, "psk") || !strcmp(p, "wpa") ||
	    !strcmp(p, "wpa2") || !strcmp(p, "wpawpa2") || !strcmp(p, "radius") ||
	    nvram_match(strcat_r(prefix, "radio", tmp), "0") ||
	    !((sw_mode() == SW_MODE_ROUTER) || (sw_mode() == SW_MODE_AP)))
		return 0;

	return 1;
}

int need_to_start_wps_band(int wps_band)
{
	int ret = 1;
	char prefix[] = "wlXXXXXXXXXX_";

	switch (wps_band) {
	case 0:	/* fall through */
	case 1:
		snprintf(prefix, sizeof(prefix), "wl%d_", wps_band);
		ret = __need_to_start_wps_band(prefix);
		break;
	default:
		ret = 0;
	}

	return ret;
}

#if defined (W7_LOGO) || defined (wifi_LOGO)
int
wps_pin(int pincode)
{
	int i, wps_band = nvram_get_int("wps_band_x"), multiband = get_wps_multiband();
	char str_lan_ipaddr[16];
	char tmp[128], prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];

	if (nvram_match("lan_ipaddr", ""))
		return 0;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		eval("route", "delete", "239.255.255.250");
		kill_pidfile_s_rm(get_wscd_pidfile_band(i), SIGKILL, 1);

		dbg("%s: start wsc (%d)\n", __func__, i);


#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(i));	// Stop WPS Process.
#endif

		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 7);		// Enrollee + Proxy + Registrar

		eval("route", "add", "-host", "239.255.255.250", "dev", "br0");
		strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));
		doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(i));

		dbg("WPS: PIN\n");					// PIN method
		doSystem("iwpriv %s set WscMode=1", get_wifname(i));

		if (pincode == 0) {
			g_isEnrollee[i] = 1;
			doSystem("iwpriv %s set WscPinCode=%d", get_wifname(i), 0);
			doSystem("iwpriv %s set WscGetConf=%d", get_wifname(i), 1);	// Trigger WPS AP to do simple config with WPS Client
		}
		else {
			doSystem("iwpriv %s set WscPinCode=%08d", get_wifname(i), pincode);
			doSystem("iwpriv %s set WscGetConf=%d", get_wifname(i), 1);	// Trigger WPS AP to do simple config with WPS Client
		}

		++i;
	}

	return 0;
}

static int
__wps_pbc(const int multiband)
{
	int i, wps_band = nvram_get_int("wps_band_x");
	char str_lan_ipaddr[16];
	char tmp[128], prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];

	if (nvram_match("lan_ipaddr", ""))
		return 0;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		eval("route", "delete", "239.255.255.250");
		kill_pidfile_s_rm(get_wscd_pidfile_band(i), SIGKILL, 1);

		dbg("%s: start wsc (%d)\n", __func__, i);

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(i));	// Stop WPS Process.
#endif

		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 7);		// Enrollee + Proxy + Registrar

		eval("route", "add", "-host", "239.255.255.250", "dev", "br0");
		strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));
		doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(i));

//		dbg("WPS: PBC\n");
		g_isEnrollee[i] = 1;
		doSystem("iwpriv %s set WscMode=%d", get_wifname(i), 2);		// PBC method
		doSystem("iwpriv %s set WscGetConf=%d", get_wifname(i), 1);		// Trigger WPS AP to do simple config with WPS Client

		++i;
	}

	return 0;
}

int
wps_pbc(void)
{
	return __wps_pbc(get_wps_multiband());
}

int
wps_pbc_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	return __wps_pbc(1);
#else
	char str_lan_ipaddr[16];

	if (nvram_match("lan_ipaddr", ""))
		return 0;

	if (!__need_to_start_wps_band("wl1") || !__need_to_start_wps_band("wl0")) return 0;

	eval("route", "delete", "239.255.255.250");

#if defined(RTCONFIG_HAS_5G)
	kill_pidfile_s_rm(get_wscd_pidfile_band(1), SIGKILL, 1);
#endif	/* RTCONFIG_HAS_5G */
	kill_pidfile_s_rm(get_wscd_pidfile_band(0), SIGKILL, 1);

	dbg("%s: start wsc ()\n", __func__);

#if defined(RTCONFIG_HAS_5G)
#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(1));	// Stop WPS Process.
#endif

	doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 7);		// Enrollee + Proxy + Registrar
#endif	/* RTCONFIG_HAS_5G */

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(0));	// Stop WPS Process.
#endif

	doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 7);		// Enrollee + Proxy + Registrar

	eval("route", "add", "-host", "239.255.255.250", "dev", "br0");
	strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));
#if defined(RTCONFIG_HAS_5G)
	doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(1));
#endif	/* RTCONFIG_HAS_5G */
	doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(0));

//	dbg("WPS: PBC\n");
#if defined(RTCONFIG_HAS_5G)
	g_isEnrollee[1] = 1;
	doSystem("iwpriv %s set WscMode=%d", get_wifname(1), 2);		// PBC method
	doSystem("iwpriv %s set WscGetConf=%d", get_wifname(1), 1);		// Trigger WPS AP to do simple config with WPS Client
#endif	/* RTCONFIG_HAS_5G */

	g_isEnrollee[0] = 1;
	doSystem("iwpriv %s set WscMode=%d", get_wifname(0), 2);		// PBC method
	doSystem("iwpriv %s set WscGetConf=%d", get_wifname(0), 1);		// Trigger WPS AP to do simple config with WPS Client

	return 0;
#endif	/* RTCONFIG_WPSMULTIBAND */
}
#else	/* !(defined (W7_LOGO) || defined (wifi_LOGO)) */
int
wps_pin(int pincode)
{
	int i;
	char prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x"), multiband = get_wps_multiband();

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

//		dbg("WPS: PIN\n");
		doSystem("iwpriv %s set WscMode=1", get_wifname(i));

		if (pincode == 0) {
			doSystem("iwpriv %s set WscGetConf=%d", get_wifname(i), 1);	// Trigger WPS AP to do simple config with WPS Client
		} else {
			doSystem("iwpriv %s set WscPinCode=%08d", get_wifname(i), pincode);
		}

		++i;
	}

	return 0;
}

static int
__wps_pbc(const int multiband)
{
	int i;
	char prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x");

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

//		dbg("WPS: PBC\n");
		g_isEnrollee[i] = 1;
		doSystem("iwpriv %s set WscMode=%d", get_wifname(i), 2);		// PBC method
		doSystem("iwpriv %s set WscGetConf=%d", get_wifname(i), 1);	// Trigger WPS AP to do simple config with WPS Client

		++i;
	}

	return 0;
}

int
wps_pbc(void)
{
	return __wps_pbc(get_wps_multiband());
}

int
wps_pbc_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	return __wps_pbc(1);
#else
	if (!__need_to_start_wps_band("wl1") || !__need_to_start_wps_band("wl0")) return 0;

//	dbg("WPS: PBC\n");
#if defined(RTCONFIG_HAS_5G)
	g_isEnrollee[1] = 1;
	doSystem("iwpriv %s set WscMode=%d", get_wifname(1), 2);		// PBC method
	doSystem("iwpriv %s set WscGetConf=%d", get_wifname(1), 1);		// Trigger WPS AP to do simple config with WPS Client
#endif	/* RTCONFIG_HAS_5G */

	g_isEnrollee[0] = 1;
	doSystem("iwpriv %s set WscMode=%d", get_wifname(0), 2);		// PBC method
	doSystem("iwpriv %s set WscGetConf=%d", get_wifname(0), 1);		// Trigger WPS AP to do simple config with WPS Client

	return 0;
#endif
}
#endif	/* defined (W7_LOGO) || defined (wifi_LOGO) */

extern void wl_default_wps(int unit);

void
__wps_oob(const int multiband)
{
	int i, wps_band = nvram_get_int("wps_band_x");
	char tmp[128], prefix[] = "wlXXXXXXXXXX_", word[256], *next;
	char *p, ifnames[128];

	if (nvram_match("lan_ipaddr", ""))
		return;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);
		nvram_set("w_Setting", "0");
		if (!i)
			nvram_set("wl0_wsc_config_state", "0");
		else
			nvram_set("wl1_wsc_config_state", "0");

		wl_default_wps(i);

		nvram_commit();

	snprintf(prefix, sizeof(prefix), "wl%d_", wps_band);
#if defined (W7_LOGO) || defined (wifi_LOGO)
		doSystem("iwpriv %s set AuthMode=%s", get_wifname(i), "OPEN");
		doSystem("iwpriv %s set EncrypType=%s", get_wifname(i), "NONE");
		doSystem("iwpriv %s set IEEE8021X=%d", get_wifname(i), 0);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key1", tmp)))))
			iwprivSet(get_wifname(i), "Key1", p);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key2", tmp)))))
			iwprivSet(get_wifname(i), "Key2", p);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key3", tmp)))))
			iwprivSet(get_wifname(i), "Key3", p);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key4", tmp)))))
			iwprivSet(get_wifname(i), "Key4", p);
		doSystem("iwpriv %s set DefaultKeyID=%s", get_wifname(i), nvram_safe_get(strcat_r(prefix, "key", tmp)));
		iwprivSet(get_wifname(i), "SSID", nvram_safe_get(strcat_r(prefix, "ssid", tmp)));

		eval("route", "delete", "239.255.255.250");
		kill_pidfile_s_rm(get_wscd_pidfile_band(i), SIGKILL, 1);

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(i));	// Stop WPS Process.
#endif

		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 7);		// Enrollee + Proxy + Registrar
		doSystem("iwpriv %s set WscConfStatus=%d", get_wifname(i), 1);		// AP is unconfigured
		g_wsc_configured = 0;

		eval("route", "add", "-host", "239.255.255.250", "dev", "br0");
		strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));
		doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(i));

		doSystem("iwpriv %s set WscMode=1", get_wifname(i));			// PIN method
//		doSystem("iwpriv %s set WscGetConf=%d", get_wifname(i), 1);		// Trigger WPS AP to do simple config with WPS Client
#else
		doSystem("iwpriv %s set AuthMode=%s", get_wifname(i), "OPEN");
		doSystem("iwpriv %s set EncrypType=%s", get_wifname(i), "NONE");
		doSystem("iwpriv %s set IEEE8021X=%d", get_wifname(i), 0);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key1", tmp)))))
			iwprivSet(get_wifname(i), "Key1", p);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key2", tmp)))))
			iwprivSet(get_wifname(i), "Key2", p);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key3", tmp)))))
			iwprivSet(get_wifname(i), "Key3", p);
		if (strlen((p = nvram_safe_get(strcat_r(prefix, "key4", tmp)))))
			iwprivSet(get_wifname(i), "Key4", p);
		doSystem("iwpriv %s set DefaultKeyID=%s", get_wifname(i), nvram_safe_get(strcat_r(prefix, "key", tmp)));
		iwprivSet(get_wifname(i), "SSID", nvram_safe_get(strcat_r(prefix, "ssid", tmp)));

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 0);		// WPS disabled. Force WPS status to change
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(i));	// Stop WPS Process.
#endif
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 7);		// WPS enabled. Force WPS status to change
		doSystem("iwpriv %s set WscConfStatus=%d", get_wifname(i), 1);		// AP is unconfigured
#endif
		g_isEnrollee[i] = 0;

		++i;
	}
}

void
wps_oob(void)
{
	__wps_oob(get_wps_multiband());
}

void
wps_oob_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	__wps_oob(1);
#else
	if (nvram_match("lan_ipaddr", ""))
		return;

//	if (!__need_to_start_wps_band("wl1") || !__need_to_start_wps_band("wl0")) return 0;

	nvram_set("w_Setting", "0");
	nvram_set("wl0_wsc_config_state", "0");
	nvram_set("wl1_wsc_config_state", "0");
	wl_defaults_wps();

	nvram_commit();

#if defined (W7_LOGO) || defined (wifi_LOGO)
#if defined(RTCONFIG_HAS_5G)
	doSystem("iwpriv %s set AuthMode=%s", get_wifname(1), "OPEN");
	doSystem("iwpriv %s set EncrypType=%s", get_wifname(1), "NONE");
	doSystem("iwpriv %s set IEEE8021X=%d", get_wifname(1), 0);
	if (strlen(nvram_safe_get("wl1_key1")))
		iwprivSet(get_wifname(1), "Key1", nvram_safe_get("wl1_key1"));
	if (strlen(nvram_safe_get("wl1_key2")))
		iwprivSet(get_wifname(1), "Key2", nvram_safe_get("wl1_key2"));
	if (strlen(nvram_safe_get("wl1_key3")))
		iwprivSet(get_wifname(1), "Key3", nvram_safe_get("wl1_key3"));
	if (strlen(nvram_safe_get("wl1_key4")))
		iwprivSet(get_wifname(1), "Key4", nvram_safe_get("wl1_key4"));
	doSystem("iwpriv %s set DefaultKeyID=%s", get_wifname(1), nvram_safe_get("wl1_key"));
	iwprivSet(get_wifname(1), "SSID", nvram_safe_get("wl1_ssid"));
#endif	/* RTCONFIG_HAS_5G */

	doSystem("iwpriv %s set AuthMode=%s", get_wifname(0), "OPEN");
	doSystem("iwpriv %s set EncrypType=%s", get_wifname(0), "NONE");
	doSystem("iwpriv %s set IEEE8021X=%d", get_wifname(0), 0);
	if (strlen(nvram_safe_get("wl0_key1")))
		iwprivSet(get_wifname(0), "Key1", nvram_safe_get("wl0_key1"));
	if (strlen(nvram_safe_get("wl0_key2")))
		iwprivSet(get_wifname(0), "Key2", nvram_safe_get("wl0_key2"));
	if (strlen(nvram_safe_get("wl0_key3")))
		iwprivSet(get_wifname(0), "Key3", nvram_safe_get("wl0_key3"));
	if (strlen(nvram_safe_get("wl0_key4")))
		iwprivSet(get_wifname(0), "Key4", nvram_safe_get("wl0_key4"));
	doSystem("iwpriv %s set DefaultKeyID=%s", get_wifname(0), nvram_safe_get("wl0_key"));
	iwprivSet(get_wifname(0), "SSID", nvram_safe_get("wl0_ssid"));

	eval("route", "delete", "239.255.255.250");

	kill_pidfile_s_rm(get_wscd_pidfile_band(0), SIGKILL, 1);

#if defined(RTCONFIG_HAS_5G)
	kill_pidfile_s_rm(get_wscd_pidfile_band(1), SIGKILL, 1);
#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(1));	// Stop WPS Process.
#endif
	doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 7);		// Enrollee + Proxy + Registrar
	doSystem("iwpriv %s set WscConfStatus=%d", get_wifname(1), 1);		// AP is unconfigured
#endif	/* RTCONFIG_HAS_5G */

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(0));			// Stop WPS Process.
#endif
	doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 7);		// Enrollee + Proxy + Registrar
	doSystem("iwpriv %s set WscConfStatus=%d", get_wifname(0), 1);		// AP is unconfigured

	g_wsc_configured = 0;

	eval("route", "add", "-host", "239.255.255.250", "dev", "br0");

	char str_lan_ipaddr[16];
	strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));

#if defined(RTCONFIG_HAS_5G)
	doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(1));
	doSystem("iwpriv %s set WscMode=1", get_wifname(1));			// PIN method
//	doSystem("iwpriv %s set WscGetConf=%d", get_wifname(1), 1);		// Trigger WPS AP to do simple config with WPS Client
#endif	/* RTCONFIG_HAS_5G */

	doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(0));
	doSystem("iwpriv %s set WscMode=1", get_wifname(0));			// PIN method

#else
#if defined(RTCONFIG_HAS_5G)
	doSystem("iwpriv %s set AuthMode=%s", get_wifname(1), "OPEN");
	doSystem("iwpriv %s set EncrypType=%s", get_wifname(1), "NONE");
	doSystem("iwpriv %s set IEEE8021X=%d", get_wifname(1), 0);
	if (strlen(nvram_safe_get("wl1_key1")))
		iwprivSet(get_wifname(1), "Key1", nvram_safe_get("wl1_key1"));
	if (strlen(nvram_safe_get("wl1_key2")))
		iwprivSet(get_wifname(1), "Key2", nvram_safe_get("wl1_key2"));
	if (strlen(nvram_safe_get("wl1_key3")))
		iwprivSet(get_wifname(1), "Key3", nvram_safe_get("wl1_key3"));
	if (strlen(nvram_safe_get("wl1_key4")))
		iwprivSet(get_wifname(1), "Key4", nvram_safe_get("wl1_key4"));
	doSystem("iwpriv %s set DefaultKeyID=%s", get_wifname(1), nvram_safe_get("wl1_key"));
	iwprivSet(get_wifname(1), "SSID", nvram_safe_get("wl1_ssid"));

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(1));			// Stop WPS Process.
#endif
	doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 7);		// WPS enabled. Force WPS status to change
	doSystem("iwpriv %s set WscConfStatus=%d", get_wifname(1), 1);		// AP is unconfigured
#endif	/* RTCONFIG_HAS_5G */

	doSystem("iwpriv %s set AuthMode=%s", get_wifname(0), "OPEN");
	doSystem("iwpriv %s set EncrypType=%s", get_wifname(0), "NONE");
	doSystem("iwpriv %s set IEEE8021X=%d", get_wifname(0), 0);
	if (strlen(nvram_safe_get("wl0_key1")))
		iwprivSet(get_wifname(0), "Key1", nvram_safe_get("wl0_key1"));
	if (strlen(nvram_safe_get("wl0_key2")))
		iwprivSet(get_wifname(0), "Key2", nvram_safe_get("wl0_key2"));
	if (strlen(nvram_safe_get("wl0_key3")))
		iwprivSet(get_wifname(0), "Key3", nvram_safe_get("wl0_key3"));
	if (strlen(nvram_safe_get("wl0_key4")))
		iwprivSet(get_wifname(0), "Key4", nvram_safe_get("wl0_key4"));
	doSystem("iwpriv %s set DefaultKeyID=%s", get_wifname(0), nvram_safe_get("wl0_key"));
	iwprivSet(get_wifname(0), "SSID", nvram_safe_get("wl0_ssid"));
#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(0));			// Stop WPS Process.
#endif
	doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 7);		// WPS enabled. Force WPS status to change
	doSystem("iwpriv %s set WscConfStatus=%d", get_wifname(0), 1);		// AP is unconfigured
#endif
	g_isEnrollee[0] = 0;
#endif	/* RTCONFIG_WPSMULTIBAND */
}

void
start_wsc(void)
{
	int i;
	char *wps_sta_pin = nvram_safe_get("wps_sta_pin");
	char str_lan_ipaddr[16];
	char prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x"), multiband = get_wps_multiband();
	const char *wif;
	char prefix_vif[] = "wlXXXXXXXXXX_";

	if (nvram_match("lan_ipaddr", ""))
		return;

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		eval("route", "delete", "239.255.255.250");
		kill_pidfile_s_rm(get_wscd_pidfile_band(i), SIGKILL, 1);

		dbg("%s: start wsc(%d)\n", __func__, i);

#ifdef RTCONFIG_VIF_ONBOARDING
	if (nvram_get_int("wps_via_vif") && wps_band == i) {
		snprintf(prefix_vif, sizeof(prefix_vif), "wl%d.%d_ifname", wps_band,
			(!nvram_get_int("re_mode")) ? nvram_get_int("obvif_cap_subunit"): nvram_get_int("obvif_re_subunit"));
		wif = nvram_safe_get(prefix_vif);
	}
	else
#endif
		wif = get_wifname(i);

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", wif, 0);		// WPS disabled
#else
		doSystem("iwpriv %s set WscStop=1", wif);			// Stop WPS Process.
#endif
		doSystem("iwpriv %s set WscConfMode=%d", wif, 7);	// Enrollee + Proxy + Registrar

		eval("route", "add", "-host", "239.255.255.250", "dev", "br0");
		strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));
		doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, wif);

//#if defined (W7_LOGO) || defined (wifi_LOGO)
		if (strlen(wps_sta_pin) && strcmp(wps_sta_pin, "00000000") && (wl_wpsPincheck(wps_sta_pin) == 0)) {
			dbg("WPS: PIN\n");					// PIN method
			g_isEnrollee[i] = 0;
			doSystem("iwpriv %s set WscMode=1", wif);
			doSystem("iwpriv %s set WscPinCode=%s", wif, wps_sta_pin);
		}
		else {
			dbg("WPS: PBC\n");					// PBC method
			g_isEnrollee[i] = 1;
			doSystem("iwpriv %s set WscMode=2", wif);
//			doSystem("iwpriv %s set WscPinCode=%s", get_wifname(i), "00000000");
		}

		doSystem("iwpriv %s set WscGetConf=%d", wif, 1);	// Trigger WPS AP to do simple config with WPS Client
//#endif
		sleep(2);
		++i;
	}
}

void
start_wsc_pin_enrollee(void)
{
	int i;
	char str_lan_ipaddr[16];
	char prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x"), multiband = get_wps_multiband();

	if (nvram_match("lan_ipaddr", "")) {
		nvram_set("wps_enable", "0");
		return;
	}

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		eval("route", "add", "-host", "239.255.255.250", "dev", "br0");
		kill_pidfile_s_rm(get_wscd_pidfile_band(i), SIGKILL, 1);

		dbg("%s: start wsc (%d)\n", __func__, i);

		strcpy(str_lan_ipaddr, nvram_safe_get("lan_ipaddr"));
		doSystem("wscd -m 1 -a %s -i %s &", str_lan_ipaddr, get_wifname(i));
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 7);		// Enrollee + Proxy + Registrar

		dbg("WPS: PIN\n");
		doSystem("iwpriv %s set WscMode=1", get_wifname(i));

		++i;
	}

//	nvram_set("wps_start_flag", "1");
}

static void
__stop_wsc(int multiband)
{
	int i;
	char prefix[] = "wlXXXXXXXXXX_", word[256], *next, ifnames[128];
	int wps_band = nvram_get_int("wps_band_x");

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;
		if (!multiband && wps_band != i) {
			++i;
			continue;
		}
		SKIP_ABSENT_BAND_AND_INC_UNIT(i);
		snprintf(prefix, sizeof(prefix), "wl%d_", i);

		if (!need_to_start_wps_band(i)) {
			++i;
			continue;
		}

		eval("route", "delete", "239.255.255.250");
		kill_pidfile_s_rm(get_wscd_pidfile_band(i), SIGKILL, 1);

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(i), 0);		// WPS disabled
		doSystem("iwpriv %s set WscStatus=%d", get_wifname(i), 0);		// Not Used
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(i));			// Stop WPS Process.
#endif
		++i;
	}
}

void
stop_wsc(void)
{
	__stop_wsc(get_wps_multiband());
}

void
stop_wsc_both(void)
{
#if defined(RTCONFIG_WPSMULTIBAND)
	__stop_wsc(1);
#else
	if (!__need_to_start_wps_band("wl0")
#if defined(RTCONFIG_HAS_5G)
 && !__need_to_start_wps_band("wl1")
#endif	/* RTCONFIG_HAS_5G */
	   )
		return;

	system("route delete 239.255.255.250 1>/dev/null 2>&1");

	kill_pidfile_s_rm(get_wscd_pidfile_band(0), SIGKILL, 1);

#if defined(RTCONFIG_HAS_5G)
	kill_pidfile_s_rm(get_wscd_pidfile_band(1), SIGKILL, 1);
#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(1), 0);		// WPS disabled
		doSystem("iwpriv %s set WscStatus=%d", get_wifname(1), 0);		// Not Used
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(1));			// Stop WPS Process.
#endif
#endif	/* RTCONFIG_HAS_5G */

#if defined(RTCONFIG_RALINK_RT3883) || defined(RTCONFIG_RALINK_RT3052)
		doSystem("iwpriv %s set WscConfMode=%d", get_wifname(0), 0);		// WPS disabled
		doSystem("iwpriv %s set WscStatus=%d", get_wifname(0), 0);		// Not Used
#else
		doSystem("iwpriv %s set WscStop=1", get_wifname(0));			// Stop WPS Process.
#endif
#endif
}

int getWscStatus(int unit)
{
	int data = 0;
	int wps_band = unit? 1:0;
	char prefix[] = "wlXXXXXXXXXX_";

#ifdef RTCONFIG_VIF_ONBOARDING
	if (nvram_get_int("wps_via_vif") && nvram_get_int("wps_band_x") == unit) {
		snprintf(prefix, sizeof(prefix), "wl%d.%d_ifname", wps_band,
				(!nvram_get_int("re_mode")) ? nvram_get_int("obvif_cap_subunit"): nvram_get_int("obvif_re_subunit"));
	}
	else
#endif
		snprintf(prefix, sizeof(prefix), "wl%d_ifname", wps_band);

	data = getWscStatusCli(nvram_safe_get(prefix));

	return data;
}

int getWscProfile(char *interface, WSC_CONFIGURED_VALUE *data, int len)
{
	int socket_id;
	struct iwreq wrq;

	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy((char *)data, "get_wsc_profile");
	strcpy(wrq.ifr_name, interface);
	wrq.u.data.length = len;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = 0;
	ioctl(socket_id, RTPRIV_IOCTL_WSC_PROFILE, &wrq);
	close(socket_id);
	return 0;
}

int
stainfo(int band)
{
	char data[2048];
	struct iwreq wrq;

	memset(data, 0x00, 2048);
	wrq.u.data.length = 2048;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GSTAINFO;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting STAINFO result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
}

#if defined(RTCONFIG_AMAS)
int
getgroam(int band)
{
	char data[4096];
	struct iwreq wrq;

	memset(data, 0x00, 4096);
	wrq.u.data.length = 4096;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GROAM;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting GROAM result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
}

int
get_dfschannel(int band)
{
	char data[4096];
	struct iwreq wrq;

	memset(data, 0x00, 4096);
	wrq.u.data.length = 4096;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GDFSNOPCHANNEL;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting dfs channel result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
}

int
get_dfs_status(int band)
{
	int status = 0;
	status = amas_dfs_status(band);
	_dprintf("%d\n", status);

	return 0;
}

int
get_rrm_bcn_resp(int band)
{
	char data[4096];
	struct iwreq wrq;

	memset(data, 0x00, 4096);
	wrq.u.data.length = 4096;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_RRM_BCN_RESP;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting RRM_BCN_RESP result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
}

int
get_rclass(int band)
{
	_dprintf("%d\n", get_regular_class(get_wifname(band)));
	return 0;
}

int
getcliq(int band)
{
	char data[4096];
	struct iwreq wrq;

	memset(data, 0x00, 4096);
	wrq.u.data.length = 4096;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_CLIQ;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting CLIQ result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
}

int
getclrssi(int band)
{
	int rssi_ret = Pty_get_upstream_rssi(band);
	_dprintf("%d\n", rssi_ret);
	return 0;
}

int
get_apclien(int band)
{
	int enable = 0;
	char *aif = get_staifname(band);

	enable = get_wlc_func_enable(aif);
	_dprintf("%d\n", enable);

	return 0;
}

int
get_channelinfo(int band)
{
	const char *ifname = get_wifname(band);
	int channel = 0, bw = 0, nctrlsb = 0;
	get_channel_info(ifname, &channel, &bw, &nctrlsb);
	_dprintf("channel= %d\n", channel);
	_dprintf("bandwidth= %d\n", bw);
	if (bw == 40)
		_dprintf("nctrlsb= %d\n", nctrlsb);

	return 0;
}

#ifdef RTCONFIG_BTM_11V
#define DEBUG 0
void hex_dump_dbg(char *str, unsigned char *pSrcBufVA, unsigned int SrcBufLen)
{
	unsigned char *pt;
	int x;

	if(!DEBUG && nvram_get_int("btm_test") != 1)
		return;

	pt = pSrcBufVA;
	_dprintf("%s: %p, len = %d\n",str,  pSrcBufVA, SrcBufLen);

	for (x=0; x<SrcBufLen; x++) {
		if (x % 16 == 0)
			_dprintf("0x%04x : ", x);
		_dprintf("%02x ", ((unsigned char)pt[x]));
		if (x%16 == 15) _dprintf("\n");
	}
	_dprintf("\n");
}

int mbo_check_sta_preference_and_append_nr_list(
	struct wifi_app *wapp,
#if 0
	struct wapp_sta *sta,
#endif
	char *frame_pos,
	u16 *frame_len,
#if 0
	u8 frame_type,
#endif
	u8 disassoc_imnt
#if 0
	,u8 bss_term,
	u8 is_steer_to_cell
#endif
)
{
	u8 	list_len=0;
	u8 	i=0;
#if 0
	struct non_pref_ch_entry *npc_entry;
#endif
	u8 	btm_neighbor_report_header[2] = {0};

	if(wapp->daemon_nr_list.CurrListNum > 0){
		for(i=0;i<wapp->daemon_nr_list.CurrListNum;i++){
			wapp_nr_info nr_entry;
			u16 append_entry_len = NEIGHBOR_REPORT_IE_SIZE; /* append Bssid ~ CandidatePref */

			memcpy(&nr_entry, &wapp->daemon_nr_list.NRInfo[i], sizeof(wapp_nr_info));
#if 0
			if (sta){
				RRM_BSSID_INFO bss_info;

				/* step 1: in steering to cellular case, only append AP's own BSS as candidate */
				if(is_steer_to_cell)
				{
					if(!MAC_ADDR_EQUAL(nr_entry.Bssid,sta->bssid))
						continue;
					else
						DBGPRINT_RAW(RT_DEBUG_ERROR, "%s steer to cell, append ap's own bss!!\n",__FUNCTION__);
				}

				/* step 2: search STA CH list and fill preference */
				if(!dl_list_empty(&sta->non_pref_ch_list)){
					dl_list_for_each(npc_entry, &sta->non_pref_ch_list, struct non_pref_ch_entry, list) {

						if(npc_entry && npc_entry->npc.ch == nr_entry.ChNum)
							nr_entry.CandidatePref = npc_entry->npc.pref;
					}
				}else{
					if(sta->no_none_pref_ch != TRUE)
						DBGPRINT_RAW(RT_DEBUG_OFF,
							"%s %d - uxexpected npc list empty !!\n",
							__FUNCTION__,__LINE__);
				}
				/* step 3: if disassoc imminent , set AP's own bss neigbor report preference to 0 */
				DBGPRINT_RAW(RT_DEBUG_OFF, "\033[1;32m%s %d - frame_type==BTM? %d ,"
				" BSSID %02X:%02X:%02X:%02X:%02X:%02X  disassoc_imnt %d mac qual? %d\033[0m\n",
				__FUNCTION__,__LINE__,(frame_type == MBO_FRAME_BTM),PRINT_MAC(nr_entry.Bssid),
				disassoc_imnt,MAC_ADDR_EQUAL(nr_entry.Bssid,sta->bssid));
				if(frame_type == MBO_FRAME_BTM
				&& (disassoc_imnt || bss_term)
				&& MAC_ADDR_EQUAL(nr_entry.Bssid,sta->bssid)){
					nr_entry.CandidatePref = 0;

					DBGPRINT_RAW(RT_DEBUG_OFF, "%s %d - disassoc_imnt %d set ap_own_bss_pref 0!!\n",
						__FUNCTION__,__LINE__,disassoc_imnt);
				}

				/* step 4: update nr_entry security bit */
				bss_info.word = nr_entry.BssidInfo;
				bss_info.field.Security = \
					(mbo_check_bss_sta_security_match(sta,&nr_entry))?1:0;
				nr_entry.BssidInfo = bss_info.word;
			}
#endif
			/* element ID: 52, len: 16 */
			btm_neighbor_report_header[0] = IE_RRM_NEIGHBOR_REP;
			btm_neighbor_report_header[1] = append_entry_len;

			memcpy(frame_pos, &btm_neighbor_report_header, sizeof(btm_neighbor_report_header));
			frame_pos 	+= sizeof(btm_neighbor_report_header);
			*frame_len 	+= sizeof(btm_neighbor_report_header);
			list_len 	+= sizeof(btm_neighbor_report_header);

			/* append this nr_entry */
			memcpy(frame_pos, &nr_entry, append_entry_len);
			hex_dump_dbg("entry", (u8 *)frame_pos, append_entry_len);
			frame_pos += append_entry_len;
			*frame_len += append_entry_len;
			list_len  += append_entry_len;

			if(DEBUG || nvram_get_int("btm_test") == 1)
				_dprintf("append [%d] frame_pos %p frame_len %d mac %02x:%02x:%02x:%02x:%02x:%02x\n"
					,i,frame_pos,*frame_len,PRINT_MAC(nr_entry.Bssid));

		}
	}

	hex_dump_dbg("frame", (u8 *) (frame_pos-*frame_len), *frame_len);
	return list_len;
}

/*
octet	|1		 |2		|3			 |4			  |5~6				   |7				 | 0 or 12 (8~19)			 | variable				   | variable							  |
		|Category|Action|Dialog Token|Request Mode|Disassociation Timer|Validity Interval|	BSS Termination Duration | Session Information URL |BSS Transition Candidate List Entries |

*/

size_t wapp_build_btm_req(
	u8 req_mode,
	u16 disassoc_timer,
	u8 vad_intvl,
#if 0
	struct neighbor_report_subelement *bss_term_dur,
	char *url,
	size_t	 url_len,
#endif
	char *cand_list,
	size_t cand_list_len,
	char *btm_req_buf)
{
	size_t btm_req_len = 0;
	struct btm_payload *frame;
	char *pos = btm_req_buf;
#if 0
	struct neighbor_report_subelement *report_subelement;
#endif

	frame = (struct btm_payload *)btm_req_buf;

	frame->u.btm_req.request_mode = req_mode;
	pos += 1;
	btm_req_len += 1;

	frame->u.btm_req.disassociation_timer = cpu2le16(disassoc_timer);
	pos += 2;
	btm_req_len += 2;

	frame->u.btm_req.validity_interval = vad_intvl;
	pos += 1;
	btm_req_len += 1;

#if 0
	if (bss_term_dur) {
		report_subelement = (struct neighbor_report_subelement *)pos;
		report_subelement->subelement_id = BSS_TERMINATION_DURATION;
		report_subelement->length = 10;
		report_subelement->u.bss_termination_duration.bss_termination_tsf =
											cpu2le64(bss_term_dur->u.bss_termination_duration.bss_termination_tsf);
		report_subelement->u.bss_termination_duration.duration =
											cpu2le16(bss_term_dur->u.bss_termination_duration.duration);
		frame->u.btm_req.request_mode |= (1 << BSS_TERM_INCLUDED_BIT_MAP);
		pos += 12;
		btm_req_len += 12;
	}

	/* URL is included only when ESS Disassociation Imminent is set to 1 */
	if ((req_mode & (1 << ESS_DISASSOC_IMNT_BIT_MAP)) && url) {
		/* session url length */
		*pos = url_len;
		pos++;
		btm_req_len++;

		/* session url */
		os_memcpy(pos, url, url_len);
		pos += url_len;
		btm_req_len += url_len;
	}
#endif
	if (cand_list) {
			frame->u.btm_req.request_mode |= (1 << CAND_LIST_INCLUDED_BIT_MAP);

			memcpy(pos, cand_list, cand_list_len);
			pos += cand_list_len;
			btm_req_len += cand_list_len;
	}

	return btm_req_len;
}

void mbo_make_mbo_ie_for_btm(
	struct wifi_app *wapp,
	char *frame_pos,
	u16 *frame_len,
	u8 b_insert_cdcp,
	u8 b_insert_tran_reason,
	u8 tran_reason,
	u8 b_insert_retry_delay)
{
	u8 	AttrLen = 0;
	u8 	MBO_OCE_OUIBYTE[4] = {0x50, 0x6f, 0x9a, 0x16};
	u8 *tmpbuf = NULL;
	P_MBO_ATTR_STRUCT mbo_attr = NULL;
	struct mbo_cfg *mbo;

	if(!b_insert_cdcp && !b_insert_tran_reason && !b_insert_retry_delay){
		_dprintf("[%s] no need to add, return.\n",__FUNCTION__);
		return;
	}
	mbo = wapp->mbo;
	tmpbuf = (u8 *) malloc(1024);
	memset(tmpbuf, 0, 1024);

	if(tmpbuf == NULL){
		_dprintf("[%s] MEM ALLOC FAIL!!!!!!!\n",__FUNCTION__);
		return;
	}

	if(b_insert_cdcp){
		mbo_attr = (P_MBO_ATTR_STRUCT)(tmpbuf + AttrLen);
		mbo_attr->AttrID = MBO_ATTR_AP_CDCP;
		mbo_attr->AttrLen = 1;
		mbo_attr->AttrBody[0] = mbo->cdcp;

		AttrLen	+= 3;
	}
	if(b_insert_tran_reason){
		mbo_attr = (P_MBO_ATTR_STRUCT)(tmpbuf + AttrLen);
		mbo_attr->AttrID = MBO_ATTR_AP_TRANS_REASON;
		mbo_attr->AttrLen = 1;
		mbo_attr->AttrBody[0] = tran_reason;

		AttrLen	+= 3;
	}
	if(b_insert_retry_delay){
		mbo_attr = (P_MBO_ATTR_STRUCT)(tmpbuf + AttrLen);
		mbo_attr->AttrID = MBO_ATTR_AP_ASSOC_RETRY_DELAY;
		mbo_attr->AttrLen = 2;
		memcpy(&mbo_attr->AttrBody[0], &mbo->assoc_retry_delay, 2);
		AttrLen	+= 4;
	}

	*frame_pos 	= IE_MBO_ELEMENT_ID;
	frame_pos	+= 1;
	*frame_len 	+= 1;

	*frame_pos 	= AttrLen + 4;
	frame_pos	+= 1;
	*frame_len 	+= 1;

	memcpy(frame_pos, MBO_OCE_OUIBYTE, 4);
	frame_pos	+= 4;
	*frame_len 	+= 4;

	memcpy(frame_pos, tmpbuf, AttrLen);
	frame_pos	+= AttrLen;
	*frame_len 	+= AttrLen;

	free(tmpbuf);
	hex_dump_dbg("mbo_make_mbo_ie_for_btm", (u8 *) (frame_pos-*frame_len), *frame_len);

	return;
}

static int driver_wext_set_oid(const char *ifname,
			   unsigned short oid, char *data, size_t len)
{
    char *buf;
    struct iwreq iwr;

    buf = (char *) malloc(len);
    memset(buf, 0, len);

    memset(&iwr, 0, sizeof(iwr));
    snprintf(iwr.ifr_name, IFNAMSIZ, "%s", ifname);
    iwr.u.data.flags = oid;
    iwr.u.data.flags |= OID_GET_SET_TOGGLE;

    if (data)
        memcpy(buf, data, len);

    if (buf) {
        iwr.u.data.pointer = (caddr_t)buf;
        iwr.u.data.length = len;
    } else {
        iwr.u.data.pointer = NULL;
        iwr.u.data.length = 0;
    }

    if (wl_ioctl(ifname, RT_PRIV_IOCTL, &iwr) < 0) {
        _dprintf("[%s] oid=0x%x len (%zu) failed\n", __FUNCTION__, oid, len);
        free(buf);
        return -1;
    }

    free(buf);
    return 0;
}

int driver_wnm_send_btm_req_raw(const char *ifname,
			   const char *btm_req_raw, u32 param_len)
{
	int len;
	struct wnm_command *cmd_data = NULL;

	len = sizeof(struct wnm_command)+ param_len;
	cmd_data = (struct wnm_command *) malloc(len);
	memset(cmd_data, 0, len);

	if (!cmd_data) {
		_dprintf("[%s] cmd_data alloc fail\n", __FUNCTION__);
		return 0;
	}

	cmd_data->command_id = OID_802_11_WNM_CMD_SEND_BTM_REQ_IE;
	cmd_data->command_len = param_len;

	memcpy(cmd_data->command_body, btm_req_raw,param_len);

	driver_wext_set_oid(ifname, OID_802_11_WNM_COMMAND, (char *)cmd_data, len);
	free(cmd_data);
	return 0;
}

int wapp_send_btm_req_11kv_api(struct wifi_app *wapp,
						 const char *ifname,
						 const unsigned char *peer_mac_addr,
						 const char *btm_req,
						 size_t btm_req_len)
{
	p_btm_req_ie_data_t p_btm_req_data = NULL;
	unsigned int len = 0;

	if(DEBUG || nvram_get_int("btm_test") == 1)
		_dprintf("%s  peer_mac_addr %02X:%02X:%02X:%02X:%02X:%02X\n", __func__, PRINT_MAC(peer_mac_addr));

	len = btm_req_len + sizeof(*p_btm_req_data);
	p_btm_req_data = (p_btm_req_ie_data_t) malloc(len);
	memset(p_btm_req_data, 0, len);
	if(!p_btm_req_data) {
		_dprintf("btm_req mem alloc fail\n");
		return WAPP_NOT_INITIALIZED;
	}

	memcpy(p_btm_req_data->peer_mac_addr, peer_mac_addr, MAC_ADDR_LEN);
	memcpy(p_btm_req_data->btm_req, btm_req, btm_req_len);
	p_btm_req_data->btm_req_len = btm_req_len;
	p_btm_req_data->dialog_token = 1;

	driver_wnm_send_btm_req_raw(ifname, (char *)p_btm_req_data, len);

	free(p_btm_req_data);
	return WAPP_SUCCESS;
}

int amas_11v(int band, int vidx, char *sta, char *bssid)
{
	struct wifi_app wapp_cfg;
	struct wifi_app *wapp = &wapp_cfg;
	int channel = 0, bw = 0, nctrlsb = 0;
	const char *aif = get_wifname(band);
	wapp_nr_info* nr_entry = NULL;
	int i, ret = 0;
	unsigned char mac_addr[MAC_ADDR_LEN] = {0}, sta_mac[MAC_ADDR_LEN] = {0};
	char buf[1024] = {0};
	char cand_list[1024] = {0};
	size_t btm_req_len = 0, cand_list_len = 0;
	u16 disassoc_timer = 0;
	u8 req_mode = 0, disassoc_imnt = 0, ess_disassoc_imnt = 0, abridged = 0, validity_intvl = 0;
	u8 has_trans_reason = TRUE, has_reassoc_delay = FALSE;

	ether_atoe(bssid, mac_addr);
	ether_atoe(sta, sta_mac);

	memset(wapp, 0, sizeof(struct wifi_app));
	get_channel_info(aif, &channel, &bw, &nctrlsb);
	memset(&wapp->mbo,0,sizeof(struct mbo_cfg));
	memset(&wapp->daemon_nr_list, 0, sizeof(DAEMON_NR_LIST));
	nr_entry = &wapp->daemon_nr_list.NRInfo[0];

	memcpy(nr_entry->Bssid, mac_addr, MAC_ADDR_LEN);
	nr_entry->CandidatePrefSubID = 0x3;
	nr_entry->CandidatePrefSubLen = 1;
	nr_entry->RegulatoryClass = get_regular_class(aif);
	nr_entry->ChNum = channel;
	nr_entry->CandidatePref = 255;
	wapp->daemon_nr_list.CurrListNum = 1;

	for(i=0;i<wapp->daemon_nr_list.CurrListNum;i++)
	{
		if(DEBUG || nvram_get_int("btm_test") == 1)
			_dprintf("No.%d %02X:%02X:%02X:%02X:%02X:%02X  Pref %d BssidInfo 0x%X  ChNum %d OpClass %d PhyType %d\n"
			,i,PRINT_MAC(wapp->daemon_nr_list.NRInfo[i].Bssid)
			,wapp->daemon_nr_list.NRInfo[i].CandidatePref
			,wapp->daemon_nr_list.NRInfo[i].BssidInfo
			,wapp->daemon_nr_list.NRInfo[i].ChNum
			,wapp->daemon_nr_list.NRInfo[i].RegulatoryClass
			,wapp->daemon_nr_list.NRInfo[i].PhyType);
	}

	req_mode = 	(abridged << ABIDGED_BIT_MAP) |
				(disassoc_imnt << DISASSOC_IMNT_BIT_MAP) |
				(ess_disassoc_imnt << ESS_DISASSOC_IMNT_BIT_MAP);
	mbo_check_sta_preference_and_append_nr_list( wapp,
												cand_list,
												(u16 *) &cand_list_len,
#if 0
												MBO_FRAME_BTM,
#endif
												disassoc_imnt
#if 0
												,(p_bss_term_dur ? TRUE:FALSE),
												is_steer_to_cell
#endif
												);
	hex_dump_dbg("1037====",(u8 *)buf , btm_req_len);
	/* build btm content */
	btm_req_len = wapp_build_btm_req(
					req_mode,
					disassoc_timer,
					validity_intvl,
#if 0
					NULL,
					NULL,
					0,
#endif
					(cand_list_len) ? cand_list : NULL,
					cand_list_len,
					buf);
	hex_dump_dbg("1049====",(u8 *)buf , btm_req_len);
	/* append MBO IE */
	{
		u16 ie_len = 0;
		char *pos = buf + btm_req_len;
		struct mbo_cfg *mbo __attribute__((unused)) = wapp->mbo;
		mbo_make_mbo_ie_for_btm(
					wapp,
					pos,
					&ie_len,
					0, //(sta->cell_data_cap) ? TRUE : FALSE,
					has_trans_reason,
					0, //(sta->trans_reason) ? sta->trans_reason : mbo->dft_trans_reason,
					has_reassoc_delay);
		btm_req_len += ie_len;
	}
	hex_dump_dbg("1068====",(u8  *)buf , btm_req_len);

	ret = wapp_send_btm_req_11kv_api(wapp, aif, sta_mac, buf, btm_req_len);
	return ret;
}
#endif /* RTCONFIG_BTM_11V */

#ifdef RTCONFIG_NEW_USER_LOW_RSSI
int get_monitor_rssi(int band)
{
	char *sp = NULL, *op = NULL;
	char wlif_name[32] = {0}, header[128] = {0}, data[2048] = {0};
	int hdrLen = 0, staCount = 0, getLen = 0;
	struct iwreq wrq;
	grssi_sta *ssap = NULL;
	char prefix[] = "wlXXXXXXXXXX_";
	char header_t[128] = {0};
	int stream = 0;
	char tmp[128] = {0};
	char rssinum[16] = {0};
	int i = 0;
	int sta_rssi = -100;
	char tr_mac[32] ={0};
	int xTxR;

	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	if (!(xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp))))
		return 0;

	if(xTxR > xR_MAX)
		xTxR = xR_MAX;

	// enable sta_monitor feature
	memset(data, 0x00, sizeof(data));
	strcpy(data, "mnt_en=1");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0) {
		_dprintf("Setting mnt_en=1 fail.\n");
		goto done;
	}
	// set sta monitor rule
	memset(data, 0x00, sizeof(data));
	strcpy(data, "mnt_rule=1:1:1");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0) {
		_dprintf("Setting mnt_rule=1:1:1 fail.\n");
		goto done;
	}
	// add sta into sta_monitor list
	// sprintf(tr_mac, ""MACF"", ETHERP_TO_MACF(addr));
	sprintf(tr_mac, "D8:1C:79:E2:2C:27");
	memset(data, 0x00, sizeof(data));
	snprintf(data, sizeof(data), "mnt_sta0=%s", tr_mac);
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0) {
		_dprintf("Setting mnt_sta0=%s fail.\n", tr_mac);
		goto done;
	}

	for (i = 0; i<3; i++) {
#if !defined(RTCONFIG_MT798X)
		if (band == 0)
			snprintf(wlif_name, sizeof(wlif_name), "ra%d", i);
		else
			snprintf(wlif_name, sizeof(wlif_name), "rai%d", i);
#else
		if (band == 0)
			snprintf(wlif_name, sizeof(wlif_name), "ra%d", i);
		else
			snprintf(wlif_name, sizeof(wlif_name), "rax%d", i);
#endif

		memset(data, 0x00, sizeof(data));
		wrq.u.data.length = sizeof(data);
		wrq.u.data.pointer = (caddr_t) data;
		wrq.u.data.flags = ASUS_SUBCMD_GMONITOR_RSSI;

		usleep(500000);
		if (wl_ioctl(wlif_name, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
			_dprintf("[%s]: (%d,%d) WI[%s] ASUS_SUBCMD_GMONITOR_RSSI failure\n", __FUNCTION__, band, i, wlif_name);
			goto done;
		}

		memset(header, 0, sizeof(header));
		memset(header_t, 0, sizeof(header_t));
		hdrLen = sprintf(header_t, "%-19s", "MAC");
		strcpy(header, header_t);

		for (stream = 0; stream < xR_MAX; stream++) {
			sprintf(rssinum, "RSSI%d", stream);
			memset(header_t, 0, sizeof(header_t));
			hdrLen += sprintf(header_t, "%-7s", rssinum);
			strncat(header, header_t, strlen(header_t));
		}
		hdrLen += sprintf(header_t, "%-21s", "Count");
		strncat(header, header_t, strlen(header_t));
		strcat(header,"\n");
		hdrLen++;

		if (wrq.u.data.length > 0 && data[0] != 0) {

			getLen = strlen(wrq.u.data.pointer + hdrLen);

			ssap = (grssi_sta *)(wrq.u.data.pointer + hdrLen);
			op = sp = wrq.u.data.pointer + hdrLen;
//_dprintf("wlif_name(%s) data(%s) header(%s) hdrLen(%d)\n", wlif_name, (char *)data, header, hdrLen);
			while (*sp && ((getLen - (sp-op)) >= 0)) {
				ssap->sta[staCount].mac[18]='\0';
				for (stream = 0; stream < xR_MAX; stream++) {
					ssap->sta[staCount].rssi_xR[stream][6]='\0';
				}
				ssap->sta[staCount].Count[20]='\0';
//_dprintf("%d: mac(%s) rssi_xR0(%s) rssi_xR1(%s) rssi_xR2(%s) Count(%s)\n", staCount, ssap->sta[staCount].mac, ssap->sta[staCount].rssi_xR[0], ssap->sta[staCount].rssi_xR[1], ssap->sta[staCount].rssi_xR[2], ssap->sta[staCount].Count);
				sp += hdrLen;
				staCount++;
			}

			if( !staCount ) goto done;
		} //if (wrq.u.data.length >
	} //for (i = 0; i<3; i++) {

done:

	// Clear data.
	memset(data, 0x00, sizeof(data));
	strcpy(data, "mnt_clr=1");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0) {
		_dprintf("Setting mnt_clr=1 fail.\n");
	}

	// Remove STA from monitor list.
	memset(data, 0x00, sizeof(data));
	strcpy(data, "mnt_sta0=00:00:00:00:00:00");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0) {
		_dprintf("Setting mnt_sta0=00:00:00:00:00:00 fail.\n");
	}

	// Disable monitor function.
	memset(data, 0x00, sizeof(data));
	strcpy(data, "mnt_en=0");
	wrq.u.data.length = strlen(data)+1;
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_SET, &wrq) < 0) {
		_dprintf("Setting mnt_en=0 fail.\n");
	}

	_dprintf("#### return sta_rssi= %d  ######\n",sta_rssi);
	return sta_rssi;
}

#define WLC_MACMODE_DISABLED    0       /* MAC list disabled */
#define WLC_MACMODE_ALLOW       1      /* Allow specified (i.e. deny unspecified) */
#define WLC_MACMODE_DENY        2      /* Deny specified (i.e. allow unspecified) */
struct maclist {
        uint count;                     /* number of MAC addresses */
        struct ether_addr ea[1];        /* variable length array of MAC addresses */
};

int get_maclist(int bssidx)
{
	struct iwreq wrq;
	char data[2048] = {0}, header[128] = {0};
	unsigned long macmode = 0;

	wrq.u.data.length = sizeof(macmode);
	wrq.u.data.pointer = (caddr_t)&macmode;
	wrq.u.data.flags = ASUS_SUBCMD_MACMODE;

	if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		_dprintf("[WARNING] %s get macmode error!!!\n", get_wifname(bssidx));
		return 0;
	}

	_dprintf("[%s] macmode = %s\n",
		__FUNCTION__,
		macmode==WLC_MACMODE_DISABLED ? "DISABLE" :
		macmode==WLC_MACMODE_DENY ? "DENY" : "ALLOW");

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t)data;
	wrq.u.data.flags = ASUS_SUBCMD_MACLIST;

	if (wl_ioctl(get_wifname(bssidx), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0) {
		_dprintf("[%s]: WI[%s] Get ACL List failure\n", __FUNCTION__, get_wifname(bssidx));
		return 0;
	}
	_dprintf("wrq.u.data.pointer = (%s), len = %d\n", wrq.u.data.pointer, strlen(wrq.u.data.pointer));

	char *sp = NULL, *op = NULL;
	int staCount = 0, getLen = 0, hdrLen = 0;
	acl_sta *ssap = NULL;
	struct ether_addr *ea = NULL;
	char maclist_buf[4096]={0};
	struct maclist *maclist = (struct maclist *) maclist_buf;

	memset(maclist, 0x0,sizeof(struct maclist));

	memset(header, 0x0, sizeof(header));
	hdrLen = sprintf(header, "%-19s","MAC");

	if (wrq.u.data.length > 0 && data[0] != 0) {

		getLen = strlen(wrq.u.data.pointer + hdrLen);
		_dprintf("getLen len = (%d)\n", getLen);
		_dprintf("wrq.u.data.pointer+hdrLen = (%s)\n", wrq.u.data.pointer + hdrLen);

		ssap = (acl_sta *)(wrq.u.data.pointer + hdrLen);
		op = sp = wrq.u.data.pointer + hdrLen;

		while (*sp && ((getLen - (sp-op)) >= 0)) {
			ssap->list[staCount].mac[18]='\0';
			_dprintf("ssap->list[%d].mac= (%s)\n", staCount, ssap->list[staCount].mac);
			ea = &(maclist->ea[staCount]);
			rast_ether_atoe(ssap->list[staCount].mac, ea);
			_dprintf("[%s] (%d)mac:"MACF"\n",__FUNCTION__, staCount, ETHER_TO_MACF(maclist->ea[staCount]));
			sp += hdrLen;
			staCount++;
			ea++;
		}

		maclist->count = staCount;
	}

	return 1;
}
#endif

int
getstat(int band)
{
	char data[4096];
	struct iwreq wrq;

	memset(data, 0x00, 4096);
	wrq.u.data.length = 4096;
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GSTAT;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting STAT result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		puts(wrq.u.data.pointer);
	}

	return 0;
}

int get_apcli_connect_status(int wlc_band)
{
	int status;

	status = Pty_get_wlc_status(get_staifname(wlc_band));

	if (status == 2)
		puts("connected");
	else if (status == 1)
		puts("connecting");
	else
		puts("initializing");
	return status;
}

#ifdef RTCONFIG_BCN_RPT
int send_beacon_request(int bssidx, int vifidx)
{
	struct ether_addr ea_tmp;

	rast_send_beacon_request(bssidx, vifidx, rast_ether_atoe(nvram_safe_get("bcnreq_mac"),&ea_tmp));
	return 0;
}
#endif
#endif

void
wsc_user_commit(void)
{
	int i, flag_wep;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char auth_mode[16], wep[16];
	const char *wif;

	for (i = 0; i < MAX_NR_WL_IF; ++i) {
		SKIP_ABSENT_BAND(i);

		sprintf(prefix, "wl%d_", i);
		if (!nvram_match(strcat_r(prefix, "wsc_config_state", tmp), "2"))
			continue;

		flag_wep = 0;
		wif = get_wifname(i);
		strcpy(auth_mode, nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)));
		strcpy(wep, nvram_safe_get(strcat_r(prefix, "wep_x", tmp)));

		if (!strcmp(auth_mode, "open") && !strcmp(wep, "0")) {
			doSystem("iwpriv %s set AuthMode=%s", wif, "OPEN");
			doSystem("iwpriv %s set EncrypType=%s", wif, "NONE");

			doSystem("iwpriv %s set IEEE8021X=%d", wif, 0);
		}
		else if (!strcmp(auth_mode, "open")) {
			flag_wep = 1;
			doSystem("iwpriv %s set AuthMode=%s", wif, "OPEN");
			doSystem("iwpriv %s set EncrypType=%s", wif, "WEP");

			doSystem("iwpriv %s set IEEE8021X=%d", wif, 0);
		}
		else if (!strcmp(auth_mode, "shared")) {
			flag_wep = 1;
			doSystem("iwpriv %s set AuthMode=%s", wif, "SHARED");
			doSystem("iwpriv %s set EncrypType=%s", wif, "WEP");

			doSystem("iwpriv %s set IEEE8021X=%d", wif, 0);
		}
		else if (!strcmp(auth_mode, "psk") || !strcmp(auth_mode, "psk2") || !strcmp(auth_mode, "pskpsk2")) {
			if (!strcmp(auth_mode, "pskpsk2"))
				doSystem("iwpriv %s set AuthMode=%s", wif, "WPAPSKWPA2PSK");
			else if (!strcmp(auth_mode, "psk"))
				doSystem("iwpriv %s set AuthMode=%s", wif, "WPAPSK");
			else if (!strcmp(auth_mode, "psk2"))
				doSystem("iwpriv %s set AuthMode=%s", wif, "WPA2PSK");

			//EncrypType
			if (nvram_match(strcat_r(prefix, "crypto", tmp), "tkip"))
				doSystem("iwpriv %s set EncrypType=%s", wif, "TKIP");
			else if (nvram_match(strcat_r(prefix, "crypto", tmp), "aes"))
				doSystem("iwpriv %s set EncrypType=%s", wif, "AES");
			else if (nvram_match(strcat_r(prefix, "crypto", tmp), "tkip+aes"))
				doSystem("iwpriv %s set EncrypType=%s", wif, "TKIPAES");

			doSystem("iwpriv %s set IEEE8021X=%d", wif, 0);

			iwprivSet(wif, "SSID", nvram_safe_get(strcat_r(prefix, "ssid", tmp)));

			//WPAPSK
			iwprivSet(wif, "WPAPSK", nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)));

			doSystem("iwpriv %s set DefaultKeyID=%s", wif, "2");
		}
		else {
			doSystem("iwpriv %s set AuthMode=%s", wif, "OPEN");
			doSystem("iwpriv %s set EncrypType=%s", wif, "NONE");
		}

		if (flag_wep) {
			//KeyStr
			if (strlen(nvram_safe_get(strcat_r(prefix, "key1", tmp))))
				iwprivSet(wif, "Key1", nvram_safe_get(strcat_r(prefix, "key1", tmp)));
			if (strlen(nvram_safe_get(strcat_r(prefix, "key2", tmp))))
				iwprivSet(wif, "Key2", nvram_safe_get(strcat_r(prefix, "key2", tmp)));
			if (strlen(nvram_safe_get(strcat_r(prefix, "key3", tmp))))
				iwprivSet(wif, "Key3", nvram_safe_get(strcat_r(prefix, "key3", tmp)));
			if (strlen(nvram_safe_get(strcat_r(prefix, "key4", tmp))))
				iwprivSet(wif, "Key4", nvram_safe_get(strcat_r(prefix, "key4", tmp)));

			//DefaultKeyID
			doSystem("iwpriv %s set DefaultKeyID=%s", wif, nvram_safe_get(strcat_r(prefix, "key", tmp)));
		}

		iwprivSet(wif, "SSID", nvram_safe_get(strcat_r(prefix, "ssid", tmp)));

		nvram_set(strcat_r(prefix, "wsc_config_state", tmp), "1");
		doSystem("iwpriv %s set WscConfStatus=%d", wif, 2);	// AP is configured
	}

//	doSystem("iwpriv %s set WscConfMode=%d", get_non_wpsifname(), 7);	// trigger Windows OS to give a popup about WPS PBC AP
}

int
wl_WscConfigured(int unit)
{
	WSC_CONFIGURED_VALUE result;
	struct iwreq wrq;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	wrq.u.data.length = sizeof(WSC_CONFIGURED_VALUE);
	wrq.u.data.pointer = (caddr_t) &result;
	wrq.u.data.flags = 0;
	strcpy((char *)&result, "get_wsc_profile");

	if (wl_ioctl(nvram_safe_get(strcat_r(prefix, "ifname", tmp)), RTPRIV_IOCTL_WSC_PROFILE, &wrq) < 0)
	{
		fprintf(stderr, "errors in getting WSC profile\n");
		return -1;
	}

	if (result.WscConfigured == 2)
		return 1;
	else
		return 0;
}

void gen_ra_config(const char* wif)
{
	char word[256], *next;
	const char *iNIC_name = 
#if !defined(RTCONFIG_MT798X)
		"rai"
#else
		"rax"
#endif
		;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_FAKE_IFACE(word);
		if (!strcmp(word, wif))
		{
			if (!strcmp(word, nvram_safe_get("wl0_ifname"))) // 2.4G
			{
				if (!strncmp(word, iNIC_name, 3))	// iNIC
					gen_ralink_config(0, 1);
				else{
					gen_ralink_config(0, 0);
#if defined(RTCONFIG_WLMODULE_MT7629_AP) || defined(RTCONFIG_WLMODULE_MT7915D_AP) || defined(RTCONFIG_MT798X)	/* gen both 2G and 5G profile before ra0 up */
					gen_ralink_config(1, 1);
					break;
#endif
				}
			}
			else if (!strcmp(word, nvram_safe_get("wl1_ifname"))) // 5G
			{
				if (!strncmp(word, iNIC_name, 3))	// iNIC
					gen_ralink_config(1, 1);
				else
					gen_ralink_config(1, 0);
			}
		}
	}

#if defined(RTCONFIG_WIRELESSREPEATER)
	if (repeater_mode() || mediabridge_mode())
		update_wifi_led_state_in_wlcmode();
#endif
}

int radio_ra(const char *wif, int band, int ctrl)
{
	char tmp[100], prefix[]="wlXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", band);

	if (wif == NULL) return -1;

	if (!ctrl)
	{
		ifconfig(wif, 0, NULL, NULL);	// MTK suggested use ifconfig down/up to instead RadioOn=0/1
		//doSystem("iwpriv %s set RadioOn=0", wif);
	}
	else
	{
		if (nvram_match(strcat_r(prefix, "radio", tmp), "1"))
			ifconfig(wif, 1, NULL, NULL);
			//doSystem("iwpriv %s set RadioOn=1", wif);
	}

	return 0;
}

void set_wlpara_ra(const char* wif, int band)
{
	char tmp[100], prefix[]="wlXXXXXXX_";

	snprintf(prefix, sizeof(prefix), "wl%d_", band);

	if (nvram_match(strcat_r(prefix, "radio", tmp), "0"))
		radio_ra(wif, band, 0);
	else
	{
		int txpower = nvram_get_int(strcat_r(prefix, "txpower", tmp));
		if ((txpower >= 0) && (txpower <= 100))
			doSystem("iwpriv %s set TxPower=%d",wif, txpower);
	}
#if defined(DSL_N55U) || defined(DSL_N55U_B)
	if(band == 0)
		eval("iwpriv", (char *)wif, "bbp", "1=51");
#endif
#if 0
	if (nvram_match(strcat_r(prefix, "bw", tmp), "2"))
	{
		int channel = ra_get_channel(band);

		if (channel)
			eval("iwpriv", (char *)wif, "set", "HtBw=1");
	}
#endif
#if 0 //defined (RTCONFIG_WLMODULE_RT3352_INIC_MII)	/* set RT3352 iNIC in kernel driver to avoid loss setting after reset */
	if(strcmp(wif, "rai0") == 0)
	{
		int i;
		char buf[32];
		eval("iwpriv", (char *)wif, "set", "asiccheck=1");
		for(i = 0; i < 3; i++)
		{
			sprintf(buf, "setVlanId=%d,%d", i + INIC_VLAN_IDX_START, i + INIC_VLAN_ID_START);
			eval("iwpriv", (char *)wif, "switch", buf);	//set vlan id can pass through the switch insided the RT3352.
								//set this before wl connection linu up. Or the traffic would be blocked by siwtch and need to reconnect.
		}
		for(i = 0; i < 5; i++)
		{
			sprintf(buf, "setPortPowerDown=%d,%d", i, 1);
			eval("iwpriv", (char *)wif, "switch", buf);	//power down the Ethernet PHY of RT3352 internal switch.
		}
	}
#endif // RTCONFIG_WLMODULE_RT3352_INIC_MII
#if defined(RTN14U)
#ifdef CE_ADAPTIVITY
	/* CE adaptivity 1.9.1 for RT-N14U */
	if (nvram_match("reg_spec", "CE") && (band == 0))
	{
		if ((nvram_get_int("wl0_nmode_x") != 2) && (nvram_get_int("wl0_bw") == 0)) /* N mode 20MHz */
			eval("iwpriv", (char *)wif, "mac", "1030=66655443");
		else
			eval("iwpriv", (char *)wif, "mac", "1030=77766554");
	}
#endif
#endif

#if defined(RTAC1200V2)
	if (band)
	{
		if (nvram_match(strcat_r(prefix, "radio", tmp), "1"))
		{
			// LED ON led_setting=01-00-00-00-02-00-00-02
			eval("iwpriv", (char*)wif, "set", "led_setting=01-00-00-00-02-00-00-02");
		}
#if 0
		if (nvram_match(strcat_r(prefix, "radio", tmp), "1"))
		{
			   // 5G LED ON
			   eval("iwpriv", (char*)wif, "set", "led_setting=01-00-00-00-00-00-00-00");
		}
		else
		{
			   // 5G LED OFF
			   eval("iwpriv", (char*)wif, "set", "led_setting=01-00-00-00-00-00-00-01");
		}
#endif
	}
#elif defined(RTACRH18)
	if (band)
	{
		if (nvram_match("wl0_radio", "0"))
			eval("iwpriv", (char*)wif, "set", "led_setting=00-00-00-00-02-00-00-01");	// 2G LED OFF

		if (nvram_match(strcat_r(prefix, "radio", tmp), "0"))
			eval("iwpriv", (char*)wif, "set", "led_setting=01-00-00-00-02-00-00-01");	 // 5G LED OFF

	}
	else
	{
		if (nvram_match(strcat_r(prefix, "radio", tmp), "0"))
			eval("iwpriv", (char*)wif, "set", "led_setting=00-00-00-00-02-00-00-01");	 // 2G LED OFF
	}
#elif defined(RTAX53U) || defined(RTAX54)
	if (band)
	{
		if (nvram_match(strcat_r(prefix, "radio", tmp), "1") && nvram_match("AllLED", "1"))
			eval("iwpriv", (char*)wif, "set", "led_setting=01-00-01-01-02-00-00-02");	// 5G LED ON
		else
			eval("iwpriv", (char*)wif, "set", "led_setting=01-00-01-01-02-00-00-00");	// 5G LED OFF
	}
	else
	{
		if (nvram_match(strcat_r(prefix, "radio", tmp), "1") && nvram_match("AllLED", "1"))
			eval("iwpriv", (char*)wif, "set", "led_setting=00-00-01-00-02-00-00-02");	// 2G LED ON
		else
			eval("iwpriv", (char*)wif, "set", "led_setting=00-00-01-00-02-00-00-00");	// 2G LED OFF
	}
#elif defined(XD4S)
//TBD
	_dprintf("#### LED is TBD ####\n");
#endif /* RTAC1200V2 */

	eval("iwpriv", (char *)wif, "set", "IgmpAdd=01:00:5e:7f:ff:fa");
	eval("iwpriv", (char *)wif, "set", "IgmpAdd=01:00:5e:00:00:09");
	eval("iwpriv", (char *)wif, "set", "IgmpAdd=01:00:5e:00:00:fb");
}

void set_wlpara_ra_down(const char* wif, int band)
{
#if defined(RTAC1200V2)
	if (band)
	{
		// 5G LED OFF
		eval("iwpriv", (char*)wif, "set", "led_setting=01-00-00-00-00-00-00-01");
	}
#endif	/* RTAC1200V2 */
	return;
}

int wlconf_ra_down(const char* wif)
{
	int unit = 0;
	char word[256], *next;
	char prefix[] = "wlXXXXXXXXXX_";

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

		if (!strcmp(word, wif))
		{
			if (!strcmp(word, WIF_2G))
				set_wlpara_ra_down(wif, 0);
#if defined(RTCONFIG_HAS_5G)
			else
				set_wlpara_ra_down(wif, 1);
#endif	/* RTCONFIG_HAS_5G */
		}
	}


	return 0;
}

int wlconf_ra(const char* wif)
{
	int unit = 0;
	char word[256], *next;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *p;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

		if (!strcmp(word, wif))
		{
			p = get_hwaddr(wif);
			if (p)
			{
				nvram_set(strcat_r(prefix, "hwaddr", tmp), p);
				free(p);
			}
			if (!strcmp(word, WIF_2G))
				set_wlpara_ra(wif, 0);
#if defined(RTCONFIG_HAS_5G)
			else if (!strcmp(word, WIF_5G))
				set_wlpara_ra(wif, 1);
#endif	/* RTCONFIG_HAS_5G */
		}

		unit++;
	}
	return 0;
}

#if defined(RTCONFIG_RALINK) && defined(RTCONFIG_WIRELESSREPEATER) || defined(RTCONFIG_AMAS)
#if defined(RTCONFIG_CONCURRENTREPEATER) || defined(RTCONFIG_AMAS)
void enable_apcli(char *aif, int wlc_band)
{
	int ch;
	int ht_ext;

	ch = site_survey_for_channel(0,aif, &ht_ext);
	if(ch!=-1)
	{
		if (wlc_band == 1)
		{
			doSystem("iwpriv %s set Channel=%d", APCLI_5G, ch);
			doSystem("iwpriv %s set ApCliEnable=1", APCLI_5G);
		}
		else
		{
			doSystem("iwpriv %s set Channel=%d", APCLI_2G, ch);
			doSystem("iwpriv %s set ApCliEnable=1", APCLI_2G);
		}
		fprintf(stderr,"##set channel=%d, enable apcli ..#\n",ch);
	}
	else
		fprintf(stderr,"## Can not find pap's ssid for %s ##\n", aif);
}
#endif

void apcli_start(void)
{
//repeater mode :sitesurvey channel and apclienable=1
	int ch;
	const char *aif;
	int ht_ext;
#ifdef RTCONFIG_PRELINK
	struct iwreq wrq;
	char data[8192];
	char tmp[128], prefix[] = "wlXXXXXXX_";
	int IEEE80211H = 0;
#endif
#if defined(RTCONFIG_WLMODULE_MT7629_AP)
	char ap_set_buf[128] = {0};
#endif

#if defined(RTCONFIG_AMAS)
	if (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1") && strcmp(nvram_safe_get("cfg_group"), "") == 0)
	{
		int wlc_band = nvram_get_int("wlc_band");
#if !defined(RALINK_DBDC_MODE)
		if (wlc_band == 0)
			aif=nvram_safe_get("wl0_ifname");
		else
			aif=nvram_safe_get("wl1_ifname");
#else	// !defined(RALINK_DBDC_MODE)
		if (wlc_band == 0)
		{
			aif = APCLI_2G;
		}
		else
		{
			aif = APCLI_5G;
			wlc_band = 1;
		}
#endif	// !defined(RALINK_DBDC_MODE)

#ifdef RTCONFIG_PRELINK
		snprintf(prefix, sizeof(prefix), "wl%d_", wlc_band);
		if(nvram_match(strcat_r(prefix, "IEEE80211H", tmp), "1"))
			IEEE80211H = 1;

		if(nvram_match("prelink", "1") && IEEE80211H)
		{
			memset(data, 0x00, 255);
			snprintf(data, sizeof(data), "ByPassCAC=1");
			wrq.u.data.length = strlen(data)+1;
			wrq.u.data.pointer = data;
			wrq.u.data.flags = 0;

			if (wl_ioctl(aif, RTPRIV_IOCTL_SET, &wrq) < 0) {
				_dprintf("set ByPassCAC fails\n");
			}

			for(int i=0; i<10; i++)
			{
				if(amas_dfs_status(wlc_band))
					sleep(1);
				else
					break;
			}

			memset(data, 0x00, 255);
			snprintf(data, sizeof(data), "IEEE80211H=0");
			wrq.u.data.length = strlen(data)+1;
			wrq.u.data.pointer = data;
			wrq.u.data.flags = 0;

			if (wl_ioctl(aif, RTPRIV_IOCTL_SET, &wrq) < 0) {
				_dprintf("set IEEE80211H to 0 fails\n");
			}
		}
#endif

#if 0
		ch = site_survey_for_channel(wlc_band,aif, &ht_ext);

		if(ch!=-1)
		{
			if (wlc_band == 1)
			{
				doSystem("iwpriv %s set Channel=%d", APCLI_5G, ch);
				doSystem("iwpriv %s set ApCliEnable=1", APCLI_5G);
			}
			else
			{
				doSystem("iwpriv %s set Channel=%d", APCLI_2G, ch);
				doSystem("iwpriv %s set ApCliEnable=1", APCLI_2G);

			}
			fprintf(stderr,"##set channel=%d, enable apcli ..#\n",ch);
		}
		else
			fprintf(stderr,"## Can not find pap's ssid ##\n");
#endif
		doSystem("iwpriv %s set ApCliEnable=1", aif);
		doSystem("iwpriv %s set ApCliAutoConnect=3", aif);

#if 0
		if(nvram_match("prelink", "1") && IEEE80211H)
		{
			memset(data, 0x00, 255);
			snprintf(data, sizeof(data), "IEEE80211H=1");
			wrq.u.data.length = strlen(data)+1;
			wrq.u.data.pointer = data;
			wrq.u.data.flags = 0;

			if (wl_ioctl(aif, RTPRIV_IOCTL_SET, &wrq) < 0) {
				_dprintf("set IEEE80211H to 1 fails\n");
			}
		}
#endif
	}
	else
#endif /* RTCONFIG_AMAS */
	if (sw_mode() == SW_MODE_REPEATER)
	{
#if defined(RTCONFIG_CONCURRENTREPEATER)
		int wlc_express = nvram_get_int("wlc_express");
		if (wlc_express == 0) {		// concurrent
			aif=nvram_safe_get("wl0_ifname");
			enable_apcli(aif, 0);
			aif=nvram_safe_get("wl1_ifname");
			enable_apcli(aif, 1);
		}
		else if (wlc_express == 1) {	// 2.4G express way
			aif=nvram_safe_get("wl0_ifname");
			enable_apcli(aif, 0);
		}
		else if (wlc_express == 2) {	// 5G express way
			aif=nvram_safe_get("wl1_ifname");
			enable_apcli(aif, 1);
		}
		else
			fprintf(stderr,"## No correct wlc_express for apcli ##\n");
#else /* RTCONFIG_CONCURRENTREPEATER */
		int wlc_band = nvram_get_int("wlc_band");
#if !defined(RALINK_DBDC_MODE)
		if (wlc_band == 0)
			aif=nvram_safe_get("wl0_ifname");
		else
			aif=nvram_safe_get("wl1_ifname");
#else	// !defined(RALINK_DBDC_MODE)
		if (wlc_band == 0)
			aif = APCLI_2G;
		else
			aif = APCLI_5G;
#endif	// !defined(RALINK_DBDC_MODE)

#ifdef RTCONFIG_PROXYSTA
#if !defined(RALINK_DBDC_MODE)
	if (mediabridge_mode())
		ifconfig(aif, IFUP, NULL, NULL);
#endif
#endif

		ch = site_survey_for_channel(wlc_band,aif, &ht_ext);

#ifdef RTCONFIG_PROXYSTA
#if !defined(RALINK_DBDC_MODE)
	if (mediabridge_mode())
		ifconfig(aif, 0, NULL, NULL);
#endif
#endif

		if(ch!=-1)
		{
			if (wlc_band == 1)
			{
				doSystem("iwpriv %s set Channel=%d", APCLI_5G, ch);
				doSystem("iwpriv %s set ApCliEnable=1", APCLI_5G);
#if defined(RTCONFIG_WLMODULE_MT7629_AP)
				snprintf(ap_set_buf, sizeof(ap_set_buf), "ApCliSsid=%s", nvram_safe_get("wlc_ssid"));
				ap_set(APCLI_5G, ap_set_buf);
#endif
			}
			else
			{
				doSystem("iwpriv %s set Channel=%d", APCLI_2G, ch);
				doSystem("iwpriv %s set ApCliEnable=1", APCLI_2G);

			}
			fprintf(stderr,"##set channel=%d, enable apcli ..#\n",ch);
		}
		else
			fprintf(stderr,"## Can not find pap's ssid ##\n");
#endif /* RTCONFIG_CONCURRENTREPEATER */
	}
}
#endif	/* RTCONFIG_RALINK && RTCONFIG_WIRELESSREPEATER */

#ifdef RTCONFIG_RALINK
void stop_wds_ra(const char* lan_ifname, const char* wif)
{
	char prefix[32];
	char wdsif[32];
	int i;

	if (strcmp(wif, WIF_2G) && strcmp(wif, WIF_5G))
		return;

#if !defined(RTCONFIG_MT798X)
	if (!strncmp(wif, "rai", 3))
		snprintf(prefix, sizeof(prefix), "wdsi");
	else
		snprintf(prefix, sizeof(prefix), "wds");
#else
	if (!strncmp(wif, "rax", 3))
		snprintf(prefix, sizeof(prefix), "wdsx");
	else
		snprintf(prefix, sizeof(prefix), "wds");
#endif

	for (i = 0; i < 4; i++)
	{
		sprintf(wdsif, "%s%d", prefix, i);
		doSystem("brctl delif %s %s 1>/dev/null 2>&1", lan_ifname, wdsif);
		ifconfig(wdsif, 0, NULL, NULL);
	}
}

#if defined(RTCONFIG_WLMODULE_MT7615E_AP)
void start_wds_ra(void)
{
	char* lan_ifname = nvram_safe_get("lan_ifname");
	char prefix[32];
	char wdsif[32];
	int i, j, ret;

	for(i = 0; i < 2; i++) {
		memset(prefix, 0, sizeof(prefix));
		snprintf(prefix, sizeof(prefix), "wl%d_mode_x", i);
		ret = nvram_get_int(prefix);
		if((ret !=1) && (ret != 2))
			continue;

		memset(prefix, 0, sizeof(prefix));
		if(i == 0)
			snprintf(prefix, sizeof(prefix), "wds");
		else if( i == 1)
			snprintf(prefix, sizeof(prefix), "wdsi");

		for (j = 0; j < 4; j++)
		{
			snprintf(wdsif, sizeof(wdsif), "%s%d", prefix, j);
			ifconfig(wdsif, IFUP, NULL, NULL);
			doSystem("brctl addif %s %s 1>/dev/null 2>&1", lan_ifname, wdsif);
		}
	}
}
#endif
#endif	/* RTCONFIG_RALINK */

void
Get_fail_log(char *buf, int size, unsigned int offset)
{
	struct FAIL_LOG fail_log, *log = &fail_log;
	char *p = buf;
	int x, y;

	memset(buf, 0, size);
	FRead((char*) &fail_log, offset, sizeof(fail_log));
	if(log->num == 0 || log->num > FAIL_LOG_MAX)
	{
		return;
	}
	for(x = 0; x < (FAIL_LOG_MAX >> 3); x++)
	{
		for(y = 0; log->bits[x] != 0 && y < 7; y++)
		{
			if(log->bits[x] & (1 << y))
			{
				p += snprintf(p, size - (p - buf), "%d,", (x << 3) + y);
			}
		}
	}
}

void
Gen_fail_log(const char *logStr, int max, struct FAIL_LOG *log)
{
	const char *p = logStr;
	char *next;
	int num;
	int x,y;

	memset(log, 0, sizeof(struct FAIL_LOG));
	if(max > FAIL_LOG_MAX)
		log->num = FAIL_LOG_MAX;
	else
		log->num = max;

	if(logStr == NULL)
		return;

	while(*p != '\0')
	{
		while(*p != '\0' && !isdigit(*p))
			p++;
		if(*p == '\0')
			break;
		num = strtoul(p, &next, 0);
		if(num > FAIL_LOG_MAX)
			break;
		x = num >> 3;
		y = num & 0x7;
		log->bits[x] |= (1 << y);
		p = next;
	}
}
#endif //RTCONFIG_RALINK

int getWscStatusCli(char *aif)
{
	int data = 0;
	struct iwreq wrq;

	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) &data;
	wrq.u.data.flags = RT_OID_WSC_QUERY_STATUS;

	if (wl_ioctl(aif, RT_PRIV_IOCTL, &wrq) < 0)
		dbg("errors in getting WSC status on %s\n", aif);

	return data;
}

#ifdef RTCONFIG_WIRELESSREPEATER
#if defined(RTCONFIG_CONCURRENTREPEATER)
int get_apcli_status(int wlc_band)
#else
int get_apcli_status(void)
#endif
{
#if !defined(RTCONFIG_CONCURRENTREPEATER)
	int wlc_band;
#endif
	const char *ifname;
	char data[32];
	struct iwreq wrq;
	int status;
	static int old_status[2] = {-1, -1};
#if !defined(RTCONFIG_CONCURRENTREPEATER)
	wlc_band = nvram_get_int("wlc_band");
#endif
	ifname = get_staifname(wlc_band);

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_CONN_STATUS;

	if (wl_ioctl(ifname, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting %s CONN_STATUS result\n", ifname);
		return -1;
	}

	status = *(int*)wrq.u.data.pointer;
	if (wlc_band >=0 && wlc_band <= 1 && old_status[wlc_band] != status)
	{
		cprintf("%s: %s connStatus(%d --> %d)\n", __func__, ifname, old_status[wlc_band], status);
		old_status[wlc_band] = status;
	}

	if (status == 6)	// APCLI_CTRL_CONNECTED
		return WLC_STATE_CONNECTED;
	else if (status == 4)	// APCLI_CTRL_ASSOC
		return WLC_STATE_CONNECTING;
	return WLC_STATE_INITIALIZING;
}






char *wlc_nvname(char *keyword)
{
	return(wl_nvname(keyword, nvram_get_int("wlc_band"), -1));
}

#ifdef RTCONFIG_CONCURRENTREPEATER
unsigned int get_conn_link_quality(int unit)
{
	int link_quality = 0;
	const char *aif;
	char data[16];
	struct iwreq wrq;

#if defined(RTCONFIG_RALINK_MT7620) || defined(RTCONFIG_RALINK_MT7621)
	if(unit == 0)
#else
	if(unit == 1)
#endif
		aif = "apcli0";
	else
		aif = "apclii0";

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_CLIQ;

	if (wl_ioctl(aif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting STAINFO result\n");
		return 0;
	}

	link_quality = atoi(data);

	return link_quality;
}

int select_wlc_band()
{
	int wlc_band = -1;
	int wlc0_quality = 0;
	int wlc1_quality = 0;

	if (nvram_get_int("wlc0_state") != WLC_STATE_CONNECTED)
		wlc0_quality = 0;
	else
		wlc0_quality = get_conn_link_quality(0);

	if (nvram_get_int("wlc1_state") != WLC_STATE_CONNECTED)
		wlc1_quality = 0;
	else
		wlc1_quality = get_conn_link_quality(1);

	if (wlc0_quality <= wlc1_quality)
		wlc_band = 1;
	else
		wlc_band = 0;

	return wlc_band;
}
#endif

/*
 * like: iwpriv [wif] set [pv_pair]
 */
int ap_set(char *wif, const char *pv_pair)
{
	struct iwreq wrq;
	char data[256];

	memset(data, 0x0, 256);
	strcpy(data, pv_pair);
	wrq.u.data.pointer = data;
	wrq.u.data.length = strlen(data);
	wrq.u.data.flags = 0;

	fprintf(stderr, "[%s] set %s\n", wif, pv_pair);

	if (wl_ioctl(wif, RTPRIV_IOCTL_SET, &wrq) < 0)
		return 0;
	else
		return 1;
}

// TODO: wlcconnect_main
//	wireless ap monitor to connect to ap
//	when wlc_list, then connect to it according to priority
#define FIND_CHANNEL_INTERVAL	15
#ifdef RTCONFIG_CONCURRENTREPEATER

int getPapState(int band)
{
	int ret;
	int ch;
	const char *aif;
	int ht_ext = -1;
	static long lastUptime[2] = {-FIND_CHANNEL_INTERVAL, -FIND_CHANNEL_INTERVAL};  // doing "site survey" takes time. use this to prolong interval between site survey.
	long Uptime;

	Uptime = uptime();
	if((ret = get_apcli_status(band))==0) //init
	{
		if ((Uptime > lastUptime[band] && Uptime < lastUptime[band] + FIND_CHANNEL_INTERVAL)
		   || (Uptime < lastUptime[band] && Uptime < FIND_CHANNEL_INTERVAL))
			return ret;

#if defined(RTCONFIG_RALINK_MT7620) || defined(RTCONFIG_RALINK_MT7621)
		if(band == 0)
#else
		if(band == 1)
#endif
			aif = "apcli0";
		else
			aif = "apclii0";

		ch = site_survey_for_channel(band, aif, &ht_ext);
		if(ch != -1)
		{
			doSystem("iwpriv %s set Channel=%d", aif, ch);
			doSystem("iwpriv %s set ApCliEnable=1", aif);
			doSystem("ifconfig %s up", aif);
			dbg("set pap's channel=%d, enable apcli ..#\n",ch);
			if(band == 0)
				doSystem("iwpriv %s set ApCliAutoConnect=1", aif);

			lastUptime[band] = Uptime;
		}
		else
			lastUptime[band] = -FIND_CHANNEL_INTERVAL;
	}
	else
		lastUptime[band] = Uptime;

	return ret;
}
#endif

int wlcconnect_core(void)
{
	int ret = 0;
#if defined(RTCONFIG_WLMODULE_MT7629_AP)
	char ap_set_buf[128] = {0};
#endif
#if defined(RTCONFIG_CONCURRENTREPEATER)
	int unit = 0;
	char buf[32] = {0};
	int sw_mode = sw_mode();
	int wlc_express = nvram_get_int("wlc_express");

	if (nvram_get_int("wps_cli_state") == 1 && sw_mode == SW_MODE_REPEATER)
		return 0;

	if (!nvram_get_int("wlready") && !mediabridge_mode())
		return 0;

	if (sw_mode == SW_MODE_REPEATER) {
	 	if (wlc_express == 0) {	/* for apcli0 or apclii0  */
			unit = nvram_get_int("wlc_band");
			if (unit == 0 || unit == 1) {
				ret = getPapState(unit);	/* for apcli0 or apclii0 */
				sprintf(buf, "wlc%d_state", unit);
				nvram_set_int(buf, ret);
#ifdef RTCONFIG_HAS_5G
				/* Update the other band state */
				if (unit) {
					nvram_set_int("wlc0_state", getPapState(0));
				}
				else {
					nvram_set_int("wlc1_state", getPapState(1));
				}
#endif
			}
			else
			{
				ret = getPapState(0);	/* for apcli0 */
				nvram_set_int("wlc0_state", ret);
#ifdef RTCONFIG_HAS_5G
				if (ret != WLC_STATE_CONNECTED) {
					ret = getPapState(1);	/* for apclii0 */
					nvram_set_int("wlc1_state", ret);
				}
				else { // Update sta1 state
					nvram_set_int("wlc1_state", getPapState(1));
				}
#endif
			}
		}
		else if (wlc_express == 1) {
			ret = getPapState(0);	/* for apcli0 */
			nvram_set_int("wlc0_state", ret);
		}
#ifdef RTCONFIG_HAS_5G
		else if (wlc_express == 2) {
			ret = getPapState(1);	/* for apclii0 */
			nvram_set_int("wlc1_state", ret);
		}
#endif

	}
#else // RTCONFIG_CONCURRENTREPEATER
	int ch;
	const char *aif;
	int band;
	int ht_ext = -1;
	static long lastUptime = -FIND_CHANNEL_INTERVAL; // doing "site survey" takes time. use this to prolong interval between site survey.
	long Uptime;

	Uptime = uptime();
	if((ret = get_apcli_status())==0) //init
	{
		if ((Uptime > lastUptime && Uptime < lastUptime + FIND_CHANNEL_INTERVAL)
		   || (Uptime < lastUptime && Uptime < FIND_CHANNEL_INTERVAL))
			return ret;

		band = nvram_get_int("wlc_band");
		aif = get_staifname(band);

		ch = site_survey_for_channel(band, aif, &ht_ext);
		if(ch != -1)
		{
			doSystem("iwpriv %s set Channel=%d", aif, ch);
			doSystem("iwpriv %s set ApCliEnable=1", aif);
#if defined(RTCONFIG_WLMODULE_MT7629_AP)
			snprintf(ap_set_buf, sizeof(ap_set_buf), "ApCliSsid=%s", nvram_safe_get("wlc_ssid"));
			ap_set(aif, ap_set_buf);
#endif
			doSystem("ifconfig %s up", aif);
			dbg("set pap's channel=%d, enable apcli ..#\n",ch);
			lastUptime = Uptime;
		}
		else
			lastUptime = -FIND_CHANNEL_INTERVAL;
	}
	else
		lastUptime = Uptime;
#endif // RTCONFIG_CONCURRENTREPEATER
	//dbg("wlcconnect...check\n");
	return ret;
}

int wlcscan_core(char *ofile, char *wif)
{
	int ret,count;

	count=0;

#ifdef RTCONFIG_PROXYSTA
	if (mediabridge_mode())
		ifconfig(wif, IFUP, NULL, NULL);
#endif
	while((ret=getSiteSurvey(get_wifname_num(wif),ofile)==0)&& count++ < 2)
	{
		 dbg("[rc] set scan results command failed, retry %d\n", count);
		 sleep(1);
	}
#ifdef RTCONFIG_PROXYSTA
	if (mediabridge_mode())
		ifconfig(wif, 0, NULL, NULL);
#endif

	return 0;
}
#endif	/* RTCONFIG_WIRELESSREPEATER */

#ifdef RTCONFIG_USER_LOW_RSSI
void rssi_check_unit(int unit)
{
	int xTxR;
	char header[128]={0};
	char header_t[128]={0};
	char rssinum[16]={0};
	int staCount = 0, rssi_th = 0;
	char data[2048],cmd[128],tmp[128];
	unsigned char pap_bssid[18];
	struct iwreq wrq,wrq2;
	sta_entry *ssap;
	char prefix[] = "wlXXXXXXXXXX_";
	char *wif;
	int hdrLen = 0;
	int stream = 0;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	if (!(rssi_th= nvram_get_int(strcat_r(prefix, "user_rssi", tmp))))
		return;
	//dbg("rssi_th=%d\n",rssi_th);

	if (!(xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp))))
		return;

	if(xTxR > xR_MAX)
		xTxR = xR_MAX;

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GROAM;
	wif = get_wifname(unit);
	if (wl_ioctl(wif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting STAINFO result\n");
		return;
	}
	//dbg("wif(%s) xTxR(%d) GROAM:\n%s", wif, xTxR, data);
#if 0
	memset(header, 0, sizeof(header));
	hdrLen = sprintf(header, "%-19s%-7s%-7s%-7s\n",
			"MAC", "RSSI0", "RSSI1","RSSI2");
#endif
	memset(header, 0, sizeof(header));
	memset(header_t, 0, sizeof(header_t));
	hdrLen = snprintf(header_t, sizeof(header_t), "%-19s", "MAC");
	strcpy(header, header_t);

	for (stream = 0; stream < xR_MAX; stream++) {
		sprintf(rssinum, "RSSI%d", stream);
		hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", rssinum);
		strncat(header, header_t, strlen(header_t));
	}
	hdrLen += snprintf(header_t, sizeof(header_t), "%-21s", "TxBytes");
	strncat(header, header_t, strlen(header_t));
	hdrLen += snprintf(header_t, sizeof(header_t), "%-21s", "RxBytes");
	strncat(header, header_t, strlen(header_t));
	hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "WnmCap");
	strncat(header, header_t, strlen(header_t));
	hdrLen += snprintf(header_t, sizeof(header_t), "%-7s", "BcnCap");
	strncat(header, header_t, strlen(header_t));

	strcat(header,"\n");
	hdrLen++;
	//dbG("hdrLen=%d, final header####%s####\n", hdrLen, header);

	if (wrq.u.data.length > 0 && data[0] != 0)
	{
		int len = strlen(wrq.u.data.pointer + hdrLen);
		char *sp, *op;

		//dbg("%s\n",wrq.u.data.pointer);
		ssap = (sta_entry *)(wrq.u.data.pointer + hdrLen);
		op = sp = wrq.u.data.pointer + hdrLen;
		while (*sp && ((len - (sp-op)) >= 0)) {
			ssap->sta[staCount].mac[18]='\0';
			for (stream = 0; stream < xR_MAX; stream++) {
				ssap->sta[staCount].rssi[stream][6]='\0';
			}
			sp += hdrLen;
			staCount++;
		}

#ifdef RTCONFIG_WIRELESSREPEATER
		memset(pap_bssid,0,sizeof(pap_bssid));
		if(sw_mode() == SW_MODE_REPEATER && nvram_get_int("wlc_band") == unit)
		{
			char *aif;
			aif = nvram_get(strcat_r(prefix, "vifs", tmp));
			if(wl_ioctl(aif, SIOCGIWAP, &wrq2)>=0);
			{
				wrq2.u.ap_addr.sa_family = ARPHRD_ETHER;
				sprintf(pap_bssid,"%02X:%02X:%02X:%02X:%02X:%02X",
						(unsigned char)wrq2.u.ap_addr.sa_data[0],
						(unsigned char)wrq2.u.ap_addr.sa_data[1],
						(unsigned char)wrq2.u.ap_addr.sa_data[2],
						(unsigned char)wrq2.u.ap_addr.sa_data[3],
						(unsigned char)wrq2.u.ap_addr.sa_data[4],
						(unsigned char)wrq2.u.ap_addr.sa_data[5]);
			}
		}
#endif
		if (staCount)
		{
			char *strBand = NULL;
			int rssi = 0, lrssi = 0;
			int count = 0;
			int i = 0, k = 0;

			if(unit)
				strBand = "5G";
			else
				strBand = "2.4G";

			for(i = 0; i < staCount; i++)
			{
#ifdef RTCONFIG_WIRELESSREPEATER
				//dbg("pap bssid=#%s#\n",pap_bssid);
				if(!strncmp(pap_bssid,ssap->sta[i].mac,sizeof(pap_bssid)))
					continue; //pap bssid,skip
#endif
#if 0
				dbG("sta%d:mac=%s\n",i,ssap->sta[i].mac);

				for (stream = 0; stream < xTxR; stream++) {
					fprintf(stderr," rssi_th(%d) rssi[%d]=%s\n",rssi_th, stream, ssap->sta[i].rssi[stream]);
				}
#endif
				count = 0;
				for(k = 0; k < xTxR; k++)
				{
					rssi = atoi(ssap->sta[i].rssi[k]);
					if(rssi < rssi_th)
					{
						lrssi = rssi;
						count++;
					}
				}
				//disassociation
				if(count==xTxR)
				{
					logmessage("Roaming", "%s Disconnect Station: %s  RSSI: %d", strBand, ssap->sta[i].mac, lrssi);
					sprintf(cmd,"iwpriv %s set DisConnectSta=%s", wif, ssap->sta[i].mac);
					system(cmd);
				}
			}
		}
	}
}
#endif	/* RTCONFIG_USER_LOW_RSSI */

void set_default_psk()
{
	if (!strlen(nvram_safe_get("wifi_psk")))
	{
		unsigned char key[32];

		generate_wireless_key(key);
		nvram_set("wl0_auth_mode_x", "psk2");
		nvram_set("wl0_crypto", "aes");
		nvram_set("wl0_wpa_psk", key);
#if defined(RTAC1200) || defined(RTAC1200V2)
		nvram_set("wl1_auth_mode_x", "psk2");
		nvram_set("wl1_crypto", "aes");
		nvram_set("wl1_wpa_psk", key);
#endif
	}
}

#if defined(RTCONFIG_WANRED_LED)
extern int update_wan_led_and_wanred_led(int wan_unit);
#endif	// RTCONFIG_WANRED_LED

#if defined(RTCONFIG_FAILOVER_LED)
extern int update_failover_led(void);
#endif 	// RTCONFIG_FAILOVER_LED 

int update_wan_leds(int wan_unit, int link_wan_unit)
{
	if (!nvram_get_int("x_Setting")) {
		led_control(LED_WAN, LED_OFF);
#if defined(RTCONFIG_WANRED_LED)
		led_control(LED_WAN_RED, LED_ON);
#endif	// RTCONFIG_WANRED_LED
		return 0;
	}

#if defined(RTCONFIG_WANRED_LED)
    if (!inhibit_led_on())
        update_wan_led_and_wanred_led(wan_unit);

#else   /* !RTCONFIG_WANRED_LED */
    int link_internet = nvram_get_int("link_internet");

    /* Turn on/off WAN LED in accordance with link status of WAN port */
    if (link_wan_unit && !inhibit_led_on()) {
#if defined(RT4GAC86U)
        if(link_internet == 2)
            led_control(LED_WAN, LED_ON);
        else led_control(LED_WAN, LED_OFF);
#else
        led_control(LED_WAN, LED_ON);
#endif
    } else {
        if(link_internet != 2)
            led_control(LED_WAN, LED_OFF);
    }
#endif  /* RTCONFIG_WANRED_LED */

#if defined(RTCONFIG_FAILOVER_LED)
    update_failover_led();
#endif

    return 0;
}

#if defined(RTCONFIG_AMAS)

int get_wlc_func_enable(char *wif)
{
	char data[2] = {0};
	struct iwreq wrq;
	int enable = 0;

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_GETAPCLIENABLE;

	if (wl_ioctl(wif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting %s ASUS_SUBCMD_GETAPCLIENABLE result\n", wif);
		return enable;
	}
	enable = atoi(data);

	return enable;
}

int Pty_get_wlc_status(char *wif)
{
	char data[32] = {0};
	struct iwreq wrq;
	int status;
	int band = 0;
	static int old_status[2] = {-1, -1};
	char prefix[] = "wlXXXXXXXXXX_mssid_";
	memset(prefix, 0x00, sizeof(prefix));
	sprintf(prefix, "wl%d_", band);
	char temp[128] = {0};
	
	char *ifname = nvram_safe_get(strcat_r(prefix, "vifs", temp));
	
	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_CONN_STATUS;

	if (wl_ioctl(wif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting %s CONN_STATUS result\n", wif);
		return -1;
	}

	status = *(int*)wrq.u.data.pointer;
	if (band >=0 && band <= 1 && old_status[band] != status)
	{
		cprintf("%s: %s connStatus(%d --> %d)\n", __func__, ifname, old_status[band], status);
		old_status[band] = status;
	}

	if (status == 6)	// APCLI_CTRL_CONNECTED
		return WLC_STATE_CONNECTED;
	else if (status == 4)	// APCLI_CTRL_ASSOC
		return WLC_STATE_CONNECTING;
	return WLC_STATE_INITIALIZING;
}

#ifdef RTCONFIG_BHCOST_OPT
void Pty_start_wlc_connect(int band, char *bssid)
{
    char sbuf[32]={0};
    char *ifname = get_staifname(band);
	char ap_set_buf[128] = {0};
#if defined(RTCONFIG_MT798X)
	int delay = 7;
#else
	int delay = 20;
#endif
    snprintf(sbuf, sizeof(sbuf), "wlc%d_ssid", band);
    if(bssid == NULL) {
        doSystem("iwpriv %s set ApCliAutoConnect=1", ifname);
        sleep(delay);
    }
    else
    {
		snprintf(ap_set_buf, sizeof(ap_set_buf), "ApCliSsid=%s", nvram_safe_get(sbuf));
		ap_set(ifname, ap_set_buf);

        doSystem("iwpriv %s set ApCliBssid=%s", ifname, bssid);
        doSystem("iwpriv %s set ApCliAutoConnect=1", ifname);
        sleep(delay);
    }

    return;
}

/**
 * @brief amas_wlcconnect conneced to node successfully.
 *
 * @param band Band index
 */
void post_wlc_connected(int band) {
	// TODO
	return;
}

/**
 * @brief Get DFS status
 *
 * @param band Band
 * @return int Status. 1: CAC 0: Idle
 */
int amas_dfs_status(int band)
{
	char data[2] = {0};
	struct iwreq wrq;

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_DFS_STATUS;

	if (wl_ioctl(get_wifname(band), RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		dbg("errors in getting dfs status result\n");
		return 0;
	}

	if (wrq.u.data.length > 0)
	{
		return atoi(wrq.u.data.pointer);
	}

	return 0;
}

/**
 * @brief Get the uplinkports status
 *
 * @param ifname ethernet uplink ifname
 * @return int connnected(1) or not(0)
 */
int get_uplinkports_status(char *ifname)
{
	int wan_unit = wan_primary_ifunit();

	return get_wanports_status(wan_unit);
}

#else
#define RETRIGGER_CONNECTION_TIME	20
void Pty_start_wlc_connect(int band)
{
    char sbuf[32] = {0};
    char *ifname = get_staifname(band);
	static int retry_2g = 0;

    sprintf(sbuf, "wlc%d_ssid", band);
    if (strcmp(nvram_safe_get(sbuf), "")) {
        if (get_wlc_func_enable(ifname) == 0) {
            ap_set(ifname, "ApCliEnable=1");
            ap_set(ifname, "ApCliAutoConnect=1");
            sleep(5);  // Waiting for ApCliAutoConnect
        }
		if (band == 0) { // Re-trigger 2.4G mechanism.
            if (get_psta_status(band) != WLC_STATE_CONNECTED) {
                if (retry_2g > RETRIGGER_CONNECTION_TIME) {
					ap_set(ifname, "ApCliAutoConnect=1");
					sleep(5);
                    retry_2g = 0;
                } else
                    retry_2g++;
            }
			else
				retry_2g = 0;
        }
    }
}
#endif

void Pty_stop_wlc_connect(int band)
{
    char *ifname = get_staifname(band);

    if (get_wlc_func_enable(ifname))
    {
        ap_set(ifname, "ApCliEnable=0");
        sleep(2);
    }
}

int Pty_get_upstream_rssi(int band)
{
	int rssi_ret = 0, i = 0, stream_num = 0, rssi[8];
	char data[24], tmp[128], prefix[] = "wlXXXXXXXXXX_";
	struct iwreq wrq;
	char *pt1, *p_rssi, *rssi_val;
	int xTxR;
	char *aif = get_staifname(band);

	memset(data, 0x00, sizeof(data));
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) data;
	wrq.u.data.flags = ASUS_SUBCMD_CLRSSI;

	if (wl_ioctl(aif, RTPRIV_IOCTL_ASUSCMD, &wrq) < 0)
	{
		_dprintf("errors in getting ASUS_SUBCMD_CLRSSI result\n");
		return 0;
	}

	snprintf(prefix, sizeof(prefix), "wl%d_", band);
	xTxR = nvram_get_int(strcat_r(prefix, "HT_RxStream", tmp));
	//_dprintf("xTxR (%d)\n", xTxR);

	if (wrq.u.data.length > 0) {
		//_dprintf("data (%s)\n", wrq.u.data.pointer);
		if ((p_rssi = strdup(wrq.u.data.pointer)) != NULL) {
			pt1 = p_rssi;
			memset(rssi, 0, sizeof(rssi));
			while ((rssi_val = strsep(&pt1, " ")) != NULL) {
				while (*rssi_val == ' ') ++rssi_val;
				if (*rssi_val == 0 || stream_num >= xTxR) break;

				rssi[stream_num] = atoi(rssi_val);
				stream_num++;
			}
			free(p_rssi);

			//_dprintf("stream_num(%d)\n", stream_num);
			/* summarize rssi */
			for (i = 0; i < stream_num; i++) {
				//_dprintf("rssi[%d] = %d\n", i, rssi[i]);
				rssi_ret += rssi[i];
			}

			/* compute average rssi */
			if (rssi_ret != 0 && stream_num != 0) {
				rssi_ret = rssi_ret / stream_num;
				if (rssi_ret == -127)	/* -127 is not assocated pap */
					rssi_ret = 0;
			}
			else
				rssi_ret = 0;
		}
	}
	return rssi_ret;
}

int get_psta_rssi(int unit)
{
    return Pty_get_upstream_rssi(unit);
}

void pre_addif_bridge(int iftype)
{
	/* Not need to do anything */
}

/**
 * @brief Post sent action to amas_wlcconnect
 *
 */
void post_sent_action() {}

/**
 * @brief After updated wlcX_status
 *
 */
void post_update_status() {}

/**
 * @brief Backhaul changed sysdeps function
 *
 * @param iftype BH defif
 */
void post_bh_changed(int iftype) {
#if defined(RTCONFIG_AMAS_WGN)
	char word[64], *next = NULL;
    char br_name[64], *br_next = NULL;
    char if_name[64], *if_next = NULL;
    char amas_ifname[64];
    char s[64], ss[64], iface[20];
    char *lan_ifnames = NULL;
    int eth_bh = 0;
	int found = 0;

    if (nvram_get_int("wgn_enabled") == 0)
        return;

    if (nvram_get_int("re_mode") == 0)
        return;

#if defined(RTCONFIG_BHCOST_OPT)
    eth_bh = (iftype >= ETH1_U && iftype <= ETH_MAX_BASE) ? 1 : 0;
#else
    eth_bh = (iftype==ETH || iftype==ETH_2 || iftype==ETH_3 || iftype==ETH_4) ? 1 : 0;
#endif

    memset(amas_ifname, 0, sizeof(amas_ifname));
    strlcpy(amas_ifname, nvram_safe_get("amas_ifname"), sizeof(amas_ifname));
    if (strlen(amas_ifname) > 0)
    {
        // delif
        foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next)
        {
            // wgn_brX_eth_ifnames
            memset(ss, 0, sizeof(ss));
            snprintf(ss, sizeof(ss), "wgn_%s_lan_ifnames", br_name);
            lan_ifnames = nvram_safe_get(ss);
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_eth_ifnames", br_name);
			foreach (if_name, nvram_safe_get(s), if_next) {
				found = 0;
				foreach (word, lan_ifnames, next) {
					if ((found = (strcmp(word, if_name) == 0))) 
						break;
				}
				if (found == 0)
					eval("brctl", "delif", br_name, if_name);
			}			

            // wgn_brX_sta_ifnames
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_sta_ifnames", br_name);
            foreach (if_name, nvram_safe_get(s), if_next)
                eval("brctl", "delif", br_name, if_name);
        }

        // addif
        foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next)
        {
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s),  "wgn_%s_%s_ifnames", br_name, (eth_bh==1) ? "eth" : "sta");
            if (eth_bh == 1)
            {
                foreach (if_name, nvram_safe_get(s), if_next) {
                    memset(iface, 0, sizeof(iface));
                    if (wgn_check_vlan_invalid(amas_ifname, iface)) {
                        if (!strncmp(iface, if_name, strlen(iface)))
                            eval("brctl", "addif", br_name, if_name);
                    }
                    else {
                        if (!strncmp(amas_ifname, if_name, strlen(amas_ifname)))
                            eval("brctl", "addif", br_name, if_name);
                    }
                }
            }
            else
            {
				if (strlen(amas_ifname) > 3) {
					if (strncmp(&amas_ifname[strlen(amas_ifname)-3], ".0", 2) == 0)
						amas_ifname[strlen(amas_ifname)-3] = '\0';
				}
                foreach (if_name, nvram_safe_get(s), if_next)
                {
                    if (strncmp(amas_ifname, if_name, strlen(amas_ifname)) == 0)
                    {
                        eval("brctl", "addif", br_name, if_name);
                        break;
                    }
                }
            }
        }
    }
    else
    {
        // delif
        foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next)
        {
            // wgn_brX_eth_ifnames
            memset(ss, 0, sizeof(ss));
            snprintf(ss, sizeof(ss), "wgn_%s_lan_ifnames", br_name);
            lan_ifnames = nvram_safe_get(ss);
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_eth_ifnames", br_name);
			foreach (if_name, nvram_safe_get(s), if_next) {
				found = 0;
				foreach (word, lan_ifnames, next) {
					if ((found = (strcmp(word, if_name) == 0)))
						break;
				}
				if (found == 0)
					eval("brctl", "delif", br_name, if_name);
			}

            // wgn_brX_sta_ifnames
            memset(s, 0, sizeof(s));
            snprintf(s, sizeof(s), "wgn_%s_sta_ifnames", br_name);
            foreach (if_name, nvram_safe_get(s), if_next)
                eval("brctl", "delif", br_name, if_name);
        }
    }
#endif  // RTCONFIG_AMAS_WGN
}
void post_addif_bridge(int iftype)
{
	/* Not need to do anything */
}

void pre_delif_bridge(int iftype)
{

}

void post_delif_bridge(int iftype)
{

}

#if defined(RTCONFIG_AMAS_WGN)
void wgn_sysdep_swtich_unset(int vid)
{
	if (__wgn_sysdep_swtich_unset)
		__wgn_sysdep_swtich_unset(vid);
}

void wgn_sysdep_swtich_set(int vid)
{
	if (__wgn_sysdep_swtich_set)
		__wgn_sysdep_swtich_set(vid);
}

void wl_vlan_set(char* ifname, int allow)
{
#if defined(RTCONFIG_MT798X)
	/* Nothing to do... In MT798X mt_wifi, use iwpriv to enable at runtime.
	 * Finally, you need to set the SSID again for the VLAN function to take
	 * effect. So we parsed the VLANTag of dat instead, but mt_wifi needs to
	 * be modified.*/
	return;
#else
	int flags, mtu;
	_ifconfig_get(ifname, &flags, NULL, NULL, NULL, &mtu);
	if (flags & IFF_UP)
	{
		if(allow)
		{
			doSystem("iwpriv %s set VLANTag=1", ifname);
			doSystem("iwpriv %s set VLANPolicy=0:4", ifname); // tx(0) policy allow:4
			doSystem("iwpriv %s set VLANPolicy=1:2", ifname); // rx(1) policy allow:2
		}
		else
		{
			doSystem("iwpriv %s set VLANTag=0", ifname);
			doSystem("iwpriv %s set VLANPolicy=0:0", ifname); // tx(0) policy keep tag:0
			doSystem("iwpriv %s set VLANPolicy=1:0", ifname); // rx(1) policy untag:0
		}
	}
#endif
}

void wgn_sysdep_wl_unset(int vid)
{
	char word[256], *next;
	char wl_bh_ifnames[2048];
	char sta_bh_ifnames[2048];
	char *bh_ifnames = NULL;

	int wgn_enable = 0;

	// wl
	memset(wl_bh_ifnames, 0, sizeof(wl_bh_ifnames));
	if ((bh_ifnames = get_wl_bh_ifnames(wl_bh_ifnames, sizeof(wl_bh_ifnames))))
	{
		foreach (word, bh_ifnames, next)
		{
			wl_vlan_set(word, wgn_enable);
		}
	}
	// sta
	memset(sta_bh_ifnames, 0, sizeof(sta_bh_ifnames));
	if ((bh_ifnames = get_sta_bh_ifnames(sta_bh_ifnames, sizeof(sta_bh_ifnames))))
	{
		foreach (word, bh_ifnames, next)
		{
			wl_vlan_set(word, wgn_enable);
		}
	}
}

void wgn_sysdep_wl_set(int vid)
{
	char word[256], *next;
	char wl_bh_ifnames[2048];
	char sta_bh_ifnames[2048];
	char *bh_ifnames = NULL;

	int wgn_enable = is_wgn_enabled();

	// wl
	memset(wl_bh_ifnames, 0, sizeof(wl_bh_ifnames));
	if ((bh_ifnames = get_wl_bh_ifnames(wl_bh_ifnames, sizeof(wl_bh_ifnames))))
	{
		foreach (word, bh_ifnames, next)
		{
			wl_vlan_set(word, wgn_enable);
		}
	}
	// sta
	memset(sta_bh_ifnames, 0, sizeof(sta_bh_ifnames));
	if ((bh_ifnames = get_sta_bh_ifnames(sta_bh_ifnames, sizeof(sta_bh_ifnames))))
	{
		foreach (word, bh_ifnames, next)
		{
			wl_vlan_set(word, wgn_enable);
		}
	}
}

int wgn_process(void)
{
	const char *cap_rules = "/tmp/wgn_filter.default";
        FILE *fp;

        if((fp = fopen(cap_rules, "w")) == NULL)
		return 0;

        if (sw_mode() == SW_MODE_REPEATER || (sw_mode() == SW_MODE_AP && nvram_match("re_mode", "1")))
	{
		fclose(fp);
		return 0;
	}	
	wgn_filter_input(fp);
	fclose(fp);
	doSystem("sed -i \"s/^/iptables /g\" %s", cap_rules);
	chmod(cap_rules,0777);
	doSystem(cap_rules);
	return 1;

}
#endif	// RTCONFIG_AMAS_WGN

#define MAX_NRCHANNELS (32)
int get_radar_status(int bssidx)
{
    int det = 0;
    int ch_list[MAX_NRCHANNELS];
    int radar_list[MAX_NRCHANNELS];
    int ch_cnt = 0, radar_cnt = 0;
    int i = 0, j = 0;

    if ((ch_cnt = get_channel_list(bssidx, ch_list, MAX_NRCHANNELS)) < 0) {
        dbg("get_channel_list fail ret %d\n", ch_cnt);
        return det;
    }

    if ((radar_cnt =
             get_radar_channel_list(bssidx, radar_list, MAX_NRCHANNELS)) < 0) {
        dbg("get_radar_channel_list fail ret %d\n", radar_cnt);
        return det;
    }

    for (i = 0; i < ch_cnt; i++) {
        for (j = 0; j < radar_cnt; j++) {
            if (ch_list[i] == radar_list[j]) {
                dbG("%s Channel %d get radar signal.\n", __FUNCTION__,
                    ch_list[i]);
                det = 1;
            }
        }
    }

    return det;
}

int Pty_procedure_check(int unit, int wlif_count)
{
	return 0;
}

void amas_wait_wifi_ready(void)
{
    while (!nvram_get_int("wlready")) sleep(5);
}

extern int g_upgrade;
int no_need_obd(void)
{
#ifdef RTCONFIG_SW_HW_AUTH
	if (!(getAmasSupportMode() & AMAS_RE))
		return -1;
#endif
	if (g_reboot || g_upgrade)
		return -1;

	if (IS_ATE_FACTORY_MODE())
		return -1;

	if (!is_router_mode() || (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1))
		return -1;

	if (nvram_get_int("wlready") == 0)
		return -1;

	return pids("obd");
}

int no_need_obdeth(void)
{
#ifdef RTCONFIG_SW_HW_AUTH
	if (!(getAmasSupportMode() & AMAS_RE))
		return -1;
#endif
	if (g_reboot || g_upgrade)
		return -1;

	if (IS_ATE_FACTORY_MODE())
		return -1;

	if (!is_router_mode() || (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1))
		return -1;

	if (nvram_get_int("wlready") == 0)
		return -1;

	return pids("obd_eth");
}

#ifdef RTCONFIG_BHCOST_OPT
void apply_config_to_driver(int band)
{
    int sta_band, flag_wep = 0, p;
    char *sta_ifname, *wl_ifname __attribute__((unused)), *auth_mode;
    char buf[128] = {}, tmp[64] = {};
    char prefix_sta[] = "wlXXX_";

    sta_band = band;
    sta_ifname = get_staifname(sta_band);
    wl_ifname = get_wififname(sta_band);

    snprintf(prefix_sta, sizeof(prefix_sta), "wl%d_", sta_band);

    ap_set(sta_ifname, "ApCliEnable=0");

    /* ssid */
    snprintf(buf, sizeof(buf), "ApCliSsid=%s",
             nvram_safe_get(strcat_r(prefix_sta, "ssid", tmp)));
    ap_set(sta_ifname, buf);

    /* auth_mode_x */
    auth_mode = nvram_safe_get(strcat_r(prefix_sta, "auth_mode_x", tmp));
    if (auth_mode && strlen(auth_mode)) {
        if (!strcmp(auth_mode, "open") &&
            nvram_match(strcat_r(prefix_sta, "wep_x", tmp), "0")) {
            snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "OPEN");
            ap_set(sta_ifname, buf);
            snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "NONE");
            ap_set(sta_ifname, buf);
        } else if (!strcmp(auth_mode, "open") || !strcmp(auth_mode, "shared")) {
            flag_wep = 1;
            snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WEPAUTO");
            ap_set(sta_ifname, buf);
            snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "WEP");
            ap_set(sta_ifname, buf);
        } else if (!strcmp(auth_mode, "psk") || !strcmp(auth_mode, "psk2")
            || !strcmp(auth_mode, "pskpsk2") || !strcmp(auth_mode, "sae") || !strcmp(auth_mode, "psk2sae")) {
            if (!strcmp(auth_mode, "psk"))
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPAPSK");
            else if (!strcmp(auth_mode, "psk2"))
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPA2PSK");
            else if (!strcmp(auth_mode, "pskpsk2"))
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPAPSKWPA2PSK");
            else if (!strcmp(auth_mode, "sae"))
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPA3PSK");
            else if (!strcmp(auth_mode, "psk2sae"))
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPA2PSKWPA3PSK");
            ap_set(sta_ifname, buf);

            // EncrypType
            if (nvram_match(strcat_r(prefix_sta, "crypto", tmp), "tkip"))
                snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "TKIP");
            else if (nvram_match(strcat_r(prefix_sta, "crypto", tmp), "aes"))
                snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "AES");
            else if (nvram_match(strcat_r(prefix_sta, "crypto", tmp), "tkip+aes"))
                snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "TKIPAES");
            ap_set(sta_ifname, buf);

            // WPAPSK
            snprintf(buf, sizeof(buf), "ApCliWPAPSK=%s",
                     nvram_safe_get(strcat_r(prefix_sta, "wpa_psk", tmp)));
            ap_set(sta_ifname, buf);
        } else {
            snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "OPEN");
            ap_set(sta_ifname, buf);
            snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "NONE");
            ap_set(sta_ifname, buf);
        }
    } else {
        snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "OPEN");
        ap_set(sta_ifname, buf);
        snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "NONE");
        ap_set(sta_ifname, buf);
    }

    // EncrypType
    if (flag_wep) {
        // DefaultKeyID
        snprintf(buf, sizeof(buf), "ApCliDefaultKeyID=%s",
                 nvram_safe_get(strcat_r(prefix_sta, "key", tmp)));
        ap_set(sta_ifname, buf);

        // KeyStr
        for (p = 1; p <= 4; p++) {
            if (nvram_get_int(strcat_r(prefix_sta, "key", tmp)) == p)
                snprintf(buf, sizeof(buf), "ApCliKey%d=%s", p,
                         nvram_safe_get(strcat_r(prefix_sta, "wep_key", tmp)));
            else
                snprintf(buf, sizeof(buf), "ApCliKey%d=", p);

            ap_set(sta_ifname, buf);
        }
    }

    /* ssid */
    snprintf(buf, sizeof(buf), "ApCliSsid=%s",
             nvram_safe_get(strcat_r(prefix_sta, "ssid", tmp)));
    ap_set(sta_ifname, buf);
}

#else	// RTCONFIG_BHCOST_OPT
#if defined(RTCONFIG_DWB)
void apply_config_to_driver()
{
    int SUMband = get_wl_count();
    int sta_band, flag_wep = 0, p;
    char *sta_ifname, *wl_ifname, *auth_mode;
    char buf[128] = {}, tmp[64] = {};
    char prefix_sta[] = "wlXXX_";

    if (SUMband == 2)
        sta_band = 1;
    else
        sta_band = 2;

    sta_ifname = get_staifname(sta_band);
    wl_ifname = get_wififname(sta_band);

    snprintf(prefix_sta, sizeof(prefix_sta), "wl%d_", sta_band);

    ap_set(sta_ifname, "ApCliEnable=0");

    /* ssid */
    snprintf(buf, sizeof(buf), "ApCliSsid=%s",
             nvram_safe_get(strcat_r(prefix_sta, "ssid", tmp)));
    ap_set(sta_ifname, buf);

    /* auth_mode_x */
    auth_mode = nvram_safe_get(strcat_r(prefix_sta, "auth_mode_x", tmp));
    if (auth_mode && strlen(auth_mode)) {
        if (!strcmp(auth_mode, "open") &&
            nvram_match(strcat_r(prefix_sta, "wep_x", tmp), "0")) {
            snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "OPEN");
            ap_set(sta_ifname, buf);
            snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "NONE");
            ap_set(sta_ifname, buf);
        } else if (!strcmp(auth_mode, "open") || !strcmp(auth_mode, "shared")) {
            flag_wep = 1;
            snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WEPAUTO");
            ap_set(sta_ifname, buf);
            snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "WEP");
            ap_set(sta_ifname, buf);
        } else if (!strcmp(auth_mode, "psk") || !strcmp(auth_mode, "psk2")) {
            if (!strcmp(auth_mode, "psk"))
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPAPSK");
            else
                snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "WPA2PSK");
            ap_set(sta_ifname, buf);

            // EncrypType
            if (nvram_match(strcat_r(prefix_sta, "crypto", tmp), "tkip"))
                snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "TKIP");
            else if (nvram_match(strcat_r(prefix_sta, "crypto", tmp), "aes"))
                snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "AES");
            ap_set(sta_ifname, buf);

            // WPAPSK
            snprintf(buf, sizeof(buf), "ApCliWPAPSK=%s",
                     nvram_safe_get(strcat_r(prefix_sta, "wpa_psk", tmp)));
            ap_set(sta_ifname, buf);
        } else {
            snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "OPEN");
            ap_set(sta_ifname, buf);
            snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "NONE");
            ap_set(sta_ifname, buf);
        }
    } else {
        snprintf(buf, sizeof(buf), "ApCliAuthMode=%s", "OPEN");
        ap_set(sta_ifname, buf);
        snprintf(buf, sizeof(buf), "ApCliEncrypType=%s", "NONE");
        ap_set(sta_ifname, buf);
    }

    // EncrypType
    if (flag_wep) {
        // DefaultKeyID
        snprintf(buf, sizeof(buf), "ApCliDefaultKeyID=%s",
                 nvram_safe_get(strcat_r(prefix_sta, "key", tmp)));
        ap_set(sta_ifname, buf);

        // KeyStr
        for (p = 1; p <= 4; p++) {
            if (nvram_get_int(strcat_r(prefix_sta, "key", tmp)) == p)
                snprintf(buf, sizeof(buf), "ApCliKey%d=%s", p,
                         nvram_safe_get(strcat_r(prefix_sta, "wep_key", tmp)));
            else
                snprintf(buf, sizeof(buf), "ApCliKey%d=", p);

            ap_set(sta_ifname, buf);
        }
    }

    /* ssid */
    snprintf(buf, sizeof(buf), "ApCliSsid=%s",
             nvram_safe_get(strcat_r(prefix_sta, "ssid", tmp)));
    ap_set(sta_ifname, buf);
}
#endif
#endif	// RTCONFIG_BHCOST_OPT
#endif

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

#ifdef RTCONFIG_AMAS
/**
 * @brief Set AMAS relate features interface index
 *
 */
void init_amas_subunit()
{
	char name[8], tmp[128];
	char wl_vifnames_5g[128];
	int unit = num_of_wl_if() - 1;
	int max_mssid = num_of_mssid_support(unit);
	int re_guest_subunit = max_mssid + 1; // reserve for RE 3rd guest network
	int subidx_guest = 0, subidx_fh = 0, subidx_plk = 0;

#ifdef RTCONFIG_FRONTHAUL_DWB
	int re_fh_subunit, cap_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
	int re_prelink_subunit, cap_prelink_subunit;
#endif
#ifdef RTCONFIG_VIF_ONBOARDING
	char wl_vifnames_2g[128];
	int unit_2g = 0;
	int max_mssid_2g = num_of_mssid_support(unit_2g);
	int re_guest_subunit_2g = max_mssid_2g + 1;
	int cap_obvif_subunit = 0, re_obvif_subunit = 0;
#endif
	int subidx_guest_2g = 0, subidx_obvif = 0;

#if defined(RTCONFIG_FRONTHAUL_DWB) && defined(RTCONFIG_MSSID_PRELINK)
	cap_fh_subunit = max_mssid + 1;
	cap_prelink_subunit = max_mssid + 2;

	re_fh_subunit = re_guest_subunit + 1;
	re_prelink_subunit = re_guest_subunit + 2;
#elif defined(RTCONFIG_FRONTHAUL_DWB)
	cap_fh_subunit = max_mssid + 1;
	re_fh_subunit = re_guest_subunit + 1;
#elif defined(RTCONFIG_MSSID_PRELINK)
	cap_prelink_subunit = max_mssid + 1;
	re_prelink_subunit = re_guest_subunit + 1;
#endif

	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit);
	strcpy(wl_vifnames_5g, nvram_safe_get(tmp));

#ifdef RTCONFIG_VIF_ONBOARDING
	cap_obvif_subunit = max_mssid + 1;
	re_obvif_subunit = re_guest_subunit_2g + 1;
	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit_2g);
	strcpy(wl_vifnames_2g, nvram_safe_get(tmp));
#endif
	if(!nvram_match("re_mode", "1")) {
		subidx_guest = 0;
#ifdef RTCONFIG_FRONTHAUL_DWB
		subidx_fh = cap_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
		subidx_plk = cap_prelink_subunit;
#endif
#ifdef RTCONFIG_VIF_ONBOARDING
		subidx_guest_2g = 0;
		subidx_obvif = cap_obvif_subunit;
#endif
		_dprintf("init_amas_subunit: Set default value.\n");
	}
	else {
		subidx_guest = re_guest_subunit;
#ifdef RTCONFIG_FRONTHAUL_DWB
		subidx_fh = re_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
		subidx_plk = re_prelink_subunit;
#endif
#ifdef RTCONFIG_VIF_ONBOARDING
		subidx_guest_2g = re_guest_subunit_2g;
		subidx_obvif = re_obvif_subunit;
#endif
	}

	if(subidx_guest) {
		snprintf(name, sizeof(name), "wl%d.%d", unit, subidx_guest);
		add_to_list(name, wl_vifnames_5g, sizeof(wl_vifnames_5g));
	}

	if(subidx_fh) {
		snprintf(name, sizeof(name), "wl%d.%d", unit, subidx_fh);

		add_to_list(name, wl_vifnames_5g, sizeof(wl_vifnames_5g));
	}

	if(subidx_plk) {
		snprintf(name, sizeof(name), "wl%d.%d", unit, subidx_plk);
		add_to_list(name, wl_vifnames_5g, sizeof(wl_vifnames_5g));
	}

#ifdef RTCONFIG_FRONTHAUL_DWB
	nvram_set_int("fh_cap_mssid_subunit", cap_fh_subunit);
	nvram_set_int("fh_re_mssid_subunit", re_fh_subunit);
#endif
#ifdef RTCONFIG_MSSID_PRELINK
	nvram_set_int("plk_cap_subunit", cap_prelink_subunit);
	nvram_set_int("plk_re_subunit", re_prelink_subunit);
#endif
#if defined(RTCONFIG_FRONTHAUL_DWB) || defined(RTCONFIG_MSSID_PRELINK)
	_dprintf("%s(%d): update wl%d_vifnames [%s] \n", __FUNCTION__, __LINE__, unit, wl_vifnames_5g);
	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit);
	nvram_set(tmp, wl_vifnames_5g);
#endif

#ifdef RTCONFIG_VIF_ONBOARDING
	if(subidx_guest_2g) {
		snprintf(name, sizeof(name), "wl%d.%d", unit_2g, subidx_guest_2g);
		add_to_list(name, wl_vifnames_2g, sizeof(wl_vifnames_2g));
	}

	if(subidx_obvif) {
		snprintf(name, sizeof(name), "wl%d.%d", unit_2g, subidx_obvif);
		add_to_list(name, wl_vifnames_2g, sizeof(wl_vifnames_2g));
	}

	nvram_set_int("obvif_cap_subunit", cap_obvif_subunit);
	nvram_set_int("obvif_re_subunit", re_obvif_subunit);

	_dprintf("%s(%d): update wl%d_vifnames [%s] \n", __FUNCTION__, __LINE__, unit_2g, wl_vifnames_2g);
	snprintf(tmp, sizeof(tmp), "wl%d_vifnames", unit_2g);
	nvram_set(tmp, wl_vifnames_2g);
#endif

	if (subidx_guest || subidx_fh || subidx_plk ||
		subidx_guest_2g || subidx_obvif)
		nvram_commit();
}
#endif
int get_wifi_country_code_tmp(char *ori_countrycode, char *output, int len)
{
	return -1;
}

#if defined(RTCONFIG_AMAS_MTK_EZWDS)
void set_ezwds_radio_type(void)
{
 	int i;
        char word[256], *next, ifnames[128];
        i = 0;
	if(!nvram_match("cfg_master", "1") && !nvram_match("re_mode", "1")) 
		return;

        strcpy(ifnames, nvram_safe_get("wl_ifnames"));
        foreach (word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
                        break;
 		SKIP_ABSENT_BAND(i);
		//configure ap-iface as fronthaul & backhaul
		iwprivSet(get_wifname(i), "fhBSS", "1");
		iwprivSet(get_wifname(i), "bhBSS", "1");
                ++i;
        }
}	
#endif

#if defined(RTCONFIG_MTK_BSD)
void duplicate_wl_ifaces(void)
{
        char prefix[]="wlXXXXXXX_";
        char prefix2[]="wlXXXXXXX_";
        char tmp[100], tmp2[100];
        int unit = 0;
        int i;
        int wlif_count = num_of_wl_if();
#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_PRELINK) && !defined(RTCONFIG_MSSID_PRELINK)
	int prelink = nvram_invmatch("amas_bdlkey", "");
        char prelink_ssid[100], prelink_psk[100];
	int result=0;
#endif
        snprintf(prefix, sizeof(prefix), "wl%d_", unit);
        for (i = unit + 1; i < wlif_count; i++) {
#ifdef RTCONFIG_DWB
		if((nvram_get_int("dwb_mode") == 1  || nvram_get_int("dwb_mode") == 3)  && nvram_get_int("dwb_band") > 0 && i == nvram_get_int("dwb_band")){
                	snprintf(prefix2, sizeof(prefix2), "wl%d_", i);
			if (is_router_mode() && strstr(nvram_safe_get(strcat_r(prefix2, "ssid", tmp)), "dwb")) {
				dbg("Don't apply wl0 to wl%d in smart_connect function, if enabled DWB mode.\n", i);
				continue;
			}
			else {
				nvram_set_int("dwb_mode", 0);
			}
		}
#endif
                snprintf(prefix2, sizeof(prefix2), "wl%d_", i);
#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_PRELINK) && !defined(RTCONFIG_MSSID_PRELINK)
		if (prelink && wlif_count == (i+1)) {
			strlcpy(prelink_ssid,nvram_safe_get(strcat_r(prefix2, "ssid", tmp)),sizeof(prelink_ssid));
			strlcpy(prelink_psk,nvram_safe_get(strcat_r(prefix2, "wpa_psk", tmp)),sizeof(prelink_psk));
			result=0;
        		if(amas_verify_default_backhaul_security(prelink_ssid, prelink_psk, &result) == AMAS_RESULT_SUCCESS )
			{
				if(result==1)
				{
					_dprintf("Do not apply wl0 to wl%d , if enable prelink mode.\n",i);
					continue;
				}
			}
		}
#endif
                nvram_set(strcat_r(prefix2, "ssid", tmp2), nvram_safe_get(strcat_r(prefix, "ssid", tmp)));
                nvram_set(strcat_r(prefix2, "auth_mode_x", tmp2), nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)));
                nvram_set(strcat_r(prefix2, "wep_x", tmp2), nvram_safe_get(strcat_r(prefix, "wep_x", tmp)));
                nvram_set(strcat_r(prefix2, "key", tmp2), nvram_safe_get(strcat_r(prefix, "key", tmp)));
                nvram_set(strcat_r(prefix2, "key1", tmp2), nvram_safe_get(strcat_r(prefix, "key1", tmp)));
                nvram_set(strcat_r(prefix2, "key2", tmp2), nvram_safe_get(strcat_r(prefix, "key2", tmp)));
                nvram_set(strcat_r(prefix2, "key3", tmp2), nvram_safe_get(strcat_r(prefix, "key3", tmp)));
                nvram_set(strcat_r(prefix2, "key4", tmp2), nvram_safe_get(strcat_r(prefix, "key4", tmp)));
                nvram_set(strcat_r(prefix2, "phrase_x", tmp2), nvram_safe_get(strcat_r(prefix, "phrase_x", tmp)));
                nvram_set(strcat_r(prefix2, "crypto", tmp2), nvram_safe_get(strcat_r(prefix, "crypto", tmp)));
                nvram_set(strcat_r(prefix2, "wpa_psk", tmp2), nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)));
                nvram_set(strcat_r(prefix2, "radius_ipaddr", tmp2), nvram_safe_get(strcat_r(prefix, "radius_ipaddr", tmp)));
                nvram_set(strcat_r(prefix2, "radius_key", tmp2), nvram_safe_get(strcat_r(prefix, "radius_key", tmp)));
                nvram_set(strcat_r(prefix2, "radius_port", tmp2), nvram_safe_get(strcat_r(prefix, "radius_port", tmp)));
                nvram_set(strcat_r(prefix2, "closed", tmp2), nvram_safe_get(strcat_r(prefix, "closed", tmp)));
#if defined(RTCONFIG_WIFI_QCN5024_QCN5054) || defined(RTCONFIG_QCA_AXCHIP)
                nvram_set(strcat_r(prefix2, "11ax", tmp2), nvram_safe_get(strcat_r(prefix, "11ax", tmp)));
#endif
#if defined(RTCONFIG_MFP)
                nvram_set(strcat_r(prefix2, "mfp", tmp2), nvram_safe_get(strcat_r(prefix, "mfp", tmp)));
#endif
	}
	nvram_commit();
}
#endif

#if (defined(RTCONFIG_RALINK) && LINUX_KERNEL_VERSION >= KERNEL_VERSION(3,14,0))
void config_mssid_isolate(char *ifname, int vif)
{
#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(4,18,0)
	const char *isolate_attr = "isolated";		/* Offical kernel */
#else
	const char *isolate_attr = "isolate_mode";	/* OpenWRT isolate_mode patch */
#endif
	int i, unit = -1, mode = 0;
	char prefix[sizeof("wlXXX_")], path[sizeof(SYS_CLASS_NET "/XXX/brport/isolate_mode") + IFNAMSIZ];

	if (!is_router_mode()) return;
	if (!ifname) return;

	snprintf(path, sizeof(path), "/sys/class/net/%s/brport/%s", ifname, isolate_attr);
	if (!f_exists(path)) {
		dbg("%s: %s doesn't exist!\n", __func__, path);
		return;
	}

	if (!vif) {
		/* Main WiFi, AP isolate */
		for (i = WL_2G_BAND; i < MAX_NR_WL_IF; ++i) {
			SKIP_ABSENT_BAND(i);

			if (!strcmp(ifname, get_wififname(i))) {
				unit = i;
				break;
			}
		}
		if (__absent_band(unit)) {
			dbg("%s: ifname [%s] vif [%d], unknown unit [%d]\n", ifname? : "NULL", vif, unit);
			return;
		}

		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	} else {
		/* Guest network, lan access */
		snprintf(prefix, sizeof(prefix), "%s_", wif_to_vif(ifname));
	}

	if (nvram_pf_get_int(prefix, "ap_isolate")
	 || (vif && nvram_pf_match(prefix, "lanaccess", "off")))
		mode = 1;

	f_write_string(path, mode ? "1" : "0", 0, 0);
}
#endif

