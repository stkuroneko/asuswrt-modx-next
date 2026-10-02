#include <rtconfig.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <json.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#if defined(RTCONFIG_QCA) && !defined(__GLIBC__) && !defined(__UCLIBC__)	/* QCA + musl */
struct __fdb_entry {
	uint8_t mac_addr[6];
	uint8_t port_no;
	uint8_t is_local;
	uint32_t ageing_timer_value;
	uint8_t port_hi;
	uint8_t pad0;
	uint16_t unused;
};
#else
#include <linux/if_bridge.h>
#endif	/* QCA + musl */
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#ifdef RTCONFIG_AMAS
#include <amas-utils.h>
#include <amas_path.h>
#endif
#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#endif	/* RTCONFIG_SW_HW_AUTH */
#ifdef RTCONFIG_DWB
#include "cfg_dwb.h"
#endif

#include "chmgmt.h"
#include "cfg_bandindex.h"
extern int wl_get_chconf(const char* ifname, chmgmt_chconf_t* chconf);

extern struct nvram_tuple router_defaults[];

#ifdef RTCONFIG_SW_HW_AUTH
#define APP_ID	"33716237"
#define APP_KEY	"g2hkhuig238789ajkhc"

#if !defined(RTCONFIG_BHCOST_OPT)
static char oldWiredPortStatus[128] = {0};
#endif

#define BR_MAX_ENTRY	256

int check_auth()
{
	time_t timestamp = time(NULL);
	char in_buf[48];
	char out_buf[65];
	char hw_out_buf[65];
	char *hw_auth_code = NULL;
	int ret = 0;

	// initial
	memset(in_buf, 0, sizeof(in_buf));
	memset(out_buf, 0, sizeof(out_buf));
	memset(hw_out_buf, 0, sizeof(hw_out_buf));

	// use timestamp + APP_KEY to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, APP_KEY);

	hw_auth_code = hw_auth_check(APP_ID, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

	// use timestamp + APP_KEY + APP_ID to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, APP_KEY, APP_ID);

	// if check fail, return
	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
		DBG_INFO("This is ASUS router");
		ret = 1;
	}
	else
		DBG_INFO("This is not ASUS router");

	return ret;
}
#endif	/* RTCONFIG_SW_HW_AUTH */

/*
========================================================================
Routine Description:
	Get hwaddr.

Arguments:
	*ifname		- interface name

Return Value:
	mac addr for interface name

========================================================================
*/
char *get_hwaddr(const char *ifname)
{
	int s = -1;
	struct ifreq ifr;
	char eabuf[32];
	char *p = NULL;

	if (ifname == NULL) return NULL;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) return NULL;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (ioctl(s, SIOCGIFHWADDR, &ifr)) goto error;

	p = strdup(ether_etoa((const unsigned char *)ifr.ifr_hwaddr.sa_data, eabuf));

error:
	close(s);
	return p;
} /* End of get_hwaddr */


/*
========================================================================
Routine Description:
	Get lan ip addr.

Arguments:
	None

Return Value:
	ip addr for interface name

========================================================================
*/
char *get_lan_ipaddr()
{
	int s = -1;
	struct ifreq ifr;
	struct sockaddr_in *inaddr;
	struct in_addr ip_addr; 

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		memset (&ip_addr, 0, sizeof(ip_addr));
		return inet_ntoa(ip_addr);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, LAN_IFNAME, IFNAMSIZ-1);
	inaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	inet_aton("0.0.0.0", &inaddr->sin_addr);

	/* get ip address */
	ioctl(s, SIOCGIFADDR, &ifr);
	close(s);

	ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	return inet_ntoa(ip_addr);
} /* End of get_lan_ipaddr */

int ip_atoe(const char *a, unsigned char *e)
{
	char *c = (char *) a;
	int i = 0;

	memset(e, 0, 4);
	for (;;) {
		e[i++] = (unsigned char) strtoul(c, &c, 10);
		if (!*c++ || i == 4)
			break;
	}
	return (i == 4);
} /* End of ip_atoe */

/*
========================================================================
Routine Description:
	Get port number of first lan interface (lan_ifnames) in the bridge interface.

Arguments:
	None

Return Value:
	port number for interface name

========================================================================
*/
char *get_portno_by_ifname()
{
	char buf[64] = {0};
        char *ifname = NULL;
	char lan_ifnames[128] = {0};
	char port_no[8] = {0};
	char word[16], *next;
	static char wired_ifindex[32];
	int haveInfo = 0;
#if defined(RTCONFIG_BROOP) || defined(RTCONFIG_AMAS_ETHDETECT)
	char wiredifnames[64];
	char *brif = nvram_safe_get("lan_ifname");
	char *ethif = nvram_safe_get("eth_ifnames");
#endif

	memset(wired_ifindex, 0, sizeof(wired_ifindex));

#if defined(RTCONFIG_BROOP) || defined(RTCONFIG_AMAS_ETHDETECT)
	if (nvram_get("wired_ifnames") || strlen(ethif) != 0) {
		snprintf(wiredifnames, sizeof(wiredifnames), "%s", nvram_safe_get("wired_ifnames"));
		foreach (word, ethif, next) {
			if (nvram_match("re_mode", "1") && is_bridged(brif, word) && !strstr(nvram_safe_get("wired_ifnames"), word) && (*nvram_safe_get("amas_ifname") && !strstr(word, nvram_safe_get("amas_ifname")))) {
				if (strlen(wiredifnames) != 0)
					strncat(wiredifnames, " ", sizeof(wiredifnames) - strlen(wiredifnames) - 1);
				strncat(wiredifnames, word, sizeof(wiredifnames) - strlen(wiredifnames) - 1);
			}
		}
		nvram_set("w2_ifnames", wiredifnames);
		foreach (word, wiredifnames, next) {
#else
	if (nvram_get("wired_ifnames")) {
		foreach (word, nvram_safe_get("wired_ifnames"), next) {
#endif
			snprintf(buf, sizeof(buf), "/sys/class/net/%s/brport/port_no", word);
			if (f_read_string(buf, port_no, sizeof(port_no)) <= 0)
				continue;

			snprintf(port_no, sizeof(port_no), "%d", (int)strtol(port_no, NULL, 0));

			if (!haveInfo)
				haveInfo = 1;
			else
				strcat(wired_ifindex, " ");
			strcat(wired_ifindex, port_no);
		}
	}
	else
	{
		snprintf(lan_ifnames, sizeof(lan_ifnames), "%s", nvram_safe_get("lan_ifnames"));

		/* get first lan interface */
		ifname = strtok(lan_ifnames, " ");
		snprintf(buf, sizeof(buf), "/sys/class/net/%s/brport/port_no", ifname);

		if (f_read_string(buf, port_no, sizeof(port_no)) <= 0)
			return "";

		snprintf(port_no, sizeof(port_no), "%d", (int)strtol(port_no, NULL, 0));
		snprintf(wired_ifindex, sizeof(wired_ifindex), "%s", port_no);
	}

	return wired_ifindex;
} /* End of get_portno_by_ifname */

/*
========================================================================
Routine Description:
	Check mac is re from wired or not.

Arguments:
	*mac		- mac address

Return Value:
	wired re

========================================================================
*/
int is_re_from_wired(char *mac)
{
	int ret = 0, show_re_mac = nvram_get_int("show_re_mac");
	char filter_mac[17] = {0};
	char *cfg_relist = NULL;

	if (!mac || strlen(mac) == 0) {
		DBG_ERR("mac is NULL");
		return 0;
	}

	/* filter low bits of last byte(5) for RE mac */
	strncpy(filter_mac, mac, sizeof(filter_mac) - 1);
	if (show_re_mac)
		DBG_INFO("mac (%s), filter mac (%s)", mac, filter_mac);

	if ((cfg_relist = get_cfg_relist(0)) && strstr(cfg_relist, filter_mac)) {
		if (show_re_mac)
			DBG_INFO("mac (%s) is wired re", mac);
		ret = 1;
	}

	if (cfg_relist) free(cfg_relist);

	return ret;
}

/*
========================================================================
Routine Description:
	Add the mac of ethernet port (w/ not local) to json object from bridge forwarding table.

Arguments:
	*root			- json object for adding mac
	*portIndex		- which port index need to be processed

Return Value:
	None

========================================================================
*/
void add_brforward_entry_by_port(json_object *root, char *portIndex)
{
	FILE *fd;
	int i, cnt;
	char path[128] = {0};
	struct __fdb_entry fe[BR_MAX_ENTRY];
	json_object *brArry = NULL;
	char mac[18] = {0};
	char port_buf[32] = {0};
	int port_no = 0;
	char word[16], *next;
	unsigned int ageing;
	int ageing_timer = nvram_get("cfg_ageing") ? nvram_get_int("cfg_ageing") : DEFAULT_AGEING_TIMER;
	int re_ageing_timer = nvram_get("cfg_re_ageing") ? nvram_get_int("cfg_re_ageing") : DEFAULT_RE_AGEING_TIMER;
	int is_wired_re = 0;

	snprintf(path, PATH_MAX, "/sys/class/net/%s/brforward", nvram_safe_get("lan_ifname"));
	fd = fopen(path, "r");

	if (fd) {
		cnt = fread(fe, sizeof(struct __fdb_entry), BR_MAX_ENTRY, fd);
		fclose(fd);

		snprintf(port_buf, sizeof(port_buf), "%s", portIndex);
		foreach (word, port_buf, next) {
			port_no= atoi(word);

			for (i = 0; i < cnt; i++) {
				if (fe[i].port_no == port_no) {
					memset(mac, 0, sizeof(mac));
					snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
						fe[i].mac_addr[0], fe[i].mac_addr[1], fe[i].mac_addr[2],
						fe[i].mac_addr[3], fe[i].mac_addr[4], fe[i].mac_addr[5]);

					//ageing =((1000000ULL * fe[i].ageing_timer_value) / HZ) / 1000000;
					ageing = fe[i].ageing_timer_value / 100;

					if (nvram_get("cfg_brd")) {
						DBG_INFO("mac_addr(%s) port_no(%d) is_local(%d), ageing sec(%d)",
							mac, fe[i].port_no, fe[i].is_local, ageing);
					}

					if (fe[i].is_local == 0) {
						is_wired_re = is_re_from_wired(mac);
						if ((is_wired_re && (ageing <= re_ageing_timer)) ||
							(!is_wired_re && (ageing <= ageing_timer))) {

							if (!brArry)
								brArry = json_object_new_array();

							if (brArry)
								json_object_array_add(brArry, json_object_new_string(mac));
						}
					}
				}
			}
		}

		if (brArry)
			json_object_object_add(root, CFG_STR_WIRED_MAC, brArry);
	}
} /* End of add_brforward_entry_by_port */

/*
 * Convert Key string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx notation
 * @param	e	binary data
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int
key_atoe(const char *a, unsigned char *e)
{
	char *c = (char *) a;
	int i = 0;

	memset(e, 0, KEY_LENGTH);
	for (;;) {
		e[i++] = (unsigned char) strtoul(c, &c, 16);
		if (!*c++ || i == KEY_LENGTH)
			break;
	}
	return (i == KEY_LENGTH);
}

/*
 * Convert Key binary data to string representation
 * @param	e	binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx notation
 * @return	a
 */
char *
key_etoa(const unsigned char *e, char *a)
{
	char *c = a;
	int i;

	for (i = 0; i < KEY_LENGTH; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", e[i] & 0xff);
	}
	return a;
}

unsigned long getFileSize(char *FileName)
{
        unsigned long length = 0, curpos = 0;
        FILE *stream = NULL;

        if ((stream = fopen(FileName, "rb")) == NULL)
                return length;

        curpos = ftell(stream);
        fseek(stream, 0L, SEEK_END);
        length = ftell(stream);
        fseek(stream, curpos, SEEK_SET);
        fclose(stream);
        return length;
}

int fileExists(char *FileName)
{
        int ret = 0;
        FILE *stream = NULL;

        stream = fopen(FileName, "r");
        ret = (stream == NULL) ? 0 : 1;
        if (ret == 1) fclose(stream);
        return ret;
}

static char *AdvTrim_Right(char *szSource)
{
        char* back = szSource + strlen(szSource);
        while (isspace(*--back));
        *(back+1) = '\0';
        return szSource;
}

static char *AdvTrim_Left(char *szSource)
{
        while (isspace(*szSource)) szSource++;
        return szSource;
}

char *AdvTrim(char *szSource)
{
        return AdvTrim_Right(AdvTrim_Left(szSource));
}

char *wl_ifindex_to_bsd_ifnames(char *ifindex, int *out_len)
{
	int i;
	int outlen = 0;
	int wl_if_num = num_of_wl_if();

	char s[81];
	char *ss = NULL;
	char *out = NULL;
	char word1[33];
	char *next1 = NULL;
	char word2[33];
	char *next2 = NULL;

	if (!ifindex || strlen(ifindex) <= 0)
		return NULL;

	ss = NULL;
	foreach (word1, ifindex, next1)
	{
		for (i=0; i<wl_if_num; i++)
		{
			if (atoi(word1) != i)
				continue;

			memset(s, 0, sizeof(s));
			snprintf(s, sizeof(s)-1, "wl%d_vifs", i);
			memset(word2, 0, sizeof(word2));
			foreach (word2, nvram_safe_get(s), next2)
			{
				break;
			}

			if (strlen(word2) > 0)
			{
				memset(s, 0, sizeof(s));
				snprintf(s, sizeof(s)-1, "%s ", word2);
				if ((out = (char *)realloc(out, strlen(s))) == NULL)
				{
					DBG_ERR("Memory realloc error ...");
					goto wl_ifindex_to_bsd_ifnames_exit;
				}
				if (ss == NULL) ss = &out[0];
				memcpy(ss, s, strlen(s));
				outlen += strlen(s);
				ss += strlen(s);
				break;				
			}
		}
	}

	if (outlen > 0) 
	{
		outlen --;
		out[outlen] = '\0';
	}
	else
	{
		outlen = 0;
		if (out != NULL)
		{
			free(out);
			out = NULL;
		}
	}

	if (out_len != NULL) *(out_len) = outlen;	
	return out;

wl_ifindex_to_bsd_ifnames_exit:
	if (out != NULL) free(out);
	return NULL;
}


char *wl_ifindex_to_ifnames(char *ifindex, int *out_len)
{
	int outlen = 0, wl_unit = 0;
	char s[81], *ss = NULL, *out = NULL;
	char word1[33], *next1 = NULL, word2[33], *next2 = NULL;

	if (ifindex == NULL || strlen(ifindex) <= 0)
	{
		goto wl_ifindex_to_ifnames_exit;
	}

	ss = NULL;
	memset(word1, 0, sizeof(word1));
	next1 = NULL;
	foreach (word1, ifindex, next1)
	{
		memset(word2, 0, sizeof(word2));
		next2 = NULL;
		wl_unit = 0;
		foreach (word2, nvram_safe_get("wl_ifnames"), next2)
		{
			if (atoi(word1) == wl_unit)
			{
				memset(s, 0, sizeof(s));
				snprintf(s, sizeof(s)-1, "%s ", word2);
				if ((out = (char *)realloc(out, strlen(s))) == NULL)
				{
					DBG_ERR("Memory realloc error ...");
					goto wl_ifindex_to_ifnames_exit;
				}
				if (ss == NULL) ss = &out[0];
				memcpy(ss, s, strlen(s));
				outlen += strlen(s);
				ss += strlen(s);
				break;
			}
			wl_unit++;
		}
	}

	if (outlen > 0) 
	{
		outlen --;
		out[outlen] = '\0';
	}
	else
	{
		outlen = 0;
		if (out != NULL)
		{
			free(out);
			out = NULL;
		}
	}

	if (out_len != NULL) *(out_len) = outlen;	
	return out;

wl_ifindex_to_ifnames_exit:
	if (out != NULL) free(out);
	return NULL;
}

char *wl_ifnames_to_ifindex(char *ifnames, int *out_len)
{
	int outlen = 0, wl_unit = 0;
	char s[81], *ss = NULL, *out = NULL;
	char word1[33], *next1 = NULL, word2[33], *next2 = NULL;

	if (ifnames == NULL || strlen(ifnames) <= 0)
	{
		goto wl_ifnames_to_ifindex_exit;
	}

	ss = NULL;
	memset(word1, 0, sizeof(word1));
	next1 = NULL;
	foreach (word1, ifnames, next1) 
	{
		memset(word2, 0, sizeof(word2));
		next2 = NULL;
		wl_unit = 0;
		foreach (word2, nvram_safe_get("wl_ifnames"), next2)
		{
			if (strlen(word1) == strlen(word2) && strncmp(word1, word2, strlen(word1)) == 0)
			{
				memset(s, 0, sizeof(s));
				snprintf(s, sizeof(s)-1, "%d ", wl_unit);
				if ((out = (char *)realloc(out, strlen(s))) == NULL)
				{
					DBG_ERR("Memory realloc error ...");
					goto wl_ifnames_to_ifindex_exit;
				}

				if (ss == NULL) ss = &out[0];
				memcpy(ss, s, strlen(s));
				outlen += strlen(s);
				ss += strlen(s);
				break;
			}

			wl_unit++;
		}		
	}

	if (outlen > 0) 
	{
		outlen--;
		out[outlen] = '\0';
	}
	else
	{
		outlen = 0;
		if (out != NULL)
		{
			free(out);
			out = NULL;
		}
	}

	if (out_len != NULL) *(out_len) = outlen;	
	return out;

wl_ifnames_to_ifindex_exit:
	if (out != NULL) free(out);
	return NULL;
}


char* dumpHEX(unsigned char *src, unsigned long src_size)
{
        int c;
        unsigned char *s = NULL, *ss = NULL;
        char *P = NULL, *PP = NULL, sss[33];
        unsigned long alloc_size = 0;

        if (src == NULL || src_size <= 0)
        {
                return NULL;
        }

        alloc_size = src_size * 4;
        s = &src[0];
        ss = &src[src_size];
        P = (char *)malloc(alloc_size);

        if (P == NULL)
        {
                return NULL;
        }

        memset(P, 0, alloc_size);
        for (c=0, PP=&P[0]; s<ss; s++)
        {
                memset(sss, 0, sizeof(sss));
                snprintf(sss, sizeof(sss)-1, "%02X%c", *s, (c>=15)?'\x0a':'\x20');
                strncpy(PP, sss, strlen(sss));
                PP += strlen(sss);
                if (c++>=15) c = 0;
        }

        return P;
}

static int _is_hex(char c)
{
	return (((c >= '0') && (c <= '9')) ||
		((c >= 'A') && (c <= 'F')) ||
		((c >= 'a') && (c <= 'f')));
} /* End of _is_hex */ 

int str2hex(const char *a, unsigned char *e, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = a[idx];
		tmpBuf[1] = a[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;
		e[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
} /* End of str2hex */ 

#ifdef ONBOARDING
unsigned char *get_onboarding_key()
{
	unsigned char *key = NULL;
	char *authMode = NULL;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char tmpStr[32] = {0};
	char keyStr[KEY_LENGTH + 1]= {0};
	int i = 0;

	if ((key = (unsigned char *)malloc(KEY_LENGTH)) == NULL) {
		DBG_ERR("memory allocate failed");
		goto err;
	}

	if (nvram_get("cfg_obkey")) {
		snprintf(keyStr, sizeof(keyStr), "%s", nvram_safe_get("cfg_obkey"));
	}
	else
	{
		/* using 2g prefix */
		snprintf(prefix, sizeof(prefix), "wl%d_", 0);

		authMode = nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp));

		if ((!strcmp(authMode, "open") && nvram_invmatch(strcat_r(prefix, "wep_x", tmp), "0")) ||
			!strcmp(authMode, "shaed") || !strcmp(authMode, "radius")) {
			snprintf(tmpStr, sizeof(tmpStr), "%skey%s", prefix, nvram_safe_get(strcat_r(prefix, "key", tmp)));
			snprintf(keyStr, sizeof(keyStr), "%s", nvram_safe_get(tmpStr));
		}
		else if (!strcmp(authMode, "psk") || !strcmp(authMode, "psk2") ||
			!strcmp(authMode, "pskpsk2") || !strcmp(authMode, "wpa") ||
			!strcmp(authMode, "wpa2") || !strcmp(authMode, "psk2") ||
			!strcmp(authMode, "psk2sae") || !strcmp(authMode, "sae"))
			snprintf(keyStr, sizeof(keyStr), "%s", nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)));
	}

	DBG_INFO("keyStr(%s)", keyStr);

	memset(key, 0, KEY_LENGTH);
	memcpy(key, (unsigned char *)&keyStr[0], strlen(keyStr));

	/* padding */
	if (strlen(keyStr) != KEY_LENGTH) {
		for (i = strlen(keyStr); i < KEY_LENGTH; i++)
			key[i] = '0';
	}
#if 0
	for (i = 0; i < KEY_LENGTH; i++)
		DBG_PRINTF("%02X ", key[i]);
	DBG_PRINTF("\n");
#endif

err:

	return key;
}
#endif

void update_lldp_cost(int cost)
{
	nvram_set_int("cfg_cost", cost);
#ifdef RTCONFIG_AMAS
	int ret = 0;
	amas_utils_set_debug(1);
	ret = amas_set_cost(cost);
	DBG_INFO("lldp result(%d)", ret);
#endif

#ifdef PRELINK
	update_lldp_hash_bundle_key();
#endif
}

#ifdef RTCONFIG_BHCOST_OPT
void update_rssiscore(int rssiscore)
{
	nvram_set_int("cfg_rssiscore", rssiscore);
	int ret = 0;
	amas_utils_set_debug(1);
	ret = amas_set_rssi_score(rssiscore);
	DBG_INFO("lldpd set rssiscore(%d) result(%d)", rssiscore, ret);
}

void set_wifi_lastbyte()
{
	int ret = 0;
	char buf[8], lastByteStr[18] = {0}, word[32], *next, *p;
	unsigned char eabuf[6] = {0};
	int unit = 0, i = 0;
	unsigned char lastByte[4] = {0};
	char prefix[sizeof("wlXXXXX_")], tmp[32], ifname[16];
	int nband = 0;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
	char wlPrefix[sizeof("wlXXXXX_")];
#endif

    	/* for last byte of all bands */
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		if (dpsr_mode()
#ifdef RTCONFIG_DPSTA
			|| dpsta_mode()
#endif
		) {
			snprintf(wlPrefix, sizeof(wlPrefix), "wl%d.1_", unit);
			strlcpy(ifname, nvram_safe_get(strcat_r(wlPrefix, "ifname", tmp)), sizeof(ifname));
		}
		else
#endif
		{
			strlcpy(ifname, word, sizeof(ifname));
		}
		if ((p = get_hwaddr(ifname))) {
			ether_atoe(p, eabuf);
			if (nband == 2)
				lastByte[LAST_BYTE_2G] = eabuf[5];
			else if (nband == 1) {
				if (unit == LAST_BYTE_5G)
					lastByte[LAST_BYTE_5G] = eabuf[5];
				else if (unit == LAST_BYTE_5G1)
					lastByte[LAST_BYTE_5G1] = eabuf[5];
			}
			else if (nband == 4)
				lastByte[LAST_BYTE_6G] = eabuf[5];
			free(p);
			p = NULL;
		}

		unit++;
	}

	for (i = 0; i < sizeof(lastByte); i++) {
		if (i == 0)
			snprintf(buf, sizeof(buf), "%02X", lastByte[i]);
		else
			snprintf(buf, sizeof(buf), ",%02X", lastByte[i]);
		strlcat(lastByteStr, buf, sizeof(lastByteStr));
	}

	amas_utils_set_debug(1);
	ret =  amas_set_wifi_lastbyte((unsigned char *)lastByteStr);
	DBG_INFO("lldpd set wifi_lastbyte(%s) result(%d)", lastByteStr, ret);
}
#endif

#ifdef PRELINK
void update_lldp_hash_bundle_key()
{
	int ret = 0, reset = 0;

	if (nvram_get("amas_hashbdlkey") == NULL || strlen(nvram_safe_get("amas_hashbdlkey")) == 0)
		reset = 1;

	DBG_INFO("reset (%d)", reset);

	amas_utils_set_debug(1);
	ret = amas_set_hash_bundle_key(reset);
	DBG_INFO("lldp result(%d)", ret);
}

int check_hash_bundle_key_by_prefix(char *prefix)
{
	int ret = -1, result = 0;
	char tmp[64];
	char *ssid = NULL, *psk = NULL;
	char wl_prefix[] = "wlXXXXXXXXXX_";
	int total_band = num_of_wl_if();
#ifdef MSSID_PRELINK
	int mssid_subunit = nvram_get_int("plk_cap_subunit");
#endif

	snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", total_band - 1);
	if (nvram_match(strcat_r(wl_prefix, "radio", tmp), "0") || nvram_match(strcat_r(wl_prefix, "bss_enabled", tmp), "0")) {
		DBG_INFO("wl%d radio/bss_enabled is off", total_band - 1);
		return 0;
	}

#ifdef MSSID_PRELINK
	if (nvram_get_int("re_mode") == 1)
		mssid_subunit = nvram_get_int("plk_re_subunit");

	snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.%d_", total_band - 1, mssid_subunit);
	if (nvram_match(strcat_r(wl_prefix, "bss_enabled", tmp), "0")) {
		DBG_INFO("wl%d.%d bss_enabled is off", total_band - 1, mssid_subunit);
		return 0;
	}
#endif

	ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));
	psk = nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp));

	amas_utils_set_debug(1);
	if (amas_verify_default_backhaul_security(ssid, psk, &result) == AMAS_RESULT_SUCCESS) {
		DBG_INFO("result (%d)", result);
		ret = result;
	}
	else
		ret = -1;

	DBG_INFO("ret (%d)", ret);

	return ret;
}

int check_default_hash_bundle_key()
{
	int ret = 0;
	char prefix[] = "wlXXXXXXXXXX_";
	int total_band = num_of_wl_if();
#ifdef MSSID_PRELINK
	int mssid_subunit = nvram_get_int("plk_cap_subunit");

	DBG_INFO("check on mssid prelink");
	if (nvram_get_int("re_mode") == 1)
		mssid_subunit = nvram_get_int("plk_re_subunit");

	snprintf(prefix, sizeof(prefix), "wl%d.%d_", total_band - 1, mssid_subunit);
#else
	/* check for prelink on main */
	DBG_INFO("check on prelink");
	if (nvram_get_int("re_mode") == 1)
		snprintf(prefix, sizeof(prefix), "wl%d.1_", total_band - 1);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", total_band - 1);
#endif

	ret = check_hash_bundle_key_by_prefix(prefix);

	return ret;
}

unsigned char *get_prelink_key()
{
	unsigned char *key = NULL;
	char prelink_ssid[33], prelink_psk[33];
	int i = 0;

	if ((key = (unsigned char *)malloc(KEY_LENGTH)) == NULL) {
		DBG_ERR("memory allocate failed");
		goto err;
	}

	if (amas_gen_default_backhaul_security(prelink_ssid, sizeof(prelink_ssid), prelink_psk, sizeof(prelink_psk)) != AMAS_RESULT_SUCCESS) {
		DBG_ERR("get prelink key failed");
		free(key);
		key = NULL;
		goto err;
	}

	DBG_INFO("keyStr(%s)", prelink_psk);

	memset(key, 0, KEY_LENGTH);
	strlcpy(key, prelink_psk, KEY_LENGTH);

	/* padding */
	if (strlen(prelink_psk) != KEY_LENGTH) {
		for (i = strlen(prelink_psk); i < KEY_LENGTH; i++)
			key[i] = '0';
	}
#if 0
	for (i = 0; i < KEY_LENGTH; i++)
		DBG_PRINTF("%02X ", key[i]);
	DBG_PRINTF("\n");
#endif

err:

	return key;
}

void regen_hash_bundle_key()
{
	unsigned char bundleKeyHex[HASH_BUNDLE_KEY_HEX_LEN] = {0};
	char bundleKeyStr[HASH_BUNDLE_KEY_STR_LEN] = {0};
	int ret = 0;

	if (!(nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey")))) {
		DBG_ERR("no bundle key");
		return;
	}

	ret = check_default_hash_bundle_key();

	if (ret == 1) {
		if (nvram_get("amas_hashbdlkey") == NULL || strlen(nvram_safe_get("amas_hashbdlkey")) == 0) {
			/* re-gen hash bundle key */
			if (amas_gen_hash_bundle_key(&bundleKeyHex[0]) == AMAS_RESULT_SUCCESS) {
				memset(bundleKeyStr, 0, sizeof(bundleKeyStr));
				hex2str(bundleKeyHex, &bundleKeyStr[0], sizeof(bundleKeyHex));
				DBG_INFO("re-gen hash bundle key (%s)", bundleKeyStr);
				nvram_set("amas_hashbdlkey", bundleKeyStr);
			}
		}
		else
			DBG_INFO("do nothing, keep hash bundle key");
	}
	else if (ret == -1)
	{
		DBG_INFO("fail to check default hash bundle key, do nothing");
	}
	else
	{
		if (nvram_get("amas_hashbdlkey") || strlen(nvram_safe_get("amas_hashbdlkey"))) {
			DBG_INFO("clean hash bundle key");
			nvram_unset("amas_hashbdlkey");
		}
	}
}

int verify_hash_bundle_key(char *key)
{
	int ret = 0;
	unsigned char bundleKeyHex[HASH_BUNDLE_KEY_HEX_LEN] = {0};

	if (!(nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey")))) {
		DBG_ERR("no bundle key");
		return 0;
	}

	if (strlen(key) == (HASH_BUNDLE_KEY_STR_LEN -1)) {
		str2hex(key, bundleKeyHex, strlen(key));
		if (amas_verify_hash_bundle_key(&bundleKeyHex[0], &ret) == AMAS_RESULT_SUCCESS && ret == 1)
			DBG_INFO("succes to verify hash bundle key");
		else
			DBG_INFO("fail to verify hash bundle key");
	}
	else
		DBG_ERR("the length of key (%d) is invalid", strlen(key), HASH_BUNDLE_KEY_HEX_LEN -1);

	return ret;
}
#endif

char *get_re_hwaddr()
{
	static char re_hwaddr[18];
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM)
	char *reMac = NULL, prefix[sizeof("wlXXXXX_")], tmp[32];
#endif

	memset(re_hwaddr, 0, sizeof(re_hwaddr));

#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM)
	if (nvram_get_int("sw_mode") == SW_MODE_REPEATER
		|| dpsr_mode()
#if defined(RTCONFIG_PROXYSTA) && defined(RTCONFIG_DPSTA)
		|| dpsta_mode()
#endif
	) {
		snprintf(prefix, sizeof(prefix), "wl%d.1_", WL_2G_BAND);
		reMac = get_hwaddr(nvram_safe_get(strcat_r(prefix, "ifname", tmp)));

		if (reMac) {
			snprintf(re_hwaddr, sizeof(re_hwaddr), "%s", reMac);
			free(reMac);
			reMac = NULL;
		}
	}
	else
#endif
	snprintf(re_hwaddr, sizeof(re_hwaddr), "%s", 
#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
			get_2g_hwaddr()
#else
			get_lan_hwaddr()
#endif
		);
	DBG_INFO("re_hwaddr(%s)", re_hwaddr);
	return re_hwaddr;
} /* End of get_re_hwaddr */

char *nvram_decrypt_get(const char *name)
{
#ifdef RTCONFIG_NVRAM_ENCRYPT
	struct nvram_tuple *t = NULL;
	static char decBuf[NVRAM_ENC_MAXLEN];

	memset(decBuf, 0, sizeof(decBuf));

	/* go through each nvram value */
	for (t = router_defaults; t->name; t++) {
		if (strcmp(name, t->name) == 0 && t->enc == CKN_ENC_SVR) {
			pw_dec(nvram_safe_get(name), decBuf, sizeof(decBuf), 1);
			break;
		}
	}

	return (strlen(decBuf) == 0 ? nvram_safe_get(name) : decBuf);
#else
	return nvram_safe_get(name);
#endif
}

void nvram_encrypt_set(const char *name, char *value)
{
#ifdef RTCONFIG_NVRAM_ENCRYPT
	struct nvram_tuple *t = NULL;
	char encBuf[NVRAM_ENC_MAXLEN] = {0};

	/* go through each nvram value */
	for (t = router_defaults; t->name; t++) {
		if (strcmp(name, t->name) == 0 && t->enc == CKN_ENC_SVR) {
			pw_enc(value, encBuf, 1);
			break;
		}
	}

	nvram_set(name, strlen(encBuf) == 0 ? value : encBuf);
#else
	nvram_set(name, value);
#endif
}

int wl_macfilter_is_allow_mode()
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	int ret = 0;
	char word[256], *next;
	int unit = 0;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);

		memset(prefix, 0, sizeof(prefix));
#ifdef RTCONFIG_AMAS
		if (nvram_get_int("re_mode") == 1)
			snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
		else
#endif
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);

		if (nvram_match(strcat_r(prefix, "macmode", tmp), "allow")) {
			ret = 1;
			break;
		}

		unit++;
	}

	DBG_INFO("allow mode (%d)", ret);

	return ret;
}

#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
void convert_smac_for_traffic(int band, unsigned char *smac)
{
	uint32 m, b;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	/* set local address */
	smac[0] |= 2;

	snprintf(prefix, sizeof(prefix), "wl%d_", band);

	if (nvram_get_int(strcat_r(prefix, "psr_mrpt", tmp))) {
		/* Right rotate the octets[1:3] of the mac address. This will make
		  * sure we generate an unique fixed alias for each mac address. If two
		  * client mac addresses have the same octets[1:3] then we will have
		  * a collision. If this happens then generate a random number for the
		  * mac address.
		*/

		m = smac[1] << 16 | smac[2] << 8 | smac[3];

		b = m & 1;
		m >>= 1;
		m |= (b << 23);

		smac[1] = m >> 16;
		smac[2] = (m >> 8) & 0xff;
		smac[3] = m & 0xff;
	}
}
#endif

int get_re_unique_mac(unsigned char *msg, char *mac, int macLen)
{
	json_object *decryptedRoot = json_tokener_parse((char *)msg);
	json_object *reMacObj = NULL;
	int ret = 0;

	if (mac == NULL)
		goto err;

	memset(mac, 0, macLen);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		goto err;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_NEW_RE_MAC, &reMacObj);

	if (reMacObj == NULL) {
		DBG_ERR("reMacObj is null");
		goto err;
	}

	snprintf(mac, macLen, "%s", json_object_get_string(reMacObj));
	ret  = strlen(mac);

err:

	json_object_put(decryptedRoot);

	return ret;
}

int get_join_unique_mac(unsigned char *msg, char *mac, int macLen)
{
	json_object *decryptedRoot = json_tokener_parse((char *)msg);
	json_object *reMacObj = NULL;
	int ret = 0;

	if (mac == NULL)
		goto err;

	memset(mac, 0, macLen);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		goto err;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &reMacObj);

	if (reMacObj == NULL) {
		DBG_ERR("reMacObj is null");
		goto err;
	}

	snprintf(mac, macLen, "%s", json_object_get_string(reMacObj));
	ret  = strlen(mac);

err:

	json_object_put(decryptedRoot);

	return ret;
}

#ifdef RTCONFIG_DWB
char *get_dwb_bssid(int bandnum, int unit, int subunit)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	static char bssid_str[sizeof("00:00:00:00:00:00XXX")];
	char *ifname = NULL;
	char *pBssid = NULL;

	if (unit >= 0) {
		memset(prefix, 0, sizeof(prefix));
		if (bandnum == 3 || subunit == -1) {
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
			if (dpsr_mode()
#ifdef RTCONFIG_DPSTA
				|| dpsta_mode()
#endif
			)
				snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
			else
#endif
				snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		}
		else
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);

		ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
	}
	else
	{
		DBG_ERR("unit is invalid");
		return NULL;
	}

	pBssid = get_hwaddr(ifname);
	if (pBssid) {
		memset(bssid_str, 0, sizeof(bssid_str));
		snprintf(bssid_str, sizeof(bssid_str), "%s", pBssid);
		free(pBssid);
		pBssid= NULL;
	}
	else
		return NULL;

	return bssid_str;
}
#endif

int read_tcp_message(int sock, void *pBuf, int bufLen)
{
	int nleft, nread, tlvHdrSize = 0, len = 0, ret = 0;
	TLV_Header *tlv = NULL;

	nleft = bufLen;
	tlv = pBuf;
	tlvHdrSize = sizeof(TLV_Header);

	while (nleft > 0) {
		if ( (nread = read(sock, pBuf, nleft)) < 0) {
			if (errno == EINTR) {
				nread = 0;  /* and call read() again */
				DBG_ERR("errno == EINTR");
			}
			else if (errno == EAGAIN) {
				DBG_ERR("errno == EAGAIN, continue");
			}
			else {
				DBG_ERR("Failed to socket read(%d)!", errno);
				break;
			}
		} else if (nread == 0) {
			DBG_ERR("EOF");
			if (len >= (ntohl(tlv->len) + tlvHdrSize)) {
				DBG_INFO("data received, total len(%d), received len(%d)",
					(ntohl(tlv->len) + tlvHdrSize), len);
				ret = len;
			}
			break;    /* EOF */
		}
		nleft -= nread;
		pBuf += nread;
		len += nread;

		DBG_INFO("total len(%d), received len(%d)", (ntohl(tlv->len) + tlvHdrSize), len);
		if ((ntohl(tlv->type) == REQ_GKEY ||
			ntohl(tlv->type) == REQ_GREKEY ||
			ntohl(tlv->type) == REQ_SREKEY ||
			ntohl(tlv->type) == REQ_COST ||
			ntohl(tlv->type) == REQ_LEVEL) &&
			len == tlvHdrSize)
		{
			DBG_INFO("match request type (%d), received len(%d)", ntohl(tlv->type), len);
			ret = len;
			break;
		}
		else if (len >= (ntohl(tlv->len) + tlvHdrSize)) {
			DBG_INFO("data received, total len(%d), received len(%d)",
				(ntohl(tlv->len) + tlvHdrSize), len);
			ret = len;
			break;
		}
	}

	if (len == 0) {
		DBG_ERR("Failed to socket read()!");
		ret = -1;
	}

	return ret;
}

int get_type_by_ifname(char *ifname)
{
	int type = ETH_TYPE_NONE, found_index = -1, i = 0;
	char word[32], *next;
	char eth_ifnames[128] = {0}, amas_ethif_type[64] = {0};

	strlcpy(eth_ifnames, nvram_safe_get("eth_ifnames"), sizeof(eth_ifnames));
	strlcpy(amas_ethif_type, nvram_safe_get("amas_ethif_type"), sizeof(amas_ethif_type));

	foreach(word, eth_ifnames, next) {
		if (strcasecmp(ifname, word) == 0) {
			found_index = i;
			break;
		}
		i++;
	}

	if (found_index >= 0) {
		i = 0;
		foreach(word, amas_ethif_type, next) {
			if (i == found_index) {
				type = atoi(word);
				break;
			}
			i++;
		}
	}

	return type;
}

int get_wired_port_status(json_object *wired_port_status)
{
#if defined(RTCONFIG_BHCOST_OPT)
	int amas_path_stat = nvram_get_int("amas_path_stat");
	char amas_ifname[16], link_rate[8];
	unsigned int link_rate_int = 0;

	strlcpy(amas_ifname, nvram_safe_get("amas_ifname"), sizeof(amas_ifname));
#else
	FILE *fp;
	char line[128], *ptr, *item, *port, *speed, buf[128], portStatus[16];
#ifdef RTCONFIG_BROOP
        char *brif = nvram_safe_get("lan_ifname");
        char *ethif = nvram_safe_get("eth_ifnames");
#endif
#endif	/* RTCONFIG_BHCOST_OPT && RTCONFIG_AMAS_ETHDETECT */
	char name[sizeof("WAN XXXXXXXXXX")];
	int wan_count = 0, update = 0;
	json_object *wan_port_obj = NULL, *port_entry_obj = NULL;

	if (wired_port_status == NULL){
		DBG_ERR("wired_port_status is NULL");
		return 0;
	}

#if defined(RTCONFIG_BHCOST_OPT)
	if (amas_path_stat == ETH && get_type_by_ifname(amas_ifname) != ETH_TYPE_PLC) {
		wan_port_obj = json_object_new_object();
		if (wan_port_obj == NULL) {
			DBG_ERR("wan_port_obj is NULL");
			return 0;
		}

		if ((port_entry_obj = json_object_new_object())) {
			snprintf(name, sizeof(name), "WAN %d", wan_count);
			memset(link_rate, 0, sizeof(link_rate));

			link_rate_int = get_uplinkports_linkrate(amas_ifname);
			DBG_INFO("link rate (%d)", link_rate_int);
			if (link_rate_int == 1000)	//1000Mbps
				link_rate[0] = 'G';
			else if (link_rate_int == 100 || link_rate_int == 10)	//10/100Mbps
				link_rate[0] = 'M';
			else if (link_rate_int == 10000)
				link_rate[0] = 'T';
			else if (link_rate_int == 5000)
				link_rate[0] = 'F';
			else if (link_rate_int == 2500)
				link_rate[0] = 'Q';
			else if (link_rate_int == 0)
				link_rate[0] = 'X';
			else
				DBG_INFO("link rate mismatch");
			json_object_object_add(port_entry_obj, CFG_STR_LINK_RATE, json_object_new_string(link_rate));
			json_object_object_add(wan_port_obj, name, port_entry_obj);
			wan_count++;
			update = 1;
		}
		else
		{
			json_object_put(wan_port_obj);
			DBG_ERR("wan_port_obj is NULL");
			return 0;
		}

		json_object_object_add(wired_port_status, CFG_STR_WAN_PORT_COUNT, json_object_new_int(wan_count));
		json_object_object_add(wired_port_status, CFG_STR_WAN_PORT, wan_port_obj);
	}
#else
#ifdef RTCONFIG_PTHSAFE_POPEN
	fp = PS_popen("ATE Get_WanLanStatus", "r");
#else
	fp = popen("ATE Get_WanLanStatus", "r");
#endif
	if (fp == NULL) {
		DBG_ERR("fp is NULL");
		return 0;
	}

	ptr = fgets(line, sizeof(line), fp);
#ifdef RTCONFIG_PTHSAFE_POPEN
	PS_pclose(fp);
#else
	pclose(fp);
#endif
	if (ptr == NULL){
		DBG_ERR("ptr is NULL");
		return 0;
	}
	ptr = strsep(&ptr, "\r\n");

	wan_port_obj = json_object_new_object();
	if (wan_port_obj == NULL) {
		DBG_ERR("wan_port_obj is NULL");
		return 0;
	}

	wan_count = 0;
	memset(buf, 0, sizeof(buf));
	while ((item = strsep(&ptr, ";")) != NULL) {
		if (vstrsep(item, "=", &port, &speed) < 2)
			continue;
#if defined(DSL_AC68U)
		if (port[0] == 'W') {
			continue;
		}
#endif

		memset(portStatus, 0, sizeof(portStatus));
		switch (*port++) {
		case 'W':
			snprintf(name, sizeof(name), "%s%s%s", "WAN", *port ? " " : "", port);
			if ((port_entry_obj = json_object_new_object())) {
				json_object_object_add(port_entry_obj, CFG_STR_LINK_RATE, json_object_new_string(speed));
				json_object_object_add(wan_port_obj, name, port_entry_obj);
				wan_count++;
#ifdef RTCONFIG_BROOP
				if (nvram_match("re_mode", "1") && is_bridged(brif, ethif) && (*nvram_safe_get("amas_ifname") && !strstr(ethif, nvram_safe_get("amas_ifname"))))
					snprintf(portStatus, sizeof(portStatus), "W%s=X;", port);
				else
#endif
				snprintf(portStatus, sizeof(portStatus), "W%s=%s;", port, speed);
				strlcat(buf, portStatus, sizeof(buf));
			}
			break;
		default:
			continue;
		}
	}

	json_object_object_add(wired_port_status, CFG_STR_WAN_PORT_COUNT, json_object_new_int(wan_count));
	json_object_object_add(wired_port_status, CFG_STR_WAN_PORT, wan_port_obj);

	if (strcmp(oldWiredPortStatus, buf) != 0) {
		DBG_INFO("wired port status updated (%s)", buf);
		strlcpy(oldWiredPortStatus, buf, sizeof(oldWiredPortStatus));
		update = 1;
	}
#endif	/* RTCONFIG_BHCOST_OPT */

	return update;
}

#ifdef PLC_STATUS
int get_plc_status(json_object *plc_status)
{
	int ret = 0;

#if defined(RTCONFIG_BHCOST_OPT)
	unsigned int link_rate = 0;
	char amas_ifname[16], mode[8] = {0};
	int amas_path_stat = nvram_get_int("amas_path_stat");

	strlcpy(amas_ifname, nvram_safe_get("amas_ifname"), sizeof(amas_ifname));

	if (plc_status == NULL){
		DBG_ERR("plc_status is NULL");
		return 0;
	}

	if (amas_path_stat == ETH && get_type_by_ifname(amas_ifname) == ETH_TYPE_PLC) {
		link_rate = get_uplinkports_linkrate(amas_ifname);
		DBG_INFO("link rate (%d)", link_rate);
		if (nvram_get_int("autodet_plc_rx_mimo") >= 1 || nvram_get_int("autodet_plc_tx_mimo") >= 1)
			strlcpy(mode, "MIMO", sizeof(mode));
		else
			strlcpy(mode, "SISO", sizeof(mode));

		if (strlen(mode))
			json_object_object_add(plc_status, CFG_STR_MODE, json_object_new_string(mode));

		json_object_object_add(plc_status, CFG_STR_LINK_RATE, json_object_new_int(link_rate));
		ret = 1;
	}
#endif

	return ret;
}
#endif	/* PLC_STATUS */

char *get_unique_mac()
{
#if defined(RTCONFIG_AMAS_UNIQUE_MAC)
	return get_label_mac();
#else
	return get_lan_hwaddr();
#endif
}

#if defined(RTCONFIG_AMAS_WGN)
int mapping_guest_unit(json_object *root, char *cap_ifname, int *wlunit, int *wlsubunit)
{
	json_object *cfgRoot = root;
	json_object *cfgGuestIfnamesObj = NULL;
	int unit = 0, subunit = 0, ret = 0;
#ifdef RTCONFIG_BANDINDEX_NEW
	int band_type = 0;
#endif
	int unit2 = -1, subunit2 = -1;
	int is_find = 0, cap_guest_ifidx = 0, re_guest_ifidx = 0;
	char *s = NULL, word[64], *next = NULL, guest_ifnames[512];
	char cap_gn[10];

	if (wlunit)
		*wlunit = -1;

	if (wlsubunit)
		*wlsubunit = -1;

	if (!cfgRoot || !cap_ifname)
		return 0;

	unit = subunit = -1;
	memset(cap_gn,0,sizeof(cap_gn));
#if defined(RTCONFIG_QCA)
 	if (get_wlif_unit(cap_ifname, &unit, &subunit) < 0)
		return 0;
#else
	if (get_ifname_unit(cap_ifname, &unit, &subunit) < 0)
		return 0;
#endif
#if defined(RTCONFIG_QCA)
	if(subunit>1)
		snprintf(cap_gn,sizeof(cap_gn),"wl%d.%d",unit,subunit-1);
#else
    if(subunit>0)
        snprintf(cap_gn,sizeof(cap_gn),"wl%d.%d",unit,subunit);
#endif	

#ifdef RTCONFIG_BANDINDEX_NEW

	band_type = wgn_get_band_by_unit(unit);
	switch (band_type) { 
		case WGN_WL_BAND_2G:
			json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_2G, &cfgGuestIfnamesObj);
			break;
		case WGN_WL_BAND_5G:
			json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_5G, &cfgGuestIfnamesObj);
			break;
		case WGN_WL_BAND_5GH:
			json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_5GH, &cfgGuestIfnamesObj);
			break;
		case WGN_WL_BAND_6G:
			json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_6G, &cfgGuestIfnamesObj);
			break;
		default:
			cfgGuestIfnamesObj = NULL;
			break;
	}

#else	// RTCONFIG_BANDINDEX_NEW
	if (unit == 0)
		json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_2G, &cfgGuestIfnamesObj);
	else if (unit == 1)
		json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_5G, &cfgGuestIfnamesObj);
	else if (unit == 2)
		json_object_object_get_ex(cfgRoot, CFG_STR_GUEST_IFNAMES_5GH, &cfgGuestIfnamesObj);
	else
		cfgGuestIfnamesObj = NULL;
#endif	// RTCONFIG_BANDINDEX_NEW
	if (cfgGuestIfnamesObj == NULL) 
		return 0;

	is_find = cap_guest_ifidx = 0;
	if ((s = json_object_get_string(cfgGuestIfnamesObj)))
	{
		foreach(word, s, next)
		{
			cap_guest_ifidx++;
			if (strcmp(cap_gn, word) == 0)
			{
				is_find = 1;
				break;
			}
		}
	}

	if (is_find)
	{
		is_find = re_guest_ifidx = 0;
		memset(guest_ifnames, 0, sizeof(guest_ifnames));
#ifdef RTCONFIG_BANDINDEX_NEW
		if (wgn_guest_ifnames(wgn_get_band_by_unit(band_type), 0, guest_ifnames, sizeof(guest_ifnames)-1))
#else
		if (wgn_guest_ifnames(unit, 0, guest_ifnames, sizeof(guest_ifnames)-1))
#endif
		{
			foreach(word, guest_ifnames, next)
			{
				re_guest_ifidx++;
				if (cap_guest_ifidx == re_guest_ifidx)
				{
					is_find = 1;
					break;
				}
			}
		}

		if (is_find)
		{
			unit2 = subunit2 = -1;
			sscanf(word, "wl%d.%d_%*s", &unit2, &subunit2);
			if (unit2 > -1 && subunit2 > 0)
			{
				if (wlunit) *wlunit = unit2;
				if (wlsubunit) *wlsubunit = subunit2;
				ret = 1;
			}
		}								
	}

	return ret;
}

int check_wl_guest_bw_enable()
{
    char wl[128], wlv[128], tmp[128], *next, *next2;
    char prefix[32];
    int  i = 0;

    foreach(wl, nvram_safe_get("wl_ifnames"), next) {
        SKIP_ABSENT_BAND_AND_INC_UNIT(i);
        snprintf(prefix, sizeof(prefix), "wl%d_", i);
        foreach(wlv, nvram_safe_get(strcat_r(prefix, "vifnames", tmp)), next2) {

            if ( nvram_get_int(strcat_r(wlv, "_bss_enabled", tmp)) &&
                 nvram_get_int(strcat_r(wlv, "_bw_enabled" , tmp))) {
                return 1;
            }
        }
        i++;
    }
    return 0;
}
#endif	// RTCONFIG_AMAS_WGN

int search_in_array_list(char *key, json_object *list, int list_count)
{
	int ret = 0, i = 0;
	json_object *entry = NULL;

	if (list == NULL || !json_object_is_type(list, json_type_array) || list_count <= 0)
		return -1;

	for (i = 0; i < list_count; i++) {
		entry = json_object_array_get_idx(list, i);
		if (entry && strcmp(json_object_get_string(entry), key) == 0) {
			ret = 1;
			break;
		}
	}

	return ret;
}

void  add_all_to_array_list(json_object *input, json_object *list)
{
	int i = 0, input_len = 0;
	json_object *entry = NULL;

	if (input == NULL || list == NULL || !json_object_is_type(input, json_type_array) || !json_object_is_type(list, json_type_array))
			return;

	input_len = json_object_array_length(input);
	for (i = 0; i < input_len; i++) {
		entry = json_object_array_get_idx(input, i);
		json_object_array_add(list, json_object_new_string(json_object_get_string(entry)));
	}
}

void set_channel_sync_status(int unit, int status)
{
	char wl_chsync[] = "wlXXXX_chsync";

	snprintf(wl_chsync, sizeof(wl_chsync), "wl%d_chsync", unit);
	if (nvram_get_int(wl_chsync) != status)
		nvram_set_int(wl_chsync, status);
}

int check_radio_status_by_unit(int unit)
{
	char prefix[sizeof("wlXXXX_")], tmp[32];
	int ret = 0;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ret = nvram_get_int(strcat_r(prefix, "radio", tmp));

	return ret;
}

char *convert_misc_info_to_json_str(char *miscInfo)
{
	unsigned int len = 0, i = 0, offset = 0, hexLen = 0, first = 1, index = 0, miscInfoLen = 0;
	unsigned char hexMiscInfo[128];
	static char resBuf[256];
	char value[64], ivBuf[128];

	memset(resBuf, 0, sizeof(resBuf));

	if (miscInfo && strlen(miscInfo)) {
		miscInfoLen = strlen(miscInfo);
		if (str2hex(miscInfo, hexMiscInfo, miscInfoLen)) {
			hexLen = miscInfoLen / 2;

			if (hexLen > 0) {
				strlcat(resBuf, "{", sizeof(resBuf));
				for (i = 0; i < hexLen; i+=offset) {
					index = hexMiscInfo[i];
					len = hexMiscInfo[i + 1];
					memcpy(value,  (char *)&hexMiscInfo[i + 2], len);
					value[len] = '\0';
					offset = len + 2;
					DBG_INFO("index (%d), len (%d), offset (%d), value (%s)\n", index, len, offset, value);
					if (index > 0 && strlen(value)) {
						if (first)
							first = 0;
						else
							strlcat(resBuf, ",", sizeof(resBuf));

						snprintf(ivBuf, sizeof(ivBuf), "\"%d\":\"%s\"", index, value);
						strlcat(resBuf, ivBuf, sizeof(resBuf));
					}
				}
				strlcat(resBuf, "}", sizeof(resBuf));
			}
		}
		else
		{
			strlcpy(resBuf, "{}", sizeof(resBuf));
		}
	}
	else
	{
		strlcpy(resBuf, "{}", sizeof(resBuf));
	}

	return resBuf;
}

char *get_fh_ap_ifname_by_unit(int unit)
{
	char prefix[sizeof("wlXXXXX_")], tmp[32];
	static char ifname[16];
	int re_mode = nvram_get_int("re_mode");
#if defined(RTCONFIG_DWB) && defined(RTCONFIG_FRONTHAUL_DWB)
	int dwb_mode = nvram_get_int("dwb_mode");
	int dwb_band = nvram_get_int("dwb_band");
	int fh_ap_enabled = nvram_get_int("fh_ap_enabled");
	int fh_ap_subunit = nvram_get_int("fh_cap_mssid_subunit");
#endif

	memset(ifname, 0, sizeof(ifname));

#if defined(RTCONFIG_DWB) && defined(RTCONFIG_FRONTHAUL_DWB)
	if ((dwb_mode == DWB_ENABLED_FROM_CFG || dwb_mode == DWB_ENABLED_FROM_GUI) &&
		fh_ap_enabled > 0 && unit == dwb_band)
	{
		if (re_mode)
			fh_ap_subunit = nvram_get_int("fh_re_mssid_subunit");

		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, fh_ap_subunit);
	}
	else
#endif
	{
		if (re_mode)
			snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
		else
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	}

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	return ifname;
}

char *get_fh_ap_ssid_by_unit(int unit)
{
	char prefix[sizeof("wlXXXXX_")], tmp[32];
	static char ssid[33];
	int re_mode = nvram_get_int("re_mode");
#if defined(RTCONFIG_DWB) && defined(RTCONFIG_FRONTHAUL_DWB)
	int dwb_band = nvram_get_int("dwb_band");
	int fh_ap_enabled = nvram_get_int("fh_ap_enabled");
	int fh_ap_subunit = nvram_get_int("fh_cap_mssid_subunit");
#endif

	memset(ssid, 0, sizeof(ssid));

#if defined(RTCONFIG_DWB) && defined(RTCONFIG_FRONTHAUL_DWB)
	if (fh_ap_enabled > 0 && unit == dwb_band) {
		if (re_mode)
			fh_ap_subunit = nvram_get_int("fh_re_mssid_subunit");

		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, fh_ap_subunit);
	}
	else
#endif
	{
		if (re_mode)
			snprintf(prefix, sizeof(prefix), "wl%d.1_", unit);
		else
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	}

	strlcpy(ssid, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), sizeof(ssid));

	return ssid;
}

int  check_band_unit(int bandtype)
{
	int nband=0, unit = 0;
	chmgmt_chconf_t cur_chconf;
	int num5g = num_of_5g_if();
	char wlIfnames[64] ,word[256], *next, tmp[64];
	char prefix[16] = {0};
	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			DBG_INFO("%s nband=%d", strcat_r(prefix, "nband", tmp),nband);
			if (nband == 2 && bandtype==0) {
				return unit;	
			}
			else if (nband == 1){
				DBG_INFO("num5g(%d)", num5g);
				if(num5g>1){
					 if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
					 	DBG_INFO("cur_chconf(%d)   THRESHOLD_5G_LOW_HIGH(%d)  bandtype(%d) unit(%d)", CHCONF_CH(cur_chconf) , THRESHOLD_5G_LOW_HIGH, bandtype,  unit);
						if (CHCONF_CH(cur_chconf) >= THRESHOLD_5G_LOW_HIGH && bandtype==3) {	/* check 5g high band */
							return unit;
						}
						else if (CHCONF_CH(cur_chconf) < THRESHOLD_5G_LOW_HIGH && bandtype==2){
							return unit;
						}
					}
					else 
						return unit;
				}
				else{
					if(bandtype==1)
						return unit;
				}

			}
			else if (nband == 4 && bandtype==6) {
				return unit;	
			}
			unit++;
	}
	return unit;

}

void check_band_type()
{
	int dut_bandnum=0, nband=0, unit = 0, num5g = 0;
	int have_2G=0, have_5G_1=0, have_5G_2=0, have_6G=0;
	char wlIfnames[64] ,word[256], *next, tmp[64];
	char prefix[16] = {0};
	dut_bandnum=num_of_wl_if();
	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			if (nband == 2) {
				have_2G=1;	
			}
			else if (nband == 1){
				num5g++;
				if (num5g == 1) {
					have_5G_1=1;
				}
				else if (num5g == 2)
				{
					have_5G_2=1;
				}

			}
			else if (nband == 4) {
				have_6G=1;	
			}
			unit++;
	}
	if(dut_bandnum==1){
		if(have_2G==1 && !have_5G_1 && !have_5G_2 && !have_6G){
			nvram_set_int("band_type", 0);
		}
	}
	else if(dut_bandnum==2){
		if(have_2G==1 && (have_5G_1==1 || have_5G_2==1) && !have_6G){
			nvram_set_int("band_type", 1);
		}
	}
	else if(dut_bandnum==3){
		if(have_5G_1==1 && have_5G_2==1){
			nvram_set_int("band_type", 2);
		}
		else if((have_5G_1==1 || have_5G_2==1 )&& have_6G==1){
			nvram_set_int("band_type", 3);
		}
	}else if(dut_bandnum==4){
		if(have_2G==1 && have_5G_1==1  && have_5G_2==1 && have_6G==1){
			nvram_set_int("band_type", 4);
		}
	}
	//DBG_INFO(" dut_bandnum=%d have_6G=%d band_type=%d ",dut_bandnum,have_6G,nvram_get_int("band_type"));
}

char *get_rebandtype_chanspc_by_unit (char *mac, int unit ,int reBandNum , char *rebandtype, int rebandtypeLen)
{
	json_object *fileRoot = NULL, *macObj = NULL;
	int i=0;
	if (!mac || strlen(mac) ==0) {
		DBG_ERR("macis NULL");
		return NULL;
	}
	if(unit>reBandNum-1){
		return NULL;
	}
	pthread_mutex_lock(&chanspecLock);
	//static char rebandtype[5];
	//DBG_INFO(" !!!!!!!! mac=%s unit=%d !!!!!",mac,unit);
	fileRoot = json_object_from_file("/tmp/chanspec_all.json");
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return NULL;
	}

	pthread_mutex_unlock(&chanspecLock);

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		i=0;
		json_object_object_foreach(macObj, bandKey, bandVal) {
			if (i==unit){
				//memset(rebandtype, 0, sizeof(rebandtype));
				//snprintf(rebandtype, sizeof(rebandtype), "%s", bandKey);
				strlcpy(rebandtype, bandKey, rebandtypeLen);
				json_object_put(fileRoot);
				return rebandtype;
			}else{
				i++;
			}	
		}
	}

	json_object_put(fileRoot);

	return NULL;
}


int get_unit_chanspc_by_bandtype (char *mac, char *bandtype)
{
	json_object *fileRoot = NULL, *macObj = NULL;
	int i=0;
	if (!mac || strlen(mac) ==0) {
		DBG_ERR("macis NULL");
		return -1;
	}

	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file("/tmp/chanspec_all.json");
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return -1;
	}

	pthread_mutex_unlock(&chanspecLock);

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		i=0;
		json_object_object_foreach(macObj, bandKey, bandVal) {
			if (strcmp(bandKey, bandtype) == 0){
				json_object_put(fileRoot);
				return i;
			}else{
				i++;
			}	
		}
	}

	json_object_put(fileRoot);

	return -1;
}


char *cap_get_re_final_paramname(char *mac, char *input_param,int reBandNum , char *finalparamname, int finalparamnamelen)
{
	char cap_band_type[5];
	int re_unit=-1;
	char prefix[32] = {0}, suffix[32] = {0};
	int unit = -1,  subunit = -1 ;
	
	memset(cap_band_type, 0, sizeof(cap_band_type));
	get_capbandtype_by_unit(input_param, cap_band_type, sizeof(cap_band_type));
	if(cap_band_type)
	{
		
		memset(prefix, 0, sizeof(prefix));
		sscanf(input_param, "%[^_]_%*s", prefix);
		if (!strstr(prefix, ".")){
			sscanf(prefix, "wl%d_%*s", &unit);
			memset(suffix, 0, sizeof(suffix));
			sscanf(input_param, "wl%*d_%s", suffix);
			
		}
		else if (strstr(prefix, ".")){
			sscanf(input_param, "wl%d.%d_%*s", &unit, &subunit);
			memset(suffix, 0, sizeof(suffix));
			sscanf(input_param, "wl%*d.%*d_%s", suffix);
		}
		re_unit = get_unit_chanspc_by_bandtype(mac,cap_band_type);
		if(re_unit != -1)
		{	
			if(subunit<0)
				snprintf(finalparamname, 256, "wl%d_%s", re_unit,suffix);
			else
				snprintf(finalparamname, 256, "wl%d.%d_%s", re_unit,subunit,suffix);
		}
		else{
			if(!strcmp(cap_band_type,"6G"))
			{
				if(subunit<0)
					snprintf(finalparamname, 256, "wl%d_%s", unit,suffix);
				else
					snprintf(finalparamname, 256, "wl%d.%d_%s", unit,subunit,suffix);
				
			}
			else if(!strcmp(cap_band_type,"5G1"))
			{
				if(subunit<0)
					snprintf(finalparamname, 256, "wl%d_%s", unit,suffix);
				else
					snprintf(finalparamname, 256, "wl%d.%d_%s", unit,subunit,suffix);
				
			}
		
		}
											
	}
	else{
		snprintf(finalparamname, 256, "%s", input_param);

	}
	return finalparamname;
}



char *cap_get_final_paramname(char *mac, char *input_param,int reBandNum , char *finalparamname, int finalparamnamelen)
{
#ifdef RTCONFIG_BANDINDEX_NEW
	char prefix[32] = {0}, tmp[32]= {0}, suffix[32] = {0}, fin_prefix[32] = {0};
	char wl_prefix[sizeof("wlXXXX_")];
	//static char output_param[32];
	int unit = -1,  subunit = -1 , fin_unit=-1;
	int nband= 0;
	//memset(output_param, 0, sizeof(output_param));
	char word[64], *next = NULL,  wl_ifnames[64];
	int j=0;
	int num5g = num_of_5g_if();
	typedef uint16_t cap_chconf_t;
	cap_chconf_t cur_chconf;
	int match_6G=0;
	char rebandtype[5];
	
	if (strncmp(input_param, "wl", 2) != 0) {
		//strlcpy(output_param, input_param, sizeof(output_param));
		return input_param;
	}
	else{
		
		
		memset(prefix, 0, sizeof(prefix));
		sscanf(input_param, "%[^_]_%*s", prefix);
		if (!strstr(prefix, ".")){
			sscanf(prefix, "wl%d_%*s", &unit);
			memset(suffix, 0, sizeof(suffix));
			sscanf(input_param, "wl%*d_%s", suffix);
			
		}
		else if (strstr(prefix, ".")){
			sscanf(input_param, "wl%d.%d_%*s", &unit, &subunit);
			memset(suffix, 0, sizeof(suffix));
			sscanf(input_param, "wl%*d.%*d_%s", suffix);
		}
		//DBG_INFO("!!!!!! prefix = %s suffix=%s  unit=%d subunit=%d !!!!!!",prefix,suffix,unit,subunit);
		memset(wl_prefix, 0, sizeof(wl_prefix));
		snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
		memset(rebandtype, 0, sizeof(rebandtype));
		if(get_rebandtype_chanspc_by_unit(mac,unit,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
			if(!strcmp(rebandtype,"2G"))
			{
				//DBG_INFO("!!!!!! get_rebandtype_chanspc_by_unit = %s !!!!!!",get_rebandtype_chanspc_by_unit(mac,unit,reBandNum));
				strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
				foreach (word, wl_ifnames, next) {
					SKIP_ABSENT_BAND_AND_INC_UNIT(j);
					snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", j);
					//DBG_INFO(" wl_prefix=%s ",wl_prefix);
					nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
					if (nband == 2 ) {
						fin_unit=j;
						//DBG_INFO("!!!!!! nband = %d j=%d fin_unit=%d!!!!!!",nband , j,fin_unit);
						break;	
					}
					j++;
				}
			}
			else if(!strcmp(rebandtype,"6G"))
			{
				strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
				foreach (word, wl_ifnames, next) {
					SKIP_ABSENT_BAND_AND_INC_UNIT(j);
					snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", j);
					//DBG_INFO(" wl_prefix=%s ",wl_prefix);
					nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
					if (nband == 4 ) {
						match_6G=1;
						fin_unit=j;
						break;	
					}
					j++;
				}
				if(match_6G==0)
				{
					fin_unit=unit;
				}
			}
			else if(!strcmp(rebandtype,"5G"))
			{
				strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
				foreach (word, wl_ifnames, next) {
					SKIP_ABSENT_BAND_AND_INC_UNIT(j);
					snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", j);
					//DBG_INFO(" wl_prefix=%s ",wl_prefix);
					nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
					if (nband == 1 ) {
						if(num5g<2){
							fin_unit=j;
							break;	
						}
						else{
							if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
								//DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
								if (CHCONF_CH(cur_chconf) < THRESHOLD_5G_LOW_HIGH) {	/* check 5g low band */
									fin_unit=j;
									break;	
								}
							}
						
						}
					}
					j++;
				}
			}
			else if(!strcmp(rebandtype,"5G1"))
			{
				strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
				foreach (word, wl_ifnames, next) {
					SKIP_ABSENT_BAND_AND_INC_UNIT(j);
					snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", j);
					//DBG_INFO(" wl_prefix=%s ",wl_prefix);
					nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
					if (nband == 1 ) {
						if(num5g<2){
							fin_unit=j;
							break;	
						}
						else{
							if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
								//DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
								if (CHCONF_CH(cur_chconf) >= THRESHOLD_5G_LOW_HIGH) {	/* check 5g low band */
									fin_unit=j;
									break;	
								}
							}
						
						}
					}
					j++;
				}
			}
			else
			{
			fin_unit=unit;
			//DBG_INFO(" !!!!!!!! get_rebandtype_chanspc_by_unit!=NULL but not found type fin_unit %d unit %d!!!!!",fin_unit,unit);
			}
		}
		else
		{
			//DBG_INFO(" !!!!!!!! get_rebandtype_chanspc_by_unit==NULL !!!!!");
			fin_unit=unit;
		}

		memset(fin_prefix, 0, sizeof(fin_prefix));
		if(subunit<0){
			snprintf(fin_prefix, sizeof(fin_prefix), "wl%d_", fin_unit);
			//DBG_INFO("!!!!  fin_prefix (%s) !!!!!", fin_prefix);
		}else{
			
			snprintf(fin_prefix, sizeof(fin_prefix), "wl%d.%d_", fin_unit,subunit);
		}
		memset(tmp, 0, sizeof(tmp));
		//strlcpy(output_param, strcat_r(fin_prefix, suffix, tmp), sizeof(output_param));
		strlcpy(finalparamname, strcat_r(fin_prefix, suffix, tmp), finalparamnamelen);
		//DBG_INFO("!!!!  output_param (%s) !!!!!", output_param);
	}
	return finalparamname;
#else
	//static char output_param[32];
	//memset(output_param, 0, sizeof(output_param));
	//strlcpy(output_param, input_param, sizeof(output_param));
	//return output_param;
	return input_param;
#endif

}


int get_capbandtype_by_unit(char *input_param, char *rebandtype, int rebandtypelen)
{		
	char word[64], *next = NULL, tmp[64], wl_ifnames[64], wl_prefix[sizeof("wlXXXX_")];
	char prefix[32] = {0};
	chmgmt_chconf_t cur_chconf;
	int  nband = 0;
	int j=0;
	int num5g = num_of_5g_if();
	int unit = -1,  subunit = -1;
	memset(prefix, 0, sizeof(prefix));
	sscanf(input_param, "%[^_]_%*s", prefix);
	if (!strstr(prefix, ".")){
		sscanf(prefix, "wl%d_%*s", &unit);		
	}
	else if (strstr(prefix, ".")){
		sscanf(input_param, "wl%d.%d_%*s", &unit, &subunit);
	}
	memset(wl_prefix, 0, sizeof(wl_prefix));
	memset(tmp, 0, sizeof(tmp));
	snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
	nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));

	memset(wl_ifnames, 0, sizeof(wl_ifnames));
	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		if(j==unit){
			if(nband == 2){
					snprintf(rebandtype, rebandtypelen, "%s","2G");
			}
			else if (nband == 1 ) {	/* for 5g band */
					if (num5g == 1) {	/* one 5g band */
						snprintf(rebandtype, rebandtypelen, "%s","5G");
						break;
					}
					else if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
						DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
						if (CHCONF_CH(cur_chconf) >= THRESHOLD_5G_LOW_HIGH) {	/* check 5g high band */
							snprintf(rebandtype, rebandtypelen, "%s","5G1");
							break;
						}
						else{
							snprintf(rebandtype, rebandtypelen, "%s","5G");
							break;
						}
					}
			}
			else if(nband == 4){
				snprintf(rebandtype, rebandtypelen, "%s","6G");
				break;
			}
		}
		j++;
	}
	return 0;

}


int check_match_6G(char *mac)
{
	json_object *fileRoot = NULL, *macObj = NULL;
	int re_have_6G=0;
	if (!mac || strlen(mac) ==0) {
		DBG_ERR("macis NULL");
		return -2;
	}

	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file("/tmp/chanspec_all.json");
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return -2;
	}

	pthread_mutex_unlock(&chanspecLock);

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		json_object_object_foreach(macObj, bandKey, bandVal) {
			if (strcmp(bandKey, "6G") == 0){
				re_have_6G=1;
				break;
			}
		}
	}
	else{
		json_object_put(fileRoot);
		return -2;
	}
	if(re_have_6G>0){
		char prefix[16] = {0};
		int i = 0,nband= 0;
		char wlIfnames[64] ,word[256], *next, tmp[64];
		strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
		foreach (word, wlIfnames, next) {
				SKIP_ABSENT_BAND_AND_INC_UNIT(i);
				snprintf(prefix, sizeof(prefix), "wl%d_", i);
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				//DBG_INFO(" nband=%s ",prefix);
				if (nband == 4) {
					DBG_INFO("!Both cap and re have 6G");
					json_object_put(fileRoot);
					return 1;	
				}
				i++;
		}
		json_object_put(fileRoot);
		DBG_INFO("!Cap does not have 6G, re has 6G");
		return -1;
	}
	else if(re_have_6G==0){
		char prefix[16] = {0};
		int i = 0,nband= 0;
		char wlIfnames[64] ,word[256], *next, tmp[64];
		strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
		foreach (word, wlIfnames, next) {
				SKIP_ABSENT_BAND_AND_INC_UNIT(i);
				snprintf(prefix, sizeof(prefix), "wl%d_", i);
				nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
				//DBG_INFO(" nband=%s ",prefix);
				if (nband == 4) {
					DBG_INFO("cap  have 6G and re does not have 6G");
					json_object_put(fileRoot);
					return 2;	
				}
				i++;
		}
		DBG_INFO("!Both cap and re does not have 6G");
		json_object_put(fileRoot);
		return 0;
	}
}


int check_own_unit(int bandtype)
{
	chmgmt_chconf_t cur_chconf;
	char word[64], *next = NULL, tmp[64], wl_ifnames[64], wl_prefix[sizeof("wlXXXX_")];
	int unit = 0,  nband = 0 , ret =-1;
	int num5g = num_of_5g_if();
	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
		if((bandtype == 6 && nband==4) || (bandtype == 0 && nband==2)|| (bandtype == 1 && nband==1)){
			ret = unit;
			return ret;
		}
		else if(bandtype==2 && nband==1){
			if (num5g==1){
				ret = unit;
				return ret;
			} 
			else if(num5g==2){
				if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
					//DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
					if (CHCONF_CH(cur_chconf) < THRESHOLD_5G_LOW_HIGH) 
					{	/* check 5g low band */
						ret = unit;
						return ret;
					}
				}
			}
		}
		else if(bandtype==3 && nband==1){
			if (num5g==1){
				ret = unit;
				return ret;
			} 
			else if(num5g==2){
				if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
					//DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
					if (CHCONF_CH(cur_chconf) >= THRESHOLD_5G_LOW_HIGH) 
					{	/* check 5g high band */
						ret = unit;
						return ret;
							
					}
				}
			}
		}
		unit++;
	}
	return ret;
}

int check_mac_exist(char *mac)
{
	json_object *fileRoot = NULL, *macObj = NULL;
	if (!mac || strlen(mac) ==0) {
		DBG_ERR("macis NULL");
		return -1;
	}
	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file("/tmp/chanspec_all.json");
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return -1;
	}
	pthread_mutex_unlock(&chanspecLock);

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		json_object_put(fileRoot);
		return 1;
	}
	else{
		json_object_put(fileRoot);
		return -1;
	}

}
int Add_missing_parameter(json_object *outRoot, int private,char *mac,int reBandNum, int cfgband_Ver,json_object *cfgAllObj,json_object *fileRoot)
{
	if(check_mac_exist(mac)<0)
		return -1;
	int dut_bandnum=num_of_wl_if(), bandnum_diff=0;
	bandnum_diff= reBandNum-dut_bandnum;
	char wl_6G_prefix[sizeof("wlXXXX_")],wl_5GH_prefix[sizeof("wlXXXX_")];
	char output_param[32],input_param[32],output_guess_param[32],input_guess_param[32];
	char outAuth[16], tmp[64] = {0};
	char rebandtype[8];
	int num5g = num_of_5g_if();
	if(outRoot){
		//DBG_INFO("!!!!!!!!!! outRoot != NULL !!!!!!!!!");
	}else{
		//DBG_INFO("!!!!!!!!!! outRoot == NULL !!!!!!!!!");
		return -1;
	}
	if(bandnum_diff==2){
		if(check_match_6G(mac)==-2){
			return -1;
		}
		else if(check_match_6G(mac)==-1)
		{
			memset(wl_6G_prefix, 0, sizeof(wl_6G_prefix));
			snprintf(wl_6G_prefix, sizeof(wl_6G_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"6G"));
			
			struct wlsuffix_mapping_s *P = NULL;
			for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
			{
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "%s_%s", wl_6G_prefix,P->name);
				memset(input_param, 0, sizeof(input_param));
				snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj);
				if(needdelobj){
					json_object_object_del(outRoot, output_param);
				}
				if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
					if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
						json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
					}
					else{
						if(!strcmp(P->name,"ssid")){
							if (nvram_get_int("dwb_mode")){
								memset(tmp, 0, sizeof(tmp));
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
							}
							else{
								memset(tmp, 0, sizeof(tmp));
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
							}
						}
						else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
							
							}
						else
						{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
						}
					}
				}else{
				
					if(!strcmp(P->name,"ssid")){
							if (nvram_get_int("dwb_mode")){
								memset(tmp, 0, sizeof(tmp));
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
							}
							else{
								memset(tmp, 0, sizeof(tmp));
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
							}
						}
						else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
							
							}
						else
						{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
						}
				
				}
				
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "%s_%s", "wl3",P->name);
				memset(input_param, 0, sizeof(input_param));
				memset(rebandtype, 0, sizeof(rebandtype));

				if(get_rebandtype_chanspc_by_unit(mac,3,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
					if(!strcmp(rebandtype,"2G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
					}
					else if(!strcmp(rebandtype,"5G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
					}
					else if(!strcmp(rebandtype,"5G1"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(3),P->name);
					}
					else if(!strcmp(rebandtype,"6G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(6),P->name);
					}
					else{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
					}
					
				}
				else
				{
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
				}
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj1 = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj1);
				if(needdelobj1){		
						json_object_object_del(outRoot, output_param);
				}
				
				if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
						}
				}
				else{
					json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
				}
				
			}
		}
		struct wlsuffix_guess_mapping_s *P1 = NULL;
			for (P1 = &wlsuffix_guess_mapping_list[0]; P1->name != NULL; P1++)
			{
				memset(output_guess_param, 0, sizeof(output_guess_param));
				snprintf(output_guess_param, sizeof(output_guess_param), "%s_%s", "wl3.1",P1->name);
				memset(input_guess_param, 0, sizeof(input_guess_param));
				memset(rebandtype, 0, sizeof(rebandtype));

				if(get_rebandtype_chanspc_by_unit(mac,3,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
					if(!strcmp(rebandtype,"2G"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
					}
					else if(!strcmp(rebandtype,"5G"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(2),P1->name);
					}
					else if(!strcmp(rebandtype,"5G1"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(3),P1->name);
					}
					else if(!strcmp(rebandtype,"6G"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(6),P1->name);
					}
					else{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
					}
					
				}
				else
				{
					snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
				}
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj2 = NULL;
				json_object_object_get_ex(outRoot, output_guess_param, &needdelobj2);
				if(needdelobj2){		
						json_object_object_del(outRoot, output_guess_param);
				}
				if (strncmp(input_guess_param, "wl", 2) == 0 && strstr(input_guess_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_guess_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_guess_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
						}
				}
				else{
						json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
				
				}
				
			}
	
	}
	else if(bandnum_diff==1 && reBandNum==3){
		if(cfgband_Ver>1){
			if(check_match_6G(mac)==-2){
				return -1;
			}
			else if(check_match_6G(mac)==-1)
			{
				memset(wl_6G_prefix, 0, sizeof(wl_6G_prefix));
				snprintf(wl_6G_prefix, sizeof(wl_6G_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"6G"));
				struct wlsuffix_mapping_s *P = NULL;
				for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
				{
					memset(output_param, 0, sizeof(output_param));
					snprintf(output_param, sizeof(output_param), "%s_%s", wl_6G_prefix,P->name);
					memset(input_param, 0, sizeof(input_param));
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
					memset(outAuth, 0, sizeof(outAuth));
					json_object *needdelobj = NULL;
					json_object_object_get_ex(outRoot, output_param, &needdelobj);
					if(needdelobj){
						json_object_object_del(outRoot, output_param);
					}
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "1"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
					}
					else{
						if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
						}
						else if(!strcmp(P->name,"closed")){
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "1"));
							
						}
						else
						{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
						}
					
					
					}
				}
			}
			else{
				memset(wl_5GH_prefix, 0, sizeof(wl_5GH_prefix));
				snprintf(wl_5GH_prefix, sizeof(wl_5GH_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"5G1"));
				
				struct wlsuffix_mapping_s *P = NULL;
				for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
				{
					memset(output_param, 0, sizeof(output_param));
					snprintf(output_param, sizeof(output_param), "%s_%s", wl_5GH_prefix,P->name);
					memset(input_param, 0, sizeof(input_param));
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(1),P->name);
					memset(outAuth, 0, sizeof(outAuth));
					json_object *needdelobj = NULL;
					json_object_object_get_ex(outRoot, output_param, &needdelobj);
					if(needdelobj){
						json_object_object_del(outRoot, output_param);
					}
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "1"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
					}
					else{
						if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "1"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
					}
				}
			
			
			}
				memset(rebandtype, 0, sizeof(rebandtype));
				
				if(get_rebandtype_chanspc_by_unit(mac,2,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
					if(!strcmp(rebandtype,"2G"))
					{
						struct wlsuffix_mapping_s *P = NULL;
						for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
						{
							memset(output_param, 0, sizeof(output_param));
							snprintf(output_param, sizeof(output_param), "%s_%s", "wl2",P->name);
							memset(input_param, 0, sizeof(input_param));
							memset(rebandtype, 0, sizeof(rebandtype));

							snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
							
							memset(outAuth, 0, sizeof(outAuth));
							json_object *needdelobj1 = NULL;
							json_object_object_get_ex(outRoot, output_param, &needdelobj1);
							if(needdelobj1){
								json_object_object_del(outRoot, output_param);
							}
							if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
			#if defined(RTCONFIG_WIFI_SON)
									&& !nvram_match("wifison_ready", "1")
			#endif
								){
									if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
										json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
									}
									else{
										json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
									}
							}
							else{
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							
							}
						}
			
						struct wlsuffix_guess_mapping_s *P1 = NULL;
						for (P1 = &wlsuffix_guess_mapping_list[0]; P1->name != NULL; P1++)
						{
							memset(output_guess_param, 0, sizeof(output_guess_param));
							snprintf(output_guess_param, sizeof(output_guess_param), "%s_%s", "wl2.1",P1->name);
							memset(input_guess_param, 0, sizeof(input_guess_param));
							snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
							
							memset(outAuth, 0, sizeof(outAuth));
							json_object *needdelobj2 = NULL;
							json_object_object_get_ex(outRoot, output_guess_param, &needdelobj2);
							if(needdelobj2){		
									json_object_object_del(outRoot, output_guess_param);
							}
							if (strncmp(input_guess_param, "wl", 2) == 0 && strstr(input_guess_param, "auth_mode_x")
			#if defined(RTCONFIG_WIFI_SON)
									&& !nvram_match("wifison_ready", "1")
			#endif
								){
									if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_guess_param, outAuth, sizeof(outAuth))) {
										json_object_object_add(outRoot, output_guess_param, json_object_new_string(private ? "" : outAuth));
									}
									else{
										json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
									}
							}
							else{
									json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
							
							}		
							
						}
					}
				}
		}
	
	}
	else if(bandnum_diff==1 && reBandNum==4){
		if(check_match_6G(mac)==-2){
			return -1;
		}
		else if(check_match_6G(mac)==-1)
		{
			memset(wl_6G_prefix, 0, sizeof(wl_6G_prefix));
			snprintf(wl_6G_prefix, sizeof(wl_6G_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"6G"));
			
			struct wlsuffix_mapping_s *P = NULL;
			for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
			{
				
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "%s_%s", wl_6G_prefix,P->name);
				json_object_object_del(outRoot, output_param);
				memset(input_param, 0, sizeof(input_param));
				snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj);
				if(needdelobj){
					json_object_object_del(outRoot, output_param);
				}
				if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
										json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
								
								}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
				}
				else{
					if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
										json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
								
								}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
				
				}
				
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "%s_%s", "wl3",P->name);
				memset(input_param, 0, sizeof(input_param));
				memset(rebandtype, 0, sizeof(rebandtype));

				if(get_rebandtype_chanspc_by_unit(mac,3,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
					if(!strcmp(rebandtype,"2G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
					}
					else if(!strcmp(rebandtype,"5G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
					}
					else if(!strcmp(rebandtype,"5G1"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(3),P->name);
					}
					else if(!strcmp(rebandtype,"6G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(6),P->name);
					}
					else{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
					}
					
				}
				else
				{
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
				}
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj1 = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj1);
				if(needdelobj1){		
						json_object_object_del(outRoot, output_param);
				}
				
				if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
						}
				}
				else{
					json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
				}
			}
		}
		else if(check_match_6G(mac)==1){
			
			struct wlsuffix_mapping_s *P = NULL;
			for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
			{
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "%s_%s", "wl3",P->name);
				memset(input_param, 0, sizeof(input_param));
				memset(rebandtype, 0, sizeof(rebandtype));

				if(get_rebandtype_chanspc_by_unit(mac,3,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
					if(!strcmp(rebandtype,"2G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
					}
					else if(!strcmp(rebandtype,"5G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
					}
					else if(!strcmp(rebandtype,"5G1"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(3),P->name);
					}
					else if(!strcmp(rebandtype,"6G"))
					{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(6),P->name);
					}
					else{
						snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
					}
					
				}
				else
				{
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
				}
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj1 = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj1);
				if(needdelobj1){
					json_object_object_del(outRoot, output_param);
				}
				if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
						}
				}
				else{
						json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
				
				}
			}
		
		
		}
			struct wlsuffix_guess_mapping_s *P1 = NULL;
			for (P1 = &wlsuffix_guess_mapping_list[0]; P1->name != NULL; P1++)
			{
				memset(output_guess_param, 0, sizeof(output_guess_param));
				snprintf(output_guess_param, sizeof(output_guess_param), "%s_%s", "wl3.1",P1->name);
				memset(input_guess_param, 0, sizeof(input_guess_param));
				memset(rebandtype, 0, sizeof(rebandtype));

				if(get_rebandtype_chanspc_by_unit(mac,3,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
					if(!strcmp(rebandtype,"2G"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
					}
					else if(!strcmp(rebandtype,"5G"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(2),P1->name);
					}
					else if(!strcmp(rebandtype,"5G1"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(3),P1->name);
					}
					else if(!strcmp(rebandtype,"6G"))
					{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(6),P1->name);
					}
					else{
						snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
					}
					
				}
				else
				{
					snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
				}
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj2 = NULL;
				json_object_object_get_ex(outRoot, output_guess_param, &needdelobj2);
				if(needdelobj2){		
						json_object_object_del(outRoot, output_guess_param);
				}
				if (strncmp(input_guess_param, "wl", 2) == 0 && strstr(input_guess_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_guess_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_guess_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
						}
				}
				else{
						json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
				
				}		
				
			}
	
	}
	else if(bandnum_diff==1 && dut_bandnum==2){
		if(check_match_6G(mac)==-2){
			return -1;
		}
		else if(check_match_6G(mac)==-1)
		{
			memset(wl_6G_prefix, 0, sizeof(wl_6G_prefix));
			snprintf(wl_6G_prefix, sizeof(wl_6G_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"6G"));
			
			struct wlsuffix_mapping_s *P = NULL;
			for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
			{
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "%s_%s", wl_6G_prefix,P->name);
				memset(input_param, 0, sizeof(input_param));
				snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj);
				if(needdelobj){
					json_object_object_del(outRoot, output_param);
				}
				if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
										json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
								
								}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
				}
				else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
										json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
								
								}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
				
				}
			}
		}
	
	}
	else if(bandnum_diff==0 && dut_bandnum==3){
		//if(cfgband_Ver>1){
			if(check_match_6G(mac)==-2){
				return -1;
			}
			else if(check_match_6G(mac)==-1)
			{
				memset(wl_6G_prefix, 0, sizeof(wl_6G_prefix));
				snprintf(wl_6G_prefix, sizeof(wl_6G_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"6G"));
				struct wlsuffix_mapping_s *P = NULL;
				for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
				{
					memset(output_param, 0, sizeof(output_param));
					snprintf(output_param, sizeof(output_param), "%s_%s", wl_6G_prefix,P->name);
					json_object_object_del(outRoot, output_param);
					memset(input_param, 0, sizeof(input_param));
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
					memset(outAuth, 0, sizeof(outAuth));
					json_object *needdelobj = NULL;
					json_object_object_get_ex(outRoot, output_param, &needdelobj);
					if(needdelobj){
						json_object_object_del(outRoot, output_param);
					}
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
					}
					else{
						if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
					}
				}
			}
			else if(check_match_6G(mac)==2)
			{
				memset(wl_5GH_prefix, 0, sizeof(wl_5GH_prefix));
				snprintf(wl_5GH_prefix, sizeof(wl_5GH_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"5G1"));
				
				struct wlsuffix_mapping_s *P = NULL;
				for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
				{
					memset(output_param, 0, sizeof(output_param));
					snprintf(output_param, sizeof(output_param), "%s_%s", wl_5GH_prefix,P->name);
					memset(input_param, 0, sizeof(input_param));
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(1),P->name);
					memset(outAuth, 0, sizeof(outAuth));
					json_object *needdelobj = NULL;
					json_object_object_get_ex(outRoot, output_param, &needdelobj);
					if(needdelobj){
						json_object_object_del(outRoot, output_param);
					}
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "1"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
					}
					else{
						if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "1"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
					}
				}
			
			
			
			}
		//}
	
	}
	else if(dut_bandnum>reBandNum)
	{
		
		if (!cfgAllObj && fileRoot) { 
			json_object *changedParam = NULL;
			struct wlsuffix_mapping_s *P = NULL;
			for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
			{
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "wl%d_%s", get_unit_chanspc_by_bandtype(mac,"2G"),P->name);
				memset(input_param, 0, sizeof(input_param));
				snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
				
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj1 = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj1);
				if(needdelobj1){
					json_object_object_del(outRoot, output_param);
				}

				
				json_object_object_get_ex(fileRoot, input_param, &changedParam);

				if(changedParam!=NULL){
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
							&& !nvram_match("wifison_ready", "1")
#endif
						){
							if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
								json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
							}
							else{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
					}
					else{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
					
					}
				}
				else{
				
				}
			}
			
			struct wlsuffix_guess_mapping_s *P1 = NULL;
			for (P1 = &wlsuffix_guess_mapping_list[0]; P1->name != NULL; P1++)
			{
				memset(output_guess_param, 0, sizeof(output_guess_param));
				snprintf(output_guess_param, sizeof(output_guess_param), "wl%d.1_%s", get_unit_chanspc_by_bandtype(mac,"2G"),P1->name);
				memset(input_guess_param, 0, sizeof(input_guess_param));
				snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
				
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj2 = NULL;
				json_object_object_get_ex(outRoot, output_guess_param, &needdelobj2);
				if(needdelobj2){		
						json_object_object_del(outRoot, output_guess_param);
				}
				json_object_object_get_ex(fileRoot, input_guess_param, &changedParam);
				
				if(changedParam!=NULL){
					if (strncmp(input_guess_param, "wl", 2) == 0 && strstr(input_guess_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
							&& !nvram_match("wifison_ready", "1")
#endif
						){
							if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_guess_param, outAuth, sizeof(outAuth))) {
								json_object_object_add(outRoot, output_guess_param, json_object_new_string(private ? "" : outAuth));
							}
							else{
								json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
							}
					}
					else{
							json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
					
					}
				}
				
			}
		}
		else
		{
		
		}
	
	}
	return 0;
}



int Add_missing_parameter_patch(json_object *outRoot, int private,char *mac,int reBandNum, int cfgband_Ver,json_object *cfgAllObj,json_object *fileRoot)
{
	if(check_mac_exist(mac)<0)
		return -1;
	int dut_bandnum=num_of_wl_if(), bandnum_diff=0;
	bandnum_diff= reBandNum-dut_bandnum;
	char wl_6G_prefix[sizeof("wlXXXX_")];
	char output_param[32],input_param[32],output_guess_param[32],input_guess_param[32];
	char outAuth[16], tmp[64] = {0};
	if(outRoot){
		//DBG_INFO("!!!!!!!!!! outRoot != NULL !!!!!!!!!");
	}else{
		//DBG_INFO("!!!!!!!!!! outRoot == NULL !!!!!!!!!");
		return -1;
	}

	if(bandnum_diff==0 && dut_bandnum==3){
		//if(cfgband_Ver>1){

			if(check_match_6G(mac)==-2){
				return -1;
			}
			else if(check_match_6G(mac)==-1)
			{
				memset(wl_6G_prefix, 0, sizeof(wl_6G_prefix));
				snprintf(wl_6G_prefix, sizeof(wl_6G_prefix), "wl%d", get_unit_chanspc_by_bandtype(mac,"6G"));
				struct wlsuffix_mapping_s *P = NULL;
				for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
				{
					memset(output_param, 0, sizeof(output_param));
					snprintf(output_param, sizeof(output_param), "%s_%s", wl_6G_prefix,P->name);
					json_object_object_del(outRoot, output_param);
					memset(input_param, 0, sizeof(input_param));
					snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(2),P->name);
					memset(outAuth, 0, sizeof(outAuth));
					json_object *needdelobj = NULL;
					json_object_object_get_ex(outRoot, output_param, &needdelobj);
					if(needdelobj){
						json_object_object_del(outRoot, output_param);
					}
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
						&& !nvram_match("wifison_ready", "1")
#endif
					){
						if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
							json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
						}
						else{
							if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
						}
					}
					else{
						if(!strcmp(P->name,"ssid")){
								if (nvram_get_int("dwb_mode")){
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G_dwb", tmp)));
								}
								else{
									memset(tmp, 0, sizeof(tmp));
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : strcat_r(nvram_safe_get(input_param), "_6G", tmp)));
								}
							}
							else if(!strcmp(P->name,"closed")){
									json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : "0"));
							
							}
							else
							{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
					}
				}
			}
		//}
	
	}
	else if(dut_bandnum>reBandNum)
	{
		
		if (!cfgAllObj && fileRoot) { 
			json_object *changedParam = NULL;
			struct wlsuffix_mapping_s *P = NULL;
			for (P = &wlsuffix_mapping_list[0]; P->name != NULL; P++)
			{
				memset(output_param, 0, sizeof(output_param));
				snprintf(output_param, sizeof(output_param), "wl%d_%s", get_unit_chanspc_by_bandtype(mac,"2G"),P->name);
				memset(input_param, 0, sizeof(input_param));
				snprintf(input_param, sizeof(input_param), "wl%d_%s", check_own_unit(0),P->name);
				
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj1 = NULL;
				json_object_object_get_ex(outRoot, output_param, &needdelobj1);
				if(needdelobj1){
					json_object_object_del(outRoot, output_param);
				}

				
				json_object_object_get_ex(fileRoot, input_param, &changedParam);
				if(changedParam!=NULL){
					if (strncmp(input_param, "wl", 2) == 0 && strstr(input_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
							&& !nvram_match("wifison_ready", "1")
#endif
						){
							if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_param, outAuth, sizeof(outAuth))) {
								json_object_object_add(outRoot, output_param, json_object_new_string(private ? "" : outAuth));
							}
							else{
								json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
							}
					}
					else{
							json_object_object_add(outRoot, output_param,json_object_new_string(private ? "" : nvram_safe_get(input_param)));
					
					}
				}
			}
			
			struct wlsuffix_guess_mapping_s *P1 = NULL;
			for (P1 = &wlsuffix_guess_mapping_list[0]; P1->name != NULL; P1++)
			{
				memset(output_guess_param, 0, sizeof(output_guess_param));
				snprintf(output_guess_param, sizeof(output_guess_param), "wl%d.1_%s", get_unit_chanspc_by_bandtype(mac,"2G"),P1->name);
				memset(input_guess_param, 0, sizeof(input_guess_param));
				snprintf(input_guess_param, sizeof(input_guess_param), "wl%d.1_%s", check_own_unit(0),P1->name);
				
				memset(outAuth, 0, sizeof(outAuth));
				json_object *needdelobj2 = NULL;
				json_object_object_get_ex(outRoot, output_guess_param, &needdelobj2);
				if(needdelobj2){		
						json_object_object_del(outRoot, output_guess_param);
				}
				json_object_object_get_ex(fileRoot, input_guess_param, &changedParam);
				
				if(changedParam!=NULL){
					if (strncmp(input_guess_param, "wl", 2) == 0 && strstr(input_guess_param, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
							&& !nvram_match("wifison_ready", "1")
#endif
						){
							if (cm_checkWifiAuthCap(mac, dut_bandnum, reBandNum, 0, input_guess_param, outAuth, sizeof(outAuth))) {
								json_object_object_add(outRoot, output_guess_param, json_object_new_string(private ? "" : outAuth));
							}
							else{
								json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
							}
					}
					else{
							json_object_object_add(outRoot, output_guess_param,json_object_new_string(private ? "" : nvram_safe_get(input_guess_param)));
					
					}
				}
				
			}
		}
		else
		{
		
		}
	
	}
	return 0;
}
int check_have_XG(int target_type)
{
	int nband=0, unit = 0;
	char wlIfnames[64] ,word[256], *next, tmp[64];
	char prefix[16] = {0};
	int num5g = num_of_5g_if();
	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			if (nband == 2) {
				if(target_type==2)
				{
					return 1;
				}	
			}
			else if (nband == 1){
				if(num5g<2)
				{
					if(target_type==50 || target_type==51)
						return 1;	
				}
				else if(num5g>1)
				{
					if(target_type==50 || target_type==51)
					{
						return 1;
					}
					else if(target_type==52)
					{
						return 1;
					}	
				}
			}
			else if (nband == 4) {
				if(target_type==60)
				{
					return 1;
				}	
			}
			unit++;
	}
	return -1;
}

int get_wl_bandindex_by_unit(json_object *cfgRoot, int unit, int cfgbandType_num, int cfgband_Ver) {
	int bandindex=-1;
	char subft_basic_band_name[24]={0};
	int  subft_basic_band_type = 0;
	json_object *cfgbandindextype = NULL;
	int num5g = num_of_5g_if();
	int have_6g = 0;
	
	
	if(nvram_get_int("band_type")==3 || nvram_get_int("band_type")==4){
		have_6g = 1;
	}

	if(cfgband_Ver>1){
			bandindex = unit;
			return bandindex;
			
		}
	else if(cfgband_Ver==1){
			memset(subft_basic_band_name, 0, sizeof(subft_basic_band_name));
			snprintf(subft_basic_band_name, sizeof(subft_basic_band_name), "%s%d","SUBFT_BASIC_BAND_",unit);
			json_object_object_get_ex(cfgRoot, subft_basic_band_name, &cfgbandindextype);
			if(cfgbandindextype){
				subft_basic_band_type = json_object_get_int(cfgbandindextype);
				switch (subft_basic_band_type) {
					case 0:
						bandindex = check_own_unit(0);
						break;
					case 1:
					case 2:
						if(num5g>1)
							bandindex = check_own_unit(2);
						else
							bandindex = check_own_unit(1);
						break;
					case 3:
						if(num5g>1)
							bandindex = check_own_unit(3);
						else if(num5g==1 && nvram_get_int("band_type")>2)
							bandindex = check_own_unit(6);
						else 
							bandindex = 2;
						break;
					case 4:
						bandindex = check_own_unit(6);
						break;
					default: 
						bandindex = unit;
						break;			
						
				}
				return bandindex;
			}
			else
			{
				if(unit==0){
					bandindex = check_own_unit(0);
					return bandindex;
				}	
				else if(unit==1){
					bandindex = check_own_unit(2);
					return bandindex;
				}
				else if(unit==2){
					if(strlen(nvram_safe_get("amas_cap_modelname")))
					{
						if((!strcmp(nvram_safe_get("amas_cap_modelname"),"RT-AXE")||!strcmp(nvram_safe_get("amas_cap_modelname"),"ET")||!strcmp(nvram_safe_get("amas_cap_modelname"),"GT-AXE"))&& have_6g == 1)
						{
							bandindex = check_own_unit(6);
						}
						else
						{
							bandindex = check_own_unit(3);
						}
					}
					else{
						bandindex = check_own_unit(3);
					}
					return bandindex;
				}
				else if(unit==3){
					bandindex = check_own_unit(6);
					return bandindex;
				}
				else{
					bandindex = unit;
					return bandindex;
				}
			}
		
	}
	else{
			if(unit==0){
				bandindex = check_own_unit(0);
				return bandindex;
			}	
			else if(unit==1){
				bandindex = check_own_unit(2);
				return bandindex;
			}
			else if(unit==2){
				if(strlen(nvram_safe_get("amas_cap_modelname")))
				{
					if(!strcmp(nvram_safe_get("amas_cap_modelname"),"RT-AXE")||!strcmp(nvram_safe_get("amas_cap_modelname"),"ET")||!strcmp(nvram_safe_get("amas_cap_modelname"),"GT-AXE"))
					{
						bandindex = check_own_unit(6);
					}
					else
					{
						bandindex = check_own_unit(3);
					}
				}
				else{
					bandindex = check_own_unit(3);
				}
				return bandindex;
			}
			else if(unit==3){
				bandindex = check_own_unit(6);
				return bandindex;
			}
			else{
				bandindex = unit;
				return bandindex;
			}
	
	
	}
}

int get_5g_unit()
{
	int unit = 0;
	char prefix[sizeof("wlXXXXX_")], wlIfnames[64], word[32], *next, tmp[64];

	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		if (nvram_get_int(strcat_r(prefix, "nband", tmp)) == 1) {
			DBG_INFO("the unit(%d) for 5G/5G low", unit);
			break;
		}
		unit++;
	}

	return unit;
}

#ifdef RTCONFIG_AMAS_WGN

int mapping_wl_bandindex_by_unit(int unit, json_object *root)
{
	json_object *cfgRoot = NULL;
	json_object *cfgBandVer = NULL;
	json_object *cfgBandType = NULL;

	const char *bandVer = NULL;
	long bandType = 0;
	int bandIndex = 0;
	int result = -1;

	if (unit < 0 || !(cfgRoot = root))
		return -1;

	json_object_object_get_ex(cfgRoot, CFG_BAND_INDEX_VERSION, &cfgBandVer);
	if (!cfgBandVer || !(bandVer = json_object_get_string(cfgBandVer)))
		bandVer == NULL;

	if (bandVer)
		bandIndex = atoi(bandVer);
	else 
		bandIndex = 0;

	switch (bandIndex) {
		case 0:
			if (unit == 0)
				result = wgn_get_unit_by_band(WGN_WL_BAND_2G);
			else if (unit == 1)
				result = wgn_get_unit_by_band(WGN_WL_BAND_5G);
			else if (unit == 2)
				result = wgn_get_unit_by_band(WGN_WL_BAND_5GH);
			else if (unit == 3)
				result = wgn_get_unit_by_band(WGN_WL_BAND_6G);
			else 
				result = unit;
			break;
		case 1:
			json_object_object_get_ex(cfgRoot, CFG_BAND_TYPE, &cfgBandType);
			if (cfgBandType) {
				bandType = json_object_get_int64(cfgBandType);
				switch (unit) {
					case 0:
						result = check_own_unit(0);
						break;
					case 1:
						result = check_own_unit(2);
						break;
					case 2:
						if ((bandType & HAVE_WIFI_6G) == HAVE_WIFI_6G)
							result = check_own_unit(6);
						else
							result = check_own_unit(3);
						break;
					case 3:
						result = check_own_unit(6);
						break;
					default:
						result = -1;
						break;
				}
			}
			break;
		case 2: 
			result = unit;
			break;
		default:
			result = -1;
			break;
	}

	return result;
}

#endif	// RTCONFIG_AMAS_WGN
