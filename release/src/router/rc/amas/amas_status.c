#include <rc.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <shutils.h>
#include <linux/sockios.h>
#include <stdarg.h>
#include <netdb.h>
#include <arpa/inet.h>
#ifdef RTCONFIG_RALINK
#include <ralink.h>
#endif
#ifdef RTCONFIG_QCA
#include <qca.h>
#endif
#ifdef RTCONFIG_REALTEK
#include "../shared/sysdeps/realtek/realtek.h"
#endif
#include <shared.h>

#include <syslog.h>
#include <bcmnvram.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef RTAX53U
#include <math.h>
#endif	// !MUSL_LIBC
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/sysinfo.h>
#ifdef RTCONFIG_USER_LOW_RSSI
#if defined(RTCONFIG_RALINK)
#include <typedefs.h>
#else
#include <wlioctl.h>
#include <wlutils.h>
#endif
#endif

#include "amas.h"
#include <amas-utils.h>
#include <amas_path.h>

#ifdef RTCONFIG_CFGSYNC
#include <cfg_event.h>
#include <json.h>
#include <cfg_string.h>
#endif

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#ifdef RTCONFIG_DPSTA
#include <dpsta_linux.h>
#endif

#if defined(RTCONFIG_AMAS_WGN)
#include <amas_wgn_shared.h>
#endif

int model_6g;

extern char *get_pap_bssid(int unit, char bssid_str[]);
extern int is_fixed_eth_if(char *ifname);

unsigned char s2x(char *c)
{
	unsigned char val = 0;

    switch(c[0]) {
    case '0'...'9':
        val = (unsigned char)atoi(c);
        break;
    case 'a'...'f':
        val = 0xa + (c[0]-'a');
        break;
    case 'A'...'F':
        val = 0xa + (c[0]-'A');
        break;
    default:
        return 0;
    }
    return val;
}


#define STR2HEX2(hex, str, len)  \
    do { \
        int i = 0;\
        char temp1[2]={0};\
        char temp2[2]={0};\
        for(i = 0; i < len; i++) {\
            temp1[0]=str[i*2];\
            temp1[1]='\0';\
            temp2[0]=str[i*2 + 1];\
            temp2[1]='\0';\
            hex[i] = (s2x(temp1) << 4) + s2x(temp2);\
        }\
    } while(0)

struct _upstream_default_priority default_priority_handlers[] =
{
  {ETH1_U,  1},
  {ETH2_U,  2},
  {ETH3_U,  3},
  {ETH4_U,  4},
  {ETH5_U,  5},
  {ETH6_U,  6},
  {ETH7_U,  7},
  {ETH8_U,  8},
  {ETH9_U,  9},
  {ETH10_U,  10},
  {ETH11_U,  11},
  {ETH12_U,  12},
  {ETH13_U,  13},
  {ETH14_U,  14},
  {ETH15_U,  15},
  {ETH16_U,  16},
  {WL2G_U,  20},
  {WL5G1_U,  19},
  {WL5G2_U,  18},
  {WL6G_U,  17},
  {0,   	  }
};

int amas_status_dbg = 0;
int amas_status_timer = STATUS_TIMER;
int wlc_status_fail_count = WLC_STATUS_FAIL_COUNT;
int eth_status_fail_count = ETH_STATUS_FAIL_COUNT;

wlc_status *wlcstat_list = NULL;
eth_status *ethstat_list = NULL;
ifi_priority *priority_list = NULL;

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"amas_status.log"
#define AST_DBG(fmt, arg...) \
	do {    \
		if(amas_status_dbg) \
			dbG("AST %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("amas_status_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
        } while (0)
#else
#define AST_DBG(fmt, arg...) \
        do {    \
               if(amas_status_dbg) \
                dbG("AST %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("amas_status_syslog"), "1")) \
                logmessage("AST", fmt, ##arg); \
        } while (0)
#endif

/**
 * @brief Upper string
 *
 * @param str be upper string
 */
static void string2upper(char *str)
{
	int len = strlen(str);
	int i;
	for (i = 0; i < len; i++)
		*(str+i) = toupper(*(str+i));
}

int priority_list_cmp_sort_priority( const void *a , const void *b )
{
	struct _ifi_priority *c = (ifi_priority *)a;
	struct _ifi_priority *d = (ifi_priority *)b;
	if(c->priority != d->priority) return c->priority - d->priority;
	return 0;
}

/**
 * @brief Get the befollow bandindex object
 *
 * @param defif Band definition
 * @param bandindex Band index
 * @param befollow_bandindex Output. Be followed band index array.
 * @param size befollow_bandindex size.
 */
static void get_befollow_bandindex(int defif, int bandindex, int *befollow_bandindex, int size) {
	char amas_wlc_follow_bandindex[] = "amas_wlcXXX_follow_bandindex";
	char amas_wlc_defif[] = "amas_wlcXXX_defif";
	int follow_bandindex = -1, follow_count = 0, i, j;
    int SUMband = get_wl_count();

	/* Default rules */
	amas_follow_rule_s default_follow_rules[] = {
		{WL2G_U, WL5G2_U},
		{WL2G_U, WL5G1_U},
		{WL5G1_U, 0},
		{WL5G2_U, 0},
		{WL6G_U, WL5G2_U},
		{WL6G_U, WL5G1_U},
		{0, 0}};

	for (i = 0; i < SUMband; i++) {
		if (i == bandindex)  // Self. Skip.
			continue;
		snprintf(amas_wlc_follow_bandindex, sizeof(amas_wlc_follow_bandindex), "amas_wlc%d_follow_bandindex", i);
		if (nvram_get(amas_wlc_follow_bandindex)) {
			follow_bandindex = nvram_get_int(amas_wlc_follow_bandindex);
			if (bandindex == follow_bandindex) {
				befollow_bandindex[follow_count] = i;
				follow_count++;
			}
		} else {  // default
			snprintf(amas_wlc_defif, sizeof(amas_wlc_defif), "amas_wlc%d_defif", i);
			j = 0;
			while (default_follow_rules[j].band) {
				if (default_follow_rules[j].band == nvram_get_int(amas_wlc_defif) && default_follow_rules[j].follow_band > 0) {
					//  Try to find band index.
					if (default_follow_rules[j].follow_band == defif) {
						befollow_bandindex[follow_count] = i;
						follow_count++;
						break;
					}
				}
				j++;
			}
		}
	}

	for (; follow_count < size; follow_count++) {
		befollow_bandindex[follow_count] = -1;
	}
}

int init_eth_info(int amas_eth_bhmode)
{
	char eth[32]={0}, ethType[8] = {}, *next = NULL;
	char nvramstr[64];
	int j = 0, k =0;
	div_t chkval2;
	int offset = 0;
	int chkval = 0;
	int SUMeth = get_eth_count();

	foreach(eth, nvram_safe_get("eth_ifnames"), next)
	{
        if (j < MAX_ETH )
        {
			ethstat_list[j].ethIndex 					= j;
			ethstat_list[j].defif 						= (ETH1_U << j);
			ethstat_list[j].priority 					= 100;
			snprintf(ethstat_list[j].ethif, sizeof(ethstat_list[j].ethif), "%s", eth);
			ethstat_list[j].last_state 					= INIT_CODE;
			ethstat_list[j].state 						= -1;
			ethstat_list[j].linkrate					= -1;
			ethstat_list[j].last_cost					= INIT_CODE;
			ethstat_list[j].cost						= -1;
			ethstat_list[j].papcost						= -1;
			ethstat_list[j].last_get_cost_result		= INIT_CODE;
			ethstat_list[j].get_cost_result				= -1;
			ethstat_list[j].last_rssiscore				= INIT_CODE;
			ethstat_list[j].rssiscore					= 100;
			ethstat_list[j].last_get_rssiscore_result	= INIT_CODE;
			ethstat_list[j].get_rssiscore_result		= -1;
			ethstat_list[j].getstate_fail_count 		= 0;
			ethstat_list[j].getcost_fail_count			= 0;
			ethstat_list[j].getrssiscore_fail_count 	= 0;
			ethstat_list[j].use = (amas_eth_bhmode & (1 << (4 * ((ethstat_list[j].ethIndex / 4) + 1) + ethstat_list[j].ethIndex))) > 0 ? 1 : 0;
			ethstat_list[j].isFixedWan = is_fixed_eth_if(eth);
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
			ethstat_list[j].chk_internet_timeout =
			((nvram_get_int("amas_chk_eth") > 0 ? nvram_get_int("amas_chk_eth") : AMAS_CHECK_ETH_TIMEOUT) / amas_status_timer);
#endif
            ethstat_list[j].ethType = ETH_TYPE_1000; // default
		}
		else {
            AST_DBG("(%s) ethIndex(%d) exceed the interface limitations. Must be expanded.", j);
		}

		j++;
	}

	j = 0;
    foreach(ethType, nvram_safe_get("amas_ethif_type"), next) {
        if (j < get_eth_count()) {
            ethstat_list[j].ethType = atoi(ethType);
        }
        else
            AST_DBG("(%s) ETH type setting error. The ethif type counts is too many.\n", __FUNCTION__);
        j++;
    }

	char *eth_priority = nvram_safe_get("eth_priority");

	if (eth_priority == NULL)
	{
		AST_DBG("priority is null, set to default priority.\n");
		eth_priority = DEFAULT_ETH_PRIORITY;
	}

	chkval = cal_space(eth_priority);

	chkval2 = div(chkval, ETH_PARA_COUNT);

	if (chkval2.rem != 0 || chkval2.quot == 0)
	{
		AST_DBG("priority is incorrect, set to default priority.\n");
		eth_priority = DEFAULT_ETH_PRIORITY;
	}
	else
	{
		AST_DBG("eth_priority format is OK.\n");
	}

	eth_info *ethinfo = (struct _eth_ifinfo *) malloc(chkval2.quot *sizeof(struct _eth_ifinfo));

	if (ethinfo == NULL)
	{
		AST_DBG("Can't alloc memory for %s\n", __FILE__);
		return 0;
	}
    memset(ethinfo, 0x00, chkval2.quot *sizeof(struct _eth_ifinfo));

    int count = 0;
    while (sscanf(eth_priority, " %d%d%d%n", &ethinfo[count].ethIndex, &ethinfo[count].priority, &ethinfo[count].use, &offset) == ETH_PARA_COUNT)
    {

        eth_priority += offset;
        AST_DBG("read[%d]: index(%d) priority(%d) use(%d)\n", count, ethinfo[count].ethIndex, ethinfo[count].priority, ethinfo[count].use);
        if (count < chkval2.quot)
       			count++;
    }


    for (j =0 ; j < SUMeth; j++)
    {
        for (k =0 ; k < chkval2.quot; k++)
        {
            if (ethstat_list[j].ethIndex == ethinfo[k].ethIndex)
            {
                ethstat_list[j].priority = ethinfo[k].priority;
                //ethstat_list[j].use = ethinfo[k].use;

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_ifname", ethstat_list[j].ethIndex);
				nvram_set(nvramstr, ethstat_list[j].ethif);

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_defif", ethstat_list[j].ethIndex);
				nvram_set_int(nvramstr, ethstat_list[j].defif);

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_index", ethstat_list[j].ethIndex);
				nvram_set_int(nvramstr, ethstat_list[j].ethIndex);

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_priority", ethstat_list[j].ethIndex);
				nvram_set_int(nvramstr, ethstat_list[j].priority);

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_use", ethstat_list[j].ethIndex);
				nvram_set_int(nvramstr, ethstat_list[j].use);

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_ethType", ethstat_list[j].ethIndex);
				nvram_set_int(nvramstr, ethstat_list[j].ethType);

				snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_cost", ethstat_list[j].ethIndex);
				nvram_set_int(nvramstr, ethstat_list[j].cost);
            }
        }
    }

    free(ethinfo);
    return 0;
}

int init_wlc_info(int amas_wifi_bhmode)
{
	char wif[256]={0}, *next = NULL;
	char nvramstr[64];
	int k = 0, j = 0;
	div_t chkval2;
	int offset = 0;
	int chkval = 0;
    int SUMband = get_wl_count();
	int band_count[3]= {};  // [0]:2.4G/[1]:5G/[2]:6G
	char amas_wlc_target_same_ap[] = "amas_wlcXXX_target_same_ap";

	model_6g = 0;

	foreach(wif, nvram_safe_get("sta_ifnames"), next)
	{
        if (j < MAX_WIFI)
        {
			wlcstat_list[j].band 						= 0;
			wlcstat_list[j].bandIndex 					= j;
			wlcstat_list[j].priority 					= 100;
			snprintf(wlcstat_list[j].wlcif, sizeof(wlcstat_list[j].wlcif), "%s", wif);
			wlcstat_list[j].use 						= (amas_wifi_bhmode & (1 << (4 * ((wlcstat_list[j].bandIndex / 4) + 1) + wlcstat_list[j].bandIndex))) > 0 ? 1 : 0;			
			wlcstat_list[j].unit 						= -1;
			wlcstat_list[j].pap_bssid.bssid[0] = '\0';
			wlcstat_list[j].pap_bssid.last_bssid[0] = '\0';
			wlcstat_list[j].pap_bssid.bssid_2g[0] = '\0';
			wlcstat_list[j].pap_bssid.bssid_5g[0] = '\0';
			wlcstat_list[j].pap_bssid.bssid_5g1[0] = '\0';
			wlcstat_list[j].pap_bssid.bssid_6g[0] = '\0';
			wlcstat_list[j].last_state 					= INIT_CODE;
			wlcstat_list[j].state 						= -1;
			wlcstat_list[j].last_rssi					= INIT_CODE;
			wlcstat_list[j].rssi						= -1;
			wlcstat_list[j].last_cost					= INIT_CODE;
			wlcstat_list[j].cost						= -1;
			wlcstat_list[j].papcost						= -1;
			wlcstat_list[j].get_cost_result				= -1;
			wlcstat_list[j].last_rssiscore				= INIT_CODE;
			wlcstat_list[j].rssiscore					= 100;
			wlcstat_list[j].getpap_fail_count 			= 0;
			wlcstat_list[j].getrssi_fail_count 			= 0;
			wlcstat_list[j].getstate_fail_count 		= 0;
			wlcstat_list[j].getrssiscore_fail_count 	= 0;
		}
		else {
            AST_DBG("(%s) bandIndex(%d) exceed the interface limitations. Must be expanded.", j);
		}

		j++;
	}

	char *band_priority = nvram_safe_get("sta_priority");

	if (band_priority == NULL)
	{
		AST_DBG("priority is null, set to default priority.\n");
		band_priority = DEFAULT_BAND_PRIORITY;
	}

	chkval = cal_space(band_priority);

	chkval2 = div(chkval, WIFI_PARA_COUNT);

	if (chkval2.rem != 0 || chkval2.quot == 0)
	{
		AST_DBG("priority is incorrect, set to default priority.\n");
		band_priority = DEFAULT_BAND_PRIORITY;
	}
	else
	{
		AST_DBG("sta_priority format is OK.\n");
	}

	wifi_info *wifi = (struct _wifi_ifinfo *) malloc(chkval2.quot *sizeof(struct _wifi_ifinfo));

	if (wifi == NULL)
	{
		AST_DBG("Can't alloc memory for %s\n", __FILE__);
		return 0;
	}
    memset(wifi, 0x00, chkval2.quot *sizeof(struct _wifi_ifinfo));

    int count = 0;
    while (sscanf(band_priority, " %d%d%d%d%n", &wifi[count].band, &wifi[count].bandIndex, &wifi[count].priority, &wifi[count].use, &offset) == WIFI_PARA_COUNT)
    {
        band_priority += offset;
        AST_DBG("read[%d]: band(%d) index(%d) priority(%d) use(%d)\n", count, wifi[count].band, wifi[count].bandIndex, wifi[count].priority, wifi[count].use);
        if (count < chkval2.quot)
       			count++;
    }


    for (j =0 ; j < SUMband; j++)
    {
        for (k =0 ; k < chkval2.quot; k++)
        {
            if (wlcstat_list[j].bandIndex == wifi[k].bandIndex)
            {
                wlcstat_list[j].band = wifi[k].band;
                wlcstat_list[j].priority = wifi[k].priority;
                wlcstat_list[j].unit = k;
				switch (wifi[k].band) {
					case 2:  // 2.4G
						wlcstat_list[j].defif = WL2G_U << band_count[0];
						band_count[0]++;
						break;
					case 5:  // 5G
					case 51: // 5G for old FW
					case 52: // 5G for old FW
						wlcstat_list[j].defif = WL5G1_U << band_count[1];
						band_count[1]++;
						break;
					case 6:  // 6G
						model_6g = 1;
						wlcstat_list[j].defif = WL6G_U << band_count[2];
						band_count[2]++;
						break;
					default:
						break;
				}

                                snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_ifname", wlcstat_list[j].bandIndex);
				nvram_set(nvramstr, wlcstat_list[j].wlcif);

				snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_defif", wlcstat_list[j].bandIndex);
				nvram_set_int(nvramstr, wlcstat_list[j].defif);

				snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_index", wlcstat_list[j].bandIndex);
				nvram_set_int(nvramstr, wlcstat_list[j].bandIndex);

				snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_band", wlcstat_list[j].bandIndex);
				nvram_set_int(nvramstr, wlcstat_list[j].band);

				snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_priority", wlcstat_list[j].bandIndex);
				nvram_set_int(nvramstr, wlcstat_list[j].priority);

				snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_use", wlcstat_list[j].bandIndex);
				nvram_set_int(nvramstr, wlcstat_list[j].use);

				snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_unit", wlcstat_list[j].bandIndex);
				nvram_set_int(nvramstr, wlcstat_list[j].unit);
				break;
            }
        }
    }

    for (j = 0; j < SUMband; j++) { // Init follow band.
		get_befollow_bandindex(wlcstat_list[j].defif, wlcstat_list[j].bandIndex, wlcstat_list[j].befollow_bandindex, sizeof(wlcstat_list[j].befollow_bandindex) / sizeof(int));
		snprintf(amas_wlc_target_same_ap, sizeof(amas_wlc_target_same_ap), "amas_wlc%d_target_same_ap",  wlcstat_list[j].bandIndex);
		nvram_set(amas_wlc_target_same_ap, "");
	}
    free(wifi);
    return 0;
}

int check_priority_setting(int amas_eth_bhmode, int amas_wifi_bhmode)
{
	int j = 0,  k = 0;
	int SUMeth = get_eth_count();
    int SUMband = get_wl_count();
	int SUMif = SUMeth + SUMband;
	int duplicated = 0;
	int mismatch = 0;
    char nvramstr[64];

	upstream_default_priority *handler = NULL;
	upstream_default_priority *handler_entry = &default_priority_handlers[0];

	if (j < SUMif)
	{
		for (k = 0; k < SUMeth; k++)
		{
			priority_list[j].type = UPIF_TYPE_ETH;
			priority_list[j].defif =  ethstat_list[k].defif;
			priority_list[j].index =  ethstat_list[k].ethIndex;
			priority_list[j].priority =  ethstat_list[k].priority;
            j++;
        }

		for (k = 0; k < SUMband; k++)
		{
			priority_list[j].type = UPIF_TYPE_WIFI;
			priority_list[j].defif =  wlcstat_list[k].defif;
			priority_list[j].index =  wlcstat_list[k].bandIndex;
			priority_list[j].priority =  wlcstat_list[k].priority;
            j++;
        }
	}
	qsort(priority_list, SUMif, sizeof(priority_list[0]), priority_list_cmp_sort_priority);

  k = 0;
  for(j = 0; j < (SUMif - 1); j ++)
  {
  		if (priority_list[j].priority == priority_list[j+1].priority)
  		{
  			duplicated = 1;
  			AST_DBG("\n The (%d, %d) priority settings from sta_priority and eth_priority are duplicated. Set to default priority.\n", priority_list[j].defif, priority_list[j+1].defif);
  			break;
  		}
  }

  if (duplicated == 1)
  {

		AST_DBG("\n ###### RESET priority setting to  default_priority_handlers######\n");
		for (j = 0; j < SUMif; j++)
		{
			for (handler = handler_entry; handler->defif; handler++)
			{
				if(priority_list[j].defif == handler->defif)
				{
					priority_list[j].priority = handler->priority;
				}

				for (k = 0; k < SUMeth; k++)
				{
					if (ethstat_list[k].defif == priority_list[j].defif)
					{
						ethstat_list[k].priority = priority_list[j].priority;
						snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_priority", priority_list[j].index);
						nvram_set_int(nvramstr, ethstat_list[k].priority);
					}
				}

				for (k = 0; k < SUMband; k++)
				{
					if (wlcstat_list[k].defif == priority_list[j].defif)
					{
						wlcstat_list[k].priority = priority_list[j].priority;
						snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_priority", priority_list[j].index);
						nvram_set_int(nvramstr, wlcstat_list[k].priority);

					}
				}
			}
#if 0
			AST_DBG("\n ##################### reset priority setting#################\n"
			"priority_list[%d].defif\t\t\t= %02X\n"
			"priority_list[%d].priority\t\t= %d\n",
			j, priority_list[j].defif,
			j, priority_list[j].priority);
#endif
		}

		/*sort by new priority setting.*/
		qsort(priority_list, SUMif, sizeof(priority_list[0]), priority_list_cmp_sort_priority);
	}

	if (nvram_get_int("amas_ethernet") == CONN_PRI_CUSTOM) { // Check isFirst setting in custom mode.
		if(priority_list[0].defif <= ETH_MAX_BASE)
		{
			if ((amas_eth_bhmode & (1 << (8 * (priority_list[0].index / 4) + (priority_list[0].index % 4)))) == 0)
				mismatch = 1;
		} else if(priority_list[0].defif > ETH_MAX_BASE && priority_list[0].defif <= WL_MAX_BASE) {
			if ((amas_wifi_bhmode & (1 << (8 * (priority_list[0].index / 4) + (priority_list[0].index % 4)))) == 0)
				mismatch = 1;
		}

		// eth_priority and sta_priority mismatch with bhmode.
		if (mismatch == 1)
		{
			AST_DBG("eth_priority and sta_priority mismatch with bhmode. find first priority and set to ultra high priority(0)", j);
			for (j = 0; j < SUMif; j++)
			{
				if(priority_list[j].defif <= ETH_MAX_BASE) {
					priority_list[j].priority = (amas_eth_bhmode & (1 << (8 * (priority_list[j].index / 4) + (priority_list[j].index % 4)))) > 0 ? 0 : priority_list[j].priority;
					snprintf(nvramstr, sizeof(nvramstr), "amas_eth%d_priority", priority_list[j].index);
					nvram_set_int(nvramstr, priority_list[j].priority);
				} else if(priority_list[j].defif > ETH_MAX_BASE && priority_list[j].defif <= WL_MAX_BASE) {
					priority_list[j].priority = (amas_wifi_bhmode & (1 << (8 * (priority_list[j].index / 4) + (priority_list[j].index % 4)))) > 0 ? 0 : priority_list[j].priority;
					snprintf(nvramstr, sizeof(nvramstr), "amas_wlc%d_priority", priority_list[j].index);
					nvram_set_int(nvramstr, priority_list[j].priority);
				}
			}
		}
	}

	qsort(wlcstat_list, SUMband, sizeof(wlcstat_list[0]), priority_list_cmp_sort_priority);

   return 0;
}

#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
/**
 * @brief Checking if the RE connects to CAP via ethernet backhaul.
 *
 * @param ethstat eth_status structure
 * @return amas_eth_state ethernet backhaul state
 */
static amas_eth_state check_eth_state(peth_status ethstat)
{
	amas_eth_state state = ETH_STATE_INITIALIZING;
	int wan_status = get_uplinkports_status(ethstat->ethif);
	int chk_eth_timeout = ((nvram_get_int("amas_chk_eth") > 0 ? nvram_get_int("amas_chk_eth") : AMAS_CHECK_ETH_TIMEOUT) / amas_status_timer);

	if (wan_status <= 0) {
		ethstat->chk_internet_timeout = chk_eth_timeout; // reset;
		return (wan_status == 0 ? state : wan_status);
	}
	if (ethstat->last_state <= 0)
		state = ETH_STATE_CONNECTED;
	else if (ethstat->last_state == ETH_STATE_CONNECTED) {
		if ((nvram_get_int("amas_path_stat_v3") >> 12) & (1 << ethstat->ethIndex)) { // in br0
			if (nvram_get_int("cfg_alive") != 1) {
				if (ethstat->chk_internet_timeout-- <= 0) {
					state = ETH_STATE_PLUGIN; // Don't trying.
				} else
					state = ETH_STATE_CONNECTED; // Keep trying to connect to cfg_server
			} else {
				state = ETH_STATE_CONNECTED;
				ethstat->chk_internet_timeout = chk_eth_timeout; // reset
			}
		} else
			state = ethstat->last_state; // keep state value.
	}
	else if (ethstat->last_state == ETH_STATE_PLUGIN)
		state = ETH_STATE_PLUGIN;

	return state;
}
#endif

#ifdef RTCONFIG_AMAS_ETHDETECT
int is_eth_if(char *ifname)
{
	int ret = 0;
	char eth_ifnames[32], word[16], *next = NULL;

	strlcpy(eth_ifnames, nvram_safe_get("eth_ifnames"), sizeof(eth_ifnames));

	foreach(word, eth_ifnames, next) {
		if (strcmp(ifname, word) == 0) { // found
			ret = 1;
			break;
		}
	}

	return ret;
}
#endif

int update_eth_info(int amas_eth_bhmode)
{

	int j = 0;
	char nvrampar[32];
	char nvramparf[32];
    int SUMeth = get_eth_count();

	for (j = 0; j < SUMeth; j++)
	{

			snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_state", ethstat_list[j].ethIndex);
			snprintf(nvramparf, sizeof(nvramparf), "amas_eth%d_state_fail", ethstat_list[j].ethIndex);

		if (ethstat_list[j].use == 1
#ifdef RTCONFIG_AMAS_ETHDETECT
			|| (amas_eth_bhmode == 0 && ethstat_list[j].use == 0 && is_eth_if(ethstat_list[j].ethif) && ethstat_list[j].isFixedWan == 0)
#endif
		)
		{
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
			int state = check_eth_state(&ethstat_list[j]);
			ethstat_list[j].state = state;
#else
			ethstat_list[j].state = get_uplinkports_status(ethstat_list[j].ethif);
#endif

			if (ethstat_list[j].state >= 0)
			{
				if (ethstat_list[j].last_state != ethstat_list[j].state  ||
					(ethstat_list[j].getstate_fail_count == 0 && (nvram_get_int(nvrampar) != ethstat_list[j].state)))
				{
					nvram_set_int(nvrampar, ethstat_list[j].state);
					ethstat_list[j].last_state = ethstat_list[j].state;
				}

				if(ethstat_list[j].getstate_fail_count > 0)
				{
					ethstat_list[j].getstate_fail_count = 0;
					nvram_set_int(nvramparf, 0);
				}

#ifdef RTCONFIG_QCA_PLC2
				if (ethstat_list[j].ethType >= ETH_TYPE_PLC) {
					int plc_head = 0;
					amas_is_plc_head(ethstat_list[j].ethif, &plc_head);
					nvram_set_int("plc_head", plc_head);
					AST_DBG("ETH(%d) Current plc_head: %d\n", ethstat_list[j].ethIndex , plc_head);
				}
#endif	/* RTCONFIG_QCA_PLC2 */
			}
			else
			{
				if (ethstat_list[j].getstate_fail_count > eth_status_fail_count)
				{
					if (nvram_get_int(nvramparf) == 0)
					{
						dbG("ethernet state(%d) is invalid!\n", ethstat_list[j].state);
						AST_DBG("ethernet state(%d) is invalid!\n", ethstat_list[j].state);
						//logmessage("AST","ethernet state(%d) is invalid!\n", ethstat_list[j].state);
					}
					nvram_set_int(nvramparf, ethstat_list[j].getstate_fail_count);
				}
				ethstat_list[j].getstate_fail_count++;
			}
		}
		else
		{
			nvram_set_int(nvrampar, -1);
			nvram_set_int(nvramparf, 0);
		}


		AST_DBG("\n######################################\n"
		"ethstat_list[%d].defif\t\t\t\t= %02X\n"
		"ethstat_list[%d].ethIndex\t\t\t= %d\n"
		"ethstat_list[%d].ethType\t\t\t= %d\n"
		"ethstat_list[%d].priority\t\t\t= %d\n"
		"ethstat_list[%d].ethif\t\t\t\t= %s\n"
		"ethstat_list[%d].use\t\t\t\t= %d\n"
		"ethstat_list[%d].isFixedWan\t\t\t= %d\n"
		"ethstat_list[%d].last_state\t\t\t= %d\n"
		"ethstat_list[%d].state\t\t\t\t= %d\n"
		"ethstat_list[%d].getstate_fail_count\t\t= %d\n"
		"ethstat_list[%d].last_cost\t\t\t= %.1f\n"
		"ethstat_list[%d].cost\t\t\t\t= %.1f\n"
		"ethstat_list[%d].papcost\t\t\t\t= %.1f\n"
		"ethstat_list[%d].getcost_fail_count\t\t= %d\n"
		"ethstat_list[%d].last_get_cost_result\t\t= %s\n"
		"ethstat_list[%d].get_cost_result\t\t\t= %s\n"
		"ethstat_list[%d].last_rssiscore\t\t\t= %d\n"
		"ethstat_list[%d].rssiscore\t\t\t= %d\n"
		"ethstat_list[%d].getrssiscore_fail_count\t\t= %d\n"
		"ethstat_list[%d].last_get_rssiscore_result\t= %s\n"
		"ethstat_list[%d].get_rssiscore_result\t\t= %s\n"
		"ethstat_list[%d].linkrate\t\t= %d\n"
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
		"ethstat_list[%d].chk_internet_timeout\t\t= %d\n"
#endif
		, j, ethstat_list[j].defif,
		j, ethstat_list[j].ethIndex,
		j, ethstat_list[j].ethType,
		j, ethstat_list[j].priority,
		j, ethstat_list[j].ethif,
		j, ethstat_list[j].use,
		j, ethstat_list[j].isFixedWan,
		j, ethstat_list[j].last_state,
		j, ethstat_list[j].state,
		j, ethstat_list[j].getstate_fail_count,
		j, ethstat_list[j].last_cost,
		j, ethstat_list[j].cost,
		j, ethstat_list[j].papcost,
		j, ethstat_list[j].getcost_fail_count,
		j, amas_utils_str_error(ethstat_list[j].last_get_cost_result),
		j, amas_utils_str_error(ethstat_list[j].get_cost_result),
		j, ethstat_list[j].last_rssiscore,
		j, ethstat_list[j].rssiscore,
		j, ethstat_list[j].getrssiscore_fail_count,
		j, amas_utils_str_error(ethstat_list[j].last_get_rssiscore_result),
		j, amas_utils_str_error(ethstat_list[j].get_rssiscore_result),
		j, ethstat_list[j].linkrate
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
		, j, ethstat_list[j].chk_internet_timeout
#endif
		);
	}
	return 0;
}

int update_wlc_info(void)
{
	char bssid_str[18];
	char nvrampar[32];
	char nvramparf[32];
    int j = 0;
    int SUMband = get_wl_count();

	for(j = 0 ; j < SUMband; j++)
	{

		snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_state", wlcstat_list[j].bandIndex);
		snprintf(nvramparf, sizeof(nvramparf), "amas_wlc%d_state_fail", wlcstat_list[j].bandIndex);

		if (wlcstat_list[j].use == 1)
		{
			wlcstat_list[j].state = get_psta_status(wlcstat_list[j].unit);

			if (wlcstat_list[j].state >= WLC_STATE_INITIALIZING && wlcstat_list[j].state <= WLC_STATE_STOPPED)
			{
				if (wlcstat_list[j].last_state != wlcstat_list[j].state  ||
					(wlcstat_list[j].getstate_fail_count == 0 && (nvram_get_int(nvrampar) != wlcstat_list[j].state)))
				{
					nvram_set_int(nvrampar, wlcstat_list[j].state);
					wlcstat_list[j].last_state = wlcstat_list[j].state;
				}

				if(wlcstat_list[j].getstate_fail_count > 0)
				{
					wlcstat_list[j].getstate_fail_count = 0;
					nvram_set_int(nvramparf, 0);
				}
			}
			else
			{
				if (wlcstat_list[j].getstate_fail_count > wlc_status_fail_count)
				{
					if (nvram_get_int(nvramparf) == 0)
					{
						dbG("Band%d connection state(%d) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].state);
						AST_DBG("Band%d connection state(%d) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].state);
						//logmessage("AST","Band%d connection(%d) state is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].state);
					}
					nvram_set_int(nvramparf, wlcstat_list[j].getstate_fail_count);
				}
				wlcstat_list[j].getstate_fail_count++;
			}

			if (wlcstat_list[j].state == WLC_STATE_CONNECTED)
			{
				wlcstat_list[j].rssi = get_psta_rssi(wlcstat_list[j].unit);
				snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_rssi", wlcstat_list[j].bandIndex);
				snprintf(nvramparf, sizeof(nvramparf), "amas_wlc%d_rssi_fail", wlcstat_list[j].bandIndex);


				if (wlcstat_list[j].rssi < 0)
				{
					if (wlcstat_list[j].last_rssi != wlcstat_list[j].rssi ||
						(wlcstat_list[j].getrssi_fail_count == 0 && (nvram_get_int(nvrampar) != wlcstat_list[j].rssi)))
					{
						nvram_set_int(nvrampar, wlcstat_list[j].rssi);
						wlcstat_list[j].last_rssi = wlcstat_list[j].rssi;
					}

					if(wlcstat_list[j].getrssi_fail_count > 0)
					{
						wlcstat_list[j].getrssi_fail_count = 0;
						nvram_set_int(nvramparf, 0);
					}
				}
				else
				{
					if (wlcstat_list[j].getrssi_fail_count > wlc_status_fail_count )
					{
						if (nvram_get_int(nvramparf) == 0)
						{
							AST_DBG("Band%d RSSI(%d) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].rssi);
							//logmessage("AST","Band%d RSSI(%d) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].rssi);
						}
						nvram_set_int(nvramparf, wlcstat_list[j].getrssi_fail_count);
					}
					wlcstat_list[j].getrssi_fail_count++;
				}

				get_pap_bssid(wlcstat_list[j].unit, bssid_str);
				string2upper(bssid_str);
				strlcpy(wlcstat_list[j].pap_bssid.bssid, bssid_str, sizeof(wlcstat_list[j].pap_bssid.bssid));

				snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_pap", wlcstat_list[j].bandIndex);
				snprintf(nvramparf, sizeof(nvramparf), "amas_wlc%d_pap_fail", wlcstat_list[j].bandIndex);

                if (strlen(wlcstat_list[j].pap_bssid.bssid) == 17 || strlen(wlcstat_list[j].pap_bssid.bssid) == 0) {
                    if (strncmp(wlcstat_list[j].pap_bssid.last_bssid, bssid_str, sizeof(wlcstat_list[j].pap_bssid.last_bssid)) ||
                        (wlcstat_list[j].getpap_fail_count == 0 && strncmp(nvram_safe_get(nvrampar), bssid_str, sizeof(wlcstat_list[j].pap_bssid.bssid)))) {
                        nvram_set(nvrampar, wlcstat_list[j].pap_bssid.bssid);
                        strlcpy(wlcstat_list[j].pap_bssid.last_bssid, wlcstat_list[j].pap_bssid.bssid, sizeof(wlcstat_list[j].pap_bssid.last_bssid));
					}

					if(wlcstat_list[j].getpap_fail_count > 0)
					{
						wlcstat_list[j].getpap_fail_count = 0;
						nvram_set_int(nvramparf, 0);
					}
				}
				else
				{
					if (wlcstat_list[j].getpap_fail_count > wlc_status_fail_count )
					{
						if (nvram_get_int(nvramparf) == 0)
						{
                            AST_DBG("Band%d pap(%s) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].pap_bssid.bssid);
							//logmessage("AST","Band%d pap(%s) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].pap_bssid);
						}
						nvram_set_int(nvramparf, wlcstat_list[j].getpap_fail_count);
					}
					wlcstat_list[j].getpap_fail_count++;
				}
			} else {  // Disconnected
				// Reset rssi.
				snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_rssi", wlcstat_list[j].bandIndex);
				nvram_set(nvrampar, "");
				// Reset P-AP BSSID info.
				snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_pap", wlcstat_list[j].bandIndex);
				nvram_set(nvrampar, "");
			}
		} else {
			wlcstat_list[j].state = get_psta_status(wlcstat_list[j].unit);

			if (wlcstat_list[j].state >= WLC_STATE_INITIALIZING && wlcstat_list[j].state <= WLC_STATE_STOPPED) {
				if (wlcstat_list[j].last_state != wlcstat_list[j].state ||
					(wlcstat_list[j].getstate_fail_count == 0 && (nvram_get_int(nvrampar) != wlcstat_list[j].state))) {
					nvram_set_int(nvrampar, wlcstat_list[j].state);
					wlcstat_list[j].last_state = wlcstat_list[j].state;
				}

				if (wlcstat_list[j].getstate_fail_count > 0) {
					wlcstat_list[j].getstate_fail_count = 0;
					nvram_set_int(nvramparf, 0);
				}
			} else {
				if (wlcstat_list[j].getstate_fail_count > wlc_status_fail_count) {
					if (nvram_get_int(nvramparf) == 0) {
						dbG("Band%d connection state(%d) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].state);
						AST_DBG("Band%d connection state(%d) is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].state);
						//logmessage("AST","Band%d connection(%d) state is invalid!\n", wlcstat_list[j].bandIndex, wlcstat_list[j].state);
					}
					nvram_set_int(nvramparf, wlcstat_list[j].getstate_fail_count);
				}
				wlcstat_list[j].getstate_fail_count++;
			}
		}
		AST_DBG("\n######################################\n"
		"wlcstat_list[%d].defif\t\t\t\t= %02X\n"
		"wlcstat_list[%d].bandIndex\t\t\t= %d\n"
		"wlcstat_list[%d].band\t\t\t\t= %d\n"
		"wlcstat_list[%d].priority\t\t\t= %d\n"
		"wlcstat_list[%d].wlcif\t\t\t\t= %s\n"
		"wlcstat_list[%d].use\t\t\t\t= %d\n"
		"wlcstat_list[%d].unit\t\t\t\t= %d\n"
		"wlcstat_list[%d].pap_bssid.last_bssid\t\t= %s\n"
		"wlcstat_list[%d].pap_bssid.bssid\t\t\t= %s\n"
		"wlcstat_list[%d].pap_bssid.bssid_2g\t\t= %s\n"
		"wlcstat_list[%d].pap_bssid.bssid_5g\t\t= %s\n"
		"wlcstat_list[%d].pap_bssid.bssid_5g1\t\t= %s\n"
		"wlcstat_list[%d].pap_bssid.bssid_6g\t\t= %s\n"
		"wlcstat_list[%d].getpap_fail_count\t\t= %d\n"
		"wlcstat_list[%d].last_state\t\t\t= %d\n"
		"wlcstat_list[%d].state\t\t\t\t= %d\n"
		"wlcstat_list[%d].getstate_fail_count\t\t= %d\n"
		"wlcstat_list[%d].last_rssi\t\t\t= %d\n"
		"wlcstat_list[%d].rssi\t\t\t\t= %d\n"
		"wlcstat_list[%d].getrssi_fail_count\t\t= %d\n"
		"wlcstat_list[%d].last_cost\t\t\t= %.1f\n"
		"wlcstat_list[%d].cost\t\t\t\t= %.1f\n"
		"wlcstat_list[%d].papcost\t\t\t\t= %.1f\n"
		"wlcstat_list[%d].get_cost_result\t\t\t= %s\n"
		"wlcstat_list[%d].getpaplastbyte_fail_count\t= %d\n"
		"wlcstat_list[%d].last_get_paplastbyte_result\t= %s\n"
		"wlcstat_list[%d].get_paplastbyte_result\t\t= %s\n"
		"wlcstat_list[%d].last_rssiscore\t\t\t= %d\n"
		"wlcstat_list[%d].rssiscore\t\t\t= %d\n"
		"wlcstat_list[%d].getrssiscore_fail_count\t\t= %d\n",

		j, wlcstat_list[j].defif,
		j, wlcstat_list[j].bandIndex,
		j, wlcstat_list[j].band,
		j, wlcstat_list[j].priority,
		j, wlcstat_list[j].wlcif,
		j, wlcstat_list[j].use,
		j, wlcstat_list[j].unit,
		j, wlcstat_list[j].pap_bssid.last_bssid,
		j, wlcstat_list[j].pap_bssid.bssid,
		j, wlcstat_list[j].pap_bssid.bssid_2g,
		j, wlcstat_list[j].pap_bssid.bssid_5g,
		j, wlcstat_list[j].pap_bssid.bssid_5g1,
		j, wlcstat_list[j].pap_bssid.bssid_6g,
		j, wlcstat_list[j].getpap_fail_count,
		j, wlcstat_list[j].last_state,
		j, wlcstat_list[j].state,
		j, wlcstat_list[j].getstate_fail_count,
		j, wlcstat_list[j].last_rssi,
		j, wlcstat_list[j].rssi,
		j, wlcstat_list[j].getrssi_fail_count,
		j, wlcstat_list[j].last_cost,
		j, wlcstat_list[j].cost,
		j, wlcstat_list[j].papcost,
		j, amas_utils_str_error(wlcstat_list[j].get_cost_result),
		j, wlcstat_list[j].getpaplastbyte_fail_count,
		j, amas_utils_str_error(wlcstat_list[j].last_get_paplastbyte_result),
		j, amas_utils_str_error(wlcstat_list[j].get_paplastbyte_result),
		j, wlcstat_list[j].last_rssiscore,
		j, wlcstat_list[j].rssiscore,
		j, wlcstat_list[j].getrssiscore_fail_count);
	}
	return 0;
}

/**
 * @brief Get linkrate for ethernet & power line
 *
 */
void update_linkrate(void)
{
    int SUMeth = get_eth_count();
    int j;
	int linkrate;
	char nvram_buf[] = "amas_ethXXX_linkrate";

    for (j = 0; j < SUMeth; j++) {
        if (ethstat_list[j].use == 1) {
            if (ethstat_list[j].state > 0) {
		linkrate = get_uplinkports_linkrate(ethstat_list[j].ethif);
		ethstat_list[j].last_linkrate = ethstat_list[j].linkrate;
		ethstat_list[j].linkrate = linkrate;
				if (ethstat_list[j].linkrate <= 0)  //  something wrong. Give a default linkrate 1G
					ethstat_list[j].linkrate = 1000;
            } else {
                ethstat_list[j].linkrate = -1;
            }
        } else {
            ethstat_list[j].linkrate = -1;
        }
		snprintf(nvram_buf, sizeof(nvram_buf), "amas_eth%d_linkrate", ethstat_list[j].ethIndex);
		nvram_set_int(nvram_buf, ethstat_list[j].linkrate);
    }
}

static int update_cost(void)
{
	char wlcif[16] = {}, wlcphyif[16] = {};
	char *next = NULL;
	char nvrampar[32];
	char nvrampar_papcost[32] = {};
	char nvramparf[32];
	char nvrampar_res[32];
	char nvramparf_last_res[32];
    int j = 0;
    int SUMband = get_wl_count();
    int SUMeth = get_eth_count();
    int rssi_score;
    double max_power_5G=0;
    double max_power_6G=0;
    int num5g = num_of_5g_if();
    double power_factor=0;
    int aimesh_alg = aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

#ifdef RTCONFIG_DPSTA
	int Is_dpsta = dpsta_mode();
#endif

	for (j = 0; j < SUMband; j ++)
	{
		int papcost_int = -1;
		snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_cost", wlcstat_list[j].bandIndex);
		snprintf(nvrampar_papcost, sizeof(nvrampar_papcost), "amas_wlc%d_papcost", wlcstat_list[j].bandIndex);
		snprintf(nvrampar_res, sizeof(nvrampar_res), "amas_wlc%d_cost_result", wlcstat_list[j].bandIndex);

		if (wlcstat_list[j].use == 1)
		{
			// Get current cost & p-ap cost
			if(aimesh_alg == AIMESH_ALG_COST && wlcstat_list[j].state == WLC_STATE_CONNECTED) {
				if (nvram_get(nvrampar)) {
					if (nvram_get_int(nvrampar) >= 0)
						wlcstat_list[j].cost = nvram_get_int(nvrampar) / 10.0;
					else
						wlcstat_list[j].cost = nvram_get_int(nvrampar);
				} else {
					wlcstat_list[j].cost = -1;
				}
				if (nvram_get(nvrampar_papcost)) {
					if (nvram_get_int(nvrampar_papcost) >= 0)
						wlcstat_list[j].papcost = nvram_get_int(nvrampar_papcost) / 10.0;
					else
						wlcstat_list[j].papcost = nvram_get_int(nvrampar_papcost);
				} else {
					wlcstat_list[j].papcost = -1;
				}
			}

			if (wlcstat_list[j].state == WLC_STATE_CONNECTED)
			{
#ifdef RTCONFIG_DPSTA
				if (Is_dpsta) {
#if defined(RTCONFIG_AMAS_WGN) && defined(WGN_HAVE_VLAN0) 
						if (nvram_get_int("wgn_enabled") == 1) 
							snprintf(wlcif, sizeof(wlcif), "%s.0", nvram_safe_get("sta_phy_ifnames"));
						else 
							snprintf(wlcif, sizeof(wlcif), "%s", nvram_safe_get("sta_phy_ifnames"));
#else
						snprintf(wlcif, sizeof(wlcif), "%s", nvram_safe_get("sta_phy_ifnames"));
#endif					
				}
				else
#endif
				{
#ifdef RTCONFIG_AMAS_WGN
					if (nvram_get_int("wgn_enabled") == 1) {
						foreach(wlcphyif, nvram_safe_get("sta_phy_ifnames"), next) {
							if (strcmp(wlcphyif, wlcstat_list[j].wlcif) == 0) {
#if defined(WGN_HAVE_VLAN0)
								snprintf(wlcif, sizeof(wlcif), "%s.0", wlcphyif);
#else									
								snprintf(wlcif, sizeof(wlcif), "%s", wlcphyif);
#endif
								break;
							}
						}
						if (strlen(wlcif) == 0)
							snprintf(wlcif, sizeof(wlcif), "%s", wlcstat_list[j].wlcif);
					} else
#endif
						snprintf(wlcif, sizeof(wlcif), "%s", wlcstat_list[j].wlcif);
				}

				// Get P-AP cost
				wlcstat_list[j].get_cost_result = amas_get_cost(wlcif, wlcstat_list[j].bandIndex, SUMband, wlcstat_list[j].pap_bssid.bssid, &papcost_int);

				if (wlcstat_list[j].get_cost_result == AMAS_RESULT_SUCCESS)
				{
					if (nvram_get(nvrampar_papcost))
						AST_DBG("Band(%d) Current P-AP cost: %d, Last P-AP cost: %d\n", wlcstat_list[j].bandIndex , papcost_int, nvram_get_int(nvrampar_papcost));
					else
						AST_DBG("Band(%d) Current P-AP cost: %d, No Last P-AP cost.\n", wlcstat_list[j].bandIndex, papcost_int);

					if (aimesh_alg == AIMESH_ALG_COST) {
						if (wlcstat_list[j].papcost < 0 || papcost_int != nvram_get_int(nvrampar_papcost) || wlcstat_list[j].cost < 0 || wlcstat_list[j].renew_cost == 1) {
							if (papcost_int > 0)
								wlcstat_list[j].cost = (float)papcost_int / 10.0;
							else
								wlcstat_list[j].cost = (float)papcost_int;

							char wl_hw_txchain[] = "wlXXXXXX_hw_txchain";
							int chain = 0, antenna = 0, bandwidth = 0, using_5gRssi = 0;

							snprintf(wl_hw_txchain, sizeof(wl_hw_txchain), "wl%d_hw_txchain", wlcstat_list[j].unit);
							chain = nvram_get_int(wl_hw_txchain);
							while (chain > 0) {
								if (chain % 2 == 1)
									antenna++;
								chain = chain / 2;
							}
							/* Bandwidth */
							bandwidth = wl_get_bw(wlcstat_list[j].unit);
							AST_DBG("Band(%d) wlcstat_list[%d].unit = %d. wl_get_bw bandwidth =%d\n", wlcstat_list[j].bandIndex, j,wlcstat_list[j].unit , bandwidth );
							if (bandwidth != 20 && bandwidth != 40 && bandwidth != 80 && bandwidth != 160) {
								switch (wlcstat_list[j].band) {
									case 2:  // 2.4G
										bandwidth = 20;
										break;
									case 5: // 5G
									case 51:
									case 52:
										bandwidth = 80;
										break;
									case 6:  // 6G
										bandwidth = 160;
										break;
									default:  // setting to 20MHz
										bandwidth = 20;
										break;
								}
							}
							/* XG_RSSI_score = XG_RSSI + 10log(XG antenna/4) + 10log(bandwidth/80)  log10 */
							if (antenna > 0)
								rssi_score = wlcstat_list[j].rssi + (int)(10 * (log10(antenna)- log10(4))) + (int)(10 * (log10(bandwidth)-log10(80)));  // default
							else
								rssi_score = wlcstat_list[j].rssi + (int)(10 * (log10(bandwidth)-log10(80)));  // default
						
							AST_DBG("Band(%d) rssi_score = %d.\n", wlcstat_list[j].bandIndex, rssi_score);
							if (wlcstat_list[j].band == 6 || wlcstat_list[j].band == 2) {
								/* Check 2.4G/6G P-AP is the same as 5G/5G1 P-AP */
								int i, index_5g = -1;
								for (i = 0; i < SUMband; i++) {
									if (wlcstat_list[i].use == 1) {
										if (wlcstat_list[i].band == 52 || wlcstat_list[i].band == 5) {
											index_5g = i;
										}
									}
								}
								if (index_5g >= 0) {
									if ((wlcstat_list[index_5g].state == WLC_STATE_CONNECTED) &&
										(!strcmp(wlcstat_list[index_5g].pap_bssid.bssid_6g, wlcstat_list[j].pap_bssid.bssid) ||
									    !strcmp(wlcstat_list[index_5g].pap_bssid.bssid_2g, wlcstat_list[j].pap_bssid.bssid)) ) {
									    	AST_DBG("Band(%d) using 5g.rssi (%d) antenna (%d) bandwidth = (%d) .\n", wlcstat_list[j].bandIndex, wlcstat_list[index_5g].rssi , antenna , bandwidth);
										if(wlcstat_list[j].band == 6){
									    		if(num5g>1){
									    			max_power_5G = get_wifi_tx_maxpower(52);
									    		}else
									    		{
									    			max_power_5G = get_wifi_tx_maxpower(5);
									    		}
									    		max_power_6G = get_wifi_tx_maxpower(6);
									    		
									    		if(strlen(nvram_safe_get("power_factor"))>0){
									    			power_factor = atof(nvram_safe_get("power_factor"));
									    		}
									    		else{
									    			power_factor = 1.2;
									    		}
									    		
									    		AST_DBG("Band(%d) max_power_6G = %f  max_power_5G = %f power_factor=%f.\n", wlcstat_list[j].bandIndex, max_power_6G , max_power_5G,power_factor);
									    		if (antenna > 0)
									    			rssi_score = wlcstat_list[index_5g].rssi + (int)(10 * (log10(antenna)- log10(4))) + (int)(10 * (log10(bandwidth)-log10(80))) + (int)((max_power_6G - max_power_5G)*power_factor);
									    		else
									    			rssi_score = wlcstat_list[index_5g].rssi + (int)(10 * (log10(bandwidth)-log10(80))) + (int)((max_power_6G - max_power_5G)*power_factor);
									    	
										}
										else{
											if (antenna > 0)
												rssi_score = wlcstat_list[index_5g].rssi + (int)(10 * (log10(antenna)- log10(4))) + (int)(10 * (log10(bandwidth)-log10(80)));
											else
												rssi_score = wlcstat_list[index_5g].rssi + (int)(10 * (log10(bandwidth)-log10(80)));
										}
										AST_DBG("Band(%d) 5G RSSI(%d) antenna_check = %d. bandwidth_check =%d\n", wlcstat_list[j].bandIndex, wlcstat_list[index_5g].rssi, (int)(10 * (log10(antenna)- log10(4))) ,(int)(10 * (log10(bandwidth)-log10(80))));
										
										AST_DBG("Band(%d) rssi_score = %d.\n", wlcstat_list[j].bandIndex, rssi_score);
										AST_DBG("Using 5G RSSI(%d) to calculate 2.4G/6G cost\n", wlcstat_list[index_5g].rssi);
										using_5gRssi = 1;
									} else {
										AST_DBG("Using Original RSSI(%d) to calculate 2.4G/6G cost\n", wlcstat_list[j].rssi);
									}
								}
							} else {
								using_5gRssi = 1;
							}

							if (wlcstat_list[j].cost >= 0) {
								if (rssi_score > -60)
									wlcstat_list[j].cost = wlcstat_list[j].cost + 1;
								else if (rssi_score > -70)
									wlcstat_list[j].cost = wlcstat_list[j].cost + 1 + 1 * (-60 - rssi_score) / 10.0;
								else if (rssi_score > -80)
									wlcstat_list[j].cost = wlcstat_list[j].cost + 2 + 4 * (-70 - rssi_score) / 10.0;
								else
									wlcstat_list[j].cost = wlcstat_list[j].cost + 6 + 10 * (-80 - rssi_score) / 10.0;
							}
							AST_DBG("Band(%d) cost = %f.\n", wlcstat_list[j].bandIndex, wlcstat_list[j].cost);

							//  DWB/NON-DWB cost weighted
							if (SUMband == 2) {  // Dual-Band
								wlcstat_list[j].cost = wlcstat_list[j].cost + 1;
							} else if (SUMband >= 3) {
								if (wlcstat_list[j].unit != nvram_get_int("dwb_band"))
									wlcstat_list[j].cost = wlcstat_list[j].cost + 1;
							}

							if (using_5gRssi != 1) {
								if (wlcstat_list[j].defif == WL2G_U)
									wlcstat_list[j].cost = wlcstat_list[j].cost + 16;  // 2.4G extra weight if cost by its RSSI
							}

							if (papcost_int > 0) {
								wlcstat_list[j].papcost = (float)papcost_int / 10.0;
								nvram_set_int(nvrampar_papcost, papcost_int);
							} else {
								wlcstat_list[j].papcost = (float)papcost_int;
								nvram_set_int(nvrampar_papcost, papcost_int);
							}
							wlcstat_list[j].renew_cost = 0;
						}
					} else
						wlcstat_list[j].cost = (float)papcost_int;

					if (wlcstat_list[j].last_cost != wlcstat_list[j].cost ||
						((nvram_get_int(nvrampar) / 10.0) != wlcstat_list[j].cost))
					{
						nvram_set_int(nvrampar, wlcstat_list[j].cost * 10);
						wlcstat_list[j].last_cost = wlcstat_list[j].cost;
					}
				}

				if (nvram_get_int(nvrampar_res) != wlcstat_list[j].get_cost_result) {
					AST_DBG("update cost result (%d) -> (%d)\n", nvram_get_int(nvrampar_res), wlcstat_list[j].get_cost_result);
					nvram_set_int(nvrampar_res, wlcstat_list[j].get_cost_result);
				}
			}
			else
			{
				nvram_set_int(nvrampar, INIT_CODE);
				nvram_set_int(nvrampar_papcost, INIT_CODE);
				wlcstat_list[j].cost = -1;
				wlcstat_list[j].papcost = -1;
				wlcstat_list[j].last_cost = INIT_CODE;
				wlcstat_list[j].renew_cost = 1;
				nvram_set(nvrampar_res, "");
			}
		} else {
			nvram_set_int(nvrampar, INIT_CODE);
			nvram_set_int(nvrampar_papcost, INIT_CODE);
			wlcstat_list[j].cost = -1;
			wlcstat_list[j].papcost = -1;
			wlcstat_list[j].last_cost = INIT_CODE;
			wlcstat_list[j].renew_cost = 1;
			nvram_set(nvrampar_res, "");
		}
	}


	for (j = 0; j < SUMeth; j ++)
	{
		int papcost_int = -1;
		snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_cost", ethstat_list[j].ethIndex);
		snprintf(nvrampar_papcost, sizeof(nvrampar_papcost), "amas_eth%d_papcost", ethstat_list[j].ethIndex);
		snprintf(nvramparf, sizeof(nvramparf), "amas_eth%d_cost_fail", ethstat_list[j].ethIndex);
		snprintf(nvrampar_res, sizeof(nvrampar_res), "amas_eth%d_cost_result", ethstat_list[j].ethIndex);
		snprintf(nvramparf_last_res, sizeof(nvramparf_last_res), "amas_eth%d_last_cost_result", ethstat_list[j].ethIndex);

		if (ethstat_list[j].use == 1)
		{
			if (ethstat_list[j].state > 0) {

				ethstat_list[j].get_cost_result = amas_get_cost(ethstat_list[j].ethif, ethstat_list[j].ethIndex, SUMeth, NULL, &papcost_int);

				if (ethstat_list[j].get_cost_result == AMAS_RESULT_SUCCESS)
				{
					if (nvram_get(nvrampar_papcost))
						AST_DBG("ETH(%d) Current P-AP cost: %d, Last P-AP cost: %d\n", ethstat_list[j].ethIndex , papcost_int, nvram_get_int(nvrampar_papcost));
					else
						AST_DBG("ETH(%d) Current P-AP cost: %d, No Last P-AP cost.\n", ethstat_list[j].ethIndex, papcost_int);

					// ethstat_list[j].cost = (float)cost_int;
					if (aimesh_alg == AIMESH_ALG_COST) {
						// Ethernet
						if (!nvram_get(nvrampar_papcost) || papcost_int != nvram_get_int(nvrampar_papcost) || ethstat_list[j].cost < 0
							|| (ethstat_list[j].ethType >= ETH_TYPE_PLC && abs(ethstat_list[j].linkrate - ethstat_list[j].last_linkrate) > 50 
							     && cal_plc_cost(ethstat_list[j].cost, ethstat_list[j].last_linkrate) != cal_plc_cost(ethstat_list[j].cost, ethstat_list[j].linkrate))
						   ) {

							if (papcost_int > 0)
								ethstat_list[j].cost = (float)papcost_int / 10.0;
							else
								ethstat_list[j].cost = (float)papcost_int;

							if (ethstat_list[j].ethType < ETH_TYPE_PLC) {
								if (ethstat_list[j].cost >= 0) {
									if (ethstat_list[j].linkrate >= 0) {
										if (ethstat_list[j].linkrate <= 10)
											ethstat_list[j].cost = ethstat_list[j].cost + 9;
										else if (ethstat_list[j].linkrate <= 100)
											ethstat_list[j].cost = ethstat_list[j].cost + 3;
									}
								}
							} else { //Power line
								if (ethstat_list[j].cost >= 0) {
									ethstat_list[j].cost = cal_plc_cost(ethstat_list[j].cost, ethstat_list[j].linkrate);
								}
							}
							if (papcost_int > 0) {
								ethstat_list[j].papcost = (float)papcost_int / 10.0;
								nvram_set_int(nvrampar_papcost, papcost_int);
							} else {
								ethstat_list[j].papcost = (float)papcost_int;
								nvram_set_int(nvrampar_papcost, papcost_int);
							}
						}
					} else {
						ethstat_list[j].cost = (float)papcost_int;
					}

					if (ethstat_list[j].last_cost != ethstat_list[j].cost ||
						(ethstat_list[j].getcost_fail_count == 0 && ((nvram_get_int(nvrampar) / 10.0) != ethstat_list[j].cost)))
					{
						nvram_set_int(nvrampar, ethstat_list[j].cost * 10);
						ethstat_list[j].last_cost = ethstat_list[j].cost;
					}
					if(ethstat_list[j].getcost_fail_count > 0) {
						ethstat_list[j].getcost_fail_count = 0;
						nvram_set_int(nvramparf, 0);
					}
					ethstat_list[j].last_get_cost_result = ethstat_list[j].get_cost_result;
				} else {
					if (ethstat_list[j].getcost_fail_count > eth_status_fail_count) {
						if (nvram_get_int(nvramparf) == 0) {
							AST_DBG("eth cost(%.1f) is invalid(fail_count = %d)!\n", ethstat_list[j].cost, eth_status_fail_count);
							logmessage("AST","eth cost(%d) is invalid(fail_count = %d)!\n", ethstat_list[j].cost, eth_status_fail_count);
						}
						nvram_set_int(nvrampar, ERROR_CODE);
						ethstat_list[j].cost = ERROR_CODE;
						nvram_set_int(nvrampar_papcost, ERROR_CODE);
						ethstat_list[j].papcost = ERROR_CODE;
					}
					nvram_set_int(nvramparf, ethstat_list[j].getcost_fail_count);
					ethstat_list[j].getcost_fail_count++;
				}

				if ((ethstat_list[j].last_get_cost_result != ethstat_list[j].get_cost_result) &&
					(ethstat_list[j].last_get_cost_result == AMAS_RESULT_SUCCESS || ethstat_list[j].get_cost_result == AMAS_RESULT_SUCCESS)) {
					nvram_set_int(nvramparf_last_res, ethstat_list[j].last_get_cost_result);
					nvram_set_int(nvrampar_res, ethstat_list[j].get_cost_result);
					AST_DBG("eth cost(%.1f), get_cost_result(%s), last_cost(%.1f), last_get_cost_result(%s)\n", ethstat_list[j].cost, amas_utils_str_error(ethstat_list[j].get_cost_result), ethstat_list[j].last_cost, amas_utils_str_error(ethstat_list[j].last_get_cost_result));
					//logmessage("AST","eth cost(%d), get_cost_result(%s), last_cost(%d), last_get_cost_result(%s)\n", ethstat_list[j].cost, amas_utils_str_error(ethstat_list[j].get_cost_result), ethstat_list[j].last_cost, amas_utils_str_error(ethstat_list[j].last_get_cost_result));
				}
			}
			else
			{
				nvram_set_int(nvrampar, INIT_CODE);
				ethstat_list[j].cost = -1;
				nvram_set_int(nvrampar_papcost, INIT_CODE);
				ethstat_list[j].papcost = -1;
				ethstat_list[j].last_cost = INIT_CODE;
				nvram_set_int(nvramparf, 0);
				nvram_set(nvrampar_res, "");
				nvram_set(nvramparf_last_res, "");
			}
		}
		else
		{
			nvram_set_int(nvrampar, INIT_CODE);
			ethstat_list[j].cost = -1;
			nvram_set_int(nvrampar_papcost, INIT_CODE);
			ethstat_list[j].papcost = -1;
			ethstat_list[j].last_cost = INIT_CODE;
			nvram_set_int(nvramparf, 0);
			nvram_set(nvrampar_res, "");
			nvram_set(nvramparf_last_res, "");
		}
	}

	return 0;
}


int update_rssi_score(void)
{

	char nvrampar[32];
	char nvramparf[32];
	char nvrampar_res[32];
	char nvramparf_last_res[32];
    int j = 0;
    int SUMband = get_wl_count();
    int SUMeth = get_eth_count();

	for(j = 0; j < SUMband; j++)
	{
		snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_rssiscore", wlcstat_list[j].bandIndex);

		if (wlcstat_list[j].use == 1 && wlcstat_list[j].state == WLC_STATE_CONNECTED)
		{

			wlcstat_list[j].rssiscore = nvram_get_int(nvrampar);

			if (wlcstat_list[j].rssiscore == 100)
			{
				if (wlcstat_list[j].rssi < 0 && wlcstat_list[j].get_cost_result == AMAS_RESULT_SUCCESS)
				{
					//RSSIscore = RSSI – (6 * layer)
					wlcstat_list[j].rssiscore = wlcstat_list[j].rssi  - (6 * wlcstat_list[j].cost);
					AST_DBG("Can't get Band[%d] RSSIscore from amas_wlcconnect. Self-calculation (rssiscore = %d)!\n", wlcstat_list[j].band, wlcstat_list[j].rssiscore);
					nvram_set_int(nvrampar, wlcstat_list[j].rssiscore);
				}
			}
		}
	}

	for(j = 0; j < SUMeth; j++)
	{
		snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_rssiscore", ethstat_list[j].ethIndex);
		snprintf(nvramparf, sizeof(nvramparf), "amas_eth%d_rssiscore_fail", ethstat_list[j].ethIndex);
		snprintf(nvrampar_res, sizeof(nvrampar_res), "amas_eth%d_rssiscore_result", ethstat_list[j].ethIndex);
		snprintf(nvramparf_last_res, sizeof(nvramparf_last_res), "amas_eth%d_last_rssiscore_result", ethstat_list[j].ethIndex);

		if (ethstat_list[j].use == 1)
		{
			if (ethstat_list[j].state > 0)
			{
				ethstat_list[j].get_rssiscore_result = amas_get_rssi_score(ethstat_list[j].ethif, ethstat_list[j].ethIndex, SUMeth, NULL, &ethstat_list[j].rssiscore);

				if (ethstat_list[j].get_rssiscore_result == AMAS_RESULT_SUCCESS)
				{
					if (ethstat_list[j].last_rssiscore != ethstat_list[j].rssiscore ||
						(ethstat_list[j].getrssiscore_fail_count == 0 && (nvram_get_int(nvrampar) != ethstat_list[j].rssiscore)))
					{
						nvram_set_int(nvrampar, ethstat_list[j].rssiscore);
						ethstat_list[j].last_rssiscore = ethstat_list[j].rssiscore;
					}

					if(ethstat_list[j].getrssiscore_fail_count > 0)
					{
						ethstat_list[j].getrssiscore_fail_count = 0;
						nvram_set_int(nvramparf, 0);
					}
					ethstat_list[j].last_get_rssiscore_result = ethstat_list[j].rssiscore;
				}
				else
				{
					if (ethstat_list[j].getrssiscore_fail_count > eth_status_fail_count)
					{
						if (nvram_get_int(nvramparf) == 0)
						{
							AST_DBG("eth rssiscore(%d) is invalid(fail_count = %d)!\n", ethstat_list[j].rssiscore, wlc_status_fail_count);
							//logmessage("AST","eth rssiscore(%d) is invalid(fail_count = %d)!\n", ethstat_list[j].rssiscore, wlc_status_fail_count);
						}
						nvram_set_int(nvrampar, 100);
					}
					nvram_set_int(nvramparf, ethstat_list[j].getrssiscore_fail_count);
					ethstat_list[j].getrssiscore_fail_count++;
				}


				if ((ethstat_list[j].last_get_rssiscore_result != ethstat_list[j].get_rssiscore_result) &&
					(ethstat_list[j].last_get_rssiscore_result == AMAS_RESULT_SUCCESS || ethstat_list[j].get_rssiscore_result == AMAS_RESULT_SUCCESS))
				{
					nvram_set(nvramparf_last_res, amas_utils_str_error(ethstat_list[j].last_get_rssiscore_result));
					nvram_set(nvrampar_res, amas_utils_str_error(ethstat_list[j].get_rssiscore_result));
					AST_DBG("eth rssiscore(%d), get_rssiscore_result(%s), last_rssiscore(%d), last_get_rssiscore_result(%s)\n", ethstat_list[j].rssiscore, amas_utils_str_error(ethstat_list[j].get_rssiscore_result), ethstat_list[j].last_rssiscore, amas_utils_str_error(ethstat_list[j].last_get_rssiscore_result));
					//logmessage("AST","eth rssiscore(%d), get_rssiscore_result(%s), last_rssiscore(%d), last_get_rssiscore_result(%s)\n", ethstat_list[j].rssiscore, amas_utils_str_error(ethstat_list[j].get_rssiscore_result), ethstat_list[j].last_rssiscore, amas_utils_str_error(ethstat_list[j].last_get_rssiscore_result));
				}
			}
			else
			{
				nvram_set_int(nvrampar, 100);
				nvram_set_int(nvramparf, 0);
				nvram_set(nvrampar_res, "");
				nvram_set(nvramparf_last_res, "");
			}
		}
		else
		{
			nvram_set_int(nvrampar, 100);
			nvram_set_int(nvramparf, 0);
			nvram_set(nvrampar_res, "");
			nvram_set(nvramparf_last_res, "");
		}
	}

	return 0;
}

#ifdef RTCONFIG_BCN_RPT
static void update_pap_bssid(int set, int index, char *ap2g, char *ap5g, char *ap5g1, char *ap6g) {
    if (set) {
        if (strlen(ap2g) == 17) {  // Support 2.4G
            /* P-AP 2.4G */
            strncpy(wlcstat_list[index].pap_bssid.bssid_2g, ap2g, sizeof(wlcstat_list[index].pap_bssid.bssid_2g));
        }
        if (strlen(ap5g) == 17) {  // Support 5G
            /* P-AP 5G */
            strncpy(wlcstat_list[index].pap_bssid.bssid_5g, ap5g, sizeof(wlcstat_list[index].pap_bssid.bssid_5g));
        }
        if (strlen(ap5g1) == 17) {  // Support 5G1
            /* P-AP 5G */
            strncpy(wlcstat_list[index].pap_bssid.bssid_5g1, ap5g1, sizeof(wlcstat_list[index].pap_bssid.bssid_5g1));
        }
        if (strlen(ap6g) == 17) {  // Support 6G
            /* P-AP 5G */
            strncpy(wlcstat_list[index].pap_bssid.bssid_6g, ap6g, sizeof(wlcstat_list[index].pap_bssid.bssid_6g));
        }
    } else {
        memset(wlcstat_list[index].pap_bssid.bssid_2g, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_2g));
        memset(wlcstat_list[index].pap_bssid.bssid_5g, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_5g));
        memset(wlcstat_list[index].pap_bssid.bssid_5g1, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_5g1));
        memset(wlcstat_list[index].pap_bssid.bssid_6g, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_6g));
    }
}
#else
static void update_pap_bssid(int set, int index, char *wifi_lastbyte) {
    if (set) {
		unsigned char wifi_lastbyte_hex[17] = {0};
		STR2HEX2(wifi_lastbyte_hex, wifi_lastbyte, strlen(wifi_lastbyte));
		int last_byte_count = strlen(wifi_lastbyte) / 2;
        char set_lasybyte_str[8] = {0};
        char bssid[18] = {};

		memset(bssid, 0x00, sizeof(bssid));
        if (last_byte_count > 0) {  // Support 2.4G
            /* P-AP 2.4G */
            snprintf(set_lasybyte_str, sizeof(set_lasybyte_str), "%02X", wifi_lastbyte_hex[0]);
            strncpy(bssid, wlcstat_list[index].pap_bssid.bssid, 15);
            strncat(bssid, set_lasybyte_str, 2);
            strncpy(wlcstat_list[index].pap_bssid.bssid_2g, bssid, sizeof(wlcstat_list[index].pap_bssid.bssid_2g));
        }
		memset(bssid, 0x00, sizeof(bssid));
        if (last_byte_count > 1 && wifi_lastbyte_hex[1] != 0x00) {  // Support 5G
            /* P-AP 5G */
            snprintf(set_lasybyte_str, sizeof(set_lasybyte_str), "%02X", wifi_lastbyte_hex[1]);
            strncpy(bssid, wlcstat_list[index].pap_bssid.bssid, 15);
            strncat(bssid, set_lasybyte_str, 2);
            strncpy(wlcstat_list[index].pap_bssid.bssid_5g, bssid, sizeof(wlcstat_list[index].pap_bssid.bssid_5g));
        }
		memset(bssid, 0x00, sizeof(bssid));
        if (last_byte_count > 2 && wifi_lastbyte_hex[2] != 0x00) {  // Support 5G1
            /* P-AP 5G */
            snprintf(set_lasybyte_str, sizeof(set_lasybyte_str), "%02X", wifi_lastbyte_hex[2]);
            strncpy(bssid, wlcstat_list[index].pap_bssid.bssid, 15);
            strncat(bssid, set_lasybyte_str, 2);
            strncpy(wlcstat_list[index].pap_bssid.bssid_5g1, bssid, sizeof(wlcstat_list[index].pap_bssid.bssid_5g1));
        }
		memset(bssid, 0x00, sizeof(bssid));
        if (last_byte_count > 3 && wifi_lastbyte_hex[3] != 0x00) {  // Support 6G
            /* P-AP 5G */
            snprintf(set_lasybyte_str, sizeof(set_lasybyte_str), "%02X", wifi_lastbyte_hex[3]);
            strncpy(bssid, wlcstat_list[index].pap_bssid.bssid, 15);
            strncat(bssid, set_lasybyte_str, 2);
            strncpy(wlcstat_list[index].pap_bssid.bssid_6g, bssid, sizeof(wlcstat_list[index].pap_bssid.bssid_6g));
        }
    } else {
        memset(wlcstat_list[index].pap_bssid.bssid_2g, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_2g));
        memset(wlcstat_list[index].pap_bssid.bssid_5g, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_5g));
        memset(wlcstat_list[index].pap_bssid.bssid_5g1, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_5g1));
        memset(wlcstat_list[index].pap_bssid.bssid_6g, 0x00, sizeof(wlcstat_list[index].pap_bssid.bssid_6g));
    }
}
#endif

#ifdef RTCONFIG_BCN_RPT
struct ap_node_s {
    char bssid_2g[18];
    char bssid_5g[18];
    char bssid_5g1[18];
    char bssid_6g[18];
    struct ap_node_s *next;
} ap_node_s;

static void free_list(struct ap_node_s *head) {
	struct ap_node_s *tmp = NULL, *next = NULL;
	tmp = head;
	while (tmp != NULL) {
		next = tmp->next;
		free(tmp);
		tmp = next;
	}
}

static void update_lastbyte(void) {
    json_object *aplist = NULL;
    json_object *apentryObj = NULL;
    json_object *ap2gObj = NULL;
    json_object *ap5gObj = NULL;
    json_object *ap5g1Obj = NULL;
    json_object *ap6gObj = NULL;
    static int file_not_exist = 0;
    int SUMband = get_wl_count();
    int i, y, ap_index = 0,ap_count = 0;
    char index_str[6] = {0}, amas_wlc_target_same_ap[] = "amas_wlcXXX_target_same_ap";
	int connected = 0;
	struct ap_node_s *ap_node_head = NULL, *ap_node_tail = NULL;

    if ((aplist = json_object_from_file("/tmp/aplist.json")) == NULL) {
        AST_DBG("aplist is not exist\n");
		file_not_exist++;
		goto UPDATE_LASTBYTE_EXIT;
    }

	while (1) {
		snprintf(index_str, sizeof(index_str), "%d", ap_index);
		json_object_object_get_ex(aplist, index_str, &apentryObj);
		if (apentryObj == NULL) {
			break;
		}
		struct ap_node_s *ap_node = malloc(sizeof(struct ap_node_s));
		memset(ap_node, 0x0, sizeof(struct ap_node_s));

		ap_count++;
		if (ap_node == NULL) {
			file_not_exist++;
			goto UPDATE_LASTBYTE_EXIT;
		}
		file_not_exist = 0;
		json_object_object_get_ex(apentryObj, CFG_STR_AP2G, &ap2gObj);
		if (ap2gObj)
			strncpy(ap_node->bssid_2g, json_object_get_string(ap2gObj), sizeof(ap_node->bssid_2g));
		json_object_object_get_ex(apentryObj, CFG_STR_AP5G, &ap5gObj);
		if (ap5gObj)
			strncpy(ap_node->bssid_5g, json_object_get_string(ap5gObj), sizeof(ap_node->bssid_5g));
		json_object_object_get_ex(apentryObj, CFG_STR_AP5G1, &ap5g1Obj);
		if (ap5g1Obj)
			strncpy(ap_node->bssid_5g1, json_object_get_string(ap5g1Obj), sizeof(ap_node->bssid_5g1));
		json_object_object_get_ex(apentryObj, CFG_STR_AP6G, &ap6gObj);
		if (ap6gObj)
			strncpy(ap_node->bssid_6g, json_object_get_string(ap6gObj), sizeof(ap_node->bssid_6g));

		AST_DBG("AP NODE(%d) 2.4G(%s) 5G(%s) 5G1(%s) 6G(%s)\n",
		ap_count - 1, ap_node->bssid_2g, ap_node->bssid_5g, ap_node->bssid_5g1, ap_node->bssid_6g);

		if (ap_node_head == NULL) {
			ap_node_head = ap_node;
		} else {
			if (ap_node_tail == NULL)
				ap_node_head->next = ap_node;
			else
				ap_node_tail->next = ap_node;
			ap_node_tail = ap_node;
		}
		ap_index++;
	}

	for (i = 0; i < SUMband; i++) {
		if (wlcstat_list[i].use == 1) {
			if (wlcstat_list[i].state == WLC_STATE_CONNECTED) {
				connected++;
				// P-AP BSSID in aplist?
				struct ap_node_s *ap_node_tmp = ap_node_head;
				while (ap_node_tmp) {
					if (!strcmp(wlcstat_list[i].pap_bssid.bssid, ap_node_tmp->bssid_2g) ||
					!strcmp(wlcstat_list[i].pap_bssid.bssid, ap_node_tmp->bssid_5g) ||
					!strcmp(wlcstat_list[i].pap_bssid.bssid, ap_node_tmp->bssid_5g1) ||
					!strcmp(wlcstat_list[i].pap_bssid.bssid, ap_node_tmp->bssid_6g))
						break;
					ap_node_tmp = ap_node_tmp->next;
				}
				if (ap_node_tmp) {
					for (y = 0; wlcstat_list[i].befollow_bandindex[y] >= 0; y++) {
						int j, check_defif = 0;
						for (j = 0; j < SUMband; j++) {
							if (wlcstat_list[j].bandIndex == wlcstat_list[i].befollow_bandindex[y]) {
								check_defif = wlcstat_list[j].defif;
								break;
							}
						}
						if (check_defif) {
							char amas_wlc_target_same_ap[] = "amas_wlcXXX_target_same_ap";
							char macaddr_buf[18] = {};
							snprintf(amas_wlc_target_same_ap, sizeof(amas_wlc_target_same_ap), "amas_wlc%d_target_same_ap", wlcstat_list[i].befollow_bandindex[y]);
							switch (check_defif) {
								case WL2G_U:
									strncpy(macaddr_buf, ap_node_tmp->bssid_2g, sizeof(macaddr_buf));
									break;
								case WL5G1_U:
									strncpy(macaddr_buf, ap_node_tmp->bssid_5g, sizeof(macaddr_buf));
									break;
								case WL5G2_U:
									strncpy(macaddr_buf, ap_node_tmp->bssid_5g1, sizeof(macaddr_buf));
									break;
								case WL6G_U:
									strncpy(macaddr_buf, ap_node_tmp->bssid_6g, sizeof(macaddr_buf));
									break;
								default:
									memset(macaddr_buf, 0x0, sizeof(macaddr_buf));
							}
							if (strlen(macaddr_buf) == 17) {
								if (strcmp(nvram_safe_get(amas_wlc_target_same_ap), macaddr_buf)) {
									nvram_set(amas_wlc_target_same_ap, macaddr_buf);
									wlcstat_list[j].renew_cost = 1;
								}
							}
						}
					}
					update_pap_bssid(1, i, ap_node_tmp->bssid_2g, ap_node_tmp->bssid_5g, ap_node_tmp->bssid_5g1, ap_node_tmp->bssid_6g);
				} else {
					update_pap_bssid(0, i, NULL, NULL, NULL, NULL);
				}
			} else {
				update_pap_bssid(0, i, NULL, NULL, NULL, NULL);
			}
		} else {
			update_pap_bssid(0, i, NULL, NULL, NULL, NULL);
		}
	}

UPDATE_LASTBYTE_EXIT:
	free_list(ap_node_head);
	if (aplist)
		json_object_put(aplist);
	if (file_not_exist == 3) {
		for (i = 0; i < SUMband; i++) {
			update_pap_bssid(0, i, NULL, NULL, NULL, NULL);
		}
	}
	if (connected == 0) {
	    for (i = 0; i < SUMband ;i++) {
			snprintf(amas_wlc_target_same_ap, sizeof(amas_wlc_target_same_ap), "amas_wlc%d_target_same_ap", i);
			nvram_set(amas_wlc_target_same_ap, "");
		}
	}
}
#else
int update_lastbyte(void)
{
	char wlcif[16] = {}, wlcphyif[16] = {};
	char *next = NULL;
	char nvrampar[32];
	char nvramparf[32];
	char nvrampar_res[32];
	char nvramparf_last_res[64];
    int j = 0, i = 0, y = 0;
    int SUMband = get_wl_count();
    char wifi_lastbyte_str[17]={0};
    unsigned char wifi_lastbyte_result[17]={0};
    char set_lasybyte_str[16]={0};
    int paplastbyte = 0;
    int connected = 0;
	char target_bssid[20] = {};
	char nvramparf_lastbyte[32] = {};

#ifdef RTCONFIG_DPSTA
	int Is_dpsta = dpsta_mode();
#endif

#if defined(RTCONFIG_AMAS_WGN) && defined(WGN_HAVE_VLAN0)
	char dpsta_ifname[32];
#endif

	for(j=0; j < SUMband; j++)
	{

		snprintf(nvramparf, sizeof(nvramparf), "amas_wlc%d_paplastbyte_fail", wlcstat_list[j].bandIndex);
		snprintf(nvrampar_res, sizeof(nvrampar_res), "amas_wlc%d_paplastbyte_result", wlcstat_list[j].bandIndex);
		snprintf(nvramparf_last_res, sizeof(nvramparf_last_res), "amas_wlc%d_last_paplastbyte_result", wlcstat_list[j].bandIndex);
		snprintf(nvramparf_lastbyte, sizeof(nvramparf_lastbyte), "amas_wlc%d_lastbyte", wlcstat_list[j].bandIndex);

		if (wlcstat_list[j].use == 1)
		{
			if (wlcstat_list[j].state == WLC_STATE_CONNECTED)
			{
				connected++;
				memset(wlcif, 0, sizeof(wlcif));
#ifdef RTCONFIG_DPSTA
				if (Is_dpsta) {
#if defined(RTCONFIG_AMAS_WGN) && defined(WGN_HAVE_VLAN0)
					if (nvram_get_int("wgn_enabled") == 1) {
						memset(dpsta_ifname, 0, sizeof(dpsta_ifname));
						snprintf(dpsta_ifname, sizeof(dpsta_ifname), "%s.0", nvram_safe_get("sta_phy_ifnames"));
						snprintf(wlcif, sizeof(wlcif), "%s", dpsta_ifname);
					}
					else {
						snprintf(wlcif, sizeof(wlcif), "%s", nvram_safe_get("sta_phy_ifnames"));
					}
#else
					snprintf(wlcif, sizeof(wlcif), "%s", nvram_safe_get("sta_phy_ifnames"));
#endif
				}
				else
#endif
				{
#ifdef RTCONFIG_AMAS_WGN
					if (nvram_get_int("wgn_enabled") == 1) {
						foreach(wlcphyif, nvram_safe_get("sta_phy_ifnames"), next) {
							if (strcmp(wlcphyif, wlcstat_list[j].wlcif) == 0) {
#if defined(WGN_HAVE_VLAN0)
								snprintf(wlcif, sizeof(wlcif), "%s.0", wlcphyif);
#else									
								snprintf(wlcif, sizeof(wlcif), "%s", wlcphyif);
#endif
								break;
							}
						}
						if (strlen(wlcif) == 0)
							snprintf(wlcif, sizeof(wlcif), "%s", wlcstat_list[j].wlcif);
					} else
#endif
						snprintf(wlcif, sizeof(wlcif), "%s", wlcstat_list[j].wlcif);
				}

				if (wlcstat_list[j].befollow_bandindex[0] < 0) {
					if (strlen(nvram_safe_get(nvramparf_lastbyte)) == 0) { // need to get pap lsatbyte info for others
						memset(wifi_lastbyte_str, 0, sizeof(wifi_lastbyte_str));
						wlcstat_list[j].get_paplastbyte_result = amas_get_wifi_lastbyte(wlcif, wlcstat_list[j].bandIndex, SUMband, wlcstat_list[j].pap_bssid.bssid, wifi_lastbyte_str, sizeof(wifi_lastbyte_str));
					} else {
						continue;
					}
				} else {
					memset(wifi_lastbyte_str, 0, sizeof(wifi_lastbyte_str));
					wlcstat_list[j].get_paplastbyte_result = amas_get_wifi_lastbyte(wlcif, wlcstat_list[j].bandIndex, SUMband, wlcstat_list[j].pap_bssid.bssid, wifi_lastbyte_str, sizeof(wifi_lastbyte_str));
				}

				if (wlcstat_list[j].get_paplastbyte_result == AMAS_RESULT_SUCCESS && strlen(wifi_lastbyte_str))
				{
					nvram_set(nvramparf_lastbyte, wifi_lastbyte_str);

					AST_DBG("wifi_lastbyte_str (%s)\n", wifi_lastbyte_str);
					STR2HEX2(wifi_lastbyte_result, wifi_lastbyte_str, strlen(wifi_lastbyte_str));
					update_pap_bssid(1, j, wifi_lastbyte_str);

				    for (i = 0; i < (strlen(wifi_lastbyte_str)/2);i++)
				    {
						int check_defif = -1, check_bandindex = -1, array_index = -1;
						if (i == 0) { // 2.4G
							check_defif = WL2G_U;
						} else if (i == 1 && wifi_lastbyte_result[i] != 0x00) {
							check_defif = WL5G1_U;
						} else if (i == 2 && wifi_lastbyte_result[i] != 0x00) {
							check_defif = WL5G2_U;
						} else if (i == 3 && wifi_lastbyte_result[i] != 0x00) {
							check_defif = WL6G_U;
						}
						if (check_defif != -1) {
							for (y = 0; y < SUMband; y++) {
								if (wlcstat_list[y].defif == check_defif) {
									check_bandindex = wlcstat_list[y].bandIndex;
									array_index = y;
									break;
								}
							}
						}
						if (check_bandindex == -1 || array_index == -1)
							continue;

						for (y = 0; wlcstat_list[j].befollow_bandindex[y] >= 0; y++) {
							if (wlcstat_list[j].befollow_bandindex[y] == check_bandindex) {
								memset(target_bssid, 0, sizeof(target_bssid));
								snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_paplastbyte", check_bandindex);
								paplastbyte = wifi_lastbyte_result[i];
								snprintf(set_lasybyte_str, sizeof(set_lasybyte_str), "%02X", paplastbyte);
								nvram_set(nvrampar, set_lasybyte_str);
								strncpy(target_bssid, wlcstat_list[j].pap_bssid.bssid, 15);
								strncat(target_bssid, set_lasybyte_str, 2);
								if (strlen(target_bssid) == 17) {
									snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_target_same_ap", check_bandindex);
									if (strcmp(nvram_safe_get(nvrampar), target_bssid)) {
										nvram_set(nvrampar, target_bssid);
										wlcstat_list[array_index].renew_cost = 1;
									}
								}
							}
						}
				    }

					if(wlcstat_list[j].getpaplastbyte_fail_count > 0)
					{
						wlcstat_list[j].getpaplastbyte_fail_count = 0;
						nvram_set_int(nvramparf, 0);
					}
					wlcstat_list[j].last_get_paplastbyte_result = wlcstat_list[j].get_paplastbyte_result;
				}
				else
				{
					if (wlcstat_list[j].getpaplastbyte_fail_count > wlc_status_fail_count)
					{
						if (nvram_get_int(nvramparf) == 0)
						{
							AST_DBG("Band%d paplastbyte is invalid(fail count = %d)!\n", wlcstat_list[j].bandIndex, wlc_status_fail_count);
						    for (i = 0; i < SUMband; i++)
						    {
								snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_paplastbyte", i);
								nvram_set_int(nvrampar, ERROR_CODE);
						    }
						}
						nvram_set(nvramparf_lastbyte, "");
					}
					nvram_set_int(nvramparf, wlcstat_list[j].getpaplastbyte_fail_count);
					wlcstat_list[j].getpaplastbyte_fail_count++;
				}


				if ((wlcstat_list[j].last_get_paplastbyte_result != wlcstat_list[j].get_paplastbyte_result) &&
					(wlcstat_list[j].last_get_paplastbyte_result == AMAS_RESULT_SUCCESS || wlcstat_list[j].get_paplastbyte_result == AMAS_RESULT_SUCCESS))
				{
					nvram_set_int(nvramparf_last_res, wlcstat_list[j].last_get_paplastbyte_result);
					nvram_set_int(nvrampar_res, wlcstat_list[j].get_paplastbyte_result);
					AST_DBG("Band%d get_paplastbyte_result(%s), last_get_paplastbyte_result(%s)\n", wlcstat_list[j].bandIndex, amas_utils_str_error(wlcstat_list[j].get_paplastbyte_result), amas_utils_str_error(wlcstat_list[j].last_get_paplastbyte_result));
				}
			} else {
				update_pap_bssid(0, j, NULL);
			}
		}
	}

	if (connected == 0)
	{
	    for (i = 0; i < SUMband ;i++)
		{
			snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_paplastbyte", i);
			nvram_set(nvrampar, "");
			snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_target_same_ap", i);
			nvram_set(nvrampar, "");
			snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_lastbyte", i);
			nvram_set(nvrampar, "");
		}
	}

	return 0;
}
#endif

static void amas_status_leave(int signo)
{
	if (wlcstat_list != NULL)
		free(wlcstat_list);

	if (ethstat_list != NULL)
		free(ethstat_list);

	if (priority_list != NULL)
		free(priority_list);

	nvram_set_int("amas_status_init", 0); // for amas_bhctrl

	dbG("\n## amas_status.safeexit ##\n");
	exit(0);
}

int amas_status_main(void)
{
	nvram_set_int("amas_status_init", 0); // for amas_bhctrl

#ifdef RTCONFIG_SW_HW_AUTH
	time_t timestamp = time(NULL);
	char in_buf[48];
	char out_buf[65];
	char hw_out_buf[65];
	char *hw_auth_code = NULL;

	if (!(getAmasSupportMode() & AMAS_RE)) {
		dbG("not support RE\n");
		return 0;
	}

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
		dbG("This is ASUS router\n");
	}
	else {
		dbG("This is not ASUS router\n");
		return 0;
	}
#else
	dbG("auth check is disabled\n");
	return 0;
#endif


	amas_wait_wifi_ready();

	amas_status_dbg = nvram_get_int("amas_status_dbg");
	int SUMband = get_wl_count();
	int SUMeth = get_eth_count();
	int amas_ethernet = 0;
	int amas_eth_bhmode = 0;
	int amas_wifi_bhmode = 0;
	int amas_costmode = 0;
	int amas_rssiscoremode = 0;
	char nvrammode[64];
	int aimesh_alg = aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;


	signal(SIGTERM, amas_status_leave);

	nvram_set_int("wlc_band", -1);

	amas_status_timer = nvram_get_int("amas_status_timer") ? : STATUS_TIMER;
	wlc_status_fail_count = nvram_get_int("amas_wlc_status_fail_count") ? : WLC_STATUS_FAIL_COUNT;
	eth_status_fail_count = nvram_get_int("amas_eth_status_fail_count") ? : ETH_STATUS_FAIL_COUNT;

	wlcstat_list = (struct _wlc_status *) malloc(SUMband *sizeof(struct _wlc_status));

	if (wlcstat_list == NULL) {
		dbG("Can't alloc memory for wlcstat_list(%s)\n", __FUNCTION__);
		return 0;
	}

	ethstat_list = (struct _eth_status *) malloc(SUMeth *sizeof(struct _eth_status));

	if (ethstat_list == NULL) {
		dbG("Can't alloc memory for ethstat_list(%s)\n", __FUNCTION__);
		return 0;
	}

	priority_list = (struct _ifi_priority *) malloc((SUMband+SUMeth) *sizeof(struct _ifi_priority));

	memset(wlcstat_list, 0x00, SUMband *sizeof(struct _wlc_status));
	memset(ethstat_list, 0x00, SUMeth *sizeof(struct _eth_status));
	memset(priority_list, 0x00, (SUMband+SUMeth) *sizeof(struct _ifi_priority));

    amas_ethernet = nvram_get_int("amas_ethernet") ? nvram_get_int("amas_ethernet") : CONN_PRI_AUTO;

	trans_to_bhmode(&amas_eth_bhmode, &amas_wifi_bhmode, &amas_costmode, &amas_rssiscoremode);

    snprintf(nvrammode, sizeof(nvrammode), "%X", amas_costmode);
    nvram_set("amas_costmode", nvrammode);
    snprintf(nvrammode, sizeof(nvrammode), "%X", amas_rssiscoremode);
    nvram_set("amas_rssiscoremode", nvrammode);
    snprintf(nvrammode, sizeof(nvrammode), "%X", amas_eth_bhmode);
    nvram_set("amas_eth_bhmode", nvrammode);
    snprintf(nvrammode, sizeof(nvrammode), "%X", amas_wifi_bhmode);
    nvram_set("amas_wifi_bhmode", nvrammode);

    AST_DBG("\n(%s) amas_ethernet (%02X), amas_eth_bhmode(%02X), amas_wifi_bhmode(%02X), amas_costmode(%02X), amas_rssiscoremode(%02X)\n", __FUNCTION__, amas_ethernet, amas_eth_bhmode, amas_wifi_bhmode, amas_costmode, amas_rssiscoremode);

	init_eth_info(amas_eth_bhmode);
	init_wlc_info(amas_wifi_bhmode);

	check_priority_setting(amas_eth_bhmode, amas_wifi_bhmode);

	nvram_set_int("amas_status_init", 1); // for amas_bhctrl

	while (1)
	{
		amas_status_dbg = nvram_get_int("amas_status_dbg");

		update_wlc_info();

		update_eth_info(amas_eth_bhmode);

		update_linkrate();

		update_cost();

		update_lastbyte();

		if (aimesh_alg == AIMESH_ALG_RSSISCORE)
			update_rssi_score();

		sleep(amas_status_timer);
	}

	return 0;
}
