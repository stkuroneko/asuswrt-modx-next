#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <wlutils.h>

#include "amas_path.h"
#include "shared.h"
#include "shutils.h"
#include "utils.h"
#include <syslog.h>

int cal_space(char *s1)
{

  printf("s1 = %s\n", s1);

  int space = 0;

    if(space == 0 && isspace(*s1)) {
        printf("config format is incorrect.\n");
        return 0;
    }

    while (*s1)
    {
       if (isspace(*s1))
       {
           space++;
       }
       s1++;
    }
    s1--;
    if(isspace(*s1)) {
        printf("config format is incorrect.\n");
        return 0;
    }

    printf("parameter count = %d\n", space+1);
   return space + 1;
}


int get_wl_count()
{
	char wif[256]={0}, *next = NULL;
	int SUMband = 0;
	char sta_ifnames[32];

	//Get number of bands and set initial status for wlc.
	strlcpy(sta_ifnames, nvram_safe_get("sta_ifnames"), sizeof(sta_ifnames));
	foreach(wif, sta_ifnames, next) {
		SUMband++;
	}

	return SUMband;
}

int get_eth_count()
{
	char eif[256]={0}, *next = NULL;
	int SUMeth = 0;
	char eth_ifnames[32];

	//Get number of bands and set initial status for wlc.
	strlcpy(eth_ifnames, nvram_safe_get("eth_ifnames"), sizeof(eth_ifnames));
	foreach(eif, eth_ifnames, next) {
		SUMeth++;
	}

	return SUMeth;
}

int is_self_optmz_stage(int band)
{
	char optmz_nvram[64];

    snprintf(optmz_nvram, sizeof(optmz_nvram), "amas_wlc%d_optmz", band);

    /*0: don't to do self-optimize, 1: wait forself-optimize stage.*/
    if(nvram_get_int(optmz_nvram) == OPTMZ_FROM_RE || nvram_get_int(optmz_nvram) == OPTMZ_FROM_CAP)
    {
    	return 1;
    }

    return 0;
}

#ifdef RTCONFIG_BHCOST_OPT
/**
 * @brief Set amas_bhmode for AiMesh 2.0 without auto detect function.
 *
 */
void trans_to_amas_bhmode()
{
	int amas_ethernet = nvram_get_int("amas_ethernet");
	int SUMband = get_wl_count();

	switch (amas_ethernet)
	{
		case CONN_PRI_NONE: // Be set AUTO. NONE is danger.
			SUMband == 2 ? nvram_set("amas_bhmode", "303100") : nvram_set("amas_bhmode", "503100");
			break;
		case CONN_PRI_WIFI_ONLY:
			SUMband == 2 ? nvram_set("amas_bhmode", "320000") : nvram_set("amas_bhmode", "540000");
			break;
		case CONN_PRI_ETH:
			SUMband == 2 ? nvram_set("amas_bhmode", "303100") : nvram_set("amas_bhmode", "503100");
			break;
		case CONN_PRI_AUTO:
			SUMband == 2 ? nvram_set("amas_bhmode", "303100") : nvram_set("amas_bhmode", "503100");
			break;
		default: // AUTO is default.
			SUMband == 2 ? nvram_set("amas_bhmode", "303100") : nvram_set("amas_bhmode", "503100");
			break;
	}

	nvram_commit();
}

enum {
    USE_2G = 1,
    USE_5G1 = 2,
    USE_5G2 = 4,
    USE_6G1 = 8,
    USE_6G2 = 16
};

/**
 * @brief Transfer amas_ethernet to bhmode settings.
 *
 * @param amas_eth_bhmode bhmode for ethernet
 * @param amas_wifi_bhmode bhmode for wireless ethernet
 * @param amas_costmode cost mode
 * @param amas_rssiscoremode rssi score mode
 */
void trans_to_bhmode(int *amas_eth_bhmode, int *amas_wifi_bhmode, int *amas_costmode, int *amas_rssiscoremode)
{
	int amas_ethernet = nvram_get_int("amas_ethernet") ? : CONN_PRI_AUTO;
	int SUMband = get_wl_count();
	int SUMeth = get_eth_count();
	int i;
	int amas_eap_bhmode = nvram_get_int("amas_eap_bhmode");
	char band_priority[64] = {}, *p_band_priority;
	int offset = 0, band = 0, bandindex = 0, priority = 0, use = 0, use_band = 0;
	int band_count[3] = {0, 0, 0};  // [0]: 2.4G. [1]: 5G. [2]: 6G
	int tmp_int = 0, target_ifname_idx = -1;
	int conn_priority, ethtype_only, target_port_index = 0;
	char word[8] = {}, *next = NULL;
	int num5g = 0;

	*amas_costmode = ALL_COST; // default
	*amas_rssiscoremode = AUTO_RSSISCORE; //default

	if (amas_ethernet >= 10 && amas_ethernet < 100) {
		conn_priority = amas_ethernet / 10;
		target_port_index = amas_ethernet % 10;
	} else if (amas_ethernet >= 1000) {
		conn_priority = amas_ethernet / 10;
		target_port_index = amas_ethernet % 10;
	} else {
		conn_priority = amas_ethernet;
		target_port_index = 0;
	}

	switch (conn_priority)
	{
		case CONN_PRI_ETH1G:
			ethtype_only = ETH_TYPE_1000;
			break;
		case CONN_PRI_ETH25G:
			ethtype_only = ETH_TYPE_25G;
			break;
		case CONN_PRI_ETH5G:
			ethtype_only = ETH_TYPE_5G;
			break;
		case CONN_PRI_ETH10G:
			ethtype_only = ETH_TYPE_10G;
			break;
		case CONN_PRI_ETH10GPLUS:
			ethtype_only = ETH_TYPE_10GPLUS;
			break;
		case CONN_PRI_PLC:
			ethtype_only = ETH_TYPE_PLC;
			break;
		default:
			ethtype_only = 0xFFFFFFFF; // No limit
	}

	// Get target Port's interface name
	if (target_port_index) {
		i = 0;
		foreach(word, nvram_safe_get("amas_ethif_type"), next) { // Get target port index in eth_ifnames
			if (ethtype_only & atoi(word))
				i++;
			if (target_port_index == i) {
				target_ifname_idx = tmp_int;
				break;
			}
			tmp_int++;
		}
	}

	if (SUMeth <= 0 && amas_eap_bhmode > 0) {  // No ETH
		nvram_set_int("amas_eap_bhmode", 0);   // Disable EAP mode.
		amas_eap_bhmode = 0;
	}

	/* Model type */
	snprintf(band_priority, sizeof(band_priority), "%s", nvram_safe_get("sta_priority"));
	if (strlen(band_priority) > 0) {
		p_band_priority = band_priority;
		while (sscanf(p_band_priority, " %d%d%d%d%n", &band, &bandindex, &priority, &use, &offset) == 4) {
			p_band_priority += offset;
			if (band == 6 && use == 1) {
				band_count[2]++;
				if (band_count[2] > 0)
					use_band = use_band | (USE_6G1 << (band_count[2] - 1));
			} else if (band == 2 && use == 1) {
				band_count[0]++;
				if (band_count[0] > 0)
					use_band = use_band | (USE_2G << (band_count[0] - 1));
			} else if (band == 5) {
				num5g++;
				if (use == 1) {
					band_count[1]++;
					if (band_count[1] > 0)
						use_band = use_band | (USE_5G1 << (band_count[1] - 1));
				}
			}
		}
	}

	int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;
	if (aimesh_alg == AIMESH_ALG_COST)
		*amas_rssiscoremode = DONT_RSSISCORE;

	switch (conn_priority) {
		case CONN_PRI_NONE:
			*amas_eth_bhmode = 0;
			*amas_wifi_bhmode = 0;
			break;
		case CONN_PRI_WIFI_ONLY:
			*amas_eth_bhmode = 0;
			if (SUMband >= 3) {
				if (use_band == (USE_2G | USE_5G1 | USE_6G1)) {
					if (num5g > 1)
						*amas_wifi_bhmode = 0xD4; // 2.4G, 5G2, 6G, 5G2 First
					else
						*amas_wifi_bhmode = 0x72;  // 2.4G, 5G, 6G, 5G First
				}
				else
					*amas_wifi_bhmode = 0x54;  // 2.4G, 5G2, 5G2 First
			} else
				*amas_wifi_bhmode = 0x32;  // 2.4G, 5G, 5G First
			break;
		case CONN_PRI_ETH:
		case CONN_PRI_ETH1G:
		case CONN_PRI_ETH25G:
		case CONN_PRI_ETH5G:
		case CONN_PRI_ETH10G:
		case CONN_PRI_ETH10GPLUS:
		case CONN_PRI_PLC:
			if (amas_eap_bhmode > 0) { // Only
				for (i = 0; i < SUMeth; i++) {
					if ((target_ifname_idx >= 0) && (i == target_ifname_idx))
						*amas_eth_bhmode = *amas_eth_bhmode | (1 << i) | (1 << (4 * ((i / 4) + 1) + i));
					else
						*amas_eth_bhmode = *amas_eth_bhmode | (1 << (4 * ((i / 4) + 1) + i));
				}
				*amas_wifi_bhmode = 0x0;
				*amas_costmode = DONT_COST;
			} else { // First
				for (i = 0; i < SUMeth; i++) {
					if ((target_ifname_idx >= 0) && (i == target_ifname_idx))
						*amas_eth_bhmode = *amas_eth_bhmode | (1 << i) | (1 << (4 * ((i / 4) + 1) + i));
					else
						*amas_eth_bhmode = *amas_eth_bhmode | (1 << (4 * ((i / 4) + 1) + i));
				}
				if (SUMband >= 3) {
					if (use_band == (USE_2G | USE_5G1 | USE_6G1)) {
						if (num5g > 1)
							*amas_wifi_bhmode = 0xD0; // 2.4G, 5G2, 6G
						else
							*amas_wifi_bhmode = 0x70; // 2.4G, 5G, 6G
					}
					else
						*amas_wifi_bhmode = 0x50; // 2.4G, 5G2
				}
				else
					*amas_wifi_bhmode = 0x30; // 2.4G, 5G
				*amas_costmode = DONT_COST;
				*amas_rssiscoremode = DONT_RSSISCORE;
			}
			break;
		case CONN_PRI_AUTO:
			if (amas_eap_bhmode > 0) { // Only
				for (i = 0; i < SUMeth; i++) {
					*amas_eth_bhmode = *amas_eth_bhmode | (1 << (4 * ((i / 4) + 1) + i));
				}
				*amas_wifi_bhmode = 0x0;
				*amas_costmode = DONT_COST;
			}
			else {
				for (i = 0; i < SUMeth; i++) {
					*amas_eth_bhmode = *amas_eth_bhmode | (1 << (4 * ((i / 4) + 1) + i));
				}
				if (SUMband >= 3) {
					if (use_band == (USE_2G | USE_5G1 | USE_6G1)) {
						if (num5g > 1)
							*amas_wifi_bhmode = 0xD0; // 2.4G, 5G2, 6G
						else
							*amas_wifi_bhmode = 0x70; // 2.4G, 5G, 6G
					}
					else
						*amas_wifi_bhmode = 0x50; // 2.4G, 5G2
				}
				else
					*amas_wifi_bhmode = 0x30; // 2.4G, 5G
			}
			break;
		case CONN_PRI_WIFI_2G:
    	case CONN_PRI_WIFI_5G:
    	case CONN_PRI_WIFI_5G2:
    	case CONN_PRI_WIFI_6G:
			if (SUMband >= 3) {
				if (use_band == (USE_2G | USE_5G1 | USE_6G1)) {
					if (num5g > 1)
						*amas_wifi_bhmode = 0xD0; // 2.4G, 5G2, 6G
					else
						*amas_wifi_bhmode = 0x70; // 2.4G, 5G, 6G
				}
				else
					*amas_wifi_bhmode = 0x50; // 2.4G, 5G2
			}
			else
				*amas_wifi_bhmode = 0x30; // 2.4G, 5G

			if (conn_priority == CONN_PRI_WIFI_2G)
				*amas_wifi_bhmode = *amas_wifi_bhmode | 1;
			else if (conn_priority == CONN_PRI_WIFI_5G)
				*amas_wifi_bhmode = *amas_wifi_bhmode | (1 << 1);
			else if (conn_priority == CONN_PRI_WIFI_5G2)
				*amas_wifi_bhmode = *amas_wifi_bhmode | (1 << 2);
			else if (conn_priority == CONN_PRI_WIFI_6G) {
				if (SUMband == 3)
					*amas_wifi_bhmode = *amas_wifi_bhmode | (1 << 2);
				else if (SUMband == 4)
					*amas_wifi_bhmode = *amas_wifi_bhmode | (1 << 3);
			}
			*amas_eth_bhmode = 0;
			*amas_costmode = DONT_COST;
			*amas_rssiscoremode = DONT_RSSISCORE;
			break;
        case CONN_PRI_CUSTOM:
            *amas_eth_bhmode = nvram_get_int("amas_eth_bhmode");
        	*amas_wifi_bhmode = nvram_get_int("amas_wifi_bhmode");
			*amas_costmode = nvram_get_int("amas_costmode");
			*amas_rssiscoremode = nvram_get_int("amas_rssiscoremode");
            printf("Connection Priority is custom. Don't process transfer amas_ethernet to bhmode settings.\n");
            break;
		default: // use CONN_PRI_AUTO as default.
			for (i = 0; i < SUMeth; i++) {
				*amas_eth_bhmode = *amas_eth_bhmode | (1 << (4 * ((i / 4) + 1) + i));
			}
			if (SUMband == 3) {
				if (use_band == (USE_2G | USE_5G1 | USE_6G1))
					*amas_wifi_bhmode = 0x70; // 2.4G, 5G, 6G
				else
					*amas_wifi_bhmode = 0x50; // 2.4G, 5G2
			}
			else
				*amas_wifi_bhmode = 0x30; // 2.4G, 5G
			break;
	}
	trans_to_amas_bhmode();
}

/**
 * @brief Trigger amas_bhctrl do OPT
 *
 */
void trigger_opt()
{
	int unit = 0;
	char prefix[16], tmp[64], word[64], *next;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "amas_wlc%d_", unit);

		/* set amas_wlcX_optmz for trigger self optimization */
		nvram_set_int(strcat_r(prefix, "optmz", tmp), OPTMZ_FROM_CAP);
		unit++;
	}
}

uplinkport_capval_s port_define[] = {
    {"NONE", 0},
    {"WAN", 1},
    {"LAN", 2},
    {"", -1}};
uplinkport_capval_s phy_type[] = {
    {"NONE", 0},
    {"ETH", 1},
    {"WIFI", 2},
    {"PLC", 3},
    {"", -1}};
uplinkport_capval_s phy_eth_subtype[] = {
    {"NONE", 0},
    {"10", 1},
    {"100", 2},
    {"1000", 3},
    {"1G", 3},
    {"2.5G", 4},
    {"5G", 5},
    {"10G", 6},
    {"10GSFP+", 7},	/* 10G SFP+ */
    {"", -1}};
uplinkport_capval_s phy_wifi_subtype[] = {
    {"NONE", 0},
    {"2.4G", 1},
    {"5G", 2},
    {"6G", 3},
    {"", -1}};
uplinkport_capval_s phy_plc_subtype[] = {
    {"NONE", 0},
    {"", -1}};

int gen_uplinkport_describe(char *port_def, char *type, char *subtype, int index) {
    int describe = 0;
    int i;

    //  bit 19 - 16
    if (port_def) {
        i = 0;
        while (port_define[i].val != -1) {
            if (!strcmp(port_define[i].name, port_def)) {
                describe = describe + (port_define[i].val << 16);
                break;
            }
            i++;
        }
    }

    //  bit 15 - 12
    if (type) {
        i = 0;
        while (phy_type[i].val != -1) {
            if (!strcmp(phy_type[i].name, type)) {
                describe = describe + (phy_type[i].val << 12);
                break;
            }
            i++;
        }
    }

    //  bit 11 - 8
    if (subtype) {
        uplinkport_capval_s *capval_tmp = NULL;
        if (!strcmp("ETH", type))
            capval_tmp = &phy_eth_subtype[0];
        else if (!strcmp("WIFI", type))
            capval_tmp = &phy_wifi_subtype[0];
        else if (!strcmp("PLC", type))
            capval_tmp = &phy_plc_subtype[0];

        if (capval_tmp) {
            i = 0;
            while ((capval_tmp + i)->val != -1) {
                if (!strcmp((capval_tmp + i)->name, subtype)) {
                    describe = describe + ((capval_tmp + i)->val << 8);
                    break;
                }
                i++;
            }
        }
    }

    //  bit 7 - 0
    describe = describe + index;

    if (describe)
        return describe;

    return 0;
}

/**
 * @brief PLC cost calculation.
 *
 * @param pap_cost Parent cost.
 * @param rate PLC date rate.
 * @return float cost.
 */
float cal_plc_cost(float pap_cost, int rate) {
    int fake_rssi;
    float cost;

    if (rate >= 900)
        fake_rssi = -50;
    else if (rate >= 400 && rate < 900)
        fake_rssi = -60;
    else if (rate >= 200 && rate < 400)
        fake_rssi = -70;
    else
        fake_rssi = -80;

    if (fake_rssi > -50)
        cost = pap_cost;
    else if (fake_rssi > -60)
        cost = pap_cost + 1 + 1 * (-50 - fake_rssi) / 10.0;
    else if (fake_rssi > -70)
        cost = pap_cost + 2 + 2 * (-60 - fake_rssi) / 10.0;
    else if (fake_rssi > -80)
        cost = pap_cost + 4 + 4 * (-70 - fake_rssi) / 10.0;
    else
        cost = pap_cost + 8 + 8 * (-80 - fake_rssi) / 10.0;

    return cost;
}

#ifdef RTCONFIG_BCMWL6
/**
 * @brief Stop acsd binding specific channel.
 *
 * @param model Model name
 */
void amas_stop_acsd_config_init(int model) {
    switch (model) {
        case MODEL_RTAX95Q:
        case MODEL_XT8PRO:
        case MODEL_XT8_V2:
            nvram_set_int("amas_wl0_noacsd", 1);
            nvram_set_int("amas_wl2_noacsd", 1);
            break;
        case MODEL_RTAXE95Q:
        case MODEL_ET8PRO:
            nvram_set_int("amas_wl0_noacsd", 1);
            nvram_set_int("amas_wl1_noacsd", 1);
            nvram_set_int("amas_wl2_noacsd", 1);
            break;
        default:
            break;
    }
}
#endif

#endif

int enable_ETH_U(int unit)
{
#ifdef RTCONFIG_BHCOST_OPT
	int use = 0;
    int amas_eth_bhmode = 0, amas_wifi_bhmode = 0, amas_costmode = 0, amas_rssiscoremode = 0;

    trans_to_bhmode(&amas_eth_bhmode, &amas_wifi_bhmode, &amas_costmode, &amas_rssiscoremode);

    use = (amas_eth_bhmode & (1 << (4 * ((unit / 4) + 1) + unit))) > 0 ? 1 : 0;

	return use;
#else
    return 1;
#endif

}

void add_led_ctrl_capability(int val)
{
	nvram_set_int("led_ctrl_cap", nvram_get_int("led_ctrl_cap") | val);
}

void del_led_ctrl_capability(int val)
{
	int led_ctrl_cap = nvram_get_int("led_ctrl_cap");

	if ((led_ctrl_cap <= 0) || ((led_ctrl_cap & val) != val))
		return;

	nvram_set_int("led_ctrl_cap", led_ctrl_cap - val);
}

#ifdef RTCONFIG_MSSID_PRELINK
void check_mssid_prelink_reset(uint32_t sf)
{
	nvram_unset("plk_need_reset");

	if ((sf & 0x1) == 0)
		nvram_set_int("plk_need_reset", 1);
}
#endif

void unset_selected_channel_info()
{
	int i = 0;
	int wlif_count = num_of_wl_if();
	char prefix[sizeof("wlXXXXX_")], tmp[32];

	for (i = 0; i < wlif_count; i++) {
		snprintf(prefix, sizeof(prefix), "wl%d_", i);
		nvram_unset(strcat_r(prefix, "sel_channel", tmp));
		nvram_unset(strcat_r(prefix, "sel_bw", tmp));
		nvram_unset(strcat_r(prefix, "sel_nctrlsb", tmp));
	}
}

#ifdef RTCONFIG_BCMARM
int wl_unit(char *wlif)
{
        int unit;
        char nvtmp[16], *nvif;

        for(unit = 0; unit<5; unit++) {
                sprintf(nvtmp, "wl%d_ifname", unit);
                nvif = nvram_safe_get(nvtmp);
                if(*nvif && strncmp(nvif, wlif, strlen(wlif))==0)
                        break;
        }
        if(unit == 5)
                unit = -1;

        return unit;
}

void
acsd_amasinfo(char *wlif, chanspec_t selected_chspec)
{
        int abw = 0, nsb = 0, pch = 0;
        int unit;
        char wl_prefix[20], comb[40];
        int re_mode = nvram_get_int("re_mode");

        if(!re_mode) {
                unit = wl_unit(wlif);
                if(unit < 0) {
                        syslog(LOG_NOTICE, "amasinfo invalid wlif:%s\n", wlif);
                        return;
                }
        }

        if(re_mode)
                snprintf(wl_prefix, sizeof(wl_prefix), "wl%c_", wlif[2]);
        else
                snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);

#ifdef RTCONFIG_HND_ROUTER_AX
        pch = wf_chspec_primary20_chan(selected_chspec);
#else
        pch = wf_chspec_ctlchan(selected_chspec);
#endif

        if (CHSPEC_IS20(selected_chspec))
                abw = 20;
        else if (CHSPEC_IS40(selected_chspec))
                abw = 40;
        else if (CHSPEC_IS80(selected_chspec))
                abw = 80;
#if defined(RTCONFIG_HND_ROUTER_AX) || defined(RTCONFIG_BW160M)
        else if (CHSPEC_IS160(selected_chspec))
                abw = 160;
#endif
        if(abw == 40) {
                if(CHSPEC_SB_UPPER(selected_chspec))
                        nsb = 1;
                else
                        nsb = 0;
        }

        if(nvram_get_int("acsd_debug") & 0x1)
                syslog(LOG_NOTICE, "(re:%d)wl_prefix=%s, amas bw=%d, nsb=%d\n", re_mode, wl_prefix, abw, nsb);

        nvram_set_int(strcat_r(wl_prefix, "sel_channel", comb), pch);
        nvram_set_int(strcat_r(wl_prefix, "sel_bw", comb), abw);
        nvram_set_int(strcat_r(wl_prefix, "sel_nctrlsb", comb), nsb);
}
#endif

int get_unit_by_wlc_bandindex(int bandindex)
{
	int i = 0, unit = -1;
	char prefix[sizeof("amas_wlcXXX_")], tmp[64];

	for (i = 0; i < get_wl_count(); i++) {
		snprintf(prefix, sizeof(prefix), "amas_wlc%d_", i);
		if (nvram_get_int(strcat_r(prefix, "index", tmp)) == bandindex) {
			unit = nvram_get_int(strcat_r(prefix, "unit", tmp));
			break;
		}
	}

	return unit;
}

int get_wlc_bandindex_by_unit(int unit)
{
	int i = 0, bandindex = -1;
	char prefix[sizeof("amas_wlcXXX_")], tmp[64];

	for (i = 0; i < get_wl_count(); i++) {
		snprintf(prefix, sizeof(prefix), "amas_wlc%d_", i);
		if (nvram_get_int(strcat_r(prefix, "unit", tmp)) == unit) {
			bandindex = nvram_get_int(strcat_r(prefix, "index", tmp));
			break;
		}
	}

	return bandindex;
}

double get_wifi_tx_maxpower(int band_type)
{
	double ret =0;
	switch (band_type)
	{
		case 2: // get 2G max power.
			
			break;
		case 5: // get 5G max power : Only one 5g band.
			ret = get_wifi_5G_maxpower();
			break;
		case 51: // get 5GL max power.
			
			break;
		case 52: // get 5GH max power.
			ret = get_wifi_5GH_maxpower();
			break;
		case 6: // get 6G max power.
			ret = get_wifi_6G_maxpower();
			break;
		default: // AUTO is default.
			
			break;
	}

	return ret;
}

#if defined(RTCONFIG_AMAS) && defined(RTCONFIG_AMAS_ADTBW)
void acsd_export_score(chanspec_t chspec, int score_total)
{
	char ch_score[128];
	int fd;


	fd=open(ACSD_SCORE_FILE, O_CREAT|O_APPEND|O_RDWR, S_IRUSR);
	if(fd == -1)
		return;
	if(flock(fd, LOCK_EX) != 0)
		_dprintf("%s was not locked.\n", ACSD_SCORE_FILE);

	snprintf(ch_score, sizeof(ch_score), "0x%4x %d\n", chspec, score_total);
	write(fd, ch_score, strlen(ch_score));
	if(flock(fd, LOCK_UN) != 0)
	    _dprintf("%s unlocked failed.\n", ACSD_SCORE_FILE);
	close(fd);
	return;
}
#endif

void create_amas_sys_folder()
{
#if (defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS))
	if(!d_exists("/jffs/.sys"))
		mkdir("/jffs/.sys", 0666);
#endif
}
