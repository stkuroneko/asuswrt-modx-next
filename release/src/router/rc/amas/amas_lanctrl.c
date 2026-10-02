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
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <shared.h>
#include <rc.h>
#include "amas.h"
#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif
#include <amas_path.h>
#ifdef RTCONFIG_FRONTHAUL_DWB
#include <amas_dwb.h>
#endif

int lanctl_dbg = 0;
#ifdef RTCONFIG_HND_ROUTER_AX
int bh_5g_index = -1;
#endif
#if defined(RTCONFIG_QCA)
time_t init_time;
#endif

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"amas_lanctl.log"
#define LC_DBG(fmt, arg...) \
	do {    \
		if(lanctl_dbg) \
		dbG("LC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("lanctl_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#else
#define LC_DBG(fmt, arg...) \
        do {    \
               if(lanctl_dbg) \
                dbG("LC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("lanctl_syslog"), "1")) \
				logmessage("LC", fmt, ##arg); \
        } while (0)
#endif

#define INTERVAL 2
#define MAX_SUBIF_NUM 8

int lanctrl_timer = INTERVAL;
int recheck_bss = 0;

#if defined(RTCONFIG_VIF_ONBOARDING) && (defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM))
#define OBVIF_DISABLE_COUNT	3
int disable_count = 0;
#endif

#ifdef RTCONFIG_FRONTHAUL_DWB
static int get_fronthaul_ap_idx();
static int skip_fronthaul_ap(int unit, int vidx);
#endif

#if defined(RTCONFIG_PRELINK)
void update_lldp_hash_bundle_key(int reset);
#endif

#ifdef RTCONFIG_HND_ROUTER_AX
#if 0
#define FH_5G_CHECK_COUNT	2
int fh_5g_check_count = 0;
#endif

#ifdef RTCONFIG_HND_ROUTER_AX
/**
 * @brief If STA still connecting, don't up AP service.
 *
 * @param unit Band index
 * @return int 0: STA doesn't connecting. 1: STA still connecting.
 */
int sta_connecting_keep_ap_down(int unit) {
    char wl_nband[] = "wlXXX_nband";
    char wlc_status[] = "wlcXXX_status";
    snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", unit);

    int nband = nvram_get_int(wl_nband);

    if (nband != 1 && nband != 4)
        return 0;

    snprintf(wlc_status, sizeof(wlc_status), "wlc%d_status", get_wlc_bandindex_by_unit(unit));

    if (nvram_get_int(wlc_status) == CH_SYNC_CONNECTING) {
        LC_DBG("STA Unit(%d) Still connecting. Skip up AP\n", unit);
        return 1;
    }

    return 0;
}
#endif

int need_downstream_ap_keep_down(int unit)
{
	int ret = 0, wlc_status = 0;
	char tmp[128], prefix[] = "amas_wlcXXXX_";

	/* unit is not for 5G backhaul */
	if (bh_5g_index != unit) {
		LC_DBG("unit(%d) is not for 5G backhaul, pass it.\n", unit);
		return 0;
	}

	/* backhaul is ethernet, return it */
	if (nvram_get_int("amas_path_stat") == ETH) {
		LC_DBG("ethernet backahul, pass it.\n");
		return 0;
	}

	snprintf(prefix, sizeof(prefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(unit));
	wlc_status = nvram_get_int(strcat_r(prefix, "state", tmp));
	LC_DBG("unit(%d), wlc_status(%d)\n", unit, wlc_status);
	if (wlc_status != WLC_STATE_CONNECTED)
		ret = 1;

	LC_DBG("unit(%d), ret(%d)\n", unit, ret);

	return ret;
}

int get_5g_bh_index()
{
	int i = 0, bh_5g = -1;
	char tmp[128], prefix[] = "amas_wlcXXXX_";
	int use = 0, defif = 0, index = 0;
	int SUMband = num_of_wl_if();

	for (i = 0; i < SUMband; i++) {
		snprintf(prefix, sizeof(prefix), "amas_wlc%d_", get_wlc_bandindex_by_unit(i));
		use = nvram_get_int(strcat_r(prefix, "use", tmp));
		defif = nvram_get_int(strcat_r(prefix, "defif", tmp));
		index = nvram_get_int(strcat_r(prefix, "index", tmp));
		LC_DBG("i(%d), index(%d), use(%d), defif(%02X)\n",
			i, index, use, defif);
		if (use == 1
			&& (defif == WL5G1_U || defif == WL5G2_U))
		{
			bh_5g = i;
			break;
		}
	}

	return bh_5g;
}

void check_5g_fh_bss()
{
	char tmp[128], wlc_prefix[] = "wlcXXXXXXXXX_", prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	int unit = bh_5g_index;
	int wl_assoc = 0, vidx = 0, setting_fail = 0;
	int wlc_status = 0, amas_wlc_state = 0;
	int fh_5g_dbg = nvram_get_int("fh_5g_dbg");
#ifdef RTCONFIG_FRONTHAUL_DWB
	int dwb_mode = nvram_get_int("dwb_mode");
#endif
	int wlc_bandindex = get_wlc_bandindex_by_unit(unit);

#if 0
	if (fh_5g_check_count < FH_5G_CHECK_COUNT) {
		if (fh_5g_dbg)
			LC_DBG("don't check 5g fh (%d) \n", fh_5g_check_count);
		fh_5g_check_count++;
		return;
	}

	if (fh_5g_dbg)
		LC_DBG("check 5g fh (%d) \n", fh_5g_check_count);
#endif

	snprintf(wlc_prefix, sizeof(wlc_prefix), "wlc%d_", wlc_bandindex);
	wlc_status = nvram_get_int(strcat_r(wlc_prefix, "status", tmp));

	snprintf(prefix, sizeof(prefix), "amas_wlc%d_", wlc_bandindex);
	amas_wlc_state = nvram_get_int(strcat_r(prefix, "state", tmp));

	for (vidx = 1; vidx < MAX_SUBIF_NUM; vidx++) {
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, vidx);
		if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1")) {
			strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

			wl_assoc = get_wlan_service_status(unit, vidx);
			if (wl_assoc == -1) {
				setting_fail = 1;
				continue;
			}
			else if (wl_assoc == -2) //radio off
				continue;

			if (fh_5g_dbg)
				LC_DBG("Enable/disable %s network service (wl_assoc = %d)\n", ifname , wl_assoc);

			if (!nvram_get(strcat_r(wlc_prefix, "status", tmp)) || wlc_status < 0) {
				if (wl_assoc <= 0) {
#ifdef RTCONFIG_FRONTHAUL_DWB
					if (nvram_get_int("fh_ap_enabled") > 0) { // Skip fronthual AP interface.
						if (dwb_mode == 1 || dwb_mode == 3) {
							if (skip_fronthaul_ap(unit, vidx) == 1) {
								LC_DBG("Skip fronthual AP unit:%d, Vidx:%d\n", unit, vidx);
								continue;
							}
						}
					}
#endif
					if (fh_5g_dbg)
						LC_DBG("Enable %s network service finished\n", ifname);
					set_wlan_service_status(unit, vidx, 1);
					if (get_wlan_service_status(unit, vidx) <= 0) // Enable fail
						setting_fail = 1;
				}
			}
			else
			{
				if (amas_wlc_state == WLC_STATE_CONNECTED && wl_assoc <= 0) {
#ifdef RTCONFIG_FRONTHAUL_DWB
					if (nvram_get_int("fh_ap_enabled") > 0) { // Skip fronthual AP interface.
						if (dwb_mode == 1 || dwb_mode == 3) {
							if (skip_fronthaul_ap(unit, vidx) == 1) {
								LC_DBG("Skip fronthual AP unit:%d, Vidx:%d\n", unit, vidx);
								continue;
							}
						}
					}
#endif
					if (fh_5g_dbg)
						LC_DBG("Enable %s network service finished\n", ifname);
					set_wlan_service_status(unit, vidx, 1);
					if (get_wlan_service_status(unit, vidx) <= 0) // Enable fail
						setting_fail = 1;
				}
				else if (amas_wlc_state != WLC_STATE_CONNECTED && wl_assoc > 0)
				{
					if (fh_5g_dbg)
						LC_DBG("Disable %s network service finished\n", ifname);
					set_wlan_service_status(unit, vidx, 0);
					if (get_wlan_service_status(unit, vidx) > 0) // Disable fail
						setting_fail = 1;
				}
			}
		}
	}
#if 0
	if (!setting_fail)
		fh_5g_check_count = 0;
#endif
}
#endif

#ifdef RTCONFIG_VIF_ONBOARDING
void disable_onboarding_vif_bss()
{
	int obvif_unit = WL_2G_BAND, obvif_subunit = nvram_get_int("obvif_cap_subunit"), status = 0;
	char prefix[]="wlXXXXXXX_", tmp[64];

	if (nvram_get_int("re_mode") == 1) {
		obvif_subunit = nvram_get_int("obvif_re_subunit");
		snprintf(prefix, sizeof(prefix), "wl%d.1_", obvif_unit);
	}
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", obvif_unit);

	if (nvram_match(strcat_r(prefix, "auth_mode_x", tmp), "sae") &&
		nvram_get_int("obvif_bss") == 1 && nvram_get_int("cfg_obvif_up") == 0) {
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM)
		if (disable_count < OBVIF_DISABLE_COUNT) {
			disable_count++;
			return;
		}
#endif
		status = get_wlan_service_status(obvif_unit, obvif_subunit);
		if (status == -1) { // Error
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM)
			disable_count = 0;
#endif
			return;
		}
		else if (status > 0) {
			set_wlan_service_status(obvif_unit, obvif_subunit, 0);
			LC_DBG("Disable unit:%d vidx:%d network service finished\n", obvif_unit, obvif_subunit);
			if (get_wlan_service_status(obvif_unit, obvif_subunit) == 0) {  // Disable success
				nvram_set_int("obvif_bss", 0);
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM)
				disable_count = 0;
#endif
			}
		}
		else if (status == 0) {	// Have disabled
			nvram_set_int("obvif_bss", 0);
#if defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM)
			disable_count = 0;
#endif
		}
	}
}
#endif

#ifdef RTCONFIG_FRONTHAUL_DWB

/**
 * @brief Do reset driver bss
 *
 * @param old_fh_ap_bss Pre fronthaul ap bss setting
 * @param fh_ap_bss Currently fronthaul ap bss setting
 * @return int 0: No. 1: Need to reset
 */
static int do_confirm_driver_bss(int old_fh_ap_bss, int fh_ap_bss) // check every 30s
{
	static int timer = 0;
	int timerout = 30 / lanctrl_timer; // (30s/lanctrl_timer)

	timer++;
	if (old_fh_ap_bss != fh_ap_bss)
		timer = 0;
	else if (timer > timerout) {
		timer = 0;
		return 1;
	}
	return 0;
}

/**
 * @brief Get the fronthaul ap idx
 *
 * @return int Fronthaul AP subunit
 */
static int get_fronthaul_ap_idx()
{
	if (nvram_get_int("re_mode") == 1)
		return nvram_get_int("fh_re_mssid_subunit");
	else
		return nvram_get_int("fh_cap_mssid_subunit");
}

/**
 * @brief Skip fronthaul AP index
 *
 * @param unit Band index
 * @param vidx fronthaul AP subunit
 * @return int 0: No. 1: Skip the band and subunit
 */
static int skip_fronthaul_ap(int unit, int vidx)
{
	int SUMband = num_of_wl_if();
	int dwb_band = nvram_get_int("dwb_band");
	char fh_prefix[sizeof("fh_wlXXXX_")], tmp[64];

	snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", dwb_band);

	if (SUMband >= TRI_BAND && unit == dwb_band &&
		strlen(nvram_safe_get(strcat_r(fh_prefix, "ssid", tmp))) > 0) {
		int fh_ap_idx = get_fronthaul_ap_idx();
		if (vidx == fh_ap_idx)
			return 1;
	}
	return 0;
}
#endif

/**
 * @brief Process fronthaul ap bss
 *
 * @param sig Signal
 */
void ctl_wifi_bss_cap(int sig)
{
#ifdef RTCONFIG_FRONTHAUL_DWB
	int dwb_mode = nvram_get_int("dwb_mode");
	int SUMband = num_of_wl_if();
	static int old_fh_ap_bss = -1;
	int dwb_band = nvram_get_int("dwb_band");
	char fh_prefix[sizeof("fh_wlXXXX_")], tmp[64];

	if ((dwb_mode == 1 || dwb_mode == 3) &&
								nvram_get_int("fh_ap_enabled") > 0) {
		snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", dwb_band);
		if (SUMband >= TRI_BAND && strlen(nvram_safe_get(strcat_r(fh_prefix, "ssid", tmp))) > 0) { // Tri band models and profile is be created.

			int fh_ap_bss = nvram_get_int("fh_ap_bss");

			LC_DBG("Processing fronthaul AP. Old state: %d, state: %d\n", old_fh_ap_bss, fh_ap_bss);

			if (do_confirm_driver_bss(old_fh_ap_bss, fh_ap_bss) == 1) // workaround.
				old_fh_ap_bss = -1; // re-confirm

			if (old_fh_ap_bss != fh_ap_bss) {
				int setting_fail = 0, wl_assoc = 0;
				if (fh_ap_bss) {
					wl_assoc = get_wlan_service_status(dwb_band, get_fronthaul_ap_idx());
					if (wl_assoc == -1)  // Error
						setting_fail = 1;
					else if (wl_assoc == 0) {
						LC_DBG("Fronthaul AP BSS = %d Enable unit:%d vidx:%d network service finished\n", fh_ap_bss, dwb_band, get_fronthaul_ap_idx());
						set_wlan_service_status(dwb_band, get_fronthaul_ap_idx(), 1);
						if (get_wlan_service_status(dwb_band, get_fronthaul_ap_idx()) <= 0)  // Enable fail
							setting_fail = 1;
					}
				} else {
					wl_assoc = get_wlan_service_status(dwb_band, get_fronthaul_ap_idx());
					if (wl_assoc == -1)  // Error
						setting_fail = 1;
					else if (wl_assoc > 0) {
						LC_DBG("Fronthaul AP BSS = %d Disable unit:%d vidx:%d network service finished\n", fh_ap_bss, dwb_band, get_fronthaul_ap_idx());
						set_wlan_service_status(dwb_band, get_fronthaul_ap_idx(), 0);
						if (get_wlan_service_status(dwb_band, get_fronthaul_ap_idx()) > 0)  // Disable fail
							setting_fail = 1;
					}
				}
				if (!setting_fail)
					old_fh_ap_bss = fh_ap_bss;
			}
		}
	}
#endif

#ifdef RTCONFIG_VIF_ONBOARDING
	disable_onboarding_vif_bss();
#endif

	alarm(lanctrl_timer);
}

/**
 * @brief Re-check WiFi BSS status and up/down network service
 *
 * @param sig Received signal
 */
void re_check_bss(int sig)
{
	LC_DBG("Receive SIGUSR1. Re-Check WiFi bss status.\n");
	amas_wait_wifi_ready();
	recheck_bss = 1;
}
#if defined(RTCONFIG_QCA)
static int process_band_info(void)
{
    int i,SUMband = num_of_wl_if();
    time_t cur_time=uptime();
	
    if((!nvram_get_int("wlready") || !nvram_get_int("cfg_alive")) || (cur_time-init_time <15)) //check per 15 sec
	    return -1;
    init_time=cur_time;
	
    for (i = 0; i < SUMband; i++) 
	update_band_info(i);
    return 0;
}	
#endif

#ifdef RTCONFIG_BCMWL6
/**
 * @brief Start acsd or not.
 *
 */
static void process_acsd() {
    int SUMband = num_of_wl_if();
    int i;
    char *acs_ifnames = strdup(nvram_safe_get("acs_ifnames"));
    char wlc_status[] = "wlcXXX_status", wl_ifname[] = "wlXXX.XXXX_ifname", amas_wl_noacsd[] = "amas_wlXXX_noacsd", wl_chsync[] = "wlXXXX_chsync";
    char wl_radio[] = "wlXXXX_radio";
    int restart_acsd = 0;
    int restart_threshold = 3;  // default.
    static int diff_count = 0;

    for (i = 0; i < SUMband; i++) {
        snprintf(wlc_status, sizeof(wlc_status), "wlc%d_status", get_wlc_bandindex_by_unit(i));
        snprintf(wl_ifname, sizeof(wl_ifname), "wl%d.1_ifname", i);
        snprintf(amas_wl_noacsd, sizeof(amas_wl_noacsd), "amas_wl%d_noacsd", i);
        snprintf(wl_chsync, sizeof(wl_chsync), "wl%d_chsync", i);
        snprintf(wl_radio, sizeof(wl_radio), "wl%d_radio", i);
        LC_DBG("ifname(%s) status(%d) chsync(%d) radio(%d)\n", nvram_safe_get(wl_ifname), nvram_get_int(wlc_status),
            nvram_get_int(wl_chsync), nvram_get_int(wl_radio));

        if (nvram_get_int(wl_radio) == 0) {
            LC_DBG("uint(%d) radio is off\n", i);
            continue;
        }

        if (nvram_get_int(amas_wl_noacsd) == 1) {
            if (strstr(acs_ifnames, nvram_safe_get(wl_ifname))) {
                restart_acsd = 1;
            }
        } else if (nvram_get(wlc_status) && nvram_get(wl_ifname)) {
            switch (nvram_get_int(wlc_status)) {
                case CH_SYNC_NO_USE:
                case CH_SYNC_NO_COONECT:
                case CH_SYNC_ETH_BHL:
                case CH_SYNC_WIFI_BHL:
                    if (nvram_get_int(wl_chsync)) {
                        if (strstr(acs_ifnames, nvram_safe_get(wl_ifname)))
                            restart_acsd = 1;
                    }
                    else if (!strstr(acs_ifnames, nvram_safe_get(wl_ifname))) {
                        restart_acsd = 1;
                    }
                    break;
                default:
                    if (strstr(acs_ifnames, nvram_safe_get(wl_ifname))) {
                        restart_acsd = 1;
                    }
                    break;
            }
        }
        if (restart_acsd)
            break;
    }

    if (restart_acsd) {
        diff_count++;
        if (diff_count > restart_threshold) {
            LC_DBG("acs_ifname changed. Restart wireless.\n");
            diff_count = 0;
            set_acs_ifnames();
            if (strlen(nvram_safe_get("acs_ifnames")) == 0)
                notify_rc("stop_acsd");
            else
                notify_rc("restart_acsd");
        }
    } else {
        diff_count = 0;
    }

    if (acs_ifnames)
        free(acs_ifnames);
}
#endif

/**
 * @brief Do recheck bss?
 *
 * @return int Check(1) or Not need(0)
 */
static int do_recheck_bss()
{
	int recheck = 0;

	if (recheck_bss == 1) {
		recheck = 1;
		recheck_bss = 0;
	}

	if (nvram_get_int("amas_recheck_bss") == 1) {
		recheck = 1;
		nvram_unset("amas_recheck_bss");
		LC_DBG("Got amas_recheck_bss. Re-Check WiFi bss status.\n");
		amas_wait_wifi_ready();
	}
	return recheck;
}

void ctl_wifi_bss_re(int sig)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	char word[256], *next;
	int unit = 0;
	char wl_ifnames[32] = { 0 };
	int wl_assoc = 0;
	int vidx = 0;
	int setting_fail = 0;
#ifdef RTCONFIG_VIF_ONBOARDING
	int obvif_unit = WL_2G_BAND, obvif_subunit = nvram_get_int("obvif_cap_subunit");
#endif
#ifdef RTCONFIG_FRONTHAUL_DBG
	int fh_dbg_unit = 0, fh_dbg_subunit = nvram_get_int("fh_re_dbg_subunit");
#endif

#ifdef RTCONFIG_VIF_ONBOARDING
	if (nvram_get_int("re_mode") == 1)
		obvif_subunit = nvram_get_int("obvif_re_subunit");
#endif

    lanctl_dbg = nvram_get_int("lanctl_dbg");
    wl_assoc = 0;
    unit = 0;
    static int old_cfg_stat = -1;
    int cfg_stat = nvram_get_int("cfg_alive");
#ifdef RTCONFIG_FRONTHAUL_DWB
	int dwb_mode = nvram_get_int("dwb_mode");
	int SUMband = num_of_wl_if();
	static int old_fh_ap_bss = -1;
	int dwb_band = nvram_get_int("dwb_band");
	char fh_prefix[sizeof("fh_wlXXXX_")];
#endif
	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	LC_DBG("cfg_alive = %d old_cfg_stat = %d\n",cfg_stat, old_cfg_stat);
	if (cfg_stat != old_cfg_stat || do_recheck_bss() == 1) {
        if (cfg_stat == 0) {
            foreach (word, wl_ifnames, next)
            {
                for(vidx=1; vidx < MAX_SUBIF_NUM; vidx++)
                {
#ifdef RTCONFIG_VIF_ONBOARDING
                    /* pass onboarding vif */
                    if (unit == obvif_unit && vidx == obvif_subunit)
                        continue;
#endif
#ifdef RTCONFIG_FRONTHAUL_DBG
                    /* pass fronthaul dbg */
                    if (unit == fh_dbg_unit && vidx == fh_dbg_subunit)
                        continue;
#endif
                    memset(prefix, 0x00, sizeof(prefix));
                    snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, vidx);
                    if(nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
                    {
			strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
                        wl_assoc = get_wlan_service_status(unit, vidx);
                        if (wl_assoc == -1) {
                            setting_fail = 1;
                            continue;
                        }
                        else if (wl_assoc == -2) //radio off
                            continue;
                        LC_DBG("cfg_alive = %d Disabled %s network service (wl_assoc = %d)\n",cfg_stat, ifname , wl_assoc);
#if defined(RTCONFIG_PRELINK)
                        LC_DBG("reset lldpd hash bundle key\n");
                        update_lldp_hash_bundle_key(1);
#endif
                        if(wl_assoc > 0)
                        {
                            LC_DBG("cfg_alive = %d Disabled %s network service finished\n",cfg_stat, ifname);
                            set_wlan_service_status(unit, vidx, 0);
							if (get_wlan_service_status(unit, vidx) > 0) // Disable fail
								setting_fail = 1;
                        }
                    }
                }
                unit ++;
            }
        }
        else {
            unit = 0;
            foreach (word, wl_ifnames, next)
            {
#ifdef RTCONFIG_HND_ROUTER_AX
                if (need_downstream_ap_keep_down(unit)) {
                    unit++;
                    continue;
                }
                if (sta_connecting_keep_ap_down(unit)) {
                    unit++;
                    recheck_bss = 1;
                    continue;
                }
#endif
                for(vidx=1; vidx < MAX_SUBIF_NUM; vidx++)
                {
                    memset(prefix, 0x00, sizeof(prefix));
#ifdef RTCONFIG_VIF_ONBOARDING
                    /* pass onboarding vif */
                    if (unit == obvif_unit && vidx == obvif_subunit)
                        continue;
#endif
#ifdef RTCONFIG_FRONTHAUL_DBG
                    /* pass fronthaul dbg */
                    if (unit == fh_dbg_unit && vidx == fh_dbg_subunit)
                        continue;
#endif
                    snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, vidx);
                    if(nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
                    {
#ifdef RTCONFIG_FRONTHAUL_DWB
						if (nvram_get_int("fh_ap_enabled") > 0) { // Skip fronthual AP interface.
							if (dwb_mode == 1 || dwb_mode == 3)
								if (skip_fronthaul_ap(unit, vidx) == 1) {
									LC_DBG("Skip fronthual AP unit:%d, Vidx:%d\n", unit, vidx);
									continue;
								}
						}
#endif
			strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

                        wl_assoc = get_wlan_service_status(unit, vidx);
                        if (wl_assoc == -1) {
                            setting_fail = 1;
                            continue;
                        }
                        else if (wl_assoc == -2) // radio off
                            continue;

                        LC_DBG("cfg_alive = %d Enable %s network service (wl_assoc = %d)\n",cfg_stat, ifname , wl_assoc);
#if defined(RTCONFIG_PRELINK)
                        LC_DBG("set lldpd hash bundle key\n");
                        update_lldp_hash_bundle_key(0);
#endif

                        if (wl_assoc <= 0)
                        {
                            LC_DBG("cfg_alive = %d Enable %s network service finished\n",cfg_stat, ifname);
                            set_wlan_service_status(unit, vidx, 1);
							if (get_wlan_service_status(unit, vidx) <= 0) // Enable fail
								setting_fail = 1;
                        }
                    }
                }
                unit ++;
            }
        }
#ifdef RTCONFIG_FRONTHAUL_DWB
		old_fh_ap_bss = -1; // re-processing fronthaul AP.
#endif
		if (!setting_fail) // Setting fail. Do setting again.
			old_cfg_stat = cfg_stat;
    }
	else if (cfg_stat == 1)
	{
		/* if cf_alive=1 and no backhaul, restart cfg_client */
		if (nvram_get_int("amas_path_stat") == -1 && nvram_get_int("cfg_sync_stage") == 0) {
			LC_DBG("cf_alive = 1 and no backhaul, restart cfg_client\n");
			notify_rc("start_cfgsync");
		}
#ifdef RTCONFIG_HND_ROUTER_AX
		else
			check_5g_fh_bss();
#endif
	}
#ifdef RTCONFIG_FRONTHAUL_DWB
	// Processing fronthaul AP
	setting_fail = 0;
	if ((dwb_mode == 1 || dwb_mode == 3) &&
		nvram_get_int("fh_ap_enabled") > 0 &&
		cfg_stat == 1) {
		snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", dwb_band);
		if (SUMband >= TRI_BAND && strlen(nvram_safe_get(strcat_r(fh_prefix, "ssid", tmp))) > 0) {  // Tri band models and profile is be created.

			int fh_ap_bss = nvram_get_int("fh_ap_bss");

			LC_DBG("Processing fronthaul AP. Old state: %d, state: %d\n", old_fh_ap_bss, fh_ap_bss);

			if (do_confirm_driver_bss(old_fh_ap_bss, fh_ap_bss) == 1) // workaround
				old_fh_ap_bss = -1; // re-confirm

			if (old_fh_ap_bss != fh_ap_bss) {
				if (fh_ap_bss) {
#ifdef RTCONFIG_HND_ROUTER_AX
					if (sta_connecting_keep_ap_down(dwb_band) == 1) {
						setting_fail = 1;
					} else {
#endif
						wl_assoc = get_wlan_service_status(dwb_band, get_fronthaul_ap_idx());
						if (wl_assoc == -1)  // Error
							setting_fail = 1;
						else if (wl_assoc == 0) {
							LC_DBG("Fronthaul AP BSS = %d Enable unit:%d vidx:%d network service finished\n", fh_ap_bss, dwb_band, get_fronthaul_ap_idx());
							set_wlan_service_status(dwb_band, get_fronthaul_ap_idx(), 1);
							if (get_wlan_service_status(dwb_band, get_fronthaul_ap_idx()) <= 0)  // Enable fail
								setting_fail = 1;
						}
#ifdef RTCONFIG_HND_ROUTER_AX
					}
#endif
				} else {
					wl_assoc = get_wlan_service_status(dwb_band, get_fronthaul_ap_idx());
					if (wl_assoc == -1)  // Error
						setting_fail = 1;
					else if (wl_assoc > 0) {
						LC_DBG("Fronthaul AP BSS = %d Disable unit:%d vidx:%d network service finished\n", fh_ap_bss, dwb_band, get_fronthaul_ap_idx());
						set_wlan_service_status(dwb_band, get_fronthaul_ap_idx(), 0);
						if (get_wlan_service_status(dwb_band, get_fronthaul_ap_idx()) > 0)  // Disable fail
							setting_fail = 1;
					}
				}
				if (!setting_fail)
					old_fh_ap_bss = fh_ap_bss;
			}
		}
	}
#endif

#ifdef RTCONFIG_VIF_ONBOARDING
	disable_onboarding_vif_bss();
#endif

#ifdef RTCONFIG_BCMWL6
    process_acsd();
#endif
#ifdef RTCONFIG_QCA
    process_band_info();
#endif    

    alarm(lanctrl_timer);
}

int amas_lanctrl_main() {

	FILE *fp = NULL;
	lanctrl_timer = nvram_get_int("lanctrl_timer") ? : INTERVAL;
	lanctl_dbg = nvram_get_int("lanctl_dbg");
	int i = 0;
	char wl_chsync[] = "wlXXXX_chsync";
#if defined(RTCONFIG_QCA)
	init_time = uptime();
#endif	
	amas_wait_wifi_ready();

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

	/* write pid */
	if ((fp = fopen("/var/run/amas_lanctrl.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

#ifdef RTCONFIG_HND_ROUTER_AX
	if (nvram_get_int("re_mode") == 1) {
		while (nvram_get_int("amas_status_init") != 1) {
			LC_DBG("Waiting for amas_status init.\n");
			sleep(1);
		}
	}
	bh_5g_index = get_5g_bh_index();
	LC_DBG("bh_5g_index(%d)\n", bh_5g_index);
#endif

#if defined(RTCONFIG_VIF_ONBOARDING) && (defined(CONFIG_BCMWL5) || defined(RTCONFIG_BCMARM))
	disable_count = nvram_get_int("obvif_disable_count") ? nvram_get_int("obvif_disable_count") : OBVIF_DISABLE_COUNT;
#endif

	/* unset the status of channel sync under RE mode */
	if (nvram_get_int("re_mode") == 1) {
		for (i = 0; i < num_of_wl_if(); i++) {
			snprintf(wl_chsync, sizeof(wl_chsync), "wl%d_chsync", i);
			nvram_unset(wl_chsync);
		}
	}

#if defined(RTCONFIG_FRONTHAUL_DWB) || defined(RTCONFIG_VIF_ONBOARDING)
	if (nvram_get_int("re_mode") == 1)
		signal(SIGALRM, ctl_wifi_bss_re); // ctl_wifi_bss_re
	else
		signal(SIGALRM, ctl_wifi_bss_cap); // ctl_wifi_bss_cap
#else
    signal(SIGALRM, ctl_wifi_bss_re);
#endif

	signal(SIGUSR1, re_check_bss);

    alarm(lanctrl_timer);

	while (1)
	{
		pause();
	}
	return 0;
}

#if defined(RTCONFIG_PRELINK)
void update_lldp_hash_bundle_key(int reset)
{
	int ret = 0;

	LC_DBG("reset (%d)", reset);

	amas_utils_set_debug(1);
	ret = amas_set_hash_bundle_key(reset);
	LC_DBG("lldp result(%d)", ret);
}
#endif