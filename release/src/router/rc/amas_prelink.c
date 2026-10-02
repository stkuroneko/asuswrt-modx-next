/*
 * Copyright 2019, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

/* Prelink */

#include <stdio.h>
#include <rc.h>
#ifdef RTCONFIG_AMAS
#include <amas-utils.h>
#endif

char *param_suffix[] = {"ssid", "auth_mode_x", "wep_x", "key", "key1", "key2", "key3", "key4", "crypto",
			"wpa_psk", "closed", "bss_enabled", "lanaccess"};

int set_prelink_config(char *prefix)
{
	char prelink_ssid[33], prelink_psk[33], tmp[100];
	int ret = 0;

	if (amas_gen_default_backhaul_security(prelink_ssid, sizeof(prelink_ssid), prelink_psk, sizeof(prelink_psk)) == AMAS_RESULT_SUCCESS) {
		nvram_set(strcat_r(prefix, "ssid", tmp), prelink_ssid);
		nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "psk2");
		nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
		nvram_set(strcat_r(prefix, "wpa_psk", tmp), prelink_psk);
		if (nvram_get("plk_closed"))
			nvram_set(strcat_r(prefix, "closed", tmp), nvram_safe_get("plk_closed"));
		else
			nvram_set(strcat_r(prefix, "closed", tmp), "1");
#ifdef RTCONFIG_MSSID_PRELINK
		nvram_set(strcat_r(prefix, "lanaccess", tmp), "on");
#endif
		ret = 1;
	}

	return ret;
}

#ifdef RTCONFIG_MSSID_PRELINK
void restore_mssid_prelink_config()
{
	int rev3 = 0;
	char ssid[32];
	char prefix[]="wlXXXXXX_", tmp[100];
	int defpsk = strlen(nvram_safe_get("wifi_psk")) && nvram_contains_word("rc_support", "defpsk");
	int total_band = 0, mssid_subunit = 0;

	total_band = num_of_wl_if();
	mssid_subunit = nvram_get_int("plk_cap_subunit");

	if (nvram_get_int("re_mode") == 1)
		mssid_subunit = nvram_get_int("plk_re_subunit");

#if defined(RTCONFIG_NEWSSID_REV2) || defined(RTCONFIG_NEWSSID_REV4)
	rev3 = 1;
#endif

	snprintf(prefix, sizeof(prefix), "wl%d.%d_", total_band - 1, mssid_subunit); //last band and last mssid
	nvram_set(strcat_r(prefix, "ssid", tmp), SSID_PREFIX);

	strlcpy(ssid, get_default_ssid(total_band - 1, mssid_subunit), sizeof(ssid));
#ifndef RTCONFIG_SSID_AMAPS
	if (defpsk
		|| (rev3
#ifdef RTAC68U
		&& is_ssid_rev3_series()
#endif
	))
#endif
		nvram_set(strcat_r(prefix, "ssid", tmp), ssid);

	nvram_set(strcat_r(prefix, "bss_enabled", tmp), "0");
	nvram_set(strcat_r(prefix, "closed", tmp), "0");
	nvram_set(strcat_r(prefix, "lanaccess", tmp), "off");
	if (defpsk)
	{
		nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "psk2");
		nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
		nvram_set(strcat_r(prefix, "wpa_psk", tmp), nvram_safe_get("wifi_psk"));
	}
	else
	{
		nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "open");
		nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
		nvram_set(strcat_r(prefix, "wpa_psk", tmp), "");
	}
}

void reset_mssid_prelink_config()
{
	char prefix[]="wlXXXXXX_", tmp[100];
	int total_band = 0, mssid_subunit = 0;

	total_band = num_of_wl_if();
	mssid_subunit = nvram_get_int("plk_re_subunit");

	/* restore mssid prelink config if need */
	restore_mssid_prelink_config();

	/* reset mssid prelink config on wlX.Y_ */
	snprintf(prefix, sizeof(prefix), "wl%d.%d_", total_band - 1, mssid_subunit);
	set_prelink_config(prefix);
}

void set_mssid_prelink_config()
{
	char prefix[]="wlXXXXXX_", tmp[100];
	int total_band = 0, mssid_subunit = 0;

	if (nvram_get_int("plk_re_set"))
		return;

	total_band = num_of_wl_if();
	mssid_subunit = nvram_get_int("plk_re_subunit");

	/* set mssid prelink config on wlX.Y_ for re mode */
	snprintf(prefix, sizeof(prefix), "wl%d.%d_", total_band - 1, mssid_subunit);
	set_prelink_config(prefix);

	nvram_set_int("plk_re_set", 1);
	nvram_commit();
}

void mssid_prelink_defaults()
{
	int result = 0, i = 0;
	char wl_prefix[] = "wlXXXXXX_", wl_prefix2[] = "wlXXXXXX_", *ssid = NULL, *psk = NULL;
	char wlbp_prefix[] = "wlbp_", tmp[100], tmp2[100];
	int total_band = 0, mssid_subunit = 0;

	nvram_unset("plk_need_reset");

	if (nvram_get_int("x_Setting") == 0 || nvram_get_int("plk_config_dup"))
		return;

	total_band = num_of_wl_if();
	mssid_subunit = nvram_get_int("plk_cap_subunit");
		
	/* check for old fw to new one */
	if (nvram_get_int("re_mode") == 1) {
		snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.1_", total_band - 1);
		mssid_subunit = nvram_get_int("plk_re_subunit");
	}
	else
	{
		/* not router mode or ap mode, return it */
		if (!is_router_mode() && !access_point_mode())
			return;
		snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", total_band - 1);
	}

	ssid = nvram_safe_get(strcat_r(wl_prefix, "ssid", tmp));
	psk = nvram_safe_get(strcat_r(wl_prefix, "wpa_psk", tmp));

	if (amas_verify_default_backhaul_security(ssid, psk, &result) == AMAS_RESULT_SUCCESS) {
		if (result) {
			_dprintf("it is prelink config on %s\n", wl_prefix);

			snprintf(wl_prefix2, sizeof(wl_prefix2), "wl%d.%d_", total_band - 1, mssid_subunit);

			/* backup the guest network setting of old fw (wlX.Y_ to wlbp_) and copy prelink config to mssid (wlX_ to wlX.Y_) */
			for (i = 0; i < ARRAY_SIZE(param_suffix); i++) {
				nvram_set(strcat_r(wlbp_prefix, param_suffix[i], tmp), nvram_safe_get(strcat_r(wl_prefix2, param_suffix[i], tmp2)));
				nvram_set(strcat_r(wl_prefix2, param_suffix[i], tmp), nvram_safe_get(strcat_r(wl_prefix, param_suffix[i], tmp2)));
			}

			nvram_set_int("plk_config_dup", 1);
			nvram_commit();
		}
	}
}	

void restore_prelink_config()
{
	int result = 0, i = 0;
	char wl_prefix[] = "wlXXXXXX_", wl_prefix2[] = "wlXXXXXX_", *ssid = NULL, *psk = NULL;
	char wlbp_prefix[] = "wlbp_", tmp[100], tmp2[100];
	int total_band = 0, mssid_subunit = 0;

	if (!nvram_get_int("plk_need_reset"))
		return;

	nvram_unset("plk_need_reset");

	total_band = num_of_wl_if();
	mssid_subunit = nvram_get_int("plk_cap_subunit");

	if (nvram_get_int("re_mode") == 1)
		mssid_subunit = nvram_get_int("plk_re_subunit");
	else
	{
		/* not router mode or ap mode, return it */
		if (!is_router_mode() && !access_point_mode())
			return;
	}

	/* check for new fw to old one */
	snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.%d_", total_band - 1, mssid_subunit);
	ssid = nvram_safe_get(strcat_r(wl_prefix, "ssid", tmp));
	psk = nvram_safe_get(strcat_r(wl_prefix, "wpa_psk", tmp));

	if (amas_verify_default_backhaul_security(ssid, psk, &result) == AMAS_RESULT_SUCCESS) {
		if (result) {
			_dprintf("it is prelink config on %s\n", wl_prefix);

			if (nvram_get_int("re_mode") == 1)
				snprintf(wl_prefix2, sizeof(wl_prefix), "wl%d.1_", total_band - 1);
			else
				snprintf(wl_prefix2, sizeof(wl_prefix), "wl%d_", total_band - 1);

			/* restore prelink config (wlX.Y_ to wlX.1_/wlX_) and  the guest network setting of old fw (wlbp_ to wlX.Y_)*/
			for (i = 0; i < ARRAY_SIZE(param_suffix); i++) {
				nvram_set(strcat_r(wl_prefix2, param_suffix[i], tmp), nvram_safe_get(strcat_r(wl_prefix, param_suffix[i], tmp2)));

				if (nvram_get_int("plk_config_dup")) {
					nvram_set(strcat_r(wl_prefix, param_suffix[i], tmp), nvram_safe_get(strcat_r(wlbp_prefix, param_suffix[i], tmp2)));
					nvram_unset(strcat_r(wlbp_prefix, param_suffix[i], tmp2));
				}
			}

			if (nvram_get_int("plk_config_dup") == 0)
				restore_mssid_prelink_config();

			nvram_unset("plk_config_dup");
			nvram_unset("plk_closed");
			nvram_unset("plk_cap_subunit");
			nvram_unset("plk_re_subunit");
			nvram_commit();
		}
	}
}	

void set_mssid_prelink_bss_enabled(int unit, int subunit)
{
	char prefix[]="wlXXXXXX_", tmp[100];
	int total_band = 0, mssid_subunit = nvram_get_int("plk_cap_subunit");
	int prelink = nvram_invmatch("amas_bdlkey", "");
	char ssid[64], psk[64];
	int result = 0;

	if (nvram_get_int("x_Setting") == 0)
		return;

	total_band = num_of_wl_if();

	if (nvram_get_int("re_mode") == 1)
		mssid_subunit = nvram_get_int("plk_re_subunit");

	/* set mssid prelink config on wlX.Y_ */
	if (prelink && total_band == (unit +1) && mssid_subunit == subunit) {
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", total_band - 1, mssid_subunit);
		if (nvram_get_int("re_mode") == 1 || is_router_mode() || access_point_mode()) {
			strlcpy(ssid, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), sizeof(ssid));
			strlcpy(psk, nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)), sizeof(psk));
			if (amas_verify_default_backhaul_security(ssid, psk, &result) == AMAS_RESULT_SUCCESS) {
				nvram_set(strcat_r(prefix, "bss_enabled", tmp), result ? "1": "0");
				if (nvram_get_int("plk_config_dup") && !nvram_match(strcat_r(prefix, "mode", tmp), "ap"))
					nvram_set(strcat_r(prefix, "mode", tmp), "ap");
			}
			else
				nvram_set(strcat_r(prefix, "bss_enabled", tmp), "0");
		}
		else
		{
			nvram_set(strcat_r(prefix, "bss_enabled", tmp), "0");
		}
	}
}
#endif	/* RTCONFIG_MSSID_PRELINK */
