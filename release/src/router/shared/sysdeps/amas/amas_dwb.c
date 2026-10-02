#include "amas_dwb.h"
#include "utils.h"
#include "shutils.h"
#include "shared.h"

#ifdef SMART_CONNECT
const char *sc_basic_param[] = {
	"smart_connect_x",
	"bsd_ifnames",
	"bsd_bounce_detect",
	NULL
};

const char *sc_detailed_param[] = {
	"bsd_steering_policy",
	"bsd_sta_select_policy",
	"bsd_if_select_policy",
	"bsd_if_qualify_policy",
	NULL
};

/*
========================================================================
Routine Description:
    Revert the parameters of smart connect.

Arguments:
    bandNum		- the number of supported band

Return Value:
    None

========================================================================
*/
void cm_revertSmartConnectParameters(int bandNum)
{
    if (nvram_get_int("dwb_scb") != 1)  // Not backup SmartConnectParameters. Don't need to revert.
        return;

    int i = 0, size = 0;
    char wlPrefix[]= "wlXXXXXXX_", scbWlPrefix[] = "scb_wlXXXXXXX_", scbPrefix[] = "scb_";
    char word[64] = {0}, *next = NULL;
    char tmp[100] = {0}, tmp2[100] = {0};
    int unit = 0;
    char wl_ifnames[32] = { 0 };
    int dwb_band = nvram_get_int("dwb_band");

    /* for basic parameters of smart connect */
    unit = 0;
    size = sizeof(sc_basic_param)/sizeof(char*);
    for (i = 0; i < size; i++) {
        if (sc_basic_param[i] != NULL) {
            if (!strcmp(sc_basic_param[i], "bsd_ifnames")) {
                nvram_set(sc_basic_param[i],
                          nvram_safe_get(strcat_r(scbPrefix, sc_basic_param[i], tmp)));
            } else if (!strcmp(sc_basic_param[i], "smart_connect_x")) {
                if (nvram_get_int("amas_eap_bhmode") <= 0) {  // EAP on, Don't recover.
                    switch (nvram_get_int(strcat_r(scbPrefix, sc_basic_param[i], tmp))) {
                        case 2:  // 5G-1/5G-2 smart connect
                            if (nvram_get_int("smart_connect_x") == 0) {
                                nvram_set(sc_basic_param[i],
                                          nvram_safe_get(strcat_r(scbPrefix, sc_basic_param[i], tmp)));
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
            nvram_unset(strcat_r(scbPrefix, sc_basic_param[i], tmp));
        }
    }

    /* for detailed parameters of smart connect */
    unit = 0;
    size = sizeof(sc_detailed_param)/sizeof(char*);

    strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
    foreach(word, wl_ifnames, next) {
        /* pass dwb band */
        if (unit == dwb_band) {
            unit++;
            continue;
        }

        memset(wlPrefix, 0, sizeof(wlPrefix));
        memset(scbWlPrefix, 0, sizeof(scbWlPrefix));
        snprintf(wlPrefix, sizeof(wlPrefix), "wl%d_", unit);
        snprintf(scbWlPrefix, sizeof(scbWlPrefix), "scb_wl%d_", unit);

        for (i = 0; i < size; i++) {
            if (sc_detailed_param[i] != NULL) {
                if (!strcmp(sc_detailed_param[i], "bsd_if_select_policy")) {  // Only revert bsd_if_select_policy
                    nvram_set(strcat_r(wlPrefix, sc_detailed_param[i], tmp),
                              nvram_safe_get(strcat_r(scbWlPrefix, sc_detailed_param[i], tmp2)));
                }
                nvram_unset(strcat_r(scbWlPrefix, sc_detailed_param[i], tmp));
            }
        }

        unit++;
    }
    nvram_unset("dwb_scb");
} /* End of cm_revertSmartConnectParameters */
#endif

struct connect_param_mapping_s connect_param_mapping_list[] = {
    { "ssid" },
    { "bss_enabled" },
    { "wpa_psk" },
    { "auth_mode_x" },
    { "crypto" },
    { "mbss" },
    { "closed" },
    { "wep_x" },
    { "key" },
    { "key1" },
    { "key2" },
    { "key3" },
    { "key4" },
    { NULL}
};

#ifdef RTCONFIG_FRONTHAUL_DWB
/**
 * @brief Wireless basic config parameters.
 * 
 */
struct basic_wireless_setting_s basic_wireless_settings[] = {
    {"ssid"},
    {"bss_enabled"},
    {"closed"},
    {"wpa_psk"},
    {"auth_mode_x"},
    {"crypto"},
    {"wep_x"},
    {"key"},
    {"key1"},
    {"key2"},
    {"key3"},
    {"key4"},
    {"lanaccess"},
    {"macmode"},
    {"maclist_x"},
    {NULL}
};

/**
 * @brief Checking is the DWB frontfaul AP profile be generated.
 * 
 * @param unit band index
 * @param subunit sububit index
 * @return int Generated or not. 0: Not. 1: Generated.
 */
int fronthaul_DWB_profile_generated(int unit, int subunit)
{
    char fh_prefix[] = "fh_wlXXX_", bkwl_prefix[] = "bk_wlXXX_", tmp[64] = {};
    int total_band = num_of_wl_if();
    int fh_subunit = 0, band = 0;

    if (total_band == TRI_BAND)
        band = 2;
    else
        return 0;  // not support dual band

    memset(fh_prefix, 0x0, sizeof(fh_prefix));
    snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", band);
    memset(bkwl_prefix, 0x0, sizeof(bkwl_prefix));
    snprintf(bkwl_prefix, sizeof(bkwl_prefix), "bk_wl%d_", band);

    fh_subunit = nvram_get_int("re_mode") == 1 ? nvram_get_int("fh_re_mssid_subunit") : nvram_get_int("fh_cap_mssid_subunit");

    if (subunit != fh_subunit)
        return 0;
    if (unit != band)
        return 0;
    if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) != 1)  // not generated.
        return 0;

    return 1;
}
#endif

void dwb_init_settings(void)
{
	char wif[128] = {0}, *next = NULL;
	int SUMband = 0;
	char wl_ifnames[32] = { 0 };

	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (wif, wl_ifnames, next) {
		SUMband++;
	}

    /* Init dwb_band */
    if (nvram_get("dwb_band") == NULL || strlen(nvram_safe_get("dwb_band")) == 0) {
        nvram_set_int("dwb_band", 2);
    }

	if (SUMband == DUAL_BAND)
		return;

	if (nvram_get_int("cfg_obcount") == 0 && nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI && nvram_get_int("re_mode") != 1) {

		nvram_set_int("dwb_mode", DWB_DISABLED_FROM_CFG);
#ifdef SMART_CONNECT
		cm_revertSmartConnectParameters(SUMband);
#endif
		nvram_commit();
	}
	return;
}
