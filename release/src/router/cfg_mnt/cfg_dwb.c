#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <pthread.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_dwb.h"
#include "cfg_capability.h"

#define CFG_JSON_FILE                     "/tmp/cfg.json"

#define DWB_DBG(fmt, arg...) do {\
    if (!strcmp(nvram_safe_get("dwb_dbg"), "1")) \
        cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
    if (!strcmp(nvram_safe_get("dwb_syslog"), "1")) \
        asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

static int restart_wifi = 0;
int dwb_reSync = 0;

#ifdef RTCONFIG_FRONTHAUL_DWB
static int get_fh_ap_subunit();
#endif

#ifdef SMART_CONNECT
/**
 * @brief Reset bsd_ifnames if fronthaul network and DWB is be enabled
 *
 * @param cfgRoot config data from cfg_server
 * @param bsd_ifnames output
 * @param bsd_ifnames_len output len
 */
void cm_resetRESmartConnectBsdifnames(struct json_object *cfgRoot, char *bsd_ifnames, int bsd_ifnames_len) {
    int dwb_mode = 0;
    int SUMband = num_of_wl_if();
    int dwb_band = WL_5G_2_BAND;
    int smart_connect_x = 0;
    struct json_object *ftObj = NULL;

    json_object_object_get_ex(cfgRoot, "dwb_mode", &ftObj);
    if (ftObj != NULL)
        dwb_mode = json_object_get_int(ftObj);

    json_object_object_get_ex(cfgRoot, "wireless", &ftObj);
    if (ftObj == NULL)
        return;
    json_object_object_foreach(ftObj, key, val) {
        if (strcmp(key, "smart_connect_x") == 0) {
            smart_connect_x = json_object_get_int(val);
        }
    }
    char dwb_ifname[32] = {}, wl_ifname[] = "wlXXX.XXX_ifname";

    if (dwb_mode == DWB_ENABLED_FROM_CFG || dwb_mode == DWB_ENABLED_FROM_GUI) {
        if (SUMband >= TRI_BAND) {
            if (smart_connect_x == 1) {  //  triband smart connect
                snprintf(wl_ifname, sizeof(wl_ifname) - 1, "wl%d.1_ifname", dwb_band);
                strncpy(dwb_ifname, nvram_safe_get(wl_ifname), sizeof(dwb_ifname));
                if (strstr(bsd_ifnames, dwb_ifname)) {  // exist
                    remove_from_list(dwb_ifname, bsd_ifnames, bsd_ifnames_len - 1);
                }
            }
        }
    }
#ifdef RTCONFIG_FRONTHAUL_DWB
    char fh_prefix[] = "wlXX.XX_", fh_ifname[8] = {}, tmp[64] = {};
    int fh_subunit = get_fh_ap_subunit(), fh_ap_enabled = 0;
    char ssid_2g[33] = {}, ssid_5g[33] = {};

    json_object_object_get_ex(cfgRoot, "dwbctrl", &ftObj);
    if (ftObj == NULL)
        return;
    json_object_object_foreach(ftObj, k, v) {
        if (strcmp(k, "fh_ap_enabled") == 0) {
            fh_ap_enabled = json_object_get_int(v);
        }
    }

    json_object_object_get_ex(cfgRoot, "wireless", &ftObj);
    if (ftObj == NULL)
        return;
    json_object_object_foreach(ftObj, k2, v2) {
        if (strcmp(k2, "wl0_ssid") == 0) {
            strncpy(ssid_2g, json_object_get_string(v2), sizeof(ssid_2g) - 1);
        } else if (strcmp(k2, "wl1_ssid") == 0) {
            strncpy(ssid_5g, json_object_get_string(v2), sizeof(ssid_5g) - 1);
        }
    }

    snprintf(fh_prefix, sizeof(fh_prefix), "wl%d.%d_", dwb_band, fh_subunit);
    strncpy(fh_ifname, nvram_safe_get(strcat_r(fh_prefix, "ifname", tmp)), sizeof(fh_ifname));

    if (dwb_mode == DWB_ENABLED_FROM_CFG || dwb_mode == DWB_ENABLED_FROM_GUI) {
        if (fh_ap_enabled > 0 && SUMband >= TRI_BAND) {
            if (smart_connect_x == 1) {               //  triband smart connect
                if (!strstr(bsd_ifnames, fh_ifname))  // Not exist
                    add_to_list(fh_ifname, bsd_ifnames, bsd_ifnames_len);

            } else {
                if (!strcmp(ssid_2g, ssid_5g)) {
                    if (!strstr(bsd_ifnames, fh_ifname))  // Not exist
                        add_to_list(fh_ifname, bsd_ifnames, bsd_ifnames_len);
                }
            }
        }
    }
#endif
    return;
}

/**
 * @brief Reset wlX_bsd_if_select_policy if fronthaul network is be enabled
 *
 * @param cfgRoot config data from cfg_server
 * @param key config parameter key value
 * @param if_select_policy output variables
 */
void cm_resetRESmartConnectIfPolicy(struct json_object *cfgRoot, char *key, char **if_select_policy) {
#ifdef RTCONFIG_FRONTHAUL_DWB
    int dwb_mode = 0;
    int SUMband = num_of_wl_if();
    int dwb_band = WL_5G_2_BAND;
    int smart_connect_x = 0;
    struct json_object *ftObj = NULL;
    char ssid_2g[33] = {}, ssid_5g[33] = {};
    int need_to_add = 0, i, fh_subunit = get_fh_ap_subunit();
    char *ifprefix = NULL, *savePtr = NULL;
    char fh_prefix[] = "wlXX.XX_", fh_ifname[8] = {}, tmp[16] = {};
    int fh_ap_enabled = 0, ifindex = 0;
    char key_buf[32] = {};

    if (!strstr(key, "bsd_if_select_policy_idx"))
        return;

    //  Parser ifprefix
    strncpy(key_buf, key, sizeof(key_buf));
    ifprefix = strtok_r(key_buf, "_", &savePtr);
    if (ifprefix == NULL)
        return;
    sscanf(ifprefix, "wl%d", &ifindex);

    if (ifindex == dwb_band)
        return;

    json_object_object_get_ex(cfgRoot, "dwb_mode", &ftObj);
    if (ftObj != NULL)
        dwb_mode = json_object_get_int(ftObj);

    json_object_object_get_ex(cfgRoot, "dwbctrl", &ftObj);
    if (ftObj == NULL)
        return;
    json_object_object_foreach(ftObj, k2, v2) {
        if (strcmp(k2, "fh_ap_enabled") == 0) {
            fh_ap_enabled = json_object_get_int(v2);
        }
    }

    json_object_object_get_ex(cfgRoot, "wireless", &ftObj);
    if (ftObj == NULL)
        return;
    json_object_object_foreach(ftObj, k, v) {
        if (strcmp(k, "smart_connect_x") == 0) {
            smart_connect_x = json_object_get_int(v);
        } else if (strcmp(k, "wl0_ssid") == 0) {
            strncpy(ssid_2g, json_object_get_string(v), sizeof(ssid_2g) - 1);
        } else if (strcmp(k, "wl1_ssid") == 0) {
            strncpy(ssid_5g, json_object_get_string(v), sizeof(ssid_5g) - 1);
        }
    }

    if (dwb_mode == DWB_ENABLED_FROM_CFG || dwb_mode == DWB_ENABLED_FROM_GUI) {
        if (fh_ap_enabled > 0 && SUMband >= TRI_BAND) {
            snprintf(fh_prefix, sizeof(fh_prefix), "wl%d.%d_", dwb_band, fh_subunit);
            strncpy(fh_ifname, nvram_safe_get(strcat_r(fh_prefix, "ifname", tmp)), sizeof(fh_ifname));
            if (smart_connect_x == 1) {               //  triband smart connect
                if (!strstr(*if_select_policy, fh_ifname))  // Not exist
                    need_to_add = 1;
            } else {
                if (!strcmp(ssid_2g, ssid_5g)) {
                    if (!strstr(*if_select_policy, fh_ifname))  // Not exist
                        need_to_add = 1;
                }
            }
        }
    }

    if (need_to_add) {  // add to bsd_if_select_policy
        *if_select_policy = (char *)realloc(*if_select_policy, strlen(*if_select_policy) + strlen(fh_ifname) + 1 + 1);  // a space and a '\0'
        add_to_list(fh_ifname, *if_select_policy, strlen(*if_select_policy) + strlen(fh_ifname) + 1 + 1);
    }
#endif
    return;
}

/*
========================================================================
Routine Description:
    Backup the parameters of smart connect.

Arguments:
    bandNum		- the number of supported band

Return Value:
    0		- not set config
    1		- set config

========================================================================
*/
int cm_backupSmartConnectParameters(int bandNum)
{
    char wlPrefix[sizeof("wlXXXXXXX_")], scbWlPrefix[sizeof("scb_wlXXXXXXX_")], *scbPrefix = "scb_";
    char wlIfPrefix[sizeof("wlXXXXXXX_")];
    char word[64], *next, tmp[100], tmp2[100];
    char bsdIfnames[64] = "";
    const char **param;
    int unit;
    int dwb_band = nvram_get_int("dwb_band");
    char select_policy_if[32];
    int ret = 0;

    /* for basic parameters of smart connect */
    for (param = sc_basic_param; *param; param++) {
        nvram_set(strcat_r(scbPrefix, *param, tmp),
            nvram_safe_get(*param));
        ret = 1;
    }

    /* for detailed parameters of smart connect */
    unit = 0;
    foreach(word, nvram_safe_get("wl_ifnames"), next)
    {
        /* pass dwb band */
        if (unit == dwb_band) {
            unit++;
            continue;
        }

        add_to_list(word, bsdIfnames, sizeof(bsdIfnames));

        snprintf(wlPrefix, sizeof(wlPrefix), "wl%d_", unit);
        snprintf(scbWlPrefix, sizeof(scbWlPrefix), "scb_wl%d_", unit);

        for (param = sc_detailed_param; *param; param++) {
            nvram_set(strcat_r(scbWlPrefix, *param, tmp),
                nvram_safe_get(strcat_r(wlPrefix, *param, tmp2)));

            /* for converting bsd_if_select_policy */
            if (strcmp(*param, "bsd_if_select_policy") == 0)
            {
                memset(select_policy_if, 0, sizeof(select_policy_if));
                if (unit == WL_2G_BAND) {
                    snprintf(wlIfPrefix, sizeof(wlIfPrefix), "wl%d_",
#ifdef RTCONFIG_WIFI6E
                        (bandNum > TRI_BAND) ? WL_6G_BAND : WL_5G_BAND
#else
                        WL_5G_BAND
#endif
                        );
                    strlcpy(select_policy_if, nvram_safe_get(strcat_r(wlIfPrefix, "ifname", tmp)),
                        sizeof(select_policy_if));
                }
                else if (unit == WL_5G_BAND
#ifdef RTCONFIG_WIFI6E
                     || unit == WL_6G_BAND
#endif
                ) {
                    snprintf(wlIfPrefix, sizeof(wlIfPrefix), "wl%d_", WL_2G_BAND);
                    strlcpy(select_policy_if, nvram_safe_get(strcat_r(wlIfPrefix, "ifname", tmp)),
                        sizeof(select_policy_if));
                }
                else
                    continue;

                if (strlen(select_policy_if)) {
                    nvram_set(strcat_r(wlPrefix, *param, tmp), select_policy_if);
                    ret = 1;
                }
            }
        }

        unit++;
    }

    /* convert related parameters of smart connect */
    /* for smart_connect_x */
    if (nvram_get_int("smart_connect_x") == 2) { /* 5G only, disable it */
        DWB_DBG("smart connect is 5G only, disable it");
        nvram_set_int("smart_connect_x", 0);
        ret = 1;
    }

    /* for bsd_ifnames */
    if (*bsdIfnames)
        nvram_set("bsd_ifnames", bsdIfnames);

    if (ret)
        nvram_set("dwb_scb", "1");

    return ret;
} /* End of cm_backupSmartConnectParameters */
#endif /* #ifdef SMART_CONNECT */

/**
 * @brief 2.4G/5G <-> 6G auth_mode_x convert
 *
 * @param auth_mode_x auth_mode_x setting
 * @param src_nband Source band
 * @param dest_nband Destination band
 * @return char* Conver result
 */
static char *authentication_convert_band6(char *auth_mode_x, int src_nband, int dest_nband) {
    if (src_nband != 4 && dest_nband == 4) {  // 2.4G,5G -> 6G
        if (!strcmp(auth_mode_x, "open")) {   // open -> owe
            DWB_DBG("2.4,5G -> 6G, auth_mode_x open -> owe");
            return "owe";
        } else if (!strcmp(auth_mode_x, "owe") || !strcmp(auth_mode_x, "sae")) {
            DWB_DBG("2.4,5G -> 6G, auth_mode_x is owe or sae. Don't need to convert it.\n");
        } else {  // ??? -> sae
            DWB_DBG("2.4,5G -> 6G, auth_mode_x ??? -> sae");
            return "sae";
        }
    } else if (src_nband == 4 && dest_nband != 4) {  // 6G -> 2.4G,5G
        if (!strcmp(auth_mode_x, "sae")) {           // sae -> psk2sae
            DWB_DBG("6G -> 2.4,5G, auth_mode_x sae -> psk2sae");
            return "psk2sae";
        } else if (!strcmp(auth_mode_x, "owe")) {  // owe -> open
            DWB_DBG("6G -> 2.4,5G, auth_mode_x owe -> open");
            return "open";
        }
    }
    // exception
    return auth_mode_x;
}

/**
 * @brief 2.4G/5G <-> 6G crypto convert
 *
 * @param crypto crypto setting
 * @param auth_mode_x auth_mode_x setting
 * @param src_nband Source band
 * @param dest_nband Destination band
 * @return char* Conver result
 */
static char *crypto_convert_band6(char *crypto, char *auth_mode_x, int src_nband, int dest_nband) {
    if (src_nband != 4 && dest_nband == 4) {  // 2.4G,5G -> 6G
        if (!strcmp(auth_mode_x, "open")) {   // -> aes
            DWB_DBG("2.4,5G -> 6G, auth_mode_x open, crypto -> aes");
            return "aes";
        } else if (!strcmp(auth_mode_x, "owe") || !strcmp(auth_mode_x, "sae")) {
            DWB_DBG("2.4,5G -> 6G, auth_mode_x is owe or sae. Don't need to convert it.\n");
        } else {  // ??? -> aes
            DWB_DBG("2.4,5G -> 6G, auth_mode_x ???, crypto -> aes");
            return "aes";
        }
    } else if (src_nband == 4 && dest_nband != 4) {  // 6G -> 2.4G,5G
        if (!strcmp(auth_mode_x, "sae")) {           // -> aes
            DWB_DBG("6G -> 2.4G,5G, auth_mode_x sae, crypto -> aes");
            return "aes";
        } else if (!strcmp(auth_mode_x, "owe")) {  // -> ""
            DWB_DBG("6G -> 2.4G,5G, auth_mode_x owe, crypto -> \"\"");
            return "";
        }
    }
    // exception
    return crypto;
}

/**
 * @brief Reset authentication config
 *
 * @param unit band
 * @param prefix nvram prefix
 */
static void chk_authentication_config(int unit, char *prefix) {
    char wl_nband[] = "wlXXX_nband";
    int nband;
    char *auth_mode_x;
    char *crypto;
    char tmp[64] = {};

    snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", unit);
    nband = nvram_get_int(wl_nband);

    auth_mode_x = strdup(nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)));
    crypto = strdup(nvram_safe_get(strcat_r(prefix, "crypto", tmp)));

    if (nband == 4) {  // 6G
        if (auth_mode_x != NULL && strlen(auth_mode_x) > 0) {
            if (strcmp(auth_mode_x, "sae") && strcmp(auth_mode_x, "owe")) {
                DWB_DBG("auth_mode_x(%s) is not supported. Reset.\n", auth_mode_x);
                nvram_set(strcat_r(prefix, "auth_mode_x", tmp), authentication_convert_band6(auth_mode_x, 1, nband));
                nvram_set(strcat_r(prefix, "crypto", tmp), crypto_convert_band6(crypto, auth_mode_x, 1, nband));
            }
        }
    } else {
        if (auth_mode_x != NULL && strlen(auth_mode_x) > 0) {
            if (!strcmp(auth_mode_x, "sae") || !strcmp(auth_mode_x, "owe")) {
                DWB_DBG("auth_mode_x(%s) is equal to sae or owe. Reset.\n", auth_mode_x);
                nvram_set(strcat_r(prefix, "auth_mode_x", tmp), authentication_convert_band6(auth_mode_x, 4, nband));
                nvram_set(strcat_r(prefix, "crypto", tmp), crypto_convert_band6(crypto, auth_mode_x, 4, nband));
            }
        }
    }
    if (auth_mode_x)
        free(auth_mode_x);
    if (crypto)
        free(crypto);
}

/*
========================================================================
Routine Description:
   Convert wl paramters to wlc parameters.

Arguments:
    param             - wl param

Return Value:
    If needed, return converted param.
    If not, return wl param.

========================================================================
*/
static char *cm_convert_to_wlcparam(char *param) {

	const struct convert_wlc_mapping_s *pConvertWlc = &convert_wlc_mapping_list[0];

    for (pConvertWlc = &convert_wlc_mapping_list[0]; pConvertWlc->name != NULL;
         pConvertWlc++) {
        if (!strcmp(pConvertWlc->name, param)) {
			if (pConvertWlc->converted_name)
				return pConvertWlc->converted_name;
			break;
        }
    }
	return param;
}

/*
========================================================================
Routine Description:
   Check if need to update dedicated Wifi Backhaul Parameter.

Return Value:
    If needed, return 1.
    If not, return 0.

========================================================================
*/
static int cm_Do_Update_Dedicated_Wifi_Backhaul_Parameter()
{
    struct connect_param_mapping_s *pconnParam = NULL;
    char fh_prefix[] = "wlXXXXXXX_", bh_prefix[] = "dwb_wl_";
    char fh_parameter[256] = {0}, bh_parameter[256] = {0};
    char modified_ssid_val[64] = {0}, temp_ssid_val[64] = {0}, fh_ssid_val[64] = {0};
    int offset = 0;
#ifdef SMART_CONNECT
    if (nvram_get_int("smart_connect_x") != 0)
        snprintf(fh_prefix, sizeof(fh_prefix), "wl0_");
    else
#endif
    snprintf(fh_prefix, sizeof(fh_prefix), "wl1_");
    for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++) {
        snprintf(bh_parameter, sizeof(bh_parameter), "%s%s", bh_prefix, pconnParam->param);
        snprintf(fh_parameter, sizeof(fh_parameter), "%s%s", fh_prefix, pconnParam->param);

        if (nvram_get(bh_parameter)) {
            if (!strcmp(pconnParam->param, "ssid")) {
                strncpy(fh_ssid_val, nvram_safe_get(fh_parameter), sizeof(fh_ssid_val));
                if (strlen(fh_ssid_val) <= 28) {
                    snprintf(modified_ssid_val, sizeof(modified_ssid_val), "%s_dwb", fh_ssid_val);
                }
                else {
                    offset = strlen(fh_ssid_val) - 28;
                    while (1) { // multi-bytes character check.
                        if ((*(fh_ssid_val + (strlen(fh_ssid_val) - offset)) & 0xC0) == 0xC0) { // multi-bytes character. 1100 0000. Byte 1
                            break;
                        } else if ((*(fh_ssid_val + (strlen(fh_ssid_val) - offset)) & 0x80) == 0x80) { // multi-bytes character. 1000 0000. Byte 2/3/4/5/6
                            offset++;
                        } else { // 0xxxx xxxx. 1 byte character.
                            break;
                        }
                    }
                    strncpy(temp_ssid_val, fh_ssid_val, strlen(fh_ssid_val)-offset);
                    snprintf(modified_ssid_val, sizeof(modified_ssid_val), "%s_dwb", temp_ssid_val);
                }
                if(strcmp(nvram_safe_get(bh_parameter), modified_ssid_val)) { // Not equal. Update it!.
                    return 1;
                }
                else
                    continue;
            }
            else if (!strcmp(pconnParam->param, "closed")) // Skip "closed". Because the dwb_wl_closed must is 1.
                continue;
            else {
                if(strcmp(nvram_safe_get(bh_parameter), nvram_safe_get(fh_parameter))) { // Not equal. Update it!.
                    return 1;
                }
                else
                    continue;
            }
        }
        else
            return 1; // No dwb_wl_{pconnParam->param}. Generate it!.
    }
    return 0;
}

/*
========================================================================
Routine Description:
   Check if need to unset dedicated Wifi Backhaul Parameter.

Return Value:
    If needed, return 1.
    If not, return 0.

========================================================================
*/
static int cm_Do_Unset_Dedicated_Wifi_Backhaul_Parameter()
{
    struct connect_param_mapping_s *pconnParam = NULL;
    char bh_prefix[] = "dwb_wl_";
    char bh_parameter[256] = {0};

    for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++) {
        snprintf(bh_parameter, sizeof(bh_parameter), "%s%s", bh_prefix, pconnParam->param);
        if (nvram_get(bh_parameter))
            return 1;
        else
            continue;
    }
    return 0;
}

/*
========================================================================
Routine Description:
   Unset dedicated Wifi Backhaul Parameter.

Note:
========================================================================
*/
static void cm_Unset_Dedicated_Wifi_Backhaul_Parameter()
{
    struct connect_param_mapping_s *pconnParam = NULL;
    char tmp[256] = {0};

    for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++) {
        snprintf(tmp, sizeof(tmp), "dwb_wl_%s", pconnParam->param);
        nvram_unset(tmp);
    }
}

/*
========================================================================
Routine Description:
   Generate dedicated Wifi Backhaul Parameter.

Note:
========================================================================
*/
static void cm_Generate_Dedicated_Wifi_Backhaul_Parameter()
{
    struct connect_param_mapping_s *pconnParam = NULL;
    char fh_prefix[] = "wlXXXXXXX_", bh_prefix[] = "dwb_wl_";
    char fh_parameter[256] = {0}, bh_parameter[256] = {0}, modified_ssid_val[64] = {0}, temp_ssid_val[64] = {0}, fh_ssid_val[64] = {0};
    int offset = 0;
#ifdef SMART_CONNECT
    if (nvram_get_int("smart_connect_x") != 0)
        snprintf(fh_prefix, sizeof(fh_prefix), "wl0_");
    else
#endif
    snprintf(fh_prefix, sizeof(fh_prefix), "wl1_");
    for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++) {
        snprintf(fh_parameter, sizeof(fh_parameter), "%s%s", fh_prefix, pconnParam->param);
        if (nvram_get(fh_parameter)) {
            snprintf(bh_parameter, sizeof(bh_parameter), "%s%s", bh_prefix, pconnParam->param);
            if (!strcmp(pconnParam->param, "ssid")) { // {SSID} + _dwb
                strncpy(fh_ssid_val, nvram_safe_get(fh_parameter), sizeof(fh_ssid_val));
                if (strlen(fh_ssid_val) <= 28) {
                    snprintf(modified_ssid_val, sizeof(modified_ssid_val), "%s_dwb", fh_ssid_val);
                }
                else {
                    offset = strlen(fh_ssid_val) - 28;
                    while (1) { // multi-bytes character check.
                        if ((*(fh_ssid_val + (strlen(fh_ssid_val) - offset)) & 0xC0) == 0xC0) { // multi-bytes character. 1100 0000. Byte 1
                            break;
                        } else if ((*(fh_ssid_val + (strlen(fh_ssid_val) - offset)) & 0x80) == 0x80) { // multi-bytes character. 1000 0000. Byte 2/3/4/5/6
                            offset++;
                        } else { // 0xxxx xxxx. 1 byte character.
                            break;
                        }
                    }
                    strncpy(temp_ssid_val, fh_ssid_val, strlen(fh_ssid_val)-offset);
                    snprintf(modified_ssid_val, sizeof(modified_ssid_val), "%s_dwb", temp_ssid_val);
                }
                nvram_set(bh_parameter, modified_ssid_val);
            }
            else if (!strcmp(pconnParam->param, "closed")) // The dwb_wl_closed must is 1.
                nvram_set(bh_parameter, "1");
            else
                nvram_set(bh_parameter, nvram_safe_get(fh_parameter));
        }
    }
}

/*
========================================================================
Routine Description:
    Check the ssid of dwb band same as other band or not.

Arguments:

Return Value:
    If same, return 1.
    If different, return 0.

========================================================================
*/
int cm_check_ssid_by_dwb_band()
{
    int unit = 0, ret = 0, dwb_band_unit = nvram_get_int("dwb_band");
    char wl_prefix[sizeof("wlXXXXX_")], dwb_band_prefix[sizeof("wlXXXXX_")];
    char dwb_band_ssid[64], wl_ssid[64], tmp[64];

    snprintf(dwb_band_prefix, sizeof(dwb_band_prefix), "wl%d_", dwb_band_unit);
    strlcpy(dwb_band_ssid, nvram_safe_get(strcat_r(dwb_band_prefix, "ssid", tmp)), sizeof(dwb_band_ssid));

    if (dwb_band_unit >= 0 && strlen(dwb_band_ssid)) {
        for (unit = 0; unit < num_of_wl_if(); unit++) {
            if (unit == dwb_band_unit)
                continue;

            snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
            strlcpy(wl_ssid, nvram_safe_get(strcat_r(wl_prefix, "ssid", tmp)), sizeof(wl_ssid));

            if (strcmp(wl_ssid, dwb_band_ssid) == 0) {
                DWB_DBG("%s is same as %s", wl_ssid, dwb_band_ssid);
                ret = 1;
                break;
            }
        }
    }

    return ret;
}

/*
========================================================================
Routine Description:
   Dedicated WiFi Backhaul.

Note:
========================================================================
*/

int cm_Dedicated_Wifi_Backhaul_Parameter()
{
    struct connect_param_mapping_s *pconnParam = NULL;
    char prefix[]="wlXXXXXXX_", bh_prefix[]="wlXXXXXXX_", bk_bh_prefix[]="wlXXXXXXX_";
    char ref_prefix[]="wlXXXXXXX_", dwb_band_prefix[]="wlXXXXXXX_";
    char wif[256]={0}, *next = NULL;
    char wl_para[128]={0};
    char newssid[64]={0}, ori_ssid[64] = {0}, temp_ssid_val[64] = {0};
    int offset = 0;
    int SUMband = 0, i = 0;
    int resend_config = 0;
    struct json_object *cfg_root = NULL;
    struct json_object *objtmp = NULL;
    char cfg_ver[9] = {0}, tmp[32] = {0};

    int max_guest_index = 0;

    foreach(wif, nvram_safe_get("wl_ifnames"), next) {
        SUMband++;
    }

    if (nvram_get("max_guest_index"))
    {
        nvram_set_int("max_guest_index", GUEST_WL_INDEX);
        max_guest_index = GUEST_WL_INDEX;
    }
    else {
        max_guest_index = nvram_get_int("max_guest_index");
    }

    if (SUMband == DUAL_BAND)
        nvram_set_int("dwb_band", 2); // No dwb band in Dual band CAP, but still setting fake value 2(5G High band).
    snprintf(prefix, sizeof(prefix), "wl%d_", SUMband - 1);
    snprintf(bh_prefix, sizeof(bh_prefix), "wl%d.%d_", SUMband - 1, max_guest_index);
    snprintf(bk_bh_prefix, sizeof(bk_bh_prefix), "wsb_wl%d.%d_", SUMband - 1, max_guest_index);
    strncpy(ref_prefix, "wl1_", sizeof(ref_prefix));

    if (nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG || nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI)
    {
        if (SUMband >= TRI_BAND) {
            if (cm_check_ssid_by_dwb_band())
            {
                snprintf(dwb_band_prefix, sizeof(dwb_band_prefix), "wl%d_", nvram_get_int("dwb_band"));
                strncpy(ori_ssid, nvram_safe_get(strcat_r(dwb_band_prefix, "ssid", tmp)), sizeof(ori_ssid));
                if (strlen(ori_ssid) <= 28) {
                    snprintf(newssid, sizeof(newssid), "%s_dwb", ori_ssid);
                }
                else {
                    offset = strlen(ori_ssid) - 28;
                    while (1) { // multi-bytes character check.
                        if ((*(ori_ssid + (strlen(ori_ssid) - offset)) & 0xC0) == 0xC0) { // multi-bytes character. 1100 0000. Byte 1
                            break;
                        } else if ((*(ori_ssid + (strlen(ori_ssid) - offset)) & 0x80) == 0x80) { // multi-bytes character. 1000 0000. Byte 2/3/4/5/6
                            offset++;
                        } else { // 0xxxx xxxx. 1 byte character.
                            break;
                        }
                    }
                    strncpy(temp_ssid_val, ori_ssid, strlen(ori_ssid)-offset);
                    snprintf(newssid, sizeof(newssid), "%s_dwb", temp_ssid_val);
                }
                nvram_set(strcat_r(dwb_band_prefix, "ssid", tmp), newssid);
                nvram_set(strcat_r(dwb_band_prefix, "closed", tmp), "1");
                resend_config = 1;
                restart_wifi = 1;
            }
#ifdef SMART_CONNECT
            if (cm_backupSmartConnectParameters(SUMband)) {
                resend_config = 1;
                restart_wifi = 1;
            }
#endif
        }
        else if (SUMband == DUAL_BAND) {
            if (cm_Do_Update_Dedicated_Wifi_Backhaul_Parameter()) {
                cm_Generate_Dedicated_Wifi_Backhaul_Parameter();
                resend_config = 1;
            }
        }
    }
    else {
        if (SUMband >= TRI_BAND) {
#ifdef SMART_CONNECT
            if (nvram_get_int("dwb_scb") == 1) {
                restart_wifi = 1;
                cm_revertSmartConnectParameters(SUMband);
            }
#endif
        }
        else if (SUMband == DUAL_BAND) {
            if (cm_Do_Unset_Dedicated_Wifi_Backhaul_Parameter()) {
                cm_Unset_Dedicated_Wifi_Backhaul_Parameter();
                resend_config = 1;
            }
        }
    }
    nvram_commit();

    if(resend_config == 1)
    {
        if ((cfg_root = json_object_from_file(CFG_JSON_FILE)) != NULL)
        {
            i = 0;
            foreach(wif, nvram_safe_get("wl_ifnames"), next)
            {
                for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
                {
                    memset(wl_para, 0x00, sizeof(wl_para));
                    snprintf(wl_para, sizeof(wl_para), "wl%d_%s", i, pconnParam->param);
                    json_object_object_get_ex(cfg_root, wl_para, &objtmp);
                    if(!objtmp) {
                        json_object_object_add(cfg_root, wl_para, json_object_new_string(nvram_safe_get(wl_para)));
                    }
                }
                i++;
            }
            json_object_to_file(CFG_JSON_FILE, cfg_root);
            json_object_put(cfg_root);

            /* change cfg_ver when setting changed */
            memset(cfg_ver, 0, sizeof(cfg_ver));
            srand(time(NULL));
            snprintf(cfg_ver, sizeof(cfg_ver), "%d%d", rand(), rand());
            nvram_set("cfg_ver", cfg_ver);
        }
        else if (cfg_root == NULL) { // cfg_root == NULL

            cfg_root = json_object_new_object();

            i = 0;
            foreach(wif, nvram_safe_get("wl_ifnames"), next)
            {
                for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
                {
                    memset(wl_para, 0x00, sizeof(wl_para));
                    snprintf(wl_para, sizeof(wl_para), "wl%d_%s", i, pconnParam->param);
                    json_object_object_get_ex(cfg_root, wl_para, &objtmp);
                    if(!objtmp) {
                        json_object_object_add(cfg_root, wl_para, json_object_new_string(nvram_safe_get(wl_para)));
                    }
                }
                i++;
            }
            json_object_to_file(CFG_JSON_FILE, cfg_root);
            json_object_put(cfg_root);

            /* change cfg_ver when setting changed */
            memset(cfg_ver, 0, sizeof(cfg_ver));
            srand(time(NULL));
            snprintf(cfg_ver, sizeof(cfg_ver), "%d%d", rand(), rand());
            nvram_set("cfg_ver", cfg_ver);
        }

        if (SUMband == DUAL_BAND)
            dwb_reSync = 1;

        resend_config = 0;
    }
    else {
        if (SUMband == DUAL_BAND)
            dwb_reSync = 0;
    }

    return 0;
}


/*
========================================================================
Routine Description:
    Add Dedicated_Wifi_Backhaul_Parameter for slave.

Arguments:
    mac             - unique mac
    reBandNum		- RE supported band number
    outRoot             - json object for output

Return Value:
    none

========================================================================
*/
void cm_transDedicated_Wifi_Backhaul_Parameter(char *mac, int reBandNum, json_object *outRoot)
{

    char wif[256]={0}, *next = NULL;
    char bh_prefix[]="wlXXXXXXX_";
    char wl_para[128]={0}, wsb_para[128]={0}, dwb_wl_para[128]={0};
    int SUMband = 0, i = 0;
    struct connect_param_mapping_s *pconnParam = NULL;
    char s_max_guest_index[2]={0};
    char s_SUMband[2]={0};
    int max_guest_index = 0;
    char outAuth[16];
    int wl1_fix_index = 1, wl2_fix_index = 2, dwb_band = nvram_get_int("dwb_band");
    int check_auth_type=0;
    char finalparamname[64];
    foreach(wif, nvram_safe_get("wl_ifnames"), next) {
        SUMband++;
    }

    if (nvram_get("max_guest_index") == NULL)
    {
        nvram_set_int("max_guest_index", GUEST_WL_INDEX);
        max_guest_index = GUEST_WL_INDEX;
    }
    else {
        max_guest_index = nvram_get_int("max_guest_index");
    }


    snprintf(bh_prefix, sizeof(bh_prefix), "wl%d.%d_", wl1_fix_index, max_guest_index);
    snprintf(s_max_guest_index, sizeof(s_max_guest_index), "%d", max_guest_index);
    snprintf(s_SUMband, sizeof(s_SUMband), "%d", SUMband);

    if (!outRoot) {
        DWB_DBG("outRoot is NULL");
        return;
    }

    json_object_object_add(outRoot, "dwb_mode", json_object_new_string(nvram_safe_get("dwb_mode")));
    json_object_object_add(outRoot, "cap_max_guest_index", json_object_new_string(s_max_guest_index));
    json_object_object_add(outRoot, "cap_band_count", json_object_new_string(s_SUMband));

    if (nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG || nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI) {


        for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++) {
		
		memset(finalparamname, 0, sizeof(finalparamname));
		
            if (SUMband == DUAL_BAND)
            {
                memset(wl_para, 0x00, sizeof(wl_para));
                snprintf(wl_para, sizeof(wl_para), "%s%s", bh_prefix, pconnParam->param);
                memset(dwb_wl_para, 0x00, sizeof(dwb_wl_para));
                snprintf(dwb_wl_para, sizeof(dwb_wl_para), "dwb_wl_%s", pconnParam->param);
                if (strcmp(pconnParam->param, "auth_mode_x") == 0) {
                    memset(outAuth, 0, sizeof(outAuth));
                    if (cm_checkWifiAuthCap(mac, supportedBandNum, reBandNum, 1, dwb_wl_para, outAuth, sizeof(outAuth))) {
                        json_object_object_add(outRoot, wl_para, json_object_new_string(outAuth));
                    }
                    else
                        json_object_object_add(outRoot, wl_para, json_object_new_string(nvram_safe_get(dwb_wl_para)));
                }
                else
                    json_object_object_add(outRoot, wl_para, json_object_new_string(nvram_safe_get(dwb_wl_para)));
            }

            if (SUMband >= TRI_BAND)
            {
                memset(wsb_para, 0x00, sizeof(wsb_para));
                snprintf(wsb_para, sizeof(wsb_para), "dwb_wl%d_%s", wl1_fix_index, pconnParam->param);
                memset(wl_para, 0x00, sizeof(wl_para));
                if (nvram_get_int("smart_connect_x") == 1) { // Smart connect. 2.4G&5G-1 or 2.4G&5G-1&5G-2
                    snprintf(wl_para, sizeof(wl_para), "wl%d_%s", WL_2G_BAND, pconnParam->param); // Get 2.4G parameters.
                }
                else    // Get 5G/5G low parameters
                    snprintf(wl_para, sizeof(wl_para), "wl%d_%s", get_5g_unit(), pconnParam->param);

                if (strcmp(pconnParam->param, "auth_mode_x") == 0) {
                    memset(outAuth, 0, sizeof(outAuth));
                    if (cm_checkWifiAuthCap(mac, supportedBandNum, reBandNum, 2, wl_para, outAuth, sizeof(outAuth))) {
                        json_object_object_add(outRoot, wsb_para, json_object_new_string(outAuth));
                    }
                    else
                    	json_object_object_add(outRoot, wsb_para, json_object_new_string(nvram_safe_get(wl_para)));
                        //json_object_object_add(outRoot, wsb_para, json_object_new_string(nvram_safe_get(cap_get_final_paramname(mac, wl_para,reBandNum,finalparamname, sizeof(finalparamname)))));
                }
                else
               	json_object_object_add(outRoot, wsb_para, json_object_new_string(nvram_safe_get(wl_para)));
                    //json_object_object_add(outRoot, wsb_para, json_object_new_string(nvram_safe_get(cap_get_final_paramname(mac, wl_para,reBandNum,finalparamname, sizeof(finalparamname)))));
            }

            i = 0;
            foreach(wif, nvram_safe_get("wl_ifnames"), next)
            {
                memset(wl_para, 0x00, sizeof(wl_para));
                snprintf(wl_para, sizeof(wl_para), "wl%d_%s", i, pconnParam->param);
                if (i == wl2_fix_index){
                	if(check_have_XG(60)==1 && check_match_6G(mac)==2 && dwb_band==wl2_fix_index){	
                		snprintf(dwb_wl_para, sizeof(dwb_wl_para), "wl%d_%s", check_own_unit(2), pconnParam->param);
                	}
                	else{
                    		snprintf(dwb_wl_para, sizeof(dwb_wl_para), "wl%d_%s", dwb_band, pconnParam->param);
                    	}
                    
                }
                else
                    snprintf(dwb_wl_para, sizeof(dwb_wl_para), "wl%d_%s", i, pconnParam->param);
                if (strcmp(pconnParam->param, "auth_mode_x") == 0) {
                    memset(outAuth, 0, sizeof(outAuth));
                    if(((check_match_6G(mac)==-1) || (check_have_XG(60)==1 && check_match_6G(mac)==2)) && i==2){
                    	check_auth_type=2;
                    }
                    
                    if (cm_checkWifiAuthCap(mac, supportedBandNum, reBandNum, check_auth_type, dwb_wl_para, outAuth, sizeof(outAuth))) {
                        json_object_object_add(outRoot, wl_para, json_object_new_string(outAuth));
                    }
                    else
                    {
                    	if (i == wl2_fix_index){
			 	json_object_object_add(outRoot, wl_para, json_object_new_string(nvram_safe_get(dwb_wl_para)));
			}
		 	else
			{
			 	 json_object_object_add(outRoot, wl_para, json_object_new_string(nvram_safe_get(cap_get_final_paramname(mac, dwb_wl_para,reBandNum,finalparamname, sizeof(finalparamname)))));
			 
			}
		    }
                }
                else
                {
                    if (i == wl2_fix_index){
                    		if(check_have_XG(60)==1 && check_match_6G(mac)==2 && dwb_band==wl2_fix_index){
                    			char dwb_wl_para_value[256];
                    			memset(dwb_wl_para_value, 0, sizeof(dwb_wl_para_value));
                    			if (nvram_get_int("dwb_mode")){
                    				if(strcmp(pconnParam->param, "ssid") == 0){
                    					if(reBandNum==2){
                    						snprintf(dwb_wl_para_value, sizeof(dwb_wl_para_value), "%s", nvram_safe_get(dwb_wl_para));
                    					}else
                    					{
                    						snprintf(dwb_wl_para_value, sizeof(dwb_wl_para_value), "%s_dwb", nvram_safe_get(dwb_wl_para));
                    					}
                    				}
                    				else if(strcmp(pconnParam->param, "closed") == 0){
                    					if(reBandNum==2)
                    					{
                    						snprintf(dwb_wl_para_value, sizeof(dwb_wl_para_value), "%s", nvram_safe_get(dwb_wl_para));
                    					}
                    					else{
                    						snprintf(dwb_wl_para_value, sizeof(dwb_wl_para_value), "%d", 1);
                    					}
                    				}
                    				else
                    					snprintf(dwb_wl_para_value, sizeof(dwb_wl_para_value), "%s", nvram_safe_get(dwb_wl_para));
                    			}
                    			else{
                    				snprintf(dwb_wl_para_value, sizeof(dwb_wl_para_value), "%s", nvram_safe_get(dwb_wl_para));
                    			}
			 		json_object_object_add(outRoot, wl_para, json_object_new_string(dwb_wl_para_value));
			 	}
			 	else{
			 			json_object_object_add(outRoot, wl_para, json_object_new_string(nvram_safe_get(dwb_wl_para)));
			 	}
			}
		 	else
			{
			 	 json_object_object_add(outRoot, wl_para, json_object_new_string(nvram_safe_get(cap_get_final_paramname(mac, dwb_wl_para,reBandNum,finalparamname, sizeof(finalparamname)))));
			 
			}
		}
                i++;
            }
        }
    }
} /* End of cm_transDedicated_Wifi_Backhaul_Parameter */


/*
========================================================================
Routine Description:
    cm_AutoDetect_Dedicated_Wifi_Backhaul
Arguments:
        checkpoint      - 1:  start cfg_server
                        - 2:  onboarding sucessfully for first RE.

Return Value:
    none

========================================================================*/
int cm_AutoDetect_Dedicated_Wifi_Backhaul(int checkpoint, int doAction)
{
    int SUMband = 0, do_adjust_parameters = 0;
    char wif[128]={0}, *next = NULL;
#ifdef RTCONFIG_BHCOST_OPT
    int amas_eap_bhmode = strtoul(nvram_safe_get("amas_eap_bhmode"), NULL, 16);
#endif

#if defined(RTCONFIG_WIFI_SON)
    if(nvram_match("wifison_ready", "1"))
    {
	DBG_INFO("wifison: skip DWB\n");
	nvram_set_int("dwb_mode", DWB_DISABLED_FROM_GUI);
	return 0;
    }
#endif

    foreach (wif, nvram_safe_get("wl_ifnames"), next) {
        SUMband++;
    }
#ifdef RTCONFIG_BHCOST_OPT
    if (amas_eap_bhmode > 0) {
        if (nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG || nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI) {
            nvram_set_int("dwb_mode", DWB_DISABLED_FROM_CFG);
            do_adjust_parameters = 1;
        }
    }
    else
#endif
    {
        if (checkpoint == 1) {
            if (SUMband == DUAL_BAND) {
                if (strlen(nvram_safe_get("cfg_tbrelist")) > 0 &&
                    nvram_get_int("dwb_mode") != DWB_DISABLED_FROM_GUI && nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_CFG) {
                    nvram_set_int("dwb_mode", DWB_ENABLED_FROM_CFG);
                    do_adjust_parameters = 1;
                } else if (strlen(nvram_safe_get("cfg_tbrelist")) <= 0 &&
                           nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI && nvram_get_int("dwb_mode") != DWB_DISABLED_FROM_CFG) {
                    nvram_set_int("dwb_mode", DWB_DISABLED_FROM_CFG);
                    do_adjust_parameters = 1;
                }
            } else if (SUMband >= TRI_BAND) {
                if (
#ifdef RTCONFIG_PRELINK
                    (strlen(nvram_safe_get("amas_bdlkey")) > 0 || nvram_get_int("cfg_recount") > 0) &&
#else
                    nvram_get_int("cfg_recount") > 0 &&
#endif
                    nvram_get_int("dwb_mode") != DWB_DISABLED_FROM_GUI && nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_CFG) {
                    nvram_set_int("dwb_mode", DWB_ENABLED_FROM_CFG);
                    do_adjust_parameters = 1;
                }
#ifdef RTCONFIG_PRELINK
                else if ((strlen(nvram_safe_get("amas_bdlkey")) == 0 && nvram_get_int("cfg_recount") == 0) &&
#else
                else if (nvram_get_int("cfg_recount") == 0 &&
#endif
                           nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI && nvram_get_int("dwb_mode") != DWB_DISABLED_FROM_CFG) {
                    nvram_set_int("dwb_mode", DWB_DISABLED_FROM_CFG);
                    do_adjust_parameters = 1;
                }
            }
        } else if (checkpoint == 2) {
            if (SUMband == DUAL_BAND) {
                if (strlen(nvram_safe_get("cfg_tbrelist")) == 17 && /* strlen("XX:XX:XX:XX:XX:XX") */
                    nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI && nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_CFG) {
                    nvram_set_int("dwb_mode", DWB_ENABLED_FROM_CFG);
                    do_adjust_parameters = 1;
                }
            } else if (SUMband >= TRI_BAND) {
                if (
#ifdef RTCONFIG_PRELINK
                    (strlen(nvram_safe_get("amas_bdlkey")) > 0 || nvram_get_int("cfg_recount") == 1) &&
#else
                    nvram_get_int("cfg_recount") == 1 &&
#endif
                    nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_GUI && nvram_get_int("dwb_mode") != DWB_ENABLED_FROM_CFG) {
                    nvram_set_int("dwb_mode", DWB_ENABLED_FROM_CFG);
                    do_adjust_parameters = 1;
                }
            }
        }
    }

    if (do_adjust_parameters)
        cm_Dedicated_Wifi_Backhaul_Parameter();
#ifdef RTCONFIG_FRONTHAUL_DWB
    if (Process_DWB_Fronthaul_AP() == 1)
        restart_wifi = 1;
#endif

    if (restart_wifi == 1) {
        if (doAction == 1) {
#ifdef RTCONFIG_LANTIQ
            // If the wave_flag isn't set zero on BlueCave, the backhaul vap may not be up.
            nvram_set("wave_flag", "0");
#endif
            notify_rc("restart_wireless");
            syslog(LOG_NOTICE,"\n %s: Need to restart wireless to adjust params\n", __func__);
        } else { // Write to cfg file

            struct json_object *cfg_root = NULL;
		    struct json_object *actionScriptObj = NULL;
            char actionScript[256] = {};

            if ((cfg_root = json_object_from_file(CFG_JSON_FILE)) != NULL)
            {
                json_object_object_get_ex(cfg_root, CFG_ACTION_SCRIPT, &actionScriptObj);

                if (actionScriptObj) {
                    snprintf(actionScript, sizeof(actionScript), "%s", json_object_get_string(actionScriptObj));
                    if(!strstr(actionScript, "restart_wireless")) {
                        if (strlen(actionScript) == 0)
                            strncpy(actionScript, "restart_wireless", sizeof(actionScript));
                        else
					        strcat(actionScript, ";restart_wireless");
			        }
                }
                else {
                    strncpy(actionScript, "restart_wireless", sizeof(actionScript));
                }
                json_object_object_add(cfg_root, CFG_ACTION_SCRIPT, json_object_new_string(actionScript));
                json_object_to_file(CFG_JSON_FILE, cfg_root);
                json_object_put(cfg_root);
            }
            else if (cfg_root == NULL) { // cfg_root == NULL
                cfg_root = json_object_new_object();
                strncpy(actionScript, "restart_wireless", sizeof(actionScript));
                json_object_object_add(cfg_root, CFG_ACTION_SCRIPT, json_object_new_string(actionScript));
                json_object_to_file(CFG_JSON_FILE, cfg_root);
                json_object_put(cfg_root);
            }
		}
        restart_wifi = 0;
    }
    return 0;
}

/**
 * @brief Do need to do update backhaul parameter
 *
 * @param cfgRoot sync data
 * @return int Do or not to do. (0: Not to do. 1: Do.)
 */
int Do_Setting_WiFi_Backhual_Parameter(struct json_object *cfgRoot)
{
    char wif[256]={0}, *next = NULL;
    int need = 0, SUMband = 0;
    struct json_object *val = NULL;

    /* Check band count */
    foreach(wif, nvram_safe_get("wl_ifnames"), next) {
        SUMband++;
    }
    if (SUMband < 2)
        goto DO_SETTING_WIFI_BACKHAUL_PARAMETER_EXIT;

    /* Check needed parameter in sync data */
    json_object_object_get_ex(cfgRoot, "dwb_mode", &val);
    if (val == NULL) // If no dwb_mode in json, skip processing DWB connection parameters.
        goto DO_SETTING_WIFI_BACKHAUL_PARAMETER_EXIT;

    json_object_object_get_ex(cfgRoot, "cap_band_count", &val);
    if (val == NULL) // If no cap_band_count in json, skip processing DWB connection parameters.
        goto DO_SETTING_WIFI_BACKHAUL_PARAMETER_EXIT;

    json_object_object_get_ex(cfgRoot, "cap_max_guest_index", &val);
    if (val == NULL) // If no cap_max_guest_index in json, skip processing DWB connection parameters.
        goto DO_SETTING_WIFI_BACKHAUL_PARAMETER_EXIT;

    need = 1;
DO_SETTING_WIFI_BACKHAUL_PARAMETER_EXIT:
    DWB_DBG("Need to do setting WiFi backhaul parameter? %d (0: No. 1: Yes.)\n", need);
    return need;
}

/*
========================================================================
Routine Description:
    Set_transDedicated_Wifi_Backhaul_Parameter

Arguments:
    cfgRoot             - json object for input

Return Value:
    none

========================================================================
*/
void Set_transDedicated_Wifi_Backhaul_Parameter(struct json_object *cfgRoot, int *dwb_change)
{
    char wif[256]={0}, *next = NULL;
    char wl_prefix[]="wlXXXXXXX_", wlxx_prefix[]="wlXXXXXXX_", wlc_prefix[]="wlXXXXXXX_";
    char bh_prefix[]="wlXXXXXXX_", cap_bh_prefix[]="wlXXXXXXX_";
    char wsbh_prefix[]="wlXXXXXXX_", wsfh_prefix[]="wlXXXXXXX_", dwb_wlc_prefix[]="wlXXXXXXX_", tmp[32] = {0};
    char wlc_para[128]={0}, wsb_para[128]={0}, wl_para[128]={0}, cap_wl_para[128]={0}, cap_wl1_para[128]={0};
    char wsbh_para[128]={0}, wsfh_para[128]={0}, dwb_wlc_para[128]={0};
    int SUMband = 0;
    struct json_object *val = NULL;
    int dwb_mode = 0, cap_max_guest_index = 0, cap_band_count = 0;
    int max_guest_index = 0;
    struct connect_param_mapping_s *pconnParam = NULL;
    int dwb_modify = 0, dwb_wlc_modify = 0;
    int no_equal_wsfh[2] = {0}, no_equal_wsbh[2] = {0};  // [0]: 5G Uplink, [1]: 6G Uplink
    char wlc5g_prefix[] = "wlXXXXXXX_", wlc6g_prefix[] = "wlXXXXXXX_", wlX_prefix[] = "wlXXXXXXX_";
    char wlc5g_para[64] = {}, wlc6g_para[64] = {};
    
    int i, have_6g = 0;
    int dwb_band = nvram_get_int("dwb_band"), wl1_fix_index = 1, wl2_fix_index = 2;
    	json_object *cfgbandVer = NULL;
	json_object_object_get_ex(cfgRoot, CFG_BAND_INDEX_VERSION, &cfgbandVer);
	int cfgband_Ver=0;
	if (cfgbandVer == NULL) {
		DBG_INFO("cfgbandVer(0)");
		cfgband_Ver=0;
	}
	else{
		DBG_INFO("cfgbandVer(%s)", json_object_get_string(cfgbandVer));
		cfgband_Ver = atoi(json_object_get_string(cfgbandVer));
	}

    if (nvram_get("max_guest_index") == NULL)
    {
        nvram_set_int("max_guest_index", GUEST_WL_INDEX);
        max_guest_index = GUEST_WL_INDEX;
    }
    else {
        max_guest_index = nvram_get_int("max_guest_index");
    }

    foreach(wif, nvram_safe_get("wl_ifnames"), next) {
        SUMband++;
    }

    if (SUMband == DUAL_BAND) {
        nvram_set_int("dwb_band", SUMband - 1);
        dwb_band = SUMband - 1;
    }
    snprintf(bh_prefix, sizeof(bh_prefix), "wl%d.%d_", dwb_band, max_guest_index);
    snprintf(wlc_prefix, sizeof(wlc_prefix), "wlc%d_", get_wlc_bandindex_by_unit(dwb_band));

    for (i = 0; i < SUMband; i++) {
        snprintf(wlX_prefix, sizeof(wlX_prefix), "wl%d_", i);
        int nband = nvram_get_int(strcat_r(wlX_prefix, "nband", tmp));
        if (nband == 1) {  // 5G
            snprintf(wlc5g_prefix, sizeof(wlc5g_prefix), "wlc%d_", i);
        } else if (nband == 4) {  // 6G
            snprintf(wlc6g_prefix, sizeof(wlc6g_prefix), "wlc%d_", i);
            have_6g = 1;
        }
    }

    snprintf(wlxx_prefix, sizeof(wlxx_prefix), "wl%d.1_", dwb_band);
    snprintf(dwb_wlc_prefix, sizeof(dwb_wlc_prefix), "dwb_wlc%d_", get_wlc_bandindex_by_unit(dwb_band));
    snprintf(wsbh_prefix, sizeof(wsbh_prefix), "wsbh_");
    snprintf(wsfh_prefix, sizeof(wsfh_prefix), "wsfh_");



    json_object_object_get_ex(cfgRoot, "dwb_mode", &val);
    if (val) {
        DWB_DBG("dwb_mode = %d\n", atoi(json_object_get_string(val)));
        dwb_mode = atoi(json_object_get_string(val));
    }

    json_object_object_get_ex(cfgRoot, "cap_band_count", &val);
    if (val) {
        DWB_DBG("cap_band_count = %d\n", atoi(json_object_get_string(val)));
        cap_band_count = atoi(json_object_get_string(val));
    }

    json_object_object_get_ex(cfgRoot, "cap_max_guest_index", &val);
    if (val) {
        DWB_DBG("cap_max_guest_index = %d\n", atoi(json_object_get_string(val)));
        cap_max_guest_index = atoi(json_object_get_string(val));
    }

    snprintf(cap_bh_prefix, sizeof(cap_bh_prefix), "wl%d.%d_", cap_band_count - 1, cap_max_guest_index);
    snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", (cap_band_count > TRI_BAND) ? wl2_fix_index: cap_band_count - 1);

    DBG_INFO("bh_prefix=%s, wlc_prefix=%s, wlxx_prefix=%s, dwb_wlc_prefix=%s, cap_bh_prefix=%s, wl_prefix=%s",
        bh_prefix, wlc_prefix, wlxx_prefix, dwb_wlc_prefix, cap_bh_prefix, wl_prefix);

    if (dwb_mode == DWB_ENABLED_FROM_CFG || dwb_mode == DWB_ENABLED_FROM_GUI)
    {
        for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
        {

            if (cap_band_count == DUAL_BAND)
            {
                snprintf(cap_wl_para, sizeof(cap_wl_para), "%s%s", cap_bh_prefix, pconnParam->param);

                if (SUMband == DUAL_BAND)
                {
#if 0
//for VAP
                    if (nvram_get_int("dwb_guest_index") != max_guest_index) {
                        memset(dwb_prefix, 0x00, sizeof(dwb_prefix));
                        snprintf(dwb_prefix, sizeof(dwb_prefix), "wl%d.%d_", SUMband - 1, nvram_get_int("dwb_guest_index"));

                        memset(wl_para, 0x00, sizeof(wl_para));
                        snprintf(wl_para, sizeof(wl_para), "%s%s", dwb_prefix, pconnParam->param);
                        cprintf("%s:%s:%d clear %s\n", __FILE__, __FUNCTION__, __LINE__, wl_para);
                        nvram_set(wl_para, "");
                    }
#endif
                    json_object_object_get_ex(cfgRoot, cap_wl_para, &val);
                    if (val) {
#if 0
//for VAP
                        memset(wl_para, 0x00, sizeof(wl_para));
                        snprintf(wl_para, sizeof(wl_para), "%s%s", bh_prefix, pconnParam->param);
                        nvram_set(wl_para, json_object_get_string(val));
#endif
                        if(strcmp("bss_enabled", pconnParam->param) != 0)
                        {

                            memset(wlc_para, 0x00, sizeof(wlc_para));
                            snprintf(wlc_para, sizeof(wlc_para), "%s%s", wlc_prefix, pconnParam->param);

                            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
                            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);

                            if (strcmp(json_object_get_string(val), nvram_safe_get(dwb_wlc_para)))
                            {
                                DBG_INFO("DWB: change the value of %s (%s->%s)", dwb_wlc_para, nvram_safe_get(dwb_wlc_para), json_object_get_string(val));
                                //dwb_modify = 1;
                                nvram_set(dwb_wlc_para, json_object_get_string(val));
                            }
                        }
                        DWB_DBG("wlc_para(%s) dwb_wlc_para(%s) cap_wl_para(%s) val(%s)\n", wlc_para, dwb_wlc_para, cap_wl_para, json_object_get_string(val));
                    }
                }

                if (SUMband >= TRI_BAND) {
                    json_object_object_get_ex(cfgRoot, cap_wl_para, &val);
                    if (val) {
                        if(strcmp("bss_enabled", pconnParam->param) != 0) {
                            memset(wlc_para, 0x00, sizeof(wlc_para));
                            snprintf(wlc_para, sizeof(wlc_para), "%s%s", wlc_prefix, pconnParam->param);

                            memset(wl_para, 0x00, sizeof(wl_para));
                            snprintf(wl_para, sizeof(wl_para), "%s%s", wlxx_prefix, pconnParam->param);

                            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
                            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);


                            if (strcmp(json_object_get_string(val), nvram_safe_get(dwb_wlc_para)))
                            {
                                DBG_INFO("DWB: change the value of %s (%s->%s)", dwb_wlc_para, nvram_safe_get(dwb_wlc_para), json_object_get_string(val));
                                //dwb_modify = 1;
                                nvram_set(dwb_wlc_para, json_object_get_string(val));
                            }
			if(cfgband_Ver<2){
		                    char param_val[512] = {};
		                    strlcpy(param_val, json_object_get_string(val), sizeof(param_val));
		                    if (!strcmp(pconnParam->param, "auth_mode_x")) {
		                        char wl_nband[] = "wlXXX_nband";
		                        snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", dwb_band);
		                        strlcpy(param_val, authentication_convert_band6(param_val, 1, nvram_get_int(wl_nband)), sizeof(param_val));
		                    } else if (!strcmp(pconnParam->param, "crypto")) {
		                        char wl_nband[] = "wlXXX_nband";
		                        char cap_auth_mode_x[32] = {};
		                        struct json_object *cap_auth_mode_x_val = NULL;

		                        snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", dwb_band);
		                        snprintf(cap_auth_mode_x, sizeof(cap_auth_mode_x), "%s%s", cap_bh_prefix, "auth_mode_x");
		                        json_object_object_get_ex(cfgRoot, cap_auth_mode_x, &cap_auth_mode_x_val);
		                        strlcpy(param_val, crypto_convert_band6(param_val, json_object_get_string(cap_auth_mode_x_val), 1, nvram_get_int(wl_nband)), sizeof(param_val));
		                    }
		                    if (strcmp(param_val, nvram_safe_get(wl_para))) {
		                    	if (cfgbandVer != NULL && (!strcmp(wl_para,"wl2.1_ssid")||!strcmp(wl_para,"wl2.1_closed"))) {
		                    		if((nvram_get_int("band_type")==3||nvram_get_int("band_type")==4 )&&(cap_band_count == DUAL_BAND)){
							DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        		nvram_set(wl_para, param_val);
						}
						else{
							DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        		dwb_modify = 1;
		                        		nvram_set(wl_para, param_val);
						}
		                    	}else if (cfgbandVer != NULL && !strcmp(nvram_safe_get("productid"),"GT-AXE16000") && (!strcmp(wl_para,"wl1.1_ssid")||!strcmp(wl_para,"wl1.1_closed"))) {
		                    		if((nvram_get_int("band_type")==3||nvram_get_int("band_type")==4 )&&(cap_band_count == DUAL_BAND)){
							DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        		nvram_set(wl_para, param_val);
						}
						else{
							DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        		dwb_modify = 1;
		                        		nvram_set(wl_para, param_val);
						}
		                    	}else{
		                        DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        dwb_modify = 1;
		                        nvram_set(wl_para, param_val);
		                        }
		                    }
                            }
                        }
                        DBG_INFO("dwb_wlc_para(%s) wl_para(%s) cap_wl_para(%s) val(%s)\n", dwb_wlc_para, wl_para, cap_wl_para, json_object_get_string(val));
                    }
                }
            }

            if (cap_band_count >= TRI_BAND)
            {
                memset(cap_wl_para, 0x00, sizeof(cap_wl_para));
                snprintf(cap_wl_para, sizeof(cap_wl_para), "%s%s", wl_prefix, pconnParam->param);
                memset(cap_wl1_para, 0x00, sizeof(cap_wl1_para));
                snprintf(cap_wl1_para, sizeof(cap_wl1_para), "dwb_wl%d_%s",
                    cap_band_count > TRI_BAND ? wl1_fix_index : cap_band_count - 2, pconnParam->param);

                if (SUMband == DUAL_BAND)
                {
#if 0
//for VAP
                    if (nvram_get_int("dwb_guest_index") != max_guest_index) {
                        memset(dwb_prefix, 0x00, sizeof(dwb_prefix));
                        snprintf(dwb_prefix, sizeof(dwb_prefix), "wl%d.%d_", SUMband - 1, nvram_get_int("dwb_guest_index"));

                        memset(wl_para, 0x00, sizeof(wl_para));
                        snprintf(wl_para, sizeof(wl_para), "%s%s", dwb_prefix, pconnParam->param);
    cprintf("%s:%s:%d clear %s\n", __FILE__, __FUNCTION__, __LINE__, wl_para);

                        nvram_set(wl_para, "");
                        dwb_modify = 1;
                    }
#endif

                    json_object_object_get_ex(cfgRoot, cap_wl_para, &val);
                    if (val)
                    {
#if 0
//for VAP
                        memset(wl_para, 0x00, sizeof(wl_para));
                        snprintf(wl_para, sizeof(wl_para), "%s%s", bh_prefix, pconnParam->param);

                        if ((nvram_get(wl_para) && strcmp(json_object_get_string(val), nvram_safe_get(wl_para)))
                        {
                            DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), json_object_get_string(val));
                            dwb_modify = 1;
                            nvram_set(wl_para, json_object_get_string(val));
                        }
#endif
                        if(strcmp("bss_enabled", pconnParam->param) != 0) {
                            memset(wlc_para, 0x00, sizeof(wlc_para));
                            snprintf(wlc_para, sizeof(wlc_para), "%s%s", wlc_prefix, cm_convert_to_wlcparam(pconnParam->param));

                            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
                            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);

                            if (strcmp(json_object_get_string(val), nvram_safe_get(dwb_wlc_para)))
                            {
                                DBG_INFO("DWB: change the value of %s (%s->%s)", dwb_wlc_para, nvram_safe_get(dwb_wlc_para), json_object_get_string(val));
                                //dwb_modify = 1;
                                nvram_set(dwb_wlc_para, json_object_get_string(val));
                            }
                        }
                        DWB_DBG("wlc_para(%s) dwb_wlc_para(%s) cap_wl_para(%s) val(%s)\n", wlc_para, dwb_wlc_para, cap_wl_para, json_object_get_string(val));
                    }
		     if(cap_band_count > TRI_BAND && nvram_get_int("smart_connect_x") == 0){
		            		
                    }else{
                    	json_object_object_get_ex(cfgRoot, cap_wl1_para, &val);
		            if (val)
		            {
		                memset(wsb_para, 0x00, sizeof(wsb_para));
		                snprintf(wsb_para, sizeof(wsb_para), "wl%d.1_%s", SUMband - 1, pconnParam->param);

		                if (strcmp(json_object_get_string(val), nvram_safe_get(wsb_para)))
		                {
		                    DBG_INFO("DWB: change the value of %s (%s->%s)", wsb_para, nvram_safe_get(wsb_para), json_object_get_string(val));
		                    dwb_modify = 1;
		                    nvram_set(wsb_para, json_object_get_string(val));
		                }
		                DWB_DBG("wsb_para(%s) cap_wl1_para(%s) val(%s)\n", wsb_para, cap_wl1_para, json_object_get_string(val));
		            }
                    }
                }

                if(SUMband >= TRI_BAND)
                {
                    json_object_object_get_ex(cfgRoot, cap_wl_para, &val);
                    if (val)
                    {
                        if(strcmp("bss_enabled", pconnParam->param) != 0) {
                            memset(wlc_para, 0x00, sizeof(wlc_para));
                            snprintf(wlc_para, sizeof(wlc_para), "%s%s", wlc_prefix, cm_convert_to_wlcparam(pconnParam->param));

                            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
                            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);

                            if (strcmp(json_object_get_string(val), nvram_safe_get(dwb_wlc_para)))
                            {
                                DBG_INFO("DWB: change the value of %s (%s->%s)", dwb_wlc_para, nvram_safe_get(dwb_wlc_para), json_object_get_string(val));
                                //dwb_modify = 1;
                                nvram_set(dwb_wlc_para, json_object_get_string(val));
                            }
			if(cfgband_Ver<2){
		                    memset(wl_para, 0x00, sizeof(wl_para));
		                    snprintf(wl_para, sizeof(wl_para), "%s%s", wlxx_prefix, pconnParam->param);
		                    char param_val[512] = {};
		                    strlcpy(param_val, json_object_get_string(val), sizeof(param_val));
		                    if (!strcmp(pconnParam->param, "auth_mode_x")) {
		                        char wl_nband[] = "wlXXX_nband";
		                        snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", dwb_band);
		                        strlcpy(param_val, authentication_convert_band6(param_val, 1, nvram_get_int(wl_nband)), sizeof(param_val));
		                    } else if (!strcmp(pconnParam->param, "crypto")) {
		                        char wl_nband[] = "wlXXX_nband";
		                        char cap_auth_mode_x[32] = {};
		                        struct json_object *cap_auth_mode_x_val = NULL;

		                        snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", dwb_band);
		                        snprintf(cap_auth_mode_x, sizeof(cap_auth_mode_x), "%s%s", wl_prefix, "auth_mode_x");
		                        json_object_object_get_ex(cfgRoot, cap_auth_mode_x, &cap_auth_mode_x_val);
		                        strlcpy(param_val, crypto_convert_band6(param_val, json_object_get_string(cap_auth_mode_x_val), 1, nvram_get_int(wl_nband)), sizeof(param_val));
		                    }

		                    if (strcmp(param_val, nvram_safe_get(wl_para))) {
				            if (cfgbandVer != NULL && ((!strcmp(wl_para,"wl2.1_ssid")||!strcmp(wl_para,"wl2.1_closed")) || ((!strcmp(wl_para,"wl1.1_ssid")||!strcmp(wl_para,"wl1.1_closed")) && dwb_band ==1))) {
				            		if((nvram_get_int("band_type")==4 || nvram_get_int("band_type")==2) && cap_band_count == TRI_BAND){
								//DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        			//dwb_modify = 1;
		                        			//nvram_set(wl_para, param_val);
		                        			DBG_INFO("DWB: SKIP Change wlX.1_xxx (X dwb band) when CAP one 5G band, RE two 5G Bands");
							}
							else{
								DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        			dwb_modify = 1;
		                        			nvram_set(wl_para, param_val);
							}
				            }else if (cfgbandVer != NULL && !strcmp(nvram_safe_get("productid"),"GT-AXE16000") && (!strcmp(wl_para,"wl1.1_ssid")||!strcmp(wl_para,"wl1.1_closed"))) {
				            		if(nvram_get_int("band_type")==4 && cap_band_count == TRI_BAND){
								DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        			//dwb_modify = 1;
		                        			nvram_set(wl_para, param_val);
							}
							else{
								DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        			dwb_modify = 1;
		                        			nvram_set(wl_para, param_val);
							}
				            }else{
				                	DBG_INFO("DWB: change the value of %s (%s->%s)", wl_para, nvram_safe_get(wl_para), param_val);
		                        		dwb_modify = 1;
		                        		nvram_set(wl_para, param_val);
				            }
                                }
                            }
                        }
                        DWB_DBG("dwb_wlc_para(%s) wl_para(%s) cap_wl_para(%s) val(%s)\n", dwb_wlc_para, wl_para, cap_wl_para, json_object_get_string(val));
                    }
                }
            }
        }
        nvram_set_int("dwb_mode", 1);
        nvram_set_int("dwb_guest_index", max_guest_index);
#if 0
//for VAP
        if(SUMband == DUAL_BAND) {
            memset(wl_para, 0x00, sizeof(wl_para));
            snprintf(wl_para, sizeof(wl_para), "wl%d_psr_guest", SUMband - 1);
            nvram_set(wl_para, "1");
        }
#endif

        DBG_INFO("======== Check wlc parameter parameter===============");
        for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
        {

            if(strcmp("bss_enabled", pconnParam->param) == 0)
                continue;

            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);

            memset(wlc_para, 0x00, sizeof(wlc_para));
            snprintf(wlc_para, sizeof(wlc_para), "%s%s", wlc_prefix, pconnParam->param);

            memset(wsbh_para, 0x00, sizeof(wsbh_para));
            snprintf(wsbh_para, sizeof(wsbh_para), "%s%s", wsbh_prefix, pconnParam->param);

            memset(wsfh_para, 0x00, sizeof(wsfh_para));
            snprintf(wsfh_para, sizeof(wsfh_para), "%s%s", wsfh_prefix, pconnParam->param);

            if (SUMband == TRI_BAND && have_6g) {
            memset(wlc5g_para, 0x00, sizeof(wlc5g_para));
            snprintf(wlc5g_para, sizeof(wlc5g_para), "%s%s", wlc5g_prefix, pconnParam->param);

            memset(wlc6g_para, 0x00, sizeof(wlc6g_para));
            snprintf(wlc6g_para, sizeof(wlc6g_para), "%s%s", wlc6g_prefix, pconnParam->param);

            if (!strcmp("auth_mode_x", pconnParam->param) || !strcmp("crypto", pconnParam->param)) {
                // 5G
                // wsbh
                char converted_val[32] = {};
                strlcpy(converted_val, nvram_safe_get(wsbh_para), sizeof(converted_val));
                if (!strcmp(nvram_safe_get(strcat_r(wsbh_prefix, "auth_mode_x", tmp)), "sae")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "psk2sae", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to psk2sae\n", nvram_safe_get(wsbh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to aes\n", nvram_safe_get(wsbh_para));
                    }
                } else if (!strcmp(nvram_safe_get(strcat_r(wsbh_prefix, "auth_mode_x", tmp)), "owe")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "open", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to open\n", nvram_safe_get(wsbh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to \"\"\n", nvram_safe_get(wsbh_para));
                    }
                }
                DBG_INFO("DWB: Check Backhaul config : %s(%s) == %s(%s) \n", wlc5g_para, nvram_safe_get(wlc5g_para), wsbh_para, converted_val);
                if (no_equal_wsbh[0] == 0 && nvram_get(wlc5g_para) && strcmp(nvram_safe_get(wlc5g_para), converted_val)) {
                    no_equal_wsbh[0] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal backhaul config.########\n", wlc5g_para, nvram_safe_get(wlc5g_para), wsbh_para, converted_val);
                }

                // wsfh
                strlcpy(converted_val, nvram_safe_get(wsfh_para), sizeof(converted_val));
                if (!strcmp(nvram_safe_get(strcat_r(wsfh_prefix, "auth_mode_x", tmp)), "sae")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "psk2sae", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to psk2sae\n", nvram_safe_get(wsfh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to aes\n", nvram_safe_get(wsfh_para));
                    }
                } else if (!strcmp(nvram_safe_get(strcat_r(wsfh_prefix, "auth_mode_x", tmp)), "owe")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "open", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to open\n", nvram_safe_get(wsfh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to \"\"\n", nvram_safe_get(wsfh_para));
                    }
                }
                DBG_INFO("DWB: Check fronthaul config : %s(%s) == %s(%s) \n", wlc5g_para, nvram_safe_get(wlc5g_para), wsfh_para, converted_val);
                if (no_equal_wsfh[0] == 0 && nvram_get(wlc5g_para) && strcmp(nvram_safe_get(wlc5g_para), converted_val)) {
                    no_equal_wsfh[0] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal fronthaul config.########\n", wlc5g_para, nvram_safe_get(wlc5g_para), wsfh_para, converted_val);
                }
                // 5G end.
                // 6G
                strlcpy(converted_val, nvram_safe_get(wsbh_para), sizeof(converted_val));
                if (!strcmp(nvram_safe_get(strcat_r(wsbh_prefix, "auth_mode_x", tmp)), "open")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "owe", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support open, convert %s to owe\n", nvram_safe_get(wsbh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support open, convert %s to aes\n", nvram_safe_get(wsbh_para));
                    }
                } else {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "sae", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support Non-SAE encryption, convert %s to sae\n", nvram_safe_get(wsbh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support Non-SAE encryption, convert %s to aes\n", nvram_safe_get(wsbh_para));
                    }
                }
                DBG_INFO("DWB: Check Backhaul config : %s(%s) == %s(%s) \n", wlc6g_para, nvram_safe_get(wlc6g_para), wsbh_para, converted_val);
                if (no_equal_wsbh[1] == 0 && nvram_get(wlc6g_para) && strcmp(nvram_safe_get(wlc6g_para), converted_val)) {
                    no_equal_wsbh[1] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal backhaul config.########\n", wlc6g_para, nvram_safe_get(wlc6g_para), wsbh_para, converted_val);
                }

                // wsfh
                strlcpy(converted_val, nvram_safe_get(wsfh_para), sizeof(converted_val));
                if (!strcmp(nvram_safe_get(strcat_r(wsfh_prefix, "auth_mode_x", tmp)), "open")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "owe", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support open, convert %s to owe\n", nvram_safe_get(wsfh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support open, convert %s to aes\n", nvram_safe_get(wsfh_para));
                    }
                } else {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "sae", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support Non-SAE encryption, convert %s to sae\n", nvram_safe_get(wsfh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 6G not support Non-SAE encryption, convert %s to aes\n", nvram_safe_get(wsfh_para));
                    }
                }
                DBG_INFO("DWB: Check fronthaul config : %s(%s) == %s(%s) \n", wlc6g_para, nvram_safe_get(wlc6g_para), wsfh_para, converted_val);
                if (no_equal_wsfh[1] == 0 && nvram_get(wlc6g_para) && strcmp(nvram_safe_get(wlc6g_para), converted_val)) {
                    no_equal_wsfh[1] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal fronthaul config.########\n", wlc6g_para, nvram_safe_get(wlc6g_para), wsfh_para, converted_val);
                }
                // 6G end.
            } else {
                DBG_INFO("DWB: Check Backhaul config : %s(%s) == %s(%s) \n", wlc5g_para, nvram_safe_get(wlc5g_para), wsbh_para, nvram_safe_get(wsbh_para));
                if (no_equal_wsbh[0] == 0 && nvram_get(wlc5g_para) && strcmp(nvram_safe_get(wlc5g_para), nvram_safe_get(wsbh_para))) {
                    no_equal_wsbh[0] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal backhaul config.########\n", wlc5g_para, nvram_safe_get(wlc5g_para), wsbh_para, nvram_safe_get(wsbh_para));
                }

                DBG_INFO("DWB: Check Fronthaul config : %s(%s) == %s(%s) \n", wlc5g_para, nvram_safe_get(wlc5g_para), wsfh_para, nvram_safe_get(wsfh_para));
                if (no_equal_wsfh[0] == 0 && nvram_get(wlc5g_para) && strcmp(nvram_safe_get(wlc5g_para), nvram_safe_get(wsfh_para))) {
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal fronthaul config.########\n", wlc5g_para, nvram_safe_get(wlc5g_para), wsfh_para, nvram_safe_get(wsfh_para));
                    no_equal_wsfh[0] = 1;
                }
                DBG_INFO("DWB: Check Backhaul config : %s(%s) == %s(%s) \n", wlc6g_para, nvram_safe_get(wlc6g_para), wsbh_para, nvram_safe_get(wsbh_para));
                if (no_equal_wsbh[1] == 0 && nvram_get(wlc6g_para) && strcmp(nvram_safe_get(wlc6g_para), nvram_safe_get(wsbh_para))) {
                    no_equal_wsbh[1] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal backhaul config.########\n", wlc6g_para, nvram_safe_get(wlc6g_para), wsbh_para, nvram_safe_get(wsbh_para));
                }

                DBG_INFO("DWB: Check Fronthaul config : %s(%s) == %s(%s) \n", wlc6g_para, nvram_safe_get(wlc6g_para), wsfh_para, nvram_safe_get(wsfh_para));
                if (no_equal_wsfh[1] == 0 && nvram_get(wlc6g_para) && strcmp(nvram_safe_get(wlc6g_para), nvram_safe_get(wsfh_para))) {
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal fronthaul config.########\n", wlc6g_para, nvram_safe_get(wlc6g_para), wsfh_para, nvram_safe_get(wsfh_para));
                    no_equal_wsfh[1] = 1;
                }
            }
            }
            else {
            if (!strcmp("auth_mode_x", pconnParam->param) || !strcmp("crypto", pconnParam->param)) {
                char converted_val[32] = {};
                // wsbh
                strlcpy(converted_val, nvram_safe_get(wsbh_para), sizeof(converted_val));
                if (!strcmp(nvram_safe_get(strcat_r(wsbh_prefix, "auth_mode_x", tmp)), "sae")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "psk2sae", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to psk2sae\n", nvram_safe_get(wsbh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to aes\n", nvram_safe_get(wsbh_para));
                    }
                } else if (!strcmp(nvram_safe_get(strcat_r(wsbh_prefix, "auth_mode_x", tmp)), "owe")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "open", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to open\n", nvram_safe_get(wsbh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to \"\"\n", nvram_safe_get(wsbh_para));
                    }
                }
                DBG_INFO("DWB: Check Backhaul config : %s(%s) == %s(%s) \n", wlc_para, nvram_safe_get(wlc_para), wsbh_para, converted_val);
                if (no_equal_wsbh[0] == 0 && nvram_get(wlc_para) && strcmp(nvram_safe_get(wlc_para), converted_val)) {
                    no_equal_wsbh[0] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal backhaul config.########\n", wlc_para, nvram_safe_get(wlc_para), wsbh_para, converted_val);
                }

                // wsfh
                strlcpy(converted_val, nvram_safe_get(wsfh_para), sizeof(converted_val));
                if (!strcmp(nvram_safe_get(strcat_r(wsfh_prefix, "auth_mode_x", tmp)), "sae")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "psk2sae", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to psk2sae\n", nvram_safe_get(wsfh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "aes", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support sae, convert %s to aes\n", nvram_safe_get(wsfh_para));
                    }
                } else if (!strcmp(nvram_safe_get(strcat_r(wsfh_prefix, "auth_mode_x", tmp)), "owe")) {
                    if (!strcmp("auth_mode_x", pconnParam->param)) {  // auth_mode_x
                        strlcpy(converted_val, "open", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to open\n", nvram_safe_get(wsfh_para));
                    } else {  // crypto
                        strlcpy(converted_val, "", sizeof(converted_val));
                        DBG_INFO("DWB: 5G not support owe, convert %s to open\n", nvram_safe_get(wsfh_para));
                    }
                }
                DBG_INFO("DWB: Check Fronthaul config : %s(%s) == %s(%s) \n", wlc_para, nvram_safe_get(wlc_para), wsfh_para, converted_val);
                if (no_equal_wsfh[0] == 0 && nvram_get(wlc_para) && strcmp(nvram_safe_get(wlc_para), converted_val)) {
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal fronthaul config.########\n", wlc_para, nvram_safe_get(wlc_para), wsfh_para, converted_val);
                    no_equal_wsfh[0] = 1;
                }
            } else {
                DBG_INFO("DWB: Check Backhaul config : %s(%s) == %s(%s) \n", wlc_para, nvram_safe_get(wlc_para), wsbh_para, nvram_safe_get(wsbh_para));
                if (no_equal_wsbh[0] == 0 && nvram_get(wlc_para) && strcmp(nvram_safe_get(wlc_para), nvram_safe_get(wsbh_para))) {
                    no_equal_wsbh[0] = 1;
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal backhaul config.########\n", wlc_para, nvram_safe_get(wlc_para), wsbh_para, nvram_safe_get(wsbh_para));
                }

                DBG_INFO("DWB: Check Fronthaul config : %s(%s) == %s(%s) \n", wlc_para, nvram_safe_get(wlc_para), wsfh_para, nvram_safe_get(wsfh_para));
                if (no_equal_wsfh[0] == 0 && nvram_get(wlc_para) && strcmp(nvram_safe_get(wlc_para), nvram_safe_get(wsfh_para))) {
                    DBG_INFO("DWB: #######: %s(%s) == %s(%s) is not equal fronthaul config.########\n", wlc_para, nvram_safe_get(wlc_para), wsfh_para, nvram_safe_get(wsfh_para));
                    no_equal_wsfh[0] = 1;
                }
            }
            }
        }

        DBG_INFO("======== Set wsfh and wsbh parameter===============");
        for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
        {

            if(strcmp("bss_enabled", pconnParam->param) == 0)
                continue;
            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);

            memset(wlc_para, 0x00, sizeof(wlc_para));
            snprintf(wlc_para, sizeof(wlc_para), "%s%s", wlc_prefix, pconnParam->param);

            memset(wl_para, 0x00, sizeof(wl_para));
            snprintf(wl_para, sizeof(wl_para), "wl%d.1_%s", get_5g_unit(), pconnParam->param);

            memset(wsbh_para, 0x00, sizeof(wsbh_para));
            snprintf(wsbh_para, sizeof(wsbh_para), "%s%s", wsbh_prefix, pconnParam->param);

            memset(wsfh_para, 0x00, sizeof(wsfh_para));
            snprintf(wsfh_para, sizeof(wsfh_para), "%s%s", wsfh_prefix, pconnParam->param);

            DBG_INFO("DWB: Check DWB Backhaul config : %s(%s) == %s(%s)", dwb_wlc_para, nvram_safe_get(dwb_wlc_para), wsbh_para, nvram_safe_get(wsbh_para));
            if (strcmp(nvram_safe_get(wsbh_para), nvram_safe_get(dwb_wlc_para)))
            {
                dwb_wlc_modify = 1;
                nvram_set(wsbh_para, nvram_safe_get(dwb_wlc_para));
                DBG_INFO("DWB: apply change the value of %s(%s) == %s(%s)", wsbh_para, nvram_safe_get(wsbh_para), dwb_wlc_para, nvram_safe_get(dwb_wlc_para));
            }

            DBG_INFO("DWB: Check DWB Fronthaul config : %s(%s) == %s(%s)", wl_para, nvram_safe_get(wl_para), wsfh_para, nvram_safe_get(wsfh_para));
            if (strcmp(nvram_safe_get(wsfh_para), nvram_safe_get(wl_para)))
            {
                dwb_wlc_modify = 1;
                nvram_set(wsfh_para, nvram_safe_get(wl_para));
                DBG_INFO("DWB: apply change the value of %s(%s) == %s(%s)", wsfh_para, nvram_safe_get(wsfh_para), wl_para, nvram_safe_get(wl_para));
            }
		
	    if(cfgband_Ver<2)
		{
		    DBG_INFO("DWB: Check WLC config : %s(%s) == %s(%s)", wlc_para, nvram_safe_get(wlc_para), dwb_wlc_para, nvram_safe_get(dwb_wlc_para));
		    if (dwb_wlc_modify)
		        DBG_INFO("DWB Profile changed. Re apply wlc parameters.");
		    if ((no_equal_wsbh[0] == 1 && no_equal_wsfh[0] == 1) || (no_equal_wsbh[1] == 1 && no_equal_wsfh[1] == 1) || dwb_wlc_modify == 1) {
		        dwb_wlc_modify = 1;
		        nvram_set(wlc_para, nvram_safe_get(dwb_wlc_para));
		        DBG_INFO("DWB: apply change the value of %s(%s) == %s(%s)", wlc_para, nvram_safe_get(wlc_para), dwb_wlc_para, nvram_safe_get(dwb_wlc_para));
		}
            }
        }
        chk_authentication_config(dwb_band, wlc_prefix);
    }
    else
    {
        for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
        {

            if (cap_band_count == DUAL_BAND)
            {
                memset(cap_wl_para, 0x00, sizeof(cap_wl_para));
                snprintf(cap_wl_para, sizeof(cap_wl_para), "%s%s", cap_bh_prefix, pconnParam->param);

                if (SUMband == DUAL_BAND)
                {
#if 0
//for VAP
                    memset(wl_para, 0x00, sizeof(wl_para));
                    snprintf(wl_para, sizeof(wl_para), "%s%s", bh_prefix, pconnParam->param);
                    nvram_set(wl_para, "");
                    dwb_modify = 1;
#endif
                    DBG_INFO("wlc_para(%s) wl_para(%s) cap_wl_para(%s)\n", wlc_para, wl_para, cap_wl_para);
                }

                if (SUMband == TRI_BAND) {
                    DBG_INFO("wlc_para(%s) wl_para(%s) cap_wl_para(%s)\n", wlc_para, wl_para, cap_wl_para);
                }
            }

            if (cap_band_count == TRI_BAND)
            {
                snprintf(cap_wl_para, sizeof(cap_wl_para), "%s%s", wl_prefix, pconnParam->param);

                if (SUMband == DUAL_BAND)
                {
#if 0
//for VAP
                    memset(wl_para, 0x00, sizeof(wl_para));
                    snprintf(wl_para, sizeof(wl_para), "%s%s", bh_prefix, pconnParam->param);
                    nvram_set(wl_para, "");
                    dwb_modify = 1;
#endif
                    DBG_INFO("wlc_para(%s) wl_para(%s) cap_wl_para(%s)\n", wlc_para, wl_para, cap_wl_para);
                }
            }
        }
        nvram_set_int("dwb_mode", 0);

        DBG_INFO("======== Unset wsfh and wsbh parameter===============\n");
        for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
        {

            memset(wsbh_para, 0x00, sizeof(wsbh_para));
            snprintf(wsbh_para, sizeof(wsbh_para), "%s%s", wsbh_prefix, pconnParam->param);

            memset(wsfh_para, 0x00, sizeof(wsfh_para));
            snprintf(wsfh_para, sizeof(wsfh_para), "%s%s", wsfh_prefix, pconnParam->param);

            memset(dwb_wlc_para, 0x00, sizeof(dwb_wlc_para));
            snprintf(dwb_wlc_para, sizeof(dwb_wlc_para), "%s%s", dwb_wlc_prefix, pconnParam->param);

            if (nvram_get(wsbh_para))
            {
                DBG_INFO("DWB: Clear backup value of %s(%s)", wsbh_para, nvram_safe_get(wsbh_para));
                nvram_unset(wsbh_para);
            }

            if (nvram_get(wsfh_para))
            {
                DBG_INFO("DWB: Clear backup value of %s(%s)", wsfh_para, nvram_safe_get(wsfh_para));
                nvram_unset(wsfh_para);
            }

            if (nvram_get(dwb_wlc_para))
            {
                DBG_INFO("DWB: Clear backup value of %s(%s)", dwb_wlc_para, nvram_safe_get(dwb_wlc_para));
                nvram_unset(dwb_wlc_para);
            }
        }
    }

    if (!IsNULL_PTR(dwb_change)) *(dwb_change) = ((dwb_modify << 1) | dwb_wlc_modify);

} /* End of cm_transDedicated_Wifi_Backhaul_Parameter */


/*
========================================================================
Routine Description:
    Dedicated WiFi backhaul is enabled or not.

Arguments:
    None

Return Value:
    Dedicated WiFi backhaul is enabled (1) or not (0)

========================================================================
*/
int cm_dwbIsEnabled()
{
	return ((nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG ||
					nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI) ? 1: 0);
} /* End of cm_dwbIsEnabled */

/*
========================================================================
Routine Description:
    check parameter is dwb parameter or not.

Arguments:
    None

Return Value:
    is dwb parameter (1)
    is not dwb parameter (0)

========================================================================
*/
int Is_dwb_para(struct json_object *cfgRoot, char *prefix,  char *parameter)
{
    char wl_prefix[]="wlXXXXXXX_";
    char wl1_prefix[]="wlXXXXXXX_";
    char wl2_prefix[]="wlXXXXXXX_";
    char wlX_prefix[] = "wlXXXXXXX_";
    char wl5g_prefix[] = "wlXXXXXXX_";
    char wl6g_prefix[] = "wlXXXXXXX_";
    int i, have_6g = 0;
    char tmp[32] = {};
    char wl_para[128]={0};
    char wif[256]={0}, *next = NULL;
    DWB_DBG("prefix = %s, parameter = %s\n", prefix, parameter);
    struct connect_param_mapping_s *pconnParam = NULL;
    struct json_object *val = NULL;
    int dwb_mode = 0;
    int cap_band_count = 0;
    int check_par = 0;
    int SUMband = 0;

	json_object *cfgbandVer = NULL;
	json_object_object_get_ex(cfgRoot, CFG_BAND_INDEX_VERSION, &cfgbandVer);
	int cfgband_Ver=0;
	if (cfgbandVer == NULL) {
		DBG_INFO("cfgbandVer(0)");
		cfgband_Ver=0;
	}
	else{
		DBG_INFO("cfgbandVer(%s)", json_object_get_string(cfgbandVer));
		cfgband_Ver = atoi(json_object_get_string(cfgbandVer));
	}
	
	if(cfgband_Ver>1){
		return 0;
	}
	
    json_object_object_get_ex(cfgRoot, "dwb_mode", &val);
    if (val) {
        DWB_DBG("dwb_mode = %d\n", atoi(json_object_get_string(val)));
        dwb_mode = atoi(json_object_get_string(val));
    }

    if (dwb_mode == DWB_DISABLED_FROM_CFG || dwb_mode == DWB_DISABLED_FROM_GUI)
        return 0;

    foreach(wif, nvram_safe_get("wl_ifnames"), next) {
        SUMband++;
    }

    if (SUMband < 2)
        return 0;

    if (SUMband == DUAL_BAND)
        nvram_set_int("dwb_band", SUMband - 1);

    json_object_object_get_ex(cfgRoot, "cap_band_count", &val);
    if (val)
    {
        DWB_DBG("cap_band_count = %d\n", atoi(json_object_get_string(val)));
        cap_band_count = atoi(json_object_get_string(val));
    }


    snprintf(wl_prefix, sizeof(wl_prefix), "wlc%d_", get_wlc_bandindex_by_unit(nvram_get_int("dwb_band")));

    for (i = 0; i < SUMband; i++) {
        snprintf(wlX_prefix, sizeof(wlX_prefix), "wl%d_", i);
        int nband = nvram_get_int(strcat_r(wlX_prefix, "nband", tmp));
        if (nband == 1) {  // 5G
            snprintf(wl5g_prefix, sizeof(wl5g_prefix), "wlc%d_", i);
        } else if (nband == 4) {  // 6G
            snprintf(wl6g_prefix, sizeof(wl6g_prefix), "wlc%d_", i);
            have_6g = 1;
        }
    }

    if (cap_band_count >= TRI_BAND && supportedBandNum == DUAL_BAND)
    {
        memset(wl1_prefix, 0x00, sizeof(wl1_prefix));
        snprintf(wl1_prefix, sizeof(wl1_prefix), "wl%d.1_", supportedBandNum - 1);
        DWB_DBG("prefix(%s), wl1_prefix(%s)\n", prefix, wl1_prefix);
        if(strcmp(wl1_prefix, prefix) == 0)
        {
            DWB_DBG("wl1_prefix(%s) == prefix(%s), DWB parameter check...\n", wl1_prefix, prefix);
            check_par = 1;
        }
    }
    else if (cap_band_count == DUAL_BAND && supportedBandNum >= TRI_BAND)
    {
        memset(wl2_prefix, 0x00, sizeof(wl2_prefix));
        snprintf(wl2_prefix, sizeof(wl2_prefix), "wl%d.1_", nvram_get_int("dwb_band"));
        DWB_DBG("prefix(%s), wl2_prefix(%s)\n", prefix, wl2_prefix);
        if(strcmp(wl2_prefix, prefix) == 0)
        {
            DWB_DBG("wl2_prefix(%s) == prefix(%s), DWB parameter check...\n", wl2_prefix, prefix);
            check_par = 1;
        }
    }
    if(strcmp(wl_prefix, prefix) == 0)
    {
        DWB_DBG("wl_prefix(%s) == prefix(%s), DWB parameter check...\n", wl_prefix, prefix);
        check_par = 1;
    }
    else if ((SUMband == TRI_BAND && have_6g) &&
        (!strcmp(wl5g_prefix, prefix) || !strcmp(wl6g_prefix, prefix))) {
        DWB_DBG("wl5g_prefix(%s) == prefix(%s) or wl6g_prefix(%s) == prefix(%s), DWB parameter check...\n", wl5g_prefix, prefix, wl6g_prefix, prefix);
        check_par = 1;
    }

    if(check_par == 0)
        return 0;

    for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
    {
        memset(wl_para, 0x00, sizeof(wl_para));
        snprintf(wl_para, sizeof(wl_para), "%s%s", prefix, pconnParam->param);
        if(!strcmp(parameter, wl_para)) {
            DBG_INFO("Don't check %s at wifi config sync.\n", parameter);
            return 1;
        }
    }
    return 0;
} /* End of Is_dwb_para */

#ifdef RTCONFIG_FRONTHAUL_DWB
static int get_fh_ap_subunit()
{
    if (nvram_get_int("re_mode") == 1)
        return nvram_get_int("fh_re_mssid_subunit");
    else
        return nvram_get_int("fh_cap_mssid_subunit");
}

/**
 * @brief Copy 5G-1 wireless config to fronthaul AP config
 *
 * @param band Which band need to generate fronthaul config.
 * @return int Generate result. -1: Error. 0: Not be changed. 1: Be changed.
 */
int Generate_Fronthaul_AP_Setting(int band)
{
    int SUMband = num_of_wl_if();
    int ref_band = 0, changed = 0;
    char fh_prefix[] = "fh_wlXXX_", refwl_prefix[] = "wlXXXXX_", tmp[64] = {}, tmp2[64] = {};
	const struct basic_wireless_setting_s *pParam = NULL;

    if (!(SUMband >= TRI_BAND))
        return -1;

    memset(refwl_prefix, 0x0, sizeof(refwl_prefix));
    memset(fh_prefix, 0x0, sizeof(fh_prefix));
    snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", band);

    switch (band) {
        case WL_2G_BAND:
            ref_band = WL_2G_BAND;
            break;
        case WL_5G_BAND:
            ref_band = WL_5G_BAND;
            break;
        case WL_5G_2_BAND:
            if (nvram_get_int("smart_connect_x") == 1) // 2.4G/5G-1/5G-2 smart connect
                ref_band = WL_2G_BAND;
            else
                ref_band = WL_5G_BAND;
            break;
        default:
            return -1;
    }

    if (nvram_get_int("re_mode") == 1) // RE
        snprintf(refwl_prefix, sizeof(refwl_prefix), "wl%d.1_", ref_band);
    else // CAP
        snprintf(refwl_prefix, sizeof(refwl_prefix), "wl%d_", ref_band);

    for (pParam = &basic_wireless_settings[0]; pParam->param; pParam++) {

        // Special param processing
        // lanaccess
        if (!strcmp(pParam->param, "lanaccess")) {
            if (strcmp(nvram_safe_get(strcat_r(fh_prefix, pParam->param, tmp)), "on")) {
                nvram_set(strcat_r(fh_prefix, pParam->param, tmp), "on");
                DWB_DBG("Setting %s=%s\n", strcat_r(fh_prefix, pParam->param, tmp), "on");
                changed = 1;
            }
            continue;
        }
#ifdef RTCONFIG_WIFI6E
        // auth_mode_x
        if (!strcmp(pParam->param, "auth_mode_x") || !strcmp(pParam->param, "crypto")) {
            char src_nband[] = "wlXXXX_nband", dest_nband[] = "wlXXXX_nband";
            char converted_buf[16] = {};
            strncpy(converted_buf, nvram_safe_get(strcat_r(refwl_prefix, pParam->param, tmp2)), sizeof(converted_buf) - 1);  // Original value
            // Source band
            snprintf(src_nband, sizeof(src_nband), "wl%d_nband", ref_band);
            // Destnation band
            snprintf(dest_nband, sizeof(dest_nband), "wl%d_nband", band);
            if ((nvram_get_int(src_nband) == 1 || nvram_get_int(src_nband) == 2) && nvram_get_int(dest_nband) == 4) {  // 2.4G/5G -> 6G
                if (!strcmp("open", nvram_safe_get(strcat_r(refwl_prefix, "auth_mode_x", tmp2)))) {                    // open
                    if (!strcmp(pParam->param, "auth_mode_x")) {                                                       // auth_mode_x
                        strncpy(converted_buf, "owe", sizeof(converted_buf) - 1);                                      // open -> owe
                    } else {                                                                                           // crypto
                        strncpy(converted_buf, "aes", sizeof(converted_buf) - 1);                                      // -> "aes"
                    }
                } else {                                                           // non-open
                    if (!strcmp(pParam->param, "auth_mode_x")) {                   // auth_mode_x
                        strncpy(converted_buf, "sae", sizeof(converted_buf) - 1);  // -> sae
                    } else {                                                       // crypto
                        strncpy(converted_buf, "aes", sizeof(converted_buf) - 1);  // -> "aes"
                    }
                }
            } else if (nvram_get_int(src_nband) == 4 && (nvram_get_int(dest_nband) == 1 || nvram_get_int(dest_nband) == 2)) {  // 6G -> 2.4G/5G
                if (!strcmp("owe", nvram_safe_get(strcat_r(refwl_prefix, "auth_mode_x", tmp2)))) {                             // owe
                    if (!strcmp(pParam->param, "auth_mode_x")) {                                                               // auth_mode_x
                        strncpy(converted_buf, "open", sizeof(converted_buf) - 1);                                             // owe -> open
                    } else {                                                                                                   // crypto
                        strncpy(converted_buf, "", sizeof(converted_buf) - 1);                                                 // -> ""
                    }
                } else {                                                               // sae
                    if (!strcmp(pParam->param, "auth_mode_x")) {                       // auth_mode_x
                        strncpy(converted_buf, "psk2sae", sizeof(converted_buf) - 1);  // -> psk2sae
                    } else {                                                           // crypto
                        strncpy(converted_buf, "aes", sizeof(converted_buf) - 1);      // -> "aes"
                    }
                }
            }
            if (strcmp(nvram_safe_get(strcat_r(fh_prefix, pParam->param, tmp)), converted_buf)) {  // different
                nvram_set(strcat_r(fh_prefix, pParam->param, tmp), converted_buf);
                DWB_DBG("Setting %s=%s\n", strcat_r(fh_prefix, pParam->param, tmp), converted_buf);
                changed = 1;
            }
        } else {
#endif
        // Common param processing
        if (strcmp(nvram_safe_get(strcat_r(fh_prefix, pParam->param, tmp)), nvram_safe_get(strcat_r(refwl_prefix, pParam->param, tmp2)))) { // different
            nvram_set(strcat_r(fh_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(refwl_prefix, pParam->param, tmp2)));
            DWB_DBG("Setting %s=%s\n", strcat_r(fh_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(refwl_prefix, pParam->param, tmp2)));
            changed = 1;
        }
#ifdef RTCONFIG_WIFI6E
        }
#endif
    }
    // record subunit value
    nvram_set_int(strcat_r(fh_prefix, "subunit", tmp), get_fh_ap_subunit());

    return changed;
}

/**
 * @brief Backup up fronthaul interface index original config.
 *
 * @param band Which band need to backup original wireless config.
 * @return int Backup result. 0: Be done.
 */
int Backup_Fronthaul_AP_Index_Config(int band)
{
    int mssid_subunit = 0;
    char bkwl_prefix[] = "bk_wlXXX_", wl_prefix[] = "wlXXX.XXXX_", fh_prefix[] = "fh_wlXXX_", tmp[64] = {}, tmp2[64] = {};
	const struct basic_wireless_setting_s *pParam = NULL;
    int total_band = num_of_wl_if();
	int max_mssid = num_of_mssid_support(total_band - 1);

    memset(fh_prefix, 0x0, sizeof(fh_prefix));
    snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", band);
    memset(bkwl_prefix, 0x0, sizeof(bkwl_prefix));
    snprintf(bkwl_prefix, sizeof(bkwl_prefix), "bk_wl%d_", band);

    mssid_subunit = get_fh_ap_subunit();

    memset(wl_prefix, 0x0, sizeof(wl_prefix));
    snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.%d_", band, mssid_subunit);

    for (pParam = &basic_wireless_settings[0]; pParam->param; pParam++) {
            nvram_set(strcat_r(bkwl_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(wl_prefix, pParam->param, tmp2)));
            DWB_DBG("Backup %s=%s\n", strcat_r(bkwl_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(wl_prefix, pParam->param, tmp2)));
    }
    nvram_set_int(strcat_r(bkwl_prefix, "backup", tmp), 1);
    return 0;
}

/**
 * @brief Recover for fronthaul interface index original config.
 *
 * @param band Which band need to recover original wireless config.
 * @return int Recover result. 0: Not recover. 1: Recoverd and be changed.
 */
int Recover_Fronthaul_AP_Index_Config(int band)
{
    int mssid_subunit = 0, changed = 0;
    char bkwl_prefix[] = "bk_wlXXX_", wl_prefix[] = "wlXXX.XXXX_", fh_prefix[] = "fh_wlXXX_", tmp[64] = {}, tmp2[64] = {};
	const struct basic_wireless_setting_s *pParam = NULL;
    int total_band = num_of_wl_if();
	int max_mssid = num_of_mssid_support(total_band - 1);

    memset(fh_prefix, 0x0, sizeof(fh_prefix));
    snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", band);
    memset(bkwl_prefix, 0x0, sizeof(bkwl_prefix));
    snprintf(bkwl_prefix, sizeof(bkwl_prefix), "bk_wl%d_", band);

    if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) != 1)
        return 0;

    mssid_subunit = nvram_get_int(strcat_r(fh_prefix, "subunit", tmp));

    memset(wl_prefix, 0x0, sizeof(wl_prefix));
    snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.%d_", band, mssid_subunit);

    for (pParam = &basic_wireless_settings[0]; pParam->param; pParam++) {
        if (strcmp(nvram_safe_get(strcat_r(wl_prefix, pParam->param, tmp)), nvram_safe_get(strcat_r(bkwl_prefix, pParam->param, tmp2)))) {
            nvram_set(strcat_r(wl_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(bkwl_prefix, pParam->param, tmp2)));
            DWB_DBG("Recover %s=%s\n", strcat_r(wl_prefix, pParam->param, tmp2), nvram_safe_get(strcat_r(bkwl_prefix, pParam->param, tmp)));
            changed = 1;
        }
        nvram_unset(strcat_r(bkwl_prefix, pParam->param, tmp2));
    }
    nvram_unset(strcat_r(bkwl_prefix, "backup", tmp));
    if (changed)
        set_wlan_service_status(band, mssid_subunit, 0); // deauth all client and disabled services and ready to restart wireless.
    return changed;
}

/**
 * @brief Set fronthaul AP config to fronthaul mssid_subunit.
 *
 * @param band Which band need to set fronthaul wireless config.
 * @return int Setting result. 0: Not be changed. 1: Be changed.
 */
int Setting_Fronthaul_AP_Config(int band)
{
    int mssid_subunit = 0, changed = 0;
    char fh_prefix[] = "fh_wlXXX_", wl_prefix[] = "wlXXX.XXXX_", tmp[64] = {}, tmp2[64] = {};
	const struct basic_wireless_setting_s *pParam = NULL;
    int total_band = num_of_wl_if();
	int max_mssid = num_of_mssid_support(total_band - 1);

    memset(fh_prefix, 0x0, sizeof(fh_prefix));
    snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", band);

    mssid_subunit = get_fh_ap_subunit();

    memset(wl_prefix, 0x0, sizeof(wl_prefix));
    snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.%d_", band, mssid_subunit);

    for (pParam = &basic_wireless_settings[0]; pParam->param; pParam++) {
        if (strcmp(nvram_safe_get(strcat_r(wl_prefix, pParam->param, tmp)), nvram_safe_get(strcat_r(fh_prefix, pParam->param, tmp2)))) {
            nvram_set(strcat_r(wl_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(fh_prefix, pParam->param, tmp2)));
            DWB_DBG("Setting %s=%s\n", strcat_r(wl_prefix, pParam->param, tmp), nvram_safe_get(strcat_r(fh_prefix, pParam->param, tmp2)));
            changed = 1;
        }
    }

    return changed;
}

/**
 * @brief Delete fronthaul wireless nvram config
 *
 * @param band Which band need to delete fronthaul wireless config.
 * @return int Delete result. -1: Error. 0: Success.
 */
int Unset_Fronthaul_AP_Setting(int band)
{
    int SUMband = num_of_wl_if();
    char fh_prefix[] = "fh_wlXXX_", tmp[64] = {0};
	const struct basic_wireless_setting_s *pParam = NULL;

    if (!(SUMband >= TRI_BAND))
        return -1;

    memset(fh_prefix, 0x0, sizeof(fh_prefix));
    snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", band);

    for (pParam = &basic_wireless_settings[0]; pParam->param; pParam++) {
        nvram_unset(strcat_r(fh_prefix, pParam->param, tmp));
        DWB_DBG("Unset %s\n", strcat_r(fh_prefix, pParam->param, tmp));
    }
    nvram_unset(strcat_r(fh_prefix, "subunit", tmp)); // unset recorded subunit info.
    return 0;
}

static int check_fh_ap_subunit_changed() {
    int SUMband = num_of_wl_if();
    int ret = 0;
    char bkwl_prefix[] = "bk_wlXXX_", tmp[64] = {}, fh_prefix[] = "fh_wlXXX_";
    int dwb_band = nvram_get_int("dwb_band");

    if (SUMband >= TRI_BAND) {
        snprintf(bkwl_prefix, sizeof(bkwl_prefix), "bk_wl%d_", dwb_band);
        snprintf(fh_prefix, sizeof(fh_prefix), "fh_wl%d_", dwb_band);
        if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) == 1) {
            if (nvram_get_int(strcat_r(fh_prefix, "subunit", tmp)) != get_fh_ap_subunit()) {  // different.
                Recover_Fronthaul_AP_Index_Config(dwb_band);
                nvram_set_int(strcat_r(fh_prefix, "subunit", tmp), get_fh_ap_subunit());  // record new subunit value
                Backup_Fronthaul_AP_Index_Config(dwb_band);
                Setting_Fronthaul_AP_Config(dwb_band);
                ret = 1;
            }
        }
    }
    return ret;
}

#ifdef SMART_CONNECT
/**
 * @brief Added fronthaul network to smart connect
 *
 * @param dwb_band DWB band
 */
static void fronthaul_ap_smart_connect(int dwb_band) {
    int smart_connect_x = nvram_get_int("smart_connect_x");
    int fh_subunit = get_fh_ap_subunit();
    char fh_prefix[] = "wlXX.XX_", bsd_ifnames[64] = {}, bsd_if_select_policy[64] = {};
    char fh_ifname[8] = {}, tmp[64] = {};
    int i;
    char wl_prefix[] = "wlXXX_";
    snprintf(fh_prefix, sizeof(fh_prefix), "wl%d.%d_", dwb_band, fh_subunit);
    strncpy(fh_ifname, nvram_safe_get(strcat_r(fh_prefix, "ifname", tmp)), sizeof(fh_ifname));
    if (smart_connect_x == 1) {  //  Triband Smart Connect
        // add to bsd_ifnames
        if (!strstr(nvram_safe_get("bsd_ifnames"), fh_ifname)) {  // Not exist
            add_to_list(nvram_safe_get("bsd_ifnames"), bsd_ifnames, sizeof(bsd_ifnames));
            add_to_list(fh_ifname, bsd_ifnames, sizeof(bsd_ifnames));
            nvram_set("bsd_ifnames", bsd_ifnames);
        }

        // add to bsd_if_select_policy
        for (i = 0; i < num_of_wl_if(); i++) {
            if (i == dwb_band)
                continue;

            memset(bsd_if_select_policy, 0x0, sizeof(bsd_if_select_policy));
            snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", i);
            if (!strstr(nvram_safe_get(strcat_r(wl_prefix, "bsd_if_select_policy", tmp)), fh_ifname)) {  // Not exist
                add_to_list(nvram_safe_get(strcat_r(wl_prefix, "bsd_if_select_policy", tmp)), bsd_if_select_policy, sizeof(bsd_if_select_policy));
                add_to_list(fh_ifname, bsd_if_select_policy, sizeof(bsd_if_select_policy));
                nvram_set(strcat_r(wl_prefix, "bsd_if_select_policy", tmp), bsd_if_select_policy);
            }
        }
    }
    return;
}

/**
 * @brief Remove fronthaul network from smart connect
 *
 * @param dwb_band DWB band
 */
static void remove_fronthaul_ap_smart_connect(int dwb_band) {
    char word[32] = {};
    char *next = NULL;
    int fh_subunit = get_fh_ap_subunit();
    char fh_ifname[8];
    char bsd_ifnames[64] = {}, bsd_if_select_policy[64] = {}, tmp[64] = {};
    int i;
    char wl_prefix[] = "wlXXX_", fh_prefix[] = "wlXX.XX_";

    snprintf(fh_prefix, sizeof(fh_prefix), "wl%d.%d_", dwb_band, fh_subunit);
    strncpy(fh_ifname, nvram_safe_get(strcat_r(fh_prefix, "ifname", tmp)), sizeof(fh_ifname));

    foreach (word, nvram_safe_get("bsd_ifnames"), next) {
        if (!strcmp(word, fh_ifname))  // exist
            continue;
        add_to_list(word, bsd_ifnames, sizeof(bsd_ifnames));
    }
    nvram_set("bsd_ifnames", bsd_ifnames);

    for (i = 0; i < num_of_wl_if(); i++) {
        if (i == dwb_band)
            continue;

        memset(bsd_if_select_policy, 0x0, sizeof(bsd_if_select_policy));
        snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", i);

        foreach (word, nvram_safe_get(strcat_r(wl_prefix, "bsd_if_select_policy", tmp)), next) {
            if (!strcmp(word, fh_ifname))  // exist
                continue;
            add_to_list(word, bsd_if_select_policy, sizeof(bsd_if_select_policy));
        }
        nvram_set(strcat_r(wl_prefix, "bsd_if_select_policy", tmp), bsd_if_select_policy);
    }
    return;
}
#endif

/**
 * @brief Checking the ssid of none-dwb band same as other band or not.
 *
 * @return int Process result. 0: different ssid. 1: same ssid.
 */
int cm_check_same_ssid_by_none_dwb_band()
{
    int unit = 0, ret = 1, dwb_band_unit = nvram_get_int("dwb_band"), base_unit = -1;
    int re_mode = nvram_get_int("re_mode");
    char wl_prefix[sizeof("wlXXXXX_")], base_prefix[sizeof("wlXXXXX_")];
    char base_ssid[64], wl_ssid[64], tmp[64];

    /* find base unit */
    for (unit = 0; unit < num_of_wl_if(); unit++) {
        if (unit == dwb_band_unit)
            continue;

        base_unit = unit;
        break;
    }

    if (base_unit != -1) {
        if (re_mode)
            snprintf(base_prefix, sizeof(base_prefix), "wl%d.1_", base_unit);
        else
            snprintf(base_prefix, sizeof(base_prefix), "wl%d_", base_unit);
        strlcpy(base_ssid, nvram_safe_get(strcat_r(base_prefix, "ssid", tmp)), sizeof(base_ssid));

        if (strlen(base_ssid)) {
            unit = 0;
            for (unit = 0; unit < num_of_wl_if(); unit++) {
                if (unit == dwb_band_unit || unit == base_unit)
                    continue;

                if (re_mode)
                    snprintf(wl_prefix, sizeof(wl_prefix), "wl%d.1_", unit);
                else
                    snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
                strlcpy(wl_ssid, nvram_safe_get(strcat_r(wl_prefix, "ssid", tmp)), sizeof(wl_ssid));

                if (strcmp(wl_ssid, base_ssid) != 0) {
                    DBG_INFO("%s is different as %s", wl_ssid, base_ssid);
                    ret = 0;
                    break;
                }
            }
        }
    }
    else
    {
        DBG_INFO("base_unit is invalid");
        ret = 0;
    }

    DBG_INFO("the ssid is %s", ret == 1 ? "same": "different");

    return ret;
}

/**
 * @brief Processing Fronthaul AP feature of DWB
 *
 * @return int Process result. 0: Success & don't need to do restart WiFi. 1: Success & Need to do restart WiFi.
 */
int Process_DWB_Fronthaul_AP(void) {
    char bkwl_prefix[] = "bk_wlXXX_", tmp[64] = {};
    int ret = 0, commit_flag = 0;
    int SUMband = num_of_wl_if();
    int dwb_band = nvram_get_int("dwb_band");

    if (check_fh_ap_subunit_changed() == 1) {
        commit_flag = 1;
        ret = 1;
    }

    if (nvram_get_int("re_mode") == 1) {  // RE
        if (SUMband >= TRI_BAND) {
            memset(bkwl_prefix, 0x0, sizeof(bkwl_prefix));
            snprintf(bkwl_prefix, sizeof(bkwl_prefix), "bk_wl%d_", dwb_band);
            if (nvram_get_int("fh_ap_enabled") > 0 && cm_check_same_ssid_by_none_dwb_band())
            {
                if (nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI || nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG) {
                    if (Generate_Fronthaul_AP_Setting(dwb_band) == 1) {                  // Changed
                        if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) != 1) {  // Not backup, need do it
                            Backup_Fronthaul_AP_Index_Config(dwb_band);
                            if (Setting_Fronthaul_AP_Config(dwb_band) == 1)  // Changed
                                ret = 1;
                            commit_flag = 1;
                        } else {                                               // Backuped.
                            if (Setting_Fronthaul_AP_Config(dwb_band) == 1) {  // Changed
                                ret = 1;
                                commit_flag = 1;
                            }
                        }
                    }
                } else {  // Disable dwb_mode
                    if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) == 1) {
                        if (Recover_Fronthaul_AP_Index_Config(dwb_band) == 1)  // Changed
                            ret = 1;
                        Unset_Fronthaul_AP_Setting(dwb_band);
                        commit_flag = 1;
                    }
                }
            } else {
                if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) == 1) {
                    if (Recover_Fronthaul_AP_Index_Config(dwb_band) == 1)  // Changed
                        ret = 1;
                    Unset_Fronthaul_AP_Setting(dwb_band);
                    commit_flag = 1;
                }
                nvram_set_int("fh_ap_bss", 0);
            }
        }
    } else {  // CAP
        if (SUMband >= TRI_BAND) {
            memset(bkwl_prefix, 0x0, sizeof(bkwl_prefix));
            snprintf(bkwl_prefix, sizeof(bkwl_prefix), "bk_wl%d_", dwb_band);
            if (nvram_get_int("fh_ap_enabled") > 0 &&
                (cm_check_same_ssid_by_none_dwb_band() || nvram_get_int("smart_connect_x") == 1))
            {
                if (nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_GUI || nvram_get_int("dwb_mode") == DWB_ENABLED_FROM_CFG) {
                    if (Generate_Fronthaul_AP_Setting(dwb_band) == 1) {                  // Changed
                        if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) != 1) {  // Not backup, need do it
                            Backup_Fronthaul_AP_Index_Config(dwb_band);
                            if (Setting_Fronthaul_AP_Config(dwb_band) == 1) {  // Changed
#ifdef SMART_CONNECT
                                fronthaul_ap_smart_connect(dwb_band);
#endif
                                ret = 1;
                            }
                        } else {                                               // Backuped.
                            if (Setting_Fronthaul_AP_Config(dwb_band) == 1) {  // Changed
#ifdef SMART_CONNECT
                                fronthaul_ap_smart_connect(dwb_band);
#endif
                                ret = 1;
                                commit_flag = 1;
                            }
                        }
                    }
                } else {  // Disable dwb_mode
                    if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) == 1) {
                        if (Recover_Fronthaul_AP_Index_Config(dwb_band) == 1) {  // Changed
#ifdef SMART_CONNECT
                            remove_fronthaul_ap_smart_connect(dwb_band);
#endif
                            ret = 1;
                        }
                        Unset_Fronthaul_AP_Setting(dwb_band);
                        commit_flag = 1;
                    }
                }
            } else {
                if (nvram_get_int(strcat_r(bkwl_prefix, "backup", tmp)) == 1) {
                    if (Recover_Fronthaul_AP_Index_Config(dwb_band) == 1) {  // Changed
#ifdef SMART_CONNECT
                        remove_fronthaul_ap_smart_connect(dwb_band);
#endif
                        ret = 1;
                    }
                    Unset_Fronthaul_AP_Setting(dwb_band);
                    commit_flag = 1;
                }
                nvram_set_int("fh_ap_bss", 0);
            }
        }
    }
    if (commit_flag)
        nvram_commit();
    return ret;
}

/**
 * @brief Restore all process fronthaul AP feature config
 *
 */
void Restore_Process_Fronthaul_AP(void) {
    int SUMband = num_of_wl_if();
    int fronthual_band = 0;

    switch (SUMband) {
        case DUAL_BAND:
            fronthual_band = WL_5G_BAND;
            break;
        case TRI_BAND:
            fronthual_band = WL_5G_2_BAND;
            break;
        default:
            return;
    }

    Recover_Fronthaul_AP_Index_Config(fronthual_band);
    Unset_Fronthaul_AP_Setting(fronthual_band);

    return;
}

/**
 * @brief Check fh_ap_enabled is supported in the FW version.
 *
 */
void check_fronthaul_dwb_value() {
    int current_val = 0;
    current_val = nvram_get_int("fh_ap_enabled");
    int fronthaul_capability = 0;
    int i;

    for (i = 0;  capability_list[i].type != 0; i++) {
        if (capability_list[i].type  == FRONTHAUL_AP_CTL) {
            fronthaul_capability = capability_list[i].subtype;
            break;
        }
    }

    if (nvram_get_int("re_mode") == 1) {
        // Sync from CAP. So don't do process this.
    } else {
        switch (current_val) {
            case 0:  // Off
                if (!(fronthaul_capability & BIT(0))) {
                    if (fronthaul_capability & BIT(1))
                        current_val = 1;  // Off->Auto
                    else if (fronthaul_capability & BIT(2))
                        current_val = 2;  // Off->On
                    else
                        current_val = 0;  // Off directly.
                    nvram_set_int("fh_ap_enabled", current_val);
                }
                break;
            case 1:  // Auto
                if (!(fronthaul_capability & BIT(1))) {
                    if (fronthaul_capability & BIT(0))
                        current_val = 0;  // Auto->Off
                    else if (fronthaul_capability & BIT(2))
                        current_val = 2;  // Auto->On
                    else
                        current_val = 0;  // Off directly.
                    nvram_set_int("fh_ap_enabled", current_val);
                }
                break;
            case 2:  // On
                if (!(fronthaul_capability & BIT(2))) {
                    if (fronthaul_capability & BIT(0))
                        current_val = 0;  // On->Off
                    else if (fronthaul_capability & BIT(1))
                        current_val = 2;  // On->Auto
                    else
                        current_val = 0;  // Off directly.
                    nvram_set_int("fh_ap_enabled", current_val);
                }
                break;
            default:  // Not support in this FW version.
                if (fronthaul_capability & BIT(0))
                    current_val = 0;  // ??? -> Off
                else if (fronthaul_capability & BIT(1))
                    current_val = 1;  // ??? -> Auto
                else if (fronthaul_capability & BIT(2))
                    current_val = 2;  // ??? -> On
                else
                    current_val = 0;  // Off directly.
                nvram_set_int("fh_ap_enabled", current_val);
                break;
        }
    }

    return;
}

#endif // RTCONFIG_FRONTHAUL_DWB
