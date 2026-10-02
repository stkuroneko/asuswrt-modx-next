#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <shared.h>
#include <shutils.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <json.h>
#include <math.h>
#include "amas_wlcconnect.h"
#include <amas_ipc.h>
#include <amas_path.h>
#include <cfg_dwb.h>
#include <sys/prctl.h>

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID	"33716237"
#define APP_KEY	"g2hkhuig238789ajkhc"
#endif

amas_ap_profile_s *ap_profiles;
amas_sitesurvey_ap_s *sitesurvey_ap;
amas_wlcconnect_bandindex_s *wlc_list;
amas_wlc_process_info_s process_info;
int SUMband;
int amas_wlcconnect_ipc_socket = -1;		/* socket for IPC */
unsigned int uuid_number = 0;
pid_t main_wlcconnect_pid;

int conn_timeout_reflist[8];
int profile_timeout_reflist[8];

extern void alg_update_ap_info(amas_sitesurvey_ap_s *ss_ap, int unit);
extern void alg_update_connecting_cost_to_nvram(int band, float cost);
extern void alg_clean_connecting_cost_to_nvram(int band);
extern void apply_config_to_driver(int band);

enum {SORTED_RSSI = 0, SORTED_COST = 1, SORTED_PAPCOST = 2, SORTED_RSSISCORE = 3, SORTED_BAND = 4};

int wlc_dbg = 0;

int process_term = 0;

static void init_conn_time(int SUMband) {
    int i;
    char tmp[32] = {};
    char amas_wlc_prefix[] = "amas_wlcXXX_";

    for (i = 0; i < SUMband; i++) {
        snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", i);
        conn_timeout_reflist[i] = nvram_get_int(strcat_r(amas_wlc_prefix, "connect_timeout", tmp));
        if (conn_timeout_reflist[i] < AMAS_TOTAL_CONNECTION_TIMEOUT) {
            if (conn_timeout_reflist[i] != 0)
                WLC_RUNTIME_LOG("Connection Timeout value(%d) invalid!!!.\n", conn_timeout_reflist[i]);
            conn_timeout_reflist[i] = AMAS_TOTAL_CONNECTION_TIMEOUT;
        }
        profile_timeout_reflist[i] = nvram_get_int(strcat_r(amas_wlc_prefix, "profile_timeout", tmp));
        if (profile_timeout_reflist[i] < AMAS_GLOBAL_PROFILE_TIMEOUT) {
            if (profile_timeout_reflist[i] != 0)
                WLC_RUNTIME_LOG("Profile switch Timeout value(%d) invalid!!!.\n", profile_timeout_reflist[i]);
            profile_timeout_reflist[i] = AMAS_GLOBAL_PROFILE_TIMEOUT;
        }
    }
}

/**
 * @brief Recoed process info
 *
 * @param type Kind of amas_wlcconnect process
 */
static void amas_init_process_info(int type)
{
    memset(&process_info, 0, sizeof(amas_wlc_process_info_s));
    process_info.pid = getpid();
    if (type == AMAS_WLC_PROCESS_MAIN)
        process_info.ppid = 0;
    else
        process_info.ppid = getppid();
    process_info.type = type;
}

static void amas_free_all_memory_exit(int signum);

/**
 * @brief Update amas_wlcconnect processing state
 *
 * @param state Interger for state
 */
static void update_amas_wlcconnect_status(int state)
{
    nvram_set_int("amas_wlc_action_state", state);
}

/**
 * @brief Get the amas wlcconnect status object
 *
 * @return int amas_wlcconnect state
 */
static int get_amas_wlcconnect_status(void)
{
    return nvram_get_int("amas_wlc_action_state");
}

/**
 * @brief Update wlc connection state
 *
 * @param bandindex Band index
 * @param state Connection state
 */
static void update_amas_wlcconnect_connection_status(int bandindex, int state)
{
    char amas_wlc_connection_state[] = "amas_wlcXXX_connection_state";
    snprintf(amas_wlc_connection_state, sizeof(amas_wlc_connection_state), "amas_wlc%d_connection_state", bandindex);
    if (nvram_get_int(amas_wlc_connection_state) != state) {
        nvram_set_int(amas_wlc_connection_state, state);
        WLC_DBG("BandIndex(%d) Update %s to %d\n", bandindex, amas_wlc_connection_state,
                state);
    }
}

/**
 * @brief Checking child process exist or not.
 *
 * @param pid child process id
 * @return int exist or not. 0: exit. 1: exist.
 */
static int chk_process_exist(int pid) {
    char path[] = "/proc/65535/exe";

    if (pid <= 0)
        return 0;

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    if (f_exists(path))
        return 1;

    return 0;
}

/**
 * @brief Get the amas wlcconnect connection status object
 *
 * @param bandindex Band index
 * @return int Connection state
 */
static int get_amas_wlcconnect_connection_status(int bandindex)
{
    char amas_wlc_connection_state[] = "amas_wlcXXX_connection_state";
    snprintf(amas_wlc_connection_state, sizeof(amas_wlc_connection_state), "amas_wlc%d_connection_state", bandindex);
    WLC_DBG("BandIndex(%d) Get %s = %d\n", bandindex, amas_wlc_connection_state, nvram_get_int(amas_wlc_connection_state));
    return nvram_get_int(amas_wlc_connection_state);
}

/**
 * @brief Update amas_wlcconnect processing state per band
 *
 * @param index Band index. (2G:0, 5G:1, 5G1:2, ...)
 * @param state Interger for state
 */
#if 0 // Reserved the no-use function
static void update_amas_wlcconnect_wlc_statue(int index ,int state)
{
    char amas_wlc_action_state[] = "amas_wlcXXX_action_state";
    snprintf(amas_wlc_action_state, sizeof(amas_wlc_action_state), "amas_wlc%d_action_state", index);
    nvram_set_int(amas_wlc_action_state, state);
}
#endif

/**
 * @brief
 *
 * @param param Connection parameter(SSID, auth_mode_x, ...)
 * @return char* Be converted parameter
 */
static char *covert_wlc_para(char *param)
{
    const struct convert_wlc_mapping_s *wlc_mapping_list =
        &convert_wlc_mapping_list[0];

    WLC_DBG("Ready Covert %s\n", param);

    for (wlc_mapping_list = &convert_wlc_mapping_list[0];
         wlc_mapping_list->name != NULL; wlc_mapping_list++) {
        if (!strcmp(wlc_mapping_list->name, param)) {
            if (wlc_mapping_list->converted_name) {
                WLC_DBG("Covert %s to %s\n", param, wlc_mapping_list->converted_name);
                return wlc_mapping_list->converted_name;
            }
            break;
        }
    }
    return param;
}

/**
 * @brief Get the band by index object
 *
 * @param bandindex Band index
 * @return int Band define value
 */
static int get_band_by_index(int bandindex) {
    int band;
    char amas_wlc_defif[] = "amas_wlcXXX_defif";

    snprintf(amas_wlc_defif, sizeof(amas_wlc_defif), "amas_wlc%d_defif", bandindex);
    band = nvram_get_int(amas_wlc_defif);

    if (band <= 0)
        band = WL2G_U;

    return band;
}

/**
 * @brief Get the band string by index object
 *
 * @param bandindex Band index
 * @return char* Band Name
 */
static char *get_band_string_by_index(int bandindex) {
    int band = get_band_by_index(bandindex);

    switch (band) {
        case WL2G_U:
            return "2.4G";
        case WL5G1_U:
            return "5G1";
        case WL5G2_U:
            return "5G2";
        case WL6G_U:
            return "6G";
        default:
            return "None";
    }
}

/**
 * @brief Waitting for DFS CAC
 *
 * @param wlc Up stream structure
 * @return int Don't need waitting reason.
 */
static int waitting_dfs_cac(amas_wlcconnect_bandindex_s *wlc) {
    char buf[32] = {};
    snprintf(buf, sizeof(buf), "amas_wlc%d_dfs_status", wlc->bandindex);
    do {
        if (amas_dfs_status(wlc->unit)) {
            if (wlc->dfs_status == 0) {
                wlc->dfs_status = 1;
                wlc->dfs_waitting_time = nvram_get_int("amas_dfs_time") ?: AMAS_DFS_WATTING_TIMEOUT;
                WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Stop connection.\n", getpid(), wlc->bandindex, wlc->unit);
                Pty_stop_wlc_connect(wlc->unit);
            }
            WLC_DBG("BandIndex(%d) Unit(%d) Checking DFS Status(1). DFS Timeout(%d) ###\n", wlc->bandindex, wlc->unit, wlc->dfs_waitting_time);
            if (nvram_get_int(buf) != wlc->dfs_status)  // Sync nvram for other amas daemon.
                nvram_set_int(buf, wlc->dfs_status);
            sleep(2);
            wlc->dfs_waitting_time = wlc->dfs_waitting_time - 2;
        } else {
            if (wlc->dfs_status) {
                wlc->dfs_status = 0;
                wlc->dfs_waitting_time = 0;
            }
            WLC_DBG("BandIndex(%d) Unit(%d) Checking DFS Status(0). DFS Timeout(%d) ###\n", wlc->bandindex, wlc->unit, wlc->dfs_waitting_time);
            if (nvram_get_int(buf) != wlc->dfs_status)  // Sync nvram for other amas daemon.
                nvram_set_int(buf, wlc->dfs_status);
        }
    } while (wlc->dfs_status && wlc->dfs_waitting_time > 0);

    if (wlc->dfs_status && wlc->dfs_waitting_time < 0)
        return -1;  // timeout

    return 0;  // DFS Idle.
}

/**
 * @brief Reset amas_wlcX_dfs_status
 *
 */
static void reset_dfs_status(void)
{
    WLC_DBG("Reset amas_wlcX_dfs_status\n");
    char buf[32] = {};
    int i = 0;

    while (i < SUMband) {
        snprintf(buf, sizeof(buf), "amas_wlc%d_dfs_status", i);
        if (nvram_get_int(buf) != 0)
            nvram_set_int(buf, 0);
        i++;
    }
}

/**
 * @brief Load connection nvram paramter to file.
 *
 * @param path Connection profiles file localtion
 * @return json_object* Connection profile json format data in RAM
 */
static json_object* generate_connection_profile(char *path) {
    json_object *profile_obj = NULL, *conn_para_obj = NULL;
    char buf[128] = {};
    int i;
    char wl_prefix[] = "wlXXXXXXXXXXXXX_";
    char tmp[32] = {};
    int dwb_mode = nvram_get_int("dwb_mode");

    if ((profile_obj = json_object_new_object()) == NULL) {
        WLC_DBG("profile_obj is NULL\n");
        return NULL;
    }
    for (i = 0; i < SUMband; i++) {
        snprintf(wl_prefix, sizeof(wl_prefix), "wlc%d_", i);
        if ((conn_para_obj = json_object_new_object())) {
            /* Profile name */
            snprintf(buf, sizeof(buf), "PROFILE_%s", get_band_string_by_index(i));
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_PROFILE_NAME, json_object_new_string(buf));
            /* Priority */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_PROFILE_PRIORITY, json_object_new_int(i));
            /* Band index */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_BANDINDEX, json_object_new_int(i));
            /* Band */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_BAND, json_object_new_int(get_band_by_index(i)));
            /* SSID */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_SSID, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "ssid", tmp))));
            /* bss enable */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_BSS_ENABLED, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "bss_enabled", tmp))));
            /* wpa_psk */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_WPAPSK, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "wpa_psk", tmp))));
            /* auth_mode_x */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_AUTH_MODE_X, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, covert_wlc_para("auth_mode_x"), tmp))));
            /* wep_x */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_WEP_X, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, covert_wlc_para("wep_x"), tmp))));
            /* crypto */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_CRYPTO, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "crypto", tmp))));
            /* mbss */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_MBSS, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "mbss", tmp))));
            /* closed */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_CLOSED, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "closed", tmp))));
            /* key */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key", tmp))));
            /* key1, key2, key3, key4 */
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY1, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key1", tmp))));
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY2, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key2", tmp))));
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY3, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key3", tmp))));
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY4, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key4", tmp))));
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
            json_object_object_add(conn_para_obj, WLC_CONNECT_STR_WDS, json_object_new_int(nvram_get_int("amas_wds")));
#endif
            snprintf(buf, sizeof(buf), "%d", i);
            json_object_object_add(profile_obj, buf, conn_para_obj);
        } else {
            WLC_DBG("conn_para_obj is NULL\n");
        }
    }

    if (dwb_mode == 1 || dwb_mode == 3) {  // Get DWB BH/FH
        for (i = 0; i < 2; i++) {
            if (i == 0)
                strncpy(wl_prefix, "wsfh_", sizeof(wl_prefix));
            else
                strncpy(wl_prefix, "wsbh_", sizeof(wl_prefix));

            if ((conn_para_obj = json_object_new_object())) {
                /* Profile name */
                if (i == 0) {
                    snprintf(buf, sizeof(buf), "PROFILE_FH");
                } else {
                    snprintf(buf, sizeof(buf), "PROFILE_BH");
                }
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_PROFILE_NAME, json_object_new_string(buf));
                /* Priority */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_PROFILE_PRIORITY, json_object_new_int(i + SUMband));
                /* Band index */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_BANDINDEX, json_object_new_int(1));  // Setting to 5G.
                /* Band */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_BAND, json_object_new_int(get_band_by_index(1)));  // Setting to 5G.
                /* SSID */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_SSID, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "ssid", tmp))));
                /* bss enable */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_BSS_ENABLED, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "bss_enabled", tmp))));
                /* wpa_psk */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_WPAPSK, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "wpa_psk", tmp))));
                /* auth_mode_x */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_AUTH_MODE_X, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "auth_mode_x", tmp))));
                /* wep_x */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_WEP_X, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "wep_x", tmp))));
                /* crypto */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_CRYPTO, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "crypto", tmp))));
                /* mbss */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_MBSS, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "mbss", tmp))));
                /* closed */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_CLOSED, json_object_new_int(nvram_get_int(strcat_r(wl_prefix, "closed", tmp))));
                /* key */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key", tmp))));
                /* key1, key2, key3, key4 */
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY1, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key1", tmp))));
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY2, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key2", tmp))));
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY3, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key3", tmp))));
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_KEY4, json_object_new_string(nvram_safe_get(strcat_r(wl_prefix, "key4", tmp))));
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
                json_object_object_add(conn_para_obj, WLC_CONNECT_STR_WDS, json_object_new_int(nvram_get_int("amas_wds")));
#endif
                snprintf(buf, sizeof(buf), "%d", i + SUMband);
                json_object_object_add(profile_obj, buf, conn_para_obj);
            } else {
                WLC_DBG("conn_para_obj is NULL\n");
            }
        }
    }

    return profile_obj;
}

/**
 * @brief Convert escapt string for json
 *
 * @param orig original string
 * @param conv converted string
 */
void escape_json_char(char *orig, char *conv)
{
    int i = 0, j = 0;
    while(orig[i] != '\0')
    {
        switch(orig[i])
        {
            case '"':
                conv[j] = '\\';
                ++j;
                conv[j] = '\"';
                break;
            case '\\':
                conv[j]= '\\';
                ++j;
                conv[j]= '\\';
                break;
            default:
                conv[j] = orig[i];
                break;
        }
        ++i;
        ++j;
    }

    conv[j] = '\0';
}

/**
 * @brief Waitting for SSD exit
 *
 * @param bandindex which band for ssd
 * @return int ssd exit status
 */
static int waitting_ssd_exit(int bandindex) {
    int t = 0, ssd_exit = 0;
    int ssd_exit_waitting_time = nvram_get_int("amas_ssd_exit_time") ?: AMAS_SSD_EXIT_WATTING_TIMEOUT;
    char prefix[] = "amas_wlcXXX_", tmp[32];

    WLC_RUNTIME_LOG("BandIndex(%d) wait amas_ssd exit\n", bandindex);
    if (nvram_get("ssd_not_exit"))
        return 0;

    snprintf(prefix, sizeof(prefix), "amas_wlc%d_", bandindex);

    while (t <= ssd_exit_waitting_time) {
        sleep(1);
        if (nvram_get_int(strcat_r(prefix, "ss_status", tmp)) == SS_STATUS_CANCELED ||
            nvram_get_int(strcat_r(prefix, "ss_status", tmp)) == SS_STATUS_FINISHED) {
            WLC_RUNTIME_LOG("BandIndex(%d) amas_ssd have exited\n", bandindex);
            ssd_exit = 1;
            break;
        }
        t++;
    }

    return ssd_exit;
}

/**
 * @brief Trigger amas_ssd to do sitesurvey
 *
 * @param bandindex Sitesurvey whitch band
 * @return int Sitesurvey result. 0: Success. Non-zero: Fail
 */
static int amas_trigger_sitesurvey(int bandindex)
{
    char msg[256], ssid_list[256], resp_msg[256] = {};
    int ret = 0, first_update = 0;
    amas_ap_profile_s *profiles = ap_profiles;
    int dwb_mode = nvram_get_int("dwb_mode");
    int band = get_band_by_index(bandindex);
    char compare_ssid_buf[64] = {};
    char ssid_conv_buf[65];

    memset(ssid_list, 0, sizeof(ssid_list));
    strlcat(ssid_list, "[", sizeof(ssid_list));

    while (profiles) {
        if (profiles->band == band) {
            if (strlen(profiles->ssid)) {
                snprintf(compare_ssid_buf, sizeof(compare_ssid_buf), "\"%s\"", profiles->ssid);
                if (!strstr(ssid_list, compare_ssid_buf)) {  // Not exist
                    if (!first_update)
                        first_update = 1;
                    else
                        strlcat(ssid_list, ",", sizeof(ssid_list));

                    strlcat(ssid_list, "\"", sizeof(ssid_list));
                    memset(ssid_conv_buf, 0, sizeof(ssid_conv_buf));
                    escape_json_char(profiles->ssid, ssid_conv_buf);
                    strlcat(ssid_list, ssid_conv_buf, sizeof(ssid_list));
                    strlcat(ssid_list, "\"", sizeof(ssid_list));
                }
            }
        } else if ((dwb_mode == 1 || dwb_mode == 3) && (band == WL5G1_U || band == WL5G2_U) && (profiles->band == WL5G1_U || profiles->band == WL5G2_U)) {  // If band is 5G-1 or 5G-2 and dwb_mode enable, get other 5G band SSID.
            if (strlen(profiles->ssid)) {
                snprintf(compare_ssid_buf, sizeof(compare_ssid_buf), "\"%s\"", profiles->ssid);
                if (!strstr(ssid_list, compare_ssid_buf)) {  // Not exist
                    if (!first_update)
                        first_update = 1;
                    else
                        strlcat(ssid_list, ",", sizeof(ssid_list));

                    strlcat(ssid_list, "\"", sizeof(ssid_list));
                    memset(ssid_conv_buf, 0, sizeof(ssid_conv_buf));
                    escape_json_char(profiles->ssid, ssid_conv_buf);
                    strlcat(ssid_list, ssid_conv_buf, sizeof(ssid_list));
                    strlcat(ssid_list, "\"", sizeof(ssid_list));
                }
            }
        }
        profiles = profiles->next;
    }
    strlcat(ssid_list, "]", sizeof(ssid_list));

    snprintf(msg, sizeof(msg), SSD_START_EVENT_MSG, bandindex, ssid_list);
    WLC_DBG("IPC: Event ID: SS_EVENT_START Message: %s\n", msg);
    if (send_msg_to_ipc_socket(AMAS_SSD_IPC_SOCKET_PATH, &msg[0], resp_msg, sizeof(resp_msg), 3000)) {
        WLC_DBG("Send IPC event fail.\n");
        ret = -1;
    } else {
        if (strlen(resp_msg))
            WLC_DBG("Trigger Resp Message: %s\n", resp_msg);
    }
    return ret;
}

/**
 * @brief Cancel amas_ssd to doing sitesurvey
 *
 * @param wlc_list wlc info list
 * @return int Cancel sitesurvey result. 0: Success. Non-zero: Fail
 */
static int amas_cancel_sitesurvey(amas_wlcconnect_bandindex_s *wlc_list)
{
    char msg[256], resp_msg[256] = {};
    int ret = 0, i = 0;

    while (i < SUMband) {
        if ((wlc_list+i)->sitesurveying) {
            snprintf(msg, sizeof(msg), SSD_CANCEL_EVENT_MSG, (wlc_list+i)->bandindex);
            WLC_DBG("IPC: Event ID: SS_EVENT_CANCEL Message: %s\n", msg);
            if (send_msg_to_ipc_socket(AMAS_SSD_IPC_SOCKET_PATH, &msg[0], resp_msg, sizeof(resp_msg), 3000)) {
                WLC_DBG("Send IPC event fail.\n");
                ret = -1;
            }
            else {
                if (strlen(resp_msg))
                    WLC_DBG("Trigger Resp Message: %s\n", resp_msg);
            }
            (wlc_list+i)->sitesurveying = 0;
        }
        i++;
    }
    return ret;
}

/**
 * @brief If 5GH and 5GL are the same AP and the order of 5GL is higher than 5GH, swap the order of 5GH and 5GL.
 *
 * @param tmp_head Sitesurvey result output.
 * @param new_ap Sitesurvey AP input
 * @param bandindex Band index.
 */
static void amas_sorted_5gchannel_sitesurvey_ap(amas_sitesurvey_ap_s **tmp_head, amas_sitesurvey_ap_s *new_ap, int bandindex) {
    amas_sitesurvey_ap_s *curr, *pre;
    char bssid_5g[MAC_STR_LEN + 1] = {}, bssid_5g1[MAC_STR_LEN + 1] = {};
    char lasybyte_str[8] = {};
    int swaped = 0;

    if (*tmp_head == NULL) {
        new_ap->next = *tmp_head;
        *tmp_head = new_ap;
    } else if (new_ap->last_byte_5g1 >=0 && new_ap->last_byte_5g >= 0) {
        strncpy(bssid_5g, new_ap->bssid, 15);
        snprintf(lasybyte_str, sizeof(lasybyte_str), "%02X", new_ap->last_byte_5g);
        strncat(bssid_5g, lasybyte_str, 2);

        strncpy(bssid_5g1, new_ap->bssid, 15);
        snprintf(lasybyte_str, sizeof(lasybyte_str), "%02X", new_ap->last_byte_5g1);
        strncat(bssid_5g1, lasybyte_str, 2);

        curr = *tmp_head;
        pre = NULL;
        while (curr != NULL) {
            if (!strcmp(curr->bssid, bssid_5g) || !strcmp(curr->bssid, bssid_5g1)) {  // Same AP
                if (curr->cost.cost == new_ap->cost.cost) {
                    if (new_ap->channel > curr->channel) {
                        swaped = 1;
                        break;
                    }
                }
            }
            pre = curr;
            curr = curr->next;
        }
        if (swaped) {
            if (pre != NULL) {
                pre->next = new_ap;
                new_ap->next = curr;
            } else {
                new_ap->next = curr;
                *tmp_head = new_ap;
            }
        } else {
            new_ap->next = pre->next;
            pre->next = new_ap;
        }
    } else {
        curr = *tmp_head;
        while (curr->next != NULL) {
            curr = curr->next;
        }
        new_ap->next = curr->next;
        curr->next = new_ap;
    }
}

/**
 * @brief Insertion sort API
 *
 * @param tmp_head New head for sorted linked list
 * @param new_ap Insert a AP struct
 * @param sorted_algrothim Sort by RSSI score or RSSI or cost
 * @param bandindex Band index
 */
static void amas_sorting_sitesurvey_ap_insert(amas_sitesurvey_ap_s **tmp_head, amas_sitesurvey_ap_s *new_ap, int sorted_algrothim, int bandindex) {
    amas_sitesurvey_ap_s *curr;

    if (sorted_algrothim == SORTED_RSSISCORE) {  // SORTED_RSSISCORE
        if (*tmp_head == NULL || (*tmp_head)->RSSIscore <= new_ap->RSSIscore) {
            new_ap->next = *tmp_head;
            *tmp_head = new_ap;
        } else {
            curr = *tmp_head;
            while (curr->next != NULL && curr->next->RSSIscore > new_ap->RSSIscore) {
                curr = curr->next;
            }
            new_ap->next = curr->next;
            curr->next = new_ap;
        }
    } else if (sorted_algrothim == SORTED_COST) {  // SORTED_COST
        if (*tmp_head == NULL || (*tmp_head)->cost.cost > new_ap->cost.cost) {
            new_ap->next = *tmp_head;
            *tmp_head = new_ap;
        } else {
            curr = *tmp_head;
            while (curr->next != NULL && (curr->next->cost.cost <= new_ap->cost.cost || curr->next->bandindex != bandindex)) {
                curr = curr->next;
            }
            new_ap->next = curr->next;
            curr->next = new_ap;
        }
    } else if (sorted_algrothim == SORTED_PAPCOST) {  // SORTED_PAPCOST
        if (*tmp_head == NULL || (*tmp_head)->cost.pap_cost > new_ap->cost.pap_cost) {
            new_ap->next = *tmp_head;
            *tmp_head = new_ap;
        } else {
            curr = *tmp_head;
            while (curr->next != NULL && (curr->next->cost.pap_cost <= new_ap->cost.pap_cost || curr->next->bandindex != bandindex)) {
                curr = curr->next;
            }
            new_ap->next = curr->next;
            curr->next = new_ap;
        }
    } else if (sorted_algrothim == SORTED_BAND) {  // SORTED_BAND
        //  WL6G_U > WL5G2_U > WL5G1_U > WL2G_U
        if (*tmp_head == NULL || (*tmp_head)->cost.cost_band <= new_ap->cost.cost_band) {
            new_ap->next = *tmp_head;
            *tmp_head = new_ap;
        } else {
            curr = *tmp_head;
            while (curr->next != NULL && (curr->next->cost.cost_band > new_ap->cost.cost_band || curr->next->bandindex != bandindex)) {
                curr = curr->next;
            }
            new_ap->next = curr->next;
            curr->next = new_ap;
        }
    } else {  // SORTED_RSSI
        if (*tmp_head == NULL || (*tmp_head)->rssi <= new_ap->rssi) {
            new_ap->next = *tmp_head;
            *tmp_head = new_ap;
        } else {
            curr = *tmp_head;
            while (curr->next != NULL && curr->next->rssi > new_ap->rssi) {
                curr = curr->next;
            }
            new_ap->next = curr->next;
            curr->next = new_ap;
        }
    }
}

/**
 * @brief Insert a new ap to sitesurvey AP list
 *
 * @param ss_ap_head AP list head
 * @param ss_ap new AP
 * @return int Insert AP result. 0: Success. non-zero: Fail
 */
static int amas_insert_sitesurvey_ap(amas_sitesurvey_ap_s **ss_ap_head, amas_sitesurvey_ap_s *ss_ap)
{
    amas_sitesurvey_ap_s *ss_ap_tmp = NULL;

    if (*ss_ap_head == NULL) {
        *ss_ap_head = ss_ap;
    }
    else {
        ss_ap_tmp = *ss_ap_head;
        while (ss_ap_tmp) {
            if (ss_ap_tmp->next == NULL) {
                ss_ap_tmp->next = ss_ap;
                break;
            }
            ss_ap_tmp = ss_ap_tmp->next;
        }
    }
    return 0;
}

/**
 * @brief Sorted for aimesh algorithm rssiscore
 *
 * @param ss_ap sitesurvey result
 * @param bandindex band
 */
static void alg_rssiscore_sort(amas_sitesurvey_ap_s *ss_ap, int bandindex)
{
    // Sorting by priority
    amas_sitesurvey_ap_s *tmp = NULL, *new_head = NULL, *last_prefer_device = NULL;
    amas_sitesurvey_ap_s *curr = NULL;
    int rssi_score_algorithm = SORTED_RSSISCORE;
    int cap_rssi_threshold;
    int using_cost = 1;
    int band = get_band_by_index(bandindex);

    /* First, Find CAP and move to head. */
    WLC_DBG("Sorting for finding CAP and move to head.\n");

    if (band == WL2G_U)
        cap_rssi_threshold = nvram_get_int("amas_cap_2g_rssi_th") < 0 ? nvram_get_int("amas_cap_2g_rssi_th") : -70;
    else if (band == WL5G1_U || band == WL5G2_U)
        cap_rssi_threshold = nvram_get_int("amas_cap_5g_rssi_th") < 0 ? nvram_get_int("amas_cap_5g_rssi_th") : -70;
    else
        cap_rssi_threshold = nvram_get_int("amas_cap_6g_rssi_th") < 0 ? nvram_get_int("amas_cap_6g_rssi_th") : -70;

    curr = ss_ap;
    /* Checking for using cost or not */
    while (curr) {
        if (curr->cost.cost < 0 && curr->bandindex == bandindex) {
            using_cost = 0;
            break;
        }
        curr = curr->next;
    }

    if (using_cost) { // Using cost value
        WLC_DBG("Use cost to select AP.\n");
        int have_prefer_device = 0;
        curr = ss_ap;
        while (curr) {
            if (curr->cost.cost == 0 && curr->rssi > cap_rssi_threshold && curr->bandindex == bandindex) { // CAP or Cost 0 & RSSI > Prefer device RSSI threshold
                curr->prefer_device = 1;
                have_prefer_device = 1;
                /* move to head. */
                if (curr != ss_ap) {
                    tmp->next = curr->next;
                    curr->next = ss_ap;
                    ss_ap = curr;
                    curr = tmp->next; // Ready for processing next one.
                }
                else {
                    tmp = curr; // record
                    curr = curr->next;
                }
            }
            else {
                tmp = curr; // record.
                curr = curr->next;
            }
        }
        sitesurvey_ap = ss_ap;

        /* Sorting prefer device */
        if (have_prefer_device) {
            curr = ss_ap;
            tmp = NULL;
            while(curr) {
                amas_sitesurvey_ap_s *next = curr->next;
                if (curr->prefer_device) {
                    amas_sorting_sitesurvey_ap_insert(&tmp, curr, SORTED_RSSI, bandindex);
                }
                else {
                    curr->next = NULL;
                    amas_insert_sitesurvey_ap(&tmp, curr);
                }
                curr = next;
            }
            if (tmp) {
                ss_ap = tmp;
                sitesurvey_ap = ss_ap;
            }
        }

        WLC_DBG("Don't need process CAP DuT again. So start from non-cap mode\n");
        /* Don't need process CAP DuT again. So start from non-cap mode.*/
        curr = ss_ap;
        tmp = NULL;
        while (curr) {
            if (curr->prefer_device == 1) {
                tmp = curr->next;
                if (tmp)
                    last_prefer_device = curr;
                else // all prefer device.
                    return;
            }
            curr = curr->next;
        }
        if (tmp != NULL)
            new_head = tmp;
        else { // No prefer device
            new_head = ss_ap;
        }
    }
    else { // No cost
        WLC_DBG("Don't use cost to select AP.\n");
        new_head = ss_ap;
    }

    WLC_DBG("Checking for selecting RSSI algorithm or cost relate algorithm\n");
    /* Whether have Dut with old version AiMesh. */
    /* Find No cost DuT */
    curr = new_head;
    while (curr) {
        if (curr->cost.cost < 0 && curr->bandindex == bandindex) { // RSSI algorithm.
            rssi_score_algorithm = SORTED_RSSI;
            break;
        }
        curr = curr->next;
    }

    WLC_DBG("Sorting with Algo(%d).\n", rssi_score_algorithm);
    curr = new_head;
    tmp = NULL;

    while (curr != NULL)
    {
        amas_sitesurvey_ap_s *next = curr->next;
        if (curr->bandindex != bandindex) { // Different band ap. Don't need to do sort. Added to tail.
            curr->next = NULL;
            amas_insert_sitesurvey_ap(&tmp, curr);
        } else {
            amas_sorting_sitesurvey_ap_insert(&tmp, curr, rssi_score_algorithm, bandindex);
        }
        curr = next;
    }
    new_head = tmp;

    if(last_prefer_device)
        last_prefer_device->next = new_head;
    else
        sitesurvey_ap = new_head;
}

/**
 * @brief Sorted by cost
 *
 * @param ss_ap sitesurvey result
 * @param bandindex band index
 */
static void alg_cost_sort(amas_sitesurvey_ap_s *ss_ap, int bandindex) {
    // Sorting by priority
    amas_sitesurvey_ap_s *tmp = NULL, *new_head = NULL;
    amas_sitesurvey_ap_s *curr = ss_ap;
    int using_cost = 1;

    /* Checking for using cost or not */
    while (curr) {
        if (curr->cost.cost < 0 && curr->bandindex == bandindex) {
            using_cost = 0;
            break;
        }
        curr = curr->next;
    }

    if (using_cost == 1) {  // Cost sorted
        curr = ss_ap;
        tmp = NULL;

        while (curr != NULL) {
            amas_sitesurvey_ap_s *next = curr->next;
            if (curr->bandindex != bandindex) {  // Different band ap. Don't need to do sort. Added to tail.
                curr->next = NULL;
                amas_insert_sitesurvey_ap(&tmp, curr);
            } else {
                amas_sorting_sitesurvey_ap_insert(&tmp, curr, SORTED_RSSI, bandindex);
            }
            curr = next;
        }
        new_head = tmp;

        curr = new_head;
        tmp = NULL;

        while (curr != NULL) {
            amas_sitesurvey_ap_s *next = curr->next;
            if (curr->bandindex != bandindex) {  // Different band ap. Don't need to do sort. Added to tail.
                curr->next = NULL;
                amas_insert_sitesurvey_ap(&tmp, curr);
            } else {
                amas_sorting_sitesurvey_ap_insert(&tmp, curr, SORTED_PAPCOST, bandindex);
            }
            curr = next;
        }
        new_head = tmp;

        curr = new_head;
        tmp = NULL;

        while (curr != NULL) {
            amas_sitesurvey_ap_s *next = curr->next;
            if (curr->bandindex != bandindex) {  // Different band ap. Don't need to do sort. Added to tail.
                curr->next = NULL;
                amas_insert_sitesurvey_ap(&tmp, curr);
            } else {
                amas_sorting_sitesurvey_ap_insert(&tmp, curr, SORTED_BAND, bandindex);
            }
            curr = next;
        }
        new_head = tmp;

        curr = new_head;
        tmp = NULL;

        while (curr != NULL) {
            amas_sitesurvey_ap_s *next = curr->next;
            if (curr->bandindex != bandindex) {  // Different band ap. Don't need to do sort. Added to tail.
                curr->next = NULL;
                amas_insert_sitesurvey_ap(&tmp, curr);
            } else {
                amas_sorting_sitesurvey_ap_insert(&tmp, curr, SORTED_COST, bandindex);
            }
            curr = next;
        }
        new_head = tmp;

        /* Swap 5GL/5GH AP if the cost is the sames. */
        curr = new_head;
        tmp = NULL;

        while (curr != NULL) {
            amas_sitesurvey_ap_s *next = curr->next;
            if (curr->bandindex != bandindex) {  // Different band ap. Don't need to do sort. Added to tail.
                curr->next = NULL;
                amas_insert_sitesurvey_ap(&tmp, curr);
            } else {
                amas_sorted_5gchannel_sitesurvey_ap(&tmp, curr, bandindex);
            }
            curr = next;
        }
        new_head = tmp;
    } else {  // RSSI sorted
        curr = ss_ap;
        tmp = NULL;

        while (curr != NULL) {
            amas_sitesurvey_ap_s *next = curr->next;
            if (curr->bandindex != bandindex) {  // Different band ap. Don't need to do sort. Added to tail.
                curr->next = NULL;
                amas_insert_sitesurvey_ap(&tmp, curr);
            } else {
                amas_sorting_sitesurvey_ap_insert(&tmp, curr, SORTED_RSSI, bandindex);
            }
            curr = next;
        }
        new_head = tmp;
    }
    sitesurvey_ap = new_head;
}

/**
 * @brief Sorting sitesurvey result
 *
 * @param ss_ap Sitesurvey AP list
 * @param bandindex band index.
 * @return int Sorting Result. 0: Success. non-zero: Fail
 */
static int amas_sorting_sitesurvey_result(amas_sitesurvey_ap_s *ss_ap, int bandindex)
{
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    if (aimesh_alg == AIMESH_ALG_COST)
        alg_cost_sort(ss_ap, bandindex);
    else
        alg_rssiscore_sort(ss_ap, bandindex);

    return 0;
}

/**
 * @brief Print sitesurvey result for debugging
 *
 * @param ss_ap Sitesurvey result AP list
 */
void amas_dump_sitesurvey_ap(amas_sitesurvey_ap_s *ss_ap) {
    amas_sitesurvey_ap_s *ss_ap_tmp = NULL;
    WLC_DBG("Site Survey Result:\n");

    ss_ap_tmp = ss_ap;
    int i = 0;
    while (ss_ap_tmp) {
        WLC_RUNTIME_LOG("[%d] UUID[%d] Band[%s] SSID[%s] BSSID[%s] Manual_mode[%d] CAP Role[%d] Prefer dev[%d] RSSI[%d] Channel[%d] BW[%d] Lastbytes[0x%02x,0x%02x,0x%02x,0x%02x] PAP Cost[%.1f] Cost[%.1f] Cost_Band[%d] Score[%d]\n",
                i, ss_ap_tmp->uuid, get_band_string_by_index(ss_ap_tmp->bandindex), ss_ap_tmp->ssid, ss_ap_tmp->bssid, ss_ap_tmp->manual_mode, ss_ap_tmp->cap_role, ss_ap_tmp->prefer_device, ss_ap_tmp->rssi, ss_ap_tmp->channel, ss_ap_tmp->bw, ss_ap_tmp->last_byte_2g,
                ss_ap_tmp->last_byte_5g, ss_ap_tmp->last_byte_5g1, ss_ap_tmp->last_byte_6g, ss_ap_tmp->cost.pap_cost, ss_ap_tmp->cost.cost, ss_ap_tmp->cost.cost_band, ss_ap_tmp->RSSIscore);

        ss_ap_tmp = ss_ap_tmp->next;
        i++;
    }
}

/**
 * @brief Get scanned AP counts
 *
 * @param bandindex Band
 * @return int AP counts
 */
static int amas_get_site_sitesurvey_result_counts(int bandindex)
{
    char site_survey_file_path[64];
    json_object *root;
    int ap_count = 0;

    snprintf(site_survey_file_path, sizeof(site_survey_file_path),
             SURVEY_RESULT_FILE_NAME, bandindex);

    root = json_object_from_file(site_survey_file_path);

    if (!root) {
        WLC_DBG("root is NULL\n");
        goto AMAS_GET_SITESURVEY_RESULT_COUNTS_EXIT;
    }

    json_object_object_foreach(root, key, val) {
        ap_count++;
        (void)key; (void)val; // fixed warning. Variable set but not used.
    }
    json_object_put(root);

AMAS_GET_SITESURVEY_RESULT_COUNTS_EXIT:

    WLC_DBG("Scanned %d AP\n", ap_count);
    return ap_count;
}

/**
 * @brief Get amas_ssd sitesurvey result
 *
 * @param bandindex band index
 * @param unit band unit
 * @return int Result. 0: Success. non-zero: Fail
 */
static int amas_get_site_sitesurvey_result(int bandindex, int unit) {
    json_object *root = NULL, *ssid_obj = NULL, *rssi_obj = NULL, *cap_role_obj = NULL, *infType_obj = NULL,
                *channel_obj = NULL, *cost_obj = NULL, *last_byte_2g_obj = NULL, *last_byte_5g_obj = NULL, *last_byte_5g1_obj = NULL,
                *last_byte_6g_obj = NULL, *bw_obj = NULL;
    char site_survey_file_path[64];
    amas_sitesurvey_ap_s *ss_ap = NULL;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
    json_object *wds_obj = NULL;
#endif
    char wl_nband[] = "wlXXX_nband";
    snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", unit);
    int nband = nvram_get_int(wl_nband);
    snprintf(site_survey_file_path, sizeof(site_survey_file_path),
             SURVEY_RESULT_FILE_NAME, bandindex);

    WLC_RUNTIME_LOG("Getting BandIndex(%d) Unit(%d) Site Survey result from (%s)\n", bandindex, unit, site_survey_file_path);

    root = json_object_from_file(site_survey_file_path);

    if (!root) {
        WLC_DBG("root is NULL\n");
        return -1;
    }

    json_object_object_foreach(root, key, val) {

        WLC_RUNTIME_LOG("Parsing MAC: %s\n", key);
        json_object_object_get_ex(val, SSD_STR_SSID, &ssid_obj);
        json_object_object_get_ex(val, SSD_STR_RSSI, &rssi_obj);
        json_object_object_get_ex(val, SSD_STR_CHANNEL, &channel_obj);
        json_object_object_get_ex(val, SSD_STR_COST, &cost_obj);
        json_object_object_get_ex(val, SSD_STR_CAP_ROLE, &cap_role_obj);
        json_object_object_get_ex(val, SSD_STR_2G_LAST_BYTE, &last_byte_2g_obj);
        json_object_object_get_ex(val, SSD_STR_5G_LAST_BYTE, &last_byte_5g_obj);
        json_object_object_get_ex(val, SSD_STR_5G1_LAST_BYTE, &last_byte_5g1_obj);
        json_object_object_get_ex(val, SSD_STR_6G_LAST_BYTE, &last_byte_6g_obj);
        json_object_object_get_ex(val, SSD_STR_INF_TYPE, &infType_obj);
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
        json_object_object_get_ex(val, SSD_STR_WDS, &wds_obj);
#endif
        json_object_object_get_ex(val, SSD_STR_BANDWIDTH, &bw_obj);
        if (infType_obj) {
            if (json_object_get_int(infType_obj) == 1) {
                WLC_DBG("MAC(%s) is Guest Network AP. Skip processing it.\n", key);
                continue;
            }
        }

        ss_ap = (amas_sitesurvey_ap_s *)calloc(1, sizeof(amas_sitesurvey_ap_s));

        if (ss_ap == NULL) {
            WLC_DBG("Allocate memory for Site Survey AP node fail.\n");
            return -1;
        }

        ss_ap->uuid = (++uuid_number);
        if (ss_ap->uuid == 0) //Don't use 0.
            ss_ap->uuid = (++uuid_number);

        ss_ap->bandindex = bandindex;
        ss_ap->band = get_band_by_index(bandindex);

        snprintf(ss_ap->bssid, sizeof(ss_ap->bssid), "%s", key); // BSSID.
        if (ssid_obj) { // SSID
            snprintf(ss_ap->ssid, sizeof(ss_ap->ssid), "%s", json_object_get_string(ssid_obj)); // SSID.
        }
        if (rssi_obj) {
            ss_ap->rssi = json_object_get_int(rssi_obj); // RSSI
        }
        if (channel_obj) {
            ss_ap->channel = json_object_get_int(channel_obj); // Channel
        }

        /* last bytes */
        if (last_byte_2g_obj)
            ss_ap->last_byte_2g = json_object_get_int(last_byte_2g_obj);  // last byte 2G
        else
            ss_ap->last_byte_2g = -1;

        if (last_byte_5g_obj)
            ss_ap->last_byte_5g = json_object_get_int(last_byte_5g_obj);  // last byte 5G
        else
            ss_ap->last_byte_5g = -1;

        if (last_byte_5g1_obj)
            ss_ap->last_byte_5g1 = json_object_get_int(last_byte_5g1_obj);  // last byte 5G-1
        else
            ss_ap->last_byte_5g1 = -1;

        if (last_byte_6g_obj)
            ss_ap->last_byte_6g = json_object_get_int(last_byte_6g_obj);  // last byte 6G
        else
            ss_ap->last_byte_6g = -1;

        /* Cost */
        if (cost_obj) {
            ss_ap->cost.pap_cost = json_object_get_int(cost_obj) / 10.0;  // PAP Cost
        } else {
            ss_ap->cost.pap_cost = 100;
        }
        ss_ap->cost.cost = -1;
        ss_ap->cost.cost_band = -1;
        ss_ap->cost.cost_2g = -1;   // Init.
        ss_ap->cost.cost_5g = -1;   // Init.
        ss_ap->cost.cost_5g1 = -1;  // Init.
        ss_ap->cost.cost_6g = -1;   // Init.

        if (cap_role_obj) {
            ss_ap->cap_role = json_object_get_int(cap_role_obj); // CAP role
        }
        else
            ss_ap->cap_role = 0;

        ss_ap->prefer_device = 0; // Prefer device

        ss_ap->RSSIscore = 100;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
        if (wds_obj) //sitesurvey ssid 
		ss_ap->wds = json_object_get_int(wds_obj); 
	else 
		ss_ap->wds = 0;
#endif
        /* Bandwidth */
        int no_bandwidth_info = 0;
        if (bw_obj) {
            int bw_temp = json_object_get_int(bw_obj);
            if (bw_temp == 20 || bw_temp == 40 || bw_temp == 80 || bw_temp == 160) {
                ss_ap->bw = bw_temp;
            } else {
                no_bandwidth_info = 1;
            }
        } else {
            no_bandwidth_info = 1;
        }
        if (no_bandwidth_info) {
            switch (nband) {
                case 2:  // 2.4G
                    ss_ap->bw = 20;
                    break;
                case 1:  // 5G
                    ss_ap->bw = 80;
                    break;
                case 4:  // 6G
                    ss_ap->bw = 160;
                    break;
                default:  // setting to 20MHz
                    ss_ap->bw = 20;
                    break;
            }
        }

        alg_update_ap_info(ss_ap, unit);

        amas_insert_sitesurvey_ap(&sitesurvey_ap, ss_ap);
        ss_ap = NULL;
    }

    json_object_put(root);
    return 0;
}

/**
 * @brief Looking for the AP is in the result list
 *
 * @param bssid The BSSID of the AP being looked for
 * @param ss_ap result list
 * @return amas_sitesurvey_ap_s* If found, return the AP address. If not found, return NULL.
 */
static amas_sitesurvey_ap_s *amas_find_bssid(char *bssid, amas_sitesurvey_ap_s *ss_ap)
{
    amas_sitesurvey_ap_s *tmp = ss_ap;

    while(tmp) {
        if (!strcmp(tmp->bssid, bssid)) {
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}

/**
 * @brief Get user setting target bssid counts
 *
 * @param bandindex Band
 * @return int target bssid counts
 */
static int amas_get_target_bssid_counts(int bandindex)
{
    char amas_wlc_target_bssid[] = "amas_wlcXXX_target_bssid";
    char *target_bssid = NULL, *g_target_bssid = NULL, *p_target_bssid = NULL;
    int ap_count = 0;

    snprintf(amas_wlc_target_bssid, sizeof(amas_wlc_target_bssid), "amas_wlc%d_target_bssid", bandindex);
    target_bssid = g_target_bssid = strdup(nvram_safe_get(amas_wlc_target_bssid));

    while (g_target_bssid) {
        if ((p_target_bssid = strsep(&g_target_bssid, "<")) == NULL) break;
        if (strlen(p_target_bssid) > 0)
            ap_count++;
    }

    if (target_bssid)
        free(target_bssid);

    WLC_DBG("BandIndex(%d) Target AP count %d\n", bandindex, ap_count);

    return ap_count;
}

/**
 * @brief Add manual target AP node into head of sitesurvey result
 *
 * @param sorted_ap sorted sitesurvey result
 * @param bandindex Band index
 * @return int Process result. 0: Success. Non-zero: Fail.
 */
static int amas_add_target_ap_to_result(amas_sitesurvey_ap_s **sorted_ap, int bandindex)
{
    char amas_wlc_target_bssid[] = "amas_wlcXXX_target_bssid";  // amas_wlcX_target_bssid "<AA:AA:AA:AA:AA<BB:BB:BB:BB:BB"
    char *target_bssid = NULL, *g_target_bssid = NULL, *p_target_bssid = NULL;
    int ret = 0;
    amas_sitesurvey_ap_s *target_ap_tmp = NULL;

    snprintf(amas_wlc_target_bssid, sizeof(amas_wlc_target_bssid), "amas_wlc%d_target_bssid", bandindex);
    target_bssid = g_target_bssid = strdup(nvram_safe_get(amas_wlc_target_bssid));

    if (target_bssid == NULL || strlen(target_bssid) == 0)
    {
        free(target_bssid);
        return ret;
    }

    while (g_target_bssid) {
        if ((p_target_bssid = strsep(&g_target_bssid, "<")) == NULL) break;
        if (strlen(p_target_bssid) > 0) {
            WLC_DBG("BandIndex(%d) Processing manual target AP(%s)\n", bandindex, p_target_bssid);
            target_ap_tmp = amas_find_bssid(p_target_bssid, *sorted_ap);
            if (target_ap_tmp)  // Found
                target_ap_tmp->manual_mode = 1;
        }
    }
    free(target_bssid);
    return ret;
}

/**
 * @brief Get sitesurvey result and sort it
 *
 * @param bandindex band index
 * @param unit band unit
 * @return int Result. 0: Success. non-zero: Fail
 */
static int amas_wlcconnect_load_sitesurvey_result(int bandindex, int unit)
{
    /* Open JSON file and convert to struct array */
    if (amas_get_site_sitesurvey_result(bandindex, unit))
        return -1;

    /* Sort by RSSI */
    if (amas_sorting_sitesurvey_result(sitesurvey_ap, bandindex))
        return -1;

    /* Add target AP info by user */
    if (amas_add_target_ap_to_result(&sitesurvey_ap, bandindex))
        return -1;

    WLC_RUNTIME_LOG("Sorted:\n");
    amas_dump_sitesurvey_ap(sitesurvey_ap);

    return 0;
}

/**
 * @brief Smarter way to set nvram values for Strings
 *
 * @param nvram_para Nvram parameter
 * @param val New value
 * @return int Update value. 0: Not be update to new value. 1: Be updated to new value.
 */
static int amas_nvram_diff_set(char* nvram_para, char* val) {

    if (strcmp(nvram_safe_get(nvram_para), val)) { // Different
        WLC_DBG("NVRAM(%s) Change val(%s) -> val(%s)\n", nvram_para, nvram_safe_get(nvram_para), val);
        nvram_set(nvram_para, val);
        return 1;
    }
    return 0;
}

/**
 * @brief Smarter way to set nvram values for Integer
 *
 * @param nvram_para Nvram parameter
 * @param val New value
 * @return int Update value. 0: Not be update to new value. 1: Be updated to new value.
 */
static int amas_nvram_diff_set_int(char* nvram_para, int val) {

    if (nvram_get_int(nvram_para) != val) { // Different
	WLC_DBG("NVRAM(%s) Change val(%d) -> val(%d)\n", nvram_para, nvram_get_int(nvram_para), val);
        nvram_set_int(nvram_para, val);
        return 1;
    }
    return 0;
}

/**
 * @brief Setting connection nvram value for connect
 *
 * @param profile Connection profile struct
 * @param bandindex band index
 * @param unit band unit
 */
static void amas_setting_nvram_for_connection(amas_ap_profile_s *profile, int bandindex, int unit)
{
    char prefix[] = "wlXXXXXXXXXX_";
    char wlc_prefix[] = "wlcXXXXXXXXXX_";
    char tmp[32] = {};
    int different = 0;
    char auth_mode_x[16] = {}, crypto[16];

    snprintf(prefix, sizeof(prefix), "wl%d_", unit);
    snprintf(wlc_prefix, sizeof(wlc_prefix), "wlc%d_", bandindex);

    int nband = nvram_get_int(strcat_r(prefix, "nband", tmp));

    strlcpy(auth_mode_x, profile->auth_mode_x, sizeof(auth_mode_x));
    strlcpy(crypto, profile->crypto, sizeof(crypto));
    if (nband == 1) {                       // 5G
        if (!strcmp(auth_mode_x, "sae")) {  // sae -> psk2sae
            strlcpy(auth_mode_x, "psk2sae", sizeof(auth_mode_x));
            strlcpy(crypto, "aes", sizeof(crypto));
        } else if (!strcmp(auth_mode_x, "owe")) {  // owe -> open
            strlcpy(auth_mode_x, "open", sizeof(auth_mode_x));
            strlcpy(crypto, "", sizeof(crypto));
        }
    }
#ifdef RTCONFIG_WIFI6E
    else if (nband == 4) {                                     // 6G
        if (!strcmp(auth_mode_x, "open")) {                    // open
            strlcpy(auth_mode_x, "owe", sizeof(auth_mode_x));  // open -> owe
            strlcpy(crypto, "aes", sizeof(crypto));
        } else {                                               // non-open
            strlcpy(auth_mode_x, "sae", sizeof(auth_mode_x));  // xx -> sae
            strlcpy(crypto, "aes", sizeof(crypto));
        }
    }
#endif

    /* Setting wlX_*/
    if (amas_nvram_diff_set(strcat_r(prefix, "ssid", tmp), profile->ssid)) different = 1;
    //if (amas_nvram_diff_set_int(strcat_r(prefix, "bss_enabled", tmp), profile->bss_enabled)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "wpa_psk", tmp), profile->wpa_psk)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "auth_mode_x", tmp), auth_mode_x)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "crypto", tmp), crypto)) different = 1;
    if (amas_nvram_diff_set_int(strcat_r(prefix, "wep_x", tmp), profile->wep_x)) different = 1;
    if (amas_nvram_diff_set_int(strcat_r(prefix, "mbss", tmp), profile->mbss)) different = 1;
    // if (amas_nvram_diff_set_int(strcat_r(prefix, "closed", tmp), profile->closed)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "key", tmp), profile->key)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "key1", tmp), profile->key1)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "key2", tmp), profile->key2)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "key3", tmp), profile->key3)) different = 1;
    if (amas_nvram_diff_set(strcat_r(prefix, "key4", tmp), profile->key4)) different = 1;

    /* Setting wlcX_*/
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "ssid", tmp), profile->ssid)) different = 1;
    //if (amas_nvram_diff_set_int(strcat_r(wlc_prefix, "bss_enabled", tmp), profile->bss_enabled)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "wpa_psk", tmp), profile->wpa_psk)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "auth_mode_x", tmp), auth_mode_x)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "crypto", tmp), crypto)) different = 1;
    if (amas_nvram_diff_set_int(strcat_r(wlc_prefix, "wep_x", tmp), profile->wep_x)) different = 1;
    if (amas_nvram_diff_set_int(strcat_r(wlc_prefix, "mbss", tmp), profile->mbss)) different = 1;
    // if (amas_nvram_diff_set_int(strcat_r(wlc_prefix, "closed", tmp), profile->closed)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "key", tmp), profile->key)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "key1", tmp), profile->key1)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "key2", tmp), profile->key2)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "key3", tmp), profile->key3)) different = 1;
    if (amas_nvram_diff_set(strcat_r(wlc_prefix, "key4", tmp), profile->key4)) different = 1;

    if (different) {
        apply_config_to_driver(unit);
        if (killall("amas_lanctrl", SIGUSR1) != 0) // Notify amas_lanctrl re-check wifi bss status.
            nvram_set_int("amas_recheck_bss", 1); // killall fail. Use nvram to trigger.
    }
    else
        WLC_DBG("BandIndex(%d) Connection parameters is the same. Don't need apply config.\n", bandindex);
}

/**
 * @brief Added new connection profile to profile linked list
 *
 * @param profile Be added connection profile
 * @return int Add result. 0: Success. non-zero: Fail
 */
static int amas_insert_profile(amas_ap_profile_s *profile)
{
    amas_ap_profile_s *profile_tmp = NULL;
    if (ap_profiles == NULL) {
        ap_profiles = profile;
    }
    else {
        profile_tmp = ap_profiles;
        while (profile_tmp) {
            if (profile_tmp->next == NULL) {
                profile_tmp->next = profile;
                break;
            }
            profile_tmp = profile_tmp->next;
        }
    }
    return 0;
}

/**
 * @brief Insertion sort for connection profile linked list
 *
 * @param tmp_head New be sorted head
 * @param new_profile Ready to be sorted connection profile
 */
static void amas_sorting_profiles_insert(amas_ap_profile_s** tmp_head, amas_ap_profile_s *new_profile)
{
    amas_ap_profile_s *curr;
    if (*tmp_head == NULL || (*tmp_head)->priority <= new_profile->priority) {
        new_profile->next = *tmp_head;
        *tmp_head = new_profile;
    } else {
        curr = *tmp_head;
        while (curr->next != NULL && curr->next->priority > new_profile->priority) {
            curr = curr->next;
        }
        new_profile->next = curr->next;
        curr->next = new_profile;
    }
}

/**
 * @brief Sorting connection profiles
 *
 * @param profiles Connection profile linked list
 * @return int Sorting result. 0: Success. non-zero: Fail
 */
static int amas_sorting_profiles(amas_ap_profile_s **profiles)
{
    // Sorting by priority
    amas_ap_profile_s *tmp = NULL;
    amas_ap_profile_s *curr = *profiles;

    while (curr != NULL)
    {
        struct amas_ap_profile_s *next = curr->next;
        amas_sorting_profiles_insert(&tmp, curr);
        curr = next;
    }
    *profiles = tmp;
    return 0;
}

/**
 * @brief Print connection profile linked list for debugging
 *
 * @param profiles Connection profile linked list
 */
static void amas_dump_profiles(amas_ap_profile_s *profiles)
{
    amas_ap_profile_s *tmp = profiles;
    dbg("Profiles:\n");
    while (tmp) {
        dbg("Band(%d)  SSID: [%s]  Priority[%d]\n", tmp->band, tmp->ssid, tmp->priority);
        tmp = tmp->next;
    }
}

/**
 * @brief Release connection profiles linked list memory
 *
 * @param profiles Connection profiles linked list
 */
static void amas_release_connection_profiles(amas_ap_profile_s **profiles)
{
    amas_ap_profile_s *tmp;

    while (*profiles != NULL) {
        tmp = *profiles;
        *profiles = (*profiles)->next;
        free(tmp);
    }
    *profiles = NULL;
}

/**
 * @brief Load connection relate nvram values to RAM
 *
 * @return int Load result. 0: Success. Non-zero: Fail
 */
static int amas_wlcconnect_load_connection_profile()
{
    json_object *root = NULL, *name_obj = NULL, *priority_obj = NULL, *bandindex_obj = NULL, *band_obj = NULL,
        *ssid_obj = NULL, *bss_enabled_obj = NULL, *wpa_psk_obj = NULL, *auth_mode_x_obj = NULL, *crypto_obj = NULL, *wep_x_obj = NULL,
        *mbss_obj = NULL, *closed_obj = NULL, *key_obj = NULL, *key1_obj = NULL, *key2_obj = NULL, *key3_obj = NULL, *key4_obj = NULL;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
    json_object *wds_obj = NULL;
#endif

    root = generate_connection_profile(AMAS_CONNECTION_PROFILE_LOCAL);
    if (!root) {
        dbg("root is NULL\n");
        return -1;
    }

    amas_release_connection_profiles(&ap_profiles);
    json_object_object_foreach(root, key, val) {

        WLC_DBG("ID[%s]:\n", key);
        json_object_object_get_ex(val, WLC_CONNECT_STR_PROFILE_NAME, &name_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_PROFILE_PRIORITY, &priority_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_BANDINDEX, &bandindex_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_BAND, &band_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_SSID, &ssid_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_BSS_ENABLED, &bss_enabled_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_WPAPSK, &wpa_psk_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_AUTH_MODE_X, &auth_mode_x_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_CRYPTO, &crypto_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_WEP_X, &wep_x_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_MBSS, &mbss_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_CLOSED, &closed_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_KEY, &key_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_KEY1, &key1_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_KEY2, &key2_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_KEY2, &key3_obj);
        json_object_object_get_ex(val, WLC_CONNECT_STR_KEY2, &key4_obj);
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
        json_object_object_get_ex(val, WLC_CONNECT_STR_WDS, &wds_obj);
#endif

        amas_ap_profile_s *profile = (amas_ap_profile_s *)calloc(1, sizeof(amas_ap_profile_s));
        profile->bandindex = json_object_get_int(bandindex_obj);
        profile->band = json_object_get_int(band_obj);
        profile->priority = json_object_get_int(priority_obj);
        profile->connection_fail = 0;

        strncpy(profile->ssid, json_object_get_string(ssid_obj), sizeof(profile->ssid));
        profile->bss_enabled = json_object_get_int(bss_enabled_obj);
        strncpy(profile->wpa_psk, json_object_get_string(wpa_psk_obj), sizeof(profile->wpa_psk));
        strncpy(profile->auth_mode_x, json_object_get_string(auth_mode_x_obj), sizeof(profile->auth_mode_x));
        strncpy(profile->crypto, json_object_get_string(crypto_obj), sizeof(profile->crypto));
        profile->wep_x = json_object_get_int(wep_x_obj);
        profile->mbss = json_object_get_int(mbss_obj);
        profile->closed = json_object_get_int(closed_obj);
        strncpy(profile->key, json_object_get_string(key_obj), sizeof(profile->key));
        strncpy(profile->key1, json_object_get_string(key1_obj), sizeof(profile->key1));
        strncpy(profile->key2, json_object_get_string(key2_obj), sizeof(profile->key2));
        strncpy(profile->key3, json_object_get_string(key3_obj), sizeof(profile->key3));
        strncpy(profile->key4, json_object_get_string(key4_obj), sizeof(profile->key4));
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
        profile->wds = json_object_get_int(wds_obj);
#endif
        profile->next = NULL;

        amas_insert_profile(profile);
    }

    json_object_put(root);

    amas_sorting_profiles(&ap_profiles);

    if (wlc_dbg) {
        amas_dump_profiles(ap_profiles);
    }

    return 0;
}

/**
 * @brief Release sitesurvey AP linked list memory
 *
 * @param ap_s Sitesurvey linked list
 */
static void amas_release_sitesurvey_ap(amas_sitesurvey_ap_s **ap_s)
{
    amas_sitesurvey_ap_s *tmp;

    while (*ap_s != NULL) {
        tmp = *ap_s;
        *ap_s = (*ap_s)->next;
        free(tmp);
    }
    *ap_s = NULL;
}

/**
 * @brief Check amas_ssd sitesurvey processing state
 *
 * @param wlc_list wlc_list Supported band index wlc array
 * @param sitesurvey_timeout Scan AP timeout value
 * @return int amas_ssd sitesurvey result. 0: Success. Non-zero: Fail
 */
static int amas_get_sitesurvey_result(amas_wlcconnect_bandindex_s *wlc_list, int *sitesurvey_timeout)
{
    int sitesurvey_result = AMAS_SITESURVEY_TIMEOUT;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
    int sitesurveying_counts = 0, success_count = 0, stop_count = 0, i;

    /* Calculate sitesurveying band index counts */
    i = 0;
    while (i < SUMband) {
        if ((wlc_list+i)->sitesurveying)
            sitesurveying_counts++;
        i++;
    }

    /* Checking site survey status. */
    WLC_DBG("SiteSurvey timeout: %d\n", *sitesurvey_timeout);
    while(*sitesurvey_timeout > 0) {
        i = 0;
        while (i < SUMband) {
            if ((wlc_list+i)->sitesurveying) {
                WLC_DBG("Checking BandIndex(%d) survey status\n", (wlc_list+i)->bandindex);
	            snprintf(prefix, sizeof(prefix), "amas_wlc%d_", (wlc_list+i)->bandindex);
                if (nvram_get_int(strcat_r(prefix, "ss_status", tmp)) == SS_STATUS_FINISHED) {
                    success_count++;
                    (wlc_list+i)->sitesurveying = 0;
                }
                else if (nvram_get_int(strcat_r(prefix, "ss_status", tmp)) == SS_STATUS_CANCELED) {
                    stop_count++;
                    (wlc_list+i)->sitesurveying = 0;
                }
                WLC_DBG("wlc_list[%d]: sitesurveying[%d]\tSurveyStatus[%d]\n", i, (wlc_list+i)->sitesurveying, nvram_get_int(strcat_r(prefix, "ss_status", tmp)));
            }
            i++;
        }
        if (success_count == sitesurveying_counts) {
            sitesurvey_result = AMAS_SITESURVEY_SUCCESS;
            break;
        }
        else if (stop_count == sitesurveying_counts) {
            sitesurvey_result = AMAS_SITESURVEY_UNEXPECTED_ERROR;
            break;
        }
        else if ((success_count+stop_count) >= sitesurveying_counts) {
            sitesurvey_result = AMAS_SITESURVEY_UNEXPECTED_ERROR;
            break;
        }
        else
            *sitesurvey_timeout = (*sitesurvey_timeout) - 1;
        WLC_DBG("SiteSurveying counts[%d]\tSuccess counts[%d]\tStop counts[%d]\n", sitesurveying_counts, success_count, stop_count);
        sleep(1);
    }
    WLC_DBG("SiteSurveying counts[%d]\tSuccess counts[%d]\tStop counts[%d]\n", sitesurveying_counts, success_count, stop_count);
    return sitesurvey_result;
}

/**
 * @brief Check if the AP with the band exists in the sitesurvey result
 *
 * @param band Band index
 * @return int Exist or not. 1: Exist. 0: Isn't exist.
 */
static int amas_chk_band_ap_in_sitesurvey_result(int band)
{
    if (sitesurvey_ap == NULL)
        return 0;

    amas_sitesurvey_ap_s *tmp = sitesurvey_ap;
    while (tmp) {
        if (tmp->band == band)
            return 1;
        tmp = tmp->next;
    }
    return 0;
}

/**
 * @brief Check WLC connection state
 *
 * @param bandindex band index
 * @return int Connection state. 1: Connected 0: Disconnected
 */
static int amas_chk_connection(int bandindex)
{
    char amas_wlc_state[] = "amas_wlcXXX_state";

    snprintf(amas_wlc_state, sizeof(amas_wlc_state),"amas_wlc%d_state", bandindex);
    if (nvram_get_int(amas_wlc_state) == WLC_STATE_CONNECTED)
        return 1;

    return 0;
}

static char* amas_get_wlc_pap(int bandindex)
{
    char amas_wlc_pap[] = "amas_wlcXXX_pap";

    /* Get current P-AP's BSSID */
    snprintf(amas_wlc_pap, sizeof(amas_wlc_pap), "amas_wlc%d_pap", bandindex);
    return nvram_safe_get(amas_wlc_pap);
}

enum { MANUAL_MODE_NOT_FOUND = 0,
       MANUAL_MODE_FOUND_BUT_NOT_THE_PROFILE = 1,
       MANUAL_MODE_FOUND_AND_IS_THE_PROFILE = 2 };

/**
 * @brief Is new AP better than connected AP currently
 *
 * @param bandindex band index
 * @return int Better or not. 1: New is Better. non-1: New isn't better
 */
static int amas_is_new_better_curr(int bandindex)
{
    char amas_wlc_pap[] = "amas_wlcXXX_pap", amas_wlc_rssi[] = "amas_wlcXXX_rssi",
         amas_wlc_cost[] = "amas_wlcXXX_cost";
    char wlc_ssid[] = "wlcXXX_ssid", tmp[64] = {};
    char amas_wlc_prefix[] = "amas_wlcXXXXXXXX";
    amas_sitesurvey_ap_s *ss_ap;
    int band = get_band_by_index(bandindex);

    int found_ap = 0, good_ap_rssi_threshold;
    int manual_ap_exist = 0;

    snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", bandindex);
    good_ap_rssi_threshold = nvram_get_int(strcat_r(amas_wlc_prefix, "good_ap_rssi_threshold", tmp)) ? : AMAS_GOOD_AP_RSSI_THRESHOLD;

    /* Get current P-AP's BSSID */
    snprintf(amas_wlc_pap, sizeof(amas_wlc_pap), "amas_wlc%d_pap", bandindex);
    /* Get current P-AP's SSID */
    snprintf(wlc_ssid, sizeof(wlc_ssid), "wlc%d_ssid", bandindex);
    /* Get current P-AP's RSSI */
    snprintf(amas_wlc_rssi, sizeof(amas_wlc_rssi), "amas_wlc%d_rssi", bandindex);
    /* Get current P-AP's Cost */
    snprintf(amas_wlc_cost, sizeof(amas_wlc_cost), "amas_wlc%d_cost", bandindex);

    // Checking is current AP is prefer AP
    ss_ap = sitesurvey_ap;
    while (ss_ap) {
        if (ss_ap->manual_mode == 1) {
            manual_ap_exist = 1;
            if (ss_ap->band == band) {
                if (!strcmp(ss_ap->bssid, nvram_safe_get(amas_wlc_pap))) {
                    manual_ap_exist = 2;
                    found_ap = 1;
                    break;
                }
            } else if (band == WL5G1_U || band == WL5G2_U) {
                if (ss_ap->band == WL5G1_U || ss_ap->band == WL5G2_U) {
                    if (!strcmp(ss_ap->bssid, nvram_safe_get(amas_wlc_pap))) {
                        manual_ap_exist = 2;
                        found_ap = 1;
                        break;
                    }
                }
            }
        }
        ss_ap = ss_ap->next;
    }
    if (manual_ap_exist == 1) {
        WLC_DBG("BandIndex(%d) Current AP is not manual AP in sitesurvey result. Try to connect to manual AP.\n", bandindex);
        return 1;
    }
    if (manual_ap_exist != 2) {
        // Find the best AP.
        ss_ap = sitesurvey_ap;
        found_ap = 0;
        while (ss_ap) {
            if (ss_ap->bandindex == bandindex) {
                /* Check is the AP is GOOD? Condition is RSSI >= good_ap_rssi_threshold */
                if (ss_ap->rssi >= good_ap_rssi_threshold) {
                    found_ap = 1;
                    break;
                } else {
                    found_ap = 0;
                    WLC_DBG("BandIndex(%d) The top AP RSSI(%d) < GOOD AP RSSI threshold(%d) to compare to current AP.\n",
                            bandindex, ss_ap->rssi, good_ap_rssi_threshold);
                    break;
                }
            }
            ss_ap = ss_ap->next;
        }
    }
    if (!found_ap) {
        WLC_DBG("BandIndex(%d) No AP to compare to current AP.\n", bandindex);
        return 0;
    }
    WLC_DBG("BandIndex(%d) Using AP(%s) to compare to current AP.\n", bandindex, ss_ap->bssid);

    /* Is the Current AP same as New AP */
    if (!strcmp(ss_ap->bssid, nvram_safe_get(amas_wlc_pap))) {
        WLC_DBG("The band(%d) New AP's BSSID(%s) is same as current AP's BSSID(%s).\n", bandindex, ss_ap->bssid, nvram_safe_get(amas_wlc_pap));
        return 0;  // New = Curr
    }
    if (nvram_get_int(amas_wlc_cost) <= (ss_ap->cost.cost * 10)) {  // Current AP is better.
        WLC_DBG("The band(%d) Current AP's cost(%d) <= New AP's cost(%f). Keep connection.\n", bandindex, nvram_get_int(amas_wlc_cost), ss_ap->cost.cost * 10);
        return 0;
    } else {  // New AP is better
        WLC_DBG("The band(%d) Current AP's cost(%d) > New AP's cost(%f). Re-connect.\n", bandindex, nvram_get_int(amas_wlc_cost), ss_ap->cost.cost * 10);
        return 1;
    }
    WLC_DBG("BandIndex(%d) Not find any good new AP. Keep connection.\n", bandindex);
    return 0;
}

/**
 * @brief Reset connection profiles parameter "connection_fail"
 *
 */
static void amas_reset_profile_connection_fail(void)
{
    amas_ap_profile_s *profile = ap_profiles;
    while (profile) {
        profile->connection_fail = 0;
        profile = profile->next;
    }
}

/**
 * @brief Set RSSI score to nvram "amas_wlcX_rssiscore"
 *
 * @param bandindex band index
 * @param reset_mode 1: reset the nvram "amas_wlcX_rssiscore". Non-1: Set the nvram "amas_wlcX_rssiscore"
 */
static void amas_update_wlc_RSSIscore(int bandindex, int reset_mode)
{
    char pap_bssid_nvram[] = "amas_wlcXXX_pap";
    char amas_wlc_rssiscore[] = "amas_wlcXXX_rssiscore";
    amas_sitesurvey_ap_s *ss_ap = sitesurvey_ap;

    /* Get Connected BSSID */
    snprintf(pap_bssid_nvram, sizeof(pap_bssid_nvram), "amas_wlc%d_pap", bandindex);
    snprintf(amas_wlc_rssiscore, sizeof(amas_wlc_rssiscore), "amas_wlc%d_rssiscore", bandindex);

    if (reset_mode) {
        nvram_set_int(amas_wlc_rssiscore, 100); // 0: Not RSSI score info.
        return;
    }

    /* Find the BSSID in sitesurvey result & Setting */
    while (ss_ap) {
        if (!strcmp(ss_ap->bssid, nvram_safe_get(pap_bssid_nvram))) {
            nvram_set_int(amas_wlc_rssiscore, ss_ap->RSSIscore);
            return;
        }
        ss_ap = ss_ap->next;
    }
    nvram_set_int(amas_wlc_rssiscore, 100); // 100: Not RSSI score info.
    return;
}

/**
 * @brief Reset amas_wlcX_rssiscore value
 *
 * @param mode Reset condition. 0: Reset all band. 1: Reset disconnect band.
 */
static void amas_reset_wlc_RSSIscore(int mode)
{
    int i = 0;

    if (mode == 0) { // Reset all amas_wlcX_rssiscore
        i = SUMband;
        while (i) {
            amas_update_wlc_RSSIscore(i-1, 1);
            i--;
        }
        return;
    } else if (mode == 1) { // Reset all disconnect band amas_wlcX_rssiscore
        i = SUMband;
        char amas_wlc_state[] = "amas_wlcXXX_state";
        while (i) {
            snprintf(amas_wlc_state, sizeof(amas_wlc_state), "amas_wlc%d_state", i-1);
            if (nvram_get_int(amas_wlc_state) != WLC_STATE_CONNECTED) {
                amas_update_wlc_RSSIscore(i-1, 1);
            }
            i--;
        }
        return;
    }
    WLC_DBG("Mode setting error. Skip doing anything\n", mode);
}

/**
 * @brief Do connect to AP process
 *
 * @param band band index
 * @param target_bssid Specify a specific target AP
 * @return int Connection state. 0: Connected. Non-zero: Fail.
 */
static int amas_connect_to_ap(amas_wlcconnect_bandindex_s *wlc, char *target_bssid)
{
    char wlc_prefix[] = "wlcXXXXXXXXXX", amas_wlc_prefix[] = "amas_wlcXXXXXXXX";
    char amas_wlc_state[] = "amas_wlcXXX_state";
    int i, use_only_ssid = 0;
    amas_ap_profile_s *profile = NULL;
    amas_sitesurvey_ap_s *ss_ap = NULL;
    int target_ap_mode = 0;
    int dwb_mode = nvram_get_int("dwb_mode");
    int bandindex = wlc->bandindex;
    int band = get_band_by_index(bandindex);
    int manual_mode = 0;
    int unit = wlc->unit;

    if (target_bssid != NULL)
        target_ap_mode = 1;

    snprintf(wlc_prefix, sizeof(wlc_prefix), "wlc%d_", bandindex);
    snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", bandindex);
    snprintf(amas_wlc_state, sizeof(amas_wlc_state), "amas_wlc%d_state", bandindex);

    int conn_timeout = conn_timeout_reflist[bandindex];
    int profile_timeout = profile_timeout_reflist[bandindex];

    while (conn_timeout) {
        /* Get AP profile SSID */
        if (target_ap_mode) {
            profile = ap_profiles;
            while (profile) {
                if (!profile->connection_fail && profile->band == band) {
                    break;
                } else if (!profile->connection_fail && profile->band != band) {
                    if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                        if (band == WL5G1_U || band == WL5G2_U) {
                            if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                break;
                            }
                        }
                    }
                }
                profile = profile->next;
            }
            if (profile == NULL) {
                WLC_DBG("No Connection Profile can be used!!! Stop Connection Process.\n");
                goto AMAS_CONNECT_TO_AP_EXIT;
            }
        } else {
            // Check Prefer AP
            ss_ap = sitesurvey_ap;
            while (ss_ap) {
                if (ss_ap->manual_mode) {
                    if (ss_ap->band == band && ss_ap->connected == 0) {
                        manual_mode = 1;
                        break;
                    }
                }
                ss_ap = ss_ap->next;
            }
            if (manual_mode) {
                if (ss_ap == NULL) {
                    WLC_DBG("No more Prefer AP can be connected!!! Stop Connection Process.\n");
                    goto AMAS_CONNECT_TO_AP_EXIT;
                }
                profile = ap_profiles;
                while (profile) {
                    if (profile->band == band) {
                        if (!strcmp(ss_ap->ssid, profile->ssid)) {
                            break;
                        }
                    } else if (!profile->connection_fail && profile->band != band) {
                        if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                            if (band == WL5G1_U || band == WL5G2_U) {
                                if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                    if (!strcmp(ss_ap->ssid, profile->ssid)) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    profile = profile->next;
                }
            } else {
                // Found the best AP.
                ss_ap = sitesurvey_ap;
                while (ss_ap) {
                    if (ss_ap->band == band && ss_ap->connected == 1) {
                        WLC_DBG("Band(%s) Connected to the first AP. But fail. Exit!!!\n", get_band_string_by_index(ss_ap->bandindex));
                        goto AMAS_CONNECT_TO_AP_EXIT;
                    } else if (ss_ap->band == band && ss_ap->connected == 0) {
                        break;
                    }
                    ss_ap = ss_ap->next;
                }
                if (ss_ap == NULL) {
                    use_only_ssid = 1;
                } else {
                    profile = ap_profiles;
                    while (profile) {
                        if (profile->band == band) {
                            if (!strcmp(ss_ap->ssid, profile->ssid)) {
                                break;
                            }
                        } else {
                            if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                                if (band == WL5G1_U || band == WL5G2_U) {
                                    if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                        if (!strcmp(ss_ap->ssid, profile->ssid)) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        profile = profile->next;
                    }
                }
                if (profile == NULL)
                    use_only_ssid = 1;

                if (use_only_ssid) {
                    profile = ap_profiles;
                    while (profile) {
                        if (profile->band == band) {
                            if (!profile->connection_fail)
                                break;
                        } else {
                            if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                                if (band == WL5G1_U || band == WL5G2_U) {
                                    if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                        if (!profile->connection_fail) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        profile = profile->next;
                    }
                    if (profile == NULL) {
                        WLC_DBG("No Connection Profile can be used!!! Stop Connection Process.\n");
                        goto AMAS_CONNECT_TO_AP_EXIT;
                    }
                }
            }
        }
        if (target_ap_mode)
            WLC_RUNTIME_LOG("Ready to connect to AP(%s). SSID: %s. Connection timeout: %d seconds. Switch profile timeout: %d\n", target_bssid, profile->ssid, conn_timeout, profile_timeout);
        else if (use_only_ssid)
            WLC_RUNTIME_LOG("Ready to connect to AP(NULL). SSID: %s. Connection timeout: %d seconds. Switch profile timeout: %d\n", profile->ssid, conn_timeout, profile_timeout);
        else
            WLC_RUNTIME_LOG("Ready to connect to AP(%s). SSID: %s. Connection timeout: %d seconds. Switch profile timeout: %d\n", ss_ap->bssid, profile->ssid, conn_timeout, profile_timeout);

        /* Be sure the band is be stopped. */
        WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Stop connection.\n", getpid(), bandindex, unit);
        Pty_stop_wlc_connect(unit);
        amas_update_wlc_RSSIscore(bandindex, 1);

        int amas_status_timer = (nvram_get_int("amas_status_timer") ? : 2) + 1;
        do {
            if (!amas_chk_connection(bandindex))
                break;
            sleep(1);
            amas_status_timer--;
        } while (amas_status_timer > 0);

        /* Setting NVRAM for connection */
        amas_setting_nvram_for_connection(profile, bandindex, unit);

        if (waitting_dfs_cac(wlc) < 0)
            WLC_DBG("PID(%d) band(%d) Waitting DFS CAC timeout.!!\n", getpid(), band);

        if (target_ap_mode) {
            WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Trigger start to connection. BSSID: %s\n", getpid(), bandindex, unit, target_bssid);
            Pty_start_wlc_connect(unit, target_bssid);
        } else {
            if (use_only_ssid) {
                WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Trigger start to connection. BSSID: NULL\n", getpid(), bandindex, unit);
                Pty_start_wlc_connect(unit, NULL);
            } else {
                ss_ap->connected = 1;
                WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Trigger start to connection. BSSID: %s\n", getpid(), bandindex, unit, ss_ap->bssid);
                Pty_start_wlc_connect(unit, ss_ap->bssid);
            }
        }

        if (ss_ap)
            alg_update_connecting_cost_to_nvram(bandindex, ss_ap->cost.cost);
        else
            alg_update_connecting_cost_to_nvram(bandindex, -1);

        i = profile_timeout;
        while (i && conn_timeout) {
            sleep(1);
            int wlc_state = nvram_get_int(amas_wlc_state);
            WLC_DBG("Connection Time: %d, Switch Profile Time: %d, Band(%s) Status: %d\n", conn_timeout, i, get_band_string_by_index(bandindex), wlc_state);
            if (wlc_state == WLC_STATE_CONNECTED) {
                amas_reset_profile_connection_fail();  // Reset all profile connection_fail.
                amas_update_wlc_RSSIscore(bandindex, 0);
                post_wlc_connected(unit);
                alg_clean_connecting_cost_to_nvram(bandindex);
                return 0;  // Success.
            } else if (wlc_state == WLC_STATE_STOPPED) {
                if ((profile_timeout - i) > 10) {  // 10 seconds buffer for STOP.
                    WLC_DBG("Driver is stopping to connect. Change next profile or AP.\n");
                    break;  // Fail. Ready to switch other profile.
                }
            }
            i--;
            conn_timeout--;
        }
        profile->connection_fail = AMAS_WLCCONNECT_CONNECTION_FAIL;
    }

AMAS_CONNECT_TO_AP_EXIT:
    /* Connect time out */
    WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Stop connection.\n", getpid(), bandindex, unit);
    Pty_stop_wlc_connect(unit);            // Fail. Ready to switch other band.
    amas_reset_profile_connection_fail();  // Reset all profile connection_fail.
    amas_update_wlc_RSSIscore(bandindex, 1);
    alg_clean_connecting_cost_to_nvram(bandindex);

    return -1;
}

/**
 * @brief Print wlc_list array info for debugging
 *
 * @param wlc_list wlc_list struct array
 */
static void amas_dump_wlc_list(amas_wlcconnect_bandindex_s *wlc_list)
{
    int i = 0;
    dbg("wlc_list:\n");
    while (i < SUMband) {
        dbg("wlc_list[%d]:  BandIndex[%d]  Use[%d]  Action[%d]  SiteSurveying[%d]  Priority[%d]  Try_Count[%d]\n",
         i, (wlc_list+i)->bandindex, (wlc_list+i)->use, (wlc_list+i)->action, (wlc_list+i)->sitesurveying, (wlc_list+i)->priority, (wlc_list+i)->try_count);
        i++;
    }
}

/**
 * @brief Swap two wlc struct variable
 *
 * @param wlc_list_1 Wlc1 struct variable
 * @param wlc_list_2 Wlc2 struct variable
 */
static void swap_wlc_list(amas_wlcconnect_bandindex_s *wlc_list_1, amas_wlcconnect_bandindex_s *wlc_list_2)
{
    amas_wlcconnect_bandindex_s *wlc_list_tmp = (amas_wlcconnect_bandindex_s*)calloc(1, sizeof(amas_wlcconnect_bandindex_s));

    if (wlc_list_tmp == NULL)
        return;

    memcpy(wlc_list_tmp, wlc_list_1, sizeof(amas_wlcconnect_bandindex_s));
    memcpy(wlc_list_1, wlc_list_2, sizeof(amas_wlcconnect_bandindex_s));
    memcpy(wlc_list_2, wlc_list_tmp, sizeof(amas_wlcconnect_bandindex_s));
    free(wlc_list_tmp);
}

/**
 * @brief Create wlc_list array.
 *
 * @param wlc_active Using band index bitmap
 * @param wlc_action Action band index bitmap in this action mode
 * @param wlc_list wlc_list global pointer variable
 * @return int Using band index count
 */
static int amas_wlc_list_init(unsigned int wlc_active, unsigned int wlc_action, amas_wlcconnect_bandindex_s *wlc_list)
{
    int i = 0, j;
    int wlc_use_count = 0;
    char amas_wlcX_buf[32] = {};

    /* Find which band need to connect. */
    while (i < SUMband) {
        (wlc_list+i)->bandindex = i;

        if (wlc_active & (1 << (4 * ((i / 4) + 1) + i))) {
            (wlc_list + i)->use = 1;
            wlc_use_count++;
        } else {
            (wlc_list + i)->use = 0;
        }

        if (wlc_action & (1 << (4 * ((i / 4) + 1) + i)))
            (wlc_list + i)->action = 1;
        else
            (wlc_list + i)->action = 0;

        (wlc_list+i)->sitesurveying = 0;
        snprintf(amas_wlcX_buf, sizeof(amas_wlcX_buf), "amas_wlc%d_priority", i);
        (wlc_list+i)->priority = nvram_get_int(amas_wlcX_buf);

        (wlc_list+i)->try_count = 0;
        (wlc_list+i)->dfs_status = 0;
        (wlc_list+i)->dfs_waitting_time = 0;

        snprintf(amas_wlcX_buf, sizeof(amas_wlcX_buf), "amas_wlc%d_unit", i);
        (wlc_list+i)->unit = nvram_get_int(amas_wlcX_buf);
        i++;
    }

    /* Sorted by priority */
    /* bubble sort. */
    for (i = 0; i < SUMband; i++) {
        for (j = i+1; j < SUMband; j++) {
            if ((wlc_list+i)->priority > (wlc_list+j)->priority) {
                swap_wlc_list(wlc_list+i, wlc_list+j);
            }
        }
    }

    if (wlc_dbg) {
        amas_dump_wlc_list(wlc_list);
    }

    return wlc_use_count; // use wlc count.
}

/**
 * @brief Disconnect No use band index
 *
 * @param wlc_list Supported wlc_list array
 */
static void amas_disconnect_nouse_band(amas_wlcconnect_bandindex_s *wlc_list) {
    int i = 0;
    while (i < SUMband) {
        if ((wlc_list+i)->use == 0) {
            WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) Not USE. Disconnect it\n", (wlc_list+i)->bandindex, (wlc_list+i)->unit);
            Pty_stop_wlc_connect((wlc_list+i)->unit);
            amas_update_wlc_RSSIscore((wlc_list+i)->bandindex, 1);
        }
        i++;
    }
}

/**
 * @brief Disconnect No use or disconnected band index
 *
 * @param wlc_list All wlc band index info
 */
static void amas_disconnect_nouse_noconnected_band(amas_wlcconnect_bandindex_s *wlc_list) {
    int i = 0;
    while (i < SUMband) {
        if ((wlc_list+i)->use == 0 || !amas_chk_connection((wlc_list+i)->bandindex)) {
            WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) Not USE or No connected. Disconnect it\n", (wlc_list+i)->bandindex, (wlc_list+i)->unit);
            Pty_stop_wlc_connect((wlc_list+i)->unit);
            amas_update_wlc_RSSIscore((wlc_list+i)->bandindex, 1);
        }
        i++;
    }
}

/**
 * @brief Disconnect all band
 *
 */
static void amas_disconnect_all_connection(void) {
    int i = 0;
    int unit;
    char amas_wlc_unit[] = "amas_wlcXXX_unit";

    WLC_DBG("Disconnecting all wlc connection.\n");
    while(i < SUMband) {
        snprintf(amas_wlc_unit, sizeof(amas_wlc_unit), "amas_wlc%d_unit", i);
        unit = nvram_get_int(amas_wlc_unit);
        Pty_stop_wlc_connect(unit);
        WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) IS BE DISCONNECTED.\n", i, unit);
        amas_update_wlc_RSSIscore(i, 1);
        i++;
    }
}

/**
 * @brief Disconnect action band or no use band in this request.
 *
 * @param wlc_list All wlc band index info
 */
static void amas_disconnect_action_nouse_band_connection(amas_wlcconnect_bandindex_s *wlc_list) {
    int i = 0;
    while (i < SUMband) {
        if ((wlc_list+i)->use == 0 || (wlc_list+i)->action == 1) {
            WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) No use band or Action band. Disconnect it\n", (wlc_list+i)->bandindex, (wlc_list+i)->unit);
            Pty_stop_wlc_connect((wlc_list+i)->unit);
            amas_update_wlc_RSSIscore((wlc_list+i)->bandindex, 1);
        }
        i++;
    }
}

/**
 * @brief Processing AMAS_WLCCONNECT_ACTION_MODE_ACTION_CONNECTING_BY_DRIVER action mode.
 *
 * @param band Band index. (0,1,2)
 * @return int Connection result.(0: Disconnected. 1: Connected)
 */
static int amas_connect_to_ap_by_driver(int band) {
    char amas_wlc_state[] = "amas_wlcXXX_state";

    int conn_timeout = conn_timeout_reflist[band];
    snprintf(amas_wlc_state, sizeof(amas_wlc_state), "amas_wlc%d_state", band);

    while (conn_timeout) {
        if (nvram_get_int(amas_wlc_state) == WLC_STATE_CONNECTED)
            return 1;
        conn_timeout--;
        sleep(1);
    }
    return 0;
}

static int amas_connect_to_ap_concurrent(amas_wlcconnect_bandindex_s *wlc, char *target_bssid, int use_only_ssid, int conn_timeout, int profile_timeout) {
    char wlc_prefix[] = "wlcXXXXXXXXXX";
    char amas_wlc_state[] = "amas_wlcXXX_state";
    int i;
    amas_ap_profile_s *profile = NULL;
    amas_sitesurvey_ap_s *ss_ap = NULL;
    int target_ap_mode = 0;
    int dwb_mode = nvram_get_int("dwb_mode");
    int error_code = -1;
    int bandindex = wlc->bandindex;
    int band = get_band_by_index(bandindex);
    int manual_mode = 0;
    int unit = wlc->unit;

    if (target_bssid != NULL)
        target_ap_mode = 1;

    snprintf(wlc_prefix, sizeof(wlc_prefix), "wlc%d_", bandindex);
    snprintf(amas_wlc_state, sizeof(amas_wlc_state), "amas_wlc%d_state", bandindex);

    while (conn_timeout) {
        /* Get AP profile SSID */
        profile = ap_profiles;
        if (target_ap_mode) {
            profile = ap_profiles;
            while (profile) {
                if (!profile->connection_fail && profile->band == band) {
                    break;
                } else if (!profile->connection_fail && profile->band != band) {
                    if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                        if (band == WL5G1_U || band == WL5G2_U) {
                            if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                break;
                            }
                        }
                    }
                }
                profile = profile->next;
            }
            if (profile == NULL) {
                WLC_DBG("No Connection Profile can be used!!! Stop Connection Process.\n");
                goto AMAS_CONNECT_TO_AP_CONCURRENT_EXIT;
            }
        } else {
            // Check Prefer AP
            ss_ap = sitesurvey_ap;
            while (ss_ap) {
                if (ss_ap->manual_mode) {
                    if (ss_ap->band == band && ss_ap->connected == 0) {
                        manual_mode = 1;
                        break;
                    }
                }
                ss_ap = ss_ap->next;
            }
            if (manual_mode) {
                if (ss_ap == NULL) {
                    WLC_DBG("No more Prefer AP can be connected!!! Stop Connection Process.\n");
                    goto AMAS_CONNECT_TO_AP_CONCURRENT_EXIT;
                }
                profile = ap_profiles;
                while (profile) {
                    if (profile->band == band) {
                        if (!strcmp(ss_ap->ssid, profile->ssid)) {
                            break;
                        }
                    } else if (!profile->connection_fail && profile->band != band) {
                        if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                            if (band == WL5G1_U || band == WL5G2_U) {
                                if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                    if (!strcmp(ss_ap->ssid, profile->ssid)) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    profile = profile->next;
                }
            } else {
                // Found the best AP.
                ss_ap = sitesurvey_ap;
                while (ss_ap) {
                    if (ss_ap->band == band && ss_ap->connected == 1) {
                        WLC_DBG("Band(%s) Connected to the first AP. But fail. Exit!!!\n", get_band_string_by_index(ss_ap->bandindex));
                        goto AMAS_CONNECT_TO_AP_CONCURRENT_EXIT;
                    } else if (ss_ap->band == band && ss_ap->connected == 0) {
                        break;
                    }
                    ss_ap = ss_ap->next;
                }
                if (ss_ap == NULL) {
                    use_only_ssid = 1;
                } else {
                    profile = ap_profiles;
                    while (profile) {
                        if (profile->band == band) {
                            if (!strcmp(ss_ap->ssid, profile->ssid)) {
                                break;
                            }
                        } else {
                            if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                                if (band == WL5G1_U || band == WL5G2_U) {
                                    if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                        if (!strcmp(ss_ap->ssid, profile->ssid)) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        profile = profile->next;
                    }
                }
                if (profile == NULL)
                    use_only_ssid = 1;

                if (use_only_ssid) {
                    profile = ap_profiles;
                    while (profile) {
                        if (profile->band == band) {
                            if (!profile->connection_fail)
                                break;
                        } else {
                            if (dwb_mode == 1 || dwb_mode == 3) {  // DWB mode processing. If wlc is 5G or 5G-2, try to use other 5g band profile.
                                if (band == WL5G1_U || band == WL5G2_U) {
                                    if (profile->band == WL5G1_U || profile->band == WL5G2_U) {
                                        if (!profile->connection_fail) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        profile = profile->next;
                    }
                    if (profile == NULL) {
                        WLC_DBG("No Connection Profile can be used!!! Stop Connection Process.\n");
                        goto AMAS_CONNECT_TO_AP_CONCURRENT_EXIT;
                    }
                }
            }
        }
        if (target_ap_mode)
            WLC_RUNTIME_LOG("Ready to connect to AP(%s). SSID: %s. Connection timeout: %d seconds. Switch profile timeout: %d\n", target_bssid, profile->ssid, conn_timeout, profile_timeout);
        else if (use_only_ssid)
            WLC_RUNTIME_LOG("Ready to connect to AP(NULL). SSID: %s. Connection timeout: %d seconds. Switch profile timeout: %d\n", profile->ssid, conn_timeout, profile_timeout);
        else
            WLC_RUNTIME_LOG("Ready to connect to AP(%s). SSID: %s. Connection timeout: %d seconds. Switch profile timeout: %d\n", ss_ap->bssid, profile->ssid, conn_timeout, profile_timeout);

        /* Be sure the band is be stopped. */
        WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Stop connection.\n", getpid(), bandindex, unit);
        Pty_stop_wlc_connect(unit);
        amas_update_wlc_RSSIscore(bandindex, 1);

        int amas_status_timer = (nvram_get_int("amas_status_timer") ?: 2) + 1;
        do {
            if (!amas_chk_connection(bandindex))
                break;
            sleep(1);
            amas_status_timer--;
        } while (amas_status_timer > 0);

        /* Setting NVRAM for connection */
        amas_setting_nvram_for_connection(profile, bandindex, unit);

        if (waitting_dfs_cac(wlc) < 0)
            WLC_DBG("PID(%d) band(%d) Waitting DFS CAC timeout.!!\n", getpid(), band);

        if (target_ap_mode) {
            WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Trigger start to connection. BSSID: %s\n", getpid(), bandindex, unit, target_bssid);
            Pty_start_wlc_connect(unit, target_bssid);
        } else {
            if (use_only_ssid) {
                WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Trigger start to connection. BSSID: NULL\n", getpid(), bandindex, unit);
                Pty_start_wlc_connect(unit, NULL);
            } else {
                ss_ap->connected = 1;
                WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Trigger start to connection. BSSID: %s\n", getpid(), bandindex, unit, ss_ap->bssid);
                Pty_start_wlc_connect(unit, ss_ap->bssid);
            }
        }

        if (ss_ap)
            alg_update_connecting_cost_to_nvram(bandindex, ss_ap->cost.cost);
        else
            alg_update_connecting_cost_to_nvram(bandindex, -1);

        i = profile_timeout;
        while (i && conn_timeout) {
            sleep(1);
            int wlc_state = nvram_get_int(amas_wlc_state);
            WLC_DBG("Connection Time: %d, Switch Profile Time: %d, Band(%s) Status: %d\n", conn_timeout, i, get_band_string_by_index(bandindex), wlc_state);
            if (wlc_state == WLC_STATE_CONNECTED) {
                amas_reset_profile_connection_fail();  // Reset all profile connection_fail.
                amas_update_wlc_RSSIscore(bandindex, 0);
                post_wlc_connected(unit);
                alg_clean_connecting_cost_to_nvram(bandindex);
                return 0;  // Success.
            } else if (wlc_state == WLC_STATE_STOPPED) {
                if ((profile_timeout - i) > 10) {  // 10 seconds buffer for STOP.
                    WLC_DBG("Driver is stopping to connect. Change next profile or AP.\n");
                    break;  // Fail. Ready to switch other profile.
                }
            }
            i--;
            conn_timeout--;
        }
        profile->connection_fail = AMAS_WLCCONNECT_CONNECTION_FAIL;
    }

AMAS_CONNECT_TO_AP_CONCURRENT_EXIT:
    /* Connect time out */
    WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Stop connection.\n", getpid(), bandindex, unit);
    Pty_stop_wlc_connect(unit);       // Fail. Ready to switch other band.
    amas_reset_profile_connection_fail();  // Reset all profile connection_fail.
    amas_update_wlc_RSSIscore(bandindex, 1);
    alg_clean_connecting_cost_to_nvram(bandindex);

    return error_code;
}

static void release_start_connect_ap_fork(void)
{
    char amas_wlc_connection_pid[] = "amas_wlcXXX_connection_pid";
    int i, status;

    for (i = 0; i < SUMband; i++) { // Send SIGTERM to all child process.
        snprintf(amas_wlc_connection_pid, sizeof(amas_wlc_connection_pid), "amas_wlc%d_connection_pid", i);
        int pid_num = nvram_get_int(amas_wlc_connection_pid);
        if (pid_num > 0) {
            if (i == 0)
                sleep(1);
            kill(pid_num, SIGTERM);
        }
    }

    int wait_pre_handler = 10; // 10 seconds
    while (wait_pre_handler > 0) {
        int keep_wait = 0;
        for (i = 0; i < SUMband; i++) {  // Wait for all child exist.
            snprintf(amas_wlc_connection_pid, sizeof(amas_wlc_connection_pid),
                     "amas_wlc%d_connection_pid", i);
            int pid_num = nvram_get_int(amas_wlc_connection_pid);
            if (pid_num > 0) {
                int ret = waitpid(pid_num, &status, WNOHANG);
                if (ret == 0)  // Still alive
                    keep_wait = 1;
                else if (ret == -1) {
                    if (WIFEXITED(status) || WIFSIGNALED(status)) {  // exit
                        nvram_set_int(amas_wlc_connection_pid, 0);
                        update_amas_wlcconnect_connection_status(
                            i, AMAS_WLCCONNECT_STATUS_FINISHED);
                    } else
                        keep_wait = 1;
                } else {  // > 0 exit successfully.
                    nvram_set_int(amas_wlc_connection_pid, 0);
                    update_amas_wlcconnect_connection_status(
                        i, AMAS_WLCCONNECT_STATUS_FINISHED);
                }
            }
        }
        if (keep_wait == 0) break;  // all child exist.
        wait_pre_handler--;
        sleep(1);
    }
}

/**
 * @brief Close IPC socket
 *
 */
static void amas_close_ipc_socket() {
    if (amas_wlcconnect_ipc_socket >= 0) {
        shutdown(amas_wlcconnect_ipc_socket, SHUT_RDWR);
        close(amas_wlcconnect_ipc_socket);
    }
}

/**
 * @brief Release connection profile, sitesurvey result, etc... memory
 *
 * @param signum Received signal number
 */
static void amas_free_all_memory_exit(int signum)
{
    amas_release_connection_profiles(&ap_profiles);
    amas_release_sitesurvey_ap(&sitesurvey_ap);
    if (process_info.type == AMAS_WLC_PROCESS_MAIN) { // Only for main.
        amas_close_ipc_socket();
        WLC_RUNTIME_LOG("The amas_wlcconnect main is be terminal.\n");
    }
    else if (process_info.type == AMAS_WLC_PROCESS_REQUEST_HANDLER &&
        get_amas_wlcconnect_status() !=
            AMAS_WLCCONNECT_STATUS_READY_PROCESSING) {  // Ready do next
                                                        // request. So don't
                                                        // need to do update.
        update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_FINISHED);
        WLC_RUNTIME_LOG("The Request is be terminal.\n");
    } else
        WLC_RUNTIME_LOG("The Connection process is be terminal.\n");

    exit(0);
}

static int is_keep_connecting_band_connected()
{
    int i, ret = 0;
    char amas_wlc_keep_connecting[] = "amas_wlcXXX_keep_connecting";
    char amas_wlc_state[] = "amas_wlcXXX_state";

    for (i = 0; i < get_wl_count(); i++) {
        snprintf(amas_wlc_keep_connecting, sizeof(amas_wlc_keep_connecting), "amas_wlc%d_keep_connecting", i);
        snprintf(amas_wlc_state, sizeof(amas_wlc_state), "amas_wlc%d_state", i);

        if (nvram_get_int(amas_wlc_keep_connecting) == 1) {
            if (nvram_get_int(amas_wlc_state) == WLC_STATE_CONNECTED) {
                ret = 1;
                break;
            }
        }
    }

    return ret;
}

static int start_connect_ap(amas_wlcconnect_bandindex_s *wlc_list, int index, int action_mode) {
    int skip_ss = 0, use_only_ssid = 0;
    int res = 0;
    int sitesurvey_timeout, pre_sitesurvey_timeout, rescan_timeout;
    int scan_again;
    int success_but_no_ap = 0;
    int target_bssid_count = amas_get_target_bssid_counts((wlc_list + index)->bandindex);
    char amas_wlc_rescan_timeout[] = "amas_wlcXXX_rescan_timeout";
    snprintf(amas_wlc_rescan_timeout, sizeof(amas_wlc_rescan_timeout), "amas_wlc%d_rescan_timeout", (wlc_list + index)->bandindex);
    int amas_disable_ssid_connect = nvram_get_int("amas_disable_ssid_connect");
    char *target_bssid = NULL;
    char amas_wlc_keep_connecting[] = "amas_wlcXXX_keep_connecting";
    snprintf(amas_wlc_keep_connecting, sizeof(amas_wlc_keep_connecting), "amas_wlc%d_keep_connecting", (wlc_list + index)->bandindex);
    int keep_conn = nvram_get_int(amas_wlc_keep_connecting);
    char tmp[32] = {}, amas_wlc_prefix[] = "amas_wlcXXX_";
    snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", (wlc_list + index)->bandindex);

    int conn_timeout = conn_timeout_reflist[(wlc_list + index)->bandindex];
    int profile_timeout = profile_timeout_reflist[(wlc_list + index)->bandindex];

    if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_CONNECTING_BY_DRIVER) {
        res = amas_connect_to_ap_by_driver((wlc_list + index)->bandindex);
        return 0;
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_START) {
        profile_timeout = nvram_get_int(strcat_r(amas_wlc_prefix, "conn_ptimeout", tmp));
        if (profile_timeout < AMAS_CONNECTION_PROFILE_TIMEOUT) {
            if (profile_timeout != 0)
                WLC_RUNTIME_LOG("Profile switch Timeout value(%d) invalid!!!.\n", profile_timeout);
            profile_timeout = AMAS_CONNECTION_PROFILE_TIMEOUT;
        }

        if ((wlc_list + index)->action != 1) {
            WLC_DBG("BandIndex(%d) Action mode: START_CONNECTING. Action is 0. Don't do anything.\n", (wlc_list + index)->bandindex);
            return 0;
        }
        if (amas_chk_connection((wlc_list + index)->bandindex)) {
            WLC_DBG("BandIndex(%d) Action mode: START_CONNECTING. Connected.\n", (wlc_list + index)->bandindex);
            return 0;
        } else {
            WLC_RUNTIME_LOG("PID(%d) bandindex(%d) Stop connection.\n", getpid(), (wlc_list+index)->bandindex);
            Pty_stop_wlc_connect((wlc_list+index)->bandindex);  // Besure stop "The driver connecting by itself".
        }
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_RESTART) {
        profile_timeout = nvram_get_int(strcat_r(amas_wlc_prefix, "conn_ptimeout", tmp));
        if (profile_timeout < AMAS_CONNECTION_PROFILE_TIMEOUT) {
            if (profile_timeout != 0)
                WLC_RUNTIME_LOG("Profile switch Timeout value(%d) invalid!!!.\n", profile_timeout);
            profile_timeout = AMAS_CONNECTION_PROFILE_TIMEOUT;
        }
    }

    do {
        if (!skip_ss) {  // Do sitesurvey.
            amas_release_sitesurvey_ap(&sitesurvey_ap);
            sitesurvey_timeout = nvram_get_int("amas_sitesurvey_timeout") ?: AMAS_WLCCONNECT_SITESURVEY_TIMEOUT;
            rescan_timeout = nvram_get_int(amas_wlc_rescan_timeout) ?: sitesurvey_timeout;
            /* Trigger sitesurvey */
            do {
                if (waitting_dfs_cac(wlc_list + index) < 0)  // CAC
                    WLC_DBG("PID(%d) band(%d) Waitting DFS CAC timeout.!!\n", getpid(), (wlc_list + index)->bandindex);

                WLC_DBG("PID(%d) Triggering band(%d) site survey...\n", getpid(), (wlc_list + index)->bandindex);
                res = amas_trigger_sitesurvey((wlc_list + index)->bandindex);
                if (res) {
                    WLC_DBG("Trigger band(%d) site survey fail.\n", (wlc_list + index)->bandindex);
                    return -1;
                }
                (wlc_list + index)->sitesurveying = 1;

                pre_sitesurvey_timeout = sitesurvey_timeout;
                sleep(2);  // Waitting for amas_ssd doing sitesurvey and reduce the frequency of sitesurvying
                sitesurvey_timeout = sitesurvey_timeout - 2;
                /* Check Site Survey Status */
                if ((res = amas_get_sitesurvey_result(wlc_list, &sitesurvey_timeout)) != AMAS_SITESURVEY_SUCCESS) {
                    switch (res) {
                        case AMAS_SITESURVEY_TIMEOUT:
                            nvram_set_int("amas_wlcconnect_result", AMAS_WLCCONNECT_SITESURVEY_FAIL);
                            WLC_DBG("Get site survey result timeout.\n");
                            break;

                        default:
                            nvram_set_int("amas_wlcconnect_result", AMAS_WLCCONNECT_SITESURVEY_FAIL);
                            WLC_DBG("Get site survey result fail.\n");
                            break;
                    }
                    amas_cancel_sitesurvey(wlc_list);
                    if (res == AMAS_SITESURVEY_TIMEOUT && success_but_no_ap) {
                        WLC_DBG("Timeout and doesn't scan any AP. Ready to use SSID to connect to AP.\n");
                        if (!waitting_ssd_exit((wlc_list + index)->bandindex)) {
                            snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", (wlc_list + index)->bandindex);
                            WLC_RUNTIME_LOG("BandIndex(%d) amas_ssd doesn't exit, force kill amas_ssd(%d)\n",
                                (wlc_list + index)->bandindex, nvram_get_int(strcat_r(amas_wlc_prefix, "ss_pid", tmp)));
                            kill(nvram_get_int(strcat_r(amas_wlc_prefix, "ss_pid", tmp)), SIGKILL);
                            return -1;
                        }
                    }
                    else
                        return -1;
                }
                /* Checking AP counts by sitesurvey */
                if (amas_dfs_status((wlc_list + index)->unit)) {  // Check CAC
                    scan_again = 1;
                    continue;  // Drop this result. and scan again.
                }
                scan_again = 0;
                if (amas_get_site_sitesurvey_result_counts((wlc_list + index)->bandindex) == 0 && target_bssid_count == 0) {
                    if (success_but_no_ap) {
                        rescan_timeout = rescan_timeout - (pre_sitesurvey_timeout - sitesurvey_timeout);
                    }
                    if (sitesurvey_timeout <= 0 || rescan_timeout <= 0) {
                        WLC_DBG("SiteSurvey timeout <= 0 or Re-scan timeout <= 0. Give up scanning again.\n");
                    } else {
                        WLC_DBG("SiteSurvey timeout: %d. Rescan timeout: %d. Scanning again.\n", sitesurvey_timeout, rescan_timeout);
                        success_but_no_ap = 1;
                        scan_again = 1;
                    }
                }
            } while (scan_again);

            /* Load Site Survey result. */
            res = amas_wlcconnect_load_sitesurvey_result((wlc_list + index)->bandindex, (wlc_list + index)->unit);
            if (res) {
                WLC_DBG("Load band(%d) unit(%d) site survey result fail.\n", (wlc_list + index)->bandindex, (wlc_list + index)->unit);
                if (amas_disable_ssid_connect == 1)
                    return -1;
            }
            WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) Scanned AP\n", (wlc_list + index)->bandindex, (wlc_list + index)->unit);
        }
        res = amas_connect_to_ap_concurrent((wlc_list + index), target_bssid, use_only_ssid, conn_timeout, profile_timeout);
        if (res != 0) {  // Not connected
            WLC_DBG("BandIndex(%d) Unit(%d) Conenction Fail.\n", (wlc_list + index)->bandindex, (wlc_list + index)->unit);
            if (keep_conn == 1 || is_keep_connecting_band_connected() == 0)
                update_amas_wlcconnect_connection_status((wlc_list + index)->bandindex, AMAS_WLCCONNECT_STATUS_KEEP_PROCESSING);
            else
                break;
        } else {  // Connected
            WLC_DBG("BandIndex(%d) Unit(%d) Connected.\n", (wlc_list + index)->bandindex, (wlc_list + index)->unit);
            break;
        }
    } while (1);

    if (target_bssid)
        free(target_bssid);

    return 0;
}

/**
 * @brief For ACTION_START_FOLLOW_CONNECTION
 *
 * @param wlc_list STA info.
 * @param action_mode Action mode.
 */
static void start_follow_connect(amas_wlcconnect_bandindex_s *wlc_list, int action_mode) {
    int i = 0, ret;
    char amas_wlc_target_same_ap[] = "amas_wlcXXX_target_same_ap", *target_bssid = NULL;
    update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING);
    while (i < SUMband) {
        // if (amas_chk_connection((wlc_list + i)->bandindex)) {
        if ((wlc_list + i)->action == 1) {
            snprintf(amas_wlc_target_same_ap, sizeof(amas_wlc_target_same_ap), "amas_wlc%d_target_same_ap", (wlc_list + i)->bandindex);
            target_bssid = strdup(nvram_safe_get(amas_wlc_target_same_ap));
            if (target_bssid && strlen(target_bssid) == 17) {
                if (strcmp(target_bssid, amas_get_wlc_pap((wlc_list + i)->bandindex))) {
                    ret = amas_connect_to_ap(wlc_list + i, target_bssid);
                    if (ret == 0)
                        WLC_DBG("Band(%d) Connect to AP(%s) Success.\n", (wlc_list + i)->bandindex, target_bssid);
                    else
                        WLC_DBG("Band(%d) Connect to AP(%s) Fail.\n", (wlc_list + i)->bandindex, target_bssid);
                }
            }
            if (target_bssid)
                free(target_bssid);
        }
        i++;
    }
}

/**
 * @brief Priority connection
 *
 * @param wlc_list WLC interface info
 * @param action_mode Action mode.
 */
static void start_opt_connect(amas_wlcconnect_bandindex_s *wlc_list, int action_mode) {
    int res = 0, i = 0, j = 0;
    char amas_wlc_rescan_timeout[] = "amas_wlcXXX_rescan_timeout";
    int amas_disable_ssid_connect = nvram_get_int("amas_disable_ssid_connect");
    int shift_index_5g = -1;
    int scan_again;
    int sitesurvey_timeout;
    int pre_sitesurvey_timeout;
    int success_but_no_ap, target_bssid_count;
    int rescan_timeout;
    amas_wlcconnect_bandindex_s *wlc_list_5g = NULL;
    char tmp[32] = {}, amas_wlc_prefix[] = "amas_wlcXXX_";

    update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING);

    // find 5G STA index
    for (i = 0; i < SUMband; i++) {
        if ((wlc_list + i)->use == 0)
            continue;
        if (SUMband == 2) {
            if (get_band_by_index((wlc_list + i)->bandindex) == WL5G1_U)
                shift_index_5g = i;
        } else {
            if (get_band_by_index((wlc_list + i)->bandindex) == WL5G1_U)
                shift_index_5g = i;
            else if (get_band_by_index((wlc_list + i)->bandindex) == WL5G2_U)
                shift_index_5g = i;
        }
    }

    if (shift_index_5g >= 0) {  // Just Check 5G. And other band will follow 5G
        wlc_list_5g = wlc_list + shift_index_5g;
        sitesurvey_timeout = nvram_get_int("amas_sitesurvey_timeout") ?: AMAS_WLCCONNECT_SITESURVEY_TIMEOUT;
        success_but_no_ap = 0;
        target_bssid_count = amas_get_target_bssid_counts(wlc_list_5g->bandindex);
        snprintf(amas_wlc_rescan_timeout, sizeof(amas_wlc_rescan_timeout), "amas_wlc%d_rescan_timeout", wlc_list_5g->bandindex);
        rescan_timeout = nvram_get_int(amas_wlc_rescan_timeout) ?: sitesurvey_timeout;
        do {
            if (waitting_dfs_cac(wlc_list_5g) < 0)
                WLC_DBG("PID(%d) band(%d) Waitting DFS CAC timeout.!!\n", getpid(), wlc_list_5g->bandindex);

            res = amas_trigger_sitesurvey(wlc_list_5g->bandindex);
            if (res) {
                WLC_DBG("Trigger band(%d) site survey fail.\n", wlc_list_5g->bandindex);
                return;
            }
            wlc_list_5g->sitesurveying = 1;

            pre_sitesurvey_timeout = sitesurvey_timeout;
            sleep(2);  // Waitting for amas_ssd doing sitesurvey and reduce the frequency of sitesurvying
            sitesurvey_timeout = sitesurvey_timeout - 2;
            if ((res = amas_get_sitesurvey_result(wlc_list, &sitesurvey_timeout)) != AMAS_SITESURVEY_SUCCESS) {
                /* Cancel site survey */
                switch (res) {
                    case AMAS_SITESURVEY_TIMEOUT:
                        nvram_set_int("amas_wlcconnect_result", AMAS_WLCCONNECT_SITESURVEY_FAIL);
                        WLC_DBG("Get site survey result timeout.\n");
                        break;
                    default:
                        nvram_set_int("amas_wlcconnect_result", AMAS_WLCCONNECT_SITESURVEY_FAIL);
                        WLC_DBG("Get site survey result fail.\n");
                        break;
                }
                amas_cancel_sitesurvey(wlc_list);
                if (res == AMAS_SITESURVEY_TIMEOUT && success_but_no_ap) {
                    WLC_DBG("Timeout and doesn't scan any AP. Ready to use SSID to connect to AP.\n");
                    if (!waitting_ssd_exit(wlc_list_5g->bandindex)) {
                        snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", wlc_list_5g->bandindex);
                        WLC_RUNTIME_LOG("BandIndex(%d) amas_ssd doesn't exit, force kill amas_ssd(%d)\n",
                            wlc_list_5g->bandindex, nvram_get_int(strcat_r(amas_wlc_prefix, "ss_pid", tmp)));
                        kill(nvram_get_int(strcat_r(amas_wlc_prefix, "ss_pid", tmp)), SIGKILL);
                        return;
                    }
                } else {
                    return;
                }
            }
            /* Checking AP counts by sitesurvey */
            if (amas_dfs_status(wlc_list_5g->unit)) {  // Check CAC
                scan_again = 1;
                continue;  // Drop this result. and scan again.
            }
            scan_again = 0;
            if (amas_get_site_sitesurvey_result_counts(wlc_list_5g->bandindex) == 0 && target_bssid_count == 0) {
                if (success_but_no_ap) {
                    rescan_timeout = rescan_timeout - (pre_sitesurvey_timeout - sitesurvey_timeout);
                }
                if (sitesurvey_timeout <= 0 || rescan_timeout <= 0) {
                    WLC_DBG("SiteSurvey timeout <= 0 or Re-scan timeout <= 0. Give up scanning again.\n");
                } else {
                    WLC_DBG("SiteSurvey timeout: %d. Rescan timeout: %d. Scanning again.\n", sitesurvey_timeout, rescan_timeout);
                    success_but_no_ap = 1;
                    scan_again = 1;
                }
            }
        } while (scan_again);

        /* Load Site Survey result. */
        res = amas_wlcconnect_load_sitesurvey_result(wlc_list_5g->bandindex, wlc_list_5g->unit);
        if (res) {
            WLC_DBG("Load band(%d) site survey result fail.\n", wlc_list_5g->bandindex);
            if (amas_disable_ssid_connect == 1) {
                return;
            }
        }
        WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) Scanned AP\n", wlc_list_5g->bandindex, wlc_list_5g->unit);
        if (amas_chk_band_ap_in_sitesurvey_result(wlc_list_5g->bandindex) || amas_disable_ssid_connect != 1) {
            if (amas_disable_ssid_connect != 1)
                WLC_DBG("BandIndex(%d) Have APs in Site Survey result or Use SSID connect\n", wlc_list_5g->bandindex);
            else
                WLC_DBG("BandIndex(%d) Have APs in Site Survey result\n", wlc_list_5g->bandindex);

            WLC_DBG("The request is self optimization\n");
            if (amas_is_new_better_curr(wlc_list_5g->bandindex) > 0) {  // New is better than Current.
                WLC_RUNTIME_LOG("New AP is better than Current AP\n");
                wlc_list_5g->try_count++;
                if (!amas_connect_to_ap(wlc_list_5g, NULL)) {  // Connect the first band Success.
                    WLC_RUNTIME_LOG("BandIndex(%d) Connecting to AP(%s) success\n", wlc_list_5g->bandindex, amas_get_wlc_pap(wlc_list_5g->bandindex));
                } else {  // Connection fail.
                    WLC_RUNTIME_LOG("BandIndex(%d) Connection is fail\n", wlc_list_5g->bandindex);
                }
            } else {  // Same or Current is better than New.
                WLC_RUNTIME_LOG("Current AP is better than New AP or is same as New AP\n");
            }
        } else {
            WLC_RUNTIME_LOG("BandIndex(%d) Don't Have APs in Site Survey result. Exit.\n", wlc_list_5g->bandindex);
        }
    } else {
        i = 0;
        while (i < SUMband) {
            if ((wlc_list + i)->use == 0) {
                WLC_DBG("BandIndex(%d) Not use. Skip\n", (wlc_list + i)->bandindex);
                i++;
                continue;
            }

            WLC_RUNTIME_LOG("Start processing BandIndex(%d)\n", (wlc_list + i)->bandindex);
            /* Trigger Site Survey */
            amas_release_sitesurvey_ap(&sitesurvey_ap);
            sitesurvey_timeout = nvram_get_int("amas_sitesurvey_timeout") ?: AMAS_WLCCONNECT_SITESURVEY_TIMEOUT;
            success_but_no_ap = 0;
            target_bssid_count = amas_get_target_bssid_counts((wlc_list + i)->bandindex);
            snprintf(amas_wlc_rescan_timeout, sizeof(amas_wlc_rescan_timeout), "amas_wlc%d_rescan_timeout", (wlc_list + i)->bandindex);
            rescan_timeout = nvram_get_int(amas_wlc_rescan_timeout) ?: sitesurvey_timeout;
            WLC_RUNTIME_LOG("BandIndex(%d) Scanning AP\n", (wlc_list + i)->bandindex);
            do {
                if (waitting_dfs_cac(wlc_list + i) < 0)
                    WLC_DBG("PID(%d) band(%d) Waitting DFS CAC timeout.!!\n", getpid(), (wlc_list + i)->bandindex);

                res = amas_trigger_sitesurvey((wlc_list + i)->bandindex);
                if (res) {
                    WLC_DBG("Trigger band(%d) site survey fail.\n", (wlc_list + j)->bandindex);
                    return;
                }
                (wlc_list + i)->sitesurveying = 1;

                pre_sitesurvey_timeout = sitesurvey_timeout;
                sleep(2);  // Waitting for amas_ssd doing sitesurvey and reduce the frequency of sitesurvying
                sitesurvey_timeout = sitesurvey_timeout - 2;
                if ((res = amas_get_sitesurvey_result(wlc_list, &sitesurvey_timeout)) != AMAS_SITESURVEY_SUCCESS) {
                    /* Cancel site survey */
                    switch (res) {
                        case AMAS_SITESURVEY_TIMEOUT:
                            nvram_set_int("amas_wlcconnect_result", AMAS_WLCCONNECT_SITESURVEY_FAIL);
                            WLC_DBG("Get site survey result timeout.\n");
                            break;
                        default:
                            nvram_set_int("amas_wlcconnect_result", AMAS_WLCCONNECT_SITESURVEY_FAIL);
                            WLC_DBG("Get site survey result fail.\n");
                            break;
                    }
                    amas_cancel_sitesurvey(wlc_list);
                    if (res == AMAS_SITESURVEY_TIMEOUT && success_but_no_ap) {
                        WLC_DBG("Timeout and doesn't scan any AP. Ready to use SSID to connect to AP.\n");
                        if (!waitting_ssd_exit((wlc_list + i)->bandindex)) {
                            snprintf(amas_wlc_prefix, sizeof(amas_wlc_prefix), "amas_wlc%d_", (wlc_list + i)->bandindex);
                            WLC_RUNTIME_LOG("BandIndex(%d) amas_ssd doesn't exit, force kill amas_ssd(%d)\n",
                                (wlc_list + i)->bandindex, nvram_get_int(strcat_r(amas_wlc_prefix, "ss_pid", tmp)));
                            kill(nvram_get_int(strcat_r(amas_wlc_prefix, "ss_pid", tmp)), SIGKILL);
                            return;
                        }
                    } else {
                        return;
                    }
                }
                /* Checking AP counts by sitesurvey */
                if (amas_dfs_status((wlc_list + i)->bandindex)) {  // Check CAC
                    scan_again = 1;
                    continue;  // Drop this result. and scan again.
                }
                scan_again = 0;
                if (amas_get_site_sitesurvey_result_counts((wlc_list + i)->bandindex) == 0 && target_bssid_count == 0) {
                    if (success_but_no_ap) {
                        rescan_timeout = rescan_timeout - (pre_sitesurvey_timeout - sitesurvey_timeout);
                    }
                    if (sitesurvey_timeout <= 0 || rescan_timeout <= 0) {
                        WLC_DBG("SiteSurvey timeout <= 0 or Re-scan timeout <= 0. Give up scanning again.\n");
                    } else {
                        WLC_DBG("SiteSurvey timeout: %d. Rescan timeout: %d. Scanning again.\n", sitesurvey_timeout, rescan_timeout);
                        success_but_no_ap = 1;
                        scan_again = 1;
                    }
                }
            } while (scan_again);

            /* Load Site Survey result. */

            res = amas_wlcconnect_load_sitesurvey_result((wlc_list + i)->bandindex, (wlc_list + i)->unit);
            if (res) {
                WLC_DBG("Load band(%d) site survey result fail.\n", (wlc_list + i)->bandindex);
                if (amas_disable_ssid_connect == 1) {
                    return;
                }
            }

            WLC_RUNTIME_LOG("BandIndex(%d) Unit(%d) Scanned AP\n", (wlc_list + i)->bandindex, (wlc_list + i)->unit);

            /* Check first band AP in sitesurvey_ap */
            if (amas_chk_band_ap_in_sitesurvey_result((wlc_list + i)->bandindex) || amas_disable_ssid_connect != 1) {
                if (amas_disable_ssid_connect != 1)
                    WLC_DBG("BandIndex(%d) Have APs in Site Survey result or Use SSID connect\n", (wlc_list + i)->bandindex);
                else
                    WLC_DBG("BandIndex(%d) Have APs in Site Survey result\n", (wlc_list + i)->bandindex);

                WLC_DBG("The request is self optimization\n");
                if (amas_chk_connection((wlc_list + i)->bandindex)) {  // Connected.
                    WLC_DBG("Check BandIndex(%d) status: Connected\n", (wlc_list + i)->bandindex);
                    if (amas_is_new_better_curr((wlc_list + i)->bandindex) > 0) {  // New is better than Current.
                        WLC_RUNTIME_LOG("New AP is better than Current AP\n");
                        (wlc_list + i)->try_count++;
                        if (!amas_connect_to_ap((wlc_list + i), NULL)) {  // Connect the first band Success.
                            WLC_RUNTIME_LOG("BandIndex(%d) Connecting to AP(%s) success\n", (wlc_list + i)->bandindex, amas_get_wlc_pap((wlc_list + i)->bandindex));
                            i++;
                            continue;

                        } else {  // Connection fail.
                            WLC_RUNTIME_LOG("BandIndex(%d) Connection is fail\n", (wlc_list + i)->bandindex);
                            i++;
                            continue;
                        }
                    } else {  // Same or Current is better than New.
                        WLC_RUNTIME_LOG("Current AP is better than New AP or is same as New AP\n");
                        i++;
                        continue;
                    }
                }
            } else {
                WLC_RUNTIME_LOG("BandIndex(%d) Don't Have APs in Site Survey result\n", (wlc_list + i)->bandindex);
                if (amas_chk_connection((wlc_list + i)->bandindex)) {  // Connected.
                    WLC_RUNTIME_LOG("Check BandIndex(%d) status: Connected\n", (wlc_list + i)->bandindex);
                    i++;
                    continue;
                } else {  // Connection fail.
                    WLC_RUNTIME_LOG("Check BandIndex(%d) status: Connected\n", (wlc_list + i)->bandindex);
                    i++;
                    continue;
                }
            }
        }
    }
}

/**
 * @brief Currently connection
 *
 * @param wlc_list WLC interface info
 * @param action_mode Action mode.
 */
static void start_general_connect(amas_wlcconnect_bandindex_s *wlc_list, int action_mode) {
    pid_t pid = 0;
    char amas_wlc_connection_pid[] = "amas_wlcXXX_connection_pid";
    int processing_count = 0, i;
    /* Check action band */
    for (i = 0; i < SUMband; i++) {
        if ((wlc_list + i)->use == 0) {
            WLC_DBG("BandIndex(%d) Not use. Skip\n", (wlc_list + i)->bandindex);
            continue;
        }
        pid = fork();
        if (pid == 0) {                        // Child
            prctl(PR_SET_PDEATHSIG, SIGTERM);  // Parent exist, child get SIGTERM.
            amas_init_process_info(AMAS_WLC_PROCESS_CONNECT_HANDLER);
            // record pid
            update_amas_wlcconnect_connection_status((wlc_list + i)->bandindex, AMAS_WLCCONNECT_STATUS_PROCESSING);
            snprintf(amas_wlc_connection_pid, sizeof(amas_wlc_connection_pid), "amas_wlc%d_connection_pid", (wlc_list + i)->bandindex);
            nvram_set_int(amas_wlc_connection_pid, getpid());
            start_connect_ap(wlc_list, i, action_mode);
            nvram_set_int(amas_wlc_connection_pid, 0);
            amas_release_connection_profiles(&ap_profiles);
            amas_release_sitesurvey_ap(&sitesurvey_ap);
            update_amas_wlcconnect_connection_status((wlc_list + i)->bandindex, AMAS_WLCCONNECT_STATUS_FINISHED);
            free(wlc_list);
            exit(0);
        } else if (pid > 0) {  // Parent
            processing_count++;
            process_info.child_pid[(wlc_list + i)->bandindex] = pid;
        } else {  // fork error.
            WLC_DBG("BandIndex(%d) Fork() fail.\n", (wlc_list + i)->bandindex);
        }
    }
    sleep(2);  // Waitting for child process fork.
    update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING);
    while (1) {
        int done = 0, keep_processing = 0;
        for (i = 0; i < SUMband; i++) {
            if (process_info.child_pid[(wlc_list + i)->bandindex] > 0) {
                if (chk_process_exist(process_info.child_pid[(wlc_list + i)->bandindex])) {  // Process is still exist.
                    if (get_amas_wlcconnect_connection_status(
                            (wlc_list + i)->bandindex) ==
                        AMAS_WLCCONNECT_STATUS_KEEP_PROCESSING)
                        keep_processing++;
                } else {  // exit
                    char amas_wlc_keep_connecting[] = "amas_wlcXXX_keep_connecting";
                    char amas_wlc_state[] = "amas_wlcXXX_state";
                    snprintf(amas_wlc_keep_connecting, sizeof(amas_wlc_keep_connecting), "amas_wlc%d_keep_connecting", (wlc_list + i)->bandindex);
                    snprintf(amas_wlc_state, sizeof(amas_wlc_state), "amas_wlc%d_state", (wlc_list + i)->bandindex);
                    if (nvram_get_int(amas_wlc_state) != WLC_STATE_CONNECTED && nvram_get_int(amas_wlc_keep_connecting) == 1) {
                        // restart connection
                        WLC_DBG("BandIndex(%d) Restart connection.\n", (wlc_list + i)->bandindex);
                        pid = fork();
                        if (pid == 0) {
                            prctl(PR_SET_PDEATHSIG, SIGTERM);  // Parent exist, child get SIGTERM.
                            amas_init_process_info(AMAS_WLC_PROCESS_CONNECT_HANDLER);
                            // record pid
                            update_amas_wlcconnect_connection_status((wlc_list + i)->bandindex, AMAS_WLCCONNECT_STATUS_KEEP_PROCESSING);
                            snprintf(amas_wlc_connection_pid, sizeof(amas_wlc_connection_pid), "amas_wlc%d_connection_pid", (wlc_list + i)->bandindex);
                            nvram_set_int(amas_wlc_connection_pid, getpid());
                            start_connect_ap(wlc_list, i, action_mode);
                            nvram_set_int(amas_wlc_connection_pid, 0);
                            amas_release_connection_profiles(&ap_profiles);
                            amas_release_sitesurvey_ap(&sitesurvey_ap);
                            update_amas_wlcconnect_connection_status((wlc_list + i)->bandindex, AMAS_WLCCONNECT_STATUS_FINISHED);
                            free(wlc_list);
                            exit(0);
                        } else if (pid > 0) {
                            process_info.child_pid[(wlc_list + i)->bandindex] = pid;
                            keep_processing++;
                        } else {
                            WLC_DBG("BandIndex(%d) Fork() fail.\n", (wlc_list + i)->bandindex);
                        }
                    } else {
                        done++;
                    }
                }
            }
        }
        if (keep_processing == (processing_count - done)) {
            update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_FINISHED);
        }
        if (done == processing_count) {
            WLC_DBG("All connection child process are done.\n");
            break;
        } else {
            sleep(2);
        }
    }
}

/**
 * @brief Do Start connection request
 *
 * @param action_mode Request action mode
 */
static void amas_start_connect(int action_mode) {
    unsigned int wlc_active = strtoul(nvram_safe_get("amas_wlc_active"), NULL, 16);
    unsigned int wlc_action = strtoul(nvram_safe_get("amas_wlc_action_band"), NULL, 16);

    WLC_DBG("WLC bitmap 0x%x\n", wlc_active);
    /* init wlc_list[] */
    wlc_list = (amas_wlcconnect_bandindex_s *)calloc(SUMband, sizeof(amas_wlcconnect_bandindex_s));
    if (!wlc_list) {
        WLC_DBG("Allocate memory for wlc_list[%d] fail. Stopping amas_start_connect\n", SUMband);
        goto START_CONNECT_EXIT;
    }
    int wlc_use_counts = amas_wlc_list_init(wlc_active, wlc_action, wlc_list);
    WLC_DBG("Use WLC count: %d\n", wlc_use_counts);  // The debug message for fixed WARNING "unused variable"

    if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_RESTART) {
        WLC_RUNTIME_LOG("Action mode: AMAS_WLCCONNECT_ACTION_MODE_ACTION_RESTART. Disconnect all connection.\n");
        amas_disconnect_all_connection();
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP) {
        WLC_RUNTIME_LOG("Action mode: AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP. Disconnect all connecting or disconnect band.\n");
        update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING);
        amas_disconnect_nouse_noconnected_band(wlc_list);
        goto START_CONNECT_EXIT;
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP_OPTIMIZATION) {
        WLC_DBG("Action mode: AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP_OPTIMIZATION. Not implement...Exit\n");
        update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING);
        goto START_CONNECT_EXIT;
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_DISCONNECT) {
        WLC_RUNTIME_LOG("Action mode: AMAS_WLCCONNECT_ACTION_MODE_ACTION_DISCONNECT. Disconnect specific or no use band.\n");
        update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING);
        amas_disconnect_action_nouse_band_connection(wlc_list);
        goto START_CONNECT_EXIT;
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_CONNECTING_BY_DRIVER) {
        // Don't do anything.
    } else {
        amas_disconnect_nouse_band(wlc_list);
    }

    if (amas_wlcconnect_load_connection_profile()) {
        WLC_DBG("Load Connection profile fail.\n");
        goto START_CONNECT_EXIT;
    }

    if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_CONNECTING_BY_DRIVER || action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_RESTART ||
        action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_START) {
        start_general_connect(wlc_list, action_mode);
        goto START_CONNECT_EXIT;
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_START_OPTIMIZATION) {
        start_opt_connect(wlc_list, action_mode);
        goto START_CONNECT_EXIT;
    } else if (action_mode == AMAS_WLCCONNECT_ACTION_MODE_ACTION_FOLLOW_CONNECTION) {
        start_follow_connect(wlc_list, action_mode);
        goto START_CONNECT_EXIT;
    }

START_CONNECT_EXIT:
    amas_release_connection_profiles(&ap_profiles);
    amas_release_sitesurvey_ap(&sitesurvey_ap);
    free(wlc_list);
}

/**
 * @brief Clean all band connecting AP's cost nvram
 *
 */
void alg_clean_all_connecting_cost_to_nvram()
{
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    if (aimesh_alg != AIMESH_ALG_COST) return;

    char nvrampar[32] = {};
    int i;
    for (i = 0; i < SUMband; i++) {
        snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_connecting_cost", i);
        nvram_unset(nvrampar);
    }
}

/**
 * @brief Child SIGTERM handler function.
 *
 * @param signum Received signal number
 */
static void amas_child_sigTerm_handler(int signum)
{
    char amas_wlc_state[] = "amas_wlcXXX_state";
    char amas_wlc_unit[] = "amas_wlcXXX_unit";
    int i;
    int unit;
    int pid = getpid();

    WLC_DBG("PID(%d) signal handler receive SIGTERM. Exitting...\n", pid);
    /* Check upstream connection state and stopping wlc interface that still connecting... */
    i = 0;

    if (process_info.type == AMAS_WLC_PROCESS_REQUEST_HANDLER) {
        release_start_connect_ap_fork();
        for (i = 0; i < SUMband; i++) {
            snprintf(amas_wlc_state, sizeof(amas_wlc_state),"amas_wlc%d_state", i);
            snprintf(amas_wlc_unit, sizeof(amas_wlc_unit), "amas_wlc%d_unit", i);
            unit = nvram_get_int(amas_wlc_unit);
            if (nvram_get_int(amas_wlc_state) != WLC_STATE_CONNECTED) {
                WLC_RUNTIME_LOG("PID(%d) bandindex(%d) unit(%d) Stop connection.\n", getpid(), i, unit);
                Pty_stop_wlc_connect(unit);  // Stop connecting...
                amas_update_wlc_RSSIscore(i, 1);
            }
            i++;
        }
        reset_dfs_status();
	void alg_clean_all_connecting_cost_to_nvram();
        alg_clean_all_connecting_cost_to_nvram();
        nvram_set_int("amas_wlcconnect_handler_pid", 0); // reset handler pid is 0.
    } else if (process_info.type == AMAS_WLC_PROCESS_CONNECT_HANDLER) { // Connection Child.
        WLC_RUNTIME_LOG("PID(%d) type(%d) process_term(%d).\n", pid, process_info.type, process_term);
        if (process_term == 0) {
            process_term = 1;
            WLC_RUNTIME_LOG("PID(%d) set flag for SIGTERM.\n", pid);
            if (wlc_list) {
                WLC_RUNTIME_LOG("PID(%d) cancel sitesurvey and free.\n", pid);
                amas_cancel_sitesurvey(wlc_list);
                free(wlc_list);
                wlc_list = NULL;
            }
        }
        else
        {
            WLC_RUNTIME_LOG("PID(%d) unset flag for SIGTERM.\n", pid);
            process_term = 0;
        }
    }
    amas_free_all_memory_exit(signum);
}

/**
 * @brief Create IPC socket
 *
 * @return int Create result. 1: Success. 0: Fail.
 */
static int amas_open_ipc_socket()
{
	struct sockaddr_un sock_addr_ipc;

	/* IPC Socket */
	if ((amas_wlcconnect_ipc_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		WLC_DBG("failed to IPC socket create!\n");
		goto AMAS_OPEN_IPC_ERROR;
	}

	memset(&sock_addr_ipc, 0, sizeof(sock_addr_ipc));
	sock_addr_ipc.sun_family = AF_UNIX;
	snprintf(sock_addr_ipc.sun_path, sizeof(sock_addr_ipc.sun_path), "%s", AMAS_WLCCONNECT_IPC_SOCKET_PATH);
	unlink(AMAS_WLCCONNECT_IPC_SOCKET_PATH);

	if (bind(amas_wlcconnect_ipc_socket, (struct sockaddr*)&sock_addr_ipc, sizeof(sock_addr_ipc)) < -1) {
		WLC_DBG("failed to IPC socket bind!\n");
		goto AMAS_OPEN_IPC_ERROR;
	}

	if (listen(amas_wlcconnect_ipc_socket, AMAS_WLCCONNECT_IPC_MAX_CONNECTION) == -1) {
		WLC_DBG("failed to IPC socket listen!\n");
		goto AMAS_OPEN_IPC_ERROR;
	}

	return 1;

AMAS_OPEN_IPC_ERROR:
	amas_close_ipc_socket();
	return 0;
}

/**
 * @brief Handle event from IPC socket
 *
 * @param event Event strings
 */
static void amas_ipc_event_handler(char *event)
{
    WLC_RUNTIME_LOG("Receive event: %s\n", event);
    int skip_request = 0;
    int action_mode = 0;
    //unsigned int wlc_active = strtoul(nvram_safe_get("amas_wlc_active"), NULL, 16) >> 20; // XXXX 0000 0000 0000 0000 0000 shift 20 bits
    //unsigned int wlc_action = strtoul(nvram_safe_get("amas_wlc_action_band"), NULL, 16) >> 20; // XXXX 0000 0000 0000 0000 0000 shift 20 bits
    unsigned int wlc_active = strtoul(nvram_safe_get("amas_wlc_active"), NULL, 16);
    unsigned int wlc_action = strtoul(nvram_safe_get("amas_wlc_action_band"), NULL, 16);
    char buf[32] = {};
    char para[32] = {0}, para_ongoing[32] = {0}, nvram_connection_pid[32] = {};
    int i, pid_num;

    if (!strcmp(event, ACTION_START)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_START;
    } else if (!strcmp(event, ACTION_START_OPTIMIZATION)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_START_OPTIMIZATION;
    } else if (!strcmp(event, ACTION_RESTART)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_RESTART;
    } else if (!strcmp(event, ACTION_STOP)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP;
    } else if (!strcmp(event, ACTION_STOP_OPTIMIZATION)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_STOP_OPTIMIZATION;
    } else if (!strcmp(event, ACTION_DISCONNECT)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_DISCONNECT;
    } else if (!strcmp(event, ACTION_START_BY_DRIVER)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_CONNECTING_BY_DRIVER;
    } else if (!strcmp(event, ACTION_START_FOLLOW_CONNECTION)) {
        action_mode = AMAS_WLCCONNECT_ACTION_MODE_ACTION_FOLLOW_CONNECTION;
    } else {
        WLC_DBG("IPC: Not support event: %s\n", event);
        nvram_set_int("amas_wlc_request_lock", 0);
        exit(0);
    }

    if (get_amas_wlcconnect_status() == AMAS_WLCCONNECT_STATUS_READY_PROCESSING) {
        WLC_DBG("IPC: The current request %s state is READY PROCESSING. Drop the new request.\n", nvram_safe_get("amas_wlc_action"));
        nvram_set_int("amas_wlc_request_lock", 0);
        exit(0);
    }

    pid_num = nvram_get_int("amas_wlcconnect_handler_pid");
    if (pid_num > 0) {
        if (chk_process_exist(pid_num)) {  // Process is still exist.
            if (!strcmp(nvram_safe_get("amas_wlc_action"), event)) { // the same
                if (!strcmp(event, ACTION_START_BY_DRIVER)) {
                    skip_request = 1;
                }
                else if (!strcmp(event, ACTION_START) || !strcmp(event, ACTION_RESTART)) {
                    if (wlc_active == strtoul(nvram_safe_get("amas_wlc_active_ongoing"), NULL, 16) && wlc_action == strtoul(nvram_safe_get("amas_wlc_action_ongoing"), NULL, 16)) {
                        for (i = 0; i < SUMband; i++) {
                            snprintf(para, sizeof(para), "amas_wlc%d_priority", i);
                            snprintf(para_ongoing, sizeof(para_ongoing), "amas_wlc%d_priority_ongoing", i);
                            if (nvram_get_int(para) != nvram_get_int(para_ongoing)) {
                                skip_request = 0;
                                break;
                            }
                            skip_request = 1;
                        }
                    }
                }
            }
            if (skip_request) {
                WLC_DBG("IPC: The event %s is same as the current processing event %s. Drop the request.\n", event, nvram_safe_get("amas_wlc_action"));
                update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_PROCESSING); // Update current amas_wlcconnect finish to processing
                int i;
                for (i = 0; i < get_wl_count(); i++) {
                    if (get_amas_wlcconnect_connection_status(i) == AMAS_WLCCONNECT_STATUS_KEEP_PROCESSING)
                        update_amas_wlcconnect_connection_status(i, AMAS_WLCCONNECT_STATUS_PROCESSING);
                }
                nvram_set_int("amas_wlc_request_lock", 0);
                exit(0);
            }
        }
    }
    nvram_set("amas_wlc_action", event);
    update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_READY_PROCESSING);
    nvram_set_int("amas_wlc_request_lock", 0);
    pid_num = nvram_get_int("amas_wlcconnect_handler_pid");
    if (pid_num > 0) {              // Stop pre-handler process.
        int wait_pre_handler = 30;  // 30 seconds
        kill(pid_num, SIGTERM);
        while (wait_pre_handler > 0) {
            if (!chk_process_exist(pid_num))  // exit
                break;
            wait_pre_handler--;
            sleep(1);
        }
    }
    if (chk_process_exist(pid_num)) { // the handler is still exit
        // killall fork child.
        kill(pid_num, SIGKILL);
        // Try to kill connection fork
        for (i = 0; i < SUMband; i++) {
            snprintf(nvram_connection_pid, sizeof(nvram_connection_pid), "amas_wlc%d_connection_pid", i);
            if (nvram_get_int(nvram_connection_pid) > 0) {
                kill(nvram_get_int(nvram_connection_pid), SIGKILL);
                nvram_set_int(nvram_connection_pid, 0);
            }
        }
        sleep(1);
    }

    /* Record child pid */
    nvram_set_int("amas_wlcconnect_handler_pid", getpid());

    /* Record wlc_active & wlc_action_band & amas_wlc%d_priority in this request. */
    snprintf(buf, sizeof(buf), "%X", wlc_active);
    nvram_set("amas_wlc_active_ongoing", buf);
    snprintf(buf, sizeof(buf), "%X", wlc_action);
    nvram_set("amas_wlc_action_ongoing", buf);
    for (i = 0; i < SUMband; i++) {
        snprintf(para, sizeof(para), "amas_wlc%d_priority", i);
        snprintf(para_ongoing, sizeof(para_ongoing), "amas_wlc%d_priority_ongoing", i);
        nvram_set_int(para_ongoing, nvram_get_int(para));
    }
    amas_start_connect(action_mode);
}

/**
 * @brief Reading event from IPC socket
 *
 * @param sockfd IPC socket file description
 */
static void amas_ipc_handle_socekt(int sockfd)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));

    if (read_msg_from_ipc_socket(sockfd, buf, sizeof(buf), "Received", 3000) < 0) {
        WLC_DBG("Read socket error!\n");
        exit(0);
    }
    else {
        if (nvram_get_int("amas_wlc_request_lock") == 1) {
            WLC_DBG("Request LOCK!! Drop incomming request.\n");
            exit(0);
        }
        else {
            nvram_set_int("amas_wlc_request_lock", 1);
            amas_ipc_event_handler(&buf[0]);
        }
    }
}

/**
 * @brief Handler any data from IPC socket
 *
 */
static void amas_ipc_receive_handler()
{
	int pid;
	int recv_sockfd;
    wlc_dbg = nvram_get_int("wlc_dbg");

	recv_sockfd = accept(amas_wlcconnect_ipc_socket, NULL, NULL);

	if (recv_sockfd < 0) {
		WLC_DBG("failed to socket accept()!\n");
		return;
	}

	if ((pid = fork()) < 0) {
		WLC_DBG("fork fail\n");
		return;
	} else {
		if (pid == 0) {	/* child */
			close(amas_wlcconnect_ipc_socket);
			amas_wlcconnect_ipc_socket = -1;

            amas_init_process_info(AMAS_WLC_PROCESS_REQUEST_HANDLER);
            /* Re-register SIGTERM action for child process. */
            struct sigaction act_sigterm;
            act_sigterm.sa_handler = amas_child_sigTerm_handler;
            act_sigterm.sa_flags = SA_NODEFER;
            sigaction(SIGTERM, &act_sigterm, NULL);

			amas_ipc_handle_socekt(recv_sockfd);

            update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_FINISHED);
            WLC_RUNTIME_LOG("The Request Done.\n");
            nvram_set_int("amas_wlcconnect_handler_pid", 0); // reset handler pid is 0.
            WLC_DBG("Child(%d) exit\n", getpid());
            exit(0); // Child exit.

		} else {	/* parent */
			close(recv_sockfd);
            recv_sockfd = -1;
		}
	}
}

/**
 * @brief Init for specific ALG
 *
 */
void alg_init()
{
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    amas_reset_wlc_RSSIscore(0);

    switch (aimesh_alg) {
        case AIMESH_ALG_COST:
            break;
        case AIMESH_ALG_RSSISCORE:
            break;
        default:
            break;
    }
}

/**
 * @brief Update connecting AP's cost to nvram
 *
 * @param bandindex Band index
 * @param cost the AP's cost
 */
void alg_update_connecting_cost_to_nvram(int bandindex, float cost)
{
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    if (aimesh_alg != AIMESH_ALG_COST) return;

    char nvrampar[32] = {};

    snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_connecting_cost", bandindex);

    if (cost >= 0)
        cost = cost * 10;
    else
        nvram_unset(nvrampar);

    nvram_set_int(nvrampar, cost);
}

/**
 * @brief Clean connecting AP's cost nvram
 *
 * @param bandindex Band index
 */
void alg_clean_connecting_cost_to_nvram(int bandindex)
{
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    if (aimesh_alg != AIMESH_ALG_COST) return;

    char nvrampar[32] = {};
    snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_connecting_cost", bandindex);

    nvram_unset(nvrampar);
}

static float cal_cost(int band, float pap_cost, int rssi, int unit) {
    float cost = -1;
    int SUMband = get_wl_count();

    if (pap_cost >= 0) {
        if (rssi > -60)
            cost = pap_cost + 1;
        else if (rssi > -70)
            cost = pap_cost + 1 + 1 * (-60 - rssi) / 10.0;
        else if (rssi > -80)
            cost = pap_cost + 2 + 4 * (-70 - rssi) / 10.0;
        else
            cost = pap_cost + 6 + 10 * (-80 - rssi) / 10.0;
    }

    //  DWB/NON-DWB cost weighted
    if (SUMband == 2) {  // Dual-Band
        cost = cost + 1;
    } else if (SUMband >= 3) {
        if (unit != nvram_get_int("dwb_band"))
            cost = cost + 1;
    }

    return cost;
}

/**
 * @brief Update some parameter for the ALG
 *
 * @param ss_ap sitesurvey result
 * @param unit sitesurvey band unit
 */
void alg_update_ap_info(amas_sitesurvey_ap_s *ss_ap, int unit) {
    int rssi_score = 0;
    int antenna = 0;
    int i, chain = 0;
    char wl_hw_txchain[] = "wlXXXXXX_hw_txchain";
    char wl_nband[] = "wlXXX_nband";
    int bandwidth = ss_ap->bw, bw_cap, bw_max = 0;
    int unit_6g = -1;
    double max_power_5G=0;
    double max_power_6G=0;
    int num5g = num_of_5g_if();
    double power_factor=0;
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;
    
    snprintf(wl_hw_txchain, sizeof(wl_hw_txchain), "wl%d_hw_txchain", unit);
    chain = nvram_get_int(wl_hw_txchain);
    while (chain > 0) {
        if (chain % 2 == 1)
            antenna++;
        chain = chain / 2;
    }

    wl_get_bw_cap(unit, &bw_cap);
    if (bw_cap & 0x08)
        bw_max = 160;
    else if (bw_cap & 0x04)
        bw_max = 80;
    else if (bw_cap & 0x02)
        bw_max = 40;
    else if (bw_cap & 0x01)
        bw_max = 20;
    if (bw_max > 0 && (bw_max < bandwidth))
        bandwidth = bw_max;

    switch (aimesh_alg) {
        case AIMESH_ALG_COST:
            if (antenna > 0)
                rssi_score = ss_ap->rssi + (int)(10 * (log10(antenna)-log10(4))) + (int)(10 * (log10(bandwidth)-log10(80)));
            else
                rssi_score = ss_ap->rssi + (int)(10 * (log10(bandwidth)-log10(80)));

            if (ss_ap->band == WL2G_U) {  // 2.4G cost
                ss_ap->cost.cost_2g = cal_cost(ss_ap->band, ss_ap->cost.pap_cost, rssi_score, unit);
                ss_ap->cost.cost_2g = ss_ap->cost.cost_2g + 16;  // 2.4G extra weight if cost by its RSSI.
            } else if (ss_ap->band == WL5G1_U) {                 // 5G1 cost
                ss_ap->cost.cost_5g = cal_cost(ss_ap->band, ss_ap->cost.pap_cost, rssi_score, unit);
            } else if (ss_ap->band == WL5G2_U) {  // 5G2 cost
                ss_ap->cost.cost_5g1 = cal_cost(ss_ap->band, ss_ap->cost.pap_cost, rssi_score, unit);
            } else if (ss_ap->band == WL6G_U) {  // 6G cost
                ss_ap->cost.cost_6g = cal_cost(ss_ap->band, ss_ap->cost.pap_cost, rssi_score, unit);
                unit_6g = unit;
            }
            if ((ss_ap->band == WL5G1_U || ss_ap->band == WL5G2_U) && ss_ap->last_byte_6g >= 0) {
                /* 6G antenna */
                int antenna_6g = 0;
                for (i = 0; i < SUMband; i++) {
                    snprintf(wl_nband, sizeof(wl_nband), "wl%d_nband", i);
                    if (nvram_get_int(wl_nband) == 4) {  // 6G
                        unit_6g = i;
                        break;
                    }
                }

                if (unit_6g >= 0) {
                    snprintf(wl_hw_txchain, sizeof(wl_hw_txchain), "wl%d_hw_txchain", unit_6g);
                    chain = nvram_get_int(wl_hw_txchain);
                    while (chain > 0) {
                        if (chain % 2 == 1)
                            antenna_6g++;
                        chain = chain / 2;
                    }
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
                    WLC_RUNTIME_LOG("PID(%d) Band(%s) SSID[%s] max_power_6G (%f) max_power_5G(%f) power_factor(%f) maxpowerdiff_check(%d) \n", getpid(), get_band_string_by_index(ss_ap->bandindex),
                        ss_ap->ssid ,max_power_6G , max_power_5G, power_factor , (int)((max_power_6G - max_power_5G)*power_factor));

                    if(antenna_6g > 0)
                        rssi_score = ss_ap->rssi + (int)(10 * (log10(antenna_6g)-log10(4))) + (int)(10 * (log10(160)-log10(80))) + (int)((max_power_6G - max_power_5G)*power_factor);
                    else
                        rssi_score = ss_ap->rssi + (int)(10 * (log10(160)-log10(80))) + (int)((max_power_6G - max_power_5G)*power_factor);
                    WLC_RUNTIME_LOG("PID(%d) rssi(%d) antenna_6g_check (%d) 6g_bandwidth_check(%d) maxpowerdiff_check(%d)\n", getpid(), ss_ap->rssi, (int)(10 * (log10(antenna_6g)-log10(4))), (int)(10 * (log10(160)-log10(80))),(int)((max_power_6G - max_power_5G)*power_factor));
                    ss_ap->cost.cost_6g = cal_cost(WL6G_U, ss_ap->cost.pap_cost, rssi_score, unit_6g);
                }
            }

            // Choose the best cost as the cost of the AP.
            WLC_RUNTIME_LOG("PID(%d) Band(%s) SSID[%s] Cost_2G(%f) Cost_5G(%f) Cost_5G2(%f) Cost_6G(%f)\n", getpid(), get_band_string_by_index(ss_ap->bandindex),
                    ss_ap->ssid, ss_ap->cost.cost_2g, ss_ap->cost.cost_5g, ss_ap->cost.cost_5g1, ss_ap->cost.cost_6g);
            if (ss_ap->cost.cost_2g >= 0) {
                ss_ap->cost.cost = ss_ap->cost.cost_2g;
                ss_ap->cost.cost_band = WL2G_U;
            }
            if (ss_ap->cost.cost_5g >= 0 && (ss_ap->cost.cost_5g <= ss_ap->cost.cost || ss_ap->cost.cost < 0)) {
                ss_ap->cost.cost = ss_ap->cost.cost_5g;
                ss_ap->cost.cost_band = WL5G1_U;
            }
            if (ss_ap->cost.cost_5g1 >= 0 && (ss_ap->cost.cost_5g1 <= ss_ap->cost.cost || ss_ap->cost.cost < 0)) {
                ss_ap->cost.cost = ss_ap->cost.cost_5g1;
                ss_ap->cost.cost_band = WL5G2_U;
            }
            if (unit_6g >= 0 && ss_ap->cost.cost_6g >= 0 && (ss_ap->cost.cost_6g <= ss_ap->cost.cost || ss_ap->cost.cost < 0)) {
                ss_ap->cost.cost = ss_ap->cost.cost_6g;
                ss_ap->cost.cost_band = WL6G_U;
            }
            break;
        case AIMESH_ALG_RSSISCORE:
            if (ss_ap->cost.pap_cost >= 0 && ss_ap->rssi < 0)
                ss_ap->RSSIscore = ss_ap->rssi - (6 * ss_ap->cost.pap_cost);  // RSSIscore = RSSI-(6*layer)
            else
                ss_ap->RSSIscore = 100;  // Default rssiscore is 100.
            break;
        default:
            break;
    }
}

/**
 * @brief amas_wlcconnect input function
 *
 * @return int daemon exit state.
 */
int amas_wlcconnect_main(void)
{
    dbG("Start amas_wlcconnect\n");

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

    wlc_dbg = nvram_get_int("wlc_dbg");
    ap_profiles = NULL;
    sitesurvey_ap = NULL;
	FILE *fp;
	fd_set fdSet;

    char wif[256]={0}, *next = NULL;
    SUMband = 0;

    nvram_set("amas_wlc_action", "");

  	foreach(wif, nvram_safe_get("sta_ifnames"), next) {
        SUMband++;
    }

    amas_init_process_info(AMAS_WLC_PROCESS_MAIN);
    nvram_set_int("amas_wlc_request_lock", 0); // reset amas_wlc_request_lock
    int pid_num = nvram_get_int("amas_wlcconnect_handler_pid");
    int i;
    char nvram_connection_pid[32] = {};
    if (pid_num > 0) {              // Stop pre-handler process.
        if (chk_process_exist(pid_num)) { // exit
            int wait_pre_handler = 30;  // 30 seconds
            kill(pid_num, SIGTERM);
            while (wait_pre_handler > 0) {
                WLC_DBG("Waitting Pre amas_wlcconnect\n");
                if (!chk_process_exist(pid_num))  // exit
                    break;
                wait_pre_handler--;
                sleep(1);
            }
            if (chk_process_exist(pid_num)) { // the handler is still exit
                // killall fork child.
                kill(pid_num, SIGKILL);
            }
        }
        nvram_set_int("amas_wlcconnect_handler_pid", 0); // reset handler pid is 0.
    }

    // Try to kill connection fork
    for (i = 0; i < SUMband; i++) {
        snprintf(nvram_connection_pid, sizeof(nvram_connection_pid), "amas_wlc%d_connection_pid", i);
        if (nvram_get_int(nvram_connection_pid) > 0) {
            kill(nvram_get_int(nvram_connection_pid), SIGKILL);
            nvram_set_int(nvram_connection_pid, 0);
        }
    }
    sleep(1);

    alg_init();

    /* Register signal handler for receiving doing reconnect signal from other
     * amas daemon.
     */
    struct sigaction act_sigterm;
    act_sigterm.sa_handler = amas_free_all_memory_exit;
    act_sigterm.sa_flags = SA_NODEFER;
    sigaction(SIGTERM, &act_sigterm, NULL);
	signal(SIGCHLD, SIG_IGN);
    WLC_DBG("amas_free_all_memory_exit signal handler is registered for SIGTERM...\n");
    WLC_DBG("Ignore SIGCHLD...\n");

	/* write pid */
    main_wlcconnect_pid = getpid();
	if ((fp = fopen("/var/run/amas_wlcconnect.pid", "w")) != NULL) {
		fprintf(fp, "%d", main_wlcconnect_pid);
		fclose(fp);
	}

	/* create folder */
	if(!check_if_dir_exist(AMAS_FOLDER)) {
		WLC_DBG("create a folder for cfg_mnt (%s)\n", AMAS_FOLDER);
		mkdir(AMAS_FOLDER, 0755);
	}

	/* init socket */
	if (amas_open_ipc_socket(&amas_wlcconnect_ipc_socket) == 0)
		goto AMAS_WLCCONNECT_ERR;

    /* init connection time */
    init_conn_time(SUMband);

    update_amas_wlcconnect_status(AMAS_WLCCONNECT_STATUS_IDLE);

	while (1) {

		/* must re- FD_SET before each select() */
		FD_ZERO(&fdSet);

		FD_SET(amas_wlcconnect_ipc_socket, &fdSet);

		/* must use amas_wlcconnect_ipc_socket+1, not amas_wlcconnect_ipc_socket */
		if (select(amas_wlcconnect_ipc_socket+1, &fdSet, NULL, NULL, NULL) < 0)
			break;

		/* handle packets from IPC */
		if (FD_ISSET(amas_wlcconnect_ipc_socket, &fdSet))
			amas_ipc_receive_handler(amas_wlcconnect_ipc_socket);
	}

AMAS_WLCCONNECT_ERR:
    dbG(" amas_wlcconnect exit\n");
    return 0;
}
