
#include <stdio.h>
#include <stdlib.h>
#include <shared.h>
#include <tcode.h>
#include "encrypt_main.h"
#include <cfg_loclist.h>
#if defined(RTCONFIG_SOC_IPQ8074)
#include <qca.h>
#endif

#define LOC_DBG(fmt, arg...) do {\
    if (!strcmp(nvram_safe_get("loc_dbg"), "1")) \
        cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
    if (!strcmp(nvram_safe_get("loc_syslog"), "1")) \
        asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

/*
 * {MODEL_NAME, Source ISO code, Destinaion ISO code}
 */
cm_loclist_transfer_country_s tcode_country_trans[] = {
    // {MODEL_RTAC68U, "US", "CN"}
    {-1, "", ""}
};

/**
 * @brief Convert ISO code to the other ISO code if needed.
 *
 * @param srcCountry Original ISO code
 * @return char* Converted ISO code or original ISO code
 */
static char *cm_trans_country(char *srcCountry) {

    cm_loclist_transfer_country_s *p_tcode_country_trans = NULL;
    int model = get_model();

    for (p_tcode_country_trans = &tcode_country_trans[0]; p_tcode_country_trans->model != -1; p_tcode_country_trans++) {

        if (p_tcode_country_trans->model == model && strcmp(srcCountry, p_tcode_country_trans->src_iso_code) == 0) {
            return p_tcode_country_trans->dest_iso_code;
        }
    }
    return srcCountry;
}

/**
 * @brief is the DuT support the location code
 *
 * @param location_code Country be chucked
 * @return int Supported or not. 0: Not supported 1: Supported
 */
static int is_support_location_code(char *location_code) {

    int model = get_model();
#ifdef RTAC68U
    unsigned int flag = hardware_flag();
#endif
    const struct tcode_location_s *p_tcode_location_list;
#if defined(RTCONFIG_SOC_IPQ8074)
	const int soc_version_major __attribute__((unused)) = get_soc_version_major();
#endif

    if (location_code == NULL)
        return 0;

    location_code = cm_trans_country(location_code);

    p_tcode_location_list = &tcode_location_list[0];
#if 0
    if (nvram_match("HwId", "A")) // overwrite
        p_tcode_location_list = &tcode_location_list_HwIdA[0];
#endif
#if defined(TUFAX4200)
    if (nvram_match("HwId", "B")) // overwrite
        p_tcode_location_list = &tcode_location_list_HwIdB[0];
#endif
    for (; p_tcode_location_list->model != 0; p_tcode_location_list++) {
#if defined(RTCONFIG_SOC_IPQ8074)
	if (soc_version_major != 2
	 && (!strncmp(p_tcode_location_list->location, "EU", 2)
	  || !strncmp(p_tcode_location_list->location, "JP", 2)))
		continue;
#endif
        if (p_tcode_location_list->model == model && strcmp(p_tcode_location_list->location, location_code) == 0
#ifdef RTAC68U
            && (flag & p_tcode_location_list->flag) != 0
#endif
        ) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Setting location_code from cfg_location_code
 *
 * @param cfgRoot raw data from cfg_server
 * @param location_change Location code be changed? 0: Not changed. 1: Changed.
 */
void cm_Set_location_code(struct json_object *cfgRoot, int *location_change) {

    struct json_object *val = NULL;
    char *cfg_location_code = NULL;
    json_object_object_get_ex(cfgRoot, "cfg_location_code", &val);

    if (val) {
        cfg_location_code = json_object_get_string(val);
    }

    if (cfg_location_code == NULL)
        return;

    /* Compare cfg_location_code */
    if (strcmp(cfg_location_code, nvram_safe_get("cfg_location_code"))) {
        nvram_set("cfg_location_code", cfg_location_code);
        *location_change = 1;
    }
    else {
        *location_change = 0;
        goto CM_SET_LOCATION_CODE_EXIT;
    }

    char *new_location_code = NULL;
    new_location_code = strdup(cm_trans_country(cfg_location_code));
    LOC_DBG("cfg_location_code = %s, new_location_code = %s, location_code = %s\n", cfg_location_code, new_location_code, nvram_safe_get("location_code"));
    if (new_location_code) {
        if (is_support_location_code(new_location_code)) {
            if (strcmp(nvram_safe_get("location_code"), new_location_code)) {
                nvram_set("location_code", new_location_code);
                *location_change = 2;
            }
        }
        free(new_location_code);
    }

CM_SET_LOCATION_CODE_EXIT:
    return;
}

/**
 * @brief add cfg_location_code and sent to RE
 *
 * @param outRoot raw data from cfg_server
 */
void cm_transloclist_Parameter(struct json_object *outRoot)
{
    if (!nvram_contains_word("rc_support", "loclist")) {
        LOC_DBG("Not Support loclist");
        return;
    }

    if (nvram_get_int("cfg_location_nosync") == 1) {
        LOC_DBG("Disabled location code sync. cfg_location_nosync = %d\n", nvram_get_int("cfg_location_nosync"));
        return;
    }

    if (outRoot == NULL) {
        LOC_DBG("outRoot is NULL");
        return;
    }

    char *location_code = nvram_safe_get("location_code");
    nvram_set("cfg_location_code", location_code);
    LOC_DBG("Added cfg_location_code: %s\n", location_code);
    json_object_object_add(outRoot, "cfg_location_code", json_object_new_string(location_code));

    return;
}
