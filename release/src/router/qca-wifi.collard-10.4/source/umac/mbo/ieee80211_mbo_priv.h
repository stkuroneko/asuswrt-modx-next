/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

/*
 MBO  module
*/


#include <ieee80211_var.h>
#include <ieee80211_ioctl.h>  /* for ieee80211req_athdbg */
/*
 * Structure for id(elem id or attribute id) and
 * len fields.Done to avoid redundancy due to
 * repeated usage of these two fields.
 */
struct ieee80211_mbo_header {
    u_int8_t ie;
    u_int8_t len;
}adf_os_packed;

struct ieee80211_mbo_ie {
    struct ieee80211_mbo_header header;
    u_int8_t oui[3];
    u_int8_t oui_type;
    u_int8_t opt_ie[0];
}adf_os_packed; /*packing is required */

struct ieee80211_assoc_disallow {
    struct ieee80211_mbo_header header;
    u_int8_t reason_code;
    u_int8_t opt_ie[0];
}adf_os_packed;

struct ieee80211_cell_cap {
    struct ieee80211_mbo_header header;
    u_int8_t cell_conn;
    u_int8_t opt_ie[0];
}adf_os_packed;

struct ieee80211_mbo_cap {
    struct ieee80211_mbo_header header;
    u_int8_t  reserved6:6;
    u_int8_t  cap_cellular:1;
    u_int8_t  cap_reserved1:1;
    u_int8_t  opt_ie[0];
}adf_os_packed;

struct ieee80211_cell_data_conn_pref {
    struct ieee80211_mbo_header header;
    u_int8_t cell_pref;
    u_int8_t opt_ie[0];
}adf_os_packed;

struct ieee80211_transit_reason_code {
    struct ieee80211_mbo_header header;
    u_int8_t reason_code;
    u_int8_t opt_ie[0];
}adf_os_packed;

struct ieee80211_transit_reject_reason_code {
    struct ieee80211_mbo_header header;
    u_int8_t reason_code;
    u_int8_t opt_ie[0];
}adf_os_packed;

struct ieee80211_assoc_retry_delay {
    struct ieee80211_mbo_header header;
    u_int16_t re_auth_delay;
    u_int8_t opt_ie[0];
}adf_os_packed;

struct ieee80211_mbo {
    osdev_t        mbo_osdev;
    wlan_dev_t     mbo_ic;
    u_int8_t       usr_assoc_disallow;
    u_int8_t       usr_mbocap_cellular_capable;
    u_int8_t       usr_cell_pref;
    u_int8_t       usr_trans_reason;
    u_int16_t      usr_assoc_retry;
};
