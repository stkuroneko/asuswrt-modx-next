/*
 * Copyright (c) 2008-2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __ACFG_EVENT_H
#define __ACFG_EVENT_H

/** 
 * @file acfg_event.h
 * @brief 
 * @author Atheros Communications Inc.
 * @version 0.1
 */
#include <acfg_api_types.h>

/** 
 * @brief OS Event specific handle
 */
//typedef __acfg_os_event_t   acfg_os_event_t;

/** 
 * @brief ACFG Event Structure, to be populated by the user APP
 */
typedef struct acfg_event {
    /** 
     * @brief  Indicate Device state Change event
     */
    a_status_t  (*device_state_change)(acfg_device_state_data_t *device_state);

    /** 
     * @brief  Indicate Scan complete event
     */
    a_status_t  (*scan_done)(a_uint8_t  *ifname, acfg_scan_done_t   *done);

    /** 
     * @brief  Indicate AP Association events
     */
    a_status_t  (*assoc_ap)(a_uint8_t *ifname, acfg_assoc_t  *done);
    a_status_t  (*disassoc_ap)(a_uint8_t *ifname, acfg_disassoc_t  *done);
    a_status_t  (*auth_ap)(a_uint8_t *ifname, acfg_auth_t  *done);
    a_status_t  (*deauth_ap)(a_uint8_t *ifname, acfg_dauth_t  *fail);

    /** 
     * @brief   Indicate STA Association events
     */
    a_status_t  (*assoc_sta)(a_uint8_t *ifname, acfg_assoc_t  *fail);
    a_status_t  (*disassoc_sta)(a_uint8_t *ifname, acfg_disassoc_t  *fail);
    a_status_t  (*auth_sta)(a_uint8_t *ifname, acfg_auth_t  *done);
    a_status_t  (*deauth_sta)(a_uint8_t *ifname, acfg_dauth_t  *fail);


    /** 
     * @brief   Indicate Radio On Channel events
     */
    a_status_t  (*chan_start)(a_uint8_t *ifname, acfg_chan_start_t *chan_start);

    /** 
     * @brief   Indicate Radio Off Channel events
     */
    a_status_t  (*chan_end)(a_uint8_t *ifname, acfg_chan_end_t *chan_end);

    /** 
     * @brief   Indicate Management Frame Received events
     */
    a_status_t  (*rx_mgmt)(a_uint8_t *ifname, void *dummy);

    /** 
     * @brief   Indicate Action Frame Sent events
     */
    a_status_t  (*sent_action)(a_uint8_t *ifname, void *dummy);

    /** 
     * @brief   Indicate AP Dis-association events
     */
    a_status_t  (*leave_ap)(a_uint8_t *ifname, acfg_leave_ap_t *leave_ap);

    /** 
     * @brief   Indicate to Pass IE events
     */
    a_status_t  (*gen_ie)(a_uint8_t *ifname, acfg_gen_ie_t *gen_ie);

    /** 
     * @brief   Indicate to Pass Assoc Req IE events
     */
    a_status_t  (*assoc_req_ie)(a_uint8_t *ifname, acfg_gen_ie_t *gen_ie);

    /** 
     * @brief   Indicate to Pass Radar events
     */
    a_status_t  (*radar)(a_uint8_t *ifname, acfg_radar_t *radar);

    /**
     * @brief   Indicate raw message from wpa supplicant
     */ 
    a_status_t  (*wsupp_raw_message)(a_uint8_t *, acfg_wsupp_raw_message_t *);

    /**
     * @brief   Indicate AP-STA connected
     */ 
    a_status_t  (*wsupp_ap_sta_conn)(a_uint8_t *, acfg_wsupp_ap_sta_conn_t *);
    a_status_t  (*wsupp_ap_sta_disconn)(a_uint8_t *, acfg_wsupp_ap_sta_conn_t *);

    /**
     * @brief   Indicate WPA connected
     */ 
    a_status_t  (*wsupp_wpa_conn)(a_uint8_t *, acfg_wsupp_wpa_conn_t *);

    /**
     * @brief   Indicate WPA disconnected
     */ 
    a_status_t  (*wsupp_wpa_disconn)(a_uint8_t *, acfg_wsupp_wpa_conn_t *);

    a_status_t  (*wsupp_assoc_reject)(a_uint8_t *, acfg_wsupp_assoc_t *);

    /**
     * @brief   Indicate WPA terminating
     */ 
    a_status_t  (*wsupp_wpa_term)(a_uint8_t *, acfg_wsupp_wpa_conn_t *);

    /**
     * @brief   Indicate WPA scan result available
     */ 
    a_status_t  (*wsupp_wpa_scan)(a_uint8_t *, acfg_wsupp_wpa_conn_t *);

    /**
     * @brief   Indicate WPS enrolle seen
     */ 
    a_status_t  (*wsupp_wps_enrollee)(a_uint8_t *, acfg_wsupp_wps_enrollee_t *);
    a_status_t  (*wsupp_eap_success)(a_uint8_t *, acfg_wsupp_eap_t *);
    a_status_t  (*wsupp_eap_failure)(a_uint8_t *, acfg_wsupp_eap_t *);
    a_status_t  (*push_button)(a_uint8_t *, acfg_pbc_ev_t *);
    a_status_t  (*wsupp_wps_new_ap_setting)(a_uint8_t *,
            acfg_wsupp_wps_new_ap_settings_t *);
    a_status_t  (*wsupp_wps_success)(a_uint8_t *, acfg_wsupp_wps_success_t *);
    a_status_t  (*session_timeout)(a_uint8_t *, acfg_session_t *);
    a_status_t  (*tx_overflow)(a_uint8_t *);
    a_status_t  (*gpio_input)(a_uint8_t *, acfg_gpio_t *);

    /* mgmt rx info  */
    a_status_t  (*mgmt_rx_info)(a_uint8_t *, acfg_mgmt_rx_info_t *);
    /* watchdog event */
    a_status_t  (*wdt_event)(a_uint8_t *, acfg_wdt_event_t *);
    a_status_t  (*nf_dbr_dbm_info)(a_uint8_t *, acfg_nf_dbr_dbm_t *);
    a_status_t  (*packet_power_info)(a_uint8_t *, acfg_packet_power_t *);
    a_status_t  (*cac_start)(a_uint8_t *);
    a_status_t  (*up_after_cac)(a_uint8_t *);
    a_status_t  (*kickout)(a_uint8_t *, acfg_kickout_t *);
    a_status_t  (*assoc_failure)(a_uint8_t *, acfg_assoc_failure_t *);
    a_status_t  (*diagnostics)(a_uint8_t *ifname, acfg_diag_event_t *diag);
    a_status_t  (*chan_stats)(a_uint8_t *, acfg_chan_stats_t *);
} acfg_event_t;


/** 
 * @brief 
 * 
 * @param ifname (Event 
 * @param event
 * 
 * @return 
 */
a_status_t  
acfg_setup_events(a_uint8_t *ifname, acfg_event_t  *event);

/** 
 * @brief 
 * 
 * @param ifname    (Interface name to listen)
 * @param event     (Event Structure)
 * @param mode      (Listening mode)
 * 
 * @return 
 */
a_status_t
acfg_recv_events(acfg_event_t *event, \
        acfg_event_mode_t  mode);

int acfg_recv_netlink_events(acfg_event_t *event);
void acfg_wait_for_wps_app_event(void);

/*Private reason codes*/
enum {
    ACFG_REASON_ASSOC_CAP_MISMATCH = 1,
    ACFG_REASON_ASSOC_RATE_MISMATCH= 2,
    ACFG_REASON_ASSOC_PUREN_NOHT   = 3,
    ACFG_REASON_ASSOC_PUREAC_NOVHT = 4,
    ACFG_REASON_ASSOC_11AC_TKIP_USED = 5,
    ACFG_REASON_ASSOC_CHANWIDTH_MISMATCH = 6,
};

#endif /* __ACFG_EVENT_H */
