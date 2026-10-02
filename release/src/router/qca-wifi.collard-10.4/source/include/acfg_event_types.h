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

#ifndef __ACFG_EVENT_TYPES_H
#define __ACFG_EVENT_TYPES_H

#include <a_base_types.h>

enum acfg_device_state {
    ACFG_DEVICE_STATE_UNKNOWN    = 0x00,
    ACFG_DEVICE_STATE_RESET      = 0x01,
    ACFG_DEVICE_STATE_READY      = 0x02,
    ACFG_DEVICE_STATE_ERROR      = 0xFF,
};
typedef a_uint32_t  acfg_device_state_t;

/** 
 * @brief Target State Change Event Data
 */
typedef struct acfg_device_state_data {
    acfg_device_state_t     prev_state;     /**< previous state of target */
    acfg_device_state_t     curr_state;     /**< new current state of target */
} acfg_device_state_data_t;

/** 
 * @brief Association status
 */
enum acfg_assoc_status {
    ACFG_ASSOC_SUCCESS  = 0,    /**< Assoc completed */
    ACFG_ASSOC_FAILED   = 1,    /**< Unspecified failure */
    ACFG_ASSOC_LEAVE    = 2,    /**< Peer left */
};
typedef a_uint32_t  acfg_assoc_status_t;

/** 
 * @brief De authentication Reason
 */
typedef a_uint32_t  acfg_dauth_reason_t;
typedef a_uint32_t  acfg_reason_t;


/** 
 * @brief Mode of receiving events
 */
enum acfg_event_mode {
    ACFG_EVENT_BLOCK    = 0x1,  /**< Recv Event Blocks */
    ACFG_EVENT_NOBLOCK  = 0x2   /**< Recv Event Unblocks */
};
typedef a_uint32_t acfg_event_mode_t;

/** 
 * @brief Creat Vap event structure
 */
typedef struct acfg_create_vap {
    a_uint8_t   wifi_index;
    a_uint8_t   vap_index;
    a_uint8_t   if_name[ACFG_MAX_IFNAME];
    a_uint8_t   mac_addr[ACFG_MACADDR_LEN];
} acfg_create_vap_t;

/**
 * @brief Restore wifi event structure
 */
typedef struct acfg_restore_wifi {
    a_uint8_t   wifi_index;
    a_uint8_t   if_name[ACFG_MAX_IFNAME];
    a_uint8_t   mac_addr[ACFG_MACADDR_LEN];
} acfg_restore_wifi_t;

/** 
 * @brief Association Done event structure
 */
typedef struct acfg_assoc_sta {
    acfg_assoc_status_t     status;                 /**< Assoc Status */
    acfg_ssid_t             ssid;                   /**< SSID */
    a_uint8_t               bssid[ACFG_MACADDR_LEN];/**< MAC Addr */
} acfg_assoc_sta_t;

/** 
 * @brief Association Done event structure
 */
typedef struct acfg_assoc_ap {
    acfg_assoc_status_t     status;                 /**< Assoc Status */
    a_uint8_t               bssid[ACFG_MACADDR_LEN];/**< MAC Addr */
} acfg_assoc_ap_t;

/** 
 * @brief De-Authentication event from AP
 */
typedef struct acfg_dauth {
    acfg_ssid_t             ssid;   /**< SSID of the AP */
    acfg_dauth_reason_t     reason; /**< Reason for De-Authentication */
    acfg_assoc_status_t        status;
    a_uint8_t               macaddr[ACFG_MACADDR_LEN];/**< MAC Addr */
    a_uint8_t         frame_send;
} acfg_dauth_t;

typedef struct acfg_assoc {
    acfg_assoc_status_t     status;                 /**< Assoc Status */
    acfg_ssid_t             ssid;                   /**< SSID */
    a_uint8_t               bssid[ACFG_MACADDR_LEN];/**< MAC Addr */
    a_uint8_t         frame_send;
} acfg_assoc_t;

typedef struct acfg_disassoc {
    acfg_reason_t     reason; /**< Reason for Disassociation */
    acfg_assoc_status_t        status;
    a_uint8_t               macaddr[ACFG_MACADDR_LEN];/**< MAC Addr */
    a_uint8_t         frame_send;
} acfg_disassoc_t;

typedef struct acfg_auth {
    acfg_assoc_status_t        status;  
    a_uint8_t         macaddr[ACFG_MACADDR_LEN];/**< MAC Addr */
    a_uint8_t         frame_send;
} acfg_auth_t;


/** 
 * @brief Radio On Channel event
 */
enum acfg_chan_start_reason {
    ACFG_CHAN_CHANGE_DFS = 0x01,
    ACFG_CHAN_CHANGE_NORMAL = 0x02,
};

typedef struct acfg_chan_start {
    a_uint32_t              freq;     /**< Frequency */
    a_uint32_t              reason;   /**< Reason */
    a_uint32_t              duration; /**< Duration */
    a_uint32_t              req_id;   /**< Request ID */
} acfg_chan_start_t;

/** 
 * @brief Radio Off Channel event
 */
typedef struct acfg_chan_end {
    a_uint32_t              freq;     /**< Frequency */
    a_uint32_t              reason;   /**< Reason */
    a_uint32_t              duration; /**< Duration */
    a_uint32_t              req_id;   /**< Request ID */
} acfg_chan_end_t;

/** 
 * @brief Leave AP event
 */
typedef struct acfg_leave_ap {
    acfg_reason_t     reason;
    a_uint8_t               mac[ACFG_MACADDR_LEN]; /**< MAC Addr of STA */
} acfg_leave_ap_t;

/** 
 * @brief Pass IE event
 */
typedef struct acfg_gen_ie {
    a_uint32_t              len;                        /**< IE Length */
    a_uint8_t               *data;                      /**< IE Data */
} acfg_gen_ie_t;

/** 
 * @brief scan done status
 */
enum acfg_scan_done_status {
    ACFG_SCAN_SUCCESS  = 0,    /**< SCAN Done completed */
    ACFG_LENGTH_FAIL   = 1,    /**< Unspecified failure */
};
typedef a_uint32_t  acfg_scan_done_status_t;

/** 
 * @brief Scan Completion Event
 */
typedef struct acfg_scan_done {
    acfg_scan_done_status_t     status;     /**< Scan Done Status */
    a_uint32_t                  size;      /**< Size of the Scan results */
} acfg_scan_done_t;

/** 
 * @brief Radar Event
 */
typedef struct acfg_radar {
    a_uint8_t                  count; /**< no. of freqs */
    a_uint8_t                  freqs[ACFG_MAX_IEEE_CHAN]; /**< list of radar freqs */
} acfg_radar_t;

/**
 * @brief STA Session timeout Event
 */
enum acfg_session_reason {
    ACFG_SESSION_TIMEOUT = 0x01,
    ACFG_SESSION_UNKNOWN = 0x02,
};
typedef struct acfg_session {
    acfg_reason_t           reason;
    a_uint8_t               mac[ACFG_MACADDR_LEN]; /**< MAC Addr of STA */
} acfg_session_t;

/**
 * @brief Structure returned on a ACFG_EV_WSUPP_WPS_EVENT_ENROLLEE_SEEN event\n
 */
typedef struct acfg_wsupp_wps_enrollee {
    a_uint8_t station_address[ACFG_MACADDR_LEN];    /**< MAC Addr */
    a_char_t raw_message[128];                           /**< always, undecoded char data */
} acfg_wsupp_wps_enrollee_t;

/**
 * @brief Structure returned on a ACFG_EV_WSUPP_WPA_EVENT event\n
 */
typedef struct acfg_wsupp_wpa_conn {
    a_uint8_t station_address[ACFG_MACADDR_LEN];    /**< MAC Addr */
    a_char_t raw_message[128];                      /**< always, undecoded char data */
} acfg_wsupp_wpa_conn_t;

/**
 * @brief Structure returned on a ACFG_EV_WSUPP_AP_STA_CONNECTED event\n
 */
typedef struct acfg_wsupp_ap_sta_conn {
    a_uint8_t station_address[ACFG_MACADDR_LEN];    /**< MAC Addr */
    a_char_t raw_message[128];                      /**< always, undecoded char data */
} acfg_wsupp_ap_sta_conn_t;

/**
 * @brief Structure returned on a ACFG_EV_WSUPP_RAW_MESSAGE event\n
 */
typedef struct acfg_wsupp_raw_message {
    a_char_t raw_message[128];                     /**< always, undecoded char data */
} acfg_wsupp_raw_message_t;

/**
 * @brief Structure returned on a ACFG_EV_WSUPP_RADIUS_RAW_MESSAGE event\n
 */
typedef struct acfg_wsupp_radius_message {
    a_uint8_t raw_message[1800];                     /**< always, undecoded char data */
} acfg_wsupp_radius_message_t;


/**
 * @brief Structure returned on a PROBE REQUEST Frame through IWEVASSOCREQIE event\n
 */
typedef struct acfg_probe_req {
    a_uint32_t len;
    a_uint8_t  *data;
} acfg_probe_req_t;

typedef struct acfg_wsupp_custom_message {
    a_uint8_t raw_message[500];                     /**< always, undecoded char data */
} acfg_wsupp_custom_message_t;

typedef struct acfg_wsupp_assoc {
    a_uint8_t addr[ACFG_MACADDR_LEN];
    a_char_t raw_message[128];                      /**< always, undecoded char data */
} acfg_wsupp_assoc_t;

typedef struct acfg_wsupp_eap_status {
    a_uint8_t addr[ACFG_MACADDR_LEN];
    a_char_t raw_message[128];                      /**< always, undecoded char data */
} acfg_wsupp_eap_t;

typedef struct acfg_pbc_ev {
    a_uint8_t ifname[ACFG_MAX_IFNAME];
    a_uint8_t data;
} acfg_pbc_ev_t;

typedef struct acfg_wsupp_wps_success {
    a_char_t raw_message[128];                      /**< always, undecoded char data */
} acfg_wsupp_wps_success_t;

typedef struct acfg_wsupp_wps_new_ap_settings {
    a_char_t raw_message[128];                      /**< always, undecoded char data */
} acfg_wsupp_wps_new_ap_settings_t;

typedef a_uint32_t acfg_tx_overflow_t;
typedef struct acfg_gpio {
    a_uint32_t num;
} acfg_gpio_t;

enum acfg_wdt_reason {
    ACFG_WDT_TARGET_ASSERT = 0x01,
    ACFG_WDT_REINIT_DONE = 0x02,
};
typedef struct acfg_wdt_event {
    acfg_reason_t           reason;
} acfg_wdt_event_t;

typedef a_uint32_t acfg_cac_start_t;
typedef a_uint32_t acfg_up_after_cac_t;

typedef struct acfg_kickout {
    a_uint8_t               macaddr[ACFG_MACADDR_LEN];/**< MAC Addr */
} acfg_kickout_t;

typedef struct acfg_assoc_failure {
    a_uint32_t     reason;
    a_uint8_t      macaddr[ACFG_MACADDR_LEN];/**< MAC Addr */
} acfg_assoc_failure_t;

enum acfg_diag_type {
    ACFG_DIAGNOSTICS_WARNING = 0x01,
    ACFG_DIAGNOSTICS_ERROR = 0x02,
    ACFG_DIAGNOSTICS_NORMAL = 0x04,
};

enum acfg_diag_status {
   ACFG_DIAGNOSTICS_DOWN = 0x01,
   ACFG_DIAGNOSTICS_DOWN_15_SEC = 0x02,
   ACFG_DIAGNOSTICS_DOWN_1_HR = 0x04,
   ACFG_DIAGNOSTICS_UP = 0x08,
};

typedef struct acfg_diag_event {
    a_uint32_t type;
    a_uint32_t status;
    a_uint32_t data_rate_threshold;
    a_uint8_t  macaddr[ACFG_MACADDR_LEN];/* MAC Addr */
    a_uint16_t power_level;
    a_uint8_t  rssi;
    a_char_t   mode[64];
    a_char_t   tstamp[32];
    a_uint8_t  channel_index;
    a_uint32_t tx_data_rate;
    a_uint8_t  mcs_index;
    a_uint8_t  chan_width;
    a_uint8_t  sgi;
    a_uint8_t  nss;
    a_uint8_t  airtime;
} acfg_diag_event_t;

#endif /* __ACFG_EVENT_TYPES_H */
