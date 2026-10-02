/*
 * Copyright (c) 2011-2014, Atheros Communications Inc.
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

/*
 * LMAC VAP specific offload interface functions for UMAC - for power and performance offload model
 */
#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "wmi_unified_api.h"
#include "ieee80211_api.h"
#include "umac_lmac_common.h"
#include "osif_private.h"
#if ATH_SUPPORT_GREEN_AP
#include "ath_green_ap.h"
#endif

#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS  (IEEE80211_INACT_RUN * IEEE80211_INACT_WAIT)
#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS          (DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS - 5)
#define DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MIN_IDLE_TIME_SECS          (DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS/2)
#if ATH_SUPPORT_WRAP
#include "ol_if_mat.h"
#endif

#if MESH_MODE_SUPPORT
#include <if_meta_hdr.h>
#endif

/*
 * FIX THIS - include the function prototype for ol_txrx_osif_vdev_register,
 * which is called from this file.
 * Once the call to ol_txrx_osif_vdev_register is moved to the OS shim
 * code, this ol_txrx_osif_api.h include should be removed.
 */
#include <ol_txrx_osif_api.h>
#include <ol_txrx_dbg.h>
#include <ol_txrx_api.h>
#include <ol_txrx_types.h>

#include "ieee80211_band_steering.h"

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#include <osif_nss_wifiol_vdev_if.h>
#endif

#define RC_2_RATE_IDX(_rc)        ((_rc) & 0x7)
#ifndef HT_RC_2_STREAMS
#define HT_RC_2_STREAMS(_rc)    ((((_rc) & 0x78) >> 3) + 1)
#endif

#define ONEMBPS 1000
#define MIN_IDLE_INACTIVE_TIME_SECS(val)          ((val - 5)/2)
#define MAX_IDLE_INACTIVE_TIME_SECS(val)          (val - 5)
#define MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS  5
#define MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS  (u_int16_t)~0

extern int ol_ath_set_vap_dscp_tid_map(struct ieee80211vap *vap);
#if MESH_MODE_SUPPORT
extern void ol_txrx_set_mesh_mode(ol_txrx_vdev_handle vdev, u_int32_t val);
#endif
extern int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);
#if ATH_SUPPORT_WRAP
extern unsigned int qwrap_enable;
#endif

#if ATH_PERF_PWR_OFFLOAD
static OS_TIMER_FUNC(ol_ath_vap_stop_timed_out);

/*
+legacy rate table for the MCAST/BCAST rate. This table is specific to peregrine
+chip, so its implemented here in the ol layer instead of the ieee layer.

+This table is created according to the discription mentioned in the
+wmi_unified.h file.

+Here the left hand side specify the rate and the right hand side specify the
+respective values which the target understands.
+*/

static const int legacy_11b_rate_ol[][2] = {
    {1000, 0x43},
    {2000, 0x42},
    {5500, 0x41},
    {11000, 0x40},
};

static const int legacy_11a_rate_ol[][2] = {
    {6000, 0x03},
    {9000, 0x07},
    {12000, 0x02},
    {18000, 0x06},
    {24000, 0x01},
    {36000, 0x05},
    {48000, 0x00},
    {54000, 0x04},
};

static const int legacy_11bg_rate_ol[][2] = {
    {1000, 0x43},
    {2000, 0x42},
    {5500, 0x41},
    {6000, 0x03},
    {9000, 0x07},
    {11000, 0x40},
    {12000, 0x02},
    {18000, 0x06},
    {24000, 0x01},
    {36000, 0x05},
    {48000, 0x00},
    {54000, 0x04},
};

static const int ht20_11n_rate_ol[][2] = {
    {6500,  0x80},
    {13000, 0x81},
    {19500, 0x82},
    {26000, 0x83},
    {39000, 0x84},
    {52000, 0x85},
    {58500, 0x86},
    {65000, 0x87},

    {13000,  0x90},
    {26000,  0x91},
    {39000,  0x92},
    {52000,  0x93},
    {78000,  0x94},
    {104000, 0x95},
    {117000, 0x96},
    {130000, 0x97},

    {19500,  0xa0},
    {39000,  0xa1},
    {58500,  0xa2},
    {78000,  0xa3},
    {117000, 0xa4},
    {156000, 0xa5},
    {175500, 0xa6},
    {195000, 0xa7},

    {26000,  0xb0},
    {52000,  0xb1},
    {78000,  0xb2},
    {104000, 0xb3},
    {156000, 0xb4},
    {208000, 0xb5},
    {234000, 0xb6},
    {260000, 0xb7},
};

static const int ht20_11ac_rate_ol[][2] = {
/* VHT MCS0-9 NSS 1 20 MHz */
    { 6500, 0xc0},
    {13000, 0xc1},
    {19500, 0xc2},
    {26000, 0xc3},
    {39000, 0xc4},
    {52000, 0xc5},
    {58500, 0xc6},
    {65000, 0xc7},
    {78000, 0xc8},
    {86500, 0xc9},

/* VHT MCS0-9 NSS 2 20 MHz */
    { 13000, 0xd0},
    { 26000, 0xd1},
    { 39000, 0xd2},
    { 52000, 0xd3},
    { 78000, 0xd4},
    {104000, 0xd5},
    {117000, 0xd6},
    {130000, 0xd7},
    {156000, 0xd8},
    {173000, 0xd9},

 /* HT MCS0-9 NSS 3 20 MHz */
    { 19500, 0xe0},
    { 39000, 0xe1},
    { 58500, 0xe2},
    { 78000, 0xe3},
    {117000, 0xe4},
    {156000, 0xe5},
    {175500, 0xe6},
    {195000, 0xe7},
    {234000, 0xe8},
    {260000, 0xe9},

 /* HT MCS0-9 NSS 4 20 MHz */
    { 26000, 0xf0},
    { 52000, 0xf1},
    { 78000, 0xf2},
    {104000, 0xf3},
    {156000, 0xf4},
    {208000, 0xf5},
    {234000, 0xf6},
    {260000, 0xf7},
    {312000, 0xf8},
    {344000, 0xf9},
};


/* WMI command interface functions */
static wmi_vdev_start_request_cmd *
wmi_unified_vdev_create_start_cmd(wmi_unified_t wmi_handle, u_int8_t if_id, struct ieee80211_channel *chan, u_int32_t freq, wmi_buf_t buf)
{
    wmi_vdev_start_request_cmd* cmd;
    u_int32_t chan_mode;

    static const u_int modeflags[] = {
        0,                            /* IEEE80211_MODE_AUTO           */
        MODE_11A,         /* IEEE80211_MODE_11A            */
        MODE_11B,         /* IEEE80211_MODE_11B            */
        MODE_11G,         /* IEEE80211_MODE_11G            */
        0,                            /* IEEE80211_MODE_FH             */
        0,                            /* IEEE80211_MODE_TURBO_A        */
        0,                            /* IEEE80211_MODE_TURBO_G        */
        MODE_11NA_HT20,   /* IEEE80211_MODE_11NA_HT20      */
        MODE_11NG_HT20,   /* IEEE80211_MODE_11NG_HT20      */
        MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40PLUS  */
        MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40MINUS */
        MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40PLUS  */
        MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40MINUS */
        MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40      */
        MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40      */
        MODE_11AC_VHT20,  /* IEEE80211_MODE_11AC_VHT20     */
        MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40PLUS */
        MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40MINUS*/
        MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40     */
        MODE_11AC_VHT80,  /* IEEE80211_MODE_11AC_VHT80     */
        MODE_11AC_VHT160, /* IEEE80211_MODE_11AC_VHT160    */
        MODE_11AC_VHT80_80,/* IEEE80211_MODE_11AC_VHT160   */
    };
    struct ol_ath_softc_net80211 *scn;

    scn = (struct ol_ath_softc_net80211 *)wmi_get_scn_handle(wmi_handle);

    cmd = (wmi_vdev_start_request_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;

    cmd->chan.mhz = freq;

    chan_mode = ieee80211_chan2mode(chan);
    WMI_SET_CHANNEL_MODE(&cmd->chan, modeflags[chan_mode]);

    cmd->chan.band_center_freq1 = 0;
    cmd->chan.band_center_freq2 = 0;

    if((chan_mode == IEEE80211_MODE_11AC_VHT80)|| (chan_mode == IEEE80211_MODE_11AC_VHT160) || (chan_mode == IEEE80211_MODE_11AC_VHT80_80)) {
            if (chan->ic_ieee < 20)
                cmd->chan.band_center_freq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                                                         chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_2GHZ);
            else
                cmd->chan.band_center_freq1 = ieee80211_ieee2mhz(&scn->sc_ic,
                                                         chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_5GHZ);
        if (chan_mode == IEEE80211_MODE_11AC_VHT80_80 || chan_mode == IEEE80211_MODE_11AC_VHT160)
            cmd->chan.band_center_freq2 = ieee80211_ieee2mhz(&scn->sc_ic,
                    chan->ic_vhtop_ch_freq_seg2, IEEE80211_CHAN_5GHZ);

    } else if((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) || (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
        (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS)) {
            cmd->chan.band_center_freq1 = freq + 10;
    } else if((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) || (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
        (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS)) {
            cmd->chan.band_center_freq1 = freq - 10;
    } else {
            cmd->chan.band_center_freq1 = freq;
    }

 /*
     * If the channel has DFS set, flip on radar reporting.
     *
     * It may be that this should only be done for IBSS/hostap operation
     * as this flag may be interpreted (at some point in the future)
     * by the firmware as "oh, and please do radar DETECTION."
     *
     * If that is ever the case we would insert the decision whether to
     * enable the firmware flag here.
     */
    if (IEEE80211_IS_CHAN_DFS(chan)) {
        WMI_SET_CHANNEL_FLAG(&cmd->chan, WMI_CHAN_FLAG_DFS);
    }

    if ((chan_mode == IEEE80211_MODE_11AC_VHT80_80) || ( chan_mode == IEEE80211_MODE_11AC_VHT160)) {
        if (IEEE80211_IS_CHAN_DFS_CFREQ2(chan)) {
            WMI_SET_CHANNEL_FLAG(&cmd->chan, WMI_CHAN_FLAG_DFS_CFREQ2);
        }
    }
    if (IEEE80211_IS_CHAN_HALF(chan)) {
        WMI_SET_CHANNEL_FLAG(&cmd->chan, WMI_CHAN_FLAG_HALF);
    }
    if (IEEE80211_IS_CHAN_QUARTER(chan)) {
        WMI_SET_CHANNEL_FLAG(&cmd->chan, WMI_CHAN_FLAG_QUARTER);
    }

    WMI_SET_CHANNEL_MIN_POWER(&cmd->chan, chan->ic_minpower);
    WMI_SET_CHANNEL_MAX_POWER(&cmd->chan, chan->ic_maxpower);
    WMI_SET_CHANNEL_REG_POWER(&cmd->chan, chan->ic_maxregpower);
    WMI_SET_CHANNEL_REG_CLASSID(&cmd->chan, chan->ic_regClassId);
    WMI_SET_CHANNEL_ANTENNA_MAX(&cmd->chan, chan->ic_antennamax);
    return cmd;
}

int
wmi_unified_vdev_start_send(wmi_unified_t wmi_handle, u_int8_t if_id, struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack, void *nl_handle)
{
    wmi_vdev_start_request_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_start_request_cmd);


    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd  = wmi_unified_vdev_create_start_cmd(wmi_handle, if_id, chan, freq, buf);
    cmd->disable_hw_ack = disable_hw_ack;

    if (!nl_handle) {
        printk("%s for vap %d (%p)\n",__func__, if_id, wmi_handle);
    }

    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_START_REQUEST_CMDID);
}
int
wmi_unified_vdev_restart_send(wmi_unified_t wmi_handle, u_int8_t if_id, struct ieee80211_channel *chan, u_int32_t freq, bool disable_hw_ack)
{
    wmi_vdev_start_request_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_start_request_cmd);


    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd  = wmi_unified_vdev_create_start_cmd(wmi_handle, if_id, chan, freq, buf);
    cmd->disable_hw_ack = disable_hw_ack;

    printk("%s for vap %d (%p) \n",__func__, if_id, wmi_handle);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_RESTART_REQUEST_CMDID);
}

int
wmi_unified_vdev_up_send(wmi_unified_t wmi_handle, u_int8_t if_id, u_int16_t  aid, u_int8_t bssid[IEEE80211_ADDR_LEN])
{
    wmi_vdev_up_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_up_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd = (wmi_vdev_up_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    cmd->vdev_assoc_id = aid;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(bssid, &cmd->vdev_bssid);
    printk("%s for vap %d (%p)\n",__func__, if_id, wmi_handle);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_UP_CMDID);
}
int
wmi_unified_vdev_down_send(wmi_unified_t wmi_handle, u_int8_t if_id)
{
    wmi_vdev_down_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_down_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd = (wmi_vdev_down_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    printk("%s for vap %d (%p)\n",__func__, if_id, wmi_handle);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_DOWN_CMDID);
}
int
wmi_unified_vdev_stop_send(wmi_unified_t wmi_handle, u_int8_t if_id, void *nl_handle)
{
    wmi_vdev_stop_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_stop_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd = (wmi_vdev_stop_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;

    if (!nl_handle) {
        printk("%s for vap %d (%p)\n",__func__, if_id, wmi_handle);
    }

    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_STOP_CMDID);
}
int
wmi_unified_vdev_create_send(wmi_unified_t wmi_handle, u_int8_t if_id,
                             u_int16_t type, u_int16_t subtype,
                             u_int8_t macaddr[IEEE80211_ADDR_LEN])
{
    wmi_vdev_create_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_create_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd = (wmi_vdev_create_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    cmd->vdev_type = type;
    cmd->vdev_subtype = subtype;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(macaddr, &cmd->vdev_macaddr);
    printk("%s: ID = %d Type = %d, Subtype = %d VAP Addr = %02x:%02x:%02x:%02x:%02x:%02x:\n",
                         __func__, if_id, type, subtype,
                         macaddr[0], macaddr[1], macaddr[2],
                         macaddr[3], macaddr[4], macaddr[5]);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_CREATE_CMDID);
}

int
wmi_unified_vdev_delete_send(wmi_unified_t wmi_handle, u_int8_t if_id)
{
    wmi_vdev_delete_cmd* cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_delete_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd = (wmi_vdev_delete_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    printk("%s for vap %d wmi_handle (%p)\n",__func__, if_id, wmi_handle);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_DELETE_CMDID);
}

#if QCA_AIRTIME_FAIRNESS
int
wmi_unified_vdev_atf_request_send(wmi_unified_t wmi_handle, u_int32_t param_value)
{
    /* Will be implemented when it is decided how to use it*/
    return EOK;
}
#endif

int
wmi_unified_vdev_set_param_send(wmi_unified_t wmi_handle, u_int8_t if_id,
                           u_int32_t param_id, u_int32_t param_value)
{
    wmi_vdev_set_param_cmd *cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_set_param_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return -1;
    }
    cmd = (wmi_vdev_set_param_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    cmd->param_id = param_id;
    cmd->param_value = param_value;
#if 0
    printk("Setting vdev param = %x, value = %u\n", param_id, param_value);
#endif
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_SET_PARAM_CMDID);
}

#if ATH_SUPPORT_NAC
int
wmi_unified_vdev_set_neighbour_rx(struct ieee80211vap *vap, wmi_unified_t wmi_handle, u_int8_t if_id,
                           u_int32_t idx, u_int32_t action, u_int32_t type, u_int8_t macaddr[IEEE80211_ADDR_LEN])
{
    wmi_vdev_filter_nrp_config_cmd *cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_vdev_filter_nrp_config_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return -1;
    }
    cmd = (wmi_vdev_filter_nrp_config_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    cmd->bssid_idx = idx;
    cmd->action = action;
    cmd->type = type;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(macaddr, &cmd->addr);
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s :vdev =%x, idx=%x, action=%x, macaddr[0][5]=%2x%2x", __func__, if_id, idx, action, macaddr[0],macaddr[5]);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_FILTER_NEIGHBOR_RX_PACKETS_CMDID);
}
#endif


int
wmi_unified_vdev_set_fwtest_param_send(wmi_unified_t wmi_handle,
                           u_int32_t arg, u_int32_t value)
{
    wmi_fwtest_set_param_cmd *cmd;
    wmi_buf_t buf;
    int len = sizeof(wmi_fwtest_set_param_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);

    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return -1;
    }

    cmd = (wmi_fwtest_set_param_cmd *)wmi_buf_data(buf);
    cmd->param_id = arg;
    cmd->param_value = value;

    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_FWTEST_CMDID);
}

int ol_get_rate_code(struct ieee80211_channel *chan, int val)
{
    uint32_t chan_mode;
    int i = 0, j = 0, found = 0, array_size = 0;
    int *rate_code = NULL;

    struct ol_rate_table {
        int *table;
        int size;
    } rate_table [3];

    if(chan == NULL)
        return EINVAL;

    OS_MEMZERO(&rate_table[0], sizeof(rate_table));

    chan_mode = ieee80211_chan2mode(chan);

    switch (chan_mode)
    {
        case IEEE80211_MODE_11B:
            {
                /* convert rate to index */
                rate_table[2].size = sizeof(legacy_11b_rate_ol)/sizeof(legacy_11b_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11b_rate_ol;
            }
            break;

        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
            {
                /* convert rate to index */
                rate_table[2].size = sizeof(legacy_11bg_rate_ol)/sizeof(legacy_11bg_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11bg_rate_ol;
            }
            break;

        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
            {
                /* convert rate to index */
                rate_table[2].size = sizeof(legacy_11a_rate_ol)/sizeof(legacy_11a_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11a_rate_ol;
            }
            break;

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
            {
                rate_table[0].size = sizeof(ht20_11ac_rate_ol)/sizeof(ht20_11ac_rate_ol[0]);
                rate_table[0].table = (int *)&ht20_11ac_rate_ol;
            }

        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
            {
                rate_table[1].size = sizeof(ht20_11n_rate_ol)/sizeof(ht20_11n_rate_ol[0]);
                rate_table[1].table = (int *)&ht20_11n_rate_ol;
            }

            if (IEEE80211_IS_CHAN_5GHZ(chan)) {
                rate_table[2].size = sizeof(legacy_11a_rate_ol)/sizeof(legacy_11a_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11a_rate_ol;
            } else {
                rate_table[2].size = sizeof(legacy_11bg_rate_ol)/sizeof(legacy_11bg_rate_ol[0]);
                rate_table[2].table = (int *)&legacy_11bg_rate_ol;
            }

            break;

        default:
        {
            printk("%s Invalid channel mode. \n\r",__func__);
            break;
        }
    }

    for (j = 2; ((j >= 0) && !found) && rate_table[j].table; j--) {
        array_size = rate_table[j].size;
        rate_code = rate_table[j].table;
        for (i = 0; i < array_size; i++) {
            /* Array Index 0 has the rate and 1 has the rate code.
               The variable rate has the rate code which must be converted to actual rate*/
            if (val == *rate_code) {
                val = *(rate_code + 1);
                found = 1;
                break;
            }
            rate_code += 2;
        }
    }

    if(!found) {
        return EINVAL;
    }
    return val;
}

static int
ol_ath_validate_tx_encap_type(struct ol_ath_softc_net80211 *scn,
        struct ieee80211vap *vap, u_int32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    if (!ic->ic_rawmode_support)
    {
        printk("Configuration capability not provided for this chipset\n");
        return 0;
    }

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
    {
        printk("Configuration capability available only for AP mode\n");
        return 0;
    }

#if !QCA_OL_SUPPORT_RAWMODE_TXRX
    if (val == 0) {
        printk("Valid values: 1 - Native Wi-Fi, 2 - Ethernet\n"
               "0 - RAW is unavailable\n");
        return 0;
    }
#endif

    if (val <= 2) {
        return 1;
    } else {
        printk("Valid values: 0 - RAW, 1 - Native Wi-Fi, 2 - Ethernet, "
               "%d is invalid\n", val);
        return 0;
    }
}

static int
ol_ath_validate_rx_decap_type(struct ol_ath_softc_net80211 *scn,
        struct ieee80211vap *vap, u_int32_t val)
{
    /* Though the body of this function is the same as
     * ol_ath_validate_tx_encap_type(), it is kept separate for future
     * flexibility.
     */

    struct ieee80211com *ic = vap->iv_ic;
    if (!ic->ic_rawmode_support)
    {
        printk("Configuration capability not provided for this chipset\n");
        return 0;
    }

    if (wlan_vap_get_opmode(vap) != IEEE80211_M_HOSTAP)
    {
        printk("Configuration capability available only for AP mode\n");
        return 0;
    }

#if !QCA_OL_SUPPORT_RAWMODE_TXRX
    if (val == 0) {
        printk("Valid values: 1 - Native Wi-Fi, 2 - Ethernet\n"
               "0 - RAW is unavailable\n");
        return 0;
    }
#endif

    if (val <= 2) {
        return 1;
    } else {
        printk("Valid values: 0 - RAW, 1 - Native Wi-Fi, 2 - Ethernet, "
               "%d is invalid\n", val);
        return 0;
    }
}

int
ol_rate_is_valid_basic(struct ieee80211vap *vap, u_int32_t rate)
{
    enum ieee80211_phymode mode = wlan_get_desired_phymode(vap);
    struct ieee80211_rateset *op_rs = &(vap->iv_op_rates[mode]);
    int i;
    int rs_rate,basic_rate;

    /* Find all basic rates */
    for (i=0; i < op_rs->rs_nrates; i++) {
        rs_rate = op_rs->rs_rates[i];
        /* Added this check for 11ng. Since 6,12 and 24 Mbps rates are not showing as basic rate as per the current code*/
        if (vap->iv_disabled_legacy_rate_set) {
            basic_rate = rs_rate & IEEE80211_RATE_VAL;
        } else {
            basic_rate = rs_rate & IEEE80211_RATE_BASIC;
        }
        if (basic_rate) {
            if (rate == ((rs_rate & IEEE80211_RATE_VAL) * 1000)/2) {
                return 1;
            }
        }
    }

    return 0;
}

/* Vap interface functions */
static int
ol_ath_vap_set_param(struct ieee80211vap *vap,
              ieee80211_param param, u_int32_t val)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    int retval = 0;

    /* Set the VAP param in the target */
    switch (param) {

        case IEEE80211_RTS_THRESHOLD:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_RTS_THRESHOLD, val);
        break;

        case IEEE80211_FRAG_THRESHOLD:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_FRAGMENTATION_THRESHOLD, val);
        break;


        case IEEE80211_BEACON_INTVAL:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_BEACON_INTERVAL, val);
        break;

        case IEEE80211_LISTEN_INTVAL:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_LISTEN_INTERVAL, val);
        break;

        case IEEE80211_ATIM_WINDOW:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_ATIM_WINDOW, val);
        break;

        case IEEE80211_DTIM_INTVAL:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_DTIM_PERIOD, val);
        break;

        case IEEE80211_BMISS_COUNT_RESET:
         /* this is mainly under assumsion that if this number of  */
         /* beacons are not received then HW is hung anf HW need to be resett */
         /* target will use its own method to detect and reset the chip if required. */
            retval = 0;
        break;

        case IEEE80211_BMISS_COUNT_MAX:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_BMISS_COUNT_MAX, val);
        break;

        case IEEE80211_FEATURE_WMM:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_FEATURE_WMM, val);
        break;

        case IEEE80211_FEATURE_WDS:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_WDS, val);
        break;

        case IEEE80211_CHWIDTH:
            retval = wmi_unified_vdev_set_param_send(
                         scn->wmi_handle, avn->av_if_id,
                         WMI_VDEV_PARAM_CHWIDTH, val);
        break;

        case IEEE80211_FIXED_NSS:
             wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_NSS, vap->iv_nss);
        break;

        case IEEE80211_FIXED_RATE:
           {
                u_int8_t preamble, nss, rix;
                /* Note: Event though val is 32 bits, only the lower 8 bits matter */
                if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_NONE) {
                    val = WMI_FIXED_RATE_NONE;
                }
                else {
                    rix = RC_2_RATE_IDX(vap->iv_fixed_rateset);
                    if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_MCS) {
                        preamble = WMI_RATE_PREAMBLE_HT;
                        nss = HT_RC_2_STREAMS(vap->iv_fixed_rateset) -1;
                    }
                    else {
                        nss = 0;
                        rix = RC_2_RATE_IDX(vap->iv_fixed_rateset);

                        if(scn->burst_enable)
                        {
                            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                                                WMI_PDEV_PARAM_BURST_ENABLE, 0);

                            if (retval == EOK) {
                                scn->burst_enable = 0;
                            }
                        }

						if (vap->iv_fixed_rateset & 0x10) {
							preamble = WMI_RATE_PREAMBLE_CCK;
							if(rix != 0x3)
							 /* Enable Short preamble always for CCK except 1mbps*/
							rix |= 0x4;
                        }
                        else {
                            preamble = WMI_RATE_PREAMBLE_OFDM;
                        }
                    }
                    val = (preamble << 6) | (nss << 4) | rix;
                }
                retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                              WMI_VDEV_PARAM_FIXED_RATE, val);
           }
        break;
        case IEEE80211_FIXED_VHT_MCS:
           {
                if (vap->iv_fixed_rate.mode == IEEE80211_FIXED_RATE_VHT) {
                    val = (WMI_RATE_PREAMBLE_VHT << 6) | ((vap->iv_nss -1) << 4) | vap->iv_vht_fixed_mcs;
                }
                else {
                    /* Note: Event though val is 32 bits, only the lower 8 bits matter */
                    val = WMI_FIXED_RATE_NONE;
                }
                retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                              WMI_VDEV_PARAM_FIXED_RATE, val);
           }
        break;
        case IEEE80211_FEATURE_APBRIDGE:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                              WMI_VDEV_PARAM_INTRA_BSS_FWD, val);
        break;

        case IEEE80211_SHORT_GI:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                              WMI_VDEV_PARAM_SGI, val);
        break;

        case IEEE80211_SECOND_CENTER_FREQ :
        if (scn->target_type == TARGET_TYPE_QCA9984 || scn->target_type == TARGET_TYPE_QCA9888) {

            if( vap->iv_des_mode == IEEE80211_MODE_11AC_VHT80_80) {
                if(val > 5170) {
                    vap->iv_des_cfreq2 = ieee80211_mhz2ieee(ic,val,0);
                }
                else {
                    vap->iv_des_cfreq2 = val;
                }

                printk("Desired cfreq2 is %d. Please set primary 20 MHz channel for cfreq2 setting to take effect \n", vap->iv_des_cfreq2);
            }
            else {
                printk("command not applicable for this mode \n");
                return -EINVAL;
            }
        }
        else {
            printk(" Command not applicable for this chip \n");
            return -EINVAL;
        }

        break;

        case IEEE80211_SUPPORT_LDPC:
        {
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                              WMI_VDEV_PARAM_LDPC, val);
        }
            break;

        case IEEE80211_SUPPORT_TX_STBC:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                              WMI_VDEV_PARAM_TX_STBC, val);
        break;

        case IEEE80211_SUPPORT_RX_STBC:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                          WMI_VDEV_PARAM_RX_STBC, val);
        break;
        case IEEE80211_DEFAULT_KEYID:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                          WMI_VDEV_PARAM_DEF_KEYID, val);
        break;
#if UMAC_SUPPORT_PROXY_ARP
        case IEEE80211_PROXYARP_CAP:
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                          WMI_VDEV_PARAM_MCAST_INDICATE, val);
            retval |= wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                          WMI_VDEV_PARAM_DHCP_INDICATE, val);
        break;
#endif /* UMAC_SUPPORT_PROXY_ARP */
        case IEEE80211_RUN_INACT_TIMEOUT:
        {
            if (val >= MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS && val <= MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS)
            {
                u_int16_t  max_unresponsive_time_secs = val;
                u_int16_t  max_idle_inactive_time_secs = MAX_IDLE_INACTIVE_TIME_SECS(val);
                u_int16_t  min_idle_inactive_time_secs = MIN_IDLE_INACTIVE_TIME_SECS(val);
                /* Setting iv_inact_run, for retrieval using iwpriv get_inact command */
                vap->iv_inact_run = max_unresponsive_time_secs;
                retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,
                        avn->av_if_id, WMI_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
                        min_idle_inactive_time_secs);
                retval |= wmi_unified_vdev_set_param_send(scn->wmi_handle,
                        avn->av_if_id, WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
                        max_idle_inactive_time_secs);
                retval |= wmi_unified_vdev_set_param_send(scn->wmi_handle,
                        avn->av_if_id, WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
                        max_unresponsive_time_secs);
            }
            else
            {
                printk("\nRange allowed is : %d to %d",MAX_UNRESPONSIVE_TIME_MIN_THRESHOLD_SECS, MAX_UNRESPONSIVE_TIME_MAX_THRESHOLD_SECS);
            }
        }
        break;
	    case IEEE80211_MCAST_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_mcast_rate_config_defered = TRUE;
                printk("Configuring MCAST RATE is deffered as channel is not yet set for VAP \n");
                break;
            }
            if(IEEE80211_IS_CHAN_5GHZ(chan)&&val<6000){
                printk("%s: MCAST RATE should be at least 6000(kbps) for 5G\n",__func__);
                retval = -EINVAL;
                break;
            }

            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = -EINVAL;
                break;
            }
            retval = wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                    WMI_VDEV_PARAM_MCAST_DATA_RATE, value);
            if(retval == 0 ) {
                vap->iv_mcast_rate_config_defered = FALSE;
                printk("%s: Now supported MCAST RATE is %d(kbps) and rate code: 0x%x\n",
                        __func__, val, value);
            }
        }
        break;
        case IEEE80211_BCAST_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_bcast_rate_config_defered = TRUE;
                printk("Configuring BCAST RATE is deffered as channel is not yet set for VAP \n");
                break;
            }
            if(IEEE80211_IS_CHAN_5GHZ(chan)&&val<6000){
                printk("%s: BCAST RATE should be at least 6000(kbps) for 5G\n",__func__);
                retval = -EINVAL;
                break;
            }

            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = -EINVAL;
                break;
            }
            retval = wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                     WMI_VDEV_PARAM_BCAST_DATA_RATE, value);
            if (retval == 0) {
                vap->iv_bcast_rate_config_defered = FALSE;
                printk("%s: Now supported BCAST RATE is %d(kbps) and rate code: 0x%x\n",
                        __func__, val, value);
            }
        }
        break;
        case IEEE80211_MGMT_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int value;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                vap->iv_mgt_rate_config_defered = TRUE;
                printk("Configuring MGMT RATE is deffered as channel is not yet set for VAP \n");
                break;
            }
            if(IEEE80211_IS_CHAN_5GHZ(chan)&&val<6000){
                printk("%s: MGMT RATE should be at least 6000(kbps) for 5G\n",__func__);
                retval = EINVAL;
                break;
            }
            if(!ol_rate_is_valid_basic(vap,val)){
                printk("%s: rate %d is not valid. \n",__func__,val);
                retval = EINVAL;
                break;
            }
            value = ol_get_rate_code(chan, val);
            if(value == EINVAL) {
                retval = EINVAL;
                break;
            }
            retval = wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                     WMI_VDEV_PARAM_MGMT_RATE, value);
            if (retval == 0){
                vap->iv_mgt_rate_config_defered = FALSE;
                printk("%s: Now supported MGMT RATE is %d(kbps) and rate code: 0x%x\n",
                     __func__, val, value);
            }
        }
        break;
        case IEEE80211_RTSCTS_RATE:
        {
            struct ieee80211_channel *chan = vap->iv_des_chan[vap->iv_des_mode];
            int rtscts_rate;

            if ((!chan) || (chan == IEEE80211_CHAN_ANYC)) {
                adf_os_print("Configuring  RATE for RTS and CTS is deffered as channel is not yet set for VAP \n");
                break;
            }

            if(!ol_rate_is_valid_basic(vap,val)){
                adf_os_print("%s: Rate %d is not valid. \n",__func__,val);
                retval = EINVAL;
                break;
            }
            rtscts_rate = ol_get_rate_code(chan, val);
            if(rtscts_rate == EINVAL) {
               retval = EINVAL;
                break;
            }
            retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                        WMI_VDEV_PARAM_RTS_FIXED_RATE,rtscts_rate);
            if (retval == 0)
                adf_os_print("%s:Now supported CTRL RATE is : %d kbps and rate code : 0x%x\n",__func__,val,rtscts_rate);
        }
        break;

        case IEEE80211_MAX_AMPDU:
        /*should be moved to vap in future & add wmi cmd to update vdev*/
            retval = 0;
		break;
        case IEEE80211_VHT_MAX_AMPDU:
        /*should be moved to vap in future & add wmi cmd to update vdev*/
            retval = 0;
        break;

        case IEEE80211_VHT_SUBFEE:
        case IEEE80211_VHT_MUBFEE:
        case IEEE80211_VHT_SUBFER:
        case IEEE80211_VHT_MUBFER:
        case IEEE80211_VHT_BF_STS_CAP:
        case IEEE80211_SUPPORT_IMPLICITBF:
        case IEEE80211_VHT_BF_SOUNDING_DIM:
        {
            wmi_vdev_txbf_cap txbf_en;
            txbf_en.txbf_cap = 0;
            WMI_TXBF_CONF_SU_TX_BFEE_SET(txbf_en.txbf_cap,vap->iv_vhtsubfee);
            WMI_TXBF_CONF_MU_TX_BFEE_SET(txbf_en.txbf_cap,vap->iv_vhtmubfee);
            WMI_TXBF_CONF_SU_TX_BFER_SET(txbf_en.txbf_cap,vap->iv_vhtsubfer);
            WMI_TXBF_CONF_MU_TX_BFER_SET(txbf_en.txbf_cap,vap->iv_vhtmubfer);
            WMI_TXBF_CONF_STS_CAP_SET(txbf_en.txbf_cap,vap->iv_vhtbfeestscap);
            WMI_TXBF_CONF_IMPLICIT_BF_SET(txbf_en.txbf_cap,  vap->iv_implicitbf);
            WMI_TXBF_CONF_BF_SND_DIM_SET(txbf_en.txbf_cap, vap->iv_vhtbfsoundingdim);

            printk("su bfee %d mu bfee %d su bfer %d mu bfer %d impl bf %d sounding dim %d\n",
               WMI_TXBF_CONF_SU_TX_BFEE_GET(txbf_en.txbf_cap), WMI_TXBF_CONF_MU_TX_BFEE_GET(txbf_en.txbf_cap),
               WMI_TXBF_CONF_SU_TX_BFER_GET(txbf_en.txbf_cap), WMI_TXBF_CONF_MU_TX_BFER_GET(txbf_en.txbf_cap),
               WMI_TXBF_CONF_IMPLICIT_BF_GET(txbf_en.txbf_cap),WMI_TXBF_CONF_BF_SND_DIM_GET(txbf_en.txbf_cap));

            retval = wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                                             WMI_VDEV_PARAM_TXBF, txbf_en.txbf_cap);

        }
        break;
#if QCA_AIRTIME_FAIRNESS
        case  IEEE80211_ATF_OPT:
        retval = ol_ath_set_atf(ic);
        break;
        case IEEE80211_ATF_PEER_REQUEST:
        retval = ol_ath_send_atf_peer_request(ic);
        break;
        case IEEE80211_ATF_PER_UNIT:
        retval = wmi_unified_vdev_atf_request_send(scn->wmi_handle, val);
        break;
        case IEEE80211_ATF_DYNAMIC_ENABLE:
        retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                WMI_PDEV_PARAM_ATF_DYNAMIC_ENABLE, val);
        break;
        case  IEEE80211_ATF_GROUPING:
        retval = ol_ath_set_atf_grouping(ic);
        break;
        case IEEE80211_BWF_PEER_REQUEST:
        retval = ol_ath_set_bwf(ic);
        break;
        case IEEE80211_ATF_SSID_SCHED_POLICY:
        retval = wmi_unified_vdev_set_param_send(scn->wmi_handle, avn->av_if_id, WMI_VDEV_PARAM_ATF_SSID_SCHED_POLICY, val);
        break;

#endif

#if ATH_SUPPORT_IQUE
        case IEEE80211_ME:
#if ATH_SUPPORT_ME_FW_BASED
	{
            struct ol_txrx_pdev_t *pdev;
            u_int16_t allocated;

	    /* On DA, mode 5 represents hifi, target has no special mode for hifi.
	       In target, mode 1 drops the frame if no mcast group is found.
	       Mode 1 need to be set in fw for hyfi, as hyfi needs igmp src filtering */
	    if(val == 5) {
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
                ic->ic_mcast_group_update(ic, IGMP_ACTION_ADD_MEMBER, IGMP_WILDCARD_SINGLE, (u_int8_t *)&ic->ic_hmmcs[0].ip,
                                              IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[0].mask, vap->iv_unit);
                ic->ic_mcast_group_update(ic, IGMP_ACTION_ADD_MEMBER, IGMP_WILDCARD_SINGLE, (u_int8_t *)&ic->ic_hmmcs[1].ip,
                                              IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[1].mask, vap->iv_unit);
                ic->ic_mcast_group_update(ic, IGMP_ACTION_ADD_MEMBER, IGMP_WILDCARD_SINGLE, (u_int8_t *)&ic->ic_hmmcs[2].ip,
                                              IGMP_IP_ADDR_LENGTH, NULL, 0, 0, NULL, (u_int8_t *)&ic->ic_hmmcs[2].mask, vap->iv_unit);
#endif/*ATH_SUPPORT_HYFI_ENHANCEMENTS*/
                val = 1;
	    }

            /* get the pdev from the vap handle */
	    pdev = scn->pdev_txrx_handle;

	    /* Allocate the buffers for Mcast to unicast enhancement valid values 0,1,2; 0-disabled*/
        if (val != 0) {
            /* Allocate buffers only when VoW is not enabled.
             * Incase of VoW, it is allocated dynamically when the group gets added
             */
            if( !(scn->vow_config >> 16) ) {
                /* Mcast enhancement enabled, so allocate buffers */
                ic->ic_desc_alloc_and_mark_for_mcast_clone(ic, MAX_BLOCKED_MCAST_DESC);
            }
	    } else {
                /* Mcast enhancement disabled, remove allocated buffer only in the event handler,
                 * but inform target to send event back once the target buffers are released.
                 * This is done to avoid host sending more packet before target releases the buffers
                 * used for mcast cloning.
                 */
                allocated = ic->ic_get_mcast_buf_allocated_marked(ic);
                /* We are cleaning up. No need to allocate any pending desc requests*/
                scn->pend_desc_addition = 0;
                ic->ic_desc_free_and_unmark_for_mcast_clone(ic, allocated);
                printk("%s: VAP Mcast to Unicast buffer release (cmd): %u\n", __func__, allocated);
            }

            vap->iv_me->mc_mcast_enable = val;
	    retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
			    WMI_VDEV_PARAM_MCAST2UCAST_SET, !!val);

            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
				    WMI_PDEV_PARAM_SET_MCAST2UCAST_MODE, val);
	    printk("%s: VAP param is now supported param:%u value:%u\n", __func__, param, val);
	}
#else
    {
        if( val != 0 ) {
            ol_tx_me_alloc_descriptor(scn->pdev_txrx_handle);
        } else {
            vap->iv_me->mc_mcast_enable = 0;
	    ol_tx_me_free_descriptor(scn->pdev_txrx_handle);
        }
#if ATH_MCAST_HOST_INSPECT
        retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
                                      WMI_VDEV_PARAM_MCAST_INDICATE, val);
#endif/*ATH_MCAST_HOST_INSPECT*/
    }
#endif /*ATH_SUPPORT_ME_FW_BASED*/
	break;
#endif /* ATH_SUPPORT_IQUE */

	case IEEE80211_FEATURE_AMPDU:
#if defined(TEMP_AGGR_CFG)
            retval = ol_txrx_aggr_cfg(vap->iv_txrx_handle, val, 0);
            ic->ic_vht_ampdu = val;
#endif /* TEMP_AGGR_CFG */
    break;
        case IEEE80211_ENABLE_RTSCTS:
             wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                     WMI_VDEV_PARAM_ENABLE_RTSCTS, val);
        break;
        case IEEE80211_RC_NUM_RETRIES:
            wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                    WMI_VDEV_PARAM_RC_NUM_RETRIES, vap->iv_rc_num_retries);
        break;
#if WDS_VENDOR_EXTENSION
        case IEEE80211_WDS_RX_POLICY:
            if ((ieee80211vap_get_opmode(vap) == IEEE80211_M_HOSTAP) ||
                (ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)) {
                ol_txrx_set_wds_rx_policy(vap->iv_txrx_handle, val & WDS_POLICY_RX_MASK);
            }
        break;
#endif
        case IEEE80211_FEATURE_HIDE_SSID:
             if(val) {
                 if(!IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                     IEEE80211_VAP_HIDESSID_ENABLE(vap);
                 }
             } else {
                 if(IEEE80211_VAP_IS_HIDESSID_ENABLED(vap)) {
                     IEEE80211_VAP_HIDESSID_DISABLE(vap);
                 }
             }
             retval = 0;
             break;
        case IEEE80211_FEATURE_PRIVACY:
             if(val) {
                 if(!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
                     IEEE80211_VAP_PRIVACY_ENABLE(vap);
                 }
             } else {
                 if(IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
                     IEEE80211_VAP_PRIVACY_DISABLE(vap);
                 }
             }
             retval = 0;
             break;
        case IEEE80211_FEATURE_DROP_UNENC:
             if(val) {
                if(!IEEE80211_VAP_IS_DROP_UNENC(vap)) {
                    IEEE80211_VAP_DROP_UNENC_ENABLE(vap);
                }
             } else {
                if(IEEE80211_VAP_IS_DROP_UNENC(vap)) {
                    IEEE80211_VAP_DROP_UNENC_DISABLE(vap);
                }
             }
             ic->ic_set_dropunenc(vap, val);
             retval = 0;
             break;
        case IEEE80211_SHORT_PREAMBLE:
             if(val) {
                 if(!IEEE80211_IS_SHPREAMBLE_ENABLED(ic)) {
                     IEEE80211_ENABLE_SHPREAMBLE(ic);
                 }
             } else {
                 if(IEEE80211_IS_SHPREAMBLE_ENABLED(ic)) {
                     IEEE80211_DISABLE_SHPREAMBLE(ic);
                 }
             }
             wmi_unified_vdev_set_param_send(scn->wmi_handle, avn->av_if_id,
                    WMI_VDEV_PARAM_PREAMBLE, (val) ? WMI_VDEV_PREAMBLE_SHORT : WMI_VDEV_PREAMBLE_LONG);
             retval = 0;
             break;
        case IEEE80211_PROTECTION_MODE:
            if(val)
                IEEE80211_ENABLE_PROTECTION(ic);
            else
                IEEE80211_DISABLE_PROTECTION(ic);
            ic->ic_protmode = val;
            ic->ic_update_protmode(ic);
            retval = 0;
            break;
        case IEEE80211_SHORT_SLOT:
            if (val) {
                ieee80211_set_shortslottime(ic, 1);
            } else {
                ieee80211_set_shortslottime(ic, 0);
            }
            retval = 0;
            break;

        case IEEE80211_SET_CABQ_MAXDUR:
            wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                    WMI_VDEV_PARAM_CABQ_MAXDUR, val);
        break;

        case IEEE80211_FEATURE_MFP_TEST:
            wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                    WMI_VDEV_PARAM_MFPTEST_SET, val);
        break;

        case IEEE80211_VHT_SGIMASK:
             wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_VHT_SGIMASK, val);
        break;

        case IEEE80211_VHT80_RATEMASK:
             wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_VHT80_RATEMASK, val);
        break;

        case IEEE80211_VAP_RX_DECAP_TYPE:
        {
            enum htt_pkt_type pkt_type;

            if (!ol_ath_validate_rx_decap_type(scn, vap, val)) {
                retval = EINVAL;
            } else {
                retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,
                            avn->av_if_id,
                            WMI_VDEV_PARAM_RX_DECAP_TYPE, val);

                if (retval == 0) {
                    vap->iv_rx_decap_type = val;

                    if(val == 0) {
                        pkt_type = htt_pkt_type_raw;
                        printk("Setting Rx Decap type to 0 (Raw)\n");
                    } else if(val == 1) {
                        pkt_type = htt_pkt_type_native_wifi;
                        printk("Setting Rx Decap type to 1 (Native Wi-Fi)\n");
                    } else {
                        pkt_type = htt_pkt_type_ethernet;
                        printk("Setting Rx Decap type to 2 (Ethernet)\n");
                    }

                    ol_txrx_set_vdev_rx_decap_type(vap->iv_txrx_handle, pkt_type);
               } else
                    printk("Error %d setting param "
                           "WMI_VDEV_PARAM_RX_DECAP_TYPE with val %u\n",
                           retval,
                           val);
                }
        }
        break;

        case IEEE80211_VAP_TX_ENCAP_TYPE:
        {
            enum htt_pkt_type pkt_type;

            if (!ol_ath_validate_tx_encap_type(scn, vap, val)) {
                retval = EINVAL;
            } else {
                retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,
                            avn->av_if_id,
                            WMI_VDEV_PARAM_TX_ENCAP_TYPE, val);

                if (retval == 0) {
                    vap->iv_tx_encap_type = val;

                    if (val == 0) {
                        pkt_type = htt_pkt_type_raw;
                        printk("Setting Tx Encap type to 0 (Raw)\n");
                    } else if (val == 1) {
                        pkt_type = htt_pkt_type_native_wifi;
                        printk("Setting Tx Encap type to 1 (Native Wi-Fi)\n");
                    } else {
                        pkt_type = htt_pkt_type_ethernet;
                        printk("Setting Tx Encap type to 2 (Ethernet)\n");
                    }

                    ol_txrx_set_tx_encap_type(vap->iv_txrx_handle, pkt_type);
                } else {
                    printk("Error %d setting param "
                           "WMI_VDEV_PARAM_TX_ENCAP_TYPE with val %u\n",
                           retval,
                           val);
                }
            }
        }
        break;

        case IEEE80211_BW_NSS_RATEMASK:
             wmi_unified_vdev_set_param_send( scn->wmi_handle,avn->av_if_id,
                         WMI_VDEV_PARAM_BW_NSS_RATEMASK, val);
        break;

        case IEEE80211_RX_FILTER_MONITOR:
             wlan_set_monitor_filter(ic,val);
        break;

#if ATH_SUPPORT_NAC
        case IEEE80211_RX_FILTER_NEIGHBOUR_PEERS_MONITOR:
             ol_txrx_set_filter_neighbour_peers(scn->pdev_txrx_handle, val);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
             osif_nss_ol_vdev_set_cfg(vap->iv_txrx_handle, OSIF_NSS_WIFI_VDEV_FILTER_NEIGH_PEERS);
#endif
             IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s: Monitor Invalid Peers Filter Set Val=%d \n", __func__, val);
        break;
#endif

        default:
            /*printk("%s: VAP param unsupported param:%u value:%u\n", __func__,
                    param, val);*/
        break;
    }

    return(retval);
}

static int16_t ol_ath_vap_dyn_bw_rts(struct ieee80211vap *vap, int param)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    int retval = 0;

    retval = wmi_unified_vdev_set_param_send(scn->wmi_handle,avn->av_if_id,
            WMI_VDEV_PARAM_DISABLE_DYN_BW_RTS, param);
    return retval;
}

int
wmi_unified_vdev_config_ratemask(wmi_unified_t wmi_handle, u_int8_t if_id,
                                 u_int8_t type, u_int32_t lower32, u_int32_t higher32)
{
   wmi_vdev_config_ratemask *cmd;
   wmi_buf_t buf;
   int len = sizeof(wmi_vdev_config_ratemask);
   buf = wmi_buf_alloc(wmi_handle, len);
   if (!buf) {
       printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
       return -1;
   }
    cmd = (wmi_vdev_config_ratemask *)wmi_buf_data(buf);
    cmd->vdev_id = if_id;
    cmd->type    = type;
    cmd->mask_lower32 = lower32;
    cmd->mask_higher32 = higher32;
    printk("Setting vdev ratemask vdev id = 0x%X, type = 0x%X,mask_l32 = 0x%X mask_h32 = 0x%X\n",
            if_id, cmd->type, lower32, higher32);
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_RATEMASK_CMDID);
}

static int
ol_ath_vap_set_ratemask(struct ieee80211vap *vap,
            			u_int8_t preamble, u_int32_t mask_lower32, u_int32_t mask_higher32)
{
    /* higher 32 bit is reserved for beeliner*/
    switch (preamble) {
        case 0:
            vap->iv_ratemask_default = 0;
            vap->iv_legacy_ratemasklower32 = mask_lower32;
            break;
        case 1:
            vap->iv_ratemask_default = 0;
            vap->iv_ht_ratemasklower32 = mask_lower32;
            break;
        case 2:
            vap->iv_ratemask_default = 0;
            vap->iv_vht_ratemasklower32 = mask_lower32;
            vap->iv_vht_ratemaskhigher32 = mask_higher32;
            break;
        default:
            return EINVAL;
            break;
    }
    return ENETRESET;
}

int
wmi_unified_vdev_install_key_send(wmi_unified_t wmi_handle, u_int8_t if_id,
                                  const struct ieee80211_key *ieee_key,
                                   u_int8_t macaddr[IEEE80211_ADDR_LEN], u_int8_t def_keyid, u_int8_t force_none)
{
    wmi_vdev_install_key_cmd *cmd;
    wmi_buf_t buf;
    /* length depends on ieee key length */
    int len = sizeof(wmi_vdev_install_key_cmd) + ieee_key->wk_keylen;
    const struct ieee80211_cipher *ieee_cip = ieee_key->wk_cipher;
    u_int8_t    wmi_cipher_type;
    int i;

    /* Cipher MAP has to be in the same order as ieee80211_cipher_type */
    static const u_int8_t wmi_ciphermap[] = {
        WMI_CIPHER_WEP,         /* IEEE80211_CIPHER_WEP     */
        WMI_CIPHER_TKIP,        /* IEEE80211_CIPHER_TKIP    */
        WMI_CIPHER_AES_OCB,     /* IEEE80211_CIPHER_AES_OCB */
        WMI_CIPHER_AES_CCM,     /* IEEE80211_CIPHER_AES_CCM */
#if ATH_SUPPORT_WAPI
       WMI_CIPHER_WAPI,        /* IEEE80211_CIPHER_WAPI    */
#else
       (u_int8_t) 0xff,                 /* IEEE80211_CIPHER_WAPI    */
#endif
       WMI_CIPHER_CKIP,         /* IEEE80211_CIPHER_CKIP    */
       WMI_CIPHER_AES_CMAC,
       WMI_CIPHER_AES_CCM,     /* IEEE80211_CIPHER_AES_CCM 256 */
       WMI_CIPHER_AES_CMAC,
       WMI_CIPHER_AES_GCM,      /* IEEE80211_CIPHER_AES_GCM */
       WMI_CIPHER_AES_GCM,      /* IEEE80211_CIPHER_AES_GCM 256 */
       WMI_CIPHER_AES_GMAC,
       WMI_CIPHER_AES_GMAC,
       WMI_CIPHER_NONE,         /* IEEE80211_CIPHER_NONE    */
   };

	if (force_none == 1) {
        wmi_cipher_type = WMI_CIPHER_NONE;
	} else if ((ieee_key->wk_flags & IEEE80211_KEY_SWCRYPT) == 0) {
       KASSERT(ieee_cip->ic_cipher < (sizeof(wmi_ciphermap)/sizeof(wmi_ciphermap[0])),
               ("invalid cipher type %u", ieee_cip->ic_cipher));
       wmi_cipher_type = wmi_ciphermap[ieee_cip->ic_cipher];
    } else
        wmi_cipher_type = WMI_CIPHER_NONE;

    /* ieee_key length does not have mic keylen */
    if ((wmi_cipher_type == WMI_CIPHER_TKIP) || (wmi_cipher_type == WMI_CIPHER_WAPI))
        len = len + IEEE80211_MICBUF_SIZE;

    len = roundup(len,sizeof(u_int32_t));
    buf = wmi_buf_alloc(wmi_handle, len);
    if (!buf) {
        printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ENOMEM;
    }
    cmd = (wmi_vdev_install_key_cmd *)wmi_buf_data(buf);

    cmd->vdev_id = if_id;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(macaddr, &cmd->peer_macaddr);

    /* Mapping ieee key flags to WMI key flags */
    if(ieee_key->wk_flags & IEEE80211_KEY_GROUP) {
        cmd->key_flags |= GROUP_USAGE;
        /* send the ieee keyix for multicast */
        cmd->key_ix = ieee_key->wk_keyix;
    }
    else if(ieee_key->wk_flags & (IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT)) {
        cmd->key_flags |= PAIRWISE_USAGE;
        /* Target expects keyix 0 for unicast
           other than static wep cipher */
        if(ieee_key->wk_keyix >= (IEEE80211_WEP_NKID +1))
            cmd->key_ix = 0;
        else
            cmd->key_ix = ieee_key->wk_keyix;
    }
    /* If this WEP key is the default xmit key, TX_USAGE flag is enabled */
    if(def_keyid == 1) {
        cmd->key_flags |= TX_USAGE;
    }
        cmd->key_len = ieee_key->wk_keylen;
        cmd->key_cipher = wmi_cipher_type;
    /* setting the mic lengths. Just Added for TKIP alone */
    if((wmi_cipher_type == WMI_CIPHER_TKIP) || (wmi_cipher_type == WMI_CIPHER_WAPI)) {
        cmd->key_txmic_len= 8;
        cmd->key_rxmic_len= 8;
    }

    /* target will use the same rsc counter for
       various tids from from ieee key rsc */
    if ((wmi_cipher_type == WMI_CIPHER_TKIP) || (wmi_cipher_type == WMI_CIPHER_AES_OCB)
        || (wmi_cipher_type == WMI_CIPHER_AES_CCM))
    {
        OS_MEMCPY(&cmd->key_rsc_counter, &ieee_key->wk_keyrsc[0], sizeof(ieee_key->wk_keyrsc[0]));
        OS_MEMCPY(&cmd->key_tsc_counter, &ieee_key->wk_keytsc, sizeof(ieee_key->wk_keytsc));
    }
#ifdef ATH_SUPPORT_WAPI
    if (wmi_cipher_type == WMI_CIPHER_WAPI) {
        int j;
       /* For WAPI, TSC and RSC has to be initialized with predefined value.
          Here, Indicating TSC, RSC to target as part of set key message
        */
        /* since wk_recviv and wk_txiv initialized in reverse order, Before
           indicating the Target FW, Reversing TSC and RSC
         */
        for(i=(WPI_IV_LEN-1),j=0;i>=0;i--,j++)
        *(((u_int8_t *)&cmd->wpi_key_rsc_counter)+j) = ieee_key->wk_recviv[i];

        for(i=(WPI_IV_LEN/4-1),j=0;i>=0;i--,j++)
        *(((u_int32_t *)&cmd->wpi_key_tsc_counter)+j) = ieee_key->wk_txiv[i];


       printk("RSC:");
       for(i=0; i<16; i++)
         printk("0x%x ",*(((u_int8_t *)&cmd->wpi_key_rsc_counter)+i));
        printk("\n");

       printk("TSC:");
       for(i=0; i<16; i++)
         printk("0x%x ",*(((u_int8_t *)&cmd->wpi_key_tsc_counter)+i));
        printk("\n");
    }
#endif

#ifdef BIG_ENDIAN_HOST
    {
        /* for big endian host, copy engine byte_swap is enabled
         * But the key data content is in network byte order
         * Need to byte swap the key data content - so when copy engine
         * does byte_swap - target gets key_data content in the correct order
         */
        int i;
        u_int32_t *destp, *srcp;
        destp = (u_int32_t *)cmd->key_data;
        srcp =  (u_int32_t *)ieee_key->wk_key;
        for(i=0; i < roundup(cmd->key_len, sizeof(u_int32_t))/4; i++) {
            *destp = le32_to_cpu(*srcp);
            destp++; srcp++;
        }
    }
#else
    OS_MEMCPY(cmd->key_data, ieee_key->wk_key, cmd->key_len);
#endif
#if 0
    printk("%s Setting Key for Macaddress:0x%x%x \n",__func__,cmd->peer_macaddr.mac_addr47to32,cmd->peer_macaddr.mac_addr31to0);
    printk("Keyix=%d Keylen=%d Keyflags=%x Cipher=%x \n Keydata=",cmd->key_ix,cmd->key_len,cmd->key_flags,cmd->key_cipher);

    for(i=0; i<cmd->key_len; i++)
       printk("0x%x ",cmd->key_data[i]);
       printk("\n");
#endif
    return wmi_unified_cmd_send(wmi_handle, buf, len, WMI_VDEV_INSTALL_KEY_CMDID);
}

static int
ol_ath_vap_listen(struct ieee80211vap *vap)
{
    /* Target vdev will be in listen state once it is created
     * No need to send any command to target
     */
    return 0;
}

static int ol_ath_vap_join(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    struct ieee80211_channel *chan = vap->iv_bsschan;
    u_int32_t freq;

    freq = ieee80211_chan2freq(ic, chan);
    if (!freq) {
        printk("ERROR : INVALID Freq \n");
        return 0;
    }

    if (opmode != IEEE80211_M_STA && opmode != IEEE80211_M_IBSS) {
        /* join operation is only for STA/IBSS mode */
        return 0;
    }

    return 0;
}

/* No Op for Perf offload */
static int ol_ath_vap_dfs_cac(struct ieee80211vap *vap)
{
#if OL_ATH_SUPPORT_LED
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
#if QCA_LTEU_SUPPORT
    if (!scn->lteu_support) {
#endif
#if OL_ATH_SUPPORT_LED_POLL
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_poll_timer, 500);
        }
#else
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_ON_START;
        if(scn->target_type == TARGET_TYPE_IPQ4019) {
            ipq4019_wifi_led(scn, LED_OFF);
        } else {
            wmi_unified_gpio_output(scn->wmi_handle, scn->scn_led_gpio, 0);
        }
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#if QCA_LTEU_SUPPORT
    }
#endif
#endif /* OL_ATH_SUPPORT_LED */
    return 0;
}

enum ieee80211_opmode ieee80211_new_opmode(struct ieee80211vap *vap, bool vap_active);
static int
ol_ath_vap_up(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    struct ieee80211_node *ni = vap->iv_bss;
    u_int8_t bssid_null[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    u_int32_t aid = 0;
    u_int32_t value = 0;
    wlan_if_t vaphandle;
    vaphandle = ol_ath_vap_get(scn, avn->av_if_id);

    switch (opmode) {
        case IEEE80211_M_STA:
            ol_ath_vap_set_param(vap, IEEE80211_VHT_SUBFEE, 0);
            /* Send the assoc id, negotiated capabilities & rateset to the target */
            aid = IEEE80211_AID(ni->ni_associd);
            ol_ath_net80211_newassoc(ni, 1);

            /* Set the beacon interval of the bss */
            ol_ath_vap_set_param(vap, IEEE80211_BEACON_INTVAL, ni->ni_intval);

            if (ieee80211_vap_wme_is_set(vap) &&
                    (ni->ni_ext_caps & IEEE80211_NODE_C_UAPSD)) {
                value = 0;
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_VO) {
                    value |= WMI_STA_PS_UAPSD_AC3_DELIVERY_EN |
                        WMI_STA_PS_UAPSD_AC3_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_VI) {
                    value |= WMI_STA_PS_UAPSD_AC2_DELIVERY_EN |
                        WMI_STA_PS_UAPSD_AC2_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_BK) {
                    value |= WMI_STA_PS_UAPSD_AC1_DELIVERY_EN |
                        WMI_STA_PS_UAPSD_AC1_TRIGGER_EN;
                }
                if (vap->iv_uapsd & WME_CAPINFO_UAPSD_BE) {
                    value |= WMI_STA_PS_UAPSD_AC0_DELIVERY_EN |
                        WMI_STA_PS_UAPSD_AC0_TRIGGER_EN;
                }
            }

            (void)wmi_unified_set_sta_ps_param(OL_ATH_VAP_NET80211(vap),
                    WMI_STA_PS_PARAM_UAPSD, value);
            break;
        case IEEE80211_M_HOSTAP:
        case IEEE80211_M_IBSS:
            if (vap->iv_special_vap_mode) {
                if (ol_txrx_set_monitor_mode_vap(
                            scn->pdev_txrx_handle,
                            avn->av_txrx_handle)) {
                    printk("Unable to bring up in special vap interface\n");
                    return -1;
                }
                /*Already up, return with correct status*/
                if (vaphandle) {
                    adf_os_atomic_set(&(vaphandle->init_in_progress), 0);
                }

                if(!vap->iv_smart_monitor_vap && scn->target_type == TARGET_TYPE_AR9888) {
                    /* Set Rx decap to RAW mode */
                    vap->iv_rx_decap_type = htt_pkt_type_raw;
                    ol_txrx_set_vdev_rx_decap_type(vap->iv_txrx_handle, htt_pkt_type_raw);
                    if (wmi_unified_pdev_set_param(scn->wmi_handle,
                        WMI_PDEV_PARAM_RX_DECAP_MODE, htt_pkt_type_raw) != EOK)
                                printk("Error setting rx decap mode to RAW\n");
                }

                vap->iv_special_vap_is_monitor = 1;
                return 0;
            }

            value = (vap->iv_enable_vsp)?WMI_VDEV_VOW_ENABLED:0;
#if MESH_MODE_SUPPORT
            /* If this is a mesh vap and Beacon is enabled for it, send WMI capabiltiy to FW to enable Beacon */
            if((vap->iv_mesh_vap_mode) && (vap->iv_mesh_cap & MESH_CAP_BEACON_ENABLED)) {
                printk("%s, Enabling Beacon on Mesh Vap (vdev id: %d)\n", __func__, (OL_ATH_VAP_NET80211(vap))->av_if_id);
                value |= WMI_VDEV_BEACON_SUPPORT;
            }
#endif
            wmi_unified_vdev_set_param_send(scn->wmi_handle,(OL_ATH_VAP_NET80211(vap))->av_if_id,
                WMI_VDEV_PARAM_CAPABILITIES, value);

            /* allocate beacon buffer */
            ol_ath_beacon_alloc(ic, avn->av_if_id);
            ol_ath_vap_set_param(vap, IEEE80211_BEACON_INTVAL, ni->ni_intval);
            ol_ath_vap_set_param(vap, IEEE80211_VHT_SUBFEE, 0);

        /*currently ratemask has to be set before vap is up*/
        if (!vap->iv_ratemask_default) {
            /*ratemask higher 32 bit is reserved for beeliner, use 0x0 for peregrine*/
            if (vap->iv_legacy_ratemasklower32 != 0) {
                wmi_unified_vdev_config_ratemask(scn->wmi_handle, avn->av_if_id, 0,
                                                vap->iv_legacy_ratemasklower32 , 0x0);
            }
            if (vap->iv_ht_ratemasklower32 != 0) {
                wmi_unified_vdev_config_ratemask(scn->wmi_handle, avn->av_if_id, 1,
                                                vap->iv_ht_ratemasklower32 , 0x0);
            }
            if (vap->iv_vht_ratemasklower32 != 0 || vap->iv_vht_ratemaskhigher32 != 0) {
                wmi_unified_vdev_config_ratemask(scn->wmi_handle, avn->av_if_id, 2,
                                                  vap->iv_vht_ratemasklower32,
                                                  vap->iv_vht_ratemaskhigher32);
            }
        }

        break;
    case IEEE80211_M_MONITOR:
        if (ol_txrx_set_monitor_mode_vap(
                scn->pdev_txrx_handle,
                    avn->av_txrx_handle)) {
            /*Already up, return with correct status*/
            avn->av_restart_in_progress = FALSE;
            if (vaphandle) {
                adf_os_atomic_set(&(vaphandle->init_in_progress), 0);
            }
            return -1;
        }
    default:
        break;
    }

    ic->ic_opmode = ieee80211_new_opmode(vap,true);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    osif_nss_ol_vap_up((osif_dev *)vap->iv_ifp);
#endif

    /* bring up vdev in target */
    if (wmi_unified_vdev_up_send(scn->wmi_handle, avn->av_if_id, aid,
            ((opmode == IEEE80211_M_MONITOR) ? bssid_null : ni->ni_bssid))) {
        printk("Unable to bring up the interface for ath_dev.\n");
        return -1;
    }
    avn->av_restart_in_progress = FALSE;

    if (vaphandle) {
        adf_os_atomic_set(&(vaphandle->init_in_progress), 0);
    }

#if QCA_LTEU_SUPPORT
    if (!scn->lteu_support) {
#endif
#if OL_ATH_SUPPORT_LED
#if OL_ATH_SUPPORT_LED_POLL
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_poll_timer, 500);
        }
#else
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_ON_START;
        if(scn->target_type == TARGET_TYPE_IPQ4019) {
            ipq4019_wifi_led(scn, LED_OFF);
        } else {
            wmi_unified_gpio_output(scn->wmi_handle, scn->scn_led_gpio, 0);
        }
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#endif /* OL_ATH_SUPPORT_LED */
#if QCA_LTEU_SUPPORT
    }
#endif

    return 0;
}

static int ol_ath_vap_down(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    ic->ic_opmode = ieee80211_new_opmode(vap,false);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
     osif_nss_ol_vap_down((osif_dev *)vap->iv_ifp);
#endif

     /* Resetting ol_resmgr_wait and init_in_progress flags */
     /* In vap deletion case, we are not triggering vap_stop */
    avn->av_ol_resmgr_wait = FALSE;
    adf_os_atomic_set(&(vap->init_in_progress), 0);

    /* bring down vdev in target */
    if (wmi_unified_vdev_down_send(scn->wmi_handle, avn->av_if_id)) {
        printk("Unable to bring down the interface for ath_dev.\n");
        return -1;
    }
    ieee80211_vap_deliver_stop(vap);

    return 0;
}


static int ol_ath_vap_stopping(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    enum ieee80211_opmode opmode = ieee80211vap_get_opmode(vap);
    u_int32_t peer_tid_bitmap = 0xffffffff; /* TBD : fill with all valid TIDs */
    struct ieee80211_node *ni;

    switch (opmode) {
    case IEEE80211_M_MONITOR:
        ol_txrx_set_monitor_mode_vap(
                scn->pdev_txrx_handle, NULL);
        break;
    case IEEE80211_M_HOSTAP:
        if (vap->iv_special_vap_mode && vap->iv_special_vap_is_monitor) {
            ol_txrx_set_monitor_mode_vap(
                    scn->pdev_txrx_handle, NULL);
            vap->iv_special_vap_is_monitor = 0;
        }
        if (vap->mu_cap_war == 1)
        {
           adf_os_spin_lock_bh(&vap->iv_mu_cap_lock);
           if (vap->iv_mu_timer_state == MU_TIMER_RUNNING)
              vap->iv_mu_timer_state = MU_TIMER_STOP;
           if (vap->iv_mu_cap_state_switch == MU_CAP_STATE_CHG)
              vap->iv_mu_cap_state_switch = MU_CAP_STATE_NOR;
           OS_CANCEL_TIMER(&vap->iv_mu_cap_timer);
           adf_os_spin_unlock_bh(&vap->iv_mu_cap_lock);
        }
        break;
   case IEEE80211_M_STA:
        OS_CANCEL_TIMER(&vap->iv_cswitch_timer);
        break;
    default:
        break;
    }

    /*Return from here, if VAP init is already in progress*/
    if(adf_os_atomic_read(&(vap->init_in_progress)) && !ieee80211_vap_dfswait_is_set(vap)){
        printk("Warning:Stop during VAP Init ! \n");
        return EBUSY;
    }

    spin_lock_dpc(&vap->init_lock);

    /* Interface is brought down, So UMAC is not waiting for
     * target response
     */
    avn->av_ol_resmgr_wait = FALSE;

    /*
     * free any pending nbufs in the flow control queue
     */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if(!scn->pdev_txrx_handle->nss_wifiol_ctx)
#endif
    {
#if PEER_FLOW_CONTROL
        ol_tx_flush_buffers_pflow_ctrl(scn->pdev_txrx_handle);
#else
        {
            adf_nbuf_queue_t tmpq;
            u_int32_t scn_qcnt = 0;
            adf_nbuf_t netbuf;

            /* Init temp queue */
            adf_nbuf_queue_init(&tmpq);
            OL_TX_PDEV_LOCK(&scn->pdev_txrx_handle->tx_lock);
            if (scn->pdev_txrx_handle->acqcnt) {
                OL_TX_FLOW_CTRL_LOCK(&scn->pdev_txrx_handle->acnbufqlock);
                /* Copy acnbufq into tmpq */
                (void)adf_nbuf_queue_append(&tmpq, &scn->pdev_txrx_handle->acnbufq);
                scn_qcnt = scn->pdev_txrx_handle->acqcnt;
                /* Mark acnbufq as empty */
                scn->pdev_txrx_handle->acqcnt = 0;
                adf_nbuf_queue_init(&scn->pdev_txrx_handle->acnbufq);
                OL_TX_FLOW_CTRL_UNLOCK(&scn->pdev_txrx_handle->acnbufqlock);
            }
            OL_TX_PDEV_UNLOCK(&scn->pdev_txrx_handle->tx_lock);

            while (scn_qcnt) {
                netbuf = adf_nbuf_queue_remove(&tmpq);
                if (netbuf) {
                    adf_nbuf_free(netbuf);
                } else {
                    printk("%s: Error: Broken acnbufq, remaining qlen: %d\n",
                        __func__, scn_qcnt);
                    break;
                }
                scn_qcnt--;
            }
        }
#endif
    }

    /* Flush all TIDs for bss node - to cleanup
     * pending traffic in bssnode
     */
    ni = ieee80211_ref_bss_node(vap);
    if (ni != NULL) {
        if (wmi_unified_peer_flush_tids_send(scn->wmi_handle,
                    ni->ni_macaddr, peer_tid_bitmap, avn->av_if_id)) {
            printk("%s : Unable to Flush tids peer in Target \n", __func__);
        }
        ieee80211_free_node(ni);
    }


    /* NOTE: Call the ol_ath_beacon_stop always before sending vdev_stop
     * to Target. ol_ath_beacon_stop puts the beacon buffer to
     * deferred_bcn_list and this beacon buffer gets freed,
     * when stopped event recieved from target. If the ol_ath_beacon_stop
     * called after wmi_unified_vdev_stop_send, then Target could
     * respond with vdev stopped event immidiately and deferred_bcn_list
     * is still be empty and the beacon buffer is not freed.
     */
    ol_ath_beacon_stop(scn, avn);

    /*
     * Start the timer for vap stopped event after ol_ath_beacon_stop
     * puts the beacon buffer in to deferred_bcn_list
     */
    if ((scn->target_status == OL_TRGET_STATUS_EJECT) ||
        (scn->target_status == OL_TRGET_STATUS_RESET)) {
        /* target ejected/reset,  so generate the stopped event */
       OS_SET_TIMER(&avn->av_timer, 1);
       spin_unlock_dpc(&vap->init_lock);
       return 0;
    }

#if QCA_LTEU_SUPPORT
    if (!scn->lteu_support) {
#endif
#if OL_ATH_SUPPORT_LED
        OS_CANCEL_TIMER(&scn->scn_led_blink_timer);
        OS_CANCEL_TIMER(&scn->scn_led_poll_timer);
        scn->scn_blinking = OL_BLINK_STOP;
        if (scn->scn_led_blink_rate_table) {
            OS_SET_TIMER(&scn->scn_led_blink_timer, 10);
        }
#endif
#if QCA_LTEU_SUPPORT
    }
#endif

    /* bring down vdev in target */
    if (wmi_unified_vdev_stop_send(scn->wmi_handle, avn->av_if_id, ic->ic_nl_handle)) {
        printk("Unable to bring up the interface for ath_dev.\n");
        spin_unlock_dpc(&vap->init_lock);
        return -1;
    }

    /* Reset init_in_progress flag, as host is invoking stopping */
    adf_os_atomic_set(&(vap->init_in_progress), 0);

    spin_unlock_dpc(&vap->init_lock);

    return 0;
}

static int
ol_ath_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    if (scn != NULL) {
        if (k->wk_flags & IEEE80211_KEY_GROUP) {
#if 0
            printk(" Group Keyidx set=%d \n ",k - vap->iv_nw_keys);
#endif
            return k - vap->iv_nw_keys;
        }

        /* target handles key index fetch, host
           returns a key index value which is
           always greater than 0-3 (wep index) */

        if(k->wk_keyix == IEEE80211_KEYIX_NONE) {
            k->wk_keyix= IEEE80211_WEP_NKID + 1;
#if 0
            printk(" Unicast Keyidx set=%d \n ",k->wk_keyix);
#endif
            return k->wk_keyix;
        }

    }

    return -1;
}

/* set the key in the target */
static int
ol_ath_key_set(struct ieee80211vap *vap, struct ieee80211_key *k,
                       const u_int8_t peermac[IEEE80211_ADDR_LEN])
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    const struct ieee80211_cipher *cip = k->wk_cipher;
    u_int8_t gmac[IEEE80211_ADDR_LEN];
    int opmode, force_cipher_none = 0;
    u_int8_t def_kid_enable = 0;

    ASSERT(cip != NULL);

    if (cip == NULL)
        return 0;

    if (k->wk_keyix == IEEE80211_KEYIX_NONE) {
        printk("%s Not setting Key, keyidx=%u \n",__func__,k->wk_keyix);
        return 0;
    }

    IEEE80211_ADDR_COPY(gmac, peermac);

    opmode = ieee80211vap_get_opmode(vap);

    if (k->wk_flags & IEEE80211_KEY_GROUP) {

        switch (opmode) {

        case IEEE80211_M_STA:
#if ATH_SUPPORT_WRAP
            if (avn->av_is_psta && !(avn->av_is_mpsta)){
                printk("%s:Ignore set group key for psta\n",__func__);
                return 1;
            }
#endif
            /* Setting the multicast key in sta bss (AP) peer entry */
            if (IEEE80211_IS_BROADCAST(gmac)) {
                IEEE80211_ADDR_COPY(gmac,&(vap->iv_bss->ni_macaddr));
            }
            break;

        case IEEE80211_M_HOSTAP:
             /* Setting the multicast key in self i.e AP peer entry */
            IEEE80211_ADDR_COPY(gmac,&vap->iv_myaddr);
            break;
        }

    }
    /* If the key id matches with default tx keyid or privacy is not enabled
     * (First key to be loaded) Then consider this key as the default tx key
     */
    if((cip->ic_cipher == IEEE80211_CIPHER_WEP) &&
           ((vap->iv_def_txkey == k->wk_keyix)
                  || (wlan_get_param(vap,IEEE80211_FEATURE_PRIVACY) == 0)))
    {
       def_kid_enable = 1;
    }
    /* Force Cipher to NONE if the vap is configured in RAW mode with cipher as
     * dynamic WEP. For dynamic WEP, null/dummy keys are to be plumbed into the
     * firmware with cipher set to NONE
     */
    if (k->wk_flags & IEEE80211_KEY_DUMMY) {
        force_cipher_none = 1;
    }
   /* send the key to wmi layer  */
   if (wmi_unified_vdev_install_key_send(scn->wmi_handle, avn->av_if_id, k, gmac,
         def_kid_enable, force_cipher_none)) {
       printk("Unable to send the key to target \n");
       return -1;
   }
   /* assuming wmi will be always success */
   return 1;
}

static int
ol_ath_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k,
                  struct ieee80211_node *ni)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ieee80211_key tmp_key;
    u_int8_t gmac[IEEE80211_ADDR_LEN];

    if (k->wk_keyix == IEEE80211_KEYIX_NONE) {
        printk("%s: Not deleting key, keyidx=%u \n",__func__,k->wk_keyix);
        return 0;
    }

    memset(&tmp_key,0,sizeof(struct ieee80211_key));
    tmp_key.wk_valid = k->wk_valid;
    tmp_key.wk_flags = k->wk_flags;
    tmp_key.wk_keyix = k->wk_keyix;
    tmp_key.wk_cipher = k->wk_cipher;
    tmp_key.wk_private = k->wk_private;
    tmp_key.wk_clearkeyix = k->wk_clearkeyix;
    tmp_key.wk_keylen=k->wk_keylen;

    if (ni == NULL) {
        IEEE80211_ADDR_COPY(gmac,&(vap->iv_myaddr));
    } else{
        IEEE80211_ADDR_COPY(gmac, &(ni->ni_macaddr));
    }

    /* send the key to wmi layer  */
    if (wmi_unified_vdev_install_key_send(scn->wmi_handle, avn->av_if_id, (const struct ieee80211_key*)(&tmp_key), gmac, 0, 1)) {
       printk("Unable to send the key to target\n");
       return -1;
    }

    /* assuming wmi will be always success */
    return 1;
}


/* Vdev event handlers from target */
static int
ol_ath_vap_stopped_event(struct ol_ath_softc_net80211 *scn, u_int8_t if_id)
{
    /* Free the beacon buffer */
    struct ieee80211com *ic = &scn->sc_ic;
    struct ieee80211vap *vap;

    vap = ol_ath_vap_get(scn, if_id);
    ol_ath_beacon_free(ic, if_id);

    if(vap)
    {
        ieee80211_bsteering_send_vap_stop_event(vap);
    }
    return 0;
}

static OS_TIMER_FUNC(ol_ath_vap_stop_timed_out)
{
	struct ol_ath_vap_net80211 *avn ;
	struct ol_ath_softc_net80211 *scn = NULL;
	struct ieee80211vap *vap;
	u_int8_t if_id = 0;

	OS_GET_TIMER_ARG(avn, struct ol_ath_vap_net80211 *);
	scn = (struct ol_ath_softc_net80211 *)avn->av_sc;
	vap = ol_ath_vap_get(scn, if_id);

	printk("TIMED OUT WAITING FOR STOPPED EVENT FROM TARGET FOR VAP %d \n",avn->av_if_id);
	ol_ath_vap_stopped_event(avn->av_sc, avn->av_if_id);
	ieee80211_vap_deliver_stop(vap);
}

#if ATH_SUPPORT_ME_FW_BASED
/* WMI Mcast buffer release Event APIs */
static int
wmi_mcast_buf_release_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen, void *context)
{
#define FW_RESERVE_DESC 16
    struct ieee80211com *ic = (struct ieee80211com *) context;
    struct ol_txrx_pdev_t *pdev = scn->pdev_txrx_handle;
    u_int16_t released, allocated;
    wmi_mcast_buf_release_event *ev = (wmi_mcast_buf_release_event *)data;

    /*Get the current allocated count*/
    allocated = ol_tx_get_mcast_buf_allocated_marked(scn->pdev_txrx_handle);
    /*Target gives current count after decreasing the released count*/
    released = allocated - ((u_int16_t)ev->max_tgt_msdu_cloned - FW_RESERVE_DESC);
    /* Free the Mcast buffers allocated for target */
    released = ol_tx_desc_free_and_unmark_for_mcast_clone(pdev, released);

    scn->pend_desc_removal -= released;
    if(scn->pend_desc_addition) {
        u_int16_t pend_desc_to_alloc = scn->pend_desc_addition;
        scn->pend_desc_addition = 0;
        ic->ic_desc_alloc_and_mark_for_mcast_clone(ic, pend_desc_to_alloc);
    }
    printk("%s: VAP Mcast to Unicast buffer released:%u\n", __func__, released);

    return 0;
}
#endif /*ATH_SUPPORT_ME_FW_BASED*/

/* WMI event handler functions */
static int
wmi_unified_vdev_stopped_event_handler(ol_scn_t scn,
                                       u_int8_t *data, u_int16_t datalen, void *context)
{
    struct ieee80211com *ic = &scn->sc_ic;
    wmi_vdev_stopped_event* event = (wmi_vdev_stopped_event *)data;
    struct ieee80211vap *vap;
    struct ol_ath_vap_net80211 *avn ;

    if (!ic->ic_nl_handle) {
        printk("STOPPED EVENT for vap %d (%p)\n",event->vdev_id, scn->wmi_handle);
    }

    vap = ol_ath_vap_get(scn,event->vdev_id);
    if (vap)  {
       avn = OL_ATH_VAP_NET80211(vap);
       OS_CANCEL_TIMER(&avn->av_timer);
    }
    return ol_ath_vap_stopped_event(scn, event->vdev_id);
}

/* WMI event handler for Roam events */
static int
wmi_unified_roam_event_handler(
    ol_scn_t scn, u_int8_t *data, u_int16_t datalen, void *context)
{
    wmi_roam_event *evt = (wmi_roam_event *)data;
    struct ieee80211vap *vap;

    vap = ol_ath_vap_get(scn, evt->vdev_id);
    if (vap) {
        switch (evt->reason) {
            case WMI_ROAM_REASON_BMISS:
                ASSERT(vap->iv_opmode == IEEE80211_M_STA);
                ieee80211_mlme_sta_bmiss_ind(vap);
                break;
            case WMI_ROAM_REASON_BETTER_AP:
                /* FIX THIS */
            default:
                break;
        }
    }

    return 0;
}

/* Device Interface functions */
static void ol_ath_vap_iter_vap_create(void *arg, wlan_if_t vap)
{

    struct ieee80211com *ic = vap->iv_ic;
    u_int32_t *pid_mask = (u_int32_t *) arg;
    u_int8_t myaddr[IEEE80211_ADDR_LEN];
    u_int8_t id = 0;
#if ATH_SUPPORT_WRAP
    /* Proxy STA VAP has its own mac address */
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    if (avn->av_is_psta)
        return;
#endif
    ieee80211vap_get_macaddr(vap, myaddr);
    ATH_GET_VAP_ID(myaddr, ic->ic_myaddr, id);
    (*pid_mask) |= (1 << id);
}

void *ol_ath_vap_get_ol_data_handle(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    return (void *) avn->av_txrx_handle;
}

#if ATH_SUPPORT_NAC
int
ol_ath_neighbour_rx(struct ieee80211vap *vap, u_int32_t idx,
                   enum ieee80211_nac_param nac_cmd , enum ieee80211_nac_mactype nac_type ,
                   u_int8_t macaddr[IEEE80211_ADDR_LEN])
{

    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    u_int32_t action = nac_cmd;
    u_int32_t type = nac_type;

   /* send the key to wmi layer  */
   if (wmi_unified_vdev_set_neighbour_rx(vap, scn->wmi_handle, avn->av_if_id, idx, action, type, macaddr)) {
       printk("Unable to send the neighbour_rx command to target \n");
       return -1;
   }
   /* assuming wmi will be always success */
   return 1;
}
#endif
#if ATH_SUPPORT_WRAP
static inline int ol_ath_get_qwrap_num_vdevs(struct ol_ath_softc_net80211 *scn)
{
    if (qwrap_enable){
        if (scn->target_type == TARGET_TYPE_AR9888)
            return CFG_TGT_NUM_WRAP_VDEV_AR988X;
        else if (scn->target_type == TARGET_TYPE_QCA9984)
            return CFG_TGT_NUM_WRAP_VDEV_QCA9984;
        else if (scn->target_type == TARGET_TYPE_IPQ4019)
            return CFG_TGT_NUM_WRAP_VDEV_IPQ4019;
        else
            return CFG_TGT_NUM_WRAP_VDEV_AR900B;

    } else {
        if (scn->target_type == TARGET_TYPE_QCA9984) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else if (scn->target_type == TARGET_TYPE_IPQ4019) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else if (scn->target_type == TARGET_TYPE_AR900B) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else if (scn->target_type == TARGET_TYPE_QCA9888) {
            return CFG_TGT_NUM_VDEV_AR900B;
        } else {
            return CFG_TGT_NUM_VDEV_AR988X;
        }
    }
}
#endif

/*
 * VAP create
 */
static struct ieee80211vap *
ol_ath_vap_create(struct ieee80211com *ic,
                  int                 opmode,
                  int                 scan_priority_base,
                  int                 flags,
                  const u_int8_t      bssid[IEEE80211_ADDR_LEN],
                  const u_int8_t      mataddr[IEEE80211_ADDR_LEN],
                  void                *osifp_handle)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ieee80211vap *vap = NULL;
    struct ol_ath_vap_net80211* avn = NULL;
    int id = 0;
    u_int16_t type;
    u_int16_t sub_type = 0;
    u_int8_t vap_addr[IEEE80211_ADDR_LEN] = { 0 };
    int nvaps = 0, nactivevaps = 0;
    u_int32_t id_mask = 0;
    enum wlan_op_mode txrx_opmode;
    u_int32_t retval;
    uint8_t vlimit_exceeded = false;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    int32_t nss_if = -1;
#endif
#if ATH_SUPPORT_WRAP
    int num_vdevs = 0;
#endif
    u_int8_t id_used = 0, timer_inited = 0, tgt_vdev_created = 0;

    if (!(scn->vdev_count) && scn->down_complete) {
        if (ol_ath_target_start(scn)) {
            adf_os_print("failed to start the firmware\n");
            return NULL;
        }
    }

    adf_os_spin_lock_bh(&scn->scn_lock);
    if (opmode == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count++;
        if (scn->mon_vdev_count > CFG_TGT_MAX_MONITOR_VDEV) {
            adf_os_spin_unlock_bh(&scn->scn_lock);
            printk("%s: devhandle (%p) the ap_monitor vdev count exceeds the supported number %d\n",
                    __func__, ic, CFG_TGT_MAX_MONITOR_VDEV);
            goto err_vap_create;
        }
    } else {
        if (scn->special_ap_vap && !(scn->smart_ap_monitor)) {
            printk("%s() devhandle (%p) Radio is configured in Special ap monitor mode we can't create any other vap except 1 stavap or ap smart monitor\n",
                    __func__, ic);
            /* incrementing vdev_count here to sync with error path. It will get decremented before exiting the function */
            scn->vdev_count++;
            adf_os_spin_unlock_bh(&scn->scn_lock);
            goto err_vap_create;
        } else {
            if (flags & IEEE80211_SPECIAL_VAP) {

                if ((flags & IEEE80211_SMART_MONITOR_VAP) && !(scn->smart_ap_monitor)) {
                    scn->smart_ap_monitor = 1;
                } else if ((scn->vdev_count != 0) ||(scn->mon_vdev_count != 0) ) {
                    printk("%s() devhandle (%p) Already radio having  Normal AP or STA vaps we can't create ap monitor vap\n",
                            __func__, ic);
                    /* incrementing vdev_count here. It will get decremented before exiting the function */
                    scn->vdev_count++;
                    adf_os_spin_unlock_bh(&scn->scn_lock);
                    goto err_vap_create;
                }
                scn->special_ap_vap = 1;
            }
        }
        scn->vdev_count++;
    }
    adf_os_spin_unlock_bh(&scn->scn_lock);

    /* AR988X supports at max 16 vaps and all these can be in AP mode */
    if (scn->target_type == TARGET_TYPE_AR9888) {
        if ((scn->vdev_count + scn->mon_vdev_count) > scn->wlan_resource_config.num_vdevs) {
            vlimit_exceeded = true;
        }
    } else if (scn->vdev_count > (scn->wlan_resource_config.num_vdevs - CFG_TGT_MAX_MONITOR_VDEV)) {
        vlimit_exceeded = true;
    }

    if (vlimit_exceeded) {
        printk("%s: No more VAP's allowed. devhandle (%p) scn (%p) vdev_count: %d, mon_vdev_count: %d, num_vdevs: %d\n",
            __func__, ic, scn, scn->vdev_count, scn->mon_vdev_count, scn->wlan_resource_config.num_vdevs);
        goto err_vap_create;
    }

    if ((opmode == IEEE80211_M_STA) && (scn->sc_nstavaps >0)) {
       if (!(flags & IEEE80211_WRAP_WIRED_STA) && !(flags & IEEE80211_CLONE_MATADDR )) {
           printk("\n\n %s() devhandle (%p) A STA is already created on this radio. Not creating this STA\n\n",
                   __func__, ic);
           goto err_vap_create;
       }
    }

    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ol_ath_vap_iter_vap_create,(void *) &id_mask);
    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */
    IEEE80211_ADDR_COPY(vap_addr,ic->ic_myaddr);


    if (flags & IEEE80211_P2PDEV_VAP) {
        id = 1;
    } else if ((flags & IEEE80211_CLONE_BSSID) &&
        opmode != IEEE80211_M_WDS) {
        /*nvaps != 0 && opmode != IEEE80211_M_WDS) { */
        /*nvaps can be zero if vap delete in progress but the index may still be valid so we should check for available index based on sc_prealloc_mask*/

        /*
         * Hardware supports the bssid mask and a unique bssid was
         * requested.  Assign a new mac address and expand our bssid
         * mask to cover the active virtual ap's with distinct
         * addresses.
         */
        if (nvaps == ATH_BCBUF) {
            printk("Vap count exceeds the supported value \n");
            goto err_vap_create;
        }
        for (id = 0; id < ATH_BCBUF; id++) {
            /* get the first available slot */
            if ((id_mask & (1 << id)) == 0)
                break;

        }
    }
#if ATH_SUPPORT_WRAP
    if (flags & IEEE80211_CLONE_MACADDR) {
        num_vdevs = ol_ath_get_qwrap_num_vdevs (scn);
        for (id = 0; id < num_vdevs; id++) {
            /* get the first available slot */
            if ((id_mask & (1 << id)) == 0)
                break;
        }
    } else
#endif
    if ((flags & IEEE80211_CLONE_BSSID) == 0) {
        if (ic->ic_is_macreq_enabled(ic)) {
            /*
             * Pre-allocated VAP id is used to generate MAC address,
             * this id is retrieved during VAP delete time
             * extract the id from the bssid
             */
            ATH_GET_VAP_ID(bssid, ic->ic_myaddr, id);
            if ( (scn->sc_prealloc_idmask & (1 << id)) == 0) {
                /* the mac address was not pre allocated with ath_vap_alloc_macaddr */
                printk("%s: the vap mac address was not pre allocated \n",__func__);
                goto err_vap_create;
            }

            /*
             * Generate the mac address from id and sanity check
             */
            ATH_SET_VAP_BSSID(vap_addr,ic->ic_myaddr, id);
        } else {
            /* do not clone use the one passed in */
            printk("No cloning\n");
            /*
             * Added proper logic to get vap id and bssid value.
             * when user pass BSSID MAC value through commandline using -bssid option, The
             * exsiting logic won't work to get proper vap id to create VAP
             */

            for (id = 0; id < ATH_BCBUF; id++) {
                /* get the first available slot */
                if ((id_mask & (1 << id)) == 0) {
                    break;
                }
            }
            /* Update user passed BSSID value */
            IEEE80211_ADDR_COPY(vap_addr, bssid);
        }
    }

#if ATH_SUPPORT_WRAP
    if (flags & IEEE80211_CLONE_MACADDR) {
        if (id >= num_vdevs) {
            printk("%s: VAP (%d) exceeding limit of maximum allowed (%d) \n",
                __func__, id, num_vdevs);
            goto err_vap_create;
        }
    } else if (id >= ATH_BCBUF) {
        /* check if VAP id is exceeding max beacon buffers supported for VAPs */
        printk("%s: VAP (%d) exceeding limit of maximum allowed (%d) \n",
            __func__, id, ATH_BCBUF);
        goto err_vap_create;
    }
#else
    if (id >= ATH_BCBUF) {
        printk("%s: VAP (%d) exceeding limit of maximum allowed (%d)\n",
            __func__, id, ATH_BCBUF);
        goto err_vap_create;
    }
#endif

    /* create the corresponding VAP */
    avn = (struct ol_ath_vap_net80211 *)adf_mempool_alloc(scn->adf_dev, scn->mempool_ol_ath_vap);

    if (avn == NULL) {
        printk("Can't allocate memory for ath_vap.\n");
        goto err_vap_create;
    }
    OS_MEMZERO(avn, sizeof(struct ol_ath_vap_net80211));

    switch (opmode) {
    case IEEE80211_M_STA:
        type = WMI_VDEV_TYPE_STA;
        break;
    case IEEE80211_M_IBSS:
        type = WMI_VDEV_TYPE_IBSS;
        break;
    case IEEE80211_M_MONITOR:
        type = WMI_VDEV_TYPE_MONITOR;
        break;
    case IEEE80211_M_HOSTAP:
    case IEEE80211_M_WDS:
    case IEEE80211_M_BTAMP:
        type = WMI_VDEV_TYPE_AP;
        break;
    default:
        goto err_alloc_mempool;
    }

    if ((flags & IEEE80211_CLONE_BSSID) == 0 && !ic->ic_is_macreq_enabled(ic)) {
        IEEE80211_ADDR_COPY(vap_addr, bssid);
    } else {
        /* set up MAC address */
        ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, id);
    }

    avn->av_sc = scn;
    avn->av_if_id = id;
    avn->av_restart_in_progress = FALSE;
    adf_os_spinlock_init(&avn->avn_lock);
    TAILQ_INIT(&avn->deferred_bcn_list);

    vap = &avn->av_vap;

    if (flags & IEEE80211_P2PDEV_VAP) {
        sub_type = WMI_UNIFIED_VDEV_SUBTYPE_P2P_DEVICE;
    }else if (flags & IEEE80211_P2PCLI_VAP) {
        sub_type = WMI_UNIFIED_VDEV_SUBTYPE_P2P_CLIENT;
    }else if (flags & IEEE80211_P2PGO_VAP) {
        sub_type = WMI_UNIFIED_VDEV_SUBTYPE_P2P_GO;
    }

    if (flags & IEEE80211_SPECIAL_VAP) {
        vap->iv_special_vap_mode = 1;
    }

#if ATH_SUPPORT_NAC
    if (flags & IEEE80211_SMART_MONITOR_VAP) {
        vap->iv_smart_monitor_vap =1;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_NAC, "%s : Smart Monitor Set to %d \n", __func__, vap->iv_smart_monitor_vap);
    }
#endif

    vap->mhdr_len = 0;
#if MESH_MODE_SUPPORT
    if (flags & IEEE80211_MESH_VAP) {
        if (!ic->ic_mesh_vap_support) {
            printk("Mesh vap not supported by this radio!!\n");
            goto err_alloc_mempool;
        }
        vap->iv_mesh_vap_mode =1;
        sub_type = WMI_UNIFIED_VDEV_SUBTYPE_MESH;
        vap->mhdr_len = sizeof(struct meta_hdr_s);
        vap->mhdr = 0;
    }
#endif

    scn->sc_prealloc_idmask |= (1 << id);
    id_used = 1;
#if ATH_SUPPORT_WRAP
    if ((opmode == IEEE80211_M_HOSTAP) && (flags & IEEE80211_WRAP_VAP)) {
        avn->av_is_wrap = 1;
        vap->iv_wrap =1;
        ic->ic_nwrapvaps++;
        scn->sc_nwrapvaps++;
    } else if ((opmode == IEEE80211_M_STA) && (flags & IEEE80211_CLONE_MACADDR)) {
        if (!bssid[0] && !bssid[1] && !bssid[2] &&
            !bssid[3] && !bssid[4] && !bssid[5])
        {
            /*
             * Main ProxySTA VAP for uplink WPS PBC and
             * downlink multicast receive.
             */
            avn->av_is_mpsta = 1;
            vap->iv_mpsta = 1;

            adf_os_spin_lock_bh(&scn->sc_mpsta_vap_lock);
            scn->sc_mcast_recv_vap = vap;
            adf_os_spin_unlock_bh(&scn->sc_mpsta_vap_lock);

            IEEE80211_ADDR_COPY(vap_addr,ic->ic_myaddr);
            ATH_SET_VAP_BSSID(vap_addr, ic->ic_myaddr, id);
        } else {
            /*
             * Generally, non-Main ProxySTA VAP's don't need to
             * register umac event handlers. We can save some memory
             * space by doing so. This is required to be done before
             * ieee80211_vap_setup. However we still give the scan
             * capability to the first ATH_NSCAN_PSTA_VAPS non-Main
             * PSTA VAP's. This optimizes the association speed for
             * the first several PSTA VAP's (common case).
             */
#define ATH_NSCAN_PSTA_VAPS 0
            if (scn->sc_nscanpsta >= ATH_NSCAN_PSTA_VAPS)
                vap->iv_no_event_handler = 1;
            else
                scn->sc_nscanpsta++;
        }
        avn->av_is_psta = 1;
        vap->iv_psta = 1;
        scn->sc_npstavaps++;
    }

    if (flags & IEEE80211_CLONE_MATADDR) {
        avn->av_use_mat = 1;
        vap->iv_mat = 1;
        OS_MEMCPY(avn->av_mat_addr, mataddr, IEEE80211_ADDR_LEN);
        OS_MEMCPY(vap->iv_mat_addr, mataddr, IEEE80211_ADDR_LEN);
    }

    if (flags & IEEE80211_WRAP_WIRED_STA) {
        vap->iv_wired_pvap = 1;
    }
    if (avn->av_is_psta) {
        if (avn->av_is_mpsta) {
            /*
             * Main ProxySTA VAP also handles the downlink multicast receive
             * on behalf of all the ProxySTA VAP's.
             */
            OS_MEMCPY(avn->av_mat_addr, vap->iv_myaddr, IEEE80211_ADDR_LEN);
        } else {
            sub_type = WMI_UNIFIED_VDEV_SUBTYPE_PROXY_STA;
            OS_MEMCPY(vap_addr, bssid, IEEE80211_ADDR_LEN);
        }
    }

    /*
     * This is only needed for Peregrine, remove this once we have HW CAP bit added
     * for enhanced ProxySTA support.
     */
    if (scn->target_type == TARGET_TYPE_AR9888) {
        /* enter ProxySTA mode when the first WRAP or PSTA VAP is created */
        if (scn->sc_nwrapvaps + scn->sc_npstavaps == 1)
            (void)wmi_unified_pdev_set_param(scn->wmi_handle, WMI_PDEV_PARAM_PROXY_STA_MODE, 1);
    }
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    nss_if = osif_nss_vdev_alloc(scn->pdev_txrx_handle, vap);
    if ( nss_if == -1) {
        printk("%s() devhandle (%p) NSS WiFi Offload unable to allocate VAP %d\n",
                __func__, ic, id);
        goto err_nss_vdev;
    }
#endif

    /* Create a vdev in target */
    if (wmi_unified_vdev_create_send(scn->wmi_handle, id, type, sub_type, vap_addr)) {
        printk("Unable to create vdev in target\n");
        goto err_vdev_create;
    }
    tgt_vdev_created = 1;
    vap->iv_unit = id;
    ieee80211_vap_setup(ic, vap, opmode, scan_priority_base, flags, bssid);
    /*
     * Enable MU-BFER & SU-BFER if the Tx chain number is 0x2, 0x3 and 0x4 and not otherwise.
     */
    if (ieee80211_get_txstreams(ic, vap) < 2) {
        vap->iv_vhtsubfer = 0;
        vap->iv_vhtmubfer = 0;
    }
#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = vap;
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = vap;
    }
#if ATH_PROXY_NOACK_WAR
    if (vap->iv_mpsta || vap->iv_wrap) {
        wmi_unified_register_event_handler(scn->wmi_handle, WMI_PDEV_RESERVE_AST_ENTRY_EVENTID,
                                    wmi_unified_pdev_proxy_ast_reserve_event_handler, NULL);

        ic->proxy_ast_reserve_wait.blocking = 1;
        adf_os_init_mutex(&(ic->proxy_ast_reserve_wait.sem_ptr));
        adf_os_mutex_acquire(ic->ic_adf_dev, &(ic->proxy_ast_reserve_wait.sem_ptr));
    }
#endif
#endif
    ieee80211vap_set_macaddr(vap, vap_addr);

#if ATH_SUPPORT_WRAP
    if (avn->av_is_wrap || avn->av_is_psta) {
        if (scn->sc_nwrapvaps) {
            ieee80211_ic_enh_ind_rpt_set(vap->iv_ic);
        }
    }
    vap->iv_wrap_mat_tx = ol_if_wrap_mat_tx;
    vap->iv_wrap_mat_rx = ol_if_wrap_mat_rx;
#endif

    /*
     * If BMISS offload is supported, we disable the SW Bmiss timer on host
     */
    if (WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap,
                               WMI_SERVICE_BCN_MISS_OFFLOAD)) {
        u_int32_t tmp_id;
        int8_t tmp_name[] = "tmp";

        tmp_id = ieee80211_mlme_sta_swbmiss_timer_alloc_id(vap, tmp_name);
        ieee80211_mlme_sta_swbmiss_timer_disable(vap, tmp_id);
    }

    /* set user selected channel width to an invalid value by default */
    vap->iv_chwidth = IEEE80211_CWM_WIDTHINVALID;

    /* Enable 256 QAM by default */
    vap->iv_256qam = 1;

    /* Intialize VAP interface functions */
    vap->iv_up = ol_ath_vap_up;
    vap->iv_join = ol_ath_vap_join;
    vap->iv_down = ol_ath_vap_down;
    vap->iv_listen = ol_ath_vap_listen;
    vap->iv_stopping = ol_ath_vap_stopping;
    vap->iv_dfs_cac = ol_ath_vap_dfs_cac;
    vap->iv_key_alloc = ol_ath_key_alloc;
    vap->iv_key_delete = ol_ath_key_delete;
    vap->iv_key_set = ol_ath_key_set;
#if ATH_SUPPORT_NAC
    vap->iv_neighbour_rx = ol_ath_neighbour_rx;
#endif
#if 0
    vap->iv_key_map    = ol_ath_key_map;
    vap->iv_key_update_begin = ol_ath_key_update_begin;
    vap->iv_key_update_end = ol_ath_key_update_end;
    vap->iv_reg_vap_ath_info_notify = ol_ath_net80211_reg_vap_info_notify;
    vap->iv_vap_ath_info_update_notify = ol_ath_net80211_vap_info_update_notify;
    vap->iv_dereg_vap_ath_info_notify = ol_ath_net80211_dereg_vap_info_notify;
    vap->iv_vap_ath_info_get = ol_ath_net80211_vap_info_get;
    vap->iv_update_ps_mode = ol_ath_update_ps_mode;
    vap->iv_update_node_txpow = ol_ath_net80211_update_node_txpow;
#endif

#if  0 //ATH_SUPPORT_WIFIPOS
    vap->iv_wifipos->status_request =       ieee80211_wifipos_status_request;
    vap->iv_wifipos->cap_request =          ieee80211_wifipos_cap_request;
    vap->iv_wifipos->sleep_request =        ieee80211_wifipos_sleep_request;
    vap->iv_wifipos->wakeup_request =       ol_ath_wifipos_wakeup_request;

    vap->iv_wifipos->nlsend_status_resp =   ieee80211_wifipos_nlsend_status_resp;
    vap->iv_wifipos->nlsend_cap_resp =      ieee80211_wifipos_nlsend_cap_resp;
    vap->iv_wifipos->nlsend_tsf_resp =      ieee80211_wifipos_nlsend_tsf_resp;
    vap->iv_wifipos->nlsend_sleep_resp =    ieee80211_wifipos_nlsend_sleep_resp;
    vap->iv_wifipos->nlsend_wakeup_resp =   ol_ath_wifipos_nlsend_wakeup_resp;
    vap->iv_wifipos->nlsend_empty_resp  =   ieee80211_wifipos_nlsend_empty_resp;
    vap->iv_wifipos->nlsend_probe_resp =    ieee80211_wifipos_nlsend_probe_resp;
    vap->iv_wifipos->nlsend_tsf_update =    ieee80211_wifipos_nlsend_tsf_update;

    vap->iv_wifipos->fsm =                  ieee80211_ol_wifipos_fsm;

    vap->iv_wifipos->xmittsfrequest =       ieee80211_wifipos_xmittsfrequest;
    vap->iv_wifipos->xmitprobe      =       ol_ieee80211_wifipos_xmitprobe;
#endif

    /*
     * init IEEE80211_DPRINTF control object
     * Register with asf.
     */
    ieee80211_dprintf_init(vap);

#if DBG_LVL_MAC_FILTERING
    vap->iv_print.dbgLVLmac_on = 0; /*initialize dbgLVLmac flag*/
#endif

    vap->iv_unit = id;
    adf_os_timer_init(scn->sc_osdev, &(avn->av_timer), ol_ath_vap_stop_timed_out, (void *)avn);
    timer_inited = 1;

    nactivevaps = ieee80211_vaps_active(ic);
    if (nactivevaps==0) {
        ic->ic_opmode = opmode;
    }

    /* translate the opmode into the enum expected by the txrx module */
    switch (opmode) {
    case IEEE80211_M_STA:
        txrx_opmode = wlan_op_mode_sta;
        break;
    case IEEE80211_M_HOSTAP:
        txrx_opmode = wlan_op_mode_ap;
        break;
    case IEEE80211_M_IBSS:
        txrx_opmode = wlan_op_mode_ibss;
        break;
    case IEEE80211_M_MONITOR:
        txrx_opmode = wlan_op_mode_monitor;
        break;
    default:
        txrx_opmode = wlan_op_mode_unknown;
    };
    avn->av_txrx_handle = ol_txrx_vdev_attach(
        scn->pdev_txrx_handle, vap_addr, id, txrx_opmode);
    if (avn->av_txrx_handle == NULL ) {
        printk("%s: Unable to attach ol txrx module.\n",__func__);
        goto err_txrx_attach;
    }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (osif_nss_ol_vap_create(avn->av_txrx_handle, vap, osifp_handle, nss_if) == -1) {
        printk("%s: NSS WiFi Offload Unable to attach vap \n",__func__);
        ol_txrx_vdev_detach(avn->av_txrx_handle, NULL, NULL);
        goto err_txrx_attach;
    }
#endif
    vap->iv_txrx_handle = avn->av_txrx_handle;
    vap->iv_vap_get_ol_data_handle = ol_ath_vap_get_ol_data_handle;
    /* Setting default value to be retrieved when iwpriv get_inact command is used */
    vap->iv_inact_run = DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS;

    /* Send Param indicating LP IOT vap as requested by FW */
    if (opmode == IEEE80211_M_HOSTAP) {
        if (flags & IEEE80211_LP_IOT_VAP) {
            if (wmi_unified_vdev_set_param_send(scn->wmi_handle,
                 avn->av_if_id, WMI_VDEV_PARAM_SENSOR_AP,
                 1)) {
                 printk("%s:Unable to send param LP IOT VAP mode to target\n",__func__);
            }

#ifndef WMI_BEACON_RATE_2M
#define WMI_BEACON_RATE_2M   0x42
#endif
#ifndef WMI_BEACON_RATE_6M
#define WMI_BEACON_RATE_6M   0x03
#endif
            /* Beacon rate for arlo vap on 2.4G radio is 2M */
            if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                if (wmi_unified_vdev_set_param_send(scn->wmi_handle,
                     avn->av_if_id, WMI_VDEV_PARAM_BEACON_RATE,
                     WMI_BEACON_RATE_2M)) {
                     printk("%s:Unable to send param beacon rate 2Mbps to target\n",__func__);
                }
            } else {
                if (wmi_unified_vdev_set_param_send(scn->wmi_handle,
                     avn->av_if_id, WMI_VDEV_PARAM_BEACON_RATE,
                     WMI_BEACON_RATE_6M)) {
                     printk("%s:Unable to send param beacon rate 6Mbps to target\n",__func__);
                }
            }
        }
    }
    if (wmi_unified_vdev_set_param_send(scn->wmi_handle,
        avn->av_if_id, WMI_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS,
        DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MIN_IDLE_TIME_SECS)) {
        printk("%s() Unable to send param AP MIN_Keepalive\n", __func__);
    }
    if (wmi_unified_vdev_set_param_send(scn->wmi_handle,
        avn->av_if_id, WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS,
        DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_IDLE_TIME_SECS)) {
        printk("%s() Unable to send param AP MAX_Keepalive\n", __func__);
    }
    if (wmi_unified_vdev_set_param_send(scn->wmi_handle,
        avn->av_if_id, WMI_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS,
        DEFAULT_WLAN_VDEV_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS)) {
        printk("%s() Unable to send param AP MAX_Unresponsive\n", __func__);
    }

    /*
     * Don't set promiscuous bit in smart monitor vap
     * Smar monitor vap - filters specific to other
     * configured neighbour AP BSSID & its associated clients
     */
    if (vap->iv_special_vap_mode && !vap->iv_smart_monitor_vap) {
        printk("enabling promiscuos bit\n");
        retval = wmi_unified_pdev_set_param(scn->wmi_handle,WMI_PDEV_PARAM_SET_PROMISC_MODE_CMDID, 1);
        if (retval) {
            printk("Unable to send param promisc_mode\n");
        }
    }

#if ATH_SUPPORT_DSCP_OVERRIDE
    if (vap->iv_override_dscp) {
        ol_ath_set_vap_dscp_tid_map(vap);
    }
#endif

#if UMAC_SUPPORT_WNM
    /* configure wnm default settings */
    ieee80211_vap_wnm_set(vap);
#endif

#if MESH_MODE_SUPPORT
    if (vap->iv_mesh_vap_mode) {
        ol_txrx_set_mesh_mode(vap->iv_txrx_handle,1);
    }
#endif
#ifndef ATH_WIN_NWF
    vap->iv_tx_encap_type = htt_pkt_type_ethernet;
    vap->iv_rx_decap_type = htt_pkt_type_ethernet;
#else
    vap->iv_tx_encap_type = htt_pkt_type_native_wifi;
    vap->iv_rx_decap_type = htt_pkt_type_native_wifi;
#endif
    /* disable RTT by default. WFA requirement */
    vap->rtt_enable=0;

    if (opmode == IEEE80211_M_HOSTAP)
        vap->iv_rev_sig_160w = DEFAULT_REV_SIG_160_STATUS;

    (void) ieee80211_vap_attach(vap);

    if (opmode == IEEE80211_M_STA)
        scn->sc_nstavaps++;

    return vap;

err_txrx_attach:
    if (timer_inited) {
        adf_os_timer_free(&(avn->av_timer));
    }

    /*
     * Unregister with asf.
     * Need to make sure vap is proper if there is a wrong jump to here
     */
    if (vap) {
        ieee80211_dprintf_deregister(vap);
    }

    /*
     * Delete the interface in target
     */
    if (tgt_vdev_created
        && (wmi_unified_vdev_delete_send(scn->wmi_handle, avn->av_if_id))) {
        printk("%s() Unable to remove interface in Target vdev_id %d address: %02x:%02x:%02x:%02x:%02x:%02x:\n",
                __func__, id, vap_addr[0], vap_addr[1], vap_addr[2], vap_addr[3], vap_addr[4], vap_addr[5]);
    }
err_vdev_create:
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (nss_if && (nss_if != -1) && (nss_if != NSS_PROXY_VAP_IF_NUMBER)) {
        osif_nss_vdev_dealloc(osifp_handle, nss_if);
    }
err_nss_vdev:
#endif
    if (id_used) {
        scn->sc_prealloc_idmask &= ~(1 << id);
    }
err_alloc_mempool:
    if (avn) {
        adf_mempool_free(scn->adf_dev, scn->mempool_ol_ath_vap, avn);
    }
err_vap_create:
    adf_os_spin_lock_bh(&scn->scn_lock);
    if (opmode == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count--;
    } else {
        scn->vdev_count--;
    }
    adf_os_spin_unlock_bh(&scn->scn_lock);
    return NULL;
}

/*
 * VAP delete
 */
static void
ol_ath_vap_delete(struct ieee80211vap *vap)
{
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);
    struct ol_ath_softc_net80211 *scn = avn->av_sc;

    if (!vap) {
        printk("VAP is NULL!!!\n");
        return;
    }

    /* delete key before vdev delete */
    delete_default_vap_keys(vap);

#if ATH_SUPPORT_WRAP
    /*
     * Both WRAP and ProxySTA VAP's populate keycache slot with
     * vap->iv_myaddr even when security is not used.
     */
    if (avn->av_is_wrap) {
        scn->sc_nwrapvaps--;
    } else if (avn->av_is_psta) {
        adf_os_spin_lock_bh(&scn->sc_mpsta_vap_lock);
        if (scn->sc_mcast_recv_vap == vap) {
            scn->sc_mcast_recv_vap = NULL;
        }
        adf_os_spin_unlock_bh(&scn->sc_mpsta_vap_lock);

        if (!avn->av_is_mpsta) {
            if (vap->iv_no_event_handler == 0)
                scn->sc_nscanpsta--;
        }
    scn->sc_npstavaps--;
    }
    /* exit ProxySTA mode when the last WRAP or PSTA VAP is deleted */
    if (scn->target_type == TARGET_TYPE_AR9888) {
	/* Only needed for Peregrine */
		if (avn->av_is_wrap || avn->av_is_psta) {
			if (scn->sc_nwrapvaps + scn->sc_npstavaps == 0) {
				(void)wmi_unified_pdev_set_param(scn->wmi_handle, WMI_PDEV_PARAM_PROXY_STA_MODE, 0);
			}
		}
	}
#endif

    scn->sc_prealloc_idmask &= ~(1 << avn->av_if_id);

    /* remove the interface from ath_dev */
    if (wmi_unified_vdev_delete_send(scn->wmi_handle, avn->av_if_id)) {
        printk("Unable to remove an interface for ath_dev.\n");
        ASSERT(0);
    }
    printk("%s: wmi_unified_vdev_delete_send done ID = %d vap (%p) VAP Addr = %02x:%02x:%02x:%02x:%02x:%02x:\n",
                __func__, avn->av_if_id, vap,
               vap->iv_myaddr[0], vap->iv_myaddr[1], vap->iv_myaddr[2],
               vap->iv_myaddr[3], vap->iv_myaddr[4], vap->iv_myaddr[5]);

    if(ieee80211vap_get_opmode(vap) == IEEE80211_M_STA)
        scn->sc_nstavaps--;

    if(vap->iv_special_vap_mode) {
        vap->iv_special_vap_mode = 0;
        scn->special_ap_vap = 0;
    }

    /* deregister IEEE80211_DPRINTF control object */
    ieee80211_dprintf_deregister(vap);

    /* detach VAP from the procotol stack */
    ieee80211_vap_detach(vap);

    /* TBD:
     * Should a callback be provided for notification once the
     * txrx vdev object has actually been deleted?
     */
    ol_txrx_vdev_detach(avn->av_txrx_handle, NULL, NULL);

#if ATH_SUPPORT_WRAP
    if (vap->iv_mpsta) {
        vap->iv_ic->ic_mpsta_vap = NULL;
    }
    if (vap->iv_wrap) {
         vap->iv_ic->ic_wrap_vap = NULL;
    }
#endif

    adf_os_spinlock_destroy(&avn->avn_lock);
    OS_FREE_TIMER(&avn->av_timer);
    adf_mempool_free(scn->adf_dev, scn->mempool_ol_ath_vap, avn);

    adf_os_spin_lock(&scn->scn_lock);
    if (ieee80211vap_get_opmode(vap) == IEEE80211_M_MONITOR) {
        scn->mon_vdev_count--;
    } else {
        scn->vdev_count--;
    }
    adf_os_spin_unlock(&scn->scn_lock);
}

/*
 * pre allocate a mac address and return it in bssid
 */
static int
ol_ath_vap_alloc_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    int id = 0, id_mask = 0;
    int nvaps = 0;
   //  DPRINTF(scn, ATH_DEBUG_STATE, "%s \n", __func__);
    /* do a full search to mark all the allocated vaps */
    nvaps = wlan_iterate_vap_list(ic,ol_ath_vap_iter_vap_create,(void *) &id_mask);

    id_mask |= scn->sc_prealloc_idmask; /* or in allocated ids */


    if (IEEE80211_ADDR_IS_VALID(bssid) ) {
        /* request to preallocate a specific address */
        /* check if it is valid and it is available */
        u_int8_t tmp_mac2[IEEE80211_ADDR_LEN];
        u_int8_t tmp_mac1[IEEE80211_ADDR_LEN];
        IEEE80211_ADDR_COPY(tmp_mac1, ic->ic_my_hwaddr);
        IEEE80211_ADDR_COPY(tmp_mac2, bssid);

        if (ic->ic_is_macreq_enabled(ic)) {
            tmp_mac1[0] &= 0xf; /* clear upper nibble */
            tmp_mac2[0] &= 0xf; /* clear upper nibble */
            tmp_mac1[0] |= 0x2; /*set the locally administered bit */
        } else {
            tmp_mac1[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            tmp_mac1[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );
            tmp_mac1[0] |= IEEE802_MAC_LOCAL_ADMBIT ;

            tmp_mac2[ATH_VAP_ID_INDEX] &= ~(ATH_VAP_ID_MASK >> ATH_VAP_ID_SHIFT);
            tmp_mac2[ATH_VAP_ID_INDEX+1] &= ~( ATH_VAP_ID_MASK << ( OCTET-ATH_VAP_ID_SHIFT ) );
        }
        if (!IEEE80211_ADDR_EQ(tmp_mac1,tmp_mac2) ) {
            printk("%s[%d]: Invalid mac address requested %s  \n",__func__,__LINE__,ether_sprintf(bssid));
            return -1;
        }
        ATH_GET_VAP_ID(bssid, ic->ic_my_hwaddr, id);

        if ((id_mask & (1 << id)) != 0) {
            printk("%s[%d]:mac address already allocated %s\n",__func__,__LINE__,ether_sprintf(bssid));
            return -1;
        }
     }
     else {

        for (id = 0; id < ATH_BCBUF; id++) {
             /* get the first available slot */
             if ((id_mask & (1 << id)) == 0)
                 break;
        }
        if (id == ATH_BCBUF) {
           /* no more ids left */
          printk("%s[%d]:No more free slots left \n",__func__,__LINE__);
          // DPRINTF(scn, ATH_DEBUG_STATE, "%s No more free slots left \n", __func__);
           return -1;
        }

    }


    /* set the allocated id in to the mask */
    scn->sc_prealloc_idmask |= (1 << id);

    return 0;
}

/*
 * free a  pre allocateed  mac addresses.
 */
static int
ol_ath_vap_free_macaddr(struct ieee80211com *ic, u_int8_t *bssid)
{
    /* TBD */
    return 0;
}

/* Intialization functions */
void
ol_ath_vap_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ic->ic_vap_create = ol_ath_vap_create;
    ic->ic_vap_delete = ol_ath_vap_delete;
    ic->ic_vap_alloc_macaddr = ol_ath_vap_alloc_macaddr;
    ic->ic_vap_free_macaddr = ol_ath_vap_free_macaddr;
    ic->ic_vap_set_param = ol_ath_vap_set_param;
    ic->ic_vap_set_ratemask = ol_ath_vap_set_ratemask;
    ic->ic_vap_dyn_bw_rts = ol_ath_vap_dyn_bw_rts;

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle, WMI_VDEV_STOPPED_EVENTID,
                                       wmi_unified_vdev_stopped_event_handler, NULL);
    wmi_unified_register_event_handler(scn->wmi_handle, WMI_ROAM_EVENTID,
                                       wmi_unified_roam_event_handler, NULL);

#if ATH_SUPPORT_ME_FW_BASED
    /* Register event handler for releasing the mcast buffers allocated once target
     * confirms it. This is done to sync host and target buffer allocations
     */
    wmi_unified_register_event_handler(scn->wmi_handle, WMI_MCAST_BUF_RELEASE_EVENTID,
		                       wmi_mcast_buf_release_handler, ic);
#endif /*ATH_SUPPORT_ME_FW_BASED*/

#if ATH_SUPPORT_GREEN_AP
    if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
        /* If the mode is HOSTAP, Start the Green-AP feature */
        ath_green_ap_start(ic);
    }
#endif  /* ATH_SUPPORT_GREEN_AP */

}


struct vap_id_map {
    struct ieee80211vap *vap;
    u_int8_t vdev_id;
};

void
ol_ath_vap_iter_id(void *arg, struct ieee80211vap *vap)
{
    struct vap_id_map *v_id_map = arg;

    if (vap->iv_unit == v_id_map->vdev_id) {
       v_id_map->vap = vap;
    }
}

struct ieee80211vap *
ol_ath_vap_get(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id)
{
    struct vap_id_map v_id_map;

    v_id_map.vap = NULL;
    v_id_map.vdev_id = vdev_id;

    //  Get a vap given the vdev_id : iterate through the vap list and get the vap. The ic maintains a list of vaps.
    wlan_iterate_vap_list(&scn->sc_ic, ol_ath_vap_iter_id, &v_id_map);
    return v_id_map.vap;
}

/*
 * Returns the corresponding vap based on vdev
 * Doest not involve looping through vap list to compare the vdevid to get the vap and doesnt
 * consume more CPU cycles.
 * TODO: Try to avoid using ol_ath_vap_get and switch over to ol_ath_getvap to get the vap information.
 */

struct ieee80211vap *
ol_ath_getvap(struct ol_txrx_vdev_t *vdev)
{
    ol_osif_vdev_handle osif = vdev->osif_vdev;
    osif_dev  *osdev = (osif_dev *)osif;

    return osdev->os_if;
}

u_int8_t *
ol_ath_vap_get_myaddr(struct ol_ath_softc_net80211 *scn, u_int8_t vdev_id)
{
    struct vap_id_map v_id_map;

    v_id_map.vap = NULL;
    v_id_map.vdev_id = vdev_id;

    //  Get a vap given the vdev_id : iterate through the vap list and get the vap. The ic maintains a list of vaps.
    wlan_iterate_vap_list(&scn->sc_ic, ol_ath_vap_iter_id, &v_id_map);

    if (v_id_map.vap) {
        return v_id_map.vap->iv_myaddr;
    } else {
        return NULL;
    }
}

#endif
