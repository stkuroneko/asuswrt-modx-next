/*
 * Copyright (c) 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _IEEE80211_RATE_ESTIMATE_H
#define _IEEE80211_RATE_ESTIMATE_H

/**
 * @brief Enumerations for bandwidth (MHz) supported by STA
 */
typedef enum wlan_chwidth_e {
    wlan_chwidth_20,
    wlan_chwidth_40,
    wlan_chwidth_80,
    wlan_chwidth_160,

    wlan_chwidth_invalid
} wlan_chwidth_e;

/**
 * @brief Enumerations for IEEE802.11 PHY mode
 */
typedef enum wlan_phymode_e {
    wlan_phymode_basic,
    wlan_phymode_ht,
    wlan_phymode_vht,

    wlan_phymode_invalid
} wlan_phymode_e;

/* global functions */
extern u_int16_t ieee80211_SNRToPhyRateTablePerformLookup(
                struct ieee80211vap *vap,
                u_int8_t snr, int nss,
                wlan_phymode_e phyMode,
                wlan_chwidth_e chwidth);

/* Inline functions */
static inline wlan_phymode_e convert_phymode(struct ieee80211vap *vap)
{
    wlan_chan_t c = wlan_get_bss_channel(vap);

    if ((c == NULL) || (c == IEEE80211_CHAN_ANYC)) {
        return wlan_phymode_invalid;
    }

    if (IEEE80211_IS_CHAN_108G(c) ||
            IEEE80211_IS_CHAN_108A(c) ||
            IEEE80211_IS_CHAN_TURBO(c) ||
            IEEE80211_IS_CHAN_ANYG(c) ||
            IEEE80211_IS_CHAN_A(c) ||
            IEEE80211_IS_CHAN_B(c))
        return wlan_phymode_basic;
    else if (IEEE80211_IS_CHAN_11NG(c) || IEEE80211_IS_CHAN_11NA(c))
        return wlan_phymode_ht;
    else if (IEEE80211_IS_CHAN_11AC(c))
        return wlan_phymode_vht;
    else
        return wlan_phymode_invalid;
}

#endif //_IEEE80211_RATE_ESTIMATE_H
