/*
 * Copyright (c) 2015-2016 Qualcomm Atheros, Inc.
 *
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary. 
 */

/*
 * osif_nss_wifiol_if.h
 *
 * This file used for for interface   NSS WiFi Offload Radio
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         15/june/2015              Created
 */

#ifndef __OSIF_NSS_WIFIOL_IF_H
#define __OSIF_NSS_WIFIOL_IF_H
#include <nss_api_if.h>
#include <ol_if_athvar.h>

#define OSIF_NSS_WIFI_CFG_TIMEOUT_MS  1000

int osif_nss_ol_wifi_init(void *hifctx);
int osif_nss_ol_pdev_attach(void *hifctx, void *nss_wifiol_ctx,
        int radio_id,
        uint32_t desc_pool_size,
        uint32_t *tx_desc_array,
        uint32_t wlanextdesc_addr,
        uint32_t wlanextdesc_size,
        uint32_t htt_tx_desc_base_vaddr, uint32_t htt_tx_desc_base_paddr ,
        uint32_t htt_tx_desc_offset,
        uint32_t pmap_addr);
int osif_nss_ol_wifi_pause(void *hifctx);
int osif_nss_ol_wifi_reset(void *hifctx, uint16_t delay);
void osif_nss_ol_post_recv_buffer(void *hifctx);
int osif_nss_ol_htt_rx_init(void *htt_handle );

int osif_ol_nss_htc_send( void *nss_wifiol_ctx, int nssid, adf_nbuf_t netbuf, uint32_t transfer_id );
int osif_nss_ol_mgmt_frame_send(void *nss_wifiol_ctx, int32_t radio_id, uint32_t desc_id, adf_nbuf_t netbuf);
int osif_nss_ol_pdev_add_wds_peer(ol_txrx_pdev_handle pdev, uint8_t *peer_mac, uint8_t *dest_mac);
int osif_nss_ol_pdev_del_wds_peer(ol_txrx_pdev_handle pdev, uint8_t *peer_mac, uint8_t *dest_mac);
int osif_nss_ol_stats_frame_send(void *nss_wifiol_ctx, int32_t radio_id, adf_nbuf_t netbuf);
int osif_nss_ol_wifi_monitor_set_filter(struct ieee80211com *ic, uint32_t filter_type);
void osif_nss_ol_set_msdu_ttl(struct ol_txrx_pdev_t *pdev);
void osif_nss_ol_set_perpkt_txstats(struct ol_ath_softc_net80211 *scn);
void osif_nss_ol_set_igmpmld_override_tos(struct ol_ath_softc_net80211 *scn);
int osif_nss_ol_pktlog_cfg(void *hifctx, int enable);
int osif_nss_ol_stats_cfg(void *hifctx, uint32_t cfg);
int osif_nss_tx_queue_cfg(struct ol_txrx_pdev_t *pdev, uint32_t range, uint32_t buf_size);
int osif_nss_tx_queue_min_threshold_cfg(struct ol_txrx_pdev_t *pdev, uint32_t min_threshold);
void osif_nss_ol_enable_dbdc_process(struct ieee80211com* ic, uint32_t enable);
void osif_nss_ol_set_primary_radio(struct ieee80211com* ic, uint32_t enable);
void osif_nss_ol_set_force_client_mcast_traffic(struct ieee80211com* ic);
void osif_nss_ol_store_other_pdev_stavap(struct ieee80211com* ic);
int osif_nss_peer_stats_frame_send(struct ol_txrx_pdev_t *pdev, uint16_t peer_id);
#endif







