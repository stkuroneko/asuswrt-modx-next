/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_ctrl_txrx_api.h
 * @brief Define the host control API functions called by the host data SW.
 */
#ifndef _OL_CTRL_TXRX_API__H_
#define _OL_CTRL_TXRX_API__H_

//#include <a_osapi.h>      /* u_int8_t */
#include <osdep.h>        /* u_int8_t */
#include <adf_nbuf.h>     /* adf_nbuf_t */

#include <ol_ctrl_api.h>  /* ol_vdev_handle */
#include <ol_txrx_api.h>  /* ol_txrx_peer_handle */
#include <ieee80211.h>   /*ieee80211_frame */

enum ol_rx_err_type {
    OL_RX_ERR_DEFRAG_MIC,
    OL_RX_ERR_PN,
    OL_RX_ERR_UNKNOWN_PEER,
    OL_RX_ERR_MALFORMED,
    OL_RX_ERR_TKIP_MIC,
};

/**
 * @brief Provide notification of failure during host rx processing
 * @details
 *  Indicate an error during host rx data processing, including what
 *  kind of error happened, when it happened, which peer and TID the
 *  erroneous rx frame is from, and what the erroneous rx frame itself
 *  is.
 *
 * @param vdev_id - ID of the virtual device received the erroneous rx frame
 * @param peer_mac_addr - MAC address of the peer that sent the erroneous
 *      rx frame
 * @param tid - which TID within the peer sent the erroneous rx frame
 * @param tsf32  - the timstamp in TSF units of the erroneous rx frame, or
 *      one of the fragments that when reassembled, constitute the rx frame
 * @param err_type - what kind of error occurred
 * @param rx_frame - the rx frame that had an error
 */
void
ol_rx_err(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr,
    int tid,
    u_int32_t tsf32,
    enum ol_rx_err_type err_type,
    adf_nbuf_t rx_frame);


enum ol_rx_notify_type {
    OL_RX_NOTIFY_IPV4_IGMP,
};


/**
 * @brief Provide notification of reception of data of special interest.
 * @details
 *  Indicate when "special" data has been received.  The nature of the
 *  data that results in it being considered special is specified in the
 *  notify_type argument.
 *  This function is currently used by the data-path SW to notify the
 *  control path SW when the following types of rx data are received:
 *    + IPv4 IGMP frames
 *      The control SW can use these to learn about multicast group
 *      membership, if it so chooses.
 *
 * @param pdev - handle to the ctrl SW's physical device object
 * @param vdev_id - ID of the virtual device received the special data
 * @param peer_mac_addr - MAC address of the peer that sent the special data
 * @param tid - which TID within the peer sent the special data
 * @param tsf32  - the timstamp in TSF units of the special data
 * @param notify_type - what kind of special data was received
 * @param rx_frame - the rx frame containing the special data
 */
int
ol_rx_notify(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr,
    int tid,
    u_int32_t tsf32,
    enum ol_rx_notify_type notify_type,
    adf_nbuf_t rx_frame);

#if ATH_MCAST_HOST_INSPECT
/**
 * @brief notify mcast frame indication from FW.
 * @details
 *      This notification will be used to convert
 *      multicast frame to unicast.
 *
 * @param pdev - handle to the ctrl SW's physical device object
 * @param vdev_id - ID of the virtual device received the special data
 * @param msdu - the multicast msdu returned by FW for host inspect
 */
int ol_mcast_notify( ol_pdev_handle pdev,
        u_int8_t vdev_id, adf_nbuf_t msdu );
#endif /*ATH_MCAST_HOST_INSPECT*/
/**
 * @brief Provide wlan MAC fragmented packet forward status.
 * @details
 *  Get the forward status when fragmented data has been received.
 *
 * @param pdev - handle to the ctrl SW's physical device object
 * @param vdev_id - ID of the virtual device received the data
 * @param peer_mac_addr - MAC address of the destination peer
 */
int
ol_rx_intrabss_fwd_check(
    ol_pdev_handle pdev,
    u_int8_t vdev_id,
    u_int8_t *peer_mac_addr);


/**
 * @brief Indicate when a paused STA has tx data available.
 * @details
 *  Indicate to the control SW when a paused peer that previously
 *  has all its peer-TID queues empty gets a MSDU to transmit.
 *  Conversely, indicate when a paused peer that had data in one or more of
 *  its peer-TID queues has all queued data removed (e.g. due to a U-APSD
 *  triggered transmission), but is still paused.
 *  It is up to the control SW to determine whether the peer is paused due to
 *  being in power-save sleep, or some other reason, and thus whether it is
 *  necessary to set the TIM in beacons to notify a sleeping STA that it has
 *  data.
 *  The data SW will also issue this ol_tx_paused_peer_data call when an
 *  unpaused peer that currently has tx data in one or more of its
 *  peer-TID queues becomes paused.
 *  The data SW will not issue this ol_tx_paused_peer_data call when a
 *  peer with data in one or more of its peer-TID queues becomes unpaused.
 *
 * @param peer - the paused peer
 * @param has_tx_data -
 *      1 -> a paused peer that previously had no tx data now does, -OR-
 *      0 -> a paused peer that previously had tx data now doesnt
 */
void
ol_tx_paused_peer_data(ol_peer_handle peer, int has_tx_data);

/**
* @brief determine whether VoW has extended stats
* @param pdev - handle to the ctrl SW's physical device object
* @return
* 0 - extended VoW stats not supported
* 1 - extended VoW stats are supported
*/

u_int8_t ol_scn_vow_extstats(ol_pdev_handle pdev);

/**
 * @brief Required rx stats values are filled in passed parameters. 
 * @param pdev - handle to the ctrl SW's physical device object.
 *        phy_err_count - handle to phy error count variable.
 *        rx_clear_count- handle to rx clear count variable.
 *        rx_cycle_count- handle to rx cycle count variable.
 * @return zero for success, non-zero for error
 */

u_int32_t ol_scn_vow_get_rxstats(ol_pdev_handle pdev, u_int32_t *phy_err_count,  u_int32_t *rx_clear_count,  u_int32_t *rx_cycle_count);


#endif /* _OL_CTRL_TXRX_API__H_ */
