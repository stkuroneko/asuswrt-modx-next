/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_osif_api.h
 * @brief Define the host data API functions called by the host OS shim SW.
 */
#ifndef _OL_TXRX_OSIF_API__H_
#define _OL_TXRX_OSIF_API__H_

#include <adf_nbuf.h>     /* adf_nbuf_t */

#include <ol_osif_api.h> /* ol_osif_vdev_handle */
#include <ol_txrx_api.h> /* ol_txrx_pdev_handle, etc. */

/**
 * @typedef ol_txrx_tx_fp
 * @brief top-level transmit function
 */
typedef adf_nbuf_t (*ol_txrx_tx_fp)(
    ol_txrx_vdev_handle data_vdev, adf_nbuf_t msdu_list);

/**
 * @enum ol_txrx_osif_tx_spec
 * @brief indicate what non-standard transmission actions to apply
 * @details
 *  Indicate one or more of the following:
 *    - The tx frame already has a complete 802.11 header.
 *      Thus, skip 802.3/native-WiFi to 802.11 header encapsulation and
 *      A-MSDU aggregation.
 *    - The tx frame should not be aggregated (A-MPDU or A-MSDU)
 *    - The tx frame is already encrypted - don't attempt encryption.
 *    - The tx frame is a segment of a TCP jumbo frame.
 *  More than one of these specification can apply, though typically
 *  only a single specification is applied to a tx frame.
 *  A compound specification can be created, as a bit-OR of these
 *  specifications.
 */
enum ol_txrx_osif_tx_spec {
     ol_txrx_osif_tx_spec_std         = 0x0,  /* do regular processing */
     ol_txrx_osif_tx_spec_raw         = 0x1,  /* skip encap + A-MSDU aggr */
     ol_txrx_osif_tx_spec_no_aggr     = 0x2,  /* skip encap + all aggr */
     ol_txrx_osif_tx_spec_no_encrypt  = 0x4,  /* skip encap + encrypt */
     ol_txrx_osif_tx_spec_tso         = 0x8,  /* TCP segmented */
     ol_txrx_osif_tx_spect_nwifi_no_encrypt = 0x10, /* skip encrypt for nwifi */
};

#define OL_TXRX_OSIF_TX_EXT_TID_NON_QOS_MCAST_BCAST 16
#define OL_TXRX_OSIF_TX_EXT_TID_MGMT                17
#define OL_TXRX_OSIF_TX_EXT_TID_INVALID             31

/**
 * @typedef ol_txrx_tx_non_std_fp
 * @brief top-level transmit function for non-standard tx frames
 * @details
 *  This function pointer provides an alternative to the ol_txrx_tx_fp
 *  to support non-standard transmits.  In particular, this function
 *  supports transmission of:
 *  1. "Raw" frames
 *     These raw frames already have an 802.11 header; the usual
 *     802.11 header encapsulation by the driver does not apply.
 *  2. TSO segments
 *     During tx completion, the txrx layer needs to reclaim the buffer
 *     that holds the ethernet/IP/TCP header created for the TSO segment.
 *     Thus, these tx frames need to be marked as TSO, to show that they
 *     need this special handling during tx completion.
 *  3. Out-of-band priority frames
 *     In the standard case, the frame's traffic type / priority (TID) is
 *     inferred from fields within the IP header, such as the IPv4 header's
 *     ToS/DSCP byte.  The OS shim can override this standard behavior by
 *     directly specifying the TID to use when queuing, aggregating, and
 *     transmitting the tx frame.
 *
 * @param data_vdev - which virtual device should transmit the frame
 * @param ext_tid - The frame's traffic type / priority.
 *      This value is an extension of the 4-bit 802.11 TID.
 *      Extension values can specify that a frame is a non-QoS or multicast
 *      data frame, or a management/control frame.
 *      To avoid explicitly specifying the TID, and instead have the WLAN
 *      driver infer the TID as usual from the IP header, specify the
 *      OL_TXRX_OSIF_TX_EXT_TID_INVALID value.
 * @param tx_spec - what non-standard operations to apply to the tx frame
 * @param msdu_list - tx frame(s), in a null-terminated list
 */
typedef adf_nbuf_t (*ol_txrx_tx_non_std_fp)(
    ol_txrx_vdev_handle data_vdev,
    u_int8_t ext_tid,
    enum ol_txrx_osif_tx_spec tx_spec,
    adf_nbuf_t msdu_list);

#if UMAC_SUPPORT_PROXY_ARP
typedef int (*ol_txrx_proxy_arp_fp)(ol_osif_vdev_handle vdev, adf_nbuf_t netbuf);
#endif

/**
 * @typedef ol_txrx_rx_fp
 * @brief receive function to hand batches of data frames from txrx to OS shim
 */
typedef void (*ol_txrx_rx_fp)(ol_osif_vdev_handle vdev, adf_nbuf_t msdus);
#if ATH_SUPPORT_WAPI
typedef bool (*ol_rx_check_wai_fp)(ol_osif_vdev_handle vdev, adf_nbuf_t mpdu_head, adf_nbuf_t mpdu_tail);
#endif

/**
 * @typedef ol_txrx_rx_mon_fp
 * @brief OSIF monitor mode receive function for single MPDU (802.11 format)
 */
typedef void (*ol_txrx_rx_mon_fp)(
    ol_osif_vdev_handle vdev,
    adf_nbuf_t mpdu,
    void *rx_status);

struct ol_txrx_osif_ops {
    /* tx function pointers - specified by txrx, stored by OS shim */
    struct {
        ol_txrx_tx_fp         std;
        ol_txrx_tx_non_std_fp non_std;
    } tx;

    /* rx function pointers - specified by OS shim, stored by txrx */
    struct {
        ol_txrx_rx_fp         std;
#if ATH_SUPPORT_WAPI
        ol_rx_check_wai_fp    wai_check;
#endif
        ol_txrx_rx_mon_fp     mon;
    } rx;

#if UMAC_SUPPORT_PROXY_ARP
    /* proxy arp function pointer - specified by OS shim, stored by txrx */
    ol_txrx_proxy_arp_fp      proxy_arp;
#endif
};

/**
 * @brief Link a vdev's data object with the matching OS shim vdev object.
 * @details
 *  The data object for a virtual device is created by the function
 *  ol_txrx_vdev_attach.  However, rather than fully linking the
 *  data vdev object with the vdev objects from the other subsystems
 *  that the data vdev object interacts with, the txrx_vdev_attach
 *  function focuses primarily on creating the data vdev object.
 *  After the creation of both the data vdev object and the OS shim
 *  vdev object, this txrx_osif_vdev_attach function is used to connect
 *  the two vdev objects, so the data SW can use the OS shim vdev handle
 *  when passing rx data received by a vdev up to the OS shim.
 *
 * @param txrx_vdev - the virtual device's data object
 * @param osif_vdev - the virtual device's OS shim object
 * @param txrx_ops - (pointers to) the functions used for tx and rx data xfer
 *      There are two portions of these txrx operations.
 *      The rx portion is filled in by OSIF SW before calling
 *      ol_txrx_osif_vdev_register; inside the ol_txrx_osif_vdev_register
 *      the txrx SW stores a copy of these rx function pointers, to use
 *      as it delivers rx data frames to the OSIF SW.
 *      The tx portion is filled in by the txrx SW inside
 *      ol_txrx_osif_vdev_register; when the function call returns,
 *      the OSIF SW stores a copy of these tx functions to use as it
 *      delivers tx data frames to the txrx SW.
 *      The rx function pointer inputs consist of the following:
 *      rx: the OS shim rx function to deliver rx data frames to.
 *          This can have different values for different virtual devices,
 *          e.g. so one virtual device's OS shim directly hands rx frames to
 *          the OS, but another virtual device's OS shim filters out P2P
 *          messages before sending the rx frames to the OS.
 *          The netbufs delivered to the osif_rx function are in the format
 *          specified by the OS to use for tx and rx frames (either 802.3 or
 *          native WiFi).
 *      rx_mon: the OS shim rx monitor function to deliver monitor data to
 *          Though in practice, it is probable that the same function will
 *          be used for delivering rx monitor data for all virtual devices,
 *          in theory each different virtual device can have a different
 *          OS shim function for accepting rx monitor data.
 *          The netbufs delivered to the osif_rx_mon function are in 802.11
 *          format.  Each netbuf holds a 802.11 MPDU, not an 802.11 MSDU.
 *          Depending on compile-time configuration, each netbuf may also
 *          have a monitor-mode encapsulation header such as a radiotap
 *          header added before the MPDU contents.
 *      The tx function pointer outputs consist of the following:
 *      tx: the tx function pointer for standard data frames
 *          This function pointer is set by the txrx SW to perform
 *          host-side transmit operations based on whether a HL or LL
 *          host/target interface is in use.
 *      tx_non_std: the tx function pointer for non-standard data frames,
 *          such as TSO frames, explicitly-prioritized frames, or "raw"
 *          frames which skip some of the tx operations, such as 802.11
 *          MAC header encapsulation.
 */
void
ol_txrx_osif_vdev_register(
    ol_txrx_vdev_handle txrx_vdev,
    ol_osif_vdev_handle osif_vdev,
    struct ol_txrx_osif_ops *txrx_ops);

/**
 * @brief Divide a jumbo TCP frame into smaller segments.
 * @details
 *  For efficiency, the protocol stack above the WLAN driver may operate
 *  on jumbo tx frames, which are larger than the 802.11 MTU.
 *  The OSIF SW uses this txrx API function to divide the jumbo tx TCP frame
 *  into a series of segment frames.
 *  The segments are created as clones of the input jumbo frame.
 *  The txrx SW generates a new encapsulation header (ethernet + IP + TCP)
 *  for each of the output segment frames.  The exact format of this header,
 *  e.g. 802.3 vs. Ethernet II, and IPv4 vs. IPv6, is chosen to match the
 *  header format of the input jumbo frame.
 *  The input jumbo frame is not modified.
 *  After the ol_txrx_osif_tso_segment returns, the OSIF SW needs to perform
 *  DMA mapping on each of the segment network buffers, and also needs to
 *
 * @param txrx_vdev - which virtual device will transmit the TSO segments
 * @param max_seg_payload_bytes - the maximum size for the TCP payload of
 *      each segment frame.
 *      This does not include the ethernet + IP + TCP header sizes.
 * @param jumbo_tcp_frame - jumbo frame which needs to be cloned+segmented
 * @return
 *      NULL if the segmentation fails, - OR -
 *      a NULL-terminated list of segment network buffers
 */
adf_nbuf_t ol_txrx_osif_tso_segment(
    ol_txrx_vdev_handle txrx_vdev,
    int max_seg_payload_bytes,
    adf_nbuf_t jumbo_tcp_frame);


#endif /* _OL_TXRX_OSIF_API__H_ */
