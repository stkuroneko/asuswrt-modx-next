/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_status.h
 * @brief Functions provided for visibility and debugging.
 * NOTE: This file is used by both kernel driver SW and userspace SW.
 * Thus, do not reference use any kernel header files or defs in this file!
 */
#ifndef _OL_TXRX_STATS__H_
#define _OL_TXRX_STATS__H_

#include <athdefs.h>       /* u_int64_t */
#include "wlan_defs.h" /* for wlan statst definitions */

#define TXRX_STATS_LEVEL_OFF   0
#define TXRX_STATS_LEVEL_BASIC 1
#define TXRX_STATS_LEVEL_FULL  2

#ifndef TXRX_STATS_LEVEL
#define TXRX_STATS_LEVEL TXRX_STATS_LEVEL_BASIC
#endif

/*
 * TODO: Following needs a better #define
 *       Currently this works, since x86-64 can handle
 *       64 bit and db12x / ap135 needs only 32 bits
 */
#ifndef BIG_ENDIAN_HOST
typedef struct {
   u_int32_t pkts;
   u_int32_t bytes;
} ol_txrx_stats_elem;
#else
struct ol_txrx_elem_t {
   u_int32_t pkts;
   u_int32_t bytes;
};
typedef struct ol_txrx_elem_t ol_txrx_stats_elem;
#endif

/**
 * @brief data stats published by the host txrx layer
 */
struct ol_txrx_stats {
    struct {
        /* MSDUs received from the stack */
        ol_txrx_stats_elem from_stack;
        /* MSDUs successfully sent across the WLAN */
        ol_txrx_stats_elem delivered;
        struct {
            /* MSDUs that the host did not accept */
            ol_txrx_stats_elem host_reject;
            /* MSDUs which could not be downloaded to the target */
            ol_txrx_stats_elem download_fail;
            /* MSDUs which the target discarded (lack of mem or old age) */
            ol_txrx_stats_elem target_discard;
            /* MSDUs which the target sent but couldn't get an ack for */
            ol_txrx_stats_elem no_ack;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            /* MSDUs dropped in NSS-FW */
            ol_txrx_stats_elem nss_ol_dropped;
#endif
        } dropped;
        u_int32_t desc_in_use;
        u_int32_t desc_alloc_fails;
        u_int32_t ce_ring_full;
        u_int32_t dma_map_error;
        /* MSDUs given to the txrx layer by the management stack */
        ol_txrx_stats_elem mgmt;
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
	struct {
		/* TSO applied jumbo packets received from NW Stack */
		ol_txrx_stats_elem tso_pkts;
		/* Non - TSO packets */
		ol_txrx_stats_elem non_tso_pkts;
		/* TSO packets : Dropped during TCP segmentation*/
		ol_txrx_stats_elem tso_dropped;
		/* TSO Descriptors */
		u_int32_t tso_desc_cnt;
	} tso;
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
	struct {
		/* TSO applied jumbo packets received from NW Stack */
		ol_txrx_stats_elem sg_pkts;
		/* Non - TSO packets */
		ol_txrx_stats_elem non_sg_pkts;
		/* TSO packets : Dropped during TCP segmentation*/
		ol_txrx_stats_elem sg_dropped;
		/* TSO Descriptors */
		u_int32_t sg_desc_cnt;
	} sg;
#endif /* HOST_SW_SG_ENABLE */
        struct {
                /* packets enqueued for flow control */
                u_int32_t fl_ctrl_enqueue;
                /* packets discarded for flow control is full */
                u_int32_t fl_ctrl_discard;
                /* packets sent to CE without flow control */
                u_int32_t fl_ctrl_avoid;
        } fl_ctrl;
    } tx;
    struct {
        /* MSDUs given to the OS shim */
        ol_txrx_stats_elem delivered;
        /* MSDUs forwarded from the rx path to the tx path */
        ol_txrx_stats_elem forwarded;
#if RX_CHECKSUM_OFFLOAD
        /* MSDUs in which ipv4 chksum error detected by HW */
        ol_txrx_stats_elem ipv4_cksum_err;
        /* MSDUs in which tcp chksum error detected by HW */
        ol_txrx_stats_elem tcp_ipv4_cksum_err;
        /* MSDUs in which udp chksum error detected by HW */
        ol_txrx_stats_elem udp_ipv4_cksum_err;
        /* MSDUs in which tcp V6 chksum error detected by HW */
        ol_txrx_stats_elem tcp_ipv6_cksum_err;
        /* MSDUs in which UDP V6 chksum error detected by HW */
        ol_txrx_stats_elem udp_ipv6_cksum_err;
#endif /* RX_CHECKSUM_OFFLOAD */

    } rx;
    struct {
        /* Number of mcast recieved for conversion */
        u_int32_t num_me_rcvd;
        /* Number of unicast sent as part of mcast conversion */
        u_int32_t num_me_ucast;
        /* Number of multicast frames dropped due to dma_map failure */
        u_int32_t num_me_dropped_m;
        /* Number of multicast frames dropped due to allocation failure */
        u_int32_t num_me_dropped_a;
        /* Number of multicast frames dropped due to internal failure */
        u_int32_t num_me_dropped_i;
        /* Number of me buf currently in use */
        u_int32_t num_me_buf;
        /* Number of me buf frames to self mac address  */
        u_int32_t num_me_dropped_s;
        /* Number of me buf in use in non pool based allocation*/
        u_int32_t num_me_nonpool;
        /* Number of me buf allocated using non pool based allocation*/
        u_int32_t num_me_nonpool_count;
    } mcast_enhance;
};

/*
 * Structure to consolidate host stats
 */
struct ieee80211req_ol_ath_host_stats {
    struct ol_txrx_stats txrx_stats;
    struct {
        int pkt_q_fail_count;
        int pkt_q_empty_count;
        int send_q_empty_count;
    } htc;
    struct {
        int pipe_no_resrc_count;
        int ce_ring_delta_fail_count;
    } hif;
};

struct ol_ath_dbg_rx_rssi {
    A_UINT8     rx_rssi_pri20;
    A_UINT8     rx_rssi_sec20;
    A_UINT8     rx_rssi_sec40;
    A_UINT8     rx_rssi_sec80;
};

struct ol_ath_radiostats {
    A_UINT64    tx_beacon;
    A_UINT32    be_nobuf;
    A_UINT32    tx_buf_count;
    A_UINT32    tx_packets;
    A_UINT32    rx_packets;
    A_INT32     tx_mgmt;
    A_UINT32    tx_num_data;
    A_UINT32    rx_num_data;
    A_INT32     rx_mgmt;
    A_UINT32    rx_num_mgmt;
    A_UINT32    rx_num_ctl;
    A_UINT32    tx_rssi;
    A_UINT32    tx_mcs[10];
    A_UINT32    rx_mcs[10];
    A_UINT32    rx_rssi_comb;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain0;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain1;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain2;
    struct      ol_ath_dbg_rx_rssi rx_rssi_chain3;
    A_UINT64    rx_bytes;
    A_UINT64    tx_bytes;
    A_UINT32    tx_compaggr;
    A_UINT32    rx_aggr;
    A_UINT32    tx_bawadv;
    A_UINT32    tx_compunaggr;
    A_UINT32    rx_overrun;
    A_UINT32    rx_badcrypt;
    A_UINT32    rx_badmic;
    A_UINT32    rx_crcerr;
    A_UINT32    rx_phyerr;
    A_UINT32    ackRcvBad;
    A_UINT32    rtsBad;
    A_UINT32    rtsGood;
    A_UINT32    fcsBad;
    A_UINT32    noBeacons;
    A_UINT32    mib_int_count;
    A_UINT32    rx_looplimit_start;
    A_UINT32    rx_looplimit_end;
    A_UINT8     ap_stats_tx_cal_enable;
    A_UINT32	tgt_asserts;
    A_INT16     chan_nf;
    A_UINT32    rx_last_msdu_unset_cnt;
    A_INT16     chan_nf_sec80;
};

#endif /* _OL_TXRX_STATS__H_ */
