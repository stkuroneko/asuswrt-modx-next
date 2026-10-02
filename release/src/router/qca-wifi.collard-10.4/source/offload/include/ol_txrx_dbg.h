/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_dbg.h
 * @brief Functions provided for visibility and debugging.
 */
#ifndef _OL_TXRX_DBG__H_
#define _OL_TXRX_DBG__H_

#include <athdefs.h>       /* A_STATUS, u_int64_t */
#include <adf_os_lock.h>   /* adf_os_mutex_t */
#include <htt.h>           /* htt_dbg_stats_type */
#include <ol_txrx_stats.h> /* ol_txrx_stats */

typedef void (*ol_txrx_stats_callback)(
    void *ctxt,
    enum htt_dbg_stats_type type,
    u_int8_t *buf,
    int bytes);

struct ol_txrx_stats_req {
    u_int32_t stats_type_upload_mask; /* which stats to upload */
    u_int32_t stats_type_reset_mask;  /* which stats to reset */

    /* stats will be printed if either print element is set */
    struct {
        int verbose; /* verbose stats printout */
        int concise; /* concise stats printout (takes precedence) */
    } print; /* print uploaded stats */

    /* stats notify callback will be invoked if fp is non-NULL */
    struct {
        ol_txrx_stats_callback fp;
        void *ctxt;
    } callback;

    /* stats will be copied into the specified buffer if buf is non-NULL */
    struct {
        u_int8_t *buf;
        int byte_limit; /* don't copy more than this */
    } copy;

    /*
     * If blocking is true, the caller will take the specified semaphore
     * to wait for the stats to be uploaded, and the driver will release
     * the semaphore when the stats are done being uploaded.
     */
    struct {
        int blocking;
        adf_os_mutex_t *sem_ptr;
    } wait;
};

struct ol_txrx_stats_req_internal {
    struct ol_txrx_stats_req base;
    int serviced; /* state of this request */
    int offset;
};

#define TXRX_FW_STATS_TXSTATS                     1
#define TXRX_FW_STATS_RXSTATS                     2
#define TXRX_FW_STATS_RX_RATE_INFO                3
#define TXRX_FW_STATS_PHYSTATS                    4
#define TXRX_FW_STATS_PHYSTATS_CONCISE            5
#define TXRX_FW_STATS_TX_RATE_INFO                6
#define TXRX_FW_STATS_TID_STATE                   7
#define TXRX_FW_STATS_HOST_STATS                  8
#define TXRX_FW_STATS_CLEAR_HOST_STATS            9
#define TXRX_FW_STATS_CE_STATS                   10
#define TXRX_FW_STATS_VOW_UMAC_COUNTER           11
#define TXRX_FW_STATS_ME_STATS                   12
#define TXRX_FW_STATS_TXBF_INFO                  13
#define TXRX_FW_STATS_SND_INFO                   14
#define TXRX_FW_STATS_ERROR_INFO                 15
#define TXRX_FW_STATS_TX_SELFGEN_INFO            16
#define TXRX_FW_STATS_TX_MU_INFO                 17
#define TXRX_FW_SIFS_RESP_INFO                   18
#define TXRX_FW_RESET_STATS                      19
#define TXRX_FW_MAC_WDOG_STATS                   20
#define TXRX_FW_MAC_DESC_STATS                   21
#define TXRX_FW_MAC_FETCH_MGR_STATS              22
#define TXRX_FW_MAC_PREFETCH_MGR_STATS           23

#define BSS_CHAN_INFO_READ                        1
#define BSS_CHAN_INFO_READ_AND_CLEAR              2

#if ATH_PERF_PWR_OFFLOAD == 0 /*---------------------------------------------*/

#define ol_txrx_debug(vdev, debug_specs) 0
#define ol_txrx_fw_stats_cfg(vdev, type, val) 0
#define ol_txrx_fw_stats_get(vdev, req, per_vap) 0
#define ol_txrx_aggr_cfg(vdev, max_subfrms_ampdu, max_subfrms_amsdu) 0

#else /*---------------------------------------------------------------------*/


#include <ol_txrx_api.h> /* ol_txrx_pdev_handle, etc. */

/* Macro to defrentiate if stats are requested per vap or per radio */
#define PER_RADIO_FW_STATS_REQUEST 0
#define PER_VAP_FW_STATS_REQUEST 1

int ol_txrx_debug(ol_txrx_vdev_handle vdev, int debug_specs);

void ol_txrx_fw_stats_cfg(
    ol_txrx_vdev_handle vdev,
    u_int8_t cfg_stats_type,
    u_int32_t cfg_val);

int ol_txrx_fw_stats_get(
    ol_txrx_vdev_handle vdev,
    struct ol_txrx_stats_req *req,
    bool per_vap);

#if QCA_OL_11AC_FAST_PATH
int ol_txrx_host_stats_get(
    ol_txrx_vdev_handle vdev,
    struct ol_txrx_stats_req *req);

#if PEER_FLOW_CONTROL
int ol_txrx_host_msdu_ttl_stats(
    ol_txrx_vdev_handle vdev,
    struct ol_txrx_stats_req *req);
#endif

void
ol_txrx_host_stats_clr(ol_txrx_vdev_handle vdev);

void
ol_txrx_host_ce_stats(ol_txrx_vdev_handle vdev);
A_STATUS
#if ATH_SUPPORT_IQUE
ol_txrx_host_me_stats(ol_txrx_vdev_handle vdev);
#endif
#endif /* QCA_OL_11AC_FAST_PATH */



#if defined(TEMP_AGGR_CFG)
int ol_txrx_aggr_cfg(ol_txrx_vdev_handle vdev,
                     int max_subfrms_ampdu,
                     int max_subfrms_amsdu);
#else
#define ol_txrx_aggr_cfg(vdev, max_subfrms_ampdu, max_subfrms_amsdu) 0
#endif
struct ieee80211com;
enum {
    TXRX_DBG_MASK_OBJS             = 0x01,
    TXRX_DBG_MASK_STATS            = 0x02,
    TXRX_DBG_MASK_PROT_ANALYZE     = 0x04,
    TXRX_DBG_MASK_RX_REORDER_TRACE = 0x08,
    TXRX_DBG_MASK_RX_PN_TRACE      = 0x10
};

/*--- txrx printouts ---*/

/*
 * Uncomment this to enable txrx printouts with dynamically adjustable
 * verbosity.  These printouts should not impact performance.
 */
#define TXRX_PRINT_ENABLE 0
/* uncomment this for verbose txrx printouts (may impact performance) */
//#define TXRX_PRINT_VERBOSE_ENABLE 1

void ol_txrx_print_level_set(unsigned level);

/*--- txrx object (pdev, vdev, peer) display debug functions ---*/

#ifndef TXRX_DEBUG_LEVEL
#define TXRX_DEBUG_LEVEL 0 /* no debug info */
#endif

#if TXRX_DEBUG_LEVEL > 5
void ol_txrx_pdev_display(ol_txrx_pdev_handle pdev, int indent);
void ol_txrx_vdev_display(ol_txrx_vdev_handle vdev, int indent);
void ol_txrx_peer_display(ol_txrx_peer_handle peer, int indent);
#else
#define ol_txrx_pdev_display(pdev, indent)
#define ol_txrx_vdev_display(vdev, indent)
#define ol_txrx_peer_display(peer, indent)
#endif

/*--- txrx stats display debug functions ---*/

#if TXRX_STATS_LEVEL != TXRX_STATS_LEVEL_OFF

void ol_txrx_stats_display(ol_txrx_pdev_handle pdev);

int
ol_txrx_stats_publish(ol_txrx_pdev_handle pdev, struct ol_txrx_stats *buf);

#else
#define ol_txrx_stats_display(pdev)
#define ol_txrx_stats_publish(pdev, buf) TXRX_STATS_LEVEL_OFF
#endif /* TXRX_STATS_LEVEL */

/*--- txrx protocol analyzer debug feature ---*/

/* uncomment this to enable the protocol analzyer feature */
//#define ENABLE_TXRX_PROT_ANALYZE 1

#if defined(ENABLE_TXRX_PROT_ANALYZE)

void ol_txrx_prot_ans_display(ol_txrx_pdev_handle pdev);

#else

#define ol_txrx_prot_ans_display(pdev)

#endif /* ENABLE_TXRX_PROT_ANALYZE */

/*--- txrx sequence number trace debug feature ---*/

/* uncomment this to enable the rx reorder trace feature */
//#define ENABLE_RX_REORDER_TRACE 1

#define ol_txrx_seq_num_trace_display(pdev) \
    ol_rx_reorder_trace_display(pdev, 0, 0)

#if defined(ENABLE_RX_REORDER_TRACE)

void
ol_rx_reorder_trace_display(ol_txrx_pdev_handle pdev, int just_once, int limit);

#else

#define ol_rx_reorder_trace_display(pdev, just_once, limit)

#endif /* ENABLE_RX_REORDER_TRACE */

/*--- txrx packet number trace debug feature ---*/

/* uncomment this to enable the rx PN trace feature */
//#define ENABLE_RX_PN_TRACE 1

#define ol_txrx_pn_trace_display(pdev) ol_rx_pn_trace_display(pdev, 0)

#if defined(ENABLE_RX_PN_TRACE)

void
ol_rx_pn_trace_display(ol_txrx_pdev_handle pdev, int just_once);

#else

#define ol_rx_pn_trace_display(pdev, just_once)

#endif /* ENABLE_RX_PN_TRACE */

#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
void
ol_tx_print_tso_stats(
		    ol_txrx_vdev_handle vdev);

void
ol_tx_rst_tso_stats(ol_txrx_vdev_handle vdev);
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
void
ol_tx_print_sg_stats(
		    ol_txrx_vdev_handle vdev);

void
ol_tx_rst_sg_stats(ol_txrx_vdev_handle vdev);
#endif /* HOST_SW_SG_ENABLE */

#if RX_CHECKSUM_OFFLOAD
void
ol_print_rx_cksum_stats(
		    ol_txrx_vdev_handle vdev);

void
ol_rst_rx_cksum_stats(ol_txrx_vdev_handle vdev);
#endif /* RX_CHECKSUM_OFFLOAD */


#endif /* ATH_PERF_PWR_OFFLOAD  */ /*----------------------------------------*/

#endif /* _OL_TXRX_DBG__H_ */
