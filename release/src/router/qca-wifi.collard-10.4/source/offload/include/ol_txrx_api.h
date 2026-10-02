/*
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */
/**
 * @file ol_txrx_api.h
 * @brief Definitions used in multiple external interfaces to the txrx SW.
 */
#ifndef _OL_TXRX_API__H_
#define _OL_TXRX_API__H_

/**
 * @typedef ol_txrx_pdev_handle
 * @brief opaque handle for txrx physical device object
 */
struct ol_txrx_pdev_t;
typedef struct ol_txrx_pdev_t* ol_txrx_pdev_handle;

/**
 * @typedef ol_txrx_vdev_handle
 * @brief opaque handle for txrx virtual device object
 */
struct ol_txrx_vdev_t;
typedef struct ol_txrx_vdev_t* ol_txrx_vdev_handle;

/**
 * @typedef ol_txrx_peer_handle
 * @brief opaque handle for txrx peer object
 */
struct ol_txrx_peer_t;
typedef struct ol_txrx_peer_t* ol_txrx_peer_handle;

#if ATH_SUPPORT_ME_FW_BASED
extern u_int16_t
ol_tx_desc_alloc_and_mark_for_mcast_clone(struct ol_txrx_pdev_t *pdev, u_int16_t buf_count);

extern u_int16_t
ol_tx_desc_free_and_unmark_for_mcast_clone(struct ol_txrx_pdev_t *pdev, u_int16_t buf_count);

extern u_int16_t
ol_tx_get_mcast_buf_allocated_marked(struct ol_txrx_pdev_t *pdev);
#else
extern void
ol_tx_me_alloc_descriptor(struct ol_txrx_pdev_t *pdev);

extern void
ol_tx_me_free_descriptor(struct ol_txrx_pdev_t *pdev);

extern uint16_t
ol_tx_me_init(struct ol_txrx_pdev_t *pdev);
extern void
ol_tx_me_exit(struct ol_txrx_pdev_t *pdev);
extern uint16_t
ol_tx_me_convert_ucast(ol_txrx_vdev_handle vdev, adf_nbuf_t wbuf,
                                u_int8_t newmac[][6], uint8_t newmaccnt);

/* opaque handle for ieee80211vap */
struct ieee80211vap;
extern int
ol_tx_mcast_enhance_process(struct ieee80211vap *vap, adf_nbuf_t skb);

#endif /*ATH_SUPPORT_ME_FW_BASED*/

#if !QCA_OL_TX_PDEV_LOCK && QCA_NSS_PLATFORM || (defined QCA_PARTNER_PLATFORM && QCA_PARTNER_SUPPORT_FAST_TX)
#define VAP_TX_SPIN_LOCK(_x) spin_lock(_x)
#define VAP_TX_SPIN_UNLOCK(_x) spin_unlock(_x)
#else /* QCA_OL_TX_PDEV_LOCK */
#define VAP_TX_SPIN_LOCK(_x)
#define VAP_TX_SPIN_UNLOCK(_x)
#endif /* QCA_OL_TX_PDEV_LOCK */

extern int ol_txrx_get_nwifi_mode(ol_txrx_vdev_handle vdev);
#define OL_TXRX_GET_NWIFI_MODE(vdev)  ol_txrx_get_nwifi_mode(vdev)

extern int ol_txrx_is_target_ar900b(ol_txrx_vdev_handle vdev);
#define OL_TXRX_IS_TARGET_AR900B(vdev)  ol_txrx_is_target_ar900b(vdev)

#if HOST_SW_TSO_ENABLE
extern int ol_tx_tso_process_skb(ol_txrx_vdev_handle vdev,adf_nbuf_t msdu);
#define OL_TX_LL_TSO_PROCESS(vdev,skb)  ol_tx_tso_process_skb(vdev,skb)
#else
#define OL_TX_LL_TSO_PROCESS(vdev,skb)
#endif /* HOST_SW_TSO_ENABLE */

#if HOST_SW_TSO_SG_ENABLE


extern int ol_tx_tso_sg_process_skb(ol_txrx_vdev_handle vdev,adf_nbuf_t msdu);
#define OL_TX_LL_TSO_SG_PROCESS(vdev,skb)  ol_tx_tso_sg_process_skb(vdev,skb)

#else
#define OL_TX_LL_TSO_SG_PROCESS(vdev,skb)
#endif /* HOST_SW_TSO_SG_ENABLE */

#if HOST_SW_SG_ENABLE
extern int ol_tx_sg_process_skb(ol_txrx_vdev_handle vdev,adf_nbuf_t msdu);
#define OL_TX_LL_SG_PROCESS(vdev,skb)  ol_tx_sg_process_skb(vdev,skb)
#else
#define OL_TX_LL_SG_PROCESS(vdev,skb)
#endif /* HOST_SW_SG_ENABLE */

#if QCA_OL_11AC_FAST_PATH && QCA_OL_TX_CACHEDHDR

#if PEER_FLOW_CONTROL
extern uint32_t
ol_tx_ll_cachedhdr(ol_txrx_vdev_handle vdev,  adf_nbuf_t msdu, uint16_t peer_id, uint8_t tid);
#else
extern uint32_t
ol_tx_ll_cachedhdr(ol_txrx_vdev_handle vdev,  adf_nbuf_t msdu);
#endif

#if PEER_FLOW_CONTROL

void
ol_tx_flush_tid_queue_pflow_ctrl(struct ol_txrx_pdev_t *pdev, u_int16_t peer_id, u_int8_t tid);

extern void
ol_txrx_per_peer_stats(struct ol_txrx_pdev_t *pdev, char *addr);

extern void
ol_tx_pflow_ctrl_cong_ctrl_timer(void *arg);

extern void
ol_tx_pflow_ctrl_stats_timer(void *arg);

extern void
ol_tx_pflow_ctrl_host_sched(void *arg);

void
ol_tx_pflow_ctrl_ttl(struct ol_txrx_pdev_t *pdev, u_int32_t peerid, u_int8_t tid);

extern uint32_t
ol_tx_ll_pflow_ctrl(ol_txrx_vdev_handle vdev, adf_nbuf_t netbuf);

uint32_t
ol_tx_ll_pflow_ctrl_list(ol_txrx_vdev_handle vdev,
        adf_nbuf_t *nbuf_arr,
        uint32_t num_msdus);

extern void
ol_tx_flush_buffers_pflow_ctrl(struct ol_txrx_pdev_t *pdev);

extern void
ol_tx_flush_peer_queue_pflow_ctrl(struct ol_txrx_pdev_t *pdev, u_int16_t peer_id);

extern uint16_t
ol_tx_classify_get_peer_id(struct ol_txrx_vdev_t *vdev, adf_nbuf_t nbuf);

void
ol_tx_switch_mode_flush_buffers(struct ol_txrx_pdev_t *pdev);

#define OL_TX_LL_FORWARD_PACKET(_vdev, _msdu, _num_msdus) ol_tx_ll_pflow_ctrl(_vdev, _msdu)

#define OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle) \
{ \
    ol_tx_ll_pflow_ctrl(_vdev, _msdu); \
}
#else
#define OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle) ol_tx_ll_cachedhdr(_vdev, _msdu)
#define OL_TX_LL_FORWARD_PACKET(_vdev, _msdu, _num_msdus) ol_tx_ll_fast(vdev, &_msdu, _num_msdus)
#endif

#if QCA_OL_TX_PDEV_LOCK
void ol_ll_pdev_tx_lock(void *);
void ol_ll_pdev_tx_unlock(void *);
#define OL_TX_LOCK(_x)  ol_ll_pdev_tx_lock(_x)
#define OL_TX_UNLOCK(_x) ol_ll_pdev_tx_unlock(_x)

#define OL_TX_PDEV_LOCK(_x)  adf_os_spin_lock_bh(_x)
#define OL_TX_PDEV_UNLOCK(_x) adf_os_spin_unlock_bh(_x)
#else
#define OL_TX_PDEV_LOCK(_x)
#define OL_TX_PDEV_UNLOCK(_x)

#define OL_TX_LOCK(_x)
#define OL_TX_UNLOCK(_x)
#endif /* QCA_OL_TX_PDEV_LOCK */

#if !QCA_OL_TX_PDEV_LOCK
#define OL_TX_FLOW_CTRL_LOCK(_x)  adf_os_spin_lock_bh(_x)
#define OL_TX_FLOW_CTRL_UNLOCK(_x) adf_os_spin_unlock_bh(_x)

#define OL_TX_DESC_LOCK(_x)  adf_os_spin_lock_bh(_x)
#define OL_TX_DESC_UNLOCK(_x) adf_os_spin_unlock_bh(_x)

#define OSIF_VAP_TX_LOCK(_x)  spin_lock(&((_x)->tx_lock))
#define OSIF_VAP_TX_UNLOCK(_x)  spin_unlock(&((_x)->tx_lock))

#define OL_TX_PEER_LOCK(_x, _id) adf_os_spin_lock_bh(&((_x)->peer_lock[_id]))
#define OL_TX_PEER_UNLOCK(_x, _id) adf_os_spin_unlock_bh(&((_x)->peer_lock[_id]))

#define OL_TX_PEER_UPDATE_LOCK(_x, _id) adf_os_spin_lock_bh(&((_x)->peer_lock[_id]))
#define OL_TX_PEER_UPDATE_UNLOCK(_x, _id) adf_os_spin_unlock_bh(&((_x)->peer_lock[_id]))

#else
#define OSIF_VAP_TX_LOCK(_x)  ol_ll_pdev_tx_lock((_x)->iv_txrx_handle)
#define OSIF_VAP_TX_UNLOCK(_x) ol_ll_pdev_tx_unlock((_x)->iv_txrx_handle)

#define OL_TX_FLOW_CTRL_LOCK(_x)
#define OL_TX_FLOW_CTRL_UNLOCK(_x)

#define OL_TX_DESC_LOCK(_x)
#define OL_TX_DESC_UNLOCK(_x)

#define OL_TX_PEER_LOCK(_x, _id)
#define OL_TX_PEER_UNLOCK(_x, _id)

#define OL_TX_PEER_UPDATE_LOCK(_x, _id) adf_os_spin_lock_bh(&((_x)->tx_lock))
#define OL_TX_PEER_UPDATE_UNLOCK(_x, _id) adf_os_spin_unlock_bh(&((_x)->tx_lock))

#endif /* !QCA_OL_TX_PDEV_LOCK */


extern uint32_t
ol_tx_ll_fast(ol_txrx_vdev_handle vdev,
        adf_nbuf_t *nbuf_arr,
#if PEER_FLOW_CONTROL
        uint32_t num_msdus,uint16_t peer_id,
        uint8_t tid);
#else
        uint32_t num_msdus);
#endif


#elif QCA_OL_11AC_FAST_PATH

extern uint32_t
ol_tx_ll_fast(ol_txrx_vdev_handle vdev,
        adf_nbuf_t *nbuf_arr,
        uint32_t num_msdus);
extern void
ol_tx_stats_inc_map_error(ol_txrx_vdev_handle vdev,
                             uint32_t num_map_error);
#define OL_TX_LL_WRAPPER(_vdev, _msdu, _oshandle) \
{\
    if(A_STATUS_FAILED == adf_nbuf_map_single( _oshandle , _msdu, ADF_OS_DMA_TO_DEVICE)){;\
        ol_tx_stats_inc_map_error(_vdev, 1); \
        adf_nbuf_free(_msdu); \
    }else{ \
        if (adf_os_unlikely(ol_tx_ll_fast(_vdev, &_msdu, 1 ))){ \
            adf_nbuf_unmap_single( _oshandle, _msdu, ADF_OS_DMA_TO_DEVICE); \
            adf_nbuf_free(_msdu); \
        } \
    } \
}

#endif /* QCA_OL_11AC_FAST_PATH && QCA_OL_TX_CACHEDHDR*/

#endif /* _OL_TXRX_API__H_ */
