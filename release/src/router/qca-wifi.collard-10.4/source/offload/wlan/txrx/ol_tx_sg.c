/*
 *  * Copyright (c) 2011 Qualcomm Atheros, Inc.
 *   * All Rights Reserved.
 *    * Qualcomm Atheros Confidential and Proprietary.
 *     */

#include <adf_nbuf.h>         /* adf_nbuf_t, etc. */

#include <ol_txrx_internal.h> /* TXRX_ASSERT1 */
#include <ol_txrx_types.h>    /* pdev stats */
#include <ol_tx_desc.h>       /* ol_tx_desc */
#include <ol_tx_send.h>       /* ol_tx_send */
#include <ol_txrx_api.h>       /* ol_tx_send */
#include <ol_txrx.h>          


/* FIXME Need to remove hard-coded
 * header file inclusions and
 * change as a part of convergent driver
 */
#include <AR900B/hw/datastruct/msdu_link_ext.h>
#include <QCA9984/hw/datastruct/msdu_link_ext.h>
#include <QCA9888/v2/hw/datastruct/msdu_link_ext.h>

#define SG_DBG 0

void
ol_tx_sg_desc_display(void *tx_desc)
{
    struct ol_tx_sg_desc_t *tx_sg_desc = (struct ol_tx_sg_desc_t *)tx_desc;
    int count;

    if(!tx_sg_desc) return;
    adf_os_print("==========SG Descriptor==============>\n");
    adf_os_print("tx_sg_desc %x \n",(A_UINT32 )tx_sg_desc);
    adf_os_print("tx_sg_desc->frag_cnt %d \n", tx_sg_desc->frag_cnt);
    adf_os_print("tx_sg_desc->total_len %d \n", tx_sg_desc->total_len);

    for (count = 0; count < tx_sg_desc->frag_cnt; count++)
        adf_os_print("frag addr[%d]: %x, frag_len: %d\n", count, tx_sg_desc->frag_paddr_lo[count], tx_sg_desc->frag_len[count]);
}


static inline struct ol_tx_sg_desc_t *
ol_tx_sg_desc_alloc(struct ol_txrx_pdev_t *pdev)
{
    struct ol_tx_sg_desc_t *tx_sg_desc = NULL;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    adf_os_spin_lock_bh(&pdev->tx_sg_mutex);
    if (adf_os_likely(pdev->tx_sg_desc.freelist)) {
        tx_sg_desc = &pdev->tx_sg_desc.freelist->tx_sg_desc;
        pdev->tx_sg_desc.freelist = pdev->tx_sg_desc.freelist->next;
        stats->tx.sg.sg_desc_cnt++;
    }
    adf_os_spin_unlock_bh(&pdev->tx_sg_mutex);

    return tx_sg_desc;
}
#ifdef QCA_PARTNER_PLATFORM
void
ol_tx_sg_desc_free(struct ol_txrx_pdev_t *pdev,
                    struct ol_tx_sg_desc_t *tx_sg_desc)
{
    __ol_tx_sg_desc_free(pdev, tx_sg_desc);
}
#endif

void
ol_tx_print_sg_stats(
    ol_txrx_vdev_handle vdev)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    adf_os_print("++++++++++ SG STATISTICS +++++++++++\n");
    adf_os_print("sg TX Pkts       : %u\n", stats->tx.sg.sg_pkts.pkts);
    adf_os_print("sg TX Bytes      : %u\n", stats->tx.sg.sg_pkts.bytes);
    adf_os_print("Non-sg TX Pkts   : %u\n", stats->tx.sg.non_sg_pkts.pkts);
    adf_os_print("Non-sg TX Bytes  : %u\n", stats->tx.sg.non_sg_pkts.bytes);
    adf_os_print("sg Dropped Pkts  : %u\n", stats->tx.sg.sg_dropped.pkts);
    adf_os_print("sg Dropped Bytes : %u\n", stats->tx.sg.sg_dropped.bytes);
    adf_os_print("sg Desc Total %d In Use : %d\n", pdev->tx_sg_desc.pool_size, \
                                             stats->tx.sg.sg_desc_cnt);
}

void
ol_tx_rst_sg_stats(ol_txrx_vdev_handle vdev)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    adf_os_print(".....Resetting sg Stats \n");
    /* Tx */
    stats->tx.sg.sg_pkts.pkts = 0;
    stats->tx.sg.sg_pkts.bytes = 0;
    stats->tx.sg.non_sg_pkts.pkts = 0;
    stats->tx.sg.non_sg_pkts.bytes = 0;
    stats->tx.sg.sg_dropped.pkts = 0;
    stats->tx.sg.sg_dropped.bytes = 0;

    printk("sg_stats %d %d %d %d \n",stats->tx.sg.sg_pkts.pkts,stats->tx.sg.sg_pkts.bytes,stats->tx.sg.non_sg_pkts.pkts,stats->tx.sg.non_sg_pkts.bytes);
}

void
ol_tx_sg_desc_prepare(
    struct ol_txrx_pdev_t *pdev,
    struct ol_tx_desc_t *tx_desc,
    struct ol_tx_sg_desc_t *sw_sg_desc)
{

#if SG_DBG
    ol_tx_sg_desc_display(sw_tso_desc);
#endif

    ol_tx_sg_desc_free(pdev, sw_sg_desc);

#if SG_DBG
    ol_tx_msdu_desc_display(msdu_link_ext_p);
#endif

}

inline int
ol_tx_sg_process_skb(ol_txrx_vdev_handle vdev,adf_nbuf_t msdu)
{
    unsigned int cur_frag, nr_frags;
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct skb_shared_info *info = skb_shinfo(msdu);
    struct ol_tx_sg_desc_t * sw_sg_desc;
    int ret = 0;

    TXRX_STATS_MSDU_INCR(vdev->pdev, tx.sg.sg_pkts, msdu);
    /* Allocate SW TSO Descriptor for storing parsed info. */
    sw_sg_desc = ol_tx_sg_desc_alloc(pdev);
    if (adf_os_unlikely(!sw_sg_desc)) {
        adf_os_print("HOST_SG:Dropping Pkt, SW SG Descriptor allocation failed \n");
	    adf_nbuf_free(msdu);
        return -ENOMEM;
    }

    if(A_STATUS_FAILED == adf_nbuf_map_nbytes_single(pdev->osdev, msdu,
                                                     ADF_OS_DMA_TO_DEVICE,
                                                     adf_nbuf_headlen(msdu))) {
        adf_os_print("dma map error\n");
	ol_tx_sg_desc_free(pdev, sw_sg_desc);
	adf_nbuf_free(msdu);
        return -EIO;
    }

    sw_sg_desc->frag_paddr_lo[0] = adf_nbuf_get_frag_paddr_lo(msdu, 0);
    sw_sg_desc->frag_paddr_hi[0] = 0x0;
    sw_sg_desc->frag_len[0] = adf_nbuf_headlen(msdu);

    nr_frags = adf_nbuf_get_nr_frags(msdu);
    for (cur_frag = 0; cur_frag < info->nr_frags; cur_frag++) {

	if (A_STATUS_FAILED == adf_nbuf_frag_map(pdev->osdev,
			                         msdu,
			                         0,
			                         ADF_OS_DMA_TO_DEVICE,
			                         cur_frag)) {
	    adf_os_print("frag dma map error\n");
        ol_tx_sg_desc_free(pdev, (struct ol_tx_sg_desc_t *)msdu);
	    adf_nbuf_free(msdu);
            return -EIO;
    }
        sw_sg_desc->frag_paddr_lo[cur_frag + 1] = adf_nbuf_get_frag_paddr_0(msdu);
        sw_sg_desc->frag_paddr_hi[cur_frag + 1] = 0x0;
        sw_sg_desc->frag_len[cur_frag + 1] = adf_nbuf_get_frag_size(msdu, cur_frag);
    }

    sw_sg_desc->frag_cnt = cur_frag + 1;
    sw_sg_desc->total_len = adf_nbuf_len(msdu);

#if SG_DBG
    ol_tx_sg_desc_display(sw_sg_desc);
#endif
    adf_nbuf_set_fctx_type(msdu, (u_int32_t)sw_sg_desc, CB_FTYPE_SG);
    ret = OL_TX_LL_FORWARD_PACKET(vdev, msdu, 1);
#if !PEER_FLOW_CONTROL
    if (adf_os_unlikely(ret)) {
        adf_nbuf_free(msdu);
        return -EIO;
    }
#endif
    return ret;
}

