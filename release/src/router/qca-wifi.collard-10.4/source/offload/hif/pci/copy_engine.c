//------------------------------------------------------------------------------
// Copyright (c) 2011 Atheros Communications Inc.
// All rights reserved.
//
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <osdep.h>
#include "a_types.h"
#include <athdefs.h>
#include "a_osapi.h"
#include "hif_msg_based.h"
#include "ath_pci.h"
#include "copy_engine_api.h"
#include "copy_engine_internal.h"
#include "ol_ath.h"
#include "adf_os_lock.h"
#include "hif_pci.h"

#if QCA_OL_11AC_FAST_PATH
#include <htt_types.h> /* struct htt_pdev_t */
#include <htc.h>
#include <htc_packet.h>
#include <hif.h>
#endif /* QCA_OL_11AC_FAST_PATH */

#include "target_reg_table.h"

#if QCA_PARTNER_DIRECTLINK_TX
#define QCA_PARTNER_DIRECTLINK_COPY_ENGINE 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_COPY_ENGINE
#endif /* QCA_PARTNER_DIRECTLINK_TX */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif

/*
 * Support for Copy Engine hardware, which is mainly used for
 * communication between Host and Target over a PCIe interconnect.
 */

/*
 * A single CopyEngine (CE) comprises two "rings":
 *   a source ring
 *   a destination ring
 *
 * Each ring consists of a number of descriptors which specify
 * an address, length, and meta-data.
 *
 * Typically, one side of the PCIe interconnect (Host or Target)
 * controls one ring and the other side controls the other ring.
 * The source side chooses when to initiate a transfer and it
 * chooses what to send (buffer address, length). The destination
 * side keeps a supply of "anonymous receive buffers" available and
 * it handles incoming data as it arrives (when the destination
 * recieves an interrupt).
 *
 * The sender may send a simple buffer (address/length) or it may
 * send a small list of buffers.  When a small list is sent, hardware
 * "gathers" these and they end up in a single destination buffer
 * with a single interrupt.
 *
 * There are several "contexts" managed by this layer -- more, it
 * may seem -- than should be needed. These are provided mainly for
 * maximum flexibility and especially to facilitate a simpler HIF
 * implementation. There are per-CopyEngine recv, send, and watermark
 * contexts. These are supplied by the caller when a recv, send,
 * or watermark handler is established and they are echoed back to
 * the caller when the respective callbacks are invoked. There is
 * also a per-transfer context supplied by the caller when a buffer
 * (or sendlist) is sent and when a buffer is enqueued for recv.
 * These per-transfer contexts are echoed back to the caller when
 * the buffer is sent/received.
 */

/*
 * Guts of CE_send, used by both CE_send and CE_sendlist_send.
 * The caller takes responsibility for any needed locking.
 */
#define CDC_WAR_MAGIC_STR   0xceef0000
#define CDC_WAR_DATA_CE     4
extern unsigned int war1;
extern unsigned int war1_allow_sleep;
void WAR_CE_SRC_RING_WRITE_IDX_SET(
        struct ath_hif_pci_softc *sc,
        A_target_id_t targid,
        u_int32_t ctrl_addr,
        unsigned int write_index)
{
    if (war1) {
        A_target_id_t indicator_addr;

        indicator_addr = TARGID_TO_PCI_ADDR(targid) + ctrl_addr + DST_WATERMARK_ADDRESS;
        if (!war1_allow_sleep && ctrl_addr == CE_BASE_ADDRESS(CDC_WAR_DATA_CE)) {
            A_PCI_WRITE32(indicator_addr, (CDC_WAR_MAGIC_STR | write_index));
        } else {
            unsigned long irq_flags;
            local_irq_save(irq_flags);
            A_PCI_WRITE32(indicator_addr, 1);
#ifndef __ubicom32__
            /*
             *              * PCIE write waits for ACK in IPQ8K, there is no need
             *                           * to read back value.
             *                                        */
            (void)A_PCI_READ32(indicator_addr);
            (void)A_PCI_READ32(indicator_addr); /* conservative */
#endif

            CE_SRC_RING_WRITE_IDX_SET(targid, ctrl_addr, write_index);

            A_PCI_WRITE32(indicator_addr, 0);
            local_irq_restore(irq_flags);
        }
    } else {
        CE_SRC_RING_WRITE_IDX_SET(targid, ctrl_addr, write_index);
    }
}

int
CE_completed_send_next_nolock(struct CE_state *CE_state,
                              void **per_CE_contextp,
                              void **per_transfer_contextp,
                              CE_addr_t *bufferp,
                              unsigned int *nbytesp,
                              unsigned int *transfer_idp);

void dump_ce_desc(struct CE_src_desc *desc)
{
    u_int32_t *buff = (u_int32_t *)desc;

    printk("Desc 0x%x 0x%x\n", buff[0], buff[1]);
}

int
CE_send_nolock(struct CE_handle *copyeng,
               void *per_transfer_context,
               CE_addr_t buffer,
               unsigned int nbytes,
               unsigned int transfer_id,
               unsigned int flags)
{
    int status;
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct CE_ring_state *src_ring = CE_state->src_ring;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);
    unsigned int nentries_mask = src_ring->nentries_mask;
    unsigned int sw_index = src_ring->sw_index;
    unsigned int write_index = src_ring->write_index;

	A_ASSERT(nbytes <= CE_state->src_sz_max); /* TBDXXX -- may remove before tapeout */

	A_TARGET_ACCESS_BEGIN(targid);
#if QCA_PARTNER_DIRECTLINK_TX
    if (adf_os_unlikely(sc->is_directlink) && (CE_state->id == CE_HTT_TX_CE)) {
        status = CE_send_nolock_partner(copyeng, per_transfer_context, buffer,
            nbytes, transfer_id, flags);
    } else
#endif /* QCA_PARTNER_DIRECTLINK_TX */

{
    if (unlikely(CE_RING_DELTA(nentries_mask, write_index, sw_index-1) <= 0)) {
        OL_ATH_CE_PKT_ERROR_COUNT_INCR(sc,CE_RING_DELTA_FAIL);
        status = A_ERROR;
    	A_TARGET_ACCESS_END(targid);
    	return status;
    }
    {
        struct CE_src_desc *src_ring_base = (struct CE_src_desc *)src_ring->base_addr_owner_space;
        struct CE_src_desc *shadow_base = (struct CE_src_desc *)src_ring->shadow_base;
        struct CE_src_desc *src_desc = CE_SRC_RING_TO_DESC(src_ring_base, write_index);
        struct CE_src_desc *shadow_src_desc = CE_SRC_RING_TO_DESC(shadow_base, write_index);

        /* Update source descriptor */
        shadow_src_desc->src_ptr   = buffer;
		if (sc->scn->is_ar900b) {
            shadow_src_desc->target_int_disable = 0;
            shadow_src_desc->host_int_disable = 0;
		}
        shadow_src_desc->meta_data = transfer_id;

        /*
         * Set the swap bit if:
         *   typical sends on this CE are swapped (host is big-endian) and
         *   this send doesn't disable the swapping (data is not bytestream)
         */
#if AH_NEED_TX_DATA_SWAP
        shadow_src_desc->byte_swap =
            (((CE_state->attr_flags & CE_ATTR_BYTE_SWAP_DATA) != 0) |
            ((flags & CE_SEND_FLAG_SWAP_DISABLE) == 1));
#else
        shadow_src_desc->byte_swap =
            (((CE_state->attr_flags & CE_ATTR_BYTE_SWAP_DATA) != 0) &
            ((flags & CE_SEND_FLAG_SWAP_DISABLE) == 0));
#endif
        shadow_src_desc->gather    = ((flags & CE_SEND_FLAG_GATHER) != 0);
        shadow_src_desc->nbytes    = nbytes;

        *src_desc = *shadow_src_desc;

        src_ring->per_transfer_context[write_index] = per_transfer_context;

        /* Update Source Ring Write Index */
        write_index = CE_RING_IDX_INCR(nentries_mask, write_index);

        /* WORKAROUND */
        if (!shadow_src_desc->gather) {
#if ATH_SUPPORT_CE_BARRIER
            adf_os_mb();
#endif
            WAR_CE_SRC_RING_WRITE_IDX_SET(sc, targid, ctrl_addr, write_index);
        }

        src_ring->write_index = write_index;
        status = A_OK;
    }
}

    A_TARGET_ACCESS_END(targid);

    return status;
}

int
CE_send(struct CE_handle *copyeng,
        void *per_transfer_context,
        CE_addr_t buffer,
        unsigned int nbytes,
        unsigned int transfer_id,
        unsigned int flags)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    int status;


    adf_os_spin_lock_bh(&sc->target_lock);
    status = CE_send_nolock(copyeng, per_transfer_context, buffer, nbytes, transfer_id, flags);
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}

A_COMPILE_TIME_ASSERT(sendlist_sz_ok,
        (sizeof(struct CE_sendlist) >= sizeof(struct CE_sendlist_s *)));

unsigned int
CE_sendlist_sizeof(void)
{
   return sizeof(struct CE_sendlist);
}

void
CE_sendlist_init(struct CE_sendlist *sendlist)
{
    struct CE_sendlist_s *sl = (struct CE_sendlist_s *)sendlist;
    sl->num_items=0;
}

void
CE_sendlist_buf_add(struct CE_sendlist *sendlist,
                    CE_addr_t buffer,
                    unsigned int nbytes,
                    u_int32_t flags)
{
    struct CE_sendlist_s *sl = (struct CE_sendlist_s *)sendlist;
    unsigned int num_items = sl->num_items;
    struct CE_sendlist_item *item;

    A_ASSERT(num_items < CE_SENDLIST_ITEMS_MAX);

    item = &sl->item[num_items];
    item->send_type = CE_SIMPLE_BUFFER_TYPE;
    item->data = buffer;
    item->u.nbytes = nbytes;
    item->flags = flags;
    sl->num_items = num_items+1;
}

int
CE_sendlist_send(struct CE_handle *copyeng,
                 void *per_transfer_context,
                 struct CE_sendlist *sendlist,
                 unsigned int transfer_id)
{
    int status = -ENOMEM;
    struct CE_sendlist_s *sl = (struct CE_sendlist_s *)sendlist;
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct CE_ring_state *src_ring = CE_state->src_ring;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    unsigned int nentries_mask = src_ring->nentries_mask;
    unsigned int num_items = sl->num_items;
    unsigned int sw_index ;
    unsigned int write_index ;

    A_ASSERT((num_items > 0) && (num_items < src_ring->nentries));

    adf_os_spin_lock_bh(&sc->target_lock);
    sw_index = src_ring->sw_index;
    write_index = src_ring->write_index;

#if QCA_PARTNER_DIRECTLINK_TX
    if (adf_os_unlikely(sc->is_directlink) && (CE_state->id == CE_HTT_TX_CE)) {
        nentries_mask = nentries_mask_partner();
        write_index = write_index_partner();
        sw_index = sw_index_partner();
    }
#endif /* QCA_PARTNER_DIRECTLINK_TX */

    if (CE_RING_DELTA(nentries_mask, write_index, sw_index-1) >= num_items) {
        struct CE_sendlist_item *item;
        int i;

        /* handle all but the last item uniformly */
        for (i = 0; i < num_items-1; i++) {
            item = &sl->item[i];
            /* TBDXXX: Support extensible sendlist_types? */
            A_ASSERT(item->send_type == CE_SIMPLE_BUFFER_TYPE);
            status = CE_send_nolock(copyeng, CE_SENDLIST_ITEM_CTXT,
                                    (CE_addr_t)item->data, item->u.nbytes,
                                    transfer_id,
                                    item->flags | CE_SEND_FLAG_GATHER);
            A_ASSERT(status == A_OK);
        }
        /* provide valid context pointer for final item */
        item = &sl->item[i];
        /* TBDXXX: Support extensible sendlist_types? */
        A_ASSERT(item->send_type == CE_SIMPLE_BUFFER_TYPE);
        status = CE_send_nolock(copyeng, per_transfer_context,
                                (CE_addr_t)item->data, item->u.nbytes,
                                transfer_id, item->flags);
        A_ASSERT(status == A_OK);
    } else {
        /*
         * Probably not worth the additional complexity to support
         * partial sends with continuation or notification.  We expect
         * to use large rings and small sendlists. If we can't handle
         * the entire request at once, punt it back to the caller.
         */
    }
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}

#if QCA_OL_11AC_FAST_PATH

#define HTT_HTC_DESC_DUMP_LEN 36
void
dump_bytes(uint32_t index, char *buf, int len, uint32_t paddr)
{
    int i;
    int pr_len = len >> 2; /* assumes multiple of 4 */
    uint32_t *word = (uint32_t *)buf;
    printk("----------------------------------------\n");
    printk("Dumping %d bytes of HTT HTC meta-data at index %d(0x%x)\n\n",
            len, index, paddr);

    if (!word) {
        printk("%s NULL htt_tx_desc : Nothing to print\n", __func__);
        return;
    }

    for (i = 0; i < pr_len; i++) {
        if (i && (i % 4) == 0) {
            printk("\n");
        }
        printk("0x%x ", word[i]);
    }
    printk("\n");
    printk("----------------------------------------\n");
}

/* Dump copy engine register space */
#include <ol_txrx_types.h>

#if CE_HW_IDX_DEBUG
/* This is debug API to get the current SW index and HW index for given CE
 */
void ce_debug_hw_sw_index(struct CE_handle *copyeng, int *hw_index, int *sw_index)
{
   struct CE_state *ce_state = (struct CE_state *)copyeng;
   struct CE_ring_state *src_ring = ce_state->src_ring;
   *hw_index = src_ring->hw_index;
   *sw_index = src_ring->sw_index;
   return;
}
#endif

void
ce_dbg_dump(void *pdev_hdl)
{
#define CE_DUMP_COUNT 64
    struct ol_txrx_pdev_t *pdev =
        (struct ol_txrx_pdev_t *)(pdev_hdl);

    struct CE_state *ce_state = (struct CE_state *)(pdev->ce_tx_hdl);
    struct CE_ring_state *src_ring = ce_state->src_ring;

    struct CE_src_desc *src_desc_base = (struct CE_src_desc *)src_ring->base_addr_owner_space;
    struct CE_src_desc *src_desc;
    /*void *htt_htc_desc;
    adf_nbuf_t msdu;*/
    struct ath_hif_pci_softc *sc = ce_state->sc;

    int i;
    uint32_t nentries_mask, curr, dump_start;

    adf_os_spin_lock_bh(&sc->target_lock);

    nentries_mask = src_ring->nentries_mask;

    curr = src_ring->write_index;

    printk("CE Registers...\n");
    if (sc != NULL && sc->mem != NULL) {
        A_UINT32 ce_reg_start_addr;
        A_UINT32 ce_reg_offset = 0;
        A_UINT32 ce_reg_val = 0, pipe_num;
        for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++){
           ce_reg_start_addr = CE_BASE_ADDRESS(pipe_num);
           ce_reg_offset = 0;
           ce_reg_val = 0;

           printk("CE%d=>\n", pipe_num );

           ce_reg_val = A_PCI_READ32(sc->mem + (ce_reg_start_addr + SR_WR_INDEX_ADDRESS ));
           printk("ADDR:[0x%08X], SR_WR_INDEX:%d\n", (ce_reg_start_addr + SR_WR_INDEX_ADDRESS ),ce_reg_val );

           ce_reg_val = A_PCI_READ32(sc->mem + (ce_reg_start_addr + CURRENT_SRRI_ADDRESS ));
           printk("ADDR:[0x%08X], CURRENT_SRRI:%d\n", (ce_reg_start_addr + CURRENT_SRRI_ADDRESS ),ce_reg_val );

           ce_reg_val = A_PCI_READ32(sc->mem + (ce_reg_start_addr + DST_WR_INDEX_ADDRESS ));
           printk("ADDR:[0x%08X], DST_WR_INDEX:%d\n", (ce_reg_start_addr + DST_WR_INDEX_ADDRESS ),ce_reg_val );

           ce_reg_val = A_PCI_READ32(sc->mem + (ce_reg_start_addr + CURRENT_DRRI_ADDRESS ));
           printk("ADDR:[0x%08X], CURRENT_DRRI:%d\n", (ce_reg_start_addr + CURRENT_DRRI_ADDRESS ),ce_reg_val );

           printk("---\n");
        }
    }

    /* Following assumes power of 2 */
    dump_start = (curr - CE_DUMP_COUNT) & nentries_mask;

    printk("+++++++++++++ Dumping %d entries for CE 4 ++++++++++++++++++++++\n", CE_DUMP_COUNT);
    printk("Write Index %d SW Index %d HW Index %d curr %d dump_start %d\n\n",
            src_ring->write_index, src_ring->sw_index, src_ring->hw_index, curr, dump_start);
    printk("DMA Addr: Nbytes: Meta Data: Byte Swap: Gather:\n");

    for (i = dump_start; ; (i = (i + 1) & nentries_mask)) {
        src_desc = CE_SRC_RING_TO_DESC(src_desc_base, i);
        printk("[%2d] -> 0x%x: %d: %d: %d: %d\n",
            i, src_desc->src_ptr, src_desc->nbytes, src_desc->meta_data,
                src_desc->byte_swap, src_desc->gather);
    /*
     * Commenting out dumping meta data of htt_htc desc. It is mostly null
     * and leads to crash if it points to invalid address.
     */
#if 0
        /* Now dump the meta_data */
        if (src_ring->per_transfer_context[i] != CE_SENDLIST_ITEM_CTXT) {
            msdu = src_ring->per_transfer_context[i];
            if (msdu) {
                htt_htc_desc = adf_nbuf_get_frag_vaddr_always(msdu);
                if (htt_htc_desc) {
                    dump_bytes(i, (char *)(htt_htc_desc), HTT_HTC_DESC_DUMP_LEN,
                        msdu ? adf_nbuf_get_frag_paddr_0(msdu) : 0);
                }
            }
        }
#endif
        if (i == curr)
            break;
    }
    printk("+++++++++++++ Dumped entries for CE 4 ++++++++++++++++++++++\n");
    adf_os_spin_unlock_bh(&sc->target_lock);
}

void
ol_tx_stats_inc_ring_error(ol_txrx_pdev_handle pdev,
                             uint32_t num_ring_error);
/*
 * CE layer Tx buffer posting function
 * Assumption : Called with an array of MSDU's
 *
 * Function:
 * For each msdu in the array
 * 1. Check no. of available entries
 * 2. Create src ring entries (allocated in consistent memory
 * 3. Write index to h/w
 * Returns:
 *  No. of packets that could be sent
 */
int
CE_send_fast(struct CE_handle *ce_tx_hdl,
             adf_nbuf_t *nbuf_arr,
             uint32_t num_msdus,
             uint32_t transfer_id)
{
    struct CE_state *ce_state = (struct CE_state *)ce_tx_hdl;
    struct ath_hif_pci_softc *sc = ce_state->sc;
    struct CE_ring_state *src_ring = ce_state->src_ring;
    u_int32_t ctrl_addr = ce_state->ctrl_addr;
    A_target_id_t targid = TARGID(sc);

    uint32_t nentries_mask = src_ring->nentries_mask;
    uint32_t sw_index, write_index, frag_len;

    struct CE_src_desc *src_desc_base = (struct CE_src_desc *)src_ring->base_addr_owner_space;
    struct CE_src_desc *src_desc;

    adf_nbuf_t msdu;
    int i;

    /*
     * This lock could be more fine-grained, one per CE,
     * TODO : Add this lock now.
     * That is the next step of optimization.
     */
    CE_HTT_TX_LOCK(&sc->target_lock);
    sw_index = src_ring->sw_index;
    write_index = src_ring->write_index;

    for (i = 0; i < num_msdus; i++) {
        /*
         * Each msdu needs 2 elements of the ring
         * Check for space
         * TODO: If the ring is deep enough, this check can be an assertion
         */
        if (adf_os_unlikely(CE_RING_DELTA(nentries_mask, write_index, sw_index-1) < 2)) {
            ol_tx_stats_inc_ring_error(sc->scn->pdev_txrx_handle, 1);
            break;
        }

        src_desc = CE_SRC_RING_TO_DESC(src_desc_base, write_index);

        msdu = nbuf_arr[i];
        /*
         * First fill out the ring descriptor for the HTC HTT frame header
         * These are uncached writes. Should we use a local structure instead?
         */
        /* HTT/HTC header can be passed as a argument */
        src_desc->src_ptr   = adf_nbuf_get_frag_paddr_lo(msdu, 0);
        src_desc->meta_data = transfer_id; /* Could be prefilled for HTT CE */
        src_desc->nbytes    = adf_nbuf_get_frag_len(msdu, 0);

        if (adf_os_unlikely(src_desc->nbytes > (HTC_HEADER_LEN + HTT_TX_DESC_LEN))) {
            printk("%s %d CE Desc 0 download_len %d max expected %d frags %d\n", __func__, __LINE__,
                            src_desc->nbytes, (HTC_HEADER_LEN + HTT_TX_DESC_LEN),
                            adf_nbuf_get_num_frags(msdu));
            adf_os_assert_always(0);
        }

        /* HTC HTT header is a word stream, so byte swap if CE byte swap enabled */
#if AH_NEED_TX_DATA_SWAP
        src_desc->byte_swap = 0;
#else
        src_desc->byte_swap = ((ce_state->attr_flags & CE_ATTR_BYTE_SWAP_DATA) != 0);
#endif
        src_desc->gather    = 1; /* For the first one, it still does not need to write */

        /* By default we could initialize the transfer context to this value */
        src_ring->per_transfer_context[write_index] = CE_SENDLIST_ITEM_CTXT;

        write_index = CE_RING_IDX_INCR(nentries_mask, write_index);

        /* TODO:  This needs to be a loop to cover a real SG list from OS */

        src_desc = CE_SRC_RING_TO_DESC(src_desc_base, write_index);
        /* Now fill out the ring descriptor for the actual data packet */
        src_desc->src_ptr   =  adf_nbuf_get_frag_paddr_lo(msdu, 1);
        src_desc->meta_data = transfer_id; /* Could be prefilled for HTT CE */

        frag_len = adf_nbuf_get_frag_len(msdu, 1); /* get actual packet length */

        /* Extra check, probably not needed */
        src_desc->nbytes = frag_len > ce_state->download_len ?
                                ce_state->download_len : frag_len;

        if (adf_os_unlikely(src_desc->nbytes > ce_state->download_len)) {
            printk("%s %d CE Desc 1 download_len %d max expected %d frags %d\n", __func__, __LINE__,
                            src_desc->nbytes, ce_state->download_len,
                            adf_nbuf_get_num_frags(msdu));
            adf_os_assert_always(0);
        }
        /*  Data packet is a byte stream, so disable byte swap */
#if AH_NEED_TX_DATA_SWAP
        src_desc->byte_swap = 1;
#else
        src_desc->byte_swap = 0;
#endif
        src_desc->gather    = 0; /* For the last one, gather is not set */

		if (sc->scn->is_ar900b) {
        	src_desc->target_int_disable = 0;
        	src_desc->host_int_disable = 0;
		}
        src_ring->per_transfer_context[write_index] = msdu;

        write_index = CE_RING_IDX_INCR(nentries_mask, write_index);
    }

    /* Write the final index to h/w one-shot */
    if (i) {
        src_ring->write_index = write_index;
#if ATH_SUPPORT_CE_BARRIER
        adf_os_mb();
#endif
        /* Don't call WAR_XXX from here
         * Just call XXX instead, that has the reqd. intel
         */
        WAR_CE_SRC_RING_WRITE_IDX_SET(sc, targid, ctrl_addr, write_index);
    }
    CE_HTT_TX_UNLOCK(&sc->target_lock);
    /*
     * If all packets in the array are transmitted,
     * i = num_msdus
     * Temporarily add an ASSERT
     */
    ASSERT (i == num_msdus);
    return i;
}
#endif /* QCA_OL_11AC_FAST_PATH */

#if QCA_OL_TX_CACHEDHDR
adf_nbuf_t
CE_send_list(struct CE_handle *ce_tx_hdl,  adf_nbuf_t msdu,    uint32_t transfer_id, u_int32_t len, uint32_t sendhead)
{
    struct CE_state *ce_state = (struct CE_state *)ce_tx_hdl;
    struct ath_hif_pci_softc *sc = ce_state->sc;
    struct CE_ring_state *src_ring = ce_state->src_ring;
    u_int32_t ctrl_addr = ce_state->ctrl_addr;
    A_target_id_t targid = TARGID(sc);

    uint32_t nentries_mask = src_ring->nentries_mask;
    uint32_t sw_index, write_index ;

    struct CE_src_desc *src_desc_base = (struct CE_src_desc *)src_ring->base_addr_owner_space;
    uint32_t *src_desc;

    struct CE_src_desc lsrc_desc = {0};
    int deltacount =0;
    adf_nbuf_t freelist =NULL, hfreelist =NULL,tempnext;

    sw_index = src_ring->sw_index;
    write_index = src_ring->write_index;

    deltacount = CE_RING_DELTA(nentries_mask, write_index, sw_index-1);

    while (msdu ){
        tempnext = adf_nbuf_next(msdu);

        if (deltacount   < 2) {
            if(sendhead){
                return msdu;
            }

            /* adf_os_print("Out of descriptor \n"); */
            if (sc->scn->pdev_txrx_handle) {
                ol_tx_stats_inc_ring_error(sc->scn->pdev_txrx_handle, 1);
            }
            src_ring->write_index = write_index;
            WAR_CE_SRC_RING_WRITE_IDX_SET(sc, targid, ctrl_addr, write_index);

            sw_index = src_ring->sw_index;
            write_index = src_ring->write_index;

            deltacount = CE_RING_DELTA(nentries_mask, write_index, sw_index-1);
            tempnext = adf_nbuf_next(msdu);
            if(freelist == NULL){
                freelist = msdu;
                hfreelist =msdu;
            }else{
                adf_nbuf_set_next(freelist, msdu);
                freelist =msdu;
            }
            adf_nbuf_set_next(msdu, NULL);
            msdu = tempnext;
            continue;
        }

        src_desc = (uint32_t *)CE_SRC_RING_TO_DESC(src_desc_base, write_index);

        src_desc[0]   = adf_nbuf_get_frag_paddr_lo(msdu, 0);


        lsrc_desc.meta_data = transfer_id;
        if(len  > msdu->len){
            len =  msdu->len;
        }
        lsrc_desc.nbytes = len;
        /*  Data packet is a byte stream, so disable byte swap */
#if AH_NEED_TX_DATA_SWAP
        lsrc_desc.byte_swap = 1;
#else
        lsrc_desc.byte_swap = 0;
#endif
        lsrc_desc.gather    = 0; /* For the last one, gather is not set */

        src_desc[1] = ((uint32_t *)&lsrc_desc)[1];


        src_ring->per_transfer_context[write_index] = msdu;
        write_index = CE_RING_IDX_INCR(nentries_mask, write_index);

        if(sendhead)
            break;
        adf_nbuf_set_next(msdu, NULL);
        msdu = tempnext;

    }


    src_ring->write_index = write_index;
    WAR_CE_SRC_RING_WRITE_IDX_SET(sc, targid, ctrl_addr, write_index);

    return hfreelist;
}

void
CE_update_tx_ring(struct CE_handle *ce_tx_hdl, uint32_t num_htt_cmpls)
{
    struct CE_state *ce_state = (struct CE_state *)ce_tx_hdl;
    struct CE_ring_state *src_ring = ce_state->src_ring;
    uint32_t nentries_mask = src_ring->nentries_mask;
    /*
     * Advance the s/w index:
     * This effectively simulates completing the CE ring descriptors
     */
    src_ring->sw_index =
        CE_RING_IDX_ADD(nentries_mask, src_ring->sw_index, num_htt_cmpls);
}

int
CE_send_single(struct CE_handle *ce_tx_hdl,  adf_nbuf_t msdu,    uint32_t transfer_id, u_int32_t len)
{
    struct CE_state *ce_state = (struct CE_state *)ce_tx_hdl;
    struct ath_hif_pci_softc *sc = ce_state->sc;
    struct CE_ring_state *src_ring = ce_state->src_ring;
    u_int32_t ctrl_addr = ce_state->ctrl_addr;
    A_target_id_t targid = TARGID(sc);

    uint32_t nentries_mask = src_ring->nentries_mask;
    uint32_t sw_index, write_index ;

    struct CE_src_desc *src_desc_base = (struct CE_src_desc *)src_ring->base_addr_owner_space;
    uint32_t *src_desc;

    struct CE_src_desc lsrc_desc = {0};


    CE_HTT_TX_LOCK(&sc->target_lock);

#if QCA_PARTNER_DIRECTLINK_TX
    if (adf_os_unlikely(sc->is_directlink) && (ce_state->id == CE_HTT_TX_CE)) {
        CE_send_single_partner(ce_tx_hdl, msdu, transfer_id, len);
    } else
#endif /* QCA_PARTNER_DIRECTLINK_TX */

{
    sw_index = src_ring->sw_index;
    write_index = src_ring->write_index;

    if (adf_os_unlikely(CE_RING_DELTA(nentries_mask, write_index, sw_index-1) < 1)) {
        if (sc->scn->pdev_txrx_handle) {
            ol_tx_stats_inc_ring_error(sc->scn->pdev_txrx_handle, 1);
        }
        CE_HTT_TX_UNLOCK(&sc->target_lock);
        /* adf_os_print("ce send fail %d %d %d \n",nentries_mask,write_index,sw_index); */
        return 1;
    }

    src_desc = (uint32_t *)CE_SRC_RING_TO_DESC(src_desc_base, write_index);

    src_desc[0]   = adf_nbuf_get_frag_paddr_lo(msdu, 0);


    lsrc_desc.meta_data = transfer_id;
    lsrc_desc.nbytes = len;
    /*  Data packet is a byte stream, so disable byte swap */
#if AH_NEED_TX_DATA_SWAP
    lsrc_desc.byte_swap = 1;
#else
    lsrc_desc.byte_swap = 0;
#endif
    lsrc_desc.gather    = 0; /* For the last one, gather is not set */

    src_desc[1] = ((uint32_t *)&lsrc_desc)[1];


    src_ring->per_transfer_context[write_index] = msdu;
    write_index = CE_RING_IDX_INCR(nentries_mask, write_index);

    src_ring->write_index = write_index;
    WAR_CE_SRC_RING_WRITE_IDX_SET(sc, targid, ctrl_addr, write_index);
}

    CE_HTT_TX_UNLOCK(&sc->target_lock);

    return 0;
}
#endif /*QCA_OL_TX_CACHEDHDR*/

int
CE_recv_buf_enqueue(struct CE_handle *copyeng,
                    void *per_recv_context,
                    CE_addr_t buffer)
{
    int status;
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct CE_ring_state *dest_ring = CE_state->dest_ring;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);
    unsigned int nentries_mask = dest_ring->nentries_mask;
    unsigned int write_index ;
    unsigned int sw_index;

#if QCA_OL_11AC_FAST_PATH
    unsigned int old_write_index;
#endif /* QCA_OL_11AC_FAST_PATH */

    adf_os_spin_lock_bh(&sc->target_lock);
    write_index = dest_ring->write_index;
    sw_index = dest_ring->sw_index;
#if QCA_OL_11AC_FAST_PATH
    old_write_index = write_index;
#endif  /* QCA_OL_11AC_FAST_PATH */

    A_TARGET_ACCESS_BEGIN(targid);
    if (CE_RING_DELTA(nentries_mask, write_index, sw_index-1) > 0) {
        struct CE_dest_desc *dest_ring_base = (struct CE_dest_desc *)dest_ring->base_addr_owner_space;
        struct CE_dest_desc *dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, write_index);

        /* Update destination descriptor */
        dest_desc->dest_ptr = buffer;
        dest_desc->info.nbytes = 0; /* NB: Enable CE_completed_recv_next_nolock to
								protect against race between DRRI update and
								desc update */

        dest_ring->per_transfer_context[write_index] = per_recv_context;

        /* Update Destination Ring Write Index */
        write_index = CE_RING_IDX_INCR(nentries_mask, write_index);
        CE_DEST_RING_WRITE_IDX_SET(targid, ctrl_addr, write_index);
        dest_ring->write_index = write_index;
        status = A_OK;
#if QCA_OL_11AC_FAST_PATH
        if (CE_state->id != CE_HTT_MSG_CE)
#endif
        {
            sc->scn->pkt_stats.sw_index[CE_state->id] = dest_ring->sw_index;
            sc->scn->pkt_stats.write_index[CE_state->id] = dest_ring->write_index;
        }
    } else {
        status = A_ERROR;
    }
#if QCA_OL_11AC_FAST_PATH
    if (adf_os_unlikely(!sc->hif_started) && (CE_state->id == CE_HTT_MSG_CE)) {
        struct CE_dest_desc *dest_ring_base = (struct CE_dest_desc *)dest_ring->base_addr_owner_space;
        struct CE_dest_desc *dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, (write_index - 1));

        /*
         * NOTE: This check holds good only if CE_attr->dest_nentries has been
         * set to a power of 2 start with, else this will fail. However the normal
         * case is to set attr->dest_nentries to a power of 2 always.
         */
        if (old_write_index == (dest_ring->nentries - 1)) {
            adf_os_print(KERN_INFO"%s %d Populate last entry %d for CE %d\n", __func__, __LINE__,
                dest_ring->nentries, CE_state->id);

            dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, old_write_index);
            dest_desc->dest_ptr = buffer;
            dest_desc->info.nbytes = 0;
            dest_ring->per_transfer_context[old_write_index] = per_recv_context;

            adf_os_print(KERN_INFO"%s %d CE 5 wi %d dest_ptr 0x%x nbytes %d recv_ctxt 0x%p\n",
                __func__, __LINE__, old_write_index, dest_desc->dest_ptr,
                dest_desc->info.nbytes, dest_ring->per_transfer_context[old_write_index]);
            status = A_OK;
        }
    }
#endif  /* QCA_OL_11AC_FAST_PATH */
    A_TARGET_ACCESS_END(targid);
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}

void
CE_send_watermarks_set(struct CE_handle *copyeng,
                       unsigned int low_alert_nentries,
                       unsigned int high_alert_nentries)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);

    adf_os_spin_lock(&sc->target_lock);
    CE_SRC_RING_LOWMARK_SET(targid, ctrl_addr, low_alert_nentries);
    CE_SRC_RING_HIGHMARK_SET(targid, ctrl_addr, high_alert_nentries);
    adf_os_spin_unlock(&sc->target_lock);
}

void
CE_recv_watermarks_set(struct CE_handle *copyeng,
                       unsigned int low_alert_nentries,
                       unsigned int high_alert_nentries)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);

    adf_os_spin_lock(&sc->target_lock);
    CE_DEST_RING_LOWMARK_SET(targid, ctrl_addr, low_alert_nentries);
    CE_DEST_RING_HIGHMARK_SET(targid, ctrl_addr, high_alert_nentries);
    adf_os_spin_unlock(&sc->target_lock);
}

unsigned int
CE_send_entries_avail(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct CE_ring_state *src_ring = CE_state->src_ring;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    unsigned int nentries_mask = src_ring->nentries_mask;
    unsigned int sw_index;
    unsigned int write_index;

    adf_os_spin_lock(&sc->target_lock);
    sw_index = src_ring->sw_index;
    write_index = src_ring->write_index;
    adf_os_spin_unlock(&sc->target_lock);

    return CE_RING_DELTA(nentries_mask, write_index, sw_index-1);
}

unsigned int
CE_recv_entries_avail(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct CE_ring_state *dest_ring = CE_state->dest_ring;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    unsigned int nentries_mask = dest_ring->nentries_mask;
    unsigned int sw_index;
    unsigned int write_index;

    adf_os_spin_lock(&sc->target_lock);
    sw_index = dest_ring->sw_index;
    write_index = dest_ring->write_index;
    adf_os_spin_unlock(&sc->target_lock);

    return CE_RING_DELTA(nentries_mask, write_index, sw_index-1);
}

/*
 * Guts of CE_send_entries_done.
 * The caller takes responsibility for any necessary locking.
 */
unsigned int
CE_send_entries_done_nolock(struct ath_hif_pci_softc *sc, struct CE_state *CE_state)
{
    struct CE_ring_state *src_ring = CE_state->src_ring;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    A_target_id_t targid = TARGID(sc);
    unsigned int nentries_mask = src_ring->nentries_mask;
    unsigned int sw_index;
    unsigned int read_index;

    sw_index = src_ring->sw_index;
    read_index = CE_SRC_RING_READ_IDX_GET(targid, ctrl_addr);

    return CE_RING_DELTA(nentries_mask, sw_index, read_index);
}

unsigned int
CE_send_entries_done(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    unsigned int nentries;

    adf_os_spin_lock(&sc->target_lock);
    nentries = CE_send_entries_done_nolock(sc, CE_state);
    adf_os_spin_unlock(&sc->target_lock);

    return nentries;
}

/*
 * Guts of CE_recv_entries_done.
 * The caller takes responsibility for any necessary locking.
 */
unsigned int
CE_recv_entries_done_nolock(struct ath_hif_pci_softc *sc, struct CE_state *CE_state)
{
    struct CE_ring_state *dest_ring = CE_state->dest_ring;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    A_target_id_t targid = TARGID(sc);
    unsigned int nentries_mask = dest_ring->nentries_mask;
    unsigned int sw_index;
    unsigned int read_index;

    sw_index = dest_ring->sw_index;
    read_index = CE_DEST_RING_READ_IDX_GET(targid, ctrl_addr);

    return CE_RING_DELTA(nentries_mask, sw_index, read_index);
}

unsigned int
CE_recv_entries_done(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    unsigned int nentries;

    adf_os_spin_lock(&sc->target_lock);
    nentries = CE_recv_entries_done_nolock(sc, CE_state);
    adf_os_spin_unlock(&sc->target_lock);

    return nentries;
}

/* Debug support */
void *ce_debug_cmplrn_context; /* completed recv next context */
void *ce_debug_cnclsn_context; /* cancel send next context */
void *ce_debug_rvkrn_context;  /* revoke receive next context */
void *ce_debug_cmplsn_context; /* completed send next context */


/*
 * Guts of CE_completed_recv_next.
 * The caller takes responsibility for any necessary locking.
 */
int
CE_completed_recv_next_nolock(struct CE_state *CE_state,
                              void **per_CE_contextp,
                              void **per_transfer_contextp,
                              CE_addr_t *bufferp,
                              unsigned int *nbytesp,
                              unsigned int *transfer_idp,
                              unsigned int *flagsp)
{
    int status;
    struct CE_ring_state *dest_ring = CE_state->dest_ring;
    unsigned int nentries_mask = dest_ring->nentries_mask;
    unsigned int sw_index = dest_ring->sw_index;

    struct CE_dest_desc *dest_ring_base = (struct CE_dest_desc *)dest_ring->base_addr_owner_space;
    struct CE_dest_desc *dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, sw_index);
    int nbytes;
    struct dest_desc_info dest_desc_info;

    /*
     * By copying the dest_desc_info element to local memory, we could
     * avoid extra memory read from non-cachable memory.
     */
    dest_desc_info = dest_desc->info;
    nbytes = dest_desc_info.nbytes;
    if (nbytes == 0) {
        /*
         * This closes a relatively unusual race where the Host
         * sees the updated DRRI before the update to the
         * corresponding descriptor has completed. We treat this
         * as a descriptor that is not yet done.
         */
        status = A_ERROR;
        goto done;
    }

    dest_desc->info.nbytes = 0;

    /* Return data from completed destination descriptor */
    *bufferp      = (CE_addr_t)(dest_desc->dest_ptr);
    *nbytesp      = nbytes;
    *transfer_idp = dest_desc_info.meta_data;
    *flagsp       = (dest_desc_info.byte_swap) ?  CE_RECV_FLAG_SWAPPED : 0;

    if (per_CE_contextp) {
        *per_CE_contextp = CE_state->recv_context;
    }

    ce_debug_cmplrn_context = dest_ring->per_transfer_context[sw_index];
    if (per_transfer_contextp) {
        *per_transfer_contextp = ce_debug_cmplrn_context;
    }
    dest_ring->per_transfer_context[sw_index] = 0; /* sanity */

    /* Update sw_index */
    sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
    dest_ring->sw_index = sw_index;
    status = A_OK;

done:
    return status;
}

int
CE_completed_recv_next(struct CE_handle *copyeng,
                       void **per_CE_contextp,
                       void **per_transfer_contextp,
                       CE_addr_t *bufferp,
                       unsigned int *nbytesp,
                       unsigned int *transfer_idp,
                       unsigned int *flagsp)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    int status;


    adf_os_spin_lock_bh(&sc->target_lock);
    status = CE_completed_recv_next_nolock(CE_state, per_CE_contextp, per_transfer_contextp,
                                               bufferp, nbytesp, transfer_idp, flagsp);
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}

/* NB: Modeled after CE_completed_recv_next_nolock */
A_STATUS
CE_revoke_recv_next(struct CE_handle *copyeng,
                    void **per_CE_contextp,
                    void **per_transfer_contextp,
                    CE_addr_t *bufferp)
{
    struct CE_state *CE_state;
    struct CE_ring_state *dest_ring;
    unsigned int nentries_mask;
    unsigned int sw_index;
    unsigned int write_index;
    A_STATUS status;
    struct ath_hif_pci_softc *sc;

    CE_state = (struct CE_state *)copyeng;
    dest_ring = CE_state->dest_ring;
    if (!dest_ring) {
        return A_ERROR;
    }

    sc = CE_state->sc;
    adf_os_spin_lock_bh(&sc->target_lock);
    nentries_mask = dest_ring->nentries_mask;
    sw_index = dest_ring->sw_index;
    write_index = dest_ring->write_index;
    if (write_index != sw_index) {
        struct CE_dest_desc *dest_ring_base = (struct CE_dest_desc *)dest_ring->base_addr_owner_space;
        struct CE_dest_desc *dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, sw_index);

        /* Return data from completed destination descriptor */
        *bufferp     = (CE_addr_t)(dest_desc->dest_ptr);

        if (per_CE_contextp) {
            *per_CE_contextp = CE_state->recv_context;
        }

        ce_debug_rvkrn_context = dest_ring->per_transfer_context[sw_index];
        if (per_transfer_contextp) {
            *per_transfer_contextp = ce_debug_rvkrn_context;
        }
        dest_ring->per_transfer_context[sw_index] = 0; /* sanity */

        /* Update sw_index */
        sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
        dest_ring->sw_index = sw_index;
        status = A_OK;
    } else {
        status = A_ERROR;
    }
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}

/*
 * Guts of CE_completed_send_next.
 * The caller takes responsibility for any necessary locking.
 */
int
CE_completed_send_next_nolock(struct CE_state *CE_state,
                              void **per_CE_contextp,
                              void **per_transfer_contextp,
                              CE_addr_t *bufferp,
                              unsigned int *nbytesp,
                              unsigned int *transfer_idp)
{
    int status = A_ERROR;
    struct CE_ring_state *src_ring = CE_state->src_ring;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);
    unsigned int nentries_mask = src_ring->nentries_mask;
    unsigned int sw_index = src_ring->sw_index;
    unsigned int read_index;
#if CE_HW_IDX_DEBUG
    unsigned int hw_index0;
#endif


    if (src_ring->hw_index == sw_index) {
        /*
         * The SW completion index has caught up with the cached
         * version of the HW completion index.
         * Update the cached HW completion index to see whether
         * the SW has really caught up to the HW, or if the cached
         * value of the HW index has become stale.
         */
#if CE_HW_IDX_DEBUG
        hw_index0 = src_ring->hw_index;
#endif
        A_TARGET_ACCESS_BEGIN(targid);
        src_ring->hw_index = CE_SRC_RING_READ_IDX_GET(targid, ctrl_addr);
        A_TARGET_ACCESS_END(targid);
#if CE_HW_IDX_DEBUG
        if (adf_os_unlikely((src_ring->hw_index < hw_index0) &&
                 (CE_RING_DELTA(nentries_mask, hw_index0, src_ring->hw_index) == src_ring->nentries))) {
            printk("[corruption in hw_index] old hw index is %d new hw index is %d \n", hw_index0, src_ring->hw_index);
        }
#endif
    }

#if QCA_PARTNER_DIRECTLINK_TX
    if (adf_os_unlikely(sc->is_directlink) && CE_state->id == CE_HTT_TX_CE) {
        status = CE_completed_send_next_nolock_partner(CE_state, per_CE_contextp,
            per_transfer_contextp, bufferp, nbytesp, transfer_idp, ce_debug_cmplsn_context);
        return status;
    } else
#endif /* QCA_PARTNER_DIRECTLINK_TX */

{
    read_index = src_ring->hw_index;

    if ((read_index != sw_index) && (read_index != 0xffffffff)) {
        struct CE_src_desc *shadow_base = (struct CE_src_desc *)src_ring->shadow_base;
        struct CE_src_desc *shadow_src_desc = CE_SRC_RING_TO_DESC(shadow_base, sw_index);

        /* Return data from completed source descriptor */
        *bufferp      = (CE_addr_t)(shadow_src_desc->src_ptr);
        *nbytesp      = shadow_src_desc->nbytes;
        *transfer_idp = shadow_src_desc->meta_data;

        if (per_CE_contextp) {
            *per_CE_contextp = CE_state->send_context;
        }

        ce_debug_cmplsn_context = src_ring->per_transfer_context[sw_index];
        if (per_transfer_contextp) {
            *per_transfer_contextp = ce_debug_cmplsn_context;
        }
        src_ring->per_transfer_context[sw_index] = 0; /* sanity */

        /* Update sw_index */
        sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
        src_ring->sw_index = sw_index;
        status = A_OK;
    }
}

    return status;
}

/* NB: Modeled after CE_completed_send_next */
A_STATUS
CE_cancel_send_next(struct CE_handle *copyeng,
                    void **per_CE_contextp,
                    void **per_transfer_contextp,
                    CE_addr_t *bufferp,
                    unsigned int *nbytesp,
                    unsigned int *transfer_idp)
{
    struct CE_state *CE_state;
    struct CE_ring_state *src_ring;
    unsigned int nentries_mask;
    unsigned int sw_index;
    unsigned int write_index;
    A_STATUS status;
    struct ath_hif_pci_softc *sc;

    CE_state = (struct CE_state *)copyeng;
    src_ring = CE_state->src_ring;
    if (!src_ring) {
        return A_ERROR;
    }

    sc = CE_state->sc;
    adf_os_spin_lock_bh(&sc->target_lock);
    nentries_mask = src_ring->nentries_mask;
    sw_index = src_ring->sw_index;
    write_index = src_ring->write_index;

    if (write_index != sw_index) {
        struct CE_src_desc *src_ring_base = (struct CE_src_desc *)src_ring->base_addr_owner_space;
        struct CE_src_desc *src_desc = CE_SRC_RING_TO_DESC(src_ring_base, sw_index);

        /* Return data from completed source descriptor */
        *bufferp      = (CE_addr_t)(src_desc->src_ptr);
        *nbytesp      = src_desc->nbytes;
        *transfer_idp = src_desc->meta_data;

        if (per_CE_contextp) {
            *per_CE_contextp = CE_state->send_context;
        }

        ce_debug_cnclsn_context = src_ring->per_transfer_context[sw_index];
        if (per_transfer_contextp) {
            *per_transfer_contextp = ce_debug_cnclsn_context;
        }
        src_ring->per_transfer_context[sw_index] = 0; /* sanity */

        /* Update sw_index */
        sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
        src_ring->sw_index = sw_index;
        status = A_OK;
    } else {
        status = A_ERROR;
    }
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}

/* Shift bits to convert IS_*_RING_*_WATERMARK_MASK to CE_WM_FLAG_*_* */
#define CE_WM_SHFT 1
#if 0
A_COMPILE_TIME_ASSERT(watermarks_ok,
                   (((HOST_IS_SRC_RING_HIGH_WATERMARK_MASK >> CE_WM_SHFT) == CE_WM_FLAG_SEND_HIGH) &&
                    ((HOST_IS_SRC_RING_LOW_WATERMARK_MASK >>  CE_WM_SHFT) == CE_WM_FLAG_SEND_LOW)  &&
                    ((HOST_IS_DST_RING_HIGH_WATERMARK_MASK >> CE_WM_SHFT) == CE_WM_FLAG_RECV_HIGH) &&
                    ((HOST_IS_DST_RING_LOW_WATERMARK_MASK >>  CE_WM_SHFT) == CE_WM_FLAG_RECV_LOW)));
#endif

int
CE_completed_send_next(struct CE_handle *copyeng,
                       void **per_CE_contextp,
                       void **per_transfer_contextp,
                       CE_addr_t *bufferp,
                       unsigned int *nbytesp,
                       unsigned int *transfer_idp)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    int status;


    adf_os_spin_lock_bh(&sc->target_lock);
    status = CE_completed_send_next_nolock(CE_state, per_CE_contextp, per_transfer_contextp,
                                               bufferp, nbytesp, transfer_idp);
    adf_os_spin_unlock_bh(&sc->target_lock);

    return status;
}


#if ATH_11AC_TXCOMPACT
/* CE engine descriptor reap
   Similar to CE_per_engine_service , Only difference is CE_per_engine_service
   does recieve and reaping of completed descriptor ,
   This function only handles reaping of Tx complete descriptor.
   The Function is called from threshold reap  poll routine HIFSendCompleteCheck
   So should not countain recieve functionality within it .
 */

void
CE_per_engine_servicereap(struct ath_hif_pci_softc *sc, unsigned int CE_id)
{
    struct CE_state *CE_state = sc->CE_id_to_state[CE_id];
    A_target_id_t targid = TARGID(sc);
    void *CE_context;
    void *transfer_context;
    CE_addr_t buf;
    unsigned int nbytes;
    unsigned int id;

    A_TARGET_ACCESS_BEGIN(targid);

    adf_os_spin_lock_bh(&sc->target_lock);


    if (CE_state->send_cb) {
       {
            /* Pop completed send buffers and call the registered send callback for each */
            while (CE_completed_send_next_nolock(CE_state, &CE_context, &transfer_context,
                        &buf, &nbytes, &id) == A_OK)
            {
#if QCA_OL_11AC_FAST_PATH
                adf_os_spin_unlock_bh(&sc->target_lock);
                CE_state->send_cb((struct CE_handle *)CE_state, CE_context, transfer_context, buf, nbytes, id);
                adf_os_spin_lock_bh(&sc->target_lock);
#else
                if(CE_id != CE_HTT_H2T_MSG){
                    adf_os_spin_unlock_bh(&sc->target_lock);
                    CE_state->send_cb((struct CE_handle *)CE_state, CE_context, transfer_context, buf, nbytes, id);
                    adf_os_spin_lock_bh(&sc->target_lock);
                }else{
                     struct HIF_CE_pipe_info *pipe_info = (struct HIF_CE_pipe_info *)CE_context;

                     adf_os_spin_lock(&pipe_info->completion_freeq_lock);
                     pipe_info->num_sends_allowed++;
                     adf_os_spin_unlock(&pipe_info->completion_freeq_lock);
                }
#endif
            }
        }
    }

    adf_os_spin_unlock_bh(&sc->target_lock);
    A_TARGET_ACCESS_END(targid);
}

#endif /*ATH_11AC_TXCOMPACT*/
/*
 * Guts of interrupt handler for per-engine interrupts on a particular CE.
 *
 * Invokes registered callbacks for recv_complete,
 * send_complete, and watermarks.
 */
void
CE_per_engine_service(struct ath_hif_pci_softc *sc, unsigned int CE_id)
{
    struct CE_state *CE_state = sc->CE_id_to_state[CE_id];
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    A_target_id_t targid = TARGID(sc);
    void *CE_context;
    void *transfer_context;
    CE_addr_t buf;
    unsigned int nbytes;
    unsigned int id;
    unsigned int flags;
    u_int32_t CE_int_status;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
     /*Tx CE and HTT_MSG_CE are handled in NSS offload module */
    if (sc->nss_wifi_ol_mode && ((CE_id == CE_HTT_MSG_CE)||(CE_id == CE_HTT_TX_CE))) {
        return;
    }
#endif

    A_TARGET_ACCESS_BEGIN(targid);

    adf_os_spin_lock(&sc->target_lock);

more_completions:
#if QCA_OL_11AC_FAST_PATH
    if (CE_state->recv_cb && (CE_id != CE_HTT_MSG_CE)) {
#else
    if (CE_state->recv_cb) {
#endif
#if ATH_RX_LOOPLIMIT_TIMER
        /* During looplimit timer active, disbale RX */
        if (sc->scn->rx_looplimit) {
            goto skip_rx;
        }
#endif
        /* Clear force_break flag and re-initialize receive_count to 0 */
        sc->receive_count = 0;

        /* Pop completed recv buffers and call the registered recv callback for each */
        while (CE_completed_recv_next_nolock(CE_state, &CE_context, &transfer_context,
                    &buf, &nbytes, &id, &flags) == A_OK)
        {
                adf_os_spin_unlock(&sc->target_lock);
                CE_state->recv_cb((struct CE_handle *)CE_state, CE_context, transfer_context,
                                    buf, nbytes, id, flags);

                /*
                 * EV #112693 - [Peregrine][ES1][WB342][Win8x86][Performance] BSoD_0x133 occurred in VHT80 UDP_DL
                 * Break out DPC by force if number of loops in HIF_PCI_CE_recv_data reaches MAX_NUM_OF_RECEIVES to avoid spending too long time in DPC for each interrupt handling.
                 * Schedule another DPC to avoid data loss if we had taken force-break action before
                 * Apply to Windows OS only currently, Linux/MAC os can expand to their platform if necessary
                 */

                /* Break the receive processes by force if force_break set up */
                if (adf_os_unlikely(sc->force_break))
                {
                    A_TARGET_ACCESS_END(targid);
                    return;
                }
                adf_os_spin_lock(&sc->target_lock);
        }
    }

    /*
     * Attention: We may experience potential infinite loop for below While Loop during Sending Stress test
     * Resolve the same way as Receive Case (Refer to EV #112693)
     */

    if (CE_state->send_cb) {
        /* Pop completed send buffers and call the registered send callback for each */

#if ATH_11AC_TXCOMPACT
        while (CE_completed_send_next_nolock(CE_state, &CE_context, &transfer_context,
                    &buf, &nbytes, &id) == A_OK){

            if(CE_id != CE_HTT_H2T_MSG){
                adf_os_spin_unlock(&sc->target_lock);
                CE_state->send_cb((struct CE_handle *)CE_state, CE_context, transfer_context, buf, nbytes, id);
                adf_os_spin_lock(&sc->target_lock);
            }else{
                struct HIF_CE_pipe_info *pipe_info = (struct HIF_CE_pipe_info *)CE_context;

                adf_os_spin_lock(&pipe_info->completion_freeq_lock);
                pipe_info->num_sends_allowed++;
                adf_os_spin_unlock(&pipe_info->completion_freeq_lock);
            }
        }
#else  /*ATH_11AC_TXCOMPACT*/
        while (CE_completed_send_next_nolock(CE_state, &CE_context, &transfer_context,
                    &buf, &nbytes, &id) == A_OK){
            adf_os_spin_unlock(&sc->target_lock);
            CE_state->send_cb((struct CE_handle *)CE_state, CE_context, transfer_context, buf, nbytes, id);
            adf_os_spin_lock(&sc->target_lock);
        }
#endif /*ATH_11AC_TXCOMPACT*/
    }

    /*
     * Clear the copy-complete interrupts that will be handled here.
     */
    CE_ENGINE_INT_STATUS_CLEAR(targid, ctrl_addr, HOST_IS_COPY_COMPLETE_MASK);

    if (CE_state->misc_cbs) {
more_watermarks:
        CE_int_status = CE_ENGINE_INT_STATUS_GET(targid, ctrl_addr);
        if (CE_int_status & CE_WATERMARK_MASK) {
            if (CE_state->watermark_cb) {

                adf_os_spin_unlock(&sc->target_lock);
                /* Convert HW IS bits to software flags */
                flags = (CE_int_status & CE_WATERMARK_MASK) >> CE_WM_SHFT;

                CE_state->watermark_cb((struct CE_handle *)CE_state, CE_state->wm_context, flags);
                adf_os_spin_lock(&sc->target_lock);
            }
        }

        /*
         * Clear the misc interrupts (watermark) that were handled above,
         * and that will be checked again below.
         * Clear and check for copy-complete interrupts again, just in case
         * more copy completions happened while the misc interrupts were being
         * handled.
         */
        CE_ENGINE_INT_STATUS_CLEAR(targid, ctrl_addr, CE_WATERMARK_MASK | HOST_IS_COPY_COMPLETE_MASK);

        /*
         * Now that per-engine interrupts are cleared, verify that
         * we didn't miss anything.  If we did, go back and handle it.
         * If there's nothing to do and interrupts are cleared, we're done.
         */
        if (CE_state->recv_cb && CE_recv_entries_done_nolock(sc, CE_state)) {
            goto more_completions;
        }

        if (CE_state->send_cb && CE_send_entries_done_nolock(sc, CE_state)) {
            goto more_completions;
        }

        if (CE_int_status & CE_WATERMARK_MASK) {
            if (CE_state->watermark_cb) {
                goto more_watermarks;
            }
        }
    } else {
        /*
         * Misc CE interrupts are not being handled, but still need
         * to be cleared.
         */
        CE_ENGINE_INT_STATUS_CLEAR(targid, ctrl_addr, CE_WATERMARK_MASK);
    }

#if ATH_RX_LOOPLIMIT_TIMER
skip_rx:
#endif /* ATH_RX_LOOPLIMIT_TIMER */

    adf_os_spin_unlock(&sc->target_lock);
    A_TARGET_ACCESS_END(targid);

#if ATH_RX_LOOPLIMIT_TIMER
    if (sc->scn->rx_looplimit_valid && !sc->scn->rx_looplimit) {
        sc->scn->rx_looplimit = true;
        sc->scn->scn_stats.rx_looplimit_start ++;
        adf_os_timer_start(&sc->scn->rx_looplimit_timer, sc->scn->rx_looplimit_timeout);
    }
#endif
}

/*
 * Handler for per-engine interrupts on ALL active CEs.
 * This is used in cases where the system is sharing a
 * single interrput for all CEs
 */

void
CE_per_engine_service_any(int irq, void *arg)
{
    struct ath_hif_pci_softc *sc = arg;
    A_target_id_t targid = TARGID(sc);
    int CE_id;
    A_UINT32 intr_summary;

    A_TARGET_ACCESS_BEGIN(targid);
    intr_summary = CE_INTERRUPT_SUMMARY(targid);

    for (CE_id=0; intr_summary && (CE_id < sc->ce_count); CE_id++) {
        if (intr_summary & (1<<CE_id)) {
            intr_summary &= ~(1<<CE_id);
        } else {
            continue; /* no intr pending on this CE */
        }

        CE_per_engine_service(sc, CE_id);
    }

    A_TARGET_ACCESS_END(targid);
}

#if QCA_OL_11AC_FAST_PATH

bool
CE_htt_ce_cmpl_done(struct CE_handle *ce_hdl)
{
    struct CE_state *ce_state = (struct CE_state *)ce_hdl;
    struct CE_ring_state *src_ring = ce_state->src_ring;
    struct ath_hif_pci_softc *sc = ce_state->sc;

    bool ret;

    adf_os_spin_lock_bh(&sc->target_lock);

    ret = (src_ring->sw_index == src_ring->write_index);

    adf_os_spin_unlock_bh(&sc->target_lock);

    return ret;
}

/*
 * API to reap off the HTT source ring when HTT completion happens:
 * 1) For data packets, on packet completion
 * 2) For other other HTT messages, through HTT t->h messages
 */
static void
CE_htt_ce_cmpl(struct CE_state *ce_state, uint32_t num_htt_cmpls)
{
    struct CE_ring_state *src_ring = ce_state->src_ring;
    uint32_t nentries_mask = src_ring->nentries_mask;
    struct ath_hif_pci_softc *sc = ce_state->sc;

    ASSERT (num_htt_cmpls);

    adf_os_spin_lock_bh(&sc->target_lock);

    /*
     * This locks the index manipulation of this CE with those done
     * in ce_send_fast(). Since this is only on a given CE, we use
     * a finer grained per CE lock.
     * src_ring->ce_ring_lock?
     */

    /*
     * Advance the s/w index:
     * This effectively simulates completing the CE ring descriptors
     */

    src_ring->sw_index =
        CE_RING_IDX_ADD(nentries_mask, src_ring->sw_index, num_htt_cmpls);
    adf_os_spin_unlock_bh(&sc->target_lock);
}



extern void
htt_t2h_msg_handler_fast(void *htt_pdev, adf_nbuf_t *nbuf_cmpl_arr,
                         uint32_t num_cmpls, uint32_t *num_tx_cmpls);
#define MSG_FLUSH_NUM 32
/*
 * CE handler routine to service HTT message CE (= 1)
 * Function:
 * 1) Go through the HTT CE ring, and find the completions
 * 2) For valid completions retrieve context (nbuf) for per_transfer_context[]
 * 3) Unmap buffer & accumulate in an array.
 * 4) Call HTT message handler when array is full or when exiting the handler
 */
static inline void
CE_per_engine_service_fast(struct ath_hif_pci_softc *sc, uint32_t ce_id)
{
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (sc->nss_wifi_ol_mode) {
        return;
    } else
#endif
    {
        struct CE_state *ce_state = sc->CE_id_to_state[ce_id];
#if !QCA_OL_TX_PDEV_LOCK
        struct CE_state *CE_tx_cmpl_state = sc->CE_id_to_state[CE_HTT_TX_CE];
#endif
        struct CE_ring_state *dest_ring = ce_state->dest_ring;
        struct CE_dest_desc *dest_ring_base = (struct CE_dest_desc *)dest_ring->base_addr_owner_space;

        uint32_t nentries_mask = dest_ring->nentries_mask;
        uint32_t sw_index = dest_ring->sw_index;
        uint32_t write_index;
        uint32_t nbytes, nbuf_cmpl_idx = 0;
        uint32_t num_htt_cmpls;
        void **transfer_contexts;
        adf_nbuf_t *nbuf_cmpl_arr = NULL;
        adf_nbuf_t nbuf;
        u_int32_t paddr_lo;

        struct CE_dest_desc *dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, sw_index);
        struct dest_desc_info *dest_desc_info = &dest_desc->info;

        u_int32_t ctrl_addr = ce_state->ctrl_addr;
        A_target_id_t targid = TARGID(sc);

        struct htt_pdev_t *htt_pdev = sc->scn->htt_pdev;
        struct HIF_CE_state *hif_state = (struct HIF_CE_state *)sc->hif_device;
        struct HIF_CE_pipe_info *pipe_info = &(hif_state->pipe_info[ce_id]);
        adf_os_size_t ce_max_buf_size = pipe_info->buf_sz;

        CE_ENGINE_INT_STATUS_CLEAR(targid, ctrl_addr, HOST_IS_COPY_COMPLETE_MASK);

#if QCA_PARTNER_DIRECTLINK_RX
        /*
         * For Direct Link RX, CE5 only clear up interrupt status as above.
         * Go through CE5 ring and T2H message would be handled by partner API.
         */
        if (!adf_os_unlikely(sc->is_directlink) || (ce_id != CE_HTT_MSG_CE))
#endif /* QCA_PARTNER_DIRECTLINK_RX */
        {
            nbuf_cmpl_arr = &htt_pdev->nbuf_cmpl_arr[0];
            transfer_contexts = dest_ring->per_transfer_context;

            for (;;) {
                if (sc->napi_enable && !(--sc->napi_budget))
                    break;

                dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, sw_index);

                dest_desc_info = &dest_desc->info;

                /*
                 * The following 2 reads are from non-cached memory
                 * TODO : Make this cacheable memory, since we will read
                 *        ring in a loop in a given call. That way, we
                 *        can avoid quite a few memory reads.
                 */
                nbytes = dest_desc_info->nbytes;

                /* If completion is invalid, break */
                if (adf_os_unlikely(nbytes == 0)) {
                    break;
                }

                /*
                 * CAREFUL : Uncached write, but still less expensive,
                 * since most modern caches use "write-combining" to flush
                 * multiple cache-writes all at once.
                 */
                dest_desc_info->nbytes = 0;

                /*
                 * Build the nbuf list from valid completions
                 */
                nbuf = dest_ring->per_transfer_context[sw_index];

#if 1
                /*
                 * Per our understanding this is not required on our
                 * since we are doing the same cache invalidation operation
                 * on the same buffer twice in succession, without any modifiication
                 * to this buffer by CPU in between.
                 * However, this code with 2 syncs in succession has been undergoing some
                 * testing at a customer site, and seemed to be showing no problems
                 * so far. Would like to validate from the customer, that this line
                 * is really not required, before we remove this line completely.
                 */
                paddr_lo = adf_nbuf_get_frag_paddr_lo(nbuf, 0);
                OS_SYNC_SINGLE(sc->scn->sc_osdev, paddr_lo, nbytes, BUS_DMA_FROMDEVICE, &paddr_lo);
#endif

                if (adf_os_unlikely(nbytes > ce_max_buf_size)) {
                    adf_os_print("%s: oversized packet received in CE: nbytes %u metadata %u sw_index %u\n", __func__, nbytes, dest_desc_info->meta_data, sw_index);
                    nbytes = ce_max_buf_size;
                }

                /* Set the length, & put accumulate in the array */
                adf_nbuf_set_pktlen(nbuf, nbytes);
                nbuf_cmpl_arr[nbuf_cmpl_idx++] = nbuf;

                /*
                 * If array is full call the HTT message handler directly here
                 * Also post buffers for this CE
                 * TODO : Optimize this posting, these postings are not required.
                 * Need to incorporate Anand's idea of reusing the buffers
                 */
                if (adf_os_unlikely(nbuf_cmpl_idx == MSG_FLUSH_NUM)) {

                    htt_t2h_msg_handler_fast(htt_pdev, nbuf_cmpl_arr, MSG_FLUSH_NUM, &num_htt_cmpls);

                    /* Update Destination Ring Write Index */
                    write_index = dest_ring->write_index;
                    write_index = CE_RING_IDX_ADD(nentries_mask, write_index, MSG_FLUSH_NUM);
                    CE_DEST_RING_WRITE_IDX_SET(targid, ctrl_addr, write_index);
                    dest_ring->write_index = write_index;

#if !QCA_OL_TX_PDEV_LOCK
                    CE_htt_ce_cmpl(CE_tx_cmpl_state, num_htt_cmpls);
#endif /* !QCA_OL_TX_PDEV_LOCK */

                    nbuf_cmpl_idx = 0;
                }

                /*
                 * No lock is needed here, since this is the only thread
                 * that accesses the sw_index
                 */
                sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
            }

            /*
             * If there are not enough completions to fill the array,
             * just call the HTT message handler here
             */
            if (adf_os_likely(nbuf_cmpl_idx)) {

                htt_t2h_msg_handler_fast(htt_pdev, nbuf_cmpl_arr, nbuf_cmpl_idx, &num_htt_cmpls);

                /* Update Destination Ring Write Index */
                write_index = dest_ring->write_index;
                write_index = CE_RING_IDX_ADD(nentries_mask, write_index, nbuf_cmpl_idx);
                CE_DEST_RING_WRITE_IDX_SET(targid, ctrl_addr, write_index);
                dest_ring->write_index = write_index;

#if !QCA_OL_TX_PDEV_LOCK
                CE_htt_ce_cmpl(CE_tx_cmpl_state, num_htt_cmpls);
#endif /* !QCA_OL_TX_PDEV_LOCK */

                nbuf_cmpl_idx = 0;
            }
            dest_ring->sw_index = sw_index;
            sc->scn->pkt_stats.sw_index[ce_id]= dest_ring->sw_index;
            sc->scn->pkt_stats.write_index[ce_id]=dest_ring->write_index;

        } /* else QCA_PARTNER_DIRECTLINK_RX */
    } /* !nss_wifi_ol_mode */
}

/*
 * This is only used in the cleanup. This API is only required,
 * since we don't want to get rid of the "static inline" nature
 * CE_per_engine_service_fast(), which is used in the fast data
 * path. This function is accessible as an exported API from other
 * modules.
 */
void
CE_per_engine_service_one(struct ath_hif_pci_softc *sc, uint32_t ce_id)
{
    CE_per_engine_service_fast(sc, ce_id);

#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * For Direct Link RX,
     * Go through CE5 ring and T2H message would be handled by partner API.
     */
    if (adf_os_unlikely(sc->is_directlink) && (ce_id == CE_HTT_MSG_CE)) {
        CE5_service_fast_partner();
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

}

#define MAX_RX_CES      8
#define MAX_TX_CES      8
#define MAX_MS_CES      8

void CE_htt_rx_msi(int irq, struct ath_hif_pci_softc *sc)
{

    CE_per_engine_service_fast(sc, CE_HTT_MSG_CE);

#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * For Direct Link RX,
     * Go through CE5 ring and T2H message would be handled by partner API.
     */
    if (adf_os_unlikely(sc->is_directlink)) {
        CE5_service_fast_partner();
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */
}

void
CE_per_engine_service_each(int irq, struct ath_hif_pci_softc *sc)
{
    A_target_id_t targid = TARGID(sc);
    void **transfer_contexts;
    void *tx_transfer_ctx;
    struct CE_state *CE_state;
    int CE_id;
    struct CE_dest_desc *dest_ring_base;
    struct CE_dest_desc *dest_desc;
    int nbytes;
    CE_addr_t buf;
    unsigned int sw_index;
    unsigned int nentries_mask;
    unsigned int id;
    int i = 0;

    struct HIF_CE_pipe_info *pipe_info;
    struct HIF_CE_state *hif_state;
    struct HIF_CE_completion_state *compl_state;
    struct HIF_CE_completion_state *compl_queue_head, *compl_queue_tail; /* local queue */
    uint32_t num_cmpl_states = 0;

    adf_os_device_t adf_dev = sc->scn->adf_dev;

    /*If msi is not registered process the CE5*/
    if( sc->num_msi_intrs <= 1 )
    {

	CE_per_engine_service_fast(sc, CE_HTT_MSG_CE);

#if QCA_PARTNER_DIRECTLINK_RX
	/*
	* For Direct Link RX,
	* Go through CE5 ring and T2H message would be handled by partner API.
	*/
	if (adf_os_unlikely(sc->is_directlink)) {
	    CE5_service_fast_partner();
	}
#endif /* QCA_PARTNER_DIRECTLINK_RX */
    }

    /* Process Rx CE's */
    for (i = 0; i < MAX_RX_CES; i++) {
        if (sc->rx_ce_list_fast[i] == -1) {
            break;
        }
        CE_id = sc->rx_ce_list_fast[i];

        CE_state = sc->CE_id_to_state[CE_id];
        pipe_info = CE_state->recv_context;
        hif_state = pipe_info->HIF_CE_state;
        compl_queue_head = compl_queue_tail = NULL;

        CE_ENGINE_INT_STATUS_CLEAR(targid, CE_state->ctrl_addr, HOST_IS_COPY_COMPLETE_MASK);
        /*
         * Grab the SW index and ring base. Get the mask to be used in the
         * loop for index increment.
         */
        sw_index = (CE_state->dest_ring->sw_index);
        dest_ring_base = (struct CE_dest_desc *)(CE_state->dest_ring->base_addr_owner_space);
        nentries_mask = (CE_state->dest_ring->nentries_mask);
        transfer_contexts = (CE_state->dest_ring->per_transfer_context);
        while (1) {
            dest_desc = CE_DEST_RING_TO_DESC(dest_ring_base, sw_index);
            nbytes = dest_desc->info.nbytes;
            if (nbytes != 0) {
                adf_nbuf_t netbuf;
                netbuf = transfer_contexts[sw_index];
                dest_desc->info.nbytes = 0;

                sw_index = CE_RING_IDX_INCR(nentries_mask, sw_index);
                CE_state->dest_ring->sw_index = sw_index;
                {
                    adf_os_spin_lock(&pipe_info->completion_freeq_lock);
                    compl_state = pipe_info->completion_freeq_head;
                    ASSERT(compl_state != NULL);
                    pipe_info->completion_freeq_head = compl_state->next;
                    adf_os_spin_unlock(&pipe_info->completion_freeq_lock);
                    compl_state->next = NULL;
                    /* Enqueue at end of local queue */
                    if (compl_queue_tail) {
                        compl_queue_tail->next = compl_state;
                        compl_queue_tail = compl_state;
                    } else {
                        compl_queue_head = compl_queue_tail = compl_state;
                    }

                    compl_state->send_or_recv = HIF_CE_COMPLETE_RECV;
                    compl_state->copyeng = (struct CE_handle *)CE_state;
                    compl_state->ce_context = CE_state->recv_context;
                    compl_state->transfer_context = netbuf;
                    compl_state->data = (CE_addr_t)(dest_desc->dest_ptr);
                    compl_state->nbytes = nbytes;
                    compl_state->transfer_id = dest_desc->info.meta_data;
                    compl_state->flags = dest_desc->info.byte_swap ?  CE_RECV_FLAG_SWAPPED : 0;
                    adf_nbuf_unmap_nbytes_single(adf_dev, (adf_nbuf_t)compl_state->transfer_context,
                                    ADF_OS_DMA_FROM_DEVICE, nbytes);
                    num_cmpl_states++;
                }
            } else {
                break;
            }
        }
        if (compl_queue_head) {
            num_cmpl_states = 0;

            // Hand off the list to the handler function.
            if (hif_state->completion_pendingq_head) {
                hif_state->completion_pendingq_tail->next = compl_queue_head;
                hif_state->completion_pendingq_tail = compl_queue_tail;
            }
            else {
                hif_state->completion_pendingq_head = compl_queue_head;
                hif_state->completion_pendingq_tail = compl_queue_tail;
            }
            /* Alert the recv completion service thread */
            hif_completion_thread(hif_state);
        }
    }

    /* Process Tx CE's */
    for (i = 0; i < MAX_TX_CES; i++) {
        void *CE_context;
        if (sc->tx_ce_list[i] == -1) {
            break;
        }
        CE_id = sc->tx_ce_list[i];

        CE_state = sc->CE_id_to_state[CE_id];
        CE_ENGINE_INT_STATUS_CLEAR(targid, CE_state->ctrl_addr, HOST_IS_COPY_COMPLETE_MASK);

        adf_os_spin_lock(&sc->target_lock);
        while (CE_completed_send_next_nolock(CE_state, &CE_context, &tx_transfer_ctx,
                &buf, &nbytes, &id) == A_OK) {
            if( sc->tx_ce_list[i] != CE_HTT_TX_CE)
            {
                adf_os_spin_unlock(&sc->target_lock);
                CE_state->send_cb((struct CE_handle *)CE_state, CE_context, tx_transfer_ctx, buf, nbytes, id);
                adf_os_spin_lock(&sc->target_lock);

            }
        }
        adf_os_spin_unlock(&sc->target_lock);
    }

    /* Just clear the interrupt source for all other CE's */
    for (i = 0; i < MAX_MS_CES; i++) {
        if (sc->misc_ce_list[i] == -1) {
            break;
        }
        CE_id = sc->misc_ce_list[i];
        CE_state = sc->CE_id_to_state[CE_id];
        CE_ENGINE_INT_STATUS_CLEAR(targid, CE_state->ctrl_addr, HOST_IS_COPY_COMPLETE_MASK);
    }
}

/*
 * Cleanup buffers on the t2h HTT msg queue.
 * These buffers are never allocated on the fly, but
 * are allocated only once during HIF start and freed
 * only once during HIF stop.
 * NOTE:
 * The assumption here is there is no in-flight DMA in progress
 * currently, so that buffers can be freed up safely.
 */
static void
CE_t2h_msg_ce_cleanup(struct CE_handle *ce_hdl)
{
    struct CE_state *ce_state = (struct CE_state *)ce_hdl;
    struct ath_hif_pci_softc *sc = ce_state->sc;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (sc->nss_wifi_ol_mode) {
        return;
    } else
#endif
    {
        struct CE_ring_state *dst_ring = ce_state->dest_ring;
        adf_nbuf_t nbuf;
        int i;

        /*
         * Unlike other CE's, this CE is completely full:
         * does not leave one blank space, to distinguish
         * between empty queue & full queue.
         * So free all the entries.
         */
        for (i = 0; i < dst_ring->nentries; i++) {
            nbuf = dst_ring->per_transfer_context[i];

            /*
             * The reasons for doing this check are:
             * 1) Protect against calling cleanup before allocating buffers
             * 2) In a corner case, hif_started may be set, but we could have
             *    a partially filled ring, because of a memory allocation failure
             *    in the middle of allocating ring.
             *    This check accounts for that case, checking hif_started flag or
             *    started flag would not have covered that case.
             *    This is not in performance path, so OK to do this.
             */
            if (adf_os_likely(nbuf)) {
                adf_nbuf_unmap_single(sc->scn->adf_dev, nbuf, ADF_OS_DMA_FROM_DEVICE);
                adf_nbuf_free(nbuf);
            }
        }
    }
}


/*
 * Place holder function for H2T CE cleanup.
 * No processing is required inside this function.
 * Using an assert, this function makes sure that,
 * the TX CE has been processed completely.
 */
static void
CE_h2t_tx_ce_cleanup(struct CE_handle *ce_hdl)
{
    struct CE_state *ce_state = (struct CE_state *)ce_hdl;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ath_hif_pci_softc *sc = ce_state->sc;
    if (sc->nss_wifi_ol_mode) {
        return;
    } else
#endif
    {
        struct CE_ring_state *src_ring = ce_state->src_ring;
        uint32_t sw_index, write_index;
#if !QCA_OL_TX_PDEV_LOCK
        struct ath_hif_pci_softc *sc = ce_state->sc;
        CE_HTT_TX_LOCK(&sc->target_lock);
#endif
        sw_index = src_ring->sw_index;
        write_index = src_ring->sw_index;
#if !QCA_OL_TX_PDEV_LOCK
        CE_HTT_TX_UNLOCK(&sc->target_lock);
#endif
        /* At this point Tx CE should be clean */
        adf_os_assert_always(sw_index == write_index);
    }
}
#endif /* QCA_OL_11AC_FAST_PATH */

#define MSI_DATA_ADDRESS 0x20
/*
 * Adjust interrupts for the copy complete handler.
 * If it's needed for either send or recv, then unmask
 * this interrupt; otherwise, mask it.
 *
 * Called with target_lock held.
 */
void
CE_per_engine_handler_adjust(struct CE_state *CE_state,
                             int disable_copy_compl_intr)
{
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);
#if !QCA_PARTNER_DIRECTLINK_RX
    int intr_enabled=0;
    volatile uint32_t msi_data=0;
#endif

    A_TARGET_ACCESS_BEGIN(targid);
    if ((!disable_copy_compl_intr) &&
        (CE_state->send_cb || CE_state->recv_cb))
    {
        CE_COPY_COMPLETE_INTR_ENABLE(targid, ctrl_addr);
#if !QCA_PARTNER_DIRECTLINK_RX
	intr_enabled=1;
#endif
    } else {
        CE_COPY_COMPLETE_INTR_DISABLE(targid, ctrl_addr);
    }

    if (CE_state->watermark_cb) {
        CE_WATERMARK_INTR_ENABLE(targid, ctrl_addr);
#if !QCA_PARTNER_DIRECTLINK_RX
	intr_enabled=1;
#endif
    } else {
        CE_WATERMARK_INTR_DISABLE(targid, ctrl_addr);
    }
    /*Isolate HTT_RX_CE interrupt if MSI is enabled*/
#if !QCA_PARTNER_DIRECTLINK_RX
    if (intr_enabled && (sc->num_msi_intrs > 1))
    {
        msi_data = A_TARGET_READ(targid,(ctrl_addr+MSI_DATA_ADDRESS));
        /* printk("CE%d msi data 0x%08x\n",CE_state->id,msi_data); */
        msi_data = ((CE_state->id)+MSI_ASSIGN_CE_INITIAL );
        A_TARGET_WRITE(targid,ctrl_addr+MSI_DATA_ADDRESS, msi_data);
        /* printk("CE%d msi data written 0x%08x\n\n",CE_state->id,msi_data); */
    }
#endif
    A_TARGET_ACCESS_END(targid);
}

void
CE_per_engine_disable_interupt(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    u_int32_t ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);

    printk("%p:Disable CE interrupt \n ", sc);

    A_TARGET_ACCESS_BEGIN(targid);

    CE_COPY_COMPLETE_INTR_DISABLE(targid, ctrl_addr);

    A_TARGET_ACCESS_END(targid);
}


void
CE_send_cb_register(struct CE_handle *copyeng,
                    CE_send_cb fn_ptr,
                    void *CE_send_context,
                    int disable_interrupts)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;

    adf_os_spin_lock_bh(&sc->target_lock);
    CE_state->send_cb = fn_ptr;
    CE_state->send_context = CE_send_context;
    CE_per_engine_handler_adjust(CE_state, disable_interrupts);
    adf_os_spin_unlock_bh(&sc->target_lock);
}

void
CE_recv_cb_register(struct CE_handle *copyeng,
                    CE_recv_cb fn_ptr,
                    void *CE_recv_context)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;

    adf_os_spin_lock_bh(&sc->target_lock);
    CE_state->recv_cb = fn_ptr;
    CE_state->recv_context = CE_recv_context;
    CE_per_engine_handler_adjust(CE_state, 0);
    adf_os_spin_unlock_bh(&sc->target_lock);
}

void
CE_watermark_cb_register(struct CE_handle *copyeng,
                         CE_watermark_cb fn_ptr,
                         void *CE_wm_context)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    struct ath_hif_pci_softc *sc = CE_state->sc;

    adf_os_spin_lock(&sc->target_lock);
    CE_state->watermark_cb = fn_ptr;
    CE_state->wm_context = CE_wm_context;
    CE_per_engine_handler_adjust(CE_state, 0);
    if (fn_ptr) {
        CE_state->misc_cbs = 1;
    }
    adf_os_spin_unlock(&sc->target_lock);
}

static unsigned int
roundup_pwr2(unsigned int n)
{
    int i;
    unsigned int test_pwr2;

    if (!(n & (n-1))) {
        return n; /* already a power of 2 */
    }

    test_pwr2 = 4;
    for (i=0; i<29; i++) {
        if (test_pwr2 > n) {
            return test_pwr2;
        }
        test_pwr2 = test_pwr2 << 1;
    }

    A_ASSERT(0); /* n too large */
    return 0;
}

#if QCA_OL_11AC_FAST_PATH
void CE_pkt_dl_len_set(void *hif_sc,
                          u_int32_t pkt_download_len)
{
    struct ath_hif_pci_softc *sc =
        (struct ath_hif_pci_softc *)(hif_sc);

    struct CE_state *CE_state =
            sc->CE_id_to_state[CE_HTT_TX_CE];

    adf_os_assert_always(CE_state);

    adf_os_spin_lock_bh(&sc->target_lock);
    CE_state->download_len = pkt_download_len;
    adf_os_spin_unlock_bh(&sc->target_lock);

    adf_os_print(KERN_INFO"%s CE %d Pkt download length %d\n",
            __func__, CE_state->id, CE_state->download_len);
}
#endif /* QCA_OL_11AC_FAST_PATH */

/*
 * Initialize a Copy Engine based on caller-supplied attributes.
 * This may be called once to initialize both source and destination
 * rings or it may be called twice for separate source and destination
 * initialization. It may be that only one side or the other is
 * initialized by software/firmware.
 */
struct CE_handle *
CE_init(struct ath_hif_pci_softc *sc,
        unsigned int CE_id,
        struct CE_attr *attr)
{
    struct CE_state *CE_state;
    u_int32_t ctrl_addr;
    A_target_id_t targid;
    unsigned int nentries;
    adf_os_dma_addr_t base_addr;
    struct ol_ath_softc_net80211 *scn = sc->scn;
#if QCA_PARTNER_DIRECTLINK_RX
    uint32_t t2h_ring_sz = 0;
    uint32_t dst_ring_base = 0;
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    A_ASSERT(CE_id < sc->ce_count);
    ctrl_addr = CE_BASE_ADDRESS(CE_id);
    adf_os_spin_lock_bh(&sc->target_lock);
    CE_state = sc->CE_id_to_state[CE_id];


    if (!CE_state) {
        adf_os_spin_unlock_bh(&sc->target_lock);
        CE_state = (struct CE_state *)A_MALLOC(sizeof(*CE_state));
		/*A_ASSERT(CE_state);*/ /* TBDXXX */
        if (!CE_state) {
            return NULL;
        }
        A_MEMZERO(CE_state, sizeof(*CE_state));
        adf_os_spin_lock_bh(&sc->target_lock);
        if (!sc->CE_id_to_state[CE_id]) { /* re-check under lock */
            sc->CE_id_to_state[CE_id] = CE_state;

            CE_state->sc = sc;
            CE_state->id = CE_id;
            CE_state->ctrl_addr = ctrl_addr;
            CE_state->state = CE_RUNNING;
            CE_state->attr_flags = attr->flags; /* Save attribute flags */
        } else {
            /*
             * We released target_lock in order to allocate CE state,
             * but someone else beat us to it.  Continue, using that
             * CE_state (and free the one we allocated).
             */
            A_FREE(CE_state);
            CE_state = sc->CE_id_to_state[CE_id];
        }
    }
    adf_os_spin_unlock_bh(&sc->target_lock);

    if (attr == NULL) {
        /* Already initialized; caller wants the handle */
        return (struct CE_handle *)CE_state;
    }

    targid = TARGID(sc);

    if (CE_state->src_sz_max) {
        A_ASSERT(CE_state->src_sz_max == attr->src_sz_max);
    } else {
        CE_state->src_sz_max = attr->src_sz_max;
    }

    /* source ring setup */
    nentries = attr->src_nentries;
    if (nentries) {
        struct CE_ring_state *src_ring;
        unsigned CE_nbytes;
        char *ptr;

        nentries = roundup_pwr2(nentries);
        /* limit nentries to what the hardware can support as per CR717220 */
        adf_os_assert_always(nentries <= CE_SRC_RING_SZ_MAX);

        if (CE_state->src_ring) {
            A_ASSERT(CE_state->src_ring->nentries == nentries);
        } else {
            CE_nbytes = sizeof(struct CE_ring_state)
                      + (nentries * sizeof(void *)); /* per-send context */
            ptr = A_MALLOC(CE_nbytes);
            /*A_ASSERT(ptr); *//* TBDXXX */
            if (!ptr) {
                return NULL;
            }
            A_MEMZERO(ptr, CE_nbytes);

            src_ring = CE_state->src_ring = (struct CE_ring_state *)ptr;
            ptr += sizeof(struct CE_ring_state);
            src_ring->nentries = nentries;
            src_ring->nentries_mask = nentries-1;
            A_TARGET_ACCESS_BEGIN(targid);
            src_ring->hw_index =
                src_ring->sw_index = CE_SRC_RING_READ_IDX_GET(targid, ctrl_addr);
            src_ring->write_index = CE_SRC_RING_WRITE_IDX_GET(targid, ctrl_addr);
            A_TARGET_ACCESS_END(targid);
            src_ring->low_water_mark_nentries = 0;
            src_ring->high_water_mark_nentries = nentries;
            src_ring->per_transfer_context = (void **)ptr;
            ptr += (nentries * sizeof(void *));

            /* Legacy platforms that do not support cache coherent DMA are unsupported */
            src_ring->base_addr_owner_space_unaligned =
                OS_MALLOC_CONSISTENT(scn->sc_osdev,
                                    (nentries * sizeof(struct CE_src_desc) + CE_DESC_RING_ALIGN),
                                    &base_addr,
                                    OS_GET_DMA_MEM_CONTEXT(src_ring, ce_dmacontext), 0);
            if (!src_ring->base_addr_owner_space_unaligned) {
                A_FREE(CE_state->src_ring);
                CE_state->src_ring = NULL;
                return NULL;
            }
            src_ring->base_addr_CE_space_unaligned = base_addr;


            if (src_ring->base_addr_CE_space_unaligned & (CE_DESC_RING_ALIGN-1)) {

                src_ring->base_addr_CE_space = (src_ring->base_addr_CE_space_unaligned +
                        CE_DESC_RING_ALIGN-1) & ~(CE_DESC_RING_ALIGN-1);

                src_ring->base_addr_owner_space = (void *)(((size_t)src_ring->base_addr_owner_space_unaligned +
                        CE_DESC_RING_ALIGN-1) & ~(CE_DESC_RING_ALIGN-1));
            } else {
                src_ring->base_addr_CE_space = src_ring->base_addr_CE_space_unaligned;
                src_ring->base_addr_owner_space = src_ring->base_addr_owner_space_unaligned;
            }
            /*
             * Also allocate a shadow src ring in regular mem to use for
             * faster access.
             */
            src_ring->shadow_base_unaligned = A_MALLOC(
                nentries * sizeof(struct CE_src_desc) + CE_DESC_RING_ALIGN);
            if (!src_ring->shadow_base_unaligned) {
		OS_FREE_CONSISTENT(scn->sc_osdev,
                   (nentries * sizeof(struct CE_src_desc) + CE_DESC_RING_ALIGN),
                   src_ring->base_addr_owner_space_unaligned, src_ring->base_addr_CE_space,
                   OS_GET_DMA_MEM_CONTEXT(src_ring, ce_dmacontext));
                A_FREE(CE_state->src_ring);
                CE_state->src_ring = NULL;
                return NULL;
            }
            src_ring->shadow_base = (struct CE_src_desc *)
                (((size_t) src_ring->shadow_base_unaligned +
                CE_DESC_RING_ALIGN-1) & ~(CE_DESC_RING_ALIGN-1));

#if QCA_OL_11AC_FAST_PATH
            adf_os_spinlock_init(&src_ring->ce_ring_lock);
#endif
            A_TARGET_ACCESS_BEGIN(targid);
            CE_SRC_RING_BASE_ADDR_SET(targid, ctrl_addr, src_ring->base_addr_CE_space);
            CE_SRC_RING_SZ_SET(targid, ctrl_addr, nentries);
            CE_SRC_RING_DMAX_SET(targid, ctrl_addr, attr->src_sz_max);
#if defined(BIG_ENDIAN_HOST) && !AH_NEED_TX_DATA_SWAP
            /* Enable source ring byte swap for big endian host */
            CE_SRC_RING_BYTE_SWAP_SET(targid, ctrl_addr, 1);
#endif
            CE_SRC_RING_LOWMARK_SET(targid, ctrl_addr, 0);
            CE_SRC_RING_HIGHMARK_SET(targid, ctrl_addr, nentries);
            A_TARGET_ACCESS_END(targid);
        }
    }

    /* destination ring setup */
#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * For Direct Link RX, CE5 destination ring size would get from partner API.
     */
    if (adf_os_unlikely(sc->is_directlink) && (CE_id == CE_HTT_MSG_CE)) {
        CE5_init_partner(&t2h_ring_sz, &dst_ring_base);
        nentries = t2h_ring_sz;
    } else
#endif /* QCA_PARTNER_DIRECTLINK_RX */
{
    nentries = attr->dest_nentries;
}

    /* limit nentries to what the hardware can support as per CR717220 */
    adf_os_assert_always(nentries <= CE_DEST_RING_SZ_MAX);

    if (nentries) {
        struct CE_ring_state *dest_ring;
        unsigned CE_nbytes;
        char *ptr;

        nentries = roundup_pwr2(nentries);
        if (CE_state->dest_ring) {
            A_ASSERT(CE_state->dest_ring->nentries == nentries);
        } else {
            CE_nbytes = sizeof(struct CE_ring_state)
                      + (nentries * sizeof(void *)); /* per-recv context */
            ptr = A_MALLOC(CE_nbytes);
            /*A_ASSERT(ptr);*/ /* TBDXXX */
            if (!ptr) {
                return NULL;
            }
            A_MEMZERO(ptr, CE_nbytes);

            dest_ring = CE_state->dest_ring = (struct CE_ring_state *)ptr;
            ptr += sizeof(struct CE_ring_state);
            dest_ring->nentries = nentries;
            dest_ring->nentries_mask = nentries-1;
            A_TARGET_ACCESS_BEGIN(targid);
            dest_ring->sw_index = CE_DEST_RING_READ_IDX_GET(targid, ctrl_addr);
            dest_ring->write_index = CE_DEST_RING_WRITE_IDX_GET(targid, ctrl_addr);
            A_TARGET_ACCESS_END(targid);
            dest_ring->low_water_mark_nentries = 0;
            dest_ring->high_water_mark_nentries = nentries;
            dest_ring->per_transfer_context = (void **)ptr;
            ptr += (nentries * sizeof(void *));

#if QCA_PARTNER_DIRECTLINK_RX
            /*
             * For Direct Link RX
             * CE5 destination ring desciptors are created by partner API.
             */
            if (adf_os_unlikely(sc->is_directlink) && (CE_id == CE_HTT_MSG_CE)) {
                dest_ring->base_addr_CE_space_unaligned = (CE_addr_t ) dst_ring_base;
                dest_ring->base_addr_owner_space_unaligned = (void *) dst_ring_base;
            } else
#endif /* QCA_PARTNER_DIRECTLINK_RX */
        {
            /* Legacy platforms that do not support cache coherent DMA are unsupported */
            dest_ring->base_addr_owner_space_unaligned =
                OS_MALLOC_CONSISTENT(scn->sc_osdev,
                                    (nentries * sizeof(struct CE_dest_desc) + CE_DESC_RING_ALIGN),
                                    &base_addr,
                                    OS_GET_DMA_MEM_CONTEXT(dest_ring, ce_dmacontext), 0);
            if (!dest_ring->base_addr_owner_space_unaligned) {
                A_FREE(CE_state->dest_ring);
                CE_state->dest_ring = NULL;
                return NULL;
            }
            dest_ring->base_addr_CE_space_unaligned = base_addr;

            /* Correctly initialize memory to 0 to prevent garbage data
             * crashing system when download firmware
             */
            A_MEMZERO(dest_ring->base_addr_owner_space_unaligned, nentries * sizeof(struct CE_dest_desc) + CE_DESC_RING_ALIGN);

        } /* QCA_PARTNER_DIRECTLINK_RX */

            if (dest_ring->base_addr_CE_space_unaligned & (CE_DESC_RING_ALIGN-1)) {

                dest_ring->base_addr_CE_space = (dest_ring->base_addr_CE_space_unaligned +
                        CE_DESC_RING_ALIGN-1) & ~(CE_DESC_RING_ALIGN-1);

                dest_ring->base_addr_owner_space = (void *)(((size_t)dest_ring->base_addr_owner_space_unaligned +
                        CE_DESC_RING_ALIGN-1) & ~(CE_DESC_RING_ALIGN-1));
            } else {
                dest_ring->base_addr_CE_space = dest_ring->base_addr_CE_space_unaligned;
                dest_ring->base_addr_owner_space = dest_ring->base_addr_owner_space_unaligned;
            }
#if QCA_OL_11AC_FAST_PATH
            adf_os_spinlock_init(&dest_ring->ce_ring_lock);
#endif
            A_TARGET_ACCESS_BEGIN(targid);
            CE_DEST_RING_BASE_ADDR_SET(targid, ctrl_addr, dest_ring->base_addr_CE_space);
            CE_DEST_RING_SZ_SET(targid, ctrl_addr, nentries);
#if defined(BIG_ENDIAN_HOST) && !AH_NEED_TX_DATA_SWAP
            /* Enable Destination ring byte swap for big endian host */
            CE_DEST_RING_BYTE_SWAP_SET(targid, ctrl_addr, 1);
#endif
            CE_DEST_RING_LOWMARK_SET(targid, ctrl_addr, 0);
            CE_DEST_RING_HIGHMARK_SET(targid, ctrl_addr, nentries);
            A_TARGET_ACCESS_END(targid);
        }
    }

    /* Enable CE error interrupts */
    A_TARGET_ACCESS_BEGIN(targid);
    CE_ERROR_INTR_ENABLE(targid, ctrl_addr);
    A_TARGET_ACCESS_END(targid);

#if QCA_PARTNER_DIRECTLINK_TX
    if (CE_id==CE_HTT_TX_CE) {
        CE_init_HTT_TX_CE_partner(CE_state);
    }
#endif /* QCA_PARTNER_DIRECTLINK_TX */

#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * For Direct Link RX
     * CE5 recv buffer is already enqueued by partner API.
     * So update Destination Ring Write Index here
     */
    if (adf_os_unlikely(sc->is_directlink) && (CE_id == CE_HTT_MSG_CE)) {
        A_TARGET_ACCESS_BEGIN(targid);
        CE_DEST_RING_WRITE_IDX_SET(targid, ctrl_addr, t2h_ring_sz-1);
        A_TARGET_ACCESS_END(targid);
    }
#endif /* QCA_PARTNER_DIRECTLINK_RX */

    return (struct CE_handle *)CE_state;
}

void
CE_pause(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    A_UINT32 ctrl_addr = CE_state->ctrl_addr;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    A_target_id_t targid = TARGID(sc);
    int i = 0;
    A_TARGET_ACCESS_BEGIN(targid);
    CE_HALT(targid, ctrl_addr);
    while (!CE_HALT_STATUS(targid, ctrl_addr)) {
        A_MDELAY(1);
        if (i++ > CE_HALT_TIMEOUT_MS) {
            printk("%s : %d : ERROR failed to HALT Copy Engine id %d \n",
                     __func__, __LINE__, CE_state->id);
            goto done;
        }
    }
done:
    A_TARGET_ACCESS_END(targid);
}

int
CE_state_check(struct ath_hif_pci_softc *sc)
{
    int i;
    struct CE_state *CE_state;
    for (i=0; i< sc->ce_count ; i++) {
        CE_state = sc->CE_id_to_state[i];
        if ((CE_state->sc == NULL) || (CE_state->id != i) || (CE_state->state != CE_RUNNING)) {
            adf_os_print("CE_state->sc %p \n", CE_state->sc);
            adf_os_print("CE_state->id %d \n", CE_state->id);
            adf_os_print("CE_state->state %u \n", CE_state->state);
            adf_os_print("CE_state->attr_flags %u \n", CE_state->attr_flags);
            adf_os_print("CE_state->ctrl_addr %d \n", CE_state->ctrl_addr);
            adf_os_print("CE_state->src_ring %p \n", CE_state->src_ring);
            adf_os_print("CE_state->dest_ring %p \n", CE_state->dest_ring);
            adf_os_print("CE_state->src_sz_max %u \n", CE_state->src_sz_max);
            adf_os_print("CE_state->send_cb %p \n", CE_state->send_cb);
            adf_os_print("CE_state->recv_cb %p \n", CE_state->recv_cb);
            adf_os_print("CE_state->watermark_cb %p \n", CE_state->watermark_cb);
            adf_os_print("CE_state->send_context %p \n", CE_state->send_context);
            adf_os_print("CE_state->recv_context %p \n", CE_state->recv_context);
            adf_os_print("CE_state->wm_context %p \n", CE_state->wm_context);
            return 0;
        }
    }
    return 1;
}

void
CE_fini(struct CE_handle *copyeng)
{
    struct CE_state *CE_state = (struct CE_state *)copyeng;
    unsigned int CE_id = CE_state->id;
    struct ath_hif_pci_softc *sc = CE_state->sc;
    struct ol_ath_softc_net80211 *scn = sc->scn;

    CE_state->state = CE_UNUSED;
    CE_state->sc->CE_id_to_state[CE_id] = NULL;
    /* temp. workaround to Halt CE to avoid any uplink transfer during SOC reset */

    if ( scn->fwsuspendfailed != 1 ) {
        CE_pause(copyeng);
    }

    if (CE_state->src_ring) {

#if QCA_OL_11AC_FAST_PATH
        /* Cleanup the HTT Tx ring */
        if (CE_state->id == CE_HTT_TX_CE) {
            adf_os_print(KERN_INFO"%s %d Cleaning up HTT Tx CE\n", __func__, __LINE__);
            CE_h2t_tx_ce_cleanup(copyeng);
#if QCA_PARTNER_DIRECTLINK_TX
	        if (adf_os_unlikely(sc->is_directlink)) {
			    CE_fini_HTT_TX_CE_partner();
	        }
#endif
        }
#endif
        A_FREE(CE_state->src_ring->shadow_base_unaligned);
		OS_FREE_CONSISTENT(scn->sc_osdev,
                   (CE_state->src_ring->nentries * sizeof(struct CE_src_desc) + CE_DESC_RING_ALIGN),
                   CE_state->src_ring->base_addr_owner_space_unaligned, CE_state->src_ring->base_addr_CE_space,
                   OS_GET_DMA_MEM_CONTEXT(CE_state->src_ring, ce_dmacontext));
#if QCA_OL_11AC_FAST_PATH
        adf_os_spinlock_destroy(&CE_state->src_ring->ce_ring_lock);
#endif
        A_FREE(CE_state->src_ring);
    }
    if (CE_state->dest_ring) {
#if QCA_PARTNER_DIRECTLINK_RX
        /*
         * For Direct Link RX, CE5 T2H message ring would clean up by partner API.
         */
        if (!adf_os_unlikely(sc->is_directlink) || (CE_state->id != CE_HTT_MSG_CE))
#endif /* QCA_PARTNER_DIRECTLINK_RX */
    {
#if QCA_OL_11AC_FAST_PATH
        /* Cleanup the HTT Tx ring */
        if (CE_state->id == CE_HTT_MSG_CE) {
            adf_os_print(KERN_INFO"%s Cleaning up HTT MSG CE(%d)\n", __func__, CE_HTT_MSG_CE);
            CE_t2h_msg_ce_cleanup(copyeng);
        }
#endif /* QCA_OL_11AC_FAST_PATH */
		OS_FREE_CONSISTENT(scn->sc_osdev,
                   (CE_state->dest_ring->nentries * sizeof(struct CE_dest_desc) + CE_DESC_RING_ALIGN),
                   CE_state->dest_ring->base_addr_owner_space_unaligned, CE_state->dest_ring->base_addr_CE_space,
                   OS_GET_DMA_MEM_CONTEXT(CE_state->dest_ring, ce_dmacontext));
    } /* QCA_PARTNER_DIRECTLINK_RX */

#if QCA_OL_11AC_FAST_PATH
        adf_os_spinlock_destroy(&CE_state->dest_ring->ce_ring_lock);
#endif
        A_FREE(CE_state->dest_ring);
    }
    A_FREE(CE_state);
}
