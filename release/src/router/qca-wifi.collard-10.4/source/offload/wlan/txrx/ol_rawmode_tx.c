/*
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <adf_nbuf.h>               /* adf_nbuf_t, etc. */
#include <ol_txrx_types.h>          /* ol_txrx_pdev_t */
#include <ol_txrx_api.h>            /* ol_txrx_vdev_handle */
#include <ol_rawmode_txrx_api.h>    /* API definitions */
#include <ol_htt_tx_api.h>          /* htt_tx_desc_frag */

#if QCA_OL_SUPPORT_RAWMODE_TXRX

/* Raw Mode specific Tx functionality */


#if QCA_OL_SUPPORT_RAWMODE_AR900B_BUFFCOALESCE

/* Raw mode Tx buffer coalescing
 *
 * This should ideally be disabled in end systems to avoid the if checks and
 * copies.
 * Instead, interfacing with external entities like Access Controller should be
 * designed such that this is never required (e.g. using Jumbo frames).
 *
 * We implement a simple coalescing scheme wherein last few buffers are combined
 * if necessary to help form max sized A-MSDU.
 *
 * For efficiency, we don't check the PHY mode/peer HT capability etc. to see
 * if a lower A-MSDU limit applies. The external entity (e.g. Access Controller)
 * must take care of ensuring it uses the right limit.
 *
 * However, as simple guard steps, we do check if previous buffers have been
 * fully utilized (by examining sub-total so far, assuming non Jumbo 802.3
 * frames), and whether total of all buffers falls within max VHT A-MSDU limit.
 * This is necessary to ensure we demand a new nbuf of reasonable size from the
 * OS.
 */

/* Max number of Raw frame nbufs (including master) which can be chained
 * together, before coalescing kicks in.
 * This is equal to pointers in MSDU Link extension descriptor */
#define RAW_TX_AR900B_MAX_CHAINS                    (6)

#define RAW_TX_8023_MTU_MAX                         (1500)
#define RAW_TX_VHT_MPDU_MAX                         (11454)

static int
ol_raw_tx_coalesce_nbufs(struct ol_txrx_pdev_t *pdev,
        adf_nbuf_t *pnbuf, u_int16_t non_coalesce_len)
{
    u_int16_t coalesce_len = 0;
    adf_nbuf_t currnbuf = NULL, nextnbuf = NULL, newnbuf = NULL;
    u_int8_t *currnewbufptr = NULL;

    adf_os_assert_always(non_coalesce_len >=
            (RAW_TX_8023_MTU_MAX * (RAW_TX_AR900B_MAX_CHAINS - 1)));

    currnbuf = *pnbuf;

    while(currnbuf)
    {
        coalesce_len += adf_nbuf_len(currnbuf);
        currnbuf = adf_nbuf_next(currnbuf);
    }

    /* We do not check mode etc. - see previous comments above */
    adf_os_assert_always((coalesce_len + non_coalesce_len) <=
                            RAW_TX_VHT_MPDU_MAX);

    newnbuf = adf_nbuf_alloc(pdev->osdev, coalesce_len, 0, 4, FALSE);

    if (!newnbuf) {
        adf_os_print("Could not allocate new buffer for Raw Tx buffer "
                     "coalescing\n");
        return -1;
    }

    adf_nbuf_set_pktlen(newnbuf, coalesce_len);

    currnbuf = *pnbuf;
    currnewbufptr = (u_int8_t*)adf_nbuf_data(newnbuf);

    while(currnbuf)
    {
        adf_os_mem_copy(currnewbufptr,
                adf_nbuf_data(currnbuf), adf_nbuf_len(currnbuf));
        currnewbufptr += adf_nbuf_len(currnbuf);
        nextnbuf = adf_nbuf_next(currnbuf);

        adf_nbuf_free(currnbuf);

        currnbuf = nextnbuf;
    }

    *pnbuf = newnbuf;

    return 0;
}
#endif /* QCA_OL_SUPPORT_RAWMODE_AR900B_BUFFCOALESCE */


#if QCA_OL_TX_CACHEDHDR
int8_t
ol_tx_prepare_raw_desc_chdhdr(
        struct ol_txrx_pdev_t *pdev,
        ol_txrx_vdev_handle vdev,
        adf_nbuf_t netbuf,
        struct ol_tx_desc_t *tx_desc,
        u_int16_t *total_len,
        u_int8_t *pnum_frags)
{
    adf_nbuf_t currnbuf = NULL, nextnbuf = NULL;
#if QCA_OL_SUPPORT_RAWMODE_AR900B_BUFFCOALESCE
    adf_nbuf_t tempnbuf = NULL;
#endif
    u_int16_t extra_len = 0;
    u_int8_t num_extra_frags = 0;

    /* Process the non-master nbufs in the chain, if any.
     * We need to carry out this processing at this point in order to
     * determine total data length. We piggy-back other operations to avoid
     * additional loops in caller later.
     */
    currnbuf = adf_nbuf_next(netbuf);

    while (currnbuf) {
        adf_nbuf_frags_num_init(currnbuf);

        if(A_STATUS_FAILED ==
            adf_nbuf_map_single(vdev->osdev,
                currnbuf,
                ADF_OS_DMA_TO_DEVICE)) {
            adf_os_print("DMA Mapping error \n");
            goto bad;
        }

        num_extra_frags++;

        /* adf_nbuf_len() is a light-weight inline dereferencing operation
         * hence we do not store it into a local variable for second reuse.
         * Can revisit this if later extensions require more than two
         * accesses.
         */
         extra_len += adf_nbuf_len(currnbuf);

         htt_tx_desc_frag(pdev->htt_pdev, tx_desc->htt_frag_desc,
                 num_extra_frags, adf_nbuf_get_frag_paddr_lo(currnbuf, 0),
                 adf_nbuf_len(currnbuf));

#if QCA_OL_SUPPORT_RAWMODE_AR900B_BUFFCOALESCE
         /* Look-ahead */
         if (pdev->is_ar900b &&
             (num_extra_frags == (RAW_TX_AR900B_MAX_CHAINS - 2)) &&
             ((tempnbuf = adf_nbuf_next(currnbuf)) != NULL) &&
             adf_nbuf_next(tempnbuf) != NULL) {
            /* We will be crossing chaining limit in the next 2 passes.
               Try to coalesce.
             */
            if (ol_raw_tx_coalesce_nbufs(pdev,
                        &tempnbuf, extra_len + adf_nbuf_len(netbuf)) < 0) {
                goto bad;
            } else {
                /* tempnbuf now contains the final, coalesced buffer */
                adf_nbuf_set_next(currnbuf, tempnbuf);
                adf_nbuf_set_next(tempnbuf, NULL);
            }
        }
#endif /* QCA_OL_SUPPORT_RAWMODE_AR900B_BUFFCOALESCE */

         currnbuf = adf_nbuf_next(currnbuf);
    }

    (*total_len) += extra_len;
    (*pnum_frags) += num_extra_frags;

    return 0;

bad:
    /* Free all nbufs in the chain */
    currnbuf = netbuf;
    while (currnbuf) {
        nextnbuf = adf_nbuf_next(currnbuf);
        if (adf_nbuf_get_frag_paddr_lo(currnbuf, 0)) {
            adf_nbuf_unmap_single(vdev->osdev, currnbuf, ADF_OS_DMA_TO_DEVICE);
        }
        adf_nbuf_free(currnbuf);
        currnbuf = nextnbuf;
    }
    return -1;
}
#endif /* QCA_OL_TX_CACHEDHDR */

void
ol_raw_tx_chained_nbuf_unmap(ol_txrx_pdev_handle pdev, adf_nbuf_t netbuf)
{
    /* It is the responsibility of the caller to ensure that
     * adf_nbuf_next(netbuf) is non-NULL. This is for overall efficiency.
     */

    adf_nbuf_t chnbuf = adf_nbuf_next(netbuf);

    do {
        struct sk_buff *next = adf_nbuf_next(chnbuf);
        adf_nbuf_unmap_single(
                pdev->osdev, (adf_nbuf_t) chnbuf, ADF_OS_DMA_TO_DEVICE);
        adf_nbuf_free(chnbuf);
        chnbuf = next;
    } while (chnbuf);

    adf_nbuf_set_next(netbuf, NULL);
}

inline uint32_t ol_tx_rawmode_nbuf_len(adf_nbuf_t nbuf)
{
    adf_nbuf_t tmpbuf;
    uint32_t len = 0;

    /* Calcuating the length of Chained Raw SKBs */
    if (adf_nbuf_is_chfrag_start(nbuf)) {
        for (tmpbuf = nbuf; tmpbuf != NULL; tmpbuf = tmpbuf->next) {
            len += adf_nbuf_len(tmpbuf);
            if (adf_nbuf_is_chfrag_end(nbuf)) {
                break;
            }
        }
    } else {
        /* Length of single raw SKB */
        len = adf_nbuf_len(nbuf);
    }

    return len;
}

#if PEER_FLOW_CONTROL
/*
 *  This function assumes peer lock is already taken
 *  by the caller function
 */
inline uint32_t
ol_tx_rawmode_enque_pflow_ctl_helper(struct ol_txrx_pdev_t *pdev,
                struct ol_txrx_peer_t *peer, adf_nbuf_t nbuf,
                uint32_t peer_id, u_int8_t tid)
{

    adf_nbuf_t tmpbuf = NULL;
    adf_nbuf_t headbuf = nbuf;
    uint32_t len = 0;

    /* Flow control for unchained Raw packets will be handled in a manner
    similar to non-Raw packets.*/
    if (nbuf->next == NULL) {
        len = adf_nbuf_len(nbuf);
        adf_nbuf_queue_add(&peer->tidq[tid].nbufq, nbuf);
    } else {

        /* Marking start and end SKBs in chain so that while de-queuing,
        SKBs belonging to the same chain can be retrieved and
        serviced under a common Tx descriptor*/
        adf_nbuf_set_chfrag_start(nbuf, 1);

        for (; nbuf != NULL; nbuf = nbuf->next) {
            if (nbuf->next == NULL) {
                adf_nbuf_set_chfrag_end(nbuf, 1);
            }
            tmpbuf = nbuf;
            adf_nbuf_queue_add(&peer->tidq[tid].nbufq, tmpbuf);
            len += adf_nbuf_len(tmpbuf);
        }
        /* resetting the nbuf to point the head SKB*/
        nbuf = headbuf;
    }

    /* Queue count is increased by one even for chained packets
     * since all the skbs in the chain correspond to a single packet */
    return len;
}

/*
 *  This function assumes peer lock is already taken
 *  by the caller function
 */
inline uint32_t
ol_tx_rawmode_deque_pflow_ctl_helper(struct ol_txrx_pdev_t *pdev,
                struct ol_txrx_peer_t *peer, adf_nbuf_t nbuf, u_int8_t tid)
{
    adf_nbuf_t chainbuf = NULL;
    adf_nbuf_t tmpbuf = NULL;
    uint32_t pkt_len = 0;

    if (adf_nbuf_is_chfrag_start(nbuf)) {
        chainbuf = adf_nbuf_queue_remove(&peer->tidq[tid].nbufq);
        if (chainbuf == NULL)
            return pkt_len;
        do {
            tmpbuf = adf_nbuf_queue_remove(&peer->tidq[tid].nbufq);
            if (tmpbuf == NULL)
                return pkt_len;
            pkt_len += adf_nbuf_len(tmpbuf);
            chainbuf->next = tmpbuf;
            chainbuf = chainbuf->next;
        } while(!adf_nbuf_is_chfrag_end(tmpbuf));
        tmpbuf->next = NULL;

    } else {
        nbuf = adf_nbuf_queue_remove(&peer->tidq[tid].nbufq);
        pkt_len = adf_nbuf_len(nbuf);
        nbuf->next = NULL;
    }

    return pkt_len;
}
#endif


#endif /* QCA_OL_SUPPORT_RAWMODE_TXRX */
