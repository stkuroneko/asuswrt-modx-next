/*
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <adf_nbuf.h>         /* adf_nbuf_t, etc. */

#include <ol_txrx_internal.h> /* TXRX_ASSERT1 */
#include <ol_txrx_types.h>    /* pdev stats */
#include <ol_tx_desc.h>       /* ol_tx_desc */
#include <ol_tx_send.h>       /* ol_tx_send */
#include <ol_txrx_api.h>       /* ol_tx_send */
#include <enet.h>


#include <AR900B/hw/datastruct/msdu_link_ext.h>

#define TSO_DBG 0

#ifndef IS_ETHERTYPE
#define IS_ETHERTYPE(_typeOrLen) ((_typeOrLen) >= 0x0600)
#endif

static inline struct ol_tx_tso_desc_t *
ol_tx_tso_desc_alloc(struct ol_txrx_pdev_t *pdev)
{
    struct ol_tx_tso_desc_t *tx_tso_desc = NULL;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    adf_os_spin_lock_bh(&pdev->tx_tso_mutex);
    if (adf_os_likely(pdev->tx_tso_desc.freelist)) {
        tx_tso_desc = &pdev->tx_tso_desc.freelist->tx_tso_desc;
        pdev->tx_tso_desc.freelist = pdev->tx_tso_desc.freelist->next;
        stats->tx.tso.tso_desc_cnt++;
    }
    adf_os_spin_unlock_bh(&pdev->tx_tso_mutex);

    return tx_tso_desc;
}
static inline void
ol_tx_tso_desc_free(struct ol_txrx_pdev_t *pdev,
                    struct ol_tx_tso_desc_t *tx_tso_desc)
{
    struct ol_txrx_stats *stats = &pdev->stats.pub;
    adf_os_spin_lock_bh(&pdev->tx_tso_mutex);
    ((union ol_tx_tso_desc_list_elem_t *) tx_tso_desc)->next =
                                      pdev->tx_tso_desc.freelist;
    pdev->tx_tso_desc.freelist =
                (union ol_tx_tso_desc_list_elem_t *) tx_tso_desc;
    stats->tx.tso.tso_desc_cnt--;
    adf_os_spin_unlock_bh(&pdev->tx_tso_mutex);
}

#define link_segment(head, tail, seg) \
    do { \
        if (head) { \
            adf_nbuf_set_next(tail, seg); \
            tail = seg; \
        } else { \
            head = tail = seg; \
        } \
        adf_nbuf_set_next(tail, NULL); \
    } while (0)

void
ol_tx_tso_failure_cleanup( struct ol_txrx_pdev_t *pdev, adf_nbuf_t segment_list)
{
    adf_nbuf_t tso_header_nbuf;
    struct ol_tx_tso_desc_t *tx_tso_desc=NULL;

    /* The list of network buffers will be freed by the caller at OS Shim */
    /* Only free the additional Header buffer and SW TSO descriptor */

    tso_header_nbuf = adf_nbuf_get_parent(segment_list);
    if (tso_header_nbuf) {
        /* SW TSO Descriptor is stored as part of frag[0]
           inside header buffer */
        tx_tso_desc =
          (struct ol_tx_tso_desc_t *)NBUF_EXTRA_FRAG_VADDR(tso_header_nbuf,0);
        if (tx_tso_desc) ol_tx_tso_desc_free(pdev,tx_tso_desc);
        adf_nbuf_free(tso_header_nbuf);
#if TSO_DBG
        adf_os_print("HOST_TSO::Dropping Pkt->tso_failure_cleanup \n");
#endif
    } else {
#if TSO_DBG
        adf_os_print("HOST_TSO::Dropping Pkt->tso_failure_cleanup  \
                      Header buffer is NULL \n");
#endif
        return;
    }
}

void
ol_tx_tso_desc_display(void *tx_desc)
{
    struct ol_tx_tso_desc_t *tx_tso_desc = (struct ol_tx_tso_desc_t *)tx_desc;

    if(!tx_tso_desc) return;

    adf_os_print("==========TSO Descriptor==============>\n");
    adf_os_print("tx_tso_desc %x \n",(A_UINT32 )tx_tso_desc);
    adf_os_print("HOST_TSO::tso_final_segment %x\n",(A_UINT32 )tx_tso_desc->tso_final_segment);
    adf_os_print("HOST_TSO::ip_hdr_type %x\n",(A_UINT32 )tx_tso_desc->ip_hdr_type);
    if(tx_tso_desc->ip_hdr_type == TSO_IPV4)
        adf_os_print("HOST_TSO::iphdr %x\n",(A_UINT32 )(tx_tso_desc->iphdr));
    else
        adf_os_print("HOST_TSO::ip6hdr %x\n",(A_UINT32 )(tx_tso_desc->iphdr));

    adf_os_print("HOST_TSO::tcphdr %x\n",(A_UINT32 )tx_tso_desc->tcphdr);
    adf_os_print("HOST_TSO::l2_length %x\n",tx_tso_desc->l2_length);
    adf_os_print("HOST_TSO::l3_hdr_length %x\n",tx_tso_desc->l3_hdr_size);
    adf_os_print("HOST_TSO::l2_l3_l4_hdr_size %x\n",tx_tso_desc->l2_l3_l4_hdr_size);
    adf_os_print("HOST_TSO::ref_cnt %x\n",tx_tso_desc->ref_cnt);
}

void
ol_tx_msdu_desc_display(void *msdu_desc)
{
    struct msdu_link_ext *msdu_link_ext_p = (struct msdu_link_ext *)msdu_desc;

    adf_os_print("===========MSDU Link extension descriptor======\n");
    adf_os_print("HOST_TSO::tso_enable %x\n",msdu_link_ext_p->tso_enable);
    adf_os_print("HOST_TSO::tcp_flag %x\n",msdu_link_ext_p->tcp_flag);
    adf_os_print("HOST_TSO::tcp_flag_mask %x\n",msdu_link_ext_p->tcp_flag_mask);
    adf_os_print("HOST_TSO::l2_length %x\n",msdu_link_ext_p->l2_length);
    adf_os_print("HOST_TSO::ip_length %x\n",msdu_link_ext_p->ip_length);
    adf_os_print("HOST_TSO::tcp_seq_number %x\n",msdu_link_ext_p->tcp_seq_number);
    adf_os_print("HOST_TSO::ip_identification %x\n",msdu_link_ext_p->ip_identification);
    adf_os_print("HOST_TSO::ipv4_checksum_en %x\n",msdu_link_ext_p->ipv4_checksum_en);
    adf_os_print("HOST_TSO::udp_over_ipv4_checksum_en %x\n",msdu_link_ext_p->udp_over_ipv4_checksum_en);
    adf_os_print("HOST_TSO::udp_over_ipv6_checksum_en %x\n",msdu_link_ext_p->udp_over_ipv6_checksum_en);
    adf_os_print("HOST_TSO::tcp_over_ipv4_checksum_en %x\n",msdu_link_ext_p->tcp_over_ipv4_checksum_en);
    adf_os_print("HOST_TSO::tcp_over_ipv6_checksum_en %x\n",msdu_link_ext_p->tcp_over_ipv6_checksum_en);
    adf_os_print("HOST_TSO::buf0_ptr_31_0 %x\n",msdu_link_ext_p->buf0_ptr_31_0);
    adf_os_print("HOST_TSO::buf0_len %x\n",msdu_link_ext_p->buf0_len);
    adf_os_print("HOST_TSO::buf1_ptr_31_0 %x\n",msdu_link_ext_p->buf1_ptr_31_0);
    adf_os_print("HOST_TSO::buf1_len %x\n",msdu_link_ext_p->buf1_len);
    adf_os_print("--------> ENd of MSDU Desc \n");
}

static struct ol_tx_tso_desc_t *
ol_tx_tso_sw_desc_alloc_fill(adf_nbuf_t msdu,
                             struct ol_txrx_pdev_t *pdev)
{
    struct ol_tx_tso_desc_t *sw_tso_desc = NULL;
    A_UINT16 typeorlength;
#ifndef TSO_PKT_VALIDATION
    A_UINT16 frag_off;
#endif
    A_UINT8  *ehdr,*datap,*ip6hdr = NULL;
    adf_net_iphdr_t *iphdr = NULL; /* Ip header ptr */
    adf_net_tcphdr_t *tcphdr;      /* Tcp header ptr */

    ehdr = adf_nbuf_data(msdu);
    typeorlength = adf_os_ntohs(*(A_UINT16*)(ehdr + ADF_NET_ETH_LEN * 2));

    if (typeorlength == ETHERTYPE_VLAN) {
        typeorlength = adf_os_ntohs(*(A_UINT16*)(ehdr
                        + ADF_NET_ETH_LEN * 2
                        + ADF_NET_VLAN_LEN));
    }

    if (!IS_ETHERTYPE(typeorlength)) { /* 802.3 header */
        struct llc_snap_hdr_t *llc_hdr =
                (struct llc_snap_hdr_t *)(ehdr + sizeof(struct ethernet_hdr_t));

        typeorlength = (llc_hdr->ethertype[0] << 8) | llc_hdr->ethertype[1];
    }

    if (adf_os_unlikely((typeorlength != ADF_ETH_TYPE_IPV4) &&
                        (typeorlength != ADF_ETH_TYPE_IPV6))) {
        adf_os_print("HOST_TSO::Dropping Pkt->Not an IPV4/V6 packet %d \n",typeorlength);
        return NULL;
    }
    if (typeorlength == ADF_ETH_TYPE_IPV4)  {
        iphdr = (adf_net_iphdr_t *)(adf_nbuf_network_header(msdu));

#ifndef TSO_PKT_VALIDATION
        /* Following checks will be removed after different pkt tests
           for HW validation ?? */
        if (iphdr->ip_proto != IPPROTO_TCP) {
            adf_os_print("HOST_TSO:Dropping Pkt->Not an TCPV4 packet \n");
            return NULL;
        }

        /* XXX If the pkt is an ip fragment, TSO not expected to happen */
        frag_off = adf_os_ntohs(iphdr->ip_frag_off);
        if (frag_off & (IP_MF | IP_OFFSET)) {
            adf_os_print("HOST_TSO::Dropping Pkt->Fragmented IP packet \n");
            return NULL;
        }
#endif
    } else {
        ip6hdr = (A_UINT8 *)(adf_nbuf_network_header(msdu));
    }
    tcphdr = (adf_net_tcphdr_t *)(adf_nbuf_transport_header(msdu));

#ifndef TSO_PKT_VALIDATION
    /* Following checks will be removed after different pkt tests
       for HW validation ?? */
    if (tcphdr->urg || tcphdr->syn || tcphdr->rst || tcphdr->urg_ptr) {
         adf_os_print("HOST_TSO:Dropping Pkt-> has invalid TCP flags syn %d \
                       rst %d urg %d \n",tcphdr->syn,tcphdr->rst,tcphdr->urg);
         return NULL;
    }
#endif

    /* Allocate SW TSO Descriptor for storing parsed info. */
    sw_tso_desc = ol_tx_tso_desc_alloc(pdev);
    if (adf_os_unlikely(!sw_tso_desc)) {
        adf_os_print("HOST_TSO:Dropping Pkt->SW TSO Descriptor allocation \
                      failed \n");
        return NULL;
    }
    adf_os_atomic_init(&sw_tso_desc->ref_cnt);
    if (typeorlength == ADF_ETH_TYPE_IPV4)  {
        sw_tso_desc->iphdr = iphdr;
        sw_tso_desc->ip_hdr_type = TSO_IPV4;
        sw_tso_desc->l3_hdr_size = ((A_UINT8 *)tcphdr - (A_UINT8 *)iphdr);
    } else {
      /* For IPV6 */
        sw_tso_desc->iphdr = ip6hdr;
        sw_tso_desc->ip_hdr_type = TSO_IPV6;
        sw_tso_desc->l3_hdr_size = ((A_UINT8 *)tcphdr - (A_UINT8 *)ip6hdr);
    }
    sw_tso_desc->tcphdr = tcphdr;
    sw_tso_desc->l2_length = ((A_UINT8 *)(sw_tso_desc->iphdr) - ehdr);

    /* tcphdr->doff is number of 4-byte words in tcp header */
    datap = (A_UINT8 *)((A_UINT32 *)tcphdr + tcphdr->doff);
    sw_tso_desc->l2_l3_l4_hdr_size = datap - ehdr;      /* Number of bytes to payload start */

   /* SW TSO descriptor is allocated and filled, ready to be returned */
   return sw_tso_desc;
}

/* Carve a netbuf into multiple pieces. Parse the enet, ipv4/v6 and tcp headers
 * and record relevant information in the tso descriptor structure
 * input: vdev & msdu - Jumbo TCP packet as single network buffer
 * return value -
      On Success : List of segmented network buffers,
      On Failure : return NULL, and free the original network buffer
*/
adf_nbuf_t
ol_tx_tso_segment(ol_txrx_vdev_handle vdev, adf_nbuf_t msdu)
{
    struct ol_txrx_pdev_t *pdev;
    struct ol_tx_tso_desc_t *sw_tso_desc = NULL;

    A_INT32  msdu_len, mss_size;
    A_UINT32 header_paddr_lo;
    A_INT32  payload_offset, payload_len; /* Length of input - headers */
    A_UINT8  *header_vaddr = NULL;

    adf_nbuf_t tso_header_nbuf = NULL,segment = NULL;
    adf_nbuf_t segment_list_head = NULL, segment_list_tail = NULL;

    pdev = vdev->pdev;

    if (adf_os_unlikely(ol_cfg_pkt_type(pdev) != htt_pkt_type_ethernet)) {
        adf_os_print("HOST_TSO:Dropping Pkt->Device Frame Format is not 8023\n");
        goto fail;
    }

    msdu_len = adf_nbuf_len(msdu);
    /* Extract MSS_size received as part of network buffer,
     * set by upper layers of network stack */
    mss_size = adf_nbuf_tcp_tso_size(msdu);
    if(adf_os_unlikely(mss_size <= 0 || msdu_len <=0 )) {
        adf_os_print("HOST_TSO::Dropping Pkt->Invalid Jumbo Buffer length \
                      or Invalid TCP MSS received\n");
        goto fail;
    }
#if TSO_DBG
    adf_os_print("MSS Size %d Pkt Len %d \n",mss_size,msdu_len);
#endif

    tso_header_nbuf = msdu;/*Use the original netbuf recived as header buffer */

    adf_nbuf_map_single(pdev->osdev, tso_header_nbuf, ADF_OS_DMA_TO_DEVICE);

    header_vaddr = adf_nbuf_data(tso_header_nbuf);
    header_paddr_lo = adf_nbuf_get_frag_paddr_lo(tso_header_nbuf,
                                      adf_nbuf_get_num_frags(tso_header_nbuf));

    sw_tso_desc = ol_tx_tso_sw_desc_alloc_fill(msdu,pdev);
    if(adf_os_unlikely(sw_tso_desc == NULL))
        goto fail_unmap;

    payload_offset = sw_tso_desc->l2_l3_l4_hdr_size;
    payload_len = msdu_len - payload_offset;

#if TSO_DBG
    adf_os_print("payload %d offset %d hdr %d mss %d \n",payload_len,payload_offset,sw_tso_desc->l2_l3_l4_hdr_size,mss_size);
#endif
    /* Now, carve the netbuf into multiple pieces */
    while (payload_len > 0) {

       if (payload_len < mss_size) {
            /* Last chunk - include the remainder */
            mss_size = payload_len;
        }

        segment = adf_nbuf_clone(msdu);
        if (adf_os_unlikely(segment == NULL)) {
            /*   This segment is dropped.
             *   Let's continue and try clone for other segments.
             *   Updating following 2 fields to proceed with segmentation
             *   while (....) loop exits without cloning any buffers
             *   incase of system memory exhaust
            */
            payload_offset += mss_size;
            payload_len -= mss_size;
            TXRX_STATS_MSDU_INCR(vdev->pdev, tx.tso.tso_dropped, msdu);
            continue;
        }

        /* Link all cloned skb's with each other for later processing */
        link_segment(segment_list_head, segment_list_tail, segment);

        adf_nbuf_frag_push_head(segment, sw_tso_desc->l2_l3_l4_hdr_size,
                                header_vaddr, header_paddr_lo, 0);

        /* Specify that this just-added fragment is a bytestream,
         * and should not be byte-swapped by the target during download.
         */

        /* Since adf_nbuf_frag_push_head() always copies at the location "0"
         * safe to assume the latest header(l2/l3/l4) frag is at 0 */
        adf_nbuf_set_frag_is_wordstream(segment, 0, 0);

        adf_nbuf_pull_head(segment, payload_offset);    /* Trim from front */
        adf_nbuf_trim_tail(segment, payload_len - mss_size);

        payload_offset += mss_size;
        payload_len -= mss_size;

         /*  maintain refcnt for TSO allocated SW desc
          *  increment once per cloned network buffer */
         adf_os_atomic_inc(&sw_tso_desc->ref_cnt);

         /* Store header nbuf as part of cloned skb for later retrieval */
         adf_nbuf_put_parent(segment,tso_header_nbuf);

        /* DMA mapping for cloned network buffers */
        adf_nbuf_map_single(pdev->osdev, segment, ADF_OS_DMA_TO_DEVICE);
    }

    /* None of the segments are created,
       free the header buffer & TSO descriptor */
    if( adf_os_unlikely(adf_os_atomic_read(&sw_tso_desc->ref_cnt) == 0)) {
        ol_tx_tso_desc_free(pdev,sw_tso_desc);
        goto fail_unmap;
    }

    sw_tso_desc->tso_final_segment = segment;

    /* Link SW TSO Descriptor to Header network buffer for later usage */
    adf_nbuf_frag_push_head(tso_header_nbuf, sizeof(struct ol_tx_tso_desc_t),
                                (char *)sw_tso_desc, 0, 0);

#if TSO_DBG
    ol_tx_tso_desc_display(sw_tso_desc);
#endif
    return segment_list_head;

fail_unmap:
    /* DMA mapping for cloned network buffers */
    adf_nbuf_unmap_single(pdev->osdev, msdu, ADF_OS_DMA_TO_DEVICE);

fail:
    TXRX_STATS_MSDU_INCR(vdev->pdev, tx.tso.tso_dropped, msdu);
    adf_nbuf_free(msdu);
    return NULL;
}

/*  Prepares TX Descriptor per TCP Segment for TSO Packets
 *  Fills MSDU Link Ext descriptor with TSO details */
void
ol_tx_tso_desc_prepare(
    struct ol_txrx_pdev_t *pdev,
    adf_nbuf_t tso_header_nbuf,
    adf_nbuf_t segment,
    struct ol_tx_desc_t *tx_desc,
    struct ol_tx_tso_desc_t *sw_tso_desc)
{
    A_UINT32 frag_offset,data_len;
    A_UINT16 ip_id,v6_opt_len;
    A_UINT8 *header_vaddr;
    A_UINT8 *segment_vaddr,frag_no;
    adf_net_tcphdr_t *tcphdr;
    adf_net_iphdr_t *iphdr;
    struct msdu_link_ext *msdu_link_ext_p;
    A_UINT32 tcp_seq;


#if TSO_DBG
    ol_tx_tso_desc_display(sw_tso_desc);
#endif

#define EXT_P_FLAG_FIN  0x1
#define EXT_P_FLAG_SYN  0x2
#define EXT_P_FLAG_RST  0x4
#define EXT_P_FLAG_PSH  0x8
#define EXT_P_FLAG_ACK  0x10
#define EXT_P_FLAG_URG  0x20
#define EXT_P_FLAG_ECE  0x40
#define EXT_P_FLAG_CWR  0x80
#define EXT_P_FLAG_NS   0x100
#define IPV6_STD_HDR_SIZE   0x28
#define TSO_TCP_FLAG_MASK   0x1ff /* All 1's for 9 of TCP flags */
    tcphdr = sw_tso_desc->tcphdr;
    iphdr = sw_tso_desc->iphdr;

    /* Now, fill in the msdu_link_ext structure */
    msdu_link_ext_p = (struct msdu_link_ext *)tx_desc->htt_frag_desc;

    msdu_link_ext_p->tso_enable = 1;
    msdu_link_ext_p->tcp_flag = 0;

    if (tcphdr->fin && segment == sw_tso_desc->tso_final_segment) {
        /* Set fin in last segment, if set in original */
        msdu_link_ext_p->tcp_flag |= EXT_P_FLAG_FIN;
    }
    if (tcphdr->psh) {
        msdu_link_ext_p->tcp_flag |= EXT_P_FLAG_PSH;
    }
    if (tcphdr->ack) {
        msdu_link_ext_p->tcp_flag |= EXT_P_FLAG_ACK;
    }
    msdu_link_ext_p->tcp_flag_mask = TSO_TCP_FLAG_MASK;
    msdu_link_ext_p->l2_length = sw_tso_desc->l2_length;


    frag_no = adf_nbuf_get_num_frags(segment);
    data_len = adf_nbuf_get_frag_len(segment,frag_no);

    /* Fill IP Length and ip_id only incase of IPV4 */
    if(sw_tso_desc->ip_hdr_type == TSO_IPV4)
    {
        iphdr = (adf_net_iphdr_t *)sw_tso_desc->iphdr;
        /* IPV4 Length includes data length + l3 + l4 */
        msdu_link_ext_p->ip_length = data_len + sw_tso_desc->l2_l3_l4_hdr_size - sw_tso_desc->l2_length;
        msdu_link_ext_p->ip_identification = adf_os_ntohs(iphdr->ip_id);
        iphdr->ip_id = adf_os_htons(msdu_link_ext_p->ip_identification + 1);

        msdu_link_ext_p->ipv4_checksum_en = 1;
        msdu_link_ext_p->tcp_over_ipv4_checksum_en = 1;
    }
    else
    {
        /* IPV6 Length includes data length + l4 */
        /* IPV6 length should include IPV6 ext. header length also, extracting as follows.... */
        v6_opt_len = sw_tso_desc->l3_hdr_size - IPV6_STD_HDR_SIZE;
        msdu_link_ext_p->ip_length = data_len + sw_tso_desc->l2_l3_l4_hdr_size-sw_tso_desc->l2_length - sw_tso_desc->l3_hdr_size + v6_opt_len;
        msdu_link_ext_p->tcp_over_ipv6_checksum_en = 1;
    }

    header_vaddr = adf_nbuf_get_frag_vaddr(tso_header_nbuf, adf_nbuf_get_num_frags(tso_header_nbuf) - 1);
    segment_vaddr = adf_nbuf_get_frag_vaddr(segment, adf_nbuf_get_num_frags(segment) - 1);

    /* compute tcp_seq for this fragment
     * this assumes that the header and all data segments of the netbuf
     * are virtually contiguous.
     * Need to review and modify once the support for non-contiguous physical memory(map_sg) for jumbo frame is added
     */
    tcp_seq = adf_os_ntohl(tcphdr->seq);
    frag_offset = segment_vaddr - header_vaddr - sw_tso_desc->l2_l3_l4_hdr_size;
    msdu_link_ext_p->tcp_seq_number = tcp_seq + frag_offset;

#if TSO_DBG
    adf_os_print("Seq No. %x \n",msdu_link_ext_p->tcp_seq_number);
#endif

    /* Decrement ref_cnt in SW TSO Descriptor since
     * one TCP segment has already used it and no longer requires it */
    if (adf_os_atomic_dec_and_test(&sw_tso_desc->ref_cnt)) {
        /* Free the header skb and SW TSO descriptor
         * since this is the last segment, No one else requires it further */
#if TSO_DBG
        adf_os_print("Last Segment Transfer, Freeing header buffer %x  \
                      and TX TSo Descriptor %x -----\n",tso_header_nbuf,sw_tso_desc);
#endif

        adf_nbuf_free(tso_header_nbuf);
        ol_tx_tso_desc_free(pdev, sw_tso_desc);
    }
#if TSO_DBG
    ol_tx_msdu_desc_display(msdu_link_ext_p);
#endif
    return;
}

void
ol_tx_print_tso_stats(
    ol_txrx_vdev_handle vdev)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    adf_os_print("++++++++++ TSO STATISTICS +++++++++++\n");
    adf_os_print("TSO TX Pkts       : %lu\n", stats->tx.tso.tso_pkts.pkts);
    adf_os_print("TSO TX Bytes      : %lu\n", stats->tx.tso.tso_pkts.bytes);
    adf_os_print("Non-TSO TX Pkts   : %lu\n", stats->tx.tso.non_tso_pkts.pkts);
    adf_os_print("Non-TSO TX Bytes  : %lu\n", stats->tx.tso.non_tso_pkts.bytes);
    adf_os_print("TSO Dropped Pkts  : %lu\n", stats->tx.tso.tso_dropped.pkts);
    adf_os_print("TSO Dropped Bytes : %lu\n", stats->tx.tso.tso_dropped.bytes);
    adf_os_print("TSO Desc Total %d In Use : %d\n", pdev->tx_tso_desc.pool_size, \
                                             stats->tx.tso.tso_desc_cnt);
}

void
ol_tx_rst_tso_stats(ol_txrx_vdev_handle vdev)
{
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    struct ol_txrx_stats *stats = &pdev->stats.pub;

    adf_os_print(".....Resetting TSO Stats \n");
    /* Tx */
    stats->tx.tso.tso_pkts.pkts = 0;
    stats->tx.tso.tso_pkts.bytes = 0;
    stats->tx.tso.non_tso_pkts.pkts = 0;
    stats->tx.tso.non_tso_pkts.bytes = 0;
    stats->tx.tso.tso_dropped.pkts = 0;
    stats->tx.tso.tso_dropped.bytes = 0;

    printk("tso_stats %d %d %d %d \n",stats->tx.tso.tso_pkts.pkts,stats->tx.tso.tso_pkts.bytes,stats->tx.tso.non_tso_pkts.pkts,stats->tx.tso.non_tso_pkts.bytes);
}

void
tso_release_parent_tso_desc(ol_txrx_vdev_handle vdev, adf_nbuf_t seg_msdu)
{
    adf_nbuf_t tso_header_nbuf;
    struct ol_tx_tso_desc_t *tx_tso_desc=NULL;
    struct ol_txrx_pdev_t *pdev;

    pdev = vdev->pdev;

    /* free the additional Header buffer and SW TSO descriptor */

    tso_header_nbuf = adf_nbuf_get_parent(seg_msdu);
    if (tso_header_nbuf) {
        /* SW TSO Descriptor is stored as part of frag[0]
           inside header buffer */
        tx_tso_desc =
          (struct ol_tx_tso_desc_t *)NBUF_EXTRA_FRAG_VADDR(tso_header_nbuf,0);
        if(tx_tso_desc)
        {
            /* Decrement ref_cnt in SW TSO Descriptor since
             * one TCP segment hit error and is going to be freed */
            if (adf_os_atomic_dec_and_test(&tx_tso_desc->ref_cnt)) {
                /* Free the header skb and SW TSO descriptor
                 * since this is the last segment, No one else requires it further */
                adf_nbuf_free(tso_header_nbuf);
                ol_tx_tso_desc_free(pdev, tx_tso_desc);
            }
        }
    }
}

inline int
ol_tx_tso_process_skb(ol_txrx_vdev_handle vdev,adf_nbuf_t msdu)
{
    adf_nbuf_t msdu_list;
    int tid_q_map;
    struct ol_txrx_pdev_t *pdev = vdev->pdev;
    uint8_t tid;

    msdu = adf_nbuf_unshare(msdu);
    if (msdu == NULL)
        return 1;

    TXRX_STATS_MSDU_INCR(vdev->pdev, tx.tso.tso_pkts, msdu);

    /* Following function creates Multiple buffers (one per segment) and linked with each other
     * for further TX processing,
     * Original buffer used as header buffer, freed at later stage of TX
     * If NULL is returned, error encountered in segmentation
     * else proceed processing of individual TCP segments */

    msdu_list = ol_tx_tso_segment(vdev, msdu);

    if (adf_os_unlikely(!msdu_list))  {
        adf_os_print(".....Error in TSO Segmentation \n");
        return 0;
    }

    /* Inject the TCP segments into regular TX Data path */
    while(msdu_list) {
        adf_nbuf_t next;
        tid = HTT_TX_EXT_TID_INVALID;
        next = adf_nbuf_next(msdu_list);
        msdu_list->next = NULL;
#if PEER_FLOW_CONTROL
        tid_q_map = ol_tx_get_tid_override_queue_mapping(pdev, netbuf);
        if (tid_q_map >= 0) {
            tid = tid_q_map;
        }
        if (ol_tx_ll_fast(vdev,&msdu_list,1,HTT_INVALID_PEER,tid))
#else
        if (ol_tx_ll_fast(vdev,&msdu_list,1))
#endif
        {
           /* Decrement ref cnt for parent skb & sw tso desc for this segment,
            * which is going to be dropped */
           tso_release_parent_tso_desc(vdev, msdu_list);
           adf_nbuf_free(msdu_list);
        }
        msdu_list = next;
    }
    return 0;
}

