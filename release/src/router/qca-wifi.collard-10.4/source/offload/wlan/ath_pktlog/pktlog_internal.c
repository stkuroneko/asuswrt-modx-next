/*
 * Copyright (c) 2013-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef REMOVE_PKT_LOG
#include "ol_txrx_types.h"
#include "ol_htt_tx_api.h"
#include "ol_tx_desc.h"
#include "adf_os_mem.h"
#include "htt.h"
#include "htt_internal.h"
#include "pktlog_ac_i.h"
#include <dbglog_host.h>
#include "pktlog_ac_fmt.h"
#include "ieee80211.h"
#include <pktlog_fmt.h>
#include <linux_remote_pktlog.h>
//#include "ratectrl_11ac.h"

#if QCA_PARTNER_DIRECTLINK_RX
#define QCA_PARTNER_DIRECTLINK_PKTLOG_INTERNAL 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_PKTLOG_INTERNAL
#endif

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif

#define TX_DESC_ID_LOW_MASK 0xffff
#define TX_DESC_ID_LOW_SHIFT 0
#define TX_DESC_ID_HIGH_MASK 0xffff0000
#define TX_DESC_ID_HIGH_SHIFT 16
char dbglog_print_buffer[1024];
void
pktlog_getbuf_intsafe(struct ath_pktlog_arg *plarg)
{
    struct ath_pktlog_buf *log_buf;
    int32_t buf_size;
    ath_pktlog_hdr_t *log_hdr;
    int32_t cur_wr_offset;
    char *log_ptr;
    struct ath_pktlog_info *pl_info = NULL;
    u_int16_t log_type = 0;
    size_t log_size = 0;
    uint32_t flags = 0;
    size_t pktlog_hdr_size;
#if REMOTE_PKTLOG_SUPPORT
    ol_pktlog_dev_t *pl_dev = NULL; /* pointer to pktlog dev */
    struct ol_ath_softc_net80211 *scn; /* pointer to scn object */
    struct pktlog_remote_service *service = NULL; /* pointer to remote packet service */
#endif

    if(!plarg) {
        printk("Invalid parg in %s\n", __FUNCTION__);
        return;
    }

    pl_info  = plarg->pl_info;
    log_type = plarg->log_type;
    log_size = plarg->log_size;
    flags    = plarg->flags;
    log_buf  = pl_info->buf;
    pktlog_hdr_size = plarg->pktlog_hdr_size;

#if REMOTE_PKTLOG_SUPPORT
    scn =  (struct ol_ath_softc_net80211 *)pl_info->scn;
    pl_dev   = scn->pl_dev;
    service = &pl_dev->rpktlog_svc;
#endif
    if(!log_buf) {
        printk("Invalid log_buf in %s\n", __FUNCTION__);
        return;
    }

#if REMOTE_PKTLOG_SUPPORT

    /* remote Logging */
    if (service->running) {

        /* if no connection do not fill buffer */
        if (!service->connect_done) {
            plarg->buf = NULL;
            return;
        }

        /*
         * if size of header+log_size+rlog_write_offset > max allocated size
         * check read pointer (header+logsize) < rlog_read_index; then
         * mark is_wrap = 1 and reset max size to rlog_write_index.
         * reset rlog_write_index = 0
         * starting giving buffer untill we reach (header+logzies <= rlog_read_index).
         * # is_wrap should be reset by read thread
         */

        if (!pl_info->is_wrap) { /* no wrap */

               /* data can not fit to buffer - wrap condition */
            if ((pl_info->rlog_write_index+(log_size + pl_dev->pktlog_hdr_size)) > pl_info->buf_size) {
                /* required size < read_index */
                if((log_size + pl_dev->pktlog_hdr_size) < pl_info->rlog_read_index) {
                    pl_info->rlog_max_size = pl_info->rlog_write_index;
                    pl_info->is_wrap = 1;
                    pl_info->rlog_write_index = 0;
                } else {
#if REMOTE_PKTLOG_DEBUG
                    printk("No Space Untill we read \n");
                    printk("ReadIndex: %d WriteIndex:%d MaxIndex:%d \n", pl_info->rlog_read_index
                            , pl_info->rlog_write_index
                            , pl_info->rlog_max_size);
#endif
                    service->missed_records++;
                    plarg->buf = NULL;
                    return;
                }
            }
        } else {  /* write index is wrapped & we should not over write previous writes untill we read*/
            if((pl_info->rlog_write_index+(log_size + pl_dev->pktlog_hdr_size)) >= pl_info->rlog_read_index) {
#if REMOTE_PKTLOG_DEBUG
                printk("No Space Untill we read \n");
                printk("ReadIndex: %d WriteIndex:%d MaxIndex:%d \n", pl_info->rlog_read_index
                        , pl_info->rlog_write_index
                        , pl_info->rlog_max_size);
#endif
                service->missed_records++;
                plarg->buf = NULL;
                return;
            }
        }

        cur_wr_offset = pl_info->rlog_write_index;

        log_hdr =
            (ath_pktlog_hdr_t *) (log_buf->log_data + cur_wr_offset);

        log_hdr->log_type = log_type;
        log_hdr->flags = flags;
        log_hdr->size = (u_int16_t)log_size;
        log_hdr->missed_cnt = plarg->missed_cnt;
        log_hdr->timestamp = plarg->timestamp;
#ifdef CONFIG_AR900B_SUPPORT
        log_hdr->type_specific_data = plarg->type_specific_data;
#endif
        cur_wr_offset += sizeof(*log_hdr);

        log_ptr = &(log_buf->log_data[cur_wr_offset]);

        cur_wr_offset += log_hdr->size;

        /* Update the write offset */
        pl_info->rlog_write_index = cur_wr_offset;
        plarg->buf = log_ptr;
    } else { /* Regular Packet log */
#endif
    buf_size = pl_info->buf_size;
    cur_wr_offset = log_buf->wr_offset;
    /* Move read offset to the next entry if there is a buffer overlap */
    if (log_buf->rd_offset >= 0) {
        if ((cur_wr_offset <= log_buf->rd_offset)
                && (cur_wr_offset + pktlog_hdr_size) >
                log_buf->rd_offset) {
            PKTLOG_MOV_RD_IDX_HDRSIZE(log_buf->rd_offset, log_buf, buf_size, pktlog_hdr_size);
        }
    } else {
        log_buf->rd_offset = cur_wr_offset;
    }

    log_hdr =
        (ath_pktlog_hdr_t *) (log_buf->log_data + cur_wr_offset);
    log_hdr->log_type = log_type;
    log_hdr->flags = flags;
    log_hdr->size = (u_int16_t)log_size;
    log_hdr->missed_cnt = plarg->missed_cnt;
    log_hdr->timestamp = plarg->timestamp;
#ifdef CONFIG_AR900B_SUPPORT
    log_hdr->type_specific_data = plarg->type_specific_data;
#endif

    cur_wr_offset += pktlog_hdr_size;

    if ((buf_size - cur_wr_offset) < log_size) {
        while ((cur_wr_offset <= log_buf->rd_offset)
                && (log_buf->rd_offset < buf_size)) {
            PKTLOG_MOV_RD_IDX_HDRSIZE(log_buf->rd_offset, log_buf, buf_size, pktlog_hdr_size);
        }
        cur_wr_offset = 0;
    }

    while ((cur_wr_offset <= log_buf->rd_offset)
            && (cur_wr_offset + log_size) > log_buf->rd_offset) {
        PKTLOG_MOV_RD_IDX_HDRSIZE(log_buf->rd_offset, log_buf, buf_size, pktlog_hdr_size);
    }

    log_ptr = &(log_buf->log_data[cur_wr_offset]);

    cur_wr_offset += log_hdr->size;

    log_buf->wr_offset =
        ((buf_size - cur_wr_offset) >=
         pktlog_hdr_size) ? cur_wr_offset : 0;

    plarg->buf = log_ptr;
#if REMOTE_PKTLOG_SUPPORT
    }
#endif

}

char *
pktlog_getbuf(ol_pktlog_dev_t *pl_dev,
                struct ath_pktlog_info *pl_info,
                size_t log_size,
                ath_pktlog_hdr_t *pl_hdr)
{
    struct ath_pktlog_arg plarg;
    uint8_t flags = 0;
    plarg.pl_info = pl_info;
    plarg.log_type = pl_hdr->log_type;
    plarg.log_size = log_size;
    plarg.flags = pl_hdr->flags;
    plarg.missed_cnt = pl_hdr->missed_cnt;
    plarg.timestamp = pl_hdr->timestamp;
    plarg.pktlog_hdr_size = pl_dev->pktlog_hdr_size;
    plarg.buf = NULL;
#ifdef CONFIG_AR900B_SUPPORT
    plarg.type_specific_data = pl_hdr->type_specific_data;
#endif

    if(flags & PHFLAGS_INTERRUPT_CONTEXT) {
        /*
         * We are already in interupt context, no need to make it intsafe
         * call the function directly.
         */
        pktlog_getbuf_intsafe(&plarg);
    }
    else {
        PKTLOG_LOCK(pl_info);
        OS_EXEC_INTSAFE(pl_dev->sc_osdev, pktlog_getbuf_intsafe, &plarg);
        PKTLOG_UNLOCK(pl_info);
    }

    return plarg.buf;
}

static struct txctl_frm_hdr frm_hdr;

static void process_ieee_hdr(void *data)
{
    uint8_t dir;
    struct ieee80211_frame *wh = (struct ieee80211_frame *)(data);
    frm_hdr.framectrl = *(u_int16_t *)(wh->i_fc);
    frm_hdr.seqctrl   = *(u_int16_t *)(wh->i_seq);
    dir = (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK);
    if(dir == IEEE80211_FC1_DIR_TODS) {
        frm_hdr.bssid_tail = (wh->i_addr1[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr1[IEEE80211_ADDR_LEN-1]);
        frm_hdr.sa_tail    = (wh->i_addr2[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr2[IEEE80211_ADDR_LEN-1]);
        frm_hdr.da_tail    = (wh->i_addr3[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr3[IEEE80211_ADDR_LEN-1]);
    }
    else if(dir == IEEE80211_FC1_DIR_FROMDS) {
        frm_hdr.bssid_tail = (wh->i_addr2[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr2[IEEE80211_ADDR_LEN-1]);
        frm_hdr.sa_tail    = (wh->i_addr3[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr3[IEEE80211_ADDR_LEN-1]);
        frm_hdr.da_tail    = (wh->i_addr1[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr1[IEEE80211_ADDR_LEN-1]);
    }
    else {
        frm_hdr.bssid_tail = (wh->i_addr3[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr3[IEEE80211_ADDR_LEN-1]);
        frm_hdr.sa_tail    = (wh->i_addr2[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr2[IEEE80211_ADDR_LEN-1]);
        frm_hdr.da_tail    = (wh->i_addr1[IEEE80211_ADDR_LEN-2] << 8) |
                             (wh->i_addr1[IEEE80211_ADDR_LEN-1]);
    }
}

/* process_text_info: this function forms the packet log evet of type debug print
 * from the text
 * */
A_STATUS
process_text_info(void *pdev, char *text)
{
    ol_pktlog_dev_t *pl_dev;
    ath_pktlog_hdr_t pl_hdr;
    size_t log_size;
    struct ath_pktlog_info *pl_info;
    struct ath_pktlog_dbg_print dbg_print_s;

    if (!pdev) {
        adf_os_print("Invalid pdev in %s\n", __FUNCTION__);
        return A_ERROR;
    }

    pl_dev = ((struct ol_txrx_pdev_t *) pdev)->pl_dev;
    pl_info = pl_dev->pl_info;

    if (!pl_info) {
        /* Invalid pl_info */
        return A_ERROR;
    }

    if ((pl_info->log_state & ATH_PKTLOG_DBG_PRINT) == 0) {
        /* log text not enabled */
        return A_ERROR;
    }

    /*
     *      * Makes the short words (16 bits) portable b/w little endian
     *      * and big endian
     *      */
    pl_hdr.flags = 1;
    pl_hdr.flags |= PHFLAGS_INTERRUPT_CONTEXT;
    pl_hdr.missed_cnt =  0;
    pl_hdr.log_type =  PKTLOG_TYPE_DBG_PRINT;
    pl_hdr.size =  strlen(text);
    pl_hdr.timestamp = 0;
#ifdef CONFIG_AR900B_SUPPORT
    pl_hdr.type_specific_data = 0;
#endif

    log_size = strlen(text);

    dbg_print_s.dbg_print = (void *)
            pktlog_getbuf(pl_dev, pl_info, log_size, &pl_hdr);

    if(!dbg_print_s.dbg_print) {
        return A_ERROR;
    }

    adf_os_mem_copy(dbg_print_s.dbg_print, text, log_size);

    return A_OK;
}

A_STATUS
process_tx_msdu_info_ar9888 (struct ol_txrx_pdev_t *txrx_pdev,
                             void *data, ath_pktlog_hdr_t *pl_hdr)
{
    ol_pktlog_dev_t *pl_dev = NULL;
    struct ath_pktlog_info *pl_info = NULL;
    uint32_t i = 0;
    uint32_t *htt_tx_desc = NULL;
    size_t log_size = 0;
    struct ol_tx_desc_t *tx_desc = NULL;
    uint8_t msdu_id_offset = 0;
    uint16_t tx_desc_id = 0;
    u_int8_t *addr = NULL, *vap_addr = NULL;
    u_int8_t vdev_id = 0;
    adf_nbuf_t netbuf = NULL;
    u_int32_t len = 0;
    uint32_t *msdu_id_info = NULL;
    uint32_t *msdu_id = NULL;
    static struct ath_pktlog_msdu_info_ar9888 pl_msdu_info;
    /*
     *  Must include to process different types
     *  TX_CTL, TX_STATUS, TX_MSDU_ID, TX_FRM_HDR
     */
    pl_dev = txrx_pdev->pl_dev;
    pl_info = pl_dev->pl_info;
    msdu_id_offset = pl_dev->msdu_id_offset;

    msdu_id_info = (uint32_t *) ((void *)data + pl_dev->pktlog_hdr_size);
    msdu_id = (uint32_t *)((char *)msdu_id_info + msdu_id_offset);


    pl_msdu_info.num_msdu = *msdu_id_info;
    pl_msdu_info.priv_size = sizeof(uint32_t) * pl_msdu_info.num_msdu +
                             sizeof(uint32_t);
    log_size = sizeof(pl_msdu_info.priv);

    for (i = 0; i < pl_msdu_info.num_msdu; i++) {
        /*
         *  Handle big endianess
         *  Increment msdu_id once after retrieving
         *  lower 16 bits and uppper 16 bits
         */
        if (!(i % 2)) {
            tx_desc_id = ((*msdu_id & TX_DESC_ID_LOW_MASK)
                    >> TX_DESC_ID_LOW_SHIFT);
        } else {
            tx_desc_id = ((*msdu_id & TX_DESC_ID_HIGH_MASK)
                    >> TX_DESC_ID_HIGH_SHIFT);
            msdu_id += 1;
        }
        tx_desc = ol_tx_desc_find(txrx_pdev, tx_desc_id);
        adf_os_assert(tx_desc);
        netbuf = tx_desc->netbuf;
        adf_os_assert(netbuf);
        htt_tx_desc = (uint32_t *) tx_desc->htt_tx_desc;
        adf_os_assert(htt_tx_desc);
        if(!(pl_hdr->flags & (1 << PKTLOG_FLG_FRM_TYPE_CLONE_S))){
            adf_nbuf_peek_header(netbuf, &addr, &len);
            adf_os_assert(addr);
            if (len < (2 * IEEE80211_ADDR_LEN)) {
                adf_os_print("TX frame does not have a valid address %d \n",len);
                return -1;
            }
            /* Adding header information for the TX data frames */
            frm_hdr.da_tail    = (addr[IEEE80211_ADDR_LEN-2] << 8) |
                (addr[IEEE80211_ADDR_LEN-1]);
            frm_hdr.sa_tail    = (addr[2 * IEEE80211_ADDR_LEN-2] << 8) |
                (addr[2 * IEEE80211_ADDR_LEN-1]);

            vdev_id = (u_int8_t)(*(htt_tx_desc + HTT_TX_VDEV_ID_WORD) >>
                    HTT_TX_VDEV_ID_SHIFT) &
                HTT_TX_VDEV_ID_MASK;
            vap_addr = ol_ath_vap_get_myaddr((struct ol_ath_softc_net80211 *)pl_dev->scn, vdev_id);

            if (vap_addr) {
                frm_hdr.bssid_tail = (vap_addr[IEEE80211_ADDR_LEN-2] << 8) |
                    (vap_addr[IEEE80211_ADDR_LEN-1]);
            } else {
                frm_hdr.bssid_tail = 0x0000;
            }
            pl_msdu_info.priv.msdu_len[i] = *(htt_tx_desc +
                    HTT_TX_MSDU_LEN_DWORD)
                & HTT_TX_MSDU_LEN_MASK;
        } else {
            /* This is for cloned packet init with some constants*/
            frm_hdr.da_tail = 0x0000;
            frm_hdr.sa_tail = 0x0000;
            frm_hdr.bssid_tail = 0x0000;
            pl_msdu_info.priv.msdu_len[i] = 200;
        }
    }

    /*
     * Add more information per MSDU
     * e.g., protocol information
     */
    pl_msdu_info.ath_msdu_info = pktlog_getbuf(pl_dev, pl_info,
            log_size, pl_hdr);
    if (pl_msdu_info.ath_msdu_info == NULL) {
        return A_ERROR;
    }
    adf_os_mem_copy((void *)&pl_msdu_info.priv.msdu_id_info,
            ((void *)data + pl_dev->pktlog_hdr_size),
            sizeof(pl_msdu_info.priv.msdu_id_info));

    adf_os_mem_copy(pl_msdu_info.ath_msdu_info, &pl_msdu_info.priv,
            sizeof(pl_msdu_info.priv));

    return A_OK;
}

A_STATUS
process_tx_msdu_info_ar900b (struct ol_txrx_pdev_t *txrx_pdev,
                             void *data, ath_pktlog_hdr_t *pl_hdr)
{
    ol_pktlog_dev_t *pl_dev = NULL;
    struct ath_pktlog_info *pl_info = NULL;
    uint32_t i = 0;
    uint32_t *htt_tx_desc = NULL;
    size_t log_size = 0;
    struct ol_tx_desc_t *tx_desc = NULL;
    uint8_t msdu_id_offset = 0;
    uint16_t tx_desc_id = 0;
    u_int8_t *addr = NULL, *vap_addr = NULL;
    u_int8_t vdev_id = 0;
    adf_nbuf_t netbuf = NULL;
    u_int32_t len = 0;
    uint32_t *msdu_id_info = NULL;
    uint32_t *msdu_id = NULL;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    uint8_t *pl_metadata_addr = NULL;
#endif
    static struct ath_pktlog_msdu_info_ar900b pl_msdu_info;
    /*
     *  Must include to process different types
     *  TX_CTL, TX_STATUS, TX_MSDU_ID, TX_FRM_HDR
     */
    pl_dev = txrx_pdev->pl_dev;
    pl_info = pl_dev->pl_info;
    msdu_id_offset = pl_dev->msdu_id_offset;

    msdu_id_info = (uint32_t *) ((void *)data + pl_dev->pktlog_hdr_size);
    msdu_id = (uint32_t *)((char *)msdu_id_info + msdu_id_offset);


    pl_msdu_info.num_msdu = *msdu_id_info;
    pl_msdu_info.priv_size = sizeof(uint32_t) * pl_msdu_info.num_msdu +
                             sizeof(uint32_t);
    log_size = sizeof(pl_msdu_info.priv);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (txrx_pdev->nss_wifiol_ctx) {
        pl_metadata_addr = (char *)data + 116;
    }
#endif

    for (i = 0; i < pl_msdu_info.num_msdu; i++) {
        /*
         *  Handle big endianess
         *  Increment msdu_id once after retrieving
         *  lower 16 bits and uppper 16 bits
         */
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (txrx_pdev->nss_wifiol_ctx) {
            struct nss_wifi_pl_metadata *pl_metadata = (struct nss_wifi_pl_metadata *)(pl_metadata_addr);
            if(!(pl_hdr->flags & (1 << PKTLOG_FLG_FRM_TYPE_CLONE_S))) {
                len = pl_metadata->len;
                if (len < (2 * IEEE80211_ADDR_LEN)) {
                    adf_os_print("TX frame does not have a valid address %d \n",len);
                    return -1;
                }

                /* Adding header information for the TX data frames */
                frm_hdr.da_tail = pl_metadata->da_tail;
                frm_hdr.sa_tail = pl_metadata->sa_tail;

                vdev_id = pl_metadata->vdev_id;
                vap_addr = ol_ath_vap_get_myaddr((struct ol_ath_softc_net80211 *)pl_dev->scn, vdev_id);
                if (vap_addr) {
                    frm_hdr.bssid_tail = (vap_addr[IEEE80211_ADDR_LEN-2] << 8) |
                        (vap_addr[IEEE80211_ADDR_LEN-1]);
                } else {
                    frm_hdr.bssid_tail = 0x0000;
                }

                pl_msdu_info.priv.msdu_len[i] = pl_metadata->msdu_len;
                pl_metadata_addr += (sizeof(struct nss_wifi_pl_metadata));
            } else {
                /* This is for cloned packet init with some constants*/
                frm_hdr.da_tail = 0x0000;
                frm_hdr.sa_tail = 0x0000;
                frm_hdr.bssid_tail = 0x0000;
                pl_msdu_info.priv.msdu_len[i] = 200;
            }
        } else
#endif
        {
#ifdef BIG_ENDIAN_HOST
            if ((i % 2)) {
                tx_desc_id = ((*msdu_id & TX_DESC_ID_LOW_MASK)
                        >> TX_DESC_ID_LOW_SHIFT);
                msdu_id += 1;
            } else {
                tx_desc_id = ((*msdu_id & TX_DESC_ID_HIGH_MASK)
                        >> TX_DESC_ID_HIGH_SHIFT);
            }

#else
            if (!(i % 2)) {
                tx_desc_id = ((*msdu_id & TX_DESC_ID_LOW_MASK)
                        >> TX_DESC_ID_LOW_SHIFT);
            } else {
                tx_desc_id = ((*msdu_id & TX_DESC_ID_HIGH_MASK)
                        >> TX_DESC_ID_HIGH_SHIFT);
                msdu_id += 1;
            }
#endif
            tx_desc = ol_tx_desc_find(txrx_pdev, tx_desc_id);
            adf_os_assert(tx_desc);
            netbuf = tx_desc->netbuf;
            adf_os_assert(netbuf);
            htt_tx_desc = (uint32_t *) tx_desc->htt_tx_desc;
            adf_os_assert(htt_tx_desc);
            if(!(pl_hdr->flags & (1 << PKTLOG_FLG_FRM_TYPE_CLONE_S))){
                adf_nbuf_peek_header(netbuf, &addr, &len);
                adf_os_assert(addr);
                if (len < (2 * IEEE80211_ADDR_LEN)) {
                    adf_os_print("TX frame does not have a valid address %d \n",len);
                    return -1;
                }
                /* Adding header information for the TX data frames */
                frm_hdr.da_tail    = (addr[IEEE80211_ADDR_LEN-2] << 8) |
                    (addr[IEEE80211_ADDR_LEN-1]);
                frm_hdr.sa_tail    = (addr[2 * IEEE80211_ADDR_LEN-2] << 8) |
                    (addr[2 * IEEE80211_ADDR_LEN-1]);

                vdev_id = (u_int8_t)(*(htt_tx_desc + HTT_TX_VDEV_ID_WORD) >>
                        HTT_TX_VDEV_ID_SHIFT) &
                    HTT_TX_VDEV_ID_MASK;
                vap_addr = ol_ath_vap_get_myaddr((struct ol_ath_softc_net80211 *)pl_dev->scn, vdev_id);

                if (vap_addr) {
                    frm_hdr.bssid_tail = (vap_addr[IEEE80211_ADDR_LEN-2] << 8) |
                        (vap_addr[IEEE80211_ADDR_LEN-1]);
                } else {
                    frm_hdr.bssid_tail = 0x0000;
                }
                pl_msdu_info.priv.msdu_len[i] = *(htt_tx_desc +
                        HTT_TX_MSDU_LEN_DWORD)
                    & HTT_TX_MSDU_LEN_MASK;

            } else {
                /* This is for cloned packet init with some constants*/
                frm_hdr.da_tail = 0x0000;
                frm_hdr.sa_tail = 0x0000;
                frm_hdr.bssid_tail = 0x0000;
                pl_msdu_info.priv.msdu_len[i] = 200;
            }
        }
    }

    /*
     * Add more information per MSDU
     * e.g., protocol information
     */
    pl_msdu_info.ath_msdu_info = pktlog_getbuf(pl_dev, pl_info,
            log_size, pl_hdr);
    if (pl_msdu_info.ath_msdu_info == NULL) {
        return A_ERROR;
    }
    adf_os_mem_copy((void *)&pl_msdu_info.priv.msdu_id_info,
            ((void *)data + pl_dev->pktlog_hdr_size),
            sizeof(pl_msdu_info.priv.msdu_id_info));
    adf_os_mem_copy(pl_msdu_info.ath_msdu_info, &pl_msdu_info.priv,
            sizeof(pl_msdu_info.priv));

    return A_OK;
}



A_STATUS
process_tx_info(struct ol_txrx_pdev_t *txrx_pdev, void *data,
                        ath_pktlog_hdr_t *pl_hdr)
{
    ol_pktlog_dev_t *pl_dev;
    struct ath_pktlog_info *pl_info;
    void *pl;

    /*
     *  Must include to process different types
     *  TX_CTL, TX_STATUS, TX_MSDU_ID, TX_FRM_HDR
     */

    pl_dev = txrx_pdev->pl_dev;
    pl_info = pl_dev->pl_info;

    if(pl_hdr->log_type == PKTLOG_TYPE_TX_FRM_HDR) {
        /* Valid only for the TX CTL */
        process_ieee_hdr(data + pl_dev->pktlog_hdr_size);
    }

    if (pl_hdr->log_type == PKTLOG_TYPE_TX_VIRT_ADDR) {

        if (txrx_pdev->is_ar900b) {
            A_UINT32 desc_id = (A_UINT32) *((A_UINT32 *)(data + pl_dev->pktlog_hdr_size));
            A_UINT32 vdev_id = desc_id;
            /* if the pkt log msg is for the bcn frame the vdev id is piggybacked in desc_id
             * and the MSB of the desc ID would be set to FF
             */
            #define BCN_DESC_ID 0xFF
            if ((desc_id >> 24) == BCN_DESC_ID) {
                vdev_id &= 0x00FFFFFF;
		        pl = ol_ath_get_bcn_header(txrx_pdev->ctrl_pdev, vdev_id);
                if (pl)
                    process_ieee_hdr(pl);
            } else {
                /*TODO*/
                /* get the hdr conetnt for mgmt frames from Tx mgmt desc pool*/
            }
        } else {
            A_UINT32 virt_addr = (A_UINT32) *((A_UINT32 *)(data + pl_dev->pktlog_hdr_size));
            wbuf_t wbuf = (wbuf_t) virt_addr;
            process_ieee_hdr(wbuf_header(wbuf));
        }
    }


    if(pl_hdr->log_type == PKTLOG_TYPE_TX_CTRL) {
        size_t log_size = 0;
        size_t tmp_log_size = 0;

        tmp_log_size = sizeof(frm_hdr) + pl_hdr->size;

        if (txrx_pdev->is_ar900b) {
            void *txdesc_hdr_ctl = NULL;

            log_size = sizeof(frm_hdr) + pl_hdr->size;
            txdesc_hdr_ctl = (void *)
                pktlog_getbuf(pl_dev, pl_info, log_size, pl_hdr);
            if (txdesc_hdr_ctl == NULL) {
                return A_NO_MEMORY;
            }
            adf_os_assert(txdesc_hdr_ctl);

            adf_os_assert(pl_hdr->size < PKTLOG_MAX_TXCTL_WORDS_AR900B * sizeof(u_int32_t));

            adf_os_mem_copy(txdesc_hdr_ctl, &frm_hdr, sizeof(frm_hdr));
            adf_os_mem_copy((char *)txdesc_hdr_ctl + sizeof(frm_hdr),
                    ((void *)data + pl_dev->pktlog_hdr_size),
                    pl_hdr->size);
        } else {
            struct ath_pktlog_txctl_ar9888 txctl_log;
            log_size = sizeof(txctl_log.priv);
            txctl_log.txdesc_hdr_ctl = (void *)
                pktlog_getbuf(pl_dev, pl_info, log_size, pl_hdr);

            if(!txctl_log.txdesc_hdr_ctl) {
                return A_ERROR;
            }
            /*
             *  frm hdr is currently Valid only for local frames
             *  Add capability to include the fmr hdr for remote frames
             */
            txctl_log.priv.frm_hdr = frm_hdr;
            adf_os_assert(txctl_log.priv.txdesc_ctl);
            adf_os_mem_copy((void *)&txctl_log.priv.txdesc_ctl,
                    ((void *)data + pl_dev->pktlog_hdr_size),
                    pl_hdr->size);
            adf_os_mem_copy(txctl_log.txdesc_hdr_ctl,
                    &txctl_log.priv, sizeof(txctl_log.priv));
        }
    }

    if (pl_hdr->log_type == PKTLOG_TYPE_TX_STAT) {
        struct ath_pktlog_tx_status txstat_log;
        size_t log_size = pl_hdr->size;
        txstat_log.ds_status = (void *)
        pktlog_getbuf(pl_dev, pl_info, log_size, pl_hdr);
        if (txstat_log.ds_status == NULL) {
            return A_NO_MEMORY;
        }
        adf_os_assert(txstat_log.ds_status);
        adf_os_mem_copy(txstat_log.ds_status,
                ((void *)data + pl_dev->pktlog_hdr_size),
                 pl_hdr->size);
    }

    if (pl_hdr->log_type == PKTLOG_TYPE_TX_MSDU_ID) {

        (void)pl_dev->process_tx_msdu_info(txrx_pdev, data, pl_hdr);
    }

    return A_OK;
}


A_STATUS
process_rx_cbf_remote(void *dev, adf_nbuf_t amsdu)
{
    ol_pktlog_dev_t *pl_dev;
    struct ath_pktlog_info *pl_info;
    void *rx_desc;
    ath_pktlog_hdr_t pl_hdr;
    size_t log_size;
    struct ath_pktlog_cbf_info rxcbf_log;
    adf_nbuf_t msdu;
    struct ieee80211_frame *wh;
    A_UINT8 type, subtype, action_category;
    struct ieee80211_action *ia_header = NULL;
    struct bb_tlv_pkt_hdr *bb_hdr = NULL;
    struct ath_pktlog_cbf_submix_info  cbf_mix_info;
    int    msdu_chained = 0;
    A_BOOL fragNend = true;
    int    msdu_len = 0;
    struct ol_txrx_pdev_t *pdev;
    uint32_t rx_desc_size = 0;

    pdev = (struct ol_txrx_pdev_t *) dev;
    if(!pdev) {
        printk("Invalid pdev in %s\n",
                __FUNCTION__);
        return A_ERROR;
    }
    if(!amsdu) {
        printk("Invalid data in %s\n",
                __FUNCTION__);
        return A_ERROR;
    }

    adf_os_mem_set(&pl_hdr, 0, sizeof(pl_hdr));
    adf_os_mem_set(&cbf_mix_info, 0, sizeof(cbf_mix_info));
    pl_dev =  pdev->pl_dev;
    pl_info = pl_dev->pl_info;
    msdu = amsdu;

    while (msdu) {

#if QCA_PARTNER_DIRECTLINK_RX
        /*
         * For Direct Link RX, neeed to get rx descriptor by partner API.
         */
        if (CE_is_directlink(((struct ol_txrx_pdev_t *) pdev)->ce_tx_hdl)) {
            rx_desc = htt_rx_desc_partner(msdu);
        } else
#endif /* QCA_PARTNER_DIRECTLINK_RX */
    {
        rx_desc = htt_rx_desc(msdu);
    } /* QCA_PARTNER_DIRECTLINK_RX */

        /* Check PHY data type */
        if (pdev->htt_pdev->ar_rx_ops->msdu_desc_phy_data_type(rx_desc))
        {
           /* Handle Implicit CV*/
           bb_hdr    = (struct bb_tlv_pkt_hdr *)adf_nbuf_data(msdu);
           if ((bb_hdr->sig == PKTLOG_PHY_BB_SIGNATURE) &&
               (bb_hdr->tag == PKTLOG_RX_IMPLICIT_CV_TRANSFER || bb_hdr->tag == PKTLOG_BEAMFORM_DEBUG_H))
           {
               ia_header = (struct ieee80211_action *)(&bb_hdr[1]);
               log_size = adf_nbuf_len(msdu) - sizeof(struct bb_tlv_pkt_hdr);
               cbf_mix_info.sub_type = PKTLOG_RX_IMPLICIT_CV_TRANSFER;
           }else{
               goto ChkNextMsdu;
           }
        }else{
           /* Handle Explicit CV*/
           wh = (struct ieee80211_frame *)adf_nbuf_data(msdu);
           type    = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
           subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
           action_category = ((struct ieee80211_action *)(&wh[1]))->ia_category;
           if((type == IEEE80211_FC0_TYPE_MGT )&&(subtype == IEEE80211_FCO_SUBTYPE_ACTION_NO_ACK)
              &&(action_category == IEEE80211_ACTION_CAT_VHT))
           {
               ia_header   = (struct ieee80211_action *)(&wh[1]);
               log_size = adf_nbuf_len(msdu) - sizeof(struct ieee80211_frame);
               cbf_mix_info.sub_type = PKTLOG_RX_EXPLICIT_CV_TRANSFER;
           }else{
               goto ChkNextMsdu;
           }

        }

        msdu_len = pdev->htt_pdev->ar_rx_ops->msdu_desc_msdu_length(rx_desc);
        msdu_chained = pdev->htt_pdev->ar_rx_ops->msdu_desc_msdu_chained(rx_desc);

        cbf_mix_info.frag_flag = 0;

        do{
             log_size += sizeof(struct ath_pktlog_cbf_submix_info);
             /*
              * Construct the pktlog header pl_hdr
              * Because desc is DMA'd to the host memory
              */
             pl_hdr.flags = (1 << PKTLOG_FLG_FRM_TYPE_CBF_S);
             pl_hdr.missed_cnt = 0;
             pl_hdr.log_type = PKTLOG_TYPE_RX_CBF;
             pl_hdr.size += log_size;
             pl_hdr.timestamp =  pdev->htt_pdev->ar_rx_ops->msdu_desc_tsf_timestamp(rx_desc);

             rxcbf_log.cbf = (void *)
                   pktlog_getbuf(pl_dev, pl_info, log_size, &pl_hdr);
             if (rxcbf_log.cbf == NULL) {
                 return A_ERROR;
             }
             adf_os_mem_copy(rxcbf_log.cbf, (void *)&cbf_mix_info, sizeof(struct ath_pktlog_cbf_submix_info));

             rxcbf_log.cbf = (void *)rxcbf_log.cbf + sizeof(struct ath_pktlog_cbf_submix_info);

             adf_os_mem_copy(rxcbf_log.cbf, (void *)ia_header, log_size - sizeof(struct ath_pktlog_cbf_submix_info));
             if ((msdu_chained != 0) && (adf_nbuf_next(msdu) != NULL))
             {
                rx_desc_size = pdev->htt_pdev->ar_rx_ops->sizeof_rx_desc();
                msdu_len -= adf_nbuf_len(msdu);
                msdu = adf_nbuf_next(msdu);
                msdu_chained--;
                if(msdu_chained == 0)
                {
                    if (((unsigned)msdu_len) > ((unsigned)(HTT_RX_BUF_SIZE - rx_desc_size)))
                    {
                        msdu_len = (HTT_RX_BUF_SIZE - rx_desc_size);
                    }
                    log_size = msdu_len;
                }
                adf_os_mem_set(&pl_hdr, 0, sizeof(pl_hdr));
                cbf_mix_info.frag_flag = 1;
                ia_header = (struct ieee80211_action *)adf_nbuf_data(msdu);
                fragNend = true;
             }else{
                fragNend = false;
             }
        }while(fragNend);

ChkNextMsdu:
        msdu = adf_nbuf_next(msdu);
    }
    return A_OK;
}

A_STATUS
process_rx_info_remote(void *dev, adf_nbuf_t amsdu)
{
    ol_pktlog_dev_t *pl_dev;
    struct ath_pktlog_info *pl_info;
    struct htt_host_rx_desc_base *rx_desc;
    ath_pktlog_hdr_t pl_hdr;
    struct ath_pktlog_rx_info rxstat_log;
    size_t log_size;
    adf_nbuf_t msdu;
    struct ol_txrx_pdev_t *pdev;
    uint32_t rx_desc_size = 0;
    struct ieee80211_action_vht_gid_mgmt  *gid_mgmt_frm;

    pdev = (struct ol_txrx_pdev_t *) dev;

    if(!pdev) {
        printk("Invalid pdev in %s\n",
                __FUNCTION__);
        return A_ERROR;
    }
    if(!amsdu) {
        printk("Invalid data in %s\n",
                __FUNCTION__);
        return A_ERROR;
    }
    pl_dev = ((struct ol_txrx_pdev_t *) pdev)->pl_dev;
    pl_info = pl_dev->pl_info;
    rx_desc_size = pdev->htt_pdev->ar_rx_ops->sizeof_rx_desc();

    /* Insert VHT ACTION group ID information*/
    if(((struct ol_txrx_pdev_t *) pdev)->gid_flag)
    {

        gid_mgmt_frm = (struct ieee80211_action_vht_gid_mgmt *)&pdev->gid_mgmt.ia_category;
        pl_hdr.flags = (1 << PKTLOG_FLG_FRM_TYPE_REMOTE_S);
        pl_hdr.missed_cnt = 0;
        pl_hdr.log_type = PKTLOG_TYPE_GRPID;
        pl_hdr.size = sizeof(struct ieee80211_action_vht_gid_mgmt) -
            sizeof(struct ieee80211_action);
        pl_hdr.timestamp = 0;
#ifdef CONFIG_AR900B_SUPPORT
        pl_hdr.type_specific_data = 0;
#endif
        log_size = pl_hdr.size;
        rxstat_log.rx_desc = (void *)pktlog_getbuf(pl_dev, pl_info, log_size, &pl_hdr);
        if (rxstat_log.rx_desc == NULL) {
            return A_ERROR;
        }
        adf_os_mem_copy(rxstat_log.rx_desc,(u_int8_t *)&(((struct ol_txrx_pdev_t *) pdev)->gid_mgmt.member_status[0]) ,pl_hdr.size);
    }
    msdu = amsdu;
    while (msdu) {
        /* old code:

        rx_desc = (struct htt_host_rx_desc_base *)(
                            adf_nbuf_data(msdu)) - 1;

           replaced by following line, it should work for Peregrine
           as well, but not verified.
        */
#if QCA_PARTNER_DIRECTLINK_RX
        /*
         * For Direct Link RX, neeed to get rx descriptor by partner API.
         */
        if (CE_is_directlink(((struct ol_txrx_pdev_t *) pdev)->ce_tx_hdl)) {
            rx_desc = htt_rx_desc_partner(msdu);
        } else
#endif /* QCA_PARTNER_DIRECTLINK_RX */
    {
        rx_desc = htt_rx_desc(msdu);
    } /* QCA_PARTNER_DIRECTLINK_RX */

        log_size = rx_desc_size -
                   pdev->htt_pdev->ar_rx_ops->fw_rx_desc_size();

        /*
         * Construct the pktlog header pl_hdr
         * Because desc is DMA'd to the host memory
         */
        pl_hdr.flags = (1 << PKTLOG_FLG_FRM_TYPE_REMOTE_S);
        pl_hdr.missed_cnt = 0;
        pl_hdr.log_type = PKTLOG_TYPE_RX_STAT;
        pl_hdr.size = log_size;
        pl_hdr.timestamp =  pdev->htt_pdev->ar_rx_ops->msdu_desc_tsf_timestamp(rx_desc);

#ifdef CONFIG_AR900B_SUPPORT
        pl_hdr.type_specific_data = 0;
#endif

        rxstat_log.rx_desc = (void *)
            pktlog_getbuf(pl_dev, pl_info, log_size, &pl_hdr);
        if (rxstat_log.rx_desc == NULL) {
            return A_NO_MEMORY;
        }

        adf_os_mem_copy(rxstat_log.rx_desc, (void *)rx_desc +
                pdev->htt_pdev->ar_rx_ops->fw_rx_desc_size(),
                pl_hdr.size);

        msdu = adf_nbuf_next(msdu);
    }
    return A_OK;
}

static A_STATUS
process_rx_info(struct ol_pktlog_dev_t *pl_dev, void *data,
                        ath_pktlog_hdr_t *pl_hdr)
{
    struct ath_pktlog_info *pl_info;
    struct ath_pktlog_rx_info rxstat_log;
    size_t log_size;

    pl_info = pl_dev->pl_info;
    log_size = pl_hdr->size;
    rxstat_log.rx_desc = (void *)
        pktlog_getbuf(pl_dev, pl_info, log_size, pl_hdr);
    if (rxstat_log.rx_desc == NULL) {
        return A_NO_MEMORY;
    }
    adf_os_mem_copy(rxstat_log.rx_desc,
                    (void *)data + pl_dev->pktlog_hdr_size,
                    pl_hdr->size);

    return A_OK;
}

static A_STATUS
process_rate_find(struct ol_pktlog_dev_t *pl_dev, void *data,
                          ath_pktlog_hdr_t *pl_hdr)
{
    struct ath_pktlog_info *pl_info;
    size_t log_size;
    struct ath_pktlog_rc_find rcf_log;

    pl_info           = pl_dev->pl_info;
    log_size          = pl_hdr->size;
    rcf_log.rcFind    = (void *) pktlog_getbuf(pl_dev, pl_info,
            log_size, pl_hdr);
    if (rcf_log.rcFind == NULL ){
        return A_NO_MEMORY;
    }
    adf_os_mem_copy(rcf_log.rcFind,
            ((char *)data + pl_dev->pktlog_hdr_size), pl_hdr->size);

    return A_OK;
}

static A_STATUS
process_rate_update(struct ol_pktlog_dev_t *pl_dev, void *data,
                            ath_pktlog_hdr_t *pl_hdr)
{
    size_t log_size;
    struct ath_pktlog_info *pl_info;
    struct ath_pktlog_rc_update rcu_log;

    log_size = pl_hdr->size;
    pl_info = pl_dev->pl_info;

    /*
     * Will be uncommented when the rate control update
     * for pktlog is implemented in the firmware.
     * Currently derived from the TX PPDU status
     */
    rcu_log.txRateCtrl = (void *)
        pktlog_getbuf(pl_dev, pl_info, log_size, pl_hdr);
    if (rcu_log.txRateCtrl == NULL) {
        return A_NO_MEMORY;
    }
    adf_os_mem_copy(rcu_log.txRateCtrl,
            ((char *)data + pl_dev->pktlog_hdr_size), pl_hdr->size);

    return A_OK;
}

/* TODO::*/
A_STATUS
process_dbg_print(void *pdev, void *data)
{
    ol_pktlog_dev_t *pl_dev;
    ath_pktlog_hdr_t pl_hdr;
    size_t log_size;
    struct ath_pktlog_info *pl_info;
    struct ath_pktlog_dbg_print dbg_print_s;
    uint32_t *pl_tgt_hdr;

    if (!pdev) {
        adf_os_print("Invalid pdev in %s\n", __FUNCTION__);
        return A_ERROR;
    }
    if (!data) {
        adf_os_print("Invalid data in %s\n", __FUNCTION__);
        return A_ERROR;
    }

    pl_tgt_hdr = (uint32_t *)data;
    /*
     * Makes the short words (16 bits) portable b/w little endian
     * and big endian
     */
    pl_hdr.flags = (*(pl_tgt_hdr + ATH_PKTLOG_HDR_FLAGS_OFFSET) &
                                    ATH_PKTLOG_HDR_FLAGS_MASK) >>
                                    ATH_PKTLOG_HDR_FLAGS_SHIFT;
    pl_hdr.missed_cnt =  (*(pl_tgt_hdr + ATH_PKTLOG_HDR_MISSED_CNT_OFFSET) &
                                        ATH_PKTLOG_HDR_MISSED_CNT_MASK) >>
                                        ATH_PKTLOG_HDR_MISSED_CNT_SHIFT;
    pl_hdr.log_type =  (*(pl_tgt_hdr + ATH_PKTLOG_HDR_LOG_TYPE_OFFSET) &
                                        ATH_PKTLOG_HDR_LOG_TYPE_MASK) >>
                                        ATH_PKTLOG_HDR_LOG_TYPE_SHIFT;
    pl_hdr.size =  (*(pl_tgt_hdr + ATH_PKTLOG_HDR_SIZE_OFFSET) &
                                    ATH_PKTLOG_HDR_SIZE_MASK) >>
                                    ATH_PKTLOG_HDR_SIZE_SHIFT;
    pl_hdr.timestamp = *(pl_tgt_hdr + ATH_PKTLOG_HDR_TIMESTAMP_OFFSET);
#ifdef CONFIG_AR900B_SUPPORT
    pl_hdr.type_specific_data = 0;
#endif
    pl_dev = ((struct ol_txrx_pdev_t *) pdev)->pl_dev;
    pl_info = pl_dev->pl_info;

    adf_os_mem_set(dbglog_print_buffer, 0, sizeof(dbglog_print_buffer));
    dbglog_parse_debug_logs((struct ol_ath_softc_net80211 *)(((struct ol_txrx_pdev_t *) pdev)->ctrl_pdev),
                            (char *)data +  pl_dev->pktlog_hdr_size, pl_hdr.size,
                            (void *)DBGLOG_PRT_PKTLOG);
    log_size = strlen(dbglog_print_buffer);
    dbg_print_s.dbg_print = (void *)
                    pktlog_getbuf(pl_dev, pl_info, log_size, &pl_hdr);
    if (dbg_print_s.dbg_print == NULL) {
        return A_NO_MEMORY;
    }
    adf_os_mem_copy(dbg_print_s.dbg_print, dbglog_print_buffer, log_size);
    return A_OK;
}

#if PEER_FLOW_CONTROL
/* Do a plain dump of pktlog data */
    static A_STATUS
process_opaque_pktlog(struct ol_pktlog_dev_t *pl_dev, void *data,
                      ath_pktlog_hdr_t *pl_hdr)
{
    size_t log_size;
    struct ath_pktlog_info *pl_info;
    void *buf;

    log_size = pl_hdr->size;
    pl_info = pl_dev->pl_info;

    buf = (void *)pktlog_getbuf(pl_dev, pl_info, log_size, pl_hdr);
    if (!buf) {
        return A_ERROR;
    }

    adf_os_mem_copy(buf, ((char *)data + sizeof(ath_pktlog_hdr_t)), pl_hdr->size);

    return A_OK;
}
#endif

A_STATUS
process_offload_pktlog(void *pdev, void *data)
{
    struct ol_pktlog_dev_t *pl_dev;
    ath_pktlog_hdr_t pl_hdr;
    uint32_t *pl_tgt_hdr;
    A_STATUS rc;

    if(!pdev) {
        printk("Invalid pdev in %s\n", __FUNCTION__);
        return A_ERROR;
    }
    if(!data) {
        printk("Invalid data in %s\n", __FUNCTION__);
        return A_ERROR;
    }
    pl_tgt_hdr = (uint32_t *)data;
    /*
     * Makes the short words (16 bits) portable b/w little endian
     * and big endian
     */
    pl_hdr.flags = (*(pl_tgt_hdr + ATH_PKTLOG_HDR_FLAGS_OFFSET) &
            ATH_PKTLOG_HDR_FLAGS_MASK) >>
        ATH_PKTLOG_HDR_FLAGS_SHIFT;
    pl_hdr.missed_cnt =  (*(pl_tgt_hdr + ATH_PKTLOG_HDR_MISSED_CNT_OFFSET) &
            ATH_PKTLOG_HDR_MISSED_CNT_MASK) >>
        ATH_PKTLOG_HDR_MISSED_CNT_SHIFT;
    pl_hdr.log_type =  (*(pl_tgt_hdr + ATH_PKTLOG_HDR_LOG_TYPE_OFFSET) &
            ATH_PKTLOG_HDR_LOG_TYPE_MASK) >>
        ATH_PKTLOG_HDR_LOG_TYPE_SHIFT;
    pl_hdr.size =  (*(pl_tgt_hdr + ATH_PKTLOG_HDR_SIZE_OFFSET) &
            ATH_PKTLOG_HDR_SIZE_MASK) >>
        ATH_PKTLOG_HDR_SIZE_SHIFT;
    pl_hdr.timestamp = *(pl_tgt_hdr + ATH_PKTLOG_HDR_TIMESTAMP_OFFSET);

    if (((struct ol_txrx_pdev_t *)pdev)->is_ar900b) {
        pl_hdr.type_specific_data = *(pl_tgt_hdr + ATH_PKTLOG_HDR_TYPE_SPECIFIC_DATA_OFFSET);
    } else {
        pl_hdr.type_specific_data = 0;
    }

    pl_dev = ((struct ol_txrx_pdev_t *) pdev)->pl_dev;

    switch(pl_hdr.log_type) {
        case PKTLOG_TYPE_TX_CTRL:
        case PKTLOG_TYPE_TX_STAT:
        case PKTLOG_TYPE_TX_MSDU_ID:
        case PKTLOG_TYPE_TX_FRM_HDR:
        case PKTLOG_TYPE_TX_VIRT_ADDR:
            rc = process_tx_info(pdev, data, &pl_hdr);
            break;

        case PKTLOG_TYPE_RC_FIND:
            rc = process_rate_find(pl_dev, data, &pl_hdr);
            break;

        case PKTLOG_TYPE_RC_UPDATE:
            rc = process_rate_update(pl_dev, data, &pl_hdr);
            break;

        case PKTLOG_TYPE_RX_STAT:
            rc = process_rx_info(pl_dev, data, &pl_hdr);
            break;

        default:
#if PEER_FLOW_CONTROL
            rc = process_opaque_pktlog(pl_dev, data, &pl_hdr);
#else
            rc = A_ERROR;
#endif
            break;
    }

    return rc;
}
#endif /*REMOVE_PKT_LOG*/
