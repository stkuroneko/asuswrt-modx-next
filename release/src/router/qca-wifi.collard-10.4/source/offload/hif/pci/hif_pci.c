/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

/*
 * Implementation of the Host-side Host InterFace (HIF) API
 * for a Host/Target interconnect using Copy Engines over PCIe.
 */

//#include <athdefs.h>
#include <osdep.h>
#include "a_types.h"
#include "athdefs.h"
#include "a_osapi.h"
#include "targcfg.h"
#include "adf_os_lock.h"
#include <adf_os_atomic.h> /* adf_os_atomic_read */

#if 0
#include <adf_os_stdtypes.h>
#include <adf_nbuf.h>
#endif

#include <targaddrs.h>
#include <bmi_msg.h>
#include <hif.h>
#include <htc_services.h>

#include "hif_msg_based.h"

#include "ath_pci.h"
#include "copy_engine_api.h"
#include "host_reg_table.h"
#include "target_reg_table.h"
#include "ol_ath.h"
#include "ol_cfg.h"  /* OL_CFG_RX_RING_SIZE_MAX */

#include "epping_test.h"

#define ATH_MODULE_NAME hif
#include <a_debug.h>
#include "hif_pci.h"

#if QCA_OL_11AC_FAST_PATH
#include "ol_txrx_api.h"
#endif /* QCA_OL_11AC_FAST_PATH */

#if QCA_PARTNER_DIRECTLINK_RX
#define QCA_PARTNER_DIRECTLINK_HIF_PCI 1
#include "ath_carr_pltfrm.h"
#undef QCA_PARTNER_DIRECTLINK_HIF_PCI
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
extern int nss_wifi_olcfg;
extern int nss_wifi_ol_skip_nw_process;
#endif

#include "../../platform.h"	//ASUS

/* use credit flow control over HTC */

/* EV #134248 BUG Fix: Credit miss happens resulting in failure to create
* VAP. Disable Credit for WMI Endpoint
*/
unsigned int htc_credit_flow = 0;
//module_param(htc_credit_flow, uint, 0644);

#ifndef REMOVE_INIT_DEBUG_CODE
/* CR : 735871 */
extern int wmi_init_flag;
#endif

#ifdef EPPING_TEST
static unsigned int hif_epping_test = 1;
#endif

OSDRV_CALLBACKS HIF_osDrvcallback;

#define HIF_PCI_DEBUG   ATH_DEBUG_MAKE_MODULE_MASK(0)

#define CLOCK_OVERRIDE 0x2

#if defined(DEBUG)
static ATH_DEBUG_MASK_DESCRIPTION g_HIFDebugDescription[] = {
    {HIF_PCI_DEBUG,"hif_pci"},
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(hif,
                                 "hif",
                                 "PCIe Host Interface",
                                 ATH_DEBUG_MASK_DEFAULTS | ATH_DEBUG_INFO | HIF_PCI_DEBUG,
                                 ATH_DEBUG_DESCRIPTION_COUNT(g_HIFDebugDescription),
                                 g_HIFDebugDescription);
#endif


#if CONFIG_ATH_PCIE_ACCESS_DEBUG
spinlock_t pcie_access_log_lock;
#endif

/* Forward references */
static int hif_post_recv_buffers_for_pipe(struct HIF_CE_pipe_info *pipe_info);
static int hif_post_recv_buffers(HIF_DEVICE *hif_device);

/*
 * Host software's Copy Engine configuration.
 * This table is derived from the CE_PCI TABLE, above.
 */
#if defined(BIG_ENDIAN_HOST) && !AH_NEED_TX_DATA_SWAP
#define CE_ATTR_FLAGS CE_ATTR_BYTE_SWAP_DATA
#else
#define CE_ATTR_FLAGS 0
#endif

static struct CE_attr host_CE_config_wlan[] =
{
        { /* CE0 */ CE_ATTR_FLAGS, 0, 16, 256, 0, NULL, }, /* host->target HTC control and raw streams */
                                                           /* could be moved to share CE3 */
        { /* CE1 */ CE_ATTR_FLAGS, 0, 0, 512, 512, NULL, },/* target->host BMI + HTC control */
        { /* CE2 */ CE_ATTR_FLAGS, 0, 0, 2048, 128, NULL, },/* target->host WMI */
        { /* CE3 */ CE_ATTR_FLAGS, 0, 32, 2048, 0, NULL, },/* host->target WMI */
        { /* CE4 */ CE_ATTR_FLAGS | CE_ATTR_DISABLE_INTR, 0, CE_HTT_H2T_MSG_SRC_NENTRIES, 256, 0, NULL, }, /* host->target HTT */
#if QCA_OL_11AC_FAST_PATH
        { /* CE5 */ CE_ATTR_FLAGS, 0, 0, 512, 512, NULL, },    /* target->host HTT messages */
#else   /* QCA_OL_11AC_FAST_PATH */
        { /* CE5 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* unused */
#endif  /* QCA_OL_11AC_FAST_PATH */
        { /* CE6 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* Target autonomous HIF_memcpy */
        { /* CE7 */ CE_ATTR_FLAGS, 0, 2, DIAG_TRANSFER_LIMIT, 2, NULL, }, /* ce_diag, the Diagnostic Window */
        { /* CE8 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* Target autonomous HIF_memcpy */
};

static struct CE_attr host_CE_config_wlan_ar900b[] =
{
        { /* CE0 */ CE_ATTR_FLAGS, 0, 16, 256, 0, NULL, }, /* host->target HTC control and raw streams */
                                                           /* could be moved to share CE3 */
        { /* CE1 */ CE_ATTR_FLAGS, 0, 0, 512, 512, NULL, },/* target->host BMI + HTC control */
        { /* CE2 */ CE_ATTR_FLAGS, 0, 0, 2048, 128, NULL, },/* target->host WMI */
        { /* CE3 */ CE_ATTR_FLAGS, 0, 32, 2048, 0, NULL, },/* host->target WMI */
        { /* CE4 */ CE_ATTR_FLAGS | CE_ATTR_DISABLE_INTR, 0, CE_HTT_H2T_MSG_SRC_NENTRIES, 256, 0, NULL, }, /* host->target HTT */
#if QCA_OL_11AC_FAST_PATH
        { /* CE5 */ CE_ATTR_FLAGS, 0, 0, 512, 512, NULL, },    /* target->host HTT messages */
#else   /* QCA_OL_11AC_FAST_PATH */
        { /* CE5 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* unused */
#endif  /* QCA_OL_11AC_FAST_PATH */
        { /* CE6 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* Target autonomous HIF_memcpy */
        { /* CE7 */ CE_ATTR_FLAGS, 0, 2, DIAG_TRANSFER_LIMIT, 2, NULL, }, /* ce_diag, the Diagnostic Window */
        { /* CE8 */ CE_ATTR_FLAGS, 0, 0, 2048, 128, NULL, },/* target->host pktlog */
        { /* CE9 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* Target autonomous HIF_memcpy */
        { /* CE10 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },   /* Target autonomous HIF_memcpy */
        { /* CE11 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },   /* Target autonomous HIF_memcpy */
};

static struct CE_attr *host_CE_config = host_CE_config_wlan;

#ifdef EPPING_TEST
/*
 * CE config for endpoint-ping test
 * EP-ping is used to verify HTC/HIF basic functionality and could be used to
 * measure interface performance. Here comes some notes.
 * 1. In theory, each CE could be used to test. However, due to the limitation
 *    of target memory EP-ping only focus on CE 1/2/3/4 which are used for
 *    WMI/HTT services
 * 2. The EP-ping CE config does not share the same CE config with WLAN
 *    application since the max_size and entries requirement for EP-ping
 *    is different.
 */
static struct CE_attr host_CE_config_epping[] =
{
        { /* CE0 */ CE_ATTR_FLAGS, 0, 16, 256, 0, NULL, },  /* host->target HTC control and raw streams */
        { /* CE1 */ CE_ATTR_FLAGS, 0, 0, 2048, 32, NULL, }, /* target->host EP-ping */
        { /* CE2 */ CE_ATTR_FLAGS, 0, 0, 2048, 32, NULL, }, /* target->host EP-ping */
        { /* CE3 */ CE_ATTR_FLAGS, 0, 32, 2048, 0, NULL, }, /* host->target EP-ping */
        { /* CE4 */ CE_ATTR_FLAGS, 0, 32, 2048, 0, NULL, }, /* host->target EP-ping */
        { /* CE5 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },     /* unused */
        { /* CE6 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },     /* unused */
        { /* CE7 */ CE_ATTR_FLAGS, 0, 2, DIAG_TRANSFER_LIMIT, 2, NULL, }, /* ce_diag, the Diagnostic Window */
        { /* CE8 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },     /* unused */
        { /* CE9 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },     /* unused */
        { /* CE10 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* unused */
        { /* CE11 */ CE_ATTR_FLAGS, 0, 0, 0, 0, NULL, },    /* unused */
};
#endif

/*
 * Target firmware's Copy Engine configuration.
 * This table is derived from the CE_PCI TABLE, above.
 * It is passed to the Target at startup for use by firmware.
 */
static struct CE_pipe_config target_CE_config_wlan[] = {
        { /* CE0 */ 0, PIPEDIR_OUT, 32, 256, CE_ATTR_FLAGS, 0, },   /* host->target HTC control and raw streams */
        { /* CE1 */ 1, PIPEDIR_IN, 32, 512, CE_ATTR_FLAGS, 0, },    /* target->host HTC control */
        { /* CE2 */ 2, PIPEDIR_IN, 64, 2048, CE_ATTR_FLAGS, 0, },   /* target->host WMI */
        { /* CE3 */ 3, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },  /* host->target WMI */
        { /* CE4 */ 4, PIPEDIR_OUT, 256, 256, CE_ATTR_FLAGS, 0, },  /* host->target HTT */
                                   /* NB: 50% of src nentries, since tx has 2 frags */
#if QCA_OL_11AC_FAST_PATH
        { /* CE5 */ 5, PIPEDIR_IN, 32, 512, CE_ATTR_FLAGS, 0, },    /* target->host HTT */
#else
        { /* CE5 */ 5, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },  /* unused */
#endif
        { /* CE6 */ 6, PIPEDIR_INOUT, 32, 4096, CE_ATTR_FLAGS, 0, },/* Reserved for target autonomous HIF_memcpy */
        /* CE7 used only by Host */
};

static struct CE_pipe_config target_CE_config_wlan_ar900b[] = {
        { /* CE0 */ 0, PIPEDIR_OUT, 32, 256, CE_ATTR_FLAGS, 0, },   /* host->target HTC control and raw streams */
        { /* CE1 */ 1, PIPEDIR_IN, 32, 512, CE_ATTR_FLAGS, 0, },    /* target->host HTC control */
        { /* CE2 */ 2, PIPEDIR_IN, 64, 2048, CE_ATTR_FLAGS, 0, },   /* target->host WMI */
        { /* CE3 */ 3, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },  /* host->target WMI */
        { /* CE4 */ 4, PIPEDIR_OUT, 256, 256, CE_ATTR_FLAGS, 0, },  /* host->target HTT */
                                   /* NB: 50% of src nentries, since tx has 2 frags */
#if QCA_OL_11AC_FAST_PATH
        { /* CE5 */ 5, PIPEDIR_IN, 32, 512, CE_ATTR_FLAGS, 0, },    /* target->host HTT */
#else
        { /* CE5 */ 5, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },  /* unused */
#endif
        { /* CE6 */ 6, PIPEDIR_INOUT, 32, 4096, CE_ATTR_FLAGS, 0, },/* Reserved for target autonomous HIF_memcpy */
        { /* CE7 */ 7, PIPEDIR_INOUT, 0, 0, 0, 0, },                /* CE7 used only by Host */
        { /* CE8 */ 8, PIPEDIR_IN, 64, 2048, CE_ATTR_FLAGS|CE_ATTR_DISABLE_INTR, 0, }, /* target->host packtlog */
#if PEER_CACHEING_HOST_ENABLE
        { /* CE9 */ 9, PIPEDIR_INOUT, 32, 2048, CE_ATTR_FLAGS|CE_ATTR_DISABLE_INTR, 0, }, /* target autonomous qcache memcpy */
#endif
};

static struct CE_pipe_config *target_CE_config = target_CE_config_wlan;
static int target_CE_config_sz = sizeof(target_CE_config_wlan);

#ifdef EPPING_TEST
/*
 * EP-ping firmware's CE configuration
 */
static struct CE_pipe_config target_CE_config_epping[] = {
        { /* CE0 */ 0, PIPEDIR_OUT, 32, 256, CE_ATTR_FLAGS, 0, },    /* host->target HTC control and raw streams */
        { /* CE1 */ 1, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS, 0, },    /* target->host EP-ping */
        { /* CE2 */ 2, PIPEDIR_IN, 32, 2048, CE_ATTR_FLAGS, 0, },    /* target->host EP-ping */
        { /* CE3 */ 3, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },   /* host->target EP-ping */
        { /* CE4 */ 4, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },   /* host->target EP-ping */
        { /* CE5 */ 5, PIPEDIR_OUT, 32, 2048, CE_ATTR_FLAGS, 0, },   /* unused */
        { /* CE6 */ 6, PIPEDIR_INOUT, 32, 4096, CE_ATTR_FLAGS, 0, }, /* unused */
        /* CE7 used only by Host */
};
#endif

int hif_completion_thread(struct HIF_CE_state *hif_state);


int HIFInit(OSDRV_CALLBACKS *callbacks)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    A_MEMZERO(&HIF_osDrvcallback,sizeof(HIF_osDrvcallback));

    A_REGISTER_MODULE_DEBUG_INFO(hif);

    HIF_osDrvcallback.deviceInsertedHandler = callbacks->deviceInsertedHandler;
    HIF_osDrvcallback.deviceRemovedHandler = callbacks->deviceRemovedHandler;
    HIF_osDrvcallback.deviceSuspendHandler = callbacks->deviceSuspendHandler;
    HIF_osDrvcallback.deviceResumeHandler = callbacks->deviceResumeHandler;
    HIF_osDrvcallback.deviceWakeupHandler = callbacks->deviceWakeupHandler;
    HIF_osDrvcallback.context = callbacks->context;

#if CONFIG_ATH_PCIE_ACCESS_DEBUG
    spin_lock_init(&pcie_access_log_lock);
#endif

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
    return EOK;
}

int
HIFAttachHTC(HIF_DEVICE *hif_device, HTC_CALLBACKS *callbacks)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    ASSERT(0);
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return EOK;
}

void
HIFDetachHTC(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    A_MEMZERO(&hif_state->msg_callbacks_pending, sizeof(hif_state->msg_callbacks_pending));
    A_MEMZERO(&hif_state->msg_callbacks_current, sizeof(hif_state->msg_callbacks_current));
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

/* Send the first nbytes bytes of the buffer */
A_STATUS
HIFSend_head(HIF_DEVICE *hif_device,
             a_uint8_t pipe, unsigned int transfer_id, unsigned int nbytes, adf_nbuf_t nbuf)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct HIF_CE_pipe_info *pipe_info = &(hif_state->pipe_info[pipe]);
    struct CE_handle *ce_hdl = pipe_info->ce_hdl;
    int bytes = nbytes, nfrags = 0;
    struct CE_sendlist sendlist;
    int status;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    A_ASSERT(nbytes <= adf_nbuf_len(nbuf));

    /*
     * The common case involves sending multiple fragments within a
     * single download (the tx descriptor and the tx frame header).
     * So, optimize for the case of multiple fragments by not even
     * checking whether it's necessary to use a sendlist.
     * The overhead of using a sendlist for a single buffer download
     * is not a big deal, since it happens rarely (for WMI messages).
     */
    CE_sendlist_init(&sendlist);
    do {
        a_uint32_t frag_paddr;
        int frag_bytes;

        frag_paddr = adf_nbuf_get_frag_paddr_lo(nbuf, nfrags);
        frag_bytes = adf_nbuf_get_frag_len(nbuf, nfrags);
        CE_sendlist_buf_add(
            &sendlist, frag_paddr,
            frag_bytes > bytes ? bytes : frag_bytes,
            adf_nbuf_get_frag_is_wordstream(nbuf, nfrags) ?
                0 : CE_SEND_FLAG_SWAP_DISABLE);
        bytes -= frag_bytes;
        nfrags++;
    } while (bytes > 0);

    /* Make sure we have resources to handle this request */
    adf_os_spin_lock_bh(&pipe_info->completion_freeq_lock);
    if (pipe_info->num_sends_allowed < nfrags) {
        adf_os_spin_unlock_bh(&pipe_info->completion_freeq_lock);
        OL_ATH_HIF_PKT_ERROR_COUNT_INCR(hif_state, HIF_PIPE_NO_RESOURCE);
        return A_NO_RESOURCE;
    }
#if QCA_OL_11AC_FAST_PATH
	/* fix EV135303, we should reap to budget after we send the msg */
	if (pipe != CE_HTT_TX_CE) {
    pipe_info->num_sends_allowed -= nfrags;
	}
#endif

    adf_os_spin_unlock_bh(&pipe_info->completion_freeq_lock);


#ifndef REMOVE_INIT_DEBUG_CODE
    /* Below debug code has been enabled to catch the corruption happening */
    /* randomly. Will be removed after fix. This is not in Performance path */
    /* Reference : CR 735871 */
    if(wmi_init_flag)
    {
        void ol_ath_dump_u32_buf(uint32_t *ptr, int len);
        wmi_init_flag = 0;

        printk("Hif Layer\n");
        ol_ath_dump_u32_buf((uint32_t*)wbuf_header(nbuf), wbuf_get_pktlen(nbuf));
        if(hif_state->sc->scn->nbuf==NULL)
            hif_state->sc->scn->nbuf = nbuf;
        else if(hif_state->sc->scn->nbuf1==NULL)
            hif_state->sc->scn->nbuf1 = nbuf;
    }
#endif

    status = CE_sendlist_send(ce_hdl, nbuf, &sendlist, transfer_id);
    A_ASSERT(status == A_OK);

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return status;
}

#if QCA_OL_11AC_FAST_PATH
/*
 * Funciotn :
 *      Updates pipe->num_sends allowed in the fast path
 *      so that, later sends through the additional HTC layer
 *      is fine
 */
void
HIF_update_pipe_info(HIF_DEVICE *hif_device,
             a_uint8_t pipe, uint32_t num_frags)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct HIF_CE_pipe_info *pipe_info = &(hif_state->pipe_info[pipe]);

    ASSERT(pipe_info->num_sends_allowed >= num_frags);
    adf_os_spin_lock_bh(&pipe_info->completion_freeq_lock);
    pipe_info->num_sends_allowed -= num_frags;
    adf_os_spin_unlock_bh(&pipe_info->completion_freeq_lock);
}

#endif /* QCA_OL_11AC_FAST_PATH */


/* Send the entire buffer */
A_STATUS
HIFSend(HIF_DEVICE *hif_device, a_uint8_t pipe, adf_nbuf_t hdr_buf, adf_nbuf_t netbuf)
{
    return HIFSend_head(hif_device, pipe, 0, adf_nbuf_len(netbuf), netbuf);
}

void
HIFSendCompleteCheck(HIF_DEVICE *hif_device, a_uint8_t pipe, int force)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    if (! force) {
        int resources;
        /*
         * Decide whether to actually poll for completions, or just
         * wait for a later chance.
         * If there seem to be plenty of resources left, then just wait,
         * since checking involves reading a CE register, which is a
         * relatively expensive operation.
         */
        resources = HIFGetFreeQueueNumber(hif_device, pipe);
        /*
         * If at least 50% of the total resources are still available,
         * don't bother checking again yet.
         */
        if (resources > (host_CE_config[pipe].src_nentries >> 1)) {
            return;
        }
    }
#if  ATH_11AC_TXCOMPACT
    CE_per_engine_servicereap(hif_state->sc, pipe);
#else
    CE_per_engine_service(hif_state->sc, pipe);
#endif
}

a_uint16_t
HIFGetFreeQueueNumber(HIF_DEVICE *hif_device, a_uint8_t pipe)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct HIF_CE_pipe_info *pipe_info = &(hif_state->pipe_info[pipe]);
    a_uint16_t rv;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    adf_os_spin_lock_bh(&pipe_info->completion_freeq_lock);
    rv = pipe_info->num_sends_allowed;
    adf_os_spin_unlock_bh(&pipe_info->completion_freeq_lock);
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
    return rv;
}

/* This is debug API to get the current SW index and HW index for given CE
 * The API is needed as the CE parameters can't be accessed from this file due to modularity
 */
extern void ce_debug_hw_sw_index(struct CE_handle *copyeng, int *hw_index, int *sw_index);
/* Called by lower (CE) layer when a send to Target completes. */
void
HIF_PCI_CE_send_done(struct CE_handle *copyeng, void *ce_context, void *transfer_context,
    CE_addr_t CE_data, unsigned int nbytes, unsigned int transfer_id)
{
    struct HIF_CE_pipe_info *pipe_info = (struct HIF_CE_pipe_info *)ce_context;
    struct HIF_CE_state *hif_state = pipe_info->HIF_CE_state;
    struct HIF_CE_completion_state *compl_state;
    struct HIF_CE_completion_state *compl_queue_head, *compl_queue_tail; /* local queue */
#if CE_HW_IDX_DEBUG
    /* HW and SW index debug variables */
    unsigned int sw_index0=0, sw_index1=0;
    unsigned int sw_index2=0, hw_index0=0;
    unsigned int hw_index1=0, hw_index2=0;
    unsigned int i=0;
#endif
    compl_queue_head = compl_queue_tail = NULL;
#if CE_HW_IDX_DEBUG
    ce_debug_hw_sw_index(copyeng, &hw_index0, &sw_index0);
#endif
    do {
#if CE_HW_IDX_DEBUG
        if (adf_os_unlikely(i == 1)) {
           ce_debug_hw_sw_index(copyeng, &hw_index1, &sw_index1);
        }
        i++;
#endif
        /*
         * For the send completion of an item in sendlist, just increment
         * num_sends_allowed. The upper layer callback will be triggered
         * when last fragment is done with send.
         */
        if (transfer_context == CE_SENDLIST_ITEM_CTXT) {
            adf_os_spin_lock(&pipe_info->completion_freeq_lock);
            pipe_info->num_sends_allowed++; /* NB: meaningful only for Sends */
            adf_os_spin_unlock(&pipe_info->completion_freeq_lock);
            continue;
        }

        adf_os_spin_lock(&pipe_info->completion_freeq_lock);
        compl_state = pipe_info->completion_freeq_head;
        ASSERT(compl_state != NULL);
#if CE_HW_IDX_DEBUG
        if(adf_os_unlikely(compl_state == NULL)) {
           ce_debug_hw_sw_index(copyeng, &hw_index2, &sw_index2);
           printk(" compl_state is NULL, some issue could be with sw_index \n");
           printk("1: SW index %d, HW index %d \n "
                   "2: SW index %d, HW index %d \n"
                   "3: SW index %d, HW index %d \n ", sw_index0, hw_index0, sw_index1, hw_index1, sw_index2, hw_index2);
           printk("The SW completion index has caught up with the cached version of the HW completion index.\n");
           break;
        }
#endif
        pipe_info->completion_freeq_head = compl_state->next;
        adf_os_spin_unlock(&pipe_info->completion_freeq_lock);

        compl_state->next = NULL;
        compl_state->send_or_recv = HIF_CE_COMPLETE_SEND;
        compl_state->copyeng = copyeng;
        compl_state->ce_context = ce_context;
        compl_state->transfer_context = transfer_context;
        compl_state->data = CE_data;
        compl_state->nbytes = nbytes;
        compl_state->transfer_id = transfer_id;
        compl_state->flags = 0;

        /* Enqueue at end of local queue */
        if (compl_queue_tail) {
            compl_queue_tail->next = compl_state;
        } else {
            compl_queue_head = compl_state;
        }
        compl_queue_tail = compl_state;
    } while (CE_completed_send_next(copyeng, &ce_context, &transfer_context,
                                         &CE_data, &nbytes, &transfer_id) == EOK);

    if (compl_queue_head == NULL) {
        /*
         * If only some of the items within a sendlist have completed,
         * don't invoke completion processing until the entire sendlist
         * has been sent.
         */
        return;
    }

    adf_os_spin_lock(&hif_state->completion_pendingq_lock);

    /* Enqueue the local completion queue on the per-device completion queue */
    if (hif_state->completion_pendingq_head) {
        hif_state->completion_pendingq_tail->next = compl_queue_head;
        hif_state->completion_pendingq_tail = compl_queue_tail;
        adf_os_spin_unlock(&hif_state->completion_pendingq_lock);
    } else {
        hif_state->completion_pendingq_head = compl_queue_head;
        hif_state->completion_pendingq_tail = compl_queue_tail;
        adf_os_spin_unlock(&hif_state->completion_pendingq_lock);

        /* Alert the send completion service thread */
#if 0
        wake_up(&hif_state->service_waitq);
#endif
        hif_completion_thread(hif_state);
    }
}


/* Called by lower (CE) layer when data is received from the Target. */
void
HIF_PCI_CE_recv_data(struct CE_handle *copyeng, void *ce_context, void *transfer_context,
    CE_addr_t CE_data, unsigned int nbytes, unsigned int transfer_id, unsigned int flags)
{
    struct HIF_CE_pipe_info *pipe_info = (struct HIF_CE_pipe_info *)ce_context;
    struct HIF_CE_state *hif_state = pipe_info->HIF_CE_state;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    struct ol_ath_softc_net80211 *scn = sc->scn;
    struct HIF_CE_completion_state *compl_state;
    struct HIF_CE_completion_state *compl_queue_head, *compl_queue_tail; /* local queue */

    compl_queue_head = compl_queue_tail = NULL;
    do {
        adf_os_spin_lock(&pipe_info->completion_freeq_lock);
        compl_state = pipe_info->completion_freeq_head;
        ASSERT(compl_state != NULL);
        if(!compl_state){
            printk("%s:%d:compl_state is 0\n",__func__,__LINE__);
            adf_os_spin_unlock(&pipe_info->completion_freeq_lock);
            return;
        }
        pipe_info->completion_freeq_head = compl_state->next;
        adf_os_spin_unlock(&pipe_info->completion_freeq_lock);

        compl_state->next = NULL;
        compl_state->send_or_recv = HIF_CE_COMPLETE_RECV;
        compl_state->copyeng = copyeng;
        compl_state->ce_context = ce_context;
        compl_state->transfer_context = transfer_context;
        compl_state->data = CE_data;
        compl_state->nbytes = nbytes;
        compl_state->transfer_id = transfer_id;
        compl_state->flags = flags;

        /* Enqueue at end of local queue */
        if (compl_queue_tail) {
            compl_queue_tail->next = compl_state;
        } else {
            compl_queue_head = compl_state;
        }
        compl_queue_tail = compl_state;

        adf_nbuf_unmap_nbytes_single(scn->adf_dev, (adf_nbuf_t)transfer_context, ADF_OS_DMA_FROM_DEVICE, nbytes);

        /*
         * EV #112693 - [Peregrine][ES1][WB342][Win8x86][Performance] BSoD_0x133 occurred in VHT80 UDP_DL
         * Break out DPC by force if number of loops in HIF_PCI_CE_recv_data reaches MAX_NUM_OF_RECEIVES to avoid spending too long time in DPC for each interrupt handling.
         * Schedule another DPC to avoid data loss if we had taken force-break action before
         * Apply to Windows OS only currently, Linux/MAC os can expand to their platform if necessary
         */

        /* Set up force_break flag if num of receices reaches MAX_NUM_OF_RECEIVES */
        sc->receive_count++;
        if (adf_os_unlikely(ath_max_num_receives_reached(sc->receive_count)))
        {
            sc->force_break = 1;
            break;
        }
    } while (CE_completed_recv_next(copyeng, &ce_context, &transfer_context,
                                         &CE_data, &nbytes, &transfer_id, &flags) == EOK);

    adf_os_spin_lock(&hif_state->completion_pendingq_lock);

    /* Enqueue the local completion queue on the per-device completion queue */
    if (hif_state->completion_pendingq_head) {
        hif_state->completion_pendingq_tail->next = compl_queue_head;
        hif_state->completion_pendingq_tail = compl_queue_tail;
        adf_os_spin_unlock(&hif_state->completion_pendingq_lock);
    } else {
        hif_state->completion_pendingq_head = compl_queue_head;
        hif_state->completion_pendingq_tail = compl_queue_tail;
        adf_os_spin_unlock(&hif_state->completion_pendingq_lock);

        /* Alert the recv completion service thread */
#if 0
        wake_up(&hif_state->service_waitq);
#endif
        hif_completion_thread(hif_state);
    }
}

/* TBDXXX: Set CE High Watermark; invoke txResourceAvailHandler in response */


void
HIFPostInit(HIF_DEVICE *hif_device, void *unused, MSG_BASED_HIF_CALLBACKS *callbacks)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    /* Save callbacks for later installation */
    A_MEMCPY(&hif_state->msg_callbacks_pending, callbacks, sizeof(hif_state->msg_callbacks_pending));

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
HIFRegisterPipeCallbacks(HIF_DEVICE *hif_device, u_int8_t PipeID, MSG_BASED_HIF_CALLBACKS *callbacks)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct HIF_CE_pipe_info *pipe_info;

    ASSERT(PipeID < CE_COUNT_MAX);

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    pipe_info = &hif_state->pipe_info[PipeID];

    A_MEMCPY(&pipe_info->pipe_callbacks, callbacks, sizeof(pipe_info->pipe_callbacks));

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
hif_completion_thread_startup(struct HIF_CE_state *hif_state)
{
    struct CE_handle *ce_diag = hif_state->ce_diag;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    A_target_id_t targid = hif_state->targid;
    int pipe_num;

    //daemonize("hif_compl_thread");

    adf_os_spinlock_init(&hif_state->completion_pendingq_lock);
    hif_state->completion_pendingq_head = hif_state->completion_pendingq_tail = NULL;

    A_TARGET_ACCESS_LIKELY(targid);
    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        struct CE_attr attr;
        struct HIF_CE_pipe_info *pipe_info;
        int completions_needed;

        pipe_info = &hif_state->pipe_info[pipe_num];
        if (pipe_info->ce_hdl == ce_diag) {
            continue; /* Handle Diagnostic CE specially */
        }
        attr = host_CE_config[pipe_num];
        completions_needed = 0;
        if (attr.src_nentries) { /* pipe used to send to target */
            CE_send_cb_register(pipe_info->ce_hdl, HIF_PCI_CE_send_done, pipe_info, attr.flags & CE_ATTR_DISABLE_INTR);
            completions_needed += attr.src_nentries;
            pipe_info->num_sends_allowed = attr.src_nentries-1;
        }
        if (attr.dest_nentries) { /* pipe used to receive from target */
            CE_recv_cb_register(pipe_info->ce_hdl, HIF_PCI_CE_recv_data, pipe_info);
            completions_needed += attr.dest_nentries;
        }

        pipe_info->completion_freeq_head = pipe_info->completion_freeq_tail = NULL;
        if (completions_needed > 0) {
            struct HIF_CE_completion_state *compl_state;
            int i;

            /* Allocate structures to track pending send/recv completions */
            compl_state = (struct HIF_CE_completion_state *)
                    vmalloc(completions_needed * sizeof(struct HIF_CE_completion_state));
            ASSERT(compl_state != NULL); /* TBDXXX */
            pipe_info->completion_space = compl_state;

            adf_os_spinlock_init(&pipe_info->completion_freeq_lock);
            for (i=0; i<completions_needed; i++) {
                compl_state->send_or_recv = HIF_CE_COMPLETE_FREE;
                compl_state->next = NULL;
                if (pipe_info->completion_freeq_head) {
                    pipe_info->completion_freeq_tail->next = compl_state;
                } else {
                    pipe_info->completion_freeq_head = compl_state;
                }
                pipe_info->completion_freeq_tail = compl_state;
                compl_state++;
            }
        }

    }
    A_TARGET_ACCESS_UNLIKELY(targid);
}

void
hif_completion_thread_shutdown(struct HIF_CE_state *hif_state)
{
    struct HIF_CE_completion_state *compl_state;
    struct HIF_CE_pipe_info *pipe_info;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    int pipe_num;

    /*
     * Drop pending completions.  These have already been
     * reported by the CE layer to us but we have not yet
     * passed them upstack.
     */
    while ((compl_state = hif_state->completion_pendingq_head) != NULL) {
        adf_nbuf_t netbuf;

        pipe_info = (struct HIF_CE_pipe_info *)compl_state->ce_context;
        netbuf = (adf_nbuf_t)compl_state->transfer_context;
        adf_nbuf_free(netbuf);

        hif_state->completion_pendingq_head = compl_state->next;

        /*
         * NB: Don't bother to place compl_state on pipe's free queue,
         * because we'll free underlying memory for the free queues
         * in a moment anyway.
         */
    }

    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        pipe_info = &hif_state->pipe_info[pipe_num];
        if (pipe_info->completion_space) {
            vfree(pipe_info->completion_space);
        }
        adf_os_spinlock_destroy(&pipe_info->completion_freeq_lock);
        pipe_info->completion_space = NULL; /* sanity */
        pipe_info->completion_freeq_head = pipe_info->completion_freeq_tail = NULL;
    }

    //hif_state->compl_thread = NULL;
    //complete_and_exit(&hif_state->compl_thread_done, 0);
}

/*
 * This thread provides a context in which send/recv completions
 * are handled.
 *
 * Note: HIF installs callback functions with the CE layer.
 * Those functions are called directly (e.g. in interrupt context).
 * Upper layers (e.g. HTC) have installed callbacks with HIF which
 * expect to be called in a thread context. This is where that
 * conversion occurs.
 *
 * TBDXXX: Currently we use just one thread for all pipes.
 * This might be sufficient or we might need multiple threads.
 */
int
//hif_completion_thread(void *hif_dev)
hif_completion_thread(struct HIF_CE_state *hif_state)
{
#if 0
    HIF_DEVICE *hif_device = (HIF_DEVICE *)hif_dev;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
#endif
    MSG_BASED_HIF_CALLBACKS *msg_callbacks = &hif_state->msg_callbacks_current;
    MSG_BASED_HIF_CALLBACKS *pipe_callbacks;
    struct HIF_CE_completion_state *compl_state;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

#if 0
    hif_completion_thread_startup(hif_state);

    for(;;) {
        struct HIF_CE_completion_state *compl_state;

        wait_event(hif_state->service_waitq,
                (hif_state->completion_pendingq_head || hif_state->shut_down));

        if (hif_state->shut_down) {
            hif_completion_thread_shutdown(hif_state);
            /* NOTREACHED */
        }
#endif

        /* Allow only one instance of the thread to execute at a time to
         * prevent out of order processing of messages - this is bad for higher
         * layer code
         */
        if (!adf_os_atomic_dec_and_test(&hif_state->hif_thread_idle)) {
            /* We were not the lucky one */
            adf_os_atomic_inc(&hif_state->hif_thread_idle);
            return 0;
        }



        while (atomic_read(&hif_state->fw_event_pending) > 0) {
            /*
             * Clear pending state before handling, in case there's
             * another while we process the first.
             */
            atomic_set(&hif_state->fw_event_pending, 0);
            msg_callbacks->fwEventHandler(msg_callbacks->Context);
        }

        for (;;) {
            struct HIF_CE_pipe_info *pipe_info;
            int send_done = 0;

            adf_os_spin_lock(&hif_state->completion_pendingq_lock);

            if (!hif_state->completion_pendingq_head) {
                /* We are atomically sure that there is no pending work */
                adf_os_atomic_inc(&hif_state->hif_thread_idle);
                adf_os_spin_unlock(&hif_state->completion_pendingq_lock);
                break; /* All pending completions are handled */
            }

            /* Dequeue the first unprocessed but completed transfer */
            compl_state = hif_state->completion_pendingq_head;
            hif_state->completion_pendingq_head = compl_state->next;
            adf_os_spin_unlock(&hif_state->completion_pendingq_lock);

            pipe_info = (struct HIF_CE_pipe_info *)compl_state->ce_context;
            pipe_callbacks = &pipe_info->pipe_callbacks;

            if (compl_state->send_or_recv == HIF_CE_COMPLETE_SEND) {
#ifndef REMOVE_INIT_DEBUG_CODE
                adf_nbuf_t netbuf;
                netbuf = (adf_nbuf_t)compl_state->transfer_context;
                 if(netbuf == hif_state->sc->scn->nbuf ||
                        netbuf == hif_state->sc->scn->nbuf1 )
                 {
                     uint32_t *ptr = (uint32_t*) wbuf_header(netbuf);
                     void ol_ath_dump_u32_buf(uint32_t *ptr, int len);

                     printk("Completion\n");
                     /*dma sync netbuf*/
                     adf_nbuf_sync_for_cpu(hif_state->sc->scn->adf_dev,
                             netbuf, ADF_OS_DMA_TO_DEVICE);
                     ol_ath_dump_u32_buf(ptr, wbuf_get_pktlen(netbuf));
                     if(hif_state->sc->scn->nbuf)
                         hif_state->sc->scn->nbuf = NULL;
                     else
                         hif_state->sc->scn->nbuf1 = NULL;
                 }
#endif
                msg_callbacks->txCompletionHandler(msg_callbacks->Context, compl_state->transfer_context, compl_state->transfer_id);
                send_done = 1;
            } else { /* compl_state->send_or_recv == HIF_CE_COMPLETE_RECV */
                adf_nbuf_t netbuf;
                unsigned int nbytes;

                atomic_inc(&pipe_info->recv_bufs_needed);
#if 0
                if (atomic_inc_return(&hif_state->replenish_recv_buf_flag) == 1) {
                    wake_up(&hif_state->replenish_recv_buf_waitq);
                }
#else
                hif_post_recv_buffers((HIF_DEVICE *)hif_state);
#endif

                netbuf = (adf_nbuf_t)compl_state->transfer_context;
                nbytes = compl_state->nbytes;
                AR_DEBUG_PRINTF(HIF_PCI_DEBUG,("HIF_PCI_CE_recv_data netbuf=%p  nbytes=%d\n", netbuf, nbytes));
                adf_nbuf_set_pktlen(netbuf, nbytes);
                if(pipe_callbacks->rxCompletionHandler) {
                    pipe_callbacks->rxCompletionHandler(pipe_callbacks->Context, netbuf, pipe_info->pipe_num);
                } else if(msg_callbacks->rxCompletionHandler) {
                    msg_callbacks->rxCompletionHandler(msg_callbacks->Context, netbuf, pipe_info->pipe_num);
                } else {
                    printk("%s Error : rxCompletionHandler is NULL\n",__func__);
                }
            }

            /* Recycle completion state back to the pipe it came from. */
            compl_state->next = NULL;
            compl_state->send_or_recv = HIF_CE_COMPLETE_FREE;
            adf_os_spin_lock(&pipe_info->completion_freeq_lock);
            if (pipe_info->completion_freeq_head) {
                pipe_info->completion_freeq_tail->next = compl_state;
            } else {
                pipe_info->completion_freeq_head = compl_state;
            }
            pipe_info->completion_freeq_tail = compl_state;
            pipe_info->num_sends_allowed += send_done;
            adf_os_spin_unlock(&pipe_info->completion_freeq_lock);
        }
#if 0
    }
#endif

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return 0;
}

/*
 * Install pending msg callbacks.
 *
 * TBDXXX: This hack is needed because upper layers install msg callbacks
 * for use with HTC before BMI is done; yet this HIF implementation
 * needs to continue to use BMI msg callbacks. Really, upper layers
 * should not register HTC callbacks until AFTER BMI phase.
 */
static void
hif_msg_callbacks_install(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    A_MEMCPY(&hif_state->msg_callbacks_current,
                 &hif_state->msg_callbacks_pending, sizeof(hif_state->msg_callbacks_pending));

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

int
HIFConfigureDevice(HIF_DEVICE *hif_device, HIF_DEVICE_CONFIG_OPCODE opcode,
                            void *config, u_int32_t configLen)
{
    int status = EOK;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    switch (opcode) {
        case HIF_DEVICE_GET_OS_DEVICE:
        {
            HIF_DEVICE_OS_DEVICE_INFO *info = (HIF_DEVICE_OS_DEVICE_INFO *)config;

            info->pOSDevice = (void *)sc->dev;
        }
        break;

        case HIF_DEVICE_GET_MBOX_BLOCK_SIZE:
            /* provide fake block sizes for mailboxes to satisfy upper layer software */
            ((u_int32_t *)config)[0] = 16;
            ((u_int32_t *)config)[1] = 16;
            ((u_int32_t *)config)[2] = 16;
            ((u_int32_t *)config)[3] = 16;
            break;

        case HIF_BMI_DONE:
        {
            printk("%s: BMI_DONE\n", __FUNCTION__); /* TBDXXX */
            break;
        }

        default:
            status = !EOK;
            break;

    }
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return status;
}

void
HIFClaimDevice(HIF_DEVICE *hif_device, void *claimedContext)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    hif_state->claimedContext = claimedContext;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
HIFReleaseDevice(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    hif_state->claimedContext = NULL;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
HIFGetDefaultPipe(HIF_DEVICE *hif_device, a_uint8_t *ULPipe, a_uint8_t *DLPipe)
{
    int ul_is_polled, dl_is_polled;

    (void)HIFMapServiceToPipe(
        hif_device, HTC_CTRL_RSVD_SVC,
        ULPipe, DLPipe,
        &ul_is_polled, &dl_is_polled);
}

/* TBDXXX - temporary mapping while we have too few CE's */
int
HIFMapServiceToPipe(HIF_DEVICE *hif_device, a_uint16_t ServiceId, a_uint8_t *ULPipe, a_uint8_t *DLPipe, int *ul_is_polled, int *dl_is_polled)
{
    int status = EOK;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    *dl_is_polled = 0; /* polling for received messages not supported */
    switch (ServiceId) {
        case HTT_DATA_MSG_SVC:
            /*
             * Host->target HTT gets its own pipe, so it can be polled
             * while other pipes are interrupt driven.
             */
            *ULPipe = 4;
#if QCA_OL_11AC_FAST_PATH
            /*
             * Pipe 5 is unused currently, use that for t->h HTT messages.
             */
            *DLPipe = 5;
#else   /* QCA_OL_11AC_FAST_PATH */
            /*
             * Use the same target->host pipe for HTC ctrl, HTC raw streams,
             * and HTT.
             */
            *DLPipe = 1;
#endif  /* QCA_OL_11AC_FAST_PATH */
            break;

        case HTC_CTRL_RSVD_SVC:
        case HTC_RAW_STREAMS_SVC:
            /*
             * Note: HTC_RAW_STREAMS_SVC is currently unused, and
             * HTC_CTRL_RSVD_SVC could share the same pipe as the
             * WMI services.  So, if another CE is needed, change
             * this to *ULPipe = 3, which frees up CE 0.
             */
            //*ULPipe = 3;
            *ULPipe = 0;
            *DLPipe = 1;
            break;

        case WMI_DATA_BK_SVC:
#ifdef EPPING_TEST
            /*
             * TODO: To avoid some confusions, better to introduce new EP-ping
             * service instead of using existed services. Until the main
             * framework support this, keep original design.
             */
            if (hif_epping_test) {
                *ULPipe = 4;
                *DLPipe = 1;
                break;
            }
#endif
        case WMI_DATA_BE_SVC:
        case WMI_DATA_VI_SVC:
        case WMI_DATA_VO_SVC:

        case WMI_CONTROL_SVC:
            *ULPipe = 3;
            *DLPipe = 2;
            break;

        /* pipe 5 unused   */
        /* pipe 6 reserved */
        /* pipe 7 reserved */

        default:
            status = !EOK;
            break;
    }
    *ul_is_polled = (host_CE_config[*ULPipe].flags & CE_ATTR_DISABLE_INTR) != 0;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return status;
}

/*
 * TBDXXX: Should be a function call specific to each Target-type.
 * This convoluted macro converts from Target CPU Virtual Address Space to CE Address Space.
 * As part of this process, we conservatively fetch the current PCIE_BAR. MOST of the time,
 * this should match the upper bits of PCI space for this device; but that's not guaranteed.
 */
#define TARG_CPU_SPACE_TO_CE_SPACE_IPQ4019(pci_addr, addr) \
    (A_PCI_READ32((pci_addr)+(WIFICMN_PCIE_BAR_REG_ADDRESS)) | ((addr) & 0xfffff))
#define TARG_CPU_SPACE_TO_CE_SPACE_AR900B(pci_addr, addr) \
    (A_PCI_READ32((pci_addr)+(WIFICMN_PCIE_BAR_REG_ADDRESS)) | 0x100000 | ((addr) & 0xfffff))
#define TARG_CPU_SPACE_TO_CE_SPACE_AR9888(pci_addr, addr) \
    (((A_PCI_READ32((pci_addr)+(SOC_CORE_BASE_ADDRESS|CORE_CTRL_ADDRESS)) & 0x7ff) << 21) \
                        | 0x100000 | ((addr) & 0xfffff))

/* Wait up to this many Ms for a Diagnostic Access CE operation to complete */
#define DIAG_ACCESS_CE_TIMEOUT_MS 10

struct valid_reg_range {
    int start;
    int end;
} dakota_soc_reg_range[] = {
    { 0x080000, 0x080000 },
    { 0x080020, 0x080020 },
    { 0x080028, 0x080050 },
    { 0x0800d4, 0x0800ec },
    { 0x08010c, 0x080118 },
    { 0x080284, 0x080290 },
    { 0x0802a8, 0x0802b8 },
    { 0x0802dc, 0x08030c },
    { 0x082000, 0x083fff }};

A_STATUS HIFDiagReadSoc_ipq4019(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT8 *data, int nbytes)
{
    int i=0;
    A_UINT32 *ptr= (A_UINT32 *)data;
    A_UINT8 *data_base = data;
    int range = 0;
    A_INT32 length;
    for(i=0; i<nbytes/4; i++) {
        ptr[i] = 0xdeadbeef;
    }
    for(range = 0; range < 9; range++) {
        length = dakota_soc_reg_range[range].end - dakota_soc_reg_range[range].start + 4;
        data = data_base + (dakota_soc_reg_range[range].start - 0x80000);
        address = dakota_soc_reg_range[range].start;
        HIFDiagReadMem(hif_device, address, data, length);
    }
    return EOK;
}

A_STATUS
HIFDiagReadSram_ipq4019(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT8 *data, int nbytes)
{
    struct HIF_CE_state *hif_state;
    struct ath_hif_pci_softc *sc;
    struct ol_ath_softc_net80211 *scn;
    A_target_id_t targid;
    A_STATUS status = EOK;
    CE_addr_t buf;
    unsigned int completed_nbytes, orig_nbytes, remaining_bytes;
    unsigned int id;
    unsigned int flags;
    struct CE_handle *ce_diag;
    CE_addr_t CE_data; /* Host buffer address in CE space */
    adf_os_dma_addr_t CE_data_base = 0;
    struct device *dev;
    void *data_buf = NULL;
    int i;
    OS_DMA_MEM_CONTEXT(diag_dmacontext)

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" %s\n",__FUNCTION__));


    hif_state = (struct HIF_CE_state *)hif_device;
    sc = hif_state->sc;
    scn = sc->scn;
    targid = hif_state->targid;
    ce_diag = hif_state->ce_diag;
    dev = sc->dev;
    if(scn->target_type != TARGET_TYPE_IPQ4019) {
            printk("ERROR: SRAM read function specific to Dakota\n");
            return A_ERROR;
    }

    A_TARGET_ACCESS_LIKELY(targid);

    /*
     * Allocate a temporary bounce buffer to hold caller's data
     * to be DMA'ed from Target. This guarantees
     *   1) 4-byte alignment
     *   2) Buffer in DMA-able space
     */
    orig_nbytes = nbytes;
    data_buf = (A_UCHAR *)HIF_MALLOC_DIAGMEM(scn->sc_osdev,
                                             orig_nbytes,
                                             &CE_data_base,
                                             &diag_dmacontext, 0);
    if (!data_buf) {
        status = A_NO_MEMORY;
        goto done;
    }
    adf_os_mem_set(data_buf, 0, orig_nbytes);
    HIF_DIAGMEM_SYNC(scn->sc_osdev, CE_data_base, orig_nbytes, BUS_DMA_FROMDEVICE, &diag_dmacontext);

    remaining_bytes = orig_nbytes;
    CE_data = CE_data_base;
    while (remaining_bytes) {
        nbytes = min(remaining_bytes, (u_int32_t)DIAG_TRANSFER_LIMIT);
        {
            status = CE_recv_buf_enqueue(ce_diag, NULL, CE_data);
            if (status != A_OK) {
                goto done;
            }
        }

        {
            A_TARGET_ACCESS_BEGIN(targid);
            address = TARG_CPU_SPACE_TO_CE_SPACE_IPQ4019(sc->mem, address);
            A_TARGET_ACCESS_END(targid);

            status = CE_send(ce_diag, NULL, (CE_addr_t)address, nbytes, 0, 0);
            if (status != EOK) {
                goto done;
            }
        }

        i=0;
        while (CE_completed_send_next(ce_diag, NULL, NULL, &buf, &completed_nbytes, &id) != A_OK) {
            A_MDELAY(1);
            if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
                status = A_EBUSY;
                goto done;
            }
        }
        if (nbytes != completed_nbytes) {
            status = A_ERROR;
            goto done;
        }
        if (buf != (CE_addr_t)address) {
            status = A_ERROR;
            goto done;
        }

        i=0;
        while (CE_completed_recv_next(ce_diag, NULL, NULL, &buf, &completed_nbytes, &id, &flags) != A_OK) {
            A_MDELAY(1);
            if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
                status = A_EBUSY;
                goto done;
            }
        }
        if (nbytes != completed_nbytes) {
            status = A_ERROR;
            goto done;
        }
        if (buf != CE_data) {
            status = A_ERROR;
            goto done;
        }

        remaining_bytes -= nbytes;
        address += nbytes;
        CE_data += nbytes;
    }

done:
    A_TARGET_ACCESS_UNLIKELY(targid);

    if (status == A_OK) {
        /* Copy data from allocated DMA buf to caller's buf */
        A_MEMCPY(data, data_buf, orig_nbytes);
    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s failure (0x%x)\n", __FUNCTION__, address));
    }

    if (data_buf) {
       HIF_FREE_DIAGMEM(scn->sc_osdev, orig_nbytes,
                        data_buf, CE_data_base, &diag_dmacontext);
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return status;
}


/*
 * Diagnostic read/write access is provided for startup/config/debug usage.
 * Caller must guarantee proper alignment, when applicable, and single user
 * at any moment.
 */

A_STATUS
HIFDiagReadMem(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT8 *data, int nbytes)
{
    struct HIF_CE_state *hif_state;
    struct ath_hif_pci_softc *sc;
    struct ol_ath_softc_net80211 *scn;
    A_UINT32 region = address & 0xfffff;
    A_UINT32 bar  = address & 0xfff00000;
    A_target_id_t targid;
    A_STATUS status = EOK;
    CE_addr_t buf;
    unsigned int completed_nbytes, orig_nbytes, remaining_bytes;
    unsigned int id;
    unsigned int flags;
    struct CE_handle *ce_diag;
    CE_addr_t CE_data; /* Host buffer address in CE space */
    adf_os_dma_addr_t CE_data_base = 0;
    int sramregion = 0;

    struct device *dev;
    void *data_buf = NULL;
    int i;
    OS_DMA_MEM_CONTEXT(diag_dmacontext)

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" %s\n",__FUNCTION__));


/* The below macros need to be moved to a common header file */
#define SRAM_BASE_ADDRESS 0xc0000
#define SRAM_END_ADDRESS 0x100000
#define WIFI0_IPQ4019_BAR 0xa000000
#define WIFI1_IPQ4019_BAR 0xa800000
    /* This code cannot handle reads to non-memory space. Redirect to the
     * register read fn but preserve the multi word read capability of this fn
     */
    if (address < FW_SRAM_ADDRESS) {

        if ((address & 0x3) || ((uintptr_t)data & 0x3)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d: address 0x%x, return from here\n", __FUNCTION__,__LINE__,address));
            return (-EIO);
        }

        while ((nbytes >= 4) &&
                (A_OK == (status = HIFDiagReadAccess(hif_device, address,
                                                     (A_UINT32*)data)))) {

            nbytes -= sizeof(A_UINT32);
            address+= sizeof(A_UINT32);
            data   += sizeof(A_UINT32);

        }

        return status;
    }


    hif_state = (struct HIF_CE_state *)hif_device;
    sc = hif_state->sc;
    scn = sc->scn;
    targid = hif_state->targid;
    ce_diag = hif_state->ce_diag;
    dev = sc->dev;

    if ((scn->target_type == TARGET_TYPE_IPQ4019) && (region >= SRAM_BASE_ADDRESS && region <=SRAM_END_ADDRESS)
                            && (bar == WIFI0_IPQ4019_BAR || bar == WIFI1_IPQ4019_BAR || bar == 0)) {
            sramregion = 1;
    }

    A_TARGET_ACCESS_LIKELY(targid);

    /*
     * Allocate a temporary bounce buffer to hold caller's data
     * to be DMA'ed from Target. This guarantees
     *   1) 4-byte alignment
     *   2) Buffer in DMA-able space
     */
    orig_nbytes = nbytes;
    data_buf = (A_UCHAR *)HIF_MALLOC_DIAGMEM(scn->sc_osdev,
                                             orig_nbytes,
                                             &CE_data_base,
                                             &diag_dmacontext, 0);
    if (!data_buf) {
        status = A_NO_MEMORY;
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:NO Memory.. address 0x%x,status %d \n", __FUNCTION__,__LINE__,address,status));
        goto done;
    }
    adf_os_mem_set(data_buf, 0, orig_nbytes);
    HIF_DIAGMEM_SYNC(scn->sc_osdev, CE_data_base, orig_nbytes, BUS_DMA_FROMDEVICE, &diag_dmacontext);

    remaining_bytes = orig_nbytes;
    CE_data = CE_data_base;
    while (remaining_bytes) {
        nbytes = min(remaining_bytes, (u_int32_t)DIAG_TRANSFER_LIMIT);
        {
            status = CE_recv_buf_enqueue(ce_diag, NULL, CE_data);
            if (status != A_OK) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:Enqueue failed.. address 0x%x,status %d \n", __FUNCTION__,__LINE__,address,status));
                goto done;
            }
        }

        { /* Request CE to send from Target(!) address to Host buffer */
            /*
             * The address supplied by the caller is in the
             * Target CPU virtual address space.
             *
             * In order to use this address with the diagnostic CE,
             * convert it from
             *    Target CPU virtual address space
             * to
             *    CE address space
             */
            A_TARGET_ACCESS_BEGIN(targid);
            if((scn->target_type == TARGET_TYPE_IPQ4019) && sramregion == 1) {
                address = TARG_CPU_SPACE_TO_CE_SPACE_IPQ4019(sc->mem, address);
            }
            else if (scn->is_ar900b) {
                address = TARG_CPU_SPACE_TO_CE_SPACE_AR900B(sc->mem, address);
            } else {
                address = TARG_CPU_SPACE_TO_CE_SPACE_AR9888(sc->mem, address);
            }
            A_TARGET_ACCESS_END(targid);

            status = CE_send(ce_diag, NULL, (CE_addr_t)address, nbytes, 0, 0);
            if (status != EOK) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:Send failed ..address 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
                goto done;
            }
        }

        i=0;
        while (CE_completed_send_next(ce_diag, NULL, NULL, &buf, &completed_nbytes, &id) != A_OK) {
            A_MDELAY(1);
            if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
                status = A_EBUSY;
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d: Timeout. 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
                goto done;
            }
        }
        if (nbytes != completed_nbytes) {
            status = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:#ERROR#address 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
            goto done;
        }
        if (buf != (CE_addr_t)address) {
            status = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:##ERROR##  address 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
            goto done;
        }

        i=0;
        while (CE_completed_recv_next(ce_diag, NULL, NULL, &buf, &completed_nbytes, &id, &flags) != A_OK) {
            A_MDELAY(1);
            if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
                status = A_EBUSY;
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:#timeout#  address 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
                goto done;
            }
        }
        if (nbytes != completed_nbytes) {
            status = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:###ERROR###  address 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
            goto done;
        }
        if (buf != CE_data) {
            status = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s:%d:####ERROR####  address 0x%x,status %d\n", __FUNCTION__,__LINE__,address,status));
            goto done;
        }

        remaining_bytes -= nbytes;
        address += nbytes;
        CE_data += nbytes;
    }

done:
    A_TARGET_ACCESS_UNLIKELY(targid);

    if (status == A_OK) {
        /* Copy data from allocated DMA buf to caller's buf */
        A_MEMCPY(data, data_buf, orig_nbytes);
    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s failure (0x%x)\n", __FUNCTION__, address));
    }

    if (data_buf) {
       HIF_FREE_DIAGMEM(scn->sc_osdev, orig_nbytes,
                        data_buf, CE_data_base, &diag_dmacontext);
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return status;
}

int
HIFDiagReadSram(HIF_DEVICE *hif_device, unsigned int sram_base, void *dst,  size_t len)
{
    int i=0;
    A_target_id_t targetid= ((struct HIF_CE_state*)hif_device)->targid;
    A_target_id_t pci_addr = TARGID_TO_PCI_ADDR(targetid);
    unsigned int target_bar0;

    if (!dst) return -ENOMEM;
    /* get the bar0 from target register */
#define SOC_PCIE_REGBASE 0x81030

    target_bar0 = A_PCI_READ32(TARGID_TO_PCI_ADDR(targetid)+SOC_PCIE_REGBASE /*__SOC_PCIE_REG_BASE_ADDRESS+PCIE_BAR0_START*/);

    /* clear off the bits 0-19 */
#define PCIE_BAR0_MASK 0xfffff
    target_bar0 = target_bar0 & ~PCIE_BAR0_MASK;

    for (i=0; i < len; i+=4) {
        A_PCI_WRITE32(pci_addr+0x4d00c, target_bar0+sram_base+i);
        *(unsigned int*)dst = A_PCI_READ32(pci_addr+0x4d010);
        dst += 4;
    }
    return EOK;
}
/* Read 4-byte aligned data from Target memory or register */
A_STATUS
HIFDiagReadAccess(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT32 *data)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;

    if (address >= DRAM_BASE_ADDRESS) { /* Assume range doesn't cross this boundary */
        return HIFDiagReadMem(hif_device, address, (A_UINT8 *)data, sizeof(A_UINT32));
    } else {
        A_target_id_t targid;

        targid = hif_state->targid;

        A_TARGET_ACCESS_BEGIN(targid);
        *data = A_TARGET_READ(targid, address);
        A_TARGET_ACCESS_END(targid);

        return A_OK;
    }
}

uint32_t
HIF_Read_Reg(void *ol_scn, A_UINT32 addr)
{
    uint32_t value;
    struct ol_ath_softc_net80211 *scn
            = (struct ol_ath_softc_net80211 *)ol_scn;

    HIFDiagReadAccess(scn->hif_hdl, addr, &value);

    return value;
}


A_STATUS
HIFDiagWriteMem(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT8 *data, int nbytes)
{
    struct HIF_CE_state *hif_state;
    struct ath_hif_pci_softc *sc;
    struct ol_ath_softc_net80211 *scn;
    A_target_id_t targid;
    A_STATUS status = A_OK;
    CE_addr_t buf;
    unsigned int completed_nbytes, orig_nbytes, remaining_bytes;
    unsigned int id;
    unsigned int flags;
    struct CE_handle *ce_diag;
    void *data_buf = NULL;
    CE_addr_t CE_data; /* Host buffer address in CE space */
    adf_os_dma_addr_t CE_data_base = 0;
    int i;
    OS_DMA_MEM_CONTEXT(diag_dmacontext)

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" %s\n",__FUNCTION__));

    hif_state = (struct HIF_CE_state *)hif_device;
    sc = hif_state->sc;
    scn = sc->scn;
    targid = hif_state->targid;
    ce_diag = hif_state->ce_diag;

    A_TARGET_ACCESS_LIKELY(targid);

    /*
     * Allocate a temporary bounce buffer to hold caller's data
     * to be DMA'ed to Target. This guarantees
     *   1) 4-byte alignment
     *   2) Buffer in DMA-able space
     */
    orig_nbytes = nbytes;
    data_buf = (A_UCHAR *)HIF_MALLOC_DIAGMEM(scn->sc_osdev,
                                             orig_nbytes,
                                             &CE_data_base,
                                             &diag_dmacontext, 0);
    if (!data_buf) {
        status = A_NO_MEMORY;
        goto done;
    }

    /* Copy caller's data to allocated DMA buf */
    A_MEMCPY(data_buf, data, orig_nbytes);
    HIF_DIAGMEM_SYNC(scn->sc_osdev, CE_data_base, orig_nbytes, BUS_DMA_TODEVICE, &diag_dmacontext);

    /*
     * The address supplied by the caller is in the
     * Target CPU virtual address space.
     *
     * In order to use this address with the diagnostic CE,
     * convert it from
     *    Target CPU virtual address space
     * to
     *    CE address space
     */
    A_TARGET_ACCESS_BEGIN(targid);
    if (scn->is_ar900b) {
        address = TARG_CPU_SPACE_TO_CE_SPACE_AR900B(sc->mem, address);
    } else {
        address = TARG_CPU_SPACE_TO_CE_SPACE_AR9888(sc->mem, address);
    }
    A_TARGET_ACCESS_END(targid);

    remaining_bytes = orig_nbytes;
    CE_data = CE_data_base;
    while (remaining_bytes) {
        nbytes = min(remaining_bytes, (u_int32_t)DIAG_TRANSFER_LIMIT);

        { /* Set up to receive directly into Target(!) address */
            status = CE_recv_buf_enqueue(ce_diag, NULL, address);
            if (status != A_OK) {
                goto done;
            }
        }

        {
            /*
             * Request CE to send caller-supplied data that
             * was copied to bounce buffer to Target(!) address.
             */
            status = CE_send(ce_diag, NULL, (CE_addr_t)CE_data, nbytes, 0, 0);
            if (status != A_OK) {
                goto done;
            }
        }

        i=0;
        while (CE_completed_send_next(ce_diag, NULL, NULL, &buf, &completed_nbytes, &id) != A_OK) {
            A_MDELAY(1);
            if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
                status = A_EBUSY;
                goto done;
            }
        }

        if (nbytes != completed_nbytes) {
            status = A_ERROR;
            goto done;
        }

        if (buf != CE_data) {
            status = A_ERROR;
            goto done;
        }

        i=0;
        while (CE_completed_recv_next(ce_diag, NULL, NULL, &buf, &completed_nbytes, &id, &flags) != A_OK) {
            A_MDELAY(1);
            if (i++ > DIAG_ACCESS_CE_TIMEOUT_MS) {
                status = A_EBUSY;
                goto done;
            }
        }

        if (nbytes != completed_nbytes) {
            status = A_ERROR;
            goto done;
        }

        if (buf != address) {
            status = A_ERROR;
            goto done;
        }

        remaining_bytes -= nbytes;
        address += nbytes;
        CE_data += nbytes;
    }

done:
    A_TARGET_ACCESS_UNLIKELY(targid);

    if (data_buf) {
        HIF_FREE_DIAGMEM(scn->sc_osdev, orig_nbytes,
                         data_buf, CE_data_base, &diag_dmacontext);
    }

    if (status != A_OK) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s failure (0x%x)\n", __FUNCTION__, address));
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return status;
}

/* Write 4B data to Target memory or register */
A_STATUS
HIFDiagWriteAccess(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT32 data)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;

    if (address >= DRAM_BASE_ADDRESS) { /* Assume range doesn't cross this boundary */
        A_UINT32 data_buf = data;

        return HIFDiagWriteMem(hif_device, address, (A_UINT8 *)&data_buf, sizeof(A_UINT32));
    } else {
        A_target_id_t targid;

        targid = hif_state->targid;

        A_TARGET_ACCESS_BEGIN(targid);
        A_TARGET_WRITE(targid, address, data);
        A_TARGET_ACCESS_END(targid);

        return A_OK;
    }
}

static int
hif_post_recv_buffers_for_pipe(struct HIF_CE_pipe_info *pipe_info)
{
    struct CE_handle *ce_hdl;
    adf_os_size_t buf_sz;
    struct HIF_CE_state *hif_state = pipe_info->HIF_CE_state;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    struct ol_ath_softc_net80211 *scn = sc->scn;
    a_status_t ret;

    buf_sz = pipe_info->buf_sz;
    if (buf_sz == 0) {
        /* Unused Copy Engine */
        return 0;
    }

    ce_hdl = pipe_info->ce_hdl;

#if QCA_PARTNER_DIRECTLINK_RX
    /*
     * For Direct Link RX
     * CE5 recv buffer is already enqueued by partner API.
     * So skip the same processing on wlan driver.
     */
    if (CE_is_directlink(ce_hdl)) {
        if (pipe_info->pipe_num == CE_HTT_MSG_CE) {
                return 0;
        }
    }
#endif

    adf_os_spin_lock_bh(&pipe_info->recv_bufs_needed_lock);
    while (atomic_read(&pipe_info->recv_bufs_needed) > 0) {
        CE_addr_t CE_data;  /* CE space buffer address*/
        adf_nbuf_t nbuf;
        int status;

        atomic_dec(&pipe_info->recv_bufs_needed);
        adf_os_spin_unlock_bh(&pipe_info->recv_bufs_needed_lock);

        nbuf = adf_nbuf_alloc(scn->adf_dev, buf_sz, 0, 4, FALSE);
        if (!nbuf) {
           AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s buf alloc error [%d] needed %d\n", __FUNCTION__, pipe_info->pipe_num, atomic_read(&pipe_info->recv_bufs_needed)));
            atomic_inc(&pipe_info->recv_bufs_needed);
            return 1;
        }

        /*
         * adf_nbuf_peek_header(nbuf, &data, &unused);
         * CE_data = dma_map_single(dev, data, buf_sz, DMA_FROM_DEVICE);
         */
        ret = adf_nbuf_map_nbytes_single(scn->adf_dev, nbuf, ADF_OS_DMA_FROM_DEVICE, buf_sz);

        if (unlikely(ret != A_STATUS_OK)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s mapping error\n", __FUNCTION__));
            adf_nbuf_free(nbuf);
            atomic_inc(&pipe_info->recv_bufs_needed);
            return 1;
        }

        CE_data = adf_nbuf_get_frag_paddr_lo(nbuf, 0);

        OS_SYNC_SINGLE(scn->sc_osdev, CE_data, buf_sz, BUS_DMA_FROMDEVICE, &CE_data);
        status = CE_recv_buf_enqueue(ce_hdl, (void *)nbuf, CE_data);
        A_ASSERT(status == EOK);

        adf_os_spin_lock_bh(&pipe_info->recv_bufs_needed_lock);
    }
    adf_os_spin_unlock_bh(&pipe_info->recv_bufs_needed_lock);

    return 0;
}

/*
 * Try to post all desired receive buffers for all pipes.
 * Returns 0 if all desired buffers are posted,
 * non-zero if were were unable to completely
 * replenish receive buffers.
 */
static int
hif_post_recv_buffers(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    A_target_id_t targid = hif_state->targid;
    int pipe_num, rv=0;

    A_TARGET_ACCESS_LIKELY(targid);
    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        struct HIF_CE_pipe_info *pipe_info;

        pipe_info = &hif_state->pipe_info[pipe_num];
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (sc->nss_wifi_ol_mode && (pipe_num == CE_HTT_MSG_CE)) {
            continue  ;
        }
#endif
        if (hif_post_recv_buffers_for_pipe(pipe_info)) {
            rv = 1;
            goto done;
        }
    }

done:
    A_TARGET_ACCESS_UNLIKELY(targid);

    return rv;
}

/*
 * This thread allocates and posts receive buffers.
 * TBDXXX: HIF probably should not allocate/own receive
 * buffers. Rather, the upper layers should allocate them
 * and pass them down -- in an OS-independent form --
 * through HTC to HIF to be posted.
 */
#if 0
int
hif_post_recv_buffers_thread(void *hif_dev)
{
    HIF_DEVICE *hif_device = (HIF_DEVICE *)hif_dev;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    //daemonize("hif_post_recv_buffers_thread");

    atomic_set(&hif_state->replenish_recv_buf_flag, 1);

    for(;;) {
        wait_event(hif_state->replenish_recv_buf_waitq,
                ((atomic_read(&hif_state->replenish_recv_buf_flag) > 0) || hif_state->shut_down));

        if (hif_state->shut_down) {
            hif_state->replenish_thread = NULL;
            complete_and_exit(&hif_state->post_recv_bufs_thread_done, 0);
            /* NOTREACHED */
        }

        atomic_set(&hif_state->replenish_recv_buf_flag, 0);
        if (hif_post_recv_buffers(hif_device)) {
            /*
             * We weren't able to finish the job.
             * wait for a while and try again.
             */
            A_MSLEEP(100); /* TBDXXX - adapt */
            atomic_inc(&hif_state->replenish_recv_buf_flag);
        }
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}
#endif

void
HIFStart(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ath_hif_pci_softc *sc = hif_state->sc;
#endif
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    hif_completion_thread_startup(hif_state);

    hif_msg_callbacks_install(hif_device);

    /* Post buffers once to start things off. */
    (void)hif_post_recv_buffers(hif_device);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (sc->nss_wifi_ol_mode) {
        osif_nss_ol_post_recv_buffer(sc);
    }
#endif

    hif_state->started=1;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

#if QCA_OL_11AC_FAST_PATH
void
hif_start_set(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

    hif_state->sc->hif_started = 1; /* For use in data path */
}

int
hif_state_check(struct ath_hif_pci_softc *sc)
{
    int retv;
    retv = CE_state_check(sc);
    return retv;
}
#endif /* QCA_OL_11AC_FAST_PATH */

void
hif_recv_buffer_cleanup_on_pipe(struct HIF_CE_pipe_info *pipe_info)
{
    struct ol_ath_softc_net80211 *scn;
    struct CE_handle *ce_hdl;
    u_int32_t buf_sz;
    struct HIF_CE_state *hif_state;
    struct ath_hif_pci_softc *sc;
    adf_nbuf_t netbuf;
    CE_addr_t CE_data;
    void *per_CE_context;

    buf_sz = pipe_info->buf_sz;
    if (buf_sz == 0) {
        /* Unused Copy Engine */
        return;
    }

    hif_state = pipe_info->HIF_CE_state;
    if (!hif_state->started) {
        return;
    }

    sc = hif_state->sc;
    scn = sc->scn;
    ce_hdl = pipe_info->ce_hdl;

    while (CE_revoke_recv_next(ce_hdl, &per_CE_context, (void **)&netbuf, &CE_data) == A_OK)
    {
        adf_nbuf_unmap_single(scn->adf_dev, netbuf, ADF_OS_DMA_FROM_DEVICE);
        adf_nbuf_free(netbuf);
    }
}

void
hif_send_buffer_cleanup_on_pipe(struct HIF_CE_pipe_info *pipe_info)
{
    struct ol_ath_softc_net80211 *scn;
    struct CE_handle *ce_hdl;
    struct HIF_CE_state *hif_state;
    struct ath_hif_pci_softc *sc;
    adf_nbuf_t netbuf;
    void *per_CE_context;
    CE_addr_t CE_data;
    unsigned int nbytes;
    unsigned int id;
    u_int32_t buf_sz;

    buf_sz = pipe_info->buf_sz;
    if (buf_sz == 0) {
        /* Unused Copy Engine */
        return;
    }

    hif_state = pipe_info->HIF_CE_state;
    if (!hif_state->started) {
        return;
    }

    sc = hif_state->sc;
    scn = sc->scn;
    ce_hdl = pipe_info->ce_hdl;

    while (CE_cancel_send_next(ce_hdl, &per_CE_context, (void **)&netbuf, &CE_data, &nbytes, &id) == A_OK)
    {
        if (netbuf != CE_SENDLIST_ITEM_CTXT)
        {
            /* Indicate the completion to higer layer to free the buffer */
            hif_state->msg_callbacks_current.txCompletionHandler(
                hif_state->msg_callbacks_current.Context, netbuf, id);
        }
    }
}

/*
 * Cleanup residual buffers for device shutdown:
 *    buffers that were enqueued for receive
 *    buffers that were to be sent
 * Note: Buffers that had completed but which were
 * not yet processed are on a completion queue. They
 * are handled when the completion thread shuts down.
 */
void
hif_buffer_cleanup(struct HIF_CE_state *hif_state)
{
    struct ath_hif_pci_softc *sc = hif_state->sc;
    int pipe_num;

    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        struct HIF_CE_pipe_info *pipe_info;

        pipe_info = &hif_state->pipe_info[pipe_num];

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if (((pipe_num == CE_HTT_MSG_CE) || (pipe_num == CE_HTT_TX_CE)) && sc->nss_wifi_ol_mode ) {
            continue;
        }
#endif

#if QCA_OL_11AC_FAST_PATH
        /*
         * Cleanly reap off as much as possible from the CE's
         * before unconditionally freeing the data.
         */
        if (pipe_num == CE_HTT_MSG_CE ||
            pipe_num == CE_HTT_TX_CE) {
            /* Try to reap as much from CE */
            /* Cleanup twice, is it required? */
            CE_per_engine_service_one(sc, CE_HTT_MSG_CE);
        } else
#endif /* QCA_OL_11AC_FAST_PATH */
        {
            hif_recv_buffer_cleanup_on_pipe(pipe_info);
            hif_send_buffer_cleanup_on_pipe(pipe_info);
        }
    }
}

void
HIFPause(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    int pipe_num;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    if (hif_state->shut_down) {
        return; /* already stopped or stopping */
    }

    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        struct HIF_CE_pipe_info *pipe_info;

        pipe_info = &hif_state->pipe_info[pipe_num];
        if (pipe_info->ce_hdl) {

            CE_pause(pipe_info->ce_hdl);
        }
    }
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
HIFStop(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    int pipe_num;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    if (hif_state->shut_down) {
        return; /* already stopped or stopping */
    }

    /* Cleanly shutdown driver's threads */
    hif_state->shut_down = 1;

    /* sync shutdown */
    hif_completion_thread_shutdown(hif_state);
    hif_completion_thread(hif_state);

    /*
     * At this point, asynchronous threads are stopped,
     * The Target should not DMA nor interrupt, Host code may
     * not initiate anything more.  So we just need to clean
     * up Host-side state.
     */

    ol_ath_diag_user_agent_fini(sc->scn);

    hif_buffer_cleanup(hif_state);

    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        struct HIF_CE_pipe_info *pipe_info;

        pipe_info = &hif_state->pipe_info[pipe_num];
        if (pipe_info->ce_hdl) {
            CE_fini(pipe_info->ce_hdl);
            pipe_info->ce_hdl = NULL;
            pipe_info->buf_sz = 0;
        }
    }
    hif_state->started=0;
#if QCA_OL_11AC_FAST_PATH
    hif_state->sc->hif_started =0;
#endif

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}


int
hifWaitForPendingRecv(HIF_DEVICE *device)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" %s\n",__FUNCTION__));
    /* Nothing needed -- CE layer will notify via recv completion */

    return EOK;
}

void
HIFShutDownDevice(HIF_DEVICE *hif_device)
{

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("+%s\n",__FUNCTION__));

    if (hif_device) {
        struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;

        HIFStop(hif_device);
        A_FREE(hif_state);
#if 0
    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("Full ath PCI HIF shutdown\n"));
        ath_pci_module_exit();
#endif
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("-%s\n",__FUNCTION__));
}

/* Track a BMI transaction that is in progress */
struct BMI_transaction {
    struct HIF_CE_state *hif_state;
    adf_os_mutex_t   bmi_transaction_sem;
    A_UINT8         *bmi_request_host;   /* Request BMI message in Host address space */
    CE_addr_t        bmi_request_CE;     /* Request BMI message in CE address space */
    u_int32_t         bmi_request_length; /* Length of BMI request */
    A_UINT8         *bmi_response_host;  /* Response BMI message in Host address space */
    CE_addr_t        bmi_response_CE;    /* Response BMI message in CE address space */
    unsigned int     bmi_response_length;/* Length of received response */
    unsigned int     bmi_timeout_ms;
};

/*
 * send/recv completion functions for BMI.
 * NB: The "net_buf" parameter is actually just a straight buffer, not an sk_buff.
 */
static void
HIF_BMI_send_done(struct CE_handle *copyeng, void *ce_context, void *transfer_context,
    CE_addr_t data, unsigned int nbytes, unsigned int transfer_id)
{
    struct BMI_transaction *transaction = (struct BMI_transaction *)transfer_context;
    struct ath_hif_pci_softc *sc = transaction->hif_state->sc;

    /*
     * If a response is anticipated, we'll complete the
     * transaction when the response has been received.
     * If no response is anticipated, complete the
     * transaction now.
     */
    if (!transaction->bmi_response_CE) {
        adf_os_mutex_release(sc->scn->adf_dev, &transaction->bmi_transaction_sem);
    }
}

static void
HIF_BMI_recv_data(struct CE_handle *copyeng, void *ce_context, void *transfer_context,
    CE_addr_t data, unsigned int nbytes, unsigned int transfer_id, unsigned int flags)
{
    struct BMI_transaction *transaction = (struct BMI_transaction *)transfer_context;
    struct ath_hif_pci_softc *sc = transaction->hif_state->sc;

    transaction->bmi_response_length = nbytes;
    adf_os_mutex_release(sc->scn->adf_dev, &transaction->bmi_transaction_sem);
}

int
HIFExchangeBMIMsg(HIF_DEVICE *hif_device,
                  A_UINT8    *bmi_request,
                  u_int32_t   request_length,
                  A_UINT8    *bmi_response,
                  u_int32_t   *bmi_response_lengthp,
                  u_int32_t   TimeoutMS)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    struct ol_ath_softc_net80211 *scn = sc->scn;
    //struct device *dev = sc->dev;
    struct HIF_CE_pipe_info *send_pipe_info = &(hif_state->pipe_info[BMI_CE_NUM_TO_TARG]);
    struct CE_handle *ce_send = send_pipe_info->ce_hdl;
    CE_addr_t CE_request, CE_response = 0;
    A_target_id_t targid = hif_state->targid;
    struct BMI_transaction *transaction = NULL;
    int status = EOK;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, (" %s\n",__FUNCTION__));

    transaction = (struct BMI_transaction *)A_MALLOC(sizeof(*transaction));
    if (unlikely(!transaction)) {
        return -ENOMEM;
    }

    A_TARGET_ACCESS_LIKELY(targid);

    /* Initialize bmi_transaction_sem to block */
    adf_os_init_mutex(&transaction->bmi_transaction_sem);
    adf_os_mutex_acquire(scn->adf_dev, &transaction->bmi_transaction_sem);

    transaction->hif_state = hif_state;
    transaction->bmi_request_host = bmi_request;
    transaction->bmi_request_length = request_length;
    transaction->bmi_response_length = 0;
    transaction->bmi_timeout_ms = TimeoutMS;

    /*
     * CE_request = dma_map_single(dev, (void *)bmi_request, request_length, DMA_TO_DEVICE);
     */
    CE_request = scn->BMICmd_pa;
#if 0
    if (unlikely(DMA_MAPPING_ERROR(dev, CE_request))) {
        return A_NO_RESOURCE;
    }
#endif
    transaction->bmi_request_CE = CE_request;

    if (bmi_response) {
        struct HIF_CE_pipe_info *recv_pipe_info = &(hif_state->pipe_info[BMI_CE_NUM_TO_HOST]);
        struct CE_handle *ce_recv = recv_pipe_info->ce_hdl;

        /*
         * CE_response = dma_map_single(dev, bmi_response, BMI_DATASZ_MAX, DMA_FROM_DEVICE);
         */
        CE_response = scn->BMIRsp_pa;
#if 0
        if (unlikely(DMA_MAPPING_ERROR(dev, CE_response))) {
            dma_unmap_single(dev, CE_request, request_length, DMA_TO_DEVICE);
            return A_NO_RESOURCE;
        }
#endif
        transaction->bmi_response_host = bmi_response;
        transaction->bmi_response_CE = CE_response;
        /* dma_cache_sync(dev, bmi_response, BMI_DATASZ_MAX, DMA_FROM_DEVICE); */
        OS_SYNC_SINGLE(scn->sc_osdev, CE_response, BMI_DATASZ_MAX, BUS_DMA_FROMDEVICE,
                        OS_GET_DMA_MEM_CONTEXT(scn, bmirsp_dmacontext));
        CE_recv_buf_enqueue(ce_recv, transaction, transaction->bmi_response_CE);
        /* NB: see HIF_BMI_recv_done */
    } else {
        transaction->bmi_response_host = NULL;
        transaction->bmi_response_CE = 0;
    }

    /* dma_cache_sync(dev, bmi_request, request_length, DMA_TO_DEVICE); */
    OS_SYNC_SINGLE(scn->sc_osdev, CE_request, request_length, BUS_DMA_TODEVICE,
                    OS_GET_DMA_MEM_CONTEXT(scn, bmicmd_dmacontext));

    status = CE_send(ce_send, transaction, CE_request, request_length, -1, 0);
    ASSERT(status == EOK);
    /* NB: see HIF_BMI_send_done */

    /* TBDXXX: handle timeout */

    /* Wait for BMI request/response transaction to complete */
#if defined(RPAC51)
#define BMI_TIMEOUT 1000
#else
#define BMI_TIMEOUT 10000
#endif
    if (adf_os_mutex_acquire_timeout(scn->adf_dev,
                             &transaction->bmi_transaction_sem, BMI_TIMEOUT)) {
        printk("%s bmi_transaction_sem not acquired status = 0x%x BMI_TIMEOUT=%d \n", __func__, status,BMI_TIMEOUT);
        status = A_ERROR;
    }

    if (bmi_response) {
     //   bus_unmap_single(scn->sc_osdev, CE_response, BMI_DATASZ_MAX, BUS_DMA_FROMDEVICE);
        if ((status == EOK) && bmi_response_lengthp) {
            *bmi_response_lengthp = transaction->bmi_response_length;
        }
    }

    /* dma_unmap_single(dev, transaction->bmi_request_CE, request_length, DMA_TO_DEVICE); */
    //bus_unmap_single(scn->sc_osdev, transaction->bmi_request_CE, request_length, BUS_DMA_TODEVICE);

    if (status != EOK) {
        CE_addr_t unused_buffer;
        unsigned int unused_nbytes;
        unsigned int unused_id;

        CE_cancel_send_next(ce_send, NULL, NULL, &unused_buffer, &unused_nbytes, &unused_id);
    }

    A_TARGET_ACCESS_UNLIKELY(targid);
    A_FREE(transaction);
    return status;
}

#if 0
int
_HIF_PCI_CE_notifyDeviceInsertedHandler(void *hif_dev)
{
    HIF_DEVICE *hif_device = (HIF_DEVICE *)hif_dev;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    //daemonize("HIF_PCI_CE_notifyDeviceInsertedHandler");
    HIF_osDrvcallback.deviceInsertedHandler(HIF_osDrvcallback.context, hif_device);
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    complete_and_exit(NULL, 0);

    return 0;
}
#endif

#if 0 /* CE_PCI TABLE */
/*
 * NOTE: the table below is out of date, though still a useful reference.
 * Refer to target_service_to_CE_map and HIFMapServiceToPipe for the actual
 * mapping of HTC services to HIF pipes.
 */
/*
 * This authoritative table defines Copy Engine configuration and the mapping
 * of services/endpoints to CEs.  A subset of this information is passed to
 * the Target during startup as a prerequisite to entering BMI phase.
 * See:
 *    target_service_to_CE_map - Target-side mapping
 *    HIFMapServiceToPipe      - Host-side mapping
 *    target_CE_config         - Target-side configuration
 *    host_CE_config           - Host-side configuration
 */
=============================================================================
Purpose    | Service / Endpoint   | CE   | Dire | Xfer     | Xfer
           |                      |      | ctio | Size     | Frequency
           |                      |      | n    |          |
=============================================================================
tx         | HTT_DATA (downlink)  | CE 0 | h->t | medium - | very frequent
descriptor |                      |      |      | O(100B)  | and regular
download   |                      |      |      |          |
-----------------------------------------------------------------------------
rx         | HTT_DATA (uplink)    | CE 1 | t->h | small -  | frequent and
indication |                      |      |      | O(10B)   | regular
upload     |                      |      |      |          |
-----------------------------------------------------------------------------
MSDU       | DATA_BK (uplink)     | CE 2 | t->h | large -  | rare
upload     |                      |      |      | O(1000B) | (frequent
e.g. noise |                      |      |      |          | during IP1.0
packets    |                      |      |      |          | testing)
-----------------------------------------------------------------------------
MSDU       | DATA_BK (downlink)   | CE 3 | h->t | large -  | very rare
download   |                      |      |      | O(1000B) | (frequent
e.g.       |                      |      |      |          | during IP1.0
misdirecte |                      |      |      |          | testing)
d EAPOL    |                      |      |      |          |
packets    |                      |      |      |          |
-----------------------------------------------------------------------------
n/a        | DATA_BE, DATA_VI     | CE 2 | t->h |          | never(?)
           | DATA_VO (uplink)     |      |      |          |
-----------------------------------------------------------------------------
n/a        | DATA_BE, DATA_VI     | CE 3 | h->t |          | never(?)
           | DATA_VO (downlink)   |      |      |          |
-----------------------------------------------------------------------------
WMI events | WMI_CONTROL (uplink) | CE 4 | t->h | medium - | infrequent
           |                      |      |      | O(100B)  |
-----------------------------------------------------------------------------
WMI        | WMI_CONTROL          | CE 5 | h->t | medium - | infrequent
messages   | (downlink)           |      |      | O(100B)  |
           |                      |      |      |          |
-----------------------------------------------------------------------------
n/a        | HTC_CTRL_RSVD,       | CE 1 | t->h |          | never(?)
           | HTC_RAW_STREAMS      |      |      |          |
           | (uplink)             |      |      |          |
-----------------------------------------------------------------------------
n/a        | HTC_CTRL_RSVD,       | CE 0 | h->t |          | never(?)
           | HTC_RAW_STREAMS      |      |      |          |
           | (downlink)           |      |      |          |
-----------------------------------------------------------------------------
diag       | none (raw CE)        | CE 7 | t<>h |    4     | Diag Window
           |                      |      |      |          | infrequent
=============================================================================
#endif

/*
 * Map from service/endpoint to Copy Engine.
 * This table is derived from the CE_PCI TABLE, above.
 * It is passed to the Target at startup for use by firmware.
 */
static struct service_to_pipe target_service_to_CE_map_wlan[] = {
    {
        WMI_DATA_VO_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        3,
    },
    {
        WMI_DATA_VO_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        2,
    },
    {
        WMI_DATA_BK_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        3,
    },
    {
        WMI_DATA_BK_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        2,
    },
    {
        WMI_DATA_BE_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        3,
    },
    {
        WMI_DATA_BE_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        2,
    },
    {
        WMI_DATA_VI_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        3,
    },
    {
        WMI_DATA_VI_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        2,
    },
    {
        WMI_CONTROL_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        3,
    },
    {
        WMI_CONTROL_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        2,
    },
    {
        HTC_CTRL_RSVD_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        0, /* could be moved to 3 (share with WMI) */
    },
    {
        HTC_CTRL_RSVD_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        1,
    },
    {
        HTC_RAW_STREAMS_SVC, /* not currently used */
        PIPEDIR_OUT, /* out = UL = host -> target */
        0,
    },
    {
        HTC_RAW_STREAMS_SVC, /* not currently used */
        PIPEDIR_IN,  /* in = DL = target -> host */
        1,
    },
    {
        HTT_DATA_MSG_SVC,
        PIPEDIR_OUT, /* out = UL = host -> target */
        4,
    },
#if QCA_OL_11AC_FAST_PATH
    {
        HTT_DATA_MSG_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        5,
    },
#else /* QCA_OL_11AC_FAST_PATH */
    {
        HTT_DATA_MSG_SVC,
        PIPEDIR_IN,  /* in = DL = target -> host */
        1,
    },
#endif /* QCA_OL_11AC_FAST_PATH */

    /* (Additions here) */

    { /* Must be last */
        0,
        0,
        0,
    },
};

static struct service_to_pipe *target_service_to_CE_map = target_service_to_CE_map_wlan;
static int target_service_to_CE_map_sz = sizeof(target_service_to_CE_map_wlan);

#ifdef EPPING_TEST
static struct service_to_pipe target_service_to_CE_map_epping[] = {
    { WMI_DATA_VO_SVC, PIPEDIR_OUT, 3, },     /* out = UL = host -> target */
    { WMI_DATA_VO_SVC, PIPEDIR_IN, 2, },      /* in = DL = target -> host */
    { WMI_DATA_BK_SVC, PIPEDIR_OUT, 4, },     /* out = UL = host -> target */
    { WMI_DATA_BK_SVC, PIPEDIR_IN, 1, },      /* in = DL = target -> host */
    { WMI_DATA_BE_SVC, PIPEDIR_OUT, 3, },     /* out = UL = host -> target */
    { WMI_DATA_BE_SVC, PIPEDIR_IN, 2, },      /* in = DL = target -> host */
    { WMI_DATA_VI_SVC, PIPEDIR_OUT, 3, },     /* out = UL = host -> target */
    { WMI_DATA_VI_SVC, PIPEDIR_IN, 2, },      /* in = DL = target -> host */
    { WMI_CONTROL_SVC, PIPEDIR_OUT, 3, },     /* out = UL = host -> target */
    { WMI_CONTROL_SVC, PIPEDIR_IN, 2, },      /* in = DL = target -> host */
    { HTC_CTRL_RSVD_SVC, PIPEDIR_OUT, 0, },   /* out = UL = host -> target */
    { HTC_CTRL_RSVD_SVC, PIPEDIR_IN, 1, },    /* in = DL = target -> host */
    { HTC_RAW_STREAMS_SVC, PIPEDIR_OUT, 0, }, /* out = UL = host -> target */
    { HTC_RAW_STREAMS_SVC, PIPEDIR_IN, 1, },  /* in = DL = target -> host */
    { HTT_DATA_MSG_SVC, PIPEDIR_OUT, 4, },    /* out = UL = host -> target */
    { HTT_DATA_MSG_SVC, PIPEDIR_IN, 1, },     /* in = DL = target -> host */
    { 0, 0, 0, },                             /* Must be last */
};
#endif

#if 0 /* SHAN TBD */
A_COMPILE_TIME_ASSERT(svcmap_sz_ok, sizeof(target_service_to_CE_map)/sizeof(*target_service_to_CE_map) <= PIPE_TO_CE_MAP_CNT);
#endif


/*
 * Send an interrupt to the device to wake up the Target CPU
 * so it has an opportunity to notice any changed state.
 */
void
HIF_wake_target_cpu(struct ath_hif_pci_softc *sc)
{
        A_STATUS rv;
        A_UINT32 core_ctrl;

        rv = HIFDiagReadAccess(sc->hif_device, SOC_CORE_BASE_ADDRESS|CORE_CTRL_ADDRESS, &core_ctrl);
        ASSERT(rv == A_OK);

        core_ctrl |= CORE_CTRL_CPU_INTR_MASK; /* A_INUM_FIRMWARE interrupt to Target CPU */

        rv = HIFDiagWriteAccess(sc->hif_device, SOC_CORE_BASE_ADDRESS|CORE_CTRL_ADDRESS, core_ctrl);
        ASSERT(rv == A_OK);
}


/*
 * Called from PCI layer whenever a new PCI device is probed.
 * Initializes per-device HIF state and notifies the main
 * driver that a new HIF device is present.
 */

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
int radio_id=0;
int nssradio_id=0;
#endif
int
HIF_PCIDeviceProbed(hif_handle_t hif_hdl)
{
    struct HIF_CE_state *hif_state;
    struct HIF_CE_pipe_info *pipe_info;
    int pipe_num;
    A_STATUS rv;
    struct ath_hif_pci_softc *sc = hif_hdl;
    struct ol_ath_softc_net80211 *scn = sc->scn;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    hif_state = (struct HIF_CE_state *)A_MALLOC(sizeof(*hif_state));
    if (!hif_state) {
        return -ENOMEM;
    }

    A_MEMZERO(hif_state, sizeof(*hif_state));

    sc->hif_device = scn->hif_hdl = (HIF_DEVICE *)hif_state;
    hif_state->sc = sc;

    adf_os_spinlock_init(&hif_state->keep_awake_lock);

    adf_os_atomic_init(&hif_state->hif_thread_idle);
    adf_os_atomic_inc(&hif_state->hif_thread_idle);

    hif_state->keep_awake_count = 0;

    hif_state->fw_indicator_address = FW_INDICATOR_ADDRESS;
    hif_state->targid = A_TARGET_ID(sc->hif_device);
#if  CONFIG_ATH_PCIE_MAX_PERF
    if(scn->target_type != TARGET_TYPE_IPQ4019) {
        /* Force AWAKE forever */
        HIFTargetSleepStateAdjust(hif_state->targid, FALSE, TRUE);
    }
#endif

    if (scn->is_ar900b) {
        host_CE_config = host_CE_config_wlan_ar900b;
        target_CE_config = target_CE_config_wlan_ar900b;
        target_CE_config_sz = sizeof(target_CE_config_wlan_ar900b);
    }

#ifdef EPPING_TEST
    /* Use EP-ping CE config if EP-ping is enabled */
    if (hif_epping_test) {
        host_CE_config = host_CE_config_epping;
        target_CE_config = target_CE_config_epping;
        target_CE_config_sz = sizeof(target_CE_config_epping);
        target_service_to_CE_map = target_service_to_CE_map_epping;
        target_service_to_CE_map_sz = sizeof(target_service_to_CE_map_epping);
    }
#endif

    A_TARGET_ACCESS_LIKELY(hif_state->targid); /* During CE initializtion */


#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (!(scn->nss_enabled)) {
        sc->nss_wifi_ol_mode = 0;
        sc->nss_wifiol_id = -1;
        scn->nss_wifiol_id = sc->nss_wifiol_id;

        if (nss_cmn_get_nss_enabled() == true) {
            if (nss_wifi_olcfg & (1 << radio_id )) {
                if ((scn->target_type == TARGET_TYPE_AR900B)
                        || (scn->target_type == TARGET_TYPE_QCA9984) ){
                    sc->nss_wifi_ol_mode = 1;
                    sc->nss_wifiol_id = nssradio_id++;
                    scn->nss_wifiol_id = sc->nss_wifiol_id;
                    sc->nss_wifiol_bypass_nw_process = (nss_wifi_ol_skip_nw_process & (1 << radio_id));
                } else {
                    adf_os_print("Target type not supported in NSS wifi offload %x",scn->target_type);
                }
            }
        }
        adf_os_print("nss register id %d offload mode enabled = %d nss config %x Target Type %x host radio id %d \n",
                sc->nss_wifiol_id, sc->nss_wifi_ol_mode, nss_wifi_olcfg, scn->target_type, radio_id);
        radio_id++;
        scn->nss_enabled = true;
    }
#endif

    for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
        struct CE_attr *attr;

        pipe_info = &hif_state->pipe_info[pipe_num];
        pipe_info->pipe_num = pipe_num;
        pipe_info->HIF_CE_state = hif_state;
        attr = &host_CE_config[pipe_num];
        pipe_info->ce_hdl = CE_init(sc, pipe_num, attr);
        /*ASSERT(pipe_info->ce_hdl != NULL);*/
        if (!pipe_info->ce_hdl) {
            rv = -ENOMEM;
            goto done;
        }

        if (pipe_num == CE_DIAG_PIPE) {
            /* Reserve CE 7 for Diagnostic Window support */
            hif_state->ce_diag = hif_state->pipe_info[pipe_num].ce_hdl;
            continue;

        }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
        if ((pipe_info->pipe_num == CE_HTT_MSG_CE) && sc->nss_wifi_ol_mode ) {
            continue ;
        }
#endif

        pipe_info->buf_sz = (adf_os_size_t)(attr->src_sz_max);
        adf_os_spinlock_init(&pipe_info->recv_bufs_needed_lock);
        if (attr->dest_nentries > 0) {
            unsigned int dest_nentries;

#if !QCA_OL_11AC_FAST_PATH
            dest_nentries = attr->dest_nentries-1;
#else /* QCA_OL_11AC_FAST_PATH */
            /*
             * CE_HTT_MSG_CE is a special case, where we
             * reuse all the message buffers. Hence we
             * have to post all the entries in the pipe, even,
             * in the beginning unlike for other CE pipes where
             * one less than dest_nentries are filled in the
             * beginning.
             */
            if (pipe_info->pipe_num == CE_HTT_MSG_CE) {
                dest_nentries = attr->dest_nentries;
            } else {
                dest_nentries = attr->dest_nentries-1;
            }
#endif /* QCA_OL_11AC_FAST_PATH */
            atomic_set(&pipe_info->recv_bufs_needed, dest_nentries);
        } else {
            atomic_set(&pipe_info->recv_bufs_needed, 0);
        }
    }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (sc->nss_wifi_ol_mode) {
        osif_nss_ol_wifi_init(sc);
    }
#endif
    /*
     * Initially, establish CE completion handlers for use with BMI.
     * These are overwritten with generic handlers after we exit BMI phase.
     */
    pipe_info = &hif_state->pipe_info[BMI_CE_NUM_TO_TARG];
    CE_send_cb_register(pipe_info->ce_hdl, HIF_BMI_send_done, pipe_info, 0);
    pipe_info = &hif_state->pipe_info[BMI_CE_NUM_TO_HOST];
    CE_recv_cb_register(pipe_info->ce_hdl, HIF_BMI_recv_data, pipe_info);

    { /* Download to Target the CE Configuration and the service-to-CE map */
        A_UINT32 interconnect_targ_addr = host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_interconnect_state));
        A_UINT32 pcie_state_targ_addr = 0;
        A_UINT32 pipe_cfg_targ_addr = 0;
        A_UINT32 svc_to_pipe_map = 0;
        A_UINT32 pcie_config_flags = 0;

        /* Supply Target-side CE configuration */
        rv = HIFDiagReadAccess(sc->hif_device, interconnect_targ_addr, &pcie_state_targ_addr);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed get pcie state addr (%d)\n", rv));
            goto done;
        }
        if (pcie_state_targ_addr == 0) {
            rv = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed pcie state addr is 0\n"));
            goto done;
        }

        rv = HIFDiagReadAccess(sc->hif_device,
                               pcie_state_targ_addr+offsetof(struct pcie_state_s, pipe_cfg_addr),
                               &pipe_cfg_targ_addr);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed get pipe cfg addr (%d)\n", rv));
            goto done;
        }
        if (pipe_cfg_targ_addr == 0) {
            rv = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed pipe cfg addr is 0\n"));
            goto done;
        }

        rv = HIFDiagWriteMem(sc->hif_device, pipe_cfg_targ_addr, (A_UINT8 *)target_CE_config, target_CE_config_sz);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed write pipe cfg (%d)\n", rv));
            goto done;
        }

        rv = HIFDiagReadAccess(sc->hif_device,
                               pcie_state_targ_addr+offsetof(struct pcie_state_s, svc_to_pipe_map),
                               &svc_to_pipe_map);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed get svc/pipe map (%d)\n", rv));
            goto done;
        }
        if (svc_to_pipe_map == 0) {
            rv = A_ERROR;
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed svc_to_pipe map is 0\n"));
            goto done;
        }

        rv = HIFDiagWriteMem(sc->hif_device,
                             svc_to_pipe_map,
                             (A_UINT8 *)target_service_to_CE_map,
                             target_service_to_CE_map_sz);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed write svc/pipe map (%d)\n", rv));
            goto done;
        }

        rv = HIFDiagReadAccess(sc->hif_device,
                               pcie_state_targ_addr+offsetof(struct pcie_state_s, config_flags),
                               &pcie_config_flags);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed get pcie config_flags (%d)\n", rv));
            goto done;
        }

#if (CONFIG_PCIE_ENABLE_L1_CLOCK_GATE)
        pcie_config_flags |= PCIE_CONFIG_FLAG_ENABLE_L1;
#else
        pcie_config_flags &= ~PCIE_CONFIG_FLAG_ENABLE_L1;
#endif /* CONFIG_PCIE_ENABLE_L1_CLOCK_GATE */
        pcie_config_flags |= PCIE_CONFIG_FLAG_CLK_SWITCH_WAIT;
#if (CONFIG_PCIE_ENABLE_AXI_CLK_GATE)
        pcie_config_flags |= PCIE_CONFIG_FLAG_AXI_CLK_GATE;
#endif
        rv = HIFDiagWriteMem(sc->hif_device,
                             pcie_state_targ_addr+offsetof(struct pcie_state_s, config_flags),
                             (A_UINT8 *)&pcie_config_flags,
                             sizeof(pcie_config_flags));
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed write pcie config_flags (%d)\n", rv));
            goto done;
        }
    }

    { /* configure early allocation */
        A_UINT32 ealloc_value;
        A_UINT32 ealloc_targ_addr = host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_early_alloc));

        rv = HIFDiagReadAccess(sc->hif_device, ealloc_targ_addr, &ealloc_value);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed get early alloc val (%d)\n", rv));
            goto done;
        }

        /* 1 bank is switched to IRAM */
        ealloc_value |= ((HI_EARLY_ALLOC_MAGIC << HI_EARLY_ALLOC_MAGIC_SHIFT) & HI_EARLY_ALLOC_MAGIC_MASK);
        ealloc_value |= ((1 << HI_EARLY_ALLOC_IRAM_BANKS_SHIFT) & HI_EARLY_ALLOC_IRAM_BANKS_MASK);
        rv = HIFDiagWriteAccess(sc->hif_device, ealloc_targ_addr, ealloc_value);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed set early alloc val (%d)\n", rv));
            goto done;
        }
    }

    // Skip PLL initiailization
    {
        A_UINT32 flag2_value = 0;
        extern int32_t frac, intval, ar900b_20_targ_clk;
        A_UINT32 flag2_targ_addr = host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_skip_clock_init));

        if ((ar900b_20_targ_clk != -1) && (frac != -1) && (intval != -1)) {
            HIFDiagReadAccess(sc->hif_device, flag2_targ_addr, &flag2_value);
            printk("\n Setting clk_override  \n");
            flag2_value |= CLOCK_OVERRIDE;

            HIFDiagWriteAccess(sc->hif_device, flag2_targ_addr, flag2_value);
            printk("\n CLOCK PLL val set %d \n", flag2_value);
        } else {
            printk(KERN_INFO"\n CLOCK PLL skipped \n");
        }
    }
    /*
     * Default PLL custom values disabled
     * hi_clock_info has the address for FRAC
     * FRAC value to be written to *hi_clock_info
     * intval value to be written to (*hi_clock_info + 4)
     */
#if defined (CONFIG_AR900B_SUPPORT) || defined (CONFIG_AR9888_SUPPORT)
    if (scn->target_type == TARGET_TYPE_AR900B || scn->target_type == TARGET_TYPE_QCA9984 || scn->target_type == TARGET_TYPE_QCA9888) {
            extern int32_t frac, intval, ar900b_20_targ_clk, qca9888_20_targ_clk;

            /* for AR9980_2.0, 300 mhz clock is used, right now we assume this
             * would be supplied through module parameters, if not supplied
             * assumed default or same behavior as 1.0.  Assume 1.0 clock can't
             * be tuned, reset to defaults
             */
            printk(KERN_INFO"%s: setting the target pll frac %x intval %x\n", __func__,
                    frac, intval);

            /* do not touch frac, and int val, let them be default -1,
             * if desired, host can supply these through module params
             */
            if (frac != -1 || intval != -1) {
                    A_UINT32 flag2_value = 0;
                    A_UINT32 flag2_targ_addr;

                    flag2_targ_addr= host_interest_item_address(scn->target_type,
                            offsetof(struct host_interest_s, hi_clock_info));
                    HIFDiagReadAccess(sc->hif_device, flag2_targ_addr, &flag2_value);
                    printk("\n ====> FRAC Val %x Address %x\n", frac, flag2_value);
                    HIFDiagWriteAccess(sc->hif_device, flag2_value, frac);
                    printk("\n INT Val %x  Address %x\n", intval, flag2_value + 4);
                    HIFDiagWriteAccess(sc->hif_device, flag2_value + 4, intval);

            } else {
                printk(KERN_INFO"%s: no frac provided, skipping pre-configuring PLL\n",
                        __func__);
            }

            /* for 2.0 write 300 mhz into hi_desired_cpu_speed_hz  */
            if ((scn->target_type == TARGET_TYPE_AR900B) && (scn->target_revision == AR900B_REV_2) && ar900b_20_targ_clk != -1) {
                A_UINT32 flag2_value = 0;
                A_UINT32 flag2_targ_addr;

                flag2_targ_addr= host_interest_item_address(scn->target_type,
                        offsetof(struct host_interest_s, hi_desired_cpu_speed_hz));
                HIFDiagReadAccess(sc->hif_device, flag2_targ_addr, &flag2_value);
                printk("\n ====> hi_desired_cpu_speed_hz Address %x\n", flag2_value);
                HIFDiagWriteAccess(sc->hif_device, flag2_targ_addr, ar900b_20_targ_clk/*300000000u*/);
            } else if (scn->target_type == TARGET_TYPE_QCA9888) {
                A_UINT32 flag2_targ_addr;

                if(200000000u != qca9888_20_targ_clk) {
                    qca9888_20_targ_clk = 300000000u;/*Setting the target clock speed to 300 mhz*/
                }

                flag2_targ_addr= host_interest_item_address(scn->target_type,
                        offsetof(struct host_interest_s, hi_desired_cpu_speed_hz));
                HIFDiagWriteAccess(sc->hif_device, flag2_targ_addr, qca9888_20_targ_clk);
            } else {
                printk(KERN_INFO"%s: targ_clk is not provided, skipping pre-configuring PLL\n",
                        __func__);
            }
    }
    else
    {
        extern int32_t frac, intval;
        if(frac != -1 || intval != -1)
        {
                A_UINT32 flag2_value = 0;
                A_UINT32 flag2_targ_addr = host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_clock_info));
                HIFDiagReadAccess(sc->hif_device, flag2_targ_addr, &flag2_value);
                printk("\n ====> FRAC Val %x Address %x\n", frac, flag2_value);
                HIFDiagWriteAccess(sc->hif_device, flag2_value, frac);
                printk("\n INT Val %x  Address %x\n", intval, flag2_value + 4);
                HIFDiagWriteAccess(sc->hif_device, flag2_value + 4, intval);
        }
    }
#endif

    { /* Tell Target to proceed with initialization */
        A_UINT32 flag2_value;
        A_UINT32 flag2_targ_addr = host_interest_item_address(scn->target_type, offsetof(struct host_interest_s, hi_option_flag2));

        rv = HIFDiagReadAccess(sc->hif_device, flag2_targ_addr, &flag2_value);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed get option val (%d)\n", rv));
            goto done;
        }

        flag2_value |= HI_OPTION_EARLY_CFG_DONE;
        rv = HIFDiagWriteAccess(sc->hif_device, flag2_targ_addr, flag2_value);
        if (rv != A_OK) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("ath: HIF_PCIDeviceProbed set option val (%d)\n", rv));
            goto done;
        }

        HIF_wake_target_cpu(sc);
    }

done:
    A_TARGET_ACCESS_UNLIKELY(hif_state->targid);

    if (rv == A_OK) {
#if 0
    BUG_ON(HIF_osDrvcallback.deviceInsertedHandler == NULL);

    if (HIF_osDrvcallback.deviceInsertedHandler != NULL) {
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("PCI HIF: Notify driver layer\n"));
        init_completion(&hif_state->pci_dev_inserted_thread_done);
        hif_state->pci_dev_inserted_thread =
            kthread_run(_HIF_PCI_CE_notifyDeviceInsertedHandler, (HIF_DEVICE *)hif_state, "hif_dev_insert");
    }
#endif
    } else {
        /* Failure, so clean up */
        for (pipe_num=0; pipe_num < sc->ce_count; pipe_num++) {
            pipe_info = &hif_state->pipe_info[pipe_num];
            if (pipe_info->ce_hdl) {
                CE_fini(pipe_info->ce_hdl);
                pipe_info->ce_hdl = NULL;
                pipe_info->buf_sz = 0;
            }
        }

        A_FREE(hif_state);
        sc->hif_device = scn->hif_hdl = NULL;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));

    return (rv != A_OK);
}

/*
 * The "ID" returned here is an opaque cookie used for
 * A_TARGET_READ and A_TARGET_WRITE -- low-overhead APIs
 * appropriate for PCIe.
 */
A_target_id_t
HIFGetTargetId(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;

    return(TARGID(sc));
}

extern void HIFdebug(void);

/*
 * For now, we use simple on-demand sleep/wake.
 * Some possible improvements:
 *  -Use the Host-destined A_INUM_PCIE_AWAKE interrupt rather than spin/delay
 *   (or perhaps spin/delay for a short while, then convert to sleep/interrupt)
 *   Careful, though, these functions may be used by interrupt handlers ("atomic")
 *  -Don't use host_reg_table for this code; instead use values directly
 *  -Use a separate timer to track activity and allow Target to sleep only
 *   if it hasn't done anything for a while; may even want to delay some
 *   processing for a short while in order to "batch" (e.g.) transmit
 *   requests with completion processing into "windows of up time".  Costs
 *   some performance, but improves power utilization.
 *  -On some platforms, it might be possible to eliminate explicit
 *   sleep/wakeup. Instead, take a chance that each access works OK. If not,
 *   recover from the failure by forcing the Target awake.
 *  -Change keep_awake_count to an atomic_t in order to avoid spin lock
 *   overhead in some cases. Perhaps this makes more sense when
 *   CONFIG_ATH_PCIE_ACCESS_LIKELY is used and less sense when LIKELY is
 *   disabled.
 *  -It is possible to compile this code out and simply force the Target
 *   to remain awake.  That would yield optimal performance at the cost of
 *   increased power. See CONFIG_ATH_PCIE_MAX_PERF.
 *
 * Note: parameter wait_for_it has meaning only when waking (when sleep_ok==0).
 */
void
HIFTargetSleepStateAdjust(A_target_id_t targid,
                          A_BOOL sleep_ok,
                          A_BOOL wait_for_it)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)TARGID_TO_HIF(targid);
    A_target_id_t pci_addr = TARGID_TO_PCI_ADDR(targid);
    static int max_delay;


    if (sleep_ok) {
        adf_os_spin_lock(&hif_state->keep_awake_lock);
        hif_state->keep_awake_count--;
        if (hif_state->keep_awake_count == 0) {
            /* Allow sleep */
            hif_state->verified_awake = FALSE;
            A_PCI_WRITE32(pci_addr + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
        }
        adf_os_spin_unlock(&hif_state->keep_awake_lock);
    } else {
        adf_os_spin_lock(&hif_state->keep_awake_lock);
        if (hif_state->keep_awake_count == 0) {
            /* Force AWAKE */
            A_PCI_WRITE32(pci_addr + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
        }
        hif_state->keep_awake_count++;
        adf_os_spin_unlock(&hif_state->keep_awake_lock);

        if (wait_for_it && !hif_state->verified_awake) {
#define PCIE_WAKE_TIMEOUT 5000 /* 5Ms */
            int tot_delay = 0;
            int curr_delay = 5;

            for (;;) {
                if (ath_pci_targ_is_awake(pci_addr)) {
                    hif_state->verified_awake = TRUE;
                    break;
                } else if (!ath_pci_targ_is_present(targid, pci_addr)) {
                    break;
                }

                //ASSERT(tot_delay <= PCIE_WAKE_TIMEOUT);
                if (tot_delay > PCIE_WAKE_TIMEOUT)
                {
                    printk("%s: keep_awake_count %d PCIE_SOC_WAKE_ADDRESS = %x\n", __func__,
                            hif_state->keep_awake_count,
                            A_PCI_READ32(pci_addr + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS));
                    ASSERT(0);
                }

                OS_DELAY(curr_delay);
                tot_delay += curr_delay;

                if (curr_delay < 50) {
                    curr_delay += 5;
                }
            }

            /*
             * NB: If Target has to come out of Deep Sleep,
             * this may take a few Msecs. Typically, though
             * this delay should be <30us.
             */
            if (tot_delay > max_delay) {
                max_delay = tot_delay;
            }
        }
    }
}

A_BOOL
HIFTargetForcedAwake(A_target_id_t targid)
{
    A_target_id_t pci_addr = TARGID_TO_PCI_ADDR(targid);
    A_BOOL awake;
    A_BOOL pcie_forced_awake;

    awake = ath_pci_targ_is_awake(pci_addr);

    pcie_forced_awake =
        !!(A_PCI_READ32(pci_addr + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS) & PCIE_SOC_WAKE_V_MASK);

    return (awake && pcie_forced_awake);
}

#if CONFIG_ATH_PCIE_ACCESS_DEBUG
A_UINT32
HIFTargetReadChecked(A_target_id_t targid, A_UINT32 offset)
{
    A_UINT32 value;
    void *addr;

    if (!A_TARGET_ACCESS_OK(targid)) {
        HIFdebug();
    }

    addr = TARGID_TO_PCI_ADDR(targid)+offset;
    value = A_PCI_READ32(addr);

    {
    unsigned long irq_flags;
    int idx = pcie_access_log_seqnum % PCIE_ACCESS_LOG_NUM;

    spin_lock_irqsave(&pcie_access_log_lock, irq_flags);
    pcie_access_log[idx].seqnum = pcie_access_log_seqnum;
    pcie_access_log[idx].is_write = FALSE;
    pcie_access_log[idx].addr = addr;
    pcie_access_log[idx].value = value;
    pcie_access_log_seqnum++;
    spin_unlock_irqrestore(&pcie_access_log_lock, irq_flags);
    }

    return value;
}

void
HIFTargetWriteChecked(A_target_id_t targid, A_UINT32 offset, A_UINT32 value)
{
    void *addr;

    if (!A_TARGET_ACCESS_OK(targid)) {
        HIFdebug();
    }

    addr = TARGID_TO_PCI_ADDR(targid)+(offset);
    A_PCI_WRITE32(addr, value);

    {
    unsigned long irq_flags;
    int idx = pcie_access_log_seqnum % PCIE_ACCESS_LOG_NUM;

    spin_lock_irqsave(&pcie_access_log_lock, irq_flags);
    pcie_access_log[idx].seqnum = pcie_access_log_seqnum;
    pcie_access_log[idx].is_write = TRUE;
    pcie_access_log[idx].addr = addr;
    pcie_access_log[idx].value = value;
    pcie_access_log_seqnum++;
    spin_unlock_irqrestore(&pcie_access_log_lock, irq_flags);
    }
}

void
HIFdebug(void)
{
    /* BUG_ON(1); */
    BREAK();
}
#endif

/*
 * Convert an opaque HIF device handle into the corresponding
 * opaque (void *) operating system device handle.
 */
#if ! defined(A_SIMOS_DEVHOST)
void *
HIFDeviceToOsDevice(HIF_DEVICE *hif_device)
{
    return ((struct HIF_CE_state *) hif_device)->sc->dev;
}
#endif

/*
 * Typically called from either the PCI infrastructure when
 * a firmware interrupt is pending OR from the the shared PCI
 * interrupt handler when a firmware-generated interrupt
 * to the Host might be pending.
 */
atomic_t target_assert_count = ATOMIC_INIT(0);

irqreturn_t
HIF_fw_interrupt_handler(int irq, void *arg)
{
    struct ath_hif_pci_softc *sc = arg;
    struct HIF_CE_state *hif_state;
    A_target_id_t targid;
    A_UINT32 fw_indicator_address, fw_indicator;

    if (adf_os_unlikely(!sc->sc_valid)) {
        return ATH_ISR_NOTMINE;
    }

    hif_state = (struct HIF_CE_state *)sc->hif_device;
    targid = hif_state->targid;

    A_TARGET_ACCESS_BEGIN(targid);

    fw_indicator_address = hif_state->fw_indicator_address;
    fw_indicator = A_TARGET_READ(targid, fw_indicator_address);

    if (fw_indicator & FW_IND_EVENT_PENDING) {
        /* ACK: clear Target-side pending event */
        A_TARGET_WRITE(targid, fw_indicator_address, fw_indicator & ~FW_IND_EVENT_PENDING);
        A_TARGET_ACCESS_END(targid);
        atomic_inc(&target_assert_count);
        if (hif_state->started) {
            /* Alert the Host-side service thread */
            atomic_set(&hif_state->fw_event_pending, 1);
#if 0
            wake_up(&hif_state->service_waitq);
#else
            hif_completion_thread(hif_state);
#endif
        } else {
            /*
             * Probable Target failure before we're prepared
             * to handle it.  Generally unexpected.
             */
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("ath ERROR: Early firmware event indicated\n"));
             printk("%s : fw_indicator : 0x%8x \n",__func__,fw_indicator);
        }
    } else {
        A_TARGET_ACCESS_END(targid);
    }

    return ATH_ISR_SCHED;
}
