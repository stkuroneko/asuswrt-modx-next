/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "htc_internal.h"
#include <adf_nbuf.h> /* adf_nbuf_t */

//#define USB_HIF_SINGLE_PIPE_DATA_SCHED
//#ifdef USB_HIF_SINGLE_PIPE_DATA_SCHED
#define DATA_EP_SIZE 4
//#endif
#define HTC_DATA_RESOURCE_THRS 256
#define HTC_DATA_MINDESC_PERPACKET 2

typedef enum _HTC_SEND_QUEUE_RESULT {
    HTC_SEND_QUEUE_OK = 0,    /* packet was queued */
    HTC_SEND_QUEUE_DROP = 1,  /* this packet should be dropped */
} HTC_SEND_QUEUE_RESULT;


static INLINE void RestoreTxPacket(HTC_TARGET *target, HTC_PACKET *pPacket)
{
    if (pPacket->PktInfo.AsTx.Flags & HTC_TX_PACKET_FLAG_FIXUP_NETBUF) {
        adf_nbuf_t netbuf = GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket);
        adf_nbuf_unmap(target->osdev, netbuf, ADF_OS_DMA_TO_DEVICE);
        adf_nbuf_pull_head(netbuf, sizeof(HTC_FRAME_HDR));
        pPacket->PktInfo.AsTx.Flags &= ~HTC_TX_PACKET_FLAG_FIXUP_NETBUF;
    }

}

static void DoSendCompletion(HTC_ENDPOINT       *pEndpoint,
                             HTC_PACKET_QUEUE   *pQueueToIndicate)
{
    do {

        if (HTC_QUEUE_EMPTY(pQueueToIndicate)) {
                /* nothing to indicate */
            break;
        }

        if (pEndpoint->EpCallBacks.EpTxCompleteMultiple != NULL) {
            AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" HTC calling ep %d, send complete multiple callback (%d pkts) \n",
                     pEndpoint->Id, HTC_PACKET_QUEUE_DEPTH(pQueueToIndicate)));
                /* a multiple send complete handler is being used, pass the queue to the handler */
            pEndpoint->EpCallBacks.EpTxCompleteMultiple(pEndpoint->EpCallBacks.pContext,
                                                        pQueueToIndicate);
                /* all packets are now owned by the callback, reset queue to be safe */
            INIT_HTC_PACKET_QUEUE(pQueueToIndicate);
        } else {
            HTC_PACKET *pPacket;
            /* using legacy EpTxComplete */
            do {
                pPacket = HTC_PACKET_DEQUEUE(pQueueToIndicate);
                AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" HTC calling ep %d send complete callback on packet %p \n", \
                        pEndpoint->Id, pPacket));
                pEndpoint->EpCallBacks.EpTxComplete(pEndpoint->EpCallBacks.pContext, pPacket);
            } while (!HTC_QUEUE_EMPTY(pQueueToIndicate));
        }

    } while (FALSE);

}

static void SendPacketCompletion(HTC_TARGET *target, HTC_PACKET *pPacket)
{
    HTC_ENDPOINT    *pEndpoint = &target->EndPoint[pPacket->Endpoint];
    HTC_PACKET_QUEUE container;
#if defined(EPPING_TEST) && defined(HIF_USB)
    EPPING_HEADER *pktHeader;
    adf_nbuf_t          nbuf;
#endif
    RestoreTxPacket(target, pPacket);
    INIT_HTC_PACKET_QUEUE_AND_ADD(&container,pPacket);
        /* do completion */
#if defined(EPPING_TEST) && defined(HIF_USB)
    pktHeader = (EPPING_HEADER *)(pPacket->pBuffer);
    if (IS_EPPING_PACKET(pktHeader))
    {
        nbuf = GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket);
        adf_nbuf_free(nbuf);
        A_FREE(pPacket);
    } else {
        DoSendCompletion(pEndpoint,&container);
    }
#else
    DoSendCompletion(pEndpoint,&container);
#endif
    pPacket = NULL;
}

void
HTCSendCompleteCheckCleanup(void *context)
{
    HTC_ENDPOINT *pEndpoint = (HTC_ENDPOINT *) context;
    HTCSendCompleteCheck(pEndpoint, 1);
}

static A_STATUS HTCIssuePackets(HTC_TARGET       *target,
                                HTC_ENDPOINT     *pEndpoint,
                                HTC_PACKET_QUEUE *pPktQueue)
{
    A_STATUS            status = A_OK;
    adf_nbuf_t          netbuf;
    HTC_PACKET          *pPacket = NULL;
    u_int16_t           payloadLen;
    HTC_FRAME_HDR       *pHtcHdr;

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("+HTCIssuePackets: Queue: %p, Pkts %d \n",
                    pPktQueue, HTC_PACKET_QUEUE_DEPTH(pPktQueue)));

    while (!HTC_QUEUE_EMPTY(pPktQueue)) {
        pPacket = HTC_PACKET_DEQUEUE(pPktQueue);
        netbuf = GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket);
        AR_DEBUG_ASSERT(netbuf);
        /* Non-credit enabled endpoints have been mapped and setup by now,
         * so no need to revisit the HTC headers
         */
        if (IS_TX_CREDIT_FLOW_ENABLED(pEndpoint)) {

            payloadLen = pPacket->ActualLength;
            /* setup HTC frame header */

            pHtcHdr = (HTC_FRAME_HDR *) adf_nbuf_get_frag_vaddr(netbuf, 0);
            AR_DEBUG_ASSERT(pHtcHdr);


            HTC_WRITE32(pHtcHdr, SM(payloadLen, HTC_FRAME_HDR_PAYLOADLEN) |
                    SM(pPacket->PktInfo.AsTx.SendFlags, HTC_FRAME_HDR_FLAGS) |
                    SM(pPacket->Endpoint, HTC_FRAME_HDR_ENDPOINTID));
            HTC_WRITE32(((A_UINT32 *)pHtcHdr) + 1,
                    SM(pPacket->PktInfo.AsTx.SeqNo, HTC_FRAME_HDR_CONTROLBYTES1));

            /*
             * Now that the HTC frame header has been added, the netbuf can be
             * mapped.  This only applies to non-data frames, since data frames
             * were already mapped as they entered into the driver.
             * Check the "FIXUP_NETBUF" flag to see whether this is a data netbuf
             * that is already mapped, or a non-data netbuf that needs to be
             * mapped.
             */
            if (pPacket->PktInfo.AsTx.Flags & HTC_TX_PACKET_FLAG_FIXUP_NETBUF) {
                adf_nbuf_map(
                        target->osdev,
                        GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket),
                        ADF_OS_DMA_TO_DEVICE);
            }
        }

        if( pEndpoint->ServiceID != WMI_CONTROL_SVC){ 
            LOCK_HTC_TX(target);
        }  
            /* store in look up queue to match completions */
        HTC_PACKET_ENQUEUE(&pEndpoint->TxLookupQueue,pPacket);
        INC_HTC_EP_STAT(pEndpoint,TxIssued,1);
        pEndpoint->ul_outstanding_cnt++;
        if( pEndpoint->ServiceID != WMI_CONTROL_SVC){ 
            UNLOCK_HTC_TX(target);
        }

        status = HIFSend_head(target->hif_dev,
                              pEndpoint->UL_PipeID, pEndpoint->Id,
                              HTC_HDR_LENGTH + pPacket->ActualLength,
                              netbuf);

        if (adf_os_unlikely(A_FAILED(status))) {
            if (status != A_NO_RESOURCE) {
                /* TODO : if more than 1 endpoint maps to the same PipeID it is possible
                 * to run out of resources in the HIF layer. Don't emit the error */
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("HIFSend Failed status:%d \n",status));
            }
            if( pEndpoint->ServiceID != WMI_CONTROL_SVC){ 
                LOCK_HTC_TX(target);
            }
            pEndpoint->ul_outstanding_cnt--;
            HTC_PACKET_REMOVE(&pEndpoint->TxLookupQueue,pPacket);
                /* reclaim credits */
#if defined(HIF_USB)
            if (pEndpoint->Id >= ENDPOINT_2 && pEndpoint->Id <= ENDPOINT_5)
                target->avail_tx_credits += pPacket->PktInfo.AsTx.CreditsUsed;
            else
                pEndpoint->TxCredits += pPacket->PktInfo.AsTx.CreditsUsed;
#else
            pEndpoint->TxCredits += pPacket->PktInfo.AsTx.CreditsUsed;
#endif
                /* put it back into the callers queue */
            HTC_PACKET_ENQUEUE_TO_HEAD(pPktQueue,pPacket);
            if( pEndpoint->ServiceID != WMI_CONTROL_SVC){ 
                UNLOCK_HTC_TX(target);
            } 
            break;
        }

    }

    if (adf_os_unlikely(A_FAILED(status))) {
#if defined(HIF_USB)
        if (pEndpoint->Id >= ENDPOINT_2 && pEndpoint->Id <= ENDPOINT_5)
            target->avail_tx_credits += pPacket->PktInfo.AsTx.CreditsUsed;
        else
            pEndpoint->TxCredits += pPacket->PktInfo.AsTx.CreditsUsed;
#endif
        while (!HTC_QUEUE_EMPTY(pPktQueue)) {
            if (status != A_NO_RESOURCE) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("HTCIssuePackets, failed pkt:0x%p status:%d \n",pPacket,status));
            }
             /* WMI command can't be dropped, if the resource is not available,
                Queue to head for sending when resource is available
                This should not occur XXX          */
            if((status == A_NO_RESOURCE) && (pEndpoint->ServiceID == WMI_CONTROL_SVC)) {
                printk("Queueing WMI command back to TxQueue \n");
                HTC_PACKET_QUEUE_TRANSFER_TO_HEAD(&pEndpoint->TxQueue, pPktQueue);
                break;
            }
            else {
                pPacket = HTC_PACKET_DEQUEUE(pPktQueue);
                pPacket->Status = status;
                SendPacketCompletion(target,pPacket);
            }
        }
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCIssuePackets \n"));

    return status;
}

    /* get HTC send packets from the TX queue on an endpoint, based on available credits */
void GetHTCSendPacketsCreditBased(HTC_TARGET        *target,
                                  HTC_ENDPOINT      *pEndpoint,
                                  HTC_PACKET_QUEUE  *pQueue)
{
    int          creditsRequired;
    int          remainder;
    A_UINT8      sendFlags;
    HTC_PACKET   *pPacket;
    unsigned int transferLength;

    /****** NOTE : the TX lock is held when this function is called *****************/
    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+GetHTCSendPacketsCreditBased \n"));

        /* loop until we can grab as many packets out of the queue as we can */
    while (TRUE) {

        sendFlags = 0;
            /* get packet at head, but don't remove it */
        pPacket = HTC_GET_PKT_AT_HEAD(&pEndpoint->TxQueue);
        if (pPacket == NULL) {
            break;
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Got head packet:%p , Queue Depth: %d\n",
                pPacket, HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)));

        transferLength = pPacket->ActualLength + HTC_HDR_LENGTH;

        if (transferLength <= target->TargetCreditSize) {
            creditsRequired = 1;
        } else {
                /* figure out how many credits this message requires */
            creditsRequired = transferLength / target->TargetCreditSize;
            remainder = transferLength % target->TargetCreditSize;

            if (remainder) {
                creditsRequired++;
            }
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Creds Required:%d   Got:%d\n",
                            creditsRequired, pEndpoint->TxCredits));

        if (pEndpoint->Id == ENDPOINT_0) {
            /* endpoint 0 is special, it always has a credit and does not require credit based
             * flow control */
            creditsRequired = 0;
#if defined(HIF_USB)
        } else if (pEndpoint->Id >= ENDPOINT_2 && pEndpoint->Id <= ENDPOINT_5) {
            if (target->avail_tx_credits < creditsRequired)
                break;

            target->avail_tx_credits -= creditsRequired;

            if (target->avail_tx_credits < 9) {
                /* tell the target we need credits ASAP! */
                sendFlags |= HTC_FLAGS_NEED_CREDIT_UPDATE;
                INC_HTC_EP_STAT(pEndpoint, TxCreditLowIndications, 1);
                AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Host Needs Credits  \n"));
            }
#endif
        } else {

            if (pEndpoint->TxCredits < creditsRequired) {
                break;
            }

            pEndpoint->TxCredits -= creditsRequired;
            INC_HTC_EP_STAT(pEndpoint, TxCreditsConsummed, creditsRequired);

                /* check if we need credits back from the target */
            if (pEndpoint->TxCredits < pEndpoint->TxCreditsPerMaxMsg) {
                    /* tell the target we need credits ASAP! */
                sendFlags |= HTC_FLAGS_NEED_CREDIT_UPDATE;
                INC_HTC_EP_STAT(pEndpoint, TxCreditLowIndications, 1);
                AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Host Needs Credits  \n"));
            }
        }

            /* now we can fully dequeue */
        pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->TxQueue);
            /* save the number of credits this packet consumed */
        pPacket->PktInfo.AsTx.CreditsUsed = creditsRequired;
            /* save send flags */
        pPacket->PktInfo.AsTx.SendFlags = sendFlags;
        pPacket->PktInfo.AsTx.SeqNo = pEndpoint->SeqNo;
        pEndpoint->SeqNo++;
            /* queue this packet into the caller's queue */
        HTC_PACKET_ENQUEUE(pQueue,pPacket);
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-GetHTCSendPacketsCreditBased \n"));

}

void GetHTCSendPackets(HTC_TARGET        *target,
                       HTC_ENDPOINT      *pEndpoint,
                       HTC_PACKET_QUEUE  *pQueue,
                       int                Resources)
{

    HTC_PACKET   *pPacket;

    /****** NOTE : the TX lock is held when this function is called *****************/
    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+GetHTCSendPackets %d resources\n",Resources));

        /* loop until we can grab as many packets out of the queue as we can */
    while (Resources > 0) {
        int num_frags;

        pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->TxQueue);
        if (pPacket == NULL) {
            break;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Got packet:%p , New Queue Depth: %d\n",
                pPacket, HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)));
        /* For non-credit path the sequence number is already embedded
         * in the constructed HTC header
         */
#if 0
        pPacket->PktInfo.AsTx.SeqNo = pEndpoint->SeqNo;
        pEndpoint->SeqNo++;
#endif
        pPacket->PktInfo.AsTx.SendFlags = 0;
        pPacket->PktInfo.AsTx.CreditsUsed = 0;
        /* queue this packet into the caller's queue */
        HTC_PACKET_ENQUEUE(pQueue,pPacket);

        /*
         * FIX THIS:
         * For now, avoid calling adf_nbuf_get_num_frags before calling
         * adf_nbuf_map, because the MacOS version of adf_nbuf_t doesn't
         * support adf_nbuf_get_num_frags until after adf_nbuf_map has
         * been done.
         * Assume that the non-data netbufs, i.e. the WMI message netbufs,
         * consist of a single fragment.
         */
        num_frags =
            (pPacket->PktInfo.AsTx.Flags & HTC_TX_PACKET_FLAG_FIXUP_NETBUF) ?
            1 /* WMI messages are in a single-fragment network buffer */ :
            adf_nbuf_get_num_frags(GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket));
        Resources -= num_frags;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-GetHTCSendPackets \n"));

}

static HTC_SEND_QUEUE_RESULT HTCTrySend(HTC_TARGET       *target,
                                        HTC_ENDPOINT     *pEndpoint,
                                        HTC_PACKET_QUEUE *pCallersSendQueue)
{
    HTC_PACKET_QUEUE      sendQueue; /* temp queue to hold packets at various stages */
    HTC_PACKET            *pPacket;
    int                   tx_resources;
    int                   overflow;
    HTC_SEND_QUEUE_RESULT result = HTC_SEND_QUEUE_OK;

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+HTCTrySend (Queue:%p Depth:%d)\n",
            pCallersSendQueue,
            (pCallersSendQueue == NULL) ? 0 : HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue)));

        /* init the local send queue */
    INIT_HTC_PACKET_QUEUE(&sendQueue);

    do {

        if (NULL == pCallersSendQueue) {
                /* caller didn't provide a queue, just wants us to check queues and send */
            break;
        }

        if (HTC_QUEUE_EMPTY(pCallersSendQueue)) {
                /* empty queue */
            OL_ATH_HTC_PKT_ERROR_COUNT_INCR(target,HTC_PKT_Q_EMPTY);
            result = HTC_SEND_QUEUE_DROP;
            break;
        }

        if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue) >= pEndpoint->MaxTxQueueDepth) {
                    /* we've already overflowed */
            overflow = HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue);
        } else {
                /* figure out how much we will overflow by */
            overflow = HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue);
            overflow += HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue);
                /* figure out how much we will overflow the TX queue by */
            overflow -= pEndpoint->MaxTxQueueDepth;
        }

            /* if overflow is negative or zero, we are okay */
        if (overflow > 0) {
            AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
                (" Endpoint %d, TX queue will overflow :%d , Tx Depth:%d, Max:%d \n",
                pEndpoint->Id, overflow, HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue), pEndpoint->MaxTxQueueDepth));
        }
        if ((overflow <= 0) || (pEndpoint->EpCallBacks.EpSendFull == NULL)) {
                /* all packets will fit or caller did not provide send full indication handler
                 * --  just move all of them to the local sendQueue object */
            HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&sendQueue, pCallersSendQueue);
        } else {
            int               i;
            int               goodPkts = HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue) - overflow;

            A_ASSERT(goodPkts >= 0);
                /* we have overflowed, and a callback is provided */
                /* dequeue all non-overflow packets into the sendqueue */
            for (i = 0; i < goodPkts; i++) {
                    /* pop off caller's queue*/
                pPacket = HTC_PACKET_DEQUEUE(pCallersSendQueue);
                A_ASSERT(pPacket != NULL);
                    /* insert into local queue */
                HTC_PACKET_ENQUEUE(&sendQueue,pPacket);
            }

                /* the caller's queue has all the packets that won't fit*/
                /* walk through the caller's queue and indicate each one to the send full handler */
            ITERATE_OVER_LIST_ALLOW_REMOVE(&pCallersSendQueue->QueueHead, pPacket, HTC_PACKET, ListLink) {

                AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" Indicating overflowed TX packet: %p \n",
                                pPacket));
                /*
                 * Remove headroom reserved for HTC_FRAME_HDR before giving
                 * the packet back to the user via the EpSendFull callback.
                 */
                RestoreTxPacket(target, pPacket);

                if (pEndpoint->EpCallBacks.EpSendFull(pEndpoint->EpCallBacks.pContext,
                                                      pPacket) == HTC_SEND_FULL_DROP) {
                        /* callback wants the packet dropped */
                    INC_HTC_EP_STAT(pEndpoint, TxDropped, 1);
                        /* leave this one in the caller's queue for cleanup */
                } else {
                        /* callback wants to keep this packet, remove from caller's queue */
                    HTC_PACKET_REMOVE(pCallersSendQueue, pPacket);
                        /* put it in the send queue */
                    /* add HTC_FRAME_HDR space reservation again */
                    adf_nbuf_push_head(
                        GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket),
                        sizeof(HTC_FRAME_HDR));

                    HTC_PACKET_ENQUEUE(&sendQueue,pPacket);
                }

            } ITERATE_END;

            if (HTC_QUEUE_EMPTY(&sendQueue)) {
                    /* no packets made it in, caller will cleanup */
                OL_ATH_HTC_PKT_ERROR_COUNT_INCR(target,HTC_SEND_Q_EMPTY);
                result = HTC_SEND_QUEUE_DROP;
                break;
            }
        }

    } while (FALSE);

    if (result != HTC_SEND_QUEUE_OK) {
        AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCTrySend:  \n"));
        return result;
    }

    if (!IS_TX_CREDIT_FLOW_ENABLED(pEndpoint)) {
        tx_resources = HIFGetFreeQueueNumber(target->hif_dev,pEndpoint->UL_PipeID);
    } else {
        tx_resources = 0;
    }

    LOCK_HTC_TX(target);

    if (!HTC_QUEUE_EMPTY(&sendQueue)) {
            /* transfer packets to tail */
        HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&pEndpoint->TxQueue,&sendQueue);
        A_ASSERT(HTC_QUEUE_EMPTY(&sendQueue));
        INIT_HTC_PACKET_QUEUE(&sendQueue);
    }

        /* increment tx processing count on entry */
    adf_os_atomic_inc(&pEndpoint->TxProcessCount);
    if (adf_os_atomic_read(&pEndpoint->TxProcessCount) > 1) {
            /* another thread or task is draining the TX queues on this endpoint
             * that thread will reset the tx processing count when the queue is drained */
        adf_os_atomic_dec(&pEndpoint->TxProcessCount);
        UNLOCK_HTC_TX(target);
        AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCTrySend (busy) \n"));
        return HTC_SEND_QUEUE_OK;
    }

    /***** beyond this point only 1 thread may enter ******/

        /* now drain the endpoint TX queue for transmission as long as we have enough
         * transmit resources */
    while (TRUE) {

        if ((HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue) == 0) || ((!tx_resources) && ( pEndpoint->ServiceID == WMI_CONTROL_SVC) )) {
            break;
        }

        if (IS_TX_CREDIT_FLOW_ENABLED(pEndpoint)) {
            /* credit based mechanism provides flow control based on target transmit resource availability, we
             * assume that the HIF layer will always have bus resources greater than target transmit resources */
            GetHTCSendPacketsCreditBased(target,pEndpoint,&sendQueue);
        } else {
                /* get all the packets for this endpoint that we can for this pass */
            GetHTCSendPackets(target,pEndpoint,&sendQueue,tx_resources);
        }

        if (HTC_PACKET_QUEUE_DEPTH(&sendQueue) == 0) {
                /* didn't get any packets due to a lack of resources or TX queue was drained */
            break;
        }

        if( pEndpoint->ServiceID != WMI_CONTROL_SVC){ 
            UNLOCK_HTC_TX(target);
        }

            /* send what we can */
        HTCIssuePackets(target,pEndpoint,&sendQueue);

        if (!IS_TX_CREDIT_FLOW_ENABLED(pEndpoint)) {
            tx_resources = HIFGetFreeQueueNumber(target->hif_dev,pEndpoint->UL_PipeID);
        }

        if( pEndpoint->ServiceID != WMI_CONTROL_SVC){ 
            LOCK_HTC_TX(target);
        }

    }

        /* done with this endpoint, we can clear the count */
    adf_os_atomic_init(&pEndpoint->TxProcessCount);
    UNLOCK_HTC_TX(target);

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCTrySend:  \n"));

    return HTC_SEND_QUEUE_OK;
}

#ifdef USB_HIF_SINGLE_PIPE_DATA_SCHED
static A_UINT16 HTCSendPktsSchedCheck(HTC_HANDLE HTCHandle, HTC_ENDPOINT_ID id)
{
    HTC_TARGET        *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    HTC_ENDPOINT      *pEndpoint;
    HTC_ENDPOINT_ID   eid;
    HTC_PACKET_QUEUE  *pTxQueue;
    A_UINT16          resources;
    A_UINT16          acQueueStatus[DATA_EP_SIZE] = {0, 0, 0, 0};

    if (id < ENDPOINT_2 || id > ENDPOINT_5) {
        return 1;
    }

    for (eid = ENDPOINT_2; eid <= ENDPOINT_5; eid++) {
        pEndpoint = &target->EndPoint[eid];
        pTxQueue = &pEndpoint->TxQueue;

        if (HTC_QUEUE_EMPTY(pTxQueue)) {
            acQueueStatus[eid - 2] = 1;
        }
    }

    switch (id)
    {
        case ENDPOINT_2: //BE
            return (acQueueStatus[0] && acQueueStatus[2] && acQueueStatus[3]);
        case ENDPOINT_3: //BK
            return (acQueueStatus[0] && acQueueStatus[1] && acQueueStatus[2] && acQueueStatus[3]);
        case ENDPOINT_4: //VI
            return (acQueueStatus[2] && acQueueStatus[3]);
        case ENDPOINT_5: //VO
            return (acQueueStatus[3]);
        default:
            return 0;
    }

}

static A_STATUS HTCSendPktsSchedQueue(HTC_TARGET *target, HTC_PACKET_QUEUE *pPktQueue, HTC_ENDPOINT_ID eid)
{
    HTC_ENDPOINT      *pEndpoint;
    HTC_PACKET_QUEUE  *pTxQueue;
    HTC_PACKET        *pPacket;
    int               goodPkts;

    pEndpoint = &target->EndPoint[eid];
    pTxQueue = &pEndpoint->TxQueue;

    LOCK_HTC_TX(target);

    goodPkts = pEndpoint->MaxTxQueueDepth - HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue);

    if (goodPkts > 0){
        while (!HTC_QUEUE_EMPTY(pPktQueue)) {
            pPacket = HTC_PACKET_DEQUEUE(pPktQueue);
            HTC_PACKET_ENQUEUE(pTxQueue, pPacket);
            goodPkts--;

            if (goodPkts <= 0) {
                break;
            }
        }
    }

    if (HTC_PACKET_QUEUE_DEPTH(pPktQueue)) {
        ITERATE_OVER_LIST_ALLOW_REMOVE(&pPktQueue->QueueHead, pPacket, HTC_PACKET, ListLink) {

            if (pEndpoint->EpCallBacks.EpSendFull(pEndpoint->EpCallBacks.pContext,
                                                    pPacket) == HTC_SEND_FULL_DROP) {
                INC_HTC_EP_STAT(pEndpoint, TxDropped, 1);
            } else {
                HTC_PACKET_REMOVE(pPktQueue, pPacket);
                HTC_PACKET_ENQUEUE(pTxQueue,pPacket);
            }
        } ITERATE_END;
    }

    UNLOCK_HTC_TX(target);

    return A_OK;
}

#endif

A_STATUS HTCSendPktsMultiple(HTC_HANDLE HTCHandle, HTC_PACKET_QUEUE *pPktQueue)
{
    HTC_TARGET      *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    HTC_ENDPOINT    *pEndpoint;
    HTC_PACKET      *pPacket;
    adf_nbuf_t      netbuf;
    HTC_FRAME_HDR       *pHtcHdr;

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("+HTCSendPktsMultiple: Queue: %p, Pkts %d \n",
                    pPktQueue, HTC_PACKET_QUEUE_DEPTH(pPktQueue)));

        /* get packet at head to figure out which endpoint these packets will go into */
    pPacket = HTC_GET_PKT_AT_HEAD(pPktQueue);
    if (NULL == pPacket) {
        OL_ATH_HTC_PKT_ERROR_COUNT_INCR(target,GET_HTC_PKT_Q_FAIL);
        AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCSendPktsMultiple \n"));
        printk("%s : WMI Command send failed \n",__func__);
        return A_EINVAL;
    }

    AR_DEBUG_ASSERT(pPacket->Endpoint < ENDPOINT_MAX);
    pEndpoint = &target->EndPoint[pPacket->Endpoint];

#ifdef HTC_EP_STAT_PROFILING
    LOCK_HTC_TX(target);
    INC_HTC_EP_STAT(pEndpoint,TxPosted,HTC_PACKET_QUEUE_DEPTH(pPktQueue));
    UNLOCK_HTC_TX(target);
#endif

    /* provide room in each packet's netbuf for the HTC frame header */
    HTC_PACKET_QUEUE_ITERATE_ALLOW_REMOVE(pPktQueue,pPacket) {
        netbuf = GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket);
        AR_DEBUG_ASSERT(netbuf);

        adf_nbuf_push_head(netbuf, sizeof(HTC_FRAME_HDR));

        /* Non credit enabled endpoints are used for data path using
         * HTCSendData - This path assumes prconstructed and pre-mapped HTC headers
         * As these paths can mix on SMP systems they need to follow same model.
         * Credit enabled endpoints do not mix and also have more requirements that
         * need last minute HTC header setup
         */
        if (!IS_TX_CREDIT_FLOW_ENABLED(pEndpoint)) {
            /* setup HTC frame header */
            pHtcHdr = (HTC_FRAME_HDR *) adf_nbuf_get_frag_vaddr(netbuf, 0);
            AR_DEBUG_ASSERT(pHtcHdr);

            HTC_WRITE32(pHtcHdr, SM(pPacket->ActualLength, HTC_FRAME_HDR_PAYLOADLEN) |
                    SM(pPacket->Endpoint, HTC_FRAME_HDR_ENDPOINTID));

            LOCK_HTC_TX(target);

            pPacket->PktInfo.AsTx.SeqNo = pEndpoint->SeqNo;
            pEndpoint->SeqNo++;

            HTC_WRITE32(((A_UINT32 *)pHtcHdr) + 1,
                    SM(pPacket->PktInfo.AsTx.SeqNo, HTC_FRAME_HDR_CONTROLBYTES1));

            UNLOCK_HTC_TX(target);
            /*
             * Now that the HTC frame header has been added, the netbuf can be
             * mapped.  This only applies to non-data frames, since data frames
             * were already mapped as they entered into the driver.
             */
            if(A_STATUS_FAILED == adf_nbuf_map(
                    target->osdev,
                    GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket),
                    ADF_OS_DMA_TO_DEVICE)) {
                adf_os_print("%s: DMA mapping failed!!!\n", __func__);
#ifndef REMOVE_INIT_DEBUG_CODE
                adf_os_assert_always(0);
#endif
            }

        }
        pPacket->PktInfo.AsTx.Flags |= HTC_TX_PACKET_FLAG_FIXUP_NETBUF;
    } HTC_PACKET_QUEUE_ITERATE_END;

#ifdef USB_HIF_SINGLE_PIPE_DATA_SCHED
    if (!HTCSendPktsSchedCheck(HTCHandle, pEndpoint->Id)) {
        HTCSendPktsSchedQueue(HTCHandle, pPktQueue, pEndpoint->Id);
    } else {
        HTCTrySend(target,pEndpoint,pPktQueue);
    }
#else
    HTCTrySend(target,pEndpoint,pPktQueue);
#endif

        /* do completion on any packets that couldn't get in */
    if (!HTC_QUEUE_EMPTY(pPktQueue)) {

        HTC_PACKET_QUEUE_ITERATE_ALLOW_REMOVE(pPktQueue,pPacket) {
            /* remove the headroom reserved for HTC_FRAME_HDR */
            RestoreTxPacket(target, pPacket);

            if (HTC_STOPPING(target)) {
                pPacket->Status = A_ECANCELED;
            } else {
                pPacket->Status = A_NO_RESOURCE;
            }
        } HTC_PACKET_QUEUE_ITERATE_END;

        DoSendCompletion(pEndpoint,pPktQueue);
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCSendPktsMultiple \n"));

    return A_OK;
}

/* HTC API - HTCSendPkt */
A_STATUS    HTCSendPkt(HTC_HANDLE HTCHandle, HTC_PACKET *pPacket)
{
    HTC_PACKET_QUEUE queue;

    a_mem_trace(GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket));
    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
                    ("+-HTCSendPkt: Enter endPointId: %d, buffer: %p, length: %d \n",
                    pPacket->Endpoint, pPacket->pBuffer, pPacket->ActualLength));
    INIT_HTC_PACKET_QUEUE_AND_ADD(&queue,pPacket);
    return HTCSendPktsMultiple(HTCHandle, &queue);
}

#if ATH_11AC_TXCOMPACT

A_STATUS HTCSendDataPkt(HTC_HANDLE HTCHandle, adf_nbuf_t       netbuf, int Epid, int ActualLength)
{
    HTC_TARGET       *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    HTC_ENDPOINT     *pEndpoint;
    HTC_FRAME_HDR    *pHtcHdr;
    A_STATUS         status = A_OK;
    int              tx_resources;

    pEndpoint = &target->EndPoint[Epid];

    tx_resources = HIFGetFreeQueueNumber(target->hif_dev, pEndpoint->UL_PipeID);

    if(tx_resources <  HTC_DATA_RESOURCE_THRS){
        if (pEndpoint->ul_is_polled){
            HIFSendCompleteCheck(
                    pEndpoint->target->hif_dev, pEndpoint->UL_PipeID, 1);
            tx_resources = HIFGetFreeQueueNumber(target->hif_dev, pEndpoint->UL_PipeID);
        }
        if(tx_resources < HTC_DATA_MINDESC_PERPACKET){
            return A_ERROR;
        }
    }

    pHtcHdr = (HTC_FRAME_HDR *) adf_nbuf_get_frag_vaddr(netbuf, 0);
    AR_DEBUG_ASSERT(pHtcHdr);

    HTC_WRITE32(pHtcHdr, SM(ActualLength, HTC_FRAME_HDR_PAYLOADLEN) |
			 SM(Epid, HTC_FRAME_HDR_ENDPOINTID));
    /*
     * If the HIF pipe for the data endpoint is polled rather than
     * interrupt-driven, this is a good point to check whether any
     * data previously sent through the HIF pipe have finished being
     * sent.
     * Since this may result in callbacks to HTCTxCompletionHandler,
     * which can take the HTC tx lock, make the HIFSendCompleteCheck
     * call before acquiring the HTC tx lock.
     * Call HIFSendCompleteCheck directly, rather than calling
     * HTCSendCompleteCheck, and call the PollTimerStart separately
     * after calling HIFSend_head, so the timer will be started to
     * check for completion of the new outstanding download (in the
     * unexpected event that other polling calls don't catch it).
     */

    LOCK_HTC_TX(target);

    HTC_WRITE32(((A_UINT32 *)pHtcHdr) + 1, SM(pEndpoint->SeqNo, HTC_FRAME_HDR_CONTROLBYTES1));

    pEndpoint->SeqNo++;

    status = HIFSend_head(target->hif_dev,
            pEndpoint->UL_PipeID,
            pEndpoint->Id,
            ActualLength,
            netbuf);


    UNLOCK_HTC_TX(target);
    return status ;
}
#else /*ATH_11AC_TXCOMPACT*/


A_STATUS HTCSendDataPkt(HTC_HANDLE HTCHandle, HTC_PACKET *pPacket)
{
    HTC_TARGET       *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    HTC_ENDPOINT     *pEndpoint;
    HTC_FRAME_HDR    *pHtcHdr;
    HTC_PACKET_QUEUE sendQueue;
    adf_nbuf_t       netbuf;
    int              tx_resources;
    A_STATUS         status = A_OK;

    AR_DEBUG_ASSERT(pPacket->Endpoint < ENDPOINT_MAX);
    pEndpoint = &target->EndPoint[pPacket->Endpoint];

    /* add HTC_FRAME_HDR in the initial fragment */
    netbuf = GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket);
    pHtcHdr = (HTC_FRAME_HDR *) adf_nbuf_get_frag_vaddr(netbuf, 0);
    AR_DEBUG_ASSERT(pHtcHdr);

    HTC_WRITE32(pHtcHdr, SM(pPacket->ActualLength, HTC_FRAME_HDR_PAYLOADLEN) |
			 SM(pPacket->Endpoint, HTC_FRAME_HDR_ENDPOINTID));

    /*
     * If the HIF pipe for the data endpoint is polled rather than
     * interrupt-driven, this is a good point to check whether any
     * data previously sent through the HIF pipe have finished being
     * sent.
     * Since this may result in callbacks to HTCTxCompletionHandler,
     * which can take the HTC tx lock, make the HIFSendCompleteCheck
     * call before acquiring the HTC tx lock.
     * Call HIFSendCompleteCheck directly, rather than calling
     * HTCSendCompleteCheck, and call the PollTimerStart separately
     * after calling HIFSend_head, so the timer will be started to
     * check for completion of the new outstanding download (in the
     * unexpected event that other polling calls don't catch it).
     */
    if (pEndpoint->ul_is_polled) {
        HTCSendCompletePollTimerStop(pEndpoint);
        HIFSendCompleteCheck(
            pEndpoint->target->hif_dev, pEndpoint->UL_PipeID, 0);
    }

    LOCK_HTC_TX(target);

    pPacket->PktInfo.AsTx.SeqNo = pEndpoint->SeqNo;
    pEndpoint->SeqNo++;


    HTC_WRITE32(((A_UINT32 *)pHtcHdr) + 1, SM(pPacket->PktInfo.AsTx.SeqNo, HTC_FRAME_HDR_CONTROLBYTES1));

    /* append new packet to pEndpoint->TxQueue */
    HTC_PACKET_ENQUEUE(&pEndpoint->TxQueue, pPacket);

    /* increment tx processing count on entry */
    adf_os_atomic_inc(&pEndpoint->TxProcessCount);
    if (adf_os_atomic_read(&pEndpoint->TxProcessCount) > 1) {
        /*
         * Another thread or task is draining the TX queues on this endpoint.
         * That thread will reset the tx processing count when the queue is
         * drained.
         */
        adf_os_atomic_dec(&pEndpoint->TxProcessCount);
        UNLOCK_HTC_TX(target);
        return A_OK;
    }

    /***** beyond this point only 1 thread may enter ******/

    /*
     * Now drain the endpoint TX queue for transmission as long as we have
     * enough transmit resources
     */
    tx_resources = HIFGetFreeQueueNumber(target->hif_dev,pEndpoint->UL_PipeID);
    INIT_HTC_PACKET_QUEUE(&sendQueue);
    GetHTCSendPackets(target, pEndpoint, &sendQueue, tx_resources);

    UNLOCK_HTC_TX(target);

    /* send what we can */
    while (!HTC_QUEUE_EMPTY(&sendQueue)) {
        pPacket = HTC_PACKET_DEQUEUE(&sendQueue);
        netbuf = GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket);

        LOCK_HTC_TX(target);
        /* store in look up queue to match completions */
        HTC_PACKET_ENQUEUE(&pEndpoint->TxLookupQueue,pPacket);
        INC_HTC_EP_STAT(pEndpoint,TxIssued,1);
        pEndpoint->ul_outstanding_cnt++;
        UNLOCK_HTC_TX(target);

        status = HIFSend_head(target->hif_dev,
                              pEndpoint->UL_PipeID,
                              pEndpoint->Id,
                              HTC_HDR_LENGTH + pPacket->ActualLength,
                              netbuf);
        if (adf_os_unlikely(A_FAILED(status))) {
            LOCK_HTC_TX(target);
            pEndpoint->ul_outstanding_cnt--;
            /* remove this packet from the tx completion queue */
            HTC_PACKET_REMOVE(&pEndpoint->TxLookupQueue,pPacket);

            /*
             * Don't bother reclaiming credits - HTC flow control
             * is not applicable to tx data.
             * In LL systems, there is no download flow control,
             * since there's virtually no download delay.
             * In HL systems, the txrx SW explicitly performs the
             * tx flow control.
             */
            //pEndpoint->TxCredits += pPacket->PktInfo.AsTx.CreditsUsed;

            /* put this frame back at the front of the sendQueue */
            HTC_PACKET_ENQUEUE_TO_HEAD(&sendQueue, pPacket);

            /* put the sendQueue back at the front of pEndpoint->TxQueue */
            HTC_PACKET_QUEUE_TRANSFER_TO_HEAD(&pEndpoint->TxQueue, &sendQueue);
            UNLOCK_HTC_TX(target);
            break; /* still need to reset TxProcessCount */
        }
    }

    /* done with this endpoint, we can clear the count */
    adf_os_atomic_init(&pEndpoint->TxProcessCount);

    if (pEndpoint->ul_is_polled) {
        /*
         * Start a cleanup timer to poll for download completion.
         * The download completion should be noticed promptly from
         * other polling calls, but the timer provides a safety net
         * in case other polling calls don't occur as expected.
         */
        HTCSendCompletePollTimerStart(pEndpoint);
    }

    return status;
}
#endif /*ATH_11AC_TXCOMPACT*/

/*
 * In the adapted HIF layer, adf_nbuf_t are passed between HIF and HTC, since upper layers expects
 * HTC_PACKET containers we use the completed netbuf and lookup its corresponding HTC packet buffer
 * from a lookup list.
 * This is extra overhead that can be fixed by re-aligning HIF interfaces with HTC.
 *
 */
static HTC_PACKET *HTCLookupTxPacket(HTC_TARGET *target, HTC_ENDPOINT *pEndpoint, adf_nbuf_t netbuf)
{
    HTC_PACKET *pPacket = NULL;
    HTC_PACKET *pFoundPacket = NULL;
    HTC_PACKET_QUEUE lookupQueue;

    INIT_HTC_PACKET_QUEUE(&lookupQueue);
    LOCK_HTC_TX(target);

    /* mark that HIF has indicated the send complete for another packet */
    pEndpoint->ul_outstanding_cnt--;

    /* Dequeue first packet directly because of in-order completion */
    pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->TxLookupQueue);
    if (adf_os_unlikely(!pPacket)) {
        UNLOCK_HTC_TX(target);
        return NULL;
    }
    if (netbuf == (adf_nbuf_t)GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket)) {
        UNLOCK_HTC_TX(target);
        return pPacket;
    } else {
        HTC_PACKET_ENQUEUE(&lookupQueue, pPacket);
    }

    /*
     * Move TX lookup queue to temp queue because most of packets that are not index 0
     * are not top 10 packets.
     */
    HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&lookupQueue, &pEndpoint->TxLookupQueue);
    UNLOCK_HTC_TX(target);

    ITERATE_OVER_LIST_ALLOW_REMOVE(&lookupQueue.QueueHead,pPacket,HTC_PACKET,ListLink) {
            /* check for removal */
        if (netbuf == (adf_nbuf_t)GET_HTC_PACKET_NET_BUF_CONTEXT(pPacket)) {
                /* found it */
            HTC_PACKET_REMOVE(&lookupQueue, pPacket);
            pFoundPacket = pPacket;
            break;
        }

    } ITERATE_END;

    LOCK_HTC_TX(target);
    HTC_PACKET_QUEUE_TRANSFER_TO_HEAD(&pEndpoint->TxLookupQueue, &lookupQueue);
    UNLOCK_HTC_TX(target);

    return pFoundPacket;
}


A_STATUS HTCTxCompletionHandler(void *Context,
                                adf_nbuf_t netbuf,
                                unsigned int EpID)
{
    HTC_TARGET      *target = (HTC_TARGET *)Context;
    HTC_ENDPOINT    *pEndpoint;
    HTC_PACKET      *pPacket;
#ifdef USB_HIF_SINGLE_PIPE_DATA_SCHED
    HTC_ENDPOINT_ID eid[DATA_EP_SIZE] = {ENDPOINT_5, ENDPOINT_4, ENDPOINT_2, ENDPOINT_3};
    int epidIdx;
    A_UINT16 resourcesThresh[DATA_EP_SIZE]; //urb resources
    A_UINT16 resources;
    A_UINT16 resourcesMax;
#endif

    if (EpID >= ENDPOINT_MAX) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Invalid EndPoint Id : %d!\n", EpID));
        return A_EINVAL;
    }

    pEndpoint = &target->EndPoint[EpID];

    do {
        pPacket = HTCLookupTxPacket(target, pEndpoint, netbuf);
        if (NULL == pPacket) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("HTC TX lookup failed!\n"));
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Target:%p pEndpoint:%p EpID:%d TxLookupQueue:%p Netbuffpkt:%p\n"
                        , target, pEndpoint, EpID, &pEndpoint->TxLookupQueue, netbuf));
                /* may have already been flushed and freed */
            netbuf = NULL;
            break;
        }
        a_mem_trace(netbuf);

            /* will be giving this buffer back to upper layers */
        netbuf = NULL;
        pPacket->Status = A_OK;
        SendPacketCompletion(target,pPacket);

    } while (FALSE);

    if (!IS_TX_CREDIT_FLOW_ENABLED(pEndpoint)) {
#ifdef USB_HIF_SINGLE_PIPE_DATA_SCHED
        if ((HTC_ENDPOINT_ID)EpID >= ENDPOINT_2 &&
            (HTC_ENDPOINT_ID)EpID <= ENDPOINT_5) {

            resourcesMax = HIFGetMaxQueueNumber(target->hif_dev, pEndpoint->UL_PipeID);

            resourcesThresh[0] = 0;                           //VO
            resourcesThresh[1] = (resourcesMax *  2) / 32;    //VI
            resourcesThresh[2] = (resourcesMax *  3) / 32;    //BE
            resourcesThresh[3] = (resourcesMax *  4) / 32;    //BK

            resources = HIFGetFreeQueueNumber(target->hif_dev, pEndpoint->UL_PipeID);

            for (epidIdx = 0; epidIdx < DATA_EP_SIZE; epidIdx++) {

                pEndpoint = &target->EndPoint[eid[epidIdx]];

                if (!HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)) {
                    continue;
                }

                if (resources >= resourcesThresh[epidIdx]) {
                    break;
                }
            }

            if (epidIdx == DATA_EP_SIZE) {
                #if 0
                if (resources) {
                    for (epidIdx = 0; epidIdx < DATA_EP_SIZE; epidIdx++) {

                        pEndpoint = &target->EndPoint[eid[epidIdx]];

                        if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)) {
                            break;
                        }
                    }
                } else
                #endif
                return A_OK;
            }
        }
#endif

        /* note: when using TX credit flow, the re-checking of queues happens
         * when credits flow back from the target.
         * in the non-TX credit case, we recheck after the packet completes */
        if ((adf_os_atomic_read(&pEndpoint->TxProcessCount) == 0) || ( pEndpoint->ServiceID != WMI_CONTROL_SVC)) {
            HTCTrySend(target,pEndpoint,NULL);
        }
    }

    return A_OK;
}

/*
 * Waits for the download completion of the
 * HTT version request & Rx Ring config messages
 * and frees the buffers & the CE slot.
 */
#if QCA_OL_11AC_FAST_PATH
void
htc_ctrl_msg_cmpl(HTC_HANDLE htc_pdev, HTC_ENDPOINT_ID htc_ep_id)
{
    HTC_TARGET      *target = GET_HTC_TARGET_FROM_HANDLE(htc_pdev);
    HTC_ENDPOINT    *pEndpoint = &target->EndPoint[htc_ep_id];

    /* Blindly wait for 5ms for download to be complete */
    A_MDELAY(5);

    HTCSendCompleteCheck(pEndpoint, 1);
}
#endif

    /* callback when TX resources become available */
void  HTCTxResourceAvailHandler(void *context, A_UINT8 pipeID)
{
    int             i;
    HTC_TARGET      *target = (HTC_TARGET *)context;
    HTC_ENDPOINT    *pEndpoint = NULL;

    for (i = 0; i < ENDPOINT_MAX; i++) {
        pEndpoint = &target->EndPoint[i];
        if (pEndpoint->ServiceID != 0) {
            if (pEndpoint->UL_PipeID == pipeID) {
                break;
            }
        }
    }

    if (i >= ENDPOINT_MAX) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Invalid pipe indicated for TX resource avail : %d!\n",pipeID));
        return;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("HIF indicated more resources for pipe:%d \n",pipeID));

    HTCTrySend(target,pEndpoint,NULL);
}

/* flush endpoint TX queue */
void HTCFlushEndpointTX(HTC_TARGET *target, HTC_ENDPOINT *pEndpoint, HTC_TX_TAG Tag)
{
    HTC_PACKET *pPacket;

    LOCK_HTC_TX(target);
    while(HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)){
        pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->TxQueue);

        /* let the sender know the packet was not delivered */
        pPacket->Status = A_ECANCELED;
        SendPacketCompletion(target, pPacket);
    }
    UNLOCK_HTC_TX(target);
}

/* HTC API to flush an endpoint's TX queue*/
void HTCFlushEndpoint(HTC_HANDLE HTCHandle, HTC_ENDPOINT_ID Endpoint, HTC_TX_TAG Tag)
{
    HTC_TARGET      *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    HTC_ENDPOINT    *pEndpoint = &target->EndPoint[Endpoint];

    if (pEndpoint->ServiceID == 0) {
        AR_DEBUG_ASSERT(FALSE);
        /* not in use.. */
        return;
    }

    HTCFlushEndpointTX(target,pEndpoint,Tag);
}

/* HTC API to indicate activity to the credit distribution function */
void HTCIndicateActivityChange(HTC_HANDLE      HTCHandle,
                               HTC_ENDPOINT_ID Endpoint,
                               A_BOOL          Active)
{
   /*  TODO */
}

A_BOOL HTCIsEndpointActive(HTC_HANDLE      HTCHandle,
                           HTC_ENDPOINT_ID Endpoint)
{
    return TRUE;
}

/* process credit reports and call distribution function */
void HTCProcessCreditRpt(HTC_TARGET *target, HTC_CREDIT_REPORT *pRpt, int NumEntries, HTC_ENDPOINT_ID FromEndpoint)
{
    int             i;
    HTC_ENDPOINT    *pEndpoint;
    int             totalCredits = 0;
    A_UINT8         rpt_credits, rpt_ep_id;

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("+HTCProcessCreditRpt, Credit Report Entries:%d \n", NumEntries));

        /* lock out TX while we update credits */
    LOCK_HTC_TX(target);


    for (i = 0; i < NumEntries; i++, pRpt++) {

        rpt_ep_id = HTC_GET_FIELD(pRpt, HTC_CREDIT_REPORT, ENDPOINTID);

        if (rpt_ep_id >= ENDPOINT_MAX) {
            AR_DEBUG_ASSERT(FALSE);
            break;
        }

        rpt_credits = HTC_GET_FIELD(pRpt, HTC_CREDIT_REPORT, CREDITS);

        pEndpoint = &target->EndPoint[rpt_ep_id];

        AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("  Endpoint %d got %d credits \n",
                rpt_ep_id, rpt_credits));

#ifdef HTC_EP_STAT_PROFILING

        INC_HTC_EP_STAT(pEndpoint, TxCreditRpts, 1);
        INC_HTC_EP_STAT(pEndpoint, TxCreditsReturned, rpt_credits);

        if (FromEndpoint == rpt_ep_id) {
                /* this credit report arrived on the same endpoint indicating it arrived in an RX
                 * packet */
            INC_HTC_EP_STAT(pEndpoint, TxCreditsFromRx, rpt_credits);
            INC_HTC_EP_STAT(pEndpoint, TxCreditRptsFromRx, 1);
        } else if (FromEndpoint == ENDPOINT_0) {
                /* this credit arrived on endpoint 0 as a NULL message */
            INC_HTC_EP_STAT(pEndpoint, TxCreditsFromEp0, rpt_credits);
            INC_HTC_EP_STAT(pEndpoint, TxCreditRptsFromEp0, 1);
        } else {
                /* arrived on another endpoint */
            INC_HTC_EP_STAT(pEndpoint, TxCreditsFromOther, rpt_credits);
            INC_HTC_EP_STAT(pEndpoint, TxCreditRptsFromOther, 1);
        }

#endif
#if defined(HIF_USB)
        if (pEndpoint->Id >= ENDPOINT_2 && pEndpoint->Id <= ENDPOINT_5) {
            HTC_ENDPOINT_ID eid[DATA_EP_SIZE] = {ENDPOINT_5, ENDPOINT_4, ENDPOINT_2, ENDPOINT_3};
            int epid_idx;

            target->avail_tx_credits += rpt_credits;

            for (epid_idx = 0; epid_idx < DATA_EP_SIZE; epid_idx++) {
                pEndpoint = &target->EndPoint[eid[epid_idx]];
                if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)) {
                    break;
                }

            }
            UNLOCK_HTC_TX(target);
            HTCTrySend(target,pEndpoint,NULL);
            LOCK_HTC_TX(target);
        } else {
            pEndpoint->TxCredits += rpt_credits;

            if (pEndpoint->TxCredits && HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)) {
                UNLOCK_HTC_TX(target);
                HTCTrySend(target,pEndpoint,NULL);
                LOCK_HTC_TX(target);
            }
        }
#else
        pEndpoint->TxCredits += rpt_credits;

        if (pEndpoint->TxCredits && HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)) {
            UNLOCK_HTC_TX(target);
            HTCTrySend(target,pEndpoint,NULL);
            LOCK_HTC_TX(target);
        }
#endif
        totalCredits += rpt_credits;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("  Report indicated %d credits to distribute \n", totalCredits));

    UNLOCK_HTC_TX(target);

    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCProcessCreditRpt \n"));
}

/* function to fetch stats from htc layer*/
struct ol_ath_htc_stats *ieee80211_ioctl_get_htc_stats(HTC_HANDLE HTCHandle)
{
    HTC_TARGET *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);

    return(&(target->htc_pkt_stats));
}

