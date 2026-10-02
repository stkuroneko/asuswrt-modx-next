//------------------------------------------------------------------------------
// <copyright file="htc_services.c" company="Atheros">
//    Copyright (c) 2007-2010 Atheros Corporation.  All rights reserved.
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------
//==============================================================================
// Author(s): ="Atheros"
//==============================================================================
/*
 *  Copyright (c) 2014 Qualcomm Atheros, Inc.  All rights reserved.
 *
 *  Qualcomm is a trademark of Qualcomm Technologies Incorporated, registered in the United
 *  States and other countries.  All Qualcomm Technologies Incorporated trademarks are used with
 *  permission.  Atheros is a trademark of Qualcomm Atheros, Inc., registered in
 *  the United States and other countries.  Other products and brand names may be
 *  trademarks or registered trademarks of their respective owners.
 */
#include "htc_internal.h"
#include <adf_nbuf.h>  /* adf_nbuf_t */

extern unsigned int htc_credit_flow;

A_STATUS HTCConnectService(HTC_HANDLE               HTCHandle,
                           HTC_SERVICE_CONNECT_REQ  *pConnectReq,
                           HTC_SERVICE_CONNECT_RESP *pConnectResp)
{
    HTC_TARGET *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    A_STATUS                            status = A_OK;
    HTC_PACKET                          *pSendPacket = NULL;
    HTC_CONNECT_SERVICE_RESPONSE_MSG    *pResponseMsg;
    HTC_CONNECT_SERVICE_MSG             *pConnectMsg;
    HTC_ENDPOINT_ID                     assignedEndpoint = ENDPOINT_MAX;
    HTC_ENDPOINT                        *pEndpoint;
    unsigned int                        maxMsgSize = 0;
    adf_nbuf_t                          netbuf;
    A_UINT8                             txAlloc;
    int                                 length;
    A_BOOL                              disableCreditFlowCtrl = FALSE;
    A_UINT16                            conn_flags;
    A_UINT16                            rsp_msg_id, rsp_msg_serv_id, rsp_msg_max_msg_size;
    A_UINT8                             rsp_msg_status, rsp_msg_end_id, rsp_msg_serv_meta_len;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+HTCConnectService, target:%p SvcID:0x%X \n",
               		target, pConnectReq->ServiceID));

    do {

        AR_DEBUG_ASSERT(pConnectReq->ServiceID != 0);

        if (HTC_CTRL_RSVD_SVC == pConnectReq->ServiceID) {
                /* special case for pseudo control service */
            assignedEndpoint = ENDPOINT_0;
            maxMsgSize = HTC_MAX_CONTROL_MESSAGE_LENGTH;
            txAlloc = 0;

        } else {

            txAlloc = HTCGetCreditAllocation(target,pConnectReq->ServiceID);
            if (!txAlloc) {
                AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("Service %d does not allocate target credits!\n",
                            pConnectReq->ServiceID));
            }

                /* allocate a packet to send to the target */
            pSendPacket = HTCAllocControlTxPacket(target);

            if (NULL == pSendPacket) {
                AR_DEBUG_ASSERT(FALSE);
                status = A_NO_MEMORY;
                break;
            }

            netbuf = (adf_nbuf_t)GET_HTC_PACKET_NET_BUF_CONTEXT(pSendPacket);
            length = sizeof(HTC_CONNECT_SERVICE_MSG) + pConnectReq->MetaDataLength;

                /* assemble connect service message */
            if (adf_nbuf_put_tail(netbuf, length) == NULL) {
                AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("Failed to expand head for HTC_CONNECT_SERVICE_MSG msg\n"));
                status = A_NO_MEMORY;
                break;
            }
            pConnectMsg = (HTC_CONNECT_SERVICE_MSG *)adf_nbuf_data(netbuf);
            AR_DEBUG_ASSERT(pConnectMsg != NULL);

            A_MEMZERO(pConnectMsg,sizeof(HTC_CONNECT_SERVICE_MSG));

            conn_flags = (pConnectReq->ConnectionFlags & ~HTC_SET_RECV_ALLOC_MASK) |
                        HTC_CONNECT_FLAGS_SET_RECV_ALLOCATION(txAlloc);
            HTC_SET_FIELD(pConnectMsg, HTC_CONNECT_SERVICE_MSG, MESSAGEID,
                            HTC_MSG_CONNECT_SERVICE_ID);
            HTC_SET_FIELD(pConnectMsg, HTC_CONNECT_SERVICE_MSG, SERVICE_ID,
                            pConnectReq->ServiceID);
            HTC_SET_FIELD(pConnectMsg, HTC_CONNECT_SERVICE_MSG,
                            CONNECTIONFLAGS, conn_flags);

            if (pConnectReq->ConnectionFlags & HTC_CONNECT_FLAGS_DISABLE_CREDIT_FLOW_CTRL) {
                disableCreditFlowCtrl = TRUE;
            }

             /*
              * EV #134248 BUG Fix : Credit miss happens resulting in failure to create
             * VAP. Disable Credit for WMI endpoint too.
             */
            if (!htc_credit_flow ) {
                disableCreditFlowCtrl = TRUE;
            }

                /* check caller if it wants to transfer meta data */
            if ((pConnectReq->pMetaData != NULL) &&
                (pConnectReq->MetaDataLength <= HTC_SERVICE_META_DATA_MAX_LENGTH)) {
                    /* copy meta data into message buffer (after header ) */
                A_MEMCPY((A_UINT8 *)pConnectMsg + sizeof(HTC_CONNECT_SERVICE_MSG),
                         pConnectReq->pMetaData,
                         pConnectReq->MetaDataLength);

                HTC_SET_FIELD(pConnectMsg, HTC_CONNECT_SERVICE_MSG,
                            SERVICEMETALENGTH, pConnectReq->MetaDataLength);
            }

            SET_HTC_PACKET_INFO_TX(pSendPacket,
                                   NULL,
                                   (A_UINT8 *)pConnectMsg,
                                   length,
                                   ENDPOINT_0,
                                   HTC_SERVICE_TX_PACKET_TAG);


            status = HTCSendPkt((HTC_HANDLE)target,pSendPacket);
                /* we don't own it anymore */
            pSendPacket = NULL;
            if (A_FAILED(status)) {
                break;
            }

                /* wait for response */
            status = HTCWaitRecvCtrlMessage(target);
            if (A_FAILED(status)) {
                break;
            }
                /* we controlled the buffer creation so it has to be properly aligned */
            pResponseMsg = (HTC_CONNECT_SERVICE_RESPONSE_MSG *)target->CtrlResponseBuffer;

            rsp_msg_id = HTC_GET_FIELD(pResponseMsg,
                    HTC_CONNECT_SERVICE_RESPONSE_MSG, MESSAGEID);
            rsp_msg_serv_id = HTC_GET_FIELD(pResponseMsg,
                    HTC_CONNECT_SERVICE_RESPONSE_MSG, SERVICEID);
            rsp_msg_status = HTC_GET_FIELD(pResponseMsg,
                    HTC_CONNECT_SERVICE_RESPONSE_MSG, STATUS);
            rsp_msg_end_id = HTC_GET_FIELD(pResponseMsg,
                    HTC_CONNECT_SERVICE_RESPONSE_MSG, ENDPOINTID);
            rsp_msg_max_msg_size = HTC_GET_FIELD(pResponseMsg,
                    HTC_CONNECT_SERVICE_RESPONSE_MSG, MAXMSGSIZE);
            rsp_msg_serv_meta_len = HTC_GET_FIELD(pResponseMsg,
                    HTC_CONNECT_SERVICE_RESPONSE_MSG, SERVICEMETALENGTH);


            if ((rsp_msg_id != HTC_MSG_CONNECT_SERVICE_RESPONSE_ID) ||
                (target->CtrlResponseLength < sizeof(HTC_CONNECT_SERVICE_RESPONSE_MSG))) {
                    /* this message is not valid */
                AR_DEBUG_ASSERT(FALSE);
                status = A_EPROTO;
                break;
            }

            AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
                    ("HTCConnectService, service 0x%X connect response from target status:%d, assigned ep: %d\n",
                                rsp_msg_serv_id, rsp_msg_status, rsp_msg_end_id));

            pConnectResp->ConnectRespCode = rsp_msg_status;

            /* check response status */
            if (rsp_msg_status != HTC_SERVICE_SUCCESS) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
                    (" Target failed service 0x%X connect request (status:%d)\n",
                                rsp_msg_serv_id, rsp_msg_status));
                status = A_EPROTO;
                break;
            }

            assignedEndpoint = (HTC_ENDPOINT_ID)rsp_msg_end_id;
            maxMsgSize = rsp_msg_max_msg_size;

            if ((pConnectResp->pMetaData != NULL) &&
                (rsp_msg_serv_meta_len > 0) &&
                (rsp_msg_serv_meta_len <= HTC_SERVICE_META_DATA_MAX_LENGTH)) {
                    /* caller supplied a buffer and the target responded with data */
                int copyLength = min((int)pConnectResp->BufferLength, (int)rsp_msg_serv_meta_len);
                    /* copy the meta data */
                A_MEMCPY(pConnectResp->pMetaData,
                         ((A_UINT8 *)pResponseMsg) + sizeof(HTC_CONNECT_SERVICE_RESPONSE_MSG),
                         copyLength);
                pConnectResp->ActualLength = copyLength;
            }
                /* done processing response buffer */
            target->CtrlResponseProcessing = FALSE;
        }

            /* the rest of these are parameter checks so set the error status */
        status = A_EPROTO;

        if (assignedEndpoint >= ENDPOINT_MAX) {
            AR_DEBUG_ASSERT(FALSE);
            break;
        }

        if (0 == maxMsgSize) {
            AR_DEBUG_ASSERT(FALSE);
            break;
        }

        pEndpoint = &target->EndPoint[assignedEndpoint];
        pEndpoint->Id = assignedEndpoint;
        if (pEndpoint->ServiceID != 0) {
            /* endpoint already in use! */
            AR_DEBUG_ASSERT(FALSE);
            break;
        }

            /* return assigned endpoint to caller */
        pConnectResp->Endpoint = assignedEndpoint;
        pConnectResp->MaxMsgLength = maxMsgSize;

            /* setup the endpoint */
        pEndpoint->ServiceID = pConnectReq->ServiceID; /* this marks the endpoint in use */
        pEndpoint->MaxTxQueueDepth = pConnectReq->MaxSendQueueDepth;
        pEndpoint->MaxMsgLength = maxMsgSize;
        pEndpoint->TxCredits = txAlloc;
        pEndpoint->TxCreditSize = target->TargetCreditSize;
        pEndpoint->TxCreditsPerMaxMsg = maxMsgSize / target->TargetCreditSize;
        if (maxMsgSize % target->TargetCreditSize) {
            pEndpoint->TxCreditsPerMaxMsg++;
        }

            /* copy all the callbacks */
        pEndpoint->EpCallBacks = pConnectReq->EpCallbacks;

        status = HIFMapServiceToPipe(target->hif_dev,
                                     pEndpoint->ServiceID,
                                     &pEndpoint->UL_PipeID,
                                     &pEndpoint->DL_PipeID,
                                     &pEndpoint->ul_is_polled,
                                     &pEndpoint->dl_is_polled);
        if (A_FAILED(status)) {
            break;
        }

        adf_os_assert(!pEndpoint->dl_is_polled); /* not currently supported */

        if (pEndpoint->ul_is_polled) {
            adf_os_timer_init(
                target->osdev,
                &pEndpoint->ul_poll_timer,
                HTCSendCompleteCheckCleanup,
                pEndpoint);
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("Target:%p HTC Service:0x%4.4X, ULpipe:%d DLpipe:%d id:%d Ready\n",
                       target, pEndpoint->ServiceID,pEndpoint->UL_PipeID,pEndpoint->DL_PipeID,pEndpoint->Id));

        if (disableCreditFlowCtrl && pEndpoint->TxCreditFlowEnabled) {
            pEndpoint->TxCreditFlowEnabled = FALSE;
            AR_DEBUG_PRINTF(ATH_DEBUG_WARN,("HTC Service:0x%4.4X ep:%d TX flow control disabled\n",
                                pEndpoint->ServiceID, assignedEndpoint));
        }

    } while (FALSE);

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-HTCConnectService \n"));

    return status;
}


void HTCSetCreditDistribution(HTC_HANDLE               HTCHandle,
                              void                     *pCreditDistContext,
                              HTC_CREDIT_DIST_CALLBACK CreditDistFunc,
                              HTC_CREDIT_INIT_CALLBACK CreditInitFunc,
                              HTC_SERVICE_ID           ServicePriorityOrder[],
                              int                      ListLength)
{
   /* NOT Supported, this transport does not use a credit based flow control mechanism */

}


void HTCFwEventHandler(void *context)
{
    HTC_TARGET      *target = (HTC_TARGET *)context;
    HTC_INIT_INFO   *initInfo = &target->HTCInitInfo;

    /*
     * Currently, there's only one event type (Target Failure);
     * there's no need to discriminate between event types.
     */
    if (target->HTCInitInfo.TargetFailure != NULL) {
        initInfo->TargetFailure(initInfo->pContext, A_ERROR);
    }
}
