//------------------------------------------------------------------------------
// Copyright (c) 2011 Atheros Communications Inc.
// All rights reserved.
//
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------
/*
 *  Copyright (c) 2014 Qualcomm Atheros, Inc.  All rights reserved. 
 *
 *  Qualcomm is a trademark of Qualcomm Technologies Incorporated, registered in the United
 *  States and other countries.  All Qualcomm Technologies Incorporated trademarks are used with
 *  permission.  Atheros is a trademark of Qualcomm Atheros, Inc., registered in
 *  the United States and other countries.  Other products and brand names may be
 *  trademarks or registered trademarks of their respective owners. 
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


#include <targaddrs.h>
#include <bmi_msg.h>
#include <hif.h>
#include <htc_services.h>

#include "hif_msg_based.h"

#include "ath_hif_usb.h"
#include "host_reg_table.h"
#include "target_reg_table.h"
#include "ol_ath.h"

#if defined(EPPING_TEST)
#include "epping_test.h"
#endif

#define ATH_MODULE_NAME hif_usb
#include <a_debug.h>
#include "hif_usb_internal.h"

#define HIF_USB_DEBUG   ATH_DEBUG_MAKE_MODULE_MASK(0)

#if defined(DEBUG)
static ATH_DEBUG_MASK_DESCRIPTION g_HIFDebugDescription[] = {
    {HIF_USB_DEBUG,"hif_usb"},
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(hif_usb,
                                 "hif_usb",
                                 "USB Host Interface",
                                 ATH_DEBUG_MASK_DEFAULTS | ATH_DEBUG_INFO | HIF_USB_DEBUG,
                                 ATH_DEBUG_DESCRIPTION_COUNT(g_HIFDebugDescription),
                                 g_HIFDebugDescription);
#endif

/* use credit flow control over HTC */
unsigned int htc_credit_flow = 1;
unsigned int hif_usb_disable_rxdata2 = 1;
#define USB_HIF_USE_SINGLE_PIPE_FOR_DATA

struct HIF_CE_state {
    struct ath_hif_pci_softc *sc;
    int shut_down; /* Set to non-zero during driver shut down */
    int started;
    
    void *claimedContext;
};

NTSTATUS KmdfUsbControl(WDFUSBDEVICE Device, UCHAR req, USHORT value, USHORT index,
    void *data, ULONG size, UCHAR in)
{
    PURB         pUrb = NULL;
    USHORT       siz;
    NTSTATUS     ntStatus;
    UCHAR        *image;
    WDF_REQUEST_SEND_OPTIONS reqSendOptions;

    // Set up urb to download file
    image = (UCHAR *) data;
    siz = sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST);
    NdisAllocateMemoryWithTag((PVOID *)&pUrb, siz, 'athr');
                      
    if (pUrb == NULL)
    {
        return NDIS_STATUS_FAILURE;
    }

    UsbBuildVendorRequest(  pUrb,
                            URB_FUNCTION_VENDOR_DEVICE,
                            siz,
                            (in == 0)? 0: (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK),
                            0,
                            req,                        // reguest, ID
                            value,                      // Value
                            0,                          // Index
                            image,
                            NULL,
                            size,
                            NULL
                         );

    WDF_REQUEST_SEND_OPTIONS_INIT(&reqSendOptions, 
                                  WDF_REQUEST_SEND_OPTION_TIMEOUT |
                                  WDF_REQUEST_SEND_OPTION_SYNCHRONOUS |
                                  WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE);
    reqSendOptions.Timeout = WDF_REL_TIMEOUT_IN_MS(2000);

    ntStatus = WdfUsbTargetDeviceSendUrbSynchronously(Device, 
                                           NULL,
                                           &reqSendOptions,
                                           pUrb);

    // free resources
    NdisFreeMemory(pUrb, siz, 0);


    if (!NT_SUCCESS(ntStatus))
    {
        /* TODO: exception handling */
    }

    return NDIS_STATUS_SUCCESS;        
}

A_STATUS usb_hif_submit_ctrl_out(HIF_DEVICE_USB *device, 
                                 A_UINT8        req, 
                                 A_UINT16       value, 
                                 A_UINT16       index, 
                                 void           *data, 
                                 A_UINT32       size)
{
    A_UINT32  result = 0;
    A_STATUS  ret = A_OK;
    A_UINT8   *buf = NULL;

    do {
        if (size > 0) {
            buf = A_MALLOC(size);
            if (NULL == buf) {
                ret = A_NO_MEMORY;
                break;    
            }
            memcpy(buf, (A_UINT8*)data, size);
        }
        
        AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
                        ("ctrl-out req:0x%2.2X, value:0x%4.4X index:0x%4.4X, datasize:%d\n",
                        req,value,index,size));

        result = KmdfUsbControl(device->usbCb.WdfUsbTargetDevice,
                                 req,
                                 value,
                                 index,
                                 buf,
                                 size,
                                 0
                                );

        if (A_FAILED(result)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s failed,result = %d \n", __FUNCTION__, result));
            ret = A_ERROR;
        }
    
    } while (FALSE);
        
    if (buf != NULL) {
        A_FREE(buf);
    }

    return ret;
}

A_STATUS usb_hif_submit_ctrl_in(HIF_DEVICE_USB *device,
                                A_UINT8        req, 
                                A_UINT16       value, 
                                A_UINT16       index, 
                                void           *data, 
                                A_UINT32       size)
{
    A_UINT32   result = 0;
    A_STATUS   ret = A_OK;
    A_UINT8    *buf = NULL;

    do {
        
        if (size > 0) {
            buf = A_MALLOC(size);
            if (NULL == buf) {
                ret = A_NO_MEMORY;
                break;    
            }
        }
    
        AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
                        ("ctrl-in req:0x%2.2X, value:0x%4.4X index:0x%4.4X, datasize:%d\n",
                        req,value,index,size));

        result = KmdfUsbControl(device->usbCb.WdfUsbTargetDevice,
                                 req,
                                 value,
                                 index,
                                 buf,
                                 size,
                                 1
                                );

        if (A_FAILED(result)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s failed,result = %d \n", __FUNCTION__,result));
            ret = A_ERROR;
            break;
        }    
    
        memcpy((A_UINT8*)data, buf, size);
    
    } while (FALSE);
    
    if (buf != NULL) {
        A_FREE(buf);
    }
    
    return ret;
}


static A_STATUS HIFCtrlMsgExchange(HIF_DEVICE_USB *macp, 
                                   A_UINT8         SendReqVal,
                                   A_UINT8        *pSendMessage, 
                                   A_UINT32        Length, 
                                   A_UINT8         ResponseReqVal,
                                   A_UINT8        *pResponseMessage,
                                   A_UINT32       *pResponseLength)
{
    A_STATUS    status;

    do {
        /* send command */
        status = usb_hif_submit_ctrl_out(macp,SendReqVal, 0, 0, pSendMessage, Length);
        
        if (A_FAILED(status)) {
            break;    
        }
        
        if (NULL == pResponseMessage) {
            /* no expected response */            
            break;    
        }
       
        /* get response */
        status = usb_hif_submit_ctrl_in(macp,ResponseReqVal, 0, 0, pResponseMessage, *pResponseLength);
        
        if (A_FAILED(status)) {
            break;    
        }
        
    } while (FALSE);
    
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
HIFShutDownDevice(HIF_DEVICE *hif_device)
{

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("+%s\n",__FUNCTION__));

    if (hif_device) {
        struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
        struct ath_hif_pci_softc *sc = hif_state->sc;
        HIF_DEVICE_USB              *hHIF_DEV = sc->UsbBusInterface;

        HIFStop(hif_device);
        KmdfUSbReturnPipeResources(hHIF_DEV);
        usb_hif_destroy(hHIF_DEV);
        A_FREE(hif_state);
#if 0
    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("Full ath PCI HIF shutdown\n"));
        ath_pci_module_exit();
#endif
    }   

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("-%s\n",__FUNCTION__));
}

A_STATUS
HIFDiagReadMem(HIF_DEVICE *hif_device, A_UINT32 address, A_UINT8 *data, int nbytes)
{
    A_STATUS status = EOK;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));  
    return status;
}

int
HIFExchangeBMIMsg(HIF_DEVICE *hif_device,
                  A_UINT8    *bmi_request,
                  u_int32_t   request_length,
                  A_UINT8    *bmi_response,
                  u_int32_t   *bmi_response_lengthp,
                  u_int32_t   TimeoutMS)
{
    int status = EOK;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    HIF_DEVICE_USB            *hHIF_DEV = sc->UsbBusInterface;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    status = HIFCtrlMsgExchange(hHIF_DEV, 
                              USB_CONTROL_REQ_SEND_BMI_CMD,
                              bmi_request, 
                              request_length, 
                              USB_CONTROL_REQ_RECV_BMI_RESP,
                              bmi_response,
                              bmi_response_lengthp);
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));      
    return status;
}

int
HIFMapServiceToPipe(HIF_DEVICE *hif_device, a_uint16_t ServiceId, a_uint8_t *ULPipe, a_uint8_t *DLPipe, int *ul_is_polled, int *dl_is_polled)
{
    int status = EOK;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    PADAPTER pAdapter = sc->scn->sc_osdev->pAdapter;
    HIF_DEVICE_USB            *hHIF_DEV = sc->UsbBusInterface;
    HIF_KMDF_USB_CB *pUsbCb = &hHIF_DEV->usbCb;    
    A_BOOL bFullSpeed = pUsbCb->bFullSpeed;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    switch (ServiceId) {
        case HTC_CTRL_RSVD_SVC :
        case WMI_CONTROL_SVC  :
            *ULPipe = HIF_TX_CTRL_PIPE;
            //*DLPipe = HIF_RX_CTRL_PIPE;
            // due to large control packets, shift to data pipe
            if (bFullSpeed) {
                *DLPipe = HIF_RX_INT_PIPE;
            } else {
                *DLPipe = HIF_RX_DATA_PIPE;
            }
            break;
        case WMI_DATA_BE_SVC :
        case WMI_DATA_BK_SVC :
            *ULPipe = HIF_TX_DATA_LP_PIPE;
            if (bFullSpeed) {
                *DLPipe = HIF_RX_INT_PIPE;
            } else {
                if (hif_usb_disable_rxdata2) {
                    *DLPipe = HIF_RX_DATA_PIPE;    
                } else {
                    *DLPipe = HIF_RX_DATA2_PIPE;
                }
            }
            break;
        case WMI_DATA_VI_SVC :
#ifdef USB_HIF_USE_SINGLE_PIPE_FOR_DATA
            *ULPipe = HIF_TX_DATA_LP_PIPE;
#else        
            *ULPipe = HIF_TX_DATA_MP_PIPE;
#endif            
            if (bFullSpeed) {
                *DLPipe = HIF_RX_INT_PIPE;
            } else {
                if (hif_usb_disable_rxdata2) {
                    *DLPipe = HIF_RX_DATA_PIPE;    
                } else {
                    *DLPipe = HIF_RX_DATA2_PIPE;
                }
            }
            break;
        case WMI_DATA_VO_SVC :
#ifdef USB_HIF_USE_SINGLE_PIPE_FOR_DATA
            *ULPipe = HIF_TX_DATA_LP_PIPE;
#else          
            *ULPipe = HIF_TX_DATA_HP_PIPE;
#endif            
            if (bFullSpeed) {
                *DLPipe = HIF_RX_INT_PIPE;
            } else {
                if (hif_usb_disable_rxdata2) {
                    *DLPipe = HIF_RX_DATA_PIPE;    
                } else {
                    *DLPipe = HIF_RX_DATA2_PIPE;
                }
#ifdef USB_HIF_TEST_INTERRUPT_IN 
                *DLPipe = HIF_RX_INT_PIPE;
#endif      
            }
            break;
        case HTC_RAW_STREAMS_SVC :
            *ULPipe = HIF_TX_CTRL_PIPE;
            if (bFullSpeed) {
                *DLPipe = HIF_RX_INT_PIPE;
            } else {
                *DLPipe = HIF_RX_DATA_PIPE;
            }
            break;
        default:
            status = A_ENOTSUP;
            break;    
    } 

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));    
    return status;
}

NTSTATUS HIF_UsbSend(HIF_DEVICE *hifDevice, UCHAR endpt,unsigned int transfer_id, adf_nbuf_t buf)
{

    ULONG ret = 0;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hifDevice;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    PADAPTER  pAdapter = sc->scn->sc_osdev->pAdapter;
    HIF_DEVICE_USB            *device = sc->UsbBusInterface;
    HIF_KMDF_USB_CB *pUsbCb = &device->usbCb;
    HIF_USB_TX_PIPE *txPipe = &(pUsbCb->USB_TX_PIPE[endpt]);
    if (pUsbCb->USB_TX_PIPE[endpt].UsbTxPipe == NULL) {
        HIF_InitTxPipe(device, endpt);
    }

    /* Enqueue the packet into UsbTxBufQ */
    if (KmdfUsbPutTxBuffer(device, endpt, transfer_id, buf) != A_OK) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ret = KmdfUsbSubmitTxData(device, txPipe, endpt, transfer_id);

    return ret;
}

A_STATUS
HIFSend_head(HIF_DEVICE *hif_device, 
             a_uint8_t pipe, unsigned int transfer_id, unsigned int nbytes, adf_nbuf_t nbuf)
{
    A_STATUS status = EOK;
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;  
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    if (!hif_state->started)
        return -ENOMEM;
    HIF_UsbSend(hif_device, usb_hif_get_usb_epnum(pipe)-1, transfer_id, nbuf);
   
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));    
    return status;
}

void
HIFSendCompleteCheck(HIF_DEVICE *hif_device, a_uint8_t pipe, int force)
{

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

a_uint16_t
HIFGetFreeQueueNumber(HIF_DEVICE *hif_device, a_uint8_t pipe)
{
    a_uint16_t rv = 0;
    rv = ATH_USB_MAX_TX_BUF_NUM;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
    return rv;
}

void
HIFDetachHTC(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
    struct ath_hif_pci_softc *sc = hif_state->sc;
    HIF_DEVICE_USB            *device = sc->UsbBusInterface;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));
    A_MEMZERO(&device->htcCallbacks, sizeof(MSG_BASED_HIF_CALLBACKS));    
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
HIFPostInit(HIF_DEVICE *hif_device, void *unused, MSG_BASED_HIF_CALLBACKS *callbacks)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
	struct ath_hif_pci_softc *sc = hif_state->sc;
	HIF_DEVICE_USB            *device = sc->UsbBusInterface;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));

    A_MEMCPY(&device->htcCallbacks.Context, callbacks, sizeof(MSG_BASED_HIF_CALLBACKS));
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}


extern ULONGLONG numReceived;
unsigned int recvPayloadlen = 0;
extern ULONGLONG epptimer_start;
extern ULONGLONG epptimer_end;
extern ULONGLONG txduration_ms;
extern ULONGLONG txduration;
extern unsigned int EPPING_RX_TEST_START;
extern unsigned int EPPING_TX_TEST_START;

void UsbRxRequestCompletionRoutine(
    IN WDFREQUEST                  Request,
    IN WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    IN WDFCONTEXT                  Context
    )
{
    NTSTATUS    status;
    NTSTATUS    rxStatus;
    WDFOBJECT rxObj = (WDFOBJECT)Context;
    UsbRxRequestItem *pItem = (UsbRxRequestItem *)GetUsbRxRequestItem(rxObj);
    PADAPTER pAdapter = pItem->pAdapter;
    struct ath_hif_pci_softc *sc = pItem->sc;
    struct ol_ath_softc_net80211 *scn = sc->scn;    
    HIF_DEVICE_USB *device = (HIF_DEVICE_USB *)sc->UsbBusInterface;
    HIF_KMDF_USB_CB *pUsbCb = &device->usbCb;
    adf_nbuf_t nbuf = NULL;
    WDF_REQUEST_REUSE_PARAMS params;
    int res;
    ULONG readLen, i;
    int rxPIPE;
    A_UINT8 *netdata, *netdata_new;
    A_UINT32 netlen, netlen_new;
#if defined(EPPING_TEST)  
    EPPING_HEADER *pktHeader = NULL;
    ULONGLONG rx_Throughput = 0;
    unsigned int  numTxPerfReceived = 0;
    unsigned int  numTxPerfDataCRC = 0;
    unsigned int numTxPerfTransmitted = EPPING_TX_PACKET_NUM * EPPING_TX_PACKETS_TOGETHER;
    ULONGLONG tx_Throughput = 0;
    ULONGLONG rxduration;
#endif

    PWDF_USB_REQUEST_COMPLETION_PARAMS usbCompletionParams;

    rxStatus = CompletionParams->IoStatus.Status;
    usbCompletionParams = CompletionParams->Parameters.Usb.Completion;
    readLen = (ULONG)(usbCompletionParams->Parameters.PipeRead.Length);
    netdata = pItem->rxwbuf;
    netlen = readLen;

    if (pUsbCb->bFullSpeed) {
        rxPIPE = HIF_RX_INT_PIPE;
    } else {
        rxPIPE = HIF_RX_DATA_PIPE;
    }

    if (MP_GET_BIT(pUsbCb->UsbPipeResetFlag, rxPIPE)) {
    } else if (NT_SUCCESS(rxStatus)) {
        do {
            if (readLen < HTC_HDR_LENGTH) {
              AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("%s it's bed length: %d \n",__FUNCTION__, readLen));
              break;
            }
#if defined(EPPING_TEST)
            pktHeader = (EPPING_HEADER *)(netdata + HTC_HDR_LENGTH);
#if AR6004_HW
            if ((readLen >= (HTC_HDR_LENGTH + sizeof(EPPING_HEADER) -2)) && (IS_EPPING_PACKET(pktHeader))){
#else
            if ((readLen >= (HTC_HDR_LENGTH + sizeof(EPPING_HEADER))) && (IS_EPPING_PACKET(pktHeader))){
#endif
                if ((pktHeader->Cmd_h == EPPING_CMD_CONT_RX_STOP) && EPPING_RX_TEST_START)
                {
                    EPPING_RX_TEST_START = 0;
                    NdisGetSystemUpTimeEx ((PLARGE_INTEGER) &epptimer_end);
                    rxduration = (epptimer_end - epptimer_start);
                    if ((rxduration != 0 && rxduration > 1000) && ((numReceived*recvPayloadlen) != 0))
                        rx_Throughput = (numReceived*recvPayloadlen*8)/(rxduration/1000);

                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n\n---------------------------------------------------------------------------------\n"));
                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n    EPP RX Result:  Recv(%I64d)Packets   (%d)bytes/pkt    Duration(%I64d)ms  EP(%d)\n", 
                            numReceived, recvPayloadlen, rxduration, *netdata));
                    if (rx_Throughput > 0) {
            		AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n    EPP RX throughput:(%I64d)bps\n", rx_Throughput)); }
                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n---------------------------------------------------------------------------------\n\n"));
                } else {
                    numReceived++;
                    recvPayloadlen = readLen - HTC_HDR_LENGTH;
                }
                if ((pktHeader->HostContext_h == 3) && (pktHeader->Cmd_h == EPPING_CMD_CAPTURE_RECV_CNT) 
                    && EPPING_TX_TEST_START) {
                    EPPING_TX_TEST_START = 0;
                    memcpy(&numTxPerfReceived, pktHeader->CmdBuffer_t, sizeof(numTxPerfReceived));
                    memcpy(&numTxPerfDataCRC, &pktHeader->CmdBuffer_t[4], sizeof(numTxPerfReceived));
                    if ((numTxPerfReceived != 0) && (txduration_ms != 0 && txduration_ms > 1000))
                      tx_Throughput = (numTxPerfReceived*EPPING_TX_PACKET_LEN*8)/(txduration_ms/1000);
                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n\n---------------------------------------------------------------------------------\n"));
                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n    EPP  TX Result:   Firmware recv %d Packet     (%d)bytes/pkt    Duration (%I64d)ms \n", 
                        numTxPerfReceived, EPPING_TX_PACKET_LEN, txduration_ms));
                    if (tx_Throughput > 0) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n          TX throughput: (%I64d)bps \n", tx_Throughput));}
                    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("\n---------------------------------------------------------------------------------\n\n"));                    
                }
            } 
			else 
#endif
#if AR6004_HW
            {
                if (netdata[1] == 0x02 && netdata[6] == 0x01 && netdata[7] == 0x02) {
                   netdata[2] = 8;
                   netdata[4] = 8;
                   netdata[7] = 4;
                   nbuf = adf_nbuf_alloc(scn->adf_dev,(readLen +6), 0, 4, FALSE);
                   if (nbuf == NULL) {
                     break;
                   }
                   adf_nbuf_peek_header(nbuf, &netdata_new, &netlen_new);
                   A_MEMCPY(netdata_new, netdata, 6);
                   A_MEMCPY(netdata_new+8, netdata+6, 2);
                   A_MEMCPY(netdata_new+12, netdata+8, 2);
                   adf_nbuf_put_tail(nbuf, readLen+6);
                } else {
                   nbuf = adf_nbuf_alloc(scn->adf_dev,(readLen +4), 0, 4, FALSE);
                   if (nbuf == NULL) {
                      break;
                   }
                   adf_nbuf_peek_header(nbuf, &netdata_new, &netlen_new);
                   A_MEMCPY(netdata_new, netdata, 6);
                   A_MEMCPY(netdata_new+8, netdata+6, (readLen-6));
                   adf_nbuf_put_tail(nbuf, readLen+4);
                }
                device->htcCallbacks.rxCompletionHandler(device->htcCallbacks.Context,
                                                         nbuf,
                                                         rxPIPE);
            }
#else
            {
                nbuf = adf_nbuf_alloc(scn->adf_dev,readLen, 0, 4, FALSE);
                if (nbuf == NULL) {
                    break;
                }
                adf_nbuf_peek_header(nbuf, &netdata_new, &netlen_new);
                A_MEMCPY(netdata_new, netdata, readLen);
                adf_nbuf_put_tail(nbuf, readLen);
                device->htcCallbacks.rxCompletionHandler(device->htcCallbacks.Context,
                                                          nbuf,
                                                          rxPIPE);
            }
#endif
        } while (FALSE);
    }
    else {
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("%s_%d: IO return failed, IoStatus = 0x%x, UsbdStatus = 0x%x\n",  __FUNCTION__, __LINE__, rxStatus, CompletionParams->Parameters.Usb.Completion->UsbdStatus));        
       
        if ( (rxStatus != STATUS_CANCELLED) &&
             (rxStatus != STATUS_NO_SUCH_DEVICE) &&
             (device->bUSBDeveiceAttached == TRUE) ) {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("%s_%d: Issue reset !, IoStatus = 0x%x, UsbdStatus = 0x%x\n",  __FUNCTION__, __LINE__, rxStatus, CompletionParams->Parameters.Usb.Completion->UsbdStatus));        
            KmdfUsbSchedulePipeReset(device, pUsbCb->USBRestPipe[rxPIPE]);
        }
    }

    WDF_REQUEST_REUSE_PARAMS_INIT(&params, WDF_REQUEST_REUSE_NO_FLAGS, STATUS_SUCCESS);
    status = WdfRequestReuse(pItem->UsbInRequest, &params);
    if (!NT_SUCCESS(status))
    {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("WdfRequestReuse failed!!!\n"));
        MPASSERT(0);
    }  

    if (MP_GET_BIT(pUsbCb->UsbPipeResetFlag, rxPIPE) ||
       (!NT_SUCCESS(rxStatus))) {
        goto rxFailed;
    }

    {
        res = SendRxObject(device, rxObj);
        
        if ( res != 0 )
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s_%d: SendRxObject fail !\n", __FUNCTION__, __LINE__));

            NdisAcquireSpinLock(&pUsbCb->UsbRxListLock);            
            WdfCollectionRemove(pUsbCb->UsbRxUsedList, rxObj);
            status = WdfCollectionAdd(pUsbCb->UsbRxFreeList, rxObj);
            ASSERT(status == STATUS_SUCCESS);
            NdisReleaseSpinLock(&pUsbCb->UsbRxListLock);              
        }
    }
    
    return;
rxFailed:    
    NdisAcquireSpinLock(&pUsbCb->UsbRxListLock);
    WdfCollectionRemove(pUsbCb->UsbRxUsedList, rxObj);
    WdfCollectionAdd(pUsbCb->UsbRxFreeList, rxObj);
    NdisReleaseSpinLock(&pUsbCb->UsbRxListLock);
}

int SendRxObject(HIF_DEVICE_USB *device, WDFOBJECT rxObj)
{
    UsbRxRequestItem *pItem;
    HIF_KMDF_USB_CB *pUsbCb;
    WDFMEMORY_OFFSET wdfMemOffset;
    adf_nbuf_t buf = NULL;
    WDFIOTARGET IOTarget;

    pUsbCb = &device->usbCb;
    pItem = (UsbRxRequestItem *)GetUsbRxRequestItem(rxObj);


    wdfMemOffset.BufferOffset = 0;
    wdfMemOffset.BufferLength = HIF_USB_RX_BUFFER_SIZE;

    IOTarget = WdfUsbTargetPipeGetIoTarget(pUsbCb->RxPipe);

    WdfUsbTargetPipeFormatRequestForRead(pUsbCb->RxPipe, pItem->UsbInRequest,
                                         pItem->UsbRequestBuffer,
                                         &wdfMemOffset);
                            
    WdfRequestSetCompletionRoutine(pItem->UsbInRequest,
                                   UsbRxRequestCompletionRoutine, rxObj);  

    WdfRequestSend(pItem->UsbInRequest,
                   IOTarget,
                   NULL);      
                       
    return 0;
}

void usb_hif_start_recv_pipes(HIF_DEVICE_USB *device)
{
    struct ath_hif_pci_softc *sc = device->sc;
    struct ol_ath_softc_net80211 *scn = sc->scn;
    PADAPTER  pAdapter = scn->sc_osdev->pAdapter;
    HIF_KMDF_USB_CB *pUsbCb = &device->usbCb;
    int i;
    WDFOBJECT rxObj;

    for (i = 0; i < ATH_USB_RX_CELL_NUMBER; i++)
    {
        NdisAcquireSpinLock(&pUsbCb->UsbRxListLock);
        
        rxObj = WdfCollectionGetFirstItem(pUsbCb->UsbRxFreeList);
        if (rxObj == NULL) {
            NdisReleaseSpinLock(&pUsbCb->UsbRxListLock);
            continue;
        }
        
        WdfCollectionRemove(pUsbCb->UsbRxFreeList, rxObj);
        WdfCollectionAdd(pUsbCb->UsbRxUsedList, rxObj);
        
        NdisReleaseSpinLock(&pUsbCb->UsbRxListLock);

        SendRxObject(device, rxObj);
    }
}

void
HIFStart(HIF_DEVICE *hif_device)
{
    struct HIF_CE_state *hif_state = (struct HIF_CE_state *)hif_device;
	struct ath_hif_pci_softc *sc = hif_state->sc;
	HIF_DEVICE_USB            *hHIF_DEV = sc->UsbBusInterface;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));


    hif_state->started=1;
    hHIF_DEV->bUSBDeveiceAttached = TRUE;
    usb_hif_start_recv_pipes(hHIF_DEV);
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-%s\n",__FUNCTION__));
}

void
HIFStop(HIF_DEVICE *hif_device)
{

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+%s\n",__FUNCTION__));


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
/*
 * Called from USB layer whenever a new PCI device is probed.
 * Initializes per-device HIF state and notifies the main
 * driver that a new HIF device is present.
 */
int
HIF_USBDeviceProbed(hif_handle_t hif_hdl)
{
    struct HIF_CE_state *hif_state;
    HIF_DEVICE_USB              *hHIF_DEV = NULL;
    HIF_KMDF_USB_CB             *pUsbCb = NULL;
    a_uint16_t rv = 0;
    NTSTATUS                    ntStatus = STATUS_SUCCESS;
    struct ath_hif_pci_softc *sc = hif_hdl;
    struct ol_ath_softc_net80211 *scn = sc->scn;
    PADAPTER  pAdapter = scn->sc_osdev->pAdapter;

    hif_state = (struct HIF_CE_state *)A_MALLOC(sizeof(*hif_state));
    if (!hif_state) {
        return -ENOMEM;
    }

    A_MEMZERO(hif_state, sizeof(*hif_state));

    sc->hif_device = (HIF_DEVICE *)hif_state;
    hif_state->sc = sc;

	hHIF_DEV = usb_hif_create(sc->hif_device);
    if (hHIF_DEV == NULL)
    {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("usb_hif_create failed"));
        return -ENOMEM;
    }

    hHIF_DEV->sc = sc;
    hHIF_DEV->bUSBDeveiceAttached = TRUE;
    sc->UsbBusInterface = hHIF_DEV;
    pUsbCb = (HIF_KMDF_USB_CB *)&hHIF_DEV->usbCb;
    NdisZeroMemory(&hHIF_DEV->usbCb, sizeof(HIF_KMDF_USB_CB));
    ntStatus = WdfUsbTargetDeviceCreate(pAdapter->WdfDevice,
                                      WDF_NO_OBJECT_ATTRIBUTES,
                                      &hHIF_DEV->usbCb.WdfUsbTargetDevice);
    if (!NT_SUCCESS(ntStatus)) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s: WdfUsbTargetDeviceCreate failed %x\n",
               __FUNCTION__, ntStatus));
        return -ENOMEM;
    }
    NdisZeroMemory(&hHIF_DEV->usbCb.UsbDeviceDescriptor, sizeof(USB_DEVICE_DESCRIPTOR));
    WdfUsbTargetDeviceGetDeviceDescriptor(hHIF_DEV->usbCb.WdfUsbTargetDevice,
                                          &hHIF_DEV->usbCb.UsbDeviceDescriptor);

    ntStatus = KmdfUsbConfigureDevice(pAdapter->WdfDevice, &hHIF_DEV->usbCb);

    if (!NT_SUCCESS(ntStatus)) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s: ConfigureDevice failed %x\n",
               __FUNCTION__, ntStatus));
        return -ENOMEM;
    }

    ntStatus = KmdfUSbSetupPipeResources(hHIF_DEV);
    if (!NT_SUCCESS(ntStatus)) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s: SetupPipeResources failed %x\n",
               __FUNCTION__, ntStatus));
        return -ENOMEM;
    }

    return rv;
}

static HIF_DEVICE_USB *usb_hif_create(HIF_DEVICE *hifDevice)
{
    HIF_DEVICE_USB      *device = NULL;
    A_STATUS             status = A_OK;
    int                  i;
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("+%s\n",__FUNCTION__));
    do {
        device = (HIF_DEVICE_USB *)A_MALLOC(sizeof(HIF_DEVICE_USB));
        if (NULL == device) {
            break;
        }

        device->diag_cmd_buffer = (A_UINT8 *)A_MALLOC(USB_CTRL_MAX_DIAG_CMD_SIZE);
        if (NULL == device->diag_cmd_buffer) {
            status = A_NO_MEMORY;
            break;
        }
        device->diag_resp_buffer = (A_UINT8 *)A_MALLOC(USB_CTRL_MAX_DIAG_RESP_SIZE);
        if (NULL == device->diag_resp_buffer) {
            status = A_NO_MEMORY;
            break;
        } 
    } while (FALSE);
    if (A_FAILED(status)) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s error: %08x\n", __FUNCTION__, status));
        usb_hif_destroy(device);    
        device = NULL;
    }
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("-%s\n",__FUNCTION__));
    return device;
}

static void usb_hif_destroy(HIF_DEVICE_USB *device)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("+%s\n",__FUNCTION__));
    
    if (device->diag_cmd_buffer != NULL) {
        A_FREE(device->diag_cmd_buffer);   
    }
    
    if (device->diag_resp_buffer != NULL) {
        A_FREE(device->diag_resp_buffer);    
    }

    A_FREE(device);    
    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("-%s\n",__FUNCTION__));
}

A_UINT8 usb_hif_get_usb_epnum(A_UINT8 pipe_num)
{
    A_UINT8 usb_epnum;

    switch (pipe_num) {
        case HIF_RX_CTRL_PIPE:
            usb_epnum = USB_EP_ADDR_APP_CTRL_IN;
            break;
        case HIF_RX_DATA_PIPE:
            usb_epnum = USB_EP_ADDR_APP_DATA_IN;
            break;
        case HIF_RX_INT_PIPE:
            usb_epnum = USB_EP_ADDR_APP_INT_IN;
            break;
        case HIF_RX_DATA2_PIPE:
            usb_epnum = USB_EP_ADDR_APP_DATA2_IN;
            break;
        case HIF_TX_CTRL_PIPE:
            usb_epnum = USB_EP_ADDR_APP_CTRL_OUT;
            break;
        case HIF_TX_DATA_LP_PIPE:
            usb_epnum = USB_EP_ADDR_APP_DATA_LP_OUT;
            break;
        case HIF_TX_DATA_MP_PIPE:
            usb_epnum = USB_EP_ADDR_APP_DATA_MP_OUT;
            break;
        case HIF_TX_DATA_HP_PIPE:
            usb_epnum = USB_EP_ADDR_APP_DATA_HP_OUT;
            break;
        default :
            /* note: there may be endpoints not currently used */
            break;
    }

    /* since pipe_num contains the direction bit, mask it before return the value */
    usb_epnum &= 0x0f;

    return usb_epnum;
}

