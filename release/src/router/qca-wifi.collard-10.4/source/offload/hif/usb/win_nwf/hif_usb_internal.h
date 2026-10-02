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

#ifndef _HIF_USB_INTERNAL_H
#define _HIF_USB_INTERNAL_H
//#include "ath_ndis.h"
#include "hif.h"
#include "Mp_Dot11.h"
#include "hif_usb_kmdf.h"
#include <adf_os_stdtypes.h>
#include <adf_nbuf.h>
#include "hif_msg_based.h"
#include "a_usb_defs.h"
#include <a_debug.h>

#define HIF_USB_TX_BUFFER_SIZE  1664
#define HIF_USB_RX_BUFFER_SIZE  4096 /* to accommodate 3839B AMSDU with some margin */
#define HIF_USB_TXZERO_BUFFER_SIZE  10

typedef struct hif_device HIF_DEVICE;

static INLINE PADAPTER HIFGetAdapter(HIF_DEVICE *pHif) {
    return (PADAPTER)pHif;
}

/* USB Endpoint definition */
typedef enum {
    HIF_TX_CTRL_PIPE = 0,
    HIF_TX_DATA_LP_PIPE,
    HIF_TX_DATA_MP_PIPE,
    HIF_TX_DATA_HP_PIPE,
    HIF_RX_CTRL_PIPE,
    HIF_RX_DATA_PIPE,    
    HIF_RX_DATA2_PIPE,
    HIF_RX_INT_PIPE,
    HIF_USB_PIPE_MAX
} HIF_USB_PIPE_ID;

#define HIF_USB_PIPE_INVALID HIF_USB_PIPE_MAX
#define HIF_USB_TX_PIPE_NUM                 4

typedef struct UsbTxQ
{
    adf_nbuf_t      buf;  
    adf_nbuf_t      hdr_buf;
    systime_t       timeStamp;
} UsbTxQ_t;

typedef struct _HIF_USB_TX_PIPE {
    WDFUSBPIPE                      UsbTxPipe;    
    NDIS_SPIN_LOCK                  UsbTxListLock;
    NDIS_SPIN_LOCK                  UsbTxSendLock;
    WDFCOLLECTION                   UsbTxFreeList;
    WDFCOLLECTION                   UsbTxUsedList;
    WDFCOLLECTION                   UsbTxZeroFreeList;
    WDFCOLLECTION                   UsbTxZeroUsedList;   
    WDF_USB_PIPE_INFORMATION        UsbTxPipeInfo;

    NDIS_SPIN_LOCK                  UsbTxBufQLock;
    ULONG                          TxBufHead;
    ULONG                          TxBufTail;
    ULONG                          TxBufCnt; 

    ULONG                            usbTxPktCnt;
    ULONG                            usbTxCntPerSec;
    UCHAR                            TxPktQueued;
    systime_t                        timeStamp;

    UsbTxQ_t                        UsbTxBufQ[ATH_USB_MAX_TX_BUF_NUM];
} HIF_USB_TX_PIPE;

/*
 * Used for scheduling pipe reset
 */
typedef struct _UsbPipeResetInfo
{
    PVOID          device;
    LONG            epId;
} UsbPipeResetInfo, *PUsbPipeResetInfo;

typedef struct _HIF_KMDF_USB_CB
{
    WDFUSBDEVICE                    WdfUsbTargetDevice;
    USB_DEVICE_DESCRIPTOR           UsbDeviceDescriptor;
    PUSB_CONFIGURATION_DESCRIPTOR   UsbConfigurationDescriptor;

    UCHAR                           NumberConfiguredPipes;
    WDFUSBINTERFACE                 UsbInterface;     

    LONG                            UsbPipeResetFlag;
    LONG                            UsbPipeStopFlag;
    
    WDFIOTARGET                     UsbIntIoTarget;
    WDFIOTARGET                     UsbRxIoTarget;

    WDFUSBPIPE                      RxPipe;
    NDIS_SPIN_LOCK                  UsbRxListLock;
    WDFCOLLECTION                   UsbRxFreeList;
    WDFCOLLECTION                   UsbRxUsedList;

    HIF_USB_TX_PIPE                 USB_TX_PIPE[HIF_USB_TX_PIPE_NUM];
    PUsbPipeResetInfo               USBRestPipe[HIF_USB_PIPE_MAX];
    BOOLEAN                         bFullSpeed;
} HIF_KMDF_USB_CB;

typedef struct _HIF_DEVICE_USB {
    //PATH_ADAPTER        os_hdl;
    struct ath_hif_pci_softc *sc;
    HIF_KMDF_USB_CB     usbCb;
    MSG_BASED_HIF_CALLBACKS htcCallbacks;
    UCHAR               *diag_cmd_buffer;
    UCHAR               *diag_resp_buffer;
    void                *claimed_context;
    A_UINT8             surpriseRemoved;
    BOOLEAN            bUSBDeveiceAttached;
} HIF_DEVICE_USB;

static HIF_DEVICE_USB *usb_hif_create(HIF_DEVICE *interface);
static void usb_hif_destroy(HIF_DEVICE_USB *device);
A_UINT8 usb_hif_get_usb_epnum(A_UINT8 pipe_num);
NTSTATUS KmdfUsbConfigureDevice(WDFDEVICE Device, HIF_KMDF_USB_CB *pUsbCb);
NTSTATUS KmdfUSbSetupPipeResources(HIF_DEVICE_USB *device);
NTSTATUS KmdfUSbReturnPipeResources(HIF_DEVICE_USB *device);
int SendRxObject(HIF_DEVICE_USB *device, WDFOBJECT rxObj);
void KmdfUsbPipeResetRoutine(IN PVOID  WorkItemContext,IN NDIS_HANDLE  NdisIoWorkItemHandle);
USHORT KmdfUsbCheckTxBufferCnt(HIF_USB_TX_PIPE *txPipe);
void
KmdfUsbSchedulePipeReset(
    HIF_DEVICE_USB *device,
    PUsbPipeResetInfo        pUsbPipeResetInfo);
A_STATUS KmdfUsbPutTxBuffer(HIF_DEVICE_USB *device, UCHAR endpt, unsigned int transfer_id, adf_nbuf_t buf);
void HIF_InitTxPipe(HIF_DEVICE_USB *device, UCHAR endpt);
A_STATUS KmdfUsbSubmitTxData(HIF_DEVICE_USB *device, HIF_USB_TX_PIPE *txPipe, LONG epId, unsigned int transfer_id);


#endif /* _HIF_USB_INTERNAL_H */
