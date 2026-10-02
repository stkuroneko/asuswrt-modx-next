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

#ifndef _HIF_USB_KMDF_H
#define _HIF_USB_KMDF_H
#include "a_types.h"
#include <usbdi.h>
#include <usbdlib.h>
#include <wdf.h>
#include <WdfMiniport.h>
#include <wdfusb.h>
#include "Mp_Dot11.h"
#include <adf_os_stdtypes.h>
#include <adf_nbuf.h>

#define ATH_USB_TX_CELL_NUMBER              8
#define ATH_USB_MAX_TX_BUF_NUM              4096//256
#define ATH_USB_RX_CELL_NUMBER              32
#define ATH_USB_MSGIN_CELL_NUMBER           32
#define ATH_USB_TXZERO_CELL_NUMBER       		32  

#define MP_INTERLOCKED_SET_BIT(_v, _b)      InterlockedExchange(&(_v), (_v | (1 << _b)))
#define MP_INTERLOCKED_CLR_BIT(_v, _b)      InterlockedExchange(&(_v), (_v & (~(1 << _b))))
#define MP_GET_BIT(_v, _b)                  (_v & (1 << _b))

NTSTATUS initUsbKMDF(    
    __in struct _DRIVER_OBJECT *DriverObject,
    __in PUNICODE_STRING RegistryPath );
NTSTATUS HIFUsbCreateWdfDevice(PADAPTER pAdapter);


typedef struct _UsbOutRequestItem
{
    PADAPTER                        pAdapter;
	struct ath_hif_pci_softc        *sc;
    WDFMEMORY                       UsbRequestBuffer;
    WDFMEMORY                       UsbUrbBuffer;
    WDFREQUEST                      UsbOutRequest;
    UCHAR                           IsUsed;
    UCHAR                           IsReboot;
    UCHAR                           PipeIndex;
	unsigned int                    transfer_id;
    void*                           txwbuf;
    USHORT                          offset;
    void                            *pHifContext;
	adf_nbuf_t                      tx_adf_buf;  
} UsbOutRequestItem, *PUsbOutRequestItem;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(UsbOutRequestItem, GetUsbOutRequestItem)

typedef struct _UsbZeroOutRequestItem
{
    PADAPTER                        pAdapter;
	struct ath_hif_pci_softc        *sc;
    WDFMEMORY                       UsbRequestBuffer;
    WDFMEMORY                       UsbUrbBuffer;
    WDFREQUEST                      UsbOutRequest;
    UCHAR                           IsUsed;
    UCHAR                           IsReboot;
    UCHAR                           PipeIndex;
    void*                           txwbuf;
    USHORT                          offset;
    void                            *pHifContext;
} UsbZeroOutRequestItem, *PUsbZeroOutRequestItem;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(UsbZeroOutRequestItem, GetUsbZeroOutRequestItem)

typedef struct _UsbRxRequestItem
{
    PADAPTER                        pAdapter;
	struct ath_hif_pci_softc        *sc;
    WDFMEMORY                       UsbRequestBuffer;
    WDFREQUEST                      UsbInRequest;
    UCHAR                           *rxwbuf;
} UsbRxRequestItem, *PUsbRxRequestItem;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(UsbRxRequestItem, GetUsbRxRequestItem)

typedef struct _UsbMsgInRequestItem
{
    PADAPTER        pAdapter;
	struct ath_hif_pci_softc        *sc;
    WDFMEMORY       UsbRequestBuffer;  
    WDFREQUEST      UsbInRequest;  
    UCHAR           *msgInwbuf;
} UsbMsgInRequestItem, *PUsbMsgInRequestItem;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(UsbMsgInRequestItem, GetUsbMsgInRequestItem)

typedef struct _WDF_DEVICE_INFO{

    PADAPTER pAdapter;

} WDF_DEVICE_INFO, *PWDF_DEVICE_INFO;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(WDF_DEVICE_INFO, GetWdfDeviceInfo);

//NTSTATUS KmdfUsbConfigureDevice(WDFDEVICE Device, HIF_KMDF_USB_CB *pUsbCb);

#endif /* _HIF_USB_KMDF_H */
