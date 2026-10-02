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

#ifndef __ATH_HIF_USB_H__
#define __ATH_HIF_USB_H__

#define CONFIG_COPY_ENGINE_SUPPORT /* TBDXXX: here for now */
#undef CONFIG_ATH_SYSFS_CE
#define ATH_DBG_DEFAULT   0

#include <osdep.h>
#include <ol_if_athvar.h>
#include <athdefs.h>
#include "a_osapi.h"
#include "hif.h"
#include "cepci.h"
#include "ol_ath.h"
#include "a_types.h"
#include "osapi_win.h"

/* Maximum number of Copy Engine's supported */
#define CE_COUNT_MAX 8

struct CE_state;
struct ol_ath_softc_net80211;

/* An address (e.g. of a buffer) in Copy Engine space. */
typedef dma_addr_t CE_addr_t;
typedef int irqreturn_t;

struct ath_hif_pci_softc {

    char        *mem; /* PCI address. For efficiency, should be first in struct */
    PNIC_DEV    aps_osdev;
    void        *dev; /* not used on windows */
    struct ol_ath_softc_net80211 *scn;
    int num_msi_intrs; /* number of MSI interrupts granted, 0 --> using legacy PCI line interrupts */
    adf_os_spinlock_t target_lock; /* Guard changes to Target HW state and to software structures that track hardware state.*/
    unsigned int ce_count; /* Number of Copy Engines supported */
    struct CE_state *CE_id_to_state[CE_COUNT_MAX]; /* Map CE id to CE_state */
    spinlock_t dpc_lock; /* Sync DPC */
    HIF_DEVICE *hif_device;
#if defined(HIF_USB)
    PVOID       UsbBusInterface;
#endif
};

#define TARGID(sc) ((A_target_id_t)(&(sc)->mem))
#define TARGID_TO_HIF(targid) (((struct ath_hif_pci_softc *)((char *)(targid) - (char *)&(((struct ath_hif_pci_softc *)0)->mem)))->hif_device)
#define TARGID_TO_SC(targid) ((char *)(targid) - (char *)&(((struct ath_hif_pci_softc *)0)->mem))
extern int ol_ath_usb_initialize(PADAPTER pdev, void *params);
extern void ol_ath_usb_remove(PADAPTER pdev);
int HIF_USBDeviceProbed(hif_handle_t hif_hdl);


#endif /* __ATH_HIF_USB__ */
