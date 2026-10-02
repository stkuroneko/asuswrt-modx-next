//------------------------------------------------------------------------------
// Copyright (c) 2011 Qualcomm Atheros Communications Inc.
// All rights reserved.
//
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------

#include "precomp.h"
#if defined(HIF_USB)
#include "osdep.h"
#include "if_athvar.h"
#include "ath_hif_usb.h"
#include "bmi_msg.h" /* TARGET_TYPE_ */
#include "host_reg_table.h"
#include "target_reg_table.h"
#include "ol_ath.h"
#include "hif_usb_internal.h"

NDIS_STATUS
ol_ath_usb_initialize(PADAPTER pdev, void *params)
{
    NDIS_STATUS ret = NDIS_STATUS_SUCCESS;
    struct ol_attach_t ol_cfg;
    struct ath_hif_pci_softc *sc;

    sc = OS_MALLOC(pdev->pNic->sc_osdev, sizeof(*sc), GFP_KERNEL);
    OS_MEMZERO(sc, sizeof(*sc));
    if (!sc) {
        ret = NDIS_STATUS_RESOURCES;
        goto RET;
    }

    sc->mem = pdev->pNic->sc_osdev->CardInfo.CSRAddress;
    sc->aps_osdev = pdev->pNic->sc_osdev;
    pdev->pNic->sc_osdev->offload_hif = sc;

    //pdev->pNic->sc_osdev->CardInfo.DeviceID = 0xabcd;
    ol_cfg.devid = pdev->pNic->sc_osdev->CardInfo.DeviceID;
    ol_cfg.bus_type = BUS_TYPE_USB;

    spin_lock_init(&sc->target_lock);
    spin_lock_init(&sc->dpc_lock);

    {
        /*
         * Attach Target register table.  This is needed early on --
         * even before BMI -- since PCI and HIF initialization (and BMI init)
         * directly access Target registers (e.g. CE registers).
         *
         * TBDXXX: targetdef should not be global -- should be stored
         * in per-device struct so that we can support multiple
         * different Target types with a single Host driver.
         * The whole notion of an "hif type" -- (not as in the hif
         * module, but generic "Host Interface Type") is bizarre.
         * At first, one one expect it to be things like SDIO, USB, PCI.
         * But instead, it's an actual platform type. Inexplicably, the
         * values used for HIF platform types are *different* from the
         * values used for Target Types.
         */
        extern void hif_register_tbl_attach(A_UINT32 target_type);
        extern void target_register_tbl_attach(A_UINT32 target_type);
        hif_register_tbl_attach(HIF_TYPE_AR9888);
        target_register_tbl_attach(TARGET_TYPE_AR9888);
    }
    {

        if (__ol_ath_attach(sc, &ol_cfg, pdev->pNic->sc_osdev, params)) {
            ret = NDIS_STATUS_FAILURE;
        }
    }     
RET:

    if (ret != NDIS_STATUS_SUCCESS && sc) {
        //Free sc->dpc_lock and sc->target_lock
        spin_lock_destroy(&sc->dpc_lock);
        spin_lock_destroy(&sc->target_lock);        
        OS_FREE(sc);
    }
    return ret;
}

void
ol_ath_usb_remove(PADAPTER pdev)
{
    struct ath_hif_pci_softc *sc;
    sc = (struct ath_hif_pci_softc *) (pdev->pNic->sc_osdev->offload_hif);
    
    //detach ath device
    __ol_ath_detach(pdev);

    if(sc)
    {
        MpTrace(COMP_INIT_PNP, DBG_LOUD,
                ("reset target device start!"));
        //ath_pci_device_reset(sc);
        MpTrace(COMP_INIT_PNP, DBG_LOUD,
                ("reset target device end!"));
        //Free sc->dpc_lock and sc->target_lock
        spin_lock_destroy(&sc->dpc_lock);
        spin_lock_destroy(&sc->target_lock);
        
        //Free pdev->pNic->sc_osdev        
        OS_FREE(sc);  
    }
    else
    {
        MpTrace(COMP_INIT_PNP, DBG_LOUD,
                ("ol_ath_pci_remove: invalid sc pointer"));
    }      
}
int ol_ath_usb_configure(hif_softc_t hif_sc, hif_handle_t *hif_hdl)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    int ret = 0;
    if (HIF_USBDeviceProbed(sc)) {
            ret = -1;
            goto err_stalled;
    }
    *hif_hdl = sc->hif_device;
    return ret;
err_stalled:
    HIFShutDownDevice(sc->hif_device);
    return ret;
}
int ol_ath_usb_unconfigure(hif_softc_t hif_sc, hif_handle_t *hif_hdl)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    int ret = 0;
    HIFShutDownDevice(sc->hif_device);
    return ret;
}
#endif