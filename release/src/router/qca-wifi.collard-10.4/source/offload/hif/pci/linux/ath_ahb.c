/*
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <osdep.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/if_arp.h>
#include "ath_pci.h"
#include "copy_engine_api.h"
#include "bmi_msg.h" /* TARGET_TYPE_ */
#include "host_reg_table.h"
#include "target_reg_table.h"
#include "ol_ath.h"
#include "hif_msg_based.h"
#include <osapi_linux.h>
#include "ah_devid.h"

#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/of.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#include <linux/reset.h>
#endif
#include <linux/of_address.h>

#include <linux/clk.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#include <drivers/leds/leds-ipq40xx.h>
#include <linux/of_gpio.h>
#endif

extern unsigned int msienable;
extern void pci_reconnect_cb(struct ol_ath_softc_net80211 *scn);

#if ATH_RX_LOOPLIMIT_TIMER
extern void ol_rx_looplimit_handler(void *arg);
#endif

#if 0 /* Check if this is required for ABH also */
/* PCIE data bus error seems to occur on RTC_STATE read 
 * after putting Target in to reset and pulling Target out of reset. 
 * As a temp. workaround replacing this RTC_STATE read with a Delay of 3ms
 * And this WAR is enabled by READ_AFTER_RESET_TEMP_WAR define
 */
#define READ_AFTER_RESET_TEMP_WAR
#endif

#if 0 
/* TBD: replace the following with AHB alternatives if required - For now using
 * these as it is from ath_pci.c */
/*
 * Top-level interrupt handler for all PCI interrupts from a Target.
 * When a block of MSI interrupts is allocated, this top-level handler
 * is not used; instead, we directly call the correct sub-handler.
 */
irqreturn_t
ath_pci_interrupt_handler(int irq, void *arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    volatile int tmp;

    if (LEGACY_INTERRUPTS(sc)) {
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_CAUSE_ADDRESS));  
        if (!( tmp & (PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL))){
            return IRQ_NONE;
        }
        /* Clear Legacy PCI line interrupts */
        /* IMPORTANT: INTR_CLR regiser has to be set after INTR_ENABLE is set to 0, */
        /*            otherwise interrupt can not be really cleared */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS), 0);
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_CLR_ADDRESS), PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
        /* IMPORTANT: this extra read transaction is required to flush the posted write buffer */
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    }
    /* TBDXXX: Add support for WMAC */

    sc->irq_event = irq;
    tasklet_schedule(&sc->intr_tq);

    return IRQ_HANDLED;
}

irqreturn_t
ath_pci_msi_fw_handler(int irq, void *arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;

    (irqreturn_t)HIF_fw_interrupt_handler(sc->irq_event, sc);

    return IRQ_HANDLED;
}

bool
ath_pci_targ_is_awake(void *__iomem *mem)
{
#if AR900B_IP1_EMU_HACK
/* we have the pci_local regs, but the RTC_STATE is not connected to
 * anything - so just return OK
 */
    return 1;
#else
    volatile A_UINT32 val;
    val = A_PCI_READ32(mem + PCIE_LOCAL_BASE_ADDRESS + RTC_STATE_ADDRESS);
    return ((RTC_STATE_V_GET(val) & RTC_STATE_V_ON) == RTC_STATE_V_ON);
#endif
}

bool ath_pci_targ_is_present(A_target_id_t targetid, void *__iomem *mem)
{
    return 1; /* FIX THIS */
}

bool ath_max_num_receives_reached(unsigned int count)
{
    /* Not implemented yet */
    return 0;
}

/*
 * Handler for a per-engine interrupt on a PARTICULAR CE.
 * This is used in cases where each CE has a private
 * MSI interrupt.
 */
irqreturn_t
CE_per_engine_handler(int irq, void *arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    int CE_id = irq - MSI_ASSIGN_CE_INITIAL;

    /*
     * NOTE: We are able to derive CE_id from irq because we
     * use a one-to-one mapping for CE's 0..5.
     * CE's 6 & 7 do not use interrupts at all.
     *
     * This mapping must be kept in sync with the mapping
     * used by firmware.
     */

    CE_per_engine_service(sc, CE_id);

    return IRQ_HANDLED;
}
static void
ath_tasklet(unsigned long data)
{
    struct net_device *dev = (struct net_device *)data;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    volatile int tmp;

    int ret;

    ret = (irqreturn_t)HIF_fw_interrupt_handler(sc->irq_event, sc);
    if (ret == ATH_ISR_NOTMINE) {
        return;
    }

#if QCA_OL_11AC_FAST_PATH
    if (adf_os_likely(sc->hif_started)) {
        CE_per_engine_service_each(sc->irq_event, sc);
        /* Enable Legacy PCI line interrupts */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
            PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
        return;
    }
#endif /* QCA_OL_11AC_FAST_PATH */
    CE_per_engine_service_any(sc->irq_event, sc);
    if (LEGACY_INTERRUPTS(sc)) {
        /* Enable Legacy PCI line interrupts */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS), 
		    PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL); 
        /* IMPORTANT: this extra read transaction is required to flush the posted write buffer */
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    }
}
#endif /* #if 0 */

extern void ol_ath_tasklet(unsigned long data);
extern irqreturn_t ath_pci_msi_fw_handler(int irq, void *arg);
extern irqreturn_t CE_per_engine_handler(int irq, void *arg);
extern irqreturn_t ath_pci_interrupt_handler(int irq, void *arg);

/* These registers are outsize Wifi space. */
/* TBD: Should we add these offsets as device tree properties? */
#define TCSR_BASE 0x1900000
#define TCSR_SIZE 0x80000
#define TCSR_WIFI0_GLB_CFG 0x49000
#define TCSR_WIFI1_GLB_CFG 0x49004
#define TCSR_WCSS0_HALTREQ 0x52000
#define TCSR_WCSS1_HALTREQ 0x52004
#define TCSR_WCSS0_HALTACK 0x52010
#define TCSR_WCSS1_HALTACK 0x52014

#define ATH_AHB_RESET_WAIT_MAX 10 /* Ms */


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)

/*
 * To Enable/Disable the clk for GCC registers
 */
int clk_enable_disable(struct device *dev,const char *str,int enable){
    struct clk *clk_t = NULL;
    int ret;

    clk_t = clk_get(dev, str);
    if (IS_ERR(clk_t)) {
        printk("%s: Failed to get %s clk %ld\n", __func__,str,PTR_ERR(clk_t));
        return -EFAULT;
    }
    if(TRUE == enable){
        /* Prepare and Enable clk */
        ret = clk_prepare_enable(clk_t);
        if(ret){
            printk("%s: Failed to clk_prepare_enable for %s clk, with error:%d\n",__func__,str,ret);
            return ret;
        }
    }else{
        /* Disable and unprepare clk */
        clk_disable_unprepare(clk_t);
    }
    return 0;
}

/* Enable/Disable WIFI clk input*/
int wifi_clk_enable_disable(struct device *dev,int enable){
    int ret;

    if((ret = clk_enable_disable(dev, "wifi_wcss_cmd",enable))){
        return ret;
    }
    if((ret = clk_enable_disable(dev, "wifi_wcss_ref",enable))){
        return ret;
    }
    if((ret = clk_enable_disable(dev, "wifi_wcss_rtc",enable))){
        return ret;
    }
    return 0;
}

/*
 * IPQ4019 uses reset routines that are available in linux/reset.h 
 * from kernel 3.9
 */
void
ath_ahb_device_reset(struct ath_hif_pci_softc *sc)
{
    struct reset_control *resetctl = NULL;
    struct reset_control *core_resetctl = NULL;
    struct platform_device *pdev = (struct platform_device *)(sc->pdev);
    u_int32_t glb_cfg_offset;
    u_int32_t haltreq_offset;
    u_int32_t haltack_offset;
    void __iomem *mem_tcsr;
    u_int32_t wifi_core_id;
    u_int32_t reg_value;
    int wait_limit = ATH_AHB_RESET_WAIT_MAX;


    wifi_core_id = A_IO_READ32(sc->mem + WLAN_SUBSYSTEM_CORE_ID_ADDRESS);
    glb_cfg_offset = (wifi_core_id == 0) ? TCSR_WIFI0_GLB_CFG : TCSR_WIFI1_GLB_CFG;
    haltreq_offset = (wifi_core_id == 0) ? TCSR_WCSS0_HALTREQ : TCSR_WCSS1_HALTREQ;
    haltack_offset = (wifi_core_id == 0) ? TCSR_WCSS0_HALTACK : TCSR_WCSS1_HALTACK;

    mem_tcsr = ioremap_nocache(TCSR_BASE, TCSR_SIZE);
    if (IS_ERR(mem_tcsr)) {
        printk("%s: TCSR ioremap failed\n",__func__);
        return;
    }
    reg_value = A_IO_READ32(mem_tcsr + haltreq_offset);
    A_IO_WRITE32(mem_tcsr + haltreq_offset, reg_value | 0x1);
    /* Wait for halt ack before asserting reset */
    while (wait_limit) {
        if (A_IO_READ32(mem_tcsr + haltack_offset) & 0x1) {
            break;
        }
        A_MDELAY(1);
        wait_limit--;
    }

    reg_value = A_IO_READ32(mem_tcsr + glb_cfg_offset);
    A_IO_WRITE32(mem_tcsr + glb_cfg_offset, reg_value | (1 << 25));

#if 1 /* Using cold reset by default. */
    core_resetctl = reset_control_get(&pdev->dev, "wifi_core_cold");
#else
    core_resetctl = reset_control_get(&pdev->dev, "wifi_core_warm");
#endif
    if(IS_ERR(core_resetctl)) {
        printk("Failed to get wifi core cold reset control\n");
        return; 
    }

    /* Reset wifi core */
    reset_control_assert(core_resetctl);

    /* TBD: Check if we should also assert other bits (radio_cold, radio_warm, radio_srif, cpu_ini) */
    A_MDELAY(1); /* TBD: Get reqd delay from HW team */

    /* Assert radio cold reset */
    resetctl = reset_control_get(&pdev->dev, "wifi_radio_cold");
    if(IS_ERR(resetctl)) {
        printk("%s: Failed to get radio cold reset control\n", __func__);
        return; 
    }
    reset_control_assert(resetctl);
    A_MDELAY(1); /* TBD: Get reqd delay from HW team */
    reset_control_put(resetctl);
    
    /* Assert radio warm reset */
    resetctl = reset_control_get(&pdev->dev, "wifi_radio_warm");
    if(IS_ERR(resetctl)) {
        printk("%s: Failed to get radio warm reset control\n", __func__);
        return; 
    }
    reset_control_assert(resetctl);
    A_MDELAY(1); /* TBD: Get reqd delay from HW team */
    reset_control_put(resetctl);
    
    /* Assert radio srif reset */
    resetctl = reset_control_get(&pdev->dev, "wifi_radio_srif");
    if(IS_ERR(resetctl)) {
        printk("%s: Failed to get radio srif reset control\n", __func__);
        return; 
    }
    reset_control_assert(resetctl);
    A_MDELAY(1); /* TBD: Get reqd delay from HW team */
    reset_control_put(resetctl);
    
    /* Assert target CPU reset */
    resetctl = reset_control_get(&pdev->dev, "wifi_cpu_init");
    if(IS_ERR(resetctl)) {
        printk("%s: Failed to get cpu init reset control\n", __func__);
        return; 
    }
    reset_control_assert(resetctl);
    A_MDELAY(10); /* TBD: Get reqd delay from HW team */
    reset_control_put(resetctl);

    /* Clear gbl_cfg and haltreq before clearing Wifi core reset */
    reg_value = A_IO_READ32(mem_tcsr + haltreq_offset);
    A_IO_WRITE32(mem_tcsr + haltreq_offset, reg_value & ~0x1);
    reg_value = A_IO_READ32(mem_tcsr + glb_cfg_offset);
    A_IO_WRITE32(mem_tcsr + glb_cfg_offset, reg_value & ~(1 << 25));

    /* de-assert wifi core reset */
    reset_control_deassert(core_resetctl);

    A_MDELAY(1); /* TBD: Get reqd delay from HW team */

    /* TBD: Check if we should de-assert other bits here */
    reset_control_put(core_resetctl);
    iounmap(mem_tcsr);
    printk("Reset complete for wifi core id : %d\n", wifi_core_id);

}
#else
void
ath_ahb_device_reset(struct ath_hif_pci_softc *sc)
{
    /* 
     * TBD:dakota - Should we support older kernel versions without reset
     * routines?
     */
    printk("%s:%d:Reset routines not available in kernel version.\n", __func__,__LINE__);
}
#endif
struct pci_device_id ahb_id;
int
ol_ath_ahb_probe(struct platform_device *pdev, const struct platform_device_id *id)
{
    void __iomem *mem;
    int ret = 0;
    u_int32_t hif_type;
    u_int32_t target_type;
    struct ol_attach_t ol_cfg;
    /* TBD: Rename ath_hif_pci_softc as ath_hif_ce_softc */
    struct ath_hif_pci_softc *sc;
    struct net_device *dev;

    struct resource *memres;

    printk("ol_ath_ahb_probe\n");

    memres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if(!memres) {
        printk("%s: Failed to get IORESOURCE_MEM\n", __func__);
        return -EIO;
    }

    ret =  dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
    if (ret) {
        printk(KERN_ERR "ath: 32-bit DMA not available\n");
        goto err_dma;
    }

    ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32));
    if (ret) {
        printk(KERN_ERR "ath: Cannot enable 32-bit consistent DMA\n");
        goto err_dma;
    }

#if 0 /* Check if any DMA related configuration is required for AHB */
    /* Set bus master bit in PCI_COMMAND to enable DMA */
    pci_set_master(pdev);

    /* Temporary FIX: disable ASPM on peregrine. Will be removed after the OTP is programmed */
    pci_read_config_dword(pdev, 0x80, &lcr_val);
    pci_write_config_dword(pdev, 0x80, (lcr_val & 0xffffff00));

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
    /* Arrange for access to Target SoC registers. */
    mem = devm_ioremap_resource(&pdev->dev, memres);
    if (IS_ERR(mem)) {
        printk(KERN_ERR "ath: ioremap error\n") ;
        ret = PTR_ERR(mem);
        goto err_ioremap;
    }
#else
    /* 
     * TBD:dakota - Should we support older kernel versions?
     */
    printk(KERN_ERR "IPQ4019 not supported in this kernel\n") ;
    return -ENOTSUPP;
#endif

    printk("%s: io resource start: 0x%lx, mem=0x%lx\n", __func__, 
            (unsigned long)(memres->start), (unsigned long)mem);

    sc = A_MALLOC(sizeof(*sc));
    if (!sc) {
        ret = -ENOMEM;
        goto err_alloc;
    }
    OS_MEMZERO(sc, sizeof(*sc));

    sc->mem = mem;
    sc->pdev = (void *)pdev;
    OS_MEMZERO(&ahb_id, sizeof(struct pci_device_id));
    ahb_id.device = id->driver_data;
    sc->id = (void *)&ahb_id;
    sc->dev = &pdev->dev;

    sc->aps_osdev.bdev = NULL;
    sc->aps_osdev.device = &pdev->dev;
    sc->aps_osdev.bc.bc_handle = (void *)mem;
    sc->aps_osdev.bc.bc_bustype = HAL_BUS_TYPE_AHB;

    ol_cfg.devid = id->driver_data;
    ol_cfg.bus_type = BUS_TYPE_AHB;

    adf_os_spinlock_init(&sc->target_lock);

    sc->cacheline_sz = dma_get_cache_alignment();

    /* TBD: Replace proper id */
    if (id->driver_data == IPQ4019_DEVICE_ID) {
        /* TBD: Setting type to Beeliner - check if we need a separate type for Dakota */
        hif_type = HIF_TYPE_IPQ4019;
        target_type = TARGET_TYPE_IPQ4019;
        printk(KERN_INFO " *********** Dakota *************\n");
    } else {
        printk("Unsupported device\n");
        ret = -EIO;
        goto err_notsup;
    }
    sc->hif_type = hif_type;
    sc->target_type = target_type;

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
        extern void hif_register_tbl_attach(u_int32_t target_type);
        extern struct targetdef_s* target_register_tbl_attach(u_int32_t target_type);

        hif_register_tbl_attach(hif_type);
        sc->targetdef = target_register_tbl_attach(target_type);
    }

    ol_cfg.target_type = target_type;
    /* TBD: Check if this is required */
#if 0
    {
        A_UINT32 fw_indicator;

        /*
         * Verify that the Target was started cleanly.
         *
         * The case where this is most likely is with an AUX-powered
         * Target and a Host in WoW mode. If the Host crashes,
         * loses power, or is restarted (without unloading the driver)
         * then the Target is left (aux) powered and running.  On a
         * subsequent driver load, the Target is in an unexpected state.
         * We try to catch that here in order to reset the Target and
         * retry the probe.
         */
        A_PCI_WRITE32(mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
        while (!ath_pci_targ_is_awake(mem)) {
                ;
        }
        fw_indicator = A_PCI_READ32(mem + FW_INDICATOR_ADDRESS);
        A_PCI_WRITE32(mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);

        if (fw_indicator & FW_IND_INITIALIZED) {
            probe_again++;
            warm_reset = 1;
            printk(KERN_ERR "ath: Target is in an unknown state. Resetting (attempt %d).\n", probe_again);
            /* ath_pci_device_reset, below, will reset the target */
            ret = -EIO;
            goto err_tgtstate;
        }
    }
#endif

    if (__ol_ath_attach(sc, &ol_cfg, &sc->aps_osdev, NULL)) {
        goto err_attach;
    }

    /* Register for Target Paused event */
    dev = platform_get_drvdata(pdev);
    __ol_ath_suspend_resume_attach(dev);

#if ATH_RX_LOOPLIMIT_TIMER
    printk("looplimit timer init\n");
    adf_os_timer_init(sc->scn->adf_dev, &sc->scn->rx_looplimit_timer,
                       ol_rx_looplimit_handler, (void *)sc);
#endif  

    return 0;

err_attach:
    ret = -EIO;
    platform_set_drvdata(pdev, NULL);
#if 0
err_tgtstate:
#endif
#if 0 //(defined(CPU_WARM_RESET_WAR) && (PCI_PEREGRINE_V2_X86_WAR))
    /* This should be enabled only x86 platform and Peregrine 2.0
       It was observed in our experiments that ath_pci_device_warm_reset()
       is not resetting the target completely(some times), if it is crashed.
     */
    if(warm_reset) {
       ath_pci_device_warm_reset(sc);
       warm_reset = 0;
    }
    else 
#endif
    {
       ath_ahb_device_reset(sc);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
       if(ol_cfg.target_type == TARGET_TYPE_IPQ4019){
           wifi_clk_enable_disable(&pdev->dev,0);
       }
#endif
    }
err_notsup:
    A_FREE(sc);
err_alloc:
    /* call HIF PCI free here */
    //printk("%s: HIF PCI Free needs to happen here \n", __func__);
    devm_iounmap(&pdev->dev, mem);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
err_ioremap:
#endif

err_dma:
    /* Nothing to be done */
#if 0
    pci_disable_device(pdev);

    if (probe_again && (probe_again <= ATH_PCI_PROBE_RETRY_MAX)) {
        int delay_time;

        /*
         * We can get here after a Host crash or power fail when
         * the Target has aux power.  We just did a device_reset,
         * so we need to delay a short while before we try to
         * reinitialize.  Typically only one retry with the smallest
         * delay is needed.  Target should never need more than a 100Ms
         * delay; that would not conform to the PCIe std.
         */

        printk(KERN_INFO "ath reprobe.\n");
        delay_time = max(100, 10 * (probe_again * probe_again)); /* 10, 40, 90, 100, 100, ... */
        A_MDELAY(delay_time);
        goto again;
    }
#endif

    return ret;
}

/* TBD: Add this if there's any additional handling is required for AHB. Currently we're using ol_ath_pci_nointrs for AHB also */
void
ol_ath_ahb_nointrs(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn;
    struct ath_hif_pci_softc *sc;
    int i;

    scn = ath_netdev_priv(dev);
    sc = (struct ath_hif_pci_softc *)scn->hif_sc;

    if (sc->num_msi_intrs > 0) {
        /* MSI interrupt(s) */
        for (i = 0; i < sc->num_msi_intrs; i++) {
#ifdef QCA_PARTNER_PLATFORM	
	    osif_pltfrm_interupt_unregister(dev,i);
#else	
            free_irq(dev->irq + i, dev);
#endif			
        }
        sc->num_msi_intrs = 0;
    } else {
        /* Legacy PCI line interrupt */
#ifdef QCA_PARTNER_PLATFORM	
        osif_pltfrm_interupt_unregister(dev,0);
#else	
        free_irq(dev->irq, dev);
#endif

    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
int ahb_init_radio(hif_softc_t hif_sc)
{
    struct reset_control *reset_ctl = NULL;
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    struct platform_device *pdev = (struct platform_device *)(sc->pdev);
    int ret;

    /* TBD: Temporary changes. Frequency should be
       retreived through clk_xxx once kernel GCC driver is available */
    {
#define GCC_BASE 0x1800000
#define GCC_SIZE 0x60000
#define GCC_FEPLL_PLL_DIV 0x2f020
#define GCC_FEPLL_PLL_CLK_WIFI_0_SEL_MASK 0x00000300
#define GCC_FEPLL_PLL_CLK_WIFI_0_SEL_SHIFT 8
#define GCC_FEPLL_PLL_CLK_WIFI_1_SEL_MASK 0x00003000
#define GCC_FEPLL_PLL_CLK_WIFI_1_SEL_SHIFT 12
        void __iomem *mem_gcc;
        u_int32_t gcc_fepll_pll_div;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
        /* Enable WIFI clock input */
        if((ret = wifi_clk_enable_disable(&pdev->dev,1))){
            return ret;
        }
#endif
        mem_gcc = ioremap_nocache(GCC_BASE, GCC_SIZE);
        if (IS_ERR(mem_gcc)) {
            printk("%s: GCC ioremap failed\n",__func__);
            return PTR_ERR(mem_gcc);
        }
        gcc_fepll_pll_div = A_IO_READ32(mem_gcc + GCC_FEPLL_PLL_DIV);

        A_IO_WRITE32(sc->mem + FW_CPU_PLL_CONFIG, gcc_fepll_pll_div);

        iounmap(mem_gcc);
    }

    /* De-assert radio cold reset */
    reset_ctl = reset_control_get(&pdev->dev, "wifi_radio_cold");
    if(IS_ERR(reset_ctl)) {
        printk("%s: Failed to get radio cold reset control\n", __func__);
        ret = PTR_ERR(reset_ctl);
        return -EIO;
    }
    reset_control_deassert(reset_ctl);
    reset_control_put(reset_ctl);

    /* De-assert radio warm reset */
    reset_ctl = reset_control_get(&pdev->dev, "wifi_radio_warm");
    if(IS_ERR(reset_ctl)) {
        printk("%s: Failed to get radio warm reset control\n", __func__);
        ret = PTR_ERR(reset_ctl);
        return -EIO;
    }
    reset_control_deassert(reset_ctl);
    reset_control_put(reset_ctl);

    /* De-assert radio srif reset */
    reset_ctl = reset_control_get(&pdev->dev, "wifi_radio_srif");
    if(IS_ERR(reset_ctl)) {
        printk("%s: Failed to get radio srif reset control\n", __func__);
        ret = PTR_ERR(reset_ctl);
        return -EIO;
    }
    reset_control_deassert(reset_ctl);
    reset_control_put(reset_ctl);

    /* De-assert target CPU reset */
    reset_ctl = reset_control_get(&pdev->dev, "wifi_cpu_init");
    if(IS_ERR(reset_ctl)) {
        printk("%s: Failed to get cpu init reset control\n", __func__);
        ret = PTR_ERR(reset_ctl);
        return -EIO;
    }
    reset_control_deassert(reset_ctl);
    reset_control_put(reset_ctl);

    A_IO_WRITE32(sc->mem + FW_INDICATOR_ADDRESS, FW_IND_HOST_READY);

    return 0;
}

int ahb_wait_for_target(hif_softc_t hif_sc)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    /* Synchronization point: Wait for Target to finish initialization before we proceed. */
#if 0
    int wait_limit = (30 * HZ) / 100; /* 30 sec */
#else  /* Change this back to 30 once kernel timer issue is fixed */
    int wait_limit = (3 * HZ) / 100; /* 30 sec */
#endif
    int num_msi_desired;

#if defined(FORCE_LEGACY_PCI_INTERRUPTS)
    num_msi_desired = 0; /* Use legacy PCI line interrupts rather than MSI */
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    num_msi_desired = MSI_NUM_REQUEST; /* Multiple MSI */
#else
    num_msi_desired = 1; /* Single MSI */
#endif

    if (!msienable) {
        num_msi_desired = 0;
    }
#endif

    adf_os_print("\n Waiting for target init\n");
    while (wait_limit-- && !(A_IO_READ32(sc->mem + FW_INDICATOR_ADDRESS) & FW_IND_INITIALIZED)) {
        schedule_timeout_interruptible(100);
        if (num_msi_desired == 0) {
            /* Fix potential race by repeating CORE_BASE writes */
            A_IO_WRITE32(sc->mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
                    PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
            /* read to flush write */
            (void)A_IO_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
        }
    }

    adf_os_print("\n Done waiting\n");
    if (wait_limit < 0) {
        adf_os_print(KERN_ERR "ath: %s: TARGET STALLED : \n", __FUNCTION__);
        return -EIO;

    }
    return 0;
}

void ahb_txrx_ce_list_init(hif_softc_t hif_sc)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;

    /* initialize the used ce engine numbers */
    sc->rx_ce_list_fast[0] = 1;
    sc->rx_ce_list_fast[1] = 2;
    if (sc->scn->target_type == TARGET_TYPE_IPQ4019) {
        sc->rx_ce_list_fast[2] = 8;
        sc->rx_ce_list_fast[3] = -1;
    }
    else {
        /* Needed when any derivative of peregrine/swift needs AHB support */
        sc->rx_ce_list_fast[2] = -1;
    }
    sc->tx_ce_list[0] = 3;
    sc->tx_ce_list[1] = -1;
    sc->misc_ce_list[0] = 0;
    sc->misc_ce_list[1] = -1;
}

void ahb_irq_enable(hif_softc_t hif_sc)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    struct net_device *dev = sc->aps_osdev.netdev;
    /* Disable interrupt till the hif_state is initialized */
    disable_irq(dev->irq);
    adf_os_print("\n Using Legacy Interrupt\n");

#if 0   /* TBD: Assuming this is not required and above reset sequence is
         * sufficient */
    /* Make sure to wake the Target before enabling Legacy Interrupt */
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    while (!ath_pci_targ_is_awake(sc->mem)) {
        ;
    }
#endif
    /* Use Legacy Interrupts */
    /*
     * A potential race occurs here: The CORE_BASE write depends on
     * target correctly decoding AXI address but host won't know
     * when target writes BAR to CORE_CTRL. This write might get lost
     * if target has NOT written BAR. For now, fix the race by repeating
     * the write in below synchronization checking.
     */
    /* TBD: Confirm if PCIE_INTR_ENABLE_ADDRESS is the right register */
    A_IO_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
            PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
    /* read to flush pcie write */
    (void)A_IO_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
}

/*
 * IPQ4019 uses reset routines that are available in linux/reset.h
 * from kernel 3.9
 */
int
ol_ath_ahb_configure(hif_softc_t hif_sc, struct net_device *dev, hif_handle_t *hif_hdl)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    int ret = 0;
    int num_msi_desired;
#if 0
    u_int32_t val;
#endif
    struct platform_device *pdev = (struct platform_device *)(sc->pdev);
    struct resource *memres;
    int irq;
    struct device_node *dev_node = pdev->dev.of_node;
    u_int32_t msi_addr, msi_base,wifi_core_id;

#if 0
    struct clk *wifi_cpu_pll = NULL;
#endif

    BUG_ON(platform_get_drvdata(pdev) != NULL);

    if ((ret = of_property_read_u32(dev_node, "qca,msi_addr", &msi_addr)) ||
        (ret = of_property_read_u32(dev_node, "qca,msi_base", &msi_base)) ||
        (ret = of_property_read_u32(dev_node, "core-id", &wifi_core_id))) {
        adf_os_print("%s: Unable to get msi_addr - error:%d\n", __func__, ret);
        return -EIO;
    }

    adf_os_print("%s: MSI addr: %08x, MSI base: %08x\n", __func__, msi_addr, msi_base);

    /* Program the above values into Wifi scratch regists */
    if(msienable) {
        A_IO_WRITE32(sc->mem + FW_AXI_MSI_ADDR, msi_addr);
        A_IO_WRITE32(sc->mem + FW_AXI_MSI_DATA, msi_base);
    }

    ret = ahb_init_radio(sc);

    if (ret)
        return ret;

    platform_set_drvdata(pdev, dev);
    sc->scn = ath_netdev_priv(dev);
    sc->aps_osdev.netdev = dev;

    memres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if(!memres) {
        adf_os_print("%s: Failed to get IORESOURCE_MEM\n", __func__);
        return -EIO;
    }

    dev->mem_start = (unsigned long) sc->mem;
    dev->mem_end = (unsigned long)sc->mem + resource_size(memres);

    dev_info(&pdev->dev, "ath DEBUG: sc=0x%p\n", sc);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    SET_MODULE_OWNER(dev);
#endif
    SET_NETDEV_DEV(dev, &pdev->dev);

    tasklet_init(&sc->intr_tq, ol_ath_tasklet, (unsigned long)dev);
    sc->tasklet_enable = TRUE;

    INIT_WORK(&sc->pci_reconnect_work, pci_defer_reconnect);
    sc->scn->recovery_enable = FALSE;
    sc->scn->pci_reconnect = pci_reconnect_cb;	

	/*
	 * Interrupt Management is divided into these scenarios :
	 * A) We wish to use MSI and Multiple MSI is supported and we 
	 *    are able to obtain the number of MSI interrupts desired
	 *    (best performance)
	 * B) We wish to use MSI and Single MSI is supported and we are
	 *    able to obtain a single MSI interrupt
	 * C) We don't want to use MSI or MSI is not supported and we 
	 *    are able to obtain a legacy interrupt
	 * D) Failure
	 */
#if defined(FORCE_LEGACY_PCI_INTERRUPTS)
    num_msi_desired = 0; /* Use legacy PCI line interrupts rather than MSI */
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    num_msi_desired = MSI_NUM_REQUEST; /* Multiple MSI */
#else
    num_msi_desired = 1; /* Single MSI */
#endif

    if (!msienable) {
        num_msi_desired = 0;
    }
#endif

    printk("\n %s : num_desired MSI set to %d\n", __func__, num_msi_desired);

    if (num_msi_desired >=1) {
        irq = platform_get_irq_byname(pdev, "msi0");
    } else {
        /* Legacy interrupt */
        irq = platform_get_irq_byname(pdev, "legacy");
    }

    if (irq < 0) {
        dev_err(&pdev->dev, "Unable to get irq\n");
        goto err_intr;
    }

    sc->sc_valid = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    if (num_msi_desired > 1) {
        int i;

    /* TBD: Check if anything to be done to allocate MSI interrupts */
		sc->num_msi_intrs = MSI_NUM_REQUEST;
		dev->irq = irq;
		ret = request_irq(dev->irq+MSI_ASSIGN_FW, ath_pci_msi_fw_handler, IRQF_DISABLED, dev->name, dev);
		if(ret) {
			dev_err(&pdev->dev, "ath_request_irq failed\n");
			goto err_intr;
		}
		for (i=MSI_ASSIGN_CE_INITIAL; i<=MSI_ASSIGN_CE_MAX; i++) {
			ret = request_irq(dev->irq+i, CE_per_engine_handler, IRQF_DISABLED, dev->name, dev);
			if(ret) {
				dev_err(&pdev->dev, "ath_request_irq failed\n");
				goto err_intr;
			}
		}
	}
#endif
    
    if ( num_msi_desired <= 1) {
	    /* We are here because we want to multiplex a single host interrupt among all 
	     * Target interrupt sources
	     */
	    dev->irq = irq;
#ifdef QCA_PARTNER_PLATFORM
        ret = osif_pltfrm_interupt_register(dev, OFFLOAD_TYPE_LEGACY, ath_pci_interrupt_handler, NULL);
#else
	    ret = request_irq(dev->irq, ath_pci_interrupt_handler, IRQF_DISABLED, dev->name, dev);
#endif
	    if(ret) {
		    dev_err(&pdev->dev, "ath_request_irq failed\n");
		    goto err_intr;
	    }

    }

    if(num_msi_desired == 0) {
       ahb_irq_enable(sc);
    }

    sc->num_msi_intrs = num_msi_desired;
    sc->ce_count = CE_COUNT;

    ahb_txrx_ce_list_init(sc);

    if (ahb_wait_for_target(sc)) {
        ret = -EIO;
        goto  err_stalled;
    }

    if (HIF_PCIDeviceProbed(sc)) {
        adf_os_print(KERN_ERR "ath: %s: Target probe failed.\n", __FUNCTION__);
        ret = -EIO;
        goto err_stalled;
    }

    sc->sc_valid = 1;

    if(num_msi_desired == 0)
        enable_irq(dev->irq);

    ol_ath_diag_user_agent_init(sc->scn);

#if defined(CONFIG_ATH_SYSFS_CE)
    ath_sysfs_CE_init(sc);
#endif

    *hif_hdl = sc->hif_device;

	/* Get btcoex HW support info from device tree */
	if (of_property_read_u32(dev_node, "btcoex_support", &sc->scn->btcoex_support)) {
		sc->scn->btcoex_support = 0;
	} else {
		if (of_property_read_u32(dev_node, "wlan_prio_gpio", &sc->scn->btcoex_gpio)) {
			sc->scn->btcoex_gpio = 0;
			sc->scn->btcoex_support = 0;
		}
	}

     return 0;

err_stalled:
    /* Read Target CPU Intr Cause for debug */
#if 0 /* TBD: Check if the register CPU_INTR_ADDRESS is valid for Dakota */
    val = A_IO_READ32(sc->mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
    printk("ERROR: Target Stalled : Target CPU Intr Cause 0x%x \n", val);
#endif
    ol_ath_pci_nointrs(dev);
err_intr:
#if 0
    if (num_msi_desired) {
        pci_disable_msi(sc->pdev);
    }
#endif
    platform_set_drvdata((struct platform_device * )sc->pdev, NULL);

    return ret;
}
#else   
int 
ol_ath_ahb_configure(hif_softc_t hif_sc, struct net_device *dev, hif_handle_t *hif_hdl) 
{   
    /*  
     * TBD:dakota - Should we support older kernel versions without reset 
     * routines?  
     */ 
    printk("%s:%d:Reset routines not available in kernel version.\n", __func__,__LINE__);   
    return -ENOTSUPP;  
}   
#endif

#define REMOVE_VAP_TIMEOUT_COUNT  20
#define REMOVE_VAP_TIMEOUT        (HZ/10)

void
ol_ath_ahb_remove(struct platform_device *pdev)
{
    struct net_device *dev = platform_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn;
    u_int32_t target_ver,target_type;
    struct ath_hif_pci_softc *sc;
    HIF_DEVICE *hifdev;
    void __iomem *mem;
    int target_paused = TRUE;
    int waitcnt = 0;

    /* Attach did not succeed, all resources have been
     * freed in error handler
     */
    if (!dev)
        return;

    scn = ath_netdev_priv(dev);
    sc = (struct ath_hif_pci_softc *)scn->hif_sc;
    mem = (void __iomem *)dev->mem_start;
    hifdev = sc->hif_device;

    __ol_vap_delete_on_rmmod(dev);

    while (atomic_read(&scn->reset_in_progress)  && (waitcnt < REMOVE_VAP_TIMEOUT_COUNT)) {
        schedule_timeout_interruptible(REMOVE_VAP_TIMEOUT);
        waitcnt++;
    }

    /* Suspend the target if it is not done during the last vap removal */

    if (!(scn->down_complete)) {
        /* Suspend Target */
        adf_os_print("Suspending Target - with disable_intr set :%s (sc %p) scn=%p\n",dev->name,sc, scn);
        if (!ol_ath_suspend_target(scn, 1)) {
            u_int32_t  timeleft;
            adf_os_print("waiting for target paused event from target :%s (sc %p)\n",dev->name,sc);
            /* wait for the event from Target*/
            timeleft = wait_event_interruptible_timeout(scn->sc_osdev->event_queue,
                    (scn->is_target_paused == TRUE),
                    200);
            if(!timeleft || signal_pending(current)) {
                adf_os_print("ERROR: Failed to receive target paused event :%s (sc %p)\n",dev->name,sc);
                target_paused = FALSE;
            }
            /*
             * reset is_target_paused and host can check that in next time,
             * or it will always be TRUE and host just skip the waiting
             * condition, it causes target assert due to host already suspend
             */
            scn->is_target_paused = FALSE;
        }
    }
    ol_ath_pci_nointrs(dev);

if (!(scn->down_complete)) {
#if QCA_OL_NAPI_SUPPORT
    napi_disable(&sc->napi_hdl);
    sc->napi_enable = FALSE;
#else
    /* Cancel the pending tasklet */
    tasklet_kill(&sc->intr_tq);
    sc->tasklet_enable = FALSE;
#endif
}
    /* save target_version since scn is not valid after __ol_ath_detach */
    target_ver = scn->target_version;
    target_type = sc->scn->target_type;
    if (target_paused == TRUE) {
    __ol_ath_detach(dev);
    } else {
        HIFPause(hifdev);
        scn->fwsuspendfailed = 1;
        wmi_stop(scn->wmi_handle);
    }

    if (!(scn->down_complete))
        ath_ahb_device_reset(sc);

    if (target_paused != TRUE) {
        __ol_ath_detach(dev);
    }

    if (!(scn->down_complete)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
        /*Disable WIFI clock input*/
        if(target_type == TARGET_TYPE_IPQ4019){
            wifi_clk_enable_disable(&pdev->dev,0);
        }
#endif
    }

    A_FREE(sc);
    platform_set_drvdata(pdev, NULL);
    devm_iounmap(&pdev->dev, mem);
    printk(KERN_INFO "ath_ahb_remove\n");
}


#if OL_ATH_SUPPORT_LED
/* Temporarily defining the core_sw_output address here as 
ar900b,qca9884,qca9888 didn't define the macro in FW cmn headers */
#define CORE_SW_OUTPUT 0x82004

void ol_ath_led_event(struct ol_ath_softc_net80211 *scn, OL_LED_EVENT event);
extern bool ipq4019_led_initialized;
extern uint32_t ipq4019_led_type;
extern struct ol_ath_softc_net80211 *ol_global_scn[GLOBAL_SCN_SIZE];
extern int ol_num_global_scn;

void ipq4019_wifi_led(struct ol_ath_softc_net80211 *scn, int on_or_off)
{
    struct ath_hif_pci_softc *sc = ( struct ath_hif_pci_softc *) scn->hif_sc;
    struct platform_device *pdev = (struct platform_device *)(sc->pdev);

    if (!pdev)
        return;

    if (!ipq4019_led_initialized) {
        return;
    }
    if ((ipq4019_led_type == IPQ4019_LED_GPIO_PIN) &&
        (scn->scn_led_gpio > 0)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
            gpio_set_value_cansleep(scn->scn_led_gpio, on_or_off);
#endif
    } else if (ipq4019_led_type == IPQ4019_LED_SOURCE) {
        A_IO_WRITE32(sc->mem + CORE_SW_OUTPUT, on_or_off);
    }
    return;
}

uint8_t ipq4019_is_wifi_gpio_shared(struct ol_ath_softc_net80211 *scn)
{
    struct ol_ath_softc_net80211 *tmp_scn = NULL;
    int32_t scn_idx = 0;
    int32_t scn_num = 0;

    while ((scn_num < ol_num_global_scn) && (scn_idx < GLOBAL_SCN_SIZE)) {
        tmp_scn = ol_global_scn[scn_idx++];
        if (tmp_scn == NULL)
            continue;
        scn_num++;
        if (tmp_scn == scn)
            continue;
        if (tmp_scn->scn_led_gpio == scn->scn_led_gpio) {
            // same gpio is already requested
            return TRUE;
        }
    }
    return FALSE;
}

void ipq4019_wifi_led_init(struct ol_ath_softc_net80211 *scn)
{
    struct ath_hif_pci_softc *sc = ( struct ath_hif_pci_softc *) scn->hif_sc;
    struct platform_device *pdev = (struct platform_device *)(sc->pdev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    uint32_t wifi_core_id=0xffffffff;
    int32_t led_gpio = 0;
    uint32_t led_num = 0;
    uint32_t led_source = 0;
    int32_t ret = -1;
#endif // linux kernel > 3.14

    if (!pdev ) {
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    if (of_property_read_u32(pdev->dev.of_node, "core-id", &wifi_core_id) != 0) {
        printk("%s: Wifi LED init failed.. Couldn't get core id\r\n", __func__);
        return;
    }

    led_gpio = of_get_named_gpio(pdev->dev.of_node, "wifi-led-gpios", 0);
    if (led_gpio <= 0) {
        /* no led gpio.. get led source */
        if ((ret = of_property_read_u32(pdev->dev.of_node, "wifi_led_num", &led_num)) ||
            (ret = of_property_read_u32(pdev->dev.of_node, "wifi_led_source", &led_source))) {
            printk("%s: Wifi LED init failed.. Couldn't get led gpio/led source\r\n", __func__);
            return;
        }
    }

    if ((wifi_core_id == 0) || (wifi_core_id == 1)) {
        if ((led_gpio > 0) && (gpio_is_valid(led_gpio))) {
            int32_t ret_status = 0;
            ipq4019_led_type = IPQ4019_LED_GPIO_PIN; // led type gpio
            scn->scn_led_gpio = led_gpio;
            /* check if this gpio is already requested/shared between wifi radios */
            if (!ipq4019_is_wifi_gpio_shared(scn)) {
                //ret_status = gpio_request_one(led_gpio, GPIOF_OUT_INIT_LOW, "wifi-led-gpios");
                ret_status = gpio_request_one(led_gpio, GPIOF_DIR_OUT, "wifi-led-gpios");
                if (ret_status != 0) {
                    printk("%s: Wifi LED gpio request failed.. \r\n", __func__);
                    return;
                }
            }
        } else if (led_num > 0) {
            ipq4019_led_type = IPQ4019_LED_SOURCE; // led source selected
            ipq40xx_led_source_select(led_num, led_source);
            scn->scn_led_gpio = 0;
        }
    }

    if ((led_gpio > 0) || (led_num > 0)) {
        ipq4019_led_initialized = 1;
    }

#endif // linux kernel > 3.14
    return;
}

void ipq4019_wifi_led_deinit(struct ol_ath_softc_net80211 *scn)
{
    if (ipq4019_led_type == IPQ4019_LED_GPIO_PIN) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
        if ((scn->scn_led_gpio) && (gpio_is_valid(scn->scn_led_gpio))) {
            /* check if this gpio is freed already by another scn context */
            if (!ipq4019_is_wifi_gpio_shared(scn)) {
                gpio_set_value_cansleep(scn->scn_led_gpio, 0);
                gpio_free(scn->scn_led_gpio);
            }
        }
#endif
    } else if (ipq4019_led_type == IPQ4019_LED_SOURCE) {
        /* nothing to be done */
    }
    scn->scn_led_gpio = 0;
    ipq4019_led_initialized = 0;
}
#endif
