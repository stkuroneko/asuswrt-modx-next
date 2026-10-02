/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
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
#include<ol_txrx_types.h>
#include<copy_engine_internal.h>

unsigned int msienable = 0;
module_param(msienable, int, 0644);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
unsigned int nss_wifi_olcfg = 0x0;
unsigned int nss_wifi_ol_skip_nw_process = 0x0;
module_param(nss_wifi_olcfg, uint, 0644);
module_param(nss_wifi_ol_skip_nw_process, uint, 0644);
#endif


/* PCIE data bus error seems to occur on RTC_STATE read
 * after putting Target in to reset and pulling Target out of reset.
 * As a temp. workaround replacing this RTC_STATE read with a Delay of 3ms
 * And this WAR is enabled by READ_AFTER_RESET_TEMP_WAR define
 */
#define READ_AFTER_RESET_TEMP_WAR


#if defined(QCA_PARTNER_PLATFORM) && !QCA_PARTNER_DIRECTLINK_RX
extern 	int osif_pltfrm_interupt_register(struct net_device *dev,int type, void * isr_handler, void *msi_ce_handler);
extern int osif_pltfrm_interupt_unregister(struct net_device *dev,int level);
#endif

/* Setting SOC_GLOBAL_RESET during driver unload causes intermittent PCIe data bus error
 * As workaround for this issue - changing the reset sequence to use TargetCPU warm reset
 * instead of SOC_GLOBAL_RESET
 */
#define CPU_WARM_RESET_WAR

irqreturn_t
ath_pci_msi_htt_rx_handler(int irq, void *arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;

#if PEER_FLOW_CONTROL
    ol_txrx_pdev_handle pdev =scn->pdev_txrx_handle;
#endif

#if PEER_FLOW_CONTROL
        if(pdev && pdev->prof_trigger) {
            pdev->delta_intr_tasklet_usecs = ktime_get_real();
        }
#endif

    sc->irq_event = irq;

    if(sc->napi_enable){
       napi_schedule(&sc->napi_hdl);
    } else if (sc->tasklet_enable) {
        tasklet_schedule(&sc->msi_tq_htt_rx);
    }


    return IRQ_HANDLED;
}

irqreturn_t
ath_pci_msi_common_handler(int irq, void *arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    int ret;

    sc->irq_event = irq;

    ret = (irqreturn_t)HIF_fw_interrupt_handler(sc->irq_event, sc);
    if (ret == ATH_ISR_NOTMINE) {
        return ATH_ISR_NOTMINE;
    }

    tasklet_schedule(&sc->msi_tq_cmn);

    return IRQ_HANDLED;
}
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

#if PEER_FLOW_CONTROL
    ol_txrx_pdev_handle pdev =scn->pdev_txrx_handle;
#endif

    if (LEGACY_INTERRUPTS(sc)) {
#if PEER_FLOW_CONTROL
        if(pdev && pdev->prof_trigger) {
            pdev->delta_intr_tasklet_usecs = ktime_get_real();
        }
#endif
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

    if(sc->napi_enable){
       napi_schedule(&sc->napi_hdl);
    } else if (sc->tasklet_enable) {
        tasklet_schedule(&sc->intr_tq);
    }


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
    int CE_id = irq - (sc->pdev->irq + MSI_ASSIGN_CE_INITIAL);
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

void CE_htt_rx_msi(int irq, struct ath_hif_pci_softc *sc);
extern void
CE_per_engine_handler_adjust(struct CE_state *CE_state,
                                     int disable_copy_compl_intr);

void
ol_ath_msi_tasklet_htt_rx(unsigned long data)
{
    struct net_device *dev = (struct net_device *)data;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;

    struct CE_state *CE_state = sc->CE_id_to_state[CE_HTT_MSG_CE];
    /* u_int32_t ctrl_addr = CE_state->ctrl_addr; */
    /* volatile uint32_t msi_data=0; */
    /* A_target_id_t targid = TARGID(sc); */

#if PEER_FLOW_CONTROL
    unsigned long delta_usecs;
    ol_txrx_pdev_handle lpdev =scn->pdev_txrx_handle;
#endif

#define MSI_DATA_ADDRESS 0x20
#if QCA_OL_11AC_FAST_PATH
    if (adf_os_likely(sc->hif_started)) {
        /*Disable HTT_RX CE interrupt*/
        CE_per_engine_handler_adjust(CE_state, 1);

        CE_htt_rx_msi(sc->irq_event, sc);
#if PEER_FLOW_CONTROL
        /*
         * Debug Latency Stats: prof_trigger controls execution
         */
        if(lpdev && lpdev->prof_trigger) {
            delta_usecs = ktime_to_us(ktime_sub(ktime_get_real(), lpdev->delta_intr_tasklet_usecs));
            if(delta_usecs < 500)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN500, 1);
            else if(delta_usecs < 1000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN1000, 1);
            else if(delta_usecs < 2000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN2000, 1);
            else if(delta_usecs < 4000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN4000, 1);
            else if(delta_usecs < 6000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN6000, 1);
            else
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBINHIGH, 1);
        }
#endif
        if (sc->napi_enable) {
            if (sc->napi_budget > 0) {
                napi_complete(&sc->napi_hdl);
            } else {
                return;
            }
        }

        /*Enable HTT_RX CE interrupt*/
        CE_per_engine_handler_adjust(CE_state, 0);

	return;
    }
#endif /* QCA_OL_11AC_FAST_PATH */
}


void
ol_ath_msi_tasklet_common(unsigned long data)
{
    struct net_device *dev = (struct net_device *)data;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;


#if QCA_OL_11AC_FAST_PATH
    if (adf_os_likely(sc->hif_started)) {

        CE_per_engine_service_each(sc->irq_event, sc);
        return;
    }
#endif /* QCA_OL_11AC_FAST_PATH */
    CE_per_engine_service_any(sc->irq_event, sc);
}

static void
ath_tasklet_msi(unsigned long data)
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
        if (LEGACY_INTERRUPTS(sc)) {
        /* Enable Legacy PCI line interrupts */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
            PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
        }
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


void
ol_ath_tasklet(unsigned long data)
{
    struct net_device *dev = (struct net_device *)data;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    volatile int tmp;

#if PEER_FLOW_CONTROL
    unsigned long delta_usecs;
    ol_txrx_pdev_handle lpdev =scn->pdev_txrx_handle;
#endif
    int ret;

    ret = (irqreturn_t)HIF_fw_interrupt_handler(sc->irq_event, sc);
    if (ret == ATH_ISR_NOTMINE) {
        return;
    }

#if QCA_OL_11AC_FAST_PATH
    if (adf_os_likely(sc->hif_started)) {
        CE_per_engine_service_each(sc->irq_event, sc);
#if PEER_FLOW_CONTROL
        /*
         * Debug Latency Stats: prof_trigger controls execution
         */
        if(lpdev && lpdev->prof_trigger) {
            delta_usecs = ktime_to_us(ktime_sub(ktime_get_real(), lpdev->delta_intr_tasklet_usecs));
            if(delta_usecs < 500)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN500, 1);
            else if(delta_usecs < 1000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN1000, 1);
            else if(delta_usecs < 2000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN2000, 1);
            else if(delta_usecs < 4000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN4000, 1);
            else if(delta_usecs < 6000)
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBIN6000, 1);
            else
                PFLOW_CTRL_PDEV_STATS_ADD(lpdev, INTR_TASKLETBINHIGH, 1);
        }
#endif
        if (sc->napi_enable) {
            if (sc->napi_budget > 0) {
                napi_complete(&sc->napi_hdl);
            } else {
                return;
            }
        }
	if (LEGACY_INTERRUPTS(sc)) {
	    /* Enable Legacy PCI line interrupts */
	    A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
                PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
	    tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
	}
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

void pci_reconnect_cb(struct ol_ath_softc_net80211 *scn)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    schedule_work(&sc->pci_reconnect_work);
}

#define ATH_PCI_PROBE_RETRY_MAX 3
struct ath_hif_pci_softc *diag_sc;


#if ATH_RX_LOOPLIMIT_TIMER
void
ol_rx_looplimit_handler(void *arg)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *)arg;
    volatile int tmp;

    sc->scn->rx_looplimit = false;
    sc->scn->scn_stats.rx_looplimit_end ++;
    adf_os_timer_cancel(&sc->scn->rx_looplimit_timer);

    if (LEGACY_INTERRUPTS(sc)) {
        /* Disable Legacy PCI line interrupts */
        A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS), 0);
        /* IMPORTANT: this extra read transaction is required to flush the posted write buffer */
        tmp = A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    }

    /* irq_event is not used here actually */
    tasklet_schedule(&sc->intr_tq);
}
#endif

/*
 * napi poll method for wlan
 */
int wlan_handle_napi(struct napi_struct *napi, int budget)
{
    struct net_device *dev = napi->dev;
    struct ol_ath_softc_net80211 *scn = ath_netdev_priv(dev);
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) scn->hif_sc;
    unsigned long data = (unsigned long)dev;
    sc->napi_budget = budget;
    if( LEGACY_INTERRUPTS(sc) || (sc->num_msi_intrs <=1) ) {
    	ol_ath_tasklet(data);
    }
    else {
	ol_ath_msi_tasklet_htt_rx(data);
    }

    return (budget - (sc->napi_budget));
}

int ath_pci_check_target(struct ath_hif_pci_softc *sc, struct pci_dev *pdev)
{
    u_int32_t lcr_val, fw_indicator;
    int ret = 0;
    int probe_again = 0;

again:
    if (pci_enable_device(pdev)) {
        adf_os_print(KERN_ERR "ath: cannot enable PCI device\n");
        return -EIO;
    }

    /* Disable ASPM on peregrine. Will be removed after the OTP is programmed */
    pci_read_config_dword(pdev, 0x80, &lcr_val);
    pci_write_config_dword(pdev, 0x80, (lcr_val & 0xffffff00));

    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    while (!ath_pci_targ_is_awake(sc->mem)) {
        ;
    }
    fw_indicator = A_PCI_READ32(sc->mem + FW_INDICATOR_ADDRESS);
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);

    if (fw_indicator & FW_IND_INITIALIZED) {
        probe_again++;
        adf_os_print(KERN_ERR "ath: Target is in an unknown state. Resetting (attempt %d).\n", probe_again);
        /* ath_pci_device_reset, below, will reset the target */
        ret = -EIO;
        goto err_tgtstate;
    }

    return ret;

err_tgtstate:
#if defined(CPU_WARM_RESET_WAR)
    if (sc->target_type == TARGET_TYPE_AR9888)
        ath_pci_device_warm_reset(sc);
    else
#endif
    {
        ath_pci_device_reset(sc);
    }

    if (probe_again <= ATH_PCI_PROBE_RETRY_MAX) {
        adf_os_print(KERN_INFO "ath reprobe\n");
        A_MDELAY(100);
        goto again;
    }
     return ret;
}

int
ol_ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    void __iomem *mem;
    int ret = 0;
    u_int32_t hif_type;
    u_int32_t target_type;
    struct ol_attach_t ol_cfg;
    struct ath_hif_pci_softc *sc;
    struct net_device *dev;
    int probe_again = 0;
    u_int16_t device_id;
    u_int8_t warm_reset = 0;

    u_int32_t lcr_val;

again:
    ret = 0;

#define BAR_NUM 0
    /*
     * Without any knowledge of the Host, the Target
     * may have been reset or power cycled and its
     * Config Space may no longer reflect the PCI
     * address space that was assigned earlier
     * by the PCI infrastructure.  Refresh it now.
     */
     /*WAR for EV#117307, if PCI link is down, return from probe() */
    pci_read_config_word(pdev,PCI_DEVICE_ID,&device_id);
    printk(KERN_INFO "%s: PCI device id %04x :%04x\n",__func__,device_id,id->device);
    if(device_id != id->device)  {
        printk(KERN_ERR "ath: PCI link is down.\n");
         /* pci link is down, so returing with error code */
        return -EIO;
    }

    /* FIXME: temp. commenting out assign_resource
     * call for dev_attach to work on 2.6.38 kernel
     */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0))  && !(__LINUX_ARM_ARCH__)
    if (pci_assign_resource(pdev, BAR_NUM)) {
        printk(KERN_ERR "ath: cannot assign PCI space\n");
        return -EIO;
    }
#endif

    if (pci_enable_device(pdev)) {
        printk(KERN_ERR "ath: cannot enable PCI device\n");
        return -EIO;
    }

#define BAR_NUM 0
    /* Request MMIO resources */
    ret = pci_request_region(pdev, BAR_NUM, "ath");
    if (ret) {
        dev_err(&pdev->dev, "ath: PCI MMIO reservation error\n");
        ret = -EIO;
        goto err_region;
    }

    ret =  pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
    if (ret) {
        printk(KERN_ERR "ath: 32-bit DMA not available\n");
        goto err_dma;
    }

    ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
    if (ret) {
        printk(KERN_ERR "ath: Cannot enable 32-bit consistent DMA\n");
        goto err_dma;
    }

    /* Set bus master bit in PCI_COMMAND to enable DMA */
    pci_set_master(pdev);

    /* Temporary FIX: disable ASPM on peregrine. Will be removed after the OTP is programmed */
    pci_read_config_dword(pdev, 0x80, &lcr_val);
    pci_write_config_dword(pdev, 0x80, (lcr_val & 0xffffff00));

    /* Arrange for access to Target SoC registers. */
    mem = pci_iomap(pdev, BAR_NUM, 0);
    if (!mem) {
        printk(KERN_ERR "ath: PCI iomap error\n") ;
        ret = -EIO;
        goto err_iomap;
    }

    sc = A_MALLOC(sizeof(*sc));
    if (!sc) {
        ret = -ENOMEM;
        goto err_alloc;
    }
    OS_MEMZERO(sc, sizeof(*sc));

    sc->mem = mem;
    sc->pdev = pdev;
    sc->id = (struct pci_device_id*)id;
    sc->dev = &pdev->dev;
    sc->aps_osdev.bdev = pdev;
    sc->aps_osdev.device = &pdev->dev;
    sc->aps_osdev.bc.bc_handle = (void *)mem;
    sc->aps_osdev.bc.bc_bustype = HAL_BUS_TYPE_PCI;
    ol_cfg.devid = id->device;
    ol_cfg.bus_type = BUS_TYPE_PCIE;

    adf_os_spinlock_init(&sc->target_lock);

    sc->cacheline_sz = dma_get_cache_alignment();

#if defined(CONFIG_AR6320_SUPPORT)
    hif_type = HIF_TYPE_AR6320;
    target_type = TARGET_TYPE_AR6320;
#elif defined(CONFIG_AR9888_SUPPORT) || defined(CONFIG_AR900B_SUPPORT)
#define AR9888_DEVICE_ID	(0x003c)
#define AR9887_DEVICE_ID	(0x0050)
#define AR900B_DEVICE_ID    (0x0040)
#define QCA9984_DEVICE_ID   (0x0046)
#define QCA9888_DEVICE_ID   (0x0056)
    if ((id->device == AR9888_DEVICE_ID) || (id->device == AR9887_DEVICE_ID)) {
        hif_type = HIF_TYPE_AR9888;
        target_type = TARGET_TYPE_AR9888;
        printk(KERN_INFO " *********** Peregrine **************\n");
    } else if (id->device == QCA9984_DEVICE_ID) {
        hif_type = HIF_TYPE_QCA9984;
        target_type = TARGET_TYPE_QCA9984;
        printk(KERN_INFO " *********** Cascade *************\n");
    } else if (id->device == QCA9888_DEVICE_ID) {
        hif_type = HIF_TYPE_QCA9888;
        target_type = TARGET_TYPE_QCA9888;
        printk(KERN_INFO " *********** Besra *************\n");
    } else {
        hif_type = HIF_TYPE_AR900B;
        target_type = TARGET_TYPE_AR900B;
        printk(KERN_INFO " *********** Beeliner *************\n");
    }
#else
#error "CONFIG_ARxxxx_SUPPORT not defined"
#endif
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

    sc->hif_type = hif_type;
    sc->target_type = target_type;

    ol_cfg.target_type = target_type;
#ifdef __ubicom32__
    /* Rewrite BAR0 address to work around the IPQ8K's PCIE issue:
     * BAR0 address is cleared by chip warm reset.
     */
    printk(KERN_INFO "BAR0 0x%x\n", sc->mem);
    pci_write_config_dword(pdev, PCI_BASE_ADDRESS_0, sc->mem);
#endif

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

    if (__ol_ath_attach(sc, &ol_cfg, &sc->aps_osdev, NULL)) {
        if (id->device == PEREGRINE_PCI_DEVID) {
            warm_reset = 1;
        }
        goto err_attach;
    }

    /* Register for Target Paused event */
    dev = pci_get_drvdata(pdev);
    __ol_ath_suspend_resume_attach(dev);

    diag_sc = sc;

    sc->scn->is_pci_device_type = true;
#if ATH_RX_LOOPLIMIT_TIMER
    printk("looplimit timer init\n");
    adf_os_timer_init(sc->scn->adf_dev, &sc->scn->rx_looplimit_timer,
                       ol_rx_looplimit_handler, (void *)sc);
#endif

    return 0;

err_attach:
    ret = -EIO;
err_tgtstate:
    pci_set_drvdata(pdev, NULL);
#if defined(CPU_WARM_RESET_WAR)
    if(warm_reset && id->device == PEREGRINE_PCI_DEVID) {
       ath_pci_device_warm_reset(sc);
       warm_reset = 0;
    }
    else
#endif
    {
       ath_pci_device_reset(sc);
    }
    A_FREE(sc);
err_alloc:
    /* call HIF PCI free here */
    printk("%s: HIF PCI Free needs to happen here \n", __func__);
    pci_iounmap(pdev, mem);
err_iomap:
    pci_release_region(pdev, BAR_NUM);
err_region:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
    pci_clear_master(pdev);
#endif
err_dma:
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

    return ret;
}

void
ol_ath_pci_nointrs(struct net_device *dev)
{
    struct ol_ath_softc_net80211 *scn;
    struct ath_hif_pci_softc *sc;
    int i;

    scn = ath_netdev_priv(dev);
    sc = (struct ath_hif_pci_softc *)scn->hif_sc;

    if (sc->num_msi_intrs > 0) {
        /* MSI interrupt(s) */
        for (i = 0; i < sc->num_msi_intrs; i++) {
#if defined(QCA_PARTNER_PLATFORM) && !QCA_PARTNER_DIRECTLINK_RX
	    osif_pltfrm_interupt_unregister(dev,i);
#else
            free_irq(dev->irq + i, dev);
#endif
        }
        sc->num_msi_intrs = 0;
    } else {
        /* Legacy PCI line interrupt */
#if defined(QCA_PARTNER_PLATFORM) && !QCA_PARTNER_DIRECTLINK_RX
        osif_pltfrm_interupt_unregister(dev,0);
#else
        free_irq(dev->irq, dev);
#endif

    }
}

void pci_irq_enable(hif_softc_t hif_sc)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    /* Disable interrupt till the hif_state is initialized */

    adf_os_print(KERN_INFO"\n Using PCI Legacy Interrupt\n");

    /* Make sure to wake the Target before enabling Legacy Interrupt */
    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    while (!ath_pci_targ_is_awake(sc->mem)) {
        ;
    }
    /* Use Legacy PCI Interrupts */
    /*
     * A potential race occurs here: The CORE_BASE write depends on
     * target correctly decoding AXI address but host won't know
     * when target writes BAR to CORE_CTRL. This write might get lost
     * if target has NOT written BAR. For now, fix the race by repeating
     * the write in below synchronization checking.
     */
    A_PCI_WRITE32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
            PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
    /* read to flush pcie write */
    (void)A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
}

int pci_wait_for_target(hif_softc_t hif_sc)
{ /* Synchronization point: Wait for Target to finish initialization before we proceed. */
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;

    int wait_limit = 300; /* 30 sec */
    while (wait_limit-- && !(A_PCI_READ32(sc->mem + FW_INDICATOR_ADDRESS) & FW_IND_INITIALIZED)) {
        schedule_timeout_interruptible(100);
        /* Fix potential race by repeating CORE_BASE writes */
        A_PCI_WRITE32(sc->mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS),
                PCIE_INTR_FIRMWARE_MASK | PCIE_INTR_CE_MASK_ALL);
        /* read to flush pcie write */
        (void)A_PCI_READ32(sc->mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    }

    if (wait_limit < 0) {
        adf_os_print(KERN_ERR "ath: %s: TARGET STALLED : \n", __FUNCTION__);
        return -EIO;
    }

    A_PCI_WRITE32(sc->mem + PCIE_LOCAL_BASE_ADDRESS + PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
    return 0;
}

int
ol_ath_pci_configure(hif_softc_t hif_sc, struct net_device *dev, hif_handle_t *hif_hdl)
{
    struct ath_hif_pci_softc *sc = (struct ath_hif_pci_softc *) hif_sc;
    int ret = 0;
    int num_msi_desired;
    u_int32_t val = 0;
    struct pci_dev *pdev = (struct pci_dev *)sc->pdev;

    BUG_ON(pci_get_drvdata(pdev) != NULL);
    pci_set_drvdata(pdev, dev);
    sc->scn = ath_netdev_priv(dev);
    sc->aps_osdev.netdev = dev;

    dev->mem_start = (unsigned long) sc->mem;
    dev->mem_end = (unsigned long)sc->mem + pci_resource_len(pdev, 0);

    dev_info(&pdev->dev, "ath DEBUG: sc=0x%p\n", sc);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    SET_MODULE_OWNER(dev);
#endif
    SET_NETDEV_DEV(dev, &pdev->dev);

    tasklet_init(&sc->intr_tq, ol_ath_tasklet, (unsigned long)dev);
    tasklet_init(&sc->msi_intr_tq, ath_tasklet_msi, (unsigned long)dev);
    sc->msi_status = 0;
    tasklet_init(&sc->msi_tq_htt_rx, ol_ath_msi_tasklet_htt_rx, (unsigned long)dev);
    tasklet_init(&sc->msi_tq_cmn, ol_ath_msi_tasklet_common, (unsigned long)dev);
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

    sc->sc_valid = 0;

    printk(KERN_INFO "\n %s : num_desired MSI set to %d\n", __func__, num_msi_desired);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    if (num_msi_desired > 1) {
        int i;
        int rv;

        rv = pci_enable_msi_block(pdev, num_msi_desired);

	if (rv == 0) { /* successfully allocated all MSI interrupts */
		/*
		 * TBDXXX: This path not yet tested,
		 * since Linux x86 does not currently
		 * support "Multiple MSIs".
		 */
		sc->num_msi_intrs = MSI_NUM_REQUEST;
		dev->irq = pdev->irq;

#if defined(QCA_PARTNER_PLATFORM) && !QCA_PARTNER_DIRECTLINK_RX
        ret = osif_pltfrm_interupt_register(dev, OFFLOAD_TYPE_MSI, ath_pci_msi_fw_handler, CE_per_engine_handler);
		if(ret) {
			dev_err(&pdev->dev, "ath_request_irq failed\n");
			goto err_intr;
		}
#else
		ret = request_irq(pdev->irq+MSI_ASSIGN_FW, ath_pci_msi_common_handler, IRQF_SHARED, dev->name, dev);
		if(ret) {
			dev_err(&pdev->dev, "ath_request_irq failed\n");
			goto err_intr;
		}
		for (i=MSI_ASSIGN_CE_INITIAL; i<num_msi_desired; i++) {
		    if(i == (MSI_ASSIGN_CE_INITIAL+CE_HTT_MSG_CE))
		    {
	                ret = request_irq(pdev->irq+i, ath_pci_msi_htt_rx_handler, IRQF_SHARED, dev->name, dev);
		        if(ret) {
		            dev_err(&pdev->dev, "ath_request_irq failed\n");
			    goto err_intr;
			}
		    }
		    else
		    {
			ret = request_irq(pdev->irq+i, ath_pci_msi_common_handler, IRQF_SHARED, dev->name, dev);
			if(ret) {
				dev_err(&pdev->dev, "ath_request_irq failed\n");
				goto err_intr;
			}
		    }
		}
#endif
	} else {
            if (rv < 0) {
                /* Can't get any MSI -- try for legacy line interrupts */
                num_msi_desired = 0;
            } else {
                /* Can't get enough MSI interrupts -- try for just 1 */
                num_msi_desired = 1;
            }
        }
    }
#endif

    if (num_msi_desired == 1) {
        /*
         * We are here because either the platform only supports
         * single MSI OR because we couldn't get all the MSI interrupts
         * that we wanted so we fall back to a single MSI.
         */
        if (pci_enable_msi(pdev) < 0) {
            printk(KERN_ERR "ath: single MSI interrupt allocation failed\n");
            /* Try for legacy PCI line interrupts */
            num_msi_desired = 0;
        } else {
            /* Use a single Host-side MSI interrupt handler for all interrupts */
            num_msi_desired = 1;
        }
    }

    if ( num_msi_desired <= 1) {
	    /* We are here because we want to multiplex a single host interrupt among all
	     * Target interrupt sources
	     */
	    dev->irq = pdev->irq;
#if defined(QCA_PARTNER_PLATFORM) && !QCA_PARTNER_DIRECTLINK_RX
        ret = osif_pltfrm_interupt_register(dev, OFFLOAD_TYPE_LEGACY, ath_pci_interrupt_handler, NULL);
#else
	    ret = request_irq(pdev->irq, ath_pci_interrupt_handler, IRQF_SHARED, dev->name, dev);
#endif
	    if(ret) {
		    dev_err(&pdev->dev, "ath_request_irq failed\n");
		    goto err_intr;
	    }

    }

    if (num_msi_desired == 0) {
        disable_irq(dev->irq);
        pci_irq_enable(sc);
    }
#if CONFIG_AR900B_SUPPORT
    /* read the sub revision of the chip, from beeliner onwards we try to
    *  differentiate between different chips. This is useful for selecting
    *  different versions of the firmware files
    */

    sc->scn->target_revision = 0;
    if (sc->scn->target_type == TARGET_TYPE_AR900B || sc->scn->target_type == TARGET_TYPE_QCA9984 || \
        sc->scn->target_type == TARGET_TYPE_QCA9888){
        /* CHIP revision is 8-11 bits of the CHIP_ID register 0xec in RTC space
         */
        /*sc->scn->target_revision = (A_PCI_READ32(sc->mem+0x800ec) & 0xf00) >> 8;*/
        sc->scn->target_revision = SOC_CHIP_ID_REVISION_GET(A_PCI_READ32(sc->mem+SOC_CHIP_ID_ADDRESS));
        printk(KERN_INFO"chip_id 0x%x chip_revision 0x%x \n", sc->scn->target_type, sc->scn->target_revision);
    }
#else
    sc->scn->target_revision = 0;
#endif

    sc->num_msi_intrs = num_msi_desired;
    sc->ce_count = CE_COUNT;
    {
        /* initialize the used ce engine numbers */
        sc->rx_ce_list_fast[0] = 1;
        sc->rx_ce_list_fast[1] = 2;
        if (sc->scn->target_type == TARGET_TYPE_AR900B || sc->scn->target_type == TARGET_TYPE_QCA9984 || \
            sc->scn->target_type == TARGET_TYPE_QCA9888) {
             sc->rx_ce_list_fast[2] = 8;
             sc->rx_ce_list_fast[3] = -1;
        } else {
            sc->rx_ce_list_fast[2] = -1;
        }
        sc->tx_ce_list[0] = 3;
        sc->tx_ce_list[1] = -1;
        sc->misc_ce_list[0] = 0;
        sc->misc_ce_list[1] = -1;
    }

    if (pci_wait_for_target(sc)) {
		ret = -EIO;
		goto err_stalled;
	}

    if (HIF_PCIDeviceProbed(sc)) {
            printk(KERN_ERR "ath: %s: Target probe failed.\n", __FUNCTION__);
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
     return 0;

err_stalled:
    /* Read Target CPU Intr Cause for debug */
    if(sc->scn->target_type == TARGET_TYPE_QCA9984 || sc->scn->target_type == TARGET_TYPE_AR900B) {
        val = A_PCI_READ32(sc->mem + (SOC_CORE_BASE_ADDRESS | WIFICMN_INT_STATUS_ADDRESS));
        printk("ERROR: Target Stalled : Target CPU Intr Cause 0x%x \n", val);
    }
    else if(sc->scn->target_type == TARGET_TYPE_AR9888) {
        val = A_PCI_READ32(sc->mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
        printk("ERROR: Target Stalled : Target CPU Intr Cause 0x%x \n", val);
    }
    ol_ath_pci_nointrs(dev);
err_intr:
    if (num_msi_desired) {
        pci_disable_msi(pdev);
    }
    pci_set_drvdata(pdev, NULL);

    return ret;
}

#define REMOVE_VAP_TIMEOUT_COUNT  20
#define REMOVE_VAP_TIMEOUT        (HZ/10)
void
ol_ath_pci_remove(struct pci_dev *pdev)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    struct ol_ath_softc_net80211 *scn;
    u_int32_t target_ver;
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
        adf_os_print(KERN_INFO"Suspending Target - with disable_intr set :%s (sc %p)\n",dev->name,sc);
        if (!ol_ath_suspend_target(scn, 1)) {
            u_int32_t  timeleft;
            adf_os_print(KERN_INFO"waiting for target paused event from target :%s (sc %p)\n",dev->name,sc);
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
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    if (!(scn->down_complete)) {
    preempt_disable();

    if (sc->nss_wifi_ol_mode) {
        osif_nss_ol_wifi_pause(sc);
        adf_os_print("%s:nss wifi offload pause\n",__FUNCTION__);
        mdelay(100);

        osif_nss_ol_wifi_reset(sc, 100);
    }

    preempt_enable();
    }
#endif

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
    if (target_paused == TRUE) {
    __ol_ath_detach(dev);
    } else {
        if (sc->id->device == PEREGRINE_PCI_DEVID) {
            /*
             * Removing the call to HIFPause from here, if target paused event has
             * not been received from the firmware. Data bus error is seen in
             * CE_Pause otherwise.
             */
        } else {
            HIFPause(hifdev);
        }
        scn->fwsuspendfailed = 1;
        wmi_stop(scn->wmi_handle);
    }

    if (!(scn->down_complete))  {
#if defined(CPU_WARM_RESET_WAR)
        /* Currently CPU warm reset sequence is tested only for AR9888_REV2
         * Need to enable for AR9888_REV1 once CPU warm reset sequence is
         * verified for AR9888_REV1
         */
        if ( (target_paused == TRUE)
                && (target_ver == AR9888_REV2_VERSION || target_ver == AR9887_REV1_VERSION) ) {
            adf_os_print("ath_pci_warm_reset :(sc %p)\n",sc);
            ath_pci_device_warm_reset(sc);
        }
        else {
            adf_os_print(KERN_INFO"%s:(sc %p)\n",__func__,sc);
            ath_pci_device_reset(sc);
        }
#else
        ath_pci_device_reset(sc);
#endif
    }
   if (target_paused != TRUE) {
       __ol_ath_detach(dev);
   }
    pci_disable_msi(pdev);
    A_FREE(sc);
    pci_set_drvdata(pdev, NULL);
    pci_iounmap(pdev, mem);
    pci_release_region(pdev, BAR_NUM);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
    pci_clear_master(pdev);
#endif
    pci_disable_device(pdev);
    printk(KERN_INFO "ath_pci_remove\n");
}


#define OL_ATH_PCI_PM_CONTROL 0x44

int
ol_ath_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    u32 val;

    if (__ol_ath_suspend(dev))
        return (-1);

    pci_read_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, &val);
    if ((val & 0x000000ff) != 0x3) {
        PCI_SAVE_STATE(pdev,
            ((struct ath_pci_softc *)ath_netdev_priv(dev))->aps_pmstate);
        pci_disable_device(pdev);
        pci_write_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, (val & 0xffffff00) | 0x03);
    }
    return 0;
}

int
ol_ath_pci_resume(struct pci_dev *pdev)
{
    struct net_device *dev = pci_get_drvdata(pdev);
    u32 val;
    int err;

    err = pci_enable_device(pdev);
    if (err)
        return err;

    pci_read_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, &val);
    if ((val & 0x000000ff) != 0) {
        PCI_RESTORE_STATE(pdev,
            ((struct ath_pci_softc *)ath_netdev_priv(dev))->aps_pmstate);

        pci_write_config_dword(pdev, OL_ATH_PCI_PM_CONTROL, val & 0xffffff00);

        /*
         * Suspend/Resume resets the PCI configuration space, so we have to
         * re-disable the RETRY_TIMEOUT register (0x41) to keep
         * PCI Tx retries from interfering with C3 CPU state
         *
         */
        pci_read_config_dword(pdev, 0x40, &val);

        if ((val & 0x0000ff00) != 0)
            pci_write_config_dword(pdev, 0x40, val & 0xffff00ff);
    }

    if (__ol_ath_resume(dev))
        return (-1);

    return 0;
}

#define A_PCIE_LOCAL_REG_READ(mem, addr) \
        A_PCI_READ32((char *)(mem) + PCIE_LOCAL_BASE_ADDRESS + (A_UINT32)(addr))

#define A_PCIE_LOCAL_REG_WRITE(mem, addr, val) \
        A_PCI_WRITE32(((char *)(mem) + PCIE_LOCAL_BASE_ADDRESS + (A_UINT32)(addr)), (val))

#define ATH_PCI_RESET_WAIT_MAX 10 /* Ms */
void
ath_pci_device_reset(struct ath_hif_pci_softc *sc)
{
    void __iomem *mem = sc->mem;
    int i;
    u_int32_t val;

    /* NB: Don't check resetok here.  This form of reset is integral to correct operation. */

    if (!SOC_GLOBAL_RESET_ADDRESS) {
        return;
    }

    if (!mem) {
        return;
    }

    printk("Reset Device \n");

    /*
     * NB: If we try to write SOC_GLOBAL_RESET_ADDRESS without first
     * writing WAKE_V, the Target may scribble over Host memory!
     */
    A_PCIE_LOCAL_REG_WRITE(mem, PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (ath_pci_targ_is_awake(mem)) {
            break;
        }

        A_MDELAY(1);
    }

    /* Put Target, including PCIe, into RESET. */
    val = A_PCIE_LOCAL_REG_READ(mem, SOC_GLOBAL_RESET_ADDRESS);
    val |= 1;
    A_PCIE_LOCAL_REG_WRITE(mem, SOC_GLOBAL_RESET_ADDRESS, val);

#if defined(READ_AFTER_RESET_TEMP_WAR)
    A_MDELAY(3);
#else
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (A_PCIE_LOCAL_REG_READ(mem, RTC_STATE_ADDRESS) & RTC_STATE_COLD_RESET_MASK) {
            break;
        }

        A_MDELAY(1);
    }
#endif /* end of READ_AFTER_RESET_TEMP_WAR */

    /* Pull Target, including PCIe, out of RESET. */
    val &= ~1;
    A_PCIE_LOCAL_REG_WRITE(mem, SOC_GLOBAL_RESET_ADDRESS, val);
#if defined(READ_AFTER_RESET_TEMP_WAR)
    A_MDELAY(3);
#else
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (!(A_PCIE_LOCAL_REG_READ(mem, RTC_STATE_ADDRESS) & RTC_STATE_COLD_RESET_MASK)) {
            break;
        }

        A_MDELAY(1);
    }
#endif /* end of READ_AFTER_RESET_TEMP_WAR */

    A_PCIE_LOCAL_REG_WRITE(mem, PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_RESET);
}


/* CPU warm reset function
 * Steps:
 * 	1. Disable all pending interrupts - so no pending interrupts on WARM reset
 * 	2. Clear the FW_INDICATOR_ADDRESS -so Traget CPU intializes FW correctly on WARM reset
 *      3. Clear TARGET CPU LF timer interrupt
 *      4. Reset all CEs to clear any pending CE tarnsactions
 *      5. Warm reset CPU
 */
void
ath_pci_device_warm_reset(struct ath_hif_pci_softc *sc)
{
    void __iomem *mem = sc->mem;
    int i;
    u_int32_t val;
    u_int32_t fw_indicator;

    /* NB: Don't check resetok here.  This form of reset is integral to correct operation. */

    if (!mem) {
        return;
    }

    printk("Target Warm Reset\n");

    /*
     * NB: If we try to write SOC_GLOBAL_RESET_ADDRESS without first
     * writing WAKE_V, the Target may scribble over Host memory!
     */
    A_PCIE_LOCAL_REG_WRITE(mem, PCIE_SOC_WAKE_ADDRESS, PCIE_SOC_WAKE_V_MASK);
    for (i=0; i<ATH_PCI_RESET_WAIT_MAX; i++) {
        if (ath_pci_targ_is_awake(mem)) {
            break;
        }
        A_MDELAY(1);
    }

    /*
     * Disable Pending interrupts
     */
    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_CAUSE_ADDRESS));
    printk("Host Intr Cause reg 0x%x : value : 0x%x \n", (SOC_CORE_BASE_ADDRESS | PCIE_INTR_CAUSE_ADDRESS), val);
    /* Target CPU Intr Cause */
    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
    printk("Target CPU Intr Cause 0x%x \n", val);

    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS));
    A_PCI_WRITE32((mem+(SOC_CORE_BASE_ADDRESS | PCIE_INTR_ENABLE_ADDRESS)), 0);
    A_PCI_WRITE32((mem+(SOC_CORE_BASE_ADDRESS+PCIE_INTR_CLR_ADDRESS)), 0xffffffff);

    A_MDELAY(100);

    /* Clear FW_INDICATOR_ADDRESS */
    fw_indicator = A_PCI_READ32(mem + FW_INDICATOR_ADDRESS);
    A_PCI_WRITE32(mem+FW_INDICATOR_ADDRESS, 0);

    /* Clear Target LF Timer interrupts */
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS + SOC_LF_TIMER_CONTROL0_ADDRESS));
    printk("addr 0x%x :  0x%x \n", (RTC_SOC_BASE_ADDRESS + SOC_LF_TIMER_CONTROL0_ADDRESS), val);
    val &= ~SOC_LF_TIMER_CONTROL0_ENABLE_MASK;
    A_PCI_WRITE32(mem+(RTC_SOC_BASE_ADDRESS + SOC_LF_TIMER_CONTROL0_ADDRESS), val);

    /* Reset CE */
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    val |= SOC_RESET_CONTROL_CE_RST_MASK;
    A_PCI_WRITE32((mem+(RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS)), val);
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    A_MDELAY(10);

    /* CE unreset */
    val &= ~SOC_RESET_CONTROL_CE_RST_MASK;
    A_PCI_WRITE32(mem+(RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS), val);
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    A_MDELAY(10);

    /* Read Target CPU Intr Cause */
    val = A_PCI_READ32(mem + (SOC_CORE_BASE_ADDRESS | CPU_INTR_ADDRESS));
    printk("Target CPU Intr Cause after CE reset 0x%x \n", val);

    /* CPU warm RESET */
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    val |= SOC_RESET_CONTROL_CPU_WARM_RST_MASK;
    A_PCI_WRITE32(mem+(RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS), val);
    val = A_PCI_READ32(mem + (RTC_SOC_BASE_ADDRESS | SOC_RESET_CONTROL_ADDRESS));
    printk("RESET_CONTROL after cpu warm reset 0x%x \n", val);

    A_MDELAY(100);
    printk("Target Warm reset complete\n");

}


EXPORT_SYMBOL(diag_sc);
