/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <osdep.h>
#include <linux/if_arp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#endif

#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
#include "ol_if_athvar.h"
#include "ath_pci.h"
#endif

#include "if_athvar.h"
#include "if_ath_pci.h"
#include "if_bus.h"

#ifdef MAGPIE_HIF_PCI
/* WMI/HTC/HIF */
#include "ath_htc.h"
#endif

#include "osif_private.h"
#include <acfg_api_types.h>   /* for ACFG_WDT_REINIT_DONE */
#include <acfg_drv_event.h>

#ifndef ATH_BUS_PM
#ifdef CONFIG_PM
#define ATH_BUS_PM
#endif /* CONFIG_PM */
#endif /* ATH_BUS_PM */

#ifdef ATH_BUS_PM
#define ATH_PCI_PM_CONTROL 0x44
#endif

#ifdef AH_CAL_IN_FLASH_PCI
u_int32_t CalAddr[AH_CAL_RADIOS_PCI] = {AH_CAL_LOCATIONS_PCI};
int pci_dev_cnt=0;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
/*
 * PCI initialization uses Linux 2.4.x version and
 * older kernels do not support this
 */
#error Atheros PCI version requires at least Linux kernel version 2.4.0
#endif /* kernel < 2.4.0 */

/* ahbskip usage  : Skip registering direct attach devices only when set to 1 */
unsigned int ahbskip = 0;
module_param(ahbskip, int, 0644);
/*
 * Use a static table of PCI id's for now.  While this is the
 * "new way" to do things, we may want to switch back to having
 * the HAL check them by defining a probe method.
 */
DEFINE_PCI_DEVICE_TABLE(ath_pci_id_table) = {
    { 0x168c, 0x003c, PCI_ANY_ID, PCI_ANY_ID }, /* Peregrine PCIE  */
    { 0x168c, 0x0050, PCI_ANY_ID, PCI_ANY_ID }, /* Swift PCIE  */
    { 0x168c, 0x0040, PCI_ANY_ID, PCI_ANY_ID }, /* beeliner PCIE  */
    { 0x168c, 0x0046, PCI_ANY_ID, PCI_ANY_ID }, /* Cascade PCIE  */
    { 0x168c, 0x0056, PCI_ANY_ID, PCI_ANY_ID }, /* Besra PCIE  */
    { 0 }
};

#if QCA_PARTNER_DIRECTLINK_TX
extern void wlan_pltfrm_directlink_set_pcie_base(uint32_t mem);
#endif /* QCA_PARTNER_DIRECTLINK_TX */

static int
ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	
    u_int8_t max_payload;
    int ret=0,trynum=0;
#ifdef AH_CAL_IN_FLASH_PCI
    pci_dev_cnt++;
#endif
    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
#define AR9888_DEVICE_ID	(0x003c)
#define AR9887_DEVICE_ID    (0x0050)
#define AR900B_DEVICE_ID    (0x0040)
#define QCA9984_DEVICE_ID   (0x0046)
#define QCA9888_DEVICE_ID   (0x0056)
    /* emulation device id, peregrine id or beeliner id*/
    if (((id->device == 0xabcd) && (max_payload != 0)) || (id->device == AR9888_DEVICE_ID) || (id->device == AR9887_DEVICE_ID) || (id->device == AR900B_DEVICE_ID) || (id->device == QCA9984_DEVICE_ID) || (id->device == QCA9888_DEVICE_ID)) {
#if QCA_PARTNER_DIRECTLINK_TX
        wlan_pltfrm_directlink_set_pcie_base((uint32_t) pci_resource_start(pdev, 0));
#endif /* QCA_PARTNER_DIRECTLINK_TX */

	for(trynum=0;trynum<15;trynum++){
		printk("@@@@@@@@@%s: ol_ath_pci_probe trynum =%d\n", __func__,trynum);
		ret=ol_ath_pci_probe(pdev, id);
	    if (ret) {
		if(trynum>14){
		return ret;
		}
	    }
	   else{
		break;
		}
	}
	return ret;
        //return ol_ath_pci_probe(pdev, id);
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return (-ENODEV);
}

static void
ath_pci_remove(struct pci_dev *pdev)
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || (pdev->device == AR9888_DEVICE_ID) || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        ol_ath_pci_remove(pdev);
        return;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */
}

#ifdef ATH_BUS_PM
static int
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,10)
ath_pci_suspend(struct pci_dev *pdev, pm_message_t state)
#else
ath_pci_suspend(struct pci_dev *pdev, u32 state)
#endif
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || (pdev->device == AR9888_DEVICE_ID) || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        if(ol_ath_pci_suspend(pdev, state)) {
            return (-1);
        }
        return 0;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return 0;
}

static int
ath_pci_resume(struct pci_dev *pdev)
{
    u_int8_t max_payload;

    pci_read_config_byte(pdev, 0x74, &max_payload);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
    if (((pdev->device == 0xabcd) && (max_payload != 0)) || pdev->device == AR9888_DEVICE_ID || (pdev->device == AR900B_DEVICE_ID) || (pdev->device == AR9887_DEVICE_ID) || (pdev->device == QCA9984_DEVICE_ID) || (pdev->device == QCA9888_DEVICE_ID)) {
        if (ol_ath_pci_resume(pdev)) {
            return (-1);
        }
        return 0;
    }
#endif /* ATH_PERF_PWR_OFFLOAD && HIF_PCI */

    return 0;
}
#endif /* ATH_BUS_PM */

MODULE_DEVICE_TABLE(pci, ath_pci_id_table);

static struct pci_driver ath_pci_driver = {
    .name       = "ath_ol_pci",
    .id_table   = ath_pci_id_table,
    .probe      = ath_pci_probe,
    .remove     = ath_pci_remove,
#ifdef ATH_BUS_PM
    .suspend    = ath_pci_suspend,
    .resume     = ath_pci_resume,
#endif /* ATH_BUS_PM */
    /* Linux 2.4.6 has save_state and enable_wake that are not used here */
};

/*
 * Module glue.
 */
#include "version.h"
static char *version = ATH_PCI_VERSION " (Atheros/multi-bss)";
static char *dev_info = "ath_ol_pci";

struct semaphore reset_in_progress;
bool driver_registered = false;


#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
/* peregrine */
#ifdef CONFIG_AR900B_SUPPORT
extern void ramdump_work_handler(void *scn);
#endif

extern struct ol_ath_softc_net80211 *ol_global_scn[10];
void pci_defer_reconnect(struct work_struct *pci_reconnect_work)
{

    struct ath_hif_pci_softc *sc;
    struct pci_dev *pdev;
    const struct pci_device_id *id;
    struct ol_ath_softc_net80211 *scn = NULL;
    unsigned int radio_id;
printk("%s\n",__func__);
#ifdef CONFIG_AR900B_SUPPORT
	printk("%s\n CONFIG_AR900B_SUPPORT ",__func__);
    sc = container_of(pci_reconnect_work, struct ath_hif_pci_softc, pci_reconnect_work);
    ramdump_work_handler(sc->scn);

    if (sc->scn->recovery_enable == TRUE) {
        printk("Resetting the radio\n");
#endif
        if (down_interruptible(&reset_in_progress))
            return;

        if (!driver_registered) {
            up(&reset_in_progress);
            return;
        }


        /* We are here because the target has crashed
         * hence remove the PCI device and reload it
         */
        pdev = sc->pdev;
        id = sc->id;
        radio_id = sc->scn->radio_id;


        ath_pci_remove(pdev);
        ath_pci_probe(pdev, id);

        up(&reset_in_progress);

        /* get the new scn struct from updated global scn array */
        /* sc&scn structs are freed and re-alloced in pci remove&probe, global scn'll be updated */
        scn = ol_global_scn[radio_id];
        if(scn){
            /*Send event to user space */
            OSIF_RADIO_DELIVER_EVENT_WATCHDOG(&(scn->sc_ic), ACFG_WDT_REINIT_DONE);
        }

#ifdef CONFIG_AR900B_SUPPORT
    }
#endif
}
#endif  /* (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI) */

#include <linux/ethtool.h>

int
ath_ioctl_ethtool(struct ath_softc_net80211 *sc, int cmd, void *addr)
{
    struct ethtool_drvinfo info;

    if (cmd != ETHTOOL_GDRVINFO)
        return -EOPNOTSUPP;
    memset(&info, 0, sizeof(info));
    info.cmd = cmd;
    strncpy(info.driver, dev_info, sizeof(info.driver)-1);
    strncpy(info.version, version, sizeof(info.version)-1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,22)
    /* include the device name so later versions of kudzu DTRT */
    strncpy(info.bus_info, pci_name((struct pci_dev *)sc->sc_osdev->bdev),
        sizeof(info.bus_info)-1);
#endif
    return _copy_to_user(addr, &info, sizeof(info)) ? -EFAULT : 0;
}

MODULE_AUTHOR("Errno Consulting, Sam Leffler");
MODULE_DESCRIPTION("Support for Atheros 802.11 wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros WLAN cards");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

#if defined(CONFIG_KGDB)
unsigned int initbrk = 0;
module_param(initbrk, int, 0644);
#endif

static int __init
init_ath_pci(void)
{

#ifdef ATH_AHB
    int pciret = 0, ahbret = 0;
    int init_ath_ahb(void);
#endif

#if defined(CONFIG_KGDB)
    if (initbrk) {
        extern void kgdb_breakpoint(void);
        kgdb_breakpoint();
    }
#endif

#ifdef ATH_AHB
    ahbret = init_ath_ahb();
    if(ahbret < 0 ) {
        printk("ath_ahb: Error while registering ath wlan ahb driver\n");
    }
#endif

    printk(KERN_INFO "%s: %s\n", dev_info, version);

    if (pci_register_driver(&ath_pci_driver) < 0) {
        printk("ath_pci: No devices found, driver not installed.\n");
        pci_unregister_driver(&ath_pci_driver);
#ifdef ATH_AHB
        pciret = -ENODEV;
#else
        return (-ENODEV);
#endif
    }


#ifdef ATH_AHB
    /*
     * Return failure only when there is no wlan device
     * on both pci and ahb buses.
     */
      if (ahbret && pciret) {
              /* which error takes priority ?? */
              return ahbret;
      }
#endif

    driver_registered = true;
    sema_init(&reset_in_progress, 1);
    return 0;
}
module_init(init_ath_pci);


static void __exit
exit_ath_pci(void)
{

#ifdef ATH_AHB
    void exit_ath_ahb(void);
#endif


    if (down_interruptible(&reset_in_progress))
        return;

    pci_unregister_driver(&ath_pci_driver);
    driver_registered = false;
    up(&reset_in_progress);

#ifdef ATH_AHB
        exit_ath_ahb();
#else
    printk(KERN_INFO "%s: driver unloaded\n", dev_info);
#endif /* ATH_AHB */

}
module_exit(exit_ath_pci);
#if (ATH_PERF_PWR_OFFLOAD != 0) && defined(HIF_PCI)
EXPORT_SYMBOL(pci_defer_reconnect);
#endif /* defined(ATH_PERF_PWR_OFFLOAD) && defined(HIF_PCI) */
