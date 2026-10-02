/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef __ATH_PCI_H__
#define __ATH_PCI_H__

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/interrupt.h>
#include <linux/platform_device.h>

#if DUMP_FW_RAM
#if (ATH_SUPPORT_FW_RAM_DUMP_FOR_MIPS && (LINUX_VERSION_CODE == KERNEL_VERSION(3,3,8)))
#include <linux/ath79_wlan.h>
#endif
#endif

#define CONFIG_COPY_ENGINE_SUPPORT /* TBDXXX: here for now */
#undef CONFIG_ATH_SYSFS_CE
#define ATH_DBG_DEFAULT   0

#include <osdep.h>
#include <if_bus.h>
#include <ol_if_athvar.h>
#include <athdefs.h>
#include "a_osapi.h"
#if 0
#include "a_types.h"
#include "athdefs.h"
#endif
#include "hif.h"
#include "cepci.h"
#include "ol_ath.h"

/* Maximum number of Copy Engine's supported */
#define CE_COUNT_MAX 12
#if QCA_OL_11AC_FAST_PATH
#define CE_HTT_H2T_MSG_SRC_NENTRIES 4096
#else   /* QCA_OL_11AC_FAST_PATH */
#define CE_HTT_H2T_MSG_SRC_NENTRIES 2048
#endif  /* QCA_OL_11AC_FAST_PATH */

struct CE_state;
struct ol_ath_softc_net80211;
struct targetdef_s;

/* An address (e.g. of a buffer) in Copy Engine space. */
typedef ath_dma_addr_t CE_addr_t;

#if defined(CONFIG_ATH_SYSFS_CE)
struct ath_sysfs_buf_list {
    struct ath_sysfs_buf_list *next;
    char *host_data;     /* buffer in Host space */
    CE_addr_t CE_data;   /* buffer in CE space */
    size_t nbytes;
};

int ath_sysfs_CE_init(struct ol_ath_softc_net80211 *sc);
#endif

struct ath_hif_pci_softc {
    void __iomem *mem; /* PCI address. */
                       /* For efficiency, should be first in struct */
    struct device *dev;
    struct pci_dev *pdev;
    struct pci_device_id *id;
    struct _NIC_DEV aps_osdev;
    struct ol_ath_softc_net80211 *scn;
    int num_msi_intrs; /* number of MSI interrupts granted */
			/* 0 --> using legacy PCI line interrupts */
    struct tasklet_struct intr_tq;    /* tasklet */
    struct tasklet_struct msi_intr_tq;    /* tasklet for Multiple MSI interrupt handling */
    struct tasklet_struct msi_tq_htt_rx;
    struct tasklet_struct msi_tq_cmn;
    unsigned int msi_status; 
    struct work_struct pci_reconnect_work;	/* work queue */
#if QCA_OL_11AC_FAST_PATH
    int hif_started; /* Duplicating this for data path efficiency */
#endif /* QCA_OL_11AC_FAST_PATH */

    u_int32_t hif_type;
    u_int32_t target_type;
    int irq;
    int irq_event;
    int cacheline_sz;
    /*
    * Guard changes to Target HW state and to software
    * structures that track hardware state.
    */
    adf_os_spinlock_t target_lock;

#if defined(CONFIG_ATH_SYSFS_CE)
    struct CE_handle *sysfs_copyeng_recv;
    spinlock_t CE_recvq_lock;
    struct semaphore CE_recvdata_sem; /* tracks # full bufs recv'd */
    struct ath_sysfs_buf_list *CE_recvq_head;
    struct ath_sysfs_buf_list *CE_recvq_tail;

    struct CE_handle *sysfs_copyeng_send;
    spinlock_t CE_sendq_lock;
    struct semaphore CE_sendbuf_sem; /* tracks # free bufs */
    struct ath_sysfs_buf_list *CE_sendq_freehead;
    struct ath_sysfs_buf_list *CE_sendq_freetail;
#endif
    int rx_ce_list_fast[CE_COUNT_MAX];
    int tx_ce_list[CE_COUNT_MAX];
    int misc_ce_list[CE_COUNT_MAX];
    unsigned int ce_count; /* Number of Copy Engines supported */
    struct CE_state *CE_id_to_state[CE_COUNT_MAX]; /* Map CE id to CE_state */
    HIF_DEVICE *hif_device;

    bool force_break;  /* Flag to indicate whether to break out the DPC context */
    unsigned int receive_count; /* count Num Of Receive Buffers handled for one interrupt DPC routine */
    bool sc_valid;
    struct targetdef_s *targetdef;
#if QCA_PARTNER_DIRECTLINK_TX
    bool is_directlink;
#endif /* QCA_PARTNER_DIRECTLINK_TX */

    struct napi_struct napi_hdl;
    int  napi_budget;
    bool napi_enable;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    uint32_t nss_wifi_ol_mode;
    int32_t  nss_wifiol_id ;
    void    *nss_wifiol_ctx;
    int32_t nss_wifiol_bypass_nw_process;
#endif
    bool tasklet_enable;
};

#define TARGID(sc) ((A_target_id_t)(&(sc)->mem))
#define TARGID_TO_HIF(targid) (((struct ath_hif_pci_softc *)((char *)(targid) - (char *)&(((struct ath_hif_pci_softc *)0)->mem)))->hif_device)

bool ath_pci_targ_is_awake(void *__iomem *mem);

bool ath_pci_targ_is_present(A_target_id_t targetid, void *__iomem *mem);

bool ath_max_num_receives_reached(unsigned int count);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define DMA_MAPPING_ERROR(dev, addr) dma_mapping_error((addr))
#else
#define DMA_MAPPING_ERROR(dev, addr) dma_mapping_error((dev), (addr))
#endif

extern int ol_ath_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
extern void ol_ath_pci_remove(struct pci_dev *pdev);
extern int ol_ath_pci_suspend(struct pci_dev *pdev, pm_message_t state);
extern int ol_ath_pci_resume(struct pci_dev *pdev);

extern int ath_pci_check_target(struct ath_hif_pci_softc *sc, struct pci_dev *pdev);
extern void ath_pci_device_reset(struct ath_hif_pci_softc *sc);
extern void ath_pci_device_warm_reset(struct ath_hif_pci_softc *sc);

extern void pci_defer_reconnect(struct work_struct *pci_reconnect_work);

int HIF_PCIDeviceProbed(hif_handle_t hif_hdl);
int wifi_clk_enable_disable(struct device *dev,int enable);

irqreturn_t HIF_fw_interrupt_handler(int irq, void *arg);

int wlan_handle_napi(struct napi_struct *napi, int budget);

#ifdef ATH_AHB
extern int ol_ath_ahb_probe(struct platform_device *pdev, const struct platform_device_id *id);
extern void ol_ath_ahb_remove(struct platform_device *pdev);
extern void ath_ahb_device_reset(struct ath_hif_pci_softc *sc);
#else
#define ol_ath_ahb_probe(_pdev, _id) (-1)
#define ol_ath_ahb_remove(_pdev)
#define ath_ahb_device_reset(_sc)
#endif
#if 0
extern void kgdb_breakpoint(void);
#define BREAK() \
do { \
    kgdb_breakpoint(); \
} while (0)
#endif


/*
 * Typically, MSI Interrupts are used with PCIe. To force use of legacy
 * "ABCD" PCI line interrupts rather than MSI, define FORCE_LEGACY_PCI_INTERRUPTS.
 * Even when NOT forced, the driver may attempt to use legacy PCI interrupts
 * MSI allocation fails
 */
#define LEGACY_INTERRUPTS(sc) ((sc)->num_msi_intrs == 0)

#define PEREGRINE_PCI_DEVID        0x003c
#define BEELINER_PCI_DEVID         0x0040

#define WLAN_NAPI_BUDGET 64
#endif /* __ATH_PCI_H__ */
