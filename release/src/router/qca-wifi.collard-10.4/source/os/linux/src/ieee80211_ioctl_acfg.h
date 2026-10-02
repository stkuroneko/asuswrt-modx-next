#ifndef IEEE80211_IOCTL_ACFG_H
#define IEEE80211_IOCTL_ACFG_H

#include <linux/wireless.h>
#include <linux/etherdevice.h>
#include <net/iw_handler.h>
#include <acfg_api_types.h>
#include <adf_os_atomic.h>
#include <acfg_event_types.h>

#if UMAC_SUPPORT_ACFG

#define ACFG_PVT_IOCTL  (SIOCWANDEV)

#if ACFG_NETLINK_TX

extern struct ath_softc_net80211 *global_scn[10];
extern int num_global_scn;
extern struct ol_ath_softc_net80211 *ol_global_scn[10];
extern int ol_num_global_scn;

typedef struct acfg_netlink_pvt {
    void *acfg_sock;
    adf_os_mutex_t *sem_lock;
    adf_os_spinlock_t offchan_lock;
    adf_nbuf_queue_t offchan_list;
    struct timer_list offchan_timer;
    u_int8_t home_chan;
    struct acfg_offchan_resp acfg_resp;
    struct acfg_offchan_tx_status acfg_tx_status[ACFG_MAX_OFFCHAN_TX_FRAMES];
    int process_pid;
    acfg_offchan_stat_t offchan_stat;
    adf_os_atomic_t num_cmpl_pending;
    struct ieee80211vap *vap;
} acfg_netlink_pvt_t;

#endif

typedef struct acfg_diag_stainfo {
    TAILQ_ENTRY(acfg_diag_stainfo) next;
    a_int64_t seconds;
    a_uint8_t notify;
    struct ieee80211vap *vap;
    acfg_diag_event_t diag;
}acfg_diag_stainfo_t;

typedef struct acfg_diag_pvt
{
    TAILQ_HEAD(, acfg_diag_stainfo) curr_stas;
    TAILQ_HEAD(, acfg_diag_stainfo) prev_stas;
    struct timer_list diag_timer;
}acfg_diag_pvt_t;

int
acfg_handle_vap_ioctl(struct net_device *dev, void *data);

#else
#define acfg_handle_vap_ioctl(dev, data) {}
#endif 

#endif /*IEEE80211_IOCTL_ACFG_H*/
