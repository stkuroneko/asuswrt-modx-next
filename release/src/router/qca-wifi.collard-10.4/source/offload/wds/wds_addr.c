/*
 * Copyright (c) 2011, Atheros Communications Inc.
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
 * Copyright (c) 2013-2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include "athdefs.h"
#include "a_types.h"
#include "a_osapi.h"
#include "a_debug.h"
#include "ol_if_athvar.h"
#include "ol_defines.h"
#include "ol_if_ath_api.h"
#include "ol_helper.h"
#include "wmi.h"
#include "wmi_unified_api.h"
#include <pktlog_ac_api.h>
#include "wds_addr.h"
#include <ol_txrx_peer_find.h>
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif

#if PERF_FIND_WDS_NODE

#define WDS_TABLE_SZ 32

static void
_wds_entry_delete(struct wds_table *table, struct wds_table_entry *wds)
{
    TAILQ_REMOVE(&table->wds_entry, wds, wds_list);
    LIST_REMOVE(wds, wds_entry_hash);
    kfree(wds);
}

void
wds_table_init(struct wds_table *table)
{
    int i;

    rwlock_init(&table->wds_table_lock);
    TAILQ_INIT(&table->wds_entry);
    for (i = 0; i < WDS_TABLE_SZ; i++)
        LIST_INIT(&table->wds_table_hash[i]);
}

void
wds_table_uninit(struct wds_table *table)
{
    //unsigned long flags;
    struct wds_table_entry *wds, *next_wds;

    write_lock_bh(&table->wds_table_lock);
    TAILQ_FOREACH_SAFE(wds, &table->wds_entry, wds_list, next_wds) {
        _wds_entry_delete(table, wds);
    }
    write_unlock_bh(&table->wds_table_lock);
}

static struct wds_table_entry *
_wds_entry_find(struct wds_table *table, unsigned char *dest_mac)
{
    struct wds_table_entry *wds;
    int hash;

    hash = dest_mac[5] % WDS_TABLE_SZ;
    LIST_FOREACH(wds, &table->wds_table_hash[hash], wds_entry_hash) {
        if (!adf_os_mem_cmp(wds->dest_mac, dest_mac, 6))
            return wds;
    }
    return NULL;
}

static int
wds_entry_find(struct wds_table *table, unsigned char *dest_mac, unsigned char *peer_mac, struct ieee80211vap **vap)
{
    struct wds_table_entry *wds;
    //unsigned long flags;
    int ret = 0;

    read_lock_bh(&table->wds_table_lock);
    wds = _wds_entry_find(table, dest_mac);
    if (wds){
        adf_os_mem_copy(peer_mac, wds->peer_mac, 6);
        *vap = wds->vap;
    } else
         ret = 1;
    read_unlock_bh(&table->wds_table_lock);
    return ret;
}

int
wds_find(ol_scn_t scn, unsigned char *dest_mac, unsigned char *peer_mac, struct ieee80211vap **vap)
{
    return wds_entry_find(&((struct ol_ath_softc_net80211 *)scn)->scn_wds_table, dest_mac, peer_mac, vap);
}
#if QCA_PARTNER_PLATFORM
EXPORT_SYMBOL(wds_find);
#endif
static int
wds_entry_delete(struct wds_table *table, unsigned char *dest_mac)
{
    struct wds_table_entry *wds;
    //unsigned long flags;
    int ret = 0;

    write_lock_bh(&table->wds_table_lock);
    wds = _wds_entry_find(table, dest_mac);
    if (wds)
        _wds_entry_delete(table, wds);
    else
        ret = -1;
    write_unlock_bh(&table->wds_table_lock);
    return ret;
}

static int
wds_entry_add(ol_scn_t scn, struct wds_table *table, unsigned char *dest_mac, unsigned char *peer_mac)
{
    struct wds_table_entry *wds;
    //unsigned long flags;
    int hash, ret = 0;
    struct ieee80211_node *ni;

    write_lock_bh(&table->wds_table_lock);
    wds = _wds_entry_find(table, dest_mac);
    if (!wds) {
        wds = kmalloc(sizeof(*wds), GFP_ATOMIC);
        if (wds) {
            hash = dest_mac[5] % WDS_TABLE_SZ;
            adf_os_mem_copy(wds->dest_mac, dest_mac, 6);
            TAILQ_INSERT_TAIL(&table->wds_entry, wds, wds_list);
            LIST_INSERT_HEAD(&table->wds_table_hash[hash], wds, wds_entry_hash);
        }
    }
    if (wds) {
        adf_os_mem_copy(wds->peer_mac, peer_mac, 6);
        wds->vap = NULL;
        ni = ieee80211_find_node(&((struct ol_ath_softc_net80211 *)scn)->sc_ic.ic_sta, peer_mac);
        if (ni) {
            wds->vap = ni->ni_vap;
            ieee80211_unref_node(&ni);
        }
    } else
        ret = -1;
    write_unlock_bh(&table->wds_table_lock);
    return ret;
}

static int
wds_peer_event_handler(ol_scn_t scn, u_int8_t *datap, u_int16_t len, void *context)
{
    wmi_wds_addr_event_t *wds_addr_event = (wmi_wds_addr_event_t *)datap;
    unsigned char peer_mac[6],dest_mac[6];
    int i;
#ifdef BIG_ENDIAN_HOST
    for (i = 0; i < (len / sizeof(u_int32_t)); i++, datap += sizeof(u_int32_t))
        *(u_int32_t *)datap = le32_to_cpu(*(u_int32_t *)datap);
#endif
    for ( i = 0; i < 4; i++ )
    {
    	  peer_mac[i] = ((u_int8_t*)&(wds_addr_event->peer_mac.mac_addr31to0))[i];
    	  dest_mac[i] = ((u_int8_t*)&(wds_addr_event->dest_mac.mac_addr31to0))[i];
    }
    for ( i = 0; i < 2; i++ )
    {
    	  peer_mac[4+i] = ((u_int8_t*)&(wds_addr_event->peer_mac.mac_addr47to32))[i];
    	  dest_mac[4+i] = ((u_int8_t*)&(wds_addr_event->dest_mac.mac_addr47to32))[i];
    }
    if (len < sizeof(*wds_addr_event))
        printk(KERN_ERR "%s, size of WMI is %d, expected %d\n", __func__, len, sizeof(*wds_addr_event));
    else {
        if (wds_addr_event->event_type[0] == 1) {
            printk(KERN_ERR "Adding WDS entry through(%02x:%02x:%02x:%02x:%02x:%02x) of mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                   peer_mac[0], peer_mac[1],
                   peer_mac[2], peer_mac[3],
                   peer_mac[4], peer_mac[5],
                   dest_mac[0], dest_mac[1],
                   dest_mac[2], dest_mac[3],
                   dest_mac[4], dest_mac[5]);
                   wds_entry_add(scn, &((struct ol_ath_softc_net80211 *)scn)->scn_wds_table, dest_mac, peer_mac);
#if PEER_FLOW_CONTROL
                   ol_txrx_ast_find_hash_add(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle,
                    peer_mac, dest_mac, HTT_INVALID_PEER, 0);
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                       osif_nss_ol_pdev_add_wds_peer(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle,
                               &peer_mac, &dest_mac);
#endif

        } else if (wds_addr_event->event_type[0] == 2) {
            printk(KERN_ERR "Deleting WDS entry through(%02x:%02x:%02x:%02x:%02x:%02x) of mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                   peer_mac[0], peer_mac[1],
                   peer_mac[2], peer_mac[3],
                   peer_mac[4], peer_mac[5],
                   dest_mac[0], dest_mac[1],
                   dest_mac[2], dest_mac[3],
                   dest_mac[4], dest_mac[5]);
                   wds_entry_delete(&((struct ol_ath_softc_net80211 *)scn)->scn_wds_table, dest_mac);
#if PEER_FLOW_CONTROL
                   if(ol_txrx_ast_find_hash_remove(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle, dest_mac)) {
                       goto out;
                   }
#endif
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                   if (((struct ol_ath_softc_net80211 *)scn)->nss_nwifi_offload) {
                       osif_nss_ol_pdev_del_wds_peer(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle , &peer_mac, &dest_mac);
                   }
#endif


        } else {
            printk(KERN_ERR "%s, invalid WMI event type %d\n", __func__, wds_addr_event->event_type[0]);
        }
    }
#if PEER_FLOW_CONTROL
out:
#endif
    return 0;
}

#else
#if PEER_FLOW_CONTROL
static int
wds_peer_event_handler(ol_scn_t scn, u_int8_t *datap, u_int16_t len, void *context)
{
    wmi_wds_addr_event_t *wds_addr_event = (wmi_wds_addr_event_t *)datap;
    unsigned char peer_mac[6],dest_mac[6];
    int i;
#ifdef BIG_ENDIAN_HOST
    /*Skip swapping the first long word*/
    datap += sizeof(u_int32_t);
    for (i = 0; i < ((len / sizeof(u_int32_t))-1); i++, datap += sizeof(u_int32_t))
        *(u_int32_t *)datap = adf_os_le32_to_cpu(*(u_int32_t *)datap);
#endif
    for ( i = 0; i < 4; i++ )
    {
        peer_mac[i] = ((u_int8_t*)&(wds_addr_event->peer_mac.mac_addr31to0))[i];
        dest_mac[i] = ((u_int8_t*)&(wds_addr_event->dest_mac.mac_addr31to0))[i];
    }
    for ( i = 0; i < 2; i++ )
    {
        peer_mac[4+i] = ((u_int8_t*)&(wds_addr_event->peer_mac.mac_addr47to32))[i];
        dest_mac[4+i] = ((u_int8_t*)&(wds_addr_event->dest_mac.mac_addr47to32))[i];
    }
    if (len < sizeof(*wds_addr_event))
        adf_os_print("%s, size of WMI is %d, expected %d\n", __func__, len, sizeof(*wds_addr_event));
    else {
        if(wds_addr_event->event_type[0] == 1) {
            if (scn->pdev_txrx_handle->prof_trigger) {
                adf_os_print("Adding WDS entry through(%02x:%02x:%02x:%02x:%02x:%02x) of mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                        peer_mac[0], peer_mac[1],
                        peer_mac[2], peer_mac[3],
                        peer_mac[4], peer_mac[5],
                        dest_mac[0], dest_mac[1],
                        dest_mac[2], dest_mac[3],
                        dest_mac[4], dest_mac[5]);
            }
            ol_txrx_ast_find_hash_add(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle,
                    peer_mac, dest_mac, HTT_INVALID_PEER, 0);
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_nss_ol_pdev_add_wds_peer(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle,
                    (uint8_t *)&peer_mac, (uint8_t *)&dest_mac);
#endif


        } else if (wds_addr_event->event_type[0] == 2) {
            if (scn->pdev_txrx_handle->prof_trigger) {
                adf_os_print("Deleting WDS entry through(%02x:%02x:%02x:%02x:%02x:%02x) of mac(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                        peer_mac[0], peer_mac[1],
                        peer_mac[2], peer_mac[3],
                        peer_mac[4], peer_mac[5],
                        dest_mac[0], dest_mac[1],
                        dest_mac[2], dest_mac[3],
                        dest_mac[4], dest_mac[5]);
            }
            if(ol_txrx_ast_find_hash_remove(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle, dest_mac)) {
                goto out;
            }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            osif_nss_ol_pdev_del_wds_peer(((struct ol_ath_softc_net80211 *)scn)->pdev_txrx_handle,
                    (uint8_t *)&peer_mac, (uint8_t *)&dest_mac);
#endif

        } else {
            adf_os_print("%s, invalid WMI event type %d\n", __func__, wds_addr_event->event_type[0]);
        }
    }
out:
    return 0;
}

#else /* PEER_FLOW_CONTROL */
static int
wds_peer_event_handler(ol_scn_t scn, u_int8_t *datap, u_int16_t len, void *context)
{
        return 0;//do nothing
}

#endif /* PEER_FLOW_CONTROL */
#endif /* PERF_FIND_WDS_NODE */

void
wds_addr_init(wmi_unified_t wmi_handle)
{
    wmi_unified_register_event_handler(wmi_handle, WMI_WDS_PEER_EVENTID,
                                       wds_peer_event_handler, NULL);
}

void
wds_addr_detach(wmi_unified_t wmi_handle)
{
    wmi_unified_unregister_event_handler(wmi_handle, WMI_WDS_PEER_EVENTID);
}

