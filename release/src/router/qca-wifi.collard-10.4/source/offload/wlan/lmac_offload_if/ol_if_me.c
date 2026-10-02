/*
 * Copyright (c) 2014, Qualcomm Atheros Inc.
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
 * LMAC offload interface functions for UMAC - Mcast enhancement feature 
 */

#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "sw_version.h"
#include "ol_txrx_ctrl_api.h"
#include "adf_os_mem.h"   /* adf_os_mem_alloc,free */
#include "adf_os_lock.h"  /* adf_os_spinlock_* */
#include "adf_os_types.h" /* adf_os_vprint */
#include "ol_ath.h"

#include "ol_if_stats.h"
#include "ol_ratetable.h"
#include "ol_if_vap.h"

#if ATH_SUPPORT_IQUE

#if ATH_SUPPORT_ME_FW_BASED
/* wrapper func for the inline function in ol_tx_desc.h */
u_int16_t
ol_ath_desc_alloc_and_mark_for_mcast_clone(struct ieee80211com *ic, u_int16_t buf_count)
{
    u_int16_t allocated, cur_alloc;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    /* TODO: Increase of high traffic scenario, there is a possiblity that alloc fails due
     * to lack of free descriptors. Need handle this by grabbing those descriptors while freeing*/
    cur_alloc = ol_tx_get_mcast_buf_allocated_marked(OL_ATH_SOFTC_NET80211(ic)->pdev_txrx_handle);
    /*Wait for FW to complete previous removal before adding any new request*/
    if( scn->pend_desc_removal ) {
        scn->pend_desc_addition += buf_count;
        return cur_alloc;
    }

    allocated = ol_tx_desc_alloc_and_mark_for_mcast_clone(OL_ATH_SOFTC_NET80211(ic)->pdev_txrx_handle, buf_count);

    if( (cur_alloc + buf_count) < allocated ) {
        scn->pend_desc_addition += (cur_alloc + buf_count) - allocated;
    }
    if( allocated > cur_alloc ) {
        wmi_unified_pdev_set_param(scn->wmi_handle,
                WMI_PDEV_PARAM_SET_MCAST2UCAST_BUFFER, allocated);
        printk("%s: VAP Mcast to Unicast buffer allocated: %u\n", __func__, allocated);
    }

    return allocated;
}

/* wrappers func for the inline function in ol_tx_desc.h */
u_int16_t
ol_ath_desc_free_and_unmark_for_mcast_clone(struct ieee80211com *ic, u_int16_t buf_count)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    scn->pend_desc_removal += buf_count;
    return (wmi_unified_pdev_set_param(scn->wmi_handle, WMI_PDEV_PARAM_REMOVE_MCAST2UCAST_BUFFER,
                buf_count));
}

/* function to get the value from txrx structure, instead of accessing directly */
u_int16_t
ol_ath_get_mcast_buf_allocated_marked(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    return(ol_tx_get_mcast_buf_allocated_marked(OL_ATH_SOFTC_NET80211(ic)->pdev_txrx_handle) - scn->pend_desc_removal);
}
#endif /*ATH_SUPPORT_ME_FW_BASED*/
static void
ol_ath_mcast_group_update(
    struct ieee80211com *ic,
    int action,
    int wildcard,
    u_int8_t *mcast_ip_addr,
    int mcast_ip_addr_bytes,
    u_int8_t *ucast_mac_addr,
    u_int8_t filter_mode,
    u_int8_t nsrcs,
    u_int8_t *srcs,
    u_int8_t *mask,
    u_int8_t vap_id)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_peer_mcast_group_cmd *cmd;
    wmi_buf_t buf;
    int len;
    int offset = 0;
    char dummymask[4] = { 0xFF, 0xFF, 0xFF, 0xFF};

    if (scn->is_ar900b) 
      return; 
    
    len = sizeof(wmi_peer_mcast_group_cmd);
    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        printk("%s: wmi_buf_alloc failed\n", __FUNCTION__);
        return;
    }
    cmd = (wmi_peer_mcast_group_cmd *) wmi_buf_data(buf);
    /* confirm the buffer is 4-byte aligned */
    ASSERT((((size_t) cmd) & 0x3) == 0);
    OS_MEMZERO(cmd,sizeof(wmi_peer_mcast_group_cmd));

    /* construct the message assuming our endianness matches the target */
    cmd->flags |= WMI_PEER_MCAST_GROUP_FLAG_ACTION_M &
        (action << WMI_PEER_MCAST_GROUP_FLAG_ACTION_S);
    cmd->flags |= WMI_PEER_MCAST_GROUP_FLAG_WILDCARD_M &
        (wildcard << WMI_PEER_MCAST_GROUP_FLAG_WILDCARD_S);
    if(action == IGMP_ACTION_DELETE_MEMBER && wildcard && !mcast_ip_addr)  {
        cmd->flags |= WMI_PEER_MCAST_GROUP_FLAG_DELETEALL_M;
    }

    if(mcast_ip_addr_bytes != IGMP_IP_ADDR_LENGTH)
        cmd->flags |=  WMI_PEER_MCAST_GROUP_FLAG_IPV6_M;
    if(filter_mode != IGMP_SNOOP_CMD_ADD_INC_LIST)
        cmd->flags |=WMI_PEER_MCAST_GROUP_FLAG_SRC_FILTER_EXCLUDE_M;

    /* unicast address spec only applies for non-wildcard cases */
    if (!wildcard && ucast_mac_addr) {
        OS_MEMCPY(
                &cmd->ucast_mac_addr,
                ucast_mac_addr,
                sizeof(cmd->ucast_mac_addr));
    }
    if(mcast_ip_addr) {
        ASSERT(mcast_ip_addr_bytes <= sizeof(cmd->mcast_ip_addr));
        offset = sizeof(cmd->mcast_ip_addr) - mcast_ip_addr_bytes;
        OS_MEMCPY(((u_int8_t *) &cmd->mcast_ip_addr) + offset,
                mcast_ip_addr,
                mcast_ip_addr_bytes);
    }

    if(!mask){
        mask= &dummymask[0];
    }
    OS_MEMCPY( ((u_int8_t *) &cmd->mcast_ip_mask) + offset, mask, mcast_ip_addr_bytes);

    if(srcs && nsrcs) {
        cmd->num_filter_addr = nsrcs;
        ASSERT((nsrcs * mcast_ip_addr_bytes) <= sizeof(cmd->srcs));

        OS_MEMCPY(((u_int8_t *) &cmd->filter_addr),srcs,nsrcs * mcast_ip_addr_bytes);
    }
    /* now correct for endianness, if necessary */
    /*
     * For Little Endian, N/w Stack gives packets in Network byte order and issue occurs
     * if both Host and Target happens to be in Little Endian. Target when compares IP
     * addresses in packet with MCAST_GROUP_CMDID given IP addresses, it fails. Hence
     * swap only mcast_ip_addr ( 16 bytes ) for now.
     * TODO : filter
     */
#ifdef BIG_ENDIAN_HOST
    ol_bytestream_endian_fix(
            (u_int32_t *)&cmd->ucast_mac_addr, (sizeof(*cmd)-4) / sizeof(u_int32_t));
#else
    ol_bytestream_endian_fix(
            (u_int32_t *)&cmd->mcast_ip_addr, (sizeof(cmd->mcast_ip_addr)) / sizeof(u_int32_t));
#endif /* Little Endian */
    wmi_unified_cmd_send(
            scn->wmi_handle, buf, len, WMI_PEER_MCAST_GROUP_CMDID);
}

extern uint16_t
ol_me_convert_ucast(struct ieee80211vap *vap, adf_nbuf_t wbuf,
                             u_int8_t newmac[][6], uint8_t new_mac_cnt)
{
    return ol_tx_me_convert_ucast(vap->iv_txrx_handle, wbuf,
                                        newmac, new_mac_cnt);
}
int ol_if_me_setup(struct ieee80211com *ic)
{
    ic->ic_mcast_group_update = ol_ath_mcast_group_update;
#if ATH_SUPPORT_ME_FW_BASED
    ic->ic_desc_alloc_and_mark_for_mcast_clone = ol_ath_desc_alloc_and_mark_for_mcast_clone;
    ic->ic_desc_free_and_unmark_for_mcast_clone = ol_ath_desc_free_and_unmark_for_mcast_clone;
    ic->ic_get_mcast_buf_allocated_marked = ol_ath_get_mcast_buf_allocated_marked;
#else
    ic->ic_me_convert = ol_me_convert_ucast;
#endif /*ATH_SUPPORT_ME_FW_BASED*/ 
    return 1;
}

#endif /*ATH_SUPPORT_IQUE*/
