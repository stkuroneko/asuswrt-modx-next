/*
 * Copyright (c) 2008, Atheros Communications Inc.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * Qualcomm Atheros, Inc. has chosen to take madwifi subject to the BSD license and terms.
 *
 */

#include "ieee80211_mlme_priv.h"
#include "ieee80211_bssload.h"
#include "ieee80211_quiet_priv.h"


#if UMAC_SUPPORT_AP || UMAC_SUPPORT_IBSS || UMAC_SUPPORT_BTAMP
/*
 * Send a probe response frame.
 * NB: for probe response, the node may not represent the peer STA.
 * We could use BSS node to reduce the memory usage from temporary node.
 */
int
ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                         const void *optie, const size_t  optielen,
                         struct ieee80211_framing_extractx *extractx)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    int enable_htrates;
    bool add_wpa_ie = true;
    struct ieee80211_bwnss_map nssmap;
    u_int8_t rx_chainmask = ieee80211com_get_rx_chainmask(ic);

    ASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_IBSS ||
           vap->iv_opmode == IEEE80211_M_BTAMP);

    /*
     * XXX : This section needs more testing with P2P
     */
    if (!vap->iv_bss) {
        return 0;
    }

    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                          "%s: Error: unable to alloc wbuf of type WBUF_TX_MGMT.\n",
                          __func__);
        return -ENOMEM;
    }

#ifdef IEEE80211_DEBUG_REFCNT
    printk("%s ,line %u: increase node %p <%s> refcnt to %d\n",
           __func__, __LINE__, ni, ether_sprintf(ni->ni_macaddr),
           ieee80211_node_refcnt(ni));
#endif

    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                         vap->iv_myaddr, macaddr,
                         ieee80211_node_get_bssid(ni));
    frm = (u_int8_t *)&wh[1];

    /*
     * probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] cabability information
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] parameter set (FH/DS)
     *  [tlv] parameter set (QUIET)
     *  [tlv] parameter set (IBSS)
     *  [tlv] extended rate phy (ERP)
     *  [tlv] extended supported rates
     *  [tlv] country (if present)
     *  [3] power constraint
     *  [tlv] WPA
     *  [tlv] WME
     *  [tlv] HT Capabilities
     *  [tlv] HT Information
     *      [tlv] Atheros Advanced Capabilities
     */
    OS_MEMZERO(frm, 8);  /* timestamp should be filled later */
    frm += 8;
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;
    if (vap->iv_opmode == IEEE80211_M_IBSS){
        if(ic->ic_softap_enable)
            capinfo = IEEE80211_CAPINFO_ESS;
        else
            capinfo = IEEE80211_CAPINFO_IBSS;
	}
    else
        capinfo = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
    /* set rrm capbabilities, if supported */
    if (ieee80211_vap_rrm_is_set(vap)) {
        capinfo |= IEEE80211_CAPINFO_RADIOMEAS;
    }
    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;

    frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
                             vap->iv_bss->ni_esslen);
    frm = ieee80211_add_rates(frm, &vap->iv_bss->ni_rates);

    if (!IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
    }

    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;     /* TODO: ATIM window */
    }

    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
        frm = ieee80211_add_country(frm, vap);
    }

    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap) &&
	(IEEE80211_IS_CHAN_DFS(ic->ic_curchan) ||
          ((IEEE80211_IS_CHAN_11AC_VHT160(ic->ic_curchan) || IEEE80211_IS_CHAN_11AC_VHT80_80(ic->ic_curchan))
                        && IEEE80211_IS_CHAN_DFS_CFREQ2(ic->ic_curchan)))) {
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }

    frm = ieee80211_add_quiet(vap, ic, frm);

#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        frm =  ieee80211_add_ibss_dfs(frm,vap);
    }
#endif

    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) ||
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) {
        frm = ieee80211_add_erp(frm, ic);
    }

    /*
     * check if os shim has setup RSN IE it self.
     */
    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].ie,
                                           vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length);
    }
    /*
     * Check if RSN ie is present in probe response frame. Traverse the linked list
     * and check for RSN IE.
     * If not present, add it in the driver
     */
    add_wpa_ie=ieee80211_mlme_app_ie_check_wpaie(vap,IEEE80211_FRAME_TYPE_PROBERESP);
    if (vap->iv_opt_ie.length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_opt_ie.ie,
                                           vap->iv_opt_ie.length);
    }
    IEEE80211_VAP_UNLOCK(vap);

#if ATH_SUPPORT_HS20
    if (add_wpa_ie && !vap->iv_osen) {
#else
    if (add_wpa_ie) {
#endif
        if (RSN_AUTH_IS_RSNA(rsn))
            frm = ieee80211_setup_rsn_ie(vap, frm);
    }

#if ATH_SUPPORT_WAPI
    if (RSN_AUTH_IS_WAI(rsn))
        frm = ieee80211_setup_wapi_ie(vap, frm);
#endif

    frm = ieee80211_add_xrates(frm, &vap->iv_bss->ni_rates);

    frm = ieee80211_add_bssload(frm, ni);

    /* Add rrm capbabilities, if supported */
    frm = ieee80211_add_rrm_cap_ie(frm, ni);

    enable_htrates = ieee80211vap_htallowed(vap);

    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        enable_htrates) {
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        frm = ieee80211_add_htinfo(frm, ni);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            frm = ieee80211_add_obss_scan(frm, ni);
        }
    }

    /* Add extended capbabilities, if applicable */
    frm = ieee80211_add_extcap(frm, ni);

    /*  VHT capable  */
      /* Add vht cap for 2.4G mode, if 256QAM is enabled */
    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) &&
        ieee80211vap_vhtallowed(vap)) {

        /* Add VHT capabilities IE */
        if (ASSOCWAR160_IS_VHT_CAP_CHANGE(vap->iv_cfg_assoc_war_160w))
            frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);
        else
            frm = ieee80211_add_vhtcap(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, NULL);

        /* Add VHT Operation IE */
        frm = ieee80211_add_vhtop(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP, extractx);

        /* Add VHT TX power Envelope IE */
        if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
            frm = ieee80211_add_vht_txpwr_envlp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                                                         !IEEE80211_VHT_TXPWR_IS_SUB_ELEMENT);
            /* If iv_chanchange_count is non zero and ic_chanchange_channel is not null,
               it means vap is in chan/ch_width switch period */
            if(vap->iv_chanchange_count && (ic->ic_chanchange_channel != NULL)) {
                frm = ieee80211_add_chan_switch_wrp(frm, ni, ic, IEEE80211_FC0_SUBTYPE_BEACON,
                                                                  IEEE80211_VHT_EXTCH_SWITCH);
            }
        }
    }

    if (add_wpa_ie) {
        if (RSN_AUTH_IS_WPA(rsn))
            frm = ieee80211_setup_wpa_ie(vap, frm);
    }

    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) /* don't support WMM in ad-hoc for now */
        frm = ieee80211_add_wme_param(frm, &vap->iv_wmestate, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));

    if (ieee80211_vap_wme_is_set(vap) &&
        (IEEE80211_IS_CHAN_11AC(ic->ic_curchan) || IEEE80211_IS_CHAN_11N(ic->ic_curchan)) &&
        (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    }
    if (vap->iv_ena_vendor_ie == 1) {
	    if (vap->iv_bss->ni_ath_flags) {
		    frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
				    vap->iv_bss->ni_ath_defkeyindex);
	    } else {
		    frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
	    }
    }
    /* Insert ieee80211_ie_ath_extcap IE to beacon */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

    if(!(ic->ic_disable_bwnss_adv) && !ieee80211_get_bw_nss_mapping(vap, &nssmap, rx_chainmask))  {
        frm = ieee80211_add_bw_nss_maping(frm, &nssmap);
    }


    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_opt_ie.length) {
        OS_MEMCPY(frm, vap->iv_opt_ie.ie,
                  vap->iv_opt_ie.length);
        frm += vap->iv_opt_ie.length;
    }

    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length) {
        OS_MEMCPY(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].ie,
                  vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length;
    }

    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    IEEE80211_VAP_UNLOCK(vap);

    if (IEEE80211_VAP_IS_WDS_ENABLED(vap)) {
        u_int16_t whcCaps = QCA_OUI_WHC_AP_INFO_CAP_WDS;
        u_int16_t ie_len;

        /* SON mode requires WDS as a prereq */
        if (IEEE80211_VAP_IS_SON_ENABLED(vap)) {
            whcCaps |= QCA_OUI_WHC_AP_INFO_CAP_SON;
        }

        frm = ieee80211_add_whc_ap_info_ie(frm, whcCaps, vap, &ie_len);
    }

    if (ieee80211_vap_mbo_check(vap)) {
        frm = ieee80211_setup_mbo_ie(vap,frm);
    }

    if (optie != NULL && optielen != 0) {
        OS_MEMCPY(frm, optie, optielen);
        frm += optielen;
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

/* Determine whether probe response needs modification towards 160 MHz width
   association WAR.
 */
static bool
is_assocwar160_reqd_proberesp(struct ieee80211vap *vap,
        struct ieee80211_ie_ssid *probereq_ssid_ie,
        struct ieee80211_ie_vhtcap *sta_vhtcap)
{
    int is_sta_any160cap = 0;

    adf_os_assert_always(vap != NULL);
    adf_os_assert_always(probereq_ssid_ie != NULL);

    if (((vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT160) &&
                (vap->iv_cur_mode != IEEE80211_MODE_11AC_VHT80_80)) ||
        !vap->iv_cfg_assoc_war_160w) {
        return false;
    }

    /* The WAR is required only for STAs not having any 160/80+80 MHz
     * capability. */
    if (sta_vhtcap == NULL) {
        return true;
    }

    is_sta_any160cap =
        ((sta_vhtcap->vht_cap_info &
            (IEEE80211_VHTCAP_SUP_CHAN_WIDTH_160 |
             IEEE80211_VHTCAP_SUP_CHAN_WIDTH_80_160 |
             IEEE80211_VHTCAP_SHORTGI_160)) != 0);

    if (is_sta_any160cap) {
        return false;
    }

    return true;
}

int
ieee80211_recv_probereq(struct ieee80211_node *ni, wbuf_t wbuf, int subtype,
                        struct ieee80211_rx_status *rs)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    unsigned int found_vap  = 0;
    unsigned int found_null_bssid = 0;
    int ret = -EINVAL;
    u_int8_t *frm, *efrm;
    u_int8_t *ssid, *rates, *ven;
#if ATH_SUPPORT_HS20
    u_int8_t *iw = NULL, *xcaps = NULL;
    uint8_t empty[IEEE80211_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};
#endif
    u_int8_t nullbssid[IEEE80211_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};
    int snd_prb_resp = 0;
    struct ieee80211_ie_vhtcap *vhtcap = NULL;
    struct ieee80211_framing_extractx extractx;

    OS_MEMZERO(&extractx, sizeof(extractx));

#if ATH_SUPPORT_AP_WDS_COMBO
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap) || vap->iv_no_beacon) {
#else
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap)) {
#endif
        vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
        return -EINVAL;
    }

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

    if (IEEE80211_IS_MULTICAST(wh->i_addr2)) {
        /* frame must be directed */
        vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
        return -EINVAL;
    }

    /* Drop mcast Probe requests if Tx buffers availability goes low */
    if ((IEEE80211_IS_MULTICAST(wh->i_addr1)) &&
            (!ic->ic_is_mode_offload(ic)) &&
            (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) &&
            (vap->iv_opmode == IEEE80211_M_HOSTAP))
    {
        u_int32_t txbuf_free_count = 0, nvaps = 0, drop_threshold = 0;

        nvaps = ieee80211_get_num_active_vaps(ic);
        txbuf_free_count = ic->ic_get_txbuf_free(ic);
        if (nvaps > 8)
            drop_threshold = ATH_TXBUF/3;
        else
            drop_threshold = ATH_TXBUF/4;

        if (txbuf_free_count <= drop_threshold)
            goto exit;
    }

#if UMAC_SUPPORT_NAWDS
    /* Skip probe request if configured as NAWDS bridge */
    if(vap->iv_nawds.mode == IEEE80211_NAWDS_STATIC_BRIDGE
		  || vap->iv_nawds.mode == IEEE80211_NAWDS_LEARNING_BRIDGE) {
        return -EINVAL;
    }
#endif
    /*Update node if ni->bssid is NULL*/
    if(!OS_MEMCMP(ni->ni_bssid,nullbssid,IEEE80211_ADDR_LEN))
    {
        ni = ieee80211_ref_bss_node(vap);
        if(ni == NULL) {
            return -EINVAL;
        }

        found_null_bssid = 1;
    }
#if ATH_BAND_STEERING
    ieee80211_bsteering_send_probereq_event(vap, wh->i_addr2, rs->rs_rssi);

    /* If band steering is withholding probes (due to steering being in
     * progress), return here so that the response is not sent.
     */
    if (ieee80211_bsteering_is_probe_resp_wh(vap, wh->i_addr2)) {
        return 0;
    }

    /* If band steering wants to withhold the probe response for configured timeout/count,
     * to force association with 5G band, check and return without sending probe response.
     */
    if (ieee80211_bsteering_is_probe_resp_wh_24g(vap, wh->i_addr2, rs->rs_rssi))
    {
        return 0;
    }
#else
    // To silence compiler warning about unused variable.
    (void) rs;
#endif
    adf_os_mem_set((char *)(ni->ni_dedicated_macaddr),0,IEEE80211_ADDR_LEN);
    /*
     * prreq frame format
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] extended supported rates
     *  [tlv] Atheros Advanced Capabilities
     */
    ssid = rates = NULL;
    while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
#if ATH_SUPPORT_HS20
        case IEEE80211_ELEMID_XCAPS:
            xcaps = frm;
            break;
        case IEEE80211_ELEMID_INTERWORKING:
            iw = frm;
            break;
#endif
        case IEEE80211_ELEMID_VENDOR:
            if (vap->iv_venie && vap->iv_venie->ven_oui_set) {
                ven = frm;
                if (ven[2] == vap->iv_venie->ven_oui[0] &&
                    ven[3] == vap->iv_venie->ven_oui[1] &&
                    ven[4] == vap->iv_venie->ven_oui[2]) {
                    vap->iv_venie->ven_ie_len = MIN(ven[1] + 2, IEEE80211_MAX_IE_LEN);
                    OS_MEMCPY(vap->iv_venie->ven_ie, ven, vap->iv_venie->ven_ie_len);
                }
            }
           if (isdedicated_cap_oui(frm))
           {
              ni->ni_mu_bfee_cap = 1;
              OS_MEMCPY((char *)(ni->ni_dedicated_macaddr),(char *)(wh->i_addr2),IEEE80211_ADDR_LEN);
           }else{
              ni->ni_mu_bfee_cap = 0;
           }
            break;
        case IEEE80211_ELEMID_VHTCAP:
            vhtcap = (struct ieee80211_ie_vhtcap *)frm;
            break;
        }
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        return -EINVAL;
    }


    IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE);
    IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN);

    /* update rate and rssi information */
    ni->ni_stats.ns_last_rx_mgmt_rate = rs->rs_datarate;
    ni->ni_stats.ns_rx_mgmt_rssi = rs->rs_rssi;
    
    IEEE80211_DELIVER_EVENT_RECV_PROBE_REQ(vap, wh->i_addr2, ssid);
    /*
     * XXX bug fix 107944: STA Entry exists in the node table,
     * But the STA want to associate with the other vap,  vap should
     * send the correct proble response to Station.
     *
     */

    if(IEEE80211_MATCH_SSID(vap->iv_bss, ssid)  == 1)  //ssid not match
    {
        struct ieee80211vap *tmpvap = NULL;
        if(ni != vap->iv_bss)
        {
            TAILQ_FOREACH(tmpvap, &(ic)->ic_vaps, iv_next)
            {
                if((tmpvap->iv_opmode == IEEE80211_M_HOSTAP) && (!IEEE80211_MATCH_SSID(tmpvap->iv_bss, ssid)))
                {
                        found_vap = 1;
                        break;
                }
            }
        }
        if(found_vap  == 1)
        {
            ni = ieee80211_ref_bss_node(tmpvap);
            if ( ni ) {
                vap = ni->ni_vap;
            }
        }
        else
        {
            vap->iv_stats.is_rx_ssidmismatch++;
            goto exit;
        }

    }

    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) && (ssid[1] == 0)) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "no ssid with ssid suppression enabled");
        vap->iv_stats.is_rx_ssidmismatch++; /*XXX*/
        goto exit;
    }

#if ATH_SUPPORT_HS20
    if (!IEEE80211_ADDR_EQ(vap->iv_hessid, &empty)) {
        if (iw && !xcaps)
            goto exit;
        if (iw && (xcaps[5] & 0x80)) {
            /* hessid match ? */
            if (iw[1] == 9 && !IEEE80211_ADDR_EQ(iw+5, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+5, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            if (iw[1] == 7 && !IEEE80211_ADDR_EQ(iw+3, vap->iv_hessid) && !IEEE80211_ADDR_EQ(iw+3, IEEE80211_GET_BCAST_ADDR(ic)))
                goto exit;
            /* access_network_type match ? */
            if ((iw[2] & 0xF) != vap->iv_access_network_type && (iw[2] & 0xF) != 0xF)
                goto exit;
        }
    }
#endif

    /*
     * Skip Probe Requests received while the scan algorithm is setting a new
     * channel, or while in a foreign channel.
     * Trying to transmit a frame (Probe Response) during a channel change
     * (which includes a channel reset) can cause a NMI due to invalid HW
     * addresses.
     * Trying to transmit the Probe Response while in a foreign channel
     * wouldn't do us any good either.
     */
    if (ieee80211_scan_can_transmit(ic->ic_scanner) && !vap->iv_special_vap_mode) {
        if (likely(ic->ic_curchan == vap->iv_bsschan)) {
            snd_prb_resp = 1;
        }
#if MESH_MODE_SUPPORT
        if (vap->iv_mesh_vap_mode) {
            snd_prb_resp = 0;
        }
#endif
    }
    if (snd_prb_resp) {
        extractx.fectx_assocwar160_reqd = is_assocwar160_reqd_proberesp(vap,
                (struct ieee80211_ie_ssid *)ssid, vhtcap);

        if (extractx.fectx_assocwar160_reqd) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME,
                              "%s: Applying 160MHz assoc WAR: probe resp to "
                              "STA %s\n",
                              __func__, ether_sprintf(wh->i_addr2));
        }

        ieee80211_send_proberesp(ni, wh->i_addr2, NULL, 0, &extractx);
    }
    else {
        goto exit;
    }

    ret = 0;
exit:
    if(found_vap == 1 || found_null_bssid == 1)
        ieee80211_free_node(ni);

    return ret;
}

#endif
