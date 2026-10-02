/*
* Copyright (c) 2013 Qualcomm Atheros, Inc..
* All Rights Reserved.
* Qualcomm Atheros Confidential and Proprietary.
*/

/* This will be registered when smart antenna is not enabled. So that WMI doesnt print
 * unhandled message.
 */
#include <ieee80211_var.h>
#include <ol_if_athvar.h>
#include <ol_txrx_types.h>
#include "ol_tx_desc.h"
#include "ol_if_athpriv.h"
#include <htt.h>

static int
wmi_unified_smart_ant_assoc_dummy_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen, void *context)
{
    return 0;
}

#if UNIFIED_SMARTANTENNA
#include <if_smart_ant.h>
#include <ieee80211_smart_ant_api.h>
#include "ol_if_smart_ant.h"

int ol_ath_smart_ant_stats_handler(struct ol_txrx_pdev_t *txrx_pdev, uint32_t* stats_base, uint32_t msg_len) 
{
#if ENHANCED_STATS
    struct sa_tx_feedback tx_feedback;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_txrx_peer_t *peer;
    struct ieee80211_node *ni = NULL;
    ppdu_common_stats *ppdu_stats;
    ppdu_sant_stats  *sant_stats;
#if __FW_DEBUG__   
    uint32_t *dwords;
#endif
    int i = 0; 
    scn = (struct ol_ath_softc_net80211 *)txrx_pdev->ctrl_pdev;
    ic  = &scn->sc_ic;

    if (!SMART_ANTENNA_TX_FEEDBACK_ENABLED(ic)) {
        return A_ERROR;
    }

    ppdu_stats = (ppdu_common_stats *)
                 ol_txrx_get_stats_base(txrx_pdev, stats_base, msg_len, HTT_T2H_EN_STATS_TYPE_COMMON);
    sant_stats = (ppdu_sant_stats *)
                 ol_txrx_get_stats_base(txrx_pdev, stats_base, msg_len, HTT_T2H_EN_STATS_TYPE_SANT);

    if ((ppdu_stats == NULL) || sant_stats == NULL) {
        return A_ERROR;
    }

#if __FW_DEBUG__   
    if (ppdu_stats) {
        dwords = ppdu_stats;
        printk("PPDU Raw Bytes: 0x%08x 0x%08x 0x%08x 0x%08x \n", dwords[0], dwords[1], dwords[2], dwords[3]);
    }

    if (ppdu_stats) {
        dwords = sant_stats;
        printk("SANT Raw Bytes: 0x%08x 0x%08x 0x%08x  0x%08x \n", dwords[0], dwords[1], dwords[2], dwords[3]);
    }
#endif    

    if (ppdu_stats->pkt_type == TX_FRAME_TYPE_DATA) { /* data frame */

        peer = (ppdu_stats->peer_id == HTT_INVALID_PEER) ?
            NULL : txrx_pdev->peer_id_to_obj_map[ppdu_stats->peer_id];

        if (peer && !(peer->bss_peer)) {
            ni = ieee80211_find_node(&ic->ic_sta, peer->mac_addr.raw);
            if (!ni) {
                return A_ERROR;
            }
            OS_MEMZERO(&tx_feedback, sizeof(tx_feedback));

            /* common ppdu stats */
            tx_feedback.nPackets = ppdu_stats->mpdus_queued;
            tx_feedback.nBad = ppdu_stats->mpdus_failed;

            tx_feedback.rate_mcs[0] = ppdu_stats->rate; 

            if (ic->ic_smart_ant_mode == SMART_ANT_MODE_SERIAL) {
                /* Extract and fill */
                /* index0 - s0_bw20, index1 - s0_bw40  index4 - s1_bw20 ... index7: s1_bw160 */
                for (i = 0; i < MAX_RETRIES; i++) {
                    tx_feedback.nlong_retries[i] =  ((ppdu_stats->long_retries >> (i*NIBBLE_BITS)) & MASK_LOWER_NIBBLE);
                    tx_feedback.nshort_retries[i] = ((ppdu_stats->short_retries >> (i*NIBBLE_BITS)) & MASK_LOWER_NIBBLE);
                    /* HW gives try counts and for SA module we need to provide failure counts
                     * So manipulate short failure count accordingly.
                     */
                    if (tx_feedback.nlong_retries[i]) {
                        if (tx_feedback.nshort_retries[i] == tx_feedback.nlong_retries[i]) {
                            tx_feedback.nshort_retries[i]--;
                        }
                    }
                }
            }

            tx_feedback.rssi[0] = ppdu_stats->rssi[0];
            tx_feedback.rssi[1] = ppdu_stats->rssi[1];
            tx_feedback.rssi[2] = ppdu_stats->rssi[2];
            tx_feedback.rssi[3] = ppdu_stats->rssi[3];

            /* Smart Antenna stats */
            tx_feedback.tx_antenna[0] = sant_stats->tx_antenna; 
            /* succes_idx is comming from Firmware, with recent changes success_idx is comming from
               bw_idx of ppdu stats */
            tx_feedback.rate_index = ppdu_stats->bw_idx;

            if (ic->ic_smart_ant_mode == SMART_ANT_MODE_SERIAL) {
                if (tx_feedback.nPackets != tx_feedback.nBad) {

                    if (tx_feedback.nlong_retries[ppdu_stats->bw_idx]) {
                        tx_feedback.nlong_retries[ppdu_stats->bw_idx] -= 1;
                    }

                    if (tx_feedback.nshort_retries[ppdu_stats->bw_idx]) {
                        tx_feedback.nshort_retries[ppdu_stats->bw_idx] -= 1;
                    }
                }
            }


            tx_feedback.is_trainpkt = sant_stats->is_training;
            tx_feedback.ratemaxphy = sant_stats->sa_max_rates;
            tx_feedback.goodput = sant_stats->sa_goodput;
#if __COMBINED_FEEDBACK__            
            tx_feedback.num_comb_feedback = sant_stats->num_comfeedbacks;
            *((A_UINT32 *)&tx_feedback.comb_fb[0]) = sant_stats->combined_fb[0];
            *((A_UINT32 *)&tx_feedback.comb_fb[1]) = sant_stats->combined_fb[1];
#endif

            ieee80211_smart_ant_update_txfeedback(ni, &tx_feedback);
            ieee80211_free_node(ni);
        }
    }
#endif
    return 0;    
}


static int
wmi_unified_smart_ant_assoc_handler(ol_scn_t scn, u_int8_t *data, u_int16_t datalen, void *context)
{
    struct ieee80211com *ic = &scn->sc_ic;
    A_UINT8 peer_macaddr[ATH_MAC_LEN];
    struct ieee80211_node *ni = NULL;
    struct sa_rate_cap rate_cap;
    int htindex = 0, i, j;
    uint8_t shift =0;
    wmi_peer_ratecode_list_event_t *rate_event = (wmi_peer_ratecode_list_event_t *)data;
    WMI_MAC_ADDR_TO_CHAR_ARRAY(&rate_event->peer_macaddr,peer_macaddr);

    ni = ieee80211_find_node(&ic->ic_sta, peer_macaddr);
    if (!ni) {
        return -1;
    }

    htindex = 0;
    rate_cap.ratecount[0] = ((rate_event->peer_rate_info.ratecount) & MASK_BYTE);
    rate_cap.ratecount[1] = ((rate_event->peer_rate_info.ratecount >> 8) & MASK_BYTE);
    rate_cap.ratecount[2] = ((rate_event->peer_rate_info.ratecount >> 16) & MASK_BYTE);
    rate_cap.ratecount[3] = ((rate_event->peer_rate_info.ratecount >> 24) & MASK_BYTE);

    if (rate_cap.ratecount[0]) {
        for (i = 0; i < MAX_LEGACY_RATE_DWORDS; i++) {
            for (j = 0;j < BYTES_IN_DWORD; j++) {
                rate_cap.ratecode_legacy[htindex] = ((rate_event->peer_rate_info.ratecode_legacy[i] >> (8*j)) & MASK_BYTE);
                htindex++;
            }
        }
    }

    htindex = 0;
    for (i = 0; i < MAX_HT_RATE_DWORDS; i++) {
        for (j = 0; j < BYTES_IN_DWORD; j++) {
            shift = (8*j);
            rate_cap.ratecode_20[htindex] = ((rate_event->peer_rate_info.ratecode_20[i] >> (shift)) & MASK_BYTE);
            rate_cap.ratecode_40[htindex] = ((rate_event->peer_rate_info.ratecode_40[i] >> (shift)) & MASK_BYTE);
            rate_cap.ratecode_80[htindex] = ((rate_event->peer_rate_info.ratecode_80[i] >> (shift)) & MASK_BYTE);
            htindex++;
        }
    }

    /* node connect */
    ieee80211_smart_ant_node_connect(ni, &rate_cap);
    ieee80211_free_node(ni);
    return 0;
}
void ol_ath_smart_ant_enable(struct ieee80211com *ic, uint32_t enable, uint32_t mode, uint32_t rx_antenna)
{
    /* Send WMI COMMAND to Enable */
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_pdev_smart_ant_enable_cmd *cmd;
    wmi_buf_t buf;
    void __iomem *smart_antenna_gpio;
    u_int32_t reg_value;
    int len = 0;
    int ret;
    len = sizeof(wmi_pdev_smart_ant_enable_cmd);
    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ;
    }

    cmd = (wmi_pdev_smart_ant_enable_cmd *)wmi_buf_data(buf);
    cmd->enable = enable & SMART_ANT_ENABLE_MASK;

    if(scn->sa_validate_sw == 1) { 
        cmd->mode = SMART_ANT_MODE_SERIAL;
    }
    else if(scn->sa_validate_sw == 2) {
        cmd->mode = SMART_ANT_MODE_PARALLEL;
    }
    else {
        cmd->mode = mode;
    }



    cmd->rx_antenna = rx_antenna;
    cmd->tx_default_antenna = rx_antenna;

    if (!scn->is_ar900b) {

        if (mode == SMART_ANT_MODE_SERIAL) {
            cmd->gpio_pin[0] = scn->sa_gpio_conf.gpio_pin[0];
            cmd->gpio_pin[1] = scn->sa_gpio_conf.gpio_pin[1];
            cmd->gpio_pin[2] = 0;
            cmd->gpio_pin[3] = 0;

            cmd->gpio_func[0] = scn->sa_gpio_conf.gpio_func[0];
            cmd->gpio_func[1] = scn->sa_gpio_conf.gpio_func[1];
            cmd->gpio_func[2] = 0;
            cmd->gpio_func[3] = 0;
        } else if (mode == SMART_ANT_MODE_PARALLEL){
            cmd->gpio_pin[0] = scn->sa_gpio_conf.gpio_pin[0];
            cmd->gpio_pin[1] = scn->sa_gpio_conf.gpio_pin[1];
            cmd->gpio_pin[2] = scn->sa_gpio_conf.gpio_pin[2];
            cmd->gpio_pin[3] = scn->sa_gpio_conf.gpio_pin[3];

            cmd->gpio_func[0] = scn->sa_gpio_conf.gpio_func[0];
            cmd->gpio_func[1] = scn->sa_gpio_conf.gpio_func[1];
            cmd->gpio_func[2] = scn->sa_gpio_conf.gpio_func[2];
            cmd->gpio_func[3] = scn->sa_gpio_conf.gpio_func[3];
        }

    } 
    if (enable && scn->target_type == TARGET_TYPE_IPQ4019) {

        /* Enable Smart antenna related GPIOs */
        smart_antenna_gpio = ioremap_nocache(IPQ4019_SMARTANTENNA_BASE_GPIO, IPQ4019_SMARTANTENNA_GPIOS_REG_SIZE);

        if(smart_antenna_gpio) {
            if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                printk("Enabling 2G Smart Antenna GPIO on ipq4019\n");
                reg_value = A_IO_READ32(smart_antenna_gpio);
                reg_value = (reg_value & ~0x1C) | 0xC;
                A_IO_WRITE32(smart_antenna_gpio, reg_value ); //gpio 44 2G Strobe

                reg_value = A_IO_READ32(smart_antenna_gpio + IPQ4019_SMARTANTENNA_GPIO45_OFFSET);
                reg_value = (reg_value & ~0x1C) | 0x10;
                A_IO_WRITE32(smart_antenna_gpio+0x1000, reg_value); //gpio 45 2G Sdata
            } else {
                printk("Enabling 5G Smart Antenna GPIO on ipq4019\n");
                reg_value = A_IO_READ32(smart_antenna_gpio + IPQ4019_SMARTANTENNA_GPIO46_OFFSET);
                reg_value = (reg_value & ~0x1C) | 0xC;
                A_IO_WRITE32(smart_antenna_gpio+0x2000, reg_value ); //gpio 46 5G Strobe

                reg_value = A_IO_READ32(smart_antenna_gpio + IPQ4019_SMARTANTENNA_GPIO47_OFFSET);
                reg_value = (reg_value & ~0x1C) | 0xC;
                A_IO_WRITE32(smart_antenna_gpio+0x3000, reg_value); //gpio 47 5G Sdata
            }

            iounmap(smart_antenna_gpio);
        }

    }

    if(!enable) {

        /* Disable Smart antenna related GPIOs */
        if (scn->target_type == TARGET_TYPE_IPQ4019) {

            smart_antenna_gpio = ioremap_nocache(IPQ4019_SMARTANTENNA_BASE_GPIO, IPQ4019_SMARTANTENNA_GPIOS_REG_SIZE);

            if(smart_antenna_gpio) {
                if (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan)) {
                    printk("Disabling 2G Smart Antenna GPIO on ipq4019\n");
                    reg_value = A_IO_READ32(smart_antenna_gpio);
                    reg_value = (reg_value & ~0x1C);
                    A_IO_WRITE32(smart_antenna_gpio, reg_value ); //gpio 44 2G Strobe

                    reg_value = A_IO_READ32(smart_antenna_gpio+0x1000);
                    reg_value = (reg_value & ~0x1C);
                    A_IO_WRITE32(smart_antenna_gpio+0x1000, reg_value); //gpio 45 2G Sdata
                } else {
                    printk("Disabling 5G Smart Antenna GPIO on ipq4019\n");
                    reg_value = A_IO_READ32(smart_antenna_gpio+0x2000);
                    reg_value = (reg_value & ~0x1C);
                    A_IO_WRITE32(smart_antenna_gpio+0x2000, reg_value ); //gpio 46 5G Strobe

                    reg_value = A_IO_READ32(smart_antenna_gpio+0x3000);
                    reg_value = (reg_value & ~0x1C);
                    A_IO_WRITE32(smart_antenna_gpio+0x3000, reg_value); //gpio 47 5G Sdata
                }
                iounmap(smart_antenna_gpio);
            }
        }
    }

    ret = wmi_unified_cmd_send(scn->wmi_handle,
                               buf,
                               len,
                               WMI_PDEV_SMART_ANT_ENABLE_CMDID);


    ic->smart_ant_enable = enable;
    /* Enable txfeed back to receive TX Control and Status descriptors from target */
    if( ret == 0) {
        if (scn->is_ar900b) {
        if (enable) {
            if (enable & SMART_ANT_TX_FEEDBACK_MASK) {
                ret = wmi_unified_pdev_set_param(scn->wmi_handle,
                        WMI_PDEV_PARAM_EN_STATS, 1);
                if (ret != EOK) {
                    printk("Enabling Stats failed \n");
                }
            }
        } else {
            ret = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_EN_STATS, 0);
            if (ret != EOK) {
                printk("Diabling Stats failed \n");
            }
        }
        } else {
        if (enable) {
            if (enable & SMART_ANT_TX_FEEDBACK_MASK) {
                ol_ath_smart_ant_enable_txfeedback(ic, 1);
            }
        } else {
            ol_ath_smart_ant_enable_txfeedback(ic, 0);
        }
        }
    } else {
        adf_os_print(" %s :WMI Failed \n", __func__);
        adf_os_print("%s: Sent WMI_PDEV_SMART_ANT_ENABLE_CMDID.\n"
                "enable:%d mode:%d  rx_antenna: 0x%08x PINS: [%d %d %d %d] Func[%d %d %d %d] cmdstatus=%d\n",
                __FUNCTION__,
                cmd->enable,
                cmd->mode,
                cmd->rx_antenna,
                cmd->gpio_pin[0], cmd->gpio_pin[1], cmd->gpio_pin[2], cmd->gpio_pin[3],
                cmd->gpio_func[0], cmd->gpio_func[1], cmd->gpio_func[2], cmd->gpio_func[3],
                ret);

    }
}

void ol_ath_smart_ant_set_rx_antenna(struct ieee80211com *ic, u_int32_t antenna)
{

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_pdev_smart_ant_set_rx_antenna_cmd *cmd;
    wmi_buf_t buf;
    int len = 0;
    int ret;

    len = sizeof(wmi_pdev_smart_ant_set_rx_antenna_cmd);
    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ;
    }

    cmd = (wmi_pdev_smart_ant_set_rx_antenna_cmd *)wmi_buf_data(buf);
    cmd->rx_antenna = antenna;
    ret = wmi_unified_cmd_send(scn->wmi_handle,
                               buf,
                               len,
                               WMI_PDEV_SMART_ANT_SET_RX_ANTENNA_CMDID);

    if (ret != 0) {
        adf_os_print(" %s :WMI Failed \n", __func__);
        adf_os_print("%s: Sent WMI_PDEV_SMART_ANT_SET_RX_ANTENNA_CMDID. \n"
                " rx_antenna: 0x%08x cmdstatus=%d\n",
                __FUNCTION__,
                cmd->rx_antenna,
                ret);
    }
}
/*
* TODO: As of now both RX antenna and TX default antenna are same.
* So call RX antena function and in future if required need to add a WMI for the same.
*/
void ol_ath_smart_ant_set_tx_default_antenna(struct ieee80211com *ic, u_int32_t antenna)
{
    ol_ath_smart_ant_set_rx_antenna(ic, antenna);
}

void ol_ath_smart_ant_set_tx_antenna(struct ieee80211_node *ni, u_int32_t *antenna_array)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    wmi_peer_sant_set_tx_antenna_cmd *cmd;
    wmi_buf_t buf;
    int len = 0;
    int ret;

    len = sizeof(wmi_peer_sant_set_tx_antenna_cmd);
    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ;
    }

    cmd = (wmi_peer_sant_set_tx_antenna_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = avn->av_if_id;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(ni->ni_macaddr, &cmd->peer_macaddr);

    cmd->antenna_series[0] = antenna_array[0];
    cmd->antenna_series[1] = antenna_array[1];
    ret = wmi_unified_cmd_send(scn->wmi_handle,
                               buf,
                               len,
                               WMI_PEER_SMART_ANT_SET_TX_ANTENNA_CMDID);

    if (ret != 0) {
        adf_os_print(" %s :WMI Failed \n", __func__);
        adf_os_print("%s: Sent WMI_PEER_SMART_ANT_SET_TX_ANTENNA_CMDID. \n"
                " Node: %s tx_antennas: [0x%08x 0x%08x] cmdstatus=%d\n",
                __FUNCTION__,
                ether_sprintf(ni->ni_macaddr),
                cmd->antenna_series[0],
                cmd->antenna_series[1],
                ret);
    }

}

void ol_ath_smart_ant_set_training_info(struct ieee80211_node *ni, uint32_t *rate_array, uint32_t *antenna_array, uint32_t numpkts)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    wmi_peer_sant_set_train_antenna_cmd *cmd;
    wmi_buf_t buf;
    int len = 0;
    int ret;

    len = sizeof(wmi_peer_sant_set_train_antenna_cmd);
    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ;
    }

    cmd = (wmi_peer_sant_set_train_antenna_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = avn->av_if_id;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(ni->ni_macaddr, &cmd->peer_macaddr);
    OS_MEMCPY(&cmd->train_rate_series[0], &rate_array[0], (sizeof(uint32_t)*SMART_ANT_MAX_RATE_SERIES));
    OS_MEMCPY(& cmd->train_antenna_series[0], &antenna_array[0], (sizeof(uint32_t)*SMART_ANT_MAX_RATE_SERIES));
    cmd->num_pkts = numpkts;
    ret = wmi_unified_cmd_send(scn->wmi_handle,
                               buf,
                               len,
                               WMI_PEER_SMART_ANT_SET_TRAIN_INFO_CMDID);

    if (ret != 0) {
        adf_os_print(" %s :WMI Failed \n", __func__);
        adf_os_print("%s: Sent WMI_PEER_SMART_ANT_SET_TRAIN_INFO_CMDID. \n"
                " Train Node: %s rate_array[0x%02x 0x%02x] tx_antennas: [0x%08x 0x%08x] cmdstatus=%d \n",
                __FUNCTION__,
                ether_sprintf(ni->ni_macaddr),
                cmd->train_rate_series[0], cmd->train_rate_series[1],
                cmd->train_antenna_series[0],cmd->train_antenna_series[1],
                ret);
    }

}


void ol_ath_smart_ant_set_node_config_ops(struct ieee80211_node *ni, uint32_t cmd_id, uint16_t args_count, u_int32_t args_arr[])
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(ni->ni_vap);
    wmi_peer_sant_set_node_config_ops_cmd *cmd;
    wmi_buf_t buf;
    int len = 0;
    int ret;
    int i = 0;

    len = sizeof(wmi_peer_sant_set_node_config_ops_cmd);

    if ((args_count == 0) || (args_count > (sizeof(cmd->args) / sizeof(cmd->args[0])))) {
        adf_os_print("%s: Can't send a command with %d arguments\n", __FUNCTION__, args_count);
	return;
    }

    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return ;
    }

    cmd = (wmi_peer_sant_set_node_config_ops_cmd *)wmi_buf_data(buf);
    cmd->vdev_id = avn->av_if_id;
    WMI_CHAR_ARRAY_TO_MAC_ADDR(ni->ni_macaddr, &cmd->peer_macaddr);
    cmd->cmd_id = cmd_id;
    cmd->args_count = args_count;
    for (i = 0; i < args_count; i++) {
        cmd->args[i] = args_arr[i];
    }

    ret = wmi_unified_cmd_send(scn->wmi_handle,
                               buf,
                               len,
                               WMI_PEER_SMART_ANT_SET_NODE_CONFIG_OPS_CMDID);

    if (ret != 0) {
        adf_os_print(" %s :WMI Failed \n", __func__);
        adf_os_print("%s: Sent WMI_PEER_SMART_ANT_SET_NODE_CONFIG_OPS_CMDID, cmd_id: 0x%x \n"
            " Node: %s cmdstatus=%d\n", __FUNCTION__, cmd_id, ether_sprintf(ni->ni_macaddr), ret);
    }
}



int ol_ath_smart_ant_rxfeedback(struct ol_txrx_pdev_t *pdev, struct ol_txrx_peer_t *peer, struct  sa_rx_feedback *rx_feedback)
{
    struct ol_txrx_vdev_t *vdev = NULL;
    struct ieee80211vap *vap = NULL;
    struct ieee80211_node *ni = NULL;
    int status = -1;
    struct ol_ath_softc_net80211 *scn =
        (struct ol_ath_softc_net80211 *)pdev->ctrl_pdev;

    vdev = peer->vdev;
    vap = ol_ath_vap_get(scn, vdev->vdev_id);
    if(!vap)
        return status;
    ni = ieee80211_find_node(&vap->iv_ic->ic_sta,
            peer->mac_addr.raw);
    if (ni) {
        status = ieee80211_smart_ant_update_rxfeedback(ni, rx_feedback);
        ieee80211_free_node(ni);
    }
    return status;
}

void
ol_ath_smart_ant_get_txfeedback (void *pdev, enum WDI_EVENT event, void *data,
                                 uint16_t peer_id, enum htt_rx_status status)
{
    struct ath_smart_ant_pktlog_hdr pl_hdr;
    uint32_t *pl_tgt_hdr;
    int txstatus = 0;
    int i = 0;
    struct sa_tx_feedback tx_feedback;
    struct ol_txrx_pdev_t *txrx_pdev = (struct ol_txrx_pdev_t *)pdev;
    struct ol_ath_softc_net80211 *scn = NULL;
    struct ieee80211com *ic = NULL;
    struct ol_txrx_peer_t *peer;
    struct ieee80211_node *ni = NULL;

    if (!txrx_pdev) {
        adf_os_print("Invalid pdev in %s\n", __func__);
        return;
    }
    scn = (struct ol_ath_softc_net80211 *)txrx_pdev->ctrl_pdev;
    ic  = &scn->sc_ic;

    if (event != WDI_EVENT_TX_STATUS) {
        adf_os_print("%s: Un Subscribed Event: %d \n", __func__, event);
        return;
    }

    if (!txrx_pdev) {
        adf_os_print("Invalid pdev in %s\n", __func__);
        return;
    }

    pl_tgt_hdr = (uint32_t *)data;
    pl_hdr.log_type =  (*(pl_tgt_hdr + ATH_SMART_ANT_PKTLOG_HDR_LOG_TYPE_OFFSET) &
                                        ATH_SMART_ANT_PKTLOG_HDR_LOG_TYPE_MASK) >>
                                        ATH_SMART_ANT_PKTLOG_HDR_LOG_TYPE_SHIFT;

    if ((pl_hdr.log_type == SMART_ANT_PKTLOG_TYPE_TX_CTRL)) {
        int frame_type;
        int peer_id;
        void *tx_ppdu_ctrl_desc;
        u_int32_t *tx_ctrl_ppdu, try_status = 0;
        uint8_t total_tries =0, sbw_indx_succ = 0;
        tx_ppdu_ctrl_desc = (void *)data + sizeof(struct ath_smart_ant_pktlog_hdr);

        tx_ctrl_ppdu = (u_int32_t *)tx_ppdu_ctrl_desc;

        peer_id = tx_ctrl_ppdu[TX_PEER_ID_OFFSET];

        frame_type = (tx_ctrl_ppdu[TX_FRAME_OFFSET]
                          & TX_FRAME_TYPE_MASK) >> TX_FRAME_TYPE_SHIFT;

        if (frame_type == TX_FRAME_TYPE_DATA) { /* data frame */

            if (ic->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] == 0) {
                return;
            }

            peer = (peer_id == HTT_INVALID_PEER) ?
                NULL : txrx_pdev->peer_id_to_obj_map[peer_id];
            if (peer && !(peer->bss_peer)) {

                ni = ieee80211_find_node(&ic->ic_sta, peer->mac_addr.raw);
                if (!ni) {
                    return;
                }

                total_tries = (ic->tx_ppdu_end[TX_TOTAL_TRIES_OFFSET] & TX_TOTAL_TRIES_MASK) >> TX_TOTAL_TRIES_SHIFT;

                OS_MEMZERO(&tx_feedback, sizeof(tx_feedback));
                tx_feedback.nPackets = (ic->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] & 0xffff);
                tx_feedback.nBad = (ic->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] & 0x1fff0000) >> 16;

                /* Rate code and Antenna values */
                tx_feedback.tx_antenna[0] = (tx_ctrl_ppdu[TX_ANT_OFFSET_S0] & TX_ANT_MASK);
                tx_feedback.tx_antenna[1] = (tx_ctrl_ppdu[TX_ANT_OFFSET_S1] & TX_ANT_MASK);

                /* RateCode */
                tx_feedback.rate_mcs[0] = ((tx_ctrl_ppdu[TXCTRL_S0_RATE_BW20_OFFSET] & TXCTRL_RATE_MASK) >> 24) |
                                          ((tx_ctrl_ppdu[TXCTRL_S0_RATE_BW40_OFFSET] & TXCTRL_RATE_MASK) >> 16) |
                                          ((tx_ctrl_ppdu[TXCTRL_S0_RATE_BW80_OFFSET] & TXCTRL_RATE_MASK) >> 8) |
                                          (tx_ctrl_ppdu[TXCTRL_S0_RATE_BW160_OFFSET] & TXCTRL_RATE_MASK);

                tx_feedback.rate_mcs[1] = ((tx_ctrl_ppdu[TXCTRL_S1_RATE_BW20_OFFSET] & TXCTRL_RATE_MASK) >> 24) |
                                          ((tx_ctrl_ppdu[TXCTRL_S1_RATE_BW40_OFFSET] & TXCTRL_RATE_MASK) >> 16) |
                                          ((tx_ctrl_ppdu[TXCTRL_S1_RATE_BW80_OFFSET] & TXCTRL_RATE_MASK) >> 8) |
                                          (tx_ctrl_ppdu[TXCTRL_S1_RATE_BW160_OFFSET] & TXCTRL_RATE_MASK);


                if (ic->ic_smart_ant_mode == SMART_ANT_MODE_SERIAL) {
                    /* Extract and fill */
                    /* index0 - s0_bw20, index1 - s0_bw40  index4 - s1_bw20 ... index7: s1_bw160 */
                    for (i = 0; i < MAX_RETRIES; i++) {
                        tx_feedback.nlong_retries[i] =  ((ic->tx_ppdu_end[LONG_RETRIES_OFFSET] >> (i*4)) & 0x0f);
                        tx_feedback.nshort_retries[i] = ((ic->tx_ppdu_end[SHORT_RETRIES_OFFSET] >> (i*4)) & 0x0f);

                        /* HW gives try counts and for SA module we need to provide failure counts
                         * So manipulate short failure count accordingly.
                         */
                        if (tx_feedback.nlong_retries[i]) {
                            if (tx_feedback.nshort_retries[i] == tx_feedback.nlong_retries[i]) {
                                tx_feedback.nshort_retries[i]--;
                            }
                        }
                    }
                }
                /* ACK RSSI */
                tx_feedback.rssi[0] = ic->tx_ppdu_end[ACK_RSSI0_OFFSET];
                tx_feedback.rssi[1] = ic->tx_ppdu_end[ACK_RSSI1_OFFSET];
                tx_feedback.rssi[2] = ic->tx_ppdu_end[ACK_RSSI2_OFFSET];
                tx_feedback.rssi[3] = ic->tx_ppdu_end[ACK_RSSI3_OFFSET];

                try_status = ic->tx_ppdu_end[total_tries-1];
                sbw_indx_succ = (try_status & TX_TRY_SERIES_MASK)?NUM_DYN_BW_MAX:0;
                sbw_indx_succ += ((try_status & TX_TRY_BW_MASK) >> TX_TRY_BW_SHIFT);
                if (ic->ic_smart_ant_mode == SMART_ANT_MODE_SERIAL) {
                    if (tx_feedback.nPackets != tx_feedback.nBad) {

                        if (tx_feedback.nlong_retries[sbw_indx_succ]) {
                            tx_feedback.nlong_retries[sbw_indx_succ] -= 1;
                        }

                        if (tx_feedback.nshort_retries[sbw_indx_succ]) {
                            tx_feedback.nshort_retries[sbw_indx_succ] -= 1;
                        }
                    }
                }

                tx_feedback.rate_index = sbw_indx_succ;
                tx_feedback.is_trainpkt = ((ic->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET] & SMART_ANT_FEEDBACK_TRAIN_MASK) ? 1: 0);
                tx_feedback.ratemaxphy =  (ic->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET_2]);
                tx_feedback.goodput =  (ic->tx_ppdu_end[(SMART_ANT_FEEDBACK_OFFSET_2+1)]);

                tx_feedback.num_comb_feedback = (ic->tx_ppdu_end[SMART_ANT_FEEDBACK_OFFSET]  & 0x60000000) >> 29;
                *((uint32_t *)&tx_feedback.comb_fb[0]) = ic->tx_ppdu_end[LONG_RETRIES_OFFSET];
                *((uint32_t *)&tx_feedback.comb_fb[1]) = ic->tx_ppdu_end[SHORT_RETRIES_OFFSET];

                /* Data recevied from the associated node, Prepare TX feed back structure and send to SA module */
                txstatus = ieee80211_smart_ant_update_txfeedback(ni, &tx_feedback);
                ieee80211_free_node(ni);
            }
        }
    } else {
        /* First We will get status */
        if (pl_hdr.log_type == SMART_ANT_PKTLOG_TYPE_TX_STAT) {
            void *tx_ppdu_status_desc;
            u_int32_t *tx_status_ppdu;
            tx_ppdu_status_desc = (void *)data + sizeof(struct ath_smart_ant_pktlog_hdr);
            tx_status_ppdu = (u_int32_t *)tx_ppdu_status_desc;
            /* cache ppdu end (tx status desc) for smart antenna txfeedback */
            OS_MEMCPY(&ic->tx_ppdu_end, tx_status_ppdu, (sizeof(uint32_t)*MAX_TX_PPDU_SIZE));
        }
    }
    return;
}

int ol_ath_smart_ant_enable_txfeedback(struct ieee80211com *ic, int enable)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t types=0;
    int len = 0;
    wmi_buf_t buf;
    wmi_pdev_pktlog_enable_cmd *cmd;

    if (enable == 1) {
        /* Call back for txfeedback */
        ((scn->sa_event_sub).callback) = ol_ath_smart_ant_get_txfeedback;
        if(wdi_event_sub(scn->pdev_txrx_handle,
                        &(scn->sa_event_sub),
                        WDI_EVENT_TX_STATUS)) {
            return A_ERROR;
        }

        types |= WMI_PKTLOG_EVENT_TX;
	types |= WMI_PKTLOG_EVENT_SMART_ANTENNA;

        len = sizeof(wmi_pdev_pktlog_enable_cmd);
        buf = wmi_buf_alloc(scn->wmi_handle, len);
        if (!buf) {
                adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
            return A_ERROR;
        }
        cmd = (wmi_pdev_pktlog_enable_cmd *)wmi_buf_data(buf);
        cmd->evlist = types;
        /*enabling the pktlog for smart antenna tx feedback*/
        if(wmi_unified_cmd_send(scn->wmi_handle, buf, len,
                                WMI_PDEV_PKTLOG_ENABLE_CMDID)) {
            return A_ERROR;
        }
        return A_OK;
    } else if (enable == 0) {
        if(wdi_event_unsub(
                    scn->pdev_txrx_handle,
                    &(scn->sa_event_sub),
                    WDI_EVENT_TX_STATUS)) {
            return A_ERROR;
        }

        buf = wmi_buf_alloc(scn->wmi_handle, 0);
        if (!buf) {
            adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
            return A_ERROR;
        }
        if(!wmi_unified_cmd_send(scn->wmi_handle, buf, len,
                                WMI_PDEV_PKTLOG_DISABLE_CMDID)) {
            return A_ERROR;
        }
        return A_OK;
    } else {
        return A_ERROR;
    }
}

int ol_smart_ant_enabled(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    return SMART_ANTENNA_ENABLED(ic);
}
EXPORT_SYMBOL(ol_smart_ant_enabled);

int ol_smart_ant_rx_feedback_enabled(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    return SMART_ANTENNA_RX_FEEDBACK_ENABLED(ic);
}
EXPORT_SYMBOL(ol_smart_ant_rx_feedback_enabled);

int ol_smart_ant_tx_feedback_enabled(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    return SMART_ANTENNA_TX_FEEDBACK_ENABLED(ic);
}
EXPORT_SYMBOL(ol_smart_ant_tx_feedback_enabled);


void ol_ath_smart_ant_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t smart_ant_enable = 0;
    smart_ant_enable = ((WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT) &&
                        WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_HW_SUPPORT) && scn->enable_smart_antenna)
                        || (WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT) && scn->sa_validate_sw));

    if (smart_ant_enable) {
        ic->ic_smart_ant_enable = ol_ath_smart_ant_enable;
        ic->ic_smart_ant_set_rx_antenna = ol_ath_smart_ant_set_rx_antenna;
        ic->ic_smart_ant_set_tx_antenna = ol_ath_smart_ant_set_tx_antenna;
        ic->ic_smart_ant_set_tx_default_antenna = ol_ath_smart_ant_set_tx_default_antenna;
        ic->ic_smart_ant_set_training_info = ol_ath_smart_ant_set_training_info;
	    ic->ic_smart_ant_set_node_config_ops = ol_ath_smart_ant_set_node_config_ops;
        ic->ic_smart_ant_prepare_rateset = NULL;
        ic->max_fallback_rates = 1; /* 1 primary and 1 fall back rate */
        ic->radio_id = 1; /* Radio Id is 1 for 5Ghz/offload */
        ic->ic_smart_ant_state = SMART_ANT_STATE_DEFAULT;
        /*
         * For pregrine host need to configure, For later chips
         * Firmware configures GPIO pins and function values.
         */
        if (!scn->is_ar900b) {
            scn->sa_gpio_conf.gpio_pin[0] = OL_SMART_ANTENNA_PIN0;
            scn->sa_gpio_conf.gpio_func[0] = OL_SMART_ANTENNA_FUNC0;
            scn->sa_gpio_conf.gpio_pin[1] = OL_SMART_ANTENNA_PIN1;
            scn->sa_gpio_conf.gpio_func[1] = OL_SMART_ANTENNA_FUNC1;
            scn->sa_gpio_conf.gpio_pin[2] = OL_SMART_ANTENNA_PIN2;
            scn->sa_gpio_conf.gpio_func[2] = OL_SMART_ANTENNA_FUNC2;
            scn->sa_gpio_conf.gpio_pin[3] = 0;  /*NA for !is_ar900b */
            scn->sa_gpio_conf.gpio_func[3] = 0; /*NA for !is_ar900b */
        }

        wmi_unified_register_event_handler(scn->wmi_handle, WMI_PEER_RATECODE_LIST_EVENTID,
                wmi_unified_smart_ant_assoc_handler, NULL);

    } else {
        ic->ic_smart_ant_enable = NULL;
        ic->ic_smart_ant_set_rx_antenna = NULL;
        ic->ic_smart_ant_set_tx_antenna = NULL;
        ic->ic_smart_ant_set_tx_default_antenna = NULL;
        ic->ic_smart_ant_set_training_info = NULL;
	    ic->ic_smart_ant_set_node_config_ops = NULL;
        ic->ic_smart_ant_prepare_rateset = NULL;
        if(!(WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT)))
            printk("%s: Firmware doest not support Smart Antenna.\n", __func__);

        if(!(WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_HW_SUPPORT)))
            printk("%s: Hardware doest not support Smart Antenna.\n", __func__);

        wmi_unified_register_event_handler(scn->wmi_handle, WMI_PEER_RATECODE_LIST_EVENTID,
                wmi_unified_smart_ant_assoc_dummy_handler, NULL);
    }
}

void ol_ath_smart_ant_detach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    uint32_t smart_ant_enable = 0;
    smart_ant_enable = ((WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT) &&
                        WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_HW_SUPPORT) && scn->enable_smart_antenna)
                        || (WMI_SERVICE_IS_ENABLED(scn->wmi_service_bitmap, WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT) && scn->sa_validate_sw));

    if (smart_ant_enable) {
        wmi_unified_unregister_event_handler(scn->wmi_handle, WMI_PEER_RATECODE_LIST_EVENTID);
    }
}

#else  /*UNIFIED_SMARTANTENNA not defined*/

void ol_ath_smart_ant_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_unified_register_event_handler(scn->wmi_handle, WMI_PEER_RATECODE_LIST_EVENTID,
            wmi_unified_smart_ant_assoc_dummy_handler, NULL);
}

void ol_ath_smart_ant_detach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_unified_unregister_event_handler(scn->wmi_handle, WMI_PEER_RATECODE_LIST_EVENTID);
}

#endif
