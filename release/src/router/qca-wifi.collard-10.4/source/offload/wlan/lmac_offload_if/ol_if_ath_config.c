/*
 * Copyright (c) 2011-2014, Atheros Communications Inc.
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
 * Radio interface configuration routines for perf_pwr_offload
 */
#include <osdep.h>
#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "ath_ald.h"
#include "dbglog_host.h"
#define IF_ID_OFFLOAD (1)
#if ATH_PERF_PWR_OFFLOAD
#if ATH_SUPPORT_SPECTRAL
#include "spectral.h"
#endif
#include "osif_private.h"

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
#include <osif_nss_wifiol_if.h>
#endif
#include <ieee80211_ioctl_acfg.h>

#if ATH_SUPPORT_HYFI_ENHANCEMENTS
/* Do we need to move these to some appropriate header */
void ol_ath_set_hmmc_tid(struct ieee80211com *ic , u_int32_t tid);
void ol_ath_set_hmmc_dscp_override(struct ieee80211com *ic , u_int32_t val);
void ol_ath_set_hmmc_tid(struct ieee80211com *ic , u_int32_t tid);


u_int32_t ol_ath_get_hmmc_tid(struct ieee80211com *ic);
u_int32_t ol_ath_get_hmmc_dscp_override(struct ieee80211com *ic);
#endif
void ol_ath_reset_vap_stat(struct ieee80211com *ic);
uint32_t promisc_is_active (struct ieee80211com *ic);
#if PEER_FLOW_CONTROL
extern uint32_t ol_pflow_update_pdev_params(struct ol_txrx_pdev_t *, ol_ath_param_t, uint32_t, void *);
#endif
extern uint32_t ol_update_txpow_pdev(struct ol_txrx_pdev_t *pdev, uint32_t value, void *buff);
extern int ol_ath_target_start(struct ol_ath_softc_net80211 *scn);

void ol_pdev_set_tid_override_queue_mapping(struct ol_txrx_pdev_t *pdev, int value);
int ol_pdev_get_tid_override_queue_mapping(struct ol_txrx_pdev_t *pdev);

static u_int32_t ol_ath_net80211_get_total_per(struct ieee80211com *ic)
{
    /* TODO: Receive values as u_int64_t and handle the division */
    u_int32_t failures = ic->ic_get_tx_hw_retries(ic);
    u_int32_t success  = ic->ic_get_tx_hw_success(ic);

    if ((success + failures) == 0) {
    return 0;
    }

    return ((failures * 100) / (success + failures));
}

int config_txchainmask(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    int retval = 0;

    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_TX_CHAIN_MASK, scn->user_config_val);
    if (retval == EOK) {
            /* Update the ic_chainmask */
            ieee80211com_set_tx_chainmask(ic, (u_int8_t)(scn->user_config_val));
    }

    return 0;
}

int config_rxchainmask(struct ol_ath_softc_net80211 *scn)
{
    struct ieee80211com *ic = &scn->sc_ic;
    int retval = 0;

    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                     WMI_PDEV_PARAM_RX_CHAIN_MASK, scn->user_config_val);

    if (retval == EOK) {
        /* Update the ic_chainmask */
        ieee80211com_set_rx_chainmask(ic, (u_int8_t)(scn->user_config_val));
    }

    return 0;
}

int
ol_ath_set_config_param(struct ol_ath_softc_net80211 *scn,
        ol_ath_param_t param, void *buff, bool *restart_vaps)
{
    int retval = 0;
    u_int32_t value = *(u_int32_t *)buff, param_id;
    struct ieee80211com *ic = &scn->sc_ic;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
	int thresh = 0;
#endif
#if DBDC_REPEATER_SUPPORT
    struct ieee80211com *other_ic = NULL;
    int i = 0;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
    struct ieee80211com *tmp_ic = NULL;
#endif
#endif
    u_int8_t transmit_power;
    adf_os_assert_always(restart_vaps != NULL);

    if (atomic_read(&scn->reset_in_progress)) {
        adf_os_print("Reset in progress, return\n");
        return -1;
    }

    if (scn->down_complete) {
        adf_os_print("Starting the target before sending the command\n");
        if (ol_ath_target_start(scn)) {
               adf_os_print("failed to start the target\n");
               return -1;
        }
    }

    switch(param)
    {
        case OL_ATH_PARAM_TXCHAINMASK:
        {
            u_int8_t cur_mask = ieee80211com_get_tx_chainmask(ic);

            if (!value) {
                /* value is 0 - set the chainmask to be the default
                 * supported tx_chain_mask value
                 */
                if (cur_mask == scn->wlan_resource_config.tx_chain_mask){
                    break;
                }
                scn->user_config_val = scn->wlan_resource_config.tx_chain_mask;
                scn->pdev_config_cb = config_txchainmask;
                osif_restart_for_config(ic);
            } else if (cur_mask != value) {
                /* Update chainmask only if the current chainmask is different */
                if (value > scn->wlan_resource_config.tx_chain_mask) {
                    printk("ERROR - value is greater than supported chainmask 0x%x \n",
                            scn->wlan_resource_config.tx_chain_mask);
                    return -1;
                }
                scn->user_config_val = value;
                scn->pdev_config_cb = config_txchainmask;
                osif_restart_for_config(ic);
            }
        }
        break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS || ATH_SUPPORT_DSCP_OVERRIDE

		case OL_ATH_PARAM_HMMC_DSCP_TID_MAP:
			ol_ath_set_hmmc_tid(ic,value);
		break;

		case OL_ATH_PARAM_HMMC_DSCP_OVERRIDE:
			ol_ath_set_hmmc_dscp_override(ic,value);
        break;
#endif
        case OL_ATH_PARAM_RXCHAINMASK:
        {
            u_int8_t cur_mask = ieee80211com_get_rx_chainmask(ic);
#if ATH_SUPPORT_SPECTRAL
            struct ath_spectral *spectral = NULL;
#endif
            if (!value) {
                /* value is 0 - set the chainmask to be the default
                 * supported rx_chain_mask value
                 */
                if (cur_mask == scn->wlan_resource_config.rx_chain_mask){
                    break;
                }
                scn->user_config_val = scn->wlan_resource_config.rx_chain_mask;
                scn->pdev_config_cb = config_rxchainmask;
                osif_restart_for_config(ic);
            } else if (cur_mask != value) {
                /* Update chainmask only if the current chainmask is different */
                if (value > scn->wlan_resource_config.rx_chain_mask) {
                    printk("ERROR - value is greater than supported chainmask 0x%x \n",
                            scn->wlan_resource_config.rx_chain_mask);
                    return -1;
                }
                scn->user_config_val = value;
                scn->pdev_config_cb = config_rxchainmask;
                osif_restart_for_config(ic);
            }
#if ATH_SUPPORT_SPECTRAL
            spectral = (struct ath_spectral *)ic->ic_spectral;
            printk("Resetting spectral chainmask to Rx chainmask\n");
            spectral->params.ss_chn_mask = ieee80211com_get_rx_chainmask(ic);
#endif
        }
        break;
#if QCA_AIRTIME_FAIRNESS
        case  OL_ATH_PARAM_ATF_STRICT_SCHED:
        {
            if ((value != 0) && (value != 1))
            {
                printk("\n ATF Strict Sched value only accept 1 (Enable) or 0 (Disable)!! \n");
                return -1;
            }
            if ((value == 1) && (!(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY)) && (ic->ic_atf_ssidgroup))
            {
                printk("\nFair queue across groups is enabled so strict queue within groups is not allowed. Invalid combination \n");
                return -EINVAL;
            }
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_ATF_STRICT_SCH,
                    value);
                if (retval == EOK) {
                    if (value)
                        ic->ic_atf_sched |= IEEE80211_ATF_SCHED_STRICT;
                    else
                        ic->ic_atf_sched &= ~IEEE80211_ATF_SCHED_STRICT;
            }
        }
        break;
        case  OL_ATH_PARAM_ATF_GROUP_POLICY:
        {
            if ((value != 0) && (value != 1))
            {
                printk("\n ATF Group policy value only accept 1 (strict) or 0 (fair)!! \n");
                return -1;
            }
            if ((value == 0) && (ic->ic_atf_sched & IEEE80211_ATF_SCHED_STRICT))
            {
                printk("\n Strict queue within groups is enabled so fair queue across groups is not allowed.Invalid combination \n");
                return -EINVAL;
            }
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_ATF_SSID_GROUP_POLICY,
                    value);
            if (retval == EOK) {
                if (value)
                    ic->ic_atf_sched |= IEEE80211_ATF_GROUP_SCHED_POLICY;
                else
                    ic->ic_atf_sched &= ~IEEE80211_ATF_GROUP_SCHED_POLICY;
            }

        }
        break;

    case  OL_ATH_PARAM_ATF_OBSS_SCHED:
        {
#if 0 /* remove after FW support */
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_ATF_OBSS_NOISE_SCH, !!value);
#endif
            if (retval == EOK) {
                if (value)
                    ic->ic_atf_sched |= IEEE80211_ATF_SCHED_OBSS;
                else
                    ic->ic_atf_sched &= ~IEEE80211_ATF_SCHED_OBSS;
            }
        }
        break;
    case  OL_ATH_PARAM_ATF_OBSS_SCALE:
        {
#if 0 /* remove after FW support */
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_ATF_OBSS_NOISE_SCALING_FACTOR, value);
#endif
            if (retval == EOK) {
                ic->atf_obss_scale = value;
            }
        }
        break;
#endif
        case OL_ATH_PARAM_TXPOWER_LIMIT2G:
        {
            if (!value) {
                value = scn->max_tx_power;
            }
            ic->ic_set_txPowerLimit(ic, value, value, 1);
        }
        break;

        case OL_ATH_PARAM_TXPOWER_LIMIT5G:
        {
            if (!value) {
                value = scn->max_tx_power;
                }
                ic->ic_set_txPowerLimit(ic, value, value, 0);
            }
        break;
        case OL_ATH_PARAM_RTS_CTS_RATE:
        if(value > 4) {
            printk("Invalid value for setctsrate Disabling it in Firmware \n");
            value = WMI_FIXED_RATE_NONE;
        }
        scn->ol_rts_cts_rate = value;
        return wmi_unified_pdev_set_param(scn->wmi_handle,
                WMI_PDEV_PARAM_RTS_FIXED_RATE,value);
        break;

        case OL_ATH_PARAM_DEAUTH_COUNT:
        if(value) {
            scn->scn_user_peer_invalid_cnt = value;
            scn->scn_peer_invalid_cnt = 0;
        }
        break;

            case OL_ATH_PARAM_TXPOWER_SCALE:
        {
            if((WMI_TP_SCALE_MAX <= value) && (value <= WMI_TP_SCALE_MIN))
            {
                scn->txpower_scale = value;
                return wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_TXPOWER_SCALE, value);
            } else {
                retval = -EINVAL;
            }
        }
        break;
            case OL_ATH_PARAM_PS_STATE_CHANGE:
        {
            (void)wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PEER_STA_PS_STATECHG_ENABLE, value);
            scn->ps_report = value;
        }
        break;
        case OL_ATH_PARAM_NON_AGG_SW_RETRY_TH:
        {
                return wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_NON_AGG_SW_RETRY_TH, value);
        }
        break;
        case OL_ATH_PARAM_AGG_SW_RETRY_TH:
        {
		return wmi_unified_pdev_set_param(scn->wmi_handle,
				WMI_PDEV_PARAM_AGG_SW_RETRY_TH, value);
	}
	break;
	case OL_ATH_PARAM_STA_KICKOUT_TH:
	{
		return wmi_unified_pdev_set_param(scn->wmi_handle,
				WMI_PDEV_PARAM_STA_KICKOUT_TH, value);
	}
	break;
    case OL_ATH_PARAM_DYN_GROUPING:
    {
        value = !!value;
        if ((scn->dyngroup != (u_int8_t)value) && (ic->ic_dynamic_grouping_support)) {
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_MU_GROUP_POLICY, value);

            if (retval == EOK) {
                scn->dyngroup = (u_int8_t)value;
            }

        } else {
                retval = -EINVAL;
        }
        break;
    }
    case OL_ATH_PARAM_DBGLOG_RATELIM:
    {
            dbglog_ratelimit_set(value);
    }
    break;
	case OL_ATH_PARAM_BCN_BURST:
	{
		/* value is set to either 1 (bursted) or 0 (staggered).
		 * if value passed is non-zero, convert it to 1 with
                 * double negation
                 */
                value = !!value;
                if (scn->bcn_mode != (u_int8_t)value) {
                    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_BEACON_TX_MODE, value);
                    if (retval == EOK) {
                        scn->bcn_mode = (u_int8_t)value;
                    }
                }
                break;
        }
        break;
    case OL_ATH_PARAM_DPD_ENABLE:
        {
            value = !!value;
            if ((scn->dpdenable != (u_int8_t)value) && (ic->ic_dpd_support)) {
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                        WMI_PDEV_PARAM_DPD_ENABLE, value);
                if (retval == EOK) {
                    scn->dpdenable = (u_int8_t)value;
                }
            } else {
                retval = -EINVAL;
            }
        }
        break;

    case OL_ATH_PARAM_ARPDHCP_AC_OVERRIDE:
        {
            if ((WME_AC_BE <= value) && (value <= WME_AC_VO)) {
                scn->arp_override = value;
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                        WMI_PDEV_PARAM_ARP_AC_OVERRIDE, value);
            } else {
                retval = -EINVAL;
            }
        }
        break;

        case OL_ATH_PARAM_IGMPMLD_OVERRIDE:
            if ((0 == value) || (value == 1)) {
                scn->igmpmld_override = value;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                osif_nss_ol_set_igmpmld_override_tos(scn);
#endif
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_IGMPMLD_OVERRIDE, value);
            } else {
                retval = -EINVAL;
            }
        break;
        case OL_ATH_PARAM_IGMPMLD_TID:
            if ((0 <= value) && (value <= 7)) {
                scn->igmpmld_tid = value;
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                osif_nss_ol_set_igmpmld_override_tos(scn);
#endif
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                    WMI_PDEV_PARAM_IGMPMLD_TID, value);
            } else {
                retval = -EINVAL;
            }
        break;
        case OL_ATH_PARAM_ANI_ENABLE:
        {
                if (value <= 1) {
                    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_ANI_ENABLE, value);
                } else {
                    retval = -EINVAL;
                }
                if (retval == EOK) {
                    if (!value) {
                        scn->is_ani_enable = false;
                    } else {
                        scn->is_ani_enable = true;
                    }
                }
        }
        break;
        case OL_ATH_PARAM_ANI_POLL_PERIOD:
        {
                if (value > 0) {
                    return wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_ANI_POLL_PERIOD, value);
                } else {
                    retval = -EINVAL;
                }
        }
        break;
        case OL_ATH_PARAM_ANI_LISTEN_PERIOD:
        {
                if (value > 0) {
                    return wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_ANI_LISTEN_PERIOD, value);
                } else {
                    retval = -EINVAL;
                }
        }
        break;
        case OL_ATH_PARAM_ANI_OFDM_LEVEL:
        {
                return wmi_unified_pdev_set_param(scn->wmi_handle,
                       WMI_PDEV_PARAM_ANI_OFDM_LEVEL, value);
        }
        break;
        case OL_ATH_PARAM_ANI_CCK_LEVEL:
        {
                return wmi_unified_pdev_set_param(scn->wmi_handle,
                       WMI_PDEV_PARAM_ANI_CCK_LEVEL, value);
        }
        break;
        case OL_ATH_PARAM_BURST_DUR:
        {
                if (value > 0 && value <= 8192) {
                    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_BURST_DUR, value);
                    if (retval == EOK) {
                        scn->burst_dur = (u_int16_t)value;
                    }
                } else {
                    retval = -EINVAL;
                }
        }
        break;

        case OL_ATH_PARAM_BURST_ENABLE:
        {
                if (value == 0 || value ==1) {
                    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_BURST_ENABLE, value);

                    if (retval == EOK) {
                        scn->burst_enable = (u_int8_t)value;
                    }
		    if(!scn->burst_dur)
		    {
			retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_BURST_DUR, 8160);
			if (retval == EOK) {
			    scn->burst_dur = (u_int16_t)value;
			}
		    }
                } else {
                    retval = -EINVAL;
                }
        }
        break;

        case OL_ATH_PARAM_CCA_THRESHOLD:
        {
            if (value > -11) {
                value = -11;
            } else if (value < -94) {
                value = -94;
            }
            if (value) {
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                        WMI_PDEV_PARAM_CCA_THRESHOLD, value);
                if (retval == EOK) {
                    scn->cca_threshold = (u_int16_t)value;
                }
            } else {
                retval = -EINVAL;
            }
        }
        break;

        case OL_ATH_PARAM_DCS:
            {
                value &= OL_ATH_CAP_DCS_MASK;
                if ((value & OL_ATH_CAP_DCS_WLANIM) && !(IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))) {
                    printk("Disabling DCS-WLANIM for 11G mode\n");
                    value &= (~OL_ATH_CAP_DCS_WLANIM);
                }
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) {
                    retval = EOK;
                    break;
                }
                /* if already enabled and run state is not running, more
                 * likely that channel change is in progress, do not let
                 * user modify the current status
                 */
                if ((OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) &&
                        !(OL_IS_DCS_RUNNING(scn->scn_dcs.dcs_enable))) {
                    retval = EINVAL;
                    break;
                }
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                WMI_PDEV_PARAM_DCS, value);

                /*
                 * we do not expect this to fail, if failed, eventually
                 * target and host may not be at agreement. Otherway is
                 * to keep it in same old state.
                 */
                if (EOK == retval) {
                    scn->scn_dcs.dcs_enable = value;
                    printk("DCS: %s dcs enable value %d return value %d", __func__, value, retval );
                } else {
                    printk("DCS: %s target command fail, setting return value %d",
                            __func__, retval );
                }
                (OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable)) ? (OL_ATH_DCS_SET_RUNSTATE(scn->scn_dcs.dcs_enable)) :
                                        (OL_ATH_DCS_CLR_RUNSTATE(scn->scn_dcs.dcs_enable));
            }
            break;
        case OL_ATH_PARAM_DCS_COCH_THR:
            scn->scn_dcs.coch_intr_thresh = value;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_THR:
            scn->scn_dcs.phy_err_threshold = value;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_PENALTY:
            scn->scn_dcs.phy_err_penalty = value;         /* phy error penalty*/
            break;
        case OL_ATH_PARAM_DCS_RADAR_ERR_THR:
            scn->scn_dcs.radar_err_threshold = value;
            break;
        case OL_ATH_PARAM_DCS_USERMAX_CU_THR:
            scn->scn_dcs.user_max_cu = value;             /* tx_cu + rx_cu */
            break;
        case OL_ATH_PARAM_DCS_INTR_DETECT_THR:
            scn->scn_dcs.intr_detection_threshold = value;
            break;
        case OL_ATH_PARAM_DCS_SAMPLE_WINDOW:
            scn->scn_dcs.intr_detection_window = value;
            break;
        case OL_ATH_PARAM_DCS_DEBUG:
            if (value < 0 || value > 2) {
                printk("0-disable, 1-critical 2-all, %d-not valid option\n", value);
                return -EINVAL;
            }
            scn->scn_dcs.dcs_debug = value;
            break;

        case OL_ATH_PARAM_DYN_TX_CHAINMASK:
            /****************************************
             *Value definition:
             * bit 0        dynamic TXCHAIN
             * bit 1        single TXCHAIN
             * bit 2        single TXCHAIN for ctrl frames
             * For bit 0-1, if value =
             * 0x1  ==>   Dyntxchain enabled,  single_txchain disabled
             * 0x2  ==>   Dyntxchain disabled, single_txchain enabled
             * 0x3  ==>   Both enabled
             * 0x0  ==>   Both disabled
             *
             * bit 3-7      reserved
             * bit 8-11     single txchain mask, only valid if bit 1 set
             *
             * For bit 8-11, the single txchain mask for this radio,
             * only valid if single_txchain enabled, by setting bit 1.
             * Single txchain mask need to be updated when txchainmask,
             * is changed, e.g. 4x4(0xf) ==> 3x3(0x7)
             ****************************************/
#define DYN_TXCHAIN         0x1
#define SINGLE_TXCHAIN      0x2
#define SINGLE_TXCHAIN_CTL  0x4
            if( (value & SINGLE_TXCHAIN) ||
                     (value & SINGLE_TXCHAIN_CTL) ){
                value &= 0xf07;
            }else{
                value &= 0x1;
            }

            if (scn->dtcs != value) {
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_DYNTXCHAIN, value);
                if (retval == EOK) {
                    scn->dtcs = value;
                }
            }
        break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
		case OL_ATH_PARAM_BUFF_THRESH:
			thresh = value;
			if((thresh >= MIN_BUFF_LEVEL_IN_PERCENT) && (thresh<=100))
			{
				scn->buff_thresh.ald_free_buf_lvl = scn->buff_thresh.pool_size - ((scn->buff_thresh.pool_size * thresh) / 100);
				printk("Buff Warning Level=%d\n", (scn->buff_thresh.pool_size - scn->buff_thresh.ald_free_buf_lvl));
			} else {
                printk("ERR: Buff Thresh(in %%) should be >=%d and <=100\n", MIN_BUFF_LEVEL_IN_PERCENT);
            }
			break;
		case OL_ATH_PARAM_DROP_STA_QUERY:
			ic->ic_dropstaquery = !!value;
			break;
		case OL_ATH_PARAM_BLK_REPORT_FLOOD:
			ic->ic_blkreportflood = !!value;
			break;
#endif

        case OL_ATH_PARAM_VOW_EXT_STATS:
            {
                scn->vow_extstats = value;
            }
            break;

        case OL_ATH_PARAM_LTR_ENABLE:
            param_id = WMI_PDEV_PARAM_LTR_ENABLE;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_BE:
            param_id = WMI_PDEV_PARAM_LTR_AC_LATENCY_BE;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_BK:
            param_id = WMI_PDEV_PARAM_LTR_AC_LATENCY_BK;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_VI:
            param_id = WMI_PDEV_PARAM_LTR_AC_LATENCY_VI;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_VO:
            param_id = WMI_PDEV_PARAM_LTR_AC_LATENCY_VO;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_AC_LATENCY_TIMEOUT:
            param_id = WMI_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_TX_ACTIVITY_TIMEOUT:
            param_id = WMI_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_SLEEP_OVERRIDE:
            param_id = WMI_PDEV_PARAM_LTR_SLEEP_OVERRIDE;
            goto low_power_config;
        case OL_ATH_PARAM_LTR_RX_OVERRIDE:
            param_id = WMI_PDEV_PARAM_LTR_RX_OVERRIDE;
            goto low_power_config;
        case OL_ATH_PARAM_L1SS_ENABLE:
            param_id = WMI_PDEV_PARAM_L1SS_ENABLE;
            goto low_power_config;
        case OL_ATH_PARAM_DSLEEP_ENABLE:
            param_id = WMI_PDEV_PARAM_DSLEEP_ENABLE;
            goto low_power_config;
low_power_config:
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                         param_id, value);
        case OL_ATH_PARAM_ACS_CTRLFLAG:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_CTRLFLAG , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_ENABLE_BK_SCANTIMEREN:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_ENABLE_BK_SCANTIMER , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_SCANTIME:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_SCANTIME , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_RSSIVAR:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_RSSIVAR , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_CHLOADVAR:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_CHLOADVAR , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_LIMITEDOBSS:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_LIMITEDOBSS , *(int *)buff);
            }
            break;
        case OL_ATH_PARAM_ACS_DEBUGTRACE:
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_DEBUGTRACE , *(int *)buff);
            }
             break;
#if ATH_CHANNEL_BLOCKING
        case OL_ATH_PARAM_ACS_BLOCK_MODE:
            if (ic->ic_acs) {
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_BLOCK_MODE , *(int *)buff);
            }
            break;
#endif
        case OL_ATH_PARAM_RESET_OL_STATS:
            ol_ath_reset_vap_stat(ic);
            break;
#if ATH_RX_LOOPLIMIT_TIMER
        case OL_ATH_PARAM_LOOPLIMIT_NUM:
            if (*(int *)buff > 0)
                scn->rx_looplimit_timeout = *(int *)buff;
            break;
#endif
#define ANTENNA_GAIN_2G_MASK    0x0
#define ANTENNA_GAIN_5G_MASK    0x8000
        case OL_ATH_PARAM_ANTENNA_GAIN_2G:
            if (value >= 0 && value <= 30) {
                return wmi_unified_pdev_set_param(scn->wmi_handle,
                         WMI_PDEV_PARAM_ANTENNA_GAIN, value | ANTENNA_GAIN_2G_MASK);
            } else {
                retval = -EINVAL;
            }
            break;
        case OL_ATH_PARAM_ANTENNA_GAIN_5G:
            if (value >= 0 && value <= 30) {
                return wmi_unified_pdev_set_param(scn->wmi_handle,
                         WMI_PDEV_PARAM_ANTENNA_GAIN, value | ANTENNA_GAIN_5G_MASK);
            } else {
                retval = -EINVAL;
            }
            break;
        case OL_ATH_PARAM_RX_FILTER:
            if (ic->ic_set_rxfilter)
                ic->ic_set_rxfilter(ic, value);
            else
                retval = -EINVAL;
            break;
       case OL_ATH_PARAM_SET_FW_HANG_ID:
            wmi_unified_pdev_set_fw_hang(scn->wmi_handle, value);
            break;
       case OL_ATH_PARAM_FW_RECOVERY_ID:
            if (value == 1)
	        scn->recovery_enable = TRUE;
            else if (value == 0)
                scn->recovery_enable = FALSE;
            else
                printk("Please enter: 1 = Enable & 0 = Disable\n");
            break;
       case OL_ATH_PARAM_FW_DUMP_NO_HOST_CRASH:
            if (value == 1){
                /* Do not crash host when target assert happened */
                /* By default, host will crash when target assert happened */
                scn->sc_dump_opts |= FW_DUMP_NO_HOST_CRASH;
            }else{
                scn->sc_dump_opts &= ~FW_DUMP_NO_HOST_CRASH;
            }
            break;
       case OL_ATH_PARAM_DISABLE_DFS:
            {
                if (!value)
                    scn->sc_is_blockdfs_set = false;
                else
                    scn->sc_is_blockdfs_set = true;
            }
            break;
        case OL_ATH_PARAM_QBOOST:
            {
		        if (!ic->ic_qboost_support)
                    return -EINVAL;
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == scn->scn_qboost_enable) {
                    retval = EOK;
                    break;
                }

                    scn->scn_qboost_enable = value;

                    printk("QBOOST: %s qboost value %d\n", __func__, value);
            }
            break;
        case OL_ATH_PARAM_SIFS_FRMTYPE:
            {
		        if (!ic->ic_sifs_frame_support)
                    return -EINVAL;
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == scn->scn_sifs_frmtype) {
                    retval = EOK;
                    break;
                }

                    scn->scn_sifs_frmtype = value;

                    printk("SIFS RESP FRMTYPE: %s SIFS  value %d\n", __func__, value);
            }
            break;
        case OL_ATH_PARAM_SIFS_UAPSD:
            {
		        if (!ic->ic_sifs_frame_support)
                    return -EINVAL;
                /*
                 * Host and target should always contain the same value. So
                 * avoid talking to target if the values are same.
                 */
                if (value == scn->scn_sifs_uapsd) {
                    retval = EOK;
                    break;
                }

                    scn->scn_sifs_uapsd = value;

                    printk("SIFS RESP UAPSD: %s SIFS  value %d\n", __func__, value);
            }
            break;
        case OL_ATH_PARAM_BLOCK_INTERBSS:
            {
		        if (!ic->ic_block_interbss_support)
                    return -EINVAL;

                if (value == scn->scn_block_interbss) {
                    retval = EOK;
                    break;
                }
		/* send the WMI command to enable and if that is success update the state */
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                WMI_PDEV_PARAM_BLOCK_INTERBSS, value);

                /*
                 * we do not expect this to fail, if failed, eventually
                 * target and host may not be in agreement. Otherway is
                 * to keep it in same old state.
                 */
                if (EOK == retval) {
                    scn->scn_block_interbss = value;
                    printk("set block_interbss: value %d wmi_status %d\n", value, retval );
                } else {
                    printk("set block_interbss: wmi failed. retval = %d\n", retval );
                }
	    }
        break;
        case OL_ATH_PARAM_FW_DISABLE_RESET:
        {
		        if (!ic->ic_disable_reset_support)
                    return -EINVAL;
                /* value is set to either 1 (enable) or 0 (disable).
                 * if value passed is non-zero, convert it to 1 with
                 * double negation
                 */
                value = !!value;
                if (scn->fw_disable_reset != (u_int8_t)value) {
                    retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_SET_DISABLE_RESET_CMDID, value);
                    if (retval == EOK) {
                        scn->fw_disable_reset = (u_int8_t)value;
                    }
                }
        }
        break;
        case OL_ATH_PARAM_MSDU_TTL:
        {
		    if (!ic->ic_msdu_ttl_support)
                return -EINVAL;
            /* value is set to 0 (disable) else set msdu_ttl in ms.
             */
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_SET_MSDU_TTL_CMDID, value);
            if (retval == EOK) {
                printk("set MSDU_TTL: value %d wmi_status %d\n", value, retval );
            } else {
                printk("set MSDU_TTL wmi_failed: wmi_status %d\n", retval );
            }
#if PEER_FLOW_CONTROL
            /* update host msdu ttl */
            ol_pflow_update_pdev_params(scn->pdev_txrx_handle, param, value, NULL);
#endif
        }
        break;
        case OL_ATH_PARAM_PPDU_DURATION:
        {
		    if (!ic->ic_ppdu_duration_support)
                return -EINVAL;
            /* Set global PPDU duration in usecs.
             */
	    if(value < 100 || value > 4000)
		return -EINVAL;
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_SET_PPDU_DURATION_CMDID, value);
            if (retval == EOK) {
                printk("set PPDU_DURATION: value %d wmi_status %d\n", value, retval );
            } else {
                printk("set PPDU_DURATION: wmi_failed: wmi_status %d\n", retval );
            }
        }
        break;

        case OL_ATH_PARAM_SET_TXBF_SND_PERIOD:
        {
            /* Set global TXBF sounding duration in usecs.
             */
            if(value < 10 || value > 10000)
                return -EINVAL;
            scn->txbf_sound_period = value;
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_TXBF_SOUND_PERIOD_CMDID, value);
            if (retval == EOK) {
                printk("set TXBF_SND_PERIOD: value %d wmi_status %d\n", value, retval );
            } else {
                printk("set TXBF_SND_PERIOD: wmi_failed: wmi_status %d\n", retval );
            }
        }
        break;

        case OL_ATH_PARAM_ALLOW_PROMISC:
        {
	    if (!ic->ic_promisc_support)
                return -EINVAL;
            /* Set or clear promisc mode.
             */
            if (promisc_is_active(&scn->sc_ic)) {
                printk("Device have an active monitor vap\n");
                retval = -EINVAL;
            } else if (value == scn->scn_promisc) {
                retval = EOK;
            } else {
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_SET_PROMISC_MODE_CMDID, value);
                if (retval == EOK) {
                    scn->scn_promisc = value;
                    printk("set PROMISC_MODE: value %d wmi_status %d\n", value, retval );
                } else {
                    printk("set PROMISC_MODE: wmi_failed: wmi_status %d\n", retval );
                }
            }
        }
        break;

        case OL_ATH_PARAM_BURST_MODE:
        {
		    if (!ic->ic_burst_mode_support)
                return -EINVAL;
            /* Set global Burst mode data-cts:0 data-ping-pong:1 data-cts-ping-pong:2.
             */
	    if(value < 0 || value > 3) {
                printk("Usage: burst_mode <0:data-cts 1:data-data 2:data-(data/cts)\n");
		return -EINVAL;
            }

            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_SET_BURST_MODE_CMDID, value);
            if (retval == EOK) {
                printk("set BURST_MODE: value %d wmi_status %d\n", value, retval );
            } else {
                printk("set BURST_MODE: wmi_failed: wmi_status %d\n", retval );
            }
        }
        break;

#if ATH_SUPPORT_WRAP
         case OL_ATH_PARAM_MCAST_BCAST_ECHO:
        {
            /* Set global Burst mode data-cts:0 data-ping-pong:1 data-cts-ping-pong:2.
             */
            if(value < 0 || value > 1) {
                printk("Usage: Mcast Bcast Echo mode usage  <0:disable 1:enable \n");
                return -EINVAL;
            }

            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                 WMI_PDEV_PARAM_SET_MCAST_BCAST_ECHO, value);
            if (retval == EOK) {
                printk("set : Mcast Bcast Echo value %d wmi_status %d\n", value, retval );
                scn->mcast_bcast_echo = (u_int8_t)value;
            } else {
                printk("set : Mcast Bcast Echo mode wmi_failed: wmi_status %d\n", retval );
            }
        }
        break;
#endif
         case OL_ATH_PARAM_OBSS_RSSI_THRESHOLD:
        {
            if (value >= OBSS_RSSI_MIN && value <= OBSS_RSSI_MAX) {
                ic->obss_rssi_threshold = value;
            } else {
                retval = -EINVAL;
            }
        }
        break;
         case OL_ATH_PARAM_OBSS_RX_RSSI_THRESHOLD:
        {
            if (value >= OBSS_RSSI_MIN && value <= OBSS_RSSI_MAX) {
                ic->obss_rx_rssi_threshold = value;
            } else {
                retval = -EINVAL;
            }
        }
        break;
        case OL_ATH_PARAM_ACS_TX_POWER_OPTION:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_TX_POWER_OPTION, *(int *)buff);
            }
        }
        break;

        case OL_ATH_PARAM_ACS_2G_ALLCHAN:
        {
            if(ic->ic_acs){
                ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_2G_ALL_CHAN, *(int *)buff);
            }
        }
        break;
        case OL_ATH_PARAM_ANT_POLARIZATION:
        {
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                          WMI_PDEV_PARAM_ANT_PLZN, value);
        }
        break;

         case OL_ATH_PARAM_ENABLE_AMSDU:
        {

            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                  WMI_PDEV_PARAM_ENABLE_PER_TID_AMSDU, value);
            if (retval == EOK) {
                printk("enable AMSDU: value %d wmi_status %d\n", value, retval );
                scn->scn_amsdu_mask = value;
            } else {
                printk("enable AMSDU: wmi_failed: wmi_status %d\n", retval );
            }
        }
        break;

        case OL_ATH_PARAM_ENABLE_AMPDU:
        {

            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                                   WMI_PDEV_PARAM_ENABLE_PER_TID_AMPDU, value);
            if (retval == EOK) {
                printk("enable AMPDU: value %d wmi_status %d\n", value, retval );
                scn->scn_ampdu_mask = value;
            } else {
                printk("enable AMPDU: wmi_failed: wmi_status %d\n", retval );
            }
        }
        break;

       case OL_ATH_PARAM_PRINT_RATE_LIMIT:

        if (value <= 0) {
            retval = -EINVAL;
        } else {
            scn->dbg.print_rate_limit = value;
            printk("Changing rate limit to: %d \n", scn->dbg.print_rate_limit);
        }
        break;

        case OL_ATH_PARAM_PDEV_RESET:
        {
                if ( (value > 0) && (value < 6)) {
                    return wmi_unified_pdev_set_param(scn->wmi_handle,
                             WMI_PDEV_PARAM_PDEV_RESET, value);
                } else {
                    printk(" Invalid vaue : Use any one of the below values \n"
                        "    TX_FLUSH = 1 \n"
                        "    WARM_RESET = 2 \n"
                        "    COLD_RESET = 3 \n"
                        "    WARM_RESET_RESTORE_CAL = 4 \n"
                        "    COLD_RESET_RESTORE_CAL = 5 \n");
                    retval = -EINVAL;
                }
        }
        break;

        case OL_ATH_PARAM_CONSIDER_OBSS_NON_ERP_LONG_SLOT:
        {
            ic->ic_consider_obss_long_slot = !!value;
        }

        break;

#if PEER_FLOW_CONTROL
         case OL_ATH_PARAM_QFLUSHINTERVAL:
         case OL_ATH_PARAM_TOTAL_Q_SIZE:
         case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE0:
         case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE1:
         case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE2:
         case OL_ATH_PARAM_TOTAL_Q_SIZE_RANGE3:
         case OL_ATH_PARAM_MIN_THRESHOLD:
         case OL_ATH_PARAM_MAX_Q_LIMIT:
         case OL_ATH_PARAM_MIN_Q_LIMIT:
         case OL_ATH_PARAM_CONG_CTRL_TIMER_INTV:
         case OL_ATH_PARAM_STATS_TIMER_INTV:
         case OL_ATH_PARAM_ROTTING_TIMER_INTV:
         case OL_ATH_PARAM_LATENCY_PROFILE:
         case OL_ATH_PARAM_HOSTQ_DUMP:
         case OL_ATH_PARAM_TIDQ_MAP:
        {
            ol_pflow_update_pdev_params(scn->pdev_txrx_handle, param, value, NULL);
        }
        break;
#endif
        /* The variable 'value' will be a 2 byte integer, first 8 bits will hold frame
         * subtype and last 8 bits will hold the tx power */
         case OL_ATH_PARAM_TXPOW_MGMT:
        {
            retval = EOK;
            if ((value >> 8) == IEEE80211_FC0_SUBTYPE_BEACON) {
                transmit_power = (value &  0xFF);
                retval = wmi_txpower_beacon(scn->wmi_handle,transmit_power,scn->pdev_txrx_handle);

                if (retval != EOK) {
                    printk("set TX Power for beacon  wmi_failed: wmi_status %d\n", retval );
                }
            }
            if (retval == EOK)
                ol_update_txpow_pdev(scn->pdev_txrx_handle, value, NULL);
        }
        break;
        case OL_ATH_PARAM_DBG_ARP_SRC_ADDR:
        {
            scn->sc_arp_dbg_srcaddr = value;
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                         WMI_PDEV_PARAM_ARP_SRCADDR,
                         scn->sc_arp_dbg_srcaddr);
            if (retval != EOK) {
                printk("Failed to set ARP DEBUG SRC addr in firmware \r\n");
            }
        }
        break;

        case OL_ATH_PARAM_DBG_ARP_DST_ADDR:
        {
            scn->sc_arp_dbg_dstaddr = value;
            retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                         WMI_PDEV_PARAM_ARP_DSTADDR,
                         scn->sc_arp_dbg_dstaddr);
            if (retval != EOK) {
                printk("Failed to set ARP DEBUG DEST addr in firmware \r\n");
            }
        }
        break;

        case OL_ATH_PARAM_ARP_DBG_CONF:
        {
#define ARP_RESET 0xff000000
            if (value & ARP_RESET) {
                /* Reset stats */
                scn->sc_tx_arp_req_count = 0;
                scn->sc_rx_arp_req_count = 0;
            } else {
                scn->sc_arp_dbg_conf = value;
            }
#undef ARP_RESET
        }
        break;
            /* Disable AMSDU for Station vap */
        case OL_ATH_PARAM_DISABLE_STA_VAP_AMSDU:
        {
            ic->ic_sta_vap_amsdu_disable = value;
        }
        break;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        case OL_ATH_PARAM_STADFS_ENABLE:
            if(!value) {
                ieee80211com_clear_cap_ext(ic,IEEE80211_CEXT_STADFS);
            } else {
                ieee80211com_set_cap_ext(ic,IEEE80211_CEXT_STADFS);
            }
            break;
#endif
        case OL_ATH_PARAM_CHANSWITCH_OPTIONS:
            ic->ic_chanswitch_flags = (*(int *)buff);
            /* When TxCSA is set to 1, Repeater CAC(IEEE80211_CSH_OPT_CAC_APUP_BYSTA)
             * will be forced to 1. Because, the TXCSA is done by changing channel in
             * the beacon update function(ieee80211_beacon_update) and AP VAPs change
             * the channel, if the new channel is DFS then AP VAPs do CAC and STA VAP
             * has to synchronize with the AP VAPS' CAC.
             */
            if (IEEE80211_IS_CSH_CSA_APUP_BYSTA_ENABLED(ic)) {
                IEEE80211_CSH_CAC_APUP_BYSTA_ENABLE(ic);
                adf_os_print("%s: When TXCSA is set to 1, Repeater CAC is forced to 1\n", __func__);
            }
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_PRIMARY_RADIO:
            if(!ic->ic_sta_vap) {
                printk("Primary radio config is applicable only for repeater mode \n");
                retval = -EINVAL;
                break;
            }
            for (i=0; i < MAX_RADIO_CNT; i++) {
                GLOBAL_IC_LOCK(ic->ic_global_list);
                other_ic = ic->ic_global_list->global_ic[i];
                GLOBAL_IC_UNLOCK(ic->ic_global_list);
                if (other_ic) {
                    spin_lock(&other_ic->ic_lock);
                    if (ic == other_ic) {
                        other_ic->ic_primary_radio = (value) ?1:0;
                    } else {
                        other_ic->ic_primary_radio = (value) ?0:1;
                    }
#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
                    osif_nss_ol_set_primary_radio(other_ic, other_ic->ic_primary_radio);
#endif
                    spin_unlock(&other_ic->ic_lock);
                }
            }
            break;
        case OL_ATH_PARAM_DBDC_ENABLE:
            GLOBAL_IC_LOCK(ic->ic_global_list);
            ic->ic_global_list->dbdc_process_enable = (value) ?1:0;
            GLOBAL_IC_UNLOCK(ic->ic_global_list);

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            for (i = 0; i < MAX_RADIO_CNT; i++) {
                tmp_ic = ic->ic_global_list->global_ic[i];
                if (tmp_ic) {
                    spin_lock(&tmp_ic->ic_lock);
                    if (value) {
                        if (tmp_ic->ic_global_list->num_stavaps_up > 1) {
                            osif_nss_ol_enable_dbdc_process(tmp_ic, value);
                        }
                    } else {
                        osif_nss_ol_enable_dbdc_process(tmp_ic, 0);
                    }
                    spin_unlock(&tmp_ic->ic_lock);
                }
            }
#endif
            break;
        case OL_ATH_PARAM_CLIENT_MCAST:
            GLOBAL_IC_LOCK(ic->ic_global_list);
            if(value) {
                ic->ic_global_list->force_client_mcast_traffic = 1;
                printk("Enabling MCAST client traffic to go on corresponding STA VAP\n");
            } else {
                ic->ic_global_list->force_client_mcast_traffic = 0;
                printk("Disabling MCAST client traffic to go on corresponding STA VAP\n");
            }

#ifdef QCA_NSS_WIFI_OFFLOAD_SUPPORT
            for (i = 0; i < MAX_RADIO_CNT; i++) {
                tmp_ic = ic->ic_global_list->global_ic[i];
                if (tmp_ic) {
                    osif_nss_ol_set_force_client_mcast_traffic(tmp_ic);
                }
            }
#endif
            GLOBAL_IC_UNLOCK(ic->ic_global_list);
            break;
#endif
        case OL_ATH_PARAM_TXPOWER_DBSCALE:
            {
                retval = wmi_unified_pdev_set_param(scn->wmi_handle,
                        WMI_PDEV_PARAM_TXPOWER_DECR_DB, value);
            }
            break;
        case OL_ATH_PARAM_CTL_POWER_SCALE:
            {
                if((WMI_TP_SCALE_MAX <= value) && (value <= WMI_TP_SCALE_MIN))
                {
                    scn->powerscale = value;
                    return wmi_unified_pdev_set_param(scn->wmi_handle,
                            WMI_PDEV_PARAM_CUST_TXPOWER_SCALE, value);
                } else {
                    retval = -EINVAL;
                }
            }
            break;

#ifdef QCA_EMIWAR_80P80_CONFIG_SUPPORT
        case OL_ATH_PARAM_EMIWAR_80P80:
            {
                IEEE80211_COUNTRY_ENTRY    cval;

                if (IS_EMIWAR_80P80_APPLICABLE(scn)) {
                    if ((value >= EMIWAR_80P80_DISABLE) && (value < EMIWAR_80P80_MAX)) {
                        (scn->sc_ic).ic_emiwar_80p80 = value;
                        printk("Re-applying current country code.\n");
                        ic->ic_get_currentCountry(ic, &cval);
                        retval = wlan_set_countrycode(&scn->sc_ic, NULL, cval.countryCode, CLIST_NEW_COUNTRY);
                        /*Using set country code for re-usability and non-duplication of INIT code */
                    }
                    else {
                        printk(" Please enter 0:Disable, 1:BandEdge (FC1:5775, and FC2:5210), 2:All FC1>FC2\n");
                        retval = -EINVAL;
                    }
                }
                else {
                    printk("emiwar80p80 not applicable for this chipset \n");

                }
            }
            break;
#endif /*QCA_EMIWAR_80P80_CONFIG_SUPPORT*/
        case OL_ATH_PARAM_BATCHMODE:
            return wmi_unified_pdev_set_param(scn->wmi_handle,
                         WMI_PDEV_PARAM_RX_BATCHMODE, !!value);
            break;
        case OL_ATH_PARAM_PACK_AGGR_DELAY:
            return wmi_unified_pdev_set_param(scn->wmi_handle,
                         WMI_PDEV_PARAM_PACKET_AGGR_DELAY, !!value);
            break;
#if UMAC_SUPPORT_ACFG
        case OL_ATH_PARAM_DIAG_ENABLE:
            if (value == 0 || value == 1) {
                if (value && !ic->ic_diag_enable) {
                    acfg_diag_pvt_t *diag = (acfg_diag_pvt_t *)ic->ic_diag_handle;
                    if (diag) {
                        ic->ic_diag_enable = value;
                        OS_SET_TIMER(&diag->diag_timer, 0);
                    }
                }else if (!value) {
                    ic->ic_diag_enable = value;
                }
            } else {
                printk("Please enter 0 or 1.\n");
                retval = -EINVAL;
            }
            break;
#endif /* UMAC_SUPPORT_ACFG */

        case OL_ATH_PARAM_CHAN_STATS_TH:
            ic->ic_chan_stats_th = (value % 100);
            break;

        case OL_ATH_PARAM_PASSIVE_SCAN_ENABLE:
            ic->ic_strict_pscan_enable = !!value;
            break;

        case OL_ATH_MIN_RSSI_ENABLE:
            {
                if (value == 0 || value == 1) {
                    if (value)
                        ic->ic_min_rssi_enable = true;
                    else
                        ic->ic_min_rssi_enable = false;
               } else {
                   printk("Please enter 0 or 1.\n");
                   retval = -EINVAL;
               }
            }
            break;
        case OL_ATH_MIN_RSSI:
            {
                int val = *(int *)buff;
                if (val <= 0) {
                    printk("snr should be a positive value.\n");
                    retval = -EINVAL;
                } else if (ic->ic_min_rssi_enable)
                    ic->ic_min_rssi = val;
                else
                    printk("Cannot set, feature not enabled.\n");
            }
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_DELAY_STAVAP_UP:
            GLOBAL_IC_LOCK(ic->ic_global_list);
            if(value) {
                ic->ic_global_list->delay_stavap_connection = 1;
                printk("Enabling DELAY_STAVAP_UP\n");
            } else {
                ic->ic_global_list->delay_stavap_connection = 0;
                printk("Disabling DELAY_STAVAP_UP\n");
            }
            GLOBAL_IC_UNLOCK(ic->ic_global_list);
            break;
#endif
        case OL_ATH_BTCOEX_ENABLE:
            {
                int val = !!(*((int *) buff));

                if (scn->btcoex_support) {
                    if (wmi_unified_pdev_set_param(scn->wmi_handle, WMI_PDEV_PARAM_ENABLE_BTCOEX, val) == EOK) {
                        scn->btcoex_enable = val;
                    }
                } else {
                    retval = -EPERM;
                }
            }
            break;
        case OL_ATH_BTCOEX_WL_PRIORITY:
            {
                int val = *((int *) buff);
                wmi_buf_t buf;
                wmi_btcoex_cfg_cmd *cmd;
                int len = sizeof(wmi_btcoex_cfg_cmd);

                if (scn->btcoex_support) {
                    buf = wmi_buf_alloc(scn->wmi_handle, len);
                    if (buf) {
                        cmd = (wmi_btcoex_cfg_cmd *) wmi_buf_data(buf);
                        cmd->btcoex_wlan_priority_bitmap = val;

                        if (wmi_unified_cmd_send(scn->wmi_handle, buf, len, WMI_BTCOEX_CFG_CMDID) == EOK) {
                            scn->btcoex_wl_priority = val;
                        }
                    } else {
                        return -ENOMEM;
                    }
                } else {
                    retval = -EPERM;
                }
            }
            break;
        case OL_ATH_PARAM_CAL_VER_CHECK:
            {
                if(scn->sw_cal_support_check_flag == 1) {
                    if(value == 0 || value == 1) {
                        ic->ic_cal_ver_check = value;
                        retval = wmi_unified_pdev_caldata_version_check_cmd(scn->wmi_handle, value);
                    } else {
                        adf_os_print("Enter value 0 or 1. \n");
                        retval = -EINVAL;
                    }
                } else {
                    adf_os_print(" wmi service to check cal version not supported \n");
                }
            }
            break;
        case OL_ATH_PARAM_TID_OVERRIDE_QUEUE_MAPPING:
            ol_pdev_set_tid_override_queue_mapping(scn->pdev_txrx_handle, value);
            break;
        case OL_ATH_PARAM_NO_VLAN:
            ic->ic_no_vlan = !!value;
            break;
        default:
            return (-1);
    }
    return retval;
}

int
ol_ath_get_config_param(struct ol_ath_softc_net80211 *scn, ol_ath_param_t param, void *buff)
{
    int retval = 0;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS || PEER_FLOW_CONTROL
	u_int32_t value = *(u_int32_t *)buff;
#endif
    int *txpow_frm_subtype = (int *)buff;
    struct ieee80211com *ic = &scn->sc_ic;

    switch(param)
    {
        case OL_ATH_PARAM_GET_IF_ID:
            *(int *)buff = IF_ID_OFFLOAD;
            break;

        case OL_ATH_PARAM_TXCHAINMASK:
            *(int *)buff = ieee80211com_get_tx_chainmask(ic);
            break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS || ATH_SUPPORT_DSCP_OVERRIDE
        case OL_ATH_PARAM_HMMC_DSCP_TID_MAP:
            *(int *)buff = ol_ath_get_hmmc_tid(ic);
            break;

        case OL_ATH_PARAM_HMMC_DSCP_OVERRIDE:
            *(int *)buff = ol_ath_get_hmmc_dscp_override(ic);
            break;
#endif
        case OL_ATH_PARAM_RXCHAINMASK:
            *(int *)buff = ieee80211com_get_rx_chainmask(ic);
            break;
        case OL_ATH_PARAM_DYN_GROUPING:
            *(int *)buff = scn->dyngroup;
            break;
        case OL_ATH_PARAM_BCN_BURST:
            *(int *)buff = scn->bcn_mode;
            break;
        case OL_ATH_PARAM_DPD_ENABLE:
            *(int *)buff = scn->dpdenable;
            break;
        case OL_ATH_PARAM_ARPDHCP_AC_OVERRIDE:
            *(int *)buff = scn->arp_override;
            break;
        case OL_ATH_PARAM_IGMPMLD_OVERRIDE:
            *(int *)buff = scn->igmpmld_override;
            break;
        case OL_ATH_PARAM_IGMPMLD_TID:
            *(int *)buff = scn->igmpmld_tid;
            break;

        case OL_ATH_PARAM_TXPOWER_LIMIT2G:
            *(int *)buff = scn->txpowlimit2G;
            break;

        case OL_ATH_PARAM_TXPOWER_LIMIT5G:
            *(int *)buff = scn->txpowlimit5G;
            break;

        case OL_ATH_PARAM_TXPOWER_SCALE:
            *(int *)buff = scn->txpower_scale;
            break;
        case OL_ATH_PARAM_RTS_CTS_RATE:
            *(int *)buff =  scn->ol_rts_cts_rate;
            break;
        case OL_ATH_PARAM_DEAUTH_COUNT:
            *(int *)buff =  scn->scn_user_peer_invalid_cnt;;
            break;
        case OL_ATH_PARAM_DYN_TX_CHAINMASK:
            *(int *)buff = scn->dtcs;
            break;
        case OL_ATH_PARAM_VOW_EXT_STATS:
            *(int *)buff = scn->vow_extstats;
            break;
        case OL_ATH_PARAM_DCS:
            /* do not need to talk to target */
            *(int *)buff = OL_IS_DCS_ENABLED(scn->scn_dcs.dcs_enable);
            break;
        case OL_ATH_PARAM_DCS_COCH_THR:
            *(int *)buff = scn->scn_dcs.coch_intr_thresh ;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_THR:
            *(int *)buff = scn->scn_dcs.phy_err_threshold ;
            break;
        case OL_ATH_PARAM_DCS_PHYERR_PENALTY:
            *(int *)buff = scn->scn_dcs.phy_err_penalty ;
            break;
        case OL_ATH_PARAM_DCS_RADAR_ERR_THR:
            *(int *)buff = scn->scn_dcs.radar_err_threshold ;
            break;
        case OL_ATH_PARAM_DCS_USERMAX_CU_THR:
            *(int *)buff = scn->scn_dcs.user_max_cu ;
            break;
        case OL_ATH_PARAM_DCS_INTR_DETECT_THR:
            *(int *)buff = scn->scn_dcs.intr_detection_threshold ;
            break;
        case OL_ATH_PARAM_DCS_SAMPLE_WINDOW:
            *(int *)buff = scn->scn_dcs.intr_detection_window ;
            break;
        case OL_ATH_PARAM_DCS_DEBUG:
            *(int *)buff = scn->scn_dcs.dcs_debug ;
            break;
#if ATH_SUPPORT_HYFI_ENHANCEMENTS
        case OL_ATH_PARAM_BUFF_THRESH:
            *(int *)buff = scn->buff_thresh.pool_size - scn->buff_thresh.ald_free_buf_lvl;
            break;
        case OL_ATH_PARAM_BLK_REPORT_FLOOD:
            *(int *)buff = ic->ic_blkreportflood;
            break;
        case OL_ATH_PARAM_DROP_STA_QUERY:
            *(int *)buff = ic->ic_dropstaquery;
            break;
#endif
        case OL_ATH_PARAM_BURST_ENABLE:
            *(int *)buff = scn->burst_enable;
            break;
        case OL_ATH_PARAM_CCA_THRESHOLD:
            *(int *)buff = scn->cca_threshold;
            break;
        case OL_ATH_PARAM_BURST_DUR:
            *(int *)buff = scn->burst_dur;
            break;
        case OL_ATH_PARAM_ANI_ENABLE:
            *(int *)buff =  (scn->is_ani_enable == true);
            break;
        case OL_ATH_PARAM_ACS_CTRLFLAG:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_CTRLFLAG );
            }
            break;
        case OL_ATH_PARAM_ACS_ENABLE_BK_SCANTIMEREN:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_ENABLE_BK_SCANTIMER );
            }
            break;
        case OL_ATH_PARAM_ACS_SCANTIME:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_SCANTIME );
            }
            break;
        case OL_ATH_PARAM_ACS_RSSIVAR:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_RSSIVAR );
            }
            break;
        case OL_ATH_PARAM_ACS_CHLOADVAR:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_CHLOADVAR );
            }
            break;
        case OL_ATH_PARAM_ACS_LIMITEDOBSS:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_LIMITEDOBSS);
            }
            break;
        case OL_ATH_PARAM_ACS_DEBUGTRACE:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_DEBUGTRACE);
            }
            break;
#if ATH_CHANNEL_BLOCKING
        case OL_ATH_PARAM_ACS_BLOCK_MODE:
            if (ic->ic_acs) {
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_BLOCK_MODE);
            }
            break;
#endif
        case OL_ATH_PARAM_RESET_OL_STATS:
            ol_ath_reset_vap_stat(ic);
            break;
        case OL_ATH_PARAM_TOTAL_PER:
            *(int *)buff =
                ol_ath_net80211_get_total_per(ic);
            break;
#if ATH_RX_LOOPLIMIT_TIMER
        case OL_ATH_PARAM_LOOPLIMIT_NUM:
            *(int *)buff = scn->rx_looplimit_timeout;
            break;
#endif
        case OL_ATH_PARAM_RADIO_TYPE:
            *(int *)buff = ic->ic_is_mode_offload(ic);
            break;

        case OL_ATH_PARAM_FW_RECOVERY_ID:
            *(int *)buff = scn->recovery_enable;
            break;
        case OL_ATH_PARAM_FW_DUMP_NO_HOST_CRASH:
            *(int *)buff = (scn->sc_dump_opts & FW_DUMP_NO_HOST_CRASH ? 1: 0);
            break;
        case OL_ATH_PARAM_DISABLE_DFS:
            *(int *)buff =	(scn->sc_is_blockdfs_set == true);
            break;
        case OL_ATH_PARAM_PS_STATE_CHANGE:
            {
                *(int *) buff =  scn->ps_report ;
            }
            break;
        case OL_ATH_PARAM_BLOCK_INTERBSS:
            *(int*)buff = scn->scn_block_interbss;
            break;
        case OL_ATH_PARAM_SET_TXBF_SND_PERIOD:
            printk("\n scn->txbf_sound_period hex %x %d\n", scn->txbf_sound_period, scn->txbf_sound_period);
            *(int*)buff = scn->txbf_sound_period;
            break;
#if ATH_SUPPORT_WRAP
        case OL_ATH_PARAM_MCAST_BCAST_ECHO:
            *(int*)buff = scn->mcast_bcast_echo;
            break;
#endif
        case OL_ATH_PARAM_OBSS_RSSI_THRESHOLD:
            {
                *(int*)buff = ic->obss_rssi_threshold;
            }
            break;
        case OL_ATH_PARAM_OBSS_RX_RSSI_THRESHOLD:
            {
                *(int*)buff = ic->obss_rx_rssi_threshold;
            }
            break;
        case OL_ATH_PARAM_ALLOW_PROMISC:
            {
                *(int*)buff = (scn->scn_promisc || promisc_is_active(&scn->sc_ic)) ? 1 : 0;
            }
            break;
        case OL_ATH_PARAM_ACS_TX_POWER_OPTION:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_TX_POWER_OPTION);
            }
            break;
         case OL_ATH_PARAM_ACS_2G_ALLCHAN:
            if(ic->ic_acs){
                *(int *)buff = ieee80211_acs_get_param(ic->ic_acs, IEEE80211_ACS_2G_ALL_CHAN);
            }
            break;


        case OL_ATH_PARAM_ENABLE_AMSDU:
             *(int*)buff = scn->scn_amsdu_mask;
        break;

        case OL_ATH_PARAM_ENABLE_AMPDU:
             *(int*)buff = scn->scn_ampdu_mask;
        break;

       case OL_ATH_PARAM_PRINT_RATE_LIMIT:
             *(int*)buff = scn->dbg.print_rate_limit;
       break;
        case OL_ATH_PARAM_CONSIDER_OBSS_NON_ERP_LONG_SLOT:
            *(int*)buff = ic->ic_consider_obss_long_slot;
        break;

#if PEER_FLOW_CONTROL
        case OL_ATH_PARAM_STATS_FC:
        case OL_ATH_PARAM_QFLUSHINTERVAL:
        case OL_ATH_PARAM_TOTAL_Q_SIZE:
        case OL_ATH_PARAM_MIN_THRESHOLD:
        case OL_ATH_PARAM_MAX_Q_LIMIT:
        case OL_ATH_PARAM_MIN_Q_LIMIT:
        case OL_ATH_PARAM_CONG_CTRL_TIMER_INTV:
        case OL_ATH_PARAM_STATS_TIMER_INTV:
        case OL_ATH_PARAM_ROTTING_TIMER_INTV:
        case OL_ATH_PARAM_LATENCY_PROFILE:
            {
                ol_pflow_update_pdev_params(scn->pdev_txrx_handle, param, value, buff);
            }
            break;
#endif
        case OL_ATH_PARAM_TXPOW_MGMT:
            {
                ol_update_txpow_pdev(scn->pdev_txrx_handle, txpow_frm_subtype[1], &txpow_frm_subtype[0]);
            }
            break;

        case OL_ATH_PARAM_DBG_ARP_SRC_ADDR:
        {
             /* arp dbg stats */
             printk("---- ARP DBG STATS ---- \n");
             printk("\n TX_ARP_REQ \t TX_ARP_RESP \t RX_ARP_REQ \t RX_ARP_RESP\n");
             printk("\n %d \t\t %d \t %d \t %d \n", scn->sc_tx_arp_req_count, scn->sc_tx_arp_resp_count, scn->sc_rx_arp_req_count, scn->sc_rx_arp_resp_count);
        }
        break;

        case OL_ATH_PARAM_ARP_DBG_CONF:

             *(int*)buff = scn->sc_arp_dbg_conf;
        break;

        case OL_ATH_PARAM_DISABLE_STA_VAP_AMSDU:
            *(int*)buff = ic->ic_sta_vap_amsdu_disable;
        break;

#if ATH_SUPPORT_DFS && ATH_SUPPORT_STA_DFS
        case OL_ATH_PARAM_STADFS_ENABLE:
            *(int *)buff = ieee80211com_has_cap_ext(ic,IEEE80211_CEXT_STADFS);
        break;
#endif
        case OL_ATH_PARAM_CHANSWITCH_OPTIONS:
            (*(int *)buff) = ic->ic_chanswitch_flags;
            adf_os_print(
                    "IEEE80211_CSH_OPT_NONDFS_RANDOM    0x00000001\n"
                    "IEEE80211_CSH_OPT_IGNORE_CSA_DFS   0x00000002\n"
                    "IEEE80211_CSH_OPT_CAC_APUP_BYSTA   0x00000004\n"
                    "IEEE80211_CSH_OPT_CSA_APUP_BYSTA   0x00000008\n"
                    "IEEE80211_CSH_OPT_RCSA_TO_UPLINK   0x00000010\n"
                    "IEEE80211_CSH_OPT_PROCESS_RCSA     0x00000020\n"
                    "IEEE80211_CSH_OPT_APRIORI_NEXT_CHANNEL 0x00000040\n"
                    "IEEE80211_CSH_OPT_AVOID_DUAL_CAC   0x00000080\n"
                    );
        break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_PRIMARY_RADIO:
            *(int *) buff =  ic->ic_primary_radio;
            break;
        case OL_ATH_PARAM_DBDC_ENABLE:
            *(int *) buff =  ic->ic_global_list->dbdc_process_enable;
            break;
        case OL_ATH_PARAM_CLIENT_MCAST:
            *(int *)buff = ic->ic_global_list->force_client_mcast_traffic;
            break;
#endif
        case OL_ATH_PARAM_CTL_POWER_SCALE:
            *(int *)buff = scn->powerscale;
            break;
#if QCA_AIRTIME_FAIRNESS
    case  OL_ATH_PARAM_ATF_STRICT_SCHED:
        *(int *)buff =!!(ic->ic_atf_sched & IEEE80211_ATF_SCHED_STRICT);
        break;
    case  OL_ATH_PARAM_ATF_GROUP_POLICY:
        *(int *)buff =  !!(ic->ic_atf_sched & IEEE80211_ATF_GROUP_SCHED_POLICY);
        break;
    case  OL_ATH_PARAM_ATF_OBSS_SCHED:
        *(int *)buff =!!(ic->ic_atf_sched & IEEE80211_ATF_SCHED_OBSS);
        break;
    case  OL_ATH_PARAM_ATF_OBSS_SCALE:
        *(int *)buff =ic->atf_obss_scale;
        break;
#endif
        case OL_ATH_PARAM_PHY_OFDM_ERR:
            *(int *)buff = scn->scn_stats.rx_phyerr;
            break;
        case OL_ATH_PARAM_PHY_CCK_ERR:
            *(int *)buff = scn->scn_stats.rx_phyerr;
            break;
        case OL_ATH_PARAM_FCS_ERR:
            *(int *)buff = scn->scn_stats.fcsBad;
            break;
        case OL_ATH_PARAM_CHAN_UTIL:
            *(int *)buff = -1;
            break;
        case OL_ATH_PARAM_EMIWAR_80P80:
            *(int *)buff = ic->ic_emiwar_80p80;
            break;
#if UMAC_SUPPORT_ACFG
        case OL_ATH_PARAM_DIAG_ENABLE:
            *(int *)buff = ic->ic_diag_enable;
        break;
#endif

        case OL_ATH_PARAM_CHAN_STATS_TH:
            *(int *)buff = ic->ic_chan_stats_th;
            break;

        case OL_ATH_PARAM_PASSIVE_SCAN_ENABLE:
            *(int *)buff = ic->ic_strict_pscan_enable;
            break;

        case OL_ATH_MIN_RSSI_ENABLE:
            *(int *)buff = ic->ic_min_rssi_enable;
            break;
        case OL_ATH_MIN_RSSI:
            *(int *)buff = ic->ic_min_rssi;
            break;
#if DBDC_REPEATER_SUPPORT
        case OL_ATH_PARAM_DELAY_STAVAP_UP:
            *(int *)buff = ic->ic_global_list->delay_stavap_connection;
            break;
#endif
        case OL_ATH_BTCOEX_ENABLE:
            *((int *) buff) = scn->btcoex_enable;
            break;
        case OL_ATH_BTCOEX_WL_PRIORITY:
            *((int *) buff) = scn->btcoex_wl_priority;
            break;
        case OL_ATH_PARAM_CAL_VER_CHECK:
            *(int *)buff = ic->ic_cal_ver_check;
           break;
        case OL_ATH_PARAM_TID_OVERRIDE_QUEUE_MAPPING:
            *(int *)buff = ol_pdev_get_tid_override_queue_mapping(scn->pdev_txrx_handle);
            break;
        case OL_ATH_PARAM_NO_VLAN:
            *(int *)buff = ic->ic_no_vlan;
            break;
        default:
            return (-1);
    }
    return retval;
}


int
ol_hal_set_config_param(struct ol_ath_softc_net80211 *scn, ol_hal_param_t param, void *buff)
{
    return -1;
}

int
ol_hal_get_config_param(struct ol_ath_softc_net80211 *scn, ol_hal_param_t param, void *address)
{
    return -1;
}

int
ol_net80211_set_mu_whtlist(wlan_if_t vap, u_int8_t *macaddr, u_int16_t tidmask)
{
    int retval = 0;
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    struct ol_ath_vap_net80211 *avn = OL_ATH_VAP_NET80211(vap);

    if((retval = wmi_unified_node_set_param(scn->wmi_handle, macaddr, WMI_PEER_SET_MU_WHITELIST,
            tidmask, avn->av_if_id))) {
        printk("%s:Unable to set peer MU white list\n", __func__);
    }
    return retval;
}
#endif /* ATH_PERF_PWR_OFFLOAD */
