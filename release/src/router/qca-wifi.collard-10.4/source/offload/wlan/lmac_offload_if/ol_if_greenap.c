/*
 * =====================================================================================
 *
 *       Filename:  ol_if_greenap.c
 *
 *    Description:  Green AP feature
 *
 *        Version:  1.0
 *        Created:  10/26/2012 01:34:26 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros Confidential and Proprietary
 *
 * =====================================================================================
 */

#ifdef  ATH_SUPPORT_GREEN_AP

#include "ol_if_athvar.h"
#include "ol_if_athpriv.h"
#include "bmi.h"
#include "sw_version.h"
#include "targaddrs.h"
#include "ol_helper.h"
#include "ol_txrx_ctrl_api.h"
#include "adf_os_mem.h"
#include "adf_os_lock.h"
#include "adf_os_types.h"

#include "ol_if_greenap.h"
#include "ath_green_ap.h"
#include "ieee80211_var.h"

#ifndef STATUS_PASS
#define STATUS_PASS 1
#endif

#ifndef STATUS_FAIL
#define STATUS_FAIL 0
#endif


/*
 * Green-AP function table, holds green ap related functions
 * that depends on direct/offload architecture.
 */
GREEN_AP_OPS green_ap_ops;


/*
 * Function     : wmi_send_pdev_green_ap_ps_enable_cmd
 * Description  : Send WMI command to enable/disable Green AP
 *                Power Save.
 * Input        : Pointer to ieee80211com,
 *                Flag indicating whether to enable (1) or
 *                disable (0)
 * Return       : 0 on success, negative error code on failure
 */
static int wmi_send_pdev_green_ap_ps_enable_cmd(struct ieee80211com *ic,
                                                u_int32_t enable)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_pdev_green_ap_ps_enable_cmd *cmd;
    wmi_buf_t buf;
    int len = 0;
    int ret;

    len = sizeof(wmi_pdev_green_ap_ps_enable_cmd);
    buf = wmi_buf_alloc(scn->wmi_handle, len);
    if (!buf) {
        adf_os_print("%s:wmi_buf_alloc failed\n", __FUNCTION__);
        return -ENOMEM;
    }

    cmd = (wmi_pdev_green_ap_ps_enable_cmd *)wmi_buf_data(buf);
    cmd->enable = enable;

    ret = wmi_unified_cmd_send(scn->wmi_handle,
                               buf,
                               len,
                               WMI_PDEV_GREEN_AP_PS_ENABLE_CMDID);

#ifdef OL_GREEN_AP_DEBUG_CONFIG_INTERACTIONS
    adf_os_print("%s: Sent WMI_PDEV_GREEN_AP_PS_ENABLE_CMDID.\n"
                 "enable=%u status=%d\n",
                 __FUNCTION__,
                 cmd->enable,
                 ret);
#endif /* OL_GREEN_AP_DEBUG_CONFIG_INTERACTIONS */

    return ret;
}

/*
 * Function     : ol_if_green_ap_set_ps
 * Description  : Configure the Green-AP Power save
 * Input        : Pointer to Green AP structure, state
 * Output       : Success/Failure
 */
u_int32_t ol_if_green_ap_set_ps(void* arg, u_int32_t val)
{
    int status = STATUS_PASS;
    struct ieee80211com* ic = ((struct ath_green_ap*)arg)->ic;
    struct ath_green_ap* green_ap = (struct ath_green_ap*)arg;

    if ((!green_ap->num_nodes) && (val)) {
        if (wmi_send_pdev_green_ap_ps_enable_cmd(ic, val) < 0) {
            status = STATUS_FAIL;
        }
    } else {
        /* If Stations are associated disable the Green AP*/
        if (wmi_send_pdev_green_ap_ps_enable_cmd(ic, 0) < 0) {
            status = STATUS_FAIL;
        } else {
            green_ap->ps_state = ATH_PWR_SAVE_OFF;
        }
    }

    return status;
}


/*
 * Function     : ol_if_green_ap_is_vap_active
 * Description  : Indicates if VAPs are active
 * Input        : Pointer to Green AP structure
 * Output       : Active (1)/Inactive (0)
 */
u_int32_t ol_if_green_ap_is_vap_active(void* arg)
{
    int numvaps = 0;
    struct ieee80211com* ic = ((struct ath_green_ap*)arg)->ic;
    numvaps = ieee80211_vaps_active(ic);
    return numvaps;
}


/*
 * Function     : ol_if_green_ap_get_current_channel
 * Description  : Get current channel
 * Input        : Pointer to IC
 * Output       : Channel
 */
u_int16_t ol_if_green_ap_get_current_channel(void* arg)
{
    int channel;
    struct ath_green_ap* green_ap = (struct ath_green_ap*)arg;
    struct ieee80211com* ic = green_ap->ic;
    channel = ic->ic_curchan->ic_freq;
    return channel;
}

/*
 * Function     : ol_if_green_ap_get_current_channel_flags
 * Description  : Get current channel flags
 * Input        : Pointer to IC
 * Output       : Channel flags
 */
u_int32_t ol_if_green_ap_get_current_channel_flags(void* arg)
{
    int channel_flags;
    struct ath_green_ap* green_ap = (struct ath_green_ap*)arg;
    struct ieee80211com* ic = green_ap->ic;
    channel_flags = ic->ic_curchan->ic_flags;
    return channel_flags;
}

/*
 * Function     : ol_if_green_ap_reset_dev
 * Description  : Reset the device
 * Input        : Pointer to Green-AP
 * Output       : Channel
 */
u_int32_t ol_if_green_ap_reset_dev(void* arg)
{
    GREEN_AP_INFO("No Reset required");
    return 0;
}

/*
 * Function     : ol_init_green_ap_ops
 * Description  : Initiate the Green-AP Ops
 * Input        : Pointer to IC, Pointer to function table
 * Output       : Success/Failure
 */
int ol_init_green_ap_ops(struct ieee80211com* ic)
{
    GREEN_AP_OPS* p_ops = &green_ap_ops;
    p_ops->set_ap_ps_on_off     = ol_if_green_ap_set_ps;
    p_ops->is_vap_active        = ol_if_green_ap_is_vap_active;
    p_ops->get_current_channel  = ol_if_green_ap_get_current_channel;
    p_ops->get_current_channel_flags = ol_if_green_ap_get_current_channel_flags;
    p_ops->reset_dev = ol_if_green_ap_reset_dev;
    return 0;
}

/*
 * Function     : ol_if_green_ap_set_enable
 * Description  : Set the Green-AP Enable
 * Input        : Pointer to IC, Value
 * Output       : Void
 */

void ol_if_green_ap_set_enable(struct ieee80211com* ic, int val)
{
    struct ieee80211vap *vap;
    struct ieee80211vap *vapnext;

    if(val) {
        vap = TAILQ_FIRST(&ic->ic_vaps);
        while (vap != NULL) {            
            if(vap->iv_opmode != IEEE80211_M_HOSTAP)
            {
                GREEN_AP_INFO("Not Supported when not in HOSTAP Mode\n");
                return;
            }
            vapnext = TAILQ_NEXT(vap, iv_next);
            vap = vapnext;
        }    
    }
    ath_green_ap_sc_set_enable(ic, val);
}

/*
 * Function     : ol_if_green_ap_get_enable
 * Description  : Get the Green-AP Enable state
 * Input        : Pointer to IC
 * Output       : State
 */
int ol_if_green_ap_get_enable(struct ieee80211com* ic)
{
    return ath_green_ap_sc_get_enable(ic);
}

/*
 * Function     : ol_if_green_ap_set_transition_time
 * Description  : Set the Green-AP Transistion time
 * Input        : Pointer to IC, val
 * Output       : Void
 */
void ol_if_green_ap_set_transition_time(struct ieee80211com* ic, int val)
{
    ath_green_ap_sc_set_transition_time(ic, val);
}

/*
 * Function     : ol_if_green_ap_get_transition_time
 * Description  : Get the Green-AP Transistion time
 * Input        : Pointer to IC
 * Output       : val
 */
int ol_if_green_ap_get_transition_time(struct ieee80211com* ic)
{
    return ath_green_ap_sc_get_transition_time(ic);
}

/*
 * Function     : ol_if_green_ap_set_on_time
 * Description  :
 * Input        :
 * Output       :
 */
void ol_if_green_ap_set_on_time(struct ieee80211com* ic, int val)
{
    ath_green_ap_sc_set_on_time(ic, val);
}

/*
 * Function     : ol_if_green_ap_get_on_time
 * Description  :
 * Input        :
 * Output       :
 */
int ol_if_green_ap_get_on_time(struct ieee80211com* ic)
{
    return ath_green_ap_sc_get_on_time(ic);
}

/*
 * Function : ol_if_green_ap_set_print_level
 */
void ol_if_green_ap_set_print_level(struct ieee80211com* ic, int val)
{
    printk("Green-AP : Debug print feature not available on offload architecture\n");
    return;
}

/*
 * Function : ol_if_green_ap_get_print_level
 */
int  ol_if_green_ap_get_print_level(struct ieee80211com* ic)
{
    printk("Green-AP : Debug print feature not available on offload architecture\n");
    return 0;
}


/*
 * Function     : ol_if_green_ap_attach
 * Description  : Attach Green-AP module
 * Input        : Pointer to IC
 * Output       : Success/Failure
 */
int ol_if_green_ap_attach(struct ieee80211com* ic)
{
    int status = STATUS_FAIL;

    if (ath_green_ap_attach(ic) != NULL) {
        ol_init_green_ap_ops(ic);
        /* Hook Green-AP functions to IC */
        ic->ic_green_ap_set_enable = ol_if_green_ap_set_enable;
        ic->ic_green_ap_get_enable = ol_if_green_ap_get_enable;
        ic->ic_green_ap_set_transition_time = ol_if_green_ap_set_transition_time;
        ic->ic_green_ap_get_transition_time = ol_if_green_ap_get_transition_time;
        ic->ic_green_ap_set_on_time = ol_if_green_ap_set_on_time;
        ic->ic_green_ap_get_on_time = ol_if_green_ap_get_on_time;
        ic->ic_green_ap_set_print_level = ol_if_green_ap_set_print_level;
        ic->ic_green_ap_get_print_level = ol_if_green_ap_get_print_level;
        green_ap_register_funcs(ic->ic_green_ap, &green_ap_ops);
        status = STATUS_PASS;
        printk(KERN_INFO"Green-AP : Attached\n");
    }

    return status;
}


/*
 * Function     : ol_if_green_ap_detach
 * Description  : Remove Green-AP module
 * Input        : Pointer to IC
 * Output       : Success/Failure
 */
int ol_if_green_ap_detach(struct ieee80211com* ic)
{
    int status = STATUS_PASS;

    if (ath_green_ap_detach(ic) < 0 ) {
        status = STATUS_FAIL;
    }

    if (status) {
        printk("Green-AP : Detached\n");
    } else {
        printk("Green-AP : Failed to Detach\n");
    }

    return status;
}

#endif  /* ATH_SUPPORT_GREEN_AP */
