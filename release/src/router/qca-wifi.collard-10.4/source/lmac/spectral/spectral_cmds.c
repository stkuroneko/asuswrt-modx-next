/*
 * Copyright (c) 2010, Atheros Communications Inc.
 * All Rights Reserved.
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#include "ath_internal.h"

#if ATH_SUPPORT_SPECTRAL

#include "spectral.h"

/*
 * Function     : print_spectral_params
 * Description  : print configured spectral params
 * Input        : Pointer to HAL spectral params
 * Output       : Void
 *
 */
void print_spectral_params(HAL_SPECTRAL_PARAM *p)
{
    printk("ss_fft_period      : %d\n", p->ss_fft_period);
    printk("ss_period          : %d\n", p->ss_period);
    printk("ss_count           : %d\n", p->ss_count);
    printk("ss_short_report    : %d\n", p->ss_short_report);
    printk("ss_fft_size        : %d\n", p->ss_fft_size);
    printk("ss_gc_ena          : %d\n", p->ss_gc_ena);
    printk("ss_restart_ena     : %d\n", p->ss_restart_ena);
    printk("ss_noise_floor_ref : %d\n", p->ss_noise_floor_ref);
    printk("ss_init_delay      : %d\n", p->ss_init_delay);
    printk("ss_nb_tone_thr     : %d\n", p->ss_nb_tone_thr);
    printk("ss_str_bin_thr     : %d\n", p->ss_str_bin_thr);
    printk("ss_wb_rpt_mode     : %d\n", p->ss_wb_rpt_mode);
    printk("ss_rssi_rpt_mode   : %d\n", p->ss_rssi_rpt_mode);
    printk("ss_rssi_thr        : %d\n", p->ss_rssi_thr);
    printk("ss_pwr_format      : %d\n", p->ss_pwr_format);
    printk("ss_rpt_mode        : %d\n", p->ss_rpt_mode);
    printk("ss_bin_scale       : %d\n", p->ss_bin_scale);
    printk("ss_dBm_adj         : %d\n", p->ss_dBm_adj);
    printk("ss_chn_mask        : %d\n", p->ss_chn_mask);
    printk("radar threshold    : %d\n", p->radar_bin_thresh_sel);
}

/*
 * Function     : stop_current_scan
 * Description  : stops the current on-going spectral scan
 * Input        : Pointer to spectral
 * Output       : Void
 *
 */
void stop_current_scan(struct ath_spectral* spectral)
{
    SPECTRAL_OPS *p_sops = GET_SPECTRAL_OPS(spectral);

    if (spectral == NULL) {
        printk("SPECTRAL : Spectral is NUll  (%s)\n", __func__);
        return;
    }

    p_sops->stop_spectral_scan(spectral);

    if( spectral->classify_scan) {
        SPECTRAL_TODO("Check if this logic is necessary");
        spectral->detects_control_channel   = 0;
        spectral->detects_extension_channel = 0;
        spectral->detects_above_dc          = 0;
        spectral->detects_below_dc          = 0;
        spectral->classify_scan             = 0;
    }

    spectral->send_single_packet        = 0;
    spectral->sc_spectral_scan          = 0;
    spectral->sc_spectral_noise_pwr_cal = 0;

    /*
     * Reset the priority because it stops WLAN rx.
     * If it is needed to set, user has to set it explicitly
     *
     */
    spectral->params.ss_spectral_pri    = 0;    /* Reset Priority */
}

/*
 * Function     : start_spectral_scan
 * Description  : start the spectral scan
 * Input        : Pointer to spectral
 * Output       : Void
 *
 */
void start_spectral_scan(struct ath_spectral *spectral)
{

    HAL_SPECTRAL_PARAM params;
    SPECTRAL_OPS* p_sops = GET_SPECTRAL_OPS(spectral);

    if (spectral == NULL) {
        printk("SPECTRAL : Spectral is NUll  (%s)\n", __func__);
        return;
    }

    spectral_scan_enable_params(spectral, &spectral->params);

    p_sops->configure_spectral(spectral, &spectral->params);

    /* XXX : Verify if the params change their values ? */
    spectral_get_thresholds(spectral, &params);

    spectral->send_single_packet            = 1;
    spectral->spectral_sent_msg             = 0;
    spectral->classify_scan                 = 0;
    spectral->num_spectral_data             = 0;
    spectral->sc_spectral_scan              = 1;

    p_sops->start_spectral_scan(spectral);
}

#endif
