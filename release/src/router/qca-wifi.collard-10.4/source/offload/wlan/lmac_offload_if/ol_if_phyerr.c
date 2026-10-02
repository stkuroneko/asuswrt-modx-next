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
 * LMAC management specific offload interface functions - for PHY error handling
 */
#include "ol_if_athvar.h"

/* This enables verbose printing of PHY error debugging */
#define ATH_PHYERR_DEBUG        0

#if ATH_PERF_PWR_OFFLOAD

#if ATH_SUPPORT_DFS
#include "ath_dfs_structs.h"
#include "dfs_interface.h"
#include "dfs.h"                /* for DFS_*_DOMAIN */
#endif /* ATH_SUPPORT_DFS */

#if ATH_SUPPORT_SPECTRAL
#include "spectral.h"
#include "ol_if_spectral.h"
#endif

#define AR900B_DFS_PHYERR_MASK      0x4
#define AR900B_SPECTRAL_PHYERR_MASK 0x4000000

static int
wmi_unified_phyerr_rx_event_handler_wifi2_0(ol_scn_t scn, u_int8_t *data,
        u_int16_t datalen, void *context);
/*
 * XXX TODO: talk to Nitin about the endian-ness of this - what's
 * being byteswapped by the firmware?!
 */
static int
wmi_unified_phyerr_rx_event_handler(ol_scn_t scn, u_int8_t *data,
    u_int16_t datalen, void *context)
{
    wmi_comb_phyerr_rx_event *pe;
    wmi_single_phyerr_rx_event *ev;
#if ATH_SUPPORT_DFS || ATH_SUPPORT_SPECTRAL
    struct ieee80211com *ic = &scn->sc_ic;
#endif /* ATH_SUPPORT_DFS || ATH_SUPPORT_SPECTRAL */
#if ATH_PHYERR_DEBUG
    int i;
#endif /* ATH_PHYERR_DEBUG */
    int n;
    A_UINT64 tsf64;
    int phy_err_code;
#if ATH_SUPPORT_SPECTRAL
    spectral_acs_stats_t acs_stats;
    struct ath_spectral* spectral = (struct ath_spectral*) ic->ic_spectral;
#endif

    if (scn->target_type == TARGET_TYPE_AR900B  || scn->target_type == TARGET_TYPE_QCA9984 || \
                        scn->target_type == TARGET_TYPE_QCA9888 || scn->target_type == TARGET_TYPE_IPQ4019) {
        return wmi_unified_phyerr_rx_event_handler_wifi2_0(scn, data, datalen, context);
    }
#if ATH_PHYERR_DEBUG
   adf_os_print("%s: data=%p, datalen=%d\n", __func__, data, datalen);
    /* XXX for now */

    for (i = 0; i < datalen; i++) {
        adf_os_print("%02X ", data[i]);
        if (i % 32 == 31)
                adf_os_print("\n");
    }
    adf_os_print("\n");
#endif /* ATH_PHYERR_DEBUG */

    /* Ensure it's at least the size of the header */
    if (datalen < sizeof(*pe)) {
#if ATH_SUPPORT_SPECTRAL
        spectral->ath_spectral_stats.datalen_discards++;
#endif
        return (1);             /* XXX what should errors be? */
    }

    pe = (wmi_comb_phyerr_rx_event *) data;
#if ATH_PHYERR_DEBUG
    adf_os_print("%s: pe->hdr.num_phyerr_events=%d\n",
       __func__,
       pe->hdr.num_phyerr_events);
#endif /* ATH_PHYERR_DEBUG */

    /*
     * Reconstruct the 64 bit event TSF.  This isn't from the MAC, it's
     * at the time the event was sent to us, the TSF value will be
     * in the future.
     */
    tsf64 = pe->hdr.tsf_l32;
    tsf64 |= (((uint64_t) pe->hdr.tsf_u32) << 32);

    /* Loop over the bufp, extracting out phyerrors */
    /*
     * XXX wmi_unified_comb_phyerr_rx_event.bufp is a char pointer,
     * which isn't correct here - what we have received here
     * is an array of TLV-style PHY errors.
     */
    /*
     * XXX should ensure that we only decode 'num_phyerr_events'
     * worth of events!
     */
    n = sizeof(pe->hdr);    /* Start just after the header */
    while (n < datalen) {
        /* ensure there's at least space for the header */
        if ((datalen - n) < sizeof(ev->hdr)) {
                adf_os_print("%s: not enough space? (datalen=%d, n=%d, hdr=%d bytes\n",
                  __func__,
                  datalen,
                  n,
                  sizeof(ev->hdr));
                break;
        }

        /*
         * Obtain a pointer to the beginning of the current event.
         * data[0] is the beginning of the WMI payload.
         */
        ev = (wmi_single_phyerr_rx_event *) &data[n];

        /*
         * Sanity check the buffer length of the event against
         * what we currently have.
         *
         * Since buf_len is 32 bits, we check if it overflows
         * a large 32 bit value.  It's not 0x7fffffff because
         * we increase n by (buf_len + sizeof(hdr)), which would
         * in itself cause n to overflow.
         *
         * If "int" is 64 bits then this becomes a moot point.
         */
        if (ev->hdr.buf_len > 0x7f000000) {
            adf_os_print("%s: buf_len is garbage? (0x%x\n)\n",
                __func__,
                ev->hdr.buf_len);
            break;
        }
        if (n + ev->hdr.buf_len > datalen) {
            adf_os_print("%s: buf_len exceeds available space "
              "(n=%d, buf_len=%d, datalen=%d\n",
              __func__,
              n,
              ev->hdr.buf_len,
              datalen);
            break;
        }

        phy_err_code = WMI_UNIFIED_PHYERRCODE_GET(&ev->hdr);

        /*
         * Print some debugging.
         */
#if ATH_PHYERR_DEBUG
        adf_os_print("%s: len=%d, tsf=0x%08x, rssi = 0x%x/0x%x/0x%x/0x%x, "
            "comb rssi = 0x%x, phycode=%d\n",
            __func__,
            ev->hdr.buf_len,
            ev->hdr.tsf_timestamp,
            ev->hdr.rssi_chain0,
            ev->hdr.rssi_chain1,
            ev->hdr.rssi_chain2,
            ev->hdr.rssi_chain3,
            WMI_UNIFIED_RSSI_COMB_GET(&ev->hdr),
            phy_err_code);

        /*
         * For now, unroll this loop - the chain 'value' field isn't
         * a variable but glued together into a macro field definition.
         * Grr. :-)
         */
        adf_os_print("%s: chain 0: raw=0x%08x; pri20=%d sec20=%d sec40=%d sec80=%d\n",
          __func__,
          ev->hdr.rssi_chain0,
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, PRI20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC40),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC80));

        adf_os_print("%s: chain 1: raw=0x%08x: pri20=%d sec20=%d sec40=%d sec80=%d\n",
          __func__,
          ev->hdr.rssi_chain1,
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, PRI20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC40),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC80));

        adf_os_print("%s: chain 2: raw=0x%08x: pri20=%d sec20=%d sec40=%d sec80=%d\n",
          __func__,
          ev->hdr.rssi_chain2,
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, PRI20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC40),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC80));

        adf_os_print("%s: chain 3: raw=0x%08x: pri20=%d sec20=%d sec40=%d sec80=%d\n",
          __func__,
          ev->hdr.rssi_chain3,
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, PRI20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC20),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC40),
          WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC80));


        adf_os_print("%s: freq_info_1=0x%08x, freq_info_2=0x%08x\n",
            __func__, ev->hdr.freq_info_1, ev->hdr.freq_info_2);

        /*
         * The NF chain values are signed and are negative - hence
         * the cast evilness.
         */
        adf_os_print("%s: nfval[1]=0x%08x, nfval[2]=0x%08x, nf=%d/%d/%d/%d, "
            "freq1=%d, freq2=%d, cw=%d\n",
            __func__,
            ev->hdr.nf_list_1,
            ev->hdr.nf_list_2,
            (int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 0),
            (int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 1),
            (int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 2),
            (int) WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 3),
            WMI_UNIFIED_FREQ_INFO_GET(&ev->hdr, 1),
            WMI_UNIFIED_FREQ_INFO_GET(&ev->hdr, 2),
            WMI_UNIFIED_CHWIDTH_GET(&ev->hdr));
#endif /* ATH_PHYERR_DEBUG */

#if ATH_SUPPORT_DFS
        /*
         * If required, pass radar events to the dfs pattern matching code.
         *
         * Don't pass radar events with no buffer payload.
         */
        if (phy_err_code == 0x5 || phy_err_code == 0x24) {
            if (ev->hdr.buf_len > 0)
                dfs_process_phyerr(ic, &ev->bufp[0], ev->hdr.buf_len,
                  WMI_UNIFIED_RSSI_COMB_GET(&ev->hdr) & 0xff,
                  WMI_UNIFIED_RSSI_COMB_GET(&ev->hdr) & 0xff, /* XXX Extension RSSI */
                  ev->hdr.tsf_timestamp,
                  tsf64);
        }
#endif /* ATH_SUPPORT_DFS */

#if ATH_SUPPORT_SPECTRAL

        /*
         * If required, pass spectral events to the spectral module
         *
         */
        if (phy_err_code == PHY_ERROR_FALSE_RADAR_EXT ||
          phy_err_code == PHY_ERROR_SPECTRAL_SCAN) {
            if (ev->hdr.buf_len > 0) {
                SPECTRAL_RFQUAL_INFO rfqual_info;
                SPECTRAL_CHAN_INFO   chan_info;

                /* Initialize the NF values to Zero. */
                rfqual_info.noise_floor[0] = WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 0);
                rfqual_info.noise_floor[1] = WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 1);
                rfqual_info.noise_floor[2] = WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 2);
                rfqual_info.noise_floor[3] = WMI_UNIFIED_NF_CHAIN_GET(&ev->hdr, 3);

                /* populate the rf info */
                rfqual_info.rssi_comb = WMI_UNIFIED_RSSI_COMB_GET(&ev->hdr);

                /* Need to unroll loop due to macro constraints */
                /* chain 0 */
                rfqual_info.pc_rssi_info[0].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, PRI20);
                rfqual_info.pc_rssi_info[0].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC20);
                rfqual_info.pc_rssi_info[0].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC40);
                rfqual_info.pc_rssi_info[0].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 0, SEC80);

                /* chain 1 */
                rfqual_info.pc_rssi_info[1].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, PRI20);
                rfqual_info.pc_rssi_info[1].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC20);
                rfqual_info.pc_rssi_info[1].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC40);
                rfqual_info.pc_rssi_info[1].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 1, SEC80);

                /* chain 2 */
                rfqual_info.pc_rssi_info[2].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, PRI20);
                rfqual_info.pc_rssi_info[2].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC20);
                rfqual_info.pc_rssi_info[2].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC40);
                rfqual_info.pc_rssi_info[2].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 2, SEC80);

                /* chain 3 */
                rfqual_info.pc_rssi_info[3].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, PRI20);
                rfqual_info.pc_rssi_info[3].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC20);
                rfqual_info.pc_rssi_info[3].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC40);
                rfqual_info.pc_rssi_info[3].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(&ev->hdr, 3, SEC80);

                chan_info.center_freq1 = WMI_UNIFIED_FREQ_INFO_GET(&ev->hdr, 1);
                chan_info.center_freq2 = WMI_UNIFIED_FREQ_INFO_GET(&ev->hdr, 2);

                if (phy_err_code == PHY_ERROR_SPECTRAL_SCAN) {
                    spectral_process_phyerr(ic->ic_spectral, ev->bufp, ev->hdr.buf_len, &rfqual_info, &chan_info, tsf64, &acs_stats);
                }

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
                if (phy_err_code == PHY_ERROR_SPECTRAL_SCAN) {
                    ieee80211_init_spectral_chan_loading(ic, chan_info.center_freq1, 0);
                    ieee80211_update_eacs_counters(ic, acs_stats.nfc_ctl_rssi,
                                                       acs_stats.nfc_ext_rssi,
                                                       acs_stats.ctrl_nf,
                                                       acs_stats.ext_nf);
                }
#endif
#ifdef SPECTRAL_SUPPORT_LOGSPECTRAL
                spectral_send_tlv_to_host(ic->ic_spectral, ev->bufp, ev->hdr.buf_len);
#endif
            }
        }
#endif  /* ATH_SUPPORT_SPECTRAL */

        /*
         * Advance the buffer pointer to the next PHY error.
         * buflen is the length of this payload, so we need to
         * advance past the current header _AND_ the payload.
         */
        n += sizeof(*ev) + ev->hdr.buf_len;
    }

     return (0);
}

static int
wmi_unified_phyerr_rx_event_handler_wifi2_0(ol_scn_t scn, u_int8_t *data,
        u_int16_t datalen, void *context)
{
    wmi_composite_phyerr_rx_event *pe;
    wmi_composite_phyerr_rx_hdr *ph;
    A_UINT64 tsf64;
    struct ieee80211com *ic = &scn->sc_ic;
#if ATH_SUPPORT_SPECTRAL
    spectral_acs_stats_t acs_stats;
    struct ath_spectral* spectral = (struct ath_spectral*) ic->ic_spectral;
#endif


    /* sanity check on data length */
    if (datalen < sizeof(*pe)) {
#if ATH_SUPPORT_SPECTRAL
        spectral->ath_spectral_stats.datalen_discards++;
#endif
        return (1);
    }

    pe = (wmi_composite_phyerr_rx_event *)data;
    ph = &pe->hdr;

    /* handle different PHY Error conditions */
    if (((ph->phy_err_mask0 & (AR900B_DFS_PHYERR_MASK | AR900B_SPECTRAL_PHYERR_MASK)) == 0)) {
        /* unknown PHY error, currently only Spectral and DFS are handled */
        return (1);
    }

    /*
     * Reconstruct the 64 bit event TSF.  This isn't from the MAC, it's
     * at the time the event was sent to us, the TSF value will be
     * in the future.
     */
    tsf64 = ph->tsf_l32;
    tsf64 |= (((uint64_t) ph->tsf_u32) << 32);


    /* Handle Spectral PHY Error */
    if ((ph->phy_err_mask0 & AR900B_SPECTRAL_PHYERR_MASK)) {
#if ATH_SUPPORT_SPECTRAL
        if (ph->buf_len > 0) {
                SPECTRAL_RFQUAL_INFO rfqual_info;
                SPECTRAL_CHAN_INFO   chan_info;

                /* Initialize the NF values to zero */
                rfqual_info.noise_floor[0] = WMI_UNIFIED_NF_CHAIN_GET(ph, 0);
                rfqual_info.noise_floor[1] = WMI_UNIFIED_NF_CHAIN_GET(ph, 1);
                rfqual_info.noise_floor[2] = WMI_UNIFIED_NF_CHAIN_GET(ph, 2);
                rfqual_info.noise_floor[3] = WMI_UNIFIED_NF_CHAIN_GET(ph, 3);

                /* populate the rf info */
                rfqual_info.rssi_comb = WMI_UNIFIED_RSSI_COMB_GET(ph);

                /* Need to unroll loop due to macro constraints */
                /* chain 0 */
                rfqual_info.pc_rssi_info[0].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 0, PRI20);
                rfqual_info.pc_rssi_info[0].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 0, SEC20);
                rfqual_info.pc_rssi_info[0].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 0, SEC40);
                rfqual_info.pc_rssi_info[0].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 0, SEC80);

                /* chain 1 */
                rfqual_info.pc_rssi_info[1].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 1, PRI20);
                rfqual_info.pc_rssi_info[1].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 1, SEC20);
                rfqual_info.pc_rssi_info[1].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 1, SEC40);
                rfqual_info.pc_rssi_info[1].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 1, SEC80);

                /* chain 2 */
                rfqual_info.pc_rssi_info[2].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 2, PRI20);
                rfqual_info.pc_rssi_info[2].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 2, SEC20);
                rfqual_info.pc_rssi_info[2].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 2, SEC40);
                rfqual_info.pc_rssi_info[2].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 2, SEC80);

                /* chain 3 */
                rfqual_info.pc_rssi_info[3].rssi_pri20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 3, PRI20);
                rfqual_info.pc_rssi_info[3].rssi_sec20 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 3, SEC20);
                rfqual_info.pc_rssi_info[3].rssi_sec40 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 3, SEC40);
                rfqual_info.pc_rssi_info[3].rssi_sec80 =
                    WMI_UNIFIED_RSSI_CHAN_GET(ph, 3, SEC80);

                chan_info.center_freq1 = WMI_UNIFIED_FREQ_INFO_GET(ph, 1);
                chan_info.center_freq2 = WMI_UNIFIED_FREQ_INFO_GET(ph, 2);

                if ( ph->phy_err_mask0 & AR900B_SPECTRAL_PHYERR_MASK) {
                    spectral_process_phyerr(ic->ic_spectral, pe->bufp, ph->buf_len, &rfqual_info, &chan_info, tsf64, &acs_stats);
                }

#if ATH_ACS_SUPPORT_SPECTRAL && ATH_SUPPORT_SPECTRAL
                if ( ph->phy_err_mask0 & AR900B_SPECTRAL_PHYERR_MASK) {
                    ieee80211_init_spectral_chan_loading(ic, chan_info.center_freq1, 0);
                    ieee80211_update_eacs_counters(ic, acs_stats.nfc_ctl_rssi,
                                                       acs_stats.nfc_ext_rssi,
                                                       acs_stats.ctrl_nf,
                                                       acs_stats.ext_nf);
                }
#endif
#ifdef SPECTRAL_SUPPORT_LOGSPECTRAL
                spectral_send_tlv_to_host(ic->ic_spectral, pe->bufp, ph->buf_len);
#endif
        }
#endif  /* ATH_SUPPORT_SPECTRAL */

    } else if ((ph->phy_err_mask0 & AR900B_DFS_PHYERR_MASK)) {
        if (ph->buf_len > 0) {
#if ATH_SUPPORT_DFS
            dfs_process_phyerr(ic, pe->bufp, ph->buf_len,
                WMI_UNIFIED_RSSI_COMB_GET(ph) & 0xff,
                WMI_UNIFIED_RSSI_COMB_GET(ph) & 0xff, /* XXX Extension RSSI */
                ph->tsf_timestamp,
                tsf64);
#endif /*ATH_SUPPORT_DFS*/
        }
    }
     return (0);
}

/*
 * Enable PHY errors.
 *
 * For now, this just enables the DFS PHY errors rather than
 * being able to select which PHY errors to enable.
 */
void
ol_ath_phyerr_enable(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_buf_t buf;
    /*
     * Passing a NULL pointer to wmi_unified_cmd_send() panics it,
     * so let's just use a 32 byte fake array for now.
     */
    buf = wmi_buf_alloc(scn->wmi_handle, 32);
    if (buf == NULL) {
        /* XXX error? */
        return;
    }

    adf_os_print("%s: about to send\n", __func__);
    if (wmi_unified_cmd_send(scn->wmi_handle, buf, 32,
      WMI_PDEV_DFS_ENABLE_CMDID) != A_OK) {
        adf_os_print("%s: send failed\n", __func__);
    }
}

/*
 * Disbale PHY errors.
 *
 * For now, this just disables the DFS PHY errors rather than
 * being able to select which PHY errors to disable.
 */
void
ol_ath_phyerr_disable(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_buf_t buf;
    /*
     * Passing a NULL pointer to wmi_unified_cmd_send() panics it,
     * so let's just use a 32 byte fake array for now.
     */
    buf = wmi_buf_alloc(scn->wmi_handle, 32);
    if (buf == NULL) {
        /* XXX error? */
        return;
    }

    adf_os_print("%s: about to send\n", __func__);
    if (wmi_unified_cmd_send(scn->wmi_handle, buf, 32,
      WMI_PDEV_DFS_DISABLE_CMDID) != A_OK) {
        adf_os_print("%s: send failed\n", __func__);
    }
}

/*
 * PHY error attach functions for offload solutions
 */
void
ol_ath_phyerr_attach(struct ieee80211com *ic)
{
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    adf_os_print(KERN_DEBUG"%s: called\n", __func__);

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle,
      WMI_PHYERR_EVENTID,
      wmi_unified_phyerr_rx_event_handler,
      NULL);
}

/*
 * Detach the PHY error module.
 */
void
ol_ath_phyerr_detach(struct ieee80211com *ic)
{

    /* XXX TODO: see what needs to be unregistered */
    adf_os_print(KERN_INFO"%s: called\n", __func__);
}

#endif /* ATH_PERF_PWR_OFFLOAD */
