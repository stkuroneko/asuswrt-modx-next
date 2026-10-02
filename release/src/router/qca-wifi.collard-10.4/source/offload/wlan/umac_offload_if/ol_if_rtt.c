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

#include "ol_if_athvar.h"
#include <ieee80211_defines.h>
#include <ieee80211_scan.h>
//#define ATH_SUPPORT_WIFIPOS 1
#if ATH_SUPPORT_WIFIPOS
#include <ieee80211_wifipos_pvt.h>
#include <ieee80211_api.h>


//tone number of each bw
//bw = 0, Legacy 20MHz, 53 tones
//bw = 1, HT 20MHz, 57 tones
//bw = 2, HT 40MHz, 117 tones
//bw = 3, VHT 80MHz, 242 tones
#define IS_2GHZ_CH 20
#define RTT3_FRAME_TYPE 3
extern struct ol_ath_softc_net80211 *ol_global_scn[10];
extern int ol_num_global_scn;
static atomic_t rtt_nl_users = ATOMIC_INIT(0);
#define TONE_LEGACY_20M 53
#define TONE_VHT_20M 56
#define TONE_VHT_40M 117
#define TONE_VHT_80M 242
#define RTT_TIMEOUT_MS 180
int tone_number[4] = {TONE_LEGACY_20M, TONE_VHT_20M, TONE_VHT_40M, TONE_VHT_80M};
#define MEM_ALIGN(x) (((x)<<1)+3) & 0xFFFC

#define NUM_ARRAY_ELEMENTS(array_name) ((size_t)(sizeof(array_name) / sizeof(array_name[0])))
#define IS_VALID_INDEX_OF_ARRAY(array_name, array_index) (array_index < NUM_ARRAY_ELEMENTS(array_name))

#define TARGET_OEM_CONFIGURE_LCI        0x0A
#define TARGET_OEM_CONFIGURE_LCR        0x09
#define RTT_LCI_ALTITUDE_MASK		0x3FFFFFFF
#define RTT3_DEFAULT_BURST_DURATION     15
#define IEEE80211_SUBIE_COLOCATED_BSSID 0x7
#define MAXBSSID_INDICATOR_DEFAULT      0
#define IEEE80211_COLOCATED_BSS_MAX_LEN 196

// the buffer size of 1 chain for each BW 0-3
u_int16_t bw_size [4] =
{
    MEM_ALIGN(TONE_LEGACY_20M),
    MEM_ALIGN(TONE_VHT_20M),
    MEM_ALIGN(TONE_VHT_40M),
    MEM_ALIGN(TONE_VHT_80M)
};

char* measurement_type[] = {
    "NULL Frame",
    "QoS_NULL Frame",
    "TMR/TM Frame"
};

/*
 * Define the sting for each RTT request type
 * for debug print purpose only
 */
char* error_indicator[] = {
    "RTT_COMMAND_HEADER_ERROR",
    "RTT_COMMAND_ERROR",
    "RTT_MODULE_BUSY",
    "RTT_TOO_MANY_STA",
    "RTT_NO_RESOURCE",
    "RTT_VDEV_ERROR",
    "RTT_TRANSIMISSION_ERROR",
    "RTT_TM_TIMER_EXPIRE",
    "RTT_FRAME_TYPE_NOSUPPORT",
    "RTT_TIMER_EXPIRE",
    "RTT_CHAN_SWITCH_ERROR",
    "RTT_TMR_TRANS_ERROR", //TMR trans error, this dest peer will be skipped
    "RTT_NO_REPORT_BAD_CFR_TOKEN", //V3 only. If both CFR and Token mismatch, do not report
    "RTT_NO_REPORT_FIRST_TM_BAD_CFR", //For First TM, if CFR is bad, then do not report
    "RTT_REPORT_TYPE2_MIX", //do not allow report type2 mix with type 0, 1
    "WMI_RTT_REJECT_MAX"
};

#define NUM_ARRAY_ELEMENTS(array_name) ((size_t)(sizeof(array_name) / sizeof(array_name[0])))
#define IS_VALID_INDEX_OF_ARRAY(array_name, array_index) (array_index < NUM_ARRAY_ELEMENTS(array_name))


struct ieee80211_lci_subelement_info{
    A_UINT8     latitude_unc:6,
                latitude_0_1:2;     //bits 0 to 1 of latitude
    A_UINT32    latitude_2_33;     //bits 2 to 33 of latitude
    A_UINT8     longitude_unc:6,
                longitude_0_1:2;    //bits 0 to 1 of longitude
    A_UINT32    longitude_2_33;    //bits 2 to 33 of longitude
    A_UINT8     altitude_type:4,
                altitude_unc_0_3:4;
    A_UINT32    altitude_unc_4_5:2,
                altitude:30;
    A_UINT8     datum:3,
                reg_loc_agmt:1,
                reg_loc_dse:1,
                dep_sta:1,
                version:2;
} __ATTRIB_PACK;


/*

 * Calculate how many chains in a mask

 * mask -- chain mask  return: Number of chains

 */

static u_int8_t rtt_get_chain_no(u_int16_t mask)
{
    u_int8_t counter = 0;
    while (mask > 0) {
        if(mask & 1) counter++;
        mask = mask >> 1;
    }

    return counter;
}

/*
 * print out the rtt measurement response on host
 * for debug purpose
 */
void rtt_print_resp_header(wmi_rtt_event_hdr *header,
                           u_int8_t* frame_type,
                           u_int8_t* report_type,
                           ieee80211_ol_wifiposdesc_t * wifiposdesc)
{
    u_int8_t dest_mac[6];
    char* measurement_type_str = NULL;
    u_int16_t req_id = WMI_RTT_REQ_ID_GET(header->req_id);
    u_int32_t result = (header->req_id & 0xffff0000) >> 16;

    wifiposdesc->request_id = req_id;
    wifiposdesc->rx_pkt_type = WMI_RTT_REPORT_MEAS_TYPE_GET(header->req_id);
    WMI_MAC_ADDR_TO_CHAR_ARRAY(&header->dest_mac, dest_mac);
    *frame_type = WMI_RTT_REPORT_MEAS_TYPE_GET(header->req_id);
    *report_type = WMI_RTT_REPORT_REPORT_TYPE_GET(header->req_id);
    measurement_type_str = ((*frame_type < 3) ? measurement_type[*frame_type] : "INVALID");
    wifiposdesc->req_type = *frame_type;
    /* Only 3 type of frames are used for Measurement type ,
        even though  RTT measurement type is 3 bit header */
    adf_os_print("\nRTTREPORT ==================Measurement Report====================\n");
    adf_os_print("RTTREPORT Request ID=%u Result=0x%x MeasurementType=%s ReportType=%d ", req_id, result, measurement_type_str, *report_type);
    adf_os_print("MAC=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    memcpy(wifiposdesc->sta_mac_addr, dest_mac, 6);
}

void rtt_print_meas_resp_body(wmi_rtt_meas_event *body,
                              u_int8_t meas_type,
                              u_int8_t report_type,
                              ieee80211_ol_wifiposdesc_t * wifiposdesc)
{
    u_int8_t mask;
    u_int8_t bw;
    u_int8_t *p, *tmp, *temp1, *temp2;
    u_int8_t index, index1;
    u_int64_t t1_or_tod = 0;
    u_int64_t t2_or_toa = 0;
    u_int64_t t3 = 0;
    u_int64_t t4 = 0;

    A_TIME64 *time;

    //adf_os_print("%s:\n", __func__);
	if (wifiposdesc == NULL){
		printk("\nRTTREPORT WIFIPOS: Desc is NULL *****\n");
		return;
    }
    if(body) {
        mask = WMI_RTT_REPORT_RX_CHAIN_GET(body->rx_chain);
        bw = WMI_RTT_REPORT_RX_BW_GET(body->rx_chain);
        adf_os_print("RTTREPORT Rx ChainMask=:0x%x BW=%d\n", mask, bw);

        t1_or_tod = ((u_int64_t) body->tod.time32) <<32;
        t1_or_tod |= body->tod.time0; //tmp1 is the 64 bit tod
        wifiposdesc->tod = t1_or_tod;

        t2_or_toa = ((u_int64_t) body->toa.time32) <<32;
        t2_or_toa |= body->toa.time0;
        wifiposdesc->toa = t2_or_toa;

        p =(u_int8_t *) (++body);

        //if the measurement is TMR, we should have T3 and T4
        if ( meas_type == RTT_MEAS_FRAME_TMR) {
            time = (A_TIME64 *) body;
            t3 = (u_int64_t) (time->time32) <<32;
            t3 |= time->time0;
            wifiposdesc->t3 = t3;

            time++;
            t4 = (u_int64_t)(time->time32) <<32;
            t4 |= time->time0;
            wifiposdesc->t4 = t4;

            adf_os_print("RTTREPORT Timestamps %llu %llu %llu %llu\n", t1_or_tod, t2_or_toa, t3, t4);

            p =(u_int8_t *) (++time);
        }
        else {
            adf_os_print("RTTREPORT Timestamps %llu 0 0 %llu\n", t1_or_tod, t2_or_toa);
        }
        temp1 = temp2 = wifiposdesc->hdump;


        wifiposdesc->rssi0 = 0;
        wifiposdesc->rssi1 = 0;
        wifiposdesc->rssi2 = 0;
        wifiposdesc->rssi3 = 0;

        for (index = 0; index <4; index++ ) {
            if(mask & (1 << index)) {
                if(index==0) {
                    wifiposdesc->rssi0 = *((u_int32_t *)p);
                }
                if(index==1) {
                    wifiposdesc->rssi1 = *((u_int32_t *)p);
                }
                if(index==2) {
                    wifiposdesc->rssi2 = *((u_int32_t *)p);
                }
                if(index==3) {
                    wifiposdesc->rssi3 = *((u_int32_t *)p);
                }

                p += sizeof(u_int32_t);
                if(report_type == WMI_RTT_REPORT_CFR) {
                    tmp = p + bw_size[bw]; //end of this chains channel dump
                    wifiposdesc->txrxchain_mask = tone_number[bw];
                    temp2 = temp2 + bw_size[bw];
                    for(index1 = 0; index1 < tone_number[bw]; index1++){
                        adf_os_print("%.4x ", *((u_int16_t *)(p)));
                        memcpy(temp1, p, 2);
                        temp1+=2;
                        p+=2;
                    }
                    temp1 = temp2;
                    p = tmp; //alignment adjustment
                }
            }
        }
        adf_os_print("RTTREPORT RSSI %.8x %.8x %.8x %.8x\n", wifiposdesc->rssi0, wifiposdesc->rssi1, wifiposdesc->rssi2, wifiposdesc->rssi3);
        temp1 = wifiposdesc->hdump;
    } else {
        adf_os_print("Error! body is NULL\n") ;
    }

    return;
}


/*
 * event handler for  RTT measurement response
 * data  -- rtt measurement response from fw
 */

static int
wmi_rtt_meas_report_event_handler(ol_scn_t scn, u_int8_t *data,
                    u_int16_t datalen, void *context)
{
    u_int8_t meas_type, report_type;
#if !ATH_SUPPORT_LOWI
    struct ieee80211com *ic = &scn->sc_ic;
#endif
    ieee80211_ol_wifiposdesc_t *wifiposdesc;
	wifiposdesc = (ieee80211_ol_wifiposdesc_t *)OS_MALLOC(scn->sc_osdev, sizeof(* wifiposdesc), GFP_KERNEL);
    if (wifiposdesc == NULL) {
        adf_os_print("\n Unable to allocate memory for WIFIPOS desc \n");
        return -1;
    }

    wifiposdesc->hdump = (u_int8_t *)OS_MALLOC(scn->sc_osdev, 324, GFP_KERNEL);
    if (wifiposdesc->hdump == NULL) {
        OS_FREE(wifiposdesc);
        adf_os_print("\n Unable to allocate memory for WIFIPOS desc \n");
        return -1;
    }

    if (!data) {
        adf_os_print("Get NULL point message from FW\n");
        return -1;
    }
    rtt_print_resp_header((wmi_rtt_event_hdr *)data, & meas_type, &report_type, wifiposdesc);
    rtt_print_meas_resp_body((wmi_rtt_meas_event *)data, meas_type, report_type, wifiposdesc);
#if !ATH_SUPPORT_LOWI
    if (meas_type < RTT3_FRAME_TYPE) {
        ic->ic_update_wifipos_stats(ic, (ieee80211_ol_wifiposdesc_t *)wifiposdesc);
    }
#endif
    OS_FREE(wifiposdesc->hdump);
    OS_FREE(wifiposdesc);
    return 0;
}

/*
 * event handler for TSF measurement response
 * data  -- TSF measurement response from fw
 */
static int
wmi_tsf_meas_report_event_handle(ol_scn_t scn, u_int8_t *data,
                    u_int16_t datalen, void *context)

{
  //ToDo
  return 0;

}

/*
 * event handler for RTT Error report
 * data  -- rtt measurement response from fw
 */
static int
wmi_error_report_event_handle(ol_scn_t scn, u_int8_t *data,
                    u_int16_t datalen, void *context)
{
    u_int8_t report_type, frame_type;
#if !ATH_SUPPORT_LOWI
    struct ieee80211com *ic = &scn->sc_ic;
#endif
    ieee80211_ol_wifiposdesc_t * wifiposdesc;
    WMI_RTT_ERROR_INDICATOR * error_index_p;
    WMI_RTT_ERROR_INDICATOR error_index;
    adf_os_print("%s: data=%p, datalen=%u\n", __func__, data, datalen);
    if (!data) {
        adf_os_print("Get NULL point message from FW\n");
        return -1;
    }
	wifiposdesc = (ieee80211_ol_wifiposdesc_t *)OS_MALLOC(scn->sc_osdev, sizeof(* wifiposdesc), GFP_KERNEL);
    if (wifiposdesc == NULL) {
        adf_os_print("\n Unable to allocate memory for WIFIPOS desc \n");
        return -1;
    }
    wifiposdesc->hdump = OS_MALLOC(scn->sc_osdev, 324, GFP_KERNEL);
    if (wifiposdesc->hdump == NULL) {
        OS_FREE(wifiposdesc);
        adf_os_print("\n Unable to allocate memory for WIFIPOS desc \n");
        return -1;
    }

    rtt_print_resp_header((wmi_rtt_event_hdr *)data, &frame_type, &report_type, wifiposdesc);
    printk("\n The meas type is %d\n",frame_type);
    data += sizeof(wmi_rtt_event_hdr);
    adf_os_print("An RTT error occurred: ");
    error_index_p = (WMI_RTT_ERROR_INDICATOR *) data;
    error_index = *error_index_p;
    if (IS_VALID_INDEX_OF_ARRAY(error_indicator, error_index)) {
        adf_os_print("%s\n",error_indicator[error_index] );
    }
    else {
        adf_os_print("Unknown error index (%d)\n", error_index );
    }
    //KW# 6147 adf_os_print("%s\n",error_indicator[*((WMI_RTT_ERROR_INDICATOR *)data)<10 ? *((WMI_RTT_ERROR_INDICATOR *)data) : 1 ] ) ;

    //If the error code < 10, we can use it, otherwise use some valid error-code between 0-9. I used 1 here to signify error.

    //The developer may change add another code or use a completely different logic to handle this

    /* Only 3 type of frames are used for Measurement type ,
       even though  RTT measurement type is 3 bit header */
    adf_os_print("Measurement Type is %s \n", (frame_type < 3)? measurement_type[frame_type]:"Invalid frame type");
    adf_os_print("Report Type is %d\n", report_type);
    // if the frame < 2, then only call the update_stats function(RTT2).
#if !ATH_SUPPORT_LOWI
    if (frame_type < 2) {
        ic->ic_update_wifipos_stats(ic, NULL);
    }
#endif
    OS_FREE(wifiposdesc->hdump);
    OS_FREE(wifiposdesc);

    return 1;
}

/*
 * event handler for keepalive notification
 */
static int
wmi_rtt_keepalive_event_handle(ol_scn_t scn, u_int8_t *data,
                    u_int16_t datalen, void *context)
{
    wmi_rtt_event_hdr *header = (wmi_rtt_event_hdr *)data;
    struct ieee80211com *ic = &scn->sc_ic;
    u_int8_t dest_mac[6];

    adf_os_print("\n\n==================Keepalive Event====================\n");
    adf_os_print("Request ID is:0x%x\n", header->req_id  & 0x0000ffff);
    adf_os_print("Request result is:%d\n", (header->req_id & 0x10000) >> 16);

    WMI_MAC_ADDR_TO_CHAR_ARRAY(&header->dest_mac, dest_mac);
    adf_os_print("Request dest_mac is:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", dest_mac[0],dest_mac[1],
                 dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
    ic->ic_update_ka_done(dest_mac, 1);
    return 0;
}
void
ol_ath_rtt_netlink_attach(struct ieee80211com *ic)
{
    int ret = -1;
    if (ic->ic_rtt_init_netlink) {
        ret = ic->ic_rtt_init_netlink(ic);
        if (ret == 0) {
            atomic_inc(&rtt_nl_users);
        }
    }
}

void
ol_if_rtt_detach(struct ieee80211com *ic)
{
    struct ieee80211com *ic_tmp;
    int i = 0;
    struct ol_ath_softc_net80211 *scn = NULL;
    for (i = 0; i < ol_num_global_scn; i++) {
        scn = ol_global_scn[i];
        if (scn == NULL)
            continue;
        ic_tmp = (struct ieee80211com *)scn;
        if (ic_tmp->rtt_sock == NULL) {
            //ic->rtt_sock = ic_tmp->rtt_sock;
            printk("%s: Socket already released %p\n", __func__, ic->rtt_sock);
            return;
        }
    }
    if (atomic_dec_and_test(&rtt_nl_users)) {
        OS_SOCKET_RELEASE(ic->rtt_sock);
        ic->rtt_sock = NULL;
        printk(KERN_INFO"\n releasing the socket %p and val of ic is %p\n", ic->rtt_sock, ic);
    }

}
/*
 * RTT measurement response handler attach functions for offload solutions
 */
void
ol_ath_rtt_meas_report_attach(struct ieee80211com *ic)
{

    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);

    adf_os_print(KERN_DEBUG"%s: called\n", __func__);

    /* Register WMI event handlers */
    wmi_unified_register_event_handler(scn->wmi_handle,
        WMI_RTT_MEASUREMENT_REPORT_EVENTID,
        wmi_rtt_meas_report_event_handler,
        NULL);

    wmi_unified_register_event_handler(scn->wmi_handle,
        WMI_TSF_MEASUREMENT_REPORT_EVENTID,
        wmi_tsf_meas_report_event_handle,
        NULL);

    wmi_unified_register_event_handler(scn->wmi_handle,
        WMI_RTT_ERROR_REPORT_EVENTID,
        wmi_error_report_event_handle,
        NULL);

    wmi_unified_register_event_handler(scn->wmi_handle,
        WMI_RTT_KEEPALIVE_EVENTID,
        wmi_rtt_keepalive_event_handle,
        NULL);

    return;

}

typedef struct {
    wmi_channel *channel;
    struct ieee80211com *ic;
} channel_search;





/*
 * Find the channel information according to the scan entry
 */
int rtt_find_channel_info (void *arg, wlan_scan_entry_t scan_entry)
{
    wmi_channel *wmi_chan;
    u_int32_t chan_mode;
    struct ieee80211com *ic;
    struct ieee80211_channel *se_chan;
    static const u_int modeflags[] = {
        0,                            /* IEEE80211_MODE_AUTO           */
        MODE_11A,         /* IEEE80211_MODE_11A            */
        MODE_11B,         /* IEEE80211_MODE_11B            */
        MODE_11G,         /* IEEE80211_MODE_11G            */
        0,                            /* IEEE80211_MODE_FH             */
        0,                            /* IEEE80211_MODE_TURBO_A        */
        0,                            /* IEEE80211_MODE_TURBO_G        */
        MODE_11NA_HT20,   /* IEEE80211_MODE_11NA_HT20      */
        MODE_11NG_HT20,   /* IEEE80211_MODE_11NG_HT20      */
        MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40PLUS  */
        MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40MINUS */
        MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40PLUS  */
        MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40MINUS */
        MODE_11NG_HT40,   /* IEEE80211_MODE_11NG_HT40      */
        MODE_11NA_HT40,   /* IEEE80211_MODE_11NA_HT40      */
        MODE_11AC_VHT20,  /* IEEE80211_MODE_11AC_VHT20     */
        MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40PLUS */
        MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40MINUS*/
        MODE_11AC_VHT40,  /* IEEE80211_MODE_11AC_VHT40     */
        MODE_11AC_VHT80,  /* IEEE80211_MODE_11AC_VHT80     */
	MODE_11AC_VHT160, /* IEEE80211_MODE_11AC_VHT160    */
	MODE_11AC_VHT80_80,/* IEEE80211_MODE_11AC_VHT80_80 */
    };

    adf_os_print("%s:\n", __func__);

    if (!(arg && scan_entry)) {
        return -1; //critical error
    }

    wmi_chan = ((channel_search *)arg)->channel;
    ic = ((channel_search *)arg)->ic;

    if(!(wmi_chan && ic)) {
        return -1; //critical error
    }

    se_chan = wlan_scan_entry_channel(scan_entry);

    if(!se_chan) {
        return -1; //critical error
    }

    wmi_chan->mhz = ieee80211_chan2freq(ic,se_chan);
    chan_mode = ieee80211_chan2mode(se_chan);
    WMI_SET_CHANNEL_MODE(wmi_chan, modeflags[chan_mode]);

    if(chan_mode == IEEE80211_MODE_11AC_VHT80) {
        if (se_chan->ic_ieee < IS_2GHZ_CH) {
            wmi_chan->band_center_freq1 = ieee80211_ieee2mhz(
                                             ic,
                                             se_chan->ic_vhtop_ch_freq_seg1,
                                             IEEE80211_CHAN_2GHZ);
        } else {
            wmi_chan->band_center_freq1 = ieee80211_ieee2mhz(
                                            ic,
                                            se_chan->ic_vhtop_ch_freq_seg1,
                                            IEEE80211_CHAN_5GHZ);
        }
    } else if((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) ||
              (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
              (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS)) {
        wmi_chan->band_center_freq1 = wmi_chan->mhz + 10;
    } else if((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) ||
              (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
              (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS)) {
        wmi_chan->band_center_freq1 = wmi_chan->mhz - 10;
    } else {
        wmi_chan->band_center_freq1 = wmi_chan->mhz;
    }

    /* we do not support HT80PLUS80 yet */
    wmi_chan->band_center_freq2=0;
    WMI_SET_CHANNEL_MIN_POWER(wmi_chan, se_chan->ic_minpower);
    WMI_SET_CHANNEL_MAX_POWER(wmi_chan, se_chan->ic_maxpower);
    WMI_SET_CHANNEL_REG_POWER(wmi_chan, se_chan->ic_maxregpower);
    WMI_SET_CHANNEL_ANTENNA_MAX(wmi_chan, se_chan->ic_antennamax);
    WMI_SET_CHANNEL_REG_CLASSID(wmi_chan, se_chan->ic_regClassId);

    if (IEEE80211_IS_CHAN_DFS(se_chan))
        WMI_SET_CHANNEL_FLAG(wmi_chan, WMI_CHAN_FLAG_DFS);

    adf_os_print("WMI channel freq=%d, mode=%x band_center_freq1=%d\n", wmi_chan->mhz,
        WMI_GET_CHANNEL_MODE(wmi_chan), wmi_chan->band_center_freq1);

    return 1; //seccessful!
}

#define RTT_TEST 1

#if RTT_TEST

#define RTT_REQ_FRAME_TYPE_LSB    (0)
#define RTT_REQ_FRAME_TYPE_MASK   (0x3 << RTT_REQ_FRAME_TYPE_LSB)
#define RTT_REQ_BW_LSB            (2)
#define RTT_REQ_BW_MASK           (0x3 << RTT_REQ_BW_LSB)
#define RTT_REQ_PREAMBLE_LSB      (4)
#define RTT_REQ_PREAMBLE_MASK     (0x3 << RTT_REQ_PREAMBLE_LSB)
#define RTT_REQ_NUM_REQ_LSB       (6)
#define RTT_REQ_NUM_REQ_MASK      (0xf << RTT_REQ_NUM_REQ_LSB)
#define RTT_REQ_REPORT_TYPE_LSB   (10)
#define RTT_REQ_REPORT_TYPE_MASK  (0x3 << RTT_REQ_REPORT_TYPE_LSB)
#define RTT_REQ_NUM_MEASUREMENTS_LSB   (12)
#define RTT_REQ_NUM_MEASUREMENTS_MASK  (0x1f << RTT_REQ_NUM_MEASUREMENTS_LSB)
#define RTT_REQ_ASAP_MODE_LSB   (20)
#define RTT_REQ_ASAP_MODE_MASK  (0x1 << RTT_REQ_ASAP_MODE_LSB)
#define RTT_REQ_LCI_REQUESTED_LSB   (21)
#define RTT_REQ_LCI_REQUESTED_MASK  (0x1 << RTT_REQ_LCI_REQUESTED_LSB)
#define RTT_REQ_LOC_CIV_REQUESTED_LSB   (22)
#define RTT_REQ_LOC_CIV_REQUESTED_MASK  (0x1 << RTT_REQ_LOC_CIV_REQUESTED_LSB)


void ol_ath_rtt_meas_req_test(wmi_unified_t  wmi_handle, struct ieee80211com *ic, u_int8_t *mac_addr, int extra)
{
  //struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    wmi_buf_t buf;
    u_int8_t *p;
    int ret;
    u_int16_t len;
    u_int8_t peer[6];  //ap
    u_int8_t spoof[6];
    wmi_rtt_measreq_head *head;
    wmi_rtt_measreq_body *body;
    struct ieee80211vap *vap;
    static u_int8_t req_id = 1;
    channel_search channel_search_info;
    int req_frame_type, req_bw, req_preamble;
    int req_num_req, req_report_type;
    u_int32_t num_measurements;
    u_int32_t asap_mode;
    u_int32_t lci_requested;
    u_int32_t loc_civ_requested;

    adf_os_print("%s:\n", __func__);
    if(!wmi_handle) {
        adf_os_print("WMI ERROR:Invalid wmi_handle  ");
        req_id++;
        return;
    }

    //for test purpose, assume there is only one vap
    vap = TAILQ_FIRST(&(ic)->ic_vaps) ;

    req_num_req = MS(extra, RTT_REQ_NUM_REQ) + 1;   /* 1 more, so that 0 -> 1 */

    len = sizeof(wmi_rtt_measreq_head) + req_num_req * sizeof(wmi_rtt_measreq_body);

    buf = wmi_buf_alloc(wmi_handle, len);
    if(!buf){
      adf_os_print("No WMI resource!");
        return;
    }

    p = (u_int8_t *) wmi_buf_data(buf);
    memset(p, 0, len);

    //encode header
    head = (wmi_rtt_measreq_head *) p;
    //head->req_id = req_id;
    WMI_RTT_REQ_ID_SET(head->req_id, req_id);
    WMI_RTT_SPS_SET(head->req_id, 1);

    WMI_RTT_NUM_STA_SET(head->sta_num, req_num_req);

    req_frame_type  = MS(extra, RTT_REQ_FRAME_TYPE);
    req_bw          = MS(extra, RTT_REQ_BW);
    req_preamble    = MS(extra, RTT_REQ_PREAMBLE);
    req_report_type = MS(extra, RTT_REQ_REPORT_TYPE);
    if(req_report_type < WMI_RTT_AGGREAGET_REPORT_NON_CFR) {
        req_report_type ^= 1;   /* In command line, 0 - FAC, 1 - CFR, need to revert here */
    }

    num_measurements = MS(extra, RTT_REQ_NUM_MEASUREMENTS);
    if (num_measurements == 0) {
        num_measurements = 25;
    }

    asap_mode = MS(extra, RTT_REQ_ASAP_MODE);
    loc_civ_requested = MS(extra, RTT_REQ_LOC_CIV_REQUESTED);
    lci_requested = MS(extra, RTT_REQ_LCI_REQUESTED);

    //encode common parts for each RTT measurement command body
    //The value here can be overwrite in following each req hardcoding
    body = &(head->body[0]);
    //set vdev_id
    WMI_RTT_VDEV_ID_SET(body-> measure_info, 0);
    //set timeout = 100ms
    WMI_RTT_TIMEOUT_SET(body->measure_info, 100);
    //set report type = 0
    WMI_RTT_REPORT_TYPE_SET(body->measure_info, req_report_type);
    //set QOS_NULL frame, peer surpport TM OPT, TX chain mask
    WMI_RTT_FRAME_TYPE_SET(body->control_flag, req_frame_type);

    //set Tx chain mask
    WMI_RTT_TX_CHAIN_SET(body->control_flag, 001);
    //set peer is QCA device
    WMI_RTT_QCA_PEER_SET(body->control_flag, 1);
    //set rate MCS
    if(req_preamble == WMI_RTT_PREAM_LEGACY)
        WMI_RTT_MCS_SET(body->control_flag, 3);
    else
        WMI_RTT_MCS_SET(body->control_flag, 0);
    //set HW retry time
    WMI_RTT_RETRIES_SET(body->control_flag, 1);

    OS_MEMCPY(peer, mac_addr, 6);

    adf_os_print("The mac_addr is"
                 " %.2x:%.2x:%.2x:%.2x:%.2x:%.2x extra=%d\n", peer[0],peer[1], peer[2],
                                               peer[3], peer[4],peer[5], extra);

    //start from here, embed the first req in each RTT measurement Command
    /*peer[5] = 0x12;
    peer[4] = 0x90;
    peer[3] = 0x78;
    peer[2] = 0x56;
    peer[1] = 0x34;
    peer[0] = 0x12;
	*/
    //find channel from the peer mac of first request
    channel_search_info.channel = (wmi_channel *)&head->channel;
    channel_search_info.ic = ic;
    ret = wlan_scan_macaddr_iterate(vap, &peer[0], rtt_find_channel_info, &channel_search_info);

    if (!ret) {
        adf_os_print("Can not find corresponding channel info %d of "
                     "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", ret, peer[0],peer[1], peer[2],
                     peer[3], peer[4],peer[5]);
        req_id++;
        return;
    } else if (ret == -1){
        req_id++;
        adf_os_print("critical error %d", ret);
        return;
    }

    WMI_CHAR_ARRAY_TO_MAC_ADDR(((u_int8_t *)peer),&body->dest_mac) ;
    memset(spoof, 0 , 6);
    WMI_CHAR_ARRAY_TO_MAC_ADDR(((u_int8_t *)peer),&body->spoof_bssid) ;

    //embedded varing part of each request
    //set Preamble, BW, measurement times
    WMI_RTT_BW_SET(body->control_flag, req_bw);
    WMI_RTT_PREAMBLE_SET(body->control_flag, req_preamble);
    WMI_RTT_MEAS_NUM_SET(body->measure_info, num_measurements);

    body->measure_params_1 = 0;
    body->measure_params_2 = 0;

    WMI_RTT_ASAP_MODE_SET(body->measure_params_1, asap_mode);
    WMI_RTT_LCI_REQ_SET(body->measure_params_1, lci_requested);
    WMI_RTT_LOC_CIV_REQ_SET(body->measure_params_1, loc_civ_requested);
    WMI_RTT_NUM_BURST_EXP_SET(body->measure_params_1, 0);
    WMI_RTT_BURST_DUR_SET(body->measure_params_1, 15);
    WMI_RTT_BURST_PERIOD_SET(body->measure_params_1, 0);
    WMI_RTT_TSF_DELTA_VALID_SET(body->measure_params_1, 1);
    WMI_RTT_TSF_DELTA_SET(body->measure_params_2, 0);

    /* other requests are same with first request */
    p = (u_int8_t *) body;
    while(--req_num_req) {
        body++;
        memcpy(body, p, sizeof(wmi_rtt_measreq_body));
    }

    ret = wmi_unified_cmd_send(wmi_handle, buf, len, WMI_RTT_MEASREQ_CMDID);
    adf_os_print("send rtt cmd to FW with length %d and return %d\n", len, ret);
    req_id++;
}
#endif
/*
 * Send RTT measurement Command to FW (for test purpose only) here we encode two
 * STA request in each measurement comments If you need change the embedded
 * value, please search the corresponding macro in wmi_unified.h and choose the
 * macro you want to use.
 */

void
ol_ath_rtt_meas_req(wmi_unified_t  wmi_handle, struct ieee80211com *ic,
                    struct ieee80211vap *vap, ieee80211_wifipos_reqdata_t *reqdata)
{
    wmi_buf_t buf;
    u_int8_t *p, vdev_id;
    int ret;
    u_int16_t len;
    u_int8_t peer[6];  //ap
    u_int8_t spoof[6];
    u_int32_t chan_mode;
    wmi_rtt_measreq_head *head;
    wmi_rtt_measreq_body *body;
    //struct ieee80211vap *vap;
    u_int16_t req_id = reqdata->request_id;
    int req_frame_type, req_preamble;
    struct ieee80211_channel      *chan;
    wmi_channel *w_chan;
    u_int16_t       freq;
    u_int32_t req_report_type;
    u_int32_t asap_mode =0;
    u_int32_t lci_requested;
    u_int32_t loc_civ_requested;
    int burst_exp, burst_period, ftm_per_burst = 0;
    int burst_dur = RTT3_DEFAULT_BURST_DURATION;

    adf_os_print("%s: The request ID is: %d\n", __func__, req_id);
    if(!wmi_handle) {
        adf_os_print("WMI ERROR:Invalid wmi_handle  ");
        req_id++;
        return;
    }

    //for test purpose, assume there is only one vap
    //vap = TAILQ_FIRST(&(ic)->ic_vaps) ;

    /* Temporarily, hardcoding peer mac address for test purpose will be removed
     * once RTT host has been developed for even req_id, loke 0, 2, 4, there is
     * no channel_swicth for odd req_id, like 1, 3 ,5, there is channel switch
     * currently, for both cases, we have 3 req in each command please change
     * here if you only have one (or just let it be). Even == HC, odd == OC.
     */
    if(!(req_id & 0x1)) {
        len = sizeof(wmi_rtt_measreq_head);// + 2 * sizeof(wmi_rtt_measreq_body);
    } else {
        len = sizeof(wmi_rtt_measreq_head);// + 2 * sizeof(wmi_rtt_measreq_body);
    }

    buf = wmi_buf_alloc(wmi_handle, len);
    if(!buf){
      adf_os_print("No WMI resource!");
        return;
    }

    p = (u_int8_t *) wmi_buf_data(buf);
    memset(p,0,len);


//#define RTT_TEST
    //encode header
    head = (wmi_rtt_measreq_head *) p;
    //head->req_id = req_id;
    WMI_RTT_REQ_ID_SET(head->req_id, req_id);
//    WMI_RTT_SPS_SET(head->req_id, 1);

    if(!(req_id & 0x1)) {//even req id
#ifndef RTT_TEST
        //we actually only have 3 sta to measure
        //this is used to test over limit request protection
        //XIN:WMI_RTT_NUM_STA_SET(head->sta_num, 5);
#else
        //XIN:WMI_RTT_NUM_STA_SET(head->sta_num, 2);
        WMI_RTT_NUM_STA_SET(head->sta_num, 1);
#endif
        WMI_RTT_NUM_STA_SET(head->sta_num, 1);
    } else { //odd req id
        //XIN:WMI_RTT_NUM_STA_SET(head->sta_num, 3);
        WMI_RTT_NUM_STA_SET(head->sta_num, 1);

    }

    req_frame_type = reqdata->pkt_type;
    req_report_type = reqdata->req_report_type; //MS(extra, RTT_REQ_REPORT_TYPE);
    req_preamble   = reqdata->req_preamble;
    if(req_report_type < WMI_RTT_AGGREAGET_REPORT_NON_CFR) {
       req_report_type ^= 1;   /* In command line, 0 - FAC, 1 - CFR, need to revert here */
     }
    asap_mode = reqdata->asap_mode; //MS(extra, RTT_REQ_ASAP_MODE);
    loc_civ_requested = reqdata->loc_civ_req; //MS(extra, RTT_REQ_LOC_CIV_REQUESTED);
    lci_requested = reqdata->lci_req; //MS(extra, RTT_REQ_LCI_REQUESTED);
    burst_exp = reqdata->burst_exp;
    burst_dur = reqdata->burst_dur;
    burst_period = reqdata->burst_period;
    ftm_per_burst = reqdata->ftm_per_burst;

    //encode common parts for each RTT measurement command body
    //The value here can be overwrite in following each req hardcoding
    body = &(head->body[0]);
    //set vdev_id
    vdev_id = (OL_ATH_VAP_NET80211(vap))->av_if_id;
    WMI_RTT_VDEV_ID_SET(body-> measure_info, vdev_id);
    //set timeout = 500ms
    WMI_RTT_TIMEOUT_SET(body->measure_info, RTT_TIMEOUT_MS);
    //set report type = 0
    //if (reqdata->mode & 0x1000)
    WMI_RTT_REPORT_TYPE_SET(body->measure_info, 1);
    //set QOS_NULL frame, peer surpport TM OPT, TX chain mask
    WMI_RTT_FRAME_TYPE_SET(body->control_flag, req_frame_type);
    //set Tx chain mask
    WMI_RTT_TX_CHAIN_SET(body->control_flag, 001);
    //set peer is QCA device
    WMI_RTT_QCA_PEER_SET(body->control_flag, 1);
    //set rate MCS
    if(req_preamble == WMI_RTT_PREAM_LEGACY)
        WMI_RTT_MCS_SET(body->control_flag, 3);
    else
        WMI_RTT_MCS_SET(body->control_flag, 0);
    //set HW retry time
    WMI_RTT_RETRIES_SET(body->control_flag, 1);

    //start from here, embed the first req in each RTT measurement Command
    if(!(req_id & 0x1)) { // even time
	OS_MEMCPY(peer, reqdata->sta_mac_addr, 6);
    } else { //odd time
        OS_MEMCPY(peer, reqdata->sta_mac_addr, 6);
    }
    if(reqdata->oc_channel != ic->ic_curchan->ic_ieee) {
        if (reqdata->oc_channel < IS_2GHZ_CH) {
            head->channel.mhz = ieee80211_ieee2mhz(ic,reqdata->oc_channel,IEEE80211_CHAN_2GHZ);
        }
        else {
            head->channel.mhz = ieee80211_ieee2mhz(ic,reqdata->oc_channel,IEEE80211_CHAN_5GHZ);
        }
        chan = ol_ath_find_full_channel(ic, head->channel.mhz);
        if (chan) {
        chan_mode = ieee80211_chan2mode(chan);
        freq = chan->ic_freq;
        if(chan_mode == IEEE80211_MODE_11AC_VHT80) {
        if (chan->ic_ieee < IS_2GHZ_CH)
            head->channel.band_center_freq1 = ieee80211_ieee2mhz(ic,
                                        chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_2GHZ);
        else
            head->channel.band_center_freq1 = ieee80211_ieee2mhz(ic,
                                        chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_5GHZ);
        } else if((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) || (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                   (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS)) {
            head->channel.band_center_freq1 = freq + 10;
        } else if((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) || (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                   (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS)) {
                   head->channel.band_center_freq1 = freq - 10;
                   } else {
                   head->channel.band_center_freq1 = freq;
                   }
                   /* we do not support HT80PLUS80 yet */
       head->channel.band_center_freq2=0;

        w_chan = (wmi_channel *)&head->channel;
        WMI_SET_CHANNEL_MIN_POWER(w_chan, chan->ic_minpower);
        WMI_SET_CHANNEL_MAX_POWER(w_chan, chan->ic_maxpower);
        WMI_SET_CHANNEL_REG_POWER(w_chan, chan->ic_maxregpower);
        WMI_SET_CHANNEL_ANTENNA_MAX(w_chan, chan->ic_antennamax);
        WMI_SET_CHANNEL_REG_CLASSID(w_chan, chan->ic_regClassId);
        if (chan->ic_ieee < IS_2GHZ_CH) {
            WMI_SET_CHANNEL_MODE(w_chan, MODE_11NG_HT20);
        }
        else {
            WMI_SET_CHANNEL_MODE(w_chan, MODE_11NA_HT20);
        }
        if (IEEE80211_IS_CHAN_DFS(ic->ic_curchan))
            WMI_SET_CHANNEL_FLAG(w_chan, WMI_CHAN_FLAG_DFS);

        head->channel.band_center_freq2 = 0;
    }
    }
    else {
        if (reqdata->hc_channel < IS_2GHZ_CH) {
            head->channel.mhz = ieee80211_ieee2mhz(ic,reqdata->hc_channel,IEEE80211_CHAN_2GHZ);
        }
        else {
            head->channel.mhz = ieee80211_ieee2mhz(ic,reqdata->hc_channel,IEEE80211_CHAN_5GHZ);
        }
        chan = ol_ath_find_full_channel(ic, head->channel.mhz);
        if (chan) {
        chan_mode = ieee80211_chan2mode(chan);
        freq = chan->ic_freq;
        if(chan_mode == IEEE80211_MODE_11AC_VHT80) {
        if (chan->ic_ieee < IS_2GHZ_CH)
            head->channel.band_center_freq1 = ieee80211_ieee2mhz(ic,
                                        chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_2GHZ);
        else
            head->channel.band_center_freq1 = ieee80211_ieee2mhz(ic,
                                        chan->ic_vhtop_ch_freq_seg1, IEEE80211_CHAN_5GHZ);
        } else if((chan_mode == IEEE80211_MODE_11NA_HT40PLUS) || (chan_mode == IEEE80211_MODE_11NG_HT40PLUS) ||
                   (chan_mode == IEEE80211_MODE_11AC_VHT40PLUS)) {
            head->channel.band_center_freq1 = freq + 10;
        } else if((chan_mode == IEEE80211_MODE_11NA_HT40MINUS) || (chan_mode == IEEE80211_MODE_11NG_HT40MINUS) ||
                   (chan_mode == IEEE80211_MODE_11AC_VHT40MINUS)) {
                   head->channel.band_center_freq1 = freq - 10;
                   } else {
                   head->channel.band_center_freq1 = freq;
                   }
                   /* we do not support HT80PLUS80 yet */
       head->channel.band_center_freq2=0;

        w_chan = (wmi_channel *)&head->channel;
        WMI_SET_CHANNEL_MIN_POWER(w_chan, chan->ic_minpower);
        WMI_SET_CHANNEL_MAX_POWER(w_chan, chan->ic_maxpower);
        WMI_SET_CHANNEL_REG_POWER(w_chan, chan->ic_maxregpower);
        WMI_SET_CHANNEL_ANTENNA_MAX(w_chan, chan->ic_antennamax);
        WMI_SET_CHANNEL_REG_CLASSID(w_chan, chan->ic_regClassId);
        if (chan->ic_ieee < IS_2GHZ_CH) {
            WMI_SET_CHANNEL_MODE(w_chan, MODE_11NG_HT20);
        }
        else {
            WMI_SET_CHANNEL_MODE(w_chan, MODE_11NA_HT20);
        }
        if (IEEE80211_IS_CHAN_DFS(ic->ic_curchan))
            WMI_SET_CHANNEL_FLAG(w_chan, WMI_CHAN_FLAG_DFS);

        head->channel.band_center_freq2 = 0;

    }
    }

    WMI_CHAR_ARRAY_TO_MAC_ADDR(((u_int8_t *)peer),&body->dest_mac) ;
    memset(spoof, 0 , 6);
    WMI_CHAR_ARRAY_TO_MAC_ADDR(((u_int8_t *)reqdata->spoof_mac_addr),&body->spoof_bssid) ;

    //embedded varing part of each request
    //set Preamble, BW, measurement times
    WMI_RTT_BW_SET(body->control_flag, reqdata->bandwidth);
    WMI_RTT_PREAMBLE_SET(body->control_flag, req_preamble);
    WMI_RTT_MEAS_NUM_SET(body->measure_info, ftm_per_burst);

    body->measure_params_1 = 0;
    body->measure_params_2 = 0;

    WMI_RTT_ASAP_MODE_SET(body->measure_params_1, asap_mode);
    WMI_RTT_LCI_REQ_SET(body->measure_params_1, lci_requested);
    WMI_RTT_LOC_CIV_REQ_SET(body->measure_params_1, loc_civ_requested);
    WMI_RTT_NUM_BURST_EXP_SET(body->measure_params_1, burst_exp);
    WMI_RTT_BURST_DUR_SET(body->measure_params_1, burst_dur);
    WMI_RTT_BURST_PERIOD_SET(body->measure_params_1, burst_period);
    WMI_RTT_TSF_DELTA_VALID_SET(body->measure_params_1, 1);
    WMI_RTT_TSF_DELTA_SET(body->measure_params_2, 0);

    ret = wmi_unified_cmd_send(wmi_handle, buf, len, WMI_RTT_MEASREQ_CMDID);
    adf_os_print("send rtt cmd to FW with length %d and return %d\n", len, ret);

    adf_os_print("Sending Request: pkt_type:%d, req_report_type:%d, bandwidth:%d, asap:%d, ftm_per_burst: %d, burstexp:%d, burstperiod:%d, burst_dur:%d\n", req_frame_type, req_report_type, reqdata->bandwidth, asap_mode, ftm_per_burst, burst_exp, burst_period, burst_dur);
}

/*
 * Send Keepalive command to FW to probe a single associated station.
 * Make sure the client is awake before sending RTT measurement command.
 */
void
ol_ath_rtt_keepalive_req(struct ieee80211vap *vap,
                         struct ieee80211_node *ni, bool stop)
{
    wmi_buf_t buf;
    wmi_unified_t  wmi_handle;
    wmi_rtt_keepalive_cmd *cmd;
    int ret;
    u_int16_t len;
    u_int8_t *ptr;
    static u_int16_t req_id = 1;
    struct ieee80211com *ic;
    struct ol_ath_softc_net80211 *scn;

    if (ni == NULL) {
        return;
    }

    ic = ni->ni_ic;
    scn = OL_ATH_SOFTC_NET80211(ic);

    stop = 0;

    if ((!vap || !ni) || (vap != ni->ni_vap)) {
        adf_os_print("%s: Invalid parameter\n", __func__);
        req_id++;
        return;
    }
    wmi_handle = scn->wmi_handle;
    if(!wmi_handle) {
        adf_os_print("%s: Invalid parameter\n", __func__);
        req_id++;
        return;
    }
    len = sizeof(wmi_rtt_keepalive_cmd);
    buf = wmi_buf_alloc(wmi_handle, len);
    if(!buf) {
        adf_os_print("No WMI resource\n");
        return;
    }
    ptr = (u_int8_t *)wmi_buf_data(buf);
    OS_MEMSET(ptr, 0, len);

    cmd = (wmi_rtt_keepalive_cmd *)wmi_buf_data(buf);

    WMI_RTT_REQ_ID_SET(cmd->req_id, req_id);
    WMI_RTT_KEEPALIVE_ACTION_SET(cmd->req_id, stop);
    WMI_RTT_VDEV_ID_SET(cmd->probe_info, (OL_ATH_VAP_NET80211(vap))->av_if_id);
    /* 3ms probe interval by default */
    WMI_RTT_KEEPALIVE_PERIOD_SET(cmd->probe_info, 3);
    /* max retry of 50 by default */
    WMI_RTT_TIMEOUT_SET(cmd->probe_info, 20);
    /* set frame type */
    WMI_RTT_FRAME_TYPE_SET(cmd->control_flag, RTT_MEAS_FRAME_KEEPALIVE);

    WMI_CHAR_ARRAY_TO_MAC_ADDR(ni->ni_macaddr, &cmd->sta_mac);

    ret = wmi_unified_cmd_send(wmi_handle, buf, len, WMI_RTT_KEEPALIVE_CMDID);
    adf_os_print("send rtt keepalive cmd to FW with length %d and return %d\n", len, ret);
    req_id++;

    return;
}

extern u_int32_t ap_lcr[RTT_LOC_CIVIC_REPORT_LEN];
extern int num_ap_lci;
extern u_int32_t ap_lci[RTT_LOC_CIVIC_INFO_LEN];
extern int num_ap_lcr;

/* Function called by VAP iterator that adds active vaps as colocated bssids */
void ieee80211_vap_iter_get_colocated_bss(void *arg, wlan_if_t vap)
{
    /* This function is called iteratively for each active VAP and populate params array */
    /* params[]: subelementId (1octet), num_vaps(1 octet), maxbssidInd (1octect), BSSIDs...(each 6 octets) */
    u_int8_t *params, num_vaps;
    params = (u_int8_t *) arg;
    params[0]=IEEE80211_SUBIE_COLOCATED_BSSID; //Colocated BSSID Subelement ID
    params[2]=MAXBSSID_INDICATOR_DEFAULT; //MaxBSSID Indicator: Default: 0
    /* params[1] contains num_vaps added so far */
    num_vaps = params[1];

    /* If an active vap, add it to correct location in params */
    if (ieee80211_vap_ready_is_set(vap)) {
        /* Position to store this vap: First 3 octets + 6*(Num of Vaps already added) */
        /* Position is always w.r.t params as there could already be non-zero num_vaps(bssids) */
        /* stored in the params array previously or coming into the function */
        memcpy(params+((num_vaps*IEEE80211_ADDR_LEN)+3), vap->iv_myaddr, IEEE80211_ADDR_LEN);
        params[1]++;
    }
}

int ol_ath_lci_set(wmi_unified_t  wmi_handle, struct ieee80211com *ic,
                    void *lci_data)
{
    wmi_buf_t buf;
    u_int8_t *p;
    wmi_oem_measreq_head *head;
    int len;
    u_int8_t colocated_bss[IEEE80211_COLOCATED_BSS_MAX_LEN]={0};

    wmi_rtt_lci_cfg_head *rtt_req;
    struct ieee80211_lci_subelement_info lci_sub;
    rtt_req = (wmi_rtt_lci_cfg_head *) lci_data;

    /* Get colocated bss and populate colocated_bssid_info field in wmi_rtt_lci_cfg_head */
    wlan_iterate_vap_list(ic, ieee80211_vap_iter_get_colocated_bss,(void *) &colocated_bss);

    /* colocated_bss[1] contains num of vaps */
    /* Provide colocated bssid subIE only when there are 2 vaps or more */
    if(colocated_bss[1] > 1) {
        adf_os_print("%s: Adding %d co-located BSSIDs \n", __func__, colocated_bss[1]);
        /* Convert num_vaps to octets: 6*Num_of_vap + 1 (Max BSSID Indicator field) */
        colocated_bss[1] = (colocated_bss[1]*IEEE80211_ADDR_LEN)+1;
        memcpy(rtt_req->colocated_bssids_info, colocated_bss, colocated_bss[1]+2);
        rtt_req->co_located_bssid_len = colocated_bss[1]+2;
    }
    len = sizeof(wmi_oem_measreq_head)+sizeof(wmi_rtt_lci_cfg_head);

    buf = wmi_buf_alloc(wmi_handle, len);
    if(!buf){
      adf_os_print("No WMI resource!");
        return -1;
    }

    p = (u_int8_t *) wmi_buf_data(buf);
    memset(p, 0, len);

    head = (wmi_oem_measreq_head *)p;
    head->sub_type = TARGET_OEM_CONFIGURE_LCI;
    OL_IF_MSG_COPY_CHAR_ARRAY(&(head->head), lci_data, sizeof(wmi_rtt_lci_cfg_head));
    if(wmi_unified_cmd_send(wmi_handle, buf, len, WMI_OEM_REQ_CMDID)) {
        printk("%s:Unable to set LCI data\n", __func__);
        return -1;
    }

    /* Save LCI data in host buffer */
    {

        lci_sub.latitude_unc = WMI_RTT_LCI_LAT_UNC_GET(rtt_req->lci_cfg_param_info);
        lci_sub.latitude_0_1 = ((A_UINT32)(rtt_req->latitude & 0x3));
        lci_sub.latitude_2_33 = (A_UINT32)(((A_UINT64)(rtt_req->latitude)) >> 2);
        lci_sub.longitude_unc = WMI_RTT_LCI_LON_UNC_GET(rtt_req->lci_cfg_param_info);
        lci_sub.longitude_0_1 = ((A_UINT32)(rtt_req->longitude & 0x3));
        lci_sub.longitude_2_33 = (A_UINT32)(((A_UINT64)(rtt_req->longitude)) >> 2);
        lci_sub.altitude_type = WMI_RTT_LCI_ALT_TYPE_GET(rtt_req->altitude_info);
        lci_sub.altitude_unc_0_3 = (WMI_RTT_LCI_ALT_UNC_GET(rtt_req->altitude_info) & 0xF);
        lci_sub.altitude_unc_4_5 = ((WMI_RTT_LCI_ALT_UNC_GET(rtt_req->altitude_info) >> 4) & 0x3);
        lci_sub.altitude = (rtt_req->altitude & RTT_LCI_ALTITUDE_MASK);
        lci_sub.datum = WMI_RTT_LCI_DATUM_GET(rtt_req->lci_cfg_param_info);
        lci_sub.reg_loc_agmt = WMI_RTT_LCI_REG_LOC_AGMT_GET(rtt_req->lci_cfg_param_info);
        lci_sub.reg_loc_dse = WMI_RTT_LCI_REG_LOC_DSE_GET(rtt_req->lci_cfg_param_info);
        lci_sub.dep_sta = WMI_RTT_LCI_DEP_STA_GET(rtt_req->lci_cfg_param_info);
        lci_sub.version = WMI_RTT_LCI_VERSION_GET(rtt_req->lci_cfg_param_info);

	/* Max size of LCI is 16 octets */
        OL_IF_MSG_COPY_CHAR_ARRAY(ap_lci, &lci_sub, sizeof(struct ieee80211_lci_subelement_info));
        num_ap_lci = 1;
        adf_os_print("Copied LCI num %d to driver cache\n", num_ap_lci);
    }
    return 0;
}

int ol_ath_lcr_set(wmi_unified_t  wmi_handle, struct ieee80211com *ic,
                    void *lcr_data)
{

    wmi_buf_t buf;
    u_int8_t *p;
    wmi_oem_measreq_head *head;
    int len;

    len = sizeof(wmi_oem_measreq_head)+sizeof(wmi_rtt_lcr_cfg_head);

    buf = wmi_buf_alloc(wmi_handle, len);
    if(!buf){
      adf_os_print("No WMI resource!");
        return -1;
    }

    p = (u_int8_t *) wmi_buf_data(buf);
    memset(p, 0, len);

    head = (wmi_oem_measreq_head *)p;
    head->sub_type = TARGET_OEM_CONFIGURE_LCR;
    OL_IF_MSG_COPY_CHAR_ARRAY(&(head->head), lcr_data, sizeof(wmi_rtt_lcr_cfg_head));

    if(wmi_unified_cmd_send(wmi_handle, buf, len, WMI_OEM_REQ_CMDID)) {
        printk("%s:Unable to set LCR data\n", __func__);
        return -1;
    }

    /* Save LCR data in host buffer */
    /* lcr_data is pointing to wmi_rtt_lcr_cfg_head defined in wpc.c, need to move 8 bytes to get to civic_info[64] */
    lcr_data = lcr_data + 8;
    OL_IF_MSG_COPY_CHAR_ARRAY(ap_lcr, lcr_data, RTT_LOC_CIVIC_REPORT_LEN*4); /* Max size for LCR is 256 */

    num_ap_lcr = 1;
    adf_os_print("Copy LCR num %d to driver cache\n", num_ap_lcr);

    return 0;
}

//#if ATH_SUPPORT_WIFIPOS
int ol_ieee80211_wifipos_xmitprobe (struct ieee80211vap *vap,
                                        ieee80211_wifipos_reqdata_t *reqdata)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_rtt_meas_req(scn->wmi_handle, &scn->sc_ic, vap, reqdata);
    return 1;

}

int ol_ieee80211_wifipos_xmitrtt3 (struct ieee80211vap *vap, u_int8_t *mac_addr,
                                        int extra)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_rtt_meas_req_test(scn->wmi_handle, &scn->sc_ic, mac_addr, extra);
    return 0;

}

int ol_ieee80211_lci_set (struct ieee80211vap *vap,
                                        void *reqdata)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_lci_set(scn->wmi_handle, &scn->sc_ic, reqdata);
    return 0;

}

int ol_ieee80211_lcr_set (struct ieee80211vap *vap,
                                        void *reqdata)
{
    struct ieee80211com *ic = vap->iv_ic;
    struct ol_ath_softc_net80211 *scn = OL_ATH_SOFTC_NET80211(ic);
    ol_ath_lcr_set(scn->wmi_handle, &scn->sc_ic, reqdata);
    return 0;

}

#endif

