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
#include "ol_if_athutf.h"
#include "sw_version.h"
#include "targaddrs.h"
#include "ol_helper.h"
#include "adf_os_mem.h"   /* adf_os_mem_alloc,free */
#include "adf_os_types.h" /* adf_os_vprint */

#if ATH_PERF_PWR_OFFLOAD

static int
ol_ath_utf_event(ol_scn_t scn_handle, u_int8_t *data, u_int16_t datalen, void *context)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)scn_handle;
    SEG_HDR_INFO_STRUCT segHdrInfo;
    u_int8_t totalNumOfSegments,currentSeq;

    segHdrInfo = *(SEG_HDR_INFO_STRUCT *)&(data[0]);

    scn->utf_event_info.currentSeq = (segHdrInfo.segmentInfo & 0xF);

    currentSeq = (segHdrInfo.segmentInfo & 0xF);
    totalNumOfSegments = (segHdrInfo.segmentInfo >>4)&0xF;

    datalen = datalen - sizeof(segHdrInfo);

    if ( currentSeq == 0 )
    {
        scn->utf_event_info.expectedSeq = 0;
        scn->utf_event_info.offset = 0;
    }
    else 
    {
        if ( scn->utf_event_info.expectedSeq != currentSeq )
        {
            printk("Mismatch in expecting seq expected Seq %d got seq %d\n",scn->utf_event_info.expectedSeq,currentSeq);
        }
    }

    OS_MEMCPY(&scn->utf_event_info.data[scn->utf_event_info.offset],&data[sizeof(segHdrInfo)],datalen);

    // Adding delay
    OS_DELAY(100);

    scn->utf_event_info.offset = scn->utf_event_info.offset + datalen;
    scn->utf_event_info.expectedSeq++;

    if ( scn->utf_event_info.expectedSeq == totalNumOfSegments )
    {
        if( scn->utf_event_info.offset != segHdrInfo.len )
        {
            printk("All segs received total len mismatch .. len %d total len %d\n",scn->utf_event_info.offset,segHdrInfo.len);
        }

        scn->utf_event_info.length = scn->utf_event_info.offset;
    }

    return 0;
}

void
ol_ath_utf_detach(struct ol_ath_softc_net80211 *scn)
{
    if (scn->utf_event_info.data)
    {
        OS_FREE(scn->utf_event_info.data);
        scn->utf_event_info.data = NULL;
        scn->utf_event_info.length = 0;
        wmi_unified_unregister_event_handler(scn->wmi_handle, WMI_PDEV_UTF_EVENTID);
    }
}

void
ol_ath_utf_attach(struct ol_ath_softc_net80211 *scn)
{
    scn->utf_event_info.data = (unsigned char *)OS_MALLOC((void*)scn->sc_osdev,MAX_UTF_EVENT_LENGTH,GFP_KERNEL);
    scn->utf_event_info.length = 0;

    wmi_unified_register_event_handler(scn->wmi_handle, WMI_PDEV_UTF_EVENTID,
                                       ol_ath_utf_event,
                                       NULL);
}

int
wmi_unified_pdev_utf_cmd(ol_scn_t scn_handle, wmi_unified_t wmi_handle, u_int8_t *utf_payload,
                         u_int32_t len)
{
    wmi_buf_t buf;
    u_int8_t *cmd;
    int ret=0;
    static u_int8_t msgref = 1; /// We can initialize the value and increment..
    u_int8_t segNumber =0,segInfo,numSegments;
    u_int16_t  chunkLen, totalBytes;
    u_int8_t*  bufpos;
    SEG_HDR_INFO_STRUCT segHdrInfo;

    bufpos = utf_payload;
    totalBytes = len;
    numSegments = (totalBytes / MAX_WMI_UTF_LEN );
    OS_MEMSET(&segHdrInfo, 0, sizeof(segHdrInfo));

    if ( len - (numSegments * MAX_WMI_UTF_LEN) )
        numSegments++;

    while (len) {
        if (len > MAX_WMI_UTF_LEN)
            chunkLen = MAX_WMI_UTF_LEN; /* MAX messsage.. */
        else
            chunkLen = len;
 
        buf = wmi_buf_alloc(wmi_handle, (chunkLen + sizeof(segHdrInfo)) );
        if (!buf) {
            printk("%s:wmi_buf_alloc failed\n", __FUNCTION__);
            return -1;
        }

        cmd = (u_int8_t *)wmi_buf_data(buf);

        segHdrInfo.len = totalBytes;
        segHdrInfo.msgref =  msgref;
        segInfo = ((numSegments << 4 ) & 0xF0) | (segNumber & 0xF);
        segHdrInfo.segmentInfo = segInfo;

//        printk("%s:segHdrInfo.len=%d, segHdrInfo.msgref=%d, segHdrInfo.segmentInfo=%d\n",__func__,segHdrInfo.len,segHdrInfo.msgref,segHdrInfo.segmentInfo);

        //printk("%s:totalBytes %d segNumber %d totalSegments %d chunk len %d\n", __FUNCTION__,totalBytes,segNumber,numSegments,chunkLen);

        segNumber++;

        OS_MEMCPY(cmd, &segHdrInfo, sizeof(segHdrInfo)); // 4 bytes..
        OS_MEMCPY(&cmd[sizeof(segHdrInfo)], bufpos, chunkLen);

        ret =  wmi_unified_cmd_send(wmi_handle, buf, (chunkLen + sizeof(segHdrInfo)),
                                WMI_PDEV_UTF_CMDID);

        if (ret != 0 )
	    break;

        len -= chunkLen;
        bufpos += chunkLen;
    }

    msgref++;

    return ret;
}

int
ol_ath_utf_cmd(ol_scn_t scn_handle, u_int8_t *data, u_int16_t len)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)scn_handle;

    scn->utf_event_info.length = 0;

    return wmi_unified_pdev_utf_cmd(scn_handle,scn->wmi_handle,data,len);
}

int
ol_ath_utf_rsp(ol_scn_t scn_handle, u_int8_t *payload)
{
    struct ol_ath_softc_net80211 *scn = (struct ol_ath_softc_net80211 *)scn_handle;

    int ret = -1;
    if ( scn->utf_event_info.length )
    {
        ret = 0;

        *(A_UINT32*)&(payload[0]) = scn->utf_event_info.length;
        OS_MEMCPY((payload+4), scn->utf_event_info.data, scn->utf_event_info.length);

        scn->utf_event_info.length = 0;
    }

    return ret;
}

#endif
