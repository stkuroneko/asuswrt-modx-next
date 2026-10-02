
/*
 * Copyright (c) 2009, Atheros Communications Inc.
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
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <stdarg.h>

#ifndef _BYTE_ORDER
#include <endian.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define _BYTE_ORDER _LITTLE_ENDIAN
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define _BYTE_ORDER _BIG_ENDIAN
#endif
#endif  /* _BYTE_ORDER */
#include "ieee80211_external.h"

#include "if_athioctl.h"
#define _LINUX_TYPES_H
/*
 * Provide dummy defs for kernel types whose definitions are only
 * provided when compiling with __KERNEL__ defined.
 * This is required because ah_internal.h indirectly includes
 * kernel header files, which reference these data types.
 */
#define __be64 u_int64_t
#define __le64 u_int64_t
#define __be32 u_int32_t
#define __le32 u_int32_t
#define __be16 u_int16_t
#define __le16 u_int16_t
#define __be8  u_int8_t
#define __le8  u_int8_t
typedef struct {
        volatile int counter;
} atomic_t;

#ifndef __KERNEL__
#define __iomem
#endif


#include "ah.h"
#include "spectral_ioctl.h"
#include "ah_devid.h"
#include "ah_internal.h"
#include "ar5212/ar5212.h"
#include "ar5212/ar5212reg.h"
#include "dfs_ioctl.h"
#include "spectral_data.h"
#ifndef ATH_DEFAULT
#define	ATH_DEFAULT	"wifi0"
#endif

struct spectralhandler {
	int	s;
	struct ath_diag atd;
};

static int spectralStartScan(struct spectralhandler *spectral);
static int spectralStopScan(struct spectralhandler *spectral);
void spectralset(struct spectralhandler *spectral, int op, u_int32_t param);
static void spectralAtdClean(struct spectralhandler *spectral);

#define MAX_PAYLOAD 1024  /* maximum payload size*/
#ifndef NETLINK_ATHEROS
#define NETLINK_ATHEROS 17
#endif
#define MAX_RAW_SPECT_DATA_SZ (600)
#define SCAN_COUNT_OFFSET     (95)
#define SAMPRECVBUF_SZ        (2048)
static void
spectralGetThresholds(struct spectralhandler *spectral, HAL_SPECTRAL_PARAM *sp)
{
    struct ifreq ifr;
	spectral->atd.ad_id = SPECTRAL_GET_CONFIG | ATH_DIAG_DYN;
	spectral->atd.ad_out_data = (void *) sp;
	spectral->atd.ad_out_size = sizeof(HAL_SPECTRAL_PARAM);
    strcpy(ifr.ifr_name, spectral->atd.ad_name);
    ifr.ifr_data = (caddr_t)&spectral->atd;
	if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, spectral->atd.ad_name);
}

/*
 * Function    : spectralGetNSamples
 * Description : Capture N spectral samples from the hardware FFT engine
 * Input       : Pointer to spectral structure, bit that indicates if start and stop scan is required
 *               and Number of raw data to capture given as input by the user
 * Output      : File that contains the spectral samples captured
 */
static int spectralGetNSamples(struct spectralhandler *spectral, int need_start_stop, int num_raw_data_to_cap)
{
    int ret = 0;
    struct sockaddr_nl src_addr, dest_addr;
    socklen_t fromlen;
    struct nlmsghdr *nlh = NULL;
    int sock_fd = -1, read_bytes = 0;
    struct msghdr msg;
    u_int8_t *samprecvbuf = NULL;
    u_int16_t num_buf_written = 0;
    FILE *fp = NULL;
    u_int8_t *bufSave = NULL, *buf_ptr = NULL;
    u_int8_t *bufSave_sec80 = NULL, *buf_ptr_sec80 = NULL;
    int32_t *timeStp = NULL, *sampinfo = NULL;
    int32_t *rssi_nf_sec80 = NULL;
    u_int8_t *is_160 = NULL;
    HAL_SPECTRAL_PARAM sp;
    int is_pwr_format_enabled = 0;

    adf_os_mem_zero(&sp, sizeof(sp));

    /* Check if the user input is within the valid allowed range
       Note: scan_count is a 12-bit field => Range of 0-4095
       Allowed range is 1-4000 to account for the dropped packets */
    if ((num_raw_data_to_cap < 0) || (num_raw_data_to_cap > 4000)) {
        printf("Number of samples to capture out of range\n");
        printf("Enter valid input in the range 1-4000\n");
        ret = -1;
        goto out;
    }
    
    sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_ATHEROS);
    if (sock_fd < 0) {
        printf("socket errno=%d\n", sock_fd);
        ret = sock_fd;
        goto out;
    }
    
    fp = fopen("outFile", "wt");
    if (!fp) {
        printf("Could not open file to write\n");
        ret = -1; 
        goto out;
    }
    
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid();  /* self pid */
    /* interested in group 1<<0 */
    src_addr.nl_groups = 1;
    
    if(read_bytes=bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        if (read_bytes < 0)
            perror("bind(netlink)");
        printf("BIND errno=%d\n", read_bytes);
        ret = read_bytes;
        goto out;
    }

    samprecvbuf = (u_int8_t *)malloc(SAMPRECVBUF_SZ * sizeof(u_int8_t));
    if (samprecvbuf == NULL) {
        printf("Could not allocate buffer to receive SAMP data\n");
        ret = -1;
        goto out;
    }
    memset(samprecvbuf, 0, SAMPRECVBUF_SZ * sizeof(u_int8_t));

    bufSave = (u_int8_t *)malloc(num_raw_data_to_cap * MAX_RAW_SPECT_DATA_SZ);
    if (bufSave == NULL) {
        printf("Could not allocate buffer to save Spectral bins\n");
        ret = -1;
        goto out;
    }
    memset(bufSave, 0, num_raw_data_to_cap * MAX_RAW_SPECT_DATA_SZ);

    bufSave_sec80 = (u_int8_t *)malloc(num_raw_data_to_cap *
                                       MAX_RAW_SPECT_DATA_SZ);
    if (bufSave_sec80 == NULL) {
        printf("Could not allocate buffer to save Spectral bins for secondary "
               "80 MHz segment\n");
        ret = -1;
        goto out;
    }
    memset(bufSave_sec80, 0, num_raw_data_to_cap * MAX_RAW_SPECT_DATA_SZ);

    timeStp = (int32_t *)malloc(num_raw_data_to_cap * 3 * sizeof(int32_t));
    if (timeStp == NULL) {
        printf("Could not allocate buffers to save timestamp, RSSI and NF\n");
        ret = -1;
        goto out;
    }
    memset(timeStp, 0, num_raw_data_to_cap * 3 * sizeof(int32_t));

    rssi_nf_sec80 = (int32_t *)malloc(num_raw_data_to_cap * 2 * sizeof(int32_t));
    if (rssi_nf_sec80 == NULL) {
        printf("Could not allocate buffers to save RSSI and NF for secondary "
               "80 MHz segment\n");
        ret = -1;
        goto out;
    }
    memset(rssi_nf_sec80, 0, num_raw_data_to_cap * 2 * sizeof(int32_t));

    sampinfo = (int32_t *)malloc(num_raw_data_to_cap * 2 * sizeof(int32_t));
    if (sampinfo == NULL) {
        printf("Could not allocate buffers to save sample info\n");
        ret = -1;
        goto out;
    }
    memset(sampinfo, 0, num_raw_data_to_cap * 2 * sizeof(int32_t));

    is_160 = (u_int8_t *)malloc(num_raw_data_to_cap * sizeof(u_int8_t));
    if (is_160 == NULL) {
        printf("Could not allocate buffers to save flag indicating if sample "
               "was taken at 160 MHz width\n");
        ret = -1;
        goto out;
    }
    memset(is_160, 0, num_raw_data_to_cap * sizeof(u_int8_t));

    buf_ptr = bufSave;
    buf_ptr_sec80 = bufSave_sec80;

    /* Setting scan count and starting spectral scan in case of N samples to capture */
    if(need_start_stop) {
        /* Scan count set to (N+95) that is added as an offset to account for the dropped packets */
        spectralset(spectral, SPECTRAL_PARAM_SCAN_COUNT, num_raw_data_to_cap + SCAN_COUNT_OFFSET);
        spectralStartScan(spectral);
    }

    printf("Waiting for message from kernel\n");

    while (num_buf_written < num_raw_data_to_cap) {
        fromlen = sizeof(src_addr);
        read_bytes = recvfrom(sock_fd, samprecvbuf,
                              SAMPRECVBUF_SZ * sizeof(u_int8_t), MSG_WAITALL,
                              (struct sockaddr *) &src_addr, &fromlen);
        if (read_bytes < 0) {
            perror("recvfrom(netlink)\n");
            printf("Error reading netlink\n");
            ret = read_bytes;
            goto out;
        } else {
            SPECTRAL_SAMP_MSG *msg;
            
            nlh = (struct nlmsghdr *) samprecvbuf;
            msg = (SPECTRAL_SAMP_MSG *) NLMSG_DATA(nlh);
           
            /* sampinfo will be re-used for secondary 80 MHz if applicable,
             * since it is known that the number of samples will be the same for
             * both 80 MHz segments.
             *
             * Similarly, time stamp will be reused.
             *
             * XXX: Remove this space optimization if the delivery format for
             * future 160 MHz chipsets post QCA9984 changes and a difference in
             * number of samples/timestamps becomes possible.
             */
            sampinfo[num_buf_written * 2] = num_buf_written;
            sampinfo[num_buf_written * 2 + 1] = msg->samp_data.bin_pwr_count;
            
            memcpy(buf_ptr,msg->samp_data.bin_pwr, msg->samp_data.bin_pwr_count);
            buf_ptr += MAX_RAW_SPECT_DATA_SZ;
            
            timeStp[num_buf_written * 3] = msg->samp_data.spectral_tstamp;
            timeStp[num_buf_written * 3 + 1] = msg->samp_data.spectral_rssi;
            timeStp[num_buf_written * 3 + 2] = msg->samp_data.noise_floor;
            {
                static int nf_cnt = 0;
                nf_cnt++;
                if(nf_cnt == num_raw_data_to_cap) {
                    printf("Noise Floor %d\n", msg->samp_data.noise_floor);
                    nf_cnt = 0;   
                }
             
            }

            if (msg->samp_data.ch_width == IEEE80211_CWM_WIDTH160) {
                is_160[num_buf_written] = 1; 
                
                memcpy(buf_ptr_sec80,
                       msg->samp_data.bin_pwr_sec80,
                       msg->samp_data.bin_pwr_count_sec80);

                rssi_nf_sec80[num_buf_written * 2] = msg->samp_data.spectral_rssi_sec80;
                rssi_nf_sec80[num_buf_written * 2 + 1] = msg->samp_data.noise_floor_sec80;
            }

            /* Irrespective of whether the current FFT bins were at
             * 160 MHz or not, we skip to next position to be in sync with first
             * (original) segment's FFT bin positions. Hence the increment
             * outside of check of 160 MHz width.
             */
            buf_ptr_sec80 += MAX_RAW_SPECT_DATA_SZ;
            
            num_buf_written++;
        }
    }

    /* Stopping spectral scan and resetting scan count to 0 in case of N samples to capture */
    if(need_start_stop) {
        spectralStopScan(spectral);
        spectralset(spectral, SPECTRAL_PARAM_SCAN_COUNT, 0);
    }

    /* Get current configurations */
    spectralGetThresholds(spectral, &sp);
    is_pwr_format_enabled = sp.ss_pwr_format;

     /* Read message from kernel 
    read_bytes = recvmsg(sock_fd, &msg, MSG_WAITALL) ;
    if(read_bytes != -1){*/
    printf("Number of sample captured %d\n",
           num_buf_written); 
    {
        u_int16_t cnt, valCnt;
        buf_ptr = bufSave;
        buf_ptr_sec80 = bufSave_sec80;

        for (cnt = 0; cnt < num_buf_written; cnt++) {
            fprintf( fp, "%u ", (unsigned)sampinfo[cnt * 2]);
            fprintf( fp, "%u ", (unsigned)sampinfo[cnt * 2 + 1]);

            if (is_pwr_format_enabled) {
                for (valCnt = 0; valCnt < (unsigned)sampinfo[cnt * 2 + 1]; valCnt++) {
                    fprintf( fp, "%d ", (int8_t)(buf_ptr[valCnt]));
                }
            } else {
                for (valCnt = 0; valCnt < (unsigned)sampinfo[cnt * 2 + 1]; valCnt++) {
                    fprintf( fp, "%u ", (u_int8_t)(buf_ptr[valCnt]));
                }
            }

            fprintf(fp, "%u ", (unsigned)timeStp[cnt * 3]);
            fprintf(fp, "%d ", timeStp[cnt * 3 + 1]);
            fprintf(fp, "%d ", timeStp[cnt * 3 + 2]);
            fprintf(fp,"\n");
            buf_ptr += MAX_RAW_SPECT_DATA_SZ;

            if (is_160[cnt]) {
                fprintf( fp, "%u ", (unsigned)sampinfo[cnt * 2]);
                fprintf( fp, "%u ", (unsigned)sampinfo[cnt * 2 + 1]);
                
                for (valCnt = 0; valCnt < (unsigned)sampinfo[cnt * 2 + 1]; valCnt++) {
                    fprintf( fp, "%u ", (u_int8_t)(buf_ptr_sec80[valCnt]));
                }
                fprintf(fp, "%u ", (unsigned)timeStp[cnt * 3]);
                fprintf(fp, "%d ", rssi_nf_sec80[cnt * 2]);
                fprintf(fp, "%d ", rssi_nf_sec80[cnt * 2 + 1]);
                fprintf(fp,"\n");
            }

            buf_ptr_sec80 += MAX_RAW_SPECT_DATA_SZ;
        }
    }

out:
    if (sock_fd >= 0) {
        close(sock_fd);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    if (samprecvbuf != NULL) {
        free(samprecvbuf);
    }

    if (bufSave != NULL) {
        free(bufSave);
    }

    if (bufSave_sec80 != NULL) {
        free(bufSave_sec80);
    }

    if (sampinfo != NULL) {
        free(sampinfo);
    }
 
    if (timeStp != NULL) {
        free(timeStp);
    }
 
    if (rssi_nf_sec80 != NULL) {
        free(rssi_nf_sec80);
    }
   
    if (is_160 != NULL) {
        free(is_160);
    }

    spectralAtdClean(spectral);
    return ret;
}

static void
spectralAtdClean(struct spectralhandler *spectral)
{
    spectral->atd.ad_id = 0;
    spectral->atd.ad_in_data = NULL;
    spectral->atd.ad_in_size = 0;
    spectral->atd.ad_out_data = NULL;
    spectral->atd.ad_out_size = 0;
}

static int
spectralIsEnabled(struct spectralhandler *spectral)
{
    u_int32_t result=0;
    struct ifreq ifr;

    spectral->atd.ad_id = SPECTRAL_IS_ENABLED | ATH_DIAG_DYN;
    spectral->atd.ad_in_data = NULL;
    spectral->atd.ad_in_size = 0;
    spectral->atd.ad_out_data = (void *) &result;
    spectral->atd.ad_out_size = sizeof(u_int32_t);
    strcpy(ifr.ifr_name, spectral->atd.ad_name);
    ifr.ifr_data = (caddr_t) &spectral->atd;
    if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
          err(1, spectral->atd.ad_name);
    spectralAtdClean(spectral);
    return(result);
}
static int
spectralIsActive(struct spectralhandler *spectral)
{
    u_int32_t result=0;
    struct ifreq ifr;

    spectral->atd.ad_id = SPECTRAL_IS_ACTIVE | ATH_DIAG_DYN;
    spectral->atd.ad_in_data = NULL;
    spectral->atd.ad_in_size = 0;
    spectral->atd.ad_out_data = (void *) &result;
    spectral->atd.ad_out_size = sizeof(u_int32_t);
    strcpy(ifr.ifr_name, spectral->atd.ad_name);
    ifr.ifr_data = (caddr_t) &spectral->atd;
    if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
          err(1, spectral->atd.ad_name);
    spectralAtdClean(spectral);
    return(result);
}
static int
spectralStartScan(struct spectralhandler *spectral)
{
	u_int32_t result;
        struct ifreq ifr;

	spectral->atd.ad_id = SPECTRAL_ACTIVATE_SCAN | ATH_DIAG_DYN;
	spectral->atd.ad_out_data = NULL;
	spectral->atd.ad_out_size = 0;
	spectral->atd.ad_in_data = (void *) &result;
	spectral->atd.ad_in_size = sizeof(u_int32_t);
        strcpy(ifr.ifr_name, spectral->atd.ad_name);
        ifr.ifr_data = (caddr_t)&spectral->atd;
	if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0) 
		err(1, spectral->atd.ad_name);
	spectralAtdClean(spectral);
	return 0;
}

static int
spectralStopScan(struct spectralhandler *spectral)
{
	u_int32_t result;
    struct ifreq ifr;

	spectral->atd.ad_id = SPECTRAL_STOP_SCAN | ATH_DIAG_DYN;
	spectral->atd.ad_out_data = NULL;
	spectral->atd.ad_out_size = 0;
	spectral->atd.ad_in_data = (void *) &result;
	spectral->atd.ad_in_size = sizeof(u_int32_t);
        strcpy(ifr.ifr_name, spectral->atd.ad_name);
        ifr.ifr_data = (caddr_t)&spectral->atd;
	if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, spectral->atd.ad_name);
	spectralAtdClean(spectral);
	return 0;
}

static int
spectralSetDebugLevel(struct spectralhandler *spectral, u_int32_t level)
{
	u_int32_t result;
    struct ifreq ifr;

	spectral->atd.ad_id = SPECTRAL_SET_DEBUG_LEVEL | ATH_DIAG_IN;
	spectral->atd.ad_out_data = NULL;
	spectral->atd.ad_out_size = 0;
	spectral->atd.ad_in_data = (void *) &level;
	spectral->atd.ad_in_size = sizeof(u_int32_t);
        strcpy(ifr.ifr_name, spectral->atd.ad_name);
        ifr.ifr_data = (caddr_t)&spectral->atd;
	if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, spectral->atd.ad_name);
	spectralAtdClean(spectral);
	return 0;
}


static void
spectralGetDiagStats(struct spectralhandler *spectral,
                     struct spectral_diag_stats *diag_stats)
{
    struct ifreq ifr;
    spectral->atd.ad_id = SPECTRAL_GET_DIAG_STATS | ATH_DIAG_DYN;
    spectral->atd.ad_out_data = (void *) diag_stats;
    spectral->atd.ad_out_size = sizeof(struct spectral_diag_stats);
    strcpy(ifr.ifr_name, spectral->atd.ad_name);
    ifr.ifr_data = (caddr_t)&spectral->atd;
    if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
        err(1, spectral->atd.ad_name);
}

static int
spectralPrintDiagStats(struct spectralhandler *spectral)
{
    struct spectral_diag_stats diag_stats;

    adf_os_mem_zero(&diag_stats, sizeof(diag_stats));

    spectralGetDiagStats(spectral, &diag_stats);

    printf("Diagnostic statistics:\n");
    printf("Spectral TLV signature mismatches: %llu\n",
           diag_stats.spectral_mismatch);
    printf("Insufficient length when parsing for Secondary 80 Search FFT report:"
           " %llu\n",
           diag_stats.spectral_sec80_sfft_insufflen);
    printf("Secondary 80 Search FFT report TLV not found: %llu\n",
           diag_stats.spectral_no_sec80_sfft);
    printf("VHT Operation Segment 1 ID mismatches in Search FFT report: %llu\n",
           diag_stats.spectral_vhtseg1id_mismatch);
    printf("VHT Operation Segment 2 ID mismatches in Search FFT report: %llu\n",
           diag_stats.spectral_vhtseg2id_mismatch);

    spectralAtdClean(spectral);
    return 0;
}

static int
spectralIsAdvncdSpectral(struct spectralhandler *spectral)
{
    struct ifreq ifr;
    struct ath_spectral_caps caps;

    memset(&caps, 0, sizeof(caps));

    spectral->atd.ad_id = SPECTRAL_GET_CAPABILITY_INFO | ATH_DIAG_DYN;
    spectral->atd.ad_out_data = (void *)&caps;
    spectral->atd.ad_out_size = sizeof(struct ath_spectral_caps);
    strcpy(ifr.ifr_name, spectral->atd.ad_name);
    ifr.ifr_data = (caddr_t)&spectral->atd;

    if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0) {
        err(1, spectral->atd.ad_name);
	spectralAtdClean(spectral);
        return 0;
    }

    spectralAtdClean(spectral);

    if (caps.advncd_spectral_cap) {
        return 1;
    } else {
        return 0;
    }
}



#if 0
static void
spectralGetClassifierParams(struct spectralhandler *spectral, SPECTRAL_CLASSIFIER_PARAMS *sp)
{
    struct ifreq ifr;
	spectral->atd.ad_id = SPECTRAL_GET_CLASSIFIER_CONFIG | ATH_DIAG_DYN;
	spectral->atd.ad_out_data = (void *) sp;
	spectral->atd.ad_out_size = sizeof(SPECTRAL_CLASSIFIER_PARAMS);
    strcpy(ifr.ifr_name, spectral->atd.ad_name);
    ifr.ifr_data = (caddr_t)&spectral->atd;
	if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, spectral->atd.ad_name);
}
#endif
void
spectralset(struct spectralhandler *spectral, int op, u_int32_t param)
{
	HAL_SPECTRAL_PARAM sp;
    struct ifreq ifr;

	sp.ss_period = HAL_PHYERR_PARAM_NOVAL;
	sp.ss_count = HAL_PHYERR_PARAM_NOVAL;
	sp.ss_fft_period = HAL_PHYERR_PARAM_NOVAL;
	sp.ss_short_report = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_spectral_pri = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_fft_size = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_gc_ena = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_restart_ena = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_noise_floor_ref = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_init_delay = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_nb_tone_thr = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_str_bin_thr = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_wb_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_rssi_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_rssi_thr = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_pwr_format = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_rpt_mode = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_bin_scale = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_dBm_adj = HAL_PHYERR_PARAM_NOVAL;
    sp.ss_chn_mask = HAL_PHYERR_PARAM_NOVAL;

	switch(op) {
        case SPECTRAL_PARAM_FFT_PERIOD:
            sp.ss_fft_period = param;
            break;
        case SPECTRAL_PARAM_SCAN_PERIOD:
            sp.ss_period = param;
            break;
        case SPECTRAL_PARAM_SHORT_REPORT:
                if (param)
                        sp.ss_short_report = AH_TRUE;
                    else 
                        sp.ss_short_report = AH_FALSE;
                    printf("short being set to %d param %d\n", sp.ss_short_report, param);                       
            break;
        case SPECTRAL_PARAM_SCAN_COUNT:
            sp.ss_count = param;
            break;
        
        case SPECTRAL_PARAM_SPECT_PRI:
            sp.ss_spectral_pri = (!!param) ? true:false;
            printf("Spectral priority being set to %d\n",sp.ss_spectral_pri);
            break;

        case SPECTRAL_PARAM_FFT_SIZE:
            sp.ss_fft_size = param;
            break;

        case SPECTRAL_PARAM_GC_ENA:
            sp.ss_gc_ena = !!param;
            printf("gc_ena being set to %u\n",sp.ss_gc_ena);
            break;

        case SPECTRAL_PARAM_RESTART_ENA:
            sp.ss_restart_ena = !!param;
            printf("restart_ena being set to %u\n",sp.ss_restart_ena);
            break;

        case SPECTRAL_PARAM_NOISE_FLOOR_REF:
            sp.ss_noise_floor_ref = param;
            break;

        case SPECTRAL_PARAM_INIT_DELAY:
            sp.ss_init_delay = param;
            break;

        case SPECTRAL_PARAM_NB_TONE_THR:
            sp.ss_nb_tone_thr = param;
            break;

        case SPECTRAL_PARAM_STR_BIN_THR:
            sp.ss_str_bin_thr = param;
            break;

        case SPECTRAL_PARAM_WB_RPT_MODE:
            sp.ss_wb_rpt_mode = !!param;
            printf("wb_rpt_mode being set to %u\n",sp.ss_wb_rpt_mode);
            break;

        case SPECTRAL_PARAM_RSSI_RPT_MODE:
            sp.ss_rssi_rpt_mode = !!param;
            printf("rssi_rpt_mode being set to %u\n",sp.ss_rssi_rpt_mode);
            break;

        case SPECTRAL_PARAM_RSSI_THR:
            sp.ss_rssi_thr = param;
            break;

        case SPECTRAL_PARAM_PWR_FORMAT:
            sp.ss_pwr_format = !!param;
            printf("pwr_format being set to %u\n",sp.ss_pwr_format);
            break;

        case SPECTRAL_PARAM_RPT_MODE:
            sp.ss_rpt_mode = param;
            break;

        case SPECTRAL_PARAM_BIN_SCALE:
            sp.ss_bin_scale = param;
            break;

        case SPECTRAL_PARAM_DBM_ADJ:
            sp.ss_dBm_adj = !!param;
            printf("dBm_adj being set to %u\n",sp.ss_dBm_adj);
            break;

        case SPECTRAL_PARAM_CHN_MASK:
            sp.ss_chn_mask = param;
            break;
    }
    
	spectral->atd.ad_id = SPECTRAL_SET_CONFIG | ATH_DIAG_IN;
	spectral->atd.ad_out_data = NULL;
	spectral->atd.ad_out_size = 0;
	spectral->atd.ad_in_data = (void *) &sp;
	spectral->atd.ad_in_size = sizeof(HAL_SPECTRAL_PARAM);
        strcpy(ifr.ifr_name, spectral->atd.ad_name);
        ifr.ifr_data = (caddr_t) &spectral->atd;

	if (ioctl(spectral->s, SIOCGATHPHYERR, &ifr) < 0)
		err(1, spectral->atd.ad_name);
	spectralAtdClean(spectral);
}

static void
usage(void)
{
	const char *msg = "\
Usage: spectraltool [-i wifiX] [cmd] [cmd_parameter]\n\
           <cmd> = startscan, stopscan, get_advncd, raw_data, diag_stats \n\
                   do not require a param\n\
           <cmd> = fft_period, scan_period, short_report, scan_count, \n\
                   priority, fft_size, gc_ena,restart_ena, noise_floor_ref,\n\
                   init_delay, nb_tone_thr, str_bin_thr, wb_rpt_mode, \n\
                   rssi_rpt_mode, rssi_thr, pwr_format, rpt_mode, bin_scale,\n\
                   dBm_adj, chn_mask, debug, get_samples require a param\n\
                   Some of the above may or may not be available depending on \n\
                   whether advanced Spectral functionality is implemented \n\
                   in hardware, and details are documented in the Spectral \n\
                   configuration parameter description. Use the get_advncd command \n\
                   to determine if advanced Spectral functionality is supported \n\
                   by the interface. \n\
                   Also note that applications such as athssd may not work with \n\
                   some value combinations for the above parameters, or may \n\
                   choose to write values as required by their operation. \n\
           <cmd> = -h : print this usage message\n\
           <cmd> = -p : print description of Spectral configuration parameters.\n";

	fprintf(stderr, "%s", msg);
}

static void
config_param_description(void)
{
	const char *msg = "\
spectraltool: Description of Spectral configuration parameters:\n\
('NA for Advanced': Not available for hardware having advanced Spectral \n\
                    functionality, i.e. 11ac chipsets onwards \n\
 'Advanced Only'  : Available (or exposed) only for hardware having advanced \n\
                    Spectral functionality, i.e. 11ac chipsets onwards) \n\
            fft_period      : Skip interval for FFT reports \n\
                              (NA for Advanced) \n\
            scan_period     : Spectral scan period \n\
            scan_count      : No. of reports to return \n\
            short_report    : Set to report ony 1 set of FFT results \n\
                              (NA for Advanced) \n\
            priority        : Priority \n\
            fft_size        : Defines the number of FFT data points to \n\
                              compute, defined as a log index:\n\
                              num_fft_pts = 2^fft_size \n\
                              (Advanced Only) \n\
            gc_ena          : Set, to enable targeted gain change before \n\
                              starting the spectral scan FFT \n\
                              (Advanced Only) \n\
            restart_ena     : Set, to enable abort of receive frames when \n\
                              in high priority and a spectral scan is queued \n\
                              (Advanced Only) \n\
            noise_floor_ref : Noise floor reference number (signed) for the \n\
                              calculation of bin power (dBm) \n\
                              (Advanced Only) \n\
            init_delay      : Disallow spectral scan triggers after Tx/Rx \n\
                              packets by setting this delay value to \n\
                              roughly  SIFS time period or greater. Delay \n\
                              timer counts in units of 0.25us \n\
                              (Advanced Only) \n\
            nb_tone_thr     : Number of strong bins (inclusive) per \n\
                              sub-channel, below which a signal is declared \n\
                              a narrowband tone \n\
                              (Advanced Only) \n\
            str_bin_thr     : bin/max_bin ratio threshold over which a bin is\n\
                              declared strong (for spectral scan bandwidth \n\
                              analysis). \n\
                              (Advanced Only) \n\
            wb_rpt_mode     : Set this to 1 to report spectral scans as \n\
                              EXT_BLOCKER (phy_error=36), if none of the \n\
                              sub-channels are deemed narrowband. \n\
                              (Advanced Only) \n\
            rssi_rpt_mode   : Set this to 1 to report spectral scans as \n\
                              EXT_BLOCKER (phy_error=36), if the ADC RSSI is \n\
                              below the threshold rssi_thr \n\
                              (Advanced Only) \n\
            rssi_thr        : ADC RSSI must be greater than or equal to this \n\
                              threshold (signed Db) to ensure spectral scan \n\
                              reporting with normal phy error codes (please \n\
                              see rssi_rpt_mode above) \n\
                              (Advanced Only) \n\
            pwr_format      : Format of frequency bin magnitude for spectral \n\
                              scan triggered FFTs: \n\
                              0: linear magnitude \n\
                              1: log magnitude \n\
                                 (20*log10(lin_mag), \n\
                                  1/2 dB step size) \n\
                              (Advanced Only) \n\
            rpt_mode        : Format of per-FFT reports to software for \n\
                              spectral scan triggered FFTs. \n\
                              0: No FFT report \n\
                                 (only pulse end summary) \n\
                              1: 2-dword summary of metrics \n\
                                 for each completed FFT \n\
                              2: 2-dword summary + \n\
                                 1x-oversampled bins(in-band) \n\
                                 per FFT \n\
                              3: 2-dword summary + \n\
                                 2x-oversampled bins (all) \n\
                                 per FFT \n\
                              (Advanced Only) \n\
            bin_scale       : Number of LSBs to shift out to scale the FFT bins \n\
                              for spectral scan triggered FFTs. \n\
                              (Advanced Only) \n\
            dBm_adj         : Set (with pwr_format=1), to report bin \n\
                              magnitudes converted to dBm power using the \n\
                              noisefloor calibration results. \n\
                              (Advanced Only) \n\
            chn_mask        : Per chain enable mask to select input ADC for \n\
                              search FFT. \n\
                              (Advanced Only)\n";
	fprintf(stderr, "%s", msg);
}

int
main(int argc, char *argv[])
{
#define	streq(a,b)	(strcasecmp(a,b) == 0)
    struct spectralhandler spectral;
    HAL_REVS revs;
    struct ifreq ifr;
    int advncd_spectral = 0;
    int option_unavbl = 0;

	memset(&spectral, 0, sizeof(spectral));
	spectral.s = socket(AF_INET, SOCK_DGRAM, 0);
	if (spectral.s < 0)
		err(1, "socket");
	if (argc > 1 && strcmp(argv[1], "-i") == 0) {
		if (argc <= 2) {
			fprintf(stderr, "%s: missing interface name for -i\n",
				argv[0]);
			exit(-1);
		}
		strncpy(spectral.atd.ad_name, argv[2], sizeof (spectral.atd.ad_name));
		argc -= 2, argv += 2;
	} else
		strncpy(spectral.atd.ad_name, ATH_DEFAULT, sizeof (spectral.atd.ad_name));

    advncd_spectral = spectralIsAdvncdSpectral(&spectral);

	if (argc >= 2) {
        if(streq(argv[1], "fft_period") && (argc == 3)) {
            if (!advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_FFT_PERIOD,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "scan_period") && (argc == 3)) {
            spectralset(&spectral, SPECTRAL_PARAM_SCAN_PERIOD, (u_int16_t) atoi(argv[2]));
        } else if (streq(argv[1], "short_report") && (argc == 3)) {
            if (!advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_SHORT_REPORT,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "scan_count") && (argc == 3)) {
            spectralset(&spectral, SPECTRAL_PARAM_SCAN_COUNT, (u_int16_t) atoi(argv[2]));
        } else if (streq(argv[1], "priority") && (argc == 3)) {
            spectralset(&spectral, SPECTRAL_PARAM_SPECT_PRI, (u_int16_t) atoi(argv[2]));
        } else if (streq(argv[1], "fft_size") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_FFT_SIZE,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "gc_ena") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_GC_ENA,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "restart_ena") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_RESTART_ENA,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "noise_floor_ref") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_NOISE_FLOOR_REF,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "init_delay") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_INIT_DELAY,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "nb_tone_thr") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_NB_TONE_THR,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "str_bin_thr") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_STR_BIN_THR,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "wb_rpt_mode") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_WB_RPT_MODE,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "rssi_rpt_mode") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_RSSI_RPT_MODE,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "rssi_thr") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_RSSI_THR,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "pwr_format") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_PWR_FORMAT,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "rpt_mode") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_RPT_MODE,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "bin_scale") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_BIN_SCALE,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "dBm_adj") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_DBM_ADJ,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "chn_mask") && (argc == 3)) {
            if (advncd_spectral) {
                spectralset(&spectral,
                            SPECTRAL_PARAM_CHN_MASK,
                            (u_int16_t) atoi(argv[2]));
            } else {
                option_unavbl = 1;
            }
        } else if (streq(argv[1], "startscan")) {
            spectralStartScan(&spectral);
        } else if (streq(argv[1], "stopscan")) {
            spectralStopScan(&spectral);
        } else if (streq(argv[1], "debug") && (argc == 3)) {
             spectralSetDebugLevel(&spectral, (u_int32_t)atoi(argv[2]));
        } else if (streq(argv[1], "get_advncd")) {
            printf("Advanced Spectral functionality for %s: %s\n",
                   spectral.atd.ad_name,
                   advncd_spectral ? "available":"unavailable");
        } else if (streq(argv[1],"-h")) {
            usage();
        } else if (streq(argv[1],"-p")) {
            config_param_description();
        } else if (streq(argv[1],"raw_data")) {
            return spectralGetNSamples(&spectral, 0, 1000);
        } else if (streq(argv[1],"diag_stats")) {
            return spectralPrintDiagStats(&spectral);
        } else if (streq(argv[1],"get_samples") && (argc == 3)) {
            return spectralGetNSamples(&spectral, 1, (u_int32_t)atoi(argv[2]));
        } else {
            fprintf(stderr,
                    "Invalid command option used for spectraltool\n");
            usage();
        }

        if (option_unavbl) {
                fprintf(stderr,
                        "Command option unavailable for interface %s\n",
                        spectral.atd.ad_name);
                usage();
        }
	} else if (argc == 1) {
        HAL_SPECTRAL_PARAM sp;
        int val=0;
        memset(&sp, 0, sizeof(sp));
        printf ("SPECTRAL PARAMS\n");
        val = spectralIsEnabled(&spectral);
        printf("Spectral scan is %s\n", (val) ? "enabled": "disabled");
        val = spectralIsActive(&spectral);
        printf("Spectral scan is %s\n", (val) ? "active": "inactive");
        spectralGetThresholds(&spectral, &sp);
        if (!advncd_spectral) {
            printf ("fft_period:  %d\n",sp.ss_fft_period);
        }
        printf ("scan_period: %d\n",sp.ss_period);
        printf ("scan_count: %d\n",sp.ss_count);
        if (!advncd_spectral) {
            printf ("short_report: %s\n",(sp.ss_short_report) ? "yes":"no");
        }
        printf ("priority: %s\n",(sp.ss_spectral_pri) ? "enabled":"disabled");

        if (advncd_spectral) {
             printf ("fft_size: %u\n", sp.ss_fft_size);
             printf ("gc_ena: %s\n",
                     (sp.ss_gc_ena) ? "enabled":"disabled");
             printf ("restart_ena: %s\n",
                     (sp.ss_restart_ena) ? "enabled":"disabled");
             printf ("noise_floor_ref: %d\n",(int8_t)sp.ss_noise_floor_ref);
             printf ("init_delay: %u\n",sp.ss_init_delay);
             printf ("nb_tone_thr: %u\n",sp.ss_nb_tone_thr);
             printf ("str_bin_thr: %u\n",sp.ss_str_bin_thr);
             printf ("wb_rpt_mode: %u\n",sp.ss_wb_rpt_mode);
             printf ("rssi_rpt_mode: %u\n",sp.ss_rssi_rpt_mode);
             printf ("rssi_thr: %d\n",(int8_t)sp.ss_rssi_thr);
             printf ("pwr_format: %u\n",sp.ss_pwr_format);
             printf ("rpt_mode: %u\n",sp.ss_rpt_mode);
             printf ("bin_scale: %u\n",sp.ss_bin_scale);
             printf ("dBm_adj: %u\n",sp.ss_dBm_adj);
             printf ("chn_mask: %u\n",sp.ss_chn_mask);
        }

    } else {
		usage ();
	}
	return 0;
}

