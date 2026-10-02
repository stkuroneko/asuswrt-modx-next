/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <wlutils.h>
#include <shutils.h>
#include <shared.h>
#include <wlioctl.h>
#include <rc.h>

#include <wlscan.h>
#include <bcmendian.h>
#ifdef RTCONFIG_BCMARM
#include <bcmutils.h>
#include <security_ipc.h>
#endif
#ifdef RTCONFIG_HND_ROUTER_AX
#include <wlc_types.h>
#endif

#ifndef RTCONFIG_HND_ROUTER_AX
#define WL_RECONNECT
#endif

int psta_debug = 0;

#define PSTA_DEBUG_NOTICE	0x0001
#define PSTA_DEBUG_SYSLOG	0x0002
#define PSTA_DEBUG_INFO		0x0004

#define PSTA_LOG(fmt, arg...) \
	do { \
		logmessage("psta_monitor", "%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		if (psta_debug & PSTA_DEBUG_NOTICE) { \
			_dprintf("psta_monitor >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		} \
	} while (0)

#define PSTA_PRINT(fmt, arg...) \
	do { \
		if (psta_debug) { \
			dbg("psta_monitor >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
			if (psta_debug & PSTA_DEBUG_SYSLOG) \
				logmessage("psta_monitor", "%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		} \
	} while (0)

#define PSTA_INFO(fmt, arg...) \
	do { \
		if (psta_debug & PSTA_DEBUG_INFO) { \
			dbg("psta_monitor >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
			if (psta_debug & PSTA_DEBUG_SYSLOG) \
				logmessage("psta_monitor", "%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		} \
	} while (0)

#ifdef RTCONFIG_BCMWL6
#ifdef RTCONFIG_PROXYSTA

#define NORMAL_PERIOD	3
#define	MAX_STA_COUNT	128
#define	NVRAM_BUFSIZE	100

#ifdef WL_RECONNECT
static int count_bss_down[3] = { 0, 0, 0 };
#endif
#ifdef WL_SEND_NULLDATA
static int count_bss_up[3] = { 0, 0, 0 };
#endif
static uint32 txframe = 0, txframe_old = 0;
static time_t time_txframe;
static struct ether_addr bssid[3];
#ifdef RTCONFIG_BCMARM
static struct ether_addr bssid_org[3];
static int wlif_count;
#endif
#ifdef PSTA_DEBUG
static int cnt = -1;
#endif
static int count_arp = 0;
static int connected = -1, connected_old;

#ifdef WL_RECONNECT
/* WPS ENR mode APIs */
typedef struct wlc_ap_list_info
{
#if 0
	bool	used;
#endif
	uint8	ssid[33];
	uint8	ssidLen;
	uint8	BSSID[6];
#if 0
	uint8	*ie_buf;
	uint32	ie_buflen;
#endif
	uint8	channel;
#if 0
	uint8	wep;
#endif
} wlc_ap_list_info_t;

#define WLC_SCAN_RETRY_TIMES		5
#define NUMCHANS			64
#define MAX_SSID_LEN			32

static wlc_ap_list_info_t ap_list[MAX_NUMBER_OF_APINFO];
static char scan_result[WLC_SCAN_RESULT_BUF_LEN];

/* The below macro handle endian mis-matches between wl utility and wl driver. */
//static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))

#ifdef __CONFIG_DHDAP__
#define WL_EVENT_TIMEOUT 10

typedef struct escan_wksp_s {
	uint8 packet[4096];
	fd_set fdset;
	int fdmax;
	int event_fd;
} escan_wksp_t;

static escan_wksp_t *d_info;

static bool escan_swap = FALSE;
#define htod16(i) (escan_swap?bcmswap16(i):(uint16)(i))

static bool escan_inprogress;

struct escan_bss {
	struct escan_bss *next;
	wl_bss_info_t bss[1];
};

static struct escan_bss *escan_bss_head; /* raw escan results */
static struct escan_bss *escan_bss_tail;

/* open a UDP packet to event dispatcher for receiving/sending data */
static int
escan_open_eventfd()
{
	int reuse = 1;
	struct sockaddr_in sockaddr;
	int fd = -1;

	/* open loopback socket to communicate with event dispatcher */
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(EAPD_WKSP_WLEVENT_UDP_SPORT);

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		dbg("Unable to create loopback socket\n");
		goto exit;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) < 0) {
		dbg("Unable to setsockopt to loopback socket %d.\n", fd);
		goto exit;
	}

	if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
		dbg("Unable to bind to loopback socket %d\n", fd);
		goto exit;
	}

	d_info->event_fd = fd;

	return 0;

	/* error handling */
exit:
	if (fd != -1) {
		close(fd);
	}

	return errno;
}

static int
validate_wlpvt_message(int bytes, uint8 *dpkt)
{
	bcm_event_t *pvt_data;

	/* the message should be at least the header to even look at it */
	if (bytes < sizeof(bcm_event_t) + 2) {
		dbg("Invalid length of message\n");
		goto error_exit;
	}
	pvt_data = (bcm_event_t *)dpkt;
	if (ntohs(pvt_data->bcm_hdr.subtype) != BCMILCP_SUBTYPE_VENDOR_LONG) {
		dbg("%s: not vendor specifictype\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	if (pvt_data->bcm_hdr.version != BCMILCP_BCM_SUBTYPEHDR_VERSION) {
		dbg("%s: subtype header version mismatch\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	if (ntohs(pvt_data->bcm_hdr.length) < BCMILCP_BCM_SUBTYPEHDR_MINLENGTH) {
		dbg("%s: subtype hdr length not even minimum\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	if (bcmp(&pvt_data->bcm_hdr.oui[0], BRCM_OUI, DOT11_OUI_LEN) != 0) {
		dbg("%s: validate_wlpvt_message: not BRCM OUI\n",
			pvt_data->event.ifname);
		goto error_exit;
	}
	/* check for wl dcs message types */
	switch (ntohs(pvt_data->bcm_hdr.usr_subtype)) {
		case BCMILCP_BCM_SUBTYPE_EVENT:
			break;
		default:
			goto error_exit;
			break;
	}
	return 0; /* good packet may be this is destined to us */
error_exit:
	return -1;
}

static void
escan_main_loop(struct timeval *tv)
{
	fd_set fdset;
	int width, status = 0, bytes, len;
	uint8 *pkt;
	bcm_event_t *pvt_data;
	int err;
	uint32 escan_event_status;
	wl_escan_result_t *escan_data = NULL;
	struct escan_bss *result;

	/* init file descriptor set */
	FD_ZERO(&d_info->fdset);
	d_info->fdmax = -1;

	/* build file descriptor set now to save time later */
	if (d_info->event_fd != -1) {
		FD_SET(d_info->event_fd, &d_info->fdset);
		d_info->fdmax = d_info->event_fd;
	}

	pkt = d_info->packet;
	len = sizeof(d_info->packet);
	width = d_info->fdmax + 1;
	fdset = d_info->fdset;

	/* listen to data availible on all sockets */
	status = select(width, &fdset, NULL, NULL, tv);

	if ((status == -1 && errno == EINTR) || (status == 0))
		return;

	if (status <= 0) {
		dbg("err from select: %s", strerror(errno));
		return;
	}

	/* handle brcm event */
	if (d_info->event_fd != -1 && FD_ISSET(d_info->event_fd, &fdset)) {
		char *ifname = (char *)pkt;
		struct ether_header *eth_hdr = (struct ether_header *)(ifname + IFNAMSIZ);
		uint16 ether_type = 0;
		uint32 evt_type;

		if ((bytes = recv(d_info->event_fd, pkt, len, 0)) <= 0)
			return;

		bytes -= IFNAMSIZ;

		if ((ether_type = ntohs(eth_hdr->ether_type) != ETHER_TYPE_BRCM)) {
			return;
		}

		if ((err = validate_wlpvt_message(bytes, (uint8 *)eth_hdr)))
			return;

		pvt_data = (bcm_event_t *)(ifname + IFNAMSIZ);
		evt_type = ntoh32(pvt_data->event.event_type);

		switch (evt_type) {
			case WLC_E_ESCAN_RESULT:
				{
					if (!escan_inprogress) {
						dbg("Escan not triggered from rc\n");
						return;
					}

					escan_event_status = ntoh32(pvt_data->event.status);
					escan_data = (wl_escan_result_t*)(pvt_data + 1);

					if (escan_event_status == WLC_E_STATUS_PARTIAL) {
						wl_bss_info_t *bi = &escan_data->bss_info[0];
						wl_bss_info_t *bss;

						/* check if we've received info of same BSSID */
						for (result = escan_bss_head;
								result;	result = result->next) {
							bss = result->bss;

							if (!memcmp(bi->BSSID.octet,
								bss->BSSID.octet,
								ETHER_ADDR_LEN) &&
								CHSPEC_BAND(bi->chanspec) ==
								CHSPEC_BAND(bss->chanspec) &&
								bi->SSID_len ==	bss->SSID_len &&
								! memcmp(bi->SSID, bss->SSID,
								bi->SSID_len)) {
								break;
							}
						}

						if (!result) {
							/* New BSS. Allocate memory and save it */
							struct escan_bss *ebss = (struct escan_bss *)malloc(
								OFFSETOF(struct escan_bss, bss)
								+ bi->length);

							if (!ebss) {
								dbg("can't allocate memory"
										"for escan bss");
								break;
							}

							ebss->next = NULL;
							memcpy(&ebss->bss, bi, bi->length);

							if (escan_bss_tail) {
								escan_bss_tail->next = ebss;
							} else {
								escan_bss_head =
								ebss;
							}

							escan_bss_tail = ebss;
						} else if (bi->RSSI != WLC_RSSI_INVALID) {
							/* We've got this BSS. Update RSSI
							   if necessary
							   */
							bool preserve_maxrssi = FALSE;
							if (((bss->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL) ==
								(bi->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL)) &&
								((bss->RSSI == WLC_RSSI_INVALID) ||
								(bss->RSSI < bi->RSSI))) {
								/* Preserve max RSSI if the
								   measurements are both
								   on-channel or both off-channel
								   */
								preserve_maxrssi = TRUE;
							} else if ((bi->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL) &&
								(bss->flags &
								WL_BSS_FLAGS_RSSI_ONCHANNEL) == 0) {
								/* Preserve the on-channel RSSI
								   measurement if the
								   new measurement is off channel
								   */
								preserve_maxrssi = TRUE;
								bss->flags |=
								WL_BSS_FLAGS_RSSI_ONCHANNEL;
							}

							if (preserve_maxrssi) {
								bss->RSSI = bi->RSSI;
								bss->SNR = bi->SNR;
								bss->phy_noise = bi->phy_noise;
							}
						}
					} else if (escan_event_status == WLC_E_STATUS_SUCCESS) {
						escan_inprogress = FALSE;
					} else {
						dbg("sync_id: %d, status:%d, misc."
							"error/abort\n",
							escan_data->sync_id, status);

						escan_bss_head = NULL;
						escan_bss_tail = NULL;
						escan_inprogress = FALSE;
					}
					break;
				}
			default:
				break;
		}
	}
}

/* listen to sockets and receive escan results */
static int
get_scan_escan(char *scan_buf, uint buf_len)
{
	int err;
	struct timeval tv, tv_tmp;
	time_t timeout;
	int len;
	struct escan_bss *result;
	struct escan_bss *next;
	wl_scan_results_t* s_result = (wl_scan_results_t*)scan_buf;
	wl_bss_info_t *bi = s_result->bss_info;
	wl_bss_info_t *bss;

	d_info = (escan_wksp_t*)malloc(sizeof(escan_wksp_t));
	d_info->fdmax = -1;
	d_info->event_fd = -1;
	err = escan_open_eventfd();
	if (err) return -1;

	tv.tv_usec = 0;
	tv.tv_sec = WL_EVENT_TIMEOUT;
	timeout = uptime() + WL_EVENT_TIMEOUT;

	escan_inprogress = TRUE;

	escan_bss_head = NULL;
	escan_bss_tail = NULL;

	while ((uptime() < timeout) && escan_inprogress) {
		memcpy(&tv_tmp, &tv, sizeof(tv));
		escan_main_loop(&tv_tmp);
	}

	escan_inprogress = FALSE;

	s_result->count = 0;
	len = buf_len - WL_SCAN_RESULTS_FIXED_SIZE;
	for (result = escan_bss_head; result; result = result->next) {
		bss = result->bss;
		if (len < bss->length) {
			dbg("Memory not enough for scan results\n");
			break;
		}
		memcpy(bi, bss, bss->length);
		bi = (wl_bss_info_t*)((int8*)bi + bss->length);
		len -= bss->length;
		s_result->count++;
	}

	for (result = escan_bss_head; result; result = next) {
		next = result->next;
		free(result);
	}

	/* close event dispatcher socket */
	if (d_info->event_fd != -1) {
		close(d_info->event_fd);
	}

	if (d_info)
		free(d_info);

	return 0;
}

static char *
wl_get_scan_results_escan(int unit)
{
	int ret, retry_times = 0;
	wl_escan_params_t *params = NULL;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params) + NUMCHANS * sizeof(uint16);
	wlc_ssid_t wst = { 0, "" };
	int i, count, scount = 0;
	wl_uint32_list_t *list;
	char data_buf[WLC_IOCTL_MAXLEN];
	chanspec_t c = WL_CHANSPEC_BW_20;
	int org_scan_time = 20, scan_time = 40;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	int band;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	wst.SSID_len = strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp)));
	if (wst.SSID_len <= MAX_SSID_LEN)
		memcpy(wst.SSID, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), wst.SSID_len);
	else
		wst.SSID_len = 0;

	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL) {
		return NULL;
	}

	memset(params, 0, params_size);
	params->params.ssid = wst;
	params->params.bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->params.scan_type = (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") && !is_psta(unit)) ? WL_SCANFLAGS_PASSIVE : 0;
	params->params.nprobes = -1;
	params->params.active_time = -1;
	params->params.passive_time = -1;
	params->params.home_time = -1;
	params->params.channel_num = 0;

	wl_ioctl(ifname, WLC_GET_BAND, &band, sizeof(band));
	if (band == WLC_BAND_5G)
	    c |= WL_CHANSPEC_BAND_5G;
#ifdef RTCONFIG_WIFI6E
	else if(band == WLC_BAND_6G)
	    c |= WL_CHANSPEC_BAND_6G;
#endif
	else
	    c |= WL_CHANSPEC_BAND_2G;
	
	memset(data_buf, 0, WLC_IOCTL_MAXLEN);
	ret = wl_iovar_getbuf(ifname, "chanspecs", &c, sizeof(chanspec_t),
		data_buf, WLC_IOCTL_MAXLEN);
	if (ret < 0)
		dbg("failed to get valid chanspec list\n");
	else {
		list = (wl_uint32_list_t *)data_buf;
		count = dtoh32(list->count);

		if (count && !(count > (data_buf + sizeof(data_buf) - (char *)&list->element[0])/sizeof(list->element[0]))) {
			for (i = 0; i < count; i++) {
				c = (chanspec_t)dtoh32(list->element[i]);
				params->params.channel_list[scount++] = c;
			}

			params->params.channel_num = htod32(scount & WL_SCAN_PARAMS_COUNT_MASK);
			params_size = WL_SCAN_PARAMS_FIXED_SIZE + scount * sizeof(uint16);
		}
	}

	params->version = htod32(ESCAN_REQ_VERSION);
	params->action = htod16(WL_SCAN_ACTION_START);

	srand((unsigned int)uptime());
	params->sync_id = htod16(rand() & 0xffff);

	params_size += OFFSETOF(wl_escan_params_t, params);

	/* extend scan channel time to get more AP probe resp */
	wl_ioctl(ifname, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
	if (org_scan_time < scan_time)
		wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &scan_time,	sizeof(scan_time));

	while ((ret = wl_iovar_set(ifname, "escan", params, params_size)) < 0 &&
				retry_times++ < WLC_SCAN_RETRY_TIMES) {
		dbg("set escan command failed, retry %d\n", retry_times);
		sleep(1);
	}

	free(params);

	/* restore original scan channel time */
	wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));

	if (ret == 0) {
		ret = get_scan_escan(scan_result, WLC_SCAN_RESULT_BUF_LEN);
		if (ret == 0)
			return scan_result;
	}

	return NULL;
}
#endif

static char *
wl_get_scan_results(int unit)
{
	int ret, retry_times = 0;
	wl_scan_params_t *params;
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + NUMCHANS * sizeof(uint16);
	wlc_ssid_t wst = { 0, "" };
	int org_scan_time = 20, scan_time = 40;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	wst.SSID_len = strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp)));
	if (wst.SSID_len <= MAX_SSID_LEN)
		memcpy(wst.SSID, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), wst.SSID_len);
	else
		wst.SSID_len = 0;

	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL) {
		return NULL;
	}

	memset(params, 0, params_size);
	params->ssid = wst;
	params->bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h") && !is_psta(unit)) ? WL_SCANFLAGS_PASSIVE : 0;
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
	params->channel_num = 0;

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	/* extend scan channel time to get more AP probe resp */
	wl_ioctl(ifname, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
	if (org_scan_time < scan_time)
		wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &scan_time,	sizeof(scan_time));

	while ((ret = wl_ioctl(ifname, WLC_SCAN, params, params_size)) < 0 &&
				retry_times++ < WLC_SCAN_RETRY_TIMES) {
		dbg("set scan command failed, retry %d\n", retry_times);
		sleep(1);
	}

	free(params);

	/* restore original scan channel time */
	wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));

	sleep(2);

	if (ret == 0) {
		list->buflen = WLC_SCAN_RESULT_BUF_LEN;
		ret = wl_ioctl(ifname, WLC_SCAN_RESULTS, scan_result, WLC_SCAN_RESULT_BUF_LEN);
		if (ret < 0) {
			PSTA_PRINT("get scan result failed\n");
		}
	}

	if (ret < 0)
		return NULL;

	return scan_result;
}

static int
wl_scan(int unit)
{
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	wl_bss_info_t *bi;
	wl_bss_info_107_t *old_bi;
	uint i, ap_count = 0;
	char macstr[18];
	char tmp[256], prefix[] = "wlXXXXXXXXXX_";
	int ctl_ch;
#ifdef __CONFIG_DHDAP__
	char ifname[NVRAM_MAX_PARAM_LEN];
	int is_dhd = 0;

	wl_ifname(unit, 0, ifname);
	is_dhd = !dhd_probe(ifname);
#endif
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ctl_ch = wl_control_channel(unit);
	if (nvram_match(strcat_r(prefix, "reg_mode", tmp), "h")
		&& ((ctl_ch > 48) && (ctl_ch < 149))) {
		dbg("scan rejected under DFS mode\n");
		return 0;
	}

#ifdef __CONFIG_DHDAP__
	if (is_dhd)
	{
		if (wl_get_scan_results_escan(unit) == NULL)
			return 0;
	}
	else
#endif
	{
		if (wl_get_scan_results(unit) == NULL)
			return 0;
	}

	if (list->count == 0)
		return 0;
	else if (
#ifdef __CONFIG_DHDAP__
			!is_dhd &&
#endif
			list->version != WL_BSS_INFO_VERSION &&
			list->version != LEGACY_WL_BSS_INFO_VERSION &&
			list->version != LEGACY2_WL_BSS_INFO_VERSION) {
		dbg("Sorry, your driver has bss_info_version %d "
		    "but this program supports only version %d.\n",
		    list->version, WL_BSS_INFO_VERSION);
		return 0;
	}

	memset(ap_list, 0, sizeof(ap_list));
	bi = list->bss_info;
	for (i = 0; i < list->count; i++) {
		/* Convert version 107 to 109 */
		if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
			old_bi = (wl_bss_info_107_t *)bi;
			bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
			bi->ie_length = old_bi->ie_length;
			bi->ie_offset = sizeof(wl_bss_info_107_t);
		}

		if (bi->ie_length) {
			if (ap_count < MAX_NUMBER_OF_APINFO) {
#if 0
				ap_list[ap_count].used = TRUE;
#endif
				memcpy(ap_list[ap_count].BSSID, (uint8 *)&bi->BSSID, 6);
				strncpy((char *)ap_list[ap_count].ssid, (char *)bi->SSID, bi->SSID_len);
				ap_list[ap_count].ssid[bi->SSID_len] = '\0';
				ap_list[ap_count].ssidLen= bi->SSID_len;
#if 0
				ap_list[ap_count].ie_buf = (uint8 *)(((uint8 *)bi) + bi->ie_offset);
				ap_list[ap_count].ie_buflen = bi->ie_length;
#endif
				if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap)
					ap_list[ap_count].channel= bi->ctl_ch;
				else
					ap_list[ap_count].channel= (bi->chanspec & WL_CHANSPEC_CHAN_MASK);
#if 0
				ap_list[ap_count].wep = bi->capability & DOT11_CAP_PRIVACY;
#endif
				ap_count++;
			}
		}
		bi = (wl_bss_info_t*)((int8*)bi + bi->length);
	}

	if (ap_count)
	{
		PSTA_PRINT("%-4s%-33s%-18s\n", "Ch", "SSID", "BSSID");

		for (i = 0; i < ap_count; i++) {
			ether_etoa((const unsigned char *) &ap_list[i].BSSID, macstr);
			PSTA_PRINT("%-4d%-33s%-18s\n",
				ap_list[i].channel,
				ap_list[i].ssid,
				macstr
			);
		}
	}

	return ap_count;
}
#endif

static struct itimerval itv;
static void
alarmtimer(unsigned long sec, unsigned long usec)
{
	itv.it_value.tv_sec  = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static int
wl_autho(char *name, struct ether_addr *ea)
{
	char buf[sizeof(sta_info_t)];

	strcpy(buf, "sta_info");
	memcpy(buf + strlen(buf) + 1, (unsigned char *)ea, ETHER_ADDR_LEN);

	if (!wl_ioctl(name, WLC_GET_VAR, buf, sizeof(buf))) {
		sta_info_t *sta = (sta_info_t *)buf;
		uint32 f = sta->flags;

		if (f & WL_STA_AUTHO)
			return 1;
	}

	return 0;
}

static uint32
wl_txframe(char *name)
{
	char cmd[64], buf[1024];
	FILE *pfp = NULL;
	char *p;
	uint32 txframe = 0;

	snprintf(cmd, sizeof(cmd), "wl -i %s counters | grep txframe", name);
	pfp = popen(cmd, "r");
	if (pfp != NULL) {
		while (fgets(buf, sizeof(buf), pfp) != NULL) {
			p = strstr(buf, "txframe");
			if (p != NULL)
				sscanf(p, "%*s %d", &txframe);
		}

		pclose(pfp);
	}

	return txframe;
}

#ifdef PSTA_DEBUG
static void check_wl_rate(char *ifname)
{
	int rate = 0;
	char rate_buf[32];

	sprintf(rate_buf, "0 Mbps");

	if (wl_ioctl(ifname, WLC_GET_RATE, &rate, sizeof(int)))
	{
		dbG("can not get rate info of %s\n", ifname);
		goto ERROR;
	}
	else
	{
		rate = dtoh32(rate);
		if ((rate == -1) || (rate == 0))
			sprintf(rate_buf, "auto");
		else
			sprintf(rate_buf, "%d%s Mbps", (rate / 2), (rate & 1) ? ".5" : "");
	}

ERROR:
	PSTA_PRINT("wl interface %s data rate: %s", ifname, rate_buf);
}
#endif
static int
psta_keepalive(int unit)
{
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char *name = NULL;
	char ifname[IFNAMSIZ] = { 0 };
	struct maclist *mac_list = NULL;
	int mac_list_size, i;
	int psta = 0;
	unsigned char bssid_null[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	wlc_ssid_t ssid = { 0, "" };
	char ssid_str[33];
#ifdef WL_SEND_NULLDATA
	char macaddr[18];
#endif

	if (unit == -1) return psta;

	if (!is_psta(unit) && !is_psr(unit))
		goto PSTA_ERR;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

	if (wl_ioctl(ifname, WLC_GET_SSID, &ssid, sizeof(ssid))) {
		PSTA_PRINT("%s psta get SSID failed!\n", ifname);
		goto PSTA_ERR;
	}
	else if ((strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp))) != ssid.SSID_len) ||
		strncmp(nvram_safe_get(strcat_r(prefix, "ssid", tmp)), (const char *) ssid.SSID, ssid.SSID_len)) {
		memset(ssid_str, 0, sizeof(ssid_str));
		PSTA_PRINT("%s psta SSID (%s) mismatch!\n", ifname, strncpy(ssid_str, (const char *) ssid.SSID, ssid.SSID_len));
		goto PSTA_ERR;
	}

#ifdef RTCONFIG_BCMARM
	memcpy(&bssid_org[unit], &bssid[unit], ETHER_ADDR_LEN);
#endif
	if (wl_ioctl(ifname, WLC_GET_BSSID, &bssid[unit], ETHER_ADDR_LEN) != 0)
	{
		PSTA_PRINT("%s psta get BSSID failed!\n", ifname);
		goto PSTA_ERR;
	}
	else if (!memcmp(&bssid[unit], bssid_null, ETHER_ADDR_LEN))
	{
		PSTA_PRINT("%s psta null BSSID!\n", ifname);
		goto PSTA_ERR;
	}

#ifdef RTCONFIG_BCMARM
	if ((wlif_count == 2) && is_psr(unit) && nvram_match(strcat_r(prefix, "reg_mode", tmp), "h")) {
		if (memcmp(&bssid_org[unit], &bssid[unit], ETHER_ADDR_LEN) != 0 && (bssid[unit].octet[5] % 16) == 8)
			eval("wl", "-i", ifname, "dfs_channel_forced", "-l", "+112/80 +136u +108l +100l +140 +132 +116");
		else
			eval("wl", "-i", ifname, "dfs_channel_forced", "0");
	}
#endif

	/* buffers and length */
	mac_list_size = sizeof(mac_list->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	mac_list = malloc(mac_list_size);

	if (!mac_list)
		goto PSTA_ERR;

	/* query wl for authenticated sta list */
	strcpy((char*)mac_list, "authe_sta_list");
	if (wl_ioctl(ifname, WLC_GET_VAR, mac_list, mac_list_size)) {
		free(mac_list);
		goto PSTA_ERR;
	}

	/* query sta_info for each STA and output one table row each */
	if (mac_list->count)
	{
		if (nvram_match(strcat_r(prefix, "akm", tmp), ""))
			psta = 2;
		else
		{
			psta = 1;
			for (i = 0; i < mac_list->count; i++) {
				if (wl_autho(ifname, &mac_list->ea[i]))
				{
					psta = 2;
					break;
				}
			}
		}
	}

	if (mac_list) free(mac_list);
PSTA_ERR:
	if (psta == 2)
	{
#ifdef WL_RECONNECT
		count_bss_down[unit] = 0;
#endif
#ifdef WL_SEND_NULLDATA
		if (++count_bss_up[unit] > 9) {
			count_bss_up[unit] = 0;
			ether_etoa((const unsigned char *) &bssid[unit], macaddr);
			PSTA_PRINT("%s: psta send keepalive nulldata to %s\n", name, macaddr);
			eval("wl", "-i", ifname, "send_nulldata", macaddr);
		}
#endif

		count_arp = (count_arp + 1) % 60;
		if (!count_arp) {
			PSTA_INFO("%s: send arp req\n", name);
			send_arpreq();
		}

		txframe_old = txframe;
		txframe = wl_txframe(ifname);

		if (txframe != txframe_old) {
			time_txframe = uptime();
			PSTA_INFO("%s: txframe: %d (uptime: %ld)\n", ifname, txframe, time_txframe);
		} else {
			if ((uptime() - time_txframe) > 200) {
				PSTA_PRINT("%s: no txframe for %ld seconds\n", ifname, (uptime() - time_txframe));
				return 0;
			}
		}

#ifdef PSTA_DEBUG
		cnt = (cnt + 1) % 10;
		if (!cnt) check_wl_rate(ifname);
#endif
	}
	else
	{
#ifdef WL_RECONNECT
		if (++count_bss_down[unit] > 3)
		{
			count_bss_down[unit] = 0;
			if (wl_scan(unit))
			{
				char *amode;
				char ssid[33] = { 0 };
				char sec[16] = { 0 };
				char *argv[] = { "wl", "-i", ifname, "join", NULL, "amode", NULL, NULL, NULL, NULL };
				int index = 6;
				unsigned char ea[ETHER_ADDR_LEN];

				strlcpy(ssid, nvram_safe_get(strcat_r(prefix, "ssid", tmp)), sizeof(ssid));
				argv[4] = ssid;

				strlcpy(sec, nvram_safe_get(strcat_r(prefix, "akm", tmp)), sizeof(sec));
				if (strstr(sec, "psk2")) amode = "wpa2psk";
				else if (strstr(sec, "psk")) amode = "wpapsk";
				else if (strstr(sec, "wpa2")) amode = "wpa2";
				else if (strstr(sec, "wpa")) amode = "wpa";
				else if (nvram_get_int(strcat_r(prefix, "auth", tmp))) amode = "shared";
				else amode = "open";

				argv[index++] = amode;
				if (ether_atoe(nvram_safe_get(strcat_r(prefix, "ap_bssid", tmp)), ea)) {
					argv[index++] = "-b";
					argv[index++] = nvram_safe_get(strcat_r(prefix, "ap_bssid", tmp));
				}

				PSTA_PRINT("%s: join ap manually\n", ifname);
				_eval(argv, NULL, 0, NULL);
			}
		}
#endif
	}

	return psta;
}

static void
psta_monitor_exit(int sig)
{
#if defined(RTCONFIG_DPSTA) || defined(RTCONFIG_DPSR)
	char word[80], *next;
	int unit;
#endif
	char wlvif[] = "wlxxxx";
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	char dpsta_ifnames[32] = { 0 };

	if (sig == SIGTERM)
	{
#if defined(RTCONFIG_DPSTA) || defined(RTCONFIG_DPSR)
#ifdef RTCONFIG_DPSTA
		strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));
#elif defined(RTCONFIG_DPSR)
		strlcpy(dpsta_ifnames, nvram_safe_get("dpsr_ifnames"), sizeof(dpsta_ifnames));
#endif
		if (strlen(dpsta_ifnames)) {
			foreach(word, dpsta_ifnames, next) {
				wl_ioctl(word, WLC_GET_INSTANCE, &unit, sizeof(unit));
				snprintf(prefix, sizeof(prefix), "wl%d_", unit);

				if (!strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp)))) {
					snprintf(wlvif, sizeof(wlvif), "wl%d.1", unit);
					eval("wl", "-i", wlvif, "bss", "down");

					eval("wl", "-i", word, "disassoc");
				}
			}
		}
		else
#endif
		{
			snprintf(prefix, sizeof(prefix), "wl%d_", nvram_get_int("wlc_band"));

			if (!strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp)))) {
				if (is_psr(nvram_get_int("wlc_band"))) {
					snprintf(wlvif, sizeof(wlvif), "wl%d.1", nvram_get_int("wlc_band"));
					eval("wl", "-i", wlvif, "bss", "down");
				}

				strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
				eval("wl", "-i", ifname, "disassoc");
			}
		}

		alarmtimer(0, 0);
		remove("/var/run/psta_monitor.pid");
		exit(0);
	}
}

#if defined(RTCONFIG_DPSTA) || defined(RTCONFIG_DPSR)
#define        WL_IW_RSSI_NO_SIGNAL    -91     /* NDIS RSSI link quality cutoffs */
#define MAX_DPSTA      6

int rets[MAX_DPSTA], pre_rets[MAX_DPSTA];
char pap[MAX_DPSTA][18];

static void
init_ex_report()
{
	int idx = 0;
	char name[80], *next;
	char dpsta_ifnames[32] = { 0 };

#ifdef RTCONFIG_DPSTA
		strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));
#elif defined(RTCONFIG_DPSR)
		strlcpy(dpsta_ifnames, nvram_safe_get("dpsr_ifnames"), sizeof(dpsta_ifnames));
#endif
	if (strlen(dpsta_ifnames)) {
		foreach(name, dpsta_ifnames, next) {
			rets[idx] = -1;
			pre_rets[idx] = -1;
			memset(&pap[idx], 0 , sizeof(pap[idx]));
			idx++;
		}
	}
}
#endif

static void
psta_monitor(int sig)
{
#if defined(RTCONFIG_DPSTA) || defined(RTCONFIG_DPSR)
	char name[80], *next;
	int unit;
	int ret, ret_all = 0;
	int idx = 0;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlcXXXXXXXXX_";
	char dpsta_ifnames[32] = { 0 };
	/* more info */
	int rssi = WL_IW_RSSI_NO_SIGNAL;
	char ure_mac[18];
	unsigned char bssid[6];
	unsigned char bssid_null[6] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
#ifdef RTCONFIG_DPSR
	int dpsr_main_ret, dpsr_backup_ret;
	char dpsr_backup[16] = {0};
	char dpsr_main[16] = {0};
#endif
#endif

	if (!nvram_get_int("wlready"))
		return;

	if (sig == SIGALRM)
	{
		connected_old = connected;

#if defined(RTCONFIG_DPSTA) || defined(RTCONFIG_DPSR)
#ifdef RTCONFIG_DPSTA
		strlcpy(dpsta_ifnames, nvram_safe_get("dpsta_ifnames"), sizeof(dpsta_ifnames));
#elif defined(RTCONFIG_DPSR)
		strlcpy(dpsta_ifnames, nvram_safe_get("dpsr_ifnames"), sizeof(dpsta_ifnames));
		strlcpy(dpsr_main, nvram_safe_get("dpsr_main"), sizeof(dpsr_main));
#endif
		if (strlen(dpsta_ifnames)) {
			foreach(name, dpsta_ifnames, next) {
				wl_ioctl(name, WLC_GET_INSTANCE, &unit, sizeof(unit));

				snprintf(prefix, sizeof(prefix), "wl%d_", unit);
				if (!strlen(nvram_safe_get(strcat_r(prefix, "ssid", tmp))))
					ret = 0;
				else
					ret = psta_keepalive(unit);

				snprintf(prefix, sizeof(prefix), "wlc%d_", idx);
				nvram_set_int(strcat_r(prefix, "state", tmp), ret);
#ifdef RTCONFIG_DPSR
				if(strncmp(dpsr_main, name, strlen(dpsr_main)) == 0) {
					dpsr_main_ret = ret; 
				} else {
					dpsr_backup_ret = ret; 
					strlcpy(dpsr_backup, name, sizeof(dpsr_backup));
				}
#endif
				ret_all += (ret == 2);
				/* get more info */
				if(nonre_clientMode()) {
					rets[idx] = ret;

					if((rets[idx] != pre_rets[idx]) || (nvram_match("pdebug", "1"))) {
						PSTA_PRINT("(%s)...report event[%d][%s], [%d]->[%d], retchk:%d\n", (rets[idx] != pre_rets[idx])?"***":"---", idx, name, pre_rets[idx], rets[idx], ret);

						if(pre_rets[idx]==2 && rets[idx]!=2)
							PSTA_LOG("disconnected w/ :%s\n", pap[idx]);

						memset(ure_mac, 0x0, 18);
						if (!wl_ioctl(name, WLC_GET_BSSID, bssid, sizeof(bssid)) && memcmp(bssid, bssid_null, ETHER_ADDR_LEN)) {
							ether_etoa((const unsigned char *) &bssid, ure_mac);
						} else {
							PSTA_PRINT("[wlc] WLC_GET_BSSID error:%s[%d]\n", name, idx);
							goto dploop;
						}

						memcpy(pap[idx], ure_mac, sizeof(pap[idx]));

						if(pre_rets[idx]==2 && rets[idx]!=2) {
							_dprintf("!!! psta_monitor see ghosts\n");
						}

						if(wl_ioctl(name, WLC_GET_RSSI, &rssi, sizeof(rssi))) {
							PSTA_PRINT("get rssi fail (%s)\n", name);
							goto dploop;
						} 

						if(rets[idx]==2 && pre_rets[idx]!=2)
							PSTA_LOG("[%s], connected w/ bssid[%s], rssi=%d\n", name, pap[idx], rssi);
					}
dploop:
					pre_rets[idx] = rets[idx];
				}

				idx++;
			}

			PSTA_PRINT("keep alive: %d\n", ret_all);

			connected = (ret_all > 0);
		}
		else
#endif
		{
			connected = (psta_keepalive(nvram_get_int("wlc_band")) == 2);
		}

#ifdef RTCONFIG_DPSR
		PSTA_PRINT("dpsr_main:[%s](%d), dpsr_backup:[%s](%d)\n", dpsr_main, dpsr_main_ret, dpsr_backup, dpsr_backup_ret);
		if((dpsr_main_ret==0 && dpsr_backup_ret!=0) 
		|| (dpsr_main_ret!=0 && dpsr_backup_ret!=0 && strcmp(dpsr_main, nvram_safe_get("wl1_ifname")))
		)
		{
			PSTA_PRINT("%s, reset%s dpsr_main as %s, and replace old(%s) from lan br.\n", __func__, dpsr_main_ret==0?"":" back", dpsr_backup, dpsr_main);
			eval("brctl", "delif", nvram_safe_get("lan_ifname"), dpsr_main);
			eval("brctl", "addif", nvram_safe_get("lan_ifname"), dpsr_backup);
			nvram_set("dpsr_main", dpsr_backup);
		}
#endif
		if (connected != connected_old) {
			PSTA_PRINT("link: %d\n", connected);

			nvram_set_int("wlc_state", connected ? WLC_STATE_CONNECTED : WLC_STATE_CONNECTING);

			if (connected)
				notify_rc_and_wait("restart_wlcmode 1");
			else {
				notify_rc_and_wait("restart_wlcmode 0");
				if (connected_old != -1) {
#if defined(RTCONFIG_BRCM_HOSTAPD) || defined(RTCONFIG_DPSR)
					if(nvram_match("pa_mon", "2"))
						notify_rc("restart_wpasupp");
					else
#endif
					notify_rc("restart_wireless");
				}
			}
		}

		alarm(NORMAL_PERIOD);
	}
}

int
psta_monitor_main(int argc, char *argv[])
{
	FILE *fp;
	sigset_t sigs_to_catch;

	if (nvram_match("x_Setting", "0"))
		return 0;

#ifdef RTCONFIG_QTN
	if (nvram_get_int("wlc_band") == 1)
		return 0;
#endif

	if (!psta_exist() && !psr_exist())
		return 0;

#ifdef RTCONFIG_DPSTA
	if (!nvram_match("dpsta_ifnames", "")) {
		if (!strlen(nvram_safe_get("wlc0_ssid")) &&
		    !strlen(nvram_safe_get("wlc1_ssid")))
			return 0;
	} else
#endif
#ifdef RTCONFIG_DPSR
	if (!nvram_match("dpsr_ifnames", "")) {
		if (!strlen(nvram_safe_get("wlc0_ssid")) &&
		    !strlen(nvram_safe_get("wlc1_ssid")))
			return 0;
	} else
#endif
	if (!strlen(nvram_safe_get("wlc_ssid"))
#if defined(RPAX56) || defined(RPAX58)
	&& !strlen(nvram_safe_get("wlc0_ssid"))
	&& !strlen(nvram_safe_get("wlc1_ssid"))
#endif
	)
		return 0;

	/* write pid */
	if ((fp = fopen("/var/run/psta_monitor.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	psta_debug = nvram_get_int("psta_debug");

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, psta_monitor);
	signal(SIGTERM, psta_monitor_exit);

	/* turn off wireless led of other bands under psta mode */
	if (is_psta(nvram_get_int("wlc_band")))
		setWlOffLed();

#ifdef RTCONFIG_BCMARM
	int i;
	wlif_count = num_of_wl_if();
	for (i = 0; i < wlif_count; i++)
		memset(&bssid[i], 0, ETHER_ADDR_LEN);
#endif

	nvram_set_int("wlc_state", WLC_STATE_CONNECTING);
	nvram_set_int("wlc0_state", WLC_STATE_CONNECTING);
	nvram_set_int("wlc1_state", WLC_STATE_CONNECTING);
	time_txframe = uptime();

	alarm(NORMAL_PERIOD);

#if defined(RTCONFIG_DPSTA) || defined(RTCONFIG_DPSR)
	if(nonre_clientMode()) {
		init_ex_report();
	}
#endif

	/* Most of time it goes to sleep */
	while (1)
	{
		pause();
	}

	return 0;
}
#endif
#endif
