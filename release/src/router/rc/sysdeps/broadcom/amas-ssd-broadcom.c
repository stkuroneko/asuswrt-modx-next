#include <wlutils.h>
#include <wlscan.h>
#include <bcmendian.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <shutils.h>
#include <shared.h>
#include <wlioctl.h>
#ifdef __CONFIG_DHDAP__
#include <bcmutils.h>
#include <security_ipc.h>
#endif

#include <amas_ssd.h>

#if defined(RTCONFIG_AMAS)
#define MULTI_SSID

#define WLC_SCAN_RETRY_TIMES		2
#define NUMCHANS			64
#define MAX_SSID_LEN			32

int stop_scan = 0;

static int
wl_parse_ssid_list(ssid_list_t *ssid_list, wlc_ssid_t* ssid, int idx, int max)
{
	char str[33];
	int i = 0;

	for (i = 0; i < ssid_list->ssid_count; i++) {
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str), "%s", ssid_list->ssid[i]);
#if 0
		if (strlen(str) > MAX_SSID_LEN) {
			dbg("ssid <%s> exceeds %d\n", str, MAX_SSID_LEN);
			return -1;
		}
#endif
		if (strlen(str) == 0)
			ssid[idx].SSID_len = 0;

		if (idx < max) {
			strcpy((char*)ssid[idx].SSID, str);
			ssid[idx].SSID_len = strlen(str);
		}
		idx++;
	}

	return idx;
}

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
escan_main_loop(struct timeval *tv, char *wl_ifname)
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

		SSD_DBG("recved %d bytes from eventfd, ifname: %s, wl_ifname: %s\n", bytes, ifname, wl_ifname);

		if (strcmp(wl_ifname, ifname) != 0) {
			SSD_DBG("invalid ifname (%s), should be %s\n", ifname, wl_ifname);
			return;
		}

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
get_scan_escan(char *scan_buf, uint buf_len, char *wl_ifname)
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
		escan_main_loop(&tv_tmp, wl_ifname);
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
wl_get_scan_results_escan(int unit, char *scan_result, ssid_list_t *ssid_list)
{
	int ret, retry_times = 0;
	wl_escan_params_t *params = NULL;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params) + NUMCHANS * sizeof(uint16);
	int i, count, scount = 0;
	wl_uint32_list_t *list;
	char data_buf[WLC_IOCTL_MAXLEN];
	chanspec_t c = WL_CHANSPEC_BW_20;
	int org_scan_time = 20, scan_time = 40;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[16];
	int band;
#ifdef MULTI_SSID
	char *p;
	int nssid = 0;
	wlc_ssid_t ssids[WL_SCAN_PARAMS_SSID_MAX];
#endif

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	SSD_LOG("unit(%d) - ifname (%s) for escan\n", unit, ifname);
#ifdef MULTI_SSID
	params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
#endif
	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL) {
		return NULL;
	}

	memset(params, 0, params_size);
	params->params.bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->params.scan_type = 0;	//Acitve Scan
	params->params.nprobes = -1;
	params->params.active_time = -1;
	params->params.passive_time = -1;
	params->params.home_time = -1;
	params->params.channel_num = 0;
#ifdef MULTI_SSID
	memset(ssids, 0, WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t));
#endif
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
#ifndef MULTI_SSID
			params->params.channel_num = htod32(scount & WL_SCAN_PARAMS_COUNT_MASK);
			params_size = WL_SCAN_PARAMS_FIXED_SIZE + scount * sizeof(uint16);
#endif
		}
	}

#ifdef MULTI_SSID
	/* for ssid list */
	nssid = wl_parse_ssid_list(ssid_list, ssids, nssid, WL_SCAN_PARAMS_SSID_MAX);

	for (i = 0; i < nssid; i++) {
		ssids[i].SSID_len = htod32(ssids[i].SSID_len);
	}

	/* For a single ssid, use the single fixed field */
	if (nssid == 1) {
		nssid = 0;
		memcpy(&params->params.ssid, &ssids[0], sizeof(ssids[0]));
	}

	/* Copy ssid array if applicable */
	if (nssid > 0) {
		i = OFFSETOF(wl_scan_params_t, channel_list) + scount * sizeof(uint16);
		i = ROUNDUP(i, sizeof(uint32));
		if (i + nssid * sizeof(wlc_ssid_t) > (uint)params_size) {
			dbg("additional ssids exceed params_size\n");
			free(params);
			return NULL;
		}

		p = (char*)&params->params + i;
		memcpy(p, ssids, nssid * sizeof(wlc_ssid_t));
		p += nssid * sizeof(wlc_ssid_t);
	} else {
		p = (char*)params->params.channel_list + scount * sizeof(uint16);
	}

	params->params.channel_num = htod32((nssid << WL_SCAN_PARAMS_NSSID_SHIFT) |
						(scount & WL_SCAN_PARAMS_COUNT_MASK));
	params_size = p - (char*)&params->params;
#endif

	params->version = htod32(ESCAN_REQ_VERSION);
	params->action = htod16(WL_SCAN_ACTION_START);

	srand((unsigned int)uptime());
	params->sync_id = htod16(rand() & 0xffff);
	SSD_DBG("unit(%d) - sync_id is %X\n", unit, params->sync_id);

	params_size += OFFSETOF(wl_escan_params_t, params);
		
	/* extend scan channel time to get more AP probe resp */
	wl_ioctl(ifname, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
	if (org_scan_time < scan_time)
		wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &scan_time,	sizeof(scan_time));

	while ((ret = wl_iovar_set(ifname, "escan", params, params_size)) < 0 &&
				retry_times++ < WLC_SCAN_RETRY_TIMES) {
		SSD_ERROR("set escan command failed, retry %d\n", retry_times);
		sleep(1);
	}

	free(params);

	/* restore original scan channel time */
	wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));

	if (stop_scan) {
		SSD_DBG("stop scan for unit (%d)\n", unit);
		return NULL;
	}

	if (ret == 0) {
		ret = get_scan_escan(scan_result, WLC_SCAN_RESULT_BUF_LEN, ifname);
		if (ret == 0)
			return scan_result;
	}

	return NULL;
}
#endif

static char *
wl_get_scan_results(int unit, char *scan_result, ssid_list_t *ssid_list)
{
	int ret, retry_times = 0;
	wl_scan_params_t *params;
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + NUMCHANS * sizeof(uint16);
	int org_scan_time = 20, scan_time = 40;
	char tmp[NVRAM_BUFSIZE], prefix[] = "wlXXXXXXXXXX_";
	char ifname[16];
#ifdef MULTI_SSID
	char *p;
	int nssid = 0, scount = 0, i = 0;
	wlc_ssid_t ssids[WL_SCAN_PARAMS_SSID_MAX];
#endif

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
#ifdef MULTI_SSID
	params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
#endif
	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL) {
		return NULL;
	}

	memset(params, 0, params_size);
	params->bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = 0;	//Active Scan
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
	params->channel_num = 0;
#ifdef MULTI_SSID
	memset(ssids, 0, WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t));
#endif

#ifdef MULTI_SSID
	/* for ssid list */
	nssid = wl_parse_ssid_list(ssid_list, ssids, nssid, WL_SCAN_PARAMS_SSID_MAX);

	for (i = 0; i < nssid; i++) {
		ssids[i].SSID_len = htod32(ssids[i].SSID_len);
	}

	/* For a single ssid, use the single fixed field */
	if (nssid == 1) {
		nssid = 0;
		memcpy(&params->ssid, &ssids[0], sizeof(ssids[0]));
	}

	/* Copy ssid array if applicable */
	if (nssid > 0) {
		i = OFFSETOF(wl_scan_params_t, channel_list) + scount * sizeof(uint16);
		i = ROUNDUP(i, sizeof(uint32));
		if (i + nssid * sizeof(wlc_ssid_t) > (uint)params_size) {
			dbg("additional ssids exceed params_size\n");
			free(params);
			return NULL;
		}

		p = (char*)params + i;
		memcpy(p, ssids, nssid * sizeof(wlc_ssid_t));
		p += nssid * sizeof(wlc_ssid_t);
	} else {
		p = (char*)params->channel_list + scount * sizeof(uint16);
	}

	params->channel_num = htod32((nssid << WL_SCAN_PARAMS_NSSID_SHIFT) |
						(scount & WL_SCAN_PARAMS_COUNT_MASK));
	params_size = p - (char*)params + nssid * sizeof(wlc_ssid_t);
#endif

	strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
	SSD_LOG("unit(%d) - ifname (%s) for scan\n", unit, ifname);

	/* extend scan channel time to get more AP probe resp */
	wl_ioctl(ifname, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
	if (org_scan_time < scan_time)
		wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &scan_time,	sizeof(scan_time));

	while ((ret = wl_ioctl(ifname, WLC_SCAN, params, params_size)) < 0 &&
				retry_times++ < WLC_SCAN_RETRY_TIMES) {
		SSD_ERROR("set scan command failed, retry %d\n", retry_times);
		sleep(1);
	}

	free(params);

	/* restore original scan channel time */
	wl_ioctl(ifname, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));

	if (stop_scan) {
		SSD_DBG("stop scan for unit (%d)\n", unit);
		return NULL;
	}

	sleep(2);

	if (ret == 0) {
		list->buflen = WLC_SCAN_RESULT_BUF_LEN;
		ret = wl_ioctl(ifname, WLC_SCAN_RESULTS, scan_result, WLC_SCAN_RESULT_BUF_LEN);
		if (ret < 0) {
			SSD_ERROR("get scan result failed, retry %d\n", retry_times);
		}
	}

	if (ret < 0)
		return NULL;

	return scan_result;
}

struct site_survey_result *do_site_survey(int unit, ssid_list_t *ssid_list)
{
	struct site_survey_result *bss_list = NULL, *current_bss = NULL;
	uint i, left;
	uint8 channel;
	char scan_result[WLC_SCAN_RESULT_BUF_LEN];
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	wl_bss_info_t *bi;
	wl_bss_info_107_t *old_bi;
	struct bss_ie_hdr *ie;
	struct vndr_ie *ie_vs;
	int val;
	char vsie_str[MAX_VSIE_LEN];
	char bssid[ETHER_ADDR_LEN];
	struct site_survey_result *bss = NULL;

#ifdef __CONFIG_DHDAP__
	char ifname[NVRAM_MAX_PARAM_LEN];
	int is_dhd = 0;

	wl_ifname(unit, 0, ifname);
	is_dhd = !dhd_probe(ifname);
#endif

	val = nvram_get_int("wlc_scan_state");
	if ((val > WLCSCAN_STATE_STOPPED) && (val < WLCSCAN_STATE_FINISHED))
		return NULL;
#ifdef __CONFIG_DHDAP__
	if (is_dhd) {
		if (wl_get_scan_results_escan(unit, scan_result, ssid_list) == NULL)
			return NULL;
	}
	else
#endif
	{
		if (wl_get_scan_results(unit, scan_result, ssid_list) == NULL)
			return NULL;
	}

	
	if (list->count == 0)
	{
		return NULL;
	}
	else if (
#ifdef __CONFIG_DHDAP__
			!is_dhd &&
#endif
			list->version != WL_BSS_INFO_VERSION &&
			list->version != LEGACY_WL_BSS_INFO_VERSION &&
			list->version != LEGACY2_WL_BSS_INFO_VERSION) {
		SSD_DBG("Sorry, your driver has bss_info_version %d "
		    "but this program supports only version %d.\n",
		    list->version, WL_BSS_INFO_VERSION);
		return NULL;
	}

	bi = list->bss_info;

	for (i = 0; i < list->count; i++) {
		/* Convert version 107 to 109 */
		if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
			old_bi = (wl_bss_info_107_t *)bi;
#if defined(RTCONFIG_HND_ROUTER_AX_6756)
			bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel, WL_CHANNEL_2G5G_BAND(old_bi->channel));
#else
			bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
#endif
			bi->ie_length = old_bi->ie_length;
			bi->ie_offset = sizeof(wl_bss_info_107_t);
		}

		if (bi->ie_length) {
			if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap)
				channel= bi->ctl_ch;
			else
				channel= (bi->chanspec & WL_CHANSPEC_CHAN_MASK);
		}
		else
			continue;

		if (nvram_get_int("filter_vsie") == 0) {
		if ((bss = malloc(sizeof(struct site_survey_result))) == NULL) {
			SSD_ERROR("malloc failed\n");
			continue;
		}
			
		memset(bss, 0, sizeof(struct site_survey_result));

		// channel
		bss->channel = channel;

		// bw
                if (CHSPEC_IS20(bi->chanspec))
                        bss->bw = 20;
                else if (CHSPEC_IS40(bi->chanspec))
                        bss->bw = 40;
                else if (CHSPEC_IS80(bi->chanspec))
                        bss->bw = 80;
#if defined(RTCONFIG_HND_ROUTER_AX) || defined(RTCONFIG_BW160M)
                else if (CHSPEC_IS160(bi->chanspec))
                        bss->bw = 160;
#endif
		SSD_DBG("bw=%d\n", bss->bw);

		// bssid
		memcpy(&bss->bssid, &bi->BSSID, ETHER_ADDR_LEN);
		ether_etoa((const unsigned char *) &bss->bssid, bssid);
		SSD_DBG("bssid=%s\n", bssid);
			
		// rssi
		bss->rssi = (unsigned char)bi->RSSI;

		// ssid
		strncpy((char *)bss->ssid, (char *)bi->SSID, bi->SSID_len);
		bss->ssid[bi->SSID_len] = '\0';
		bss->ssid_len = bi->SSID_len;
		SSD_DBG("ssid=%s\n", bss->ssid);
		}

		ie = (struct bss_ie_hdr *)((unsigned char *) bi + bi->ie_offset);
		for (left = bi->ie_length; left > 0;
			left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len)) {

			if (ie->elem_id != VS_ID)
				continue;

			if (memcmp(ie->oui, OUI_ASUS, 3))
				continue;

			ie_vs = (struct vndr_ie *) ie;


			if (nvram_get_int("filter_vsie")) {
			if ((bss = malloc(sizeof(struct site_survey_result))) == NULL) {
				SSD_ERROR("malloc failed\n");
				continue;
			}
				
			memset(bss, 0, sizeof(struct site_survey_result));

			// channel
			bss->channel = channel;

			// bssid
			memcpy(&bss->bssid, &bi->BSSID, ETHER_ADDR_LEN);
			ether_etoa((const unsigned char *) &bss->bssid, bssid);
			SSD_DBG("bssid=%s\n", bssid);
				
			// rssi
			bss->rssi = (unsigned char)bi->RSSI;

			// ssid
			strncpy((char *)bss->ssid, (char *)bi->SSID, bi->SSID_len);
			bss->ssid[bi->SSID_len] = '\0';
			bss->ssid_len = bi->SSID_len;
			SSD_DBG("ssid=%s\n", bss->ssid);
			}

			// vsie
			bss->vsie_len = ie_vs->len - OUI_LEN;
			memcpy((void *)&bss->vsie[0], (void *)&ie_vs->data[0], bss->vsie_len);
			memset(vsie_str, 0, sizeof(vsie_str));
			hex2str(&ie_vs->data[0], vsie_str, bss->vsie_len);
			SSD_DBG("%s vsie_len=%d\n", vsie_str, bss->vsie_len);

			if (nvram_get_int("filter_vsie")) {
			if (current_bss) {
				current_bss->next = bss;
			}
			current_bss = bss;

			if (bss_list == NULL)
				bss_list = bss;
			
			goto NEXT_BI;
			}
		}

		if (nvram_get_int("filter_vsie") == 0) {
		if (current_bss) {
			current_bss->next = bss;
		}
		current_bss = bss;

		if (bss_list == NULL)
			bss_list = bss;
		}

NEXT_BI:
		bi = (wl_bss_info_t*)((int8*)bi + bi->length);
	}
	return bss_list;
}

void stop_site_survey()
{
	stop_scan = 1;
}
#endif //#if defined(RTCONFIG_AMAS)
