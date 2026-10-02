#include <string.h>
#include <acsd.h>
#include <conn_diag.h>
#include <conn_diag-sql.h>


bool acsd_swap = FALSE;

#ifdef RTCONFIG_HND_ROUTER
#define SYS_TEMP_PATH "/sys/devices/virtual/thermal/thermal_zone0/temp"
#else
#define SYS_TEMP_PATH "/proc/dmu/temperature"
#endif

#define CMD_MAX 128

extern int get_hw_acceleration(char *output, int size){
#ifdef RTCONFIG_HND_ROUTER
	snprintf(output, size, "%s,%s", nvram_safe_get("runner_disable"), nvram_safe_get("fc_disable"));
#else
	snprintf(output, size, "%s", nvram_safe_get("ctf_disable"));
#endif

	return 0;
}

extern int get_sys_clk(char *output, int size){
#ifdef RTCONFIG_HND_ROUTER
	snprintf(output, size, "-1");
#else
	snprintf(output, size, "%s", nvram_safe_get("clkfreq"));
#endif

	return 0;
}

extern int get_sys_temp(unsigned int *temp){
	char cmd[CMD_MAX] = {0};
	FILE *fp = NULL;

	snprintf(cmd, sizeof(cmd), "/bin/cat %s 2>/dev/null", SYS_TEMP_PATH);
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute cat.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

#ifdef RTCONFIG_HND_ROUTER
	char buf[16];
	unsigned int temperature;

	fgets(buf, sizeof(buf), fp);
	temperature = atoi(buf);
	*temp = temperature/1000;
#else
	fscanf(fp, "CPU temperature : %u%*s", temp);
#endif

	pclose(fp);

	return 0;
}

extern int get_wifi_chip(char *ifname, char *output, int size){
	wlc_rev_info_t revinfo;

	memset(&revinfo, 0, sizeof(revinfo));
	if(wl_ioctl(ifname, WLC_GET_REVINFO, &revinfo, sizeof(revinfo)) < 0){
		if(output != NULL) output[0] = '\0';
		DIAG_LOG(LOG_DEBUG, "[WARNING] get revinfo %s error!!!", ifname);

		return -1;
	}

	snprintf(output, size, "0x%x,0x%x,0x%x", revinfo.chipnum, revinfo.chiprev, revinfo.chippkg);

	return 0;
}

extern int get_wifi_temp(char *ifname, unsigned int *temp){
	char buf[WLC_IOCTL_SMLEN];
	unsigned int *tt;

	snprintf(buf, sizeof(buf), "phy_tempsense");

	if(wl_ioctl(ifname, WLC_GET_VAR, buf, sizeof(buf)) < 0){
		if(temp != NULL) *temp = 0;
		DIAG_LOG(LOG_DEBUG, "[WARNING] get phy_tempsense %s error!!!", ifname);

		return -1;
	}

	tt = (unsigned int *)buf;
	*temp = *tt;

	return 0;
}

extern int get_wifi_country(char *ifname, char *output, int len){
	char cmd[CMD_MAX] = {0};
	FILE *fp = NULL;
	int count;
	//need fix
	if(output != NULL) output[0] = '\0';
	return -1;

	snprintf(cmd, sizeof(cmd), "/usr/sbin/wl -i %s country", ifname);
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute wl.");
		DIAG_LOG(LOG_DEBUG, "... Failed");
		if(output != NULL) output[0] = '\0';

		return -1;
	}

	fgets(output, len, fp);
	pclose(fp);
	count = strlen(output);
	output[count-1] = '\0';

	return 0;
}

extern int get_wifi_noise(char *ifname, char *output, int len){
	char cmd[CMD_MAX] = {0};
	FILE *fp = NULL;
	int count;

	snprintf(cmd, sizeof(cmd), "/usr/sbin/wl -i %s noise", ifname);
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute wl.");
		DIAG_LOG(LOG_DEBUG, "... Failed");
		if(output != NULL) output[0] = '\0';

		return -1;
	}

	fgets(output, len, fp);
	pclose(fp);
	count = strlen(output);
	output[count-1] = '\0';

	return 0;
}

extern int get_wifi_mcs(char *ifname, char *output, int len){
	char cmd[CMD_MAX] = {0};
	FILE *fp = NULL;
	int count;

	snprintf(cmd, sizeof(cmd), "/usr/sbin/wl -i %s nrate", ifname);
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute wl.");
		DIAG_LOG(LOG_DEBUG, "... Failed");
		if(output != NULL) output[0] = '\0';

		return -1;
	}

	fgets(output, len, fp);
	pclose(fp);
	count = strlen(output);
	output[count-1] = '\0';

	return 0;
}

#ifdef RTCONFIG_BCMARM
extern int get_bss_info(char *ifname, int *capability){
	char buf[WLC_IOCTL_MAXLEN];
	wl_bss_info_t *bi;

	*(uint32*)buf = htod32(WLC_IOCTL_MAXLEN);
	if(wl_ioctl(ifname, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN) < 0)
		return -1;

	bi = (wl_bss_info_t*)(buf + 4);

	*capability = bi->capability;

	return 0;
}

#ifndef MAX_SUBIF_NUM
#define MAX_SUBIF_NUM 4
#endif

extern int get_subif_count(char *target, int *count){
	char ifname[128], *next;
	int idx = 0, idxList = 0;
	char prefix[32], tmp[100];

	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
		if(!strcmp(ifname, target)){
			*count = 0;
			for(idxList = 1; idxList < MAX_SUBIF_NUM; ++idxList){
				snprintf(prefix, sizeof(prefix), "wl%d.%d_", idx, idxList);

				if(nvram_get_int(strcat_r(prefix, "bss_enabled", tmp)) == 1)
					++(*count);
			}

			return *count;
		}

		++idx;
	}

	return 0;
}

extern int get_subif_ssid(char *target, char *output, int outputlen){
	char ifname[128], *next;
	int idx = 0, idxList = 0;
	char prefix[32], tmp[100], ssid[33], ssid_enc[64];
	char *ptr;
	int len;
	int count;

	len = 0;
	ptr = output;
	memset(output, 0, outputlen);

	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
		if(!strcmp(ifname, target)){
			count = 0;
			for(idxList = 1; idxList < MAX_SUBIF_NUM; ++idxList){
				snprintf(prefix, sizeof(prefix), "wl%d.%d_", idx, idxList);

				if(nvram_get_int(strcat_r(prefix, "bss_enabled", tmp)) != 1)
					continue;

				if(count != 0){
					len = strlen(output);
					ptr = output+len;
					snprintf(ptr, outputlen-len, ",");
				}

				memset(ssid_enc, 0, sizeof(ssid_enc));
				snprintf(ssid, sizeof(ssid), "%s", nvram_safe_get(strcat_r(prefix, "ssid", tmp)));
				if (base64_encode((const unsigned char*)ssid, ssid_enc, strlen(ssid))) {
					len = strlen(output);
					ptr = output+len;
					snprintf(ptr, outputlen-len, "%s", ssid_enc);
					++count;
				}
			}

			break;
		}

		++idx;
	}

	if(!(*output))
		snprintf(output, outputlen, "-1");

	return 0;
}

// version,chanspec,tx,inbss,obss,nocat,nopkt,doze,txop,goodtx,badtx,glitch,badplcp,knoise,idle,timestamp
extern int get_wifi_chanim(char *ifname, char *output, int outputlen){

	char *chanim_buf = NULL;
	int count;
	wl_chanim_stats_t *chanim_stats;
	wl_chanim_stats_t param;
	int ret;
	char *ptr;
	int datalen;
	int i, j;

	chanim_buf = malloc(outputlen);

	snprintf(output, outputlen, "-1");

	if(!chanim_buf){
		DIAG_LOG(LOG_DEBUG, "[WARNING] Memory can not allocated!!!");
		return -1;
	}


	count = WL_CHANIM_COUNT_ONE;
	chanim_stats = (wl_chanim_stats_t *)chanim_buf;

	param.buflen = htod32(outputlen);
	param.count = htod32(count);

	ret = wl_iovar_getbuf(ifname, "chanim_stats", &param, sizeof(wl_chanim_stats_t), chanim_buf, sizeof(chanim_buf));
	if(ret < 0){
		DIAG_LOG(LOG_DEBUG, "[WARNING] get chanim_stats %s error!!!", ifname);

		free(chanim_buf);
		return -1;
	}

	chanim_stats->buflen = dtoh32(chanim_stats->buflen);
	chanim_stats->version = dtoh32(chanim_stats->version);
	chanim_stats->count = dtoh32(chanim_stats->count);

	DIAG_LOG(LOG_DEBUG, "buflen: %d, version: %d count: %d\n", chanim_stats->buflen, chanim_stats->version, chanim_stats->count);

	datalen = 0;
	ptr = output;
	snprintf(ptr, outputlen, "%d", chanim_stats->version);

#ifdef RTCONFIG_HND_ROUTER_AX
	if(chanim_stats->version == WL_CHANIM_STATS_V2) {
		chanim_stats_v2_t *stats;
		char chanspecbuf[32];

		stats = (chanim_stats_v2_t *)chanim_stats->stats;
		for(i = 0; i < count; ++i, ++stats){
			datalen = strlen(output);
			ptr = output+datalen;
			snprintf(ptr, outputlen-datalen, ",0x%4x(%s)", stats->chanspec, wf_chspec_ntoa(stats->chanspec, chanspecbuf));

			for(j = 0; j < CCASTATS_V2_MAX; ++j){
				datalen = strlen(output);
				ptr = output+datalen;
				snprintf(ptr, outputlen-datalen, ",%d", stats->ccastats[j]);
			}

			datalen = strlen(output);
			ptr = output+datalen;
			snprintf(ptr, outputlen-datalen, ",%d,%d,%d,%d", dtoh32(stats->glitchcnt), dtoh32(stats->badplcp), stats->bgnoise, dtoh32(stats->timestamp));
		}
	}
	else
#else
	{
		chanim_stats_t *stats;

		for(i = 0; i < count; ++i, ++stats){
			stats = (chanim_stats_t *)&chanim_stats->stats[i];

			datalen = strlen(output);
			ptr = output+datalen;
			snprintf(ptr, outputlen-datalen, ",0x%4x", stats->chanspec);

			for(j = 0; j < CCASTATS_MAX; ++j){
				datalen = strlen(output);
				ptr = output+datalen;
				snprintf(ptr, outputlen-datalen, ",%d", stats->ccastats[j]);
			}

			datalen = strlen(output);
			ptr = output+datalen;
			snprintf(ptr, outputlen-datalen, ",%d,%d,%d,%d", dtoh32(stats->glitchcnt), dtoh32(stats->badplcp), stats->bgnoise, dtoh32(stats->timestamp));
		}
	}
#endif

	free(chanim_buf);

	return 0;
}
#endif

extern char *diag_get_wifi_fh_ifnames(int wifi_unit, char *buffer, size_t buffer_size)
{
	int subunit;
	char *ptr = NULL;
	char *end = NULL;
	char wlifname[33];
	char *s = NULL;
	size_t size;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	ptr = &buffer[0];
	end = ptr + buffer_size;
	size = 0;

#ifdef RTCONFIG_FRONTHAUL_DWB
	if (nvram_match("smart_connect_x", "1") && nvram_get_int("fh_ap_enabled") > 0 && wifi_unit == nvram_get_int("dwb_band"))
		subunit = aimesh_re_node() ? nvram_get_int("fh_re_mssid_subunit") : nvram_get_int("fh_cap_mssid_subunit");
	else
#endif
	subunit = aimesh_re_node() ? 1 : 0;

	//_dprintf("%s(%d) : wifi_unit=%d, subunit=%d\n", __func__, __LINE__, wifi_unit, subunit);
	if (diag_get_sub_if_bss_enabled(wifi_unit, subunit)) {
		memset(wlifname, 0, sizeof(wlifname));
		s = diag_get_wl_ifname(wifi_unit, subunit, wlifname, sizeof(wlifname)-1);
		//_dprintf("%s(%d) : wlifname=%s\n", __func__, __LINE__, s);
		if (s && strlen(s) > 0 && (size + strlen(s) + 1) < buffer_size)
		{
			ptr += snprintf(ptr, end-ptr, "%s ", s);
			size += strlen(s) + 1;
		}
	}

	if (strlen(buffer) > 0)
	{
		buffer[strlen(buffer)-1] = '\0';
	}
	//_dprintf("%s(%d) : wlifnames=%s\n", __func__, __LINE__, buffer);

	return (strlen(buffer) > 0) ? buffer : NULL;
}

extern char *diag_get_eth_bh_ifnames(char *buffer, size_t buffer_size)
{
	char eth_ifnames[64];
	char amas_ifname[64];
	char *ptr = NULL;
	char *end = NULL;
	size_t size;
	char word[64];
	char *next = NULL;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	ptr = &buffer[0];
	end = ptr + buffer_size;
	size = 0;

	snprintf(eth_ifnames, sizeof(eth_ifnames), "%s", nvram_safe_get("eth_ifnames"));
	snprintf(amas_ifname, sizeof(amas_ifname), "%s", nvram_safe_get("amas_ifname"));

	foreach(word, eth_ifnames, next) {
		if (strstr(amas_ifname, word)) {
			ptr += snprintf(ptr, end-ptr, "%s ", word);
			size += strlen(word) + 1;
		}
	}

	if (strlen(buffer) > 0)
	{
		buffer[strlen(buffer)-1] = '\0';
	}

	return (strlen(buffer) > 0) ? buffer : NULL;
}

static int is_wlif(char *ifname)
{
	int ret = 0;
	char word[33];
	char *next = NULL;
	int unit = 0;
	int re_mode;

	if (!ifname)
		return ret;

	re_mode = nvram_get_int("re_mode");

	foreach(word, nvram_safe_get("wl_ifnames"), next) {
		if ((ret = !strncmp(word, ifname, strlen(ifname))))
			break;

		// Check wifi fronthaul interface on re mode.
		if (re_mode) {
			char wl_fh_ifnames[64];
			// Get wifi fronthaul interface
			diag_get_wifi_fh_ifnames(unit, wl_fh_ifnames, sizeof(wl_fh_ifnames));
			//DIAG_LOG(LOG_DEBUG, "wl_fh_ifnames=%s", wl_fh_ifnames);
			if ((ret = (strstr(wl_fh_ifnames, ifname)) != NULL))
				break;
		}
		unit++;
	}

	return ret;
}

extern char *diag_get_eth_fh_ifnames(char *buffer, size_t buffer_size)
{
	char *ptr = NULL;
	char *end = NULL;
	char *lan_ifnames = NULL;
	char eth_bh_ifnames[64];

	char word[64];
	char *next = NULL;
	size_t size = 0;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	if (!(lan_ifnames = nvram_get("lan_ifnames")))
		return NULL;

	// Get backhaul interface
	diag_get_eth_bh_ifnames(eth_bh_ifnames, sizeof(eth_bh_ifnames));

	ptr = &buffer[0];
	end = ptr + buffer_size;

	foreach(word, lan_ifnames, next)
	{
		if (is_wlif(word) || guest_wlif(word) || strstr(eth_bh_ifnames, word))  // bypass wifi/guest/backhaul interfaces
			continue;

		if (size >= buffer_size || (size + strlen(word) + 1) >= buffer_size)
			break;

		ptr += snprintf(ptr, end-ptr, "%s ", word);
		size += strlen(word) + 1;
	}

	if (strlen(buffer) > 0)
		buffer[strlen(buffer)-1] = '\0';

	return (strlen(buffer) > 0) ? buffer : NULL;
}

extern int get_plc_phy_rate(unsigned long *tx_rate, unsigned long *rx_rate) {
	*tx_rate = 0;
	*rx_rate = 0;
	return 0;
}