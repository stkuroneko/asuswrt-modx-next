#include <string.h>
#include <conn_diag.h>


#ifdef RTCONFIG_HND_ROUTER
#define SYS_TEMP_PATH "/sys/devices/virtual/thermal/thermal_zone0/temp"
#else
#define SYS_TEMP_PATH "/proc/dmu/temperature"
#endif

extern int get_wifi_chip(char *ifname, char *output, int size){
#define KEY "1bef:"
	char cmd[64] = {0};
	char *chipnum = "-1";
	char buf[512];
	int len;
	char *p;
	FILE *fp = NULL;

	snprintf(cmd, sizeof(cmd), "/usr/bin/lspci | grep %s 2>/dev/null", !strcmp(ifname, "wlan0") ? "01:" : "03:");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute cat.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

	len = fread(buf, 1, sizeof(buf), fp);
	if ((p = strstr(buf, KEY))) {
		chipnum = p+strlen(KEY);
		if (p = strstr(buf, "\n")) // remove newline
			*p = '\0';
	}
	snprintf(output, size, "%s,%s,%s", chipnum, "-1", "-1");

	pclose(fp);

	return 0;
}

extern int get_hw_acceleration(char *output, int size){
	snprintf(output, size, "%s", nvram_safe_get("ctf_disable"));

	return 0;
}

extern int get_sys_clk(char *output, int size){
#define KEY ": "
	FILE *fp = NULL;
	char cmd[64] = {0};
	char *clk = "-1";
	char buf[512];
	int len;
	char *p;

	snprintf(cmd, sizeof(cmd), "/bin/cat /proc/cpuinfo | grep \"cpu MHz\" 2>/dev/null");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute cat.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

	len = fread(buf, 1, sizeof(buf), fp);
	if ((p = strstr(buf, KEY))) {
		clk = p+strlen(KEY);
		if (p = strstr(buf, "\n")) // remove newline
			*p = '\0';
	}
	snprintf(output, size, "%s", clk);

	pclose(fp);

	return 0;
}

extern int get_sys_temp(unsigned int *temp){
	//TODO lantiq
#if 0
	char cmd[64] = {0};
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
#else
	*temp = -1;
	return -1;
#endif
}

extern int get_wifi_temp(char *ifname, unsigned int *temp){
	//TODO lantiq
#if 0
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
#else
	*temp = -1;
	return -1;
#endif
}

extern int get_wifi_country(char *ifname, char *output, int len){
	char country[64] = {0};
	/* 2G and 5G use same country code */
	if (wlan_getCountryCode(0, country) == 0)
		snprintf(output, len, "%s", country);
	else {
		snprintf(output, len, "%s", "-1");
		return -1;
	}
	return 0;
}

extern int get_wifi_noise(char *ifname, char *output, int len){
#define DELIM " "
	FILE *fp = NULL;
	char cmd[64] = {0};
	char *noise = "-1";
	char line[512];
	char *pch;
	int noise_idx = 0;

	snprintf(cmd, sizeof(cmd), "/bin/cat /proc/net/wireless 2>/dev/null");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute cat.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL)  {
		if (strstr(line, "noise")) {
			char * pch;
			pch = strtok(line, DELIM);
			while (pch != NULL)
			{
				//printf ("%s\n", pch);
				if (!strcmp(pch, "noise")) {
					//printf ("noise_idx=%d\n", noise_idx);
					break;
				} else if (strcmp(pch, "|")) {
					noise_idx++;
				}
				pch = strtok (NULL, DELIM);
			}
		} else if (strstr(line, ifname)) {
			int idx = 0;
			pch = strtok(line, DELIM);
			while (pch != NULL)
			{
				//printf ("%s\n", pch);
				if (idx++ == noise_idx) {
					noise = pch;
					remove_word(noise, ".");
					break;
				}
				pch = strtok (NULL, DELIM);
			}
			break;
		}
    	//printf(line);
    	//printf("\n");
	}
	snprintf(output, len, "%s", noise);

	pclose(fp);

	return 0;
}

extern int get_wifi_mcs(char *ifname, char *output, int len){
	//TODO lantiq
#if 0
	char cmd[64] = {0};
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
#else
	snprintf(output, len, "%s", "-1");
	return -1;
#endif
}

extern char *diag_get_wifi_fh_ifnames(int wifi_unit, char *buffer, size_t buffer_size)
{
	return NULL;
}

extern char *diag_get_eth_bh_ifnames(char *buffer, size_t buffer_size)
{
	return NULL;
}

extern char *diag_get_eth_fh_ifnames(char *buffer, size_t buffer_size)
{
	return NULL;
}

extern int get_plc_phy_rate(unsigned long *tx_rate, unsigned long *rx_rate) {
	*tx_rate = 0;
	*rx_rate = 0;
	return 0;
}