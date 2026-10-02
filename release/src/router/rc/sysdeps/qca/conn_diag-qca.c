#include <string.h>
#include <conn_diag.h>

/* Report NAT acceleration status. */
int get_hw_acceleration(char *output, int size)
{
	if (!output || size <= 0)
		return -1;

	snprintf(output, size, "%d", nat_acceleration_status());
	return 0;
}

/* Report CPU frequency. */
int get_sys_clk(char *output, int size)
{
	char line[64] __attribute__((unused))= "";

	if (!output || size <= 0)
		return -1;

	snprintf(output, size, "-1");
#if defined(RTCONFIG_QCA953X)
	snprintf(output, size, "650");
#elif defined(RTCONFIG_SOC_QCA9557)
	snprintf(output, size, "700");
#elif defined(RTCONFIG_QCA956X)
	snprintf(output, size, "775");
#elif defined(RTCONFIG_SOC_IPQ40XX)
	snprintf(output, size, "710");
#else
	if (f_read_string("/sys/devices/system/cpu/cpufreq/policy0/cpuinfo_cur_freq", line, sizeof(line)) > 0) {
		snprintf(output, size, "%d", safe_atoi(line));
	} else {
		dbg("%s: FIXME\n", __func__);
	}
#endif

	return 0;
}

/* Report CPU temperature. */
int get_sys_temp(unsigned int *temp)
{
	char line[64] __attribute__((unused))= "";

	if (!temp)
		return -1;

	*temp = -1;
	if (f_read_string("/sys/class/thermal/thermal_zone0/temp", line, sizeof(line)) <= 0) {
		dbg("%s: FIXME\n", __func__);
		return -1;
	}
	*temp = safe_atoi(line);

	return 0;
}

/* Report chipnum,chiprev,chippkg of @ifname. */
int get_wifi_chip(char *ifname, char *output, int size)
{
	int band __attribute__((unused)) = -1;

	if (!ifname || !output || size <= 0)
		return - 1;

#if defined(MAPAC1300) || defined(MAPAC2200) || defined(VZWAC1300) || defined(SHAC1300)
	if (!strcmp(ifname, "ath0"))
		snprintf(output, size, "IPQ4019,-1,-1");
	else if (!strcmp(ifname, "ath1"))
		snprintf(output, size, "IPQ4019,-1,-1");
	else
		snprintf(output, size, "QCA9886,-1,-1");
#elif defined(MAPAC1750)
	if (!strcmp(ifname, "ath0"))
		snprintf(output, size, "QCA9563,-1,-1");
	else
		snprintf(output, size, "QCA9880,-1,-1");
#elif defined(RTAC95U)
	if (!strcmp(ifname, "ath0"))
		snprintf(output, size, "IPQ4019,-1,-1");
	else if (!strcmp(ifname, "ath1"))
		snprintf(output, size, "IPQ4019,-1,-1");
	else
		snprintf(output, size, "QCA9984,-1,-1");
#elif defined(RTCONFIG_WIFI_QCN5024_QCN5054)
	get_wlif_unit(ifname, &band, NULL);
	if (band == WL_2G_BAND)
		snprintf(output, size, "QCN5024,-1,-1");
	else if (band == WL_5G_BAND)
		snprintf(output, size, "QCN5054,-1,-1");
	else {
		dbg("%s: Unknown ifname %s\n", __func__, ifname);
		snprintf(output, size, "-1,-1,-1");
	}
#else
#warning FIXME
	snprintf(output, size, "-1,-1,-1");
#endif

	return 0;
}

int get_wifi_temp(char *ifname, unsigned int *temp)
{
	if (!ifname || !temp)
		return -1;
	if (!nvram_match(WLREADY, "1"))
		return 0;

#if defined(RTCONFIG_SOC_IPQ40XX)
	*temp = __get_wifi_thermal(ifname[3]);
#elif defined(RTCONFIG_SOC_IPQ8074)
	int band = -1;

	get_wlif_unit(ifname, &band, NULL);
	*temp = get_wifi_temperature(band);
	if (*temp <= 0 || *temp > 200) {
		dbg("%s: Invalid temperature %u, ifname %s\n", __func__, *temp, ifname);
		*temp = -1;
	}
#else
#warning FIXME
	*temp = -1;
#endif

	return 0;
}

int get_wifi_country(char *ifname, char *output, int len)
{
	if (!ifname || !output || len <= 0)
		return -1;
	if (!nvram_match(WLREADY, "1"))
		return 0;
	snprintf(output, len, nvram_safe_get("wl0_country_code"));

	return 0;
}

/* Report a negative value: (Result of "wl -i IFACE noise" on BRCM)
 */
int get_wifi_noise(char *ifname, char *output, int len)
{
	int noise;
	char cmd[sizeof("iwconfig XXX") + IFNAMSIZ];

	if (!ifname || !output || len <= 0)
		return -1;
	if (!nvram_match(WLREADY, "1"))
		return 0;
	/* Example
	 * ath0      IEEE 802.11axa  ESSID:"ASUS_282828_TEST_5G"
	 *           Mode:Master  Frequency:5.24 GHz  Access Point: 04:D4:C4:C4:E9:C4
	 *           Bit Rate:4.8039 Gb/s   Tx-Power:18 dBm
	 *           RTS thr:off   Fragment thr:off
	 *           Encryption key:AE63-2D8F-B777-EA11-B779-EF81-AC5D-68C0   Security mode:restricted
	 *           Power Management:off
	 *           Link Quality=0/94  Signal level=-96 dBm  Noise level=-96 dBm
	 *           Rx invalid nwid:8551  Rx invalid crypt:0  Rx invalid frag:0
	 *           Tx excessive retries:0  Invalid misc:0   Missed beacon:0
	 */
	snprintf(cmd, sizeof(cmd), "iwconfig %s", ifname);
	if (exec_and_parse(cmd, "Noise level=", "%*[ 	]Link Quality=%*d/%*d Signal level=%*d dBm  Noise level=%d dBm", 1, &noise))
		noise = -1;
	snprintf(output, len, "%d", noise);

	return -1;
}

/* Report data in below format: (Result of "wl -i IFACE nrate" on GT-AC5300 platform)
 * 2G:
 * vht mcs 7 Nss 4 Tx Exp 0 bw20 sgi auto
 * 5G:
 * vht mcs 11 Nss 4 Tx Exp 0 bw80 sgi auto
 * Reference to wl_nrate_print(), return data with one of below format.
 * "auto"
 * "legacy rate %d%s Mbps stf mode %d %s", rate/2, (rate % 2)?".5":"", stf, rspec_auto
 * "mcs index %d stf mode %d %s", rate, stf, rspec_auto
 * "vht mcs %d Nss %d Tx Exp %d %s%s%s%s %s", vht, Nss, txexp, bw, stbc, ldpc, sgi, rspec_auto
 * "he mcs %d Nss %d Tx Exp %d %s%s%s%s %s", he, Nss, txexp, bw, stbc, ldpc, gi_ltf[gi_int], rspec_auto
 */
int get_wifi_mcs(char *vap, char *output, int len)
{
	char cmd[sizeof("wifitool ") + IFNAMSIZ + sizeof(" get_wl_nrateXXX")], line[256], *p;
	int data_len;
	FILE *fp;

	if (vap == NULL || vap[0] == '\0')
		return -1;
	if (!nvram_match(WLREADY, "1"))
		return 0;

	*output = '\0';
	snprintf(cmd, sizeof(cmd), "wifitool %s get_wl_nrate", vap);
	if (!(fp = popen(cmd, "r"))) {
		dbg("%s: can't execute [%s], errno %d (%s)\n", __func__, cmd, errno, strerror(errno));
		return -2;
	}

	data_len = 0;
	while (data_len < len && fgets(line, sizeof(line), fp)) {
		strlcat(output + data_len, line, len - data_len);
		data_len += strlen(line);
	}
	pclose(fp);

	if (strlen(output) <= 0) {
		snprintf(output, len, "-1");
	}
	if ((p = strrchr(output, '\n')) != NULL)
		*p = '\0';

	return 0;
}

char *diag_get_wifi_fh_ifnames(int wifi_unit, char *buffer, size_t buffer_size)
{
	int i, subunit;
	char *ptr = NULL;
	char *end = NULL;
	char *next = NULL;
	char word[64];
	char *wl_ifnames = NULL;
	char wlifname[33];
	char *s = NULL;
	size_t size;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	ptr = &buffer[0];
	end = ptr + buffer_size;

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

char *diag_get_eth_bh_ifnames(char *buffer, size_t buffer_size)
{
	char eth_ifnames[64];
	char amas_ifname[64];
	char *ptr;
	char *end;
	char word[64], *next;
	int len;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	ptr = &buffer[0];
	end = ptr + buffer_size;

	snprintf(eth_ifnames, sizeof(eth_ifnames), "%s", nvram_safe_get("eth_ifnames"));
	snprintf(amas_ifname, sizeof(amas_ifname), "%s", nvram_safe_get("amas_ifname"));

	foreach(word, eth_ifnames, next) {
		if (!find_word(amas_ifname, word))
			continue;

		len = strlen(word);
		if (ptr + len + 1 >= end)
			break;

		ptr += snprintf(ptr, end-ptr, "%s ", word);
	}

	if (ptr <= buffer)
		return NULL;

	*(ptr-1) = '\0';	// remove ' ' at the end

	return buffer;
}

char *diag_get_eth_fh_ifnames(char *buffer, size_t buffer_size)
{
	char *ptr;
	char *end;
	char lan_ifnames[64];
	char eth_bh_ifnames[64];

	char word[64], *next;
	size_t len;

	if (!buffer || buffer_size <= 0)
		return NULL;

	memset(buffer, 0, buffer_size);
	snprintf(lan_ifnames, sizeof(lan_ifnames), nvram_safe_get("lan_ifnames"));

	// Get backhaul interface
	diag_get_eth_bh_ifnames(eth_bh_ifnames, sizeof(eth_bh_ifnames));

	ptr = &buffer[0];
	end = ptr + buffer_size;

	foreach(word, lan_ifnames, next)
	{
		if (is_wlif(word) || guest_wlif(word) || find_word(eth_bh_ifnames, word))  // bypass wifi/guest/backhaul interfaces
			continue;

		len = strlen(word);
		if (ptr + len + 1 >= end)
			break;

		ptr += snprintf(ptr, end-ptr, "%s ", word);
	}

	if (strlen(buffer) > 0)
		buffer[strlen(buffer)-1] = '\0';

	return (strlen(buffer) > 0) ? buffer : NULL;
	if (ptr <= buffer)
		return NULL;

	*(ptr-1) = '\0';	// remove ' ' at the end

	return buffer;
}

int get_plc_phy_rate(unsigned long *tx_rate, unsigned long *rx_rate)
{
#ifdef PLAX56_XP4
	*tx_rate = nvram_get_int("autodet_plc_tx");
	*rx_rate = nvram_get_int("autodet_plc_rx");
#else
	*tx_rate = 0;
	*rx_rate = 0;
#endif
	return 0;
}
