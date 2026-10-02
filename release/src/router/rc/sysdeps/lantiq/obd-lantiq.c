#include <obd.h>

#if defined(RTCONFIG_AMAS)

#define ACTIVE_SCANNED_BSS "/tmp/scanned_bss"
#define PASSIVE_SCANNED_BSS "/tmp/passive_scanned_bss"
#define ACTIVE_SCANNED_BSS_LOCK "/var/lock/scanned_bss.lock"
#define PASSIVE_SCANNED_BSS_LOCK "/var/lock/passive_scanned_bss.lock"

#define SCANNING_PERIOD 0

static int is_scanning = 0;
static int scanning_count = 0;
static int obd_lock_fd = -1;

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, uint8 *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	uint8 *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

int obd_init()
{
	if(nvram_get_int("wave_ready") == 0) {
		goto INIT_FAILED;
	}

	//obd_clear_all_probe_req_vsie(0);
	trigger_wave_monitor_and_wait(__func__, __LINE__, WAVE_ACTION_CLEAR_ALL_PROBE_REQ_VSIE, 1);

	return 0;

INIT_FAILED:
	return -1;
}

void obd_final(int clean_vsie)
{
	remove(ACTIVE_SCANNED_BSS);
	remove(PASSIVE_SCANNED_BSS);
	//obd_clear_all_probe_req_vsie(0);
	if (clean_vsie)
		trigger_wave_monitor_and_wait(__func__, __LINE__, WAVE_ACTION_CLEAR_ALL_PROBE_REQ_VSIE, 1);
}

void obd_save_para()
{
	nvram_set("sw_mode", "3");
	nvram_set("wlc_psta", "2");
	nvram_set("wlc_dpsta", "2");
	nvram_set("lan_proto", "dhcp");
	nvram_set("lan_dnsenable_x", "1");
	nvram_set("x_Setting", "1");
	nvram_set("w_Setting", "1");
	nvram_set("re_mode", "1");
	//nvram_set("wlc_dbg", "1");
	//nvram_set("cfg_dbg", "1");
	nvram_unset("cfg_group");

	nvram_unset("wps_e_success");
	nvram_unset("wps_success");
	nvram_unset("wps_enrollee");

	nvram_commit();
}

void obd_start_active_scan()
{
	char cmd[300] = {0};
	char prefix[] = "wlXXXXXXXXXX_";
	char *ifname = get_staifname(0);
	OBD_DBG("Send probe-req %s\n\n", ifname);		

	snprintf(cmd, sizeof(cmd), "wpa_cli -i%s scan",	ifname);
	OBD_DBG("%s: cmd=%s\n", __func__, cmd);
	system(cmd);
}

struct scanned_bss *obd_get_bss_scan_result()
{
#define KEY_BSSID "bssid="
#define KEY_BSSID_LEN 6
#define KEY_SIGNAL_LEVEL "signal_level="
#define KEY_SIGNAL_LEVEL_LEN 13
#define KEY_VSIE "vsie="
#define KEY_VSIE_LEN 5
	char *bss_result_file[2] = {ACTIVE_SCANNED_BSS, PASSIVE_SCANNED_BSS};
	char *bss_lock_file[2] = {ACTIVE_SCANNED_BSS_LOCK, PASSIVE_SCANNED_BSS_LOCK};
	struct scanned_bss *bss_list = NULL, *current_bss = NULL;
	char *bss_entry[256];
	int i, lock_fd = -1;

	// WORKAOUND!!! If /tmp/wpa_cli_wlan1 isn't running, run it.
	if (!pids("wpa_cli_wlan1"))
		system("/tmp/wpa_cli_wlan1 -iwlan1 -a/opt/lantiq/wave/scripts/fapi_wlan_wave_events_supplicant.sh -B");

	for (i=0; i<sizeof(bss_result_file)/sizeof(bss_result_file[0]); i++) {
		FILE *fp = NULL;
		//if (f_exists(bss_lock_file[i]))
		//	continue;

		//if ((lock_fd = file_lock(bss_lock_file[i])  == -1))
		//	continue;

		// discard passive scan (listen beacon)
		if (!strcmp(bss_result_file[i], PASSIVE_SCANNED_BSS)) {
			if (is_scanning)
				scanning_count++;

			if (scanning_count > SCANNING_PERIOD || !is_scanning) {
				obd_start_active_scan();
				is_scanning = 1;
				scanning_count = 0;
				OBD_DBG("obd_start_active_scan\n");
			}
			continue;
		}

		if ((lock_fd = open(bss_lock_file[i], O_RDONLY | O_CREAT)) == -1) {
			OBD_DBG("open lock [%s] failed. %s\n", bss_lock_file[i], strerror(errno));
			continue;
		}

		if (flock(lock_fd, LOCK_EX) == -1) {
			OBD_DBG("flock failed. %s\n", strerror(errno));
			close(lock_fd);
			continue;
		}

		if ((fp = fopen(bss_result_file[i], "r")) != NULL) {
			memset(bss_entry, 0, sizeof(bss_entry));
			while(1) {
				char *tmp2 = fgets(bss_entry, sizeof(bss_entry) , fp);
				if (!tmp2) {
					//OBD_ERROR("[%s] eof or error occur, %d, %d\n", bss_result_file[i], ferror(fp), feof(fp));
					break;
				}
				int match_1 = 0, match_2 = 0, match_3 = 0;
				uint8 vsie_len = 0;
				uint8 vsie[MAX_VSIE_LEN];
				int RSSI = 0;
				struct ether_addr BSSID;

				const char *tmp = NULL;

				bss_entry[strlen(bss_entry) - 1] = '\0';

				memset(&vsie[0], 0, sizeof(vsie));
				memset(&BSSID, 0, sizeof(BSSID));

				//OBD_DBG("[%s ] bss_entry [%s]\n", bss_result_file[i], bss_entry);
				// bssid
				if ((tmp = strstr((const char *)bss_entry, KEY_BSSID)) == NULL) {
					continue;
				}

				if (strlen(tmp) > KEY_BSSID_LEN) {

					ether_aton_r(tmp+KEY_BSSID_LEN, &BSSID);
					//OBD_DBG("[%s] BSSID=%.*s\n", bss_result_file[i], 17, tmp+KEY_BSSID_LEN);
					match_1 = 1;
				}

				//OBD_DBG("bss_entry2 [%s]\n", bss_entry);

				// skip entry which have no signal_level.
				if ((tmp = strstr((const char *)bss_entry, KEY_SIGNAL_LEVEL)) == NULL) {
					continue;
				}

				// signal_level
				if (strlen(tmp) > KEY_SIGNAL_LEVEL_LEN) {
					sscanf(tmp+KEY_SIGNAL_LEVEL_LEN, "%d", &RSSI);
					//OBD_DBG("[%s] SIGNAL_LEVEL=%d\n", bss_result_file[i], RSSI);
					match_2 = 1;
				}

				//OBD_DBG("bss_entry3 [%s]\n", bss_entry);

				// skip entry which have no vsie.
				if ((tmp = strstr((const char *)bss_entry, KEY_VSIE)) == NULL) {
					continue;
				}

				// vsie_len-OUI_LEN
				if (strlen(tmp) > KEY_VSIE_LEN) {
					vsie_len = (strlen(tmp) - KEY_VSIE_LEN);
					vsie_len /= 2;
					vsie_len -= OUI_LEN;
					hexstr2bin(tmp+KEY_VSIE_LEN+(OUI_LEN*2), vsie, vsie_len);
					//OBD_DBG("[%s] VSIE=%.*s vsie_len=%d\n", bss_result_file[i], vsie_len*2-KEY_VSIE_LEN, tmp+KEY_VSIE_LEN+(OUI_LEN*2), vsie_len);
					match_3 = 1;
				}
				
				//OBD_DBG("[%s] \n", bss_result_file[i]);

				// create bss entry
				if (match_1 && match_2 && match_3) {
					/*if (i == 1 && bss_list) {
						struct scanned_bss *tmp_bss;
						int j;

						// check if the BSSID already in the bss_list. If true, get the RSSI.
						for (j=0, tmp_bss = bss_list; tmp_bss; j++, tmp_bss = tmp_bss->next) {
							if (!memcmp(&tmp_bss->BSSID, &BSSID, ETHER_ADDR_LEN)) {
								RSSI = tmp_bss->RSSI;
								break;
							}
						}
					}*/

					struct scanned_bss *bss = malloc(sizeof(struct scanned_bss));
					memset(bss, 0, sizeof(struct scanned_bss));

					bss->vsie_len = vsie_len;
					memcpy(&bss->vsie[0], &vsie[0], bss->vsie_len);
					bss->RSSI = (unsigned char)RSSI;
					memcpy(&bss->BSSID, &BSSID, sizeof(struct ether_addr));

					if (current_bss) {
						current_bss->next = bss;
					}
					current_bss = bss;

					if (bss_list == NULL)
						bss_list = bss;
				} else {
					//OBD_DBG("skip match_1=[%d] match_2=[%d] match_3=[%d]\n", match_1, match_2, match_3);
				}
				memset(bss_entry, 0, sizeof(bss_entry));

				//fseek(fp, 1, SEEK_CUR);
			}
			if (fp)
				fclose(fp);

			if (is_scanning && !strcmp(bss_result_file[i], ACTIVE_SCANNED_BSS)) {
				is_scanning = 0;
				remove(bss_result_file[i]);
			}
		} else {
			OBD_WARNING("%s, %s\n", bss_result_file[i], strerror(errno));
		}

		if (lock_fd != -1) {
			flock(lock_fd, LOCK_UN);
			close(lock_fd);
		}
	}
	return bss_list;
}

void obd_start_wps_enrollee()
{
	nvram_unset("wps_e_success");
	nvram_unset("wps_success");
	nvram_set("wps_enrollee", "1");
	start_wps_method();
	sleep(5); // wait for wps configured from wave_monitor
}
#if 0
void obd_clear_all_probe_req_vsie(int unit)
{	
	char cmd[300] = {0};
	int pktflag = 0xE;
	char *ifname = NULL;
	FILE *fp;
	
	ifname = get_staifname(unit);

	snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_get %d",
		ifname, pktflag);
	if ((fp = popen(cmd, "r")) != NULL) {
		char *vendor_elem[MAX_VSIE_LEN];
		memset(vendor_elem, 0, sizeof(vendor_elem));

		if (fgets(vendor_elem , sizeof(vendor_elem) , fp) != NULL) {
			if (strlen(vendor_elem)) {
				snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_remove %d %s",
					ifname, pktflag, vendor_elem);
				OBD_DBG("%s: cmd=%s\n", __func__, cmd);
				system(cmd);
			}
		}
		pclose(fp);
	}
}
#endif
void obd_add_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
	// 13 : Associatino Request
	// 14 : Probe Reqeust
	// 15 : Authentication Request
	char cmd[300] = {0};
	char hexdata[256];
	int pktflag = 0xE;
	int i, ie_len = (len - OUI_LEN);
	char *ifname = NULL;
	FILE *fp;

	ifname = get_staifname(unit);

	memset(hexdata, 0, sizeof(hexdata));
	for (i = 0; i < ie_len; i++)
		sprintf(&hexdata[2 * i], "%02X", ie_data[i]);
	hexdata[2 * ie_len] = 0;

#if 0
	obd_clear_all_probe_req_vsie(unit);

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_add %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)len, (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], hexdata);
		OBD_DBG("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
#endif
	nvram_set("amas_add_probe_req_vsie", hexdata);
	trigger_wave_monitor_and_wait(__func__, __LINE__, WAVE_ACTION_ADD_PROBE_REQ_VSIE, 1);
}

void obd_del_probe_req_vsie(int unit, int len, unsigned char *ie_data)
{
	char cmd[300] = {0};
	char hexdata[256];
	int pktflag = 0xE;
	int i, ie_len = (len - OUI_LEN);
	char *ifname = NULL;

	ifname = get_staifname(unit);

	memset(hexdata, 0, sizeof(hexdata));
	for (i = 0; i < ie_len; i++)
		sprintf(&hexdata[2 * i], "%02X", ie_data[i]);
	hexdata[2 * ie_len] = 0;

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

#if 0
	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_remove %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)len,  (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], hexdata);
		OBD_DBG("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
#endif
	nvram_set("amas_del_probe_req_vsie", hexdata);
	trigger_wave_monitor_and_wait(__func__, __LINE__, WAVE_ACTION_DEL_PROBE_REQ_VSIE, 1);
}

void obd_led_blink()
{
	nvram_set("bc_ledbh", "wps");
	kill_pidfile_s("/var/run/sw_devled.pid", SIGUSR1);
	OBD_DBG("Send signal obd_led_blink.\n");
}

void obd_led_off()
{
	nvram_set("bc_ledbh", "");
	kill_pidfile_s("/var/run/sw_devled.pid", SIGUSR1);
	OBD_DBG("Send signal obd_led_off.\n");
}

#ifdef RTCONFIG_PRELINK
void obd_save_prelink_profile()
{
	int i = 0;
	char tmp[128], tmp2[128], prefix[] = "wlcXXXXXXXXX_", prefix2[] = "wlXXXXXXXXX_", word[256], *next, ifnames[128];

	int unit_total = num_of_wl_if();
#ifdef RTCONFIG_MSSID_PRELINK
	snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit_total-1, nvram_get_int("plk_cap_subunit")); //last band and last mssid
#else
	snprintf(prefix, sizeof(prefix), "wl%d_", unit_total-1); //last band
#endif

	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		//wlcx
		snprintf(prefix2, sizeof(prefix2), "wlc%d_", i);
		nvram_set(strcat_r(prefix2, "ssid", tmp), nvram_safe_get(strcat_r(prefix, "ssid", tmp2)));
		nvram_set(strcat_r(prefix2, "auth_mode", tmp), nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp2)));
		/*nvram_set(strcat_r(prefix2, "wep_x", tmp), nvram_safe_get(strcat_r(prefix, "wep", tmp2)));
		if (nvram_get_int(strcat_r(prefix, "wep", tmp))) {
			nvram_set(strcat_r(prefix2, "key", tmp), nvram_safe_get(strcat_r(prefix, "key", tmp2)));
			nvram_set(strcat_r(prefix2, "key1", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
			nvram_set(strcat_r(prefix2, "key2", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
			nvram_set(strcat_r(prefix2, "key3", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
			nvram_set(strcat_r(prefix2, "key4", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
		}*/
		nvram_set(strcat_r(prefix2, "crypto", tmp), nvram_safe_get(strcat_r(prefix, "crypto", tmp2)));
		nvram_set(strcat_r(prefix2, "wpa_psk", tmp), nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp2)));

		if (i < unit_total-1) {
			//wlx
			snprintf(prefix2, sizeof(prefix2), "wl%d_", i);
			nvram_set(strcat_r(prefix2, "ssid", tmp), nvram_safe_get(strcat_r(prefix, "ssid", tmp2)));
			nvram_set(strcat_r(prefix2, "auth_mode_x", tmp), nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp2)));
			/*nvram_set(strcat_r(prefix2, "wep_x", tmp), nvram_safe_get(strcat_r(prefix, "wep", tmp2)));
			if (nvram_get_int(strcat_r(prefix, "wep", tmp))) {
				nvram_set(strcat_r(prefix2, "key", tmp), nvram_safe_get(strcat_r(prefix, "key", tmp2)));
				nvram_set(strcat_r(prefix2, "key1", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
				nvram_set(strcat_r(prefix2, "key2", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
				nvram_set(strcat_r(prefix2, "key3", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
				nvram_set(strcat_r(prefix2, "key4", tmp), nvram_safe_get(strcat_r(prefix, "wep_key", tmp2)));
			}*/
			nvram_set(strcat_r(prefix2, "crypto", tmp), nvram_safe_get(strcat_r(prefix, "crypto", tmp2)));
			nvram_set(strcat_r(prefix2, "wpa_psk", tmp), nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp2)));
		}
		++i;
	}

	nvram_set("prelink", "1");
	nvram_set("obd_Setting", "1");
}

void obd_switch_re(int wifi)
{
	kill(1, SIGTERM);
}
#endif
#endif //#if defined(RTCONFIG_AMAS)
