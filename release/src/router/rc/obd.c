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
#include <time.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <wlutils.h>
#include <shutils.h>
//#include <shared.h>
#include <wlioctl.h>
#include <rc.h>
#include <obd.h>
#include <sys/file.h>



//#define SWITCH_RE_WITHOUT_REBOOT 1

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID	"33716237"
#define APP_KEY	"g2hkhuig238789ajkhc"
#endif

#include <wlscan.h>
#include <bcmendian.h>
#if defined(RTCONFIG_BCM7) || defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER) || defined(RTCONFIG_HND_ROUTER_AX)
#include <bcmutils.h>
#include <security_ipc.h>
#endif

#include <sys/reboot.h>
#include <sysdeps/amas/amas_ob.h>
#include <amas-utils.h>

#define NORMAL_PERIOD		1	/* second */
#define OBD_TIMEOUT		300

#define OBD_PRELINK_LOCK "/var/lock/prelink.lock"

static time_t time_ref;
static int status_g = 0;
static int wpsTimeout = 0;

unsigned char misc_info[128];
int misc_info_len = 0;

struct cap_rssi {
	struct ether_addr BSSID;
	unsigned char RSSI;
};

struct rssi_info_s {
	unsigned char cap_count;
	struct cap_rssi caprssi[64];
} rssi_info;

#define SECURITY_DOWNGRADE

#ifndef SECURITY_DOWNGRADE
struct cap_info_s {
	wlc_ssid_t ssid;
	struct ether_addr BSSID;
	time_t timestamp;
} cap_info[64];

static unsigned char cap_count;
#endif

static void obd_exit(int sig);

static int obd_get_interval() {
	int interval = nvram_get_int("obd_interval");
	return (interval > 0) ? interval : NORMAL_PERIOD;
}

static int clean_vsie() {
	/* To vaoid clean the vsie which cfg_server set.
	   If cfg_server is running, don't clean vsie.*/
	return !pids("cfg_server");
}

static void free_bss_scan_result(struct scanned_bss *list) {
	struct scanned_bss *tmp;
	while(list) {
		tmp = list->next;
		free(list);
		list = tmp;
	}
}

static int vsie_setbuf(int type, unsigned char *dst, unsigned char *data)
{
	int len = 0;
	unsigned char c;

	switch (type) {
	case 1:
		len = 1;
		break;
	case 3:
		len = 20;
		break;
	case 4:
		len = 6;
		break;
	case 5:
		len = strlen(get_productid());
		break;
	case 6:
		len = 1 + rssi_info.cap_count * 7;
		break;
	case 15:
	case 16:
	case 17:
		len = 2;
		break;
	case 22:
		len = strlen(nvram_safe_get("territory_code"));
		break;
	case 27:
		len = misc_info_len;
		break;
	}

	if (len) {
		c = type;
		memcpy(dst, &c, 1);
		c = len;
		memcpy(dst+1, &c, 1);
		memcpy(dst+2, data, len);
	}

	return len + 2;
}

#if 0
static void set_temp_id(unsigned char *buf)
{
	time_t now;
	char now_byte[4];
	char str_groupid[] = "DC1A2BFCBCAE839DF23EF0F3B676C0DB";
	unsigned char groupid[16];
	char hexstr[3];
	char *src, *dest, *pp;
	int idx;
	unsigned char val;

	time(&now);
	src = str_groupid;
	dest = (char *) groupid;
	for (idx = 0; idx < sizeof(groupid); idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (unsigned char) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;
	}

	pp = (char *) &now;
	for (idx = 0; idx < sizeof(now_byte); idx++)
		now_byte[idx] = pp[sizeof(now_byte) - 1 -idx];

	for (idx = 0; idx < sizeof(groupid); idx++)
		groupid[idx] = groupid[idx] & now_byte[idx % sizeof(now_byte)];

	f_read("/dev/urandom", buf, 16);
	memcpy(buf + 16, now_byte, 4);
}
#endif

static void
add_ie_in_prbreq(int unit)
{
	unsigned char value[256];
	unsigned char *p = NULL;
	unsigned char status[] = { 0x3 };
	unsigned char ea[ETHER_ADDR_LEN];
#if 0
	unsigned char ID[20];
#endif
	int len;
	struct time_mapping_s time_mapping;
	short reboot_time = 0, connection_timeout = 0, traffic_timeout = 0;

	time_mapping_get(get_productid(), &time_mapping);
	reboot_time = htons((short)time_mapping.reboot_time);
	connection_timeout = htons((short)time_mapping.connection_timeout);
	traffic_timeout = htons((short)time_mapping.traffic_timeout);

	memset(value, 0, sizeof(value));
	p = value;
	p += vsie_setbuf(1, p, status);
#if defined(RTCONFIG_AMAS_UNIQUE_MAC)
	ether_atoe(get_label_mac(), ea);
#else
	ether_atoe(get_lan_hwaddr(), ea);
#endif
	p += vsie_setbuf(4, p, ea);
#if 0
	set_temp_id(ID);
	p += vsie_setbuf(3, p, ID);
#endif
	p += vsie_setbuf(5, p, (unsigned char *) get_productid());
	p += vsie_setbuf(6, p, (unsigned char *) &rssi_info);
	p += vsie_setbuf(15, p, (unsigned char *) &reboot_time);
	p += vsie_setbuf(16, p, (unsigned char *) &connection_timeout);
	p += vsie_setbuf(17, p, (unsigned char *) &traffic_timeout);
	if (strlen(nvram_safe_get("territory_code")) > 0)
		p += vsie_setbuf(22, p, (unsigned char *) nvram_safe_get("territory_code"));

	if (misc_info_len > 0)
		p += vsie_setbuf(27, p, (unsigned char *)&misc_info);

	len = p - value;

	len += OUI_LEN;

	obd_del_probe_req_vsie(unit, len, value);

	obd_add_probe_req_vsie(unit, len, value);
}

#ifdef RTCONFIG_PRELINK
static int prelink_lock(int dbg_on, char *pname)
{
	int lock_fd = -1;

	if ((lock_fd = open(OBD_PRELINK_LOCK, O_RDONLY | O_CREAT)) == -1) {
		if (dbg_on)
			dbG("%s open lock [%s] failed. %s\n", pname, OBD_PRELINK_LOCK, strerror(errno));
		return -1;
	}

	if (flock(lock_fd, LOCK_EX) == -1) {
		if (dbg_on)
			dbG("%s flock failed. %s\n", pname, strerror(errno));
		close(lock_fd);
		return -1;
	}
	return lock_fd;
}

int prelink_lock_acquire(int dbg_on)
{
	int lock_fd = -1;
	int timeout_cnt = 0;
	char *amas_bdl_type_wifi_first = nvram_get("amas_bdl_type_wifi_first");
	int amas_bdl_type_select_timeout = nvram_get_int("amas_bdl_type_select_timeout");
	char pname[NAME_MAX];
	memset(pname, 0, sizeof(pname));
	psname(getpid(), pname, sizeof(pname));
	if (!amas_bdl_type_wifi_first) { // No prio defined, try to lock directly.
		if (dbg_on)
			dbG("%s with no prelink priority flag defined.\n", pname);
		lock_fd = prelink_lock(dbg_on, pname);
	} else if((!strcmp(amas_bdl_type_wifi_first, "1") && !strcmp(pname, "obd")) ||
			(!strcmp(amas_bdl_type_wifi_first, "0") && !strcmp(pname, "obd_eth"))) { // Try to lock multiple times if lock failed.
		if (dbg_on)
			dbG("%s with high priority.\n", pname);
		while ((lock_fd = prelink_lock(dbg_on, pname)) == -1 && ++timeout_cnt <= amas_bdl_type_select_timeout) {
			if (dbg_on)
				dbG("%s with high priority but failed %d\n", pname, timeout_cnt);

			// If X_Setting==1, just give up. It represents prelink or onboarding is proceeding.
			if (nvram_get_int("x_Setting"))
				return -1;
			sleep(1);
		}
	} else { // Try to lock multiple seconds later.
		if (dbg_on)
			dbG("%s with low priority.\n", pname);
		while (++timeout_cnt <= amas_bdl_type_select_timeout) {
			if (dbg_on)
				dbG("%s with low priority. wait %d\n", pname, timeout_cnt);

			// Ff X_Setting==1, just give up. Due to prelink or onboarding is proceeding.
			if (nvram_get_int("x_Setting"))
				return -1;
			sleep(1);
		}
		lock_fd = prelink_lock(dbg_on, pname);
	}
	return lock_fd;
}

void prelink_unlock(int lock_fd)
{
	flock(lock_fd, LOCK_UN);
	close(lock_fd);
}
#endif

static int
cap_scan()
{
	int unit = 0;
	struct scanned_bss *bss_list = NULL;
	struct scanned_bss *bss;
	struct tlvbase *tlv;
#ifndef SECURITY_DOWNGRADE
	struct tlvbase *tlv_timestamp;
#endif
	uint i, j;
	int left2;
	char eaddr[18];
	int match_1, match_2, match_3, match_4;
#ifndef SECURITY_DOWNGRADE
	int match_7;
#endif
	uint8 status = 0, cost;
	unsigned char ID[20], ea[ETHER_ADDR_LEN];
	int count_available;
	int ob_locked;
	int count_mismatch;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
	int ob_wds;
#endif	

	if ((bss_list = obd_get_bss_scan_result()) == NULL)
		return 0;

	bss = bss_list;

	if (status_g == 0)
		OBD_DBG("%-4s%-18s\n", "idx", "BSSID");
	
	/*for (i=0, bss = bss_list; bss; i++, bss = bss->next) {
		OBD_DBG("bss->vsie_len=%d\n", bss->vsie_len);
		if (bss->vsie_len) {
		}
	}

	free_bss_scan_result(bss_list);
	return 0;*/

	count_available = ob_locked = count_mismatch = 0;
#if defined(RTCONFIG_AMAS_UNIQUE_MAC)
	ether_atoe(get_label_mac(), ea);
#else
	ether_atoe(get_lan_hwaddr(), ea);
#endif
	for (i=0, bss = bss_list; bss; i++, bss = bss->next) {
		/* Convert version 107 to 109 */
		/*if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
			old_bi = (wl_bss_info_107_t *)bi;
			bi->chanspec = CH20MHZ_CHSPEC(old_bi->channel);
			bi->ie_length = old_bi->ie_length;
			bi->ie_offset = sizeof(wl_bss_info_107_t);
		}*/

		//OBD_DBG("rssi=%d, bss->vsie_len=%d\n", (int)bss->RSSI, bss->vsie_len);
		if (bss->vsie_len) {
			ether_etoa((const unsigned char *) (uint8 *)&bss->BSSID, eaddr);

			/*if (dtoh32(bi->version) != LEGACY_WL_BSS_INFO_VERSION && bi->n_cap)
				channel= bi->ctl_ch;
			else
				channel= (bi->chanspec & WL_CHANSPEC_CHAN_MASK);*/

			OBD_DBG("BSSID=%s, RSSI=%d, VSIE_LEN=%d\n", eaddr, (signed char)bss->RSSI, bss->vsie_len);
			/*if (status_g == 0)
				OBD_DBG("%-4d%-18s\n", i+1, eaddr);*/
		} else continue;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
		ob_wds=0;
#endif	

		match_1 = match_2 = match_3 = match_4 = 0;
#ifndef SECURITY_DOWNGRADE
		match_7 = 0;
#endif
		/*ie = (struct bss_ie_hdr *)((unsigned char *) bi + bi->ie_offset);
		for (left = bi->ie_length; left > 0;
			left -= (ie->len + 2), ie = (struct bss_ie_hdr *) ((unsigned char *) ie + 2 + ie->len)) {

			if (ie->elem_id != VS_ID)
				continue;

			if (memcmp(ie->oui, OUI_ASUS, 3))
				continue;

			if (status_g == 1)
				OBD_DBG("%-4d%-4d%-33s%-18s\n", i+1, channel, bi->SSID, eaddr);

			ie_vs = (struct vndr_ie *) ie;*/
			tlv = (struct tlvbase *) &(bss->vsie[0]);
#ifndef SECURITY_DOWNGRADE
			tlv_timestamp = NULL;
#endif

			for (left2 = (bss->vsie_len - (tlv->len + 2)); left2 > 0;
				left2 -= (tlv->len + 2), tlv = (struct tlvbase *) ((unsigned char *) tlv + 2 + tlv->len)) {
				switch (tlv->type) {
				case 1:
					if (tlv->len != 1) break;
					match_1 = 1;
					status = tlv->data[0];
					OBD_DBG("Status: %x\n", status);
					break;
				case 2:
					if (tlv->len != 1) break;
					match_2 = 1;
					cost = tlv->data[0];
					OBD_DBG("Cost: %x\n", cost);
					break;
				case 3:
					if (tlv->len != 20) break;
					match_3 = 1;
					memcpy(ID, &tlv->data[0], 20);
					OBD_DBG("ID: ");
					if (msglevel & OBD_DEBUG_DETAIL) {
						for (j = 0; j < tlv->len; j++)
							dbg("%02X", tlv->data[j]);
						dbg("\n");
					}
					break;
				case 4:
					if (tlv->len != 6) break;
					if (!memcmp(ea, &tlv->data[0], ETHER_ADDR_LEN))
						match_4 = 1;
					else
						match_4 = -1;
					OBD_DBG("MAC address: %s\n", ether_etoa(&tlv->data[0], eaddr));
					break;
				case 7:
#ifndef SECURITY_DOWNGRADE
					if (tlv->len != 4) break;
					match_7 = 1;
					tlv_timestamp = tlv;
					OBD_DBG("Timestamp: ");
					if (msglevel & OBD_DEBUG_DETAIL) {
						for (j = 0; j < tlv->len; j++)
							dbg("%02X", tlv->data[j]);
						dbg("\n");
					}
#else
					break;
#endif

#ifdef RTCONFIG_PRELINK
				case 20:
					if (nvram_invmatch("amas_bdlkey", "") && nvram_match("x_Setting", "0")) {
						int verified = 0;
						unsigned char hash_bundle_key[21] = {0};
						int lock = -1;
						if (tlv->len != 20) break;
						OBD_DBG("hash_bundle_key: ");
						if (msglevel & OBD_DEBUG_DETAIL) {
							for (j = 0; j < tlv->len; j++)
								dbg("%02X", tlv->data[j]);
							dbg("\n");
						}
						memcpy(&hash_bundle_key[0], &tlv->data[0], sizeof(hash_bundle_key)-1);
						if (amas_verify_hash_bundle_key(hash_bundle_key, &verified) == AMAS_RESULT_SUCCESS && 
						    verified == 1 &&
						    (lock = prelink_lock_acquire(msglevel & OBD_DEBUG_DETAIL)) >= 0) {
							OBD_DBG("Prelink detected.\n");
#if defined(RTCONFIG_QCA)
							nvram_set("obd_prelinking", "1");
#endif
							obd_save_prelink_profile();
#ifdef RTCONFIG_MSSID_PRELINK
							restore_mssid_prelink_config();
#endif
							obd_save_para();
							obd_final(clean_vsie());
							free_bss_scan_result(bss_list);
							prelink_unlock(lock);
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
							if(bss->wds==1)		
								nvram_set("ob_qca_wds","1");
							else
								nvram_set("ob_qca_wds","0");
#endif
							obd_switch_re(1);
#if defined(RTCONFIG_QCA)
							nvram_set("obd_prelinking", "0");
#endif
							obd_exit(SIGTERM);
							return 0;
						}
					}
					break;
#endif

				default:
					OBD_ERROR("Unknown TLV: ");
					if (msglevel & OBD_DEBUG_DETAIL) {
						dbg("%02X", tlv->type);
						dbg("%02X", tlv->len);
						for (j = 0; j < tlv->len; j++)
							dbg("%02X", tlv->data[j]);
						dbg("\n");
					}
				}
			}
			if (msglevel & OBD_DEBUG_DETAIL)
				dbg("\n");

#ifndef SECURITY_DOWNGRADE
			if (!(match_1 && match_2 && match_3 && match_7))
#else
			if (!(match_1 && match_2 && match_3))
#endif
				goto NEXT_BSS;

			if (status_g == 0 && status == 2) {
				count_available++;

				if (count_available == 1)
					nvram_set_int("amesh_found_cap", 1);

				memcpy(&rssi_info.caprssi[count_available - 1].BSSID, &bss->BSSID, ETHER_ADDR_LEN);
				rssi_info.caprssi[count_available - 1].RSSI = bss->RSSI;

#ifndef SECURITY_DOWNGRADE
				memcpy(&cap_info[count_available - 1].BSSID, &bi->BSSID, ETHER_ADDR_LEN);
				strncpy((char *)cap_info[count_available - 1].ssid.SSID, (char *)bi->SSID, bi->SSID_len);
				cap_info[count_available - 1].ssid.SSID[bi->SSID_len] = '\0';
				cap_info[count_available - 1].ssid.SSID_len = bi->SSID_len;
				memcpy(&cap_info[count_available - 1].timestamp, &tlv_timestamp->data[0], sizeof(time_t));
#endif

				goto NEXT_BSS;
			} else if (status_g == 1) {
				if (status == 2) {
					count_available++;

					memcpy(&rssi_info.caprssi[count_available - 1].BSSID, &bss->BSSID, ETHER_ADDR_LEN);
					rssi_info.caprssi[count_available - 1].RSSI = bss->RSSI;

					if (match_4 == 1) {
						nvram_set_int("amesh_led", 1);
						obd_led_blink();
					} else if (match_4 == -1) {
						nvram_set_int("amesh_led", 0);
						obd_led_off();
					}

					goto NEXT_BSS;
				} else if (status == 4) {

					if (match_4 == -1) {
						count_mismatch++;
					} else if (match_4 == 1) {
#ifndef SECURITY_DOWNGRADE
						for (j = 0; j < cap_count; j++) {
							if (    !memcmp(&bi->BSSID, &cap_info[j].BSSID, ETHER_ADDR_LEN) &&
								(bi->SSID_len == cap_info[j].ssid.SSID_len) &&
								!memcmp(bi->SSID, cap_info[j].ssid.SSID, cap_info[j].ssid.SSID_len) &&
								!memcmp(&tlv_timestamp->data[0], &cap_info[j].timestamp, sizeof(time_t))) {
#endif
								ob_locked = 1;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
								if(bss->wds==1)		
									ob_wds=1;
								else
									ob_wds=0;
#endif								
								nvram_set_int("amesh_found_cap", 0);

								goto ACTION;
#ifndef SECURITY_DOWNGRADE
							}
						}
#endif
					}
				}
			}

			//goto NEXT_BSS;
		//}
NEXT_BSS:
		continue;
	}

	if (count_mismatch) {
		OBD_DBG("Reset due to mismatch of RE MAC address\n\n");
		status_g = 0;

		time_ref = uptime();

		nvram_set_int("amesh_found_cap", 0);

		free_bss_scan_result(bss_list);
		return 0;
	}

ACTION:
	if ((uptime() - time_ref) > OBD_TIMEOUT) {
		OBD_DBG("Reset due to timeout\n\n");
		status_g = 0;

		time_ref = uptime();

		nvram_set_int("amesh_found_cap", 0);

		if (nvram_get_int("amesh_led") == 1) {
			obd_led_off();
			nvram_set_int("amesh_led", 0);
		}

#ifdef RTCONFIG_LANTIQ
		obd_final(clean_vsie());
#endif
	} else if (ob_locked && status_g == 1) {
		if (nvram_get_int("amesh_led") == 1) {
			obd_led_off();
			nvram_set_int("amesh_led", 0);
		}
		OBD_DBG("Start WPS Enroll\n\n");
		wpsTimeout = 0;
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
		if(ob_wds)
			nvram_set("ob_qca_wds","1");
#endif		
		obd_start_wps_enrollee();
		status_g = 2;
	} else if (count_available && (status_g == 0 || status_g == 1)) {
		rssi_info.cap_count = count_available;
		add_ie_in_prbreq(unit);

		obd_start_active_scan();

		if (!status_g) {
#ifndef SECURITY_DOWNGRADE
			cap_count = count_available;
#endif
			status_g = 1;
		}
		// Reset timestamp. To avoid timeout reached in onboarding flow.
		time_ref = uptime();
	}
	
	free_bss_scan_result(bss_list);
	return 0;
}

static struct itimerval itv;
static void
alarmtimer(unsigned long sec, unsigned long usec)
{
	itv.it_value.tv_sec = sec;
	itv.it_value.tv_usec = usec;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void
obd(int sig)
{
	if (sig == SIGALRM)
	{
		if (status_g == 0 || status_g == 1) {
			cap_scan();

			alarm(obd_get_interval());
		} else if (status_g == 2) {	// WPS enrolling
			if (is_wps_stopped() || wpsTimeout >= WPS_TIMEOUT) {
				if (is_wps_success())
					status_g = 3;
				else
					status_g = 4;

				alarm(obd_get_interval());
			} else {
				wpsTimeout += RUSHURGENT_PERIOD;
				alarmtimer(0, RUSHURGENT_PERIOD);
			}
		} else if (status_g == 3) {	// WPS success
			if (nvram_get_int("obd_Setting") == 1) {
#ifdef RTCONFIG_MSSID_PRELINK
				restore_mssid_prelink_config();
#endif
				obd_save_para();
				obd_final(clean_vsie());
			} else {
				OBD_DBG("Exit due to WPS profile retrieval failure\n");
				nvram_set("restore_defaults", "1");
				notify_rc_after_wait("resetdefault");
			}

			kill(1, SIGTERM);
		} else if (status_g == 4) {	// WPS failure
			OBD_DBG("Exit due to WPS failure\n");
			nvram_set_int("amesh_wps_enr", 0);
			notify_rc("restart_wireless");
			obd_exit(SIGTERM);
		}
	}
}

static void
obd_exit(int sig)
{
	if (sig == SIGTERM)
	{
		alarmtimer(0, 0);

		obd_final(clean_vsie());

		remove("/var/run/obd.pid");
		exit(0);
	}
}

int
obd_main(int argc, char *argv[])
{
	FILE *fp;
	sigset_t sigs_to_catch;
	char *val;

	if (no_need_obd() == -1) {
		return 0;
	}

#ifdef RTCONFIG_SW_HW_AUTH
	time_t timestamp = time(NULL);
	char in_buf[48];
	char out_buf[65];
	char hw_out_buf[65];
	char *hw_auth_code = NULL;

	// initial
	memset(in_buf, 0, sizeof(in_buf));
	memset(out_buf, 0, sizeof(out_buf));
	memset(hw_out_buf, 0, sizeof(hw_out_buf));

	// use timestamp + APP_KEY to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, APP_KEY);

	hw_auth_code = hw_auth_check(APP_ID, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

	// use timestamp + APP_KEY + APP_ID to get auth_code
	snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, APP_KEY, APP_ID);

	// if check fail, return
	if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))))
		return 0;
#else
    dbG("auth check is disabled\n");
    return 0;
#endif

	if (obd_init() != 0)
	{
		return 0;
	}

	/* write pid */
	if ((fp = fopen("/var/run/obd.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	time_ref = uptime();

	nvram_set_int("amesh_found_cap", 0);
	nvram_set_int("amesh_led", 0);
	nvram_set_int("amesh_wps_enr", 0);
#ifdef CONFIG_BCMWL5
	nvram_set_int("obd_scan_state", 0);
#endif

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, obd);
	signal(SIGTERM, obd_exit);

	alarm(obd_get_interval());

	val = nvram_safe_get("obd_msglevel");
	if (strcmp(val, ""))
		msglevel = strtoul(val, NULL, 0);

	/* Get msic info */
	amas_get_misc_info((unsigned char *)&misc_info, &misc_info_len);

	/* Most of time it goes to sleep */
	while (1)
	{
		val = nvram_safe_get("obd_msglevel");
		if (strcmp(val, ""))
			msglevel = strtoul(val, NULL, 0);

		if (nvram_get_int("x_Setting") == 1)
			obd_exit(SIGTERM);

		pause();
	}

	return 0;
}
