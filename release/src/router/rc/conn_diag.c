#include <rc.h>

#ifdef RTCONFIG_ADV_RAST
#include <limits.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <json.h>
#include <math.h>
#include <pthread.h>
#ifdef RTCONFIG_CFGSYNC
#include <sys/shm.h>

#include <cfg_ipc.h>
#include <cfg_slavelist.h>
#endif
#include <conn_diag.h>
#include <conn_diag-sql.h>
#include "roamast.h"

#ifdef RTCONFIG_BCMBSD
#define BSD_REASON_NAME
#include "bsd.h"
#endif

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#include <wlceventd.h>


static int shm_wlc_event_tid = 0;
static P_WLC_EVENT_TABLE p_wlc_event_tbl = NULL;

static int shm_tg_roaming_tid = 0;
static P_TG_ROAMING_TABLE p_tg_roaming_tbl = NULL;
static int got_tg_roaming = 0;

static int shm_roaming_tid = 0;
static P_ROAMING_TABLE p_roaming_tbl = NULL;
static int got_roaming = 0;

#ifdef RTCONFIG_BCMBSD
static int shm_tg_bsd_tid = 0;
static P_TG_BSD_TABLE p_tg_bsd_tbl = NULL;
static int got_tg_bsd = 0;
#endif

int diag_mode = DIAGMODE_NONE;
int once_det = 0;

static int diag_interval = NORMAL_PERIOD;
static int diag_data_level = LOG_INFO;

static sigset_t sigs_to_catch;
static volatile int alarmed = 0;


int wlif_count = 0;

char lan_hwaddr[18];
char lan_ipaddr[16];
char chksta_mac[18];
int chksta_band = 0;
char* cat_buf = NULL;
char cap_ip[16];

int link_wan[WAN_UNIT_MAX];
char wan_ip[WAN_UNIT_MAX][32];
char wan_mask[WAN_UNIT_MAX][32];
char wan_gate[WAN_UNIT_MAX][32];
int got_default_route;
int got_redirect_rules;
int got_dns_resolved;
int got_ping_rep;

struct ether_addr* rast_ether_atoe(char *a, struct ether_addr *ret_ea);

static void classify_data(int isCAP, int mode, char *data);
static int enable_chksta();
// IPC
static int thread_term = 0;
static int snd_chksta_to_re(char *cap_mac, char *sta_mac, int band);
static int rcv_chksta_from_cap(char *data);
#if defined(RTCONFIG_HND_ROUTER_AX)
static int snd_chksta_data_to_cap(int gotSTA, char *ap_mac, int rssi, char *tx_rate, char *rx_rate, char *tx_nrate, char *rx_nrate);
#else
static int snd_chksta_data_to_cap(int gotSTA, char *ap_mac, int rssi, char *tx_rate, char *rx_rate);
#endif
static int rcv_chksta_data_from_re(char *data);
static int snd_req_to_re(int mode);
static int rcv_req_from_cap(char *data);
static int snd_data_to_cap(int mode, char *data);
static int rcv_data_from_re(char *data);
char *print_rate_buf(int raw_rate, char *buf, int buf_len);
char *print_llu_buf(unsigned long long raw_rate, char *buf, int buf_len);
static void print_sta_info();
static void sta_watchdog(int mode);
static int rcv_all_channel_detect_radar(char *data);
struct eventHandler{
    int event_id;
    int (*func)(char *data);
};

struct eventHandler CHK_EVENTS[] = {
	{ EID_CD_STA_CHK_ONE, rcv_chksta_from_cap },         // enable/disable to check one MAC's RSSI
	{ EID_CD_STA_CHK_ONE_RSP, rcv_chksta_data_from_re }, // report one MAC's RSSI
	{ EID_CD_CFG_RADAR_ALL, rcv_all_channel_detect_radar },
	{ -1, NULL }
};

#define PROC_NET_DEV "/proc/net/dev"
static int get_if_stats(const char *net_dev, const _if_stats *prev_stats, _if_stats *curr_stats) {
	FILE *fp;
	char buf[256];
	char *ifname;
	char *ptr;
	int i, ret = -1;

	if((fp = fopen(PROC_NET_DEV, "r")) == NULL) {
		DIAG_LOG(LOG_DEBUG, "\tCan't open the file: %s.", PROC_NET_DEV);
		DIAG_LOG(LOG_DEBUG, "... Failed");
		return ret;
	}

	fcntl(fileno(fp), F_SETFL, fcntl(fileno(fp), F_GETFL) | O_NONBLOCK);

	// headers.
	for(i = 0; i < 2; ++i){
		if(fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			DIAG_LOG(LOG_DEBUG, "\tCan't read the headers of %s.", PROC_NET_DEV);
			DIAG_LOG(LOG_DEBUG, "... Failed");
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				ret = -2;

			return ret;
		}
	}

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		if((ptr = strchr(buf, ':')) == NULL)
			continue;

		*ptr = 0;
		if((ifname = strrchr(buf, ' ')) == NULL)
			ifname = buf;
		else
			++ifname;

		if(strcmp(ifname, net_dev))
			continue;

		// <rx bytes, packets, errors, dropped, fifo errors, frame errors, compressed, multicast><tx ...>
		if(sscanf(ptr+1, "%llu%*u%*u%*u%*u%*u%*u%*u%llu", &curr_stats->rx_byte, &curr_stats->tx_byte) != 2) {
			fclose(fp);
			DIAG_LOG(LOG_DEBUG, "\tCan't read the bytes number in %s.", PROC_NET_DEV);
			DIAG_LOG(LOG_DEBUG, "... Failed");
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				ret = -2;

			return ret;
		}

		ret = 0;
		break;
	}
	fclose(fp);

	return ret;
}

/**
 * net_dev : wdsX, X is the band index.
 */
static int get_all_wds_if_stats(const int wifi_unit, const _if_stats *prev_stats, _if_stats *curr_stats) {
	FILE *fp;
	char buf[256];
	char *ifname;
	char *ptr;
	unsigned long long rx_byte = 0, tx_byte = 0;
	int i, ret = -1;
	char wds_prefix[8];

	if((fp = fopen(PROC_NET_DEV, "r")) == NULL) {
		DIAG_LOG(LOG_DEBUG, "\tCan't open the file: %s.", PROC_NET_DEV);
		DIAG_LOG(LOG_DEBUG, "... Failed");
		return ret;
	}

	fcntl(fileno(fp), F_SETFL, fcntl(fileno(fp), F_GETFL) | O_NONBLOCK);

	// headers.
	for(i = 0; i < 2; ++i){
		if(fgets(buf, sizeof(buf), fp) == NULL) {
			fclose(fp);
			DIAG_LOG(LOG_DEBUG, "\tCan't read the headers of %s.", PROC_NET_DEV);
			DIAG_LOG(LOG_DEBUG, "... Failed");
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				ret = -2;

			return ret;
		}
	}

	snprintf(wds_prefix, sizeof(wds_prefix), "wds%d", wifi_unit);

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		if((ptr = strchr(buf, ':')) == NULL)
			continue;

		*ptr = 0;
		if((ifname = strrchr(buf, ' ')) == NULL)
			ifname = buf;
		else
			++ifname;

		if(strncmp(ifname, wds_prefix, strlen(wds_prefix)))
			continue;

		// <rx bytes, packets, errors, dropped, fifo errors, frame errors, compressed, multicast><tx ...>
		if(sscanf(ptr+1, "%llu%*u%*u%*u%*u%*u%*u%*u%llu", &rx_byte, &tx_byte) != 2) {
			fclose(fp);
			DIAG_LOG(LOG_DEBUG, "\tCan't read the bytes number in %s.", PROC_NET_DEV);
			DIAG_LOG(LOG_DEBUG, "... Failed");
			if(errno == EAGAIN || errno == EWOULDBLOCK)
				ret = -2;

			return ret;
		}

		curr_stats->rx_byte += rx_byte;
		curr_stats->tx_byte += tx_byte;
	}
	ret = 0;
	fclose(fp);

	return ret;
}

static int get_wifi_fh_stats(const int wifi_unit, int include_wds, const _if_stats *prev_stats, _if_stats *curr_stats)
{
	int ret = -1;
	char *next = NULL;
	char word[64];
	char ifnames[64];
	_if_stats main_if_stats, wds_if_stats;
	if (wifi_unit < 0 || !curr_stats)
		return ret;

	// Get main fronthaul interfaces.
	if (!diag_get_wifi_fh_ifnames(wifi_unit, ifnames, sizeof(ifnames)))
		return ret;

	DIAG_LOG(LOG_DEBUG, "wifi_fh ifnames=%s", ifnames);
	foreach (word, ifnames, next) {
		memset(&main_if_stats, 0, sizeof(main_if_stats));
		ret = get_if_stats(word, NULL, &main_if_stats);
		if (ret < 0)
			return ret;

		curr_stats->rx_byte += main_if_stats.rx_byte;
		curr_stats->tx_byte += main_if_stats.tx_byte;
	}

	if (include_wds) {
		// Get all wds interfaces of the current wifi unit.
		memset(&wds_if_stats, 0, sizeof(wds_if_stats));
		ret = get_all_wds_if_stats(wifi_unit, NULL, &wds_if_stats);
		if (ret < 0)
			return ret;

		curr_stats->rx_byte += wds_if_stats.rx_byte;
		curr_stats->tx_byte += wds_if_stats.tx_byte;
	}

	return ret;
}

extern char* diag_get_wl_ifname(
	int unit, 
	int subunit, 
	char *buffer, 
	size_t buffer_size)
{
	char s[81], *ss = NULL, *ret = NULL;

	if (!buffer || buffer_size <= 0 || unit < 0)
		return NULL;

	memset(s, 0, sizeof(s));
	if (subunit <= 0)
		snprintf(s, sizeof(s), "wl%d_ifname", unit);
	else
		snprintf(s, sizeof(s)-1, "wl%d.%d_ifname", unit, subunit);

	ss = nvram_get(s);
	if (ss && strlen(ss) > 0)
	{
		memcpy(buffer, ss, (strlen(ss) > buffer_size) ? buffer_size : strlen(ss));
		ret = &buffer[0];
	}

	return ret;
}

extern int diag_get_sub_if_bss_enabled(int unit, int subunit)
{
	char s[81];

	if (unit < 0)
		return 0;

	memset(s, 0, sizeof(s));
	if (subunit <= 0)
		snprintf(s, sizeof(s)-1, "wl%d_bss_enabled", unit);
	else
		snprintf(s, sizeof(s)-1,  "wl%d.%d_bss_enabled", unit, subunit);

	return nvram_get_int(s);
}

extern int diag_get_sub_if_closed(int unit, int subunit)
{
	char s[81];

	if (unit < 0)
		return 0;

	memset(s, 0, sizeof(s));
	if (subunit <= 0)
		snprintf(s, sizeof(s)-1, "wl%d_closed", unit);
	else
		snprintf(s, sizeof(s)-1,  "wl%d.%d_closed", unit, subunit);

	return nvram_get_int(s);
}

static char* get_sub_if_name(int unit, int subunit, char *buffer, size_t buffer_size)
{
	char s[81], *ss = NULL, *ret = NULL;

	if (!buffer || buffer_size <= 0 || unit < 0)
		return NULL;

	if (subunit <= 0)
		snprintf(s, sizeof(s), "wl%d_ifname", unit);
	else
		snprintf(s, sizeof(s)-1, "wl%d.%d_ifname", unit, subunit);

	ss = nvram_get(s);
	if (ss && strlen(ss) > 0)
	{
		snprintf(buffer, buffer_size, "%s", ss);
		ret = &buffer[0];
	}

	return ret;
}

static char *get_node_band_by_unit(int unit, char *buf, int buflen){
#ifndef NO_NBAND
	char nv_nband[64];
	snprintf(nv_nband, sizeof(nv_nband), "wl%d_nband", unit);
	int nband = nvram_get_int(nv_nband);
	if (nband == 2)
		snprintf(buf, buflen, "2G");
	else if (nband == 1)
	{
		if (unit == 1)
			snprintf(buf, buflen, "5G");
		else if (unit == 2)
			snprintf(buf, buflen, "5G1");
	}
	else if (nband == 4)
		snprintf(buf, buflen, "6G");
	else
		snprintf(buf, buflen, "-1");
#else
	snprintf(buf, buflen, "-1");
#endif
    return buf;
}

static char *get_node_band_by_ifname(char *ifname, char *buf, int buflen){
	int idx, vidx;
	char wl_ifname[8];
	char tmp[100], prefix[32];
	int got_unit = 0;

	for(idx = 0; idx < wlif_count; idx++){
		if(!bssinfo[idx].bss_enable[0]) continue;
		if(!bssinfo[idx].user_low_rssi) continue;

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++){
			if(vidx > 0){
				if(!bssinfo[idx].bss_enable[vidx]) continue;

				snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);
			}
			else
				snprintf(prefix, sizeof(prefix), "wl%d_", idx);

			snprintf(wl_ifname, sizeof(wl_ifname), "%s", nvram_safe_get(strcat_r(prefix, "ifname", tmp)));

			if(!strcmp(wl_ifname, ifname)){
				got_unit = 1;

				break;
			}
		}

		if(got_unit)
			break;
	}

	if(!got_unit)
		snprintf(buf, buflen, "-1");
	else if(idx > 1)
		snprintf(buf, buflen, "5G%d", idx);
	else if(idx == 1)
		snprintf(buf, buflen, "5G");
	else
		snprintf(buf, buflen, "2G");

	return buf;
}

/*
 *  Return values:
 *  >1: there were other situations
 *   1: OK
 *   0: No
 *  -1: Failed
 */
static int if_phy_connected(int wan_unit){
	int link_wan = 0;
#ifdef RTCONFIG_USB_MODEM
	int modem_act_reset = 0;
	int sim_state = 0;
	int modem_unit;
	char tmp2[100], prefix2[32];
	char env_unit[32];
	char modem_type[32];

	DIAG_LOG(LOG_DEBUG, "********** detect the PHY connection:");

#ifdef RTCONFIG_WIRELESSREPEATER
	// check if set AP.
	if(!is_cap()){
		snprintf(prefix2, sizeof(prefix2), "wlc_");
		link_wan = (nvram_get_int(strcat_r(prefix2, "state", tmp2)) == WLC_STATE_CONNECTED)?STATE_PHY_CONN:STATE_PHY_DISCONN;

		if(link_wan == STATE_PHY_CONN)
			DIAG_LOG(LOG_DEBUG, "... OK");
		else if(!link_wan || link_wan > 1)
			DIAG_LOG(LOG_DEBUG, "... No");
		else{
			DIAG_LOG(LOG_DEBUG, "\tcouldn't detect the PHY connection.");
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}

		return link_wan;
	}
	else
#endif
	if(dualwan_unit__usbif(wan_unit)){
		modem_unit = get_modemunit_by_type(get_dualwan_by_unit(wan_unit));

		if(modem_unit == MODEM_UNIT_NONE){
			DIAG_LOG(LOG_DEBUG, "\tcannot get the modem unit!");
			DIAG_LOG(LOG_DEBUG, "... Failed");

			return -1;
		}

		usb_modem_prefix(modem_unit, prefix2, sizeof(prefix2));

		// need to check before detecting SIM. If not, the detect of conn_diag will be blocked.
		if(nvram_get_int(strcat_r(prefix2, "act_scanning", tmp2)) != 0){
			DIAG_LOG(LOG_DEBUG, "\tdetect the modem was scanning.");
			DIAG_LOG(LOG_DEBUG, "... Failed");

			return STATE_MODEM_SCAN;
		}

		modem_act_reset = nvram_get_int(strcat_r(prefix2, "act_reset", tmp2));
		if(modem_act_reset == 1 || modem_act_reset == 2){
			DIAG_LOG(LOG_DEBUG, "\tdetect the modem was reseting.");
			DIAG_LOG(LOG_DEBUG, "... Failed");

			return STATE_MODEM_RESET;
		}

		// need to see the link status of modem anyway.
		link_wan = is_usb_modem_ready(get_dualwan_by_unit(wan_unit));

		if(link_wan){
			snprintf(env_unit, sizeof(env_unit), "unit=%d", modem_unit);
			putenv(env_unit);

			snprintf(modem_type, sizeof(modem_type), "%s", nvram_safe_get(strcat_r(prefix2, "act_type", tmp2)));
			if(strlen(modem_type) <= 0){
				eval("/usr/sbin/find_modem_type.sh");
				snprintf(modem_type, sizeof(modem_type), "%s", nvram_safe_get(strcat_r(prefix2, "act_type", tmp2)));
			}

			if(!nvram_get(strcat_r(prefix2, "act_sim", tmp2)))
				sim_state = 100; // 100: didn't detect the SIM status yet.
			else
				sim_state = nvram_get_int(strcat_r(prefix2, "act_sim", tmp2));

			if(!strcmp(modem_type, "tty") || !strcmp(modem_type, "mbim") || !strcmp(modem_type, "qmi") || !strcmp(modem_type, "gobi")
#if defined(RTCONFIG_FIBOCOM_FG621)
				|| (!strcmp(modem_type, "ncm"))
#endif
				){
				if(sim_state == 100){
					DIAG_LOG(LOG_DEBUG, "\tdidn't detect the SIM status yet.");
					DIAG_LOG(LOG_DEBUG, "... Failed");

					sim_state = nvram_get_int(strcat_r(prefix2, "act_sim", tmp2));
				}

				if(sim_state == 2){
					DIAG_LOG(LOG_DEBUG, "\tdetect the modem was locked by PIN.");
					DIAG_LOG(LOG_DEBUG, "... Failed");

					link_wan = STATE_MODEM_LOCK_PIN;
				}
				else if(sim_state == 3){
					DIAG_LOG(LOG_DEBUG, "\tdetect the modem was locked by PUK.");
					DIAG_LOG(LOG_DEBUG, "... Failed");

					link_wan = STATE_MODEM_LOCK_PUK;
				}
				else if(sim_state != 1){
					DIAG_LOG(LOG_DEBUG, "\tdetect the modem was not inserted the SIM.");
					DIAG_LOG(LOG_DEBUG, "... Failed");

					link_wan = STATE_MODEM_NOSIM;
				}
			}

			unsetenv("unit");
		}
	}
	else
#endif // RTCONFIG_USB_MODEM
	{
		// check wan port.
		if(get_wanports_status(wan_unit) > 0)
			link_wan = STATE_PHY_CONN;
		else
			link_wan = STATE_PHY_DISCONN;
	}

	if(link_wan == STATE_PHY_CONN)
		DIAG_LOG(LOG_DEBUG, "... OK");
	else if(!link_wan)
		DIAG_LOG(LOG_DEBUG, "... No");
	else{
		DIAG_LOG(LOG_DEBUG, "\tcouldn't detect the PHY connection.");
		DIAG_LOG(LOG_DEBUG, "... Failed");
	}

	return link_wan;
}

static int if_ip_profile_existed(int wan_unit, char *wan_ip, int ip_len, char *wan_mask, int mask_len, char *wan_gate, int gate_len){
	int sk = 0;
	struct ifreq ifr;
	char wan_ifname[32];
	struct sockaddr ip, mask;

	DIAG_LOG(LOG_DEBUG, "********** detect the IP profile:");

	memset(wan_ip, 0, ip_len);
	memset(wan_mask, 0, mask_len);
	memset(wan_gate, 0, gate_len);

	snprintf(wan_ip, ip_len, "-1");
	snprintf(wan_mask, mask_len, "-1");
	snprintf(wan_gate, gate_len, "-1");

	if(!is_cap())
		snprintf(wan_ifname, sizeof(wan_ifname), "%s", nvram_safe_get("lan_ifname"));
	else
		snprintf(wan_ifname, sizeof(wan_ifname), "%s", get_wan_ifname(wan_unit));
	if(strlen(wan_ifname) <= 0){
		if(!is_cap()){
			DIAG_LOG(LOG_DEBUG, "\tno interface.");
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}
		else{
			DIAG_LOG(LOG_DEBUG, "\tno interface of wan_unit %d.", wan_unit);
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}

		return -1;
	}

	/* Retrieve IP info */
	if((sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		if(!is_cap()){
			DIAG_LOG(LOG_DEBUG, "\tCan't build the socket.");
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}
		else{
			DIAG_LOG(LOG_DEBUG, "\tCan't build the socket of wan_unit %d.", wan_unit);
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}

		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, wan_ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if(ioctl(sk, SIOCGIFADDR, &ifr)){
		if(!is_cap()){
			DIAG_LOG(LOG_DEBUG, "\tCan't send SIOCGIFADDR.");
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}
		else{
			DIAG_LOG(LOG_DEBUG, "\tCan't send SIOCGIFADDR of wan_unit %d.", wan_unit);
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}

		close(sk);
		return -1;
	}

	ip.sa_family = AF_INET;
	memcpy(&ip.sa_data, &ifr.ifr_addr.sa_data, 14);
	snprintf(wan_ip, ip_len, "%s", inet_ntoa(sin_addr(&ip)));
	if(!(*wan_ip))
		snprintf(wan_ip, ip_len, "-1");

	if(ioctl(sk, SIOCGIFNETMASK, &ifr)){
		if(!is_cap()){
			DIAG_LOG(LOG_DEBUG, "\tCan't send SIOCGIFNETMASK.");
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}
		else{
			DIAG_LOG(LOG_DEBUG, "\tCan't send SIOCGIFNETMASK of wan_unit %d.", wan_unit);
			DIAG_LOG(LOG_DEBUG, "... Failed");
		}

		close(sk);
		return -1;
	}
	close(sk);

	mask.sa_family = AF_INET;
	memcpy(&mask.sa_data, &ifr.ifr_netmask.sa_data, 14);
	snprintf(wan_mask, mask_len, "%s", inet_ntoa(sin_addr(&mask)));
	if(!(*wan_mask))
		snprintf(wan_mask, mask_len, "-1");

#if 1
	if(!is_cap()){
		snprintf(wan_gate, gate_len, "%s", nvram_safe_get("lan_gateway"));
	}
	else{
		char tmp[100], prefix[32];

		snprintf(prefix, sizeof(prefix), "wan%d_", wan_unit);
		snprintf(wan_gate, gate_len, "%s", nvram_safe_get(strcat_r(prefix, "gateway", tmp)));
	}
	if(!(*wan_gate))
		snprintf(wan_gate, gate_len, "-1");
#else
	// Broadcom BCM4708 cannot get the gateway by SIOCGIFDSTADDR, so mark these.
	int sk2 = 0;
	struct ifreq ifr2;

	if((sk2 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		return -1;
	}

	memset(&ifr2, 0, sizeof(struct ifreq));
	strncpy(ifr2.ifr_name, wan_ifname, IFNAMSIZ);
	ifr2.ifr_addr.sa_family = AF_INET;
	if(ioctl(sk2, SIOCGIFDSTADDR, &ifr2)){
		close(sk2);
		return -1;
	}

	snprintf(wan_gate, gate_len, "%s", inet_ntoa(sin_addr(&ifr2.ifr_dstaddr)));

	close(sk2);
#endif

	if(!is_cap()){
		DIAG_LOG(LOG_DEBUG, "  ip=%s.", wan_ip);
		DIAG_LOG(LOG_DEBUG, "mask=%s.", wan_mask);
		DIAG_LOG(LOG_DEBUG, "gate=%s.", wan_gate);
	}
	else{
		DIAG_LOG(LOG_DEBUG, "  wan_ip=%s.", wan_ip);
		DIAG_LOG(LOG_DEBUG, "wan_mask=%s.", wan_mask);
		DIAG_LOG(LOG_DEBUG, "wan_gate=%s.", wan_gate);
	}

	DIAG_LOG(LOG_DEBUG, "... OK");

	return 0;
}

/*
 *  Return values:
 *   1: OK
 *   0: No
 *  -1: Failed
 */
static int if_def_route(){
	char cmd[64] = {0};
	FILE *fp = NULL;
	char buf[MAX_DATA];

	DIAG_LOG(LOG_DEBUG, "********** detect the default route:");

	snprintf(cmd, sizeof(cmd), "/usr/sbin/ip route |grep default 2>/dev/null");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCan't execute ip.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

	memset(buf, 0, sizeof(buf));
	if(fgets(buf, sizeof(buf), fp) != NULL){
		pclose(fp);

		DIAG_LOG(LOG_DEBUG, "... OK");

		return 1;
	}
	pclose(fp);

	DIAG_LOG(LOG_DEBUG, "... No");

	return 0;
}

/*
 *  Return values:
 *   3: redirect http & dns
 *   2: redirect http
 *   1: redirect dns
 *   0: no redirect rules
 *  -1: redirect http & dns
 */
static int if_redirect_rule(){
	char cmd[64] = {0};
	FILE *fp = NULL;
	char buf[MAX_DATA];
	char rule_http[32], rule_dns[32];
	int ret = 0;

	DIAG_LOG(LOG_DEBUG, "********** detect the redirect rules:");

	snprintf(cmd, sizeof(cmd), "/usr/sbin/iptables -t nat -nL PREROUTING 2>/dev/null");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCann't execute iptables.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

	snprintf(rule_http, sizeof(rule_http), "tcp dpt:80 to:%s:18017", lan_ipaddr);
	snprintf(rule_dns, sizeof(rule_dns), "udp dpt:53 to:%s:18018", lan_ipaddr);

	memset(buf, 0, sizeof(buf));
	while(fgets(buf, sizeof(buf), fp) != NULL){
		if(strstr(buf, rule_http))
			ret |= 1<<1;
		else if(strstr(buf, rule_dns))
			if(is_cap())
				ret |= 1;

		if(ret == 3)
			break;

		memset(buf, 0, sizeof(buf));
	}
	pclose(fp);

	if(!ret)
		DIAG_LOG(LOG_DEBUG, "... OK");
	else if(ret == 3){
		DIAG_LOG(LOG_DEBUG, "\tRedirected HTTP & DNS.");
		DIAG_LOG(LOG_DEBUG, "... No");
	}
	else if(ret == 2){
		DIAG_LOG(LOG_DEBUG, "\tRedirected HTTP.");
		DIAG_LOG(LOG_DEBUG, "... No");
	}
	else if(ret == 1){
		DIAG_LOG(LOG_DEBUG, "\tRedirected DNS.");
		DIAG_LOG(LOG_DEBUG, "... No");
	}
	else{
		DIAG_LOG(LOG_DEBUG, "\tcouldn't detect the redirect rule.");
		DIAG_LOG(LOG_DEBUG, "... Failed");
	}

	return ret;
}

/*
 *  Return values:
 *   1: dns probe ok
 *   0: dns probe has failed
 *  -1: dns probe is disabled
 */
static int if_dns_response(){
	int ret = do_dns_detect(-1);

	DIAG_LOG(LOG_DEBUG, "********** detect the DNS response:");

	if (ret < 0)
		DIAG_LOG(LOG_DEBUG, "... Failed"); /* internal checking error! */
	else if (ret > 0)
		DIAG_LOG(LOG_DEBUG, "... OK");
	else
		DIAG_LOG(LOG_DEBUG, "... No");

	return ret;
}

/*
 *  Return values:
 *   1: ping target ok
 *   0: ping target has failed
 *  -1: ping target is disabled
 */
static int if_ping_detect(char *target){
	int ret = do_ping_detect(-1, target);

	DIAG_LOG(LOG_DEBUG, "********** detect the ping result:");

	if (ret < 0)
		DIAG_LOG(LOG_DEBUG, "... Failed"); /* internal checking error! */
	else if (ret > 0)
		DIAG_LOG(LOG_DEBUG, "... OK");
	else
		DIAG_LOG(LOG_DEBUG, "... No");

	return ret;
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_NET>node type>IP>MAC>wan_unit>link_wan>runIP>runMASK>runGATE>got_Route>got Redirect rules>DNS>Ping
 */
static int diag_wan_detect(){
	int wan_unit = -1;
	char data[MAX_DATA];

	for(wan_unit = WAN_UNIT_FIRST; wan_unit < WAN_UNIT_MAX; ++wan_unit){
		if(get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_NONE)
			continue;

		link_wan[wan_unit] = if_phy_connected(wan_unit);
		if_ip_profile_existed(wan_unit, wan_ip[wan_unit], sizeof(wan_ip[wan_unit]), wan_mask[wan_unit], sizeof(wan_mask[wan_unit]), wan_gate[wan_unit], sizeof(wan_gate[wan_unit]));
		got_default_route = if_def_route();
		got_redirect_rules = if_redirect_rule();
		got_dns_resolved = if_dns_response();
		got_ping_rep = if_ping_detect(nvram_safe_get("wandog_target"));

		snprintf(data, sizeof(data), "<%s>%s>%s>%s>%d>%d>%s>%s>%s>%d>%d>%d>%d", DIAG_EVENT_NET, node_str(), lan_ipaddr, lan_hwaddr,
				wan_unit, link_wan[wan_unit], wan_ip[wan_unit], wan_mask[wan_unit], wan_gate[wan_unit],
				got_default_route, got_redirect_rules,
				got_dns_resolved, got_ping_rep
				);
		snd_data_to_cap(DIAGMODE_NET_DETECT, data);

		if(!is_cap())
			break;
	}

	return 0;
}

/*
 *  value: DIAG_EVENT_WIFISYS>node type>IP>MAC>2G's ifname,2G's chip,2G's country/rev>5G's ifname,5G's chip,5G's country/rev
 */
static void diag_wifi_sys_setting(){
	char ifname[8], *next;
	char buf1[32], buf2[32];
	char data[MAX_DATA], *ptr;
	int len;

	snprintf(data, sizeof(data), "<%s>%s>%s>%s", DIAG_EVENT_WIFISYS, node_str(), lan_ipaddr, lan_hwaddr);

	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
		get_wifi_chip(ifname, buf1, sizeof(buf1));
		get_wifi_country(ifname, buf2, sizeof(buf2));

		len = strlen(data);
		ptr = data+len;
		snprintf(ptr, sizeof(data)-len, ">%s,%s,%s", ifname, buf1, buf2);
	}

	snd_data_to_cap(DIAGMODE_WIFI_SETTING, data);
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_STAINFO>node type>IP>MAC>STA's MAC>STA's Band>STA's RSSI>active>STA's Tx rate>STA's Rx rate>STA's Tx byte>STA's Rx byte
 */
static int get_wifi_client(int mode){
	time_t now = uptime();
	int idx, vidx;
	rast_sta_info_t *sta;
	char mac[32], tx_rate[32], rx_rate[32];
	char tx_byte[32], rx_byte[32];
	char data[MAX_DATA];
	int enabled = 0;
	char band[4];

	DIAG_LOG(LOG_DEBUG, "********** detect wireless clients:");

	for(idx = 0; idx < wlif_count; idx++){
		if(!bssinfo[idx].user_low_rssi) continue;

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++){
			if(vidx > 0){
				if(!bssinfo[idx].bss_enable[vidx])
					continue;
			}

			sta = bssinfo[idx].assoclist[vidx];
			while(sta){
				if(now-sta->active > diag_interval*2)
					enabled = 0;
				else
					enabled = 1;
				snprintf(mac, sizeof(mac), MACF_UP, ETHER_TO_MACF(sta->addr));
				print_rate_buf(sta->tx_rate, tx_rate, sizeof(tx_rate));
				print_rate_buf(sta->rx_rate, rx_rate, sizeof(rx_rate));
				print_llu_buf(sta->tx_byte, tx_byte, sizeof(tx_byte));
				print_llu_buf(sta->rx_byte, rx_byte, sizeof(rx_byte));

#if defined(RTCONFIG_HND_ROUTER_AX)
				snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%s>%d>%d>%s>%s>%s>%s>%s>%s", DIAG_EVENT_STAINFO, node_str(), lan_ipaddr, lan_hwaddr,
						mac, get_node_band_by_unit(idx, band, sizeof(band)), sta->rssi, enabled, tx_rate, rx_rate, tx_byte, rx_byte, sta->tx_nrate, sta->rx_nrate);
#else
				snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%s>%d>%d>%s>%s>%s>%s>-1>-1", DIAG_EVENT_STAINFO, node_str(), lan_ipaddr, lan_hwaddr,
						mac, get_node_band_by_unit(idx, band, sizeof(band)), sta->rssi, enabled, tx_rate, rx_rate, tx_byte, rx_byte);
#endif

				snd_data_to_cap(mode, data);

				sta = sta->next;
			}
		}
	}

	return 0;
}

static void _close_wlc_event_tbl(int sig){
	/* detach shared memory */
	if(shmdt(p_wlc_event_tbl) == -1)
		DIAG_LOG(LOG_DEBUG, "detach wlc_event's shared memory failed");
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_WLCE>node type>IP>MAC>STA's MAC>STA's Band>last_act>count_auth>count_deauth>count_assoc>count_disassoc>count_reassoc
 */
static int get_wlce_count(){
	int lock, i;
	char data[MAX_DATA];
	char sta_band[4];
	int got_data = 0;

	DIAG_LOG(LOG_DEBUG, "********** detect WLC event counts:");

	lock = file_lock(WLCE_FILE_LOCK);
	shm_wlc_event_tid = shmget((key_t)KEY_WLC_EVENT, sizeof(WLC_EVENT_TABLE), 0444);
	if(shm_wlc_event_tid == -1){
		DIAG_LOG(LOG_DEBUG, "Reading wlc event table shmget failed");
		file_unlock(lock);
		return 0;
	}

	p_wlc_event_tbl = (P_WLC_EVENT_TABLE)shmat(shm_wlc_event_tid, NULL, 0);

	DIAG_LOG(LOG_DEBUG, "SHM: wlc total=%d.\n", p_wlc_event_tbl->total);

	for(i = 0; i < p_wlc_event_tbl->total; i++){
		if(!got_data)
			got_data = 1;

		snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%s>%d>%d>%d>%d>%d>%d", DIAG_EVENT_WLCE, node_str(), lan_ipaddr, lan_hwaddr,
				p_wlc_event_tbl->macAddr[i], get_node_band_by_ifname(p_wlc_event_tbl->node_if[i], sta_band, sizeof(sta_band)), p_wlc_event_tbl->last_act[i],
				p_wlc_event_tbl->count_auth[i], p_wlc_event_tbl->count_deauth[i], p_wlc_event_tbl->count_assoc[i], p_wlc_event_tbl->count_disassoc[i], p_wlc_event_tbl->count_reassoc[i]
				);

		DIAG_LOG(LOG_DEBUG, "%s.\n", data);
		snd_data_to_cap(DIAGMODE_STAINFO, data);
	}

	file_unlock(lock);

	_close_wlc_event_tbl(-1);

	if(got_data)
		kill_pidfile_s("/var/run/wlceventd.pid", SIGUSR1);

	return 0;
}

static void _close_tg_roaming_tbl(int sig){
	/* detach shared memory */
	if(shmdt(p_tg_roaming_tbl) == -1)
		DIAG_LOG(LOG_DEBUG, "detach tg_roaming's shared memory failed");
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_TG_ROAMING>node type>IP>MAC>STA's MAC>STA's Band>STA's RSSI>timestamp>user_low_rssi>rssi_cnt>idle_period>idle_start
 */
static int get_tg_roaming_event(){
	int lock, i;
	char data[MAX_DATA];
	char band[4];

	DIAG_LOG(LOG_DEBUG, "********** detect tg_roaming events:");

	lock = file_lock(TG_ROAMING_LOCK);
	shm_tg_roaming_tid = shmget((key_t)KEY_TG_ROAMING_EVENT, sizeof(TG_ROAMING_TABLE), 0444);
	if(shm_tg_roaming_tid == -1){
		DIAG_LOG(LOG_DEBUG, "Reading tg_roaming event table shmget failed");
		file_unlock(lock);
		return 0;
	}

	p_tg_roaming_tbl = (P_TG_ROAMING_TABLE)shmat(shm_tg_roaming_tid, NULL, 0);

	DIAG_LOG(LOG_DEBUG, "SHM: tg_roaming total=%d.\n", p_tg_roaming_tbl->total);

	for(i = 0; i < p_tg_roaming_tbl->total; i++){
		got_tg_roaming = 1;

		snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%s>%d>%lu>%d>%d>%d>%lu", DIAG_EVENT_TG_ROAMING, node_str(), lan_ipaddr, lan_hwaddr,
				p_tg_roaming_tbl->sta[i], get_node_band_by_unit(p_tg_roaming_tbl->band_unit[i], band, sizeof(band)), p_tg_roaming_tbl->sta_rssi[i],
				p_tg_roaming_tbl->tstamp[i], p_tg_roaming_tbl->user_low_rssi[i], p_tg_roaming_tbl->rssi_cnt[i],
				p_tg_roaming_tbl->idle_period[i], p_tg_roaming_tbl->idle_start[i]
				);

		DIAG_LOG(LOG_DEBUG, "%s.\n", data);
		snd_data_to_cap(DIAGMODE_STAINFO, data);
	}

	file_unlock(lock);

	_close_tg_roaming_tbl(-1);

	return 0;
}

static void _close_roaming_tbl(int sig){
	/* detach shared memory */
	if(shmdt(p_roaming_tbl) == -1)
		DIAG_LOG(LOG_DEBUG, "detach roaming's shared memory failed");
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_ROAMING>node type>IP>MAC>STA's MAC>STA's RSSI>timestamp>candidate_rssi_criteria>candidate's MAC>candidate's RSSI
 */
static int get_roaming_event(){
	int lock, i;
	char data[MAX_DATA];

	DIAG_LOG(LOG_DEBUG, "********** detect roaming events:");

	lock = file_lock(ROAMING_LOCK);
	shm_roaming_tid = shmget((key_t)KEY_ROAMING_EVENT, sizeof(ROAMING_TABLE), 0444);
	if(shm_roaming_tid == -1){
		DIAG_LOG(LOG_DEBUG, "Reading roaming event table shmget failed");
		file_unlock(lock);
		return 0;
	}

	p_roaming_tbl = (P_ROAMING_TABLE)shmat(shm_roaming_tid, NULL, 0);

	DIAG_LOG(LOG_DEBUG, "SHM: roaming total=%d.\n", p_roaming_tbl->total);

	for(i = 0; i < p_roaming_tbl->total; i++){
		got_roaming = 1;

		snprintf(data, sizeof(data), "<%s>%s>%s>%s>%u>%s>%d>%d>%s>%d>%d>%s", DIAG_EVENT_ROAMING, node_str(), lan_ipaddr, lan_hwaddr,
				(unsigned int)p_roaming_tbl->tstamp[i], p_roaming_tbl->sta[i], p_roaming_tbl->sta_rssi[i],
				p_roaming_tbl->candidate_rssi_criteria[i], p_roaming_tbl->candidate[i], p_roaming_tbl->candidate_rssi[i]
#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
				,p_roaming_tbl->ret_11v[i]
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
				,p_roaming_tbl->present_ap[i]
#else
				,""
#endif
#else
				,-2,""
#endif
				);

		DIAG_LOG(LOG_DEBUG, "%s.\n", data);
		snd_data_to_cap(DIAGMODE_STAINFO, data);
	}

	file_unlock(lock);

	_close_roaming_tbl(-1);

	return 0;
}

#ifdef RTCONFIG_BCMBSD
static void _close_tg_bsd_tbl(int sig){
	/* detach shared memory */
	if(shmdt(p_tg_bsd_tbl) == -1)
		DIAG_LOG(LOG_DEBUG, "detach tg_bsd's shared memory failed");
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_TG_BSD>node type>IP>MAC>STA's MAC>timestamp>from_chanspec>to_chanspec>reason
 */
static int get_tg_bsd_event(){
	int lock, i;
	char data[MAX_DATA];

	DIAG_LOG(LOG_DEBUG, "********** detect tg_bsd events:");

	lock = file_lock(TG_BSD_LOCK);
	shm_tg_bsd_tid = shmget((key_t)KEY_TG_BSD_EVENT, sizeof(TG_BSD_TABLE), 0444);
	if(shm_tg_bsd_tid == -1){
		DIAG_LOG(LOG_DEBUG, "Reading tg_bsd event table shmget failed");
		file_unlock(lock);
		return 0;
	}

	p_tg_bsd_tbl = (P_TG_BSD_TABLE)shmat(shm_tg_bsd_tid, NULL, 0);

	DIAG_LOG(LOG_DEBUG, "SHM: tg_bsd total=%d.\n", p_tg_bsd_tbl->total);

	for(i = 0; i < p_tg_bsd_tbl->total; i++){
		got_tg_bsd = 1;

		snprintf(data, sizeof(data), "<%s>%s>%s>%s>"MACF">%lu>%x>%x>%s", DIAG_EVENT_TG_BSD, node_str(), lan_ipaddr, lan_hwaddr,
				ETHER_TO_MACF(p_tg_bsd_tbl->steer_records[i].addr),
				(unsigned long)(p_tg_bsd_tbl->steer_records[i].timestamp),
				p_tg_bsd_tbl->steer_records[i].from_chanspec,
				p_tg_bsd_tbl->steer_records[i].to_chanspec,
				bsd_get_reason_name(p_tg_bsd_tbl->steer_records[i].reason)
				);

		DIAG_LOG(LOG_DEBUG, "%s.\n", data);
		snd_data_to_cap(DIAGMODE_STAINFO, data);
	}

	file_unlock(lock);

	_close_tg_bsd_tbl(-1);

	return 0;
}
#endif

/*
#ifdef RTCONFIG_BCMARM
 *  value: DIAG_EVENT_WIFISYS2>node type>IP>MAC>band>band's ifname>band's MAC>band's noise>band's MCS>band's capability>band's subif_count>base64encode(band's subif_ssid)>band's chanim
#else
 *  value: DIAG_EVENT_WIFISYS2>node type>IP>MAC>band>band's ifname>band's MAC>band's noise>band's MCS>band's capability>band's subif_count>base64encode(band's subif_ssid)
#endif
 */
static void diag_wifi_detect(int mode){
	char ifname[8], *next, buf_tx[12], buf_rx[12];
	int wifi_unit;
	char mac_nvram[64];
	char band[4], mac[18], noise[32], mcs[64];
	char data[MAX_DATA], *ptr;
	int len;
#ifdef RTCONFIG_BCMARM
	int capability = 0;
	int subif_count = 0;
	char subif_ssid[MAX_DATA];
#endif
	_if_stats if_stats;
	int include_wds;

	wifi_unit = 0;
	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
		include_wds = 1;

#ifdef RTCONFIG_FRONTHAUL_DWB
		char fh_ap_prefix[8];
		int dwb_band = nvram_get_int("dwb_band");
		if (nvram_match("smart_connect_x", "1") && nvram_get_int("fh_ap_enabled") > 0 && wifi_unit == dwb_band) {
			snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s", DIAG_EVENT_WIFISYS2, node_str(), lan_ipaddr, lan_hwaddr, get_node_band_by_unit(dwb_band, band, sizeof(band)));

			snprintf(fh_ap_prefix, sizeof(fh_ap_prefix), "wl%d.%d", dwb_band, 
				(is_cap() ? nvram_get_int("fh_capTmssid_subunit") : nvram_get_int("fh_re_mssid_subunit")));

			snprintf(ifname, sizeof(ifname), "%s", nvram_safe_get(strcat_safe(fh_ap_prefix, "_ifname")));
			snprintf(mac, sizeof(mac), "%s", nvram_safe_get(strcat_safe(fh_ap_prefix, "_hwaddr")));
			include_wds = 0;  // This band is for user's client, so no wds interface needed.
		} else
#endif
		{
			snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s", DIAG_EVENT_WIFISYS2, node_str(), lan_ipaddr, lan_hwaddr, get_node_band_by_unit(wifi_unit, band, sizeof(band)));
			if (!is_cap()) {
				if (diag_get_sub_if_bss_enabled(wifi_unit, 1) && get_sub_if_name(wifi_unit, 1, ifname, sizeof(ifname)))
					snprintf(mac_nvram, sizeof(mac_nvram), "wl%d.1_hwaddr", wifi_unit);
				else
					continue;
			} else {
				snprintf(mac_nvram, sizeof(mac_nvram), "wl%d_hwaddr", wifi_unit);
			}
			snprintf(mac, sizeof(mac), "%s", nvram_safe_get(mac_nvram));
		}
		get_wifi_noise(ifname, noise, sizeof(noise));
		get_wifi_mcs(ifname, mcs, sizeof(mcs));

		len = strlen(data);
		ptr = data+len;
		snprintf(ptr, sizeof(data)-len, ">%s>%s>%s>%s", ifname, (*mac)?mac:"-1", noise, mcs);

#ifdef RTCONFIG_BCMARM
		get_bss_info(ifname, &capability);
		get_subif_count(ifname, &subif_count);
		get_subif_ssid(ifname, subif_ssid, sizeof(subif_ssid));

		len = strlen(data);
		ptr = data+len;
		snprintf(ptr, sizeof(data)-len, ">0x%x>%d>%s", capability, subif_count, subif_ssid);

		char chanim[ACS_CHANIM_BUF_LEN];

		get_wifi_chanim(ifname, chanim, sizeof(chanim));

		len = strlen(data);
		ptr = data+len;
		snprintf(ptr, sizeof(data)-len, ">%s", chanim);
#else
		len = strlen(data);
		ptr = data+len;
		snprintf(ptr, sizeof(data)-len, ">-1>-1>-1>-1");
#endif

		//tx_rate/rx_rate/tx_byte/rx_byte
		len = strlen(data);
		ptr = data+len;
		memset(&if_stats, 0, sizeof(if_stats));
		if (!get_wifi_fh_stats(wifi_unit, include_wds, NULL, &if_stats)) {
			snprintf(ptr, sizeof(data)-len, ">-1>-1>%s>%s", 
				print_llu_buf(if_stats.tx_byte, buf_tx, sizeof(buf_tx)),
				print_llu_buf(if_stats.rx_byte, buf_rx, sizeof(buf_rx)));
		}
		else
			snprintf(ptr, sizeof(data)-len, ">-1>-1>-1>-1");

		++wifi_unit;

		snd_data_to_cap(DIAGMODE_WIFI_DETECT, data);
	}

	get_wifi_client(mode);

	get_wlce_count();

	get_tg_roaming_event();
	get_roaming_event();

#ifdef RTCONFIG_BCMBSD
	get_tg_bsd_event();
#endif

	if(got_tg_roaming || got_roaming){
		kill_pidfile_s("/var/run/roamast.pid", SIGUSR1);
		got_tg_roaming = 0;
		got_roaming = 0;
	}

#ifdef RTCONFIG_BCMBSD
	if(got_tg_bsd){
		kill_pidfile_s("/var/run/bsd.pid", SIGFPE);
		got_tg_bsd = 0;
	}
#endif
}

/*
 *  value: // DIAG_EVENT_ETHSYS>node type>BH or FH>infame>>tx rate>rx rate>tx byte>rx byte
 */
static void diag_eth_detect() {
	char ifname[8], ifnames[64], *next, buf_tx[12], buf_rx[12];
	unsigned long tx_rate = 0, rx_rate = 0;
	unsigned long long tx_byte, rx_byte;
	char data[MAX_DATA];
	_if_stats if_stats;

	if (diag_get_eth_fh_ifnames(ifnames, sizeof(ifnames))) {
		tx_byte = 0;
		rx_byte = 0;
		DIAG_LOG(LOG_DEBUG, "eth_fh ifnames=%s", ifnames);
		foreach(ifname, ifnames, next) {
			memset(&if_stats, 0, sizeof(if_stats));
			if (!get_if_stats(ifname, NULL, &if_stats)) {
				tx_byte += if_stats.tx_byte;
				rx_byte += if_stats.rx_byte;
			}
		}

		snprintf(data, sizeof(data), "<%s>%s>%s>%s>FH>%lu>%lu>%s>%s",
				DIAG_EVENT_ETHINFO, node_str(), lan_ipaddr, lan_hwaddr,
				tx_rate, rx_rate,
				print_llu_buf(tx_byte, buf_rx, sizeof(buf_rx)),
				print_llu_buf(rx_byte, buf_tx, sizeof(buf_tx)));
		snd_data_to_cap(DIAGMODE_ETH_DETECT, data);
	}


	if (diag_get_eth_bh_ifnames(ifnames, sizeof(ifnames))) {
		tx_byte = 0;
		rx_byte = 0;
		DIAG_LOG(LOG_DEBUG, "eth_bh ifnames=%s", ifnames);
		foreach(ifname, ifnames, next) {
			memset(&if_stats, 0, sizeof(if_stats));
			if (!get_if_stats(ifname, NULL, &if_stats)) {
				tx_byte += if_stats.tx_byte;
				rx_byte += if_stats.rx_byte;
			}

#ifdef PLAX56_XP4
			if (!strcmp(ifname, "eth1"))
				get_plc_phy_rate(&tx_rate, &rx_rate);
#endif
		}

		snprintf(data,
		 sizeof(data), "<%s>%s>%s>%s>BH>%lu>%lu>%s>%s",
				DIAG_EVENT_ETHINFO, node_str(), lan_ipaddr, lan_hwaddr,
				tx_rate, rx_rate,
				print_llu_buf(tx_byte, buf_tx, sizeof(buf_tx)),
				print_llu_buf(rx_byte, buf_rx, sizeof(buf_rx)));

		snd_data_to_cap(DIAGMODE_ETH_DETECT, data);
	}
}

/*
 *  #ifdef RTCONFIG_HND_ROUTER
 *  	value: DIAG_EVENT_SYS>node type>IP>MAC>FW version>t-code>AiProtection>USB mode>Runner,FC disable
 *  #else
 *  	value: DIAG_EVENT_SYS>node type>IP>MAC>FW version>t-code>AiProtection>USB mode>CTF disable
 *  #endif
 */
static void get_sys_setting(){
	char cmd[64] = {0}, data[MAX_DATA];
	FILE *fp = NULL;
	char tcode[8];
	int len;
	char acceleration[8];

	snprintf(cmd, sizeof(cmd), "/sbin/ATE Get_TerritoryCode 2>/dev/null");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute ATE.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return;
	}

	memset(tcode, 0, sizeof(tcode));
	fgets(tcode, sizeof(tcode), fp);
	pclose(fp);
	len = strlen(tcode);
	if (len)
		tcode[len-1] = 0;

	get_hw_acceleration(acceleration, sizeof(acceleration));

	snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s.%s_%s>%s>%s>%s>%s", DIAG_EVENT_SYS, node_str(), lan_ipaddr, lan_hwaddr,
			nvram_safe_get("firmver"),
			nvram_safe_get("buildno"),
			nvram_safe_get("extendno"),
			tcode,
			nvram_safe_get("wrs_protect_enable"),
			nvram_safe_get("usb_usb3"),
			acceleration
			);

	DIAG_LOG(LOG_DEBUG, "%s.\n", data);
	snd_data_to_cap(DIAGMODE_SYS_SETTING, data);
}

static int get_sys_memfree(unsigned int *memfree)
{
	char cmd[64] = {0};
	FILE *fp = NULL;

	snprintf(cmd, sizeof(cmd), "/bin/cat /proc/meminfo |/bin/grep MemFree 2>/dev/null");
	if((fp = popen(cmd, "r")) == NULL){
		DIAG_LOG(LOG_DEBUG, "\tCannot execute cat.");
		DIAG_LOG(LOG_DEBUG, "... Failed");

		return -1;
	}

	fscanf(fp, "MemFree: %u %*s", memfree);
	pclose(fp);

	return 0;
}

/*
 *  	value: DIAG_EVENT_SYS2>node type>IP>MAC>CPU freq>MemFree>CPU temperature>2G's temperature>5G's temperature
 */
//#define DETECT_TEMP 1
static void get_sys_detect(){
	char ifname[8], *next;
	char data[MAX_DATA], *ptr;
	int len;
	char clk[16];
	unsigned int memfree = 0;
	int temp_sys = -1, temp_wifi = -1;

	get_sys_clk(clk, sizeof(clk));
	get_sys_memfree(&memfree);
#ifdef DETECT_TEMP
	get_sys_temp(&temp_sys);
#endif

	snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%u>%d", DIAG_EVENT_SYS2, node_str(), lan_ipaddr, lan_hwaddr,
			clk, memfree, temp_sys
			);

	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
#ifdef DETECT_TEMP
		get_wifi_temp(ifname, &temp_wifi);
#endif

		len = strlen(data);
		ptr = data+len;
		snprintf(ptr, sizeof(data)-len, ">%d", temp_wifi);
	}

	snd_data_to_cap(DIAGMODE_SYS_DETECT, data);
}

/*
 *  Return values:
 *   0: Ok
 *  -1: Failed
 *  value: DIAG_EVENT_PORTINFO>node type>IP>MAC>>label name>lan or wan>up or down>link rate>duplex>tx packets>rx packets>tx bytes>rx bytes>crc errors
 */
static int get_port_info(){
	char data[MAX_DATA];
	phy_info_list phy_list = {0};
	int i;

	if (!diag_portinfo)
		return 0;

	GetPhyStatus(0, &phy_list);
	for(i=0;i<phy_list.count;i++) {
		if (!strcmp(phy_list.phy_info[i].state, "up")) {
			snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%s>%s>%d>%s>%u>%u>%" PRIu64 ">%" PRIu64 ">%u", DIAG_EVENT_PORTINFO, node_str(), lan_ipaddr, lan_hwaddr,
					phy_list.phy_info[i].label_name,
					phy_list.phy_info[i].cap_name,
					phy_list.phy_info[i].state,
					phy_list.phy_info[i].link_rate,
					phy_list.phy_info[i].duplex,
					phy_list.phy_info[i].tx_packets,
					phy_list.phy_info[i].rx_packets,
					phy_list.phy_info[i].tx_bytes,
					phy_list.phy_info[i].rx_bytes,
					phy_list.phy_info[i].crc_errors
					);
			snd_data_to_cap(DIAGMODE_PORTINFO, data);
		}
	}

	return 0;
}

static void conn_diag_alarm(int sig){
	alarmed = 1;
}

static void conn_diag_get(){
	char *ptr;

	if(is_cap()){
		diag_mode = nvram_get_int("enable_diag");
		if(diag_mode == DIAGMODE_CHKSTA){
			snprintf(chksta_mac, sizeof(chksta_mac), "%s", nvram_safe_get("chksta_mac"));
			chksta_band = nvram_get_int("chksta_band");
		}

		if((ptr = nvram_get("diag_data_level")) != NULL && *ptr)
			diag_data_level = atoi(ptr);
	}

	diag_log_status();

	snprintf(lan_ipaddr, sizeof(lan_ipaddr), "%s", nvram_safe_get("lan_ipaddr"));
	if(!(*lan_hwaddr))
		snprintf(lan_hwaddr, sizeof(lan_hwaddr), "%s", nvram_safe_get("lan_hwaddr"));
}

static void conn_diag_exit(int sig){
	_close_wlc_event_tbl(-1);

	_close_tg_roaming_tbl(-1);
	_close_roaming_tbl(-1);

#ifdef RTCONFIG_BCMBSD
	_close_tg_bsd_tbl(-1);
#endif

	remove("/var/run/conn_diag.pid");
	exit(0);
}

static void diag_ipc_receive(int sockfd){
	int length = 0;
	char buf[MAX_DATA];
	json_object *rootObj = NULL;
	json_object *cfgObj = NULL;
	json_object *eidObj = NULL;
	int EID = 0;
	struct eventHandler *handler = NULL;

	memset(buf, 0, sizeof(buf));
	if ((length = read(sockfd, buf, sizeof(buf))) <= 0) {
		DIAG_LOG(LOG_DEBUG, "ipc read socket error!");
		return;
	}

	DIAG_LOG(LOG_DEBUG, "IPC Receive: %s <<< RCV EVENT >>>", buf);

	rootObj = json_tokener_parse((char *)buf);
	json_object_object_get_ex(rootObj, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_EVENT_ID, &eidObj);

	if(eidObj){
		EID = atoi(json_object_get_string(eidObj));
		for(handler = &CHK_EVENTS[0]; handler->event_id > 0; handler++){
			if (handler->event_id == EID)
				break;
		}

		if(handler == NULL || handler->event_id < 0)
			DIAG_LOG(LOG_DEBUG, "no corresponding function pointer(%d)", EID);
		else{
			DIAG_LOG(LOG_DEBUG, "process event (%d)", EID);
			if (handler->func(buf)) {
				DIAG_LOG(LOG_DEBUG, "fail to process event(%d)", EID);
			}
		}
	}

	json_object_put(rootObj);
}

static int diag_start_ipc_socket(void)
{
#if defined(RTCONFIG_RALINK_MT7621)    
	Set_RAST_CPU();
#endif
	struct sockaddr_un addr;
	int sockfd, newsockfd;

	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		DIAG_LOG(LOG_DEBUG, "ipc create socket error!");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, CONNDIAG_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);

	unlink(CONNDIAG_IPC_SOCKET_PATH);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		DIAG_LOG(LOG_DEBUG, "ipc bind socket error!");
		exit(-1);
	}

	if (listen(sockfd, RAST_IPC_MAX_CONNECTION) == -1) {
		DIAG_LOG(LOG_DEBUG, "ipc listen socket error!");
		exit(-1);
	}

	while (!thread_term) {
		DIAG_LOG(LOG_DEBUG, "ipc accept socket...");
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			DIAG_LOG(LOG_DEBUG, "ipc accept socket error!");
			continue;
		}

		diag_ipc_receive(newsockfd);
		close(newsockfd);
	}

	return 0;
}

void diag_ipc_socket_thread(void){
	pthread_t thread;
	pthread_attr_t attr;

	DIAG_LOG(LOG_DEBUG, "Start ipc socket thread.");

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread, NULL, (void *)&diag_start_ipc_socket, NULL);
	pthread_attr_destroy(&attr);
}

int diag_ipc_send_event(const char *ipc_path, char *data){
	int fd, length;
	int ret = -1;
	struct sockaddr_un addr_un;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DIAG_LOG(LOG_DEBUG, "ipc socket error!");
		goto error;
	}

	memset(&addr_un, 0, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	snprintf(addr_un.sun_path, sizeof(addr_un.sun_path), ipc_path);
	if (connect(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) < 0) {
		DIAG_LOG(LOG_DEBUG, "ipc connect error");
		goto error;
	}

	DIAG_LOG(LOG_DEBUG, "IPC Send: %s  <<< SEND EVENT >>>", data);

	length = write(fd, data, strlen(data));

	if(length < 0) {
		DIAG_LOG(LOG_DEBUG, "[%s:(%d)] ERROR writing:%s.", __func__, __LINE__, strerror(errno));
		goto error;
	}

	ret = 0;

error:
	close(fd);
	return ret;
}

// node number is 0: cap, 1: re1, 2: re2, ...etc.
char *convert_nodenum_to_str(int node, char *str, int len){
	if(node < 0)
		return NULL;

	if(node == 0)
		snprintf(str, len, "cap");
	else
		snprintf(str, len, "re%d", node);

	return str;
}

// return value is 0: cap, 1: re1, 2: re2, ...etc.
int convert_mac_to_node(char *sta_mac){
	int node_order;
	int lock;
	int shm_client_tbl_id;
	P_CM_CLIENT_TABLE p_client_tbl;
	void *shared_client_info = (void *)0;
	char mac_buf[32] = {0};

	lock = file_lock(CFG_FILE_LOCK);
	shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
	if (shm_client_tbl_id == -1){
		DIAG_LOG(LOG_DEBUG, "shmget failed");
		file_unlock(lock);
		return 0;
	}

	shared_client_info = shmat(shm_client_tbl_id, (void *)0, 0);
	if (shared_client_info == (void *)-1){
		DIAG_LOG(LOG_DEBUG, "shmat failed");
		file_unlock(lock);
		return 0;
	}

	p_client_tbl = (P_CM_CLIENT_TABLE)shared_client_info;
	for(node_order = 0; node_order < p_client_tbl->count; node_order++){
		snprintf(mac_buf, sizeof(mac_buf), MACF_UP,
				p_client_tbl->realMacAddr[node_order][0], p_client_tbl->realMacAddr[node_order][1],
				p_client_tbl->realMacAddr[node_order][2], p_client_tbl->realMacAddr[node_order][3],
				p_client_tbl->realMacAddr[node_order][4], p_client_tbl->realMacAddr[node_order][5]);
		if(!strcmp(mac_buf, sta_mac))
			break;

		snprintf(mac_buf, sizeof(mac_buf), MACF_UP,
				p_client_tbl->ap2g[node_order][0], p_client_tbl->ap2g[node_order][1],
				p_client_tbl->ap2g[node_order][2], p_client_tbl->ap2g[node_order][3],
				p_client_tbl->ap2g[node_order][4], p_client_tbl->ap2g[node_order][5]);
		if(!strcmp(mac_buf, sta_mac))
			break;

		snprintf(mac_buf, sizeof(mac_buf), MACF_UP,
				p_client_tbl->ap5g[node_order][0], p_client_tbl->ap5g[node_order][1],
				p_client_tbl->ap5g[node_order][2], p_client_tbl->ap5g[node_order][3],
				p_client_tbl->ap5g[node_order][4], p_client_tbl->ap5g[node_order][5]);
		if(!strcmp(mac_buf, sta_mac))
			break;

		snprintf(mac_buf, sizeof(mac_buf), MACF_UP,
				p_client_tbl->ap5g1[node_order][0], p_client_tbl->ap5g1[node_order][1],
				p_client_tbl->ap5g1[node_order][2], p_client_tbl->ap5g1[node_order][3],
				p_client_tbl->ap5g1[node_order][4], p_client_tbl->ap5g1[node_order][5]);
		if(!strcmp(mac_buf, sta_mac))
			break;
	}
	if(node_order >= p_client_tbl->count)
		node_order = -1;

	shmdt(shared_client_info);
	file_unlock(lock);

	return node_order;
}

#if defined(RTCONFIG_HND_ROUTER_AX)
static void save_data_sta(char *MAC, int gotSTA, char *rssi, char *txrate, char *rxrate, char *txnrate, char *rxnrate)
#else
static void save_data_sta(char *MAC, int gotSTA, char *rssi, char *txrate, char *rxrate)
#endif
{
	char data[MAX_DATA];
	char nvram[32], *ptr = NULL;
	char src_str[8];

#if defined(RTCONFIG_HND_ROUTER_AX)
	if(txnrate && rxnrate)
		snprintf(data, sizeof(data), "<%d>%s>%s (%s)>%s (%s)", gotSTA, rssi, txrate, txnrate, rxrate, rxnrate);
	else
#else
		snprintf(data, sizeof(data), "<%d>%s>%s>%s", gotSTA, rssi, txrate, rxrate);
#endif

	if((ptr = convert_nodenum_to_str(convert_mac_to_node(MAC), src_str, sizeof(src_str))) == NULL){
		DIAG_LOG(LOG_DEBUG, "%s: Can not find which node the MAC(%s) was belong to?", __func__, MAC);
		return;
	}

	snprintf(nvram, sizeof(nvram), "diag_chk_%s", ptr);
	nvram_set(nvram, data);
}

void save_data(int mode, char *field, char *node_MAC, char *raw){
	int count;
	char *ptr, *ptr2;
	char word[MAX_DATA], *next_word = NULL;
	char sta_mac[18], sta_band[4], sta_rssi[8], fname[64];
	char data[MAX_DATA];
	int got_data = 0;
	int enabled = 0;
	char str_src[8], str_dst[8];

	DIAG_LOG(LOG_DEBUG, "%s: %s.", __func__, raw);

	if(mode == (DIAGMODE_CHKSTA|DIAGMODE_STAINFO)
			&& !strcmp(field, DIAG_EVENT_STAINFO)
			){
		count = 0;
		foreach_62(word, raw, next_word){
			// STA's MAC>STA's Band>STA's RSSI>active>STA's Tx>STA's Rx>STA's Tx byte>STA's Rx byte
			if(count == 0) // read STA's MAC.
				snprintf(sta_mac, sizeof(sta_mac), "%s", word);
			else if(count == 1) // read Band.
				snprintf(sta_band, sizeof(sta_band), "%s", word);
			else if(count == 2) // read RSSI.
				snprintf(sta_rssi, sizeof(sta_rssi), "%s", word);
			else if(count == 3){ // read STA's active.
				enabled = atoi(word);
				got_data = 1;
				// STA's RSSI>STA's Tx>STA's Rx>STA's Tx byte>STA's Rx byte
				snprintf(data, sizeof(data), "%s>%s", sta_rssi, (next_word+1));
				CHK_LOG(LOG_DEBUG, "%s: %s %s %d: %s.", __func__, sta_mac, sta_band, enabled, data);
				break;
			}

			++count;
		}
		if(!got_data)
			return;

		ptr = convert_nodenum_to_str(convert_mac_to_node(node_MAC), str_dst, sizeof(str_dst));
		ptr2 = convert_nodenum_to_str(convert_mac_to_node(sta_mac), str_src, sizeof(str_src));
		snprintf(fname, sizeof(fname), "%s/sta_%s_%s_%s",
				LOG_DIR,
				(ptr != NULL)?str_dst:node_MAC,
				(ptr2 != NULL)?str_src:sta_mac,
				sta_band);

		if(enabled)
			f_write_string(fname, data, 0, 0);
		else
			unlink(fname);
	}
	else{
		DIAG_LOG(diag_data_level, "%s", raw);
		if(nvram_get_int("diag_local_data") == 1)
			save_data_in_sql(field, raw);
	}
}

static void classify_data(int isCAP, int mode, char *raw){
	char word[MAX_DATA], *next_word = NULL;
	char word2[MAX_DATA], *next_word2;
	int count;
	char FIELD[16], node_type[4], node_ip[16], node_MAC[18];
	char *data = NULL;
	int got_data = 0;

	DIAG_LOG(LOG_DEBUG, "%s raw:\n%s\n**********", (isCAP)?"CAP":"RE", raw);

	count = 0;
	foreach_60(word2, raw, next_word2){
		foreach_62(word, word2, next_word){
			// FIELD>node type>node IP>node MAC>...
			if(count == 0) // read FIELD.
				snprintf(FIELD, sizeof(FIELD), "%s", word);
			else if(count == 1) // read node type.
				snprintf(node_type, sizeof(node_type), "%s", word);
			else if(count == 2) // read IP.
				snprintf(node_ip, sizeof(node_ip), "%s", word);
			else if(count == 3){ // read MAC.
				snprintf(node_MAC, sizeof(node_MAC), "%s", word);
				got_data = 1;
				data = next_word+1;
			}

			++count;
		}

		if(got_data)
			break;
	}

	if(!got_data)
		return;

	if(mode == (DIAGMODE_CHKSTA|DIAGMODE_STAINFO)
			&& !strcmp(FIELD, DIAG_EVENT_STAINFO)
			)
		save_data(mode, FIELD, node_MAC, data);
	else
		save_data(mode, FIELD, node_MAC, raw);
}

static int snd_chksta_to_re(char *cap_mac, char *sta_mac, int band){
	char json_data[MAX_DATA];
	char _MODE[4];
	char _EID[8];
	char _BAND[2];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	if(!is_cap())
		return 0;

	CHK_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	snprintf(_EID, sizeof(_EID), "%d", EID_CD_STA_CHK_ONE);
	snprintf(_MODE, sizeof(_MODE), "%d", DIAGMODE_CHKSTA);
	snprintf(_BAND, sizeof(_BAND), "%d", band);

	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_MODE, json_object_new_string(_MODE));
	json_object_object_add(param, RAST_AP, json_object_new_string(cap_mac));
	json_object_object_add(param, RAST_STA, json_object_new_string(sta_mac));
	json_object_object_add(param, RAST_BAND, json_object_new_string(_BAND));

	json_object_object_add(root, CHKSTA_PREFIX, param);

	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return diag_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);
}

static int rcv_chksta_from_cap(char *data){
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *cipObj = NULL;
	json_object *capObj = NULL;
	json_object *staObj = NULL;
	json_object *bandObj = NULL;
	char capMAC[18], staMAC[18], band[4];
	json_object *modeObj = NULL;
	char *ptr;
	int mode = 0;

	if(is_cap())
		return -1;

	CHK_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_PEERIP, &cipObj);
	json_object_object_get_ex(cfgObj, RAST_MODE, &modeObj);
	json_object_object_get_ex(cfgObj, RAST_AP, &capObj);
	json_object_object_get_ex(cfgObj, RAST_STA, &staObj);
	json_object_object_get_ex(cfgObj, RAST_BAND, &bandObj);

	if(!(modeObj && *(ptr = (char *)json_object_get_string(modeObj)))){
		CHK_LOG(LOG_DEBUG, "incorrect data format!!");
		json_object_put(root);
		return -1;
	}

	mode = atoi(ptr);
	if(mode != DIAGMODE_CHKSTA){
		if (mode == DIAGMODE_ALL_CHAN_RADAR) {
			//snd_req_to_re(DIAGMODE_ALL_CHAN_RADAR);
			DIAG_SYSLOG("Radar is detected on all channels.");
			return 0;
		}
		json_object_put(root);
		return rcv_req_from_cap(data);
	}
	else if(mode <= DIAGMODE_NONE || mode >= DIAGMODE_MAX){
		CHK_LOG(LOG_DEBUG, "Didn't know the mode %d.", mode);
		json_object_put(root);
		return -1;
	}

	if((cipObj && *(json_object_get_string(cipObj)))
			&& (capObj && *(json_object_get_string(capObj)))
			&& (staObj && *(json_object_get_string(staObj)))
			&& (bandObj && *(json_object_get_string(bandObj)))
			){
		snprintf(cap_ip, sizeof(cap_ip), "%s", json_object_get_string(cipObj));
		snprintf(capMAC, sizeof(capMAC), "%s", json_object_get_string(capObj));
		snprintf(staMAC, sizeof(staMAC), "%s", json_object_get_string(staObj));
		snprintf(band, sizeof(band), "%s", json_object_get_string(bandObj));

		diag_mode = mode;
		snprintf(chksta_mac, sizeof(chksta_mac), "%s", staMAC);
		chksta_band = atoi(band);

		CHK_LOG(LOG_DEBUG, "Enable RE's chksta.");
	}
	else{
		CHK_LOG(LOG_DEBUG, "incorrect data format!!");
	}

	json_object_put(root);

	return 0;
}

#if defined(RTCONFIG_HND_ROUTER_AX)
static int snd_chksta_data_to_cap(int gotSTA, char *ap_mac, int rssi, char *tx_rate, char *rx_rate, char *tx_nrate, char *rx_nrate)
#else
static int snd_chksta_data_to_cap(int gotSTA, char *ap_mac, int rssi, char *tx_rate, char *rx_rate)
#endif
{
	char json_data[MAX_DATA];
	char _EID[8];
	char _MODE[32], _gotSTA[2], _RSSI[8];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	snprintf(_EID, sizeof(_EID), "%d", EID_CD_STA_CHK_ONE_RSP);
	snprintf(_MODE, sizeof(_MODE), "%d", DIAGMODE_CHKSTA);
	snprintf(_gotSTA, sizeof(_gotSTA), "%d", gotSTA);
	snprintf(_RSSI, sizeof(_RSSI), "%d", rssi);

	if(is_cap()){
#if defined(RTCONFIG_HND_ROUTER_AX)
		save_data_sta(ap_mac, gotSTA, _RSSI, tx_rate, rx_rate, tx_nrate, rx_nrate);
#else
		save_data_sta(ap_mac, gotSTA, _RSSI, tx_rate, rx_rate);
#endif
		return 0;
	}

	CHK_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_MODE, json_object_new_string(_MODE));
	json_object_object_add(param, RAST_ENABLE, json_object_new_string(_gotSTA));
	json_object_object_add(param, RAST_PEERIP, json_object_new_string(cap_ip));
	json_object_object_add(param, RAST_AP, json_object_new_string(ap_mac));
	json_object_object_add(param, RAST_RSSI, json_object_new_string(_RSSI));
	json_object_object_add(param, RAST_TXRATE, json_object_new_string(tx_rate));
	json_object_object_add(param, RAST_RXRATE, json_object_new_string(rx_rate));
#if defined(RTCONFIG_HND_ROUTER_AX)
	json_object_object_add(param, RAST_TXNRATE, json_object_new_string(tx_nrate));
	json_object_object_add(param, RAST_RXNRATE, json_object_new_string(rx_nrate));
#endif

	json_object_object_add(root, CHKSTA_PREFIX, param);

	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return diag_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);
}
int radar_syslog_uptime = 0;

static int rcv_all_channel_detect_radar(char *data){

	if(radar_syslog_uptime == 0 || (radar_syslog_uptime - uptime() > 1800) ){
		DIAG_SYSLOG("Radar is detected on all channels.");
		snd_req_to_re(DIAGMODE_ALL_CHAN_RADAR);
		radar_syslog_uptime = uptime();
	}

	return 0;
}

static int rcv_chksta_data_from_re(char *data){
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *modeObj = NULL;
	json_object *gotSTAObj = NULL;
	json_object *ripObj = NULL;
	json_object *reObj = NULL;
	json_object *rssiObj = NULL;
	json_object *txrateObj = NULL;
	json_object *rxrateObj = NULL;
	char txrate[8];
	char rxrate[8];
#if defined(RTCONFIG_HND_ROUTER_AX)
	json_object *txnrateObj = NULL;
	json_object *rxnrateObj = NULL;
	char txnrate[8];
	char rxnrate[8];
#endif
	char gotSTA[2], rip[16], reMAC[18], rssi[8];
	char buf[MAX_DATA], *ptr;
	int mode = 0;

	if(!is_cap())
		return -1;

	CHK_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_MODE, &modeObj);
	json_object_object_get_ex(cfgObj, RAST_ENABLE, &gotSTAObj);
	json_object_object_get_ex(cfgObj, RAST_PEERIP, &ripObj);
	json_object_object_get_ex(cfgObj, RAST_AP, &reObj);
	json_object_object_get_ex(cfgObj, RAST_RSSI, &rssiObj);
	json_object_object_get_ex(cfgObj, RAST_TXRATE, &txrateObj);
	json_object_object_get_ex(cfgObj, RAST_RXRATE, &rxrateObj);
#if defined(RTCONFIG_HND_ROUTER_AX)
	json_object_object_get_ex(cfgObj, RAST_TXNRATE, &txnrateObj);
	json_object_object_get_ex(cfgObj, RAST_RXNRATE, &rxnrateObj);
#endif

	if(!(modeObj && *(ptr = (char *)json_object_get_string(modeObj)))){
		CHK_LOG(LOG_DEBUG, "incorrect data format!!");
		json_object_put(root);
		return -1;
	}

	mode = atoi(ptr);
	if(mode != DIAGMODE_CHKSTA){
		json_object_put(root);
		return rcv_data_from_re(data);
	}
	else if(mode <= DIAGMODE_NONE || mode >= DIAGMODE_MAX){
		CHK_LOG(LOG_DEBUG, "Didn't know the mode %d.", mode);
		json_object_put(root);
		return -1;
	}

	if((gotSTAObj && *(json_object_get_string(gotSTAObj)))
			&& (ripObj && *(json_object_get_string(ripObj)))
			&& (reObj && *(json_object_get_string(reObj)))
			&& (rssiObj && *(json_object_get_string(rssiObj)))
			&& (txrateObj && *(json_object_get_string(txrateObj)))
			&& (rxrateObj && *(json_object_get_string(rxrateObj)))
#if 0
#ifdef RTCONFIG_HND_ROUTER
			&& (txnrateObj && *(json_object_get_string(txnrateObj)))
			&& (rxnrateObj && *(json_object_get_string(rxnrateObj)))
#endif
#endif
			){
		snprintf(gotSTA, sizeof(gotSTA), "%s", json_object_get_string(gotSTAObj));
		snprintf(rip, sizeof(rip), "%s", json_object_get_string(ripObj));
		snprintf(reMAC, sizeof(reMAC), "%s", json_object_get_string(reObj));
		snprintf(rssi, sizeof(rssi), "%s", json_object_get_string(rssiObj));
		snprintf(txrate, sizeof(txrate), "%s", json_object_get_string(txrateObj));
		snprintf(rxrate, sizeof(rxrate), "%s", json_object_get_string(rxrateObj));
#if defined(RTCONFIG_HND_ROUTER_AX)
		if((txnrateObj && *(json_object_get_string(txnrateObj)))
				&& (rxnrateObj && *(json_object_get_string(rxnrateObj)))
				){
			snprintf(txnrate, sizeof(txnrate), "%s", json_object_get_string(txnrateObj));
			snprintf(rxnrate, sizeof(rxnrate), "%s", json_object_get_string(rxnrateObj));

			save_data_sta(reMAC, atoi(gotSTA), rssi, txrate, rxrate, txnrate, rxnrate);

			snprintf(buf, sizeof(buf), "Got %s:%s,MAC:%s,RSSI:%s,TX_RATE:%sM(%s),RX_RATE:%sM(%s)",
					(atoi(gotSTA))?"AP":"from",
					rip,
					reMAC,
					rssi,
					txrate,
					txnrate,
					rxrate,
					rxnrate
					);
		}
		else
#endif
		{
#if defined(RTCONFIG_HND_ROUTER_AX)
			save_data_sta(reMAC, atoi(gotSTA), rssi, txrate, rxrate, NULL, NULL);
#else
			save_data_sta(reMAC, atoi(gotSTA), rssi, txrate, rxrate);
#endif

			snprintf(buf, sizeof(buf), "Got %s:%s,MAC:%s,RSSI:%s,TX_RATE:%sM,RX_RATE:%sM",
					(atoi(gotSTA))?"AP":"from",
					rip,
					reMAC,
					rssi,
					txrate,
					rxrate
					);
		}

		CHK_DATA("%s\n", buf);
	}
	else
		CHK_LOG(LOG_DEBUG, "incorrect data format!!");

	json_object_put(root);

	return 0;
}

static int snd_req_to_re(int mode){
	char json_data[MAX_DATA];
	char _EID[8];
	char _MODE[32];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	if(!is_cap())
		return 0;

	DIAG_LOG(LOG_DEBUG, ".......... %s: %d ..........", __func__, mode);

	snprintf(_EID, sizeof(_EID), "%d", EID_CD_STA_CHK_ONE);
	snprintf(_MODE, sizeof(_MODE), "%d", mode);

	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_MODE, json_object_new_string(_MODE));

	json_object_object_add(root, CHKSTA_PREFIX, param);

	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return diag_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);
}

static int rcv_req_from_cap(char *data){
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *cipObj = NULL;
	json_object *modeObj = NULL;
	char _MODE[32];

	if(is_cap())
		return -1;

	DIAG_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_PEERIP, &cipObj);
	json_object_object_get_ex(cfgObj, RAST_MODE, &modeObj);

	if((cipObj && *(json_object_get_string(cipObj)))
			&& (modeObj && *(json_object_get_string(modeObj)))
			){
		snprintf(cap_ip, sizeof(cap_ip), "%s", json_object_get_string(cipObj));
		snprintf(_MODE, sizeof(_MODE), "%s", json_object_get_string(modeObj));

		diag_mode = atoi(_MODE);
		conn_diag_get();

		DIAG_LOG(LOG_DEBUG, "Diagnostic(%d) was %s.", diag_mode, (diag_mode > DIAGMODE_CHKSTA)?"Enabled":"Disabled");
	}
	else
		DIAG_LOG(LOG_DEBUG, "incorrect data format!!");

	json_object_put(root);

	return 0;
}

// from the test, the data size cannot be bigger than 128.
static int snd_data_to_cap(int mode, char *snd_data){
	char json_data[MAX_DATA];
	char _EID[8];
	char _MODE[32];
	struct json_object *root = NULL;
	struct json_object *param = NULL;

	snprintf(_EID, sizeof(_EID), "%d", EID_CD_STA_CHK_ONE_RSP);
	snprintf(_MODE, sizeof(_MODE), "%d", mode);

	if(is_cap()){
		DIAG_LOG(LOG_DEBUG, "%s: %s.", __func__, snd_data);
		classify_data(1, mode, snd_data);
		return 0;
	}

	DIAG_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	root = json_object_new_object();
	param = json_object_new_object();
	json_object_object_add(param, RAST_EVENT_ID, json_object_new_string(_EID));
	json_object_object_add(param, RAST_MODE, json_object_new_string(_MODE));
	json_object_object_add(param, RAST_PEERIP, json_object_new_string(cap_ip));
	json_object_object_add(param, RAST_DATA, json_object_new_string(snd_data));

	json_object_object_add(root, CHKSTA_PREFIX, param);

	snprintf(json_data, sizeof(json_data), "%s", json_object_to_json_string(root));
	json_object_put(root);

	return diag_ipc_send_event(CFGMNT_IPC_SOCKET_PATH, &json_data[0]);
}

static int rcv_data_from_re(char *rcv_data){
	json_object *root = NULL;
	json_object *cfgObj = NULL;
	json_object *modeObj = NULL;
	json_object *ripObj = NULL;
	json_object *dataObj = NULL;
	char _MODE[32];
	char rip[16];
	char raw[MAX_DATA];

	if(!is_cap())
		return -1;

	DIAG_LOG(LOG_DEBUG, ".......... %s ..........", __func__);

	root = json_tokener_parse((char *)rcv_data);
	json_object_object_get_ex(root, CFG_PREFIX, &cfgObj);
	json_object_object_get_ex(cfgObj, RAST_MODE, &modeObj);
	json_object_object_get_ex(cfgObj, RAST_PEERIP, &ripObj);
	json_object_object_get_ex(cfgObj, RAST_DATA, &dataObj);

	if(!(modeObj && *(json_object_get_string(modeObj)))
			|| !(ripObj && *(json_object_get_string(ripObj)))){
		DIAG_LOG(LOG_DEBUG, "incorrect data format!!");
		json_object_put(root);
		return -1;
	}

	snprintf(_MODE, sizeof(_MODE), "%s", json_object_get_string(modeObj));
	snprintf(rip, sizeof(rip), "%s", json_object_get_string(ripObj));
	snprintf(raw, sizeof(raw), "%s", json_object_get_string(dataObj));

	classify_data(0, atoi(_MODE), raw);

	json_object_put(root);
	return 0;
}

char *print_rate_buf(int raw_rate, char *buf, int buf_len){
	if (!buf) return NULL;

	if (raw_rate == -1) memset(buf, 0, buf_len);
	else if ((raw_rate % 1000) == 0)
		snprintf(buf, buf_len, "%d", raw_rate / 1000);
	else
		snprintf(buf, buf_len, "%.1f", (double) raw_rate / 1000);

	return buf;
}

char *print_llu_buf(unsigned long long raw_rate, char *buf, int buf_len){
	if (!buf) return NULL;

	if (raw_rate == -1) memset(buf, 0, buf_len);
	else if ((raw_rate % 1000) == 0)
		snprintf(buf, buf_len, "%llu", raw_rate / 1000);
	else
		snprintf(buf, buf_len, "%.1f", (double) raw_rate / 1000);

	return buf;
}

void chksta(int bssidx, int vifidx){
	rast_sta_info_t *sta = bssinfo[bssidx].assoclist[vifidx];
	int rssi = 0;
	char data[MAX_DATA];
	char buf_tx[8], buf_rx[8];
	struct ether_addr ea_tmp;
	char band[4];

	if(!enable_chksta() || bssidx != chksta_band)
		return;

	if(!vifidx && bssinfo[bssidx].upstream_if)
		return;

	CHK_LOG(LOG_DEBUG, ".......... chksta ..........");

	while(sta){
		char buff[32];

		snprintf(buff, sizeof(buff), MACF_UP, ETHER_TO_MACF(sta->addr));

		if(strcasecmp(buff, chksta_mac) == 0){
#if defined(RTCONFIG_HND_ROUTER_AX)
			snprintf(data, sizeof(data), "AP:%s,MAC:%s,BAND:%s,RSSI:%d,TX_RATE:%sM (%s),RX_RATE:%sM (%s)",
					lan_ipaddr,
					lan_hwaddr,
					get_node_band_by_unit(bssidx, band, sizeof(band)),
					sta->rssi,
					print_rate_buf(sta->tx_rate, buf_tx, sizeof(buf_tx)),
					sta->tx_nrate,
					print_rate_buf(sta->rx_rate, buf_rx, sizeof(buf_rx)),
					sta->rx_nrate
					);
#else
			snprintf(data, sizeof(data), "AP:%s,MAC:%s,BAND:%s,RSSI:%d,TX_RATE:%sM,RX_RATE:%sM",
					lan_ipaddr,
					lan_hwaddr,
					get_node_band_by_unit(bssidx, band, sizeof(band)),
					sta->rssi,
					print_rate_buf(sta->tx_rate, buf_tx, sizeof(buf_tx)),
					print_rate_buf(sta->rx_rate, buf_rx, sizeof(buf_rx))
					);
#endif
			CHK_DATA("%s\n", data);

			CHK_LOG(LOG_DEBUG, "chksta: get the specific station info.");

#if defined(RTCONFIG_HND_ROUTER_AX)
			snd_chksta_data_to_cap(1, lan_hwaddr, sta->rssi, buf_tx, buf_rx, sta->tx_nrate, sta->rx_nrate);
#else
			snd_chksta_data_to_cap(1, lan_hwaddr, sta->rssi, buf_tx, buf_rx);
#endif

			return;
		}

		sta = sta->next;
	}

	if(bssinfo[bssidx].rast_mode == RAST_MODE_LEGACY){
		rssi = rast_stamon_get_rssi(bssidx, rast_ether_atoe(chksta_mac, &ea_tmp));
		CHK_LOG(LOG_DEBUG, "chksta: get the monitor station info.");
	}

	snprintf(data, sizeof(data), "from:%s,MAC:%s,BAND:%s,RSSI:%d",
			lan_ipaddr,
			lan_hwaddr,
			get_node_band_by_unit(bssidx, band, sizeof(band)),
			rssi
			);
	CHK_DATA("%s\n", data);

#if defined(RTCONFIG_HND_ROUTER_AX)
	snd_chksta_data_to_cap(0, lan_hwaddr, rssi, "0", "0", "0", "0");
#else
	snd_chksta_data_to_cap(0, lan_hwaddr, rssi, "0", "0");
#endif

	return;
}

static void print_sta_info(){
	int idx, vidx;
	rast_sta_info_t *sta;
	char buff[32], tx_rate[32], rx_rate[32];
	char band[4];

	sta_watchdog(DIAGMODE_STAINFO);

	for(idx = 0; idx < wlif_count; idx++){
		if(!bssinfo[idx].user_low_rssi) continue;

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++){
			if(vidx > 0){
				if(!bssinfo[idx].bss_enable[vidx])
					continue;
			}

			sta = bssinfo[idx].assoclist[vidx];
			while(sta){
				snprintf(buff, sizeof(buff), MACF_UP, ETHER_TO_MACF(sta->addr));

				_dprintf("%s(%d)(%d) sta [%s]: %lu RSSI %d, Tx rate %s M, Rx rate %s M\n",
						get_node_band_by_unit(idx, band, sizeof(band)),
						idx,
						bssinfo[idx].user_low_rssi,
						buff,
						sta->active,
						sta->rssi,
						print_rate_buf(sta->tx_rate, tx_rate, sizeof(tx_rate)),
						print_rate_buf(sta->rx_rate, rx_rate, sizeof(rx_rate))
						);

				sta = sta->next;
			}
		}
	}
}

void remove_timeout_sta(int mode, int bssidx, int vifidx){
	time_t now = uptime();
	char mac[32], data[MAX_DATA];
	rast_sta_info_t *sta, *prev, *next, *head;
	sta = bssinfo[bssidx].assoclist[vifidx];
	head = NULL;
	prev = NULL;
	int mode2;
	char band[4];

	while(sta){
		if(now-sta->active > diag_interval*2){
			snprintf(mac, sizeof(mac), MACF_UP, ETHER_TO_MACF(sta->addr));
			snprintf(data, sizeof(data), "<%s>%s>%s>%s>%s>%s>%d>%d>%d>%d>%d>%d", DIAG_EVENT_STAINFO, node_str(), lan_ipaddr, lan_hwaddr,
					mac, get_node_band_by_unit(bssidx, band, sizeof(band)), -1, 0, 0, 0, 0, 0);

			if(mode == DIAGMODE_CHKSTA)
				mode2 = DIAGMODE_CHKSTA|DIAGMODE_STAINFO;
			else
				mode2 = mode;
			snd_data_to_cap(mode2, data);

			next = sta->next;
			free(sta);
			sta = next;
			if(prev)
				prev->next = sta;
			continue;
		}

		if(head == NULL)
			head = sta;

		prev = sta;
		sta = sta->next;
	}
	bssinfo[bssidx].assoclist[vifidx] = head;
}

void update_sta_info(int mode, int bssidx, int vifidx){
#if defined(RTCONFIG_RALINK) || defined(RTCONFIG_LANTIQ) || defined(CONFIG_BCMWL5) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_QCA)
	get_stainfo(bssidx, vifidx);
#endif

#if defined(RTCONFIG_BCMARM) || defined(RTCONFIG_BCMWL6)
	rast_retrieve_bs_data(bssidx, vifidx, diag_interval);
#endif
	remove_timeout_sta(mode, bssidx, vifidx);

	chksta(bssidx, vifidx);
}

void init_bssinfo(void){
	char ifname[8], *next;
	int idx = 0, idxList = 0, senslevel=0;
	char prefix[32];
	int legacy_ipc = 0;

	memset(bssinfo, 0, sizeof(struct rast_bss_info));

	foreach(ifname, nvram_safe_get("wl_ifnames"), next){
		snprintf(bssinfo[idx].wlif_name, sizeof(bssinfo[idx].wlif_name), ifname);
		bssinfo[idx].user_low_rssi = 0;
		snprintf(bssinfo[idx].prefix, sizeof(bssinfo[idx].prefix), "%s", "");

		for (idxList = 0; idxList < MAX_SUBIF_NUM; idxList++) {
			bssinfo[idx].assoclist[idxList] = NULL;
			if (!idxList) {
				snprintf(prefix, sizeof(prefix), "wl%d_", idx);

				strncpy(bssinfo[idx].prefix, prefix, sizeof(bssinfo[idx].prefix));

				bssinfo[idx].rast_mode = atoi(nvram_safe_get(strcat_safe(prefix, "rast_mode")));
				if(bssinfo[idx].rast_mode != RAST_MODE_RSSI && bssinfo[idx].rast_mode != RAST_MODE_LEGACY)
					bssinfo[idx].rast_mode = RAST_MODE_RSSI;
				bssinfo[idx].static_client = NULL;
				snprintf(bssinfo[idx].tmp_static_client_path, sizeof(bssinfo[idx].tmp_static_client_path),
						"/tmp/cd_stc_idx%d", idx);

				if(bssinfo[idx].rast_mode == RAST_MODE_LEGACY)
					legacy_ipc = 1;
			}
			else
				snprintf(prefix, sizeof(prefix), "wl%d.%d_", idx, idxList);

			bssinfo[idx].bss_enable[idxList] = nvram_get_int(strcat_safe(prefix, "bss_enabled"));
		}

#if defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_LANTIQ)
		if (idx >= MAX_NR_WL_IF)
			break;

		SKIP_ABSENT_BAND_AND_INC_UNIT(idx);

#if defined(RTCONFIG_REALTEK)
		if (repeater_mode() && nvram_get_int("wlc_express") != 0) {
			if (nvram_get_int("wlc_express") -1 == idx) // wlc interface
				bssinfo[idx].user_low_rssi = 0;
			else
				bssinfo[idx].user_low_rssi = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "user_rssi"));
		}
		else
#endif
			bssinfo[idx].user_low_rssi = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "user_rssi"));

#else
		int ret, unit;

		ret = wl_ioctl(bssinfo[idx].wlif_name, WLC_GET_INSTANCE, &unit, sizeof(unit));
		if(ret < 0)
			DIAG_LOG(LOG_DEBUG, "[WARNING] get instance %s error!!!", bssinfo[idx].wlif_name);
		else{
			snprintf(bssinfo[idx].prefix, sizeof(bssinfo[idx].prefix), "wl%d_", unit);
			bssinfo[idx].user_low_rssi = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "user_rssi"));
		}
#endif

		bssinfo[idx].band = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "nband"));
		senslevel = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "rast_sens_level"));
		if(senslevel == 2) {
			bssinfo[idx].rssi_cnt = RAST_COUNT_RSSI_SENSITIVE;
			bssinfo[idx].idle_period = RAST_PERIOD_IDLE_SENSITIVE;
			bssinfo[idx].idle_rate = RAST_DFT_IDLE_RATE_SENSITIVE;
		}
		else if(senslevel == 1) {
			bssinfo[idx].rssi_cnt = RAST_COUNT_RSSI_NORMAL;
			bssinfo[idx].idle_period = RAST_PERIOD_IDLE_NORMAL;
			bssinfo[idx].idle_rate = RAST_DFT_IDLE_RATE_NORMAL;
		}
		else {
			bssinfo[idx].rssi_cnt = RAST_COUNT_RSSI_LAZY;
			bssinfo[idx].idle_period = RAST_PERIOD_IDLE_LAZY;
			bssinfo[idx].idle_rate = RAST_DFT_IDLE_RATE_LAZY;
		}

		if (nvram_get_int("sw_mode") == SW_MODE_REPEATER && idx == nvram_get_int("wlc_band")
#if defined (RTCONFIG_REALTEK) && defined(RTCONFIG_CONCURRENTREPEATER)
				/* Realtek wlc interfaces are different from wl_ifnames in repeater mode. So skip to set upstream_if is 1. */
				&& nvram_get_int("wlc_express") != 0
#endif
				)
			bssinfo[idx].upstream_if = 1;
#if defined(RTCONFIG_BCMWL6) && defined(RTCONFIG_PROXYSTA)
		else if (/*is_psta(idx) || */is_psr(idx))
			bssinfo[idx].upstream_if = 1;
#endif
		else
			bssinfo[idx].upstream_if = 0;

		//for debug purpose
		if(nvram_get_int(strcat_safe(bssinfo[idx].prefix, "idle_rate")) > 0)
			bssinfo[idx].idle_rate = nvram_get_int(strcat_safe(bssinfo[idx].prefix, "idle_rate"));

		DIAG_LOG(LOG_DEBUG, "[bss info]: WIF[%s], idx[%d]", bssinfo[idx].wlif_name, idx);
		DIAG_LOG(LOG_DEBUG, "\t\tmode: %s", bssinfo[idx].rast_mode == RAST_MODE_LEGACY ? "LEGACY" : "RSSI");
		DIAG_LOG(LOG_DEBUG, "\t\trssi threshold: [%d]", bssinfo[idx].user_low_rssi);
		DIAG_LOG(LOG_DEBUG, "\t\trssi hit count: [%d]", bssinfo[idx].rssi_cnt);
		//DIAG_LOG(LOG_DEBUG, "\t\tidle period: [%d]", bssinfo[idx].idle_period);
		//DIAG_LOG(LOG_DEBUG, "\t\tidle rate: [%d]", bssinfo[idx].idle_rate);

		idx++;
	}
	wlif_count = idx;

	if(legacy_ipc)
		diag_ipc_socket_thread();

	DIAG_LOG(LOG_DEBUG, "\tTotalWI[%d] \n", wlif_count);
}

static int enable_chksta(){
	if(diag_mode == DIAGMODE_CHKSTA && *chksta_mac)
		return 1;

	return 0;
}

static void sta_watchdog(int mode){
	int idx,vidx;
	char prefix[32];

	if(is_cap() && enable_chksta())
		snd_chksta_to_re(lan_hwaddr, chksta_mac, chksta_band);

#ifndef RTCONFIG_LANTIQ
	if(!nvram_get_int("wlready"))
#else
	if(!nvram_get_int("wave_ready"))
#endif
		return;

	for (idx = 0; idx < wlif_count; idx++) {
		if(!bssinfo[idx].user_low_rssi) continue;

#if defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_LANTIQ)
#if defined(RTCONFIG_REALTEK)
		if (!get_radio(idx, 0)) {
			DIAG_LOG(LOG_DEBUG, "%s radio is disabled!", bssinfo[idx].wlif_name);
			continue;
		}
#endif

		for (vidx = 0; vidx < MAX_SUBIF_NUM; vidx++) {
			if(vidx > 0) {
#ifdef RTCONFIG_WIRELESSREPEATER
				if (sw_mode() == SW_MODE_REPEATER) continue;
#endif
				if( !bssinfo[idx].bss_enable[vidx] ) continue;
			}

			DIAG_LOG(LOG_DEBUG, "[%s]: StaInfo[%s], RssiCriteria[%d]",
					__func__,
					vidx > 0 ? nvram_safe_get(strcat_safe(prefix, "_ifname")) : bssinfo[idx].wlif_name,
					bssinfo[idx].user_low_rssi );
			update_sta_info(mode, idx, vidx);
		}
#else // BCM
		int val;

		wl_ioctl(bssinfo[idx].wlif_name, WLC_GET_RADIO, &val, sizeof(val));
		val &= WL_RADIO_SW_DISABLE | WL_RADIO_HW_DISABLE;
		if(val){
			DIAG_LOG(LOG_DEBUG, "%s radio is disabled!", bssinfo[idx].wlif_name);
			continue;
		}

#ifdef RTCONFIG_WIRELESS_REPEATER
		if((sw_mode() == SW_MODE_REPEATER)
				&& (nvram_get_int("wlc_band")) == idx){
			DIAG_LOG(LOG_DEBUG, "### Check stainfo [wl%d.%d][rssi criteria = %d] ###",
			idx,
			1,
			bssinfo[idx].user_low_rssi);
			update_sta_info(mode, idx, 1);
			continue;
		}
#endif

		for(vidx = 0; vidx < MAX_SUBIF_NUM; vidx++) {
			//if(diag_mode == DIAGMODE_CHKSTA && vidx == 0 && bssinfo[idx].upstream_if)
			//	continue;

			if (vidx > 0) {
				snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);
				if(!bssinfo[idx].bss_enable[vidx])
					continue;
			}

			DIAG_LOG(LOG_DEBUG, "### Check stainfo [%s][rssi criteria = %d] ###",
				vidx > 0 ? prefix : bssinfo[idx].wlif_name,
				bssinfo[idx].user_low_rssi);

			update_sta_info(mode, idx, vidx);
		}
#endif
	}
}

static void conn_diag_detect(int mode){
	if(is_cap())
		snd_req_to_re(mode);

	switch(mode){
		case DIAGMODE_CHKSTA:
			get_wifi_client(DIAGMODE_CHKSTA|DIAGMODE_STAINFO);
			break;
		case DIAGMODE_SYS_DETECT:
			if(!once_det){
				get_sys_setting();
				diag_wifi_sys_setting();

				once_det = 1;
			}
			get_sys_detect();
			diag_wifi_detect(DIAGMODE_STAINFO);
			diag_wan_detect();
			diag_eth_detect();
			get_port_info();
			break;
		case DIAGMODE_SYS_SETTING:
			get_sys_setting();
			break;
		case DIAGMODE_WIFI_DETECT:
			diag_wifi_detect(DIAGMODE_STAINFO);
			break;
		case DIAGMODE_WIFI_SETTING:
			diag_wifi_sys_setting();
			break;
		case DIAGMODE_STAINFO:
			get_wifi_client(DIAGMODE_STAINFO);

			get_wlce_count();

			get_tg_roaming_event();
			get_roaming_event();

#ifdef RTCONFIG_BCMBSD
			get_tg_bsd_event();
#endif

			if(got_tg_roaming || got_roaming){
				kill_pidfile_s("/var/run/roamast.pid", SIGUSR1);
				got_tg_roaming = 0;
				got_roaming = 0;
			}

#ifdef RTCONFIG_BCMBSD
			if(got_tg_bsd){
				kill_pidfile_s("/var/run/bsd.pid", SIGFPE);
				got_tg_bsd = 0;
			}
#endif

			break;
		case DIAGMODE_NET_DETECT:
			diag_wan_detect();
			break;
		case DIAGMODE_ETH_DETECT:
			diag_eth_detect();
			break;
		case DIAGMODE_PORTINFO:
			get_port_info();
			break;
	}
}

static void clean_diag(){
	char *ptr;

	if(is_cap()){
		if(diag_mode == DIAGMODE_CHKSTA)
			nvram_set_int("enable_diag", DIAGMODE_NONE);

		if((ptr = nvram_get("diag_db_path")) != NULL && *ptr && strcmp(ptr, nvram_safe_get("diag_db_path_old")))
			nvram_set("diag_db_path_old", nvram_safe_get("diag_db_path"));
		nvram_set("diag_db_path", "");
#ifdef RTCONFIG_UPLOADER
		nvram_set("diag_cloud_path", "");
#endif
	}

	diag_mode = DIAGMODE_NONE;
}

void main_detect(int mode){
	DIAG_LOG(LOG_DEBUG, "%s: mode = %d.", __func__, mode);
	sta_watchdog(mode);

	conn_diag_detect(mode);

	clean_diag();
}

int loop_interval(){
	if(!is_cap())
		return 1;

	diag_interval = nvram_get_int("diag_interval");
	if(!diag_interval)
		diag_interval = NORMAL_PERIOD;

	return diag_interval;
}

int conn_diag_main(int argc, char *argv[]){
	FILE *fp;
	char *ptr;

	/* write pid */
	if((fp = fopen("/var/run/conn_diag.pid", "w")) != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	if(!d_exists(SYS_DIR))
		mkdir(SYS_DIR, 0666);
	if(!d_exists(DIAG_DB_DIR))
		mkdir(DIAG_DB_DIR, 0777);

#ifdef RTCONFIG_UPLOADER
	if(!d_exists(DIAG_CLOUD_DIR))
		mkdir(DIAG_CLOUD_DIR, 0777);
	if(!d_exists(DIAG_CLOUD_UPLOAD))
		mkdir(DIAG_CLOUD_UPLOAD, 0777);
	if(!d_exists(DIAG_CLOUD_DOWNLOAD))
		mkdir(DIAG_CLOUD_DOWNLOAD, 0777);
#endif

	diag_interval = nvram_get_int("diag_interval");
	if((ptr = nvram_get("diag_data_level")) != NULL && *ptr)
		diag_data_level = atoi(ptr);
	else
		diag_data_level = LOG_INFO;

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigaddset(&sigs_to_catch, SIGUSR2);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGALRM, conn_diag_alarm);
	signal(SIGUSR2, print_sta_info);
	signal(SIGTERM, conn_diag_exit);
	signal(SIGCHLD, chld_reap);

	alarmed = 0;
	alarm(loop_interval());

	snprintf(lan_ipaddr, sizeof(lan_ipaddr), "%s", nvram_safe_get("lan_ipaddr"));
	snprintf(lan_hwaddr, sizeof(lan_hwaddr), "%s", nvram_safe_get("lan_hwaddr"));
	init_bssinfo();

	/* Most of time it goes to sleep */
	while(1){
		pause();

		if(!alarmed)
			continue;

		if(is_cap())
			conn_diag_get();

		if(!diag_mode){
			alarmed = 0;
			alarm(loop_interval());
			continue;
		}

		main_detect(diag_mode);

		alarmed = 0;
		alarm(loop_interval());
	}

	conn_diag_exit(0);
	return 0;
}
#else
#include <conn_diag-sql.h>
#endif // RTCONFIG_ADV_RAST

void diag_data_usage(){
	fprintf(stdout, "Usage: %s where [timestamp] [where clause]\n", DATA_TAB_NAME);
	fprintf(stdout, "Usage: %s sql [timestamp] [EVENT_NAME] [node_ip]\n", DATA_TAB_NAME);
	fprintf(stdout, "Usage: %s json [timestamp] [EVENT_NAME] [node_mac]\n", DATA_TAB_NAME);
	fprintf(stdout, "Usage: %s json_period [start_timestamp] [end_timestamp] [EVENT_NAME] [node_mac]\n", DATA_TAB_NAME);
	fprintf(stdout, "Usage: %s merge dst_file src_file\n", DATA_TAB_NAME);
	fprintf(stdout, "Usage: %s upload file\n", DATA_TAB_NAME);
	fprintf(stdout, "Usage: %s download download_timestamp\n", DATA_TAB_NAME);
}

int diag_data_main(int argc, char *argv[]){
	int rows = 0;
	int cols = 0;
	char **result = NULL;
	int ret = -1;
	int r = 0, c = 0, i, is_period = 0;
	char event_name[16];
	unsigned long ts = 0, ts2 = 0;
	json_result_t *json_result = NULL, *tmp_result = NULL;

	if(argc <= 1){
		diag_data_usage();
		return 0;
	}

	memset(event_name, 0, sizeof(event_name));

	if(!strcmp(argv[1], "where")){
		if(argc == 2)
			ret = specific_data_on_day(0, NULL, &rows, &cols, &result);
		else if(argc == 3){
			ts = strtoul(argv[2], NULL, 10);

			ret = specific_data_on_day(ts, NULL, &rows, &cols, &result);
		}
		else if(argc == 4){
			ts = strtoul(argv[2], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[3]);

			ret = specific_data_on_day(ts, argv[3], &rows, &cols, &result);
		}
		else
			diag_data_usage();
	}
	else if(!strcmp(argv[1], "sql")){
		if(argc == 2)
			ret = get_sql_on_day(0, NULL, NULL, NULL, &rows, &cols, &result);
		else if(argc == 3){
			ts = strtoul(argv[2], NULL, 10);

			ret = get_sql_on_day(ts, NULL, NULL, NULL, &rows, &cols, &result);
		}
		else if(argc == 4){
			ts = strtoul(argv[2], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[3]);

			ret = get_sql_on_day(ts, argv[3], NULL, NULL, &rows, &cols, &result);
		}
		else if(argc == 5){
			ts = strtoul(argv[2], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[3]);

			ret = get_sql_on_day(ts, argv[3], argv[4], NULL, &rows, &cols, &result);
		}
		else
			diag_data_usage();
	}
	else if(!strcmp(argv[1], "json")){
		if(argc == 2)
			ret = get_json_on_day(0, NULL, NULL, NULL, &rows, &cols, &result);
		else if(argc == 3){
			ts = strtoul(argv[2], NULL, 10);

			ret = get_json_on_day(ts, NULL, NULL, NULL, &rows, &cols, &result);
		}
		else if(argc == 4){
			ts = strtoul(argv[2], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[3]);

			ret = get_json_on_day(ts, argv[3], NULL, NULL, &rows, &cols, &result);
		}
		else if(argc == 5){
			ts = strtoul(argv[2], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[3]);

			ret = get_json_on_day(ts, argv[3], NULL, argv[4], &rows, &cols, &result);
		}
		else
			diag_data_usage();
	}
	else if(!strcmp(argv[1], "json_period")){
		is_period = 1;
		if(argc == 3) {
			ts = strtoul(argv[2], NULL, 10);
			ret = get_json_in_period(ts, 0, NULL, NULL, NULL, &json_result);
		} else if(argc == 4){
			ts = strtoul(argv[2], NULL, 10);
			ts2 = strtoul(argv[3], NULL, 10);

			ret = get_json_in_period(ts, ts2, NULL, NULL, NULL, &json_result);
		}
		else if(argc == 5){
			ts = strtoul(argv[2], NULL, 10);
			ts2 = strtoul(argv[3], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[3]);

			ret = get_json_in_period(ts, ts2, argv[3], NULL, NULL, &json_result);
		}
		else if(argc == 6){
			ts = strtoul(argv[2], NULL, 10);
			ts2 = strtoul(argv[3], NULL, 10);
			snprintf(event_name, sizeof(event_name), "%s", argv[4]);
			printf("argv2=%s, argv3=%s, argv4=%s, argv5=%s\n", argv[2], argv[3], argv[4], argv[5]);

			ret = get_json_in_period(ts, ts2, argv[4], NULL, argv[5], &json_result);
		}
		else
			diag_data_usage();
	}
	else if(argc == 4 && !strcmp(argv[1], "merge")){
		ret = merge_data_in_sql(argv[2], argv[3]);
		return ret;
	}
	else if(argc == 3 && !strcmp(argv[1], "upload")){
		ret = run_upload_file_by_name(argv[2]);
		return ret;
	}
	else if(argc == 3 && !strcmp(argv[1], "download")){
		unsigned long ts = strtoul(argv[2], NULL, 10);

		ret = run_download_file_at_ts(ts, 0);
		return ret;
	}

	if(ret == SQLITE_OK){
		if (is_period) {
			tmp_result = json_result;
			while (tmp_result) {
				printf("ts1=%lu, ts2=%lu, db=%s, row_count=%d, col_count=%d\n", ts, ts2, tmp_result->db_path, tmp_result->row_count, tmp_result->col_count);

				if(!(*event_name))
					snprintf(event_name, sizeof(event_name), "All");

				fprintf(stdout, "**************************************************\n");
				fprintf(stdout, "%s events, rows=%d, cols=%d:\n", event_name, tmp_result->row_count, tmp_result->col_count);
				fprintf(stdout, "**************************************************\n");
				for(i = 0; i < tmp_result->col_count; ++i){
					if(i != 0)
						fprintf(stdout, "|");
					fprintf(stdout, "%s", tmp_result->result[i]);
				}
				fprintf(stdout, "\n");

				for(r = 0; r < tmp_result->row_count; ++r){
					fprintf(stdout, "--------------------------------------------------\n");
					for(c = 0; c < tmp_result->col_count; ++c, ++i){
						if(c != 0)
							fprintf(stdout, "|");
						fprintf(stdout, "%s", tmp_result->result[i]);
					}
					fprintf(stdout, "\n");
				}
				fprintf(stdout, "**************************************************\n");
				tmp_result = tmp_result->next;
			}
			if (json_result) {
				free_json_result(&json_result);
				json_result = NULL;
			}
		} else {
			if(!(*event_name))
				snprintf(event_name, sizeof(event_name), "All");

			fprintf(stdout, "**************************************************\n");
			fprintf(stdout, "%s events, rows=%d, cols=%d:\n", event_name, rows, cols);
			fprintf(stdout, "**************************************************\n");
			for(i = 0; i < cols; ++i){
				if(i != 0)
					fprintf(stdout, "|");
				fprintf(stdout, "%s", result[i]);
			}
			fprintf(stdout, "\n");

			for(r = 0; r < rows; ++r){
				fprintf(stdout, "--------------------------------------------------\n");
				for(c = 0; c < cols; ++c, ++i){
					if(c != 0)
						fprintf(stdout, "|");
					fprintf(stdout, "%s", result[i]);
				}
				fprintf(stdout, "\n");
			}
			fprintf(stdout, "**************************************************\n");
			sqlite3_free_table(result);
		}
	}
	else
		diag_data_usage();

	return 0;
}

int is_6G(int bandidx){
	//char band[8];
	//get_node_band_by_unit(bandidx, band, sizeof(band));
	//if(!strcmp("6G",band))
	//	return 1;

	return 0;
}
