#include <rc.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <shutils.h>
#include <linux/sockios.h>
#ifndef MUSL_LIBC
#include <linux/if_bridge.h>
#endif	// !MUSL_LIBC
#include <stdarg.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#ifdef RTCONFIG_RALINK
#include <ralink.h>
#if defined(RTCONFIG_AMAS_ETHDETECT) && defined(MUSL_LIBC)
#include <linux/if_bridge.h>
#endif
#endif
#ifdef RTCONFIG_QCA
#include <qca.h>
#endif
#ifdef RTCONFIG_REALTEK
#include "../shared/sysdeps/realtek/realtek.h"
#endif
#include <shared.h>

#include <syslog.h>
#include <bcmnvram.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef MUSL_LIBC
#include <math.h>
#endif	// !MUSL_LIBC
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/sysinfo.h>
#ifdef RTCONFIG_USER_LOW_RSSI
#if defined(RTCONFIG_RALINK)
#include <typedefs.h>
#else
#include <wlioctl.h>
#include <wlutils.h>
#endif
#endif

#include "amas.h"
#include <amas-utils.h>
#include <amas_path.h>
#include <amas_ipc.h>
#if defined(RTCONFIG_AMAS_WDS)
#include <amas_ssd.h>
#endif

#ifdef RTCONFIG_CFGSYNC
#include <cfg_event.h>
#endif

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#include <pthread.h>
#ifdef RTCONFIG_DPSTA
#include <dpsta_linux.h>
#endif

#if defined(RTCONFIG_AMAS_WGN)
#include <amas_wgn_shared.h>
#endif

#if defined(RTCONFIG_SOC_IPQ8074)
#define BHCTL_LESS_DBGMSG
#endif

#include <json.h>

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"amas_bhctrl.log"
#ifdef BHCTL_LESS_DBGMSG
#define BH_VDBG(fmt, arg...) \
	do {    \
		if (bhctl_dbg == 1) \
			dbG("BHC %lu: "fmt, uptime(), ##arg); \
		if (nvram_match("bhctl_syslog", "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
        } while (0)
#define BH_DBG(fmt, arg...) \
	do {    \
		if (bhctl_dbg == 1 || bhctl_dbg == 2) \
			dbG("BHC %lu: "fmt, uptime(), ##arg); \
		if (nvram_match("bhctl_syslog", "1") || nvram_match("bhctl_syslog", "2")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
        } while (0)
#else
#define BH_DBG(fmt, arg...) \
	do {    \
		if(bhctl_dbg) \
			dbG("BHC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("bhctl_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
        } while (0)
#endif
#else	/* !RTCONFIG_LIBASUSLOG */
#ifdef BHCTL_LESS_DBGMSG
#define BH_VDBG(fmt, arg...) \
        do {    \
		if (bhctl_dbg == 1) \
			dbG("BHC %lu: "fmt, uptime(), ##arg); \
		if (nvram_match("bhctl_syslog", "1")) \
			logmessage("BHC", fmt, ##arg); \
        } while (0)
#define BH_DBG(fmt, arg...) \
        do {    \
		if (bhctl_dbg == 1 || bhctl_dbg == 2) \
			dbG("BHC %lu: "fmt, uptime(), ##arg); \
		if (nvram_match("bhctl_syslog", "1") || nvram_match("bhctl_syslog", "2")) \
			logmessage("BHC", fmt, ##arg); \
        } while (0)
#else
#define BH_DBG(fmt, arg...) \
        do {    \
               if(bhctl_dbg) \
                dbG("BHC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("bhctl_syslog"), "1")) \
                logmessage("BHC", fmt, ##arg); \
        } while (0)
#endif
#endif	/* RTCONFIG_LIBASUSLOG */

#if !defined(BHCTL_LESS_DBGMSG)
#define BH_VDBG BH_DBG
#endif

#if defined(RTCONFIG_PTHSAFE_POPEN)
#define	popen	PS_popen
#define	pclose	PS_pclose
#endif

int bhctl_dbg = 0;
int Is_dpsta = 0;
int self_opt_timer = 0;
int last_defif = -1;
int trigger_all_connect = 0;
int wait_wifi = 0;
int wait_band = 0;
int plc_wait_wifi = 0;
int plc_support = 0;
int bhctrl_init_keep_waitting_wifi = 0;
int amas_bhctl_timer = 0;
int amas_check_no_loop_time = 0;
int amas_set_rssi_score_ret = AMAS_RESULT_SUCCESS;
int amas_set_cost_ret = AMAS_RESULT_SUCCESS;
unsigned int rand_seed;
wl_br_status *wlbrs_list = NULL;
eth_br_status *ethbrs_list  = NULL;
ifi_priority *ava_upifi_list = NULL;
#if defined(BHCTL_LESS_DBGMSG)
wl_br_status *old_wlbrs_list = NULL;
eth_br_status *old_ethbrs_list  = NULL;
ifi_priority *old_ava_upifi_list = NULL;
#endif

static void reset_plc_wait_wifi(void);

char cap_addr[18] = {};

enum {
    WIFI_STAGE_ALL_KEEP_BAND_CONNECTED = 0,
    WIFI_STAGE_STOP_KEEP_TRY_CONNECTING = 1,
    WIFI_STAGE_KEEP_TRY_CONNECTING = 2,
    WIFI_STAGE_FOLLOW_CONNECTING = 3,
};

enum { INFTYPE_ETH = 0,
       INFTYPE_WIFI = 1 };

int ioctl_for_bridge(int action, char *br, char *brif)
{
    int ret = -1, err = 0;
    int fd = 0;
    unsigned request;
    struct ifreq ifr;

    if(br == NULL){
        BH_DBG("[%s:%s] Unknow lan_ifname, can't add interface to bridge.\n", __FILE__, __FUNCTION__);
        return ret;
    }

    memset(&ifr, 0x00, sizeof(struct ifreq));
    strlcpy(ifr.ifr_name, nvram_safe_get("lan_ifname"), IFNAMSIZ);
    ifr.ifr_ifindex = if_nametoindex(brif);

    if (!ifr.ifr_ifindex) {
        BH_DBG("Can't get index for %s", brif);
        return ret;
    }

    if (action == ARG_addif)
            request = SIOCBRADDIF;
    else if(action == ARG_delif)
            request = SIOCBRDELIF;
    else {
        BH_DBG("Only support addif/delif from bridge interface.\n");
        return ret;
    }

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return ret;

    if ((ret = ioctl(fd, request, &ifr)) < 0)
        err = errno;
    BH_DBG("bridge ioctl ret = %d.\n", ret);
    close(fd);

    if (ret < 0 && ((action == ARG_addif && err == EBUSY) || (action == ARG_delif && err == EINVAL)))
        ret = 0;

    if (ret < 0) {
        BH_DBG("bridge ioct err: %s\n", strerror(err));
        return ret;
    }
    BH_DBG("%s interface(%s) %s bridge successfully.\n",
	(action==2)? "Add" : "Del", "action",  brif, (action==2)? "to" : "from");
    return ret;
}

/**
 * @brief Generate rand seed for rand_r()
 *
 */
static void init_rand_seed() {
    char lan_hwaddr[] = "00:00:00:00:00:00", machaddr[] = "00:00:00:00:00:00";
    int i, j = 0;

    strlcpy(lan_hwaddr, get_lan_hwaddr(), sizeof(lan_hwaddr));

    if (strlen(lan_hwaddr) == 0) {
        rand_seed = 0;
        return;
    }

    for (i = 0; i < strlen(lan_hwaddr); i++) {
        if (lan_hwaddr[i] != ':') {
            machaddr[j] = lan_hwaddr[i];
            j++;
        }
    }
    machaddr[j] = '\0';
    rand_seed = strtoumax(machaddr, NULL, 16);
}

#ifdef RTCONFIG_AMAS_ETHDETECT
#define MAX_PORTS   1024
/**
 * @brief Get the portno object
 *
 * @param brname Bridge name.
 * @param ifname Interface name in bridge.
 * @return int Port number.
 */
static int get_portno(const char *brname, const char *ifname)
{
    int fd = -1;
    int i;
    int ifindex = if_nametoindex(ifname);
    int ifindices[MAX_PORTS];
    unsigned long args[4] = {BRCTL_GET_PORT_LIST,
                             (unsigned long)ifindices, MAX_PORTS, 0};
    struct ifreq ifr;

    if (ifindex <= 0)
        goto error;

    if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
        goto error;

    memset(ifindices, 0, sizeof(ifindices));
    strncpy(ifr.ifr_name, brname, IFNAMSIZ);
    ifr.ifr_data = (char *)&args;

    if (ioctl(fd, SIOCDEVPRIVATE, &ifr) < 0) {
        BH_DBG("get_portno: get ports of %s failed: %s\n",
               brname, strerror(errno));
        goto error;
    }

    for (i = 0; i < MAX_PORTS; i++) {
        if (ifindices[i] == ifindex) {
            close(fd);
            return i;
        }
    }

    BH_DBG("%s is not in bridge %s\n", ifname, brname);
error:
    if (fd >= 0)
        close(fd);

    return -1;
}

/**
 * @brief Get the mac object
 *
 * @param mactable output mac learning table.
 * @param f mac learing table from bridge info.
 */
static inline void get_mac(struct __fdb_entry *mactable,
                              const struct __fdb_entry *f)
{
    memcpy(mactable->mac_addr, f->mac_addr, 6);
    mactable->port_no = f->port_no;
    mactable->is_local = f->is_local;
}

/**
 * @brief Get the br mactable object
 *
 * @param bridge Bridge name.
 * @param mactable mac learning table result.
 * @param offset offset
 * @param num records counts
 * @return int records counts.
 */
static int get_br_mactable(const char *bridge, struct __fdb_entry *mactable,
                unsigned long offset, int num)
{
    struct __fdb_entry *result = NULL;
    unsigned long args[4] = {BRCTL_GET_FDB_ENTRIES,
                             (unsigned long)result,
                             num, offset};
    struct ifreq ifr;
    int retries = 0, n = -1, i;
    int fd = -1;

    result = (struct __fdb_entry *)malloc(sizeof(struct __fdb_entry) * num);
    if (!result)
        goto error;

    if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
        goto error;

    strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
    ifr.ifr_data = (char *)args;

GET_BR_MACTABLE_RETRY:
    n = ioctl(fd, SIOCDEVPRIVATE, &ifr);

    /* table can change during ioctl processing */
    if (n < 0 && errno == EAGAIN && ++retries < 10)
    {
        sleep(0);
        goto GET_BR_MACTABLE_RETRY;
    }

    for (i = 0; i < n; i++)
        get_mac(mactable+i, result+i);

    close(fd);
error:
    if (result)
	    free(result);
    return n;
}
#endif

void set_channel_sync_status(int unit, int status)
{
    char wl_chsync[] = "wlXXXX_chsync";

    snprintf(wl_chsync, sizeof(wl_chsync), "wl%d_chsync", unit);
    if (nvram_get_int(wl_chsync) != status)
        nvram_set_int(wl_chsync, status);
}

int ava_upifi_list_cmp_sort_priority( const void *a , const void *b )
{
    struct _ifi_priority *c = (ifi_priority *)a;
    struct _ifi_priority *d = (ifi_priority *)b;
    if(c->priority != d->priority) return c->priority - d->priority;
    return 0;
}

int ava_upifi_list_cmp_sort_cost( const void *a , const void *b )
{
    struct _ifi_priority *c = (ifi_priority *)a;
    struct _ifi_priority *d = (ifi_priority *)b;
    if(c->cost != d->cost) return 10*(c->cost - d->cost);
    else return c->priority - d->priority;
    return 0;
}

int ethbrs_list_cmp_sort_priority( const void *a , const void *b )
{
    struct _wl_br_status *c = (wl_br_status *)a;
    struct _wl_br_status *d = (wl_br_status *)b;
    if(c->priority != d->priority) return c->priority - d->priority;
    return 0;
}

int wlbrs_list_cmp_sort_priority( const void *a , const void *b )
{
    struct _wl_br_status *c = (wl_br_status *)a;
    struct _wl_br_status *d = (wl_br_status *)b;
    if(c->priority != d->priority) return c->priority - d->priority;
    return 0;
}

int ava_upifi_list_cmp_sort_rssiscore( const void *a , const void *b )
{
    struct _ifi_priority *c = (ifi_priority *)a;
    struct _ifi_priority *d = (ifi_priority *)b;
    if(c->rssiscore != d->rssiscore) return d->rssiscore - c->rssiscore;
    else return c->priority - d->priority;
    return 0;
}

/**
 * @brief Move isFirst uplink port to top1
 *
 * @param a Be compared val
 * @param b Be compared val
 * @return int > = < result
 */
int ava_upifi_list_cmp_sort_isFirst(const void *a, const void *b) {
    struct _ifi_priority *c = (ifi_priority *)a;
    struct _ifi_priority *d = (ifi_priority *)b;
    if (c->isfirst != d->isfirst)
        return d->isfirst - c->isfirst;
    return 0;
}

void update_rssiscore(int rssiscore)
{
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    if (aimesh_alg != AIMESH_ALG_RSSISCORE)
        return;

    if (!pids("lldpd")) {
        amas_set_rssi_score_ret = AMAS_RESULT_FAILED;
        return;
    }
    amas_set_rssi_score_ret = amas_set_rssi_score(rssiscore);
    if (amas_set_rssi_score_ret == AMAS_RESULT_SUCCESS)
        nvram_set_int("amas_re_rssiscore", rssiscore);

    BH_DBG("lldpd set rssiscore(%d) result(%d)\n", rssiscore, amas_set_rssi_score_ret);
}

/**
 * @brief Update cost to nvram/lldpd/beacon
 *
 * @param cost Cost value
 */
static void update_cost(int cost) {
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    if (aimesh_alg == AIMESH_ALG_COST) {          // Update cost by amas_bhctrl
        if (!nvram_get("cfg_cost") || cost != nvram_get_int("cfg_cost")) {  // update lldpd value
            BH_DBG("Update cfg_cost(%d) -> (%d).\n", nvram_get_int("cfg_cost"), cost);
            nvram_set_int("cfg_cost", cost);
            // update beacon
            send_event_to_cfgmnt(EID_RC_RESTART_WIRELESS);  // update beacon.
        }
    }

    // update lldpd
    if (pids("lldpd"))
        amas_set_cost_ret = amas_set_cost(cost);
    else
        amas_set_cost_ret = AMAS_RESULT_FAILED;
}

/**
 * @brief Delay seconds for send connect request to amas_wlcconnect
 *
 * @param action request type
 */
static void delay_send(char *action)
{
    int delay_s = 0;
    int time_base = nvram_get_int("amas_delay_cmd") ? nvram_get_int("amas_delay_cmd") : 3;  // default is 3s

    if (!nvram_get("cfg_maxlevel") || !nvram_get("cfg_level"))
        return;

    if (!strcmp(action, ACTION_RESTART) || !strcmp(action, ACTION_START))
        delay_s = (nvram_get_int("cfg_maxlevel") - nvram_get_int("cfg_level") + 1) * time_base;

    while (delay_s > 0) {
        BH_DBG("Delay %d seconds for send...\n", delay_s);
        sleep(1);
        delay_s--;
    }
    return;
}

void sned_action_to_amas_wlcconnect(char *action)
{
    pid_t pid = -1, i = 0;
    int status = 0;

    delay_send(action);

    pid = fork();

    if (pid < 0)
    {
        BH_DBG("[%s:%d] Can't fork for sned_action_to_amas_wlcconnect()\n", __FUNCTION__, __LINE__);
        return;
    }
    else if (pid == 0)
    {
        char response_ack[256] = {};
        int ret = 0;
        nvram_set_int("amas_send_action_res", SEND_ACTION_RESET);

        ret = send_msg_to_ipc_socket(AMAS_WLCCONNECT_IPC_SOCKET_PATH, action, response_ack, sizeof(response_ack), 3000);
        if (ret == 0)
        { // Success
            BH_DBG("Send action(%s) to amas_wlcconnect success. Response message: %s\n", action, response_ack);
            nvram_set("amas_send_action", action);
            nvram_set_int("amas_send_action_res", SEND_ACTION_SUCCESS);
            /* sysdeps post sent action */
            post_sent_action();
            exit(0);
        }
        else { // fail
            BH_DBG("Send action(%s) to amas_wlcconnect fail\n", action);
            nvram_set("amas_send_action", "");
            nvram_set_int("amas_send_action_res", SEND_ACTION_FAIL);
            exit(0);
        }
    }
    else
    {
        BH_DBG("Waiting child process to finish, My PID is still %d\n", getpid());
        waitpid(pid, &status, 0);
        i = WEXITSTATUS(status);
        BH_DBG("child's pid =%d . exit status=%d\n", pid, i);

    }

    return;
}

/**
 * @brief Get the keep connection object
 *
 * @param bandindex Band index
 * @param defif Band definition
 * @return int Keep connection mode. Keep(1), Don't need(0).
 */
static int get_keep_connection(int bandindex, int defif) {
    char amas_wlc_keep_conn[] = "amas_wlcXXX_keep_conn";
    char amas_wlc_keep_connecting[] = "amas_wlcXXX_keep_connecting";
    int keep_conn = 0;

    struct keep_conn_rule {
        int defif;
        int keep;
    } rule[] = {{WL2G_U, 0}, {WL5G1_U, 1}, {WL5G2_U, 1}, {WL6G_U, 1}, {0, 0}};

    // Check manual setting
    snprintf(amas_wlc_keep_conn, sizeof(amas_wlc_keep_conn), "amas_wlc%d_keep_conn", bandindex);
    if (nvram_get(amas_wlc_keep_conn)) {
        if (nvram_get_int(amas_wlc_keep_conn) == 1)
            keep_conn = 1;
    } else {  // default setting.
        int i = 0;
        while (rule[i].defif) {
            if (rule[i].defif == defif) {
                keep_conn = rule[i].keep;
                break;
            }
            i++;
        }
    }
    snprintf(amas_wlc_keep_connecting, sizeof(amas_wlc_keep_connecting), "amas_wlc%d_keep_connecting", bandindex);
    nvram_set_int(amas_wlc_keep_connecting, keep_conn);  // for amas_wlcconnect
    return keep_conn;
}

int is_fixed_eth_if(char *ifname)
{
	int ret = 0;
	char fixed_eth_ifnames[32], word[16], *next = NULL;

	strlcpy(fixed_eth_ifnames, nvram_safe_get("fixed_eth_ifnames"), sizeof(fixed_eth_ifnames));

	foreach(word, fixed_eth_ifnames, next) {
		if (strcmp(ifname, word) == 0) { // found
			ret = 1;
			break;
		}
	}

	return ret;
}

void init_eth_status(int SUMeth, int amas_eth_bhmode)
{
    int j = 0;
    char eth[32]={0}, *next = NULL;
    char nvram_buf[32] = {};

    if (SUMeth == 0)
        return;

    foreach(eth, nvram_safe_get("eth_ifnames"), next)
    {
        if (j < MAX_ETH )
        {
            ethbrs_list[j].ethIndex = j;
            snprintf(nvram_buf, sizeof(nvram_buf), "amas_eth%d_defif", j);
            ethbrs_list[j].defif = nvram_get_int(nvram_buf);
            ethbrs_list[j].priority = INIT_CODE;
            snprintf(ethbrs_list[j].ethif, sizeof(ethbrs_list[j].ethif), "%s", eth);
            ethbrs_list[j].state = INIT_CODE;
            ethbrs_list[j].cost = INIT_CODE;
            ethbrs_list[j].role = ROLE_NONE;
            ethbrs_list[j].role_determine_time = 5;
            ethbrs_list[j].dest_eth_role = ROLE_NONE;
            ethbrs_list[j].isfirst = (amas_eth_bhmode & (1 << (8 * (ethbrs_list[j].ethIndex / 4) + (ethbrs_list[j].ethIndex % 4)))) > 0 ? 1 : 0;
            ethbrs_list[j].isFixedWan = is_fixed_eth_if(eth);
            ethbrs_list[j].ethType = ETH_TYPE_100; // default

            //loop detect structure
            ethbrs_list[j].loop_detect.status = ETH_LOOP_DETECT_NONE;
            ethbrs_list[j].loop_detect.loop_detect_count = 0;
            ethbrs_list[j].loop_detect.loop_detect_time = 0;
            ethbrs_list[j].loop_detect.no_find_cap_detect_count = 0;

            ethbrs_list[j].br_status.status = INIT_CODE;
            ethbrs_list[j].br_status.in_br = INIT_CODE;
        }
        else {
            BH_DBG("(%s) ethIndex(%d) exceed the interface limitations. Must be expanded.\n", __FUNCTION__, j);
        }
        j++;
    }
    qsort(ethbrs_list, SUMeth, sizeof(ethbrs_list[0]), ethbrs_list_cmp_sort_priority);

}

void init_wlc_status(int SUMband, int amas_wifi_bhmode)
{
    int j = 0;
    char wif[32]={0}, *next = NULL;
    char nvram_buf[32] = {};

    if (SUMband == 0)
        return;

    foreach(wif, nvram_safe_get("sta_ifnames"), next)
    {
        if (j < MAX_WIFI )
        {
            wlbrs_list[j].bandIndex = j;
            snprintf(nvram_buf, sizeof(nvram_buf), "amas_wlc%d_defif", j);
            wlbrs_list[j].defif = nvram_get_int(nvram_buf);
            snprintf(wlbrs_list[j].wlcif, sizeof(wlbrs_list[j].wlcif), "%s", wif);
            wlbrs_list[j].state =  INIT_CODE;
            wlbrs_list[j].rssi  =  INIT_CODE;
            wlbrs_list[j].optmz_base_rssi  =  0;
            wlbrs_list[j].optmz_match_count  =  0;
            wlbrs_list[j].cost  =  INIT_CODE;
            wlbrs_list[j].use   =  1;
            wlbrs_list[j].isfirst  =  (amas_wifi_bhmode & (1 << (8 * (wlbrs_list[j].bandIndex / 4) + (wlbrs_list[j].bandIndex % 4)))) > 0 ? 1 : 0;
            wlbrs_list[j].role = ROLE_NONE;
            wlbrs_list[j].br_status.status = INIT_CODE;
            wlbrs_list[j].br_status.in_br = INIT_CODE;
            wlbrs_list[j].keep_conn = get_keep_connection(j, wlbrs_list[j].defif);
            snprintf(nvram_buf, sizeof(nvram_buf), "amas_wlc%d_unit", j);
            wlbrs_list[j].unit = nvram_get_int(nvram_buf);
        }
        else {
            BH_DBG("(%s) bandIndex(%d) exceed the interface limitations. Must be expanded.", j);
        }
        j++;
    }
}

#ifdef RTCONFIG_BROOP
/**
 * @brief Get the defif object
 *
 * @param ifname iterface name
 * @return int defif
 */
static int get_defif(char *ifname)
{
    int j, defif = -1;
    char buf[32]={0}, *next = NULL;

    if (ifname == NULL || strlen(ifname) == 0)
        return defif;

    // Wireless
    j = 0;
    foreach(buf, nvram_safe_get("sta_ifnames"), next)
    {
        if (!strcmp(wlbrs_list[j].wlcif, ifname)) { // found
            defif = wlbrs_list[j].defif;
            break;
        }
        j++;
    }
    if (defif >= 0)
        return defif;

    // ETH
    j = 0;
    foreach(buf, nvram_safe_get("eth_ifnames"), next)
    {
        if (!strcmp(ethbrs_list[j].ethif, ifname)) { // found
            defif = ethbrs_list[j].defif;
            break;
        }
        j++;
    }
    if (defif >= 0)
        return defif;

    // DPSTA
    if (Is_dpsta) {
        if (strstr(nvram_safe_get("sta_phy_ifnames"), ifname)) // dpsta
            defif = WL5G1_U; // Just give a wifi defif.
    }
    return defif;
}
#endif

#ifdef RTCONFIG_AMAS_ETHDETECT
/**
 * @brief Update client type.
 *
 * @param index ETH index
 * @return int client type.
 */
static int update_client_type(int index)
{
    if (ethbrs_list[index].state == 0)
        return ETH_CLIENT_TYPE_NONE;

    /* Check client type */
    if (ethbrs_list[index].cost >= -1) {
        if (ethbrs_list[index].client_type != ETH_CLIENT_TYPE_AIMESH_DEVICE)
            update_rssiscore(nvram_get_int("amas_re_rssiscore")); // Do set rssiscore again. for eth interface. if not do this, the eth cost is 100(not set).

        return ETH_CLIENT_TYPE_AIMESH_DEVICE;
    }
#ifdef RTCONFIG_QCA_PLC2
    else if ((nvram_get_int("amas_eth_bhmode") == 0) && (ethbrs_list[index].use == 0) && (ethbrs_list[index].ethType == ETH_TYPE_PLC) && (nvram_get_int("plc_head") > 0)) {

        return ETH_CLIENT_TYPE_AIMESH_DEVICE;
    }
#endif
    else if (ethbrs_list[index].cost < -1 && ethbrs_list[index].client_type == ETH_CLIENT_TYPE_NONE)
        return ETH_CLIENT_TYPE_NORMAL_DEVICE;

    return ethbrs_list[index].client_type; // keep.
}

/**
 * @brief Update detect loop status.
 *
 * @param index ETH index
 * @param role ETH role type
 */
static void update_detect_status(int index, int role)
{
    switch (role)
    {
    case ROLE_LAN_LOOP:
        if (ethbrs_list[index].loop_detect.status != ETH_LOOP_DETECTED)
            ethbrs_list[index].loop_detect.status = ETH_LOOP_DETECTED;
        break;
    case ROLE_NONE:
    case ROLE_NOT_DETERMINED:
    case ROLE_PLC_1ST:
    case ROLE_WAN:
        ethbrs_list[index].loop_detect.status = ETH_LOOP_DETECT_NONE;
        break;
    case ROLE_LAN:
        ethbrs_list[index].loop_detect.status = ETH_LOOP_DETECTING;
        break;
    default:
        ethbrs_list[index].loop_detect.status = ETH_LOOP_DETECT_NONE;
        break;
    }
    ethbrs_list[index].loop_detect.loop_detect_count = 0;
    ethbrs_list[index].loop_detect.loop_detect_time = 0;

    return;
}
#endif

#if defined(RTCONFIG_DPSTA) && defined(RTCONFIG_AMAS_ETHDETECT)
/**
 * @brief Clear DPSTA stalist
 *
 * @param SUMeth Uplink port counts
 * @param direct_flush flush it directly.
 */
static void flush_dpsta_stalist(int SUMeth, int direct_flush)
{
    if (!Is_dpsta)
        return;

    int flush_flag = direct_flush, j;
    static int wan_role_bitmap = 0;
    int wan_role_bitmap_tmp = 0;

    /* Dest port is WAN */
    for(j = 0; j < SUMeth; j++) {
        if (ethbrs_list[j].dest_eth_role == ROLE_WAN)
            wan_role_bitmap_tmp = wan_role_bitmap_tmp | (1 << j);
    }

    if (wan_role_bitmap != wan_role_bitmap_tmp) {
        if (wan_role_bitmap_tmp != 0)
            flush_flag = 1;
        wan_role_bitmap = wan_role_bitmap_tmp;
    }

    if (flush_flag)
        system("echo flush > /proc/dpsta/stalist");
}
#endif

/**
 * @brief update ETH role
 *
 * @param index ETH index.
 * @return int ETH role.
 */
static int update_eth_role(int index)
{
    int role = ROLE_NONE;
#ifdef RTCONFIG_AMAS_ETHDETECT
    if (ethbrs_list[index].client_type == ETH_CLIENT_TYPE_NONE) { // Disconnected
        ethbrs_list[index].loop_detect.status = ETH_LOOP_DETECT_NONE;
        return role;
    }
    if (ethbrs_list[index].isFixedWan == 1) {
        if(!strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname")))
        {
            return ROLE_WAN;
        }
        else
        {
            return ROLE_NONE;
        }
    }

    if (ethbrs_list[index].client_type == ETH_CLIENT_TYPE_AIMESH_DEVICE) { // CAP & RE
        switch (ethbrs_list[index].role) {
            case ROLE_NONE:
                role = ROLE_NOT_DETERMINED;
                if (strcmp(nvram_safe_get("cfg_group"), ""))
                    ethbrs_list[index].role_determine_time = 5;
                else  //  OB processing... Don't not detect time.
                    ethbrs_list[index].role_determine_time = 0;
                break;
            case ROLE_NOT_DETERMINED:
                /* Keep 10s to determine eth role */
                if (ethbrs_list[index].role_determine_time && strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname"))) {
                    ethbrs_list[index].role_determine_time--;
                    role = ethbrs_list[index].role; // keep
                } else {
                    ethbrs_list[index].role_determine_time = 0;
                    if (!strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname"))) {
                        role = ROLE_WAN;
                    }
                    else {
                        if (strlen(nvram_safe_get("amas_ifname")) != 0) { // selected BH
#ifdef RTCONFIG_QCA_PLC2
                            if (ethbrs_list[index].ethType == ETH_TYPE_PLC)
                            {
                                if (nvram_get_int("plc_head") > 0)
                                    role = ROLE_LAN;
                                else if (ethbrs_list[index].isfirst)
                                    role = ROLE_PLC_1ST;
                                else
                                    role = ethbrs_list[index].role; // keep
                            }
                            else
#endif	/* RTCONFIG_QCA_PLC2 */
                            if (ethbrs_list[index].dest_eth_role == ROLE_WAN)
                                role = ROLE_LAN;
                            else if (ethbrs_list[index].dest_eth_role == ROLE_LAN || ethbrs_list[index].dest_eth_role == ROLE_NOT_DETERMINED)
                                role = ROLE_LAN_LOOP;
                            else if (ethbrs_list[index].loop_detect.status == ETH_LOOP_DETECTED)
                                role = ethbrs_list[index].role; // keep
                            else { // PC or lldpd problem AiMesh device
                                role = ROLE_LAN;
                            }
                        } else // Not select BH
                            role = ethbrs_list[index].role; // keep
                    }
                }
                break;
            case ROLE_LAN:
                if (!strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname")))
                    role = ROLE_WAN;
#ifdef RTCONFIG_QCA_PLC2
                else if (ethbrs_list[index].ethType == ETH_TYPE_PLC)
                {
                    if (nvram_get_int("plc_head") > 0)
                        role = ROLE_LAN;
                    else if (ethbrs_list[index].isfirst)
                        role = ROLE_PLC_1ST;
                    else
                        role = ROLE_NOT_DETERMINED; // Re-Check
                }
#endif	/* RTCONFIG_QCA_PLC2 */
                else if (ethbrs_list[index].loop_detect.status == ETH_LOOP_DETECTED) {
                    role = ROLE_LAN_LOOP;
#ifdef RTCONFIG_DPSTA
                    flush_dpsta_stalist(get_eth_count(), 1);
#endif
                }
                else if (ethbrs_list[index].dest_eth_role == ROLE_LAN) {
                    role = ROLE_LAN_LOOP;
#ifdef RTCONFIG_DPSTA
                    flush_dpsta_stalist(get_eth_count(), 1);
#endif
                }
                else
                    role = ethbrs_list[index].role; // keep
                break;
            case ROLE_PLC_1ST:
            case ROLE_LAN_LOOP:
                if (!strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname")))
                    role = ROLE_WAN;
#ifdef RTCONFIG_QCA_PLC2
                else if (ethbrs_list[index].ethType == ETH_TYPE_PLC)
                {
                    if (nvram_get_int("plc_head") > 0)
                        role = ROLE_LAN;
                    else if (ethbrs_list[index].isfirst)
                        role = ROLE_PLC_1ST;
                    else
                        role = ethbrs_list[index].role; // keep
                }
#endif	/* RTCONFIG_QCA_PLC2 */
                else if (ethbrs_list[index].dest_eth_role == ROLE_WAN)
                    role = ROLE_LAN;
                else if (ethbrs_list[index].dest_eth_role == ROLE_NOT_DETERMINED || ethbrs_list[index].dest_eth_role == ROLE_LAN)
                    role = ethbrs_list[index].role; // keep
                else if (ethbrs_list[index].loop_detect.status == ETH_LOOP_DETECTED)
                    role = ethbrs_list[index].role; // keep
                else { // PC or lldpd problem AiMesh device
                    role = ROLE_LAN; //reason = 10;
                }
                break;
            case ROLE_WAN:
                if (strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname")))
                    role = ROLE_NOT_DETERMINED; // Re-Check
                else
                    role = ethbrs_list[index].role; // keep
                break;
            default:
                role = ethbrs_list[index].role; // keep
        }
    }
    else { // PC or lldpd problem AiMesh device
        if (ethbrs_list[index].loop_detect.status == ETH_LOOP_DETECTED) {
            role = ROLE_LAN_LOOP;
#ifdef RTCONFIG_DPSTA
            flush_dpsta_stalist(get_eth_count(), 1);
#endif
        }
        else if (!strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname")))
            role = ROLE_WAN;
#ifdef RTCONFIG_QCA_PLC2
        else if (ethbrs_list[index].ethType == ETH_TYPE_PLC)
        {
            if (ethbrs_list[index].isfirst)
                role = ROLE_PLC_1ST;
            if (nvram_get_int("plc_head") > 0)
                role = ROLE_LAN;
            else
                role = ROLE_NOT_DETERMINED; // Re-Check
        }
#endif
        else
            role = ROLE_LAN;
    }

    //  OB processing...but not use this interface OB, set as NOT_DETERMINED
    if (strcmp(nvram_safe_get("cfg_group"), "") == 0 && role == ROLE_LAN)
    {
        return ROLE_NOT_DETERMINED;
    }

    if (role != ethbrs_list[index].role) // Role changed.
    {
        BH_DBG("%s: ethType(%d) client_type(%d) role(%d --> %d) amas_ifname(%s)\n", ethbrs_list[index].ethif, ethbrs_list[index].ethType, ethbrs_list[index].client_type, ethbrs_list[index].role, role, nvram_get("amas_ifname"));
        update_detect_status(index, role);
    }
#else
    if (strlen(nvram_safe_get("amas_ifname")) != 0) { // selected BH
        if(!strcmp(ethbrs_list[index].ethif, nvram_safe_get("amas_ifname")))
            role = ROLE_WAN;
        else
            role = ROLE_NONE;
    }
    else
        role = ROLE_NONE;
#endif
    return role;
}

#ifdef RTCONFIG_AMAS_ETHDETECT
/**
 * @brief Detect loop
 *
 * @param SUMeth uplink ETH counts.
 */
static void detect_loop(int SUMeth)
{
    int j, i, loop = 0;
    int eth_port_no = 0;
	char *nv = NULL, *nvp = NULL, *b = NULL;
    char *routerProductID = NULL, *routerIPAddress = NULL, *routerRealMacAddress = NULL, *isMaster = NULL;
    struct __fdb_entry *mactable = NULL;
    int offset = 0;
#ifdef RTCONFIG_DPSTA
    FILE *stalist_fp = NULL;
    char cap_addr_lower[18] = {};
#endif
    static int check_not_detect_count = 0;

    // Get CAP MAC
    if (strlen(cap_addr) == 0) {
        nv = nvp = strdup(nvram_safe_get("cfg_device_list"));
        if (nv) {
            while ((b = strsep(&nvp, "<")) != NULL) {
                if (vstrsep(b, ">", &routerProductID, &routerIPAddress, &routerRealMacAddress, &isMaster) != 4)
                    continue;
                if (atoi(isMaster) == 1) { // CAP
                    if (strlen(routerRealMacAddress) != 0)
                        snprintf(cap_addr, sizeof(cap_addr), "%s", routerRealMacAddress);
                    break;
                }
            }
        }
    }

    if (strlen(cap_addr) == 0) { // No CAP MAC info.
        if (strlen(nvram_safe_get("amas_cap_addr")) == 0)
            goto DETECT_LOOP_EXIT;
        else
            snprintf(cap_addr, sizeof(cap_addr), "%s", nvram_safe_get("amas_cap_addr"));
    } else {
        if (strcmp(cap_addr, nvram_safe_get("amas_cap_addr"))) {
            nvram_set("amas_cap_addr", cap_addr);
            nvram_commit();
        }
    }

#ifdef RTCONFIG_DPSTA
    i = 0;
    while (cap_addr[i]) {
        cap_addr_lower[i] = tolower(cap_addr[i]);
        i++;
    }
#endif

    for(j = 0; j < SUMeth; j++)
    {
        loop = 0;
        if (ethbrs_list[j].loop_detect.status == ETH_LOOP_DETECTING) {
            BH_DBG("Detecting Loop(%d)\n", j);
            // Get Port ID
            eth_port_no = get_portno(nvram_safe_get("lan_ifname"), ethbrs_list[j].ethif);
            if (eth_port_no < 0)
                continue;

            // Check is CAP on LAN port mac learning table.
            for(;;) {
                int n;
                mactable = realloc(mactable, (offset + 128) * sizeof(struct __fdb_entry));
                if (!mactable) {
                    BH_DBG("Allocate memory fail.\n");
                    goto DETECT_LOOP_EXIT;
                }

                n = get_br_mactable(nvram_safe_get("lan_ifname"), mactable + offset, offset, 128);
                if (n == 0)
                    break;
                if (n < 0) {
                    BH_DBG("Getting mac learning table fail\n");
                    goto DETECT_LOOP_EXIT;
                }
                offset += n;
            }

            for (i = 0; i < offset; i++) {
                if ((mactable + i)->port_no == eth_port_no) {
                    if (!(mactable + i)->is_local) {
                        char mac[18] = {};
                        snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", (mactable + i)->mac_addr[0], (mactable + i)->mac_addr[1], (mactable + i)->mac_addr[2],
                                 (mactable + i)->mac_addr[3], (mactable + i)->mac_addr[4], (mactable + i)->mac_addr[5]);
                        BH_DBG("Compare CAP MAC(%s), MACTABLE MAC(%s)\n", cap_addr, mac);
                        if (!strcmp(mac, cap_addr))
                            loop = 1;
                    }
                }
            }

#ifdef RTCONFIG_DPSTA
            int dpsta_loop = 0;
            if (Is_dpsta) {
                if (strlen(nvram_safe_get("amas_ifname")) > 0 &&
                    strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname"))) { // DPSTA is backhaul.
                    stalist_fp = popen("cat /proc/dpsta/stalist", "r");
                    if (stalist_fp) {
                        BH_DBG("Compare CAP MAC(%s) and DPSTA stalist \n", cap_addr_lower);
                        char stalist_buf[64] = {};
                        while (fgets(stalist_buf, sizeof(stalist_buf), stalist_fp) != NULL) {
                            if (strstr(stalist_buf, cap_addr_lower)) {
                                dpsta_loop = 1;
                                loop = 1;
                                break;
                            }
                        }
                    }
                }
            }
#endif
            int direct_clean = 0;
            if (ethbrs_list[j].loop_detect.loop_detect_time == 0) { // first detect. clear all mac
                if (loop == 0) {
                    direct_clean = 1;
                }
            }
            if (loop || direct_clean) { // clear all mac learning table in the port.
                for (i = 0; i < offset; i++) {
                    if ((mactable + i)->port_no == eth_port_no) {
                        if (!(mactable + i)->is_local) {
                            char mac[18] = {};
                            snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", (mactable + i)->mac_addr[0], (mactable + i)->mac_addr[1], (mactable + i)->mac_addr[2],
                                    (mactable + i)->mac_addr[3], (mactable + i)->mac_addr[4], (mactable + i)->mac_addr[5]);
                            BH_DBG("Del Ifname(%s) MAC(%s) in Bridge(br0) learning table.\n", ethbrs_list[j].ethif, mac);
                            eval("brctl", "delmacs", nvram_safe_get("lan_ifname"), ethbrs_list[j].ethif, mac);
                        }
                    }
                }
#ifdef RTCONFIG_DPSTA
                if (dpsta_loop || direct_clean)
                    flush_dpsta_stalist(SUMeth, 1);
#endif
                if (direct_clean != 1)
                    ethbrs_list[j].loop_detect.loop_detect_count++;
            }

            ethbrs_list[j].loop_detect.loop_detect_time += amas_bhctl_timer;
            BH_DBG("(%s) Loop Detected. Loop(%d) Count(%d) Time(%d)\n", ethbrs_list[j].ethif, loop, ethbrs_list[j].loop_detect.loop_detect_count, ethbrs_list[j].loop_detect.loop_detect_time);
            if (ethbrs_list[j].loop_detect.loop_detect_count > 5) {
                // Loop detected.
                ethbrs_list[j].loop_detect.status = ETH_LOOP_DETECTED;
            } else if (ethbrs_list[j].loop_detect.loop_detect_time > 180) {
                // Not detected
                ethbrs_list[j].loop_detect.status = ETH_LOOP_NOT_DETECTED;
            }
        } else if (ethbrs_list[j].loop_detect.status == ETH_LOOP_NOT_DETECTED && check_not_detect_count == 0) {
            BH_DBG("Detecting Not Loop port(%d)\n", j);
            // Get Port ID
            eth_port_no = get_portno(nvram_safe_get("lan_ifname"), ethbrs_list[j].ethif);
            if (eth_port_no < 0)
                continue;

            // Check is CAP on LAN port mac learning table.
            for (;;) {
                int n;
                mactable = realloc(mactable, (offset + 128) * sizeof(struct __fdb_entry));
                if (!mactable) {
                    BH_DBG("Allocate memory fail.\n");
                    goto DETECT_LOOP_EXIT;
                }

                n = get_br_mactable(nvram_safe_get("lan_ifname"), mactable + offset, offset, 128);
                if (n == 0)
                    break;
                if (n < 0) {
                    BH_DBG("Getting mac learning table fail\n");
                    goto DETECT_LOOP_EXIT;
                }
                offset += n;
            }

            for (i = 0; i < offset; i++) {
                if ((mactable + i)->port_no == eth_port_no) {
                    if (!(mactable + i)->is_local) {
                        char mac[18] = {};
                        snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", (mactable + i)->mac_addr[0], (mactable + i)->mac_addr[1], (mactable + i)->mac_addr[2],
                                 (mactable + i)->mac_addr[3], (mactable + i)->mac_addr[4], (mactable + i)->mac_addr[5]);
                        BH_DBG("Compare CAP MAC(%s), MACTABLE MAC(%s)\n", cap_addr, mac);
                        if (!strcmp(mac, cap_addr))
                            loop = 1;
                    }
                }
            }

#ifdef RTCONFIG_DPSTA
            int dpsta_loop = 0;
            if (Is_dpsta) {
                if (strlen(nvram_safe_get("amas_ifname")) > 0 &&
                    strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname"))) {  // DPSTA is backhaul.
                    stalist_fp = popen("cat /proc/dpsta/stalist", "r");
                    if (stalist_fp) {
                        BH_DBG("Compare CAP MAC(%s) and DPSTA stalist \n", cap_addr_lower);
                        char stalist_buf[64] = {};
                        while (fgets(stalist_buf, sizeof(stalist_buf), stalist_fp) != NULL) {
                            if (strstr(stalist_buf, cap_addr_lower)) {
                                dpsta_loop = 1;
                                loop = 1;
                                break;
                            }
                        }
                    }
                }
            }
#endif
            if (loop
#ifdef RTCONFIG_DPSTA
                || dpsta_loop
#endif
            ) {
                ethbrs_list[j].loop_detect.status = ETH_LOOP_DETECTING;  //  re-detected.
                ethbrs_list[j].loop_detect.loop_detect_count = 0;
                ethbrs_list[j].loop_detect.loop_detect_time = 0;
            }
        }
    }

DETECT_LOOP_EXIT:
    if (check_not_detect_count <= 0)
        check_not_detect_count = DETECT_NOT_LOOPED_PORT_TIME / amas_bhctl_timer;
    else
        check_not_detect_count--;

    if (mactable)
        free(mactable);
    if (nv)
        free(nv);
#ifdef RTCONFIG_DPSTA
    if (stalist_fp)
        pclose(stalist_fp);
#endif
}
#endif

#if defined(RTCONFIG_AMAS_WGN)
#if defined(WGN_HAVE_VLAN0)
static void wgn_update_bridge(int action, char *br, char *brif) 
{
	int ret = 0;
	
	if (action != ARG_delif && action != ARG_addif)
		return;

	if (br == NULL || brif == NULL)
		return;

	ret = ioctl_for_bridge(action, br, brif);
    if (ret == -1) {
        if (action == ARG_delif)
            BH_DBG("Guest network Delete %s from %s fail.\n", brif, br);
        else
            BH_DBG("Guest network Add %s from %s fail.\n", brif, br);
    }

    return;	
}
#endif

static void wgn_update_bridge_ifname(int action, char *ifname)
{
	char nv[128];
    char br_name[64], *br_next = NULL;
    char if_name[64], *if_next = NULL;

#if defined(WGN_HAVE_VLAN0)
	char vlan0[64];
#endif

	if (action != ARG_delif && action != ARG_addif)
		return;

	if (nvram_get_int("wgn_enabled") == 0)
		return;

	if (ifname == NULL || strlen(ifname) <= 0)
		return;

#if defined(WGN_HAVE_VLAN0)
	memset(vlan0, 0, sizeof(vlan0));
	snprintf(vlan0, sizeof(vlan0), "%s.0", ifname);
    wgn_update_bridge(action, nvram_safe_get("lan_ifname"), vlan0);
#endif

	foreach (br_name, nvram_safe_get("wgn_ifnames"), br_next) {
		memset(nv, 0, sizeof(nv));
		snprintf(nv, sizeof(nv)-1, "wgn_%s_lan_ifnames", br_name);
		foreach (if_name, nvram_safe_get(nv), if_next) {
			if (strncmp(if_name, ifname, strlen(ifname)) == 0) {
				if (action == ARG_delif)
					eval("brctl", "delif", br_name, if_name);
				else
					eval("brctl", "addif", br_name, if_name);
			}
		}
	}

	return;	
}
#endif  // RTCONFIG_AMAS_WGN


#ifndef RTCONFIG_BROOP
/**
 * @brief add/del ifname to bridge.
 *
 * @param infType WIFI or ETH
 * @param index ifname index
 */
static void update_bridge_ifname(int infType, int index)
{
    int action = -1, role, defif;
    int ret = 0;
    char *ifname = NULL;

    if (infType == INFTYPE_ETH) { // ETH
        if ((ifname = ethbrs_list[index].ethif) == NULL) return;
        role = ethbrs_list[index].role;
        defif = ethbrs_list[index].defif;

    } else { // WIFI
#ifdef RTCONFIG_DPSTA
        if (Is_dpsta) {
            if ((ifname = nvram_safe_get("sta_phy_ifnames")) == NULL) return;
        }
        else
#endif
        {
            if ((ifname = wlbrs_list[index].wlcif) == NULL) return;
        }
        role = wlbrs_list[index].role;
        defif = wlbrs_list[index].defif;
    }

    switch(role) {
        case ROLE_NONE:
        case ROLE_NOT_DETERMINED:
        case ROLE_LAN_LOOP:
        case ROLE_PLC_1ST:
            action = ARG_delif;
            break;
        case ROLE_WAN:
        case ROLE_LAN:
            action = ARG_addif;
            break;
        default:
            ; // Don't do anything.
            break;
    }

    if (action == ARG_delif) {
        pre_delif_bridge(defif);
        ret = ioctl_for_bridge(action, nvram_safe_get("lan_ifname"), ifname);
        if (ret != -1)
            post_delif_bridge(defif);
    }
    else if (action == ARG_addif) {
        pre_addif_bridge(defif);
        ret = ioctl_for_bridge(action, nvram_safe_get("lan_ifname"), ifname);
        if (ret != -1)
            post_addif_bridge(defif);
    } else
        return;

    if (ret != -1) {
        if (action == ARG_delif) {
            if (infType == INFTYPE_ETH) {
                ethbrs_list[index].br_status.in_br = 0;
                update_rssiscore(nvram_get_int("amas_re_rssiscore")); // Do set rssiscore again. for eth interface. if not do this, the eth cost is 100(not set).
                update_cost(nvram_get_int("cfg_cost")); // Do set cost again. for eth interface. if not do this, the eth cost is -1(not set).
            }
            else {
                wlbrs_list[index].br_status.in_br = 0;
			}

#if defined(RTCONFIG_AMAS_WGN)
          	wgn_update_bridge_ifname(action, ifname);
#endif // RTCONFIG_AMAS_WGN

            BH_DBG("Delete %s from %s successfully.\n", ifname, nvram_safe_get("lan_ifname"));
        }
        else {
            if (infType == INFTYPE_ETH) {
                ethbrs_list[index].br_status.in_br = 1;
                update_rssiscore(nvram_get_int("amas_re_rssiscore")); // Do set rssiscore again. for eth interface. if not do this, the eth cost is 100(not set).
                update_cost(nvram_get_int("cfg_cost")); // Do set cost again. for eth interface. if not do this, the eth cost is -1(not set).
            }
            else {
                wlbrs_list[index].br_status.in_br = 1;
            }
			
#if defined(RTCONFIG_AMAS_WGN)
          	wgn_update_bridge_ifname(action, ifname);
#endif // RTCONFIG_AMAS_WGN	

            BH_DBG("Add %s from %s successfully.\n", ifname, nvram_safe_get("lan_ifname"));
        }

        if (infType == INFTYPE_ETH)
            ethbrs_list[index].br_status.status = BRIDGE_STATUS_SUCCESS;
        else
            wlbrs_list[index].br_status.status = BRIDGE_STATUS_SUCCESS;
    }
    else {
        if (action == ARG_delif)
            BH_DBG("Delete %s from %s fail.\n", ifname, nvram_safe_get("lan_ifname"));
        else
            BH_DBG("Add %s from %s fail.\n", ifname, nvram_safe_get("lan_ifname"));

        if (infType == 0)
            ethbrs_list[index].br_status.status = BRIDGE_STATUS_FAIL;
        else
            wlbrs_list[index].br_status.status = BRIDGE_STATUS_FAIL;
    }

    return;
}
#endif

int check_eth_ifname_in_br()
{
    int find = 0, i;
    char eth_ifnames[32];

    strlcpy(eth_ifnames, nvram_safe_get("eth_ifnames"), sizeof(eth_ifnames));
    for (i = 0; i < get_eth_count(); i++) {
        if (strstr(eth_ifnames, ethbrs_list[i].ethif)) {
            if (ethbrs_list[i].br_status.in_br == 1) {
                find++;
                BH_DBG("[%s(%d)] find eth_ifname %s in bridge\n", __FUNCTION__, __LINE__, ethbrs_list[i].ethif);
            }
        }
    }

    return find;
}

int do_find_cap_ifname(int infType, int index)
{
    int role, defif __attribute__((unused)), SUMeth, i, ret = 0, find_cap = 0;
    char *ifname = NULL;
    char *br_ifname = strdup(nvram_safe_get("lan_ifname"));
    char *eth_ifnames = strdup(nvram_safe_get("eth_ifnames"));
    char *nv = NULL, *nvp = NULL, *b = NULL, *discovery_if = NULL;
    char *routerProductID = NULL, *routerIPAddress = NULL, *routerRealMacAddress = NULL, *isMaster = NULL;
    char cfg_device_list_name[100] = {0}, buf[1024];
    FILE *find_cap_fp = NULL;

    if (strcmp(nvram_safe_get("cfg_group"), "") == 0) {
        BH_DBG("[%s(%d)] onboarding ...\n", __FUNCTION__, __LINE__);
        goto FIND_CAP_EXIT;
    }

    if (infType == INFTYPE_ETH) { // ETH
        if ((ifname = ethbrs_list[index].ethif) == NULL) return ret;
        role = ethbrs_list[index].role;
        defif = ethbrs_list[index].defif;

    } else { // WIFI
#ifdef RTCONFIG_DPSTA
        if (Is_dpsta) {
            if ((ifname = nvram_safe_get("sta_phy_ifnames")) == NULL) return ret;
        }
        else
#endif
        {
            if ((ifname = wlbrs_list[index].wlcif) == NULL) return ret;
        }
        role = wlbrs_list[index].role;
        defif = wlbrs_list[index].defif;
    }

    BH_DBG("[%s(%d)] ifname=%s\n", __FUNCTION__, __LINE__, ifname);

    nvram_unset("discovery_if");

    switch(role) {
        case ROLE_WAN:
            /* if bh changed, need check the eth_ifnames interface in bridge
               if not in bridge, no need to find cap
            */
            if (check_eth_ifname_in_br() == 0){
                BH_DBG("[%s(%d)] no eth_ifname in br, no need to do find cap\n", __FUNCTION__, __LINE__);
                goto FIND_CAP_EXIT;
            }
            nvram_set("discovery_if", br_ifname);
            break;
        case ROLE_LAN:
            nvram_set("discovery_if", ifname);
            break;
        default:
            goto FIND_CAP_EXIT; // Don't do anything.
            break;
    }
    discovery_if = strdup(nvram_safe_get("discovery_if"));
    strcat_r("cfg_device_list_", discovery_if, cfg_device_list_name);

    if(discovery_if == NULL)
    {
        goto FIND_CAP_EXIT;
    }
    nvram_unset(cfg_device_list_name);

    find_cap_fp = popen("find_cap", "r");

    if (find_cap_fp) {
        memset(buf, 0, sizeof(buf));
        while(fgets(buf, sizeof(buf), find_cap_fp) != NULL) {
            //BH_DBG("%s\n", buf);
        }
    }

    nv = nvp = strdup(nvram_safe_get(cfg_device_list_name));
    if (nv) {
        BH_DBG("[%s(%d)] %s=%s\n", __FUNCTION__, __LINE__, cfg_device_list_name, nv);
        while ((b = strsep(&nvp, "<")) != NULL) {
            if (vstrsep(b, ">", &routerProductID, &routerIPAddress, &routerRealMacAddress, &isMaster) != 4)
                continue;
            if (atoi(isMaster) == 1) { // CAP
                find_cap = 1;
                break;
            }
        }
    }

    if(find_cap == 1)
    {
        ret = 1;
        BH_DBG("find cap from %s\n", discovery_if);
        if (role == ROLE_LAN) {
            ethbrs_list[index].role = ROLE_LAN_LOOP;
            ethbrs_list[index].loop_detect.status = ETH_LOOP_DETECTED;
            ethbrs_list[index].loop_detect.loop_detect_count = 0;
            ethbrs_list[index].loop_detect.loop_detect_time = 0;
        }
        else if (role == ROLE_WAN) {
            SUMeth = get_eth_count();
            if (infType == INFTYPE_WIFI) {
                for (i = 0; i < SUMeth; i++)
                {
                    if (strstr(eth_ifnames, ethbrs_list[i].ethif))
                    {
                        if(SUMeth == 1)
                        {
                            ethbrs_list[i].role = ROLE_LAN_LOOP;
                            ethbrs_list[i].loop_detect.status = ETH_LOOP_DETECTED;
                            ethbrs_list[i].loop_detect.loop_detect_count = 0;
                            ethbrs_list[i].loop_detect.loop_detect_time = 0;
                        }
                        else
                        {
                            ethbrs_list[i].role = ROLE_NOT_DETERMINED;
                        }
                        ethbrs_list[i].br_status.in_br = 0;
                        ioctl_for_bridge(ARG_delif, br_ifname, ethbrs_list[i].ethif);
                    }
                }
            }
            else {
                for (i = 0; i < SUMeth; i++)
                {
                    if (strstr(eth_ifnames, ethbrs_list[i].ethif))
                    {
                        ethbrs_list[i].role = ROLE_NOT_DETERMINED;
                        ethbrs_list[i].br_status.in_br = 0;
                        ioctl_for_bridge(ARG_delif, br_ifname, ethbrs_list[i].ethif);
                    }
                }
            }
        }
    }
    else
    {
        if (role == ROLE_LAN && (ethbrs_list[index].loop_detect.no_find_cap_detect_count < amas_check_no_loop_time)) {
			ethbrs_list[index].loop_detect.no_find_cap_detect_count++;
			ethbrs_list[index].role = ROLE_NOT_DETERMINED;
        }
        BH_DBG("no find cap from %s\n", discovery_if);
    }

FIND_CAP_EXIT:
    if (nv)
        free(nv);
    if (br_ifname)
        free(br_ifname);
    if (eth_ifnames)
        free(eth_ifnames);
    if (discovery_if)
        free(discovery_if);
    if (find_cap_fp)
        pclose(find_cap_fp);

    return ret;
}

#ifndef RTCONFIG_BROOP
/**
 * @brief Process bridge action.
 *
 */
static void bridge_action(void)
{
	static char old_ifaces[10 * IFNAMSIZ + 10 * 4] = { 0 };
	int i;
	char tmp[IFNAMSIZ + 4], ifaces[10 * IFNAMSIZ + 10 * 4] = { 0 };
	eth_br_status *pethbr;
	wl_br_status *pwlbr;

    char *brifname = strdup(nvram_safe_get("lan_ifname"));

    if (brifname == NULL)
        return;

    if (strlen(brifname) == 0) {
        free(brifname);
        return;
    }

    // for log message.
    for (i = 0; i < get_eth_count(); i++) {
		pethbr = &ethbrs_list[i];
		if (pethbr->br_status.in_br) {
			snprintf(tmp, sizeof(tmp), "%s,R%d", pethbr->ethif, pethbr->role);
			if (*ifaces != '\0')
				strlcat(ifaces, " ", sizeof(ifaces));
			strlcat(ifaces, tmp, sizeof(ifaces));
#if defined(BHCTL_LESS_DBGMSG)
			BH_DBG("(%s) BR status(%d) IN_BR(%d,R%d)\n", pethbr->ethif,
				pethbr->br_status.status, pethbr->br_status.in_br, pethbr->role);
#endif
		}
#if !defined(BHCTL_LESS_DBGMSG)
		BH_DBG("(%s) BR status(%d) IN_BR(%d)\n", ethbrs_list[i].ethif, ethbrs_list[i].br_status.status, ethbrs_list[i].br_status.in_br);
#endif
    }
    for (i = 0; i < get_wl_count(); i++) {
		pwlbr = &wlbrs_list[i];
		if (pwlbr->br_status.in_br) {
			snprintf(tmp, sizeof(tmp), "%s,R%d", pwlbr->wlcif, pwlbr->role);
			if (*ifaces != '\0')
				strlcat(ifaces, " ", sizeof(ifaces));
			strlcat(ifaces, tmp, sizeof(ifaces));
#if defined(BHCTL_LESS_DBGMSG)
			BH_DBG("(%s) BR status(%d) IN_BR(%d,R%d)\n", pwlbr->wlcif,
				pwlbr->br_status.status, pwlbr->br_status.in_br, pwlbr->role);
#endif
		}
#if !defined(BHCTL_LESS_DBGMSG)
		BH_DBG("(%s) BR status(%d) IN_BR(%d)\n", wlbrs_list[i].wlcif, wlbrs_list[i].br_status.status, wlbrs_list[i].br_status.in_br);
#endif
    }

    // Remove ETH/PLC
    for (i = 0; i < get_eth_count(); i++) {
        switch (ethbrs_list[i].role)
        {
            case ROLE_NONE:
            case ROLE_LAN_LOOP:
            case ROLE_NOT_DETERMINED:
            case ROLE_PLC_1ST:
                if (ethbrs_list[i].br_status.in_br == 1)
                    ethbrs_list[i].br_status.status = BRIDGE_STATUS_NEED_PROCESS; // remove it.
                if (ethbrs_list[i].br_status.status != BRIDGE_STATUS_SUCCESS)
                    update_bridge_ifname(INFTYPE_ETH, i);
                break;
            default:
                ; // Don't do anything.
                break;
        }
    }

    // Remove WIFI
    for (i = 0; i < get_wl_count(); i++) {
        switch (wlbrs_list[i].role)
        {
            case ROLE_NONE:
            case ROLE_LAN_LOOP:
            case ROLE_NOT_DETERMINED:
                if (wlbrs_list[i].br_status.in_br == 1)
                    wlbrs_list[i].br_status.status = BRIDGE_STATUS_NEED_PROCESS; // remove it.
                if (wlbrs_list[i].br_status.status != BRIDGE_STATUS_SUCCESS)
                    update_bridge_ifname(INFTYPE_WIFI, i);
                break;
            default:
                ; // Don't do anything.
                break;
        }
    }

    // eth_ifnames as lan or bh changed, need check port loop
    for (i = 0; i < get_eth_count(); i++) {
        switch (ethbrs_list[i].role)
        {
            case ROLE_WAN:
            case ROLE_LAN:
                if (ethbrs_list[i].br_status.in_br != 1)
                    do_find_cap_ifname(INFTYPE_ETH, i);
                break;
            default:
                ; // Don't do anything.
                break;
        }
    }

    // Add ETH/PLC
    for (i = 0; i < get_eth_count(); i++) {
        switch (ethbrs_list[i].role)
        {
            case ROLE_WAN:
            case ROLE_LAN:
                if (ethbrs_list[i].br_status.in_br != 1)
                    ethbrs_list[i].br_status.status = BRIDGE_STATUS_NEED_PROCESS; // add it.
                if (ethbrs_list[i].br_status.status != BRIDGE_STATUS_SUCCESS)
                    update_bridge_ifname(INFTYPE_ETH, i);
                break;
            default:
                ; // Don't do anything.
                break;
        }
    }

    // bh changed, need check port loop
    for (i = 0; i < get_wl_count(); i++) {
        switch (wlbrs_list[i].role)
        {
            case ROLE_WAN:
                if (wlbrs_list[i].br_status.in_br != 1)
                    do_find_cap_ifname(INFTYPE_WIFI, i);
                break;
            default:
                ; // Don't do anything.
                break;
        }
    }

    // Add WIFI
    for (i = 0; i < get_wl_count(); i++) {
        switch (wlbrs_list[i].role)
        {
            case ROLE_WAN:
            case ROLE_LAN:
                if (wlbrs_list[i].br_status.in_br != 1)
                    wlbrs_list[i].br_status.status = BRIDGE_STATUS_NEED_PROCESS; // add it.
                if (wlbrs_list[i].br_status.status != BRIDGE_STATUS_SUCCESS)
                    update_bridge_ifname(INFTYPE_WIFI, i);
                break;
            default:
                ; // Don't do anything.
                break;
        }
    }

	if (strcmp(old_ifaces, ifaces)) {
		dbg("BHC: IN_BR %s\n", ifaces);
		logmessage("BHC", "IN_BR %s", ifaces);
		strlcpy(old_ifaces, ifaces, sizeof(old_ifaces));
	}
    free(brifname);
}
#endif

/**
 * @brief Update Ethernet port role & update lldp info.
 */
static void update_eth_role_info()
{
    int i;
    char buf[64] = {}, tmp[16] = {};

    for (i = 0; i < get_eth_count(); i++) {
        if (i != 0)
            strlcat(buf, ">", sizeof(buf));
        snprintf(tmp, sizeof(tmp), "%s:%d", ethbrs_list[i].ethif, ethbrs_list[i].role);
        strlcat(buf, tmp, sizeof(buf));     // eth0:0>eth1:0...
    }
    if (strlen(buf) > 0)
        amas_set_eth_role(buf);
}

void get_eth_info(int SUMeth)
{
    char eth_prefix[16], tmp[100]={0};
    int j = 0;
    int eth_plugin = 0, plc_plugin = 0, plc_is_bh = 0;
    static int pre_plc_is_bh = 0;
    int role_changed = 0;
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    for(j = 0; j < SUMeth; j++)
    {

        snprintf(eth_prefix, sizeof(eth_prefix), "amas_eth%d_",  ethbrs_list[j].ethIndex);
        ethbrs_list[j].priority = nvram_get_int(strcat_r(eth_prefix, "priority", tmp));
        ethbrs_list[j].state = nvram_get_int(strcat_r(eth_prefix, "state", tmp));
        if (aimesh_alg == AIMESH_ALG_COST && nvram_get_int(strcat_r(eth_prefix, "cost", tmp)) >= 0)
            ethbrs_list[j].cost = nvram_get_int(strcat_r(eth_prefix, "cost", tmp)) / 10.0;
        else
            ethbrs_list[j].cost = nvram_get_int(strcat_r(eth_prefix, "cost", tmp));
        ethbrs_list[j].rssiscore  = nvram_get_int(strcat_r(eth_prefix, "rssiscore", tmp));
        ethbrs_list[j].use  = nvram_get_int(strcat_r(eth_prefix, "use", tmp));

        int role = update_eth_role(j);
        if (ethbrs_list[j].role != role) {
            ethbrs_list[j].role = role;
            role_changed = 1;
        }
#ifdef RTCONFIG_AMAS_ETHDETECT
        ethbrs_list[j].client_type = update_client_type(j);
        amas_get_dest_eth_role(ethbrs_list[j].ethif, &(ethbrs_list[j].dest_eth_role));
#endif

        if ((ethbrs_list[j].ethType = nvram_get_int(strcat_r(eth_prefix, "ethType", tmp))) == 0)
            ethbrs_list[j].ethType = ETH_TYPE_100; // default.

        if (ethbrs_list[j].ethType == ETH_TYPE_PLC)
            plc_support = 1;

        if (ethbrs_list[j].state > 0) {
            if (ethbrs_list[j].ethType != ETH_TYPE_PLC) {
                eth_plugin = 1;
            } else {
                plc_plugin = 1;
                if (ethbrs_list[j].role == ROLE_WAN)
                    plc_is_bh = 1;
            }
        } else {
            // reset loop detect structure
            ethbrs_list[j].loop_detect.status = ETH_LOOP_DETECT_NONE;
            ethbrs_list[j].loop_detect.loop_detect_count = 0;
            ethbrs_list[j].loop_detect.loop_detect_time = 0;
            ethbrs_list[j].loop_detect.no_find_cap_detect_count = 0;
        }

        if (role_changed && ethbrs_list[j].br_status.in_br == 1
        && (role == ROLE_NONE || role == ROLE_LAN_LOOP || role == ROLE_NOT_DETERMINED || role == ROLE_PLC_1ST))
        {
            ethbrs_list[j].loop_detect.no_find_cap_detect_count = 0;
        }

#if defined(BHCTL_LESS_DBGMSG)
	old_ethbrs_list[j].loop_detect.loop_detect_time = ethbrs_list[j].loop_detect.loop_detect_time;
	if (memcmp(&old_ethbrs_list[j], &ethbrs_list[j], sizeof(eth_br_status))) {
		BH_DBG("ethbrs_list[%d].defif=%02X use=%d ethIndex=%d priority=%d ethif=%s ethType=%-2d "
			"state=%d cost=%.1f rssiscore=%d isfirst=%d role=%d dest_eth_role=%d "
			"loop_detect (status=%d count=%d time=%d)\n",
			j, ethbrs_list[j].defif, ethbrs_list[j].use, ethbrs_list[j].ethIndex,
			ethbrs_list[j].priority, ethbrs_list[j].ethif, ethbrs_list[j].ethType,
			ethbrs_list[j].state, ethbrs_list[j].cost, ethbrs_list[j].rssiscore,
			ethbrs_list[j].isfirst, ethbrs_list[j].role, ethbrs_list[j].dest_eth_role,
			ethbrs_list[j].loop_detect.status, ethbrs_list[j].loop_detect.loop_detect_count,
			ethbrs_list[j].loop_detect.loop_detect_time);
		memcpy(&old_ethbrs_list[j], &ethbrs_list[j], sizeof(eth_br_status));
	}
#else
        BH_DBG("\n######################################\n"
        "ethbrs_list[%d].defif\t\t\t= %02X\n"
        "ethbrs_list[%d].use\t\t\t= %d\n"
        "ethbrs_list[%d].ethIndex\t\t\t= %d\n"
        "ethbrs_list[%d].priority\t\t\t= %d\n"
        "ethbrs_list[%d].ethif\t\t\t= %s\n"
        "ethbrs_list[%d].ethType\t\t\t= %d\n"
        "ethbrs_list[%d].state\t\t\t= %d\n"
        "ethbrs_list[%d].cost\t\t\t= %.1f\n"
        "ethbrs_list[%d].rssiscore\t\t= %d\n"
        "ethbrs_list[%d].isfirst\t\t\t= %d\n"
        "ethbrs_list[%d].isFixedWan\t\t= %d\n"
        "ethbrs_list[%d].role\t\t\t= %d\n"
        "ethbrs_list[%d].dest_eth_role\t\t\t= %d\n"
        "ethbrs_list[%d].client_type\t\t\t= %d\n"
        "ethbrs_list[%d].loop_detect.status\t\t\t= %d\n"
        "ethbrs_list[%d].loop_detect.loop_detect_count\t\t\t= %d\n"
        "ethbrs_list[%d].loop_detect.loop_detect_time\t\t\t= %d\n"
        "ethbrs_list[%d].loop_detect.no_cap_detect_count\t\t\t= %d\n",

        j, ethbrs_list[j].defif,
        j, ethbrs_list[j].use,
        j, ethbrs_list[j].ethIndex,
        j, ethbrs_list[j].priority,
        j, ethbrs_list[j].ethif,
        j, ethbrs_list[j].ethType,
        j, ethbrs_list[j].state,
        j, ethbrs_list[j].cost,
        j, ethbrs_list[j].rssiscore,
        j, ethbrs_list[j].isfirst,
        j, ethbrs_list[j].isFixedWan,
        j, ethbrs_list[j].role,
        j, ethbrs_list[j].dest_eth_role,
        j, ethbrs_list[j].client_type,
        j, ethbrs_list[j].loop_detect.status,
        j, ethbrs_list[j].loop_detect.loop_detect_count,
        j, ethbrs_list[j].loop_detect.loop_detect_time,
        j, ethbrs_list[j].loop_detect.no_find_cap_detect_count);
#endif
    }
    if (eth_plugin == 0)
        wait_wifi = (nvram_get_int("wait_wifi") < MAX_WIFI_WAIT_TIME ? MAX_WIFI_WAIT_TIME : nvram_get_int("wait_wifi")) / amas_bhctl_timer; // reset wait_wifi

    if (plc_support == 1) {
        if (plc_plugin == 0) {
            reset_plc_wait_wifi();
        } else if (pre_plc_is_bh != plc_is_bh) {
            if (pre_plc_is_bh == 1)
                reset_plc_wait_wifi();
            pre_plc_is_bh = plc_is_bh;
        }
    }

    if (role_changed) update_eth_role_info();

}

void get_wlc_info(int SUMband)
{
    char wlc_prefix[16], tmp[100]={0};
    int j = 0;
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    for (j = 0; j < SUMband; j++)
    {

        snprintf(wlc_prefix, sizeof(wlc_prefix), "amas_wlc%d_", wlbrs_list[j].bandIndex);

        snprintf(wlbrs_list[j].pap_bssid, sizeof(wlbrs_list[j].pap_bssid), "%s", nvram_safe_get(strcat_r(wlc_prefix, "pap", tmp)));
        wlbrs_list[j].band = nvram_get_int(strcat_r(wlc_prefix, "band", tmp));
        wlbrs_list[j].priority = nvram_get_int(strcat_r(wlc_prefix, "priority", tmp));
        wlbrs_list[j].state =  nvram_get_int(strcat_r(wlc_prefix, "state", tmp));
        wlbrs_list[j].rssi  =  nvram_get_int(strcat_r(wlc_prefix, "rssi", tmp));
        if (aimesh_alg == AIMESH_ALG_COST && nvram_get_int(strcat_r(wlc_prefix, "cost", tmp)) >= 0)
            wlbrs_list[j].cost = nvram_get_int(strcat_r(wlc_prefix, "cost", tmp)) / 10.0;
        else
            wlbrs_list[j].cost = nvram_get_int(strcat_r(wlc_prefix, "cost", tmp));
        wlbrs_list[j].rssiscore  =  nvram_get_int(strcat_r(wlc_prefix, "rssiscore", tmp));
        wlbrs_list[j].use   =  nvram_get_int(strcat_r(wlc_prefix, "use", tmp));

#ifdef RTCONFIG_DPSTA
        if (Is_dpsta) {
            if (strlen(nvram_safe_get("amas_ifname")) > 0 && strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname")))
                wlbrs_list[j].role = ROLE_WAN;
            else
                wlbrs_list[j].role = ROLE_NONE;
        }
        else
#endif
        {
            if (!strcmp(nvram_safe_get("amas_ifname"), wlbrs_list[j].wlcif))
                wlbrs_list[j].role = ROLE_WAN;
            else
                wlbrs_list[j].role = ROLE_NONE;
        }

#if defined(BHCTL_LESS_DBGMSG)
	if (memcmp(&old_wlbrs_list[j], &wlbrs_list[j], sizeof(wl_br_status))) {
		BH_DBG("wlbrs_list[%d].defif=%02X bandIndex=%d band=%d priority=%d "
			"wlcif=%s pap_bssid=%s use=%d unit=%d state=%d rssi=%d cost=%.1f "
			"rssiscore=%d isfirst=%d role=%d br_status.in_br=%d\n",
		j, wlbrs_list[j].defif, wlbrs_list[j].bandIndex, wlbrs_list[j].band,
		wlbrs_list[j].priority, wlbrs_list[j].wlcif, wlbrs_list[j].pap_bssid,
		wlbrs_list[j].use, wlbrs_list[j].unit, wlbrs_list[j].state, wlbrs_list[j].rssi, wlbrs_list[j].cost,
		wlbrs_list[j].rssiscore, wlbrs_list[j].isfirst, wlbrs_list[j].role,
		wlbrs_list[j].br_status.in_br);

		memcpy(&old_wlbrs_list[j], &wlbrs_list[j], sizeof(wl_br_status));
		qsort(old_wlbrs_list, SUMband, sizeof(old_wlbrs_list[0]), wlbrs_list_cmp_sort_priority);
	}
#else
        BH_DBG("\n######################################\n"
        "wlbrs_list[%d].defif\t\t\t= %02X\n"
        "wlbrs_list[%d].bandIndex\t\t\t= %d\n"
        "wlbrs_list[%d].band\t\t\t= %d\n"
        "wlbrs_list[%d].priority\t\t\t= %d\n"
        "wlbrs_list[%d].wlcif\t\t\t= %s\n"
        "wlbrs_list[%d].pap_bssid\t\t\t= %s\n"
        "wlbrs_list[%d].use\t\t\t= %d\n"
        "wlbrs_list[%d].unit\t\t\t= %d\n"
        "wlbrs_list[%d].state\t\t\t= %d\n"
        "wlbrs_list[%d].rssi\t\t\t= %d\n"
        "wlbrs_list[%d].cost\t\t\t= %.1f\n"
        "wlbrs_list[%d].rssiscore\t\t\t= %d\n"
        "wlbrs_list[%d].isfirst\t\t\t= %d\n"
        "wlbrs_list[%d].role\t\t\t= %d\n"
        "wlbrs_list[%d].br_status.in_br\t\t\t= %d\n",
        j, wlbrs_list[j].defif,
        j, wlbrs_list[j].bandIndex,
        j, wlbrs_list[j].band,
        j, wlbrs_list[j].priority,
        j, wlbrs_list[j].wlcif,
        j, wlbrs_list[j].pap_bssid,
        j, wlbrs_list[j].use,
        j, wlbrs_list[j].unit,
        j, wlbrs_list[j].state,
        j, wlbrs_list[j].rssi,
        j, wlbrs_list[j].cost,
        j, wlbrs_list[j].rssiscore,
        j, wlbrs_list[j].isfirst,
        j, wlbrs_list[j].role,
        j, wlbrs_list[j].br_status.in_br);
#endif
    }
    qsort(wlbrs_list, SUMband, sizeof(wlbrs_list[0]), wlbrs_list_cmp_sort_priority);
}

/**
 * @brief ETH must waitting for Wireless connecting.
 *
 * @return int Waitting(1) or don't wait(0).
 */
static int waitting_for_wireless(float eth_cost)
{
    if (wait_wifi <= 0)
        return 0;

    if (eth_cost == 0) {
        wait_wifi = 0;
        return 0;
    }

    //  Check BH is PLC
    //  If PLC is BH, don't wait in this function.
    //  plc_waitting_for_wireless replace with waitting_for_wireless
    int j;
    int SUMeth = get_eth_count();
    char *amas_ifname = strdup(nvram_safe_get("amas_ifname"));
    if (amas_ifname && strlen(amas_ifname) > 0) {
        for (j = 0; j < SUMeth; j++) {
            if (ethbrs_list[j].ethType == ETH_TYPE_PLC) {
                if (!strcmp(ethbrs_list[j].ethif, amas_ifname)) {
                    wait_wifi = 0;
                    free(amas_ifname);
                    return 0;
                }
            }
        }
        free(amas_ifname);
    }

    int amas_costmode = strtoul(nvram_safe_get("amas_costmode"), NULL, 16) ?: AUTO_COST;
    int connected = 0;
    int SUMband = get_wl_count();
    int dfs_status = 0, wifi_better = -1;
    char buf[32] = {};
    int priority_tmp = 100, highest_band = -1;
    int wlc_connecting = 0;

    //  find the highest priority band
    for (j = 0; j < SUMband; j++) {
        if (wlbrs_list[j].use == 1) {
            if (wlbrs_list[j].priority < priority_tmp) {
                highest_band = wlbrs_list[j].band;
                priority_tmp = wlbrs_list[j].priority;
            }
        }
    }

    if (highest_band >= 0) {
        for (j = 0; j < SUMband; j++) {
            float cost = -1;
            if (wlbrs_list[j].band == highest_band) {
                if (wlbrs_list[j].state == WLC_STATE_CONNECTED)
                    connected++;
                snprintf(buf, sizeof(buf), "amas_wlc%d_dfs_status", j);
                if (nvram_get_int(buf) == 1)
                    dfs_status = 1;
                snprintf(buf, sizeof(buf), "amas_wlc%d_connecting_cost", j);
                if (nvram_get(buf))
                    wlc_connecting = 1;
                if (nvram_get(buf) && eth_cost >= 0) {
                    cost = nvram_get_int(buf);
                    if (cost >= 0) {
                        cost = cost / 10.0;
                        //  Compare ETH cost.
                        BH_DBG("ETH cost(%.1f) WIFI cost(%.1f)\n", eth_cost, cost);
                        if (cost < eth_cost)  // Wireless is the better.
                            wifi_better = 1;
                        else  // ETH is the better
                            wifi_better = 0;
                    }
                }
            }
        }
    }

    if (amas_costmode == DONT_COST ||
        amas_costmode == WIFI_COST ||
        highest_band < 0) {
        wait_wifi = 0;
        return 0;
    }

    if (bhctrl_init_keep_waitting_wifi > 0) {  // amas_bhctrl init. skip 20s for this.
        if (wlc_connecting == 1) {             //  wlc trying connect to ap, so doesn't need to waitting wifi when booted.
            bhctrl_init_keep_waitting_wifi = 0;
        } else {
            BH_DBG("amas_bhctrl is be started. Keep wait wifi.");
            return 1;
        }
    }

    if (connected || wifi_better == 0)
        wait_wifi = 0;

    if (wait_wifi <= 0)
        return 0;

    if (dfs_status) {
        BH_DBG("DFS CAC. Waitting %d seconds for wireless connecting...\n", wait_wifi * amas_bhctl_timer);
    } else {
        BH_DBG("Waitting %d seconds for wireless connecting...\n", wait_wifi * amas_bhctl_timer);
        wait_wifi--;
    }
    return 1;
}

/**
 * @ Confirm whether the PAP exists 6G and matches the current re  
 	 Confirm that PAP has no 6G and re has 6G, then return 1 
 	 and return 0 in other cases
 */
 
 typedef struct amas_sitesurvey_ap_s_6g {
    int cap_role;
    int last_byte_6g;
    struct amas_sitesurvey_ap_s_6g *next;
} amas_sitesurvey_ap_s_6g;

#define RE_SURVEY_RESULT_FILE_NAME	"/tmp/amas/survey_result_%d"

static int check_6G_from_get_site_sitesurvey_result(int defif_bh)
{
	char wlIfnames[64] ,word[256], *next, tmp[64];
	char prefix[16] = {0};
	int bandindex=0, nband=0, unit = 0, have_6G = 0, ret=0;
	json_object *root = NULL, *cap_role_obj = NULL,*last_byte_6g_obj = NULL;
    	char site_survey_file_path[64];
    	amas_sitesurvey_ap_s_6g *ss_ap = NULL;
	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
			SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			BH_DBG(" prefix=%s ",prefix);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			BH_DBG(" nband=%d ",nband);
			if (nband == 4) {
				have_6G=1;	
			}
			unit++;
	}
	if(have_6G==0){
		return ret;
	}
	if(defif_bh==WL5G1_U){
		bandindex=1;
	}
	else if(defif_bh==WL5G2_U)
	{
		bandindex=2;
	}	
	snprintf(site_survey_file_path, sizeof(site_survey_file_path),RE_SURVEY_RESULT_FILE_NAME, bandindex);
	 root = json_object_from_file(site_survey_file_path);

    	if (!root) {
        	BH_DBG("root is NULL\n");
        	return -1;
    	}

    	json_object_object_foreach(root, key, val) {

        BH_DBG("Parsing MAC: %s\n", key);
        json_object_object_get_ex(val, "cap_role", &cap_role_obj);
        json_object_object_get_ex(val, "6g_last_byte", &last_byte_6g_obj);

        ss_ap = (amas_sitesurvey_ap_s_6g *)calloc(1, sizeof(amas_sitesurvey_ap_s_6g));

        if (ss_ap == NULL) {
            BH_DBG("Allocate memory for Site Survey AP node fail.\n");
            return -1;
        }

        /* last bytes */

        if (cap_role_obj) {
            ss_ap->cap_role = json_object_get_int(cap_role_obj); // CAP role
        }
        else
            ss_ap->cap_role = 0;
	
	if(ss_ap->cap_role > 0){
	        if (last_byte_6g_obj){
            		ss_ap->last_byte_6g = json_object_get_int(last_byte_6g_obj);  // last byte 6G
            		if(ss_ap->last_byte_6g==0){
            			BH_DBG("pap does not exist 6G. need stop 6g connect to pap.\n");
				ret=1;	
            		}
            		else{
            			BH_DBG("pap exists 6G.\n");
				ret=0;
            		}
            		
            	}
            	else{
            		ss_ap->last_byte_6g=-1;
            		ret=0;
            	}
            	free(ss_ap);
            	ss_ap = NULL;
            	json_object_put(root);
            	return ret;
	}
	free(ss_ap);
	ss_ap = NULL;    
    }
    json_object_put(root);
    return ret;
}
/**
 * @brief Whether to stop the connection
 *
 * @param defif_bh BH band definition
 * @return int Keep(1) or Stop(0)
 */
static int get_wifi_stage(int defif_bh) {
    int stage, j;
    int SUMband = get_wl_count();
    int keep_on_band_count = 0, keep_on_band_connected_count = 0;

    if (defif_bh < WL5G1_U && defif_bh > WL6G_U) {
        stage = WIFI_STAGE_KEEP_TRY_CONNECTING;
        wait_band = (nvram_get_int("amas_wait_band") < MAX_WIFI_BAND_WAIT_TIME ? MAX_WIFI_BAND_WAIT_TIME : nvram_get_int("amas_wait_band")) / amas_bhctl_timer;  // reset wait_band
        goto GET_WIFI_STAGE_EXIT;
    }

    for (j = 0; j < SUMband; j++) {
        if (wlbrs_list[j].use == 1 && wlbrs_list[j].keep_conn == 1) {
            if (wlbrs_list[j].defif >= WL5G1_U && wlbrs_list[j].defif <= WL6G_U && wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                keep_on_band_connected_count++;
            }
            keep_on_band_count++;
        }
    }
    if (keep_on_band_connected_count == keep_on_band_count) {  // all connected
        stage = WIFI_STAGE_ALL_KEEP_BAND_CONNECTED;
        wait_band = (nvram_get_int("amas_wait_band") < MAX_WIFI_BAND_WAIT_TIME ? MAX_WIFI_BAND_WAIT_TIME : nvram_get_int("amas_wait_band")) / amas_bhctl_timer;  // reset wait_band
        goto GET_WIFI_STAGE_EXIT;
    }
    if (keep_on_band_connected_count == 0) {  // all disconnect
        stage = WIFI_STAGE_KEEP_TRY_CONNECTING;
        wait_band = (nvram_get_int("amas_wait_band") < MAX_WIFI_BAND_WAIT_TIME ? MAX_WIFI_BAND_WAIT_TIME : nvram_get_int("amas_wait_band")) / amas_bhctl_timer;  // reset wait_band
        goto GET_WIFI_STAGE_EXIT;
    }
    if (defif_bh == WL5G1_U || defif_bh == WL5G2_U) {
        stage = WIFI_STAGE_FOLLOW_CONNECTING;
        if(check_6G_from_get_site_sitesurvey_result(defif_bh)==1)
        {
        	 stage = WIFI_STAGE_STOP_KEEP_TRY_CONNECTING;
        	 goto GET_WIFI_STAGE_EXIT;
        }
        
        wait_band = (nvram_get_int("amas_wait_band") < MAX_WIFI_BAND_WAIT_TIME ? MAX_WIFI_BAND_WAIT_TIME : nvram_get_int("amas_wait_band")) / amas_bhctl_timer;  // reset wait_band
        goto GET_WIFI_STAGE_EXIT;
    }

    if (wait_band <= 0) {
        stage = WIFI_STAGE_STOP_KEEP_TRY_CONNECTING;
        goto GET_WIFI_STAGE_EXIT;
    }

    wait_band--;
    stage = WIFI_STAGE_KEEP_TRY_CONNECTING;

GET_WIFI_STAGE_EXIT:
    if (stage == WIFI_STAGE_STOP_KEEP_TRY_CONNECTING)
        BH_DBG("Wait(%d) other major bands. Keep to try connecting...\n", wait_band);

    return stage;
}

/*
 * @brief Reset PLC wait WiFi timer.
 *
 */
static void reset_plc_wait_wifi(void) {
    if (nvram_get("plc_wait_wifi")) {
        plc_wait_wifi = (nvram_get_int("plc_wait_wifi") < 0 ? MAX_PLC_WIFI_WAIT_TIME : nvram_get_int("plc_wait_wifi")) / amas_bhctl_timer;  // reset plc_wait_wifi
    } else {
        plc_wait_wifi = MAX_PLC_WIFI_WAIT_TIME / amas_bhctl_timer;
    }
}

/**
 * @brief PLC waitting WiFi connecting.
 *
 * @return int 0: Don't wait. 1: Wait.
 */
static int plc_waitting_for_wireless(void) {
    if (!plc_support)
        return 0;

    int waitting = 1;
    int amas_costmode = strtoul(nvram_safe_get("amas_costmode"), NULL, 16) ?: AUTO_COST;
    int connected = 0, j;
    int SUMband = get_wl_count();
    int priority_tmp = 100, highest_band = -1;
    static int pre_wifi_connected = 0;
    int SUMeth = get_eth_count();
    int plc_bh = 0;

    //  Check BH is PLC
    char *amas_ifname = strdup(nvram_safe_get("amas_ifname"));
    if (amas_ifname == NULL || strlen(amas_ifname) == 0) {
        waitting = 0;
        goto PLC_WAITTING_FOR_WIRELESS_EXIT;
    }

    for (j = 0; j < SUMeth; j++) {
        if (ethbrs_list[j].ethType == ETH_TYPE_PLC) {
            if (!strcmp(ethbrs_list[j].ethif, amas_ifname)) {
                plc_bh = 1;
                break;
            }
        }
    }

    if (plc_bh == 0) {
        waitting = 0;
        goto PLC_WAITTING_FOR_WIRELESS_EXIT;
    }

    //  find the highest priority band
    for (j = 0; j < SUMband; j++) {
        if (wlbrs_list[j].use == 1) {
            if (wlbrs_list[j].priority < priority_tmp) {
                highest_band = wlbrs_list[j].band;
                priority_tmp = wlbrs_list[j].priority;
            }
        }
    }

    if (amas_costmode == DONT_COST ||
        amas_costmode == WIFI_COST ||
        highest_band < 0) {
        plc_wait_wifi = 0;
        goto PLC_WAITTING_FOR_WIRELESS_EXIT;
    }

    if (highest_band >= 0) {
        for (j = 0; j < SUMband; j++) {
            if (wlbrs_list[j].band == highest_band) {
                if (wlbrs_list[j].state == WLC_STATE_CONNECTED)
                    connected++;
            }
        }
    }

    if (connected) {
        pre_wifi_connected = connected;
        plc_wait_wifi = 0;
        goto PLC_WAITTING_FOR_WIRELESS_EXIT;
    }

    if (pre_wifi_connected != connected && pre_wifi_connected == 1) {
        pre_wifi_connected = connected;
        reset_plc_wait_wifi();
    }

    plc_wait_wifi--;

PLC_WAITTING_FOR_WIRELESS_EXIT:
    if (plc_wait_wifi <= 0) {
        waitting = 0;
    } else {
        if (waitting)
            BH_DBG("PLC BH Waitting %d seconds for wireless connecting...\n", plc_wait_wifi * amas_bhctl_timer);
    }

    if (amas_ifname)
        free(amas_ifname);

    return waitting;
}

void check_cost_for_allupif(int *costif, int *nocostif)
{
    int j = 0;
    int SUMeth = get_eth_count();
    int SUMband = get_wl_count();
    int tmp_costif = 0;   //connected , have cost;
    int tmp_nocostif = 0; //connected, can't get cost;

    for (j = 0; j < SUMeth; j++)
    {
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
        if (ethbrs_list[j].state == ETH_STATE_CONNECTED &&
#else
        if (ethbrs_list[j].state > 0 &&
#endif
            ethbrs_list[j].cost >= 0)
        {
            tmp_costif = ethbrs_list[j].defif | tmp_costif;
        }
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
        else if (ethbrs_list[j].state == ETH_STATE_CONNECTED)
#else
        else if (ethbrs_list[j].state > 0)
#endif
        {
            tmp_nocostif = ethbrs_list[j].defif | tmp_nocostif;
        }
    }

    for (j = 0; j < SUMband; j++)
    {
        if (wlbrs_list[j].use == 1)
        {
            if (wlbrs_list[j].state == WLC_STATE_CONNECTED && wlbrs_list[j].cost >= 0)
            {
                tmp_costif = wlbrs_list[j].defif | tmp_costif;
            }
            else if (wlbrs_list[j].state == WLC_STATE_CONNECTED)
            {
                tmp_nocostif = wlbrs_list[j].defif | tmp_nocostif;
            }
        }
    }

    *costif =  tmp_costif;
    *nocostif = tmp_nocostif;
    return;
}

void check_rssiscore_for_allupif(int *rssiscoreif, int *norssiscoreif)
{
    int j = 0;
    int SUMeth = get_eth_count();
    int SUMband = get_wl_count();
    int tmp_rssiscoreif = 0;   //connected , have rssi score;
    int tmp_norssiscoreif = 0; //connected, can't get rssi score;

    for (j = 0; j < SUMeth; j++)
    {
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
        if (ethbrs_list[j].state == ETH_STATE_CONNECTED &&
#else
        if (ethbrs_list[j].state > 0 &&
#endif
            ethbrs_list[j].rssiscore <= 0)
        {
            tmp_rssiscoreif = ethbrs_list[j].defif | tmp_rssiscoreif;
        }
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
        else if (ethbrs_list[j].state == ETH_STATE_CONNECTED)
#else
        else if (ethbrs_list[j].state > 0)
#endif
        {
            tmp_norssiscoreif = ethbrs_list[j].defif | tmp_norssiscoreif;
        }
    }

    for (j = 0; j < SUMband; j++)
    {
        if (wlbrs_list[j].use == 1)
        {
            if (wlbrs_list[j].state == WLC_STATE_CONNECTED && wlbrs_list[j].rssiscore <= 0)
            {
                tmp_rssiscoreif = wlbrs_list[j].defif | tmp_rssiscoreif;
            }
            else if (wlbrs_list[j].state == WLC_STATE_CONNECTED)
            {
                tmp_norssiscoreif = wlbrs_list[j].defif | tmp_norssiscoreif;
            }
        }
    }

    *rssiscoreif =  tmp_rssiscoreif;
    *norssiscoreif = tmp_norssiscoreif;
    return;
}


#ifdef RTCONFIG_QCA_PLC2
static int is_wifi_connected(void)
{
    int w;
    int SUMband = get_wl_count();
    for (w = 0; w < SUMband; w++) {
        if (wlbrs_list[w].use == 1 && wlbrs_list[w].state == WLC_STATE_CONNECTED && wlbrs_list[w].cost >= 0) {
             return 1;
         }
    }
    return 0;
}
#endif

void get_ethavaupif_entry(int *entry, int SUMeth, int SUMband, int costmode)
{
    int j = 0,  k = 0;
    int SUMif = SUMeth + SUMband;
    j  = *entry;
    int ethtype_only;
    int amas_ethernet = nvram_get_int("amas_ethernet");
    int conn_priority = 0, target_port_index = 0;
    char target_port_ifname[8] = {}, word[8] = {}, *next = NULL;

    if (amas_ethernet >= 10 && amas_ethernet < 100) {
        conn_priority = amas_ethernet / 10;
        target_port_index = amas_ethernet % 10;
    } else if (amas_ethernet >= 1000) {
        conn_priority = amas_ethernet / 10;
        target_port_index = amas_ethernet % 10;
    } else {
        conn_priority = amas_ethernet;
        target_port_index = 0;
    }

    switch (conn_priority)
    {
		case CONN_PRI_ETH1G:
            ethtype_only = ETH_TYPE_1000;
            break;
		case CONN_PRI_ETH25G:
            ethtype_only = ETH_TYPE_25G;
            break;
        case CONN_PRI_ETH5G:
            ethtype_only = ETH_TYPE_5G;
            break;
		case CONN_PRI_ETH10G:
            ethtype_only = ETH_TYPE_10G;
            break;
		case CONN_PRI_ETH10GPLUS:
            ethtype_only = ETH_TYPE_10GPLUS;
            break;
        case CONN_PRI_PLC:
            ethtype_only = ETH_TYPE_PLC;
            break;
        default:
            ethtype_only = 0xFFFFFFFF; // No limit
    }

    // Get target Port's interface name
    if (target_port_index) {
        int i = 0, tmp_int = 0, target_ifname_idx = -1;
        foreach(word, nvram_safe_get("amas_ethif_type"), next) { // Get target port index in eth_ifnames
            if (ethtype_only & atoi(word))
                i++;
            if (target_port_index == i) {
                target_ifname_idx = tmp_int;
                break;
            }
            tmp_int++;
        }
        if (target_ifname_idx >= 0) {
            i = 0;
            foreach(word, nvram_safe_get("eth_ifnames"), next) { // find target port interface name
                if (target_ifname_idx == i) {
                    snprintf(target_port_ifname, sizeof(target_port_ifname), "%s", word);
                    break;
                }
                i++;
            }
        }
    }

    if (costmode == ETH_COST)
    {
        if (j < SUMif)
        {
            for (k = 0; k < SUMeth; k++)
            {
                if (
                    ethbrs_list[k].use == 1 &&
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
		    ethbrs_list[k].state == ETH_STATE_CONNECTED &&
#else
		    ethbrs_list[k].state > 0 &&
#endif
                    ethbrs_list[k].cost >= 0 && (ethtype_only & ethbrs_list[k].ethType) && (strlen(target_port_ifname) == 0 || !strcmp(ethbrs_list[k].ethif, target_port_ifname))
#ifdef RTCONFIG_AMAS_ETHDETECT
                    && ethbrs_list[k].dest_eth_role != ROLE_WAN
#endif
                    )
                {
#ifdef RTCONFIG_QCA_PLC2
		    if (ethbrs_list[k].ethType == ETH_TYPE_PLC) {
                        int wifi = -1;
		        if (nvram_match("cfg_plc_m_ex", get_lan_hwaddr()) || ethbrs_list[k].dest_eth_role != ROLE_LAN)
                        {
                            BH_DBG("#PLC# skip by cfg_plc_m_ex(%s) || dest_eth_role(%d)\n", nvram_get("cfg_plc_m_ex"), ethbrs_list[k].dest_eth_role);
			    continue;
                        }
                        if (nvram_get_int("cfg_alive") == 0 && (wifi = is_wifi_connected()))
                        {
                            BH_DBG("#PLC# skip by cfg_alive(%s) && is_wifi_connected(%d)\n", nvram_get("cfg_alive"), wifi);
			    continue;
                        }
                    }
#endif	/* RTCONFIG_QCA_PLC2 */
                    if (waitting_for_wireless(ethbrs_list[k].cost) == 0 || ethbrs_list[k].ethType == ETH_TYPE_PLC) {  // Skip PLC
                        ava_upifi_list[j].defif =  ethbrs_list[k].defif;
                        ava_upifi_list[j].index =  ethbrs_list[k].ethIndex;
                        ava_upifi_list[j].priority =  ethbrs_list[k].priority;
                        ava_upifi_list[j].cost =  ethbrs_list[k].cost;
                        ava_upifi_list[j].rssiscore =  ethbrs_list[k].rssiscore;
                        ava_upifi_list[j].isfirst =  ethbrs_list[k].isfirst;
                        j++;
                    }
                }
            }
        }
    } else if (costmode == DONT_COST) {
        if (j < SUMif)
        {
            for (k = 0; k < SUMeth; k++)
            {
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
                if (ethbrs_list[k].use == 1 && ethbrs_list[k].state == ETH_STATE_CONNECTED)
#else
                if (ethbrs_list[k].use == 1 && ethbrs_list[k].state > 0 && (ethtype_only & ethbrs_list[k].ethType) && (strlen(target_port_ifname) == 0 || !strcmp(ethbrs_list[k].ethif, target_port_ifname)))
#endif
                {
#ifdef RTCONFIG_QCA_PLC2
		    if (ethbrs_list[k].ethType == ETH_TYPE_PLC) {
                        int wifi = -1;
		        if (nvram_match("cfg_plc_m_ex", get_lan_hwaddr()) || ethbrs_list[k].dest_eth_role != ROLE_LAN)
                        {
                            BH_DBG("#PLC# skip by cfg_plc_m_ex(%s) || dest_eth_role(%d)\n", nvram_get("cfg_plc_m_ex"), ethbrs_list[k].dest_eth_role);
			    continue;
                        }
                        if (nvram_get_int("cfg_alive") == 0 && (wifi = is_wifi_connected()))
                        {
                            BH_DBG("#PLC# skip by cfg_alive(%s) && is_wifi_connected(%d)\n", nvram_get("cfg_alive"), wifi);
                            continue;
                        }
                    }
#endif	/* RTCONFIG_QCA_PLC2 */
                    /* skip none ob ifname during onboarding, cfg_obifname will be remove after onboarding success */
                    if (nvram_get("cfg_obifname") && strcmp(ethbrs_list[k].ethif, nvram_safe_get("cfg_obifname")))
                        continue;

                    ava_upifi_list[j].defif =  ethbrs_list[k].defif;
                    ava_upifi_list[j].index =  ethbrs_list[k].ethIndex;
                    ava_upifi_list[j].priority =  ethbrs_list[k].priority;
                    ava_upifi_list[j].cost =  ethbrs_list[k].cost;
                    ava_upifi_list[j].rssiscore =  ethbrs_list[k].rssiscore;
                    ava_upifi_list[j].isfirst =  ethbrs_list[k].isfirst;
                    j++;
                }
            }
        }
    }

    if (entry != NULL) *(entry) = j;

    return;

}

void get_wifiavaupif_entry(int *entry, int SUMeth, int SUMband, int costmode)
{
    int j = 0,  k = 0;
    int SUMif = SUMeth + SUMband, have_wifi = 0;
    j  = *entry;


    if (costmode == WIFI_COST)
    {
        if (j < SUMif)
        {
            for (k = 0; k < SUMband; k++)
            {
                if (wlbrs_list[k].use == 1 && wlbrs_list[k].state == WLC_STATE_CONNECTED && wlbrs_list[k].cost >= 0)
                {
                    if (wlbrs_list[k].defif == WL2G_U)  // 2.4G is backup path. skip it.
                        continue;
                    ava_upifi_list[j].defif =  wlbrs_list[k].defif;
                    ava_upifi_list[j].index =  wlbrs_list[k].bandIndex;
                    ava_upifi_list[j].priority =  wlbrs_list[k].priority;
                    ava_upifi_list[j].cost =  wlbrs_list[k].cost;
                    ava_upifi_list[j].rssiscore =  wlbrs_list[k].rssiscore;
                    ava_upifi_list[j].isfirst =  wlbrs_list[k].isfirst;
                    have_wifi = 1;
                    j++;
                }
            }
        }
    }

    if (costmode == DONT_COST)
    {
        if (j < SUMif)
        {
            for (k = 0; k < SUMband; k++)
            {
                if (wlbrs_list[k].use == 1 && wlbrs_list[k].state == WLC_STATE_CONNECTED)
                {
                    if (wlbrs_list[k].defif == WL2G_U)  // 2.4G is backup path. skip it.
                        continue;
                    ava_upifi_list[j].defif =  wlbrs_list[k].defif;
                    ava_upifi_list[j].index =  wlbrs_list[k].bandIndex;
                    ava_upifi_list[j].priority =  wlbrs_list[k].priority;
                    ava_upifi_list[j].cost =  wlbrs_list[k].cost;
                    ava_upifi_list[j].rssiscore =  wlbrs_list[k].rssiscore;
                    ava_upifi_list[j].isfirst =  wlbrs_list[k].isfirst;
                    have_wifi = 1;
                    j++;
                }
            }
        }
    }

    if (have_wifi == 0) {  //  Check 2.4G backup path.
        if (costmode == WIFI_COST) {
            if (j < SUMif) {
                for (k = 0; k < SUMband; k++) {
                    if (wlbrs_list[k].use == 1 && wlbrs_list[k].defif == WL2G_U && wlbrs_list[k].state == WLC_STATE_CONNECTED && wlbrs_list[k].cost >= 0) {
                        ava_upifi_list[j].defif = wlbrs_list[k].defif;
                        ava_upifi_list[j].index = wlbrs_list[k].bandIndex;
                        ava_upifi_list[j].priority = wlbrs_list[k].priority;
                        ava_upifi_list[j].cost = wlbrs_list[k].cost;
                        ava_upifi_list[j].rssiscore = wlbrs_list[k].rssiscore;
                        ava_upifi_list[j].isfirst = wlbrs_list[k].isfirst;
                        j++;
                    }
                }
            }
        } else if (costmode == DONT_COST) {
            if (j < SUMif) {
                for (k = 0; k < SUMband; k++) {
                    if (wlbrs_list[k].use == 1 && wlbrs_list[k].defif == WL2G_U && wlbrs_list[k].state == WLC_STATE_CONNECTED) {
                        ava_upifi_list[j].defif = wlbrs_list[k].defif;
                        ava_upifi_list[j].index = wlbrs_list[k].bandIndex;
                        ava_upifi_list[j].priority = wlbrs_list[k].priority;
                        ava_upifi_list[j].cost = wlbrs_list[k].cost;
                        ava_upifi_list[j].rssiscore = wlbrs_list[k].rssiscore;
                        ava_upifi_list[j].isfirst = wlbrs_list[k].isfirst;
                        j++;
                    }
                }
            }
        }
    }

    if (entry != NULL) *(entry) = j;

    return;
}

/**
 * @brief Move isfirst=1 uplink port to top1
 *
 */
static void isfirst_check() {
    int i;
    int entry = 0, conn_priority = 0;
    int amas_ethernet = nvram_get_int("amas_ethernet");
    int SUMeth = get_eth_count();
    int SUMband = get_wl_count();
    int SUMif = SUMeth + SUMband;

    if (amas_ethernet >= 100 && amas_ethernet < 1000) {
        conn_priority = amas_ethernet;
    } else if (amas_ethernet >= 1000 && amas_ethernet < 10000) {
        conn_priority = amas_ethernet / 10;
    }

    //  Calculate entry
    for (i = 0; i < SUMif; i++) {
        if (ava_upifi_list[i].defif > 0)
            entry++;
    }

    switch (conn_priority) {
        case CONN_PRI_WIFI_2G:
        case CONN_PRI_WIFI_5G:
        case CONN_PRI_WIFI_5G2:
        case CONN_PRI_WIFI_6G:
            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_isFirst);
            break;
        default:
            break;
    }
}

/**
 * @brief If prefer Node connected. Besure the prefer node priority is the
 * higher than other non-preferd node.
 *
 */
static void prefer_node_check() {
    char amas_wlc_target_bssid[] = "amas_wlcXXX_target_bssid";
    char amas_wlc_pap[] = "amas_wlcXXX_pap";
    char *target_bssid = NULL;
    int SUMband = get_wl_count(), SUMeth = get_eth_count();
    int i, prefer_node_connected = 0;

    if (strlen(nvram_safe_get("amas_wlc_target_bssid")) == 0)
        goto PREFER_NODE_CHECK_EXIT;

    if (ava_upifi_list[0].defif < WL2G_U || ava_upifi_list[0].defif > WL6G_U)
        goto PREFER_NODE_CHECK_EXIT;

    snprintf(amas_wlc_target_bssid, sizeof(amas_wlc_target_bssid),
             "amas_wlc%d_target_bssid", ava_upifi_list[0].index);
    snprintf(amas_wlc_pap, sizeof(amas_wlc_pap),
             "amas_wlc%d_pap", ava_upifi_list[0].index);

    target_bssid = strdup(nvram_safe_get(amas_wlc_target_bssid));
    if (strstr(target_bssid, nvram_safe_get(amas_wlc_pap))) {
        goto PREFER_NODE_CHECK_EXIT;
    }

    for (i = 1; i < (SUMband + SUMeth); i++) {
        if (ava_upifi_list[i].defif < WL2G_U || ava_upifi_list[i].defif > WL6G_U) {
            continue;
        }
        snprintf(amas_wlc_target_bssid, sizeof(amas_wlc_target_bssid),
                 "amas_wlc%d_target_bssid", ava_upifi_list[i].index);
        snprintf(amas_wlc_pap, sizeof(amas_wlc_pap),
                 "amas_wlc%d_pap", ava_upifi_list[i].index);
        if (target_bssid)
            free(target_bssid);

        target_bssid = strdup(nvram_safe_get(amas_wlc_target_bssid));
        if (strstr(target_bssid, nvram_safe_get(amas_wlc_pap))) {
            prefer_node_connected = 1;
            break;
        }
    }

    if (prefer_node_connected) {
        int process_count = 0;
        i = 0;
        while (ava_upifi_list[i].defif > 0 && process_count < (SUMband + SUMeth)) {
            if (ava_upifi_list[i].defif < WL2G_U || ava_upifi_list[i].defif > WL6G_U) {
                i++;
                process_count++;
                continue;
            }
            snprintf(amas_wlc_target_bssid, sizeof(amas_wlc_target_bssid),
                    "amas_wlc%d_target_bssid", ava_upifi_list[i].index);
            snprintf(amas_wlc_pap, sizeof(amas_wlc_pap),
                    "amas_wlc%d_pap", ava_upifi_list[i].index);
            if (target_bssid)
                free(target_bssid);

            target_bssid = strdup(nvram_safe_get(amas_wlc_target_bssid));
            if (!strstr(target_bssid, nvram_safe_get(amas_wlc_pap))) {
                BH_DBG("Prefer Node Connected. Removed Not Prefer Node backhaul(%d).\n", ava_upifi_list[i].defif);
                if ((i + 1) < (SUMband + SUMeth)) {
                    int j;
                    for (j = i; j < (SUMband + SUMeth) - 1; j++) {
                        memcpy(&ava_upifi_list[j], &ava_upifi_list[j + 1], sizeof(ava_upifi_list[j]));
                        memset(&ava_upifi_list[j + 1], 0x00, sizeof(ava_upifi_list[j + 1]));
                    }
                }
            } else {
                i++;
            }
            process_count++;
        }
    }

PREFER_NODE_CHECK_EXIT:
    if (target_bssid)
        free(target_bssid);
}

void get_avaupif_by_costsetting(int SUMeth, int SUMband, int cost_mode,  int rssiscore_mode)
{
    int j = 0;
    int SUMif = SUMeth + SUMband;
    int costif = 0, nocostif = 0;
    int rssiscoreif = 0, norssiscoreif = 0;
    int entry = 0;
    ifi_priority tmp_eth_upifi_list[2];
    int have_ethbh = 0;

    memset(tmp_eth_upifi_list, 0x00, 2* sizeof(struct _ifi_priority));


    BH_VDBG("cost_mode = %02X, rssiscore_mode = %02X\n", cost_mode, rssiscore_mode);

    memset(ava_upifi_list, 0x00, SUMif *sizeof(struct _ifi_priority));

    if (rssiscore_mode != DONT_RSSISCORE)
    {
        check_rssiscore_for_allupif(&rssiscoreif, &norssiscoreif);
        BH_DBG("rssiscoreif = %02X, norssiscoreif = %02X\n", rssiscoreif, norssiscoreif);
    }

    if (rssiscoreif > 0 && norssiscoreif == 0)
    {
        if(rssiscore_mode == AUTO_RSSISCORE)
        {
            get_ethavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            get_wifiavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_rssiscore);
            BH_VDBG("================== Sort by rssiscore ==================\n");

           for (j = 0; j < SUMif; j++)
            {
                if(ava_upifi_list[j].defif > 0 && ava_upifi_list[j].defif < ETH_MAX_BASE)
                {
                    have_ethbh = 1;
                    /*Get Ethernet information base on best RSSIscore*/
                    tmp_eth_upifi_list[0].defif =  ava_upifi_list[j].defif;
                    tmp_eth_upifi_list[0].index =  ava_upifi_list[j].index;
                    tmp_eth_upifi_list[0].priority =  ava_upifi_list[j].priority;
                    tmp_eth_upifi_list[0].cost =  ava_upifi_list[j].cost;
                    tmp_eth_upifi_list[0].rssiscore =  ava_upifi_list[j].rssiscore;
                    tmp_eth_upifi_list[0].isfirst =  ava_upifi_list[j].isfirst;

                    BH_DBG("\n ####### tmp_eth_upifi_list #############\n"
                    "tmp_eth_upifi_list[0].defif\t\t\t\t= %02X\n"
                    "tmp_eth_upifi_list[0].index\t\t\t\t= %02X\n"
                    "tmp_eth_upifi_list[0].priority\t\t= %d\n"
                    "tmp_eth_upifi_list[0].cost\t\t\t\t= %.1f\n"
                    "tmp_eth_upifi_list[0].rssiscore\t\t= %d\n"
                    "tmp_eth_upifi_list[0].isfirst\t\t\t= %d\n",
                    tmp_eth_upifi_list[0].defif,
                    tmp_eth_upifi_list[0].index,
                    tmp_eth_upifi_list[0].priority,
                    tmp_eth_upifi_list[0].cost,
                    tmp_eth_upifi_list[0].rssiscore,
                    tmp_eth_upifi_list[0].isfirst);
                    break;
                }
            }

            if (have_ethbh == 1)
            {
                /*Get RSSIscore from 1st priority wireless band.*/
                BH_DBG("======have_ethbh=1 (Sort by priority to get RSSIscore from 1st priority band)=======\n");
                qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);

                for (j= 0; j < SUMif; j++)
                {
                    if(ava_upifi_list[j].defif > ETH_MAX_BASE && ava_upifi_list[j].defif <= WL_MAX_BASE)
                    {
                        tmp_eth_upifi_list[1].defif =  ava_upifi_list[j].defif;
                        tmp_eth_upifi_list[1].index =  ava_upifi_list[j].index;
                        tmp_eth_upifi_list[1].priority =  ava_upifi_list[j].priority;
                        tmp_eth_upifi_list[1].cost =  ava_upifi_list[j].cost;
                        tmp_eth_upifi_list[1].rssiscore =  ava_upifi_list[j].rssiscore;
                        tmp_eth_upifi_list[1].isfirst =  ava_upifi_list[j].isfirst;
                        BH_DBG("\n ####### tmp_eth_upifi_list #############\n"
                        "tmp_eth_upifi_list[1].defif\t\t\t\t= %02X\n"
                        "tmp_eth_upifi_list[1].index\t\t\t\t= %02X\n"
                        "tmp_eth_upifi_list[1].priority\t\t= %d\n"
                        "tmp_eth_upifi_list[1].cost\t\t\t\t= %.1f\n"
                        "tmp_eth_upifi_list[1].rssiscore\t\t= %d\n"
                        "tmp_eth_upifi_list[1].isfirst\t\t\t= %d\n",
                        tmp_eth_upifi_list[1].defif,
                        tmp_eth_upifi_list[1].index,
                        tmp_eth_upifi_list[1].priority,
                        tmp_eth_upifi_list[1].cost,
                        tmp_eth_upifi_list[1].rssiscore,
                        tmp_eth_upifi_list[1].isfirst);
                        break;
                    }
                }

                if (tmp_eth_upifi_list[1].defif >= WL_U_BASE && tmp_eth_upifi_list[1].defif <= WL_MAX_BASE) { // have wifi.
                    BH_DBG("======ethbh_rssiscore(%d), wifibh_rssiscore(%d)=====\n",  tmp_eth_upifi_list[0].rssiscore,  tmp_eth_upifi_list[1].rssiscore);
                    if ((tmp_eth_upifi_list[0].rssiscore > tmp_eth_upifi_list[1].rssiscore) ||
                        (tmp_eth_upifi_list[0].rssiscore == tmp_eth_upifi_list[1].rssiscore && ((tmp_eth_upifi_list[0].cost >= 0 && tmp_eth_upifi_list[0].cost <= tmp_eth_upifi_list[1].cost) || tmp_eth_upifi_list[1].cost < 0)))
                    {
                        BH_DBG("======Find the best ethernet backhaul by RSSIscore.=======\n");
                        if(ava_upifi_list[0].defif != tmp_eth_upifi_list[0].defif)
                        {
                            for (j = 0; j < SUMif; j++)
                            {
                                if(ava_upifi_list[j].defif == tmp_eth_upifi_list[0].defif)
                                {
                                    BH_DBG("======Move best ethernet backhaul to ava_upifi_list[0]=======\n");
                                    // select_bh_path() will add to backhaul by ava_upifi_list[0].
                                    ava_upifi_list[j].defif =  ava_upifi_list[0].defif;
                                    ava_upifi_list[j].index =  ava_upifi_list[0].index;
                                    ava_upifi_list[j].priority =  ava_upifi_list[0].priority;
                                    ava_upifi_list[j].cost =  ava_upifi_list[0].cost;
                                    ava_upifi_list[j].rssiscore =  ava_upifi_list[0].rssiscore;
                                    ava_upifi_list[j].isfirst =  ava_upifi_list[0].isfirst;

                                    ava_upifi_list[0].defif =  tmp_eth_upifi_list[0].defif;
                                    ava_upifi_list[0].index =  tmp_eth_upifi_list[0].index;
                                    ava_upifi_list[0].priority =  tmp_eth_upifi_list[0].priority;
                                    ava_upifi_list[0].cost =  tmp_eth_upifi_list[0].cost;
                                    ava_upifi_list[0].rssiscore =  tmp_eth_upifi_list[0].rssiscore;
                                    ava_upifi_list[0].isfirst =  tmp_eth_upifi_list[0].isfirst;
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                        BH_DBG("======Find the wifi backhaul by priority.=======\n");
                        if(ava_upifi_list[0].defif != tmp_eth_upifi_list[1].defif)
                        {
                            for (j = 0; j < SUMif; j++)
                            {
                                if(ava_upifi_list[j].defif == tmp_eth_upifi_list[1].defif)
                                {
                                    BH_DBG("======Move 1st priority wireless backhaul to ava_upifi_list[0]=======\n");
                                    // select_bh_path() will add to backhaul by ava_upifi_list[0].
                                    ava_upifi_list[j].defif =  ava_upifi_list[0].defif;
                                    ava_upifi_list[j].index =  ava_upifi_list[0].index;
                                    ava_upifi_list[j].priority =  ava_upifi_list[0].priority;
                                    ava_upifi_list[j].cost =  ava_upifi_list[0].cost;
                                    ava_upifi_list[j].rssiscore =  ava_upifi_list[0].rssiscore;
                                    ava_upifi_list[j].isfirst =  ava_upifi_list[0].isfirst;

                                    ava_upifi_list[0].defif =  tmp_eth_upifi_list[1].defif;
                                    ava_upifi_list[0].index =  tmp_eth_upifi_list[1].index;
                                    ava_upifi_list[0].priority =  tmp_eth_upifi_list[1].priority;
                                    ava_upifi_list[0].cost =  tmp_eth_upifi_list[1].cost;
                                    ava_upifi_list[0].rssiscore =  tmp_eth_upifi_list[1].rssiscore;
                                    ava_upifi_list[0].isfirst =  tmp_eth_upifi_list[1].isfirst;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                /*no ethernet backhaul, sort by priority*/
                BH_DBG("======have_ethbh=0 (Sort by priority)=======\n");
                qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
            }
        }
    }
    else
    {
        if (!strcmp(nvram_safe_get("cfg_group"), "")) {
            BH_DBG("Onboarding Processing...\n");
            if (nvram_get_int("amas_ethernet") == 2) // ETH first. This means that it is ETH OB processing.
                get_ethavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);
            else
                get_wifiavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
            BH_DBG("================== Sort by priority ==================\n");
        } else if (cost_mode == AUTO_COST) {
            check_cost_for_allupif(&costif, &nocostif);

            BH_DBG("costif = %02X, nocostif = %02X\n", costif, nocostif);

            /*
                (costif > 0 && nocostif == 0)  All connected interfaces get cost
                (costif > 0 && nocostif > 0)   Some of the connected interfaces have got cost, and some doesn't get the cost. select interface that have cost.
            */
            if ((costif > 0 && nocostif == 0) || (costif > 0 && nocostif > 0))
            {
                get_ethavaupif_entry(&entry, SUMeth, SUMband, ETH_COST);

                get_wifiavaupif_entry(&entry, SUMeth, SUMband, WIFI_COST);

                qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_cost);
                BH_VDBG("================== Sort by cost ==================\n");

                for (j = 0; j < SUMif; j++)
                {
                    if(ava_upifi_list[j].defif > 0 && ava_upifi_list[j].defif < ETH_MAX_BASE)
                    {
                        have_ethbh = 1;
                        /*Get Ethernet information base on best cost*/
                        tmp_eth_upifi_list[0].defif =  ava_upifi_list[j].defif;
                        tmp_eth_upifi_list[0].index =  ava_upifi_list[j].index;
                        tmp_eth_upifi_list[0].priority =  ava_upifi_list[j].priority;
                        tmp_eth_upifi_list[0].cost =  ava_upifi_list[j].cost;
                        tmp_eth_upifi_list[0].rssiscore =  ava_upifi_list[j].rssiscore;
                        tmp_eth_upifi_list[0].isfirst =  ava_upifi_list[j].isfirst;
                        break;
                    }
                }

                if (have_ethbh == 1)
                {
                    /*Get cost from 1st priority wireless band.*/
                    BH_DBG("======have_ethbh=1 (Sort by priority to get cost from 1st priority band)=======\n");
                    qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);

                    for (j= 0; j < SUMif; j++)
                    {
                        if(ava_upifi_list[j].defif > ETH_MAX_BASE && ava_upifi_list[j].defif <= WL_MAX_BASE)
                        {
                            tmp_eth_upifi_list[1].defif =  ava_upifi_list[j].defif;
                            tmp_eth_upifi_list[1].index =  ava_upifi_list[j].index;
                            tmp_eth_upifi_list[1].priority =  ava_upifi_list[j].priority;
                            tmp_eth_upifi_list[1].cost =  ava_upifi_list[j].cost;
                            tmp_eth_upifi_list[1].rssiscore =  ava_upifi_list[j].rssiscore;
                            tmp_eth_upifi_list[1].isfirst =  ava_upifi_list[j].isfirst;
                            break;
                        }
                    }

                    BH_DBG("======ethbh_cost(%d), wifibh_cost(%d)=====\n",  tmp_eth_upifi_list[0].cost,  tmp_eth_upifi_list[1].cost);
                    if ( tmp_eth_upifi_list[0].cost <= tmp_eth_upifi_list[1].cost)
                    {
                        BH_DBG("======Find the best ethernet backhaul by cost.=======\n");
                        if(ava_upifi_list[0].defif != tmp_eth_upifi_list[0].defif)
                        {
                            for (j = 0; j < SUMif; j++)
                            {
                                if(ava_upifi_list[j].defif == tmp_eth_upifi_list[0].defif)
                                {
                                    BH_DBG("======Move best ethernet backhaul to ava_upifi_list[0]=======\n");
                                    // select_bh_path() will add to backhaul by ava_upifi_list[0].
                                    ava_upifi_list[j].defif =  ava_upifi_list[0].defif;
                                    ava_upifi_list[j].index =  ava_upifi_list[0].index;
                                    ava_upifi_list[j].priority =  ava_upifi_list[0].priority;
                                    ava_upifi_list[j].cost =  ava_upifi_list[0].cost;
                                    ava_upifi_list[j].rssiscore =  ava_upifi_list[0].rssiscore;
                                    ava_upifi_list[j].isfirst =  ava_upifi_list[0].isfirst;

                                    ava_upifi_list[0].defif =  tmp_eth_upifi_list[0].defif;
                                    ava_upifi_list[0].index =  tmp_eth_upifi_list[0].index;
                                    ava_upifi_list[0].priority =  tmp_eth_upifi_list[0].priority;
                                    ava_upifi_list[0].cost =  tmp_eth_upifi_list[0].cost;
                                    ava_upifi_list[0].rssiscore =  tmp_eth_upifi_list[0].rssiscore;
                                    ava_upifi_list[0].isfirst =  tmp_eth_upifi_list[0].isfirst;
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                         BH_DBG("======Find the wifi backhaul by priority.=======\n");
                        if(ava_upifi_list[0].defif != tmp_eth_upifi_list[1].defif)
                        {
                            for (j = 0; j < SUMif; j++)
                            {
                                if(ava_upifi_list[j].defif == tmp_eth_upifi_list[1].defif)
                                {
                                    BH_DBG("======Move 1st priority wireless backhaul to ava_upifi_list[0]=======\n");
                                    // select_bh_path() will add to backhaul by ava_upifi_list[0].
                                    ava_upifi_list[j].defif =  ava_upifi_list[0].defif;
                                    ava_upifi_list[j].index =  ava_upifi_list[0].index;
                                    ava_upifi_list[j].priority =  ava_upifi_list[0].priority;
                                    ava_upifi_list[j].cost =  ava_upifi_list[0].cost;
                                    ava_upifi_list[j].rssiscore =  ava_upifi_list[0].rssiscore;
                                    ava_upifi_list[j].isfirst =  ava_upifi_list[0].isfirst;

                                    ava_upifi_list[0].defif =  tmp_eth_upifi_list[1].defif;
                                    ava_upifi_list[0].index =  tmp_eth_upifi_list[1].index;
                                    ava_upifi_list[0].priority =  tmp_eth_upifi_list[1].priority;
                                    ava_upifi_list[0].cost =  tmp_eth_upifi_list[1].cost;
                                    ava_upifi_list[0].rssiscore =  tmp_eth_upifi_list[1].rssiscore;
                                    ava_upifi_list[0].isfirst =  tmp_eth_upifi_list[1].isfirst;
                                    break;
                                }
                            }
                        }
                    }
                 }
                else
                {
                    /*no ethernet backhaul, sort by priority*/
                    BH_VDBG("======have_ethbh=0 (Sort by priority)=======\n");
                    qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
                }
            }

            if (costif == 0 && nocostif > 0) //All connected interfaces are not getting cost
            {
                get_ethavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

                get_wifiavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

                qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
                BH_VDBG("================== Sort by priority ==================\n");

            }
        } else if (cost_mode == DONT_COST) {
            get_ethavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            get_wifiavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
            BH_VDBG("================== Sort by priority ==================\n");
        } else if (cost_mode == ETH_COST ) {
            get_ethavaupif_entry(&entry, SUMeth, SUMband, ETH_COST);

            get_wifiavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
            BH_VDBG("================== Sort by priority ==================\n");
        } else if (cost_mode == WIFI_COST) {
            get_ethavaupif_entry(&entry, SUMeth, SUMband, DONT_COST);

            get_wifiavaupif_entry(&entry, SUMeth, SUMband, WIFI_COST);

            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_priority);
            BH_VDBG("================== Sort by priority ==================\n");
        } else if (cost_mode == ALL_COST) {
            get_ethavaupif_entry(&entry, SUMeth, SUMband, ETH_COST);

            get_wifiavaupif_entry(&entry, SUMeth, SUMband, WIFI_COST);

            qsort(ava_upifi_list, entry, sizeof(ava_upifi_list[0]), ava_upifi_list_cmp_sort_cost);
            BH_VDBG("================== Sort by cost ==================\n");
        }
    }

    return;
}

void trigger_amas_wlcconnect(int SUMband, int amas_wifi_bhmode)
{
    char str_active[16];
    int trigger_band = 0;
    int j = 0;
    char wlc_prefix[16], tmp[100]={0};
    int amas_wlc_init = nvram_get_int("amas_wlc_init") ? : RESTART_CONNECTING;
    char wlc_status[] = "wlcXXX_status";


    for (j = 0; j < SUMband; j++)
    {
        snprintf(wlc_prefix, sizeof(wlc_prefix), "amas_wlc%d_", wlbrs_list[j].bandIndex);

        if (nvram_get_int(strcat_r(wlc_prefix, "use", tmp)) == 1)
            trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
    }

    trigger_band = (amas_wifi_bhmode & trigger_band);

    snprintf(str_active, sizeof(str_active), "%X", trigger_band);

    BH_DBG("%d amas_wlc_active = %02X\n", __LINE__, trigger_band);

    nvram_set("amas_wlc_active", str_active);
    nvram_set("amas_wlc_action_band", str_active);

    if (amas_wifi_bhmode == 0)
    {
         //Don't support wireless backhaul.
        sned_action_to_amas_wlcconnect(ACTION_DISCONNECT);
    }
    else
    {
        //Support wireless backhaul.
        if(strcmp(nvram_safe_get("cfg_first_sync"), "1") == 0)
        {
            sned_action_to_amas_wlcconnect(ACTION_START_BY_DRIVER);
        }
        else if (amas_wlc_init == START_CONNECTING)
        {
            sned_action_to_amas_wlcconnect(ACTION_START);
        }
        else if (amas_wlc_init == RESTART_CONNECTING)
        {
            for (j = 0; j < SUMband; j++) {
                snprintf(wlc_prefix, sizeof(wlc_prefix), "amas_wlc%d_", wlbrs_list[j].bandIndex);
                snprintf(wlc_status, sizeof(wlc_status), "wlc%d_status", wlbrs_list[j].bandIndex);
                if (nvram_get_int(strcat_r(wlc_prefix, "use", tmp)) == 1) {
                    trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                    nvram_set_int(wlc_status, CH_SYNC_CONNECTING);
                    set_channel_sync_status(wlbrs_list[j].unit, 0);
                } else {
                    nvram_set_int(wlc_status, CH_SYNC_NO_USE);
                }
            }
            sned_action_to_amas_wlcconnect(ACTION_RESTART);
        }
        else if (amas_wlc_init == MAINTAIN_STATUS_QUO)
        {
            sned_action_to_amas_wlcconnect(ACTION_STOP);
        }
        else if(amas_wlc_init == START_SELF_OPTIMIZATION)
        {
            sned_action_to_amas_wlcconnect(ACTION_START_OPTIMIZATION);
        }
        else if(amas_wlc_init == STOP_SELF_OPTIMIZATION)
        {
             sned_action_to_amas_wlcconnect(ACTION_STOP_OPTIMIZATION);
        }
        else if(amas_wlc_init == DISCONNECT_BAND)
        {
            sned_action_to_amas_wlcconnect(ACTION_DISCONNECT);
        }
    }
    return;
}

#ifdef RTCONFIG_BROOP
void reset_broop_ethif()
{
    char xif[256]={0}, *next = NULL;
    int wan_state;

    if( !nvram_match("stop_broop", "1") && nvram_get_int("cfg_alive")==1 && *nvram_safe_get("amas_ifname") &&  strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname")) ) {
        wan_state = get_wanports_status(wan_primary_ifunit());
        if((nvram_match("reset_broop", "0") && (wan_state > 0)) || (nvram_match("reset_broop", "2") && (wan_state <= 0))) {

            _dprintf("\n\n......(reset case:%s) Add ethernet to br members..(%s)(%s).....\n\n", nvram_safe_get("reset_broop"), nvram_safe_get("cfg_alive"), nvram_safe_get("amas_ifname"));
            syslog(LOG_NOTICE, "add export to lan bridge (reset:%s)(aif:%s)", nvram_safe_get("reset_broop"), nvram_safe_get("amas_ifname"));
            foreach(xif, nvram_safe_get("eth_ifnames"), next)
            ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), xif);

            nvram_set("reset_broop", "1");
            update_rssiscore(nvram_get_int("amas_re_rssiscore")); // Do set rssiscore again. for eth interface. if not do this, the eth cost is 100(not set).
        }
    }
}

int broop_counts = 0;
int broop_counts_max = 0;

int ismax_broop()
{
    if(!broop_counts_max)
        return 0;

    if(detect_broop()) {
        broop_counts++;
        _dprintf("brloop: %d\n", broop_counts);
    }

    if(broop_counts == broop_counts_max) {
        broop_counts = 0;
        return 1;
    } else
        return 0;
}
#endif

/**
 * @brief Update processing request status.
 *
 */
static void update_status(void) {
    int j = 0;
    int SUMband = get_wl_count();
    char nvrampar[] = "wlcXXX_status";
    char *amas_wlc_action = strdup(nvram_safe_get("amas_wlc_action"));
    char *amas_send_action = strdup(nvram_safe_get("amas_send_action"));
    int amas_wlc_action_state = nvram_get_int("amas_wlc_action_state");
    int updated_status = 0;

    if (amas_wlc_action == NULL || amas_send_action == NULL)
        goto UPDATE_STATUS_EXIT;

    // Update SELF OPTIMIZATION state
    if (!strcmp(amas_send_action, ACTION_START_OPTIMIZATION) &&
        !strcmp(amas_wlc_action, ACTION_START_OPTIMIZATION)) {
        for (j = 0; j < SUMband; j++) {
            if (wlbrs_list[j].use == 1 &&
                is_self_optmz_stage(wlbrs_list[j].bandIndex) ==
                    1)  //&& (wlbrs_list[j].defif & amas_wlc_action_band) ==
                        //wlbrs_list[j].defif)
            {
                BH_DBG(
                    "%s:%d Send Self-Optimization action to "
                    "amas_wlcconnect successfully. Reset amas_wlc%d_optmz "
                    "nvram.\n",
                    __FUNCTION__, __LINE__, wlbrs_list[j].bandIndex);
                char optmz_nvram[64] = "amas_wlcXXX_optmz";
                memset(optmz_nvram, 0, sizeof(optmz_nvram));
                snprintf(optmz_nvram, sizeof(optmz_nvram),
                         "amas_wlc%d_optmz", wlbrs_list[j].bandIndex);
                nvram_set_int(optmz_nvram, 0);
                wlbrs_list[j].optmz_base_rssi = 0;
                wlbrs_list[j].optmz_match_count = 0;
            }
        }
    }

    BH_DBG(
        "%s:%d sned_action(%s) wlc_action(%s) amas_wlc_action_state(%d).\n",
        __FUNCTION__, __LINE__, amas_send_action, amas_wlc_action, amas_wlc_action_state);

    if (!strcmp(amas_wlc_action, "") ||
        (strcmp(amas_send_action, "") && (!strcmp(amas_send_action, amas_wlc_action) && amas_wlc_action_state == FIN)) ||
        (!strcmp(amas_send_action, "") && strcmp(amas_wlc_action, "") && amas_wlc_action_state == FIN)) {
        BH_DBG("%s:%d action(%s) clear.\n", __FUNCTION__, __LINE__,
               amas_send_action);
        nvram_set("amas_send_action", "");

        for (j = 0; j < SUMband; j++) {
            if (wlbrs_list[j].use == 1) {
                memset(nvrampar, 0, sizeof(nvrampar));
                if (wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                    if (j != 0) {
                        snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                 wlbrs_list[j].bandIndex);
                        if (nvram_get_int(nvrampar) != CH_SYNC_NO_COONECT) {
                            nvram_set_int(nvrampar, CH_SYNC_NO_COONECT);
                            updated_status = 1;
                        }
                    }
                } else if (wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                    snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                             wlbrs_list[j].bandIndex);
                    if (nvram_get_int(nvrampar) != CH_SYNC_CONNECTED) {
                        nvram_set_int(nvrampar, CH_SYNC_CONNECTED);
                        updated_status = 1;
                        set_channel_sync_status(wlbrs_list[j].unit, 0);
                    }
                }
            }
        }
    } else if ((strcmp(amas_send_action, "") && !strcmp(amas_send_action, amas_wlc_action) && amas_wlc_action_state != FIN) ||
               (!strcmp(amas_send_action, "") && strcmp(amas_wlc_action, "") && amas_wlc_action_state != FIN) ||
               (strcmp(amas_send_action, "") && nvram_get_int("amas_send_action_res") == SEND_ACTION_SUCCESS && strcmp(amas_send_action, amas_wlc_action) && amas_wlc_action_state == FIN)) {
        char amas_wlc_connection_state[] = "amas_wlcXXX_connection_state";
        for (j = 0; j < SUMband; j++) {
            if (wlbrs_list[j].use == 1) {
                snprintf(amas_wlc_connection_state, sizeof(amas_wlc_connection_state), "amas_wlc%d_connection_state", wlbrs_list[j].bandIndex);
                if (nvram_get_int(amas_wlc_connection_state) == 2) {  // AMAS_WLCCONNECT_STATUS_FINISHED = 2
                    memset(nvrampar, 0, sizeof(nvrampar));
                    if (wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                        if (j != 0) {
                            snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                     wlbrs_list[j].bandIndex);
                            if (nvram_get_int(nvrampar) != CH_SYNC_NO_COONECT) {
                                nvram_set_int(nvrampar, CH_SYNC_NO_COONECT);
                                updated_status = 1;
                            }
                        }
                    } else if (wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                        snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                 wlbrs_list[j].bandIndex);
                        if (nvram_get_int(nvrampar) != CH_SYNC_CONNECTED) {
                            nvram_set_int(nvrampar, CH_SYNC_CONNECTED);
                            updated_status = 1;
                            set_channel_sync_status(wlbrs_list[j].unit, 0);
                        }
                    }
                }
            }
        }
    }

UPDATE_STATUS_EXIT:
    if (updated_status)
        post_update_status();

    if (amas_wlc_action)
        free(amas_wlc_action);
    if (amas_send_action)
        free(amas_send_action);
}

int check_connection_status_for_action(int defif, int SUMeth, int SUMband, int amas_wifi_bhmode)
{
    int j = 0;
    char nvrampar[64], str_active[16], optmz_nvram[64], target_bssid[20]={0};
    int trigger_band = 0;
    int amas_wlc_action_band = strtoul(nvram_safe_get("amas_wlc_action_band"), NULL, 16);
    char *action = NULL;
    static int keep_connection = 1, check_sent = 0;

    BH_VDBG("%s:%d amas_send_action(%s), amas_wlc_action(%s)\n", __FUNCTION__, __LINE__, nvram_safe_get("amas_send_action"), nvram_safe_get("amas_wlc_action"));

    if (!strcmp(nvram_safe_get("amas_send_action"), "") && !strcmp(nvram_safe_get("amas_wlc_action"), "")) {
        action = strdup("ACTION_INITIAL"); // initial mode.
        goto DO_ACTION_REQUEST;
    //} else if (!strcmp(nvram_safe_get("amas_send_action"), "")) {
    }
    else {
        /*Disconnect unuse band.*/
        trigger_band = 0;
        for (j = 0; j < SUMband; j++) {
            if (wlbrs_list[j].use == 0) {
                snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                         wlbrs_list[j].bandIndex);
                nvram_set_int(nvrampar, CH_SYNC_NO_USE);

                if (wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                    trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                }
            }
        }
        if (trigger_band > 0) {
            action = strdup(ACTION_DISCONNECT);
            goto DO_ACTION_REQUEST;
        }

        /* cfg_group = NULL */
        if (strcmp(nvram_safe_get("cfg_first_sync"), "1") == 0) {
            trigger_band = 0;
            for (j = 0; j < SUMband; j++) {
                if (wlbrs_list[j].use == 1 &&
                    wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                    trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                    snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                             wlbrs_list[j].bandIndex);
                    nvram_set_int(nvrampar, CH_SYNC_CONNECTING);
                    set_channel_sync_status(wlbrs_list[j].unit, 0);
                }
            }
            if (trigger_band > 0) {
                action = strdup(ACTION_START_BY_DRIVER);
                goto DO_ACTION_REQUEST;
            }
        } else if (amas_wifi_bhmode > 0) {
            BH_VDBG(
                "========= defif = %02X, last_defif = %02x, "
                "trigger_all_connect = %d\n",
                defif, last_defif, trigger_all_connect);

            // if (defif == 0 || (last_defif <= ETH_MAX_BASE && defif >=
            // WL2G_U))
            if (defif == -1 || trigger_all_connect == 1) {
                /*
                    last_defif <= ETH_MAX_BASE && defif >= WL2G_U ==> Bakchaul
                   path Switch from ethernet backhaul to wireless backhaul defif
                   == 0 ==> There are no available backhaul paths now. So we
                   must trigger use band to connect.
                */
                trigger_band = 0;
                trigger_all_connect = 0;
                for (j = 0; j < SUMband; j++) {
                    if (wlbrs_list[j].use == 1 &&
                        wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                        trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                        snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                 wlbrs_list[j].bandIndex);
                        nvram_set_int(nvrampar, CH_SYNC_CONNECTING);
                        set_channel_sync_status(wlbrs_list[j].unit, 0);
                    }
                }
                if (trigger_band > 0) {
                    action = strdup(ACTION_START);
                    goto DO_ACTION_REQUEST;
                }
            } else if (defif > 0 && defif <= ETH_MAX_BASE
#ifdef RTCONFIG_BH_SWITCH_ETH_FIRST
                       && nvram_get_int("cfg_alive") == 1
#endif
                      && plc_waitting_for_wireless() == 0) {
                /*
                    defif > 0 && defif < ETH_MAX_BASE ==> ethernet bakchaul
                    The Wireless that has been connected to the P-AP remains
                connected. If DUT do not connect to P-AP, stop trying to
                connect.
                */
                trigger_band = 0;
                for (j = 0; j < SUMband; j++) {
                    if (wlbrs_list[j].use == 1) {
                        if (wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                            trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                            snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                    wlbrs_list[j].bandIndex);
                            nvram_set_int(nvrampar, CH_SYNC_ETH_BHL);
                        }

                        if (wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                            snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                    wlbrs_list[j].bandIndex);
                            nvram_set_int(nvrampar, CH_SYNC_CONNECTED);
                            set_channel_sync_status(wlbrs_list[j].unit, 0);
                        }
                    }
                }
                if (trigger_band > 0) {
                    action = strdup(ACTION_STOP);
                    goto DO_ACTION_REQUEST;
                }
            } else {
                /* check keep connection band */
                if (!((!strcmp(nvram_safe_get("amas_wlc_action"), ACTION_START_OPTIMIZATION) ||
                       !strcmp(nvram_safe_get("amas_wlc_action"), ACTION_START_FOLLOW_CONNECTION)) &&
                      nvram_get_int("amas_wlc_action_state") != FIN)) {
                          int wifi_stage = get_wifi_stage(defif);
                    if (wifi_stage == WIFI_STAGE_KEEP_TRY_CONNECTING) {
                        keep_connection = 1;
                        trigger_band = 0;
                        for (j = 0; j < SUMband; j++) {
                            if (wlbrs_list[j].use == 1 && wlbrs_list[j].keep_conn == 1 &&
                                wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                                trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                                snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                         wlbrs_list[j].bandIndex);
                                nvram_set_int(nvrampar, CH_SYNC_CONNECTING);
                                set_channel_sync_status(wlbrs_list[j].unit, 0);
                            }
                        }
                        if (trigger_band > 0) {
                            action = strdup(ACTION_START);
                            goto DO_ACTION_REQUEST;
                        }
                    } else if (wifi_stage == WIFI_STAGE_STOP_KEEP_TRY_CONNECTING) {
                        if (keep_connection == 1 || check_sent == 1) {  // Keep -> Stop
                            trigger_band = 0;
                            int skip_sent = 0;
                            if (!strcmp(nvram_safe_get("amas_wlc_action"), ACTION_STOP)) {
                                if (keep_connection == 1) {
                                    check_sent = 1;  // Next check sent result again.
                                } else {
                                    check_sent = 0;  // Sent success.
                                    skip_sent = 1;
                                }
                            } else {
                                check_sent = 1;  // Next check sent result again.
                            }

                            keep_connection = 0;
                            if (skip_sent != 1) {
                                for (j = 0; j < SUMband; j++) {
                                    if (wlbrs_list[j].use == 1) {
                                        if (wlbrs_list[j].state != WLC_STATE_CONNECTED) {
                                            trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                                            snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                                    wlbrs_list[j].bandIndex);
                                            nvram_set_int(nvrampar, CH_SYNC_WIFI_BHL);
                                        }

                                        if (wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                                            snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                                    wlbrs_list[j].bandIndex);
                                            nvram_set_int(nvrampar, CH_SYNC_CONNECTED);
                                            set_channel_sync_status(wlbrs_list[j].unit, 0);
                                        }
                                    }
                                }
                                if (trigger_band > 0) {
                                    action = strdup(ACTION_STOP);
                                    goto DO_ACTION_REQUEST;
                                }
                            }
                        }
                    }
                }
                /* check keep connection band */
            }

            /*check for ACTION_START_OPTIMIZATION*/
            trigger_band = 0;

            /*Use for() loop to reserve development flexibility*/
            for (j = 0; j < SUMband; j++) {
                if (wlbrs_list[j].use == 1 &&
                    is_self_optmz_stage(wlbrs_list[j].bandIndex) == 1) {
                    /* opt for major band */
                    if (wlbrs_list[j].keep_conn == 1) {
                        if (nvram_get_int("amas_path_stat_v3") <=
                                ETH_MAX_BASE ||
                            wlbrs_list[j].state == WLC_STATE_CONNECTED) {
                            trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                            snprintf(nvrampar, sizeof(nvrampar), "wlc%d_status",
                                     wlbrs_list[j].bandIndex);
                            nvram_set_int(nvrampar, CH_SYNC_CONNECTING);
                            set_channel_sync_status(wlbrs_list[j].unit, 0);
                            break;
                        }
                    }
                }
            }
            if (trigger_band > 0) {
                action = strdup(ACTION_START_OPTIMIZATION);
                goto DO_ACTION_REQUEST;
            } else {
                for (j = 0; j < SUMband; j++) {
                    if (wlbrs_list[j].use == 1 &&
                        is_self_optmz_stage(wlbrs_list[j].bandIndex) ==
                            1)  //&& (wlbrs_list[j].defif &
                                //amas_wlc_action_band) == wlbrs_list[j].defif)
                    {
                        BH_DBG(
                            "%s:%d No need to trigger optimization. Reset "
                            "amas_wlc%d_optmz nvram.\n",
                            __FUNCTION__, __LINE__, wlbrs_list[j].bandIndex);
                        snprintf(optmz_nvram, sizeof(optmz_nvram),
                                 "amas_wlc%d_optmz", wlbrs_list[j].bandIndex);
                        nvram_set_int(optmz_nvram, 0);
                    }
                }
            }
            /*check for ACTION_START_OPTIMIZATION*/

            /*if 2.4G and 5G are connected to the different P-APs, we will
             * trigger start_follow_connection */

            trigger_band = 0;

            if ((!strcmp(nvram_safe_get("amas_wlc_action"), ACTION_START_FOLLOW_CONNECTION) &&
                 nvram_get_int("amas_wlc_action_state") == FIN) ||
                strcmp(nvram_safe_get("amas_wlc_action"), ACTION_START_FOLLOW_CONNECTION)) {
                for (j = 0; j < SUMband; j++) {
                    if (wlbrs_list[j].use == 1) {
                        if (wlbrs_list[j].state == WLC_STATE_CONNECTED && wlbrs_list[j].defif == WL2G_U) {
                            snprintf(nvrampar, sizeof(nvrampar),
                                    "amas_wlc%d_target_same_ap",
                                    wlbrs_list[j].bandIndex);
                            strncpy(target_bssid, nvram_safe_get(nvrampar), sizeof(target_bssid));
                            BH_DBG(
                                "wlbrs_list[%d].pap_bssid(%s), "
                                "target_bssid(%s)",
                                j, wlbrs_list[j].pap_bssid, target_bssid);
                            if (strlen(target_bssid) == 17 &&
                                strcmp(wlbrs_list[j].pap_bssid, target_bssid)) {
                                trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                            }
                        } else if (wlbrs_list[j].defif != WL2G_U) {
                            snprintf(nvrampar, sizeof(nvrampar),
                                    "amas_wlc%d_target_same_ap",
                                    wlbrs_list[j].bandIndex);
                            strncpy(target_bssid, nvram_safe_get(nvrampar), sizeof(target_bssid));
                            BH_DBG(
                                "wlbrs_list[%d].pap_bssid(%s), "
                                "target_bssid(%s)",
                                j, wlbrs_list[j].pap_bssid, target_bssid);
                            if (strlen(target_bssid) == 17 &&
                                strcmp(wlbrs_list[j].pap_bssid, target_bssid)) {
                                trigger_band = (1 << (4 * ((wlbrs_list[j].bandIndex / 4) + 1) + wlbrs_list[j].bandIndex)) | trigger_band;
                            }
                        }
                    }
                }
            }
            if (trigger_band > 0) {
                action = strdup(ACTION_START_FOLLOW_CONNECTION);
                goto DO_ACTION_REQUEST;
            }
            /*if 2.4G and 5G are connected to the different P-APs, we will
             * trigger start_follow_connection */
        }
    }

DO_ACTION_REQUEST:
    BH_VDBG("action: %s, amas_send_action: %s, amas_wlc_action: %s\n", action, nvram_safe_get("amas_send_action"), nvram_safe_get("amas_wlc_action"));
    if (action && ((strcmp(action, nvram_safe_get("amas_send_action")) && strcmp(nvram_safe_get("amas_send_action"), ACTION_DISCONNECT)) ||
                   strlen(nvram_safe_get("amas_send_action")) == 0 ||
                   strcmp(nvram_safe_get("amas_send_action"), nvram_safe_get("amas_wlc_action"))
                   )) {
        if (!strcmp(action, "ACTION_INITIAL")) {
            trigger_amas_wlcconnect(SUMband, amas_wifi_bhmode);
        } else if (!strcmp(action, ACTION_DISCONNECT)) {
            trigger_band = (amas_wifi_bhmode & trigger_band);
            snprintf(str_active, sizeof(str_active), "%X", trigger_band);
            BH_VDBG("%s:%d set %02X to amas_wlc_action_band for %s\n", __FUNCTION__,
                __LINE__, trigger_band, ACTION_DISCONNECT);
            nvram_set("amas_wlc_action_band", str_active);
            sned_action_to_amas_wlcconnect(ACTION_DISCONNECT);
        } else if (!strcmp(action, ACTION_START_BY_DRIVER)) {
            trigger_band = (amas_wifi_bhmode & trigger_band);
            snprintf(str_active, sizeof(str_active), "%X", trigger_band);
            BH_VDBG("%s:%d set %02X to amas_wlc_action_band for %s\n", __FUNCTION__,
                __LINE__, trigger_band, ACTION_START_BY_DRIVER);
            nvram_set("amas_wlc_action_band", str_active);
            sned_action_to_amas_wlcconnect(ACTION_START_BY_DRIVER);
        } else if (!strcmp(action, ACTION_START)) {
            trigger_band = (amas_wifi_bhmode & trigger_band);
            snprintf(str_active, sizeof(str_active), "%X", trigger_band);
            /**
             * amas_wlcconnect processing restart connection and the action bands is same as new action band value.
             * Skip the start connection request.
             */
            if (!strcmp(nvram_safe_get("amas_wlc_action"), ACTION_RESTART) && nvram_get_int("amas_wlc_action_state") != FIN) {
                if ((trigger_band | strtol(nvram_safe_get("amas_wlc_action_ongoing"), NULL, 16)) ==
                    strtol(nvram_safe_get("amas_wlc_action_ongoing"), NULL, 16)) {
                    update_status();  // update statue
                } else {
                    BH_VDBG("%s:%d set %02X to amas_wlc_action_band for %s\n", __FUNCTION__,
                            __LINE__, trigger_band, ACTION_START);
                    nvram_set("amas_wlc_action_band", str_active);
                    sned_action_to_amas_wlcconnect(ACTION_START);
                }
            } else if (!strcmp(nvram_safe_get("amas_wlc_action"), ACTION_START_OPTIMIZATION) && // start_connect must waitting optimization
                nvram_get_int("amas_wlc_action_state") != FIN) {
                update_status(); // update statue
            } else {
                BH_VDBG("%s:%d set %02X to amas_wlc_action_band for %s\n", __FUNCTION__,
                       __LINE__, trigger_band, ACTION_START);
                nvram_set("amas_wlc_action_band", str_active);
                sned_action_to_amas_wlcconnect(ACTION_START);
            }
        } else if (!strcmp(action, ACTION_STOP)) {
            trigger_band = (amas_wifi_bhmode & trigger_band);
            snprintf(str_active, sizeof(str_active), "%X", trigger_band);
            BH_VDBG(
                "%s:%d amas_wlc_action = %s, amas_wlc_action_band = "
                "%02X\n",
                __FUNCTION__, __LINE__, nvram_safe_get("amas_wlc_action"),
                amas_wlc_action_band);
            if (strcmp(nvram_safe_get("amas_wlc_action"), ACTION_STOP) ||
                amas_wlc_action_band != trigger_band) {
                BH_VDBG("%s:%d set %02X to amas_wlc_action_band for %s\n",
                    __FUNCTION__, __LINE__, trigger_band, ACTION_STOP);
                nvram_set("amas_wlc_action_band", str_active);
                sned_action_to_amas_wlcconnect(ACTION_STOP);
            } else {
                BH_VDBG(
                    "%s:%d Don't re-send %s (band = %02X) command to "
                    "amas_wlcconnect.\n",
                    __FUNCTION__, __LINE__, ACTION_STOP, trigger_band);
            }
        } else if (!strcmp(action, ACTION_START_OPTIMIZATION)) {
            trigger_band = (amas_wifi_bhmode & trigger_band);
            snprintf(str_active, sizeof(str_active), "%X", trigger_band);
            BH_VDBG("%s:%d amas_wlc_action = %s, amas_wlc_action_band = %02X\n",
                __FUNCTION__, __LINE__, nvram_safe_get("amas_wlc_action"),
                amas_wlc_action_band);

            BH_VDBG("%s:%d set %02X to amas_wlc_action_band for %s\n", __FUNCTION__,
                __LINE__, trigger_band, ACTION_START_OPTIMIZATION);
            nvram_set("amas_wlc_action_band", str_active);
            if (nvram_get_int("amas_wlc_action_state") != BUSY) // If amas_wlcconnect processing pre-request, skip doing OPT.
                sned_action_to_amas_wlcconnect(ACTION_START_OPTIMIZATION);
        } else if (!strcmp(action, ACTION_START_FOLLOW_CONNECTION)) {
            trigger_band = (amas_wifi_bhmode & trigger_band);
            snprintf(str_active, sizeof(str_active), "%X", trigger_band);
            BH_DBG("%s:%d amas_wlc_action = %s, amas_wlc_action_band = %02X\n",
                __FUNCTION__, __LINE__, nvram_safe_get("amas_wlc_action"),
                amas_wlc_action_band);

            BH_DBG("%s:%d set %02X to amas_wlc_action_band for %s\n", __FUNCTION__,
                __LINE__, trigger_band, ACTION_START_FOLLOW_CONNECTION);
            nvram_set("amas_wlc_action_band", str_active);
            if (nvram_get_int("amas_wlc_action_state") != BUSY)  // If amas_wlcconnect processing pre-request, skip doing follow band.
                sned_action_to_amas_wlcconnect(ACTION_START_FOLLOW_CONNECTION);
        } else {
            BH_VDBG("%s:%d Not do anything.\n", __FUNCTION__, __LINE__);
        }
        free(action);
    } else { // Don't do anything. Update status.
        update_status();
    }

    return 0;
}

static void cal_cost_for_store(int defif, int index, float *cost)
{
    if (*cost >= 0) {
        *cost = *cost * 10;
        return;
    }

    if (defif < 0 || index < 0) {
        *cost = -1;
        return;
    }

    if (defif <= ETH_MAX_BASE) {  // ETH or PLC
        char amas_eth_linkrate[] = "amas_ethXXX_linkrate", amas_eth_ethType[] = "amas_ethXXX_ethType";
        snprintf(amas_eth_linkrate, sizeof(amas_eth_linkrate), "amas_eth%d_linkrate", index);
        snprintf(amas_eth_ethType, sizeof(amas_eth_ethType), "amas_eth%d_ethType", index);
        int linkrate = nvram_get_int(amas_eth_linkrate);

        if (nvram_get_int(amas_eth_ethType) == ETH_TYPE_PLC) {  // PLC
            *cost = cal_plc_cost(0, linkrate);
        } else {  // ETH
            if (linkrate <= 10)
                *cost = 9;
            else if (linkrate <= 100)
                *cost = 3;
            else
                *cost = 0;
        }
    } else {  // WIFI
        char amas_wlc_rssi[] = "amas_wlcXXX_rssi";
        snprintf(amas_wlc_rssi, sizeof(amas_wlc_rssi), "amas_wlc%d_rssi", index);
        int rssi = nvram_get_int(amas_wlc_rssi);

        if (rssi > -60)
            *cost = 1;
        else if (rssi > -70)
            *cost = 1 + 1 * (-60 - rssi) / 10.0;
        else if (rssi > -80)
            *cost = 4 + 4 * (-70 - rssi) / 10.0;
        else
            *cost = 8 + 8 * (-80 - rssi) / 10.0;
    }

    if (*cost > 0)
        *cost = *cost * 10;

    return;
}

/**
 * @brief Reset info for lldpd config.
 *
 */
void reset_lldpd_info()
{
    if (!pids("lldpd"))
        return;

    /* cost */
    if (amas_set_cost_ret != AMAS_RESULT_SUCCESS)
        update_cost(nvram_get_int("cfg_cost"));

    /* rssiscore */
    if (amas_set_rssi_score_ret != AMAS_RESULT_SUCCESS)
        update_rssiscore(nvram_get_int("amas_re_rssiscore"));
}

int select_bh_path(int SUMeth, int SUMband, int amas_eth_bhmode, int amas_wifi_bhmode, int amas_costmode, int amas_rssiscoremode)
{
#ifdef BHCTL_LESS_DBGMSG
	static char old_selif[64] = { 0 };
	static int old_defif = 0, old_rssiscore = -1;
	static float old_cost = 0;
#endif
    int j = 0;
    char wif[256]={0}, *next = NULL;
    char ifi_preifx[64];
    char selif[64] = {0};
#ifdef RTCONFIG_BROOP
    int chk_del_wifi_brif = -1;
    int chk_del_eth_brif = -1;
#ifdef RTCONFIG_DPSTA
    int chk_add_brif = -1;
#endif
#endif
    int SUMif = SUMeth + SUMband;
    int defif = -1, rssiscore = 100;
    char nvrampar[32];
    int compatible_defif = 0;
#ifdef RTCONFIG_AMAS_ETHDETECT
    static int change_threshold = 3;
    static int bh_change = 0;
#endif
    float cost = -1;
    int if_index = -1;
	int bh_changed = 0;
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    get_avaupif_by_costsetting(SUMeth, SUMband, amas_costmode, amas_rssiscoremode);

    isfirst_check();

    prefer_node_check();

    for (j = 0; j < SUMif; j++) {
#if defined(BHCTL_LESS_DBGMSG)
        if (!memcmp(&old_ava_upifi_list[j], &ava_upifi_list[j], sizeof(ifi_priority)))
            continue;
        BH_DBG("ava_upifi_list[%d].defif=%02X index=%02X priority=%d cost=%.1f rssiscore=%d isfirst=%d\n",
               j, ava_upifi_list[j].defif, ava_upifi_list[j].index, ava_upifi_list[j].priority,
               ava_upifi_list[j].cost, ava_upifi_list[j].rssiscore, ava_upifi_list[j].isfirst);

        memcpy(&old_ava_upifi_list[j], &ava_upifi_list[j], sizeof(ifi_priority));
#else
        BH_DBG(
            "\n ####### ava_upifi_list #############\n"
            "ava_upifi_list[%d].defif\t\t\t= %02X\n"
            "ava_upifi_list[%d].index\t\t\t= %02X\n"
            "ava_upifi_list[%d].priority\t\t= %d\n"
            "ava_upifi_list[%d].cost\t\t\t= %.1f\n"
            "ava_upifi_list[%d].rssiscore\t\t= %d\n"
            "ava_upifi_list[%d].isfirst\t\t= %d\n",
            j, ava_upifi_list[j].defif,
            j, ava_upifi_list[j].index,
            j, ava_upifi_list[j].priority,
            j, ava_upifi_list[j].cost,
            j, ava_upifi_list[j].rssiscore,
            j, ava_upifi_list[j].isfirst);
#endif
    }

    if(ava_upifi_list[0].defif > 0)
    {

        if (amas_wifi_bhmode > 0 && amas_eth_bhmode > 0)
        {
            if (ava_upifi_list[0].defif > 0 && ava_upifi_list[0].defif <= ETH_MAX_BASE)
                snprintf(ifi_preifx, sizeof(ifi_preifx), "amas_eth%d_", ava_upifi_list[0].index);
            if (ava_upifi_list[0].defif > ETH_MAX_BASE && ava_upifi_list[0].defif <= WL_MAX_BASE)
                snprintf(ifi_preifx, sizeof(ifi_preifx), "amas_wlc%d_", ava_upifi_list[0].index);

            defif = ava_upifi_list[0].defif;
            rssiscore = ava_upifi_list[0].rssiscore;
            cost = ava_upifi_list[0].cost;
            if_index = ava_upifi_list[0].index;
            snprintf(nvrampar, sizeof(nvrampar), "%sifname", ifi_preifx);
        }

        if (amas_eth_bhmode == 0)
        {
            if (amas_wifi_bhmode == 0x11) // 2.4G only
            {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif == WL2G_U)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_ifname", ava_upifi_list[j].index);
                        defif =  ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
            else if (amas_wifi_bhmode == 0x22) // 5G1 only
            {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif == WL5G1_U)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_ifname", ava_upifi_list[j].index);
                        defif =  ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
            else if (amas_wifi_bhmode == 0x44) // 5G2 only
            {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif == WL5G2_U)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_ifname", ava_upifi_list[j].index);
                        defif =  ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
            else
            {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif > ETH_MAX_BASE && ava_upifi_list[j].defif <= WL_MAX_BASE)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_ifname", ava_upifi_list[j].index);
                        defif = ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
        }

        if (amas_eth_bhmode > 0 && amas_wifi_bhmode == 0)
        {
            if (amas_eth_bhmode == 0x11)
            {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif == ETH1_U)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_ifname", ava_upifi_list[j].index);
                        defif =  ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
            else if (amas_eth_bhmode == 0x22)
            {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif == ETH2_U)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_ifname", ava_upifi_list[j].index);
                        defif =  ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
            else {
                for (j =0; j < SUMif; j++)
                {
                    if (ava_upifi_list[j].defif > 0 && ava_upifi_list[j].defif <= ETH_MAX_BASE)
                    {
                        snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_ifname", ava_upifi_list[j].index);
                        defif =  ava_upifi_list[j].defif;
                        rssiscore = ava_upifi_list[j].rssiscore;
                        cost = ava_upifi_list[j].cost;
                        if_index = ava_upifi_list[j].index;
                        break;
                    }
                }
            }
        }


        snprintf(selif, sizeof(selif), "%s", nvram_safe_get(nvrampar));
#ifdef BHCTL_LESS_DBGMSG
	if (old_defif != defif || strcmp(old_selif, selif) || old_cost != cost || old_rssiscore != rssiscore) {
		BH_DBG("%s:%d selif=%s, defif=%02X, cost=%.1f, rssiscore=%d\n",
			__func__, __LINE__, selif, defif, cost, rssiscore);
		old_defif = defif;
		strlcpy(old_selif, selif, sizeof(old_selif));
		old_cost = cost;
		old_rssiscore = rssiscore;
	}
#else
        BH_DBG("%s:%d selif = %s, defif = %02X, cost = %.1f, rssiscore = %d\n", __FUNCTION__, __LINE__, selif, defif, cost, rssiscore);
#endif

    #ifdef RTCONFIG_DPSTA
        if (Is_dpsta)
        {
            if (defif > ETH_MAX_BASE && defif <= WL_MAX_BASE)
            {
                snprintf(selif, sizeof(selif), "%s", nvram_safe_get("sta_phy_ifnames"));

                if (nvram_get_int("dpsta_policy") == DPSTA_POLICY_AUTO)
                {
                    for (j =0; j < SUMif; j++)
                    {
                        if (ava_upifi_list[j].defif > ETH_MAX_BASE && ava_upifi_list[j].defif <= WL_MAX_BASE)
                            defif |= ava_upifi_list[j].defif;
                    }
                }

                if (nvram_get_int("dpsta_policy") == DPSTA_POLICY_AUTO_1)
                {
                        ;//don't need recalculate defif value.
                }
            }
        }
    #endif

        if (defif >= ETH1_U && defif <= ETH_MAX_BASE)
            compatible_defif = compatible_defif | ETH;
        if ((defif & WL2G_U) == WL2G_U)
            compatible_defif = compatible_defif | WL_2G;
        if ((defif & WL5G1_U) == WL5G1_U)
            compatible_defif = compatible_defif | WL_5G;
        if ((defif & WL5G2_U) == WL5G2_U)
            compatible_defif = compatible_defif | WL_5G_1;
        if ((defif & WL6G_U) == WL6G_U)
            compatible_defif = compatible_defif | WL_6G;
    }
    if(defif == -1)
        compatible_defif = -1;

    BH_VDBG("defif = %02X, compatible_defif = %d\n", defif, compatible_defif);

#ifdef RTCONFIG_AMAS_ETHDETECT
    // This is for loop detect.
    // avoid the bh path(ETH->???) is be changed too fast.
    if (defif != last_defif) {
        if ((last_defif >= ETH1_U && last_defif <= ETH_MAX_BASE)) {  // ETH -> ???
            if (bh_change < change_threshold && strcmp(nvram_safe_get("cfg_group"), "")) {
                BH_DBG("BH path different. Change threshole(%d) Change counts(%d). Don't changed.\n", change_threshold, bh_change);
                defif = last_defif;                              // keep last path.
                rssiscore = nvram_get_int("amas_re_rssiscore");  // keep rssiscore
                cost = nvram_get_int("cfg_cost");                // keep cost
                /* update compatible_defif based on defif */
                compatible_defif = 0;
                if (defif >= ETH1_U && defif <= ETH_MAX_BASE)
                    compatible_defif = compatible_defif | ETH;
                if ((defif & WL2G_U) == WL2G_U)
                    compatible_defif = compatible_defif | WL_2G;
                if ((defif & WL5G1_U) == WL5G1_U)
                    compatible_defif = compatible_defif | WL_5G;
                if ((defif & WL5G2_U) == WL5G2_U)
                    compatible_defif = compatible_defif | WL_5G_1;
                if ((defif & WL6G_U) == WL6G_U)
                    compatible_defif = compatible_defif | WL_6G;
                if(defif == -1)
                    compatible_defif = -1;

                if (cost > 0)
                    cost = cost / 10;
                snprintf(selif, sizeof(selif), "%s", nvram_safe_get("amas_ifname"));  // keep selif name
                bh_change++;
            } else {
                bh_change = 0;
                change_threshold = (rand_r(&rand_seed) % 4) + 2;  // rand: 2 ~ 5
            }
        }
    }
#endif

    if((defif != nvram_get_int("amas_path_stat_v3") || defif != nvram_get_int("amas_path_report_v3")))
    {
        nvram_set_int("amas_path_stat_v3", defif);
        nvram_set_int("amas_path_stat", compatible_defif);

#ifdef RTCONFIG_CFGSYNC
        if (nvram_get_int("cfg_alive") == 1)
        {
            BH_DBG("======= Update path (amas_path_stat_v3 = %02X) to cfg_mnt.=======\n", defif);
            send_event_to_cfgmnt(EID_RC_REPORT_PATH);
            nvram_set_int("amas_path_report_v3", defif);
        }
        else
        BH_DBG("Can't Update path (amas_path_stat_v3 = %02X) to cfg_mnt. (disconnect with cfg_server)\n", defif);
#endif
		bh_changed = 1;
    }

    if (!strncmp(selif, "", sizeof(selif)))
    {
#ifdef RTCONFIG_BROOP // Keep the codes for BROOP function.
#ifdef RTCONFIG_DPSTA
        if (Is_dpsta) // add default path
        {
                       if (!strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname")) || !strcmp(nvram_safe_get("amas_ifname"), "")) {
#ifdef RTCONFIG_BROOP
               if(!nvram_match("reset_broop", "1"))
#endif
                foreach(wif, nvram_safe_get("eth_ifnames"), next) {
                    chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
                    if (chk_del_eth_brif != -1)
                        dbG("Delete %s from %s successfully.(5)\n", wif, nvram_safe_get("lan_ifname"));
                }

                foreach (wif, nvram_safe_get("sta_phy_ifnames"), next) {
                    pre_addif_bridge(defif);
                    chk_add_brif = ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), wif);
                    if (chk_add_brif != -1) {
                        BH_DBG("Add %s to %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
                        logmessage("BHC", "Add %s to %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
                        nvram_set("amas_ifname", wif);
                        post_addif_bridge(defif);
#if defined(RTCONFIG_AMAS_WGN)
                       	wgn_update_bridge_ifname(ARG_addif, wif);
#endif // RTCONFIG_AMAS_WGN
                    }
                }
            }
        }
        else
#endif
        {
            foreach(wif, nvram_safe_get("sta_phy_ifnames"), next)
            {
                int wif_defif = get_defif(wif);
                if (wif_defif != -1)
                    pre_delif_bridge(wif_defif);
                chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
                if (chk_del_wifi_brif != -1)
                {
#if defined(RTCONFIG_AMAS_WGN)
                   wgn_update_bridge_ifname(ARG_delif, wif);
#endif // RTCONFIG_AMAS_WGN
                    if (wif_defif != -1)
                        post_delif_bridge(wif_defif);
                    BH_DBG("Delete %s from %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
					if (!nvram_match("amas_ifname", ""))
						nvram_set("amas_ifname", "");
                }
            }

#ifdef RTCONFIG_BROOP
           if(!nvram_match("reset_broop", "1"))
#endif
            foreach(wif, nvram_safe_get("eth_ifnames"), next)
            {
                chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
                if (chk_del_eth_brif != -1)
                {
                    BH_DBG("Delete %s from %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
					if (!nvram_match("amas_ifname", ""))
						nvram_set("amas_ifname", "");
                }
            }
        }
#else  // RTCONFIG_BROOP
        if (Is_dpsta) {  // add default path
            foreach(wif, nvram_safe_get("sta_phy_ifnames"), next) {
                nvram_set("amas_ifname", wif);
            }
        } else {
			if (!nvram_match("amas_ifname", ""))
				nvram_set("amas_ifname", "");
        }
#endif
    }
    else if (strcmp(selif, nvram_safe_get("amas_ifname")))
    {
#ifdef RTCONFIG_BROOP // keep the codes for BROOP
        foreach(wif, nvram_safe_get("sta_phy_ifnames"), next)
        {
            int wif_defif = get_defif(wif);
            if (wif_defif != -1)
                pre_delif_bridge(wif_defif);
            chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
            if (chk_del_wifi_brif != -1)
            {
#if defined(RTCONFIG_AMAS_WGN)
               	wgn_update_bridge_ifname(ARG_delif, wif);
#endif  // RTCONFIG_AMAS_WGN
                if (wif_defif != -1)
                    post_delif_bridge(wif_defif);
                BH_DBG("Delete %s from %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
				if (!nvram_match("amas_ifname", ""))
					nvram_set("amas_ifname", "");
            }
        }

#ifdef RTCONFIG_BROOP
       if(!nvram_match("reset_broop", "1"))
#endif
        foreach(wif, nvram_safe_get("eth_ifnames"), next)
        {
            chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
            if (chk_del_eth_brif != -1)
            {
                BH_DBG("Delete %s from %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
				if (!nvram_match("amas_ifname", ""))
					nvram_set("amas_ifname", "");
            }
        }


        BH_DBG("===== add lan ifname(%s) to bridge !!!!.\n", selif);
        pre_addif_bridge(defif);
        chk_add_brif = ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), selif);
        if (chk_add_brif != -1)
        {
            BH_DBG("Add %s to %s successfully.\n", selif, nvram_safe_get("lan_ifname"));
            logmessage("BHC","Add %s to %s successfully.\n", selif, nvram_safe_get("lan_ifname"));
            nvram_set("amas_ifname", selif);
            post_addif_bridge(defif);
        }
#endif
        nvram_set("amas_ifname", selif);
    }
	
	if (bh_changed == 1)
		post_bh_changed(defif);

    if (rssiscore != nvram_get_int("amas_re_rssiscore"))
    {
        BH_VDBG("[%d]=======rssiscore(%d), amas_re_rssiscore(%d)========\n",__LINE__,rssiscore, nvram_get_int("amas_re_rssiscore"));
        update_rssiscore(rssiscore);
    }

    if (aimesh_alg == AIMESH_ALG_COST) {
        cal_cost_for_store(defif, if_index, &cost);
        if (!nvram_get("cfg_cost") || cost != nvram_get_int("cfg_cost")) {
            update_cost((int)cost);
        }
    }

    check_connection_status_for_action(defif, SUMeth, SUMband, amas_wifi_bhmode);

    if ((last_defif > 0 && last_defif <= ETH_MAX_BASE) && (defif >= WL2G_U && defif < WL_MAX_BASE))
    {
        BH_DBG("=======Set trigger_all_connect = 1========\n");
        trigger_all_connect = 1;
    }

    if (defif != last_defif)
    {
        BH_DBG("=======Change last_defif from %02X to %02X========\n",  last_defif, defif);
        last_defif = defif;
    }
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
    detect_pap_wds();
#endif    

    return 0;
}

void self_optimization_event(int sig)
{

    int j = 0;
    int SUMband = get_wl_count();
    char nvrampar[64], optmz_nvram[64];
    int amas_optmz_rssi_threshold = 0;
    int amas_optmz_tigger_count = 0;

    for (j = 0; j < SUMband; j++)
    {
        /* is_self_optmz_stage() ==> 0: don't to do self-optimize, 1: wait for self-optimize stage.*/
        if(wlbrs_list[j].use == 1 && is_self_optmz_stage(wlbrs_list[j].bandIndex) == 0 &&  wlbrs_list[j].state == WLC_STATE_CONNECTED)
        {
            BH_DBG("wlbrs_list[%d].rssi(%d), wlbrs_list[%d].optmz_base_rssi(%d), wlbrs_list[%d].optmz_match_count(%d)\n", j, wlbrs_list[j].rssi,  j, wlbrs_list[j].optmz_base_rssi, j,  wlbrs_list[j].optmz_match_count);

            if( wlbrs_list[j].optmz_base_rssi == 0)
            {
                wlbrs_list[j].optmz_base_rssi = wlbrs_list[j].rssi;
                wlbrs_list[j].optmz_match_count = 0;
            }
            else
            {
                snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_optmz_rssi_threshold", wlbrs_list[j].bandIndex);
                amas_optmz_rssi_threshold = nvram_get_int(nvrampar) ? : -12;

                snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_optmz_tigger_count", wlbrs_list[j].bandIndex);
                amas_optmz_tigger_count = nvram_get_int(nvrampar) ? : 3;

                if (wlbrs_list[j].rssi - wlbrs_list[j].optmz_base_rssi <  amas_optmz_rssi_threshold)
                {
                     wlbrs_list[j].optmz_match_count++;

                    if (wlbrs_list[j].optmz_match_count >= amas_optmz_tigger_count)
                    {
                        BH_DBG("====== Set amas_wlc%d_optmz to 1\n", wlbrs_list[j].bandIndex);
                        snprintf(optmz_nvram, sizeof(optmz_nvram), "amas_wlc%d_optmz", wlbrs_list[j].bandIndex);
                        nvram_set_int(optmz_nvram, 1);
                    }
                }
                else
                {
                    wlbrs_list[j].optmz_base_rssi = wlbrs_list[j].rssi;
                    wlbrs_list[j].optmz_match_count = 0;
                }
            }
        }
        else
        {
            wlbrs_list[j].optmz_base_rssi = 0;
            wlbrs_list[j].optmz_match_count = 0;
        }
    }
    alarm(self_opt_timer);

}

void monitor_backhaul_status(int SUMband)
{
    pid_t pid;
    int bh_monitor_timer = nvram_get_int("bh_monitor_timer") ? : MONITOR_BACKHAUL_TIMER;
    int have_bh = 0, last_bh = -1, now_bh = -1;
    time_t disc_time = 0, now = 0;
    time_t disc_log_time = nvram_get_int("disc_log_time") ? : DISCONNECT_LOG_TIME;
    int i = 0, connected = 0, last_connected = -1;
    char wlc_prefix[16], tmp[100];
    int wlc_state = 0, wlc_index = 0;

    if ((pid = fork()) < 0) {
        BH_DBG("fork fail\n");
        return;
    } else {
        if (pid == 0) {	/* child */
#ifdef RTCONFIG_BROOP
            int oop_rmeth = 0;
            char wif[256]={0}, *next = NULL, *oopif = NULL;
#endif
            /* reset signal */
            signal(SIGALRM, SIG_IGN);

            /* free */
            if (wlbrs_list != NULL) {
                free(wlbrs_list);
                wlbrs_list = NULL;
            }

            if (ethbrs_list != NULL) {
                free(ethbrs_list);
                ethbrs_list = NULL;
            }

            if (ava_upifi_list != NULL) {
                free(ava_upifi_list);
                ava_upifi_list = NULL;
            }
#if defined(BHCTL_LESS_DBGMSG)
			/* free */
			if (old_wlbrs_list != NULL) {
				free(old_wlbrs_list);
				old_wlbrs_list = NULL;
			}

			if (old_ethbrs_list != NULL) {
				free(old_ethbrs_list);
				old_ethbrs_list = NULL;
			}

			if (old_ava_upifi_list != NULL) {
				free(old_ava_upifi_list);
				old_ava_upifi_list = NULL;
			}
#endif

            disc_time = uptime();

            while (1) {
                bhctl_dbg = nvram_get_int("bhctl_dbg");

                /* check the connection status of wlc */
                connected = 0;
                for (i = 0; i < SUMband; i++) {
                    snprintf(wlc_prefix, sizeof(wlc_prefix), "amas_wlc%d_", i);
                    if (nvram_get_int(strcat_r(wlc_prefix, "state", tmp)) == WLC_STATE_CONNECTED)
                        connected++;
                }

                if (last_connected != connected) {
                    BH_DBG("WiFi connection status change.\n");
                    logmessage("BHC","WiFi connection status change.\n");

                    for (i = 0; i < SUMband; i++) {
                        snprintf(wlc_prefix, sizeof(wlc_prefix), "amas_wlc%d_", i);
                        wlc_state = nvram_get_int(strcat_r(wlc_prefix, "state", tmp));
                        wlc_index = nvram_get_int(strcat_r(wlc_prefix, "index", tmp));
                        BH_DBG("bandindex(%d): state is %d\n", wlc_index, wlc_state);
                        logmessage("BHC","bandindex(%d): state is %d\n", wlc_index, wlc_state);
                    }

                    last_connected = connected;
                }

                /* check backhaul status */
                now_bh = nvram_get_int("amas_path_stat");
                now = uptime();
                if (last_bh != now_bh) {
                    disc_time = now;
                    BH_DBG("Topology change from %d to %d.\n", last_bh, now_bh);
                    logmessage("BHC", "Topology change from %d to %d.\n", last_bh, now_bh);
                    last_bh = now_bh;
                    if (now_bh != -1)
                        have_bh = 1;
                }
                else
                {
                    if (have_bh) {
                        /* reset disconnect time */
                        if (nvram_get_int("cfg_alive") == 1)
                            disc_time = now;
                    }
                }

                if ((now - disc_time) >= disc_log_time) {
                    disc_time = now;
                    BH_DBG("Disconnected from CAP.\n");
                    logmessage("BHC", "Disconnected from CAP.\n");
                }
#ifdef RTCONFIG_BROOP
                if (nvram_match("amas_ethernet", "3") && nvram_match("cfg_alive", "1") && nvram_match("reset_broop", "1") && ismax_broop()) {
                    oop_rmeth = strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname")) ? 1 : 0;  // don't remove current amas path
                    if (oop_rmeth) {                                                                               // backhaul is wireless.
                        oopif = nvram_safe_get("eth_ifnames");
                        foreach (wif, oopif, next) {  // remove eth
                            if (get_uplinkports_status(wif) > 0) {
                                ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
                                _dprintf("\n\n>>>>>>> Remove %s from br due loop occuring <<<<<<\n\n", wif);
                                syslog(LOG_NOTICE, "Remove oopif %s from lan-bridge.", wif);
                            }
                        }
                        nvram_set("reset_broop", "2");
                    } else {  // backhaul is eth. removed wireless
                        oopif = nvram_safe_get("sta_phy_ifnames");
                        foreach (wif, oopif, next) {
                            int wif_defif = get_defif(wif);
                            if (wif_defif != -1)
                                pre_delif_bridge(wif_defif);
                            int chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
                            if (chk_del_wifi_brif != -1) {
#if defined(RTCONFIG_AMAS_WGN)
                               	wgn_update_bridge_ifname(ARG_delif, wif);
#endif // RTCONFIG_AMAS_WGN
                                if (wif_defif != -1)
                                    pre_delif_bridge(wif_defif);
                                _dprintf("\n\n>>>>>>> Remove %s from br due loop occuring <<<<<<\n\n", wif);
                                syslog(LOG_NOTICE, "Remove oopif %s from lan-bridge.", wif);
                            }
                        }
                    }
                }
#endif
                sleep(bh_monitor_timer);
            }
        }
    }
}

static void amas_bhctrl_leave(int signo)
{
    if (wlbrs_list != NULL)
        free(wlbrs_list);

    if (ethbrs_list != NULL)
        free(ethbrs_list);

    if (ava_upifi_list != NULL)
        free(ava_upifi_list);
#if defined(BHCTL_LESS_DBGMSG)
	if (old_wlbrs_list != NULL)
		free(old_wlbrs_list);

	if (old_ethbrs_list != NULL)
		free(old_ethbrs_list);

	if (old_ava_upifi_list != NULL)
		free(old_ava_upifi_list);
#endif

    dbG("\n## amas_bhctrl.safeexit ##\n");
    exit(0);
}

int amas_bhctrl_main(void)
{

#ifdef RTCONFIG_SW_HW_AUTH
    time_t timestamp = time(NULL);
    char in_buf[48];
    char out_buf[65];
    char hw_out_buf[65];
    char *hw_auth_code = NULL;

    if (!(getAmasSupportMode() & AMAS_RE)) {
        dbG("not support RE\n");
        return 0;
    }

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
    if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
        dbG("This is ASUS router\n");
    }
    else {
        dbG("This is not ASUS router\n");
        return 0;
    }
#else
    dbG("auth check is disabled\n");
    return 0;
#endif

    FILE *fp = NULL;


    /* write pid */
    if ((fp = fopen("/var/run/amas_bhctrl.pid", "w")) != NULL)
    {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }

    self_opt_timer =  nvram_get_int("amas_self_opt_timer") ? : 30;

    nvram_set("amas_ifname", "");
    nvram_set("amas_send_action", "");
    nvram_set_int("amas_path_stat", -1);
    nvram_set_int("amas_path_stat_v3", -1);
    nvram_set_int("amas_re_rssiscore", 100);
	nvram_unset("plc_head");

    amas_wait_wifi_ready();

    bhctl_dbg = nvram_get_int("bhctl_dbg");
    amas_bhctl_timer = nvram_get_int("amas_bhctl_timer") ? : STATUS_TIMER;
    amas_check_no_loop_time = nvram_get_int("amas_check_no_loop_time") ? : 2;
    wait_wifi = (nvram_get_int("wait_wifi") < MAX_WIFI_WAIT_TIME ? MAX_WIFI_WAIT_TIME : nvram_get_int("wait_wifi")) / amas_bhctl_timer; // reset wait_wifi
    wait_band = (nvram_get_int("amas_wait_band") < MAX_WIFI_BAND_WAIT_TIME ? MAX_WIFI_BAND_WAIT_TIME : nvram_get_int("amas_wait_band")) / amas_bhctl_timer;  // reset wait_band
    reset_plc_wait_wifi();

    int SUMband = get_wl_count();
    int SUMeth = get_eth_count();
    int amas_eth_bhmode = 0;
    int amas_wifi_bhmode = 0;
    int amas_costmode = 0;
    int amas_rssiscoremode = 0;
    char optmz_nvram[64];
    int j = 0;
    int aimesh_alg = nvram_get_int("aimesh_alg") ? : AIMESH_ALG_COST;

    /* signal */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, amas_bhctrl_leave);

    wlbrs_list = (struct _wl_br_status *) malloc(SUMband *sizeof(struct _wl_br_status));
    if (wlbrs_list == NULL) {
        dbG("Can't alloc memory for %s (wlbrs_list)\n", __FILE__);
        return 0;
    }

    ethbrs_list = (struct _eth_br_status *) malloc(SUMeth *sizeof(struct _eth_br_status));
    if (ethbrs_list == NULL) {
        dbG("Can't alloc memory for %s (ethbrs_list)\n", __FILE__);
        return 0;
    }

    ava_upifi_list = (struct _ifi_priority *) malloc((SUMband+SUMeth) *sizeof(struct _ifi_priority));
    if (ava_upifi_list == NULL) {
        dbG("Can't alloc memory for %s (ava_upifi_list)\n", __FILE__);
        return 0;
    }

    memset(wlbrs_list, 0x00, SUMband *sizeof(struct _wl_br_status));
    memset(ethbrs_list, 0x00, SUMeth *sizeof(struct _eth_br_status));
    memset(ava_upifi_list, 0x00, (SUMband+SUMeth) *sizeof(struct _ifi_priority));

#if defined(BHCTL_LESS_DBGMSG)
	old_wlbrs_list = (struct _wl_br_status *) malloc(SUMband *sizeof(struct _wl_br_status));
	if (old_wlbrs_list == NULL) {
		dbG("Can't alloc memory for %s (old_wlbrs_list)\n", __FILE__);
		return 0;
	}
	old_ethbrs_list = (struct _eth_br_status *) malloc(SUMeth *sizeof(struct _eth_br_status));
	if (old_ethbrs_list == NULL) {
		dbG("Can't alloc memory for %s (old_ethbrs_list)\n", __FILE__);
		return 0;
	}

	old_ava_upifi_list = (struct _ifi_priority *) malloc((SUMband+SUMeth) *sizeof(struct _ifi_priority));
	if (old_ava_upifi_list == NULL) {
		dbG("Can't alloc memory for %s (old_ava_upifi_list)\n", __FILE__);
		return 0;
	}

	memset(old_wlbrs_list, 0x00, SUMband *sizeof(struct _wl_br_status));
	memset(old_ethbrs_list, 0x00, SUMeth *sizeof(struct _eth_br_status));
	memset(old_ava_upifi_list, 0x00, (SUMband+SUMeth) *sizeof(struct _ifi_priority));
#endif

#ifdef RTCONFIG_DPSTA
   Is_dpsta = dpsta_mode();
#endif

	trans_to_bhmode(&amas_eth_bhmode, &amas_wifi_bhmode, &amas_costmode, &amas_rssiscoremode);

    BH_DBG("\n(%s) amas_eth_bhmode(%02X) amas_wifi_bhmode(%02X)\n", __FUNCTION__, amas_eth_bhmode, amas_wifi_bhmode);

    while (nvram_get_int("amas_status_init") != 1) {
        BH_DBG("Waiting for amas_status init.\n");
        sleep(1);
    }

    init_eth_status(SUMeth, amas_eth_bhmode);
    init_wlc_status(SUMband, amas_wifi_bhmode);

    while (!pids("lldpd")) {
        BH_DBG("Waiting for lldpd daemon.\n");
        sleep(1);
    }

    if (aimesh_alg == AIMESH_ALG_COST)
        update_cost(-1);  //  Init cost

#ifdef RTCONFIG_BROOP
       char *brif = nvram_safe_get("lan_ifname");
       char *ethif = nvram_safe_get("eth_ifnames");
       _dprintf("\n(re)run amas_bhctrl, check eth_ifnames=%s\n\n", nvram_safe_get("eth_ifnames"));
       if(!is_bridged(brif, ethif) || !nvram_match("stop_resetbr", "1"))
               nvram_set("reset_broop", "0");
       else
               _dprintf("\nkeep broop state\n");

       broop_counts_max = (nvram_get_int("broop_max") > 0)? nvram_get_int("broop_max"): 0;
#endif

    trigger_amas_wlcconnect(SUMband, amas_wifi_bhmode);

    signal(SIGALRM, self_optimization_event);
    alarm(self_opt_timer);

    monitor_backhaul_status(SUMband);

    for (j = 0; j < SUMband; j++)
    {
        snprintf(optmz_nvram, sizeof(optmz_nvram), "amas_wlc%d_optmz", wlbrs_list[j].bandIndex);
        nvram_set_int(optmz_nvram, 0);
    }

    bhctrl_init_keep_waitting_wifi = 10;  // for waitting wireless

    init_rand_seed();

    while (1)
    {

        bhctl_dbg = nvram_get_int("bhctl_dbg");

        get_eth_info(SUMeth);

        get_wlc_info(SUMband);

        select_bh_path(SUMeth, SUMband, amas_eth_bhmode, amas_wifi_bhmode, amas_costmode, amas_rssiscoremode);
#ifdef RTCONFIG_AMAS_ETHDETECT
        detect_loop(SUMeth);
#endif
#ifndef RTCONFIG_BROOP
        bridge_action();
#endif
#if defined(RTCONFIG_DPSTA) && defined(RTCONFIG_AMAS_ETHDETECT)
        flush_dpsta_stalist(SUMeth, 0);
#endif
#ifdef RTCONFIG_BROOP
        reset_broop_ethif();
#endif
        reset_lldpd_info();

        sleep(amas_bhctl_timer);

        if (bhctrl_init_keep_waitting_wifi > 0) bhctrl_init_keep_waitting_wifi--;  // for waitting wireless
    }

    return 0;
}

