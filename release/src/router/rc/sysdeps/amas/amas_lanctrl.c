#include <rc.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <shutils.h>
#include <stdarg.h>
#include <netdb.h>
#include <arpa/inet.h>
#ifdef RTCONFIG_RALINK
#include <ralink.h>
#endif
#ifdef RTCONFIG_QCA
#include <qca.h>
#endif
#ifdef RTCONFIG_REALTEK
#include "../../shared/sysdeps/realtek/realtek.h"
#endif
#include <shared.h>

#include <syslog.h>
#include <bcmnvram.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <math.h>
#include <string.h>
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

#include <amas-utils.h>
//#include <cfg_common.h>
#include <cfg_string.h>
#include "amas.h"
#include <json.h>
#include <amas_path.h>

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#include <pthread.h>

int lanctl_dbg = 0;
int stack_size = 0;
wl_br_status *wlclist = NULL;

pthread_attr_t attr;
pthread_attr_t *attrp = NULL;

#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
pthread_mutex_t detectcap_mutex;
pthread_cond_t detectcap_cond;

pthread_mutex_t renewip_mutex;
pthread_cond_t renewip_cond;
#endif

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"amas_lanctl.log"
#define LC_DBG(fmt, arg...) \
	do {    \
		if(lanctl_dbg) \
		dbG("LC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("lanctl_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#else
#define LC_DBG(fmt, arg...) \
        do {    \
               if(lanctl_dbg) \
                dbG("LC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("lanctl_syslog"), "1")) \
				logmessage("LC", fmt, ##arg); \
        } while (0)
#endif

#define INTERVAL 2
#if defined(RTCONFIG_LANTIQ)  // Temporarily to use different defined value by platform.
#define IP_RENEW_INTERVAL 100 //rico 30 to 100
#else
#define IP_RENEW_INTERVAL 30
#endif
#define DFS_DETECT_INTERVAL 600
#define MAX_SUBIF_NUM 4

int lanctrl_timer = 2;
int renewip_timer = 30;
int dfs_timer = 600;
int lanlink = -1,  oldlanlink = -1;
int old_cfg_stat = -1;
int cfg_stat = -1;


void detect_dfs_event(int sig) {
	int dfs_status = 0, j = 0;
	int SUMband = get_wl_count();
	lanctl_dbg = nvram_get_int("lanctl_dbg");

	if (nvram_get_int("radar_detected") == 1)
	{
		LC_DBG("Monitor radar signal.\n");
		logmessage("lanctrl-radar detected", "Monitor radar signal");
		
		for(j = 0; j < SUMband; j++)
		{
			if (wlclist[j].use == 1 && wlclist[j].band == BAND_5G)
			{
				dfs_status = get_radar_status(wlclist[j].bandIndex);
				LC_DBG("dfs_status (Out of Service) = %d\n", dfs_status);
				if(dfs_status == 0)
				{
					logmessage("lanctrl-radar detected", "DFS timer is expired.");
					wlclist[j].state = get_psta_status(wlclist[j].bandIndex);

					if(wlclist[j].state != WLC_STATE_CONNECTED)
					{
						logmessage("lanctrl-radar detected", "%dG band is disconnect with P-AP, retry connecting...", wlclist[j].band);
						notify_rc("restart_amas_wlcconnect");
					}
					nvram_set_int("radar_detected", 0);
				}
			}
		}
	}

	alarm(dfs_timer);
}

#ifdef RTCONFIG_HND_ROUTER_AX
int need_downstream_ap_keep_down(int unit)
{
	int ret = 0, i = 0, bh_5g = 0, wlc_status = 0;
	int SUMband = get_wl_count();

	/* backhaul is ethernet, return it */
	if (nvram_get_int("amas_path_stat") == ETH) {
		LC_DBG("ethernet backahul, pass it.\n");
		return 0;
	}

	/* check unit is for 5G backhaul */
	for (i = 0; i < SUMband; i++) {
		//LC_DBG("i(%d), bandIndex(%d), use(%d), defif(%d)\n",
		//	i, wlclist[i].bandIndex, wlclist[i].use, wlclist[i].defif);
		if (wlclist[i].use == 1
			&& (wlclist[i].defif == WL_5G || wlclist[i].defif == WL_5G_1)
			&& unit == wlclist[i].bandIndex)
		{
			bh_5g = 1;
			break;
		}
	}

	/* unit is not for 5G backhaul */
	if (bh_5g == 0) {
		LC_DBG("unit(%d) is not for 5G backhaul, pass it.\n", unit);
		return 0;
	}

	wlc_status = get_psta_status(unit);
	LC_DBG("unit(%d), wlc_status(%d)\n", unit, wlc_status);
	if (wlc_status != WLC_STATE_CONNECTED)
		ret = 1;

	LC_DBG("unit(%d), ret(%d)\n", unit, ret);

	return ret;
}
#endif

void *detect_cap_status()
{

	pthread_detach(pthread_self());
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	struct timeval now;
	struct timespec outtime;
#endif
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char ifname[IFNAMSIZ] = { 0 };
	char word[256], *next;
	int unit = 0;
	char wl_ifnames[32] = { 0 };
	int wl_assoc = 0;
	int vidx = 0;

	while (1)
	{
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_lock(&detectcap_mutex);
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + lanctrl_timer;
		outtime.tv_nsec = 0;
		pthread_cond_timedwait(&detectcap_cond, &detectcap_mutex, &outtime);
#else
        sleep(lanctrl_timer);
#endif
		lanctl_dbg = nvram_get_int("lanctl_dbg");
		wl_assoc = 0;
		unit = 0;
		cfg_stat = nvram_get_int("cfg_alive");
		strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));

		//if (cfg_stat != old_cfg_stat) {
			if (cfg_stat == 0) {
				foreach (word, wl_ifnames, next)
				{
					for(vidx=1; vidx < MAX_SUBIF_NUM; vidx++)
					{
						memset(prefix, 0x00, sizeof(prefix));
						snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, vidx);
						if(nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
						{
							strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));
							wl_assoc = get_wlan_service_status(unit, vidx);
							if (wl_assoc == -1) continue;

							LC_DBG("cfg_alive = %d Disabled %s network service (wl_assoc = %d)\n",cfg_stat, ifname , wl_assoc);
							if(wl_assoc > 0)
							{
								LC_DBG("cfg_alive = %d Disabled %s network service finished\n",cfg_stat, ifname);
								set_wlan_service_status(unit, vidx, 0);
							}
						}
					}
					unit ++;
				}

			}
			else {
				unit = 0;
				foreach (word, wl_ifnames, next)
				{
#ifdef RTCONFIG_HND_ROUTER_AX
					if (need_downstream_ap_keep_down(unit)) {
						unit++;
						continue;
					}
#endif
					for(vidx=1; vidx < MAX_SUBIF_NUM; vidx++)
					{
						memset(prefix, 0x00, sizeof(prefix));
						snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, vidx);
						if(nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
						{
							strlcpy(ifname, nvram_safe_get(strcat_r(prefix, "ifname", tmp)), sizeof(ifname));

							wl_assoc = get_wlan_service_status(unit, vidx);
							if (wl_assoc == -1) continue;

							LC_DBG("cfg_alive = %d Enable %s network service (wl_assoc = %d)\n",cfg_stat, ifname , wl_assoc);

							if (wl_assoc <= 0)
							{
								LC_DBG("cfg_alive = %d Enable %s network service finished\n",cfg_stat, ifname);
								set_wlan_service_status(unit, vidx, 1);
							}
						}
					}
					unit ++;
				}
			}
			//old_cfg_stat = cfg_stat;
		//}
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_unlock(&detectcap_mutex);
#endif
	}
	pthread_exit(NULL);

}

void *renew_re_ip()
{
	pthread_detach(pthread_self());
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	struct timeval now;
	struct timespec outtime;
#endif
	while (1)
	{
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_lock(&renewip_mutex);
		renewip_timer = nvram_get_int("renewip_timer") ? : IP_RENEW_INTERVAL;
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + renewip_timer;
		outtime.tv_nsec = 0;
		pthread_cond_timedwait(&renewip_cond, &renewip_mutex, &outtime);
#else
        renewip_timer = nvram_get_int("renewip_timer") ? : IP_RENEW_INTERVAL;
        sleep(renewip_timer);
#endif
		lanctl_dbg = nvram_get_int("lanctl_dbg");

		cfg_stat = nvram_get_int("cfg_alive");

		if (cfg_stat == 0 && !nvram_get_int("stop_keep_renewip")) {  //regular renew ip
			LC_DBG("[renew_re_ip] keep renew IP...\n");
			killall("udhcpc", SIGUSR1);
		}
		else if (cfg_stat != old_cfg_stat) {		// renew ip, only status change.
			LC_DBG("[renew_re_ip] cfg_alive change to %d, renew IP...\n", cfg_stat);
			killall("udhcpc", SIGUSR1);
			old_cfg_stat = cfg_stat;
		}

#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_unlock(&renewip_mutex);
#endif
	}
	pthread_exit(NULL);

}

int amas_lanctrl_main() {

	FILE *fp = NULL;
	lanctrl_timer = nvram_get_int("lanctrl_timer") ? : INTERVAL;
	renewip_timer = nvram_get_int("renewip_timer") ? : IP_RENEW_INTERVAL;
	dfs_timer =  nvram_get_int("dfs_timer") ? : DFS_DETECT_INTERVAL;
	lanctl_dbg = nvram_get_int("lanctl_dbg");
	pthread_t detectcap_thread;
	pthread_t renewip_thread;
	int res = 0;
	int SUMband = get_wl_count();
#ifdef PTHREAD_STACK_SIZE
	stack_size = nvram_get_int("lanctrl_stack_size") ? : PTHREAD_STACK_SIZE;
#endif

	amas_wait_wifi_ready();

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

	/* write pid */
	if ((fp = fopen("/var/run/amas_lanctrl.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}


	wlclist = (struct _wl_br_status *) malloc(SUMband *sizeof(struct _wl_br_status));
	if (wlclist == NULL) {
		dbG("Can't alloc memory for %s\n", __FILE__);
		return 0;
	}
	init_wlc_status(wlclist, SUMband);
	signal(SIGALRM, detect_dfs_event);
	alarm(dfs_timer);

	attrp = &attr;
	/* change the default stack size of pthread */
	pthread_attr_init(&attr);

#ifdef PTHREAD_STACK_SIZE
	pthread_attr_setstacksize(&attr, stack_size);
#endif
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	res = pthread_mutex_init(&detectcap_mutex, NULL);
	if (res != 0) {
		dbG("[detect_cap_status] semaphore initialization failed\n");
		return 0;
	}

	res = pthread_cond_init(&detectcap_cond, NULL);
	if (res != 0) {
		dbG("[detect_cap_status] detectcap_cond initialization failed\n");
		return 0;
	}
#endif
	res = pthread_create (&detectcap_thread, attrp, detect_cap_status, NULL);
	if (res != 0) {
		dbG("detect cap thread creation failed");
		return 0;
	}
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	res = pthread_mutex_init(&renewip_mutex, NULL);
	if (res != 0) {
		dbG("[renew_re_ip] semaphore initialization failed\n");
		return 0;
	}

	res = pthread_cond_init(&renewip_cond, NULL);
	if (res != 0) {
		dbG("[renew_re_ip] detectcap_cond initialization failed\n");
		return 0;
	}
#endif
	res = pthread_create (&renewip_thread, attrp, renew_re_ip, NULL);
	if (res != 0) {
		dbG("renew_re_ip thread creation failed");
		return 0;
	}

	while (1)
	{
		pause();
	}

	if (attrp != NULL) pthread_attr_destroy(attrp);

	if (wlclist) free(wlclist);

	return 0;
}
