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
#include "../shared/sysdeps/realtek/realtek.h"
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
#include <pthread.h>

#include "amas.h"
#include <amas_path.h>

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#if !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
#if defined(RTCONFIG_DWB)
#include <amas_dwb.h>
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
pthread_mutex_t update_profile_mutex;
pthread_cond_t update_profile_cond;
#endif
int profile = 0;
int dwb_profile = 0;
int dwb_try_profile = 0;
int pcount = 0;
#endif
#endif //!NO_TRY_DWB_PROFILE
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
pthread_mutex_t monitor_connect_mutex;
pthread_cond_t monitor_connect_cond;
#endif

int wlc_dbg = 0;
wl_br_status *wlc_list = NULL;

static int all_disconnected_count = 0;

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG    "amas_wlcconnect.log"
#define WLC_DBG(fmt, arg...) \
	do {    \
		if(wlc_dbg) \
			dbG("WLC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("wlcconnect_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#else
#define WLC_DBG(fmt, arg...) \
        do {    \
               if(wlc_dbg) \
                dbG("WLC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("wlcconnect_syslog"), "1")) \
					logmessage("WLC", fmt, ##arg); \
        } while (0)
#endif

/* for checking upstream connection */
#define MAX_DISCONNECTION_COUNT	3
#define CHECKING_TIME		30
int max_disc_count = MAX_DISCONNECTION_COUNT;
int checking_time = CHECKING_TIME;
int disc_count = 0;
int check_count = 0;

void check_wifi_upstream_status(int wlc_wait_time, int connected)
{
	/* only for wireless upstream */
	if(!strcmp(nvram_safe_get("cfg_group"), ""))
		return;

	if (nvram_get_int("amas_path_stat") > ETH) {
		check_count++;
		if ((check_count * wlc_wait_time) < checking_time)
			return;

		check_count = 0;	/* reset count */

		WLC_DBG("connected(%d), cfg_alive(%d), disc_count(%d), max_disc_count(%d)\n",
			connected, nvram_get_int("cfg_alive"), disc_count, max_disc_count);

		if (connected == 1 && nvram_get_int("cfg_alive") == 0) {
			disc_count++;
			if (disc_count >= max_disc_count) {
				WLC_DBG("disc_count (%d) >= max_disc_count (%d)\n",
					disc_count, max_disc_count);
				disc_count = 0;
				if (!nvram_get_int("wlc_recover_stop"))
					notify_rc("restart_wireless");
			}
		}
		else
			disc_count = 0;
	}
	else
	{
		check_count = 0;
		disc_count = 0;
	}
}


void *monitor_connect_func()
{
	pthread_detach(pthread_self());
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	struct timeval now;
	struct timespec outtime;
#endif
	char tmp[128], prefix[] = "wlXXXXXXXXXX_mssid_";
	char wif[256]={0}, *next = NULL;
	int j = 0, unit = 0;
	int connected = 0, unstable = 0;
	int SUMband = 0;
	int wlc_wait_time = nvram_get_int("wl_time") ? : WLC_RETRY_INTERVAL;
	int WLC_DISCONN = nvram_get_int("wlc_retry_count") ? : WLC_RETRY_COUNT;
	int BACKOFF = nvram_get_int("wlc_backoff_count") ? : WLC_BACKOFF_COUNT;
	int STOP_CONN = nvram_get_int("wlc_stopconn_count") ? : WLC_STOP_COUNT;
	int CHECK_CONN = nvram_get_int("wlc_chkstable_count") ? : WLC_CHKSTABLE_COUNT;
	int RESET_CONN = nvram_get_int("wlc_resetconn_count") ? : WLC_RESET_COUNT;
	float fail_rate_threshold = nvram_get_int("fail_rate_threshold") ? : FAIL_RATE;
	float sucess_rate_threshold = nvram_get_int("success_rate_threshold") ? : SUCCESS_RATE;

#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
	dwb_profile = nvram_get_int("dwb_profile") ? : DWB_PROFILE;
	int wlc_retry_fh_count = nvram_get_int("wlc_retry_fh_count") ? : WLC_RETRY_FH_COUNT;
	int SEC_BACKOFF = 0;
	//int SEC_RETRY_COUNT = (BACKOFF / 3) ? : WLC_TRY_SECOND_PROFILE_COUNT;
	int dwb_band = nvram_get_int("dwb_band");
	int change_freq = nvram_get_int("wlc_sec_profile_freq") ? : WLC_TRY_SECOND_PROFILE_COUNT;
	int sec_backoff_count = nvram_get_int("wlc_sec_backoff_count") ? : WLC_BACKOFF_COUNT;
	int sec_retry_threshold = change_freq + (SEC_BACKOFF * sec_backoff_count);
	profile = dwb_profile;
#endif


	/* for checking wifi upstream */
	max_disc_count = nvram_get_int("max_disc_count") ? : MAX_DISCONNECTION_COUNT;
	checking_time = nvram_get_int("us_checking_time") ? : CHECKING_TIME;
	SUMband = get_wl_count();

	for (j = 0; j < SUMband; j++) 
	{
		memset(prefix, 0x00, sizeof(prefix));
		sprintf(prefix, "wlc%d_", j);
		nvram_set_int(strcat_r(prefix, "state", tmp), WLC_STATE_INITIALIZING);
		nvram_set_int(strcat_r(prefix, "sbstate", tmp), WLC_STOPPED_REASON_NONE);
	}

	j = 0;
	//Get number of bands and set initial status for wlc.
	foreach(wif, nvram_safe_get("wl_ifnames"), next) {
        snprintf(tmp, sizeof(tmp), "wlc%d_status", j);
		nvram_unset(tmp);
		j++;
	}


	nvram_set_int("wlc_state", WLC_STATE_INITIALIZING);
	nvram_set_int("wlc_sbstate", WLC_STOPPED_REASON_NONE);

	wlc_list = (struct _wl_br_status *) malloc(SUMband *sizeof(struct _wl_br_status));

	if(wlc_list == NULL) {
		WLC_DBG("Can't alloc memory for %s\n", __FILE__);
		goto error;
	}

	init_wlc_status(wlc_list, SUMband);
	while (1)
	{
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_lock(&monitor_connect_mutex);
		gettimeofday(&now, NULL);
		wlc_wait_time = nvram_get_int("wl_time") ? : WLC_RETRY_INTERVAL;
		outtime.tv_sec = now.tv_sec + wlc_wait_time;
		outtime.tv_nsec = 0;
		pthread_cond_timedwait(&monitor_connect_cond, &monitor_connect_mutex, &outtime);
#else
        wlc_wait_time = nvram_get_int("wl_time") ? : WLC_MONITOR_PROFILE_INTERVAL;
        sleep(wlc_wait_time);
#endif
		wlc_dbg = nvram_get_int("wlc_dbg");
		unit = nvram_get_int("wlc_band");

#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
		dwb_profile = nvram_get_int("dwb_profile") ? : DWB_PROFILE;
		dwb_band = nvram_get_int("dwb_band");

		if(nvram_get("dwb_profile") != NULL && nvram_get_int("dwb_profile") != dwb_profile && dwb_try_profile == profile) {
			profile = dwb_profile;
		}
#endif

		memset(prefix, 0x00, sizeof(prefix));

		for(j = 0; j < SUMband; j++)
		{
			sprintf(prefix, "wlc%d_", wlc_list[j].bandIndex);

			wlc_list[j].state = get_psta_status(wlc_list[j].bandIndex);

			if (wlc_list[j].state == WLC_STATE_CONNECTED) 
			{
				nvram_set_int(strcat_r(prefix, "state", tmp), WLC_STATE_CONNECTED);
			}
			else if (wlc_list[j].state == WLC_STATE_CONNECTING) 
			{
				nvram_set_int(strcat_r(prefix, "state", tmp), WLC_STATE_STOPPED);
				nvram_set_int(strcat_r(prefix, "sbstate", tmp), WLC_STOPPED_REASON_AUTH_FAIL);
			}
			else if (wlc_list[j].state == WLC_STATE_INITIALIZING) 
			{
				nvram_set_int(strcat_r(prefix, "state", tmp), WLC_STATE_STOPPED);
				nvram_set_int(strcat_r(prefix, "sbstate", tmp), WLC_STOPPED_REASON_NO_SIGNAL);
			}

			if((nvram_get(strcat_r(prefix, "status", tmp)) == NULL && wlc_list[j].RETRY_COUNT == 0) \
				|| (wlc_list[j].RETRY_COUNT < 0 && nvram_get_int(strcat_r(prefix, "status", tmp)) >= 0) \
				|| (wlc_list[j].RETRY_COUNT >= 0 && nvram_get_int(strcat_r(prefix, "status", tmp)) < 0))
			{
				nvram_set_int(strcat_r(prefix, "status", tmp), wlc_list[j].RETRY_COUNT);
					WLC_DBG("==========Set %s to %d=========\n", strcat_r(prefix, "status", tmp), wlc_list[j].RETRY_COUNT);
			}

			WLC_DBG("******wlc_list[%d].bandIndex =%d wlc_list[%d].state = %d  wlc_list[%d].RETRY_COUNT = %d\n", j,wlc_list[j].bandIndex, j, wlc_list[j].state,j, wlc_list[j].RETRY_COUNT);
			if(wlc_list[j].use == 0 && ((wlc_list[j].state != WLC_STATE_INITIALIZING && wlc_list[j].state != WLC_STATE_STOPPED) || wlc_list[j].RETRY_COUNT != STOP_RECONN)) 
			{
				WLC_DBG("******DISCONNECT UNUSE BAND:wlc_list[%d].bandIndex=%d wlc_list[%d].state = %d\n", j,wlc_list[j].bandIndex, j, wlc_list[j].state);
				Pty_stop_wlc_connect(wlc_list[j].bandIndex);
				wlc_list[j].RETRY_COUNT = STOP_RECONN;
				continue;
			}

			if (nvram_get_int("amas_path_stat") == ETH && wlc_list[j].state != WLC_STATE_CONNECTED) 
			{
					WLC_DBG("******ETHERNET PATH, STOP RETRY:wlc_list[%d].bandIndex =%d wlc_list[%d].state = %d\n", j,wlc_list[j].bandIndex, j, wlc_list[j].state);
					Pty_stop_wlc_connect(wlc_list[j].bandIndex);
					wlc_list[j].RETRY_COUNT = STOP_WIFI;
			}
			else if (nvram_get_int("amas_path_stat") != ETH &&  wlc_list[j].RETRY_COUNT == STOP_WIFI) 
			{
				wlc_list[j].RETRY_COUNT = RESET_COUNT;
			}


			if(nvram_get("skip_wlc_band") != NULL && nvram_get_int("skip_wlc_band") == wlc_list[j].bandIndex && wlc_list[j].state == WLC_STATE_CONNECTED)
			{
				if (wlc_list[j].band == BAND_2G)
				{
					WLC_DBG("******SKIP_WLC_BAND, DISCONNECT:wlc_list[%d].bandIndex =%d wlc_list[%d].state = %d\n", j,wlc_list[j].bandIndex, j, wlc_list[j].state);
					Pty_stop_wlc_connect(wlc_list[j].bandIndex);
					wlc_list[j].RETRY_COUNT = STOP_BAND;
				}
			}
			else if (nvram_get("skip_wlc_band") == NULL && wlc_list[j].RETRY_COUNT == STOP_BAND) 
			{
				wlc_list[j].RETRY_COUNT = RESET_COUNT;
			}


			if(unit == -1 && wlc_list[j].RETRY_COUNT == STOP_RETRY) 
			{
				wlc_list[j].RETRY_COUNT = RESET_COUNT;
			}

			WLC_DBG("****** unit = %d, wlc_list[%d].bandIndex =%d wlc_list[%d].state = %d, wlc_list[%d].RETRY_COUNT = %d  wlc_list[%d].RETRY_COUNT/BACKOFF = %d\n", unit, j, wlc_list[j].bandIndex, j, wlc_list[j].state , j, wlc_list[j].RETRY_COUNT, j, (wlc_list[j].RETRY_COUNT % BACKOFF));
			if (wlc_list[j].RETRY_COUNT < WLC_DISCONN || ((wlc_list[j].RETRY_COUNT- WLC_DISCONN) % BACKOFF) == 0 || (wlc_list[j].RETRY_COUNT > STOP_CONN))
			{
				if ((unit == -1 && wlc_list[j].state != WLC_STATE_CONNECTED && wlc_list[j].RETRY_COUNT != STOP_RETRY && wlc_list[j].RETRY_COUNT != STOP_WIFI && wlc_list[j].RETRY_COUNT != STOP_RECONN && wlc_list[j].RETRY_COUNT != STOP_BAND && wlc_list[j].RETRY_COUNT != STOP_KEEP) || (wlc_list[j].RETRY_COUNT >= RESET_COUNT && wlc_list[j].state != WLC_STATE_CONNECTED))
				{

#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
					if (nvram_get_int("dwb_mode") == 1 && wlc_list[j].bandIndex == dwb_band && dwb_try_profile == profile)
					{
						WLC_DBG("pcount(%d),change_freq(%d), wlc_retry_fh_count(%d)\n", pcount, change_freq, wlc_retry_fh_count);
						if(pcount > (change_freq + wlc_retry_fh_count))
						{
							pcount = 1;
						}
						if(pcount >= change_freq && pcount < (change_freq + wlc_retry_fh_count))
						{
							if (dwb_profile == DWB_PROFILE) {
									WLC_DBG("%s:%d Set profile to %d\n", __FUNCTION__, __LINE__, USER_PROFILE);
									profile = USER_PROFILE;
							}
							else {
									WLC_DBG("%s:%d Set profile to %d\n", __FUNCTION__, __LINE__, DWB_PROFILE);
									profile = DWB_PROFILE;
							}
						}
						else
						{
							if (wlc_list[j].bandIndex == dwb_band && dwb_try_profile == profile)
							{
								profile = dwb_profile;
								WLC_DBG("%s:%d Set profile to %d\n", __FUNCTION__, __LINE__, DWB_PROFILE);
							}
						}
						pcount++;
					}
#endif
					Pty_start_wlc_connect(wlc_list[j].bandIndex);
				}
				else if (wlc_list[j].RETRY_COUNT <= STOP_RETRY)
				{
					if (wlc_list[j].band == BAND_2G)
						Pty_stop_wlc_connect(wlc_list[j].bandIndex);
				}
			}		
#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
			if (wlc_list[j].state != WLC_STATE_CONNECTED) 
			{
				if(nvram_get_int("dwb_mode") == 1 && dwb_band == wlc_list[j].bandIndex)
				{
					sec_retry_threshold = change_freq + (SEC_BACKOFF * sec_backoff_count);

					WLC_DBG("sec_retry_threshold(%d), wlc_retry_fh_count(%d)\n", sec_retry_threshold, wlc_retry_fh_count);

					if ((wlc_list[j].RETRY_COUNT >= sec_retry_threshold) && (wlc_list[j].RETRY_COUNT <= (sec_retry_threshold + wlc_retry_fh_count)))
					{
						if (wlc_list[j].RETRY_COUNT != STOP_RECONN && wlc_list[j].RETRY_COUNT != STOP_BAND && wlc_list[j].RETRY_COUNT != STOP_KEEP && wlc_list[j].RETRY_COUNT != STOP_WIFI)
						{
							WLC_DBG("=====start try second profile.\n");
							if (wlc_list[j].bandIndex == dwb_band && dwb_try_profile == profile)
							{
								if (dwb_profile == DWB_PROFILE) {
										WLC_DBG("%s:%d Set profile to %d\n", __FUNCTION__, __LINE__, USER_PROFILE);
										profile = USER_PROFILE;
								}
								else {
										WLC_DBG("%s:%d Set profile to %d\n", __FUNCTION__, __LINE__, DWB_PROFILE);
										profile = DWB_PROFILE;
								}
							}
							Pty_start_wlc_connect(wlc_list[j].bandIndex);
						}
					}
					else if (wlc_list[j].RETRY_COUNT > (sec_retry_threshold + wlc_retry_fh_count))
					{
						SEC_BACKOFF++;
						if (wlc_list[j].bandIndex == dwb_band && dwb_try_profile == profile)
						{
							WLC_DBG("%s:%d Set profile to %d\n", __FUNCTION__, __LINE__, dwb_profile);
							profile = dwb_profile;
						}
						Pty_start_wlc_connect(wlc_list[j].bandIndex);
					}
				}
			}
#endif
			wlc_list[j].state = get_psta_status(wlc_list[j].bandIndex);
			if (wlc_list[j].RETRY_COUNT != STOP_RECONN && wlc_list[j].RETRY_COUNT != STOP_BAND && wlc_list[j].RETRY_COUNT != STOP_KEEP)
			{
				if (wlc_list[j].RECORD_COUNT < CHECK_CONN)
				{
					if(wlc_list[j].state != WLC_STATE_CONNECTED) {
						wlc_list[j].RETRY_FAILED_COUNT++;
					}
				}

				if (wlc_list[j].RECORD_COUNT >= CHECK_CONN && wlc_list[j].RECORD_COUNT <= STOP_CONN)
				{
					if (wlc_list[j].RECORD_COUNT < STOP_CONN && wlc_list[j].state == WLC_STATE_CONNECTED)
					{
						wlc_list[j].RETRY_SUCCESS_COUNT++;
					}
				}

				if (wlc_list[j].RECORD_COUNT < STOP_CONN)
						wlc_list[j].RECORD_COUNT++;
				WLC_DBG("====Band(%d), wlc_list[%d].state(%d)\n\n", wlc_list[j].bandIndex,j,  wlc_list[j].state);
				WLC_DBG("====Band(%d), wlc_list[%d].RECORD_COUNT(%d)\n\n", wlc_list[j].bandIndex, j, wlc_list[j].RECORD_COUNT);
				WLC_DBG("====Band(%d), wlc_list[%d].RETRY_FAILED_COUNT(%f)\n\n", wlc_list[j].bandIndex, j, wlc_list[j].RETRY_FAILED_COUNT);
				WLC_DBG("====Band(%d), wlc_list[%d].RETRY_SUCCESS_COUNT(%f)\n\n", wlc_list[j].bandIndex,j,wlc_list[j].RETRY_SUCCESS_COUNT);

			}

			if (wlc_list[j].RECORD_COUNT >= STOP_CONN && wlc_list[j].RETRY_COUNT != STOP_KEEP)
			{

				wlc_list[j].RETRY_FAILED_RATE = (wlc_list[j].RETRY_FAILED_COUNT/CHECK_CONN);

				WLC_DBG("====Band(%d), wlc_list[%d].RETRY_FAILED_COUNT(%f) fail_rate(%f)  CHECK_CONN(%d)\n\n", wlc_list[j].bandIndex, j,  wlc_list[j].RETRY_FAILED_COUNT, wlc_list[j].RETRY_FAILED_RATE, CHECK_CONN);
				if (wlc_list[j].RETRY_FAILED_RATE == 1)
						WLC_DBG("====Band(%d), Can't connect to P-AP.\n\n", wlc_list[j].bandIndex);

				wlc_list[j].RETRY_SUCCESS_RATE = (wlc_list[j].RETRY_SUCCESS_COUNT/(wlc_list[j].RECORD_COUNT - CHECK_CONN));
				WLC_DBG("====Band(%d), wlc_list[%d].RETRY_SUCCESS_COUNT(%f) sucess_rate(%f) (wlc_list[j].RECORD_COUNT - CHECK_CONN)(%d).\n\n", wlc_list[j].bandIndex, j,  wlc_list[j].RETRY_SUCCESS_COUNT, wlc_list[j].RETRY_SUCCESS_RATE , (wlc_list[j].RECORD_COUNT - CHECK_CONN));
			}
			else if(wlc_list[j].RETRY_COUNT < RESET_COUNT)
			{
					wlc_list[j].RECORD_COUNT = 0;
					wlc_list[j].RETRY_SUCCESS_COUNT = 0;
					wlc_list[j].RETRY_FAILED_COUNT = 0;
			}

            if (wlc_list[j].state == WLC_STATE_CONNECTED) {
                if (wlc_list[j].RETRY_COUNT != RESET_COUNT)
                    wlc_list[j].RETRY_COUNT = RESET_COUNT;
#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
                if (wlc_list[j].bandIndex == dwb_band)
                    pcount = 0;  // Reset pcount.
#endif
            }
            else if(unit != -1 && wlc_list[j].bandIndex != unit && wlc_list[j].state != WLC_STATE_CONNECTED && wlc_list[j].RETRY_COUNT >= 0)
			{
#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
				if (nvram_get_int("dwb_mode") == 1)
				{
					if(dwb_try_profile == profile)
					{
							wlc_list[j].RETRY_COUNT++;
					}
				}
				else
#endif
					wlc_list[j].RETRY_COUNT++;

				if(wlc_list[j].RETRY_COUNT > (STOP_CONN + WLC_DISCONN))
				{
					if (wlc_list[j].band == BAND_2G)
						wlc_list[j].RETRY_COUNT = STOP_RETRY;
				}
			}
			else 
			{

				if(wlc_list[j].RETRY_COUNT > 0)
				{
					if (unit != -1 && wlc_list[unit].RETRY_COUNT >= 5)
					{
						wlc_list[j].RETRY_COUNT = RESET_COUNT;
					}
				}
			}
			Pty_procedure_check(wlc_list[j].bandIndex, SUMband);
		}

		unstable = 0;
		for(j = 0; j < SUMband; j++) 
		{

			if (wlc_list[j].RECORD_COUNT >= STOP_CONN && wlc_list[j].RETRY_COUNT != STOP_KEEP &&
				wlc_list[j].RETRY_FAILED_RATE > fail_rate_threshold && wlc_list[j].RETRY_FAILED_RATE < 1 && wlc_list[j].RETRY_SUCCESS_RATE < sucess_rate_threshold)
			{
				WLC_DBG("====Band(%d), fail_rate(%f) Connection is not stable.\n\n", wlc_list[j].bandIndex, wlc_list[j].RETRY_FAILED_RATE);
				unstable++;
				if (wlc_list[j].band == BAND_2G)
					wlc_list[j].RETRY_COUNT = STOP_KEEP;
			}
		}

		if(unstable == 1)
		{
			for(j = 0; j < SUMband; j++)
			{
				if (wlc_list[j].RETRY_COUNT == STOP_KEEP)
				{
					if (wlc_list[j].band == BAND_2G)
							Pty_stop_wlc_connect(wlc_list[j].bandIndex);
					wlc_list[j].RECORD_COUNT = 0;
					wlc_list[j].RETRY_SUCCESS_COUNT = 0;
					wlc_list[j].RETRY_FAILED_COUNT = 0;
					WLC_DBG("******STOP KEEP_WLC_BAND, DISCONNECT:wlc_list[%d].bandIndex =%d wlc_list[%d].state = %d\n", j,wlc_list[j].bandIndex, j, wlc_list[j].state);
					break;
				}
			}
		}
		if (unstable == 2) 
		{
			for(j = 0; j < SUMband; j++)
			{
				if (wlc_list[j].RETRY_COUNT == STOP_KEEP)
				{
					wlc_list[j].RETRY_COUNT = RESET_COUNT;
					wlc_list[j].RECORD_COUNT = 0;
					wlc_list[j].RETRY_SUCCESS_COUNT = 0;
					wlc_list[j].RETRY_FAILED_COUNT = 0;
					WLC_DBG("******RESTART KEEP_WLC_BAND, RECONNECT:wlc_list[%d].bandIndex =%d wlc_list[%d].state = %d\n", j,wlc_list[j].bandIndex, j, wlc_list[j].state);
				}
			}
		}

		connected = 0;
		for(j = 0; j < SUMband; j++)
		{
			if (wlc_list[j].state == WLC_STATE_CONNECTED) 
			{
				connected = 1;
				break;
			}
		}

		if (connected == 1)	 
		{
			nvram_set_int("wlc_state", WLC_STATE_CONNECTED);
		}
		else if (connected == 0)
		{
			if (nvram_get_int("wlc_state") != WLC_STATE_INITIALIZING) {
				if (unit != -1 && wlc_list[unit].RETRY_COUNT >= RESET_CONN && wlc_list[unit].RETRY_COUNT != RESET_COUNT)
				{
					for(j = 0; j < SUMband; j++) 
					{
						if (wlc_list[j].use != 0)
						{
								wlc_list[j].RETRY_COUNT = RESET_COUNT;
								wlc_list[j].RECORD_COUNT = 0;
								wlc_list[j].RETRY_SUCCESS_COUNT = 0;
								wlc_list[j].RETRY_FAILED_COUNT = 0;
								wlc_list[j].RETRY_SUCCESS_RATE = 0;
								wlc_list[j].RETRY_FAILED_RATE = 0;
						}
					}
					nvram_set_int("wlc_state", WLC_STATE_STOPPED);
					nvram_set_int("wlc_sbstate", WLC_STOPPED_REASON_AUTH_FAIL);
				}
				else if (unit == -1)
				{
					if (all_disconnected_count == RESET_CONN) 
					{ // Waiting 5 counts for 5g change profile.
						for(j = 0; j < SUMband; j++)  
						{
							if (wlc_list[j].use != 0 && wlc_list[j].RETRY_COUNT != STOP_WIFI)
							{
								wlc_list[j].RETRY_COUNT = RESET_COUNT;
							}
						}
						nvram_set_int("wlc_state", WLC_STATE_STOPPED);
						nvram_set_int("wlc_sbstate", WLC_STOPPED_REASON_AUTH_FAIL);
					}
					if (all_disconnected_count < (RESET_CONN+1))
						all_disconnected_count++; // Avoid all_disconnected_count++ overflow.
				}
			}
		}
		if (connected > 0 && all_disconnected_count > 0)
			all_disconnected_count = 0; // reset to 0

		check_wifi_upstream_status(wlc_wait_time, connected);
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_unlock(&monitor_connect_mutex);
#endif
	} //while

	if (wlc_list)
		free(wlc_list);
error:
	pthread_exit(NULL);

}

#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
void *write_connect_profile()
{
	pthread_detach(pthread_self());
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	struct timeval now;
	struct timespec outtime;
#endif
	int wlc_wait_time = nvram_get_int("wlc_monitor_time") ? : WLC_MONITOR_PROFILE_INTERVAL;
	char tmp[100] = {0}, tmp2[100] = {0};
	char prefix[] = "wlXXXXXXXXXX_", wl_prefix[]="wlXXXXXXXXXX_", wlc_prefix[]="wlXXXXXXXXXX_";
	char wsbh_prefix[]="wlXXXXXXXXXX_", wsfh_prefix[]="wlXXXXXXX_";
	int dwb_band = nvram_get_int("dwb_band");
    struct connect_param_mapping_s *pconnParam = NULL;
    int notify_change = 0;

	dwb_try_profile =  0;
	while (1)
	{
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_lock(&update_profile_mutex);
		wlc_wait_time = nvram_get_int("wlc_monitor_time") ? : WLC_MONITOR_PROFILE_INTERVAL;
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + wlc_wait_time;
		outtime.tv_nsec = 0;
		pthread_cond_timedwait(&update_profile_cond, &update_profile_mutex, &outtime);
#else
	wlc_wait_time = nvram_get_int("wlc_monitor_time") ? : WLC_MONITOR_PROFILE_INTERVAL;
	sleep(wlc_wait_time);
#endif

		dwb_band = nvram_get_int("dwb_band");
		notify_change = 0;

		if (nvram_get_int("dwb_mode") == 0) continue;

		if (dwb_band < 1) continue;


		snprintf(prefix, sizeof(prefix), "wl%d_", dwb_band);
		snprintf(wlc_prefix, sizeof(wlc_prefix), "wlc%d_", dwb_band);
		snprintf(wl_prefix, sizeof(wl_prefix), "wl1.1_");
		snprintf(wsbh_prefix, sizeof(wsbh_prefix), "wsbh_");
		snprintf(wsfh_prefix, sizeof(wsfh_prefix), "wsfh_");

		WLC_DBG("dwb_try_profile(%d)  profile(%d)\n", dwb_try_profile, profile);

		if (dwb_try_profile != profile)
		{
			for (pconnParam = &connect_param_mapping_list[0]; pconnParam->param != NULL; pconnParam++)
			{
				if (profile == DWB_PROFILE) {
		    		if(strcmp("bss_enabled", pconnParam->param) != 0) {
						if (nvram_get(strcat_r(wsbh_prefix, pconnParam->param, tmp)) != NULL) {
							WLC_DBG("(%s%s)(val: %s)  (%s%s)(val:%s)\n", prefix, pconnParam->param, nvram_safe_get(strcat_r(prefix, pconnParam->param, tmp)), wsbh_prefix, pconnParam->param, nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)));
							if(strcmp(nvram_safe_get(strcat_r(prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)))) {
									nvram_set(strcat_r(prefix, pconnParam->param, tmp), nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)));
									WLC_DBG("====Change %s%s(val:%s) to (val:%s)=====\n", prefix, pconnParam->param, nvram_safe_get(strcat_r(prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)));
									notify_change = 1;
							}

							WLC_DBG("(%s%s)(val: %s)  (%s%s)(val:%s)\n", wlc_prefix, pconnParam->param, nvram_safe_get(strcat_r(wlc_prefix, pconnParam->param, tmp)), wsbh_prefix, pconnParam->param, nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)));
							if(strcmp(nvram_safe_get(strcat_r(wlc_prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)))) {
									nvram_set(strcat_r(wlc_prefix, pconnParam->param, tmp), nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)));
									WLC_DBG("====Change %s%s(val:%s) to (val:%s)=====\n", wlc_prefix, pconnParam->param, nvram_safe_get(strcat_r(wlc_prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsbh_prefix, pconnParam->param, tmp2)));
									notify_change = 1;
							}
						}
		    		}
				}
				if (profile == USER_PROFILE) {
		    		if(strcmp("bss_enabled", pconnParam->param) != 0) {
						WLC_DBG("(%s%s)(val: %s)  (%s%s)(val:%s)\n", prefix, pconnParam->param, nvram_safe_get(strcat_r(prefix, pconnParam->param, tmp)), wsfh_prefix, pconnParam->param, nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)));
						if(strcmp(nvram_safe_get(strcat_r(prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)))) {
							nvram_set(strcat_r(prefix, pconnParam->param, tmp), nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)));
							WLC_DBG("====Change %s%s(val:%s) to (val:%s)=====\n", prefix, pconnParam->param, nvram_safe_get(strcat_r(prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)));
							notify_change = 1;
						}
						WLC_DBG("(%s%s)(val: %s)  (%s%s)(val:%s)\n", wlc_prefix, pconnParam->param, nvram_safe_get(strcat_r(wlc_prefix, pconnParam->param, tmp)), wsfh_prefix, pconnParam->param, nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)));
						if(strcmp(nvram_safe_get(strcat_r(wlc_prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wl_prefix, pconnParam->param, tmp2)))) {
							nvram_set(strcat_r(wlc_prefix, pconnParam->param, tmp), nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)));
							WLC_DBG("====Change %s%s(val:%s) to (val:%s)=====\n", wlc_prefix, pconnParam->param, nvram_safe_get(strcat_r(wlc_prefix, pconnParam->param, tmp)), nvram_safe_get(strcat_r(wsfh_prefix, pconnParam->param, tmp2)));
							notify_change = 1;
						}
		    		}
				}
			}
			if (notify_change == 1)
				apply_config_to_driver();

			WLC_DBG("[%s] Set profile (%d)= dwb_try_profile(%d)\n", __FUNCTION__, profile, dwb_try_profile);
			nvram_set_int("dwb_try_profile", profile);
			dwb_try_profile = profile;
			WLC_DBG("[%s] modify profile to profile %d\n", __FUNCTION__, profile);
		}
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		pthread_mutex_unlock(&update_profile_mutex);
#endif
	}
	pthread_exit(NULL);

}
#endif
int amas_wlcconnect_main(void)
{
#if defined(RTCONFIG_RALINK_MT7621)
    Set_RAST_CPU();
#endif
    _dprintf("%s: Start to run...\n", __FUNCTION__);
	FILE *fp = NULL;
	//sigset_t sigs_to_catch;

	int res = 0;
	pthread_t monitor_connect_thread;

#if defined(RTCONFIG_DWB) && !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
	pthread_t update_profile_thread;
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
	if ((fp = fopen("/var/run/amas_wlcconnect.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}
#ifdef RTCONFIG_DPSTA
	Is_dpsta = dpsta_mode();
#endif

#ifdef PTHREAD_STACK_SIZE
	attrp = &attr;
	/* change the default stack size of pthread */
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	res = pthread_mutex_init(&monitor_connect_mutex, NULL);
	if (res != 0) {
		dbG("[monitor_connect_func] semaphore initialization failed\n");
		return 0;
	}

	res = pthread_cond_init(&monitor_connect_cond, NULL);
	if (res != 0) {
		dbG("[monitor_connect_func] monitor_connect_cond initialization failed\n");

	}
#endif
	res = pthread_create (&monitor_connect_thread, attrp, monitor_connect_func, NULL);
	if (res != 0) {
		dbG("monitor connection thread creation failed");
		return 0;
	}

#if !defined(RTCONFIG_NO_TRY_DWB_PROFILE)
#if defined(RTCONFIG_DWB)
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
res = pthread_mutex_init(&update_profile_mutex, NULL);
if (res != 0) {
	dbG("[write_connect_profile] semaphore initialization failed\n");
	return 0;
}

res = pthread_cond_init(&update_profile_cond, NULL);
if (res != 0) {
	dbG("[write_connect_profile] update_profile_cond initialization failed\n");
	return 0;
}
#endif
res = pthread_create (&update_profile_thread, attrp, write_connect_profile, NULL);
if (res != 0) {
	dbG("update profile thread creation failed");
	return 0;
}
#endif
#endif //!NO_TRY_DWB_PROFILE
while (1)
{
	pause();
}

if (attrp != NULL) pthread_attr_destroy(attrp);


return 0;
}
