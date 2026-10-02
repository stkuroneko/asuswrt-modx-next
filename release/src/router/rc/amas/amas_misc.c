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
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <shared.h>
#include <rc.h>
#include <sys/time.h>
#include "amas.h"
#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#include <amas_path.h>

int misc_dbg = 0;

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"amas_misc.log"
#define MISC_DBG(fmt, arg...) \
	do {    \
		if(misc_dbg) \
		dbG("MISC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("amas_misc_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)
#else
#define MISC_DBG(fmt, arg...) \
        do {    \
               if(misc_dbg) \
                dbG("MISC %lu: "fmt, uptime(), ##arg); \
            	if (!strcmp(nvram_safe_get("amas_misc_syslog"), "1")) \
				logmessage("MISC", fmt, ##arg); \
        } while (0)
#endif

#define INTERVAL 2
#define MAX_SUBIF_NUM 4
#if defined(RTCONFIG_LANTIQ)  // Temporarily to use different defined value by platform.
#define IP_RENEW_INTERVAL 100 //rico 30 to 100
#else
#define IP_RENEW_INTERVAL 30
#endif
#define DFS_DETECT_INTERVAL 600

#define CHECK_WIFI_INTERVAL 30

int misc_timer = INTERVAL;
int dfs_timer = 600;


struct timeval renew_ip_base_uptime;
struct timeval renew_ip_uptime;

struct timeval det_dfs_base_uptime;
struct timeval det_dfs_uptime;

struct timeval chk_wifi_base_uptime;
struct timeval chk_wifi_uptime;

struct timeval getuptime(void)
{
    struct timeval now;
    char timestr[60] = {0};
    char uptimestr[30] = {0};
    char *dotaddr;
   // unsigned long second;
    char error = 0;
    FILE * timefile = NULL;

    timefile = fopen("/proc/uptime", "r");
    if(!timefile)
    {
        printf("[%s:line:%d] error opening '/proc/uptime'",__FILE__,__LINE__);
        error = 1;
        goto out;
    }

    if( (fread(timestr, sizeof(char), 60, timefile)) == 0 )
    {
        printf("[%s:line:%d] read '/proc/uptime' error",__FILE__,__LINE__);
        error = 1;
        goto out;
    }

    dotaddr = strchr(timestr, '.');
    if((dotaddr - timestr + 2) < 30)
    {
        memcpy(uptimestr, timestr, dotaddr - timestr + 2);
        printf("uptimestr = (%s)\n", uptimestr);
    }
    else
    {
        printf("[%s:line:%d] uptime string is too long",__FILE__,__LINE__);
        error = 1;
        goto out;
    }
    uptimestr[dotaddr - timestr + 2] = '\0';
    printf("uptimestr = (%s)\n", uptimestr);

out:
    if(error)
    {
        now.tv_sec  = 0;
        now.tv_usec = 0;
    }
    else
    {
        now.tv_sec  = atol(uptimestr);
        now.tv_usec = 0;
    }

    fclose(timefile);
    return now;
}


/* for checking upstream connection */
#define MAX_DISCONNECTION_COUNT 10
#define CHECKING_TIME       30
int max_disc_count = MAX_DISCONNECTION_COUNT;
int checking_time = CHECKING_TIME;
int disc_count = 0;
int check_count = 0;

void check_wifi_upstream_status()
{
    /* only for wireless upstream */
    if (nvram_get_int("amas_path_stat_v3") >= WL2G_U && nvram_get_int("amas_path_stat_v3") <= WL_MAX_BASE)
    {
        if (chk_wifi_base_uptime.tv_sec == 0)
        {
            chk_wifi_base_uptime =  getuptime();
            MISC_DBG("[%d] first set uptime to  chk_wifi_base_uptime = %lu\n", __LINE__, chk_wifi_base_uptime.tv_sec);
        }

        chk_wifi_uptime = getuptime();
        MISC_DBG("[%d] Get chk_wifi_uptime.tv_sec (%lu)-chk_wifi_base_uptime.tv_sec(%lu) = %lu \n", __LINE__, chk_wifi_uptime.tv_sec, chk_wifi_base_uptime.tv_sec, (chk_wifi_uptime.tv_sec  - chk_wifi_base_uptime.tv_sec));

        if (chk_wifi_uptime.tv_sec  - chk_wifi_base_uptime.tv_sec >= CHECK_WIFI_INTERVAL)
        {
            MISC_DBG("cfg_alive(%d), disc_count(%d), max_disc_count(%d)\n", nvram_get_int("cfg_alive"), disc_count, max_disc_count);

            if (nvram_get_int("cfg_alive") == 0)
            {
                disc_count++;
                if (disc_count == 1) {
                    MISC_DBG("wifi upstream is connected, and disconnected from CAP.\n");
                    logmessage("MISC", "wifi upstream is connected, and disconnected from CAP.\n");
                }

                if (disc_count >= max_disc_count)
                {
                    MISC_DBG("disc_count (%d) >= max_disc_count (%d)\n",
                        disc_count, max_disc_count);
                    disc_count = 0;
                    if (!nvram_get_int("wlc_recover_stop"))
                        notify_rc("restart_wireless");
                }
            }
            else
                 disc_count = 0;

            chk_wifi_base_uptime.tv_sec = 0;
            chk_wifi_uptime.tv_sec = 0;
        }
    }
    else
    {
        disc_count = 0;
        chk_wifi_base_uptime.tv_sec = 0;
        chk_wifi_uptime.tv_sec = 0;
    }

}


int old_cfg_stat = -1;
int cfg_stat = -1;
void renew_re_ip()
{

    if (nvram_get_int("cfg_alive") == 0)
    {
        if (renew_ip_base_uptime.tv_sec == 0)
        {
            renew_ip_base_uptime =  getuptime();
            MISC_DBG("[%d] first set uptime to  renew_ip_base_uptime = %lu\n", __LINE__, renew_ip_base_uptime.tv_sec);

        }

        renew_ip_uptime = getuptime();
        MISC_DBG("[%d] Get renew_ip_uptime.tv_sec (%lu)-renew_ip_base_uptime.tv_sec(%lu) = %lu \n", __LINE__, renew_ip_uptime.tv_sec, renew_ip_base_uptime.tv_sec, (renew_ip_uptime.tv_sec  - renew_ip_base_uptime.tv_sec));

        if (renew_ip_uptime.tv_sec  - renew_ip_base_uptime.tv_sec >= IP_RENEW_INTERVAL)
        {
            cfg_stat = nvram_get_int("cfg_alive");

            if (cfg_stat == 0 && !nvram_get_int("stop_keep_renewip"))
            {  //regular renew ip
                MISC_DBG("[renew_re_ip] keep renew IP...\n");
                killall("udhcpc", SIGUSR1);
            }
            else if (cfg_stat != old_cfg_stat)
            {  // renew ip, only status change.
                MISC_DBG("[renew_re_ip] cfg_alive change to %d, renew IP...\n", cfg_stat);
                killall("udhcpc", SIGUSR1);
                old_cfg_stat = cfg_stat;
            }

            renew_ip_base_uptime.tv_sec = 0;
            renew_ip_uptime.tv_sec = 0;
        }
    }
    else
    {
        renew_ip_base_uptime.tv_sec = 0;
        renew_ip_uptime.tv_sec = 0;
    }
}

void set_dfs_channel_forced()
{
    int SUMband = get_wl_count();
    int j = 0, bandindex = 0;
    char nvrampar[64];

    for (j = 0; j < SUMband; j++)
    {
        snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_unit", j);
        bandindex = nvram_get_int(nvrampar);
        Pty_procedure_check(bandindex, SUMband);
    }
}

static void amas_misc_leave(int signo)
{

    dbG("\n## amas_misc.safeexit ##\n");
    exit(0);
}


int amas_misc_main()
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
    misc_timer = nvram_get_int("amas_misc_timer") ? : INTERVAL;
    misc_dbg = nvram_get_int("amas_misc_dbg");
    dfs_timer =  nvram_get_int("dfs_timer") ? : DFS_DETECT_INTERVAL;

    amas_wait_wifi_ready();

	/* write pid */
	if ((fp = fopen("/var/run/amas_misc.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}


    signal(SIGTERM, amas_misc_leave);

    renew_ip_base_uptime.tv_sec = 0;
    renew_ip_uptime.tv_sec = 0;

    det_dfs_base_uptime.tv_sec = 0;
    det_dfs_uptime.tv_sec = 0;

    chk_wifi_base_uptime.tv_sec = 0;
    chk_wifi_uptime.tv_sec = 0;

	while (1)
	{

        misc_dbg = nvram_get_int("amas_misc_dbg");

        renew_re_ip();


        if(strcmp(nvram_safe_get("cfg_group"), ""))
        {
            check_wifi_upstream_status();
        }


        set_dfs_channel_forced();



		sleep(misc_timer);
	}
	return 0;
}
