#include <rc.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <shutils.h>
#include <linux/sockios.h>
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

#include "amas.h"
#include <amas-utils.h>
#include <amas_path.h>

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

extern char *get_pap_bssid(int unit, char bssid_str[]);

int bhctl_dbg = 0;

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"amas_bhctrl.log"
#define BH_DBG(fmt, arg...) \
	do {    \
		if(bhctl_dbg) \
			dbG("BHC %lu: "fmt, uptime(), ##arg); \
		if (!strcmp(nvram_safe_get("bhctl_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
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

pthread_mutex_t lock_mutex;
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
pthread_cond_t wifi_cond;
pthread_cond_t eth_cond;
#endif
wl_br_status *wlbrs_list = NULL;
eth_br_status *ethbrs_list	= NULL;

#define INTERVAL 2

int loop = 1;
int SUMband = 0;
int SUMeth = 0;
int Is_dpsta = 0;
int keep_state = -1;
int wlc_band = -1;
int timer = 0;
int status_timer = 0;
int selwlentry = -1;
int selethentry = -1;
int amas_ethernet = ETHERNET_HOP;
int last_ethpath = -1;
int connected = 0;
int last_connected = -1;
int brifname = -1;
int last_brifname = -1;
int max_band = 0;
int wait_time = 0;
int wait_wifi = 0;
int worst_signal_count = 0;
int worst_signal_count_threshold = 0;
int rssi_select_above = RSSI_SELECT_ABOVE;
int rssi_select_below = RSSI_SELECT_BELOW;

struct _signal_handler default_signal_handlers[] = {
  {0,  20, -92},
  {0,  40, -89},
  {1,  20, -92},
  {1,  40, -89},
  {1,  80, -86},
  {1,  160, -83},
  {2,  20, -92},
  {2,  40, -89},
  {2,  80, -86},
  {2,  160, -83},
  {0,   0,   0}
};

signal_handler *sig_entry = NULL;
signal_handler *handler = NULL;
signal_handler *handler_entry = NULL;

static void h_chld(int signo)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

int ioctl_for_bridge(int action, char *br, char *brif)
{
	int ret = -1;
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

	//BH_DBG("brif(%s), ifr.ifr_ifindex(%d), ifr.ifr_name(%s)\n", brif, ifr.ifr_ifindex, ifr.ifr_name);

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

	ret = ioctl(fd, request, &ifr);
	BH_DBG("bridge ioctl ret = %d.\n", ret);
#ifdef RTCONFIG_BROOP
	if (ret<0 && ( (action==ARG_addif && errno==EBUSY) || (action==ARG_delif && errno==EINVAL)) )
		ret = 0;
#endif
	if (ret < 0) {
		return ret;
	}
	BH_DBG("2:Add/3:Del(action:%d) interface(%s) to bridge successfully.\n", action,  brif);
	close(fd);
	return ret;
}

int cmp_sort( const void *a , const void *b )
{
	struct _wl_br_status *c = (wl_br_status *)a;
	struct _wl_br_status *d = (wl_br_status *)b;
	if(c->priority != d->priority) return c->priority - d->priority;
	return 0;
}

void init_eth_status(eth_br_status *ethbrs_list)
{
	char eth[256]={0}, *next = NULL;
	int j = 0;

	foreach(eth, nvram_safe_get("eth_ifnames"), next) {
		ethbrs_list[j].defif = ETH;
		ethbrs_list[j].ethIndex = j;
		ethbrs_list[j].priority = 100;
		memset(ethbrs_list[j].ethif, 0x00, sizeof(ethbrs_list[j].ethif));
		memcpy(ethbrs_list[j].ethif, eth, sizeof(ethbrs_list[j].ethif));
		ethbrs_list[j].state = -1;
		ethbrs_list[j].hop	= -1;
		j ++;
	}

}

void init_wlc_status(wl_br_status *wlbrs_list, int SUMband)
{
	char wif[256]={0}, *next = NULL;
	int j = 0, k = 0;
	div_t chkval2;
	int offset = 0;
	int chkval = 0;
	char *band_priority = nvram_safe_get("sta_priority");
	nvram_set_int("wlc_band", -1);

	foreach(wif, nvram_safe_get("sta_ifnames"), next) {
		wlbrs_list[j].band = 0;
		wlbrs_list[j].bandIndex = j;
		wlbrs_list[j].priority = 100;
		memset(wlbrs_list[j].wlcif, 0x00, sizeof(wlbrs_list[j].wlcif));
		memcpy(wlbrs_list[j].wlcif, wif, sizeof(wlbrs_list[j].wlcif));
		wlbrs_list[j].state = 0;
		wlbrs_list[j].rssi	= 0;
		wlbrs_list[j].hop	= -1;
		wlbrs_list[j].use	= 1;
		wlbrs_list[j].RETRY_COUNT = 0;
		wlbrs_list[j].RETRY_FAILED_COUNT = 0;
		wlbrs_list[j].RETRY_SUCCESS_COUNT = 0;
		wlbrs_list[j].RETRY_FAILED_RATE = 0;
		wlbrs_list[j].RETRY_SUCCESS_RATE = 0;
		j ++;
	}

	if (band_priority == NULL) {
		BH_DBG("priority is null, set to default priority.\n");
		band_priority = DEFAULT_BAND_PRIORITY;
	}

	chkval = cal_space(band_priority);

	chkval2 = div(chkval, PARA_COUNT);

	if (chkval2.rem != 0 || chkval2.quot == 0) {
		BH_DBG("priority is incorrect, set to default priority.\n");
		band_priority = DEFAULT_BAND_PRIORITY;
	}
	else {
		BH_DBG("priority is OK.\n");
	}

	dpsta_info *dpsta = (struct _dpsta_ifinfo *) malloc(chkval2.quot *sizeof(struct _dpsta_ifinfo));

	if (dpsta == NULL) {
		BH_DBG("Can't alloc memory for %s\n", __FILE__);
		return;
	}
    memset(dpsta, 0x00, chkval2.quot *sizeof(struct _dpsta_ifinfo));

    int count = 0;
    while (sscanf(band_priority, " %d%d%d%d%n", &dpsta[count].band, &dpsta[count].bandIndex, &dpsta[count].priority, &dpsta[count].use, &offset) == PARA_COUNT)
    {

        band_priority += offset;
        BH_DBG("read[%d]: %d %d %d %d\n", count, dpsta[count].band,dpsta[count].bandIndex, dpsta[count].priority, dpsta[count].use);
        if (count < chkval2.quot)
       			count++;
    }

    for (j =0 ; j < SUMband; j++)
    {
        for (k =0 ; k < chkval2.quot; k++)
        {
            if (wlbrs_list[j].bandIndex == dpsta[k].bandIndex)
            {
                wlbrs_list[j].band = dpsta[k].band;
                wlbrs_list[j].priority = dpsta[k].priority;
                wlbrs_list[j].use = dpsta[k].use;
                if (wlbrs_list[j].bandIndex == 0 )
                    wlbrs_list[j].defif = WL_2G;
                if (wlbrs_list[j].bandIndex == 1 )
                    wlbrs_list[j].defif = WL_5G;
                if (wlbrs_list[j].bandIndex == 2 )
                    wlbrs_list[j].defif = WL_5G_1;
            }
        }
    }
    free(dpsta);

	qsort(wlbrs_list, SUMband, sizeof(wlbrs_list[0]), cmp_sort);


}

int init_signal_threshold()
{

    char *sigReq = nvram_safe_get("aimesh_signal_threshold");
    worst_signal_count_threshold = nvram_get_int("aimesh_worst_signal_count_threshold") ? : WORST_SIGNAL_COUNT_THRESHOLD;

    int chkval = 0, count = 0, offset = 0;
    div_t entry;

    if (sigReq == NULL)
    {
        BH_DBG("sigReq is null, set to default sigReq.\n");
        handler_entry = &default_signal_handlers[0];
        }
    else
    {
        chkval = cal_space(sigReq);
        BH_DBG("sigReq length = %d\n", chkval);

        entry = div(chkval, 3);
        BH_DBG("Quo = %d, rem = %d\n", entry.quot, entry.rem);

        if (entry.rem != 0 || entry.quot == 0)
        {
            BH_DBG("sigReq is incorrect, use default sigReq.\n");
            handler_entry = &default_signal_handlers[0];
        }
        else
        {
            BH_DBG("sigReq is OK.\n");

            sig_entry = (struct _signal_handler *) malloc((entry.quot+1) *sizeof(struct _signal_handler));

            if (sig_entry == NULL) {
                BH_DBG("can't alloc memory\n");
                return 0;
            }
            memset(sig_entry,0x00,(entry.quot+1) *sizeof(struct _signal_handler));

            while (sscanf(sigReq, " %d%d%d%n", &sig_entry[count].bandIndex, &sig_entry[count].bandWidth, &sig_entry[count].rssi_threshold, &offset) == 3)
            {
                sigReq += offset;
                printf("read: %d %d %d\n", sig_entry[count].bandIndex,sig_entry[count].bandWidth, sig_entry[count].rssi_threshold);

                if (count < entry.quot)
                    count++;
            }
            handler_entry = &sig_entry[0];
        }

    }
#if 0
    for (handler = handler_entry; handler->bandWidth; handler++) {
        BH_DBG("%s bandIndex = %d, handler->bandWidth = %d, handler->rssi_threshold = %d\n", __FUNCTION__,   handler->bandIndex ,  handler->bandWidth, handler->rssi_threshold);
    }
#endif
    return 0;
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

void *update_eth_status(void *list)
{
	pthread_detach(pthread_self());
	eth_br_status *ethbrs_list = (struct _eth_br_status *) list;
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	struct timeval now;
	struct timespec outtime;
#endif
	char prefix[] = "wlXXXXXXXXXX";
    	int j = 0;
    	int wan_unit = wan_primary_ifunit();
    	int res = -1, hop = -1;
	char nvrampar[32];
	char nvrampar_res[32];
#ifdef RTCONFIG_BROOP
	int oop_rmeth = 0;
	char wif[256]={0}, *next = NULL, *oopif = NULL;
#endif

    while(loop)
    {
#ifdef RTCONFIG_NO_PTHREAD_TIMEDWAIT
    	sleep(status_timer);
#endif
		pthread_mutex_lock(&lock_mutex);

#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + status_timer;
		outtime.tv_nsec = 0;
		pthread_cond_timedwait(&eth_cond, &lock_mutex, &outtime);
#endif

    	res = -1;
	    for(j = 0; j < SUMeth; j++)
	    {
	    	snprintf(nvrampar, sizeof(nvrampar), "amas_eth%d_cost", ethbrs_list[j].ethIndex);
			snprintf(nvrampar_res, sizeof(nvrampar_res), "amas_eth%d_cost_result", ethbrs_list[j].ethIndex);

    		ethbrs_list[j].state = get_wanports_status(wan_unit);
			memset(prefix, 0x00, sizeof(prefix));
			sprintf(prefix, "lan%d", j);
			if (ethbrs_list[j].state > 0) {
#ifdef RTCONFIG_BROOP
				if(nvram_match("amas_ethernet", "3") && nvram_match("cfg_alive", "1") && nvram_match("reset_broop", "1") && ismax_broop()) {
					oop_rmeth = strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname"))? 1:0; // don't remove current amas path
					if(oop_rmeth)
						oopif = nvram_safe_get("eth_ifnames");
					else
						oopif = nvram_safe_get("sta_phy_ifnames");
					foreach(wif, oopif, next) {
						ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
						_dprintf("\n\n>>>>>>> Remove %s from br due loop occuring <<<<<<\n\n", wif);
						syslog(LOG_NOTICE, "Remove oopif %s from lan-bridge.", wif);
					}
					if(oop_rmeth)
						nvram_set("reset_broop", "2");
				}
#endif
				res = amas_get_cost(ethbrs_list[j].ethif, ethbrs_list[j].ethIndex, SUMeth, NULL, &hop);
				if (res == AMAS_RESULT_SUCCESS)
					ethbrs_list[j].hop = hop;
				else
					ethbrs_list[j].hop = -1;
			}
			else
				ethbrs_list[j].hop = -1;

			nvram_set_int(nvrampar, ethbrs_list[j].hop);
			nvram_set_int(nvrampar_res, res);

			BH_DBG("\n\
			ethbrs_list[%d].ethIndex=%d\n\
			ethbrs_list[%d].priority=%d\n\
			ethbrs_list[%d].ethif = %s\n\
			ethbrs_list[%d].state = %d\n\
			ethbrs_list[%d].hop = %d  (result = %s)\n",
			j, ethbrs_list[j].ethIndex,
			j, ethbrs_list[j].priority,
			j, ethbrs_list[j].ethif,
			j, ethbrs_list[j].state,
			j, ethbrs_list[j].hop,  amas_utils_str_error(res));
		}

		pthread_mutex_unlock(&lock_mutex);
	}
	pthread_exit(NULL);
}


void *update_wlc_status (void *list)
{

	pthread_detach(pthread_self());
	wl_br_status *wlbrs_list = (struct _wl_br_status *) list;
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	struct timeval now;
	struct timespec outtime;
#endif
	char prefix[] = "wlXXXXXXXXXX";
    int j = 0, res = -1, hop = -1;
	char bssid_str[18];
	char nvrampar[32];
	char nvrampar_res[32];

   while (loop)
   {
#ifdef RTCONFIG_NO_PTHREAD_TIMEDWAIT
   		sleep(status_timer);
#endif
		pthread_mutex_lock(&lock_mutex);

#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + status_timer;
		outtime.tv_nsec = 0;
		pthread_cond_timedwait(&wifi_cond, &lock_mutex, &outtime);
#endif

		res = -1;
	    for(j = 0; j < SUMband ; j++)
	    {
	    	snprintf(nvrampar, sizeof(nvrampar), "amas_wlc%d_cost", wlbrs_list[j].bandIndex);
			snprintf(nvrampar_res, sizeof(nvrampar_res), "amas_wlc%d_cost_result", wlbrs_list[j].bandIndex);

			if (wlbrs_list[j].use == 0)
			{
				nvram_set_int(nvrampar, -1);
				nvram_set_int(nvrampar_res, -1);
				continue;
			}

			wlbrs_list[j].state = get_psta_status(wlbrs_list[j].bandIndex);
			if(nvram_get_int("rssi_test") == 1)
			{
				if(wlbrs_list[j].bandIndex == 0)
					wlbrs_list[j].rssi = nvram_get_int("wl0_rssi");
				else if (wlbrs_list[j].bandIndex == 1)
					wlbrs_list[j].rssi = nvram_get_int("wl1_rssi");
				else if (wlbrs_list[j].bandIndex == 2)
					wlbrs_list[j].rssi = nvram_get_int("wl2_rssi");
			}
			else {
				wlbrs_list[j].rssi	= get_psta_rssi(wlbrs_list[j].bandIndex);
			}


			memset(prefix, 0x00, sizeof(prefix));
			sprintf(prefix, "wlc%d", j);

			if (wlbrs_list[j].state == WLC_STATE_CONNECTED) {
				char wlcif[16];
#ifdef RTCONFIG_DPSTA
			if (Is_dpsta) {
#if defined(RTCONFIG_AMAS_WGN) && defined(WGN_HAVE_VLAN0) 
				if (nvram_get_int("wgn_enabled") == 1)
					snprintf(wlcif, sizeof(wlcif), "%s.0", nvram_safe_get("sta_phy_ifnames"));
				else
					snprintf(wlcif, sizeof(wlcif), "%s", nvram_safe_get("sta_phy_ifnames"));
#else
				snprintf(wlcif, sizeof(wlcif), "%s", nvram_safe_get("sta_phy_ifnames"));
#endif
			}
			else
#endif
				snprintf(wlcif, sizeof(wlcif), "%s", wlbrs_list[j].wlcif);

				res = amas_get_cost(wlcif, wlbrs_list[j].bandIndex, SUMband, get_pap_bssid(wlbrs_list[j].bandIndex, bssid_str),  &hop);
				if (res == AMAS_RESULT_SUCCESS)
					wlbrs_list[j].hop = hop;
				else
					wlbrs_list[j].hop = -1;
			}
			else
				wlbrs_list[j].hop = -1;

			nvram_set_int(nvrampar, wlbrs_list[j].hop);
			nvram_set_int(nvrampar_res, res);

				BH_DBG("\n\
				wlbrs_list[%d].bandIndex=%d\n\
				wlbrs_list[%d].band = %d\n\
				wlbrs_list[%d].priority=%d\n\
				wlbrs_list[%d].wlcif = %s\n\
				wlbrs_list[%d].state = %d\n\
				wlbrs_list[%d].rssi = %d\n\
				wlbrs_list[%d].use = %d\n\
				wlbrs_list[%d].hop = %d (result = %s)\n",
				j, wlbrs_list[j].bandIndex,
				j, wlbrs_list[j].band,
				j, wlbrs_list[j].priority,
				j, wlbrs_list[j].wlcif,
				j, wlbrs_list[j].state,
				j, wlbrs_list[j].rssi,
				j, wlbrs_list[j].use,
				j, wlbrs_list[j].hop, amas_utils_str_error(res));
		}
		pthread_mutex_unlock(&lock_mutex);
	}
	pthread_exit(NULL);
}

int select_wifi_path(wl_br_status *wlbrs_list, int selwlentry)
{

	int i = 0, max_rssi = 0, selentry = -1;
	i = 0;

	BH_DBG("#### %s:%d wlc_band(%d), wait_time(%d)\n\n", __FUNCTION__, __LINE__,wlc_band, wait_time);
#if 0  //if 5G connected, update wifi path to 5G.
	foreach(wif, nvram_safe_get("sta_ifnames"), next)
	{
		if(wlc_band >= 0)
		{
			if (wlbrs_list[i].bandIndex == wlc_band  && wlbrs_list[i].state == WLC_STATE_CONNECTED && (wait_time == 0))
			{
				BH_DBG("#### %s:%d wlbrs_list[%d].bandIndex = %d\n\n", __FUNCTION__, __LINE__,i, wlbrs_list[i].bandIndex);
    			return i;
			}
		}
		i++;
	}
#endif
	if (selwlentry == -1)
	{
		wait_time = nvram_get_int("wait_band");
		if (wait_time > 0)
			return -2;
	}
	else if (max_band != connected && connected > 0 && wait_time > 0) {
			wait_time--;
			return -2;
	}
	else {
			wait_time = 0;
	}

	for (i = 0; i < SUMband; i++) 
	{

		if (wlbrs_list[i].state == WLC_STATE_CONNECTED ) {
			if(wlbrs_list[i].rssi > rssi_select_above) {
				selentry = i;
				break;
			}
			else if((wlbrs_list[i].rssi < rssi_select_above && wlbrs_list[i].rssi > rssi_select_below) && (max_rssi == 0 || max_rssi < wlbrs_list[i].rssi)) {
				max_rssi = wlbrs_list[i].rssi;
				selentry = i;
			}
			else if(wlbrs_list[i].band == BAND_2G) {
				selentry = i;
				break;
			}
			else {
				 selentry = i;
			}
		}
	}

	if (wait_time == 0)
	{
		nvram_set_int("wlc_band", selentry >= 0 ? wlbrs_list[selentry].bandIndex : -1);
	}

	return selentry;
}


int select_eth_path(eth_br_status *ethbrs_list, int selethentry, int selwlentry ) {

		int i = 0, selentry = -1, min_hop = -1;


		BH_DBG("#### %s:%d wait_wifi-- = %d  selwlentry = %d  selethentry= %d\n", __FUNCTION__, __LINE__, wait_wifi, selwlentry, selethentry);
		if (amas_ethernet == ETHERNET_NONE)
		{
			return -1;
		}

		if (amas_ethernet == ETHERNET_HOP)
		{
			if (ethbrs_list[i].state > 0 && ethbrs_list[i].hop >= 0)
			{
				if (selethentry == -1) {
					wait_wifi = nvram_get_int("wait_wifi");
					if (wait_wifi > 0)
						return -2;
				}
				else if (selethentry == -2 && wait_wifi > 0 && connected != max_band)
				{
						wait_wifi--;
						return -2;
				}
				else {
					wait_wifi = 0;
				}
			}
			else
			{
				wait_wifi = 0;
			}
		}

		for(i = 0; i < SUMeth ; i++) 
		{

			if (amas_ethernet == ETHERNET_PLUGIN)  {
				if (ethbrs_list[i].state > 0 && strcmp(ethbrs_list[i].ethif, nvram_safe_get("amas_ifname")))
					return i;

				if (ethbrs_list[i].state > 0) {
						selentry = i;
				}
			}

			if (amas_ethernet == ETHERNET_HOP)
			{
				if (ethbrs_list[i].state > 0 && strcmp(ethbrs_list[i].ethif, nvram_safe_get("amas_ifname")) && ethbrs_list[i].hop >= 0)
				{
					BH_DBG("#### %s:%d Don't need re-selection for ethernet path.(%d).\n", __FUNCTION__, __LINE__,i);
					return i;
				}

				if (ethbrs_list[i].state > 0 && ethbrs_list[i].hop >= 0) {

					if((min_hop == -1 || min_hop > ethbrs_list[i].hop)) {
						min_hop = ethbrs_list[i].hop;
						selentry = i;
					}
				}
				else if (ethbrs_list[i].state > 0 && ethbrs_list[i].hop < 0)
				{
					if ((strstr(ethbrs_list[i].ethif, nvram_safe_get("amas_ifname")) != NULL) && nvram_get_int("cfg_alive") == 1)
					{
						BH_DBG("#### %s:%d Keep ethernet selection by cfg_alive(%d).\n", __FUNCTION__, __LINE__,i);
						return i;
					}
				}
			}
		}

	return selentry;
}

int get_dpsta_maxhop(wl_br_status *wlbrs_list)
{

		int i = 0, max_hop = -1;

		for(i = 0; i < SUMband; i++) 
		{

			if (wlbrs_list[i].state == WLC_STATE_CONNECTED && wlbrs_list[i].hop >= 0) {

				if((max_hop == -1 || max_hop < wlbrs_list[i].hop)) {
					max_hop = wlbrs_list[i].hop;
				}
			}
		}
		return max_hop;
}

void add_ifname_to_bridge(wl_br_status *wlbrs_list, int selwlentry, eth_br_status *ethbrs_list, int selethentry)
{
	char wif[256]={0}, *next = NULL, selif[32]={0}, ssidbuf[32]={0};
	int bandIndex = -1, i= 0, wl_max_hop = -1, wifipath = 0, ethpath = 0;
	int bw = 0;
	int chk_del_eth_brif = -1, chk_del_wifi_brif = -1, chk_add_brif = -1;
	BH_DBG("%s:%d:selwlentry(%d), selethentry(%d).\n",__FUNCTION__,__LINE__, selwlentry, selethentry);

	for(i = 0; i <SUMband; i++)
	{
		if (Is_dpsta)
		{
			if (wlbrs_list[i].state == WLC_STATE_CONNECTED)
			 {
				wifipath |= wlbrs_list[i].defif;
			}
		}
		else { // dpsr
			if (i == selwlentry)
				wifipath = wlbrs_list[i].defif;
		}
	}
#ifdef RTCONFIG_DPSTA
	if (Is_dpsta && connected > 1 && (wifipath & 12)) { // 5G-1 and 5G-2 = 1100
		if (nvram_get_int("dpsta_policy") == DPSTA_POLICY_AUTO_1)
		{
			BH_DBG("%s:%d DPSTA_POLYC_AUTO_5G and 2.4G & 5G connected to CAP. Change wifipath to 5G.\n", __FUNCTION__, __LINE__);
			wifipath = wifipath & 8 ? 8 : 4;
		}
	}
#endif

	for(i = 0; i < SUMeth; i++)
	{
		if (amas_ethernet == ETHERNET_HOP)
		{
			if (ethbrs_list[i].state > 0 && ethbrs_list[i].hop >= 0)
			{
				ethpath |= ethbrs_list[i].defif;
			}
			else if (ethbrs_list[i].state > 0 && ethbrs_list[i].hop < 0)
			{
				if ((strstr(ethbrs_list[i].ethif, nvram_safe_get("amas_ifname")) != NULL) && nvram_get_int("cfg_alive") == 1)
				{
					ethpath |= ethbrs_list[i].defif;
				}
			}
		}
		if (amas_ethernet == ETHERNET_PLUGIN)
		{
			if (ethbrs_list[i].state > 0)
			{
				ethpath |= ethbrs_list[i].defif;
			}
		}
	}

	if ((selethentry != -2 && selwlentry >= 0) || selethentry >= 0)
	{
		if (selethentry >= 0  && selwlentry >= 0)
		{
			if (amas_ethernet == ETHERNET_HOP)
			{

				if (Is_dpsta)
				{
					wl_max_hop = get_dpsta_maxhop(wlbrs_list);
				}
				else {
					wl_max_hop = wlbrs_list[selwlentry].hop;
				}

				if (ethbrs_list[selethentry].hop >= 0)
				{
					BH_DBG("ethernet hop(%d), wireless hop(%d).\n", ethbrs_list[selethentry].hop, wl_max_hop);
					if (ethbrs_list[selethentry].state > 0 && ((wl_max_hop >= 0 && ethbrs_list[selethentry].hop <= wl_max_hop) || wl_max_hop < 0))
					{
							memcpy(selif, ethbrs_list[selethentry].ethif, sizeof(selif));
							brifname = ethpath;
							BH_DBG("select %s  (brifname = %02X).\n", selif, brifname);
					}
					else
					{
						bandIndex = wlbrs_list[selwlentry].bandIndex;
						memset(ssidbuf, 0x00, sizeof(ssidbuf));
						sprintf(ssidbuf, "wlc%d_ssid", bandIndex);
						nvram_set("wlc_ssid", nvram_safe_get(ssidbuf));

						if(Is_dpsta && strcmp(nvram_safe_get("sta_phy_ifnames"), "")) {
							memcpy(selif, nvram_safe_get("sta_phy_ifnames"), sizeof(selif));
							brifname = wifipath;
							BH_DBG("select %s (brifname = %02X).\n", selif, brifname);
						}
						else {
							memset(selif, 0x00, sizeof(selif));
							memcpy(selif, wlbrs_list[selwlentry].wlcif, sizeof(selif));
							brifname = wifipath;
							BH_DBG("select band %d (index: %d, brifname = %02X).\n", wlbrs_list[selwlentry].band, wlbrs_list[selwlentry].bandIndex, brifname);
						}
					}
				}
				else if (ethbrs_list[selethentry].hop < 0)
				{
					if ((strstr(ethbrs_list[selethentry].ethif, nvram_safe_get("amas_ifname")) != NULL) && nvram_get_int("cfg_alive") == 1)
					{
						memcpy(selif, ethbrs_list[selethentry].ethif, sizeof(selif));
						brifname = ethpath;
						BH_DBG("Can't get lldpd cost, but cfg_alive =1, Keep %s  (brifname = %02X).\n", selif, brifname);
					}
					else
					{
						bandIndex = wlbrs_list[selwlentry].bandIndex;
						memset(ssidbuf, 0x00, sizeof(ssidbuf));
						sprintf(ssidbuf, "wlc%d_ssid", bandIndex);
						nvram_set("wlc_ssid", nvram_safe_get(ssidbuf));

						if(Is_dpsta && strcmp(nvram_safe_get("sta_phy_ifnames"), "")) {
							memcpy(selif, nvram_safe_get("sta_phy_ifnames"), sizeof(selif));
							brifname = wifipath;
							BH_DBG("select %s (brifname = %02X).\n", selif, brifname);
						}
						else {
							memset(selif, 0x00, sizeof(selif));
							memcpy(selif, wlbrs_list[selwlentry].wlcif, sizeof(selif));
							brifname = wifipath;
							BH_DBG("select band %d (index: %d, brifname = %02X).\n", wlbrs_list[selwlentry].band, wlbrs_list[selwlentry].bandIndex, brifname);
						}
					}
				}
			}

			if (amas_ethernet == ETHERNET_PLUGIN)
			{
				memcpy(selif, ethbrs_list[selethentry].ethif, sizeof(selif));
				brifname = ethpath;
				BH_DBG("select %s  (brifname = %02X).\n", selif, brifname);
			}
		}
		else if (selwlentry>=0)
		{
			bandIndex = wlbrs_list[selwlentry].bandIndex;
			memset(ssidbuf, 0x00, sizeof(ssidbuf));
			sprintf(ssidbuf, "wlc%d_ssid", bandIndex);
			nvram_set("wlc_ssid", nvram_safe_get(ssidbuf));

			if(strcmp(nvram_safe_get("sta_phy_ifnames"), "") && Is_dpsta) {
					memcpy(selif, nvram_safe_get("sta_phy_ifnames"), sizeof(selif));
					brifname = wifipath;
					BH_DBG("select %s (brifname = %02X).\n", selif, brifname);

			}
			else {
				memset(selif, 0x00, sizeof(selif));
				memcpy(selif, wlbrs_list[selwlentry].wlcif, sizeof(selif));
				brifname = wifipath;
				BH_DBG("select band %d (index: %d, brifname = %02X).\n", wlbrs_list[selwlentry].band, wlbrs_list[selwlentry].bandIndex, brifname);

			}
		}
		else if (selethentry >= 0)
		{
			memcpy(selif, ethbrs_list[selethentry].ethif, sizeof(selif));
			brifname = ethpath;
			BH_DBG("select %s  (brifname = %02X).\n", selif, brifname);
			nvram_set_int("wlc_band", -1);
		}

		//last_ethpath = ethpath;

		if(brifname != nvram_get_int("amas_path_stat")) {
			nvram_set_int("amas_path_stat", brifname);
#ifdef RTCONFIG_CFGSYNC
			if (nvram_get_int("cfg_alive") == 1 && nvram_get_int("amas_path_report") != brifname) {
				BH_DBG("===== Update path (amas_path_state = %02X) to cfg_mnt.=======\n", brifname);
				send_event_to_cfgmnt(EID_RC_REPORT_PATH);
				nvram_set_int("amas_path_report", brifname);
			}
			else
			BH_DBG("===== Can't Update path (amas_path_state = %02X) to cfg_mnt. (disconnect with cfg_server)=======\n", brifname);
#endif
		}

		if (strcmp(selif, nvram_safe_get("amas_ifname")))
		{
			foreach(wif, nvram_safe_get("sta_phy_ifnames"), next) {
				chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
				if (chk_del_wifi_brif != -1) {
					dbG("Delete %s from %s successfully.(1)\n", wif, nvram_safe_get("lan_ifname"));
					if (!nvram_match("amas_ifname", ""))
						nvram_set("amas_ifname", "");
				}
			}
#ifdef RTCONFIG_BROOP
			if(!nvram_match("reset_broop", "1"))
#endif
			foreach(wif, nvram_safe_get("eth_ifnames"), next) {
				chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
				if (chk_del_eth_brif != -1) {
					dbG("Delete %s from %s successfully.(2)\n", wif, nvram_safe_get("lan_ifname"));
					if (!nvram_match("amas_ifname", ""))
						nvram_set("amas_ifname", "");
				}
			}

			BH_DBG("===== add lan ifname(%s) to bridge !!!!.\n", selif);
			pre_addif_bridge(brifname);
			chk_add_brif = ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), selif);
			if (chk_add_brif != -1)
			{
				dbG("Add %s to %s successfully.\n", selif, nvram_safe_get("lan_ifname"));
				logmessage("BHC","Add %s to %s successfully.\n", selif, nvram_safe_get("lan_ifname"));
				nvram_set("amas_ifname", selif);
				post_addif_bridge(brifname);
			}
		}

		if (selwlentry >= 0)
		{
			for(i = 0; i < SUMband; i++)
			{
				if(wlbrs_list[i].state == WLC_STATE_CONNECTED && wlbrs_list[selwlentry].bandIndex != wlbrs_list[i].bandIndex)
				{
					bw = wl_get_bw(wlbrs_list[i].bandIndex);
                    for (handler = handler_entry; handler->bandWidth; handler++)
                    {
                        if(wlbrs_list[selwlentry].bandIndex ==  handler->bandIndex && handler->bandWidth == bw && wlbrs_list[i].rssi < handler->rssi_threshold) {
                            if(worst_signal_count > worst_signal_count_threshold) {
                                nvram_set_int("skip_wlc_band", wlbrs_list[i].bandIndex);
                                BH_DBG("#### %s:%d wlbrs_list[%d].rssi(%d)  handler->rssi_threshold(%d) skip_wlc_band(%d)\n\n", __FUNCTION__, __LINE__,i, wlbrs_list[i].rssi, handler->rssi_threshold, wlbrs_list[i].bandIndex);
                                break;
                            }
                            worst_signal_count++;
                        }
                        else if (wlbrs_list[selwlentry].bandIndex ==  handler->bandIndex && handler->bandWidth == bw && wlbrs_list[i].rssi > handler->rssi_threshold)
                            if(worst_signal_count > 0 && worst_signal_count < worst_signal_count_threshold)
                                worst_signal_count = 0;
                    }
				}
			}
		}
	}
	else
	{

		BH_DBG("===== No connection with P-AP !. cfg_alive = %d\n", nvram_get_int("cfg_alive"));

		last_ethpath = 0;
		worst_signal_count = 0;
		nvram_set("wlc_ssid", "");
		nvram_unset("skip_wlc_band");

		//selethentry == -2, Add Ethernet to temporary backhaul, if ethernet plug-in and wireless is disconnect.
		if (selethentry == -2)
		{
			if (!strstr(nvram_safe_get("eth_ifnames"), nvram_safe_get("amas_ifname")) || !strcmp(nvram_safe_get("amas_ifname"), ""))
			{
			 	brifname = ethpath;

				foreach(wif, nvram_safe_get("sta_phy_ifnames"), next)
				{
					chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
					if (chk_del_wifi_brif != -1) {
						dbG("Delete %s from %s successfully.(3)\n", wif, nvram_safe_get("lan_ifname"));
						if (!nvram_match("amas_ifname", ""))
							nvram_set("amas_ifname", "");
					}
				}
#ifdef RTCONFIG_BROOP
				if(!nvram_match("reset_broop", "1"))
#endif
				foreach(wif, nvram_safe_get("eth_ifnames"), next) {
					chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
					if (chk_del_eth_brif != -1) {
						dbG("Delete %s from %s successfully.(4)\n", wif, nvram_safe_get("lan_ifname"));
						if (!nvram_match("amas_ifname", ""))
							nvram_set("amas_ifname", "");
					}
				}

				pre_addif_bridge(brifname);
				chk_add_brif = ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), nvram_safe_get("eth_ifnames"));
				if (chk_add_brif != -1)
				{
					dbG("Add ethernet backhaul(%s) to bridge and waiting wi-fi connection!\n", nvram_safe_get("eth_ifnames"));
					BH_DBG("Add ethernet backhaul(%s) to bridge and waiting wi-fi connection!\n", nvram_safe_get("eth_ifnames"));
					logmessage("BHC","Add ethernet backhaul(%s) to bridge and waiting wi-fi connection!\n", nvram_safe_get("lan_ifname"));
					nvram_set("amas_ifname", nvram_safe_get("eth_ifnames"));
					post_addif_bridge(brifname);
				}
			}
		}
		else
		{
#ifdef RTCONFIG_DPSTA
			if (dpsta_mode())
			{
				if (!strstr(nvram_safe_get("sta_phy_ifnames"), nvram_safe_get("amas_ifname")) || !strcmp(nvram_safe_get("amas_ifname"), ""))
				{
					brifname = wifipath;
#ifdef RTCONFIG_BROOP
					if(!nvram_match("reset_broop", "1"))
#endif
					foreach(wif, nvram_safe_get("eth_ifnames"), next) {
						chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
						if (chk_del_eth_brif != -1) {
							dbG("Delete %s from %s successfully.(5)\n", wif, nvram_safe_get("lan_ifname"));
							if (!nvram_match("amas_ifname", ""))
								nvram_set("amas_ifname", "");
						}
					}

					foreach(wif, nvram_safe_get("sta_phy_ifnames"), next) {
						pre_addif_bridge(brifname);
						chk_add_brif = ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), wif);
						if (chk_add_brif != -1){
							dbG("Add %s to %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
							logmessage("BHC","Add %s to %s successfully.\n", wif, nvram_safe_get("lan_ifname"));
							nvram_set("amas_ifname", wif);
							post_addif_bridge(brifname);
						}
					}
				}
			}
			else
#endif
			{
				if (selwlentry == -2)
				{
					for(i = 0; i < SUMband; i++)
					{
						/*Select the first interface that is connection to the P-AP as backhaul because it has been sorted*/
						if (wlbrs_list[i].state == WLC_STATE_CONNECTED)
						{
							memset(selif, 0x00, sizeof(selif));
							memcpy(selif, wlbrs_list[i].wlcif, sizeof(selif));
							brifname = wlbrs_list[i].defif;
							BH_DBG("select band %d (index: %d, brifname = %02X).\n", wlbrs_list[i].band, wlbrs_list[i].bandIndex, brifname);
							break;
						}
					}
					if (strncmp(selif, "", sizeof(selif)))
					{
						if (!strstr(selif, nvram_safe_get("amas_ifname")) || !strcmp(nvram_safe_get("amas_ifname"), ""))
						{
							foreach(wif, nvram_safe_get("sta_phy_ifnames"), next)
							{
								chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
								if (chk_del_wifi_brif != -1) {
									dbG("Delete %s from %s successfully.(6)\n", wif, nvram_safe_get("lan_ifname"));
									if (!nvram_match("amas_ifname", ""))
										nvram_set("amas_ifname", "");
								}
							}
#ifdef RTCONFIG_BROOP
							if(!nvram_match("reset_broop", "1"))
#endif
							foreach(wif, nvram_safe_get("eth_ifnames"), next) {
								chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
								if (chk_del_eth_brif != -1) {
									dbG("Delete %s from %s successfully.(7)\n", wif, nvram_safe_get("lan_ifname"));
									if (!nvram_match("amas_ifname", ""))
										nvram_set("amas_ifname", "");
								}
							}

							pre_addif_bridge(brifname);
							chk_add_brif = ioctl_for_bridge(ARG_addif, nvram_safe_get("lan_ifname"), selif);
							if (chk_add_brif != -1)
							{
								dbG("Add wireless(%s) to bridge and Waiting for another band to connect!\n", selif);
								BH_DBG("Add wireless(%s) to bridge and Waiting for another band to connect!\n", selif);
								logmessage("BHC","Add wireless(%s) to bridge and and Waiting for another band to connect!\n", selif);
								nvram_set("amas_ifname", selif);
								post_addif_bridge(brifname);
							}
						}
					}
				}
				else
				{
					if (strcmp(nvram_safe_get("amas_ifname"), ""))
					{
						foreach(wif, nvram_safe_get("sta_phy_ifnames"), next) {
							chk_del_wifi_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
							if (chk_del_wifi_brif != -1) {
								dbG("Delete %s from %s successfully.(8)\n", wif, nvram_safe_get("lan_ifname"));
								if (!nvram_match("amas_ifname", ""))
									nvram_set("amas_ifname", "");
								brifname = -1;
							}
						}
#ifdef RTCONFIG_BROOP
						if(!nvram_match("reset_broop", "1"))
#endif
						foreach(wif, nvram_safe_get("eth_ifnames"), next) {
							chk_del_eth_brif = ioctl_for_bridge(ARG_delif, nvram_safe_get("lan_ifname"), wif);
							if (chk_del_eth_brif != -1) {
								dbG("Delete %s from %s successfully.(9)\n", wif, nvram_safe_get("lan_ifname"));
								if (!nvram_match("amas_ifname", ""))
									nvram_set("amas_ifname", "");
								brifname = -1;
							}
						}
					}
				}
			}
		}

		if(brifname != nvram_get_int("amas_path_stat"))
		{
			nvram_set_int("amas_path_stat", brifname);
#ifdef RTCONFIG_CFGSYNC
			if (nvram_get_int("cfg_alive") == 1 && nvram_get_int("amas_path_report") != brifname) {
				BH_DBG("===== Update path (amas_path_state = %02X) to cfg_mnt.=======\n", brifname);
				send_event_to_cfgmnt(EID_RC_REPORT_PATH);
				nvram_set_int("amas_path_report", brifname);
			}
			else
			BH_DBG("===== Can't Update path (amas_path_state = %02X) to cfg_mnt. (disconnect with cfg_server)=======\n", brifname);
#endif
		}

		nvram_set_int("wlc_band", -1);
	}
}

void select_bh_path(int sig)
{
	int i = 0;
	bhctl_dbg = nvram_get_int("bhctl_dbg");
	wlc_band = nvram_get_int("wlc_band");

	connected = 0;
	for (i = 0; i < SUMband; i++)
	{
		if (wlbrs_list[i].state == WLC_STATE_CONNECTED)
		{
			connected ++;
		}
	}

	if (last_connected != connected)
	{
		BH_DBG("WiFi connection status change.\n");
		logmessage("BHC","WiFi connection status change..\n");

		for (i = 0; i < SUMband; i++)
		{
			BH_DBG("bandindex(%d): state is %d\n", wlbrs_list[i].bandIndex, wlbrs_list[i].state);
			logmessage("BHC","bandindex(%d): state is %d\n", wlbrs_list[i].bandIndex, wlbrs_list[i].state);
		}

		last_connected = connected;
	}

	if (last_brifname != brifname)
	{
		BH_DBG("Topology change from %d to %d.\n", last_brifname, brifname);
		logmessage("BHC","Topology change from %d to %d.\n", last_brifname, brifname);
		last_brifname = brifname;
		nvram_set_int("amas_path_reselection", 1);
	}

	if (nvram_get_int("amas_path_reselection") == 1)
	{
		BH_DBG("Start AMAS Path Reselection!\n");
		logmessage("BHC","Start AMAS Path Reselection!");

		if (selwlentry > 0)
		{
			selwlentry = -1;
			wait_time = nvram_get_int("wait_band");
		}

		if (selethentry > 0)
		{
			selethentry = -1;
			wait_wifi = nvram_get_int("wait_wifi");
		}

		nvram_unset("skip_wlc_band");
		nvram_set_int("amas_path_reselection", 0);
	}

	selwlentry = select_wifi_path(wlbrs_list, selwlentry);
	selethentry = select_eth_path(ethbrs_list, selethentry, selwlentry);
	add_ifname_to_bridge(wlbrs_list, selwlentry, ethbrs_list, selethentry);
#ifdef RTCONFIG_BROOP
	reset_broop_ethif();
#endif

	alarm(timer);
}

int amas_bhctrl_main(void)
{

	FILE *fp = NULL;
	timer = nvram_get_int("bhctl_timer") ? : INTERVAL;
	status_timer = nvram_get_int("bhctl_status_timer") ? : 2;
	amas_ethernet = nvram_get_int("amas_ethernet") ? : ETHERNET_HOP;
	int res = 0, i = 0;
	pthread_t wifi_thread, eth_thread;

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



#ifdef RTCONFIG_DPSTA
	Is_dpsta = dpsta_mode();
#endif

	nvram_set("amas_rssi_above", "-1000");  //select 5G for upstream path, if 5G is connected to P-AP.

	wait_time = nvram_get_int("wait_band");
	wait_wifi = nvram_get_int("wait_wifi");
	rssi_select_above = nvram_get_int("amas_rssi_above") ? : RSSI_SELECT_ABOVE;
	rssi_select_below = nvram_get_int("amas_rssi_below") ? : RSSI_SELECT_BELOW;


	/* write pid */
	if ((fp = fopen("/var/run/amas_bhctrl.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	SUMband = get_wl_count();
	SUMeth = get_eth_count();

	bhctl_dbg = nvram_get_int("bhctl_dbg");
	wlbrs_list = (struct _wl_br_status *) malloc(SUMband *sizeof(struct _wl_br_status));
	ethbrs_list = (struct _eth_br_status *) malloc(SUMeth *sizeof(struct _eth_br_status));

	if (wlbrs_list == NULL || ethbrs_list == NULL) {
		dbG("Can't alloc memory for %s\n", __FILE__);
		return 0;
	}


	init_wlc_status(wlbrs_list, SUMband);
	init_eth_status(ethbrs_list);
	init_signal_threshold();

	nvram_set("amas_ifname", "");
	nvram_set_int("amas_path_stat", -1);
	nvram_unset("skip_wlc_band");
	nvram_set_int("amas_path_reselection", 0);
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

	for(i = 0; i < SUMband; i++)
	{
		if (wlbrs_list[i].use)
			max_band++;
	}


#ifdef PTHREAD_STACK_SIZE
	attrp = &attr;
	/* change the default stack size of pthread */
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif

	res = pthread_mutex_init(&lock_mutex, NULL);
	if (res != 0) {
		dbG("[update info] semaphore initialization failed\n");
		goto exit;
	}
#ifndef RTCONFIG_NO_PTHREAD_TIMEDWAIT
	res = pthread_cond_init(&wifi_cond, NULL);
	if (res != 0) {
		dbG("[update wireless info] wifi_cond initialization failed\n");
		goto exit;
	}
	res = pthread_cond_init(&eth_cond, NULL);
	if (res != 0) {
		dbG("[update wireless info] wifi_cond initialization failed\n");
		goto exit;
	}
#endif
	res = pthread_create (&wifi_thread, attrp, update_wlc_status, (void*)wlbrs_list);
	if (res != 0) {
		dbG("wifi_thread creation failed");
		goto exit;
	}

	res = pthread_create (&eth_thread, attrp, update_eth_status, (void*)ethbrs_list);
	if (res != 0) {
		dbG("eth_thread creation failed");
		goto exit;
	}

	signal(SIGALRM, select_bh_path);
	signal(SIGCHLD, h_chld);
	alarm(timer);

	while(loop)
    {
    	pause();
    }

exit:
	if (wlbrs_list != NULL)
		free(wlbrs_list);

	if (ethbrs_list != NULL)
		free(ethbrs_list);

    if (sig_entry != NULL)
        free(sig_entry);

#ifdef PTHREAD_STACK_SIZE
	if (attrp != NULL) pthread_attr_destroy(attrp);
#endif
	return 0;
}


