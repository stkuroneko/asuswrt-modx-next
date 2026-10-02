#include <sys/reboot.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <rc.h>
#include <shared.h>
#ifdef HND_ROUTER
#include <sys/stat.h>
#endif
#if defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
#include <wlutils.h>
#endif
#include <bcmendian.h>

#define MAX_STA_COUNT 128
#define MAX_SUBIF_NUM 4

//static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))

static int adtbw_dbg = 0;
#define ADTBW_DBG(fmt, arg...) \
        do { if (adtbw_dbg) \
                dbg("ADTBW %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
        } while (0)


static char* adtbw_get_ifname(int unit)
{
	char *name = NULL;
	char nv_interface[NVRAM_MAX_PARAM_LEN];
	int wlidx;
	int model;

	snprintf(nv_interface, sizeof(nv_interface), "wl%d_ifname", unit);
	name = nvram_safe_get(nv_interface);
	if (!strlen(name)) {
		model = get_model();
		switch(model) {
			case MODEL_GTAC5300:
				wlidx = 6;
				break;
			case MODEL_RTAC86U:
				wlidx = 5;
				break;
			default:
				wlidx = 1;
				break;
		}
		sprintf(name, "eth%d", unit + wlidx);
	}

	return name;

}

static int adtbw_bw_allow(int unit) {

	int wlbw = -1;
	char tmp[32] = {0};
	snprintf(tmp, sizeof(tmp), "wl%d_bw", unit);
	wlbw = nvram_get_int(tmp);

	ADTBW_DBG("%s = %d\n", tmp, wlbw);

	if(wlbw == 0 || wlbw == 2)	return 1;	//auto or force 40MHz
	else				return 0;

}

static chanspec_t adtbw_get_chanspec(int unit) {

        char buf[256] = {0};
        char *name = NULL;
        int chansp;
        chanspec_t chanspec = 0;

	name = adtbw_get_ifname(unit);
	if(!strlen(name))
		return chanspec;

	if (wl_iovar_getint(name, "chanspec", &chansp) < 0) {
		ADTBW_DBG("Get chanspec iovar failed...\n");
	}
	else {
		chanspec = (chanspec_t)dtoh32(chansp);
		wf_chspec_ntoa(chanspec, buf);
		ADTBW_DBG("%s (0x%x)\n", buf, chanspec);
	}

	return chanspec;
}

static int adtbw_sta_ht_cap_40M(char *name, struct ether_addr *ea)
{
	char buf[sizeof(sta_info_t)];
	uint32 ht_cap;

	strcpy(buf, "sta_info");
	memcpy(buf + strlen(buf) + 1, (unsigned char *)ea, ETHER_ADDR_LEN);

	if (!wl_ioctl(name, WLC_GET_VAR, buf, sizeof(buf))) {
		sta_info_t *sta = (sta_info_t *)buf;
		ht_cap = sta->ht_capabilities;

		ADTBW_DBG("%s: ht_cap=%d\n", name, ht_cap);

		if ((ht_cap & WL_STA_CAP_40MHZ) ||
		    (ht_cap & WL_STA_CAP_SHORT_GI_40))

		return 1;
	}

        return 0;
}


static int adtbw_sta_info_match(int unit) {

	char *ifname = NULL;
	char prefix[32], tmp[128], name[32];
	int sub_unit;
	struct maclist *mac_list;
	int mac_list_size;
	int total_sta_cnt = 0;
	int match = 1;
	int i = 0;

	mac_list_size = sizeof(mac_list->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	mac_list = malloc(mac_list_size);
	if(!mac_list) {
		match = 0;
		goto exit;
	}

	ifname = adtbw_get_ifname(unit);
	if(!strlen(ifname)) {
		match = 0;
		goto exit;
	}

	for(sub_unit = 0; sub_unit < MAX_SUBIF_NUM; sub_unit++) {
		if(sub_unit > 0) {
			snprintf(prefix, sizeof(prefix), "wl%d.%d", unit, sub_unit);
			snprintf(name, sizeof(name), "wl%d.%d", unit, sub_unit);
		}
		else {
			snprintf(prefix, sizeof(prefix), "wl%d", unit);
			snprintf(name, sizeof(name), "%s", ifname);
		}
		if( !nvram_match(strcat_r(prefix, "_radio", tmp), "1") ) continue;
		if( !nvram_match(strcat_r(prefix, "_bss_enabled", tmp), "1") ) continue;

		memset(mac_list, 0, mac_list_size);
		/* query authentication sta list */
		strcpy((char*) mac_list, "authe_sta_list");
		if(wl_ioctl(name, WLC_GET_VAR, mac_list, mac_list_size))
			goto exit;

		total_sta_cnt += mac_list->count;
		ADTBW_DBG("%s total station count = %d\n", name, total_sta_cnt);
		if(total_sta_cnt != 1) {
			match = 0;
			break;
		}

		for (i = 0; i < mac_list->count; i++) {
			if(adtbw_sta_ht_cap_40M(name, &mac_list->ea[i])) {
				match = 0;
				break;
			}
		}
	}

exit:
        if(mac_list) free(mac_list);
        return match;
}




int adtbw_enable()
{
#if 0
	FILE *fp = NULL;
	char buffer[64] = {0};
	int adtbw = 0;

	adtbw_dbg = nvram_get_int("ADTBW_DBG");

	if (!pids("envrams")) {
		system("/usr/sbin/envrams");
		usleep(100000);
	}

	memset(buffer, 0, sizeof(buffer));
	fp = popen("/usr/sbin/envram get adtbw", "r");
	if(fp) {
		fgets(buffer, sizeof(buffer), fp);
		adtbw = (atoi(buffer) > 0) ? 1 : 0;
                pclose(fp);
        }
#else
	int adtbw = (nvram_get_int("adtbw_disable_force") || strncmp(nvram_safe_get("territory_code"), "US", 2))
? 0 : 1;
#endif

	ADTBW_DBG("adtbw enable = %d\n", adtbw);

	return adtbw;
}

int adtbw_config()
{
	return adtbw_bw_allow(0); //2.4GHz only
}

int adtbw_enter()
{
	ADTBW_DBG("check enter...\n");
	chanspec_t chanspec = adtbw_get_chanspec(0);
	if(CHSPEC_IS40(chanspec) && adtbw_sta_info_match(0))	return 1; //only one sta and w/o HT40 cap, AP is 40MHz
	else							return 0;	
}

int adtbw_leave()
{
	ADTBW_DBG("check leave...\n");
	if(!adtbw_sta_info_match(0))	return 1;
	else				return 0;
}

int adtbw_active()
{
	FILE *fp;
	char buf[32] = {0};
	chanspec_t chansp = 0;
	int channel = 0;
	chansp = adtbw_get_chanspec(0);
	wf_chspec_ntoa(chansp, buf);

	if(strchr(buf, 'u') != NULL || strchr(buf, 'l') != NULL) {

		if ((fp = fopen("/tmp/abw_chsp", "w")) != NULL) {
			fprintf(fp, "%s", buf);
			fclose(fp);
		}
		else {
			ADTBW_DBG("Fail to open /tmp/abw_chsp\n");
			return 0;
		}
	}

	channel = wf_chspec_ctlchan(chansp);
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d", channel);
	ADTBW_DBG("*** adjust to chanspec %s ***\n", buf);

	eval("wl", "down");
	eval("wl", "chanspec", buf);
	eval("wl", "up");

	return 1;
}

int adtbw_restore()
{
	FILE *fp;
        char buf[64];
	chanspec_t chansp_40m;
	char *chsp = nvram_get("wl0_chanspec");

        if(strlen(chsp) > 0 && strcmp(chsp, "0") != 0) {
	ADTBW_DBG("*** restore chanspec from wl0_chanspec: %s ***\n", chsp);
                eval("wl", "down");
                eval("wl", "chanspec", chsp);
                eval("wl", "up");
        }
        else {
		if (!(fp=fopen("/tmp/abw_chsp", "r"))) {
                        return 0;
                }
                fgets(buf, sizeof(buf), fp);
                fclose(fp);
                //read from file
		chansp_40m = wf_chspec_aton(buf);
		ADTBW_DBG("*** restor chanspec from /tmp/abw_chsp: %s\n ***", buf);
		if(CHSPEC_IS40(chansp_40m)) {
			eval("wl", "down");
			eval("wl", "chanspec", buf);
			eval("wl", "up");
		}
        }

	unlink("/tmp/abw_chsp");

	return 1;
}
