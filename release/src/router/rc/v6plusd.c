#define _GNU_SOURCE

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
#include <shared.h>
#include <wlioctl.h>
#include <rc.h>
#include <curl/curl.h>
#include <json.h>

static int CURRENT_STATE = S46_MAPSVR_INIT;
static int FORCE_TRIGGER = 1;
static int HGW_STATE_CHK = 1;
static int HGW_DHCP_WAIT = 0;
static int DEF_INTERVAL = 30;
static int WAN_PROTO = -1;
static int WAN_UNIT = 0;
static char WAN_PREFIX[16] = {0};
static char WAN_IFNAME[32] = {0};
static struct itimerval tick;

static void do_v6plus_check(void);

int check_v6plusd(int unit)
{
	char pid_file[64];
	char buf[64];
	pid_t pid;

	snprintf(pid_file, sizeof(pid_file), V6PLUSD_PIDFILE, unit);
	f_read_string(pid_file, buf, sizeof(buf));

	pid = strtoul(buf, NULL, 0);
	if (!process_exists(pid)) {
		snprintf(buf, sizeof(buf), "start_v6plusd %d", unit);
		notify_rc(buf);
		return 1;
	}

	return 0;
}

static int getRandom(int min, int max)
{
	srand(time(0));
	return (rand() % (max - min + 1)) + min;
}

static int GetExeTime(int status)
{
	int t_unit;

	t_unit = nvram_get_int("v6plusd_debug");

	if (S46_MAPSVR_DATA_INVALID == status) {
		// 10-30 min
		if (!t_unit)
			return getRandom(10*60, 30*60);
		else //debug
			return getRandom(10*t_unit, 30*t_unit);
	} else if (S46_MAPSVR_ERR == status ||
		   S46_MAPSVR_OK  == status) {
		// 3-24 hr
		if (!t_unit)
			return getRandom(3*60*60, 24*60*60);
		else //debug
			return getRandom(3*t_unit, 24*t_unit);
	} else if (S46_MAPSVR_INIT == status ||
		   S46_MAPSVR_NO_RESPONSE == status) {
		// 1-10 min
		if (!t_unit)
			return getRandom(1*60, 10*60);
		else //debug
			return getRandom(1*t_unit, 10*t_unit);
	} else
		return 0;
}

static void setalarm_t(unsigned long sec, unsigned long usec)
{
	//Timeout to run first time
	tick.it_value.tv_sec = sec;
	tick.it_value.tv_usec = usec;

	//After first, the Interval time for clock
	tick.it_interval = tick.it_value;
	if (setitimer(ITIMER_REAL, &tick, NULL) < 0)
		S46_DBG("[Err] set alarm timer failed!\n");
	else
		S46_DBG("[ALRM TIME] alarm set after %d sec\n", sec);
}

static void handlesignal(int signum)
{
	if (signum == SIGUSR1) {
		S46_DBG("[Get SIGUSR1]\n");
		FORCE_TRIGGER = 1;
		setalarm_t(1, 0);
	} else if (signum == SIGUSR2) {
		S46_DBG("[DEBUG][Get SIGUSR2]\n");
		setalarm_t(1, 0);
	} else if (signum == SIGALRM) {
		do_v6plus_check();
	} else if (signum == SIGTERM) {
		char path[128];
		setalarm_t(0, 0);
		snprintf(path, sizeof(path), V6PLUSD_PIDFILE, WAN_UNIT);
		remove(path);
		nvram_pf_set_int(WAN_PREFIX, "s46_mapsvr_state", S46_MAPSVR_INIT);
		S46_DBG("Exit!!!\n");
		exit(0);
	} else
		S46_DBG("Unknown SIGNAL\n");
}

static void signal_register(void) {

	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handlesignal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void _restart_wan_if(void)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "restart_wan_if %d", WAN_UNIT);
	notify_rc_and_wait(buf);
}

void s46_jpne_report(char *id, int act, int reason)
{
	CURL *curl;
	CURLcode res;
	json_object *json, *obj;
	char ret[4], url[256], *buf, *p, *s;
	size_t bufsz;
	FILE *fp;
	long rsp_code = -1;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	if ((curl = curl_easy_init())) {
		if (asprintf(&buf, "%s%s", (id && *id) ? "&id=" : "", (id && *id) ? id : "") < 0 ||
		    !get_s46_url(url, sizeof(url), SET_V6PLUS_URL, act, reason, buf))
			goto cleanup;

		if (f_exists(S46_DEBUG))
			S46_DBG("[REPLY_JPNE_URL] %s\n", url);

		curl_easy_setopt(curl, CURLOPT_URL, url);
		free(buf);

		if ((fp = open_memstream(&buf, &bufsz)) == NULL)
			goto cleanup;

		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rsp_code);
		S46_DBG("[HTTP_RESPONSE_CODE]:%d\n", rsp_code);
		fclose(fp);

		json = NULL;
		if (res == CURLE_OK) {
			for (p = buf; (p = s = strstr(p, "rpt"));) {
				p += sizeof("rpt") - 1;
				if (s == buf || isspace(s[-1])) {
					while (*p && isspace(*p)) p++;
					if (*p == '(') {
						*strchrnul(++p, ')') = '\0';
						json = json_tokener_parse(p);
						break;
					}
				}
			}
		} else
			goto cleanup;
		S46_DBG("[ret] %s\n", json_object_to_json_string(json));
		if (json) {
			if (json_object_object_get_ex(json, "status", &obj))
				strlcpy(ret, json_object_get_string(obj), sizeof(ret));
			json_object_put(json);
		}
	cleanup:
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	return;
}

char *s46_jpne_maprules(char *id, char *idbuf, size_t idlen, long *rsp_code)
{
	CURL *curl;
	CURLcode res;
	json_object *json, *obj, *list_obj, *entry_obj;
	char addrbuf[INET6_ADDRSTRLEN], url[256], *buf, *p, *s, *ret = NULL;
	FILE *fp;
	int retry = 0;
	int MapSvrState = S46_MAPSVR_INIT;
	size_t bufsz;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	if ((curl = curl_easy_init())) {
		if (asprintf(&buf, "%s%s", (id && *id) ? "&id=" : "", (id && *id) ? id : "") < 0 ||
		    !get_s46_url(url, sizeof(url), GET_V6PLUS_URL, buf))
			goto cleanup;

		if (f_exists(S46_DEBUG))
			S46_DBG("[GET_JPNE_URL] %s\n", url);

		curl_easy_setopt(curl, CURLOPT_URL, url);
		free(buf);

		if ((fp = open_memstream(&buf, &bufsz)) == NULL)
			goto cleanup;

		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, rsp_code);
		S46_DBG("[HTTP_RESPONSE_CODE]:%d\n", *rsp_code);
		fclose(fp);

		if (*rsp_code >= 400 && *rsp_code <= 499) {
			MapSvrState = S46_MAPSVR_ERR;
		} else if (*rsp_code >= 500) {  /* rsp_code >= 500 or other error*/
			MapSvrState = S46_MAPSVR_NO_RESPONSE;
		}

		json = NULL;
		if (res == CURLE_OK) {
			for (p = buf; (p = s = strstr(p, "v6plus"));) {
				p += sizeof("v6plus") - 1;
				if (s == buf || isspace(s[-1])) {
					while (*p && isspace(*p)) p++;
					if (*p == '(') {
						*strchrnul(++p, ')') = '\0';
						json = json_tokener_parse(p);
						break;
					}
				}
			}
			nvram_pf_set_int(WAN_PREFIX, "s46_retry", 0);
		} else {
			S46_DBG("[Err] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			if ((res == CURLE_COULDNT_RESOLVE_HOST) && (retry = nvram_pf_get_int(WAN_PREFIX, "s46_retry")) < S46_RETRY_TIME) {
				S46_DBG("[Err] Try to restart WAN(%d).....%d\n", WAN_UNIT, retry+1);
				nvram_pf_set_int(WAN_PREFIX, "s46_retry", retry+1);
				_restart_wan_if();
			} else {
				MapSvrState = S46_MAPSVR_NO_RESPONSE;
			}
		}
		free(buf);
		S46_DBG("[ret] %s\n", json_object_to_json_string(json));

		if (json) {
			const char *dmr = NULL;
			int i, len;
			int __attribute__ ((unused)) pdlen = 0;

			if ((fp = open_memstream(&ret, &bufsz)) == NULL)
				goto json_put;

			if (json_object_object_get_ex(json, "id", &obj) && idbuf)
				strlcpy(idbuf, json_object_get_string(obj), idlen);
			else
				MapSvrState = S46_MAPSVR_DATA_INVALID;
			if (json_object_object_get_ex(json, "dmr", &obj))
				dmr = json_object_get_string(obj);
			else
				MapSvrState = S46_MAPSVR_DATA_INVALID;
			if (json_object_object_get_ex(json, "ipv6_fixlen", &obj))
				pdlen = json_object_get_int(obj);
			else
				MapSvrState = S46_MAPSVR_DATA_INVALID;
			if (json_object_object_get_ex(json, "fmr", &list_obj)) {
				for (i = 0; i < json_object_array_length(list_obj); i++) {
					entry_obj = json_object_array_get_idx(list_obj, i);
					if (entry_obj) {
						fprintf(fp, "fmr,type=map-e");
						if (json_object_object_get_ex(entry_obj, "ipv6", &obj) &&
						    sscanf(json_object_get_string(obj), "%45[^/]/%d", addrbuf, &len) == 2)
							fprintf(fp, ",ipv6prefix=%s,prefix6len=%d", addrbuf, len);
						if (json_object_object_get_ex(entry_obj, "ipv4", &obj) &&
						    sscanf(json_object_get_string(obj), "%15[^/]/%d", addrbuf, &len) == 2)
							fprintf(fp, ",ipv4prefix=%s,prefix4len=%d", addrbuf, len);
						if (json_object_object_get_ex(entry_obj, "psid_offset", &obj))
							fprintf(fp, ",offset=%d", json_object_get_int(obj));
						if (json_object_object_get_ex(entry_obj, "ea_length", &obj))
							fprintf(fp, ",ealen=%d", json_object_get_int(obj));
						if (dmr)
							fprintf(fp, ",br=%s", dmr);
						fprintf(fp, " ");
					}
				}
			} else
				MapSvrState = S46_MAPSVR_DATA_INVALID;
			fclose(fp);
		json_put:
			json_object_put(json);
		} else { /* json parser err */
			if (MapSvrState == S46_MAPSVR_INIT) {
				MapSvrState = S46_MAPSVR_DATA_INVALID;
			}
		}
	cleanup:
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();

	if (MapSvrState == S46_MAPSVR_INIT) {
		nvram_pf_set_int(WAN_PREFIX, "s46_mapsvr_state", S46_MAPSVR_OK);
	} else {
		nvram_pf_set_int(WAN_PREFIX, "s46_mapsvr_state", MapSvrState);
		idbuf = NULL;
	}

	S46_DBG("s46_mapsvr_state=[%d]\n", nvram_pf_get_int(WAN_PREFIX, "s46_mapsvr_state"));
	S46_DBG("%s\n", ret);
	return ret;
}

int s46_mapcalc_check(char *id, char *rules, int draft)
{
	char peerbuf[INET6_ADDRSTRLEN];
	char addr6buf[INET6_ADDRSTRLEN];
	char addr4buf[INET_ADDRSTRLEN + sizeof("/32")];
	char ports[2048] = {0};
	char *fmrs;
	int offset, psidlen, psid;
	int s46_changed;
	int state = 0;

	state = nvram_pf_get_int(WAN_PREFIX, "s46_mapsvr_state");
	if (state > S46_MAPSVR_OK) {
		S46_DBG("[ERR]\n");
		if (state != S46_MAPSVR_NO_RESPONSE)
			s46_jpne_report(id, 2, 0); //stop, Normal operation
		return state;
	}

	if (s46_mapcalc(WAN_UNIT, WAN_PROTO, rules, peerbuf, sizeof(peerbuf), addr6buf, sizeof(addr6buf),
			addr4buf, sizeof(addr4buf), &offset, &psidlen, &psid, &fmrs, draft) <= 0) {
		peerbuf[0] = addr6buf[0] = addr4buf[0] = '\0';
		offset = 0, psidlen = 0, psid = 0;
		fmrs = NULL;
	}
	//Check have matched rule
	if (!strcmp(peerbuf, "") || !strcmp(addr6buf, "") || !strcmp(addr4buf, "")) {
		s46_jpne_report(id, 2, 3); //stop, Map rule mismatch
		S46_DBG("[MAP RULE MISMATCH]\n");
		state = S46_MAPSVR_DATA_INVALID;
		goto end;
	} else {
		if ((nvram_invmatch(ipv6_nvname_by_unit("ipv6_s46_peer", WAN_UNIT), peerbuf)    ||
		    nvram_invmatch(ipv6_nvname_by_unit("ipv6_s46_addr6", WAN_UNIT), addr6buf)   ||
		    nvram_invmatch(ipv6_nvname_by_unit("ipv6_s46_addr4", WAN_UNIT), addr4buf)   ||
		    nvram_get_int(ipv6_nvname_by_unit("ipv6_s46_offset", WAN_UNIT)) != offset   ||
		    nvram_get_int(ipv6_nvname_by_unit("ipv6_s46_psidlen", WAN_UNIT)) != psidlen ||
		    nvram_get_int(ipv6_nvname_by_unit("ipv6_s46_psid", WAN_UNIT)) != psid) &&
		    (strcmp(nvram_safe_get(ipv6_nvname_by_unit("ipv6_s46_peer", WAN_UNIT)), "") &&
		    strcmp(nvram_safe_get(ipv6_nvname_by_unit("ipv6_s46_addr6", WAN_UNIT)), "") &&
		    strcmp(nvram_safe_get(ipv6_nvname_by_unit("ipv6_s46_addr4", WAN_UNIT)), "")))
		{
			s46_jpne_report(id, 2, 2); //stop, Address change
			S46_DBG("[MAP RULE CHANGE]\n");
			logmessage("[MAP-E]", "Detected map rule changed.");
		} else {
			S46_DBG("[Normal OK]\n");
			s46_jpne_report(id, 1, 0); //start, Normal operation
		}
	}

	// Delete the last blank character
	fmrs[strlen(fmrs)-1] = '\0';
	s46_changed = _nvram_set_check(ipv6_nvname_by_unit("ipv6_s46_peer", WAN_UNIT), peerbuf);
	s46_changed += _nvram_set_check(ipv6_nvname_by_unit("ipv6_s46_addr6", WAN_UNIT), addr6buf);
	s46_changed += _nvram_set_check(ipv6_nvname_by_unit("ipv6_s46_addr4", WAN_UNIT), addr4buf);
	s46_changed += _nvram_set_check(ipv6_nvname_by_unit("ipv6_s46_fmrs", WAN_UNIT), fmrs ? : "");
	if (s46_changed || FORCE_TRIGGER) {
		nvram_set_int(ipv6_nvname_by_unit("ipv6_s46_offset", WAN_UNIT), offset);
		nvram_set_int(ipv6_nvname_by_unit("ipv6_s46_psidlen", WAN_UNIT), psidlen);
		nvram_set_int(ipv6_nvname_by_unit("ipv6_s46_psid", WAN_UNIT), psid);

		//v6plus port range
		nvram_set(ipv6_nvname_by_unit("ipv6_s46_ports", WAN_UNIT), calc_s46_port_range(1, psid, psidlen, offset, ports, sizeof(ports)));

		S46_DBG("[Create s46 tunnel interface]\n");
		stop_s46_tunnel(WAN_UNIT, 0);
		start_s46_tunnel(WAN_UNIT);
	}
	state = S46_MAPSVR_OK;
end:
	free(fmrs);
	nvram_pf_set_int(WAN_PREFIX, "s46_mapsvr_state", state);
	return state;
}

void do_v6plus_check(void)
{
	int interval_t = DEF_INTERVAL;
	int state = 0;
	long rsp_code = -1;
	char *rules, *rulebuf;
	char ports[2048] = {0};
	char maprule_id[64] = {0};
	char wan_ifname[16];
	char tmp[100];

	if (HGW_STATE_CHK) {
		if (nvram_pf_get_int(WAN_PREFIX, "s46_hgw_case") == S46_CASE_INIT) {
			setalarm_t(5, 0);
			if (HGW_DHCP_WAIT == 1) {
				logmessage("[MAP-E]", "Checking scenario...");
			}
			if (HGW_DHCP_WAIT == 6) {
				setalarm_t(DEF_INTERVAL, 0);
				HGW_DHCP_WAIT = 0;
				HGW_STATE_CHK = 0;
				nvram_pf_set_int(WAN_PREFIX, "s46_hgw_case", S46_CASE_MAP_CE_ON);
				snprintf(wan_ifname, sizeof(wan_ifname), "%s", nvram_safe_get(strcat_r(WAN_PREFIX, "ifname", tmp)));
				S46_DBG("### HGW OFF ### (v6plus starts.)\n");
				logmessage("[MAP-E]", "v6plus starts.");
				wan6_up(wan_ifname);
				return;
			}
			HGW_DHCP_WAIT +=1;
			return;
		} else if (nvram_pf_get_int(WAN_PREFIX, "s46_hgw_case") == S46_CASE_MAP_HGW_OFF) {
			setalarm_t(15, 0);
			HGW_STATE_CHK = 0;
			snprintf(wan_ifname, sizeof(wan_ifname), "%s", nvram_safe_get(strcat_r(WAN_PREFIX, "ifname", tmp)));
			S46_DBG("### HGW OFF ### (HGW v6plus is not activated)\n");
			logmessage("[MAP-E]", "v6plus starts.(HGW v6plus is not activated)");

			/* FIXME: wait v6addr assign to wan interface */
			wan6_up(wan_ifname);
			sleep(2);
			get_s46_ra(WAN_UNIT);
			return;
		} else if (nvram_pf_get_int(WAN_PREFIX, "s46_hgw_case") == S46_CASE_MAP_HGW_ON) {
			S46_DBG("### HGW ON ### (v6plus is active on HGW)\n");
			logmessage("[MAP-E]", "v6plus is active on HGW");
			s46_jpne_report(NULL, 2, 4); //stop, HGW
			stop_v6plusd(WAN_UNIT);
			return;
		}
	}

	if (FORCE_TRIGGER) {
		CURRENT_STATE = S46_MAPSVR_INIT;
		S46_DBG("### Current State Force Change: [%d] ###\n", CURRENT_STATE);
		nvram_pf_set_int(WAN_PREFIX, "s46_mapsvr_state", S46_MAPSVR_INIT);
		if (strcmp(nvram_safe_get(ipv6_nvname_by_unit("ipv6_s46_fmrs", WAN_UNIT)), "")) {
			interval_t = GetExeTime(S46_MAPSVR_INIT);
			nvram_set(ipv6_nvname_by_unit("ipv6_s46_ports", WAN_UNIT),
				  calc_s46_port_range(1, nvram_get_int(ipv6_nvname_by_unit("ipv6_s46_psid", WAN_UNIT)),
							 nvram_get_int(ipv6_nvname_by_unit("ipv6_s46_psidlen", WAN_UNIT)),
							 nvram_get_int(ipv6_nvname_by_unit("ipv6_s46_offset", WAN_UNIT)),
							 ports, sizeof(ports)));

			S46_DBG("[MAP rule has exist, create s46 tunnel interface. Reconfirm after %d min.]\n", interval_t/60);
			logmessage("[MAP-E]", "The map rule has exist. Reconfirm after %d min.", interval_t/60);

			fmrs2file(WAN_UNIT);
			stop_s46_tunnel(WAN_UNIT, 0);
			start_s46_tunnel(WAN_UNIT);
			goto setime;
		}
	} else {
		S46_DBG("### Current State: [%d] ###\n", CURRENT_STATE);
	}

	if (_nvram_check(ipv6_nvname_by_unit("ipv6_ra_addr", WAN_UNIT), ""))
		get_s46_ra(WAN_UNIT);

	rules = rulebuf = s46_jpne_maprules(nvram_pf_safe_get(WAN_PREFIX, "s46_mapsvr_id"), maprule_id, sizeof(maprule_id), &rsp_code);
	if (nvram_pf_match(WAN_PREFIX, "s46_mapsvr_id", "")) {
		nvram_pf_set(WAN_PREFIX, "s46_mapsvr_id", maprule_id);
		S46_DBG("[mapsvrId]:[%s]\n", maprule_id);
	}
	state = s46_mapcalc_check(maprule_id, rules, 1);

	if (state == S46_MAPSVR_INIT) {
		if (CURRENT_STATE != S46_MAPSVR_INIT) {
			S46_DBG("Current State: [%d] -> [%d](S46_MAPSVR_INIT)\n", CURRENT_STATE, S46_MAPSVR_INIT);
			CURRENT_STATE = S46_MAPSVR_INIT;
		}
	} else if (state == S46_MAPSVR_OK) {
		interval_t = GetExeTime(S46_MAPSVR_OK);
		logmessage("[MAP-E]", "Receiving a rule is successfully(%d). Reconfirm after %d min.", rsp_code, interval_t/60);
		if (CURRENT_STATE != S46_MAPSVR_OK) {
			S46_DBG("Current State: [%d] -> [%d](S46_MAPSVR_OK)\n", CURRENT_STATE, S46_MAPSVR_OK);
			if (CURRENT_STATE > 1) { //[Error] -> [OK]
				if (!strcmp(nvram_safe_get(ipv6_nvname_by_unit("ipv6_s46_fmrs", WAN_UNIT)), "")) {
					//FIXME Need to check current connection is online/offline.
					_restart_wan_if();
				} else if (CURRENT_STATE != S46_MAPSVR_NO_RESPONSE) {
					start_s46_tunnel(WAN_UNIT);
				}
			}
			CURRENT_STATE = S46_MAPSVR_OK;
		}
		if (ce_dad_check(WAN_UNIT))
			logmessage("[MAP-E]", "Detect duplicate CE address.");
	} else if (state == S46_MAPSVR_DATA_INVALID) {
		interval_t = GetExeTime(S46_MAPSVR_DATA_INVALID);
		logmessage("[MAP-E]", "Receiveing invalid rule. Reconfirm after %d min.", interval_t/60);
		if (CURRENT_STATE != S46_MAPSVR_DATA_INVALID) {
			S46_DBG("Current State: [%d] -> [%d](S46_MAPSVR_DATA_INVALID)\n", CURRENT_STATE, S46_MAPSVR_DATA_INVALID);
			stop_s46_tunnel(WAN_UNIT, 0);
			nvram_set(ipv6_nvname_by_unit("ipv6_s46_fmrs", WAN_UNIT), "");
			nvram_commit();
			CURRENT_STATE = S46_MAPSVR_DATA_INVALID;
		}
	} else if (state == S46_MAPSVR_ERR) {
		interval_t = GetExeTime(S46_MAPSVR_ERR);
		logmessage("[MAP-E]", "MAP server error(%d). Reconfirm after %d min.", rsp_code, interval_t/60);
		if (CURRENT_STATE != S46_MAPSVR_ERR) {
			S46_DBG("Current State: [%d] -> [%d](S46_MAPSVR_ERR)\n", CURRENT_STATE, S46_MAPSVR_ERR);
			stop_s46_tunnel(WAN_UNIT, 0);
			nvram_set(ipv6_nvname_by_unit("ipv6_s46_fmrs", WAN_UNIT), "");
			nvram_commit();
			CURRENT_STATE = S46_MAPSVR_ERR;
		}
	} else if (state == S46_MAPSVR_NO_RESPONSE) {
		interval_t = GetExeTime(S46_MAPSVR_NO_RESPONSE);
		logmessage("[MAP-E]", "MAP server did not reply(%d). Reconfirm after %d min.", rsp_code, interval_t/60);
		if (CURRENT_STATE != S46_MAPSVR_NO_RESPONSE) {
			S46_DBG("Current State: [%d] -> [%d](S46_MAPSVR_NO_RESPONSE)\n", CURRENT_STATE, S46_MAPSVR_NO_RESPONSE);
			CURRENT_STATE = S46_MAPSVR_NO_RESPONSE;
		}
	}

	if (rulebuf)
		free(rulebuf);
setime:
	FORCE_TRIGGER = 0;
	setalarm_t(interval_t, 0);
}

int v6plusd_main(int argc, char *argv[])
{
	FILE *fp;
	char pid_path[128];
	int opt;

	WAN_UNIT = wan_primary_ifunit();

	while ((opt = getopt(argc, argv, "u:")) != -1) {
		switch (opt)
		{
		case 'u':
			WAN_UNIT = strtoul(optarg, NULL, 0);
			break;
		default:
			fprintf(stderr, "Usage: [options] -u <wan unit>\n");
			exit(EXIT_FAILURE);
		}
	}

	strncpy(WAN_IFNAME, get_wan6_ifname(WAN_UNIT), sizeof(WAN_IFNAME));
	snprintf(WAN_PREFIX, sizeof(WAN_PREFIX), "wan%d_", WAN_UNIT);
	snprintf(pid_path, sizeof(pid_path), V6PLUSD_PIDFILE, WAN_UNIT);
	WAN_PROTO = get_wan_proto(WAN_PREFIX);

	nvram_pf_set(WAN_PREFIX, "s46_mapsvr_id", "");

	/* write pid */
	if ((fp = fopen(pid_path, "w")) != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	signal_register();

	memset(&tick, 0, sizeof(tick));

	do_v6plus_check();

	/* When get a SIGALRM, the main process will enter another loop for pause() */
	while(1) {
		pause();
	}

	return 0;
}

