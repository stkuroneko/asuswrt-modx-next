
#include "dblog.h"

#ifdef RTCONFIG_HND_ROUTER
int gWiFiLogEn = 0;
#endif /* RTCONFIG_HND_ROUTER */

void monitor_wifilog(void)
{
	char orig_file[64] = {0};
	char target_file[64] = {0};
	char cmdbuf[256] = {0};

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "/tmp/syslog.log");
	snprintf(target_file, sizeof(target_file), "%s/syslog.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);
#ifdef RTCONFIG_HND_ROUTER
	gWiFiLogEn = 1;
#endif /* RTCONFIG_HND_ROUTER */
}

void enable_wifilog(void)
{
#if defined(RTAC86U)||defined(RTAC88U)||defined(RTAC3100)||defined(RTAC3200)||defined(RTAC5300)||defined(GTAC5300)
	char word[256] = {0}, *next = NULL;
	char ifnames[128] = {0};
	char cmdbuf[256] = {0};
#endif

	monitor_wifilog();

#if defined(RTAC86U)||defined(RTAC88U)||defined(RTAC3100)||defined(RTAC3200)||defined(RTAC5300)||defined(GTAC5300)
	snprintf(ifnames, sizeof(ifnames), "%s", nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next)
	{
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "dhd -i %s msglevel +err", word);
		system(cmdbuf);
	}
#endif

#ifdef RTCONFIG_HND_ROUTER_AX_675X
	//Note: for "log_wlstat", it will be unset after one hour, no need to reset it in disable_wifilog().
	nvram_set("log_wlstat", "1");
#endif /* RTCONFIG_HND_ROUTER_AX_675X */
}

void disable_wifilog(void)
{
#if defined(RTAC86U)||defined(RTAC88U)||defined(RTAC3100)||defined(RTAC3200)||defined(RTAC5300)||defined(GTAC5300)
	char word[256] = {0}, *next = NULL;
	char ifnames[128] = {0};
	char cmdbuf[256] = {0};
#endif

#if defined(RTAC86U)||defined(RTAC88U)||defined(RTAC3100)||defined(RTAC3200)||defined(RTAC5300)||defined(GTAC5300)
	snprintf(ifnames, sizeof(ifnames), "%s", nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next)
	{
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "dhd -i %s msglevel -err", word);
		system(cmdbuf);
	}
#endif
}

void backup_wifilog(void)
{
	char word[256] = {0}, *next = NULL;
	char ifnames[128] = {0};
	char cmdbuf[256] = {0};
	static int isCaptured = 0;
	int idx = 0;

	if(isCaptured == 0)
	{
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "wl revinfo >> %s/wl_revinfo.txt", nvram_safe_get("dblog_log_path"));
		system(cmdbuf);

		snprintf(ifnames, sizeof(ifnames), "%s", nvram_safe_get("wl_ifnames"));
		foreach (word, ifnames, next)
		{
#if defined(RTAC86U)||defined(RTAC88U)||defined(RTAC3100)||defined(RTAC3200)||defined(RTAC5300)||defined(GTAC5300)
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(cmdbuf, sizeof(cmdbuf), "dhd -i %s cons mu", word);
			system(cmdbuf);
#endif
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(cmdbuf, sizeof(cmdbuf), "wl -i %s status >> %s/wl_ethx_status.txt", word, nvram_safe_get("dblog_log_path"));
			system(cmdbuf);

			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(cmdbuf, sizeof(cmdbuf), "echo %s assoclist: >> %s/wl_ethx_assoclist.txt", word, nvram_safe_get("dblog_log_path"));
			system(cmdbuf);
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(cmdbuf, sizeof(cmdbuf), "wl -i %s assoclist >> %s/wl_ethx_assoclist.txt", word, nvram_safe_get("dblog_log_path"));
			system(cmdbuf);
		}

		for(idx = 0; idx < 10; ++idx)
		{
			snprintf(ifnames, sizeof(ifnames), "%s", nvram_safe_get("wl_ifnames"));
			foreach (word, ifnames, next)
			{
				memset(cmdbuf, 0, sizeof(cmdbuf));
				snprintf(cmdbuf, sizeof(cmdbuf), "echo %s counters: >> %s/wl_%s_counters.txt", word, nvram_safe_get("dblog_log_path"), word);
				system(cmdbuf);
				memset(cmdbuf, 0, sizeof(cmdbuf));
				snprintf(cmdbuf, sizeof(cmdbuf), "wl -i %s counters >> %s/wl_%s_counters.txt", word, nvram_safe_get("dblog_log_path"), word);
				system(cmdbuf);
			}
			sleep(2);
		}
		isCaptured = 1;
	}
}

#ifdef RTCONFIG_HND_ROUTER
/**
*** Per Jiahao, after enabling DHD log, the DHD log will be displayed in syslog as Wi-Fi log.
**/
void monitor_dhdlog(void)
{
	if(gWiFiLogEn)
	{
		//don't do again
	}
	else
	{
		monitor_wifilog();
	}
}

void enable_dhdlog(void)
{
	char word[256] = {0}, *next = NULL;
	char ifnames[128] = {0};
	char cmdbuf[256] = {0};

	monitor_dhdlog();

	nvram_set("dhd_msg_level", "1");

	snprintf(ifnames, sizeof(ifnames), "%s", nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next)
	{
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "dhd -i %s msglevel 1", word);
		system(cmdbuf);
	}
}

void disable_dhdlog(void)
{
	char word[256] = {0}, *next = NULL;
	char ifnames[128] = {0};
	char cmdbuf[256] = {0};

	nvram_set("dhd_msg_level", "0");

	snprintf(ifnames, sizeof(ifnames), "%s", nvram_safe_get("wl_ifnames"));
	foreach (word, ifnames, next)
	{
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "dhd -i %s msglevel 0", word);
		system(cmdbuf);
	}
}

void backup_dhdlog(void)
{
	if(gWiFiLogEn)
	{
		//don't do again
	}
	else
	{
		backup_wifilog();
	}
}
#endif /* RTCONFIG_HND_ROUTER */
