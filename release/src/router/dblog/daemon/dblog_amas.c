
#include "dblog.h"

#define DEFAULT_DBG_PATH "/tmp/asusdebuglog"

void monitor_amaslog(void)
{
	char orig_file[64] = {0};
	char target_file[64] = {0};
	char cmdbuf[256] = {0};

/****************************************
nvram set cfg_syslog=1
/tmp/asusdebuglog/cfg_mnt.log

nvram set bhctl_syslog=1
/tmp/asusdebuglog/amas_bhctrl.log

nvram set lanctl_syslog=1
/tmp/asusdebuglog/amas_lanctl.log

nvram set wlcconnect_syslog=1
/tmp/asusdebuglog/amas_wlcconnect.log

touch /tmp/RAST_DEBUG
/tmp/asusdebuglog/roamast.log

log prefix, nvram is "asuslog_path", which is composed of nvram_safe_get("dblog_usb_path") and "asusdebuglog"
e.g., dblog_usb_path = /tmp/mnt/sda1, so asuslog_path = /tmp/mnt/sda1/asusdebuglog

log full path:
-if nvram_safe_get("asuslog_path") is not NULL, then
nvram_safe_get("asuslog_path")/xxx.log

-if nvram_safe_get("asuslog_path") is NULL, then
/tmp/asusdebuglog/xxx.log

****************************************/
	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/cfg_mnt.log", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/cfg_mnt.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/amas_bhctrl.log", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/amas_bhctrl.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/amas_lanctl.log", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/amas_lanctl.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/amas_wlcconnect.log", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/amas_wlcconnect.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/roamast.log", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/roamast.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/amas_ssd.log", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/amas_ssd.log", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(orig_file, sizeof(orig_file), "%s/amas_ssd.log-1", (strlen(nvram_safe_get("asuslog_path")) > 0) ? nvram_safe_get("asuslog_path") : DEFAULT_DBG_PATH );
	snprintf(target_file, sizeof(target_file), "%s/amas_ssd.log-1", nvram_safe_get("dblog_log_path"));
	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);

}

void enable_amaslog(void)
{
	char full_path[256] = {0};

cprintf("[%s]\n", __FUNCTION__);

	if(nvram_get_int("dblog_tousb") == 1)
	{
		snprintf(full_path, sizeof(full_path), "%s/%s", nvram_safe_get("dblog_usb_path"), "asusdebuglog" );
		nvram_set("asuslog_path", full_path);
	}

	nvram_set_int("cfg_syslog", 1);
	nvram_set_int("bhctl_syslog", 1);
	nvram_set_int("lanctl_syslog", 1);
	nvram_set_int("wlcconnect_syslog", 1);
	nvram_set_int("ssd_syslog", 1);
	system("touch /tmp/RAST_DEBUG");

	monitor_amaslog();
}

void disable_amaslog(void)
{
	nvram_set_int("cfg_syslog", 0);
	nvram_set_int("bhctl_syslog", 0);
	nvram_set_int("lanctl_syslog", 0);
	nvram_set_int("wlcconnect_syslog", 0);
	nvram_set_int("ssd_syslog", 0);
	system("rm -f /tmp/RAST_DEBUG");
	nvram_set("asuslog_path", "");
}

void backup_amaslog(void)
{
	//cprintf("[%s]\n", __FUNCTION__);
}

