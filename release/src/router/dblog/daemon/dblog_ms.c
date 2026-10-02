
#include "dblog.h"

enum {
	MS_TYPE_ERR = 0
	,MS_TYPE_IPKG = 1
	,MS_TYPE_BUILT_IN = 2
};

int gIpkg = MS_TYPE_ERR;

void init_mslog(void)
{
	if(check_if_file_exist("/opt/bin/minidlna"))
	{
		gIpkg = MS_TYPE_IPKG;
	}
	else if(check_if_file_exist("/usr/sbin/minidlna"))
	{
		gIpkg = MS_TYPE_BUILT_IN;
	}
	else
	{
		cprintf("[%s]media server is not installed.\n", __FUNCTION__);
		gIpkg = MS_TYPE_ERR;
	}
}

void monitor_mslog(void)
{
	char orig_file[64] = {0};
	char target_file[64] = {0};
	char cmdbuf[256] = {0};

	init_mslog();

	if(gIpkg == MS_TYPE_ERR)
	{
		cprintf("[%s]media server is not installed.\n", __FUNCTION__);
		return;
	}

	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(cmdbuf, 0, sizeof(cmdbuf));

	if(gIpkg == MS_TYPE_IPKG)
	{
		snprintf(orig_file, sizeof(orig_file), "/opt/var/minidlna/minidlna.log");
		snprintf(target_file, sizeof(target_file), "%s/minidlna_ipkg.log", nvram_safe_get("dblog_log_path"));
	}
	else if(gIpkg == MS_TYPE_BUILT_IN)
	{
		snprintf(orig_file, sizeof(orig_file), "%s/minidlna.log", nvram_safe_get("dms_dbdir"));
		snprintf(target_file, sizeof(target_file), "%s/minidlna_built_in.log", nvram_safe_get("dblog_log_path"));
	}

	snprintf(cmdbuf, sizeof(cmdbuf), "tail -n 500 -s 10 -F %s > %s 2>/dev/null &", orig_file, target_file);
	system(cmdbuf);
}

void enable_mslog(void)
{
cprintf("[%s]\n", __FUNCTION__);

	init_mslog();

	if(gIpkg == MS_TYPE_ERR)
	{
		cprintf("[%s]media server is not installed.\n", __FUNCTION__);
		return;
	}

	if(gIpkg == MS_TYPE_IPKG)
	{
		killall("minidlna", SIGKILL);
		system("/opt/bin/minidlna -f /opt/etc/minidlna.conf -r -D -v");
	}
	else if(gIpkg == MS_TYPE_BUILT_IN)
	{
		nvram_set("dms_dbg", "1");
		system("rc rc_service restart_dms");
	}

	monitor_mslog();
}

void disable_mslog(void)
{
cprintf("[%s]\n", __FUNCTION__);

	if(gIpkg == MS_TYPE_IPKG)
	{
		killall("minidlna", SIGKILL);
		system("/opt/bin/minidlna -f /opt/etc/minidlna.conf -r -D");
	}
	if(gIpkg == MS_TYPE_BUILT_IN)
	{
		nvram_set("dms_dbg", "0");
		notify_rc("restart_dms");
	}
}

void backup_mslog(void)
{
	//cprintf("[%s]\n", __FUNCTION__);
}

