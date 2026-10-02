
#include "dblog.h"

void monitor_dmlog(void)
{
	//cprintf("[%s]nothing to do.\n", __FUNCTION__);
}

void enable_dmlog(void)
{
	//cprintf("[%s]nothing to do.\n", __FUNCTION__);
}

void disable_dmlog(void)
{
	//cprintf("[%s]nothing to do.\n", __FUNCTION__);
}


void backup_dmlog(void)
{
	char cmdbuf[512] = {0};

	snprintf(cmdbuf, sizeof(cmdbuf), "rm -f %s/dblog_dm.tgz", nvram_safe_get("dblog_log_path"));
	system(cmdbuf);

	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(cmdbuf, sizeof(cmdbuf), "tar -zch -f %s/dblog_dm.tgz %s %s %s %s %s 2>/dev/null"
		, nvram_safe_get("dblog_log_path")
		, "/tmp/asus_router.conf"
		, "/opt/etc/dm2_general.conf"
		, "/opt/etc/dm2_snarf.conf"
		, "/opt/etc/dm2_transmission.conf"
		, "/opt/lib/ipkg/info/*.control"
	);

	system(cmdbuf);
}

