
#include "dblog.h"


void backup_syslog(void);



void backup_syslog(void)
{
	char cmdbuf[256] = {0};
	char orig_file[64] = {0};
	char target_file[64] = {0};
	char tmp_file[80] = {0};

cprintf("backup_syslog\n");
	memset(orig_file, 0, sizeof(orig_file));
	memset(target_file, 0, sizeof(target_file));
	memset(tmp_file, 0, sizeof(tmp_file));
	snprintf(orig_file, sizeof(orig_file), "/tmp/syslog.log");
	snprintf(target_file, sizeof(target_file), "/tmp/asus_dblog/syslog.log");
	snprintf(tmp_file, sizeof(tmp_file), "/tmp/syslog.log_tmp");

	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(cmdbuf, sizeof(cmdbuf), "sed -n '1,100p' %s >> %s", orig_file, target_file);
	system(cmdbuf);
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(cmdbuf, sizeof(cmdbuf), "sed '1,100d' %s > %s", orig_file, tmp_file);
	system(cmdbuf);
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(cmdbuf, sizeof(cmdbuf), "mv -f %s %s", tmp_file, orig_file);
	system(cmdbuf);
}
