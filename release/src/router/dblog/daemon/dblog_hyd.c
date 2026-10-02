
#include "dblog.h"

void enable_hydlog(void)
{
	nvram_set("hive_dbg", "1");
	killall("hyd", SIGKILL);
}

void disable_hydlog(void)
{
	nvram_set("hive_dbg", "0");
        killall("hyd", SIGKILL);
}
