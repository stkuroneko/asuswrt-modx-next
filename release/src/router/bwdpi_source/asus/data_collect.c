/*
	data_collect.c for data collection in statistics,
	dcd must enabled for DPI engine function.
*/

#include "bwdpi.h"

void stop_dc()
{
	eval("killall", "-9", DATACOLLD);
	if (f_exists("/var/conf_serv_sock"))
		eval("rm", "-f", "/var/conf_serv_sock");
}

void start_dc(char *path)
{
	char buf[512];

	if (!check_tdts_module_exist()) {
		BWDPI_DBG(" module doesn't exist, stop!\n");
		return;
	}

	if (!is_router_mode())
		return;

	if (!f_exists(DPI_CERT))
		eval("cp", "/usr/bwdpi/ntdasus2014.cert", DPI_CERT, "-f");

	if (path != NULL)
		snprintf(buf, sizeof(buf), "%s", path);
	else
		snprintf(buf, sizeof(buf), "LD_LIBRARY_PATH=%s %s -i 3600 -p 43200 -b -d %s &", LD_PATH, DATACOLLD, TMP_BWDPI);

	if (!pids(DATACOLLD)) {
		stop_dc();
		chdir(TMP_BWDPI);
		BWDPI_DBG("buf=%s\n", buf);
		system(buf);
		chdir("/");
	}
}

int data_collect_main(char *cmd, char *path)
{
	if (!strcmp(cmd, "restart")) {
		stop_dc();
		start_dc(path);
	}
	else if (!strcmp(cmd, "stop")) {
		stop_dc();
	}
	else if (!strcmp(cmd, "start")) {
		start_dc(path);
	}

	return 1;
}
