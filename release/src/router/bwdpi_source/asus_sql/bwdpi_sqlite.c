/*
	database body

	1. traffic analyzer
		command : analyzer
	2. web history
		command : web_history
*/

#include "bwdpi.h"
#include "bwdpi_sqlite.h"

typedef struct {
	const char *name;
	int (*main)(int argc, char *argv[]);
} applets_t;

static const applets_t applets[] = {
	{ "TrafficAnalyzer"     , traffic_analyzer_main     },
	{ "WebHistory"          , web_history_main          },
	{ "AiProtectionMonitor" , aiprotection_monitor_main },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	char *base;
	int f;

	if ((f = open("/dev/null", O_RDWR)) < 0) {
	}
	else if(f < 3) {
		dup(f);
		dup(f);
	}
	else {
		close(f);
	}

	base = strrchr(argv[0], '/');
	base = base ? base + 1 : argv[0];

	const applets_t *a;
	for (a = applets; a->name; ++a) {
		if (strcmp(base, a->name) == 0) {
			openlog(base, LOG_PID, LOG_USER);
			return a->main(argc, argv);
		}
	}

	return 0;
}
