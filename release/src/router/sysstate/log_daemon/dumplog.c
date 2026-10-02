#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "dumplog.h"

extern void cpuusage_dump(void);
extern void cpuusage_dump_detail(void);
extern void ramusage_dump(void);
extern void cputemp_dump(void);

int DumpLogRecord(void)
{
	cpuusage_dump();
	ramusage_dump();
	cputemp_dump();

	return 0;
}

int DumpLogRecord_detail(void)
{
	cpuusage_dump_detail();

	return 0;
}

