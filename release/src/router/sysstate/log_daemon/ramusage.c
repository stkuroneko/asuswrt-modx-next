#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <shared.h>
#include <time.h>	//time(), ctime()

#include "sysstate.h"

#define RAM_MAX_ENTRY 6000

#define DUMP_PATH_RAMUSAGE "/tmp/asusfbsvcs/ramusage_log.txt"

struct ram_usage_stat {
	unsigned long memTotal;
	unsigned long memFree;
	unsigned long memBuffers;
	unsigned long memCached;
	unsigned long memSwapCached;
	unsigned long memSwapTotal;
	unsigned long memSwapFree;
};

struct ram_usage_record_s {
	time_t timestamp;
	struct ram_usage_stat* ramRecord;
	struct ram_usage_record_s* next;
};

struct ram_usage_stat ram_stat;

struct ram_usage_record_s *ramHead = NULL;
struct ram_usage_record_s *ramCurrent = NULL;
struct ram_usage_record_s *ramPrev = NULL;

void get_ram_usage(struct ram_usage_stat *result);
void copy_ram_usage(struct ram_usage_stat* dst, struct ram_usage_stat *src);

void get_ram_usage(struct ram_usage_stat *result)
{
	FILE *fp = NULL;
	char buf[8] = {0};

	fp = fopen("/proc/meminfo", "r");

	if(fp && result)
	{
		//MemTotal:         255600 kB
		fscanf(fp, "MemTotal: %lu %s\n", &(result->memTotal), buf);
		fscanf(fp, "MemFree: %lu %s\n", &(result->memFree), buf);
		fscanf(fp, "Buffers: %lu %s\n", &(result->memBuffers), buf);
		fscanf(fp, "Cached: %lu %s\n", &(result->memCached), buf);
		fscanf(fp, "SwapCached: %lu %s\n", &(result->memSwapCached), buf);
		fscanf(fp, "SwapTotal: %lu %s\n", &(result->memSwapTotal), buf);
		fscanf(fp, "SwapFree: %lu %s\n", &(result->memSwapFree), buf);
		fclose(fp);
	}
	else
	{
		result->memTotal = 0;
		result->memFree = 0;
		result->memBuffers = 0;
		result->memCached = 0;
		result->memSwapCached = 0;
		result->memSwapTotal = 0;
		result->memSwapFree = 0;
	}
}

void copy_ram_usage(struct ram_usage_stat* dst, struct ram_usage_stat *src)
{
	if(!dst || !src)
	{
		cprintf("copy_diff_value(): Null Pointer\n");
		exit(1);
	}

	dst->memTotal = src->memTotal;
	dst->memFree = src->memFree;
	dst->memBuffers = src->memBuffers;
	dst->memCached = src->memCached;
	dst->memSwapCached = src->memSwapCached;
	dst->memSwapTotal = src->memSwapTotal;
	dst->memSwapFree = src->memSwapFree;
}

/*************************
# cat meminfo
MemTotal:         255600 kB
MemFree:          196132 kB
Buffers:             468 kB
Cached:             9920 kB
SwapCached:            0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
*************************/

void ramusage_main(int interval)
{
	time_t secs = 0;
	static int counter = 0;
	static unsigned long localcounter = 0;
	struct ram_usage_record_s *del_node = NULL;

	if(counter++ % interval == 0)
	{
		counter = 1; //reset counter
		time(&secs);

		get_ram_usage(&ram_stat);

		ramCurrent = (struct ram_usage_record_s *) malloc(sizeof(struct ram_usage_record_s));
		if(ramCurrent == NULL)
		{
			cprintf("[ramusage_main](1)Cannot allocate memory!!\n");
			return;
		}
		ramCurrent->next = NULL;

		ramCurrent->ramRecord = (struct ram_usage_stat *) malloc(sizeof(struct ram_usage_stat));
		if(ramCurrent->ramRecord == NULL)
		{
			free(ramCurrent);
			ramCurrent = NULL;
			cprintf("[ramusage_main](2)Cannot allocate memory!!\n");
			return;
		}

		copy_ram_usage(ramCurrent->ramRecord, &ram_stat);

		ramCurrent->timestamp = secs;

		if(ramHead == NULL)
		{
			ramHead = ramCurrent;
			localcounter = 1;
		}
		else
		{
			ramPrev->next = ramCurrent;
			localcounter++;
		}

		ramPrev = ramCurrent;

		if( localcounter > RAM_MAX_ENTRY )
		{
			del_node = ramHead;
			ramHead = ramHead->next;
			localcounter--;

			free(del_node->ramRecord);
			free(del_node);
		}

	}
}

void ramusage_dump(void)
{
	FILE *fp = NULL;
	char timestr[32] = {0};
	struct ram_usage_record_s *ramDump = NULL;
	unsigned long tmpTotal = 0;
	unsigned long tmpUsed = 0;

	fp = fopen(DUMP_PATH_RAMUSAGE, "w");
	if(!fp)
	{
		cprintf("cpuusage_dump(): cannot create log file.\n");
		return;
	}

	if(ramHead)
	{
		fprintf(fp, "[timestamp] %25s %8s %10s %10s %10s %7s %12s %9s %8s\n", "MemTotal", "MemFree", "MemUsed", "MemUsage", "Buffers", "Cached", "SwapCached", "SwapTotal", "SwapFree");
		ramDump = ramHead;
		while(ramDump)
		{
			sprintf(timestr, "%s", ctime(&(ramDump->timestamp)));
			timestr[strlen(timestr)-1] = '\0';

			tmpTotal = ramDump->ramRecord->memTotal;
			tmpUsed = tmpTotal - ramDump->ramRecord->memFree;
			fprintf(fp, "[%s] %9lu %9lu %9lu %9.2f%% %9lu %9lu %9lu %9lu %9lu\n", timestr,
				tmpTotal, ramDump->ramRecord->memFree, tmpUsed, (100.0*tmpUsed)/tmpTotal,
				ramDump->ramRecord->memBuffers, ramDump->ramRecord->memCached,
				ramDump->ramRecord->memSwapCached, ramDump->ramRecord->memSwapTotal,
				ramDump->ramRecord->memSwapFree
			);
			ramDump = ramDump->next;
		}
	}

	fclose(fp);
}

void init_ramusage(void)
{
	memset(&ram_stat, 0, sizeof(struct ram_usage_stat));
}

