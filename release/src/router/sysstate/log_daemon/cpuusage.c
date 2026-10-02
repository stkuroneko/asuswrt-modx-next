#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <shared.h>
#include <time.h>	//time(), ctime()

#define CU_MAX_ENTRY 6000

#define DUMP_PATH_CPUUSAGE "/tmp/asusfbsvcs/cpuusage_log.txt"
#define DUMP_PATH_DETAIL_CPUUSAGE "/tmp/asusfbsvcs/cpuusage_detail_log.txt"

typedef unsigned long long cputime64_t;

struct cpu_usage_stat {
	cputime64_t user;
	cputime64_t nice;
	cputime64_t system;
	cputime64_t softirq;
	cputime64_t irq;
	cputime64_t idle;
	cputime64_t iowait;
	cputime64_t steal;
};

struct cpu_usage_diff {
	cputime64_t user;
	cputime64_t nice;
	cputime64_t system;
	cputime64_t softirq;
	cputime64_t irq;
	cputime64_t idle;
	cputime64_t iowait;
	cputime64_t steal;
	double factor;
};

struct cpu_usage_record_s {
	time_t timestamp;
	struct cpu_usage_diff* cuRecord;
	struct cpu_usage_record_s* next;
};

int is_cpu_prefix(char *line);
unsigned int get_cpu_amount(void);
void get_cpu_jiffies(struct cpu_usage_stat *result);
void calc_diff(struct cpu_usage_stat *prev, struct cpu_usage_stat *curr, struct cpu_usage_diff *diff);
void store_prev_value(struct cpu_usage_stat *prev, struct cpu_usage_stat *curr);
void cpuusage_main(int interval);
void cpuusage_dump(void);
void cpuusage_dump_detail(void);
void init_cpuusage(void);

struct cpu_usage_stat *prev_stat = NULL;
struct cpu_usage_stat *curr_stat = NULL;
struct cpu_usage_diff *diff_stat = NULL;

struct cpu_usage_record_s *cuHead = NULL;
struct cpu_usage_record_s *cuCurrent = NULL;
struct cpu_usage_record_s *cuPrev = NULL;

unsigned int cpu_cnt = 1;

unsigned int get_cpu_amount(void)
{
	FILE *fp = NULL;
	char buffer[256] = {0};
	int cpu_num = 0;
	int max_cpu = 0;

	fp = fopen("/proc/stat", "r");
	if(!fp)
	{
		cprintf("Cannot read [/proc/stat]!!!\n");
		return 1;
	}

	while (fgets(buffer, sizeof(buffer), fp))
	{
		if(strncmp(buffer, "cpu", 3) != 0)
		{
			if(max_cpu > 0)
			{
				break;
			}
			else
			{
				continue;
			}
		}

		if(buffer[3] != ' ')
		{
			cpu_num = 0;
			if (sscanf(buffer + 3, "%u", &cpu_num) == 1)
			{
				if(cpu_num > max_cpu)
				{
					max_cpu = cpu_num;
				}
			}
		}
	}

	fclose(fp);
	return max_cpu + 1;
}

/*************************
typedef unsigned long long cputime64_t;
struct cpu_usage_stat {
	cputime64_t user;
	cputime64_t nice;
	cputime64_t system;
	cputime64_t softirq;
	cputime64_t irq;
	cputime64_t idle;
	cputime64_t iowait;
	cputime64_t steal;
};

//linux-2.6.36/fs/proc/stat.c
(unsigned long long)cputime64_to_clock_t(user),
(unsigned long long)cputime64_to_clock_t(nice),
(unsigned long long)cputime64_to_clock_t(system),
(unsigned long long)cputime64_to_clock_t(idle),
(unsigned long long)cputime64_to_clock_t(iowait),
(unsigned long long)cputime64_to_clock_t(irq),
(unsigned long long)cputime64_to_clock_t(softirq),
(unsigned long long)cputime64_to_clock_t(steal),
(unsigned long long)cputime64_to_clock_t(guest),
(unsigned long long)cputime64_to_clock_t(guest_nice));

//linux/fs/proc/proc_misc.c (for linux 2.6.22)
(unsigned long long)cputime64_to_clock_t(user),
(unsigned long long)cputime64_to_clock_t(nice),
(unsigned long long)cputime64_to_clock_t(system),
(unsigned long long)cputime64_to_clock_t(idle),
(unsigned long long)cputime64_to_clock_t(iowait),
(unsigned long long)cputime64_to_clock_t(irq),
(unsigned long long)cputime64_to_clock_t(softirq),
(unsigned long long)cputime64_to_clock_t(steal));
*************************/

void get_cpu_jiffies(struct cpu_usage_stat *result)
{
	FILE *fp = NULL;
	char buffer[256] = {0};
	int index = 0;

	fp = fopen("/proc/stat", "r");
	if(!fp)
	{
		cprintf("Cannot read [/proc/stat]!!!\n");
		return;
	}

	//To scan [cpu  111793 0 332092 18509670 2964 2096 81212 0 0 0]
	while(fgets(buffer, sizeof(buffer), fp))
	{
		if(strncmp(buffer, "cpu ", 4) == 0)
		{
			sscanf(buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
				&(result[0].user), &(result[0].nice), &(result[0].system), &(result[0].idle),
				&(result[0].iowait), &(result[0].irq), &(result[0].softirq), &(result[0].steal)
			);
			break;
		}
	}
#if 0
cprintf("result[0]=[%llu %llu %llu %llu %llu %llu %llu %llu]\n", result[0].user, result[0].nice, result[0].system, result[0].idle,
	result[0].iowait, result[0].irq, result[0].softirq, result[0].steal
);
#endif

	//to scan [cpu0  ...], [cpu1  ...], ...
	while(fgets(buffer, sizeof(buffer), fp))
	{
		if(strncmp(buffer, "cpu", 3) == 0)
		{
			sscanf(buffer, "cpu%d", &index);

			if(index < cpu_cnt)
			{
				sscanf(buffer, "cpu%*d %llu %llu %llu %llu %llu %llu %llu %llu",
					&(result[index+1].user), &(result[index+1].nice), &(result[index+1].system), &(result[index+1].idle),
					&(result[index+1].iowait), &(result[index+1].irq), &(result[index+1].softirq), &(result[index+1].steal)
				);
				#if 0
				cprintf("result[%d]=[%llu %llu %llu %llu %llu %llu %llu %llu]\n", index+1, result[index+1].user, result[index+1].nice, result[index+1].system, result[index+1].idle,
					result[index+1].iowait, result[index+1].irq, result[index+1].softirq, result[index+1].steal
				);
				#endif
			}
		}
	}

	fclose(fp);
}

void calc_diff(struct cpu_usage_stat *prev, struct cpu_usage_stat *curr, struct cpu_usage_diff *diff)
{
	int index = 0;
	unsigned long long sum = 0;

	for(index = 0; index < cpu_cnt + 1; index++)
	{
		diff[index].user = curr[index].user - prev[index].user;
		diff[index].nice = curr[index].nice - prev[index].nice;
		diff[index].system = curr[index].system - prev[index].system;
		diff[index].idle = curr[index].idle - prev[index].idle;
		diff[index].iowait = curr[index].iowait - prev[index].iowait;
		diff[index].irq = curr[index].irq - prev[index].irq;
		diff[index].softirq = curr[index].softirq - prev[index].softirq;
		diff[index].steal = curr[index].steal - prev[index].steal;

		sum = diff[index].user + diff[index].nice + diff[index].system + diff[index].idle +
			diff[index].iowait + diff[index].irq + diff[index].softirq + diff[index].steal;

		if(sum < 1)
		{
			sum = 1;
		}

		diff[index].factor = 100.0 / sum;
	}
}

void store_prev_value(struct cpu_usage_stat *prev, struct cpu_usage_stat *curr)
{
	int index = 0;

	if(!prev || !curr)
	{
		cprintf("store_prev_value(): Null Pointer\n");
		exit(1);
	}

	for(index = 0; index < cpu_cnt + 1; index++)
	{
		prev[index].user = curr[index].user;
		prev[index].nice = curr[index].nice;
		prev[index].system = curr[index].system;
		prev[index].softirq = curr[index].softirq;
		prev[index].irq = curr[index].irq;
		prev[index].idle = curr[index].idle;
		prev[index].iowait = curr[index].iowait;
		prev[index].steal = curr[index].steal;
	}
}

void copy_diff_value(struct cpu_usage_diff *dst, struct cpu_usage_diff *src)
{
	int index = 0;

	if(!dst || !src)
	{
		cprintf("copy_diff_value(): Null Pointer\n");
		exit(1);
	}

	for(index = 0; index < cpu_cnt + 1; index++)
	{
		dst[index].user = src[index].user;
		dst[index].nice = src[index].nice;
		dst[index].system = src[index].system;
		dst[index].softirq = src[index].softirq;
		dst[index].irq = src[index].irq;
		dst[index].idle = src[index].idle;
		dst[index].iowait = src[index].iowait;
		dst[index].steal = src[index].steal;
		dst[index].factor = src[index].factor;
	}
}

void cpuusage_main(int interval)
{
	time_t secs = 0;
	static int counter = 0;
	static unsigned long localcounter = 0;
	struct cpu_usage_record_s *del_node = NULL;

	if(counter++ % interval == 0)
	{
		counter = 1; //reset counter
		get_cpu_jiffies(curr_stat);

		calc_diff(prev_stat, curr_stat, diff_stat);
		store_prev_value(prev_stat, curr_stat);

		time(&secs);

		cuCurrent = (struct cpu_usage_record_s *) malloc(sizeof(struct cpu_usage_record_s));
		if(cuCurrent == NULL)
		{
			cprintf("[cpuusage_main](1)Cannot allocate memory!!\n");
			return;
		}
		cuCurrent->next = NULL;

		cuCurrent->cuRecord = (struct cpu_usage_diff *) malloc(sizeof(struct cpu_usage_diff)*(cpu_cnt + 1));
		if(cuCurrent->cuRecord == NULL)
		{
			free(cuCurrent);
			cuCurrent = NULL;
			cprintf("[cpuusage_main](2)Cannot allocate memory!!\n");
			return;
		}

		copy_diff_value(cuCurrent->cuRecord, diff_stat);

		cuCurrent->timestamp = secs;

		if(cuHead == NULL)
		{
			cuHead = cuCurrent;
			localcounter = 1;
		}
		else
		{
			cuPrev->next = cuCurrent;
			localcounter++;
		}

		cuPrev = cuCurrent;

		if( localcounter > CU_MAX_ENTRY )
		{
			del_node = cuHead;
			cuHead = cuHead->next;
			localcounter--;

			free(del_node->cuRecord);
			free(del_node);
		}

	}
}

void cpuusage_dump(void)
{
	FILE *fp = NULL;
	char timestr[32] = {0};
	struct cpu_usage_record_s *cuDump = NULL;
	double tmpFactor = 0.0;

	fp = fopen(DUMP_PATH_CPUUSAGE, "w");
	if(!fp)
	{
		cprintf("cpuusage_dump(): cannot create log file.\n");
		return;
	}

	if(cuHead)
	{
		fprintf(fp, "[timestamp] %18s %7s %7s %8s %8s %4s %7s %9s %7s\n", "cpu", "user", "nice", "system", "softirq", "irq", "idle", "iowait", "steal");
		cuDump = cuHead;
		while(cuDump)
		{
			sprintf(timestr, "%s", ctime(&(cuDump->timestamp)));
			timestr[strlen(timestr)-1] = '\0';

			tmpFactor = cuDump->cuRecord->factor;
			fprintf(fp, "[%s]%4s %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n", timestr, "all",
				cuDump->cuRecord->user*tmpFactor, cuDump->cuRecord->nice*tmpFactor,
				cuDump->cuRecord->system*tmpFactor,  cuDump->cuRecord->softirq*tmpFactor,
				cuDump->cuRecord->irq*tmpFactor,  cuDump->cuRecord->idle*tmpFactor,
				cuDump->cuRecord->iowait*tmpFactor, cuDump->cuRecord->steal*tmpFactor
			);
			cuDump = cuDump->next;
		}
	}

	fclose(fp);

}

void cpuusage_dump_detail(void)
{
	FILE *fp = NULL;
	char timestr[32] = {0};
	struct cpu_usage_record_s *cuDump = NULL;
	int cpu_idx = 0;
	double tmpFactor = 0.0;

	fp = fopen(DUMP_PATH_DETAIL_CPUUSAGE, "w");
	if(!fp)
	{
		cprintf("cpuusage_dump(): cannot create log file.\n");
		return;
	}

	if(cuHead)
	{
		fprintf(fp, "[timestamp] %18s %7s %7s %8s %8s %4s %7s %9s %7s\n", "cpu", "user", "nice", "system", "softirq", "irq", "idle", "iowait", "steal");
		cuDump = cuHead;
		while(cuDump)
		{
			sprintf(timestr, "%s", ctime(&(cuDump->timestamp)));
			timestr[strlen(timestr)-1] = '\0';

			for(cpu_idx = 0; cpu_idx < cpu_cnt + 1; cpu_idx++)
			{
				if(cpu_idx == 0)
				{
					tmpFactor = cuDump->cuRecord->factor;
					fprintf(fp, "[%s]%4s %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n", timestr, "all",
						cuDump->cuRecord->user*tmpFactor, cuDump->cuRecord->nice*tmpFactor,
						cuDump->cuRecord->system*tmpFactor,  cuDump->cuRecord->softirq*tmpFactor,
						cuDump->cuRecord->irq*tmpFactor,  cuDump->cuRecord->idle*tmpFactor,
						cuDump->cuRecord->iowait*tmpFactor, cuDump->cuRecord->steal*tmpFactor
					);
				}
				else
				{
					tmpFactor = cuDump->cuRecord[cpu_idx].factor;
					fprintf(fp, "[%s]%4d %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n", timestr, (cpu_idx - 1),
						cuDump->cuRecord[cpu_idx].user*tmpFactor, cuDump->cuRecord[cpu_idx].nice*tmpFactor,
						cuDump->cuRecord[cpu_idx].system*tmpFactor,  cuDump->cuRecord[cpu_idx].softirq*tmpFactor,
						cuDump->cuRecord[cpu_idx].irq*tmpFactor,  cuDump->cuRecord[cpu_idx].idle*tmpFactor,
						cuDump->cuRecord[cpu_idx].iowait*tmpFactor, cuDump->cuRecord[cpu_idx].steal*tmpFactor
					);
				}
			}

			cuDump = cuDump->next;
		}
	}

	fclose(fp);
}

void init_cpuusage(void)
{
	cpu_cnt = get_cpu_amount();

	prev_stat = (struct cpu_usage_stat*) calloc(cpu_cnt+1, sizeof(struct cpu_usage_stat));
	curr_stat = (struct cpu_usage_stat*) calloc(cpu_cnt+1, sizeof(struct cpu_usage_stat));
	diff_stat = (struct cpu_usage_diff*) calloc(cpu_cnt+1, sizeof(struct cpu_usage_diff));

	if( (prev_stat == NULL) || (curr_stat == NULL) || (diff_stat == NULL) )
	{
		cprintf("init_cpuusage(): malloc failed.\n");
		exit(1);
	}
}
