#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <shared.h>
#include <shutils.h>
#include <time.h>

#define CT_MAX_ENTRY 6000

#define DUMP_PATH_CPUTEMP "/tmp/asusfbsvcs/cputemp_log.txt"

#if defined(RTCONFIG_SOC_IPQ8064) || defined(RTCONFIG_SOC_IPQ8074)
#define PROC_ENTRY_CPUTEMP "/sys/class/thermal/thermal_zone0/temp"
#elif defined(HND_ROUTER)
#define PROC_ENTRY_CPUTEMP "/sys/class/thermal/thermal_zone0/temp"
#else
#define PROC_ENTRY_CPUTEMP "/proc/dmu/temperature"
#endif

int temperature_proc_entry_exist = 0;

struct cpu_temp_record_s {
	time_t timestamp;
	double cputemp;
	struct cpu_temp_record_s* next;
};

void cputemp_main(int interval);
void cputemp_dump(void);
void init_cputemp(void);

struct cpu_temp_record_s *ctHead = NULL;
struct cpu_temp_record_s *ctCurrent = NULL;
struct cpu_temp_record_s *ctPrev = NULL;

void get_cpu_temp(struct cpu_temp_record_s *result)
{
#if defined(RTCONFIG_SOC_IPQ8064) || defined(RTCONFIG_SOC_IPQ8074)
	char *buf = NULL;

	buf = file2str(PROC_ENTRY_CPUTEMP);
	if (!buf)
		return;

	result->cputemp = (double) strtoul(buf, NULL, 10);
	free(buf);
#elif defined(HND_ROUTER)
	char *buf = NULL;

	buf = file2str(PROC_ENTRY_CPUTEMP);
	if(!buf)
	{
		return;
	}

	result->cputemp = (double) (strtoul(buf, NULL, 10)*1.0)/1000.0;
	free(buf);
#else
	char buffer[32] = {0};
	double cpu_temperature = 0.0;
	FILE *fp = fopen(PROC_ENTRY_CPUTEMP, "r");

	if(fp)
	{
		if(fgets(buffer, sizeof(buffer), fp))
		{
			// ASCII code of °C is 248 & 67.
			sscanf(buffer, "CPU temperature : %lf\248\67", &cpu_temperature);
			//cprintf("[%lf]\n", cpu_temperature);
			result->cputemp = cpu_temperature;
		}
		fclose(fp);
	}
#endif
}

void cputemp_main(int interval)
{
	time_t secs = 0;
	static int counter = 0;
	static unsigned long localcounter = 0;
	struct cpu_temp_record_s *del_node = NULL;

	if(!temperature_proc_entry_exist)
	{
		return;
	}

	if(counter++ % interval == 0)
	{
		counter = 1; //reset counter

		time(&secs);
		//cprintf("cputemp_main::%s", ctime(&secs));

		ctCurrent = (struct cpu_temp_record_s *) malloc(sizeof(struct cpu_temp_record_s));
		if(ctCurrent == NULL)
		{
			cprintf("[cputemp_main](1)Cannot allocate memory!!\n");
			return;
		}
		ctCurrent->next = NULL;

		ctCurrent->timestamp = secs;
		get_cpu_temp(ctCurrent);

		if(ctHead == NULL)
		{
			ctHead = ctCurrent;
			localcounter = 1;
		}
		else
		{
			ctPrev->next = ctCurrent;
			localcounter++;
		}

		ctPrev = ctCurrent;

		if( localcounter > CT_MAX_ENTRY )
		{
			del_node = ctHead;
			ctHead = ctHead->next;
			localcounter--;

			free(del_node);
		}
	}
}

void cputemp_dump(void)
{
	FILE *fp = NULL;
	char timestr[32] = {0};
	struct cpu_temp_record_s *ctDump = NULL;

	fp = fopen(DUMP_PATH_CPUTEMP, "w");
	if(!fp)
	{
		cprintf("cputemp_dump(): cannot create log file.\n");
		return;
	}

	if(ctHead)
	{
		fprintf(fp, "[timestamp] %27s\n", "temperature");
		ctDump = ctHead;
		while(ctDump)
		{
			sprintf(timestr, "%s", ctime(&(ctDump->timestamp)));
			timestr[strlen(timestr)-1] = '\0';

			fprintf(fp, "[%s]%10.2f %s\n", timestr, ctDump->cputemp, "Celsius");
			ctDump = ctDump->next;
		}
	}

	fclose(fp);
}

void init_cputemp(void)
{
	if(f_exists(PROC_ENTRY_CPUTEMP))
	{
		temperature_proc_entry_exist = 1;
	}
}
