/*

	sysstate
	Copyright (C) 2016 Renjie Lee

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <stdint.h>
#include <syslog.h>
#include <shutils.h>
#include <shared.h>

#include "sysstate.h"


int is_get_alarm = 0;
int is_recording_log = 0;
int is_recording_allowed = 1;
int m_Exit = 0;

extern void init_cpuusage(void);
extern void cpuusage_main(int interval);

extern void init_ramusage(void);
extern void ramusage_main(int interval);

extern void init_cputemp(void);
extern void cputemp_main(int interval);

extern int CreateMsgQ(void);
extern int RcvMsgQ(void);
extern unsigned int cpu_cnt;

extern struct cpu_usage_stat *prev_stat;
extern struct cpu_usage_stat *curr_stat;
extern struct cpu_usage_diff *diff_stat;


void initial_functions(void)
{
	system("mkdir -p /tmp/asusfbsvcs");

	init_cpuusage();
	init_ramusage();
	init_cputemp();
}

void log_ram_usage(int interval)
{
	ramusage_main(interval);
}

void log_cpu_usage(int interval)
{
	cpuusage_main(interval);
}

void log_cpu_temperature(int interval)
{
	cputemp_main(interval);
}

/*
*  start the timer repeatly
*
*  first_seconds: the first timer when you call this function
*  interval: the following timer interval for each run
*  func: call back function pointer
*  The whole behavior should be: after first_seconds->call func->after interval->call func->after interval->call func->...
*
*/
int timerTrigger_re(unsigned int first_seconds, unsigned int interval, void (*func)(int signo))
{
	struct itimerval delay;
	int ret;

	signal(SIGALRM, func);

	delay.it_value.tv_sec = first_seconds;
	delay.it_value.tv_usec = 0;
	delay.it_interval.tv_sec = interval;
	delay.it_interval.tv_usec = 0;
	ret = setitimer (ITIMER_REAL, &delay, NULL);
	if(ret)
	{
		cprintf("[timerTrigger()]setitimer error, ret=%d\n", ret);
	}
	return ret;
}


int wait_for_semaphore(void)
{
	while(is_recording_log)
	{
		sleep(1);
	}
	//cprintf("=====get semaphore=====\n");
	return 0;
}

int get_logging_flag(void)
{
	return is_recording_allowed;
}

void enable_logging(void)
{
	is_recording_allowed = 1;
}

void disable_logging(void)
{
	is_recording_allowed = 0;
}

void log_actions(void)
{
	if(is_recording_log == 0)
	{
		is_recording_log = 1;
		if(get_logging_flag() == 1)
		{
			log_ram_usage(6);
			log_cpu_usage(6);
			log_cpu_temperature(6);
		}
		else
		{
			//do nothing.
		}
		is_recording_log = 0;
	}
}

static void sig_alarm_handler(int sig)
{
	is_get_alarm = 1;
}

int main(int argc, char *argv[])
{
	int ret_rcv_msg;

	printf("sysstate\nCopyright (C) 2016\n\n");

	initial_functions();

	timerTrigger_re(5, 5, sig_alarm_handler);

	if(CreateMsgQ() != 0)
	{
		cprintf("sysstate:failed to create message queue!\n\n");
		return -1;
	}

	/* tell parent process to ignore the terminated child process.
       ** Or there will be zombie process.
	signal(SIGCHLD, SIG_IGN);
	*/

	while (1) {
		if (is_get_alarm)
		{
			is_get_alarm = 0;
			log_actions();
		}

		ret_rcv_msg = -1;
		ret_rcv_msg = RcvMsgQ();
		if (ret_rcv_msg == -1)
		{
			//error
		}
		else if (ret_rcv_msg == 1)
		{
			m_Exit = 1;
			break;
		}
	}
	cprintf("sysstate:quit process...\n\n");
	return 0;
}

