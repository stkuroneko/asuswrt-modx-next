/*
 * Copyright 2020, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/sysinfo.h>

#include "dsl_diag.h"

#define ALARM_SECONDS    5
#define RESTART_PEROID   3600

static int do_alrm = 0;
static int do_term = 0;

enum dsl_diag_state{
	DSL_DIAG_STATE_NONE=0,
	DSL_DIAG_STATE_START,
	DSL_DIAG_STATE_TASK_COMPLETE,
	DSL_DIAG_STATE_SENDMAIL_SUCCESS,
	DSL_DIAG_STATE_SENDMAIL_FAIL_SMTP,
	DSL_DIAG_UI_CANCEL_DEBUG_CAPTURE,
	DSL_DIAG_STATE_DUMP_LOG_FAIL,
	DSL_DIAG_STATE_SENDMAIL_FAIL_OTHER
};

void signal_handler(int signum)
{
	if (signum == SIGALRM)
	{
		if(do_alrm == 0)
			do_alrm = 1;
		else
			printf("DSL_DIAG: last task not finished!\n");
	}
	else if (signum == SIGTERM)
		do_term = 1;
	else
		printf("DSL_DIAG: ignore signal: %d\n", signum);
}

static void reg_signal()
{
	struct sigaction sa;
	struct itimerval itv;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &signal_handler;

	sigaction(SIGALRM, &sa, NULL);

	itv.it_value.tv_sec = ALARM_SECONDS;
	itv.it_value.tv_usec = 0;
	itv.it_interval = itv.it_value;
	setitimer(ITIMER_REAL, &itv, NULL);
}

static void exit_option_error()
{
	fprintf(stderr, "Usage: [options] -d nsecs -o <full path of output file>\n");
	exit(EXIT_FAILURE);
}

int main (int argc, char **argv)
{
	int opt;
	DIAG_PARAM param;
	struct sysinfo si;
	long start_time;
	long restart_time;
	int dsl_link_state;

	if (argc < 5)
		return EXIT_FAILURE;

	memset(&param, 0, sizeof(param));

	while ((opt = getopt(argc, argv, "rd:o:")) != -1)
	{
		switch (opt)
		{
		case 'd':
			param.duration = strtoul(optarg, NULL, 0);
			break;
		case 'o':
			snprintf(param.log_path, sizeof(param.log_path), "%s", optarg);
			break;
		case 'r':
			param.tillretrain = 1;
			break;
		default:
			exit_option_error();
		}
	}

	if (param.duration == 0 || strlen(param.log_path) == 0)
		exit_option_error();

	reg_signal();

	sysinfo(&si);
	start_time = si.uptime;
	restart_time = si.uptime;

	unlink(param.log_path);
	start_diag(&param);

	// down / up to make sure training data is captured.
	dsl_downup();
	while(1)
	{
		pause();

		if(do_alrm)
		{
			dump_diag_log(&param);
			do_alrm = 0;
		}

		if(do_term)
		{
			stop_diag(&param);
			return 0;
		}

		if (is_dsl_link_up())
			break;
	}

	dsl_link_state = 1;

	// long term capturing
	while(1)
	{
		pause();

		if(do_alrm)
		{
			dump_diag_log(&param);
			do_alrm = 0;
		}

		if(do_term)
		{
			stop_diag(&param);
			break;
		}

		sysinfo(&si);
		if ((si.uptime - start_time) > param.duration)
		{
			stop_diag(&param);
			update_dsl_diag_state(DSL_DIAG_STATE_TASK_COMPLETE);
			system("service stop_dsl_diag");
			break;
		}

		if (param.tillretrain)
		{
			// stop if down to up
			if (is_dsl_link_up())
			{
				if (dsl_link_state == 0) //down -> up
				{
					stop_diag(&param);
					update_dsl_diag_state(DSL_DIAG_STATE_TASK_COMPLETE);
					system("service stop_dsl_diag");
					break;
				}
				dsl_link_state = 1;
			}
			else
			{
				dsl_link_state = 0;
			}

			// restart if running RESTART_PEROID
			if ((si.uptime - restart_time) > RESTART_PEROID)
			{
				stop_diag(&param);
				unlink(param.log_path);
				start_diag(&param);
				restart_time = si.uptime;
			}
		}
	}

	return 0;
}
