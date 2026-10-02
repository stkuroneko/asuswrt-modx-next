/*
	spectrum.c

	    This program executes commands and outputs the command results.
	When getting SIGUSR1 signal, it will ...
	When getting SIGUSR2 signal, it will ...

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <stdint.h>
#include <syslog.h>

#include <bcmnvram.h>
#include <shared.h>
#include <shutils.h>

volatile int gotuser1 = 0;
volatile int gotterm = 0;

//snr : signal to noise ratio
static void save_snr(void)
{
	static int runFlag = 0;

	if(runFlag == 1)
	{
		//skip this time.
		return;
	}

	runFlag = 1;

	eval("adslate", "showsnr");

	runFlag = 0;
}

//bpc : bits per carrier
static void save_bpc(void)
{
	static int runFlag = 0;

	if(runFlag == 1)
	{
		//skip this time.
		return;
	}

	runFlag = 1;

	eval("adslate", "showbpc");

	runFlag = 0;
}

static void sig_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		gotterm = 1;
		break;
	case SIGUSR1:
		gotuser1 = 1;
		nvram_set("spectrum_hook_is_running","1");
		break;
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	pid_t fpid;

	printf("spectrum\nCopyright (C) 2012-2014 ASUSWRT\n\n");

	nvram_set("spectrum_hook_is_running","0"); //initial, 0:NotRunning, 1: Running

	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	/* tell parent process to ignore the terminated child process. 
       ** Or there will be zombie process.
       */
	signal(SIGCHLD, SIG_IGN);

	while (1) {
		sleep(20);
		if (gotterm) {
			exit(0);
		}
		if (gotuser1) {
			gotuser1 = 0;
			fpid = fork();
			if(fpid == 0) {
				//child
				save_bpc();
				save_snr();
				nvram_set("spectrum_hook_is_running","0");
				_exit(0);
			}
			else {
				//parent, do nothing.
				continue;
			}
		}
	}
	return 0;
}
