/*
	bwdpi_check.c for keep wred / data_colld alive
*/

#include <rc.h>
#include <bwdpi_common.h>
#include <time.h>

static void tstamp_log(char *timestamp, int len)
{
	time_t now;
	time(&now);
	snprintf(timestamp, len, "%lu", now);
}

static void check_wred_alive()
{
	int enabled = check_bwdpi_nvram_setting();
	static int period = 0;
	int cycle = 4;
	char tstamp[20] = {0};

	period = (period + 1) % cycle;

	tstamp_log(tstamp, sizeof(tstamp));
	BWDPI_DBG("tstamp=%s, enabled=%d, period=%d\n", tstamp, enabled, period);
	if (enabled && !period) {
		BWDPI_DBG("start_wrs and start_data_colld\n");
		// start wrs
		start_wrs();
		// start data_colld
		start_dc(NULL);
	}
}

static int sig_cur = -1;

static void catch_sig(int sig)
{
	char tstamp[20] = {0};
	sig_cur = sig;
	
	if (sig == SIGTERM)
	{
		remove("/var/run/bwdpi_wred_check.pid");
		exit(0);
	}
	else if(sig == SIGALRM)
	{
		auto_sig_check();
		tm_eula_check();
		web_history_save();
		AiProtectionMonitor_mail_log();
		check_wred_alive();

		tstamp_log(tstamp, sizeof(tstamp));
		BWDPI_DBG("tstamp=%s, SIGALRM!\n", tstamp);
	}
}

int bwdpi_wred_alive_main(int argc, char **argv)
{
	FILE *fp;
	sigset_t sigs_to_catch;
	char tstamp[20] = {0};

	/* write pid */
	if ((fp = fopen("/var/run/bwdpi_wred_alive.pid", "w")) != NULL)
	{
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	/* set the signal handler */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGTERM);
	sigaddset(&sigs_to_catch, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &sigs_to_catch, NULL);

	signal(SIGTERM, catch_sig);
	signal(SIGALRM, catch_sig);

	while(1)
	{
		tstamp_log(tstamp, sizeof(tstamp));
		BWDPI_DBG("tstamp=%s, alarm 30 secs\n", tstamp);
		// keep alarm 30 secs
		alarm(30);
		pause();
	}

	return 0;
}
