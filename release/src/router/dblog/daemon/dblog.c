/*

	dblog
	Copyright (C) 2016 Renjie Lee

*/

#include "dblog.h"
#include <fcntl.h>	//open
#include <unistd.h>	//close

/****************************************
	Macros
****************************************/
#define DBLOG_PIDPATH "/var/run"
#define DBLOG_PIDFILE "/var/run/dblog.pid"
#define DBLOG_FOLDER "asus_dblog/collections"
#define DBLOG_PATH "/tmp/asus_dblog/collections"
#define DBLOG_TAR_PATH "/tmp/asus_dblog"
#define DBLOG_CHECK_PERIOD 60

#define DBLOG_ENABLE_WIFI (1<<0)
#define DBLOG_ENABLE_DM (1<<1)
#define DBLOG_ENABLE_MS (1<<2)
#define DBLOG_ENABLE_AMAS (1<<3)
#define DBLOG_ENABLE_DHD (1<<4)

/****************************************
	Variables
****************************************/
int is_get_alarm = 0;
int is_get_term = 0;
int is_recording_log = 0;
int is_recording_allowed = 1;

int gTousb = 0;
int gService = 0;
int gRemaining = 0;
/****************************************
	Function declaration (prototype)
****************************************/
extern int CreateMsgQ(void);
extern int RcvMsgQ(void);

void pause_logging(void)
{
	char buf[16] = {0};
	FILE *fp = popen("ps|grep \'tail -n 500 -s 10 -F \'|grep -v \'grep\'|awk \'{print $1}\'", "r");

	if(fp)
	{
		while(fgets(buf, sizeof(buf), fp))
		{
			if(atoi(buf) > 1)
			{
				kill(atoi(buf), SIGTERM);
			}
			memset(buf, 0, sizeof(buf));
		}
		pclose(fp);
	}
}

void quit_process(void)
{
	unlink(DBLOG_PIDFILE);
	cprintf("dblog:quit_process(), dblog_state=[%d]\n", nvram_get_int("dblog_state"));
	logmessage("dblog", "quit_process(), dblog_state=[%d]\n", nvram_get_int("dblog_state"));
	nvram_commit();
	exit(0);
}

void dblog_initial(void)
{
	char cmdbuf[128] = {0};
	char pathbuf[64] = {0};
	int pid_file = 0;
	pid_t pid;
	char pidbuf[16] = {0};
	int pidbuflen = 0;
	//int needReboot = 0; // remove reboot mechanism

	cprintf("[%s]\n", __FUNCTION__);

	if(!check_if_dir_exist(DBLOG_PIDPATH))
	{
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "mkdir -p %s", DBLOG_PIDPATH);
		system(cmdbuf);
	}

	if((pid_file = open(DBLOG_PIDFILE, O_RDONLY)) < 0)
	{
		//pid_file is not there, should be the first instance.
		pid_file = open(DBLOG_PIDFILE, O_CREAT | O_RDWR, 0666);
		if(pid_file != -1)
		{
			pidbuflen = snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
			write(pid_file, pidbuf, pidbuflen);
			close(pid_file);
		}
		else
		{
			cprintf("[%s]cannot create [%s].\n", __FUNCTION__, DBLOG_PIDFILE);
			exit(0);
		}
	}
	else
	{
		memset(pathbuf, 0, sizeof(pathbuf));
		if(read(pid_file, pathbuf, sizeof(pathbuf)-1))
		{
			if((pid = atol(pathbuf)) > 0)
			{
				cprintf("[%s]dblog is already running.\n", __FUNCTION__);
				close(pid_file);
				exit(0);
			}
		}
		close(pid_file);
	}

	memset(pathbuf, 0, sizeof(pathbuf));
	memset(cmdbuf, 0, sizeof(cmdbuf));
	snprintf(pathbuf, sizeof(pathbuf), "%s", DBLOG_PATH);
	snprintf(cmdbuf, sizeof(cmdbuf), "mkdir -p %s", pathbuf);
	system(cmdbuf);

	if(!check_if_dir_exist(pathbuf))
	{
		//should not come here.
		cprintf("[%s]Failed to create [%s].\n", __FUNCTION__, pathbuf);
		if(gTousb == 1)
		{
			nvram_set_int("dblog_state", DBLOG_STATE_ERR_USB);
		}
		else
		{
			nvram_set_int("dblog_state", DBLOG_STATE_ERR_OTHERS);
		}
		nvram_set_int("dblog_enable", 0);
		quit_process();
	}

	pause_logging();
	sleep(1);

	gTousb = nvram_get_int("dblog_tousb");

	if(gTousb == 1)
	{
		if(strlen(nvram_safe_get("dblog_usb_path")) > 0)
		{
			memset(pathbuf, 0, sizeof(pathbuf));
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", nvram_safe_get("dblog_usb_path"), DBLOG_FOLDER);
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(cmdbuf, sizeof(cmdbuf), "mkdir -p %s", pathbuf);
			system(cmdbuf);

			if(!check_if_dir_exist(pathbuf))
			{
				cprintf("[%s]Cannot create folder in USB, use default path [%s].\n", __FUNCTION__, DBLOG_PATH);
				gTousb = 0;
				nvram_set("dblog_log_path", DBLOG_PATH);
			}
		}
		else
		{
			cprintf("[%s]No USB disk, use default path [%s].\n", __FUNCTION__, DBLOG_PATH);
			gTousb = 0;
			nvram_set("dblog_log_path", DBLOG_PATH);
		}
	}

	nvram_set("dblog_log_path", pathbuf);

	gRemaining = nvram_get_int("dblog_remaining");

	if(gRemaining <= 0)
	{
		gRemaining = nvram_get_int("dblog_duration");
	}

	gService = nvram_get_int("dblog_service");
	if(gService & DBLOG_ENABLE_WIFI)
	{
#if 0 // remove reboot mechanism
	#ifdef RTCONFIG_BCM_7114
		needReboot = 0;
	#else /* RTCONFIG_BCM_7114 */
		needReboot = 1;
	#endif /* RTCONFIG_BCM_7114 */
#endif
		enable_wifilog();
#if 0 // remove reboot mechanism
		if((needReboot == 1) && (nvram_get_int("dblog_state") != DBLOG_STATE_REBOOT))
		{
			nvram_set_int("dblog_state", DBLOG_STATE_REBOOT);
			nvram_commit();
cprintf("[%s]Prepare to reboot device once to enable Wi-Fi log.\n", __FUNCTION__);
			notify_rc("reboot");
			unlink(DBLOG_PIDFILE);
			exit(0);
		}
#endif
	}
	if(gService & DBLOG_ENABLE_DM)
	{
		enable_dmlog();
	}
	if(gService & DBLOG_ENABLE_MS)
	{
		enable_mslog();
	}
	if(gService & DBLOG_ENABLE_AMAS)
	{
		enable_amaslog();
	}
#ifdef RTCONFIG_HND_ROUTER
	if(gService & DBLOG_ENABLE_DHD)
	{
		enable_dhdlog();
	}
#endif /* RTCONFIG_HND_ROUTER */

#if defined(MAPAC1300) || defined(MAPAC2200) || defined(VZWAC1300)
	enable_hydlog();
#endif

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

void killall_tk(const char *name)
{
	int n;

	if (killall(name, SIGTERM) == 0) {
		n = 10;
		while ((killall(name, 0) == 0) && (n-- > 0)) {
			cprintf("%s: waiting name=%s n=%d\n", __FUNCTION__, name, n);
			usleep(100 * 1000);
		}
		if (n < 0) {
			n = 10;
			while ((killall(name, SIGKILL) == 0) && (n-- > 0)) {
				cprintf("%s: SIGKILL name=%s n=%d\n", __FUNCTION__, name, n);
				usleep(100 * 1000);
			}
		}
	}
}

void stop_logging(void)
{
	pause_logging();

	if(gService & DBLOG_ENABLE_WIFI)
	{
		disable_wifilog();
	}
	if(gService & DBLOG_ENABLE_DM)
	{
		disable_dmlog();
	}
	if(gService & DBLOG_ENABLE_MS)
	{
		disable_mslog();
	}
	if(gService & DBLOG_ENABLE_AMAS)
	{
		disable_amaslog();
	}
#ifdef RTCONFIG_HND_ROUTER
	if(gService & DBLOG_ENABLE_DHD)
	{
		disable_dhdlog();
	}
#endif /* RTCONFIG_HND_ROUTER */

#if defined(MAPAC1300) || defined(MAPAC2200) || defined(VZWAC1300)
	disable_hydlog();
#endif
}

void restart_logging(void)
{
	if(gService & DBLOG_ENABLE_WIFI)
	{
		monitor_wifilog();
	}
	if(gService & DBLOG_ENABLE_DM)
	{
		monitor_dmlog();
	}
	if(gService & DBLOG_ENABLE_MS)
	{
		monitor_mslog();
	}
	if(gService & DBLOG_ENABLE_AMAS)
	{
		monitor_amaslog();
	}
#ifdef RTCONFIG_HND_ROUTER
	if(gService & DBLOG_ENABLE_DHD)
	{
		monitor_dhdlog();
	}
#endif /* RTCONFIG_HND_ROUTER */
}

void add_extra_wifi_log(void)
{
#ifdef RTCONFIG_HND_ROUTER_AX_675X
	char cmdbuf[256] = {0};
	FILE *cmd_pipe = NULL;
	char tmp[128] = {0};

	cmd_pipe = popen("find /tmp -name \"core-*\"|wc -l", "r");
	if(cmd_pipe)
	{
		fgets(tmp, sizeof(tmp), cmd_pipe);
		if(atoi(tmp) > 0)
		{
			snprintf(cmdbuf, sizeof(cmdbuf), "cd /tmp; rm -f core.tgz; tar zcf core.tgz core-*");
			system(cmdbuf);
			snprintf(cmdbuf, sizeof(cmdbuf), "rm -rf /tmp/core-*");
			system(cmdbuf);
			snprintf(cmdbuf, sizeof(cmdbuf), "mv /tmp/core.tgz %s", nvram_safe_get("dblog_log_path"));
			system(cmdbuf);
		}
		pclose(cmd_pipe);
	}
#endif /* RTCONFIG_HND_ROUTER_AX_675X */
}

void log_actions(void)
{
	int dblog_dir_size = 0;
	char cmdbuf[256] = {0};
	char filename[128] = {0};
	static unsigned int index = 1;
	int retval = 0;

	if(nvram_get_int("dblog_state") >= DBLOG_STATE_SENDMAIL_FAIL_SMTP)
	{
		nvram_set_int("dblog_enable", 0);
		stop_logging();
		quit_process();
	}

	if(nvram_get_int("dblog_state") == DBLOG_STATE_SENDMAIL_SUCCESS)
	{
		nvram_set_int("dblog_state", DBLOG_STATE_RUN);
		nvram_commit();
	}
	else if(nvram_get_int("dblog_state") == DBLOG_STATE_PAUSE)
	{
		return;
	}

	dblog_dir_size = d_size(nvram_safe_get("dblog_log_path"));

	//cprintf("log_actions:folder size=%lu\n", dblog_dir_size);
	//cprintf("gRemaining=%d\n", gRemaining);

	if(dblog_dir_size == -1)
	{
		nvram_set_int("dblog_state", DBLOG_STATE_ERR_OTHERS);
		nvram_set_int("dblog_enable", 0);
		stop_logging();
		quit_process();
	}
	else if(gRemaining <= 0)
	{
		stop_logging();
		nvram_set_int("dblog_remaining", 0);
		nvram_set_int("dblog_enable", 0);

		if(!check_if_dir_exist(DBLOG_PATH))
		{
			memset(cmdbuf, 0, sizeof(cmdbuf));
			snprintf(cmdbuf, sizeof(cmdbuf), "mkdir -p %s", DBLOG_PATH);
			retval = system(cmdbuf);
			if(retval)
			{
				nvram_set_int("dblog_state", DBLOG_STATE_ERR_OTHERS);
				quit_process();
			}
		}

		add_extra_wifi_log();
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename), "sysdblog%05d.tgz", index);

		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "tar -zc -f %s/%s %s/*", DBLOG_TAR_PATH, filename, nvram_safe_get("dblog_log_path"));
		retval = system(cmdbuf);
		if(retval)
		{
			nvram_set_int("dblog_state", DBLOG_STATE_ERR_OTHERS);
			quit_process();
		}

		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "rm -f %s/*", nvram_safe_get("dblog_log_path"));
		system(cmdbuf);

		nvram_set_int("dblog_state", DBLOG_STATE_FINISH);
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "start_senddblog %s/%s", DBLOG_TAR_PATH, filename);
		notify_rc(cmdbuf);

		quit_process();
	}
	// if folder size > 2 Mbytes
	else if((dblog_dir_size > 2*1024*1024) && (gTousb == 0))
	{
		add_extra_wifi_log();
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename), "sysdblog%05d.tgz", index);

		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "tar -zc -f %s/%s %s/*", DBLOG_TAR_PATH, filename, nvram_safe_get("dblog_log_path"));
		retval = system(cmdbuf);
		if(retval)
		{
			nvram_set_int("dblog_state", DBLOG_STATE_ERR_OTHERS);
			nvram_set_int("dblog_enable", 0);
			stop_logging();
			quit_process();
		}

		pause_logging();
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "rm -f %s/*", nvram_safe_get("dblog_log_path"));
		system(cmdbuf);
		restart_logging();

		nvram_set_int("dblog_state", DBLOG_STATE_PAUSE);
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "start_senddblog %s/%s", DBLOG_TAR_PATH, filename);
		notify_rc(cmdbuf);
		index++;
	}

	if(gService & DBLOG_ENABLE_WIFI)
	{
		backup_wifilog();
	}
	if(gService & DBLOG_ENABLE_DM)
	{
		backup_dmlog();
	}
	if(gService & DBLOG_ENABLE_MS)
	{
		backup_mslog();
	}
	if(gService & DBLOG_ENABLE_AMAS)
	{
		backup_amaslog();
	}
#ifdef RTCONFIG_HND_ROUTER
	if(gService & DBLOG_ENABLE_DHD)
	{
		backup_dhdlog();
	}
#endif /* RTCONFIG_HND_ROUTER */
	gRemaining -= DBLOG_CHECK_PERIOD;
	if(gRemaining < 0)
	{
		gRemaining = 0;
	}
	nvram_set_int("dblog_remaining", gRemaining);
	nvram_commit();
}

static void sig_alarm_handler(int sig)
{
	is_get_alarm = 1;
}

static void sig_term_handler(int sig)
{
	is_get_term = 1;
}

int main(int argc, char *argv[])
{
	int ret_rcv_msg;
	int exitPoint = 0;

	if(nvram_get_int("dblog_enable") != 1)
	{
		cprintf("[%s]dblog is not enabled.\n", __FUNCTION__);
		nvram_set_int("dblog_enable", 0);
		nvram_commit();
		return 0;
	}

	printf("dblog\nCopyright (C) 2017\n\n");

	if(argc == 2)
	{
		if(strcmp(argv[1], "reset") == 0)
		{
			nvram_set_int("dblog_remaining", 0);
			nvram_set_int("dblog_state", DBLOG_STATE_INIT);
		}
	}

	dblog_initial();

	signal(SIGTERM, sig_term_handler);

	timerTrigger_re(5, DBLOG_CHECK_PERIOD, sig_alarm_handler);

	if(CreateMsgQ() != 0)
	{
		cprintf("dblog:failed to create message queue!\n\n");
		return -1;
	}

	/* tell parent process to ignore the terminated child process.
       ** Or there will be zombie process.
	signal(SIGCHLD, SIG_IGN);
	*/

	nvram_set_int("dblog_state", DBLOG_STATE_RUN);
	nvram_commit(); //save settings
	logmessage("dblog", "duration=[%d], remaining=[%d], service=[%d]\n", nvram_get_int("dblog_duration"), gRemaining, nvram_get_int("dblog_service"));

	while (1) {
		if (is_get_term)
		{
			is_get_term = 0;
			stop_logging();
			nvram_set_int("dblog_remaining", 0);
			nvram_set_int("dblog_state", DBLOG_STATE_STOP);
			//dblog_enable should be reset to 0 by GUI/others so that AiMesh master/slave could catch this event.
			unlink(DBLOG_PIDFILE);
			nvram_commit();
			exitPoint = 1;
			break;
		}

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
			stop_logging();
			nvram_set_int("dblog_remaining", 0);
			nvram_set_int("dblog_state", DBLOG_STATE_STOP);
			//dblog_enable should be reset to 0 by GUI/others so that AiMesh master/slave could catch this event.
			unlink(DBLOG_PIDFILE);
			nvram_commit();
			exitPoint = 2;
			break;
		}
	}
	cprintf("dblog:quit process, exitPoint-[%d]!\n\n", exitPoint);
	logmessage("dblog", "exitPoint=[%d]!\n", exitPoint);
	return 0;
}

