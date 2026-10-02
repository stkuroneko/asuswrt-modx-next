#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <libnt.h>
#include <pthread.h>

#define NORMAL_STATUS_INTERVAL  10
#define NULL_STATUS_INTERVAL    60
#define ONCE_CHECK_INTERVAL     1

#ifdef CONFIG_LINUX3X_OR_4X
/* For LINUX KERNEL 3.14.x and later Process Num */
#define NTC_DAEMON_NUM  1
#define NAM_DAEMON_NUM  1
#else
#define NTC_DAEMON_NUM  3
#define NAM_DAEMON_NUM  3
#endif


#define MyDBG(fmt,args...) \
	if(isFileExist(NOTIFY_CENTER_MONITOR_DEBUG) > 0) { \
		Debug2Console("[NTMONITOR][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}
#define ErrorMsg(fmt,args...) \
	Debug2Console("[NTMONITER][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args);

typedef enum {
	STATUS_NULL = 0,
	STATUS_NORMAL,
	STATUS_RESTART,
	STATUS_RESTARTING,
	STATUS_STOP,
	STATUS_ERROR
} NTM_STATUS_T;

typedef enum {
	SIG_NULL = 0,
	SIG_RESTART,
	SIG_STOP
} NTM_SIG_T;

NTM_SIG_T m_sig     = SIG_NULL; /* Notification Center */
NTM_SIG_T m_nam_sig = SIG_NULL; /* Notification ActMail */
NTM_STATUS_T m_status     = STATUS_RESTART ;
NTM_STATUS_T m_nam_status = STATUS_RESTART ;

static int run = 1;
static int miss_count = 0; 
static int miss_nam_count = 0;

static int CTRL_SEC = NORMAL_STATUS_INTERVAL;
static int NTC_TERM = 1;
static int NAM_TERM = 1;

static void handlesignal(int signum) 
{
	if (signum == SIGUSR1)
	{
		m_sig = SIG_RESTART;
		m_nam_sig = SIG_RESTART;
		CTRL_SEC = ONCE_CHECK_INTERVAL; /* need check status immeditaely */
	} else if (signum == SIGUSR2) {
		m_sig = SIG_STOP;
		m_nam_sig = SIG_STOP;
		CTRL_SEC = ONCE_CHECK_INTERVAL; /* need check status immeditaely */
	} else if (signum == SIGTERM) {
		run  = 0;
	} else
		printf("Unknown SIGNAL\n");
}

static void signal_register(void) {
	struct sigaction sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handlesignal;
	sigaction(SIGUSR1, &sa, NULL); /* restart */
	sigaction(SIGUSR2, &sa, NULL); /* stop    */
	sigaction(SIGTERM, &sa, NULL); /* terminate */
}

static void generate_pid_file()
{
	FILE *fp;
	
	fp = fopen(NOTIFY_CENTER_MONITOR_PID_PATH, "wt");
	if (fp) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}
}

static void start_ntc_monitor(void)
{
	do
	{
		MyDBG("[NTC] Daemon Num :[%d]\n", get_pid_num_by_name("nt_center"));
		if (m_status == STATUS_RESTART)
		{
			/* just in case, kill nt_center again */
			if (get_pid_num_by_name("nt_center") > 0)
			{
				system("killall nt_center");
				usleep(5000);
				MyDBG("KILL AGAIN\n");
				continue;
			}
			
			system("nt_center &");
			
			MyDBG("[NTC] STATUS CHANGE TO : [STATUS_RESTARTING]\n");
			m_status = STATUS_RESTARTING;
			miss_count = 0;
			continue;
		}
		else if (m_status == STATUS_RESTARTING)
		{
			if (get_pid_num_by_name("nt_center") < NTC_DAEMON_NUM)
			{
				/* something wrong, restart again */
				if (miss_count == 2)
				{
					system("killall nt_center");
					sleep(1);
					MyDBG("[NTC] STATUS CHANGE TO : [STATUS_RESTART]\n");
					m_status = STATUS_RESTART;
					miss_count = 0;
				}
				else  /* if it's in restarting status, wait 2 seconds before we try to restart again */
				{
					miss_count++;
					MyDBG("[NTC] RETRY CNT:[%d]\n", miss_count);
					sleep(2);
					continue;
				}
			}
			else
			{
				MyDBG("[NTC] STATUS CHANGE TO : [STATUS_NORMAL]\n");
				m_status = STATUS_NORMAL;
				miss_count = 0;
				CTRL_SEC = NORMAL_STATUS_INTERVAL;
			}
		}
		else if (m_status == STATUS_STOP)
		{
			MyDBG("[NTC] PRECESSING : [STATUS_STOP]\n");
			system("killall nt_center");
			sleep(1);
			m_status = STATUS_NULL;
		}
		else if (m_status == STATUS_ERROR)
		{
			MyDBG("[NTC] PRECESSING : [STATUS_ERROR]\n");
			system("killall nt_center");
			sleep(1);
			MyDBG("[NTC] STATUS CHANGE TO : [STATUS_RESTART]\n");
			m_status = STATUS_RESTART;
			continue;
		}
		else if (m_status == STATUS_NULL)
		{
			MyDBG("[NTC] PRECESSING : [STATUS_NULL]\n");
		
		}
		else  /* STATUS_NORMAL */
		{
			if (get_pid_num_by_name("nt_center") < NTC_DAEMON_NUM)
			{
				m_status = STATUS_ERROR;
				MyDBG("[NTC] STATUS CHANGE TO : [STATUS_ERROR]\n");
				ErrorMsg("[NTC][Error] Number of errors Process, Try to restart.\n");
				continue;
			}
		}
		
		// Check signal
		if (m_sig == SIG_RESTART)
		{
			system("killall nt_center");
			m_status = STATUS_RESTART;
			MyDBG("[NTC][SIG] STATUS CHANGE TO : [STATUS_RESTART]\n");
			m_sig = SIG_NULL;
			sleep(1);
		}
		else if (m_sig == SIG_STOP)
		{
			m_status = STATUS_STOP;
			MyDBG("[NTC][SIG] STATUS CHANGE TO : [STATUS_STOP]\n");
			m_sig = SIG_NULL;
		}
		
		sleep(CTRL_SEC);
	}while(NTC_TERM);
}

static void start_nam_monitor(void)
{
	do
	{
		MyDBG("[NAM] Daemon Num :[%d]\n", get_pid_num_by_name("nt_actMail"));
		if (m_nam_status == STATUS_RESTART)
		{
			/* just in case, kill nt_actMail again */
			if (get_pid_num_by_name("nt_actMail") > 0)
			{
				system("killall nt_actMail");
				usleep(5000);
				MyDBG("KILL AGAIN\n");
				continue;
			}
			
			system("nt_actMail &");
			
			MyDBG("[NAM] STATUS CHANGE TO : [STATUS_RESTARTING]\n");
			m_nam_status = STATUS_RESTARTING;
			miss_nam_count = 0;
			continue;
		}
		else if (m_nam_status == STATUS_RESTARTING)
		{
			if (get_pid_num_by_name("nt_actMail") < NAM_DAEMON_NUM)
			{
				/* something wrong, restart again */
				if (miss_nam_count == 2)
				{
					system("killall nt_actMail");
					sleep(1);
					MyDBG("[NAM] STATUS CHANGE TO : [STATUS_RESTART]\n");
					m_nam_status = STATUS_RESTART;
					miss_nam_count = 0;
				}
				else  /* if it's in restarting status, wait 2 seconds before we try to restart again */
				{
					miss_nam_count++;
					MyDBG("[NAM] RETRY CNT:[%d]\n", miss_nam_count);
					sleep(2);
					continue;
				}
			}
			else
			{
				MyDBG("[NAM] STATUS CHANGE TO : [STATUS_NORMAL]\n");
				m_nam_status = STATUS_NORMAL;
				miss_nam_count = 0;
				CTRL_SEC = NORMAL_STATUS_INTERVAL;
			}
		}
		else if (m_nam_status == STATUS_STOP)
		{
			MyDBG("[NAM] PRECESSING : [STATUS_STOP]\n");
			system("killall nt_actMail");
			sleep(1);
			m_nam_status = STATUS_NULL;
		}
		else if (m_nam_status == STATUS_ERROR)
		{
			MyDBG("[NAM] PRECESSING : [STATUS_ERROR]\n");
			system("killall nt_actMail");
			sleep(1);
			MyDBG("[NAM] STATUS CHANGE TO : [STATUS_RESTART]\n");
			m_nam_status = STATUS_RESTART;
			continue;
		}
		else if (m_nam_status == STATUS_NULL)
		{
			MyDBG("[NAM] PRECESSING : [STATUS_NULL]\n");
		
		}
		else  /* STATUS_NORMAL */
		{
			if (get_pid_num_by_name("nt_actMail") < NAM_DAEMON_NUM)
			{
				m_nam_status = STATUS_ERROR;
				MyDBG("[NAM] STATUS CHANGE TO : [STATUS_ERROR]\n");
				ErrorMsg("[NAM][Error] Number of errors Process, Try to restart.\n");
				continue;
			}
		}
		
		// Check signal
		if (m_nam_sig == SIG_RESTART)
		{
			system("killall nt_actMail");
			m_nam_status = STATUS_RESTART;
			MyDBG("[NAM][SIG] STATUS CHANGE TO : [STATUS_RESTART]\n");
			m_nam_sig = SIG_NULL;
			sleep(1);
		}
		else if (m_nam_sig == SIG_STOP)
		{
			m_nam_status = STATUS_STOP;
			MyDBG("[NAM][SIG] STATUS CHANGE TO : [STATUS_STOP]\n");
			m_nam_sig = SIG_NULL;
		}
		
		sleep(CTRL_SEC);
	}while(NAM_TERM);
}

static void monitor_nam_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start monitor NAM thread.\n");
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&start_nam_monitor, NULL);
	pthread_attr_destroy(&attr);
}

static void monitor_ntc_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start monitor NTC thread.\n");
	
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&start_ntc_monitor, NULL);
	pthread_attr_destroy(&attr);
}

int main(int argc, char* argv[])
{
	/* write pid */
	generate_pid_file();
	
	/* Signal */
	signal_register();
	
	/* start monitor thread */
	monitor_ntc_thread();
	
	/* Fix got Aborted/Segmentation fault error when create multithread */
	sleep(1);
	
	monitor_nam_thread();
	
	while(run) {
		sleep(1);
	}
	
	MyDBG("Notification_Center Monitor Terminated\n");
	
	return 0;
}

