#include <signal.h>
#include "libsmspdu.h"


#define PULLSMS_INTERVAL 30
#define PULLSMS_SAFE_RANGE 10
#define NO_SIG -1

static char ttynode[16];
static time_t oldtime;
static int pullsms_signal;
static int old_sms_num;
static char old_sms_index[PATH_MAX];

static int pull_status(int status){
	static int run_status = PULL_IDLE;
	int old_status = run_status;
	//char *message;

	switch(status){
		case PULL_IDLE:
			//message = "Be idle...";
			break;
		case PULL_PULL:
			//message = "pull SMS";
			break;
		case PULL_FORCE_STOP:
			//message = "forcely stop";
			break;
		default:
			/* Just return previous status */
			return old_status;
	}

	/* Set new status */
	run_status = status;

	return old_status;
}

// -1: manully scan by diskmon_usbport, 1: scan the USB port 1,  2: scan the USB port 2.
static void start_pullsms(void){
	int new_sms_num;
	char new_sms_index[PATH_MAX];

	pull_status(PULL_PULL);

#if 0
	if((new_sms_num = listSMSIndex(ttynode, new_sms_index, PATH_MAX)) < 0){
		printf("Fail to get the new SMS index.\n");
		pull_status(PULL_IDLE);
		return;
	}
#else
	if((old_sms_num = getSMSPDUbyType(ttynode, 0, new_sms_index, PATH_MAX)) < 0){
		printf("Fail to get the new SMS index.\n");
		pull_status(PULL_IDLE);
		return;
	}
#endif

	if(new_sms_num == old_sms_num){
		pull_status(PULL_IDLE);
		return;
	}
	else if(new_sms_num > old_sms_num){
		printf("********** Have the new SMS!!! **********\n");
#ifdef SAVESMS
		if(getallSMSPDU(ttynode) < 0){
			printf("Fail to get the new SMS index.\n");
			pull_status(PULL_IDLE);
			return;
		}
#endif
	}

	old_sms_num = new_sms_num;
	snprintf(old_sms_index, PATH_MAX, "%s", new_sms_index);

	pull_status(PULL_IDLE);
	return;
}

static void pullsms_sighandler(int sig){
	switch(sig){
		case SIGTERM:
			printf("pullsms: Finish!\n");
			unlink("/var/run/pullsms.pid");
			pullsms_signal = sig;
			exit(0);
		case SIGUSR1:
			printf("pullsms: Get the status: %d.\n", pull_status(-1));
			pullsms_signal = sig;
			break;
		case SIGUSR2:
			pullsms_signal = sig;
			break;
		case SIGALRM:
			pullsms_signal = sig;
			break;
	}
}

int main(int argc, char *argv[]){
	FILE *fp;
	sigset_t mask;
	int ret;
	time_t now;
	struct tm local;
	int pullsms_alarm_sec;
	int diff;

	if(argc != 2 || argv[1] == NULL){
		printf("Usage: %s <TTY node> &\n", argv[0]);
		return 0;
	}

	fp = fopen("/var/run/pullsms.pid", "w");
	if(fp != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	signal(SIGTERM, pullsms_sighandler);
	signal(SIGUSR1, pullsms_sighandler);
	signal(SIGUSR2, pullsms_sighandler);
	signal(SIGALRM, pullsms_sighandler);

	sigfillset(&mask);
	sigdelset(&mask, SIGTERM);
	sigdelset(&mask, SIGUSR1);
	sigdelset(&mask, SIGUSR2);
	sigdelset(&mask, SIGALRM);

	pull_status(PULL_PULL);

	if((ret = initial_smspdu(argv[1])) < 0){
		printf("Fail to initial SMS's directory.\n");
		return 0;
	}
#ifdef SAVESMS
	if((ret = getallSMSPDU(argv[1])) < 0){
		printf("Fail to get all SMS.\n");
		return 0;
	}
#endif

	snprintf(ttynode, 16, "%s", argv[1]);
	time(&oldtime);
	pullsms_signal = NO_SIG;

	printf("pullsms: starting with %s...\n", ttynode);
#if 0
	if((old_sms_num = listSMSIndex(ttynode, old_sms_index, PATH_MAX)) < 0){
		printf("Fail to get the first SMS index.\n");
		return 0;
	}
#else
	if((old_sms_num = getSMSPDUbyType(ttynode, 0, old_sms_index, PATH_MAX)) < 0){
		printf("Fail to get the first SMS inbox.\n");
		return 0;
	}
#endif

	while(1){
		time(&now);
		localtime_r(&now, &local);

		diff = now-oldtime;
		if(pullsms_signal == SIGUSR2){
			if(diff <= PULLSMS_SAFE_RANGE){
				printf("pullsms: wait more %d seconds and avoid to pull too often.\n", PULLSMS_SAFE_RANGE+1-diff);
				pullsms_alarm_sec = PULLSMS_INTERVAL-diff;
			}
			else{
				//printf("pullsms: Pull manually...\n");
				oldtime = now;
				pullsms_alarm_sec = PULLSMS_INTERVAL;

				start_pullsms();
			}
		}
		else{
			if(pullsms_signal == SIGUSR1)
				printf("pullsms(%lu): day=%d, week=%d, time=%02d:%02d:%02d.\n", (unsigned long)now, local.tm_mday, local.tm_wday, local.tm_hour, local.tm_min, local.tm_sec);

			if(diff >= PULLSMS_INTERVAL){
				oldtime = now;
				pullsms_alarm_sec = PULLSMS_INTERVAL;

				if(pullsms_signal == SIGALRM){
					//printf("pullsms: Pull automatically...\n");
					start_pullsms();
				}
			}
			else
				pullsms_alarm_sec = PULLSMS_INTERVAL-diff;

			if(pullsms_signal == SIGUSR1)
				printf("pullsms: wait_second=%d...\n", pullsms_alarm_sec);
		}

		alarm(pullsms_alarm_sec);

		pull_status(PULL_IDLE);
		pullsms_signal = NO_SIG;
		sigsuspend(&mask);
	}

	unlink("/var/run/disk_monitor.pid");

	return 0;
}
