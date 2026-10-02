 /*
 * Copyright 2015, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */
 
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
/* -- */
#include <nt_actMail.h>
#include "mailContent.cc"
#include "mailutility.cc"

#if defined(RTCONFIG_DMALLOC)
#include <dmalloc.h>
#endif

#define MUTEX pthread_mutex_t
#define MUTEXINIT(m) pthread_mutex_init(m, NULL)
#define MUTEXLOCK(m) pthread_mutex_lock(m)
#define MUTEXTRYLOCK(m) pthread_mutex_trylock(m)
#define MUTEXUNLOCK(m) pthread_mutex_unlock(m)
#define MUTEXDESTROY(m) pthread_mutex_destroy(m)

#define MAIL_CONF               "/etc/email/email.conf"
#define RANDOM_INDEX_MAX        1000
#define SEND_MAIL_RETRY         3
#define MAIL_SENDING_TIMEOUT    60

enum {
	OFF=0,
	ON
};


/* Global */
static MUTEX event_list_lock;
struct list *event_list=NULL;
static int RECVSIG = 0;
static int terminated = 1;
static int rec_cnt = 0;
static int rIndex[RANDOM_INDEX_MAX];

/* Declare and Define int type shuffle function from macro */
int irand(int n);
DECL_SHUFFLE(int);

/* Declare Function Pointer Prototype */
MAIL_INFO_T *(*MailContentFunc) (MAIL_INFO_T *);

MAIL_INFO_T *E_MInfo = NULL;

/* Declare Hash Table */
hashtable_t *HT;

char *GetMailContInfo(char *key)
{
	return (char *)ht_get(HT, key);
}

void SetMailContInfo(char *key, char *val)
{
	ht_put(HT, key, val);
}


void CollectSendMailInfo(void)
{
	char path[STRLEN];
	char buf[STRLEN];
	int i;
	
	for(i=0; KeyNameInfo[i].keyName != 0; i++) {
		snprintf(path, sizeof(path), MAIL_ITEM_PATH"/%s", KeyNameInfo[i].keyName);
		if (f_read_string(path, buf, sizeof(path)) > 0) {
			SetMailContInfo(KeyNameInfo[i].keyName, xstrdup(buf));
		} else {
			SetMailContInfo(KeyNameInfo[i].keyName, KeyNameInfo[i].keyName);
		}
		
	}
}
void UpdateSendMailInfo(void)
{
	ht_destroy(HT);
	HT = ht_create(1024);
	MyDBG("Update SendMailInfo from System\n");
	CollectSendMailInfo();
	RECVSIG = OFF;
	
}

/* random integer from 0 to n-1 */
int irand(int n)
{
	int r, rand_max = RAND_MAX - (RAND_MAX % n);
	/* reroll until r falls in a range that can be evenly
	 * distributed in n bins.  Unless n is comparable to
	 * to RAND_MAX, it's not *that* important really. */
	srand(time(NULL));
	while ((r = rand()) >= rand_max);
	return r / (rand_max / n);
}
 
static void CreateRandomIndex(void) 
{
	int i;
	for(i=0; i < RANDOM_INDEX_MAX; i++) {
		rIndex[i] = rand() % RANDOM_INDEX_MAX;
	}
	shuffle_int(rIndex, RANDOM_INDEX_MAX);
}

static int eMail_get_pFunc(int e)
{
	int i;
	int en = -1;
	
	MailContentFunc = NULL;
	
	for(i=0; CONTENT_TABLE[i].event != 0; i++) {
		if( CONTENT_TABLE[i].event == e) {
			if(!strcmp(CONTENT_TABLE[i].lang, "EN")) {
				en = i;
			}
			if(!strcmp(CONTENT_TABLE[i].lang, GetMailContInfo(SYSTEM_LANGUAGE))) {
				MailContentFunc = (void *)CONTENT_TABLE[i].MailContentFunc;
				return i;
			} 
		}
	}
	/* Set Default */
	if(en >= 0) {
		MyDBG("[WARNING] Mail Content CANT support specify language, Using default language EN.\n");
		MailContentFunc = (void *)CONTENT_TABLE[en].MailContentFunc;
		return en;
	}
	
	return -1;
}

static char *GetMailAccount()
{
	FILE *fp;
	char *np;
	char cmd[128];
	char *val;
	
	val = malloc(sizeof(cmd));
	memset(cmd, 0, sizeof(cmd));
	memset(val, 0, sizeof(cmd));
	
	snprintf(cmd, sizeof(cmd), "cat %s | grep \"MY_EMAIL\" | awk -F \"'\" '{printf$2}'", MAIL_CONF);
	fp = popen(cmd, "r");
	if(fp) {
		fgets(val,sizeof(cmd) ,fp);
		pclose(fp);
		np = strrchr(val,'\n');
		if (np) *np='\0';
		return val;
	} else {
		free(val);
		return NULL;
	}
}

void send_mail(void *mInfo)
{
	pthread_detach(pthread_self());
	
	char *mAct = NULL;
	
	MAIL_INFO_T *mData = mInfo;
	
	/* Get Mail Account */
	mAct = GetMailAccount();
	if(mAct == NULL) {
		ErrorMsg("Error: Cant get email account from %s\n", MAIL_CONF);
		goto releaseMem;
	} else {
		if(!strcmp(GetMailContInfo(MAIL_TO), "MailTo")) {
			snprintf(mData->toMail, sizeof(mData->toMail), "%s", mAct);
		} else {
			snprintf(mData->toMail, sizeof(mData->toMail), "%s,%s", mAct, GetMailContInfo(MAIL_TO));
		}
	}
	
	/* Get Device Model Name */
	snprintf(mData->modelName, sizeof(mData->modelName), "%s", GetMailContInfo(MODEL_NAME));
	
	/* Set Mail Default Subject Info */
	strncpy(mData->subject, "Notification", sizeof(mData->subject)-1);
	
	/* Get Mail Content Callback Func */
	if(eMail_get_pFunc(mData->event) == -1) {
		ErrorMsg("Error: Cant get MailContentFunc pointer from CONTENT_TABLE \n");
		goto releaseMem;
	}
	
	/* Exec Send Mail Callback Func */
	MailContentFunc(mData);
	
releaseMem:
	if (mAct) free(mAct);
	if (mData) free(mData);

	pthread_exit(NULL);
}

static void send_mail_thread(void *mInfo)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start Send Mail thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&send_mail, mInfo);
}

static void update_event_status(int index, MAIL_STATUS_T act)
{
	NOTIFY_EVENT_T *listevent;
	struct listnode *ln;
	int chk = 0;
	
	MUTEXLOCK(&event_list_lock);
	LIST_LOOP(event_list,listevent,ln)
	{
		if(listevent->mail_t.MsendId == index) {
			if(act == MAIL_SUCCESS) {
				MyDBG("[UPDATE] EVENT:[%x] SENDID:[%d] Send successful, remove it.\n",
				      listevent->event, listevent->mail_t.MsendId);
				chk = 1;
				break;
			} else if (act == MAIL_FATAL_ERROR) {
				ErrorMsg("[WARNING] EVENT:[%x] Occur fatal error via email, remove it.\n", listevent->event);
				chk = 1;
				break;
				
			} else if (act == MAIL_FAILED) {
				if(listevent->mail_t.Mretry < SEND_MAIL_RETRY) {
					listevent->mail_t.MsendStatus = MAIL_WAIT;
					MyDBG("[UPDATE] EVENT:[%x] SENDID:[%d] Send Failed, RETRY:[%d]\n",
					      listevent->event, listevent->mail_t.MsendId, listevent->mail_t.Mretry);
				} else {
					chk = 1;
					MyDBG("[UPDATE] EVENT:[%x] SENDID:[%d] Arrive max retry time, remove it.\n",
					      listevent->event, listevent->mail_t.MsendId);
					break;
				}
				
			} else {
				MyDBG("[UPDATE] EVENT:[%x] SENDID:[%d] STATUS FROM:[%d] change to [%d]\n", 
				       listevent->event, listevent->mail_t.MsendId, listevent->mail_t.MsendStatus, act);
				listevent->mail_t.MsendStatus = act;
				break;
			}
		}
	}
	
	if( chk && (act >= MAIL_SUCCESS) ) {
		listnode_delete(event_list, listevent);
	}
	
	MUTEXUNLOCK(&event_list_lock);

}

NOTIFY_EVENT_T *event_listcreate(NOTIFY_EVENT_T input)
{
	NOTIFY_EVENT_T *new=malloc(sizeof(*new));
	
	memcpy(new,&input,sizeof(*new));
	return new;
}

void receive_s(int newsockfd)
{
	int    n;
	time_t now;
	char   date[30];
	NOTIFY_EVENT_T event_t;
	NOTIFY_EVENT_T *sevent_t;
	
	bzero(&event_t,sizeof(NOTIFY_EVENT_T));
	
	n = read( newsockfd, &event_t, sizeof(NOTIFY_EVENT_T));
	if( n < 0 )
	{
		MyDBG("ERROR reading from socket.\n");
		return;
	}
	
	event_t.tstamp = time(&now);
	StampToDate(event_t.tstamp, date);
	
	/* If receive RESERVATION of send mail status 
	 * from email daemon, then update event_list status */
	if( event_t.event == RESERVATION_MAIL_REPORT_EVENT ) {
		MyDBG("[%s] REPORT_EVENT:[%s (%x)] SENDID:[%d] STATUS:[%d]\n", 
		      date, eInfo_get_eName(event_t.event), event_t.event, event_t.mail_t.MsendId, event_t.mail_t.MsendStatus);
		update_event_status(event_t.mail_t.MsendId, event_t.mail_t.MsendStatus);
		return;
	}
	
	/* Cycle of RANDOM_INDEX_MAX */
	if(rec_cnt == RANDOM_INDEX_MAX) {
		rec_cnt = 0;
	}
	
	event_t.mail_t.MsendId = rIndex[++rec_cnt];
	event_t.mail_t.MsendStatus = MAIL_WAIT;
	event_t.mail_t.Mretry = 0;
	
	MyDBG("[%s] event:[%s (%x)] sendId:[%d] msg:[%s] Num:[%d]\n", 
	      date, eInfo_get_eName(event_t.event), event_t.event, event_t.mail_t.MsendId, event_t.msg, rec_cnt);
	
	if(GetDebugValue(NOTIFY_ACTION_MAIL_DEBUG)) {
		char info[200];
		snprintf(info, sizeof(info), "echo \"[Notification_Center ActMail][receive event] [%s] event:[%s (%x)] msg:[%s] Num:[%d]\" >> %s", 
			date, eInfo_get_eName(event_t.event), event_t.event, event_t.msg, rec_cnt, NOTIFY_ACTION_MAIL_LOG_FILE);
		system(info);
	}
	
	MUTEXLOCK(&event_list_lock);
	if(event_list) {
		sevent_t=NULL;
		sevent_t=event_listcreate(event_t);
		if(sevent_t)
			listnode_add(event_list,(void*)sevent_t);
	
	}
	MUTEXUNLOCK(&event_list_lock);
	
}
static int start_local_socket(void)
{
	struct sockaddr_un addr;
	int sockfd, newsockfd;
	
	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ErrorMsg("socket error\n");
		perror("socket error");
		exit(-1);
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, NOTIFY_MAIL_SERVICE_SOCKET_PATH, sizeof(addr.sun_path)-1);
	
	unlink(NOTIFY_MAIL_SERVICE_SOCKET_PATH);
	
	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		ErrorMsg("socket bind error\n");
		perror("socket bind error");
		exit(-1);
	}
	
	if (listen(sockfd, MAX_NOTIFY_SOCKET_CLIENT) == -1) {
		ErrorMsg("listen error\n");
		perror("listen error");
		exit(-1);
	}
	
	while (1) {
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			ErrorMsg("accept error\n");
			perror("accept error");
			continue;
		}
		
		receive_s(newsockfd);
		close(newsockfd);
	}
}
	
static void local_socket_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start unix socket thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&start_local_socket, NULL);
	pthread_attr_destroy(&attr);
}

static void do_event_check(void)
{
	NOTIFY_EVENT_T *listevent;
	struct listnode *ln;
	time_t now;
	int    del = 0;
	
	MUTEXLOCK(&event_list_lock);
	LIST_LOOP(event_list,listevent,ln)
	{
		/* To prevent email daemon unknown or not expected error/crash 
		 * cause have not send REPORT EVENT back. 
		 * If event status keep MAIL_SENDING over TIMEOUT time 
		 * will mail again until arrive RETRY setting */
		if( listevent->mail_t.MsendStatus == MAIL_SENDING) {
			if( (time(&now) - listevent->mail_t.MsendTime) >= MAIL_SENDING_TIMEOUT ) {
				listevent->mail_t.MsendStatus = MAIL_WAIT;
				MyDBG("EVENT:[%x] MSG:[%s] SENDID:[%d] Sending time over %ds, do retry part [%d].\n",
				      listevent->event , listevent->msg, listevent->mail_t.MsendId, 
				      MAIL_SENDING_TIMEOUT,listevent->mail_t.Mretry);
			}
			if( (time(&now) - listevent->mail_t.MsendTime) >= MAIL_SENDING_TIMEOUT && 
			    listevent->mail_t.Mretry >= SEND_MAIL_RETRY) {
				MyDBG("EVENT:[%x] MSG:[%s] SENDID:[%d] Sending timeout and arrive MAX retry, drop it.\n",
				      listevent->event , listevent->msg, listevent->mail_t.MsendId); 
				del = 1;
				break;
			}
		}
	}
	
	if (del) listnode_delete(event_list, listevent);
	MUTEXUNLOCK(&event_list_lock);
}

static void process_event(void)
{
	NOTIFY_EVENT_T *listevent;
	struct listnode *ln;
	time_t now;
	
	MUTEXLOCK(&event_list_lock);
	LIST_LOOP(event_list,listevent,ln)
	{
		MyDBG("EVENT:[%x] MSG:[%s] SENDID:[%d] STATUS:[%d]\n", 
		      listevent->event , listevent->msg, listevent->mail_t.MsendId, listevent->mail_t.MsendStatus);
		if( listevent->mail_t.MsendStatus == MAIL_SENDING) {
			if( (time(&now) - listevent->mail_t.MsendTime) >= MAIL_SENDING_TIMEOUT ) {
				listevent->mail_t.MsendStatus = MAIL_WAIT;
				MyDBG("EVENT:[%x] MSG:[%s] SENDID:[%d] Sending time over %ds, do retry.\n",
				      listevent->event , listevent->msg, listevent->mail_t.MsendId, MAIL_SENDING_TIMEOUT);
			}
		}
		if( listevent->mail_t.MsendStatus == MAIL_WAIT ) {
			E_MInfo = malloc(sizeof(MAIL_INFO_T));
			if(E_MInfo == NULL) {
				ErrorMsg("Error, E_MInfo malloc error.");
				MUTEXUNLOCK(&event_list_lock);
				return;
			}
			/* Put data into MAIL_INFO_T */
			memset(E_MInfo, 0, sizeof(MAIL_INFO_T));
			E_MInfo->event = listevent->event;
			E_MInfo->tstamp = listevent->tstamp;
			strncpy(E_MInfo->msg, listevent->msg, sizeof(E_MInfo->msg)-1);
			E_MInfo->MsendId = listevent->mail_t.MsendId;
			/* Check Mail Config */
			if(!isFileExist(MAIL_CONF)) {
				ErrorMsg("Error: %s not found.\n", MAIL_CONF);
				break;
			}
			/* Change  Status */
			listevent->mail_t.Mretry += 1;
			listevent->mail_t.MsendStatus = MAIL_SENDING;
			listevent->mail_t.MsendTime = time(&now);
			send_mail_thread((void *)E_MInfo);
			break;
		}
	}
	
	MUTEXUNLOCK(&event_list_lock);
}
static void event_handler()
{
	if(RECVSIG) {
		UpdateSendMailInfo();
		return;
	}
	/* Check Event List */
	do_event_check();
	
	/* Event Process 
	 * 1. Process status in MAIL_WAIT event
	 * 2. If status in MAIL_FAILED, do retry */
	process_event();
	
	 /* TODO:Network check. */
	
}

static void handlesignal(int signum)
{
	if (signum == SIGUSR1) {
		//TODO: update event switch structure
		;
	} else if (signum == SIGUSR2) {
		/* Update System Info */
		RECVSIG = ON;
	} else if (signum == SIGTERM) {
		terminated = 0;
	} else
		MyDBG("Unknown SIGNAL\n");
	
}

static void signal_register(void) {
	
	struct sigaction sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handlesignal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);    
}

int  main(void)
{
	char pid[8];
	
	MyDBG("[Start Notification_Center ActMail]\n");
	
	/* write pid */
	snprintf(pid, sizeof(pid), "%d", getpid());
	f_write_string(NOTIFY_ACTION_MAIL_PID_PATH, pid, 0, 0);
	
	/* Signal */
	signal_register();
	
	/* Init hash table & Collect Info */
	HT = ht_create(1024);
	CollectSendMailInfo();
	
	/* start unix socket */
	local_socket_thread();
	
	/* record event info*/
	event_list=list_new();
	
	/* init mutex lock switch */
	MUTEXINIT(&event_list_lock);
	
	/* Generate Random Index */
	CreateRandomIndex();
	
	while(terminated) {
		event_handler();
		sleep(5);
	}
	
	/* free memory */
	MUTEXDESTROY(&event_list_lock);
	ht_destroy(HT);
	
	MyDBG("Notification_Center ActMail Terminated\n");
	
	return 0;
}
