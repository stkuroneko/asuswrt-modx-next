/*************************

	dblog.h
	Copyright (C) 2017

*************************/
#ifndef __DBLOG_H__
#define __DBLOG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <stdint.h>
#include <syslog.h>
#include <shutils.h>
#include <shared.h>

enum {
	DBLOG_STATE_INIT = 0
	,DBLOG_STATE_RUN = 1
	,DBLOG_STATE_REBOOT = 2
	,DBLOG_STATE_PAUSE = 3
	,DBLOG_STATE_STOP = 4
	,DBLOG_STATE_FINISH = 5
	,DBLOG_STATE_SENDMAIL_SUCCESS
	,DBLOG_STATE_SENDMAIL_FAIL_SMTP
	,DBLOG_STATE_SENDMAIL_FAIL_DISK_SPACE
	,DBLOG_STATE_SENDMAIL_FAIL_OTHER
	,DBLOG_STATE_ERR_USB
	,DBLOG_STATE_ERR_OTHERS
};

extern int m_Exit;


/***** dblog.c *****/
void killall_tk(const char *name);
void pause_logging(void);
void quit_process(void);
int timerTrigger_re(unsigned int first_seconds, unsigned int interval, void (*func)(int signo));

/***** dblog_syslog.c *****/
void backup_syslog(void);

/***** dblog_wifi.c *****/
void monitor_wifilog(void);
void enable_wifilog(void);
void disable_wifilog(void);
void backup_wifilog(void);
#ifdef RTCONFIG_HND_ROUTER
void monitor_dhdlog(void);
void enable_dhdlog(void);
void disable_dhdlog(void);
void backup_dhdlog(void);
#endif /* RTCONFIG_HND_ROUTER */


/***** dblog_dm.c *****/
void monitor_dmlog(void);
void enable_dmlog(void);
void disable_dmlog(void);
void backup_dmlog(void);


/***** dblog_ms.c *****/
void init_mslog(void);
void monitor_mslog(void);
void enable_mslog(void);
void disable_mslog(void);
void backup_mslog(void);


/***** dblog_amas.c *****/
void monitor_amaslog(void);
void enable_amaslog(void);
void disable_amaslog(void);
void backup_amaslog(void);

#endif /* __DBLOG_H__ */
