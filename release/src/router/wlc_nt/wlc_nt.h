 /*
 * Copyright 2017, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#ifndef _wlc_nt_h_
#define _wlc_nt_h_

/* header */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <shutils.h>
#include <shared.h>
/* -- */
#include <libnt.h>
#include <json.h>
#include <linklist.h>

/* DEBUG DEFINE */
#define WLCNT_DEBUG             "/tmp/WLCNT_DEBUG"
#define MyDBG(fmt,args...) \
	if(f_exists(WLCNT_DEBUG) > 0) { \
		printf("[WLCNT][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}

/* wlc_nt */
#define WLCNT_PID_PATH           "/var/run/wlcnt.pid"
#define WLCNT_SOCKET_PATH        "/var/run/wlcnt_socket"
#define MAX_WLCNT_SOCKET_CLIENT  5
#define WLCNT_SPAM_ONLINE        60*2
#define WLCNT_SPAM_OFFLINE       60*1

/* WLCNT_EVENT_T */
typedef struct __wlc_notification__t_
{
	time_t tstamp;      /* Receive time    */
	char   addr[18];    /* address for MAC */
	char   ifname[18];  /* interface       */
	int    online;      /* wlc online        */
} WLCNT_EVENT_T;

typedef struct __wlc_spam__t_
{
	time_t tstamp;
	char   mac[18];
} WLC_SPAM_T;

/* wlc_nt_client.c */
extern void WLCNT_TRIGGER(char *eaddr, char *ifname, int online);

#endif /*  _wlc_nt_h_ */
