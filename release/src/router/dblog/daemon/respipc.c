//
// programming note for router SOC
// DO NOT USE fscanf/fprintf
//

//
// if autodetect enabled, adsl status polling MUST be disabled (no timer function)
// This is because multiple send and wait resp is not allowed
//


#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <shared.h>

#include "../msg_define.h"

extern int wait_for_semaphore(void);
extern void enable_logging(void);
extern void disable_logging(void);
extern int DumpLogRecord(void);
extern int DumpLogRecord_detail(void);

static int m_msqid_to_d = 0;
static int m_msqid_from_d = 0;

// sync variables
volatile int m_start_polling=0;
volatile int m_stop_polling_ok=0;
volatile int m_req_auto_det_pvc=0;

int test_command(void)
{
	cprintf("this is test command\n");

	return 0;
}

int CreateMsgQ(void)
{
// create IPC
// dblogcmd <-> dblog daemon
	int ret_val = 0;
	char strQid[32] = {0};

	if ((m_msqid_to_d=msgget(IPC_PRIVATE,0700))<0)
	{
		cprintf("msgget err\n");
		return -1;
	}
	else
	{
		cprintf("msgget ok, [%d]\n", m_msqid_to_d);
	}
	snprintf(strQid, sizeof(strQid), "%d", m_msqid_to_d);
	nvram_set("dblog_msqid_to_d", strQid);
	return ret_val;
}

int RcvMsgQ(void)
{
	int infolen;
	int bAskQuit = 0;
	msgbuf send_buf;
	msgbuf receive_buf;
	int bSendResp = 1;

	memset(&send_buf, 0, sizeof(msgbuf));
	memset(&receive_buf, 0, sizeof(msgbuf));

	if((infolen=msgrcv(m_msqid_to_d, &receive_buf, MAX_IPC_MSG_BUF, 0, 0))<0)
	{
		if (errno == EINTR)
		{
			return 0;
		}
		else
		{
			cprintf("dblog:msgrcv2::%d\n", errno);
			return -1;
		}
	}
	else
	{
		if (IPC_CLIENT_MSG_Q_ID == receive_buf.mtype)
		{
			int* pInt;

			pInt=(int*)(&receive_buf.mtext[0]);
			m_msqid_from_d = *pInt;
			cprintf("dblog:IPC_CLIENT_MSG_Q_ID=[%d]\n", m_msqid_from_d);
			bSendResp = 0;
		}
		else if (IPC_STOP_DBLOG_TIMER == receive_buf.mtype)
		{
			int ret;

			ret = wait_for_semaphore();
			send_buf.mtype=IPC_STOP_DBLOG_TIMER;
			if(ret)
				snprintf(send_buf.mtext, sizeof(send_buf.mtext), "Fail");
			else
				snprintf(send_buf.mtext, sizeof(send_buf.mtext), "Done");
		}
		else if (IPC_TEST_DBLOG_COMMAND == receive_buf.mtype)
		{
			int ret;

			ret = test_command();
			send_buf.mtype=IPC_TEST_DBLOG_COMMAND;
			if(ret)
				snprintf(send_buf.mtext, sizeof(send_buf.mtext), "Fail");
			else
				snprintf(send_buf.mtext, sizeof(send_buf.mtext), "Done");
		}
		else if (IPC_EXIT_DBLOG_DAEMON == receive_buf.mtype)
		{
			cprintf("dblog:IPC_EXIT_DAEMON\n");
			send_buf.mtype=IPC_EXIT_DBLOG_DAEMON;
			snprintf(send_buf.mtext, sizeof(send_buf.mtext), "Done");
		}

		if (bSendResp)
		{
			if(msgsnd(m_msqid_from_d, &send_buf, MAX_IPC_MSG_BUF, 0)<0)
			{
				cprintf("TP_INIT:msgsnd fail %s\n", strerror(errno));
				return -1;
			}
			if (IPC_EXIT_DBLOG_DAEMON == receive_buf.mtype)
			{
				if(msgctl(m_msqid_to_d, IPC_RMID, NULL) == 0)
				{
					bAskQuit = 1;
					cprintf("bAskQuit = 1\n");
				}
				else
				{
					perror("IPC_RMID:");
					exit(1);
				}
			}
		}
	}

	if (bAskQuit == 1) return 1;
	return 0;
}

