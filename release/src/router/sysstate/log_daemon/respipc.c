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
static unsigned int m_Cnt = 0;

// sync variables
volatile int m_start_polling=0;
volatile int m_stop_polling_ok=0;
volatile int m_req_auto_det_pvc=0;

int test_command(void)
{
	cprintf("this is test command\n");

	return 0;
}

void enable_polling(void)
{
	m_req_auto_det_pvc = 0;
	m_start_polling = 1;
}

void disable_polling(void)
{
	m_req_auto_det_pvc = 1;
}

void wait_polling_stop(void)
{
	while (1)
	{
		if (m_stop_polling_ok == 1)
		{
			break;
		}
		usleep(10*1000);
	}
	m_stop_polling_ok = 0;
}


void polling_tc_info(int signo)
{
	if (m_req_auto_det_pvc)
	{
		m_start_polling = 0;
		m_stop_polling_ok = 1;
	}
	else
	{
		if (m_start_polling)
		{
			if( !(m_Cnt%10) )	//every 10 sec
			{
				cprintf("polling_tc_info\n");
			}
		}
	}

    m_Cnt++;
}

int CreateMsgQ(void)
{
// create IPC
// asuslog <-> sysstate
	int ret_val = 0;
	char strQid[32] = {0};

	if ((m_msqid_to_d=msgget(IPC_PRIVATE,0700))<0)
	{
		cprintf("msgget err\n");
		return -1;
	}
	else
	{
		cprintf("msgget ok\n");
	}
	snprintf(strQid, sizeof(strQid), "%d", m_msqid_to_d);
	nvram_set("sysstate_msqid_to_d", strQid);
	return ret_val;
}

int RcvMsgQ(void)
{
	int infolen;
	int bAskQuit = 0;
	msgbuf send_buf;
	msgbuf receive_buf;
	int bSendResp = 1;
	int bEnablelog = 1;

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
			cprintf("sysstate:msgrcv2::%d\n", errno);
			return -1;
		}
	}
	else
	{
		if (IPC_CLIENT_MSG_Q_ID == receive_buf.mtype)
		{
			int* pInt;

			disable_logging();

			pInt=(int*)(&receive_buf.mtext[0]);
			m_msqid_from_d = *pInt;
			cprintf("sysstate:IPC_CLIENT_MSG_Q_ID=[%d]\n", m_msqid_from_d);
			bSendResp = 0;
			bEnablelog = 0;
		}
		else if (IPC_STOP_LOG_TIMER == receive_buf.mtype)
		{
			int ret;

			ret = wait_for_semaphore();
			send_buf.mtype=IPC_STOP_LOG_TIMER;
			if(ret)
				strcpy(send_buf.mtext, "FAIL");
			else
				strcpy(send_buf.mtext, "Done");
			bEnablelog = 0;
		}
		else if (IPC_DUMP_LOG_RECORD == receive_buf.mtype)
		{
			int ret;

			ret = DumpLogRecord();
			send_buf.mtype=IPC_DUMP_LOG_RECORD;
			if(ret)
				strcpy(send_buf.mtext, "FAIL");
			else
				strcpy(send_buf.mtext, "Done");
		}
		else if (IPC_DUMP_DETAIL_RECORD == receive_buf.mtype)
		{
			int ret;

			ret = DumpLogRecord_detail();
			send_buf.mtype=IPC_DUMP_LOG_RECORD;
			if(ret)
				strcpy(send_buf.mtext, "FAIL");
			else
				strcpy(send_buf.mtext, "Done");
		}
		else if (IPC_TEST_COMMAND == receive_buf.mtype)
		{
			int ret;

			ret = test_command();
			send_buf.mtype=IPC_TEST_COMMAND;
			if(ret)
				strcpy(send_buf.mtext, "FAIL");
			else
				strcpy(send_buf.mtext, "Done");
		}
		else if (IPC_EXIT_DAEMON == receive_buf.mtype)
		{
			cprintf("sysstate:IPC_EXIT_DAEMON\n");
			send_buf.mtype=IPC_EXIT_DAEMON;
			strcpy(send_buf.mtext, "Done");
		}

		if(bEnablelog)
		{
			enable_logging();
		}

		if (bSendResp)
		{
			if(msgsnd(m_msqid_from_d, &send_buf, MAX_IPC_MSG_BUF, 0)<0)
			{
				cprintf("TP_INIT:msgsnd fail %s\n", strerror(errno));
				return -1;
			}
			if (IPC_EXIT_DAEMON == receive_buf.mtype)
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

