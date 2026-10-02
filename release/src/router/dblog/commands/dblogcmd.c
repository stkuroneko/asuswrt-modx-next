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

#define WAIT_RESP_TO	10

void delete_msg_q(int msqid_from_d)
{
	msgctl(msqid_from_d, IPC_RMID, NULL);
}

int main(int argc, char* argv[])
{
	int msqid_to_d=0;
	int msqid_from_d=0;
	msgbuf send_buf;
	msgbuf receive_buf;
	int cnt = WAIT_RESP_TO;

	if(argc < 2) {
		printf("Command error\n");
		return -EINVAL;
	}

	msqid_to_d = atoi(nvram_get("dblog_msqid_to_d"));

	if(msqid_to_d < 0)
	{
		printf("Message queue ID error\n");
		return -EINVAL;
	}

	if ((msqid_from_d=msgget(IPC_PRIVATE,0700))<0)
	{
		perror("msgget");
		return -1;
	}

	printf("MSQ_to_daemon : %d\n",msqid_to_d);
	printf("MSQ_from_daemon : %d\n",msqid_from_d);

	memset(&send_buf, 0, sizeof(msgbuf));
	send_buf.mtype=IPC_CLIENT_MSG_Q_ID;
	*(int*)send_buf.mtext = msqid_from_d;
	if(msgsnd(msqid_to_d, &send_buf, MAX_IPC_MSG_BUF, 0) < 0)
	{
		perror("msgsnd IPC_CLIENT_MSG_Q_ID");
		goto delete_msgq_and_quit;
	}

	// to stop timer
	send_buf.mtype=IPC_STOP_DBLOG_TIMER;
	snprintf(send_buf.mtext, sizeof(send_buf.mtext), "stoplogtimer");
	if(msgsnd(msqid_to_d, &send_buf, MAX_IPC_MSG_BUF, 0) < 0)
	{
		perror("msgsnd IPC_STOP_DBLOG_TIMER");
		goto delete_msgq_and_quit;
	}

	// wait daemon response
	cnt = WAIT_RESP_TO*6;
	while (cnt--)
	{
		if(msgrcv(msqid_from_d, &receive_buf, MAX_IPC_MSG_BUF, 0, 0) < 0)
		{
			cprintf("errno=%d\n", errno);
			cprintf("EINTR=%d\n", EINTR);
			perror("[dblogcmd]");
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				perror("msgrcv");
				break;
			}
		}
		else
		{
			break;
		}
	}

	if(cnt == 0)
	{
		return -1;
	}

	if (strcmp(argv[1],"testcommand") == 0)
	{
		printf("testcommand command\n");
		send_buf.mtype = IPC_TEST_DBLOG_COMMAND;
		strcpy(send_buf.mtext, "testcommand");
	}
	else if (strcmp(argv[1],"exit") == 0)
	{
		send_buf.mtype = IPC_EXIT_DBLOG_DAEMON;
		strcpy(send_buf.mtext, "exit");
	}
	else
	{
		printf("Unknown command\n");
		goto delete_msgq_and_quit;
	}

	if(msgsnd(msqid_to_d,&send_buf,MAX_IPC_MSG_BUF,0)<0)
	{
		perror("msgsnd");
		goto delete_msgq_and_quit;
	}

	// wait daemon response
	cnt = WAIT_RESP_TO;
	while (cnt--)
	{
		if(msgrcv(msqid_from_d,&receive_buf,MAX_IPC_MSG_BUF,0,0) < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				perror("msgrcv");
				break;
			}
		}
		else
		{
			printf(receive_buf.mtext);
			printf("\n");
			break;
		}
		sleep(1);
	}

delete_msgq_and_quit:
	delete_msg_q(msqid_from_d);

	printf("EXIT dblogcmd\n");
	return 0;

}


