// message type
#define msgTypeDaemon 1
#define msgTypeCommand 2

#define MAX_IPC_MSG_BUF 64

typedef struct
{
    long mtype;
    char mtext[MAX_IPC_MSG_BUF];
} msgbuf;

// linux IPC number need to be greater than 1
enum {
	IPC_CLIENT_MSG_Q_ID = 1
	, IPC_STOP_DBLOG_TIMER
	, IPC_TEST_DBLOG_COMMAND
	, IPC_EXIT_DBLOG_DAEMON
};


