#include <pthread.h>

static void* tcp_server_start(void* arg);
int tcp_server_run ();
int tcp_server_stop(int listen_fd);

typedef struct srv_thread_info {
	pthread_t	thread_id;
	int			thread_num;
	char*		filename;
	int			srv_sockfd;
	int			thr_terminate;
}SRV_THREAD_INFO, *PSRV_THREAD_INFO;

typedef struct cl_thread_info{
	pthread_t	thread_id;
	int			server_accept_sock;
}CL_THR_INFO, *PCL_THR_INFO;

//SRV_THREAD_INFO				Srv_info;
//CL_THR_INFO						client_thread_info;


int stop_tcp_server_thread();
int start_tcp_server_thread();
