/*
 * Copyright © 2021 ASUSTeK COMPUTER INC. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include "fsmd.h"

#define FSMD_PID_FILE "/var/run/fsmd.pid"
#define FSMD_ALARM_SECS 300
#define FSMD_PTHREAD_STACK_SIZE 0x100000

static int monitoring = 1;

void handle_socket(int newsockfd)
{
	fsm_sock_data_t data;
	int n;

	bzero(&data, sizeof(fsm_sock_data_t));

	n = read( newsockfd, &data, sizeof(fsm_sock_data_t));
	if( n < 0 ) {
		printf("ERROR reading from socket.\n");
		return;
	}

	if (data.d_type == FSM_S_DUMP) {
		dump_jffs_usage(data.dump_path);
	}
	else {
		printf("Unknown message.\n");
	}
}

static void start_local_socket(void)
{
	struct sockaddr_un addr;
	int sockfd, newsockfd;

	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		exit(-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, FSMD_SOCKET_PATH, sizeof(addr.sun_path)-1);

	unlink(FSMD_SOCKET_PATH);

	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("socket bind error");
		exit(-1);
	}

	if (listen(sockfd, 3) == -1) {
		perror("listen error");
		exit(-1);
	}

	while (1) {
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			perror("accept error");
			continue;
		}

		handle_socket(newsockfd);
		close(newsockfd);
	}
}

static void local_socket_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, FSMD_PTHREAD_STACK_SIZE);
	pthread_create(&thread, &attr, (void *)&start_local_socket, NULL);
	pthread_attr_destroy(&attr);
}

void handle_signal(int signum)
{
	if (signum == SIGALRM) {
		check_jffs_quota();
	} else if (signum == SIGUSR1) {
		check_jffs_quota();
	} else if (signum == SIGTERM) {
		monitoring = 0;
	} else
		printf("Not handle %d\n", signum);
}
static void initial_signal(void)
{
	struct sigaction sa;
	struct itimerval value;

	value.it_value.tv_sec = FSMD_ALARM_SECS;
	value.it_value.tv_usec = 0;
	value.it_interval = value.it_value;
	setitimer(ITIMER_REAL, &value, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handle_signal;
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

int main (int argc, char **argv)
{
	pid_t pid;
	FILE* fp;

	// background
	pid = fork();
	if (pid > 0) {
		fp = fopen(FSMD_PID_FILE, "w");
		if(fp) {
			fprintf(fp, "%d", pid);
			fclose(fp);
		}
		return 0;
	}
	else if (pid < 0)
		return -1;

	// Signal
	initial_signal();

	// load defined table
	initial_jffs_quota();

	// first check
	update_jffs_usage();

	// local socket
	local_socket_thread();

	while (monitoring) {
		pause();
	}

	// finish
	destroy_jffs_quota();

	return 0;
}
