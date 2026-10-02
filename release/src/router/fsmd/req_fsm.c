/*
 * Copyright © 2021 ASUSTeK COMPUTER INC. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

#include "fsmd.h"

int fsm_cli_create()
{
	struct sockaddr_un addr;
	int sockfd;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", FSMD_SOCKET_PATH);

	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		perror("connect");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

int fsm_set_cmd(fsm_sock_data_t *s_data)
{
	int fd;
	int ret = 0;
	size_t left = 0;
	ssize_t n = 0;
	uint8_t *p = NULL;

	fd = fsm_cli_create();
	if (fd < 0)
		return -1;

	left = sizeof(fsm_sock_data_t);
	p = (uint8_t *)s_data;
	while (1) {
		n = write(fd, p, left);
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			else {
				perror("write");
				ret = -1;
				goto done;
			}
		}
		else if (n == left)
			break;
		else {
			left -= n;
			p += n;
		}
	}

done:
	close(fd);
	return (ret);
}

int fsm_get_cmd(fsm_sock_data_t *s_data, void* data, size_t len)
{
	int fd;
	int ret = 0;
	size_t left = 0;
	ssize_t n = 0;
	uint8_t *p = NULL;

	fd = fsm_cli_create();
	if(fd < 0)
		return -1;

	left = sizeof(fsm_sock_data_t);
	p = (uint8_t *)s_data;
	while (1) {
		n = write(fd, p, left);
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			else {
				perror("write");
				ret = -1;
				goto done;
			}
		}
		else if (n == left)
			break;
		else {
			left -= n;
			p += n;
		}
	}

	left = len;
	p = data;
	while (1) {
		n = read(fd, p, left);
		if (n < 0) {
			if (errno == EAGAIN)
				continue;
			else {
				perror("read");
				ret = -1;
				goto done;
			}
		}
		else if (n == 0)
			break;
		else {
			left -= n;
			p += n;
		}
	}

done:
	close(fd);
	return (ret);
}

int main(int argc, char *argv[])
{
	fsm_sock_data_t s_data;

	if (argc < 2) {
		printf("Command Error.\n");
		return -1;
	}

	if (!strncmp(argv[1], "dump", 4)) {
		s_data.d_type = FSM_S_DUMP;
		if (argc < 3)
			snprintf(s_data.dump_path, sizeof(s_data.dump_path), "/dev/console");
		else
			snprintf(s_data.dump_path, sizeof(s_data.dump_path), "%s", argv[2]);
		return fsm_set_cmd(&s_data);
	}
	else {
		printf("Command not support.\n");
	}

	return 0;
}
