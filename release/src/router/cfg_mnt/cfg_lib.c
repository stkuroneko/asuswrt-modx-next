#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <shared.h>
#include "cfg_ipc.h"
#include "cfg_lib.h"

#define CHANSPEC_AVAILABLE_LIST_TXT_PATH	"/tmp/chanspec_avbl.txt"
#define foreach_comma(word, wordlist, next) \
                for (next = &wordlist[strspn(wordlist, ",")], \
                                strncpy(word, next, sizeof(word)), \
                                word[strcspn(word, ",")] = '\0', \
                                word[sizeof(word) - 1] = '\0', \
                                next = strchr(next, ','); \
                                strlen(word); \
                                next = next ? &next[strspn(next, ",")] : "", \
                                strncpy(word, next, sizeof(word)), \
                                word[strcspn(word, ",")] = '\0', \
                                word[sizeof(word) - 1] = '\0', \
                                next = strchr(next, ','))

/*
========================================================================
Routine Description:
	Send event to cfg sync.

Arguments:
	*msg		- message to send out

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int send_cfgmnt_event(char *msg)
{
	int fd = -1;
	int length = 0;
	struct sockaddr_un addr;
	int ret= 0;

	if (strlen(msg) == 0)
		goto err;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		printf("[libcfgmnt - %d] ipc socket error!\n", __LINE__);
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, CFGMNT_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("[libcfgmnt - %d] ipc connect error!\n", __LINE__);
		goto err;
	}

	length = write(fd, msg, strlen(msg));

	if (length < 0) {
		printf("[libcfgmnt - %d] error writing:%s\n", __LINE__, strerror(errno));
		goto err;
	}

	ret = 1;

err:
	if (fd >= 0)
		close(fd);

	return ret;
} /* End of send_cfgmnt_event */ 

int file_read_string(const char *path, char *buffer, int max)
{
	int f;
	int n = 0;

	if (max <= 0) return -1;

	if ((f = open(path, O_RDONLY)) < 0) return -1;
	n = read(f, buffer, max - 1);
	close(f);

	buffer[(n > 0) ? n : 0] = 0;
	return n;
}

/*
========================================================================
Routine Description:
	Chanspec information for 2g and 5g

Arguments:
	avblChannel		- available chanspec

Return Value:
	-1		- error
	0		- fail
	1		- success

========================================================================
*/
int get_chanspec_info (AVBL_CHANSPEC_T *avblChanspec)
{
	char avblChanspecStr[512] = {0};
	char bw2gTmp[8] = {0}, bw5gTmp[8] = {0}, bw6gTmp[8] = {0};
	char channel2gTmp[256] = {0}, channel5gTmp[256] = {0}, tribandReTmp[8] = {0}, channel6gTmp[256] = {0}, dual5gReTmp[8] = {0};
	int ret = 0;
	char word[256], *next;
	int i = 0;

	if (file_read_string(CHANSPEC_AVAILABLE_LIST_TXT_PATH, avblChanspecStr, sizeof(avblChanspecStr))) {
		/* bw2g:3 channel2g:1,2,3,4,5,6,7,8,9,10,11 bw5g:7 channel5g:36,40,44,48,149,153,157,161,165 tribandRe:1 dual5gRe:1 */
		if (sscanf(avblChanspecStr, "%*[^:]:%s %*[^:]:%s %*[^:]:%s %*[^:]:%s %*[^:]:%s %*[^:]:%s %*[^:]:%s %*[^:]:%s",
			bw2gTmp, channel2gTmp, bw5gTmp, channel5gTmp, bw6gTmp, channel6gTmp, tribandReTmp, dual5gReTmp) != 8)
			return -1;

		avblChanspec->bw2g = atoi(bw2gTmp);
		avblChanspec->bw5g = atoi(bw5gTmp);
		avblChanspec->bw6g = atoi(bw6gTmp);

		/* grab 2g channel list */
		if (strlen(channel2gTmp)) {
			i = 0;
			foreach_comma (word, channel2gTmp, next) {
				if (i >= MAX_2G_CHANNEL_LIST_NUM)
					continue;
				avblChanspec->channelList2g[i] = atoi(word);
				i++;
			}
			for(; i <= MAX_2G_CHANNEL_LIST_NUM; i++)
				avblChanspec->channelList2g[i] = 0;
		}

		/* grab 5g channel list */
		if (strlen(channel5gTmp)) {
			i = 0;
			foreach_comma (word, channel5gTmp, next) {
				if (i >= MAX_5G_CHANNEL_LIST_NUM)
					continue;
				avblChanspec->channelList5g[i] = atoi(word);
				i++;
			}
			for(; i <= MAX_5G_CHANNEL_LIST_NUM; i++)
				avblChanspec->channelList5g[i] = 0;
		}
#ifdef RTCONFIG_WIFI6E
		/* grab 6g channel list */
		if (strlen(channel6gTmp)) {
			i = 0;
			foreach_comma (word, channel6gTmp, next) {
				if (i >= MAX_6G_CHANNEL_LIST_NUM)
					continue;
				avblChanspec->channelList6g[i] = atoi(word);
				i++;
			}
			for(; i <= MAX_6G_CHANNEL_LIST_NUM; i++)
				avblChanspec->channelList6g[i] = 0;
		}
#endif
		/* support tri-band */
		avblChanspec->existTribandRe = atoi(tribandReTmp);

		/* support dual 5g */
		avblChanspec->existDual5gRe = atoi(dual5gReTmp);

		ret = 1;
	}

	return ret;
} /* End of get_chanspec_info */

/*
========================================================================
Routine Description:
	Send event to roamast.

Arguments:
	data		- data to send out

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int send_event_to_roamast(char *data)
{
	int fd = -1;
	int length = 0;
	int ret = 0;
	struct sockaddr_un addr;
	int flags;
	int status;
	socklen_t statusLen;
	fd_set writeFds;
	int selectRet;
	struct timeval timeout = {2, 0};

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		printf("[libcfgmnt - %d] ipc socket error\n", __LINE__);
		goto err;
	}

	/* set NONBLOCK for connect() */
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		printf("[libcfgmnt - %d] F_GETFL error\n", __LINE__);
		goto err;
	}

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0) {
		printf("[libcfgmnt - %d] F_SETFL error\n", __LINE__);
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, RAST_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno == EINPROGRESS) {
			FD_ZERO(&writeFds);
			FD_SET(fd, &writeFds);

			selectRet = select(fd + 1, NULL, &writeFds, NULL, &timeout);

			//Check return, -1 is error, 0 is timeout
			if (selectRet == -1 || selectRet == 0) {
				printf("[libcfgmnt - %d] ipc connect error\n", __LINE__);
				goto err;
			}
		}
		else
		{
			printf("[libcfgmnt - %d] ipc connect error\n", __LINE__);
			goto err;
		}
	}

	/* check the status of connect() */
	status = 0;
	statusLen = sizeof(status);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
		printf("[libcfgmnt - %d] getsockopt(SO_ERROR):%s\n", __LINE__, strerror(errno));
		goto err;
	}

	length = write(fd, data, strlen((char *)data));

	if (length < 0) {
		printf("[libcfgmnt - %d] error writing:%s\n", __LINE__, strerror(errno));
		goto err;
	}

	ret = 1;

	printf("[libcfgmnt - %d] send event to roamast: %s\n", __LINE__, data);

err:
	if (fd >= 0)
		close(fd);

	return ret;
} /* End of send_event_to_roamast */

int send_event_to_bsd(char *data)
{
	int fd = -1;
	int length = 0;
	int ret = 0;
	struct sockaddr_un addr;
	int flags;
	int status;
	socklen_t statusLen;
	fd_set writeFds;
	int selectRet;
	struct timeval timeout = {2, 0};

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		printf("[libcfgmnt - %d] ipc socket error\n", __LINE__);
		goto err;
	}

	/* set NONBLOCK for connect() */
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		printf("[libcfgmnt - %d] F_GETFL error\n", __LINE__);
		goto err;
	}

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0) {
		printf("[libcfgmnt - %d] F_SETFL error\n", __LINE__);
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, BSD_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno == EINPROGRESS) {
			FD_ZERO(&writeFds);
			FD_SET(fd, &writeFds);

			selectRet = select(fd + 1, NULL, &writeFds, NULL, &timeout);

			//Check return, -1 is error, 0 is timeout
			if (selectRet == -1 || selectRet == 0) {
				printf("[libcfgmnt - %d] ipc connect error\n", __LINE__);
				goto err;
			}
		}
		else
		{
			printf("[libcfgmnt - %d] ipc connect error\n", __LINE__);
			goto err;
		}
	}

	/* check the status of connect() */
	status = 0;
	statusLen = sizeof(status);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
		printf("[libcfgmnt - %d] getsockopt(SO_ERROR):%s\n", __LINE__, strerror(errno));
		goto err;
	}

	length = write(fd, data, strlen((char *)data));

	if (length < 0) {
		printf("[libcfgmnt - %d] error writing:%s\n", __LINE__, strerror(errno));
		goto err;
	}

	ret = 1;

	printf("[libcfgmnt - %d] send event to bsd: %s\n", __LINE__, data);

err:
	if (fd >= 0)
		close(fd);

	return ret;
} /* End of send_event_to_bsd */

/*
========================================================================
Routine Description:
	Update sta binding list.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int update_sta_binding_list()
{
	char data[64];
	int ret=0;

	snprintf(data, sizeof(data), "{\"%s\":{\"%s\":\"%d\"}}", CFG_PREFIX, RAST_EVENT_ID, EID_RM_STA_BINDING_UPDATE);

	ret = send_event_to_bsd(data);

	ret |= send_event_to_roamast(data);

	return ret;
} /* End of update_sta_binding_list */
