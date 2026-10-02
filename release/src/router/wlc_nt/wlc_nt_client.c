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

#include "wlc_nt.h"

static int SEND_WLC_EVENT(WLCNT_EVENT_T *event)
{
	struct    sockaddr_un addr;
	int       sockfd, n;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		printf("[%s:(%d)] ERROR socket.\n", __FUNCTION__, __LINE__);
		perror("socket error");
		return 0;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, WLCNT_SOCKET_PATH, sizeof(addr.sun_path));

	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		printf("[%s:(%d)] ERROR connecting:%s.\n", __FUNCTION__, __LINE__, strerror(errno));
		perror("connect error");
		close(sockfd);
		return 0;
	}

	//printf("[%s:(%d)] tstamp=%ld, addr=%s, ifname=%s, online=%d\n", __FUNCTION__, __LINE__, event->tstamp, event->addr, event->ifname, event->online); // debug
	n = write(sockfd, (WLCNT_EVENT_T *)event, sizeof(WLCNT_EVENT_T));

	close(sockfd);

	if (n < 0) {
		printf("[%s:(%d)] ERROR writing:%s.\n", __FUNCTION__, __LINE__, strerror(errno));
		perror("writing error");
		return 0;
	}

	return 1;
}

void WLCNT_TRIGGER(char *eaddr, char *ifname, int online)
{
	WLCNT_EVENT_T *wlc = NULL;
	time_t now;

	wlc = (WLCNT_EVENT_T *)malloc(sizeof(WLCNT_EVENT_T));
	if (wlc == NULL) {
		printf("[%s:(%d)] malloc(WLCNT_EVENT_T) error:%s.\n", __FUNCTION__, __LINE__, strerror(errno));
		return;
	}

	time(&now);

	wlc->tstamp = now;
	memcpy(wlc->addr, eaddr, sizeof(wlc->addr));
	memcpy(wlc->ifname, ifname, sizeof(wlc->ifname));
	wlc->online = online;
	//MyDBG("tstamp=%ld, addr=%s, ifname=%s, online=%d\n", wlc->tstamp, wlc->addr, wlc->ifname, wlc->online); // debug

	/* send wlc event into wlc_nt */
	SEND_WLC_EVENT(wlc);

	/* free memory */
	free(wlc);
}
