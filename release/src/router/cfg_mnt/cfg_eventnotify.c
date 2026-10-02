#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/un.h>
#include <shared.h>
#include <shutils.h>
#if defined(RTCONFIG_RALINK)
#include "ralink.h"
#endif
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_eventnotify.h"
#ifdef RTCONFIG_NOTIFICATION_CENTER
#include <libnt.h>
#include <wlc_nt.h>
#endif

/*
========================================================================
Routine Description:
	Send event to amas lib.

Arguments:
        event		- event info.

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendEventToAmasLib(AMASLIB_EVENT_T *event)
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

	DBG_INFO("enter");

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DBG_ERR("ipc socket error!");
		goto err;
	}

	/* set NONBLOCK for connect() */
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		DBG_ERR("F_GETFL error!");
		goto err;
	}

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0) {
		DBG_ERR("F_SETFL error!");
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, AMASLIB_SOCKET_PATH, sizeof(addr.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno == EINPROGRESS) {
			FD_ZERO(&writeFds);
			FD_SET(fd, &writeFds);

			selectRet = select(fd + 1, NULL, &writeFds, NULL, &timeout);

			//Check return, -1 is error, 0 is timeout
			if (selectRet == -1 || selectRet == 0) {
				DBG_ERR("ipc connect error");
				goto err;
			}
		}
		else
		{
			DBG_ERR("ipc connect error");
			goto err;
		}
	}

	/* check the status of connect() */
	status = 0;
	statusLen = sizeof(status);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
		DBG_ERR("getsockopt(SO_ERROR): %s", strerror(errno));
		goto err;
	}

	length = write(fd, (AMASLIB_EVENT_T *)event, sizeof(AMASLIB_EVENT_T));

	if (length < 0) {
		DBG_ERR("error writing:%s", strerror(errno));
		goto err;
	}

	ret = 1;

err:
	if (fd >= 0)
        	close(fd);

	DBG_INFO("leave");
	return ret;
} /* End of cm_sendEventToAmasLib */

/*
========================================================================
Routine Description:
	Update the sta mac of 2G & 5G for amas lib.

Arguments:
	decodeMsg               - decrypted message

Return Value:
	None

========================================================================
*/
void cm_updateStaMacToAmasLib(unsigned char *decodeMsg)
{
	json_object *root = json_tokener_parse((char *)decodeMsg);
	json_object *sta2gObj = NULL;
	json_object *sta5gObj = NULL;
	AMASLIB_EVENT_T *event = NULL;

	if (root == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	if ((event = (AMASLIB_EVENT_T *)malloc(sizeof(AMASLIB_EVENT_T))) == NULL) {
                DBG_ERR("malloc failed for event");
		json_object_put(root);
                return;
        }

	json_object_object_get_ex(root, CFG_STR_STA2G, &sta2gObj);
	json_object_object_get_ex(root, CFG_STR_STA5G, &sta5gObj);

	memset(event, 0, sizeof(AMASLIB_EVENT_T));
	event->flag = 0;

	if (sta2gObj) {
		strlcpy(event->sta2g, json_object_get_string(sta2gObj), sizeof(event->sta2g));
		event->flag = 1;
	}

	if (sta5gObj) {
		strlcpy(event->sta5g, json_object_get_string(sta5gObj), sizeof(event->sta5g));
		event->flag = 1;
	}
	
	/* send event to amas lib */
	cm_sendEventToAmasLib(event);

	free(event);
	json_object_put(root);
} /* End of cm_updateStaMacToAmasLib */ 

#ifdef RTCONFIG_NOTIFICATION_CENTER
void cm_sendEventToNtCenter(int event, char *msg)
{
	SEND_NT_EVENT(event, msg);
}

void cm_forwardWifiEventToNtCenter(int event, char *mac, char *band)
{
	char msg[512];
	int nt_event = GENERAL_WIFI_DEV_ONLINE;

	if (event == WIFI_DEVICE_OFFLINE)
		nt_event = GENERAL_WIFI_DEV_OFFLINE;

	snprintf(msg, sizeof(msg), "{\"from\":\"%s\",\"client_mac\":\"%s\"}", SERVER_PROGNAME, mac);

	cm_sendEventToNtCenter(nt_event, msg);
}

void cm_forwardEthEventToNtCenter(int event, char *mac)
{
	char msg[512];
	int nt_event = GENERAL_ETH_DEV_ONLINE;

	if (event == ETH_DEVICE_OFFLINE)
		nt_event = GENERAL_ETH_DEV_OFFLINE;

	snprintf(msg, sizeof(msg), "{\"from\":\"%s\",\"client_mac\":\"%s\"}", SERVER_PROGNAME, mac);

	cm_sendEventToNtCenter(nt_event, msg);
}
#endif
