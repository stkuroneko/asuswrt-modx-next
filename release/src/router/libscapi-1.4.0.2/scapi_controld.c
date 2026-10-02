/******************************************************************************

                         Copyright (c) 2012, 2014, 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "ltq_api_include.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>

#define MAX_BUF 1024

/*! \brief api for command line utility of controld 
*/
int32_t ControlDCtl(eControlDOption_t eControlDOption, ControlDArgs_t * pxControlDArgs)
{
	int nSock, nRecvLen, nLen;
	struct sockaddr_un xSockAddrRemote;
	char sBuf[MAX_BUF] = { '\0' };

	if ((nSock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		LOGF_LOG_ERROR("Unable to open AF_UNIX socket:%s\n", strerror(errno));
		exit(UGW_FAILURE);
	}

	xSockAddrRemote.sun_family = AF_UNIX;
	strcpy(xSockAddrRemote.sun_path, CONTROLD_SOCK_PATH);
	nLen = strlen(xSockAddrRemote.sun_path) + sizeof(xSockAddrRemote.sun_family);
	if (connect(nSock, (struct sockaddr *)&xSockAddrRemote, nLen) == -1) {
		LOGF_LOG_ERROR("Unable to connect to %s: %s\n", CONTROLD_SOCK_PATH, strerror(errno));
		exit(UGW_FAILURE);
	}
    /*Populating the buffer based on eControlDOption*/   
	switch (eControlDOption) {
	case DAEMON_ADD:

		snprintf(sBuf, sizeof(sBuf),
			 "add%cCMD=%s%cKEYNAME=%s%cDELAY=%d%cRESPAWN=%d%c", '\0', pxControlDArgs->sCmd, '\0', pxControlDArgs->sKeyName, '\0', pxControlDArgs->nDelay, '\0', pxControlDArgs->nRespawn, '\0');
		LOGF_LOG_DEBUG("Sending Request: [%s]\n", sBuf);

		break;
	case DAEMON_START:
		snprintf(sBuf, sizeof(sBuf), "start%c%s%c", '\0', pxControlDArgs->sKeyName, '\0');
		LOGF_LOG_DEBUG("Sending Request: [%s]\n", sBuf);
		break;
	case DAEMON_STOP:
		snprintf(sBuf, sizeof(sBuf), "stop%c%s%c", '\0', pxControlDArgs->sKeyName, '\0');
		LOGF_LOG_DEBUG("Sending Request: [%s]\n", sBuf);
		break;
	case DAEMON_DELETE:
		snprintf(sBuf, sizeof(sBuf), "delete%c%s%c", '\0', pxControlDArgs->sKeyName, '\0');
		LOGF_LOG_DEBUG("Sending Request: [%s]\n", sBuf);
		break;
	case DAEMON_SHOW:
		strcpy(sBuf, "show");
		break;
	default:
		LOGF_LOG_INFO("Error:Option Not supported\n");
		return UGW_FAILURE;
	}
	LOGF_LOG_INFO("Sending request to controld from api:[%s][%d]\n", sBuf, sizeof(sBuf));
	if (send(nSock, sBuf, sizeof(sBuf), 0) == -1) {
		LOGF_LOG_INFO("send: %s", strerror(errno));
		exit(UGW_FAILURE);
	}
	LOGF_LOG_INFO("Receive request From controld :\n");
	while ((nRecvLen = recv(nSock, sBuf, MAX_BUF - 1, 0)) > 0) {
		LOGF_LOG_INFO("%s", sBuf);
	}

	if (nRecvLen < 0) {
		LOGF_LOG_ERROR("recv");
	}
	close(nSock);
	LOGF_LOG_INFO("ControlD addition success\n");
	return UGW_SUCCESS;
}
