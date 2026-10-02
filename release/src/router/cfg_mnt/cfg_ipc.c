#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/un.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_roaming.h"
#include "cfg_ipc.h"
#include "cfg_event.h"
#include "cfg_wevent.h"
#include "cfg_onboarding.h"
#include "cfg_ethevent.h"
#include "cfg_conndiag.h"
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
#include "cfg_centralcontrol.h"
#endif

/* for ipc packet handler */
struct ipcArgStruct {
	unsigned char data[MAX_IPC_PACKET_SIZE];
	size_t dataLen;
}ipcArgs;

/* for httpd event */
struct eventHandler
{
	int type;
	int (*func)(unsigned char *data);
};

int cm_processhttpdFwCheck(unsigned char *data);
int cm_processhttpdFwUpgrade(unsigned char *data);
int cm_processhttpdSlaveRemove(unsigned char *data);
int cm_processhttpdStartWps(unsigned char *data);
int cm_processhttpdResetDefault(unsigned char *data);
#ifdef ONBOARDING
int cm_processhttpdOnboarding(unsigned char *data);
#endif
int cm_processhttpdConfigChanged(unsigned char *data);
#ifdef RTCONFIG_BHCOST_OPT
int cm_processhttpdSelfOptimize(unsigned char *data);
#endif
int cm_processhttpdReboot(unsigned char *data);
int cm_processhttpdAction(unsigned char *data);

struct eventHandler httpdEventHandlers[] = {
	{ EID_HTTPD_FW_CHECK, cm_processhttpdFwCheck },
	{ EID_HTTPD_FW_UPGRADE, cm_processhttpdFwUpgrade },
	{ EID_HTTPD_REMOVE_SLAVE, cm_processhttpdSlaveRemove },
	{ EID_HTTPD_RESET_DEFAULT, cm_processhttpdResetDefault },
#ifdef ONBOARDING
	{ EID_HTTPD_ONBOARDING, cm_processhttpdOnboarding },
#endif
	{ EID_HTTPD_CONFIG_CHANGED, cm_processhttpdConfigChanged },
	{ EID_HTTPD_START_WPS, cm_processhttpdStartWps },
#ifdef RTCONFIG_BHCOST_OPT
	{ EID_HTTPD_SELF_OPTIMIZE, cm_processhttpdSelfOptimize },
#endif
	{ EID_HTTPD_REBOOT, cm_processhttpdReboot },
	{ EID_HTTPD_RE_RECONNECT, cm_processhttpdAction },
	{ EID_HTTPD_FORCE_ROAMING, cm_processhttpdAction },
	{-1, NULL }
};

/* for rc event */
#ifdef ONBOARDING
int cm_processrcWpsStop(unsigned char *data);
#endif
int cm_processReportPath(unsigned char *data);
int cm_processGetTopology(unsigned char *data);
int cm_processFeedback(unsigned char *data);
int cm_processRestartWireless(unsigned char *data);
int cm_processConfigChanged(unsigned char *data);


struct eventHandler rcEventHandlers[] = {
#ifdef ONBOARDING
	{ EID_RC_WPS_STOP, cm_processrcWpsStop },
#endif
	{ EID_RC_REPORT_PATH, cm_processReportPath },
	{ EID_RC_GET_TOPOLOGY, cm_processGetTopology },
	{ EID_RC_FEEDBACK, cm_processFeedback },
	{ EID_RC_RESTART_WIRELESS, cm_processRestartWireless },
	{ EID_RC_CONFIG_CHANGED, cm_processConfigChanged },
    {-1, NULL }
};

/*
========================================================================
Routine Description:
	Process EID_RC_GET_TOPOLOGY.

Arguments:
	data            - data from amas_lanctrl

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processReportPath(unsigned char *data)
{
	DBG_INFO("%s:%s:%d get event from amas_bhctrl\n", __FILE__, __FUNCTION__, __LINE__);
	cm_reportConnStatus();
	return 1;
} /* End of cm_processGetTopology */


/*
========================================================================
Routine Description:
	Process EID_RC_GET_TOPOLOGY.

Arguments:
	data            - data from amas_lanctrl

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processGetTopology(unsigned char *data)
{
	//DBG_INFO("%s:%s:%d get event from amas_lanctrl\n", __FILE__, __FUNCTION__, __LINE__);
	cm_requestTopology();
	return 1;
} /* End of cm_processGetTopology */

/*
========================================================================
Routine Description:
	Process EID_RC_CONFIG_CHANGED.

Arguments:
	data            - data from rc

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processConfigChanged(unsigned char *data)
{
	cm_configChanged(data);
	return 1;
}

/*
========================================================================
Routine Description:
	Process EID_RC_FEEDBACK.

Arguments:
	data            - data from rc

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processFeedback(unsigned char *data)
{
	cm_feedback();
	return 1;
} /* End of cm_processFeedback */

/*
========================================================================
Routine Description:
	Process EID_RC_RESTART_WIRELESS.

Arguments:
	data            - data from rc

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processRestartWireless(unsigned char *data)
{
	if (cm_ctrlBlock.role == IS_SERVER) {
		selected5gBand = NO_SELECTION;
#ifdef RTCONFIG_DWB
		cm_updateDwbInfo();
#endif
		cm_updateDutInfo();
		cm_updateDutChanspecs();
	}

#ifdef PRELINK
	if (cm_ctrlBlock.role == IS_SERVER)
		regen_hash_bundle_key();
	update_lldp_hash_bundle_key();	/* update lldp hash bundle key */
#endif
	update_vsie_info();

	return 1;
} /* End of cm_processRestartWireless */

/*
========================================================================
Routine Description:
	Process EID_HTTPD_FW_CHECK event.

Arguments:
	data		- data from httpd

Return Value:
        0		- fail
	1		- success

========================================================================
*/
int cm_processhttpdFwCheck(unsigned char *data)
{
	cm_handleFirmwareCheck();
	return 1;
} /* End of cm_processhttpdFwCheck */

/*
========================================================================
Routine Description:
	Process EID_HTTPD_FW_UPGRADE event.

Arguments:
	data		- data from httpd

Return Value:
        0		- fail
	1		- success

========================================================================
*/
int cm_processhttpdFwUpgrade(unsigned char *data)
{
	cm_handleFirmwareDownload();
	return 1;
} /* End of cm_processhttpdFwUpgrade */


/*
========================================================================
Routine Description:
	Process EID_HTTPD_REMOVE_SLAVE event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdSlaveRemove(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *macObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, SLAVE_MAC, &macObj);

	if (macObj)
		cm_removeSlave((char *)json_object_get_string(macObj));

	json_object_put(root);
	return 1;
} /* End of cm_processhttpdSlaveRemove */

/*
========================================================================
Routine Description:
	Process EID_HTTPD_RESET_DEFAULT event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdResetDefault(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *macObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, SLAVE_MAC, &macObj);

	if (macObj)
		cm_resetDefault((char *)json_object_get_string(macObj));

	json_object_put(root);
	return 1;
} /* End of cm_processhttpdResetDefault */

#ifdef ONBOARDING
/*
========================================================================
Routine Description:
	Process EID_HTTPD_ONBOARDING event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdOnboarding(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);

	if (httpdObj)
		cm_handleOnboarding((char *)json_object_to_json_string(httpdObj));

	json_object_put(root);

	return 1;
} /* End of cm_processhttpdOnboarding */
#endif	/* ONBOARDING */

/*
========================================================================
Routine Description:
	Update changed cofig on master side first.

Arguments:
	mac			- slave's mac
	config		- changed config

Return Value:
	0               - not upate
	1               - update

========================================================================
*/
int cm_updateConfigChanged(char *mac, json_object *config)
{
	json_object *fileRoot = NULL;
	char cfgTmpPath[64] = {0};
	json_object *paramObj = NULL;
	char paraStr[64] = {0};
	char valStr[64] = {0};
	int updateFlag = 0;
	char cfgVer[9] = {0};
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	char cfgMntPath[64] = {0};
	json_object *cfgArrayObj = NULL;
#endif

	snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/%s.json", mac);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", mac);
	cfgArrayObj = json_object_new_array();
#endif
	fileRoot = json_object_from_file(cfgTmpPath);
	if (fileRoot
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		&& cfgArrayObj
#endif
	) {
		json_object_object_foreach(config, key, val) {
			memset(paraStr, 0, sizeof(paraStr));
			memset(valStr, 0, sizeof(valStr));
			snprintf(paraStr, sizeof(paraStr), "%s", key);
			snprintf(valStr, sizeof(valStr), "%s", json_object_get_string(val));
			DBG_INFO("param(%s) value(%s)", paraStr, valStr);

			json_object_object_foreach(fileRoot, key, val) {
				json_object_object_get_ex(val, paraStr, &paramObj);
				/* delete matched parameter first and then add new value */
				if (paramObj) {
					json_object_object_del(val, paraStr);
					json_object_object_add(val, paraStr, json_object_new_string(valStr));
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
					json_object_array_add(cfgArrayObj, json_object_new_string(paraStr));
#endif
					DBG_INFO("update %s=%s", paraStr, valStr);
					updateFlag = 1;
				}
			}
		}
	}

	/* update to file */
	if (updateFlag) {
		json_object_to_file(cfgTmpPath, fileRoot);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		json_object_to_file(cfgMntPath, fileRoot);
		cm_updatePrivateRuleByMac(mac, cfgArrayObj, FOLLOW_RE, RULE_UPDATE);
#endif

		/* update cfg_ver info */
		srand(time(NULL));
		snprintf(cfgVer, sizeof(cfgVer), "%d%d", rand(), rand());
		nvram_set("cfg_ver", cfgVer);
		nvram_commit();
	}

	json_object_put(fileRoot);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	json_object_put(cfgArrayObj);
#endif

	return updateFlag;
} /* End of cm_processhttpdResetDefault */

/*
========================================================================
Routine Description:
	Process EID_HTTPD_CONFIG_CHANGED event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdConfigChanged(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *macObj = NULL;
	json_object *configObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, RE_MAC, &macObj);
	json_object_object_get_ex(httpdObj, CONFIG, &configObj);

	if (macObj && configObj) {
		if (cm_updateConfigChanged((char *)json_object_get_string(macObj), configObj))
			cm_notifyConfigChanged((char *)json_object_get_string(macObj));
	}

	json_object_put(root);
	return 1;
} /* End of cm_processhttpdResetDefault */

/*
========================================================================
Routine Description:
	Process EID_HTTPD_START_WPS event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdStartWps(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *ipObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, LOGIN_IP, &ipObj);

	if (ipObj)
		cm_startWps((char *)json_object_get_string(ipObj));

	json_object_put(root);

	return 1;
} /* End of cm_processhttpdStartWps */

#ifdef RTCONFIG_BHCOST_OPT
/*
========================================================================
Routine Description:
	Process EID_HTTPD_SELF_OPTIMIZE event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/

int cm_processhttpdSelfOptimize(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *macObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, SLAVE_MAC, &macObj);

	if (macObj)
		cm_selfOptimize((char *)json_object_get_string(macObj));

	json_object_put(root);
	return 1;
} /* End of cm_processhttpdSelfOptimize */
#endif /* RTCONFIG_BHCOST_OPT */

/*
========================================================================
Routine Description:
    Process EID_HTTPD_REBOOT event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdReboot(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *macListObj = NULL;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, MAC_LIST, &macListObj);

	if (macListObj)
		cm_notifyReboot(macListObj);

	json_object_put(root);

	return 1;
} /* End of cm_processhttpdReboot */

/*
========================================================================
Routine Description:
    Process EID_HTTPD_XXXX event.

Arguments:
	data            - data from httpd

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processhttpdAction(unsigned char *data)
{
	json_object *root = NULL, *httpdObj = NULL, *macListObj = NULL, *eidObj = NULL, *dataObj = NULL;
	int eid = 0;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, MAC_LIST, &macListObj);
	json_object_object_get_ex(httpdObj, EVENT_ID, &eidObj);
	json_object_object_get_ex(httpdObj, DATA, &dataObj);

	if (eidObj && macListObj && dataObj) {
		eid = atoi(json_object_get_string(eidObj));
		cm_notifyAction(eid, macListObj, dataObj);
	}

	json_object_put(root);

	return 1;
} /* End of cm_processhttpdAction */

/*
========================================================================
Routine Description:
	Process packets from httpd.

Arguments:
	data		- received data

Return Value:
	0		- continue to receive
	1		- break to receive

========================================================================
*/
int cm_httpdPacketProcess(unsigned char *data)
{
	json_object *root = NULL;
	json_object *httpdObj = NULL;
	json_object *eidObj = NULL;
	int eid = 0;
	struct eventHandler *handler = NULL;
	int ret = 0;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
	json_object_object_get_ex(httpdObj, EVENT_ID, &eidObj);

	DBG_INFO("received data (%s)", (char *)data);

	if (eidObj) {
		eid = atoi(json_object_get_string(eidObj));
		json_object_put(root);

		for (handler = &httpdEventHandlers[0]; handler->type > 0; handler++) {
			if (handler->type == eid)
				break;
		}

		if (handler == NULL || handler->type < 0)
			DBG_INFO("no corresponding function pointer(%d)", eid);
		else
		{
			DBG_INFO("process event (%d)", handler->type);
			if (!handler->func(data)) {
				DBG_ERR("fail to process corresponding event");
				goto err;
			}
		}
	}

	ret = 1;

err:

	return ret;
} /* End of cm_httpdPacketProcess */

#ifdef ONBOARDING
/*
========================================================================
Routine Description:
	Process EID_RC_WPS_STOP event.

Arguments:
	data            - data from rc

Return Value:
	0               - fail
	1               - success

========================================================================
*/
int cm_processrcWpsStop(unsigned char *data)
{
	cm_stopWps();
	return 1;
} /* End of cm_processrcWpsStop */



/*
========================================================================
Routine Description:
	Process packets from rc.

Arguments:
	data		- received data

Return Value:
	0		- continue to receive
	1		- break to receive

========================================================================
*/
int cm_rcPacketProcess(unsigned char *data)
{
	json_object *root = NULL;
	json_object *rcObj = NULL;
	json_object *eidObj = NULL;
	int eid = 0;
	struct eventHandler *handler = NULL;
	int ret = 0;

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, RC_PREFIX, &rcObj);
	json_object_object_get_ex(rcObj, EVENT_ID, &eidObj);

	DBG_INFO("received data (%s)", (char *)data);

	if (eidObj) {
		eid = atoi(json_object_get_string(eidObj));
		json_object_put(root);

		for (handler = &rcEventHandlers[0]; handler->type > 0; handler++) {
			if (handler->type == eid)
				break;
		}

		if (handler == NULL || handler->type < 0)
			DBG_INFO("no corresponding function pointer(%d)", eid);
		else
		{
			DBG_INFO("process event (%d)", handler->type);
			if (!handler->func(data)) {
				DBG_ERR("fail to process corresponding event");
				goto err;
			}
		}
	}

	ret = 1;

err:

	return ret;
} /* End of cm_httpdPacketProcess */
#endif	/* ONBOARDING */

/*
========================================================================
Routine Description:
	Create a thread to handle received packets from ipc socket.

Arguments:
	*args		- arguments for socket

Return Value:
	None

Note:
========================================================================
*/
void *cm_ipcPacketHandler(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif
	pthread_detach(pthread_self());

	json_object *root = NULL;
#ifdef LEGACY_ROAMING
	json_object *rastObj = NULL;
	int fromRast = 0;
#endif
	json_object *httpdObj = NULL;
	int fromHttpd = 0;
	json_object *weventObj = NULL;
	int fromWevent = 0;
#ifdef ONBOARDING
	json_object *rcObj = NULL;
	int fromRc = 0;
	json_object *ethEventObj = NULL;
	int fromEthEvent = 0;
#endif
#ifdef CONN_DIAG
	json_object *connDiagObj = NULL;
	int fromConnDiag = 0;
#endif
	struct ipcArgStruct *ipcArgs = (struct ipcArgStruct *)args;
	unsigned char *pPktBuf = NULL;

	if (IsNULL_PTR(ipcArgs->data)) {
		DBG_ERR("data is null!");
		goto err;
	}

	pPktBuf = &ipcArgs->data[0];

	DBG_INFO("msg(%s)", (char *)pPktBuf);

	root = json_tokener_parse((char *)pPktBuf);

	if (root) {
#ifdef LEGACY_ROAMING
		json_object_object_get_ex(root, RAST_PREFIX, &rastObj);
		if (rastObj)
			fromRast = 1;
#endif
		json_object_object_get_ex(root, HTTPD_PREFIX, &httpdObj);
		json_object_object_get_ex(root, WEVENT_PREFIX, &weventObj);
#ifdef ONBOARDING
		json_object_object_get_ex(root, RC_PREFIX, &rcObj);
		json_object_object_get_ex(root, ETHEVENT_PREFIX, &ethEventObj);
#endif
#ifdef ONBOARDING
		json_object_object_get_ex(root, CHKSTA_PREFIX, &connDiagObj);
#endif
		if (httpdObj)
			fromHttpd = 1;
		if (weventObj)
			fromWevent = 1;
#ifdef ONBOARDING
		if (rcObj) fromRc = 1;
		if (ethEventObj) fromEthEvent = 1;
#endif
#ifdef CONN_DIAG
		if (connDiagObj)
			fromConnDiag = 1;
#endif

		json_object_put(root);

		if (fromWevent)
			cm_weventPacketProcess(pPktBuf);
		else if (fromHttpd) {
			if (cm_ctrlBlock.role == IS_SERVER)
				cm_httpdPacketProcess(pPktBuf);
		}
#ifdef LEGACY_ROAMING
		else if (fromRast) 	cm_rastPacketProcess(pPktBuf);
#endif
#ifdef ONBOARDING
		else if (fromRc) cm_rcPacketProcess(pPktBuf);
		else if (fromEthEvent) cm_ethEventPacketProcess(pPktBuf);
#endif
#ifdef CONN_DIAG
		else if (fromConnDiag)
			cm_connDiagPacketProcess(pPktBuf);
#endif
		else
			DBG_INFO("no packet process");
	}
	else
		DBG_ERR("root is invalid");

err:

	free(args);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_ipcPacketHandler */

/*
========================================================================
Routine Description:
	Handle received packets from IPC socket.

Arguments:
	sock		- sock fd for IPC

Return Value:
	None

Note:
========================================================================
*/
void cm_rcvIpcHandler(int sock)
{
	int clientSock = 0;
	pthread_t sockThread;
	struct ipcArgStruct *args = NULL;
	unsigned char pPktBuf[MAX_IPC_PACKET_SIZE] = {0};
	int len = 0;

	DBG_INFO("enter");

	clientSock = accept(sock, NULL, NULL);

	if (clientSock < 0) {
		DBG_ERR("Failed to socket accept() !!!");
		return;
	}

	/* handle the packet */
	if ((len = read(clientSock, pPktBuf, sizeof(pPktBuf))) <= 0) {
		DBG_ERR("Failed to socket read()!!!");
		close(clientSock);
		return;
	}

	close(clientSock);

	args = malloc(sizeof(struct ipcArgStruct));
	memset(args, 0, sizeof(struct ipcArgStruct));
	memcpy(args->data, (unsigned char *)&pPktBuf[0], len);
	args->dataLen = len;

	DBG_INFO("create thread for handle ipc packet");
	if (pthread_create(&sockThread, attrp, cm_ipcPacketHandler, args) != 0) {
		DBG_ERR("could not create thread !!!");
		free(args);
	}

	DBG_INFO("leave");
} /* End of cm_rcvIpcHandler */

/*
========================================================================
Routine Description:
	Send data to specificed IPC socket path.

Arguments:
	ipcPath		- ipc socket path
	data		- data will be sent out
	dataLen		- the length of data

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendIpcHandler(char *ipcPath, char *data, int dataLen)
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
	strncpy(addr.sun_path, ipcPath, sizeof(addr.sun_path)-1);
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

	length = write(fd, data, dataLen);

	if (length < 0) {
		DBG_ERR("error writing:%s", strerror(errno));
		goto err;
	}

	ret = 1;

	DBG_INFO("send data out (%s) via (%s)", data, ipcPath);

err:
	if (fd >= 0)
		close(fd);

	DBG_INFO("leave");
	return ret;
} /* End of cm_sendIpcHandler */
