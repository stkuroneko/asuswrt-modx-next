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
#include "cfg_udp.h"
#include "cfg_ipc.h"
#include "cfg_conndiag.h"
#include "cfg_dencrypt.h"

/* for udp data */
struct udpDataStruct {
	unsigned char data[MAX_UDP_PACKET_SIZE];
	size_t dataLen;
	char peerIp[32];
}udpDataArgs;

/* for romaing event */
struct eventHandler 
{
    int type;
    int (*func)(unsigned char *data);
};

int cm_processChkOne(unsigned char *data);
int cm_processChkOneRsp(unsigned char *data);

struct eventHandler connDiagEventHandlers[] = {
	{ EID_CD_STA_CHK_ONE, cm_processChkOne },
	{ EID_CD_STA_CHK_ONE_RSP, cm_processChkOneRsp },
	{-1, NULL }	
};

/* for roaming packet */
struct connDiagPacketHandler
{
    int type;
    int (*func)(unsigned char *data, size_t dataLen, char *peerIp);
};

int cm_processREQ_CHKSTA(unsigned char *data, size_t dataLen, char *peerIp);
int cm_processRSP_CHKSTA(unsigned char *data, size_t dataLen, char *peerIp);

struct connDiagPacketHandler connDiagPacketHandlers[] = {
	{ REQ_CHKSTA, cm_processREQ_CHKSTA },
	{ RSP_CHKSTA, cm_processRSP_CHKSTA },
	{-1, NULL }
};

int terminateConnDiagPktList = 0;
int leaveConnDiagPktList = 0;

/*
========================================================================
Routine Description:
	Send event to roaming assistant.

Arguments:
        *data		- data from conn_diag of other AP

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_sendEventToConnDiag(unsigned char *data)
{
	int fd = -1;
	int length = 0;
	int ret = 0;
	struct sockaddr_un addr;

	DBG_INFO("enter");

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DBG_ERR("ipc socket error!");
		goto err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, CONNDIAG_IPC_SOCKET_PATH, sizeof(addr.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DBG_ERR("ipc connect error\n");
		goto err;
	}

	length = write(fd, data, strlen((char *)data));

	if (length < 0) {
		DBG_ERR("error writing:%s", strerror(errno));
		goto err;
	}

	ret = 1;

	DBG_INFO("send event to conn_diag (%s)", (char *)data);

err:
	if (fd >= 0)
        	close(fd);

	DBG_INFO("leave");
	return ret;
} /* End of cm_sendEventToConnDiag */

/*
========================================================================
Routine Description:
	Convert json from the conn_diag of other AP to the conn_diag of myself 

Arguments:
	*inData		- data from conn_diag
	*peerIp		- the ip of peer AP
	*outData	- converted data for conn_diag
	*outDataLen	- the buf length of outData

Return Value:
	data length of converted data

========================================================================
*/
int cm_convertConnDiagData(unsigned char *inData, char *peerIp, unsigned char *outData, size_t outDataLen)
{
	json_object *connDiagRoot = NULL;
	json_object *cfgRoot = NULL;
	json_object *connDiagObj = NULL;
	json_object *cfgObj = NULL;

	connDiagRoot = json_tokener_parse((char *)inData);
	json_object_object_get_ex(connDiagRoot, CHKSTA_PREFIX, &connDiagObj);

	//DBG_INFO("inData(%s), peerIp(%s)", inData, peerIp);
	if (connDiagObj) {
		cfgObj = json_object_new_object();
		if (cfgObj) {
			json_object_object_foreach(connDiagObj, key, val) {
				json_object_object_add(cfgObj, key, json_object_new_string(json_object_get_string(val)));
			}

			if (peerIp)
				json_object_object_add(cfgObj, RAST_PEERIP, json_object_new_string(peerIp));

			cfgRoot = json_object_new_object();
			if (cfgRoot) {
				json_object_object_add(cfgRoot, CFG_PREFIX, cfgObj);
				snprintf((char *)outData, outDataLen, "%s", json_object_to_json_string(cfgRoot));
				DBG_INFO("convertedData(%s)", outData);
				json_object_put(cfgRoot);
			}
			else
				json_object_put(cfgObj);
		}
		else
			DBG_INFO("cfgObj is NULL");
	}

	json_object_put(connDiagRoot);

	return strlen((char *)outData);
} /* End of cm_convertConnDiagData */

/*
========================================================================
Routine Description:
	Process REQ_CHKSTA packet.

Arguments:
	data		- data from conn_diag

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_CHKSTA(unsigned char *data, size_t dataLen, char *peerIp)
{
	unsigned char *decryptedMsg = NULL;
	unsigned char msg[MAX_IPC_PACKET_SIZE] = {0};
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey = cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);

	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (cm_convertConnDiagData(decryptedMsg, peerIp, &msg[0], sizeof(msg)))
		cm_sendEventToConnDiag(&msg[0]); /* send event to conn_diag */
	
	MFREE(decryptedMsg);

	return 1;	
} /* End of cm_processREQ_CHKSTA */

/*
========================================================================
Routine Description:
	Process RSP_CHKSTA packet.

Arguments:
	data		- data from conn_diag

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processRSP_CHKSTA(unsigned char *data, size_t dataLen, char *peerIp)
{
	unsigned char *decryptedMsg = NULL;
	unsigned char msg[MAX_IPC_PACKET_SIZE] = {0};
	unsigned char *groupKey = NULL;
	unsigned char *groupKeyExpired = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		return 0;
	}

	/* select group key */
	if ((groupKey = cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}

	/* select another group key for expired */
	groupKeyExpired = cm_selectGroupKey(0);

	/* decrypt data */
	decryptedMsg = cm_aesDecryptMsg(groupKey, groupKeyExpired, data, dataLen);

	if (IsNULL_PTR(decryptedMsg)) {
		DBG_ERR("Failed to aes_decrypt() !!!");
		return 0;
	}

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (cm_convertConnDiagData(decryptedMsg, peerIp, &msg[0], sizeof(msg)))
		cm_sendEventToConnDiag(&msg[0]); /* send event to conn_diag */
	
	MFREE(decryptedMsg);

	return 1;
} /* End of cm_processRSP_CHKSTA */

/*
========================================================================
Routine Description:
	Process conn_diag packets.

Arguments:
	tlv		- tlv header of the packet
	*data		- data from other AP
	*peerIp		- the ip of AP

Return Value:
        None

========================================================================
*/ 
void cm_processConnDiagPkt(TLV_Header tlv, unsigned char *data, char *peerIp)
{
	struct connDiagPacketHandler *handler = NULL;

	for(handler = &connDiagPacketHandlers[0]; handler->type > 0; handler++) {
		if (handler->type == ntohl(tlv.type))
			break;
	}

	if (handler == NULL || handler->type < 0)
		DBG_INFO("no corresponding function pointer(%d)", ntohl(tlv.type));
	else
	{
		DBG_INFO("process packet (%d)", handler->type);
		if (!handler->func(data, ntohl(tlv.len), peerIp)) {
			DBG_ERR("fail to process corresponding packet");
			return;
		}
	} 
} /* End of cm_processConnDiagPkt */


/*
========================================================================
Routine Description:
	Process EID_RM_STA_CHK_ONE event.

Arguments:
	data		- data from conn_diag

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processChkOne(unsigned char *data)
{
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	unsigned char *groupKey = NULL;
	char peerIp[18];

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		goto err;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}
	
	/* encrypt data */
	encryptedMsg = cm_aesEncryptMsg(groupKey, REQ_CHKSTA, data, strlen((char *)data) + 1, &encLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
	}

	/* broadcast ip */
	snprintf(peerIp, sizeof(peerIp), "%d.%d.%d.%d", 
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 24) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 16) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) >> 8) & 0xFF,
			(htonl(cm_ctrlBlock.broadcastAddr.s_addr) & 0xFF));

	/* send udp packet */
	if (cm_sendUdpPacket(peerIp, encryptedMsg, encLen) == 0) {
		DBG_ERR("Fail to send UDP packet to %s!", peerIp);
		goto err;
	}

	ret = 1;

err:

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return ret;
} /* End of cm_processChkOne */

/*
========================================================================
Routine Description:
	Process EID_RM_STA_CHK_ONE_RSP event.

Arguments:
	data		- data from conn_diag

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processChkOneRsp(unsigned char *data)
{
	json_object *root = NULL;
	json_object *connDiagObj = NULL;
	json_object *pipObj = NULL;
	unsigned char *encryptedMsg = NULL;
	size_t encLen = 0;
	int ret = 0;
	char peerIp[32] = {0};
	unsigned char *groupKey = NULL;

	/* check key is valid or not */
	if (!cm_ctrlBlock.groupKeyReady) {
		DBG_ERR("key is not ready !!!");
		goto err;
	}

	/* select group key */
	if ((groupKey= cm_selectGroupKey(1)) == NULL) {
		DBG_ERR("no group key be selected");
		return 0;
	}
	
	/* encrypt data */
	encryptedMsg = cm_aesEncryptMsg(groupKey, RSP_CHKSTA, data, strlen((char *)data) + 1, &encLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
	}

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CHKSTA_PREFIX, &connDiagObj);
	json_object_object_get_ex(connDiagObj, RAST_PEERIP, &pipObj);

	if (pipObj) {
		snprintf(peerIp, sizeof(peerIp), "%s", json_object_get_string(pipObj));
		/* send udp packet */
		if (cm_sendUdpPacket(peerIp, encryptedMsg, encLen) == 0) {
			DBG_ERR("Fail to send UDP packet to %s!", peerIp);
			goto err;
		}
	}

	ret = 1;
	
err:

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	json_object_put(root);

	return ret;
} /* End of cm_processChkOneRsp */

/*
========================================================================
Routine Description:
	Process packets from conn_diag.

Arguments:
	data		- received data

Return Value:
	0		- continue to receive
        1		- break to receive

========================================================================
*/
int cm_connDiagPacketProcess(unsigned char *data)
{
	json_object *root = NULL;
	json_object *connDiagObj = NULL;
	json_object *eidObj = NULL;
	int eid = 0;
	struct eventHandler *handler = NULL;
	int ret = 0;

	/* need check group key expired or not before using group key */
	if (cm_checkGroupKeyExpire()) { // group key expired
		DBG_ERR("group key expired");
		goto err;
	}

	root = json_tokener_parse((char *)data);
	json_object_object_get_ex(root, CHKSTA_PREFIX, &connDiagObj);
	json_object_object_get_ex(connDiagObj, RAST_EVENT_ID, &eidObj);

	DBG_INFO("received data (%s)", (char *)data);

	if (eidObj) {
		eid = atoi(json_object_get_string(eidObj));

		for(handler = &connDiagEventHandlers[0]; handler->type > 0; handler++) {
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

	json_object_put(root);

	return ret;
} /* End of cm_connDiagPacketProcess */

/*
========================================================================
Routine Description:
	Add conn_diag packets into to list

Arguments:
	*data		- data from other AP

Return Value:
        None

========================================================================
*/
void cm_addConnDiagPktToList(void *data)
{
	if (!connDiagUdpList) {
		DBG_ERR("connDiagUdpList is NULL");
		if (data) {
			DBG_ERR("free udp packet data");
			free(data);
		}
		return;
	}

	pthread_mutex_lock(&connDiagLock);

	/* add conn diag pkt to list */
	DBG_INFO("add conn diag pkt to list");
	listnode_add(connDiagUdpList, (void*)data);

	pthread_mutex_unlock(&connDiagLock);
} /* End of cm_addConnDiagPktToList */

/*
========================================================================
Routine Description:
	Timer for differnt event.

Arguments:
	*args		- argument for thread

Return Value:
	None

Note:
========================================================================
*/
void cm_processConnDiagPktList()
{
	struct udpDataStruct *mylist = NULL;
	struct listnode *ln = NULL;
	unsigned char *pData = NULL;
	TLV_Header tlv;

	pthread_mutex_lock(&connDiagLock);

	if (connDiagUdpList->count > 0) {
		LIST_LOOP(connDiagUdpList, mylist, ln)
		{
			if (terminateConnDiagPktList)
				break;

			if (IsNULL_PTR(mylist->data)) {
				DBG_ERR("data is null!");
				continue;
			}

			pData = (unsigned char *)&mylist->data[0];

			memset(&tlv, 0, sizeof(TLV_Header));
			memcpy((unsigned char *)&tlv, (unsigned char *)pData, sizeof(TLV_Header));
			pData += sizeof(TLV_Header);

			if (ntohl(tlv.len) != (mylist->dataLen - sizeof(TLV_Header))) {
				DBG_ERR("Checking length error !!!");
				continue;
			}

			if (Adv_CRC32(0, pData, ntohl(tlv.len)) != ntohl(tlv.crc)) {
				DBG_ERR("Verify checksum error !!!");
				continue;
			}

			if (ntohl(tlv.type) == RSP_CHKSTA) {	/* RSP_CHKSTA pkg */
				DBG_INFO("update for %s", mylist->peerIp);
				cm_processConnDiagPkt(tlv, (unsigned char *)&pData[0], mylist->peerIp);
			}
		}

		list_delete_all_node(connDiagUdpList);
	}

	pthread_mutex_unlock(&connDiagLock);
} /* End of cm_processConnDiagPktList */

/*
========================================================================
Routine Description:
	Timer for differnt event.

Arguments:
	*args		- argument for thread

Return Value:
	None

Note:
========================================================================
*/
void *cm_connDiagPktListHandler(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif
	pthread_detach(pthread_self());

	if (!connDiagUdpList) {
		DBG_ERR("connDiagUdpList is NULL");
#ifdef PTHREAD_EXIT
		return (void *)1;
#else
		pthread_exit(NULL);
#endif
	}

	DBG_INFO("enter");

	while (terminateConnDiagPktList == 0) {
		cm_processConnDiagPktList();
		usleep(1000);
	}

	DBG_INFO("leave");
	leaveConnDiagPktList = 1;

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_connDiagPktListHandler */

/*
========================================================================
Routine Description:
	Terminate pkt handle for conn diag.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_terminateConnDiagPktList()
{
	int i = 1;

	terminateConnDiagPktList = 1;

	while (i <= 5) {
		if (leaveConnDiagPktList)
			break;
		sleep(1);
		i++;
	}
} /* End of cm_terminateConnDiagPktList */
