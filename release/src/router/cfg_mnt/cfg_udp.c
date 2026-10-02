#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <shared.h>
#include <shutils.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_roaming.h"
#ifdef CONN_DIAG
#include "cfg_conndiag.h"
#endif
#include "cfg_udp.h"

/* for udp packet handler */
struct udpArgStruct {
	unsigned char data[MAX_UDP_PACKET_SIZE];
	size_t dataLen;
	char peerIp[32];
}udpArgs;

/*
========================================================================
Routine Description:
	Send UDP packet out.

Arguments:
        ip              - broadcast or unicast ip
        *msg             - plain message
        msgLen          - the length of plain message

Return Value:
        0               - fail
        1               - success

========================================================================
*/
int cm_sendUdpPacket(char *ip, unsigned char *msg, size_t msgLen)
{
	int sockfd;
	struct sockaddr_in their_addr;
	int numbytes;
	int broadcast = 1;
	int ret = 0;

	memset((char *) &their_addr, 0, sizeof(their_addr));
	their_addr.sin_family = AF_INET; // host byte order
	their_addr.sin_port = htons(port); // short, network byte order
	if (inet_aton(ip, &their_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", ip);
		return ret;
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		DBG_ERR("create socket failed!");
		return ret;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast,
		sizeof(broadcast)) == -1) {
		DBG_ERR("setsockopt (SO_BROADCAST) failed!");
		goto err;
	}

	if ((numbytes=sendto(sockfd, msg, msgLen, 0,
		(struct sockaddr *)&their_addr, sizeof(their_addr))) == -1) {
		DBG_ERR("sendto failed!");
		goto err;
	}

	DBG_INFO("sent %d bytes to %s", numbytes,
	inet_ntoa(their_addr.sin_addr));

	ret = 1;

err:
	if (sockfd)
		close(sockfd);

	return ret;
} /* End of cm_sendUdpPacket */


/*
========================================================================
Routine Description:
        Create a thread to handle received UDP packets.

Arguments:
        *args           - arguments for udp packet

Return Value:
        None

Note:
========================================================================
*/
void *cm_udpPacketHandler(void *args)
{

#if defined(RTCONFIG_RALINK_MT7621)     
        Set_CPU();
#endif  
        pthread_detach(pthread_self());
	unsigned char *pData = NULL;
        struct udpArgStruct *udpArgs = (struct udpArgStruct *)args;
	TLV_Header tlv;
	int len = 0;

	if (IsNULL_PTR(udpArgs->data)) {
		DBG_ERR("data is null!");
		goto err;
	}

	pData = (unsigned char *)&udpArgs->data[0];
	len = udpArgs->dataLen;

	if (sizeof(TLV_Header) > len) {
		DBG_WARNING("Error on receive size !!!");
		goto err;
	}

	//DBG_INFO("data(%s), dataLen(%d)", udpArgs->data, udpArgs->dataLen);
	//DBG_INFO("peer ip(%s)", udpArgs->peerIp);
	memset(&tlv, 0, sizeof(TLV_Header));
	memcpy((unsigned char *)&tlv, (unsigned char *)pData, sizeof(TLV_Header));
	pData += sizeof(TLV_Header);

	if (ntohl(tlv.len) != (len - sizeof(TLV_Header))) {
		DBG_ERR("Checking length error !!!");
		goto err;
	}

	if (Adv_CRC32(0, pData, ntohl(tlv.len)) != ntohl(tlv.crc)) {
		DBG_ERR("Verify checksum error !!!");
		goto err;
	}

#ifdef LEGACY_ROAMING
	/* for roaming packet */
	if ((ntohl(tlv.type) >= REQ_STAMON && ntohl(tlv.type) <= REQ_STAFILTER)
#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
		|| (ntohl(tlv.type) == REQ_EXAPCHECK)
#endif
		) {
		cm_processRoamingPkt(tlv, (unsigned char *)&pData[0], udpArgs->peerIp);
	}
#endif

#ifdef CONN_DIAG
	/* for conn_diag packet */
	if (ntohl(tlv.type) >= REQ_CHKSTA && ntohl(tlv.type) <= RSP_CHKSTA) {
		cm_processConnDiagPkt(tlv, (unsigned char *)&pData[0], udpArgs->peerIp);
	}
#endif

err:

        free(args);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_udpPacketHandler */

/*
========================================================================
Routine Description:
        Handle received UDP packets.

Arguments:
        None

Return Value:
        None

Note:
========================================================================
*/
void cm_rcvUdpHandler()
{
	unsigned char pPktBuf[MAX_UDP_PACKET_SIZE] = {0};
	int numBytes;
	struct sockaddr_in peerAddr;
	socklen_t addrLen;
	pthread_t udpPacketThread;
	struct udpArgStruct *args = NULL;
	TLV_Header tlv;

	memset(pPktBuf, 0, sizeof(pPktBuf));

	memset(&peerAddr, 0, sizeof(peerAddr));
	addrLen = sizeof(struct sockaddr_in);

	if ((numBytes = recvfrom(cm_ctrlBlock.socketUdpSendRcv, pPktBuf, MAX_UDP_PACKET_SIZE-1 , 0,
		(struct sockaddr *)&peerAddr, &addrLen)) == -1) {
		DBG_ERR("recvfrom");
		return;
	}

	if (peerAddr.sin_addr.s_addr == cm_ctrlBlock.ownAddr.s_addr) {
		DBG_INFO("skip UDP broacast packet from us!");
		return;
	}

	DBG_INFO("own addr %d.%d.%d.%d",
		(htonl(cm_ctrlBlock.ownAddr.s_addr) >> 24) & 0xFF,
		(htonl(cm_ctrlBlock.ownAddr.s_addr) >> 16) & 0xFF,
		(htonl(cm_ctrlBlock.ownAddr.s_addr) >> 8) & 0xFF,
		(htonl(cm_ctrlBlock.ownAddr.s_addr) & 0xFF));

	DBG_INFO("got packet from %d.%d.%d.%d",
		(htonl(peerAddr.sin_addr.s_addr) >> 24) & 0xFF,
		(htonl(peerAddr.sin_addr.s_addr) >> 16) & 0xFF,
		(htonl(peerAddr.sin_addr.s_addr) >> 8) & 0xFF,
		(htonl(peerAddr.sin_addr.s_addr) & 0xFF));

	memset(&tlv, 0, sizeof(TLV_Header));
	memcpy((unsigned char *)&tlv, (unsigned char *)&pPktBuf[0], sizeof(TLV_Header));
	DBG_INFO("tlv len(%ld,0x%02x), received bytes(%d), received bytes w/o tlv(%d)",
		ntohl(tlv.len), ntohl(tlv.len), numBytes, (numBytes - sizeof(TLV_Header)));

	if (sizeof(TLV_Header) > numBytes) {
		DBG_INFO("error on received size(%d)", numBytes);
		return;
	}

	if (ntohl(tlv.len) < 0 || ntohl(tlv.len) != (numBytes - sizeof(TLV_Header))) {
		DBG_INFO("error on check size");
		return;
	}

	args = malloc(sizeof(struct udpArgStruct));

	if (args == NULL) {
		DBG_ERR("malloc on args failed");
		return;
	}

	memset(args, 0, sizeof(struct udpArgStruct));
	//memset(args->data, 0, sizeof(args->data));
	//memset(args->peerIp, 0, sizeof(args->peerIp));
	memcpy(args->data, (unsigned char *)&pPktBuf[0], numBytes);
	args->dataLen = numBytes;
	snprintf(args->peerIp, sizeof(args->peerIp),    "%d.%d.%d.%d",
		(htonl(peerAddr.sin_addr.s_addr) >> 24) & 0xFF,
		(htonl(peerAddr.sin_addr.s_addr) >> 16) & 0xFF,
		(htonl(peerAddr.sin_addr.s_addr) >> 8) & 0xFF,
		(htonl(peerAddr.sin_addr.s_addr) & 0xFF));

#ifdef CONN_DIAG
	/* for conn_diag packet */
	if (ntohl(tlv.type) == RSP_CHKSTA)
		cm_addConnDiagPktToList(args);
	else
#endif
	if (pthread_create(&udpPacketThread, attrp, cm_udpPacketHandler, (void *)args) != 0) {
		DBG_ERR("could not create thread !!!");
		free(args);
	}
} /* End of cm_rcvUdpHandler */
