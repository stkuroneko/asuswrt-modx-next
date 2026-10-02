#ifndef __CFG_UDP_H__
#define __CFG_UDP_H__

extern int cm_sendUdpPacket(char *ip, unsigned char *msg, size_t msgLen);
extern void cm_rcvUdpHandler();

#define MAX_UDP_PACKET_SIZE		2048

#endif /* __CFG_UDP_H__ */
/* End of cfg_udp.h */
