#ifndef __CFG_ROAMING_H__
#define __CFG_ROAMING_H__

enum romaingStatus {
	RM_SUCCESS = 1,
	RM_FAIL,
	RM_OTHERS
};

#if 0
enum roamingPkgType {
	REQ_STAMON = 1,
	RSP_MONRPT,
	REQ_ACL
};
#endif

#define REPORT_WAITING_TIME	3
#define REPORT_ROOT_PATH	"/tmp"
#define ROAMING_RSSI_TOLERANCE	10
#define ROAMING_RCPI_TOLERANCE  5

extern void cm_processRoamingPkt(TLV_Header tlv, unsigned char *data, char *peerIp);
extern void cm_rcvRastHandler(int sock);
extern int cm_sendStaFilterPkt();
extern int cm_rastPacketProcess(unsigned char *data);
extern int cm_sendEventToRast(unsigned char *data);

#endif /* __CFG_ROAMING_H__ */
/* End of cfg_roaming.h */
