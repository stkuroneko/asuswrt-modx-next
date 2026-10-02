/************************************************************/
/*  Version 1.4     by Yuhsin_Lee 2005/1/19 16:31           */
/************************************************************/

#ifndef __PACKET_H__
#define __PACKET_H__

#ifdef __cplusplus
extern "C" {
#endif
#define TYPEDEF_BOOL
#include <stdbool.h>
#include <bcmnvram.h>
#include <bcmparams.h>
#include <shared.h>
#include <ctype.h>
#include <signal.h>
#include "utility.h"

#pragma pack(1)

/****************************************/
/*              FOR LINUX               */
/****************************************/
#ifndef  WIN32
#define ULONG   unsigned long
#define DWORD   unsigned long
#define BYTE    unsigned char
#define PBYTE   unsigned char *
#define WORD    unsigned short
#define INT     int
#endif //#ifndef  WIN32

/* ===================================================================================================================== */
#define BLE_VERSION		13
#define DEFLEN_32 		32
#define DEFLEN_128 		128
#define DEFLEN_256 		256
#define DEFLEN_512 		512
#define DEFLEN_1024 		1024
#define DEFLEN_65536 		65536

#define MAX_PACKET_SIZE		4096
#define BLE_MAX_MTU_SIZE	20
#define BLECMD_CODE_SIZE	1
#define BLECMD_SEQNO_SIZE	1
#define BLECMD_LEN_SIZE	2
#define BLECMD_CSUM_SIZE	2
#define BLECMD_STATUS_SIZE 1

#define BLE_FLAG_WITH_ENCRYPT 	0x1
#define BLE_FLAG_WITH_CHECKSUM  0x2
#define BLECMD_FLAGS		BLE_FLAG_WITH_CHECKSUM
#define BLE_RESPONSE_FLAGS	BLE_FLAG_WITH_CHECKSUM
#define BLECMD_WITH_ENCRYPT	0x80

#define BLE_PDU_SIZE		3584	//(packet_size - packet_size/20*2 - checksum length - packet lenght - status)/16%16
#define MAX_DETWAN 4
#define MILLISEC		1000

#define APLIST_TXT "/tmp/apscan_info.txt"
#define APLIST_MODIFY_TXT "/tmp/apscan_info_modify.txt"
#define UI_SUPPORT_JSON "/tmp/ui_support.json"
#define FRS_LIVEUPDATEINFO_JSON "/tmp/FrsLiveUpdateInfo.json"
#define IPTV_PROFILE_JSON "/tmp/iptvSettings.json"

/* ===================================================================================================================== */
enum  BLECMD
{
	BLECMD_REQ_PUBLICKEY		= 0x00,
	BLECMD_REQ_SERVERNONCE		= 0x01,
	BLECMD_APPLY			= 0x02,
	BLECMD_RESET			= 0x03,
	BLECMD_GET_WAN_STATUS		= 0x04,
	BLECMD_GET_WIFI_STATUS		= 0x05,
	BLECMD_SET_WAN_TYPE		= 0x06,
	BLECMD_SET_WAN_PPPOE_NAME	= 0x07,
	BLECMD_SET_WAN_PPPOE_PWD	= 0x08,
	BLECMD_SET_WAN_IPADDR		= 0x09,
	BLECMD_SET_WAN_SUBNET_MASK	= 0x0a,
	BLECMD_SET_WAN_GATEWAY		= 0x0b,
	BLECMD_SET_WAN_DNS1		= 0x0c,
	BLECMD_SET_WAN_DNS2		= 0x0d,
	BLECMD_SET_WAN_PORT		= 0x0e,
	BLECMD_SET_WIFI_NAME		= 0x0f,
	BLECMD_SET_WIFI_PWD		= 0x10,
	BLECMD_SET_GROUP_ID		= 0x11,
	BLECMD_SET_ADMIN_NAME		= 0x12,
	BLECMD_SET_ADMIN_PWD		= 0x13,
	BLECMD_SET_USER_LOCATION	= 0x14,
	BLECMD_SET_USER_PLACE		= 0x15,
	BLECMD_SET_SW_MODE		= 0x16,
	BLECMD_SET_WAN_DNS_ENABLE	= 0x17,
	BLECMD_GET_MAC_BLE_VERSION	= 0x18,
	BLECMD_GET_ATH1_CHAN		= 0x19,
	BLECMD_SET_ATH1_CHAN		= 0x1a,
	BLECMD_GET_NVRAM		= 0x1b,
	BLECMD_SET_RC_SERVICE		= 0x1c,
	BLECMD_GET_WAN_CONN_STATE	= 0x1d,
/* Time Zone */
	BLECMD_SET_TZ			= 0x1e,
	BLECMD_SET_TZ_DST		= 0x1f,
	BLECMD_SET_TZ_DSTOFF		= 0x20,
/* Wireless */
#ifdef RTCONFIG_WIRELESSREPEATER
	BLECMD_SCAN_AP			= 0x21,
	BLECMD_GET_SCAN_LIST		= 0x22,
	BLECMD_SET_WLCX_PSTA		= 0x23,
	BLECMD_SET_WLCX_BAND		= 0x24,
	BLECMD_SET_WLCX_SSID		= 0x25,
	BLECMD_SET_WLCX_AUTH_MODE	= 0x26,
	BLECMD_SET_WLCX_CRYPTO		= 0x27,
	BLECMD_SET_WLCX_WPA_PSK		= 0x28,
	BLECMD_SET_WLX_SSID		= 0x29,
	BLECMD_SET_WLX_AUTH_MODE_X	= 0x2a,
	BLECMD_SET_WLX_CRYPTO		= 0x2b,
	BLECMD_SET_WLX_WPA_PSK		= 0x2c,
#endif 
/* LAN */
	BLECMD_SET_LAN_PROTO		= 0x2d,
	BLECMD_SET_LAN_IPADDR		= 0x2e,
	BLECMD_SET_LAN_NETMASK		= 0x2f,
	BLECMD_SET_LAN_GATEWAY		= 0x30,
	BLECMD_SET_LAN_DNSENABLE_X	= 0x31,
	BLECMD_SET_LAN_DNS1_X		= 0x32,
	BLECMD_SET_LAN_DNS2_X		= 0x33,
/* */
#if defined(RTCONFIG_AMAS)
	BLECMD_SET_AIMESHMODE		= 0x34,
#endif
	BLECMD_SET_SWITCH_STB_X		= 0x35,
	BLECMD_SET_SWITCH_WANTAG	= 0x36,
	BLECMD_SET_SWITCH_WANXTAGID	= 0x37,
	BLECMD_SET_SWITCH_WANXPRIO	= 0x38,
	BLECMD_SET_JSON_NVRAM		= 0x39,
	BLECMD_GET_UI_SUPPORT		= 0x3a,
	BLECMD_TRIG_FRS_LIVE_UPDATE	= 0x3b,
	BLECMD_GET_FRS_LIVE_UPDATE_INFO	= 0x3c,
	BLECMD_GET_IPTV_PROFILE		= 0x3d,

	BLECMD_END
};

enum  BLE_RESULT
{
        BLE_RESULT_OK = 0,
        BLE_RESULT_INVALID,
        BLE_RESULT_KEY_INVALID,
        BLE_RESULT_CHECKSUM_INVALID
};

enum BLE_PYH_STATUS
{
	PHY_PORT0	= 0x01,
	PHY_PORT1	= 0x02
};

enum BLE_WAN_STATUS
{
	BLE_WAN_STATUS_ALL_DISCONN=0,
	BLE_WAN_STATUS_ALL_UNKNOWN,
	BLE_WAN_STATUS_PORT0_DHCP,
	BLE_WAN_STATUS_PORT0_PPPOE,
	BLE_WAN_STATUS_PORT0_UNKNOWN,
	BLE_WAN_STATUS_PORT1_DHCP,
	BLE_WAN_STATUS_PORT1_PPPOE,
	BLE_WAN_STATUS_PORT1_UNKNOWN,
	BLE_WAN_STATUS_PORT0_DHCP_PPPOE,
	BLE_WAN_STATUS_PORT1_DHCP_PPPOE,
	BLE_WAN_END
};

enum  BLE_WIFI_STATUS
{
        BLE_WIFI_STATUS_CONNECTED = 0,
        BLE_WIFI_STATUS_PASSWORD_ERROR,
        BLE_WIFI_STATUS_UNKNOWN_ERROR
};

enum BLE_DATA_TYPE
{
	BLE_DATA_TYPE_NULL = 0,
	BLE_DATA_TYPE_STRING,
	BLE_DATA_TYPE_INTEGER,
	BLE_DATA_TYPE_IP
};

/* ===================================================================================================================== */
typedef struct ble_chunk_t        {
        union   {
                struct {
			BYTE cmdno;
			BYTE seqno; // unused now
                	WORD length;
			WORD csum;
			BYTE chunkdata[BLE_MAX_MTU_SIZE-BLECMD_CODE_SIZE-BLECMD_SEQNO_SIZE-BLECMD_LEN_SIZE-BLECMD_CSUM_SIZE];
		} firstcmd;

		struct {
			BYTE cmdno;
			BYTE seqno; // unused no
			WORD length;
			WORD csum;
			BYTE status;
			BYTE chunkdata[BLE_MAX_MTU_SIZE-BLECMD_CODE_SIZE-BLECMD_SEQNO_SIZE-BLECMD_LEN_SIZE-BLECMD_CSUM_SIZE-BLECMD_STATUS_SIZE];
		} firstres;

		struct {
			BYTE chunkdata[BLE_MAX_MTU_SIZE];
		} other;
        } u;
} BLE_CHUNK_T;

typedef struct FileData_t
{
	unsigned char *ku, *kp, *km, *ns, *nc, *ks, *iv, *aplist;
	size_t ku_len, kp_len, ns_len, km_len, nc_len, ks_len, iv_len;
	int aplist_len;
} FileData_s;

struct api_handler {
	int cmdno;
	char *nvram;
	char *do_rc_service;
	int t_type;
	void (*unpack)(struct api_handler *handler, unsigned char *data, int datalen);
	void (*pack)(int cmdno, int status, unsigned char *pdu, int *pdulen);
};

/* ===================================================================================================================== */
int ble_dbg;
FileData_s fileData_s;

/* ===================================================================================================================== */
extern int BLE_EnableDBG(void);
extern int fileExists(char *FileName);
extern unsigned long getFileSize(char *FileName);
extern void Reset_S();
extern int FileRead_Save(char *fileName, unsigned char *fileContent, size_t fileLen);
extern int UnpackBLECommandData(unsigned char *pdu, int pdulen, int *cmdno, unsigned char *data, unsigned int *datalen);
extern void UnpackBLECommandReq(struct api_handler *handler, unsigned char *data, int datalen);
extern void UnpackBLECommandReqServerNonce(struct api_handler *handler, unsigned char *data, int datalen);
extern void UnpackBLEDataToNvram(struct api_handler *handler, unsigned char *data, int datalen);

extern void PackBLEResponseData(int cmdno, int status, unsigned char *data, int datalen, unsigned char *pdu, int *pdulen, int flag);
extern void PackBLEResponseOnly(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetWanStatus(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetWifiStatus(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseReqPublicKey(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseReqServerNonce(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetMacBleVersion(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetAth1Chan(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetWanConnState(int cmdno, int status, unsigned char *pdu, int *pdulen);
#ifdef RTCONFIG_WIRELESSREPEATER
extern void PackBLEResponseScanAP(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetScanList(int cmdno, int status, unsigned char *pdu, int *pdulen);
#endif
extern void PackBLEResponseGetUIsupport(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseTrigFrsLiveUpdate(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetFrsLiveUpdateInfo(int cmdno, int status, unsigned char *pdu, int *pdulen);
extern void PackBLEResponseGetIPTVProfile(int cmdno, int status, unsigned char *pdu, int *pdulen);

extern void UnPackBLEExceptionGetNvram(int cmdno, int status, unsigned char *data, int datalen, unsigned char *pdu, int *pdulen);
extern void UnPackBLEExceptionSetRcSrv(int cmdno, int status, unsigned char *data, int datalen, unsigned char *pdu, int *pdulen);
#ifdef __cplusplus
}
#endif

#endif // #ifndef __PACKET_H__
 
