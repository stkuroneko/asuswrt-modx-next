/*
 ***************************************************************************
 * MediaTek Inc.
 *
 * All rights reserved. source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of MediaTek. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of MediaTek, Inc. is obtained.
 ***************************************************************************

	Module Name:
	band_steering.h
*/

#ifndef _BAND_STEERING_H_
#define __BAND_STEERING_H__

#ifdef BAND_STEERING

/* Debug Level */
#define DBG_LVL_OFF		0
#define DBG_LVL_ERROR	1
#define DBG_LVL_WARN	2
#define DBG_LVL_TRACE	3
#define DBG_LVL_INFO	4
#define DBG_LVL_LOUD	5
#define DBG_LVL_NOISY	6
#define DBG_LVL_MAX		DBG_LVL_NOISY

/* Debug Category */
#define DBG_CAT_INIT    0x00000001u /* initialization/shutdown */
#define DBG_CAT_HW      0x00000002u /* MAC/BBP/RF/Chip */
#define DBG_CAT_FW      0x00000004u /* FW related command, response, CR that FW care about */
#define DBG_CAT_HIF     0x00000008u /* Host interface: usb/sdio/pcie/rbus */
#define DBG_CAT_FPGA    0x00000010u /* FPGA Chip verify, DVT */
#define DBG_CAT_TEST    0x00000020u /* ATE, QA, UT, FPGA?, TDT, SLT, WHQL, and other TEST */
#define DBG_CAT_RA      0x00000040u /* Rate Adaption/Throughput related */
#define DBG_CAT_AP      0x00000080u /* AP, MBSS, WDS */
#define DBG_CAT_CLIENT  0x00000100u /* STA, ApClient, AdHoc, Mesh */
#define DBG_CAT_TX      0x00000200u /* Tx data path */
#define DBG_CAT_RX      0x00000400u /* Rx data path */
#define DBG_CAT_CFG     0x00000800u /* ioctl/oid/profile/cfg80211/Registry */
#define DBG_CAT_MLME    0x00001000u /* 802.11 fundamental connection flow, auth, assoc, disconnect, etc */
#define DBG_CAT_PROTO   0x00002000u /* protocol, ex. TDLS */
#define DBG_CAT_SEC     0x00004000u /* security/key/WPS/WAPI/PMF/11i related*/
#define DBG_CAT_PS      0x00008000u /* power saving/UAPSD */
#define DBG_CAT_POWER   0x00010000u /* power Setting, Single Sku, Temperature comp, etc */
#define DBG_CAT_COEX    0x00020000u /* BT, BT WiFi Coex, LTE, TVWS*/
#define DBG_CAT_P2P     0x00040000u /* P2P, Miracast */
#define DBG_CAT_TOKEN	0x00080000u
#define DBG_CAT_CMW     0x00100000u /* CMW Link Test */
#define DBG_CAT_RSV1    0x40000000u /* reserved index for code development */
#define DBG_CAT_RSV2    0x80000000u /* reserved index for code development */
#define DBG_CAT_ALL     0xFFFFFFFFu

/* Debug SubCategory */
#define DBG_SUBCAT_ALL	0xFFFFFFFFu

typedef char RTMP_STRING;

/* ioctl */
INT Show_BndStrg_List(PRTMP_ADAPTER pAd, RTMP_STRING *arg);
INT Show_BndStrg_Info(PRTMP_ADAPTER pAd, RTMP_STRING *arg);
INT Set_BndStrg_Enable(PRTMP_ADAPTER pAd, RTMP_STRING *arg);
INT Set_BndStrg_Param(PRTMP_ADAPTER pAd, RTMP_STRING *arg);
#ifdef BND_STRG_DBG
INT Set_BndStrg_MonitorAddr(PRTMP_ADAPTER	pAd, RTMP_STRING *arg);
#endif /* BND_STRG_DBG */

INT BndStrg_Init(PRTMP_ADAPTER pAd);
INT BndStrg_Release(PRTMP_ADAPTER pAd);
INT BndStrg_TableInit(PRTMP_ADAPTER pAd, INT apidx);
INT BndStrg_TableRelease(PBND_STRG_CLI_TABLE table);
PBND_STRG_CLI_TABLE Get_BndStrgTable(PRTMP_ADAPTER pAd, INT apidx);

BOOLEAN BndStrg_CheckConnectionReq(
		PRTMP_ADAPTER	pAd,
		struct wifi_dev *wdev,
		PUCHAR pSrcAddr,
	MLME_QUEUE_ELEM *Elem,
	PEER_PROBE_REQ_PARAM *ProbeReqParam);

//INT BndStrg_Tb_Enable(PBND_STRG_CLI_TABLE table, BOOLEAN enable, CHAR *IfName);
INT BndStrg_SetInfFlags(PRTMP_ADAPTER pAd, struct wifi_dev *wdev, PBND_STRG_CLI_TABLE table, BOOLEAN bInfReady);
INT BndStrg_MsgHandle(PRTMP_ADAPTER pAd, RTMP_IOCTL_INPUT_STRUCT *wrq, INT apidx);
#ifdef VENDOR_FEATURE5_SUPPORT
void BndStrg_GetNvram(PRTMP_ADAPTER pAd, RTMP_IOCTL_INPUT_STRUCT *wrq, INT apidx);
void BndStrg_SetNvram(PRTMP_ADAPTER pAd, RTMP_IOCTL_INPUT_STRUCT *wrq, INT apidx);
INT Show_BndStrg_NvramTable(PRTMP_ADAPTER pAd, RTMP_STRING *arg);
#endif /* VENDOR_FEATURE5_SUPPORT */
INT Set_BndStrg_BssIdx(PRTMP_ADAPTER pAd, RTMP_STRING *arg);
void BndStrg_UpdateEntry(PRTMP_ADAPTER pAd, MAC_TABLE_ENTRY *pEntry, IE_LISTS *ie_list, BOOLEAN bConnStatus);
UINT8 GetNssFromHTCapRxMCSBitmask(UINT32 RxMCSBitmask);
extern VOID EnableRadioChstats(PRTMP_ADAPTER 	pAd,UINT32		mac_val);
void BndStrgSetProfileParam(struct _RTMP_ADAPTER *pAd, RTMP_STRING *tmpbuf, RTMP_STRING *pBuffer);
void BndStrgHeartBeatMonitor(PRTMP_ADAPTER	pAd);
INT BndStrgSendMsg(PRTMP_ADAPTER pAd, BNDSTRG_MSG *msg);
void BndStrg_send_BTM_req(IN PRTMP_ADAPTER pAd, IN RTMP_STRING *PeerMACAddr, IN RTMP_STRING *BTMReq, IN UINT32 BTMReqLen, PBND_STRG_CLI_TABLE table);
void BndStrg_Send_NeighborReport(PRTMP_ADAPTER pAd, PBND_STRG_CLI_TABLE table);


#define IS_VALID_MAC(addr) \
	((addr[0])|(addr[1])|(addr[2])|(addr[3])|(addr[4])|(addr[5]))

#ifdef BND_STRG_DBG
#define RED(_text)  "\033[1;31m"_text"\033[0m"
#define GRN(_text)  "\033[1;32m"_text"\033[0m"
#define YLW(_text)  "\033[1;33m"_text"\033[0m"
#define BLUE(_text) "\033[1;36m"_text"\033[0m"

#define BND_STRG_MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, _Level, _Fmt) DBGPRINT(_Level, _Fmt)
#define MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, _Level, _Fmt) DBGPRINT(_Level, _Fmt)

#else /* BND_STRG_DBG */
#define RED(_text)	 _text
#define GRN(_text) _text
#define YLW(_text) _text
#define BLUE(_text) _text

#define BND_STRG_MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, _Level, _Fmt)
#endif /* !BND_STRG_DBG */

#ifdef BND_STRG_QA
#define BND_STRG_PRINTQAMSG(_table, _Addr, _Fmt) \
{	\
	if (MAC_ADDR_EQUAL(_table->MonitorAddr, _Addr))	\
		DBGPRINT(RT_DEBUG_OFF, _Fmt); \
}
#else
#define BND_STRG_PRINTQAMSG(_Level, _Fmt)
#endif /* BND_STRG_QA */

#endif /* BAND_STEERING */
#endif /* _BAND_STEERING_H_ */

