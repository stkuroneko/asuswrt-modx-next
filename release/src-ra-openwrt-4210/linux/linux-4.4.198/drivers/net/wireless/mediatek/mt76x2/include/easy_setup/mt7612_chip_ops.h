/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology	5th	Rd.
 * Science-based Industrial	Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2004, Ralink Technology, Inc.
 *
 * All rights reserved.	Ralink's source	code is	an unpublished work	and	the
 * use of a	copyright notice does not imply	otherwise. This	source code
 * contains	confidential trade secret material of Ralink Tech. Any attemp
 * or participation	in deciphering,	decoding, reverse engineering or in	any
 * way altering	the	source code	is stricitly prohibited, unless	the	prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	cmm_ez.c

	Abstract:
	Easy Setup APIs

	Revision History:
	Who			When			What
	--------	----------		----------------------------------------------
*/
#ifndef __MT7612_EZ_chip_ops_H__
#define __MT7612_EZ_chip_ops_H__

#ifdef WH_EZ_SETUP
#include "rt_config.h"


#define SET_AUTHMODE_WPA2PSK(_Auth)  (_Auth = Ndis802_11AuthModeWPA2PSK)
#define SET_CIPHER_CCMP128(_encry)  (_encry = Ndis802_11AESEnable)

int EzDebugLevel = DBG_LVL_ERROR;

#define EZ_DEBUG(__debug_cat, __debug_sub_cat, __debug_level, __fmt) \
	do { \
		if (__debug_level <= EzDebugLevel) { \
			printk __fmt;\
		} \
	} while (0)

#define EZ_TIMER_INIT(__ad, __data, __time_var, __time_flg, __time_fn) \
	do { \
		RTMPInitTimer((__ad), (__time_var),\
		GET_TIMER_FUNCTION(__time_fn), (__data), FALSE); \
		(__time_flg) = FALSE; \
	} while (0)

#define EZ_CANCEL_TIMER(__time_var, __time_flg) \
	do { \
		unsigned char __cancelled; \
		RTMPCancelTimer(__time_var, &__cancelled); \
		(__time_flg) = FALSE; \
	} while (0)

typedef struct ez_timer_s {
	RALINK_TIMER_STRUCT ez_timer;
	BOOLEAN ez_timer_running;
} ez_timer_t;

VOID UpdateBeaconHandler(
	void *ad_obj,
	struct wifi_dev *wdev,
	UCHAR BCN_UPDATE_REASON);

void ez_hex_dump(
	char *str,
	unsigned char *pSrcBufVA,
	unsigned int SrcBufLen);

void ez_install_pairwise_key_mt7612(
	PRTMP_ADAPTER pAd,
	struct wifi_dev *wdev,
	char *peer_mac,
	unsigned char *pmk,
	unsigned char *ptk,
	unsigned char authenticator);

unsigned char ez_RandomByte_mt7612(PRTMP_ADAPTER pAd);

void ez_DH_PublicKey_Generate_mt7612(
	UINT8 GValue[],
	UINT GValueLength,
	UINT8 PValue[],
	UINT PValueLength,
	UINT8 PrivateKey[],
	UINT PrivateKeyLength,
	UINT8 PublicKey[],
	UINT *PublicKeyLength);

void ez_RT_DH_SecretKey_Generate_mt7612(
	UINT8 PublicKey[],
	UINT PublicKeyLength,
	UINT8 PValue[],
	UINT PValueLength,
	UINT8 PrivateKey[],
	UINT PrivateKeyLength,
	UINT8 SecretKey[],
	UINT *SecretKeyLength);

void ez_RT_SHA256_mt7612(
	IN  const UINT8 Message[],
	IN  UINT MessageLen,
	OUT UINT8 DigestMessage[]);

VOID ez_WpaDerivePTK_mt7612(
	PRTMP_ADAPTER pAd,
	UCHAR *PMK,
	UCHAR *ANonce,
	UCHAR *AA,
	UCHAR *SNonce,
	UCHAR *SA,
	UCHAR *output,
	UINT len);

INT ez_AES_Key_Unwrap_mt7612(
	UINT8 CipherText[],
	UINT CipherTextLength,
	UINT8 Key[],
	UINT KeyLength,
	UINT8 PlainText[],
	UINT *PlainTextLength);


#ifdef APCLI_SUPPORT
void ez_apcli_install_group_key_mt7612(
	PRTMP_ADAPTER pAd,
	char *peer_gtk,
	unsigned char gtk_len,
	PMAC_TABLE_ENTRY pentry);
#endif /* APCLI_SUPPORT */

INT ez_wlan_config_get_ht_bw_mt7612(PRTMP_ADAPTER pAd);

#ifdef DOT11_VHT_AC
INT ez_wlan_config_get_vht_bw_mt7612(PRTMP_ADAPTER pAd);
#endif

INT ez_wlan_operate_get_ht_bw_mt7612(PRTMP_ADAPTER pAd);

INT ez_wlan_operate_get_ext_cha_mt7612(PRTMP_ADAPTER pAd);

INT ez_wlan_config_get_ext_cha_mt7612(PRTMP_ADAPTER pAd);

int ez_get_cli_aid_mt7612(
	PRTMP_ADAPTER pAd,
	char *peer_mac);

void ez_cancel_timer_mt7612(
	PRTMP_ADAPTER pAd,
	void *timer_struct);

void ez_set_timer_mt7612(
	PRTMP_ADAPTER pAd,
	void *timer_struct,
	unsigned long time);

int ez_is_timer_running_mt7612(
	PRTMP_ADAPTER pAd,
	void *timer_struct);

#ifdef APCLI_SUPPORT
int get_apcli_enable_mt7612(
	PRTMP_ADAPTER pAd,
	int ifIndex);
#endif

int ez_ApScanRunning_mt7612(PRTMP_ADAPTER pAd);

void ez_send_unicast_deauth_mt7612(
	void *ad_obj,
	UCHAR *peer_addr);

void ez_UpdateBeaconHandler_mt7612(
	RTMP_ADAPTER *ez_ad, 
	struct wifi_dev *wdev, 
	UCHAR reason);
void ez_update_security_setting_mt7612(
	PRTMP_ADAPTER pAd,
	struct wifi_dev *wdev,
	unsigned char *pmk);

#ifdef WSC_AP_SUPPORT
void ez_updage_ap_wsc_profile_mt7612(
	PRTMP_ADAPTER pAd,
	struct wifi_dev *wdev,
	unsigned char if_idx);
#endif /* WSC_AP_SUPPORT */

void ez_MiniportMMRequest_mt7612(
	PRTMP_ADAPTER pAd,
	UCHAR QueIdx,
	UCHAR *out_buf,
	UINT frame_len);

void ez_NdisGetSystemUpTime_mt7612(ULONG *time);

INT ez_AES_Key_Wrap_mt7612(
	UINT8 PlainText[],
	UINT  PlainTextLength,
	UINT8 Key[],
	UINT  KeyLength,
	UINT8 CipherText[],
	UINT *CipherTextLength);

INT ez_RtmpOSWrielessEventSendExt_mt7612(
	PNET_DEV pNetDev,
	UINT32 eventType,
	INT flags,
	PUCHAR pSrcMac,
	PUCHAR pData,
	UINT32 dataLen);

void ez_send_broadcast_deauth_mt7612(
	PRTMP_ADAPTER pAd,
	struct wifi_dev *wdev);

void ez_ChipOp_MgtMacHeaderInit_mt7612(
	void *pAd,
	HEADER_802_11 *pHdr80211,
	UCHAR SubType,
	UCHAR ToDs,
	UCHAR *pDA,
	UCHAR *pSA,
	UCHAR *pBssid);

void ez_ChipOp_apcli_stop_auto_connect_mt7612(
	void *pAd,
	BOOLEAN enable);

void ez_timer_init_mt7612(
	PRTMP_ADAPTER pAd,
	void *timer,
	void *callback);

void ez_set_ap_ssid_null_mt7612(
	PRTMP_ADAPTER pAd,
	INT apidx);

void ez_set_entry_apcli_mt7612(
	PRTMP_ADAPTER pAd,
	UCHAR *mac_addr,
	BOOLEAN is_apcli);

void *ez_get_pentry_mt7612(
	PRTMP_ADAPTER pAd,
	UCHAR *mac_addr);

void ez_mark_entry_duplicate_mt7612(
	PRTMP_ADAPTER pAd,
	UCHAR *mac_addr);

void ez_restore_cli_config_mt7612(void *pAd);

void ez_ScanTableInit_mt7612(PRTMP_ADAPTER pAd);


void ez_wlan_operate_set_ht_bw_mt7612(
	PRTMP_ADAPTER pAd,
	UINT8 ht_bw);

void ez_wlan_operate_set_ext_cha_mt7612(
	PRTMP_ADAPTER pAd,
	UINT8 ext_cha);

INT	rtmp_set_channel_mt7612(
	PRTMP_ADAPTER pAd,
	struct wifi_dev *wdev,
	UCHAR Channel);

void ez_APScanCnclAction_mt7612(PRTMP_ADAPTER pAd);

/* Form and transmit Custom loop detect Pkt*/
void ez_send_loop_detect_pkt_mt7612(
	IN	PRTMP_ADAPTER	pAd,
	IN  PMAC_TABLE_ENTRY pMacEntry,
	IN  PUCHAR          pOtherCliMac);


#ifdef DOT11_N_SUPPORT

/*
*	========================================================================
*	Rakesh: based on ApCliCheckHt
*
*	========================================================================
*/
BOOLEAN ez_ApCliSetHt_mt7612(
	IN PAPCLI_STRUCT pApCliEntry,
	PMAC_TABLE_ENTRY pEntry);

#endif

void ez_update_cli_peer_record_mt7612(
	void *ad_obj,
	void *wdev_obj,
	BOOLEAN band_switched,
	PUCHAR peer_addr);


void ez_update_ap_peer_record_mt7612(
	void *ad_obj,
	void *wdev_obj,
	BOOLEAN band_switched,
	PUCHAR peer_addr);

#endif
#endif

