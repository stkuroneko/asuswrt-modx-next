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

#ifdef WH_EZ_SETUP

#include "rt_config.h"
#include "easy_setup/ez_mod_hooks.h"
#include "easy_setup/mt7612_chip_ops_api.h"


UCHAR wlan_config_get_ht_bw(struct wifi_dev *wdev)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)wdev->sys_handle;

	return pAd->CommonCfg.RegTransmitSetting.field.BW;
}

UCHAR wlan_config_get_vht_bw(struct wifi_dev *wdev)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)wdev->sys_handle;

	return pAd->CommonCfg.vht_bw;
}

UCHAR wlan_config_get_ext_cha(struct wifi_dev *wdev)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)wdev->sys_handle;

	return pAd->CommonCfg.RegTransmitSetting.field.EXTCHA;
}

UCHAR wlan_config_get_tx_stream(struct wifi_dev *wdev)
{
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)wdev->sys_handle;

	return pAd->CommonCfg.TxStream;
}

UCHAR ez_driver_ops_RandomByte_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	return RandomByte(pAd);
}

void ez_driver_ops_GenRandom_mt7612(
	void *ezdev,
	UCHAR *macAddr,
	UCHAR *random)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	GenRandom(pAd, macAddr, random);
}

void ez_driver_ops_DH_PublicKey_Generate_mt7612(
	void *ezdev,
	UINT8 GValue[],
	UINT GValueLength,
	UINT8 PValue[],
	UINT PValueLength,
	UINT8 PrivateKey[],
	UINT PrivateKeyLength,
	UINT8 PublicKey[],
	UINT *PublicKeyLength)
{
	DH_PublicKey_Generate(GValue, GValueLength, PValue, PValueLength,
		PrivateKey, PrivateKeyLength, PublicKey, PublicKeyLength);
}

void ez_driver_ops_RT_DH_SecretKey_Generate_mt7612(
	void *ezdev,
	UINT8 PublicKey[],
	UINT PublicKeyLength,
	UINT8 PValue[],
	UINT PValueLength,
	UINT8 PrivateKey[],
	UINT PrivateKeyLength,
	UINT8 SecretKey[],
	UINT *SecretKeyLength)
{
	RT_DH_SecretKey_Generate(PublicKey, PublicKeyLength, PValue, PValueLength,
		PrivateKey, PrivateKeyLength, SecretKey, SecretKeyLength);
}

void ez_driver_ops_RT_SHA256_mt7612(
	void *ezdev,
	IN  const UINT8 Message[],
	IN  UINT MessageLen,
	OUT UINT8 DigestMessage[])
{
	RT_SHA256(Message, MessageLen, DigestMessage);
}

VOID ez_driver_ops_WpaDerivePTK_mt7612(
	void *ezdev,
	UCHAR *PMK,
	UCHAR *ANonce,
	UCHAR *AA,
	UCHAR *SNonce,
	UCHAR *SA,
	UCHAR *output,
	UINT len)
{

	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	WpaDerivePTK(pAd, PMK, ANonce, AA, SNonce, SA, output, len);
}

INT ez_driver_ops_AES_Key_Unwrap_mt7612(
	void *ezdev,
	UINT8 CipherText[],
	UINT CipherTextLength,
	UINT8 Key[],
	UINT KeyLength,
	UINT8 PlainText[],
	UINT *PlainTextLength)
{
	return AES_Key_Unwrap(CipherText, CipherTextLength,
		Key, KeyLength, PlainText, PlainTextLength);
}

void ez_install_pairwise_key_mt7612(
	PRTMP_ADAPTER pAd,
	struct wifi_dev *wdev,
	char *peer_mac,
	unsigned char *pmk,
	unsigned char *ptk,
	unsigned char authenticator)
{
	MAC_TABLE_ENTRY *entry;

	entry = MacTableLookup(pAd, peer_mac);
	SET_AUTHMODE_WPA2PSK(entry->AuthMode);
	SET_ENCRYTYPE_AES(entry->WepStatus);
	SET_ENCRYTYPE_AES(entry->GroupKeyWepStatus);

	if (wdev && (wdev->wdev_type == WDEV_TYPE_AP)) {
		MULTISSID_STRUCT *pMbss = &pAd->ApCfg.MBSSID[wdev->func_idx];

		NdisZeroMemory(&pMbss->PMK[0], LEN_PMK);
		NdisCopyMemory(&pMbss->PMK[0], pmk, LEN_PMK);
	} else if (entry->wdev && entry->wdev->wdev_type == WDEV_TYPE_STA) {
		APCLI_STRUCT *apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];

		NdisZeroMemory(&apcli_entry->PMK[0], LEN_PMK);
		NdisCopyMemory(&apcli_entry->PMK[0], pmk, LEN_PMK);
	}
	NdisZeroMemory(&entry->PTK[0], LEN_PTK);
	NdisCopyMemory(&entry->PTK[0], ptk, LEN_PTK);
	WPAInstallPairwiseKey(pAd, entry->apidx, entry, TRUE);

	/* Update status and set Port as Secured */
	entry->WpaState = AS_PTKINITDONE;
	entry->GTKState = REKEY_ESTABLISHED;
	entry->PrivacyFilter = Ndis802_11PrivFilterAcceptAll;
	entry->PortSecured = WPA_802_1X_PORT_SECURED;
}

void ez_driver_ops_install_pairwise_key_mt7612(
	void *ezdev,
	char *peer_mac,
	unsigned char *pmk,
	unsigned char *ptk,
	unsigned char authenticator)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	ez_install_pairwise_key_mt7612(pAd, wdev, peer_mac, pmk, ptk, authenticator);
}

#ifdef APCLI_SUPPORT
void ez_driver_ops_apcli_install_group_key_mt7612(
	void *ezdev,
	char *peer_mac,
	char *peer_gtk,
	unsigned char gtk_len)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MAC_TABLE_ENTRY *entry;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	entry = MacTableLookup(pAd, peer_mac);
	/* Set Group key material, TxMic and RxMic for AP-Client*/
	if (entry) {
		APCliInstallSharedKey(
			pAd,
			peer_gtk,
			gtk_len,
			1,
			entry);
	}
}
#endif

int ez_driver_ops_wlan_config_get_ht_bw_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	return pAd->CommonCfg.RegTransmitSetting.field.BW;
}

int ez_driver_ops_wlan_config_get_vht_bw_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	return wlan_config_get_vht_bw(wdev);
}

int ez_driver_ops_wlan_operate_get_ht_bw_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	return pAd->CommonCfg.AddHTInfo.AddHtInfo.RecomWidth;
}

int ez_driver_ops_wlan_operate_get_vht_bw_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	return wlan_config_get_vht_bw(wdev);
}

int ez_driver_ops_wlan_config_get_ext_cha_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	return pAd->CommonCfg.RegTransmitSetting.field.EXTCHA;
}

int ez_driver_ops_wlan_operate_get_ext_cha_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	return pAd->CommonCfg.AddHTInfo.AddHtInfo.ExtChanOffset;
}

int ez_driver_ops_get_cli_aid_mt7612(
	void *ezdev,
	char *peer_mac)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MAC_TABLE_ENTRY *pEntry;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	UINT32 ret;

	pEntry = MacTableLookup(pAd, peer_mac);
	if (pEntry)
		ret = pEntry->Aid;
	else {
		DBGPRINT(RT_DEBUG_ERROR, ("%s Entry not found\n", __func__));
		ASSERT(FALSE);
		ret = -1;
	}
	return ret;
}

void ez_driver_ops_ez_cancel_timer_mt7612(
	void *ezdev,
	void *timer_struct)
{
	ez_timer_t *timer = (ez_timer_t *)timer_struct;

	EZ_CANCEL_TIMER(&timer->ez_timer, timer->ez_timer_running);
}

void ez_driver_ops_ez_set_timer_mt7612(
	void *ezdev,
	void *timer_struct,
	unsigned long time)
{
	ez_timer_t *timer = (ez_timer_t *)timer_struct;

	RTMPSetTimer(&timer->ez_timer, time);
	timer->ez_timer_running = TRUE;
}

BOOLEAN ez_driver_ops_is_timer_running_mt7612(
	void *ezdev,
	void *timer_struct)
{
	ez_timer_t *timer = (ez_timer_t *)timer_struct;

	/* Arvind : ToDo*/
	return timer->ez_timer_running;
}

int ez_driver_ops_get_apcli_enable_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
	UINT32 ret;
#ifdef APCLI_SUPPORT
	if (pAd->ApCfg.ApCliTab[wdev->func_idx].Enable)
		ret = TRUE;
	else
#endif
		ret = FALSE;
	return ret;
}

int ez_driver_ops_ApScanRunning_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	if (ApScanRunning(pAd))
		return TRUE;
	else
		return FALSE;
}

BOOLEAN EzMlmeEnqueue(
	IN RTMP_ADAPTER *pAd,
	IN ULONG Machine,
	IN ULONG MsgType,
	IN ULONG MsgLen,
	IN VOID *Msg,
	IN ULONG Priv)
{
	INT Tail;
	MLME_QUEUE	*Queue = (MLME_QUEUE *)&pAd->Mlme.Queue;

	/* Do nothing if the driver is starting halt state.*/
	/* This might happen when timer already been fired before cancel timer with mlmehalt*/
	if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_HALT_IN_PROGRESS | fRTMP_ADAPTER_NIC_NOT_EXIST))
		return FALSE;
	/* First check the size, it MUST not exceed the mlme queue size*/
	if (MsgLen > MGMT_DMA_BUFFER_SIZE) {
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
		("MlmeEnqueue: msg too large, size = %ld\n", MsgLen));
		return FALSE;
	}

	if (MlmeQueueFull(Queue, 1)) {
		return FALSE;
	}
	NdisAcquireSpinLock(&(Queue->Lock));
	Tail = Queue->Tail;
	/*
	*	Double check for safety in multi-thread system.
	*/
	if (Queue->Entry[Tail].Occupied) {
		NdisReleaseSpinLock(&(Queue->Lock));
		return FALSE;
	}
	Queue->Tail++;
	Queue->Num++;
	if (Queue->Tail == MAX_LEN_OF_MLME_QUEUE)
		Queue->Tail = 0;

	Queue->Entry[Tail].Occupied = TRUE;
	Queue->Entry[Tail].Machine = Machine;
	Queue->Entry[Tail].MsgType = MsgType;
	Queue->Entry[Tail].MsgLen = MsgLen;
	Queue->Entry[Tail].Priv = Priv;

	if (Msg != NULL) {
		Queue->Entry[Tail].Wcid = ((MLME_QUEUE_ELEM *)Msg)->Wcid;
		NdisMoveMemory(Queue->Entry[Tail].Msg, Msg, MsgLen);
	}
	NdisReleaseSpinLock(&(Queue->Lock));
	return TRUE;
}

void ez_send_unicast_deauth_ap(void *ad_obj, UCHAR *peer_addr)
{
	MLME_DEAUTH_REQ_STRUCT  *pInfo = NULL;
	MLME_QUEUE_ELEM *Elem;
	MAC_TABLE_ENTRY *pEntry = NULL;
	RTMP_ADAPTER *pAd = ad_obj;
	struct _ez_peer_security_info *ez_peer;
	/*BOOLEAN ez_peer = FALSE;*/
	os_alloc_mem(pAd, (UCHAR **)&Elem, sizeof(MLME_QUEUE_ELEM));
	if (Elem == NULL) {
		EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
			("Set::OID_802_11_DEAUTHENTICATION, Failed!!\n"));
		return;
	}
	if (Elem) {
		pInfo = (MLME_DEAUTH_REQ_STRUCT *) Elem->Msg;
		pInfo->Reason = REASON_NO_LONGER_VALID;
		NdisCopyMemory(pInfo->Addr, peer_addr, MAC_ADDR_LEN);
		pEntry = MacTableLookup(pAd, peer_addr);
		if (pEntry != NULL) {
			Elem->Wcid = pEntry->wcid;
			EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
				("WCID = %d\n;", Elem->Wcid));
			hex_dump("address :", pEntry->Addr, 6);
			ez_peer = ez_peer_table_search_by_addr(pEntry->wdev, pEntry->Addr);
			if (ez_peer && !ez_peer->delete_in_differred_context) {
				ez_APMlmeDeauthReqAction(pAd, Elem);
			} else {
				EzMlmeEnqueue(pAd, AP_AUTH_STATE_MACHINE, APMT2_MLME_DEAUTH_REQ,
					sizeof(MLME_DEAUTH_REQ_STRUCT), Elem, 0);
			}
			EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
				("EZ Set::OID_802_11_DEAUTHENTICATION (Reason=%d)\n", pInfo->Reason));
		}
		os_free_mem(pAd, Elem);
	}
}

void ez_send_unicast_deauth_apcli(void *ad_obj, USHORT idx)
{
	MLME_QUEUE_ELEM *Elem;
	struct _ez_peer_security_info *ez_peer = NULL;
	/*BOOLEAN ez_peer = FALSE;*/
	struct wifi_dev *wdev;
	PRTMP_ADAPTER ad = ad_obj;

	wdev = &ad->ApCfg.ApCliTab[idx].wdev;
	os_alloc_mem(ad_obj, (UCHAR **)&Elem, sizeof(MLME_QUEUE_ELEM));
	if (Elem == NULL) {
		EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
			("Set::OID_802_11_DEAUTHENTICATION, Failed!!\n"));
		return;
	}
	ez_peer = ez_peer_table_search_by_addr(wdev,
		wdev->bssid);
#ifdef EZ_DFS_SUPPORT
	if ((ez_peer && !ez_peer->delete_in_differred_context)
		|| wdev->ez_driver_params.DfsOngoing)
#else
	if (ez_peer && !ez_peer->delete_in_differred_context)
#endif
	{
		Elem->Priv = idx | IMM_DISCONNECT;
		ez_ApCliCtrlDeAuthAction(ad_obj, Elem);
	} else {
		MlmeEnqueue(ad, APCLI_CTRL_STATE_MACHINE, APCLI_CTRL_DISCONNECT_REQ, 0, NULL, idx);
	}
		os_free_mem(ad, Elem);
}


void ez_driver_ops_send_unicast_deauth_mt7612(
	void *ezdev,
	char *peer_mac)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MAC_TABLE_ENTRY *pEntry = NULL;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pEntry = MacTableLookup(pAd, peer_mac);
	RtmpOsMsDelay(50);
	if (pEntry && pEntry->wdev->wdev_type == WDEV_TYPE_AP)
		ez_send_unicast_deauth_ap(ez_dev->driver_ad, peer_mac);
	else if (pEntry && pEntry->wdev->wdev_type == WDEV_TYPE_STA)
		ez_send_unicast_deauth_apcli(ez_dev->driver_ad, pEntry->wdev->func_idx);

}
VOID UpdateBeaconHandler(
	void *ad_obj,
	struct wifi_dev *wdev,
	UCHAR BCN_UPDATE_REASON)
{
	RTMP_ADAPTER *pAd;

	pAd = (RTMP_ADAPTER *)ad_obj;
#ifdef WH_EZ_SETUP
#ifdef DUAL_CHIP
	if (!IS_SINGLE_CHIP_DBDC(pAd)) {
		if ((wdev != NULL) && IS_EZ_SETUP_ENABLED(wdev))
			ez_acquire_lock(pAd, NULL, BEACON_UPDATE_LOCK);
	}
#endif
#endif
	APMakeAllBssBeacon(pAd);
	APUpdateAllBeaconFrame(pAd);

#ifdef WH_EZ_SETUP
#ifdef DUAL_CHIP
	if (!IS_SINGLE_CHIP_DBDC(pAd)) {
		if ((wdev != NULL) && IS_EZ_SETUP_ENABLED(wdev))
			ez_release_lock(pAd, NULL, BEACON_UPDATE_LOCK);
	}
#endif
#endif
}


void ez_driver_ops_UpdateBeaconHandler_mt7612(
	void *ezdev,
	int reason)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	UpdateBeaconHandler(pAd, wdev, (UCHAR)reason);
}

void ez_driver_ops_update_security_setting_mt7612(
	void *ezdev,
	unsigned char *pmk)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	int i;
	unsigned char *ptr;
	PAPCLI_STRUCT pApCliEntry;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
		("------> %s()\n", __func__));
	if (wdev->wdev_type == WDEV_TYPE_AP) {
		MULTISSID_STRUCT *pMbss;

		pMbss = &pAd->ApCfg.MBSSID[wdev->func_idx];
		NdisCopyMemory(&pMbss->PMK[0], pmk, LEN_PMK);
		hex_dump("pMbss_pmk", &pMbss->PMK[0], LEN_PMK);
		ptr = &pMbss->PSK[0];
		NdisZeroMemory(ptr, sizeof(pMbss->PSK));
		for (i = 0; i < LEN_PMK; i++)
			snprintf(ptr, (LEN_PSK+1), "%s%02x", ptr, pmk[i]);

		EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
				("%s() pMbss->PSK: %s (%d)\n",
				__func__, pMbss->PSK, (int)strlen(pMbss->PSK)));
	} else if (wdev->wdev_type == WDEV_TYPE_STA) {
		pApCliEntry = &pAd->ApCfg.ApCliTab[wdev->func_idx];

		NdisCopyMemory(&pApCliEntry->PMK[0], pmk, LEN_PMK);
		hex_dump("pApCliEntry_pmk", &pApCliEntry->PMK[0], LEN_PMK);
		ptr = &pApCliEntry->PSK[0];
		NdisZeroMemory(ptr, sizeof(pApCliEntry->PSK));
		for (i = 0; i < LEN_PMK; i++)
			snprintf(ptr, (LEN_PSK+1), "%s%02x", ptr, pmk[i]);

		pApCliEntry->PSKLen = strlen(pApCliEntry->PSK);
		EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
				("%s()PSK: %s (%d)\n",
				__func__, pApCliEntry->PSK, pApCliEntry->PSKLen));
	}

	EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("<------ %s()\n", __func__));
}


void ez_driver_ops_update_ap_wsc_profile_mt7612(void *ezdev)
{
#ifdef WSC_AP_SUPPORT
		ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
		RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
		struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
		WSC_CTRL *wsc_ctrl;
		MULTISSID_STRUCT *pMbss;

		pMbss = &pAd->ApCfg.MBSSID[wdev->func_idx];
		wsc_ctrl = &pAd->ApCfg.MBSSID[wdev->func_idx].WscControl;
		NdisZeroMemory(&wsc_ctrl->WpaPsk[0], LEN_PSK);
		wsc_ctrl->WpaPskLen = strlen(pMbss->PSK);
		NdisCopyMemory(&wsc_ctrl->WpaPsk[0], pMbss->PSK, wsc_ctrl->WpaPskLen);
#ifdef APCLI_SUPPORT
		if ((wdev->wdev_type == WDEV_TYPE_STA)
			&& (IS_EZ_SETUP_ENABLED(&pAd->ApCfg.MBSSID[wdev->func_idx].wdev))) {
			APCLI_STRUCT *pApCliEntry;

			pApCliEntry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
			NdisZeroMemory(pMbss->PSK, sizeof(pMbss->PSK));
			NdisCopyMemory(pMbss->PSK, pApCliEntry->PSK, sizeof(pMbss->PSK));
		}
#endif /* APCLI_SUPPORT */
		wsc_ctrl->WscConfStatus = WSC_SCSTATE_CONFIGURED;
#endif /* WSC_AP_SUPPORT */
}


void ez_driver_ops_MiniportMMRequest_mt7612(
	void *ezdev,
	char *out_buf,
	int frame_len,
	BOOLEAN need_tx_status)
{
	struct wifi_dev *wdev;
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	wdev = ez_dev->wdev;
	wdev->ez_driver_params.need_tx_satus = need_tx_status;
	MiniportMMRequest(pAd, 0, out_buf, frame_len);
}

void ez_driver_ops_NdisGetSystemUpTime_mt7612(
	void *ezdev,
	ULONG *time)
{
	NdisGetSystemUpTime(time);
}


INT ez_driver_ops_AES_Key_Wrap_mt7612(
	void *ezdev,
	UINT8 PlainText[],
	UINT  PlainTextLength,
	UINT8 Key[],
	UINT  KeyLength,
	UINT8 CipherText[],
	UINT *CipherTextLength)
{
	return AES_Key_Wrap(PlainText, PlainTextLength, Key,
		KeyLength, CipherText, CipherTextLength);
}

INT ez_driver_ops_RtmpOSWrielessEventSendExt_mt7612(
	void *ezdev,
	UINT32 eventType,
	INT flags,
	PUCHAR pSrcMac,
	PUCHAR pData,
	UINT32 dataLen)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	/* Arvind : family field needed*/
	return RtmpOSWrielessEventSendExt(pAd->net_dev, eventType,
	flags, pSrcMac, pData, dataLen, 0);

}

#ifdef EZ_NETWORK_MERGE_SUPPORT
VOID ez_APMlmeBroadcastDeauthReqAction(
		IN PRTMP_ADAPTER pAd,
		IN MLME_QUEUE_ELEM *Elem)
{
	MLME_BROADCAST_DEAUTH_REQ_STRUCT	*pInfo;
	HEADER_802_11			Hdr;
	PUCHAR					pOutBuffer = NULL;
	NDIS_STATUS				NStatus;
	ULONG					FrameLen = 0;
	MAC_TABLE_ENTRY			*pEntry;
	UCHAR					apidx = 0;
	struct wifi_dev         *wdev;
	int wcid, startWcid;

	startWcid = 1;
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
		("%s\n", __func__));
	pInfo = (PMLME_BROADCAST_DEAUTH_REQ_STRUCT)Elem->Msg;
	if (!MAC_ADDR_EQUAL(pInfo->Addr, BROADCAST_ADDR))
		return;

	wdev = pInfo->wdev;
	apidx = wdev->func_idx;
	for (wcid = startWcid; VALID_UCAST_ENTRY_WCID(pAd, wcid); wcid++) {
		pEntry = &pAd->MacTab.Content[wcid];
		if (pEntry->wdev != wdev)
			continue;

		if (IS_EZ_SETUP_ENABLED(wdev) && ez_peer_table_search_by_addr(pEntry->wdev, pEntry->Addr) != NULL)
			continue;

		RTMPSendWirelessEvent(pAd, IW_DEAUTH_EVENT_FLAG, pEntry->Addr, 0, 0);
		ApLogEvent(pAd, pInfo->Addr, EVENT_DISASSOCIATED);
		hex_dump("DeleteEntryAddr", pEntry->Addr, 6);
		MacTableDeleteEntry(pAd, wcid, pEntry->Addr);
#ifdef WH_EVENT_NOTIFIER
		{
			EventHdlr pEventHdlrHook = NULL;

			pEventHdlrHook = GetEventNotiferHook(WHC_DRVEVNT_STA_LEAVE);
			if (pEventHdlrHook && wdev)
				pEventHdlrHook(pAd, wdev, pEntry->Addr, Elem->Channel);
		}
#endif /* WH_EVENT_NOTIFIER */
	}
	NStatus = MlmeAllocateMemory(pAd, &pOutBuffer);
	if (NStatus != NDIS_STATUS_SUCCESS)
		return;
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("AUTH - Send DE-AUTH req to %02x:%02x:%02x:%02x:%02x:%02x\n",
			PRINT_MAC(pInfo->Addr)));
	MgtMacHeaderInit(pAd, &Hdr, SUBTYPE_DEAUTH, 0, pInfo->Addr,
					pAd->ApCfg.MBSSID[apidx].wdev.if_addr,
					pAd->ApCfg.MBSSID[apidx].wdev.bssid);
	MakeOutgoingFrame(pOutBuffer,				&FrameLen,
					  sizeof(HEADER_802_11),	&Hdr,
					  2,						&pInfo->Reason,
					  END_OF_ARGS);
	MiniportMMRequest(pAd, 0, pOutBuffer, FrameLen);
	MlmeFreeMemory(pAd, pOutBuffer);
}
#endif

void ez_driver_ops_send_broadcast_deauth_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MLME_BROADCAST_DEAUTH_REQ_STRUCT  *pInfo = NULL;
	MLME_QUEUE_ELEM *Elem;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	os_alloc_mem(pAd, (UCHAR **)&Elem, sizeof(MLME_QUEUE_ELEM));

	if (Elem == NULL) {
		EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
			("Set::OID_802_11_DEAUTHENTICATION, Failed!!\n"));
		return;
	}
	if (Elem) {
		pInfo = (MLME_BROADCAST_DEAUTH_REQ_STRUCT *) Elem->Msg;
		pInfo->wdev = wdev;
		Elem->Wcid = WCID_ALL;
		pInfo->Reason = MLME_EZ_DISCONNECT_NON_EZ;
		NdisCopyMemory(pInfo->Addr, BROADCAST_ADDR, MAC_ADDR_LEN);
		ez_APMlmeDeauthReqAction(pAd, Elem);
		os_free_mem(pAd, Elem);
	}
}

void ez_driver_ops_apcli_stop_auto_connect_mt7612(
	void *ezdev,
	BOOLEAN enable)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	APCLI_STRUCT *apcli_entry;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	/* Arvind : ToDo by raghav*/
	apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
	apcli_entry->stop_auto_connect = enable;
}

void ez_driver_ops_timer_init_mt7612(
	void *ezdev,
	void *timer,
	void *callback)
{
/*
*ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
*RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
*struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
*Arvind : ToDo
*/
}

void ez_driver_ops_set_ap_ssid_null_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	UCHAR apidx;
	MULTISSID_STRUCT *mbss;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	apidx = wdev->func_idx;
	mbss = &pAd->ApCfg.MBSSID[apidx];
	NdisZeroMemory(mbss->Ssid, MAX_LEN_OF_SSID);
	mbss->SsidLen = 0;
}

void *ez_driver_ops_get_pentry_mt7612(
	void *ezdev,
	UCHAR *mac_addr)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MAC_TABLE_ENTRY *pEntry;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pEntry = MacTableLookup(pAd, mac_addr);
	return pEntry;
}


void ez_driver_ops_reset_entry_duplicate_mt7612(
	void *ezdev,
	UCHAR *mac_addr)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MAC_TABLE_ENTRY *pEntry;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pEntry = MacTableLookup(pAd, mac_addr);
#ifdef WH_EZ_SETUP
#ifdef EZ_DUAL_BAND_SUPPORT
	if (pEntry)
		pEntry->link_duplicate = FALSE;
	else
		EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
		("%s Entry not found !!\n", __func__));
#endif
#endif /* WH_EZ_SETUP */
	EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
	("pEntry->link_duplicate is %d\n", pEntry->link_duplicate));
}



void ez_driver_ops_mark_entry_duplicate_mt7612(
	void *ezdev,
	UCHAR *mac_addr)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	MAC_TABLE_ENTRY *pEntry;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pEntry = MacTableLookup(pAd, mac_addr);
#ifdef WH_EZ_SETUP
#ifdef EZ_DUAL_BAND_SUPPORT
	if (pEntry)
		pEntry->link_duplicate = TRUE;
	else
		EZ_DEBUG(DBG_CAT_CFG, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
		("%s Entry not found !!\n", __func__));
#endif
#endif /* WH_EZ_SETUP */
}

void ez_driver_ops_restore_cli_config_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	APCLI_STRUCT *apcli_entry;
	MULTISSID_STRUCT *pMbss;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

	/*Arvind : todo by raghav*/
	apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
	pMbss = &pAd->ApCfg.MBSSID[wdev->func_idx];
	/*! this is a configuration push so I need to switch back to my older configutration.*/
	NdisZeroMemory(apcli_entry->Ssid, apcli_entry->SsidLen);
	apcli_entry->SsidLen = ez_dev->ez_security.this_band_info.shared_info.ssid_len;
	NdisCopyMemory(apcli_entry->Ssid, ez_dev->ez_security.this_band_info.shared_info.ssid,
		ez_dev->ez_security.this_band_info.shared_info.ssid_len);
	NdisZeroMemory(apcli_entry->CfgSsid, apcli_entry->SsidLen);
	apcli_entry->CfgSsidLen = ez_dev->ez_security.this_band_info.shared_info.ssid_len;
	NdisCopyMemory(apcli_entry->CfgSsid, ez_dev->ez_security.this_band_info.shared_info.ssid,
		ez_dev->ez_security.this_band_info.shared_info.ssid_len);
}

void ez_driver_ops_ScanTableInit_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
/*	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev; */

	BssTableInit(&pAd->ScanTab);
}

void ez_driver_ops_wlan_operate_set_ht_bw_mt7612(
	void *ezdev,
	UINT8 ht_bw)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pAd->CommonCfg.AddHTInfo.AddHtInfo.RecomWidth = ht_bw;
}

void ez_driver_ops_wlan_operate_set_ext_cha_mt7612(
	void *ezdev,
	UINT8 ext_cha)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pAd->CommonCfg.AddHTInfo.AddHtInfo.ExtChanOffset = ext_cha;
}

void ez_driver_ops_rtmp_set_channel_mt7612(
	void *ad_obj, void *wdev_obj,
	UCHAR Channel)
{
	UCHAR tempBuf[20];
	struct wifi_dev *wdev = (struct wifi_dev *)wdev_obj;

	wdev->ez_driver_params.do_not_restart_interfaces = 1;
	sprintf(tempBuf, "%d", Channel);
	Set_Channel_Proc(ad_obj, tempBuf);
	wdev->ez_driver_params.do_not_restart_interfaces = 0;
}

void ez_driver_ops_APScanCnclAction_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	APScanCnclAction(pAd, NULL);
}

static void ez_send_loop_detect_pkt_mt7612(
	IN	PRTMP_ADAPTER	pAd,
	IN  PMAC_TABLE_ENTRY pMacEntry,
	IN  PUCHAR          pOtherCliMac)
{
	UCHAR BROADCAST_ADDR[MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	UCHAR Header802_3[14] = {0};
	UCHAR CustomPayload[26] = {0x45, 0x00,/* version(4bit),*/
								/*hdr lenght(4bit), tos*/
								0x00, 0x1A,/*total ip datagram length*/
								0x00, 0x01,/*identification*/
								0x40, 0x00,/*flag & fragmentation*/
								0x40, 0xFD,/*TTL, Protocol type*/
								0x39, 0xE7,/*hdr checksum*/
								/*(considered 0 for calculation)*/
								0x00, 0x00,/*Source IP*/
								0x00, 0x00,/*Source IP*/
								0xFF, 0xFF,/*Dest IP*/
								0xFF, 0xFF,/*Dest IP*/
								0x11, 0x22,/*Random Bytes*/
								0x33, 0x44,/*Random bytes*/
								0x55, 0x66};/*Random bytes*/

	/*Protocol Type (0x3D any host internal protocol,0x3F any local host network,
	*0xFD & 0xFE for experimentation, 0xFF reserved)
	* 2 byte header checksum field,
	*calculated manually by formula and assuming checksum is zero
	*EZ_DEBUG(DBG_CAT_CLIENT, CATCLIENT_APCLI, EZ_DBG_LVL_OFF,
	*("-----> ez_send_loop_detect_pkt\n"));
	*EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_OFF,
	*("ez_send_loop_detect_pkt---->\n"));
	*/
	NdisZeroMemory(Header802_3, sizeof(UCHAR)*14);
	/* or snap type?*/
	MAKE_802_3_HEADER(Header802_3, BROADCAST_ADDR, &pMacEntry->wdev->if_addr[0], IPV4TYPE);
	/* Using fixed payload due to checksum calculation required using one's complement*/
	NdisCopyMemory(&CustomPayload[20], pOtherCliMac, MAC_ADDR_LEN);
	/*
	*EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_OFF,
	*("ez_send_loop_detect_pkt=> Add in payload Other CLi MAC:
	*%02x-%02x-%02x-%02x-%02x-%02x\n",
	*CustomPayload[20],CustomPayload[21],CustomPayload[22],
	*CustomPayload[23],CustomPayload[24],CustomPayload[25]));
	*Copy frame to Tx ring
	*Pkt 1
	*EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_OFF,
	("ez_send_loop_detect_pkt: wdev_idx:0x%x => Send Loop Detection Pkt 1\n",
	pMacEntry->wdev->wdev_idx));
	*/
	RTMPToWirelessSta((PRTMP_ADAPTER)pAd, pMacEntry,
		Header802_3, LENGTH_802_3, (PUCHAR)CustomPayload, 26, FALSE);
	OS_WAIT(5);

	/* Pkt 2
	*EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_OFF,
	*("ez_send_loop_detect_pkt: wdev_idx:0x%x => Send Loop Detection Pkt 2\n",
	*pMacEntry->wdev->wdev_idx));
	*/
	RTMPToWirelessSta((PRTMP_ADAPTER)pAd, pMacEntry,
		Header802_3, LENGTH_802_3, (PUCHAR)CustomPayload, 26, FALSE);
	OS_WAIT(5);

	/*Pkt 3
	*EZ_DEBUG(DBG_CAT_ALL, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_OFF,
	*("ez_send_loop_detect_pkt: wdev_idx:0x%x => Send Loop Detection Pkt 3\n",
	*pMacEntry->wdev->wdev_idx));
	*/
	RTMPToWirelessSta((PRTMP_ADAPTER)pAd, pMacEntry,
		Header802_3, LENGTH_802_3, (PUCHAR)CustomPayload, 26, FALSE);

	/*EZ_DEBUG(DBG_CAT_CLIENT, CATCLIENT_APCLI, EZ_DBG_LVL_OFF,
	*("<----- ez_send_loop_detect_pkt\n"));
	*/
}


void ez_driver_ops_send_loop_detect_pkt_mt7612(
	void *ezdev,
	PUCHAR pOtherCliMac)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
	PMAC_TABLE_ENTRY pEntry = MacTableLookup2(pAd, ((struct wifi_dev *)(wdev))->bssid, wdev);

	if (pEntry && IS_ENTRY_APCLI(pEntry))
		ez_send_loop_detect_pkt_mt7612(pAd, pEntry, pOtherCliMac);
}

static BOOLEAN ez_ApStaSetHt(
	IN struct wifi_dev *wdev,
	MAC_TABLE_ENTRY *pEntry)
{
	HT_CAPABILITY_IE *aux_ht_cap;
	UCHAR cfg_ht_bw;
	PRTMP_ADAPTER ad = (PRTMP_ADAPTER)wdev->sys_handle;

	cfg_ht_bw = wlan_config_get_ht_bw(wdev);
	aux_ht_cap = &pEntry->HTCapability;
	/* choose smaller setting */
#ifdef CONFIG_MULTI_CHANNEL
	aux_ht_cap->HtCapInfo.ChannelWidth = cfg_ht_bw; /*pAddHtInfo->AddHtInfo.RecomWidth;*/
#else /* CONFIG_MULTI_CHANNEL */
	aux_ht_cap->HtCapInfo.ChannelWidth = cfg_ht_bw; /*pAddHtInfo->AddHtInfo.RecomWidth & cfg_ht_bw;*/
#endif /* !CONFIG_MULTI_CHANNEL */
	/* Fix throughput issue for some vendor AP with AES mode */
	if (cfg_ht_bw) /* remove pAddHtInfo->AddHtInfo.RecomWidth & check*/
		aux_ht_cap->HtCapInfo.CCKmodein40 = ad->CommonCfg.HtCapability.HtCapInfo.CCKmodein40;
	else
		aux_ht_cap->HtCapInfo.CCKmodein40 = 0;
	return TRUE;
}

static BOOLEAN ez_ApStaSetVht(
	IN struct wifi_dev *wdev,
	MAC_TABLE_ENTRY *pEntry)
{
	UCHAR cfg_vht_bw;
	VHT_CAP_IE *pVht_cap_ie = NULL;
	PRTMP_ADAPTER pAd = NULL;
	UCHAR bw;

	pAd = (PRTMP_ADAPTER)wdev->sys_handle;
	bw = pAd->CommonCfg.vht_bw;
	cfg_vht_bw = wlan_config_get_vht_bw(wdev);
	pVht_cap_ie = &pEntry->vht_cap_ie;

	/*Use cfg_vht_bw instead of pAd->CommonCfg.vht_bw*/
	if (cfg_vht_bw == VHT_BW_160) {
		pVht_cap_ie->vht_cap.ch_width = 1;
		pVht_cap_ie->vht_cap.sgi_160M = pAd->CommonCfg.vht_sgi_80;
	} else if (cfg_vht_bw == VHT_BW_8080) {
		pVht_cap_ie->vht_cap.ch_width = 2;
		pVht_cap_ie->vht_cap.sgi_160M = pAd->CommonCfg.vht_sgi_80;
	} else {
		pVht_cap_ie->vht_cap.ch_width = 0;
	}
	return TRUE;
}

static BOOLEAN ez_ApCliSetHt(
	IN APCLI_STRUCT *pApCliEntry,
	MAC_TABLE_ENTRY *pEntry)
{
	HT_CAPABILITY_IE *aux_ht_cap;
	UCHAR cfg_ht_bw;
	PRTMP_ADAPTER ad = (PRTMP_ADAPTER)(pApCliEntry->wdev.sys_handle);

	cfg_ht_bw = wlan_config_get_ht_bw(&pApCliEntry->wdev);
	aux_ht_cap = &pApCliEntry->MlmeAux.HtCapability;
	/* choose smaller setting */
#ifdef CONFIG_MULTI_CHANNEL
	aux_ht_cap->HtCapInfo.ChannelWidth = cfg_ht_bw; /*pAddHtInfo->AddHtInfo.RecomWidth;*/
#else /* CONFIG_MULTI_CHANNEL */
	aux_ht_cap->HtCapInfo.ChannelWidth = cfg_ht_bw; /*pAddHtInfo->AddHtInfo.RecomWidth & cfg_ht_bw;*/
#endif /* !CONFIG_MULTI_CHANNEL */
	/* Fix throughput issue for some vendor AP with AES mode */
	if (cfg_ht_bw)/* remove pAddHtInfo->AddHtInfo.RecomWidth & check*/
		aux_ht_cap->HtCapInfo.CCKmodein40 = ad->CommonCfg.HtCapability.HtCapInfo.CCKmodein40;
	else
		aux_ht_cap->HtCapInfo.CCKmodein40 = 0;
	/* Record the RxMcs of AP */
	NdisMoveMemory(pApCliEntry->RxMcsSet, ad->CommonCfg.HtCapability.MCSSet, 16);
	NdisMoveMemory(&pEntry->HTCapability, &pApCliEntry->MlmeAux.HtCapability,
		sizeof(HT_CAPABILITY_IE));
	NdisMoveMemory(pEntry->HTCapability.MCSSet, pApCliEntry->RxMcsSet, 16);
	return TRUE;
}

static BOOLEAN ez_ApCliSetVht(
	IN APCLI_STRUCT *pApCliEntry,
	MAC_TABLE_ENTRY *pEntry)
{
	UCHAR cfg_vht_bw;
	VHT_CAP_IE *pVht_cap_ie = NULL;
	PRTMP_ADAPTER pAd = NULL;
	UCHAR bw;
	VHT_OP_IE *pVht_op = NULL;
	UCHAR cent_ch;
	UCHAR prim_ch;

	pAd = (PRTMP_ADAPTER)pApCliEntry->wdev.sys_handle;
	bw = pAd->CommonCfg.vht_bw;
	cfg_vht_bw = wlan_config_get_vht_bw(&pApCliEntry->wdev);
	pVht_cap_ie = &pApCliEntry->MlmeAux.vht_cap;
	pVht_op = &pApCliEntry->MlmeAux.vht_op;

	/*Use cfg_vht_bw instead of pAd->CommonCfg.vht_bw*/

	if (cfg_vht_bw == VHT_BW_160) {
		pVht_cap_ie->vht_cap.ch_width = 1;
		pVht_cap_ie->vht_cap.sgi_160M = pAd->CommonCfg.vht_sgi_80;
	} else if (cfg_vht_bw == VHT_BW_8080) {
		pVht_cap_ie->vht_cap.ch_width = 2;
		pVht_cap_ie->vht_cap.sgi_160M = pAd->CommonCfg.vht_sgi_80;
	} else {
		pVht_cap_ie->vht_cap.ch_width = 0;
	}

	/* Rakesh: assuming pApCliEntry->MlmeAux.vht_cap is correct*/
	NdisMoveMemory(&pEntry->vht_cap_ie, &pApCliEntry->MlmeAux.vht_cap, sizeof(VHT_CAP_IE));

#ifdef CONFIG_AP_SUPPORT
	if (pApCliEntry->wdev.channel > 14 &&
		(pAd->CommonCfg.bIEEE80211H == 1) &&
		(pAd->Dot11_H.RDMode == RD_SWITCHING_MODE)) {
		cent_ch = vht_cent_ch_freq(pAd->Dot11_H.org_ch, bw);
		prim_ch = pAd->Dot11_H.org_ch;
	} else
#endif /* CONFIG_AP_SUPPORT */
	{
		cent_ch = vht_cent_ch_freq(pApCliEntry->wdev.channel, bw);
		prim_ch = pApCliEntry->wdev.channel;
	}

	switch (bw) {
	case VHT_BW_2040:
		pVht_op->vht_op_info.ch_width = 0;
		pVht_op->vht_op_info.center_freq_1 = 0;
		pVht_op->vht_op_info.center_freq_2 = 0;
		break;
	case VHT_BW_80:
		pVht_op->vht_op_info.ch_width = 1;
		pVht_op->vht_op_info.center_freq_1 = cent_ch;
		pVht_op->vht_op_info.center_freq_2 = 0;
		break;
	case VHT_BW_160:
#ifdef DOT11_VHT_R2
		pVht_op->vht_op_info.ch_width = 1;
		pVht_op->vht_op_info.center_freq_1 = (prim_ch > cent_ch) ? (cent_ch + 8) : (cent_ch - 8);
		pVht_op->vht_op_info.center_freq_2 = cent_ch;
#else
		pVht_op->vht_op_info.ch_width = 2;
		pVht_op->vht_op_info.center_freq_1 = cent_ch;
		pVht_op->vht_op_info.center_freq_2 = 0;
#endif /* DOT11_VHT_R2 */
		break;
	case VHT_BW_8080:
#ifdef DOT11_VHT_R2
		pVht_op->vht_op_info.ch_width = 1;
		pVht_op->vht_op_info.center_freq_1 = cent_ch;
		pVht_op->vht_op_info.center_freq_2 = pAd->CommonCfg.vht_cent_ch2;
#else
		pVht_op->vht_op_info.ch_width = 3;
		pVht_op->vht_op_info.center_freq_1 = cent_ch;
		pVht_op->vht_op_info.center_freq_2 = pAd->CommonCfg.vht_cent_ch2;
#endif /* DOT11_VHT_R2 */
		break;
	}
	return TRUE;
}

void ez_driver_ops_update_ap_peer_record_mt7612(
	void *ezdev,
	BOOLEAN band_switched,
	PUCHAR peer_addr)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
	MAC_TABLE_ENTRY *pEntry = NULL;
	MULTISSID_STRUCT *mbss;
#ifdef DOT11_N_SUPPORT
	UCHAR supported_bw;
#endif
#ifdef DOT11_VHT_AC
	UCHAR vht_bw;
#endif
	UCHAR MaxSupportedRateIn500Kbps = 0;

	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
	("%s >>>\n", __func__));
	if (wdev->wdev_type == WDEV_TYPE_STA)
		wdev = &pAd->ApCfg.MBSSID[wdev->func_idx].wdev;

	mbss = wdev->func_dev;
	pEntry = MacTableLookup(pAd, peer_addr);
	if (pEntry != NULL) {
		/*Rakesh: print current info pMacEntry->HTPhyMode.word
		*pMacEntry->MaxHTPhyMode.word	ClientStatusFlags
		*pApCliEntry->MlmeAux.HtCapability	pMacEntry->HTCapability
		*(pApCliEntry->MlmeAux.vht_cap), (pApCliEntry->MlmeAux.vht_op)
		*pMacEntry->vht_cap_ie
		*/
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
			("%s(),MacEntry CURRENT MODE = %d, BW = %d\n", __func__,
			pEntry->MaxHTPhyMode.field.MODE,
			pEntry->MaxHTPhyMode.field.BW));
		/*Rakesh: following code taken from update_associated_mac_entry
		*& ap_cmm_peer_assoc_req_action
		*/
#ifdef DOT11_N_SUPPORT
		supported_bw = wlan_config_get_ht_bw(wdev);
		if (pAd->CommonCfg.HtCapability.HtCapInfo.ChannelWidth != supported_bw) {
			EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("**** CmnCfg HtCap chan width not in sync with current ht bw\n"));
			pAd->CommonCfg.HtCapability.HtCapInfo.ChannelWidth = supported_bw;
		}
		ez_ApStaSetHt(wdev, pEntry);/*will update pEntry->HTCapability*/
#endif
#ifdef DOT11_VHT_AC
		vht_bw = wlan_config_get_vht_bw(wdev);
		if (pAd->CommonCfg.vht_bw != vht_bw) {
			EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
				("**** CmnCfg VHt Cap chan width not in sync with current vht bw\n"));
			pAd->CommonCfg.vht_bw = vht_bw;
		}
		ez_ApStaSetVht(wdev, pEntry);/* will update pEntry->vht_cap_ie*/
#endif
		RTMPSetSupportMCS(pAd,
						OPMODE_AP,
						pEntry,
						pAd->CommonCfg.SupRate,/*ie_list->SupportedRates Rakesh:
						* use ap values as same phy mode on all devices,
						* no need to use RTMPCheckRates as done by Cli
						*/
						pAd->CommonCfg.SupRateLen,/*ie_list->SupportedRatesLen,*/
						NULL,/*wdev->rate.ExtRate can be used*/
						0,/*wdev->rate.ExtRateLen can be used*/
#ifdef DOT11_VHT_AC
						sizeof(pEntry->vht_cap_ie),/*use build_vht_cap_ie??*/
						&pEntry->vht_cap_ie,
#endif /* DOT11_VHT_AC */
						&pEntry->HTCapability,
						sizeof(pEntry->HTCapability));

#ifdef DOT11_N_SUPPORT
		/* If this Entry supports 802.11n, upgrade to HT rate. */
		if (/*(ie_list->ht_cap_len != 0) &&
		*Rakesh: todo check peer capability first before updating
		*(wdev->DesiredHtPhyInfo.bHtEnable) &&
		*/
			WMODE_CAP_N(wdev->PhyMode))
			/* Rakesh: current code assumes all devices on same PhyMode*/{
			/* Rakesh refer ht_mode_adjust() for partial changes taken here as applicable*/
			if (/*(peer->HtCapInfo.ChannelWidth) &&
			*Rakesh: todo check peer capability before updating
			*/
				(wlan_config_get_ht_bw(wdev)) &&
				(ez_driver_ops_wlan_operate_get_ht_bw_mt7612(ezdev)) &&
				(supported_bw == BW_40)) {
				pEntry->MaxHTPhyMode.field.BW = BW_40;
			} else {
				pEntry->MaxHTPhyMode.field.BW = BW_20;
				pAd->MacTab.fAnyStation20Only = TRUE;
			}
			EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
				("%s(),MacEntry Updated MODE = %d, BW = %d\n", __func__,
				pEntry->MaxHTPhyMode.field.MODE,
				pEntry->MaxHTPhyMode.field.BW));
#ifdef DOT11_VHT_AC
			if (WMODE_CAP_AC(wdev->PhyMode)
				/* Rakesh: current code assumes PhyMode same on all devices*/
				/*&& (Channel > 14) &&*/
				/*ie_list->vht_cap_len Rakesh  Todo: check actual apability*/
				) {
				/*Referred vht_mode_adjust()*/
				pEntry->MaxHTPhyMode.field.MODE = MODE_VHT;
				if ((pEntry->MaxHTPhyMode.field.BW == BW_40) && (pEntry->wdev)) {
					/*Rakesh: check config vht bw instead of DesiredHtPhyInfo*/
					if (vht_bw) {
						/*if ((vht_bw >= VHT_BW_80) &&
						*(cap->vht_cap.ch_width == 0)
						*Rakesh: todo check peer capability
						*	)
						*{
							*if  (op != NULL) { Rakesh: todo check peer capability
							*	if(op->vht_op_info.ch_width == 0) {
							*	peer support VHT20,40
							*		pMacEntry->MaxHTPhyMode.field.BW = BW_40;
							*	} else {
							*		pMacEntry->MaxHTPhyMode.field.BW = BW_80;
							*	}
							*} else
							*{
							* can not know peer capability, use it's maximum capability
							*	pEntry->MaxHTPhyMode.field.BW = BW_80;
							*}
						*} else
						*/
						if ((vht_bw == VHT_BW_80)
							/*&& (cap->vht_cap.ch_width != 0)
							*Rakesh: todo: check peer capability
							*/
							) {
							pEntry->MaxHTPhyMode.field.BW = BW_80;
						} else if (((vht_bw == VHT_BW_160) || (vht_bw == VHT_BW_8080))
						/*&& (cap->vht_cap.ch_width != 0)  Rakesh: check peer capability*/
							) {
							pEntry->MaxHTPhyMode.field.BW = BW_160;
						}
					}
				}
/*				dot11_vht_mcs_to_internal_mcs(pAd,
*				wdev, &pEntry->vht_cap_ie, &pEntry->MaxHTPhyMode);
*/
				/* Rakesh: choose vht cap ie to use*/
			}

#endif /* DOT11_VHT_AC */

		}
		/*else	Rakesh: todo: check actual cability
		*{
		*	pAd->MacTab.fAnyStationIsLegacy = TRUE;
		*	NdisZeroMemory(&pEntry->HTCapability, sizeof(HT_CAPABILITY_IE));
*#ifdef DOT11_VHT_AC
		*TODO: shiang-usw, it's ugly and need to revise it
		*NdisZeroMemory(&pEntry->vht_cap_ie, sizeof(VHT_CAP_IE));
		*pEntry->SupportVHTMCS1SS = 0;
		*pEntry->SupportVHTMCS2SS = 0;
		*pEntry->SupportVHTMCS3SS = 0;
		*pEntry->SupportVHTMCS4SS = 0;
		*pEntry->SupportRateMode &= (~SUPPORT_VHT_MODE);
*#endif
		*}
		*/
#endif /* DOT11_N_SUPPORT */

		pEntry->HTPhyMode.word = pEntry->MaxHTPhyMode.word;

#ifdef MT_MAC
		if (pAd->chipCap.hif_type == HIF_MT) {
			if (wdev->bAutoTxRateSwitch == TRUE) {
				pEntry->bAutoTxRateSwitch = TRUE;
			} else {
				pEntry->HTPhyMode.field.MCS = wdev->HTPhyMode.field.MCS;
				pEntry->bAutoTxRateSwitch = FALSE;
#ifdef WFA_VHT_PF
				if (WMODE_CAP_AC(wdev->PhyMode)) {
					pEntry->HTPhyMode.field.MCS = wdev->DesiredTransmitSetting.field.MCS +
						((wlan_config_get_tx_stream(wdev) - 1) << 4);
				}
#endif /* WFA_VHT_PF */
				if (pEntry->HTPhyMode.field.MODE == MODE_VHT) {
					pEntry->HTPhyMode.field.MCS = wdev->DesiredTransmitSetting.field.MCS +
						((wlan_config_get_tx_stream(wdev) - 1) << 4);
				}
				/* If the legacy mode is set, overwrite the transmit setting of this entry. */
				RTMPUpdateLegacyTxSetting((UCHAR)wdev->DesiredTransmitSetting.field.FixedTxMode,
				pEntry);
			}
		}
#endif /* MT_MAC */
		MaxSupportedRateIn500Kbps =
		dot11_max_sup_rate(pAd->CommonCfg.SupRateLen,
		pAd->CommonCfg.SupRate, pAd->CommonCfg.ExtRateLen,
		pAd->CommonCfg.ExtRate);

		EzAPApCliUpdateAssociation(pAd, pEntry, mbss->CapabilityInfo,
			MaxSupportedRateIn500Kbps, pAd->CommonCfg.ExtCapIE,
			&pEntry->HTCapability, sizeof(pEntry->HTCapability),
			&pEntry->Aid);/*,ie_list); // Rakesh: todo pass peer capabilities*/
	} else {
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
			("ERROR !!! not found other peer mac entry\n"));
		ASSERT(FALSE);
	}
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
		("%s <<<\n", __func__));
}

void ez_driver_ops_update_cli_peer_record_mt7612(
	void *ezdev,
	BOOLEAN band_switched,
	PUCHAR peer_addr)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	struct wifi_dev *wdev = ez_dev->wdev;
	struct wifi_dev *ap_wdev = NULL;
	APCLI_STRUCT *pApCliEntry;
	PRTMP_ADAPTER pAd = ez_dev->driver_ad;
	MAC_TABLE_ENTRY *pMacEntry = NULL;
#ifdef DOT11_N_SUPPORT
	UCHAR supported_bw;
#endif
#ifdef DOT11_VHT_AC
	unsigned char vht_bw;
#endif
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
	("%s >>>\n", __func__));
	if (wdev->wdev_type == WDEV_TYPE_AP)
		wdev = &pAd->ApCfg.ApCliTab[wdev->func_idx].wdev;

	pApCliEntry = wdev->func_dev;
	if (/* !MAC_ADDR_EQUAL(wdev->ez_security.this_band_info.cli_peer_ap_mac,
	*updated_configs->mac_addr)  &&
	*Rakesh: from port secured should be checked if just connected ap
	*/
		!MAC_ADDR_EQUAL(wdev->bssid, ZERO_MAC_ADDR)) {
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
			("%s, wdev_idx:%x, cli_peer_ap_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
			__func__, wdev->wdev_idx, PRINT_MAC(wdev->bssid)));
			pMacEntry = MacTableLookup(wdev->sys_handle, peer_addr);
			if (pMacEntry != NULL) {
				/* Rakesh: print current info
				*pMacEntry->HTPhyMode.word pMacEntry->MaxHTPhyMode.word
				*ClientStatusFlags
				* pApCliEntry->MlmeAux.HtCapability
				*pMacEntry->HTCapability (pApCliEntry->MlmeAux.vht_cap),
				*(pApCliEntry->MlmeAux.vht_op)
				* pMacEntry->vht_cap_ie
				*/
				EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
				("%s(),MacEntry CURRENT MODE = %d, BW = %d\n", __func__,
					pMacEntry->MaxHTPhyMode.field.MODE,
					pMacEntry->MaxHTPhyMode.field.BW));
				/*Rakesh: following code taken from ApCliLinkUp*/
				ap_wdev = &(pAd->ApCfg.MBSSID[wdev->func_idx].wdev);
#ifdef DOT11_N_SUPPORT
				supported_bw = wlan_config_get_ht_bw(wdev);
				if (pAd->CommonCfg.HtCapability.HtCapInfo.ChannelWidth
					!= supported_bw) {
					EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
						("**** CmnCfg HtCap chan width not in sync with current ht bw\n"));
					pAd->CommonCfg.HtCapability.HtCapInfo.ChannelWidth
					= supported_bw;
				}
				ez_ApCliSetHt(pApCliEntry, pMacEntry); /*will update pEntry->HTCapability*/
#endif
#ifdef DOT11_VHT_AC
				vht_bw = wlan_config_get_vht_bw(wdev);

				if (pAd->CommonCfg.vht_bw != vht_bw) {
					EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
						("**** CmnCfg VHt Cap chan width not in sync with current vht bw\n"));
					pAd->CommonCfg.vht_bw = vht_bw;
				}
				ez_ApCliSetVht(pApCliEntry, pMacEntry); /* will update pEntry->vht_cap_ie*/
#endif
#ifdef DOT11_N_SUPPORT
				/* If this Entry supports 802.11n, upgrade to HT rate. */
				/*if (pApCliEntry->MlmeAux.HtCapabilityLen != 0)
				*Rakesh: todo check peer capability before updating
				*/
				/*Rakesh: code written asuming all device suport same PhyMode*/
				if (WMODE_CAP_N(pApCliEntry->wdev.PhyMode)) {
					/*Rakesh refer ht_mode_adjust() for partial changes taken here as applicable*/

					if (/*(peer->HtCapInfo.ChannelWidth) &&
					*Rakesh: todo check peer capability before updating
					*/
						(wlan_config_get_ht_bw(wdev)) &&
						(ez_driver_ops_wlan_operate_get_ht_bw_mt7612(ezdev)) &&
						(supported_bw == BW_40)) {
						pMacEntry->MaxHTPhyMode.field.BW = BW_40;
					} else {
						pMacEntry->MaxHTPhyMode.field.BW = BW_20;
						pAd->MacTab.fAnyStation20Only = TRUE;
					}
					EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO,
						("%s(),MacEntry Updated MODE = %d, BW = %d\n", __func__,
						pMacEntry->MaxHTPhyMode.field.MODE,
						pMacEntry->MaxHTPhyMode.field.BW));
					pMacEntry->HTPhyMode.word = pMacEntry->MaxHTPhyMode.word;
				}
				/*else	Rakesh: Todo check AP capability
				*{
				*	pAd->MacTab.fAnyStationIsLegacy = TRUE;
				*	EZ_DEBUG(DBG_CAT_CLIENT, CATCLIENT_APCLI, EZ_DBG_LVL_TRACE,
				*("ApCliLinkUp - MaxSupRate=%d Mbps\n",
				*	  RateIdToMbps[pMacEntry->MaxSupportedRate]));
				*}
				*/
#endif /* DOT11_N_SUPPORT */

#ifdef DOT11_VHT_AC
				/*if (WMODE_CAP_AC(pApCliEntry->wdev.PhyMode) &&
				*pApCliEntry->MlmeAux.vht_cap_len &&
				*pApCliEntry->MlmeAux.vht_op_len)	Rakesh: Todo: check capability
				*/
				/* Rakesh: code written asuming all device suport same PhyMode*/
				if (WMODE_CAP_AC(pApCliEntry->wdev.PhyMode)) {
					/*Rakesh: referred vht_mode_adjust()*/
					pMacEntry->MaxHTPhyMode.field.MODE = MODE_VHT;
					if ((pMacEntry->MaxHTPhyMode.field.BW == BW_40) && (pMacEntry->wdev)) {
						/*Rakesh: check config vht bw instead of DesiredHtPhyInfo*/
						if (vht_bw) {
							/*if((vht_bw >= VHT_BW_80) &&
							*(cap->vht_cap.ch_width == 0)
							*Rakesh: todo check peer capability
							*	) {
								*if (op != NULL) { Rakesh: todo check peer capability
								*if (op->vht_op_info.ch_width == 0)  {
								*	peer support VHT20,40
								*	pMacEntry->MaxHTPhyMode.field.BW = BW_40;
								*	} else {
								*	pMacEntry->MaxHTPhyMode.field.BW = BW_80;
								*	}
								*} else {
								* can not know peer capability,
								*use it's maximum capability
								*	pMacEntry->MaxHTPhyMode.field.BW = BW_80;
								*}
							*} else
							*/
							if ((vht_bw == VHT_BW_80)
								/*&& (cap->vht_cap.ch_width != 0)
								*Rakesh: todo: check peer capability
								*/
								) {
								pMacEntry->MaxHTPhyMode.field.BW = BW_80;
							} else if (((vht_bw == VHT_BW_160) || (vht_bw == VHT_BW_8080))
							/*&& (cap->vht_cap.ch_width != 0)
							*Rakesh: check peer capability
							*/
									) {
								pMacEntry->MaxHTPhyMode.field.BW = BW_160;
							}
						}
					}

/*					dot11_vht_mcs_to_internal_mcs(((PRTMP_ADAPTER)wdev->sys_handle),
*						&pApCliEntry->wdev, &pApCliEntry->MlmeAux.vht_cap,
*						&pMacEntry->MaxHTPhyMode);
*/
						/*Rakesh: keeping this as it refers BW*/
				}
#endif /* DOT11_VHT_AC */
				pMacEntry->HTPhyMode.word = pMacEntry->MaxHTPhyMode.word;
				pApCliEntry->MlmeAux.SupRateLen = pAd->CommonCfg.SupRateLen;
				NdisMoveMemory(pApCliEntry->MlmeAux.SupRate, pAd->CommonCfg.SupRate,
					pApCliEntry->MlmeAux.SupRateLen);
				/* Rakesh: RTMPCheckRates not required as same phy mode on all devices*/
				pApCliEntry->MlmeAux.ExtRateLen = pAd->CommonCfg.ExtRateLen;
				NdisMoveMemory(pApCliEntry->MlmeAux.ExtRate, pAd->CommonCfg.ExtRateLen,
					pApCliEntry->MlmeAux.ExtRateLen);
				/*Rakesh: RTMPCheckRates not required as same phy mode on all devices*/
				RTMPSetSupportMCS(wdev->sys_handle,
								OPMODE_AP,
								pMacEntry,
								pApCliEntry->MlmeAux.SupRate,
								pApCliEntry->MlmeAux.SupRateLen,
								pApCliEntry->MlmeAux.ExtRate,
								pApCliEntry->MlmeAux.ExtRateLen,
#ifdef DOT11_VHT_AC
								pApCliEntry->MlmeAux.vht_cap_len,
								&pApCliEntry->MlmeAux.vht_cap,
#endif /* DOT11_VHT_AC */
								&pApCliEntry->MlmeAux.HtCapability,
								pApCliEntry->MlmeAux.HtCapabilityLen);
				/*WifiSysApCliChBwUpdate(((PRTMP_ADAPTER)wdev->sys_handle),
				*pApCliEntry, CliIdx, pMacEntry);
				*/
#ifdef MT_MAC
				if (pAd->chipCap.hif_type == HIF_MT) {
					if (wdev->bAutoTxRateSwitch == TRUE) {
						pMacEntry->bAutoTxRateSwitch = TRUE;
					} else {
						pMacEntry->HTPhyMode.field.MCS = wdev->HTPhyMode.field.MCS;
						pMacEntry->bAutoTxRateSwitch = FALSE;
						/* If the legacy mode is set,
						*overwrite the transmit setting of this entry.
						*/
						RTMPUpdateLegacyTxSetting
						((UCHAR)wdev->DesiredTransmitSetting.field.FixedTxMode,
						pMacEntry);
					}
					MlmeRAInit(pAd, pMacEntry);
				}
#endif
			} else {
				EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
					("ERROR !!! not found other peer mac entry\n"));
				ASSERT(FALSE);
			}
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_INFO, ("%s <<<\n", __func__));
	}

}

void ez_driver_ops_MgtMacHeaderInit_mt7612(
	 void *ezdev,
	 HEADER_802_11_EZ *pHdr80211,
	 UCHAR SubType,
	 UCHAR ToDs,
	 UCHAR *pDA,
	 UCHAR *pSA,
	 UCHAR *pBssid)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	/*struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;*/

	MgtMacHeaderInit(pAd, (HEADER_802_11 *)pHdr80211, SubType, ToDs, pDA, pSA, pBssid);
}

BOOLEAN ez_driver_ops_is_mlme_running_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	return pAd->Mlme.bRunning;
}
#endif
VOID ez_driver_ops_ApSiteSurvey_by_wdev_mt7612(
	void *ezdev_obj,
	void *pSsid,
	UCHAR	ScanType,
	BOOLEAN	ChannelSel,
	BOOLEAN scan_one_channel
	)
{
	ez_dev_t *ezdev = ezdev_obj;
	struct wifi_dev *wdev = ezdev->wdev;
	PRTMP_ADAPTER ad = wdev->sys_handle;

	wdev->ez_driver_params.ez_scan = TRUE;
	wdev->ez_driver_params.scan_one_channel = scan_one_channel;
	ad->ApCfg.ScanReqwdev = wdev;
	ApSiteSurvey(ad, pSsid, SCAN_ACTIVE, ChannelSel);
}

void ez_driver_ops_fill_out_table_mt7612(BSS_TABLE *Tab, EZ_BSS_TABLE *pEzBss)
{
	UINT16 i;

	pEzBss->BssNr = Tab->BssNr;
	for (i = 0; i < Tab->BssNr; i++) {
		COPY_MAC_ADDR(pEzBss->BssEntry[i].MacAddr, Tab->BssEntry[i].MacAddr);
		COPY_MAC_ADDR(pEzBss->BssEntry[i].Bssid, Tab->BssEntry[i].Bssid);
		pEzBss->BssEntry[i].Channel = Tab->BssEntry[i].Channel;
		pEzBss->BssEntry[i].CentralChannel = Tab->BssEntry[i].CentralChannel;
		pEzBss->BssEntry[i].Rssi = Tab->BssEntry[i].Rssi;
		pEzBss->BssEntry[i].SsidLen = Tab->BssEntry[i].SsidLen;
		NdisCopyMemory(pEzBss->BssEntry[i].Ssid, Tab->BssEntry[i].Ssid, pEzBss->BssEntry[i].SsidLen);
		pEzBss->BssEntry[i].AKMMap = AuthMode_to_AKM_map(Tab->BssEntry[i].AuthMode);
		pEzBss->BssEntry[i].PairwiseCipher = WepStatus_to_PairwiseCipher(Tab->BssEntry[i].WepStatus);
		pEzBss->BssEntry[i].GroupCipher = WepStatus_to_PairwiseCipher(Tab->BssEntry[i].WepStatus);
		pEzBss->BssEntry[i].support_easy_setup = Tab->BssEntry[i].support_easy_setup;
		pEzBss->BssEntry[i].easy_setup_capability = Tab->BssEntry[i].easy_setup_capability;
		pEzBss->BssEntry[i].bConnectAttemptFailed = Tab->BssEntry[i].bConnectAttemptFailed;
		pEzBss->BssEntry[i].non_ez_beacon = Tab->BssEntry[i].non_ez_beacon;
		NdisCopyMemory(pEzBss->BssEntry[i].open_group_id,
				Tab->BssEntry[i].open_group_id, Tab->BssEntry[i].open_group_id_len);
		pEzBss->BssEntry[i].open_group_id_len = Tab->BssEntry[i].open_group_id_len;
		NdisCopyMemory(&pEzBss->BssEntry[i].beacon_info,
			&Tab->BssEntry[i].beacon_info, sizeof(beacon_info_tag_t));
	}
}


void ez_driver_sort_apcli_tab_by_rssi_mt7612(void *ad_obj, void *wdev_obj)
{
	PRTMP_ADAPTER pAd = ad_obj;
	struct wifi_dev *wdev = wdev_obj;
	APCLI_STRUCT *apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
	BSS_TABLE *Tab = &apcli_entry->MlmeAux.SsidBssTab;

	BssTableSortByRssi(Tab, FALSE);
}

void ez_driver_ops_add_entry_in_apcli_tab_mt7612(void *ad_obj, void *wdev_obj, ULONG bss_entry_idx)
{
	PRTMP_ADAPTER pAd = ad_obj;
	struct wifi_dev *wdev = wdev_obj;
	APCLI_STRUCT *apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
	BSS_TABLE *Tab = &apcli_entry->MlmeAux.SsidBssTab;

	NdisCopyMemory(&Tab->BssEntry[Tab->BssNr], &pAd->ScanTab.BssEntry[bss_entry_idx], sizeof(BSS_ENTRY));
	Tab->BssNr++;
	Tab->BssOverlapNr++;
}

void ez_driver_ops_ApCliBssTabInit_mt7612(void *ad_obj, void *wdev_obj)
{
	PRTMP_ADAPTER pAd = ad_obj;
	struct wifi_dev *wdev = wdev_obj;
	APCLI_STRUCT *apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
	BSS_TABLE *Tab = &apcli_entry->MlmeAux.SsidBssTab;

	BssTableInit(Tab);
}


void ez_driver_ops_get_scan_table_mt7612(void *ad_obj, EZ_BSS_TABLE *pEzBss)
{
	PRTMP_ADAPTER pAd = ad_obj;
	BSS_TABLE *Tab = &pAd->ScanTab;
	UINT16 i;

	pEzBss->BssNr = Tab->BssNr;
	for (i = 0; i < Tab->BssNr; i++) {
		COPY_MAC_ADDR(pEzBss->BssEntry[i].MacAddr, Tab->BssEntry[i].MacAddr);
		COPY_MAC_ADDR(pEzBss->BssEntry[i].Bssid, Tab->BssEntry[i].Bssid);
		pEzBss->BssEntry[i].Channel = Tab->BssEntry[i].Channel;
		pEzBss->BssEntry[i].CentralChannel = Tab->BssEntry[i].CentralChannel;
		pEzBss->BssEntry[i].Rssi = Tab->BssEntry[i].Rssi;
		pEzBss->BssEntry[i].SsidLen = Tab->BssEntry[i].SsidLen;
		NdisCopyMemory(pEzBss->BssEntry[i].Ssid, Tab->BssEntry[i].Ssid, pEzBss->BssEntry[i].SsidLen);
		pEzBss->BssEntry[i].AKMMap = AuthMode_to_AKM_map(Tab->BssEntry[i].AuthMode);
		pEzBss->BssEntry[i].PairwiseCipher = WepStatus_to_PairwiseCipher(Tab->BssEntry[i].WepStatus);
		pEzBss->BssEntry[i].GroupCipher = WepStatus_to_PairwiseCipher(Tab->BssEntry[i].WepStatus);
		pEzBss->BssEntry[i].support_easy_setup = Tab->BssEntry[i].support_easy_setup;
		pEzBss->BssEntry[i].easy_setup_capability = Tab->BssEntry[i].easy_setup_capability;
		pEzBss->BssEntry[i].bConnectAttemptFailed = Tab->BssEntry[i].bConnectAttemptFailed;
		pEzBss->BssEntry[i].non_ez_beacon = Tab->BssEntry[i].non_ez_beacon;
		NdisCopyMemory(pEzBss->BssEntry[i].open_group_id,
				Tab->BssEntry[i].open_group_id, Tab->BssEntry[i].open_group_id_len);
		pEzBss->BssEntry[i].open_group_id_len = Tab->BssEntry[i].open_group_id_len;
		NdisCopyMemory(&pEzBss->BssEntry[i].beacon_info, &Tab->BssEntry[i].beacon_info,
			sizeof(beacon_info_tag_t));
	}

}



void ez_driver_ops_update_partial_scan_mt7612(void *ez_ad_obj, void *wdev_obj)
{
	ULONG now;
	EZ_ADAPTER *ez_ad = ez_ad_obj;
	struct wifi_dev *wdev = wdev_obj;

	NdisGetSystemUpTime(&now);
	if (RTMP_TIME_AFTER(now, wdev->ez_driver_params.partial_scan_time_stamp +
		ez_ad->ez_partial_scan_time*OS_HZ)) {
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("%s() Eligible candidate found !!! Restart partial scan timer\n",
			__func__));
		NdisGetSystemUpTime(&wdev->ez_driver_params.partial_scan_time_stamp);
	}
}
VOID ez_driver_ops_BssTableSsidSort_mt7612(
	IN void *ad_obj,
	IN void *wdev_obj,
	OUT EZ_BSS_TABLE *OutTab,
	IN CHAR Ssid[],
	IN UCHAR SsidLen)
{
	PRTMP_ADAPTER pAd = ad_obj;
	struct wifi_dev *wdev = wdev_obj;
	APCLI_STRUCT *apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];

	BSS_TABLE *Tab = &apcli_entry->MlmeAux.SsidBssTab;

	BssTableSsidSort(ad_obj, Tab, Ssid, SsidLen);
	ez_driver_ops_fill_out_table_mt7612(Tab, OutTab);
	/*os_free_mem(driver_out_tab);*/
}
#ifdef WH_EZ_SETUP
void ez_initiate_new_scan_driver(struct wifi_dev *wdev)
{
	if (wdev->ez_driver_params.ezdev)
		return ez_initiate_new_scan_hook(wdev->ez_driver_params.ezdev);
}
#endif
BOOLEAN ez_driver_ops_update_cli_conn_mt7612(void *ad_obj, void *ez_dev_obj,
EZ_BSS_ENTRY *bss_entry)
{
	PRTMP_ADAPTER pAd = ad_obj;
	ez_dev_t *ezdev = ez_dev_obj;
	EZ_ADAPTER *ez_ad = ezdev->ez_ad;
	ez_dev_t *ap_ezdev = &ez_ad->ez_band_info[ezdev->ez_band_idx].ap_ezdev;
	struct wifi_dev *wdev = ((ez_dev_t *)ezdev)->wdev;
	struct wifi_dev *ap_wdev = &pAd->ApCfg.MBSSID[wdev->func_idx].wdev;
	PAPCLI_STRUCT apcli_entry;
	UCHAR tempBuf[20];

	apcli_entry = &pAd->ApCfg.ApCliTab[wdev->func_idx];
	COPY_MAC_ADDR(apcli_entry->CfgApCliBssid, bss_entry->Bssid);
	NdisZeroMemory(apcli_entry->CfgSsid, MAX_LEN_OF_SSID);
	NdisMoveMemory(apcli_entry->CfgSsid, bss_entry->Ssid, bss_entry->SsidLen);
	apcli_entry->CfgSsidLen = bss_entry->SsidLen;
	wdev->AuthMode = AKM_map_to_AuthMode(bss_entry->AKMMap);
	wdev->WepStatus = PairwiseCipher_to_WepStatus(bss_entry->PairwiseCipher);
	wdev->GroupKeyWepStatus = PairwiseCipher_to_WepStatus(bss_entry->GroupCipher);
	apcli_entry->MlmeAux.attempted_candidate_index = ezdev->attempted_candidate_index;
	apcli_entry->MlmeAux.support_easy_setup = ezdev->support_ez_setup;
#ifdef EZ_NETWORK_MERGE_SUPPORT
	if (ezdev->ez_security.internal_force_connect_bssid == TRUE) {
		if (pAd->CommonCfg.Channel != bss_entry->Channel) {
			EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_ERROR,
				("stale scan list %d %d!!!\n", wdev->channel, bss_entry->Channel));
			/*ASSERT(FALSE);*/
			ez_initiate_new_scan_hook(ezdev->ez_ad);
			return FALSE;
		}
	}
	/*! adjust APCLI's operating bandwidth to that of peer*/
	ez_ApCliAutoConnectBWAdjust(pAd, wdev, bss_entry);
	ez_ApCliAutoConnectBWAdjust(pAd, ap_wdev, bss_entry);
#ifdef EZ_NETWORK_MERGE_SUPPORT
#ifdef EZ_DUAL_BAND_SUPPORT
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
	("ez_apcli_search_best_ap_configured\nAPCLI=> CurrChannel: %d, TarChannel: %d\n",
	ezdev->ez_security.this_band_info.shared_info.channel_info.channel,
	bss_entry->Channel));
#ifdef EZ_PUSH_BW_SUPPORT
	/*if( ((PRTMP_ADAPTER)(wdev->sys_handle))->push_bw_config )*/
	{
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("\tHT-BW: %d, CFG:%d OPER:%d\n",
			ezdev->ez_security.this_band_info.shared_info.channel_info.ht_bw,
			wlan_config_get_ht_bw(wdev),
			ez_driver_ops_wlan_operate_get_ht_bw_mt7612(wdev)));
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("\tVHT-BW: %d CFG:%d OPER:%d\n",
			ezdev->ez_security.this_band_info.shared_info.channel_info.vht_bw,
			ez_driver_ops_wlan_config_get_vht_bw_mt7612(wdev),
			ez_driver_ops_wlan_operate_get_vht_bw_mt7612(wdev)));
	}
#else
	{
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("\tHT-BW: CFG:%d OPER:%d\n",
			ez_driver_ops_wlan_config_get_ht_bw_mt7612(wdev->ez_driver_params.ezdev),
			ez_driver_ops_wlan_operate_get_ht_bw_mt7612(wdev->ez_driver_params.ezdev)));
#ifdef DOT11_VHT_AC
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
		("\tVHT-BW: CFG:%d OPER:%d\n",
		ez_driver_ops_wlan_config_get_vht_bw_mt7612(wdev->ez_driver_params.ezdev),
		ez_driver_ops_wlan_operate_get_vht_bw_mt7612(wdev->ez_driver_params.ezdev)));
#endif
	}
#endif
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE, ("\tEXTCHA: %d CFG:%d OPER:%d\n",
		ezdev->ez_security.this_band_info.shared_info.channel_info.extcha,
		wlan_config_get_ext_cha(wdev),
		ez_driver_ops_wlan_operate_get_ext_cha_mt7612(wdev)));
	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
		("AP=> CurrChannel: %d, TarChannel: %d\n",
		ap_ezdev->ez_security.this_band_info.shared_info.channel_info.channel,
		bss_entry->Channel));
#ifdef EZ_PUSH_BW_SUPPORT
	/*if( ((PRTMP_ADAPTER)(ap_wdev->sys_handle))->push_bw_config )*/
	{
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("\tHT-BW: %d, CFG:%d OPER:%d\n",
			ap_ezdev->ez_security.this_band_info.shared_info.channel_info.ht_bw,
			ez_driver_ops_wlan_config_get_ht_bw_mt7612(ap_wdev->ez_driver_params.ezdev),
			ez_driver_ops_wlan_operate_get_ht_bw_mt7612(ap_wdev->ez_driver_params.ezdev)));
#ifdef DOT11_VHT_AC
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
		("\tVHT-BW: %d CFG:%d OPER:%d\n",
		ap_ezdev->ez_security.this_band_info.shared_info.channel_info.vht_bw,
		wlan_config_get_vht_bw(ap_wdev),
		ez_driver_ops_wlan_operate_get_vht_bw_mt7612(ap_wdev->ez_driver_params.ezdev)));
#endif
	}
#else
	{
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("\tHT-BW: CFG:%d OPER:%d\n",
			ez_driver_ops_wlan_config_get_ht_bw_mt7612(ap_wdev->ez_driver_params.ezdev),
			ez_driver_ops_wlan_operate_get_ht_bw_mt7612(ap_wdev->ez_driver_params.ezdev)));
#ifdef DOT11_VHT_AC
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
		("\tVHT-BW: CFG:%d OPER:%d\n",
		wlan_config_get_vht_bw(ap_wdev),
		ez_driver_ops_wlan_operate_get_vht_bw_mt7612(ap_wdev->ez_driver_params.ezdev)));
#endif
	}
#endif

	EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
	("\tEXTCHA: %d CFG:%d OPER:%d\n",
	ap_ezdev->ez_security.this_band_info.shared_info.channel_info.extcha,
	ez_driver_ops_wlan_config_get_ext_cha_mt7612(ap_wdev->ez_driver_params.ezdev),
	ez_driver_ops_wlan_operate_get_ext_cha_mt7612(ap_wdev->ez_driver_params.ezdev)));
#endif
#endif
	ap_wdev->ez_driver_params.do_not_restart_interfaces = 1;
	sprintf(tempBuf, "%d", bss_entry->Channel);
	Set_Channel_Proc(pAd, tempBuf);
/*	rtmp_set_channel(pAd,ap_wdev, bss_entry->Channel);*/
	ap_wdev->ez_driver_params.do_not_restart_interfaces = 0;
#else
	if ((ap_wdev->channel != bss_entry->Channel) || (wdev->channel != bss_entry->Channel)) {
		EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("%s - Switch channel to ch.%d\n", __func__, bss_entry->Channel));
		sprintf(tempBuf, "%d", bss_entry->Channel);
		Set_Channel_Proc(pAd, tempBuf);
		/*rtmp_set_channel(pAd,ap_wdev, bss_entry->Channel);*/
#ifdef APCLI_AUTO_CONNECT_SUPPORT
#ifdef APCLI_AUTO_BW_TMP
		if (ez_ApCliAutoConnectBWAdjust(pAd, wdev, bss_entry)) {
			sprintf(tempBuf, "%d", bss_entry->Channel);
			Set_Channel_Proc(pAd, tempBuf);
			/*rtmp_set_channel(pAd, ap_wdev, bss_entry->Channel);*/
		}
		 else
			EZ_DEBUG(EZ_DUMMY_DBG_DEFINE, EZ_DUMMY_DBG_DEFINE, EZ_DBG_LVL_TRACE,
			("%s(): ApCliAutoConnectBWAdjust() return FALSE\n", __func__));

#endif /*APCLI_AUTO_BW_TMP*/
#endif /*APCLI_AUTO_CONNECT_SUPPORT*/
	}
#endif
	return TRUE;
}

BOOLEAN ez_driver_ops_update_ap_mt7612(
	void *ezdev,
	void *updated_configs)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	EZ_ADAPTER *ez_ad = (EZ_ADAPTER *)ez_dev->ez_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
	updated_configs_t *update_configs = (updated_configs_t *)updated_configs;

	MULTISSID_STRUCT *mbss;

	if (wdev->wdev_type == WDEV_TYPE_STA)
		wdev = &pAd->ApCfg.MBSSID[wdev->func_idx].wdev;
	mbss = wdev->func_dev;
	mbss->SsidLen = update_configs->this_band_info.shared_info.ssid_len;
	NdisZeroMemory(mbss->Ssid, MAX_LEN_OF_SSID);
	NdisCopyMemory(mbss->Ssid, update_configs->this_band_info.shared_info.ssid,
		mbss->SsidLen);
	if (ez_ad->band_count == 1 && ez_ad->non_ez_band_count == 2) {
		mbss->SsidLen = 0;
		NdisZeroMemory(mbss->Ssid, MAX_LEN_OF_SSID);
		NdisCopyMemory(mbss->Ssid, "\0", sizeof("\0"));
	}
	NdisCopyMemory(&mbss->PMK[0], update_configs->this_band_info.pmk, LEN_PMK);

	SET_AUTHMODE_WPA2PSK(wdev->AuthMode);
	SET_ENCRYTYPE_AES(wdev->WepStatus);
	SET_ENCRYTYPE_AES(wdev->GroupKeyWepStatus);

	return TRUE;
}


BOOLEAN ez_driver_ops_update_cli_mt7612(
	void *ezdev,
	void *updated_configs)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;
	updated_configs_t *update_configs = (updated_configs_t *)updated_configs;
	APCLI_STRUCT *apcli_entry;

	if (wdev->wdev_type == WDEV_TYPE_AP)
		wdev = &pAd->ApCfg.ApCliTab[wdev->func_idx].wdev;

	apcli_entry = wdev->func_dev;

	NdisZeroMemory(apcli_entry->Ssid, MAX_LEN_OF_SSID);
	apcli_entry->SsidLen = update_configs->this_band_info.shared_info.ssid_len;
	NdisCopyMemory(apcli_entry->Ssid, update_configs->this_band_info.shared_info.ssid,
		update_configs->this_band_info.shared_info.ssid_len);
	NdisZeroMemory(apcli_entry->CfgSsid, MAX_LEN_OF_SSID);
	apcli_entry->CfgSsidLen = update_configs->this_band_info.shared_info.ssid_len;
	NdisCopyMemory(apcli_entry->CfgSsid, update_configs->this_band_info.shared_info.ssid,
		update_configs->this_band_info.shared_info.ssid_len);
	NdisCopyMemory(&apcli_entry->PMK[0], update_configs->this_band_info.pmk, LEN_PMK);
	return TRUE;
}

void ez_driver_ops_wlan_config_set_ht_bw_mt7612(void *ezdev, UINT8 ht_bw)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pAd->CommonCfg.RegTransmitSetting.field.BW = ht_bw;
	return;

}

void ez_driver_ops_wlan_config_set_vht_bw_mt7612(void *ezdev, UINT8 vht_bw)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pAd->CommonCfg.vht_bw = vht_bw;
}

void ez_driver_ops_wlan_config_set_ext_cha_mt7612(void *ezdev, UINT8 ext_cha)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;

	pAd->CommonCfg.RegTransmitSetting.field.EXTCHA = ext_cha;
}

INT ez_driver_ops_SetCommonHtVht_mt7612(void *ezdev)
{
	ez_dev_t *ez_dev = (ez_dev_t *)ezdev;
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)ez_dev->driver_ad;
	struct wifi_dev *wdev = (struct wifi_dev *)ez_dev->wdev;

#ifdef DOT11_N_SUPPORT
	SetCommonHT(pAd);
#ifdef DOT11_VHT_AC
	if (WMODE_CAP_AC(wdev->PhyMode))
		SetCommonVHT(pAd);
#endif /* DOT11_VHT_AC */
#endif /* DOT11_N_SUPPORT */
	return TRUE;
}

void ez_driver_ops_RT_HMAC_SHA1_mt7612(void *ezdev, UINT8 Key[],
	UINT KeyLen, UINT8 Message[],
	UINT MessageLen, UINT8 MAC[],
	UINT MACLen)
{
	RT_HMAC_SHA1(Key, KeyLen, Message, MessageLen, MAC, MACLen);
}

void ez_driver_ops_restore_channel_config_7612(void *ezdev)
{
	ez_restore_channel_config(((ez_dev_t *)ezdev)->wdev);
}




ez_driver_ops_t ez_driver_ops_7612 = {
	.RandomByte = ez_driver_ops_RandomByte_mt7612,
	.GenRandom = ez_driver_ops_GenRandom_mt7612,
	.DH_PublicKey_Generate = ez_driver_ops_DH_PublicKey_Generate_mt7612,
	.RT_DH_SecretKey_Generate = ez_driver_ops_RT_DH_SecretKey_Generate_mt7612,
	.RT_SHA256 = ez_driver_ops_RT_SHA256_mt7612,
	.WpaDerivePTK = ez_driver_ops_WpaDerivePTK_mt7612,
	.AES_Key_Unwrap = ez_driver_ops_AES_Key_Unwrap_mt7612,
	.ez_install_pairwise_key = ez_driver_ops_install_pairwise_key_mt7612,
	.ez_apcli_install_group_key = ez_driver_ops_apcli_install_group_key_mt7612,
	.wlan_config_get_ht_bw = ez_driver_ops_wlan_config_get_ht_bw_mt7612,
	.wlan_config_get_vht_bw = ez_driver_ops_wlan_config_get_vht_bw_mt7612,
	.wlan_operate_get_ht_bw = ez_driver_ops_wlan_operate_get_ht_bw_mt7612,
	.wlan_operate_get_vht_bw = ez_driver_ops_wlan_operate_get_vht_bw_mt7612,
	.wlan_config_get_ext_cha = ez_driver_ops_wlan_config_get_ext_cha_mt7612,
	.wlan_operate_get_ext_cha = ez_driver_ops_wlan_operate_get_ext_cha_mt7612,
	.get_cli_aid = ez_driver_ops_get_cli_aid_mt7612,
	.ez_cancel_timer = ez_driver_ops_ez_cancel_timer_mt7612,
	.ez_set_timer = ez_driver_ops_ez_set_timer_mt7612,
	.ez_is_timer_running = ez_driver_ops_is_timer_running_mt7612,
	.get_apcli_enable = ez_driver_ops_get_apcli_enable_mt7612,
	.ApScanRunning = ez_driver_ops_ApScanRunning_mt7612,
	.ez_send_unicast_deauth = ez_driver_ops_send_unicast_deauth_mt7612,
	.ez_restore_channel_config = ez_driver_ops_restore_channel_config_7612,
	.UpdateBeaconHandler = ez_driver_ops_UpdateBeaconHandler_mt7612,
	.ez_update_security_setting = ez_driver_ops_update_security_setting_mt7612,
	.ez_update_ap_wsc_profile = ez_driver_ops_update_ap_wsc_profile_mt7612,
	.APScanCnclAction = ez_driver_ops_APScanCnclAction_mt7612,
	.ez_send_loop_detect_pkt = ez_driver_ops_send_loop_detect_pkt_mt7612,
	.ez_update_ap = ez_driver_ops_update_ap_mt7612,
	.ez_update_cli = ez_driver_ops_update_cli_mt7612,
	.ez_update_ap_peer_record = ez_driver_ops_update_ap_peer_record_mt7612,
	.ez_update_cli_peer_record = ez_driver_ops_update_cli_peer_record_mt7612,
	.MiniportMMRequest = ez_driver_ops_MiniportMMRequest_mt7612,
	.NdisGetSystemUpTime = ez_driver_ops_NdisGetSystemUpTime_mt7612,
	.AES_Key_Wrap = ez_driver_ops_AES_Key_Wrap_mt7612,
	.RtmpOSWrielessEventSendExt = ez_driver_ops_RtmpOSWrielessEventSendExt_mt7612,
	.ez_send_broadcast_deauth = ez_driver_ops_send_broadcast_deauth_mt7612,
	.MgtMacHeaderInit = ez_driver_ops_MgtMacHeaderInit_mt7612,
	.apcli_stop_auto_connect = ez_driver_ops_apcli_stop_auto_connect_mt7612,
	.timer_init = NULL,
	.set_ap_ssid_null = ez_driver_ops_set_ap_ssid_null_mt7612,
	/*.ez_set_entry_apcli = ez_driver_ops_set_entry_apcli_mt7612,*/
	.ez_get_pentry = ez_driver_ops_get_pentry_mt7612,
	.ez_mark_entry_duplicate = ez_driver_ops_mark_entry_duplicate_mt7612,
	.ez_restore_cli_config = ez_driver_ops_restore_cli_config_mt7612,
	.ScanTableInit = ez_driver_ops_ScanTableInit_mt7612,
	.RT_HMAC_SHA1 = ez_driver_ops_RT_HMAC_SHA1_mt7612,
	.is_mlme_running = ez_driver_ops_is_mlme_running_mt7612,
	.ez_ApSiteSurvey_by_wdev = ez_driver_ops_ApSiteSurvey_by_wdev_mt7612,
	.ez_BssTableSsidSort = ez_driver_ops_BssTableSsidSort_mt7612,
	.ez_get_scan_table = ez_driver_ops_get_scan_table_mt7612,
	.ez_add_entry_in_apcli_tab = ez_driver_ops_add_entry_in_apcli_tab_mt7612,
	.ez_sort_apcli_tab_by_rssi = ez_driver_sort_apcli_tab_by_rssi_mt7612,
	.ez_ApCliBssTabInit = ez_driver_ops_ApCliBssTabInit_mt7612,
	.ez_update_cli_conn = ez_driver_ops_update_cli_conn_mt7612,
	.ez_update_partial_scan = ez_driver_ops_update_partial_scan_mt7612,
	.ez_rtmp_set_channel = ez_driver_ops_rtmp_set_channel_mt7612,
	.wlan_config_set_ht_bw = ez_driver_ops_wlan_config_set_ht_bw_mt7612,
	.wlan_config_set_vht_bw = ez_driver_ops_wlan_config_set_vht_bw_mt7612,
	.wlan_config_set_ext_cha = ez_driver_ops_wlan_config_set_ext_cha_mt7612,
	.SetCommonHtVht = ez_driver_ops_SetCommonHtVht_mt7612,
	.ez_reset_entry_duplicate = ez_driver_ops_reset_entry_duplicate_mt7612
	};

