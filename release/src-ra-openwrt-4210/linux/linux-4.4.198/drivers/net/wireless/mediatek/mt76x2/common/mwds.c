/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 5F., No.36, Taiyuan St., Jhubei City,
 * Hsinchu County 302,
 * Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2009, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************


 Module Name:
 mwds.c

Abstract:
This is MWDS feature used to process those 4-addr of connected APClient or STA.

Revision History:
Who          When          What
---------    ----------    ----------------------------------------------
 */
#ifdef MWDS
#include "rt_config.h"

VOID MWDSConnEntryListInit(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	MULTISSID_STRUCT *pMbss = NULL;

	if (ifIndex >= HW_BEACON_MAX_NUM)
		return;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	if (pMbss->bMWDSAPInit)
		return;

	NdisAllocateSpinLock(pAd, &pMbss->MWDSConnEntryLock);
	DlListInit(&pMbss->MWDSConnEntryList);
}

VOID MWDSConnEntryListClear(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	MULTISSID_STRUCT *pMbss = NULL;
	struct _MWDS_CONNECT_ENTRY *pConnEntry = NULL, *pConnEntryTmp = NULL;
	PDL_LIST pMWDSConnEntryList = NULL;

	if (ifIndex >= HW_BEACON_MAX_NUM)
		return;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	if (!pMbss->bMWDSAPInit)
		return;

	pMWDSConnEntryList = &pMbss->MWDSConnEntryList;
	DlListForEachSafe(pConnEntry, pConnEntryTmp, pMWDSConnEntryList, struct  _MWDS_CONNECT_ENTRY, List)
	{
		if (pConnEntry) {
			DlListDel(&pConnEntry->List);
			os_free_mem(NULL, pConnEntry);
		}
	}

	NdisFreeSpinLock(&pMbss->MWDSConnEntryLock);
}

BOOLEAN MWDSConnEntryLookupByWCID(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN UCHAR wcid)
{
	MULTISSID_STRUCT *pMbss = NULL;
	PDL_LIST pMWDSConnEntryList = NULL;
	struct _MWDS_CONNECT_ENTRY *pConnEntry = NULL;
	BOOLEAN bFound = FALSE;

	if ((ifIndex >= HW_BEACON_MAX_NUM) || (MWDSGetConnEntryCount(pAd, ifIndex) == 0))
		return FALSE;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	pMWDSConnEntryList = &pMbss->MWDSConnEntryList;
	DlListForEach(pConnEntry, pMWDSConnEntryList, struct _MWDS_CONNECT_ENTRY, List)
	{
		if (pConnEntry &&
				pConnEntry->Valid &&
				(pConnEntry->wcid == wcid)) {
			bFound = TRUE;
			break;
		}
	}

	return bFound;
}

BOOLEAN MWDSConnEntryLookupByAddr(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN PUCHAR pMac)
{
	MULTISSID_STRUCT *pMbss = NULL;
	PDL_LIST pMWDSConnEntryList = NULL;
	struct _MWDS_CONNECT_ENTRY *pConnEntry = NULL;
	PMAC_TABLE_ENTRY pEntry = NULL;
	BOOLEAN bFound = FALSE;

	if ((ifIndex >= HW_BEACON_MAX_NUM) ||
			(MWDSGetConnEntryCount(pAd, ifIndex) == 0) ||
			(pMac == NULL))
		return FALSE;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	pMWDSConnEntryList = &pMbss->MWDSConnEntryList;
	DlListForEach(pConnEntry, pMWDSConnEntryList, struct _MWDS_CONNECT_ENTRY, List)
	{
		if (pConnEntry && pConnEntry->Valid && VALID_WCID(pConnEntry->wcid)) {
			pEntry = &pAd->MacTab.Content[pConnEntry->wcid];
			if (MAC_ADDR_EQUAL(pMac, pEntry->Addr)) {
				bFound = TRUE;
				break;
			}
		}
	}

	return bFound;
}

VOID MWDSConnEntryUpdate(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN UCHAR wcid)
{
	MULTISSID_STRUCT *pMbss = NULL;
	struct _MWDS_CONNECT_ENTRY *pNewConnEntry = NULL;

	if ((ifIndex >= HW_BEACON_MAX_NUM) || MWDSConnEntryLookupByWCID(pAd, ifIndex, wcid))
		return;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	os_alloc_mem(pAd, (UCHAR **)&pNewConnEntry, sizeof(struct  _MWDS_CONNECT_ENTRY));
	if (pNewConnEntry) {
		NdisZeroMemory(pNewConnEntry, sizeof(struct _MWDS_CONNECT_ENTRY));
		pNewConnEntry->Valid = 1;
		pNewConnEntry->wcid = wcid;
		RTMP_SEM_LOCK(&pMbss->MWDSConnEntryLock);
		DlListAddTail(&pMbss->MWDSConnEntryList, &pNewConnEntry->List);
		RTMP_SEM_UNLOCK(&pMbss->MWDSConnEntryLock);
	} else
		DBGPRINT(RT_DEBUG_ERROR, ("%s: Fail to alloc memory for pNewConnEntry\n", __func__));
}

VOID MWDSConnEntryDelete(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN UCHAR wcid)
{
	MULTISSID_STRUCT *pMbss = NULL;
	struct _MWDS_CONNECT_ENTRY *pConnEntry = NULL;
	PDL_LIST pMWDSConnEntryList = NULL;

	if (MWDSGetConnEntryCount(pAd, ifIndex) == 0)
		return;

	if (ifIndex >= HW_BEACON_MAX_NUM)
		return;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	pMWDSConnEntryList = &pMbss->MWDSConnEntryList;
	RTMP_SEM_LOCK(&pMbss->MWDSConnEntryLock);
	DlListForEach(pConnEntry, pMWDSConnEntryList, struct _MWDS_CONNECT_ENTRY, List)
	{
		if (pConnEntry &&
				pConnEntry->Valid &&
				(pConnEntry->wcid == wcid)) {
			DlListDel(&pConnEntry->List);
			os_free_mem(NULL, pConnEntry);
			RoutingTabSetAllFree(pAd, ifIndex, wcid, ROUTING_ENTRY_MWDS);
			break;
		}
	}
	RTMP_SEM_UNLOCK(&pMbss->MWDSConnEntryLock);
}

INT MWDSGetConnEntryCount(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	int count = 0;
	MULTISSID_STRUCT *pMbss = NULL;

	if (ifIndex >= HW_BEACON_MAX_NUM)
		return 0;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	if (!pMbss->bMWDSAPInit)
		return 0;

	count = DlListLen(&pMbss->MWDSConnEntryList);
	return count;
}

BOOLEAN ISMWDSValid(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	MULTISSID_STRUCT *pMbss = NULL;

	if (ifIndex >= HW_BEACON_MAX_NUM)
		return FALSE;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
	if (!pMbss->bMWDSAPInit || (MWDSGetConnEntryCount(pAd, ifIndex) == 0))
		return FALSE;

	return TRUE;
}

VOID MWDSProxyEntryDelete(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN PUCHAR pMac)
{
	if (!ISMWDSValid(pAd, ifIndex))
		return;

	RoutingTabSetOneFree(pAd, ifIndex, pMac, ROUTING_ENTRY_MWDS);
}

BOOLEAN MWDSProxyLookup(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN PUCHAR pMac,
		IN BOOLEAN bUpdateAliveTime,
		OUT UCHAR *pWcid)
{
	UCHAR Wcid;

	if (!ISMWDSValid(pAd, ifIndex))
		return FALSE;

	if (RoutingTabLookup(pAd, ifIndex, pMac, bUpdateAliveTime, &Wcid) != NULL) {
		*pWcid = Wcid;
		return TRUE;
	} else
		return FALSE;
}

VOID MWDSProxyTabUpdate(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN UCHAR wcid,
		IN PUCHAR pMac,
		IN UINT32 ARPSenderIP
		)
{
	UCHAR ProxyAPWcid = 0;
	BOOLEAN bFound = FALSE;
	struct _ROUTING_ENTRY *pRoutingEntry = NULL;

	if (!ISMWDSValid(pAd, ifIndex))
		return;

	if (!VALID_WCID(wcid) || !pMac)
		return;

	pRoutingEntry = RoutingTabLookup(pAd, ifIndex, pMac, TRUE, &ProxyAPWcid);
	bFound = (pRoutingEntry != NULL)?TRUE:FALSE;
	if (bFound) {
		if (ROUTING_ENTRY_TEST_FLAG(pRoutingEntry, ROUTING_ENTRY_MWDS)) {
			/* Mean the target change to other ProxyAP */
			if (ProxyAPWcid != wcid) {
				RoutingTabSetOneFree(pAd, ifIndex, pMac, ROUTING_ENTRY_MWDS);
				pRoutingEntry = NULL;
				bFound = FALSE;
			}
		} else {
			/* Assign MWDS falg to this one if found. */
			SET_ROUTING_ENTRY(pRoutingEntry, ROUTING_ENTRY_MWDS);
		}
	}

	if (!bFound) {
		/* Allocate a new one if not found. */
		pRoutingEntry = RoutingTabGetFree(pAd, ifIndex);
		if (pRoutingEntry) {
			SET_ROUTING_ENTRY(pRoutingEntry, ROUTING_ENTRY_MWDS);
			RoutingEntrySet(pAd, ifIndex, wcid, pMac, pRoutingEntry);
		}
	}

	if (pRoutingEntry != NULL && (ARPSenderIP != 0)) /* ARP Sender IP Update*/
		RoutingTabARPLookupUpdate(pAd, ifIndex, pRoutingEntry, ARPSenderIP);
}

VOID MWDSProxyTabMaintain(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	if (!ISMWDSValid(pAd, ifIndex))
		return;

	RoutingTabMaintain(pAd, ifIndex);
}

PNDIS_PACKET MWDSClonePacket(
		IN PRTMP_ADAPTER pAd,
		IN PNET_DEV if_dev,
		IN PNDIS_PACKET pPacket)
{
	struct sk_buff *skb = NULL;
	PNDIS_PACKET pPacketClone = NULL;

	OS_PKT_CLONE(pAd, pPacket, skb, MEM_ALLOC_FLAG)
		if (skb) {
			skb->dev = if_dev;
			pPacketClone = OSPKT_TO_RTPKT(skb);
		}

	return pPacketClone;
}

void MWDSSendClonePacket(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN PNDIS_PACKET pPacket,
		IN PUCHAR pExcludeMac)
{
	struct wifi_dev *wdev = NULL;
#ifdef WH_EZ_SETUP
	struct wifi_dev *ap_wdev = &pAd->ApCfg.MBSSID[ifIndex].wdev;
#endif
	PNDIS_PACKET pPacketClone = NULL;
	PDL_LIST pMWDSConnEntryList = NULL;
	struct _MWDS_CONNECT_ENTRY *pConnEntry = NULL;
	struct _ROUTING_ENTRY *pRoutingEntry = NULL;
	PMAC_TABLE_ENTRY pEntry = NULL;
	BOOLEAN bFound = FALSE;
	UCHAR Wcid = 0;
#ifdef WH_EZ_SETUP
	BOOLEAN drop_pkt_to_dup_ez_apcli = FALSE;
#endif

	if (!pPacket || (ifIndex >= HW_BEACON_MAX_NUM))
		return;
#ifdef WH_EZ_SETUP
		if ((IS_EZ_SETUP_ENABLED(ap_wdev))
#ifdef EZ_API_SUPPORT
			&& (ap_wdev->ez_driver_params.ez_api_mode != CONNECTION_OFFLOAD)
#endif
			)
			drop_pkt_to_dup_ez_apcli =
			ez_ap_tx_grp_pkt_drop_to_ez_apcli(ap_wdev, (struct sk_buff *)pPacket);
#endif

	if ((MWDSGetConnEntryCount(pAd, ifIndex) > 0)) {
		if (pExcludeMac) {
			pRoutingEntry = RoutingTabLookup(pAd, ifIndex, pExcludeMac, FALSE, &Wcid);
			if (pRoutingEntry && ROUTING_ENTRY_TEST_FLAG(pRoutingEntry, ROUTING_ENTRY_MWDS))
				bFound = TRUE;
			else
				bFound = FALSE;
		}

		pMWDSConnEntryList = &pAd->ApCfg.MBSSID[ifIndex].MWDSConnEntryList;
		DlListForEach(pConnEntry, pMWDSConnEntryList, struct _MWDS_CONNECT_ENTRY, List)
		{
			if (pConnEntry && pConnEntry->Valid && VALID_WCID(pConnEntry->wcid)) {
				if (bFound && (Wcid == pConnEntry->wcid))
					continue;

				pEntry = &pAd->MacTab.Content[pConnEntry->wcid];
				wdev = pEntry->wdev;
				if (!wdev || !wdev->if_dev)
					continue;
#if (defined(WH_EZ_SETUP) && defined(EZ_DUAL_BAND_SUPPORT))
				if ((IS_EZ_SETUP_ENABLED(wdev))
#ifdef EZ_API_SUPPORT
				 && (wdev->ez_driver_params.ez_api_mode != CONNECTION_OFFLOAD)
#endif
				) {
					if (drop_pkt_to_dup_ez_apcli && pEntry->link_duplicate) {
						EZ_DEBUG(DBG_CAT_ALL, DBG_SUBCAT_ALL, EZ_DBG_LVL_TRACE,
							("Skip sending Grp pkt to my CLI\n"));
						EZ_DEBUG(DBG_CAT_ALL, DBG_SUBCAT_ALL, EZ_DBG_LVL_TRACE,
							("as it's other band CLI connected to my other AP\n"));

						continue;
					}
				}
#endif
				pPacketClone = MWDSClonePacket(pAd, wdev->if_dev, pPacket);
				if (pPacketClone == NULL) {
					DBGPRINT(RT_DEBUG_ERROR,
					("%s: Fail to alloc memory forpPacketClone\n", __func__));
					return;
				}
				RTMP_SET_PACKET_WCID(pPacketClone, pEntry->wcid);
				RTMP_SET_PACKET_WDEV(pPacketClone, wdev->wdev_idx);
				RTMP_SET_PACKET_MOREDATA(pPacketClone, FALSE);
				APSendPacket(pAd, pPacketClone);
			}
		}
	}
}

VOID MWDSAPPeerEnable(
		IN PRTMP_ADAPTER pAd,
		IN MAC_TABLE_ENTRY * pEntry,
		IN BOOLEAN bWTBLUpdate)
{
	MULTISSID_STRUCT *pMbss = NULL;
#ifdef WSC_AP_SUPPORT
	BOOLEAN bWPSRunning = FALSE;
#endif /* WSC_AP_SUPPORT */
	BOOLEAN bKeySuccess = FALSE;
	UCHAR ifIndex;

	if (!pEntry || !IS_ENTRY_CLIENT(pEntry) || (pEntry->bEnableMWDS == TRUE))
		return;

	ifIndex = pEntry->func_tb_idx;
	if (ifIndex >= HW_BEACON_MAX_NUM)
		return;

	pMbss = &pAd->ApCfg.MBSSID[ifIndex];
#ifdef WSC_AP_SUPPORT
	if (pMbss &&
			(pMbss->WscControl.WscConfMode != WSC_DISABLE) &&
			(pMbss->WscControl.bWscTrigger == TRUE))
		bWPSRunning = TRUE;
#endif /* WSC_AP_SUPPORT */

	/* To check and remove entry which is created from another side. */
	MWDSProxyEntryDelete(pAd, ifIndex, pEntry->Addr);

	if (
#ifdef WSC_AP_SUPPORT
			!bWPSRunning &&
#endif /* WSC_AP_SUPPORT */
			pEntry->bSupportMWDS &&
			pEntry->wdev &&
			pEntry->wdev->bSupportMWDS
	   ) {
		if (bWTBLUpdate) {
			pEntry->bEnableMWDS = TRUE;
			DBGPRINT(RT_DEBUG_WARN,
				("MWDSAPPeerEnable enabled MWDS for entry : "));
			DBGPRINT(RT_DEBUG_WARN,
				("%02x-%02x-%02x-%02x-%02x-%02x\n",
					 PRINT_MAC(pEntry->Addr)));
			bKeySuccess = TRUE;
		} else {
			bKeySuccess = TRUE; /* Open */
			pEntry->bEnableMWDS = TRUE;
			DBGPRINT(RT_DEBUG_WARN,
				("MWDSAPPeerEnable enabled MWDS for entry : "));
			DBGPRINT(RT_DEBUG_WARN,
				("%02x-%02x-%02x-%02x-%02x-%02x\n",
					 PRINT_MAC(pEntry->Addr)));
		}

		if (bKeySuccess) {
			SET_MWDS_OPMODE_AP(pEntry);
			MWDSConnEntryUpdate(pAd, ifIndex, pEntry->wcid);
			DBGPRINT(RT_DEBUG_OFF, ("SET_MWDS_OPMODE_AP OK!\n"));
			return;
		}
	}

	MWDSAPPeerDisable(pAd, pEntry);
}

VOID MWDSAPPeerDisable(
		IN PRTMP_ADAPTER pAd,
		IN MAC_TABLE_ENTRY * pEntry)
{
	UCHAR ifIndex;

	if (!pEntry)
		return;

	ifIndex = pEntry->func_tb_idx;
	if (ifIndex >= HW_BEACON_MAX_NUM)
		return;

	if (IS_MWDS_OPMODE_AP(pEntry))
		MWDSConnEntryDelete(pAd, ifIndex, pEntry->wcid);

	if (pEntry->bEnableMWDS)
		DBGPRINT(RT_DEBUG_WARN,
			("MWDSAPPeerDisable: Disable MWDS for entry :"));
		DBGPRINT(RT_DEBUG_WARN,
			("%02x-%02x-%02x-%02x-%02x-%02x\n",
			PRINT_MAC(pEntry->Addr)));

	pEntry->bSupportMWDS = FALSE;
	pEntry->bEnableMWDS = FALSE;
	SET_MWDS_OPMODE_NONE(pEntry);
}

#ifdef APCLI_SUPPORT
VOID MWDSAPCliPeerEnable(
		IN PRTMP_ADAPTER pAd,
		IN PAPCLI_STRUCT pApCliEntry,
		IN MAC_TABLE_ENTRY * pEntry,
		IN BOOLEAN bWTBLUpdate)
{

#ifdef WSC_AP_SUPPORT
	BOOLEAN bWPSRunning = FALSE;
#endif /* WSC_AP_SUPPORT */
	BOOLEAN bKeySuccess = FALSE;

	if (!pApCliEntry || !pEntry || !IS_ENTRY_APCLI(pEntry) || (pApCliEntry->bEnableMWDS == TRUE))
		return;

#ifdef WSC_AP_SUPPORT
	if (((pApCliEntry->WscControl.WscConfMode != WSC_DISABLE) &&
				(pApCliEntry->WscControl.bWscTrigger == TRUE)))
		bWPSRunning = TRUE;
#endif /* WSC_AP_SUPPORT */

	if (
#ifdef WSC_AP_SUPPORT
			!bWPSRunning &&
#endif /* WSC_AP_SUPPORT */
			pApCliEntry->MlmeAux.bSupportMWDS &&
			pApCliEntry->wdev.bSupportMWDS) {

		if (bWTBLUpdate) {
			pApCliEntry->bEnableMWDS = TRUE;
			pEntry->bEnableMWDS = TRUE;
			DBGPRINT(RT_DEBUG_WARN,
				("MWDSAPCliPeerEnable enabled MWDS for entry : "));
			DBGPRINT(RT_DEBUG_WARN,
				("%02x-%02x-%02x-%02x-%02x-%02x\n",
				PRINT_MAC(pEntry->Addr)));
			bKeySuccess = TRUE;
		} else {
			bKeySuccess = TRUE; /* Open */
			pApCliEntry->bEnableMWDS = TRUE;
			pEntry->bEnableMWDS = TRUE; /* need to set before RTMP_STA_ENTRY */
			DBGPRINT(RT_DEBUG_WARN,
				("MWDSAPCliPeerEnable enabled MWDS for entry : "));
			DBGPRINT(RT_DEBUG_WARN,
				("%02x-%02x-%02x-%02x-%02x-%02x\n",
				PRINT_MAC(pEntry->Addr)));
		}

		if (bKeySuccess) {
			SET_MWDS_OPMODE_APCLI(pEntry);
			DBGPRINT(RT_DEBUG_OFF, ("SET_MWDS_OPMODE_APCLI OK!\n"));
			return;
		}
	}

	MWDSAPCliPeerDisable(pAd, pApCliEntry, pEntry);
}

VOID MWDSAPCliPeerDisable(
		IN PRTMP_ADAPTER pAd,
		IN PAPCLI_STRUCT pApCliEntry,
		IN MAC_TABLE_ENTRY * pEntry)
{
	if (!pApCliEntry || !pEntry)
		return;

	if (pEntry->bEnableMWDS)
		DBGPRINT(RT_DEBUG_WARN,
			("MWDSAPCliPeerDisable: Disable MWDS for entry :"));
		DBGPRINT(RT_DEBUG_WARN,
			("%02x-%02x-%02x-%02x-%02x-%02x\n",
			PRINT_MAC(pEntry->Addr)));

	pApCliEntry->bEnableMWDS = FALSE;
	pEntry->bEnableMWDS = FALSE;
	SET_MWDS_OPMODE_NONE(pEntry);
}
#endif /* APCLI_SUPPORT */

/* INT32 MtCmdSetMwdsEnable(RTMP_ADAPTER *pAd, UINT8 McuDest, UINT32 en); */

INT MWDSEnable(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN BOOLEAN isAP,
		IN BOOLEAN isDevOpen)
{
	struct wifi_dev *wdev = NULL;

	if (isAP) {
		if (ifIndex < HW_BEACON_MAX_NUM) {
			wdev = &pAd->ApCfg.MBSSID[ifIndex].wdev;
			if (!wdev->bSupportMWDS) {
				wdev->bSupportMWDS = TRUE;
				MWDSAPUP(pAd, ifIndex);
				/*
				* if (!isDevOpen)
				* UpdateBeaconHandler(pAd, wdev, IE_CHANGE);
				*/
			}
		}
	}
#ifdef APCLI_SUPPORT
	else {
		if (ifIndex < MAX_APCLI_NUM) {
			wdev = &pAd->ApCfg.ApCliTab[ifIndex].wdev;
			if (!wdev->bSupportMWDS)
				wdev->bSupportMWDS = TRUE;
		}
	}
#endif /* APCLI_SUPPORT */
	pAd->mwds_interface_count++;
	/* MtCmdSetMwdsEnable(pAd, HOST2CR4, TRUE);*/
	return TRUE;
}

INT MWDSDisable(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex,
		IN BOOLEAN isAP,
		IN BOOLEAN isDevClose)
{
	struct wifi_dev *wdev = NULL;

	if (isAP) {
		if (ifIndex < HW_BEACON_MAX_NUM) {
			wdev = &pAd->ApCfg.MBSSID[ifIndex].wdev;
			if (wdev && wdev->bSupportMWDS) {
				wdev->bSupportMWDS = FALSE;
				MWDSAPDown(pAd, ifIndex);
				/*
				* if(!isDevClose)
				* UpdateBeaconHandler(pAd, wdev, IE_CHANGE);
				*/
			}
		}
	}
#ifdef APCLI_SUPPORT
	else {
		if (ifIndex < MAX_APCLI_NUM) {
			wdev = &pAd->ApCfg.ApCliTab[ifIndex].wdev;
			if (wdev && wdev->bSupportMWDS)
				wdev->bSupportMWDS = FALSE;
		}
	}
#endif /* APCLI_SUPPORT */
	pAd->mwds_interface_count--;
	/*
	* if (!pAd->mwds_interface_count){
	* MtCmdSetMwdsEnable(pAd, HOST2CR4, FALSE);
	* }
	*/
	return TRUE;
}

INT MWDSAPUP(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	if (ifIndex >= HW_BEACON_MAX_NUM)
		return FALSE;

	MWDSConnEntryListInit(pAd, ifIndex);
	RoutingTabInit(pAd, ifIndex, ROUTING_ENTRY_MWDS);
	pAd->ApCfg.MBSSID[ifIndex].bMWDSAPInit = TRUE;

	return TRUE;
}

INT MWDSAPDown(
		IN PRTMP_ADAPTER pAd,
		IN UCHAR ifIndex)
{
	if (ifIndex >= HW_BEACON_MAX_NUM)
		return FALSE;

	MWDSConnEntryListClear(pAd, ifIndex);
	RoutingTabDestory(pAd, ifIndex, ROUTING_ENTRY_MWDS);
	pAd->ApCfg.MBSSID[ifIndex].bMWDSAPInit = FALSE;

	return TRUE;
}

INT	Set_Enable_MWDS_Proc(
		IN  PRTMP_ADAPTER pAd,
		IN  BOOLEAN Enable,
		IN  BOOLEAN isAP)
{
	POS_COOKIE	pObj;
	UCHAR	ifIndex;

	pObj = (POS_COOKIE) pAd->OS_Cookie;

	if (isAP) {
		ifIndex = pObj->ioctl_if;
		pAd->ApCfg.MBSSID[ifIndex].wdev.bDefaultMwdsStatus = (Enable == 0)?FALSE:TRUE;
	}
#ifdef APCLI_SUPPORT
	else {
		if (pObj->ioctl_if_type != INT_APCLI)
			return FALSE;
		ifIndex = pObj->ioctl_if;
		pAd->ApCfg.ApCliTab[ifIndex].wdev.bDefaultMwdsStatus = (Enable == 0)?FALSE:TRUE;
	}
#endif /* APCLI_SUPPORT */

	if (Enable)
		MWDSEnable(pAd, ifIndex, isAP, FALSE);
	else
		MWDSDisable(pAd, ifIndex, isAP, FALSE);

	return TRUE;
}

INT Set_Ap_MWDS_Proc(
	IN  PRTMP_ADAPTER pAd,
	IN  PSTRING arg)
{
	UCHAR Enable;

	Enable = simple_strtol(arg, 0, 10);

	return Set_Enable_MWDS_Proc(pAd, Enable, TRUE);
}

INT Set_ApCli_MWDS_Proc(
	IN  PRTMP_ADAPTER pAd,
	IN  PSTRING arg)
{
	UCHAR Enable;

	Enable = simple_strtol(arg, 0, 10);

	return Set_Enable_MWDS_Proc(pAd, Enable, FALSE);
}

INT Set_Ap_MWDS_Show_Proc(
	IN  PRTMP_ADAPTER pAd,
	IN  PSTRING arg)
{
	POS_COOKIE pObj;
	UCHAR ifIndex;
	BOOLEAN bEnable, bSupportMWDS;

	pObj = (POS_COOKIE) pAd->OS_Cookie;
	ifIndex = pObj->ioctl_if;

	if (((pObj->ioctl_if_type == INT_MBSSID) || (pObj->ioctl_if_type == INT_MAIN)) &&
			(ifIndex < HW_BEACON_MAX_NUM))
		bSupportMWDS = pAd->ApCfg.MBSSID[ifIndex].wdev.bSupportMWDS;
	else
		return FALSE;

	bEnable = bSupportMWDS;

	DBGPRINT(RT_DEBUG_OFF, ("%d\n", bEnable));
	return TRUE;
}

INT Set_ApCli_MWDS_Show_Proc(
	IN  PRTMP_ADAPTER pAd,
	IN  PSTRING arg)
{
	POS_COOKIE pObj;
	UCHAR ifIndex;
	BOOLEAN bEnable, bSupportMWDS;

	pObj = (POS_COOKIE) pAd->OS_Cookie;
	ifIndex = pObj->ioctl_if;

	if ((pObj->ioctl_if_type == INT_APCLI) && (ifIndex < MAX_APCLI_NUM))
		bSupportMWDS = pAd->ApCfg.ApCliTab[ifIndex].wdev.bSupportMWDS;
	else
		return FALSE;

	bEnable = bSupportMWDS;

	DBGPRINT(RT_DEBUG_OFF, ("%d\n", bEnable));
	return TRUE;
}

INT Set_APProxy_Status_Show_Proc(
	IN  PRTMP_ADAPTER pAd,
	IN  PSTRING arg)
{
	POS_COOKIE pObj;
	UCHAR ifIndex;
	INT32 i, count = 0;
	UINT32 ip_addr = 0;
	ULONG Now = 0, AliveTime = 0;
	PDL_LIST pMWDSConnEntryList = NULL;
	struct _MWDS_CONNECT_ENTRY *pConnEntry = NULL;
	struct _ROUTING_ENTRY *pRoutingEntry = NULL, **RoutingEntryList[ROUTING_POOL_SIZE];
	UCHAR *pProxyMac = NULL, ProxyMacIP[64];

	pObj = (POS_COOKIE) pAd->OS_Cookie;
	ifIndex = pObj->ioctl_if;

	if ((pObj->ioctl_if_type != INT_MBSSID) && (pObj->ioctl_if_type != INT_MAIN))
		return FALSE;

	if (ifIndex >= HW_BEACON_MAX_NUM)
		return FALSE;

	if ((MWDSGetConnEntryCount(pAd, ifIndex) == 0))
		return TRUE;

	pMWDSConnEntryList = &pAd->ApCfg.MBSSID[ifIndex].MWDSConnEntryList;
	NdisGetSystemUpTime(&Now);
	DlListForEach(pConnEntry, pMWDSConnEntryList, struct _MWDS_CONNECT_ENTRY, List)
	{
		if (pConnEntry && pConnEntry->Valid && VALID_WCID(pConnEntry->wcid)) {
			count = 0;
			pProxyMac = pAd->MacTab.Content[pConnEntry->wcid].Addr;
			DBGPRINT(RT_DEBUG_OFF,
				("Proxy Mac: %02X:%02X:%02X:%02X:%02X:%02X\n",
				PRINT_MAC(pProxyMac)));
			if (GetRoutingEntryAll(pAd, ifIndex, pConnEntry->wcid, ROUTING_ENTRY_MWDS,
						ROUTING_POOL_SIZE,
						(struct _ROUTING_ENTRY **)&RoutingEntryList, &count)) {

				for (i = 0; i < count; i++) {
					pRoutingEntry = (struct _ROUTING_ENTRY *)RoutingEntryList[i];
					if (!pRoutingEntry)
						continue;

					if (pRoutingEntry->KeepAliveTime >= Now)
						AliveTime = ((pRoutingEntry->KeepAliveTime - Now) / OS_HZ);
					else if (pRoutingEntry->RetryTime >= Now)
						AliveTime = ((pRoutingEntry->RetryTime - Now) / OS_HZ);
					else
						AliveTime = 0;

					if (pRoutingEntry->IPAddr != 0) {
						ip_addr = pRoutingEntry->IPAddr;
						sprintf(ProxyMacIP, "%d.%d.%d.%d", (ip_addr & 0xff),
							((ip_addr & (0xff << 8)) >> 8),
							((ip_addr & (0xff << 16)) >> 16),
							((ip_addr & (0xff << 24)) >> 24));
					} else
						strcpy(ProxyMacIP, "0.0.0.0");
					DBGPRINT(RT_DEBUG_OFF,
						("\tMAC: %02X:%02X:%02X:%02X:%02X:%02X\t",
						PRINT_MAC(pRoutingEntry->Mac)));
					DBGPRINT(RT_DEBUG_OFF,
						("IP: %s\t\AgeOut: %lus\tRetry: (%d,%d)\n",
						ProxyMacIP, AliveTime,
						pRoutingEntry->Retry, ROUTING_ENTRY_MAX_RETRY));
				}
				DBGPRINT(RT_DEBUG_OFF, ("Total Count = %d\n\n", count));
			}
		}
	}

	return TRUE;
}

VOID rtmp_read_MWDS_from_file(
		IN  PRTMP_ADAPTER pAd,
		PSTRING tmpbuf,
		PSTRING buffer)
{
	PSTRING	tmpptr = NULL;

#ifdef CONFIG_AP_SUPPORT
	/* ApMWDS */
	if (RTMPGetKeyParameter("ApMWDS", tmpbuf, 256, buffer, TRUE)) {
		INT	Value;

		UCHAR i = 0;

		for (i = 0, tmpptr = rstrtok(tmpbuf, ";"); tmpptr; tmpptr = rstrtok(NULL, ";"), i++) {
			if (i >= pAd->ApCfg.BssidNum)
				break;

			Value = (INT) simple_strtol(tmpptr, 0, 10);
			if (Value == 0)
				MWDSDisable(pAd, i, TRUE, FALSE);
			else
				MWDSEnable(pAd, i, TRUE, FALSE);

			pAd->ApCfg.MBSSID[i].wdev.bDefaultMwdsStatus = (Value == 0)?FALSE:TRUE;

			DBGPRINT(RT_DEBUG_TRACE, ("ApMWDS=%d\n", Value));
		}
	}
#endif /* CONFIG_AP_SUPPORT */

#ifdef APCLI_SUPPORT
	/* ApCliMWDS */
	if (RTMPGetKeyParameter("ApCliMWDS", tmpbuf, 256, buffer, TRUE)) {
		INT	Value;

		UCHAR i = 0;

		for (i = 0, tmpptr = rstrtok(tmpbuf, ";"); tmpptr; tmpptr = rstrtok(NULL, ";"), i++) {
			if (i >= MAX_APCLI_NUM)
				break;

			Value = (INT) simple_strtol(tmpptr, 0, 10);
			if (Value == 0)
				MWDSDisable(pAd, i, FALSE, FALSE);
			else
				MWDSEnable(pAd, i, FALSE, FALSE);

			pAd->ApCfg.ApCliTab[i].wdev.bDefaultMwdsStatus = (Value == 0)?FALSE:TRUE;
			DBGPRINT(RT_DEBUG_TRACE, ("ApCliMWDS=%d\n", Value));
		}
	}
#endif /* APCLI_SUPPORT */
}

#endif /* MWDS */
