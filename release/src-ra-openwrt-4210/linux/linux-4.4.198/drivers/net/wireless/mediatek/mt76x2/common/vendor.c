#include "rt_config.h"

#define BRCM_VENDOR_VHT_TYPE		0x04

ULONG build_vendor_ie(struct _RTMP_ADAPTER *pAd,
		struct wifi_dev *wdev, UCHAR *frame_buffer)
{
	struct _mediatek_ie mtk_ie;
	ULONG mtk_ie_len = 0;
	ULONG mwds_tag_len = 0;
	UCHAR mwds_tag[] = {0x0A, 0x0A};
	ULONG vendor_ie_len = 0;

	NdisZeroMemory(&mtk_ie, sizeof(struct _mediatek_ie));
	mwds_tag_len = sizeof(mwds_tag);
	mtk_ie.ie_hdr.eid = IE_VENDOR_SPECIFIC;
	mtk_ie.ie_hdr.len = (0x7 + mwds_tag_len);

	mtk_ie.oui[0] = 0x00;
	mtk_ie.oui[1] = 0x0C;
	mtk_ie.oui[2] = 0xE7;
#ifdef MWDS
	if (pAd->chipCap.g_band_256_qam
			&& WMODE_CAP(wdev->PhyMode, WMODE_GN)) {
		mtk_ie.cap0 |= MEDIATEK_256QAM_CAP;
	}
#endif
#ifdef MWDS
	if (wdev->bSupportMWDS)
		mtk_ie.cap0 |= MEDIATEK_MWDS_CAP;
#endif /* MWDS */

#ifdef STA_FORCE_ROAM_SUPPORT
		if ((wdev->wdev_type == WDEV_TYPE_STA) &&  pAd->en_force_roam_supp)
			mtk_ie.cap0 |= MEDIATEK_CLI_ENTRY;
#endif
	MakeOutgoingFrame((frame_buffer + vendor_ie_len),
			&mtk_ie_len, sizeof(struct _mediatek_ie), &mtk_ie,
			END_OF_ARGS);

	vendor_ie_len += mtk_ie_len;
	MakeOutgoingFrame((frame_buffer + vendor_ie_len),
			&mwds_tag_len,
			sizeof(mwds_tag),
			&mwds_tag,
			END_OF_ARGS);

	vendor_ie_len += mwds_tag_len;
	return vendor_ie_len;
}


VOID check_vendor_ie(struct _RTMP_ADAPTER *pAd,
		UCHAR *ie_buffer, struct _vendor_ie_cap *vendor_ie)
{
	PEID_STRUCT info_elem = (PEID_STRUCT)ie_buffer;
	UCHAR mediatek_oui[] = {0x00, 0x0c, 0xe7};

	if (NdisEqualMemory(info_elem->Octet, mediatek_oui, 3)
			&& (info_elem->Len >= 7)) {
		vendor_ie->mtk_cap = (ULONG)info_elem->Octet[3];
		vendor_ie->is_mtk = TRUE;
#ifdef WH_EZ_SETUP
				if(IS_ADPTR_EZ_SETUP_ENABLED(pAd) && info_elem->Octet[3] & MEDIATEK_EASY_SETUP)
				{
					
					ez_vendor_ie_parse(vendor_ie, ie_buffer);
				}
#endif
		if (info_elem->Len > 7) {
#ifdef MWDS
			/* We can't be covered by easy setup customized mtk ie. */
			vendor_ie->mtk_cap_found = TRUE;
			if (MWDS_SUPPORT(vendor_ie->mtk_cap))
				vendor_ie->support_mwds = TRUE;
#endif /* MWDS */
		}
	}
}

