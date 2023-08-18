
struct _RTMP_ADAPTER;

#define RALINK_IE_LEN   0x9
#define MEDIATEK_IE_LEN 0x9

#define RALINK_AGG_CAP      (1 << 0)
#define RALINK_PIGGY_CAP    (1 << 1)
#define RALINK_RDG_CAP      (1 << 2)
#define RALINK_256QAM_CAP   (1 << 3)

#define MEDIATEK_256QAM_CAP (1 << 3)

#define BROADCOM_256QAM_CAP (1 << 0)
#define BROADCOM_2G_4SS_CAP (1 << 4)

#ifdef MWDS
#define MEDIATEK_MWDS_CAP   (1 << 7)
#endif
#ifdef STA_FORCE_ROAM_SUPPORT
#define MEDIATEK_CLI_ENTRY (1 << 4)
#endif

extern UCHAR CISCO_OUI[];
extern UCHAR RALINK_OUI[];
extern UCHAR WPA_OUI[];
extern UCHAR RSN_OUI[];
extern UCHAR WAPI_OUI[];
extern UCHAR WME_INFO_ELEM[];
extern UCHAR WME_PARM_ELEM[];
extern UCHAR BROADCOM_OUI[];
extern UCHAR WPS_OUI[];

struct GNU_PACKED _ie_hdr {
	UCHAR eid;
	UINT8 len;
};


struct GNU_PACKED _ralink_ie {
	struct GNU_PACKED _ie_hdr ie_hdr;
	UCHAR oui[3];
	UCHAR cap0;
	UCHAR cap1;
	UCHAR cap2;
	UCHAR cap3;
};


struct GNU_PACKED _vht_cap_ie {
	struct GNU_PACKED _ie_hdr ie_hdr;
	UCHAR vht_cap_info[4];
	UCHAR support_vht_mcs_nss[8];
};


struct GNU_PACKED _vht_op_ie {
	struct GNU_PACKED _ie_hdr ie_hdr;
	UCHAR vht_op_info[3];
	UCHAR basic_vht_mcs_nss[2];
};


struct GNU_PACKED _vht_tx_pwr_env_ie {
	struct GNU_PACKED _ie_hdr ie_hdr;
	UCHAR tx_pwr_info;
	UCHAR local_max_txpwr_20Mhz;
	UCHAR local_max_txpwr_40Mhz;
};


struct GNU_PACKED _mediatek_ie {
	struct GNU_PACKED _ie_hdr ie_hdr;
	UCHAR oui[3];
	UCHAR cap0;
	UCHAR cap1;
	UCHAR cap2;
	UCHAR cap3;
};


struct GNU_PACKED _mediatek_vht_ie {
	struct GNU_PACKED _vht_cap_ie vht_cap;
	struct GNU_PACKED _vht_op_ie vht_op;
	struct GNU_PACKED _vht_tx_pwr_env_ie vht_txpwr_env;
};


struct GNU_PACKED _broadcom_ie {
	struct GNU_PACKED _ie_hdr ie_hdr;
	UCHAR oui[3];
	UCHAR fixed_pattern[2];
	struct GNU_PACKED _vht_cap_ie vht_cap;
	struct GNU_PACKED _vht_op_ie vht_op;
	struct GNU_PACKED _vht_tx_pwr_env_ie vht_txpwr_env;
};


ULONG build_vendor_ie(struct _RTMP_ADAPTER *pAd,
		struct wifi_dev *wdev, UCHAR *frame_buffer);

VOID check_vendor_ie(struct _RTMP_ADAPTER *pAd,
		UCHAR *ie_buffer, struct _vendor_ie_cap *vendor_ie);

#ifdef CUSTOMER_VENDOR_IE_SUPPORT
VOID customer_check_vendor_ie(struct _RTMP_ADAPTER *pAd,
		UCHAR *ie_buffer,
		struct customer_vendor_ie *vendor_ie,
		BCN_IE_LIST *ie_list);
#endif /* CUSTOMER_VENDOR_IE_SUPPORT */
