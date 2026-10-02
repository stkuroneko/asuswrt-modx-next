#ifndef __AMAS_SSD_H__
#define __AMAS_SSD_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shared.h>
#include <proto/ethernet.h>
#include <rc.h>

#if defined(RTCONFIG_AMAS)

#if defined(RTCONFIG_LIBASUSLOG)
#include <libasuslog.h>
#define AMAS_SSD_LOG	"amas_ssd.log"
#endif

#define AMAS_FOLDER		"/tmp/amas/"
#if (defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS))
#define AMAS_JFFS_FOLDER	"/jffs/.sys/amas/"
#define AMAS_SSD_DBG_LOG	AMAS_JFFS_FOLDER"amas_ssd_dbg.log"
#else
#define AMAS_SSD_DBG_LOG	AMAS_FOLDER"amas_ssd_dbg.log"
#endif

#if defined(RTCONFIG_LANTIQ) || defined(RTCONFIG_QCA) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_RALINK)
#define OUI_LEN 3
#define VS_ID 221
#else
#define OUI_LEN DOT11_OUI_LEN
#define VS_ID DOT11_MNG_VS_ID
#endif

#define NVRAM_BUFSIZE   100

/* Debug Print */
#define SSD_DEBUG_ERROR		0x000001
#define SSD_DEBUG_WARNING		0x000002
#define SSD_DEBUG_INFO			0x000004
#define SSD_DEBUG_EVENT		0x000008
#define SSD_DEBUG_DETAIL		0x000010
#define SSD_DEBUG "/tmp/SSD_DEBUG"

extern int ssd_msglevel; //OBD_DEBUG_ERROR | OBD_DEBUG_INFO | OBD_DEBUG_EVENT | OBD_DEBUG_DETAIL;

#define SSD_ERROR(fmt, arg...) \
	do { \
		if ((ssd_msglevel & SSD_DEBUG_ERROR) || f_exists(SSD_DEBUG) > 0) \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		if (nvram_get_int("ssd_syslog")) \
			asusdebuglog(LOG_INFO, AMAS_SSD_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)

#define SSD_WARNING(fmt, arg...) \
	do { \
		if ((ssd_msglevel & SSD_DEBUG_WARNING) || f_exists(SSD_DEBUG) > 0) \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		if (nvram_get_int("ssd_syslog")) \
			asusdebuglog(LOG_INFO, AMAS_SSD_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)

#define SSD_INFO(fmt, arg...) \
	do { \
		if ((ssd_msglevel & SSD_DEBUG_INFO) || f_exists(SSD_DEBUG) > 0) \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		if (nvram_get_int("ssd_syslog")) \
			asusdebuglog(LOG_INFO, AMAS_SSD_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)

#define SSD_EVENT(fmt, arg...) \
	do { \
		if ((ssd_msglevel & SSD_DEBUG_EVENT) || f_exists(SSD_DEBUG) > 0) \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		if (nvram_get_int("ssd_syslog")) \
			asusdebuglog(LOG_INFO, AMAS_SSD_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)

#define SSD_DBG(fmt, arg...) \
	do { \
		if ((ssd_msglevel & SSD_DEBUG_DETAIL) || f_exists(SSD_DEBUG) > 0) \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		if (nvram_get_int("ssd_syslog")) \
			asusdebuglog(LOG_INFO, AMAS_SSD_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)

#define SSD_PRINT(fmt, arg...) \
	do { \
		if (nvram_get_int("ssd_syslog")) \
			asusdebuglog(LOG_INFO, AMAS_SSD_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
		else \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
	} while (0)

#define SSD_LOG(fmt, arg...) \
	do { \
		if ((ssd_msglevel > 0) || f_exists(SSD_DEBUG) > 0) \
			dbg("SSD %s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); \
		asusdebuglog(LOG_INFO, AMAS_SSD_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt, ##arg); \
	} while (0)

#define MAX_VSIE_LEN 512
#define SSID_LEN		33
#define SSID_COUNT	8
#define AMAS_SSD_IPC_SOCKET_PATH	"/etc/ssd_ipc_socket"
#define AMAS_SSD_IPC_MAX_CONNECTION       10
#define SURVEY_RESULT_FILE_NAME		AMAS_FOLDER"survey_result_%d"

#define SSD_STR_SSID 	"ssid"
#define SSD_STR_COST	"cost"
#define SSD_STR_RSSI	"rssi"
#define SSD_STR_CHANNEL	"channel"
#define SSD_STR_BANDWIDTH	"bandwidth"
#define SSD_STR_EVENT_ID	"event_id"
#define SSD_STR_BAND_UNIT	"band_unit"
#define SSD_STR_SSID_LIST	"ssid_list"
#define SSD_STR_2G_LAST_BYTE	"2g_last_byte"
#define SSD_STR_5G_LAST_BYTE	"5g_last_byte"
#define SSD_STR_5G1_LAST_BYTE	"5g1_last_byte"
#define SSD_STR_6G_LAST_BYTE	"6g_last_byte"
#define SSD_STR_CAP_ROLE	"cap_role"
#define SSD_STR_INF_TYPE	"infType"
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
#define SSD_STR_WDS		"wds"
#endif 
#define LEN_VSIE_TYPE_ID		20
#define ONE_BYTE_VSIE_TYPE		1
#define LEN_VSIE_TYPE_AP_LAST_BYTE		4
#define SSD_START_EVENT_MSG	 "{\""SSD_STR_EVENT_ID"\":1,\""SSD_STR_BAND_UNIT"\":%d,\""SSD_STR_SSID_LIST"\":%s}"
#define SSD_CANCEL_EVENT_MSG	 "{\""SSD_STR_EVENT_ID"\":2,\""SSD_STR_BAND_UNIT"\":%d}"

#define SSD_SITESURVEY_COUNT	2

/* Use to store scanned bss which contains vsie information. */
typedef struct site_survey_result {
	struct site_survey_result *next;
	uint8 channel;
	struct ether_addr bssid;
	uint8 vsie_len;
	uint8 vsie[MAX_VSIE_LEN];
	unsigned char rssi;
	uint8 ssid[33];
	uint8 ssid_len;
	uint8 bw;  // bandwidth
	uint8 ss_count;
} site_survey_result_t;

typedef struct ssid_list {
	uint8 ssid_count;
	char ssid[SSID_COUNT][SSID_LEN];
} ssid_list_t;

enum site_survey_status {
	SS_STATUS_START = 1,
	SS_STATUS_EXECUTING,
	SS_STATUS_FINISHED,
	SS_STATUS_CANCELED
};

enum site_survey_event {
	SS_EVENT_START = 1,
	SS_EVENT_CANCEL
};

enum vsie_type {
	VSIE_TYPE_STATUS = 1,
	VSIE_TYPE_COST,
	VSIE_TYPE_ID,
	VSIE_TYPE_RE_MAC,
	VSIE_TYPE_MODEL_NAME,
	VSIE_TYPE_RSSI,
	VSIE_TYPE_TIMESTAMP,
	VSIE_TYPE_REBOOT_TIME = 15,
	VSIE_TYPE_CONN_TIMEOUT = 16,
	VSIE_TYPE_TRAFFIC_TIMEOUT = 17,
	VSIE_TYPE_AP_LAST_BYTE = 18,
	VSIE_TYPE_CAP_ROLE = 19,
	VSIE_TYPE_INF_TYPE = 21,
#if defined(RTCONFIG_AMAS_WDS) && defined(RTCONFIG_BHCOST_OPT)
	VSIE_TYPE_WDS = 23
#endif		
};

enum byte_index {
	byte_index_2G = 0,
	byte_index_5G = 1,
	byte_index_5G1 = 2,
	byte_index_6G = 3
};

struct site_survey_result *do_site_survey(int unit, ssid_list_t *ssid_list);
void stop_site_survey();
#if defined(RTCONFIG_AMAS_WDS)
int get_wds_from_ssd_result(int band,char *ap_mac);
int detect_wds_lldpd(void);
void update_beacon(int wds);
void connect_mode(int option);
int detect_pap_wds(void);
#endif

#endif //#if defined(RTCONFIG_AMAS)

#endif
