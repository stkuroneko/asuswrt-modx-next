#ifndef __CFG_MNT_H__
#define __CFG_MNT_H__

//Hashtable element structure
typedef struct hash_elem_t {
	struct hash_elem_t* next; 	// Next element in case of a collision
	unsigned char* sessionKey;	// Pointer to the session key
	time_t sessionKeyStartTime;	// the start time of session key
	unsigned char* sessionKey1;	// Pointer to the session key 1
	time_t sessionKey1StartTime;	// the start time of session key 1
	size_t sessionKeyLen;		// the length of session key
	char clientIP[32];		// client IP
	//char clientMac[32];		// client mac
	unsigned int authorized;	// authorized client or not
	unsigned int fwStatus;		// status for firmware upgrade
	unsigned char* featureList;	// Pointer to the feature list
#ifdef RTCONFIG_BHCOST_OPT
	unsigned int soStatus;		// status for notify self optimization
#endif
	unsigned int joinStatus;		// status for join
	unsigned int reconnStatus;		// status for re reconnect
	char key[]; 			// Key of the stored element
} hash_elem_t;

//Hashtabe structure
typedef struct {
	unsigned int capacity;	// Hashtable capacity (in terms of hashed keys)
	unsigned int e_num;	// Number of element currently stored in the hashtable
	hash_elem_t** table;	// The table containaing elements
} hashtable_t;

//Structure used for iterations
typedef struct {
	hashtable_t* ht; 	// The hashtable on which we iterate
	unsigned int index;	// Current index in the table
	hash_elem_t* elem; 	// Curent element in the list
} hash_elem_it;

// Inititalize hashtable iterator on hashtable 'ht'
#define HT_ITERATOR(ht) {ht, 0, ht->table[0]}
#define HT_CAPACITY	8

typedef struct securityInfo_t
{
	unsigned char *masterKey;	// master key
	unsigned char *serverNounce;	// server nounce
	unsigned char *clientNounce;	// client nounce
	size_t masterKeyLen;		// the length of master key
	size_t serverNounceLen;		// the length of server nounce
	size_t clientNounceLen;		// the length of client nounce
} securityInfo;

struct packetHandler 
{
    int type;
    int (*func)(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
};

extern int cm_processREQ_KU(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_NC(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREP_OK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_CHK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processACK_CHK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_JOIN(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_RPT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_GKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_GREKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_WEVENT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_STALIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_FWSTAT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
//extern int cm_processREQ_CHANSYNC(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_COST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_CLIENTLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#ifdef ONBOARDING
extern int cm_processREQ_ONBOARDING(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_GROUPID(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processACK_GROUPID(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#endif
extern int cm_processREQ_SREKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
extern int cm_processREQ_TOPOLOGY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#ifdef RADAR_DET
extern int cm_processREQ_RADARDET(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#endif	/* RADAR_DET */
extern int cm_processREQ_RELIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#ifdef RTCONFIG_BCN_RPT
extern int cm_processREQ_APLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#endif
#ifdef DUAL_BAND_DETECTION
extern int cm_processREQ_DBLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#endif
extern int cm_processREQ_CHANGED_CONFIG(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#ifdef RTCONFIG_FRONTHAUL_DWB
extern int cm_processREQ_BACKHUALSTATUS(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);
#endif
extern int cm_processREQ_LEVEL(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac);

struct packetHandler packetHandlers[] = {
	{ REQ_KU,	cm_processREQ_KU },
	{ REQ_NC,	cm_processREQ_NC },
	{ REP_OK,	cm_processREP_OK },
	{ REQ_CHK,	cm_processREQ_CHK },
	{ ACK_CHK,	cm_processACK_CHK},
	{ REQ_JOIN,	cm_processREQ_JOIN },
	{ REQ_RPT,	cm_processREQ_RPT },
	{ REQ_GKEY,	cm_processREQ_GKEY },
	{ REQ_GREKEY,	cm_processREQ_GREKEY },
	{ REQ_WEVENT,	cm_processREQ_WEVENT },
	{ REQ_STALIST,	cm_processREQ_STALIST },
	{ REQ_FWSTAT,	cm_processREQ_FWSTAT },
	//{ REQ_CHANSYNC,	cm_processREQ_CHANSYNC },
	{ REQ_COST,	cm_processREQ_COST },
	{ REQ_CLIENTLIST,	cm_processREQ_CLIENTLIST },
#ifdef ONBOARDING
	{ REQ_ONBOARDING,	cm_processREQ_ONBOARDING },
	{ REQ_GROUPID,	cm_processREQ_GROUPID},
	{ ACK_GROUPID,	cm_processACK_GROUPID},
#endif
	{ REQ_SREKEY,	cm_processREQ_SREKEY },
	{ REQ_TOPOLOGY,	cm_processREQ_TOPOLOGY },
#ifdef RADAR_DET
	{ REQ_RADARDET,	cm_processREQ_RADARDET },
#endif	/* RADAR_DET */
	{ REQ_RELIST,	cm_processREQ_RELIST },
#ifdef RTCONFIG_BCN_RPT
	{ REQ_APLIST,	cm_processREQ_APLIST },
#endif
#ifdef DUAL_BAND_DETECTION
	{ REQ_DBLIST,	cm_processREQ_DBLIST },
#endif
	{ REQ_CHANGED_CONFIG,	cm_processREQ_CHANGED_CONFIG },
#ifdef RTCONFIG_FRONTHAUL_DWB
	{ REQ_BACKHUALSTATUS,	cm_processREQ_BACKHUALSTATUS},
#endif
	{ REQ_LEVEL,	cm_processREQ_LEVEL },
	{ -1,		NULL }
};

#define DEFAULT_CFG_CERT_PATH		"/etc/cfg_mnt"
#define DEFAULT_PUBLIC_PEM_FILE		DEFAULT_CFG_CERT_PATH"/pubkey.pem"
#define DEFAULT_PRIVATE_PEM_FILE	DEFAULT_CFG_CERT_PATH"/key.pem"
#define PID_CM_SERVER			"/var/run/cfg_server.pid"
#define CFG_JSON_FILE			"/tmp/cfg.json"
#ifdef RTCONFIG_BHCOST_OPT
#define RSSI_THRESHOLD_5G		-70

enum soStatus {
	SO_NONE = 0,
	SO_DONE
};

#ifdef RTCONFIG_BHSWITCH_RE_SELFOPT
enum bhIndex {
	BH_NONE = 1,
	BH_2G = 2,
	BH_5G = 4,
	BH_6G = 8,
	BH_ETH = 16
};

/* rule 1 - NONE/2G to 5G/6G/ETH, rule 2 - NONE/2G/5G/6G to ETH, rule 3 - ETH to 5G/6G */
#define DEF_BH_SWITCH_RULE		"<3>28<15>16<16>12"

typedef struct _bh_index_mapping {
	int index;
	unsigned int activePath;
} bh_index_mapping;

typedef struct _bh_switch_rule {
	unsigned int from;		/* 1, 2, 4, 8, 16 */
	unsigned int to;         	/* 1, 2, 4, 8, 16 */
} bh_switch_rule;
#endif /* RTCONFIG_BHSWITCH_RE_SELFOPT */
#endif

enum statusType {
	FW_STATUS = 0,
	SO_STATUS = 1,
	JOIN_STATUS = 2,
	MAX_STATUS
};

enum joinStatus {
	JOIN_NONE = 0,
	JOIN_DONE
};

#endif /* __CFG_MNT_H__ */

/* End of cfg_mnt.h */
