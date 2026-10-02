#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#ifdef RTCONFIG_ADV_RAST
#include <sys/un.h>
#endif
#include "encrypt_main.h"
#include "cfg_crc.h"
#include "cfg_common.h"
#include "cfg_param.h"
#include "cfg_mnt.h"
#include "cfg_slavelist.h"
#include "cfg_ipc.h"
#include "cfg_udp.h"
#include "cfg_wevent.h"
#include "cfg_upgrade.h"
#include "cfg_dencrypt.h"
#if defined(RTCONFIG_TCODE) && defined(RTCONFIG_CFGSYNC_LOCSYNC)
#include "cfg_loclist.h"	//cm_transloclist_Parameter()
#endif
/* init sta roaming check */
#ifdef LEGACY_ROAMING
#include "cfg_roaming.h"
#endif
#ifdef ROAMING_INFO
#include "cfg_roaminginfo.h"
#endif
#include "cfg_clientlist.h"
#include "cfg_event.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif
#ifdef RADAR_DET
#include "cfg_radardet.h"
#include "chmgmt.h"
#endif	/* RADAR_DET */

#include <wlioctl.h>
#include <wlutils.h>

#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#else
#include <fcntl.h>
#endif
#include "cfg_sched.h"
#include "cfg_eventnotify.h"

#ifdef RTCONFIG_DWB
#include "cfg_dwb.h"
#endif

#include "cfg_chanspec.h"
#include "cfg_parammgnt.h"
#ifdef DUAL_BAND_DETECTION
#include "cfg_dualbandlist.h"
#endif
#include "cfg_capability.h"

#if defined(RTCONFIG_AMAS_WGN)
#include "cfg_capability.h"
#endif	// RTCONFIG_AMAS_WGN

#include "cfg_action.h"
#ifdef PRELINK
#include "cfg_prelink.h"
#endif

#ifdef RTCONFIG_NBR_RPT
#include "cfg_nbr_rpt.h"
#endif

#include "cfg_ctrllist.h"

#ifdef CONN_DIAG
#include "cfg_conndiag.h"
#endif

#include "cfg_bandindex.h"

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
#include "cfg_centralcontrol.h"
#endif

/* for parameter */
char public_pem_file[64] = {0};
char private_pem_file[64] = {0};
int port = 7788;
static char groupID[64];
int sessionKeyExpireTime = SESSION_KEY_EXPIRE_TIME;
int groupKeyExpireTime = GROUP_KEY_EXPIRE_TIME;
CM_CTRL cm_ctrlBlock;
char err_ptr;
void* HT_ERROR = &err_ptr; // Data pointing to HT_ERROR are returned in case of error
hashtable_t *clientHashTable = NULL;
CM_CLIENT_TABLE *p_client_tbl = NULL;
int shm_client_tbl_id = 0;
#ifdef ONBOARDING
int obTimeStamp = 0;
#endif

/* for pthread */
pthread_mutex_t threadLock;	/* for hashtable */
pthread_mutex_t cfgLock;		/* for cfg client list */
pthread_mutex_t weventLock;		/* for wireless event */
pthread_mutex_t allWeventLock;		/* for all wireless event */
pthread_mutex_t wiredClientListLock;		/* for wired client list */
pthread_mutex_t clientListLock;		/* for client list */
#ifdef ONBOARDING
pthread_mutex_t onboardingLock;		/* for onboarding */
#endif
pthread_mutex_t radarDetLock;		/* for radar detect */
#ifdef ROAMING_INFO
pthread_mutex_t roamingInfoLock;		/* for romaing info */
#endif
#ifdef LEGACY_ROAMING
pthread_mutex_t roamingLock;		/* for romaing */
#endif
pthread_mutex_t reListLock;		/* for re list */
pthread_mutex_t chanspecLock;		/* for chanspec */
#ifdef DUAL_BAND_DETECTION
pthread_mutex_t dualBandLock;		/* for wireless dual band */
#endif
#ifdef PRELINK
pthread_mutex_t prelinkLock;		/* for prelink */
#endif
pthread_mutex_t changedConfigLock;		/* for changed config */
#ifdef RTCONFIG_NBR_RPT
pthread_mutex_t nbrRptLock;		/* for neighbor report */
#endif
#ifdef CONN_DIAG
pthread_mutex_t connDiagLock;	/* for conn diag udp */
#endif
pthread_attr_t attr;
pthread_attr_t *attrp = NULL;

#ifdef RTCONFIG_DWB
int dwbUpdate = 0;
#endif

/* for function */
hash_elem_t* ht_iterate_elem(hash_elem_it* iterator);
static void cm_closeSocket(CM_CTRL *pCtrlBK);
static int cm_checkSessionKeyExpire(hash_elem_t* elem);
static int cm_sendNotification(hash_elem_t* elem, int type, json_object *inData);
static void cm_sendNotificationByType(int notifyType, json_object *inData);
int cm_packetProcess(int sock_fd, unsigned char *data, int data_len, char *client_ip, char *client_mac, CM_CTRL *pCtrlBK, securityInfo *keyInfo);
void *cm_sendCfgAction(void *args);
void *cm_sendGroupRekey(void *args);
static char *cm_getClientMac(char *host, char *macAddr, int macAddrLen);
void cm_generateGroupKey(CM_CTRL *pCtrlBK);
static int cm_prepareGroupKey(char *msg, int msgLen, int reKey);
static int cm_checkCfgInfo(char *clientMac, unsigned char *decryptedMsg, char *msg, int msgLen, int checkVer);
int cm_updateClientLevel();
void cm_updateNetworkCost(char *slaveMac);
void cm_updateNetworkLevel(char *slaveMac);
static int cm_delClientArp(char *clientIp);
static void cm_usr2Handle(int sig);
#ifdef RTCONFIG_BHCOST_OPT
int cm_sendSelfOptimization(unsigned char *decodeMsg, json_object *notifiedRe);
#ifdef RTCONFIG_BHSWITCH_RE_SELFOPT
int cm_judgeSelfOptTrigger(int lastActivePath, int curActivePath);
int cm_initBhSwitchRule();
#endif /* RTCONFIG_BHSWITCH_RE_SELFOPT */
#ifdef RTCONFIG_PREFERAP_RE_SELFOPT
json_object *cm_sendSelfOptByPreferAp(unsigned char *decryptedMsg);
#endif /* RTCONFIG_PREFERAP_RE_SELFOPT */
#endif /* RTCONFIG_BHCOST_OPT */
#ifdef STA_BIND_AP
int cm_updateStaBindingAp(int delAction, char *mac);
#endif /* STA_BIND_AP */
void cm_processWiredClientList(char *msg, char *brMac, json_object *onlineListObj, json_object *offlineListObj);

/* for session & group key to update time */
static long uptimeDiff = 0;
static int uptimeDiffSet = 0;

/* for scheduler */
static struct sched scStatusReport;	/* The scheduler for reporting status */
static struct sched scWeventReport;	/* The scheduler for reporting wireless event */
static struct sched scStaListReport; /* The scheduler for reporting sta list */
static struct sched scClientListReport; /* The scheduler for reporting client list */
static struct sched scGroupKeyCheck; /* The scheduler for checking group key */
#ifdef RADAR_DET
static struct sched scAvailChannelUpdate;	/* The scheduler for update available channel */
#endif
static struct sched scWiredClientListCheck; /* The scheduler for checking wired client list */
static struct sched scReStatusCheck;		/* The scheduler for check re status */
#ifdef RTCONFIG_BHCOST_OPT
static struct sched scReSelfOptCheck;		/* The scheduler for triggering re self optimization */
#endif

/* for band number */
int supportedBandNum = 0;

/* for band version */
int supportedIndexVersion = 1;

/* for the channel selection of 5G low/high band */
int selected5gBand = NO_SELECTION;
int channel5g = 0;
int bw5g = 0;
int nctrlsb5g = 0;

/* for channel info of new band */
json_object *newBandObj = NULL;
/* for multi band */
json_object *multiBandObj = NULL;

#ifdef RTCONFIG_BHCOST_OPT
unsigned int reJoinTime = 0, intervalCheckSelfOpt = 0;
char reJoinMac[18] = {0};

#ifdef RTCONFIG_BHSWITCH_RE_SELFOPT
bh_switch_rule *optBhSwitchRule;
int bhSwitchRuleCount = 0;

bh_index_mapping bh_index_list[] = {
	{ BH_ETH, 	ETH | ETH_2 | ETH_3 | ETH_4 },
	{ BH_2G,	WL_2G },
	{ BH_5G,	WL_5G | WL_5G_1},
	{ BH_6G,	WL_6G },
	{ 0,		0 }
};
#endif /* RTCONFIG_BHSWITCH_RE_SELFOPT */
#endif

int pid = 0;

#ifdef CONN_DIAG
/* for conn diag */
struct list *connDiagUdpList = NULL;
#endif

unsigned char nullMAC[MAC_LEN] = {0};

/* 	Internal funcion to calculate hash for keys.
	It's based on the DJB algorithm from Daniel J. Bernstein.
	The key must be ended by '\0' character.*/
static unsigned int ht_calc_hash(char* key)
{
	unsigned int h = 5381;
	while(*(key++))
		h = ((h << 5) + h) + (*key);
	return h;
}

/* 	Create a hashtable with capacity 'capacity'
	and return a pointer to it*/
hashtable_t* ht_create(unsigned int capacity)
{
	unsigned int i = 0;
	hashtable_t* hasht = malloc(sizeof(hashtable_t));

	if(!hasht)
		return NULL;
	if((hasht->table = malloc(capacity*sizeof(hash_elem_t*))) == NULL)
	{
		free(hasht);
		return NULL;
	}
	hasht->capacity = capacity;
	hasht->e_num = 0;

	for(i = 0; i < capacity; i++)
		hasht->table[i] = NULL;

	return hasht;
}

/* 	Store data in the hashtable. If data with the same keyCLIENT_DETAIL_INFO_TABLE are already stored,
	they are overwritten, and return by the function. Else it return NULL.
	Return HT_ERROR if there are memory alloc error*/
void* ht_put(hashtable_t* hasht, char* key, char *ip, void* data, int dataLen, time_t sessionKeyStartTime)
{
	unsigned int h = 0;
	hash_elem_t* e = NULL;
	hash_elem_it it = HT_ITERATOR(hasht);

	if(data == NULL)
		return NULL;

	h = ht_calc_hash(key) % hasht->capacity;
	e = ht_iterate_elem(&it);

	pthread_mutex_lock(&threadLock);
	while(e != NULL)
	{
		if ((strcmp(e->key, key) == 0 && strcmp(e->clientIP, ip) == 0) ||
			strcmp(e->clientIP, ip) == 0)
		{
			void* ret = e->sessionKey;
			// reset client ip
			if (strlen(ip) > 0) {
				memset(e->clientIP, 0, sizeof(e->clientIP));
				snprintf(e->clientIP, sizeof(e->clientIP), "%s", ip);
			}

			//free sessionKey
			if (e->sessionKey != NULL) {
				free(e->sessionKey);
				e->sessionKey = NULL;
			}
			e->authorized = 0;
			e->fwStatus = FW_NONE;
#ifdef RTCONFIG_BHCOST_OPT
			e->soStatus= SO_NONE;
#endif
			e->joinStatus= JOIN_NONE;
			e->reconnStatus= 0;

			e->sessionKey = data;
			e->sessionKeyLen = dataLen;
			e->sessionKeyStartTime = sessionKeyStartTime;

			/* free sessionKey1 */
			if (e->sessionKey1 != NULL){
				free(e->sessionKey1);
				e->sessionKey1 = NULL;
			}
			e->sessionKey1StartTime = sessionKeyStartTime - sessionKeyExpireTime;

			pthread_mutex_unlock(&threadLock);
			return ret;
		}
		e = ht_iterate_elem(&it);
	}

	// Getting here means the key doesn't already exist

	if((e = malloc(sizeof(hash_elem_t)+strlen(key)+1)) == NULL) {
		pthread_mutex_unlock(&threadLock);
		return HT_ERROR;
	}
	strncpy(e->key, key, strlen(key)+1);
	snprintf(e->clientIP, sizeof(e->clientIP), "%s", ip);
	e->sessionKey = data;
	e->sessionKeyLen = dataLen;
	e->sessionKeyStartTime = sessionKeyStartTime;
	e->authorized = 0;
	e->sessionKey1 = NULL;
	e->sessionKey1StartTime = sessionKeyStartTime - sessionKeyExpireTime;
	e->fwStatus = FW_NONE;
	e->featureList = NULL;
#ifdef RTCONFIG_BHCOST_OPT
	e->soStatus= SO_NONE;
#endif
	e->joinStatus= JOIN_NONE;
	e->reconnStatus= 0;

	// Add the element at the beginning of the linked list
	e->next = hasht->table[h];
	hasht->table[h] = e;
	hasht->e_num ++;

	pthread_mutex_unlock(&threadLock);

	return NULL;
}

/* Upate authorized client in the hashtable */
int ht_update(hashtable_t* hasht, char* key, char* ip, char *feature)
{
	hash_elem_t* e = NULL;
	hash_elem_it it = HT_ITERATOR(hasht);

	e = ht_iterate_elem(&it);

	pthread_mutex_lock(&threadLock);
	while(e != NULL)
	{
		if ((strcmp(e->key, key) == 0 && strcmp(e->clientIP, ip) == 0) ||
			strcmp(e->clientIP, ip) == 0)
		{
			e->authorized = 1;
			if (e->featureList != NULL)
				free(e->featureList);
			e->featureList = (unsigned char*)feature;
			pthread_mutex_unlock(&threadLock);
			return 1;
		}
		e = ht_iterate_elem(&it);
	}

	pthread_mutex_unlock(&threadLock);
	return 0;
}

/* Upate status of the client in the hashtable */
int ht_update_status(hashtable_t* hasht, char* key, char* ip, int type, int status)
{
	hash_elem_t* e = NULL;
	hash_elem_it it = HT_ITERATOR(hasht);

	e = ht_iterate_elem(&it);

        pthread_mutex_lock(&threadLock);
        while(e != NULL)
        {
		if ((strcmp(e->key, key) == 0 && strcmp(e->clientIP, ip) == 0) ||
			strcmp(e->clientIP, ip) == 0)
		{
			switch (type)
			{
				case FW_STATUS:
					e->fwStatus = status;
					break;
#ifdef RTCONFIG_BHCOST_OPT
				case SO_STATUS:
					e->soStatus = status;
					break;
#endif
				case JOIN_STATUS:
					e->joinStatus = status;
					break;
				default:
					DBG_ERR("unknown status type");
			}
			pthread_mutex_unlock(&threadLock);
			return 1;
		}
		e = ht_iterate_elem(&it);
        }

        pthread_mutex_unlock(&threadLock);
        return 0;
}

/* Retrieve data from the hashtable */
hash_elem_t* ht_get(hashtable_t* hasht, char* key, char *ip)
{
	hash_elem_t* e = NULL;
	hash_elem_it it = HT_ITERATOR(hasht);

	e = ht_iterate_elem(&it);

	pthread_mutex_lock(&threadLock);
	while(e != NULL)
	{
		if ((strcmp(e->key, key) == 0 && strcmp(e->clientIP, ip) == 0) ||
			strcmp(e->clientIP, ip) == 0)
		{
			pthread_mutex_unlock(&threadLock);
			return e;//return e->sessionKey;
		}
		e = ht_iterate_elem(&it);
	}

	pthread_mutex_unlock(&threadLock);

	return NULL;
}

/* 	Remove data from the hashtable. Return the data removed from the table
	so that we can free memory if needed */
void* ht_remove(hashtable_t* hasht, char* key, char* ip)
{
	int h = 0;
	hash_elem_t* e = NULL;
	hash_elem_t* prev = NULL;
	int found = 0;

	h = hasht->capacity;
	pthread_mutex_lock(&threadLock);
	/* search table index based on key and ip */
	while (--h >= 0)
	{
		e = hasht->table[h];
		while (e)
		{
			if ((strcmp(e->key, key) == 0 && (ip == NULL || !strcmp(e->clientIP, ip))) ||
				(ip && !strcmp(e->clientIP, ip)))
			{
				found  = 1;
				break;
			}
			e = e->next;
		}

		if (found == 1)
			break;
	}

	if (found == 0) {
		DBG_INFO("can't find table index");
		pthread_mutex_unlock(&threadLock);
		return NULL;
	}

	e = hasht->table[h];

	while(e != NULL)
	{
		if ((strcmp(e->key, key) == 0 && (ip == NULL || !strcmp(e->clientIP, ip))) ||
			(ip && !strcmp(e->clientIP, ip)))
		{
			if(prev != NULL)
				prev->next = e->next;
			else
				hasht->table[h] = e->next;

			//free sessionKey
			if (e->sessionKey != NULL) {
				free(e->sessionKey);
				e->sessionKey = NULL;
			}

			//free sessionKey1
			if (e->sessionKey1 != NULL) {
				free(e->sessionKey1);
				e->sessionKey1 = NULL;
			}

			//free featureList
			if (e->featureList!= NULL) {
				free(e->featureList);
				e->featureList = NULL;
			}

			free(e);
			e = NULL;
			hasht->e_num --;
			pthread_mutex_unlock(&threadLock);
			return NULL; //return ret;
		}
		prev = e;
		e = e->next;
	}
	pthread_mutex_unlock(&threadLock);
	return NULL;
}

/* List keys. k should have length equals or greater than the number of keys */
void ht_list_keys(hashtable_t* hasht, char** k, size_t len)
{
	if(len < hasht->e_num)
		return;
	int ki = 0; //Index to the current string in **k
	int i = hasht->capacity;
	while(--i >= 0)
	{
		hash_elem_t* e = hasht->table[i];
		while(e)
		{
			k[ki++] = e->key;
			e = e->next;
		}
	}
}

/* 	List values. v should have length equals or greater
	than the number of stored elements */
void ht_list_values(hashtable_t* hasht, void** v, size_t len)
{
	if(len < hasht->e_num)
		return;
	int vi = 0; //Index to the current string in **v
	int i = hasht->capacity;
	while(--i >= 0)
	{
		hash_elem_t* e = hasht->table[i];
		while(e)
		{
			v[vi++] = e->sessionKey;
			e = e->next;
		}
	}
}

/* Iterate through table's elements. */
hash_elem_t* ht_iterate(hash_elem_it* iterator)
{
	while(iterator->elem == NULL)
	{
		if(iterator->index < iterator->ht->capacity - 1)
		{
			iterator->index++;
			iterator->elem = iterator->ht->table[iterator->index];
		}
		else
			return NULL;
	}
	hash_elem_t* e = iterator->elem;
	if(e)
		iterator->elem = e->next;
	return e;
}

/* Iterate through keys. */
char* ht_iterate_keys(hash_elem_it* iterator)
{
	hash_elem_t* e = ht_iterate(iterator);
	return (e == NULL ? NULL : e->key);
}

/* Iterate through values. */
void* ht_iterate_values(hash_elem_it* iterator)
{
	hash_elem_t* e = ht_iterate(iterator);
	return (e == NULL ? NULL : e->sessionKey);
}

/* Iterate through element. */
hash_elem_t* ht_iterate_elem(hash_elem_it* iterator)
{
	hash_elem_t* e = ht_iterate(iterator);
	return (e == NULL ? NULL : e);
}

/* 	Removes all elements stored in the hashtable.
	if free_data, all stored datas are also freed.*/
void ht_clear(hashtable_t* hasht, int free_data)
{
	hash_elem_it it = HT_ITERATOR(hasht);
	char* k = ht_iterate_keys(&it);
	while(k != NULL)
	{
		//free_data ? free(ht_remove(hasht, k)) : ht_remove(hasht, k);
		ht_remove(hasht, k, NULL);
		k = ht_iterate_keys(&it);
	}
}

/* 	Destroy the hash table, and free memory.
	Data still stored are freed*/
void ht_destroy(hashtable_t* hasht)
{
	ht_clear(hasht, 1); // Delete and free all.
	free(hasht->table);
	free(hasht);
}

/*
========================================================================
Routine Description:
	Update time for sesssion and group key.

Arguments:
	None

Return Value:
	None

========================================================================
*/
static void cm_updateTime(void)
{
	long newDiff;
	struct timeval t;
	struct sysinfo i;

	gettimeofday(&t, NULL);
	sysinfo(&i);
	newDiff = t.tv_sec - i.uptime;

	if (!uptimeDiffSet) {
		uptimeDiff = newDiff;
		uptimeDiffSet = 1;
		return;
	}

	if ((newDiff - 5 > uptimeDiff) || (newDiff + 5 < uptimeDiff)) {
		/* system time has changed, update counters and timeouts */
		hashtable_t* hasht = clientHashTable;
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		DBG_INFO("System time change detected.");

		/* update start time of group key */
		if (cm_ctrlBlock.groupKeyStartTime > 0)
			cm_ctrlBlock.groupKeyStartTime += newDiff - uptimeDiff;
		if (cm_ctrlBlock.groupKey1StartTime > 0)
			cm_ctrlBlock.groupKey1StartTime += newDiff - uptimeDiff;

		/* update start time of session key for all clients */
		while(e != NULL) {
			if (e->sessionKeyStartTime > 0)
				e->sessionKeyStartTime += newDiff - uptimeDiff;
			if (e->sessionKey1StartTime > 0)
				e->sessionKey1StartTime += newDiff - uptimeDiff;
			e = ht_iterate_elem(&it);
		}
	}
	uptimeDiff = newDiff;
} /* End of cm_updateTime */

/*
========================================================================
Routine Description:
	Add DUT's related info to shared memory for client table.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_addDutInfo()
{
	char word[256] = {0};
	char *next = NULL;
	char *p = NULL;
	int unit = 0, num5g = 0;
	unsigned char rea[MAC_LEN] = {0};
	unsigned char ipa[IP_LEN] = {0};
	unsigned char apea[MAC_LEN] = {0};
	char fwVer[FWVER_LEN] = {0};
	int reportPapInfo = 0;
#ifdef RADAR_DET
	char msg[2048] = {0};
	char ch_data[MAX_CH_DATA_BUFLEN] = {0};
	json_object *root = NULL, *chanspecObj = NULL;
#endif
	json_object *wiredClientList = NULL, *capabilityObj = NULL;
	char capabilityFilePath[64] = {0};
#ifdef REPORT_PAP_INFO
	reportPapInfo = is_router_mode() ? 0 : 1;
#endif
#ifdef RTCONFIG_NBR_RPT
	char nbrData[MAX_NBR_DATA_BUFLEN] = {0}, nbrDataMsg[MAX_NBR_DATA_BUFLEN] = {0};
	json_object *nbrRoot = NULL;
#endif
	int nband = 0;
	char prefix[sizeof("wlXXXXX_")], tmp[64];
	char ifname[16], wlIfnames[64];
	json_object *onlineListObj = NULL, *offlineListObj = NULL;

	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));

        if (nvram_get_int("re_mode") == 1)
                reportPapInfo = 1;

	DBG_INFO("add DUT releated information");

	/* get alias */
	if (nvram_get("cfg_alias") && strlen(nvram_safe_get("cfg_alias")))
		snprintf(p_client_tbl->alias[p_client_tbl->count],
			sizeof(p_client_tbl->alias[p_client_tbl->count]), "%s",
			nvram_safe_get("cfg_alias"));

	/* get mac addr by interface (br0) */
	p = get_unique_mac();
	if (p) {
		ether_atoe(p, rea);
		memcpy(p_client_tbl->macAddr[p_client_tbl->count], rea, MAC_LEN);
		memcpy(p_client_tbl->realMacAddr[p_client_tbl->count], rea, MAC_LEN);
	}

	/* get ip addr of lan */
	ip_atoe(nvram_safe_get("lan_ipaddr"), ipa);
	memcpy(p_client_tbl->ipAddr[p_client_tbl->count], ipa, IP_LEN);

	/* get bssid for backhaul */
	unit = 0;
	num5g = 0;
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		strlcpy(ifname, word, sizeof(ifname));
		p = get_hwaddr(ifname);
		if (p) {
			memset(apea, 0, sizeof(apea));
			ether_atoe(p, apea);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));

			if (nband == 2)
				memcpy(p_client_tbl->ap2g[p_client_tbl->count], apea, MAC_LEN);
			else if (nband == 1)
			{
				num5g++;
				if (num5g == 1)
					memcpy(p_client_tbl->ap5g[p_client_tbl->count], apea, MAC_LEN);
				else if (num5g == 2)
					memcpy(p_client_tbl->ap5g1[p_client_tbl->count], apea, MAC_LEN);
			}
			else if (nband == 4)
				memcpy(p_client_tbl->ap6g[p_client_tbl->count], apea, MAC_LEN);
			free(p);
			p = NULL;
		}
		unit++;
	}
	p_client_tbl->bandnum[p_client_tbl->count] = unit;

	/* get bssid for fronthaul */
	unit = 0;
	num5g = 0;
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		strlcpy(ifname, get_fh_ap_ifname_by_unit(unit), sizeof(ifname));
		p = get_hwaddr(ifname);
		if (p) {
			memset(apea, 0, sizeof(apea));
			ether_atoe(p, apea);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));

			if (nband == 2)
				memcpy(p_client_tbl->ap2g_fh[p_client_tbl->count], apea, MAC_LEN);
			else if (nband == 1)
			{
				num5g++;
				if (num5g == 1)
					memcpy(p_client_tbl->ap5g_fh[p_client_tbl->count], apea, MAC_LEN);
				else if (num5g == 2)
					memcpy(p_client_tbl->ap5g1_fh[p_client_tbl->count], apea, MAC_LEN);
			}
			else if (nband == 4)
				memcpy(p_client_tbl->ap6g_fh[p_client_tbl->count], apea, MAC_LEN);
			free(p);
			p = NULL;
		}
		unit++;
	}

	/* get bssid of dwb */
#ifdef RTCONFIG_DWB
	if (cm_dwbIsEnabled()) {
		p = get_dwb_bssid(supportedBandNum, nvram_get_int("dwb_band"), nvram_get_int("max_guest_index"));
		if (p) {
			memset(apea, 0, sizeof(apea));
			ether_atoe(p, apea);
			memcpy(p_client_tbl->apDwb[p_client_tbl->count], apea, MAC_LEN);
		}
	}
#endif

	/* get bssid and rssi of 2g & 5g for pap */
	if (nvram_get_int("sw_mode") == SW_MODE_REPEATER || reportPapInfo) {
		char tmpStr[18] = {0};
		unsigned char pap2g[MAC_LEN] = {0};
		unsigned char pap5g[MAC_LEN] = {0};
		unsigned char sta2g[MAC_LEN] = {0};
		unsigned char sta5g[MAC_LEN] = {0};
		int rssi2gInt = 0;
		int rssi5gInt = 0;

		rssi2gInt = get_pap_rssi(0);
		rssi5gInt = get_pap_rssi(1);

		/* update pap and rssi for 2g */
		if (rssi2gInt != 0) {
			ether_atoe(get_pap_bssid(0, &tmpStr[0], sizeof(tmpStr)), pap2g);
			p_client_tbl->rssi2g[p_client_tbl->count] = rssi2gInt;
			memcpy(p_client_tbl->pap2g[p_client_tbl->count], pap2g, MAC_LEN);
		}

		/* update pap and rssi for 5g */
		if (rssi5gInt != 0) {
			ether_atoe(get_pap_bssid(1, &tmpStr[0], sizeof(tmpStr)), pap5g);
			p_client_tbl->rssi5g[p_client_tbl->count] = rssi5gInt;
			memcpy(p_client_tbl->pap5g[p_client_tbl->count], pap5g, MAC_LEN);
		}

		/* update sta for 2g */
		if (strlen(get_sta_mac(0))) {
			ether_atoe(get_sta_mac(0), sta2g);
			memcpy(p_client_tbl->sta2g[p_client_tbl->count], sta2g, MAC_LEN);
		}

		/* update sta for 5g */
		if (strlen(get_sta_mac(1))) {
			ether_atoe(get_sta_mac(1), sta5g);
			memcpy(p_client_tbl->sta5g[p_client_tbl->count], sta5g, MAC_LEN);
		}
	}

	/* get firmware version */
	snprintf(fwVer, sizeof(fwVer), "%s.%s_%s", nvram_safe_get("firmver"),
				nvram_safe_get("buildno"), nvram_safe_get("extendno"));
	if (strlen(fwVer))
		snprintf(p_client_tbl->fwVer[p_client_tbl->count],
			sizeof(p_client_tbl->fwVer[p_client_tbl->count]), "%s", fwVer);

	/* get model name */
	snprintf(p_client_tbl->modelName[p_client_tbl->count],
			sizeof(p_client_tbl->modelName[p_client_tbl->count]), "%s", get_productid());

	/* get product id */
	snprintf(p_client_tbl->productId[p_client_tbl->count],
			sizeof(p_client_tbl->productId[p_client_tbl->count]), "%s", nvram_safe_get("productid"));

	/* update level */
	p_client_tbl->level[p_client_tbl->count] = 0;
	p_client_tbl->maxLevel = p_client_tbl->level[p_client_tbl->count];
	nvram_set_int("cfg_maxlevel", p_client_tbl->maxLevel);

	/* get territory_code */
	snprintf(p_client_tbl->territoryCode[p_client_tbl->count],
		sizeof(p_client_tbl->territoryCode[p_client_tbl->count]), "%s", nvram_safe_get("territory_code"));

	p_client_tbl->count = 1;

#ifdef RADAR_DET
#if defined(RTCONFIG_WIFI_SON)
	if (!nvram_match("wifison_ready","1"))
#endif
	{
	/* update chanspec */
	root = json_object_new_object();
	if (root && chmgmt_get_chan_info(ch_data, sizeof(ch_data)) > 0 )
	{
		DBG_INFO("channel information updated");

		/* unique mac */
		json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));
		/* channel */
		json_object_object_add(root, CFG_STR_CHANNEL, json_object_new_string(ch_data));
		/* supported chanspec */
		chanspecObj = json_object_new_object();
		if (chanspecObj) {
			if (cm_getChanspec(chanspecObj, 0)) {
				json_object_object_add(root, CFG_STR_CHANSPEC, chanspecObj);
				json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			}
			else
				json_object_put(chanspecObj);
		}

		snprintf((char *)msg, sizeof(msg), "%s", json_object_to_json_string_ext(root, 0));
		DBG_INFO("msg(%s)", msg);

		cm_updateAvailableChannel(msg);
		cm_updateChanspec(msg);
		json_object_put(root);
	}
	} /* !wifison_ready */
#endif	/* RADAR_DET */

	/* update wired client list */
	if ((wiredClientList = json_object_new_array()) != NULL) {
		if (cm_needUpdateWiredClientlLst(wiredClientList)) {
			if ((onlineListObj = json_object_new_array()) && (offlineListObj = json_object_new_array())) {
				cm_processWiredClientList((char *)json_object_to_json_string(wiredClientList), (char *)get_unique_mac(), onlineListObj, offlineListObj);
#ifdef RTCONFIG_NOTIFICATION_CENTER
				cm_notifyWiredClientEvent(onlineListObj, offlineListObj);
#endif
			}

			if (onlineListObj)
				json_object_put(onlineListObj);
			if (offlineListObj)
				json_object_put(offlineListObj);
		}

		json_object_put(wiredClientList);
	}

	/* generate capability */
	capabilityObj = cm_generateCapability(CAP_SUPPORT, &capability_list[0]);
	if (capabilityObj) {
		snprintf(capabilityFilePath, sizeof(capabilityFilePath), "%s/%s.cap",
			TEMP_ROOT_PATH, (char *)get_unique_mac());
		json_object_to_file(capabilityFilePath, capabilityObj);
		json_object_put(capabilityObj);
	}

#ifdef RTCONFIG_NBR_RPT
	/* update neighbor */
	if (cm_getNbrData(nbrData, sizeof(nbrData)) > 0) {
		DBG_INFO("update neighbor information");
		snprintf(nbrDataMsg, sizeof(nbrDataMsg), "{\"%s\":\"%s\",\"%s\":%s}",
			CFG_STR_MAC, (char *)get_unique_mac(), CFG_STR_NBR_DATA, nbrData);
		cm_updateNbrData(nbrDataMsg);

		/* update private nbr list */
		nbrRoot = json_object_new_object();
		if (nbrRoot) {
			snprintf(nbrDataMsg, sizeof(nbrDataMsg), "{\"%s\":\"%s\",\"%s\":\"%s\"}",
				CFG_STR_MAC, (char *)get_unique_mac(), CFG_STR_NBR_VERSION, nvram_safe_get("cfg_nbr_ver"));

			if (cm_prepareNbrList((unsigned char *)nbrDataMsg, nbrRoot))
				cm_updateNbrList((unsigned char *)json_object_get_string(nbrRoot));
			json_object_put(nbrRoot);
		}
		else
			DBG_ERR("root is NULL");
	}
#endif	/* RTCONFIG_NBR_RPT */
} /* End of cm_addDutInfo */

/*
========================================================================
Routine Description:
	Update DUT's related info to shared memory for client table.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_updateDutInfo()
{
	int unit = 0, nband = 0, lock = 0, num5g = 0;
	char prefix[sizeof("wlXXXXX_")], ifname[16], *p = NULL, tmp[32];
	char word[32], wlIfnames[64], *next = NULL;
	unsigned char apea[MAC_LEN] = {0};

	pthread_mutex_lock(&cfgLock);
	lock = file_lock(CFG_FILE_LOCK);

	/* update bssid for fronthaul */
	strlcpy(wlIfnames, nvram_safe_get("wl_ifnames"), sizeof(wlIfnames));
	foreach (word, wlIfnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		strlcpy(ifname, get_fh_ap_ifname_by_unit(unit), sizeof(ifname));
		p = get_hwaddr(ifname);
		if (p) {
			memset(apea, 0, sizeof(apea));
			ether_atoe(p, apea);
			nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
			if (nband == 2)
				memcpy(p_client_tbl->ap2g_fh[0], apea, MAC_LEN);
			else if (nband == 1)
			{
				num5g++;
				if (num5g == 1)
					memcpy(p_client_tbl->ap5g_fh[0], apea, MAC_LEN);
				else if (num5g == 2)
					memcpy(p_client_tbl->ap5g1_fh[0], apea, MAC_LEN);
			}
			else if (nband == 4)
				memcpy(p_client_tbl->ap6g_fh[0], apea, MAC_LEN);
			free(p);
			p = NULL;
		}
		unit++;
	}
	file_unlock(lock);
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_updateDutInfo */

/*
========================================================================
Routine Description:
	Update dut chanspecs

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_updateDutChanspecs()
{
	json_object *root = NULL, *chanspecObj = NULL;
	char msg[MAX_CHANSPEC_BUFLEN] = {0};

	root = json_object_new_object();
	if (root) {
		DBG_INFO("update chanspec itself");

		/* unique mac */
		json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));

		/* supported chanspec */
		chanspecObj = json_object_new_object();
		if (chanspecObj) {
			if (cm_getChanspec(chanspecObj, 1)) {
				json_object_object_add(root, CFG_STR_CHANSPEC, chanspecObj);
				json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			}
			else
			{
				json_object_put(chanspecObj);
				json_object_put(root);
				return;
			}
		}
		else
		{
			json_object_put(root);
			return;
		}

		snprintf((char *)msg, sizeof(msg), "%s", json_object_get_string(root));
		DBG_INFO("msg(%s)", msg);

		cm_updateChanspec(msg);

		json_object_put(root);
	}
} /* End of cm_updateDutChanspecs */

#ifdef RTCONFIG_DWB
/*
========================================================================
Routine Description:
	Update dwb info.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_updateDwbInfo()
{
	char *p = NULL;
	unsigned char apea[MAC_LEN] = {0};

	if (cm_dwbIsEnabled()) {
		p = get_dwb_bssid(supportedBandNum, nvram_get_int("dwb_band"), nvram_get_int("max_guest_index"));
		if (p) {
			memset(apea, 0, sizeof(apea));
			ether_atoe(p, apea);
			if (memcmp(p_client_tbl->apDwb[0], apea, MAC_LEN) != 0) {
				memcpy(p_client_tbl->apDwb[0], apea, MAC_LEN);
				dwbUpdate = 1;
			}
		}
	}
} /* End of cm_updateDwbInfo */

/*
========================================================================
Routine Description:
	Check dwb whether need to be enabled.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	None

========================================================================
*/
static void cm_checkDwbSwitch(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *reMacObj = NULL, *bandNumObj = NULL;

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &reMacObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_BANDNUM, &bandNumObj);

	if (reMacObj && bandNumObj) {
		cm_updateTribandReList((char *)json_object_get_string(reMacObj), atoi(json_object_get_string(bandNumObj)), NULL, RELIST_ADD, 1);
		cm_AutoDetect_Dedicated_Wifi_Backhaul(1, 1);
    	if (dwb_reSync) {
    		cm_usr2Handle(-1);  // Notify re to resync and don't do cm_AutoDetect_Dedicated_Wifi_Backhaul(1) again.
        	dwb_reSync = 0;
    	}
	}

	json_object_put(decryptedRoot);
} /* End of cm_checkDwbSwitch */
#endif	/* RTCONFIG_DWB */

/*
========================================================================
Routine Description:
	Init shared memory for client table.

Arguments:
	None

Return Value:
	0	- fail
	1	- success

========================================================================
*/
int cm_initClientTbl()
{
	shm_client_tbl_id = shmget((key_t)KEY_SHM_CFG, sizeof(CM_CLIENT_TABLE), 0666|IPC_CREAT);
        if(shm_client_tbl_id == -1) {
		DBG_ERR("client table shmget failed");
		return 0;
    	}

	p_client_tbl = (P_CM_CLIENT_TABLE)shmat(shm_client_tbl_id,(void *) 0,0);
	memset(p_client_tbl, 0x0, sizeof(CM_CLIENT_TABLE));
	p_client_tbl->count = 0;
	cm_addDutInfo();

	return 1;
} /* End of cm_initClientTbl */

/*
========================================================================
Routine Description:
	Update the level of client.

Arguments:
	None

Return Value:
	0		- don't need to update cost
	1		- need to update cost

========================================================================
*/
int cm_updateClientLevel()
{
	int i = 0;
	int j = 0;
	int k = 0;
	char uMac[18] = {0};
	char dMac[18] = {0};
	json_object *allBrMacListObj = NULL;
	json_object *macEntryObj = NULL;
	int ret = 0;
#ifdef RTCONFIG_AMAS
	int wirelessPath = WL_2G | WL_5G | WL_5G_1 | WL_6G;
	int wiredPath = ETH;
#ifdef RTCONFIG_BHCOST_OPT
	int wirelessPathNew = WL2G_U | WL5G1_U | WL5G2_U | WL6G_U;
	int wiredPathNew = ETH | ETH_2 | ETH_3 | ETH_4;
#endif /* RTCONFIG_BHCOST_OPT */
#endif
	int minLevel = 0;
	int needUpdated = 0;
	json_object *entry = NULL;
	int macEntryLen = 0;
#ifdef RTCONFIG_DWB
	int dwbEnabled =cm_dwbIsEnabled();
#endif

	if (p_client_tbl->count == 1)
		return ret;

	allBrMacListObj = json_object_from_file(MAC_LIST_JSON_FILE);

	DBG_INFO("update the level of relationship for client");

	for (i = 0; i < p_client_tbl->count; i++) {
		for (j = 1; j < p_client_tbl->count; j++) {

			if (i == j)
				continue;

			/* for wireless */
			if (p_client_tbl->activePath[j] == 0
#ifdef RTCONFIG_AMAS
				|| ((
#ifdef RTCONFIG_BHCOST_OPT
				(p_client_tbl->activePath[j] & wirelessPathNew)||
#endif /* RTCONFIG_BHCOST_OPT */
					(p_client_tbl->activePath[j] & wirelessPath))
#if defined(RTCONFIG_WIFI_SON)
				&& !nvram_match("wifison_ready","1")
#endif
				)
#endif
			) {
				needUpdated = 0;
				minLevel = 100;
				/* for 2G */
				if (
#ifdef RTCONFIG_AMAS
					(
#if defined(RTCONFIG_WIFI_SON)
					 nvram_match("wifison_ready","1") ||
#endif
					(
#ifdef RTCONFIG_BHCOST_OPT
					(p_client_tbl->activePath[j] & WL2G_U) ||
#endif /* RTCONFIG_BHCOST_OPT */
					(p_client_tbl->activePath[j] & WL_2G))) &&
#endif
					(memcmp(p_client_tbl->pap2g[j], nullMAC, sizeof(nullMAC)) &&
					memcmp(p_client_tbl->ap2g[i], p_client_tbl->pap2g[j], sizeof(p_client_tbl->ap2g[i])) == 0)) {
					if ((p_client_tbl->level[i] + 1) < minLevel) {
						minLevel = p_client_tbl->level[i] + 1;
						needUpdated = 1;
					}
				}

				/* for 5G, 5G1 and dwb */
				if (
#ifdef RTCONFIG_AMAS
					(
#if defined(RTCONFIG_WIFI_SON)
					  nvram_match("wifison_ready","1") ||
#endif
					 ((
#ifdef RTCONFIG_BHCOST_OPT
					(p_client_tbl->activePath[j] & (WL5G1_U | WL5G2_U)) ||
#endif /* RTCONFIG_BHCOST_OPT */
					(p_client_tbl->activePath[j] & (WL_5G | WL_5G_1))))) &&
#endif
					((memcmp(p_client_tbl->pap5g[j], nullMAC, sizeof(nullMAC)) &&
					memcmp(p_client_tbl->ap5g[i], p_client_tbl->pap5g[j], sizeof(p_client_tbl->ap5g[i])) == 0) ||
					(memcmp(p_client_tbl->pap5g[j], nullMAC, sizeof(nullMAC)) &&
					memcmp(p_client_tbl->ap5g1[i], p_client_tbl->pap5g[j], sizeof(p_client_tbl->ap5g1[i])) == 0)
#ifdef RTCONFIG_DWB
					|| (dwbEnabled && memcmp(p_client_tbl->pap5g[j], nullMAC, sizeof(nullMAC)) &&
					memcmp(p_client_tbl->apDwb[i], p_client_tbl->pap5g[j], sizeof(p_client_tbl->apDwb[i])) == 0)
#endif
					)) {
					if ((p_client_tbl->level[i] + 1) < minLevel) {
						minLevel = p_client_tbl->level[i] + 1;
						needUpdated = 1;
					}
				}

				/* for 6G */
				if (
#ifdef RTCONFIG_AMAS
					(
#if defined(RTCONFIG_WIFI_SON)
					 nvram_match("wifison_ready","1") ||
#endif
#ifdef RTCONFIG_BHCOST_OPT
					(p_client_tbl->activePath[j] & WL6G_U) ||
#endif /* RTCONFIG_BHCOST_OPT */
					(p_client_tbl->activePath[j] & WL_6G)) &&
#endif
					((memcmp(p_client_tbl->pap6g[j], nullMAC, sizeof(nullMAC)) &&
					memcmp(p_client_tbl->ap6g[i], p_client_tbl->pap6g[j], sizeof(p_client_tbl->ap6g[i])) == 0)
#ifdef RTCONFIG_DWB
					|| (dwbEnabled && memcmp(p_client_tbl->pap6g[j], nullMAC, sizeof(nullMAC)) &&
					memcmp(p_client_tbl->apDwb[i], p_client_tbl->pap6g[j], sizeof(p_client_tbl->apDwb[i])) == 0)
#endif
					)) {
					if ((p_client_tbl->level[i] + 1) < minLevel) {
						minLevel = p_client_tbl->level[i] + 1;
						needUpdated = 1;
					}
				}

				if (needUpdated && (minLevel != p_client_tbl->level[j])) {
					ret = 1;
					p_client_tbl->level[j] = minLevel;
					if (p_client_tbl->level[j] > p_client_tbl->maxLevel)
						p_client_tbl->maxLevel = p_client_tbl->level[j];
				}
			}

			/* for wired */
			if (allBrMacListObj && (p_client_tbl->activePath[j] == 0
#ifdef RTCONFIG_AMAS
				|| ((
#ifdef RTCONFIG_BHCOST_OPT
					(p_client_tbl->activePath[j] & wiredPathNew)||
#endif /* RTCONFIG_BHCOST_OPT */
					(p_client_tbl->activePath[j] & wiredPath))
#if defined(RTCONFIG_WIFI_SON)
			       	&& !nvram_match("wifison_ready","1")
#endif
				)
#endif
			)) {
				memset(uMac, 0, sizeof(uMac));
				snprintf(uMac, sizeof(uMac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

				memset(dMac, 0, sizeof(dMac));
				snprintf(dMac, sizeof(dMac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
					p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
					p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

				json_object_object_get_ex(allBrMacListObj, uMac, &macEntryObj);

				if (macEntryObj) {
					macEntryLen = json_object_array_length(macEntryObj);

					for (k = 0; k < macEntryLen; k++) {
						entry = json_object_array_get_idx(macEntryObj, k);

						if (!strcmp(dMac, json_object_get_string(entry))) {
							if (p_client_tbl->level[i] != p_client_tbl->level[j]) {
								ret = 1;
								p_client_tbl->level[j] = p_client_tbl->level[i];
							}
							break;
						}
					}
				}
			}
		}
	}

	if (allBrMacListObj)
		json_object_put(allBrMacListObj);

	/* update max level and master's cose if need */
	if (ret) {
		DBG_INFO("max level(%d) for slave list", p_client_tbl->maxLevel);
		nvram_set_int("cfg_maxlevel", p_client_tbl->maxLevel);

		/* update master's cost */
		if (nvram_get_int("cfg_cost") != p_client_tbl->level[0]) {
			update_lldp_cost(p_client_tbl->level[0]);
#ifdef ONBOARDING
#ifdef RTCONFIG_WIFI_SON
			if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
			cm_updateOnboardingVsie(nvram_get_int("cfg_obstatus"));
#endif
		}
	}

	return ret;
} /* End of cm_updateClientLevel */

/*
========================================================================
Routine Description:
	Send notification to slave to update network cost.

Arguments:
	slaveMac			- slave's mac

Return Value:
	None

========================================================================
*/
void cm_updateNetworkCost(char *slaveMac)
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (slaveMac && strcmp(mac, slaveMac))
			continue;

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification to slave to request cost*/
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s), key time(%d)",
					e->clientIP, e->key,  (int) (uptime() - e->sessionKeyStartTime));
				if (cm_checkSessionKeyExpire(e))
					cm_sendNotification(e, NOTIFY_REKEY, NULL);	// ask the client to rekey
				else
					cm_sendNotification(e, NOTIFY_REQUESTCOST, NULL);
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_updateNetworkCost */

/*
========================================================================
Routine Description:
	Send notification to slave to update network level.

Arguments:
	slaveMac			- slave's mac

Return Value:
	None

========================================================================
*/
void cm_updateNetworkLevel(char *slaveMac)
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (slaveMac && strcmp(mac, slaveMac))
			continue;

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification to slave to request cost*/
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s), key time(%d)",
					e->clientIP, e->key,  (int) (uptime() - e->sessionKeyStartTime));
				if (cm_checkSessionKeyExpire(e))
					cm_sendNotification(e, NOTIFY_REKEY, NULL);	// ask the client to rekey
				else
					cm_sendNotification(e, NOTIFY_REQUESTLEVEL, NULL);
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_updateNetworkLevel */

/*
========================================================================
Routine Description:
	Update bridge mac list for wired.

Arguments:
	*brMac		- json object for bridge mac list
	*mac		- client's mac

Return Value:
	None

========================================================================
*/
void cm_updateBridgeMacList(json_object *wiredMacListObj, char *mac)
{
	json_object *matchedMacListObj = NULL;
	json_object *brMacArrayObj = NULL;
	json_object *brMacEntry = NULL;
	json_object *entry = NULL;
	json_object *authMacEntry = NULL;
	json_object *matchedMacEntry = NULL;
	json_object *allWiredMacListObj = NULL;
	int wiredMacListLen = 0;
	int matchedMacListLen = 0;
	int i = 0;
	int j = 0;
	int neededUpdate = 0;
	int authorized = 0;
	char rmac[32] = {0};
	json_object *authMacArraryObj = NULL;
	int authMacLen = 0;

	allWiredMacListObj = json_object_from_file(MAC_LIST_JSON_FILE);
	if (!allWiredMacListObj) {
		allWiredMacListObj = json_object_new_object();
		if (!allWiredMacListObj) {
			DBG_ERR("allWiredMacListObj is NULL");
			return;
		}
	}

	json_object_object_get_ex(allWiredMacListObj, mac, &matchedMacListObj);

	if (wiredMacListObj)
		wiredMacListLen = json_object_array_length(wiredMacListObj);

	DBG_INFO("wiredMacListLen(%d) mac(%s)", wiredMacListLen, mac);

	/* filter un-authorized mac in wiredMacListObj */
	for (i = 0; i < wiredMacListLen; i++) {
		brMacEntry = json_object_array_get_idx(wiredMacListObj, i);

		if (!brMacEntry)
			continue;

		authorized = 0;
		for (j = 0; j < p_client_tbl->count; j++) {
			if (j == 0 || (int) difftime(time(NULL), p_client_tbl->reportStartTime[j]) < OFFLINE_THRESHOLD) {
				memset(rmac, 0, sizeof(rmac));
				snprintf(rmac, sizeof(rmac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
					p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
					p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

				if (!strcmp(json_object_get_string(brMacEntry), rmac)) {
					authorized = 1;
					break;
				}
			}
		}

		if (authorized) {
			if (!authMacArraryObj)
				authMacArraryObj = json_object_new_array();

			if (authMacArraryObj) {
				entry = json_object_new_string(json_object_get_string(brMacEntry));
				json_object_array_add(authMacArraryObj, entry);
			}
		}
	}
	if (authMacArraryObj)
		authMacLen = json_object_array_length(authMacArraryObj);

	/* check need to update or not */
	if (matchedMacListObj)
		matchedMacListLen = json_object_array_length(matchedMacListObj);

	if (matchedMacListLen != authMacLen)
		neededUpdate = 1;

	if (!neededUpdate) {	/* check all mac between matchedMacListObj and authMacArraryObj */
		for (i = 0 ; i < authMacLen; i++) {
			authMacEntry = json_object_array_get_idx(authMacArraryObj, i);

			if (!authMacEntry)
				continue;

			for (j = 0 ; j < matchedMacListLen; j++) {
				matchedMacEntry = json_object_array_get_idx(matchedMacListObj, j);

				if (!matchedMacEntry)
					continue;

				if (strcmp(json_object_get_string(authMacEntry), json_object_get_string(matchedMacEntry))) {
					neededUpdate = 1;
					break;
				}
			}

			if (neededUpdate)	/* need to update, don't continue */
				break;
		}
	}

	if (neededUpdate) {
		/* delete object in allWiredMacListObj first */
		if (matchedMacListObj)
			json_object_object_del(allWiredMacListObj, mac);

		/* re-create array for authorized mac */
		for (i = 0; i < authMacLen; i++) {
			brMacEntry = json_object_array_get_idx(authMacArraryObj, i);

			if (!brMacEntry)
				continue;

			if (!brMacArrayObj)
				brMacArrayObj = json_object_new_array();

			if (brMacArrayObj) {
				entry = json_object_new_string(json_object_get_string(brMacEntry));
				json_object_array_add(brMacArrayObj, entry);
			}
		}
		if (brMacArrayObj)
			json_object_object_add(allWiredMacListObj, mac, brMacArrayObj);
	}

	if (neededUpdate) {	/* rewrite data to file */
		if (allWiredMacListObj)
			json_object_to_file(MAC_LIST_JSON_FILE, allWiredMacListObj);
	}

	/* destory memory */
	json_object_put(authMacArraryObj);
	json_object_put(allWiredMacListObj);
} /* End of cm_updateBridgeMacList */

/*
========================================================================
Routine Description:
	Record 5G low/high band releated infomation.

Arguments:
	bandNumRE			- band number for RE
	channelObj			- json object for RE's current channel

Return Value:
	None

========================================================================
*/
void cm_record5gBand(int bandNumRE, json_object *channelObj)
{
	int bandNumCap = 0;
	int channelCap = 0;
	int bwCap = 0;
	int nctrlsbCap = 0;
	json_object *curChannelObj = NULL;
	json_object *curBwObj = NULL;
	json_object *curNctrlsbObj = NULL;
	char prefix[16] = {0};
	char tmp[64] = {0};
	int selectedBand = NO_SELECTION;

	bandNumCap = supportedBandNum;

	/* have selected 5g for tri-band */
	if ((selected5gBand != NO_SELECTION) &&
		(bandNumCap == 2 && bandNumRE == 3)) {	/* CAP is dual band, RE is tri-band */
		wl_control_channel(1, &channelCap,  &bwCap, &nctrlsbCap);
		if (channelCap != 0) {
			if (channelCap >= THRESHOLD_5G_LOW_HIGH)
				selectedBand = LOW_BAND_5G;
			else
				selectedBand = HIGH_BAND_5G;

			if (selected5gBand != selectedBand) {
				DBG_INFO("selected5gBand (%s), selectedBand (%s)",
					(selected5gBand == LOW_BAND_5G) ? "low": "high",
					(selectedBand == LOW_BAND_5G) ? "low": "high");
				selected5gBand = NO_SELECTION;
				DBG_INFO("CAP 5G channel is changed, re-select 5G for tri-band.");
			}
		}
	}

	/* no select 5g for tri-band */
	if (selected5gBand == NO_SELECTION) {
		if (bandNumCap == bandNumRE)	/* supported band is equal */
			return;
		else if (bandNumCap == 2 && bandNumRE == 3) {	/* CAP is dual band, RE is tri-band  */
			/* get 5G's releated info on Cap */
			wl_control_channel(1, &channelCap,  &bwCap, &nctrlsbCap);
			if (channelCap != 0) {
				if (channelCap >= THRESHOLD_5G_LOW_HIGH)
					selectedBand = LOW_BAND_5G;
				else
					selectedBand = HIGH_BAND_5G;
				snprintf(prefix, sizeof(prefix), "wl%d_", selectedBand);

				json_object_object_get_ex(channelObj, strcat_r(prefix, "channel", tmp), &curChannelObj);
				json_object_object_get_ex(channelObj, strcat_r(prefix, "bw", tmp), &curBwObj);
				json_object_object_get_ex(channelObj, strcat_r(prefix, "nctrlsb", tmp), &curNctrlsbObj);

				/* decide 5g's channel, bw and nctrlsb */
				if (curChannelObj && curBwObj && curNctrlsbObj) {
					selected5gBand = selectedBand;
					channel5g =  json_object_get_int(curChannelObj);
#ifdef RTCONFIG_BCN_RPT
					nvram_set_int("multi_channel_5g", channel5g);
#endif
					bw5g = json_object_get_int(curBwObj);
					nctrlsb5g = json_object_get_int(curNctrlsbObj);
#ifdef RTCONFIG_NBR_RPT
					nvram_set_int("r_selected5gband",selected5gBand);
					nvram_set_int("r_selected5gchannel",channel5g);
					nvram_set_int("r_selected5gbw",bw5g);
					nvram_set_int("r_selected5gnctrlsb",nctrlsb5g);
#endif
					DBG_INFO("selected5gBand(%s), channel5g(%d), bw5g(%d), nctrlsb5g(%d)",
						selected5gBand == LOW_BAND_5G ? "low": "high", channel5g, bw5g, nctrlsb5g);
				}
			}
		}
	}
} /* End of cm_record5gBand */

/*
========================================================================
Routine Description:
	Add new band.

Arguments:
	bandIndex		- band index
	bnadType		-band type

Return Value:
	None

========================================================================
*/
void cm_addNewBand(int bandIndex, char *bandType, json_object *channelObj)
{
	char channelKey[32], bwKey[32], ctrlsbKey[32];
	json_object *channelKeyObj = NULL, *bwKeyObj = NULL, *ctrlsbKeyObj = NULL, *channelChkObj = NULL;

	snprintf(channelKey, sizeof(channelKey), "wl%d_channel", bandIndex);
	snprintf(bwKey, sizeof(bwKey), "wl%d_bw", bandIndex);
	snprintf(ctrlsbKey, sizeof(ctrlsbKey), "wl%d_nctrlsb", bandIndex);

	json_object_object_get_ex(channelObj, channelKey, &channelKeyObj);
	json_object_object_get_ex(channelObj, bwKey, &bwKeyObj);
	json_object_object_get_ex(channelObj, ctrlsbKey, &ctrlsbKeyObj);

	/* check new band or not */
	if (channelKeyObj && bwKeyObj && ctrlsbKeyObj) {
		/* re-gen sring key for channel, bw, ctrlsb by band type */
		snprintf(channelKey, sizeof(channelKey), "%s_channel", bandType);
		snprintf(bwKey, sizeof(bwKey), "%s_bw", bandType);
		snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", bandType);

		json_object_object_get_ex(newBandObj, channelKey, &channelChkObj);
		/* check channel info of new band is in newBandObj or not */
		if (!channelChkObj) {
			DBG_INFO("no channel info [%s (%d), %s (%d), %s (%d)] of new band in newBandObj, add it",
				channelKey, json_object_get_int(channelKeyObj),
				bwKey, json_object_get_int(bwKeyObj),
				ctrlsbKey, json_object_get_int(ctrlsbKeyObj));
			json_object_object_add(newBandObj, channelKey, json_object_new_int(json_object_get_int(channelKeyObj)));
			json_object_object_add(newBandObj, bwKey, json_object_new_int(json_object_get_int(bwKeyObj)));
			json_object_object_add(newBandObj, ctrlsbKey, json_object_new_int(json_object_get_int(ctrlsbKeyObj)));
		}
	}
} /* End of cm_addNewBand */

/*
========================================================================
Routine Description:
	Update new band based on re mac.

Arguments:
	mac		- re mac
	bandIndex		- band index
	bnadType		-band type

Return Value:
	None

========================================================================
*/
void cm_updateNewBand(char *mac, int bandIndex, char *bandType)
{
	char channelKey[32], bwKey[32], ctrlsbKey[32], band[8];
	int channelCap = 0, bwCap = 0, nctrlsbCap = 0;
	json_object *channelObj = NULL, *bwObj = NULL, *ctrlsbObj = NULL;

	/* get channel, bw, nctrlsb */
	wl_control_channel(bandIndex, &channelCap,  &bwCap, &nctrlsbCap);
	if (channelCap != 0) {
		strlcpy(band, cm_getBandTypeByChannel(mac, channelCap), sizeof(band));

		DBG_INFO("mac (%s), channelCap (%d), band (%s)", mac, channelCap, band);
		if (strlen(band) > 0) {
			snprintf(channelKey, sizeof(channelKey), "%s_channel", band);
			snprintf(bwKey, sizeof(bwKey), "%s_bw", band);
			snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", band);

			json_object_object_get_ex(newBandObj, channelKey, &channelObj);
			json_object_object_get_ex(newBandObj, bwKey, &bwObj);
			json_object_object_get_ex(newBandObj, ctrlsbKey, &ctrlsbObj);
			if (!channelObj || !bwObj || !ctrlsbObj
				|| (json_object_get_int(channelObj) != channelCap ||
				json_object_get_int(bwObj) != bwCap ||
				json_object_get_int(ctrlsbObj) != nctrlsbCap)
			) {
				/* delete exited item from newBandObj */
				json_object_object_del(newBandObj, channelKey);
				json_object_object_del(newBandObj, bwKey);
				json_object_object_del(newBandObj, ctrlsbKey);

				/* update new one to newBandObj */
				json_object_object_add(newBandObj, channelKey, json_object_new_int(channelCap));
				json_object_object_add(newBandObj, bwKey, json_object_new_int(bwCap));
				json_object_object_add(newBandObj, ctrlsbKey, json_object_new_int(nctrlsbCap));
			}
		}
	}
} /* End of cm_updateNewBand */

/*
========================================================================
Routine Description:
	Delete new band based on band.

Arguments:
	bandIndexObj		- band index
	band		-band string

Return Value:
	0		- don't delete new band
	1		- delete new band

========================================================================
*/
int cm_deleteNewBand(json_object *bandIndexObj, char *band)
{
	char channelKey[32], bwKey[32], ctrlsbKey[32], bandType[8];
	json_object *channelKeyObj = NULL, *bwKeyObj = NULL, *ctrlsbKeyObj = NULL;
	int ret = 0;

	if (!band || strlen(band) == 0) {
		DBG_ERR("band is NULL");
		return 0;
	}
	strlcpy(bandType, band, sizeof(bandType));

	json_object_object_foreach(bandIndexObj, bandIndexKey, bandIndexVal) {
		if (strncmp(bandType, bandIndexKey, strlen(bandType)) == 0) {
			snprintf(channelKey, sizeof(channelKey), "%s_channel", bandIndexKey);
			snprintf(bwKey, sizeof(bwKey), "%s_bw", bandIndexKey);
			snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", bandIndexKey);

			json_object_object_get_ex(newBandObj, channelKey, &channelKeyObj);
			json_object_object_get_ex(newBandObj, bwKey, &bwKeyObj);
			json_object_object_get_ex(newBandObj, ctrlsbKey, &ctrlsbKeyObj);

			if (channelKeyObj && bwKeyObj && ctrlsbKeyObj) {
				json_object_object_del(newBandObj, channelKey);
				json_object_object_del(newBandObj, bwKey);
				json_object_object_del(newBandObj, ctrlsbKey);
				ret = 1;
			}
		}
	}

	return ret;
} /* End of cm_deleteNewBand */

/*
========================================================================
Routine Description:
	Check band is new band or not in newBandObj.

Arguments:
	bnadType		-band type

Return Value:
	0		- nont in new band list
	1		- in new band list

========================================================================
*/
int cm_isNewBand(char *bandType)
{
	json_object *channelObj = NULL;
	char channel[32];
	int ret = 0;

	snprintf(channel, sizeof(channel), "%s_channel", bandType);
	json_object_object_get_ex(newBandObj, channel, &channelObj);

	if (channelObj) ret = 1;

	return ret;
} /* End of cm_isNewBand */

/*
========================================================================
Routine Description:
	Update exist new band.

Arguments:
	mac		- re mac
	band		- re multi band
	existNewBandObj		-exist new band

Return Value:
	None

========================================================================
*/
void cm_updateExistNewBand(char *mac, char *band, json_object *existNewBandObj)
{
	char channelKey[32], bwKey[32], ctrlsbKey[32], newBandType[8], bandType[8], newBandIndex[8];
	int channel = 0, bw = 0, nctrlsb = 0;
	json_object *channelObj = NULL, *bwObj = NULL, *ctrlsbObj = NULL;
	json_object *tempExistNewBandObj = NULL;

	if (!band || strlen(band) == 0) {
		DBG_ERR("band is NULL");
		return;
	}
	strlcpy(newBandType, band, sizeof(newBandType));
	tempExistNewBandObj = existNewBandObj;

	json_object_object_foreach(existNewBandObj, newBandKey, newBandVal) {
		if (strncmp(newBandType, newBandKey, strlen(newBandType)) == 0 && strstr(newBandKey, "channel")) {
			if (sscanf(newBandKey, "%[^_]", newBandIndex) == 1) {
				snprintf(channelKey, sizeof(channelKey), "%s_channel", newBandIndex);
				snprintf(bwKey, sizeof(bwKey), "%s_bw", newBandIndex);
				snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", newBandIndex);
				json_object_object_get_ex(tempExistNewBandObj, channelKey, &channelObj);
				json_object_object_get_ex(tempExistNewBandObj, bwKey, &bwObj);
				json_object_object_get_ex(tempExistNewBandObj, ctrlsbKey, &ctrlsbObj);

				if (channelObj && bwObj && ctrlsbObj) {
					channel =  json_object_get_int(channelObj);
					bw =  json_object_get_int(bwObj);
					nctrlsb =  json_object_get_int(ctrlsbObj);
					DBG_INFO("newBandKey (%s), mac (%s), channel (%d), bw (%d), nctrlsb (%d)", newBandKey, mac, channel, bw, nctrlsb);
					strlcpy(bandType, cm_getBandTypeByChannel(mac, channel), sizeof(bandType));

					DBG_INFO("newBandIndex (%s), bandType (%s)", newBandIndex, bandType);
					if (strlen(bandType) > 0) {
						snprintf(channelKey, sizeof(channelKey), "%s_channel", bandType);
						snprintf(bwKey, sizeof(bwKey), "%s_bw", bandType);
						snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", bandType);

						json_object_object_get_ex(newBandObj, channelKey, &channelObj);
						json_object_object_get_ex(newBandObj, bwKey, &bwObj);
						json_object_object_get_ex(newBandObj, ctrlsbKey, &ctrlsbObj);

						if (!channelObj || !bwObj || !ctrlsbObj
							|| (json_object_get_int(channelObj) != channel ||
							json_object_get_int(bwObj) != bw ||
							json_object_get_int(ctrlsbObj) != nctrlsb)
						) {
							/* delete exited item from newBandObj */
							json_object_object_del(newBandObj, channelKey);
							json_object_object_del(newBandObj, bwKey);
							json_object_object_del(newBandObj, ctrlsbKey);

							/* update new one to newBandObj */
							json_object_object_add(newBandObj, channelKey, json_object_new_int(channel));
							json_object_object_add(newBandObj, bwKey, json_object_new_int(bw));
							json_object_object_add(newBandObj, ctrlsbKey, json_object_new_int(nctrlsb));
							DBG_INFO("update %s (%d), %s (%d), %s (%d) to newBandObj", channelKey, channel, bwKey, bw, ctrlsbKey, nctrlsb);
						}
					}
				}
			}
		}
	}
} /* End of cm_updateExistNewBand */

/*
========================================================================
Routine Description:
	Record new band releated infomation.

Arguments:
	mac		- mac for re
	channelObj			- json object for RE's current channel

Return Value:
	None

========================================================================
*/
void cm_recordNewBand(char *mac, json_object *channelObj)
{
	json_object *capBandIndexObj = NULL, *reBandIndexObj = NULL, *capMultiBandListObj = NULL, *reMultiBandListObj = NULL;
	json_object *channelTmpObj = NULL, *bandObj = NULL, *channelKeyObj = NULL, *existNewBandObj = NULL, *reMultiBandObj = NULL;
	int isNewBand = 0, capBandIndex = 0, reBandIndex = 0, addNewBand = 0, delNewBand = 0, updateExistNewBand = 0;
	char reBandType[8], tmp[16], reMultiBand[16], channelKey[32];

	if (!channelObj) {
		DBG_ERR("channelObj is NULL");
		return;
	}

	channelTmpObj = channelObj;

	capBandIndexObj = json_object_new_object();
	if (!capBandIndexObj) {
		DBG_INFO("capBandIndexObj is NULL");
		goto err;
	}

	reBandIndexObj = json_object_new_object();
	if (!reBandIndexObj) {
		DBG_INFO("reBandIndexObj is NULL");
		goto err;
	}

	capMultiBandListObj = json_object_new_object();
	if (!capMultiBandListObj) {
		DBG_INFO("capMultiBandListObj is NULL");
		goto err;
	}

	reMultiBandListObj = json_object_new_object();
	if (!reMultiBandListObj) {
		DBG_INFO("reMultiBandListObj is NULL");
		goto err;
	}

	/* band index mapping for cap */
	if (!cm_getBandTypeMappingByMac(get_unique_mac(), 1, capBandIndexObj)) {
		DBG_INFO("can't get band type mapping for cap (%s)", get_unique_mac());
		goto err;
	}

	/* multiple band list for cap */
	if (!cm_getMultipleBandListByMac(get_unique_mac(), 1, capBandIndexObj, capMultiBandListObj)) {
		DBG_INFO("can't get multi band list for re (%s)", get_unique_mac());
		goto err;
	}

	/* band index mapping for re */
	if (!cm_getBandTypeMappingByMac(mac, 0, reBandIndexObj)) {
		DBG_INFO("can't get band type mapping for re (%s)", mac);
		goto err;
	}

	/* multiple band list for re */
	if (!cm_getMultipleBandListByMac(mac, 0, reBandIndexObj, reMultiBandListObj)) {
		DBG_INFO("can't get multi band list for re (%s)", mac);
		goto err;
	}

	if (!newBandObj)
		newBandObj = json_object_new_object();

	if (!multiBandObj)
		multiBandObj = json_object_new_object();

	if (newBandObj && multiBandObj) {
		/* for new band */
		json_object_object_foreach(reBandIndexObj, reBandIndexKey, reBandIndexVal) {
			strlcpy(reBandType, reBandIndexKey, sizeof(reBandType));
			isNewBand = 1;
			reBandIndex = json_object_get_int(reBandIndexVal);
			/* check new band or not */
			json_object_object_foreach(capBandIndexObj, capBandIndexKey, capBandIndexVal) {
				capBandIndex = json_object_get_int(capBandIndexVal);
				if (strcmp(reBandType, capBandIndexKey) == 0) {
					isNewBand = 0;
					break;
				}
			}

			if (isNewBand) {
				/* check multi band for adding new band*/
				addNewBand = 1;
				json_object_object_foreach(multiBandObj, multiBandKey, multiBandVal) {
					strlcpy(tmp, multiBandKey, sizeof(tmp));
					if (strncmp(tmp, reBandType, strlen(tmp)) == 0) {
						addNewBand = 0;
						DBG_INFO("reBandType (%s) match %s in multiBandObj for adding new band, don't add it", reBandType, tmp);
						break;
					}
				}

				/* check in new band list or not. If yes, don't add it again */
				if (cm_isNewBand(reBandType)) {
					DBG_INFO("reBandType (%s) is in new band list, dont' add it", reBandType);
					addNewBand = 0;
				}

				if (addNewBand) {
					DBG_INFO("try to add %s (%d) for new band", reBandType, reBandIndex);
					cm_addNewBand(reBandIndex, reBandType, channelTmpObj);
				}
			}
			else
			{
				/* check multi band for deleting new band */
				delNewBand = 1;
				json_object_object_foreach(multiBandObj, multiBandKey, multiBandVal) {
					strlcpy(tmp, multiBandKey, sizeof(tmp));
					if (strncmp(tmp, reBandType, strlen(tmp)) == 0) {
						delNewBand = 0;
						DBG_INFO("reBandType (%s) match %s in multiBandObj for deleting new band, don't delete it", reBandType, tmp);
						break;
					}
				}

				if (delNewBand) {
					/* delete new band based on band */
					if (cm_deleteNewBand(reBandIndexObj, reBandType))
						DBG_INFO("delete %s (%d) from new band list", reBandType, reBandIndex);
				}
			}
		}

		/* for multi band on re and cap */
		json_object_object_foreach(reMultiBandListObj, reMultiBandKey, reMultiBandVal) {
			strlcpy(reMultiBand, reMultiBandKey, sizeof(reMultiBand));
			json_object_object_get_ex(capMultiBandListObj, reMultiBand, &reMultiBandObj);
			if (!reMultiBandObj) {
				/* check in new band but doesn't exist in multiBandObj, need to record and delete it, and than update */
				json_object_object_get_ex(multiBandObj, reMultiBand, &bandObj);
				existNewBandObj = json_object_new_object();
				updateExistNewBand = 0;
				if (!bandObj) {
					/* record channel info of new band based on newBandObj */
					json_object_object_foreach(newBandObj, newBandKey, newBandVal) {
						if (strncmp(reMultiBand, newBandKey, strlen(reMultiBand)) == 0) {
							if (existNewBandObj) {
								DBG_INFO("add newBandKey (%s) val (%d) to existNewBandObj", newBandKey, json_object_get_int(newBandVal));
								json_object_object_add(existNewBandObj, newBandKey, json_object_new_int(json_object_get_int(newBandVal)));
								updateExistNewBand = 1;
							}
						}
					}

					/* after record channel info and then delete in newBandObj */
					json_object_object_foreach(existNewBandObj, existNewBandKey, existNewBandVal) {
						DBG_INFO("delete existNewBandKey (%s) in newBandObj", existNewBandKey);
						json_object_object_del(newBandObj, existNewBandKey);
					}
				}

				/* check multi band and add it first based on reBandIndexObj */
				json_object_object_foreach(reBandIndexObj, reBandIndexKey, reBandIndexVal) {
					if (strncmp(reMultiBand, reBandIndexKey, strlen(reMultiBand)) == 0) {
						reBandIndex = json_object_get_int(reBandIndexVal);
						DBG_INFO("try to add %s (%d) for new multi band", reBandIndexKey, reBandIndex);
						cm_addNewBand(reBandIndex, reBandIndexKey, channelTmpObj);

						/* add to multiBandObj if new band is added */
						json_object_object_get_ex(multiBandObj, reMultiBand, &bandObj);
						if (!bandObj) {
							DBG_INFO("add reMultiBand (%s) to multiBandObj", reMultiBand);
							json_object_object_add(multiBandObj, reMultiBand, json_object_new_int(json_object_get_int(reMultiBandVal)));
						}
					}
				}

				/* update exist new band recorded before */
				DBG_INFO("updateExistNewBand (%d)", updateExistNewBand);
				if (existNewBandObj && updateExistNewBand) {
					cm_updateExistNewBand(mac, reMultiBand, existNewBandObj);
				}

				/* check multi band and update it based on capBandIndexObj if needed */
				json_object_object_foreach(capBandIndexObj, capBandIndexKey, capBandIndexVal) {
					if (strncmp(reMultiBand, capBandIndexKey, strlen(reMultiBand)) == 0) {
						capBandIndex = json_object_get_int(capBandIndexVal);
						DBG_INFO("update %s (%d) for multi band", capBandIndexKey, capBandIndex);
						cm_updateNewBand(mac, capBandIndex, capBandIndexKey);
					}
				}

				json_object_put(existNewBandObj);
			}
			else
			{
				/* delete new band based on multi band */
				if (cm_deleteNewBand(capBandIndexObj, reMultiBand))
					DBG_INFO("delete %s from new band list", reMultiBand);

				/* delete from multiBandObj if new band is deleted */
				json_object_object_get_ex(multiBandObj, reMultiBand, &bandObj);
				if (bandObj)
					json_object_object_del(multiBandObj, reMultiBand);
			}
		}
	}

err:

	json_object_put(capBandIndexObj);
	json_object_put(reBandIndexObj);
	json_object_put(capMultiBandListObj);
	json_object_put(reMultiBandListObj);
} /* End of cm_recordNewBand */

/*
========================================================================
Routine Description:
	check re territory code from list

Arguments:
	None

Return Value:
	None

========================================================================
*/
static void cm_checkTerritoryCode(
	void)
{
#define SZ_NVRAM_UI_REGION_DISABLE		"cfg_ui_region_disable"

#if defined(RTCONFIG_TCODE) && defined(RTCONFIG_CFGSYNC_LOCSYNC) // Because supported location code sync mechanism. So display county selection option.
	nvram_set_int(SZ_NVRAM_UI_REGION_DISABLE, 0);
    return;
#endif

	int i, disable = 0;

	pthread_mutex_lock(&cfgLock);
	for (i=0; i<p_client_tbl->count; i++)
	{
		disable = (strlen(p_client_tbl->territoryCode[i]) > 0 &&
			strncmp(nvram_safe_get("territory_code"), p_client_tbl->territoryCode[i], 2) != 0 &&
			cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) ? 1 : 0;
		if (disable == 1) break;
	}
	pthread_mutex_unlock(&cfgLock);
	nvram_set_int(SZ_NVRAM_UI_REGION_DISABLE, disable);
	return;
}

/*
========================================================================
Routine Description:
	Update RE's private config if it needed.

Arguments:
	mac			- RE unique mac
	configObj			- json object for RE's changed config

Return Value:
	None
========================================================================
*/
void cm_updatePrivateConfig(char *mac, json_object *configObj)
{
	json_object *fileRoot = NULL, *paramObj = NULL;
	char reCfgPath[64], paraStr[64], valStr[256];
	int update = 0;

	snprintf(reCfgPath, sizeof(reCfgPath), "/tmp/%s.json", mac);
	fileRoot = json_object_from_file(reCfgPath);
	if (fileRoot) {
		json_object_object_foreach(configObj, key, val) {
			snprintf(paraStr, sizeof(paraStr), "%s", key);
			snprintf(valStr, sizeof(valStr), "%s", json_object_get_string(val));
			DBG_INFO("param(%s) value(%s)", paraStr, valStr);

			json_object_object_foreach(fileRoot, key, val) {
				json_object_object_get_ex(val, paraStr, &paramObj);
				/* delete matched parameter first and then add new value */
				if (paramObj && strcmp(json_object_get_string(paramObj), valStr) != 0) {
					json_object_object_del(val, paraStr);
					json_object_object_add(val, paraStr, json_object_new_string(valStr));
					DBG_INFO("update %s=%s", paraStr, valStr);
					update = 1;
				}
			}
		}

		if (update)
			json_object_to_file(reCfgPath, fileRoot);
	}

	json_object_put(fileRoot);
} /* End of cm_updatePrivateConfig */

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
/*
========================================================================
Routine Description:
	sync common config to RE's private config if it needed.

Arguments:
	mac		- RE's mac
	inCfgObj		- config array

Return Value:
	-1		- error
	0		- no update
	1		- update
========================================================================
*/
int cm_syncCommonToPrivateConfigByMac(char *mac, json_object *inCfgObj)
{
	hash_elem_t* e = NULL;
	char cmac[18], rmac[18], ip[18];
	int i = 0, j = 0, ftLen = 0, update = 0;
	json_object *ftListObj = NULL, *ftEntry = NULL, *ftObj = NULL, *cfgObj = NULL;
	struct subfeature_mapping_s *pSubFeature = NULL;
	struct param_mapping_s *pParam = NULL;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		memset(cmac, 0, sizeof(cmac));
		memset(rmac, 0, sizeof(rmac));
		memset(ip, 0, sizeof(ip));
		snprintf(cmac, sizeof(cmac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

		snprintf(rmac, sizeof(rmac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (strcmp(mac, rmac) == 0) {
			if ((e = ht_get(clientHashTable, cmac, ip)) && e->featureList) {
				ftListObj = json_tokener_parse((char *)e->featureList);
				if (inCfgObj) {
					if (ftListObj)
						update = cm_updateCommonToPrivateConfig(mac, e->featureList, inCfgObj);
				}
				else
				{
					cfgObj = json_object_new_object();
					if (ftListObj && cfgObj) {
						json_object_object_get_ex(ftListObj, CFG_STR_FEATURE, &ftObj);
						if (ftObj) {
							ftLen = json_object_array_length(ftObj);
							for (pSubFeature = &subfeature_mapping_list[0]; pSubFeature->index != 0; pSubFeature++) {
								for (j = 0; j < ftLen; j++) {
									if ((ftEntry = json_object_array_get_idx(ftObj, j)) &&
										strcmp(pSubFeature->name, json_object_get_string(ftEntry)) == 0) {
										for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
											if (pSubFeature->index == pParam->subfeature) {
												json_object_object_add(cfgObj,
													pParam->param, json_object_new_string(""));
											}
										}
									}
								}
							}

							update = cm_updateCommonToPrivateConfig(mac, e->featureList, cfgObj);
						}
					}
				}

				if (cfgObj) json_object_put(cfgObj);
				if (ftListObj) json_object_put(ftListObj);
			}

			break;
		}
	}
	pthread_mutex_unlock(&cfgLock);

	return update;
} /* End of cm_syncCommonToPrivateConfigByMac */
#endif	/* RTCONFIG_AMAS_CENTRAL_CONTROL */

#ifdef RTCONFIG_FRONTHAUL_DWB
/**
 * @brief Update p_client_tbl->BackhualStatus
 *
 * @return int Updated(1) or not(0).
 */
static int cm_updateBackhaulStatus()
{
	int update = 0;
	int i, j;
	char macaddr[32] = {}, ap6g_buf[18] = {};
	int fh_ap_enabled = nvram_get_int("fh_ap_enabled");

	pthread_mutex_lock(&cfgLock);
	for (i = 0; i < p_client_tbl->count; i++) {
		if (fh_ap_enabled == 1) { // Auto
			if (p_client_tbl->bandnum[i] >= 3 && cm_isSlaveOnline(p_client_tbl->reportStartTime[i]) && (p_client_tbl->activePath[i] & (WL_2G | WL_5G | WL_5G_1 | WL_6G)) > 0) {
				if ((p_client_tbl->BackhualStatus[i] & 0x1) == 0x0 || (nvram_get_int("fh_ap_bss") == 1 && i == 0)) { // non-use -> use
					if (i == 0) { // CAP
						p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1);
						nvram_set_int("fh_ap_bss", 0); // Disable CAP fronthaul AP.
					} else { //RE
						p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1) | (0x1 << 3);
						update = 1; // for notify RE
					}
					ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
					DBG_INFO("Change to RE(%s) BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
				}
				continue;
			} else if (p_client_tbl->bandnum[i] >= 3) {
				int cont_flag = 0;
				for (j = 0; j < p_client_tbl->count; j++) {
					if (cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						if ((memcmp(p_client_tbl->pap5g[j], nullMAC, sizeof(nullMAC)) && memcmp(p_client_tbl->ap5g1[i], p_client_tbl->pap5g[j], MAC_LEN) == 0)
							|| (memcmp(p_client_tbl->pap6g[j], nullMAC, sizeof(nullMAC)) && memcmp(p_client_tbl->ap6g[i], p_client_tbl->pap6g[j], MAC_LEN) == 0)) { // 5GH or 6G
							if (p_client_tbl->activePath[j] == WL_5G_1 || p_client_tbl->activePath[j] == WL_6G || (p_client_tbl->activePath[j] == WL_5G && p_client_tbl->bandnum[j] == 2)) {
								if ((p_client_tbl->BackhualStatus[i] & 0x1) == 0x0 || (nvram_get_int("fh_ap_bss") == 1 && i == 0)) { // non-use -> use
									if (i == 0) { // CAP
										p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1);
										nvram_set_int("fh_ap_bss", 0); // Disable CAP fronthaul AP.
									} else { // RE
										p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1) | (0x1 << 3);
										update = 1; // for notify RE
									}
									ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
									DBG_INFO("Change to RE(%s) BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
								}
								cont_flag = 1;
								break;
							}
						}
						if (memcmp(p_client_tbl->ap5g[i], p_client_tbl->pap5g[j], MAC_LEN) == 0) { // 5GL
							if (p_client_tbl->activePath[j] == 4) {
								if ((p_client_tbl->BackhualStatus[i] & 0x1) == 0x0 || (nvram_get_int("fh_ap_bss") == 1 && i == 0)) { // non-use -> use
									if (i == 0) { // CAP
										p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1);
										nvram_set_int("fh_ap_bss", 0); // Disable CAP fronthaul AP.
									} else { // RE
										p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1) | (0x1 << 3);
										update = 1; // for notify RE
									}
									ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
									DBG_INFO("Change to RE(%s) BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
								}
								cont_flag = 1;
								break;
							}
						}
						if (memcmp(p_client_tbl->ap2g[i], p_client_tbl->pap2g[j], MAC_LEN) == 0) { // 2.4G
							if (p_client_tbl->activePath[j] == 2) {
								if ((p_client_tbl->BackhualStatus[i] & 0x1) == 0x0 || (nvram_get_int("fh_ap_bss") == 1 && i == 0)) { // non-use -> use
									if (i == 0) { // CAP
										p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1);
										nvram_set_int("fh_ap_bss", 0); // Disable CAP fronthaul AP.
									} else { // RE
										p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] | 0x1) | (0x1 << 3);
										update = 1; // for notify RE
									}
									ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
									DBG_INFO("Change to RE(%s) BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
								}
								cont_flag = 1;
								break;
							}
						}
					}
				}
				if (cont_flag)
					continue;
			}
			if ((p_client_tbl->BackhualStatus[i] & 0x1) == 0x1 || (nvram_get_int("fh_ap_bss") == 0 && i == 0)) { // use -> non-use
				if (i == 0) { // CAP
					p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] & 0x0);
					nvram_set_int("fh_ap_bss", 1); // Enable CAP fronthaul AP.
				} else { // RE
					p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] & 0x0) | (0x1 << 3);
					update = 1; // for notify RE
				}
				ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
				DBG_INFO("Change to RE(%s) BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
			}
		} else if (fh_ap_enabled == 2) {  //  always on
			if ((p_client_tbl->BackhualStatus[i] & 0x1) == 0x1 || (nvram_get_int("fh_ap_bss") == 0 && i == 0)) { // use -> non-use
				if (i == 0) { // CAP
					p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] & 0x0);
					nvram_set_int("fh_ap_bss", 1); // Enable CAP fronthaul AP.
				} else { // RE
					p_client_tbl->BackhualStatus[i] = (p_client_tbl->BackhualStatus[i] & 0x0) | (0x1 << 3);
					update = 1; // for notify RE
				}
				ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
				DBG_INFO("Change to RE(%s) BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
			}
		}
	}
	pthread_mutex_unlock(&cfgLock);
	return update;
}

/**
 * @brief Notify RE to update BackhaulStatus
 *
 */
void cm_NotifyUpdateBackhaulStatus()
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		if ((p_client_tbl->BackhualStatus[i] & (0x1 << 3)) == 0x0) // Don't need update.
			continue;

		/* send notification to slave to request backhual status */
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s), key time(%d)",
					e->clientIP, e->key,  (int) (uptime() - e->sessionKeyStartTime));
				if (cm_checkSessionKeyExpire(e))
					cm_sendNotification(e, NOTIFY_REKEY, NULL);	// ask the client to rekey
				else
					cm_sendNotification(e, NOTIFY_REQUESTBACKHUALSTATUS, NULL);
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);
}

/**
 * @brief Check whether re-notify RE to update BackhaulStatus
 *
 * @return int Need(1) or not(0)
 */
static int chk_renotify_backhualstatus()
{
	int i, re_notify = 0;
	char macaddr[32] = {};
	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		/* Check need re-notify RE */
		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) // Only check online RE.
			continue;
		if ((p_client_tbl->BackhualStatus[i] >> 3) & 0x1) { // need re-notify.
			ether_etoa(p_client_tbl->realMacAddr[i], macaddr);
			DBG_INFO("RE(%s) Need re-send NOTIFY_REQUESTBACKHUALSTATUS. BackhualStatus: %d\n", macaddr, p_client_tbl->BackhualStatus[i]);
			re_notify = 1;
			break;
		}
	}
	pthread_mutex_unlock(&cfgLock);
	return re_notify;
}

/**
 * @brief Reset p_client_tbl->BackhualStatus value
 *
 * @param clientMac RE MAC
 */
static void reset_BackhualStatus(char *clientMac) {
	unsigned char rea[MAC_LEN] = {0};
	int i;
	int found = 0;
	int lock = 0;

	ether_atoe(clientMac, rea);
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], rea, MAC_LEN) == 0) {
			found = 1;
			break;
		}
	}

	if (found) {
		pthread_mutex_lock(&cfgLock);
		lock = file_lock(CFG_FILE_LOCK);

		/* Reset backhual status */
		p_client_tbl->BackhualStatus[i] = 8;

		DBG_INFO("Client(%02X:%02X:%02X:%02X:%02X:%02X) Reset BackhualStatus to 8\n",
			rea[0], rea[1], rea[2], rea[3], rea[4], rea[5]);

		file_unlock(lock);
		pthread_mutex_unlock(&cfgLock);
	}
}
#endif

/*
========================================================================
Routine Description:
	update client info to shared memory.

Arguments:
	*decryptedMsg		- decrypted message
	*clientMac		- client's mac
	*clientIP		- client's IP
	*bandNum	- band number for RE
	isFirstJoined		- RE joined at first time
	onlineListObj	- online wired client list
	offlineListObj	- offline wired client list

Return Value:
	0		- don't trigger self opt
	1		- trigger self opt

========================================================================
*/
static int cm_updateClientTbl(unsigned char *decryptedMsg, char *clientMac, char *clientIP, int *bandNum, int isFirstJoined,
	json_object *onlineListObj, json_object *offlineListObj)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *macObj = NULL;
	json_object *aliasObj = NULL;
	json_object *pap2gObj = NULL, *pap5gObj = NULL, *pap6gObj = NULL;
	json_object *rssi2gObj = NULL, *rssi5gObj = NULL, *rssi6gObj = NULL;
	json_object *ap2gObj = NULL, *ap5gObj = NULL, *ap5g1Obj = NULL, *ap6gObj = NULL;
#ifdef RTCONFIG_DWB
	json_object *apdwbObj = NULL;
#endif
	json_object *sta2gObj = NULL, *sta5gObj = NULL, *sta6gObj = NULL;
	json_object *wiredMacObj = NULL;
	json_object *dutRootObj = NULL;
	json_object *dutWiredMacObj = NULL;
	json_object *fwVerObj = NULL;
	json_object *swModeObj = NULL;
	json_object *modelNameObj = NULL, *productIdObj = NULL;
	json_object *activePathObj = NULL;
#ifdef RTCONFIG_BHCOST_OPT
	json_object *activePathV2Obj = NULL;
	json_object *activePathV3Obj = NULL;
#endif
#ifdef RADAR_DET
	json_object *channelObj = NULL;
	char channelMsg[512] = {0};
#endif	/* RADAR_DET */
#ifdef RTCONFIG_BCN_RPT
	json_object *APListObj = NULL;
#endif
	json_object *bandNumObj = NULL;
	json_object *curChannelObj = NULL, *selChannelObj = NULL;
	json_object *reListObj = NULL;
	json_object *territoryCodeObj = NULL;
	json_object *chanspecObj = NULL;
	json_object *sta2gTrafficObj = NULL, *sta5gTrafficObj = NULL, *wiredPortObj = NULL, *configObj = NULL, *sta6gTrafficObj = NULL;
	json_object *plcStatusObj = NULL;
	char chanspecMsg[MAX_CHANSPEC_BUFLEN] = {0}, filePath[64] = {0};
#ifdef RTCONFIG_NBR_RPT
	json_object *nbrDataObj = NULL;
	char nbrDataMsg[MAX_NBR_DATA_BUFLEN] = {0};
#endif

	char portNo[32] = {0};
	int i = 0;
	char alias[ALIAS_LEN] = {0};
	unsigned char ea[MAC_LEN] = {0};
	unsigned char rea[MAC_LEN] = {0};
	unsigned char ipa[IP_LEN] = {0};
	unsigned char pap2g[MAC_LEN] = {0}, pap5g[MAC_LEN] = {0}, pap6g[MAC_LEN] = {0};
	unsigned char ap2g[MAC_LEN] = {0}, ap5g[MAC_LEN] = {0}, ap5g1[MAC_LEN] = {0}, ap6g[MAC_LEN] = {0};
#ifdef RTCONFIG_DWB
	unsigned char apdwb[MAC_LEN] = {0};
#endif
	unsigned char sta2g[MAC_LEN] = {0}, sta5g[MAC_LEN] = {0}, sta6g[MAC_LEN] = {0};
	char fwVer[FWVER_LEN] = {0};
	char modelName[MODEL_NAME_LEN] = {0}, productId[MODEL_NAME_LEN] = {0};
	char territoryCode[TERRITORY_CODE_LEN] = {0};
	int rssi2g = 0, rssi5g = 0, rssi6g = 0;
	int found = 0;
	int isPapSetting = 0;
	int updated = 0;
	int swMode = 0;
	int networkCostUpdate = 0;
	int activePath = 0;
	int activePathUpdate =0;
#ifdef RTCONFIG_FRONTHAUL_DWB
	int backhaulStatusUpdate = 0;
#endif
	int lock = 0;
	char realMac[18] = {0};
	char sta2gMac[18] = {0}, sta5gMac[18] = {0}, sta6gMac[18] = {0};
	char sta2gMacTraffic[18] = {0}, sta5gMacTraffic[18] = {0}, sta6gMacTraffic[18] = {0};
	char sta2gMacList[128] = {0}, sta5gMacList[128] = {0}, sta6gMacList[128] = {0};
	json_object *ap2gSsidObj = NULL, *ap5gSsidObj = NULL, *ap5g1SsidObj = NULL, *ap6gSsidObj = NULL;
	json_object *pap2gSsidObj = NULL, *pap5gSsidObj = NULL, *pap6gSsidObj = NULL;
	char ap2gSsid[SSID_LEN] = {0},  ap5gSsid[SSID_LEN] = {0}, ap5g1Ssid[SSID_LEN] = {0}, ap6gSsid[SSID_LEN] = {0};
	char pap2gSsid[SSID_LEN] = {0},  pap5gSsid[SSID_LEN] = {0},  pap6gSsid[SSID_LEN] = {0};
    json_object *lldpwlcstatObj = NULL, *lldpethstatObj = NULL;
	int triggerSelfOpt = 0;
	char lldpwlcstat[LLDP_STAT_LEN] = {0}, lldpethstat[LLDP_STAT_LEN] = {0};
	json_object *ap2gFhObj = NULL, *ap5gFhObj = NULL, *ap5g1FhObj = NULL, *ap6gFhObj = NULL;
	json_object *ap2gSsidFhObj = NULL, *ap5gSsidFhObj = NULL, *ap5g1SsidFhObj = NULL, *ap6gSsidFhObj = NULL;
	unsigned char ap2gFh[MAC_LEN] = {0}, ap5gFh[MAC_LEN] = {0}, ap5g1Fh[MAC_LEN] = {0}, ap6gFh[MAC_LEN] = {0};
	char ap2gSsidFh[SSID_LEN] = {0}, ap5gSsidFh[SSID_LEN] = {0}, ap5g1SsidFh[SSID_LEN] = {0}, ap6gSsidFh[SSID_LEN] = {0};

	if (decryptedRoot == NULL) {
		DBG_LOG("decryptedRoot is NULL");
		if (decryptedMsg && strlen((char *)decryptedMsg))
			DBG_LOG("the length of decryptedMsg > 0");
		return 0;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &macObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_ALIAS, &aliasObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PAP2G, &pap2gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PAP5G, &pap5gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PAP6G, &pap6gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_RSSI2G, &rssi2gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_RSSI5G, &rssi5gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_RSSI6G, &rssi6gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP2G, &ap2gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G, &ap5gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G1, &ap5g1Obj);
#ifdef RTCONFIG_DWB
	json_object_object_get_ex(decryptedRoot, CFG_STR_APDWB, &apdwbObj);
#endif
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP6G, &ap6gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA2G, &sta2gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA5G, &sta5gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA6G, &sta6gObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_WIRED_MAC, &wiredMacObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_FWVER, &fwVerObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_SWMODE, &swModeObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_MODEL_NAME, &modelNameObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PRODUCT_ID, &productIdObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_TERRITORY_CODE, &territoryCodeObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PATH, &activePathObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_BANDNUM, &bandNumObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_CURRENT_CHANNEL, &curChannelObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA2G_TRAFFIC, &sta2gTrafficObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA5G_TRAFFIC, &sta5gTrafficObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_STA6G_TRAFFIC, &sta6gTrafficObj);
#ifdef RTCONFIG_BHCOST_OPT
	json_object_object_get_ex(decryptedRoot, CFG_STR_PATH_V2, &activePathV2Obj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PATH_V3, &activePathV3Obj);
#endif
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP2G_SSID, &ap2gSsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G_SSID, &ap5gSsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G1_SSID, &ap5g1SsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP6G_SSID, &ap6gSsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PAP2G_SSID, &pap2gSsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PAP5G_SSID, &pap5gSsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_PAP6G_SSID, &pap6gSsidObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_WLC_LLDP_COST_STAT, &lldpwlcstatObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_ETH_LLDP_COST_STAT, &lldpethstatObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_CHANGED_CONFIG, &configObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_SELECTED_CHANNEL, &selChannelObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP2G_FH, &ap2gFhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G_FH, &ap5gFhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G1_FH, &ap5g1FhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP6G_FH, &ap6gFhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP2G_SSID_FH, &ap2gSsidFhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G_SSID_FH, &ap5gSsidFhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP5G1_SSID_FH, &ap5g1SsidFhObj);
	json_object_object_get_ex(decryptedRoot, CFG_STR_AP6G_SSID_FH, &ap6gSsidFhObj);

	/* convert json object to the corresponding params */
	if (macObj) {
		snprintf(realMac, sizeof(realMac), "%s", json_object_get_string(macObj));
		ether_atoe(realMac, rea);
	}
	else
	{
		json_object_put(decryptedRoot);
		DBG_LOG("macObj is NULL");
		return 0;
	}

	/* check re unique mac */
	if (!cm_checkReListExist(realMac)) {
		json_object_put(decryptedRoot);
		DBG_ERR("re unique mac is invalid!");
		return 0;
	}

	if (aliasObj) snprintf(alias, sizeof(alias), "%s", json_object_get_string(aliasObj));
	if (pap2gObj) ether_atoe(json_object_get_string(pap2gObj), pap2g);
	if (pap5gObj) ether_atoe(json_object_get_string(pap5gObj), pap5g);
	if (pap6gObj) ether_atoe(json_object_get_string(pap6gObj), pap6g);
	if (rssi2gObj) rssi2g = atoi(json_object_get_string(rssi2gObj));
	if (rssi5gObj) rssi5g = atoi(json_object_get_string(rssi5gObj));
	if (rssi6gObj) rssi6g = atoi(json_object_get_string(rssi6gObj));
	if (fwVerObj) snprintf(fwVer, sizeof(fwVer), "%s", json_object_get_string(fwVerObj));
	if (swModeObj) swMode = atoi(json_object_get_string(swModeObj));
	if (modelNameObj) snprintf(modelName, sizeof(modelName), "%s", json_object_get_string(modelNameObj));
	if (productIdObj) snprintf(productId, sizeof(productId), "%s", json_object_get_string(productIdObj));
	if (territoryCodeObj) snprintf(territoryCode, sizeof(territoryCode), "%s", json_object_get_string(territoryCodeObj));
	if (bandNumObj) *bandNum = json_object_get_int(bandNumObj);
	if (sta2gObj) {
		snprintf(sta2gMac, sizeof(sta2gMac), "%s", json_object_get_string(sta2gObj));
		ether_atoe(sta2gMac, sta2g);
		strlcat(sta2gMacList, sta2gMac, sizeof(sta2gMacList));
	}
	if (sta5gObj) {
		snprintf(sta5gMac, sizeof(sta5gMac), "%s", json_object_get_string(sta5gObj));
		ether_atoe(sta5gMac, sta5g);
		strlcat(sta5gMacList, sta5gMac, sizeof(sta5gMacList));
	}
	if (sta6gObj) {
		snprintf(sta6gMac, sizeof(sta6gMac), "%s", json_object_get_string(sta6gObj));
		ether_atoe(sta6gMac, sta6g);
		strlcat(sta6gMacList, sta6gMac, sizeof(sta6gMacList));
	}
	if (sta2gTrafficObj) {
		if (strlen(sta2gMacList))
			strlcat(sta2gMacList, ",", sizeof(sta2gMacList));
		snprintf(sta2gMacTraffic, sizeof(sta2gMacTraffic), "%s", json_object_get_string(sta2gTrafficObj));
		strlcat(sta2gMacList, sta2gMacTraffic, sizeof(sta2gMacList));
	}
	if (sta5gTrafficObj) {
		if (strlen(sta5gMacList))
			strlcat(sta5gMacList, ",", sizeof(sta5gMacList));
		snprintf(sta5gMacTraffic, sizeof(sta5gMacTraffic), "%s", json_object_get_string(sta5gTrafficObj));
		strlcat(sta5gMacList, sta5gMacTraffic, sizeof(sta5gMacList));
	}
	if (sta6gTrafficObj) {
		if (strlen(sta6gMacList))
			strlcat(sta6gMacList, ",", sizeof(sta6gMacList));
		snprintf(sta6gMacTraffic, sizeof(sta6gMacTraffic), "%s", json_object_get_string(sta6gTrafficObj));
		strlcat(sta6gMacList, sta6gMacTraffic, sizeof(sta6gMacList));
	}
	if (ap2gSsidObj) strlcpy(ap2gSsid, json_object_get_string(ap2gSsidObj), sizeof(ap2gSsid));
	if (ap5gSsidObj) strlcpy(ap5gSsid, json_object_get_string(ap5gSsidObj), sizeof(ap5gSsid));
	if (ap5g1SsidObj) strlcpy(ap5g1Ssid, json_object_get_string(ap5g1SsidObj), sizeof(ap5g1Ssid));
	if (ap6gSsidObj) strlcpy(ap6gSsid, json_object_get_string(ap6gSsidObj), sizeof(ap6gSsid));
	if (pap2gSsidObj) strlcpy(pap2gSsid, json_object_get_string(pap2gSsidObj), sizeof(pap2gSsid));
	if (pap5gSsidObj) strlcpy(pap5gSsid, json_object_get_string(pap5gSsidObj), sizeof(pap5gSsid));
	if (pap6gSsidObj) strlcpy(pap6gSsid, json_object_get_string(pap6gSsidObj), sizeof(pap6gSsid));
	if (ap2gObj) ether_atoe(json_object_get_string(ap2gObj), ap2g);
	if (ap5gObj) ether_atoe(json_object_get_string(ap5gObj), ap5g);
	if (ap5g1Obj) ether_atoe(json_object_get_string(ap5g1Obj), ap5g1);
#ifdef RTCONFIG_DWB
	if (apdwbObj) ether_atoe(json_object_get_string(apdwbObj), apdwb);
#endif
	if (ap6gObj) ether_atoe(json_object_get_string(ap6gObj), ap6g);
	if (lldpwlcstatObj) strlcpy(lldpwlcstat, json_object_get_string(lldpwlcstatObj), sizeof(lldpwlcstat));
	if (lldpethstatObj) strlcpy(lldpethstat, json_object_get_string(lldpethstatObj), sizeof(lldpethstat));
	if (ap2gFhObj) ether_atoe(json_object_get_string(ap2gFhObj), ap2gFh);
	if (ap5gFhObj) ether_atoe(json_object_get_string(ap5gFhObj), ap5gFh);
	if (ap5g1FhObj) ether_atoe(json_object_get_string(ap5g1FhObj), ap5g1Fh);
	if (ap6gFhObj) ether_atoe(json_object_get_string(ap6gFhObj), ap6gFh);
	if (ap2gSsidFhObj) strlcpy(ap2gSsidFh, json_object_get_string(ap2gSsidFhObj), sizeof(ap2gSsidFh));
	if (ap5gSsidFhObj) strlcpy(ap5gSsidFh, json_object_get_string(ap5gSsidFhObj), sizeof(ap5gSsidFh));
	if (ap5g1SsidFhObj) strlcpy(ap5g1SsidFh, json_object_get_string(ap5g1SsidFhObj), sizeof(ap5g1SsidFh));
	if (ap6gSsidFhObj) strlcpy(ap6gSsidFh, json_object_get_string(ap6gSsidFhObj), sizeof(ap6gSsidFh));

#ifdef RTCONFIG_BHCOST_OPT
	/* for re path v1 & v2 & v3 */
	if (activePathV3Obj) {
		activePath = json_object_get_int(activePathV3Obj);
		if (activePath >= 0) {
			if (activePath & ETH1_U)
				activePath = ETH;
			else if (activePath & ETH2_U)
				activePath = ETH_2;
			else if (activePath & ETH3_U)
				activePath = ETH_3;
			else if (activePath & ETH4_U)
				activePath = ETH_4;
			else if (activePath & WL2G_U)
				activePath = WL_2G;
			else if (activePath & WL5G1_U)
				activePath = WL_5G;
			else if (activePath & WL5G2_U)
				activePath = WL_5G_1;
			else if (activePath & WL6G_U)
				activePath = WL_6G;
		}
	} else if (activePathV2Obj) {
		activePath = json_object_get_int(activePathV2Obj);
		if (activePath >= 0) {
			if (activePath & ETH1_U_V2)
				activePath = ETH;
			else if (activePath & ETH2_U_V2)
				activePath = ETH_2;
			else if (activePath & ETH3_U_V2)
				activePath = ETH_3;
			else if (activePath & ETH4_U_V2)
				activePath = ETH_4;
			else if (activePath & WL2G_U_V2)
				activePath = WL_2G;
			else if (activePath & WL5G1_U_V2)
				activePath = WL_5G;
			else if (activePath & WL5G2_U_V2)
				activePath = WL_5G_1;
		}
	}
	else
#endif
	if (activePathObj)
		activePath = json_object_get_int(activePathObj);

	//if (pap2gObj && pap5gObj && rssi2gObj && rssi5gObj)
	//	isPapSetting = 1;

	/* check slave client exists or not */
	ether_atoe(clientMac, ea);
	ip_atoe(clientIP, ipa);

	pthread_mutex_lock(&cfgLock);
	lock = file_lock(CFG_FILE_LOCK);
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], rea, MAC_LEN) == 0) {
			DBG_INFO("Find the same mac in the table");
			found = 1;
			break;
		}
	}

	if (found == 0) {	//add client info to table
		DBG_INFO("No the corresponding IP & MAC in the table");

		if(strlen(alias))
			snprintf(p_client_tbl->alias[p_client_tbl->count],
				sizeof(p_client_tbl->alias[p_client_tbl->count]), "%s", alias);
		memcpy(p_client_tbl->ipAddr[p_client_tbl->count], ipa, IP_LEN);
		memcpy(p_client_tbl->macAddr[p_client_tbl->count], ea, MAC_LEN);
		memcpy(p_client_tbl->realMacAddr[p_client_tbl->count], rea, MAC_LEN);
		p_client_tbl->reportStartTime[i] = time(NULL);
		p_client_tbl->online[i] = 1;

		/* 2g pap & rssi */
		if (pap2gObj && rssi2gObj) {
			memcpy(p_client_tbl->pap2g[p_client_tbl->count], pap2g, MAC_LEN);
			p_client_tbl->rssi2g[p_client_tbl->count] = rssi2g;
		}
		else
		{
			memset(p_client_tbl->pap2g[p_client_tbl->count], 0, MAC_LEN);
			p_client_tbl->rssi2g[p_client_tbl->count] = 0;
		}

		/* 5g pap & rssi */
		if (pap5gObj && rssi5gObj) {
			memcpy(p_client_tbl->pap5g[p_client_tbl->count], pap5g, MAC_LEN);
			p_client_tbl->rssi5g[p_client_tbl->count] = rssi5g;
		}
		else
		{
			memset(p_client_tbl->pap6g[p_client_tbl->count], 0, MAC_LEN);
			p_client_tbl->rssi5g[p_client_tbl->count] = 0;
		}

		/* 6g pap & rssi */
		if (pap6gObj && rssi6gObj) {
			memcpy(p_client_tbl->pap6g[p_client_tbl->count], pap6g, MAC_LEN);
			p_client_tbl->rssi6g[p_client_tbl->count] = rssi6g;
		}
		else
		{
			memset(p_client_tbl->pap6g[p_client_tbl->count], 0, MAC_LEN);
			p_client_tbl->rssi5g[p_client_tbl->count] = 0;
		}

		memcpy(p_client_tbl->ap2g[p_client_tbl->count], ap2g, MAC_LEN);
		memcpy(p_client_tbl->ap5g[p_client_tbl->count], ap5g, MAC_LEN);
		memcpy(p_client_tbl->ap5g1[p_client_tbl->count], ap5g1, MAC_LEN);
#ifdef RTCONFIG_DWB
		memcpy(p_client_tbl->apDwb[p_client_tbl->count], apdwb, MAC_LEN);
#endif
		memcpy(p_client_tbl->ap6g[p_client_tbl->count], ap6g, MAC_LEN);
		memcpy(p_client_tbl->sta2g[p_client_tbl->count], sta2g, MAC_LEN);
		memcpy(p_client_tbl->sta5g[p_client_tbl->count], sta5g, MAC_LEN);
		memcpy(p_client_tbl->sta6g[p_client_tbl->count], sta6g, MAC_LEN);

		if(strlen(fwVer))
			snprintf(p_client_tbl->fwVer[p_client_tbl->count],
				sizeof(p_client_tbl->fwVer[p_client_tbl->count]), "%s", fwVer);

		if(strlen(modelName))
			snprintf(p_client_tbl->modelName[p_client_tbl->count],
				sizeof(p_client_tbl->modelName[p_client_tbl->count]), "%s", modelName);

		if(strlen(productId))
			snprintf(p_client_tbl->productId[p_client_tbl->count],
				sizeof(p_client_tbl->productId[p_client_tbl->count]), "%s", productId);

		if (strlen(territoryCode))
			snprintf(p_client_tbl->territoryCode[p_client_tbl->count],
				sizeof(p_client_tbl->territoryCode[p_client_tbl->count]), "%s", territoryCode);

		/* update level */
		p_client_tbl->level[p_client_tbl->count] = (swMode == SW_MODE_ROUTER) ? 0 : -1;

#if defined(RTCONFIG_BHCOST_OPT) && defined(RTCONFIG_BHSWITCH_RE_SELFOPT)
		/* check trigger self opt or not */
		if (cm_judgeSelfOptTrigger(0, activePath))
			triggerSelfOpt = 1;
#endif

		/* update active path */
		p_client_tbl->activePath[p_client_tbl->count] = activePath;

		/* update band number */
		p_client_tbl->bandnum[p_client_tbl->count] = *bandNum;

		/* update ap ssid */
		memset(p_client_tbl->ap2g_ssid[p_client_tbl->count], 0, SSID_LEN);
		memset(p_client_tbl->ap5g_ssid[p_client_tbl->count], 0, SSID_LEN);
		memset(p_client_tbl->ap5g1_ssid[p_client_tbl->count], 0, SSID_LEN);
		memset(p_client_tbl->ap6g_ssid[p_client_tbl->count], 0, SSID_LEN);
		memcpy(p_client_tbl->ap2g_ssid[p_client_tbl->count], ap2gSsid, SSID_LEN);
		memcpy(p_client_tbl->ap5g_ssid[p_client_tbl->count], ap5gSsid, SSID_LEN);
		memcpy(p_client_tbl->ap5g1_ssid[p_client_tbl->count], ap5g1Ssid, SSID_LEN);
		memcpy(p_client_tbl->ap6g_ssid[p_client_tbl->count], ap6gSsid, SSID_LEN);

		/* update pap ssid */
		memset(p_client_tbl->pap2g_ssid[p_client_tbl->count], 0, SSID_LEN);
		memset(p_client_tbl->pap5g_ssid[p_client_tbl->count], 0, SSID_LEN);
		memset(p_client_tbl->pap6g_ssid[p_client_tbl->count], 0, SSID_LEN);
		memcpy(p_client_tbl->pap2g_ssid[p_client_tbl->count], pap2gSsid, SSID_LEN);
		memcpy(p_client_tbl->pap5g_ssid[p_client_tbl->count], pap5gSsid, SSID_LEN);
		memcpy(p_client_tbl->pap6g_ssid[p_client_tbl->count], pap6gSsid, SSID_LEN);

		/* update lldp stat*/
		memset(p_client_tbl->lldp_wlc_stat[p_client_tbl->count], 0, LLDP_STAT_LEN);
		memset(p_client_tbl->lldp_eth_stat[p_client_tbl->count], 0, LLDP_STAT_LEN);
		memcpy(p_client_tbl->lldp_wlc_stat[p_client_tbl->count], lldpwlcstat, LLDP_STAT_LEN);
		memcpy(p_client_tbl->lldp_eth_stat[p_client_tbl->count], lldpethstat, LLDP_STAT_LEN);

#ifdef RTCONFIG_FRONTHAUL_DWB
		/* update backhual status */
		p_client_tbl->BackhualStatus[p_client_tbl->count] = 8; // 1000. Set resend bits.
		backhaulStatusUpdate = 1;
#endif

#ifdef RTCONFIG_BHCOST_OPT
		/* update join time */
		if (isFirstJoined) 	p_client_tbl->joinTime[p_client_tbl->count] = uptime();
#endif

		/* update bssid for fronthaul */
		memcpy(p_client_tbl->ap2g_fh[p_client_tbl->count], ap2gFh, MAC_LEN);
		memcpy(p_client_tbl->ap5g_fh[p_client_tbl->count], ap5gFh, MAC_LEN);
		memcpy(p_client_tbl->ap5g1_fh[p_client_tbl->count], ap5g1Fh, MAC_LEN);
		memcpy(p_client_tbl->ap6g_fh[p_client_tbl->count], ap6gFh, MAC_LEN);

		/* update ssid for fronthaul */
		memcpy(p_client_tbl->ap2g_ssid_fh[p_client_tbl->count], ap2gSsidFh, SSID_LEN);
		memcpy(p_client_tbl->ap5g_ssid_fh[p_client_tbl->count], ap5gSsidFh, SSID_LEN);
		memcpy(p_client_tbl->ap5g1_ssid_fh[p_client_tbl->count], ap5g1SsidFh, SSID_LEN);
		memcpy(p_client_tbl->ap6g_ssid_fh[p_client_tbl->count], ap6gSsidFh, SSID_LEN);

		p_client_tbl->count++;

		updated = 1;
	}
	else	//update client info to table
	{

		DBG_INFO("Update corresponding IP & MAC(%d) in the table", i);

		p_client_tbl->reportStartTime[i] = time(NULL);
		p_client_tbl->online[i] = 1;

#ifdef RTCONFIG_BHCOST_OPT
		/* update join time */
		if (isFirstJoined) 	p_client_tbl->joinTime[i] = uptime();
#endif

		/* update alias */
		if (strlen(alias) && strcmp(alias, p_client_tbl->alias[i])) {
			memset(p_client_tbl->alias[i], 0,
				sizeof(p_client_tbl->alias[i]));
			snprintf(p_client_tbl->alias[i],
				sizeof(p_client_tbl->alias[i]), "%s", alias);
		}

		/* update mac for connection */
		if (memcmp(p_client_tbl->macAddr[i], ea, MAC_LEN) != 0)
			memcpy(p_client_tbl->macAddr[i], ea, MAC_LEN);

		/* update ip */
		if (memcmp(p_client_tbl->ipAddr[i], ipa, IP_LEN))
			memcpy(p_client_tbl->ipAddr[i], ipa, IP_LEN);

		/* update 2g pap and rssi */
		if (memcmp(p_client_tbl->pap2g[i], pap2g, MAC_LEN) != 0) {
			memcpy(p_client_tbl->pap2g[i], pap2g, sizeof(pap2g));
			p_client_tbl->level[i] = -1;
			updated = 1;
		}
		p_client_tbl->rssi2g[i] = rssi2g;

		/* update 5g pap and rssi */
		if (memcmp(p_client_tbl->pap5g[i], pap5g, MAC_LEN) != 0) {
			memcpy(p_client_tbl->pap5g[i], pap5g, sizeof(pap5g));
			p_client_tbl->level[i] = -1;
			updated = 1;
		}
		p_client_tbl->rssi5g[i] = rssi5g;

		/* update 6g pap and rssi */
		if (memcmp(p_client_tbl->pap6g[i], pap6g, MAC_LEN) != 0) {
			memcpy(p_client_tbl->pap6g[i], pap6g, sizeof(pap6g));
			p_client_tbl->level[i] = -1;
			updated = 1;
		}
		p_client_tbl->rssi6g[i] = rssi6g;

		/* update fw ver */
		if (strlen(fwVer) && strcmp(fwVer, p_client_tbl->fwVer[i])) {
			memset(p_client_tbl->fwVer[i], 0,
				sizeof(p_client_tbl->fwVer[i]));
			snprintf(p_client_tbl->fwVer[i],
				sizeof(p_client_tbl->fwVer[i]), "%s", fwVer);
		}

		/* update level */
		if (swMode == SW_MODE_ROUTER) {
			p_client_tbl->level[i] = 0;
			updated = 1;
		}

#if defined(RTCONFIG_BHCOST_OPT) && defined(RTCONFIG_BHSWITCH_RE_SELFOPT)
		/* check trigger self opt or not */
		if (cm_judgeSelfOptTrigger((isFirstJoined ? 0:p_client_tbl->activePath[i]), activePath))
			triggerSelfOpt = 1;
#endif

		/* update active path */
		if (p_client_tbl->activePath[i] != activePath) {
			p_client_tbl->activePath[i] = activePath;
			p_client_tbl->level[i] = -1;
			updated = 1;
			activePathUpdate = 1;
		}
#ifdef RTCONFIG_AMAS
		else if (p_client_tbl->activePath[i] == ETH && p_client_tbl->level[i] == -1)
			updated = 1;
#endif

		/* update territory Code */
		if (strlen(territoryCode))
		{
			memset(p_client_tbl->territoryCode[i], 0, sizeof(p_client_tbl->territoryCode[i]));
			snprintf(p_client_tbl->territoryCode[i], sizeof(p_client_tbl->territoryCode[i]), "%s", territoryCode);
		}

		/* update ap */
		if (memcmp(p_client_tbl->ap2g[i], ap2g, MAC_LEN) != 0) {
			memset(p_client_tbl->ap2g[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap2g[i], ap2g, MAC_LEN);
		}
		if (memcmp(p_client_tbl->ap5g[i], ap5g, MAC_LEN) != 0) {
			memset(p_client_tbl->ap5g[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap5g[i], ap5g, MAC_LEN);
		}
		if (memcmp(p_client_tbl->ap5g1[i], ap5g1, MAC_LEN) != 0) {
			memset(p_client_tbl->ap5g1[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap5g1[i], ap5g1, MAC_LEN);
		}
		if (memcmp(p_client_tbl->ap6g[i], ap6g, MAC_LEN) != 0) {
			memset(p_client_tbl->ap6g[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap6g[i], ap6g, MAC_LEN);
		}

		/* update dwb */
#ifdef RTCONFIG_DWB
		if (apdwbObj) {
			ether_atoe(json_object_get_string(apdwbObj), apdwb);
			if (memcmp(p_client_tbl->apDwb[i], apdwb, MAC_LEN) != 0) {
				memcpy(p_client_tbl->apDwb[i], apdwb, sizeof(apdwb));
				updated = 1;
			}
		}
#endif
		/* update ap ssid */
		if (memcmp(p_client_tbl->ap2g_ssid[i], ap2gSsid, SSID_LEN) != 0) {
			memset(p_client_tbl->ap2g_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap2g_ssid[i], ap2gSsid, SSID_LEN);
		}
		if (memcmp(p_client_tbl->ap5g_ssid[i], ap5gSsid, SSID_LEN) != 0) {
			memset(p_client_tbl->ap5g_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap5g_ssid[i], ap5gSsid, SSID_LEN);
		}
		if (memcmp(p_client_tbl->ap5g1_ssid[i], ap5g1Ssid, SSID_LEN) != 0) {
			memset(p_client_tbl->ap5g1_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap5g1_ssid[i], ap5g1Ssid, SSID_LEN);
		}
		if (memcmp(p_client_tbl->ap6g_ssid[i], ap6gSsid, SSID_LEN) != 0) {
			memset(p_client_tbl->ap6g_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap6g_ssid[i], ap6gSsid, SSID_LEN);
		}

		/* update pap ssid */
		if (memcmp(p_client_tbl->pap2g_ssid[i], pap2gSsid, SSID_LEN) != 0) {
			memset(p_client_tbl->pap2g_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->pap2g_ssid[i], pap2gSsid, SSID_LEN);
		}
		if (memcmp(p_client_tbl->pap5g_ssid[i], pap5gSsid, SSID_LEN) != 0) {
			memset(p_client_tbl->pap5g_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->pap5g_ssid[i], pap5gSsid, SSID_LEN);
		}
		if (memcmp(p_client_tbl->pap6g_ssid[i], pap6gSsid, SSID_LEN) != 0) {
			memset(p_client_tbl->pap6g_ssid[i], 0, SSID_LEN);
			memcpy(p_client_tbl->pap6g_ssid[i], pap6gSsid, SSID_LEN);
		}

		/* update lldp stat */
		if (strlen(lldpwlcstat)) {
			if (memcmp(p_client_tbl->lldp_wlc_stat[i], lldpwlcstat, LLDP_STAT_LEN) != 0) {
				memset(p_client_tbl->lldp_wlc_stat[i], 0, LLDP_STAT_LEN);
				memcpy(p_client_tbl->lldp_wlc_stat[i], lldpwlcstat, LLDP_STAT_LEN);
			}
		}

		if (strlen(lldpethstat)) {
			if (memcmp(p_client_tbl->lldp_eth_stat[i], lldpethstat, LLDP_STAT_LEN) != 0) {
				memset(p_client_tbl->lldp_eth_stat[i], 0, LLDP_STAT_LEN);
				memcpy(p_client_tbl->lldp_eth_stat[i], lldpethstat, LLDP_STAT_LEN);
			}
		}

		/* update bssid for fronthaul */
		if (memcmp(p_client_tbl->ap2g_fh[i], ap2gFh, MAC_LEN) != 0) {
			memset(p_client_tbl->ap2g_fh[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap2g_fh[i], ap2gFh, MAC_LEN);
		}
		if (memcmp(p_client_tbl->ap5g_fh[i], ap5gFh, MAC_LEN) != 0) {
			memset(p_client_tbl->ap5g_fh[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap5g_fh[i], ap5gFh, MAC_LEN);
		}
		if (memcmp(p_client_tbl->ap5g1_fh[i], ap5g1Fh, MAC_LEN) != 0) {
			memset(p_client_tbl->ap5g1_fh[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap5g1_fh[i], ap5g1Fh, MAC_LEN);
		}
		if (memcmp(p_client_tbl->ap6g_fh[i], ap6gFh, MAC_LEN) != 0) {
			memset(p_client_tbl->ap6g_fh[i], 0, MAC_LEN);
			memcpy(p_client_tbl->ap6g_fh[i], ap6gFh, MAC_LEN);
		}

		/* update ssid for fronthaul */
		if (memcmp(p_client_tbl->ap2g_ssid_fh[i], ap2gSsidFh, SSID_LEN) != 0) {
			memset(p_client_tbl->ap2g_ssid_fh[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap2g_ssid_fh[i], ap2gSsidFh, SSID_LEN);
		}
		if (memcmp(p_client_tbl->ap5g_ssid_fh[i], ap5gSsidFh, SSID_LEN) != 0) {
			memset(p_client_tbl->ap5g_ssid_fh[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap5g_ssid_fh[i], ap5gSsidFh, SSID_LEN);
		}
		if (memcmp(p_client_tbl->ap5g1_ssid_fh[i], ap5g1SsidFh, SSID_LEN) != 0) {
			memset(p_client_tbl->ap5g1_ssid_fh[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap5g1_ssid_fh[i], ap5g1SsidFh, SSID_LEN);
		}
		if (memcmp(p_client_tbl->ap6g_ssid_fh[i], ap6gSsidFh, SSID_LEN) != 0) {
			memset(p_client_tbl->ap6g_ssid_fh[i], 0, SSID_LEN);
			memcpy(p_client_tbl->ap6g_ssid_fh[i], ap6gSsidFh, SSID_LEN);
		}
	}

#ifdef RTCONFIG_DWB
	if (dwbUpdate) {
		updated = 1;
		dwbUpdate = 0;
	}
#endif
	/* Update bridge's wired mac for authorized ap/re*/
	if (wiredMacObj && macObj) {
		cm_updateBridgeMacList(wiredMacObj, realMac);
		cm_processWiredClientList((char *)json_object_to_json_string(wiredMacObj), realMac, onlineListObj, offlineListObj);
	}

	/* Update bridge's wired mac for DUT */
	snprintf(portNo, sizeof(portNo), "%s", get_portno_by_ifname());
	if (strlen(portNo) > 0) {
		DBG_INFO("portNo(%s)", portNo);

		dutRootObj = json_object_new_object();
		if (dutRootObj) {
			add_brforward_entry_by_port(dutRootObj, portNo);
			json_object_object_get_ex(dutRootObj, CFG_STR_WIRED_MAC, &dutWiredMacObj);
			if (dutWiredMacObj)
				cm_updateBridgeMacList(dutWiredMacObj, get_unique_mac());
			json_object_put(dutRootObj);
		}
		else
			DBG_INFO("dutRootObj is NULL");
	}
	else
		DBG_INFO("failed");

	/* update the level of relationship */
	if (updated)
		networkCostUpdate = cm_updateClientLevel();

	/* record 5g low/high band */
	if (curChannelObj)
		cm_record5gBand(*bandNum, curChannelObj);

	/* update changed config */
	if (configObj)
		cm_updatePrivateConfig(realMac, configObj);

	file_unlock(lock);
	pthread_mutex_unlock(&cfgLock);

#ifdef RADAR_DET
#if defined(RTCONFIG_WIFI_SON)
	if (!nvram_match("wifison_ready","1"))
#endif
	{
	/* update available wireless channel */
	json_object_object_get_ex(decryptedRoot, CFG_STR_CHANNEL, &channelObj);
	if (channelObj && macObj) {
		snprintf(channelMsg, sizeof(channelMsg), "{\"%s\":\"%s\",\"%s\":\"%s\"}",
			 CFG_STR_MAC, realMac,
			 CFG_STR_CHANNEL, (char *)json_object_get_string(channelObj));
		cm_updateAvailableChannel(channelMsg);
		chmgmt_notify();
	}
	} /* !wifison_ready */
#endif	/* RADAR_DET */

	/* update chanspec */
	json_object_object_get_ex(decryptedRoot, CFG_STR_CHANSPEC, &chanspecObj);
	if (chanspecObj && macObj) {
		snprintf(chanspecMsg, sizeof(chanspecMsg), "{\"%s\":\"%s\",\"%s\":%s}",
			 CFG_STR_MAC, realMac,
			 CFG_STR_CHANSPEC, (char *)json_object_get_string(chanspecObj));
		cm_updateChanspec(chanspecMsg);
	}

	/* record new band */
	pthread_mutex_lock(&cfgLock);
	if (selChannelObj)
		cm_recordNewBand(realMac, selChannelObj);
	else if (curChannelObj)
		cm_recordNewBand(realMac, curChannelObj);
	pthread_mutex_unlock(&cfgLock);

	/* update wired port status */
	json_object_object_get_ex(decryptedRoot, CFG_STR_WIRED_PORT, &wiredPortObj);
	if (wiredPortObj) {
		snprintf(filePath, sizeof(filePath), "%s/%s.port",
			TEMP_ROOT_PATH, realMac);
		json_object_to_file(filePath, wiredPortObj);
	}

	/* update plc status */
	json_object_object_get_ex(decryptedRoot, CFG_STR_PLC_STATUS, &plcStatusObj);
	if (plcStatusObj) {
		snprintf(filePath, sizeof(filePath), "%s/%s.plc",
			TEMP_ROOT_PATH, realMac);
		json_object_to_file(filePath, plcStatusObj);
	}

#ifdef RTCONFIG_NBR_RPT
	/* update nbr data */
	json_object_object_get_ex(decryptedRoot, CFG_STR_NBR_DATA, &nbrDataObj);
	if (nbrDataObj && macObj) {
		snprintf(nbrDataMsg, sizeof(nbrDataMsg), "{\"%s\":\"%s\",\"%s\":%s}",
			CFG_STR_MAC, realMac,
			CFG_STR_NBR_DATA, (char *)json_object_get_string(nbrDataObj));
		cm_updateNbrData(nbrDataMsg);
	}
#endif

	json_object_put(decryptedRoot);

	/* notify cost update */
	if (networkCostUpdate) {
		/* notify all slaves to request cost */
		cm_updateNetworkCost(NULL);
		cm_updateNetworkLevel(NULL);
	}
	else
	{
		if (activePathUpdate) {
			/* only notify one slave to request cost */
			cm_updateNetworkCost(realMac);
			cm_updateNetworkLevel(realMac);
		}
	}

#ifdef RTCONFIG_FRONTHAUL_DWB
	if (updated || backhaulStatusUpdate)
		backhaulStatusUpdate = cm_updateBackhaulStatus();

	if (backhaulStatusUpdate || chk_renotify_backhualstatus()) // Notify needed update backhual status slaves
		cm_NotifyUpdateBackhaulStatus();
#endif
#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
	/* notify re list update */
	if (cm_checkReListUpdate(realMac, sta2gMacList, sta5gMacList, sta6gMacList)) {
		cm_updateReList(realMac, sta2gMacList, sta5gMacList, sta6gMacList, RELIST_UPDATE);
		if ((reListObj = json_object_from_file(RE_LIST_JSON_FILE)) != NULL) {
			cm_sendNotificationByType(NOTIFY_UPDATERELIST, reListObj);
			json_object_put(reListObj);
			wl_set_macfilter_list();
		}
	}
#ifdef RTCONFIG_BCN_RPT
	if(found == 0) {
		cm_updateAPList();
		if ((APListObj = json_object_from_file(AP_LIST_JSON_FILE)) != NULL) {
			cm_sendNotificationByType(NOTIFY_UPDATEAPLIST, APListObj);
			json_object_put(APListObj);
		}
	}
#endif


	/* check RE territory code from list  */
	if (nvram_contains_word("rc_support", "loclist"))
	{
		DBG_INFO("** check RE territory code from list **");
		(void)cm_checkTerritoryCode();
	}
	} /* !wifison_ready */

	return triggerSelfOpt;
} /* End of cm_updateClientTbl */

/*
========================================================================
Routine Description:
	Handle termination signal.

Arguments:
	sig		- no use

Return Value:
	None

========================================================================
*/
static void cm_terminateHandle(int sig)
{
	int sig_pid = getpid();

	if (sig == SIGTERM) {
		DBG_INFO("pid (%d) got SIGTERM", sig_pid);

		if (pid != sig_pid) {
			DBG_INFO("pid (%d) isn't main, pass signal handle", sig_pid);
			return;
		}

		/* stop sched */
		stop_sched();

		/* detach shared memory */
		if (shmdt(p_client_tbl) == -1)
			DBG_ERR("detach shared memory failed");

		/* destroy shared memory */
		if (shmctl(shm_client_tbl_id, IPC_RMID, 0) == -1)
			DBG_ERR("destroy shared memory failed");

#ifdef DUAL_BAND_DETECTION
		cm_destroyDBListSharedMemory(1);
#endif

		/* delete json object */
#ifdef ROAMING_INFO
		json_object_put(staRoamingInfo);
#endif

		/* delete new and multi band */
		if (newBandObj) json_object_put(newBandObj);
		if (multiBandObj) json_object_put(multiBandObj);

		/* close all used sockets */
		cm_closeSocket(&cm_ctrlBlock);

		/* destroy client's hashtable */
		ht_destroy(clientHashTable);

		/* free public, private and group key */
		if (!IsNULL_PTR(cm_ctrlBlock.publicKey)) MFREE(cm_ctrlBlock.publicKey);
		if (!IsNULL_PTR(cm_ctrlBlock.privateKey)) MFREE(cm_ctrlBlock.privateKey);
		if (!IsNULL_PTR(cm_ctrlBlock.groupKey)) MFREE(cm_ctrlBlock.groupKey);
		if (!IsNULL_PTR(cm_ctrlBlock.groupKey1)) MFREE(cm_ctrlBlock.groupKey1);

#ifdef CONN_DIAG
		/* for conn diag */
		if (connDiagUdpList) {
			cm_terminateConnDiagPktList();
			list_delete(connDiagUdpList);
		}
#endif

		/* set flagIsTerminated for exit */
		cm_ctrlBlock.flagIsTerminated = 1;

#ifdef PTHREAD_STACK_SIZE
		if (attrp != NULL) pthread_attr_destroy(attrp);
#endif

#if defined(RTCONFIG_BHCOST_OPT) && defined(RTCONFIG_BHSWITCH_RE_SELFOPT)
		if (!IsNULL_PTR(optBhSwitchRule)) MFREE(optBhSwitchRule);
#endif
	}
} /* End of cm_terminateHandle */

/*
========================================================================
Routine Description:
	Display client information.

Arguments:
	sig		- no use

Return Value:
	None

========================================================================
*/
static void cm_usr1Handle(int sig)
{
	if (!strcmp(nvram_safe_get("cfg_status"), "1")) {
		CM_CTRL *pCtrlBK = &cm_ctrlBlock;
		int i = clientHashTable->capacity;
		char *dump = NULL;

		DBG_PRINTF("Firmware Check: %d\n", pCtrlBK->flagIsFirmwareCheck);
		DBG_PRINTF("Selected 5G band: %d [channel(%d), bw(%d), sb(%d)]\n",
			selected5gBand, channel5g, bw5g, nctrlsb5g);
		if (newBandObj) {
			DBG_INFO("Channel Info of New Band:");
			json_object_object_foreach(newBandObj, key, val) {
				DBG_INFO("\t%s (%d)", key, json_object_get_int(val));
			}
		}
		if (multiBandObj) {
			DBG_INFO("Band Type of Multi Band:");
			json_object_object_foreach(multiBandObj, key, val) {
				DBG_INFO("\t%s", key);
			}
		}
		DBG_PRINTF("Expired time for group key: %d\n", groupKeyExpireTime);
		DBG_PRINTF("Group Key Ready: %d\n", pCtrlBK->groupKeyReady);
		if (pCtrlBK->groupKeyStartTime !=0 ) {
		dump = dumpHEX((unsigned char *)&pCtrlBK->groupKey[0], pCtrlBK->groupKeyLen);
			if (!IsNULL_PTR(dump)) {
				DBG_PRINTF("*** DUMP group key ***\n%s\n", dump);
				MFREE(dump);
			}
		}
		DBG_PRINTF("Group Key Time: %d\n", (int) (uptime() - pCtrlBK->groupKeyStartTime));
		DBG_PRINTF("Start Group Key Time: %ld\n", pCtrlBK->groupKeyStartTime);

		if (pCtrlBK->groupKey1StartTime !=0 ) {
			dump = dumpHEX((unsigned char *)&pCtrlBK->groupKey1[0], pCtrlBK->groupKeyLen);
			if (!IsNULL_PTR(dump)) {
				DBG_PRINTF("*** DUMP group key 1 ***\n%s\n", dump);
				MFREE(dump);
			}
			DBG_PRINTF("Group Key 1 Time: %d\n", (int) (uptime() - pCtrlBK->groupKey1StartTime));
			DBG_PRINTF("Group Key 1 Start Time: %ld\n", pCtrlBK->groupKey1StartTime);
		}
		DBG_PRINTF("Now Up Time: %ld\n", uptime());

		DBG_PRINTF("Expired time for session key: %d\n", sessionKeyExpireTime);
		DBG_PRINTF("The number of elements in table(%d)\n", clientHashTable->e_num);
		while(--i >= 0) {
			hash_elem_t* e = clientHashTable->table[i];

			DBG_PRINTF("The index of hash(%d)\n", i);
			DBG_PRINTF("====================================\n");
			while(e) {
				DBG_PRINTF("Client MAC(Hash Key): %s\n", e->key);
				DBG_PRINTF("Client IP: %s\n", e->clientIP);
				DBG_PRINTF("Authorized: %d\n", e->authorized);
				DBG_PRINTF("FW Status: %d\n", e->fwStatus);
#ifdef RTCONFIG_BHCOST_OPT
				DBG_PRINTF("SO Status: %d\n", e->soStatus);
#endif
				DBG_PRINTF("Join Status: %d\n", e->joinStatus);
				DBG_PRINTF("Reconnect Status: %d\n", e->reconnStatus);
				if (e->featureList)
					DBG_PRINTF("Feature List: %s\n", e->featureList);

				if (e->sessionKeyStartTime != 0) {
					dump = dumpHEX((unsigned char *)&e->sessionKey[0], 32);
					if (!IsNULL_PTR(dump)) {
						DBG_PRINTF("*** DUMP session key ***\n%s\n", dump);
						MFREE(dump);
					}
				}
				DBG_PRINTF("Session Key Time: %d\n", (int) (uptime() - e->sessionKeyStartTime));
				DBG_PRINTF("Session Key Start Time: %ld\n", e->sessionKeyStartTime);

				if (e->sessionKey1StartTime != 0) {
					dump = dumpHEX((unsigned char *)&e->sessionKey1[0], 32);
					if (!IsNULL_PTR(dump)) {
						DBG_PRINTF("*** DUMP session key ***\n%s\n", dump);
						MFREE(dump);
					}
					DBG_PRINTF("Session Key 1 Time: %d\n", (int) (uptime() - e->sessionKey1StartTime));
					DBG_PRINTF("Session Key 1 Start Time: %ld\n", e->sessionKey1StartTime);
				}
				DBG_PRINTF("Now Up Time: %ld\n", uptime());
				e = e->next;
			}
			DBG_PRINTF("\n");
		}
	}

#if 0
        /* for test */
        unsigned char *encryptedMsg = NULL;
        size_t encLen = 0;
        unsigned char msgBuf[256] = {0};
        //snprintf((char *)&msgBuf[0], sizeof(msgBuf), "{\"RAST\": { \"EID\": \"1\", \"STA\": \"00:11:22:33:44:55\", \"RSSI\": \"-80\", \"BAND\": \"2\"}}");
        //encryptedMsg = cm_aesEncryptMsg(cm_ctrlBlock.groupKey, REQ_STAMON, &msgBuf[0], strlen((char *)msgBuf), &encLen);
        //snprintf((char *)&msgBuf[0], sizeof(msgBuf), "{\"RAST\": { \"EID\": \"2\", \"STA\": \"00:11:22:33:44:55\", \"RSSI\": \"-70\", \"AP\": \"D8:50:E6:5A:3F:C0\"}}");
        //encryptedMsg = cm_aesEncryptMsg(cm_ctrlBlock.groupKey, RSP_STAMON, &msgBuf[0], strlen((char *)msgBuf), &encLen);

        snprintf((char *)&msgBuf[0], sizeof(msgBuf), "{\"RAST\": { \"EID\": \"4\", \"STA\": \"00:11:22:33:44:55\", \"RSSI\": \"-70\", \"CANDIDATE\": \"%s\"}}", get_lan_hwaddr());
        encryptedMsg = cm_aesEncryptMsg(cm_ctrlBlock.groupKey, REQ_ACL, &msgBuf[0], strlen((char *)msgBuf), &encLen);

        if (IsNULL_PTR(encryptedMsg)) {
                DBG_ERR("Failed to MALLOC() !!!");
                return;
        }

        if (cm_sendUdpPacket("192.168.1.255", encryptedMsg, encLen) == 0) {
                DBG_ERR("Fail to send UDP packet to %s!");
        }

        if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
        DBG_INFO("send udp packet out");
#endif
} /* End of cm_usr1Handle */

/*
========================================================================
Routine Description:
	Send notification to client.

Arguments:
	sig		- no use

Return Value:
	None

========================================================================
*/
static void cm_usr2Handle(int sig)
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;
	pthread_t sockThread;
	json_object *ftListObj = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	char rmac[18];
	json_object *cfgFileObj = NULL;
#endif
	int applyLock = 0;
	int *args = NULL;

#ifdef RTCONFIG_AMAS_WGN
    int keep_wloff_vifs = 0;
#endif  // RTCONFIG_AMAS_WGN    

	applyLock = file_lock(CFG_APPLY_LOCK);
	pthread_mutex_lock(&cfgLock);
#ifdef PRELINK
	regen_hash_bundle_key();
#endif
#ifdef RTCONFIG_DWB
	if (sig != -1) // -1, Don't do cm_AutoDetect_Dedicated_Wifi_Backhaul();
		cm_AutoDetect_Dedicated_Wifi_Backhaul(1, 0);
#endif
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	cfgFileObj = json_object_from_file(CFG_JSON_FILE);

#ifdef UPDATE_COMMON_CONFIG
	cm_updateCommonConfigToFile(NULL);
#endif
#endif

	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		memset(rmac, 0, sizeof(rmac));
		snprintf(rmac, sizeof(rmac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);
#endif

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification to slave to request cost*/
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s), key time(%d)",
					e->clientIP, e->key,  (int) (uptime() - e->sessionKeyStartTime));
				if (cm_checkSessionKeyExpire(e))
					cm_sendNotification(e, NOTIFY_REKEY, NULL);	// ask the client to rekey
				else
				{
					memset(msgBuf, 0, sizeof(msgBuf));
					if (e->featureList) {
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
						cm_updateCommonToPrivateConfig(rmac, e->featureList, cfgFileObj);
#endif
						if (cm_checkCfgInfo(e->key, e->featureList, (char *)&msgBuf[0], MAX_MESSAGE_SIZE, 0) > 0 &&
							(ftListObj = json_tokener_parse((char *)msgBuf)) != NULL) {
#ifdef RTCONFIG_AMAS_WGN
                            if (!cm_sendNotification(e, NOTIFY_CHECK, ftListObj))   // cfg changed
                                keep_wloff_vifs = 1;
#else   // RTCONFIG_AMAS_WGN                            
							cm_sendNotification(e, NOTIFY_CHECK, ftListObj);	// cfg changed
#endif  // RTCONFIG_AMAS_WGN
                            json_object_put(ftListObj);
						}
						else
#ifdef RTCONFIG_AMAS_WGN    
                            if (!cm_sendNotification(e, NOTIFY_CHECK, NULL))  
                                 keep_wloff_vifs = 1;              
#else   // RTCONFIG_AMAS_WGN                            
							cm_sendNotification(e, NOTIFY_CHECK, NULL);
#endif  // RTCONFIG_AMAS_WGN
					}
					else
						cm_sendNotification(e, NOTIFY_CHECK, NULL);	// cfg changed
				}
			}
			e = ht_iterate_elem(&it);
		}
	}
#ifdef RTCONFIG_AMAS_WGN
    if (keep_wloff_vifs == 0 && nvram_get("wgn_wloff_vifs"))
        nvram_unset("wgn_wloff_vifs");
#endif  // RTCONFIG_AMAS_WGN
    
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	json_object_put(cfgFileObj);
#endif
	pthread_mutex_unlock(&cfgLock);

	if (args = malloc(sizeof(int))) {
		*args = applyLock;
		/* check & send cfg action */
		if (pthread_create(&sockThread, attrp, cm_sendCfgAction, args) != 0) {
			DBG_ERR("could not create thread for cm_sendCfgAction");
			file_unlock(applyLock);
			free(args);
		}
	}
	else
		file_unlock(applyLock);
} /* End of cm_usr2Handle */

/*
========================================================================
Routine Description:
	Kill running daemon if exists.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_killDaemon()
{
	kill_pidfile_s(PID_CM_SERVER, SIGTERM);

	/* sleep for a where to kill old daemon */
	sleep(1);
} /* End of cm_killDaemon */

/*
========================================================================
Routine Description:
	Save the pid for running daemon.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_saveDaemonPid()
{
	FILE *fp;

	/* write pid */
	if ((fp = fopen(PID_CM_SERVER, "w")) != NULL)
	{
		pid = getpid();
		fprintf(fp, "%d", pid);
		fclose(fp);
	}
} /* End of cm_saveDaemonPid */

/*
========================================================================
Routine Description:
	Check timeout for the session key of client.

Arguments:
	elem		- hash element for client.

Return Value:
	0		- not expire
	1		- expire

========================================================================
*/
static int cm_checkSessionKeyExpire(hash_elem_t* elem)
{
	int sKeyTime = (int) (uptime() - elem->sessionKeyStartTime);
	int sKey1Time = (int) (uptime() - elem->sessionKey1StartTime);

	if (sKeyTime >= sessionKeyExpireTime &&
		sKey1Time >= sessionKeyExpireTime) {
		DBG_INFO("sKeyTime(%d), sKey1Time(%d), sessionKeyExpireTime(%d)",
				sKeyTime, sKey1Time, sessionKeyExpireTime);
		return 1;
	}

	return 0;
} /* End of cm_checkSessionKeyExpire */

/*
========================================================================
Routine Description:
	Check timeout for the group key.

Arguments:
	None

Return Value:
	0		- not expire
	1		- expire

========================================================================
*/
int cm_checkGroupKeyExpire()
{
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	if (!cm_ctrlBlock.groupKeyReady)
		return 1;

	if (gKeyTime >= groupKeyExpireTime &&
		gKey1Time >= groupKeyExpireTime) {
		DBG_INFO("gKeyTime(%d), gKey1Time(%d), groupKeyExpireTime(%d)",
				gKeyTime, gKey1Time, groupKeyExpireTime);
		return 1;
	}

	return 0;
} /* End of cm_checkGroupKeyExpire */

/*
========================================================================
Routine Description:
	Send group rekey except for client ip.

Arguments:
	*clientIP		- client's ip for exception

Return Value:
	None

========================================================================
*/
void cm_sendGroupRekeyExceptIp(char *clientIP)
{
	pthread_t notifyThread;
	char *ipArgs = NULL;

        if (clientIP && strlen(clientIP)) {
                ipArgs = malloc(32);
                snprintf(ipArgs, 32, "%s", clientIP);
        }

	/* send notification to do group rekey */
	if (pthread_create(&notifyThread, attrp, cm_sendGroupRekey, (void *)ipArgs) != 0) {
		DBG_ERR("could not create thread");
		free(ipArgs);
	}
} /* End of cm_sendGroupKeyExpireExceptIp */

/*
========================================================================
Routine Description:
	Ignore 5g2 to 5g1 Convert

Arguments:
	*name		- nvram key

Return Value:
	1 : ignore, 0 : none

========================================================================
*/
int ignore_5g2_to_5g1(char *name)
{
	struct ignore_list_t { char *s; };
	const struct ignore_list_t ignore_list[] =
   	{
    	{ "wl1_bsd_steering_policy\0"      },
    	{ "wl1_bsd_steering_policy_x\0"    },
    	{ "wl1_bsd_sta_select_policy\0"    },
   		{ "wl1_bsd_sta_select_policy_x\0"  },
   		{ "wl1_bsd_if_select_policy\0"     },
   		{ "wl1_bsd_if_select_policy_x\0"   },
     	{ "wl1_bsd_if_qualify_policy\0"    },
     	{ "wl1_bsd_if_qualify_policy_x\0"  },
     	{ NULL }
   	};

  	int ignore = 0;
  	struct ignore_list_t *ss  = NULL;

   	for (ss = (struct ignore_list_t *)&ignore_list[0]; name != NULL && ss->s != NULL; ss++)
  	{
    	if ((ignore = (strlen(name) == strlen(ss->s) && strncmp(name, ss->s, strlen(name)) == 0)) == 1)
    	{
        	break;
    	}
 	}

#ifdef SMART_CONNECT
	if (ignore == 0) {
		int smart_connect = nvram_get_int("smart_connect_x");
		struct smart_connect_nvsuffix_t *P = NULL;
		if ((smart_connect == 1 || smart_connect == 3) && strstr(name, "wl1_")) {  // Only for 5G
			for (P = &smart_connect_nvsuffix_list[0]; P->name != NULL; P++) {
				if (strlen(P->name) > 0 && strstr(name, P->name)) {
					ignore = 1;
					break;
				}
				if (P->converted_name != NULL && strlen(P->converted_name) > 0 && strstr(name, P->converted_name)) {
					ignore = 1;
					break;
				}
			}
		}
	}
#endif

	return ignore;
}



/*
========================================================================
Routine Description:
	Transform the name and value of cfg for different mode.

Arguments:
	inRoot		- decrypted json object from client
	outRoot		- transformed json object to client
	private		- process private cfg

Return Value:
	None

========================================================================
*/
static void cm_transformCfgParam(json_object *inRoot, json_object *outRoot, int private)
{
	json_object *ftListObj = NULL;
	json_object *cfgAllObj = NULL;
	json_object *fileRoot = NULL;
	json_object *cfgbandnum = NULL;
	json_object *cfgbandVer = NULL;
	json_object *cfgWireless = NULL;
	int ftListLen = 0;
	struct feature_mapping_s *pFeature = NULL;
	struct subfeature_mapping_s *pSubFeature = NULL;
	json_object *paramObj = NULL;
	json_object *ftEntry = NULL;
	struct param_mapping_s *pParam = NULL;
	json_object *changedParam = NULL;
	json_object *uMacObj = NULL;
	char uniqueMac[18] = {0}, outAuth[16] ,finalparamname[256];
	int reBandNum = 0;
	int cfgband_Ver=0;
	int i = 0;
#ifdef SUPPORT_TRI_BAND
	char suffix[32] = {0};
	char new_param[32] = {0};
	int client_5g1=0;
#endif
	char check_param_name[128] = {0};
	
	
	char *ss = NULL, s[81];
#if defined(RTCONFIG_AMAS_WGN)

	char capabilityFilePath[64] = {0};
	json_object *capabilityObj = NULL;
	json_object *cfgGuestNetworkNo2g = NULL;
	json_object *cfgGuestNetworkNo5g = NULL;
	json_object *cfgGuestNetworkNo5gH = NULL;
	json_object *cfgGuestNetworkNo6g = NULL;
	json_object *cfgParam = NULL;
	int guestNetworkNo = 0;
	int guestNetworkNo2g = 0;
	int guestNetworkNo5g = 0;
	int guestNetworkNo5gH  = 0;
	int guestNetworkNo6g = 0;
	char guest_ifnames[512], word[64], *next = NULL;
	int unit = -1, subunit = -1, band_type = -1;
	char re_band_type[5];
	int isfind = 0;

#endif	/* RTCONFIG_AMAS_WGN */
	int amas_eap_bhmode_changed = 0, smart_connect_x_changed = 0;

	DBG_INFO("enter");

	json_object_object_get_ex(inRoot, CFG_STR_FEATURE, &ftListObj);
	json_object_object_get_ex(inRoot, CFG_STR_CFGALL, &cfgAllObj);
	json_object_object_get_ex(inRoot, CFG_STR_BANDNUM, &cfgbandnum);
	json_object_object_get_ex(inRoot, CFG_BAND_INDEX_VERSION, &cfgbandVer);
	json_object_object_get_ex(inRoot, CFG_STR_MAC, &uMacObj);
	if (uMacObj)
		snprintf(uniqueMac, sizeof(uniqueMac), "%s", json_object_get_string(uMacObj));

	if (private)
		json_object_object_get_ex(inRoot, CFG_STR_PRIVATE_FEATURE, &ftListObj);

	if (cfgbandnum)
		reBandNum = atoi(json_object_get_string(cfgbandnum));


	if (cfgbandVer == NULL) {
		DBG_INFO("cfgbandVer(0)");
		cfgband_Ver=0;
	}
	else{
		DBG_INFO("cfgbandVer(%s)", json_object_get_string(cfgbandVer));
		cfgband_Ver = atoi(json_object_get_string(cfgbandVer));
	}
	
	if (ftListObj)
	{
		ftListLen = json_object_array_length(ftListObj);
#ifdef SUPPORT_TRI_BAND
#if defined(RTCONFIG_WIFI_SON)
		if(!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
		{
		if(cfgbandnum!=NULL && reBandNum>2)
		{
			client_5g1=1;
			DBG_INFO("cfgbandnum(%s)", json_object_get_string(cfgbandnum));
		}
		} /* !wifison_ready */
#endif

	}
	else
	{
		DBG_ERR("ftListObj is NULL!");
		return;
	}

        if (!cfgAllObj && !private) {
                fileRoot = json_object_from_file(CFG_JSON_FILE);
                if (!fileRoot) {
                        DBG_ERR("fileRoot is NULL!");
                        return;
                }
        }

#if defined(RTCONFIG_AMAS_WGN)
	/* read capability file */
 	json_object_object_get_ex(inRoot, CFG_STR_MAC, &uMacObj);
	if (uMacObj)
	{
		snprintf(capabilityFilePath, sizeof(capabilityFilePath), "%s/%s.cap", TEMP_ROOT_PATH, json_object_get_string(uMacObj));
		if ((capabilityObj = json_object_from_file(capabilityFilePath)))
		{
			guestNetworkNo2g = 0;
			memset(s, 0, sizeof(s));
			snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_2G);
			if (json_object_object_get_ex(capabilityObj, s, &cfgGuestNetworkNo2g) == TRUE)
			{
				if (json_object_get_int64(cfgGuestNetworkNo2g) == ONE_GUEST_NETWORK)
					guestNetworkNo2g = 1;
				else if (json_object_get_int64(cfgGuestNetworkNo2g) == TWO_GUEST_NETWORK)
					guestNetworkNo2g = 2;
				else if (json_object_get_int64(cfgGuestNetworkNo2g) == THREE_GUEST_NETWORK)
					guestNetworkNo2g = 3;
				else 
					guestNetworkNo2g = 0;			
			}
				
			guestNetworkNo5g = 0;
			memset(s, 0, sizeof(s));
			snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_5G);
			if (json_object_object_get_ex(capabilityObj, s, &cfgGuestNetworkNo5g) == TRUE)
			{
				if (json_object_get_int64(cfgGuestNetworkNo5g) == ONE_GUEST_NETWORK)
					guestNetworkNo5g = 1;
				else if (json_object_get_int64(cfgGuestNetworkNo5g) == TWO_GUEST_NETWORK)
					guestNetworkNo5g = 2;
				else if (json_object_get_int64(cfgGuestNetworkNo5g) == THREE_GUEST_NETWORK)
					guestNetworkNo5g = 3;
				else 
					guestNetworkNo5g = 0;							
			}

			guestNetworkNo5gH = 0;		
			memset(s, 0, sizeof(s));
			snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_5GH);
			if (json_object_object_get_ex(capabilityObj, s, &cfgGuestNetworkNo5gH) == TRUE)
			{
				if (json_object_get_int64(cfgGuestNetworkNo5gH) == ONE_GUEST_NETWORK)
					guestNetworkNo5gH = 1;
				else if (json_object_get_int64(cfgGuestNetworkNo5gH) == TWO_GUEST_NETWORK)
					guestNetworkNo5gH = 2;
				else if (json_object_get_int64(cfgGuestNetworkNo5gH) == THREE_GUEST_NETWORK)
					guestNetworkNo5gH = 3;
				else 
					guestNetworkNo5gH = 0;											
			}

			guestNetworkNo6g = 0;
			memset(s, 0, sizeof(s));
			snprintf(s, sizeof(s), "%d", GUEST_NETWORK_NO_6G);
			if (json_object_object_get_ex(capabilityObj, s, &cfgGuestNetworkNo6g) == TRUE)
			{
				if (json_object_get_int64(cfgGuestNetworkNo6g) == ONE_GUEST_NETWORK)
					guestNetworkNo6g = 1;
				else if (json_object_get_int64(cfgGuestNetworkNo6g) == TWO_GUEST_NETWORK)
					guestNetworkNo6g = 2;
				else if (json_object_get_int64(cfgGuestNetworkNo6g) == THREE_GUEST_NETWORK)
					guestNetworkNo6g = 3;
				else 
					guestNetworkNo6g = 0;										
			}
		}
	}
#endif	/* RTCONFIG_AMAS_WGN */			

	for (pFeature = &feature_mapping_list[0]; pFeature->index != 0; pFeature++) {
		paramObj = NULL;

		for (pSubFeature = &subfeature_mapping_list[0]; pSubFeature->index != 0; pSubFeature++) {
			if (pFeature->index == pSubFeature->feature) {
				for (i = 0; i < ftListLen; i++) {
					ftEntry = json_object_array_get_idx(ftListObj, i);

					if (!strcmp(pSubFeature->name, json_object_get_string(ftEntry))) {

						for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
							if (skip_param_mapping(pParam->param, (cm_ctrlBlock.role == IS_SERVER) ? SKIP_SERVER : SKIP_CLIENT)) {
								DBG_INFO("*** skip_param_mapping(%s, %d) !! ***", pParam->param, (cm_ctrlBlock.role == IS_SERVER) ? SKIP_SERVER : SKIP_CLIENT);
								continue;
							}
#ifdef SUPPORT_TRI_BAND
#if defined(RTCONFIG_WIFI_SON)
							if(!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
							sscanf(pParam->param, "wl1_%s", suffix);
#endif
							if (pSubFeature->index == pParam->subfeature) {
								memset(check_param_name, 0, sizeof(check_param_name));
								if (!cfgAllObj && fileRoot) { /* need to check param in fileRoot */								
#ifdef SUPPORT_TRI_BAND
									if(!ignore_5g2_to_5g1(pParam->param) && strstr(pParam->param,"wl1_")&&!client_5g1
#if defined(RTCONFIG_WIFI_SON)
        								 && !nvram_match("wifison_ready", "1")
#endif
									)
									{
										memset(new_param, 0, sizeof(new_param));
										snprintf(new_param, sizeof(new_param), "wl%d_%s", check_own_unit(2), suffix);
										json_object_object_get_ex(fileRoot, new_param, &changedParam);
										if (strncmp(new_param, "wl", 2) == 0)
										{
											memset(finalparamname, 0, sizeof(finalparamname));
											cap_get_re_final_paramname(uniqueMac, new_param,reBandNum,finalparamname, sizeof(finalparamname));
											if(strlen(finalparamname) && supportedIndexVersion>1)
											{
												snprintf(check_param_name, 256, "%s", finalparamname);
											}
											else{
												snprintf(check_param_name, 256, "%s", pParam->param);
											}
										
										}
										else{
											snprintf(check_param_name, 256, "%s", pParam->param);
										}	
									}
									else
									{
										json_object_object_get_ex(fileRoot, pParam->param, &changedParam);
										if (strncmp(pParam->param, "wl", 2) == 0)
										{
											memset(finalparamname, 0, sizeof(finalparamname));
											cap_get_re_final_paramname(uniqueMac, pParam->param,reBandNum,finalparamname, sizeof(finalparamname));
											if(strlen(finalparamname) && supportedIndexVersion>1)
											{
												snprintf(check_param_name, 256, "%s", finalparamname);
											}
											else{
												snprintf(check_param_name, 256, "%s", pParam->param);
											}
										
										}
										else{
												snprintf(check_param_name, 256, "%s", pParam->param);
											}
									}
#else
									json_object_object_get_ex(fileRoot, pParam->param, &changedParam);
									if (strncmp(pParam->param, "wl", 2) == 0)
									{
										memset(finalparamname, 0, sizeof(finalparamname));
										cap_get_re_final_paramname(uniqueMac, pParam->param,reBandNum,finalparamname, sizeof(finalparamname));
										if(strlen(finalparamname) && supportedIndexVersion>1)
										{
											snprintf(check_param_name, 256, "%s", finalparamname);
										}
										else{
												snprintf(check_param_name, 256, "%s", pParam->param);
											}
									
									}
									else{
											snprintf(check_param_name, 256, "%s", pParam->param);
									}
#endif
									
									if (changedParam == NULL)
										continue;
								}
								else {
									
									snprintf(check_param_name, 256, "%s", pParam->param);
								}

								if (!paramObj)
									paramObj = json_object_new_object();

								if (paramObj) {
									memset(outAuth, 0, sizeof(outAuth));
									memset(finalparamname, 0, sizeof(finalparamname));

#ifdef SUPPORT_TRI_BAND
									if(!ignore_5g2_to_5g1(check_param_name) && !client_5g1 && strstr(check_param_name,"wl1_")
#if defined(RTCONFIG_WIFI_SON)
        								  && !nvram_match("wifison_ready", "1")
#endif
									)
									{
										memset(suffix, 0, sizeof(suffix));
										sscanf(pParam->param, "wl1_%s", suffix);
										memset(new_param, 0, sizeof(new_param));
										snprintf(new_param, sizeof(new_param), "wl%d_%s", check_own_unit(2), suffix);
										if (strncmp(check_param_name, "wl", 2) == 0 && strstr(check_param_name, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
											&& !nvram_match("wifison_ready", "1")
#endif
										) {
											if (cm_checkWifiAuthCap(uniqueMac, supportedBandNum, reBandNum, 0, check_param_name, outAuth, sizeof(outAuth))) {
												json_object_object_add(paramObj, check_param_name,
													json_object_new_string(private ? "" : outAuth));
											}
											else
												json_object_object_add(paramObj, check_param_name,
													json_object_new_string(private ? "" : nvram_safe_get(new_param)));
										}
										else
										{
											if (private || nvram_get(new_param))
												json_object_object_add(paramObj, check_param_name,
													json_object_new_string(private ? "" : nvram_safe_get(new_param)));
										}
									}
									else
									{
										if (private || nvram_get(check_param_name))
										{
											if (strncmp(check_param_name, "wl", 2) == 0 && strstr(check_param_name, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
												&& !nvram_match("wifison_ready", "1")
#endif
											) {
												if (cm_checkWifiAuthCap(uniqueMac, supportedBandNum, reBandNum, 0, check_param_name, outAuth, sizeof(outAuth))) {
													json_object_object_add(paramObj, check_param_name,
														json_object_new_string(private ? "" : outAuth));
												}
												else
													json_object_object_add(paramObj, check_param_name,
														json_object_new_string(private ? "" : nvram_decrypt_get(cap_get_final_paramname(uniqueMac, check_param_name,reBandNum,finalparamname, sizeof(finalparamname)))));
											}
											else
											{
												json_object_object_add(paramObj, check_param_name,
													json_object_new_string(private ? "" : nvram_decrypt_get(cap_get_final_paramname(uniqueMac, check_param_name,reBandNum,finalparamname, sizeof(finalparamname)))));		
											}
										}
									}
#else
									if (private || nvram_get(check_param_name))
									{
										if (strncmp(check_param_name, "wl", 2) == 0 && strstr(check_param_name, "auth_mode_x")
#if defined(RTCONFIG_WIFI_SON)
											&& !nvram_match("wifison_ready", "1")
#endif
										) {
											if (cm_checkWifiAuthCap(uniqueMac, supportedBandNum, reBandNum, 0, check_param_name, outAuth, sizeof(outAuth))) {
												json_object_object_add(paramObj, check_param_name,
													json_object_new_string(private ? "" : outAuth));
											}
											else
												json_object_object_add(paramObj, check_param_name,
													json_object_new_string(private ? "" : nvram_decrypt_get(cap_get_final_paramname(uniqueMac, check_param_name,reBandNum,finalparamname, sizeof(finalparamname)))));
										}
										else
										{
											json_object_object_add(paramObj, check_param_name,
												json_object_new_string(private ? "" : nvram_decrypt_get(cap_get_final_paramname(uniqueMac, check_param_name,reBandNum,finalparamname, sizeof(finalparamname)))));
										}
									}
#endif
									// bsd_if_select_policy & bsd_if_select_policy_x
									if (strstr(check_param_name, "bsd_if_select_policy"))
									{
										DBG_INFO("** Process SMART_CONNECT_RULE START !! **");
										if ((ss = wl_ifnames_to_ifindex(nvram_safe_get(check_param_name), NULL)) != NULL)
										{
											memset(s, 0, sizeof(s));
											snprintf(s, sizeof(s)-1, "%s_idx", check_param_name);
											json_object_object_add(paramObj, s, json_object_new_string(private ? "" : ss));
											DBG_INFO("json_object_object_add(%s:%s)", s, (private) ? "" : ss);
											json_object_object_del(paramObj, check_param_name);
											DBG_INFO("json_object_object_del(%s)", cap_get_final_paramname(uniqueMac, check_param_name,reBandNum,finalparamname, sizeof(finalparamname)));
											free(ss);
										}
										DBG_INFO("** Process SMART_CONNECT_RULE END !! **");
									}
									// amas_eap_bhmode changed
									if (strstr(check_param_name, "amas_eap_bhmode")) {
										amas_eap_bhmode_changed = 1;
									}
									// smart_connect_x, mode changed
									if (strstr(check_param_name, "smart_connect_x")) {
										smart_connect_x_changed = 1;
									}
#if defined(RTCONFIG_AMAS_WGN)
									if (strstr(check_param_name, "vlan_rulelist"))
									{
										if (guestNetworkNo2g <= 0 &&
											guestNetworkNo5g <= 0 &&
											guestNetworkNo5gH <= 0 &&
											guestNetworkNo6g <= 0)
										{
											json_object_object_del(paramObj, check_param_name);
										}
									}

									if (strncmp(check_param_name, "wl", 2) == 0)
									{
										unit = subunit = -1;
										sscanf(check_param_name, "wl%d.%d_%*s", &unit, &subunit);
										if (unit > -1 && subunit > 0)
										{

#ifdef RTCONFIG_BANDINDEX_NEW
											band_type = -1;
											guestNetworkNo = 0;
											memset(re_band_type, 0, sizeof(re_band_type));
											if(get_rebandtype_chanspc_by_unit(uniqueMac, unit,reBandNum,re_band_type,sizeof(re_band_type))!=NULL){
												if (strcmp(re_band_type, "2G")==0) {
													band_type = WGN_WL_BAND_2G;
													guestNetworkNo = guestNetworkNo2g;
												}
												else if (strcmp(re_band_type, "5G")==0) {
													band_type = WGN_WL_BAND_5G;
													guestNetworkNo = guestNetworkNo5g;
												}
												else if (strcmp(re_band_type, "5G1")==0) {
													band_type = WGN_WL_BAND_5GH;
													guestNetworkNo = guestNetworkNo5gH;
												}
												else if (strcmp(re_band_type, "6G")==0) {
													band_type = WGN_WL_BAND_6G;
													guestNetworkNo = guestNetworkNo6g;
												}
												else {
													band_type = -1;
													guestNetworkNo = 0;	
												}

												memset(guest_ifnames, 0, sizeof(guest_ifnames));
												if (guestNetworkNo <= 0 || wgn_guest_ifnames(wgn_get_unit_by_band(band_type), guestNetworkNo, guest_ifnames, sizeof(guest_ifnames)-1)==NULL) {
													json_object_object_del(paramObj, check_param_name);
												}
											}

#else 	// RTCONFIG_BANDINDEX_NEW
											guestNetworkNo = 0;
											memset(guest_ifnames, 0, sizeof(guest_ifnames));
											switch (unit) {
												case 0: // 2G
													if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_2G), guestNetworkNo2g, guest_ifnames, sizeof(guest_ifnames)-1) && strlen(guest_ifnames) > 0) 
														guestNetworkNo = guestNetworkNo2g;
													else 
														guestNetworkNo = 0;
													break;
												case 1: // 5G
													if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_5G), guestNetworkNo5g, guest_ifnames, sizeof(guest_ifnames)-1) && strlen(guest_ifnames) > 0) 
														guestNetworkNo = guestNetworkNo5g;
													else 
														guestNetworkNo = 0;
													break;
												case 2: // 5G1 or 6G
													if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_5GH), guestNetworkNo5gH, guest_ifnames, sizeof(guest_ifnames)-1) && strlen(guest_ifnames) > 0) 
														guestNetworkNo = guestNetworkNo5gH;
													else 
														guestNetworkNo = 0;
													if (guestNetworkNo <= 0) {							
														if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_6G), guestNetworkNo6g, guest_ifnames, sizeof(guest_ifnames)-1) && strlen(guest_ifnames) > 0) 
															guestNetworkNo = guestNetworkNo6g;
														else 
															guestNetworkNo = 0;
													}
													break;
												default:
													guestNetworkNo = 0;
													break;
											}

											if (guestNetworkNo > 0)
											{
												isfind = 0;
												memset(guest_ifnames, 0, sizeof(guest_ifnames));
												if (wgn_guest_ifnames(unit, guestNetworkNo, guest_ifnames, sizeof(guest_ifnames)-1))
												{
													foreach(word, guest_ifnames, next)
													{
														if (strncmp(check_param_name, word, strlen(word)) == 0)
														{
															isfind = 1;
															break;
														}
													}
												}

												if (!isfind)
													json_object_object_del(paramObj, check_param_name);

											}
											else {
												json_object_object_del(paramObj, check_param_name);
											}
#endif 	// RTCONFIG_BANDINDEX_NEW
										}
									}									
#endif	/* RTCONFIG_AMAS_WGN */
								
								}
							}
							
						}
					}

				}
			}
		}

		if (paramObj) {
			if (pFeature->service
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
				&& !private
#endif
			)
				json_object_object_add(paramObj, CFG_ACTION_SCRIPT,
					json_object_new_string(pFeature->service));
			json_object_object_add(outRoot, pFeature->name, paramObj);
		}
	}

	if (amas_eap_bhmode_changed == 1 || smart_connect_x_changed == 1) {  // add smart connect config to json.
		int found = 0;
		int new_obj;
		json_object *feature_name_Obj = NULL;
		for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
			if (strcmp(pParam->param, "smart_connect_x") == 0) {
				for (pFeature = &feature_mapping_list[0]; pFeature->index != 0; pFeature++) {
					if (pFeature->index == pParam->feature) {
						found = 1;
						break;
					}
				}
			}
			if (found == 1)
				break;
		}

		if (found == 1) {
			json_object_object_get_ex(outRoot, pFeature->name, &feature_name_Obj);
			if (!feature_name_Obj) {
				feature_name_Obj = json_object_new_object();
				new_obj = 1;
			} else {
				new_obj = 0;
			}
		}

		if (feature_name_Obj) {
			if (amas_eap_bhmode_changed == 1 && smart_connect_x_changed == 0)  // add smart_connect_x
				json_object_object_add(feature_name_Obj, "smart_connect_x", json_object_new_int(nvram_get_int("smart_connect_x")));
			DBG_INFO("** Process SMART_CONNECT_RULE START !! **");
			switch (nvram_get_int("smart_connect_x")) {
				case 0:  // none
					break;
				case 1:  // Tri-Band smart connect
				case 3:  // Dual-Band smart connect
					// bsd_steering_policy
					json_object_object_add(feature_name_Obj, "wl0_bsd_steering_policy", json_object_new_string(private ? "" : nvram_safe_get("wl0_bsd_steering_policy")));
					json_object_object_add(feature_name_Obj, "wl1_bsd_steering_policy", json_object_new_string(private ? "" : nvram_safe_get("wl1_bsd_steering_policy")));
					// bsd_sta_select_policy
					json_object_object_add(feature_name_Obj, "wl0_bsd_sta_select_policy", json_object_new_string(private ? "" : nvram_safe_get("wl0_bsd_sta_select_policy")));
					json_object_object_add(feature_name_Obj, "wl1_bsd_sta_select_policy", json_object_new_string(private ? "" : nvram_safe_get("wl1_bsd_sta_select_policy")));
					// bsd_if_select_policy
					if ((ss = wl_ifnames_to_ifindex(nvram_safe_get("wl0_bsd_if_select_policy"), NULL)) != NULL) {
						json_object_object_add(feature_name_Obj, "wl0_bsd_if_select_policy_idx", json_object_new_string(private ? "" : ss));
						free(ss);
					}
					if ((ss = wl_ifnames_to_ifindex(nvram_safe_get("wl1_bsd_if_select_policy"), NULL)) != NULL) {
						json_object_object_add(feature_name_Obj, "wl1_bsd_if_select_policy_idx", json_object_new_string(private ? "" : ss));
						free(ss);
					}
					// bsd_if_qualify_policy
					json_object_object_add(feature_name_Obj, "wl0_bsd_if_qualify_policy", json_object_new_string(private ? "" : nvram_safe_get("wl0_bsd_if_qualify_policy")));
					json_object_object_add(feature_name_Obj, "wl1_bsd_if_qualify_policy", json_object_new_string(private ? "" : nvram_safe_get("wl1_bsd_if_qualify_policy")));
					// bsd_bounce_detect
					json_object_object_add(feature_name_Obj, "bsd_bounce_detect", json_object_new_string(private ? "" : nvram_safe_get("bsd_bounce_detect")));

	#ifdef SUPPORT_TRI_BAND
	#if defined(RTCONFIG_WIFI_SON)
					if (!nvram_match("wifison_ready", "1"))
	#endif /* WIFI_SON */
					{
						// bsd_steering_policy
						json_object_object_add(feature_name_Obj, "wl2_bsd_steering_policy", json_object_new_string(private ? "" : nvram_safe_get("wl2_bsd_steering_policy")));
						// bsd_sta_select_policy
						json_object_object_add(feature_name_Obj, "wl2_bsd_sta_select_policy", json_object_new_string(private ? "" : nvram_safe_get("wl2_bsd_sta_select_policy")));
						// bsd_if_select_policy
						if ((ss = wl_ifnames_to_ifindex(nvram_safe_get("wl2_bsd_if_select_policy"), NULL)) != NULL) {
							json_object_object_add(feature_name_Obj, "wl2_bsd_if_select_policy_idx", json_object_new_string(private ? "" : ss));
							free(ss);
						}
						// bsd_if_qualify_policy
						json_object_object_add(feature_name_Obj, "wl2_bsd_if_qualify_policy", json_object_new_string(private ? "" : nvram_safe_get("wl2_bsd_if_qualify_policy")));
					} /* !wifison_ready */
	#endif                // SUPPORT_TRI_BAND
					break;
				case 2:  // 5GHz smart connect
	#ifdef SUPPORT_TRI_BAND
	#if defined(RTCONFIG_WIFI_SON)
					if (!nvram_match("wifison_ready", "1"))
	#endif /* WIFI_SON */
					{
						// bsd_steering_policy_x
						json_object_object_add(feature_name_Obj, "wl1_bsd_steering_policy_x", json_object_new_string(private ? "" : nvram_safe_get("wl1_bsd_steering_policy_x")));
						json_object_object_add(feature_name_Obj, "wl2_bsd_steering_policy_x", json_object_new_string(private ? "" : nvram_safe_get("wl2_bsd_steering_policy_x")));
						// bsd_sta_select_policy_x
						json_object_object_add(feature_name_Obj, "wl1_bsd_sta_select_policy_x", json_object_new_string(private ? "" : nvram_safe_get("wl1_bsd_sta_select_policy_x")));
						json_object_object_add(feature_name_Obj, "wl2_bsd_sta_select_policy_x", json_object_new_string(private ? "" : nvram_safe_get("wl2_bsd_sta_select_policy_x")));
						// bsd_if_select_policy_x
						if ((ss = wl_ifnames_to_ifindex(nvram_safe_get("wl1_bsd_if_select_policy_x"), NULL)) != NULL) {
							json_object_object_add(feature_name_Obj, "wl1_bsd_if_select_policy_x_idx", json_object_new_string(private ? "" : ss));
							free(ss);
						}
						if ((ss = wl_ifnames_to_ifindex(nvram_safe_get("wl2_bsd_if_select_policy_x"), NULL)) != NULL) {
							json_object_object_add(feature_name_Obj, "wl2_bsd_if_select_policy_x_idx", json_object_new_string(private ? "" : ss));
							free(ss);
						}
						// bsd_if_qualify_policy_x
						json_object_object_add(feature_name_Obj, "wl1_bsd_if_qualify_policy_x", json_object_new_string(private ? "" : nvram_safe_get("wl1_bsd_if_qualify_policy_x")));
						json_object_object_add(feature_name_Obj, "wl2_bsd_if_qualify_policy_x", json_object_new_string(private ? "" : nvram_safe_get("wl2_bsd_if_qualify_policy_x")));
						// bsd_bounce_detect_x
						json_object_object_add(feature_name_Obj, "bsd_bounce_detect_x", json_object_new_string(private ? "" : nvram_safe_get("bsd_bounce_detect_x")));
					} /* !wifison_ready */
	#endif                // 	SUPPORT_TRI_BAND
					break;
			}
			if (pFeature->service && (amas_eap_bhmode_changed == 1 && smart_connect_x_changed == 0))  // add action_script
				json_object_object_add(feature_name_Obj, "action_script", json_object_new_string(pFeature->service));
			if (new_obj)
				json_object_object_add(outRoot, pFeature->name, feature_name_Obj);
		}

	}
#ifdef RTCONFIG_BANDINDEX_NEW
	if(cfgband_Ver>1 ){
		json_object_object_get_ex(outRoot, "wireless", &cfgWireless);
		if(cfgWireless==NULL){
			if (!cfgAllObj && fileRoot && num_of_wl_if()>reBandNum) { 
				cfgWireless = json_object_new_object();
				json_object_object_add(outRoot, "wireless", cfgWireless);
			}
		}
		if(cfgWireless!=NULL && !private){
				Add_missing_parameter(cfgWireless, private,uniqueMac,reBandNum,cfgband_Ver,cfgAllObj,fileRoot);
			}
	}
	else if(cfgband_Ver<2)
	{
	
		json_object_object_get_ex(outRoot, "wireless", &cfgWireless);

		if(cfgWireless==NULL){
			if (!cfgAllObj && fileRoot && num_of_wl_if()>reBandNum) { 
				cfgWireless = json_object_new_object();
				json_object_object_add(outRoot, "wireless", cfgWireless);
			}
		}
			
		if(cfgWireless!=NULL && !private){
				Add_missing_parameter_patch(cfgWireless, private,uniqueMac,reBandNum,cfgband_Ver,cfgAllObj,fileRoot);
			}
	
	}
#endif
	json_object_put(fileRoot);

#if defined(RTCONFIG_AMAS_WGN)	
	if (capabilityObj) json_object_put(capabilityObj);
#endif	// RTCONFIG_AMAS_WGN	

	DBG_INFO("leave");
} /* End of cm_transformCfgParam */

/*
========================================================================
Routine Description:
	Callback for report wireless event.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportWeventEvent(struct sched *sched)
{
	unsigned char msg[MAX_PACKET_SIZE] = {0};
#ifdef DUAL_BAND_DETECTION
	json_object *dualBandObj = NULL;
#endif

	pthread_mutex_lock(&weventLock);
	if (cm_prepareWeventMsg((char *)&msg[0], MAX_MESSAGE_SIZE) == 0) {
		//DBG_INFO("no contenet of wireless event");
		pthread_mutex_unlock(&weventLock);
		goto err;
	}
	unlink(WCLIENT_LIST_JSON_PATH);
	pthread_mutex_unlock(&weventLock);

#ifdef DUAL_BAND_DETECTION
	if (cm_processWevent((char *)msg)) {
		memset(msg, 0, sizeof(msg));

		if (cm_prepareDualBandListMsg(msg, MAX_PACKET_SIZE)) {
			if ((dualBandObj = json_tokener_parse(msg)) != NULL) {
				cm_sendNotificationByType(NOTIFY_UPDATEDBLIST, dualBandObj);
				json_object_put(dualBandObj);
			}
		}
	}
#else
	cm_processWevent((char *)msg);
#endif

err:

	scWeventReport.timeout = current_time() + REPORT_WEVENT_INTERVAL;
} /* End of cm_reportWeventEvent */

/*
========================================================================
Routine Description:
	Callback for report wireless client list.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportStalistEvent(struct sched *sched)
{
	unsigned char msgBuf[MAX_MESSAGE_SIZE] = {0};

	// check have the content of wireless event
	if (cm_prepareStaListMsg((char *)&msgBuf[0], MAX_MESSAGE_SIZE) == 0) {
		DBG_INFO("no contenet of sta list");
		goto err;
	}

	cm_processStaList((char *)msgBuf);

err:

	scStaListReport.timeout = current_time() + REPORT_STALIST_INTERVAL;
} /* End of cm_reportStalistEvent */

/*
========================================================================
Routine Description:
	Callback for report all client list include wireless and wired client.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_reportClientlistEvent(struct sched *sched)
{
	unsigned char msgBuf[MAX_MESSAGE_SIZE] = {0};

	// check have the content of client list
	if (cm_prepareClientListMsg((char *)&msgBuf[0], MAX_MESSAGE_SIZE) == 0) {
		DBG_INFO("no contenet of client list");
		goto err;
	}

	cm_processClientList((char *)msgBuf);

err:

	scClientListReport.timeout = current_time() + REPORT_CLIENTLIST_INTERVAL;
} /* End of cm_reportClientlistEvent */

/*
========================================================================
Routine Description:
	Callback for check group key.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkGroupKeyEvent(struct sched *sched)
{
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	DBG_INFO("gKeyTime(%d), gKey1Time(%d), groupKeyExpireTime(%d), rekeyTime(%d)",
			gKeyTime, gKey1Time , groupKeyExpireTime, REKEY_TIME(groupKeyExpireTime));

	/* check key ready */
	if (!cm_ctrlBlock.groupKeyReady)
		goto err;

	/* check session key whether do rekey */
	if ((gKeyTime >= REKEY_TIME(groupKeyExpireTime) &&
		gKeyTime <= groupKeyExpireTime &&
		gKey1Time >= groupKeyExpireTime) ||
		(gKey1Time >= REKEY_TIME(groupKeyExpireTime) &&
		gKey1Time <= groupKeyExpireTime &&
		gKeyTime >= groupKeyExpireTime)) {
		unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
		cm_prepareGroupKey((char *)&msgBuf[0], MAX_MESSAGE_SIZE, 1);
	}

err:

	scGroupKeyCheck.timeout = current_time() + CHECK_KEY_INTERVAL;
} /* End of cm_checkCfgEvent */

#ifdef RADAR_DET
/*
========================================================================
Routine Description:
	Callback for update wireless available channel.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_updateAvailableChannelEvent(struct sched *sched)
{
	char msg[MAX_CHANSPEC_BUFLEN] = {0};
	char ch_data[MAX_CH_DATA_BUFLEN] = {0};
	json_object *root = json_object_new_object();
	json_object *chanspecObj = NULL;

	if( root && chmgmt_get_chan_info(ch_data, sizeof(ch_data)) > 0 )
	{
		DBG_INFO("channel information updated");

		/* unique mac */
		json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));
		/* channel */
		json_object_object_add(root, CFG_STR_CHANNEL, json_object_new_string(ch_data));
		/* supported chanspec */
		chanspecObj = json_object_new_object();
		if (chanspecObj) {
			if (cm_getChanspec(chanspecObj, 0)) {
				json_object_object_add(root, CFG_STR_CHANSPEC, chanspecObj);
				json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			}
			else
				json_object_put(chanspecObj);
		}

		snprintf((char *)msg, sizeof(msg), "%s", json_object_get_string(root));
		DBG_INFO("msg(%s)", msg);

		cm_updateAvailableChannel(msg);
		cm_updateChanspec(msg);
		chmgmt_notify();
	}

	json_object_put(root);

	scAvailChannelUpdate.timeout = current_time() + UPDATE_AVAIL_CHANNEL_INTERVAL;
} /* End of cm_updateAvailableChannelEvent */
#endif /* RADAR_DET */

/*========================================================================
Routine Description:
	Filter client list for wired.

Arguments:
	brMac		- unique mac for identitfication
	allClientList		- all wired client list
	clientList		- online/offline client list
	filterClientList		- filterd online/offline client list
	type		- online (1)/ offline (0)

Return Value:
	None

Note:
========================================================================
*/
void cm_filterWiredClientList(char *brMac, json_object *allClientList, json_object *clientList, json_object *filterClientList, int type)
{
	int i = 0, j = 0, clientListLen = 0, filter = 0, offline = 0;
	json_object *brMacObj = NULL, *entryObj = NULL;
	char mac[18], rmac[18];

	if (clientList) {
		clientListLen = json_object_array_length(clientList);
		for (i = 0; i < clientListLen; i++) {
			entryObj = json_object_array_get_idx(clientList, i);
			if (entryObj) {
				filter = 0;
				memset(mac, 0, sizeof(mac));
				snprintf(mac, sizeof(mac), "%s", (char *)json_object_get_string(entryObj));

				/* filter amas devcies */
				if (strcmp(mac, get_unique_mac()) == 0 || cm_checkReListExist(mac)) {
					DBG_INFO("%s is an amas devcie, filter it.", mac);
					continue;
				}

				if (type == 1)	/* for online entry */
				{
					/* filter multiple devcies on different amas devcies */
					json_object_object_foreach(allClientList, key, val) {
						/* pass itself entry */
						if (strcmp(key, brMac) == 0) {
							//DBG_INFO("pass itself entry (%s)", key);
							continue;
						}

						brMacObj = val;

						/* pass offline entry */
						offline = 0;
						for (j = 1; j < p_client_tbl->count; j++) {
							memset(rmac, 0, sizeof(rmac));
							snprintf(rmac, sizeof(rmac), "%02X:%02X:%02X:%02X:%02X:%02X",
								p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
								p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
								p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

							if (strcmp(key, rmac) == 0 && !cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
								offline = 1;
								break;
							}
						}

						if (offline) {
							//DBG_INFO("pass offline entry (%s)", key);
							continue;
						}

						/* check exists in any entry */
						json_object_object_foreach(brMacObj, entry_key, entry_val) {
							if (strcmp(entry_key, mac) == 0) {
								//DBG_INFO("%s exists in %s, filter it", mac, key);
								filter = 1;
								break;
							}
						}
					}
				}
				else		/* for offline entry */
				{
					/* delete mac in other entry */
					json_object_object_foreach(allClientList, key, val) {
						/* pass itself entry */
						if (strcmp(key, brMac) == 0) {
							//DBG_INFO("pass itself entry (%s)", key);
							continue;
						}

						json_object_object_del(val, mac);
					}
				}

				if (filter == 0)
					json_object_array_add(filterClientList, json_object_new_string(mac));
			}
		}
	}
} /* End of cm_filterWiredClientList */

/*========================================================================
Routine Description:
	Process client list for wired.

Arguments:
	*msg	- client list
	*brMac	- bridge mac
	onlineListObj	- online list
	offlineListObj	- offline list

Return Value:
	None

Note:
========================================================================
*/
void cm_processWiredClientList(char *msg, char *brMac, json_object *onlineListObj, json_object *offlineListObj)
{
	json_object *clientListObj = json_tokener_parse(msg);
	int lock;
	json_object *fileRoot = NULL, *oldClientListObj = NULL, *entryObj = NULL;
	json_object *tmpOldClientListObj = NULL;
	json_object *tmpOnlineListObj = NULL, *tmpOfflineListObj = NULL, *tmpClientListObj = NULL, *wiredClientObj = NULL;
	int clientListLen = 0, oldClientListLen = 0, i = 0;
	time_t ts;

	time(&ts);

	if (!brMac) {
		DBG_ERR("brMac is NULL");
		return;
	}

	if (!clientListObj) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("brMac (%s), msg (%s)", brMac, msg);

	pthread_mutex_lock(&wiredClientListLock);
	lock = file_lock(WIREDCLIENTLIST_FILE_LOCK);

	fileRoot = json_object_from_file(WIRED_CLIENT_LIST_JSON_PATH);
	if (!fileRoot)
		fileRoot = json_object_new_object();

	tmpOnlineListObj = json_object_new_array();
	tmpOfflineListObj = json_object_new_array();

	if (fileRoot && tmpOnlineListObj && tmpOfflineListObj && onlineListObj && offlineListObj) {
		/* convert all old entry to array first */
		json_object_object_get_ex(fileRoot, brMac, &tmpOldClientListObj);
		if (tmpOldClientListObj) {
			oldClientListObj = json_object_new_array();
			if (oldClientListObj) {
				json_object_object_foreach(tmpOldClientListObj, key, val) {
					json_object_array_add(oldClientListObj, json_object_new_string(key));
				}
			}
		}

		/* record online & offline client */
		if (oldClientListObj) {
			oldClientListLen = json_object_array_length(oldClientListObj);
			if (oldClientListLen > 0) {
				if (clientListObj) {
					clientListLen = json_object_array_length(clientListObj);
					if (clientListLen > 0) {
						//offline
						for (i = 0; i < oldClientListLen; i++) {
							entryObj = json_object_array_get_idx(oldClientListObj, i);
							if (entryObj) {
								if (!search_in_array_list((char *)json_object_get_string(entryObj), clientListObj, clientListLen))
									json_object_array_add(tmpOfflineListObj, json_object_new_string(json_object_get_string(entryObj)));
							}
						}
						cm_filterWiredClientList(brMac, fileRoot, tmpOfflineListObj, offlineListObj, 0);

						//online
						for (i = 0; i < clientListLen; i++) {
							entryObj = json_object_array_get_idx(clientListObj, i);
							if (entryObj) {
								if (!search_in_array_list((char *)json_object_get_string(entryObj), oldClientListObj, oldClientListLen))
									json_object_array_add(tmpOnlineListObj, json_object_new_string(json_object_get_string(entryObj)));
							}
						}
						cm_filterWiredClientList(brMac, fileRoot, tmpOnlineListObj, onlineListObj, 1);
					}
					else
					{
						add_all_to_array_list(oldClientListObj, tmpOfflineListObj);	//offline
						cm_filterWiredClientList(brMac, fileRoot, tmpOfflineListObj, offlineListObj, 0);
					}
				}
				else
				{
					add_all_to_array_list(oldClientListObj, tmpOfflineListObj);	//offline
					cm_filterWiredClientList(brMac, fileRoot, tmpOfflineListObj, offlineListObj, 0);
				}
			}
			else
			{
				add_all_to_array_list(clientListObj, tmpOnlineListObj);	//online
				cm_filterWiredClientList(brMac, fileRoot, tmpOnlineListObj, onlineListObj, 1);
			}

			json_object_put(oldClientListObj);
		}
		else
		{
			add_all_to_array_list(clientListObj, tmpOnlineListObj);	//online
			cm_filterWiredClientList(brMac, fileRoot, tmpOnlineListObj, onlineListObj, 1);
		}

		/* update & filter wired client on differnt DUT */
		tmpClientListObj = json_object_new_object();
		if (tmpClientListObj) {
			json_object_object_del(fileRoot, brMac);
			clientListLen = json_object_array_length(clientListObj);
			for (i = 0; i < clientListLen; i++) {
				entryObj = json_object_array_get_idx(clientListObj, i);
				if (entryObj) {
					wiredClientObj = json_object_new_object();
					if (wiredClientObj) {
						json_object_object_add(wiredClientObj, CFG_STR_TIMESTAMP,
							json_object_new_int64(ts));
						json_object_object_add(tmpClientListObj, json_object_get_string(entryObj), wiredClientObj);
					}
				}
			}
			json_object_object_add(fileRoot, brMac, tmpClientListObj);

			/* write to file */
			json_object_to_file(WIRED_CLIENT_LIST_JSON_PATH, fileRoot);
		}
	}

	json_object_put(clientListObj);
	json_object_put(fileRoot);
	json_object_put(tmpOnlineListObj);
	json_object_put(tmpOfflineListObj);
	file_unlock(lock);
	pthread_mutex_unlock(&wiredClientListLock);
} /* End of cm_processWiredClientList */

/*
========================================================================
Routine Description:
	Callback for check wired client list.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkWiredClientListEvent(struct sched *sched)
{
	json_object *wiredClientList = NULL;
	json_object *onlineListObj = NULL, *offlineListObj = NULL;

	if ((wiredClientList = json_object_new_array()) != NULL) {
		if (cm_needUpdateWiredClientlLst(wiredClientList)) {
			if ((onlineListObj = json_object_new_array()) && (offlineListObj = json_object_new_array())) {
				cm_processWiredClientList((char *)json_object_to_json_string(wiredClientList), (char *)get_unique_mac(), onlineListObj, offlineListObj);
#ifdef RTCONFIG_NOTIFICATION_CENTER
				cm_notifyWiredClientEvent(onlineListObj, offlineListObj);
#endif
			}

			if (onlineListObj)
				json_object_put(onlineListObj);
			if (offlineListObj)
				json_object_put(offlineListObj);
		}
		json_object_put(wiredClientList);
	}

	scWiredClientListCheck.timeout = current_time() + CHECK_CLIENTLIST_INTERVAL;
} /* End of cm_checkWiredClientListEvent */

/*
========================================================================
Routine Description:
	Update the status of re join.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_updateReJoinStatus()
{
	int i = 0;
	int reJoin = 0;

	if (p_client_tbl->count > 1) {
		pthread_mutex_lock(&cfgLock);
		for (i = 1; i < p_client_tbl->count; i++) {
			if (cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
				reJoin = 1;
				break;
			}
		}
		pthread_mutex_unlock(&cfgLock);

		if (nvram_get_int("cfg_rejoin") != reJoin)
			nvram_set_int("cfg_rejoin", reJoin);
	}
} /* End of cm_updateReJoinStatus */

#ifdef STA_BIND_AP
/*
========================================================================
Routine Description:
	Update the status of re offline.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_updateReOfflineStatus()
{
	int i = 0;
	int reOffline = 0;

	if (p_client_tbl->count > 1) {
		/* record the status of RE offline */
		for (i = 1; i < p_client_tbl->count; i++) {
			if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
				if (p_client_tbl->online[i]) {
					reOffline = 1;
					break;
				}
			}
		}
	}

	if (reOffline) {
		if (cm_updateStaBindingAp(0, NULL)) {
			pthread_mutex_lock(&cfgLock);
			/* update the status of RE offline */
			for (i = 1; i < p_client_tbl->count; i++) {
				if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
					if (p_client_tbl->online[i])
						p_client_tbl->online[i] = 0;
				}
			}
			pthread_mutex_unlock(&cfgLock);
		}
		else
			DBG_ERR("update sta binding list failed");
	}
} /* End of cm_updateReOfflineStatus */
#endif /* STA_BIND_AP */

#ifdef RTCONFIG_NBR_RPT
/*
========================================================================
Routine Description:
	Update the status of re in neighbor list.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_updateReStatusInNbrList()
{
	int i = 0, online = 0;
	char mac[18] = {0};
	char nbrData[MAX_NBR_DATA_BUFLEN] = {0}, nbrDataMsg[MAX_NBR_DATA_BUFLEN] = {0};
	json_object *nbrRoot = NULL;

	/* update re status in nbr list */
	if (p_client_tbl->count > 1) {
		pthread_mutex_lock(&cfgLock);
		for (i = 1; i < p_client_tbl->count; i++) {
			online = 0;
			if (cm_isSlaveOnline(p_client_tbl->reportStartTime[i]))
				online = 1;

			snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

			cm_updateOnlineInNbrData(mac, online);
		}
		pthread_mutex_unlock(&cfgLock);
	}

	/* update nbr list if needed */
	if (cm_getNbrData(nbrData, sizeof(nbrData)) > 0) {
		DBG_INFO("update neighbor information");
		snprintf(nbrDataMsg, sizeof(nbrDataMsg), "{\"%s\":\"%s\",\"%s\":%s}",
			CFG_STR_MAC, (char *)get_unique_mac(), CFG_STR_NBR_DATA, nbrData);
		cm_updateNbrData(nbrDataMsg);
	}

	/* update private nbr list if needed */
	nbrRoot = json_object_new_object();
	if (nbrRoot) {
		snprintf(nbrDataMsg, sizeof(nbrDataMsg), "{\"%s\":\"%s\",\"%s\":\"%s\"}",
			CFG_STR_MAC, (char *)get_unique_mac(), CFG_STR_NBR_VERSION, nvram_safe_get("cfg_nbr_ver"));

		if (cm_prepareNbrList((unsigned char *)nbrDataMsg, nbrRoot))
			cm_updateNbrList((unsigned char *)json_object_get_string(nbrRoot));
		json_object_put(nbrRoot);
	}
	else
		DBG_ERR("nbrRoot is NULL");
} /* End of cm_updateReStatusInNbrList */
#endif

/*
========================================================================
Routine Description:
	Callback for check re status.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkReStatusEvent(struct sched *sched)
{
	cm_updateReJoinStatus();
#ifdef DUAL_BAND_DETECTION
	cm_checkDBListUpdated();
#endif
#ifdef STA_BIND_AP
	cm_updateReOfflineStatus();
#endif /* STA_BIND_AP */
#ifdef RTCONFIG_FRONTHAUL_DWB
	cm_updateBackhaulStatus();
#endif
#ifdef RTCONFIG_NBR_RPT
	cm_updateReStatusInNbrList();
#endif
	scReStatusCheck.timeout = current_time() + CHECK_RE_STATUS_INTERVAL;
} /* End of cm_checkReStatusEvent */


#ifdef RTCONFIG_BHCOST_OPT
/*
========================================================================
Routine Description:
	Search the valid and oldest RE join time.

Arguments:
	nowUpTime		- up time now

Return Value:
	0		- no update
	1		- update

Note:
========================================================================
*/
int cm_searchValidReJoinTime(unsigned nowUpTime)
{
	int i = 0, update = 0;
	char mac[18] = {0};
	unsigned int minJoinTime = 0, nowPassTime = 0;

	if (nowUpTime <= 0) {
		DBG_ERR("invalid nowUpTime (%d)", nowUpTime);
		return 0;
	}

	nowPassTime = nowUpTime - intervalCheckSelfOpt;
	DBG_INFO("nowUpTime (%d), nowPassTime (%d)", nowUpTime, nowPassTime);

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		if (p_client_tbl->joinTime[i] > 0 && p_client_tbl->joinTime[i] <= nowUpTime)
		{
			if ((minJoinTime == 0 || (p_client_tbl->joinTime[i] < minJoinTime)) &&
				(p_client_tbl->joinTime[i] > nowPassTime))
			{
				minJoinTime =  p_client_tbl->joinTime[i];
				snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

				DBG_LOG("search re (%s), join time (%d)", mac, minJoinTime);
				update = 1;
			}
			else if ( p_client_tbl->joinTime[i] <= nowPassTime)
			{
				DBG_LOG("re (%02X:%02X:%02X:%02X:%02X:%02X) join time (%d) doesn't match time interval (%d - %d)",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5],
					p_client_tbl->joinTime[i], nowPassTime, nowUpTime);
				p_client_tbl->joinTime[i] = 0;
			}
		}
	}

	if (update) {
		reJoinTime = minJoinTime;
		strlcpy(reJoinMac, mac, sizeof(reJoinMac));
		DBG_LOG("reJoinMac (%s), reJoinTime (%d)", reJoinMac, reJoinTime);
	}
	pthread_mutex_unlock(&cfgLock);

	return update;
} /* End of cm_searchOldestReJoinTime */

/*
========================================================================
Routine Description:
	Trigger RE do self optimization when its join time match time interval

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_triggerReSelfOpt()
{
	int i = 0, j = 0;
	int rssiThres5g = (nvram_get("cfg_rssi5g")) ? nvram_get_int("cfg_rssi5g"): RSSI_THRESHOLD_5G;
	char mac[18] = {0}, ip[18] = {0};
	unsigned int reJoinMaxTime =  0;
	hash_elem_t* e = NULL;
	int rePath = 0, wiredPath = ETH | ETH_2 | ETH_3 | ETH_4;

	if (strlen(reJoinMac) == 0) {
		DBG_ERR("reJoinMac is empty");
		return;
	}

	if (reJoinTime == 0) {
		DBG_ERR("reJoinTime is equal to 0");
		return;
	}

	reJoinMaxTime =  reJoinTime +  intervalCheckSelfOpt;

	DBG_LOG("reJoinTime(%d), reJoinMaxTime(%d)",  reJoinTime, reJoinMaxTime);

	pthread_mutex_lock(&cfgLock);
	for (i = p_client_tbl->maxLevel; i >= 0; i--) {
		for (j = 1; j < p_client_tbl->count; j++) {
			/* different level, pass it */
			if (p_client_tbl->level[j] != i)
				continue;

			snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
				p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
				p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
				p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
				p_client_tbl->ipAddr[j][3]);

			/* smae as joined mac */
			if (strcmp(reJoinMac, mac) == 0) {
				DBG_LOG("mac (%s) is same as reJoinMac, pass", mac);
				p_client_tbl->joinTime[j] = 0;
				continue;
			}

			/* check for re wired backhaul */
			rePath = p_client_tbl->activePath[j];
			DBG_LOG("re (%s, %s) rePath & wiredPath(%X)", mac, ip, (rePath & wiredPath));
			if (rePath & wiredPath)
			{
				DBG_LOG("re (%s) is under wired backhaul, pass", mac);
				p_client_tbl->joinTime[j] = 0;
				continue;
			}

			if (p_client_tbl->joinTime[j] >= reJoinTime &&
				p_client_tbl->joinTime[j] <= reJoinMaxTime)
			{
				DBG_LOG("re (%s) join time (%d) match time interval (%d - %d)",
					mac, p_client_tbl->joinTime[j], reJoinTime, reJoinMaxTime);

				/* judgement for self optimization */
				DBG_LOG("%s [2g rssi (%d), 5g rssi (%d), threshold (%d)]",
					mac, p_client_tbl->rssi2g[j], p_client_tbl->rssi5g[j], rssiThres5g);

				if ((p_client_tbl->rssi2g[j] < 0 && p_client_tbl->rssi5g[j] == 0) ||
					(p_client_tbl->rssi5g[j] < rssiThres5g)) {
					DBG_LOG("notify re (%s) to do self optimization", mac);
					if ((e = ht_get(clientHashTable, mac, ip))) {
						DBG_LOG("found entry (%s) and send notification (%d)", mac, NOTIFY_SELF_OPTIMIZATION);
						if (!cm_sendNotification(e, NOTIFY_SELF_OPTIMIZATION, NULL))
							DBG_LOG("send notification (%d) to %s failed", NOTIFY_SELF_OPTIMIZATION, e->clientIP);
					}
				}
				p_client_tbl->joinTime[j] = 0;
			}
			else if  (p_client_tbl->joinTime[j] < reJoinTime)
			{
				DBG_LOG("re (%s) join time (%d) < reJoinTime (%d), reset it", mac, p_client_tbl->joinTime[j], reJoinTime);
				p_client_tbl->joinTime[j] = 0;
			}
		}
	}

	/* reset join mac and time */
	memset(reJoinMac, 0, sizeof(reJoinMac));
	reJoinTime = 0;

	pthread_mutex_unlock(&cfgLock);
} /* End of cm_triggerReSelfOpt */

/*
========================================================================
Routine Description:
	Callback for checking and triggering re do self optimization.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
static void cm_checkReSelfOptEvent(struct sched *sched)
{
	unsigned int nextCheckTime= intervalCheckSelfOpt;
	unsigned int nowUpTime = uptime();

	if (strlen(reJoinMac) == 0 && reJoinTime == 0) {
		if (cm_searchValidReJoinTime(nowUpTime)) {
			nextCheckTime = intervalCheckSelfOpt - (nowUpTime - reJoinTime);
			if (nextCheckTime < 0) {
				DBG_INFO("next check time (%d) < 0", nextCheckTime);
				nextCheckTime = intervalCheckSelfOpt;
				memset(reJoinMac, 0, sizeof(reJoinMac));
				reJoinTime = 0;
			}
		}
	}
	else if (strlen(reJoinMac) && reJoinTime > 0)
	{
		cm_triggerReSelfOpt();
	}

	DBG_INFO("next check time (%d)", nextCheckTime);

	scReSelfOptCheck.timeout = current_time() + nextCheckTime;
} /* End of cm_checkReSelfOptEvent */
#endif

/*
========================================================================
Routine Description:
	Timer for differnt event.

Arguments:
	*args		- argument for thread

Return Value:
	None

Note:
========================================================================
*/
void *cm_eventTimer(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif
	pthread_detach(pthread_self());

	DBG_INFO("enter");

	/* register scheduler for report wireless event */
	scWeventReport.on_timeout = cm_reportWeventEvent;
	scWeventReport.timeout = current_time() + REPORT_WEVENT_INTERVAL;
	scWeventReport.name = "WeventReport";
	add_sched(&scWeventReport);

	/* register scheduler for reporting sta list */
	scStaListReport.on_timeout = cm_reportStalistEvent;
	scStaListReport.timeout = current_time() + REPORT_STALIST_INTERVAL;
	scStaListReport.name	= "StaListReport";
	add_sched(&scStaListReport);

	/* register scheduler for reporting client list */
	scClientListReport.on_timeout = cm_reportClientlistEvent;
	scClientListReport.timeout = current_time() + REPORT_CLIENTLIST_INTERVAL;
	scClientListReport.name	= "ClientListReport";
	add_sched(&scClientListReport);

#ifdef ROAMING_INFO
	/* register scheduler for checking roaming info */
	cm_registerRoamingInfoSch();
#endif

	/* register scheduler for checking group key */
	scGroupKeyCheck.on_timeout = cm_checkGroupKeyEvent;
	scGroupKeyCheck.timeout = current_time() + CHECK_KEY_INTERVAL;
	scGroupKeyCheck.name = "GroupKeyCheck";
	add_sched(&scGroupKeyCheck);

#ifdef RADAR_DET
#if defined(RTCONFIG_WIFI_SON)
	if (!nvram_match("wifison_ready","1"))
#endif
	{
	/* register scheduler for update availabe channel */
	scAvailChannelUpdate.on_timeout = cm_updateAvailableChannelEvent;
	scAvailChannelUpdate.timeout = current_time() + UPDATE_AVAIL_CHANNEL_INTERVAL;
	scAvailChannelUpdate.name = "AvailChannelUpdate";
	add_sched(&scAvailChannelUpdate);
	} /* !wifison_ready */
#endif /* RADAR_DET */

	/* register scheduler for checking wired client list */
	scWiredClientListCheck.on_timeout = cm_checkWiredClientListEvent;
	scWiredClientListCheck.timeout = current_time() + CHECK_CLIENTLIST_INTERVAL;
	scWiredClientListCheck.name	= "WiredClientListCheck";
	add_sched(&scWiredClientListCheck);

	/* register scheduler for checking RE status */
	scReStatusCheck.on_timeout = cm_checkReStatusEvent;
	scReStatusCheck.timeout = current_time() + CHECK_RE_STATUS_INTERVAL;
	scReStatusCheck.name = "ReStatusCheck";
	add_sched(&scReStatusCheck);

#ifdef RTCONFIG_BHCOST_OPT
	/* register scheduler for triggering RE do self optimization */
	intervalCheckSelfOpt = nvram_get_int("cfg_tcso") > 0 ? nvram_get_int("cfg_tcso") : CHECK_RE_SELF_OPT_INTERVAL;
	scReSelfOptCheck.on_timeout = cm_checkReSelfOptEvent;
	scReSelfOptCheck.timeout = current_time() + intervalCheckSelfOpt;
	scReSelfOptCheck.name = "ReSelfOptCheck";
	add_sched(&scReSelfOptCheck);
#endif

	start_sched();

	DBG_INFO("leave");

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_eventTimer */

/*
========================================================================
Routine Description:
	Prepare return date for RE join.

Arguments:
	mac		- mac
	decryptedMsg		- decrypted message
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareJoinReturnData(char *mac, unsigned char *decryptedMsg, char *msg, int msgLen)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *outRoot = NULL;
	json_object *cfgRoot = NULL;
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	char cfgTmpPath[64] = {0}, cfgMntPath[64] = {0};
	json_object *cfgTmpObj = NULL, *cfgObj = NULL, *ftObj = NULL, *paramObj = NULL, *ftTmpObj = NULL;
	json_object *cfgArrayObj = NULL;
	int cfgUpdate = 0, paramUpdate = 0;
#endif

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return 0;
	}

	cfgRoot = json_object_new_object();
	if (cfgRoot) {
		cm_transformCfgParam(decryptedRoot, cfgRoot, 1);
		outRoot = json_object_new_object();
		if (outRoot) {
			/* for private config */
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
			snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/%s.json", mac);
			snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", mac);

			if ((cfgTmpObj = json_object_from_file(cfgTmpPath))) {
				/* update for return private setting */
				cfgUpdate = 0;
				if ((cfgObj = json_object_new_object())) {
					/* add subfeature and config to cfgTmpObj based on cfgRoot */
					json_object_object_foreach(cfgRoot, ftKey, ftVal) {
						json_object_object_get_ex(cfgTmpObj, ftKey, &ftObj);
						if (!ftObj) {	/* add subfeature */
							paramUpdate = 0;
							if ((ftTmpObj = json_object_new_object())) {
								/* loop config and add to ftObj */
								json_object_object_foreach(ftVal, cfgKey, cfgVal) {
									json_object_object_add(ftTmpObj,
										cfgKey, json_object_new_string(json_object_get_string(cfgVal)));
									cfgUpdate = 1;
									paramUpdate = 1;
								}

								if (paramUpdate)
									json_object_object_add(cfgObj, ftKey, ftTmpObj);
								else
									json_object_put(ftTmpObj);
							}
						}
						else	/* add config in each subfeature */
						{
							paramUpdate = 0;
							if ((ftTmpObj = json_object_new_object())) {
								json_object_object_foreach(ftVal, cfgKey, cfgVal) {
									json_object_object_get_ex(ftObj, cfgKey, &paramObj);
									if (!paramObj) {
										json_object_object_add(ftTmpObj,
											cfgKey, json_object_new_string(json_object_get_string(cfgVal)));
										cfgUpdate = 1;
										paramUpdate = 1;
									}
								}

								if (paramUpdate)
									json_object_object_add(cfgObj, ftKey, ftTmpObj);
								else
									json_object_put(ftTmpObj);
							}
						}
					}
					if (cfgUpdate) {
						DBG_INFO("return private feature (%s) for mac(%s)",
								json_object_to_json_string_ext(cfgObj, 0), mac);
						json_object_object_add(outRoot, CFG_STR_PRIVATE_FEATURE, cfgObj);
					}
					else
					{
						json_object_put(cfgObj);
					}
				}

				/* update file for private config */
				cfgUpdate = 0;
				if ((cfgArrayObj = json_object_new_array())) {
					/* delete subfeature and config in cfgTmpObj based on cfgRoot */
					json_object_object_foreach(cfgTmpObj, cfgFtKey, cfgFtVal) {
						json_object_object_get_ex(cfgRoot, cfgFtKey, &ftObj);
						if (!ftObj) {	/* delete subfeature */
							json_object_object_get_ex(cfgTmpObj, cfgFtKey, &ftObj);
							if (ftObj) {
								json_object_object_foreach(ftObj, ftKey, ftVal) {
									json_object_array_add(cfgArrayObj, json_object_new_string(ftKey));
								}
							}
							json_object_object_del(cfgTmpObj, cfgFtKey);
							cfgUpdate = 1;
						}
						else /* delete config in each subfeature */
						{
							json_object_object_foreach(cfgFtVal, cfgKey, cfgVal) {
								json_object_object_get_ex(ftObj, cfgKey, &paramObj);
								if (!paramObj) {
									json_object_array_add(cfgArrayObj, json_object_new_string(cfgKey));
									json_object_object_del(cfgFtVal, cfgKey);
									cfgUpdate = 1;
								}
							}
						}
					}

					if (cfgUpdate) {
						DBG_INFO("update private config to tmp (%s) and mnt (%s) for mac(%s)", cfgTmpPath, cfgMntPath, mac);
						json_object_to_file(cfgTmpPath, cfgTmpObj);
						json_object_to_file(cfgMntPath, cfgTmpObj);
						DBG_INFO("update private rule for mac(%s)", mac);
						cm_updatePrivateRuleByMac(mac, cfgArrayObj, FOLLOW_RE, RULE_DEL);
					}
				}

				json_object_put(cfgRoot);
				json_object_put(cfgTmpObj);
				json_object_put(cfgArrayObj);
			}
			else
				json_object_object_add(outRoot, CFG_STR_PRIVATE_FEATURE, cfgRoot);
#else
			json_object_object_add(outRoot, CFG_STR_PRIVATE_FEATURE, cfgRoot);
#endif

#ifdef PRELINK
			/* for hash bundle key */
			if (nvram_get("amas_hashbdlkey") && strlen(nvram_safe_get("amas_hashbdlkey")))
				json_object_object_add(outRoot, CFG_STR_HASH_BUNDLE_KEY,
					json_object_new_string(nvram_safe_get("amas_hashbdlkey")));
#endif

			snprintf(msg, msgLen, "%s", (unsigned char *)json_object_to_json_string(outRoot));
			DBG_INFO("msg(%s)", msg);
		}
		else
		{
			json_object_put(cfgRoot);
			DBG_ERR("create json object failed");
		}
	}
	else
		DBG_ERR("create json object failed");

	json_object_put(outRoot);
	json_object_put(decryptedRoot);

	return strlen(msg);
} /* End of cm_handlePrivateFeature */

/*
========================================================================
Routine Description:
	Handle private cfg from slave.

Arguments:
	clientMac			- client mac for identification
	decryptedMsg		- decrypted message

Return Value:
	none

========================================================================
*/
static void cm_handlePrivateCfg(char *clientMac, unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *cfgRoot = NULL;
	char cfgTmpPath[64] = {0};
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	json_object *cfgTmpObj = NULL, *ftObj = NULL, *ftTmpObj = NULL, *paramObj = NULL;
	json_object *cfgObj = NULL, *cfgArrayObj = NULL;
	char cfgMntPath[64] = {0};
	int cfgUpdate = 0;
#endif

	json_object_object_get_ex(decryptedRoot, CFG_STR_PRIVATE_FEATURE, &cfgRoot);

	DBG_INFO("clientMac(%s), decryptedMsg(%s)", clientMac, decryptedMsg);

	if (strlen(clientMac)) {
		snprintf(cfgTmpPath, sizeof(cfgTmpPath), "/tmp/%s.json", clientMac);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		snprintf(cfgMntPath, sizeof(cfgMntPath), CFG_MNT_FOLDER"%s.json", clientMac);
#endif
	}

	if (decryptedRoot == NULL) {
		json_object_put(decryptedRoot);
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	if (cfgRoot) {
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		if (strlen(cfgTmpPath)) {
			if (!check_if_file_exist(cfgMntPath)) {
				if (strstr(nvram_safe_get("cfg_reoblist"), clientMac)) {
					DBG_INFO("sync common config to tmp (%s) for ob re (%s)", cfgTmpPath, clientMac);
					json_object_to_file(cfgTmpPath, cfgRoot);
					/* update rule */
					if ((cfgObj = json_object_new_array()) && cm_transformCfgToArray(cfgRoot, cfgObj)) {
						DBG_INFO("cfgObj (%s)", json_object_to_json_string_ext(cfgObj, 0));
						cm_updatePrivateRuleByMac(clientMac, cfgObj, FOLLOW_RE, RULE_ADD);
					}
					json_object_put(cfgObj);

					if (cm_syncCommonToPrivateConfigByMac(clientMac, NULL) == 0) {
						DBG_INFO("no update, sync common config to mnt (%s) for ob re (%s)", cfgMntPath, clientMac);
						json_object_to_file(cfgMntPath, cfgRoot);
					}
					cm_updateReObList(clientMac, RELIST_DEL, 1);
				}
				else
				{
					DBG_INFO("add private config to tmp (%s) & mnt (%s) for re",
						cfgTmpPath, cfgMntPath, clientMac);
					json_object_to_file(cfgTmpPath, cfgRoot);
					json_object_to_file(cfgMntPath, cfgRoot);
					/* update rule */
					if ((cfgObj = json_object_new_array()) && cm_transformCfgToArray(cfgRoot, cfgObj)) {
						DBG_INFO("cfgObj (%s)", json_object_to_json_string_ext(cfgObj, 0));
						cm_updatePrivateRuleByMac(clientMac, cfgObj, FOLLOW_RE, RULE_ADD);
					}
					json_object_put(cfgObj);
				}
			}
			else
			{
				if ((cfgTmpObj = json_object_from_file(cfgTmpPath)) && (cfgObj = json_object_new_object())
					&& (cfgArrayObj = json_object_new_array()))
				{
					/* add subfeature and config to cfgTmpObj based on cfgRoot */
					json_object_object_foreach(cfgRoot, ftKey, ftVal) {
						json_object_object_get_ex(cfgTmpObj, ftKey, &ftObj);
						if (!ftObj) {	/* add subfeature */
							if ((ftTmpObj = json_object_new_object())) {
								/* loop config and add to ftObj */
								json_object_object_foreach(ftVal, cfgKey, cfgVal) {
									json_object_object_add(ftTmpObj,
										cfgKey, json_object_new_string(json_object_get_string(cfgVal)));
									json_object_object_add(cfgObj,
										cfgKey, json_object_new_string(json_object_get_string(cfgVal)));
									json_object_array_add(cfgArrayObj, json_object_new_string(cfgKey));
								}

								json_object_object_add(cfgTmpObj, ftKey, ftTmpObj);
								cfgUpdate = 1;
							}
						}
						else	/* add config in each subfeature */
						{
							json_object_object_foreach(ftVal, cfgKey, cfgVal) {
								json_object_object_get_ex(ftObj, cfgKey, &paramObj);
								if (!paramObj) {
									json_object_object_add(ftObj,
										cfgKey, json_object_new_string(json_object_get_string(cfgVal)));
									json_object_object_add(cfgObj,
										cfgKey, json_object_new_string(json_object_get_string(cfgVal)));
									json_object_array_add(cfgArrayObj, json_object_new_string(cfgKey));
									cfgUpdate = 1;
								}
							}
						}
					}

					if (cfgUpdate) {
						DBG_INFO("update private config to tmp (%s) and mnt (%s)", cfgTmpPath, cfgMntPath);
						json_object_to_file(cfgTmpPath, cfgTmpObj);
						json_object_to_file(cfgMntPath, cfgTmpObj);
						cm_updatePrivateRuleByMac(clientMac, cfgArrayObj, FOLLOW_RE, RULE_ADD);
						cm_syncCommonToPrivateConfigByMac(clientMac, cfgObj);
					}
				}

				json_object_put(cfgTmpObj);
				json_object_put(cfgObj);
				json_object_put(cfgArrayObj);
			}
		}
#else
		if (strlen(cfgTmpPath))
			json_object_to_file(cfgTmpPath, cfgRoot);
#endif
	}

	json_object_put(decryptedRoot);
} /* End of cm_handlePrivateCfg */

/*
========================================================================
Routine Description:
	Find the corresponding service by parameter name.

Arguments:
	param		- parameter name

Return Value:
	sevice		- service for parameter

========================================================================
*/
char *cm_findServiceByParam(char *param)
{
	struct param_mapping_s *pParam = NULL;
	struct feature_mapping_s *pFeature = NULL;
	char *service = NULL;

	if (!param) {
		DBG_ERR("param is NULL");
		return NULL;
	}

	if (strlen(param) == 0) {
		DBG_ERR("the length of param is 0");
		return NULL;
	}

	for (pParam = &param_mapping_list[0]; pParam->param != NULL; pParam++) {
		if (strcmp(pParam->param, param) == 0) {
			for (pFeature = &feature_mapping_list[0]; pFeature->index != 0; pFeature++) {
				if (pFeature->index == pParam->feature) {
					service = pFeature->service;
					break;
				}
			}
		}
	}

	return service;
} /* End of cm_findServiceByParam */

/*
========================================================================
Routine Description:
	Add private cfg for slave.

Arguments:
	clientMac			- client mac for identification
	outRoot		- json object for output

Return Value:
	none

========================================================================
*/
static void cm_addPrivateCfg(char *clientMac, json_object *outRoot)
{
	json_object *fileRoot = NULL;
	json_object *ftObj = NULL;
	json_object *pftObj = NULL;
	char privateCfgPath[64] = {0};
	char ftName[32] = {0};
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	char *service = NULL, actionScript[128];
	int updateAction = 0;
	json_object *actionObj = NULL;
#endif

	if (!clientMac) {
		DBG_INFO("clientMac is NULL");
		return;
	}

	if (!outRoot) {
		DBG_INFO("outRoot is NULL");
		return;
	}

	DBG_INFO("clientMac(%s)", clientMac);

	if (strlen(clientMac)) {
		snprintf(privateCfgPath, sizeof(privateCfgPath), "/tmp/%s.json", clientMac);

		fileRoot = json_object_from_file(privateCfgPath);
		if (fileRoot) {
			json_object_object_foreach(fileRoot, key, val) {
				pftObj = val;
				memset(ftName, 0, sizeof(ftName));
				snprintf(ftName, sizeof(ftName), "%s", key);
				json_object_object_get_ex(outRoot, ftName, &ftObj);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
				updateAction = 0;
				memset(actionScript, 0, sizeof(actionScript));
#endif
				if (ftObj) {
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
					/* get action script */
					json_object_object_get_ex(ftObj, CFG_ACTION_SCRIPT, &actionObj);
					if (actionObj) {
						strlcat(actionScript, json_object_get_string(actionObj), sizeof(actionScript));
					}
#endif

					json_object_object_foreach(pftObj, key, val) {
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
						if (cm_checkParamFollowRule(clientMac, key, FOLLOW_RE))
#endif
						json_object_object_add(ftObj, key,
							json_object_new_string(json_object_get_string(val)));

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
						/* add action script */
						if ((service = cm_findServiceByParam(key))) {
							if (strlen(service) && !strstr(actionScript, service)) {
								if (strlen(actionScript))
									strlcat(actionScript, ";", sizeof(actionScript));
								strlcat(actionScript, service, sizeof(actionScript));
								updateAction = 1;
							}
						}
#endif
					}

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
					/* update action script to outRoot */
					if (updateAction) {
						DBG_INFO("update action script (%s)", actionScript);
						json_object_object_del(ftObj, CFG_ACTION_SCRIPT);
						json_object_object_add(ftObj, CFG_ACTION_SCRIPT,
							json_object_new_string(actionScript));
					}
#endif
				}
				else
				{
					ftObj = json_object_new_object();
					if (ftObj) {
						json_object_object_foreach(pftObj, key, val) {
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
							if (cm_checkParamFollowRule(clientMac, key, FOLLOW_RE))
#endif
							json_object_object_add(ftObj, key,
								json_object_new_string(json_object_get_string(val)));

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
							/* add action script */
							if ((service = cm_findServiceByParam(key))) {
								if (strlen(service) && !strstr(actionScript, service)) {
									if (strlen(actionScript))
										strlcat(actionScript, ";", sizeof(actionScript));
									strlcat(actionScript, service, sizeof(actionScript));
									updateAction = 1;
								}
							}
#endif
						}

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
						/* update action script to outRoot */
						if (updateAction) {
							DBG_INFO("update action script (%s)", actionScript);
							json_object_object_add(ftObj, CFG_ACTION_SCRIPT,
								json_object_new_string(actionScript));
						}
#endif

						json_object_object_add(outRoot, ftName, ftObj);
					}
				}
			}
		}

		json_object_put(fileRoot);
	}
} /* End of cm_addPrivateCfg */

/*
========================================================================
Routine Description:
	Check some information (such as cfg_ver, sw_mode etc.) of the client.

Arguments:
	clientMac			- client mac for identification
	decryptedMsg		- decrypted message
	msg			- output message array
	msgLen			- the legnth of output message array
	checkVer			- check version

Return Value:
	message length

========================================================================
*/
static int cm_checkCfgInfo(char *clientMac, unsigned char *decryptedMsg, char *msg, int msgLen, int checkVer)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *outRoot = NULL;
	json_object *cfgVer = NULL;
	json_object *cfgAll = NULL;
	json_object *uMacObj = NULL;
#if defined(RTCONFIG_AMAS_WGN)
	char tmp_gifnames[512];
	char *guest_ifnames_ptr = NULL, *guest_ifnames_end = NULL;
	json_object *capabilityObj = NULL;
	int re_guestif_num = 0, unit = 0, subunit = 0;
	char s1[80], s2[80], guest_ifnames[512], guest_vlans[512], word[64], *next = NULL;
	char sync_node_ifs[128], bss_enabled_ifs[128];
	json_object *cfgGuestNetworkNo2g = NULL;
	json_object *cfgGuestNetworkNo5g = NULL;
	json_object *cfgGuestNetworkNo5gH = NULL;
	json_object *cfgGuestNetworkNo6g = NULL;
	char capabilityFilePath[64] = {0};
#endif	/* RTCONFIG_AMAS_WGN */	
	json_object *bandNumObj = NULL;
	char uniqueMac[18] = {0};
	int reBandNum = 0;

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (decryptedRoot == NULL) {
		json_object_put(decryptedRoot);
		DBG_ERR("json_tokener_parse err!");
		return 0;
	}

	/* get unique mac for slave */
	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &uMacObj);
	if (uMacObj)
		snprintf(uniqueMac, sizeof(uniqueMac), "%s", json_object_get_string(uMacObj));

	/* check re unique mac */
	if (!cm_checkReListExist(uniqueMac)) {
		json_object_put(decryptedRoot);
		DBG_ERR("re unique mac is invalid!");
		return 0;
	}

	/* get supported band number for re */
	json_object_object_get_ex(decryptedRoot, CFG_STR_BANDNUM, &bandNumObj);
	if (bandNumObj)
		reBandNum = atoi(json_object_get_string(bandNumObj));

	/* check version info */
	if (checkVer) {
		json_object_object_get_ex(decryptedRoot, CFG_STR_CFGVER, &cfgVer);
		json_object_object_get_ex(decryptedRoot, CFG_STR_CFGALL, &cfgAll);
		if (cfgVer == NULL) {
			DBG_ERR("no cfg_ver in message!");
			json_object_put(decryptedRoot);
			return 0;
	        }
		else
		{
			if (!strcmp(nvram_safe_get("cfg_ver"), json_object_get_string(cfgVer)) &&
				!cfgAll) {
	                        DBG_INFO("cfg ver is same, don't change!");
				json_object_put(decryptedRoot);
				return 0;
			}
		}

#if defined(RTCONFIG_WIFI_SON)
		if(!nvram_match("wifison_ready", "1"))
#endif
		/* handle private cfg first */
		cm_handlePrivateCfg(uniqueMac, decryptedMsg);

	}

	outRoot = json_object_new_object();

	if (!outRoot) {
		json_object_put(decryptedRoot);
		DBG_ERR("outRoot is NULL");
		return 0;
	}

#if defined(RTCONFIG_AMAS_WGN)
	/* read capability file */
	snprintf(capabilityFilePath, sizeof(capabilityFilePath), "%s/%s.cap", TEMP_ROOT_PATH, uniqueMac);
	if ((capabilityObj = json_object_from_file(capabilityFilePath)))
	{
		memset(s1, 0, sizeof(s1));
		snprintf(s1, sizeof(s1), "%d", GUEST_NETWORK_NO_2G);	
		json_object_object_get_ex(capabilityObj, s1, &cfgGuestNetworkNo2g);

		memset(s1, 0, sizeof(s1));
		snprintf(s1, sizeof(s1), "%d", GUEST_NETWORK_NO_5G);	
		json_object_object_get_ex(capabilityObj, s1, &cfgGuestNetworkNo5g);

		memset(s1, 0, sizeof(s1));
		snprintf(s1, sizeof(s1), "%d", GUEST_NETWORK_NO_5GH);	
		json_object_object_get_ex(capabilityObj, s1, &cfgGuestNetworkNo5gH);

		memset(s1, 0, sizeof(s1));
		snprintf(s1, sizeof(s1), "%d", GUEST_NETWORK_NO_6G);	
		json_object_object_get_ex(capabilityObj, s1, &cfgGuestNetworkNo6g);
	}
#endif	/* RTCONFIG_AMAS_WGN */		

	/* add cfg ver */
	json_object_object_add(outRoot, CFG_STR_CFGVER, json_object_new_string(nvram_safe_get("cfg_ver")));
	if (cfgAll)
		json_object_object_add(outRoot, CFG_STR_CFGALL, json_object_new_string(""));
	/* add cfg band index version */
#if defined(RTCONFIG_BANDINDEX_NEW)
	json_object_object_add(outRoot, CFG_BAND_INDEX_VERSION, json_object_new_string("2"));
#else
	json_object_object_add(outRoot, CFG_BAND_INDEX_VERSION, json_object_new_string("1"));
#endif

	/* add cfg band type */
	cm_addBandIndex(outRoot);
	/* add cfg band number */
	
	/* supported band number */
	json_object_object_add(outRoot, CFG_STR_BANDNUM, json_object_new_int(supportedBandNum));

	/* add vendor name */
	json_object_object_add(outRoot, CFG_STR_VENDOR, json_object_new_string(VENDOR_NAME));

	/* add bandwidth capability */
	json_object_object_add(outRoot, CFG_STR_BWCAP, json_object_new_int(BW_CAP));

	/* add smart_connect_x */
	json_object_object_add(outRoot, CFG_STR_SMART_CONNECT, json_object_new_int(nvram_get_int("smart_connect_x")));

#ifdef PRELINK
	cm_addPrelinkConfig(outRoot);
#endif

#ifdef RTCONFIG_DWB
	cm_transDedicated_Wifi_Backhaul_Parameter(uniqueMac, reBandNum, outRoot);
#endif

#if defined(RTCONFIG_TCODE) && defined(RTCONFIG_CFGSYNC_LOCSYNC)
    cm_transloclist_Parameter(outRoot);
#endif

	/* add params based on feature list */
	cm_transformCfgParam(decryptedRoot, outRoot, 0);

	/* add control paramter */
	cm_transCtrlParam(outRoot);

#if defined(RTCONFIG_WIFI_SON)
	if(!nvram_match("wifison_ready", "1"))
#endif

#if defined(RTCONFIG_AMAS_WGN)
	if (capabilityObj)
	{
		if (cfgGuestNetworkNo2g)
		{
			if (json_object_get_int64(cfgGuestNetworkNo2g) == ONE_GUEST_NETWORK)
				re_guestif_num = 1;
			else if (json_object_get_int64(cfgGuestNetworkNo2g) == TWO_GUEST_NETWORK)
				re_guestif_num = 2;
			else if (json_object_get_int64(cfgGuestNetworkNo2g) == THREE_GUEST_NETWORK)
				re_guestif_num = 3;
			else
				re_guestif_num = 0;

			if (re_guestif_num > 0)
			{
				memset(tmp_gifnames, 0, sizeof(tmp_gifnames));
				if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_2G), re_guestif_num, tmp_gifnames, sizeof(tmp_gifnames)-1))
				{
					memset(guest_vlans, 0, sizeof(guest_vlans));				
					if (wgn_guest_vlans(tmp_gifnames, guest_vlans, sizeof(guest_vlans)-1))
					{
						memset(guest_ifnames, 0, sizeof(guest_ifnames));
						guest_ifnames_ptr = &guest_ifnames[0];
						guest_ifnames_end = guest_ifnames_ptr + sizeof(guest_ifnames)-1;
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							unit =  get_unit_chanspc_by_bandtype(uniqueMac, "2G");
							if (unit > -1 && subunit > 0) guest_ifnames_ptr += snprintf(guest_ifnames_ptr, guest_ifnames_end-guest_ifnames_ptr, "wl%d.%d ", unit, subunit);
						}

						if (strlen(guest_ifnames) > 0 && guest_ifnames[strlen(guest_ifnames)-1] == ' ')
                    		guest_ifnames[strlen(guest_ifnames)-1]='\0';
						
						json_object_object_add(outRoot, CFG_STR_GUEST_IFNAMES_2G, json_object_new_string(guest_ifnames));
						json_object_object_add(outRoot, CFG_STR_GUEST_VLANS_2G, json_object_new_string(guest_vlans));
						foreach(word, tmp_gifnames, next)
						{
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit > -1 && subunit > 0)
							{
								// add wlx.x_sync_node
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_SYNC_NODE_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "2G"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_sync_node", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));
								// add wlx.x_bss_enabled 
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_BSS_ONOFF_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "2G"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_bss_enabled", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));
							}
						}

						// add sync_node & bss_enabled info by band
						memset(sync_node_ifs, 0, sizeof(sync_node_ifs));
						memset(bss_enabled_ifs, 0, sizeof(bss_enabled_ifs));
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit < 0 || subunit <= 0)
								continue;
							
							// sync_node
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_sync_node", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(sync_node_ifs, s2, sizeof(sync_node_ifs));

							// bss_enabled
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_bss_enabled", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(bss_enabled_ifs, s2, sizeof(sync_node_ifs));
						}

						if (strlen(sync_node_ifs) > 0) {
							if (strlen(sync_node_ifs) > 1)
								sync_node_ifs[strlen(sync_node_ifs)-1] = '\0';
							json_object_object_add(outRoot, CFG_STR_SYNC_NODE_2G, json_object_new_string(sync_node_ifs));
						}

						if (strlen(bss_enabled_ifs) > 0) {
							if (strlen(bss_enabled_ifs) > 1)
								bss_enabled_ifs[strlen(bss_enabled_ifs)] = '\0';
							json_object_object_add(outRoot, CFG_STR_BSS_ENABLED_2G, json_object_new_string(bss_enabled_ifs));
						}
					}
				}
			}
		}

		if (cfgGuestNetworkNo5g)
		{
			if (json_object_get_int64(cfgGuestNetworkNo5g) == ONE_GUEST_NETWORK)
				re_guestif_num = 1;
			else if (json_object_get_int64(cfgGuestNetworkNo5g) == TWO_GUEST_NETWORK)
				re_guestif_num = 2;
			else if (json_object_get_int64(cfgGuestNetworkNo5g) == THREE_GUEST_NETWORK)
				re_guestif_num = 3;
			else
				re_guestif_num = 0;

			if (re_guestif_num > 0)
			{
				memset(tmp_gifnames, 0, sizeof(tmp_gifnames));
				if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_5G), re_guestif_num, tmp_gifnames, sizeof(tmp_gifnames)-1))
				{
					memset(guest_vlans, 0, sizeof(guest_vlans));
					if (wgn_guest_vlans(tmp_gifnames, guest_vlans, sizeof(guest_vlans)-1))
					{
						memset(guest_ifnames, 0, sizeof(guest_ifnames));
						guest_ifnames_ptr = &guest_ifnames[0];
						guest_ifnames_end = guest_ifnames_ptr + sizeof(guest_ifnames)-1;
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							unit =  get_unit_chanspc_by_bandtype(uniqueMac, "5G");
							if (unit > -1 && subunit > 0) guest_ifnames_ptr += snprintf(guest_ifnames_ptr, guest_ifnames_end-guest_ifnames_ptr, "wl%d.%d ", unit, subunit);
						}

						if (strlen(guest_ifnames) > 0 && guest_ifnames[strlen(guest_ifnames)-1] == ' ')
                    		guest_ifnames[strlen(guest_ifnames)-1]='\0';

						json_object_object_add(outRoot, CFG_STR_GUEST_IFNAMES_5G, json_object_new_string(guest_ifnames));
						json_object_object_add(outRoot, CFG_STR_GUEST_VLANS_5G, json_object_new_string(guest_vlans));
						foreach(word, tmp_gifnames, next)
						{
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit > -1 && subunit > 0)
							{
								// add wlx.x_sync_node
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_SYNC_NODE_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "5G"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_sync_node", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));

								// add wlx.x_bss_enabled 
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_BSS_ONOFF_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "5G"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_bss_enabled", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));
							}
						}

						// add sync_node & bss_enabled info by band
						memset(sync_node_ifs, 0, sizeof(sync_node_ifs));
						memset(bss_enabled_ifs, 0, sizeof(bss_enabled_ifs));
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit < 0 || subunit <= 0)
								continue;
							
							// sync_node
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_sync_node", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(sync_node_ifs, s2, sizeof(sync_node_ifs));

							// bss_enabled
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_bss_enabled", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(bss_enabled_ifs, s2, sizeof(sync_node_ifs));
						}

						if (strlen(sync_node_ifs) > 0) {
							if (strlen(sync_node_ifs) > 1)
								sync_node_ifs[strlen(sync_node_ifs)-1] = '\0';
							json_object_object_add(outRoot, CFG_STR_SYNC_NODE_5G, json_object_new_string(sync_node_ifs));
						}

						if (strlen(bss_enabled_ifs) > 0) {
							if (strlen(bss_enabled_ifs) > 1)
								bss_enabled_ifs[strlen(bss_enabled_ifs)] = '\0';
							json_object_object_add(outRoot, CFG_STR_BSS_ENABLED_5G, json_object_new_string(bss_enabled_ifs));
						}
					}
				}
			}
		}

		if (cfgGuestNetworkNo5gH)
		{
			if (json_object_get_int64(cfgGuestNetworkNo5gH) == ONE_GUEST_NETWORK)
				re_guestif_num = 1;
			else if (json_object_get_int64(cfgGuestNetworkNo5gH) == TWO_GUEST_NETWORK)
				re_guestif_num = 2;
			else if (json_object_get_int64(cfgGuestNetworkNo5gH) == THREE_GUEST_NETWORK)
				re_guestif_num = 3;
			else
				re_guestif_num = 0;

			if (re_guestif_num > 0)
			{
				memset(tmp_gifnames, 0, sizeof(tmp_gifnames));
				if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_5GH), re_guestif_num, tmp_gifnames, sizeof(tmp_gifnames)-1))
				{
					memset(guest_vlans, 0, sizeof(guest_vlans));
					if (wgn_guest_vlans(tmp_gifnames, guest_vlans, sizeof(guest_vlans)-1))
					{
						memset(guest_ifnames, 0, sizeof(guest_ifnames));
						guest_ifnames_ptr = &guest_ifnames[0];
						guest_ifnames_end = guest_ifnames_ptr + sizeof(guest_ifnames)-1;
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							unit =  get_unit_chanspc_by_bandtype(uniqueMac, "5G1");
							if (unit > -1 && subunit > 0) guest_ifnames_ptr += snprintf(guest_ifnames_ptr, guest_ifnames_end-guest_ifnames_ptr, "wl%d.%d ", unit, subunit);
						}

						if (strlen(guest_ifnames) > 0 && guest_ifnames[strlen(guest_ifnames)-1] == ' ')
                    		guest_ifnames[strlen(guest_ifnames)-1]='\0';

						json_object_object_add(outRoot, CFG_STR_GUEST_IFNAMES_5GH, json_object_new_string(guest_ifnames));
						json_object_object_add(outRoot, CFG_STR_GUEST_VLANS_5GH, json_object_new_string(guest_vlans));
						foreach(word, tmp_gifnames, next)
						{
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit > -1 && subunit > 0)
							{
								// add wlx.x_sync_node
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_SYNC_NODE_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "5G1"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_sync_node", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));

								// add wlx.x_bss_enabled
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_BSS_ONOFF_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "5G1"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_bss_enabled", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));
							}
						}

						// add sync_node & bss_enabled info by band
						memset(sync_node_ifs, 0, sizeof(sync_node_ifs));
						memset(bss_enabled_ifs, 0, sizeof(bss_enabled_ifs));
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit < 0 || subunit <= 0)
								continue;
							
							// sync_node
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_sync_node", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(sync_node_ifs, s2, sizeof(sync_node_ifs));

							// bss_enabled
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_bss_enabled", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(bss_enabled_ifs, s2, sizeof(sync_node_ifs));
						}

						if (strlen(sync_node_ifs) > 0) {
							if (strlen(sync_node_ifs) > 1)
								sync_node_ifs[strlen(sync_node_ifs)-1] = '\0';
							json_object_object_add(outRoot, CFG_STR_SYNC_NODE_5GH, json_object_new_string(sync_node_ifs));
						}

						if (strlen(bss_enabled_ifs) > 0) {
							if (strlen(bss_enabled_ifs) > 1)
								bss_enabled_ifs[strlen(bss_enabled_ifs)] = '\0';
							json_object_object_add(outRoot, CFG_STR_BSS_ENABLED_5GH, json_object_new_string(bss_enabled_ifs));
						}
					}
				}
			}
		}

		if (cfgGuestNetworkNo6g)
		{
			if (json_object_get_int64(cfgGuestNetworkNo6g) == ONE_GUEST_NETWORK)
				re_guestif_num = 1;
			else if (json_object_get_int64(cfgGuestNetworkNo6g) == TWO_GUEST_NETWORK)
				re_guestif_num = 2;
			else if (json_object_get_int64(cfgGuestNetworkNo6g) == THREE_GUEST_NETWORK)
				re_guestif_num = 3;
			else
				re_guestif_num = 0;

			if (re_guestif_num > 0)
			{
				memset(tmp_gifnames, 0, sizeof(tmp_gifnames));
				if (wgn_guest_ifnames(wgn_get_unit_by_band(WGN_WL_BAND_6G), re_guestif_num, tmp_gifnames, sizeof(tmp_gifnames)-1))
				{
					memset(guest_vlans, 0, sizeof(guest_vlans));
					if (wgn_guest_vlans(tmp_gifnames, guest_vlans, sizeof(guest_vlans)-1))
					{
						memset(guest_ifnames, 0, sizeof(guest_ifnames));
						guest_ifnames_ptr = &guest_ifnames[0];
						guest_ifnames_end = guest_ifnames_ptr + sizeof(guest_ifnames)-1;
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							unit =  get_unit_chanspc_by_bandtype(uniqueMac, "6G");
							if (unit > -1 && subunit > 0) guest_ifnames_ptr += snprintf(guest_ifnames_ptr, guest_ifnames_end-guest_ifnames_ptr, "wl%d.%d ", unit, subunit);
						}

						if (strlen(guest_ifnames) > 0 && guest_ifnames[strlen(guest_ifnames)-1] == ' ')
                    		guest_ifnames[strlen(guest_ifnames)-1]='\0';

						json_object_object_add(outRoot, CFG_STR_GUEST_IFNAMES_6G, json_object_new_string(guest_ifnames));
						json_object_object_add(outRoot, CFG_STR_GUEST_VLANS_6G, json_object_new_string(guest_vlans));
						foreach(word, tmp_gifnames, next)
						{
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit > -1 && subunit > 0)
							{
								// add wlx.x_sync_node
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_SYNC_NODE_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "6G"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_sync_node", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));

								// add wlx.x_bss_enabled 
								memset(s1, 0, sizeof(s1));
								snprintf(s1, sizeof(s1), CFG_STR_BSS_ONOFF_X_Y, get_unit_chanspc_by_bandtype(uniqueMac, "6G"), subunit);
								memset(s2, 0, sizeof(s2));
								snprintf(s2, sizeof(s2), "wl%d.%d_bss_enabled", unit, subunit);
								json_object_object_add(outRoot, s1, json_object_new_int(nvram_get_int(s2)));						
							}
						}

						// add sync_node & bss_enabled info by band
						memset(sync_node_ifs, 0, sizeof(sync_node_ifs));
						memset(bss_enabled_ifs, 0, sizeof(bss_enabled_ifs));
						foreach (word, tmp_gifnames, next) {
							unit = subunit = -1;
							sscanf(word, "wl%d.%d_%*s", &unit, &subunit);
							if (unit < 0 || subunit <= 0)
								continue;
							
							// sync_node
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_sync_node", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(sync_node_ifs, s2, sizeof(sync_node_ifs));

							// bss_enabled
							memset(s1, 0, sizeof(s1));
							snprintf(s1, sizeof(s1), "wl%d.%d_bss_enabled", unit, subunit);
							memset(s2, 0, sizeof(s2));
							snprintf(s2, sizeof(s2), "%d ", nvram_get_int(s1));
							strlcat(bss_enabled_ifs, s2, sizeof(sync_node_ifs));
						}

						if (strlen(sync_node_ifs) > 0) {
							if (strlen(sync_node_ifs) > 1)
								sync_node_ifs[strlen(sync_node_ifs)-1] = '\0';
							json_object_object_add(outRoot, CFG_STR_SYNC_NODE_6G, json_object_new_string(sync_node_ifs));
						}

						if (strlen(bss_enabled_ifs) > 0) {
							if (strlen(bss_enabled_ifs) > 1)
								bss_enabled_ifs[strlen(bss_enabled_ifs)] = '\0';
							json_object_object_add(outRoot, CFG_STR_BSS_ENABLED_6G, json_object_new_string(bss_enabled_ifs));
						}
					}
				}
			}
		}
	}

	if (strlen(nvram_safe_get("wgn_wloff_vifs")) > 0)
	{
		json_object_object_add(outRoot, CFG_STR_WGN_WLOFF_VIFS, json_object_new_string(nvram_safe_get("wgn_wloff_vifs")));
	}
#endif	/* RTCONFIG_AMAS_WGN */
	/* add private feature list */
	cm_addPrivateCfg(uniqueMac, outRoot);

	
	snprintf(msg, msgLen, "%s", (unsigned char *)json_object_to_json_string_ext(outRoot, 0));
	DBG_INFO("msg(%s)", msg);

	json_object_put(outRoot);
	json_object_put(decryptedRoot);

#if defined(RTCONFIG_AMAS_WGN)	
	if (capabilityObj) json_object_put(capabilityObj);
#endif	// RTCONFIG_AMAS_WGN	

	return strlen(msg);
} /* End of cm_checkCfgInfo */

/*
========================================================================
Routine Description:
	Update related info from slave.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	none

========================================================================
*/
static void cm_updateSlaveRelatedInfo(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *uMacObj = NULL;
	json_object *capabilityObj = NULL, *miscInfoObj = NULL;
	char infoFilePath[64] = {0};

	DBG_INFO("decryptedMsg(%s)", decryptedMsg);

	if (decryptedRoot == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	/* get unique mac for slave */
	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &uMacObj);

	/* get capability for slave */
	json_object_object_get_ex(decryptedRoot, CFG_STR_CAPABILITY, &capabilityObj);

	/* get misc info for slave */
	json_object_object_get_ex(decryptedRoot, CFG_STR_MISC_INFO, &miscInfoObj);


	if (uMacObj) {
		snprintf(infoFilePath, sizeof(infoFilePath), "%s/%s.cap",
			TEMP_ROOT_PATH, json_object_get_string(uMacObj));

		if (capabilityObj)
			json_object_to_file(infoFilePath, capabilityObj);

		snprintf(infoFilePath, sizeof(infoFilePath), "%s/%s.misc",
			TEMP_ROOT_PATH, json_object_get_string(uMacObj));

		if (miscInfoObj)
			json_object_to_file(infoFilePath, miscInfoObj);
		else
		{
			if (f_exists(infoFilePath)) {
				DBG_INFO("no update but %s exists, remove it", infoFilePath);
				unlink(infoFilePath);
			}
		}
	}

	json_object_put(decryptedRoot);
} /* End of cm_updateSlaveRelatedInfo */

/*
========================================================================
Routine Description:
	Select session key.

Arguments:
	e		- hash element for client.
	keyIndex		- key index for no expired (1) and expired (0)

Return Value:
	session key

========================================================================
*/
static unsigned char *cm_selectSessionKey(hash_elem_t* e, int keyIndex)
{
	int sKeyTime = (int) (uptime() - e->sessionKeyStartTime);
	int sKey1Time = (int) (uptime() - e->sessionKey1StartTime);

	DBG_INFO("sKeyTime(%d), sKey1Time(%d), sessionKeyExpireTime(%d), rekeyTime(%d)",
				sKeyTime, sKey1Time , sessionKeyExpireTime, REKEY_TIME(sessionKeyExpireTime));

	if (sKeyTime > sessionKeyExpireTime) {
		DBG_INFO("sKeyTime > sessionKeyExpireTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? e->sessionKey1 : e->sessionKey);
	}

	if (sKey1Time > sessionKeyExpireTime) {
		DBG_INFO("sKey1Time > sessionKeyExpireTime, select %s", keyIndex ? "key" : "key1");
		return (keyIndex ? e->sessionKey : e->sessionKey1);
	}

	if (e->sessionKeyStartTime >= e->sessionKey1StartTime) {
		DBG_INFO("sessionKeyStartTime >= sessionKey1StartTime, select %s", keyIndex ? "key" : "key1");
		return (keyIndex ? e->sessionKey : e->sessionKey1);
	}
	else
	{
		DBG_INFO("sessionKey1StartTime > sessionKeyStartTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? e->sessionKey1 : e->sessionKey);
	}
} /* End of cm_selectSessionKey*/

/*
========================================================================
Routine Description:
	Select group key.

Arguments:
	keyIndex		- key index for no expired (1) and expired (0)

Return Value:
	group key

========================================================================
*/
unsigned char *cm_selectGroupKey(int keyIndex)
{
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	DBG_INFO("gKeyTime(%d), gKey1Time(%d), groupKeyExpireTime(%d), rekeyTime(%d)",
				gKeyTime, gKey1Time , groupKeyExpireTime, REKEY_TIME(groupKeyExpireTime));

	if (gKeyTime > groupKeyExpireTime) {
		DBG_INFO("gKeyTime > groupKeyExpireTime, select %s", keyIndex ? "key1" : "key");
		return (keyIndex ? cm_ctrlBlock.groupKey1 : cm_ctrlBlock.groupKey);
	}

	if (gKey1Time > groupKeyExpireTime) {
		DBG_INFO("gKey1Time > groupKeyExpireTime, select %s", keyIndex ? "key" : "key1");
		return  (keyIndex ? cm_ctrlBlock.groupKey : cm_ctrlBlock.groupKey1);
	}

	if (cm_ctrlBlock.groupKeyStartTime >= cm_ctrlBlock.groupKey1StartTime) {
		DBG_INFO("groupKeyStartTime >= groupKey1StartTime, select %s", keyIndex ? "key" : "key1");
		return  (keyIndex ? cm_ctrlBlock.groupKey : cm_ctrlBlock.groupKey1);
	}
	else
	{
		DBG_INFO("groupKey1StartTime > groupKeyStartTime, select %s", keyIndex ? "key1" : "key");
		return  (keyIndex ? cm_ctrlBlock.groupKey1 : cm_ctrlBlock.groupKey);
	}
} /* End of cm_selectGroupKey*/

/*
========================================================================
Routine Description:
	Prepare the info of session key and time diff.

Arguments:
	pCtrlBK			- CM control blcok
	decryptedMsg		- decrypted message
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareSessionKey(hash_elem_t* e, unsigned char *decryptedMsg, char *msg, int msgLen)
{
	struct json_object *root = NULL;
	char keyBuf[128] = {0};
	unsigned char *randKey1 = NULL;	// random key 1 for generating group key
	unsigned char *randKey2 = NULL;	// random key 2 for generating group key
	unsigned char *randKey3 = NULL;	// random key 3 for generating group key
	size_t randKey1Len = 0;		// the length of random key 1
	size_t randKey2Len = 0;		// the length of random key 2
	size_t randKey3Len = 0;		// the length of random key 3

	root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return 0;
	}

	DBG_INFO("prepare session key");
	/* generate three random keys */
	randKey1 = gen_rand(&randKey1Len);
	randKey2 = gen_rand(&randKey2Len);
	randKey3 = gen_rand(&randKey3Len);
	/* generate session key */
	if (e->sessionKeyStartTime > e->sessionKey1StartTime) {
		/* free sessionKey1 first */
		if (e->sessionKey1) free(e->sessionKey1);
		e->sessionKey1 = gen_session_key(randKey1, randKey1Len, randKey2,
				randKey2Len, randKey3, randKey3Len, &e->sessionKeyLen);
		e->sessionKey1StartTime = e->sessionKeyStartTime + sessionKeyExpireTime;
		key_etoa(e->sessionKey1, keyBuf);
	}
	else
	{
		/* free sessionKey first */
		if (e->sessionKey) free(e->sessionKey);
		e->sessionKey = gen_session_key(randKey1, randKey1Len, randKey2,
				randKey2Len, randKey3, randKey3Len, &e->sessionKeyLen);
		e->sessionKeyStartTime = e->sessionKey1StartTime + sessionKeyExpireTime;
		key_etoa(e->sessionKey, keyBuf);
	}

	/* free three random keys */
	if (randKey1) free(randKey1);
	if (randKey2) free(randKey2);
	if (randKey3) free(randKey3);

	/* prepare required */
	if (strlen(keyBuf))
		json_object_object_add(root, "key", json_object_new_string(keyBuf));

	snprintf(msg, msgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", msg);
	json_object_put(root);

	return strlen(msg);
} /* End of cm_prepareSessionKey */

/*
========================================================================
Routine Description:
	Prepare the info of group key and time diff.

Arguments:
	msg			- output message array
	msgLen			- the legnth of output message array
	reKey		- do rekey

Return Value:
	message length

========================================================================
*/
static int cm_prepareGroupKey(char *msg, int msgLen, int reKey)
{
	struct json_object *root = NULL;
	char keyBuf[128] = {0};
	char diffBuf[16] = {0};
	int gKeyTime = (int) (uptime() - cm_ctrlBlock.groupKeyStartTime);
	int gKey1Time = (int) (uptime() - cm_ctrlBlock.groupKey1StartTime);

	root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return 0;
	}

	DBG_INFO("prepare group key, reKey(%d)", reKey);

	if (!reKey) {
		if (gKey1Time > groupKeyExpireTime) {
			DBG_INFO("gKey1Time > groupKeyExpireTime");
			key_etoa(cm_ctrlBlock.groupKey, keyBuf);
			snprintf(diffBuf, sizeof(diffBuf), "%d", (int) (uptime() - cm_ctrlBlock.groupKeyStartTime));
		}
		else if (gKeyTime > groupKeyExpireTime) {
			DBG_INFO("gKeyTime > groupKeyExpireTime");
			key_etoa(cm_ctrlBlock.groupKey1, keyBuf);
			snprintf(diffBuf, sizeof(diffBuf), "%d", (int) (uptime() - cm_ctrlBlock.groupKey1StartTime));
		}
		else {
			if (cm_ctrlBlock.groupKeyStartTime > cm_ctrlBlock.groupKey1StartTime) {
				DBG_INFO("cm_ctrlBlock.groupKeyStartTime > cm_ctrlBlock.groupKey1StartTime");
				key_etoa(cm_ctrlBlock.groupKey, keyBuf);
				snprintf(diffBuf, sizeof(diffBuf), "%d", (int) (uptime() - cm_ctrlBlock.groupKeyStartTime));
			}
			else
			{
				DBG_INFO("cm_ctrlBlock.groupKeyStartTime <= cm_ctrlBlock.groupKey1StartTime");
				key_etoa(cm_ctrlBlock.groupKey1, keyBuf);
				snprintf(diffBuf, sizeof(diffBuf), "%d", (int) (uptime() - cm_ctrlBlock.groupKey1StartTime));
			}
		}

		/* prepare required */
		if (strlen(keyBuf) && strlen(diffBuf)) {
			DBG_INFO("prepare required key and time");
			json_object_object_add(root, "key", json_object_new_string(keyBuf));
			json_object_object_add(root, "time", json_object_new_string(diffBuf));
		}
	}
	else
	{
		//if (cm_ctrlBlock.groupKeyStartTime >= REKEY_TIME(sessionKeyExpireTime) &&
		//	cm_ctrlBlock.groupKey1StartTime >= REKEY_TIME(sessionKeyExpireTime)) {
		if ((gKeyTime >= REKEY_TIME(groupKeyExpireTime) &&
			gKeyTime <= groupKeyExpireTime &&
			gKey1Time >= groupKeyExpireTime) ||
			(gKey1Time >= REKEY_TIME(groupKeyExpireTime) &&
			gKey1Time <= groupKeyExpireTime &&
			gKeyTime >= groupKeyExpireTime))
		{
			unsigned char *randKey1 = NULL;	// random key 1 for generating group key
			unsigned char *randKey2 = NULL;	// random key 2 for generating group key
			unsigned char *randKey3 = NULL;	// random key 3 for generating group key
			size_t randKey1Len = 0;		// the length of random key 1
			size_t randKey2Len = 0;		// the length of random key 2
			size_t randKey3Len = 0;		// the length of random key 3

			/* generate three random keys */
			randKey1 = gen_rand(&randKey1Len);
			randKey2 = gen_rand(&randKey2Len);
			randKey3 = gen_rand(&randKey3Len);

			/* generate group key */
			if (cm_ctrlBlock.groupKeyStartTime > cm_ctrlBlock.groupKey1StartTime) {
				/* free groupKey1 first */
				if (cm_ctrlBlock.groupKey1) free(cm_ctrlBlock.groupKey1);

				cm_ctrlBlock.groupKey1 = gen_session_key(randKey1, randKey1Len, randKey2,
						randKey2Len, randKey3, randKey3Len, &cm_ctrlBlock.sessionKeyLen);
				cm_ctrlBlock.groupKey1StartTime = cm_ctrlBlock.groupKeyStartTime + groupKeyExpireTime;
				key_etoa(cm_ctrlBlock.groupKey1, keyBuf);
			}
			else
			{
				/* free groupKey first */
				if (cm_ctrlBlock.groupKey) free(cm_ctrlBlock.groupKey);

				cm_ctrlBlock.groupKey = gen_session_key(randKey1, randKey1Len, randKey2,
						randKey2Len, randKey3, randKey3Len, &cm_ctrlBlock.sessionKeyLen);
				cm_ctrlBlock.groupKeyStartTime = cm_ctrlBlock.groupKey1StartTime + groupKeyExpireTime;
				key_etoa(cm_ctrlBlock.groupKey, keyBuf);
			}

			/* free three random keys */
			if (randKey1) free(randKey1);
			if (randKey2) free(randKey2);
			if (randKey3) free(randKey3);
		}
		else
		{
			if (gKeyTime > groupKeyExpireTime)
				key_etoa(cm_ctrlBlock.groupKey1, keyBuf);
			else if (gKey1Time > groupKeyExpireTime)
				key_etoa(cm_ctrlBlock.groupKey, keyBuf);
			else
			{
				if (cm_ctrlBlock.groupKeyStartTime > cm_ctrlBlock.groupKey1StartTime)
					key_etoa(cm_ctrlBlock.groupKey, keyBuf);
				else
					key_etoa(cm_ctrlBlock.groupKey1, keyBuf);
			}
		}

		/* prepare required */
		if (strlen(keyBuf))
			json_object_object_add(root, "key", json_object_new_string(keyBuf));
	}

	snprintf(msg, msgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", json_object_to_json_string(root));
	json_object_put(root);

	return strlen(msg);
} /* End of cm_prepareGroupKey */

/*
========================================================================
Routine Description:
	Prepare the info of wireless channel.

Arguments:
	bandNumRE		- band number for RE
	msg		- rerport message
	root			- output message for RE

Return Value:
	None

========================================================================
*/
static void cm_prepareWirelessChannel(int bandNumRE, unsigned char *msg, json_object *root)
{
	json_object *decryptedRoot = json_tokener_parse((char *)msg);
	json_object *channelObj = NULL, *capBandIndexObj = NULL, *reBandIndexObj = NULL;
	json_object *macObj = NULL, *allBandObj = NULL, *capMultiBandListObj = NULL, *reMultiBandListObj = NULL;
	json_object *channelKeyObj = NULL, *bwKeyObj = NULL, *ctrlsbKeyObj = NULL;
	char tmp[64] = {0}, mac[18];
	char channelKey[32], bwKey[32], ctrlsbKey[32], bandType[16];
	int channel = 0, bw = 0, nctrlsb = 0, bandIndex = 0;
	int bandNumCAP = supportedBandNum;
	int inCapMultiBand = 0, inReMultiBand = 0, inMultiBand = 0;

	if (!decryptedRoot) {
		DBG_INFO("decryptedRoot is NULL");
		goto err;
	}

	capBandIndexObj = json_object_new_object();
	if (!capBandIndexObj) {
		DBG_INFO("capBandIndexObj is NULL");
		goto err;
	}

	reBandIndexObj = json_object_new_object();
	if (!reBandIndexObj) {
		DBG_INFO("reBandIndexObj is NULL");
		goto err;
	}

	capMultiBandListObj = json_object_new_object();
	if (!capMultiBandListObj) {
		DBG_INFO("capMultiBandListObj is NULL");
		goto err;
	}

	reMultiBandListObj = json_object_new_object();
	if (!reMultiBandListObj) {
		DBG_INFO("reMultiBandListObj is NULL");
		goto err;
	}

	channelObj = json_object_new_object();
	if (!channelObj) {
		DBG_INFO("channelObj is NULL");
		goto err;
	}

	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &macObj);

	if (!macObj) {
		DBG_INFO("macObj is NULL");
		goto err;
	}
	strlcpy(mac, json_object_get_string(macObj), sizeof(mac));

	/* band index mapping for cap */
	if (!cm_getBandTypeMappingByMac(get_unique_mac(), 1, capBandIndexObj)) {
		DBG_INFO("can't get band type mapping for cap (%s)", get_unique_mac());
		goto err;
	}

	/* multiple band list for cap */
	if (!cm_getMultipleBandListByMac(get_unique_mac(), 01, capBandIndexObj, capMultiBandListObj)) {
		DBG_INFO("can't get multi band list for re (%s)", get_unique_mac());
		goto err;
	}

	/* band index mapping for re */
	if (!cm_getBandTypeMappingByMac(mac, 0, reBandIndexObj)) {
		DBG_INFO("can't get band type mapping for re (%s)", mac);
		goto err;
	}

	/* multiple band list for re */
	if (!cm_getMultipleBandListByMac(mac, 0, reBandIndexObj, reMultiBandListObj)) {
		DBG_INFO("can't get multi band list for re (%s)", mac);
		goto err;
	}

	json_object_object_add(channelObj, CFG_STR_BANDNUM, json_object_new_int(bandNumCAP));

	/* prepare new key for all band info */
	pthread_mutex_lock(&cfgLock);
	if ((allBandObj = json_object_new_object())) {
		json_object_object_foreach(capBandIndexObj, capBandKey, capBandVal) {
			bandIndex = json_object_get_int(capBandVal);
			wl_control_channel(bandIndex, &channel,  &bw, &nctrlsb);
			snprintf(channelKey, sizeof(channelKey), "%s_channel", capBandKey);
			snprintf(bwKey, sizeof(bwKey), "%s_bw", capBandKey);
			snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", capBandKey);
			json_object_object_add(allBandObj, channelKey, json_object_new_int(channel));
			json_object_object_add(allBandObj, bwKey, json_object_new_int(bw));
			json_object_object_add(allBandObj, ctrlsbKey, json_object_new_int(nctrlsb));
		}

		if (newBandObj) {
			json_object_object_foreach(newBandObj, newBandKey, newBandVal) {
				json_object_object_add(allBandObj, newBandKey, json_object_new_int(json_object_get_int(newBandVal)));
			}
		}

		/* display channel info of all band */
		json_object_object_foreach(allBandObj, allBandKey, allBandVal) {
			DBG_INFO("%s (%d)", allBandKey, json_object_get_int(allBandVal));
		}

		/* prepare channel info for RE supported band */
		json_object_object_foreach(reBandIndexObj, reBandKey, reBandVal) {
			bandIndex = json_object_get_int(reBandVal);

			/* check whether in re multi band */
			inReMultiBand = 0;
			json_object_object_foreach(reMultiBandListObj, reMultiBandKey, reMultiBandVal) {
				strlcpy(tmp, reMultiBandKey, sizeof(tmp));
				if (strncmp(tmp, reBandKey, strlen(tmp)) == 0) {
					inReMultiBand = 1;
					break;
				}
			}

			/* check whether in cap multi band */
			inCapMultiBand = 0;
			json_object_object_foreach(capMultiBandListObj, capMultiBandKey, capMultiBandVal) {
				strlcpy(tmp, capMultiBandKey, sizeof(tmp));
				if (strncmp(tmp, reBandKey, strlen(tmp)) == 0) {
					inCapMultiBand = 1;
					break;
				}
			}

			/* check whether in multi band */
			inMultiBand = 0;
			if (multiBandObj) {
				json_object_object_foreach(multiBandObj, multiBandKey, multiBandVal) {
					strlcpy(tmp, multiBandKey, sizeof(tmp));
					if (strncmp(tmp, reBandKey, strlen(tmp)) == 0) {
						inMultiBand = 1;
						break;
					}
				}
			}

			DBG_INFO("inReMultiBand (%d), inMultiBand (%d)", inReMultiBand, inMultiBand);

			/* convert band type if needed */
			memset(bandType, 0, sizeof(bandType));
			if (!inReMultiBand  && (inCapMultiBand || inMultiBand))
				strlcpy(bandType, cm_findSuitableBandType(allBandObj, reBandKey), sizeof(bandType));
			else
				strlcpy(bandType, reBandKey, sizeof(bandType));

			DBG_INFO("band type (%s), band index (%d)", bandType, bandIndex);
			if (strlen(bandType) > 0) {
				snprintf(channelKey, sizeof(channelKey), "%s_channel", bandType);
				snprintf(bwKey, sizeof(bwKey), "%s_bw", bandType);
				snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", bandType);

				json_object_object_get_ex(allBandObj, channelKey, &channelKeyObj);
				json_object_object_get_ex(allBandObj, bwKey, &bwKeyObj);
				json_object_object_get_ex(allBandObj, ctrlsbKey, &ctrlsbKeyObj);

				if (channelKeyObj && bwKeyObj && ctrlsbKeyObj) {
					snprintf(channelKey, sizeof(channelKey), "wl%d_channel", bandIndex);
					json_object_object_add(channelObj, channelKey, json_object_new_int(json_object_get_int(channelKeyObj)));
					snprintf(bwKey, sizeof(bwKey), "wl%d_bw", bandIndex);
					json_object_object_add(channelObj, bwKey, json_object_new_int(json_object_get_int(bwKeyObj)));
					snprintf(ctrlsbKey, sizeof(ctrlsbKey), "wl%d_nctrlsb", bandIndex);
					json_object_object_add(channelObj, ctrlsbKey, json_object_new_int(json_object_get_int(ctrlsbKeyObj)));
				}
			}
		}

		/* for special case, CAP's tri-band and 5G of RE dual band, need wl2_ */
		if (bandNumCAP== 3 && bandNumRE == 2) {
			memset(bandType, 0, sizeof(bandType));
			strlcpy(bandType, cm_findSuitableBandType(allBandObj, "5G"), sizeof(bandType));
			bandIndex = bandNumRE;
			DBG_INFO("band type (%s), band index (%d)", bandType, bandIndex);
			if (strlen(bandType) > 0) {
				snprintf(channelKey, sizeof(channelKey), "%s_channel", bandType);
				snprintf(bwKey, sizeof(bwKey), "%s_bw", bandType);
				snprintf(ctrlsbKey, sizeof(ctrlsbKey), "%s_nctrlsb", bandType);

				json_object_object_get_ex(allBandObj, channelKey, &channelKeyObj);
				json_object_object_get_ex(allBandObj, bwKey, &bwKeyObj);
				json_object_object_get_ex(allBandObj, ctrlsbKey, &ctrlsbKeyObj);

				if (channelKeyObj && bwKeyObj && ctrlsbKeyObj) {
					snprintf(channelKey, sizeof(channelKey), "wl%d_channel", bandIndex);
					json_object_object_add(channelObj, channelKey, json_object_new_int(json_object_get_int(channelKeyObj)));
					snprintf(bwKey, sizeof(bwKey), "wl%d_bw", bandIndex);
					json_object_object_add(channelObj, bwKey, json_object_new_int(json_object_get_int(bwKeyObj)));
					snprintf(ctrlsbKey, sizeof(ctrlsbKey), "wl%d_nctrlsb", bandIndex);
					json_object_object_add(channelObj, ctrlsbKey, json_object_new_int(json_object_get_int(ctrlsbKeyObj)));
				}
			}
		}

		json_object_put(allBandObj);
	}
	pthread_mutex_unlock(&cfgLock);

#ifdef RTCONFIG_NBR_RPT
	if(bandNumCAP== 2 && bandNumRE == 2 && selected5gBand != NO_SELECTION)
	{
		channel = channel5g;
		bw = bw5g;
		nctrlsb = nctrlsb5g;
		json_object_object_add(channelObj, "r_selected_band", json_object_new_int(selected5gBand));
		json_object_object_add(channelObj, "r_selected_channel", json_object_new_int(channel));
		json_object_object_add(channelObj, "r_selected_bw", json_object_new_int(bw));
		json_object_object_add(channelObj, "r_selected_nctrlsb", json_object_new_int(nctrlsb));
	}
#endif
#ifdef RTCONFIG_BCN_RPT
	if(bandNumCAP == 2 && bandNumRE == 2 && channel5g) {
		json_object_object_add(channelObj, "multi_channel_5g", json_object_new_int(channel5g));
	}
#endif

	json_object_object_add(root, CFG_STR_CHANNEL, channelObj);

err:

	json_object_put(decryptedRoot);
	json_object_put(reBandIndexObj);
	json_object_put(capBandIndexObj);
	json_object_put(capMultiBandListObj);
	json_object_put(reMultiBandListObj);
} /* End of cm_prepareWirelessChannel */

/*
========================================================================
Routine Description:
	Prepare the info of report response.

Arguments:
	decryptedMsg		- decrypted message
	bandNum		- band number for RE
	joinRE		- join status for RE
	msg		- output message
	msgLen		- the length of output mesage

Return Value:
	message length

========================================================================
*/
static int cm_prepareReportRspMsg(unsigned char *decryptedMsg, int bandNum, int join, char *msg, int msgLen)
{
	json_object *root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return 0;
	}

	/* add related message */
	cm_prepareWirelessChannel(bandNum, decryptedMsg, root);
#ifdef STA_BIND_AP
	if (join != JOIN_NONE)
		json_object_object_add(root, CFG_STA_BINDING_LIST, json_object_new_string(nvram_safe_get("sta_binding_list")));
#endif /* STA_BIND_AP */

#ifdef RTCONFIG_NBR_RPT
	cm_prepareNbrList(decryptedMsg, root);
#endif

	snprintf(msg, msgLen, "%s", json_object_to_json_string_ext(root, 0));
	json_object_put(root);

	DBG_INFO("msg (%s), len (%d)", msg, strlen(msg));

	return strlen(msg);
} /* End of cm_prepareReportRspMsg */

#ifdef RTCONFIG_BCN_RPT
/*
========================================================================
Routine Description:
	Prepare message for AP list.

Arguments:
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
void cm_updateAPList()
{
	int i;
	char ap2g_buf[18] = {0}, ap5g_buf[18] = {0}, ap5g1_buf[18] = {0}, ap6g_buf[18] = {0};
	char count_str[4] = {0};

	//json_object *root = NULL;
	json_object *APObj = NULL;
	json_object *APArrayObj = NULL;

	APArrayObj = json_object_new_object();
	if(!APArrayObj) {
		DBG_ERR("APArrayObj is NULL");
		return;
	}

	pthread_mutex_lock(&cfgLock);
	for(i = 0; i < p_client_tbl->count; i++) {
		memset(ap2g_buf, 0, sizeof(ap2g_buf));
		memset(ap5g_buf, 0, sizeof(ap5g_buf));
		memset(ap5g1_buf, 0, sizeof(ap5g1_buf));
		memset(ap6g_buf, 0, sizeof(ap6g_buf));

		snprintf(ap2g_buf, sizeof(ap2g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->ap2g[i][0], p_client_tbl->ap2g[i][1],
			p_client_tbl->ap2g[i][2], p_client_tbl->ap2g[i][3],
			p_client_tbl->ap2g[i][4], p_client_tbl->ap2g[i][5]);

		snprintf(ap5g_buf, sizeof(ap5g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->ap5g[i][0], p_client_tbl->ap5g[i][1],
			p_client_tbl->ap5g[i][2], p_client_tbl->ap5g[i][3],
			p_client_tbl->ap5g[i][4], p_client_tbl->ap5g[i][5]);

		snprintf(ap5g1_buf, sizeof(ap5g1_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->ap5g1[i][0], p_client_tbl->ap5g1[i][1],
			p_client_tbl->ap5g1[i][2], p_client_tbl->ap5g1[i][3],
			p_client_tbl->ap5g1[i][4], p_client_tbl->ap5g1[i][5]);

		snprintf(ap6g_buf, sizeof(ap6g_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->ap6g[i][0], p_client_tbl->ap6g[i][1],
			p_client_tbl->ap6g[i][2], p_client_tbl->ap6g[i][3],
			p_client_tbl->ap6g[i][4], p_client_tbl->ap6g[i][5]);

		APObj = json_object_new_object();
		if(!APObj) continue;

		json_object_object_add(APObj, CFG_STR_AP2G,
			strcmp(ap2g_buf, "00:00:00:00:00:00") ? json_object_new_string(ap2g_buf):  json_object_new_string(""));
		json_object_object_add(APObj, CFG_STR_AP5G,
			strcmp(ap5g_buf, "00:00:00:00:00:00") ? json_object_new_string(ap5g_buf):  json_object_new_string(""));
		json_object_object_add(APObj, CFG_STR_AP5G1,
			strcmp(ap5g1_buf, "00:00:00:00:00:00") ? json_object_new_string(ap5g1_buf):  json_object_new_string(""));
		json_object_object_add(APObj, CFG_STR_AP6G,
			strcmp(ap6g_buf, "00:00:00:00:00:00") ? json_object_new_string(ap6g_buf):  json_object_new_string(""));

		snprintf(count_str, sizeof(count_str), "%d", i);
		json_object_object_add (APArrayObj, count_str, APObj);
	}

	pthread_mutex_unlock(&cfgLock);

	nvram_unset("channel_2g");

	json_object_to_file(AP_LIST_JSON_FILE, APArrayObj);
	json_object_put(APArrayObj);
	return ;
} /* End of cm_updateAPList */
#endif

#ifdef RTCONFIG_FRONTHAUL_DWB
/**
 * @brief Generate message for RE update backhual status
 *
 * @param clientMac RE MAC
 * @param clientIP RE IP
 * @param inMsg Original message buffer
 * @param outMsg Output message buffer
 * @param outMsgLen Output message len
 * @return int Message len.
 */
static int cm_prepareBackhualStatus(char *clientMac, char *clientIP, char *inMsg, char *outMsg, int outMsgLen)
{
	json_object *root = NULL;
	json_object *inRoot = NULL;
	json_object *rMacObj = NULL;
	char backhualStatusBuf[16] = {0};
	int i = 0;
	unsigned char ea[6] = {0};
	char rMac[18] = {0};

	root = json_object_new_object();

	if (!root) {
		DBG_INFO("root is NULL");
		return 0;
	}

	/* grab real mac form client */
	if (inMsg) {
		DBG_INFO("have real mac (%s)", inMsg);
		inRoot = json_tokener_parse(inMsg);
		if (!inRoot) {
			DBG_INFO("inRoot is NULL");
			json_object_put(root);
			return 0;
		}
		else
		{
			json_object_object_get_ex(inRoot, CFG_STR_MAC, &rMacObj);
			if (rMacObj) {
				snprintf(rMac, sizeof(rMac), "%s", json_object_get_string(rMacObj));
				json_object_put(inRoot);
			}
			else
			{
				DBG_INFO("rMacObj is NULL");
				json_object_put(root);
				json_object_put(inRoot);
				return 0;
			}
		}
	}
	else
	{
		DBG_INFO("no real mac");
		snprintf(rMac, sizeof(rMac), "%s", clientMac);
	}

	DBG_INFO("real mac (%s) for backhaul status request", rMac);

	ether_atoe(rMac, ea);

	pthread_mutex_lock(&cfgLock);
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			DBG_INFO("Find the entry in the table");
			p_client_tbl->BackhualStatus[i] = p_client_tbl->BackhualStatus[i] & 7; // Set update bit to 0. 0 X X X
			snprintf(backhualStatusBuf, sizeof(backhualStatusBuf), "%d", p_client_tbl->BackhualStatus[i]);
			break;
		}
	}
	pthread_mutex_unlock(&cfgLock);

	/* prepare backhaul status */
	if (strlen(backhualStatusBuf))
		json_object_object_add(root, CFG_STR_BACKHUAL_STATUS, json_object_new_string(backhualStatusBuf));
	else
		goto err;

#ifdef ONBOARDING
	/* prepare timestamp for onboarding */
	json_object_object_add(root, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
#endif

	snprintf(outMsg, outMsgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", outMsg);

err:
	json_object_put(root);

	return strlen(outMsg);
}
#endif

/*
========================================================================
Routine Description:
	Prepare the cost of network topology.

Arguments:
	cleintMac		- client's MAC
	clientIP		- client's IP
	inMsg		- decoded message
	outMsg			- output message array
	outMsgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareNetworkCost(char *clientMac, char *clientIP, char *inMsg, char *outMsg, int outMsgLen)
{
	json_object *root = NULL;
	json_object *inRoot = NULL;
	json_object *rMacObj = NULL;
	char costBuf[16] = {0};
	int i = 0;
	unsigned char ea[6] = {0};
	char rMac[18] = {0};

	root = json_object_new_object();

	if (!root) {
		DBG_INFO("root is NULL");
		return 0;
	}

	/* grab real mac form client */
	if (inMsg) {
		DBG_INFO("have real mac (%s)", inMsg);
		inRoot = json_tokener_parse(inMsg);
		if (!inRoot) {
			DBG_INFO("inRoot is NULL");
			json_object_put(root);
			return 0;
		}
		else
		{
			json_object_object_get_ex(inRoot, CFG_STR_MAC, &rMacObj);
			if (rMacObj) {
				snprintf(rMac, sizeof(rMac), "%s", json_object_get_string(rMacObj));
				json_object_put(inRoot);
			}
			else
			{
				DBG_INFO("rMacObj is NULL");
				json_object_put(root);
				json_object_put(inRoot);
				return 0;
			}
		}
	}
	else
	{
		DBG_INFO("no real mac");
		snprintf(rMac, sizeof(rMac), "%s", clientMac);
	}

	DBG_INFO("real mac (%s) for cost request", rMac);

	ether_atoe(rMac, ea);

	pthread_mutex_lock(&cfgLock);
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			DBG_INFO("Find the entry in the table");
			snprintf(costBuf, sizeof(costBuf), "%d", p_client_tbl->level[i]);
			break;
		}
	}
	pthread_mutex_unlock(&cfgLock);

	/* prepare cost */
	if (strlen(costBuf))
		json_object_object_add(root, CFG_STR_COST, json_object_new_string(costBuf));
	else
		goto err;

#ifdef ONBOARDING
	/* prepare timestamp for onboarding */
	json_object_object_add(root, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
#endif

	snprintf(outMsg, outMsgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", outMsg);

err:
	json_object_put(root);

	return strlen(outMsg);
} /* End of cm_prepareNetworkCost */

/*
========================================================================
Routine Description:
	Prepare the level of network topology.

Arguments:
	cleintMac		- client's MAC
	clientIP		- client's IP
	inMsg		- decoded message
	outMsg			- output message array
	outMsgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareNetworkLevel(char *clientMac, char *clientIP, char *inMsg, char *outMsg, int outMsgLen)
{
	json_object *root = NULL;
	json_object *inRoot = NULL;
	json_object *rMacObj = NULL;
	char levelBuf[16] = {0}, maxlevelBuf[16] = {0};
	int i = 0;
	unsigned char ea[6] = {0};
	char rMac[18] = {0};

	root = json_object_new_object();

	if (!root) {
		DBG_INFO("root is NULL");
		return 0;
	}

	/* grab real mac form client */
	if (inMsg) {
		DBG_INFO("have real mac (%s)", inMsg);
		inRoot = json_tokener_parse(inMsg);
		if (!inRoot) {
			DBG_INFO("inRoot is NULL");
			json_object_put(root);
			return 0;
		}
		else
		{
			json_object_object_get_ex(inRoot, CFG_STR_MAC, &rMacObj);
			if (rMacObj) {
				snprintf(rMac, sizeof(rMac), "%s", json_object_get_string(rMacObj));
				json_object_put(inRoot);
			}
			else
			{
				DBG_INFO("rMacObj is NULL");
				json_object_put(root);
				json_object_put(inRoot);
				return 0;
			}
		}
	}
	else
	{
		DBG_INFO("no real mac");
		snprintf(rMac, sizeof(rMac), "%s", clientMac);
	}

	DBG_INFO("real mac (%s) for cost request", rMac);

	ether_atoe(rMac, ea);

	pthread_mutex_lock(&cfgLock);
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			DBG_INFO("Find the entry in the table");
			snprintf(levelBuf, sizeof(levelBuf), "%d", p_client_tbl->level[i]);
			break;
		}
	}
	snprintf(maxlevelBuf, sizeof(maxlevelBuf), "%d", p_client_tbl->maxLevel);
	pthread_mutex_unlock(&cfgLock);

	/* prepare max level */
	if (strlen(maxlevelBuf))
		json_object_object_add(root, CFG_STR_MAXLEVEL, json_object_new_string(maxlevelBuf));
	else
		goto err;

	/* prepare level */
	if (strlen(levelBuf))
		json_object_object_add(root, CFG_STR_LEVEL, json_object_new_string(levelBuf));
	else
		goto err;

#ifdef ONBOARDING
	/* prepare timestamp for onboarding */
	json_object_object_add(root, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
#endif

	snprintf(outMsg, outMsgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", outMsg);

err:
	json_object_put(root);

	return strlen(outMsg);
} /* End of cm_prepareNetworkLevel */

/*
========================================================================
Routine Description:
	Prepare the network topology.

Arguments:
	cleintMac		- client's MAC
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareNetworkTopology(char *msg, int msgLen)
{
	struct json_object *root = NULL;
	char costBuf[16] = {0};
	char stamac_2g[32] = {0};
	char stamac_5g[32] = {0};
	char brmac[32] = {0};
	json_object *clientObj = NULL;
	int i = 0;

	root = json_object_new_object();

	if (!root) {
		DBG_INFO("root is NULL");
		return 0;
	}

	pthread_mutex_lock(&cfgLock);
	for(i = 0; i < p_client_tbl->count; i++) {

			clientObj = json_object_new_object();
			if (!clientObj) {
				DBG_ERR("clientObj is NULL");
				continue;
			}

			memset(stamac_2g, 0x00, sizeof(stamac_2g));
			memset(stamac_5g, 0x00, sizeof(stamac_5g));
			memset(brmac, 0x00, sizeof(brmac));
			memset(costBuf, 0x00, sizeof(costBuf));

			snprintf(brmac, sizeof(brmac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0],p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2],p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4],p_client_tbl->realMacAddr[i][5]
			);

			snprintf(stamac_2g, sizeof(stamac_2g), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->sta2g[i][0],p_client_tbl->sta2g[i][1],
			p_client_tbl->sta2g[i][2],p_client_tbl->sta2g[i][3],
			p_client_tbl->sta2g[i][4],p_client_tbl->sta2g[i][5]
			);
			json_object_object_add(clientObj, CFG_STR_STA2G, json_object_new_string(stamac_2g));

			snprintf(stamac_5g, sizeof(stamac_5g), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->sta5g[i][0],p_client_tbl->sta5g[i][1],
			p_client_tbl->sta5g[i][2],p_client_tbl->sta5g[i][3],
			p_client_tbl->sta5g[i][4],p_client_tbl->sta5g[i][5]
			);
			json_object_object_add(clientObj, CFG_STR_STA5G, json_object_new_string(stamac_5g));

			snprintf(costBuf, sizeof(costBuf), "%d", p_client_tbl->level[i]);
			json_object_object_add(clientObj, CFG_STR_COST, json_object_new_string(costBuf));

			//cprintf("%s:%s:%d stamac_2g(%s),stamac_5g(%s), costBuf(%s) \n", __FILE__, __FUNCTION__, __LINE__, stamac_2g, stamac_5g, costBuf);
			json_object_object_add(root, brmac, clientObj);
	}
	pthread_mutex_unlock(&cfgLock);

	snprintf(msg, msgLen, "%s", json_object_to_json_string(root));
	DBG_INFO("msg(%s)", msg);

	json_object_put(root);

	return strlen(msg);
} /* End of cm_prepareNetworkTopology */

/*
========================================================================
Routine Description:
	Send notification to client.

Arguments:
	elem		- hash element for client.
	notifyType	- the content type in the packet
	inData		- data

Return Value:
	0		- fail
	1		- success

========================================================================
*/
static int cm_sendNotification(hash_elem_t* elem, int notifyType, json_object *inData)
{
	int sock = -1;
	struct sockaddr_in sock_addr;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	int clientPort = port;
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	struct timeval timeout = {2, 0};
	int len = 0;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	json_object *outData = NULL;
	unsigned char *sessionKey = NULL;
	int flags;
	int status;
	socklen_t statusLen;
	fd_set writeFds;
	int selectRet;

	DBG_INFO("enter");

	if ((sessionKey = cm_selectSessionKey(elem, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		goto err;
	}

	/* delete client's arp first */
	//eval("arp", "-d", elem->clientIP);
	cm_delClientArp(elem->clientIP);

	memset((char *) &sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET; // host byte order
	sock_addr.sin_port = htons(clientPort); // short, network byte order
	if (inet_aton(elem->clientIP, &sock_addr.sin_addr)==0) {
		DBG_ERR("inet_aton (%s) failed!", elem->clientIP);
		goto err;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		DBG_ERR("Failed to socket create !!!");
		goto err;
	}

	/* set NONBLOCK for connect() */
	if ((flags = fcntl(sock, F_GETFL)) < 0) {
		DBG_ERR("F_GETFL error!");
		goto err;
	}

	flags |= O_NONBLOCK;

	if (fcntl(sock, F_SETFL, flags) < 0) {
		DBG_ERR("F_SETFL error!");
		goto err;
	}

	if (connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
		if (errno == EINPROGRESS) {
			FD_ZERO(&writeFds);
			FD_SET(sock, &writeFds);

			selectRet = select(sock + 1, NULL, &writeFds, NULL, &timeout);

			//Check return, -1 is error, 0 is timeout
			if (selectRet == -1 || selectRet == 0) {
				DBG_ERR("Failed to connect() !!!");
				goto err;
			}
		}
		else
		{
			DBG_ERR("Failed to connect() !!!");
			goto err;
		}
	}

	/* check the status of connect() */
	status = 0;
	statusLen = sizeof(status);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &status, &statusLen) == -1) {
		DBG_ERR("getsockopt(SO_ERROR): %s", strerror(errno));
		goto err;
	}

	if (status) {
		DBG_ERR("error for connect()");
		goto err;
	}

	/* unset NONBLOCK for connect() */
	flags &= ~O_NONBLOCK;
	if (fcntl(sock, F_SETFL, flags) < 0) {
		DBG_ERR("F_SETFL error!");
		goto err;
	}

	DBG_INFO("Connect to %s:%d - OK", elem->clientIP, clientPort);

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
		DBG_ERR("Failed to setsockopt() !!!");
		goto err;
	}

	DBG_INFO("Send notification request(%d) to client ...", notifyType);

	/* fill in notify type and data */
	memset(pPktBuf, 0, sizeof(pPktBuf));
	if (inData)
		outData = json_tokener_parse(json_object_to_json_string(inData));
	else
		outData = json_object_new_object();

	if (!outData) {
		DBG_ERR("outData is NULL");
		goto err;
	}

	json_object_object_add(outData, CFG_STR_NOTIFY_TYPE, json_object_new_int(notifyType));
	snprintf((char *)pPktBuf, MAX_MESSAGE_SIZE, "%s", (char *)json_object_to_json_string_ext(outData, 0));
	json_object_put(outData);

	encryptedMsg = cm_aesEncryptMsg(sessionKey, REQ_NTF, &pPktBuf[0], strlen((char *)pPktBuf) + 1, &encryptedMsgLen);

	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		goto err;
	}

	//if (write(sock, (char*)encryptedMsg, sizeof(TLV_Header)+encryptedMsgLen) <= 0)
	if (send(sock, (char*)encryptedMsg, encryptedMsgLen, 0) <= 0) {
		DBG_ERR("Failed to socket write() !!!");
		if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);
		goto err;
	}

	DBG_LOG("Send notification request(%d) to client(%s) ... OK", notifyType, elem->clientIP);

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	while (1)
	{
		if ((len = recv(sock, pPktBuf, sizeof(pPktBuf), 0)) <= 0)
		{
			DBG_WARNING("Failed to socket read() !!!");
			break;
		}

		if (cm_packetProcess(sock, pPktBuf, len, NULL, NULL, pCtrlBK, NULL) == 1)
			break;
	}

	close(sock);
	return 1;

err:
	if (sock >= 0)
		close(sock);
	DBG_LOG("Send notification request(%d) to client(%s) ... Failed", notifyType, elem->clientIP);
	DBG_INFO("leave");
	return 0;

} /* End of cm_sendNotification */

/*
========================================================================
Routine Description:
	Send notification by input notify type.

Arguments:
	notifyType      - notify type
	inData		- data

Return Value:
	None

Note:
========================================================================
*/
void cm_sendNotificationByType(int notifyType, json_object *inData)
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 0; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		if (i == 0 && is_router_mode())
			continue;

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));

		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification */
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s)", e->clientIP, e->key);
				if (!cm_sendNotification(e, notifyType, inData))
					DBG_INFO("send notification (%d) to %s failed", notifyType, e->clientIP);
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_resetFirmwareStatus */

/*
========================================================================
Routine Description:
	Reset firmware check/upgrade status.

Arguments:
	notifyType      - notify type

Return Value:
	None

Note:
========================================================================
*/
void cm_resetFirmwareStatus(int notifyType)
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification */
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s)", e->clientIP, e->key);
				if (!cm_sendNotification(e, notifyType, NULL))
					DBG_INFO("send notification (%d) to %s failed", notifyType, e->clientIP);
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_resetFirmwareStatus */

/*
========================================================================
Routine Description:
	Send notification of firmware check and record which client need
	to check firmware.
	To sync nvram webs_update_enable | webs_update_beta for RE
	To sync webs_update_ts for RE if webs_update_beta was changed

Arguments:
	NONE

Return Value:
	ret		- the number of client need to check firmware

Note:
========================================================================
*/
int cm_sendFirmwareCheck()
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	int ret = 0;
	json_object *infoObj = json_object_new_object();
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	if (infoObj){
#if defined(RTCONFIG_AUTO_FW_UPGRAD)
		json_object_object_add(infoObj, "auto_upgrade_enable", json_object_new_string(nvram_safe_get("webs_update_enable")));
#endif
#if defined(RTCONFIG_BETA_UPGRADE)
		json_object_object_add(infoObj, "beta_path", json_object_new_string(nvram_safe_get("webs_update_beta")));
		json_object_object_add(infoObj, "update_ts", json_object_new_string(nvram_safe_get("webs_update_ts")));
#endif		
	}
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification of firmware check */
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s)", e->clientIP, e->key);
				e->fwStatus = FW_NONE;
				if (cm_sendNotification(e, NOTIFY_FWCHECK, infoObj)) {  /* ask client to do firmware check */
					e->fwStatus = FW_START;
					ret++;
				}
			}
			e = ht_iterate_elem(&it);
		}
	}
	json_object_put(infoObj);
	pthread_mutex_unlock(&cfgLock);
	return ret;
} /* End of cm_sendFirmwareCheck */

/*
========================================================================
Routine Description:
	Send notification of firmware download and record which client
	need to download firmware.

Arguments:
	NONE

Return Value:
	ret		- the number of client need to check firmware

Note:
========================================================================
*/
int cm_sendFirmwareDownload()
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	int ret = 0;
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification of firmware download */
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s), fw status(%d)", e->clientIP, e->key, e->fwStatus);
				if (e->fwStatus == FW_SUCCESS_CHECK) {
					e->fwStatus = FW_NONE;
					if (cm_sendNotification(e, NOTIFY_FWDOWNLOAD, NULL)) { /* ask client to do firmware download */
						e->fwStatus = FW_START;
						ret++;
					}
				}
				else
					e->fwStatus = FW_NONE;
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);

	return ret;
} /* End of cm_sendFirmwareDownload */

/*
========================================================================
Routine Description:
	Clean the last new firmware version.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_cleanFirmwareVersionInfo()
{
	int i = 0;
	int lock;

	pthread_mutex_lock(&cfgLock);
	lock = file_lock(CFG_FILE_LOCK);
	for (i = 0; i < p_client_tbl->count; i++) {
		memset(p_client_tbl->newFwVer[i], 0, sizeof(p_client_tbl->newFwVer[i]));
		memset(p_client_tbl->frsModelName[i], 0, sizeof(p_client_tbl->frsModelName[i]));
	}
	file_unlock(lock);
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_cleanFirmwareVersionInfo */

/*
========================================================================
Routine Description:
	Handle firmware check.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_handleFirmwareCheck()
{
	int i = 1;
	int j = 0;
	int l = 0;
	int clientNum = 0;
	hashtable_t* hasht = clientHashTable;
	hash_elem_t* e = NULL;
	char mac[18] = {0};
	char ip[18] = {0};

	if (nvram_get_int("cfg_check") == FW_START) {
		DBG_INFO("firmware check is running, skip this request.");
		return;
	}

	/* reset cfg_check as FW_START */
	nvram_set_int("cfg_check", FW_START);

	/* reset cfg_fwstatus as FW_START */
	nvram_set_int("cfg_fwstatus", FW_START);

	/* reset status for firmware check first */
	DBG_INFO("reset status for firmware check");
	cm_resetFirmwareStatus(NOTIFY_CANCELFWCHECK);
	cm_cancelFirmwareCheck();

	cm_ctrlBlock.flagIsFirmwareCheck = 1;

	cm_cleanFirmwareVersionInfo();	/* clean info of last firmware version */
	cm_doFirmwareCheck(NULL);
	clientNum = cm_sendFirmwareCheck();

	DBG_INFO("number of client need to firmware check (%d)", clientNum);

	while (1) {
		if (!cm_ctrlBlock.flagIsFirmwareCheck)
			break;

		/* send the notification of firmware status */
		if (clientNum) {
			if ((i % TIMES_FW_CHECK) == 0) {
				pthread_mutex_lock(&cfgLock);
				for (j = 1; j < p_client_tbl->count; j++) {
					hash_elem_it it = HT_ITERATOR(hasht);
					e = ht_iterate_elem(&it);

					memset(mac, 0, sizeof(mac));
					memset(ip, 0, sizeof(ip));
					snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
						p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
						p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
						p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

					snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
						p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
						p_client_tbl->ipAddr[j][3]);

					if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						DBG_INFO("%s (%s) is offline", mac, ip);
						continue;
					}

					while(e != NULL) {
						if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
							strcmp(ip, e->clientIP) == 0)
						{
							DBG_INFO("client ip(%s), client mac(%s), status(%d)", e->clientIP, e->key, e->fwStatus);

							/* ask client to report the status of firmware check */
		                                        if (e->fwStatus == FW_START || e->fwStatus == FW_IS_CHECKING) {
								if (!cm_sendNotification(e, NOTIFY_FWCHECKSTATUS, NULL))
									e->fwStatus = FW_NONE;
							}
						}
						e = ht_iterate_elem(&it);
					}
				}
				pthread_mutex_unlock(&cfgLock);
			}
			else
			{
				int status = FW_MAX;
				int fwNotify = 0;
				int fwStartStatus = 0;

				pthread_mutex_lock(&cfgLock);
				for (j = 1; j < p_client_tbl->count; j++) {
					hash_elem_it it = HT_ITERATOR(hasht);
					e = ht_iterate_elem(&it);

					memset(mac, 0, sizeof(mac));
					memset(ip, 0, sizeof(ip));
					snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
						p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
						p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
						p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

					snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
						p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
						p_client_tbl->ipAddr[j][3]);

					if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						DBG_INFO("%s (%s) is offline", mac, ip);
						continue;
					}

					/* check status for all clients */
					while(e != NULL) {
						if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
							strcmp(ip, e->clientIP) == 0)
						{
							DBG_INFO("check client ip(%s), client mac(%s), status(%d)", e->clientIP, e->key, e->fwStatus);

							if (e->fwStatus > FW_START && e->fwStatus < status)
								status = e->fwStatus;
							else if (e->fwStatus == FW_START)
								fwStartStatus = 1;
						}
						e = ht_iterate_elem(&it);
					}
				}
				pthread_mutex_unlock(&cfgLock);

				/* check status for server */
				if (nvram_get_int("cfg_fwstatus") > FW_START &&
					nvram_get_int("cfg_fwstatus") < status)
					status = nvram_get_int("cfg_fwstatus");
				else if (nvram_get_int("cfg_fwstatus") == FW_START)
					fwStartStatus = 1;

				if (!strcmp(nvram_safe_get("cfg_fwdbg"), "1"))
					DBG_INFO("status(%d) fwStartStatus(%d)", status, fwStartStatus);

				/* check final fw status and do something */
				if (status >= FW_FAIL_RETRIEVE && status <= FW_IS_WRONG)
					fwNotify = NOTIFY_CANCELFWCHECK;
				else
				{
					if (fwStartStatus) {
						status = FW_START;
						fwNotify = FW_NONE;
					}
					else if (status == FW_SUCCESS_CHECK ||
						status == FW_NO_NEED_UPGRADE)
						fwNotify = NOTIFY_FWCHECKSUCCESS;
				}

				if (fwNotify) {
					DBG_INFO("fwNotify(%d) for firmware check", fwNotify);

					pthread_mutex_lock(&cfgLock);
					for (l = p_client_tbl->maxLevel; l >= 0; l--) {
						for (j = 1; j < p_client_tbl->count; j++) {
							hash_elem_it it1 = HT_ITERATOR(hasht);
							e = ht_iterate_elem(&it1);

							if (p_client_tbl->level[j] != l)
								continue;

							memset(mac, 0, sizeof(mac));
							memset(ip, 0, sizeof(ip));
							snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
								p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
								p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
								p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

							snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
								p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
								p_client_tbl->ipAddr[j][3]);

							if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
								DBG_INFO("%s (%s) is offline", mac, ip);
								continue;
							}

							while(e != NULL) {
								/* send notification to all clients */
								if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
									strcmp(ip, e->clientIP) == 0)
								{
									DBG_INFO("client ip(%s), client mac(%s)", e->clientIP, e->key);
									if (!cm_sendNotification(e, fwNotify, NULL))
										DBG_ERR("send notification to %s failed", e->clientIP);
								}
								e = ht_iterate_elem(&it1);
							}
						}
					}
					pthread_mutex_unlock(&cfgLock);

					if (fwNotify == NOTIFY_CANCELFWCHECK) {
						nvram_set_int("cfg_check", status);
						cm_cancelFirmwareCheck();
					}
					else if (fwNotify == NOTIFY_FWCHECKSUCCESS) {
						nvram_set_int("cfg_check", status);
						cm_checkFirmwareSuccess();
					}

					break;
				}
				else
					nvram_set_int("cfg_check", status);
			}

			i++;
		}
		else
		{
			if (nvram_get_int("cfg_fwstatus") > FW_START) {
                                nvram_set_int("cfg_check", nvram_get_int("cfg_fwstatus"));
				cm_ctrlBlock.flagIsFirmwareCheck = 0;
				break;
			}
		}

		sleep(1);
	}
} /* End of cm_handleFirmwareCheck */

/*
========================================================================
Routine Description:
	Handle firmware download.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_handleFirmwareDownload()
{
	int i = 1;
	int j = 0;
	int l = 0;
	int clientNum = 0;
	hashtable_t* hasht = clientHashTable;
	hash_elem_t* e = NULL;
	int status = FW_MAX;
	char mac[18] = {0};
	char ip[18] = {0};

	/* reset cfg_upgrade as FW_START */
	nvram_set_int("cfg_upgrade", FW_START);

	/* reset cfg_fwstatus as FW_START */
	nvram_set_int("cfg_fwstatus", FW_START);

	/* reset status for firmwar upgrade first */
	DBG_INFO("reset status for firmware upgrade");
	cm_resetFirmwareStatus(NOTIFY_CANCELFWCHECK);
	cm_cancelFirmwareCheck();

	cm_ctrlBlock.flagIsFirmwareCheck = 1;

	cm_doFirmwareDownload();
	clientNum = cm_sendFirmwareDownload();

	DBG_INFO("number of client need to firmware download (%d)", clientNum);

	while (1) {
		if (!cm_ctrlBlock.flagIsFirmwareCheck)
			break;

		/* send the notification of firmware status */
		if (clientNum) {
			if ((i % TIMES_FW_CHECK) == 0) {
				pthread_mutex_lock(&cfgLock);
				for (j = 1; j < p_client_tbl->count; j++) {
					hash_elem_it it = HT_ITERATOR(hasht);
					e = ht_iterate_elem(&it);

					memset(mac, 0, sizeof(mac));
					memset(ip, 0, sizeof(ip));
					snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
						p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
						p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
						p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

					snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
						p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
						p_client_tbl->ipAddr[j][3]);

					if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						DBG_INFO("%s (%s) is offline", mac, ip);
						continue;
					}

					while(e != NULL) {
						if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
							strcmp(ip, e->clientIP) == 0)
						{
							DBG_INFO("client ip(%s), client mac(%s), status(%d)", e->clientIP, e->key, e->fwStatus);

							/* ask client to report firmware status */
		                                        if (e->fwStatus == FW_START || e->fwStatus == FW_IS_DOWNLOADING) {
								if (!cm_sendNotification(e, NOTIFY_FWDOWNLOADSTATUS, NULL))
									e->fwStatus = FW_NONE;
							}
						}
						e = ht_iterate_elem(&it);
					}
				}
				pthread_mutex_unlock(&cfgLock);
			}
			else
			{
				int fwNotify = 0;
				int fwStartStatus = 0;
				status = FW_MAX;

				pthread_mutex_lock(&cfgLock);
				for (j = 1; j < p_client_tbl->count; j++) {
					hash_elem_it it = HT_ITERATOR(hasht);
					e = ht_iterate_elem(&it);

					memset(mac, 0, sizeof(mac));
					memset(ip, 0, sizeof(ip));
					snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
						p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
						p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
						p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

					snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
						p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
						p_client_tbl->ipAddr[j][3]);

					if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						DBG_INFO("%s (%s) is offline", mac, ip);
						continue;
					}

					/* check status for all clients */
					while(e != NULL) {
						if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
							strcmp(ip, e->clientIP) == 0)
						{
							DBG_INFO("check client ip(%s), client mac(%s), status(%d)", e->clientIP, e->key, e->fwStatus);

							if (e->fwStatus > FW_START && e->fwStatus < status)
								status = e->fwStatus;
							else if (e->fwStatus == FW_START)
								fwStartStatus = 1;
						}
						e = ht_iterate_elem(&it);
					}
				}
				pthread_mutex_unlock(&cfgLock);

				/* check status for server */
				if (nvram_get_int("cfg_fwstatus") > FW_START &&
					nvram_get_int("cfg_fwstatus") < status)
					status = nvram_get_int("cfg_fwstatus");
				else if (nvram_get_int("cfg_fwstatus") == FW_START)
					fwStartStatus = 1;


				if (!strcmp(nvram_safe_get("cfg_fwdbg"), "1"))
					DBG_INFO("status(%d) fwStartStatus(%d)", status, fwStartStatus);

				/* check final fw status and do something */
				if (status >= FW_FAIL_RETRIEVE && status <= FW_IS_WRONG)
					fwNotify = NOTIFY_CANCELFWUPGRADE;
				else
				{
					if (fwStartStatus) {
						status = FW_START;
						fwNotify = FW_NONE;
					}
					else if (status == FW_SUCCESS_DOWNLOAD)
						fwNotify = NOTIFY_FWUPGRADE;
				}

				if (fwNotify) {
					DBG_INFO("fwNotify(%d) for firmware download", fwNotify);

					pthread_mutex_lock(&cfgLock);
					for (l = p_client_tbl->maxLevel; l >= 0; l--) {
						for (j = 1; j < p_client_tbl->count; j++) {
							hash_elem_it it1 = HT_ITERATOR(hasht);
							e = ht_iterate_elem(&it1);

							if (p_client_tbl->level[j] != l)
								continue;

							memset(mac, 0, sizeof(mac));
							memset(ip, 0, sizeof(ip));
							snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
								p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
								p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
								p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

							snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
								p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
								p_client_tbl->ipAddr[j][3]);

							if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
								DBG_INFO("%s (%s) is offline", mac, ip);
								continue;
							}

							while(e != NULL) {
								/* send notification to all clients */
								if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
									strcmp(ip, e->clientIP) == 0)
								{
									DBG_INFO("client ip(%s), client mac(%s)", e->clientIP, e->key);
									if (!cm_sendNotification(e, fwNotify, NULL))
										DBG_ERR("send notification to %s failed", e->clientIP);
								}
								e = ht_iterate_elem(&it1);
							}
						}
					}
					pthread_mutex_unlock(&cfgLock);

					if (fwNotify == NOTIFY_CANCELFWUPGRADE) {
						nvram_set_int("cfg_check", FW_NONE);
						nvram_set_int("cfg_upgrade", status);
						cm_cancelFirmwareUpgrade();
					}
					else if (fwNotify == NOTIFY_FWUPGRADE) {
						nvram_set_int("cfg_check", FW_NONE);
						nvram_set_int("cfg_upgrade", FW_DO_UPGRADE);
						cm_upgradeFirmware();
					}

					break;
				}
				else
					nvram_set_int("cfg_upgrade", status);
			}

			i++;
		}
		else
		{
			if (nvram_get_int("cfg_fwstatus") > FW_START &&
				nvram_get_int("cfg_fwstatus") < status)
				status = nvram_get_int("cfg_fwstatus");

			/* check final fw status and do something */
			if ((status >= FW_FAIL_RETRIEVE && status <= FW_IS_WRONG) ||
				status == FW_NO_NEED_UPGRADE) {
				nvram_set_int("cfg_check", FW_NONE);
				DBG_INFO("firmware status for download (%d)", status);
				nvram_set_int("cfg_upgrade", status);
				cm_cancelFirmwareUpgrade();
				break;
			}
			else
			{
				if (nvram_get_int("cfg_fwstatus") > FW_NONE) {
					nvram_set_int("cfg_upgrade", nvram_get_int("cfg_fwstatus"));
					if (nvram_get_int("cfg_fwstatus") == FW_SUCCESS_DOWNLOAD) {
						nvram_set_int("cfg_check", FW_NONE);
						nvram_set_int("cfg_upgrade", FW_DO_UPGRADE);
						cm_upgradeFirmware();
					}
				}
			}
		}

		sleep(1);
	}
} /* End of cm_handleFirmwareDownload */

/*
========================================================================
Routine Description:
	Remove slave's info.

Arguments:
	*mac		- slave's mac

Return Value:
	None

Note:
========================================================================
*/
void cm_removeSlave(char *mac)
{
	int i = 0;
	int j = 0;
	int found = -1;
	unsigned char ea[6] = {0};
	int lock;
	json_object *reListObj = NULL;
#ifdef RTCONFIG_BCN_RPT
	json_object *APListObj = NULL;
#endif
	char realMac[18] = {0};
	char sta2gMac[18] = {0}, sta5gMac[18] = {0}, sta6gMac[18] = {0};
	char ip[18] = {0};

	ether_atoe(mac, ea);

	pthread_mutex_lock(&cfgLock);
	lock = file_lock(CFG_FILE_LOCK);

	/* search slave based on mac */
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			snprintf(realMac, sizeof(realMac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
							p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
							p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);
			snprintf(sta2gMac, sizeof(sta2gMac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->sta2g[i][0], p_client_tbl->sta2g[i][1],
							p_client_tbl->sta2g[i][2], p_client_tbl->sta2g[i][3],
							p_client_tbl->sta2g[i][4], p_client_tbl->sta2g[i][5]);
			snprintf(sta5gMac, sizeof(sta5gMac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->sta5g[i][0], p_client_tbl->sta5g[i][1],
							p_client_tbl->sta5g[i][2], p_client_tbl->sta5g[i][3],
							p_client_tbl->sta5g[i][4], p_client_tbl->sta5g[i][5]);
			snprintf(sta6gMac, sizeof(sta6gMac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->sta6g[i][0], p_client_tbl->sta6g[i][1],
							p_client_tbl->sta6g[i][2], p_client_tbl->sta6g[i][3],
							p_client_tbl->sta6g[i][4], p_client_tbl->sta6g[i][5]);
			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
				p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
				p_client_tbl->ipAddr[i][3]);
			DBG_INFO("Find the slave (%s) in the table", realMac);
			found = i;
			break;
		}
	}

	/* remove slave */
	if (found >= 0) {
		/* remove slave on hashtable */
		ht_remove(clientHashTable, mac, ip);

		for(i = found; i < p_client_tbl->count; i++) {
			if (i == (CFG_CLIENT_NUM - 1))
				break;
			j = i + 1;
			memcpy(p_client_tbl->alias[i], p_client_tbl->alias[j], ALIAS_LEN);
			memcpy(p_client_tbl->ipAddr[i], p_client_tbl->ipAddr[j], IP_LEN);
			memcpy(p_client_tbl->macAddr[i], p_client_tbl->macAddr[j], MAC_LEN);
			memcpy(p_client_tbl->realMacAddr[i], p_client_tbl->realMacAddr[j], MAC_LEN);
			p_client_tbl->reportStartTime[i] = p_client_tbl->reportStartTime[j];
			memcpy(p_client_tbl->pap2g[i], p_client_tbl->pap2g[j], MAC_LEN);
			memcpy(p_client_tbl->pap5g[i], p_client_tbl->pap5g[j], MAC_LEN);
			memcpy(p_client_tbl->pap6g[i], p_client_tbl->pap6g[j], MAC_LEN);
			p_client_tbl->rssi2g[i] =  p_client_tbl->rssi2g[j];
			p_client_tbl->rssi5g[i] =  p_client_tbl->rssi5g[j];
			p_client_tbl->rssi6g[i] =  p_client_tbl->rssi6g[j];
			memcpy(p_client_tbl->sta2g[i], p_client_tbl->sta2g[j], MAC_LEN);
			memcpy(p_client_tbl->sta5g[i], p_client_tbl->sta5g[j], MAC_LEN);
			memcpy(p_client_tbl->sta6g[i], p_client_tbl->sta6g[j], MAC_LEN);
			memcpy(p_client_tbl->ap2g[i], p_client_tbl->ap2g[j], MAC_LEN);
			memcpy(p_client_tbl->ap5g[i], p_client_tbl->ap5g[j], MAC_LEN);
			memcpy(p_client_tbl->ap5g1[i], p_client_tbl->ap5g1[j], MAC_LEN);
			memcpy(p_client_tbl->ap6g[i], p_client_tbl->ap6g[j], MAC_LEN);
			memcpy(p_client_tbl->fwVer[i], p_client_tbl->fwVer[j], FWVER_LEN);
			memcpy(p_client_tbl->modelName[i], p_client_tbl->modelName[j], MODEL_NAME_LEN);
			memcpy(p_client_tbl->productId[i], p_client_tbl->productId[j], MODEL_NAME_LEN);
			memcpy(p_client_tbl->territoryCode[i], p_client_tbl->territoryCode[j], TERRITORY_CODE_LEN);
			p_client_tbl->bandnum[i] =  p_client_tbl->bandnum[j];
			p_client_tbl->level[i] = p_client_tbl->level[j];
			p_client_tbl->activePath[i] = p_client_tbl->activePath[j];
			p_client_tbl->online[i] = p_client_tbl->online[j];
			memcpy(p_client_tbl->ap2g_ssid[i], p_client_tbl->ap2g_ssid[j], SSID_LEN);
			memcpy(p_client_tbl->ap5g_ssid[i], p_client_tbl->ap5g_ssid[j], SSID_LEN);
			memcpy(p_client_tbl->ap5g1_ssid[i], p_client_tbl->ap5g1_ssid[j], SSID_LEN);
			memcpy(p_client_tbl->ap6g_ssid[i], p_client_tbl->ap6g_ssid[j], SSID_LEN);
			memcpy(p_client_tbl->ap2g_fh[i], p_client_tbl->ap2g_fh[j], MAC_LEN);
			memcpy(p_client_tbl->ap5g_fh[i], p_client_tbl->ap5g_fh[j], MAC_LEN);
			memcpy(p_client_tbl->ap5g1_fh[i], p_client_tbl->ap5g1_fh[j], MAC_LEN);
			memcpy(p_client_tbl->ap6g_fh[i], p_client_tbl->ap6g_fh[j], MAC_LEN);
			memcpy(p_client_tbl->ap2g_ssid_fh[i], p_client_tbl->ap2g_ssid_fh[j], SSID_LEN);
			memcpy(p_client_tbl->ap5g_ssid_fh[i], p_client_tbl->ap5g_ssid_fh[j], SSID_LEN);
			memcpy(p_client_tbl->ap5g1_ssid_fh[i], p_client_tbl->ap5g1_ssid_fh[j], SSID_LEN);
			memcpy(p_client_tbl->ap6g_ssid_fh[i], p_client_tbl->ap6g_ssid_fh[j], SSID_LEN);
		}
		p_client_tbl->count--;
#ifdef RTCONFIG_BCN_RPT
		/* checking RE wether exist Tri band */
		for(i = 0; i < p_client_tbl->count; i++) {
			if(p_client_tbl->bandnum[i] > 2)
				break;
		}
		if(i == p_client_tbl->count) {
			channel5g = 0;
			selected5gBand = NO_SELECTION;
#ifdef RTCONFIG_NBR_RPT
			nvram_unset("r_selected5gband");
#endif
			nvram_unset("multi_channel_5g");
		}
#endif
		if (p_client_tbl->count == 1)
			nvram_set_int("cfg_rejoin", 0);
		DBG_LOG("remove re (%s)", mac);
	}

	file_unlock(lock);
	pthread_mutex_unlock(&cfgLock);

	/* update the status of re join */
	cm_updateReJoinStatus();

#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
	/* update region UI disabled/enabled */
	cm_checkTerritoryCode();

	/* remove chanspec */
	cm_removeChanspecByMac(mac);

	/* remove wireless client */
	cm_removeWirelessClientListByMac(mac);

	/* remove wired client */
	cm_removeWireledClientListByMac(mac);

	/* remove re lsit */
	if (found >= 0) {
		cm_updateTribandReList(realMac, 0, NULL, RELIST_DEL, 0);
		cm_updateReList(realMac, sta2gMac, sta5gMac, sta6gMac, RELIST_DEL);
		if ((reListObj = json_object_from_file(RE_LIST_JSON_FILE)) != NULL) {
			cm_sendNotificationByType(NOTIFY_UPDATERELIST, reListObj);
			json_object_put(reListObj);
			wl_set_macfilter_list();
		}
#ifdef RTCONFIG_BCN_RPT
		cm_updateAPList();
		if ((APListObj = json_object_from_file(AP_LIST_JSON_FILE)) != NULL) {
			cm_sendNotificationByType(NOTIFY_UPDATEAPLIST, APListObj);
			json_object_put(APListObj);
		}
#endif
#ifdef STA_BIND_AP
		cm_updateStaBindingAp(1, mac);
#endif
	}
	} /* !wifison_ready */
}

/*
========================================================================
Routine Description:
	Delete slave releated file.

Arguments:
	mac		- slave's mac

Return Value:
	None

Note:
========================================================================
*/
void cm_removeSlaveRelatedFiles(char *mac)
{
	char filePath[64] = {0};

	/* remove private config file for slave */
	snprintf(filePath, sizeof(filePath), "%s/%s.json", TEMP_ROOT_PATH, mac);
	if (f_exists(filePath)) {
		DBG_INFO("private config (%s) is removed", filePath);
		unlink(filePath);
	}

	/* remove capability file for slave */
	snprintf(filePath, sizeof(filePath), "%s/%s.cap", TEMP_ROOT_PATH, mac);
	if (f_exists(filePath)) {
		DBG_INFO("capability file (%s) is removed", filePath);
		unlink(filePath);
	}

	/* remove wired port status for slave */
	snprintf(filePath, sizeof(filePath), "%s/%s.port", TEMP_ROOT_PATH, mac);
	if (f_exists(filePath)) {
		DBG_INFO("wired port status file (%s) is removed", filePath);
		unlink(filePath);
	}

	/* remove misc info file for slave */
	snprintf(filePath, sizeof(filePath), "%s/%s.misc", TEMP_ROOT_PATH, mac);
	if (f_exists(filePath)) {
		DBG_INFO("misc info file (%s) is removed", filePath);
		unlink(filePath);
	}

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	/* remove private config mnt for slave */
	snprintf(filePath, sizeof(filePath), CFG_MNT_FOLDER"%s.json", mac);
	if (f_exists(filePath)) {
		DBG_INFO("private config mnt (%s) is removed", filePath);
		unlink(filePath);
	}

	/* remove private rule mnt for slave */
	snprintf(filePath, sizeof(filePath), CFG_MNT_FOLDER"%s.rule", mac);
	if (f_exists(filePath)) {
		DBG_INFO("private rule mnt (%s) is removed", filePath);
		unlink(filePath);
	}
#endif

	/* remove band info file for slave */
	snprintf(filePath, sizeof(filePath), "%s/%s.bi", TEMP_ROOT_PATH, mac);
	if (f_exists(filePath)) {
		DBG_INFO("band info file (%s) is removed", filePath);
		unlink(filePath);
	}
}/* End of cm_removeSlaveRelatedFiles */

/*
========================================================================
Routine Description:
        Send event w/ reset default to the client.

Arguments:
        *mac            - slave's mac

Return Value:
        None

Note:
========================================================================
*/
void cm_resetDefault(char *mac)
{
	int i = 0;
	unsigned char ea[6] = {0};
	char ipStr[18] = {0};
	char macStr[18] = {0};
	int found = 0;
	int reObSuccessCount = nvram_get_int("cfg_obcount");

	if (mac) {
		if (strlen(mac) > 0) {	/* for remove re */
			ether_atoe(mac, ea);

			pthread_mutex_lock(&cfgLock);

			/* search slave based on mac */
			for(i = 0; i < p_client_tbl->count; i++) {
		                if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
					DBG_INFO("Find the same MAC in the table");
					found = 1;
					snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
						p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
						p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
						p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

					snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
						p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
						p_client_tbl->ipAddr[i][3]);
					break;
				}
			}

			pthread_mutex_unlock(&cfgLock);

			if (found) {
				hash_elem_t* e = NULL;

				if ((e = ht_get(clientHashTable, macStr, ipStr))) {
					if (!cm_sendNotification(e, NOTIFY_RESETDEFAULT, NULL))
						DBG_ERR("send notification to %s failed", e->clientIP);

					cm_removeSlave(mac);

					if (reObSuccessCount > 0) {
						nvram_set_int("cfg_obcount", --reObSuccessCount);
						nvram_commit();
					}
				}
			}
			cm_removeSlaveRelatedFiles(mac);
#ifdef RTCONFIG_DWB
			cm_AutoDetect_Dedicated_Wifi_Backhaul(1, 1);
			if (dwb_reSync) {
				cm_usr2Handle(-1);  // Notify re to resync and don't do cm_AutoDetect_Dedicated_Wifi_Backhaul(1) again.
				dwb_reSync = 0;
			}
#endif
		}
		else		/* reset default for cap and all re */
		{
			/* notify all re first */
			cm_sendNotificationByType(NOTIFY_RESETDEFAULT, NULL);

			/* cap do reset default */
			notify_rc("resetdefault");
		}
	}
} /* End of cm_resetDefault */

/*
========================================================================
Routine Description:
        Nofity which slave's config changed via web.

Arguments:
        *mac            - slave's mac for config changed.

Return Value:
        None

Note:
========================================================================
*/
void cm_notifyConfigChanged(char *mac)
{
	int i = 0;
	unsigned char ea[6] = {0};
	char ipStr[18] = {0};
	char macStr[18] = {0};
	int found = 0;
	char slaveCfgPath[64] = {0};
	hash_elem_t* e = NULL;
	json_object *fileRoot = NULL;
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	int updateAction = 0, paramLen = 0;
	char *service = NULL, actionScript[128], param[64];
	json_object *paramObj = NULL, *paramArrayObj = NULL, *paramEntry = NULL;
#endif

	snprintf(slaveCfgPath, sizeof(slaveCfgPath), "/tmp/%s.json", mac);

	ether_atoe(mac, ea);

	pthread_mutex_lock(&cfgLock);

	/* search slave based on mac */
	for(i = 0; i < p_client_tbl->count; i++) {
                if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			DBG_INFO("Find the same MAC in the table");

			memset(macStr, 0, sizeof(macStr));
			memset(ipStr, 0, sizeof(ipStr));

			snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
				p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
				p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

			snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
				p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
				p_client_tbl->ipAddr[i][3]);

			if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
				DBG_INFO("%s (%s) is offline", macStr, ipStr);
				continue;
			}

			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&cfgLock);

	if (found) {
		fileRoot = json_object_from_file(slaveCfgPath);
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
		paramArrayObj = json_object_new_array();
#endif

		if (fileRoot
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
			&& paramArrayObj
#endif
		) {
#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
			json_object_object_foreach(fileRoot, fileKey, fileVal) {
				updateAction = 0;
				memset(actionScript, 0, sizeof(actionScript));
				paramObj = fileVal;
				json_object_object_foreach(paramObj, paramKey, paramVal) {
					/* record the parameter to update commaon config */
					if (cm_checkParamFollowRule(mac, paramKey, FOLLOW_CAP)) {
						json_object_array_add(paramArrayObj, json_object_new_string(paramKey));
					}

					/* record action script */
					if ((service = cm_findServiceByParam(paramKey))) {
						if (strlen(service) && !strstr(actionScript, service)) {
							if (strlen(actionScript))
								strlcat(actionScript, ";", sizeof(actionScript));
							strlcat(actionScript, service, sizeof(actionScript));
							updateAction = 1;
						}
					}
				}

				/* update action script to fileRoot */
				if (updateAction) {
					DBG_INFO("update action script (%s)", actionScript);
					json_object_object_del(fileVal, CFG_ACTION_SCRIPT);
					json_object_object_add(fileVal, CFG_ACTION_SCRIPT,
						json_object_new_string(actionScript));
				}
			}

			/* update value based on paramArrayObj */
			paramLen = json_object_array_length(paramArrayObj);
			if (paramLen > 0) {
				json_object_object_foreach(fileRoot, fileKey, fileVal) {
					for (i = 0; i < paramLen; i++) {
						if ((paramEntry = json_object_array_get_idx(paramArrayObj, i))) {
							strlcpy(param, json_object_get_string(paramEntry), sizeof(param));
							json_object_object_get_ex(fileVal, param, &paramObj);
							if (paramObj) {
								/* need to update common config follow CAP */
								json_object_object_add(fileVal, param,
									json_object_new_string(nvram_safe_get(param)));
							}
						}
					}
				}
			}

			json_object_put(paramArrayObj);
#endif

			/* add cfg ver */
			json_object_object_add(fileRoot, CFG_STR_CFGVER, json_object_new_string(nvram_safe_get("cfg_ver")));
			json_object_object_add(fileRoot, CFG_STR_CFGALL, json_object_new_string(""));

			if ((e = ht_get(clientHashTable, macStr, ipStr))) {
				if (!cm_sendNotification(e, NOTIFY_CFGCHANGED, fileRoot))
					DBG_ERR("send notification to %s failed", e->clientIP);
			}
		}

		json_object_put(fileRoot);
	}
} /* End of cm_notifyConfigChanged */

#ifdef ONBOARDING
/*
========================================================================
Routine Description:
        Send event w/ onboarding to the client.

Arguments:
        None

Return Value:
        None

Note:
========================================================================
*/
void cm_sendOnboardingMsg(json_object *data)
{
	cm_sendNotificationByType(NOTIFY_ONBOARDING, data);
} /* End of cm_sendOnboardingMsg */

/*
========================================================================
Routine Description:
        Select best RE for onboarding.

Arguments:
        *newReMac		- new re mac
        *rssi		- rssi
        obPath		- onboarding path
        *rTime		- reboot time
        *cTimeout	- connection timeout
        *tTimeout		- traffic timeout

Return Value:
        reMac		- the best RE for onboarding.

Note:
========================================================================
*/
char *cm_selectBestOnboardingRe(char *newReMac, int *rssi, int obPath, int *rTime, int *cTimeout, int *tTimeout)
{
	json_object *obListObj = NULL;
	json_object *reObj = NULL;
	json_object *newReObj = NULL;
	json_object *rssiObj = NULL;
	json_object *sourceObj = NULL;
	json_object *rTimeObj = NULL, *cTimeoutObj = NULL, *tTimeoutObj = NULL;
	static char reMac[18];

	pthread_mutex_lock(&onboardingLock);

	obListObj = json_object_from_file(ONBOARDING_LIST_JSON_PATH);
	memset(reMac, 0, sizeof(reMac));

	if (obListObj) {
		json_object_object_foreach(obListObj, key, val) {
			reObj = val;

			json_object_object_get_ex(reObj, newReMac, &newReObj);
			if (newReObj) {
				json_object_object_get_ex(newReObj, CFG_STR_RSSI, &rssiObj);
				json_object_object_get_ex(newReObj, CFG_STR_SOURCE, &sourceObj);
				json_object_object_get_ex(newReObj, CFG_STR_REBOOT_TIME, &rTimeObj);
				json_object_object_get_ex(newReObj, CFG_STR_CONN_TIMEOUT, &cTimeoutObj);
				json_object_object_get_ex(newReObj, CFG_STR_TRAFFIC_TIMEOUT, &tTimeoutObj);
				if (*rssi <= json_object_get_int(rssiObj)) {
					snprintf(reMac, sizeof(reMac), "%s", key);
					*rssi = json_object_get_int(rssiObj);

					if (rTimeObj) *rTime = json_object_get_int(rTimeObj);
					if (cTimeoutObj) *cTimeout = json_object_get_int(cTimeoutObj);
					if (tTimeoutObj) *tTimeout = json_object_get_int(tTimeoutObj);
				}

				if (((obPath & FROM_ETHERNET) == FROM_ETHERNET) &&
					((json_object_get_int(sourceObj) & FROM_ETHERNET) == FROM_ETHERNET)) {
					snprintf(reMac, sizeof(reMac), "%s", key);
					DBG_INFO("obPath (%d), reMac (%s)", obPath , reMac);

					if (rTimeObj) *rTime = json_object_get_int(rTimeObj);
					if (cTimeoutObj) *cTimeout = json_object_get_int(cTimeoutObj);
					if (tTimeoutObj) *tTimeout = json_object_get_int(tTimeoutObj);
					break;
				}
			}
		}
	}

	if (strlen(reMac))
		DBG_INFO("best RE(%s) rssi(%d) be selected", reMac, *rssi);

	json_object_put(obListObj);

	pthread_mutex_unlock(&onboardingLock);

	return reMac;
} /* End of cm_selectBestOnboardingRe */

/*
========================================================================
Routine Description:
        Send event w/ onboarding to the client.

Arguments:
        None

Return Value:
        None

Note:
========================================================================
*/
void cm_handleOnboarding(char *data)
{
	int rssi = -100;
	char reMac[18] = {0};
	char newReMac[18] = {0};
	json_object *inRoot = json_tokener_parse(data);
	json_object *outRoot = NULL;
	json_object *obStatusObj = NULL;
	json_object *newReMacObj = NULL;
	json_object *obPathObj = NULL;
	int obPath = FROM_WIRELESS;
	char group[9] = {0}, obMsg[128] = {0};
	int rTime = 0, cTimeout = 0, tTimeout = 0;
#ifdef ONBOARDING_VIA_VIF
	char obReIp[18] = {0}, reTrafficMac[18] = {0}, obVifMac[18] = {0};
	hash_elem_t* e = NULL;
	int obViaCap = 0;
#endif

	if (!inRoot) {
		DBG_ERR("inRoot is null");
		goto err;
	}

	outRoot = json_object_new_object();
	json_object_object_get_ex(inRoot, OB_STATUS, &obStatusObj);

	if (!obStatusObj) {
		DBG_ERR("obStatusObj is null");
		goto err;
	}

	if (!outRoot) {
		DBG_ERR("outRoot is null");
		goto err;
	}

	json_object_object_add(outRoot, CFG_STR_TYPE, obStatusObj);

	if (json_object_get_int(obStatusObj) == OB_TYPE_AVAILABLE) {
		json_object_object_get_ex(inRoot, NEW_RE_MAC, &newReMacObj);

		if (newReMacObj) {
			if (strlen((char *)json_object_get_string(newReMacObj)) > 0) {
				json_object_object_add(outRoot, CFG_STR_NEW_RE_MAC, newReMacObj);

				/* set ob path */
				json_object_object_get_ex(inRoot, CFG_STR_OB_PATH, &obPathObj);
				if (!obPathObj) {
					DBG_ERR("obPathObj is null");
					goto err;
				}

				obPath = json_object_get_int(obPathObj);
				if (obPath == 0) {
					DBG_ERR("ob path is invalid (%d)");
					goto err;
				}
				cm_setOnboardingPath(obPath);

				json_object_object_add(outRoot, CFG_STR_OB_PATH,
					json_object_new_int(cm_getOnboardingPath()));
			}
			else
			{
				json_object_object_add(outRoot, CFG_STR_NEW_RE_MAC,
					json_object_new_string(UNDEF_RE_MAC));
				json_object_object_add(outRoot, CFG_STR_OB_PATH,
					json_object_new_int(cm_getOnboardingPath()));
				cm_setOnboardingPath(FROM_NONE);
			}
		}
		else
			obTimeStamp = time((time_t*)NULL);

		json_object_object_add(outRoot, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
	}
	else if (json_object_get_int(obStatusObj) == OB_TYPE_LOCKED) {
		obPath = cm_getOnboardingPath();

		/* for new RE */
		json_object_object_get_ex(inRoot, NEW_RE_MAC, &newReMacObj);
		if (!newReMacObj) {
			DBG_ERR("newReMacObj is null");
			goto err;
		}
		snprintf(newReMac, sizeof(newReMac), "%s", json_object_get_string(newReMacObj));

		/* select best RE for onboarding */
		snprintf(reMac, sizeof(reMac), "%s",
			cm_selectBestOnboardingRe(newReMac, &rssi, obPath, &rTime, &cTimeout, &tTimeout));
		if (strlen(reMac) == 0) {
			DBG_ERR("reMac is null");
			goto err;
		}

		if (obPath == FROM_NONE) {      /* new RE and related don't be selected */
			snprintf(obMsg, sizeof(obMsg), "{\"%s\": %d, \"%s\": %d, \"%s\": {\"%s\": \"%s\"} }",
				CFG_STR_STATUS, OB_STATUS_TERMINATE,
				CFG_STR_FAIL_RESULT, OB_SELECT_RE_FAIL,
				reMac, CFG_STR_MAC, newReMac);
			cm_processOnboardingMsg(obMsg);
			goto err;
		}
		else
		{
			DBG_INFO("reMac(%s) and newReMac(%s) for onboarding via %s (%d)", reMac, newReMac,
				(obPath == FROM_ETHERNET) ? "ethernet": "wireless", obPath);
			nvram_set("cfg_obre", reMac);

			json_object_object_add(outRoot, CFG_STR_RE_MAC, json_object_new_string(reMac));
			json_object_object_add(outRoot, CFG_STR_NEW_RE_MAC, json_object_new_string(newReMac));
			json_object_object_add(outRoot, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
			json_object_object_add(outRoot, CFG_STR_OB_PATH, json_object_new_int(obPath));
			snprintf(group, sizeof(group), "%d%d", rand(), rand());
			json_object_object_add(outRoot, CFG_STR_OB_GROUP, json_object_new_string(group));
			if (rTime && cTimeout && tTimeout) {
				json_object_object_add(outRoot, CFG_STR_REBOOT_TIME, json_object_new_int(rTime));
				json_object_object_add(outRoot, CFG_STR_CONN_TIMEOUT, json_object_new_int(cTimeout));
				json_object_object_add(outRoot, CFG_STR_TRAFFIC_TIMEOUT, json_object_new_int(tTimeout));
			}

#ifdef ONBOARDING_VIA_VIF
			/* hdnalde OB_TYPE_VIF_CHECK first before OB_TYPE_LOCKED */
			if (obPath == FROM_WIRELESS) {

				if (strcmp(reMac, get_re_hwaddr()) == 0) {	/* ob via CAP */
					obViaCap = 1;
					snprintf(obVifMac, sizeof(obVifMac), "%s", reMac);
				}
				else
				{
					obViaCap = 0;
					if (cm_getReMacBy2gMac(p_client_tbl, reMac, obVifMac, sizeof(obVifMac)) == 0) {
						/* can get RE real mac */
						snprintf(obMsg, sizeof(obMsg), "{\"%s\":%d,\"%s\":%d,\"%s\":{\"%s\":\"%s\"}}",
							CFG_STR_STATUS, OB_STATUS_TERMINATE,
							CFG_STR_FAIL_RESULT, OB_VIF_CHECK_FAIL,
							reMac, CFG_STR_MAC, newReMac);
						cm_processOnboardingMsg(obMsg);
						goto err;
					}
				}
				DBG_INFO("reMac(%s), obVifMac(%s)", reMac, obVifMac);

				if (cm_checkOnboardingVifCapability(obVifMac)) {
					nvram_set_int("cfg_obvif_ready", -1);
					nvram_set("cfg_obvif_mac", obVifMac);
					json_object_object_del(outRoot, CFG_STR_TYPE);
					json_object_object_add(outRoot, CFG_STR_TYPE, json_object_new_int(OB_TYPE_VIF_CHECK));

					cm_processOnboardingEvent((char *)json_object_to_json_string(outRoot));
					if (obViaCap == 0) {	/* onboarding via RE */
						if (cm_getReIpByReMac(p_client_tbl, obVifMac, obReIp, sizeof(obReIp)) > 0 &&
							cm_getReTrafficMacByReMac(p_client_tbl, obVifMac, reTrafficMac, sizeof(reTrafficMac)) > 0) {
							if ((e = ht_get(clientHashTable, reTrafficMac, obReIp))) {
								if (!cm_sendNotification(e, NOTIFY_ONBOARDING, outRoot)) {
									DBG_INFO("send notification(%d) to %s(%s) success", NOTIFY_ONBOARDING, obVifMac, obReIp);
								}
								else
									DBG_ERR("send notification(%d) to %s(%s) failed", NOTIFY_ONBOARDING, obVifMac, obReIp);
							}
						}
					}

					if (cm_waitOnboardingVifReady(obVifMac) == 0) {
						/* ob vif is not ready */
						snprintf(obMsg, sizeof(obMsg), "{\"%s\":%d,\"%s\":%d,\"%s\":{\"%s\":\"%s\"}}",
							CFG_STR_STATUS, OB_STATUS_TERMINATE,
							CFG_STR_FAIL_RESULT, OB_VIF_CHECK_FAIL,
							reMac, CFG_STR_MAC, newReMac);
						cm_processOnboardingMsg(obMsg);
						goto err;
					}
				}
			}
#endif

			json_object_object_del(outRoot, CFG_STR_TYPE);
			json_object_object_add(outRoot, CFG_STR_TYPE, json_object_new_int(OB_TYPE_LOCKED));

			/* update ob status as OB_STATUS_START */
			cm_updateOnboardingListStatus(reMac,
					(char *)json_object_get_string(newReMacObj), OB_STATUS_START);
		}
	}

	/* send onboarding notification to all client */
	cm_sendOnboardingMsg(outRoot);

	cm_processOnboardingEvent((char *)json_object_to_json_string(outRoot));

err:

	json_object_put(inRoot);
	json_object_put(outRoot);
} /* End of cm_handleOnboarding */

/*========================================================================
Routine Description:
	Process onboarding msg.

Arguments:
	*msg	- onboarding msg

Return Value:
	None

Note:
==========================================================================
*/
void cm_processOnboardingMsg(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	json_object *outRoot = NULL;
	json_object *newReMacObj = NULL;
	json_object *obKeyObj = NULL;
	char reMac[32] = {0};
	char newReMac[32] = {0};
	int obStatus = -1, failResult = OB_FAIL_NONE;
	char obKey[KEY_LENGTH + 1] = {0};
#ifdef ONBOARDING_VIA_VIF
	int vifStatus = 0;
#endif

	DBG_INFO("msg(%s)", msg);

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_foreach(root, key, val) {
		if (!strcmp(key, CFG_STR_STATUS)) {
			if (val) {
				obStatus = json_object_get_int(val);
				DBG_INFO("onboarding status (%d)", obStatus);
			}
		}
		else if (!strcmp(key, CFG_STR_FAIL_RESULT))
		{
			if (val) {
				failResult = json_object_get_int(val);
				DBG_INFO("fail result (%d)", failResult);
			}
		}
#ifdef ONBOARDING_VIA_VIF
		else if (!strcmp(key, CFG_STR_VIF_STATUS))
		{
			if (val) {
				vifStatus = json_object_get_int(val);
				DBG_INFO("vif status (%d)", vifStatus);
			}
		}
		else if (!strcmp(key, CFG_STR_OB_KEY))
		{
			if (val) {
				snprintf(obKey, sizeof(obKey), "%s", json_object_get_string(val));
				DBG_INFO("ob key (%s)", obKey);
			}
		}
#endif
		else
		{
			snprintf(reMac, sizeof(reMac), "%s", key);
			json_object_object_get_ex(val, CFG_STR_MAC, &newReMacObj);
			json_object_object_get_ex(val, CFG_STR_OB_KEY, &obKeyObj);
			if (newReMacObj) {
				snprintf(newReMac, sizeof(newReMac), "%s", json_object_get_string(newReMacObj));
			}

			if (obKeyObj) {
				snprintf(obKey, sizeof(obKey), "%s", json_object_get_string(obKeyObj));
			}
		}
	}

	json_object_put(root);

	if (obStatus == OB_STATUS_REQ) {
		if (cm_isOnboardingAvailable())
			cm_processOnboardingList(msg);
	}
	else if (obStatus == OB_STATUS_SUCCESS || obStatus == OB_STATUS_WPS_FAIL ||
		obStatus == OB_STATUS_TERMINATE) {
		/* update fail result */
		if (failResult)
			cm_updateOnboardingFailResult(failResult);

		cm_updateOnboardingListStatus(reMac, newReMac, obStatus);
		outRoot = json_object_new_object();
		if (outRoot) {
			/* change timestmp for onboarding off */
			obTimeStamp = time((time_t*)NULL);

			json_object_object_add(outRoot, CFG_STR_TYPE, json_object_new_int(OB_TYPE_OFF));
#ifdef ONBOARDING_VIA_VIF
			if (strlen(nvram_safe_get("cfg_obvif_mac")) &&
				(obStatus == OB_STATUS_WPS_FAIL || obStatus == OB_STATUS_TERMINATE))
				json_object_object_add(outRoot, CFG_STR_OB_VIA_VIF, json_object_new_int(1));
#endif
			cm_processOnboardingEvent((char *)json_object_to_json_string(outRoot));
			json_object_object_add(outRoot, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
			cm_sendOnboardingMsg(outRoot);
		}
		json_object_put(outRoot);

		if (obStatus == OB_STATUS_SUCCESS || obStatus == OB_STATUS_WPS_FAIL) {
			if (obStatus == OB_STATUS_SUCCESS)
				DBG_LOG("onboarding success for new re (%s)", newReMac);
			else
			{
				DBG_INFO("wps failed (%d) for new re (%s)", failResult, newReMac);
				DBG_LOG("onboarding failed (%d) for new re (%s)", failResult, newReMac);
			}
			cm_stopOnboardingMonitor();
		}
		else if (obStatus == OB_STATUS_TERMINATE) {
			DBG_INFO("onboarding terminate (%d) for new re (%s)", nvram_get_int("cfg_obfailresult"), newReMac);
			DBG_LOG("onboarding failed (%d) for new re (%s)", nvram_get_int("cfg_obfailresult"), newReMac);
			cm_stopOnboardingAvailable();
		}
	}
	else if (obStatus == OB_STATUS_WPS_SUCCESS) {
		cm_updateOnboardingListStatus(reMac, newReMac, obStatus);
		if (strlen(obKey) > 0)
			nvram_set("cfg_obkey", obKey);
		DBG_LOG("wps success for new re (%s)", newReMac);
	}
	else if (obStatus == OB_STATUS_AVALIABLE_TIMEOUT) {
		outRoot = json_object_new_object();
		if (outRoot) {
			DBG_LOG("onboarding available timeout");
			/* change timestmp for onboarding off */
			obTimeStamp = time((time_t*)NULL);

			json_object_object_add(outRoot, CFG_STR_TYPE, json_object_new_int(OB_TYPE_OFF));
			cm_processOnboardingEvent((char *)json_object_to_json_string(outRoot));
			json_object_object_add(outRoot, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
			cm_sendOnboardingMsg(outRoot);
		}
		json_object_put(outRoot);
	}
	else if (obStatus == OB_STATUS_CANCEL_SELECTION) {
		outRoot = json_object_new_object();
		if (outRoot) {
			DBG_LOG("cancel onboarding selection");
			json_object_object_add(outRoot, CFG_STR_TYPE, json_object_new_int(OB_TYPE_AVAILABLE));
			json_object_object_add(outRoot, CFG_STR_NEW_RE_MAC, json_object_new_string(UNDEF_RE_MAC));
			json_object_object_add(outRoot, CFG_STR_TIMESTAMP, json_object_new_int(obTimeStamp));
			cm_processOnboardingEvent((char *)json_object_to_json_string(outRoot));
			cm_sendOnboardingMsg(outRoot);
		}
		json_object_put(outRoot);
	}
#ifdef ONBOARDING_VIA_VIF
	else if (obStatus == OB_STATUS_REPORT_VIF_STATUS) {
		DBG_INFO("the status (%d) for onboarding vif", vifStatus);
		nvram_set_int("cfg_obvif_ready", vifStatus);
		if (vifStatus && strlen(obKey) > 0) {
			DBG_INFO("the key of onboarding vif is %s", obKey);
			nvram_set("cfg_obkey", obKey);
		}
	}
#endif
	else
		DBG_INFO("unknown onboarding status");
} /* End of cm_processOnboardingMsg */

/*
========================================================================
Routine Description:
	Prepare the group id.

Arguments:
	msg			- output message array
	msgLen			- the legnth of output message array

Return Value:
	message length

========================================================================
*/
static int cm_prepareGroupId(char *msg, int msgLen)
{
	snprintf(msg, msgLen, "{\"%s\":\"%s\"}", CFG_STR_ID, nvram_safe_get("cfg_group"));
	return strlen(msg);
} /* End of cm_prepareGroupId */

/*
========================================================================
Routine Description:
	Process REQ_GROUPID packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_GROUPID(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *decodeMsg = NULL;
	size_t decodeMsgLen = 0;
	unsigned char *key = NULL;
	int ret = 0;
	char reMac[18] = {0};
	unsigned char *keyPrelink = NULL;
	int keyType = KEY_IS_UNKNOWN;

	DBG_INFO("Got REQ_GROUPID ...");

#ifdef PRELINK
	if (nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey")) && (keyPrelink = get_prelink_key()) == NULL) {
		DBG_ERR("Prelink key failed");
		goto err;
	}
#endif

	if ((key = get_onboarding_key()) == NULL) {
		DBG_ERR("Onboarding key failed");
		goto err;
	}

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
		goto err;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			goto err;
		}
		DBG_INFO("OK");

#ifdef PRELINK
		if (keyPrelink) {
			decodeMsg = aes_decrypt(keyPrelink, (unsigned char *)packetMsg, ntohl(tlv.len), &decodeMsgLen);
			if (IsNULL_PTR(decodeMsg))
				DBG_INFO("Failed to aes_decrypt() by keyPrelink !!!");
			else
			{
				keyType = KEY_IS_PRELINK;
				if (get_re_unique_mac(decodeMsg, reMac, sizeof(reMac)) != 0) {
					cm_updatePrelinkStatus(reMac, PRELINK_GID_REQUEST);
					DBG_LOG("RE (%s %s) request group id", reMac, clientIP);
				}
			}
		}
#endif

		if (keyType == KEY_IS_UNKNOWN) {
			decodeMsg = aes_decrypt(key, (unsigned char *)packetMsg, ntohl(tlv.len), &decodeMsgLen);
			if (IsNULL_PTR(decodeMsg)) {
				DBG_ERR("Failed to aes_decrypt() !!!");
				goto err;
			}
			keyType = KEY_IS_ONBOARDING;
			DBG_INFO("OK");
		}
	}

	/* check the number of RE */
	if (nvram_get_int("cfg_recount") >= MAX_RELIST_COUNT) {
		DBG_ERR("the number of RE has reached the maximum (%d)", MAX_RELIST_COUNT);
		goto err;
	}

	/* check new RE is valid or not */
	if (keyType == KEY_IS_PRELINK || cm_checkOnboardingNewReValid(decodeMsg)) {
		/* remove slave related file */
		if (get_re_unique_mac(decodeMsg, reMac, sizeof(reMac)) != 0)
			cm_removeSlaveRelatedFiles(reMac);

		memset(msgBuf, 0, sizeof(msgBuf));
		if (cm_prepareGroupId((char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
			encryptedMsg = cm_aesEncryptMsg((keyType == KEY_IS_PRELINK) ? keyPrelink : key,
				RSP_GROUPID, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

			if (IsNULL_PTR(encryptedMsg)) {
				DBG_ERR("Failed to MALLOC() !!!");
				goto err;
			}
		}
		else
		{
			memset(&packetTlvHdr, 0, sizeof(TLV_Header));
			packetTlvHdr.type = htonl(RSP_GROUPID);
			MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
			memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
			encryptedMsgLen = sizeof(TLV_Header);
		}

		if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0) {
			DBG_ERR("Failed to socket write() !!!");
			goto err;
		}

#ifdef PRELINK
		if (keyType == KEY_IS_PRELINK) {
			cm_updatePrelinkStatus(reMac, PRELINK_GID_RESPONSE);
			DBG_LOG("CAP response group id to RE (%s %s)", reMac, clientIP);
		}
#endif
	}
	else
	{
		DBG_ERR("new RE is invalid");
		goto err;
	}

	ret = 1;

err:
	MFREE(decodeMsg);
	MFREE(encryptedMsg);
	MFREE(key);
	MFREE(keyPrelink);

	return ret;
} /* End of cm_processREQ_GROUPID */

/*
========================================================================
Routine Description:
	Process ACK_GROUPID packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processACK_GROUPID(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	unsigned char *decodeMsg = NULL;
	unsigned char *key = NULL;
	int ret = 0;
	json_object *reListObj = NULL;
	unsigned char *keyPrelink = NULL;
	int keyType = KEY_IS_UNKNOWN;
#ifdef PRELINK
	char reMac[18] = {0};
#endif

	DBG_INFO("Got ACK_GROUPID ...");

#ifdef PRELINK
	if (nvram_get("amas_bdlkey") && strlen(nvram_safe_get("amas_bdlkey")) && (keyPrelink = get_prelink_key()) == NULL) {
		DBG_ERR("Prelink key failed");
		goto err;
	}
#endif

	if ((key = get_onboarding_key()) == NULL) {
		DBG_ERR("Onboarding key failed");
		goto err;
	}

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
		goto err;
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			goto err;
		}
		DBG_INFO("OK");
#ifdef PRELINK
		if (keyPrelink) {
			decodeMsg = cm_aesDecryptMsg(keyPrelink, keyPrelink, (unsigned char *)packetMsg, ntohl(tlv.len));
			if (IsNULL_PTR(decodeMsg))
				DBG_INFO("Failed to aes_decrypt() by keyPrelink !!!");
			else
			{
				keyType = KEY_IS_PRELINK;
				if (get_re_unique_mac(decodeMsg, reMac, sizeof(reMac)) != 0) {
					cm_updatePrelinkStatus(reMac, PRELINK_GID_ACK);
					DBG_LOG("RE (%s %s) ack group id", reMac, clientIP);
				}
			}
		}
#endif

		if (keyType == KEY_IS_UNKNOWN) {
			decodeMsg = cm_aesDecryptMsg(key, key, (unsigned char *)packetMsg, ntohl(tlv.len));
			if (IsNULL_PTR(decodeMsg)) {
				DBG_ERR("Failed to aes_decrypt() !!!");
				goto err;
			}
			keyType = KEY_IS_ONBOARDING;
			DBG_INFO("OK");
		}
	}

	/* check new RE is valid or not */
	if (keyType == KEY_IS_PRELINK || cm_checkOnboardingNewReValid(decodeMsg)) {
		if (cm_updateOnboardingSuccess(keyType, decodeMsg)) {
#ifdef RTCONFIG_DWB
			cm_updateDwbInfo();
#endif
			/* notify re list update */
			if ((reListObj = json_object_from_file(RE_LIST_JSON_FILE)) != NULL) {
				cm_sendNotificationByType(NOTIFY_UPDATERELIST, reListObj);
				json_object_put(reListObj);
				sleep(3);
				wl_set_macfilter_list();
			}
#ifdef RTCONFIG_DWB
			if (dwb_reSync) {
				cm_usr2Handle(-1); // Notify re to resync and don't do cm_AutoDetect_Dedicated_Wifi_Backhaul(1) again.
				dwb_reSync = 0;
			}
#endif
		}
	}
	else
	{
		DBG_ERR("new RE is invalid");
		goto err;
	}

	ret = 1;

err:
	MFREE(decodeMsg);
	MFREE(key);
	MFREE(keyPrelink);

	return ret;
} /* End of cm_processACK_COST */

/*
========================================================================
Routine Description:
	Validate RE is valid or not for onboarding.

Arguments:
	reMac		- RE's MAC for onboarding

Return Value:
	0			- invalid
	1			- valid

========================================================================
*/
int cm_validateOnboardingRe(char *reMac)
{
	int i = 0;
	unsigned char ea[MAC_LEN] = {0};
	int ret = 0;

	if (!reMac)
		return ret;

	ether_atoe(reMac, ea);

	pthread_mutex_lock(&cfgLock);
	for(i = 0; i < p_client_tbl->count; i++) {
		/* compare first 5 bytes only */
		if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN - 1) == 0 ||
			memcmp(p_client_tbl->ap2g[i], ea, MAC_LEN) == 0 ||
			memcmp(p_client_tbl->ap5g[i], ea, MAC_LEN) == 0 ||
			memcmp(p_client_tbl->ap5g1[i], ea, MAC_LEN) == 0 ||
			memcmp(p_client_tbl->ap6g[i], ea, MAC_LEN) == 0
		) {
			DBG_INFO("%s is valid for onboarding", reMac);
			ret = 1;
			break;
		}
	}
	pthread_mutex_unlock(&cfgLock);

	return ret;
} /* End of cm_validateOnboardingRe */
#endif	/* ONBOARDING */

#ifdef RADAR_DET
/*
========================================================================
Routine Description:
	Report available wireless channel after detecting radar.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_processRadarDetection(void)
{
	char msg[MAX_CHANSPEC_BUFLEN] = {0};
	char ch_data[MAX_CH_DATA_BUFLEN] = {0};
	json_object *root = json_object_new_object();
	json_object *chanspecObj = NULL;

	DBG_INFO("Radar Detected...");

	if( root && chmgmt_get_chan_info(ch_data, sizeof(ch_data)) > 0 )
	{
		DBG_INFO("channel information updated");

		/* unique mac */
		json_object_object_add(root, CFG_STR_MAC, json_object_new_string(get_unique_mac()));
		/* channel */
		json_object_object_add(root, CFG_STR_CHANNEL, json_object_new_string(ch_data));
		/* supported chanspec */
		chanspecObj = json_object_new_object();
		if (chanspecObj) {
			if (cm_getChanspec(chanspecObj, 0)) {
				json_object_object_add(root, CFG_STR_CHANSPEC, chanspecObj);
				json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			}
			else
				json_object_put(chanspecObj);
		}

		snprintf((char *)msg, sizeof(msg), "%s", json_object_get_string(root));
		DBG_INFO("msg(%s)", msg);

		cm_updateAvailableChannel(msg);
		cm_updateChanspec(msg);
		/* send notification w/ amas_wlcconnect */
		cm_sendNotificationByType(NOTIFY_WLCRECONNECT, NULL);
		chmgmt_notify();
	}

	json_object_put(root);
} /* End of cm_processRadarDetection */

/*
========================================================================
Routine Description:
	Process REQ_RADARDET packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_RADARDET(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_RADARDET ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

        if (!e->authorized) {
                DBG_ERR("client is not authorized");
                return 0;
        }

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_RADARDET);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
		cm_updateAvailableChannel((char *)decodeMsg);
		cm_updateChanspec((char *)decodeMsg);
		/* send notification w/ amas_wlcconnect */
		cm_sendNotificationByType(NOTIFY_WLCRECONNECT, NULL);
		chmgmt_notify();
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_REQUESTWCHANNEL */
#endif	/* RADAR_DET */

/*
========================================================================
Routine Description:
	Update new firmware version.

Arguments:
	firmVer		- new firmware version

Return Value:
	None

Note:
========================================================================
*/
void cm_updateFirmwareVersion(char *firmVer)
{
	char realMac[18] = {0};
	int i = 0;

	pthread_mutex_lock(&cfgLock);
	for (i = 0; i < p_client_tbl->count; i++) {
		memset(realMac, 0, sizeof(realMac));
		snprintf(realMac, sizeof(realMac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		if (strcmp(realMac, get_unique_mac()) == 0) {
			snprintf(p_client_tbl->newFwVer[i], sizeof(p_client_tbl->newFwVer[i]), "%s",
				firmVer);
			snprintf(p_client_tbl->frsModelName[i], sizeof(p_client_tbl->frsModelName[i]), "%s",
				nvram_safe_get("webs_state_odm"));
		}
	}
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_updateFirmwareVersion */

/*
========================================================================
Routine Description:
	Check  master/salve whether valid or not.

Arguments:
	mac		- mac for master/slave

Return Value:
	0		- invalid
	1		- valid

Note:
========================================================================
*/
int cm_checkClientStatus(char *mac)
{
	int i = 0;
	char rMac[18] = {0};
	int ret = 0;

	pthread_mutex_lock(&cfgLock);
	for (i = 0; i < p_client_tbl->count; i++) {
		memset(rMac, 0, sizeof(rMac));
		snprintf(rMac, sizeof(rMac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		if (!strcmp(rMac, mac)) {
			if (i == 0)	/* DUT info */
				ret = 1;
			else
				ret = ((int) difftime(time(NULL), p_client_tbl->reportStartTime[i]) < OFFLINE_THRESHOLD) ? 1 : 0;
		}
	}
	pthread_mutex_unlock(&cfgLock);

	return ret;
} /* End of cm_checkClientStatus */

/*
========================================================================
Routine Description:
	Start wps for registrar.

Arguments:
	*ip		- login ip

Return Value:
	None

Note:
========================================================================
*/
void cm_startWps(char *ip)
{
	char clientMac[32] = {0};

	/* get client's mac based on login ip */
	cm_getClientMac(ip, &clientMac[0], sizeof(clientMac));

	if (strlen(clientMac)) {
		/* client mac is from wireless? */
		char staMac[32] = {0};
		char band[16] = {0};
		char brMac[32] = {0};
		json_object *fileRoot = NULL;
		json_object *brMacObj = NULL;
		json_object *bandObj = NULL;
		int found = 0;
		hashtable_t* hasht = clientHashTable;
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		pthread_mutex_lock(&weventLock);

		fileRoot = json_object_from_file(WCLIENT_LIST_JSON_PATH);
		if (fileRoot) {
			json_object_object_foreach(fileRoot, key, val) {
				memset(brMac, 0, sizeof(brMac));
				snprintf(brMac, sizeof(brMac), "%s", key);
				brMacObj = val;

				json_object_object_foreach(brMacObj, key, val) {
					memset(band, 0, sizeof(band));
					snprintf(band, sizeof(band), "%s", key);
					bandObj = val;
					json_object_object_foreach(bandObj, key, val) {
						memset(staMac, 0, sizeof(staMac));
						snprintf(staMac, sizeof(staMac), "%s", key);
						if (!strcmp(staMac, clientMac)) {
							found = 1;
							break;
						}
					}

					if (found) break;
				}

				if (found) break;
			}
		}

		json_object_put(fileRoot);
		pthread_mutex_unlock(&weventLock);

		/* find the client is from wireless */
		if (found) {
			int i = 0;
			char keyMac[18] = {0};
			char keyIp[18] = {0};
			char realMac[18] = {0};

			DBG_INFO("login ip(%s), mac(%s) is from wireless(%s)", ip, clientMac, brMac);
			found = 0;

			/* find ap's mac and ip from p_client_tbl */
			pthread_mutex_lock(&cfgLock);
			for (i = 0; i < p_client_tbl->count; i++) {
				memset(realMac, 0, sizeof(realMac));
				snprintf(realMac, sizeof(realMac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
					p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
					p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

				if (!strcmp(realMac, brMac)) {
					snprintf(keyMac, sizeof(keyMac), "%02X:%02X:%02X:%02X:%02X:%02X",
						p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
						p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
						p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

					snprintf(keyIp, sizeof(keyIp), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
						p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
						p_client_tbl->ipAddr[i][3]);

					found = 1;
					break;
				}
			}
			pthread_mutex_unlock(&cfgLock);

			/* send notification to slave or start wps at master */
			if (found) {
				if (i == 0) {	/* for master */
					notify_rc("restart_wps");
				}
				else	/* for slave */
				{
					while(e != NULL) {
						if (!strcmp(keyMac, e->key) && !strcmp(keyIp, e->clientIP)) {
							if (!cm_sendNotification(e, NOTIFY_STARTWPS, NULL))
								DBG_ERR("send notification to %s failed", e->clientIP);
							break;
						}
						e = ht_iterate_elem(&it);
					}
				}
			}
		}
		else
		{
			while(e != NULL) {
				/* send notification to all clients */
				if (!cm_sendNotification(e, NOTIFY_STARTWPS, NULL))
					DBG_ERR("send notification to %s failed", e->clientIP);
				e = ht_iterate_elem(&it);
			}
			notify_rc("restart_wps");
		}
	}
} /* End of cm_startWps */

/*
========================================================================
Routine Description:
        Notify reboot via web.

Arguments:
        macList            - mac list need to be notified reboot.

Return Value:
        None

Note:
========================================================================
*/
void cm_notifyReboot(json_object *macListObj)
{
	int i = 0, j = 0, k = 0, listLen = 0, capReboot = 0;
	json_object *macEntry = NULL;
	char mac[18], ipStr[18], macStr[18];
	unsigned char ea[6];
	hash_elem_t* e = NULL;

	listLen = json_object_array_length(macListObj);

	pthread_mutex_lock(&cfgLock);
	for (i = p_client_tbl->maxLevel; i >= -1; i--) {
		for (j = 0; j < p_client_tbl->count; j++) {
			if (p_client_tbl->level[j] != i)
				continue;

			memset(macStr, 0, sizeof(macStr));
			memset(ipStr, 0, sizeof(ipStr));
			snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
				p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
				p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

			snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
				p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
				p_client_tbl->ipAddr[j][3]);

			if (listLen) {	//for specific cap/re
				for (k = 0; k < listLen; k++) {
					macEntry = json_object_array_get_idx(macListObj, k);
					if (macEntry) {
						strlcpy(mac, json_object_get_string(macEntry), sizeof(mac));
						ether_atoe(mac, ea);

						if (memcmp(p_client_tbl->realMacAddr[j], ea, MAC_LEN) == 0) {
							if (j == 0) {
								DBG_INFO("cap need to reboot");
								capReboot = 1;
							}
							else
							{
								if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
									DBG_INFO("%s (%s) is offline", macStr, ipStr);
								}
								else if ((e = ht_get(clientHashTable, macStr, ipStr))) {
									if (!cm_sendNotification(e, NOTIFY_REBOOT, NULL))
										DBG_ERR("send notification to %s failed", e->clientIP);
								}
							}

							break;
						}
					}
				}
			}
			else		//for all cap & re
			{
				if (j == 0) {
					DBG_INFO("cap need to reboot");
					capReboot = 1;
				}
				else
				{
					if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						DBG_INFO("%s (%s) is offline", macStr, ipStr);
					}
					else if ((e = ht_get(clientHashTable, macStr, ipStr))) {
						if (!cm_sendNotification(e, NOTIFY_REBOOT, NULL))
							DBG_ERR("send notification to %s failed", e->clientIP);
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&cfgLock);

	if (capReboot)
		notify_rc("reboot");
} /* End of cm_notifyReboot */

/*
========================================================================
Routine Description:
	Notify action via web.

Arguments:
	eid		- event id
	macListObj		- mac list need to be notified to do action.
	dataObj		- data for action

Return Value:
	None

Note:
========================================================================
*/
void cm_notifyAction(int eid, json_object *macListObj, json_object *dataObj)
{
	int i = 0, j = 0, k = 0, listLen = 0, capDoAction = 0, capAction = 0, action = 0, capType = 0;
	json_object *macEntry = NULL, *notifyDataObj = NULL;
	char mac[18], ipStr[18], macStr[18];
	unsigned char ea[6];
	hash_elem_t* e = NULL;
	int found = 0;

	if (!cm_findActionInfo(eid, &action, &capAction, &capType)) {
		DBG_INFO("not corresponding action info");
		return;
	}

	if ((notifyDataObj = json_object_new_object())) {
		json_object_object_add(notifyDataObj, CFG_ACTION_ID, json_object_new_int(action));
		json_object_object_add(notifyDataObj, CFG_DATA, dataObj);
	}
	else
	{
		DBG_INFO("notifyDataObj is NULL");
		return;
	}

	DBG_INFO("eid(%d), action(%d), capAction(%d), capType(%d)", eid, action, capAction, capType);

	listLen = json_object_array_length(macListObj);

	/* for re reconnect, need to set re offline */
	if (action == ACTION_RE_RECONNECT) {
		if (listLen > 0) {
			for (i = 0; i < listLen; i++) {
				macEntry = json_object_array_get_idx(macListObj, i);
				if (macEntry) {
					for (j = 1; j < p_client_tbl->count; j++) {
						snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
							p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
							p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

						if (strcmp(mac, json_object_get_string(macEntry)) == 0) {
							DBG_INFO("found mac (%s)", mac);
							snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
								p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
								p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
								p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

							snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
								p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
								p_client_tbl->ipAddr[j][3]);

							found = 1;
							break;
						}
					}

					if (found) {
						if (cm_isCapSupported(mac, capType, 0)) {
							if (p_client_tbl->activePath[j] == 1 && p_client_tbl->level[j] == 0)
								continue;

							if ((e = ht_get(clientHashTable, macStr, ipStr))) {
								cm_setReOffline(&p_client_tbl->reportStartTime[j]);
								e->reconnStatus = 1;
							}
						}
					}
				}
			}
		}
		else
		{
			for (j = 1; j < p_client_tbl->count; j++) {
				snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
					p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
					p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

				snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
					p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
					p_client_tbl->ipAddr[j][3]);

				snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
					p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
					p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

				if (cm_isCapSupported(mac, capType, 0)) {
					if (p_client_tbl->activePath[j] == 1 && p_client_tbl->level[j] == 0)
						continue;
					if ((e = ht_get(clientHashTable, macStr, ipStr))) {
						cm_setReOffline(&p_client_tbl->reportStartTime[j]);
						e->reconnStatus = 1;
					}
				}
			}
		}
	}

	for (i = p_client_tbl->maxLevel; i >= -1; i--) {
		for (j = 0; j < p_client_tbl->count; j++) {
			if (p_client_tbl->level[j] != i)
				continue;

			memset(macStr, 0, sizeof(macStr));
			memset(ipStr, 0, sizeof(ipStr));
			snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
				p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
				p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

			snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
				p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
				p_client_tbl->ipAddr[j][3]);

			if (listLen) {	//for specific cap/re
				for (k = 0; k < listLen; k++) {
					macEntry = json_object_array_get_idx(macListObj, k);
					if (macEntry) {
						strlcpy(mac, json_object_get_string(macEntry), sizeof(mac));
						ether_atoe(mac, ea);

						if (memcmp(p_client_tbl->realMacAddr[j], ea, MAC_LEN) == 0) {
							if (j == 0) {
								if (capAction) {
									DBG_INFO("cap need do action");
									capDoAction = 1;
								}
							}
							else
							{
								if (action != ACTION_RE_RECONNECT && !cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
									DBG_INFO("%s (%s) is offline", macStr, ipStr);
								}
								else if ((e = ht_get(clientHashTable, macStr, ipStr))) {
									if (cm_isCapSupported(mac, capType, 0)) {
										if (action == ACTION_RE_RECONNECT) {
											if (p_client_tbl->activePath[j] == 1 && p_client_tbl->level[j] == 0) {
												DBG_INFO("active path is ethernet and level is 0, pass it");
												continue;
											}
										}

										if (cm_sendNotification(e, NOTIFY_ACTION, notifyDataObj)) {
											DBG_INFO("send notification (%d) to %s successfully", NOTIFY_ACTION, e->clientIP);
											if (action == ACTION_RE_RECONNECT) {
												cm_setReOffline(&p_client_tbl->reportStartTime[j]);
												ht_remove(clientHashTable, macStr, ipStr);
											}
										}
										else
										{
											DBG_INFO("send notification (%d) to %s failed", NOTIFY_ACTION, e->clientIP);
											if (action == ACTION_RE_RECONNECT)
												e->reconnStatus = 0;
										}
									}
								}
							}

							break;
						}
					}
				}
			}
			else		//for all cap & re
			{
				if (j == 0) {
					if (capAction) {
						DBG_INFO("cap need do action");
						capDoAction = 1;
					}
				}
				else
				{
					if (action != ACTION_RE_RECONNECT && !cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
						DBG_INFO("%s (%s) is offline", macStr, ipStr);
					}
					else if ((e = ht_get(clientHashTable, macStr, ipStr))) {
						snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
								p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
								p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
								p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

						if (cm_isCapSupported(mac, capType, 0)) {
							if (action == ACTION_RE_RECONNECT) {
								if (p_client_tbl->activePath[j] == 1 && p_client_tbl->level[j] == 0) {
									DBG_INFO("active path is ethernet and level is 0, pass it");
									continue;
								}
							}

							if (cm_sendNotification(e, NOTIFY_ACTION, notifyDataObj)) {
								DBG_INFO("send notification (%d) to %s successfully", NOTIFY_ACTION, e->clientIP);
								if (action == ACTION_RE_RECONNECT) {
									cm_setReOffline(&p_client_tbl->reportStartTime[j]);
									ht_remove(clientHashTable, macStr, ipStr);
								}
							}
							else
							{
								DBG_INFO("send notification (%d) to %s failed", NOTIFY_ACTION, e->clientIP);
								if (action == ACTION_RE_RECONNECT)
									e->reconnStatus = 0;
							}
						}
					}
				}
			}
		}
	}

	if (capDoAction)
		cm_actionHandler((unsigned char *)json_object_get_string(notifyDataObj));

	json_object_put(notifyDataObj);
} /* End of cm_notifyAction */

/*========================================================================
Routine Description:
	Process firmware status of the client.

Arguments:
	*clientIP		- client's IP
	*cleintMac		- client's MAC
	*msg			- the firmware status of msg

Return Value:
	None

Note:
========================================================================
*/
void cm_processFwStatus(char *clientIP, char *clientMac, char *msg)
{
	json_object *root = json_tokener_parse(msg);
	json_object *fwStatusObj = NULL;
	json_object *fwVerObj = NULL;
	json_object *macObj = NULL;
	json_object *frsModelNameObj = NULL;
	int lock;
	char frsModelName[MODEL_NAME_LEN] = {0};

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("msg(%s)", msg);

	json_object_object_get_ex(root, CFG_STR_FWSTATUS, &fwStatusObj);
	json_object_object_get_ex(root, CFG_STR_MAC, &macObj);
	json_object_object_get_ex(root, CFG_STR_FWVER, &fwVerObj);
	json_object_object_get_ex(root, CFG_STR_FRS_MODEL_NAME, &frsModelNameObj);

	if (frsModelNameObj)
		strlcpy(frsModelName, json_object_get_string(frsModelNameObj), sizeof(frsModelName));	

	if (fwStatusObj) {      /* update firmware status of the client in clientHashTable */
		int fwStatus = json_object_get_int(fwStatusObj);
		ht_update_status(clientHashTable, clientMac, clientIP, FW_STATUS, fwStatus);

		/* update firmware version */
		if (fwStatus == FW_SUCCESS_CHECK && macObj && fwVerObj) {
			char realMac[18] = {0};
			int i = 0;

			pthread_mutex_lock(&cfgLock);
			lock = file_lock(CFG_FILE_LOCK);
			for (i = 0; i < p_client_tbl->count; i++) {
				memset(realMac, 0, sizeof(realMac));
				snprintf(realMac, sizeof(realMac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);
				if (!strcmp(realMac, json_object_get_string(macObj))) {
					snprintf(p_client_tbl->newFwVer[i], sizeof(p_client_tbl->newFwVer[i]), "%s",
						json_object_get_string(fwVerObj));
					if (strlen(frsModelName))
						snprintf(p_client_tbl->frsModelName[i], sizeof(p_client_tbl->frsModelName[i]), "%s",
							frsModelName);
				}
			}
			file_unlock(lock);
			pthread_mutex_unlock(&cfgLock);
		}
	}
	json_object_put(root);
} /* End of cm_processFwStatus */

/*========================================================================
Routine Description:
	Process changed config msg.

Arguments:
	*msg	- changed config msg

Return Value:
	None

Note:
==========================================================================
*/
void cm_processChangedConfigMsg(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	json_object *macObj = NULL, *configObj = NULL;
	char mac[18] = {0};

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_get_ex(root, CFG_STR_MAC, &macObj);
	json_object_object_get_ex(root, CFG_STR_CHANGED_CONFIG, &configObj);

	if (macObj && configObj) {
		snprintf(mac, sizeof(mac), "%s", json_object_get_string(macObj));
		if (cm_checkReListExist(mac))
			cm_updatePrivateConfig(mac, configObj);
	}

	json_object_put(root);
} /* End of cm_processChangedConfigMsg */

/*
========================================================================
Routine Description:
	Process REQ_KU packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_KU(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	TLV_Header packetTlvHdr;
	unsigned char *packet = NULL;

	DBG_INFO("tlv.type(%d) tlv.len(%d)", ntohl(tlv.type), ntohl(tlv.len));
	DBG_INFO("public key request ... OK");
	DBG_INFO("%s(%d) reply public key request ...", ST_NAME, sock);
	DBG_INFO("pCtrlBK->publicKeyLen[%d], pCtrlBK->privateKeyLen[%d]", pCtrlBK->publicKeyLen, pCtrlBK->privateKeyLen);
	MALLOC(packet, unsigned char, (sizeof(TLV_Header) + pCtrlBK->publicKeyLen));
	if (IsNULL_PTR(packet))
	{
		DBG_ERR("Failed to MALLOC() for packet !!!");
		return 0;
	}

	memset(&packetTlvHdr, 0, sizeof(TLV_Header));
	packetTlvHdr.type = htonl(RES_KU);
	packetTlvHdr.len = htonl(pCtrlBK->publicKeyLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (void*)&pCtrlBK->publicKey[0], pCtrlBK->publicKeyLen));
	memcpy((unsigned char *)packet, (unsigned char *)&packetTlvHdr, sizeof(packetTlvHdr));
	memcpy((unsigned char *)packet+sizeof(packetTlvHdr), (unsigned char *)&pCtrlBK->publicKey[0], pCtrlBK->publicKeyLen);

	if (write(sock, (unsigned char *)&packet[0], sizeof(TLV_Header)+pCtrlBK->publicKeyLen) != sizeof(TLV_Header)+pCtrlBK->publicKeyLen)
	{
		MFREE(packet);
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	MFREE(packet);
	DBG_INFO("OK");

	return 1;
} /* End of cm_processREQ_KU */

/*
========================================================================
Routine Description:
	Process REQ_NC packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_NC(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	unsigned char *P1 = NULL;
	unsigned char *PP = NULL;
	unsigned char *PPP = NULL;
	unsigned char decodeMsg[4098] = {0};
	unsigned char *encodeMsg = NULL;
	size_t decodeMsgLen = 0;
	size_t encodeMsgLen = 0;
	TLV_Header packetTlvHdr;

	DBG_INFO("tlv.type(%d) tlv.len(%d)", ntohl(tlv.type), ntohl(tlv.len));
	DBG_INFO("nonce request ...");

	if (ntohl(tlv.len) <= 0 || ntohl(tlv.crc) <= 0)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc))
	{
		DBG_ERR("Verify checksum error !!!");
		return 0;
	}

	memset(decodeMsg, 0, sizeof(decodeMsg));
	decodeMsgLen = rsa_decrypt(packetMsg, ntohl(tlv.len), pCtrlBK->privateKey, pCtrlBK->privateKeyLen, decodeMsg, sizeof(decodeMsg), 0 /* private */);
	if (decodeMsgLen <= 0)
	{
		DBG_ERR("Failed to rsa_decrypt() !!!");
		return 0;
	}

	DBG_INFO("OK.");
	DBG_INFO("%s(%d) get master key ...", ST_NAME, sock);
	if (sizeof(TLV_Header) > decodeMsgLen)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	P1 = (unsigned char *)&decodeMsg[0];
	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	memcpy(&packetTlvHdr, P1, sizeof(packetTlvHdr));
	if (ntohl(packetTlvHdr.len) <= 0 || ntohl(packetTlvHdr.crc) <= 0)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	P1 += sizeof(TLV_Header);
	decodeMsgLen -= sizeof(TLV_Header);
	if (ntohl(packetTlvHdr.type) != MASTER_KEY)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (ntohl(packetTlvHdr.len) > decodeMsgLen)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (ntohl(packetTlvHdr.crc) != Adv_CRC32(0, P1, ntohl(packetTlvHdr.len)))
	{
		DBG_ERR("Verify checksum error !!!");
		return 0;
	}

	keyInfo->masterKeyLen = ntohl(packetTlvHdr.len);
	MALLOC(keyInfo->masterKey, unsigned char, keyInfo->masterKeyLen);
	if (IsNULL_PTR(keyInfo->masterKey))
	{
		DBG_ERR("KM : Memory allocate error !!!");
		return 0;
	}

	memset(keyInfo->masterKey, 0, keyInfo->masterKeyLen);
	memcpy((unsigned char *)&keyInfo->masterKey[0], (unsigned char *)P1, keyInfo->masterKeyLen);
	P1 += ntohl(packetTlvHdr.len);
	decodeMsgLen -= ntohl(packetTlvHdr.len);
	DBG_INFO("OK.");

	DBG_INFO("%s(%d) get client nonce ...", ST_NAME, sock);
	if (sizeof(TLV_Header) > decodeMsgLen)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}
	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	memcpy(&packetTlvHdr, P1, sizeof(packetTlvHdr));
	if (ntohl(packetTlvHdr.len) <= 0 || ntohl(packetTlvHdr.crc) <= 0)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}
	P1 += sizeof(TLV_Header);
	decodeMsgLen -= sizeof(TLV_Header);
	if (ntohl(packetTlvHdr.type) != CLIENT_NONCE)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (ntohl(packetTlvHdr.len) > decodeMsgLen)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	DBG_INFO("The length of master key is %d", ntohl(packetTlvHdr.len));
	if (ntohl(packetTlvHdr.len) != SHA256_DIGEST_LENGTH)
	{
		DBG_ERR("Parsing data error !!!");
		return 0;
	}

	if (ntohl(packetTlvHdr.crc) != Adv_CRC32(0, P1, ntohl(packetTlvHdr.len)))
	{
		DBG_ERR("Verify checksum error !!!");
		return 0;
	}

	keyInfo->clientNounceLen = ntohl(packetTlvHdr.len);
	MALLOC(keyInfo->clientNounce, unsigned char, keyInfo->clientNounceLen);
	if (IsNULL_PTR(keyInfo->clientNounce))
	{
		DBG_ERR("NC : Memory allocate error !!!");
		return 0;
	}
	memset(keyInfo->clientNounce, 0, keyInfo->clientNounceLen);
	memcpy((unsigned char *)&keyInfo->clientNounce[0], (unsigned char *)P1, keyInfo->clientNounceLen);
	P1 += ntohl(packetTlvHdr.len);
	decodeMsgLen -= ntohl(packetTlvHdr.len);
	DBG_INFO("OK.");

	DBG_INFO("%s(%d) generator server nonce ...", ST_NAME, sock);
	keyInfo->serverNounce = gen_rand(&keyInfo->serverNounceLen);
	if (IsNULL_PTR(keyInfo->serverNounce))
	{
		DBG_ERR("NS : gen_rand() error !!");
		return 0;
	}
	DBG_INFO("OK.");
	DBG_INFO("%s(%d) reply nonce request ...", ST_NAME, sock);
	MALLOC(PPP, unsigned char, (sizeof(TLV_Header)+keyInfo->serverNounceLen+sizeof(TLV_Header)+keyInfo->clientNounceLen));
	if (IsNULL_PTR(PPP))
	{
		DBG_ERR("Failed to MALLOC() !!!");
		return 0;
	}

	memset(PPP, 0, sizeof(TLV_Header)+keyInfo->serverNounceLen+sizeof(TLV_Header)+keyInfo->clientNounceLen);
	P1 = &PPP[0];
	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(SERVER_NONCE);
	packetTlvHdr.len = htonl(keyInfo->serverNounceLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (unsigned char *)&keyInfo->serverNounce[0], keyInfo->serverNounceLen));
	memcpy((unsigned char *)P1, &packetTlvHdr, sizeof(packetTlvHdr));
	P1 += sizeof(packetTlvHdr);
	memcpy((unsigned char *)P1, (unsigned char *)&keyInfo->serverNounce[0], keyInfo->serverNounceLen);
	P1 += keyInfo->serverNounceLen;

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(CLIENT_NONCE);
	packetTlvHdr.len = htonl(keyInfo->clientNounceLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (unsigned char *)&keyInfo->clientNounce[0], keyInfo->clientNounceLen));
	memcpy((unsigned char *)P1, &packetTlvHdr, sizeof(packetTlvHdr));
	P1 += sizeof(packetTlvHdr);
	memcpy((unsigned char *)P1, (unsigned char *)&keyInfo->clientNounce[0], keyInfo->clientNounceLen);
	P1 += keyInfo->clientNounceLen;

	// aes encrypt
	encodeMsg = aes_encrypt(keyInfo->masterKey, PPP, sizeof(TLV_Header)+keyInfo->serverNounceLen+sizeof(TLV_Header)+keyInfo->clientNounceLen, &encodeMsgLen);
	if (IsNULL_PTR(encodeMsg))
	{
		MFREE(PPP);
		DBG_ERR("Failed to aes_encrypt() !!!!");
		return 0;
	}

	MALLOC(PP, unsigned char, (sizeof(TLV_Header)+encodeMsgLen));
	if (IsNULL_PTR(PP))
	{
		MFREE(encodeMsg);
		MFREE(PPP);
		DBG_ERR("Failed to MALLOC() !!!");
		return 0;
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RES_NC);
	packetTlvHdr.len = htonl(encodeMsgLen);
	packetTlvHdr.crc = htonl(Adv_CRC32(0, (void*)&encodeMsg[0], encodeMsgLen));
	memcpy((unsigned char *)PP, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
	memcpy((unsigned char *)PP+sizeof(TLV_Header), (unsigned char *)&encodeMsg[0], encodeMsgLen);
	if (write(sock, PP, sizeof(TLV_Header)+encodeMsgLen) != sizeof(TLV_Header)+encodeMsgLen)
	{
		MFREE(encodeMsg);
		MFREE(PP);
		MFREE(PPP);
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	MFREE(PP);
	MFREE(PPP);
	MFREE(encodeMsg);
	DBG_INFO("OK");
	return 1;
} /* End of cm_processREQ_NC */

/*
========================================================================
Routine Description:
	Process REP_OK packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREP_OK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	unsigned char *sessionKey = NULL;
	size_t sessionKeyLen = 0;
	time_t sessionKeyStartTime = {0};
	TLV_Header packetTlvHdr;

	DBG_INFO("Got REP_OK ...");
	DBG_INFO("generate session key ...");
	//sessionKey = gen_session_key(keyInfo->masterKey, keyInfo->masterKeyLen, keyInfo->serverNounce,
	//				 keyInfo->serverNounceLen, keyInfo->clientNounce, keyInfo->clientNounceLen, &sessionKeyLen);
	sessionKey = gen_session_key((unsigned char *)&groupID[0], strlen(groupID),
		keyInfo->serverNounce, keyInfo->serverNounceLen, keyInfo->clientNounce,
		keyInfo->clientNounceLen, &sessionKeyLen);
	if (IsNULL_PTR(sessionKey))
	{
		DBG_ERR("Failed to gen_session_key() !!!");
		return 0;
	}

	/* save sessionKey in hash table */
	sessionKeyStartTime = uptime();
	ht_put(clientHashTable, clientMac, clientIP, sessionKey, sessionKeyLen, sessionKeyStartTime);

	DBG_INFO("OK");
	DBG_INFO("%s(%d) ack done ...", ST_NAME, sock);
	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(ACK_OK);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header))
	{
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}
	DBG_INFO("OK");
	return 1;
} /* End of cm_processREP_OK */

/*
========================================================================
Routine Description:
	Process REQ_CHK packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_CHK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_CHK ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no message");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg))
		{
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("%s decryption message - OK", ST_NAME);

		memset(msgBuf, 0, sizeof(msgBuf));
		if (cm_checkCfgInfo(clientMac, decodeMsg, (char *)&msgBuf[0], MAX_MESSAGE_SIZE, 1) > 0) {
			encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_CHK, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

			if (IsNULL_PTR(encryptedMsg)) {
				DBG_ERR("Failed to MALLOC() !!!");
				MFREE(decodeMsg);
				return 0;
			}
		}
		else
		{
			memset(&packetTlvHdr, 0, sizeof(TLV_Header));
			packetTlvHdr.type = htonl(RSP_CHK);
			MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
			memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
			encryptedMsgLen = sizeof(TLV_Header);
		}

		MFREE(decodeMsg);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_CHK */

/*
========================================================================
Routine Description:
	Process ACK_CHK packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processACK_CHK(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
#ifdef ONBOARDING_VIA_VIF
	char reMac[18] = {0}, obReMac[18] = {0}, reTrafficMac[18] = {0}, reIp[18] = {0};
#endif

	DBG_INFO("Got ACK_CHK ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

#ifdef ONBOARDING_VIA_VIF
	if (cm_getReMacByIp(p_client_tbl, clientIP, reMac, sizeof(reMac)) > 0) {
		if (!cm_checkObVifReListUpdate(reMac) && cm_getObVifReByNewReMac(reMac, obReMac, sizeof(obReMac))) {
			if (!strcasecmp(obReMac, get_re_hwaddr())) {	/* for CAP */
				cm_updateObVifReList(reMac, NULL, RELIST_DEL);
				sleep(3);
				cm_obVifDownUp(OB_VIF_DOWN);
			}
			else		/* for RE */
			{
				if (cm_getReIpByReMac(p_client_tbl, obReMac, reIp, sizeof(reIp)) > 0 &&
					cm_getReTrafficMacByReMac(p_client_tbl, obReMac, reTrafficMac, sizeof(reTrafficMac)) > 0) {
					if ((e = ht_get(clientHashTable, reTrafficMac, reIp))) {
						if (cm_sendNotification(e, NOTIFY_ONBOARDING_VIF_DOWN, NULL)) {
							DBG_INFO("send notification(%d) to %s(%s) success", NOTIFY_ONBOARDING_VIF_DOWN, obReMac, reIp);
							cm_updateObVifReList(reMac, NULL, RELIST_DEL);
						}
						else
							DBG_ERR("send notification(%d) to %s(%s) failed", NOTIFY_ONBOARDING_VIF_DOWN, obReMac, reIp);
					}
				}
			}
		}
	}
#endif

	return 1;
} /* End of cm_processACK_COST */


/*
========================================================================
Routine Description:
	Process REQ_JOIN packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/

int cm_processREQ_JOIN(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
        unsigned char hex[16] = {0};
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
        int i = 0;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
	char joinMac[18] = {0};

	DBG_INFO("Got REQ_JOIN");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0)
		DBG_INFO("no message");
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}

		DBG_INFO("%s decryption message ...", ST_NAME);

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_INFO("Decryption failed, slave is invalid!");
			ht_remove(clientHashTable, clientMac, clientIP);
			return 0;
		}

		if (e->authorized) {
			DBG_INFO("Slave had authorized, slave is invalid!");
			MFREE(decodeMsg);
			return 0;
		}

#if defined(RTCONFIG_WIFI_SON)
		if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
		{
		if (nvram_get_int("cfg_recount") > 0) {
			if (get_join_unique_mac(decodeMsg,joinMac, sizeof(joinMac)) == 0) {
				DBG_INFO("Cannot get unique MAC from join RE.");
				MFREE(decodeMsg);
				return 0;
			}

			if (!cm_checkReListExist(joinMac)) {
				DBG_INFO("Slave isn't on cfg_relist!");
				MFREE(decodeMsg);
				return 0;
			}
		}
		else {
			DBG_INFO("Slave is invalid because RE count is zero.");
			MFREE(decodeMsg);
			return 0;
		}
		} /* !wifison_ready */

		DBG_INFO("Slave is valid!");

#ifdef RTCONFIG_DWB
		cm_checkDwbSwitch(decodeMsg);
#endif	/* RTCONFIG_DWB */

		/* update the status of re join */
		nvram_set_int("cfg_rejoin", 1);

#ifdef PRELINK
#if defined(RTCONFIG_WIFI_SON)
		if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
		/* update prelink status */
		cm_updatePrelinkStatus(joinMac, PRELINK_JOIN);
#endif
#if defined(RTCONFIG_AMAS) && (defined(RTCONFIG_LP5523) || defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED))
		nvram_set_int("cfg_alive", 1);
#endif

		/* log for re join*/
		DBG_LOG("RE (%s %s) join", joinMac, clientIP);

		/* update authorized info in hash table */
		ht_update(clientHashTable, clientMac, clientIP, (char *)decodeMsg);

		/* update related info for slave */
		cm_updateSlaveRelatedInfo(decodeMsg);

		if (cm_prepareJoinReturnData(joinMac, decodeMsg, (char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
			DBG_INFO("have private cfg from slave");
			cm_updateReListTimestamp(decodeMsg);
		}
		else
		{
			/* prepare message for client to verify server */
			/* generate 32 bytes random for string */
			srand(time(NULL));
			for (i = 0; i < sizeof(hex); i++)
				hex[i] = rand() % 256;
				hex2str(&hex[0], (char *)&msgBuf[0], sizeof(hex));
		}
#if defined(RTCONFIG_AMAS)
		/* update sta of 2G & 5G to amas lib */
		cm_updateStaMacToAmasLib(decodeMsg);
#endif

#ifdef RTCONFIG_FRONTHAUL_DWB
		/* Reset backhual status */
		reset_BackhualStatus(joinMac);
#endif
		/* encrypt message */
		encryptedMsg = cm_aesEncryptMsg(e->sessionKey, RSP_JOIN, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);
		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0) {
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	DBG_INFO("OK");
	return 1;
} /* End of cm_processREQ_JOIN */

/*
========================================================================
Routine Description:
	Process REQ_RPT packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_RPT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
	int bandNum = 0, join = JOIN_DONE, triggerSelfOpt = 0;
#ifdef RTCONFIG_BHCOST_OPT
	json_object *notifiedRe = NULL;
#endif
	json_object *onlineListObj = NULL, *offlineListObj = NULL;

	DBG_INFO("Got REQ_RPT ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (e->reconnStatus) {
		DBG_ERR("client is under reconnnect status");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("msg(%s)", decodeMsg);

		if (!(onlineListObj = json_object_new_array()) || !(offlineListObj = json_object_new_array())) {
			DBG_ERR("onlineListObj/offlineListObj is NULL !!!");
			if (onlineListObj)
				json_object_put(onlineListObj);
			if (offlineListObj)
				json_object_put(offlineListObj);
			return 0;
		}

		join = e->joinStatus;

		triggerSelfOpt = cm_updateClientTbl(decodeMsg, clientMac, clientIP, &bandNum, !join, onlineListObj, offlineListObj);

#ifdef RTCONFIG_BHCOST_OPT
#ifdef RTCONFIG_PREFERAP_RE_SELFOPT
		if (!join)
			notifiedRe = cm_sendSelfOptByPreferAp(decodeMsg);
#endif	/* RTCONFIG_PREFERAP_RE_SELFOPT */

#ifdef RTCONFIG_BHSWITCH_RE_SELFOPT
		if (triggerSelfOpt)
			cm_sendSelfOptimization(decodeMsg, notifiedRe);
#else
		/* check and notify RE self optimization */
		if (!e->soStatus && cm_sendSelfOptimization(decodeMsg, notifiedRe))
			ht_update_status(clientHashTable, clientMac, clientIP, SO_STATUS, SO_DONE);
#endif	/* RTCONFIG_BHSWITCH_RE_SELFOPT */

		json_object_put(notifiedRe);
#endif

		if (!join) {
#ifdef STA_BIND_AP
		/* check and notify CAP/RE update sta binding */
			cm_updateStaBindingAp(0, NULL);
#endif /* STA_BIND_AP */
			ht_update_status(clientHashTable, clientMac, clientIP, JOIN_STATUS, JOIN_DONE);
		}
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (
#if defined(RTCONFIG_WIFI_SON)
		!nvram_match("wifison_ready", "1") &&
#endif /* WIFI_SON */
		cm_prepareReportRspMsg(decodeMsg, bandNum, join, (char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_RPT, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			if (!IsNULL_PTR(decodeMsg)) MFREE(decodeMsg);

			if (onlineListObj)
				json_object_put(onlineListObj);
			if (offlineListObj)
				json_object_put(offlineListObj);
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_RPT);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");

	if (!IsNULL_PTR(decodeMsg)) MFREE(decodeMsg);
	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);


#ifdef RTCONFIG_NOTIFICATION_CENTER
	cm_notifyWiredClientEvent(onlineListObj, offlineListObj);
#endif
	if (onlineListObj)
		json_object_put(onlineListObj);
	if (offlineListObj)
		json_object_put(offlineListObj);

	return 1;
} /* End of cm_processREQ_RPT */

/*
========================================================================
Routine Description:
	Process REQ_SREKEY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_SREKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_SREKEY ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareSessionKey(e, decodeMsg, (char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_SREKEY, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_SREKEY);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	MFREE(decodeMsg);

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_SREKEY */

/*
========================================================================
Routine Description:
	Process REQ_GKEY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_GKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	//int groupKeyExpired = 0;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_GKEY ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareGroupKey((char *)&msgBuf[0], MAX_MESSAGE_SIZE, 0) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_GKEY, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_GKEY);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

#if 0
	/* have re-create group key and then send group rekey notification to all clients */
	if (groupKeyExpired)
		cm_sendGroupRekeyExceptIp(clientIP);
#endif

	return 1;
} /* End of cm_processREQ_GKEY */

/*
========================================================================
Routine Description:
	Process REQ_GREKEY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_GREKEY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_GREKEY ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareGroupKey((char *)&msgBuf[0], MAX_MESSAGE_SIZE, 1) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_GREKEY, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
		return 0;
	}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_GREKEY);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
		DBG_ERR("Failed to socket write() !!!");

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_GREKEY */

/*
========================================================================
Routine Description:
	Process REQ_WEVENT packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_WEVENT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
#ifdef DUAL_BAND_DETECTION
	json_object *dualBandObj = NULL;
	unsigned char msg[MAX_PACKET_SIZE] = {0};
#endif

	DBG_INFO("Got REQ_WEVENT ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

        if (!e->authorized) {
                DBG_ERR("client is not authorized");
                return 0;
        }

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_WEVENT);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
#ifdef DUAL_BAND_DETECTION
		if (cm_processWevent((char *)decodeMsg)) {
			memset(msg, 0, sizeof(msg));
			if (cm_prepareDualBandListMsg(msg, MAX_PACKET_SIZE)) {
				if ((dualBandObj = json_tokener_parse(msg)) != NULL) {
					cm_sendNotificationByType(NOTIFY_UPDATEDBLIST, dualBandObj);
					json_object_put(dualBandObj);
				}
			}
		}
#else
		cm_processWevent((char *)decodeMsg);
#endif
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_WEVENT */

/*
========================================================================
Routine Description:
	Process REQ_STALIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_STALIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_STALIST ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

        if (!e->authorized) {
                DBG_ERR("client is not authorized");
                return 0;
        }

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_STALIST);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
		cm_processStaList((char *)decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_STALIST */

/*
========================================================================
Routine Description:
	Process REQ_FWSTAT packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg		- package message
	clientIP		- client's IP
	cleintMac		- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_FWSTAT(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_FWSTAT ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

        if (!e->authorized) {
                DBG_ERR("client is not authorized");
                return 0;
        }

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0)
		DBG_INFO("no info");
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		DBG_INFO("%s decryption message ...", ST_NAME);

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_FWSTAT);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
		cm_processFwStatus(clientIP, clientMac, (char *)decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_FWSTAT */

#if 0
/*
========================================================================
Routine Description:
	Process REQ_CHANSYNC packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_CHANSYNC(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_CHANSYNC ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareWirelessChannel((char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_CHANSYNC, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg))
		{
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_CHANSYNC);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0) {
		DBG_ERR("Failed to socket write() !!!");
		return 0;
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_CHANSYNC */
#endif
#ifdef RTCONFIG_FRONTHAUL_DWB
int cm_processREQ_BACKHUALSTATUS(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
	unsigned char *decodeMsg = NULL;

	DBG_INFO("Got REQ_BACKHUALREQUEST ...");

	DBG_INFO("Got REQ_BACKHUALREQUEST %s %s ...",clientIP,clientMac);

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0 || strlen((char *)packetMsg) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareBackhualStatus(clientMac, clientIP, (char *)decodeMsg, (char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_BACKHUALSTATUS, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			MFREE(decodeMsg);
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_BACKHUALSTATUS);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	MFREE(decodeMsg);
	MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_BACKHUALSTATUS */
#endif

/*
========================================================================
Routine Description:
	Process REQ_COST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_COST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
	unsigned char *decodeMsg = NULL;

	DBG_INFO("Got REQ_COST ...");

	DBG_INFO("Got REQ_COST %s %s ...",clientIP,clientMac);

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0 || strlen((char *)packetMsg) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareNetworkCost(clientMac, clientIP, (char *)decodeMsg, (char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_COST, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			MFREE(decodeMsg);
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_COST);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	MFREE(decodeMsg);
	MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_COST */

/*
========================================================================
Routine Description:
	Process REQ_LEVEL packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_LEVEL(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;
	unsigned char *decodeMsg = NULL;

	DBG_INFO("Got REQ_LEVEL ...");

	DBG_INFO("Got REQ_LEVEL %s %s ...",clientIP,clientMac);

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0 || strlen((char *)packetMsg) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareNetworkLevel(clientMac, clientIP, (char *)decodeMsg, (char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_LEVEL, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			MFREE(decodeMsg);
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_LEVEL);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	MFREE(decodeMsg);
	MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_LEVEL */

/*
========================================================================
Routine Description:
	Process REQ_TOPOLOGY packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_TOPOLOGY(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_TOPOLOGY ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareNetworkTopology((char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_TOPOLOGY, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_TOPOLOGY);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	MFREE(decodeMsg);

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_TOPOLOGY */

/*
========================================================================
Routine Description:
	Process REQ_CLIENTLIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_CLIENTLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_CLIENTLIST ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

        if (!e->authorized) {
                DBG_ERR("client is not authorized");
                return 0;
        }

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_CLIENTLIST);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
		cm_processClientList((char *)decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_STALIST */

#ifdef ONBOARDING
/*
========================================================================
Routine Description:
	Process REQ_ONBOARDING packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_ONBOARDING(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_ONBOARDING ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_ONBOARDING);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
		cm_processOnboardingMsg((char *)decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_ONBOARDING */
#endif	/* ONBOARDING */

/*
========================================================================
Routine Description:
	Process REQ_RELIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_RELIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_RELIST ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareReListMsg((char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_RELIST, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_RELIST);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_COST */
#ifdef RTCONFIG_BCN_RPT
/*
========================================================================
Routine Description:
	Process REQ_APLIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_APLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_APLIST ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));
	if (cm_prepareAPListMsg((char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_APLIST, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_APLIST);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_APLIST */
#endif
#ifdef DUAL_BAND_DETECTION
/*
========================================================================
Routine Description:
	Process REQ_DBLIST packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_DBLIST(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char msgBuf[MAX_PACKET_SIZE] = {0};
	unsigned char *encryptedMsg = NULL;
	size_t encryptedMsgLen = 0;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;

	DBG_INFO("Got REQ_DBLIST ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	memset(msgBuf, 0, sizeof(msgBuf));

	if (cm_prepareDualBandListMsg((char *)&msgBuf[0], MAX_MESSAGE_SIZE) > 0) {
		encryptedMsg = cm_aesEncryptMsg(sessionKey, RSP_DBLIST, &msgBuf[0], strlen((char *)msgBuf) + 1, &encryptedMsgLen);

		if (IsNULL_PTR(encryptedMsg)) {
			DBG_ERR("Failed to MALLOC() !!!");
			return 0;
		}
	}
	else
	{
		memset(&packetTlvHdr, 0, sizeof(TLV_Header));
		packetTlvHdr.type = htonl(RSP_DBLIST);
		MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header));
		memcpy(encryptedMsg, (unsigned char *)&packetTlvHdr, sizeof(TLV_Header));
		encryptedMsgLen = sizeof(TLV_Header);
	}

	if (write(sock, (char*)encryptedMsg, encryptedMsgLen) <= 0)
	{
		DBG_ERR("Failed to socket write() !!!");
	}

	if (!IsNULL_PTR(encryptedMsg)) MFREE(encryptedMsg);

	return 1;
} /* End of cm_processREQ_DBLIST */
#endif

/*
========================================================================
Routine Description:
	Process REQ_CHANGED_CONFIG packet.

Arguments:
	sock		- socket fd
	pCtrlBK		- CM control blcok
	tlv		- packet's TLV header
	keyInfo		- security information
	packetMsg	- package message
	clientIP	- client's IP
	cleintMac	- client's MAC

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_processREQ_CHANGED_CONFIG(int sock, CM_CTRL *pCtrlBK, TLV_Header tlv, securityInfo *keyInfo, unsigned char *packetMsg, char *clientIP, char *clientMac)
{
	hash_elem_t* e = NULL;
	unsigned char *decodeMsg = NULL;
	TLV_Header packetTlvHdr;
	unsigned char *sessionKey = NULL;
	unsigned char *sessionKeyExpired = NULL;

	DBG_INFO("Got REQ_CHANGED_CONFIG ...");

	if ((e = ht_get(clientHashTable, clientMac, clientIP)) == NULL) {
		DBG_ERR("ht_get is NULL !!!");
		return 0;
	}

	if (!e->authorized) {
		DBG_ERR("client is not authorized");
		return 0;
	}

	if (cm_checkSessionKeyExpire(e)) {
		DBG_ERR("session key is expired");
		return 0;
	}

	if ((sessionKey = cm_selectSessionKey(e, 1)) == NULL) {
		DBG_ERR("no session key be selected");
		return 0;
	}

	/* select another session key for expired */
	sessionKeyExpired = cm_selectSessionKey(e, 0);

	if (ntohl(tlv.len) == 0) {
		DBG_INFO("no info");
	}
	else
	{
		if (Adv_CRC32(0, packetMsg, ntohl(tlv.len)) != ntohl(tlv.crc)) {
			DBG_ERR("Verify checksum error !!!");
			return 0;
		}
		DBG_INFO("OK");

		decodeMsg = cm_aesDecryptMsg(sessionKey, sessionKeyExpired, (unsigned char *)packetMsg, ntohl(tlv.len));
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to cm_aesDecryptMsg() !!!");
			return 0;
		}
		DBG_INFO("OK");
	}

	memset(&packetTlvHdr, 0, sizeof(packetTlvHdr));
	packetTlvHdr.type = htonl(RSP_CHANGED_CONFIG);
	if (write(sock, (char *)&packetTlvHdr, sizeof(TLV_Header)) != sizeof(TLV_Header)) {
		DBG_ERR("Failed to socket write() !!!");
		MFREE(decodeMsg);
		return 0;
	}
	DBG_INFO("OK");

	if (!IsNULL_PTR(decodeMsg)) {
		cm_processChangedConfigMsg((char *)decodeMsg);
		MFREE(decodeMsg);
	}

	return 1;
} /* End of cm_processREQ_CHANGED_CONFIG */

/*
========================================================================
Routine Description:
        Send TCP packet to server.

Arguments:
        pktType         - packet for request type
        *msg            - encrypted message need to be sent out
        msgLen          - legnth of encrypted message

Return Value:
        0               - fail
        1               - success

========================================================================
*/
int cm_sendTcpPacket(int pktType, unsigned char *msg)
{
	//TODO
	return 1;
} /* End of cm_sendTcpPacket */

/*
========================================================================
Routine Description:
	Process all packet.

Arguments:
	sock_fd		- socket fd
	data		- received data
	data_len	- received data length
	client_ip	- client's IP
	cleint_mac	- client's MAC
	pCtrlBK		- CM control blcok
	keyInfo		- security information

Return Value:
	0		- continue to receive
	1		- break to receive

========================================================================
*/
int cm_packetProcess(
	int sock_fd,
	unsigned char *data,
	int data_len,
	char *client_ip,
	char *client_mac,
	CM_CTRL *pCtrlBK,
	securityInfo *keyInfo)
{
	int sock = sock_fd, len = 0, i = 0;
	unsigned char *pData = NULL;
	TLV_Header tlv, tlv_hdr;

	if (IsNULL_PTR(data)) {
		DBG_ERR("data is null !!!");
		return 1;
	}

	pData = (unsigned char *)&data[0];
	len = data_len;
	DBG_INFO("data_len(%d)", len);
	for (i=0; i<len; )
	{
		struct packetHandler *handler;

		if (i+sizeof(TLV_Header) > len) {
			DBG_WARNING("Error on receive size !!!");
			break;
		}
		memset(&tlv, 0, sizeof(TLV_Header));
		memcpy((unsigned char *)&tlv, (unsigned char *)pData, sizeof(TLV_Header));

		if (ntohl(tlv.len) != (len - sizeof(TLV_Header))) {
			DBG_ERR("Checking length error !!!");
			goto packetProcess_fail;
		}

		pData += sizeof(TLV_Header);
		i += sizeof(TLV_Header);
		if (ntohl(tlv.type) <= 0 && ntohl(tlv.type) > 99) {
			DBG_WARNING("Invalid TLV type !!!");
			break;
		}
		DBG_INFO("tlv.type(%s)", ST_NAME);

		handler = NULL;
		for(handler = &packetHandlers[0]; handler->type > 0; handler++) {
			if (handler->type == ntohl(tlv.type))
				break;
		}

		if (handler == NULL || handler->type < 0)
			DBG_INFO("no corresponding function pointer(%d)", ntohl(tlv.type));
		else
		{
			if (!handler->func(sock_fd, pCtrlBK, tlv, keyInfo, (unsigned char *)&pData[0], client_ip, client_mac))
				goto packetProcess_fail;
		}

		switch (ntohl(tlv.type))
		{
			case RES_NAK:
				DBG_INFO("reply un-ack ...");
				DBG_INFO("Abort, disconnect ...");
				return 1;
			case ACK_CHK:
			case RSP_NTF:
			case REQ_RPT:
			case REQ_GKEY:
			case ACK_GKEY:
			case ACK_CHANSYNC:
			case REQ_JOIN:
			case REQ_WEVENT:
			case REQ_STALIST:
			case REQ_FWSTAT:
			case REQ_CLIENTLIST:
			case REQ_COST:
			case REQ_TOPOLOGY:
#ifdef ONBOARDING
			case REQ_ONBOARDING:
			case ACK_GROUPID:
#endif
			case REQ_SREKEY:
			case REQ_GREKEY:
			case REQ_RADARDET:
			case REQ_RELIST:
			case REQ_APLIST:
			case REQ_DBLIST:
			case REQ_CHANGED_CONFIG:
			case REQ_LEVEL:
#ifdef RTCONFIG_FRONTHAUL_DWB
			case REQ_BACKHUALSTATUS:
#endif
				DBG_INFO("Got %s...", ST_NAME);
				return 1;
		}
		pData += ntohl(tlv.len);
		i += ntohl(tlv.len);
	}

	return 0;

packetProcess_fail:
	memset(&tlv_hdr, 0, sizeof(tlv_hdr));
	tlv_hdr.type = htonl(RES_NAK);
	if (write(sock, (unsigned char *)&tlv_hdr, sizeof(tlv_hdr)) != sizeof(tlv_hdr))
		DBG_ERR("Failed to socket write !!!");

	return 1;
} /* End of cm_packetProcess */

/*
========================================================================
Routine Description:
	Create a thread to handle received TCP packets.

Arguments:
	*args		- arguments for socket

Return Value:
	None

Note:
========================================================================
*/
void *cm_tcpPacketHandler(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());

        struct sockaddr_in cliAddr;
        int cliAddrLen = 0;
	//socketInfo *sockArgs = args;
	unsigned char pPktBuf[MAX_PACKET_SIZE] = {0};
	int len = 0;
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	//int newSock = *(int*)sockArgs->socketDesc;
	int newSock = *(int*)args;
	securityInfo keyInfo;
	struct timeval rcvTimeout = {3, 0};
        char clientIP[32] = {0};
        char clientMac[32] = {0};

	memset(pPktBuf, 0, sizeof(pPktBuf));
	memset(&keyInfo, 0, sizeof(keyInfo));
        cliAddrLen = sizeof(cliAddr);
        getpeername(newSock, (struct sockaddr*)&cliAddr, (socklen_t *)&cliAddrLen);
        snprintf(clientIP, sizeof(clientIP), "%s", inet_ntoa(cliAddr.sin_addr));
	cm_getClientMac(clientIP, &clientMac[0], sizeof(clientMac));

	if (strlen(clientMac) == 0) {
		DBG_INFO("clientMac is NULL");
		goto err;
	}

	DBG_INFO("new_sock(%d), client_ip(%s), client_mac(%s)", newSock, clientIP, clientMac);

	if (setsockopt(newSock, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, sizeof(struct timeval)) < 0)
		DBG_ERR("Failed to setsockopt() !!!");

	while (1)
	{
		/* handle the packet */
		memset(pPktBuf, 0, sizeof(pPktBuf));
		if ((len = read_tcp_message(newSock, &pPktBuf[0], sizeof(pPktBuf))) <= 0) {
			DBG_ERR("Failed to read_tcp_message()!");
			break;
		}

		if (cm_packetProcess(newSock, pPktBuf, len, clientIP, clientMac, pCtrlBK, &keyInfo) == 1)
			break;
	}

err:
	// free memory for keyInfo
	if (!IsNULL_PTR(keyInfo.masterKey))
		MFREE(keyInfo.masterKey);

	if (!IsNULL_PTR(keyInfo.serverNounce))
		MFREE(keyInfo.serverNounce);

	if (!IsNULL_PTR(keyInfo.clientNounce))
		MFREE(keyInfo.clientNounce);

	close(newSock);
	free(args);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
} /* End of cm_tcpPacketHandler */

/*
========================================================================
Routine Description:
	Create a thread to send cfg action.

Arguments:
	*args		- arguments for socket

Return Value:
	None

Note:
========================================================================
*/
void *cm_sendCfgAction(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());
	hashtable_t* hasht = clientHashTable;

	hash_elem_t* e = NULL;
	struct json_object *cfgRoot = NULL;
	int i = 0;
	int j = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	int applyLock = *(int*)args;

	if (nvram_get_int("cfg_rejoin"))
		sleep(CFG_ACTION_TIMEOUT);

	pthread_mutex_lock(&cfgLock);
	/* send cfg action */
	for (i = p_client_tbl->maxLevel; i >= 0; i--) {
		for (j = 1; j < p_client_tbl->count; j++) {
			hash_elem_it it = HT_ITERATOR(hasht);
			e = ht_iterate_elem(&it);

			if (p_client_tbl->level[j] != i)
				continue;

			memset(mac, 0, sizeof(mac));
			memset(ip, 0, sizeof(ip));
			snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
				p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
				p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
				p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
				p_client_tbl->ipAddr[j][3]);

			if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
				DBG_INFO("%s (%s) is offline", mac, ip);
				continue;
			}

			while(e != NULL) {
				/* send notification to all clients */
				if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
					strcmp(ip, e->clientIP) == 0)
				{
					DBG_INFO("client ip(%s), client mac(%s)", e->clientIP, e->key);
					if (!cm_sendNotification(e, NOTIFY_CFGACT, NULL))	// ask the client to do cfg action
						DBG_ERR("send notification to %s failed", e->clientIP);
				}
				e = ht_iterate_elem(&it);
			}
		}
	}
	pthread_mutex_unlock(&cfgLock);
	if ((cfgRoot = json_object_from_file(CFG_JSON_FILE)) == NULL)
		DBG_INFO("cfgRoot is null");
	else
	{
		struct json_object *actionScriptObj = NULL;

		json_object_object_get_ex(cfgRoot, "action_script", &actionScriptObj);

		if (actionScriptObj) {
			DBG_INFO("action script(%s)", json_object_get_string(actionScriptObj));
			notify_rc(json_object_get_string(actionScriptObj));
		}
		else
			DBG_INFO("no action script");

		json_object_put(cfgRoot);
		unlink(CFG_JSON_FILE);
	}

	file_unlock(applyLock);
	free(args);

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
}

/*
========================================================================
Routine Description:
	Create a thread to send group rekey.

Arguments:
	*args	 - arguments for socket

Return Value:
	None

Note:
========================================================================
*/
void *cm_sendGroupRekey(void *args)
{
#if defined(RTCONFIG_RALINK_MT7621)
        Set_CPU();
#endif
	pthread_detach(pthread_self());
	hashtable_t* hasht = clientHashTable;
	hash_elem_it it = HT_ITERATOR(hasht);
	hash_elem_t* e = ht_iterate_elem(&it);
	char clientIP[32] = {0};

	if (args) {
		snprintf(clientIP, sizeof(clientIP), "%s", (char *)args);
		DBG_INFO("client ip(%s) from args", clientIP);
		free(args);
	}

#if 0
	/* re-create group key */
	cm_ctrlBlock.groupKeyReady = 0;
	cm_generateGroupKey(&cm_ctrlBlock);
#endif

	/* send group rekey */
	while(e != NULL) {
		DBG_INFO("Client MAC(Hash Key): %s", e->key);
		DBG_INFO("Key Time: %d", (int) (uptime() - e->sessionKeyStartTime));
		if (strlen(clientIP) > 0 && !strcmp(e->clientIP, clientIP)) {
			DBG_INFO("don't need send group rekey notification for %s", clientIP);
			e = ht_iterate_elem(&it);
			continue;
		}
		cm_sendNotification(e, NOTIFY_GREKEY, NULL);      // ask the client to do group rekey
		e = ht_iterate_elem(&it);
	}

#ifdef PTHREAD_EXIT
	return (void *)1;
#else
	pthread_exit(NULL);
#endif
}  /* End of cm_sendGroupRekey */

#ifdef RTCONFIG_BHCOST_OPT
/*
========================================================================
Routine Description:
	Send self optimization notification to RE if needed.

Arguments:
	decryptedMsg		- decrypted message
	notifiedRe		- array for re have been notified self optimization

Return Value:
	0		- don't notify self optimization
	1		- notify self optimization

Note:
========================================================================
*/
int cm_sendSelfOptimization(unsigned char *decodeMsg, json_object *notifiedRe)
{
	int i = 0, j = 0, k = 0, reArrayLen = 0, foundEntry = 0, ret = 0, notifyRe = 0;
	char rmac[18], mac[18], ip[18], reMac[18];
	hash_elem_t* e = NULL;
	json_object *root = json_tokener_parse((char *)decodeMsg);
	json_object *reMacObj = NULL, *reArray = NULL, *reEntry = NULL;
	int rssiThres5g = (nvram_get("cfg_rssi5g")) ? nvram_get_int("cfg_rssi5g"): RSSI_THRESHOLD_5G;

	if (root == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return 0;
	}

	json_object_object_get_ex(root, CFG_STR_MAC, &reMacObj);
	if (reMacObj) {
		snprintf(reMac, sizeof(reMac), "%s", json_object_get_string(reMacObj));
	}
	else
	{
		DBG_ERR("reMacOb is NULL");
		json_object_put(root);
		return 0;
	}

	json_object_put(root);

	pthread_mutex_lock(&cfgLock);

	/* get joined RE list for checking self optimization or not */
	reArray = cm_recordReListArray(p_client_tbl, reMac);
	if (reArray && json_object_array_length(reArray) > 0) {
		for (i = p_client_tbl->maxLevel; i >= 0; i--) {
			for (j = 1; j < p_client_tbl->count; j++) {
				/* different level, pass it */
				if (p_client_tbl->level[j] != i)
					continue;

				memset(rmac, 0, sizeof(rmac));
				snprintf(rmac, sizeof(rmac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
					p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
					p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

				memset(mac, 0, sizeof(mac));
				snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
					p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
					p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

				memset(ip, 0, sizeof(ip));
				snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
					p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
					p_client_tbl->ipAddr[j][3]);

				/* same re mac, pass it */
				if (strcmp(rmac, reMac) == 0) {
					DBG_LOG("same re mac (%s), pass it", rmac);
					continue;
				}

				/* re offline, pass it */
				if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
					DBG_LOG("%s (%s) is offline", rmac, ip);
					continue;
				}

				/* judgement for self optimization */
				DBG_LOG("%s [2g rssi (%d), 5g rssi (%d), threshold (%d)]",
						rmac, p_client_tbl->rssi2g[j], p_client_tbl->rssi5g[j], rssiThres5g);

				if ((p_client_tbl->rssi2g[j] < 0 && p_client_tbl->rssi5g[j] == 0) ||
					(p_client_tbl->rssi5g[j] < rssiThres5g) || nvram_get_int("cfg_no_rssi_check")) {
					/* based on reArray, check RE do self optimization or not */
					foundEntry = 0;
					reArrayLen = json_object_array_length(reArray);
					for (k = 0; k < reArrayLen; k++) {
						reEntry = json_object_array_get_idx(reArray, k);
						if (strcmp(json_object_get_string(reEntry), rmac) == 0) {
							foundEntry = 1;
							break;
						}
					}

					if (foundEntry) {
						DBG_LOG("%s match condition, but it's joined RE", rmac);
						continue;
					}
					else
					{
						notifyRe = 1;
						if (notifiedRe) {
							reArrayLen = json_object_array_length(notifiedRe);
							for (k = 0; k < reArrayLen; k++) {
								reEntry = json_object_array_get_idx(notifiedRe, k);
								if (strcmp(json_object_get_string(reEntry), rmac) == 0) {
									DBG_LOG("re (%s) have been notified", rmac);
									notifyRe = 0;
									break;
								}
							}
						}

						if (notifyRe) {
							DBG_LOG("notify %s to do self optimization", rmac);
							if ((e = ht_get(clientHashTable, mac, ip))) {
								if (!cm_sendNotification(e, NOTIFY_SELF_OPTIMIZATION, NULL))
									DBG_LOG("send notification to %s failed", e->clientIP);
							}
						}
					}
				}
				else
					DBG_LOG("%s dismatch condition, don't do self optimization", rmac);
			}
		}

		ret = 1;	/* finish notification for self optimization */
	}
	pthread_mutex_unlock(&cfgLock);

	json_object_put(reArray);

	return ret;
}  /* End of cm_sendSelfOptimization */

#if RTCONFIG_BHSWITCH_RE_SELFOPT
/*
========================================================================
Routine Description:
	Init backhaul switch rule for judging self optimization trigger.

Arguments:
	None

Return Value:
	0		- init backhaul switch rule list failed
	1		- init backhaul switch rule list success

Note:
========================================================================
*/
int cm_initBhSwitchRule()
{
	char bhSwitchRule[128], *pBhSwitchRule = NULL, *from, *to, *b;
	int count = 0;

	strlcpy(bhSwitchRule, nvram_safe_get("cfg_bhswitch_rulelist"), sizeof(bhSwitchRule));

	if (strlen(bhSwitchRule) == 0) {
		DBG_INFO("bh switch rule is null, set to default bh switch rule");
		strlcpy(bhSwitchRule, DEF_BH_SWITCH_RULE, sizeof(bhSwitchRule));
	}

	if (strlen(bhSwitchRule)) {
		pBhSwitchRule = &bhSwitchRule[0];
		bhSwitchRuleCount = get_char_count(bhSwitchRule, '<');
		DBG_INFO("the count of backhaul switch rule is %d", bhSwitchRuleCount);

		if (bhSwitchRuleCount > 0) {
			optBhSwitchRule = (struct _bh_switch_rule *) malloc(bhSwitchRuleCount *sizeof(struct _bh_switch_rule));

			while ((b = strsep(&pBhSwitchRule, "<")) != NULL) {
				if (strlen(b) == 0)
					continue;

				if ((vstrsep(b, ">", &from, &to) != 2))
					continue;

				if (strlen(from) == 0 || strlen(to) == 0) {
					DBG_ERR("from or to is null");
					continue;
				}

				optBhSwitchRule[count].from = atoi(from);
				optBhSwitchRule[count].to = atoi(to);

				DBG_INFO("rule %d: from (%d) to (%d)", count, optBhSwitchRule[count].from, optBhSwitchRule[count].to);

				if (count < bhSwitchRuleCount)
					count++;
			}
		}
	}
	else
	{
		DBG_ERR("no backhaul switch rule list");
		return 0;
	}

	return 1;
}  /* End of cm_initBhSwitchRule */

/*
========================================================================
Routine Description:
	Judge self optimization trigger when active path changed.

Arguments:
	lastActivePath		- last active path
	curActivePath		- current active path

Return Value:
	0		- don't trigger self optimization
	1		- trigger self optimization

Note:
========================================================================
*/
int cm_judgeSelfOptTrigger(int lastActivePath, int curActivePath)
{
	bh_index_mapping *pBhIndex = NULL;
	int lastBhIndex = 0, curBhIndex = 0, ret = 0, i = 0;

	DBG_INFO("lastActivePath (%d), curActivePath (%d)", lastActivePath, curActivePath);

	/* get real backhaul index based on last active path */
	if (lastActivePath > 0) {
		for (pBhIndex = &bh_index_list[0]; pBhIndex->index != 0; pBhIndex++) {
			if (pBhIndex->activePath &  lastActivePath) {
				lastBhIndex = pBhIndex->index;
				break;
			}
		}
	}
	else
	{
		lastBhIndex = BH_NONE;
	}

	/* get real backhaul index based on current active path */
	if (curActivePath > 0) {
		for (pBhIndex = &bh_index_list[0]; pBhIndex->index != 0; pBhIndex++) {
			if (pBhIndex->activePath &  curActivePath) {
				curBhIndex = pBhIndex->index;
				break;
			}
		}
	}
	else
	{
		curBhIndex = BH_NONE;
	}

	DBG_INFO("lastBhIndex (%d), curBhIndex (%d)", lastBhIndex, curBhIndex);

	/* judge for triggering sel opt based on backhual switch rule */
	for (i =0 ; i < bhSwitchRuleCount; i++) {
		if ((optBhSwitchRule[i].from & lastBhIndex) && (optBhSwitchRule[i].to & curBhIndex)) {
			DBG_INFO("match rule %d - from (%d) to (%d)", i, optBhSwitchRule[i].from, optBhSwitchRule[i].to);
			ret = 1;
			break;
		}
	}

	return ret;
}  /* End of cm_judgeSelfOptTrigger */
#endif /* RTCONFIG_BHSWITCH_RE_SELFOPT */

#ifdef RTCONFIG_PREFERAP_RE_SELFOPT
/*
========================================================================
Routine Description:
	Check RE whether trigger self optimization or not based on prefer ap.

Arguments:
	reMac		- re mac
	preferReMac		- prefer re mac
	preferAp5g		- prefer re 5g ap mac
	preferAp5g1		- prefer re 5g1 ap mac

Return Value:
	0		- don't trigger self optimization
	1		- trigger self optimization

Note:
========================================================================
*/
int cm_checkSelfOptByPreferAp(char *reMac, char *preferReMac, char *preferAp5g, char *preferAp5g1)
{
	int i = 0, ret = 1, reArrayLen = 0;
	unsigned char ea[6] = {0};
	char pap5g[18] = {0};
	json_object *reArray = NULL, *reEntry = NULL;

	if (reMac && strlen(reMac)) {
		ether_atoe(reMac, ea);

		/* re related info found */
		for (i = 1; i < p_client_tbl->count; i++) {
			if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
				snprintf(pap5g, sizeof(pap5g), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->pap5g[i][0], p_client_tbl->pap5g[i][1],
					p_client_tbl->pap5g[i][2], p_client_tbl->pap5g[i][3],
					p_client_tbl->pap5g[i][4], p_client_tbl->pap5g[i][5]);
				break;
			}
		}

		if (strcmp(pap5g, preferAp5g) == 0 || strcmp(pap5g, preferAp5g1) == 0) {
			DBG_LOG("re (%s) connects to the prefer re (%s) ap, pass it", reMac, preferReMac);
			ret = 0;
		}
		else
		{
			reArray = cm_recordReListArray(p_client_tbl, preferReMac);

			if (reArray && json_object_array_length(reArray) > 0) {
				reArrayLen = json_object_array_length(reArray);
				for (i = 0; i < reArrayLen; i++) {
					reEntry = json_object_array_get_idx(reArray, i);
					if (strcmp(json_object_get_string(reEntry), reMac) == 0) {
						ret = 0;
						DBG_LOG("prefer re (%s) is the sub-node of re (%s), pass it", preferReMac, reMac);
						break;
					}
				}
			}

			json_object_put(reArray);
		}
	}

	return ret;
}

/*
========================================================================
Routine Description:
	Send self optimization notification to RE based on prefer ap condition.

Arguments:
	decryptedMsg		- decrypted message

Return Value:
	reArray		- array for re have been notified self optimization

Note:
========================================================================
*/
json_object *cm_sendSelfOptByPreferAp(unsigned char *decryptedMsg)
{
	json_object *decryptedRoot = json_tokener_parse((char *)decryptedMsg);
	json_object *reMacObj = NULL, *privateCfgObj = NULL, *preferApObj = NULL;
	//json_object *wlc0TargetBssidObj = NULL;
	json_object *wlcTargetBssidObj = NULL, *wlc1TargetBssidObj = NULL, *wlc2TargetBssidObj = NULL;
	json_object *reArray = NULL, *reEntry = NULL;
	char privateCfgPath[64], rmac[18], ip[18], ap5g[18], ap5g1[18], mac[18];
	//char wlc0TargetBssid[64];
	char wlc1TargetBssid[64], wlc2TargetBssid[64], wlcTargetBssid[64];
	int i = 0, j = 0, k = 0, foundRe = 0, reArrayLen = 0, foundEntry = 0;
	unsigned char ea[6] = {0};
	hash_elem_t* e = NULL;

	pthread_mutex_lock(&cfgLock);
	json_object_object_get_ex(decryptedRoot, CFG_STR_MAC, &reMacObj);

	if (reMacObj && p_client_tbl->count > 2) {
		ether_atoe(json_object_get_string(reMacObj), ea);

		/* re related info found */
		for (i = 1; i < p_client_tbl->count; i++) {
			if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
				strlcpy(rmac, json_object_get_string(reMacObj), sizeof(rmac));

				snprintf(ap5g, sizeof(ap5g), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->ap5g[i][0], p_client_tbl->ap5g[i][1],
					p_client_tbl->ap5g[i][2], p_client_tbl->ap5g[i][3],
					p_client_tbl->ap5g[i][4], p_client_tbl->ap5g[i][5]);

				snprintf(ap5g1, sizeof(ap5g1), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->ap5g1[i][0], p_client_tbl->ap5g1[i][1],
					p_client_tbl->ap5g1[i][2], p_client_tbl->ap5g1[i][3],
					p_client_tbl->ap5g1[i][4], p_client_tbl->ap5g1[i][5]);

				foundRe = 1;
				DBG_INFO("rmac (%s), ap5g (%s), ap5g1 (%s)", rmac, ap5g, ap5g1);
				break;
			}
		}

		if (foundRe) {
			for (i = 1; i < p_client_tbl->count; i++) {
				snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
					p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
					p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
					p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

				/* same re mac, pass it */
				if (strcmp(rmac, mac) == 0) {
					DBG_LOG("same re mac (%s), pass it", rmac);
					continue;
				}

				snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
					p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
					p_client_tbl->ipAddr[i][3]);

				/* re offline, pass it */
				if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
					DBG_LOG("%s (%s) is offline", mac, ip);
					continue;
				}

				snprintf(privateCfgPath, sizeof(privateCfgPath), "/tmp/%s.json", mac);
				privateCfgObj = json_object_from_file(privateCfgPath);

				DBG_INFO("privateCfgPath (%s)", privateCfgPath);

				if (privateCfgObj ) {
					json_object_object_get_ex(privateCfgObj, CFG_STR_PREFER_AP, &preferApObj);
					if (preferApObj) {
						memset(wlcTargetBssid, 0, sizeof(wlcTargetBssid));
						json_object_object_get_ex(preferApObj, CFG_STR_WLC_TARGET_BSSID, &wlcTargetBssidObj);
						if (wlcTargetBssidObj)
							strlcpy(wlcTargetBssid, json_object_get_string(wlcTargetBssidObj), sizeof(wlcTargetBssid));

#if 0
						memset(wlc0TargetBssid, 0, sizeof(wlc0TargetBssid));
						json_object_object_get_ex(preferApObjb, CFG_STR_WLC0_TARGET_BSSID, &wlc0TargetBssidObj);
						if (wlc0TargetBssidObj)
							strlcpy(wlc0TargetBssid, json_object_get_string(wlc0TargetBssidObj), sizeof(wlc0TargetBssid));
#endif

						memset(wlc1TargetBssid, 0, sizeof(wlc1TargetBssid));
						json_object_object_get_ex(preferApObj, CFG_STR_WLC1_TARGET_BSSID, &wlc1TargetBssidObj);
						if (wlc1TargetBssidObj)
							strlcpy(wlc1TargetBssid, json_object_get_string(wlc1TargetBssidObj), sizeof(wlc1TargetBssid));

						memset(wlc2TargetBssid, 0, sizeof(wlc2TargetBssid));
						json_object_object_get_ex(preferApObj, CFG_STR_WLC2_TARGET_BSSID, &wlc2TargetBssidObj);
						if (wlc2TargetBssidObj)
							strlcpy(wlc2TargetBssid, json_object_get_string(wlc2TargetBssidObj), sizeof(wlc2TargetBssid));

						DBG_INFO("wlcTargetBssid (%s), wlc1TargetBssid (%s), wlc1TargetBssid (%s)",
							wlcTargetBssid, wlc1TargetBssid, wlc2TargetBssid);

						if (strlen(wlcTargetBssid) || strlen(wlc1TargetBssid) || strlen(wlc2TargetBssid)) {
							if (strstr(wlcTargetBssid, rmac) ||
								strstr(wlc1TargetBssid, ap5g) || strstr(wlc1TargetBssid, ap5g1) ||
								strstr(wlc2TargetBssid, ap5g) || strstr(wlc2TargetBssid, ap5g1))
							{
								if (cm_checkSelfOptByPreferAp(mac, rmac, ap5g, ap5g1)) {
									if (!reArray)
										reArray = json_object_new_array();

									if (reArray)
										json_object_array_add(reArray, json_object_new_string(mac));
								}
							}
						}
					}

					json_object_put(privateCfgObj);
				}
			}

			if (reArray && json_object_array_length(reArray) > 0) {
				for (i = p_client_tbl->maxLevel; i >= 0; i--) {
					for (j = 1; j < p_client_tbl->count; j++) {
						/* different level, pass it */
						if (p_client_tbl->level[j] != i)
							continue;

						memset(rmac, 0, sizeof(rmac));
						snprintf(rmac, sizeof(rmac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->realMacAddr[j][0], p_client_tbl->realMacAddr[j][1],
							p_client_tbl->realMacAddr[j][2], p_client_tbl->realMacAddr[j][3],
							p_client_tbl->realMacAddr[j][4], p_client_tbl->realMacAddr[j][5]);

						memset(mac, 0, sizeof(mac));
						snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
							p_client_tbl->macAddr[j][0], p_client_tbl->macAddr[j][1],
							p_client_tbl->macAddr[j][2], p_client_tbl->macAddr[j][3],
							p_client_tbl->macAddr[j][4], p_client_tbl->macAddr[j][5]);

						memset(ip, 0, sizeof(ip));
						snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[j][0],
							p_client_tbl->ipAddr[j][1], p_client_tbl->ipAddr[j][2],
							p_client_tbl->ipAddr[j][3]);

						/* re offline, pass it */
						if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[j])) {
							DBG_LOG("%s (%s) is offline", rmac, ip);
							continue;
						}

						/* based on reArray, check RE do self optimization or not */
						foundEntry = 0;
						reArrayLen = json_object_array_length(reArray);
						for (k = 0; k < reArrayLen; k++) {
							reEntry = json_object_array_get_idx(reArray, k);
							if (strcmp(json_object_get_string(reEntry), rmac) == 0) {
								foundEntry = 1;
								break;
							}
						}

						if (foundEntry) {
							DBG_LOG("notify re (%s) to do self optimization", rmac);
							if ((e = ht_get(clientHashTable, mac, ip))) {
								if (!cm_sendNotification(e, NOTIFY_SELF_OPTIMIZATION, NULL))
									DBG_LOG("send notification to re (%s) failed", e->clientIP);
							}
							else
								DBG_LOG("can't find the re (%s %s) from client hash table", rmac, ip);
						}
					}
				}
			}
		}
	}

	json_object_put(decryptedRoot);

	pthread_mutex_unlock(&cfgLock);

	return reArray;
}  /* End of cm_sendSelfOptByPreferAp */
#endif /* RTCONFIG_PREFERAP_RE_SELFOPT */
#endif /* RTCONFIG_BHCOST_OPT */

#ifdef STA_BIND_AP
/*
========================================================================
Routine Description:
	Update sta binding ap.

Arguments:
	delAction		- delete action for sta binding ap
	mac		- mac for RE

Return Value:
	0		- no update
	1		- update

Note:
========================================================================
*/
int cm_updateStaBindingAp(int delAction, char *mac)
{
	json_object *reListObj = NULL, *reObj = NULL, *bindingListObj = NULL;
	char *nv, *nvp, *b, *rMac, *enable, *staList;
	char reMac[18], reEntry[1024], bindingList[8192] = {0};
	int i = 0, online = 0, reUpdate = 0, reEnable = 0;
	int sta_binding_len = -1;

	if (!(reListObj = json_object_new_object())) {
		DBG_ERR("reListObj is NULL");
		goto err;
	}

	if (!(bindingListObj = json_object_new_object())) {
		DBG_ERR("bindingListObj is NULL");
		goto err;
	}

	pthread_mutex_lock(&cfgLock);

	for (i = 0; i < p_client_tbl->count; i++) {
		memset(reMac, 0, sizeof(reMac));
		snprintf(reMac, sizeof(reMac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
			p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
			p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		/* record online/offline re */
		online = (i != 0 ? cm_isSlaveOnline(p_client_tbl->reportStartTime[i]) : 1);
		DBG_INFO("%s is %s", reMac, online ? "online": "offline");
		json_object_object_add(reListObj, reMac, json_object_new_int(online));
	}

	pthread_mutex_unlock(&cfgLock);

	/* check any RE update or not */
	nv = nvp = strdup(nvram_safe_get("sta_binding_list"));
	if (nv) {
		sta_binding_len = strlen(nv);

		while ((b = strsep(&nvp, "<")) != NULL) {
			if (strlen(b) ==0)
				continue;

			if ((vstrsep(b, ">", &rMac, &enable, &staList) != 3))
				continue;

			if (delAction && strcmp(rMac, mac) == 0) {
				reUpdate = 1;
				continue;
			}

			json_object_object_get_ex(reListObj, rMac, &reObj);

			if (reObj && (atoi(enable) != json_object_get_int(reObj))) {
				reEnable = json_object_get_int(reObj);
				reUpdate = 1;
			}
			else if (!reObj && (atoi(enable) == 1))
			{
				reEnable = 0;
				reUpdate = 1;
			}
			else
				reEnable = atoi(enable);

			memset(reEntry, 0, sizeof(reEntry));
			snprintf(reEntry, sizeof(reEntry), "<%s>%d>%s",
						rMac, reEnable, staList);

			strlcat(bindingList, reEntry, sizeof(bindingList));
		}
		free(nv);
	}

	if (reUpdate) {
		nvram_set("sta_binding_list", bindingList);
		json_object_object_add(bindingListObj, CFG_STA_BINDING_LIST, json_object_new_string(bindingList));
		cm_sendNotificationByType(NOTIFY_UPDATE_STA_BINDING, bindingListObj);
		notify_rc(UPDATE_STA_BINDING);
	}
	else if (sta_binding_len == 0) {
		reUpdate = 1;
	}

err:

	json_object_put(reListObj);
	json_object_put(bindingListObj);

	return reUpdate;
}  /* End of cm_updateStaBindingAp */
#endif /* STA_BIND_AP */

static char *cm_getClientMac(char *host, char *macAddr, int macAddrLen)
{
	int s;
	struct arpreq req;
	//struct hostent *hp;
	struct sockaddr_in *sin;
	int retry = 0;

	bzero((caddr_t)&req, sizeof(req));

	sin = (struct sockaddr_in *)&req.arp_pa;
	sin->sin_family = AF_INET; /* Address Family: Internet */
	sin->sin_addr.s_addr = inet_addr(host);

retry:

	if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		DBG_ERR("socket() failed");
		return NULL;
        } /* Socket is opened.*/

	snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", LAN_IFNAME);

	if(ioctl(s, SIOCGARP, (caddr_t)&req) <0) {
		if(errno == ENXIO){
			DBG_ERR("%s (%s) -- no entry", host, inet_ntoa(sin->sin_addr));
			return macAddr;
        	} else {
			DBG_ERR("SIOCGARP (%d)", retry);
			retry++;
			if (retry != 3) {
				close(s);
				goto retry;
			}
			return macAddr;
        	}
	}
	close(s); /* Close the socket, we don't need it anymore. */

	if(req.arp_flags & ATF_COM) {
		snprintf(macAddr, macAddrLen, "%02X:%02X:%02X:%02X:%02X:%02X",
					(unsigned char)req.arp_ha.sa_data[0], (unsigned char)req.arp_ha.sa_data[1],
					(unsigned char)req.arp_ha.sa_data[2], (unsigned char)req.arp_ha.sa_data[3],
					(unsigned char)req.arp_ha.sa_data[4], (unsigned char)req.arp_ha.sa_data[5]);
		DBG_INFO("%s (%s) at %s", host, inet_ntoa(sin->sin_addr), macAddr);
	} else {
		DBG_INFO("%s (%s) at incomplete", host, inet_ntoa(sin->sin_addr));
	}

	return macAddr;
}

static int cm_delClientArp(char *clientIp)
{
	return delClientArp(clientIp);
}

/*
========================================================================
Routine Description:
	Handle received TCP packets.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
void cm_rcvTcpHandler(CM_CTRL *pCtrlBK)
{
	struct sockaddr_in cliSockAddr;
	int clientSock = 0, sockAddrLen = sizeof(cliSockAddr);
	char clientIP[32] = {0}, clientMac[32] = {0};
        pthread_t sockThread;
	//socketInfo *sockArgs = malloc(sizeof *sockArgs);
	int *sockArgs = malloc(sizeof(int));

	DBG_INFO("enter");

	memset(&cliSockAddr, 0, sizeof(struct sockaddr_in));
	memset(clientIP, 0, sizeof(clientIP));
	memset(clientMac, 0, sizeof(clientMac));

	clientSock = accept(pCtrlBK->socketTCPSend, (struct sockaddr *)&cliSockAddr, (socklen_t *)&sockAddrLen);

	if (clientSock < 0) {
		DBG_ERR("Failed to socket accept() !!!");
		free(sockArgs);
		return;
	}

	//prepare related data for thread to handle packet
#if 0
	snprintf(clientIP, sizeof(clientIP), "%s", (char *)inet_ntoa(cliSockAddr.sin_addr));
	snprintf(clientMac, sizeof(clientMac), "%s", cm_getClientMac(clientIP));
	DBG_INFO("client_sock(%d) IP(%s) port(%d) mac(%s)", clientSock, clientIP, ntohs(cliSockAddr.sin_port), clientMac);
	sockArgs->socketDesc = &clientSock;
        sockArgs->clientIP = (char *)&clientIP;
	sockArgs->clientMac = (char *)&clientMac;
#endif
	*sockArgs = clientSock;

	if (pthread_create(&sockThread, attrp, cm_tcpPacketHandler, sockArgs) != 0) {
		DBG_ERR("could not create thread !!!");
		free(sockArgs);
	}

	DBG_INFO("leave");
} /* End of cm_rcvTcpHandler */

/*
========================================================================
Routine Description:
	Handle received CM packets.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
void cm_rcvHandler(CM_CTRL *pCtrlBK)
{
	fd_set fdSet;
	int sockMax;

	/* sanity check */
	if (pCtrlBK->flagIsRunning)
		return;

	/* init */
	pCtrlBK->flagIsRunning = 1;
	sockMax = pCtrlBK->socketTCPSend;

	if (pCtrlBK->socketUdpSendRcv > pCtrlBK->socketTCPSend)
		sockMax = pCtrlBK->socketUdpSendRcv;

	if (pCtrlBK->socketIpcSendRcv > sockMax)
		sockMax = pCtrlBK->socketIpcSendRcv;

	/* waiting for any packet */
	while(1)
	{
		/* must re- FD_SET before each select() */
		FD_ZERO(&fdSet);

		FD_SET(pCtrlBK->socketTCPSend, &fdSet);
		FD_SET(pCtrlBK->socketUdpSendRcv, &fdSet);
		FD_SET(pCtrlBK->socketIpcSendRcv, &fdSet);

		/* must use sockMax+1, not sockMax */
		if (select(sockMax+1, &fdSet, NULL, NULL, NULL) < 0)
			break;

		/* handle packets from TCP layer */
		if (FD_ISSET(pCtrlBK->socketTCPSend, &fdSet))
			cm_rcvTcpHandler(pCtrlBK);

		/* handle packets from UDP layer */
		if (FD_ISSET(pCtrlBK->socketUdpSendRcv, &fdSet))
			cm_rcvUdpHandler();

		/* handle packets from IPC */
		if (FD_ISSET(pCtrlBK->socketIpcSendRcv, &fdSet))
			cm_rcvIpcHandler(pCtrlBK->socketIpcSendRcv);
	};

	pCtrlBK->flagIsRunning = 0;
} /* End of cm_rcvHandler */

/*
========================================================================
Routine Description:
	Start CM realted threads.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
static void cm_startThread()
{
	pthread_t timerThread;
#ifdef CONN_DIAG
	pthread_t connDiagThread;
#endif

	DBG_INFO("startThread");

	/* start thread for timer */
	if (pthread_create(&timerThread, attrp, cm_eventTimer, NULL) != 0)
		DBG_ERR("could not create thread for timerThread");

#ifdef CONN_DIAG
	/* start thread for timer */
	if (pthread_create(&connDiagThread, attrp, cm_connDiagPktListHandler, NULL) != 0)
		DBG_ERR("could not create thread for connDiagThread");
#endif
} /* End of cm_startThread */

/*
========================================================================
Routine Description:
	Init pthread mutex.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
static int cm_initThreadMutex()
{
	if (pthread_mutex_init(&threadLock, NULL) != 0) {
		DBG_ERR("mutex init failed for threadLock");
		return 0;
	}

	if (pthread_mutex_init(&cfgLock, NULL) != 0) {
		DBG_ERR("mutex init failed for cfgLock");
		return 0;
	}

	if (pthread_mutex_init(&weventLock, NULL) != 0) {
		DBG_ERR("mutex init failed for weventLock");
		return 0;
	}

	if (pthread_mutex_init(&allWeventLock, NULL) != 0) {
		DBG_ERR("mutex init failed for allWeventLock");
		return 0;
	}

	if (pthread_mutex_init(&wiredClientListLock, NULL) != 0) {
		DBG_ERR("mutex init failed for wiredClientListLock");
		return 0;
	}

	if (pthread_mutex_init(&clientListLock, NULL) != 0) {
		DBG_ERR("mutex init failed for clientListLock");
		return 0;
	}

#ifdef ONBOARDING
	if (pthread_mutex_init(&onboardingLock, NULL) != 0) {
		DBG_ERR("mutex init failed for onboardingLock");
		return 0;
	}
#endif

	if (pthread_mutex_init(&radarDetLock, NULL) != 0) {
		DBG_ERR("mutex init failed for radarDetLock");
		return 0;
	}

#ifdef ROAMING_INFO
	if (pthread_mutex_init(&roamingInfoLock, NULL) != 0) {
		DBG_ERR("mutex init failed for roamingInfoLock");
		return 0;
	}
#endif

#ifdef LEGACY_ROAMING
	if (pthread_mutex_init(&roamingLock, NULL) != 0) {
		DBG_ERR("mutex init failed for roamingLock");
		return 0;
	}
#endif

	if (pthread_mutex_init(&reListLock, NULL) != 0) {
		DBG_ERR("mutex init failed for reListLock");
		return 0;
	}

	if (pthread_mutex_init(&chanspecLock, NULL) != 0) {
		DBG_ERR("mutex init failed for chanspecLock");
		return 0;
	}

#ifdef DUAL_BAND_DETECTION
	if (pthread_mutex_init(&dualBandLock, NULL) != 0) {
		DBG_ERR("mutex init failed for dualBandLock");
		return 0;
	}
#endif

#ifdef PRELINK
	if (pthread_mutex_init(&prelinkLock, NULL) != 0) {
		DBG_ERR("mutex init failed for prelinkLock");
		return 0;
	}
#endif

#ifdef RTCONFIG_NBR_RPT
	if (pthread_mutex_init(&nbrRptLock, NULL) != 0) {
		DBG_ERR("mutex init failed for nbrRptLock");
		return 0;
	}
#endif

#ifdef CONN_DIAG
	if (pthread_mutex_init(&connDiagLock, NULL) != 0) {
		DBG_ERR("mutex init failed for connDiagtLock");
		return 0;
	}
#endif

	return 1;
} /* End of cm_initThreadMutex */

/*
========================================================================
Routine Description:
	Start CM daemon.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
static void cm_start(CM_CTRL *pCtrlBK)
{
	/* init */
	pCtrlBK->flagIsTerminated = 0;

	/* update sta list */
	cm_reportStalistEvent(NULL);

	/* update client list */
	cm_reportClientlistEvent(NULL);

	/* start related thread for cm */
	cm_startThread();

#ifdef STA_BIND_AP
#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
	cm_updateStaBindingAp(0, NULL);
	}
#endif /* STA_BIND_AP */

#ifdef ONBOARDING
#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
	/* unset onboarding result */
	nvram_unset("cfg_obre");
	nvram_unset("cfg_newre");
	nvram_unset("cfg_obresult");
	nvram_unset("cfg_obmodel");

	/* update onboarding vsie */
	cm_updateOnboardingVsie(OB_TYPE_OFF);
	} /* !wifison_ready */
#endif

	/* waiting for CM packets */
	while(!pCtrlBK->flagIsTerminated) {
		/* CPU suspend will be done in cm_rcvHandler() */
		cm_rcvHandler(pCtrlBK);
	} /* End of while */
} /* End of cm_start */

/*
========================================================================
Routine Description:
	Generate group key.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	1		- get successfully
	0		- get fail

Note:
========================================================================
*/
void cm_generateGroupKey(CM_CTRL *pCtrlBK)
{
	unsigned char *randKey1 = NULL;	// random key 1 for generating group key
	unsigned char *randKey2 = NULL;	// random key 2 for generating group key
	unsigned char *randKey3 = NULL;	// random key 3 for generating group key
	size_t randKey1Len = 0;		// the length of random key 1
	size_t randKey2Len = 0;		// the length of random key 2
	size_t randKey3Len = 0;		// the length of random key 3

	DBG_INFO("generate group key");
	/* generate three random keys */
	randKey1 = gen_rand(&randKey1Len);
	randKey2 = gen_rand(&randKey2Len);
	randKey3 = gen_rand(&randKey3Len);

	/* free group key first when it expired */
	if (pCtrlBK->groupKey) free(pCtrlBK->groupKey);

	/* generate group key */
	pCtrlBK->groupKey = gen_session_key(randKey1, randKey1Len, randKey2, randKey2Len, randKey3, randKey3Len, &pCtrlBK->groupKeyLen);
	pCtrlBK->groupKeyStartTime = uptime();
	pCtrlBK->groupKeyReady = 1;
	pCtrlBK->groupKey1StartTime = uptime() - groupKeyExpireTime;

	/* free three random keys */
	if (randKey1) free(randKey1);
	if (randKey2) free(randKey2);
	if (randKey3) free(randKey3);
} /* End of cm_generateGroupKey */

/*
========================================================================
Routine Description:
	Get public & private & group key.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	1		- get successfully
	0		- get fail

Note:
========================================================================
*/
static int cm_initKeyInfo(CM_CTRL *pCtrlBK)
{
	FILE *pFile = NULL;
	int i = 0;
	unsigned long long sn;
	char t[32];

	if (strlen(public_pem_file) <= 0)
		snprintf(public_pem_file, sizeof(public_pem_file), "%s", DEFAULT_PUBLIC_PEM_FILE);

	if (strlen(private_pem_file) <= 0)
		snprintf(private_pem_file, sizeof(private_pem_file), "%s", DEFAULT_PRIVATE_PEM_FILE);

	/* generate SSL certification if needed */
	if (!fileExists(public_pem_file) || !fileExists(private_pem_file)) {
		DBG_INFO("generating SSL certificate");
		f_read("/dev/urandom", &sn, sizeof(sn));
		sprintf(t, "%llu", sn & 0x7FFFFFFFFFFFFFFFULL);
		eval("gencfgcert.sh", t);
	}

	/* waiting for public and private key generation via openssl */
	for (i = 0; i < KEY_CHECK_TIMES; i++) {
		if (fileExists(public_pem_file)&&
			getFileSize(public_pem_file) > 0 &&
			fileExists(private_pem_file) &&
			getFileSize(private_pem_file) > 0)
			break;
		DBG_INFO("wait public & private key are generated(%d)", i);
		sleep(5);
	}
	/* no public & private key are generated */
	if (i == KEY_CHECK_TIMES) {
		DBG_ERR("no public & private key are generated, can't start it");
		goto err;
	}

	/* init public key */
	DBG_INFO("open public PEM file : %s ...", public_pem_file);

	if ((pCtrlBK->publicKeyLen = getFileSize(public_pem_file)) <= 0) {
		DBG_ERR("Failed, check public PEM file size failed, size : %zu", pCtrlBK->publicKeyLen);
		goto err;
	}

	if ((pCtrlBK->publicKey = (unsigned char *)malloc(pCtrlBK->publicKeyLen+1)) == NULL) {
		DBG_ERR("Failed, Memory allocate failed ...");
		goto err;
	}

	if ((pFile = fopen(public_pem_file, "rb")) == NULL) {
		DBG_ERR("open file failed");
		goto err;
	}

	fseek(pFile, 0L, SEEK_SET);
	memset(pCtrlBK->publicKey, 0, pCtrlBK->publicKeyLen+1);
	if (fread(pCtrlBK->publicKey, 1, pCtrlBK->publicKeyLen, pFile) != pCtrlBK->publicKeyLen) {
		DBG_ERR("Failed");
		goto err;
	}
	fclose(pFile);
	pFile = NULL;
	pCtrlBK->publicKeyLen+=1;
	DBG_INFO("Done");

	/* init private key */
	DBG_INFO("open private PEM file : %s ...",private_pem_file);

	if ((pCtrlBK->privateKeyLen = getFileSize(private_pem_file)) <= 0) {
		DBG_ERR("Failed, check private PEM file size failed, size : %zu", pCtrlBK->privateKeyLen);
		goto err;
	}

	if ((pCtrlBK->privateKey = (unsigned char *)malloc(pCtrlBK->privateKeyLen+1)) == NULL) {
		DBG_ERR("Failed, Memory allocate failed ...");
		goto err;
	}

	if ((pFile = fopen(private_pem_file, "rb")) == NULL) {
		DBG_ERR("Failed");
		goto err;
	}

	fseek(pFile, 0L, SEEK_SET);
	memset(pCtrlBK->privateKey, 0, pCtrlBK->privateKeyLen+1);
	if (fread(pCtrlBK->privateKey, 1, pCtrlBK->privateKeyLen, pFile) != pCtrlBK->privateKeyLen) {
		DBG_ERR("Failed");
		goto err;
	}
	fclose(pFile);
	pFile = NULL;
	pCtrlBK->privateKeyLen+=1;
	DBG_INFO("Done");

	/* init group key */
	cm_generateGroupKey(pCtrlBK);

	return 1;
err:
	if (!IsNULL_PTR(pFile)) fclose(pFile);
	if (!IsNULL_PTR(pCtrlBK->publicKey)) MFREE(pCtrlBK->publicKey);
	if (!IsNULL_PTR(pCtrlBK->privateKey)) MFREE(pCtrlBK->privateKey);
	if (!IsNULL_PTR(pCtrlBK->groupKey)) MFREE(pCtrlBK->groupKey);

	return 0;
} /* End of cm_initKeyInfo */

/*
========================================================================
Routine Description:
	Init group id.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
int cm_initGroupId()
{
	if (nvram_get("cfg_group") && strlen(nvram_safe_get("cfg_group")) == 0) {
		/* no gorup id */
		unsigned char outmd[CFGSYNC_GROUPID_LEN/2] = {0};
		char str[CFGSYNC_GROUPID_LEN+1] = {0};
		char data[64];
		MD5_CTX ctx;

		snprintf(data, sizeof(data), "%s_%d", get_lan_hwaddr(), (int)time(NULL));
		DBG_INFO("data (%s)", data);
		if (!MD5_Init(&ctx)) {
			DBG_ERR("md5 init failed");
			return 0;
		}

		if (!MD5_Update(&ctx, data, strlen(data))) {
			DBG_ERR("md5 update failed");
			return 0;
		}

		if (!MD5_Final(outmd, &ctx)) {
			DBG_ERR("md5 final failed");
			return 0;
		}

		if (hex2str(&outmd[0], &str[0], sizeof(outmd)) && strlen(str)) {
			DBG_INFO("group id(%s)", str);
			nvram_set("cfg_group", str);
			nvram_commit();
#ifdef RTCONFIG_WIFI_SON
			if(nvram_match("wifison_ready", "1"))
				eval("hive_wsplcd");
#endif
#ifdef RTCONFIG_QCA_PLC2
			//notify_rc_after_wait("restart_plc");
			eval("restart_plc");
#endif	/* RTCONFIG_QCA_PLC2 */
		}
		else
			return 0;
	}

	memset(groupID, 0, sizeof(groupID));
	snprintf(groupID, sizeof(groupID), "%s", nvram_safe_get("cfg_group"));

	return 1;
} /* End of cm_initGroupId */

/*
========================================================================
Routine Description:
	Get interface information, such as IP, AddrNetmask, broadcast addr, etc.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
static int cm_getIfInfo(CM_CTRL *pCtrlBK)
{
	int sockIf;
	struct ifreq reqIf;
	char *pMac = NULL;

	/* init */
	snprintf(reqIf.ifr_name, IFNAMSIZ, "%s", LAN_IFNAME);

	/* open a UDP socket */
	if ((sockIf = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		DBG_ERR("open socket failed!");
		return 0;
	}

	/* get own addr */
	if (ioctl(sockIf, SIOCGIFADDR, (long) &reqIf) < 0) {
		DBG_ERR("get own address of %s failed!", reqIf.ifr_name);
		goto err;
	}

	memmove(&pCtrlBK->ownAddr,
			&((struct sockaddr_in *) &reqIf.ifr_addr)->sin_addr,
			sizeof(pCtrlBK->ownAddr));
	DBG_INFO("own address (%d.%d.%d.%d)",
			(htonl(pCtrlBK->ownAddr.s_addr) >> 24) & 0xFF,
			(htonl(pCtrlBK->ownAddr.s_addr) >> 16) & 0xFF,
			(htonl(pCtrlBK->ownAddr.s_addr) >> 8) & 0xFF,
			(htonl(pCtrlBK->ownAddr.s_addr) & 0xFF));

	/* get broadcast address */
	if (ioctl(sockIf, SIOCGIFBRDADDR, (long) &reqIf) < 0) {
		DBG_ERR("get broadcast address failed!");
		goto err;
	}

	memmove(&pCtrlBK->broadcastAddr,
			&((struct sockaddr_in *) &reqIf.ifr_addr)->sin_addr,
			sizeof(pCtrlBK->broadcastAddr));
	DBG_INFO("broadcast address (%d.%d.%d.%d)",
			(htonl(pCtrlBK->broadcastAddr.s_addr) >> 24) & 0xFF,
			(htonl(pCtrlBK->broadcastAddr.s_addr) >> 16) & 0xFF,
			(htonl(pCtrlBK->broadcastAddr.s_addr) >> 8) & 0xFF,
			(htonl(pCtrlBK->broadcastAddr.s_addr) & 0xFF));

	close(sockIf);

        /* get bridge mac */
	pMac = get_hwaddr(LAN_IFNAME);
	if (pMac) {
		memset(pCtrlBK->brIfMac, 0, sizeof(pCtrlBK->brIfMac));
		snprintf(pCtrlBK->brIfMac, sizeof(pCtrlBK->brIfMac), "%s", pMac);
		DBG_INFO("br0 mac(%s)", pCtrlBK->brIfMac);
		free(pMac);
	}

	return 1;

err:
	close(sockIf);
	return 0;
} /* End of cm_getIfInfo */

/*
========================================================================
Routine Description:
	Request network topology.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_requestTopology(void){
	//TODO
	return 0;
}
/*
========================================================================
Routine Description:
	Report dut's connection status.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_reportConnStatus(void){
	//TODO
	return 0;
}

void cm_setStatePending(){
	//TODO
}

/*
========================================================================
Routine Description:
	Send notification to slave to update network cost.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_updateTopology(void)
{
	int i = 0;
	char mac[18] = {0};
	char ip[18] = {0};
	hashtable_t* hasht = clientHashTable;

	pthread_mutex_lock(&cfgLock);
	for (i = 1; i < p_client_tbl->count; i++) {
		hash_elem_it it = HT_ITERATOR(hasht);
		hash_elem_t* e = ht_iterate_elem(&it);

		memset(mac, 0, sizeof(mac));
		memset(ip, 0, sizeof(ip));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
			p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
			p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
			p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
			p_client_tbl->ipAddr[i][3]);

		if (!cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
			DBG_INFO("%s (%s) is offline", mac, ip);
			continue;
		}

		/* send notification to slave to request cost*/
		while(e != NULL) {
			if ((strcmp(mac, e->key) == 0 && strcmp(ip, e->clientIP) == 0) ||
				strcmp(ip, e->clientIP) == 0)
			{
				DBG_INFO("client ip(%s), client mac(%s), key time(%d)",
					e->clientIP, e->key,  (int) (uptime() - e->sessionKeyStartTime));
				if (cm_checkSessionKeyExpire(e))
					cm_sendNotification(e, NOTIFY_REKEY, NULL);	// ask the client to rekey
				else
					cm_sendNotification(e, NOTIFY_REQUESTTOPOLOGY, NULL);
			}
			e = ht_iterate_elem(&it);
		}
	}
	pthread_mutex_unlock(&cfgLock);
} /* End of cm_updateTopology */

/*
========================================================================
Routine Description:
	Config changed from EID_RC_CONFIG_CHANGED

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_configChanged(unsigned char *data)
{
	json_object *root = NULL;
	json_object *rcObj = NULL;
	json_object *cfgObj = NULL;
	char cfg_ver[9];

	if ((root = json_tokener_parse((char *)data)) == NULL)
		goto cm_configChanged_Fail;

	json_object_object_get_ex(root, RC_PREFIX, &rcObj);
	if (rcObj == NULL)
		goto cm_configChanged_Fail;

	json_object_object_get_ex(rcObj, CFG_STR_CONFIG, &cfgObj);
	if (cfgObj == NULL)
		goto cm_configChanged_Fail;

	json_object_to_file(CFG_JSON_FILE, cfgObj);
	json_object_put(root);

	/* change cfg_ver when setting changed */
    memset(cfg_ver, 0, sizeof(cfg_ver));
   	srand(time(NULL));
    snprintf(cfg_ver, sizeof(cfg_ver), "%d%d", rand(), rand());
   	nvram_set("cfg_ver", cfg_ver);
   	nvram_commit();

   	// trigger cm_usr2Handle()
   	cm_usr2Handle(0);
	return;

cm_configChanged_Fail:
	if (root != NULL)
		json_object_put(root);
	return;

} /* End of cm_ConfigChanged */

#ifdef RTCONFIG_BHCOST_OPT
/*
========================================================================
Routine Description:
        Send event w/ self optimize to the client.

Arguments:
        *mac            - slave's mac

Return Value:
        None

Note:
========================================================================
*/
void cm_selfOptimize(char *mac)
{
	int i = 0;
	unsigned char ea[6] = {0};
	char ipStr[18] = {0};
	char macStr[18] = {0};
	int found = 0;
	hash_elem_t* e = NULL;

	ether_atoe(mac, ea);

	pthread_mutex_lock(&cfgLock);

	/* search slave based on mac */
	for(i = 0; i < p_client_tbl->count; i++) {
                if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			DBG_INFO("Find the same MAC in the table");
			found = 1;
			snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
				p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
				p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

			snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
				p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
				p_client_tbl->ipAddr[i][3]);
			break;
		}
	}

	pthread_mutex_unlock(&cfgLock);

	if (found) {
		if ((e = ht_get(clientHashTable, macStr, ipStr))) {
			if (!cm_sendNotification(e, NOTIFY_SELF_OPTIMIZATION, NULL))
				DBG_ERR("send notification (%d) to %s failed", NOTIFY_SELF_OPTIMIZATION, e->clientIP);
		}
	}
} /* End of cm_selfOptimize */
#endif /* RTCONFIG_BHCOST_OPT */

/*
========================================================================
Routine Description:
	Feedback the issue.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_feedback()
{
	json_object *data = json_object_new_object();

	if (data) {
		json_object_object_add(data, "fb_country", json_object_new_string(nvram_safe_get("fb_country")));
		json_object_object_add(data, "fb_email", json_object_new_string(nvram_safe_get("fb_email")));
		json_object_object_add(data, "fb_serviceno", json_object_new_string(nvram_safe_get("fb_email")));
		json_object_object_add(data, "fb_ptype", json_object_new_string(nvram_safe_get("fb_ptype")));
		json_object_object_add(data, "fb_pdesc", json_object_new_string(nvram_safe_get("fb_pdesc")));
		json_object_object_add(data, "fb_comment", json_object_new_string(nvram_safe_get("fb_comment")));
		json_object_object_add(data, "fb_attach_syslog", json_object_new_string(nvram_safe_get("fb_attach_syslog")));
		json_object_object_add(data, "fb_attach_cfgfile", json_object_new_string(nvram_safe_get("fb_attach_cfgfile")));
		json_object_object_add(data, "fb_attach_modemlog", json_object_new_string(nvram_safe_get("fb_attach_modemlog")));

		cm_sendNotificationByType(NOTIFY_FEEDBACK, data);
	}

	json_object_put(data);
} /* End of cm_feedback */

/*
========================================================================
Routine Description:
	Check RE whether exist in client list or not.

Arguments:
	clientTbl		- client table
	reMac		- RE's mac

Return Value:
	0		- not found
	1		- found

========================================================================
*/
int cm_reExistInClientList(char *reMac)
{
	char mac[18] = {0};
	int i = 0, found = 0;

	for (i = 1; i < p_client_tbl->count; i++) {
		memset(mac, 0, sizeof(mac));
		snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->realMacAddr[i][0], p_client_tbl->realMacAddr[i][1],
				p_client_tbl->realMacAddr[i][2], p_client_tbl->realMacAddr[i][3],
				p_client_tbl->realMacAddr[i][4], p_client_tbl->realMacAddr[i][5]);

		if (strcmp(reMac, mac) == 0 && cm_isSlaveOnline(p_client_tbl->reportStartTime[i]) == 1) {
			found = 1;
			break;
		}
	}

	return found;
} /* End of cm_reExistInClientList */

/*
========================================================================
Routine Description:
	Clse socket.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	None

Note:
========================================================================
*/
static void cm_closeSocket(CM_CTRL *pCtrlBK)
{
	if (pCtrlBK->socketTCPSend >= 0)
		close(pCtrlBK->socketTCPSend);

	if (pCtrlBK->socketUdpSendRcv >= 0)
		close(pCtrlBK->socketUdpSendRcv);

	if (pCtrlBK->socketIpcSendRcv >= 0)
		close(pCtrlBK->socketIpcSendRcv);
} /* End of cm_closeSocket */

/*
========================================================================
Routine Description:
	Open socket.

Arguments:
	*pCtrlBK	- CM control blcok

Return Value:
	1		- open successfully
	0		- open fail

Note:
========================================================================
*/
static int cm_openSocket(CM_CTRL *pCtrlBK)
{
	struct sockaddr_in sock_addr_tcp;
	struct sockaddr_in sock_addr_udp;
	struct sockaddr_un sock_addr_ipc;
	int broadcast = 1;
	int reused = 1;
	char *udpBindingIf = nvram_safe_get("lan_ifname");

	/* init */
	pCtrlBK->socketTCPSend = -1;
	pCtrlBK->socketUdpSendRcv = -1;
	pCtrlBK->socketIpcSendRcv = -1;

	/* Open TCP socket for accepting connection from other AP */
	pCtrlBK->socketTCPSend = socket(AF_INET, SOCK_STREAM, 0);

	if (pCtrlBK->socketTCPSend < 0) {
		DBG_ERR("Failed to TCP socket create!");
		goto err;
	}

	/* set socket reusable */
	if (setsockopt(pCtrlBK->socketTCPSend, SOL_SOCKET, SO_REUSEADDR,
			&reused, sizeof(reused)) < 0)
	{
		DBG_ERR("Failed to setsockopt(SO_REUSEADDR)");
		goto err;
	}

	/* bind the Rcv TCP socket */
	memset(&sock_addr_tcp, 0, sizeof(sock_addr_tcp));
	sock_addr_tcp.sin_family = AF_INET;
	sock_addr_tcp.sin_addr.s_addr = INADDR_ANY;
	sock_addr_tcp.sin_port = htons(port);

	if (bind(pCtrlBK->socketTCPSend, (struct sockaddr*)&sock_addr_tcp, sizeof(struct sockaddr_in)) < 0) {
		DBG_ERR("Failed to bind()!");
		goto err;
	}

	listen(pCtrlBK->socketTCPSend, 10); /* max 10 TCP connections simultaneously */


	/* open a Send UDP socket */
	if ((pCtrlBK->socketUdpSendRcv = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		DBG_ERR("Failed to UDP socket create!");
		goto err;
	}

	/* bind the Send/Rcv UDP socket */
	memset(&sock_addr_udp, 0, sizeof(sock_addr_udp));
	sock_addr_udp.sin_family = AF_INET;
	sock_addr_udp.sin_addr.s_addr = INADDR_ANY;
	sock_addr_udp.sin_port = htons(port);

	if (bind(pCtrlBK->socketUdpSendRcv, (struct sockaddr *)&sock_addr_udp, sizeof(sock_addr_udp)) < 0) {
		DBG_ERR("Failed to bind()!");
		goto err;
	}

	/* bind interface */
	if (strlen(udpBindingIf) > 0 && setsockopt(pCtrlBK->socketUdpSendRcv, SOL_SOCKET, SO_BINDTODEVICE,
		udpBindingIf, strlen(udpBindingIf)) < 0) {
		DBG_ERR("setsockopt-SO_BINDTODEVICE failed!");
		goto err;
	}

	/* use broadcast address */
	if (setsockopt(pCtrlBK->socketUdpSendRcv, SOL_SOCKET, SO_BROADCAST,
				&broadcast, sizeof(broadcast)) < 0) {
		DBG_ERR("setsockopt-SO_BROADCAST failed!");
		goto err;
	}

	/* IPC Socket */
	if ( (pCtrlBK->socketIpcSendRcv = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		DBG_ERR("Failed to IPC socket create!\n");
		goto err;
	}

	memset(&sock_addr_ipc, 0, sizeof(sock_addr_ipc));
	sock_addr_ipc.sun_family = AF_UNIX;
	snprintf(sock_addr_ipc.sun_path, sizeof(sock_addr_ipc.sun_path), "%s", CFGMNT_IPC_SOCKET_PATH);
	unlink(CFGMNT_IPC_SOCKET_PATH);

	if (bind(pCtrlBK->socketIpcSendRcv, (struct sockaddr*)&sock_addr_ipc, sizeof(sock_addr_ipc)) < -1) {
		DBG_ERR("Failed to IPC socket bind!\n");
		goto err;
	}

	if (listen(pCtrlBK->socketIpcSendRcv, CFGMNT_IPC_MAX_CONNECTION) == -1) {
		DBG_ERR("Failed to IPC socket listen!\n");
		goto err;
	}

	return 1;

err:
	cm_closeSocket(pCtrlBK);
	return 0;
} /* End of cm_openSocket */

/*
========================================================================
Routine Description:
	Main task.

Arguments:
	*pContext	- CM control block

Return Value:
	None

Note:
========================================================================
*/
void cm_task(void *pContext)
{
	CM_CTRL *pCtrlBK = (CM_CTRL *)pContext;
	DBG_INFO("task start");

	/* init role */
	pCtrlBK->role = IS_SERVER;

	/* create folder */
	if(!check_if_dir_exist(CFG_MNT_FOLDER)) {
		DBG_INFO("create a folder for cfg_mnt (%s)", CFG_MNT_FOLDER);
		mkdir(CFG_MNT_FOLDER, 0755);
	}

	/* init public & private & group key */
	if (cm_initKeyInfo(pCtrlBK) == 0)
		goto err;

	/* update time */
	cm_updateTime();

	/* init group id */
	if (cm_initGroupId() == 0)
		goto err;

	/* init expired time for session key and group key */
	if (strlen(nvram_safe_get("cfg_sket")))
		sessionKeyExpireTime = nvram_get_int("cfg_sket");
	if (strlen(nvram_safe_get("cfg_gket")))
		groupKeyExpireTime = nvram_get_int("cfg_gket");

	/* init hashtable for client */
	clientHashTable = ht_create(HT_CAPACITY);

	/* get the number of supported band */
	supportedBandNum = num_of_wl_if();

#ifdef RTCONFIG_BANDINDEX_NEW
	supportedIndexVersion = 2;
#endif

	/* init shared memory for client table */
	if (!cm_initClientTbl()) goto err;

#ifdef DUAL_BAND_DETECTION
	if (!cm_initDBListSharedMemory()) goto err;
	cm_loadFileToDBListSharedMemory();
#endif

#if defined(RTCONFIG_BHCOST_OPT) && defined(RTCONFIG_BHSWITCH_RE_SELFOPT)
	if (!cm_initBhSwitchRule())
		 goto err;
#endif

	/* init bridge mac list for wired */
	unlink(MAC_LIST_JSON_FILE);

	/* remove configured file */
	unlink(CFG_JSON_FILE);

	/* unset the status of firmware check/upgrade */
	nvram_unset("cfg_check");
	nvram_unset("cfg_upgrade");
	nvram_unset("cfg_fwstatus");

	/* unset the status of re join */
	nvram_set_int("cfg_rejoin", 0);

#ifdef PRELINK
	nvram_unset("amas_hashbdlkey");
	regen_hash_bundle_key();
#endif

#ifdef ONBOARDING_VIA_VIF
	nvram_unset("wps_via_vif");
	nvram_unset("cfg_obvif_up");
#endif

	/* update network cost */
	update_lldp_cost(0);
#ifdef RTCONFIG_BHCOST_OPT
	/* update rssi score */
	update_rssiscore(0);

    /* set wireless last byte to lldpd */
    set_wifi_lastbyte();

#ifdef RTCONFIG_FRONTHAUL_DWB
	check_fronthaul_dwb_value();
#endif
#endif

#ifdef RTCONFIG_DWB
	cm_AutoDetect_Dedicated_Wifi_Backhaul(1, 1);
#endif

#ifdef RTCONFIG_WIFI_SON
	if (!nvram_match("wifison_ready", "1"))
#endif /* WIFI_SON */
	{
#ifdef ONBOARDING
	/* init onboarding status */
	cm_initOnboardingStatus();
#endif

	/* generate RE list */
	cm_generateReList();

#ifdef RTCONFIG_BCN_RPT
	/* generate AP list */
	cm_updateAPList();
#endif
	/* update chanspec */
	cm_updatePrivateChanspec();
	} /* !wifison_ready */

#ifdef RTCONFIG_NBR_RPT
	/* update nbr version */
	cm_updateNbrListVersion();

	/* reset nbr version for private */
	nvram_unset("cfg_nbr_ver");
#endif

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
	/* copy all private config file to /tmp */
	DBG_INFO("copy private config (%s) to /tmp", CFG_MNT_FOLDER"*.json");
	system("cp "CFG_MNT_FOLDER"*.json /tmp");
#endif

	/* init signal functions */
	signal(SIGTERM, cm_terminateHandle);

	/* display client info */
	signal(SIGUSR1, cm_usr1Handle);

	/* send notification to client */
	signal(SIGUSR2, cm_usr2Handle);

	/* init mutex for thread */
	if (!cm_initThreadMutex())
		goto err;

	/* get interface info */
	if (!cm_getIfInfo(pCtrlBK)) {
		DBG_ERR("get interface information failed");
		goto err;
	}

	/* init socket */
	if (cm_openSocket(pCtrlBK) == 0)
		goto err;

#ifdef RTCONFIG_AMAS_CENTRAL_CONTROL
#ifdef UPDATE_COMMON_CONFIG
	if (cm_updateCommonConfig() == -1) {
		DBG_ERR("generate common config failed");
		goto err;
	}
#endif
#endif

#ifdef CONN_DIAG
	/* init link list for conn diag */
	connDiagUdpList = list_new();
#endif

	/* save pid */
	cm_saveDaemonPid();

	/* start CM function */
	cm_start(pCtrlBK);

err:

	return;
} /* End of cmd_task */

/*
========================================================================
Routine Description:
	User space main function.

Arguments:
	argc		- argument number
	*pArgv[]	- arguments

Return Value:
	0		- exit daemon
	-1		- fork fail

Note:
========================================================================
*/
int main(int argc, char *pArgv[])
{
#if defined(RTCONFIG_RALINK_MT7621)
	Set_CPU();
#endif
	CM_CTRL *pCtrlBK = &cm_ctrlBlock;
	pid_t pid;

#if defined(RTCONFIG_LANTIQ)
	while( !nvram_get_int("wave_ready") )
		sleep(5);
#elif defined(RTCONFIG_QCA)
	while( !nvram_get_int("wlready") )
		sleep(5);
#endif

#ifdef RTCONFIG_SW_HW_AUTH
#ifdef RTCONFIG_AMAS
	/* check supported mode */
	if (!(getAmasSupportMode() & AMAS_CAP)) {
#if defined(RTCONFIG_WIFI_SON)
          if(nvram_match("wifison_ready", "1"))
		goto skip;
#endif
		DBG_ERR("not support CAP");
		goto err;
	}
#endif

#if defined(RTCONFIG_WIFI_SON) && defined(RTCONFIG_AMAS)
skip:
#endif
	/* auth check for daemon */
	if (!check_auth()) {
		DBG_ERR("auth check failed, exit");
		goto err;
	}
	else
		DBG_INFO("auth check success");
#else
	DBG_ERR("auth check is disabled, exit");
	goto err;
#endif	/* RTCONFIG_SW_HW_AUTH */

	/* init */
	memset(pCtrlBK, 0, sizeof(CM_CTRL));

	/* kill old daemon if exists */
	cm_killDaemon();

	/* set dut band_type */
	check_band_type();

	/* fork a 'background' process */
	pid = fork(); /* two PID is established,
					non-zero: parent process, zero: child process */
	if (pid < 0)
		goto err; /* fork fail */
	else if (pid != 0)
		exit(0); /* end up parent process */
	/* End of if */

#ifdef PTHREAD_STACK_SIZE
	attrp = &attr;
	/* change the default stack size of pthread */
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_SIZE);
#endif

	cm_task((void *)pCtrlBK);

	printf("Exit daemon!\n");
	return 0;

err:
	exit(-1);

	return 0;
}

#ifdef RTCONFIG_CONN_EVENT_TO_EX_AP
void cm_mac2ip(char *mac,char *ip,int ip_len)
{
	int i = 0;
	unsigned char ea[6] = {0};
	char ipStr[18] = {0};
	char macStr[18] = {0};
	int found = 0;

	ether_atoe(mac, ea);

	pthread_mutex_lock(&cfgLock);

	/* search slave based on mac */
	for(i = 0; i < p_client_tbl->count; i++) {
		if (memcmp(p_client_tbl->realMacAddr[i], ea, MAC_LEN) == 0) {
			memset(macStr, 0, sizeof(macStr));
			memset(ipStr, 0, sizeof(ipStr));

			snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				p_client_tbl->macAddr[i][0], p_client_tbl->macAddr[i][1],
				p_client_tbl->macAddr[i][2], p_client_tbl->macAddr[i][3],
				p_client_tbl->macAddr[i][4], p_client_tbl->macAddr[i][5]);

			snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", p_client_tbl->ipAddr[i][0],
				p_client_tbl->ipAddr[i][1], p_client_tbl->ipAddr[i][2],
				p_client_tbl->ipAddr[i][3]);

			if ( !strcasecmp(macStr,nvram_safe_get("lan_hwaddr")) ){
				//CAP do not need to check on-line status
				//DBG_INFO("%s (%s) is CAP", macStr, ipStr);
			} else if ( !cm_isSlaveOnline(p_client_tbl->reportStartTime[i])) {
				//DBG_INFO("%s (%s) is offline", macStr, ipStr);
				continue;
			}

			found = 1;
			break;
		}
	}

	pthread_mutex_unlock(&cfgLock);

	if (found) {
		strncpy(ip,ipStr,ip_len);
	} else {
		memset(ip,0,ip_len);
	}
} /* End of cm_mac2ip */
#endif
