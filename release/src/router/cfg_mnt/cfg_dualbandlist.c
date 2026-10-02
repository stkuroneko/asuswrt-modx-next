#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <sys/shm.h>
#include <shared.h>
#include <shutils.h>
#include <shmkey.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_dualbandlist.h"
#include "cfg_string.h"

/* for dual bans sta that from smart connect */
static int shm_dbsta_tbl_id = -1;
static void *shared_dbsta = (void *)0;
static char *p_dbsta_tbl = NULL;

/* for dual band sta all */
static int shm_dbsta_all_tbl_id = -1;
static void *shared_dbsta_all = (void *)0;
static P_DBSTA_ALL_TABLE p_dbsta_all_tbl;
static int dbListUpdate = 0;

/*
========================================================================
Routine Description:
	Init shared memory for dual band list.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_initDBListSharedMemory()
{
	int lock = 0;

	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);
	shm_dbsta_all_tbl_id = shmget((key_t)SHMKEY_AMASDB_ALL, sizeof(DBSTA_ALL_TABLE), 0666|IPC_CREAT);
	if (shm_dbsta_all_tbl_id == -1){
		DBG_ERR("shmget failed");
		file_unlock(lock);
		return 0;
	}

	shared_dbsta_all = shmat(shm_dbsta_all_tbl_id, (void *)0, 0);
	if (shared_dbsta_all == (void *)-1){
		DBG_ERR("shmat failed");
		file_unlock(lock);
		return 0;
	}

	p_dbsta_all_tbl = (P_DBSTA_ALL_TABLE)shared_dbsta_all;

	file_unlock(lock);

	return 1;
} /* End of cm_initDBListSharedMemory */

/*
========================================================================
Routine Description:
	Destroy shared memory for dual band list.

Arguments:
	toFile		- write shared memory to file

Return Value:
	None

========================================================================
*/
void cm_destroyDBListSharedMemory(int toFile)
{
	if (toFile)
		cm_writeDBListSharedMemoryToFile();

	/* detach shared memory */
	if (shmdt(p_dbsta_all_tbl) == -1)
		DBG_ERR("detach shared memory failed");

	/* detach shared memory from smart connect */
	cm_detachDBStaListSharedMemory();
} /* End of cm_destroyDBListSharedMemory */

/*
========================================================================
Routine Description:
	Load  dual band list of file to shared memory.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_loadFileToDBListSharedMemory()
{
	int fd, lock = 0;

	pthread_mutex_lock(&dualBandLock);
	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);

	if ((fd = open(DUAL_BAND_LIST_PATH, O_RDONLY)) < 0) {
		DBG_ERR("open %s failed", DUAL_BAND_LIST_PATH);
	}
	else {
		DBG_INFO("load dual band list from file");
		read(fd, p_dbsta_all_tbl, sizeof(DBSTA_ALL_TABLE));
		DBG_INFO("dual band list (%s), num (%d)", p_dbsta_all_tbl->dbsta_all, p_dbsta_all_tbl->num);
		close(fd);
	}

	file_unlock(lock);
	pthread_mutex_unlock(&dualBandLock);
} /* End of cm_loadFileToDBListSharedMemory */

/*
========================================================================
Routine Description:
	Write shared memory of dual band list to file.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_writeDBListSharedMemoryToFile()
{
	int fd, lock = 0;

	pthread_mutex_lock(&dualBandLock);
	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);
	if (shared_dbsta_all != (void*)-1){
		if ((fd = open(DUAL_BAND_LIST_PATH, O_RDWR|O_CREAT|O_TRUNC)) < 0) {
			DBG_ERR("open %s failed", DUAL_BAND_LIST_PATH);
		}
		else {
			write(fd, p_dbsta_all_tbl, sizeof(DBSTA_ALL_TABLE));
			close(fd);
		}
	}
	file_unlock(lock);
	pthread_mutex_unlock(&dualBandLock);
} /* End of cm_writeDBListSharedMemoryToFile */


/*
========================================================================
Routine Description:
	Attach dbsta list from smart connect.

Arguments:
	None

Return Value:
	0		- fail
	1		- success

========================================================================
*/
int cm_attachDBStaListSharedMemory()
{
	shm_dbsta_tbl_id = shmget((key_t)SHMKEY_AMASDB, 0, 0);
	if (shm_dbsta_tbl_id == -1){
		DBG_ERR("shmget failed");
		return 0;
	}

	shared_dbsta = shmat(shm_dbsta_tbl_id, (void *)0, 0);
	if (shared_dbsta == (void *)-1){
		DBG_ERR("shmat failed");
		return 0;
	}

	p_dbsta_tbl = (char *)shared_dbsta;

	return 1;
} /* End of cm_attachDBStaListSharedMemory */


/*
========================================================================
Routine Description:
	Detach dbsta list from smart connect.

Arguments:
	None

Return Value:
	None

========================================================================
*/
void cm_detachDBStaListSharedMemory()
{
	/* detach shared memory */
	if (shmdt(p_dbsta_tbl) == -1)
		DBG_ERR("detach shared memory failed");
} /* End of cm_detachDBStaListSharedMemory */

/*
========================================================================
Routine Description:
	Check sta support dual band capability or not.

Arguments:
	staMac		- sta mac

Return Value:
	0		- sta doesn't support dual band capability
	1		- sta support dual band capability

========================================================================
*/
int cm_checkDualBandCapability(char *staMac)
{
	char *nv, *nvp, *b, *mac, *timestamp;
	int ret = 0;

	if (p_dbsta_tbl == NULL) {
		if (!cm_attachDBStaListSharedMemory())
			return 0;

		if (p_dbsta_tbl == NULL)
			return 0;
	}

	nv = nvp = strdup(p_dbsta_tbl);
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &timestamp) != 2))
				continue;

			if (strlen(mac) == 0)
				continue;

			if (strcasecmp(staMac, mac) == 0) {
				ret = 1;
				break;
			}
		}
		free(nv);
	}

	DBG_INFO("staMac (%s), supported dual band (%d)", staMac, ret);

	return ret;
} /* End of cm_checkDualBandCapability */

/*
========================================================================
Routine Description:
	Check wirelss dual band supported list.

Arguments:
	staMac		- sta mac

Return Value:
	0		- sta mac doesn't exist in dual band list
	1		- sta mac exist in dual band list

========================================================================
*/
int cm_checkDualBandListUpdate(char *staMac)
{
	char *nv, *nvp, *b, *mac, *timestamp;
	int ret = 0, lock = 0;

	if (staMac == NULL)
		return 0;

	if (p_dbsta_all_tbl == NULL)
		return 0;

	pthread_mutex_lock(&dualBandLock);
	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);

	nv = nvp = strdup(p_dbsta_all_tbl->dbsta_all);
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &timestamp) != 2))
				continue;

			if (strlen(mac) == 0)
				continue;

			if (strcasecmp(staMac, mac) == 0) {
				ret = 1;
				break;
			}
		}
		free(nv);
	}

	file_unlock(lock);
	pthread_mutex_unlock(&dualBandLock);

	DBG_INFO("staMac (%s), ret (%d)", staMac, ret);

	return ret;
} /* End of cm_checkDualBandListUpdate */

/*
========================================================================
Routine Description:
	Update wirelss dual band supported list.

Arguments:
	staMac		- sta mac

Return Value:
	0		- no updated
	1		- updated

========================================================================
*/
void cm_updateDualBandList(char *staMac)
{
	char staEntry[32] = {0};
	char dualBandList[MAX_SIZE_DBSTA_LIST] = {0};
	char *nv, *nvp, *b, *mac, *timestamp;
	char oldStaMac[18] = {0};
	long ts = 0;
	int lock = 0;
	time_t now;

	time(&now);
	ts = now;

	if (p_dbsta_all_tbl == NULL)
		return;

	DBG_INFO("staMac (%s)", staMac);

	pthread_mutex_lock(&dualBandLock);
	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);

	nv = nvp = strdup(p_dbsta_all_tbl->dbsta_all);

	/* find oldest sta based on timestamp */
	if (p_dbsta_all_tbl->num >= MAX_DUAL_BAND_STA) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &timestamp) != 2))
				continue;

			if (strlen(mac) == 0)
				continue;

			if (strtol(timestamp, NULL, 10) < ts) {
				ts = strtol(timestamp, NULL, 10);
				memset(oldStaMac, 0, sizeof(oldStaMac));
				strlcpy(oldStaMac, mac, sizeof(oldStaMac));
			}
		}
		free(nv);

		DBG_INFO("oldest sta(%s), timestamp(%ld)", oldStaMac, ts);
	}

	nv = nvp = strdup(p_dbsta_all_tbl->dbsta_all);
	if (nv) {
		/* reasemble dual band list */
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &timestamp) != 2))
				continue;

			if (strlen(mac) == 0 || strcmp(mac, oldStaMac) == 0)
				continue;

			memset(staEntry, 0, sizeof(staEntry));
			snprintf(staEntry, sizeof(staEntry), "<%s>%s", mac, timestamp);
			strncat(dualBandList, staEntry, strlen(staEntry));
		}
		free(nv);

		/* add new mac */
		memset(staEntry, 0, sizeof(staEntry));
		snprintf(staEntry, sizeof(staEntry), "<%s>%ld", staMac, now);
		strncat(dualBandList, staEntry, strlen(staEntry));
		strlcpy(p_dbsta_all_tbl->dbsta_all, dualBandList, sizeof(p_dbsta_all_tbl->dbsta_all));

		if (p_dbsta_all_tbl->num < MAX_DUAL_BAND_STA)
			p_dbsta_all_tbl->num++;
	}

	file_unlock(lock);
	pthread_mutex_unlock(&dualBandLock);

	//cm_writeDBListSharedMemoryToFile();
	dbListUpdate = 1;
} /* End of cm_updateDualBandList */

/*
========================================================================
Routine Description:
	Handle wireless dual band supported list.

Arguments:
	msg		- decrypted message

Return Value:
	None

========================================================================
*/
void cm_handleDualBandListUpdate(unsigned char *msg)
{
	json_object *root = NULL, *dualBandObj = NULL, *staEntry = NULL;
	int i = 0, lock = 0;
	char staMac[32] = {0};
	char dualBandList[MAX_SIZE_DBSTA_LIST] = {0};

	if (p_dbsta_all_tbl == NULL)
		return;

	root = json_tokener_parse((char *)msg);
	if (root == NULL) {
		DBG_ERR("json_tokener_parse err!");
		return;
	}

	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);
	json_object_object_get_ex(root, CFG_STR_DUAL_BAND_LIST, &dualBandObj);
	if (dualBandObj) {
		memset(p_dbsta_all_tbl->dbsta_all, 0, sizeof(p_dbsta_all_tbl->dbsta_all));
		for (i = 0; i < json_object_array_length(dualBandObj); i++) {
			staEntry = json_object_array_get_idx(dualBandObj, i);
			snprintf(staMac, sizeof(staMac), "<%s>", json_object_get_string(staEntry));
			strncat(dualBandList, staMac, strlen(staMac));
			strlcpy(p_dbsta_all_tbl->dbsta_all, dualBandList, sizeof(p_dbsta_all_tbl->dbsta_all));
			DBG_INFO("dual band list (%s)", p_dbsta_all_tbl->dbsta_all);
		}
	}
	file_unlock(lock);

	json_object_put(root);
} /* End of cm_handleDualBandListUpdate */

/*
========================================================================
Routine Description:
	Generate wireless dual band supported list.

Arguments:
	msg		- output message arrary
	msgLen		- the length of output message array

Return Value:
	message length

========================================================================
*/
int cm_prepareDualBandListMsg(char *msg, int msgLen)
{
	json_object *root = NULL, *staArray = NULL;
	char *nv, *nvp, *b, *mac, *timestamp;
	int lock = 0;

	if (p_dbsta_all_tbl == NULL)
		return 0;

	root = json_object_new_object();

	if (!root) {
		DBG_ERR("root is NULL");
		return 0;
	}

	pthread_mutex_lock(&dualBandLock);
	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);

	nv = nvp = strdup(p_dbsta_all_tbl->dbsta_all);
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &timestamp) != 2))
				continue;

			if (strlen(mac) == 0)
				continue;

			if (!staArray)
					staArray = json_object_new_array();

			if (staArray)
				json_object_array_add(staArray,  json_object_new_string(mac));
		}
		free(nv);

		if (staArray)
			json_object_object_add(root, CFG_STR_DUAL_BAND_LIST, staArray);
	}

	snprintf(msg, msgLen, "%s", json_object_to_json_string(root));
	json_object_put(root);

	file_unlock(lock);
	pthread_mutex_unlock(&dualBandLock);

	DBG_INFO("msg(%s)", msg);

	return strlen(msg);
} /* End of cm_prepareDualBandListMsg */

/*
========================================================================
Routine Description:
	Check sta support dual band or not.

Arguments:
	roo		- json object from file
	band		- band info
	staMac		- the mac of sta
	ts		- timestamp

Return Value:
	0		- doens't support dual band capability
	1		- support dual band capability

Note:
========================================================================
*/
int cm_staSupportDualBandCapability(json_object *root, char *band, char *staMac, long ts)
{
	json_object *bandObj = NULL, *staObj = NULL;
	int ret = 0;
	char bandConv[8] = {0};

	if (root == NULL || band == NULL || staMac == NULL) {
		DBG_ERR("root, band or staMac is NULL");
		return 0;
	}
	
 	DBG_INFO("band(%s), staMac(%s), ts(%ld)",  band, staMac, ts);

	/* convert 5G & 5G1 band to 5G only */
	if (strncasecmp(band, CFG_STR_5G, strlen(CFG_STR_5G)) == 0)
		snprintf(bandConv, sizeof(bandConv), "%s", CFG_STR_5G);
	else
		snprintf(bandConv, sizeof(bandConv), "%s", band);

	if (root) {
		json_object_object_foreach(root, key, val) {
			bandObj = val;

			/* update sta info w/ timestamp */
			if (strcasecmp(bandConv, key) == 0) {
				json_object_object_del(bandObj, staMac);
				json_object_object_add(bandObj, staMac, json_object_new_int64(ts));
			}
			else		/* check another band exist sta or not */
			{
				json_object_object_get_ex(bandObj, staMac, &staObj);
				if (staObj) 
					ret = 1;
			}
		}
	}

	return ret;
} /* End of cm_staSupportDualBandCapability */

/*
========================================================================
Routine Description:
	Update dual band sta timestamp.

Arguments:
	staMac		- sta mac

Return Value:
	None

========================================================================
*/
void cm_updateDualBandStaTimestamp(char *staMac)
{
	char staEntry[32] = {0};
	char dualBandList[MAX_SIZE_DBSTA_LIST] = {0};
	char *nv, *nvp, *b, *mac, *timestamp;
	time_t now;
	int lock = 0;

	if (p_dbsta_all_tbl == NULL)
		return;

	time(&now);

	DBG_INFO("staMac (%s)", staMac);

	pthread_mutex_lock(&dualBandLock);
	lock = file_lock(DUAL_BAND_LIST_FILE_LOCK);

	nv = nvp = strdup(p_dbsta_all_tbl->dbsta_all);
	if (nv) {
		/* reasemble dual band list */
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &timestamp) != 2))
				continue;

			if (strlen(mac) == 0)
				continue;

			memset(staEntry, 0, sizeof(staEntry));
			if (strcmp(mac, staMac) == 0)
				snprintf(staEntry, sizeof(staEntry), "<%s>%ld", mac, now);
			else
				snprintf(staEntry, sizeof(staEntry), "<%s>%s", mac, timestamp);
			strncat(dualBandList, staEntry, strlen(staEntry));
		}
		free(nv);

		strlcpy(p_dbsta_all_tbl->dbsta_all, dualBandList, sizeof(p_dbsta_all_tbl->dbsta_all));
	}

	file_unlock(lock);
	pthread_mutex_unlock(&dualBandLock);

	//cm_writeDBListSharedMemoryToFile();
	dbListUpdate = 1;
} /* End of cm_updateDualBandStaTimestamp */

/*
========================================================================
Routine Description:
	Check dual band list updated or not. If yes, write to file.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_checkDBListUpdated()
{
	if (dbListUpdate) {
		cm_writeDBListSharedMemoryToFile();
		dbListUpdate = 0;
	}
} /* End of cm_checkDBListUpdated */