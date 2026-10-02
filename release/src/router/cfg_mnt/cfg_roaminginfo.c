#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <pthread.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_roaminginfo.h"

static struct sched scRomaingInfoCheck; /* The scheduler for checking romaing info */

/* for sta roaming info */
json_object *staRoamingInfo = NULL;

/*
========================================================================
Routine Description:
	Callback for check sta roaming info.

Arguments:
	sched		- scheduler

Return Value:
	None

Note:
========================================================================
*/
void cm_checkRoamingInfoEvent(struct sched *sched)
{
	if (staRoamingInfo) {
		time_t now = uptime();
		json_object *staArray = NULL;
		json_object *staMac = NULL;
		int lock;

		//DBG_INFO("check roaming info for sta");

		pthread_mutex_lock(&roamingInfoLock);
		lock = file_lock(STA_ROAMING_FILE_LOCK);
		/* record which sta need to remove from staRoamingInfo */
		json_object_object_foreach(staRoamingInfo, key, val) {
			if ((now - json_object_get_int64(val)) > STA_ROAMING_TIME) {
				if (!staArray)
					staArray = json_object_new_array();
				staMac = json_object_new_string(key);
				json_object_array_add(staArray, staMac);
			}					
		}

		if (staArray) {
			int i = 0;
			int staNum = json_object_array_length(staArray);
			/* remove sta from staRoamingInfo based on staArray */
			if (staNum > 0) {
				for (i = 0; i < staNum; i++) {
					staMac = json_object_array_get_idx(staArray, i);
					/* remove sta */
					json_object_object_del(staRoamingInfo, json_object_get_string(staMac));
				}
				json_object_to_file(STA_ROAMING_FILE, staRoamingInfo);
			}
		}
	
		json_object_put(staArray);
		file_unlock(lock);
		pthread_mutex_unlock(&roamingInfoLock);
	}

	scRomaingInfoCheck.timeout = current_time() + CHECK_ROAMING_INFO_INTERVAL;
} /* End of cm_checkRoamingInfoEvent */

/*
========================================================================
Routine Description:
	Record the roaming information for specific sta.

Arguments:
	staMac		- the mac address of sta

Return Value:
	None

======================================================================== 
*/
void cm_recordRoamingInfo(char *staMac)
{
	int lock;

	pthread_mutex_lock(&roamingInfoLock);
	lock = file_lock(STA_ROAMING_FILE_LOCK);
	if (!staRoamingInfo)
		staRoamingInfo = json_object_new_object();
	else
		json_object_object_del(staRoamingInfo, staMac);
	json_object_object_add(staRoamingInfo, staMac, json_object_new_int64(uptime()));
	
	if (staRoamingInfo)
		json_object_to_file(STA_ROAMING_FILE, staRoamingInfo);

	file_unlock(lock);
	pthread_mutex_unlock(&roamingInfoLock);
} /* End of cm_recordRoamingInfo */

/*
========================================================================
Routine Description:
	Register scheduler for romaing info.

Arguments:
	None

Return Value:
	None

======================================================================== 
*/
void cm_registerRoamingInfoSch()
{
	/* for checking romaing info */
	scRomaingInfoCheck.on_timeout = cm_checkRoamingInfoEvent;
	scRomaingInfoCheck.timeout = current_time() + CHECK_ROAMING_INFO_INTERVAL;
	scRomaingInfoCheck.name = "RomaingInfoCheck";
	add_sched(&scRomaingInfoCheck);
} /* End of cm_registerRoamingInfoSch */
