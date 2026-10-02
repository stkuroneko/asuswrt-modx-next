#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_ethevent.h"
#include "cfg_event.h"
#ifdef ONBOARDING
#include "cfg_onboarding.h"
#endif

/*
========================================================================
Routine Description:
	Process probe request from ethevent.

Arguments:
	data		- received data

Return Value:
	None

Note:
========================================================================
*/
void cm_processEthProbeReq(unsigned char *data)
{
	json_object *eventRoot = json_tokener_parse((char *)data);
	json_object *ethEventObj = NULL;
	json_object *etherListObj = NULL;
	unsigned char msg[1024] = {0};

	if (!eventRoot) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_get_ex(eventRoot, ETHEVENT_PREFIX, &ethEventObj);
	json_object_object_get_ex(ethEventObj, E_ETHER_LIST, &etherListObj);

	if (!etherListObj)  {
		DBG_ERR("etherListObj is null");
		json_object_put(eventRoot);
		return;
	}

	DBG_INFO("ether list (%s)", json_object_get_string(etherListObj));

	snprintf((char *)msg, sizeof(msg), "{\"%s\":%d,\"%s\":{\"%s\":%s,\"%s\":%d}}",
			CFG_STR_STATUS, OB_STATUS_REQ, get_unique_mac(), CFG_STR_ETHER_LIST,
			json_object_get_string(etherListObj), CFG_STR_SOURCE, FROM_ETHERNET);

	DBG_INFO("msg(%s)", msg);

	if (cm_ctrlBlock.role == IS_CLIENT) {
		/* send TCP packet */
		if (cm_sendTcpPacket(REQ_ONBOARDING, &msg[0]) == 0)
			DBG_ERR("Fail to send TCP packet!");
	}
	else
		cm_processOnboardingMsg((char *)msg);
		
	json_object_put(eventRoot);
} /* End of cm_processEthProbeReq */

/*
========================================================================
Routine Description:
	Process packets from eevent.

Arguments:
	data		- received data

Return Value:
	None

Note:
========================================================================
*/
void cm_ethEventPacketProcess(unsigned char *data)
{
	json_object *eventRoot = json_tokener_parse((char *)data);
	json_object *ethEventObj = NULL;
	json_object *eidObj = NULL;
	int eid = 0;

	DBG_INFO("enter");

	if (!eventRoot) {
		DBG_ERR("error for json parse");
		return;
	}

	json_object_object_get_ex(eventRoot, ETHEVENT_PREFIX, &ethEventObj);
	json_object_object_get_ex(ethEventObj, EVENT_ID, &eidObj);

	if (!ethEventObj || !eidObj) {
		DBG_ERR("ethEventObj or eidObj is NULL!");
		return;
	}

	eid = atoi(json_object_get_string(eidObj));
	json_object_put(eventRoot);

	if (eid == EID_ETHEVENT_DEVICE_PROBE_REQ) { /* probe req event from eth */
		if (cm_isOnboardingAvailable())
			cm_processEthProbeReq(data);
	}
	else if (eid == EID_ETHEVENT_ONBOARDING_STATUS)	/* onboarding status from eth */
	{
		cm_processEthOnboardingStatus(data);
	}
	else
		DBG_INFO("unknown event id");

	DBG_INFO("leave");
} /* End of cm_ethEventPacketProcess */
