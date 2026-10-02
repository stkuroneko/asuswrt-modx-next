#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <pthread.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_chanspec.h"
#include "chmgmt.h"
#include <wlioctl.h>
#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif

int cm_updateAvblChanspec(AVBL_CHANSPEC_T *avblChannel);

/*
========================================================================
Routine Description:
	Update bandwidth & channel.

Arguments:
	msg		- bandwidth & channel

Return Value:
	None

Note:
========================================================================
*/
void cm_updateChanspec(char *msg)
{
	json_object *root = json_tokener_parse(msg);
	char uMac[18] = {0};
	json_object *fileRoot = NULL;
	json_object *uMacObj = NULL;
	json_object *chanspecObj = NULL;
	json_object *chanspecTempObj = NULL;
	AVBL_CHANSPEC_T avblChanspec;
	int bandNum = 0;
	int isRe = 0;

	if (!root) {
		DBG_ERR("error for json parse");
		return;
	}

	DBG_INFO("msg(%s)", msg);

	memset(&avblChanspec, 0, sizeof(AVBL_CHANSPEC_T));
	json_object_object_get_ex(root, CFG_STR_MAC, &uMacObj);
	json_object_object_get_ex(root, CFG_STR_CHANSPEC, &chanspecObj);

	pthread_mutex_lock(&chanspecLock);

	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			json_object_put(root);
			pthread_mutex_unlock(&chanspecLock);
			return;
		}
	}

	/* update chanspecl on differnt DUT */
	if (uMacObj && chanspecObj) {
		memset(uMac, 0, sizeof(uMac));
		snprintf(uMac, sizeof(uMac), "%s", json_object_get_string(uMacObj));

		chanspecTempObj = json_tokener_parse(json_object_get_string(chanspecObj));
		if (chanspecTempObj) {
			/* delete object */
			DBG_INFO("delete old chanspec for %s", uMac);
			json_object_object_del(fileRoot, uMac);

			/* count band number and record */
			json_object_object_foreach(chanspecTempObj, key, val)
				bandNum++;
			if (bandNum)
				json_object_object_add(chanspecTempObj, CFG_STR_BANDNUM,
					json_object_new_int(bandNum));

			/* check mac is from RE */
			if (strcasecmp(uMac, get_unique_mac()) != 0)
				isRe = 1;
			json_object_object_add(chanspecTempObj, CFG_STR_IS_RE,
				json_object_new_int(isRe));

			/* add object */
			json_object_object_add(fileRoot, uMac, chanspecTempObj);
		}
	}

	/* write to file */
	if (fileRoot)
		json_object_to_file(CHANSPEC_LIST_JSON_PATH, fileRoot);

	/* update band info */
	if (strlen(uMac)) {
		DBG_INFO("update band info for %s", uMac);
		cm_updateBandInfoByMac(uMac, chanspecObj);
	}

	json_object_put(fileRoot);
	json_object_put(root);

	if (cm_updateAvblChanspec(&avblChanspec) || nvram_match("cfg_test", "1")) {
		//TODO
		wl_chanspec_changed_action(&avblChanspec);
	}

	pthread_mutex_unlock(&chanspecLock);
} /* End of cm_updateChanspec */

/*
========================================================================
Routine Description:
	Revmoe chanspec by mac.

Arguments:
	mac		- mac

Return Value:
	None

Note:
========================================================================
*/
void cm_removeChanspecByMac(char *mac)
{
	json_object *fileRoot = NULL;
	AVBL_CHANSPEC_T avblChanspec;

	memset(&avblChanspec, 0, sizeof(AVBL_CHANSPEC_T));

	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return;
	}

	/* remove chanspec by mac */
	DBG_INFO("remove chanspec by %s", mac);
	json_object_object_del(fileRoot, mac);

	/* write to file */
	if (fileRoot)
		json_object_to_file(CHANSPEC_LIST_JSON_PATH, fileRoot);
	json_object_put(fileRoot);

	if (cm_updateAvblChanspec(&avblChanspec) || nvram_match("cfg_test", "1")) {
		//TODO
		wl_chanspec_changed_action(&avblChanspec);
	}

	pthread_mutex_unlock(&chanspecLock);
} /* End of cm_removeChanspecByMac */

/*
========================================================================
Routine Description:
	Check chanspec need to update or not.

Arguments:
	band		- band
	chInfo		- channel info
	bwCap		- bw cap

Return Value:
	0		- don't need to update
	1		- need to update

Note:
========================================================================
*/
int cm_checkChanspecUpdate(char *band, char *chInfo, int bwCap)
{
	json_object *fileRoot = NULL;
	json_object *bandObj = NULL;
	json_object *bwObj = NULL;
	json_object *channelObj = NULL;
	int ret = 0;

	fileRoot = json_object_from_file(CHANSPEC_PRIVATE_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_INFO("need to update");
		ret = 1;
		goto exit;
	}
	else
	{
		json_object_object_get_ex(fileRoot, band, &bandObj);
		if (!bandObj) {
			DBG_INFO("need to update");
			ret = 1;
			goto exit;
		}
		else
		{
			json_object_object_get_ex(bandObj, CFG_STR_CHANNEL, &channelObj);
			json_object_object_get_ex(bandObj, CFG_STR_BANDWIDTH, &bwObj);
			if (!channelObj || !bwObj) {
				DBG_INFO("need to update");
				ret = 1;
				goto exit;
			}
			else
			{
				if ((strcmp(json_object_get_string(channelObj), chInfo) != 0) ||
					(json_object_get_int(bwObj) != bwCap))
				{
					DBG_INFO("need to update");
					ret = 1;
				}
			}
		}
	}

exit:	

	json_object_put(fileRoot);

	return ret;
} /* End of cm_checkChanspecUpdate */

/*
========================================================================
Routine Description:
	Get chanspec (bandwidth & channel).

Arguments:
	chanspecObj		- chanspec
	check		- check difference on chanspec

Return Value:
	0		- no data
	1		- have data

Note:
========================================================================
*/
int cm_getChanspec(json_object *chanspecObj, int check)
{
	json_object *bandObj = NULL;
	int unit = 0;
	char word[256], *next;
	char *band = NULL;
	int bwCap = 0;
	char chInfo[MAX_CHANSPEC_BUFLEN] = {0};
	int ret = 0;
	char prefix[sizeof("wlXXXXX_")], tmp[64];
	int nband = 0, num5g = 0;

	if (!chanspecObj) {
		DBG_ERR("chanspecObj is NULL");
		return 0;
	}

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		bwCap = 0;
		nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
		if (nband == 2)
			band = CFG_STR_2G;
		else if (nband == 1) {
			num5g++;
			band = (num5g == 1 ? CFG_STR_5G : CFG_STR_5G1);
		}
		else if (nband == 4)
			band = CFG_STR_6G;
		else
			band = "unknown";

		memset(chInfo, 0, sizeof(chInfo));
		if (wl_get_chans_info(unit, chInfo, sizeof(chInfo)) < 0) {
			DBG_ERR("get chan info failed");
			break;
		}

		if (wl_get_bw_cap(unit, &bwCap) < 0) {
			DBG_ERR("get bw cap failed");
			ret = 0;
			break;
		}

		if (!ret)
			ret = check ? cm_checkChanspecUpdate(band, chInfo, bwCap) : 1;

		bandObj = json_object_new_object();
		if (!bandObj) {
			DBG_ERR("bandObj is NULL");
			ret = 0;
			break;
		}
		else
		{
			json_object_object_add(bandObj, CFG_STR_BANDWIDTH, json_object_new_int(bwCap));
			json_object_object_add(bandObj, CFG_STR_CHANNEL, json_object_new_string(chInfo));
			json_object_object_add(chanspecObj, band, bandObj);
		}

		unit++;
	}

	return ret;
}

/*
========================================================================
Routine Description:
	Update private chanspec.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_updatePrivateChanspec()
{
	char msg[MAX_CHANSPEC_BUFLEN] = {0};
	json_object *chanspecObj = json_object_new_object();

	if (chanspecObj) {
		if (cm_getChanspec(chanspecObj, 1)) {
			snprintf(msg, sizeof(msg), "{\"%s\":\"%s\",\"%s\":%s}",
				CFG_STR_MAC, get_unique_mac(), CFG_STR_CHANSPEC, json_object_get_string(chanspecObj));
			json_object_to_file(CHANSPEC_PRIVATE_LIST_JSON_PATH, chanspecObj);
			cm_updateChanspec(msg);
		}

		json_object_put(chanspecObj);
	}
}

/*
========================================================================
Routine Description:
	Load and parse chanspec.

Arguments:
	avblChannel		- available channel
	avblBandwidth		- availabe bandwidth
	channelCount		- channel count
	bwCount		- bandwidth count
	tribandRe		- RE support tri-band in AiMesh
	dual5gRe		- RE support dual 5g
	band 6g		- 6g band

Return Value:
	0		- succes
	-1		- error

Note:
========================================================================
*/
int cm_loadChanspec(chinfo_t *avblChannel, int channelCount, bwinfo_t *avblBandwidth, int bwCount, int *tribandRe, int *dual5gRe, int band6g)
{
	json_object *fileRoot = NULL;
	json_object *bandObj = NULL;
	json_object *bwObj = NULL;
	json_object *channelObj = NULL;
	json_object *bandNumObj = NULL, *isReObj = NULL;
	json_object *band6gObj = NULL;
	json_object *band5gObj = NULL, *band5g1Obj = NULL;
	char uMac[18] = {0};
	char channelData[MAX_CH_DATA_BUFLEN] = {0};
	char szChan[16];
	char *next = NULL;
	uint32_t channelStatus = 0, channelNum = 0;
	int avblChannelCount[MAX_CH_NUM] = {0};
	int avblDeviceCount = 0;
	int i;
	int fmtVer = 0;
	char *dataStart;
	int unit = 0;

	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("error of chanspec file");
		return (-1);
	}

	json_object_object_foreach(fileRoot, key, val) {
		strlcpy(uMac, key, sizeof(uMac));

#if 0
		if (cm_checkClientStatus(uMac) == 0) {
			DBG_INFO("Invalid device: %s", uMac);
			continue;
		}
#endif

		bandObj = val;
		if (band6g) {
			json_object_object_get_ex(bandObj, CFG_STR_6G, &band6gObj);
			if (band6gObj)
				avblDeviceCount++;
		}
		else
			avblDeviceCount++;

		json_object_object_get_ex(bandObj, CFG_STR_BANDNUM, &bandNumObj);
		json_object_object_get_ex(bandObj, CFG_STR_IS_RE, &isReObj);

		if (bandNumObj && isReObj) {
			if (json_object_get_int(isReObj) &&
				json_object_get_int(bandNumObj) == 3)
				*tribandRe = 1;
		}

		/* for dual 5g */
		json_object_object_get_ex(bandObj, CFG_STR_5G, &band5gObj);
		json_object_object_get_ex(bandObj, CFG_STR_5G1, &band5g1Obj);
		if (band5gObj && band5g1Obj)
			*dual5gRe = 1;

		json_object_object_foreach(bandObj, key, val) {
			unit = -1;

			/* assign unit index */
			if (band6g) {
				if (strcmp(key, CFG_STR_2G) == 0 || strcmp(key, CFG_STR_5G) == 0 || strcmp(key, CFG_STR_5G1) == 0)
					continue;
				else if (strcmp(key, CFG_STR_6G) == 0)
					unit = 2;
			}
			else
			{
				if (strcmp(key, CFG_STR_2G) == 0)
					unit = 0;
				else if (strcmp(key, CFG_STR_5G) == 0 || strcmp(key, CFG_STR_5G1) == 0)
					unit = 1;
			}

			if (unit >= 0) {
				json_object_object_get_ex(val, CFG_STR_CHANNEL, &channelObj);
				json_object_object_get_ex(val, CFG_STR_BANDWIDTH, &bwObj);

				if (channelObj) {
					strlcpy(channelData, json_object_get_string(channelObj), sizeof(channelData));

					if (sscanf(channelData, "%d %*s", &fmtVer) != 1) {
						fmtVer = CHINFO_CMNFMT_V1;
						dataStart = channelData;
					}
					else
					{
						dataStart = strchr(channelData, ' ') + 1;
					}

					if (fmtVer == CHINFO_CMNFMT_V1) {
						foreach(szChan, dataStart, next) {
							if (sscanf(szChan, "%05u%03u", &channelStatus, &channelNum) == 2) {
								if(channelNum > channelCount -1)
									continue;

								if (band6g == 1) {
									avblChannel[channelNum] |= CHINFO_AVBL;
								}
								else
								{
									if (channelNum < START_CHANNEL_NUMBER_5G)
										avblChannel[channelNum] |= CHINFO_AVBL;
									else
										avblChannel[channelNum] |= channelStatus;
								}

								avblChannelCount[channelNum]++;
							}
						}
					}
				}

				if (bwObj) {
					if (unit < bwCount)
						avblBandwidth[unit] |= json_object_get_int(bwObj);
				}
			}
		}
	}

	DBG_INFO("avblDeviceCount(%d)", avblDeviceCount);

	for (i = 0; i < channelCount; i++)
	{
		if(	(avblChannel[i]
			&& avblChannel[i] & CHINFO_BLK)
			|| (avblChannelCount[i] != avblDeviceCount)
		) {
			avblChannel[i] = 0;
		}
	}

	json_object_put(fileRoot);
	return (0);
}/* End of cm_loadChanspec */

/*
========================================================================
Routine Description:
	update available chanspec if needed

Arguments:
	avblChanspec		- available chanspec

Return Value:
	0		- not upate available chanspec
	1		- update available chanspec

Note:
========================================================================
*/
int cm_updateAvblChanspec(AVBL_CHANSPEC_T *avblChanspec)
{
	json_object *fileRoot = NULL;
	json_object *band2gObj = NULL, *band5gObj = NULL, *tribandReObj = NULL, *band6gObj = NULL, *dual5gReObj = NULL;
	json_object *bw2gObj = NULL, *bw5gObj = NULL, *bw6gObj = NULL;
	json_object *channel2gObj = NULL, *channel5gObj = NULL, *channel6gObj = NULL;
	chinfo_t avblChannel[MAX_CH_NUM] = {0};
	chinfo_t avblChannel6g[MAX_CH_NUM] = {0};
	bwinfo_t avblBandwidth[MAX_BAND_NUM] = {0};
	int i = 0, update = 0, firstUpdate2g = 0, firstUpdate5g = 0, firstUpdate = 0, firstUpdate6g = 0;
	char channelList2g[MAX_CH_DATA_BUFLEN] = {0};
	char channelList5g[MAX_CH_DATA_BUFLEN] = {0};
	char channelList6g[MAX_CH_DATA_BUFLEN] = {0};
#ifdef AVBLCHAN
	int firstUpdateFilter5g = 0;
	char filterChannelList5g[MAX_CH_DATA_BUFLEN] = {0};
#endif
	char channelStr[16] = {0};
	char avblChanspecBuf[512] = {0};
	char word[256], *next;
	int tribandRe = 0, dual5gRe = 0, supported5gBandNum = 0;
	int firstEnter = 0;

	if (!f_exists(CHANSPEC_AVAILABLE_LIST_JSON_PATH)) {
		DBG_INFO("update avbl chanspec at first time");
		firstEnter = 1;
	}

	/* get available channel and bandwidth for 2g & 5g */
	if (cm_loadChanspec(avblChannel, MAX_CH_NUM, avblBandwidth, MAX_BAND_NUM, &tribandRe, &dual5gRe, 0) < 0) {
		DBG_ERR("load 2g & 5g chanspec info failed");
		return 0;
	}

	/* for 2g & 5g channel list */
	for (i = 0; i < MAX_CH_NUM; i++) {
		if (avblChannel[i]) {
			memset(channelStr, 0, sizeof(channelStr));
			snprintf(channelStr, sizeof(channelStr), "%u", i);

			if (i < START_CHANNEL_NUMBER_5G) {
				if (firstUpdate2g == 1)
					strlcat(channelList2g, ",", sizeof(channelList2g));
				else
					firstUpdate2g = 1;

				strlcat(channelList2g, channelStr, sizeof(channelList2g));
			}
			else
			{
				if (firstUpdate5g == 1)
					strlcat(channelList5g, ",", sizeof(channelList5g));
				else
					firstUpdate5g = 1;

				strlcat(channelList5g, channelStr, sizeof(channelList5g));
			}
		}
	}

	/* compare and update */
	fileRoot = json_object_from_file(CHANSPEC_AVAILABLE_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_INFO("error of available chanspec file");
		fileRoot = json_object_new_object();
		if (!fileRoot) {
			DBG_ERR("fileRoot is NULL");
			return 0;
		}
	}

	json_object_object_get_ex(fileRoot, CFG_STR_2G, &band2gObj);
	json_object_object_get_ex(fileRoot, CFG_STR_5G, &band5gObj);
	json_object_object_get_ex(fileRoot, CFG_STR_TRIBAND_RE, &tribandReObj);
	json_object_object_get_ex(fileRoot, CFG_STR_DUAL_5G_RE, &dual5gReObj);
	/* for 2g & 5g band */
	if (band2gObj && band5gObj) {
		json_object_object_get_ex(band2gObj, CFG_STR_BANDWIDTH, &bw2gObj);
		json_object_object_get_ex(band2gObj, CFG_STR_CHANNEL, &channel2gObj);
		json_object_object_get_ex(band5gObj, CFG_STR_BANDWIDTH, &bw5gObj);
		json_object_object_get_ex(band5gObj, CFG_STR_CHANNEL, &channel5gObj);

		/* for 2g bandwidth */
		if (bw2gObj) {
			if (json_object_get_int(bw2gObj) != avblBandwidth[0]) {
				DBG_INFO("update 2g's bandwidth, old(%d), new(%d)",
					json_object_get_int(bw2gObj) , avblBandwidth[0]);
				json_object_object_del(band2gObj, CFG_STR_BANDWIDTH);
				json_object_object_add(band2gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[0]));
				update = 1;
			}
		}
		else
		{
			json_object_object_add(band2gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[0]));
			update = 1;
		}

		/* for 2g channel list */
		if (channel2gObj) {
			if (strcmp(json_object_get_string(channel2gObj), channelList2g) != 0) {
				DBG_INFO("update 2g's channel list, old(%s), new(%s)",
					json_object_get_string(channel2gObj), channelList2g);
				json_object_object_del(band2gObj, CFG_STR_CHANNEL);
				json_object_object_add(band2gObj, CFG_STR_CHANNEL, json_object_new_string(channelList2g));
				update = 1;
			}
		}
		else
		{
			json_object_object_add(band2gObj, CFG_STR_CHANNEL, json_object_new_string(channelList2g));
			update = 1;
		}

		/* for 5g bandwidth */
		if (bw5gObj) {
			if (json_object_get_int(bw5gObj) != avblBandwidth[1]) {
				DBG_INFO("update 5g's bandwidth, old(%d), new(%d)",
					json_object_get_int(bw5gObj) , avblBandwidth[1]);
				json_object_object_del(band5gObj, CFG_STR_BANDWIDTH);
				json_object_object_add(band5gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[1]));
				update = 1;
			}
		}
		else
		{
			json_object_object_add(band5gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[1]));
			update = 1;
		}


		/* for 5g channel list */
		if (channel5gObj) {
			if (strcmp(json_object_get_string(channel5gObj), channelList5g) != 0) {
				DBG_INFO("update 5g's channel list, old(%s), new(%s)",
					json_object_get_string(channel5gObj), channelList5g);
				json_object_object_del(band5gObj, CFG_STR_CHANNEL);
				json_object_object_add(band5gObj, CFG_STR_CHANNEL, json_object_new_string(channelList5g));
				update = 1;
			}
		}
		else
		{
			json_object_object_add(band5gObj, CFG_STR_CHANNEL, json_object_new_string(channelList5g));
			update = 1;
		}
	}
	else
	{
		if (!band2gObj && !band5gObj)
			firstUpdate = 1;

		json_object_object_del(fileRoot, CFG_STR_2G);
		json_object_object_del(fileRoot, CFG_STR_5G);

		band2gObj = json_object_new_object();
		band5gObj = json_object_new_object();
		if (band2gObj) {
			json_object_object_add(band2gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[0]));
			json_object_object_add(band2gObj, CFG_STR_CHANNEL, json_object_new_string(channelList2g));
			json_object_object_add(fileRoot, CFG_STR_2G, band2gObj);
			if (!firstUpdate)
				update = 1;
		}

		if (band5gObj) {
			json_object_object_add(band5gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[1]));
			json_object_object_add(band5gObj, CFG_STR_CHANNEL, json_object_new_string(channelList5g));
			json_object_object_add(fileRoot, CFG_STR_5G, band5gObj);
			if (!firstUpdate)
				update = 1;
		}
	}

	/* for RE support tri-band */
	if (tribandReObj) {
		if (json_object_get_int(tribandReObj) != tribandRe) {
			json_object_object_del(fileRoot, CFG_STR_TRIBAND_RE);
			json_object_object_add(fileRoot, CFG_STR_TRIBAND_RE,
				json_object_new_int(tribandRe));
			update = 1;
		}
	}
	else
	{
		json_object_object_add(fileRoot, CFG_STR_TRIBAND_RE,
			json_object_new_int(tribandRe));
		update = 1;
	}

	/* for RE support dual 5g */
	if (dual5gReObj) {
		if (json_object_get_int(dual5gReObj) != dual5gRe) {
			json_object_object_del(fileRoot, CFG_STR_DUAL_5G_RE);
			json_object_object_add(fileRoot, CFG_STR_DUAL_5G_RE,
				json_object_new_int(dual5gRe));
			update = 1;
		}
	}
	else
	{
		json_object_object_add(fileRoot, CFG_STR_DUAL_5G_RE,
			json_object_new_int(dual5gRe));
		update = 1;
	}

	/* get available channel and bandwidth for 6g */
	if (cm_loadChanspec(avblChannel6g, MAX_CH_NUM, avblBandwidth, MAX_BAND_NUM, &tribandRe, &dual5gRe, 1) < 0) {
		DBG_ERR("load 6g chanspec info failed");
		return 0;
	}

	/* for 6g channel list */
	for (i = 0; i < MAX_CH_NUM; i++) {
		if (avblChannel6g[i]) {
			memset(channelStr, 0, sizeof(channelStr));
			snprintf(channelStr, sizeof(channelStr), "%u", i);

			if (firstUpdate6g == 1)
				strlcat(channelList6g, ",", sizeof(channelList6g));
			else
				firstUpdate6g = 1;

			strlcat(channelList6g, channelStr, sizeof(channelList6g));
		}
	}

	json_object_object_get_ex(fileRoot, CFG_STR_6G, &band6gObj);
	/* for 6g band */
	if (band6gObj) {
		json_object_object_get_ex(band6gObj, CFG_STR_BANDWIDTH, &bw6gObj);
		json_object_object_get_ex(band6gObj, CFG_STR_CHANNEL, &channel6gObj);

		/* for 6g bandwidth */
		if (bw6gObj) {
			if (json_object_get_int(bw6gObj) != avblBandwidth[2]) {
				DBG_INFO("update 6g's bandwidth, old(%d), new(%d)",
					json_object_get_int(bw6gObj) , avblBandwidth[2]);
				json_object_object_del(band6gObj, CFG_STR_BANDWIDTH);
				json_object_object_add(band6gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[2]));
				update = 1;
			}
		}
		else
		{
			json_object_object_add(band6gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[2]));
			update = 1;
		}


		/* for 6g channel list */
		if (channel6gObj) {
			if (strcmp(json_object_get_string(channel6gObj), channelList6g) != 0) {
				DBG_INFO("update 6g's channel list, old(%s), new(%s)",
					json_object_get_string(channel6gObj), channelList6g);
				json_object_object_del(band6gObj, CFG_STR_CHANNEL);
				json_object_object_add(band6gObj, CFG_STR_CHANNEL, json_object_new_string(channelList6g));
				update = 1;
			}
		}
		else
		{
			json_object_object_add(band6gObj, CFG_STR_CHANNEL, json_object_new_string(channelList6g));
			update = 1;
		}
	}
	else
	{
		if (!band6gObj)
			firstUpdate = 1;

		json_object_object_del(fileRoot, CFG_STR_6G);

		band6gObj = json_object_new_object();
		if (band6gObj) {
			json_object_object_add(band6gObj, CFG_STR_BANDWIDTH, json_object_new_int(avblBandwidth[2]));
			json_object_object_add(band6gObj, CFG_STR_CHANNEL, json_object_new_string(channelList6g));
			json_object_object_add(fileRoot, CFG_STR_6G, band6gObj);
			if (!firstUpdate)
				update = 1;
		}
	}

	DBG_INFO("firstUpdate (%d), update(%d), chanspec(%s)", firstUpdate, update, json_object_to_json_string_ext(fileRoot, 0));

	char *test_chlist = nvram_safe_get("test_avbl_2g");
	if(*test_chlist) {
		strlcpy(channelList2g, test_chlist, sizeof(channelList2g));
	}
	test_chlist = nvram_safe_get("test_avbl_5g");
	if(*test_chlist) {
		strlcpy(channelList5g, test_chlist, sizeof(channelList5g));
	}
	DBG_INFO("Now avbl chlist\n2g:\n%s\n5g:\n%s\n6g:\n%s\n", channelList2g, channelList5g, channelList6g);
	DBG_ABL("Now avbl chlist\n2g:\n%s\n5g:\n%s\n6g:\n%s\n", channelList2g, channelList5g, channelList6g);

	snprintf(avblChanspecBuf, sizeof(avblChanspecBuf),
		"bw2g:%d channel2g:%s bw5g:%d channel5g:%s bw6g:%d channel6g:%s tribandRe:%d dual5gRe:%d",
		avblBandwidth[0], strlen(channelList2g) ? channelList2g : "0", avblBandwidth[1], strlen(channelList5g) ? channelList5g : "0", avblBandwidth[2],
		strlen(channelList6g) ? channelList6g : "0", tribandRe, dual5gRe);

	DBG_INFO("available chanspec(%s)", avblChanspecBuf);

	/* update avblChannel */
	avblChanspec->bw2g = avblBandwidth[0];
	avblChanspec->bw5g = avblBandwidth[1];
	avblChanspec->bw6g = avblBandwidth[2];

	DBG_INFO("avbl bw2g=%x, bw5g=%x, bw6g=%x\n", avblChanspec->bw2g, avblChanspec->bw5g, avblChanspec->bw6g);
	/* grab 2g channel list */
	if (strlen(channelList2g)) {
		i = 0;
		foreach_44 (word, channelList2g, next) {
			if (i >= MAX_2G_CHANNEL_LIST_NUM)
				continue;
			avblChanspec->channelList2g[i] = atoi(word);
			i++;
		}
	}

	/* grab 5g channel list */
	if (strlen(channelList5g)) {
		supported5gBandNum = num_of_5g_if();
		i = 0;
		foreach_44 (word, channelList5g, next) {
			if (i >= MAX_5G_CHANNEL_LIST_NUM)
				continue;

#ifdef AVBLCHAN
			/* filter band 1 and band 2 for CAP(support one 5g) + RE(support dual 5g) */
			if (supported5gBandNum == 1 && dual5gRe && atoi(word) < 100)
				continue;

			/* re-assemble channel list for 5g */
			if (firstUpdateFilter5g == 1)
				strlcat(filterChannelList5g, ",", sizeof(filterChannelList5g));
			else
				firstUpdateFilter5g = 1;
			strlcat(filterChannelList5g, word, sizeof(filterChannelList5g));
#endif

			avblChanspec->channelList5g[i] = atoi(word);
			i++;
		}
	}
#ifdef RTCONFIG_WIFI6E
	/* grab 6g channel list */
	if (strlen(channelList6g)) {
		i = 0;
		foreach_44 (word, channelList6g, next) {
			avblChanspec->channelList6g[i] = atoi(word);
			i++;
		}
	}
#endif
	/* update support tri-band */
	avblChanspec->existTribandRe = tribandRe;

	/* update support dual 5g */
	avblChanspec->existDual5gRe = dual5gRe;

#ifdef AVBLCHAN
	/* replace channel list for 5g, if needed */
	if (strlen(filterChannelList5g) && strcmp(channelList5g, filterChannelList5g) != 0) {
		memset(avblChanspecBuf, 0, sizeof(avblChanspecBuf));
		snprintf(avblChanspecBuf, sizeof(avblChanspecBuf),
			"bw2g:%d channel2g:%s bw5g:%d channel5g:%s bw6g:%d channel6g:%s tribandRe:%d dual5gRe:%d",
			avblBandwidth[0], strlen(channelList2g) ? channelList2g : "0", avblBandwidth[1], strlen(filterChannelList5g) ? filterChannelList5g : "0",
			avblBandwidth[2], strlen(channelList6g) ? channelList6g : "0", tribandRe, dual5gRe);

		DBG_INFO("after filter, available chanspec(%s)", avblChanspecBuf);
	}
#endif

	/* write to file */
	if (fileRoot) {
		json_object_to_file(CHANSPEC_AVAILABLE_LIST_JSON_PATH, fileRoot);
		if (update || firstUpdate ) {
			/* write file for sharing other process */
			if (strlen(avblChanspecBuf))
				f_write_string(CHANSPEC_AVAILABLE_LIST_TXT_PATH, avblChanspecBuf, 0, 0);
		}
	}
	json_object_put(fileRoot);

	return (firstEnter ? 0: update);
}/* End of cm_updateAvblChanspec */

/*
========================================================================
Routine Description:
	Load and parse private channel.

Arguments:
	unit			- band unit
	avblChannel		- available channel
	channelCount		- channel count
	avblBandwidth		- availabe bandwidth
	bwCount		- bandwidth count

Return Value:
	0		- succes
	-1		- error

Note:
========================================================================
*/
int cm_loadPrivateChannel(int unit, chinfo_t *avblChannel, int channelCount)
{
	json_object *fileRoot = NULL;
	json_object *channelObj = NULL, *bandObj = NULL;
	char channelData[MAX_CH_DATA_BUFLEN] = {0};
	char szChan[16];
	char *next = NULL;
	uint32_t channelStatus = 0, channelNum = 0;
	int fmtVer = 0;
	char *dataStart;
	char *band = NULL;
	char prefix[sizeof("wlXXXXX_")], tmp[64];
	int nband = 0, num5g = 0, i = 0;

	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file(CHANSPEC_PRIVATE_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("error of chanspec file");
		pthread_mutex_unlock(&chanspecLock);
		return (-1);
	}
	pthread_mutex_unlock(&chanspecLock);

	//band = unit ? (unit == 2 ? CFG_STR_5G1 : CFG_STR_5G) : CFG_STR_2G;
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
	if (nband == 2)
		band = CFG_STR_2G;
	else if (nband == 1) {
		for (i = 0; i < num_of_wl_if(); i++) {
			snprintf(prefix, sizeof(prefix), "wl%d_", i);
			if (nvram_get_int(strcat_r(prefix, "nband", tmp)) == 1) {
				num5g++;
				if (i == unit) {
					band = (num5g == 1 ? CFG_STR_5G : CFG_STR_5G1);
					break;
				}
			}
		}
	}
	else if (nband == 4)
		band = CFG_STR_6G;
	else
		band = CFG_STR_2G;

	json_object_object_get_ex(fileRoot, band, &bandObj);

	if (bandObj) {
		json_object_object_get_ex(bandObj, CFG_STR_CHANNEL, &channelObj);

		if (channelObj) {
			strlcpy(channelData, json_object_get_string(channelObj), sizeof(channelData));

			if (sscanf(channelData, "%d %*s", &fmtVer) != 1) {
				fmtVer = CHINFO_CMNFMT_V1;
				dataStart = channelData;
			}
			else
			{
				dataStart = strchr(channelData, ' ') + 1;
			}

			if (fmtVer == CHINFO_CMNFMT_V1) {
				foreach(szChan, dataStart, next) {
					if (sscanf(szChan, "%05u%03u", &channelStatus, &channelNum) == 2) {
						if(channelNum > channelCount -1)
							continue;

						if (!(channelStatus & CHINFO_BLK))
							avblChannel[channelNum] |= CHINFO_AVBL;
					}
				}
			}
		}
	}

	json_object_put(fileRoot);
	return (0);
}/* End of cm_loadPrivateChannel */

/*
========================================================================
Routine Description:
	Check channel is valid or not.

Arguments:
	unit		- band unit
	channel		- channel that need to check

Return Value:
	0		- invalid channel
	1		- valid channel
	-1		- error

Note:
========================================================================
*/
int cm_isValidChannel(int unit, int channel)
{
	chinfo_t avblChannel[MAX_CH_NUM] = {0};
	int ret = 0;

	if (cm_loadPrivateChannel(unit, avblChannel, MAX_CH_NUM) == -1)
		return -1;

	if (avblChannel[channel])
		ret = 1;

	return ret;
}/* End of cm_isValidChannel */

/*
========================================================================
Routine Description:
	Delete private chanspec file to reset chanspec.

Arguments:
	None

Return Value:
	None

Note:
========================================================================
*/
void cm_resetChanspec()
{
	unlink(CHANSPEC_PRIVATE_LIST_JSON_PATH);
}/* End of cm_resetChansepc */

/*
========================================================================
Routine Description:
	Check RE bandwidth capability.

Arguments:
	unit		- unit
	bwCap		- CAP's current bandwidth
	nctrlsbCap	- CAP's current control side band
	bwRe		- RE's current bandwidth
	nctrlsbRe	- RE's current control side band

Return Value:
	0		- no changed
	1		- changed

Note:
========================================================================
*/
int cm_checkBwCapability(int unit, int *bwCap, int *nctrlsbCap, int *bwRe, int *nctrlsbRe)
{
	int bwCapability = 0;
	int bwIndexCap = 0;

	if (wl_get_bw_cap(
#if defined(RTCONFIG_LYRA_5G_SWAP)
		swap_5g_band(unit)
#else
		unit
#endif
		, &bwCapability) < 0)
	{
		DBG_ERR("get bw cap failed");
		return 0;
	}

	if (*bwCap == 20) bwIndexCap = 0x01;
	else if (*bwCap == 40) bwIndexCap = 0x02;
	else if (*bwCap == 80) bwIndexCap = 0x04;
	else if (*bwCap == 160) bwIndexCap = 0x08;
	else {
		DBG_ERR("wrong bw on CAP");
		return 0;
	}

	if (bwCapability & bwIndexCap) {
		DBG_INFO("support bw capability (%02X) on RE", bwIndexCap);
		return 0;
	}
	else
	{
		DBG_INFO("doesn't support bw capability (%02X) on RE", bwIndexCap);
		*bwCap = *bwRe;
		*nctrlsbCap = *nctrlsbRe;
	}

	return 1;
}/* End of cm_checkBwCapability */

/*
========================================================================
Routine Description:
	Check bandwidth support or not.

Arguments:
	unit		- unit
	bw		- current bandwidth

Return Value:
	0		- no support
	1		- support
	-1		- error

Note:
========================================================================
*/
int cm_isBwSupported(int unit, int bw)
{
	int bwCapability = 0, bwIndexCap = 0;

	if (wl_get_bw_cap(
#if defined(RTCONFIG_LYRA_5G_SWAP)
		swap_5g_band(unit)
#else
		unit
#endif
		, &bwCapability) < 0)
	{
		DBG_ERR("get bw cap failed");
		return -1;
	}

	if (bw == 20) bwIndexCap = 0x01;
	else if (bw == 40) bwIndexCap = 0x02;
	else if (bw == 80) bwIndexCap = 0x04;
	else if (bw == 160) bwIndexCap = 0x08;
	else {
		DBG_ERR("wrong bw");
		return -1;
	}

	if (bwCapability & bwIndexCap) {
		DBG_INFO("support bw capability (%02X, %d)", bwIndexCap, bw);
		return 1;
	}
	else
	{
		DBG_INFO("doesn't support bw capability (%02X, %d)", bwIndexCap, bw);
	}

	return 0;
}/* End of cm_isBwSupported */

/*
========================================================================
Routine Description:
	Filter 5G channel by bandwidth.

Arguments:
	unit		- band unit
	bw		- bandwidth
	avblCh		- available channel

Return Value:
	0		- not filter
	1		- filter
	-1		- error

Note:
========================================================================
*/
int cm_filter5gChannelByBw(int unit, int bw, chinfo_t *avblCh)
{
	int i = 0, j = 0, d = 0, nrCh = 0, del = 0;
	int cnt[14] = {0}, ch[14] = {0};
	int arySize = 0;

	if (bw == 160) {
		d = 28;
		nrCh = 8;
		ch[0] = 36; ch[1] = 100; ch[2] = 149;
		arySize = 3;
	}
	else if (bw == 80) {
		d = 12;
		nrCh = 4;
		ch[0] = 36; ch[1] = 52; ch[2] = 100; ch[3] = 116; ch[4] = 132; ch[5] = 149; ch[6] = 165;
		arySize = 7;
	}
	else if (bw == 40) {
		d = 4;
		nrCh = 2;
		ch[0] = 36; ch[1] = 44; ch[2] = 52; ch[3] = 60; ch[4] = 100; ch[5] = 108; ch[6] = 116; ch[7] = 124; ch[8] = 132; ch[9] = 140; ch[10] = 149; ch[11] = 157; ch[12] = 165; ch[13] = 173;
		arySize = 14;
	}

	if (cm_loadPrivateChannel(unit, avblCh, MAX_CH_NUM) == -1)
		return -1;

	if (nvram_get_int("cfg_bw_validate_dbg")) {
		DBG_INFO("before avblCh");
		for (i = 0; i < MAX_CH_NUM; i++) {
			if (avblCh[i] == 0)
				continue;

			DBG_INFO("avblCh[%d]=%02X", i, avblCh[i]);
		}
	}

	for (i = 0; i < MAX_CH_NUM; i++) {
		if (avblCh[i] == 0)
			continue;

		for (j = 0; j < arySize; j++) {
			if ((i - ch[j]) >= 0 && (i - ch[j]) <= d)
				cnt[j]++;
		}
	}

	for (i = 0; i < MAX_CH_NUM; i++) {
		if (avblCh[i] == 0)
			continue;
		del = 1;

		for (j = 0; j < arySize; j++) {
			if ((i - ch[j]) >= 0 && (i - ch[j]) <= d && cnt[j] == nrCh)
				del = 0;
		}

		if (del)
			avblCh[i] = 0;
	}

	if (nvram_get_int("cfg_bw_validate_dbg")) {
		DBG_INFO("after avblCh");
		for (i = 0; i < MAX_CH_NUM; i++) {
			if (avblCh[i] == 0)
				continue;

			DBG_INFO("avblCh[%d]=%02X", i, avblCh[i]);
		}
	}

	return 1;
}/* End of cm_filter5gChannelByBw */

/*
========================================================================
Routine Description:
	Filter 6 channel by bandwidth.

Arguments:
	unit		- band unit
	bw		- bandwidth
	avblCh		- available channel

Return Value:
	0		- not filter
	1		- filter
	-1		- error

Note:
========================================================================
*/
int cm_filter6gChannelByBw(int unit, int bw, chinfo_t *avblCh)
{
	int i = 0, j = 0, d = 0, nrCh = 0, del = 0;
	int cnt[29] = {0}, ch[29] = {0};
	int arySize = 0;

	if (bw == 160) {
		d = 28;
		nrCh = 8;
		ch[0] = 1; ch[1] = 33; ch[2] = 65; ch[3] = 97; ch[4] = 129;
		ch[5] = 161; ch[6] = 193;
		arySize = 7;
	}
	else if (bw == 80) {
		d = 12;
		nrCh = 4;
		ch[0] = 1; ch[1] = 17; ch[2] = 33; ch[3] = 49; ch[4] =65;
		ch[5] = 81; ch[6] = 97; ch[7] = 113; ch[8] = 129; ch[9] = 145;
		ch[10] = 161; ch[11] = 177; ch[12] = 193; ch[13] = 209; ch[14] = 225;
		arySize = 15;
	}
	else if (bw == 40) {
		d = 4;
		nrCh = 2;
		ch[0] = 1; ch[1] = 9, ch[2] = 17; ch[3] = 25; ch[4] = 33;
		ch[5] = 41; ch[6] = 49; ch[7] = 57; ch[8] =65; ch[9] = 73;
		ch[10] = 81; ch[11] = 89; ch[12] = 97; ch[13] = 105; ch[14] = 113;
		ch[15] = 121; ch[16] = 129; ch[17] = 137; ch[18] = 145; ch[19] = 153;
		ch[20] = 161; ch[21] = 169; ch[22] = 177; ch[23] = 185; ch[24] = 193;
		ch[25] = 201; ch[26] = 209; ch[27] = 217; ch[28] = 225;
		arySize = 29;
	}

	if (cm_loadPrivateChannel(unit, avblCh, MAX_CH_NUM) == -1)
		return -1;

	if (nvram_get_int("cfg_bw_validate_dbg")) {
		DBG_INFO("before avblCh");
		for (i = 0; i < MAX_CH_NUM; i++) {
			if (avblCh[i] == 0)
				continue;

			DBG_INFO("avblCh[%d]=%02X", i, avblCh[i]);
		}
	}

	for (i = 0; i < MAX_CH_NUM; i++) {
		if (avblCh[i] == 0)
			continue;

		for (j = 0; j < arySize; j++) {
			if ((i - ch[j]) >= 0 && (i - ch[j]) <= d)
				cnt[j]++;
		}
	}

	for (i = 0; i < MAX_CH_NUM; i++) {
		if (avblCh[i] == 0)
			continue;
		del = 1;

		for (j = 0; j < arySize; j++) {
			if ((i - ch[j]) >= 0 && (i - ch[j]) <= d && cnt[j] == nrCh)
				del = 0;
		}

		if (del)
			avblCh[i] = 0;
	}

	if (nvram_get_int("cfg_bw_validate_dbg")) {
		DBG_INFO("after avblCh");
		for (i = 0; i < MAX_CH_NUM; i++) {
			if (avblCh[i] == 0)
				continue;

			DBG_INFO("avblCh[%d]=%02X", i, avblCh[i]);
		}
	}

	return 1;
}/* End of cm_filter6gChannelByBw */

/*
========================================================================
Routine Description:
	Check bandwidth and control side band are valid or not.

Arguments:
	unit		- band unit
	channel		- channel
	bw		- bandwidth
	nctrlsb	- control side band
	checkBwCap		- check bw capability

Return Value:
	0		- invalid
	1		- valid
	-1		- error

Note:
========================================================================
*/
int cm_isValidBwNctrlsb(int unit, int channel, int bw, int nctrlsb, int checkBwCap)
{
	chinfo_t avblCh[MAX_CH_NUM] = {0};
	int ret = 0, total2gChannel = 0, nctrlsbCurrent = 0, nctrlsbValid = 0, bwRet = 0;
	char prefix[sizeof("wlXXXXX_")], tmp[64];
	int nband = 0;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	nband = nvram_get_int(strcat_r(prefix, "nband", tmp));

	/* bandwidth is 20Mhz */
	if (bw == 20)
		return 1;

	/* check bw capability */
	if (checkBwCap == 1 && (bwRet = cm_isBwSupported(unit, bw)) <= 0)
		return bwRet;

	/* bandwidth is 40Mhz */
	if (bw == 40) {
		if (nctrlsb == 1)
			nctrlsbCurrent = CTRLSB_UPPER;
		else
			nctrlsbCurrent = CTRLSB_LOWER;

		if (nband == 2) {	/* for 2G */
			if (cm_loadPrivateChannel(unit, avblCh, MAX_CH_NUM) == -1)
				return -1;

			if (avblCh[13])	total2gChannel = 13;
			else if (avblCh[11])	total2gChannel = 11;
			else
			{
				DBG_ERR("invalid total channel for 2G");
				return -1;
			}

			/*
				For ch1~ch11
				ch1~ch4 "l", ch5~ch7 "l,u", ch8~ch11 "u"
				For ch1~ch13
				ch1~ch4 "l", ch5~ch9 "l,u", ch10~ch13 "u"
			*/
			if (channel >= 1 && channel <= 4)
				nctrlsbValid = CTRLSB_LOWER;
			else if (channel >= 5 && channel <= (total2gChannel - 4))
				nctrlsbValid = CTRLSB_LOWER | CTRLSB_UPPER;
			else  if (channel >= (total2gChannel -3) && channel <= total2gChannel)
				nctrlsbValid = CTRLSB_UPPER;
			else
			{
				DBG_ERR("invalid channel (%d) for 2G", channel);
				return -1;
			}
		}
		else	 if (nband == 1)	/* for 5G */
		{
			if (cm_filter5gChannelByBw(unit, bw, avblCh) == 1) {
				if (avblCh[channel]) {
					if (channel > 144) {
						if (((channel - 1) % 8) == 0)
							nctrlsbValid = CTRLSB_UPPER;
						else
							nctrlsbValid = CTRLSB_LOWER;
					}
					else
					{
						if ((channel % 8) == 0)
							nctrlsbValid = CTRLSB_UPPER;
						else
							nctrlsbValid = CTRLSB_LOWER;
					}
				}
			}
			else
			{
				DBG_ERR("error for filtering 5G channel");
				return -1;
			}
		}
		else if (nband == 4)	/* for 6G */
		{
			if (cm_filter6gChannelByBw(unit, bw, avblCh) == 1) {
				if (avblCh[channel])
					ret = 1;
			}
			else
			{
				DBG_ERR("error for filtering 6G channel");
				return -1;
			}
		}

		/* check control side band valid or not */
		if (nctrlsbValid) {
			if (nctrlsbValid & nctrlsbCurrent) {
				ret = 1;
			}
		}
	}

	/* bandwidth is 80Mhz or 160Mhz */
	if (bw == 80 || bw == 160) {
		if (nband == 1) {
			if (cm_filter5gChannelByBw(unit, bw, avblCh) == 1) {
				if (avblCh[channel])
					ret = 1;
			}
		}
		else if (nband == 4) {
			if (cm_filter6gChannelByBw(unit, bw, avblCh) == 1) {
				if (avblCh[channel])
					ret = 1;
			}
		}
	}

	return ret;
}/* End of cm_isValidBwNctrlsb */

/*
========================================================================
Routine Description:
	Find suitable bandwidth and control side band based on channel.

Arguments:
	unit		- band unit
	channel		- channel
	bw		- bandwidth
	nctrlsb	- control side band

Return Value:
	0		- not found
	1		- find
	-1		- error

Note:
========================================================================
*/
int cm_findSuitableBwNctrlsb(int unit, int channel, int *bw, int *nctrlsb)
{
	int bwCapability = 0, ret = 0;

	if (wl_get_bw_cap(
#if defined(RTCONFIG_LYRA_5G_SWAP)
		swap_5g_band(unit)
#else
		unit
#endif
		, &bwCapability) < 0)
	{
		DBG_ERR("get bw cap failed");
		return -1;
	}

	/* check bw 160Mhz */
	if (ret == 0 && bwCapability & 0x08) {	//bw 160
		if (cm_isValidBwNctrlsb(unit, channel, 160, 0, 0)) {
			*bw = 160;
			ret = 1;
		}
	}

	/* check bw 80Mhz */
	if (ret == 0 && bwCapability & 0x04) {
		if (cm_isValidBwNctrlsb(unit, channel, 80, 0, 0)) {
			*bw = 80;
			ret = 1;
		}
	}

	/* check bw 40Mhz */
	if (ret == 0 && bwCapability & 0x02) {
		/* check side band is lower */
		if (cm_isValidBwNctrlsb(unit, channel, 40, 0, 0)) {
			*bw = 40;
			*nctrlsb = 0;
			ret = 1;
		}

		/* check side band is upper */
		if (ret == 0 && cm_isValidBwNctrlsb(unit, channel, 40, 1, 0)) {
			*bw = 40;
			*nctrlsb = 1;
			ret = 1;
		}
	}

	/* check bw 40Mhz */
	if (ret == 0 && bwCapability & 0x01) {
		if (cm_isValidBwNctrlsb(unit, channel, 20, 0, 0)) {
			*bw = 20;
			ret = 1;
		}
	}

	return ret;
}/* End of cm_findSuitableBwNctrlsb */

/*
========================================================================
Routine Description:
	Get band type mapping by mac.

Arguments:
	mac		- mac
	isCap		- cap or not
	indexBandObj		- object for return index band

Return Value:
	0		- no info
	1		- have info

Note:
========================================================================
*/
int cm_getBandTypeMappingByMac(char *mac, int isCap, json_object *indexBandObj)
{
	json_object *fileRoot = NULL, *macObj = NULL;
	int ret = 0, i = 0;

	if (!indexBandObj) {
		DBG_ERR("indexBandObj is NULL");
		return 0;
	}

	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return 0;
	}

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		json_object_object_foreach(macObj, key, val) {
			if (strcmp(key, CFG_STR_BANDNUM) == 0
				|| strcmp(key, CFG_STR_IS_RE) == 0)
				continue;
			if (!isCap || (isCap &&  check_radio_status_by_unit(i)))
				json_object_object_add(indexBandObj, key, json_object_new_int(i));
			i++;
			ret = 1;
		}
	}

	DBG_INFO("mac (%s), isCap (%d)", mac, isCap);
	json_object_object_foreach(indexBandObj, indexBandKey, indexBandVal)
		DBG_INFO("band type (%s), band index (%d)", indexBandKey, json_object_get_int(indexBandVal));

	json_object_put(fileRoot);
	pthread_mutex_unlock(&chanspecLock);

	return ret;
} /* End of cm_getBandTypeMappingByMac */

/*
========================================================================
Routine Description:
	Get band type Support.

Arguments:

Return Value:
	band type support

Note:
========================================================================
*/
int cm_getBandTypeSupport()
{
	json_object *fileRoot = NULL, *bandObj = NULL;
	int bandsupport = 0;
	pthread_mutex_lock(&chanspecLock);

	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return bandsupport;
	}

	json_object_object_foreach(fileRoot, key, val) {
		bandObj = val;

		json_object_object_foreach(bandObj, key, val) {
			if(strcmp(key, CFG_STR_2G) == 0)
				bandsupport |= WL_2G;
			else if(strcmp(key, CFG_STR_5G) == 0)
				bandsupport |= WL_5G;
			else if(strcmp(key, CFG_STR_5G1) == 0)
				bandsupport |= WL_5G_1;
			else if(strcmp(key, CFG_STR_6G) == 0)
				bandsupport |= WL_6G;
		}
	}

	json_object_put(fileRoot);
	pthread_mutex_unlock(&chanspecLock);
	DBG_INFO("band support (%d)", bandsupport);

	return bandsupport;
} /* End of cm_getBandTypeSupport */

/*
========================================================================
Routine Description:
	Get channel range by band type.

Arguments:
	mac		- mac
	band		- band type
	startChannel		- start channel
	endChannel		- end channel

Return Value:
	None

Note:
========================================================================
*/
void cm_getChannelRangeByBandType(char *mac, char *band, int *startChannel, int *endChannel)
{
	json_object *fileRoot = NULL, *macObj = NULL, *bandObj = NULL, *channelObj = NULL;
	char channelData[MAX_CH_DATA_BUFLEN] = {0}, *dataStart, szChan[16], *next = NULL;
	int fmtVer = 0, i = 0;
	uint32_t channelStatus = 0, channelNum = 0;

	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		return;
	}

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		json_object_object_get_ex(macObj, band, &bandObj);
		if (bandObj) {
			json_object_object_get_ex(bandObj, CFG_STR_CHANNEL, &channelObj);

			if (channelObj) {
				strlcpy(channelData, json_object_get_string(channelObj), sizeof(channelData));

				if (sscanf(channelData, "%d %*s", &fmtVer) != 1) {
					fmtVer = CHINFO_CMNFMT_V1;
					dataStart = channelData;
				}
				else
				{
					dataStart = strchr(channelData, ' ') + 1;
				}

				if (fmtVer == CHINFO_CMNFMT_V1) {
					foreach(szChan, dataStart, next) {
						if (sscanf(szChan, "%05u%03u", &channelStatus, &channelNum) == 2) {
							if (i == 0)
								*startChannel = channelNum;
							else
								*endChannel = channelNum;

							i++;
						}
					}
				}
			}
		}
		else
			DBG_INFO("bandObj is NULL");
	}
	else
		DBG_INFO("macObj is NULL");

	DBG_INFO("startChannel (%d), endChannel (%d)", *startChannel, *endChannel);

	json_object_put(fileRoot);
} /* End of cm_getChannelRangeByBandType */

/*
========================================================================
Routine Description:
	Get multiple band list by mac.

Arguments:
	mac		- mac
	isCap		- cap or not
	indexBandObj		- object for index band
	multipleBandList		- object for return multiple band list

Return Value:
	0		- fail
	1		- success

Note:
========================================================================
*/
int cm_getMultipleBandListByMac(char *mac, int isCap, json_object *indexBandObj, json_object *multiBandList)
{
	json_object *tempIndexBandObj = NULL, *bandObj = NULL;
	int multiBandNum = 0;
	char bandIndex[8], bandType[8];

	if (!indexBandObj) {
		DBG_ERR("indexBandObj is NULL");
		return 0;
	}

	if (!multiBandList) {
		DBG_ERR("multiBandList is NULL");
		return 0;
	}

	tempIndexBandObj = indexBandObj;

	json_object_object_foreach(indexBandObj, key, val) {
		if (sscanf(key, "%[^G]", bandIndex) == 1) {
			multiBandNum = 0;
			snprintf(bandType, sizeof(bandType), "%sG", bandIndex);
			json_object_object_foreach(tempIndexBandObj, tempKey, tempVal) {
				if (strncmp(bandType, tempKey, strlen(bandType)) == 0) {
					if (!isCap || (isCap && check_radio_status_by_unit(json_object_get_int(tempVal))))
						multiBandNum++;
				}
			}

			if (multiBandNum > 1) {
				json_object_object_get_ex(multiBandList, bandType, &bandObj);
				if (!bandObj) {
					DBG_INFO("%s (%d) is multi band, add it to multiBandList", bandType, multiBandNum);
					json_object_object_add(multiBandList, bandType, json_object_new_int(json_object_get_int(val)));
				}
			}
		}
	}

	DBG_INFO("mac (%s), isCap (%d)", mac, isCap);
	json_object_object_foreach(multiBandList, multiBandKey, multiBandVal)
		DBG_INFO("multi band type (%s)", multiBandKey);

	return 1;
} /* End of cm_getMultipleBandListByMac */

/*
========================================================================
Routine Description:
	Get badnd type by channel of RE.

Arguments:
	mac		- re mac
	channel		- channel

Return Value:
	band type

Note:
========================================================================
*/
char *cm_getBandTypeByChannel(char *mac, int channel)
{
	json_object *fileRoot = NULL, *macObj = NULL;
	static char bandType[8];
	int startChannel = 0, endChannel = 0;

	memset(bandType, 0, sizeof(bandType));

	if (!mac || strlen(mac) ==0) {
		DBG_ERR("macis NULL");
		return bandType;
	}

	pthread_mutex_lock(&chanspecLock);
	fileRoot = json_object_from_file(CHANSPEC_LIST_JSON_PATH);
	if (!fileRoot) {
		DBG_ERR("fileRoot is NULL");
		pthread_mutex_unlock(&chanspecLock);
		return bandType;
	}

	pthread_mutex_unlock(&chanspecLock);

	json_object_object_get_ex(fileRoot, mac, &macObj);
	if (macObj) {
		json_object_object_foreach(macObj, bandKey, bandVal) {
			if (strcmp(bandKey, CFG_STR_BANDNUM) == 0
				|| strcmp(bandKey, CFG_STR_IS_RE) == 0)
				continue;

			startChannel = 0;
			endChannel = 0;
			cm_getChannelRangeByBandType(mac, bandKey, &startChannel, &endChannel);
			if (startChannel > 0 && endChannel > 0) {
				if (startChannel <= channel && channel <= endChannel) {
					strlcpy(bandType, bandKey, sizeof(bandType));
				}
			}
		}
	}

	json_object_put(fileRoot);

	return bandType;
} /* End of cm_getBandTypeByChannel */

/*
========================================================================
Routine Description:
	Find suitable band type.

Arguments:
	allBandObj		- channel info of all band
	bandKey		-band key

Return Value:
	band type

========================================================================
*/
char *cm_findSuitableBandType(json_object *allBandObj, char *bandKey)
{
	static char bandType[8];
	char bandIndex[8], tempBandType[8], bandUnit[8];
	int maxUnit = 0;

	memset(bandType, 0, sizeof(bandType));
	if (sscanf(bandKey, "%[^G]", bandIndex) != 1) {
		DBG_ERR("can't get band index from band key (%s)", bandKey);
		return bandType;
	}

	snprintf(tempBandType, sizeof(tempBandType), "%sG", bandIndex);
	json_object_object_foreach(allBandObj, allBandKey, allBandVal) {
		if (strstr(allBandKey, tempBandType) && strstr(allBandKey, "channel")) {
			if (sscanf(allBandKey, "%*[^G]G%[^_]_%*s", bandUnit) == 1) {
				if (atoi(bandUnit) > maxUnit)
					maxUnit = atoi(bandUnit);
			}
		}
	}

	if (maxUnit > 0)
		snprintf(bandType, sizeof(bandType), "%sG%d", bandIndex, maxUnit);
	else
		snprintf(bandType, sizeof(bandType), "%sG", bandIndex);

	DBG_INFO("suitable band type (%s)", bandType);

	return bandType;
} /* End of cm_findSuitableBandType */
