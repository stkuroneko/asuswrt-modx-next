#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_string.h"
#include "cfg_bandindex.h"
#include "chmgmt.h"
#include "cfg_chanspec.h"

/*
========================================================================
Routine Description:
	Add band index type

Arguments:
	BAND_TYPE            - the json_object of BAND_TYPE
	SUBFT_BASIC_BAND%d   - unit and  corresponding type    0:2G  1:5G 2:5GL 3:5GH 4:6G
Return Value:
	None

========================================================================
*/
void cm_addBandIndex(json_object *outRoot)
{
	long bandTypeVal = 0;
	if(nvram_get_int("band_type")==0){
		bandTypeVal |= HAVE_WIFI_2G;
	}
	else if(nvram_get_int("band_type")==1){
		bandTypeVal |= HAVE_WIFI_2G;
		bandTypeVal |= HAVE_WIFI_5G;
	}
	else if(nvram_get_int("band_type")==2){
		bandTypeVal |= HAVE_WIFI_2G;
		bandTypeVal |= HAVE_WIFI_5GL;
		bandTypeVal |= HAVE_WIFI_5GH;
	}
	else if(nvram_get_int("band_type")==3){
		bandTypeVal |= HAVE_WIFI_2G;
		bandTypeVal |= HAVE_WIFI_5G;
		bandTypeVal |= HAVE_WIFI_6G;
	}
	else if(nvram_get_int("band_type")==4){
		bandTypeVal |= HAVE_WIFI_2G;
		bandTypeVal |= HAVE_WIFI_5GL;
		bandTypeVal |= HAVE_WIFI_5GH;
		bandTypeVal |= HAVE_WIFI_6G;
	}

	json_object_object_add(outRoot, CFG_BAND_TYPE, json_object_new_int64(bandTypeVal));

	char SUBFT_BASIC_BAND_NAME[24]={0};
	chmgmt_chconf_t cur_chconf;
	char word[64], *next = NULL, tmp[64], wl_ifnames[64], wl_prefix[sizeof("wlXXXX_")];
	int unit = 0, num5g = num_of_5g_if(), nband = 0;
	/* find 5g/5g high unit   :  SUBFT_BASIC_BAND_%d value --> 2G:0  5G:1  5GL:2  5GH:3 6G:4*/
	strlcpy(wl_ifnames, nvram_safe_get("wl_ifnames"), sizeof(wl_ifnames));
	foreach (word, wl_ifnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		snprintf(wl_prefix, sizeof(wl_prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(wl_prefix, "nband", tmp));
		memset(SUBFT_BASIC_BAND_NAME, 0, sizeof(SUBFT_BASIC_BAND_NAME));
		snprintf(SUBFT_BASIC_BAND_NAME,sizeof(SUBFT_BASIC_BAND_NAME),"%s%d","SUBFT_BASIC_BAND_",unit);
		if(nband == 2){
			json_object_object_add(outRoot, SUBFT_BASIC_BAND_NAME, json_object_new_int(0));
		}
		else if (nband == 1 ) {	/* for 5g band */
			if (num5g == 1) {	/* one 5g band */
				json_object_object_add(outRoot, SUBFT_BASIC_BAND_NAME, json_object_new_int(1));
			}
			else if (wl_get_chconf(word, &cur_chconf) == 0) {	/* for more 5g band, get channel to check */
				DBG_INFO("current channel (%d)", CHCONF_CH(cur_chconf));
				if (CHCONF_CH(cur_chconf) >= THRESHOLD_5G_LOW_HIGH) {	/* check 5g high band */
					json_object_object_add(outRoot, SUBFT_BASIC_BAND_NAME, json_object_new_int(3));
				}
				else{
					json_object_object_add(outRoot, SUBFT_BASIC_BAND_NAME, json_object_new_int(2));
				}
			}
		}
		else if(nband == 4){
			json_object_object_add(outRoot, SUBFT_BASIC_BAND_NAME, json_object_new_int(4));
		}

		unit++;
	}
	
	
} /* End of cm_addBandindex */

/*
========================================================================
Routine Description:
	Update band info file by mac.

Arguments:
	mac		- mac
	chanspecObj		- channel info
Return Value:
	None

========================================================================
*/
void cm_updateBandInfoByMac(char *mac, json_object *chanspecObj)
{
	char filePath[64], bandAttrIndex[8];
	int unit = 0, update = 0, num5g = 0;
	int startChannel = 0, endChannel = 0;
	json_object *bandInfoObj = NULL, *unitObj = NULL;

	if (!mac || strlen(mac) == 0) {
		DBG_ERR("mac is NULL or length is 0");
		return;
	}

	if (!chanspecObj) {
		DBG_ERR("chanspecObj is NULL");
		return;
	}

	snprintf(filePath, sizeof(filePath), "%s/%s.bi", TEMP_ROOT_PATH, mac);
	if (f_exists(filePath)) {
		DBG_INFO("band info file (%s) exists, don't update it", filePath);
		return;
	}

	/* count 5g number */
	json_object_object_foreach(chanspecObj, key, val) {
		if (strncmp(key, CFG_STR_5G, strlen(CFG_STR_5G)) == 0)
			num5g++;
	}

	/* determine unit for all band */
	if ((bandInfoObj = json_object_new_object())) {
		json_object_object_foreach(chanspecObj, key, val) {
			if ((unitObj = json_object_new_object())) {
				memset(bandAttrIndex, 0, sizeof(bandAttrIndex));

				if (strcmp(key, CFG_STR_2G) == 0) {
					snprintf(bandAttrIndex, sizeof(bandAttrIndex), "%d", BAND_ATTR_2G);
				}
				else if (strncmp(key, CFG_STR_5G, strlen(CFG_STR_5G)) == 0) {
					if (num5g == 1) {
						snprintf(bandAttrIndex, sizeof(bandAttrIndex), "%d", BAND_ATTR_5G);
					}
					else if (num5g > 1) {
						startChannel = 0;
						endChannel = 0;
						cm_getChannelRangeByBandType(mac, key, &startChannel, &endChannel);
						if (endChannel > 0) {
							if (endChannel < THRESHOLD_5G_LOW_HIGH)
								snprintf(bandAttrIndex, sizeof(bandAttrIndex), "%d", BAND_ATTR_5GL);
							else
								snprintf(bandAttrIndex, sizeof(bandAttrIndex), "%d", BAND_ATTR_5GH);
						}
					}
				}
				else if (strcmp(key, CFG_STR_6G) == 0)
					snprintf(bandAttrIndex, sizeof(bandAttrIndex), "%d", BAND_ATTR_6G);

				if (strlen(bandAttrIndex)) {
					json_object_object_add(unitObj, CFG_STR_UNIT, json_object_new_int(unit));
					json_object_object_add(bandInfoObj, bandAttrIndex, unitObj);
					update = 1;
				}
			}
			unit++;
		}
	}

	if (update)
		json_object_to_file(filePath, bandInfoObj);

	json_object_put(bandInfoObj);
} /* End of cm_updateBandInfoByMac */
