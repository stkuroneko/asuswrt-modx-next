#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <shared.h>
#include <shutils.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_capability.h"
#include <amas_path.h>


struct wifi_auth_mapping_s {
	int index;
	char *name;
};

static struct wifi_auth_mapping_s wifi_auth_mapping_list[] = {
	{ OPEN_SYSTEM,				"open" },
	{ SHARED_KEY,				"shaed" },
	{ WPA_PERSONAL,				"psk" },
	{ WPA2_PERSONAL,			"psk2" },
	{ WPA3_PERSONAL,			"sae" },
	{ WPA_WPA2_PERSONAL,		"pskpsk2" },
	{ WPA2_WPA3_PERSONAL,		"psk2sae" },
	{ WPA_ENTERPRISE,			"wpa" },
	{ WPA2_ENTERPRISE,			"wpa2" },
	{ WPA3_ENTERPRISE,			"wpa3" },
	{ WPA_WPA2_ENTERPRISE,		"wpawpa2" },
	{ WPA2_WPA3_ENTERPRISE,		"wpa2wpa3" },
	{ RADIUS_WITH_8021X,		"radius" },
	{ OWE,						"owe" },
	{ 0, 		NULL }
};

#ifdef RTCONFIG_BHCOST_OPT
/**
 * @brief Added uplink type capablity.
 *
 * @param capablityObj Capablity obj.
 */
void cm_addUplinkType(json_object *capablityObj) {
    char typeStr[4] = {}, word[32] = {}, buf[32] = {}, *next = NULL;
    int ethType[16] = {};
    char ifname[16][8] = {}, wifi_val[8][16] = {}, ethernet_val[16][16] = {};
    int i, j, index, count = 0;
    json_object *uplinkObj = NULL;
    json_object *portObj = NULL;
    int describe_tmp;

    if (capablityObj == NULL) {
        DBG_ERR("capablityObj is NULL");
        return;
    }
    uplinkObj = json_object_new_object();
    portObj = json_object_new_object();
    if (uplinkObj == NULL || portObj == NULL) {
        DBG_ERR("uplinkObj or portObj is NULL");
        return;
    }

    // Ethernet
    i = 0;
    foreach (word, nvram_safe_get("amas_ethif_type"), next) {
        index = 1;
        for (j = 0; ethType[j] > 0; j++) {
            if (ethType[j] == atoi(word))
                index++;
        }
        ethType[j] = atoi(word);
        switch (ethType[j]) {
            case ETH_TYPE_NONE:
            case ETH_TYPE_10:
            case ETH_TYPE_100:
            case ETH_TYPE_1000:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_ETH1G, index);
                break;
            case ETH_TYPE_25G:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_ETH25G, index);
                break;
            case ETH_TYPE_5G:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_ETH5G, index);
                break;
            case ETH_TYPE_10G:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_ETH10G, index);
                break;
            case ETH_TYPE_10GPLUS:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_ETH10GPLUS, index);
                break;
            case ETH_TYPE_PLC:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_PLC, index);
                break;
            default:
                snprintf(ethernet_val[i], sizeof(ethernet_val[i]), "%d%d", CONN_PRI_ETH1G, index);
                break;
        }
        i++;
    }

    i = 0;
    foreach (word, nvram_safe_get("eth_ifnames"), next) {
        snprintf(ifname[i], sizeof(ifname[i]), "%s", word);
        i++;
    }

    // Wireless
    char *band_priority = strdup(nvram_safe_get("sta_priority"));
    if (band_priority && strlen(band_priority) > 0) {
        int chkval = cal_space(band_priority);
        int band_count[3] = {};  // [0]: 2.4G, [1]: 5G, [2]: 6G
        div_t chkval2 = div(chkval, 4);

        if (chkval2.rem == 0 && chkval2.quot != 0) {
            struct _wifi_ifinfo {
                int band;       // 2:2.4G,5:5G
                int bandIndex;  // 0,1,2...
                int priority;   // 1,2,3...
                int use;        // 0:stop connection. 1: try to connect to P-AP
            } *wifi = (struct _wifi_ifinfo *)malloc(chkval2.quot * sizeof(struct _wifi_ifinfo));

            if (wifi != NULL) {
                memset(wifi, 0x00, chkval2.quot * sizeof(struct _wifi_ifinfo));
                int w_index = 0;
                int offset = 0;
                char *band_priority_tmp = band_priority;
                while (sscanf(band_priority_tmp, " %d%d%d%d%n", &wifi[w_index].band, &wifi[w_index].bandIndex, &wifi[w_index].priority, &wifi[w_index].use, &offset) == 4) {
                    describe_tmp = 0;
                    if (wifi[w_index].band == 2) {  // 2.4G
                        if (nvram_get_int("conn_pri_24G_supp") == 1) {
                            describe_tmp = gen_uplinkport_describe("NONE", "WIFI", "2.4G", band_count[0]);
                            snprintf(wifi_val[w_index], sizeof(wifi_val[w_index]), "%d", CONN_PRI_WIFI_2G);
                        }
                        band_count[0]++;
                    } else if (wifi[w_index].band == 5 || wifi[w_index].band == 51 || wifi[w_index].band == 52) {  // 5G. 51/52 for old version.						
                        describe_tmp = gen_uplinkport_describe("NONE", "WIFI", "5G", band_count[1]);
                        if (band_count[1] == 0)
                            snprintf(wifi_val[w_index], sizeof(wifi_val[w_index]), "%d", CONN_PRI_WIFI_5G);
                        else
                            snprintf(wifi_val[w_index], sizeof(wifi_val[w_index]), "%d", CONN_PRI_WIFI_5G2);
                        band_count[1]++;
                    } else if (wifi[w_index].band == 6) {  // 6G
                        describe_tmp = gen_uplinkport_describe("NONE", "WIFI", "6G", band_count[2]);
                        snprintf(wifi_val[w_index], sizeof(wifi_val[w_index]), "%d", CONN_PRI_WIFI_6G);
                        band_count[2]++;
                    } else {
                        snprintf(wifi_val[w_index], sizeof(wifi_val[w_index]), "%d", CONN_PRI_AUTO);
                        describe_tmp = gen_uplinkport_describe("NONE", "WIFI", "NONE", NULL);
                    }
                    if (describe_tmp && wifi[w_index].use == 1) {  // Only for use band.
                        snprintf(buf, sizeof(buf), "%x", describe_tmp);
                        json_object_object_add(portObj, buf, json_object_new_string(wifi_val[w_index]));
                        count++;
                    }
                    band_priority_tmp += offset;
                    if (w_index < chkval2.quot)
                        w_index++;
                }
                free(wifi);
            }
        }
        free(band_priority);
    }

    /* Added Version */
    json_object_object_add(uplinkObj, "Ver", json_object_new_int(1));

    if (strlen(ifname[0]) == 0 || strlen(ethernet_val[0]) == 0) {  // No uplink port RE
    } else {
        for (i = 0; strlen(ifname[i]) != 0; i++) {
            describe_tmp = get_uplinkport_describe(ifname[i]);
            if (describe_tmp) {
                snprintf(buf, sizeof(buf), "%x", describe_tmp);
                json_object_object_add(portObj, buf, json_object_new_string(ethernet_val[i]));
                count++;
            }
        }
    }

    /* Port count */
    json_object_object_add(uplinkObj, "Count", json_object_new_int(count));

    json_object_object_add(uplinkObj, "Ports", portObj);
    snprintf(typeStr, sizeof(typeStr), "%d", CONN_UPLINK_PORTS);
    json_object_object_add(capablityObj, typeStr, uplinkObj);
}

/**
 * @brief Added eap mode capablity.
 *
 * @param capablityObj Capablity obj.
 */
void cm_addEapMode(json_object *capablityObj) {
    char typeStr[4] = {};

    if (capablityObj == NULL) {
        DBG_ERR("capablityObj is NULL");
        return;
    }

    if (nvram_get_int("re_mode") == 1) {
        if (strlen(nvram_safe_get("eth_ifnames")) == 0)  // No uplink ports
            return;
    }

    snprintf(typeStr, sizeof(typeStr), "%d", CONN_EAP_MODE);
    json_object_object_add(capablityObj, typeStr, json_object_new_int(GENERAL_MODE));
}
#endif

/*
========================================================================
Routine Description:
	Add led control

Arguments:
	role		- role for capability support
	capablityObj            - the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addLedCtrl(unsigned int role, json_object *capablityObj)
{
	int ledCtrlVal = 0;
	char typeStr[4];

	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}

	if (role & RE_SUPPORT) {
		ledCtrlVal = nvram_get_int("led_ctrl_cap");
		if (ledCtrlVal <= 0) {
			DBG_INFO("don't need to add led ctrl capability");
			return;
		}
	}
	else if (role & CAP_SUPPORT)
		ledCtrlVal = CENTRAL_LED | LP55XX_LED | LED_ON_OFF | LED_BRIGHTNESS | LED_AURA;

	snprintf(typeStr, sizeof(typeStr), "%d", LED_CONTROL);
	json_object_object_add(capablityObj, typeStr, json_object_new_int64(ledCtrlVal));
} /* End of cm_addLedCtrl */

/*
========================================================================
Routine Description:
	Add rc support

Arguments:
	capablityObj            - the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addRcSupport(json_object *capablityObj)
{
	char rcSupport[1024];
	long rcSupportVal = 0;
	char typeStr[4];

	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}

	strlcpy(rcSupport, nvram_safe_get("rc_support"), sizeof(rcSupport));

	if (strstr(rcSupport, "usbX") != NULL)
		rcSupportVal |= USBX;

#ifdef RTCONFIG_AMAS_WGN
	rcSupportVal |= GUEST_NETWORK;
#endif

	if (strstr(rcSupport, "wpa3") != NULL)
		rcSupportVal |= WPA3;

#ifdef ONBOARDING_VIA_VIF
	rcSupportVal |= VIF_ONBOARDING;
#endif

#if defined(RTCONFIG_WL_SCHED_V2)
	rcSupportVal |= WL_SCHED_V2;
#endif

#if defined(RTCONFIG_WL_SCHED_V3)
	rcSupportVal |= WL_SCHED_V3;
#endif

	if (nvram_contains_word("rc_support", "switchctrl"))
		rcSupportVal |= SWITCHCTRL;

	rcSupportVal |= WIFI_RADIO;

        if (strstr(rcSupport, "revertfw") != NULL)
		rcSupportVal |= REVERT_FW;

	if (strstr(rcSupport, "noFwManual") != NULL)
		rcSupportVal |= NO_FW_MANUAL;

	if (strstr(rcSupport, " update") != NULL)
		rcSupportVal |= UPDATE;

#ifdef RTCONFIG_HTTPS
	rcSupportVal |= LOCAL_ACCESS;
#endif
	snprintf(typeStr, sizeof(typeStr), "%d", RC_SUPPORT);
	json_object_object_add(capablityObj, typeStr, json_object_new_int64(rcSupportVal));
} /* End of cm_addRcSupport */

#ifdef RTCONFIG_AMAS_WGN
/*
========================================================================
Routine Description:
	Add the number of guest network by band

Arguments:
	capablityObj		- the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addGuestNetworkNo(json_object *capablityObj)
{
	char typeStr[4] = {0};

	int unit = 0, band = 0;
	char wlifnames[128], word[64], *next = NULL;
	
	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}


	memset(wlifnames, 0, sizeof(wlifnames));
	strlcpy(wlifnames, nvram_safe_get("wl_ifnames"), sizeof(wlifnames));
	foreach (word, wlifnames, next) {
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		band = wgn_get_band_by_unit(unit);
		memset(typeStr, 0, sizeof(typeStr));
		if (band == WGN_WL_BAND_2G)
			snprintf(typeStr, sizeof(typeStr), "%d", GUEST_NETWORK_NO_2G);
		else if (band == WGN_WL_BAND_5G)
			snprintf(typeStr, sizeof(typeStr), "%d", GUEST_NETWORK_NO_5G);
		else if (band == WGN_WL_BAND_5GH)
			snprintf(typeStr, sizeof(typeStr), "%d", GUEST_NETWORK_NO_5GH);
		else if (band == WGN_WL_BAND_6G)
			snprintf(typeStr, sizeof(typeStr), "%d", GUEST_NETWORK_NO_6G);
		else 
			continue;

		json_object_object_add(capablityObj, typeStr, json_object_new_int64(wgn_guest_ifcount(band)));		
		unit++;
	}

} /* End of cm_addGuestNetworkNo */
#endif

/*
========================================================================
Routine Description:
	Add sta & ap supported authentication capability

Arguments:
	capablityObj            - the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addStaApAuthCap(json_object *capablityObj)
{
	char *rcSupport = nvram_safe_get("rc_support");
	long staVal = 0, apVal = 0;
	char typeStr[8];
	int wifi2017 = 0, wpa3 = 0;
	int unit = 0;
	char word[256], *next;
	char prefix[sizeof("wlXXXXX_")], tmp[64];
	int  nband = 0;
	int staIndex = 0, apIndex = 0;

	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}

	if (strstr(rcSupport, "wifi2017") != NULL)
		wifi2017 = 1;

	if (strstr(rcSupport, "wpa3") != NULL)
		wpa3 = 1;

	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
		if (unit == 0) {
			staIndex = STA_BAND0_AUTH;
			apIndex = AP_BAND0_AUTH;
		}
		else if (unit == 1)
		{
			staIndex = STA_BAND1_AUTH;
			apIndex = AP_BAND1_AUTH;
		}
		else if (unit == 2)
		{
			staIndex = STA_BAND2_AUTH;
			apIndex = AP_BAND2_AUTH;
		}
		else
			continue;

		if (wifi2017) {
			if (nband == 4) {
				staVal = WPA3_PERSONAL;
				apVal = WPA3_PERSONAL | OWE;
			}
			else
			{
				if (wpa3) {
					staVal = OPEN_SYSTEM | SHARED_KEY | WPA2_PERSONAL | WPA3_PERSONAL | WPA_WPA2_PERSONAL \
						| WPA2_WPA3_PERSONAL | WPA2_WPA3_PERSONAL;
					apVal = OPEN_SYSTEM | SHARED_KEY | WPA2_PERSONAL | WPA3_PERSONAL | WPA_WPA2_PERSONAL \
						| WPA2_WPA3_PERSONAL | WPA2_ENTERPRISE | WPA_WPA2_ENTERPRISE | RADIUS_WITH_8021X;
				}
				else
				{
					staVal = OPEN_SYSTEM | SHARED_KEY | WPA2_PERSONAL | WPA_WPA2_PERSONAL;
					apVal = OPEN_SYSTEM | SHARED_KEY | WPA2_PERSONAL | WPA_WPA2_PERSONAL | WPA2_ENTERPRISE \
						| WPA_WPA2_ENTERPRISE | RADIUS_WITH_8021X;
				}
			}
		}
		else
		{
			if (nband == 4) {
				staVal = WPA3_PERSONAL;
				apVal = WPA3_PERSONAL | OWE;
			}
			else
			{
				if (wpa3) {
					staVal = OPEN_SYSTEM | SHARED_KEY | WPA2_PERSONAL | WPA3_PERSONAL | WPA_WPA2_PERSONAL \
						| WPA2_WPA3_PERSONAL| WPA2_WPA3_PERSONAL;
					apVal = OPEN_SYSTEM | SHARED_KEY | WPA2_PERSONAL | WPA3_PERSONAL | WPA_WPA2_PERSONAL \
						| WPA2_WPA3_PERSONAL | WPA2_ENTERPRISE | WPA_WPA2_ENTERPRISE | RADIUS_WITH_8021X;
				}
				else
				{
					staVal = OPEN_SYSTEM | SHARED_KEY | WPA_PERSONAL | WPA2_PERSONAL | WPA_WPA2_PERSONAL;
					apVal = OPEN_SYSTEM | SHARED_KEY | WPA_PERSONAL | WPA2_PERSONAL | WPA_WPA2_PERSONAL \
						| WPA_ENTERPRISE | WPA2_ENTERPRISE | WPA_WPA2_ENTERPRISE | RADIUS_WITH_8021X;
				}
			}
		}

		/* add sta auth capability */
		snprintf(typeStr, sizeof(typeStr), "%d", staIndex);
		json_object_object_add(capablityObj, typeStr, json_object_new_int64(staVal));

		/* add ap auth capability */
		snprintf(typeStr, sizeof(typeStr), "%d", apIndex);
		json_object_object_add(capablityObj, typeStr, json_object_new_int64(apVal));

		unit++;
	}
} /* End of cm_addStaApAuthCap */

/*
========================================================================
Routine Description:
	Add wan capability.
	e.g. There is not WAN port in some models. No WAN port for ethernet onboarding.

Arguments:
	capablityObj            - the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addWansCap(json_object *capablityObj)
{
	char wansCap[32] = {0};
	long wansCapVal = 0;
	char typeStr[4];

	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}

	strlcpy(wansCap, nvram_safe_get("wans_cap"), sizeof(wansCap));

	if (strstr(wansCap, "wan") != NULL)
		wansCapVal |= WANS_CAP_WAN;

	snprintf(typeStr, sizeof(typeStr), "%d", WANS_CAP);

	json_object_object_add(capablityObj, typeStr, json_object_new_int64(wansCapVal));
}  /* End of cm_addWansCap */

/*
========================================================================
Routine Description:
	Add other capability.

Arguments:
	capablityObj            - the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addOtherCap(json_object *capablityObj)
{
	long capVal = 0;
	char typeStr[4];

	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}

	/* for re reconnect */
	capVal = 0;
	capVal |= MANUAL_RECONN;
	snprintf(typeStr, sizeof(typeStr), "%d", RE_RECONNECT);
	json_object_object_add(capablityObj, typeStr, json_object_new_int64(capVal));


	/* for sta force roaming */
	capVal = 0;
	capVal |= MANUAL_FORCE_ROAMING;
	snprintf(typeStr, sizeof(typeStr), "%d", FORCE_ROAMING);
	json_object_object_add(capablityObj, typeStr, json_object_new_int64(capVal));
}  /* End of cm_addOtherCap */


/*
========================================================================
Routine Description:
	Add wifi radio capability.

Arguments:
	capablityObj            - the json_object of capablity

Return Value:
	None

========================================================================
*/
void cm_addWifiRadioCap(json_object *capablityObj)
{
	long radioCapVal = 0;
	char typeStr[4], prefix[sizeof("wlXXXXX_")], tmp[32];
	int i = 0, nband = 0, num5g = 0;

	if (capablityObj == NULL) {
		DBG_ERR("capablityObj is NULL");
		return;
	}

	for (i = 0; i < supportedBandNum; i++) {
		snprintf(prefix, sizeof(prefix), "wl%d_", i);
		nband = nvram_get_int(strcat_r(prefix, "nband", tmp));
		if (nband == 2)
			radioCapVal |= WIFI_RADIO_2G;
		else if (nband == 1) {
			num5g++;
			radioCapVal |= (num5g == 1 ? WIFI_RADIO_5G : WIFI_RADIO_5GH);
		}
		else if (nband == 4)
			radioCapVal |= WIFI_RADIO_6G;
	}

	if (radioCapVal != 0) {
		snprintf(typeStr, sizeof(typeStr), "%d", WIFI_RADIO_CTL);
		json_object_object_add(capablityObj, typeStr, json_object_new_int64(radioCapVal));
	}
}  /* End of cm_addWifiRadioCap */

/*
========================================================================
Routine Description:
	Generate json string for capability.

Arguments:
	role		- role for capability support
	capablity            - the array of capablity

Return Value:
	json object for capablity

========================================================================
*/
json_object *cm_generateCapability(unsigned int role, capability_s *capablity)
{
	char typeStr[4] = {0};
	capability_s *pCapability = NULL;
	int subType = 0;
	json_object *capabilityObj = NULL;

	if (!capablity) {
		DBG_ERR("capability is NULL");
		return NULL;
	}

	capabilityObj = json_object_new_object();
	if (!capabilityObj) {
		DBG_ERR("capabilityObj is NULL");
		return NULL;
	}

	for (pCapability = &capablity[0]; pCapability->type != 0; pCapability++) {
		if (pCapability->capSupportRole & role) {
			memset(typeStr, 0, sizeof(typeStr));
			snprintf(typeStr, sizeof(typeStr), "%d", pCapability->type);
			subType	 = pCapability->subtype;
			json_object_object_add(capabilityObj, typeStr, json_object_new_int(subType));
		}
	}

	cm_addLedCtrl(role, capabilityObj);
	cm_addRcSupport(capabilityObj);
	if (role & RE_SUPPORT) {
#ifdef RTCONFIG_AMAS_WGN
		cm_addGuestNetworkNo(capabilityObj);
#endif
		cm_addStaApAuthCap(capabilityObj);
		cm_addWansCap(capabilityObj);
#ifdef RTCONFIG_BHCOST_OPT
		cm_addUplinkType(capabilityObj);
#endif
	}
	cm_addWifiRadioCap(capabilityObj);
#ifdef RTCONFIG_BHCOST_OPT
    cm_addEapMode(capabilityObj);
#endif
	//cm_addOtherCap(capabilityObj);

	return capabilityObj;
} /* End of cm_generateCapability */

/*
========================================================================
Routine Description:
	Check the capability of wifi auth is valid or not based on RE supported capability.

Arguments:
	mac		- RE mac
	capBandNum		- CAP supported band number
	reBandNum		- RE supported band number
	type		- 0 (normal), 1 (dwb for dual band), 2 (dwb for tri-band)
	inAuth		- authentication
	outAuth		- output authentication
	outAuthLen		- max length of outAuth

Return Value:
	0		- invalid
	1		- valid

========================================================================
*/
int cm_checkWifiAuthCap(char *mac, int capBandNum, int reBandNum, int type, char *name, char *outAuth, int outAuthLen)
{
	json_object *reCapRoot = NULL, *staCapIndexObj = NULL, *apCapIndexObj = NULL;
	char reCapFile[64], indexStr[8] ,finalparamname[64];
	int ret = 0, unit = -1, subunit = -1, staIndex = -1, apIndex = -1, staAuthIndex = -1, apAuthIndex = -1;
	struct wifi_auth_mapping_s *pAuth = NULL;
	unsigned int authIndexAll = OPEN_SYSTEM | SHARED_KEY | WPA_PERSONAL | WPA2_PERSONAL | WPA_WPA2_PERSONAL |
		WPA2_WPA3_PERSONAL | WPA_ENTERPRISE | WPA2_ENTERPRISE | WPA3_ENTERPRISE | WPA_WPA2_ENTERPRISE |
		WPA2_WPA3_ENTERPRISE | RADIUS_WITH_8021X;
	char rebandtype[5];
	int  realUnit=0;

	if (mac == NULL || name == NULL || outAuth == NULL) {
		DBG_ERR("mac/name/outAuth is NULL");
		return 0;
	}

	snprintf(reCapFile, sizeof(reCapFile), "%s/%s.cap", TEMP_ROOT_PATH, mac);

	/* find unit & subunit based on name */
	if (type == 1) {
		if (capBandNum ==  2 && reBandNum == 3)
			unit = WL_5G_2_BAND;
		else
			unit = WL_5G_BAND;

		subunit = -1;
	}
	else if (type == 2) {
		unit = WL_5G_BAND;
		subunit = -1;
	}
	else
	{
		if (sscanf(name, "wl%d.%d_%*s", &unit, &subunit) != 2) {
			if (sscanf(name, "wl%d_%*s", &unit) == 1) {
				subunit = -1;

				if (unit == 2 && capBandNum ==  3 && reBandNum == 2) {
					DBG_INFO("change unit 2 to 1");
					unit = WL_5G_BAND;
				}
			}
		}
	}

	DBG_INFO("unit(%d), subunit(%d)", unit, subunit);
	if (unit == -1) {
		DBG_ERR("can't find unit for %s", name);
		return 0;
	}

	/* find sta auth setting based on name */
	for (pAuth = &wifi_auth_mapping_list[0]; pAuth->index != 0; pAuth++) {
		if (nvram_get(name) && strcmp(nvram_safe_get(name), pAuth->name) == 0) {
			staAuthIndex = pAuth->index;
			break;
		}
	}

	if (staAuthIndex == -1)  {
		DBG_ERR("can't find sta auth index for %s", name);
		return 0;
	}

	/* find ap auth setting based on name */
	for (pAuth = &wifi_auth_mapping_list[0]; pAuth->index != 0; pAuth++) {
		if (nvram_get(name) && strcmp(nvram_safe_get(name), pAuth->name) == 0) {
			apAuthIndex = pAuth->index;
			break;
		}
	}

	if (apAuthIndex == -1)  {
		DBG_ERR("can't find ap auth index for %s", name);
		return 0;
	}

	if ((reCapRoot = json_object_from_file(reCapFile)) != NULL) {		
		if (unit == WL_2G_BAND) {
			realUnit = get_unit_chanspc_by_bandtype(mac,"2G");
		}
		else if (unit == WL_5G_BAND) {
			realUnit = get_unit_chanspc_by_bandtype(mac,"5G");
		}
		else if (unit == WL_5G_2_BAND) {
			if(check_match_6G==1){
				realUnit = get_unit_chanspc_by_bandtype(mac,"6G");
			}
			else
			{
				realUnit = get_unit_chanspc_by_bandtype(mac,"5G1");
			}
		}
		if(get_rebandtype_chanspc_by_unit(mac,realUnit,reBandNum,rebandtype,sizeof(rebandtype))!=NULL){
			if(!strcmp(rebandtype,"2G"))
			{
				staIndex = STA_BAND0_AUTH;
				apIndex = AP_BAND0_AUTH;
			}
			else if(!strcmp(rebandtype,"5G"))
			{
				staIndex = STA_BAND1_AUTH;
				apIndex = AP_BAND1_AUTH;
			}
			else if(!strcmp(rebandtype,"5G1"))
			{
				if(reBandNum>3)
				{
					staIndex = STA_BAND1_AUTH;
					apIndex = AP_BAND1_AUTH;
				}
				else
				{
					staIndex = STA_BAND2_AUTH;
					apIndex = AP_BAND2_AUTH;
				}
			}
			else if(!strcmp(rebandtype,"6G"))
			{
				staIndex = STA_BAND2_AUTH;
				apIndex = AP_BAND2_AUTH;
			}
		}
		else
		{
			if (unit == WL_2G_BAND) {
				staIndex = STA_BAND0_AUTH;
				apIndex = AP_BAND0_AUTH;
			}
			else if (unit == WL_5G_BAND) {
				staIndex = STA_BAND1_AUTH;
				apIndex = AP_BAND1_AUTH;
			}
			else if (unit == WL_5G_2_BAND) {
				staIndex = STA_BAND2_AUTH;
				apIndex = AP_BAND2_AUTH;
			}	
		}
		if (staIndex >= 0 && apIndex >= 0) {
			if (unit >=0 && subunit == -1) {	/* for main */
				snprintf(indexStr, sizeof(indexStr), "%d", staIndex);
				json_object_object_get_ex(reCapRoot, indexStr, &staCapIndexObj);
				if (staCapIndexObj) {
					DBG_INFO("%s (%s)", name, nvram_safe_get(name));
					memset(finalparamname, 0, sizeof(finalparamname));
					if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "psk2sae") == 0) {
						if ((json_object_get_int(staCapIndexObj) & WPA2_WPA3_PERSONAL) > 0) {
							ret = 1;
							strlcpy(outAuth, "psk2sae", outAuthLen);
							DBG_INFO("RE supports psk2sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
					}
					else if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "sae") == 0) {
						if ((json_object_get_int(staCapIndexObj) & WPA3_PERSONAL) > 0) {
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
					}
					else if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "owe") == 0){
						if ((json_object_get_int(staCapIndexObj) & OWE) > 0) {
							ret = 1;
							strlcpy(outAuth, "owe", outAuthLen);
							DBG_INFO("RE supports owe");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
					}
					else if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "psk2") == 0) {
						 if ((json_object_get_int(staCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA2_WPA3_PERSONAL) > 0) {
							ret = 1;
							strlcpy(outAuth, "psk2sae", outAuthLen);
							DBG_INFO("RE supports psk2sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
					}
					else if ((json_object_get_int(staCapIndexObj) & authIndexAll) == 0) {
						if ((json_object_get_int(staCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("change to sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & OWE) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "owe", outAuthLen);
							DBG_INFO("change to owe");
						}
					}

#if 0
					else
					{
						if (((unit >=0 && subunit == -1) && (json_object_get_int(staCapIndexObj) & staAuthIndex) > 0) ||
							((unit >=0 && subunit >= 0) && (json_object_get_int(staCapIndexObj) & apAuthIndex) > 0))
						{
							ret = 1;
							strlcpy(outAuth, nvram_safe_get(name), outAuthLen);
						}
					}
#endif
				}
				else
				{
					if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "psk2sae") == 0 ||
						strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "sae") == 0)
					{
						ret = 1;
						strlcpy(outAuth, "psk2", outAuthLen);
						DBG_INFO("change to psk2");
					}
#if 0
					else
					{
						ret = 1;
						strlcpy(outAuth, nvram_safe_get(name), outAuthLen);
					}
#endif
				}
			}
			else if (unit >=0 && subunit > 0)	/* for guest */
			{
				snprintf(indexStr, sizeof(indexStr), "%d", apIndex);
				json_object_object_get_ex(reCapRoot, indexStr, &apCapIndexObj);
				if (apCapIndexObj) {
					memset(finalparamname, 0, sizeof(finalparamname));
					if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "psk2sae") == 0) {
						if ((json_object_get_int(apCapIndexObj) & WPA2_WPA3_PERSONAL) > 0) {
							ret = 1;
							strlcpy(outAuth, "psk2sae", outAuthLen);
							DBG_INFO("RE supports psk2sae");
						}
						else if ((json_object_get_int(apCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
						else if ((json_object_get_int(apCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
					}
					else if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "sae") == 0) {
						if ((json_object_get_int(apCapIndexObj) & WPA3_PERSONAL) > 0) {
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
						else if ((json_object_get_int(apCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
					}
					else if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "owe") == 0) {
						if ((json_object_get_int(apCapIndexObj) & OWE) > 0) {
							ret = 1;
							strlcpy(outAuth, "owe", outAuthLen);
							DBG_INFO("RE supports owe");
						}
						else if ((json_object_get_int(apCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
						else if ((json_object_get_int(apCapIndexObj) & WPA3_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
					}
					else if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "psk2") == 0) {
						 if ((json_object_get_int(staCapIndexObj) & WPA2_PERSONAL) >= 0)
						{
							ret = 1;
							strlcpy(outAuth, "psk2", outAuthLen);
							DBG_INFO("change to psk2");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA2_WPA3_PERSONAL) > 0) {
							ret = 1;
							strlcpy(outAuth, "psk2sae", outAuthLen);
							DBG_INFO("RE supports psk2sae");
						}
						else if ((json_object_get_int(staCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("RE supports sae");
						}
					}
					else if ((json_object_get_int(apCapIndexObj) & authIndexAll) == 0) {
						if ((json_object_get_int(apCapIndexObj) & WPA3_PERSONAL) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "sae", outAuthLen);
							DBG_INFO("change to sae");
						}
						else if ((json_object_get_int(apCapIndexObj) & OWE) > 0)
						{
							ret = 1;
							strlcpy(outAuth, "owe", outAuthLen);
							DBG_INFO("change to owe");
						}
					}
				}
				else
				{
					if (strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "psk2sae") == 0 ||
						strcmp(nvram_safe_get(cap_get_final_paramname(mac, name,reBandNum,finalparamname, sizeof(finalparamname))), "sae") == 0)
					{
						ret = 1;
						strlcpy(outAuth, "psk2", outAuthLen);
						DBG_INFO("change to psk2");
					}
#if 0
					else
					{
						ret = 1;
						strlcpy(outAuth, nvram_safe_get(name), outAuthLen);
					}
#endif
				}
			}
		}
		json_object_put(reCapRoot);
	}

	return ret;
} /* End of cm_checkWifiAuthCap */

/*
========================================================================
Routine Description:
	Check capability type & subtype support or not.

Arguments:
	reMac		- Re unique mac
	capType		- capability type
	capSubtyp	- capability subtype

Return Value:
	-1		- error
	0		- not support
	1		- support

========================================================================
*/
int cm_isCapSupported(char *reMac, int capType, int capSubtype)
{
	json_object *reCapRoot = NULL, *capTypeObj = NULL;
	char reCapFile[64], indexStr[8];
	int ret = 0;

	if (reMac == NULL) {
		DBG_ERR("reMac is NULL");
		return -1;
	}

	snprintf(reCapFile, sizeof(reCapFile), "%s/%s.cap", TEMP_ROOT_PATH, reMac);

	if ((reCapRoot = json_object_from_file(reCapFile)) != NULL) {
		snprintf(indexStr, sizeof(indexStr), "%d", capType);
		json_object_object_get_ex(reCapRoot, indexStr, &capTypeObj);

		if (capTypeObj) {
			if ((capSubtype && (json_object_get_int(capTypeObj) & capSubtype)) || (capSubtype == 0))
				ret = 1;
		}
	}

	json_object_put(reCapRoot);

	return ret;
}  /* End of cm_isCapSupported */
