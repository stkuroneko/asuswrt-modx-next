/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */
/* In this sample code some functions of the helper library are used to create and modify object lists */
/*!  \brief  API to add an add object node to the head node
\param[in] pxObjList Pointer to the List head object node
\param[in] pcObjName Name of the Object
\param[in] unSid n/a
\param[in] unOid n/a
\param[in] unSubOper Suboperation at object level(add, del, modify)
\param[in] unObjFlag Identify access, dynamic, etc
\return
ObjList *  help_addObjList(IN ObjList *pxObjList,
  IN const char *pcObjName,
  IN uint16_t unSid,
  IN uint16_t unOid,
  IN uint32_t unSubOper,
  IN uint32_t unObjFlag);
*/

/*! \brief  Updates the particular parameter node in the given objlist if param node found, else adds new param node
\param[in] pxDstObjList Objlist list ptr where parameter values need to be updated
\param[in] pcObjname Object name
\param[in] pcParamName Parameter name
\param[in] pcParamValue Parameter value to update
\param[in] unParamId n/a
\param[in] unParamFlag n/a
\return Destination objlist parameter value updated on successful / ugw_failure on failure
*/

#include <rc.h>
#include <stdio.h>
#include <fcntl.h>		// for restore175C() from Ralink src
#include <lantiq.h>
#include <asm/byteorder.h>
#include <bcmnvram.h>
//#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <shutils.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <mtd/ubi-user.h>
#include <dirent.h>
#include <sys/mount.h>
#include <net/if.h>
#include <linux/mii.h>
//#include <linux/if.h>
#include <iwlib.h>
//#include <stapriv.h>
#include <shared.h>
#include "flash_mtd.h"
#include "ate.h"
#include <fapi_wlan_private.h>
#include <fapi_wlan.h>
#include <help_objlist.h>
#include <wlan_config_api.h>
#include "lantiq_common.h"
#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#ifdef RTCONFIG_CFGSYNC
#include <json.h>
#include <cfg_slavelist.h>
#include <cfg_string.h>
#endif

#define VHT_SUPPORT		/* 11AC */

#define MAX_FRW 64
#define MACSIZE 12

#define APSCAN_WLIST	"/tmp/apscan_wlist"
#define target 9
char sitesurvey_field[target][40] = {"Address:", "ESSID:", "Frequency:", "Quality=", "Encryption key:", "IE:", "Authentication Suites", "Pairwise Ciphers", "phy_mode="};

struct config_in {
  char* param;
  char* value;
};

//	{"Object", "Device.WiFi.SSID"} with default values to be used on adding
struct config_in config_in_SSID[] = {
  { "Enable", "true" },
  { "Status", "Down" },
  { "Alias", "cpe-SSID-4" },
  { "Name", "" },
  { "LastChange", "0" },
  { "LowerLayers", "Device.WiFi.Radio.1." },
  { "BSSID", "" },
  { "MACAddress", "" },
  { "SSID", "" },
  { "X_LANTIQ_COM_Vendor_BridgeName", "br-lan" },
  { "X_LANTIQ_COM_Vendor_SsidType", "EndPoint"},
  { "X_LANTIQ_COM_Vendor_IsEndPoint", "true"},
  { "X_LANTIQ_COM_Vendor_WaveAtfVapWeight", "0"}
};

//	{"Object", "Device.WiFi.EndPoint"} with default values
struct config_in config_in_EndPoint[] = {
  { "Enable", "false" },
  { "Status", "Disabled" },
  { "Alias", "cpe-EndPoint-1" },
  { "ProfileReference", "" },
  { "SSIDReference", "Device.WiFi.SSID.4" },
  { "ProfileNumberOfEntries", "0" },
  { "X_LANTIQ_COM_Vendor_ScanStatus", "" },
  { "X_LANTIQ_COM_Vendor_ConnectionStatus", "Disconnected" },
  { "X_LANTIQ_COM_Vendor_WaveEndPointWDS", "false" },
  { "X_LANTIQ_COM_Vendor_WaveEndPointPMF", "0" },
  { "X_LANTIQ_COM_Vendor_WispEnable", "false" }
};

//	{"Object", "Device.WiFi.EndPoint.Security"}, with default values
struct config_in config_in_EndPoint_Security[] = {
  //{ "ModesSupported", "None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal" }
  { "ModesSupported", "None,WEP-64,WEP-128,WPA2-Personal,WPA-WPA2-Personal,WPA2-Enterprise,WPA-WPA2-Enterprise" }
};

//	{"Object", "Device.WiFi.EndPoint.WPS"}, with default values
struct config_in config_in_EndPoint_WPS[] = {
  { "Enable", "true" },
  { "ConfigMethodsSupported", "PushButton,PIN" },
  { "ConfigMethodsEnabled", "PushButton,PIN" },
  { "X_LANTIQ_COM_Vendor_WPSStatus", "Idle" },
  { "X_LANTIQ_COM_Vendor_WPSAction", "" },
  { "X_LANTIQ_COM_Vendor_EndpointPIN", "12345670" }
};

//	{"Object", "Device.WiFi.AccessPoint.AC"}, with default values
struct config_in config_in_EndPoint_AC_BE[] = {
  { "AccessCategory", "BE" },
  { "Alias", "cpe-AC-1" },
  { "AIFSN", "3" },
  { "ECWMin", "4" },
  { "ECWMax", "10" },
  { "TxOpMax", "0" },
  { "AckPolicy", "false" },
  { "OutQLenHistogramIntervals", "" },
  { "OutQLenHistogramSampleInterval", "0" }
};

//	{"Object", "Device.WiFi.AccessPoint.AC"}, with default values for Background traffic
struct config_in config_in_EndPoint_AC_BK[] = {
  { "AccessCategory", "BK" },
  { "Alias", "cpe-AC-2" },
  { "AIFSN", "7" },
  { "ECWMin", "4" },
  { "ECWMax", "10" },
  { "TxOpMax", "0" },
  { "AckPolicy", "false" },
  { "OutQLenHistogramIntervals", "" },
  { "OutQLenHistogramSampleInterval", "0" }
};

//	{"Object", "Device.WiFi.AccessPoint.AC"}, with default values for Video traffic
struct config_in config_in_EndPoint_AC_VI[] = {
  { "AccessCategory", "VI" },
  { "Alias", "cpe-AC-3" },
  { "AIFSN", "2" },
  { "ECWMin", "3" },
  { "ECWMax", "4" },
  { "TxOpMax", "94" },
  { "AckPolicy", "false" },
  { "OutQLenHistogramIntervals", "" },
  { "OutQLenHistogramSampleInterval", "0" }
};

//	{"Object", "Device.WiFi.AccessPoint.AC"}, with default values for Voice
struct config_in config_in_EndPoint_AC_VO[] = {
  { "AccessCategory", "VO" },
  { "Alias", "cpe-AC-3" },
  { "AIFSN", "2" },
  { "ECWMin", "2" },
  { "ECWMax", "3" },
  { "TxOpMax", "47" },
  { "AckPolicy", "false" },
  { "OutQLenHistogramIntervals", "" },
  { "OutQLenHistogramSampleInterval", "0" }
};

//	{"Object", "Device.WiFi.AccessPoint.AssociatedDevice"},
struct config_in config_in_EndPoint_Profile[] = {
  { "MACAddress", "" },
  { "AuthenticationState", "" },
  { "LastDataDownlinkRate", "" },
  { "LastDataUplinkRate", "" },
  { "SignalStrenght", "" },
  { "Retransmissions", "" },
  { "Active", "" },
};

static int wav_ep_disconnect(int wifi_unit);

#ifdef RTCONFIG_WIRELESSREPEATER
char *wlc_nvname(char *keyword)
{
	return wl_nvname(keyword, nvram_get_int("wlc_band"), -1);
}
#endif

/*
helper function for endpoint bringup
This function is for calling fapi_wlan_ssid_add to add the endpoint VAP during endpoint initalization
*/
static int wav_ep_ssid_add(int wifi_unit){
	ObjList * wlObj;
	unsigned int i;
	int ret;
	char buf[32];
	char macaddr[] = "00:11:22:33:44:55";

	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);

	/* help_addObjList adds an object to the object list */
	help_addObjList(wlObj, "Device.WiFi.SSID", 0, 0, 0, 0);
	/* add all parameters to Device.WiFi.SSID object with default values as defined in config_in_SSID */
	for(i = 0; i < (sizeof(config_in_SSID) / sizeof(struct config_in)); ++i){
		/* HELP_EDIT_NODE adds parameters to an object */
		HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", config_in_SSID[i].param, config_in_SSID[i].value, 0, 0);
	}

	snprintf(buf, sizeof(buf), "wl%d_hwaddr", wifi_unit);
	snprintf(macaddr, sizeof(macaddr), "%s",  nvram_safe_get(buf));
	/* Always using 2G/5G MAC + 1 for 2G/5G endpoint */
	inc_mac(macaddr, 1);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", "MACAddress", macaddr, 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", "Name", get_staifname(wifi_unit), 0, 0);

	/* fapi_wlan_ssid_add returns interface name and MAC address */
	printf("%s(%d) fapi_wlan_ssid_add: %d(%s)\n", __func__, __LINE__, wifi_unit, get_wififname(wifi_unit));
	ret = fapi_wlan_ssid_add((char *)get_wififname(wifi_unit), wlObj, 0);
	printf("%s(%d) fapi_wlan_ssid_add: %d\n", __func__, __LINE__, ret);

	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);
	return ret;
}

#if 0
/*
helper function for endpoint bringup
This function is for calling fapi_wlan_ssid_set during enpoint initalization
*/
static int wav_ep_ssid_set(int wifi_unit){
	ObjList * wlObj;
	unsigned int i;
	char buf[32];
	char macaddr[] = "00:11:22:33:44:55";

	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);

	help_addObjList(wlObj, "Device.WiFi.SSID", 0, 0, 0, 0);
	for(i = 0; i < (sizeof(config_in_SSID) / sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", config_in_SSID[i].param, config_in_SSID[i].value, 0, 0);
	}

	snprintf(buf, sizeof(buf), "wl%d_hwaddr", wifi_unit);
	snprintf(macaddr, sizeof(macaddr), "%s",  nvram_safe_get(buf));
	/* Always using 2G/5G MAC + 1 for 2G/5G endpoint */
	inc_mac(macaddr, 1);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", "MACAddress", macaddr, 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", "Name", get_staifname(wifi_unit), 0, 0);

	printf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);
	fapi_wlan_ssid_set(get_staifname(wifi_unit), wlObj, 0);
	printf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);

	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);
	return 0;
}
#endif

/*
helper function for endpoint bringup
This function is for calling fapi_wlan_endpoint_set during enpoint initalization
*/
static int wav_ep_set(int wifi_unit){
	ObjList * obj;
	ObjList * wlObj;
	unsigned int i;
	int ret=0;
	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);

	help_addObjList(wlObj, "Device.WiFi.EndPoint", 0, 0, 0, 0);
	for(i=0; i < (sizeof(config_in_EndPoint)/sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint", config_in_EndPoint[i].param, config_in_EndPoint[i].value, 0, 0);
	}

	help_addObjList(wlObj, "Device.WiFi.EndPoint.Security", 0, 0, 0, 0);
	for(i=0; i < (sizeof(config_in_EndPoint_Security)/sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Security", config_in_EndPoint_Security[i].param, config_in_EndPoint_Security[i].value, 0, 0);
	}

	help_addObjList(wlObj, "Device.WiFi.EndPoint.WPS", 0, 0, 0, 0);
	for(i = 0; i < (sizeof(config_in_EndPoint_WPS) / sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.WPS", config_in_EndPoint_WPS[i].param, config_in_EndPoint_WPS[i].value, 0, 0);
	}

	help_addObjList(wlObj, "Device.WiFi.EndPoint.AC.1", 0, 0, 0, 0);
	for(i = 0; i < (sizeof(config_in_EndPoint_AC_BE) / sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.AC.1", config_in_EndPoint_AC_BE[i].param, config_in_EndPoint_AC_BE[i].value, 0, 0);
	}

	help_addObjList(wlObj, "Device.WiFi.EndPoint.AC.2", 0, 0, 0, 0);
	for(i = 0; i < (sizeof(config_in_EndPoint_AC_BK) / sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.AC.2", config_in_EndPoint_AC_BK[i].param, config_in_EndPoint_AC_BK[i].value, 0, 0);
	}

	help_addObjList(wlObj, "Device.WiFi.EndPoint.AC.3", 0, 0, 0, 0);
	for(i = 0; i < (sizeof(config_in_EndPoint_AC_VI) / sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.AC.3", config_in_EndPoint_AC_VI[i].param, config_in_EndPoint_AC_VI[i].value, 0, 0);
	}

	help_addObjList(wlObj, "Device.WiFi.EndPoint.AC.4", 0, 0, 0, 0);
	for(i = 0; i < (sizeof(config_in_EndPoint_AC_VO) / sizeof(struct config_in)); ++i){
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.AC.4", config_in_EndPoint_AC_VO[i].param, config_in_EndPoint_AC_VO[i].value, 0, 0);
	}

	/* FAPI does not need indices like AC.1, AC.2, etc., so remove it */
	FOR_EACH_OBJ(wlObj, obj){
		if(strstr(obj->sObjName, "AC")){
			snprintf(obj->sObjName, MAX_LEN_OBJNAME, "Device.WiFi.EndPoint.AC");
		}
	}

	printf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);
	ret = fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);
	printf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);

	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);
	return ret;
}

/*
Init endpoints
*/
static int wav_ep_init(int wifi_unit){
	int ret=0;
	ret += wav_ep_ssid_add(wifi_unit);
	ret += wav_ep_set(wifi_unit);

	return 0;
}

/*
helper function for endpoint starting
*/
static int wav_ep_enable(int wifi_unit, int enabling){
	ObjList * wlObj;
	int ret=0;
	/* endpoint */
	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);
	help_addObjList(wlObj, "Device.WiFi.EndPoint", 0, 0, 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint", "Enable", (enabling)?"true":"false", 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint", "X_LANTIQ_COM_Vendor_WaveEndPointWDS", "false", 0, 0);

	ret = fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);
	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);

	/* ssid */
	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);
	help_addObjList(wlObj, "Device.WiFi.SSID", 0, 0, 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", "Enable", (enabling)?"true":"false", 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.SSID", "X_LANTIQ_COM_Vendor_BridgeName", "br-lan", 0, 0);

	ret += fapi_wlan_ssid_set(get_staifname(wifi_unit), wlObj, 0);
	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);

	return ret;
}

static int wav_ep_check_nonexist(int wifi_unit){
	ObjList * wlObj;
	int ret;

	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);
	/* add first object */
	help_addObjList(wlObj, "Device.WiFi.EndPoint", 0, 0, 0, 0);
	/* add parameters to object */
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint", "ProfileReference", "Device.WiFi.EndPoint.1.Profile.1", 0, 0);

	/* call FAPI function with created object list */
	ret = fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);
	/* empty object list (only empty, not delete) */
	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, EMPTY_OBJLIST);

	return ret;
}

/*
helper function for endpoint bringup
This function is for calling fapi_wlan_up during enpoint initalization
*/
static int wav_ep_up(int wifi_unit, int lastVAP){
	int ret;
	ret= fapi_wlan_up(get_staifname(wifi_unit), 0, lastVAP);

	return ret;
}

/*
helper function for endpoint bringdown
This function is for calling fapi_wlan_down
*/
int wav_ep_down(int wifi_unit, int lastVAP){
	int ret;
	ret = fapi_wlan_down(get_staifname(wifi_unit), 0, lastVAP);

	return 0;
}

/*
Initialize and enable endpoint of both radios
*/
static int wav_ep_start(int wifi_unit){
	int ret=0;
	ret += wav_ep_init(wifi_unit);
	ret += wav_ep_enable(wifi_unit, 1);

	return ret;
}

/*
Example: How to perform scan
*/
static int wav_ep_scan(int wifi_unit){
	ObjList * wlObj;

	/* create empty object list */
	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);

	/* add empty object */
	help_addObjList(wlObj, "Device.WiFi.EndPoint", 0, 0, 0, 0);

	/* add parameters to object */
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint", "X_LANTIQ_COM_Vendor_ScanStatus", "Scanning", 0, 0);

	printf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);
	/* call FAPI functions with created object to perform scan */
	fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);

	/* the API returns all the found profiles in wlObj, for each profile save the relevant
	information SSID, Status, X_LANTIQ_COM_Vendor_BSSID, etc. */
	//HELP_PRINT_OBJ(wlObj, SOPT_OBJVALUE);
	printf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);
	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);

	/* scanning now with set configuration */
	wav_ep_up(wifi_unit, 1);

	return 0;
}

/*
Example: How to connect to AP found during scan
*/
static int wav_ep_connect(int wifi_unit, char *apMac, char *ssid, char* security, char* beacon, char* encrypt, char* passwd)
{
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	ObjList * wlObj;
	int ret;


	/* create empty object list */
	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);
	/* add first object */
	help_addObjList(wlObj, "Device.WiFi.EndPoint", 0, 0, 0, 0);
	/* add parameters to object */
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint", "ProfileReference", "Device.WiFi.EndPoint.1.Profile.1", 0, 0);


	/* call FAPI function with created object list */
	ret = fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);

	/* empty object list (only empty, not delete) */
	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, EMPTY_OBJLIST);
	if(ret)
		return -1;

	/* add empty object to object list */
	help_addObjList(wlObj, "Device.WiFi.EndPoint.Profile", 0, 0, 0, 0);
	/* add parameters to object, use the values received from scan results */
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "Enable", "true", 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "Status", "Active", 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "Priority", "0", 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "Alias", "CPE-Profile-1", 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "X_LANTIQ_COM_Vendor_IsHiddenSsid", "true", 0, 0);

	if (apMac && strlen(apMac)) {
		/* MAC address of AP found during scan */
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "X_LANTIQ_COM_Vendor_BSSID", apMac, 0, 0);
	}

	/* SSID of AP found during scan */
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile", "SSID", ssid, 0, 0);

	/* call FAPI function with created object list */
	ret = fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);
	/* empty object list (only empty, not delete) */
	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, EMPTY_OBJLIST);

	/* add empty object to object list */
	help_addObjList(wlObj, "Device.WiFi.EndPoint.Profile.Security", 0, 0, 0, 0);
	/* add parameters to object, use the values received from scan results (password must be known) */
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "ModeEnabled", security, 0, 0);
	if(!strcmp(security, "WEP-64") || !strcmp(security, "WEP-128"))
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "WEPKey", passwd, 0, 0);
	else
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "KeyPassphrase", passwd, 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "BeaconType", beacon, 0, 0);
	HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "EncryptionMode", encrypt, 0, 0);
	if(!strcmp(security, "WPA2-Enterprise") || !strcmp(security, "WPA-WPA2-Enterprise")){
		wl_nvprefix(prefix, sizeof(prefix), wifi_unit, -1);

		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "RadiusServerIPAddr", nvram_safe_get(strcat_r(prefix, "radius_ipaddr", tmp)), 0, 0);
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "RadiusServerPort", nvram_safe_get(strcat_r(prefix, "radius_port", tmp)), 0, 0);
		HELP_EDIT_NODE(wlObj, "Device.WiFi.EndPoint.Profile.Security", "RadiusSecret", nvram_safe_get(strcat_r(prefix, "radius_key", tmp)), 0, 0);
	}

	ret = fapi_wlan_endpoint_set(get_staifname(wifi_unit), wlObj, 0);

	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, EMPTY_OBJLIST);

	/* connect now with set configuration */
	wav_ep_up(wifi_unit, 1);

#if 0
#ifdef RTCONFIG_PROXYSTA
	if(mediabridge_mode()){
		char *next;
		int i;

		/* For mediabridge mode disable the accesspoint on wlan0 and wlan2 */
#if 1
		help_addObjList(wlObj, "Device.WiFi.AccessPoint", 0, 0, 0, 0);
		HELP_EDIT_NODE(wlObj, "Device.WiFi.AccessPoint", "Enable", "false", 0, 0);
		_dprintf("%s(%d) wifi_unit: %d\n", __func__, __LINE__, wifi_unit);
#endif

		i = 0;
		foreach(tmp, nvram_safe_get("wl_ifnames"), next){
			SKIP_ABSENT_BAND_AND_INC_UNIT(i);

#if 1
			_dprintf("%s(%d) fapi_wlan_ap_set: wifi_unit: %d\n", __func__, __LINE__, i);
			ret = fapi_wlan_ap_set(get_wififname(i), wlObj, 0);
			//ret = fapi_wlan_endpoint_set(get_wififname(i), wlObj, 0);
			_dprintf("%s(%d) fapi_wlan_ap_set: ret: %d\n", __func__, __LINE__, ret);
			HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, EMPTY_OBJLIST);

			/* Bring up the interfaces after fapi_wlan_ap_set */
			_dprintf("%s(%d) fapi_wlan_up: wifi_unit: %d\n", __func__, __LINE__, i);
			ret = fapi_wlan_up(get_wififname(i), wlObj, 1);
			_dprintf("%s(%d) fapi_wlan_up: ret: %d\n", __func__, __LINE__, ret);

			HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);
#else
			wave_set_ap_professional(i, -1);
#endif

			++i;
		}
	}
	else
#endif
#endif
		//_dprintf("%s(%d) skip to stop AP nodes here.\n", __func__, __LINE__);

	/* setting DHCP or static IP is not in the scope of the sample code. Please note
	the WLAN interfaces might have to be re-added to the bridge */

	return 0;
}

// implement Client mode Enabled
int wlan_setEndpointEnabled(int index)
{
	int ret=UGW_SUCCESS;
	/* load FAPI DB */
	if(fapiWlanFailSafeLoad() != UGW_SUCCESS)
	{
		logger("%s fapiWlanFailSafeLoad failure\n", __FUNCTION__);
		return UGW_FAILURE;
	}

	if(wav_ep_check_nonexist(index)){
		ret += wav_ep_start(index);
		ret += wav_ep_up(index, 1);
	}

	/* save FAPI DB to flash */
	fapiWlanFailSafeStore();

	return ret;
}

// implement Client mode Connect
int wlan_setEndpointConnect(int index, char *apMac, char *ssid, char *security, char *beacon, char *encrypt, char *passwd)
{
	/* load FAPI DB */
	if(fapiWlanFailSafeLoad() != UGW_SUCCESS)
	{
		logger("%s fapiWlanFailSafeLoad failure\n", __FUNCTION__);
		return UGW_FAILURE;
	}

	wav_ep_start(index);
	wav_ep_connect(index, apMac, ssid, security, beacon, encrypt, passwd);

	/* save FAPI DB to flash */
	fapiWlanFailSafeStore();
	return 0;
}

// implement Client mode Connect
int wlan_setEndpointScan(int index){
	/* load FAPI DB */
	if(fapiWlanFailSafeLoad() != UGW_SUCCESS){
		logger("%s fapiWlanFailSafeLoad failure\n", __FUNCTION__);
		return UGW_FAILURE;
	}

	wav_ep_start(index);
	wav_ep_scan(index);

	/* save FAPI DB to flash */
	fapiWlanFailSafeStore();

	return 0;
}

#define DEVICE_ENDPOINT_WPS_VENDOR "Device.WiFi.EndPoint.WPS"
// implement Client mode PBC
int wlan_setEndpointWpsPbcTrigger(int index)
{
	ObjList * wlObj;

	/* load FAPI DB */
	if(fapiWlanFailSafeLoad() != UGW_SUCCESS)
	{
		logger("%s fapiWlanFailSafeLoad failure\n", __FUNCTION__);
		return UGW_FAILURE;
	}

	/* config PBC profile */
	wlObj = (ObjList*)HELP_CREATE_OBJ(SOPT_OBJVALUE);
	help_addObjList(wlObj, DEVICE_ENDPOINT_WPS_VENDOR, 0, 0, 0, 0);
	HELP_EDIT_NODE(wlObj, DEVICE_ENDPOINT_WPS_VENDOR, "X_LANTIQ_COM_Vendor_WPSAction", "PBC", 0, 0);

	if (index == 0) {
		fapi_wlan_endpoint_wps_set("wlan1", wlObj, 0);
	}
	else if (index == 1) {
		fapi_wlan_endpoint_wps_set("wlan3", wlObj, 0);
	}

	HELP_DELETE_OBJ(wlObj, SOPT_OBJVALUE, FREE_OBJLIST);

	/* save FAPI DB to flash */
	fapiWlanFailSafeStore();

	return 0;
}

char *wav_get_security_str(const char *auth, const char *crypto, int weptype){
	if(!strcmp(auth, "open")){
		if(weptype == 2)
			return "WEP-128";
		else if(weptype == 1)
			return "WEP-64";
		else
			return "None";
	}
	else if(!strcmp(auth, "psk2") && !strcmp(crypto, "aes"))
		return "WPA2-Personal";
	else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "aes"))
		return "WPA-WPA2-Personal";
	else if(!strcmp(auth, "pskpsk2") && !strcmp(crypto, "tkip+aes"))
		return "WPA-WPA2-Personal";
	else if(!strcmp(auth, "psk") && !strcmp(crypto, "tkip"))
		return "WPA-Personal";
	else if(!strcmp(auth, "wpa2") && !strcmp(crypto, "aes"))
		return "WPA2-Enterprise";
	else if(!strcmp(auth, "wpawpa2") && !strcmp(crypto, "aes"))
		return "WPA-WPA2-Enterprise";
	else if(!strcmp(auth, "wpawpa2") && !strcmp(crypto, "tkip+aes"))
		return "WPA-WPA2-Enterprise";
	else
		return "";
}

char *wav_get_beacon_type(const char *crypto){
	if(!strcmp(crypto, "tkip"))
		return "WPA";
	else if(!strcmp(crypto, "aes"))
		return "11i";
	else if(!strcmp(crypto, "tkip+aes"))
		return "WPAand11i";
	else
		return "None";
}

char *wav_get_encrypt(const char *crypto){
	if(!strcmp(crypto, "tkip"))
		return "ENC_TKIP";
	else if(!strcmp(crypto, "aes"))
		return "ENC_AES";
	else if(!strcmp(crypto, "tkip+aes"))
		return "ENC_TKIP_AND_AES";
	else
		return "None";
}

int start_repeater(void){
	int wlc_band = nvram_get_int("wlc_band");
	char ap_mac[20] = {0};
	char ap_ssid[40] = {0};
	char ap_auth[40] = {0};
	char ap_crypto[40] = {0};
	char ap_key[40] = {0};
	char ap_security[40] = {0};
	char ap_beacon[40] = {0};
	char ap_encrypt[40] = {0};
	int ap_weptype = 0;

	snprintf(ap_mac, sizeof(ap_mac), "%s", nvram_safe_get("wlc_ap_mac"));
	snprintf(ap_ssid, sizeof(ap_ssid), "%s", nvram_safe_get("wlc_ssid"));
	snprintf(ap_auth, sizeof(ap_auth), "%s", nvram_safe_get("wlc_auth_mode"));
	snprintf(ap_crypto, sizeof(ap_crypto), "%s", nvram_safe_get("wlc_crypto"));
	ap_weptype = nvram_get_int("wlc_wep");
	if(!strcmp(ap_auth, "open") && ap_weptype > 0)
		snprintf(ap_key, sizeof(ap_key), "%s", nvram_safe_get("wlc_wep_key"));
	else
		snprintf(ap_key, sizeof(ap_key), "%s", nvram_safe_get("wlc_wpa_psk"));

	if(strlen(ap_ssid) <= 0){
		_dprintf("%s: no ap_mac or ap_ssid.\n", __func__);
		return -1;
	}

	snprintf(ap_security, sizeof(ap_security), "%s", wav_get_security_str(ap_auth, ap_crypto, ap_weptype));
	snprintf(ap_beacon, sizeof(ap_beacon), "%s", wav_get_beacon_type(ap_crypto));
	snprintf(ap_encrypt, sizeof(ap_encrypt), "%s", wav_get_encrypt(ap_crypto));

	if(strlen(ap_security) <= 0){
		fprintf(stderr, "[warning] not support this auth. mode\n");
		return -1;
	}

	_dprintf("%s: ap_mac=%s, ap_ssid=%s, ap_security=%s, ap_key=%s.\n", __func__, ap_mac, ap_ssid, ap_security, ap_key);
	_dprintf("%s: ap_beacon=%s, ap_encrypt=%s.\n", __func__, ap_beacon, ap_encrypt);
	wlan_setEndpointConnect(wlc_band, ap_mac, ap_ssid, ap_security, ap_beacon, ap_encrypt, ap_key);

	return 0;
}

static unsigned char nibble_hex(char *c)
{
	int val;
	char tmpstr[3];

	tmpstr[2] = '\0';
	memcpy(tmpstr, c, 2);
	val = strtoul(tmpstr, NULL, 16);
	return val;
}

static int atoh(const char *a, unsigned char *e)
{
	char *c = (char *)a;
	int i = 0;

	memset(e, 0, MAX_FRW);
	for (i = 0; i < MAX_FRW; ++i, c += 3){
		if(!isxdigit(*c) || !isxdigit(*(c + 1)) || isxdigit(*(c + 2)))	// should be "AA:BB:CC:DD:..."
			break;
		e[i] = (unsigned char)nibble_hex(c);
	}

	return i;
}

char *htoa(const unsigned char *e, char *a, int len)
{
	char *c = a;
	int i;

	for (i = 0; i < len; ++i){
		if(i)
			*c++ = ':';
		c += sprintf(c, "%02X", e[i] & 0xff);
	}
	return a;
}

int FREAD(unsigned int addr_sa, int len)
{
	unsigned char buffer[MAX_FRW];
	char buffer_h[128];
	memset(buffer, 0, sizeof(buffer));
	memset(buffer_h, 0, sizeof(buffer_h));

	if(FRead(buffer, addr_sa, len) < 0)
		dbg("FREAD: Out of scope\n");
	else {
		if(len > MAX_FRW)
			len = MAX_FRW;
		htoa(buffer, buffer_h, len);
		puts(buffer_h);
	}
	return 0;
}

/*
 * 	write str_hex to offset da
 *	console input:	FWRITE 0x45000 00:11:22:33:44:55:66:77
 *	console output:	00:11:22:33:44:55:66:77
 *
 */
int FWRITE(const char *da, const char *str_hex)
{
	unsigned char ee[MAX_FRW];
	unsigned int addr_da;
	int len;

	addr_da = strtoul(da, NULL, 16);
	if(addr_da && (len = atoh(str_hex, ee))){
		FWrite(ee, addr_da, len);
		FREAD(addr_da, len);
	}
	return 0;
}

//End of new ATE Command
//Ren.B
int check_macmode(const char *str)
{

	if((!str) || (!strcmp(str, "")) || (!strcmp(str, "disabled"))){
		return 0;
	}

	if(strcmp(str, "allow") == 0){
		return 1;
	}

	if(strcmp(str, "deny") == 0){
		return 2;
	}
	return 0;
}

//Ren.E

//Ren.B
void gen_macmode(int mac_filter[], int band, char *prefix)
{
	char temp[128];

	snprintf(temp, sizeof(temp), "%smacmode", prefix);
	mac_filter[0] = check_macmode(nvram_get(temp));
	_dprintf("mac_filter[0] = %d\n", mac_filter[0]);
}

//Ren.E

static inline void __choose_mrate(char *prefix, int *mcast_phy, int *mcast_mcs, int *rate)
{
	int phy = 3, mcs = 7;	/* HTMIX 65/150Mbps */
	*rate=150000;
	char tmp[128];

#ifdef RTCONFIG_IPV6
	switch (get_ipv6_service()){
	default:
		if(!nvram_get_int(ipv6_nvname("ipv6_radvd")))
			break;
		/* fall through */
#ifdef RTCONFIG_6RELAYD
	case IPV6_PASSTHROUGH:
#endif
		if(!strncmp(prefix, "wl0", 3)){
			phy = 2;
			mcs = 2;	/* 2G: OFDM 12Mbps */
			*rate=12000;
		} else {
			phy = 3;
			mcs = 1;	/* 5G: HTMIX 13/30Mbps */
			*rate=30000;
		}
		/* fall through */
	case IPV6_DISABLED:
		break;
	}
#endif

	if(nvram_match(strcat_r(prefix, "nmode_x", tmp), "2") ||	/* legacy mode */
	    strstr(nvram_safe_get(strcat_r(prefix, "crypto", tmp)), "tkip")){	/* tkip */
		/* In such case, choose OFDM instead of HTMIX */
		phy = 2;
		mcs = 4;	/* OFDM 24Mbps */
		*rate=24000;
	}

	*mcast_phy = phy;
	*mcast_mcs = mcs;
}

int bw40_channel_check(int band,char *ext)
{
   	int ch;
 	if(!band)
 	   	ch=nvram_get_int("wl0_channel");
	else
 	   	ch=nvram_get_int("wl1_channel");
	if(ch)
	{
	  if(!band) //2.4G
	  {
		if((ch==1) ||(ch==2) ||(ch==3)||(ch==4))
		{
			if(!strcmp(ext,"MINUS"))
		 	{
				dbG("stage 1: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"PLUS");
			}

		}
		else if(ch>=8)
		{
			if(!strcmp(ext,"PLUS"))
		 	{
				dbG("stage 2: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"MINUS");
			}
		}
		//ch5,6,7:both
	  }
	  else //5G
	  {
		  if((ch == 36) || (ch == 44) || (ch == 52) || (ch == 60) || (ch == 100)
		     || (ch == 108) ||(ch == 116) || (ch == 124) || (ch == 132) || (ch == 149) || (ch ==157))
		  {
			if(!strcmp(ext,"MINUS"))
		 	{
				dbG("stage 1: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"PLUS");
			}

		  }
		  else if((ch == 40) || (ch == 48) || (ch == 56) || (ch == 64) || (ch == 104) || (ch == 112) ||
		         (ch == 120) || (ch == 128) || (ch == 136) || (ch == 153) ||(ch == 161))
	  	  {

			if(!strcmp(ext,"PLUS"))
		 	{
				dbG("stage 2: a  mismatch between %s mode and ch %d => fix mode\n",ext,ch);
				sprintf(ext,"MINUS");
			}

		  }

	  }

	}
	return 1; //pass
}


#define MAX_NO_GUEST 3
/************************ CONSTANTS & MACROS ************************/

/*
 * Constants fof WE-9->15
 */
#define IW15_MAX_FREQUENCIES	16
#define IW15_MAX_BITRATES	8
#define IW15_MAX_TXPOWER	8
#define IW15_MAX_ENCODING_SIZES	8
#define IW15_MAX_SPY		8
#define IW15_MAX_AP		8

/****************************** TYPES ******************************/

/*
 *	Struct iw_range up to WE-15
 */
struct iw15_range {
	__u32 throughput;
	__u32 min_nwid;
	__u32 max_nwid;
	__u16 num_channels;
	__u8 num_frequency;
	struct iw_freq freq[IW15_MAX_FREQUENCIES];
	__s32 sensitivity;
	struct iw_quality max_qual;
	__u8 num_bitrates;
	__s32 bitrate[IW15_MAX_BITRATES];
	__s32 min_rts;
	__s32 max_rts;
	__s32 min_frag;
	__s32 max_frag;
	__s32 min_pmp;
	__s32 max_pmp;
	__s32 min_pmt;
	__s32 max_pmt;
	__u16 pmp_flags;
	__u16 pmt_flags;
	__u16 pm_capa;
	__u16 encoding_size[IW15_MAX_ENCODING_SIZES];
	__u8 num_encoding_sizes;
	__u8 max_encoding_tokens;
	__u16 txpower_capa;
	__u8 num_txpower;
	__s32 txpower[IW15_MAX_TXPOWER];
	__u8 we_version_compiled;
	__u8 we_version_source;
	__u16 retry_capa;
	__u16 retry_flags;
	__u16 r_time_flags;
	__s32 min_retry;
	__s32 max_retry;
	__s32 min_r_time;
	__s32 max_r_time;
	struct iw_quality avg_qual;
};

/*
 * Union for all the versions of iwrange.
 * Fortunately, I mostly only add fields at the end, and big-bang
 * reorganisations are few.
 */
union iw_range_raw {
	struct iw15_range range15;	/* WE 9->15 */
	struct iw_range range;	/* WE 16->current */
};

/*
 * Offsets in iw_range struct
 */
#define iwr15_off(f)	( ((char *) &(((struct iw15_range *) NULL)->f)) - \
			  (char *) NULL)
#define iwr_off(f)	( ((char *) &(((struct iw_range *) NULL)->f)) - \
			  (char *) NULL)

/* Disable runtime version warning in ralink_get_range_info() */
int iw_ignore_version_sp = 0;

void Get_fail_log(char *buf, int size, unsigned int offset)
{
	struct FAIL_LOG fail_log, *log = &fail_log;
	char *p = buf;
	int x, y;

	memset(buf, 0, size);
	FRead((char *)&fail_log, offset, sizeof(fail_log));
	if(log->num == 0 || log->num > FAIL_LOG_MAX){
		return;
	}
	for (x = 0; x < (FAIL_LOG_MAX >> 3); x++){
		for (y = 0; log->bits[x] != 0 && y < 7; y++){
			if(log->bits[x] & (1 << y)){
				p += snprintf(p, size - (p - buf), "%d,",
					      (x << 3) + y);
			}
		}
	}
}


void ate_commit_bootlog(char *err_code)
{
	_dprintf("[ATE][%s][%d] err_code:[%d]\n", err_code);
	nvram_set("Ate_power_on_off_enable", err_code);
	nvram_commit();
}

void platform_start_ate_mode(void)
{
	int model = get_model();

	switch (model){
	case MODEL_BLUECAVE:
		break ;

	default:
		_dprintf("%s: model %d\n", __func__, model);
	}
}

/* Run iwlist command to do site-survey.
 * @ssv_if:
 * @return:
 *     -1:	invalid parameter
 * 	0:	site-survey fail
 * 	1:	site-survey success
 * NOTE:	sitesurvey filelock must be hold by caller!
 */
static int do_sitesurvey(char *ssv_if)
{
	int retry, ssv_ok;
	char *result, *p;
	char *iwlist_argv[] = { "iwlist", ssv_if, "scanning", NULL };

	if (!ssv_if || *ssv_if == '\0')
		return -1;

	for (retry = 0, ssv_ok = 0; !ssv_ok && retry < 1; ++retry) {
		_eval(iwlist_argv, ">/tmp/apscan_wlist", 0, NULL);

		if (!f_exists(APSCAN_WLIST) || !(result = file2str(APSCAN_WLIST)))
			continue;
		if (!(p = strstr(result, "Scan completed"))) {
			if ((p = strchr(result, '\n')))
				*p = '\0';
			if ((p = strchr(result, '\r')))
				*p = '\0';
			_dprintf("%s: iwlist %s scanning fail!! (%s)!\n", __func__, ssv_if, result);
			free(result);
			continue;
		}

		free(result);
		ssv_ok = 1;
	}

	return ssv_ok;
}

/*
int getSiteSurvey(int band, char *ofile)
=> TBD. implement it if we want to support media bridge or repeater mode
*/
int getSiteSurvey(int band, char* ofile)
{
   	int apCount=0;
	char header[128];
	FILE *fp,*ofp;
#define MAX_IE_BUFFER 200
	char buf[target][MAX_IE_BUFFER], set_flag[target];
	int i;
	char *pt1,*pt2;
	char a1[10],a2[10];
	char ssid_str[256];
	char ch[4] = "", ssid[33] = "", address[18] = "", enc[9] = "";
	char auth[32] = "", sig[9] = "", wmode[8] = "";
	int  lock;
#if defined(RTCONFIG_WIRELESSREPEATER)
	char ure_mac[18];
	int wl_authorized = 0;
#endif
	int is_ready;
	char temp1[200];
	char prefix_header[]="Cell xx - Address:";
	char ie_buff[PATH_MAX];
	int len;

	wlan_setEndpointEnabled(band);

	dbG("site survey...\n");
	if (band < 0 || band >= MAX_NR_WL_IF)
		return 0;

	lock = file_lock("sitesurvey");
	do_sitesurvey(get_staifname(band));
	file_unlock(lock);

	if(!(fp = fopen(APSCAN_WLIST, "r")))
		return 0;

	snprintf(header, sizeof(header), "%-4s%-33s%-18s%-9s%-20s%-9s%-8s\n", "Ch", "SSID", "BSSID", "Enc", "Auth", "Siganl(%)", "W-Mode");

	dbg("\n%s", header);

	if((ofp = fopen(ofile, "a")) == NULL){
		fclose(fp);
		return 0;
	}

	apCount = 1;
	while(1){
		is_ready = 0;
		memset(set_flag, 0, sizeof(set_flag));
		memset(buf, 0, sizeof(buf));
		snprintf(prefix_header, sizeof(prefix_header), "Cell %02d - Address:", apCount);

		if(feof(fp))
			break;

		memset(temp1, 0, sizeof(temp1));
		while(fgets(temp1, sizeof(temp1), fp)){
AFTER_GOTTEN_IE:
			if(strstr(temp1, prefix_header) != NULL){
				if(is_ready){
					fseek(fp, -sizeof(temp1), SEEK_CUR);
					break;
				}
				else{
					is_ready = 1;
					snprintf(prefix_header, sizeof(prefix_header), "Cell %02d - Address:", apCount+1);
				}
			}

			if(is_ready){
				for(i = 0; i < target; i++){
					if(strstr(temp1, sitesurvey_field[i]) != NULL && set_flag[i] == 0){
						set_flag[i] = 1;
						memcpy(buf[i], temp1, sizeof(temp1));

						if(i == 5){ // collect all IE rows.
							snprintf(ie_buff, sizeof(ie_buff), "%s", buf[i]);
							len = strlen(ie_buff);

							memset(temp1, 0, sizeof(temp1));
							while(fgets(temp1, sizeof(temp1), fp)){
								if(strstr(temp1, prefix_header) != NULL)
									goto AFTER_GOTTEN_IE;

								if(len+strlen(temp1) >= sizeof(ie_buff))
									break;

								memcpy((ie_buff+len), temp1, sizeof(temp1));
								len += strlen(temp1);

								memset(temp1, 0, sizeof(temp1));
							}
						}

						break;
					}
				}
			}

			memset(temp1, 0, sizeof(temp1));
		}

#if defined(RTCONFIG_CONCURRENTREPEATER)
		if(feof(fp)){
			if(!is_ready)
				break;
		}
#endif

		dbg("\napCount=%d\n",apCount);

		apCount++;

		//ch
		pt1 = strstr(buf[2], "Channel ");
		if(pt1)
		{
			pt2 = strstr(pt1,")");
			memset(ch,0,sizeof(ch));
			strncpy(ch,pt1+strlen("Channel "),pt2-pt1-strlen("Channel "));
		}

		//ssid
		pt1 = strstr(buf[1], "ESSID:");
		if(pt1)
		{
			memset(ssid,0,sizeof(ssid));
			strncpy(ssid,pt1+strlen("ESSID:")+1,strlen(buf[1])-2-(pt1+strlen("ESSID:")+1-buf[1]));
		}

		//bssid
		pt1 = strstr(buf[0], "Address: ");
		if(pt1)
		{
			memset(address,0,sizeof(address));
			strncpy(address,pt1+strlen("Address: "),strlen(buf[0])-(pt1+strlen("Address: ")-buf[0])-1);
		}

		//enc
		memset(enc, 0, sizeof(enc));
		if((pt1 = strstr(buf[4], sitesurvey_field[4])) != NULL){
			pt1 += strlen(sitesurvey_field[4]);
			if(strstr(pt1, "on")){
				if((pt2 = strstr(ie_buff, sitesurvey_field[7])) != NULL){
					if(strstr(pt2, "CCMP TKIP") || strstr(pt2,"TKIP CCMP"))
						strlcpy(enc, "TKIP+AES", sizeof(enc));
					else if(strstr(pt2, "CCMP"))
						strlcpy(enc, "AES", sizeof(enc));
					else
						strlcpy(enc, "TKIP", sizeof(enc));
				}
				else
					strlcpy(enc, "WEP", sizeof(enc));
			}
			else
				strlcpy(enc, "NONE", sizeof(enc));
		}

		//auth
		memset(auth, 0, sizeof(auth));
		if((pt1 = strstr(ie_buff, sitesurvey_field[5])) != NULL){
			int wpa = 0;

			pt1 += strlen(sitesurvey_field[5]);

			if(strstr(pt1, "WPA2 ") != NULL)
				wpa += 2;
			if(strstr(pt1, "WPA ") != NULL)
				wpa += 1;

			if(wpa == 3)
				strlcpy(auth, "WPA-WPA2-", sizeof(auth));
			else if(wpa == 2)
				strlcpy(auth, "WPA2-", sizeof(auth));
			else if(wpa == 1)
				strlcpy(auth, "WPA-", sizeof(auth));

			if((pt2 = strstr(ie_buff, sitesurvey_field[6])) != NULL){
				pt2 += strlen(sitesurvey_field[6]);
				if(strstr(pt2, "PSK") != NULL)
					strcat(auth, "Personal");
				else //802.1x
					strcat(auth, "Enterprise");
			}
			else{
				if(!strcmp(enc, "WEP"))
					strlcpy(auth, "Unknown", sizeof(auth));
				else
					strlcpy(auth, "Open System", sizeof(auth));
			}
		}

		//sig
		pt1 = strstr(buf[3], "Quality=");
		pt2 = NULL;
		if (pt1 != NULL)
			pt2 = strstr(pt1,"/");
		if(pt1 && pt2)
		{
			memset(a1, 0, sizeof(a1));
			memset(a2, 0, sizeof(a2));
			strncpy(a1, pt1+strlen("Quality="), pt2-pt1-strlen("Quality="));
			strncpy(a2, pt2+1, strstr(pt2," ")-(pt2+1));
			snprintf(sig, sizeof(sig), "%d", 100 * (safe_atoi(a1) + 6) / (safe_atoi(a2) + 6));
		}

		//wmode
		memset(wmode,0,sizeof(wmode));
		pt1=strstr(buf[8],"phy_mode=");
		if(pt1)
		{

			if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11AC_VHT"))!=NULL)
				strlcpy(wmode, "ac", sizeof(wmode));
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11A"))!=NULL
					|| (pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_TURBO_A"))!=NULL)
				strlcpy(wmode, "a", sizeof(wmode));
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11B"))!=NULL)
				strlcpy(wmode, "b", sizeof(wmode));
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11G"))!=NULL
					|| (pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_TURBO_G"))!=NULL)
				strlcpy(wmode, "bg", sizeof(wmode));
			else if((pt2=strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11NA"))!=NULL)
				strlcpy(wmode, "an", sizeof(wmode));
			else if(strstr(pt1+strlen("phy_mode="),"IEEE80211_MODE_11NG"))
				strlcpy(wmode, "bgn", sizeof(wmode));
		}
		else
			strlcpy(wmode, "unknown", sizeof(wmode));

		dbg("%-4s%-33s%-18s%-9s%-20s%-9s%-8s\n",ch,ssid,address,enc,auth,sig,wmode);

		if(safe_atoi(ch)<0)
			fprintf(ofp, "\"ERR_BAND\",");
		else if(safe_atoi(ch)>0 && safe_atoi(ch)<14)
			fprintf(ofp, "\"2G\",");
		else if(safe_atoi(ch)>14 && safe_atoi(ch)<166)
			fprintf(ofp, "\"5G\",");
		else
			fprintf(ofp, "\"ERR_BAND\",");


		memset(ssid_str, 0, sizeof(ssid_str));
#if defined(RTCONFIG_UTF8_SSID)
		char_to_ascii_with_utf8(ssid_str, trim_r(ssid));
#else
		char_to_ascii(ssid_str, trim_r(ssid));
#endif

		if(strlen(ssid)==0)
			fprintf(ofp, "\"\",");
		else
			fprintf(ofp, "\"%s\",", ssid_str);

		fprintf(ofp, "\"%d\",", safe_atoi(ch));

		fprintf(ofp, "\"%s\",",auth);

		fprintf(ofp, "\"%s\",", enc);

		fprintf(ofp, "\"%d\",", safe_atoi(sig));

		fprintf(ofp, "\"%s\",", address);

		fprintf(ofp, "\"%s\",", wmode);

#ifdef RTCONFIG_WIRELESSREPEATER
		//memset(ure_mac, 0x0, 18);
		//snprintf(ure_mac, sizeof(ure_mac), "%02X:%02X:%02X:%02X:%02X:%02X",xxxx);
		if (strcmp(nvram_safe_get(wlc_nvname("ssid")), ssid)){
			if (strcmp(ssid, ""))
				fprintf(ofp, "\"%s\"", "0");				// none
			else if (!strcmp(ure_mac, address)){
				// hidden AP (null SSID)
				if (strstr(nvram_safe_get(wlc_nvname("akm")), "psk")!=NULL){
					if (wl_authorized){
						// in profile, connected
						fprintf(ofp, "\"%s\"", "4");
					}else{
						// in profile, connecting
						fprintf(ofp, "\"%s\"", "5");
					}
				}else{
					// in profile, connected
					fprintf(ofp, "\"%s\"", "4");
				}
			}else{
				// hidden AP (null SSID)
				fprintf(ofp, "\"%s\"", "0");				// none
			}
		}else if (!strcmp(nvram_safe_get(wlc_nvname("ssid")), ssid)){
			if (!strlen(ure_mac)){
				// in profile, disconnected
				fprintf(ofp, "\"%s\",", "1");
			}else if (!strcmp(ure_mac, address)){
				if (strstr(nvram_safe_get(wlc_nvname("akm")), "psk")!=NULL){
					if (wl_authorized){
						// in profile, connected
						fprintf(ofp, "\"%s\"", "2");
					}else{
						// in profile, connecting
						fprintf(ofp, "\"%s\"", "3");
					}
				}else{
					// in profile, connected
					fprintf(ofp, "\"%s\"", "2");
				}
			}else{
				fprintf(ofp, "\"%s\"", "0");				// impossible...
			}
		}else{
			// wl0_ssid is empty
			fprintf(ofp, "\"%s\"", "0");
		}
#else
		fprintf(ofp, "\"%s\"", "0");
#endif
		fprintf(ofp, "\n");
	}

	fclose(fp);
	fclose(ofp);

	return 1;
}

char *getStaMAC(char *buf, int buflen)
{
	char cmdbuf[512];
	FILE *fp;
	int len, unit;
	char *pt1,*pt2;

	unit = nvram_get_int("wlc_band");

	snprintf(cmdbuf, sizeof(cmdbuf), "ifconfig %s", get_staifname(unit));

	fp = popen(cmdbuf, "r");
	if(fp){
		memset(buf, 0, buflen);
		len = fread(buf, 1, buflen, fp);
		pclose(fp);
		if(len > 1){
			buf[len-1] = '\0';
			pt1 = strstr(buf, "HWaddr ");
			if(pt1)
			{
				pt2 = pt1 + strlen("HWaddr ");
				*(pt2+17)='\0';
				return pt2;
			}
		}
	}

	return NULL;
}

unsigned int getPapState(int unit)
{
	char buf[8192];
	FILE *fp;
	int len;
	char *pt1, *pt2;

	snprintf(buf, sizeof(buf), "iwconfig %s", get_staifname(unit));
	fp = popen(buf, "r");
	if(fp){
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if(len > 1){
			buf[len-1] = '\0';
			pt1 = strstr(buf, "Access Point:");
			if(pt1){
				pt2 = pt1 + strlen("Access Point:");
				pt1 = strstr(pt2, "Not-Associated");
				if(pt1)
				{
					snprintf(buf, sizeof(buf), "ifconfig | grep %s", get_staifname(unit));
					fp = popen(buf, "r");
					if(fp)
					{
						memset(buf, 0, sizeof(buf));
						len = fread(buf, 1, sizeof(buf), fp);
						pclose(fp);
						if(len>=1)
							return 0;
						else
							return 3;
					}
					else
						return 0; //init
				}
				else
					return 2; //connect and auth ?????
			}
		}
	}

	return 3; // stop
}

// TODO: wlcconnect_main
//	wireless ap monitor to connect to ap
//	when wlc_list, then connect to it according to priority
int wlcconnect_core(void)
{
	int unit, ret;

	unit = nvram_get_int("wlc_band");
	ret = getPapState(unit);
	if(ret != 2) //connected
		dbG("check..wlconnect=%d \n", ret);

	return ret;
}

int wlcscan_core(char *ofile, char *wif){
#if 0
	wlan_setEndpointScan(get_wifname_band(wif));
#else
	int ret, count;

	count = 0;
	while((ret = getSiteSurvey(get_wifname_band(wif), ofile) == 0) && count++ < 2){
		dbg("[rc] set scan results command failed, retry %d\n", count);
		sleep(1);
	}
#endif

	return 0;
}

#define UBIFS_VOL_NAME	"jffs2"

int ubi_remove_dev(const char *node, int ubi_dev)
{
	int fd, ret;

	fd = open(node, O_RDONLY);
	if(fd == -1){
		fprintf(stderr, "[%s][%d] cannot open", node, ubi_dev);
		return -1;
	}
	ret = ioctl(fd, UBI_IOCDET, &ubi_dev);
	if(ret == -1)
		goto out_close;

#ifdef UDEV_SETTLE_HACK
//	if(system("udevsettle") == -1)
//		return -1;
	usleep(100000);
#endif

out_close:
	close(fd);
	return ret;
}

void check_ubi_partition(void)
{
	int dev, part, size;
	int ret = 0;

	/* UBIFS_VOL_NAME: jffs2 */
	fprintf(stderr, "... check_ubi_partition() ...\n");
	if(mknod("/dev/ubi1", S_IFCHR | 0660, makedev(248, 0)))
		perror("## mknod " "/dev/ubi1");
	if(mknod("/dev/ubi1_0", S_IFCHR | 0660, makedev(248, 1)))
		perror("## mknod " "/dev/ubi1_0");
	fprintf(stderr, "... start ubiattach ...\n");
	system("ubiattach /dev/ubi_ctrl -m 8");
	while (pids("ubiattach")){
		fprintf(stderr, "... waiting ubiattach finished ...\n");
		sleep(1);
	}
	fprintf(stderr, "... ubiattach finished ...\n");
	ret = ubi_getinfo(UBIFS_VOL_NAME, &dev, &part, &size);
	if(ret < 0 || ret == 1){

		fprintf(stderr, "... detach mtd8 ...\n");
		system("ubidetach -p /dev/mtd8");
		fprintf(stderr, "... start flash_erase ...\n");
		system("flash_erase /dev/mtd8 0 0");
		while (pids("flash_erase")){
			fprintf(stderr, "... waiting flash_erase finished ...\n");
			sleep(1);
		}
		fprintf(stderr, "... flash_erase finished ...\n");

		fprintf(stderr, "... start ubiattach ...\n");
		system("ubiattach /dev/ubi_ctrl -m 8");
		while (pids("ubiattach")){
			fprintf(stderr, "... waiting ubiattach finished ...\n");
			sleep(1);
		}
		fprintf(stderr, "... ubiattach finished ...\n");

		fprintf(stderr, "... start ubimkvol ...\n");
		system("ubimkvol /dev/ubi1 -N jffs2 -m");
		while (pids("ubimkvol")){
			fprintf(stderr, "... waiting ubimkvol finished ...\n");
			sleep(1);
		}
		fprintf(stderr, "... ubimkvol finished ...\n");
	}
	fprintf(stderr, "... ubi_getinfo() finished ...\n");
}

/*
	USB2: return 0
	USB3: return 1
	unknow mode: return -1;
 */
int get_usb_mode(void)
{
	FILE *fp = NULL;
	char buffer[64] = {0};
	char *value;
	unsigned int mem_r;
	int ret;

	memset(buffer, 0, sizeof(buffer));
	fp = popen("mem -s 0x1a40c020 -du", "r");
	if(fp){
		fgets(buffer, sizeof(buffer), fp);
		value = strstr(buffer, ":");
		if(value != NULL){
			value++;
			mem_r = strtol(value, &value, 16);
			_dprintf("Read 0x1a40c020 as [0x%08x]\n", mem_r);
			if(mem_r == 0x00002000) ret = 0;
			else if (mem_r == 0x0) ret = 1;
			else ret = -1;
		}
		pclose(fp);
	}
	return ret;
}

void set_usb3_to_usb2(void)
{
	if(get_usb_mode() == 0){
		_dprintf("[usb] already USB2 mode, skip\n");
		return;
	}
	_dprintf("[wait] usb3 to usb2 start\n");
	__ejusb_main("-1", 0);
	notify_rc_after_wait("restart_nasapps");
	// sleep(1);
	_dprintf("[warning] power off usb and change mode\n");
	usb_pwr_ctl(0);
	// sleep(1);
	system("mem -s 0x1a40c020 -uw 0x2000");
	// sleep(1);
	usb_pwr_ctl(1);
	// sleep(1);
	_dprintf("[wait] usb3 to usb2 end\n");
}

void set_usb2_to_usb3(void)
{
	if(get_usb_mode() == 1){
		_dprintf("[usb] already USB3 mode, skip\n");
		return;
	}
	_dprintf("[wait] usb2 to usb3 start\n");
	__ejusb_main("-1", 0);
	notify_rc_after_wait("restart_nasapps");
	// sleep(1);
	_dprintf("[warning] power off usb and change mode\n");
	usb_pwr_ctl(0);
	// sleep(1);
	system("mem -s 0x1a40c020 -uw 0x0");
	// sleep(1);
	usb_pwr_ctl(1);
	// sleep(1);
	_dprintf("[wait] usb2 to usb3 end\n");
}

void gen_config_sh(void)
{
	system("cp -f /rom/opt/lantiq/etc/rc.d/config.sh /etc/; cd /etc/rc.d; ln -s ../config.sh config.sh");

	return;
}

void usb_pwr_ctl(int onoff)
{
        FILE *fp = NULL;
        char buffer[64] = {0};
        char cmd[64];
        char *value;
        unsigned int mem_r, mem_w;

        memset(buffer, 0, sizeof(buffer));
        fp = popen("mem -s 0x16c00000 -du", "r");
        if(fp){
                fgets(buffer, sizeof(buffer), fp);
                value = strstr(buffer, ":");
                if(value != NULL){
                        value++;
                        mem_r = strtol(value, &value, 16);
                        _dprintf("Read 0x16c00000 as [0x%08x]\n", mem_r);
			if(onoff == 1){ // power on
				_dprintf("Set usb power [on]\n");
				mem_w = mem_r | 0x00000080;
			}
			else {		// power off
				_dprintf("Set usb power [off]\n");
				mem_w = mem_r & 0xffffff7f;
			}
                        _dprintf("Write 0x16c00000 as [0x%08x]\n", mem_w);
                        snprintf(cmd, sizeof(cmd), "mem -s 0x16c00000 -w 0x%08x -u", mem_w);
                        system(cmd);
                }

                pclose(fp);
        }

}

#if defined(RTCONFIG_AMAS)
#ifdef RTCONFIG_BHCOST_OPT
void apply_config_to_driver(int band)
{
	trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_SET_STA_CONFIG);
}
#else
#if defined(RTCONFIG_DWB)
void apply_config_to_driver()
{
	trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_SET_STA_CONFIG);
}
#endif
#endif
int Pty_get_wlc_status(char *wif)
{
return 0;
}

#ifdef RTCONFIG_BHCOST_OPT
void Pty_start_wlc_connect(int band, char *bssid)
{
	int ifindex = (band == 0 ? 1 : 3);
	char tmp[32] = {0};

	snprintf(tmp, sizeof(tmp), "wlan%d", ifindex);

	if(!is_if_up(tmp))
		eval("ifconfig", tmp, "up");
}

/**
 * @brief amas_wlcconnect conneced to node successfully.
 *
 * @param band Band index
 */
void post_wlc_connected(int band) {
	// TODO
	return;
}

/**
 * @brief Post sent action to amas_wlcconnect
 *
 */
void post_sent_action() {}

/**
 * @brief After updated wlcX_status
 *
 */
void post_update_status() {}

/**
 * @brief Backhaul changed sysdeps function
 *
 * @param iftype BH defif
 */
void post_bh_changed(int iftype) {

}

void post_addif_bridge(int iftype)
{
	int index = 0, i = 0;
	char wif[8] = {0}, cmd[64] = {0}, *next = NULL;


	if (iftype == ETH1_U) {
		snprintf(cmd, 64, "ppacmd addlan -i eth1");
		doSystem(cmd);
		return;
	}

	/* When No any interface get hop value. Device will add the highest priotity to bridge.
	   But we cannot know whitch interface is the highest priority. So we will try to set all
	   wlc interfaces in to /proc/l2nat/dev. Even if the interface is not the highest priority,
	   the device wouldn't get any side effect. */
	if (iftype == 0)
		index = 7; // 000

	if (iftype & WL2G_U)
		index |= 1; // 001
	if (iftype & WL5G1_U)
		index |= 2; // 010
	if (iftype & WL5G2_U)
		index |= 4; // 100

	foreach (wif, nvram_safe_get("sta_ifnames"), next) {
		if (index & (1 << i)) {
			snprintf(cmd, 64, "echo \"add %s\" > /proc/l2nat/dev", wif);
			doSystem(cmd);
			snprintf(cmd, 64, "ppacmd addlan -i %s", wif);
			doSystem(cmd);
		}
		i++;
	}
	return;
}

/**
 * @brief Get the uplinkports status
 *
 * @param ifname ethernet uplink ifname
 * @return int connnected(1) or not(0)
 */
int get_uplinkports_status(char *ifname)
{
	int wan_unit = wan_primary_ifunit();

	return get_wanports_status(wan_unit);
}

/**
 * @brief Get DFS status
 *
 * @param band Band
 * @return int Status. 1: CAC 0: Idle
 */
int amas_dfs_status(int band)
{
	return 0;
}

#else
void Pty_start_wlc_connect(int band)
{
	int ifindex = (band == 0 ? 1 : 3);
	char tmp[32] = {0};

	snprintf(tmp, sizeof(tmp), "wlan%d", ifindex);

	if(!is_if_up(tmp))
		eval("ifconfig", tmp, "up");
}

void post_addif_bridge(int iftype)
{
	int index = 0, i = 0;
	char wif[8] = {0}, cmd[64] = {0}, *next = NULL;


	if (iftype == ETH) {
		snprintf(cmd, 64, "ppacmd addlan -i eth1");
		doSystem(cmd);
		return;
	}

	/* When No any interface get hop value. Device will add the highest priotity to bridge.
	   But we cannot know whitch interface is the highest priority. So we will try to set all
	   wlc interfaces in to /proc/l2nat/dev. Even if the interface is not the highest priority,
	   the device wouldn't get any side effect. */
	if (iftype == 0)
		index = 7; // 000

	if (iftype & WL_2G)
		index |= 1; // 001
	if (iftype & WL_5G)
		index |= 2; // 010
	if (iftype & WL_5G_1)
		index |= 4; // 100

	foreach (wif, nvram_safe_get("sta_ifnames"), next) {
		if (index & (1 << i)) {
			snprintf(cmd, 64, "echo \"add %s\" > /proc/l2nat/dev", wif);
			doSystem(cmd);
			snprintf(cmd, 64, "ppacmd addlan -i %s", wif);
			doSystem(cmd);
		}
		i++;
	}
	return;
}
#endif

#define RSSI_NO_SIGNAL	-91
int get_psta_rssi(int unit)
{
	FILE *fp = NULL;
	char buf[128] = {0};
	int rssi = 0, antenna = 0, antenna_rssi = 0;
	static int pre_rssi[3] = {RSSI_NO_SIGNAL, RSSI_NO_SIGNAL, RSSI_NO_SIGNAL}; // 2.4G, 5G-1, 5G-2

	snprintf(buf, sizeof(buf), "/proc/net/mtlk/%s/PeerFlowStatus", get_staifname(unit));
	fp = fopen(buf, "r");

	if (fp) {
		memset(buf, 0, sizeof(buf));
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "RSSI")) {
				sscanf(buf, "%d", &antenna_rssi);
				rssi += antenna_rssi;
				antenna++;
			}
		}
		fclose(fp);
	}
	else {
		pre_rssi[unit] = RSSI_NO_SIGNAL;
		return RSSI_NO_SIGNAL;
	}

	if (antenna == 0) {
		pre_rssi[unit] = RSSI_NO_SIGNAL;
		return RSSI_NO_SIGNAL;
	}

	rssi = rssi / antenna;
	if (rssi == -128)
		rssi = pre_rssi[unit];
	else {
		if (rssi >= 0)
			rssi = -1;
		else if (rssi < RSSI_NO_SIGNAL)
			rssi = RSSI_NO_SIGNAL;

		pre_rssi[unit] = rssi;
	}
	return rssi;
}

void Pty_stop_wlc_connect(int band)
{
	int ifindex = (band == 0 ? 1 : 3);
	char tmp[32] = {0};

	snprintf(tmp, sizeof(tmp), "wlan%d", ifindex);

	if (is_if_up(tmp))
		eval("ifconfig", tmp, "down");
}

int Pty_get_upstream_rssi(int band)
{
	return get_psta_rssi(band);
}

int get_psta_status(int unit)
{
	unsigned int ret=0;

	ret = getPapState(unit);
	//_dprintf("%s: band=%d. ret %d\n", __func__, unit,ret);
	return ret;
}

/* TODO */
void wlconf_pre()
{
#if defined(RTCONFIG_AMAS)
	generate_wl_para(0,-1);
	generate_wl_para(1,-1);
#endif
}

/* return value > 0 means service is enabled */
int get_wlan_service_status(int bssidx, int vifidx)
{
	int wave_unit;
	char status[10]={0};
	int enable=0;
	char wl_radio[] = "wlXXXX_radio";
	//_dprintf("*\n**\n***\n****\n*****\n******\n*******\n");
	//_dprintf("get_wlan_service_status %d %d\n", bssidx, vifidx);
	//_dprintf("*******\n******\n*****\n****\n***\n**\n*\n");
	wave_unit = wl_wave_unit(bssidx);

	snprintf(wl_radio, sizeof(wl_radio), "wl%d_radio", bssidx);
	if (nvram_get_int(wl_radio) == 0)
		return -2;

	if(vifidx > 0){
		if(bssidx == 0) wave_unit = VAP_2G_START + vifidx;
		else if(bssidx ==1) wave_unit = VAP_5G_START + vifidx;
	}

	enable = wave_is_radio_on(bssidx,vifidx);

	//_dprintf("wave_is_radio_on unit %d enable = %d\n",wave_unit,enable);

	return enable;
}

void set_wlan_service_status(int bssidx, int vifidx, int enabled)
{
	int count;
	char wl_radio[] = "wlXXXX_radio";

	count = 0;
	while(nvram_get_int("wave_ready") == 0){
		_dprintf("[%s][%d] wave_ready==0, wait... [%d][%d][%d]\n",
			__func__, __LINE__, bssidx, vifidx, enabled);
		sleep(10);
		count++;
		if(count > 2){
			_dprintf("[%s][%d] wait wave_ready=1 over 20 seconds,"
				" please check wave_monitor status, skip [%d][%d][%d]\n",
				__func__, __LINE__, bssidx, vifidx, enabled);
			return;
		}
	}

	snprintf(wl_radio, sizeof(wl_radio), "wl%d_radio", bssidx);
	if (nvram_get_int(wl_radio) == 0)
		return;

	while(nvram_get_int("wave_action")!=WAVE_ACTION_IDLE){
		_dprintf("wave_action != IDLE, waint. [set_wlan_service_status]\n");
		sleep(1);
	}

	if(bssidx == 0 && enabled == 1){
		trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_RE_AP2G_ON);
	}else if(bssidx == 0 && enabled == 0){
		trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_RE_AP2G_OFF);
	}else if(bssidx == 1 && enabled == 1){
		trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_RE_AP5G_ON);
	}else if(bssidx == 1 && enabled == 0){
		trigger_wave_monitor(__func__, __LINE__, WAVE_ACTION_RE_AP5G_OFF);
	}

	// sleep(10);	/* waiting wave_monitor finished */

	return ;
}

void pre_addif_bridge(int iftype)
{
	char wif[32] = {0}, *next = NULL;

	/* Remove wlc interfaces from ppa LAN list */
	foreach (wif, nvram_safe_get("sta_phy_ifnames"), next) {
		eval("ppacmd", "dellan", "-i", wif);
	}
	foreach (wif, nvram_safe_get("eth_ifnames"), next) {
		eval("ppacmd", "dellan", "-i", wif);
	}
	return;
}

void pre_delif_bridge(int iftype)
{

}

void post_delif_bridge(int iftype)
{

}

int get_radar_status(int bssidx)
{
	if(bssidx == 0)
		return 0;
	return nvram_get_int("radar_status");
}
#endif

#ifdef LANTIQ_BSD
void bandstr_sync_wl_settings(void)
{
	char prefix[]="wlXXXXXXX_";
	char prefix2[]="wlXXXXXXX_";
	char tmp[100], tmp2[100];
	int unit = 0;
	int i;
	int wlif_count = num_of_wl_if();

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	for (i = unit + 1; i < wlif_count; i++) {
		snprintf(prefix2, sizeof(prefix2), "wl%d_", i);
			nvram_set(strcat_r(prefix2, "ssid", tmp2), nvram_safe_get(strcat_r(prefix, "ssid", tmp)));
			nvram_set(strcat_r(prefix2, "auth_mode_x", tmp2), nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)));
			nvram_set(strcat_r(prefix2, "wep_x", tmp2), nvram_safe_get(strcat_r(prefix, "wep_x", tmp)));
			nvram_set(strcat_r(prefix2, "key", tmp2), nvram_safe_get(strcat_r(prefix, "key", tmp)));
			nvram_set(strcat_r(prefix2, "key1", tmp2), nvram_safe_get(strcat_r(prefix, "key1", tmp)));
			nvram_set(strcat_r(prefix2, "key2", tmp2), nvram_safe_get(strcat_r(prefix, "key2", tmp)));
			nvram_set(strcat_r(prefix2, "key3", tmp2), nvram_safe_get(strcat_r(prefix, "key3", tmp)));
			nvram_set(strcat_r(prefix2, "key4", tmp2), nvram_safe_get(strcat_r(prefix, "key4", tmp)));
			nvram_set(strcat_r(prefix2, "phrase_x", tmp2), nvram_safe_get(strcat_r(prefix, "phrase_x", tmp)));
			nvram_set(strcat_r(prefix2, "crypto", tmp2), nvram_safe_get(strcat_r(prefix, "crypto", tmp)));
			nvram_set(strcat_r(prefix2, "wpa_psk", tmp2), nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)));
			nvram_set(strcat_r(prefix2, "radius_ipaddr", tmp2), nvram_safe_get(strcat_r(prefix, "radius_ipaddr", tmp)));
			nvram_set(strcat_r(prefix2, "radius_key", tmp2), nvram_safe_get(strcat_r(prefix, "radius_key", tmp)));
			nvram_set(strcat_r(prefix2, "radius_port", tmp2), nvram_safe_get(strcat_r(prefix, "radius_port", tmp)));
			nvram_set(strcat_r(prefix2, "closed", tmp2), nvram_safe_get(strcat_r(prefix, "closed", tmp)));
		}
}
#endif

#ifdef RTCONFIG_WPS_ENROLLEE
void start_wsc_enrollee(void)
{
	int retVal = 0;

	nvram_set("wps_enrollee", "1");

	doSystem("wpa_cli -i%s wps_pbc", get_staifname(0));

	/*if((retVal = wlan_setEndpointEnabled(0)) != 0) {
		_dprintf("band %d(wlan%d) wlan_setEndpointEnabled failed: %d\n", 0, 0, retVal);
		return;
	}

	if((retVal = wlan_setEndpointWpsPbcTrigger(0)) != 0)
		_dprintf("band %d(wlan%d) wlan_setEndpointWpsPbcTrigger failed: %d\n", 0, 0, retVal);*/
}

void stop_wsc_enrollee(void)
{
	int i;
	char word[256], *next, ifnames[128];
	char fpath[32];

	i = 0;
	strcpy(ifnames, nvram_safe_get("wl_ifnames"));
	foreach(word, ifnames, next) {
		if (i >= MAX_NR_WL_IF)
			break;

		doSystem("wpa_cli -i%s wps_cancel", get_staifname(i));

		/*if (sw_mode() == SW_MODE_ROUTER
				|| sw_mode() == SW_MODE_AP) {
			sprintf(fpath, "/var/run/wifi-sta%d.pid", i);
			kill_pidfile_tk(fpath);
			unlink(fpath);
			sprintf(fpath, "/etc/Wireless/conf/wpa_supplicant-sta%d.conf", i);
			unlink(fpath);

			doSystem("ifconfig sta%d down", i);
			doSystem("wlanconfig sta%d destroy", i);
		}*/

		i++;
	}
}

#ifdef RTCONFIG_WIFI_CLONE
void wifi_clone(int unit)
{
	char buf[512];
	FILE *fp;
	int len;
	char *pt1, *pt2;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	sprintf(buf, "/etc/Wireless/conf/wpa_supplicant-sta%d.conf", unit);
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	fp = fopen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		fclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			//SSID
			pt1 = strstr(buf, "ssid=\"");
			if (pt1) {
				pt2 = pt1 + strlen("ssid=\"");
				pt1 = strstr(pt2, "\"");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
					nvram_set(strcat_r(prefix, "ssid", tmp), pt2);
				}
			}
					nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
			//PSK
			pt2 = pt1 + 1;
			pt1 = strstr(pt2, "psk=\"");
			if (pt1) {	//WPA2-PSK
				pt2 = pt1 + strlen("psk=\"");
				pt1 = strstr(pt2, "\"");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
					nvram_set(strcat_r(prefix, "wpa_psk", tmp), pt2);
					nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "psk2");
					nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
				}
			}
			else {		//OPEN
				nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "open");
				nvram_set(strcat_r(prefix, "wep_x", tmp), "0");
			}
			nvram_set("x_Setting", "1");
			nvram_commit();
		}
	}
}
#endif //RTCONFIG_WIFI_CLONE

char *getWscStatus_enrollee(int unit)
{
	char buf[512];
	FILE *fp;
	int len;
	char *pt1, *pt2;

	sprintf(buf, "wpa_cli -i%s status", get_staifname(unit));
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "wpa_state=");
			if (pt1) {
				pt2 = pt1 + strlen("wpa_state=");
				pt1 = strstr(pt2, "address=");
				if (pt1) {
					*pt1 = '\0';
					chomp(pt2);
				}
				return pt2;
			}
		}
	}

	return "";
}
#endif //RTCONFIG_WPS_ENROLLEE
#if defined(RTCONFIG_AMAS)
#if 0
#ifdef RTCONFIG_BCMARM
	struct ether_addr bssid;
	struct ether_addr bssid_org;
#endif
#endif
int Pty_procedure_check(int unit, int wlif_count)
{
	//no need in lantiq
	return 0;
}
extern int g_upgrade;
int is_default(void)
{
	if (g_reboot || g_upgrade)
		return 0;

	if (IS_ATE_FACTORY_MODE())
		return 0;

	if ( (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1) )
		return 0;

	return 1;
}

int no_need_obd(void)
{
	if (g_reboot || g_upgrade)
		return -1;

	if (IS_ATE_FACTORY_MODE())
		return -1;

	if (!is_router_mode() || (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1))
		return -1;

	if (nvram_get_int("wave_ready") == 0)
		return -1;

	return pids("obd");
}

int no_need_obdeth(void)
{
	if (g_reboot || g_upgrade)
		return -1;

	if (IS_ATE_FACTORY_MODE())
		return -1;

	if (!is_router_mode() || (nvram_get_int("obd_Setting") == 1) || (nvram_get_int("x_Setting") == 1) || (nvram_get_int("obdeth_Setting") == 1))
		return -1;

	if (nvram_get_int("wave_ready") == 0)
		return -1;

	return pids("obd_eth");
}

void amas_wait_wifi_ready(void)
{
	while( !nvram_get_int("wave_ready") )
		sleep(5);
}
#endif

#if defined(RTCONFIG_LANWAN_LED) || defined(RTCONFIG_LAN4WAN_LED)
int LanWanLedCtrl(void)
{
#ifdef RTCONFIG_LANWAN_LED
	if(get_lanports_status() && !inhibit_led_on())
		led_control(LED_LAN, LED_ON);
	else
		led_control(LED_LAN, LED_OFF);
#endif

	return 1;
}
#endif

#ifdef RTCONFIG_AMAS
/**
 * @brief Set AMAS relate features interface index
 *
 */
void init_amas_subunit()
{
	// TODO
	int model = get_model();

#ifdef RTCONFIG_FRONTHAUL_DWB
	int re_fh_subunit, cap_fh_subunit;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
	int re_prelink_subunit, cap_prelink_subunit;
#endif

	switch (model)
	{
		default:
#ifdef RTCONFIG_FRONTHAUL_DWB
			cap_fh_subunit = 2;
			re_fh_subunit = 3;
#endif
#ifdef RTCONFIG_MSSID_PRELINK
			cap_prelink_subunit = 2;
			re_prelink_subunit = 3;
#endif
			_dprintf("init_amas_subunit: Set default value.\n");
	}

#ifdef RTCONFIG_FRONTHAUL_DWB
	nvram_set_int("fh_cap_mssid_subunit", cap_fh_subunit);
	nvram_set_int("fh_re_mssid_subunit", re_fh_subunit);
#endif
#ifdef RTCONFIG_MSSID_PRELINK
	nvram_set_int("plk_cap_subunit", cap_prelink_subunit);
	nvram_set_int("plk_re_subunit", re_prelink_subunit);
#endif
}
#endif
extern int get_wifi_country_code_tmp(char *ori_countrycode, char *output, int len){
	return -1;
}
