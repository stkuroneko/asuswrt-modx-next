/*
 *	ble data encrypt
*/

#include "bleencrypt.h"

#ifdef ENCRYPT
#define SSL_VERSION     (SSLeay_version(SSLEAY_VERSION))
#else
#define SSL_VERSION     ""
#endif

struct api_handler api_handlers[] = {
	{ BLECMD_REQ_PUBLICKEY,			NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseReqPublicKey },
	{ BLECMD_REQ_SERVERNONCE,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReqServerNonce,	PackBLEResponseReqServerNonce },
	{ BLECMD_APPLY,				NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_RESET,				NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_GET_WAN_STATUS,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetWanStatus },
	{ BLECMD_GET_WIFI_STATUS,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetWifiStatus },
	{ BLECMD_SET_WAN_TYPE,			"wan_proto",			"restart_wan_if 0",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_PPPOE_NAME,		"wan_pppoe_username",		"restart_wan_if 0",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_PPPOE_PWD,		"wan_pppoe_passwd",		"restart_wan_if 0",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_IPADDR,		"wan_ipaddr_x",			"restart_wan_if 0",		BLE_DATA_TYPE_IP,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_SUBNET_MASK,		"wan_netmask_x",		"restart_wan_if 0",		BLE_DATA_TYPE_IP,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_GATEWAY,		"wan_gateway_x",		"restart_wan_if 0",		BLE_DATA_TYPE_IP,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_DNS1,			"wan_dns1_x",			"restart_wan_if 0",		BLE_DATA_TYPE_IP,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_DNS2,			"wan_dns2_x",			"restart_wan_if 0",		BLE_DATA_TYPE_IP,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_PORT,			"bt_wanport",			NULL,				BLE_DATA_TYPE_INTEGER,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WIFI_NAME,			"wlc_ssid",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WIFI_PWD,			"wlc_wpa_psk",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_GROUP_ID,			"cfg_group",			"restart_cfgsync",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_ADMIN_NAME,		"http_username",		"chpass;restart_ftpsamba",	BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_ADMIN_PWD,			"http_passwd",			"chpass;restart_ftpsamba",	BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_USER_LOCATION,		"cfg_alias",			NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_USER_PLACE,		"bt_user_place",		NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_SW_MODE,			"sw_mode",			"ble_qis_done",			BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WAN_DNS_ENABLE,		"wan_dnsenable_x",		"restart_wan_if 0",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_GET_MAC_BLE_VERSION,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetMacBleVersion },
#if defined(RTCONFIG_QCA)																						       
	{ BLECMD_GET_ATH1_CHAN,			NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetAth1Chan },
#endif																									       
	{ BLECMD_SET_ATH1_CHAN,			NULL,				"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_GET_WAN_CONN_STATE,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetWanConnState }, 
	{ BLECMD_SET_TZ,			"time_zone",			"restart_time",			BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_TZ_DST,			"time_zone_dst",		"restart_time",			BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_TZ_DSTOFF,			"time_zone_dstoff",		"restart_time",			BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
#ifdef RTCONFIG_WIRELESSREPEATER																					       
	{ BLECMD_SCAN_AP,			NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseScanAP },
	{ BLECMD_GET_SCAN_LIST,			NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetScanList },
	{ BLECMD_SET_WLCX_PSTA,			"psta",				"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLCX_BAND,			"band",				"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLCX_SSID,			"ssid",				"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLCX_AUTH_MODE,		"auth_mode",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLCX_CRYPTO,		"crypto",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLCX_WPA_PSK,		"wpa_psk",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLX_SSID,			"ssid",				"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLX_AUTH_MODE_X,		"auth_mode_x",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLX_CRYPTO,		"crypto",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_WLX_WPA_PSK,		"wpa_psk",			"restart_wireless",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
#endif																									       
	{ BLECMD_SET_LAN_PROTO,			"lan_proto",			"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_LAN_IPADDR,		"lan_ipaddr",			"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_LAN_NETMASK,		"lan_netmask",			"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_LAN_GATEWAY,		"lan_gateway",			"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_LAN_DNSENABLE_X,		"lan_dnsenable_x",		"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_LAN_DNS1_X,		"lan_dns1_x",			"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_LAN_DNS2_X,		"lan_dns2_x",			"restart_net_and_phy",		BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
#if defined(RTCONFIG_AMAS)																						       
	{ BLECMD_SET_AIMESHMODE,		NULL,				NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
#endif																									       
	{ BLECMD_SET_SWITCH_STB_X,		"switch_stb_x",			NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_SWITCH_WANTAG,		"switch_wantag",		NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_SWITCH_WANXTAGID,		"tagid",			NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_SWITCH_WANXPRIO,		"prio",				NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_SET_JSON_NVRAM,		NULL,				NULL,				BLE_DATA_TYPE_STRING,		UnpackBLEDataToNvram,		PackBLEResponseOnly },
	{ BLECMD_GET_UI_SUPPORT,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetUIsupport },
	{ BLECMD_TRIG_FRS_LIVE_UPDATE,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseTrigFrsLiveUpdate },
	{ BLECMD_GET_FRS_LIVE_UPDATE_INFO,	NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetFrsLiveUpdateInfo},
	{ BLECMD_GET_IPTV_PROFILE,		NULL,				NULL,				BLE_DATA_TYPE_NULL,		UnpackBLECommandReq,		PackBLEResponseGetIPTVProfile },

	{ BLECMD_END,				NULL,				NULL,				BLE_DATA_TYPE_NULL,		NULL,				NULL		}
};

int BLE_EnableDBG(void)
{
	if (ble_dbg)
		return 1;
	return 0;
}

static char* dumpHEX(
	unsigned char *src,
	unsigned long src_size)
{
	int c, index;
	unsigned char *s = NULL, *ss = NULL;
	char *P = NULL, *PP = NULL, sss[33];
	unsigned long alloc_size = 0;

	if (!BLE_EnableDBG()) 
		return NULL;
	
	if (src == NULL || src_size <= 0)
		return NULL;
	
	alloc_size = src_size * 4;
	s = &src[0];
	ss = &src[src_size];
	P = (char *)malloc(alloc_size);
	
	if (P == NULL) {
		free(P);
		return NULL;
	}

	for(index=0; index<MAX_LE_DATALEN; index++)
		printf("%s%2d%s", !index?"[    ] ":" ", index, index==(MAX_LE_DATALEN-1)?"\n":"");

	memset(P, '\0', alloc_size);
	for (c=0, PP=&P[0], index=0; s<ss; s++, index++) {
		memset(sss, 0, sizeof(sss));

		if(!(index%20)) { 
			snprintf(sss, sizeof(sss)-1, "[%4d] ", index);
			strncpy(PP, sss, strlen(sss));
			PP += strlen(sss);
		}

		snprintf(sss, sizeof(sss)-1, "%02X%c", *s, (c>=19)?'\x0a':'\x20');
		strncpy(PP, sss, strlen(sss));

		PP += strlen(sss);
		if (c++>=19) c = 0;	
	}
	printf("%s\n", P);
	return 0;	
}

void print_data_topic(char *topic, int length)
{
	char str_tmp[MAX_PACKET_SIZE];
	char tmp[MAX_PACKET_SIZE];
	int index;

	if (!BLE_EnableDBG()) return;

	memset(str_tmp, '\0', MAX_PACKET_SIZE);
	snprintf(str_tmp, sizeof(str_tmp), "[%4s] ", "");

	for(index=0; index<MAX_LE_DATALEN; index++)
	{
		snprintf(tmp, sizeof(tmp), "%2d%c", index, ' ');
		strlcat(str_tmp, tmp, sizeof(str_tmp));
	}

	DBG_INFO("[%s data length]: %d\n%s", topic, length, str_tmp);

	logmessage("BLUEZ", "[%s length]: %d\n", topic, length);
	logmessage("BLUEZ", "%s\n", str_tmp);

	return;
}

/*
 * @func: printf uint8 value 
 * @value:
 * @val_len:
 * @row_len:
 * @val_index:
 * @flag:
 *
 * @return:
 * */
void print_data_info(uint8_t *value, int val_len, int row_len, int val_index, int flag)
{
	uint8_t val_tmp[MAX_PACKET_SIZE];
	char str_tmp[MAX_PACKET_SIZE];
	char tmp[MAX_PACKET_SIZE];
	int index;

	if (!BLE_EnableDBG()) return;

	memset(val_tmp, '\0', val_len);
	memset(str_tmp, '\0', MAX_PACKET_SIZE);
	memcpy(val_tmp, value, val_len);

	if (flag == 1)
		snprintf(str_tmp, sizeof(str_tmp), "Data value:\n\n");
	else
		snprintf(str_tmp, sizeof(str_tmp), "[%4d] ", val_index);

	for(index=0; index<val_len; index++) 
		if (flag == 1)
		{
			snprintf(tmp, sizeof(tmp), "%02x%c", val_tmp[index], (((index+1)%row_len)==0 && index!=0)?'\n':' ');
			strlcat(str_tmp, tmp, sizeof(str_tmp));
		}
		else
		{
			snprintf(tmp, sizeof(tmp), "%02x%c", val_tmp[index], ' ');
			strlcat(str_tmp, tmp, sizeof(str_tmp));
		}

	printf("%s\n", str_tmp);
	logmessage("BLUEZ", "%s\n", str_tmp);

	return;
}

/*
 * @func: Get public/private key from file
 * @action: do Init
 *
 * @return:
 * */
void KeyInit()
{
	int err=0;

	memset((void *)&fileData_s, 0, sizeof(FileData_s));

	fileData_s.ku_len = getFileSize(DEFAULT_PUBLIC_PEM_FILE);
	if ((fileData_s.ku = (unsigned char *)calloc(fileData_s.ku_len, sizeof(unsigned char))) == NULL) {
		DBG_ERR("[%s] Failed! ku Memory allocate failed ...\n", __func__);
		err = 1;
	}
	err = FileRead_Save(DEFAULT_PUBLIC_PEM_FILE, fileData_s.ku, fileData_s.ku_len);

	fileData_s.kp_len = getFileSize(DEFAULT_PRIVATE_PEM_FILE);
	if ((fileData_s.kp = (unsigned char *)calloc(fileData_s.kp_len, sizeof(unsigned char))) == NULL) {
		DBG_ERR("[%s] Failed! kp Memory allocate failed ...\n", __func__);
		err = 1;
	}
	err = FileRead_Save(DEFAULT_PRIVATE_PEM_FILE, fileData_s.kp, fileData_s.kp_len);

	if (err)
		notify_rc_and_wait("start_bluetooth_service");
	return;
}

/*
 * @func: server and client key init/reset action 
 * @type: Server or Client
 * @action: do Init or Reset
 *
 * @return:
 * */
void ble_key_act(char *type,  char *action)
{
	int typenum = !strcmp(type, "Server")? 1 : !strcmp(type, "Client")? 0: 2;
	int actionnum = !strcmp(action, "Init")? 1 : !strcmp(action, "Reset")? 0: 2;

	if (fileExists(DEFAULT_PUBLIC_PEM_FILE) == 0) {
		DBG_ERR("Not found file %s \n", DEFAULT_PUBLIC_PEM_FILE);
		goto err;
	}

	if (fileExists(DEFAULT_PRIVATE_PEM_FILE) == 0) {
		DBG_ERR("Not found file %s]n", DEFAULT_PRIVATE_PEM_FILE);
		goto err;
	}

	switch (typenum) {
	case 0:
		goto err;
	case 1:
		if (actionnum == 0)
			Reset_S();
		else if (actionnum == 1)
			KeyInit();
		else
			goto err;
	}

err:
	return ;
}

int ble_encrypt_svr(unsigned char *input, unsigned char *output, size_t input_len)
{
	unsigned char pdu[MAX_PACKET_SIZE];
	unsigned char data[MAX_PACKET_SIZE];
	unsigned int datalen;
	int ret, cmdno, pdulen=0;
	struct api_handler *handler;

	memset(pdu, '\0', MAX_PACKET_SIZE);
	memset(data, '\0', MAX_PACKET_SIZE);

	pdulen = (int)input_len;
	memcpy(pdu, input, input_len);

	ret=UnpackBLECommandData(pdu, pdulen, &cmdno, data, &datalen);

	if (BLE_EnableDBG()) {
		printf("********v\n");
		DBG_INFO("[ CMD No ]: %2x", cmdno);
		DBG_INFO("[ UnPack length ]: %d", datalen);
		dumpHEX(data, datalen);
	}

	if(ret==BLE_RESULT_OK) {
		if(cmdno==BLECMD_GET_NVRAM) {
			UnPackBLEExceptionGetNvram(cmdno, BLE_RESULT_OK, data, datalen, (unsigned char *)pdu, &pdulen);
		}
		else if(cmdno==BLECMD_SET_RC_SERVICE) {
			UnPackBLEExceptionSetRcSrv(cmdno, BLE_RESULT_OK, data, datalen, (unsigned char *)pdu, &pdulen);
		}
		else {
			for(handler=&api_handlers[0]; handler->cmdno<BLECMD_END; handler++) {
				if (handler->cmdno==cmdno) {
					handler->unpack(handler, data, datalen);
					handler->pack(cmdno, BLE_RESULT_OK, (unsigned char *)pdu, &pdulen);
					break;
				}
			}
		}
	}
	else { // error
		PackBLEResponseData(cmdno, ret, NULL, 0, (unsigned char *)pdu, &pdulen, BLE_RESPONSE_FLAGS);
	}

	if (BLE_EnableDBG()) {
		DBG_INFO("[ Pack Length ]: %d", pdulen);
		dumpHEX(pdu, pdulen);
	}

	memcpy(output, pdu, pdulen);

	return pdulen;
}
