//
//	ASUS_Discovery.c
//	ASUS
//
//	Created by Junda Txia on 11/22/10.
//	Copyright ASUSTek COMPUTER INC. 2011. All rights reserved.
//

#include <string.h>			//memset function
#include <stdio.h>			//sprintf function
#include <sys/socket.h>			//socket function
//#include <sys/_endian.h>		//htons function
#if defined(__GLIBC__) || defined(__UCLIBC__) /* not musl */
#include <sys/errno.h>			//errorno function
#include <sys/poll.h>			//struct pollfd
#else
#include <errno.h>			//errorno function
#include <poll.h>			//struct pollfd
#endif
#include <netinet/in.h>			//const IPPROTO_UDP
#include <unistd.h>			//close function
#include "asm/byteorder.h"
#include <rtstate.h>
#include <bcmnvram.h>

#include "ASUS_Discovery_Debug.h"	//myAsusDiscoveryDebugPrint function
#include "iboxcom.h"			//const INFO_PDU_LENGTH
#include "packet.h"			//const RESPONSE_HDR_OK
#include "ASUS_Discovery.h"

//char txMac[6] = {0};
int a_bEndApp = 0;
int a_socket = 0;
int a_GetRouterCount = 0;

extern unsigned char *gen_sha256_key(	unsigned char *data, size_t data_len, size_t *out_len);
extern int UnpackGetInfo_FINDCAP_NEW(char *pdubuf, PKT_GET_INFO *discoveryInfo, STORAGE_INFO_FINDCAP_T *storageInfo);

//SearchRouterInfoStruct searchRouterInfo[MAX_SEARCH_ROUTER] = {0};
SearchRouterInfoStruct searchRouterInfo[MAX_SEARCH_ROUTER];

#define SHAR256_KEY_LEN	16
unsigned char *extractTlvData(unsigned char *hexData, int hexDataLen, int tlvType, int *hexLen)
{
	unsigned char *data = NULL;
	unsigned char *pData = NULL;
	int i = 0;
	int type = 0;
	int len = 0; 
	char cTemp[32] = {0};

	pData = hexData;

	for (i = 0; i < hexDataLen; ) {
		type = (int)hexData[i++];
		len = (int)hexData[i++];
		pData += 2;
		if (type == tlvType) {
			sprintf(cTemp, "type(%d), len(%d)", type, len);
			myAsusDiscoveryDebugPrint(cTemp);
			if ((data = (unsigned char *)malloc(len + 1)) != NULL) {
				memset(data, 0, len + 1);
				memcpy(data, pData, len);
				*hexLen = len;
				break;
			}
		}
		i += len;
		pData += len;
	}

#if 0
	if (data) {
		for (i = 0; i < len; i++)
			DBG_PRINTF("%02X ", data[i]);
		DBG_PRINTF("\n");
	}
	else
		DBG_INFO("data is null");
#endif

	return data;
}

char* gen_vsie_id(int, size_t *);
int ASUS_Discovery()
{	
	myAsusDiscoveryDebugPrint("----------ASUS_Discovery Start----------");
	
	int iRet = 0;

	char *lan_ifname;
	char cTemp[512] = {0}, cfg_device_list_if[512] = {0};
	
	//initial search router count
	a_GetRouterCount = 0;
	// clean structure
	memset(&searchRouterInfo[0], 0, MAX_SEARCH_ROUTER * sizeof(SearchRouterInfoStruct));
	
	if (a_socket != 0)
	{
		close(a_socket);
		a_socket = 0;
	}

	a_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (a_socket < 0)
	{
		myAsusDiscoveryDebugPrint("Create socket failed");
		return 0;
	}
	// set reuseaddr option
	int reuseaddr = 1;
	if (setsockopt(a_socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) < 0)
	{
		myAsusDiscoveryDebugPrint("setsockopt: SO_REUSEADDR failed\n");
		close(a_socket);
		a_socket = 0;
		return 0;
	}

	lan_ifname = nvram_safe_get("discovery_if");
	snprintf(cfg_device_list_if, sizeof(cfg_device_list_if), "cfg_device_list_%s", lan_ifname);
	nvram_unset(cfg_device_list_if);
	snprintf(cTemp, sizeof(cTemp), "Discovery interface (%s)", lan_ifname);
	myAsusDiscoveryDebugPrint(cTemp);
	setsockopt(a_socket, SOL_SOCKET, SO_BINDTODEVICE, lan_ifname, strlen(lan_ifname));

	// set broadcast flag
	int broadcast = 1;
	int iRes = setsockopt(a_socket, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));
	if (iRes != 0)
	{
		myAsusDiscoveryDebugPrint("setsockopt: SO_BROADCAST failed");
		close(a_socket);
		a_socket = 0;
		return 0;
	}

	struct sockaddr_in clit;
	memset(&clit, 0, sizeof(clit));
	clit.sin_family = AF_INET;
	clit.sin_port = htons(INFO_SERVER_PORT);
	clit.sin_addr.s_addr = htonl(INADDR_ANY);
	
	int bind_result = bind(a_socket, (struct sockaddr *)&clit, sizeof(clit));
	if (bind_result < 0)
	{
		myAsusDiscoveryDebugPrint("could not bind to address");
		close(a_socket);
		a_socket = 0;
		return 0;
	}
	struct sockaddr_in serv;
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_port = htons(INFO_SERVER_PORT);
	inet_aton("255.255.255.255", &serv.sin_addr);
    
	char pdubuf[INFO_PDU_LENGTH] = {0};
	pdubuf[0] = 0x0C; //12
	pdubuf[1] = 0x15; //21
	pdubuf[2] = 0x36; //54
	pdubuf[3] = 0x00;
	pdubuf[4] = 0x00;
	pdubuf[5] = 0x00;
	pdubuf[6] = 0x00;
	pdubuf[7] = 0x00;
	
	// POLLIN	   any readable data available
	// POLLRDNORM  non-OOB/URG data available
	struct pollfd pollfd[1];	
	pollfd->fd = a_socket;
	pollfd->events = POLLIN;
	pollfd->revents = 0;
	
	int result;
	
	int retry = 3;
	while (retry > 0)
	{
		ssize_t iRet2 = sendto(a_socket, pdubuf, INFO_PDU_LENGTH, 0, (struct sockaddr *) &serv, sizeof(serv));
		myAsusDiscoveryDebugPrint("send discovery packet out");
		if (iRet2 < 0)
		{
			char error[128] = {0};
			sprintf(error, "sendto failed : %s", strerror(errno));
			myAsusDiscoveryDebugPrint(error);
			
			close(a_socket);
			a_socket = 0;
			return 0;
		}
		
		//receive
		while (1)
		{
			result = poll(pollfd, 1, 500); // Wait for 1 seconds
			
			// Error during poll()
			if (result < 0) 
			{
				myAsusDiscoveryDebugPrint("Error during poll()");
				break;
			}
			// Timeout...
			else if (result == 0) 
			{
				myAsusDiscoveryDebugPrint("Timeout during poll()");
				break;
			}
			// Success
			else
			{
				if (!(pollfd->revents & pollfd->events))
				continue;
				
				if (!ParseASUSDiscoveryPackage(a_socket))
				{
					myAsusDiscoveryDebugPrint("Failed to ParseASUSDiscoveryPackage");
				}
				else
				{
					iRet = 1;
					//break;
				}
			}
		}
		
		if (retry == 1) break;
		usleep(200000);
	
		retry --;
	}
	
	close(a_socket);
	a_socket = 0;

	int getRouterIndex;
#if defined(RTCONFIG_CFGSYNC) && defined(RTCONFIG_MASTER_DET)
	char cfg_device_buf[128] = {0};
	char cfg_device_list_buf[2049] = {0};
#endif
	int ts = 0;
	unsigned char v[512];
	unsigned char *id = NULL;
	size_t cfg_group_len = 0;

	for (getRouterIndex = 0; getRouterIndex < a_GetRouterCount; getRouterIndex++)
	{
		/*sprintf(cTemp, "===get_storage_info.CfgGroup hex: %x%x%x%x"
			, searchRouterInfo[getRouterIndex].routerCfgGroup[SHAR256_KEY_LEN], searchRouterInfo[getRouterIndex].routerCfgGroup[SHAR256_KEY_LEN+1]
			, searchRouterInfo[getRouterIndex].routerCfgGroup[SHAR256_KEY_LEN+2], searchRouterInfo[getRouterIndex].routerCfgGroup[SHAR256_KEY_LEN+3]);
		myAsusDiscoveryDebugPrint(cTemp);*/
		memset(v, 0, sizeof(v));
		str2hex_x(searchRouterInfo[getRouterIndex].routerCfgGroup, v);
		/*sprintf(cTemp, "===routerCfgGroup hex: %x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", 
			v[0], v[1], v[2], v[3], v[4],
			v[5], v[6], v[7], v[8], v[9],
			v[10], v[11], v[12], v[13], v[14],
			v[15], v[16], v[17], v[18], v[19]);
		myAsusDiscoveryDebugPrint(cTemp);*/
		ts = v[SHAR256_KEY_LEN] << 24 | v[SHAR256_KEY_LEN + 1] << 16 |
			 v[SHAR256_KEY_LEN + 2] << 8 | v[SHAR256_KEY_LEN + 3];
		/*sprintf(cTemp, "===ts : %x, %x"
			, ts, v[SHAR256_KEY_LEN] << 24 | v[SHAR256_KEY_LEN + 1] << 16 | v[SHAR256_KEY_LEN + 2] << 8 | v[SHAR256_KEY_LEN + 3]);
		myAsusDiscoveryDebugPrint(cTemp);*/

		id = gen_vsie_id(ts, &cfg_group_len);
		if (id)
		{
			sprintf(cTemp, "=== %s : %s", searchRouterInfo[getRouterIndex].routerCfgGroup, id);
			myAsusDiscoveryDebugPrint(cTemp);
			if (memcmp(searchRouterInfo[getRouterIndex].routerCfgGroup, id, 41) == 0)
			{
	#if defined(RTCONFIG_CFGSYNC) && defined(RTCONFIG_MASTER_DET)
				memset(cfg_device_buf, 0, sizeof(cfg_device_buf));
				snprintf(cfg_device_buf, sizeof(cfg_device_buf), "<%s>%s>%s>%d>%s",
						searchRouterInfo[getRouterIndex].routerProductID,
						searchRouterInfo[getRouterIndex].routerIPAddress,
						searchRouterInfo[getRouterIndex].routerRealMacAddress,
						searchRouterInfo[getRouterIndex].isMaster,
						searchRouterInfo[getRouterIndex].routerCfgGroup);
				if ((sizeof(cfg_device_list_buf) - strlen(cfg_device_list_buf)) > strlen(cfg_device_buf))
				{
					strncat(cfg_device_list_buf, cfg_device_buf, strlen(cfg_device_buf));
				}
				else
				{
					iRet = 1;
					break;
				}
	#endif
			}
			free(id);
		}
	}
	//nvram_set("asus_device_list", asus_device_list_buf);
#if defined(RTCONFIG_CFGSYNC) && defined(RTCONFIG_MASTER_DET)
	nvram_set(cfg_device_list_if, cfg_device_list_buf);
#endif
	return iRet;
}

int ParseASUSDiscoveryPackage(int socket)
{
	myAsusDiscoveryDebugPrint("----------ParseASUSDiscoveryPackage Start----------");
	
	if (a_bEndApp)
	{
		myAsusDiscoveryDebugPrint("a_bEndApp = true");
		return 0;
	}
	
	struct sockaddr_in from_addr;
	socklen_t ifromlen = sizeof(from_addr);
	char buf[INFO_PDU_LENGTH] = {0};
	ssize_t iRet = recvfrom(socket , buf, INFO_PDU_LENGTH, 0, (struct sockaddr *)&from_addr, &ifromlen);
	if (iRet <= 0)
	{
		myAsusDiscoveryDebugPrint("recvfrom function failed");
		return 0;
	}
	
	PROCESS_UNPACK_GET_INFO(buf, from_addr);
	
	return 1;
}

void PROCESS_UNPACK_GET_INFO(char *pbuf, struct sockaddr_in from_addr)
{

	PKT_GET_INFO get_discovery_info = {0};
	STORAGE_INFO_FINDCAP_T get_storage_info = {0};

	char cTemp[512] = {0};
	char cTemp2[32] = {0};
	int InfoLen = sizeof(get_storage_info.Info);
	char InfoStr[512] = {0};
	unsigned char *hexProductId = NULL, *hexMac = NULL, *hexId = NULL;
	int hexLen = 0;
#if defined(RTCONFIG_CFGSYNC) && defined(RTCONFIG_MASTER_DET)
       int extendcap = 0;
#endif
	char vsie_id_str[41] = {0};

	int responseUnpackGetInfo = UnpackGetInfo_FINDCAP_NEW(pbuf, &get_discovery_info, &get_storage_info);
	if (responseUnpackGetInfo == RESPONSE_HDR_IGNORE ||
		responseUnpackGetInfo == RESPONSE_HDR_ERR_UNSUPPORT)
	{
		return; // error data
	}

	// copy info to local buffer
	// check whether buffer overflow!
	if (a_GetRouterCount >= MAX_SEARCH_ROUTER)
		return;

	memcpy(InfoStr, get_storage_info.Info, InfoLen);
	hexMac = extractTlvData(InfoStr, InfoLen, INFO_TYPE_MAC, &hexLen);
	if (!hexMac)
	{
		return;
	}
    
	//check MAC address for duplicate response
	int getRouterIndex;
	for (getRouterIndex = 0; getRouterIndex < a_GetRouterCount; getRouterIndex++)
	{
		if (memcmp(searchRouterInfo[getRouterIndex].routerMacAddress, hexMac, 6) == 0) {
			myAsusDiscoveryDebugPrint("match smae entry");
			return;
		}
	}

	char *pTemp = inet_ntoa(from_addr.sin_addr);
	memcpy(searchRouterInfo[a_GetRouterCount].routerIPAddress, pTemp, 32);

	if (hexMac) {
		sprintf(cTemp2, "%02X:%02X:%02X:%02X:%02X:%02X", 
			(unsigned char)hexMac[0],
			(unsigned char)hexMac[1],
			(unsigned char)hexMac[2],
			(unsigned char)hexMac[3],
			(unsigned char)hexMac[4],
			(unsigned char)hexMac[5]);
		memcpy(searchRouterInfo[a_GetRouterCount].routerRealMacAddress, cTemp2, 17);
		memcpy(searchRouterInfo[a_GetRouterCount].routerMacAddress, hexMac, 6);
	}
	
	hexProductId = extractTlvData(InfoStr, InfoLen, INFO_TYPE_PRODUCT_NAME, &hexLen);
	if (hexProductId)
	{
		memcpy(searchRouterInfo[a_GetRouterCount].routerProductID, hexProductId, hexLen);
	}

	hexId = extractTlvData(InfoStr, InfoLen, INFO_TYPE_GROUPID, &hexLen);
	if (hexId) {
		hex2str(hexId, &vsie_id_str[0], hexLen);
		memcpy(searchRouterInfo[a_GetRouterCount].routerCfgGroup, vsie_id_str, strlen(vsie_id_str));
	}

	myAsusDiscoveryDebugPrint("********************* Search a Router ********************");
	sprintf(cTemp, "Router ProductID : %s", searchRouterInfo[a_GetRouterCount].routerProductID);
	myAsusDiscoveryDebugPrint(cTemp);
	sprintf(cTemp, "Router IPAddress : %s", searchRouterInfo[a_GetRouterCount].routerIPAddress);
	myAsusDiscoveryDebugPrint(cTemp);
	sprintf(cTemp, "Router MacAddress : %s", searchRouterInfo[a_GetRouterCount].routerRealMacAddress);
	myAsusDiscoveryDebugPrint(cTemp);
	
	if (searchRouterInfo[a_GetRouterCount].routerOperationMode == SW_MODE_ROUTER)
	{
		sprintf(cTemp, "Router Operation Mode : %d, ROUTER mode", searchRouterInfo[a_GetRouterCount].routerOperationMode);
		myAsusDiscoveryDebugPrint(cTemp);
	}
	else if (searchRouterInfo[a_GetRouterCount].routerOperationMode == SW_MODE_REPEATER)	
	{
		sprintf(cTemp, "Router Operation Mode : %d, REPEATER mode", searchRouterInfo[a_GetRouterCount].routerOperationMode);
		myAsusDiscoveryDebugPrint(cTemp);
	}
	else if (searchRouterInfo[a_GetRouterCount].routerOperationMode == SW_MODE_AP)
	{
		sprintf(cTemp, "Router Operation Mode : %d, AP mode", searchRouterInfo[a_GetRouterCount].routerOperationMode);
		myAsusDiscoveryDebugPrint(cTemp);
	}
	else if (searchRouterInfo[a_GetRouterCount].routerOperationMode == SW_MODE_HOTSPOT)
	{
		sprintf(cTemp, "Router Operation Mode : %d, HOTSPOT mode", searchRouterInfo[a_GetRouterCount].routerOperationMode);
		myAsusDiscoveryDebugPrint(cTemp);
	}
	else
	{
		sprintf(cTemp, "Router Operation Mode : %d, Not support this flag!", searchRouterInfo[a_GetRouterCount].routerOperationMode);
		myAsusDiscoveryDebugPrint(cTemp);
		searchRouterInfo[a_GetRouterCount].routerOperationMode = 0;
	}

#if defined(RTCONFIG_CFGSYNC) && defined(RTCONFIG_MASTER_DET)
	// save master/slave info
	sprintf(cTemp, "get_storage_info.ExtendCap(%X)", __le16_to_cpu(get_storage_info.ExtendCap));
	myAsusDiscoveryDebugPrint(cTemp);
	extendcap = __le16_to_cpu(get_storage_info.ExtendCap);
	searchRouterInfo[a_GetRouterCount].isMaster = (extendcap & EXTEND_CAP_MASTER) ? 1 : 0;
#endif
	sprintf(cTemp, "CfgGroup ID : %s", searchRouterInfo[a_GetRouterCount].routerCfgGroup);
	myAsusDiscoveryDebugPrint(cTemp);

	if (responseUnpackGetInfo == RESPONSE_HDR_OK)
	{
		searchRouterInfo[a_GetRouterCount].webdavSupport = 0;
		
		a_GetRouterCount++;
		return;
	}

	a_GetRouterCount++;

	if (hexProductId) free(hexProductId);
	if (hexId) free(hexId);
	if (hexMac) free(hexMac);
}

int main(void)
{
	return ASUS_Discovery();
}
