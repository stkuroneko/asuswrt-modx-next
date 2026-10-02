/********************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 
  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ********************************************************************************/

/********************************************************************************
 *     File Name  : scapi_interfaces_list.c                                     *
 *     Project    : UGW                                                         *
 *     Description: includes Api to get the interfaces list                     *
 *                                                                              *
 ********************************************************************************/
#include "scapi_interfaces_defines.h"
const char *gaDefaultConfigStr[e_configMAXEND] = {
	"false",
	"Static,DHCP, PPPoE,Bridge",
	"ETH",
	"0",
	"false",
	"false",
	"false",
	"eth1 nrgmii3",
};

/* =============================================================================
 * Function Name : scapi_createListNode
 * Description   : function to append an interface in the interface list. 
 * ============================================================================ */
IfaceCfg_t *scapi_createListNode(IfaceCfg_t * pxIfaceConfig, IfaceCfg_t * pxIfaceListHead)
{
	IfaceCfg_t *pxTmpNode = NULL;

	pxTmpNode = (IfaceCfg_t *) malloc(sizeof(IfaceCfg_t));
	if (pxTmpNode == NULL) {
		LOGF_LOG_ERROR("Malloc failed %d \n", ENOMEM);
		goto end;
	}
	strncpy(pxTmpNode->cType, pxIfaceConfig->cType, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cIfName, pxIfaceConfig->cIfName, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cMacvLan, pxIfaceConfig->cMacvLan, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cProtos, pxIfaceConfig->cProtos, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cMode, pxIfaceConfig->cMode, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cPort, pxIfaceConfig->cPort, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cEnable, pxIfaceConfig->cEnable, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cLinkEnable, pxIfaceConfig->cLinkEnable, MAX_LEN_PARAM_VALUE_D);
	strncpy(pxTmpNode->cBondMembers, pxIfaceConfig->cBondMembers, MAX_LEN_PARAM_VALUE_D);
	LOGF_LOG_DEBUG("Interface: [%s] Enable [%s] Type:[%s] MacvLan [%s] Proto [%s] Mode [%s] Port [%s] LinkEnable [%s] BondMembers [%s]", pxTmpNode->cIfName, pxTmpNode->cEnable, pxTmpNode->cType,
		       pxTmpNode->cMacvLan, pxTmpNode->cProtos, pxTmpNode->cMode, pxTmpNode->cPort, pxTmpNode->cLinkEnable, pxTmpNode->cBondMembers);
	list_add_tail((&pxTmpNode->xIfaceList), &pxIfaceListHead->xIfaceList);
 end:
	return pxTmpNode;
}

/* =============================================================================
 * Function Name : scapi_deleteInterfaceList
 * Description   : function to delete the interface list. 
 * ============================================================================ */
void scapi_deleteInterfaceList(IfaceCfg_t ** pxIfaceListHead)
{
	IfaceCfg_t *pxElem = NULL, *pxTempElem = NULL;
	IfaceCfg_t *pxIfaceList = NULL;

	if (pxIfaceListHead == NULL)
		return;
	else
		pxIfaceList = *pxIfaceListHead;

	/*Iterate over the list */
	list_for_each_entry_safe(pxElem, pxTempElem, &pxIfaceList->xIfaceList, xIfaceList) {
		list_del(&pxElem->xIfaceList);
		free(pxElem);
		pxElem = NULL;
	}
	free(*pxIfaceListHead);
	*pxIfaceListHead = NULL;

}

/* =============================================================================
 * Function Name : scapi_validateParameterList
 * Description   : Validates the interface param,
 *                    if validation fails fill the default params. 
 * ============================================================================ */
void scapi_validateParameterList(E_ParameterType e_type, char *dataString)
{
	switch (e_type) {
	case e_configMacvLan:
		if (strcasecmp(dataString, "true") != 0) {
			sprintf(dataString, "%s", gaDefaultConfigStr[e_configMacvLan]);
		}
		break;
	case e_configProtos:
		if ((strstr(dataString, "Static") != NULL) || (strstr(dataString, "DHCP") != NULL) || (strstr(dataString, "PPPoE") != NULL)) {
			return;
		} else {
			LOGF_LOG_WARNING("Reading interface Protos : [%s]", dataString);
			sprintf(dataString, "%s", gaDefaultConfigStr[e_configProtos]);
		}
		break;
	case e_configMode:
		break;
	case e_configPort:
		if (atoi(dataString) <= 0) {
			LOGF_LOG_ERROR("Reading interface Port : [%d]", atoi(dataString));
			sprintf(dataString, "%s", gaDefaultConfigStr[e_configPort]);
		}
		break;
	case e_configEnable:
	case e_configLinkEnable:
		if (strcasecmp(dataString, "true") != 0) {
			sprintf(dataString, "%s", "false");
		}
		break;
	case e_configBond:
		if (strcasecmp(dataString, "true") != 0) {
			sprintf(dataString, "%s", "false");
		}
		break;
	case e_configBondMembers:
		if (dataString[0] == '\0') {
			sprintf(dataString, "%s", gaDefaultConfigStr[e_configBondMembers]);
		}
		break;
	default:
		break;
	}
}

/* =============================================================================
 * Function Name : scapi_fillDefaultStruct
 * Description   : fill the default paramters if validation fails. 
 * ============================================================================ */
int scapi_fillDefaultStruct(IfaceCfg_t * pxIfaceConfig)
{
	if (!pxIfaceConfig)
		return UGW_FAILURE;

	sprintf(pxIfaceConfig->cMacvLan, "%s", gaDefaultConfigStr[e_configMacvLan]);
	sprintf(pxIfaceConfig->cProtos, "%s", gaDefaultConfigStr[e_configProtos]);
	sprintf(pxIfaceConfig->cMode, "%s", gaDefaultConfigStr[e_configMode]);
	sprintf(pxIfaceConfig->cPort, "%s", gaDefaultConfigStr[e_configPort]);
	sprintf(pxIfaceConfig->cEnable, "%s", gaDefaultConfigStr[e_configEnable]);
	sprintf(pxIfaceConfig->cLinkEnable, "%s", gaDefaultConfigStr[e_configLinkEnable]);
	sprintf(pxIfaceConfig->cBondMembers, "%s", gaDefaultConfigStr[e_configBondMembers]);
	return UGW_SUCCESS;
}

/* =============================================================================
 * Function Name : scapi_getInterfaceList
 * Description   : Get the list of interfaces available. 
 * ============================================================================ */
int32_t scapi_getInterfaceList(IfaceCfg_t ** xIfaceCfgListHead, uint32_t flags)
{
	/*parse c header file, add nodes in Iface linked list */
	FILE *filePtr = NULL;
	int retValue = UGW_SUCCESS;
	char readLine[100] = { 0 };
	char readLine_temp[100] = { 0 };
	char valueString[50] = { 0 };
	char *equalCharFound = NULL;
	char *hashCharFound = NULL;
	int nIter = 0;
	int nFound = 0;

	struct updateflags {
		uint32_t nTypeUpdate:1;
		uint32_t nIfaceNameUpdate:1;
		uint32_t nMacvLanUpdate:1;
		uint32_t nProtosUpdate:1;
		uint32_t nModeUpdate:1;
		uint32_t nSwitchPortUpdate:1;
		uint32_t nEnableUpdate:1;
		uint32_t nLinkEnableUpdate:1;
		uint32_t nBondMembersUpdate:1;
	} xUpdateFlag = {
	0};

	/*opening the file for parsing. */
	*xIfaceCfgListHead = (IfaceCfg_t *) malloc(sizeof(IfaceCfg_t));
	if (*xIfaceCfgListHead == NULL) {
		LOGF_LOG_ERROR("Malloc failed %d \n", ENOMEM);
		retValue = -ENOMEM;
		goto end;
	};
	INIT_LIST_HEAD(&(*xIfaceCfgListHead)->xIfaceList);

	IfaceCfg_t xIfaceConfig;
	scapi_fillDefaultStruct(&xIfaceConfig);

	filePtr = fopen(CONFIG_FILE_INTERFACES, "r");
	if (filePtr == NULL) {
		/*if file is not present the create default configuration */
		LOGF_LOG_ERROR("Failed to open interfaces.cfg\n");
		retValue = UGW_FAILURE;
		return retValue;
	}
	/*reading the file and parsing lines. */
	while (fgets(readLine, sizeof(readLine), filePtr) != NULL) {
		if (strstr(readLine, "{") != NULL) {
			while (fgets(readLine, sizeof(readLine), filePtr) != NULL) {
				if (strstr(readLine, "}") != NULL) {
					break;
				}
				nIter = nFound = 0;
				while (readLine[nIter] != '\n') {
					readLine_temp[nIter - nFound] = readLine[nIter];
					if (readLine[nIter] == '\t' || readLine[nIter] == '\r' || readLine[nIter] == '\v') {
						nFound++;
					}
					nIter++;
				}
				readLine_temp[nIter - nFound] = '\0';
				sprintf(readLine, "%s", readLine_temp);
				memset(readLine_temp, 0, sizeof(readLine_temp));
				if ((equalCharFound = strstr(readLine, "=")) != NULL) {
					hashCharFound = strstr(readLine, "#");
					if ((hashCharFound != NULL) && (hashCharFound < equalCharFound)) {
						continue;
					}
					if ((hashCharFound - equalCharFound) == sizeof(char)) {
						continue;
					}
					if (strncmp(readLine, CONFIG_FILE_TYPE, equalCharFound - readLine) == 0) {
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						if (valueString[0] != '\0') {
							if ((strcasecmp(valueString, "WAN") == 0) || (strcasecmp(valueString, "LAN") == 0)) {
								sprintf(xIfaceConfig.cType, "%s", valueString);
								xUpdateFlag.nTypeUpdate = 1;

							} else {
								LOGF_LOG_ERROR("Reading interface type:[%s] skip", valueString);
								xUpdateFlag.nTypeUpdate = 0;

							}
						} else {
							LOGF_LOG_ERROR("Empty Interface Type: Skip");
							xUpdateFlag.nTypeUpdate = 0;
						}

					} else if (strncmp(readLine, CONFIG_FILE_IFNAME, equalCharFound - readLine) == 0) {
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						if (valueString[0] != '\0') {
							xUpdateFlag.nIfaceNameUpdate = 1;
							sprintf(xIfaceConfig.cIfName, "%s", valueString);
						} else {
							LOGF_LOG_ERROR("Empty Interface Name: Skip");
							xUpdateFlag.nIfaceNameUpdate = 0;
						}
					} else if (strncmp(readLine, CONFIG_FILE_MACVLAN, equalCharFound - readLine) == 0) {
						xUpdateFlag.nMacvLanUpdate = 1;
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						scapi_validateParameterList(e_configMacvLan, valueString);
						sprintf(xIfaceConfig.cMacvLan, "%s", valueString);
					} else if (strncmp(readLine, CONFIG_FILE_PROTOS, equalCharFound - readLine) == 0) {
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						if (valueString[0] != '\0') {
							xUpdateFlag.nProtosUpdate = 1;
							scapi_validateParameterList(e_configProtos, valueString);
							sprintf(xIfaceConfig.cProtos, "%s", valueString);
						} else {
							LOGF_LOG_WARNING("Empty Interface Protos");
							xUpdateFlag.nProtosUpdate = 0;
						}
					} else if (strncmp(readLine, CONFIG_FILE_MODE, equalCharFound - readLine) == 0) {
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						if (valueString[0] != '\0') {
							xUpdateFlag.nModeUpdate = 1;

							scapi_validateParameterList(e_configMode, valueString);
							sprintf(xIfaceConfig.cMode, "%s", valueString);
						} else {
							LOGF_LOG_ERROR("Empty Interface Mode.");
							xUpdateFlag.nModeUpdate = 0;
						}
					} else if (strncmp(readLine, CONFIG_FILE_PORT, equalCharFound - readLine) == 0) {
						xUpdateFlag.nSwitchPortUpdate = 1;
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						if (valueString[0] != '\0') {
							xUpdateFlag.nSwitchPortUpdate = 1;
							scapi_validateParameterList(e_configPort, valueString);
							sprintf(xIfaceConfig.cPort, "%s", valueString);
						} else {
							LOGF_LOG_ERROR("Empty Interface Port");
							xUpdateFlag.nSwitchPortUpdate = 0;
						}
					} else if (strncmp(readLine, CONFIG_FILE_ENABLE, equalCharFound - readLine) == 0) {
						xUpdateFlag.nEnableUpdate = 1;
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						scapi_validateParameterList(e_configEnable, valueString);
						sprintf(xIfaceConfig.cEnable, "%s", valueString);
					} else if (strncmp(readLine, CONFIG_FILE_LINKENABLE, equalCharFound - readLine) == 0) {
						xUpdateFlag.nLinkEnableUpdate = 1;
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						scapi_validateParameterList(e_configLinkEnable, valueString);
						sprintf(xIfaceConfig.cLinkEnable, "%s", valueString);
					} else if (strncmp(readLine, CONFIG_FILE_BONDMEMBERS, equalCharFound - readLine) == 0) {
						xUpdateFlag.nBondMembersUpdate = 1;
						if (hashCharFound > equalCharFound) {
							snprintf(valueString, hashCharFound - equalCharFound, "%s", equalCharFound + 1);
						} else {
							sprintf(valueString, "%s", equalCharFound + 1);
						}
						scapi_validateParameterList(e_configBondMembers, valueString);
						sprintf(xIfaceConfig.cBondMembers, "%s", valueString);
					}
				}
			}

			if ((flags == ONLY_LAN_INTERFACE && (strcmp(xIfaceConfig.cType, "LAN") == 0)) || (flags == ONLY_WAN_INTERFACE && (strcmp(xIfaceConfig.cType, "WAN") == 0))
			    || (flags == BOTH_INTERFACES)) {
				/*if interface name is present then only add in the list */
				if (xUpdateFlag.nIfaceNameUpdate == 1 && xUpdateFlag.nTypeUpdate == 1) {
					if (scapi_createListNode(&xIfaceConfig, *xIfaceCfgListHead) == NULL) {
						LOGF_LOG_ERROR("Failed to create node\n");
						retValue = UGW_FAILURE;
						goto end;
					}
				}
			}
			scapi_fillDefaultStruct(&xIfaceConfig);
		}
	}

 end:
	/*close the file if reading is finished. */
	if (filePtr != NULL)
		fclose(filePtr);
	return retValue;

}
