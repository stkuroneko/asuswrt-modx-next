/********************************************************************************
 
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ****************************************************************************** 
 *         File Name    :  scapi_interfaces_defines.h                                         *
 *         Description  :  prototypes for APIs defined by SCAPI.                 *  
 *  ******************************************************************************/

/*! \file scapi_interfaces_defines.h
    \brief File contains the API prototypes defined to get interfaces list 
*/
#ifndef _INTERFACE_DEFS_H
#define _INTERFACE_DEFS_H

#include <ltq_api_include.h>
#include "list.h"
#include "scapi_structs.h"
#include <errno.h>
#include <stdio.h>		/* printf, scanf, NULL */
#include <stdlib.h>		/* malloc, free, rand */
#include <string.h>		/* malloc, free, rand */
#include <stdint.h>
#include <linux/types.h>

#define BOTH_INTERFACES 0
#define ONLY_LAN_INTERFACE 1
#define ONLY_WAN_INTERFACE 2

/* \brief Interface list params enum
*/
typedef enum {
	e_configMacvLan,
	e_configProtos,
	e_configMode,
	e_configPort,
	e_configEnable,
	e_configLinkEnable,
	e_configBond,
	e_configBondMembers,
	e_configMAXEND,
} E_ParameterType;

/* \brief Interface list params to be filled
*/
typedef struct IfaceCfg {
	char cType[MAX_LEN_PARAM_VALUE_D];
	char cIfName[MAX_LEN_PARAM_VALUE_D];
	char cMappingLowerLayer[MAX_LEN_PARAM_VALUE_D];
	char cL1ObjName[MAX_LEN_PARAM_VALUE_D];
	char cMacvLan[MAX_LEN_PARAM_VALUE_D];
	char cProtos[MAX_LEN_PARAM_VALUE_D];
	char cMode[MAX_LEN_PARAM_VALUE_D];
	char cPort[MAX_LEN_PARAM_VALUE_D];
	char cEnable[MAX_LEN_PARAM_VALUE_D];
	char cLinkEnable[MAX_LEN_PARAM_VALUE_D];
	char cBondMembers[MAX_LEN_PARAM_VALUE_D];
	struct list_head xIfaceList;
} IfaceCfg_t;

#define FOR_EACH_INTERFACE(__pxIface,__pxTmpElem)\
    list_for_each_entry(__pxTmpElem, &(__pxIface->xIfaceList), xIfaceList) \

#define CONFIG_FILE_INTERFACES		"/opt/lantiq/etc/interfaces.cfg"
#define CONFIG_FILE_TYPE			"TYPE"
#define CONFIG_FILE_IFNAME			"IFNAME"
#define CONFIG_FILE_MACVLAN			"MACVLAN"
#define CONFIG_FILE_PROTOS			"PROTOS"
#define CONFIG_FILE_MODE			"MODE"
#define CONFIG_FILE_PORT			"PORTID"
#define CONFIG_FILE_ENABLE			"ENABLE"
#define CONFIG_FILE_LINKENABLE		"LINKENABLE"
#define CONFIG_FILE_BOND		"BOND"
#define CONFIG_FILE_BONDMEMBERS		"BONDMEMBERS"

/*! \brief   scapi_createListNode append an interface in the interface list.
   \params node to be appended and listhead of the list 
*/
IfaceCfg_t *scapi_createListNode(IfaceCfg_t * s_defaultConfig, IfaceCfg_t * pxIfaceListHead);
/*! \brief   scapi_getInterfaceList Get the list of interfaces available.
   \params list to be created
*/
int32_t scapi_getInterfaceList(IfaceCfg_t ** pxIfaceList, uint32_t flags);
/*! \brief   scapi_validateParameterList Validates the interface param.
   \params type and string to be validated. 
*/
void scapi_validateParameterList(E_ParameterType e_type, char *dataString);
/*! \brief   scapi_fillDefaultStruct fill the default paramters if validation fails.
   \params node to be filled with default values.
*/
int scapi_fillDefaultStruct(IfaceCfg_t * s_defaultConfig);
/*! \brief scapi_deleteInterfaceList deletes the interface list.
   \params listhead to be deleted 
*/
void scapi_deleteInterfaceList(IfaceCfg_t ** pxIfaceListHead);

#endif				//#ifndef _INTERFACE_DEFS_H
