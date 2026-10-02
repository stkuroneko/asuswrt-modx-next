/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* header files */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ulogging.h>
#include <ugw_error.h>
#include "fapi_sys_common.h"
#include "fapi_led.h"
#include "fapi_sys.h"
#include "platform_xrx330.h"
#include "xRX330_callback.h"
#include "ltq_api_include.h"
#include "scapi_interfaces_defines.h"

/* =============================================================================
* Function Name : xRX330_getBridgeLanInterfaces                                *
* Description   : this is a helper function which takes bridge name as first   *
*                 argument and returns all LAN members (including wireless)    *
* Input         : Bridge name of type char *                                   *
* OutPut        : Bridge LAN Interface List of type char *                     *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
static int32_t xRX330_getBridgeLanInterfaces(IN char *sBrName, OUT char *sBrIfaceList)
{
	int32_t nRet = UGW_FAILURE;
	struct dirent *pDirent = NULL;
	DIR *pDir = NULL;
	char sBrDir[MAX_NAME_LEN] = { 0 };

	if ((sBrName == NULL) || (strlen(sBrName) == 0)) {
		LOGF_LOG_ERROR("Invalid bridge name!\n");
		goto ret;
	}

	/* Read bridge configuration via sysfs */
	snprintf(sBrDir, sizeof(sBrDir), "/sys/devices/virtual/net/%s/brif", sBrName);

	pDir = opendir (sBrDir);
	if (pDir == NULL) {
		LOGF_LOG_ERROR("Opening sys entry for bridge %s failed!\n", sBrName);
		goto ret;
	}

	memset(sBrIfaceList, 0, MAX_DATA_LEN);

	/* Create comma-seperated list of LAN (including wireless) interfaces in bridge.
	 * Exclude all WAN interfaces (Ethernet/DSL/LTE/WWAN) and rtlog */
	while ((pDirent = readdir(pDir)) != NULL) {
		if ((strcmp(pDirent->d_name, ".") != 0)
		     && (strcmp(pDirent->d_name, "..") != 0)
		     && (strncmp(pDirent->d_name, "ptm", 3) != 0)
		     && (strncmp(pDirent->d_name, "nas", 3) != 0)
		     && (strncmp(pDirent->d_name, "eth1", 4) != 0)
		     && (strncmp(pDirent->d_name, "lte", 3) != 0)
		     && (strncmp(pDirent->d_name, "wwan", 4) != 0)
		     && (strncmp(pDirent->d_name, "rtlog", 5) != 0)) {
			snprintf(sBrIfaceList+strlen(sBrIfaceList), MAX_DATA_LEN - strlen(sBrIfaceList), "%s,", pDirent->d_name);

			/* Break out of loop if buffer is full */
			if ((strlen(sBrIfaceList) + 1) >= MAX_DATA_LEN)
				break;
		}
	}

	if (strlen(sBrIfaceList) > 1) {
		/* Truncate the last ',' */
		sBrIfaceList[strlen(sBrIfaceList)-1] = '\0';
		nRet = UGW_SUCCESS;
	} else {
		LOGF_LOG_DEBUG("No interfaces in bridge %s\n", sBrName);
	}

	closedir (pDir);

ret:
	return nRet;
}

/* =============================================================================
* Function Name : xRX330_CfgBridgeAccel                                        *
* Description   : xRX330_CfgBridgeAccel is responsible for enabling bridge     *
*                 acceleration for bridge passed in Bridge acceleration        *
*                 configuration                                                *
* Input         : Bridge acceleration configuration of type brAccelCfg_t *     *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_CfgBridgeAccel(IN brAccelCfg_t * pxBrAccelCfg)
{
	int32_t nRet = UGW_FAILURE;
	int32_t nExitStatus = 0;
	char sCmdBuf[MAX_DATA_LEN] = { 0 };
	char sBrIfaceList[MAX_DATA_LEN] = { 0 };

	LOGF_LOG_DEBUG("Bridge wan = %s \n", pxBrAccelCfg->WanVlanCfg.ifName);

	if (xRX330_getBridgeLanInterfaces(pxBrAccelCfg->sBrName, sBrIfaceList) != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Failed to get bridge interface list for %s.\n", pxBrAccelCfg->sBrName);
		goto end;
	}

	snprintf(sCmdBuf, sizeof(sCmdBuf), "%s %s %s %s %s", FAPI_SYS_BRIDGE_ACCEL_CFG_FILE, pxBrAccelCfg->WanVlanCfg.ifName, sBrIfaceList, pxBrAccelCfg->sBrName, (pxBrAccelCfg->oper == OPER_ADD) ? "enable" : "disable");

	LOGF_LOG_DEBUG("%s\n", sCmdBuf);
	nRet = scapi_spawn(sCmdBuf, SCAPI_BLOCK, &nExitStatus);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Enable bridge acceleration in switch failed with error code:%d!!!\n", nRet);
		nRet = UGW_FAILURE;
	} else {
		LOGF_LOG_DEBUG("Bridge acceleration enabled in switch for wan vlan %d!!\n", pxBrAccelCfg->WanVlanCfg.vlanId);
		nRet = UGW_SUCCESS;
	}

 end:
	return nRet;

}

/* =============================================================================
* Function Name : xRX330_load_tc_modules                                       *
* Description   : this is a helper function which takes platform name as input *
*                 and loads only DSL TC module in DSL mode                     *
* Input         : new wanmode of type WAN_TYPE_t                               *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
static int32_t xRX330_load_tc_modules(IN WAN_TYPE_t eMode)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nIdx = 0;
	char sModule[MODULE_NAME_SIZE] = { 0 };

	if (eMode == DSL_PTM) {
		for (nIdx = 0; nIdx < (int32_t) (sizeof(xRX330PTMTCModules) / sizeof(*xRX330PTMTCModules)); nIdx++) {
			snprintf(sModule, sizeof(sModule), "%s", xRX330PTMTCModules[nIdx]);
			if (check_loaded_modules(sModule) != UGW_SUCCESS) {
				LOGF_LOG_INFO("......loading %s\n", sModule);
				nRet = scapi_insmod(sModule, NULL);
				if (nRet != UGW_SUCCESS) {
					LOGF_LOG_CRITICAL("insmod of %s Failed!\n", sModule);
					nRet = UGW_FAILURE;
				} else {
					LOGF_LOG_DEBUG("insmod of %s Successful!\n", sModule);
					usleep(6000);
				}
			}
		}
	} else if (eMode == DSL_ATM) {
		for (nIdx = 0; nIdx < (int32_t) (sizeof(xRX330ATMTCModules) / sizeof(*xRX330ATMTCModules)); nIdx++) {
			snprintf(sModule, sizeof(sModule), "%s", xRX330ATMTCModules[nIdx]);
			if (check_loaded_modules(sModule) != UGW_SUCCESS) {
				LOGF_LOG_INFO("......loading %s\n", sModule);
				nRet = scapi_insmod(sModule, NULL);
				if (nRet != UGW_SUCCESS) {
					LOGF_LOG_CRITICAL("insmod of %s Failed!\n", sModule);
					nRet = UGW_FAILURE;
				} else {
					LOGF_LOG_DEBUG("insmod of %s Successful!\n", sModule);
					usleep(6000);
				}
			}
		}
	} else {
		LOGF_LOG_CRITICAL("Invalid DSL mode %d\n", eMode);
		nRet = UGW_FAILURE;
	}

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_remove_tc_modules                                     *
* Description   : this is a helper function which takes platform name as input *
*                 and unloads only DSL TC module in DSL mode                   *
* Input         : old wanmode of type WAN_TYPE_t                               *
* OutPut          None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
static int32_t xRX330_remove_tc_modules(IN WAN_TYPE_t eMode)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nIdx = 0;
	char sModule[MODULE_NAME_SIZE] = { 0 };

	if (eMode == DSL_PTM) {
		for (nIdx = (int32_t) (sizeof(xRX330PTMTCModules) / sizeof(*xRX330PTMTCModules)) - 1; nIdx >= 0; nIdx--) {
			snprintf(sModule, sizeof(sModule), "%s", xRX330PTMTCModules[nIdx]);
			if (check_loaded_modules(sModule) == UGW_SUCCESS) {
				LOGF_LOG_INFO("......unloading %s\n", sModule);
				nRet = scapi_rmmod(sModule, 0);
				if (nRet != UGW_SUCCESS) {
					LOGF_LOG_CRITICAL("rmmod %s failed!\n", sModule);
					nRet = UGW_FAILURE;
				}
			}
		}
	} else if (eMode == DSL_ATM) {
		for (nIdx = (int32_t) (sizeof(xRX330ATMTCModules) / sizeof(*xRX330ATMTCModules)) - 1; nIdx >= 0; nIdx--) {
			snprintf(sModule, sizeof(sModule), "%s", xRX330ATMTCModules[nIdx]);
			if (check_loaded_modules(sModule) == UGW_SUCCESS) {
				LOGF_LOG_INFO("......unloading %s\n", sModule);
				nRet = scapi_rmmod(sModule, 0);
				if (nRet != UGW_SUCCESS) {
					LOGF_LOG_CRITICAL("rmmod %s failed!\n", sModule);
					nRet = UGW_FAILURE;
				}
			}
		}
	} else {
		LOGF_LOG_CRITICAL("Invalid DSL mode %d\n", eMode);
		nRet = UGW_FAILURE;
	}

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_wanSWO                                                *
* Description   : xRX330_wanSWO is responsible for handling unloading and      *
*		  and re-initialization of wan and ppa modules during wan      *
		  change over                                                  *
* Input		: system configuration                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t XRX330_wanSWO(IN sys_cfg_t *pxSysCfg)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nExitStatus = 0;
	char sCommand[MAX_FBUF_SIZE] = { 0 };

	/* Only DSL TC mode switching is supported now.
	 * TODO: Remove this checking when all switchover modes are supported. */
	if ((pxSysCfg->priWAN != DSL_ATM && pxSysCfg->priWAN != DSL_PTM) || (pxSysCfg->secWAN != DSL_ATM && pxSysCfg->secWAN != DSL_PTM)) {
		LOGF_LOG_ERROR("Unable to change requested WAN mode\n");
		goto end;
	}

	/* Remove the old DSL TC modules */
	nRet = xRX330_remove_tc_modules(pxSysCfg->secWAN);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("Fail to unload DSL TC modules\n");
		goto end;
	}

	nRet = fapicb.sysSet(pxSysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("WAN mode update in syscfg failed!\n");
	}

	/* Retrieved the cached memory */
	snprintf(sCommand, MAX_FBUF_SIZE, "echo 1 > /proc/sys/vm/drop_caches");
	nRet = scapi_spawn(sCommand, SCAPI_BLOCK, &nExitStatus);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("Fail to retrieved the cached memory\n");
	}
	usleep(250000);

	/* Load the new DSL TC modules */
	nRet = xRX330_load_tc_modules(pxSysCfg->priWAN);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("Fail to load DSL TC modules\n");
		goto end;
	}

end:
	return nRet;
}

/* =============================================================================
* Function Name : xRX330_module_load		 	         	       *
* Description   :
* Input		: new wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX330_module_load(WAN_TYPE_t next_tc_mode)
{
	int32_t nRet = UGW_SUCCESS;
	sys_cfg_t sysCfg;

	LOGF_LOG_DEBUG("next_mode %d\n", next_tc_mode);
	nRet = fapicb.sysGet(&sysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("sys fapi get failed\n");
	}

	if (sysCfg.priWAN == next_tc_mode){
		LOGF_LOG_DEBUG("No need to load modules \n");
		return nRet;	
	}
	sysCfg.priWAN = next_tc_mode;
	sysCfg.wanphy = 0;

	LOGF_LOG_DEBUG("updated primary wan information %d \n", sysCfg.priWAN);
	nRet = fapicb.sysSet(&sysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("sys fapi set failed\n");
	}

	/* Load the new DSL TC modules */
	xRX330_load_tc_modules(next_tc_mode);

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_module_unload					       *
* Description   : 
* Input		: old wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX330_module_unload(WAN_TYPE_t next_tc_mode)
{
	int nRet = UGW_SUCCESS;
	sys_cfg_t sysCfg;
	memset(&sysCfg, 0, sizeof(sys_cfg_t));

	LOGF_LOG_INFO(".....next_mode - %d\n", next_tc_mode);
	nRet = fapicb.sysGet(&sysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG(" sys fapi get failed\n");
		return nRet;
	}

	if (next_tc_mode != WAN_NONE) {
		sysCfg.priWAN = next_tc_mode;
		sysCfg.wanphy = 0;

		LOGF_LOG_DEBUG("updated primary wan information as %d \n", sysCfg.priWAN);
		nRet = fapicb.sysSet(&sysCfg);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_DEBUG(" sys fapi set failed\n");
		}
	}

	/* Remove the old DSL TC modules */
	xRX330_remove_tc_modules(sysCfg.priWAN);

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_module_init                                           *
* Description   : xRX330_module_init is responsible for loading wan and	       *
*		  and common driver modules for xRX330 platform 	       *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_module_init(void)
{
	char sIntfName[MAX_IFACE_SIZE] = { 0 };
	ifcfg_t xIfCfg;
	sys_cfg_t xSysCfg;
	PPAInit_cfg_t xPPACfg;
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	char sCmd[MAX_DATA_LEN] = { 0 };
	int32_t nExitStatus = 0;
#ifdef PLATFORM_XRX330_EASY300_AC1200
	int32_t nNumInterface = 3;
	char *pcOrigArr[] = {
		[0] = "eth0_1",
		[1] = "eth0_2",
		[2] = "eth1",
	};
#else /* #ifdef PLATFORM_XRX330_EASY300_AC1200 */
	int32_t nNumInterface = 5;
	char *pcOrigArr[] = {
		[0] = "eth0_1",
		[1] = "eth0_2",
		[2] = "eth0_3",
		[3] = "eth0_4",
		[4] = "eth1",
	};
#endif /* #else */
	char pcTmpArr[nNumInterface][MAX_DATA_LEN];
	int32_t nRet = UGW_SUCCESS, nCount = 0, nIter = 0, nMatchFound = 0;

	memset(&xPPACfg, 0, sizeof(xPPACfg));
	memset(&xIfCfg, 0, sizeof(ifcfg_t));
	memset(&xSysCfg, 0, sizeof(sys_cfg_t));

	nRet = fapicb.sysGet(&xSysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("wan mode update in syscfg failed!\n");
	}

	nRet = xRX330_load_wan_modules(&xSysCfg);
	if (nRet != UGW_SUCCESS) {
		return nRet;
	}
	nRet = xRX330_load_common_modules();
	if (nRet != UGW_SUCCESS) {
		return nRet;
	}

	/* call script to handle lan seperation */
	snprintf(sCmd, MAX_DATA_LEN, FAPI_SYS_LAN_PORT_SEP_CFG_FILE);
	nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Enable Lan port seperation failed!!!\n");
		nRet = UGW_FAILURE;
	} else {
		LOGF_LOG_DEBUG("LAN port seperation Enabled!!\n");
	}

	/* call switch init */
	if (xSysCfg.priWAN == ETH) {
		snprintf(sCmd, MAX_DATA_LEN, "%s eth", FAPI_SYS_SWITCH_INIT_SCRIPT);
		nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("Switch Init failed!!!\n");
			nRet = UGW_FAILURE;
		} else {
			LOGF_LOG_DEBUG("Switch Init Success!!\n");
		}
	} else {
		snprintf(sCmd, MAX_DATA_LEN, "%s dsl", FAPI_SYS_SWITCH_INIT_SCRIPT);
		nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("Switch Init failed!!!\n");
			nRet = UGW_FAILURE;
		} else {
			LOGF_LOG_DEBUG("Switch Init Success!!\n");
		}
	}

	xPPACfg.Min_Hits = PPA_MIN_HITS;
	xPPACfg.nMax_LANNumSessions = -1;
	xPPACfg.nMax_WANNumSessions = -1;
	xPPACfg.nMax_McastNumSessions = -1;
	xPPACfg.nMax_BrNumSessions = -1;
	xPPACfg.Def_MTUSize = -1;
	xPPACfg.bMibMode = 0;
	/*Dont do header csum*/
	xPPACfg.bIP_Verify = 0;

	nRet = fapicb.ppa_init(&xPPACfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI PPA init failed!! Initializing through cmd\n");
		snprintf(sCmd, MAX_DATA_LEN, "ppacmd init");
		nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("PPA Init failed!!!\n");
			nRet = UGW_FAILURE;
		} else {
			LOGF_LOG_DEBUG("PPA Init Successful!!\n");
		}
	}

	nRet = scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES, NULL);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if ((strcmp(pxTmpIface->cEnable, "true") == 0) && (strcmp(pxTmpIface->cMode, "ETH") == 0)) {
			if (strcmp(pxTmpIface->cIfName, pcOrigArr[nCount]) != 0) {
				/*interface doesnt match. */
				/*Compare for match/conflicts in orig in higher indices */

				/*Match only with higher indices */
				for (nIter = nCount + 1; nIter < nNumInterface; nIter++) {
					if (strcmp(pxTmpIface->cIfName, pcOrigArr[nIter]) == 0) {
						nMatchFound = 1;
						break;
					}

				}
				if (nMatchFound == 1) {
					/*Match found : Rename matched index by appending temp */
					/*copy interfacename to temp index */
					snprintf(sCmd, MAX_DATA_LEN, "ip link set name %s_temp %s", pcOrigArr[nIter], pcOrigArr[nIter]);
					LOGF_LOG_INFO("Executing [%s] \n", sCmd);
					nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
					if (nRet != UGW_SUCCESS) {
						LOGF_LOG_DEBUG("'%s' command failed\n", sCmd);
						nRet = UGW_FAILURE;
					}
					snprintf(pcTmpArr[nIter], MAX_DATA_LEN, "%s_temp", pcOrigArr[nIter]);

				}
				if (pcTmpArr[nCount][0] != '\0') {
					snprintf(sCmd, MAX_DATA_LEN, "ip link set name %s %s", pxTmpIface->cIfName, pcTmpArr[nCount]);
				} else {
					snprintf(sCmd, MAX_DATA_LEN, "ip link set name %s %s", pxTmpIface->cIfName, pcOrigArr[nCount]);
				}
				LOGF_LOG_INFO("Executing [%s] \n", sCmd);
				nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
				if (nRet != UGW_SUCCESS) {
					LOGF_LOG_DEBUG("'%s' command failed\n", sCmd);
					nRet = UGW_FAILURE;
				}

				nMatchFound = 0;
			}

		}
		nCount++;
	}

	//add lan interfaces to PPA
	if (scapi_getInterfaceList(&pxIfaceList, 0, NULL) != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if ((strcmp(pxTmpIface->cEnable, "true") == 0) && ((strcmp(pxTmpIface->cMode, "ETH") == 0)) && ((strcmp(pxTmpIface->cType, "LAN") == 0))) {
			snprintf(sIntfName, MAX_IFACE_SIZE, "%s", pxTmpIface->cIfName);
			snprintf(xIfCfg.ifName, sizeof(xIfCfg.ifName), "%s", sIntfName);
			strncpy(xIfCfg.baseifName, "eth0", sizeof(xIfCfg.baseifName));
			xIfCfg.wanIf_flag = 0;
			LOGF_LOG_DEBUG("Adding interface%s:base=%s flag=%d to PPA \n", xIfCfg.ifName, xIfCfg.baseifName, xIfCfg.wanIf_flag);
			nRet = fapicb.ppaAdd(&xIfCfg);
			if (nRet != UGW_SUCCESS) {
				LOGF_LOG_DEBUG("failed adding lan interfaces to PPA\n");
			}

		}
	}

	snprintf(sCmd, MAX_DATA_LEN, FAPI_SYS_DISABLE_BR_ACCEL_SCRIPT);
	nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("failed to execute disable bridge acceleration script\n");
		nRet = UGW_FAILURE;
	}

end:
	scapi_deleteInterfaceList(&pxIfaceList);
	return nRet;
}

/* =============================================================================
* Function Name : xRX330_module_uninit                            	       *
* Description   : this function is responsible for unloading wan and           *
*		  and common driver modules.                                   *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_module_uninit(void)
{
	int32_t nRet = UGW_FAILURE;
	int32_t nExitStatus = 0;
	char sCmd[MAX_DATA_LEN] = { 0 };
	sys_cfg_t xSysCfg;

	memset(&xSysCfg, 0, sizeof(sys_cfg_t));

	nRet = fapicb.sysGet(&xSysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("wan mode update in syscfg failed!\n");
	}

	snprintf(sCmd, MAX_DATA_LEN, "ppacmd exit\n");
	nRet = scapi_spawn(sCmd, SCAPI_BLOCK, &nExitStatus);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("PPA exit failed!!!\n");
	} else {
		LOGF_LOG_DEBUG("PPA Exit Successful!!\n");
	}

	nRet = xRX330_remove_common_modules();
	if (nRet != UGW_SUCCESS) {
		return nRet;
	}
	nRet = xRX330_remove_wan_modules(&xSysCfg);
	if (nRet != UGW_SUCCESS) {
		return nRet;
	}

	return nRet;

}

/* =============================================================================
* Function Name : xRX330_load_common_modules                                   *
* Description   : this is a helper function which takes platform name as input *
*		  and loads common driver modules used for ethwan mode         *
* Input		: none                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_load_common_modules(void)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nIdx = 0;
	char sModule[MODULE_NAME_SIZE] = { 0 };

	for (nIdx = 0; nIdx < (int32_t) (sizeof(xRX330PPAModules) / sizeof(*xRX330PPAModules)); nIdx++) {
		strncpy(sModule, xRX330PPAModules[nIdx], MODULE_NAME_SIZE);
		LOGF_LOG_INFO("......loading %s\n", sModule);
		nRet = scapi_insmod(sModule, NULL);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("insmod of %s Failed!\n", sModule);
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", sModule);
			usleep(6000);
		}
	}

	/* load lantiq_ethsw.ko */
	LOGF_LOG_INFO("......loading %s\n", eth_sw);
	nRet = scapi_insmod(eth_sw, NULL);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("insmod of %s failed!\n", eth_sw);
	} else {
		LOGF_LOG_DEBUG("insmod of %s Successful!\n", eth_sw);
		usleep(6000);
	}

	/* load eth_phy_status.ko */
	LOGF_LOG_INFO("......loading %s\n", eth_phy_status);
	nRet = scapi_insmod(eth_phy_status, NULL);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("insmod of %s failed!\n", eth_phy_status);
	} else {
		LOGF_LOG_DEBUG("insmod of %s Successful!\n", eth_phy_status);
		usleep(4000);
	}

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_remove_common_modules                         	       *
* Description   : this is a helper function which takes platform name as input *
*        	  and unloads common driver modules used in ethwan mode        *
* Input		: none                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_remove_common_modules(void)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nIdx = 0;
	char sModule[MODULE_NAME_SIZE] = { 0 };

	if (check_loaded_modules(eth_phy_status) == UGW_SUCCESS) {
		strncpy(sModule, eth_phy_status, MODULE_NAME_SIZE);
		LOGF_LOG_INFO("......unloading %s\n", sModule);
		nRet = scapi_rmmod(sModule, 0);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("rmmod of %s failed!\n", sModule);
		} else {
			LOGF_LOG_DEBUG("rmmod of %s Successful!\n", sModule);
		}
	}

	if (check_loaded_modules(eth_sw) == UGW_SUCCESS) {
		strncpy(sModule, eth_sw, MODULE_NAME_SIZE);
		LOGF_LOG_INFO("......unloading %s\n", sModule);
		nRet = scapi_rmmod(sModule, 0);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("rmmod of %s failed!\n", sModule);
		} else {
			LOGF_LOG_DEBUG("rmmod of %s Successful!\n", sModule);
		}
	}

	for (nIdx = (int32_t) (sizeof(xRX330PPAModules) / sizeof(*xRX330PPAModules)) - 1; nIdx >= 0; nIdx--) {
		snprintf(sModule, sizeof(sModule), "%s", xRX330PPAModules[nIdx]);
		if (check_loaded_modules(sModule) == UGW_SUCCESS) {
			LOGF_LOG_INFO("......unloading %s\n", sModule);
			nRet = scapi_rmmod(sModule, 0);
			if (nRet != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("rmmod %s failed!\n", sModule);
			} else {
				LOGF_LOG_DEBUG("rmmod of %s Successful!\n", sModule);
			}
		} else {
			LOGF_LOG_DEBUG("module %s not loaded\n", sModule);
			nRet = UGW_SUCCESS;
		}
	}

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_load_wan_modules                         	       *
* Description   : this is a helper function which takes platform name as input *
*		  and loads wan driver modules used in ethwan mode             *
* Input		: system configuration                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_load_wan_modules(IN sys_cfg_t *pxSysCfg)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nWanPhy = 0, nQosEn = 0;	//wan_lte = 0;
	char sModParam[MODULE_NAME_SIZE] = { 0 };
	char sModule[MODULE_NAME_SIZE] = { 0 };

	if (pxSysCfg->priWAN == ETH) {
		nWanPhy = 2;	/* wanphy =2 for ethwan */
		snprintf(sModParam, MODULE_NAME_SIZE, "ethwan=%d wanqos_en=%d", nWanPhy, nQosEn);
	} else if (pxSysCfg->priWAN == DSL_PTM || pxSysCfg->priWAN == DSL_ATM) {
		if (pxSysCfg->qosEna == 1)
			nQosEn = 8;
		else
			nQosEn = 0;
		/* FIXME: Enable this when LTE support is added. */
		//if (pxSysCfg->wanlteEna == 1)
		//	wan_lte = 8;
		//else
		//	wan_lte = 0;

		nWanPhy = 0;	/* 0 for DSL WAN, special for VRX218 test */
		snprintf(sModParam, MODULE_NAME_SIZE, "ethwan=%d wanqos_en=%d", nWanPhy, nQosEn);
	}

	/* Load PPA module which is common for all WAN modes */
	LOGF_LOG_INFO("XRX330 loading ethwan modules\n");
	strncpy(sModule, xRX330ETHModules[0], MODULE_NAME_SIZE);
	LOGF_LOG_DEBUG("%s %s\n", sModule, sModParam);
	nRet = scapi_insmod(sModule, sModParam);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("insmod of %s FAILED!\n", sModule);
	} else {
		LOGF_LOG_DEBUG("insmod of %s Successful!\n", sModule);
		usleep(6000);
	}

	if (pxSysCfg->priWAN == DSL_PTM) {
		LOGF_LOG_INFO("Primary WAN is PTM\n");
		nRet = xRX330_load_tc_modules(pxSysCfg->priWAN);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("Fail to load PTM TC modules\n");
		}
	} else if (pxSysCfg->priWAN == DSL_ATM) {
		LOGF_LOG_DEBUG("Primary WAN is ATM\n");
		nRet = xRX330_load_tc_modules(pxSysCfg->priWAN);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("Fail to load ATM TC modules\n");
		}
	}

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_remove_wan_modules                         	       *
* Description   : this is a helper function which takes platform name as input *
*		  and unloads wan driver modules used in ethwan mode           *
* Input		: system configuration                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX330_remove_wan_modules(IN sys_cfg_t *pxSysCfg)
{
	int32_t nRet = UGW_FAILURE;
	int32_t nIdx = 0;
	char sModule[MODULE_NAME_SIZE] = { 0 };

	if (pxSysCfg->priWAN == DSL_PTM) {
		nRet = xRX330_remove_tc_modules(pxSysCfg->priWAN);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("Fail to unload PTM TC modules\n");
		}
	} else if (pxSysCfg->priWAN == DSL_ATM) {
		nRet = xRX330_remove_tc_modules(pxSysCfg->priWAN);
		if (nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("Fail to unload ATM TC modules\n");
		}
	}

	/* Remove PPA modules which is common for all WAN modes */
	for (nIdx = (int32_t) (sizeof(xRX330ETHModules) / sizeof(*xRX330ETHModules)) - 1; nIdx >= 0; nIdx--) {
		snprintf(sModule, sizeof(sModule), "%s", xRX330ETHModules[nIdx]);
		if (check_loaded_modules(sModule) == UGW_SUCCESS) {
			LOGF_LOG_INFO("......unloading %s\n", sModule);
			nRet = scapi_rmmod(sModule, 0);
			if (nRet != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("rmmod %s failed!\n", sModule);
			}
		} else {
			LOGF_LOG_DEBUG("module %s not loaded\n", sModule);
			nRet = UGW_SUCCESS;
		}
	}

	return nRet;
}

/* =============================================================================
* Function Name : xRX330_PortIdGet	                         	       *
* Description   : fapi to find switch port id corresponding to network         *
*                 interface                                                    *
* InPut		: interface name 	         			       *
* OutPut	: none                   				       *
* Returns       : Port Id or UGW_FAILURE                                       *
==============================================================================*/
int32_t xRX330_PortIdGet(IN char *sIfName)
{
	int nPortId = 0;
	int32_t nRet = UGW_SUCCESS;
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;

	if (scapi_getInterfaceList(&pxIfaceList, 0, sIfName) != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Failed to get interface list with name %s.\n", sIfName);
		nRet = UGW_FAILURE;
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if (strcmp(pxTmpIface->cIfName, sIfName) == 0) {
			nPortId = atoi(pxTmpIface->cPort);
			nRet = nPortId;
			break;
		}
	}

	LOGF_LOG_DEBUG("Interface = %s; PortId=%d\n", sIfName, (int32_t) nPortId);
 end:
	scapi_deleteInterfaceList(&pxIfaceList);

	return nRet;
}

/* ==============================================================================
 * Function Name : xRX330_SetInterface                                          *
 * Description   : xRX330_SetInterface is responsible for                       *
 *                 calling platform specific FAPIs.                             *
 * Input         : InterfaceType enum,State enum,pointer pLedAttr               *
 * OutPut        : None                                                         *
 * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 * ============================================================================ */
int32_t xRX330_SetInterface(IN InterfaceType eInterface, IN State eSetState, IN void *pLedAttr)
{
	int32_t nRet = UGW_FAILURE;
	sNetDevAttr *pxNetDevAttr = NULL;
	sNetDevAttr xNetDevAttr;
	sTimerAttr xTimerAttr;
	sDefaultAttr xDefAttr;
	void *pAttr = NULL;
	TriggerType eTriggerType = TRIGGER_NONE;

	switch (eInterface) {
	case INTERNET:
		if (eSetState == UP) {
			if (pLedAttr != NULL) {
				pxNetDevAttr = (sNetDevAttr *) pLedAttr;
			} else {
				pxNetDevAttr = &xNetDevAttr;
				memset(&xNetDevAttr, 0, sizeof(sNetDevAttr));
			}
			pxNetDevAttr->nBrightness = 100;
			pxNetDevAttr->nInterval = 100;
			pxNetDevAttr->unMode = LED_TRIGGER_MODE_LINK | LED_TRIGGER_MODE_RX | LED_TRIGGER_MODE_TX;
			LOGF_LOG_INFO("Turning Internet LED ON ...\n");
			LOGF_LOG_DEBUG("nBrightness:%d nInterval:%d unMode:%u\n", pxNetDevAttr->nBrightness, pxNetDevAttr->nInterval, pxNetDevAttr->unMode);
			pAttr = (void *)pxNetDevAttr;
			nRet = FAPI_LEDSetAttribute(INTERNETLED, TRIGGER_NETDEV, pAttr);
		} else {
			LOGF_LOG_INFO("Turning Internet LED OFF ...\n");
			memset(&xDefAttr, 0, sizeof(sDefaultAttr));
			nRet = FAPI_LEDSetAttribute(INTERNETLED, TRIGGER_NONE, (void *)&xDefAttr);
		}
		break;
	case VDSL:
	case VDSL1:
		switch (eSetState) {
		case READY:
			eTriggerType = TRIGGER_TIMER;
			memset(&xTimerAttr, 0, sizeof(sTimerAttr));
			xTimerAttr.nBrightness = 255;
			xTimerAttr.nDelayOn = 250;
			xTimerAttr.nDelayOff = 250;
			pAttr = &xTimerAttr;
			break;
		case TRAINING:
			memset(&xTimerAttr, 0, sizeof(sTimerAttr));
			eTriggerType = TRIGGER_TIMER;
			xTimerAttr.nBrightness = 255;
			xTimerAttr.nDelayOn = 125;
			xTimerAttr.nDelayOff = 125;
			pAttr = &xTimerAttr;
			break;
		case UP:
			memset(&xDefAttr, 0, sizeof(sDefaultAttr));
			xDefAttr.nBrightness = 255;
			eTriggerType = TRIGGER_DEFAULT;
			pAttr = &xDefAttr;
			break;
		case DOWN:
			memset(&xDefAttr, 0, sizeof(sDefaultAttr));
			eTriggerType = TRIGGER_NONE;
			pAttr = &xDefAttr;
			break;
		default:
			LOGF_LOG_INFO("Invalid State for VDSL\n");
			return nRet;
		}

		if (eInterface == VDSL) {
			nRet = FAPI_LEDSetAttribute(BROADBANDLED, eTriggerType, pAttr);
		}
		break;
	default:
		LOGF_LOG_INFO("Invalid Interface %d state %d for 330 \n", eInterface, eSetState);
		nRet = UGW_SUCCESS;
	}
	return nRet;
}

/* ================================================================================
 * * Function Name : xRX330_SetBridgeState                                        *
 * * Description   : xRX330_SetBridgeState is responsible for                     *
 * *                 setting bridge MAC address learning on and off               *
 * * Input         : Enable/Disable value                                         *
 * * OutPut        : None                                                         *
 * * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 * ============================================================================== */
int32_t xRX330_SetBridgeAcclState(IN char *operation)
{
	/*Stub function*/
	operation = operation;
	return UGW_SUCCESS;
}

/* =============================================================================
 * * Function Name : xRX330_SetWanPhyGpio                                      *
 * * Description   : xRX330_SetWanPhyGpio is responsible for                   *
 * *                 setting a value to WAN PHY GPIO                        *
 * * Input         : uint8_t nVal                                               *
 * * OutPut        : None                                                      *
 * * Returns       : UGW_SUCCESS/UGW_FAILURE                                   *
 * =========================================================================== */
int32_t xRX330_SetWanPhyGpio(IN uint8_t nVal)
{
	/*Stub function*/
	nVal = nVal;
	return UGW_SUCCESS;
}

