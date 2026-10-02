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
#include "fapi_sys.h"
#include "platform_xrx220.h"
#include "xRX220_callback.h"
#include "ltq_api_include.h"
#include "scapi_interfaces_defines.h"

int32_t xRX220_CfgBridgeAccel(INOUT brAccelCfg_t * BrAccelCfg)
{
	int32_t ret = UGW_SUCCESS;
	char cmd_buf[MAX_DATA_LEN] = { 0 };
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	int32_t nIter = 0;
	char sLanIface[3][MAX_IFACE_SIZE] = { 0 };
	char sAction[MAX_IFACE_SIZE] = { 0 };

	LOGF_LOG_DEBUG("Bridge wan = %s \n", BrAccelCfg->WanVlanCfg.ifName);

	if (scapi_getInterfaceList(&pxIfaceList, ONLY_LAN_INTERFACE) != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		//UGW-SW-8126: bridge acceleration to be configured for DSL also  
		//if ((strcmp(pxTmpIface->cEnable, "true") == 0) && ((strcmp(pxTmpIface->cMode, "ETH") == 0)) && ((strcmp(pxTmpIface->cType, "LAN") == 0))) {
		if ((strcmp(pxTmpIface->cEnable, "true") == 0) && ((strcmp(pxTmpIface->cType, "LAN") == 0))) {
			strncpy(sLanIface[nIter], pxTmpIface->cIfName, MAX_IFACE_SIZE);
			nIter++;
		}
	}

	if (BrAccelCfg->oper == OPER_ADD)
		sprintf(sAction, "enable");
	if (BrAccelCfg->oper == OPER_REM)
		sprintf(sAction, "disable");

#ifndef MULTI_BRIDGE
	sprintf(BrAccelCfg->sBrName, "br-lan");
#endif

	sprintf(cmd_buf, "/etc/init.d/config_bridge_accel %s %s,%s,%s %s %s", BrAccelCfg->WanVlanCfg.ifName,sLanIface[0], sLanIface[1], sLanIface[2],BrAccelCfg->sBrName, sAction);

	LOGF_LOG_DEBUG("%s\n", cmd_buf);
	ret = system(cmd_buf);
	if (ret != -1) {
		LOGF_LOG_DEBUG("Enable bridge acceleration in switch failed!!!\n");
		ret = UGW_FAILURE;
	} else {
		LOGF_LOG_DEBUG("Bridge acceleration enabled in switch for wan vlan %d!!\n", BrAccelCfg->WanVlanCfg.vlanId);
		ret = UGW_SUCCESS;
	}

 end:
	scapi_deleteInterfaceList(&pxIfaceList);
	return ret;

}

/* =============================================================================
* Function Name : xRX220_wanSWO                                               *
* Description   : xRX220_wanSWO is responsible for handling unloading and      *
*		  and re-initialization of wan and ppa modules during wan      *
		  change over
* Input		: old wanmode and new wanmode of type WAN_TYPE_t               *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t XRX220_wanSWO(sys_cfg_t * sysCfg)
{
	int32_t ret = UGW_SUCCESS;

	ret = fapicb.sysSet(sysCfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("wan mode update in syscfg failed!\n");
	}
	//unload wan and common modules
	ret = xRX220_module_uninit();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("module unloading failed!\n");
	}
	sleep(5);

	ret = xRX220_module_init();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("module loading failed!\n");
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX220_module_load		 	         	       *
* Description   :
* Input		: new wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX220_module_load(WAN_TYPE_t next_tc_mode)
{
	int32_t ret = UGW_SUCCESS;
	char intfName[MAX_IFACE_SIZE] = { 0 };
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	ifcfg_t ifCfg;
	sys_cfg_t sysCfg;

	memset(&ifCfg, 0, sizeof(ifcfg_t));
	memset(&sysCfg, 0, sizeof(sys_cfg_t));

	LOGF_LOG_DEBUG("next_mode %d\n", next_tc_mode);
	ret = fapicb.sysGet(&sysCfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("sys fapi get failed\n");
	}

	sysCfg.priWAN = next_tc_mode;
	sysCfg.wanphy = 0;

	LOGF_LOG_DEBUG("updated primary wan information %d \n", sysCfg.priWAN);
	ret = fapicb.sysSet(&sysCfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("sys fapi set failed\n");
	}

	ret = xRX220_module_init();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("sys fapi init failed\n");
	}
	//add lan interfaces to PPA
	if (scapi_getInterfaceList(&pxIfaceList, ONLY_LAN_INTERFACE) != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if ((strcmp(pxTmpIface->cEnable, "true") == 0) && ((strcmp(pxTmpIface->cMode, "ETH") == 0)) && ((strcmp(pxTmpIface->cType, "LAN") == 0))) {
			snprintf(intfName, sizeof(intfName),"%s", pxTmpIface->cIfName);
			snprintf(ifCfg.ifName, sizeof(ifCfg.ifName), "%s", intfName);
			strcpy(ifCfg.baseifName, "eth0");
			ifCfg.wanIf_flag = 0;
			LOGF_LOG_DEBUG("Adding interface%s:base=%s flag=%d to PPA \n", ifCfg.ifName, ifCfg.baseifName, ifCfg.wanIf_flag);
			ret = fapicb.ppaAdd(&ifCfg);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_DEBUG("failed adding lan interfaces to PPA\n");
			}

		}
	}

#if 0
	//handling for eth wan
	if (sysCfg.priWAN == ETH) {

		system("ifconfig eth1 up");
		system("for __ii in `grep -E 'eth1' /etc/config/network|grep -w ifname|cut -d\' -f2`; do ifconfig $__ii up; done");
		system("for __ii in `grep -E 'eth1' /etc/config/network|grep -w ifname|cut -d\' -f2`; do ppacmd addwan -i $__ii -l eth1; done");
		strcpy(ifCfg.ifName, "eth1");
		ifCfg.wanIf_flag = 1;	/*add to wan */
		LOGF_LOG_DEBUG("Adding interface %s: flag=%d to PPA \n", ifCfg.ifName, ifCfg.wanIf_flag);
		ret = xRX220_PPAIntfAdd(&ifCfg);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("failed adding lan interfaces to PPA\n");
		}
	}
#endif
	system("/etc/init.d/disable_bridge_acceleration.sh");

 end:
	scapi_deleteInterfaceList(&pxIfaceList);
	return ret;
}

/* =============================================================================
* Function Name : xRX220_module_unload					       *
* Description   : 
* Input		: old wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX220_module_unload(WAN_TYPE_t next_tc_mode)
{
	int ret = UGW_SUCCESS;
	sys_cfg_t sysCfg;
	memset(&sysCfg, 0, sizeof(sys_cfg_t));

	LOGF_LOG_INFO(".....next_mode - %d\n", next_tc_mode);
	if (next_tc_mode != WAN_NONE) {
		ret = fapicb.sysGet(&sysCfg);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG(" sys fapi get failed\n");
		}

		sysCfg.priWAN = next_tc_mode;
		sysCfg.wanphy = 0;

		LOGF_LOG_DEBUG("updated primary wan information as %d \n", sysCfg.priWAN);
		ret = fapicb.sysSet(&sysCfg);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG(" sys fapi set failed\n");
		}
	}

	ret = xRX220_module_uninit();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG(" sys fapi uninit failed\n");
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX220_module_init                                           *
* Description   : xRX220_module_init is responsible for loading wan and	       *
*		  and common driver modules for xRX220 platform 	       *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX220_module_init(void)
{
	sys_cfg_t sys_cfg;
	PPAInit_cfg_t PPA_Cfg;

	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	char sCmd[MAX_DATA_LEN];
#ifdef PLATFORM_XRX200_EASY220W2
	int32_t nNumInterface = 3;
	char *pcOrigArr[] = {
		[0] = "eth0_1",
		[1] = "eth0_2",
		[2] = "eth1",
	};
#else
	int32_t nNumInterface = 4;
	char *pcOrigArr[] = {
		[0] = "eth0_1",
		[1] = "eth0_2",
		[2] = "eth0_3",
		[3] = "eth1",
	};
#endif
	char pcTmpArr[nNumInterface][MAX_DATA_LEN];
	int32_t ret = UGW_SUCCESS, nCount = 0, nIter = 0, nMatchFound = 0;

	memset(&PPA_Cfg, 0, sizeof(PPA_Cfg));
	memset(&sys_cfg, 0, sizeof(sys_cfg_t));

	ret = fapicb.sysGet(&sys_cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_CRITICAL("wan mode update in syscfg failed!\n");
	}

	ret = xRX220_load_wan_modules(&sys_cfg);
	if (ret != UGW_SUCCESS) {
		return ret;
	}
	ret = xRX220_load_common_modules();
	if (ret != UGW_SUCCESS) {
		return ret;
	}

	/* call script to handle lan seperation */
	ret = system("/etc/init.d/enable_lan_port_sep");
	if (ret != -1) {
		LOGF_LOG_DEBUG("Enable Lan port seperation failed!!!\n");
	} else {
		LOGF_LOG_DEBUG("LAN port seperation Enabled!!\n");
		ret = UGW_SUCCESS;
	}

	/* call switch init */
	if (sys_cfg.priWAN == ETH) {
		ret = system("/etc/init.d/vrx220_switch_init eth");
		if (ret != -1) {
			LOGF_LOG_DEBUG("Switch Init failed!!!\n");
		} else {
			LOGF_LOG_DEBUG("Switch Init Success!!\n");
			ret = UGW_SUCCESS;
		}
	} else {
		ret = system("/etc/init.d/vrx220_switch_init dsl");
		if (ret != -1) {
			LOGF_LOG_DEBUG("Switch Init failed!!!\n");
		} else {
			LOGF_LOG_DEBUG("Switch Init Success!!\n");
			ret = UGW_SUCCESS;
		}
	}

	PPA_Cfg.Min_Hits = PPA_MIN_HITS;
	PPA_Cfg.nMax_LANNumSessions = -1;
	PPA_Cfg.nMax_WANNumSessions = -1;
	PPA_Cfg.nMax_McastNumSessions = -1;
	PPA_Cfg.nMax_BrNumSessions = -1;
	PPA_Cfg.Def_MTUSize = -1;
	PPA_Cfg.bMibMode = -1;

	ret = fapicb.ppa_init(&PPA_Cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI PPA init failed!! Initializing through cmd\n");
		ret = system("ppacmd init");
		if (ret != -1) {
			LOGF_LOG_DEBUG("PPA Init failed!!!\n");
		} else {
			LOGF_LOG_DEBUG("PPA Init Successful!!\n");
			ret = UGW_SUCCESS;
		}
	}
	system("/etc/init.d/disable_bridge_acceleration.sh");

	ret = scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
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
					sprintf(sCmd, "ip link set name %s_temp %s", pcOrigArr[nIter], pcOrigArr[nIter]);
					LOGF_LOG_INFO("Executing [%s] \n", sCmd);
					system(sCmd);
					sprintf(pcTmpArr[nIter], "%s_temp", pcOrigArr[nIter]);

				}
				if (pcTmpArr[nCount][0] != '\0') {
					sprintf(sCmd, "ip link set name %s %s", pxTmpIface->cIfName, pcTmpArr[nCount]);
				} else {
					sprintf(sCmd, "ip link set name %s %s", pxTmpIface->cIfName, pcOrigArr[nCount]);
				}
				LOGF_LOG_INFO("Executing [%s] \n", sCmd);
				system(sCmd);

				nMatchFound = 0;
			}

		}
		nCount++;
	}
 end:
	scapi_deleteInterfaceList(&pxIfaceList);
	return ret;
}

/* =============================================================================
* Function Name : xRX220_module_uninit                            	       *
* Description   : this function is responsible for unloading wan and           *
*		  and common driver modules.                                   *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX220_module_uninit(void)
{

	sys_cfg_t sys_cfg;
	int32_t ret = UGW_FAILURE;
	memset(&sys_cfg, 0, sizeof(sys_cfg_t));

	ret = fapicb.sysGet(&sys_cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("wan mode update in syscfg failed!\n");
	}

	system("ppacmd exit\n");

	ret = xRX220_remove_common_modules();
	if (ret != UGW_SUCCESS) {
		return ret;
	}
	ret = xRX220_remove_wan_modules(&sys_cfg);
	if (ret != UGW_SUCCESS) {
		return ret;
	}

	return ret;

}

/* =============================================================================
* Function Name : xRX220_load_common_modules                                   *
* Description   : this is a helper function which takes platform name as input *
*		  and loads common driver modules used for ethwan mode         *
* Input		: platform name enum                                           *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX220_load_common_modules(void)
{

	int32_t ret = UGW_SUCCESS;
	int32_t ModIndx = 0;
	char cmd_buf[MAX_DATA_LEN];
	memset(cmd_buf, 0, sizeof(char) * MAX_DATA_LEN);

	for (ModIndx = 0; ModIndx < (int32_t) (sizeof(xRX220PPAModules) / sizeof(*xRX220PPAModules)); ModIndx++) {
		LOGF_LOG_INFO("......loading %s\n", xRX220PPAModules[ModIndx]);
		ret = scapi_insmod(xRX220PPAModules[ModIndx], NULL);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("insmod of %s Failed!\n", xRX220PPAModules[ModIndx]);
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220PPAModules[ModIndx]);
		}
		usleep(6000);
	}

	/* load lantiq_ethsw.ko */
	LOGF_LOG_INFO("......loading eth_sw.ko\n");
	ret = scapi_insmod(eth_sw, NULL);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("insmod of %s failed!\n", eth_sw);
	} else {
		LOGF_LOG_DEBUG("insmod of %s Successful!\n", eth_sw);
	}
	usleep(6000);

	/* load eth_phy_status.ko */
	LOGF_LOG_INFO("......loading eth_phy_status.ko\n");
	ret = scapi_insmod(eth_phy_status, NULL);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("insmod of %s failed!\n", eth_phy_status);
	} else {
		LOGF_LOG_DEBUG("insmod of %s Successful!\n", eth_phy_status);
	}
	usleep(4000);

	return ret;
}

/* =============================================================================
* Function Name : xRX220_remove_common_modules                         	       *
* Description   : this is a helper function which takes platform name as input *
*        	  and unloads common driver modules used in ethwan mode        *
* Input		: platform name enum                                           *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t xRX220_remove_common_modules(void)
{

	int32_t ret = UGW_SUCCESS;
	int32_t ModIndx = 0;
	char module[MODULE_NAME_SIZE];
	memset(module, 0, sizeof(char) * MODULE_NAME_SIZE);

	for (ModIndx = (int32_t) (sizeof(xRX220PPAModules) / sizeof(*xRX220PPAModules)) - 1; ModIndx >= 0; ModIndx--) {
		strcpy(module, xRX220PPAModules[ModIndx]);
		if (check_loaded_modules(xRX220PPAModules[ModIndx]) != UGW_SUCCESS) {
			LOGF_LOG_INFO("......unloading %s\n", module);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("rmmod %s failed!\n", xRX220PPAModules[ModIndx]);
			}
		} else {
			LOGF_LOG_DEBUG("module %s already loaded no need to insmod\n", xRX220PPAModules[ModIndx]);
			ret = UGW_SUCCESS;
		}
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX220_load_wan_modules                         	       *
* Description   : this is a helper function which takes platform name as input *
*		  and loads wan driver modules used in ethwan mode             *
* Input		: platform name enum                                           *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX220_load_wan_modules(IN sys_cfg_t * sys_cfg)
{
	int32_t ret = UGW_SUCCESS;
	char cmd_buf[MAX_DATA_LEN];
	int32_t wan_phy = 0, qos_en = 0;	//wan_lte = 0;
	memset(cmd_buf, 0, sizeof(char) * MAX_DATA_LEN);

	if (sys_cfg->priWAN == ETH) {
		LOGF_LOG_INFO("XRX220 loading ethwan modules \n");
		//if (sys_cfg->qosEna == 1)
		//      qos_en = 8;
		//else
		//      qos_en = 0;

		//if (sys_cfg->wanlteEna == 1)
		//      wan_lte = 8;
		//else
		//      wan_lte = 0;

		wan_phy = 2;	/* wanphy =2 for ethwan */
#ifdef CONFIG_WWAN_LTE_SUPPORT
		sprintf(cmd_buf, "insmod /lib/modules/*/%s ethwan=%d wanqos_en=%d wanitf=8", xRX220ETHModules[0], wan_phy, qos_en);
#else
		sprintf(cmd_buf, "insmod /lib/modules/*/%s ethwan=%d wanqos_en=%d", xRX220ETHModules[0], wan_phy, qos_en);
#endif
		LOGF_LOG_DEBUG("%s\n", cmd_buf);
		printf("%s\n", cmd_buf);
		ret = system(cmd_buf);
		if (ret != -1) {
			LOGF_LOG_DEBUG("Insmod WAN ETH modules failed!!!\n");
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220ETHModules[0]);
			ret = UGW_SUCCESS;
		}
		usleep(6000);

		//if ((check_loaded_modules(xRX220ETHModules[1]) != UGW_SUCCESS)) {
		ret = scapi_insmod(xRX220ETHModules[1], NULL);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX220ETHModules[1]);
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220ETHModules[1]);
		}
		//} else {
		//      LOGF_LOG_DEBUG("Module %s already loaded! no need to insmod.\n", xRX220ETHModules[1]);
		//      ret = UGW_SUCCESS;
		//}
		usleep(6000);

	}

	if (sys_cfg->priWAN == DSL_PTM) {
		LOGF_LOG_INFO("Primary WAN is VDSL_PTM \n");
		if (sys_cfg->qosEna == 1)
			qos_en = 8;
		else
			qos_en = 0;

		//if (sys_cfg->wanlteEna == 1)
		//      wan_lte = 8;
		//else
		//      wan_lte = 0;

		wan_phy = 0;
		LOGF_LOG_INFO("......loading %s\n", xRX220VDSLModules[0]);
		ret = scapi_insmod(xRX220VDSLModules[0], NULL);
		if (ret != UGW_SUCCESS) {
			printf("Insert failure\n");
			sprintf(cmd_buf, "insmod /lib/modules/*/%s ethwan=%d wanqos_en=%d", xRX220VDSLModules[0], wan_phy, qos_en);
			LOGF_LOG_DEBUG("%s\n", cmd_buf);
			ret = system(cmd_buf);
			if (ret != -1) {
				LOGF_LOG_DEBUG("insmod of %s FAILED!\n", xRX220VDSLModules[0]);
			} else {
				LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220VDSLModules[0]);
				ret = UGW_SUCCESS;
			}
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220VDSLModules[0]);
		}
		usleep(6000);

		LOGF_LOG_INFO("......loading %s\n", xRX220VDSLModules[1]);
		ret = scapi_insmod(xRX220VDSLModules[1], NULL);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("insmod of %s FAILED!\n", xRX220VDSLModules[1]);
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220VDSLModules[1]);
		}
		usleep(6000);
	}

	if (sys_cfg->priWAN == DSL_ATM) {
		LOGF_LOG_DEBUG("[%s:%d] Primary WAN is ADSL_ATM \n", __func__, __LINE__);
		if (sys_cfg->qosEna == 1)
			qos_en = 8;
		else
			qos_en = 0;

		//if (sys_cfg->wanlteEna == 1)
		//      wan_lte = 8;
		//else
		//      wan_lte = 0;

		wan_phy = 0;
		sprintf(cmd_buf, "insmod /lib/modules/*/%s ethwan=%d wanqos_en=%d", xRX220ADSLModules[0], wan_phy, qos_en);
		LOGF_LOG_DEBUG("%s\n", cmd_buf);
		printf("%s\n", cmd_buf);
		ret = system(cmd_buf);
		if (ret != -1) {
			LOGF_LOG_DEBUG("Insmod WAN ADSL modules failed!!!\n");
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220ADSLModules[0]);
			ret = UGW_SUCCESS;
		}
		usleep(3000);

		//      if ((check_loaded_modules(xRX220ADSLModules[1]) != UGW_SUCCESS)) {
		ret = scapi_insmod(xRX220ADSLModules[1], NULL);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX220ADSLModules[1]);
		} else {
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX220ADSLModules[1]);
		}
		//} else {
		//      LOGF_LOG_DEBUG("Module %s already loaded! no need to insmod.\n", xRX220ADSLModules[1]);
		//      ret = UGW_SUCCESS;
		//}
		usleep(3000);
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX220_remove_wan_modules                         	               *
* Description   : this is a helper function which takes platform name as input *
*		  and unloads wan driver modules used in ethwan mode           *
* Input		: platform name enum                                           *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX220_remove_wan_modules(IN sys_cfg_t * sys_cfg)
{
	int32_t ret = UGW_FAILURE;
	int32_t ModIndx = 0;
	char module[MODULE_NAME_SIZE];
	memset(module, 0, sizeof(char) * MODULE_NAME_SIZE);

	if (sys_cfg->priWAN == ETH) {
		for (ModIndx = (int32_t) (sizeof(xRX220ETHModules) / sizeof(*xRX220ETHModules)) - 1; ModIndx >= 0; ModIndx--) {
			strcpy(module, xRX220ETHModules[ModIndx]);
			if ((check_loaded_modules(xRX220ETHModules[ModIndx]) != UGW_SUCCESS)) {
				LOGF_LOG_INFO("......unloading %s\n", module);
				ret = scapi_rmmod(module, 0);
				if (ret != UGW_SUCCESS) {
					LOGF_LOG_DEBUG("rmmod %s failed!\n", xRX220ETHModules[ModIndx]);
				}
			}
		}
	}
	if (sys_cfg->priWAN == DSL_PTM) {
		for (ModIndx = (int32_t) (sizeof(xRX220VDSLModules) / sizeof(*xRX220VDSLModules)) - 1; ModIndx >= 0; ModIndx--) {
			strcpy(module, xRX220VDSLModules[ModIndx]);
			if ((check_loaded_modules(xRX220VDSLModules[ModIndx]) != UGW_SUCCESS)) {
				LOGF_LOG_INFO("......unloading %s\n", module);
				ret = scapi_rmmod(module, 0);
				if (ret != UGW_SUCCESS) {
					LOGF_LOG_DEBUG("rmmod %s failed!\n", xRX220VDSLModules[ModIndx]);
				}
			}
		}
	}
	if (sys_cfg->priWAN == DSL_ATM) {
		for (ModIndx = (int32_t) (sizeof(xRX220ADSLModules) / sizeof(*xRX220ADSLModules)) - 1; ModIndx >= 0; ModIndx--) {
			strcpy(module, xRX220ADSLModules[ModIndx]);
			if ((check_loaded_modules(xRX220ADSLModules[ModIndx]) != UGW_SUCCESS)) {
				LOGF_LOG_INFO("......unloading %s\n", module);
				ret = scapi_rmmod(module, 0);
				if (ret != UGW_SUCCESS) {
					LOGF_LOG_DEBUG("rmmod %s failed!\n", xRX220VDSLModules[ModIndx]);
				}
			}
		}
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX220_PortIdGet	                         	       *
* Description   : fapi to find switch port id corresponding to network         *
*                 interface                                                    *
* InPut		: interface name 	         			       *
* OutPut	: none                   				       *
* Returns       : Port Id or UGW_FAILURE                                       *
==============================================================================*/
int32_t xRX220_PortIdGet(IN char *ifname)
{
	PPA_CMD_PORTID_INFO portid;
	int32_t ret = UGW_SUCCESS;
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	memset(&portid, 0, sizeof(portid));

	strncpy(portid.ifname, ifname, sizeof(portid.ifname));

	if (scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES) != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
		ret = UGW_FAILURE;
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if (strcmp(pxTmpIface->cIfName, ifname) == 0) {
			portid.portid = atoi(pxTmpIface->cPort);
			ret = UGW_SUCCESS;
			break;
		}
	}

	LOGF_LOG_DEBUG("Interface = %s; PortId=%d\n", portid.ifname, (int32_t) portid.portid);
 end:
	scapi_deleteInterfaceList(&pxIfaceList);
	if (ret == UGW_SUCCESS)
		return portid.portid;
	return ret;
}

/* =============================================================================
* Function Name : xRX220_setBrCfg					       *
* Description   : fapi for switch configuration for multibridge 	       * 
* InPut		: PortId, operation(ADD,DEL)	 	         	       *
* OutPut	: none                   				       *
* Returns       : UGW_SUCCESS or UGW_FAILURE                                   *
==============================================================================*/
int32_t xRX220_setBrCfg(IN char *wanInf, IN char *lanInf, IN char *brname, IN char *Oper)
{

	char cmd[256]={0};
	int nRet = UGW_SUCCESS,nChildSt;
	
	if( wanInf == NULL && lanInf == NULL)
	{
		return nRet;
	}
	else if( wanInf == NULL)
	{
		sprintf(cmd,"/etc/init.d/config_bridge_accel - \"%s\" %s %s", lanInf, brname, Oper);
	}
	else if( lanInf == NULL)
	{
		sprintf(cmd,"/etc/init.d/config_bridge_accel %s - %s %s", wanInf,brname, Oper);
	}
	else
	{
		sprintf(cmd,"/etc/init.d/config_bridge_accel %s \"%s\" %s %s", wanInf,lanInf,brname, Oper);
	}

	nRet = scapi_spawn(cmd, SCAPI_BLOCK, &nChildSt);
	if (nRet !=  UGW_SUCCESS)
		LOGF_LOG_DEBUG("Failed to configure bridge.\n");
	return nRet;
}
/* =========================================================================== *
 *  Function Name : EnableMirroring                                     *
 *  Description   : This fapi is used to configure portmirroring configurations*
 *                  on the router by using the interfaces provided by user.    *
 *                  user needs to provide downstream interface and Mirrored    *
 *                  interface as inputs.                                       *
 *                  Fapi finds the switch port attached to interface and       *
 *                  configures required Mirroring configuration in switch      *
 *  Input         : Downstream Interface, Mirror Interface                     *
 *  Output        : None                                                       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ===========================================================================*/
int32_t xRX220_EnableMirroring(IN char * DownstreamIntf ,IN char * MirrorIntf)
{
        char buf[MAX_SYSBUF_SIZE]={0};
        PPA_CMD_ENABLE_INFO PPAenInfo;
        GSW_portCfg_t PortCfg;
        GSW_monitorPortCfg_t PortMirrorCfg;
        int32_t retval = UGW_SUCCESS,nChildSt;
        memset(&PPAenInfo, 0, sizeof(PPAenInfo));
        memset(&PortCfg, 0, sizeof(PortCfg));
        memset(&PortMirrorCfg, 0, sizeof(PortMirrorCfg));

        LOGF_LOG_INFO("DownstreamIntf = %s",DownstreamIntf);
        LOGF_LOG_INFO("MirrorIntf = %s",MirrorIntf);

        retval = fapi_sys_ppa_uninit();
        if (retval != UGW_SUCCESS) {
                LOGF_LOG_DEBUG("Failed to disable PPA, exiting mirroring!!\n");
                return retval;
        }

        snprintf(buf,MAX_SYSBUF_SIZE,"echo %s >/proc/mirror", MirrorIntf);
        retval = scapi_spawn(buf, SCAPI_BLOCK, &nChildSt);
        if (retval !=  UGW_SUCCESS){
                LOGF_LOG_DEBUG("Failed to configure mirror port.\n");
                return retval;
        }
        return retval;
}
/* =========================================================================== *
 *  Function Name : DisableMirroring                                     *
 *  Description   : This fapi is used to disable portmirroring configurations  *
 *                  on the router.                                             *
 *                  user needs to provide upstream interface, downstream       *
 *                  interface and Mirrored interface as inputs.                *
 *                  Fapi finds the switch port attached to interface and       *
 *                  disables port Mirroring configuration in switch            *
 *  Input         : Upstream Interface, Downstream Interface, Mirror Interface *
 *  Output        : None                                                       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ===========================================================================*/
int32_t xRX220_DisableMirroring(IN char * DownstreamIntf, IN char * MirrorIntf)
{
        char buf[MAX_SYSBUF_SIZE]={0};
        PPA_CMD_ENABLE_INFO PPAenInfo;
        PPAInit_cfg_t PPA_Cfg;
        GSW_portCfg_t PortCfg;
        GSW_monitorPortCfg_t PortMirrorCfg;
        int32_t retval = UGW_SUCCESS,nChildSt;
        memset(&PPAenInfo, 0, sizeof(PPAenInfo));
        memset(&PortCfg, 0, sizeof(PortCfg));
        memset(&PortMirrorCfg, 0, sizeof(PortMirrorCfg));

        PPA_Cfg.Min_Hits = PPA_MIN_HITS;
        PPA_Cfg.nMax_LANNumSessions = -1;
        PPA_Cfg.nMax_WANNumSessions = -1;
        PPA_Cfg.nMax_McastNumSessions = -1;
        PPA_Cfg.nMax_BrNumSessions = -1;
        PPA_Cfg.Def_MTUSize = -1;
        PPA_Cfg.bMibMode = -1;

        retval = fapi_sys_ppa_init (&PPA_Cfg);
        if (retval != UGW_SUCCESS)
        {
                printf ("PPA init failed\n");
        }
        else
        {
                printf ("PPA INIT SUCCESS\n");
                LOGF_LOG_INFO("DownstreamIntf %s and MirrorIntf %s is down",DownstreamIntf,MirrorIntf);
        }

        snprintf(buf,MAX_SYSBUF_SIZE,"echo disable >/proc/mirror");
        retval = scapi_spawn(buf, SCAPI_BLOCK, &nChildSt);
	if (retval !=  UGW_SUCCESS)
                LOGF_LOG_DEBUG("Failed to disable mirror port.\n");
        return retval;

}
