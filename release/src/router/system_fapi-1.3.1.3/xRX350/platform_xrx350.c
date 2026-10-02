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
#include "platform_xrx350.h"
#include "ltq_api_include.h"
#include "scapi_interfaces_defines.h"

/* =============================================================================
* Function Name : xRX350_wanSWO                                               *
* Description   : xRX350_wanSWO is responsible for handling unloading and      *
*		  and re-initialization of wan and ppa modules during wan      *
		  change over
* Input		: old wanmode and new wanmode of type WAN_TYPE_t               *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t XRX350_wanSWO(sys_cfg_t * sysCfg)
{
	int32_t ret = UGW_SUCCESS;
	LOGF_LOG_DEBUG("new wan mode = %d\n", sysCfg->priWAN);
	return ret;
}

/* =============================================================================
* Function Name : xRX350_module_load		 	         	       *
* Description   :
* Input		: new wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX350_module_load(WAN_TYPE_t next_tc_mode)
{
	int32_t ret = UGW_SUCCESS;
	char dsl_tc[MODULE_NAME_SIZE] = { 0 };
	char cmd_buf[MAX_DATA_LEN] = { 0 };
#ifdef CONFIG_VRX518_SUPPORT
	char vrx_proc_dir[] = "vrx518";
#else
	char vrx_proc_dir[] = "ltq_vrx318";
#endif

	LOGF_LOG_DEBUG("new tc mode = %d\n", next_tc_mode);

	if ((next_tc_mode == DSL_PTM) || (next_tc_mode == DSL_ATM) || (next_tc_mode == DSL_xTM)) {

		/*load vrx518_tc or vrx318_tc module */
		//ret = scapi_insmod(xRX350DSLModules[0], NULL);
		sprintf(cmd_buf, "insmod /lib/modules/*/%s.ko", xRX350DSLModules[0]);
		LOGF_LOG_DEBUG("%s\n", cmd_buf);
		system(cmd_buf);
		//if (ret != UGW_SUCCESS) {
		//      LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX350DSLModules[0]);
		//}
		//usleep(500);
		if (next_tc_mode == DSL_PTM) {
			strcpy(dsl_tc, "ptm");
		} else if (next_tc_mode == DSL_ATM) {
			strcpy(dsl_tc, "atm");
		}
		sprintf(cmd_buf, "echo load %s 0 > /proc/driver/%s/tc_switch", dsl_tc, vrx_proc_dir);
		LOGF_LOG_DEBUG("%s\n", cmd_buf);
		system(cmd_buf);
	}
	return ret;
}

/* =============================================================================
* Function Name : xRX350_module_unload					       *
* Description   : 
* Input		: old wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX350_module_unload(WAN_TYPE_t next_tc_mode)
{
	int ret = UGW_SUCCESS;
	char module[MODULE_NAME_SIZE] = { 0 };

	LOGF_LOG_DEBUG("old tc mode = %d\n", next_tc_mode);
	if ((next_tc_mode == DSL_PTM) || (next_tc_mode == DSL_ATM) || (next_tc_mode == DSL_xTM)) {

		/*unload vrx518_tc or vrx318_tc module */
		strcpy(module, xRX350DSLModules[0]);
		//ret = scapi_rmmod(module, 0);
		//if (ret != UGW_SUCCESS) {
		//      LOGF_LOG_CRITICAL("module %s rmmod failure\n", xRX350DSLModules[0]);
		//}
	}
	return ret;
}

/* =============================================================================
* Function Name : xRX350_module_init                                           *
* Description   : xRX350_module_init is responsible for loading wan and	       *
*		  and common driver modules for xRX350 platform 	       *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX350_module_init(void)
{
	sys_cfg_t sys_cfg;
	PPAInit_cfg_t PPA_Cfg;
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	char sCmd[MAX_DATA_LEN]={0};
	char *pcOrigArr[] = {
		[0] = "eth0_1",
		[1] = "eth0_2",
		[2] = "eth0_3",
		[3] = "eth0_4",
		[4] = "eth1",
	};
	char pcTmpArr[5][MAX_DATA_LEN];

	int32_t ret = UGW_SUCCESS, nCount = 0, nIter = 0, nMatchFound = 0;

	memset(&PPA_Cfg, 0, sizeof(PPA_Cfg));
	memset(&sys_cfg, 0, sizeof(sys_cfg_t));
	PPA_Cfg.Min_Hits = PPA_MIN_HITS;
	PPA_Cfg.nMax_LANNumSessions = -1;
	PPA_Cfg.nMax_WANNumSessions = -1;
	PPA_Cfg.nMax_McastNumSessions = -1;
	PPA_Cfg.nMax_BrNumSessions = -1;
	PPA_Cfg.Def_MTUSize = -1;
	PPA_Cfg.bMibMode = 0;
	PPA_Cfg.bIP_Verify = 1;

	ret = PPAInit(&PPA_Cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI PPA init failed!! Initializing through cmd\n");
		ret = system("ppacmd init");
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("PPA Initialization failed!!!\n");
		}
	}

	ret = scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES, NULL);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if ((strcmp(pxTmpIface->cEnable, "true") == 0) && (strcmp(pxTmpIface->cMode, "ETH") == 0)) {
			if (strcmp(pxTmpIface->cIfName, pcOrigArr[nCount]) != 0) {
				/*interface doesnt match. */
				/*Compare for match/conflicts in orig in higher indices */

				/*Match only with higher indices */
				for (nIter = nCount + 1; nIter < 5; nIter++) {
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
					snprintf(sCmd, MAX_DATA_LEN, "ip link set name %s %s", pxTmpIface->cIfName, pcTmpArr[nCount]);
				} else {
					snprintf(sCmd, MAX_DATA_LEN, "ip link set name %s %s", pxTmpIface->cIfName, pcOrigArr[nCount]);
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
* Function Name : xRX350_module_uninit                            	       *
* Description   : this function is responsible for unloading wan and           *
*		  and common driver modules.                                   *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX350_module_uninit(void)
{

	sys_cfg_t sys_cfg;
	int32_t ret = UGW_FAILURE;
	memset(&sys_cfg, 0, sizeof(sys_cfg_t));

	ret = xRX350_remove_common_modules();
	if (ret != UGW_SUCCESS) {
		return ret;
	}
	ret = xRX350_remove_wan_modules();
	if (ret != UGW_SUCCESS) {
		return ret;
	}

	return ret;

}

/* =============================================================================
* Function Name : xRX350_load_common_modules                                   *
* Description   : this is a helper function which takes platform name as input *
*		  and loads common driver modules used for ethwan mode         *
* Input		: void                                           *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX350_load_common_modules(void)
{

	int32_t ret = UGW_SUCCESS;
	int32_t ModIndx = 0, nSIndx = 0;
	char cmd_buf[MAX_DATA_LEN];
	memset(cmd_buf, 0, sizeof(char) * MAX_DATA_LEN);

	for (ModIndx = 0; ModIndx < (int32_t) (sizeof(xRX350PPAModules) / sizeof(*xRX350PPAModules)); ModIndx++) {

		if (check_loaded_modules(xRX350PPAModules[ModIndx]) != UGW_SUCCESS) {
			LOGF_LOG_INFO("......loading %s\n", xRX350PPAModules[ModIndx]);
			ret = scapi_insmod(xRX350PPAModules[ModIndx], NULL);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("insmod %s failed!\n", xRX350PPAModules[ModIndx]);
			}
			usleep(500000);
			LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX350PPAModules[ModIndx]);

		} else {
			LOGF_LOG_DEBUG("module %s already loaded no need to insmod\n", xRX350PPAModules[ModIndx]);
			ret = UGW_SUCCESS;
		}
	}
	for (nSIndx = 0; nSIndx < (int32_t) (sizeof(xRX350SplModules) / sizeof(*xRX350SplModules)); nSIndx++) { 
		if (is_module_exists(xRX350SplModules[nSIndx]) == UGW_SUCCESS) {
                                LOGF_LOG_INFO("......loading %s\n", xRX350SplModules[nSIndx]);
                                ret = scapi_insmod(xRX350SplModules[nSIndx], NULL);
                                if (ret != UGW_SUCCESS) {
                                        LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX350SplModules[nSIndx]);
                                } else {
                                        LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX350SplModules[nSIndx]);
                                }
                }	 
	}

	for (ModIndx = 0; ModIndx < (int32_t) (sizeof(xRX350NetworkModules) / sizeof(*xRX350NetworkModules)); ModIndx++) {
		if (is_module_exists(xRX350NetworkModules[ModIndx]) == UGW_SUCCESS) {
			LOGF_LOG_INFO("......loading %s\n", xRX350NetworkModules[ModIndx]);
			ret = scapi_insmod(xRX350NetworkModules[ModIndx], NULL);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX350NetworkModules[ModIndx]);
			} else {
				LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX350NetworkModules[ModIndx]);
			}
		}
	}
	return ret;
}

/* =============================================================================
* Function Name : xRX350_remove_common_modules                                 *
* Description   : this is a helper function which takes platform name as input *
*                 and unloads common driver modules used in ethwan mode        *
* Input         : void                                           *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t xRX350_remove_common_modules(void)
{

	int32_t ret = UGW_SUCCESS;
	int32_t ModIndx = 0, nSIndx = 0;
	char module[MODULE_NAME_SIZE];

	memset(module, 0, sizeof(char) * MODULE_NAME_SIZE);

	for (ModIndx = (int32_t) (sizeof(xRX350PPAModules) / sizeof(*xRX350PPAModules)) - 1; ModIndx >= 0; ModIndx--) {
		strcpy(module, xRX350PPAModules[ModIndx]);
		if (check_loaded_modules(xRX350PPAModules[ModIndx]) != UGW_SUCCESS) {
			LOGF_LOG_INFO("......unloading %s\n", xRX350PPAModules[ModIndx]);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("rmmod %s failed!\n", xRX350PPAModules[ModIndx]);
				//return ret;
			}
			LOGF_LOG_DEBUG("rmmod of %s Successful!\n", xRX350PPAModules[ModIndx]);
		} else {
			LOGF_LOG_DEBUG("module %s already loaded no need to insmod\n", xRX350PPAModules[ModIndx]);
			ret = UGW_SUCCESS;
		}
	}
	for (nSIndx = 0; nSIndx < (int32_t) (sizeof(xRX350SplModules) / sizeof(*xRX350SplModules)); nSIndx++) {
		strcpy(module, xRX350SplModules[nSIndx]);
                if (is_module_exists(xRX350SplModules[nSIndx]) == UGW_SUCCESS) {
                                LOGF_LOG_INFO("......unloading %s\n", xRX350SplModules[nSIndx]);
                                ret = scapi_rmmod(module, 0);
                                if (ret != UGW_SUCCESS) {
                                        LOGF_LOG_CRITICAL("module %s rmmod failure\n", xRX350SplModules[nSIndx]);
                                } else {
                                        LOGF_LOG_DEBUG("rmmod of %s Successful!\n", xRX350SplModules[nSIndx]);
                                }
                }
        }

	for (ModIndx = 0; ModIndx < (int32_t) (sizeof(xRX350NetworkModules) / sizeof(*xRX350NetworkModules)); ModIndx++) {
		strcpy(module, xRX350NetworkModules[ModIndx]);
		if (is_module_exists(xRX350NetworkModules[ModIndx]) == UGW_SUCCESS) {
			LOGF_LOG_INFO("......unloading %s\n", xRX350NetworkModules[ModIndx]);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s rmmod failure\n", xRX350NetworkModules[ModIndx]);
			} else {
				LOGF_LOG_DEBUG("rmmod of %s Successful!\n", xRX350NetworkModules[ModIndx]);
			}
		}
	}
	return ret;
}

/* =============================================================================
* Function Name : xRX350_load_wan_modules                                              *
* Description   : this is a helper function which takes platform name as input *
*                 and loads wan driver modules used in ethwan mode             *
* Input         : void                                           *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX350_load_wan_modules(void)
{
	int32_t ret = UGW_SUCCESS;
	char cmd_buf[MAX_DATA_LEN];
	int32_t wanModIndx = 0;
	memset(cmd_buf, 0, sizeof(char) * MAX_DATA_LEN);

	while (xRX350WanModules[wanModIndx] != NULL) {

		if ((check_loaded_modules(xRX350WanModules[wanModIndx]) != UGW_SUCCESS)) {
			LOGF_LOG_INFO("......loading %s\n", xRX350WanModules[wanModIndx]);
			ret = scapi_insmod(xRX350WanModules[wanModIndx], NULL);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX350WanModules[wanModIndx]);
				//return ret;
			} else {
				LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX350WanModules[wanModIndx]);
			}
			usleep(500000);
		} else {
			LOGF_LOG_DEBUG("Module %s already loaded! no need to insmod.\n", xRX350WanModules[wanModIndx]);
			ret = UGW_SUCCESS;
		}
		wanModIndx++;
	}

	for (wanModIndx = 0; wanModIndx < (int32_t) (sizeof(xRX350WanOptionalModules) / sizeof(*xRX350WanOptionalModules)); wanModIndx++) {

		if ((check_loaded_modules(xRX350WanOptionalModules[wanModIndx]) != UGW_SUCCESS)) {
			if (is_module_exists(xRX350WanOptionalModules[wanModIndx]) == UGW_SUCCESS) {
				LOGF_LOG_INFO("......loading %s\n", xRX350WanOptionalModules[wanModIndx]);
				ret = scapi_insmod(xRX350WanOptionalModules[wanModIndx], NULL);
				if (ret != UGW_SUCCESS) {
					LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX350WanOptionalModules[wanModIndx]);
					//return ret;
				} else {
					LOGF_LOG_DEBUG("insmod of %s Successful!\n", xRX350WanOptionalModules[wanModIndx]);
				}
				usleep(500000);
			} else {
				LOGF_LOG_DEBUG("Module %s does not exist! May be no need to insmod.\n", xRX350WanOptionalModules[wanModIndx]);
				ret = UGW_SUCCESS;
			}
		} else {
			LOGF_LOG_DEBUG("Module %s already loaded! no need to insmod.\n", xRX350WanOptionalModules[wanModIndx]);
			ret = UGW_SUCCESS;
		}
	}

	return ret;

}

/* =============================================================================
* Function Name : xRX350_remove_wan_modules                                            *
* Description   : this is a helper function which takes platform name as input *
*                 and unloads wan driver modules used in ethwan mode           *
* Input         : platform name enum                                           *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX350_remove_wan_modules(void)
{
	int32_t ret = UGW_FAILURE;
	int32_t ModIndx = 0;
	char module[MODULE_NAME_SIZE] = { 0 };

	for (ModIndx = (int32_t) (sizeof(xRX350WanOptionalModules) / sizeof(*xRX350WanOptionalModules)) - 1; ModIndx >= 0; ModIndx--) {
		strcpy(module, xRX350WanOptionalModules[ModIndx]);
		if ((check_loaded_modules(xRX350WanOptionalModules[ModIndx]) == UGW_SUCCESS)) {
			LOGF_LOG_INFO("......unloading %s\n", module);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_DEBUG("rmmod %s failed!\n", xRX350WanOptionalModules[ModIndx]);
				//      return ret;
			}
		}
	}
	for (ModIndx = (int32_t) (sizeof(xRX350WanModules) / sizeof(*xRX350WanModules)) - 1; ModIndx >= 0; ModIndx--) {
		strcpy(module, xRX350WanModules[ModIndx]);
		if ((check_loaded_modules(xRX350WanModules[ModIndx]) != UGW_SUCCESS)) {
			LOGF_LOG_INFO("......unloading %s\n", module);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_DEBUG("rmmod %s failed!\n", xRX350WanModules[ModIndx]);
				//      return ret;
			}
		}
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX350_PortIdGet	                         	       *
* Description   : fapi to find switch port id corresponding to network         *
*                 interface                                                    *
* InPut		: interface name 	         			       *
* OutPut	: none                   				       *
* Returns       : Port Id or UGW_FAILURE                                       *
==============================================================================*/
int32_t xRX350_PortIdGet(IN char *ifname)
{
	PPA_CMD_PORTID_INFO portid;
	int32_t ret = UGW_SUCCESS;
	memset(&portid, 0, sizeof(portid));
	strncpy(portid.ifname, ifname, sizeof(portid.ifname));
	ret = PPA_IOCTL(PPA_CMD_GET_PORTID, &portid);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppacmd get portid failed\n");
		return ret;
	}
	LOGF_LOG_DEBUG("Interface = %s; PortId=%d\n", portid.ifname, (int32_t) portid.portid);

	return portid.portid;

}

/* =============================================================================
 * * Function Name : xRX350_SetInterface                                          *
 * * Description   : xRX350_SetInterface is responsible for                       *
 * *                 calling platform specific FAPIs.                             *
 * * Input         : InterfaceType enum,State enum                                                          *
 * * OutPut        : None                                                         *
 * * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 * ============================================================================== */
int32_t xRX350_SetInterface(IN InterfaceType eInterface,IN State eSetState,IN void * pLedAttr)
{
	int32_t nRet = UGW_FAILURE;
	sNetDevAttr *pNetDevAttr = NULL;
	sNetDevAttr xNetDevAttr;
	sTimerAttr xTimerAttr;
    	sDefaultAttr xDefAttr;
	void *pAttr = NULL;
	TriggerType eTriggerType = TRIGGER_NONE;

	switch(eInterface) {
	case INTERNET:
                if(eSetState == UP) {
                        if(pLedAttr != NULL) {
                                pNetDevAttr = (sNetDevAttr *) pLedAttr;
                        }
                        else {
                                pNetDevAttr = &xNetDevAttr;
                                memset(&xNetDevAttr, 0, sizeof(sNetDevAttr));
                        }
                        pNetDevAttr->nBrightness = 100;
                        pNetDevAttr->nInterval = 100;
                        pNetDevAttr->unMode =  LED_TRIGGER_MODE_LINK | LED_TRIGGER_MODE_RX | LED_TRIGGER_MODE_TX;
                        LOGF_LOG_INFO("Turning Internet LED ON ...\n");
                        LOGF_LOG_DEBUG("nBrightness:%d nInterval:%d unMode:%u\n", pNetDevAttr->nBrightness, pNetDevAttr->nInterval, pNetDevAttr->unMode);
                        pAttr = (void *)pNetDevAttr;
                        nRet = FAPI_LEDSetAttribute(INTERNETLED, TRIGGER_NETDEV,pAttr);
                }
		else {
	                LOGF_LOG_INFO("Turning Internet LED OFF ...\n");
			memset(&xDefAttr, 0, sizeof(sDefaultAttr));
	                nRet = FAPI_LEDSetAttribute(INTERNETLED, TRIGGER_NONE,(void *)&xDefAttr);
        	}
	break;
	case SHDAP:
		switch(eSetState) {
		case HEART_BEAT:
			eTriggerType = TRIGGER_TIMER;
			memset(&xTimerAttr, 0, sizeof(sTimerAttr));
			xTimerAttr.nBrightness = 255;
			xTimerAttr.nDelayOn = 250;
			xTimerAttr.nDelayOff = 250;
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
		default :
			LOGF_LOG_INFO("Invalid State for SHDAP\n");
			return nRet;
		}

		nRet = FAPI_LEDSetAttribute(DECTLED, eTriggerType, pAttr);
	break;
	case VDSL:
	case VDSL1:
		switch(eSetState) {
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
		default :
			LOGF_LOG_INFO("Invalid State for VDSL\n");
			return nRet;
		}

		if(eInterface == VDSL){
			nRet = FAPI_LEDSetAttribute(BROADBANDLED, eTriggerType, pAttr);
		}
		else if(eInterface == VDSL1){
			nRet = FAPI_LEDSetAttribute(BROADBANDLED1, eTriggerType, pAttr);
		}
	break;
        default  :
                 LOGF_LOG_INFO("Invalid Interface %d state %d for 350 \n",eInterface,eSetState);
		 nRet = UGW_SUCCESS;
	}
	return nRet;
}

/* ================================================================================
 * * Function Name : xRX350_SetBridgeState                                        *
 * * Description   : xRX350_SetBridgeState is responsible for                     *
 * *                 setting bridge MAC address learning on and off               *
 * * Input         : Enable/Disable value                                         *
 * * OutPut        : None                                                         *
 * * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 * ============================================================================== */
int32_t xRX350_SetBridgeAcclState(IN char *operation)
{
	int32_t ret = UGW_SUCCESS;
	PPA_CMD_BRIDGE_ENABLE_INFO info;

	info.flags = 0;

	if (operation == NULL) {
		LOGF_LOG_ERROR("Function called with NULL pointer!\n");
		ret = UGW_FAILURE;
	} else if (!strcmp(operation, "enable")) {
		info.bridge_enable = 1;
		ret = PPA_IOCTL(PPA_CMD_BRIDGE_ENABLE, &info);
	} else if (!strcmp(operation, "disable")) {
		info.bridge_enable = 0;
		ret = PPA_IOCTL(PPA_CMD_BRIDGE_ENABLE, &info);
	} else {
		LOGF_LOG_ERROR("Function called with unrecognized input value %s\n", operation);
		ret = UGW_FAILURE;
	}

	LOGF_LOG_DEBUG("Setting bridge to %s done with return value %d\n", operation, ret);
	return ret;
}

/* =============================================================================
 * * Function Name : xRX350_SetWanPhyGpio                                      *
 * * Description   : xRX350_SetWanPhyGpio is responsible for                   *
 * *                 setting a value to WAN PHY GPIO                        *
 * * Input         : uint8_t nVal                                               *
 * * OutPut        : None                                                      *
 * * Returns       : UGW_SUCCESS/UGW_FAILURE                                   *
 * =========================================================================== */
int32_t xRX350_SetWanPhyGpio(IN uint8_t nVal)
{
	/*Stub function*/
	nVal = nVal;
	return UGW_SUCCESS;
}
