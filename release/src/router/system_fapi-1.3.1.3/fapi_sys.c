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
#include <errno.h>
#include <glob.h>
#include <ulogging.h>
#include "fapi_sys_common.h"
#include "ltq_api_include.h"
#include "fapi_sys.h"
#include "fapi_init_sequence.h"
#include "fapi_debug.h"
#ifdef PLATFORM_XRX200 
#include "xRX220_callback.h"
#endif
#ifdef PLATFORM_XRX500 
#include "xRX350_callback.h"
#endif
#ifdef PLATFORM_XRX750 
#include "xRX750_callback.h"
#endif
#ifdef PLATFORM_XRX330 
#include "xRX330_callback.h"
#endif

#ifndef LOG_LEVEL
uint16_t LOGLEVEL = SYS_LOG_DEBUG + 1;
#else
uint16_t LOGLEVEL = LOG_LEVEL + 1;
#endif

#ifndef LOG_TYPE
uint16_t LOGTYPE = SYS_LOG_TYPE_FILE;
#else
uint16_t LOGTYPE = LOG_TYPE;
#endif


int32_t fapi_CfgBridgeAccel(INOUT brAccelCfg_t * BrAccelCfg)
{
	int32_t nRet = UGW_SUCCESS;
	int32_t nPlatformType = get_hw_platform();

	/* support for bridge acceleration in fapi needed only in 220/330 platform */
	if ( nPlatformType != HW_PLATFORM_xRX220 && nPlatformType != HW_PLATFORM_xRX330 ) {
		LOGF_LOG_INFO("nothing to be done for this platform for FAPI config bridge acceleration!!\n");
		return nRet;
	}
	/* invoke call back function to load wan and ppa driver modules*/
	nRet = fapicb.cfgbrAccel(BrAccelCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_ERROR("FAPI config bridge acceleration failed with error code:%d!!\n", nRet);
	}

	return nRet;

}



/* =============================================================================
* Function Name : fapi_syslogset  					       *
* Description   : fapi_syslogset takes log info from SL and sets loglevel in   *
* 		  fapi  		                                       *
* Input		: sl_loglevel, sl_logtype                                      *   
* OutPut	: none                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      * 
============================================================================== */
int32_t fapi_syslogset(int16_t sl_logl, int16_t sl_logt)
{
	int32_t ret=UGW_SUCCESS;
	LOGLEVEL = sl_logl;
	LOGTYPE = sl_logt;
	LOGF_LOG_INFO("new loglevel = %d ; new logtype = %d \n",LOGLEVEL,LOGTYPE);	
	return ret;
}


/* =============================================================================
* Function Name : fapi_sys_SWO 						       *
* Description   : fapi_sys_SWO() is responsible for unloading and loading      *
*                 modules during wan switch over                               *
* Input		: sysCfg_t                                                     *
* OutPut	:                                                              *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_SWO(sys_cfg_t *sysCfg )
{

	int32_t ret = UGW_SUCCESS;

	/* invoke call back function to load wan and ppa driver modules*/
	ret = fapicb.wanSWO(sysCfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI switch over failed!!\n");
	}
		
	return ret;

}
/* =============================================================================
* Function Name : fapi_sys_load 					       *
* Description   : fapi_sys_load is responsible for unloading and loading       *
*                 modules during wan switch over                               *
* Input		: new wan mode                                                 *
* OutPut	:                                                              *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t fapi_sys_load(IN WAN_TYPE_t next_tc_mode)
{
        int32_t ret = UGW_SUCCESS;

	ret = fapicb.moduleLoad(next_tc_mode);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("module load failed!!\n");
	}
        return ret;
}
/* =============================================================================
* Function Name : fapi_sys_unload					       *
* Description   : fapi_sys_unload is responsible for unloading driver modules  *
* Input		: old wan mode                                                 *
* OutPut	:                                                              *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */


int32_t fapi_sys_unload(IN WAN_TYPE_t next_tc_mode)
{
         int32_t ret = UGW_SUCCESS;

	ret = fapicb.moduleUnLoad(next_tc_mode);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG(" module unload failed!!\n");
	}

        return ret;
}

/* =============================================================================
* Function Name : fapi_sys_generic_load
* Description   : fapi_sys_generic_load is responsible for loading modules
* Input         : module name
* OutPut        : 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t fapi_sys_generic_load(IN Modules_t * modules)
{
	int32_t nRet = UGW_SUCCESS;
	uint32_t nModIndx = 0;

	for(nModIndx = 0; nModIndx < modules->uNum; nModIndx++)
	{
		if((check_loaded_modules(modules->module[nModIndx]) != UGW_SUCCESS))
		{
			nRet = scapi_insmod(modules->module[nModIndx], modules->pcOptions);
			if(nRet != UGW_SUCCESS)
			{
				LOGF_LOG_CRITICAL("module %s insmod failure with error code: %s\n", modules->module[nModIndx], strerror(-nRet));
				goto end;
			} else {
				LOGF_LOG_INFO("insmod of %s Successful!\n", modules->module[nModIndx]);
			}
		} else {
			LOGF_LOG_INFO("Module %s already loaded! no need to insmod.\n", modules->module[nModIndx]);
			nRet = UGW_SUCCESS;
		}
	}

end:
	return nRet;
}

/* ========================================================================================
* Function Name : fapi_sys_generic_unload                                                 *
* Description   : fapi_sys_generic_unload is responsible for unloading driver modules     *
* Input         : module name
* OutPut        : 
* Returns       : UGW_SUCCESS/UGW_FAILURE
========================================================================================= */
int32_t fapi_sys_generic_unload(IN Modules_t * modules)
{
        int32_t nRet = UGW_FAILURE, nModIndx = 0;

        for(nModIndx = (modules->uNum-1); nModIndx >= 0; nModIndx--)
        {
                if ((check_loaded_modules(modules->module[nModIndx]) != UGW_SUCCESS))
                {
                        nRet = scapi_rmmod(modules->module[nModIndx], 0);
                        if(nRet != UGW_SUCCESS)
                        {
				LOGF_LOG_CRITICAL("rmmod of module %s failure with error code: %s\n", modules->module[nModIndx], strerror(-nRet));
				goto end;
                        }
                        else
                        {
                                LOGF_LOG_INFO("Module %s is sucessfully unloaded.\n", modules->module[nModIndx]);
                        }
                }
        }

end:
        return nRet;
}

/* =============================================================================
* Function Name : fapi_sys_mknod
* Description   : fapi_sys_mknod is responsible for creating block or character 
                  special file for NAME of the given TYPE.
* Input         : MKNODcfg_t
* OutPut        : 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */

int32_t fapi_sys_mknod(IN MKNODcfg_t *xMknod)
{
	int32_t nRet = UGW_SUCCESS;

	xMknod->unDevNo = xMknod->unMajorNo << 8;
	xMknod->unDevNo |= xMknod->unMinorNo;

	if(mknod(xMknod->DevName, S_IFCHR | 0666, xMknod->unDevNo))
	{
		LOGF_LOG_CRITICAL(" make nod failed!!\n");
		nRet = UGW_FAILURE;
		goto end;
	}
	else
		LOGF_LOG_DEBUG(" make nod created for %s\n", xMknod->DevName);
end:
	return nRet;
}

/* =============================================================================
* Function Name : fapi_sys_init                            		       *
* Description   : fapi_sys_init() is responsible for loading wan and	       *
*		  and common driver modules.After loading modules              *
*                 it calls fapi_ppa_init() to initialize PPA acceleration      *	
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_init(void)
{

	int32_t ret = UGW_SUCCESS;

	LOG_FAPI_CALLFLOW_OPEN(FAPI_SYS_INIT_DEBUG);

	/* invoke call back function to load wan and ppa driver modules*/
	ret = fapicb.SysInit();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI init failed!!\n");
	}

	LOG_FAPI_CALLFLOW_CLOSE();	
		
	return ret;

}

/* =============================================================================
* Function Name : fapi_sys_uninit                            		       *
* Description   : fapi_sys_uninit() is responsible for unloading wan and       *
*		  and common driver modules.                                   *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_uninit(void)
{

	int32_t ret = UGW_SUCCESS;
	
	ret = fapicb.SysUnInit();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI uninit failed!!\n");
	}
		
	return ret;

}

/* =============================================================================
* Function Name : fapi_sys_ppa_init                            		       *
* Description   : This function performs PPA initialization by calling callback*
* Input		: Default configurations filled in PPAInit_cfg_t struct        *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_ppa_init(PPAInit_cfg_t *ppaInit_Cfg)
{
	int32_t ret = UGW_SUCCESS;

	ret = fapicb.ppa_init(ppaInit_Cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI PPA Initialization Failed!!\n");
	}
	return ret;
}

/* =============================================================================
* Function Name : fapi_sys_ppa_uninit                         		       *
* Description   : This function unitializes PPA or PPA exit		       *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_ppa_uninit(void)
{
	int ret = UGW_SUCCESS;

	ret = fapicb.ppa_uninit();
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI PPA UnInitialization Failed!!\n");
	}

	return ret;
}

/* =============================================================================
* Function Name : fapi_sys_ppa_enable                         		       *
* Description   : This function enables LAN and WAN acceleration 	       *
* Input		: PPA_CMD_ENABLE_INFO struct to selectively ENABLE/DISABLE LAN *
*		  or WAN acceleration					       *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_ppa_enable(IN PPA_CMD_ENABLE_INFO * enable_info)
{
	int ret = UGW_SUCCESS;
	ret = fapicb.ppaHook(enable_info);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("PPA hook add enable of disable failed!!\n");
	}
	return ret;
}

/* =============================================================================
* Function Name : fapi_sys_set	                         		       *
* Description   : This function configures syscfg struct with default params   *
* InPut		: sys_cfg_t              				       *
* OutPut	: updates /tmp/syscfg file				       *                                                         
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t fapi_sys_set(IN sys_cfg_t * sys_cfg )
{
	int ret = UGW_SUCCESS;

	ret = fapicb.sysSet(sys_cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Set configuration Failed!!\n");
	}

	return ret;
}



/* =============================================================================
* Function Name : fapi_sys_get	                         		       *
* Description   : This function reads /tmp/syscfg and updates sys_cfg_t struct *
* InPut		: sys_cfg_t struct 					       *
* OutPut	: updates /tmp/syscfg file				       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
==============================================================================*/
int32_t fapi_sys_get(IN sys_cfg_t * sysCfg)
{
	int nRet = UGW_SUCCESS;

	nRet = fapicb.sysGet(sysCfg);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Get configuration Failed!!\n");
	}
	return nRet;
}

/* =============================================================================
* Function Name : fapi_sys_if_attach	                         	       *
* Description   : fapi to attach an interface to PPA for acceleration          *
*                 this fapi is called by sl_eth() or other service layer       *
*		  functions. caller needs to fill struct ifcfg_t and provide   *
*		  ifcfg_t.ifName = interface that needs to be accelerated,     *
*                 ifcfg_t.wanIf_flag = 1 if interface is WAN,0 if interface is *
*                 LAN							       *
* InPut		: struct ifcfg_t 	         			       *
* OutPut	: None                   				       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
==============================================================================*/
int32_t fapi_sys_if_attach(IN ifcfg_t * ifCfg)
{
	int ret = UGW_SUCCESS;

	ret = fapicb.ppaAdd(ifCfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to add interface to PPA!!\n");
	}
	return ret;
}

/* =============================================================================
* Function Name : fapi_sys_if_dettach	                         	       *
* Description   : fapi to remove an interface from  acceleration               *
*                 this fapi is called by sl_eth() or other service layer       *
*		  functions. caller needs to fill struct ifcfg_t and provide   *
*		  ifcfg_t.ifName = interface to be removed accelerated,        *
*                 ifcfg_t.wanIf_flag = 1 if interface is WAN,0 if interface is *
*                 LAN							       *
* InPut		: struct ifcfg_t 	         			       *
* OutPut	: None                   				       *   
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
==============================================================================*/
int32_t fapi_sys_if_detach(IN ifcfg_t * ifCfg)
{
	int ret = UGW_SUCCESS;

	ret = fapicb.ppaDel(ifCfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("PPA Del Interface failed!!\n");
	}
	return ret;
}

/* =============================================================================
* Function Name : fapi_updateLinkEnable	                         	           *
* Description   : fapi to find whether the linkenable is true/false.(Platform specific based on primary wan if only 1 wanmode supported)  *
* In		: Link enable value from interface.cfg  	        		       *
* Out	: Link enable modified if any platform dependency          		       *
* Returns   : void                                                             *
==============================================================================*/
void fapi_updateLinkEnable(INOUT char *pcLinkEnable)
{
	sys_cfg_t sysCfg;
	if (get_hw_platform() != HW_PLATFORM_xRX220) {
		LOGF_LOG_INFO("nothing to be done for this platform!!\n");
		return;
	}
	fapi_sys_get(&sysCfg);
	if (sysCfg.priWAN == ETH)
		strcpy(pcLinkEnable, "true");
	else
		strcpy(pcLinkEnable, "false");

	return;
}

/* =============================================================================
* Function Name : fapi_get_portid	                         	       *
* Description   : fapi to find switch port id corresponding to network         *
*                 interface                                                    *
* InPut		: interface name 	         			       *
* OutPut	: none                   				       *
* Returns       : Port Id or UGW_FAILURE                                       *
==============================================================================*/
int32_t fapi_get_portid(IN char *ifname)
{
	int32_t PortId = UGW_FAILURE;
	
	PortId = fapicb.getPortId(ifname);
	if (PortId < UGW_SUCCESS) {
		LOGF_LOG_DEBUG("fapi PortId Get faild!\n");
	}

	return PortId;
}

/* =============================================================================
* Function Name : fapi_set_brCfg	                         	       *
* Description   : fapi to set bridge configuration			       *
*                 interface                                                    *
* InPut		: wan interface name, lan interface name, operation 	       *
* OutPut	: none                   				       *
* Returns       : UGW_SUCCESS or UGW_FAILURE                                       *
==============================================================================*/
int32_t fapi_set_brCfg(IN char *wanInf, char *lanPorts, IN char *brname, IN char * Oper)
{
	int nRet = UGW_SUCCESS;	
	if (get_hw_platform() != HW_PLATFORM_xRX220) 
	{
		LOGF_LOG_INFO("nothing to be done for this platform!!\n");
		return nRet;
	}

	nRet = fapicb.setbrCfg(wanInf, lanPorts, brname , Oper);
	return nRet;
}

/* =============================================================================
* Function Name : PPA_IOCTL	                         	               *
* Description   : helper functionto invoke ioctl                               *
* InPut		: IOCTL cmd and structure(data) required by IOCTL 	       *
* OutPut	: data returned by ioctl                   	               *
* Returns       : UGW_SUCCESS or UGW_FAILURE                                   *
==============================================================================*/
int32_t PPA_IOCTL(IN int ioctl_cmd, INOUT void *data)
{
	int32_t ret = UGW_SUCCESS;
	int32_t fd = 0;

	if ((fd = open(PPA_DEVICE, O_RDWR)) < 0) {
		LOGF_LOG_DEBUG("[%s] : open PPA device failed.\n", PPA_DEVICE);
		ret = ERR_BAD_FD;
	} else {
		if (ioctl(fd, ioctl_cmd, data) < 0) {
			LOGF_LOG_DEBUG("ioctl failed for NR %d.\n", _IOC_NR(ioctl_cmd));
			ret = ERR_IOCTL_FAILED;
		}
		close(fd);
	}
	return ret;
}

/* ============================================================================
 *  Function Name : get_hw_platform                                            *
 *  Description   : This is a helper function used to read platform name       *
 *                   from target                                               *
 *  Input	  : none                                                       * 
 *  Output	  : none                                                       *
 *  return value  : Platform name defined in enum platform_t                   *
 * ============================================================================*/
int32_t get_hw_platform(void)
{
	FILE *fp = NULL;
	char fbuf[256];
	static int platform_type = HW_PLATFORM_NONE;
	if (platform_type != HW_PLATFORM_NONE) {
		return platform_type;
	}
	fp = fopen("/proc/cpuinfo", "r");
	if (fp) {
		fgets(fbuf, 256, fp);
		if (strstr(fbuf, "GRX350"))
			platform_type = HW_PLATFORM_GRX350;
		else if (strstr(fbuf, "GRX500"))
			platform_type = HW_PLATFORM_GRX500;
		else if (strstr(fbuf, "xRX330"))
			platform_type = HW_PLATFORM_xRX330;
		else if (strstr(fbuf, "xRX300"))
			platform_type = HW_PLATFORM_xRX300;
		else if (strstr(fbuf, "xRX200"))
			platform_type = HW_PLATFORM_xRX220; 
		else {
		/*Check if this is an Atom x86 processor*/
			do {
				if (strstr(fbuf, "Atom")){
						platform_type = HW_PLATFORM_GRX750;
						break;
					}
			} while (fgets(fbuf, 256, fp) != NULL);
		}
	}
	else {
		LOGF_LOG_CRITICAL ("/proc/cpuinfo/ not found!\n");
		return ERR_FILE_NOT_FOUND;
	}
	fclose(fp);
	return platform_type;


}

/* =============================================================================
* Function Name : check_loaded_modules                         	               *
* Description   : this is a helper function which takes module name as input   *
*		  and finds if the module is already insmoded. returns success *
*		  if module is found or failure if module is not found	       *
* Input		: pointer to module name string                                *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t check_loaded_modules(IN const char *module_to_find)
{
	FILE *fp;
	int32_t ret = UGW_FAILURE;
	unsigned int x;
	char tmp[MAX_NAME_LEN] = { 0 };
	char *proc_module = { 0 };
	char buf[MAX_MODBUF_SIZE] = "\0";

	/* if module name is appended with .ko */
                /* strip it for further processing */

	if(strstr(module_to_find,".ko"))
	{
		for (x = 0; x < (strlen(module_to_find) - 3); x++)
			tmp[x] = module_to_find[x];
	}
	else {
		for (x = 0; x < (strlen(module_to_find)); x++)
			tmp[x] = module_to_find[x];
	}
	fp = fopen("/proc/modules", "r");
	if (fp == NULL) {
		LOGF_LOG_CRITICAL("open /proc/modules FAILED!\n");
		return ret;
	}
	memset(buf, 0, sizeof(char) * MAX_MODBUF_SIZE);

	 while (fgets(buf, MAX_MODBUF_SIZE, fp) != NULL) {
		proc_module = strtok(buf," ");
		if((proc_module != NULL) && (strncmp(proc_module, tmp, MAX_NAME_LEN) == 0))
		{
			LOGF_LOG_DEBUG("module  %s found!! \n", module_to_find);
			ret = UGW_SUCCESS;
			break;	
		}
		else {
			ret = UGW_FAILURE;
		}
			
	}
		
	fclose(fp);
	return ret;
}

/* =============================================================================
* Function Name : is_module_exists
* Description   : this is a helper function which takes module name as input   *
*                 and finds if the module exists. returns success              *
*                 if module exists or failure if module does not exists        *
* Input     : pointer to module name string                                    *
* OutPut    : None                                                             *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t is_module_exists(IN const char *sModToFind)
{
	int32_t nRet = UGW_FAILURE;
	char sModName[MAX_MODPATHNAME_SIZE] = { 0 };;
	glob_t xPath = { 0 };

	snprintf(sModName, MAX_MODPATHNAME_SIZE, "%s%s.ko", DEFAULT_MODULES_DIR, sModToFind);
	glob(sModName, 0, NULL, &xPath);
	if(xPath.gl_pathv != NULL) {
		LOGF_LOG_INFO("FAPI ETH-module %s exists!!loading module.. \n", sModToFind);
		globfree(&xPath);
		nRet = UGW_SUCCESS;
	} else {
		LOGF_LOG_ERROR("FAPI ETH-module %s not exist!!\n", sModToFind);
	}
	
	return nRet;
}

/* =============================================================================
* Function Name : fapi_sys_setBridgeAccelState
* Description   : API to set bridge learning to Enable / Disable               *
* Input     : operation - The desired operation (enable/disable)               *
* OutPut    : None                                                             *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t fapi_sys_setBridgeAccelState(IN char *operation)
{
	return fapicb.setBridgeState(operation);
}

#ifdef CONFIG_IPSEC_SUPPORT
int32_t fapi_sys_pp_crypto_support(void)
{
	int32_t ipsec_disable = 0;

	FILE *fd = fopen("/proc/bootcfg/ipsec_disable", "r");

	if (fd == NULL) {
		LOGF_LOG_CRITICAL("Failed to open /proc/bootcfg/ipsec_disable\n");
		return 0;
	}

	/* Get the ASCII value of the char */
	ipsec_disable = fgetc(fd);

	fclose(fd);

	/* 0 means that ipsec is supported. ASCII value of '0' is 48 */
	return (ipsec_disable == 48);
}
#endif

/* =============================================================================
* Function Name : fapi_sys_setWanPhyGpio                                           *
* Description   : API to set WAN PHY GPIO value                                *
* Input     : nVal - The desired calue to set                                   *
* OutPut    : None                                                             *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t fapi_sys_setWanPhyGpio(IN uint8_t nVal)
{
	return fapicb.setWanPhyGpio(nVal);
}
