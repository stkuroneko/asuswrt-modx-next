/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* header files */
#define _GNU_SOURCE
//#include <stdio.h>
//#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
//#include <ctype.h>
#include <dirent.h>
//#include <sys/stat.h>
#include <ulogging.h>
#include <ugw_error.h>
#include "fapi_sys_common.h"
#include "fapi_common.h"
#include "fapi_sys.h"
//#include "ltq_api_include.h"



/* =============================================================================
* Function Name : Processor_init                                        *
* Description   : Processor_init is responsible for loading             *
*                 processor stat driver modules            *
* Input         : None                                                         *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t Processor_init(void)
{
        int32_t nRet = UGW_SUCCESS;
        Modules_t xModule_cfg;
		MKNODcfg_t xMknod_Cfg;
        uint32_t unMajorNo = PROCESSORSTAT_EVENT_MAJOR;
        uint32_t unMinorNo = PROCESSORSTAT_EVENT_MINOR;
        uint32_t unDevNo = 0;

		memset(&xMknod_Cfg, 0x0, sizeof(xMknod_Cfg));

        xModule_cfg.uNum = (sizeof(ProcessorStatModules) / sizeof(*(ProcessorStatModules)));
        xModule_cfg.module = calloc(sizeof(char *), xModule_cfg.uNum);
        if(xModule_cfg.module == NULL)
        {
                LOGF_LOG_CRITICAL("Allocating memory failed during processor init!\n");
                nRet = UGW_FAILURE;
                goto end;
        }

		/*Kernel modules to load for processor  stats*/
        xModule_cfg.module = &ProcessorStatModules[0];
        nRet = fapi_sys_generic_load(&xModule_cfg);
        if(nRet != UGW_SUCCESS) {
			LOGF_LOG_CRITICAL("Processor module load failed!\n");
			goto end;
        }
        LOGF_LOG_INFO("insmod for processor moudles successful.\n");

        strncpy(xMknod_Cfg.DevName, PROCESSOREVENT_DEVICE, sizeof(xMknod_Cfg.DevName)-1);
        xMknod_Cfg.unMajorNo = unMajorNo;
        xMknod_Cfg.unMinorNo = unMinorNo;
        xMknod_Cfg.unDevNo = unDevNo;

		/*Create a special file name using mknod for PROCESSOREVENT_DEVICE*/
        nRet = fapi_sys_mknod(&xMknod_Cfg);
        if(nRet != UGW_SUCCESS)
        {
                LOGF_LOG_CRITICAL("make nod for processor moudles failed!\n");
                goto end;
        }
        LOGF_LOG_INFO("make nod processor moudles successful.\n");
end:
        if(xModule_cfg.module != NULL)
        {
                free(xModule_cfg.module);
        }

        return nRet;
}

/* =============================================================================
* Function Name : Processor_uninit                                      *
* Description   : Processor_uninit is responsible for unloading         *
*                 processor stat driver modules				            *
* Input         : None                                                         *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t Processor_uninit(void)
{
        int32_t nRet = UGW_SUCCESS;
        Modules_t xModule_cfg;

        xModule_cfg.uNum = (sizeof(ProcessorStatModules) / sizeof(*(ProcessorStatModules)));
        xModule_cfg.module = calloc(sizeof(char *), xModule_cfg.uNum);
        if(xModule_cfg.module == NULL)
        {
                LOGF_LOG_CRITICAL("Allocating memory failed!!\n");
                nRet = UGW_FAILURE;
                goto end;
        }

        xModule_cfg.module = &ProcessorStatModules[0];

		/*Kernel modules to unload for processor  stats*/
        nRet = fapi_sys_generic_unload(&xModule_cfg);
        if(nRet != UGW_SUCCESS) {
                LOGF_LOG_CRITICAL("Processor module unload failed!\n");
                goto end;
        }

end:
        if(xModule_cfg.module != NULL)
        {
			free(xModule_cfg.module);
        }

        return nRet;
}

/* ==========================================================================
* Function Name : stats_counter
* Description   : stats_counter is responsible for reading counters
*                 from system
* Input         : None
* OutPut        : None
* Returns       : UGW_SUCCESS/UGW_FAILURE
=============================================================================*/
int32_t stats_counter(IN ProcessorCounter *xProcessorInfo)
{
	int32_t nRet = UGW_SUCCESS, nFD = 0;
	ProcessorEvent *xEvent = NULL;

	xEvent = calloc(1, sizeof(ProcessorEvent));
	if(xEvent == NULL)
	{
		nRet = ENOMEM;
		LOGF_LOG_CRITICAL("Calloc failed for ProcessorEvent : %s\n", strerror(-nRet));
		goto returnHandler;
	}

	if((nFD = open(PROCESSOREVENT_DEVICE, O_RDWR)) < 0)
	{
		nRet = ENOENT;
		LOGF_LOG_CRITICAL("open PROCESSOREVENT_DEVICE FD failed Error : %s\n", strerror(-nRet));
		goto returnHandler;
	}

	memset(xEvent, 0x0, sizeof(ProcessorEvent));
	xEvent->flag = xProcessorInfo->nFlagID;

	/*Get platform type to pass kernel module*/
	xEvent->nPlatform = get_hw_platform();

	nRet = ioctl(nFD, PROCESSOR_EVENT, xEvent);
	if(nRet !=UGW_SUCCESS)
	{
		LOGF_LOG_ERROR("IOCTL Call Counter for Processor stats failed: %s\n", strerror(-nRet));
		goto returnHandler;
	}

	/* assign the pecostat INST and ICache event values for all Processor */
	if(xProcessorInfo->nProcessorID == 1)
	{
		xProcessorInfo->nIntructions = xEvent->uPicEvnt1;
		xProcessorInfo->nICacheMissStallCycles = xEvent->uPicEvnt2;
	}
	else if (xProcessorInfo->nProcessorID == 2)
	{
		xProcessorInfo->nIntructions = xEvent->uPicEvnt3;
		xProcessorInfo->nICacheMissStallCycles = xEvent->uPicEvnt4;
	}
	else if(xProcessorInfo->nProcessorID == 3)
	{
		xProcessorInfo->nIntructions = xEvent->uPicEvnt5;
		xProcessorInfo->nICacheMissStallCycles = xEvent->uPicEvnt6;
	}

	/* assign the pecostat DCACHE and ITLB event values for all Processor */
	if(xProcessorInfo->nProcessorID == 1)
	{
		xProcessorInfo->nDCacheMissStallCycles = xEvent->uPicEvnt7;
		xProcessorInfo->nITLBMissCycles = xEvent->uPicEvnt8;
	}
	else if(xProcessorInfo->nProcessorID == 2)
	{
		xProcessorInfo->nDCacheMissStallCycles = xEvent->uPicEvnt9;
		xProcessorInfo->nITLBMissCycles = xEvent->uPicEvnt10;
	}
	else if(xProcessorInfo->nProcessorID == 3)
	{
		xProcessorInfo->nDCacheMissStallCycles = xEvent->uPicEvnt11;
		xProcessorInfo->nITLBMissCycles = xEvent->uPicEvnt12;
	}

	/* assign the pecostat DTLB anc CPUCycle event values for all Processor */
	if(xProcessorInfo->nProcessorID == 1)
	{
		xProcessorInfo->nDTLBMissCycles = xEvent->uPicEvnt13;
		xProcessorInfo->nCycles = xEvent->uPicEvnt14;
	}
	else if(xProcessorInfo->nProcessorID == 2)
	{
		xProcessorInfo->nDTLBMissCycles = xEvent->uPicEvnt15;
		xProcessorInfo->nCycles = xEvent->uPicEvnt16;
	}
	else if(xProcessorInfo->nProcessorID == 3)
	{
		xProcessorInfo->nDTLBMissCycles = xEvent->uPicEvnt17;
		xProcessorInfo->nCycles= xEvent->uPicEvnt18;
	}

returnHandler:
	if(nFD >= 0)
		close(nFD);

	free(xEvent);
	return nRet;
}


/* =============================================================================
* Function Name : PPAInit					       *
* Description   : This is a callback function which performs PPA initialization*
*		  by configuring default values to PPA parameters              *
* Input		: Default configurations filled in PPAInit_cfg_t struct        *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t PPAInit(PPAInit_cfg_t * ppaInit_Cfg)
{
	PPA_CMD_INIT_INFO ppa_data;
	PPA_CMD_MAX_ENTRY_INFO max_entries;
	PPA_CMD_ENABLE_INFO enable_info;
	PPA_VLAN_RANGE vlan_range;

	int32_t ret = UGW_SUCCESS;
	memset(&ppa_data, 0, sizeof(PPA_CMD_INIT_INFO));

	// Default PPA Settings
	ppa_data.lan_rx_checks.f_ip_verify = 1;
	ppa_data.lan_rx_checks.f_tcp_udp_verify = 1;
	ppa_data.lan_rx_checks.f_tcp_udp_err_drop = 0;
	ppa_data.lan_rx_checks.f_drop_on_no_hit = 0;
	ppa_data.lan_rx_checks.f_mc_drop_on_no_hit = 0;

	ppa_data.wan_rx_checks.f_ip_verify = 1;
	ppa_data.wan_rx_checks.f_tcp_udp_verify = 1;
	ppa_data.wan_rx_checks.f_tcp_udp_err_drop = 0;
	ppa_data.wan_rx_checks.f_drop_on_no_hit = 0;
	ppa_data.wan_rx_checks.f_mc_drop_on_no_hit = 0;

	ppa_data.num_lanifs = 0;
	memset(ppa_data.p_lanifs, 0, sizeof(ppa_data.p_lanifs));
	ppa_data.num_wanifs = 0;
	memset(ppa_data.p_wanifs, 0, sizeof(ppa_data.p_wanifs));

	/*number of packets passing through slow path before acceleration */

	ppa_data.add_requires_min_hits = ppaInit_Cfg->Min_Hits;

#if defined(CONFIG_LTQ_PPA_HANDLE_CONNTRACK_SESSIONS)
	ppa_data.add_requires_lan_collisions = 0;
	ppa_data.add_requires_wan_collisions = 0;
#endif

	ret = PPA_IOCTL(PPA_CMD_GET_MAX_ENTRY, &max_entries);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppa ioctl - Get MAX entry failed \n");
		return ret;
	}
	if (ppaInit_Cfg->nMax_LANNumSessions == -1)
		ppa_data.max_lan_source_entries = max_entries.entries.max_lan_entries;
	else
		ppa_data.max_lan_source_entries = ppaInit_Cfg->nMax_LANNumSessions;

	if (ppaInit_Cfg->nMax_WANNumSessions == -1)
		ppa_data.max_wan_source_entries = max_entries.entries.max_wan_entries;
	else
		ppa_data.max_wan_source_entries = ppaInit_Cfg->nMax_WANNumSessions;
	if (ppaInit_Cfg->nMax_McastNumSessions == -1)
		ppa_data.max_mc_entries = max_entries.entries.max_mc_entries;
	else
		ppa_data.max_mc_entries = ppaInit_Cfg->nMax_McastNumSessions;

	if (ppaInit_Cfg->nMax_BrNumSessions == -1)
		ppa_data.max_bridging_entries = max_entries.entries.max_bridging_entries;
	else
		ppa_data.max_bridging_entries = ppaInit_Cfg->nMax_BrNumSessions;

	if (ppaInit_Cfg->Def_MTUSize == -1)
		ppa_data.mtu = DEFAULT_MTU_SIZE;
	else
		ppa_data.mtu = ppaInit_Cfg->Def_MTUSize;

	if (ppaInit_Cfg->bMibMode == -1)
		ppa_data.mib_mode = MIB_BYTE_MODE;	//byte mode
	else
		ppa_data.mib_mode = ppaInit_Cfg->bMibMode;

	ret = PPA_IOCTL(PPA_CMD_INIT, &ppa_data);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppa ioctl - INIT failed..\n");
		return ret;
	} else {
		LOGF_LOG_DEBUG("ppa ioctl - INIT success..\n");
	}

	memset(&enable_info, 0, sizeof(enable_info));
	enable_info.lan_rx_ppa_enable = 1;
	enable_info.wan_rx_ppa_enable = 1;

	ret = PPA_IOCTL(PPA_CMD_ENABLE, &enable_info);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppacmd enable lan/wan failed\n");
		return ret;
	}

	memset(&vlan_range, 0, sizeof(vlan_range));
	vlan_range.start_vlan_range = 3;
	vlan_range.end_vlan_range = 4095;
	ret = PPA_IOCTL(PPA_CMD_WAN_MII0_VLAN_RANGE_ADD, &vlan_range);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppacmd add vlan range failed\n");
		return ret;
	}

	return ret;
}

/* =============================================================================
* Function Name : PPAUnInit					       *
* Description   : This is a callback function which performs PPA 
		  Uninitialization                                             *
* Input		: void							       *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t PPAUnInit(void)
{
	int ret = UGW_SUCCESS;

	PPA_CMD_IFINFO ppa_data;
	memset(&ppa_data, 0, sizeof(PPA_CMD_IFINFO));

	ret = PPA_IOCTL(PPA_CMD_EXIT, &ppa_data);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppa ioclt - EXIT failed .\n");
	} else {
		LOGF_LOG_DEBUG("ppa ioctl - EXIT success .\n");
	}

	return ret;

}

/* =============================================================================
* Function Name : SysSet	                         		       *
* Description   : This function configures syscfg struct with default params   *
* InPut		: sys_cfg_t struct 					       *
* OutPut	: updates /tmp/syscfg file				       *                                                         
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t SysSet(IN sys_cfg_t * sys_cfg)
{
	int ret = UGW_SUCCESS;
	FILE *fp = NULL;
	char buf[MAX_SYSBUF_SIZE];

	memset(buf, 0, sizeof(char) * MAX_SYSBUF_SIZE);

	fp = fopen(SYSTEM_CFG_FILE, "w+");
	if (fp == NULL) {
		LOGF_LOG_DEBUG("fapi_sys_set open file %s failed!!\n", SYSTEM_CFG_FILE);
		ret = ERR_FILE_NOT_FOUND;
	} else {
		sprintf(buf, "primarywan=\%d\n", sys_cfg->priWAN);
		fprintf(fp, "%s", buf);
		sprintf(buf, "secondarywan=\%d\n", sys_cfg->secWAN);
		fprintf(fp, "%s", buf);
		sprintf(buf, "secActivewan=\%d\n", sys_cfg->secActive);
		fprintf(fp, "%s", buf);
		sprintf(buf, "qosEnable=\%d\n", sys_cfg->qosEna);
		fprintf(fp, "%s", buf);
		sprintf(buf, "ipv6Ena=\%d\n", sys_cfg->ipv6Ena);
		fprintf(fp, "%s", buf);
		sprintf(buf, "wanlteEna=\%d\n", sys_cfg->wanlteEna);
		fprintf(fp, "%s", buf);
		sprintf(buf, "wanphy=\%d\n", sys_cfg->wanphy);
		fprintf(fp, "%s", buf);

		fclose(fp);
		ret = UGW_SUCCESS;
	}
	return ret;
}

static int sys_readFile(FILE * filePointer, char *pcLineRead)
{
	char cEndOfFile;
	int ret = 1;
	size_t nBytes = 80;

	cEndOfFile = getc(filePointer);
	fseek(filePointer, -1, 1);
	getline(&pcLineRead, &nBytes, filePointer);
	while(pcLineRead[0] == '#' || (strcmp(pcLineRead, "\n") == 0)) {
		cEndOfFile = getc(filePointer);
		if(cEndOfFile == EOF) {
			ret = 0;
			goto end;
		}
		fseek(filePointer, -1, 1);
		getline(&pcLineRead, &nBytes, filePointer);
	}
end:
	return ret;
}

/* =============================================================================
* Function Name : SysGet	                         		       *
* Description   : This function reads /tmp/syscfg and updates sys_cfg_t struct *
* InPut		: sys_cfg_t struct 					       *
* OutPut	: updates /tmp/syscfg file				       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
==============================================================================*/
int32_t SysGet(IN sys_cfg_t * sysCfg_g)
{
	int nRet = UGW_SUCCESS;

	FILE *filePointer = NULL;
	char *pcToken = NULL;
	char *pcLineRead = NULL;
	const char sDelimColon[2] = "=";
	size_t nBytes = 80;

	filePointer = fopen(SYSTEM_CFG_FILE, "r");
	if(filePointer == NULL) {
		LOGF_LOG_CRITICAL("File open error for %s!!!\n", SYSTEM_CFG_FILE);
		nRet = UGW_FAILURE;
		goto end;
	}

	pcLineRead = (char *) malloc(sizeof(char) * (nBytes + 1));
	if(pcLineRead == NULL) {
		LOGF_LOG_CRITICAL("Malloc failed for buffer to read the line\n");
		nRet = UGW_FAILURE;
		goto end;
	}
	memset(pcLineRead, 0, nBytes + 1);

	while(sys_readFile(filePointer, pcLineRead)) {
		pcToken = strtok(pcLineRead, sDelimColon);
		if(pcToken != NULL) {
			if(strcmp(pcToken, "primarywan") == 0) {
				sysCfg_g->priWAN = atoi(strtok(NULL, sDelimColon));
			} else if (strcmp(pcToken, "secondarywan") == 0) {
				sysCfg_g->secWAN = atoi(strtok(NULL, sDelimColon));
			} else if (strcmp(pcToken, "secActivewan") == 0) {
				sysCfg_g->secActive = atoi(strtok(NULL, sDelimColon));
			} else if (strcmp(pcToken, "qosEnable") == 0) {
				sysCfg_g->qosEna = atoi(strtok(NULL, sDelimColon));
			} else if (strcmp(pcToken, "ipv6Ena") == 0) {
				sysCfg_g->ipv6Ena = atoi(strtok(NULL, sDelimColon));
			} else if (strcmp(pcToken, "wanlteEna") == 0) {
				sysCfg_g->wanlteEna = atoi(strtok(NULL, sDelimColon));
			} else if (strcmp(pcToken, "wanphy") == 0) {
				sysCfg_g->wanphy = atoi(strtok(NULL, sDelimColon));
			}                
		}
	}
end:
	if(pcLineRead != NULL)
		free(pcLineRead);

	if(filePointer != NULL)
		fclose(filePointer);

	return nRet;
}


/* =============================================================================
* Function Name : PPAInftAdd	                         	       *
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
int32_t PPAIntfAdd(IN ifcfg_t *ifCfg)
{
	PPA_CMD_IFINFO ppa_data;
	int ret = UGW_SUCCESS;

	memset(&ppa_data, 0, sizeof(PPA_CMD_IFINFO));
	strcpy(ppa_data.ifname, ifCfg->ifName);
	strcpy(ppa_data.ifname_lower, ifCfg->baseifName);

	if (ifCfg->wanIf_flag == 0) {
		/* adding interface to PPA LAN */
		ppa_data.if_flags = PPA_F_LAN_IF;

		ret = PPA_IOCTL(PPA_CMD_ADD_LAN_IF, &ppa_data);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("ppa ioctl - add lanif failed .\n");
		} else {
			LOGF_LOG_INFO("ppa ioctl - add lanif %s success \n", ifCfg->ifName);
		}

	}
	if (ifCfg->wanIf_flag == 1) {
		/* adding interface to PPA WAN */
		ppa_data.force_wanitf_flag = ifCfg->wanIf_flag;
		ret = PPA_IOCTL(PPA_CMD_ADD_WAN_IF, &ppa_data);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("ppa ioctl - add Wanif failed .\n");
		} else {
			LOGF_LOG_INFO("ppa ioctl - add wanif %s  success \n", ifCfg->ifName);
		}

	}

	return ret;
}

/* =============================================================================
* Function Name : PPAIntfDel	                         	       *
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
int32_t PPAIntfDel(IN ifcfg_t * ifCfg)
{
	PPA_CMD_IFINFO ppa_data;
	int ret = UGW_SUCCESS;

	memset(&ppa_data, 0, sizeof(PPA_CMD_IFINFO));
	strcpy(ppa_data.ifname, ifCfg->ifName);
	if (ifCfg->wanIf_flag == 0) {
		/* removing interface from PPA LAN */
		ppa_data.if_flags = PPA_F_LAN_IF;

		ret = PPA_IOCTL(PPA_CMD_DEL_LAN_IF, &ppa_data);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("ppa ioctl - del lanif from ppa failed .\n");
		} else {
			LOGF_LOG_INFO("ppa ioctl - del lanif %s from ppa Success .\n", ifCfg->ifName);
		}
	}
	if (ifCfg->wanIf_flag == 1) {
		/* removing interface from PPA WAN */
		ret = PPA_IOCTL(PPA_CMD_DEL_WAN_IF, &ppa_data);
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("ppa ioctl - del wanif from ppa failed .\n");
		} else {
			LOGF_LOG_INFO("ppa ioctl - del wanif %s from ppa Success .\n", ifCfg->ifName);
		}

	}

	return ret;
}



/* =============================================================================
* Function Name : PPAEnHook                         		       *
* Description   : This function enables LAN and WAN acceleration 	       *
* Input		: PPA_CMD_ENABLE_INFO struct to selectively ENABLE/DISABLE LAN *
*		  or WAN acceleration					       *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t PPAEnHook(IN PPA_CMD_ENABLE_INFO * enable_info)
{
	int ret = UGW_SUCCESS;
	ret = PPA_IOCTL(PPA_CMD_ENABLE, enable_info);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("ppacmd control command failed!\n");
	} else {
		LOGF_LOG_DEBUG("ppacmd control command SUCCESS!\n");
		ret = UGW_SUCCESS;
	}
	return ret;
}
