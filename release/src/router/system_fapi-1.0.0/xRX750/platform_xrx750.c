/******************************************************************************
 * 	return nRet;

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
#include "platform_xrx750.h"
#include "xRX750_callback.h"
#include "ltq_api_include.h"
#include "scapi_interfaces_defines.h"

#define FILENAME "/tmp/configuration.txt"
/*General Definitions*/
#define HVP_BOARD_ID	"BoardID=0xE6"
#define CGP_BOARD_ID	"BoardID=0xE9"
#define GRX750_CPU_MHZ	2000
#define VPID_FILE_PATH  "/proc/net/pp/VPID/busy"
#define STACK_FILE_PATH "/proc/net/dev"

#define EASY750_BOARD_ID        "BoardID=0xE5"

/*GPIO decleration*/
#define WAN_GPIO_VAL	"223"

/*Static function declaration*/
static void xRX750_run_link(void);
static int32_t xRX750_load_modules(const char *modules[][2]);
int32_t check_sync_status(void);
static char *xRX750_check_boardID(void);
static int32_t xRX750_wan_reset(void);
static int32_t write_to_file(char *fileName, char *buffer);
extern int FAPI_LEDSetAttribute(IN LEDType led, IN TriggerType trigger, IN void *LedAttr);
static int HVP_setStateError(void);
/* struct defincations */
struct InterfaceData intf_arr[] = {
	{
	 .interfaceId = 5,
	 .vpidName = "RGMII",
	 .interfaceName = "eth1",
	 .GetCounters = xRX750_VpidAndStackBoth,
	 },
	{
	 .interfaceId = 4,
	 .vpidName = "SGMII1",
	 .interfaceName = "eth0_1",
	 .GetCounters = xRX750_VpidAndStackBoth,
	 },
	{
	 .interfaceId = 1,
	 .interfaceName = "ptm0",
	 .GetCounters = xRX750_ReadNetDevFile,
	 },
	{
	 .interfaceId = 2,
	 .interfaceName = "gmac5",
	 .GetCounters = xRX750_ReadNetDevFile,
	 },
	{
	 .interfaceId = 3,
	 .vpidName = "SGMII0",
	 .interfaceName = "nsgmii0",
	 .GetCounters = xRX750_VpidAndStackBoth,
	 },
	{
	 .interfaceId = 6,
	 //.interfaceName = "",
	 .GetCounters = xRX750_cgiGetCoremark,
	 }
};

/* =============================================================================
 * Function Name : write_to_file                                                *
 * Description   : write_to_file is responsible for writing data to file 	*
 * Input         : file name and buffer to be written			        *
 * OutPut        : None                                                         *
 * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 ============================================================================== */
static int32_t write_to_file(char *fileName, char *buffer)
{
	FILE *fp;

	fp = fopen(fileName, "w");
	if (!fp) {
		LOGF_LOG_ERROR("failed to open proc file: %s\n", fileName);
		return UGW_FAILURE;
	}

	fprintf(fp, "%s", buffer);
	LOGF_LOG_CRITICAL("file %s and command %s\n", fileName, buffer);
	fclose(fp);
	return UGW_SUCCESS;
}

/* =============================================================================
 * Function Name : xRX750_wanSWO                                               *
 * Description   : xRX750_wanSWO is responsible for handling unloading and      *
 *                 and re-initialization of wan and ppa modules during wan      *
                    change over
 * Input         : old wanmode and new wanmode of type WAN_TYPE_t               *
 * OutPut        : None                                                         *
 * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 ============================================================================== */
int32_t XRX750_wanSWO(sys_cfg_t * sysCfg)
{
	int32_t ret = UGW_SUCCESS;
	FILE *fp;
	char fbuf[MAX_FBUF_SIZE] = "\0";
	char cbuf1[MAX_FBUF_SIZE] = "\0", cbuf2[MAX_FBUF_SIZE] = "\0";
	char bondingStatus[DEVICE_STATUS_SIZE] = "\0", xtuStatus[DEVICE_STATUS_SIZE] = "\0", tcLayerStatus[DEVICE_STATUS_SIZE] = "\0";
	int lineNumber = 0;

	ret = xRX750_module_unload(sysCfg->secWAN);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_ERROR("module unload failed for wan : %d\n", sysCfg->secWAN);
		return ret;
	}

	ret = xRX750_module_load(sysCfg->priWAN);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_ERROR("module load failed for wan : %d\n", sysCfg->priWAN);
		return ret;
	}
#define	DSL_LINE_STATUS_FILE	"/tmp/dsl_line_conf"	// This file is created in xdslrc.sh only for GRX750 platform

	fp = fopen(DSL_LINE_STATUS_FILE, "r");
	if (!fp)
		return ret;

	if (fgets(fbuf, sizeof(fbuf), fp) == NULL) {
		LOGF_LOG_ERROR("Failed to read string from file!\n");
		fclose(fp);
		return ret;
	}

	sscanf(fbuf, "%s %s %s %d", xtuStatus, tcLayerStatus, bondingStatus, &lineNumber);
	LOGF_LOG_CRITICAL("Bonding : %s, xtu: %s, tc : %s and line number : %d", bondingStatus, xtuStatus, tcLayerStatus, lineNumber);
	fclose(fp);

	if ((sysCfg->priWAN == DSL_PTM) && !strncmp(xtuStatus, "VDSL", strlen("VDSL"))) {
		if (!strncmp(bondingStatus, "ACTIVE", strlen("ACTIVE"))) {
			sprintf(cbuf1, "DSL_LINE_NUMBER %d DSL_BONDING_STATUS active", lineNumber);
			sprintf(cbuf2, "bdmdswitch L1");
		} else {
			sprintf(cbuf1, "DSL_LINE_NUMBER %d DSL_BONDING_STATUS inactive", lineNumber);
			sprintf(cbuf2, "bdmdswitch L2");
		}
		write_to_file("/proc/dsl_tc/status", cbuf1);
		write_to_file("/proc/vrx320/tfwdbg", cbuf2);
	} else if ((sysCfg->priWAN == DSL_ATM) && !strncmp(xtuStatus, "ADSL", strlen("ADSL"))) {
		sprintf(cbuf2, "bdmdswitch L2");
		write_to_file("/proc/vrx320/tfwdbg", cbuf2);
	}

	unlink(DSL_LINE_STATUS_FILE);
	return ret;
}

/* =============================================================================
* Function Name : xRX750_module_load		 	         	       *
* Description   :
* Input		: new wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX750_module_load(WAN_TYPE_t next_tc_mode)
{
	int32_t ret = UGW_SUCCESS;
	uint32_t i = 0;

	LOGF_LOG_DEBUG("new tc mode = %d\n", next_tc_mode);

	if ((next_tc_mode == DSL_PTM)) {

		/*load E1 driver */
		for (i = 0; i < (sizeof(xRX750PTMTCModules) / sizeof(xRX750PTMTCModules[0])); i++) {
			ret = scapi_insmod(xRX750PTMTCModules[i], NULL);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX750PTMTCModules[i]);
			}
		}
	} else if (next_tc_mode == DSL_ATM) {

		/*load A1 driver */
		for (i = 0; i < (sizeof(xRX750ATMTCModules) / sizeof(xRX750ATMTCModules[0])); i++) {
			ret = scapi_insmod(xRX750ATMTCModules[i], NULL);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s insmod failure\n", xRX750ATMTCModules[i]);
			}
		}
	}
	// usleep(500);
	return ret;
}

/* =============================================================================
* Function Name : xRX750_module_unload					       *
* Description   : 
* Input		: old wan mode
* OutPut	: 
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t xRX750_module_unload(WAN_TYPE_t next_tc_mode)
{
	int32_t ret = UGW_SUCCESS;
	char module[MODULE_NAME_SIZE] = { 0 };
	int32_t i = 0;

	LOGF_LOG_DEBUG("old tc mode = %d\n", next_tc_mode);

	if ((next_tc_mode == DSL_PTM)) {

		/*load E1 driver */
		for (i = (sizeof(xRX750PTMTCModules) / sizeof(xRX750PTMTCModules[0])) - 1; i >= 0; i--) {
			strcpy(module, xRX750PTMTCModules[i]);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s rmmod failure\n", xRX750PTMTCModules[i]);
			}
		}
	} else if (next_tc_mode == DSL_ATM) {

		/*load A1 driver */
		for (i = (sizeof(xRX750ATMTCModules) / sizeof(xRX750ATMTCModules[0])) - 1; i >= 0; i--) {
			strcpy(module, xRX750ATMTCModules[i]);
			ret = scapi_rmmod(module, 0);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s rmmod failure\n", xRX750ATMTCModules[i]);
			}
		}
	}
	return ret;
}

/* =============================================================================
* Function Name : check_sync_status                                         *
* Description   : this function checks NP cpu booting status                *
*         and poll until critical boot is finished. returns success         *
    *         if boot was done                                              *
* Input     : None                                                          *
* OutPut    : None                                                          *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t check_sync_status(void)
{
	FILE *fp;
	int attempts = 0;
	char fbuf[MAX_DATA_LEN] = "\0";

	fp = fopen("/sys/devices/platform/handshake/status", "r");
	if (fp == NULL) {
		LOGF_LOG_CRITICAL("/sys/devices/platform/handshake/status not found!\n");
		return ERR_FILE_NOT_FOUND;
	}
	do {
		fgets(fbuf, MAX_DATA_LEN, fp);
		if (strstr(fbuf, "0") != NULL)
			break;
		usleep(100);
		attempts++;
	} while (attempts < 20);

	if (attempts >= 20) {
		LOGF_LOG_CRITICAL("CPU sync failed!\n");
		fclose(fp);
		return ERR_INVALID_PARAMETER_REQUEST;
	}

	LOGF_LOG_DEBUG("CPU sync completed successfully\n");
	fclose(fp);
	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_check_boardID                                       *
* Description   : This function checks and set current board type              *
* Input     : None                                                             *
* OutPut    : None                                                             *
* Returns   : Board type string                                                *
============================================================================== */

static char *xRX750_check_boardID(void)
{
	FILE *fp = NULL;
	char fbuf[1024] = { 0 };
	static char *board_type = NULL;

	if (board_type != NULL) {
		LOGF_LOG_DEBUG("board ID already exist = %s\n", board_type);
		return board_type;
	}

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL) {
		LOGF_LOG_ERROR("/proc/cmdline not found!!\n");
		goto run_default;
	}

	if (fgets(fbuf, sizeof(fbuf), fp) == NULL) {
		LOGF_LOG_ERROR("Failed to read string from file!\n");
		goto run_default;
	}

	if (strstr(fbuf, HVP_BOARD_ID) != NULL) {
		LOGF_LOG_DEBUG("Haven Park board detected\n");
		board_type = HVP_BOARD_ID;
		fclose(fp);
		return board_type;
	}

 run_default:
	LOGF_LOG_DEBUG("Set board type to CGP (default)\n");
	board_type = CGP_BOARD_ID;
	fclose(fp);
	return board_type;
}

/* =============================================================================
* Function Name : xRX750_wan_reset                                             *
* Description   : This function reset WAN HW line in Haven Park                *
* Input     : None                                                             *
* OutPut    : None                                                             *
* Returns   : SUCCESS/FAILURE                                                  *
============================================================================== */

static int32_t xRX750_wan_reset(void)
{
	FILE *fp = NULL;
	char str_gpio[2048];

	if (strstr(xRX750_check_boardID(), HVP_BOARD_ID) == NULL) {
		LOGF_LOG_DEBUG("Board type is differ then HVP - no WAN reset require");
		return UGW_SUCCESS;
	}

	/*Export WAN GPIO for read/write */
	fp = fopen("/sys/class/gpio/export", "w");
	if (fp == NULL) {
		LOGF_LOG_ERROR("/sys/class/gpio/export not found!!\n");
		return UGW_FAILURE;
	}
	fprintf(fp, WAN_GPIO_VAL);
	fclose(fp);

	/*Toggle WAN reset for 150[msec] */
	sprintf(str_gpio, "/sys/class/gpio/gpio%s/value", WAN_GPIO_VAL);
	fp = fopen(str_gpio, "w");
	if (fp == NULL) {
		LOGF_LOG_ERROR("%s not found!!\n", str_gpio);
		return UGW_FAILURE;
	}

	fprintf(fp, "0");
	fflush(fp);
	usleep(200000);
	fprintf(fp, "1");
	fclose(fp);

	LOGF_LOG_DEBUG("Finished WAN reset process");

	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_run_link                                              *
* Description   : This function checks current board type and run link         *
*                 script accordingly                                           *
* Input     : None                                                             *
* OutPut    : None                                                             *
* Returns   : None                                                             *
============================================================================== */

static void xRX750_run_link(void)
{

#ifdef ENABLE_LAN_PORT_SEPARATION
	setenv("ENABLE_LAN_PORT_SEPARATION", "1", 1);
#endif
	if (strstr(xRX750_check_boardID(), HVP_BOARD_ID) != NULL) {
		LOGF_LOG_DEBUG("Haven Park board detected, run link script\n");
		system("/opt/lantiq/etc/grx750_initscripts/link_hvp start");
	} else {
		LOGF_LOG_DEBUG("Run Cougar Park link script (default)\n");
		system("/opt/lantiq/etc/grx750_initscripts/link_cgp start");
	}
#ifdef ENABLE_LAN_PORT_SEPARATION
	unsetenv("ENABLE_LAN_PORT_SEPARATION");
#endif

	return;
}

static int32_t xRX750_load_modules(const char *modules[][2])
{
	int32_t wanModIndx = 0;
	int ret = UGW_SUCCESS;

	while (modules[wanModIndx][0] != NULL) {
#ifdef CONFIG_IPSEC_SUPPORT
		/* Only load pp_crypto_drv.ko on supported IPSEC HW */
		if (!strcmp(modules[wanModIndx][0], "pp_crypto_drv.ko") && !fapi_sys_pp_crypto_support()) {
			wanModIndx++;
			continue;
		}
#endif
		/* Check if the module is already loaded */
		if ((check_loaded_modules(modules[wanModIndx][0]) != UGW_SUCCESS)) {
			LOGF_LOG_INFO("......Loading %s\n", modules[wanModIndx][0]);
			ret = scapi_insmod(modules[wanModIndx][0], modules[wanModIndx][1]);
			if (ret != UGW_SUCCESS) {
				LOGF_LOG_CRITICAL("module %s insmod failure\n", modules[wanModIndx][0]);
			} else {
				LOGF_LOG_DEBUG("insmod of %s Successful!\n", modules[wanModIndx][0]);
			}
		} else {
			LOGF_LOG_DEBUG("Module %s already loaded! no need to insmod.\n", modules[wanModIndx][0]);
			ret = UGW_SUCCESS;
		}
		wanModIndx++;
	}

	return ret;
}

/* =============================================================================
* Function Name : xRX750_module_init                                           *
* Description   : xRX750_module_init is responsible for loading wan and	       *
*		  and common driver modules for xRX750 platform 	       *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX750_module_init(void)
{
	sys_cfg_t sys_cfg;
	PPAInit_cfg_t PPA_Cfg;
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	char sCmd[MAX_DATA_LEN];
	char *pcOrigArr[] = {
		[0] = "eth0_1",
		[1] = "eth0_2",
		[2] = "eth0_3",
		[3] = "eth0_4",
		[4] = "eth1",
		[5] = "nrgmii3",
	};
	char pcTmpArr[6][MAX_DATA_LEN];

	int32_t ret = UGW_SUCCESS, nCount = 0, nIter = 0, nMatchFound = 0;

	memset(&sys_cfg, 0, sizeof(sys_cfg_t));
	memset(&PPA_Cfg, 0, sizeof(PPA_Cfg));

	ret = check_sync_status();
	if (ret)
		return ret;

	if (xRX750_wan_reset() != UGW_SUCCESS)
		return UGW_FAILURE;

	LOGF_LOG_DEBUG("Pre init Modules Initialisation..\n");
	xRX750_load_modules(pumaPreInitModules);

	/* download packet processor firmware */
	system("/usr/sbin/pp_fw_download");

	LOGF_LOG_DEBUG("Post init Modules Initialisation..\n");
	xRX750_load_modules(pumaPostInitModules);

	LOGF_LOG_INFO("Linking Interfaces..");
	xRX750_run_link();

	PPA_Cfg.Min_Hits = PPA_MIN_HITS;
	ret = fapicb.ppa_init(&PPA_Cfg);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI PPA init failed!! Initializing through cmd\n");
		ret = system("ppacmd init");
		if (ret != UGW_SUCCESS) {
			LOGF_LOG_DEBUG("PPA Initialization failed!!!\n");
		}
	}

	ret = scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES);
	if (ret != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if (((!strcmp(pxTmpIface->cEnable, "true"))) && ((!strcmp(pxTmpIface->cMode, "ETH")))) {
			if (strcmp(pxTmpIface->cIfName, pcOrigArr[nCount]) != 0) {
				/*interface doesnt match. */
				/*Compare for match/conflicts in orig in higher indices */

				/*Match only with higher indices */
				for (nIter = nCount + 1; nIter < 6; nIter++) {
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
* Function Name : xRX750_module_uninit                            	       *
* Description   : this function is responsible for unloading wan and           *
*		  and common driver modules.                                   *
* Input		: None                                                         *
* OutPut	: None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX750_module_uninit(void)
{
	int ret = UGW_SUCCESS;

	LOGF_LOG_DEBUG("called\n");

	return ret;
}

/* =============================================================================
* Function Name : XRX750_InftAdd	                         	       *
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
int32_t xRX750_PPAIntfAdd(IN ifcfg_t * ifCfg)
{
	PPA_CMD_IFINFO ppa_data;
	int ret = UGW_SUCCESS;

	memset(&ppa_data, 0, sizeof(PPA_CMD_IFINFO));
	strncpy(ppa_data.ifname, ifCfg->ifName, PPA_IF_NAME_SIZE);

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

	strncpy(ppa_data.ifname_lower, ifCfg->baseifName, PPA_IF_NAME_SIZE);
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
* Function Name : xRX750_PortIdGet	                         	       *
* Description   : fapi to find switch port id corresponding to network         *
*                 interface                                                    *
* InPut		: interface name 	         			       *
* OutPut	: none                   				       *
* Returns       : Port Id or UGW_FAILURE                                       *
==============================================================================*/
int32_t xRX750_PortIdGet(IN char *ifname)
{
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;
	int32_t nRet = UGW_FAILURE;
	int32_t nPortId = 0;
	/*PPA_CMD_PORTID_INFO portid;
	   int32_t ret = UGW_SUCCESS;
	   memset(&portid, 0, sizeof(portid));
	   strncpy(portid.ifname, ifname, sizeof(portid.ifname));
	   ret = PPA_IOCTL(PPA_CMD_GET_PORTID, &portid);
	   if (ret != UGW_SUCCESS) {
	   LOGF_LOG_DEBUG("ppacmd get portid failed\n");
	   return ret;
	   }
	   LOGF_LOG_DEBUG("Interface = %s; PortId=%d\n", portid.ifname, (int32_t)portid.portid);
	   return portid.portid; */

	if (scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES) != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if (strcmp(pxTmpIface->cIfName, ifname) == 0) {
			nPortId = atoi(pxTmpIface->cPort);
			nRet = UGW_SUCCESS;
			break;
		}
	}
 end:
	scapi_deleteInterfaceList(&pxIfaceList);
	LOGF_LOG_DEBUG("Interface = %s; PortId=%d\n", ifname, (int32_t) nPortId);
	if (nRet == UGW_SUCCESS)
		return nPortId;
	return nRet;
}

/* =============================================================================
* Function Name : xRX750_stats_counter                                         *
* Description   : xRX750_stats_counter is responsible for getting CPU cycles   *
* Input         : xProcessorInfo                                               *
* OutPut        : xProcessorInfo                                               *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t xRX750_stats_counter(ProcessorCounter * xProcessorInfo)
{
	FILE *fd = NULL;
	uint64_t readB = 0;
	char line[256] = { 0 };
	char findPtr[25] = { 0 };
	if (xProcessorInfo->nProcessorID == 1) {
		fd = popen("chrt -r 1 perf stat -e cycles -C 0 sleep 1 2>&1 ", "r");
	} else if (xProcessorInfo->nProcessorID == 2) {
		fd = popen("chrt -r 1 perf stat -e cycles -C 1 sleep 1 2>&1", "r");
	}
	if (!fd) {
		LOGF_LOG_DEBUG("Can't Execute the command\n");
		return UGW_FAILURE;
	}
	LOGF_LOG_DEBUG("Getting Processor Stats");
	while (fgets(line, sizeof(line), fd) != NULL) {
		LOGF_LOG_DEBUG("Line : %s\n", line);
		readB = 0;
		sscanf(line, "%llu %s", &readB, findPtr);
		if (strcmp("cycles", findPtr) == 0) {
			xProcessorInfo->nCycles = readB;
			LOGF_LOG_DEBUG("nCycles =%llu\n", xProcessorInfo->nCycles);
			break;
		}
	}
	pclose(fd);
	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_ReadVpidFile                                          *
* Description   : xRX750_ReadVpidFile is responsible for getting PP stats      *
*                 for xRX750 platforms                                         *
* Input         : ifData                                                       *
* OutPut        : ifData                                                       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t xRX750_ReadVpidFile(struct InterfaceData * ifData)
{
	FILE *fp;
	char line[256] = { 0 };
	char findPtr[15];
	char findPtr2[15];
	char findPtr3[15];
	uint64_t data;
	if (!ifData->vpidName) {
		printf("Wrong Interface Name\n");
		return UGW_FAILURE;
	}
	fp = fopen(VPID_FILE_PATH, "r");
	if (fp == NULL) {
		return UGW_FAILURE;
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, ifData->vpidName) != 0) {
			while (fgets(line, sizeof(line), fp) != NULL) {
				sscanf(line, "%s %s %s %llu", findPtr, findPtr2, findPtr3, &data);
				if ((strcmp(findPtr, "Rx") == 0) && (strcmp(findPtr2, "Bytes") == 0)) {
					ifData->rxCounter = data;
				}
				if ((strcmp(findPtr, "Tx") == 0) && (strcmp(findPtr2, "Bytes") == 0)) {
					ifData->txCounter = data;
					break;
				}
			}
		}
	}

	fclose(fp);
	LOGF_LOG_DEBUG("ifData->rxCounter =%llu ifData->txCounter =%llu\n", ifData->rxCounter, ifData->txCounter);
	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_ReadNetDevFile                                        *
* Description   : xRX750_ReadNetDevFile is responsible for getting linux       *
*                 network stack stats for xRX750 platforms                     *
* Input         : ifData                                                       *
* OutPut        : ifData                                                       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t xRX750_ReadNetDevFile(struct InterfaceData * ifData)
{
	FILE *fp;
	char line[256] = { 0 };
	uint64_t dummy;
	char interfaceName[20];
	uint64_t rxB, txB;

	if (!ifData->interfaceName) {
		LOGF_LOG_DEBUG("Interface Invalid\n");
		return UGW_FAILURE;
	}
	fp = fopen(STACK_FILE_PATH, "r");
	if (fp == NULL) {
		return UGW_FAILURE;
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		sscanf(line, "%s %llu %llu %llu %llu %llu %llu %llu %llu %llu", interfaceName, &rxB, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &txB);
		if (strstr(interfaceName, ifData->interfaceName) != 0) {
			ifData->rxCounter = rxB;
			ifData->txCounter = txB;
		}
	}
	fclose(fp);
	LOGF_LOG_DEBUG("ifData->rxCounter =%llu ifData->txCounter =%llu\n", ifData->rxCounter, ifData->txCounter);
	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_VpidAndStackBoth                                      *
* Description   : xRX750_VpidAndStackBoth is responsible for getting both PP   *
*                 and network stack stats for xRX750 platforms                 *
* Input         : ifData                                                       *
* OutPut        : ifData                                                       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

int32_t xRX750_VpidAndStackBoth(struct InterfaceData * ifData)
{
	int ret = 0;
	uint64_t rxBytes = 0;
	uint64_t txBytes = 0;
	ret = xRX750_ReadVpidFile(ifData);
	if (ret == UGW_FAILURE) {
		return UGW_FAILURE;
	}
	rxBytes = ifData->rxCounter;
	txBytes = ifData->txCounter;
	ret = xRX750_ReadNetDevFile(ifData);
	if (ret < 0) {
		return UGW_FAILURE;
	}
	ifData->rxCounter += rxBytes;
	ifData->txCounter += txBytes;
	LOGF_LOG_DEBUG("ifData->rxCounter =%llu ifData->txCounter =%llu\n", ifData->rxCounter, ifData->txCounter);
	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_GetInterfaceStructPtr                                 *
* Description   : xRX750_GetInterfaceStructPtr is responsible for getting      *
*                 InterfaceData for xRX750 platforms                           *
* Input         : ifData                                                       *
* OutPut        : ifData                                                       *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */

struct InterfaceData *xRX750_GetInterfaceStructPtr(uint32_t interfaceId)
{
	int32_t looper;
	int32_t i_find = 0;
	struct InterfaceData *iFace = NULL;
	if (interfaceId > 7) {
		return NULL;
	}
	for (looper = 0; looper < MAX_INTERFACES; looper++) {
		if (intf_arr[looper].interfaceId == interfaceId) {
			iFace = &intf_arr[looper];
			i_find++;
			break;
		}
	}

	if (!i_find) {
		return NULL;
	}
	return iFace;
}

#define FILE_COREMARK_NAME "sh -c 'coremark | grep \"CoreMark 1.0\" >/tmp/.coremark_result;cp /tmp/.coremark_result /tmp/coremark_result' &"
static int xRX750_cgiGetCoremark(struct InterfaceData *ifData)
{
	FILE *fdFile = NULL;
	char c_line[256] = { 0 };
	float coremarkVal = 0;
	int ret = -1;
	int retCmd = 1;
	retCmd = system(FILE_COREMARK_NAME);
	if (retCmd == -1) {
		goto qeury_coremark_end;
	}
	fdFile = fopen("/tmp/coremark_result", "r");
	if (fdFile == NULL) {
		LOGF_LOG_DEBUG("Coremark Not Available....!");
		ret = -1;
		goto qeury_coremark_end;
	}
	while (fgets(c_line, sizeof(c_line), fdFile) != NULL) {
		LOGF_LOG_DEBUG("%s\n", c_line);
		if (strstr(c_line, "CoreMark 1.0") != NULL) {
			sscanf(c_line, "CoreMark 1.0 : %f /", &coremarkVal);
			ret = 1;
			LOGF_LOG_DEBUG("coremarkVal =%f\n", coremarkVal);
			break;
		}
	}
	fclose(fdFile);
	if (ret == 1) {
		ifData->rxCounter = (unsigned long long)coremarkVal;
		ifData->txCounter = (unsigned long long)coremarkVal;
		LOGF_LOG_DEBUG("coremarkVal =%llu\n", ifData->rxCounter);
		LOGF_LOG_DEBUG("coremarkVal =%llu\n", ifData->txCounter);
	} else {
		ifData->rxCounter = 0;
		ifData->txCounter = 0;
		LOGF_LOG_DEBUG("coremarkVal =%llu\n", ifData->rxCounter);
		LOGF_LOG_DEBUG("coremarkVal =%llu\n", ifData->txCounter);
	}
 qeury_coremark_end:
	return 0;
}

/* =============================================================================
 *  Function Name : fapi_rmon_get_platform				       *
 *  Description   : This fapi is used read switch port RMON statistics	       *
 *  Input	  : PortId, 						       *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t xRX750_RMONGetPlatform(IN int32_t port, OUT RMONGet_t * RMONGet)
{
	int ret = -1;
	struct InterfaceData *iFacePtr = NULL;
	LOGF_LOG_DEBUG("Port :%d\n", port);

	if (RMONGet == NULL) {
		return UGW_FAILURE;
	}

	if (port < 0 || port > 7) {
		return UGW_FAILURE;
	}

	iFacePtr = xRX750_GetInterfaceStructPtr(port);
	if (!iFacePtr) {
		return UGW_FAILURE;
	}

	ret = iFacePtr->GetCounters(iFacePtr);
	if (ret == UGW_FAILURE) {
		return UGW_FAILURE;
	}

	RMONGet->RxBytes = iFacePtr->rxCounter;
	RMONGet->TxBytes = iFacePtr->txCounter;
	LOGF_LOG_DEBUG("RMONGet->RxBytes =%llu, RMONGet->TxBytes =%llu\n", RMONGet->RxBytes, RMONGet->TxBytes);

	return UGW_SUCCESS;
}

/* =============================================================================
* Function Name : xRX750_Processor_init                                        *
* Description   : xRX750_Processor_init is responsible for Processor Init      * 
*                 of 750 module                                                *
* Input         : None                                                         *
* OutPut        : None                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
============================================================================== */
int32_t xRX750_Processor_init(void)
{
	return UGW_SUCCESS;
}

/* =============================================================================
 * * Function Name : GRX750_SetInterface                                        *
 * * Description   : GRX750_SetInterface is responsible for              *
 * *                 calling platform specific FAPIs.            *
 * * Input         : InterfaceType enum,State enum                                                          *
 * * OutPut        : None                                                         *
 * * Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
 * ============================================================================== */
int32_t GRX750_SetInterface(InterfaceType interface, State setState)
{
	int platform_Type = 0;
	int nRet = UGW_FAILURE;
	struct stat st;

	if (strstr(xRX750_check_boardID(), HVP_BOARD_ID) != NULL) {
		platform_Type = HVP;
	} else if (strstr(xRX750_check_boardID(), EASY750_BOARD_ID) != NULL) {
		platform_Type = GRX750;
	}
	switch (interface) {
	case INITDONE:
		if (stat(ALL_INIT_DONE_SCRIPT, &st) == 0) {
			nRet = system(ALL_INIT_DONE_SCRIPT);
			LOGF_LOG_DEBUG("%s returned %d\n", ALL_INIT_DONE_SCRIPT, nRet);
		} else {
			LOGF_LOG_ERROR("ALL_INIT_DONE script not found\n");
		}
		break;
	default:
		break;
	}
	if (platform_Type == HVP) {
		nRet = HVP_SetInterface(interface, setState);
	}
	return nRet;
}

int32_t HVP_SetInterface(IN InterfaceType interface, IN State setState)
{
	int nRet = UGW_FAILURE;

	switch (interface) {
	case BOOTING:
		{
			if (setState == UP || setState == DOWN || setState == ERROR) {
				nRet = HVP_ConfigureLED();
			}
			break;
		}
	case WIFI2:
	case WIFI5:
		{
			if (setState == UP || setState == DOWN || setState == ERROR) {
				nRet = HVP_ConfigureLED();
			}
			break;
		}
	default:
		{
			LOGF_LOG_ERROR("Invalid Interface for HVP \n");
			nRet = UGW_FAILURE;
		}
	}
	return nRet;
}

int HVP_ConfigureLED(void)
{
	sDefaultAttr attr;
	char *status = NULL;
	int nRet = UGW_FAILURE;
	State nWIFI2State = DOWN, nWIFI5State = DOWN, nBootState = DOWN;

	status = GetFAPIIfData(FILE_NAME, "BOOTING");
	if (status != NULL) {
		nBootState = atoi(status);
	}
	if (nBootState == ERROR) {
		nRet = HVP_setStateError();
		return nRet;
	}
	status = GetFAPIIfData(FILE_NAME, "WIFI2");
	if (status != NULL) {
		nWIFI2State = atoi(status);
	}
	status = GetFAPIIfData(FILE_NAME, "WIFI5");
	if (status != NULL) {
		nWIFI5State = atoi(status);
	}
	if (nWIFI2State == ERROR || nWIFI5State == ERROR) {
		LOGF_LOG_INFO("WIFI ERROR: RED is ON \n");
		nRet = HVP_setStateError();
	} else if (nWIFI2State == UP || nWIFI5State == UP) {
		LOGF_LOG_INFO("WIFI is UP: BLUE is ON\n");
		nRet = HVP_SetWIFIUP();
	} else {
		if (nBootState == UP) {
			memset(&attr, 0, sizeof(attr));
			attr.nBrightness = 1;	/* For HVP nBrightness = 1 , turns LED OFF */
			nRet = FAPI_LEDSetAttribute(HVPRED, TRIGGER_DEFAULT, &attr);
			nRet = FAPI_LEDSetAttribute(HVPBLUE, TRIGGER_DEFAULT, &attr);
			attr.nBrightness = 0;	/* For HVP nBrightness = 0 , turns LED ON */
			nRet = FAPI_LEDSetAttribute(HVPGREEN, TRIGGER_DEFAULT, &attr);
		}
	}
	return nRet;
}

int HVP_SetWIFIUP(void)
{
	sDefaultAttr attr;
	int nRet = UGW_FAILURE;

	memset(&attr, 0, sizeof(attr));
	attr.nBrightness = 1;	/* For HVP nBrightness = 1 , turns LED OFF */
	nRet = FAPI_LEDSetAttribute(HVPGREEN, TRIGGER_DEFAULT, &attr);
	nRet = FAPI_LEDSetAttribute(HVPRED, TRIGGER_DEFAULT, &attr);
	attr.nBrightness = 0;	/* For HVP nBrightness = 0 , turns LED ON */
	nRet = FAPI_LEDSetAttribute(HVPBLUE, TRIGGER_DEFAULT, &attr);
	return nRet;
}

static int HVP_setStateError(void)
{
	sDefaultAttr attr;
	int nRet = UGW_FAILURE;

	memset(&attr, 0, sizeof(attr));
	attr.nBrightness = 1;	/* For HVP nBrightness = 1 , turns LED OFF */
	nRet = FAPI_LEDSetAttribute(HVPGREEN, TRIGGER_DEFAULT, &attr);
	nRet = FAPI_LEDSetAttribute(HVPBLUE, TRIGGER_DEFAULT, &attr);
	attr.nBrightness = 0;	/* For HVP nBrightness = 0 , turns LED ON */
	nRet = FAPI_LEDSetAttribute(HVPRED, TRIGGER_DEFAULT, &attr);
	return nRet;
}
