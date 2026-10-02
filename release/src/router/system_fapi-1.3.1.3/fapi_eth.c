/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* header files */
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
#include "fapi_eth.h"
#include "ltq_api_include.h"



/* =============================================================================
* Function Name : fapi_get_mac_addr                            		       *
* Description   : function to read mac address from /proc/cmdline	       *
*                 this function is used to set the mac address of eth0_1 by    *
*		  reading from /proc/cmdline.   			       *
* Input		: None                                                         *
* OutPut	: Mac address string read from /proc/cmdline                   *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                      *
==============================================================================*/
int32_t fapi_get_mac_addr(OUT char *mac_addr)
{
	FILE *fp = NULL;
	int32_t ret = UGW_SUCCESS;
	int32_t nCount = 0;
	char fbuf[MAX_FBUF_SIZE];
	char *p = NULL;

	memset(fbuf, '\0', sizeof(char) * MAX_FBUF_SIZE);
	if (get_hw_platform() == HW_PLATFORM_GRX750) {
		fp = popen("/usr/sbin/nvram_env.sh get ethaddr", "r");
	} else {
		fp = fopen("/proc/cmdline", "r");
	}
	if (fp == NULL) {
		if (get_hw_platform() == HW_PLATFORM_GRX750) {
			LOGF_LOG_DEBUG("popen(/usr/sbin/nvram_env.sh) failed due to '%m'\n");
		} else {
			LOGF_LOG_DEBUG("/proc/cmdline not found!!\n");
		}
		ret = ERR_FILE_NOT_FOUND;
		goto cleanup;
	} else {
		p = fgets(fbuf, sizeof(fbuf), fp);
		if (p == NULL) {
			LOGF_LOG_DEBUG("fgets failed due to '%m'\n");
			ret = ERR_STRING_NOT_FOUND;
			goto cleanup;
		}
		if (get_hw_platform() == HW_PLATFORM_GRX750) {
			p = fbuf;
		} else {
			p = strstr(fbuf, "ethaddr"); /* Searching for 'ethaddr=MAC' (or may be 'ethaddr MAC') from /proc/cmdline */
			p = ((p) ? (p + 8) : NULL);
		}
		if (p != NULL) {
			for (nCount = 0; nCount < MAC_STRING_LEN; nCount++) {
				mac_addr[nCount] = *(p + nCount);
			}
		} else {
			LOGF_LOG_CRITICAL("MAC Address not found in /proc/cmdline\n");
			LOGF_LOG_CRITICAL("LAN and WAN interface mac addresses might not be correct\n");
			ret = ERR_STRING_NOT_FOUND;
		}
	}

cleanup:
	if (fp) {
		if (get_hw_platform() == HW_PLATFORM_GRX750) {
			pclose(fp);
		} else {
			fclose(fp);
		}
	}
	return ret;
}

/* ================================================================================
* Function Name : fapi_validateVLAN                            		          *
* Description   :  Function to return VLAN ID needed for ETH Untagged Bridged WAN *
*		   Connection (valid for legacy platform e.g vrx220) and reject   *
*                  any other routed wan connection request on same VLAN		  *
* Input		: Base interface name                                             *
* OutPut	: VLAN Id                                                         *
* Returns       : UGW_SUCCESS/UGW_FAILURE                                         *
==================================================================================*/
int fapi_validateVLAN(char *psBasIface, int *pnVLANId)
{
        int32_t nRet = UGW_SUCCESS;
        int32_t nPlatformType = get_hw_platform();

        if (nPlatformType != HW_PLATFORM_xRX220 && nPlatformType != HW_PLATFORM_xRX330) {
		goto end;
	}
		
	/* No Need of Dummy VLAN Creation for Other that ETH mode */	
	if (strcmp(psBasIface, "eth1") != 0) { /* TODO: Remove "eth1" Hardcoding */
		nRet = UGW_SUCCESS;
		goto end;
	}

	if (*pnVLANId == -1) { /* Opt For Dummy VLAN: 504 */
		*pnVLANId = 502;
	} else if (*pnVLANId == 502) { /* Validation: Same VLAN Cann't be used */
		nRet = UGW_FAILURE;
	}

end:
	return nRet;
}
