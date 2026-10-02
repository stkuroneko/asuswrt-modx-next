/* header files */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h> 
#include <ctype.h>
#include <ulogging.h>
#include "fapi_sys_common.h"
#ifdef PLATFORM_XRX200 
#include "xRX220_callback.h"
#endif
#ifdef PLATFORM_XRX500 
#include "xRX350_callback.h"
#endif
#ifdef PLATFORM_XRX750
#include "xRX750_callback.h"
#endif

/* =============================================================================
* Function Name : fapi_processorstat_init				       *
* Description   : This function is responsible for loading processor modules   *
* Input         : None
* OutPut        : None
* Returns       : UGW_SUCCESS/UGW_FAILURE
============================================================================== */
int32_t fapi_processorstat_init(void)
{
        int32_t nRet = UGW_SUCCESS;

	nRet = fapicb.ProcessorInit();
	if(nRet != UGW_SUCCESS)
	{
        	LOGF_LOG_CRITICAL("Loading processor moudles failed!\n");
		goto end;
        }

	LOGF_LOG_INFO("Loading processor moudles successful.\n");

end:
	return nRet;
}

/* ==================================================================================
* Function Name : fapi_cpustat_uninit	    					     *
* Description   : fapi_cpustat_uninit is responsible for unloading processor modules *
* Input         : None
* OutPut        : None
* Returns       : UGW_SUCCESS/UGW_FAILURE
==================================================================================== */
int32_t fapi_processorstat_uninit(void)
{
        int32_t nRet = UGW_SUCCESS;

        nRet = fapicb.ProcessorUnInit();
        if(nRet != UGW_SUCCESS)
        {
                LOGF_LOG_CRITICAL("Unloading processor moudles failed!\n");
		goto end;
        }
        LOGF_LOG_INFO("Unloading processor moudles successful.\n");

end:
        return nRet;
}

/* =======================================================================================
* Function Name : fapi_processorstat_get
* Description   : fapi_processorstat_get is responsible to get procrssor stats from system
* Input         : CpuCounter struct to get counter values from kernel
* OutPut        : None
* Returns       : UGW_SUCCESS/UGW_FAILURE
========================================================================================== */
int32_t fapi_processorstat_get(ProcessorCounter *xProcessorInfo)
{
	int32_t nRet = UGW_SUCCESS;

        nRet = fapicb.ProcessorStat(xProcessorInfo);
        if(nRet != UGW_SUCCESS)
        {
                LOGF_LOG_CRITICAL("Failed to fetch Processor stats!!");
		goto end;
        }

end:
	return nRet;
}

