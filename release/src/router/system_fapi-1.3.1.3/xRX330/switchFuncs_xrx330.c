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
#include "ulogging.h"
#include "fapi_sys_common.h"
#include "fapi_sys.h"
#include "ltq_api_include.h"
#include "xRX330_callback.h"
#include "fapi_eth.h"

/* ============================================================================
 *  Function Name : xRX330_cfg_SwitchIOCTL                                            *
 *  Description   : This is a helper function used to configure ioct cmd       *
 *                  based on port id the ioctl is configured on. it takes port *
 *	            ioctl and structure to configure ioctl as inputs           *
 *  Input	  : int32_t PortId, IOCTL command, structure related to ioctl  * 
 *  Output	  : none                                                       *
 *  return value  : UGW_SUCCESS/UGW_FAILURE                                    *
 * ============================================================================*/
int32_t xRX330_cfg_SwitchIOCTL(__attribute__ ((unused))IN int32_t PortId, IN int32_t ioctl_cmd, IN void *data)
{
	int32_t retval = UGW_SUCCESS;
	int32_t switch_fd = -1;

	/*if ioctl is invoked on LAN use switch dev 0 */
	SWITCH_DEV_OPEN(SWITCH_DEVICE_ID, switch_fd, retval)
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	SWITCH_DEV_IOCTL(switch_fd, ioctl_cmd, data, retval)
	if (switch_fd >= 0) {
		close(switch_fd);
	}

	return retval;
}


/* =============================================================================
 *  Function Name : xRX330_VLANCfgSet					       *
 *  Description   : This is a xRX330 platform function to set vlan config      *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t xRX330_VLANCfgSet(IN vlanCfg_t * vlanCfg)
{
	int32_t retval = UGW_SUCCESS;
	char cmd_buf[MAX_DATA_LEN] = { 0 };
	sys_cfg_t sysCfg;

	memset(&sysCfg, 0, sizeof(sys_cfg_t));
	
	LOGF_LOG_DEBUG("vconfig oper =%d; vlan =%d\n",vlanCfg->oper,vlanCfg->vlanId);
	retval = fapicb.sysGet(&sysCfg);
	if(retval == UGW_SUCCESS) {
		if(sysCfg.priWAN == ETH) {
			snprintf(cmd_buf, sizeof(cmd_buf), "%s %d %d eth", FAPI_SYS_WAN_VLAN_CFG_SCRIPT, vlanCfg->oper, (int)vlanCfg->vlanId);
		} else {
			snprintf(cmd_buf, sizeof(cmd_buf), "%s %d %d dsl", FAPI_SYS_WAN_VLAN_CFG_SCRIPT, vlanCfg->oper, (int)vlanCfg->vlanId);
		}
	} else {
		snprintf(cmd_buf, sizeof(cmd_buf), "%s %d %d eth", FAPI_SYS_WAN_VLAN_CFG_SCRIPT, vlanCfg->oper, (int)vlanCfg->vlanId);
	}
	LOGF_LOG_DEBUG("%s\n",cmd_buf);	
	system(cmd_buf);

	return retval;
}







/* =========================================================================== *
 *  Function Name : xRX330_GetPortStatus                                       * 
 *  Description   : This fapi is used to read switch port status.              *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    *
 * ===========================================================================*/
int32_t xRX330_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	GSW_portCfg_t PortCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;
	
	if ( (PortId < 0) || (PortId > 15) )
	{
		LOGF_LOG_ERROR("Invalid PortId used, Try with valid portId between 0-15!");
		return UGW_FAILURE;
	}
	memset(&PortCfg, 0, sizeof(PortCfg));
	PortCfg.nPortId = PortId;
	switch_params = (void *)&PortCfg;

	retval = xRX330_cfg_SwitchIOCTL(PortId, GSW_PORT_CFG_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}

	port_get->eEnable = PortCfg.eEnable;
	LOGF_LOG_DEBUG("Fapi Get Status: PortId=%d, Status =%d\n", PortId, port_get->eEnable);

	return retval;
}


