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
#include "fapi_eth.h"
#include "scapi_interfaces_defines.h"

/* ============================================================================
 *  Function Name : xRX750_cfg_SwitchIOCTL                                            *
 *  Description   : This is a helper function used to configure ioct cmd       *
 *                  based on port id the ioctl is configured on. it takes port *
 *	            ioctl and structure to configure ioctl as inputs           *
 *  Input	  : int32_t PortId, IOCTL command, structure related to ioctl  * 
 *  Output	  : none                                                       *
 *  return value  : UGW_SUCCESS/UGW_FAILURE                                    *
 * ============================================================================*/
int32_t xRX750_cfg_SwitchIOCTL(IN int32_t PortId, IN int32_t ioctl_cmd, IN void *data)
{
	int32_t retval = UGW_SUCCESS;
	int32_t switch_fd = -1;
	IfaceCfg_t *pxIfaceList = NULL;
	IfaceCfg_t *pxTmpIface = NULL;

	if (scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES, NULL) != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Failed to get interface list.\n");
		retval = UGW_FAILURE;
		goto end;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if (PortId == atoi(pxTmpIface->cPort)) {
			if (strcmp(pxTmpIface->cType, "LAN") == 0) {
				/*if ioctl is invoked on LAN use switch dev 0 */
				SWITCH_DEV_OPEN(SWITCH_DEVICE_ID, switch_fd, retval)
				if (retval != UGW_SUCCESS) {
					goto end;
				}
				SWITCH_DEV_IOCTL(switch_fd, ioctl_cmd, data, retval)
				if (switch_fd >= 0) {
					close(switch_fd);
					switch_fd = -1;
				} else {
					goto end;
				}
			} else {
				LOGF_LOG_ERROR("Invalid cType: '%s' [IOCTL: %d]\n", pxTmpIface->cType, ioctl_cmd);
				retval = UGW_FAILURE;
				break;
			}
		}
	}
end:
	scapi_deleteInterfaceList(&pxIfaceList);
	return retval;
}

/* =============================================================================
 *  Function Name : xRX750_VLANCfgSet					       *
 *  Description   : This is a xRX750 platform function to set vlan config      *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t xRX750_VLANCfgSet(IN vlanCfg_t * vlanCfg)
{
	int32_t retval = UGW_SUCCESS;
	char cmd_buf[MAX_DATA_LEN] = { 0 };

	snprintf(cmd_buf, sizeof(cmd_buf), "%s %d %d", FAPI_SYS_WAN_VLAN_CFG_SCRIPT, vlanCfg->oper, (int)vlanCfg->vlanId);
	system(cmd_buf);

	return retval;
}

/* =========================================================================== *
 *  Function Name : xRX750_GetPortStatus                                       * 
 *  Description   : This fapi is used to read switch port status.              *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    *
 * ===========================================================================*/
int32_t xRX750_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	GSW_portCfg_t PortCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	if ((PortId < 0) || (PortId > 31)) {
		LOGF_LOG_ERROR("Invalid PortId used, Try with valid portId between 0-15!");
		return UGW_FAILURE;
	}
	memset(&PortCfg, 0, sizeof(PortCfg));
	PortCfg.nPortId = PortId;
	switch_params = (void *)&PortCfg;

	retval = xRX750_cfg_SwitchIOCTL(PortId, GSW_PORT_CFG_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}

	port_get->eEnable = PortCfg.eEnable;
	LOGF_LOG_DEBUG("Fapi Get Status: PortId=%d, Status =%d\n", PortId, port_get->eEnable);

	return retval;
}
