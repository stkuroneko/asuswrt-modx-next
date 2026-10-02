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

	if (scapi_getInterfaceList(&pxIfaceList, BOTH_INTERFACES) != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Failed to get interface list.\n");
		return -1;
	}

	FOR_EACH_INTERFACE(pxIfaceList, pxTmpIface) {
		if (PortId == atoi(pxTmpIface->cPort)) {
			if (strcmp(pxTmpIface->cType, "LAN") == 0) {
				/*if ioctl is invoked on LAN use switch dev 0 */
				SWITCH_DEV_OPEN(SWITCH_DEVICE_ID, switch_fd, retval)
				    SWITCH_DEV_IOCTL(switch_fd, ioctl_cmd, data, retval)
				    if (switch_fd >= 0) {
					close(switch_fd);
				} else {
					LOGF_LOG_DEBUG("IOCTL %d on switch dev %d failed!!\n", ioctl_cmd, SWITCH_DEVICE_ID);
					return retval;
				}
			} else if (strcmp(pxTmpIface->cType, "WAN") == 0) {
				/*if ioctl is invoked on ETH WAN port use switch dev 1 */
				SWITCH_DEV_OPEN(SWITCH_DEVICE_ID_1, switch_fd, retval)
				    SWITCH_DEV_IOCTL(switch_fd, ioctl_cmd, data, retval)
				    if (switch_fd >= 0) {
					close(switch_fd);
				} else {
					LOGF_LOG_DEBUG("IOCTL %d on switch dev %d failed!!\n", ioctl_cmd, SWITCH_DEVICE_ID_1);
					return retval;
				}

			}

		}
	}
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

	sprintf(cmd_buf, "/etc/init.d/wan_vlan_config %d %d", vlanCfg->oper, vlanCfg->vlanId);
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
