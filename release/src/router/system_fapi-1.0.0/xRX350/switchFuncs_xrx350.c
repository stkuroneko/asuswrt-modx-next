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
 *  Function Name : xRX350_cfg_SwitchIOCTL                                            *
 *  Description   : This is a helper function used to configure ioctl cmd       *
 *                  based on port id the ioctl is configured on. it takes port *
 *	            ioctl and structure to configure ioctl as inputs           *
 *  Input	  : int32_t PortId, IOCTL command, structure related to ioctl  * 
 *  Output	  : none                                                       *
 *  return value  : UGW_SUCCESS/UGW_FAILURE                                    *
 * ============================================================================*/
int32_t xRX350_cfg_SwitchIOCTL(IN int32_t PortId, IN int32_t ioctl_cmd, IN void *data)
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
 *  Function Name : xRX350_VLANCfgSet					       *
 *  Description   : This is a xRX350 platform function to set vlan config      *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t xRX350_VLANCfgSet(IN vlanCfg_t * vlanCfg)
{
	int32_t retval = UGW_SUCCESS;
	char cmd_buf[MAX_DATA_LEN] = { 0 };

	sprintf(cmd_buf, "/etc/init.d/wan_vlan_config %d %d", vlanCfg->oper, vlanCfg->vlanId);
	system(cmd_buf);

	return retval;
}

/* =========================================================================== *
 *  Function Name : xRX350_GetPortStatus                                       * 
 *  Description   : This fapi is used to read switch port status.              *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    *
 * ===========================================================================*/
int32_t xRX350_GetPortStatus(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	GSW_portCfg_t PortCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	if ((PortId < 0) || (PortId > 15)) {
		LOGF_LOG_ERROR("Invalid PortId used, Try with valid portId between 0-15!");
		return UGW_FAILURE;
	}
	memset(&PortCfg, 0, sizeof(PortCfg));
	PortCfg.nPortId = PortId;
	switch_params = (void *)&PortCfg;

	retval = xRX350_cfg_SwitchIOCTL(PortId, GSW_PORT_CFG_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}

	port_get->eEnable = PortCfg.eEnable;
	LOGF_LOG_DEBUG("Fapi Get Status: PortId=%d, Status =%d\n", PortId, port_get->eEnable);

	return retval;
}

/* =========================================================================== *
 *  Function Name : EnableMirroring                                     * 
 *  Description   : This fapi is used to configure portmirroring configurations*
 *		    on the router by using the interfaces provided by user.    *
 *                  user needs to provide downstream interface and Mirrored    *
 *		    interface as inputs.                                       *
 *                  Fapi finds the switch port attached to interface and       *
 *                  configures required Mirroring configuration in switch      *
 *  Input	  : Downstream Interface, Mirror Interface                     *
 *  Output	  : None 						       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ===========================================================================*/
int32_t xRX350_EnableMirroring(IN char * DownstreamIntf ,IN char * MirrorIntf)
{
	PPA_CMD_ENABLE_INFO PPAenInfo;
	GSW_portCfg_t PortCfg;
	GSW_monitorPortCfg_t PortMirrorCfg;

	void *switch_params = NULL;
	int32_t switch_fd = 1;
	int32_t retval = UGW_SUCCESS;
	int32_t MirroredPort = -1;
	int32_t nIntfPortId = -1;
	
	memset(&PPAenInfo, 0, sizeof(PPAenInfo));
	memset(&PortCfg, 0, sizeof(PortCfg));
	memset(&PortMirrorCfg, 0, sizeof(PortMirrorCfg));

	/*Disable WAN acceleration*/
	PPAenInfo.lan_rx_ppa_enable = 1;
	PPAenInfo.wan_rx_ppa_enable = 0;
	
	retval = fapi_sys_ppa_enable(&PPAenInfo);
        if (retval != UGW_SUCCESS) {
        	LOGF_LOG_DEBUG("Failed to disable PPA, exiting mirroring!!\n");
		return retval;
	}
	
	/*get port id of interface passed */
	nIntfPortId = fapi_get_portid(DownstreamIntf);
	//nIntfPortId = fapicb.getPortId(DownstreamIntf);
	if (nIntfPortId < 0) {
		LOGF_LOG_DEBUG("Invalid Interface Port(LAN), DownStream interface provided maybe incorrect!!\n");
		return retval;
	}
	LOGF_LOG_DEBUG("port id of Interface =%d\n", nIntfPortId);
	

	/* Configure GSWIP R */
	SWITCH_DEV_OPEN(SWITCH_DEVICE_ID_1, switch_fd, retval);
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Switch FD open failed!\n");
		return retval;
	}
	
	LOGF_LOG_DEBUG("Configuring port mirror for LAN interface!!\n");
	
	/* Do a GET to get existing configuration into switch_params structure
	   This is done so that existing configuration is not lost
	 */
	PortCfg.nPortId = nIntfPortId;
	switch_params = (void *)&PortCfg;

	SWITCH_DEV_IOCTL(switch_fd, GSW_PORT_CFG_GET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("PORT CFG GET on LAN interface failed!\n");
        	close(switch_fd);	
		return retval;
	}
	
	/*configure ePortMointor on LAN Port*/
	PortCfg.nPortId = nIntfPortId;
	PortCfg.ePortMonitor = GSW_PORT_MONITOR_RXTX;
	switch_params = (void *)&PortCfg;
	LOGF_LOG_DEBUG("ePortMonitor =%d on Port %d\n",PortCfg.ePortMonitor,PortCfg.nPortId);
	
	SWITCH_DEV_IOCTL(switch_fd, GSW_PORT_CFG_SET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Config mirroring on DS interface failed!\n");
        	close(switch_fd);	
		return retval;
	}
	
	MirroredPort = fapi_get_portid(MirrorIntf);
	//MirroredPort = fapicb.getPortId(MirrorIntf);
	LOGF_LOG_DEBUG("Mirrored Port =%d\n", MirroredPort);
	if (MirroredPort < 0) {
		LOGF_LOG_DEBUG("INVALID Mirror port, Mirror interface may not be valid!!\n");
		return retval;
	}
	
	/*Configure Mirroring on Mirror Port */
	PortMirrorCfg.nPortId = MirroredPort;
	switch_params = (void *)&PortMirrorCfg;
	SWITCH_DEV_IOCTL(switch_fd, GSW_MONITOR_PORT_CFG_GET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Config mirroring on Mirrored port failed!\n");
        	close(switch_fd);	
		return retval;
	}
	
	PortMirrorCfg.nPortId = MirroredPort;
	PortMirrorCfg.bMonitorPort = MIRROR_ENABLE;
	switch_params = (void *)&PortMirrorCfg;
		
	LOGF_LOG_DEBUG("PortMonitorCfg =%d on Mirrored Port %d\n",PortMirrorCfg.bMonitorPort,PortMirrorCfg.nPortId);
	SWITCH_DEV_IOCTL(switch_fd, GSW_MONITOR_PORT_CFG_SET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Config mirroring on Mirrored port failed!\n");
        	close(switch_fd);	
		return retval;
	}
	
        close(switch_fd);	
	LOGF_LOG_DEBUG("Configured Port Mirroring on Port%d Successfully \n",MirroredPort);

	return retval;
}


/* =========================================================================== *
 *  Function Name : DisableMirroring                                     * 
 *  Description   : This fapi is used to disable portmirroring configurations  *
 *		    on the router.                                             *
 *                  user needs to provide upstream interface, downstream       *
 *		    interface and Mirrored interface as inputs.                *
 *                  Fapi finds the switch port attached to interface and       *
 *                  disables port Mirroring configuration in switch            *
 *  Input	  : Upstream Interface, Downstream Interface, Mirror Interface *
 *  Output	  : None 						       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ===========================================================================*/
int32_t xRX350_DisableMirroring(IN char * DownstreamIntf, IN char * MirrorIntf)
{
	PPA_CMD_ENABLE_INFO PPAenInfo;
	GSW_portCfg_t PortCfg;
	GSW_monitorPortCfg_t PortMirrorCfg;
	void *switch_params = NULL;
	int32_t switch_fd = 0;
	int32_t retval = UGW_SUCCESS;
	int32_t MirroredPort = -1;
	int32_t nIntfPortId = -1;
	
	memset(&PPAenInfo, 0, sizeof(PPAenInfo));
	memset(&PortCfg, 0, sizeof(PortCfg));
	memset(&PortMirrorCfg, 0, sizeof(PortMirrorCfg));
	
		
	nIntfPortId = fapi_get_portid(DownstreamIntf);
	//nIntfPortId = fapicb.getPortId(DownstreamIntf);
	if (nIntfPortId < 0) {
		LOGF_LOG_DEBUG("Invalid Interface Port(LAN), DownStream interface provided maybe incorrect!!\n");
		return retval;
	}
	LOGF_LOG_DEBUG("Down Stream Port =%d\n", nIntfPortId);
	
	MirroredPort = fapi_get_portid(MirrorIntf);
	//MirroredPort = fapicb.getPortId(MirrorIntf);
	LOGF_LOG_DEBUG("Mirrored Port =%d\n", MirroredPort);
	if ((MirroredPort < 0) || (MirroredPort > 5)) {
		LOGF_LOG_DEBUG("INVALID Mirror port, Mirror interface may not be valid!!\n");
		return retval;
	}
	
	SWITCH_DEV_OPEN(SWITCH_DEVICE_ID_1, switch_fd, retval);
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Switch FD open failed!\n");
		return retval;
	}
	
	LOGF_LOG_DEBUG("Configuring port mirror for LAN interface!!\n");
	PortCfg.nPortId = nIntfPortId;
	switch_params = (void *)&PortCfg;
	
	SWITCH_DEV_IOCTL(switch_fd, GSW_PORT_CFG_GET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("PORT CFG GET on LAN interface failed!\n");
	       	close(switch_fd);	
		return retval;
	}
	/*Disable ePortMointor on DS Port*/
	PortCfg.nPortId = nIntfPortId;
	PortCfg.ePortMonitor = GSW_PORT_MONITOR_RXTX;
	switch_params = (void *)&PortCfg;
	LOGF_LOG_DEBUG("PortMonitor =%d on Port %d\n",PortCfg.ePortMonitor,PortCfg.nPortId);
	SWITCH_DEV_IOCTL(switch_fd, GSW_PORT_CFG_SET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Config ePortMonitor on LAN port failed!\n");
        	close(switch_fd);	
		return retval;
	}
	
	/*Configure Mirroring on Mirror Port */
	//PortMirrorCfg.nPortId = MirroredPort;
	PortMirrorCfg.bMonitorPort = MIRROR_DISABLE;
	//switch_params = (void *)&PortMirrorCfg;
		
	LOGF_LOG_DEBUG("PortMonitor =%d on Port %d\n",PortMirrorCfg.bMonitorPort,PortMirrorCfg.nPortId);
	SWITCH_DEV_IOCTL(switch_fd, GSW_MONITOR_PORT_CFG_SET, switch_params, retval)
	if (retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Config mirroring on Mirrored failed!\n");
        	close(switch_fd);	
		return retval;
	}
	
        close(switch_fd);	
	
	/*Enable LAN and WAN acceleration*/
	PPAenInfo.lan_rx_ppa_enable = 1;
	PPAenInfo.wan_rx_ppa_enable = 1;
	
	retval = fapi_sys_ppa_enable(&PPAenInfo);
        if (retval != UGW_SUCCESS) {
        	LOGF_LOG_DEBUG("Failed to disable PPA, exiting mirroring!!\n");
		return retval;
	}

	
	LOGF_LOG_DEBUG("Configured Port Mirroring on Port%d Successfully \n",MirroredPort);

	return retval;

}


