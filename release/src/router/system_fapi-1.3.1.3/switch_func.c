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
#include "fapi_eth.h"
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


int32_t fapi_ethlogset(int16_t sl_logl, int16_t sl_logt)
{
	int32_t ret=UGW_SUCCESS;
	LOGLEVEL = sl_logl;
	LOGTYPE = sl_logt;
	LOGF_LOG_INFO("new loglevel = %d ; new logtype = %d \n",LOGLEVEL,LOGTYPE);	
	return ret;
}
/* ============================================================================*
 *  Function Name : fapi_port_SetLinkState                                     *
 *  Description   : This fapi is used to set link state of switch Port         *
 *                  allowed values are "Enabled" or "Disabled"                 *
 *  Input	  : PortId, Link state("Enabled" or "Disabled")                *
 *  Output	  : none                                                       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 * 
 * ============================================================================*/
int32_t fapi_port_setLinkState(IN int32_t PortId, IN char * LinkStatus)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.SetLinkState(PortId, LinkStatus);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Set Link Cfg failed! \n");
	}

	return retval;


}

/* ============================================================================*
 *  Function Name : fapi_port_getLinkState                                     *
 *  Description   : This fapi is used to read switch port Link Status          *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t fapi_port_getLinkState(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.GetLinkState(PortId, port_get);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Get Link Cfg failed! \n");
	}

	return retval;

}

/* =============================================================================
 *  Function Name : fapi_vlan_config					       *
 *  Description   : This is fapi is used to set vlan config in switch          *
 *  Input	  : vlan and FID to be configured in vlan_cfg struct           *
 *  Output	  :						               *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t fapi_vlan_config(IN vlanCfg_t * vlanCfg)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.VLANCfgSet(vlanCfg);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI VLAN CONFIG failed! \n");
	}

	return retval;
}


/* =============================================================================
 *  Function Name : fapi_rmon_get					       *
 *  Description   : This fapi is used read switch port RMON statistics	       *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t fapi_rmon_get(IN int32_t port, OUT RMONGet_t * RMONGet)
{

	int32_t retval = UGW_SUCCESS;

	retval = fapicb.RMONGet(port,RMONGet);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI RMON Get failed! \n");
	}

	return retval;
}
/* ============================================================================*
 *  Function Name : fapi_port_setDuplexMode                                    *
 *  Description   : This fapi is used to set Duplex Mode of switch Port        *
 *  Input	  : PortId, DuplexMode ("Full" or "Half" or "Auto")            *
 *  Output	  : none                                                       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 * 
 * ============================================================================*/
int32_t fapi_port_setDuplexMode(IN int32_t PortId, IN char *DuplexMode)
{
	int32_t retval = UGW_SUCCESS;
	
	retval = fapicb.setDuplexMode(PortId, DuplexMode);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Set Duplex Mode failed! \n");
	}
	
	return retval;
}
/* ============================================================================*
 *  Function Name : fapi_port_getDuplexMode                                    *
 *  Description   : This fapi is used to read switch port Duplex Mode          *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t fapi_port_getDuplexMode(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.getDuplexMode(PortId, port_get);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Get Duplex Mode failed! \n");
	}

	return retval;


}
/* ===========================================================================*
 *  Function Name : fapi_port_setbitrate                                      *
 *  Description   : This fapi is used to set port link speed on switch        *
 *  Input	  : PortId, MaxBitRate (10Mbps,100Mps or 1000Mbps)            *
 *  Output	  : none                                                      *    
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                *
 * ===========================================================================*/
int32_t fapi_port_setbitrate(IN int32_t PortId, IN int32_t MaxBitRate)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.setMaxRate(PortId, MaxBitRate);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Set Max Bitrate failed! \n");
	}

	return retval;

}

/* ============================================================================*
 *  Function Name : fapi_port_getbitrate                                       *
 *  Description   : This fapi is used to read switch port link speed           *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port link speed is updated in structure PORTcfg_t.         *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t fapi_port_getbitrate(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	int32_t retval = UGW_SUCCESS;

	LOGF_LOG_DEBUG("PortId = %d ; Speed = %d\n",PortId,port_get->eSpeed);
	retval = fapicb.getMaxRate(PortId, port_get);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Get MaxBitRate failed! \n");
	}

	return retval;
}



/* ============================================================================*
 *  Function Name : fapi_port_setstatus                                        *
 *  Description   : This fapi is used to enable or disable switch port         *
 *  Input	  : PortId, Port Status                                        *
 *  Output	  :                                                            *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t fapi_port_setstatus(IN int32_t PortId, IN int32_t PortEna)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.setPortStatus(PortId, PortEna);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Set Port Status failed! \n");
	}

	return retval;

}


/* =========================================================================== *
 *  Function Name : fapi_port_getstatus                                        * 
 *  Description   : This fapi is used to read switch port status.              *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ===========================================================================*/
int32_t fapi_port_getstatus(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.getPortStatus(PortId, port_get);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI get state failed! \n");
	}

	return retval;

}

/* =========================================================================== *
 *  Function Name : fapi_EnablePortMirror                                      * 
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
int32_t fapi_EnablePortMirror(IN char * DownstreamIntf ,IN char * MirrorIntf)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.EnMirror(DownstreamIntf, MirrorIntf);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Enable Port Mirroring failed! \n");
	}

	return retval;
}


/* =========================================================================== *
 *  Function Name : fapi_DisablePortMirror                                     * 
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
int32_t fapi_DisablePortMirror(IN char * DownstreamIntf, IN char * MirrorIntf)
{
	int32_t retval = UGW_SUCCESS;

	retval = fapicb.disMirror(DownstreamIntf, MirrorIntf);
	if ( retval != UGW_SUCCESS) {
		LOGF_LOG_DEBUG("FAPI Diable Port Mirroring failed! \n");
	}

	return retval;

}


