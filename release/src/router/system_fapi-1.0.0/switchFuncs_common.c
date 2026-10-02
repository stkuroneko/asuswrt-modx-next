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
 *  Function Name : SetLinkState					       *
 *  Description   : This is a function to set vlan config      *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t SetLinkState(IN int32_t PortId, IN char *LinkStatus)
{
	GSW_portLinkCfg_t PortLinkCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&PortLinkCfg, 0, sizeof(PortLinkCfg));

	/*to read switch port Duplex mode*/
 	PortLinkCfg.nPortId = PortId;

    switch_params = (void *)&PortLinkCfg;

    retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_GET, switch_params);
    if (retval != UGW_SUCCESS) {
                return retval;
    }
	/*to set switch port Link State*/
	PortLinkCfg.bLinkForce = 1;

	if (!strcmp(LinkStatus, "Enabled"))
		PortLinkCfg.eLink = GSW_PORT_LINK_UP;

	if (!strcmp(LinkStatus, "Disabled"))
		PortLinkCfg.eLink = GSW_PORT_LINK_DOWN;

	LOGF_LOG_DEBUG("configured Link State= %d \n", PortLinkCfg.eLink);

	switch_params = (void *)&PortLinkCfg;

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_SET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	LOGF_LOG_DEBUG("Set Link State on port %d SUCCESS!!\n", PortId);

	return retval;

}

/* ============================================================================*
 *  Function Name : GetLinkState                                    *
 *  Description   : This fapi is used to read switch port Link Status          *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    *
 * ============================================================================*/
int32_t GetLinkState(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	GSW_portLinkCfg_t PortLinkCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&PortLinkCfg, 0, sizeof(PortLinkCfg));
	PortLinkCfg.nPortId = PortId;

	switch_params = (void *)&PortLinkCfg;

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	port_get->eLink = PortLinkCfg.eLink;
	LOGF_LOG_DEBUG("Get Link Status: PortId=%d, Link State=%u\n", PortId, PortLinkCfg.eLink);

	return retval;
}

/* =============================================================================
 *  Function Name : RMONGet					       *
 *  Description   : This fapi is used read switch port RMON statistics	       *
 *  Input	  : PortId, 						       *
 *  Output	  : Port status is updated in structure RMONGet_t              *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t RMONGet(IN int32_t port, OUT RMONGet_t * RMONGet)
{
	GSW_RMON_Port_cnt_t ETHSW_RMONGet;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&ETHSW_RMONGet, 0, sizeof(ETHSW_RMONGet));

	ETHSW_RMONGet.nPortId = port;
	switch_params = (void *)&ETHSW_RMONGet;

	retval = fapicb.cfg_SwitchIOCTL(port, GSW_RMON_PORT_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	else {
		RMONGet->DropEvents = ETHSW_RMONGet.nTxAcmDroppedPkts;
		RMONGet->RxBytes = ETHSW_RMONGet.nRxGoodBytes + ETHSW_RMONGet.nRxBadBytes;
		RMONGet->TxBytes = ETHSW_RMONGet.nTxGoodBytes;
		RMONGet->RxPackets = ETHSW_RMONGet.nRxGoodPkts;
					//ETHSW_RMONGet.nRxGoodPausePkts +
					//ETHSW_RMONGet.nRxOversizeGoodPkts +
					//ETHSW_RMONGet.nRxUnderSizeGoodPkts;
		RMONGet->TxPackets = ETHSW_RMONGet.nTxGoodPkts;
		RMONGet->BroadcastPackets = ETHSW_RMONGet.nRxBroadcastPkts;
		RMONGet->MulticastPackets = ETHSW_RMONGet.nRxMulticastPkts;
		RMONGet->CRCErroredPackets = ETHSW_RMONGet.nRxFCSErrorPkts;
		RMONGet->UndersizePackets = ETHSW_RMONGet.nRxUnderSizeGoodPkts;
		RMONGet->OversizePackets = ETHSW_RMONGet.nRxOversizeGoodPkts;
		RMONGet->Packets64Bytes = ETHSW_RMONGet.nRx64BytePkts;
		RMONGet->Packets65to127Bytes = ETHSW_RMONGet.nRx127BytePkts;
		RMONGet->Packets128to255Bytes = ETHSW_RMONGet.nRx255BytePkts;
		RMONGet->Packets256to511Bytes = ETHSW_RMONGet.nRx511BytePkts;
		RMONGet->Packets512to1023Bytes = ETHSW_RMONGet.nRx1023BytePkts;
		RMONGet->Packets1024to1518Bytes = ETHSW_RMONGet.nRxMaxBytePkts;
		LOGF_LOG_DEBUG("FAPI RMON Get on port %d SUCCESS!!\n", port);
	}

	return retval;

	
}

/* ============================================================================*
 *  Function Name : SetDuplexMode                                    *
 *  Description   : This fapi is used to set Duplex Mode of switch Port        *
 *  Input	  : PortId, DuplexMode ("Full" or "Half" or "Auto")            *
 *  Output	  : none                                                       *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    * 
 * ============================================================================*/
int32_t SetDuplexMode(IN int32_t PortId, IN char *DuplexMode)
{
	GSW_portLinkCfg_t PortLinkCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&PortLinkCfg, 0, sizeof(PortLinkCfg));

	/*to read switch port Duplex mode*/
 	PortLinkCfg.nPortId = PortId;

    switch_params = (void *)&PortLinkCfg;

    retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_GET, switch_params);
    if (retval != UGW_SUCCESS) {
        return retval;
    }
	/*to set switch port Duplex mode*/
	PortLinkCfg.bDuplexForce = 1;

	if (!strcmp(DuplexMode, "Half"))
		PortLinkCfg.eDuplex = GSW_DUPLEX_HALF;

    if (!strcmp(DuplexMode, "Full"))
		PortLinkCfg.eDuplex = GSW_DUPLEX_FULL;

	/*--Auto mode is not supported in switch apis--*/
	if (!strcmp(DuplexMode, "Auto")) {
		LOGF_LOG_DEBUG("Auto Mode is not supported !!\n");
		return UGW_FAILURE;
	}
	LOGF_LOG_DEBUG("configured Duplex Mode= %d \n", PortLinkCfg.eDuplex);

	switch_params = (void *)&PortLinkCfg;

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_SET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	LOGF_LOG_DEBUG("FAPI Set DuplexMode on port %d SUCCESS!!\n", PortId);

	return retval;


}

/* ============================================================================*
 *  Function Name : GetDuplexMode                                    *
 *  Description   : This fapi is used to read switch port Duplex Mode          *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port status is updated in structure PORTcfg_t.             *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    *
 * ============================================================================*/
int32_t GetDuplexMode(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	GSW_portLinkCfg_t PortLinkCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&PortLinkCfg, 0, sizeof(PortLinkCfg));
	PortLinkCfg.nPortId = PortId;

	switch_params = (void *)&PortLinkCfg;

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	port_get->DuplexForce = PortLinkCfg.eDuplex;
	LOGF_LOG_DEBUG("Fapi GetDuplexMode: PortId=%d, DuplexMode=%u\n", PortId, PortLinkCfg.eDuplex);

	return retval;

}

/* ==========================================================================*
 *  Function Name : SetMaxBitRate                                     *
 *  Description   : This fapi is used to set port link speed on switch        *
 *  Input	  : PortId, MaxBitRate (10Mbps,100Mps or 1000Mbps)            *
 *  Output	  : none                                                      *    
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                   *
 * ===========================================================================*/
int32_t SetMaxBitRate(IN int32_t PortId, IN int32_t MaxBitRate)
{
	GSW_portLinkCfg_t PortLinkCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&PortLinkCfg, 0, sizeof(PortLinkCfg));

	/*to read switch port link speed*/
 	PortLinkCfg.nPortId = PortId;

    switch_params = (void *)&PortLinkCfg;

    retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_GET, switch_params);
    if (retval != UGW_SUCCESS) {
        return retval;
    }
	/*to set switch port link speed*/
	PortLinkCfg.bSpeedForce = 1;

	if (MaxBitRate == 10)
		PortLinkCfg.eSpeed = GSW_PORT_SPEED_10;

	else if (MaxBitRate == 100)
		PortLinkCfg.eSpeed = GSW_PORT_SPEED_100;

	else if (MaxBitRate == 1000)
		PortLinkCfg.eSpeed = GSW_PORT_SPEED_1000;

	switch_params = (void *)&PortLinkCfg;

	LOGF_LOG_DEBUG("configured port bitrate=%d\n", PortLinkCfg.eSpeed);

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_SET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	LOGF_LOG_DEBUG("FAPI Set LinkRate on port %d SUCCESS!!\n", PortId);

	return retval;

}


/* ============================================================================*
 *  Function Name : GetMaxBitRate                                       *
 *  Description   : This fapi is used to read switch port link speed           *
 *  Input	  : PortId to be read                                          *
 *  Output	  : Port link speed is updated in structure PORTcfg_t.         *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                    *
 * ============================================================================*/
int32_t GetMaxBitRate(IN int32_t PortId, OUT PORTcfg_t * port_get)
{
	GSW_portLinkCfg_t PortLinkCfg;
	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	LOGF_LOG_DEBUG("PortId = %d ; Speed = %d\n",PortId,port_get->eSpeed);
	memset(&PortLinkCfg, 0, sizeof(PortLinkCfg));
	PortLinkCfg.nPortId = PortId;

	switch_params = (void *)&PortLinkCfg;

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_LINK_CFG_GET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}

	port_get->eSpeed = PortLinkCfg.eSpeed;
	LOGF_LOG_DEBUG("Fapi Get Bit rate: PortId=%d, BitRate=%d\n", PortId, PortLinkCfg.eSpeed);

	return retval;
}

/* ============================================================================*
 *  Function Name : SetPortStatus                                       *
 *  Description   : This fapi is used to enable or disable switch port         *
 *  Input	  : PortId, Port Status                                        *
 *  Output	  :                                                            *
 *  return value  : UGW_SUCCESS or UGW_FAILURE                                 *
 * ============================================================================*/
int32_t SetPortStatus(IN int32_t PortId, IN int32_t PortEna)
{
	GSW_portCfg_t PortCfg;

	void *switch_params = NULL;
	int32_t retval = UGW_SUCCESS;

	memset(&PortCfg, 0, sizeof(PortCfg));
	/*to read switch port status*/
        PortCfg.nPortId = PortId;
        switch_params = (void *)&PortCfg;

        retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_CFG_GET, switch_params);
        if (retval != UGW_SUCCESS){ 
                return retval;
        }
	/*to set switch port status*/	
	if (PortEna == 0)
		PortCfg.eEnable = GSW_PORT_DISABLE;
	else if (PortEna == 1)
		PortCfg.eEnable = GSW_PORT_ENABLE_RXTX;

	LOGF_LOG_DEBUG("configured port status=%d\n", PortCfg.eEnable);

	switch_params = (void *)&PortCfg;

	retval = fapicb.cfg_SwitchIOCTL(PortId, GSW_PORT_CFG_SET, switch_params);
	if (retval != UGW_SUCCESS) {
		return retval;
	}
	LOGF_LOG_DEBUG("FAPI Set Port Enable/Disable on port %d SUCCESS!!\n", PortId);

	return retval;


}

