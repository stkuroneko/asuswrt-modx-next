/*****************************************************************************
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_ipc.h                                    *
 *         Description  :  This file contains all the data declarations that are
			   shared across the modules                      *  
 *  *****************************************************************************/

#include <string.h>
#include <unistd.h>
#include "scapi_basic_types.h"
#include "scapi_fifo.h"

/* 
** =============================================================================
**   Function Name    : UGW_IPC_SendMsg 
**   Description      : To send message in IPC 
**   Return Value     : Success -> UGW_IPC_SUCCESS 
**                      Failure -> UGW_IPC_FAIL
** ===========================================================================*/


char8 UGW_IPC_SendMsg(IN int32 iFd,	/* FIFO fd */
				IN uchar8 ucFrom,	/* Module Id of the addressee */
				IN uchar8 ucTo,	/* Module Id of the addressed */
				IN uint16 unMsgSize,	/* Size of message */
				IN uint32 uiReserved, IN char8 * pcMsg)
{				/* Pointer to message */
	x_UGW_IPC_Msg xMsg;
	memset(&xMsg, 0, sizeof(x_UGW_IPC_Msg));

	if (unMsgSize > UGW_IPC_MAX_MSG_SIZE)
		return UGW_IPC_FAIL;

	xMsg.xHdr.ucFrom = ucFrom;
	xMsg.xHdr.ucTo = ucTo;
	xMsg.xHdr.unMsgSize = unMsgSize;
	xMsg.xHdr.uiReserved = uiReserved;

	memcpy(xMsg.acMsg, pcMsg, unMsgSize);

	if (UGW_OS_WriteFifo(iFd, (char8 *) & xMsg,
			     unMsgSize + UGW_IPC_HDR_SIZE) < 0) {
		/* Error Writing Message to the FIFO */
		/* Add Debugs if required */
		return UGW_IPC_FAIL;
	}

	return UGW_IPC_SUCCESS;
}

/* 
** =============================================================================
**   Function Name    : UGW_IPC_RecvMsg 
**   Description      : To receive  message in IPC 
**   Return Value     : Success -> UGW_IPC_SUCCESS 
**                      Failure -> UGW_IPC_FAIL
** ===========================================================================*/

char8
UGW_IPC_RecvMsg(IN int32 iFd,
		OUT uchar8 * pucFrom,
		OUT uchar8 * pucTo,
		OUT uint16 * punMsgSize,
		OUT uint32 * puiReserved, OUT char8 * pcMsg, OUT char8 * pErr)
{
	x_UGW_IPC_MsgHdr xHdr;
	int16 nBytes = 0;

	if ((nBytes = UGW_OS_ReadFifo(iFd, (char8 *) & xHdr,
				      sizeof(x_UGW_IPC_MsgHdr))) < 0) {
		/* Error Reading Header */
		/* Add Debugs if required */
		*pErr = UGW_IPC_FIFO_READ_ERR;
		return UGW_IPC_FAIL;
	}
	if (nBytes != sizeof(x_UGW_IPC_MsgHdr)) {
		return UGW_IPC_FAIL;
	} else {
		*pucFrom = xHdr.ucFrom;
		*pucTo = xHdr.ucTo;
		*punMsgSize = xHdr.unMsgSize;
		*puiReserved = xHdr.uiReserved;
	}
	if(*punMsgSize <= 0)
		return UGW_IPC_FAIL;

	if ((nBytes = UGW_OS_ReadFifo(iFd, pcMsg, *punMsgSize)) < 0) {
		/* Error Reading Header */
		/* Add Debugs if required */
		*pErr = UGW_IPC_HDR_ERR;
		return UGW_IPC_FAIL;
	}
	pcMsg[*punMsgSize] = '\0';
	return UGW_IPC_SUCCESS;
}
