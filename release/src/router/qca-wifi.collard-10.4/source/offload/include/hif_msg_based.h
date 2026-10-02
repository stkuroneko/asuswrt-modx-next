//------------------------------------------------------------------------------
// <copyright file="hif.h" company="Atheros">
//    Copyright (c) 2010 Atheros Corporation.  All rights reserved.
// $ATH_LICENSE_HOSTSDK0_C$
//------------------------------------------------------------------------------
//==============================================================================
// HIF definitions for message based HIFs
//
// Author(s): ="Atheros"
//==============================================================================
/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef _HIF_MSG_BASED_H_
#define _HIF_MSG_BASED_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "hif.h"
#include <wbuf.h>

/**
 * @brief List of callbacks - filled in by HTC.
 */
typedef struct  {
    void *Context;  /**< context meaningful to HTC */
    A_STATUS (* txCompletionHandler)(void *Context, wbuf_t wbuf, unsigned transferID);
    A_STATUS (* rxCompletionHandler)(void *Context, wbuf_t wbuf, u_int8_t pipeID);
    void     (* txResourceAvailHandler)(void *context, u_int8_t pipe);
    void     (* fwEventHandler)(void *context);
} MSG_BASED_HIF_CALLBACKS;



int HIF_deregister(void);

/**
 * @brief: This API is used by the HTC layer to initialize the HIF layer and to
 * register different callback routines. Support for following events has
 * been captured - DSR, Read/Write completion, Device insertion/removal,
 * Device suspension/resumption/wakeup. In addition to this, the API is
 * also used to register the name and the revision of the chip. The latter
 * can be used to verify the revision of the chip read from the device
 * before reporting it to HTC.
 * @param[in]: callbacks - List of HTC callbacks
 * @param[out]:
 * @return: an opaque HIF handle
 */
//void *HIFInit(void *hHTC, HTC_CALLBACKS *callbacks);

void HIFPostInit(HIF_DEVICE *hifDevice, void *hHTC, MSG_BASED_HIF_CALLBACKS *callbacks);

void HIFRegisterPipeCallbacks(HIF_DEVICE *hifDevice, u_int8_t PipeID, MSG_BASED_HIF_CALLBACKS *callbacks);

void HIFStart(HIF_DEVICE *hifDevice);

void HIFStop(HIF_DEVICE *hifDevice);
void HIFPause(HIF_DEVICE *hifDevice);

/**
 * @brief: Send a buffer to HIF for transmission to the target.
 * @param[in]: hifDevice - HIF handle
 * @param[in]: pipeID - pipe to use
 * @param[in]: hdr_buf - unused
 * @param[in]: buf - buffer to send
 * @param[out]:
 * @return: Status of the send operation.
 */
int HIFSend(HIF_DEVICE *hifDevice, u_int8_t PipeID, wbuf_t hdr_buf, wbuf_t wbuf);

/**
 * @brief: Send the head of a buffer to HIF for transmission to the target.
 * @param[in]: hifDevice - HIF handle
 * @param[in]: pipeID - pipe to use
 * @param[in]: transferID - upper-layer ID for this transfer, used in the
 *             send completion callback to identify the transfer
 * @param[in]: nbytes - number of initial bytes to send
 * @param[in]: buf - buffer to send
 * @param[out]:
 * @return: Status of the send operation.
 */
int HIFSend_head(HIF_DEVICE *hifDevice, u_int8_t PipeID, unsigned int transferID, unsigned int nbytes, wbuf_t wbuf);

#if QCA_OL_11AC_FAST_PATH
/**
 * @brief: Decrements the pipe based credit info (num_sends_allowed) 
 *         Only used in the fast path for OL mode.
 * @param[in]: hif_device - HIF handle
 * @param[in]: pipe - pipe ID to use
 * @param[out]:
 * @return: void
 */
void
HIF_update_pipe_info(HIF_DEVICE *hif_device,
             a_uint8_t pipe, uint32_t num_frags);
#endif /* QCA_OL_11AC_FAST_PATH */


/**
 * @brief: Check if prior sends have completed.
 * @details:
 *  Check whether the pipe in question has any completed sends that have
 *  not yet been processed.
 *  This function is only relevant for HIF pipes that are configured to be
 *  polled rather than interrupt-driven.
 *
 * @param[in]: hifDevice - HIF handle
 * @param[in]: pipeID - pipe used for the prior sends
 * @param[in]: force - whether this is a poll suggestion or poll command
 */
void HIFSendCompleteCheck(HIF_DEVICE *hifDevice, u_int8_t PipeID, int force);

/**
 * @brief: Shutdown the HIF layer.
 * @param[in]: HIFHandle - opaque HIF handle.
 * @param[out]:
 * @return:
 */
void HIFShutDown(HIF_DEVICE *hifDevice);

u_int32_t HIFQueryQueueDepth(HIF_DEVICE *hifDevice, u_int8_t epnum);

void HIFGetDefaultPipe(HIF_DEVICE *hifDevice, u_int8_t *ULPipe, u_int8_t *DLPipe);

int HIFMapServiceToPipe(HIF_DEVICE *hifDevice, u_int16_t ServiceId, u_int8_t *ULPipe, u_int8_t *DLPipe, int *ul_is_polled, int *dl_is_polled);

u_int8_t HIFGetULPipeNum(void);
u_int8_t HIFGetDLPipeNum(void);

//a_status_t HIFGetProductInfo(HIF_DEVICE *hifDevice, adf_net_dev_product_info_t *info);

u_int16_t HIFGetFreeQueueNumber(HIF_DEVICE *hifDevice, u_int8_t PipeID);
u_int16_t HIFGetMaxQueueNumber(HIF_DEVICE *hifDevice, u_int8_t PipeID);

void HIFDumpInfo(HIF_DEVICE *hifDevice);
#ifdef __cplusplus
}
#endif

#endif /* _HIF_H_ */
