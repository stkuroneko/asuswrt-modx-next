/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef HTC_DEBUG_H_
#define HTC_DEBUG_H_

#define ATH_MODULE_NAME htc
#include "a_debug.h"

/* ------- Debug related stuff ------- */

#define  ATH_DEBUG_SEND ATH_DEBUG_MAKE_MODULE_MASK(0)
#define  ATH_DEBUG_RECV ATH_DEBUG_MAKE_MODULE_MASK(1)
#define  ATH_DEBUG_SYNC ATH_DEBUG_MAKE_MODULE_MASK(2)
#define  ATH_DEBUG_DUMP ATH_DEBUG_MAKE_MODULE_MASK(3)
#define  ATH_DEBUG_SETUP  ATH_DEBUG_MAKE_MODULE_MASK(4)


#endif /*HTC_DEBUG_H_*/
