/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


#if defined(AR6004_HEADERS_DEF)
#define AR6004 1

#define WLAN_HEADERS 1
#include "common_drv.h"
#include "AR6004/hw/apb_map.h"
#include "AR6004/hw/gpio_reg.h"
#include "AR6004/hw/rtc_reg.h"
#include "AR6004/hw/si_reg.h"
#include "AR6004/hw/mbox_reg.h"
#include "AR6004/hw/mbox_wlan_host_reg.h"

#define SYSTEM_SLEEP_OFFSET     SOC_SYSTEM_SLEEP_OFFSET
#define SCRATCH_BASE_ADDRESS    MBOX_BASE_ADDRESS

#define MY_TARGET_DEF AR6004_TARGETdef
#define MY_HOST_DEF AR6004_HOSTdef
#define MY_TARGET_BOARD_DATA_SZ AR6004_BOARD_DATA_SZ
#define MY_TARGET_BOARD_EXT_DATA_SZ AR6004_BOARD_EXT_DATA_SZ
#include "targetdef.h"
#include "hostdef.h"
#else
#include "common_drv.h"
#include "targetdef.h"
#include "hostdef.h"
struct targetdef_s *AR6004_TARGETdef=NULL;
struct hostdef_s *AR6004_HOSTdef=NULL;
#endif /*AR6004_HEADERS_DEF */
