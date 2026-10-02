/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#if defined(AR6320_HEADERS_DEF)
#define AR6320 1

#define WLAN_HEADERS 1
#include "common_drv.h"
#include "AR6320/hw/apb_map.h"
#include "AR6320/hw/gpio_reg.h"
#include "AR6320/hw/rtc_reg.h"
#include "AR6320/extra/hw/si_reg.h"
#include "AR6320/hw/mbox_reg.h"
#include "AR6320/extra/hw/ce_reg_csr.h"
#include "AR6320/hw/mbox_wlan_host_reg.h"
#include "soc_addrs.h"
#include "AR6320/extra/hw/soc_core_reg.h"
#include "AR6320/hw/pcie_local_reg.h"
#include "AR6320/hw/soc_pcie_reg.h"

#ifndef SYSTEM_SLEEP_OFFSET
#define SYSTEM_SLEEP_OFFSET     SOC_SYSTEM_SLEEP_OFFSET
#endif
#ifndef WLAN_SYSTEM_SLEEP_OFFSET
#define WLAN_SYSTEM_SLEEP_OFFSET                SOC_SYSTEM_SLEEP_OFFSET
#endif
#ifndef WLAN_RESET_CONTROL_OFFSET
#define WLAN_RESET_CONTROL_OFFSET               SOC_RESET_CONTROL_OFFSET
#endif
#ifndef RESET_CONTROL_SI0_RST_MASK
#define RESET_CONTROL_SI0_RST_MASK              SOC_RESET_CONTROL_SI0_RST_MASK
#endif
#ifndef SI_BASE_ADDRESS
#define SI_BASE_ADDRESS WLAN_SI_BASE_ADDRESS
#endif
#ifndef PCIE_LOCAL_BASE_ADDRESS
/* TBDXXX: Eventually, this Base Address will be defined in HW header files */
#define PCIE_LOCAL_BASE_ADDRESS 0x80000
#endif
#ifndef RTC_STATE_V_ON
#define RTC_STATE_V_ON 3 // FIXME: Rome. This should be defined by HW
#endif

#define MY_TARGET_DEF AR6320_TARGETdef
#define MY_HOST_DEF AR6320_HOSTdef
#define MY_TARGET_BOARD_DATA_SZ AR6320_BOARD_DATA_SZ
#define MY_TARGET_BOARD_EXT_DATA_SZ AR6320_BOARD_EXT_DATA_SZ
#define DRAM_BASE_ADDRESS TARG_DRAM_START
#include "targetdef.h"
#include "hostdef.h"
#else
#include "common_drv.h"
#include "targetdef.h"
#include "hostdef.h"
struct targetdef_s *AR6320_TARGETdef=NULL;
struct hostdef_s *AR6320_HOSTdef=NULL;
#endif /*AR6320_HEADERS_DEF */
