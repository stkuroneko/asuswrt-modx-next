/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


#ifdef WIN_MOBILE7
#include <ntddk.h>
#endif

#include "common_drv.h"
#include "a_debug.h"
#include "bmi_msg.h"

#include "targetdef.h"
#include "hostdef.h"
#include "hif.h"

/* Sanity check to make sure at least one chip header type is defined */
#undef SOME_HEADERS_DEFINED
#if !defined(SOME_HEADERS_DEFINED) && defined(AR6002_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(AR6003_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(AR6004_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(AR9888_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(AR9888V2_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(AR6320_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(AR900B_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(QCA9984_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(QCA9888_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED) && defined(IPQ4019_HEADERS_DEF)
#define SOME_HEADERS_DEFINED
#endif
#if !defined(SOME_HEADERS_DEFINED)
#error "You must define at least one HEADERS macro to support at least one chip"
#endif

/* Target-dependent addresses and definitions */
//struct targetdef_s *targetdef;
/* HIF-dependent addresses and definitions */
struct hostdef_s *ath_hostdef;

struct targetdef_s* target_register_tbl_attach(A_UINT32 target_type)
{
    struct targetdef_s *targetdef = NULL;

    switch (target_type) {
#if defined(AR6002_HEADERS_DEF)
    case TARGET_TYPE_AR6002:
        targetdef = AR6002_TARGETdef;
        break;
#endif
#if defined(AR6003_HEADERS_DEF)
    case TARGET_TYPE_AR6003:
        targetdef = AR6003_TARGETdef;
        break;
#endif
#if defined(AR6004_HEADERS_DEF)
    case TARGET_TYPE_AR6004:
        targetdef = AR6004_TARGETdef;
        break;
#endif
#if defined(AR9888_HEADERS_DEF)
    case TARGET_TYPE_AR9888:
        targetdef = AR9888_TARGETdef;
        break;
#endif
#if defined(AR9888V2_HEADERS_DEF)
    case TARGET_TYPE_AR9888V2:
        targetdef = AR9888V2_TARGETdef;
        break;
#endif
#if defined(AR6320_HEADERS_DEF)
    case TARGET_TYPE_AR6320:
        targetdef = AR6320_TARGETdef;
        break;
#endif
#if defined(AR900B_HEADERS_DEF)
    case TARGET_TYPE_AR900B:
        targetdef = AR900B_TARGETdef;
        break;
#endif
#if defined(QCA9984_HEADERS_DEF)
    case TARGET_TYPE_QCA9984:
        targetdef = QCA9984_TARGETdef;
        break;
#endif
#if defined(QCA9888_HEADERS_DEF)
    case TARGET_TYPE_QCA9888:
        targetdef = QCA9888_TARGETdef;
        break;
#endif
#ifdef ATH_AHB
#if defined(IPQ4019_HEADERS_DEF)
    case TARGET_TYPE_IPQ4019:
        targetdef = IPQ4019_TARGETdef;
        break;
#endif
#endif
    default:
        break;
    }
    A_ASSERT(targetdef != NULL);

    return targetdef;
}

void hif_register_tbl_attach(A_UINT32 hif_type)
{
    switch (hif_type) {
#if defined(AR6002_HEADERS_DEF)
    case HIF_TYPE_AR6002:
        ath_hostdef = AR6002_HOSTdef;
        break;
#endif
#if defined(AR6003_HEADERS_DEF)
    case HIF_TYPE_AR6003:
        ath_hostdef = AR6003_HOSTdef;
        break;
#endif
#if defined(AR6004_HEADERS_DEF)
    case HIF_TYPE_AR6004:
        ath_hostdef = AR6004_HOSTdef;
        break;
#endif
#if defined(AR9888_HEADERS_DEF)
    case HIF_TYPE_AR9888:
        ath_hostdef = AR9888_HOSTdef;
        break;
#endif
#if defined(AR9888V2_HEADERS_DEF)
    case HIF_TYPE_AR9888V2:
        ath_hostdef = AR9888V2_HOSTdef;
        break;
#endif
#if defined(AR6320_HEADERS_DEF)
    case HIF_TYPE_AR6320:
        ath_hostdef = AR6320_HOSTdef;
        break;
#endif
#if defined(AR900B_HEADERS_DEF)
    case HIF_TYPE_AR900B:
        ath_hostdef = AR900B_HOSTdef;
        break;
#endif
#if defined(QCA9984_HEADERS_DEF)
    case HIF_TYPE_QCA9984:
        ath_hostdef = QCA9984_HOSTdef;
        break;
#endif
#if defined(QCA9888_HEADERS_DEF)
    case HIF_TYPE_QCA9888:
        ath_hostdef = QCA9888_HOSTdef;
        break;
#endif

#ifdef ATH_AHB
#if defined(IPQ4019_HEADERS_DEF)
    case HIF_TYPE_IPQ4019:
        ath_hostdef = IPQ4019_HOSTdef;
        break;
#endif
#endif
    default:
        break;
    }
    A_ASSERT(ath_hostdef != NULL);
}

#ifdef __linux__
//EXPORT_SYMBOL(targetdef);
EXPORT_SYMBOL(ath_hostdef);
EXPORT_SYMBOL(hif_register_tbl_attach);
EXPORT_SYMBOL(target_register_tbl_attach);
#endif
