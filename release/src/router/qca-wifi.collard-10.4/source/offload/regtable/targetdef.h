/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */

#ifndef TARGETDEFS_H_
#define TARGETDEFS_H_

//#include <a_config.h>
#include <a_osapi.h>
#include <athdefs.h>
#include <a_types.h>
#include "target_reg_table.h"

extern struct targetdef_s *AR6002_TARGETdef;
extern struct targetdef_s *AR6003_TARGETdef;
extern struct targetdef_s *AR6004_TARGETdef;
extern struct targetdef_s *AR9888_TARGETdef;
extern struct targetdef_s *AR9888V2_TARGETdef;
extern struct targetdef_s *AR6320_TARGETdef;
extern struct targetdef_s *AR900B_TARGETdef;
extern struct targetdef_s *QCA9984_TARGETdef;
extern struct targetdef_s *QCA9888_TARGETdef;
#ifdef ATH_AHB
extern struct targetdef_s *IPQ4019_TARGETdef;
#endif

#endif
