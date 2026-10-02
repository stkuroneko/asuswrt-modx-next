/*
 * Copyright (c) 2013 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */


#ifndef HOSTDEFS_H_
#define HOSTDEFS_H_

//#include <a_config.h>
#include <a_osapi.h>
#include <athdefs.h>
#include <a_types.h>
#include "host_reg_table.h"

extern struct hostdef_s *AR6002_HOSTdef;
extern struct hostdef_s *AR6003_HOSTdef;
extern struct hostdef_s *AR6004_HOSTdef;
extern struct hostdef_s *AR9888_HOSTdef;
extern struct hostdef_s *AR9888V2_HOSTdef;
extern struct hostdef_s *AR6320_HOSTdef;
extern struct hostdef_s *AR900B_HOSTdef;
extern struct hostdef_s *QCA9984_HOSTdef;
extern struct hostdef_s *QCA9888_HOSTdef;
#ifdef ATH_AHB
extern struct hostdef_s *IPQ4019_HOSTdef;
#endif

#endif
