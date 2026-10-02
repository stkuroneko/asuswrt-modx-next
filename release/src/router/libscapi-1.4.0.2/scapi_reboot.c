/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapi_reboot.c                                             *
 *     Project    : UGW                                                        *
 *     Description: API for clean reboot of the system                         *
 *                                                                             *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include <ltq_api_include.h>

int scapi_reboot()
{
	sync();
	sleep(1);
	/* This sends SIGTERM to all the Child Proceses first */
	kill(1, SIGTERM);
	return 0;
}
