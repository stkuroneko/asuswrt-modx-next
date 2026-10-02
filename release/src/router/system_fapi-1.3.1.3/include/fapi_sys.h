/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/*! \file fapi_sys.h
    \brief This file contains the prototype definitions used in fapi_sys.c 
*/
#include <stdbool.h>
#ifndef BUILD_FROM_PPA_ADAPT
#define BUILD_FROM_PPA_ADAPT
#undef CONFIG_IFX_PMCU
#include <net/ppa_api.h>
#endif

#define DEFAULT_MODULES_DIR "/lib/modules/*/"
int PPA_IOCTL(int ioctl_cmd, void *data);
