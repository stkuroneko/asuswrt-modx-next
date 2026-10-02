/******************************************************************************

                         Copyright (c) 2015
                        Lantiq Beteiligungs-GmbH & Co. KG

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/*  ***************************************************************************** 
 *         File Name    : fapi_upg.h                                            *
 *         Description  : Contains firmware upgrade FAPI prototypes and		*
 *			  related macros definitions.				*
 *                                                                              *
 *  *****************************************************************************/

#include "image.h"
#include <crc32.h>

#define SCAPI_BLOCK 1

/*!
    \brief This macro defined maximum length of buffer read from image at a time.
*/
#define TEMP_BUF		4096
/*!
    \brief This macro denotes image type is kernel.
*/
#define IH_TYPE_KERNEL		2
/*!
    \brief This macro denotes image type is DSL firmware.
*/
#define IH_TYPE_FIRMWARE	5
/*!
    \brief This macro defines image magic number.
*/
#define IH_MAGIC		0x27051956
/*!
    \brief This macro defines length of image name in header.
*/
#define IH_NMLEN		32
/*!
    \brief This macro defines length of version in header.
*/
#define VERSIONLEN     		16
/*!
    \brief Path of upgrade utility.
*/
#define UPG_UTIL		"/usr/sbin/upgrade"
/*!
    \brief Path of image version file.
*/
#define IMG_VER_FILE		"/etc/version"
/*!
    \brief Path of image timestamp file.
*/
#define IMG_TS_FILE		"/etc/timestamp"
/*!
    \brief This macro denotes maximum file line length.
*/
#define MAX_FILELINE_LEN	332
