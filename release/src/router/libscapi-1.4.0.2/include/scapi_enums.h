/********************************************************************************

  Copyright (c) 2014
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 
  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    : scapi_enums.h                                         
 *         Description  : This file defines all the enums used in scapi
 *                                                                              
 *  *****************************************************************************/


/*! \file scapi_enums.h
  \brief This file defines the enumerations used in scapi
  */

#ifndef _SCAPI_ENUMS_H
#define _SCAPI_ENUMS_H

typedef enum
{
	MAC_GET,
	SERNUM_GET,
	MAC_SET
}UPGRADE_OPT;

/* Unnamed enum for RMMOD */
enum
{
	NONE  = 0,
	FORCE = (1 << 0)
};

typedef enum
{
	FREQ_NONE,
	FREQ_AUTO,
	FREQ_FIXED
}FREQ_OPT_ARG;

typedef enum
{
	BR_NONE,
	BR_AUTO,
	BR_FIXED,
	BR_UNICAST,
	BR_BROADCAST
}BITRATE_OPT_ARG;

typedef enum
{
	POW_NONE,
	POW_ALL,
	POW_UNICAST,
	POW_MULTICAST,
	POW_FORCE,
	POW_REPEAT
}POW_OPT;


typedef enum
{
	TXPOW_NONE,
	TXPOW_AUTO,
	TXPOW_FIXED
}TXPOW_OPT;


typedef enum
{
	MOD_NONE,
	MOD_AUTO,
	MOD_FIXED
}MOD_OPT;


enum {

	OPTION_STDOUT     = 1 << 0, /*!< when option is "c" */ 
	OPTION_FORCE      = 1 << 1, /*!< when option is "f" */
	OPTION_VERBOSE    = 1 << 2, /*!< when option is "v" this is not used */
	OPTION_DECOMPRESS = 1 << 3, /*!< when option is "d" */
	OPTION_TEST       = 1 << 4 /*!< when option is "t" */
};

enum {
	WIN_SIZE = 2 * SIZE_WINDOW,
	MAX_CHAIN_LEN = 4096,
	MAX_MATCH_LAZY = 258,
	MAX_INSERT_LEN = MAX_MATCH_LAZY,
	MATCH_GOOD = 32, /*!< used to speeden up the process */
	MATCH_NICE = 258 /*!< When current match exceeds this should stop */
};

enum {
	GUNZIP_WINSIZE = 0x8000,
	MAX_BIT_LEN = 16,  /*!< Code maximum bit length */
	MAX_NUM_CODE = 288    /*!< number of maximum codes */
};

/* \brief ControlD operation to be performed
*/
typedef enum { DAEMON_ADD ,DAEMON_START,DAEMON_STOP, DAEMON_DELETE, DAEMON_SHOW } eControlDOption_t;

/* \brief ControlD Respawn option
*/
typedef enum {
RESPAWN_OFF  ,   /*!< Respawn not required */         
RESPAWN_ON_EXIT,              
RESPAWN_WITH_WATCHDOG    /*!< default respawn true and watch dog */ 
}
eDaemonRespawn_t;

#endif				// _SCAPI_ENUMS_H

