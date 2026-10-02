/*
**	encrypt_main.h
**
**
**
*/
#ifndef __ENCRYPT_MAINH__
#define __ENCRYPT_MAINH__
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
//#include <adv_string.h>
#include <adv_misc.h>
//#include <adv_debug.h>
//#include <adv_verify.h>
//#include <Debug-Int.h>
#include "encrypt.h"

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

////////////////////////////////////////////////////////////////////////////////
//
// Debug Message 	
//
////////////////////////////////////////////////////////////////////////////////

#define CFG_DBG_LOG	CFG_MNT_FOLDER"cfg_dbg.log"

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"cfg_mnt.log"
#define AVBL_DBG_LOG	"cfg_abl.log"

#define DBG_ERR(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_ABL(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_abl"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	asusdebuglog(LOG_INFO, AVBL_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 4096, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_INFO(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_WARNING(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_PRINTF(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt, __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt, __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_LOG(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt, __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	asusdebuglog(LOG_INFO, CFG_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, fmt"\n", ##arg); \
}while(0)

#else
#define DBG_ERR(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		logmessage(nvram_safe_get("lan_hwaddr"), "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_INFO(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		logmessage(nvram_safe_get("lan_hwaddr"), "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_WARNING(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		logmessage(nvram_safe_get("lan_hwaddr"), "[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_PRINTF(fmt, arg...) do {\
	if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
		cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
	if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
		logmessage(nvram_safe_get("lan_hwaddr"), "[%s(%d)]:"fmt, __FUNCTION__, __LINE__ , ##arg); \
}while(0)

#define DBG_LOG(fmt, arg...) do {\
	cprintf("[%s(%d)]:"fmt"\n", __FUNCTION__, __LINE__ , ##arg); \
}while(0)
#endif

#endif	/* __ENCRYPT_MAINH__ */
