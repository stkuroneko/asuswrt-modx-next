/*
**	adv_debug.h
**
**
**
*/
#ifndef ADVDEBUGh
#define ADVDEBUGh
#include <stdio.h> 
#include <stdlib.h>
 
#ifdef __WIN32__ 
#include <windows.h>	/* Win32 header file */
#include <time.h>		/* Win32 header file */
#elif __ANDROID__
#include <android/log.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#else
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#endif	/* __WIN32__ */

#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif

#ifndef NULL
#define NULL 	0
#endif	/* NULL */
//---------------------------------------------------------------------------
#define	ADVDBG_EMERG	0	/* system is unusable */
#define	ADVDBG_ALERT	1	/* action must be taken immediately */
#define	ADVDBG_CRIT		2	/* critical conditions */
#define	ADVDBG_ERR		3	/* error conditions */
#define	ADVDBG_WARNING	4	/* warning conditions */
#define	ADVDBG_NOTICE	5	/* normal but significant condition */
#define	ADVDBG_INFO		6	/* informational */
#define	ADVDBG_DEBUG	7	/* debug-level messages */

typedef struct _AdvDBG_CODE_t {
	char*	c_name;
	int		c_code;
} AdvDBG_CODE, *AdvDBG_CODE_PTR;

#if 0
static struct _AdvDBG_CODE_t __AdvDBG_CODE_TBL[] = {
	{	"emerg", 	ADVDBG_EMERG	},
	{	"alert", 	ADVDBG_ALERT	},
	{	"crit", 	ADVDBG_CRIT		},
	{	"err", 		ADVDBG_ERR		},
	{	"warning", 	ADVDBG_WARNING	},
	{	"notice", 	ADVDBG_NOTICE	},
	{	"info", 	ADVDBG_INFO		},
	{	"debug", 	ADVDBG_DEBUG	},
	{	NULL, 		-1				},
};
#endif

#define __AdvDBG_Find_Code(code, name) do {	\
	AdvDBG_CODE_PTR pCodeTbl = &__AdvDBG_CODE_TBL[0]; \
	while (pCodeTbl->c_name != NULL && pCodeTbl->c_code != -1) \
	{ \
		if (pCodeTbl->c_code == code) \
		{ \
			name = pCodeTbl->c_name; \
			break; \
		} \
        pCodeTbl ++; \
	} \
} while(0)
//---------------------------------------------------------------------------
static void __inline __AdvDBG_OutputString(
	char *message, ...)
{
	char *msg = NULL;
	va_list args;
	unsigned long alloc_size = 0;
	
	if (message == NULL)
	{
		return;
	}
	
	alloc_size = strlen(message) + 1;	
	msg = (char *)malloc(alloc_size);
	if (msg == NULL)
	{
		return;
	}
	
	memset(msg, 0, alloc_size);
	va_start(args, message);
	vsnprintf(msg, alloc_size-1, message, args);
	va_end(args);
	
#ifdef __WIN32__
	OutputDebugStringA(msg);	/* Win32 API */
#elif __ANDROID__
	__android_log_print(ANDROID_LOG_DEBUG,"ANDROID_LOG","%s",msg);
#else
	printf("%s\n", msg);
#endif	/* __WIN32__ */
	
	free(msg);
	return;		
}
//---------------------------------------------------------------------------
#define ADVDBG_LOG_PID		0x01
#define ADVDBG_LOG_DATE		0x02
#define ADVDBG_LOG_TIME		0x04
#define ADVDBG_LOG_TITLE	0x08
#define ADVDBG_LOG_ALL		ADVDBG_LOG_PID | ADVDBG_LOG_DATE | ADVDBG_LOG_TIME | ADVDBG_LOG_TITLE

#define __AdvDBG_MAX_MSG_SIZE		8193
#define __AdvDBG_MAX_TITLE_SIZE		64

//static int 	__AdvDBG_SET_PRIO = -1;
//static char	__AdvDBG_SET_LOGFLAG = 0x00;
extern int    __AdvDBG_SET_PRIO;
extern char   __AdvDBG_SET_LOGFLAG;

#define AdvDBG_Enable(prio, flag) do { \
	__AdvDBG_SET_LOGFLAG = 0x00; \
	__AdvDBG_SET_LOGFLAG |= flag; \
	__AdvDBG_SET_PRIO = (prio < 0 && prio > 7) ? -1 : prio; \
} while(0)

#define AdvDBG_Disable do { \
	__AdvDBG_SET_LOGFLAG = 0x00; \
	__AdvDBG_SET_PRIO = -1; \
} while(0)

#define AdvDBG_SetFlag(flag) do { \
	if (__AdvDBG_SET_PRIO != -1) \
	{ \
		__AdvDBG_SET_LOGFLAG |= flag; \
	} \
} while(0)

#define AdvDBG_GetFlag(flag) do { \
	*flag = __AdvDBG_SET_LOGFLAG; \
} while(0)

#define AdvDBG_ClearFlag ( \
	__AdvDBG_SET_LOGFLAG = 0x00; \
)

#define AdvDBG_TRACE_ENTER(msg) do { \
	AdvDBG_ODS(ADVDBG_DEBUG, "(%s) >>>>>>>", msg); \
} while(0)

#define AdvDBG_TRACE_EXIT(msg) do { \
	AdvDBG_ODS(ADVDBG_DEBUG, "(%s) <<<<<<<", msg); \
} while(0)


// >>> Add by MAX 2015.06.11, Fix memory usage issue
#ifdef __WIN32__
#define AdvDBG_ODS(LEVEL,...) do {\
	char __SS__[10241];\
	memset(__SS__,0,sizeof(__SS__));\
	_snprintf(__SS__,sizeof(__SS__)-1,__VA_ARGS__);\
	OutputDebugStringA(__SS__);\
}while(0)
#elif __ANDROID__
#define AdvDBG_ODS(LEVEL,...) if ((__AdvDBG_SET_PRIO>=0&&__AdvDBG_SET_PRIO<=7)&&LEVEL<=__AdvDBG_SET_PRIO) { __android_log_print(ANDROID_LOG_DEBUG,"ANDROID_LOG",__VA_ARGS__); }
#else

#ifdef RTCONFIG_LIBASUSLOG
#define AMAS_DBG_LOG	"cfg_mnt.log"
#define AdvDBG_ODS(LEVEL,...) do { \
	{ \
		if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
			cprintf(__VA_ARGS__); \
		if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
			asusdebuglog(LOG_INFO, AMAS_DBG_LOG, LOG_CUSTOM, LOG_SHOWTIME, 0, __VA_ARGS__); \
	} \
} while(0)
#else
#define AdvDBG_ODS(LEVEL,...) do { \
	{ \
		if (!strcmp(nvram_safe_get("cfg_dbg"), "1")) \
			cprintf(__VA_ARGS__); \
		if (!strcmp(nvram_safe_get("cfg_syslog"), "1")) \
			logmessage(nvram_safe_get("lan_hwaddr"), __VA_ARGS__); \
	} \
} while(0)
#endif

#endif	/* __WIN32__ */

//---------------------------------------------------------------------------
#endif	/* ADVDEBUGh */
