/*
**	utility.h
**
**
**
*/
#ifndef __UTILITYH__
#define __UTILITYH__
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include "include/adv_misc.h"
#include "include/adv_debug.h"
#include "include/Debug-Int.h"
#include "encrypt.h"
#include "blepack.h"

////////////////////////////////////////////////////////////////////////////////
//
// Debug Message 	
//
////////////////////////////////////////////////////////////////////////////////
#define MAX_DBGMSG_LENGTH	4097

#define LIBRARY_NAME	"[BLE]"

#define DBG_ERR(...) do {\
	char __BUF__[MAX_DBGMSG_LENGTH];\
	memset(__BUF__,0,sizeof(__BUF__));\
	DEBUG_ERR(LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
}while(0)

#define DBG_INFO(...) do {\
	char __BUF__[MAX_DBGMSG_LENGTH];\
	if (!BLE_EnableDBG()) break;\
	memset(__BUF__,0,sizeof(__BUF__));\
	DEBUG_INFO(LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
}while(0)

#define DBG_NOTICE(...) do {\
	char __BUF__[MAX_DBGMSG_LENGTH];\
	memset(__BUF__,0,sizeof(__BUF__));\
	DEBUG_NOTICE(LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
}while(0)

#define DBG_WARNING(...) do {\
	char __BUF__[MAX_DBGMSG_LENGTH];\
	memset(__BUF__,0,sizeof(__BUF__));\
	DEBUG_WARNING(LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
}while(0)

#define DBG_TRACE_LINE do {\
	char __BUF__[MAX_DBGMSG_LENGTH];\
	memset(__BUF__,0,sizeof(__BUF__));\
	DEBUG_INFO(LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,"TRACE LINE!!!"));\
}while(0)

#endif	// __ENCRYPT_MAINH__ 

