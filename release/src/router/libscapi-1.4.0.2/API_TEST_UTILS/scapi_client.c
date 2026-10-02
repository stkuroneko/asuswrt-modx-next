/*****************************************************************************
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_client.c                                    *
 *         Description  :  This file contains all the data declarations that are
                           shared across the modules                      *  
 *  *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <scapi_ipc.h>

#include "ulogging.h"
#ifndef LOG_LEVEL
uint16_t   LOGLEVEL = SYS_LOG_INFO + 1;
#else
uint16_t   LOGLEVEL = LOG_LEVEL + 1;
#endif

#ifndef LOG_TYPE
uint16_t   LOGTYPE = SYS_LOG_TYPE_CONSOLE;
#else
uint16_t   LOGTYPE = LOG_TYPE;
#endif

main()
{
	x_ipc_msg_t xmsg;
	strcpy(xmsg.xhdr.aucfrom,"client");
	strcpy(xmsg.xhdr.aucto,"server");
	xmsg.xhdr.unmsgsize=strlen("request");
	strcpy(xmsg.acmsg,"request");
	printf("This is client\n");
	ipc_send_request(&xmsg);
	printf("From[%s]To[%s]Len[%d]Msg[%s]\n",xmsg.xhdr.aucfrom,xmsg.xhdr.aucto,xmsg.xhdr.unmsgsize,xmsg.acmsg);
}
