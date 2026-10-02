/*****************************************************************************
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_server.c                                    *
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

int main()
{
	void *pvhandle;
	int32_t iret;
	x_ipc_msg_t xmsg;
	printf("This is server\n");
	printf("Creating Listerner\n");
	pvhandle=ipc_create_listener("server");
	while(1){
		printf("Blocking on rcv\n");
		iret=ipc_recv(pvhandle,&xmsg);
		if(iret<0){
			printf("Receive failed\n");
			if(pvhandle != NULL)
				free(pvhandle);
			return -1;
		}
		printf("From[%s]To[%s]Len[%d]Msg[%s]\n",xmsg.xhdr.aucfrom,xmsg.xhdr.aucto,xmsg.xhdr.unmsgsize,xmsg.acmsg);
		sleep(5);
		printf("Sending reply\n");
		xmsg.xhdr.unmsgsize=strlen("response");
		strcpy(xmsg.acmsg,"response");
		ipc_send_reply(pvhandle,&xmsg);
	}
}
