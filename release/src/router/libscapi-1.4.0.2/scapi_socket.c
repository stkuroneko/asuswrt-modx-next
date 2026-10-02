/*****************************************************************************
        Copyright (c) 2015
        Lantiq Beteiligungs-GmbH & Co. KG
        Lilienthalstrasse 15, 85579 Neubiberg, Germany 
        For licensing information, see the file 'LICENSE' in the root folder of
        this software module.
 
********************************************************************************/

/*  ***************************************************************************** 
 *         File Name    :  scapi_socket.c                                    *
 *         Description  :  This file contains all the data declarations that are
                           shared across the modules                      *  
 *  *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <stdint.h>
#include <sys/socket.h>
#include <scapi_ipc.h>
#include <errno.h>
#include "ugw_error.h" 
#include "ulogging.h"

#define IPC_FILE_PATH "/tmp/MsgTo"


/* 
** =============================================================================
**   Function Name    : ipc_create_listener 
**   Description      : APT to create a socket 
**   Return Value     : Success -> Socket Id in structure pxhandle
**                      Failure -> NULL
** ===========================================================================*/

void*
ipc_create_listener(char *pucto)
{
	int32_t iret;
	char acbuf[MAX_NAME_LEN];
	struct sockaddr_un xaddr;
	x_ipc_handle *pxhandle;

	//TODO
	//pxhandle=help_calloc(1,sizeof(x_ipc_handle), __FILE__, __LINE__);
	pxhandle=calloc(1,sizeof(x_ipc_handle));

	if(pxhandle == NULL) {
		LOGF_LOG_DEBUG("memory allocation failed for listener\n");
		return NULL;
	}

	iret=snprintf(acbuf,MAX_NAME_LEN, IPC_FILE_PATH"%s", pucto);
	if(iret==MAX_NAME_LEN){
		LOGF_LOG_DEBUG("from or to strings are too long consider shortening the name\n");
		free(pxhandle);
		return NULL;
	}
	/* Create a unix domain socket */
	pxhandle->ifd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(pxhandle->ifd<0){
		LOGF_LOG_DEBUG("ipc creation failed - sock\n");
		free(pxhandle);
    		return NULL;
  	}
	memset(&xaddr, 0, sizeof(xaddr));
	xaddr.sun_family = AF_UNIX;
	strncpy(xaddr.sun_path,acbuf, sizeof(xaddr.sun_path)-1);
	
	unlink(acbuf);

	if (bind(pxhandle->ifd, (struct sockaddr*)&xaddr, sizeof(xaddr)) == -1) {
		LOGF_LOG_DEBUG("ipc creation failed - bind\n");
		if(pxhandle->ifd >= 0)
			close(pxhandle->ifd);
		free(pxhandle);
    		return NULL;
  	}

	if (listen(pxhandle->ifd, 5) == -1) {
		LOGF_LOG_DEBUG("ipc creation failed - listen\n");
		if(pxhandle->ifd >= 0)
			close(pxhandle->ifd);
		free(pxhandle);
		return NULL;
	}
	return pxhandle;
}

/* 
** =============================================================================
**   Function Name    : ipc_send_request 
**   Description      : API to send request to socket 
**   Return Value     : Success -> UGW_SUCCESS
**                      Failure -> UGW_FAILURE 
** ===========================================================================*/


int32_t
ipc_send_request(x_ipc_msg_t *pxmsg)
{
	int16_t nbytes = 0;
	int32_t ifd,iret;
	char acbuf[MAX_NAME_LEN];
	struct sockaddr_un xaddr;

	iret=snprintf(acbuf,MAX_NAME_LEN, IPC_FILE_PATH"%s",pxmsg->xhdr.aucto);

	/* Create a socket */
	if((ifd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0){
		LOGF_LOG_DEBUG("IPC create failed\n");
		return UGW_FAILURE;
	}
	/* Construct name to connect the socket to */
	memset(&xaddr, 0, sizeof(xaddr));
	xaddr.sun_family = AF_UNIX;
	strncpy(xaddr.sun_path,acbuf, sizeof(xaddr.sun_path)-1);
	/* connect the socket */
	if(connect(ifd, (struct sockaddr*)&xaddr, sizeof(xaddr)) == -1) {
		LOGF_LOG_DEBUG("IPC listener missing\n");
		if(ifd >= 0)
			close(ifd);
		return UGW_FAILURE;
	}
	/* Write the message */
	if (write(ifd, (char *)pxmsg, pxmsg->xhdr.unmsgsize + IPC_HDR_SIZE) < 0)
	{
		/* Error Writing Message to the FIFO */
		/* Add Debugs if required */
		if(ifd >= 0)
			close(ifd);
		return IPC_FAIL;
	}
	/* block for reply */
	LOGF_LOG_DEBUG("Blocked to read the header\n");
	if((nbytes = read(ifd, (char *) &pxmsg->xhdr,
				sizeof(x_ipc_msghdr_t))) < 0)
	{
		/* Error Reading Header */
		LOGF_LOG_DEBUG("Error reading response\n");
		if(ifd >= 0)
			close(ifd);
		return IPC_FAIL;
	}
	if (nbytes != sizeof(x_ipc_msghdr_t))
	{
		if(ifd >= 0)
			close(ifd);
		return IPC_FAIL;
	}
	else
	{
		iret = pxmsg->xhdr.unmsgsize;
		if(iret > (int32_t)IPC_MAX_MSG_SIZE)
		{
			if(ifd >= 0)
				close(ifd);
			return IPC_FAIL;
		}
	}
	LOGF_LOG_DEBUG("Blocked to read the msg\n");
	if ((nbytes = read(ifd, pxmsg->acmsg, iret)) < 0)
	{
		/* Error Reading Header */
		/* Add Debugs if required */
		if(ifd >= 0)
			close(ifd);
		return IPC_FAIL;
	}

	if(ifd >= 0)
		close(ifd);
	return IPC_SUCCESS;
}

/*
** =============================================================================
**   Function Name    : ipc_recv 
**   Description      : API to read message from socket 
**   Return Value     : Success -> UGW_SUCCESS
**                      Failure -> UGW_FAILURE 
** ===========================================================================*/


int32_t
ipc_recv(void *pvhandle,
				 x_ipc_msg_t *pxmsg)
{
	int16_t nbytes = 0;
	x_ipc_handle *pxhandle=pvhandle;

	if(pvhandle==NULL){
		LOGF_LOG_DEBUG("Create a Event listener first\n");
		return UGW_FAILURE;
	}

	if ( ( pxhandle->iconnfd = accept(pxhandle->ifd, NULL, NULL)) == -1) {
		perror("accept error");
		return UGW_FAILURE;
	}

	if ((nbytes = read(pxhandle->iconnfd, (char *) &pxmsg->xhdr,
			sizeof(x_ipc_msghdr_t))) < 0)
	{
		/* Error Reading Header */
		/* Add Debugs if required */
		return IPC_FAIL;
	}
	if (nbytes != sizeof(x_ipc_msghdr_t) || pxmsg->xhdr.unmsgsize > IPC_MAX_MSG_SIZE || pxmsg->xhdr.unmsgsize < 1)
	{
		return IPC_FAIL;
	}
	LOGF_LOG_DEBUG("Reading the message\n");
	if ((nbytes = read(pxhandle->iconnfd, pxmsg->acmsg, pxmsg->xhdr.unmsgsize)) < 0)
	{
		/* Error Reading Header */
		/* Add Debugs if required */
		return IPC_FAIL;
	}
	return UGW_SUCCESS;
}

/*
** =============================================================================
**   Function Name    : ipc_send_reply 
**   Description      : API to write message into socket 
**   Return Value     : Success -> UGW_SUCCESS
**                      Failure -> UGW_FAILURE 
** ===========================================================================*/

int32_t
ipc_send_reply(void *pvhandle,
               x_ipc_msg_t *pxmsg)
{
	x_ipc_handle *pxhandle=pvhandle;

	if(pvhandle==NULL){
		LOGF_LOG_DEBUG("Create a Event listener first\n");
		return UGW_FAILURE;
	}
	if (write(pxhandle->iconnfd, (char *)pxmsg, pxmsg->xhdr.unmsgsize + IPC_HDR_SIZE) < 0)
	{
		/* Error Writing Message to the FIFO */
		/* Add Debugs if required */
		LOGF_LOG_DEBUG("write failed %d\n",pxhandle->iconnfd);
		return IPC_FAIL;
	}
	close(pxhandle->iconnfd);
	return IPC_SUCCESS;
}
