/********************************************************************************

Copyright (c) 2015
Lantiq Beteiligungs-GmbH & Co. KG
Lilienthalstrasse 15, 85579 Neubiberg, Germany 
For licensing information, see the file 'LICENSE' in the root folder of
this software module.

********************************************************************************/

/*  ****************************************************************************** 
*         File Name    : scapi_crypt.c	                                         *
*         Description  : This scapi provides the encryption and decryption 	 *
*			 functions.						 * 
*  *******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ltq_api_include.h>

#define MAX_BUF_SIZE 2056

int scapi_encryption(IN char *pcInFile, IN char *pcPassWd, OUT char *pcOutFile)
{
	int nRet = -EXIT_FAILURE;
	int nChildRet = -1;
	char sBuf[MAX_BUF_SIZE] = { 0 };
	if (pcPassWd != NULL) {
		snprintf(sBuf, MAX_BUF_SIZE, "openssl aes-256-cbc -base64 -in %s -out %s -pass pass:%s", pcInFile, pcOutFile, pcPassWd);
	} else {
		snprintf(sBuf, MAX_BUF_SIZE, "openssl aes-256-cbc -base64 -in %s -out %s -pass pass:scintl", pcInFile, pcOutFile);
	}
	nRet = scapi_spawn(sBuf, SCAPI_BLOCK, &nChildRet);
	if (nRet == UGW_SUCCESS) {
		if (nChildRet != UGW_SUCCESS) {
			nRet = nChildRet;
		}
	}
	LOGF_LOG_INFO("Encryption Completed with retrun code : %d \n", nRet);
	return nRet;
}

int scapi_decryption(IN char *pcInFile, IN char *pcPassWd, OUT char *pcOutFile)
{
	int nRet = -EXIT_FAILURE;
	int nChildRet = -1;
	char sBuf[MAX_BUF_SIZE] = { 0 };
	if (pcPassWd != NULL) {
		snprintf(sBuf, MAX_BUF_SIZE, "openssl aes-256-cbc -base64 -d -in %s -out %s -pass pass:%s", pcInFile, pcOutFile, pcPassWd);
	} else {
		snprintf(sBuf, MAX_BUF_SIZE, "openssl aes-256-cbc -base64 -d -in %s -out %s -pass pass:scintl", pcInFile, pcOutFile);
	}
	nRet = scapi_spawn(sBuf, SCAPI_BLOCK, &nChildRet);
	if (nRet == UGW_SUCCESS) {
		if (nChildRet != UGW_SUCCESS) {
			nRet = nChildRet;
		}
	}
	LOGF_LOG_INFO("Decryption Completed with retrun code : %d \n", nRet);
	return nRet;
}
