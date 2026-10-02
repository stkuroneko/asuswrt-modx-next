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
#include <ltq_api_include.h>
#include <stdlib.h>

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


int main(int argc, char** argv)
{
        int nRet = -1;
	if(argc < 3)
	{
		printf("Enter proper arguments\n");
		printf("usage: ./crypt_util <DEC/ENC> <file name to dec/enc> <passwd> < output file>\n");
		exit(-1);
	}

	
	
	if(strcmp(argv[1], "ENC")==0)
	{
        	nRet = scapi_encryption(argv[2], argv[3], argv[4]);
        	printf("Done with Encryption %d\n", nRet);
	}
	else if(strcmp(argv[1], "DEC")==0)	
	{
        	nRet = scapi_decryption(argv[2], argv[3], argv[4]);
        	printf("Done with Decryption %d\n", nRet);
	}
	else
		printf("Enter proper options\n");

}

