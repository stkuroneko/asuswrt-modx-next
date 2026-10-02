/*****************************************************************************

  Copyright (c) 2015
  Lantiq Beteiligungs-GmbH & Co. KG
  Lilienthalstrasse 15, 85579 Neubiberg, Germany 

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 ******************************************************************************/

/***************************************************************************** *
 *     File Name  : scapiutil.c                                        	       *
 *     Project    : UGW                                                        *
 *     Description: To provide utility support of the scapi API's	       * 
 *                                                                             *
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include "scapi_util.h"
#include <fcntl.h> 
#include <unistd.h> 


#define FIRST_BOOT_CHK "/opt/lantiq/etc/.certchk"

int main( __attribute__ ((unused))int argc, char **argv)
{

	int nRet=0;
	int nChildSt;

	if (strcmp(argv[1], "get_mac")==0)
	{
		char sMac[32]={0};
		nRet = scapi_getBaseMac(sMac); 
		if(nRet == EXIT_SUCCESS)
			printf("%s",sMac);
	}

	if (strcmp(argv[1], "get_key")==0)
	{
		
		int fd ;
		fd = open(FIRST_BOOT_CHK, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
		if (!(fd < 0)) 
		{ 
			nRet = scapi_spawn("key=`head -200 /dev/urandom | cksum | cut -f1 -d \" \"` ; openssl req -new -x509 -subj \"/C=IN/ST=KAR/L=Benguluru/O=UGW SW/CN=CPE \" -sha256 -newkey rsa:2048 -passin pass:$key -keyout /tmp/key.pem -out /tmp/cert.pem -days 7300 -nodes -passout pass:$key 2>/dev/null; cat /tmp/key.pem /tmp/cert.pem > /etc/lighttpd/lighttpd.pem ; rm -rf /tmp/*.pem",SCAPI_BLOCK,&nChildSt);
			if (nRet !=  0)
			{
				printf("@@@@@@@@@@@@@@@ Failed to create certificate @@@@@@@@@@@@@@@@@\n");
			}
		}
		if(fd > 0) close(fd);
	}

	return nRet;
}
