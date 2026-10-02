#include <openssl/md5.h>
#include <unistd.h>
#include <ssl_api.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DECLARE_CLEAR_MEM(type, var, len) \
	type var[len]; \
	memset(var, 0, len );

void get_md5_string(char* hwaddr, char* out_md5string)
{
	//unsigned char* hwaddr = "00:0c:29:62:72:68";	
	DECLARE_CLEAR_MEM(unsigned char, md, MD_LEN);
	int i =0;
	MD5((const unsigned char*)hwaddr, strlen((const char*)hwaddr), md);
	
	memset(out_md5string, 0 , MD_STR_LEN+1);
	
	char tmp[3];
	for(i =0; i<MD_LEN; i++){
		memset(tmp,0,3);
		sprintf(tmp,"%02x", md[i]);	
		strcat(out_md5string, tmp);				
	}
	//printf(">>>>>md5stirng =%s", out_md5string);	
}
