#include <stdlib.h>             /* malloc, free, etc. */
#include <stdio.h>              /* stdin, stdout, stderr */
#include <string.h>             /* strdup */
#include <sys/ioctl.h>
#include <fcntl.h>
#include "rdm.h"


//  syntax: reg [r/w] [offset(hex)] [value(hex, w only)] 
//  example reg r 18
//  example reg w 18 12345678
int main(int argc, char *argv[])
{
	int fd, method, offset = 0, value = 0;
	char *p;

	if (argc < 3)
	{
		printf("syntax: reg [method(r/w/s/d)] [offset(hex)] [value(hex, w only)]\n");
		printf("read example : reg r 18\n");
		printf("write example : reg w 18 12345678\n");
		printf("dump example : reg d 18 \n");
		printf("To use system register: reg s 0\n");
		printf("To use wireless register: reg s 1\n");
		printf("To use other base address offset: reg s [offset]\n");
		printf("for example: reg s 0xa0500000\n");
		printf("To show current base address offset: reg s 2\n");
		return 0;
	}
	
	p = argv[1];
	if (*p == 'r')
	{
		method = RT_RDM_CMD_SHOW;
	}
	else if (*p == 'p')
	{
		method = RT_RDM_CMD_READ;
	}
	else if (*p == 'd')
	{
		method = RT_RDM_CMD_DUMP;
	}
	else if (*p == 'w')
	{
		method = RT_RDM_CMD_WRITE;
	}
	else if (*p == 's')
	{
		p = argv[2];
		if (*p == '0' && *(p+1) == '\0')
		{
			method = RT_RDM_CMD_SET_BASE_SYS;
		}
		else if (*p == '1')
		{
			method = RT_RDM_CMD_SET_BASE_WLAN;
		}
		else if (*p == '2')
		{
			method = RT_RDM_CMD_SHOW_BASE;
		}
		else
		{
			method = RT_RDM_CMD_SET_BASE;
		}
		

		if (method != RT_RDM_CMD_SET_BASE)
		{
			fd = open("/dev/rdm0", O_RDONLY);
			if (fd < 0)
			{
				printf("Open pseudo device failed\n");
				return 0;
			}
	
			ioctl(fd, method, offset);
	
			close(fd);
	
			return 0;
		}
	}
	else
	{
		printf("method must be either r or w\n");
		return 0;
	}
	
	p = argv[2];
	if (*p == '0' && *(p+1) == 'x')
		p += 2;
	if (strlen(p) > 8)
	{
		printf("invalid offset\n");
	}

	while (*p != '\0')
	{
		if (*p >= '0' && *p <= '9')
			offset = offset * 16 + *p - 48;
		else 
		{
			if (*p >= 'A' && *p <= 'F')
				offset = offset * 16 + *p - 55;
			else if (*p >= 'a' && *p <= 'f')
				offset = offset * 16 + *p - 87;
			else
			{
				printf("invalid offset\n");
				return 0;
			}
		}
		p++;
	}
	
	if (method == RT_RDM_CMD_WRITE)
	{
		p = argv[3];
		if (*p == '0' && *(p+1) == 'x')
			p += 2;
		if (strlen(p) > 8)
		{
			printf("invalid value\n");
		}
		
		method = (method | (offset << 16));
		while (*p != '\0')
		{
			if (*p >= '0' && *p <= '9')
				value = value * 16 + *p - 48;
			else 
			{
				if (*p >= 'A' && *p <= 'F')
					value = value * 16 + *p - 55;
				else if (*p >= 'a' && *p <= 'f')
					value = value * 16 + *p - 87;
				else
				{
					printf("invalid value\n");
					return 0;
				}
			}
			p++;
		}
		offset = value;
	}
	

	fd = open("/dev/rdm0", O_RDONLY);
	if (fd < 0)
	{
		printf("Open pseudo device failed\n");
		return 0;
	}

	ioctl(fd, method, &offset);
	if (method == RT_RDM_CMD_READ) {
		printf("0x%x\n", offset);	
	}
	
	close(fd);

	return 0;
}
