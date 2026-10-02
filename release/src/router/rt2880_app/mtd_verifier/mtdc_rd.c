#include	<unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include	<signal.h>
#include	<sys/stat.h>
#include	<fcntl.h>

int len = 128;
int fd;
char *mtd_d = "/dev/mtd2";

void mtd_read(void){

	int i = 0;
	char pbuf[len];

	fd = open(mtd_d, O_RDWR | O_SYNC);
	if(fd < 0) {
		printf("Could not open mtd device: %s\n",mtd_d);
		exit(1);
	}
	
	if(read(fd, pbuf, len) != len){
		printf("read() failed\n");
		close(fd);
		exit(1);
	}
	
	if ( pbuf[0] != 0x52 )
	{
		printf("\nmtd read [01]=%x%x\n", pbuf[0], pbuf[1]);
	
		for ( i = 0; i < len; i++ )
		{
			if ( i % 16 == 0 )
				printf("\n0x%04x: ", i/16);
			printf("%02x", pbuf[i]);
		}
	}
	close(fd);
}

int main(void)
{
	while(1){
		mtd_read();
		sleep(1);
	}
	return 0;
}

