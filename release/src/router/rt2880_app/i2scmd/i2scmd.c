#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include "i2s_ctrl.h"

int i2s_fd;
void *shtxbuf[MAX_I2S_PAGE];
void *shrxbuf[MAX_I2S_PAGE];
unsigned char* sbuf;
struct stat i2s_stat;
char txbuffer[I2S_PAGE_SIZE];
char rxbuffer[I2S_PAGE_SIZE];
void usage()
{
	printf("Usage: [cmd] [srate] [vol] < playback file\n");
	printf("	   [cmd] [srate] [vol] [size]\n");
	printf("       cmd = 0|1 - i2s raw playback|record\n");
	printf("       srate = 8000|16000|32000|44100|48000 Hz playback sampling rate\n");
	printf("       vol = -10~2 db playback volumn\n");
}


int main(int argc, char *argv[])
{
	FILE* fp;
	void *fdm;
	char* pBuf;
	int pos;
	int nRet=0,nLen,i=0;
	int index = 0;
	
	printf("This is Ralink I2S Command Program...\n");
	fflush(stdout);
	
    i2s_fd = open("/dev/i2s0", O_RDWR|O_SYNC); 
    if(i2s_fd<0)
    {
    	printf("i2scmd:open i2s driver failed (%d)...exit\n",i2s_fd);
    	return -1;
    }
    if(argc < 2)
    {
		usage();    
		goto EXIT;	    
    }	
    switch(strtoul(argv[1], NULL ,10))
    {
    case 0:
		if(argc < 4)
		{
			usage();
		 	goto EXIT;		
		}	
	    if (fstat(STDIN_FILENO, &i2s_stat) == -1 ||i2s_stat.st_size == 0)
			goto EXIT;
		ioctl(i2s_fd, I2S_SRATE, strtoul(argv[2], NULL ,10));
		ioctl(i2s_fd, I2S_TX_VOL, strtoul(argv[3], NULL ,10));
	    	
	    fdm = mmap(0, i2s_stat.st_size, PROT_READ, MAP_SHARED, STDIN_FILENO, 0);
		if (fdm == MAP_FAILED)
			goto EXIT;
	
#if 0
		for(i = 0; i < MAX_I2S_PAGE; i++)
		{
		   	shtxbuf[i] = mmap(0, I2S_PAGE_SIZE, PROT_WRITE, MAP_SHARED, i2s_fd, i*I2S_PAGE_SIZE);
		   	
			if (shtxbuf[i] == MAP_FAILED)
			{
				printf("i2scmd:failed to mmap..\n");
				goto EXIT;
			}
				
		}
#endif
		ioctl(i2s_fd, I2S_TX_ENABLE, 0);
    	pos = 0;
		index = 0;
		
#if 0
    	while((pos+I2S_PAGE_SIZE)<=i2s_stat.st_size)	
    	{
    		char* pData;
    		ioctl(i2s_fd, I2S_PUT_AUDIO, &index);
    		pBuf = shtxbuf[index];
    		memcpy(pBuf, (char*)fdm+pos, I2S_PAGE_SIZE);    
    		pos+=I2S_PAGE_SIZE;	
    	}
#else
		while((pos+I2S_PAGE_SIZE)<=i2s_stat.st_size)
    	{
    		pBuf = txbuffer;
    		memcpy(pBuf, (char*)fdm+pos, I2S_PAGE_SIZE);    
    		ioctl(i2s_fd, I2S_PUT_AUDIO, pBuf);
    		pos+=I2S_PAGE_SIZE;	
    	}
#endif
    	ioctl(i2s_fd, I2S_DISABLE, 0);
    	
    	munmap(fdm, i2s_stat.st_size);
   	
#if 0
		for(i = 0; i < MAX_I2S_PAGE; i++)
		{
		    	munmap(shtxbuf[i], I2S_PAGE_SIZE);
		    	if(nRet!=0)
				printf("i2scmd : munmap i2s mmap faild\n");
		}
#endif
    	break;	
    case 1:
		if(argc < 5)
		{
			usage();
			goto EXIT;
		}	
    	fp = fopen("/mnt/record.snd","wb");
    	if(fp==NULL)
    		goto EXIT;
    	ioctl(i2s_fd, I2S_SRATE, strtoul(argv[2], NULL ,10));
    	ioctl(i2s_fd, I2S_RX_VOL, strtoul(argv[3], NULL ,10));
		ioctl(i2s_fd, I2S_RX_ENABLE, 0);
    	pos = 0;
		index = 0;
		printf("argv[4]=%d\n",strtoul(argv[4], NULL ,10));
    	while((pos+I2S_PAGE_SIZE)<=strtoul(argv[4], NULL ,10))
    	{
    		short* p16Buf;	
    		int nRet = 0;

			pBuf = rxbuffer;
    		ioctl(i2s_fd, I2S_GET_AUDIO, pBuf);
    		
    		p16Buf = pBuf;
    		nRet = fwrite(pBuf, 1, I2S_PAGE_SIZE, fp);    		
    		if(nRet!=I2S_PAGE_SIZE)
    			printf("fwrite error\n");
    		pos+=I2S_PAGE_SIZE;	
    	}
		fclose(fp);
    	ioctl(i2s_fd, I2S_RX_DISABLE, 0);
    	break;
    case 11:
	{
		unsigned long param[4];
		param[0] = 4096;
		param[1] = 0x5A5A5A5A;
		ioctl(i2s_fd, I2S_DEBUG_INLBK, param);	
    	}
    	break;			
    case 12:
	{
		ioctl(i2s_fd, I2S_DEBUG_EXLBK, strtoul(argv[2], NULL ,10));	
    	}
    	break;	
    case 15:
	{
		unsigned long param[4];
		ioctl(i2s_fd, I2S_DEBUG_CODECBYPASS, 0);	
    	}
    	break;			
    default:
    	break;	
    }
  

EXIT:

	close(i2s_fd);

    	printf("i2scmd ...quit\n");
    	return 0;
}
