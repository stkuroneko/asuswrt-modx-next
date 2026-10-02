#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include "cls_io.h"


void usage()
{
	printf("Usage: clscmd 1 [num] ; num = maxium list number\n");
	printf("	 : clscmd 2 ; turn on debug print\n");
	printf(" 	 : clscmd 3 ; turn off debug print\n");
	printf("	 : clscmd 4 ; enable inband QoS tag\n");
	printf(" 	 : clscmd 5 ; enable outband QoS tag\n");
	printf("	 : clscmd 6 ; disable inband QoS tag\n");
	printf(" 	 : clscmd 7 ; disable outband QoS tag\n");
}


int main(int argc, char *argv[])
{
	FILE* fp;
	void *fdm;
	char* pBuf;
	int pos;
	int nRet=0,nLen,i=0;
	int index = 0;
	int cls_fd;
	classifier_cmd_t cls_cmd;
	finfo_t* plist;
	char* qostype[5] = {"NA", "VO", "VI", "BE", "BG"};
	char* identmethod[7] = {"NA", "Packet Len", "ASF Header", "TS Header", "bi direction", "IAT", "RTP Payload Type"};
	
    cls_fd = open("/dev/cls0", O_RDWR|O_SYNC); 
    if(cls_fd < 0)
    {
    	printf("clscmd:open classifier failed (%d)...exit\n",cls_fd);
    	return -1;
    }
    if(argc < 2)
	{
		cls_cmd.listlen = 5;   
		goto SHOWLIST;
	}	 
    switch(strtoul(argv[1], NULL, 10))
    {
    	case 1:
    		if(argc < 3)
				cls_cmd.listlen = 5;
			else
				cls_cmd.listlen = strtoul(argv[2], NULL, 10);	
    		goto SHOWLIST;
    	case 2:
    		ioctl(cls_fd, DBGPRN_ENABLE, NULL);
    		goto EXIT;
    	case 3:
    		ioctl(cls_fd, DBGPRN_DISABLE, NULL);
    		goto EXIT;
    	case 4:
    		ioctl(cls_fd, INBAND_QOS_ENABLE, NULL);	
    		goto EXIT;
    	case 5:
    		ioctl(cls_fd, OUTBAND_QOS_ENABLE, NULL);
    		goto EXIT;
    	case 6:
    		ioctl(cls_fd, INBAND_QOS_DISABLE, NULL);	
    		goto EXIT;
    	case 7:
    		ioctl(cls_fd, OUTBAND_QOS_DISABLE, NULL);
    		goto EXIT;		
    	default:
    		usage();
    		goto EXIT;
    }	

SHOWLIST:    
	if((cls_cmd.listlen < 0)||(cls_cmd.listlen > MAX_LIST_FLOW))
 		cls_cmd.listlen = 5;
    
    plist = malloc(sizeof(finfo_t)*cls_cmd.listlen);
    if(	plist == NULL)
    	goto EXIT;
	cls_cmd.plist = plist;
    memset(plist, 0, sizeof(finfo_t)*cls_cmd.listlen);	

    ioctl(cls_fd, GET_ALLFLOW_INFO, &cls_cmd);
    
    for ( i = 0 ; i < cls_cmd.listlen; i++ )
    {
  
    	finfo_t* pfinfo = plist+i;
    	if(pfinfo->data_rate > 0 )
    	{
    		char s_addr[16];
    		char d_addr[16];
    		if(pfinfo->type==-1)
    			pfinfo->type = 0;
    			
    		sprintf(s_addr, "%s",inet_ntoa(pfinfo->sip));
			sprintf(d_addr, "%s",inet_ntoa(pfinfo->dip));
    		printf("[%s:%d] => [%s:%d] %u bps T=%s D=%s\n", s_addr,(unsigned short)ntohs(pfinfo->sport),\
    									d_addr,(unsigned short)ntohs(pfinfo->dport), pfinfo->data_rate, qostype[pfinfo->type],identmethod[pfinfo->ident_method]);
    	}
    	
    }
    
    
	free(plist);
  

EXIT:
 	
	
   	close(cls_fd);

    printf("clscmd ...quit\n");
    return 0;
}
