#include <stdlib.h>             
#include <stdio.h>             
#include <string.h>           
#include <sys/ioctl.h>
#include <fcntl.h>
#include <getopt.h>

#include "acl_ioctl.h"
#include "acl_api.h"

void show_usage(void)
{
    printf("Add SDMAC  Entry for Any Protocol\n");
    printf("acl -A -n [SMAC] -U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -A -n 00:11:22:33:44:55  -u Deny \n\n");
    printf("Ex: acl -A -n 00:11:22:33:44:55  -U 3 -u FP \n\n");

    printf("Add SMAC to DIP Entry for Any Protocol\n");
    printf("acl -a -n [SMAC] -q [DipS] -r [DipE] -U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -a -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5 -u Deny \n\n");
    printf("Ex: acl -a -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5 -U 3 -u FP \n\n");

    printf("Add SMAC to DIP Entry for Tcp Protocol\n");
    printf("acl -b  -n [SMAC] -q [DipS] -r [DipE] -s [DpS] -t [DpE] -U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -b -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5 -s 1 -t 1024 -u Deny\n\n");
   
    printf("SMAC to DIP Entry for Udp Protocol\n");
    printf("acl -c  -n [SMAC] -q [DipS] -r [DipE] -s [DpS] -t [DpE] -U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -c -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5 -s 1 -t 1024 -u Deny\n\n");
  
    printf("Del SDMAC  Entry for Any Protocol\n");
    printf("acl -D -n [SMAC]\n");
    printf("Ex: acl -D -n 00:11:22:33:44:55 \n\n");

    printf("Del SMAC to DIP Entry for Any Protocol\n");
    printf("acl -d -n [SMAC] -q [DipS] -r [DipE]\n");
    printf("Ex: acl -d -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5\n\n");
   
    printf("Del SMAC to DIP Entry for Tcp Protocol\n");
    printf("acl -e  -n [SMAC] -q [DipS] -r [DipE] -s [DpS] -t [DpE]\n");
    printf("Ex: acl -e -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5 -s 1 -t 1024\n\n");
   
    printf("Del SMAC to DIP Entry for Udp Protocol\n");
    printf("acl -f  -n [SMAC] -q [DipS] -r [DipE] -s [DpS] -t [DpE]\n");
    printf("Ex: acl -f -n 00:11:22:33:44:55 -q 10.10.10.3 -r 10.10.10.5 -s 1 -t 1024\n\n");

    printf("Add SIP to DIP Entry for Any Protocol\n");
    printf("acl -g  -o [SipS] -p [SipE] -q [DipS] -r [DipE] -U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -g -o 10.10.10.3 -p 10.10.10.5 -q 10.10.20.3 -r 10.10.20.3 -u Deny\n\n");
   

    printf("Add SIP to DIP Entry for Tcp Protocol\n");
    printf("acl -h  -o [SipS] -p [SipE] -q [DipS] -r [DipE] -s [DpS] -t [DpE] -U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -h -o 10.10.10.3 -p 10.10.10.5 -q 10.10.20.3 -r 10.10.20.3 -s 1 -t 1024 -u Deny\n\n");
   

    printf("Add SIP to DIP Entry for Udp Protocol\n");
    printf("acl -i  -o [SipS] -p [SipE] -q [DipS] -r [DipE] -s [DpS] -t [DpE]-U[UP] -u [Allow/Deny/FP]\n");
    printf("Ex: acl -i -o 10.10.10.3 -p 10.10.10.5 -q 10.10.20.3 -r 10.10.20.3 -s 1 -t 1024 -u Deny\n\n");
    
    printf("Del SIP to DIP Entry for Any Protocol\n");
    printf("acl -j  -o [SipS] -p [SipE] -q [DipS] -r [DipE]\n");
    printf("Ex: acl -j -o 10.10.10.3 -p 10.10.10.5 -q 10.10.20.3 -r 10.10.20.3\n\n");
   

    printf("Del SIP to DIP Entry for Tcp Protocol\n");
    printf("acl -k  -o [SipS] -p [SipE] -q [DipS] -r [DipE] -s [DpS] -t [DpE]\n");
    printf("Ex: acl -k -o 10.10.10.3 -p 10.10.10.5 -q 10.10.20.3 -r 10.10.20.3 -s 1 -t 1024\n\n");
   

    printf("Del SIP to DIP Entry for Udp Protocol\n");
    printf("acl -l  -o [SipS] -p [SipE] -q [DipS] -r [DipE] -s [DpS] -t [DpE]\n");
    printf("Ex: acl -l -o 10.10.10.3 -p 10.10.10.5 -q 10.10.20.3 -r 10.10.20.3 -s 1 -t 1024\n\n");
}

int main(int argc, char *argv[])
{
    int opt;
    char options[] = "AabcDdefghijklm?n:o:p:q:r:s:t:u:U:";
    int fd;
    struct acl_args args;
    int method=-1;

    memset(&args, 0, sizeof(struct acl_args));
    fd = open("/dev/"ACL_DEVNAME, O_RDONLY);

    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"ACL_DEVNAME);
	return 0;
    }

    if(argc < 2) {
	show_usage();
	return 0;
    }

    while ((opt = getopt (argc, argv, options)) != -1) {
	switch (opt) {
	case 'A': 
		method=ACL_ADD_SDMAC_ANY;
		break;
	case 'a': 
		method=ACL_ADD_SMAC_DIP_ANY;
		break;
	case 'b':
		method=ACL_ADD_SMAC_DIP_TCP;
		break;
	case 'c':
		method=ACL_ADD_SMAC_DIP_UDP;
		break;
	case 'D': 
		method=ACL_DEL_SDMAC_ANY;
		break;
	case 'd': 
		method=ACL_DEL_SMAC_DIP_ANY;
		break;
	case 'e':
		method=ACL_DEL_SMAC_DIP_TCP;
		break;
	case 'f':
		method=ACL_DEL_SMAC_DIP_UDP;
		break;
	case 'g':
		method=ACL_ADD_SIP_DIP_ANY;
		break;
	case 'h':
		method=ACL_ADD_SIP_DIP_TCP;
		break;
	case 'i':
		method=ACL_ADD_SIP_DIP_UDP;
		break;
	case 'j':
		method=ACL_DEL_SIP_DIP_ANY;
		break;
	case 'k':
		method=ACL_DEL_SIP_DIP_TCP;
		break;
	case 'l':
		method=ACL_DEL_SIP_DIP_UDP;
		break;
	case 'm':
		method=ACL_CLEAN_TBL;
		break;
	case 'n': /* source mac address */
		str_to_mac(args.mac, optarg);
		break;
	case 'o': /* start of sip */
		str_to_ip(&args.sip_s, optarg);
		break;
	case 'p': /* end of sip */
		str_to_ip(&args.sip_e, optarg);
		break;
	case 'q': /* start of dip */
		str_to_ip(&args.dip_s, optarg);
		break;
	case 'r': /* end of dip */
		str_to_ip(&args.dip_e, optarg);
		break;
	case 's': /* start of dp */
		args.dp_s=strtoll(optarg, NULL, 10);
		break;
	case 't': /* end of dp */
		args.dp_e=strtoll(optarg, NULL, 10);
		break;
	case 'u': /* Deny/Allow */
		if(strcasecmp(optarg,"Deny")==0){
			args.method=ACL_DENY_RULE;
		}else if(strcasecmp(optarg,"Allow")==0){
			args.method=ACL_ALLOW_RULE;
		}else if(strcasecmp(optarg,"FP")==0){
			args.method=ACL_PRIORITY_RULE;
		}else{
			printf("Error: -t Deny or Allow\n");
			return 0;
		}
		break;
	case 'U': /* User Priority */
		args.up=strtoll(optarg, NULL, 10);
		break;
	case '?':
	    show_usage();

	}
    } 
    switch(method) {
    case ACL_ADD_SDMAC_ANY:
    case ACL_ADD_SMAC_DIP_ANY:
    case ACL_ADD_SMAC_DIP_TCP:
    case ACL_ADD_SMAC_DIP_UDP:
    case ACL_DEL_SDMAC_ANY:
    case ACL_DEL_SMAC_DIP_ANY:
    case ACL_DEL_SMAC_DIP_TCP:
    case ACL_DEL_SMAC_DIP_UDP:
    case ACL_ADD_SIP_DIP_ANY:
    case ACL_ADD_SIP_DIP_TCP:
    case ACL_ADD_SIP_DIP_UDP:
    case ACL_DEL_SIP_DIP_ANY:
    case ACL_DEL_SIP_DIP_TCP:
    case ACL_DEL_SIP_DIP_UDP:
    case ACL_CLEAN_TBL:
	      SetAclEntry(&args, method);
	      if(args.result == ACL_TBL_FULL) {
		      printf("Acl Table Full!!\n");
	      }else if (args.result == ACL_FAIL){
		      printf("Acl command fail!\n");
	      }else{
		      printf("ACL command ok!\n");
	      }
	      break;
    }
    
    return 0;
}
