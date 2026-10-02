#include <stdlib.h>             
#include <stdio.h>             
#include <string.h>           
#include <sys/ioctl.h>
#include <fcntl.h>
#include <getopt.h>
#include "hwnat_ioctl.h"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]
#define NIPHALF(addr) \
        ((unsigned short *)&addr)[1], \
        ((unsigned short *)&addr)[0]





int HwNatDumpEntry(unsigned int entry_num)
{
    struct hwnat_args opt;
    int fd;

    opt.entry_num=entry_num;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_DUMP_ENTRY, &opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;
}

int HwNatBindEntry(unsigned int entry_num)
{
    struct hwnat_args opt;
    int fd;

    opt.entry_num=entry_num;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_BIND_ENTRY, &opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;
}

int HwNatUnBindEntry(unsigned int entry_num)
{
    struct hwnat_args opt;
    int fd;

    opt.entry_num=entry_num;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_UNBIND_ENTRY, &opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return  HWNAT_FAIL;
    }

    close(fd);
    return  HWNAT_SUCCESS;
}

int HwNatInvalidEntry(unsigned int entry_num)
{
    struct hwnat_args opt;
    int fd;

    opt.entry_num=entry_num;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_INVALID_ENTRY, &opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;
}

int HwNatAddEntry(struct hwnat_tuple *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_ADD_ENTRY, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatDelEntry(struct hwnat_tuple *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_DEL_ENTRY, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}


/*hnat qos*/
int HwNatDscpRemarkEbl(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_DSCP_REMARK, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatVpriRemarkEbl(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_VPRI_REMARK, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetFoeWeight(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_FOE_WEIGHT, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetAclWeight(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_ACL_WEIGHT, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetDscpWeight(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_DSCP_WEIGHT, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetVpriWeight(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_VPRI_WEIGHT, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetDscp_Up(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_DSCP_UP, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetUp_InDscp(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_UP_IDSCP, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetUp_OutDscp(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_UP_ODSCP, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetUp_Vpri(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_UP_VPRI, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}
int HwNatSetUp_Ac(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_UP_AC, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetSchMode(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_SCH_MODE, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetSchWeight(struct hwnat_qos_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_SCH_WEIGHT, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}


int HwNatSetBindThreshold(struct hwnat_config_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_BIND_THRESHOLD, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetMaxEntryRateLimit(struct hwnat_config_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_MAX_ENTRY_LMT, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}


int HwNatSetRuleSize(struct hwnat_config_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_RULE_SIZE, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetKaInterval(struct hwnat_config_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_KA_INTERVAL, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}




int HwNatSetUnbindLifeTime(struct hwnat_config_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_UB_LIFETIME, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatSetBindLifeTime(struct hwnat_config_args *opt)
{
    int fd;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_BIND_LIFETIME, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;

}

int HwNatGetAllEntries(struct hwnat_args *opt)
{
    int fd=0;
    int i=0;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_GET_ALL_ENTRIES, opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    
    printf("Total Entry Count = %d\n",opt->num_of_entries);	
    for(i=0;i<opt->num_of_entries;i++){
	if(opt->entries[i].fmt==0) { //IPV4_NAPT
	    printf("%d : %u.%u.%u.%u:%d->%u.%u.%u.%u:%d => %u.%u.%u.%u:%d->%u.%u.%u.%u:%d\n", \
		    opt->entries[i].hash_index, \
		    NIPQUAD(opt->entries[i].sip), \
		    opt->entries[i].sport, \
		    NIPQUAD(opt->entries[i].dip), \
		    opt->entries[i].dport, \
		    NIPQUAD(opt->entries[i].new_sip), \
		    opt->entries[i].new_sport, \
		    NIPQUAD(opt->entries[i].new_dip), \
		    opt->entries[i].new_dport);
	} else if(opt->entries[i].fmt==1) { //IPV4_NAT
	    printf("%d : %u.%u.%u.%u->%u.%u.%u.%u => %u.%u.%u.%u->%u.%u.%u.%u\n", \
		    opt->entries[i].hash_index, \
		    NIPQUAD(opt->entries[i].sip), \
		    NIPQUAD(opt->entries[i].dip), \
		    NIPQUAD(opt->entries[i].new_sip), \
		    NIPQUAD(opt->entries[i].new_dip)); 
	} else if(opt->entries[i].fmt==2) { //IPV6_ROUTING
		    printf("IPv6 Entry= %d /%s/DIP: %x:%x:%x:%x:%x:%x:%x:%x\n", \
		    opt->entries[i].hash_index, \
		    opt->entries[i].is_udp?"udp":"tcp", \
		    NIPHALF(opt->entries[i].ipv6_dip3), \
		    NIPHALF(opt->entries[i].ipv6_dip2), \
		    NIPHALF(opt->entries[i].ipv6_dip1), \
		    NIPHALF(opt->entries[i].ipv6_dip0));
	} else{
	    printf("Wrong entry format!\n");
	}
    }

    return HWNAT_SUCCESS;

}

int HwNatDebug(unsigned int debug)
{
    struct hwnat_args opt;
    int fd;

    opt.debug=debug;

    fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
    if (fd < 0)
    {
	printf("Open %s pseudo device failed\n","/dev/"HW_NAT_DEVNAME);
	return HWNAT_FAIL;
    }

    if(ioctl(fd, HW_NAT_DEBUG, &opt)<0) {
	printf("HW_NAT_API: ioctl error\n");
	close(fd);
	return HWNAT_FAIL;
    }

    close(fd);
    return HWNAT_SUCCESS;
}
