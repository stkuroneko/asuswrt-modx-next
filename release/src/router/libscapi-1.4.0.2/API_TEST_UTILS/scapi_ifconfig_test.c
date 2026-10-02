#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include <ltq_api_include.h>

int main(int argc, char** argv)
{
        char ip[INET_ADDRSTRLEN] = {0};
        char netmask[INET_ADDRSTRLEN] = {0};
        char mac[SCAPI_MAC_LEN] = {0};
        int txqueuelen = -1;
        bool updown_status = false;

        int ip_ret = scapi_getIfcIpaddr(argv[1], ip);
        printf("ip_ret = %d, ip got = %s\n", ip_ret, ip);

        int netmask_ret = scapi_getIfcNetmask(argv[1], netmask);
        printf("netmask_ret = %d, netmask got = %s\n", netmask_ret, netmask);

        int mac_ret = scapi_getIfcMacaddr(argv[1], mac);
        printf("mac_ret = %d, mac got = %s\n", mac_ret, mac);

        int updown_status_ret = scapi_getIfcUpdown(argv[1], &updown_status);
        printf("updown_status_ret = %d, updown_status got = %d\n", updown_status_ret, updown_status);

        int txqueuelen_ret = scapi_getIfcTxQueuelen(argv[1], &txqueuelen);
        printf("txqueuelen_ret = %d, txqueuelen got = %d\n", txqueuelen_ret, txqueuelen);

        ip_ret = scapi_setIfcIpaddr(argv[1], "192.168.1.5");
        netmask_ret = scapi_setIfcNetmask(argv[1], "255.255.255.0");
        mac_ret = scapi_setIfcMacaddr(argv[1], "00:E0:92:FF:FF:FF", -1);
        txqueuelen_ret = scapi_setIfcTxQueuelen(argv[1], 500);
        
	if(atoi(argv[2]) == 0)
                updown_status_ret= scapi_setIfcUpdown(argv[1], false);
        else if(atoi(argv[2]) == 1)
                updown_status_ret= scapi_setIfcUpdown(argv[1], true);
        printf("updown status = %d\n", updown_status_ret);

        return 0;
}
