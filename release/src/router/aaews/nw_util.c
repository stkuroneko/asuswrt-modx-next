#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <log.h>
#include <netdb.h>
#include "ws_api.h"
#include "nw_util.h"
#include "common.h"
#include "shared.h"
#include "ipaddr.h"
#include "stun.h"
#include "nat_nvram.h"
#define APP_DBG 1

struct stun_server stun_list[] = {
    {"stun.l.google.com", GOOGLE_STUN_PORT},
    {"stun1.l.google.com", GOOGLE_STUN_PORT},
    {"stun2.l.google.com", GOOGLE_STUN_PORT},
    {"stun3.l.google.com", GOOGLE_STUN_PORT},
    {"stun4.l.google.com", GOOGLE_STUN_PORT},
    //{"stun.iptel.org", DEFAULT_STUN_PORT},
    //{"stun.stunprotocol.org", DEFAULT_STUN_PORT},
    //{"stun.xten.com", DEFAULT_STUN_PORT}
};
#define STUN_LIST_SIZE (sizeof(stun_list)/sizeof(stun_list[0]))

int get_mac(unsigned char* mac_address)
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024]; memset(buf, 0, 1024);
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
	  /* handle error*/
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>> get ock error =-1");	
		return -1;
	};

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
	  /* handle error */ 
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>>> ioctl sock error =-1");
		goto err;
	}

   struct ifreq* it = ifc.ifc_req;
   const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

   for (; it != end; ++it) {
	  strcpy(ifr.ifr_name, it->ifr_name);
	  Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>> ifr_name =%s", it->ifr_name);
	  if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
		 if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
			   success = 1;
			   break;
			}
		 }
	  }
	  else {
		Cdbg(APP_DBG, ">>>>>>>>>>>>>>>>> ioctl SIOCGIFFLAGS failed");
		 /* handle error */
	  }
   }

   //unsigned char mac_address[6];

	if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
err:
	if (sock >= 0)
		close(sock);
	return 0;
}

int is_private_ip_old = -1;

//#define WAN_IP1 "wan0_ipaddr"
//#define WAN_IP2 "wan1_ipaddr"
//char* g_cur_wan_ip2=NULL;
unsigned int g_org_wan_ip_int=0;
//char* g_org_wan_ip2=NULL;
int check_wan_ip_change(void)
{
	int is_change = 0;
	const char* g_cur_wan_ip = get_wanip();

	if( !g_org_wan_ip_int ) {

		is_change = 1;
		goto _CHECK_WAN_IP_CHANGE_EXIT;
	} else if( g_cur_wan_ip && ( g_org_wan_ip_int != inet_addr(g_cur_wan_ip)) ) {

		is_change = 1;
		goto _CHECK_WAN_IP_CHANGE_EXIT;
	}

	_CHECK_WAN_IP_CHANGE_EXIT:

	g_org_wan_ip_int = inet_addr(g_cur_wan_ip);

	return is_change;
}

int get_src_ip( unsigned int * ipaddr )
{
	GetServiceArea 	gsa;
	int rand_value = 0, get_mac_status = 0;
	char aae_account[ACCOUNT_LEN];
	char aae_pwd[PWD_LEN] ;
    char fwver[128];
    char *model_name;
	char mac_str[MAC_LEN];
	memset(mac_str, 0, sizeof(mac_str));
#if NVRAM
    get_mac_status = nvram_get_mac_addr(mac_str);
#else
    unsigned char mac_addr[7]={0};
    get_mac_status = get_mac(mac_addr);
    sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
#endif

	if(get_mac_status<0) 
		return -1;
	memset(aae_account, 0, sizeof(aae_account));
	memset(aae_pwd, 0, sizeof(aae_pwd));	
	sprintf(aae_account, "%s@asuscomm.com", mac_str);
	srand(time(NULL));
	rand_value = rand()%100 +2000;
	sprintf(aae_pwd, "%d", rand_value);

    snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
    model_name = nvram_safe_get(NVRAM_MODEL_NAME);

	memset(&gsa, 0, sizeof(gsa));
	send_getservicearea_req(
		SERVER,	//
        ASUS_DEVICE_SERVICE, 
		aae_account,
		aae_pwd,
        DEVICE_TYPE,
        fwver,
        AIHOME_API_LEVEL,
        model_name,
		&gsa);

	*ipaddr =  inet_addr(gsa.srcip);

	return 0;
}

unsigned int get_device_public_ip(unsigned int wan_ip_addr) {
	unsigned int device_public_ip = 0;
	struct in_addr in_realip;
	char prefix[16];
	char realip[32];
	char tmp[100];
	snprintf(realip, sizeof(realip), "%s", nvram_safe_get(strcat_r(prefix, "realip_ip", tmp)));
	if(nvram_get_int(strcat_r(prefix, "realip_state", tmp)) == 2 && 
		strlen(realip) > 0 && 
		inet_aton(realip, &in_realip) != 0) {
		device_public_ip = (unsigned int)in_realip.s_addr;

		Cdbg(APP_DBG, "get_device_public_ip realip=%s realip_int=%d\n", realip, device_public_ip);
	} else {
		unsigned int stun_ip=0;
		int i=0,i_base=0;
		struct hostent *stun_host_info=NULL;
		/* stun related  */
		srand(time(NULL)+wan_ip_addr);
		i_base = rand() % STUN_LIST_SIZE;
		//mastiff_errlog("check if the IP address is public");
		//printf("start from server %d\n",i_base);
		Cdbg(APP_DBG, "start from server %d\n",i_base);
		i = 0;
		while( 1 ) {
			if( i == STUN_LIST_SIZE ) {
				//using asus server while all google stun server are failed
				if( get_src_ip(&device_public_ip) >= 0)
					return device_public_ip;
				break;
			}
			stun_host_info = NULL;
			stun_host_info = gethostbyname( stun_list[ (i+i_base) % STUN_LIST_SIZE ].url);
			if( !stun_host_info ) {
				sleep(10);
				i++;
				continue;
			}

			memcpy(&stun_ip,stun_host_info->h_addr_list[0],4);

			if( !send_binding_request(stun_ip, stun_list[ (i+i_base) % STUN_LIST_SIZE ].port, &device_public_ip) ){
				break;
			}

			i++;
		}
	}
	return device_public_ip;
}

int is_in_private_list(const char *str_addr) {
	int num_of_list = sizeof(priv_ip_net) / sizeof(struct private_ip_list);
	int i;
	ip_info_t ii;
	struct in_addr addr;
	uint32_t t_ip;
#if 0
	char ceilstr[INET6_ADDRSTRLEN];
	char floorstr[INET6_ADDRSTRLEN];
	char mskstr[INET6_ADDRSTRLEN];
#endif
	if (!str_addr || inet_aton(str_addr, &addr) == 0)
		return -1;
	for (i = 0; i < num_of_list; i++) {
		// cidr
		ii.cidr = priv_ip_net[i].cidr;
		// subnet floor address
		inet_pton(AF_INET, priv_ip_net[i].addr, &ii.floor);
		// subnet mask
		t_ip = ntohl(strtoul(priv_ip_net[i].mask, NULL, 16));
		ii.netmask.s_addr = ~t_ip;
		// subnet ceil address aka broadcast
		ii.ceil.s_addr = ii.floor.s_addr ^ ~ii.netmask.s_addr;
#if 0
		inet_ntop(AF_INET, &ii.floor, floorstr, INET_ADDRSTRLEN);
		fprintf(stderr, "addr=%16s[0x%08x], addr=[%16s]\n", priv_ip_net[i].addr, ii.floor.s_addr, floorstr);

		inet_ntop(AF_INET, &ii.netmask, mskstr, INET_ADDRSTRLEN);
		fprintf(stderr, "<<<<netmask=%16s[0x%08x]\n", mskstr, ii.netmask.s_addr);

		inet_ntop(AF_INET, &ii.ceil, ceilstr, INET_ADDRSTRLEN);
		fprintf(stderr, "ceil=s%16s[0x%08x]\n", ceilstr, ii.ceil.s_addr);

		inet_ntop(AF_INET, &ii.floor, floorstr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ii.ceil, ceilstr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ii.netmask, mskstr, INET_ADDRSTRLEN);
		fprintf(stderr, "floor=[%s], ceil=[%s], mask=[%s]\n", floorstr, ceilstr, mskstr);
#endif
		if ((htonl(addr.s_addr) & htonl(ii.netmask.s_addr)) == 
			(htonl(ii.floor.s_addr) & htonl(ii.netmask.s_addr))) {
			return 1;
		}
	}
	return 0;
}

int is_private_ip(int caller) {
	unsigned int wan_ip_addr=0,device_public_ip=0;
	const char* nv_wan_ipaddr;
	int sw_mode = sw_mode();

	if (nvram_get_int("aae_dbg")) {
		return nvram_get_int("aae_private_ip");
	}

	if(sw_mode==SW_MODE_REPEATER||sw_mode==SW_MODE_AP||sw_mode==SW_MODE_HOTSPOT)
		return 1;

	nv_wan_ipaddr = get_wanip();
	//Cdbg(APP_DBG, "(%d) nv_wan_ipaddr %s...1\n", caller, nv_wan_ipaddr);

	wan_ip_addr = inet_addr(nv_wan_ipaddr);

	wan_ip_addr = htonl( wan_ip_addr );

	if( wan_ip_addr == 0 )
	{
		//mastiff_errlog("no IP, do nothing");
		g_org_wan_ip_int = wan_ip_addr;

		if(is_private_ip_old == -1)
			return 0;

		return is_private_ip_old;
	}

	//Cdbg(APP_DBG, "(%d) nv_wan_ipaddr %s...2\n", caller, nv_wan_ipaddr);
	if( !check_wan_ip_change() ){

		if(is_private_ip_old == -1)
			return 0;

		return is_private_ip_old;
	}
	//printf("is_private_ip_old %d\n",is_private_ip_old);
	Cdbg(APP_DBG, "(%d) is_private_ip_old %d\n", caller, is_private_ip_old);

	device_public_ip = get_device_public_ip(wan_ip_addr);
	if (device_public_ip == 0) {
		if (is_in_private_list(nv_wan_ipaddr) != 0) {
			is_private_ip_old = 1;
			return 1;
		}
	} else {
		if(  wan_ip_addr  != htonl( device_public_ip ) ){
			is_private_ip_old = 1;
			return 1;
		}
	}

	is_private_ip_old = 0;
	return 0;
}

