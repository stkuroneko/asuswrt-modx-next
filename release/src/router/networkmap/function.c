#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <stdio.h>
//#include <linux/in.h>
#if !(defined(__GLIBC__) || defined(__UCLIBC__))
#include <netinet/if_ether.h>
#endif
#include <linux/if_ether.h>
#include <net/if.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <bcmnvram.h>
#include "networkmap.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <asm/byteorder.h>
#include <iboxcom.h>
#include <shutils.h>

#ifdef RTCONFIG_NOTIFICATION_CENTER
#include <libnt.h>
extern int call_notify_center(int sort, int event);
#endif

#include <json.h>

void toLowerCase(char *str) {
	char *p;

	for(p=str;*p!='\0';p++)
		if('A'<=*p&&*p<='Z')*p+=32;

}

void Device_name_filter(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	unsigned char filter[] = "android";
	unsigned char *name2lower;

	name2lower = strdup(p_client_detail_info_tab->device_name[x]);
	toLowerCase(name2lower);
	
	if(strstr(name2lower, filter)) {
		memset(p_client_detail_info_tab->device_name[x], 0, sizeof(p_client_detail_info_tab->device_name[x]));
		if(p_client_detail_info_tab->vendor_name[x][0] != '\0' && strlen(p_client_detail_info_tab->vendor_name[x]) <= 22) {
			sprintf(p_client_detail_info_tab->device_name[x], 
				"%s(android)\0", p_client_detail_info_tab->vendor_name[x]);
		}
		else
			sprintf(p_client_detail_info_tab->device_name[x], "%s\0", filter);
	}
	free(name2lower);
	NMP_DEBUG("android device filter:\n%s\n", p_client_detail_info_tab->device_name[x]);
}

void type_filter(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x, unsigned char type, unsigned char base, int isDev)
{
	int ret = 0;
	unsigned char pBase = p_client_detail_info_tab->os_type[x];
	// unsigned char pType = p_client_detail_info_tab->type[x];

	/* filter desktop/laptop first */
	if(type == 34 && (base == BASE_TYPE_WINDOW || base == BASE_TYPE_ASUS)) {
		p_client_detail_info_tab->type[x] = type;
		ret = 1;
	}
	/* handle ASUS device here since OUI may not be found */
	else if((type == 28 || type == 29) && (base == BASE_TYPE_ANDROID || base == BASE_TYPE_ASUS)) {
		p_client_detail_info_tab->type[x] = type;
		ret = 1;
	}
	/* default base type -> no filter */
	else if(!base) {
		p_client_detail_info_tab->type[x] = type;
		ret = 1;
	}
	/* match os_type and base type */
	else if(base == pBase) {
		p_client_detail_info_tab->type[x] = type;
		ret = 1;
	/* match os_type and base type */
	// else if((pType == 0) && (pBase == 0)) {
	// else if(pType == 0) {
	} else {
		p_client_detail_info_tab->type[x] = type;
		p_client_detail_info_tab->os_type[x] = base;
	}

	NMP_DEBUG("%s: define type = %d, os_type = %d \n", __FUNCTION__, p_client_detail_info_tab->type[x], p_client_detail_info_tab->os_type[x]);

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
	if(ret && isDev) {
		// write device name 
		if (strcmp((char *)p_client_detail_info_tab->device_name[x], "")) {
			char *host2lower;
			host2lower = strdup(p_client_detail_info_tab->device_name[x]);
			toLowerCase(host2lower);
			if (strstr(host2lower, "android")) {
				strlcpy(p_client_detail_info_tab->device_name[x], p_client_detail_info_tab->bwdpi_device[x], 
					sizeof(p_client_detail_info_tab->device_name[x]));
			}
			free(host2lower);
		} //write anyway cause it is empty 
		else {
			strlcpy(p_client_detail_info_tab->device_name[x], p_client_detail_info_tab->bwdpi_device[x], 
				sizeof(p_client_detail_info_tab->device_name[x]));
		}

		//write device column(for UI)
		if (strcmp((char *)p_client_detail_info_tab->bwdpi_device[x], "")) {
			strlcpy(p_client_detail_info_tab->apple_model[x], p_client_detail_info_tab->bwdpi_device[x], 
				sizeof(p_client_detail_info_tab->apple_model[x]));
			NMP_DEBUG("*** Add BWDPI device model %s\n", p_client_detail_info_tab->apple_model[x]);
		}
	}
#endif
}

int isBaseType(int type)
{
	if(type == TYPE_LINUX_DEVICE || type == TYPE_WINDOWS || type == TYPE_ANDROID)
		return 1;
	else
		return 0; 
}

int FindHostname(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i)
{
	unsigned char *dest_ip = p_client_detail_info_tab->ip_addr[i];
	unsigned char *real_mac = p_client_detail_info_tab->mac_addr[i];
	char ipaddr[16];
	char macaddr[20];
	sprintf(ipaddr, "%d.%d.%d.%d",(int)*(dest_ip),(int)*(dest_ip+1),(int)*(dest_ip+2),(int)*(dest_ip+3));
	sprintf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",(int)*(real_mac),(int)*(real_mac+1),(int)*(real_mac+2),(int)*(real_mac+3),(int)*(real_mac+4),(int)*(real_mac+5));

	char *nv, *nvp, *b;
	char *mac, *ip, *name, *expire, *device2lower;
	FILE *fp;
	char line[256];
	char *next;
	unsigned char typeID = 0, baseID = 0;

	// Get current hostname from DHCP leases
	if (!nvram_get_int("dhcp_enable_x") || !nvram_match("sw_mode", "1"))
		return 0;

	if ((fp = fopen("/var/lib/misc/dnsmasq.leases", "r"))) {
		fcntl(fileno(fp), F_SETFL, fcntl(fileno(fp), F_GETFL) | O_NONBLOCK);
		while ((next = fgets(line, sizeof(line), fp)) != NULL) {
			if (vstrsep(next, " ", &expire, &mac, &ip, &name) == 4) {
				if ((!strcmp(ipaddr, ip)) &&
						(strlen(name) > 0) &&
						(!strchr(name, '*')) &&	// Ensure it's not a clientid in
						(!strchr(name, ':')))	// case device didn't have a hostname
				{
					strlcpy(p_client_detail_info_tab->device_name[i], name, sizeof(p_client_detail_info_tab->device_name[i]));
					//save dhcp host name 
					strlcpy(p_client_detail_info_tab->device_type[i], name, sizeof(p_client_detail_info_tab->device_type[i]));
					extern ac_state *acType;


					// if(p_client_detail_info_tab->type[i] == 0 ) {
					// 	device2lower = strdup(p_client_detail_info_tab->device_name[i]);
					// 	toLowerCase(device2lower);
					// 	if((typeID = full_search(acType, device2lower, &baseID))) {

					// 		p_client_detail_info_tab->type[i] = typeID;
					// 		p_client_detail_info_tab->os_type[i] = baseID;

					// 		// type_filter(p_client_detail_info_tab, i, typeID, baseID, 0);
					// 		NMP_DEBUG("FindHostname >> DHCP: Find type = %d, os_type = %d \n", typeID, baseID);
					// 	}
					// 	free(device2lower);
					// }

					if(!p_client_detail_info_tab->type[i] || isBaseType(p_client_detail_info_tab->type[i])) {
						device2lower = strdup(p_client_detail_info_tab->device_name[i]);
						toLowerCase(device2lower);
						if((typeID = full_search(acType, device2lower, &baseID))) {
							type_filter(p_client_detail_info_tab, i, typeID, baseID, 0);
							NMP_DEBUG("FindHostname >> DHCP: Find type = %d, os_type = %d \n", typeID, baseID);
						}
						free(device2lower);
					
					}

					Device_name_filter(p_client_detail_info_tab, i);
#ifdef RTCONFIG_NOTIFICATION_CENTER
					if(p_client_detail_info_tab->type[i] == 1)
						call_notify_center(FLAG_SAMBA_INLAN, HINT_SAMBA_INLAN_EVENT);
					if(p_client_detail_info_tab->type[i] == 7)
						call_notify_center(FLAG_XBOX_PS, HINT_XBOX_PS_EVENT);
					if(p_client_detail_info_tab->type[i] == 27)
						call_notify_center(FLAG_UPNP_RENDERER, HINT_UPNP_RENDERER_EVENT);
					if(p_client_detail_info_tab->type[i] == 6)
						call_notify_center(FLAG_OSX_INLAN, HINT_OSX_INLAN_EVENT);
#endif
				}
				//ipMethod: DHCP
				if (!strcmp(ipaddr, ip)) {
					strlcpy(p_client_detail_info_tab->ipMethod[i], "DHCP", sizeof(p_client_detail_info_tab->ipMethod[i]));
					//check real mac in dhcp lease
					if(strcmp(macaddr, mac)) {
						sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
								&p_client_detail_info_tab->mac_addr[i][0], &p_client_detail_info_tab->mac_addr[i][1],
								&p_client_detail_info_tab->mac_addr[i][2], &p_client_detail_info_tab->mac_addr[i][3],
								&p_client_detail_info_tab->mac_addr[i][4], &p_client_detail_info_tab->mac_addr[i][5]);
					}
				}
			}	
		}
		fclose(fp);
	}

	// Get names from static lease list, overruling anything else
	nv = nvp = strdup(nvram_safe_get("dhcp_staticlist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", &mac, &ip) == 2) && (strlen(ip) > 0)) {
				if (!strcmp(ipaddr, ip)) {
					strlcpy(p_client_detail_info_tab->ipMethod[i], "Manual",
						sizeof(p_client_detail_info_tab->ipMethod[i]));
				}
			}
		}
		free(nv);
	}

	return 1;
}

int FindDevice(unsigned char *pIP, unsigned char *pMac, int replaceMac)
{
	int ret = 0;
	unsigned char *dest_ip = pIP;
	unsigned char *real_mac = pMac;
	char ipaddr[16];
	char macaddr[20];
	sprintf(ipaddr, "%d.%d.%d.%d",(int)*(dest_ip),(int)*(dest_ip+1),(int)*(dest_ip+2),(int)*(dest_ip+3));
	sprintf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",(int)*(real_mac),(int)*(real_mac+1),(int)*(real_mac+2),(int)*(real_mac+3),(int)*(real_mac+4),(int)*(real_mac+5));

	char *mac, *ip, *name, *expire;
	FILE *fp;
	char line[256];
	char *next;

	// Get current hostname from DHCP leases
	if (!nvram_get_int("dhcp_enable_x") || !nvram_match("sw_mode", "1"))
		return ret;

	if ((fp = fopen("/var/lib/misc/dnsmasq.leases", "r"))) {
		fcntl(fileno(fp), F_SETFL, fcntl(fileno(fp), F_GETFL) | O_NONBLOCK);
		while ((next = fgets(line, sizeof(line), fp)) != NULL) {
			if (vstrsep(next, " ", &expire, &mac, &ip, &name) == 4) {
				if (replaceMac) {
					if (!strcmp(ipaddr, ip)) {
						//check real mac in dhcp lease
						if(strcmp(macaddr, mac)) {
							sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &pMac[0], &pMac[1], &pMac[2], &pMac[3], &pMac[4], &pMac[5]);
						}
						ret = 1;				
						break;
					}
				}
				else {
					if (!strcmp(macaddr, mac)) {
						//replace IP
						if(strcmp(ipaddr, ip)) {
							sscanf(ip, "%hhu.%hhu.%hhu.%hhu\0", &pIP[0], &pIP[1], &pIP[2], &pIP[3]);
						}
						ret = 1;				
						break;
					}
				}
			}	
		}
		fclose(fp);
	}
	return ret;
}
