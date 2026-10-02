/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2004, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */
#include "rc.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>															
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <wlutils.h>

/* The field index of subnet_rulelist */
enum {
	SUBNET_NAME = 0,
	SUBNET_IP,
	SUBNET_MASK,
	SUBNET_DHCP_ENABLE,
	SUBNET_DHCP_START,
	SUBNET_DHCP_END,
	SUBNET_DHCP_LEASE,
	DOMAIN_NAME,
	DNS,
	WINS_SERVER,
	ENABLE_MANUAL_ASSIGNMENT,
	MAC_IP_BINDING,
	FORWARDLIST
};

#define VLAN_PORT_STATUS_NOTHING  	0x0
#define VLAN_PORT_STATUS_UNTAGGED  	0x1
#define VLAN_PORT_STATUS_TAGGED  	0x2
#define VLAN_PORT_STATUS_BOTH	  	0x3

int netmask_bits(char *input)
{
        int ret=0;
        unsigned int in=0;
        int i=0;

        if( !input )
                return -1;

        if( ( in = inet_network(input) ) == -1 )
        {
                if(!strcmp("255.255.255.255",input))
                        return 32;
                return -1;
        }

        while(1)
        {
                if( i == 32 )
                        break;
                if( (( in >> ( 32 - i - 1) ) & 1) == 0 ){
                        _dprintf("[netmask_bits]%x %d\n", in,( in >> ( 32 - i - 1) ) & 1  );
                        break;
                }
                i++;
                ret++;
        }

        return ret;
}


char *get_subnet_info_field(char *subnet_index, int field, char *result )
{
	char *nv, *nvp, *b;
	char *ip;
	char *netmask;
	char *dhcp_enable;
	char *dhcp_start; 
	char *dhcp_end;
	char *lease;
	char *domainname;
	char *dns;
	char *wins;
	char *ema;
	char *macipbinding;
	//char *forwardlist;
	int found = 0;
	int netmask_int=0;
	char ipandmask[32] = {0};

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ( vstrsep(b, ">",	&ip, &netmask, &dhcp_enable, 
									&dhcp_start, &dhcp_end, &lease, &domainname, 
									&dns, &wins ,&ema ,&macipbinding ) != 11 )
				continue;

			memset(ipandmask,0,32);
			netmask_int = netmask_bits(netmask);
			sprintf(ipandmask,"%s/%d",ip,netmask_int);
			//_dprintf("%s %s\n",ipandmask,subnet_index);
			if (!strcmp(ipandmask, subnet_index)) {
				if (field == SUBNET_IP) sprintf(result, "%s", ip);
				else if (field == SUBNET_MASK) sprintf(result, "%s", netmask);
				else if (field == SUBNET_DHCP_ENABLE) sprintf(result, "%s", dhcp_enable);
				else if (field == SUBNET_DHCP_START) sprintf(result, "%s", dhcp_start);
				else if (field == SUBNET_DHCP_END) sprintf(result, "%s", dhcp_end);
				else if (field == SUBNET_DHCP_LEASE) sprintf(result, "%s", lease);
				else if (field == DOMAIN_NAME) sprintf(result, "%s", domainname);
				else if (field == DNS) sprintf(result, "%s", dns);
				else if (field == WINS_SERVER) sprintf(result, "%s", wins);
				else if (field == ENABLE_MANUAL_ASSIGNMENT) sprintf(result, "%s", ema);
				else if (field == MAC_IP_BINDING) sprintf(result, "%s", macipbinding);
				//else if (field == FORWARDLIST) sprintf(result, "%s", forwardlist);
				found = 1;
				break;
			}
		}
		free(nv);
	}

	if (found) return result;

	if (field == SUBNET_IP || field == SUBNET_MASK) {
		sprintf(result, "0.0.0.0");
		return result;
	}

	return NULL;
}

#define RTKSWITCH_DEV	"/dev/rtkswitch"

static int switch_check(void)
{
	int fd=0,ret=0;
	int *p = NULL;

	fd = open(RTKSWITCH_DEV, O_RDONLY);
	if (fd < 0) {
		_dprintf(".\n");
		return -1;
	}

	ret = ioctl(fd, 297, p);
	if ( ret != 8067 ) {
		_dprintf(".\n");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}



static int vlan_check(void)
{
	if ( nvram_get_int("led_failover_gpio") != 26 ){ return -1;}
	if ( nvram_get_int("btn_rst_gpio") != 4150 ){ return -1;}
	if ( nvram_get_int("led_pwr_red_gpio") != 57 ){ return -1;}
	if ( nvram_get_int("led_usb_gpio") != 8199 ){ return -1;}
	if ( nvram_get_int("btn_wps_gpio") != 4112 ){ return -1;}
	if ( nvram_get_int("led_2g_gpio") != 8260 ){ return -1;}
	if ( nvram_get_int("btn_ejusb1_gpio") != 4625 ){ return -1;}
	if ( nvram_get_int("led_usb3_gpio") != 8207 ){ return -1;}
	if ( nvram_get_int("led_wan_gpio") != 8201 ){ return -1;}
	if ( nvram_get_int("led_5g_gpio") != 8259 ){ return -1;}
	if ( nvram_get_int("led_sata_gpio") != 8217 ){ return -1;}
	if ( nvram_get_int("led_wps_gpio") != 53 ){ return -1;}
	//if ( nvram_get_int("led_turbo_gpio") != 255 ){ return -1;}
	//if ( nvram_get_int("led_lan_gpio") != 255 ){ return -1;}
	//if ( nvram_get_int("btn_radio_gpio") != 255 ){ return -1;}
	//if ( nvram_get_int("pwr_usb_gpio") != 255 ){ return -1;}
	//if ( nvram_get_int("led_all_gpio") != 255 ){ return -1;}
	//if ( nvram_get_int("have_fan_gpio") != 255 ){ return -1;}
	if ( nvram_get_int("led_wan_red_gpio") != 56 ){ return -1;}
	if ( nvram_get_int("led_wan2_red_gpio") != 55 ){ return -1;}
	//if ( nvram_get_int("fan_gpio") != 255 ){ return -1;}
	if ( nvram_get_int("btn_ejusb2_gpio") != 4376 ){ return -1;}
	if ( nvram_get_int("led_pwr_gpio") != 53 ){ return -1;}
	if ( nvram_get_int("led_wan2_gpio") != 8198 ){ return -1;}
	//if ( nvram_get_int("pwr_usb_gpio2") != 255 ){ return -1;}
	if ( switch_check() ){ return -1;}

	return 0;
}

int vlan_enable( void )
{
	char *nv, *nvp, *b;
	//<enable>WAN>LAN>WiFi-2G>WiFi-5G>Subnet>VLAN Tag<enable>
	char *enable, *vid, *prio, *wanportset, *lanportset, *wl2gset;
	char *wl5gset, *subnet_name, *internet, *public_vlan;

	int vlan_enable = 0;

	//asus hardware check
	if( vlan_check() )
		return vlan_enable;

	//media bridge mode does not support VLAN
	if(sw_mode() == SW_MODE_REPEATER && nvram_get_int("wlc_psta") == 1)
		return vlan_enable;

	if(nvram_get_int("vlan_enable") != 1)
		return vlan_enable;

	nv = nvp = strdup(nvram_safe_get("vlan_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			
			if ((vstrsep(b, ">", 	&enable, 		&vid, 			&prio, 
									&wanportset, 	&lanportset, 	&wl2gset, 
									&wl5gset, 		&subnet_name,	&internet, 
									&public_vlan ) != 10))
				continue;
			
			if ( atoi(enable) ) {
				vlan_enable = 1;
				break;
			}
		}

		free(nv);
	}

	return vlan_enable;
}

void clean_vlan_config( void )
{
	int index=0,i;
	char lan_prefix[] = "lanXXXXXXXXX_",tmp[32];

	index = nvram_get_int("vlan_index");
	if( index < VLAN_START_IFNAMES_INDEX)
		return;
	//nvram_unset
	for ( i = VLAN_START_IFNAMES_INDEX; i < index; ++i )
	{
		/* code */
		snprintf(lan_prefix, sizeof(lan_prefix), "lan%d_", index);
		memset(tmp,0,32);
		nvram_unset(strcat_r(lan_prefix, "ifname", tmp));

		memset(tmp,0,32);
		nvram_unset(strcat_r(lan_prefix, "ifnames", tmp));

		memset(tmp,0,32);
		nvram_unset(strcat_r(lan_prefix, "subnet", tmp));

		memset(tmp,0,32);
		nvram_unset(strcat_r(lan_prefix, "vlaninfo", tmp));									
	}

	nvram_unset( "vlan_index" );

}

void set_default_vlan_config(
						int vlan_id_tmp,
						int vlan_prio_tmp,
						int lanportset )
{
	char vlaninfo[64] = {0};
	/* set lanX_vlaninfo */
	sprintf(vlaninfo, "%d,%d,%d", vlan_id_tmp, vlan_prio_tmp, lanportset);
	nvram_set("default_vlaninfo", vlaninfo);
}

void set_vlan_config( 	int index, 
						int vlan_id_tmp,
						int vlan_prio_tmp,
						int lanportset,
						int wlmap,
						char *subnet_name,
						char *vlan_if )
{
	int unit = 0, subunit = 0, subunit_x = 0, max_mssid;
	char brif[8] = "brXXX", tmp[64], lan_prefix[] = "lanXXXXXXXXX_";
	char vlaninfo[64] = {0};
	char word[256], *next;
	char wl_ifnames[32], nv[32];
	char wl_if_map = 0;
	int wl_radio = 0, wl_bss_enabled = 0;
	char *p;

	memset(wl_ifnames, 0x0, sizeof(wl_ifnames));
	p = wl_ifnames;	

	snprintf(brif, sizeof(brif), "br%d", index);
	
	snprintf(lan_prefix, sizeof(lan_prefix), "lan%d_", index);

	/* set lanX_ifname */
	memset(tmp, 0, 64);
	nvram_set(strcat_r(lan_prefix, "ifname", tmp), brif);
	
	/* set lanX_subnet */
	memset(tmp, 0, 64);
	nvram_set(strcat_r(lan_prefix, "subnet", tmp), subnet_name);
	
	/* set lanX_vlaninfo */
	memset(tmp, 0, 64);
	sprintf(vlaninfo, "%d,%d,%d", vlan_id_tmp, vlan_prio_tmp, lanportset);
	nvram_set(strcat_r(lan_prefix, "vlaninfo", tmp), vlaninfo);

	/* set lanX_ifnames */
	if (vlan_if != NULL) {
		char vlaniftmp[16]={0};
		sprintf(vlaniftmp,"%s",vlan_if);
		nvram_set(strcat_r	(lan_prefix, "ifnames", tmp), vlaniftmp);
		p += sprintf(p, "%s ", nvram_safe_get(strcat_r(lan_prefix, "ifnames", tmp)));
	}

	foreach (word, nvram_safe_get("wl_ifnames"), next) {		
		SKIP_ABSENT_BAND_AND_INC_UNIT(unit);
		memset(nv, 0x0, sizeof(nv));
		snprintf(nv, sizeof(nv), "wl%d_radio", unit);
		wl_radio = nvram_get_int(nv);

		if ( wl_radio ) {		
			wl_if_map = (wlmap >> (unit * 16)) & 0x1;
	
			/* Primary wl */
			if ( wl_if_map ) {
				p += sprintf(p, "%s ", word);
			}

			/* Virtual wl */
			max_mssid = num_of_mssid_support(unit);
			for (subunit = 1; subunit < max_mssid + 1; subunit++)
			{
				int wl_vif_map = (wlmap >> (unit * 16 + subunit)) & 0x1;
				
				subunit_x++;

				memset(nv, 0x0, sizeof(nv));
				snprintf(nv, sizeof(nv), "wl%d.%d_bss_enabled", unit, subunit);
				wl_bss_enabled = nvram_get_int(nv);
				if (wl_bss_enabled) {
					if ( wl_vif_map ) {
						p += sprintf(p, "%s ", get_wlxy_ifname(unit, subunit, tmp));
					}											
				}
			}
		}

		unit++;
		subunit_x = 0;
	}
	
	if (strlen(wl_ifnames)) {
		nvram_set(strcat_r(lan_prefix, "ifnames", tmp), wl_ifnames);
		//printf(">>>>>>>>>>>%d>>>>>>>>>>>>>\n\n\n",index);
		nvram_set_int("vlan_index", index);
	}
}


int check_if_exist_vlan_ifnames(char *ifname_in)
{
	int i = 0;
	int vlan_index = nvram_get_int("vlan_index");
	char *lan_ifnames, *ifname, *p;
	char nv[32];

	/* Check the ifname of lan_ifnames whether existing in other lanX_ifnames for vlan */
	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_ifnames", i);

		//if (strstr(nvram_safe_get(nv), ifname))
		//	return 1;
		if ((lan_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
			p = lan_ifnames;
			while ((ifname = strsep(&p, " ")) != NULL) {
				while (*ifname == ' ') ++ifname;
				if (*ifname == 0) continue;
				// bring up interface
				if (strcmp(ifname, ifname_in) == 0) {
					free(lan_ifnames);
					return 1;
				}
			}
			free(lan_ifnames);
		}
	}

	return 0;
}

void get_lan_if_for_vlan(char *ifname,int size)
{
#if defined(BRTAC828) || defined(RTAD7200)
	char *wans_dualwan = NULL;

	wans_dualwan = nvram_safe_get("wans_dualwan");
	if( wans_dualwan && strstr(wans_dualwan,"lan") )
	{
		memset(ifname,0,size);
		strncpy(ifname,"eth2",4);
	} else {
		memset(ifname,0,size);
		strncpy(ifname,"bond0",5);
	}
#endif
}

void get_default_vlaninfo(int *vid, int *prio, int *portlist)
{
	char *nv, *nvp;
	nv = nvp = strdup(nvram_safe_get("default_vlaninfo"));

	if( nv ){
		sscanf(nv,"%d,%d,%d",vid,prio,portlist);
		free(nv);
		_dprintf("%d,%d,%d",*vid,*prio,*portlist);
		return;
	}

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);

	return;
}

int pvid_to_pprio(int pvid)
{
	char *nv, *nvp, *b;
	char *enable, *vid, *prio, *wanportset, *lanportset, *wl2gset;
	char *wl5gset, *subnet_name, *internet, *public_vlan;
	int ret = -1;

	nv = nvp = strdup(nvram_safe_get("vlan_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", 	&enable, 		&vid, 			&prio, 
									&wanportset, 	&lanportset, 	&wl2gset, 
									&wl5gset, 		&subnet_name,	&internet,
									&public_vlan ) != 10))
				continue;

			if (strlen(vid) && (pvid == atoi(vid)) ){
				ret =  atoi(prio);
				break;
			}
		}

		free(nv);
	}

	return ret;
}

void str_to_int(char *in,int *out,int size)
{
	int i=0,j=0,ret=0;

	*out = 0;

	for(i=0,j=size-1;j>=0;i++,j--)
	{
		printf("%c\n",in[j]);

		switch(in[j]){
			case '0':
				ret |= 0 <<(i*4);
				break;
			case '1':
				ret |= 1 <<(i*4);
				break;
			case '2':
				ret |= 2 <<(i*4);
				break;
			case '3':
				ret |= 3 <<(i*4);
				break;
			case '4':
				ret |= 4 <<(i*4);
				break;
			case '5':
				ret |= 5 <<(i*4);
				break;
			case '6':
				ret |= 6 <<(i*4);
				break;
			case '7':
				ret |= 7 <<(i*4);
				break;
			case '8':
				ret |= 8 <<(i*4);
				break;
			case '9':
				ret |= 9 <<(i*4);
				break;
			case 'a':
			case 'A':
				ret |= 0xa <<(i*4);
				break;
			case 'b':
			case 'B':
				ret |= 0xb <<(i*4);
				break;
			case 'c':
			case 'C':
				ret |= 0xc <<(i*4);
				break;
			case 'd':
			case 'D':
				ret |= 0xd <<(i*4);
				break;
			case 'e':
			case 'E':
				ret |= 0xe <<(i*4);
				break;
			case 'f':
			case 'F':
				ret |= 0xf <<(i*4);
				break;
		}

	}

	*out = ret;
}


#if defined(BRTAC828) || defined(RTAD7200)
void pvid_info_get_brtac828(int *pvid_array)
{
	char *nv, *nvp;
	char *pvid1=NULL,*pvid2=NULL,*pvid3=NULL,*pvid4=NULL,*pvid5=NULL,*pvid6=NULL,*pvid7=NULL,*pvid8=NULL;
	int i;
	char *wan,*lan,*wl2g,*wl5g;
	int lan_allow_list=0;


    nv = nvp = strdup(nvram_safe_get("vlan_if_list"));
	if (nv) {
		if ((vstrsep(nvp, ">",&wan,&lan,&wl2g,&wl5g) != 4))
		{
			_dprintf("get allow list error\n");
		} else {
			str_to_int(lan,&lan_allow_list,4);
		}
		free(nv);
	}

	nv = nvp = strdup(nvram_safe_get("vlan_pvid_list"));

	if (nv) {
			if ((vstrsep(nvp, ">", &pvid1, &pvid2, &pvid3, &pvid4, &pvid5, &pvid6, &pvid7, &pvid8) != 8))
			{
				for(i=0;i<8;i++)
					pvid_array[i] = 1;	
			} else {
				pvid_array[0] = atoi(pvid1);
				pvid_array[1] = atoi(pvid2);
				pvid_array[2] = atoi(pvid3);
				pvid_array[3] = atoi(pvid4);
				pvid_array[4] = atoi(pvid5);
				pvid_array[5] = atoi(pvid6);
				pvid_array[6] = atoi(pvid7);
				pvid_array[7] = atoi(pvid8);
			}
			free(nv);
	} else {
		for(i=0;i<8;i++)
			pvid_array[i] = 1;
	}

	for(i=0;i<8;i++){
		if( ! (lan_allow_list & 1 << i) )
			pvid_array[i] = 0;
		_dprintf("arrar[%d] %d\n",i,pvid_array[i]);		
	}
}

void pvid_to_pprio_brtac828(int *pvid, int *pprio)
{
	int i=0;
	for(i=0;i<8;i++){
		pprio[i] = pvid_to_pprio(pvid[i]);
		if(pprio[i] < 0 || pprio[i] > 7)
			pprio[i] = 0;
	}

	for(i=0;i<8;i++)
		_dprintf("port prio[%d] %d\n",i,pprio[i]);	

}
#endif

void config_PVID( void )
{
#if defined(BRTAC828) || defined(RTAD7200)
	int pvid[8]={0};
	int pprio[8]={0};

	pvid_info_get_brtac828(pvid);
	pvid_to_pprio_brtac828(pvid,pprio);

	vlan_switch_pvid_setup(pvid,pprio,8);
#endif
}

void vlan_port_status_setting(void)
{
	char *list=NULL,tmp=0,size=0,i=0;

	list = nvram_safe_get("vlan_port_status_list");
	if(list)
	{
		tmp = list[0];
		size = atoi(&tmp);
		if(size != 1) //should be 1 in brt ac828
			return;

		tmp = list[1];
		size = atoi(&tmp); 
		if( size != 8 ) //should be 8 in brt ac828
			return;

		for(i=0;i<size;i++)
		{
			tmp = list[2+i];
			switch(atoi(&tmp) ){
				case VLAN_PORT_STATUS_NOTHING:
					break;
				case VLAN_PORT_STATUS_UNTAGGED:
					vlan_switch_accept_untagged(i);
					break;
				case VLAN_PORT_STATUS_TAGGED:
					vlan_switch_accept_tagged(i);
					break;
				case VLAN_PORT_STATUS_BOTH:
					vlan_switch_accept_all(i);
					break;
				default:
					break;
			}
		}
	}
	//vlan_switch_accept_tagged(tagged_only_list);
	//vlan_switch_accept_untagged(untagged_only_list);
	//vlan_switch_accept_all(both_list);

	//return ret;
}

void start_tagged_based_vlan(char *input)
{
	int i;
	int vlan_index = nvram_get_int("vlan_index");
	int wifionly = 0;
	int vlan_id_def, vlan_prio_def, lanportset_def;
	char lan_prefix[32]={0};
	char lan_vlan_if[32]={0};

	if( input && !strncmp(input,"wifionly",8) ){
		wifionly = 1;
	}

	if (!vlan_enable())
		return;

	/* get LAN interface for VLAN interface */	
	get_lan_if_for_vlan(lan_vlan_if,32);

	/* set all ports status: untag or tag or both */
	vlan_port_status_setting();

	/* set VLAN1 switch config */
	get_default_vlaninfo(&vlan_id_def, &vlan_prio_def, &lanportset_def);
	vlan_switch_setup(vlan_id_def, vlan_prio_def, lanportset_def);

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		char *lan_ifname;
		struct ifreq ifr;
		char *lan_ifnames, *ifname, *lan_subnet, *p;
		int hwaddrset = 0;
		char eabuf[32];
		int sfd = -1;
		char nv[32],vlan_id_str[32];
		char ip[32], mask[32];
		int vlan_id, vlan_prio, lanportset;

		vlan_id = 0;
		vlan_prio = 0;
		lanportset = 0;
		memset(lan_prefix,0,32);
		sprintf(lan_prefix,"lan%d_",i);
		get_vlan_info_by_lanX(lan_prefix,&vlan_id, &vlan_prio, &lanportset);

		if(!wifionly) {	
			if ((sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
				return;
			vlan_switch_setup(vlan_id, vlan_prio, lanportset);
		}

		eval("vconfig", "set_name_type", "VLAN_PLUS_VID_NO_PAD");

		memset(vlan_id_str,0,sizeof(vlan_id_str));
		sprintf(vlan_id_str,"%d",vlan_id);
		eval("vconfig", "add", lan_vlan_if , vlan_id_str);

		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_ifname", i);


		lan_ifname = strdup(nvram_safe_get(nv));
		if (strncmp(lan_ifname, "br", 2) == 0) {
			
			if(!wifionly) {	
				
				_dprintf("%s: setting up the bridge %s\n", __FUNCTION__, lan_ifname);
				eval("brctl", "addbr", lan_ifname);
				eval("brctl", "setfd", lan_ifname, "0");
				if (is_routing_enabled())
					eval("brctl", "stp", lan_ifname, nvram_safe_get("lan_stp"));
				else
					eval("brctl", "stp", lan_ifname, "0");
#ifdef RTCONFIG_IPV6
				if ((get_ipv6_service() != IPV6_DISABLED) &&
					(!((nvram_get_int(ipv6_nvname("ipv6_accept_ra")) & 2) != 0 && !nvram_get_int(ipv6_nvname("ipv6_radvd")))))
				{
					ipv6_sysconf(lan_ifname, "accept_ra", 0);
					ipv6_sysconf(lan_ifname, "forwarding", 0);
				}
				set_intf_ipv6_dad(lan_ifname, 1, 1);
#endif
#ifdef RTCONFIG_EMF
				if (nvram_get_int("emf_enable")) {
					eval("emf", "add", "bridge", lan_ifname);
					eval("igs", "add", "bridge", lan_ifname);
				}
#endif

				hwaddrset = 0;
			}
			
			memset(nv, 0x0, sizeof(nv));
			snprintf(nv, sizeof(nv), "lan%d_ifnames", i);
			if ((lan_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
				p = lan_ifnames;
				while ((ifname = strsep(&p, " ")) != NULL) {
					while (*ifname == ' ') ++ifname;
					if (*ifname == 0) continue;
					// bring up interface
					if (strncmp(ifname, "vlan", 4) == 0) {
						if (ifconfig(ifname, IFUP, NULL, NULL) != 0)
							continue;
					}
					
					if(!wifionly){
						// set the logical bridge address to that of the first interface
						strlcpy(ifr.ifr_name, lan_ifname, IFNAMSIZ);
						if ((!hwaddrset) ||
						    (ioctl(sfd, SIOCGIFHWADDR, &ifr) == 0 &&
						    memcmp(ifr.ifr_hwaddr.sa_data, "\0\0\0\0\0\0", 6 ) == 0)) {
							strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
							if (ioctl(sfd, SIOCGIFHWADDR, &ifr) == 0) {
								strlcpy(ifr.ifr_name, lan_ifname, IFNAMSIZ);
								ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
								_dprintf("%s: setting MAC of %s bridge to %s\n", __FUNCTION__,
									ifr.ifr_name, ether_etoa(ifr.ifr_hwaddr.sa_data, eabuf));
								ioctl(sfd, SIOCSIFHWADDR, &ifr);
								hwaddrset = 1;
							}
						}
					}
				
					//eval("brctl", "delif", "br0" , ifname);
					eval("brctl", "addif", lan_ifname, ifname);
#ifdef RTCONFIG_EMF
					if (nvram_get_int("emf_enable"))
						eval("emf", "add", "iface", lan_ifname, ifname);
#endif
				}
				
				free(lan_ifnames);
			}
			
		}
		// --- this shouldn't happen ---
		else if (*lan_ifname) {
			ifconfig(lan_ifname, IFUP, NULL, NULL);
		}
		else {
			close(sfd);
			free(lan_ifname);
			continue;
		}
		
		if(!wifionly){
			
			close(sfd);
		// bring up and configure LAN interface
			memset(nv, 0x0, sizeof(nv));
			snprintf(nv, sizeof(nv), "lan%d_subnet", i);
			lan_subnet = nvram_safe_get(nv);
			memset(ip,0,32);
			memset(mask,0,32);
			if( lan_subnet && (strlen(lan_subnet)!=0) && (strcmp(lan_subnet,"none") ) ){
				ifconfig(lan_ifname, IFUP, get_subnet_info_field(lan_subnet, SUBNET_IP, ip), get_subnet_info_field(lan_subnet, SUBNET_MASK, mask));
			}
		}	
		free(lan_ifname);
	}

	config_PVID();
	
	_dprintf("%s %d\n", __FUNCTION__, __LINE__);
}

void stop_vlan_ifnames(void)
{
	int i;
	int vlan_index = nvram_get_int("vlan_index");

	if (!vlan_enable())
		return;

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		char *lan_ifname;
		char *lan_ifnames, *ifname, *p;
		char nv[32];

		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_ifname", i);

		lan_ifname = strdup(nvram_safe_get(nv));

		if(is_routing_enabled())
			del_routes("lan_", "route", lan_ifname);	//del_lan_routes(lan_ifname);

		ifconfig(lan_ifname, 0, NULL, NULL);

		if (strncmp(lan_ifname, "br", 2) == 0) {

#ifdef RTCONFIG_EMF
			//stop_emf(lan_ifname);
			eval("emf", "stop", lan_ifname);
			eval("igs", "del", "bridge", lan_ifname);
			eval("emf", "del", "bridge", lan_ifname);
#endif

			memset(nv, 0x0, sizeof(nv));
			sprintf(nv, "lan%d_ifnames", i);
			if ((lan_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
				p = lan_ifnames;

				while ((ifname = strsep(&p, " ")) != NULL) {
					while (*ifname == ' ') ++ifname;
					if (*ifname == 0) break;

#ifdef CONFIG_BCMWL5
#ifdef RTCONFIG_QTN
					if (strcmp(ifname, "wifi0"))
#endif
					{
						eval("wlconf", ifname, "down");
						eval("wl", "-i", ifname, "radio", "off");
					}
#elif defined RTCONFIG_RALINK
					if (!strncmp(ifname, "ra", 2))
						stop_wds_ra(lan_ifname, ifname);
#endif
					eval("brctl", "delif", lan_ifname, ifname);
					ifconfig(ifname, 0, NULL, NULL);
				}

				free(lan_ifnames);
			}
			eval("brctl", "delbr", lan_ifname);
		}
		else if (*lan_ifname) {
#ifdef CONFIG_BCMWL5
			eval("wlconf", lan_ifname, "down");
			eval("wl", "-i", lan_ifname, "radio", "off");
#endif
		}

		free(lan_ifname);
	}

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);
}
#if 0
void start_vlan_wl_ifnames(void)
{
	int i;
	int vlan_index = nvram_get_int("vlan_index");

	if (!vlan_enable())
		return;

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		char *lan_ifname;
		char *wl_ifnames, *ifname, *p;
		char nv[32];

		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_ifname", i);

		lan_ifname = strdup(nvram_safe_get(nv));
		if (strncmp(lan_ifname, "br", 2) == 0) {
			memset(nv, 0x0, sizeof(nv));
			snprintf(nv, sizeof(nv), "lan%d_ifnames", i);
			if ((wl_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
				p = wl_ifnames;
				printf("%s\n",wl_ifnames);
				while ((ifname = strsep(&p, " ")) != NULL) {
					printf("%s %d\n",ifname,__LINE__);
					while (*ifname == ' ') ++ifname;
					if (*ifname == 0) continue;;
					SKIP_ABSENT_FAKE_IFACE(ifname);

					// bring up interface
					if (strncmp(ifname, "vlan", 4) == 0) {
						if (ifconfig(ifname, IFUP, NULL, NULL) != 0) {
#ifdef RTCONFIG_QTN
							if (strcmp(ifname, "wifi0"))
#endif
								continue;
						}
					}
#ifdef RTCONFIG_DSL	/* for DSL-N55U & DSL-N55U-B */
					if (strncmp(ifname, "eth2", 4) == 0) {
						if (ifconfig(ifname, IFUP, NULL, NULL) != 0)
							continue;
					}
#endif
					//rico check wifi

					if(!strncmp(ifname,"ath003",6)){
						eval("brctl", "delif", "br0", "ath003" );
					}

					printf("\n\nlan_ifname %s ifname %s\n\n\n",lan_ifname, ifname);
					eval("brctl", "addif", lan_ifname, ifname);
#ifdef RTCONFIG_EMF
					if (nvram_get_int("emf_enable"))
						eval("emf", "add", "iface", lan_ifname, ifname);
#endif
				}

				free(wl_ifnames);
			}
		}

		free(lan_ifname);
	}

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);
}
#endif
void stop_vlan_wl_ifnames(void)
{
	int i;
	int vlan_index = nvram_get_int("vlan_index");

	if (!vlan_enable())
		return;

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		char *lan_ifname;
		char *wl_ifnames, *ifname, *p;
		char nv[32];
#ifdef CONFIG_BCMWL5
		int unit, subunit;
#endif

		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_ifname", i);

		lan_ifname = strdup(nvram_safe_get(nv));
		if (strncmp(lan_ifname, "br", 2) == 0) {
			memset(nv, 0x0, sizeof(nv));
			sprintf(nv, "lan%d_ifnames", i);
			if ((wl_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
				p = wl_ifnames;
				while ((ifname = strsep(&p, " ")) != NULL) {
					while (*ifname == ' ') ++ifname;
					if (*ifname == 0) break;
					SKIP_ABSENT_FAKE_IFACE(ifname);
#ifdef CONFIG_BCMWL5
#ifdef RTCONFIG_QTN
					if (!strcmp(ifname, "wifi0")) continue;
#endif
					if (strncmp(ifname, "wl", 2) == 0 && strchr(ifname, '.')) {
						if (get_ifname_unit(ifname, &unit, &subunit) < 0)
							continue;
					}
					else if (wl_ioctl(ifname, WLC_GET_INSTANCE, &unit, sizeof(unit)))
						continue;

					eval("wlconf", ifname, "down");
					eval("wl", "-i", ifname, "radio", "off");
#elif defined RTCONFIG_RALINK
					if (!strncmp(ifname, "ra", 2))
						stop_wds_ra(lan_ifname, ifname);
#endif
#ifdef RTCONFIG_EMF
					eval("emf", "del", "iface", lan_ifname, ifname);
#endif
					eval("brctl", "delif", lan_ifname, ifname);
					ifconfig(ifname, 0, NULL, NULL);

#if defined (RTCONFIG_WLMODULE_RT3352_INIC_MII)
					{ // remove interface for iNIC packets
						char *nic_if, *nic_ifs, *nic_lan_ifnames;
						if((nic_lan_ifnames = strdup(nvram_safe_get("nic_lan_ifnames"))))
						{
							nic_ifs = nic_lan_ifnames;
							while ((nic_if = strsep(&nic_ifs, " ")) != NULL) {
								while (*nic_if == ' ')
									nic_if++;
								if (*nic_if == 0)
									break;
								if(strcmp(ifname, nic_if) == 0)
								{
									eval("vconfig", "rem", ifname);
									break;
								}
							}
							free(nic_lan_ifnames);
						}
					}
#endif
				}

				free(wl_ifnames);
			}
		}

		free(lan_ifname);
	}

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);
}

int check_used_subnet(char *subnet_name, char *brif)
{
	int result = 0;
	int i;
	int vlan_index = nvram_get_int("vlan_index");

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		char *lan_subnet;
		char nv[32];

		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_subnet", i);
		lan_subnet = nvram_safe_get(nv);

		//printf("%s %s\n",lan_subnet,subnet_name);

		if (lan_subnet != NULL && strcmp(lan_subnet, "none") && strcmp(subnet_name, lan_subnet) == 0) {
			memset(nv, 0x0, sizeof(nv));
			sprintf(nv, "lan%d_ifname", i);
			sprintf(brif, "%s", nvram_safe_get(nv));
			result = 1;
			break;
		}
	}

	return result;
}

int check_used_subnet_no_subnetmask(char *subnet_name, char *brif, int len)
{
	int result = 0;
	int i;
	int vlan_index = nvram_get_int("vlan_index");
	char *lan_subnet;
	char nv[32];

	//default lan
	lan_subnet = nvram_safe_get("lan_ipaddr");

	if (lan_subnet != NULL && strcmp(lan_subnet, "none") && strncmp(subnet_name, lan_subnet,len) == 0) {
		sprintf(brif, "%s", nvram_safe_get("lan_ifname"));
		result = 1;
		return result;
	}

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_subnet", i);
		lan_subnet = nvram_safe_get(nv);

		if (lan_subnet != NULL && strcmp(lan_subnet, "none") && strncmp(subnet_name, lan_subnet,len) == 0) {
			memset(nv, 0x0, sizeof(nv));
			sprintf(nv, "lan%d_ifname", i);
			sprintf(brif, "%s", nvram_safe_get(nv));
			result = 1;
			break;
		}
	}

	return result;
}

int check_internet(char *name)
{
	char *nv, *nvp, *b;
	char *enable, *vid, *prio, *wanportset, *lanportset, *wl2gset;
	char *wl5gset, *subnet_name, *internet, *public_vlan;
	int ret = 0;

	nv = nvp = strdup(nvram_safe_get("vlan_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", 	&enable, 		&vid, 			&prio, 
									&wanportset, 	&lanportset, 	&wl2gset, 
									&wl5gset, 		&subnet_name,	&internet,
									&public_vlan ) != 10))
				continue;

			if (!strcmp(name, subnet_name)) {
				if (strlen(internet))
					ret = atoi(internet);
				break;
			}
		}

		free(nv);
	}

	return ret;
}

int check_intranet_only(char *name)
{
	char *nv, *nvp, *b;
	char *enable, *vid, *prio, *wanportset, *lanportset, *wl2gset;
	char *wl5gset, *subnet_name, *internet, *public_vlan;
	int ret = 0;

	nv = nvp = strdup(nvram_safe_get("vlan_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			if ((vstrsep(b, ">", 	&enable, 		&vid, 			&prio, 
									&wanportset, 	&lanportset, 	&wl2gset, 
									&wl5gset, 		&subnet_name,	&internet,
									&public_vlan ) != 10))
				continue;

			if (!strcmp(name, subnet_name)) {
				if (strlen(internet))
					ret = !atoi(internet);
				break;
			}
		}

		free(nv);
	}

	return ret;
}

void vlan_subnet_dnsmasq_conf(FILE *fp)
{
	char *nv, *nvp, *b;
	char *ip;
	char *netmask;
	char *dhcp_enable;
	char *dhcp_start; 
	char *dhcp_end;
	char *lease;
	char *domainname;
	char *dns;
	char *wins;
	char *ema;
	char *macipbinding;

	int netmask_int=0;
	char ipandmask[32]={0};

	if (!vlan_enable())
		return;

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			char brif[8];
			char count = 0;

			//_dprintf("%s %d - %s\n", __FUNCTION__, __LINE__, b);

			count = vstrsep(b, ">",	&ip, &netmask, &dhcp_enable, 
									&dhcp_start, &dhcp_end, &lease, &domainname, 
									&dns, &wins ,&ema ,&macipbinding );

			if ( count != 11 ){
				_dprintf("%s %d - count (%d)\n", __FUNCTION__, __LINE__, count);
				continue;
			}

			memset(ipandmask,0,32);
			netmask_int = netmask_bits(netmask);
			sprintf(ipandmask,"%s/%d",ip,netmask_int);			

			memset(brif, 0x0, sizeof(brif));
			if (!strcmp(dhcp_enable, "1") && check_used_subnet(ipandmask, brif)) {
				fprintf(fp, "interface=%s\n", brif);
				fprintf(fp, "dhcp-range=%s,%s,%s,%s,%ss\n", brif, dhcp_start, dhcp_end, netmask, lease);
				/* Gateway */
				fprintf(fp, "dhcp-option=%s,3,%s\n", brif, ip);

				/* Domain */
				if( strlen(domainname) )
					fprintf(fp, "dhcp-option=%s,15,%s\n", brif ,domainname);

				/* DNS server and additional router address */
				if ( strlen(dns) )
					fprintf(fp, "dhcp-option=%s,6,%s,0.0.0.0\n", brif, dns);

				/* WINS server */
				if ( strlen(wins) )
					fprintf(fp, "dhcp-option=%s,44,%s\n", brif, wins);

			}
		}
		free(nv);
	}
}

void vlan_subnet_filter_input(FILE *fp)
{
	char *nv, *nvp, *b;
	char *ip;
	char *netmask;
	char *dhcp_enable;
	char *dhcp_start; 
	char *dhcp_end;
	char *lease;
	char *domainname;
	char *dns;
	char *wins;
	char *ema;
	char *macipbinding;
	//char *forwardlist;
	int netmask_int=0;
	char ipandmask[32]={0};

	if ( !vlan_enable() )
		return;

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			char brif[8];
			char count = 0;

			count = vstrsep(b, ">",	&ip, &netmask, &dhcp_enable, 
									&dhcp_start, &dhcp_end, &lease, &domainname, 
									&dns, &wins ,&ema ,&macipbinding );

			if ( count != 11 ){
				_dprintf("%s %d - count (%d)\n", __FUNCTION__, __LINE__, count);
				continue;
			}

			memset(ipandmask,0,32);
			netmask_int = netmask_bits(netmask);
			sprintf(ipandmask,"%s/%d",ip,netmask_int);	

			memset(brif, 0x0, sizeof(brif));

			/* Deny brX to access DNS on the router */
			if (check_used_subnet(ipandmask, brif) && check_intranet_only(ipandmask)) {
				fprintf(fp, "-A INPUT -i %s -p udp --dport 53 -j DROP\n", brif);
				fprintf(fp, "-A INPUT -i %s -p tcp --dport 53 -j DROP\n", brif);
			}

			/*  */
			//if (check_used_subnet(name, brif) && check_internet(name)) {
			//	;
			//}

			/* Access brX from accessing the router's local sockets */
			if (check_used_subnet(ipandmask, brif))
				//fprintf(fp, "-A INPUT -i %s -m state --state NEW -j ACCEPT\n", ifname);
				fprintf(fp, "-A INPUT -i %s -m state --state NEW -j ACCEPT\n", brif);
		}
		free(nv);

		//if (used_flag)
		//	fprintf(fp, "-A INPUT -i br+ -m state --state NEW -j ACCEPT\n");
	}
}

void vlan_subnet_filter_forward(FILE *fp, char *wan_if)
{
	char *nv, *nvp, *b;
	char *ip;
	char *netmask;
	char *dhcp_enable;
	char *dhcp_start; 
	char *dhcp_end;
	char *lease;
	char *domainname;
	char *dns;
	char *wins;
	char *ema;
	char *macipbinding;
	char *forwardlist;
	char *forwardlist_tmp;
	char *forwardlist_entry;

	int netmask_int=0;
	char ipandmask[32]={0};
	char brif[8],brif_tmp[8];
	char count = 0;

	if (!vlan_enable())
		return;

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			count = vstrsep(b, ">",	&ip, &netmask, &dhcp_enable, 
									&dhcp_start, &dhcp_end, &lease, &domainname, 
									&dns, &wins ,&ema ,&macipbinding );

			if ( count != 11 ){
				_dprintf("%s %d - count (%d)\n", __FUNCTION__, __LINE__, count);
				continue;
			}

			memset(ipandmask,0,32);
			netmask_int = netmask_bits(netmask);
			sprintf(ipandmask,"%s/%d",ip,netmask_int);	
			memset(brif, 0x0, sizeof(brif));

			/* Access/Deny brX from accessing the WAN subnet (no internet access) */
			if (check_used_subnet(ipandmask, brif) && !check_intranet_only(ipandmask)) {
				fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", brif, wan_if);
			}
			else
			{
				if (strlen(brif))
					fprintf(fp, "-A FORWARD -i %s -o %s -j DROP\n", brif, wan_if);
			}

		}
		free(nv);
	}

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist_ext"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			count = vstrsep(b, ">",	&ip, &forwardlist);

			if ( count != 2 ){
				_dprintf("%s %d - count (%d)\n", __FUNCTION__, __LINE__, count);
				continue;
			}

			if(!check_used_subnet_no_subnetmask(ip, brif,strlen(ip))) continue;

			forwardlist_tmp=forwardlist;
			while ((forwardlist_entry = strsep(&forwardlist_tmp, ",")) != NULL) {
				//_dprintf("forwardlist_entry %s\n",forwardlist_entry);
				//_dprintf("forwardlist %s\n",forwardlist_tmp); 				
				if (strlen(forwardlist_entry) == 0) continue;
				memset(brif_tmp, 0x0, sizeof(brif_tmp));
				if(!check_used_subnet_no_subnetmask(forwardlist_entry, brif_tmp,strlen(forwardlist_entry))) continue;
				//_dprintf("brif %s brif_tmp %s\n",brif,brif_tmp);
				fprintf(fp, "-A FORWARD -i %s -o %s -j ACCEPT\n", brif, brif_tmp);
			}
		}
		free(nv);
	}
}

int check_exist_subnet_access_rule(int index, int subnet_group_tmp)
{
	int result = 0;
	char *nv, *nvp, *b;
	int i = 1;

	nv = nvp = strdup(nvram_safe_get("gvlan_rulelist"));
	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			int subnet_group_all = 0;
			subnet_group_all = atoi(b);
			
			if ( (subnet_group_all & subnet_group_tmp) == subnet_group_tmp) {
				result = 1;
				break;
			}

			if (++i == index)
				break;
		}
		free(nv);
	}

	return result;
}

void vlan_subnet_deny_input(FILE *fp)
{
	char *nv, *nvp, *b;
	char *ip;
	char *netmask;
	char *dhcp_enable;
	char *dhcp_start; 
	char *dhcp_end;
	char *lease;
	char *domainname;
	char *dns;
	char *wins;
	char *ema;
	char *macipbinding;
	//char *forwardlist;

	int netmask_int=0;
	char ipandmask[32]={0};
	//int used_flag = 0;

	if (!vlan_enable() || !fp)
		return;

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			char brif[8];
			char count = 0;

			count = vstrsep(b, ">",	&ip, &netmask, &dhcp_enable, 
									&dhcp_start, &dhcp_end, &lease, &domainname, 
									&dns, &wins ,&ema ,&macipbinding);

			if ( count != 11 ){
				_dprintf("%s %d - count (%d)\n", __FUNCTION__, __LINE__, count);
				continue;
			}

			memset(ipandmask,0,32);
			netmask_int = netmask_bits(netmask);
			sprintf(ipandmask,"%s/%d",ip,netmask_int);	

			memset(brif, 0x0, sizeof(brif));
			if (check_used_subnet(ipandmask, brif)) {
				//used_flag = 1;
				//fprintf(fp, "-A FORWARD -i ! %s -o %s -j DROP\n", brif, brif);
				_dprintf("-A INPUT ! -i %s -d %s/%s -j DROP\n", brif, ip ,netmask);
				fprintf(fp, "-A INPUT ! -i %s -d %s/%s -j DROP\n", brif, ip, netmask);

				/* drop packet from brX to default br */
				_dprintf("-A INPUT -i %s -d %s/%s -j DROP\n", brif, nvram_safe_get("lan_ipaddr"), nvram_safe_get("lan_netmask"));
				fprintf(fp, "-A INPUT -i %s -d %s/%s -j DROP\n", brif, nvram_safe_get("lan_ipaddr"), nvram_safe_get("lan_netmask"));
			}
		}
		free(nv);

		//if (used_flag) {
			//fprintf(fp, "-A FORWARD -i ! %s -o %s -j DROP\n", nvram_safe_get("lan_ifname"), nvram_safe_get("lan_ifname"));
		//	_dprintf("-A INPUT ! -i %s -d %s/%s -j DROP\n", nvram_safe_get("lan_ifname"), nvram_safe_get("lan_ipaddr"), nvram_safe_get("lan_netmask"));
		//	fprintf(fp, "-A INPUT ! -i %s -d %s/%s -j DROP\n", nvram_safe_get("lan_ifname"), nvram_safe_get("lan_ipaddr"), nvram_safe_get("lan_netmask"));
		//}
	}
}

void vlan_subnet_deny_forward(FILE *fp)
{
	char *nv, *nvp, *b;
	char *ip;
	char *netmask;
	char *dhcp_enable;
	char *dhcp_start; 
	char *dhcp_end;
	char *lease;
	char *domainname;
	char *dns;
	char *wins;
	char *ema;
	char *macipbinding;
	//char *forwardlist;

	int netmask_int=0;
	char ipandmask[32]={0};
	//int used_flag = 0;

	if (!vlan_enable() || !fp )
		return;

	nv = nvp = strdup(nvram_safe_get("subnet_rulelist"));

	if (nv) {
		while ((b = strsep(&nvp, "<")) != NULL) {
			char brif[8];
			char count = 0;

			//_dprintf("%s %d - %s\n", __FUNCTION__, __LINE__, b);

			count = vstrsep(b, ">",	&ip, &netmask, &dhcp_enable, 
									&dhcp_start, &dhcp_end, &lease, &domainname, 
									&dns, &wins ,&ema ,&macipbinding );

			if ( count != 11 ){
				_dprintf("%s %d - count (%d)\n", __FUNCTION__, __LINE__, count);
				continue;
			}

			memset(ipandmask,0,32);
			netmask_int = netmask_bits(netmask);
			sprintf(ipandmask,"%s/%d",ip,netmask_int);	

			memset(brif, 0x0, sizeof(brif));
			if (check_used_subnet(ipandmask, brif)) {
				//used_flag = 1;
				//fprintf(fp, "-A FORWARD -i ! %s -o %s -j DROP\n", brif, brif);
				//_dprintf("-A FORWARD -o %s ! -i %s -j DROP rico\n", brif, brif);
				fprintf(fp, "-A FORWARD -o %s   -i %s -j ACCEPT\n", brif, brif);
				fprintf(fp, "-A FORWARD -o %s   -i br+ -j DROP\n", brif);
				fprintf(fp, "-A FORWARD -o %s   -i %s -j DROP\n", nvram_safe_get("lan_ifname"), brif);
			}
		}
		free(nv);

		//if (used_flag) {
			//fprintf(fp, "-A FORWARD -i ! %s -o %s -j DROP\n", nvram_safe_get("lan_ifname"), nvram_safe_get("lan_ifname"));
			//_dprintf("-A FORWARD -o %s ! -i %s -j DROP rico1\n", nvram_safe_get("lan_ifname"), nvram_safe_get("lan_ifname"));
			//fprintf(fp, "-A FORWARD -o %s ! -i %s -j DROP\n", nvram_safe_get("lan_ifname"), nvram_safe_get("lan_ifname"));
		//}
	}
}

void vlan_lanaccess_mssid(const char *limited_ifname, char *ip, char *netmask, int mode)
{
	char lan_subnet[32];

	if (limited_ifname == NULL) return;

	if (!is_router_mode()) return;

	eval("ebtables", mode ? "-A" : "-D", "FORWARD", "-i", (char*)limited_ifname, "-j", "DROP"); //ebtables FORWARD: "for frames being forwarded by the bridge"
	eval("ebtables", mode ? "-A" : "-D", "FORWARD", "-o", (char*)limited_ifname, "-j", "DROP"); // so that traffic via host and nat is passed

	if (strcmp(ip, "0.0.0.0") && strcmp(netmask, "0.0.0.0")) {
		snprintf(lan_subnet, sizeof(lan_subnet), "%s/%s", ip, netmask);
		eval("ebtables", "-t", "broute", mode ? "-A" : "-D", "BROUTING", "-i", (char*)limited_ifname, "--ip-dst", lan_subnet, "--ip-proto", "tcp", "-j", "DROP");
	}
}

void vlan_lanaccess_wl(void)
{
	int i;
	int vlan_index = nvram_get_int("vlan_index");

	if (!vlan_enable())
		return;

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {

		char *p, *ifname;
		char *wl_ifnames;
		char nv[32];

		memset(nv, 0x0, sizeof(nv));
		sprintf(nv, "lan%d_ifnames", i);

		if ((wl_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
			p = wl_ifnames;
			while ((ifname = strsep(&p, " ")) != NULL) {
				while (*ifname == ' ') ++ifname;
				if (*ifname == 0) break;
				SKIP_ABSENT_FAKE_IFACE(ifname);
				memset(nv, 0x0, sizeof(nv));
				snprintf(nv, sizeof(nv) - 1, "%s_lanaccess", wif_to_vif(ifname));
				char *lan_subnet, ip[32], mask[32];
				memset(nv, 0x0, sizeof(nv));
				snprintf(nv, sizeof(nv), "lan%d_subnet", i);
				lan_subnet = nvram_safe_get(nv);
				if( lan_subnet && (strlen(lan_subnet)!=0) && (strcmp(lan_subnet,"none") ) ){
					_dprintf("vlan_lanaccess_mssid\n");
					memset(ip,0,32);
					memset(mask,0,32);
					vlan_lanaccess_mssid(ifname, get_subnet_info_field(lan_subnet, SUBNET_IP, ip), get_subnet_info_field(lan_subnet, SUBNET_MASK, mask), !strcmp(nvram_safe_get(nv), "off"));
				}
			}
			free(wl_ifnames);
		}
	}
}

int get_vlan_info_by_lanX(char *lan_prefix, int *vid, int *prio, int *portlist)
{
	char tmp[20]={0};
	char *nv, *nvp;
	nv = nvp = strdup(nvram_safe_get(strcat_r(lan_prefix, "vlaninfo", tmp)));

	if( nv ){
		sscanf(nv,"%d,%d,%d",vid,prio,portlist);
		free(nv);
		_dprintf("%d,%d,%d",*vid,*prio,*portlist);
		return 0;
	}

	_dprintf("%s %d\n", __FUNCTION__, __LINE__);

	return -1;
}

//wan wan2 lan1 lan2 lan3 lan4 lan5 lan6 lan7 lan8 wl0 wl0.1 wl0.2 wl0.3 wl1 wl1.1 wl1.2 wl1.3
void vlan_if_allow_list_set(unsigned int wan_allow_list, unsigned int lan_allow_list, unsigned int wl_allow_list)
{
    unsigned char wan=0;
    unsigned char allow_list[256]={0};
    unsigned short lan=0,wl2g=0,wl5g=0;

    wan = wan_allow_list & 0xFF;
    lan = lan_allow_list & 0xFFFF;
    wl2g = wl_allow_list & 0xFFFF;
    wl5g = (wl_allow_list >> 16) & 0xFFFF;

    sprintf(allow_list,"%02X>%04X>%04X>%04X",wan,lan,wl2g,wl5g);

    //printf("%s\n",allow_list);

    nvram_set("vlan_if_list",allow_list);
}

int iptv_and_dualwan_info_get(int *iptv_vids,int size, unsigned int *wan_deny_list, unsigned int *lan_deny_list)
{
	char *wans_dualwan = NULL,*switch_wantag=NULL;
	int wans_lanport=0,switch_stb_x=0;
	unsigned int lan_deny_list_tmp=0;

	lan_deny_list_tmp = *lan_deny_list;

	wans_dualwan = nvram_safe_get("wans_dualwan");
	if( wans_dualwan && strstr(wans_dualwan,"lan") )
	{
		wans_lanport = nvram_get_int("wans_lanport");
		if(wans_lanport >=5 && wans_lanport <= 8){
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (wans_lanport-1) );
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (wans_lanport-1 + 16) );
		}
	}

	switch_wantag = strdup(nvram_safe_get("switch_wantag"));

	if(!switch_wantag) {
		*lan_deny_list = lan_deny_list_tmp;
		return 0;
	}

	if( !strcmp(switch_wantag,"none" ) || !strcmp(switch_wantag,"" ) || !strcmp(switch_wantag,"hinet" ) )   
	{
		switch_stb_x = nvram_get_int("switch_stb_x");

		if(switch_stb_x == 1) {
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (1-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (1-1+16));
		}
		else if(switch_stb_x == 2) {
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (2-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (2-1+16));
		}
		else if(switch_stb_x == 3) {
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
		}
		else if(switch_stb_x == 4) {
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
		}
		else if(switch_stb_x == 5) {
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (1-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (1-1+16));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (2-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (2-1+16));			
		}
		else if(switch_stb_x == 6 || switch_stb_x == 8) {
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
			lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
		}
	} else if ( !strcmp(switch_wantag,"unifi_home" ) ) {
		iptv_vids[0] = 500;
		iptv_vids[1] = 600;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
	} else if ( !strcmp(switch_wantag,"unifi_biz" ) ) {
		iptv_vids[0] = 500;
	} else if ( !strcmp(switch_wantag,"singtel_mio" ) ) {
		iptv_vids[0] = 10;
		iptv_vids[1] = 20;
		iptv_vids[2] = 30;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
	} else if ( !strcmp(switch_wantag,"singtel_others" ) ) {
		iptv_vids[0] = 10;
		iptv_vids[1] = 20;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));//0x00010011
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));		
	} else if ( !strcmp(switch_wantag,"m1_fiber" ) ) {
		iptv_vids[0] = 1103;
		iptv_vids[1] = 1107;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
	} else if ( !strcmp(switch_wantag,"maxis_fiber_sp" ) ) {
		iptv_vids[0] = 11;
		iptv_vids[1] = 14;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
	} else if ( !strcmp(switch_wantag,"maxis_fiber" ) ) {
		iptv_vids[0] = 621;
		iptv_vids[1] = 821;
		iptv_vids[2] = 822;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
	} else if ( !strcmp(switch_wantag,"maxis_cts" ) ) {
		iptv_vids[0] = 41;
		iptv_vids[1] = 44;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
	} else if ( !strcmp(switch_wantag,"maxis_sacofa" ) ) {
		iptv_vids[0] = 31;
		iptv_vids[1] = 34;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
	} else if ( !strcmp(switch_wantag,"maxis_tnb" ) ) {
		iptv_vids[0] = 51;
		iptv_vids[1] = 54;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
	} else if ( !strcmp(switch_wantag,"movistar" ) ) {
		iptv_vids[0] = 2;
		iptv_vids[1] = 3;
		iptv_vids[2] = 6;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
	} else if ( !strcmp(switch_wantag,"meo" ) ) {
		iptv_vids[0] = 12;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
	} else if ( !strcmp(switch_wantag,"manual" ) ) {
		iptv_vids[0] = nvram_get_int("switch_wan0tagid");
		iptv_vids[1] = nvram_get_int("switch_wan1tagid");;
		iptv_vids[2] = nvram_get_int("switch_wan2tagid");;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));		
	} else if ( !strcmp(switch_wantag,"vodafone" ) ) {
		iptv_vids[0] = 100;
		iptv_vids[1] = 105;
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (3-1+16));
		lan_deny_list_tmp = lan_deny_list_tmp & ~(1 << (4-1+16));
	}
	
	*lan_deny_list = lan_deny_list_tmp;
	//printf("lan_deny_list_tmp %x wans_lanport %x\n",lan_deny_list_tmp,wans_lanport);
	free(switch_wantag);
	return 0;
}

void cp_str2list( char * if_list, unsigned int *wl_allow_list)
{
	int size = strlen(if_list);
	int idx = 0;
	char tmp[4];
	unsigned int wl_allow_list_tmp=0;

	wl_allow_list_tmp = *wl_allow_list;
	int if_idx_tmp=0;
	//printf("if_list size = %d\n",size);
	//printf("%d %x %s\n",idx,if_list,if_list+idx);
	while(1)
	{
		if( idx >= size)
			break;

		if( strncmp(if_list+idx,"wl",2) ) {
			_dprintf("captive_portal interfaces parsing error\n");
			break;
		}

		idx+=2;

		if( if_list[idx] == '0' ){
			idx++;
			if ( if_list[idx] == '.' ) {
				idx++;
				memset(tmp,0,4);
				strncpy(tmp,if_list+idx,1);
				//printf("tmp %s\n",tmp);
				if_idx_tmp = atoi(tmp);
				//printf("wl0.%d\n",if_idx_tmp);
				wl_allow_list_tmp &= ~(1 << if_idx_tmp);
				idx++;
			} else if ( if_list[idx] == 'w' ) {
				wl_allow_list_tmp &= ~(1 << 0);
				//printf("wl0\n");
			} else
				_dprintf("captive_portal interfaces parsing error\n");
		} else if( if_list[idx] == '1' ){
			idx++;
			if ( if_list[idx] == '.' ) {
				idx++;
				memset(tmp,0,4);
				strncpy(tmp,if_list+idx,1);
				//printf("tmp %s\n",tmp);
				if_idx_tmp = atoi(tmp);
				//printf("wl1.%d\n",if_idx_tmp);
				wl_allow_list_tmp &= ~(1 << (if_idx_tmp+16));
				idx++;
			} else if ( if_list[idx] == 'w' ) {
				//printf("wl1\n");
				wl_allow_list_tmp &= ~(1 << (0+16) );
			} else
				_dprintf("captive_portal interfaces parsing error\n");
		} 
	}

	 *wl_allow_list = wl_allow_list_tmp;

}

int captive_protal_info_get(unsigned int *wl_allow_list)
{
	char *cp_enable=NULL,*fbwifi_2g=NULL,*fbwifi_5g=NULL;
	char *profileName=NULL, *htmlIdx=NULL,    *awayTime=NULL,   *sessionTime=NULL;
	char *UIPath=NULL,      *ifName=NULL,     *UamAllowed=NULL, *authType=NULL, *RadiusOrNot=NULL;
	char *RadiusIP=NULL,    *RadiusPort=NULL, *RadiusNas=NULL;
	char *nv=NULL, *nvp=NULL, *b=NULL;

	cp_enable = nvram_safe_get("captive_portal_adv_enable");

	if( ! (strncmp(cp_enable,"on",2) ) )
	{
	    nv = nvp = strdup(nvram_safe_get("captive_portal_adv_profile"));

		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &htmlIdx, &profileName, &awayTime, &sessionTime,
					&UIPath, &ifName, &UamAllowed, &authType, &RadiusOrNot, &RadiusIP,
					&RadiusPort, &RadiusNas) != 12 ))
					continue;

					cp_str2list(ifName,wl_allow_list);
			}

			free(nv);
		}
	}

	cp_enable = nvram_safe_get("captive_portal_enable");

	if( !strncmp(cp_enable,"on",2) )
	{
	    nv = nvp = strdup(nvram_safe_get("captive_portal"));

		if (nv) {
			while ((b = strsep(&nvp, "<")) != NULL) {
				if ((vstrsep(b, ">", &htmlIdx, &profileName, &awayTime, &sessionTime,
					&UIPath, &ifName, &UamAllowed) != 7 ))
					continue;

					cp_str2list(ifName,wl_allow_list);
			}

			free(nv);
		}
	}
	//printf("wl_allow_list_tmp %x\n",*wl_allow_list);
	cp_enable = nvram_safe_get("fbwifi_enable");

	if( !strncmp(cp_enable,"on",2) )
	{
		fbwifi_2g = nvram_safe_get("fbwifi_2g");
		if( strncmp(fbwifi_2g,"off",3) ){
		    nv = nvp = strdup(nvram_safe_get("fbwifi_2g"));

			cp_str2list(nv,wl_allow_list);

			free(nv);
		}
		fbwifi_5g = nvram_safe_get("fbwifi_5g");
		if( strncmp(fbwifi_5g,"off",3) ){
		    nv = nvp = strdup(nvram_safe_get("fbwifi_5g"));

			cp_str2list(nv,wl_allow_list);

			free(nv);
		}		
	}
	return 0;

}
unsigned int get_wl_allow_list(void){
	unsigned int ret=0x00010001;
	int if_idx;
	int size=0;
	char tmp[8];
	const char *token =" ";
	char *pch;
	char *nv, *nvp;

	nv = nvp = strdup( nvram_safe_get("wl0_vifnames") );
	if( nv  ){
		pch = strtok(nv, token);
		while (pch != NULL)
		{
			size = strlen(pch);
			if( size > 4 && !strncmp(pch,"wl0.",4) )
			{
				if(size > 12)
					continue;
				memset(tmp,0,8);
				strncpy(tmp,pch+4,size-4);
				if_idx = atoi(tmp);
				if( if_idx > 0 && if_idx < 16 )
				{
					ret |= 1 << if_idx;
				}
			}
			pch = strtok (NULL, token);
		}


		//ret = 0x0000007F;
	} else {
		ret = 0x0000000F;
	}
	free(nvp);

	nv = nvp = strdup( nvram_safe_get("wl1_vifnames") );
	if( nv  ){
		pch = strtok(nv, token);
		while (pch != NULL)
		{
			size = strlen(pch);
			if( size > 4 && !strncmp(pch,"wl1.",4) )
			{
				if(size > 12)
					continue;
				memset(tmp,0,8);
				strncpy(tmp,pch+4,size-4);
				if_idx = atoi(tmp);
				if( if_idx > 0 && if_idx < 16 )
				{
					ret |= 1 << (if_idx+16);
				}
			}
			pch = strtok (NULL, token);
		}
	} else {
		ret |= 0x000F0000;
	}
	free(nvp);

	return ret;
}

void update_vlan_port_status(int *vlan_port_status,int size,unsigned int port_list,int *pvid,int vid)
{
	int i=0;

	//_dprintf("update_vlan_port_status port_list %x\n",port_list);

	for(i=0;i<size;i++){
		if(port_list & (0x00000001 << i))
		{
			/* if pvid != untagged vid, do nothing */
			if(port_list & (0x00010000 << i)){
				//_dprintf("pvid %d %d\n",pvid[i],vid);
				if(pvid[i] == vid){
					vlan_port_status[i] |= VLAN_PORT_STATUS_UNTAGGED;
				}
			}
			else
				vlan_port_status[i] |= VLAN_PORT_STATUS_TAGGED;
		} 
	}
}

void vlan_port_status_set(int *vlan_port_status,int size)
{
    unsigned char vlan_port_status_list[256]={0};
    int i=0,idx=0;

    sprintf(vlan_port_status_list+idx,"%d",1); //first byte is byte num of size
    idx++;
    sprintf(vlan_port_status_list+idx,"%d",size); //this is size of list
    idx++;

    for(i=0;i<size;i++){
    	if(vlan_port_status[i] < 0 || vlan_port_status[i] > 3) {
    		_dprintf("vlan port status list error [%d] %d\n",i,vlan_port_status[i]);
    		sprintf(vlan_port_status_list+idx,"%d",0);
    	}
    	else
    		sprintf(vlan_port_status_list+idx,"%d",vlan_port_status[i]);
    	idx++;
    }
    //printf("%s\n",allow_list);
    //_dprintf("vlan_port_status_list %s\n ",vlan_port_status_list);
    nvram_set("vlan_port_status_list",vlan_port_status_list);
}
/*
	lanX_ifname, lanX_subnet, lanX_ifnames, lanX_vlaninfo
*/
int init_tagged_based_vlan( void )
{
	char *nv, *nvp, *b;
	char *enable, *vlan_id, *vlan_prio, *wanportset, *lanportset;
	char *wl2gset, *wl5gset, *subnet_name,*internet,*public_vlan;
	unsigned int wan_allow_list = 0x00000000;//wan0,wan1
	unsigned int lan_allow_list = 0x00FF00FF;//lan1~8
	unsigned int wl_allow_list  = get_wl_allow_list();//wl0 wl0.1 wl0.2 wl0.3 wl1 wl1.1 wl1.2 wl1.3
	int iptv_vids[3]={0};
	int vlan_port_status[8]={0};/* 0x0=donothing, 0x1=untagged 0x2=tagged 0x3=all */
#if defined(BRTAC828) || defined(RTAD7200)
	int pvid[8]={0};
#endif

	/* clean old configurations */
	clean_vlan_config();

	iptv_and_dualwan_info_get(iptv_vids,3,&wan_allow_list,&lan_allow_list);
	captive_protal_info_get(&wl_allow_list);

	/* check and set configurations */
	if ( vlan_enable() ) {
		/* get pvid information for untag and tagged port usage */
		pvid_info_get_brtac828(pvid);

		nv = nvp = strdup(nvram_safe_get("vlan_rulelist"));

		if (nv) {
			int model;
			int br_index = VLAN_START_IFNAMES_INDEX;

			model = get_model();
			if ( model != MODEL_BRTAC828 && model != MODEL_RTAD7200 ) {
				_dprintf("model != MODEL_BRTAC828 based product\n");
				free(nv);
				
				return -1;
			}

			while ((b = strsep(&nvp, "<")) != NULL) {

				char vlan_name[12];
				unsigned int /*wanportset_tmp=0,*/lanportset_tmp=0,wlset_tmp=0;
				int vlan_id_tmp = 0,vlan_prio_tmp=0;

				if ((vstrsep(b, ">",	&enable,		&vlan_id,	&vlan_prio,	&wanportset, 
										&lanportset,	&wl2gset, 	&wl5gset, 	&subnet_name,	
										&internet, &public_vlan ) != 10))
					continue;

				//_dprintf("%s: %s %s %s %s %s %s\n", __FUNCTION__, enable, vid, priority, portset, wlmap, subnet_name);
				_dprintf("%s:  %s %s %s %s %s %s %s %s %s %s\n", __FUNCTION__, enable, vlan_id, vlan_prio, wanportset, 
							lanportset, wl2gset, wl5gset, subnet_name, internet ,public_vlan);

				if (!strcmp(enable, "0") || strlen(enable) == 0)
					continue;
				if (!strcmp(subnet_name, "0") || strlen(subnet_name) == 0)
					continue;

				/*
				wanportset_tmp = (unsigned int) strtol(wanportset,NULL,16);
				if( wanportset_tmp != 0 )
				{
					total:8 bits, bit0: WAN1
				}
				*/
				lanportset_tmp = (unsigned int) strtol(lanportset,NULL,16);

				vlan_id_tmp = atoi(vlan_id);
				vlan_prio_tmp = atoi(vlan_prio);

				/* ignore iptv vlan id */
				if(vlan_id_tmp == iptv_vids[0] || vlan_id_tmp == iptv_vids[1] || vlan_id_tmp == iptv_vids[2] )
					continue;

				if( vlan_id_tmp < 1 || vlan_id_tmp > 4095 || vlan_prio_tmp < 0 || vlan_prio_tmp > 7 )
				{
					_dprintf("VLAN vaule error vlan %d, prio %d\n",vlan_id_tmp,vlan_prio_tmp);
					continue;
				}

				sprintf(vlan_name, "vlan%d", vlan_id_tmp);

				wlset_tmp = (unsigned int) strtol(wl2gset,NULL,16) | 
							( (unsigned int) strtol(wl5gset,NULL,16) << 16 );

				/* lan allow list check */
				lanportset_tmp = lanportset_tmp & lan_allow_list;

				wlset_tmp = wlset_tmp &	wl_allow_list;// one wifi interface, one vlan

				//printf("lanportset_tmp %x wlset_tmp %x\n",lanportset_tmp,wlset_tmp);
				if( vlan_id_tmp == 1 )
				{
					/* while using a lan port as a WAN port, this LAN port should be an untag member of VLAN1(default VLAN) */
					/* IPTV wan type is none means this wan belong to VLAN1 */
					/* following codes recovering the LAN port set remove by iptv_and_dualwan_info_get() */
					char *switch_wantag = strdup(nvram_safe_get("switch_wantag"));

					/* switch_wantag == NULL means no IPTV */
					if( !switch_wantag || ( switch_wantag && ( 	!strcmp(switch_wantag,"none" ) || 
																!strcmp(switch_wantag,"" ) || 
																!strcmp(switch_wantag,"hinet" )   ) )  )
					{
						char *wans_dualwan = NULL;
						int wans_lanport=0,switch_stb_x=0;

						wans_dualwan = nvram_safe_get("wans_dualwan");
						if( wans_dualwan && strstr(wans_dualwan,"lan") )
						{
							wans_lanport = nvram_get_int("wans_lanport");
							if(wans_lanport >=5 && wans_lanport <= 8){
								lanportset_tmp = lanportset_tmp | (1 << (wans_lanport-1) );
								lanportset_tmp = lanportset_tmp | (1 << (wans_lanport-1 + 16) );
							}
						}

						switch_stb_x = nvram_get_int("switch_stb_x");

						if(switch_stb_x == 1) {
							lanportset_tmp = lanportset_tmp | (1 << (1-1));
							lanportset_tmp = lanportset_tmp | (1 << (1-1+16));
						}
						else if(switch_stb_x == 2) {
							lanportset_tmp = lanportset_tmp | (1 << (2-1));
							lanportset_tmp = lanportset_tmp | (1 << (2-1+16));
						}
						else if(switch_stb_x == 3) {
							lanportset_tmp = lanportset_tmp | (1 << (3-1));
							lanportset_tmp = lanportset_tmp | (1 << (3-1+16));
						}
						else if(switch_stb_x == 4) {
							lanportset_tmp = lanportset_tmp | (1 << (4-1));
							lanportset_tmp = lanportset_tmp | (1 << (4-1+16));
						}
						else if(switch_stb_x == 5) {
							lanportset_tmp = lanportset_tmp | (1 << (1-1));
							lanportset_tmp = lanportset_tmp | (1 << (1-1+16));
							lanportset_tmp = lanportset_tmp | (1 << (2-1));
							lanportset_tmp = lanportset_tmp | (1 << (2-1+16));			
						}
						else if(switch_stb_x == 6 || switch_stb_x == 8) {
							lanportset_tmp = lanportset_tmp | (1 << (3-1));
							lanportset_tmp = lanportset_tmp | (1 << (3-1+16));
							lanportset_tmp = lanportset_tmp | (1 << (4-1));
							lanportset_tmp = lanportset_tmp | (1 << (4-1+16));
						}

					}

					if(switch_wantag)
						free(switch_wantag);	
					set_default_vlan_config(vlan_id_tmp,vlan_prio_tmp,lanportset_tmp);
				} else {
					set_vlan_config(br_index,vlan_id_tmp,vlan_prio_tmp,lanportset_tmp ,wlset_tmp, subnet_name, vlan_name);
					br_index ++;

					wl_allow_list = wl_allow_list & (~wlset_tmp);
				}

				update_vlan_port_status(vlan_port_status,8,lanportset_tmp,pvid,vlan_id_tmp);

				/* check max vlan numbers */
				if( br_index > VLAN_MAX_NUM + VLAN_START_IFNAMES_INDEX )
					break;
			}
			free(nv);
		}
	}


	vlan_port_status_set(vlan_port_status,8);
	vlan_if_allow_list_set(wan_allow_list,lan_allow_list,wl_allow_list);

	return 0;
}

int find_brifname_by_wlifname(const char *wl_ifname, char *brif_name, int size)
{
	int i;
	int vlan_index = nvram_get_int("vlan_index");

	if( !wl_ifname || !brif_name || !strlen(wl_ifname) )
		return 0;

	for (i = VLAN_START_IFNAMES_INDEX; i <= vlan_index; i++) {
		char *lan_ifname;
		char *lan_ifnames, *ifname, *p;
		char nv[32];

		memset( nv, 0x0, sizeof( nv ) );
		sprintf(nv, "lan%d_ifnames", i);

		if ((lan_ifnames = strdup(nvram_safe_get(nv))) != NULL) {
			p = lan_ifnames;
			
			while ((ifname = strsep(&p, " ")) != NULL) {
				while (*ifname == ' ') ++ifname;
				if (*ifname == 0) continue;

				//_dprintf("%s %s\n", ifname , wl_ifname);
				// ignore disabled wl vifs
				if ( strcmp( ifname, wl_ifname ) == 0 ) {
					memset( nv, 0x0, sizeof( nv ) );
					sprintf(nv, "lan%d_ifname", i);					
					lan_ifname = nvram_safe_get(nv);
					if( strlen(lan_ifname) <= size ){
						strncpy(brif_name,lan_ifname,strlen(lan_ifname));
						//_dprintf("%s\n", brif_name);
					}

					free(lan_ifnames);
					return 0;

				}
			}
			
			free(lan_ifnames);
		}
		
	}

	return 0;
}
