#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <shared.h>
#include <rc.h>
#include <wlioctl.h>
#include <bcmendian.h>
#include <wlutils.h>
#include <roamast.h>

#ifdef RTCONFIG_BCN_RPT
#include <pthread.h>
#include <json.h>
#include <security_ipc.h>
#endif

#ifdef RTCONFIG_AMAS
#include <amas_path.h>
#endif
#include <json.h>
#include "lantiq_common.h"

#define STA_INFO_PATH "/tmp/ltq_rast_sta_list"
#define CHANNEL_PATH "/tmp/ltq_rast_channel"
#define HOSTAPD_TO_FAPI_MSG_LENGTH              (4096 * 3)
#define HOSTAPD_TO_FAPI_VALUE_STRING_LENGTH     128
#define RAST_STAMON_GET_RSSI_TIMES 30

#ifdef RTCONFIG_ADV_RAST
rast_maclist_t *r_maclist_old_table[MAX_IF_NUM][MAX_SUBIF_NUM];
#endif

rast_sta_info_t *rast_add_to_assoclist(int unit , int subunit , struct ether_addr *addr);

void get_stainfo(int unit , int subunit )
{
	FILE *fp;
//	char wif_buf[32];
	char line_buf[300];
	char addr[18];
	char rssi[5];
	char txbytes[32];
	char rxbytes[32];
	char txrate[32];
	char rxrate[32];
	unsigned long totalbytes;
	rast_sta_info_t *sta = NULL;
	time_t now = uptime();
	int check_cnt=0;
	char prefix[32];
	char wlif_name[32];
	char tmp[32]={0};
	char *endptr;

	if(subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit, subunit);

	snprintf(wlif_name,sizeof(wlif_name),"%s", nvram_safe_get(strcat_r(prefix, "ifname", tmp)) );

	if (strlen(wlif_name) == 0)
		return;
	RAST_DBG("iw dev %s station dump > %s\n", wlif_name, STA_INFO_PATH);
	doSystem("iw dev %s station dump > %s", wlif_name, STA_INFO_PATH);
	fp = fopen(STA_INFO_PATH, "r");
	if (fp) {
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			if(strstr(line_buf, "Station")) {
				check_cnt = 0;
				sscanf(line_buf, "%*s%s", addr);
				while ( fgets(line_buf, sizeof(line_buf), fp) ) {
					if(strstr(line_buf, "rx bytes")){
						check_cnt++;
						sscanf(line_buf, "%*s%*s%s", rxbytes);
					}
					else if(strstr(line_buf, "tx bytes")){
						check_cnt++;
						sscanf(line_buf, "%*s%*s%s", txbytes);
					}
					else if(strstr(line_buf, "signal")) {
						check_cnt++;
						sscanf(line_buf, "%*s%s", rssi);
					}
					else if(strstr(line_buf, "tx bitrate")) {
						check_cnt++;
						sscanf(line_buf, "%*s%*s%s", txrate);;
					}
					else if(strstr(line_buf, "rx bitrate")) {
						check_cnt++;
						sscanf(line_buf, "%*s%*s%s", rxrate);
						break;
					}
				}

				if(check_cnt != 5){
					RAST_DBG("%s is not a good sta.\n",addr);
					continue;
				}

				totalbytes = atoi(txbytes) + atoi(rxbytes);
				sta = rast_add_to_assoclist(unit , subunit , ether_aton(addr));
				sta->rssi = atoi(rssi);
				if((now - sta->active) && (totalbytes > sta->last_txrx_bytes))
					sta->datarate = ((float)(totalbytes - sta->last_txrx_bytes)/1024) / (float)(now - sta->active);
				else
					sta->datarate = 0;
				sta->last_txrx_bytes = totalbytes;
				sta->tx_rate = atof(txrate)*10000;
				sta->rx_rate = atof(rxrate)*10000;
				sta->tx_byte = (int64)strtoll(txbytes, &endptr, 10);
				sta->rx_byte = (int64)strtoll(rxbytes, &endptr, 10);
				sta->active = now;
			}
		}

		fclose(fp);
		unlink(STA_INFO_PATH);
	}

	return;
}


#ifdef RTCONFIG_ADV_RAST
#define true 1
#define false 0
static bool fieldValuesGet(char *buf, char *stringOfValues, const char *stringToSearch, char *endFieldName[])
{  /* handles list of fields, one by one in the same row */
	char *stringStart;
	char *stringFraction;
	char *localBuf = NULL;
	char *localStringToSearch = NULL;
	int  i;

	localBuf = (char *)malloc((size_t)(strlen(buf) + 1));
	if (localBuf == NULL)
	{
		RAST_INFO("%s; malloc failed ==> ABORT!\n", __FUNCTION__);
		return false;
	}

	/* Add ' ' at the beginning of a string - to handle a case in which the buf starts with the
	value of stringToSearch, like buf= 'candidate=d8:fe:e3:3e:bd:14,2178,83,5,7,255 candidate=...' */
	sprintf(localBuf, " %s", buf);

	/* localStringToSearch set to stringToSearch with addition of " " at the beginning -
	it is a MUST in order to differentiate between "ssid" and "bssid" */
	localStringToSearch = (char *)malloc(strlen(stringToSearch) + 1);
	if(localStringToSearch == NULL)
	{
		RAST_INFO("%s; malloc failed ==> ABORT!\n", __FUNCTION__);
		free((void *)localBuf);
		return false;
	}

	sprintf(localStringToSearch, " %s", stringToSearch);
	stringStart = strstr(localBuf, localStringToSearch);
	if (stringStart == NULL)
	{
		free((void *)localBuf);
		free((void *)localStringToSearch);
		RAST_INFO("%s; input string error ==> ABORT!\n", __FUNCTION__);
		return false;
	}

	/* Get the first value of the field */
	stringFraction = strtok(stringStart, " ");
	if (stringFraction == NULL)
	{
		free((void *)localBuf);
		free((void *)localStringToSearch);
		return false;
	}

	stringFraction += strlen(stringToSearch);
	strcpy(stringOfValues, stringFraction);

	while (1)
	{
		stringFraction = strtok(NULL, " ");

		if (stringFraction == NULL)
		{  /* end of string reached ==> finish */
			free((void *)localBuf);
			free((void *)localStringToSearch);
			return true;
		}

		i = 0;
		while (strcmp(endFieldName[i], "\n"))
		{  /* run over all field names in the string */
			if (!strncmp(stringFraction, endFieldName[i], strlen(endFieldName[i])))
			{  /* field name reached ==> finish */
				free((void *)localBuf);
				free((void *)localStringToSearch);
				return true;
			}

			i++;
		}

		sprintf(stringOfValues, "%s %s", stringOfValues, stringFraction);  /* add the following value to the list */
	}

	free((void *)localBuf);
	free((void *)localStringToSearch);
	return true;
}

/* return 0 means get nothing */
static int _unconnected_sta_rssi_parse(char *buf)
{
	//int 	rcpi=0;
	char    *opCode;
	char    *VAPName;
	char    *MACAddress;
	char    *rx_bytes;
	char    *rx_packets;
	char    stringOfValues[HOSTAPD_TO_FAPI_VALUE_STRING_LENGTH];
	char    *completeBuf = strdup(buf);
	char    *endFieldName[] =
	{ "rssi",
	"\n" };

	int rssi_ret=0,rssi_1=0,rssi_2=0,rssi_3=0,rssi_4=0;

	if (completeBuf == NULL) {
		RAST_INFO("%s; strdup() failed ==> ABORT!\n", __FUNCTION__);
		return rssi_ret;
	}

	opCode = strtok(buf, " ");
	if ( strstr(opCode, "UNCONNECTED-STA-RSSI") != NULL ) {
		VAPName = strtok(NULL, " ");
		if (strncmp(VAPName, "wlan", 4)) {
			RAST_INFO("%s; VAP Name ('%s') is NOT supported ==> Abort!\n", __FUNCTION__, VAPName);
			free((void *)completeBuf);
			return rssi_ret;
		}

		MACAddress = strtok(NULL, " ");
		rx_bytes   = strtok(NULL, " ") + strlen("rx_bytes=");
		rx_packets = strtok(NULL, " ") + strlen("rx_packets=");

		if (fieldValuesGet(completeBuf, stringOfValues, "rssi=", endFieldName)) {
			if(  (strncmp("-128 -128 -128 -128",stringOfValues,19) == 0) ) {
				RAST_DBG("[%d]hostapd_ret_parse %d\n",__LINE__,rssi_ret);
				free((void *)completeBuf);
				return rssi_ret;
			} else {
				sscanf(stringOfValues,"%d %d %d %d",&rssi_1,&rssi_2,&rssi_3,&rssi_4);
				rssi_ret = rssi_1;
				rssi_ret = rssi_ret > rssi_2 ? rssi_ret : rssi_2;
				rssi_ret = rssi_ret > rssi_3 ? rssi_ret : rssi_3;
				rssi_ret = rssi_ret > rssi_4 ? rssi_ret : rssi_4;
				RAST_DBG("[%d]hostapd_ret_parse %d\n",__LINE__,rssi_ret);
				free((void *)completeBuf);
				return rssi_ret;
			}
		}

		RAST_DBG("[%d]hostapd_ret_parse %d\n",__LINE__,rssi_ret);
		free((void *)completeBuf);
		return rssi_ret;
	}  else {
		RAST_DBG("%s; wrong opCode ('%s') ==> Abort!\n", __FUNCTION__, opCode);
		free((void *)completeBuf);
		return rssi_ret;
	} 
}

/* return value : rssi value; 0 means error or gets nothing */
int report_check(struct wpa_ctrl *wpaCtrlPtr)
{
	char    *buf;
	size_t  len = HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char);
	int     rssi_ret=0;

	if (wpaCtrlPtr == NULL) {
		return rssi_ret;
	}

	buf = (char *)malloc((size_t)(HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char)));
	if (buf == NULL) {
		RAST_INFO("%s; malloc error ==> ABORT!\n", __FUNCTION__);
		return rssi_ret;
	}

	memset(buf, 0, HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char));  /* Clear the output buffer */
	if (wpa_ctrl_recv(wpaCtrlPtr, buf, &len) == 0) {
		if (len <= 5) {
			RAST_INFO("%s; '%s' is NOT a report - continue!\n", __FUNCTION__, buf);
			free((void *)buf);
			return rssi_ret;
		}

		rssi_ret = _unconnected_sta_rssi_parse( buf);
		free((void *)buf);
		return rssi_ret;
	} else {
		RAST_INFO("%s; wpa_ctrl_recv() returned ERROR\n", __FUNCTION__);
		free((void *)buf);
		return rssi_ret;
	}

	free((void *)buf);

	return rssi_ret;
}
int get_channel(char *wifname,int *width,int *center_freq1,int *center_freq)
{
	FILE *fp;
	char line_buf[300];
	int ret_conut=0;

	doSystem("cat /proc/net/mtlk/%s/channel > %s", wifname, CHANNEL_PATH);
	fp = fopen(CHANNEL_PATH, "r");
	if (fp) {
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			if(strstr(line_buf, "width")) {
				sscanf(line_buf, "%*s%d", width);
				ret_conut++;
			} else if(strstr(line_buf, "center_freq1")) {
				sscanf(line_buf, "%*s%d", center_freq1);
				ret_conut++;
			} else if(strstr(line_buf, "center_freq"))  {
				sscanf(line_buf, "%*s%d", center_freq);
				ret_conut++;
			}
		}

		fclose(fp);
		unlink(CHANNEL_PATH);
	}

	if(ret_conut == 3)
		return 0;
	return -1;
}

int rast_stamon_get_rssi(int unit , struct ether_addr *addr)
{
	char 	*ifname=NULL;
	char 	macaddr_str[32]={0};
	int 	width=0,center_freq1=0,center_freq=0;
	struct 	wpa_ctrl *wpaCtrlPtr=NULL;
	int  	fd,res,res_wpa_ctrl;
	fd_set 	rfds;
	struct timeval timeout;
	int 	notfirsttimeout=0;
	size_t 	len;
	int 	retry_times=0;
	char 	localBuf[HOSTAPD_TO_FAPI_MSG_LENGTH]={0};
	int 	retry_max=0;
	int 	rssi_sum=0;
	char 	command[] = "UNCONNECTED_STA_RSSI xx:xx:xx:xx:xx:xx xxxx center_freq1=xxxx bandwidth=xx";


	if(!nvram_get_int("wave_ready")){
		RAST_INFO("rast_stamon_get_rssi wave not ready\n");
		return 0;
	}

	if(nvram_get_int("stamon_retry_max"))
		retry_max = nvram_get_int("stamon_retry_max");
	else
		retry_max = RAST_STAMON_GET_RSSI_TIMES;

	ifname = strdup( get_wififname( unit ) );
	if ( !ifname ){
	 	goto rast_stamon_get_rssi_return;
	}
	/* MAC address */
	sprintf( macaddr_str, MACF, ETHERP_TO_MACF( addr ) );
	/* freq & bandwidth */
	if( get_channel( ifname, &width, &center_freq1, &center_freq ) ){
		goto rast_stamon_get_rssi_return;
	}

	sprintf(command,"UNCONNECTED_STA_RSSI %s %d center_freq1=%d bandwidth=%d",macaddr_str,center_freq,center_freq1,width);

	if(unit  == 1)
		wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan2");
	else
		wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan0");

	if (wpaCtrlPtr == NULL) {
		RAST_INFO("%s; ERROR: hostapd_socket_get on band '%d' failed!\n", __FUNCTION__, unit );
		goto rast_stamon_get_rssi_return;
	} else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
		RAST_INFO("%s; ERROR: wpa_ctrl_attach for band '%d' failed!\n", __FUNCTION__, unit );
		wpa_ctrl_close(wpaCtrlPtr);
		goto rast_stamon_get_rssi_return;
	} else {
		fd = wpa_ctrl_get_fd(wpaCtrlPtr);
	}
    /* Main event loop */

	//system("echo 1 >> /tmp/amas_sta_req_cnt");
	//RAST_INFO("=======\n");

    while (1)
    { 	
    	//if(nvram_get_int("stamon_sleep")) usleep(20000); //test only
		if ( retry_times > retry_max )
			break;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		timeout.tv_sec = 0;
		timeout.tv_usec= 100000;
		len=HOSTAPD_TO_FAPI_MSG_LENGTH;
 
		memset(localBuf,0,(4096 * 3) );   
  
		wpa_ctrl_request(wpaCtrlPtr, command, strlen(command), localBuf, &len, NULL);
 
		res = select(fd + 1, &rfds, NULL, NULL, &timeout);
		if (res < 0)
		{
			RAST_INFO("%s; select() return value= %d ==> CONTINUE!!!\n", __FUNCTION__, res);
			retry_times ++;
			continue;
		} else if( res == 0 ) {	
			RAST_INFO("%s; select() return value= %d ==> CONTINUE!!!\n", __FUNCTION__, res);
			retry_times ++;
			continue;
		}
 
		if (FD_ISSET(fd, &rfds)) {		
			retry_times ++;
 
			//res_wpa_ctrl = wpa_ctrl_pending(wpaCtrlPtr);
			//if (res_wpa_ctrl != 1){
			//	RAST_INFO("%s; wpa_ctrl_pending return value= %d ==> BREAK!!!\n", __FUNCTION__, res_wpa_ctrl);
			//	break;  /* quit the 'while' loop */
			//}
 
			res = report_check(wpaCtrlPtr);
			if ( res != 0 ) {
				//get one ret and return		
				rssi_sum=res;
				break;
				//if(!rssi_sum) rssi_sum=res;
				//rssi_sum = res > rssi_sum ? res : rssi_sum;
			}
 				
		}
		if ( res_wpa_ctrl == (-1) ) {  
		/* ERROR - issue a trace */
			RAST_INFO("wpa_ctrl_pending() returned ERROR\n");
		}
	}

	if (wpaCtrlPtr != NULL)
		wpa_ctrl_detach(wpaCtrlPtr);

	wpa_ctrl_close(wpaCtrlPtr);
	wpaCtrlPtr = NULL;

rast_stamon_get_rssi_return:

	if(ifname)
		free(ifname);

	//RAST_INFO("rssi %d\n",rssi_sum);
	//{
	//	char tmp_sss[128]={0};
	//	sprintf(tmp_sss,"echo %d >> /tmp/amas_stamon_rssi_log",rssi_sum);
	//	system(tmp_sss);
	//}

	return rssi_sum;

	//if(nvram_get_int("stamon_ret_real_rssi")) return rssi_sum;
	//return 0;//test only
}
/* 
**deny input addr 
**check input acl_mode,if allow, remove frome list, if deny,add to list
*/

int rast_mac_deny_list_add(int unit, struct ether_addr *addr)
{
	char mac[]= "XX:XX:XX:XX:XX:XX\0";
	char cmd[128]={0};

	sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",	addr->ether_addr_octet[0],
										  	addr->ether_addr_octet[1],
											addr->ether_addr_octet[2],
											addr->ether_addr_octet[3],
											addr->ether_addr_octet[4],
											addr->ether_addr_octet[5]);

	RAST_DBG("Deny %s\n",mac);
	if(!unit) sprintf(cmd, "hostapd_cli -i wlan0 deny_mac %s 0", mac);
	else sprintf(cmd, "hostapd_cli -i wlan2 deny_mac %s 0", mac);

	eval(cmd);
	usleep(100000);

	return 0;
}
/* 
**deny input addr 
**check input acl_mode,if allow, remove frome list, if deny,add to list
*/
int rast_mac_deny_list_remove(int unit, struct ether_addr *addr)
{
	char mac[]= "XX:XX:XX:XX:XX:XX\0";
	char cmd[128]={0};

	sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",	addr->ether_addr_octet[0],
										  	addr->ether_addr_octet[1],
											addr->ether_addr_octet[2],
											addr->ether_addr_octet[3],
											addr->ether_addr_octet[4],
											addr->ether_addr_octet[5]);

	RAST_DBG("Allow %s\n",mac);
	if(!unit) sprintf(cmd, "hostapd_cli -i wlan0 deny_mac %s 1", mac);
	else sprintf(cmd, "hostapd_cli -i wlan2 deny_mac %s 1", mac);

	eval(cmd);
	usleep(100000);
	return 0;
}

/* only be called while init */
void rast_retrieve_static_maclist(int unit, int subunit)
{
	/* init r_maclist_table */
	if(unit < MAX_IF_NUM && subunit < MAX_SUBIF_NUM){
		r_maclist_old_table[unit][subunit] = NULL;
	}	
#if 0
	int ret, size, i;
	//char wlif_name[64];
	struct maclist *maclist = (struct maclist *) maclist_buf;

	char mac[]= "XX:XX:XX:XX:XX:XX";
	//int len=HOSTAPD_TO_FAPI_MSG_LENGTH;
	//struct wpa_ctrl *wpaSocket=NULL;
	//char localBuf[HOSTAPD_TO_FAPI_MSG_LENGTH]={0};
	int num=0;
	char **ret_buf;
	int acl_mode=0;
	int mactmp[6];
	int wave_unit;
	char tmp[100];
	char *b;
	char mac_str_tmp[18]={0};

	/* init r_maclist_table */
	if(unit < MAX_IF_NUM && subunit < MAX_SUBIF_NUM){
		r_maclist_old_table[unit][subunit] = NULL;
	}

	RAST_DBG("[COMM] rast_retrieve_static_maclist %d %d\n",unit,subunit);
	wave_unit = wl_wave_unit(unit);

	if(subunit > 0){
		if(unit == 0) wave_unit = VAP_2G_START + subunit;
		else if(unit ==1) wave_unit = VAP_5G_START + subunit;
	} else 
		subunit = -1;

	//wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	ret = wlan_getMacAddressControlMode(wave_unit,&(bssinfo[unit].static_macmode[subunit]));
	if(ret < 0) {
		RAST_INFO("[WARNING] get macmode error!!!\n");
		return;
	}

	RAST_DBG("[%d %d] macmode = %d %s\n",
	unit,subunit,bssinfo[unit].static_macmode[subunit],
	bssinfo[unit].static_macmode[subunit]==WLC_MACMODE_DISABLED ? "DISABLE" :
	bssinfo[unit].static_macmode[subunit]==WLC_MACMODE_DENY ? "DENY" : "ALLOW");

	wlan_getApAclDevices(wave_unit,&ret_buf,&num);
	for( i=0 ; i<num ; i++ )
		RAST_DBG("rast_retrieve_static_maclist[%d]%s\n",i,ret_buf[i]);

	/* ret_buf[i]={xx:xx:xx:xx:xx:xx} */
	maclist->count = num;
	for(i=0;i<num;i++) {
		memcpy(mac_str_tmp,ret_buf[i],17);
		RAST_DBG("mac_str_tmp %s\n",mac_str_tmp);
		sscanf(mac_str_tmp,"%x:%x:%x:%x:%x:%x"	,&mactmp[0],&mactmp[1],&mactmp[2]
												,&mactmp[3],&mactmp[4],&mactmp[5]);
		maclist->ea[i].ether_addr_octet[0] = mactmp[0];
		maclist->ea[i].ether_addr_octet[1] = mactmp[1];
		maclist->ea[i].ether_addr_octet[2] = mactmp[2];
		maclist->ea[i].ether_addr_octet[3] = mactmp[3];
		maclist->ea[i].ether_addr_octet[4] = mactmp[4];
		maclist->ea[i].ether_addr_octet[5] = mactmp[5];


		RAST_DBG("%x:%x:%x:%x:%x:%x\n"	,maclist->ea[i].ether_addr_octet[0]
												,maclist->ea[i].ether_addr_octet[1]
												,maclist->ea[i].ether_addr_octet[2]
												,maclist->ea[i].ether_addr_octet[3]
												,maclist->ea[i].ether_addr_octet[4]
												,maclist->ea[i].ether_addr_octet[5]);

		free(ret_buf[i]);
	}
	free(ret_buf);

	if (maclist->count > 0 && maclist->count < 128) {
		size = sizeof(uint) + sizeof(struct ether_addr) * (maclist->count + 1);

		RAST_DBG("count[%d] size[%d]\n", maclist->count, size);
		bssinfo[unit ].static_maclist[subunit] = (struct maclist *)malloc(size);
		if (!(bssinfo[unit ].static_maclist[subunit])) {
			RAST_INFO("%s malloc [%d] failure... \n", __FUNCTION__, size);
			return;
		}
		memcpy(bssinfo[unit ].static_maclist[subunit], maclist, size);
		maclist = bssinfo[unit ].static_maclist[subunit];
		for (size = 0; size < maclist->count; size++) {
			RAST_DBG("[%d %d] (%d)mac:"MACF"\n",unit,subunit, size, ETHER_TO_MACF(maclist->ea[size]));
		}
	} else if (maclist->count != 0) {
		RAST_INFO("Err: %d %d maclist cnt [%d] too large\n",
		unit,subunit, maclist->count);
		return;
	}
#endif
}

void rast_set_maclist(int unit , int subunit )
{
	rast_maclist_t *r_maclist_head = bssinfo[unit].maclist[subunit];
	rast_maclist_t *r_maclist_old_head = r_maclist_old_table[unit][subunit];
	rast_maclist_t *r_maclist_old=r_maclist_old_head,*r_maclist=NULL,*r_maclist_old_tmp=NULL,*r_maclist_old_pre=NULL;
	struct maclist *static_maclist = bssinfo[unit].static_maclist[subunit];
	int ret, val;
	struct ether_addr *ea;
	int cnt, match=0;
	char mac[]= "XX:XX:XX:XX:XX:XX\0";

	/* r_maclist diff r_maclist_old */
	/*
		r_maclist : r_maclist_old   :  action
			yes	  : 	yes 		:  can not pass, do nothing
			no	  : 	yes 		:  make it pass
			yes	  : 	no 			:  can not pass, make it not pass				
	*/

	while(r_maclist_old)
	{		
		r_maclist = r_maclist_head;
#if 0
		RAST_INFO("r_maclist_old %x\n",r_maclist_old);
		RAST_INFO("r_maclist_old addr %02x:%02x:%02x:%02x:%02x:%02x",	((struct ether_addr *)(&r_maclist_old->addr))->ether_addr_octet[0],
										  	((struct ether_addr *)(&r_maclist_old->addr))->ether_addr_octet[1],
											((struct ether_addr *)(&r_maclist_old->addr))->ether_addr_octet[2],
											((struct ether_addr *)(&r_maclist_old->addr))->ether_addr_octet[3],
											((struct ether_addr *)(&r_maclist_old->addr))->ether_addr_octet[4],
											((struct ether_addr *)(&r_maclist_old->addr))->ether_addr_octet[5]);
#endif											
		while(r_maclist)
		{			
			if ( memcmp( &(r_maclist->addr), &(r_maclist_old->addr) ,sizeof(struct ether_addr)) == 0) {
				match = 1;
				break;
			}
			r_maclist = r_maclist->next;			
		}
		if(!match) //no	  : 	yes 		:  make it pass
		{				
			if( rast_mac_deny_list_remove(unit,&(r_maclist_old->addr)) )
			{	
				RAST_INFO("rast_mac_deny_list_remove failed\n");
				r_maclist_old_pre = r_maclist_old;
				r_maclist_old = r_maclist_old->next;
				continue;
			}
			if(r_maclist_old_pre == NULL)
			{	
				r_maclist_old_tmp = r_maclist_old;
				r_maclist_old = r_maclist_old->next;
				r_maclist_old_head = r_maclist_old;
				free(r_maclist_old_tmp);
			} else {	
				r_maclist_old_tmp = r_maclist_old;
				r_maclist_old = r_maclist_old->next;
				r_maclist_old_pre->next = r_maclist_old;
				free(r_maclist_old_tmp);		
			}
		} else {	
			match = 0;
			//r_maclist_old_tmp = r_maclist_old;
			r_maclist_old_pre = r_maclist_old;
			r_maclist_old = r_maclist_old->next;
		} 

	}

	r_maclist_old = r_maclist_old_head;
	r_maclist = r_maclist_head;
	match = 0;
	/* r_maclist diff static_maclist */
	//memset(maclist_buf, 0, sizeof(maclist_buf));

	while(r_maclist) {
#if 0
		RAST_INFO("r_maclist %x\n",r_maclist);
		RAST_INFO("r_maclist addr %02x:%02x:%02x:%02x:%02x:%02x\n", 	((struct ether_addr *)(&r_maclist->addr))->ether_addr_octet[0],
										  	((struct ether_addr *)(&r_maclist->addr))->ether_addr_octet[1],
											((struct ether_addr *)(&r_maclist->addr))->ether_addr_octet[2],
											((struct ether_addr *)(&r_maclist->addr))->ether_addr_octet[3],
											((struct ether_addr *)(&r_maclist->addr))->ether_addr_octet[4],
											((struct ether_addr *)(&r_maclist->addr))->ether_addr_octet[5]);
#endif
		r_maclist_old = r_maclist_old_head;
		while(r_maclist_old)
		{
			if ( memcmp( &(r_maclist->addr), &(r_maclist_old->addr) ,sizeof(struct ether_addr)) == 0) {
				match = 1;
				break;
			}
			r_maclist_old = r_maclist_old->next;
		}

		/* record the entry to r_maclist_old */
		if(!match)//yes	  : 	no 			:  can not pass, make it not pass
		{
			if( rast_mac_deny_list_add(unit,&(r_maclist->addr)) )
			{
				RAST_INFO("rast_mac_deny_list_add failed\n");
				r_maclist = r_maclist->next;
				continue;
			}

			while(1){
				if(r_maclist_old == NULL)
					break;
				if(r_maclist_old->next == NULL)
					break;
				r_maclist_old = r_maclist_old->next;
			}

			if(r_maclist_old) {
				r_maclist_old->next = calloc(1,sizeof(rast_maclist_t));
				if(r_maclist_old->next == NULL)
				{
					rast_mac_deny_list_remove(unit,&(r_maclist->addr));
					RAST_INFO("Malloc failed\n");
					return;					
				}
				r_maclist_old = r_maclist_old->next;
				r_maclist_old->next = NULL;
				memcpy(&r_maclist_old->addr,&r_maclist->addr,sizeof(struct ether_addr));
			} else {
				r_maclist_old = calloc(1,sizeof(rast_maclist_t));
				if(r_maclist_old == NULL)
				{
					rast_mac_deny_list_remove(unit,&(r_maclist->addr));
					RAST_INFO("Malloc failed\n");
					return;					
				}
				r_maclist_old->next = NULL;
				memcpy(&r_maclist_old->addr,&r_maclist->addr,sizeof(struct ether_addr));
				r_maclist_old_head = r_maclist_old;
			}

		} 
		r_maclist = r_maclist->next;
		
	}
	/* r_maclist_old reset */
	r_maclist_old_table[unit][subunit] = r_maclist_old_head;
	
}
#if 0
uint8 rast_get_rclass(int unit , int subunit )
{

}

uint8 rast_get_channel(int unit , int subunit )
{

}

int rast_send_bsstrans_req(int unit , int subunit , struct ether_addr *sta_addr, struct ether_addr *nbr_bssid)
{

}
#endif
#endif

int get_channel_number(char *wifname,int *width,int *primary_channel)
{
	FILE *fp;
	char line_buf[300];
	int ret_conut=0;

	doSystem("cat /proc/net/mtlk/%s/channel > %s", wifname, CHANNEL_PATH);
	fp = fopen(CHANNEL_PATH, "r");
	if (fp) {
	        while ( fgets(line_buf, sizeof(line_buf), fp) ) {
	                if(strstr(line_buf, "width")) {
	                        sscanf(line_buf, "%*s%d", width);
	                        ret_conut++;
	                } else if(strstr(line_buf, "primary_channel"))  {
	                        sscanf(line_buf, "%*s%d", primary_channel);
	                        ret_conut++;
	                }
	        }

	        fclose(fp);
	        unlink(CHANNEL_PATH);
	}

	if(ret_conut == 2)
		return 0;
	return -1;
}

#ifdef RTCONFIG_BCN_RPT

char rcpi_to_rssi(char rcpi)
{
	return rcpi;
}
/*	generate beacon request action frame
	
*/
void
rast_send_beacon_request(int unit, int vifidx, struct ether_addr *addr)
{
	char 	*ifname=NULL;
	char 	macaddr_str[32]={0};
	int 	width=0,center_freq1=0,center_freq=0,channel=0;
	struct 	wpa_ctrl *wpaCtrlPtr=NULL;
	int  	fd,res,res_wpa_ctrl;
	fd_set 	rfds;
	struct timeval timeout;
	int 	notfirsttimeout=0;
	size_t 	len;
	char 	prefix[16];
	char 	localBuf[HOSTAPD_TO_FAPI_MSG_LENGTH]={0};
	char 	command[1024] = {0};

	int num_of_repetitions=0;
	int measurement_request_mode=0;
	/*
	For operating classes that identify the location of the primary channel, a Channel Number field value of 0
	indicates a request to make iterative measurements for all supported channels in the operating class where
	the measurement is permitted on the channel and the channel is valid for the current regulatory domain.
	*/	
	int operating_class=0; 
	//int cmd_channel=0;
	int random_interval=0;
	int measurement_duration=500;
	char mode[]="passive\0";
	char bssid[]="ff:ff:ff:ff:ff:ff\0";
	int rep_detail=0;
	char tmp[32]={0};
	char *ssid=NULL;

	if(!nvram_get_int("wave_ready")){
		RAST_INFO("rast_send_beacon_request wave not ready\n");
		return;
	}

	if(vifidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d_", unit, vifidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));

	ifname = strdup( get_wififname( unit ) );
	if ( !ifname ){
	 	goto rast_send_beacon_request;
	}
	/* MAC address */
	sprintf( macaddr_str, MACF, ETHERP_TO_MACF( addr ) );
	/* Channel */
	if( get_channel_number( ifname, &width, &channel ) ){
		goto rast_send_beacon_request;
	}

	if( nvram_get_int("11k_measurement_duration") > 0)
		measurement_duration = nvram_get_int("11k_measurement_duration");

	sprintf(command,"REQ_BEACON %s %d %d %d %d %d %d %s %s rep_detail=%d ssid=\"%s\" ap_ch_report=%d req_elements=0",
				macaddr_str,num_of_repetitions,measurement_request_mode,operating_class,
				channel,random_interval,measurement_duration,mode,bssid,rep_detail,
				ssid,channel);

#if 0
{
	int ii=0;
	char tmp[128]={0};
	int chd_p=command;
	for(ii=0;ii<10;ii++)
	{
		strncpy(tmp,chd_p,100);
		if(!strlen(tmp))
			break;
		RAST_INFO("rast_send_beacon_request[%s]\n",tmp);
		chd_p+=100;
	}
}
#endif

	if(unit  == 1)
		wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan2");
	else
		wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan0");

	if (wpaCtrlPtr == NULL) {
		RAST_INFO("%s; ERROR: hostapd_socket_get on band '%d' failed!\n", __FUNCTION__, unit );
		goto rast_send_beacon_request;
	} else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
		RAST_INFO("%s; ERROR: wpa_ctrl_attach for band '%d' failed!\n", __FUNCTION__, unit );
		wpa_ctrl_close(wpaCtrlPtr);
		goto rast_send_beacon_request;
	} else {
		fd = wpa_ctrl_get_fd(wpaCtrlPtr);
	}

	wpa_ctrl_request(wpaCtrlPtr, command, strlen(command), localBuf, &len, NULL);
 
	if (wpaCtrlPtr != NULL)
		wpa_ctrl_detach(wpaCtrlPtr);

	wpa_ctrl_close(wpaCtrlPtr);
	wpaCtrlPtr = NULL;

rast_send_beacon_request:

	if(ifname)
		free(ifname);

	return ;
}


static void lantiq_rast_update_beacon_report_ret(char *sta, char *ap_mac, char rcpi) {
	json_object *root = NULL;
	json_object *existApObj = NULL;
	json_object *reportApObj = NULL;
	int lock;
	char rssiStr[4];
	//char ap_mac[]="xx:xx:xx:xx:xx:xx";
	char path[]="/tmp/xx:xx:xx:xx:xx:xx_bcn_rpt\0";
	int i;

	//TOUPPER
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		sta[i]=toupper(sta[i]);
	for(i=0;i<strlen("xx:xx:xx:xx:xx:xx");i++)
		ap_mac[i]=toupper(ap_mac[i]);

	snprintf(path, sizeof(path), "/tmp/%s_bcn_rpt", sta);

	//RAST_INFO("rcpi_to_rssi %d\n", rcpi_to_rssi(rcpi) );

	snprintf(rssiStr, sizeof(rssiStr), "%d", rcpi_to_rssi(rcpi) );
	//snprintf(ap_mac, sizeof(ap_mac), %s, bssid);


	lock = file_lock(path+5);
	root = json_object_from_file(path);
	if(!root) {
		RAST_INFO("%s,no file or valid content\n", path);
		goto lantiq_rast_update_beacon_report_ret_end;
	}

	json_object_object_get_ex(root, ap_mac, &existApObj);
	if (existApObj) {
		RAST_INFO("report AP is exist\n");
		goto lantiq_rast_update_beacon_report_ret_end;
	}

	reportApObj = json_object_new_object();
	if (!reportApObj) {
		RAST_INFO("reportApObj is NULL\n");
		goto lantiq_rast_update_beacon_report_ret_end;
	}

	json_object_object_add(reportApObj, RAST_RCPI, json_object_new_string(rssiStr));
	json_object_object_add(root, ap_mac, reportApObj);
	json_object_to_file(path, root);

lantiq_rast_update_beacon_report_ret_end:
	json_object_put(root);
	file_unlock(lock);

}

/* return 0 means get nothing */
static int lantiq_11k_ret_parse(int unit, char *buf)
{
	char    *opCode;
	//char    stringOfValues[HOSTAPD_TO_FAPI_VALUE_STRING_LENGTH];
	char    *completeBuf;
	char    *endFieldName[] = { "\n" };
	char 	ifname[16]={0};
	int 	ret_cnt=0;
	int 	rssi_ret=0;
	char 	zero_mac[]="00:00:00:00:00:00\0";
	char 	*tmp=NULL;

	//opCode = strtok(buf, " ");
	if ( strstr(buf, "RRM-BEACON-REP-RECEIVED") != NULL ) {
		char sta_mac[]="xx:xx:xx:xx:xx:xx\0";
		char ret_mac[]="xx:xx:xx:xx:xx:xx\0";
		int  rcpi=0;

		completeBuf = strdup(buf);
		if (completeBuf == NULL) {
			RAST_INFO("%s; strdup() failed ==> ABORT!\n", __FUNCTION__);
			return rssi_ret;
		}

		if(!unit)
			strncpy(ifname,"wlan0 ",6);
		else
			strncpy(ifname,"wlan2 ",6);

		//if (fieldValuesGet(completeBuf, stringOfValues, ifname , endFieldName)) {
		if ( (tmp=strstr(buf, ifname)) != NULL ) {
			strncpy(sta_mac,tmp+6,17);
			//check mac valid?
			ret_cnt++;
		}

		//if (fieldValuesGet(completeBuf, stringOfValues, "bssid=", endFieldName)) {
		if ( (tmp=strstr(buf, "bssid=")) != NULL ) {
			strncpy(ret_mac,tmp+6,17);
			ret_cnt++;
		}

		//if (fieldValuesGet(completeBuf, stringOfValues, "rcpi=", endFieldName)) {
		if ( (tmp=strstr(buf, "rcpi=")) != NULL ) {
			sscanf(tmp+5,"%d",&rcpi);
			ret_cnt++;
		}

		if(ret_cnt != 3)
		{
			//error
			free((void *)completeBuf);
			return 0;
		}

		RAST_DBG("receive 11k pkt %s %s %d\n",sta_mac,ret_mac,(char)rcpi);

		if( memcmp(ret_mac,zero_mac,17) )
			lantiq_rast_update_beacon_report_ret(sta_mac,ret_mac,(char)rcpi);
		else
			RAST_INFO("mac zero, ignore\n");
		free((void *)completeBuf);
		return rssi_ret;
	} else {
		//RAST_DBG("%s; other opCodes ==> Abort!\n", __FUNCTION__);
		return 0;
	} 
}



/* return value : rssi value; 0 means error or gets nothing */
int report_check_11k(int unit,struct wpa_ctrl *wpaCtrlPtr)
{
	char    *buf;
	size_t  len = HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char);
	int     rssi_ret=0;

	if (wpaCtrlPtr == NULL) {
		return rssi_ret;
	}

	buf = (char *)malloc((size_t)(HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char)));
	if (buf == NULL) {
		RAST_INFO("%s; malloc error ==> ABORT!\n", __FUNCTION__);
		return rssi_ret;
	}

	while (wpa_ctrl_recv(wpaCtrlPtr, buf, &len) == 0) {

		if(len > 0)
		{
			if(strlen(buf)==0)
				continue;
			rssi_ret = lantiq_11k_ret_parse(unit, buf);
			len = HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char);
			memset(buf,0,(size_t)(HOSTAPD_TO_FAPI_MSG_LENGTH * sizeof(char)));
		}
	}

	free((void *)buf);

	return rssi_ret;
}

int rast_start_bcn_rpt_wlanX(void *data) {
	struct 	wpa_ctrl *wpaCtrlPtr=NULL;
	int  	fd,res,res_wpa_ctrl;
	fd_set 	rfds;
	struct timeval timeout;
	char 	localBuf[HOSTAPD_TO_FAPI_MSG_LENGTH]={0};
	int timeout_cnt=0;

	if(!data)
	{
		RAST_INFO("create 11k thread input parameter empty\n");
		return -1;		
	}

	int unit = *(int *)data;

	if(unit != 0 && unit != 1)
	{
		RAST_INFO("create 11k thread unit error\n");
		return -1;
	}

	while(1) {
		if( nvram_get_int("wave_ready") ) break;
		else sleep(2);
	}

	while(1) {
		if(!unit) wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan0");
		else  wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan2");

		if (wpaCtrlPtr == NULL) {
			RAST_INFO("%s; ERROR: hostapd_socket_get on unit '%d' failed. Retry.\n", __FUNCTION__, unit );
			sleep(3);
			continue;
		} else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
			RAST_INFO("%s; ERROR: wpa_ctrl_attach for unit '%d' failed. Retry.\n", __FUNCTION__, unit );
			wpa_ctrl_close(wpaCtrlPtr);
			sleep(3);
			continue;
		} else {
			fd = wpa_ctrl_get_fd(wpaCtrlPtr);
			break;
		}
	}
    /* Main event loop */

	//RAST_INFO("start 11k thread %d\n",unit);

    while (1)
    { 	
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		timeout.tv_usec= 0;
		timeout.tv_sec = 5;
 
		memset(localBuf,0,(4096 * 3) );   

		res = select(fd + 1, &rfds, NULL, NULL, &timeout);
		if (res < 0)
		{
			RAST_INFO("%d %s\n",errno,strerror(errno));
			RAST_INFO("%s; select() return value= %d ==> CONTINUE!!!\n", __FUNCTION__, res);
			continue;
		} else if( res == 0 ) {
			/* timeout handling */
			timeout_cnt++;
			if(timeout_cnt > 5)
			{
				char buf_tmp[256];
				size_t len = sizeof(buf_tmp) - 1;
				memset(buf_tmp,0,256);
				/* check socket*/
				if (wpa_ctrl_request(wpaCtrlPtr, "PING", 4, buf_tmp, &len,NULL) < 0 
					|| len < 4 || memcmp(buf_tmp, "PONG", 4) != 0)	
				{
					/* reset socket */
					if (wpaCtrlPtr != NULL)
						wpa_ctrl_detach(wpaCtrlPtr);

					wpa_ctrl_close(wpaCtrlPtr);
					wpaCtrlPtr = NULL;
					while(1) {
						if( nvram_get_int("wave_ready") ) break;
						else sleep(2);
					}					
					/* try to reconnect to hpstapd */
					while(1) {
						if(!unit) wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan0");
						else  wpaCtrlPtr = wpa_ctrl_open("/var/run/hostapd/wlan2");

						if (wpaCtrlPtr == NULL) {
							RAST_INFO("%s; ERROR: hostapd_socket_get on unit '%d' failed. Retry.\n", __FUNCTION__, unit );
							sleep(3);
							continue;
						} else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
							RAST_INFO("%s; ERROR: wpa_ctrl_attach for unit '%d' failed. Retry.\n", __FUNCTION__, unit );
							wpa_ctrl_close(wpaCtrlPtr);
							sleep(3);
							continue;
						} else {
							fd = wpa_ctrl_get_fd(wpaCtrlPtr);
							break;
						}
					}					
				}
				timeout_cnt = 0;			
			}
			RAST_DBG("%s; select() return value= %d ==> CONTINUE!!!\n", __FUNCTION__, res);
			continue;
		}

		timeout_cnt = 0;

		if (FD_ISSET(fd, &rfds)) {
			//RAST_INFO("rast_start_bcn_rpt_wlanX %d report_check_11k in\n",unit);
			res = report_check_11k(unit,wpaCtrlPtr);
			//RAST_INFO("rast_start_bcn_rpt_wlanX %d report_check_11k out\n",unit);
		}
		if ( res_wpa_ctrl == (-1) ) {  
		/* ERROR - issue a trace */
			RAST_INFO("wpa_ctrl_pending() returned ERROR\n");
		}
	}

	if (wpaCtrlPtr != NULL)
		wpa_ctrl_detach(wpaCtrlPtr);

	free(data);

	wpa_ctrl_close(wpaCtrlPtr);
	wpaCtrlPtr = NULL;

	return 0;

}

pthread_t thread_11k_wlan0,thread_11k_wlan2;

void rast_bcn_rpt_init(void) {
	pthread_attr_t attr_0,attr_1;
	int *args = NULL;

	RAST_DBG("Start beacon report thread.\n");

	args = malloc(sizeof(int));
	if(args == NULL)
	{
		RAST_INFO("malloc error\n");
		return;
	}
	*args = 0;

	pthread_attr_init(&attr_0);
	pthread_attr_setdetachstate(&attr_0, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_11k_wlan0,&attr_0,(void *)&rast_start_bcn_rpt_wlanX,args);
	pthread_attr_destroy(&attr_0);

	sleep(3);

	args = malloc(sizeof(int));
	if(args == NULL)
	{
		RAST_INFO("malloc error\n");
		return;
	}
	*args = 1;

	pthread_attr_init(&attr_1);
	pthread_attr_setdetachstate(&attr_1, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread_11k_wlan2,&attr_1,(void *)&rast_start_bcn_rpt_wlanX,args);
	pthread_attr_destroy(&attr_1);

}
#endif

#ifdef RTCONFIG_BTM_11V	
/*BSS-TM-RESP wlan2 d4:38:9c:8b:60:87 dialog_token=123 status_code=0 bss_termination_delay=0 target_bssid=60:45:cb:cd:15:20*/
static int lantiq_11v_ret_parse(int idx,int vidx, char *buf,
								char *sta_mac,int *dialog_token, int *status_code, 
								int *bss_termination_delay, char *ret_mac, int input_buf_len) {

	char    *tmp_buf=NULL,*buf_p=NULL;
	char 	*tmp=NULL;
	int 	len=0;
	char 	*delim = " ";
	char 	ifname[7]={0};
	char 	prefix[7]={0};
	char 	*pch;

	//opCode = strtok(buf, " ");
	if ( strstr(buf, "BSS-TM-RESP") != NULL ) {

		buf_p = strdup(buf);
		tmp_buf = buf_p;
		if(tmp_buf == NULL)
			return -1;
		len = strlen(tmp_buf);
		if(len <= 0) {
			free(buf_p);
			return -1;
		}

		/* get served ap bssid */
		if(vidx > 0)
			snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);
		else
			snprintf(prefix, sizeof(prefix), "wl%d", idx);

		strncpy(ifname,nvram_safe_get(strcat_safe(prefix, "_ifname")),sizeof(ifname));


		//if (fieldValuesGet(completeBuf, stringOfValues, ifname , endFieldName)) {
		if ( (tmp=strstr(tmp_buf, ifname)) != NULL ) {
			strncpy(sta_mac,tmp+6,input_buf_len);
		}

		pch = strtok(tmp_buf,delim);
		while (pch != NULL)
		{
			if ( strstr(pch, "dialog_token=") != NULL ) {
				*dialog_token = atoi(pch+strlen("dialog_token="));
			} else if ( strstr(pch, "status_code=") != NULL ) {
				*status_code = atoi(pch+strlen("status_code="));
			} else if ( strstr(pch, "bss_termination_delay=") != NULL ) {
				*bss_termination_delay = atoi(pch+strlen("bss_termination_delay="));
			} else if ( strstr(pch, "target_bssid=") != NULL ) {
				strncpy(ret_mac,pch+strlen("target_bssid="),input_buf_len);
			}
			//tmp_int_list[i]=atoi(pch);
			//i++;
			pch = strtok (NULL, delim);
		}

		free(buf_p);
		return 0;
	} else {
		_dprintf("not mine [%s]\n",buf);
	}
	return -1;		
}

/* 

Return value:
	0: success
	other: fail to receive responses or not support
*/
int rast_send_11v_req(int idx,int vidx,char *sta_mac, char *candidate_ap_mac)
{
	int unit = 0;
	struct 	wpa_ctrl *wpaCtrlPtr=NULL;
	char command[1024] = {0};
	char localBuf[HOSTAPD_TO_FAPI_MSG_LENGTH]={0};
	int category=10;
	int mode=1;
	int dialog_token=0;
	int op_class;
	int channel=0;
	int width=0;
	int ret = BTM_CMD_FAIL,hostapd_ret=0;
	fd_set fdset;
	struct timeval tv;
	int status,fdmax,event_fd,len;
	char ret_sta_mac[18]={0};
	int ret_dialog_token=0; 
	int status_code=0;  
	int bss_termination_delay=0;  
	char ret_target_mac[18]={0};
	char local_wl_mac[18]={0};
	time_t in_t,now_t;
	char ifname[7]={0};
	char prefix[7]={0};
	char wpa_path[48]={0};

	/* if guest network supports roamast, here might need to check  */
	unit = idx;

	/* get served ap bssid */
	if(vidx > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, vidx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d", idx);

	strncpy(ifname,nvram_safe_get(strcat_safe(prefix, "_ifname")),sizeof(ifname));

	if( !strlen(ifname) ) {
		_dprintf("ifname get error\n");
		ret = BTM_OTHER;
		goto rast_send_11v_req_failed;
	}
	snprintf(wpa_path,sizeof(wpa_path),"/var/run/hostapd/%s",ifname);

	/* open hostapd sockets */
	wpaCtrlPtr = wpa_ctrl_open(wpa_path);

	if (wpaCtrlPtr == NULL) {
		RAST_DBG("%s; ERROR: hostapd_socket_get on band '%d' failed!\n", __FUNCTION__, unit );
		ret = BTM_OTHER;
		goto rast_send_11v_req_failed;
	} else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
		ret = BTM_OTHER;
		RAST_DBG("%s; ERROR: wpa_ctrl_attach for band '%d' failed!\n", __FUNCTION__, unit );
		goto rast_send_11v_req_failed;
	} else {
		event_fd = wpa_ctrl_get_fd(wpaCtrlPtr);
	}

	/* send command to hostapd to send 11v packet */
	if( get_channel_number( ifname, &width, &channel ) ){
		ret = BTM_OTHER;
		goto rast_send_11v_req_failed;
	}


	srand(time(NULL));
	dialog_token = rand()%255;

	sprintf(command,"BSS_TM_REQ %s %d Mode=%d dialog_token=%d bss_term=2,3 pref=1 abridged=1 disassoc_imminent=1 neighbor=%s,11,%d,%d,5,1",
					sta_mac,category,mode,dialog_token,candidate_ap_mac,op_class,channel);

	memset(localBuf,0,sizeof(localBuf));
	len = sizeof(localBuf) -1;
	wpa_ctrl_request(wpaCtrlPtr, command, strlen(command), localBuf, &len, NULL);

	if( !strcmp(localBuf,"FAIL") ){
		ret = BTM_CMD_FAIL;
		goto rast_send_11v_req_failed;
	}

	in_t = time(NULL);
	while(1) {
		FD_ZERO(&fdset);
		FD_SET(event_fd, &fdset);
		fdmax = event_fd;
		width = fdmax + 1;		
		memset(&tv,0,sizeof(struct timeval));
		tv.tv_sec = 1;
		tv.tv_usec= 0;

		status = select(width, &fdset, NULL, NULL, &tv);
		if (status < 0)
		{
			RAST_DBG("%s; select() return value= %d\n", __FUNCTION__, status);
			ret = BTM_OTHER;
			goto rast_send_11v_req_failed;
		} else if( status == 0 ) {	
			RAST_DBG("%s; select() return value= %d\n", __FUNCTION__, status);
			ret = BTM_TIMEOUT;
			goto rast_send_11v_req_failed;
		}

		if (FD_ISSET(event_fd, &fdset)) {
			memset(localBuf,0,sizeof(localBuf));
			len = sizeof(localBuf) -1;
			if (wpa_ctrl_recv(wpaCtrlPtr, localBuf, &len) == 0) 
			{
				//_dprintf("11v ret = %s\n",localBuf);
				hostapd_ret = lantiq_11v_ret_parse( idx, vidx,localBuf,ret_sta_mac, &ret_dialog_token, &status_code, &bss_termination_delay, ret_target_mac, sizeof(ret_target_mac) );
				
				//_dprintf("lantiq_11v_ret_parse %s %d %d %d %s\n",ret_sta_mac, ret_dialog_token, status_code, bss_termination_delay, ret_target_mac);

				if( hostapd_ret == -1 ) {
					//receive other op-code
					now_t = time(NULL);
					if((now_t-in_t) > 0) {
						ret = BTM_TIMEOUT;
						goto rast_send_11v_req_failed;
					}
					else 
						continue;
				}

				if( ret_dialog_token != dialog_token ) {
					//_dprintf("dialog token error %d %d\n",ret_dialog_token,dialog_token);
					now_t = time(NULL);
					if((now_t-in_t) > 0) {
						ret = BTM_TIMEOUT;
						goto rast_send_11v_req_failed;
					}
					else 
						continue;
				}

				if( status_code == 0) {
					strncpy(local_wl_mac,nvram_safe_get(strcat_safe(prefix, "_hwaddr")),sizeof(local_wl_mac));

					if( !strcmp(ret_target_mac,local_wl_mac) )
						//means sta do not want to change AP
						ret = BTM_RET_ACCEPT_TARGETMAC_SELF;
					else
						ret = BTM_RET_ACCEPT_TARGETMAC_NOTSELF;
				} else {
					ret = BTM_RET_REJECT;
				}
				break;
			}
		}
	}

rast_send_11v_req_failed:
	if(wpaCtrlPtr) wpa_ctrl_close(wpaCtrlPtr);

	return ret;

}
#endif //#ifdef RTCONFIG_BTM_11V

int send_cmd_to_hostapd(int unit,int subunit,char *cmd_buf,int cmd_len,char *ret_buf, int ret_len)
{
	struct 	wpa_ctrl *wpaCtrlPtr=NULL;
	char ifname[7]={0};
	char prefix[7]={0};
	char wpa_path[48]={0};

	/* get served ap bssid */
	if(subunit > 0)
		snprintf(prefix, sizeof(prefix), "wl%d.%d", unit, subunit);
	else
		snprintf(prefix, sizeof(prefix), "wl%d", unit);

	strncpy(ifname,nvram_safe_get(strcat_safe(prefix, "_ifname")),sizeof(ifname));

	//_dprintf("ifname %s %d cmd_buf %s\n",ifname,__LINE__,cmd_buf);

	if( !strlen(ifname) ) {
		_dprintf("ifname get error\n");
		return -1;
	}
	snprintf(wpa_path,sizeof(wpa_path),"/var/run/hostapd/%s",ifname);
	/* open hostapd sockets */
	wpaCtrlPtr = wpa_ctrl_open(wpa_path);

	if (wpaCtrlPtr == NULL) {
		//_dprintf(" %d error\n",__LINE__);
		return -1;
	} else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
		if(wpaCtrlPtr) wpa_ctrl_close(wpaCtrlPtr);
		//_dprintf(" %d error\n",__LINE__);
		return -1;
	}

	memset(ret_buf,0,ret_len);
	ret_len = ret_len-1;
	wpa_ctrl_request(wpaCtrlPtr, cmd_buf, strlen(cmd_buf), ret_buf, &ret_len, NULL);

	wpa_ctrl_close(wpaCtrlPtr);

	return 0;

}

#if defined(RTCONFIG_BTM_11V) && defined(RTCONFIG_BCN_RPT)
int check_if_support_kv(int unit,int subunit, rast_sta_info_t *sta)
{
	char command[256] = {0};
	char localBuf[HOSTAPD_TO_FAPI_MSG_LENGTH]={0};
	char tmp[24];
	int btm_supported=0;
	int rrm_beacon_passive_measurement_supported=0;
	char sta_mac[32];
	int ret=0;

	snprintf(sta_mac, sizeof(sta_mac), MACF_UP, ETHER_TO_MACF(sta->addr));
	snprintf(command, sizeof(command), "STA_EXT %s", sta_mac);

	if(send_cmd_to_hostapd(unit,subunit,command,sizeof(command),localBuf,HOSTAPD_TO_FAPI_MSG_LENGTH))
	{
		//retry?
		return 0;
	}

	if(strlen(localBuf) && strcmp(localBuf,"FAIL"))
	{
		//_dprintf("localBuf %s",localBuf);
		sscanf(localBuf,"%s btm_supported=%d rrm_beacon_passive_measurement_supported=%d",tmp,&btm_supported,&rrm_beacon_passive_measurement_supported);
		//_dprintf("btm_supported %d rrm_beacon_passive_measurement_supported %d\n",btm_supported,rrm_beacon_passive_measurement_supported);
	}

	if( btm_supported  )
		ret |= RAST_SUPPORT_V;
	if( rrm_beacon_passive_measurement_supported )
		ret |= RAST_SUPPORT_K_PASSIVE_SCAN;

	return ret;
}

#endif

#ifdef RTCONFIG_RAST_NONMESH_KVONLY
int kv_handler_init(void){
	return 0;
}

int kv_handler_deinit(void){
	return 0;
}

void wait_k_resp(struct report_list_entry **rplist,int *num){
	return 0;
}

int is_support_rast_nonmesh(void){
	return 0;
}
#endif //RTCONFIG_RAST_NONMESH_KVONLY
#ifdef RTCONFIG_STA_AP_BAND_BIND
int rast_check_driver_maclist(int bssidx,int vifidx,struct ether_addr *addr){
	//do nothing
}
#endif