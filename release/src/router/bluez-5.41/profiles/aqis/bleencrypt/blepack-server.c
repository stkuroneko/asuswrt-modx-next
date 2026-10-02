#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>

#include <shutils.h>
/* Use SVID search */
#define __USE_GNU
#include <search.h>
#include <json.h>
#if defined(RTCONFIG_AMAS)
#include <sys/mount.h>
static int aimesh_mode = 1; /* default is wifi-son for old-app compatibility */
#endif
#if defined(RTCONFIG_DETWAN)
static int detwan_init = 0;  /* if AUTO WAN_LAN detection is initialized */
#endif

#include "blepack.h"
#include "include/adv_string.h"
#include "include/adv_verify.h"
#include "include/adv_inet.h"

static char do_rc_service[DEFLEN_256];

typedef struct TLV_Header_t
{
        unsigned int len;
} __attribute__((__packed__)) TLV_Header;

/*
 * @func: Check if the file exists
 * @FileName: search the name of file.
 *
 * @return: 1=exist, 0=no file
 * */
int fileExists(char *FileName)
{
	int ret = 0;
	FILE *stream = NULL;

	stream = fopen(FileName, "r");
	ret = (stream == NULL) ? 0 : 1;
	if (ret == 1) fclose(stream);
	return ret;
}

unsigned long getFileSize(char *FileName)
{
	unsigned long length = 0, curpos = 0;
	FILE *stream = NULL;

	if ((stream = fopen(FileName, "rb")) == NULL)
		return length;

	curpos = ftell(stream);
	fseek(stream, 0L, SEEK_END);
	length = ftell(stream);
	fseek(stream, curpos, SEEK_SET);
	fclose(stream);
	return length;
}

static int chk_inf_exist(char* inf)
{
        FILE *fp;
        int len;
	char buf[DEFLEN_512], *pt1;

        sprintf(buf, "ifconfig %s", inf);

        fp = popen(buf, "r");
        if (fp) {
                memset(buf, 0, DEFLEN_512);
                len = fread(buf, 1, DEFLEN_512, fp);
                pclose(fp);
                if (len > 1) {
                        buf[len-1] = '\0';
                        pt1 = strstr(buf, "HWaddr ");
                        if (pt1)
                                return 1;
                }
        }
        return 0;
}

static char *replace_str(char *str, char *orig, char *rep)
{
	static char buffer[DEFLEN_512];
	char tmp[DEFLEN_512];
	char *p;

	if(!strstr(str, orig))  // Is 'orig' even in 'str'?
		return str;

	memset(tmp, '\0', sizeof(tmp));
	snprintf(tmp, sizeof(tmp), "%s", str);

	while((p = strstr(tmp, orig))) {
		strncpy(buffer, tmp, p-tmp); // Copy characters from 'str' start to 'orig' st$
		buffer[p-tmp] = '\0';

		sprintf(buffer+(p-tmp), "%s%s", rep, p+strlen(orig));
		buffer[strlen(buffer)] = '\0';
		snprintf(tmp, sizeof(tmp), "%s", buffer);
		DBG_INFO("%s", tmp);
	}

	return buffer;
}

// Key Exchange Related function
// Reset_S: Reset myData structure
// FileRead_Save: read file and save it as a structure
// FileRead_ApList: read ApList and save it in APLIST_MODIFY_TXT 

int FileRead_Save(char *fName, unsigned char *fContent, size_t fLen)
{
	FILE *fp;
	int err=0;

	if ((fp = fopen(fName, "rb")) == NULL) {
		DBG_ERR("[%s] Open %s failed...\n", __func__, fName);
		err = 1;
		goto exit;
	}

	fseek(fp, 0L, SEEK_SET);
	memset(fContent, 0, fLen);
	if (fread(fContent, 1, fLen, fp) != fLen) {
		DBG_ERR("[%s] Read %s failed...\n", __func__, fName);
		err = 1;
		goto exit;
	}

	DBG_INFO("[%s] length:%zu", __func__, fLen);
exit:
	fclose(fp);
	return err;
}

static int FileRead_ApList(char *fName)
{
	char *arrstr[][2]={
			{"\\[",	"%5B"},
			{"\\]",	"%5D"},
			{NULL,	NULL }
	};
	FILE *fp, *fp1;
	char buf[DEFLEN_512], *tmp;
	int i, j, index, err=0;

	memset(buf, 0, sizeof(buf));

	if ((fp1 = fopen(APLIST_MODIFY_TXT, "w+")) == NULL) {
		DBG_ERR("[%s] Open %s failed...\n", __func__, APLIST_MODIFY_TXT);
		err = 1;
		goto exit1;
	}
	if ((fp = fopen(fName, "rb")) == NULL) {
		DBG_ERR("[%s] Open %s failed...\n", __func__, fName);
		fprintf(fp1, "[]");
		err = 1;
		goto exit;
	}
	else {
		fprintf(fp1, "[");
                i = 0;
		while (fgets(buf, DEFLEN_512, fp)){
			j = 0;
			while (j < (int)strlen(buf)+1) {
				if (buf[j] == '\n') buf[j] = '\0';
				j++;
			}

			index = 0;
			while (arrstr[index][0]!=NULL) {
				if (!index)
					tmp = replace_str(buf, arrstr[index][0], arrstr[index][1]);
				else
					tmp = replace_str(tmp, arrstr[index][0], arrstr[index][1]);
				index++;
			}

			fprintf(fp1, "%s[%s]", i>0?",":"", tmp);
			memset(buf, 0, sizeof(buf));
			i++;
		}
		fprintf(fp1, "]");
	}

exit:
	fclose(fp);
exit1:
	fclose(fp1);
	return err;
}

static void json_unescape(char *s)
{
	unsigned int c;

	while ((s = strpbrk(s, "%+"))) {
		/* Parse %xx */
		if (*s == '%') {
			sscanf(s + 1, "%02x", &c);
			*s++ = (char) c;
			strncpy(s, s + 2, strlen(s) + 1);
		}
		/* Space is special */
		else if (*s == '+') {
			*s++ = ' ';
		}
	}
}

static void decode_json_buffer(char *query)
{
	int len;
	char *q, *name, *value;

	/* Parse into individual assignments */
	q = query;
	len = strlen(query);

	for (q = query; q < (query + len);) {
		/* Unescape each assignment */
		json_unescape(name = value = q);

		/* Skip to next assignment */
		for (q += strlen(q); q < (query + len) && !*q; q++);
	}
}

static void set_json_obj_nvram(char *post_json_buf)
{
	struct json_object *root=NULL, *json_value=NULL;
	const char *value=NULL;

	decode_json_buffer(post_json_buf);
	root = json_tokener_parse(post_json_buf);

	{
		json_object_object_foreach(root, key, val) {
			json_value = val;
			json_object_object_get_ex(root, key, &json_value);
			value = json_object_get_string(val);
			if (value != NULL) {
				DBG_INFO("nvram set %s [%s]", key, value);
				nvram_set(key, value);

				usleep(100);
			}
		}
	}

	if(root) json_object_put(root);
}

static int ble_get_wanstate(int detect)
{
	int wanss = BLE_WAN_STATUS_ALL_DISCONN;
	char prefix[DEFLEN_128];
	char prefix2[DEFLEN_128];
	char tmp[DEFLEN_128], tmp2[DEFLEN_128];
	int unit=0, det_wait=0;

	memset(prefix, '\0', sizeof(prefix));
	memset(prefix2, '\0', sizeof(prefix2));

#ifndef RTCONFIG_LANTIQ
	for(unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; ++unit) {
		if(get_dualwan_by_unit(unit) != WANS_DUALWAN_IF_WAN && get_dualwan_by_unit(unit) != WANS_DUALWAN_IF_LAN)
			continue;
#endif
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);
		if(unit == WAN_UNIT_FIRST)
			snprintf(prefix2, sizeof(prefix2), "autodet_");
		else
			snprintf(prefix2, sizeof(prefix2), "autodet%d_", unit);

		if (detect) {
			det_wait=10;
			nvram_set(strcat_r(prefix2, "state", tmp2), "");
			notify_rc_after_period_wait("start_autodet", 0);
			while (nvram_get_int(strcat_r(prefix2, "state", tmp2))==0 && det_wait--)
				sleep(1);
			DBG_INFO("\nthe autodet result:%d\n", nvram_get(strcat_r(prefix2, "state", tmp2))?nvram_get_int(strcat_r(prefix2, "state", tmp2)):-1);
		}

		if (nvram_get_int(strcat_r(prefix2, "state", tmp2)) == AUTODET_STATE_FINISHED_NOLINK) {
			if(nvram_get_int(strcat_r(prefix, "auxstate_t", tmp))==1) {
				nvram_set("autodet_state", "0");
				notify_rc_after_period_wait("start_autodet", 0);
			}
			wanss = BLE_WAN_STATUS_ALL_DISCONN;
		}
		else if (nvram_get_int(strcat_r(prefix2, "state", tmp2)) == AUTODET_STATE_FINISHED_WITHPPPOE
			|| nvram_get_int(strcat_r(prefix2, "auxstate", tmp2)) == AUTODET_STATE_FINISHED_WITHPPPOE) {
			if( ( nvram_get_int(strcat_r(prefix, "state_t", tmp))==2
				&& nvram_get_int(strcat_r(prefix, "sbstate_t", tmp))==0
				&& nvram_get_int(strcat_r(prefix, "auxstate_t", tmp))==0 ) 
			    &&
			    ( nvram_get_int("link_internet")==2
				|| nvram_get_int(strcat_r(prefix, "realip_state", tmp))==2 )
			   ) {
				wanss = BLE_WAN_STATUS_PORT0_DHCP_PPPOE;
			}
			else
				wanss = BLE_WAN_STATUS_PORT0_PPPOE;
		}
		else if( nvram_get_int(strcat_r(prefix, "state_t", tmp))==2
			&& nvram_get_int(strcat_r(prefix, "sbstate_t", tmp))==0
			&& nvram_get_int(strcat_r(prefix, "auxstate_t", tmp))==0 ) 
			wanss = BLE_WAN_STATUS_PORT0_DHCP;
		else if( nvram_get_int(strcat_r(prefix2, "state", tmp2))==2) {
			if ( nvram_get_int(strcat_r(prefix, "auxstate_t", tmp))!=1)
				wanss = BLE_WAN_STATUS_PORT0_DHCP;
			else if( nvram_get_int(strcat_r(prefix, "state_t", tmp))==4
				&& nvram_get_int(strcat_r(prefix, "sbstate_t", tmp))==4
				&& nvram_get_int(strcat_r(prefix, "auxstate_t", tmp))==0 ) 
				wanss = BLE_WAN_STATUS_PORT0_UNKNOWN;
		}
		else if( nvram_get_int(strcat_r(prefix, "state_t", tmp))==4
			&& nvram_get_int(strcat_r(prefix, "sbstate_t", tmp))==4 )
			wanss = BLE_WAN_STATUS_PORT0_DHCP;
		else
			wanss = BLE_WAN_STATUS_PORT0_UNKNOWN;
#ifndef RTCONFIG_LANTIQ
	}
#endif

	DBG_INFO("\nautodet result:%d\n", nvram_get(strcat_r(prefix2, "state", tmp2))?nvram_get_int(strcat_r(prefix2, "state", tmp2)):-1);
	DBG_INFO("%s, %s[%d], %s[%d], %s[%d], %s[%d]\n"
		"%s, %s[%d], %s[%d]\n"
		"%s, %s[%d], %s[%d]",
			prefix,
			"state", nvram_get_int(strcat_r(prefix, "state_t", tmp)),
			"sbstate", nvram_get_int(strcat_r(prefix, "sbstate_t", tmp)),
			"auxstate", nvram_get_int(strcat_r(prefix, "auxstate_t", tmp)),
			"realip_state", nvram_get_int(strcat_r(prefix, "realip_state", tmp)),
			prefix2,
			"state", nvram_get_int(strcat_r(prefix2, "state", tmp2)),
			"auxstate", nvram_get_int(strcat_r(prefix2, "auxstate", tmp2)),
			"None",
			"link_internet", nvram_get_int("link_internet"),
			"WanState", wanss
	);

	logmessage("BLUEZ", "wan:%s, proto:%x, internet:%d\n", prefix, wanss, nvram_get_int("link_internet"));
	return wanss;
}

void Reset_S()
{
#if defined(RTCONFIG_WIFI_SON)
	aimesh_mode = 0;
#endif
	if (!IsNULL_PTR(fileData_s.kp)) MFREE(fileData_s.kp);
	if (!IsNULL_PTR(fileData_s.ku)) MFREE(fileData_s.ku);
	if (!IsNULL_PTR(fileData_s.km)) MFREE(fileData_s.km);
	if (!IsNULL_PTR(fileData_s.ns)) MFREE(fileData_s.ns);
	if (!IsNULL_PTR(fileData_s.nc)) MFREE(fileData_s.nc);
	if (!IsNULL_PTR(fileData_s.ks)) MFREE(fileData_s.ks);
	if (!IsNULL_PTR(fileData_s.iv)) MFREE(fileData_s.iv);
	if (!IsNULL_PTR(fileData_s.aplist)) MFREE(fileData_s.aplist);
}

/*Function: UnpackBLEDataToNvram
 *Parameter:
 * @handler: 
 * @data: input data
 * @datalen: size of data
 *
 * @return:
 * */
void UnpackBLEDataToNvram(struct api_handler *handler, unsigned char *data, int datalen)
{
	char str_data[DEFLEN_1024], tmp[DEFLEN_128], prefix[DEFLEN_128];
	char word[DEFLEN_256];
	char *next, *str_service;
	char *delim=";", *delim_1=",";
	char countryCode[3];
	int unit=0, chk_service=0, list=0;
	int is_change_lanip, len_data;
	struct in_addr lan_addr, dhcp_start_addr, dhcp_end_addr;
	
	memset(str_data, '\0', DEFLEN_1024);
	memset(prefix, '\0', DEFLEN_128);
	memset(tmp, '\0', DEFLEN_128);

	//the data type of conversion
	switch (handler->t_type)
	{
		case BLE_DATA_TYPE_STRING:
			snprintf(str_data, datalen+1, "%s", data);
			break;
		case BLE_DATA_TYPE_INTEGER:
			snprintf(str_data, datalen+1, "%d", (int)data[0]);
			break;
		case BLE_DATA_TYPE_IP:
			AdvInet_NCtoA(data, str_data);
			break;
		case BLE_DATA_TYPE_NULL:
			break;
		default:
			return;
	}

	//store service 
	if (handler->do_rc_service!=NULL && strlen(handler->do_rc_service) && strstr(do_rc_service, handler->do_rc_service)==NULL)
	{
#if defined(RTCONFIG_AMAS)
		if ( handler->cmdno==BLECMD_SET_GROUP_ID && aimesh_mode ) {
			strlcat(do_rc_service, delim, sizeof(do_rc_service));
			strlcat(do_rc_service, "restart_amas_lldpd", sizeof(do_rc_service));
		}
#endif

		if(strlen(do_rc_service))
			strcat(do_rc_service, delim);
		strncat(do_rc_service, handler->do_rc_service, strlen(handler->do_rc_service)+1);
		DBG_INFO("[rc service]: %s", handler->do_rc_service!=NULL?handler->do_rc_service:"(NULL)");
	}

	//set nvram
	if (handler->nvram!=NULL && strlen(handler->nvram)) {
		switch (handler->cmdno) {
#if defined(RTCONFIG_WIRELESSREPEATER)
			case BLECMD_SET_WLCX_PSTA:
			case BLECMD_SET_WLCX_BAND:
			case BLECMD_SET_WLCX_SSID:
			case BLECMD_SET_WLCX_AUTH_MODE:
			case BLECMD_SET_WLCX_CRYPTO:
			case BLECMD_SET_WLCX_WPA_PSK:
				if (!strlen(prefix))  {
					snprintf(prefix, sizeof(prefix), "%s", "wlc");
#if defined(RTCONFIG_CONCURRENTREPEATER)
					if ( str_data[1] == '0')
					{
						snprintf(tmp, sizeof(tmp), "%c", str_data[0]);
						strlcat(prefix, tmp, sizeof(prefix));
					}
					else
					{
						snprintf(tmp, sizeof(tmp), "%c%c%c", str_data[0], str_data[0], '.', str_data[1]);
						strlcat(prefix, tmp, sizeof(prefix));
					}
#endif
				}
				snprintf(prefix, sizeof(prefix), "%s_%s", prefix, handler->nvram);

				nvram_set(prefix, str_data+2);
				DBG_INFO("[Nvram parameter]: %s", prefix!=NULL?prefix:"(NULL)");
				break;
#endif
			case BLECMD_SET_WLX_SSID:
			case BLECMD_SET_WLX_AUTH_MODE_X:
			case BLECMD_SET_WLX_CRYPTO:
			case BLECMD_SET_WLX_WPA_PSK:
				if (!strlen(prefix)) {
					snprintf(prefix, sizeof(prefix), "%s", "wl");
					if ( str_data[1] == '0')
					{
						snprintf(tmp, sizeof(tmp), "%c", str_data[0]);
						strlcat(prefix, tmp, sizeof(prefix));
					}
					else
					{
						snprintf(tmp, sizeof(tmp), "%c%c%c", str_data[0], '.', str_data[1]);
						strlcat(prefix, tmp, sizeof(prefix));
					}
				}

				strlcat(prefix, "_", sizeof(prefix));
				strlcat(prefix, handler->nvram, sizeof(prefix));

				nvram_set(prefix, str_data+2);
				DBG_INFO("[Nvram parameter]: %s", prefix!=NULL?prefix:"(NULL)");
				break;
			case BLECMD_SET_SWITCH_WANXTAGID:
			case BLECMD_SET_SWITCH_WANXPRIO:
				snprintf(prefix, sizeof(prefix), "%s", "switch_wan");
				snprintf(tmp, sizeof(tmp), "%c%s", str_data[0], handler->nvram);
				strlcat(prefix, tmp, sizeof(prefix));

				nvram_set(prefix, str_data+1);
				DBG_INFO("[Nvram parameter]: %s", prefix!=NULL?prefix:"(NULL)");
				break;
			default:
				nvram_set(handler->nvram, str_data);
				DBG_INFO("[Nvram parameter]: %s", handler->nvram!=NULL?handler->nvram:"(NULL)");
				break;
		}
	}

	len_data = strlen(str_data);
	DBG_INFO("[Store value]: %s", len_data?str_data:"(NULL)");

	//other Setting
	switch (handler->cmdno)
	{
#if defined(RTCONFIG_AMAS)
		case BLECMD_SET_AIMESHMODE:
			{
				int org_mode = aimesh_mode;
				aimesh_mode = atoi(str_data)>0? 1:0;
				if (aimesh_mode != org_mode) { /* do some different initialization here */
#if defined(RTCONFIG_DETWAN)
					if ( !aimesh_mode ) /* change from AiMesh to WiFi-Son */
						detwan_init = 0; /* reset detwan_init */
					else { /* change to AiMesh Mode */
						if ( detwan_init ) { /* detwan already init... */
							char *detwan[] = {"detwan", "reset", NULL};
							_eval(detwan, NULL, 0, NULL);
							sleep(2);
							detwan_init = 0;
						}
					}
#endif
					DBG_INFO("[new AIMESH MODE]: %d", aimesh_mode);
				}
			}
			break;
#endif
		case BLECMD_SET_SW_MODE:
#if defined(RTCONFIG_WIRELESSREPEATER)
#if defined(RTCONFIG_LANTIQ) || defined(RTCONFIG_REALTEK) || defined(RTCONFIG_BCMARM)
			break;
#else
			if (!strncmp(str_data, "2", 1)) { // Repeater Mode
				foreach (word, nvram_safe_get("wl_ifnames"), next) {
					memset(prefix, '\0', DEFLEN_128);
					snprintf(prefix, sizeof(prefix), "%s", get_staifname(unit));
					if (chk_inf_exist(prefix))
						break;

					doSystem("wlanconfig %s create wlandev %s wlanmode sta nosbeacon", prefix, get_vphyifname(unit));
					sleep(1);
					doSystem("ifconfig %s up", prefix);
					unit++;
				}
			}
#endif
#endif
			break;
		case BLECMD_SET_WIFI_NAME:
		case BLECMD_SET_WIFI_PWD: /* Setting wifi parameter*/
			memset(prefix, '\0', DEFLEN_128);
			foreach (word, nvram_safe_get("wl_ifnames"), next) {
				snprintf(prefix, sizeof(prefix), "wl%d_", unit);

				if (handler->cmdno==BLECMD_SET_WIFI_NAME)
					nvram_set(strcat_r(prefix, "ssid", tmp), str_data);
				else if (handler->cmdno==BLECMD_SET_WIFI_PWD)
					nvram_set(strcat_r(prefix, "wpa_psk", tmp), str_data);

				nvram_set(strcat_r(prefix, "auth_mode_x", tmp), "psk2");
				nvram_set(strcat_r(prefix, "crypto", tmp), "aes");
				if (nvram_match("sw_mode", "1"))
					nvram_set(strcat_r(prefix, "channel", tmp), "0");
				unit++;
			}
#ifdef RTCONFIG_LANTIQ
			nvram_set_int("wave_flag", WAVE_FLAG_QIS);
#endif
			break;
		case BLECMD_SET_WAN_PORT:
			notify_rc_and_wait("restart_wan_if 0");
			break;
		case BLECMD_SET_WAN_TYPE:
			if(!strncmp(str_data, "static", sizeof(str_data))) {
				nvram_set("wan_dhcpenable_x", "0");
				nvram_set("wan_nat_x", "1");
				nvram_set("wan0_dhcpenable_x", "0");
				nvram_set("wan0_nat_x", "1");
			}
			else if(!strncmp(str_data, "v6plus", sizeof(str_data))) {
				nvram_set("ipv6_service", "ipv6pt");
				strlcat(do_rc_service, delim, sizeof(do_rc_service));
				strlcat(do_rc_service, "restart_net", sizeof(do_rc_service));
			}
		case BLECMD_SET_WAN_PPPOE_NAME:
		case BLECMD_SET_WAN_PPPOE_PWD:
		case BLECMD_SET_WAN_IPADDR:
		case BLECMD_SET_WAN_SUBNET_MASK:
		case BLECMD_SET_WAN_GATEWAY:
		case BLECMD_SET_WAN_DNS_ENABLE:
		case BLECMD_SET_WAN_DNS1:
		case BLECMD_SET_WAN_DNS2:
			memset(prefix, '\0', DEFLEN_128);
			strncpy(prefix, handler->nvram, strlen(handler->nvram)); 
			AdvSplit_CombineStr(prefix, "_", "wan", "0", tmp);
			nvram_set(tmp, str_data);
			break;
		case BLECMD_SET_ADMIN_NAME:
			snprintf(tmp, sizeof(tmp), "%s>%s", str_data, nvram_safe_get("http_passwd"));
			nvram_set("acc_list",tmp);
			break;
		case BLECMD_SET_ADMIN_PWD:
			snprintf(tmp, sizeof(tmp), "%s>%s", nvram_safe_get("http_username"), str_data);
			nvram_set("acc_list",tmp);
			break;
		case BLECMD_SET_ATH1_CHAN:
			unit = 1;
			memset(countryCode, 0, sizeof(countryCode));
			memset(prefix, '\0', DEFLEN_128);

			snprintf(prefix, sizeof(prefix), "wl%d_", unit);
			strncpy(countryCode, nvram_safe_get(strcat_r(prefix, "country_code", tmp)), 2);

			list = get_channel_list_via_driver(unit, word, sizeof(word));
			if (list<=0 && countryCode[0] != 0xff && countryCode[1] != 0xff) {   // 0xffff is default
				list = get_channel_list_via_country(unit, countryCode, word, sizeof(word));
			}

			if (list>0) {
				list=0;
				next = strtok(word, delim_1);
				while (next!=NULL) {
					if (!strncmp(next, str_data, strlen(next))) {
						list=1;
						break;
					}
					next = strtok(NULL, delim_1);
				}

				if (list)
					nvram_set(strcat_r(prefix, "channel", tmp), str_data);
			}

			break;
		case BLECMD_SET_JSON_NVRAM:
			set_json_obj_nvram(str_data);
			break;
		case BLECMD_APPLY:
			is_change_lanip = 0;
#ifdef RTCONFIG_LANTIQ
			while(nvram_get_int("wave_ready") == 0){
				fprintf(stderr, "[BLE] wireless not ready, waiting...\n");
				sleep(5);
			}
			nvram_set_int("wave_action", 3);
#endif
#if defined(RTCONFIG_AMAS)
			if ( aimesh_mode )
				nvram_set("wifison_ready", "0");
			else
#endif
				nvram_set("wifison_ready", "1");
#if defined(RTCONFIG_AMAS)
			if ( !aimesh_mode )
				mount("overlayfs", "/www", "overlayfs", MS_MGC_VAL, "lowerdir=/www,upperdir=/www-sys");
#endif
#if  defined(RTCONFIG_QCA) && defined(RTCONFIG_QCA_LBD)
			{
				const int max_nr_wl_if = min(MAX_NR_WL_IF, WL_5G_2_BAND + 1);
				char ssid[32+1] = {0};
				int band=0, nr_ssid=0;

				for (band = WL_2G_BAND; band < max_nr_wl_if; ++band) {
					if (absent_band(band))
						continue;

					memset(prefix, '\0', DEFLEN_128);
					snprintf(prefix, sizeof(prefix), "wl%d_", band);
#if defined(RTCONFIG_WIRELESSREPEATER)
					if (nvram_match("sw_mode", "2")
#if !defined(RTCONFIG_CONCURRENTREPEATER)
						&& nvram_get_int("wlc_band") == band && nvram_invmatch("wlc_ssid", "")
#endif
					)
					snprintf(prefix, sizeof(prefix), "wl%d.1_", band);
#endif

					if (!strlen(nvram_pf_safe_get(prefix, "ssid")))
						continue;
					if (*ssid == '\0') {
						strlcpy(ssid, nvram_pf_safe_get(prefix, "ssid"), sizeof(ssid));
						nr_ssid++;
						continue;
					}
					if (strcmp(ssid, nvram_pf_safe_get(prefix, "ssid")))
						continue;
					nr_ssid++;
				}
				if (nr_ssid > 1)
					nvram_set_int("smart_connect_x", 1);
			}
#endif

			if (nvram_match("sw_mode", "3"))
			{

				if (nvram_match("x_Setting", "0"))
				{
					nvram_set("lan_proto", "dhcp");
					nvram_set("lan_dnsenable_x", "1");
					chk_service = 3;
				}
#if defined(RTCONFIG_AMAS)
				if ( aimesh_mode ) {
					nvram_set("wlc_psta", "2");
					nvram_set("wlc_dpsta", "2");
					/* set in watchdog
					nvram_set("x_Setting", "1");
					*/
					nvram_set("w_Setting", "1");
					nvram_set("re_mode", "1");
					/* AiMesh use 5G high band for upstream => no sta2 here */
					nvram_set("sta_ifnames", "sta0 sta1");
					nvram_set("sta_phy_ifnames", "sta0 sta1");

					nvram_set("wlc0_ssid", nvram_safe_get("wl0_ssid"));
					nvram_set("wlc0_wpa_psk", nvram_safe_get("wl0_wpa_psk"));
					nvram_set("wlc0_auth_mode", nvram_safe_get("wl0_auth_mode_x"));
					nvram_set("wl0_auth_mode", nvram_safe_get("wl0_auth_mode_x"));
					nvram_set("wlc0_crypto", nvram_safe_get("wl0_crypto"));

					nvram_set("wlc1_ssid", nvram_safe_get("wl1_ssid"));
					nvram_set("wlc1_wpa_psk", nvram_safe_get("wl1_wpa_psk"));
					nvram_set("wlc1_auth_mode", nvram_safe_get("wl1_auth_mode_x"));
					nvram_set("wl1_auth_mode", nvram_safe_get("wl1_auth_mode_x"));
					nvram_set("wlc1_crypto", nvram_safe_get("wl1_crypto"));

					nvram_set("wl2_auth_mode", nvram_safe_get("wl2_auth_mode_x"));

					doSystem("wlanconfig sta0 create wlandev wifi0 wlanmode sta nosbeacon");
					sleep(1);
					doSystem("ifconfig sta0 up");
					doSystem("wlanconfig sta1 create wlandev wifi1 wlanmode sta nosbeacon");
					sleep(1);
					doSystem("ifconfig sta1 up");
				} else
#endif
					nvram_set("hive_re_autoconf", "1");
				nvram_unset("cfg_master");
			}
			else if (nvram_match("sw_mode", "2")) {
				memset(do_rc_service, '\0', DEFLEN_256);
				strlcat(do_rc_service, "ble_qis_done;reboot", sizeof(do_rc_service));
			}
			else // router mode
			{
				//////// IP conflict detection
				int wan_state, wan_sbstate, wan_auxstate;
				char *lan_ipaddr, *lan_netmask;
				char *wan_ipaddr, *wan_netmask;
				in_addr_t lan_mask, tmp_ip;


				wan_state = nvram_get_int("wan0_state_t");
				wan_sbstate = nvram_get_int("wan0_sbstate_t");
				wan_auxstate = nvram_get_int("wan0_auxstate_t");
				if (wan_state == 4 && wan_sbstate == 4 && wan_auxstate == 0)
				{
					lan_ipaddr = nvram_safe_get("lan_ipaddr");
					lan_netmask = nvram_safe_get("lan_netmask");

					wan_ipaddr = nvram_safe_get("wan0_ipaddr");
					wan_netmask = nvram_safe_get("wan0_netmask");

					if (inet_deconflict(lan_ipaddr, lan_netmask, wan_ipaddr, wan_netmask, &lan_addr)) {
						DBG_ERR("[IP conflict]: change lan IP to %s\n", inet_ntoa(lan_addr));
						lan_mask = inet_network(lan_netmask);
						tmp_ip = ntohl(lan_addr.s_addr);
						dhcp_start_addr.s_addr = htonl(tmp_ip + 1);
						dhcp_end_addr.s_addr = htonl((tmp_ip | ~lan_mask) & 0xfffffffe);
						is_change_lanip = 1;
					}
				}
				nvram_set("cfg_master", "1");
			}

			if(strlen(do_rc_service))
			{
				/* do rc_service */
				if (strstr(do_rc_service, "ble_qis_done"))
				{
					if (chk_service==3)
					{
						if (strstr(do_rc_service, "chpass"))
						{
							notify_rc_and_wait("chpass");
							notify_rc_and_wait("restart_ftpsamba");
						}
 
						memset(do_rc_service, '\0', DEFLEN_256);
						strlcat(do_rc_service, "ble_qis_done;restart_allnet", sizeof(do_rc_service));
					}
					else {
						chk_service = 1;
					}

					nvram_set_int("bt_turn_off", 1);	//QIS finish.
#ifdef RTCONFIG_LANTIQ
					nvram_set("x_Setting", "1");
					notify_rc_and_wait("chpass");
#elif defined(RTCONFIG_FIXED_BRIGHTNESS_RGBLED)
					set_rgbled(RGBLED_APPLY_EVENT);
#endif
				}
				else
				{
					str_service = strtok(do_rc_service, delim);
					while (str_service!=NULL)
					{
						DBG_INFO("[rc do service]: %s \n", str_service);
						notify_rc_and_wait(str_service);
						str_service = strtok(NULL, delim);
					}
				}

				if (chk_service)
				{
					if ( chk_service == 1 )
					{
#ifdef RTCONFIG_BWDPI
#ifndef RTCONFIG_LANTIQ
						nvram_set("wrs_protect_enable", "0");  // default set to disable for GDPR
						nvram_set("wrs_mals_t", "0");
						nvram_set("wrs_cc_t", "0");
						nvram_set("wrs_vp_t", "0");
#if defined(RTCONFIG_WIFI_SON) && !defined(MAPAC1750)
#if defined(RTCONFIG_AMAS)
						if ( !aimesh_mode )
#endif
						{
							nvram_set("bwdpi_db_enable", "1");
							nvram_set("apps_analysis", "1");
						}
#endif
						nvram_set("TM_EULA", "0"); // default set to disable for GDPR
#endif
#endif
						if (nvram_match("sw_mode", "2")) {
							goto qis_end;
						}

#if defined(RTCONFIG_WIFI_SON)
#if defined(RTCONFIG_AMAS)
						if ( !aimesh_mode )
#endif
						{
							strlcat(do_rc_service, delim, sizeof(do_rc_service));
							strlcat(do_rc_service, "start_hyfi_process", sizeof(do_rc_service));
						}
#endif
						strlcat(do_rc_service, delim, sizeof(do_rc_service));
						strlcat(do_rc_service, "restart_firewall", sizeof(do_rc_service));
					} else {
						eval("iwconfig", "ath1", "channel", nvram_safe_get("wl1_channel"));

						eval("modprobe", "-r", "shortcut_fe_cm");
						eval("modprobe", "-r", "shortcut_fe_ipv6");
						eval("modprobe", "-r", "shortcut_fe");
					}

					if ( is_change_lanip )
					{
						nvram_set("lan_ipaddr", inet_ntoa(lan_addr));
						nvram_set("dhcp_start", inet_ntoa(dhcp_start_addr));
						nvram_set("dhcp_end", inet_ntoa(dhcp_end_addr));

						strlcat(do_rc_service, delim, sizeof(do_rc_service));
						strlcat(do_rc_service, "restart_net_and_phy", sizeof(do_rc_service));
						logmessage("BLUEZ", "[IP conflict]: restart_net_and_phy\n");
					}
#if defined(RTCONFIG_AMAS)
					if ( !aimesh_mode && !is_change_lanip ) { // We need the httpd to restart to run on new /www directiory
						strlcat(do_rc_service, delim, sizeof(do_rc_service));
						strlcat(do_rc_service, "restart_httpd", sizeof(do_rc_service));
					}
					if ( !aimesh_mode ) {
						strlcat(do_rc_service, delim, sizeof(do_rc_service));
						strlcat(do_rc_service, "stop_amas_lldpd", sizeof(do_rc_service));
					}
#endif
					if (!nvram_match("switch_wantag", "none")) { // If setting IPTV, device should be reboot.
						memset(do_rc_service, '\0', DEFLEN_256);
						strlcat(do_rc_service, "ble_qis_done;reboot", sizeof(do_rc_service));
					}
#if defined(RTCONFIG_ASUSCTRL)
					if (nvram_match("webs_chg_sku", "1")) { // 1代表DUT的QIS Apply要reboot。
						memset(do_rc_service, '\0', DEFLEN_256);
						strlcat(do_rc_service, "ble_qis_done;reboot", sizeof(do_rc_service));
					}
					if (nvram_match("webs_SG_mode", "1")) { // 1代表需要wps被關閉需要restart_wireless。
						strlcat(do_rc_service, delim, sizeof(do_rc_service));
						strlcat(do_rc_service, "restart_wireless", sizeof(do_rc_service));
					}
#endif

qis_end:
					logmessage("BLUEZ", "[service]: %s\n", do_rc_service);
					DBG_INFO("[%s] rc_service: %s", __func__, do_rc_service);
					nvram_set("bt_turn_off_service", do_rc_service);
#if defined(RTCONFIG_NVRAM_ENCRYPT)
					init_enc_nvram();
#endif
				}
			}
			memset(do_rc_service, '\0', DEFLEN_256);

			break;
		default:
			break;
	}
}

// Server Receive Command
//
// UnpackBLECommandData				
// UnpackBLECommandReq				:
// UnpackBLECommandReqNonce			: Send command to get nonce
//
int UnpackBLECommandData(unsigned char *pdu, int pdulen, int *cmdno, unsigned char *data, unsigned int *datalen)
{
	BLE_CHUNK_T *chunk;

	unsigned char payload[MAX_PACKET_SIZE];
	unsigned char *final_data;
	unsigned short payloadlen;
	unsigned short payloadleft;
	unsigned short crc16;
	unsigned short chunkcount;
	unsigned short i;
	unsigned short size, offset;
	size_t final_datalen;

	chunk=(BLE_CHUNK_T *)pdu;
	crc16 = ntohs(chunk->u.firstcmd.csum);
	chunk->u.firstcmd.csum=htons(0);

	if(Adv_CRC16(pdu, pdulen)!=crc16)
		return BLE_RESULT_CHECKSUM_INVALID;

	offset = 0;

	chunkcount = pdulen/BLE_MAX_MTU_SIZE;
	if((pdulen%BLE_MAX_MTU_SIZE)!=0)
		chunkcount++;

	payloadlen = pdulen - BLECMD_CODE_SIZE - BLECMD_SEQNO_SIZE - BLECMD_LEN_SIZE - BLECMD_CSUM_SIZE;

	payloadleft = payloadlen;

	for(i=0;i<chunkcount;i++)
	{
		chunk=(BLE_CHUNK_T *)&pdu[i*BLE_MAX_MTU_SIZE];
		if(i==0) {
			*cmdno = chunk->u.firstcmd.cmdno;
			size = sizeof(chunk->u.firstcmd.chunkdata)>payloadleft?payloadleft:sizeof(chunk->u.firstcmd.chunkdata);
			memcpy(payload+offset, chunk->u.firstcmd.chunkdata, size);
			offset += size;
			payloadleft -= size;
		}
		else {
			size = sizeof(chunk->u.other.chunkdata)>payloadleft?payloadleft:sizeof(chunk->u.other.chunkdata);

			memcpy(payload+offset, chunk->u.other.chunkdata, size);
			offset += size;
			payloadleft -= size;
		}
	}

#ifdef ENCRYPT
	if(*cmdno&BLECMD_WITH_ENCRYPT) {
		final_data = aes_decrypt(fileData_s.ks, payload, payloadlen, &final_datalen);
		if(!final_data) return BLE_RESULT_KEY_INVALID;

		*datalen = (unsigned int)final_datalen;
		memcpy(data, final_data, *datalen);
	}
        else 
	{
		switch (*cmdno)
		{
		case BLECMD_REQ_PUBLICKEY:
		case BLECMD_REQ_SERVERNONCE:
			*datalen = offset;
			memcpy(data, payload, *datalen);
			break;
		default:
			return BLE_RESULT_INVALID;
		}
	}
#else
	*datalen = offset;
	memcpy(data, payload, *datalen);
#endif
	*cmdno = *cmdno &(~BLECMD_WITH_ENCRYPT);
	return (BLE_RESULT_OK);
}

void UnpackBLECommandReq(struct api_handler *handler, unsigned char *data, int datalen)
{
}
void UnpackBLECommandReqServerNonce(struct api_handler *handler, unsigned char *data, int datalen)
{
#ifdef ENCRYPT
	unsigned char *P1 = NULL, *dec = NULL, decode[MAX_PACKET_SIZE];
	size_t decode_len=0;
	TLV_Header tlv_hdr;
	int tlv_len;
	memset(decode, 0, sizeof(decode));
	decode_len = rsa_decrypt(data, datalen, fileData_s.kp, fileData_s.kp_len, decode, sizeof(decode), 0);
	if (decode_len<=0)
	{
		DBG_ERR("Failed to aes_decrypt() !!!");
		return;
	}

	P1 = (unsigned char *)&decode[0];
	memset(&tlv_hdr, 0, sizeof(tlv_hdr));
	memcpy(&tlv_hdr, P1, sizeof(tlv_hdr));
	tlv_len = ntohl(tlv_hdr.len);
	if (tlv_len <= 0)
	{
		DBG_ERR("Parsing data error !!!");
		MFREE(dec);
		return;
	}

	P1 += sizeof(TLV_Header);
	decode_len -= sizeof(TLV_Header);

	if ((unsigned int)tlv_len > decode_len)
	{
		DBG_ERR("Parsing data error !!!");
		MFREE(dec);
		return;
	}

	fileData_s.km_len = tlv_len;
	MALLOC(fileData_s.km, unsigned char, fileData_s.km_len);
	if (IsNULL_PTR(fileData_s.km))
				{
		DBG_ERR("Failed to MALLOC() !!!");
		return;
	}

	memcpy((unsigned char *)&fileData_s.km[0], (unsigned char *)P1, fileData_s.km_len);
	P1 += tlv_len;
	decode_len -= tlv_hdr.len;

	if (sizeof(TLV_Header) > decode_len)
	{
		DBG_ERR("Parsing data error !!!");
		MFREE(dec);
		return;
	}


	memset(&tlv_hdr, 0, sizeof(tlv_hdr));
	memcpy(&tlv_hdr, P1, sizeof(tlv_hdr));

	tlv_len = ntohl(tlv_hdr.len);
	if (tlv_len <= 0)
	{
		DBG_ERR("Parsing data error !!!");
		MFREE(dec);
		return;
	}

	P1 += sizeof(TLV_Header);
	decode_len -= sizeof(TLV_Header);
	
	if ((unsigned int)tlv_len > decode_len)
	{
		DBG_ERR("Parsing data error !!!");
		MFREE(dec);
		return;
	}

	fileData_s.nc_len = tlv_len;
	MALLOC(fileData_s.nc, unsigned char, fileData_s.nc_len);
	
	memcpy((unsigned char *)&fileData_s.nc[0], (unsigned char *)P1, fileData_s.nc_len);


	fileData_s.ns = gen_rand((size_t *)&fileData_s.ns_len);
	if (IsNULL_PTR(fileData_s.ns))
	{
		DBG_ERR("Failed to gen_rand() !!!");
		MFREE(dec);                
	}


	fileData_s.ks = gen_session_key(fileData_s.km, fileData_s.km_len, fileData_s.ns, fileData_s.ns_len, fileData_s.nc, fileData_s.nc_len, (size_t *)&fileData_s.ks_len);

	if (IsNULL_PTR(fileData_s.ks))
	{
		DBG_ERR("Failed to gen_session_key() !!!");
		MFREE(dec);
		return;
	}
#endif
}

// Server Return Response

// PackBLEResponseData			: Receive status for those status only command
// PackBLEResponseOnly
// PackBLEResponseGetWanStatus
// PackBLEResponseGetWifiStatus
// PackBLEResponseReqPublicKey		: Receive public key
// PackBLEResponseReqServerNonce	: Receive Server Nonce
// PackBLEResponseGetMacBleVersion

// 1. encrypt
// 2. add command/seq no/lenght
// 3. add checksum
void PackBLEResponseData(int cmdno, int status, unsigned char *data, int datalen, unsigned char *pdu, int *pdulen, int flag)
{
	BLE_CHUNK_T *chunk;
	unsigned char *final_data;
	unsigned char final_cmdno;
	unsigned short offset;
	unsigned short final_pdulen;
	size_t final_datalen;
	unsigned short final_dataleft;
	unsigned short final_chunkcount, i;
	unsigned short final_payloadlen;
	unsigned short size;

	final_cmdno = (unsigned char)cmdno;
	final_data = data;
	final_datalen = datalen;
#ifdef ENCRYPT
	if(flag&BLE_FLAG_WITH_ENCRYPT) {
		final_data = aes_encrypt(fileData_s.ks, data, datalen, &final_datalen);
		if (final_data==NULL) {
			final_data = data;
			final_datalen = datalen;
		}
		else final_cmdno |= BLECMD_WITH_ENCRYPT;
	}
#endif

	chunk=(BLE_CHUNK_T *)pdu;
	offset = 0;
	i = 0;

	final_payloadlen = final_datalen + BLECMD_CODE_SIZE + BLECMD_SEQNO_SIZE + BLECMD_LEN_SIZE + BLECMD_CSUM_SIZE + BLECMD_STATUS_SIZE;

	final_chunkcount = final_payloadlen/BLE_MAX_MTU_SIZE;
	if(final_payloadlen%BLE_MAX_MTU_SIZE) final_chunkcount++;

	final_pdulen = final_payloadlen;
	final_dataleft = final_datalen;

	for(i=0;i<final_chunkcount;i++)
	{
		chunk=(BLE_CHUNK_T *)&pdu[i*BLE_MAX_MTU_SIZE];
		if(i==0) {
			chunk->u.firstres.cmdno = final_cmdno;
			chunk->u.firstres.seqno = 0;
			chunk->u.firstres.length = htons(final_pdulen);
			chunk->u.firstres.csum = htons(0);
			chunk->u.firstres.status = status;
			size = sizeof(chunk->u.firstres.chunkdata)>final_dataleft?final_dataleft:sizeof(chunk->u.firstres.chunkdata);
			memcpy(chunk->u.firstres.chunkdata, final_data+offset, size);
		}
		else {
			size = sizeof(chunk->u.other.chunkdata)>final_dataleft?final_dataleft:sizeof(chunk->u.other.chunkdata);
			memcpy(chunk->u.other.chunkdata, final_data+offset, size);
		}
		offset += size;
		chunk += BLE_MAX_MTU_SIZE;
	}

	*pdulen = final_pdulen;

	chunk=(BLE_CHUNK_T *)pdu;
	chunk->u.firstres.csum = htons(Adv_CRC16(pdu, *pdulen));

	return;
}

void PackBLEResponseOnly(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS);
}

void PackBLEResponseGetMacBleVersion(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	char *delim="-";
#if defined(RTCONFIG_RGMII_BRCM5301X) || defined(RTCONFIG_QCA) || defined(RTAC3100)
	char *macaddr=nvram_safe_get("lan_hwaddr");
#else
	char *macaddr=nvram_safe_get("et0macaddr");
#endif
	char *groupid=nvram_safe_get("cfg_group");
	char tmp[DEFLEN_128];
	memset(tmp, 0, DEFLEN_128);

	snprintf(tmp, sizeof(tmp), "%s%s%s%d%s%s%s%d%s%d%s%d%s%d", tmp, macaddr
								, delim, BLE_VERSION
								, delim, groupid 
								, delim, ble_get_wanstate(0)
								, delim, EXTEND_AIHOME_API_LEVEL
								, delim, 32		// httpd/web_hook.c MaxLen_http_name
								, delim, 32		// httpd/web_hook.c MaxLen_http_pw
		);

	DBG_INFO("[%s] %s, len:%d", __func__, tmp, strlen(tmp));
	PackBLEResponseData(cmdno, status, (unsigned char*)tmp, strlen(tmp)+1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}

#if defined(RTCONFIG_QCA)
void PackBLEResponseGetAth1Chan(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	FILE *fp;
	char tmp[DEFLEN_128], buf[DEFLEN_128];
	char *pt1,*pt2;
	int band=1, cac=-1;
	int len, freq=-2;

	memset(tmp, '\0', sizeof(tmp));
	memset(buf, '\0', sizeof(buf));
	snprintf(tmp, sizeof(tmp), "%d", freq);

	if (nvram_get_int("sw_mode")==1) {
		sprintf(buf, "iwpriv %s get_cac_state", get_wififname(band));

		fp = popen(buf, "r");
		if (fp) {
			memset(buf, 0, sizeof(buf));
			len = fread(buf, 1, sizeof(buf), fp);
			pclose(fp);
			if (len > 1) {
				buf[len-1] = '\0';
				pt1 = strstr(buf, "get_cac_state:");
				if (pt1) {
					pt2 = pt1 + strlen("get_cac_state: ");
					chomp(pt2);
					cac = safe_atoi(pt2);
				}
			}
		}

		if (cac)
			snprintf(tmp, sizeof(tmp), "%d", cac);
		else {
			memset(buf, '\0', sizeof(buf));
			sprintf(buf, "iwconfig %s", get_wififname(band));

			fp = popen(buf, "r");
			if (fp) {
				memset(buf, 0, sizeof(buf));
				len = fread(buf, 1, sizeof(buf), fp);
				pclose(fp);
				if (len > 1) {
					buf[len-1] = '\0';
					pt1 = strstr(buf, "Frequency:");
					if (pt1) {
						pt2 = strstr(pt1, "GHz");
						if(pt2) {
							memset(tmp, '\0', sizeof(tmp));
							strncpy(tmp,pt1+strlen("Frequency:"),pt2-pt1-strlen("Frequency:"));
							chomp(tmp);
							freq=(int)(1000*atof(tmp));
							freq=(freq-5170)*2/10 + 34;
							memset(tmp, '\0', sizeof(tmp));
							snprintf(tmp, sizeof(tmp), "%d", freq);
						}
					}
				}
			}
		}
	}

	DBG_INFO("[%s] %s, len:%d", __func__, tmp, strlen(tmp));
	PackBLEResponseData(cmdno, status, (unsigned char*)tmp, strlen(tmp)+1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}
#endif

void PackBLEResponseGetWanStatus(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	unsigned char wanss = BLE_WAN_STATUS_ALL_DISCONN;
#if defined(RTCONFIG_DETWAN)
	char *detwan[] = {"detwan", "init", NULL};
	char prefix[DEFLEN_128];
	int max_inf, value, conn=0;
	int wan_proto=-1, conn_tmp=1;
	char tmp[DEFLEN_128];
	int idx=0;

	memset(prefix, '\0', sizeof(prefix));

	if ( !aimesh_mode ) {
		if ( detwan_init == 0 ) {
			// initialize env at first time
			_eval(detwan, NULL, 0, NULL);
			sleep(2);
			detwan_init = 1;
		}
		detwan[1] = NULL;

		/* Check the port status */
		max_inf = nvram_get_int("detwan_max");
		for (idx = 0; idx < max_inf; idx++, conn_tmp=conn_tmp<<1) {
			snprintf(prefix, sizeof(prefix), "detwan_mask_%d", idx);
			if ((value = nvram_get_int(prefix)) != 0) {
				if (get_ports_status((unsigned int)value))
						conn |= conn_tmp;
			}
		}

		if ((conn&PHY_PORT0)&&(conn&PHY_PORT1))
			wanss = BLE_WAN_STATUS_ALL_UNKNOWN;
		else if (conn>0) {
			/* Check the link proto */
			nvram_unset("wan0_ifname");
			_eval(detwan, NULL, 0, NULL);
			idx = 0;
			while ((nvram_safe_get("wan0_ifname")[0] =='\0') && idx<10) {
				sleep(1);
				idx++;
			}
			memset(prefix, '\0', DEFLEN_128);
			snprintf(prefix, sizeof(prefix), "%s", nvram_safe_get("wan0_ifname"));
			wan_proto = nvram_get_int("detwan_proto");

			/* Check the link status */
			notify_rc_and_wait("restart_wan_if 0");
			logmessage("BLUEZ", "wan:%s, proto:%d\n", prefix, wan_proto);

			if (strlen(prefix)) {
#if defined(RTCONFIG_QCA953X) || defined(RTCONFIG_QCA956X)
				if (!strncmp(prefix, "vlan2", strlen(prefix)))
#else
				if (!strncmp(prefix, "eth0", strlen(prefix)))
#endif
				{
					if (wan_proto == 1)
						wanss = BLE_WAN_STATUS_PORT0_DHCP;
					else if (wan_proto == 2)
						wanss = BLE_WAN_STATUS_PORT0_PPPOE;
					else if (wan_proto == 3)
						wanss = BLE_WAN_STATUS_PORT0_DHCP_PPPOE;
					else
						wanss = BLE_WAN_STATUS_PORT0_UNKNOWN;
				}
				else {
					if (wan_proto == 1)
						wanss = BLE_WAN_STATUS_PORT1_DHCP;
					else if (wan_proto == 2)
						wanss = BLE_WAN_STATUS_PORT1_PPPOE;
					else if (wan_proto == 3)
						wanss = BLE_WAN_STATUS_PORT1_DHCP_PPPOE;
					else
						wanss = BLE_WAN_STATUS_PORT1_UNKNOWN;
				}
			}
			else {
				if (conn&PHY_PORT0)
					wanss = BLE_WAN_STATUS_PORT0_UNKNOWN;
				else if (conn&PHY_PORT1)
					wanss = BLE_WAN_STATUS_PORT1_UNKNOWN;
			}

			logmessage("BLUEZ", "wan:%s, proto:%x, internet:%d\n", prefix, wanss, nvram_get_int("link_internet"));
			DBG_INFO("%s, %s[%d], %s[%d], %s[%d], %s[%d]\n"
				"%s, %s[%d]",
					prefix,
					"state", nvram_get_int(strcat_r(prefix, "state_t", tmp)),
					"sbstate", nvram_get_int(strcat_r(prefix, "sbstate_t", tmp)),
					"auxstate", nvram_get_int(strcat_r(prefix, "auxstate_t", tmp)),
					"realip_state", nvram_get_int(strcat_r(prefix, "realip_state", tmp)),
					"None",
					"link_internet", nvram_get_int("link_internet")
			);
		}
	}
	else
#endif  /* RTCONFIG_DETWAN */
	{
		wanss = ble_get_wanstate(1);
	}

	DBG_INFO("[%s] %x", __func__, wanss);
	PackBLEResponseData(cmdno, status, &wanss, 1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}

void PackBLEResponseGetWifiStatus(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	unsigned char wifistatus[2];
	memset(wifistatus, '\0', sizeof(wifistatus));

	wifistatus[0]=0x01;
	PackBLEResponseData(cmdno, status, wifistatus, 1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}

void PackBLEResponseReqPublicKey(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	PackBLEResponseData(cmdno, status, (unsigned char *)&fileData_s.ku[0], fileData_s.ku_len, pdu, pdulen, BLE_RESPONSE_FLAGS);
}

void PackBLEResponseReqServerNonce(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
#ifdef ENCRYPT
	unsigned char *PPP = NULL, *P1 = NULL, *enc = NULL;
	int enc_len;
	TLV_Header tlv_hdr;

	MALLOC(PPP, unsigned char, (sizeof(TLV_Header)+fileData_s.ns_len+sizeof(TLV_Header)+fileData_s.nc_len));
	if (IsNULL_PTR(PPP))
	{
		DBG_ERR("Failed to MALLOC() !!!");
		return;
	}

	P1 = &PPP[0];
	memset(&tlv_hdr, 0, sizeof(tlv_hdr));
	tlv_hdr.len = (unsigned int)htonl(fileData_s.ns_len);
	memcpy((unsigned char *)P1, (unsigned char *)&tlv_hdr, sizeof(tlv_hdr));
	P1 += sizeof(tlv_hdr);
	memcpy((unsigned char *)P1, (unsigned char *)&fileData_s.ns[0], fileData_s.ns_len);
	P1 += fileData_s.ns_len;

	memset(&tlv_hdr, 0, sizeof(tlv_hdr));
	tlv_hdr.len = htonl(fileData_s.nc_len);
	memcpy((unsigned char *)P1, (unsigned char *)&tlv_hdr, sizeof(tlv_hdr));
	P1 += sizeof(tlv_hdr);
	memcpy((unsigned char *)P1, (unsigned char *)&fileData_s.nc[0], fileData_s.nc_len);

	enc = aes_encrypt(fileData_s.km, PPP, sizeof(TLV_Header)+fileData_s.ns_len+sizeof(TLV_Header)+fileData_s.nc_len, (size_t *)&enc_len);

	if (enc_len <= 0)
	{
		DBG_ERR("Failed to aes_encrypt() !!!");
		MFREE(PPP);
	}

	PackBLEResponseData(cmdno, status, enc, enc_len, pdu, pdulen, BLE_RESPONSE_FLAGS); 

	MFREE(PPP);
	MFREE(enc);
#endif
}

void UnPackBLEExceptionGetNvram(int cmdno, int status, unsigned char *data, int datalen, unsigned char *pdu, int *pdulen)
{
	char tmp[DEFLEN_1024];
	
	memset(tmp, '\0', DEFLEN_1024);
	snprintf(tmp, sizeof(tmp), "%s", nvram_safe_get((char *)data));

	DBG_INFO("[%s] %s = %s, len:%d \n", __func__, data, tmp, strlen(tmp));
	PackBLEResponseData(cmdno, status, (unsigned char*)tmp, strlen(tmp)+1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}
void UnPackBLEExceptionSetRcSrv(int cmdno, int status, unsigned char *data, int datalen, unsigned char *pdu, int *pdulen)
{
	char tmp[DEFLEN_256];
	memset(tmp, '\0', DEFLEN_256);
	snprintf(tmp, sizeof(tmp), "%s", (char *)data);
	notify_rc_and_wait(tmp);

	DBG_INFO("[%s] %s, len:%d", __func__, tmp, strlen(tmp));
	PackBLEResponseData(cmdno, status, (unsigned char*)tmp, strlen(tmp)+1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}

void PackBLEResponseGetWanConnState(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	char *delim="-";
	char tmp[DEFLEN_256];

	memset(tmp, '\0', sizeof(tmp));

	snprintf(tmp, sizeof(tmp), "%s=%s%s%s=%s%s%s=%s", "wan0_state_t", nvram_safe_get("wan0_state_t"), delim, 
					     "wan0_sbstate_t", nvram_safe_get("wan0_sbstate_t"), delim, 
					     "wan0_auxstate_t", nvram_safe_get("wan0_auxstate_t") );

	DBG_INFO("[%s] %s, len:%d", __func__, tmp, strlen(tmp));
	PackBLEResponseData(cmdno, status, (unsigned char*)tmp, strlen(tmp)+1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}

#if defined(RTCONFIG_WIRELESSREPEATER)
void PackBLEResponseScanAP(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	char tmp[DEFLEN_32];
	int fLen=0, err=0;

	killall("wlcscan", SIGTERM);
	system("wlcscan");
	
	while (err < 10) {
		if (fileExists(APLIST_TXT)) {
			FileRead_ApList(APLIST_TXT);
			if (fileExists(APLIST_MODIFY_TXT))
				fLen = getFileSize(APLIST_MODIFY_TXT);
			break;
		}
		err++;
		sleep(1);
	}

	DBG_INFO("[%s] length:%d", __func__, fLen);
	snprintf(tmp, sizeof(tmp), "%d", fLen); 
	PackBLEResponseData(cmdno, status, (unsigned char*)tmp, strlen(tmp)+1, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
}

void PackBLEResponseGetScanList(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	FILE *fp;
	unsigned char *fContent;
	int fLen=0, lock, err=0;
	Byte *compr, *uncompr;
	uLong comprLen = 10000* sizeof(int); /* don't overflow on MSDOS */
	uLong uncomprLen = comprLen;

	lock = file_lock("sitesurvey");

	if (fileExists(APLIST_MODIFY_TXT)) {
		fLen = getFileSize(APLIST_MODIFY_TXT);
		if (!fLen || (fContent = (unsigned char *)calloc(fLen, sizeof(unsigned char))) == NULL) {
			DBG_ERR("[%s] Failed! Memory allocate failed ...\n", __func__);
			fContent = NULL;
			err = 1;
		}
		else {
			compr = (Byte*)calloc((uInt)comprLen, 1);
			uncompr = (Byte*)calloc((uInt)uncomprLen, 1);
			err = FileRead_Save(APLIST_MODIFY_TXT, fContent, fLen);

			if (ble_dbg) {
				fp = NULL;
				if((fp = fopen("/tmp/ap_origin.txt", "w+")) != 0) {
					fwrite((char*)fContent, 1, fLen, fp);
				}
				fclose(fp);
			}

			if (!err) {
				compress(compr, &comprLen, (const Bytef*)fContent, fLen);
				DBG_INFO("[%s] Compress length:%lu", __func__, comprLen);

				if (ble_dbg) {
					uncompress(uncompr, &uncomprLen, (const Bytef*)compr, comprLen);
					DBG_INFO("[%s] Uncompress length:%lu", __func__, uncomprLen);

					fp = NULL;
					if((fp = fopen("/tmp/aplist_uncompress.txt", "w+")) != 0) {
						fwrite((char*)uncompr, 1, (int)uncomprLen, fp);
					}
					fclose(fp);
				}
			}
		}
	}
	else
		err = 1;

	if (!err) {
		fileData_s.aplist_len = (int)comprLen +50;
		if ((fileData_s.aplist = (unsigned char *)calloc(fileData_s.aplist_len, sizeof(unsigned char))) == NULL) {
			DBG_ERR("[%s] Failed! ap_list Memory allocate failed ...\n", __func__);
			fileData_s.aplist_len = 0;
			PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
		}
		else
			PackBLEResponseData(cmdno, status, (unsigned char*)compr, (int)comprLen+1, fileData_s.aplist, &fileData_s.aplist_len, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
	}
	else
		PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);

	file_unlock(lock);        
	free(fContent);
	free(compr);
	free(uncompr);
}
#endif

void PackBLEResponseGetUIsupport(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	unsigned char *tmp;
	int fLen=0, err=0;

	fLen = getFileSize(UI_SUPPORT_JSON);
	if (!fLen || (tmp = (unsigned char *)calloc(fLen, sizeof(unsigned char))) == NULL) {
		DBG_ERR("[%s] Failed! Memory allocate failed ...\n", __func__);
		tmp = NULL;
		err = 1;
	}
	else {
		err = FileRead_Save(UI_SUPPORT_JSON, tmp, fLen);
		if (err)
			err = 1;
	}

	DBG_INFO("[%s] %s, len:%d \n", __func__, tmp, fLen);
	if (!err)
		PackBLEResponseData(cmdno, status, tmp, fLen, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
	else
		PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);

	free(tmp);
}

void PackBLEResponseTrigFrsLiveUpdate(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	notify_rc_and_wait("start_webs_update");
	sleep(1);

	PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS);
}

void PackBLEResponseGetFrsLiveUpdateInfo(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	struct json_object *FrsLiveUpdateInfor_obj = json_object_new_object();
	unsigned char *tmp;
	int fLen=0, err=0;

	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_update", json_object_new_string(nvram_safe_get("webs_state_update")));		// 0代表check還在跑，1代表live update check檢查完成
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_flag", json_object_new_string(nvram_safe_get("webs_state_flag")));			// 0 代表沒有新fw，1代表有新fw
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_error", json_object_new_string(nvram_safe_get("webs_state_error")));			// 0 代表沒error，其他值有error
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_info", json_object_new_string(nvram_safe_get("webs_state_info")));			// 新fw版本號碼
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_upgrade", json_object_new_string(nvram_safe_get("webs_state_upgrade")));
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_error_msg", json_object_new_string(nvram_safe_get("webs_state_error_msg")));
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_state_level", json_object_new_string(nvram_safe_get("webs_state_level")));
#if defined(RTCONFIG_ASUSCTRL)
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_chg_sku", json_object_new_string(nvram_safe_get("webs_chg_sku")));				// 1代表DUT的QIS Apply要reboot。
	json_object_object_add(FrsLiveUpdateInfor_obj, "webs_SG_mode", json_object_new_string(nvram_safe_get("webs_SG_mode")));				// 1代表需要wps被關閉需要restart_wireless。
	json_object_object_add(FrsLiveUpdateInfor_obj, "SG_mode", json_object_new_string(nvram_safe_get("SG_mode")));					// 1代表此機種是新加坡的機種。
#endif
	json_object_to_file(FRS_LIVEUPDATEINFO_JSON, FrsLiveUpdateInfor_obj);

	if(FrsLiveUpdateInfor_obj)
                json_object_put(FrsLiveUpdateInfor_obj);

	fLen = getFileSize(FRS_LIVEUPDATEINFO_JSON);
	if (!fLen || (tmp = (unsigned char *)calloc(fLen, sizeof(unsigned char))) == NULL) {
		DBG_ERR("[%s] Failed! Memory allocate failed ...\n", __func__);
		tmp = NULL;
		err = 1;
	}
	else {
		err = FileRead_Save(FRS_LIVEUPDATEINFO_JSON, tmp, fLen);
		if (err)
			err = 1;
	}

	DBG_INFO("[%s] %s, len:%d \n", __func__, tmp, fLen);
	if (!err)
		PackBLEResponseData(cmdno, status, tmp, fLen, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
	else
		PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);

	free(tmp);
}

void PackBLEResponseGetIPTVProfile(int cmdno, int status, unsigned char *pdu, int *pdulen)
{
	unsigned char *fContent;
	int fLen=0, err=0;
	Byte *compr, *uncompr;
	uLong comprLen = 10000* sizeof(int); /* don't overflow on MSDOS */
	uLong uncomprLen = comprLen;

	if (fileExists(IPTV_PROFILE_JSON)) {
		fLen = getFileSize(IPTV_PROFILE_JSON);
		if (!fLen || (fContent = (unsigned char *)calloc(fLen, sizeof(unsigned char))) == NULL) {
			DBG_ERR("[%s] Failed! Memory allocate failed ...\n", __func__);
			fContent = NULL;
			err = 1;
		}
		else {
			compr = (Byte*)calloc((uInt)comprLen, 1);
			uncompr = (Byte*)calloc((uInt)uncomprLen, 1);
			err = FileRead_Save(IPTV_PROFILE_JSON, fContent, fLen);

			if (!err) {
				compress(compr, &comprLen, (const Bytef*)fContent, fLen);
				DBG_INFO("[%s] Compress length:%lu", __func__, comprLen);

				if (ble_dbg) {
					uncompress(uncompr, &uncomprLen, (const Bytef*)compr, comprLen);
					DBG_INFO("[%s] Uncompress length:%lu", __func__, uncomprLen);
				}
			}
		}
	}
	else
		err = 1;

	if (!err) {
		fileData_s.aplist_len = (int)comprLen +50;
		if ((fileData_s.aplist = (unsigned char *)calloc(fileData_s.aplist_len, sizeof(unsigned char))) == NULL) {
			DBG_ERR("[%s] Failed! ap_list Memory allocate failed ...\n", __func__);
			fileData_s.aplist_len = 0;
			PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
		}
		else
			PackBLEResponseData(cmdno, status, (unsigned char*)compr, (int)comprLen+1, fileData_s.aplist, &fileData_s.aplist_len, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);
	}
	else
		PackBLEResponseData(cmdno, status, NULL, 0, pdu, pdulen, BLE_RESPONSE_FLAGS|BLE_FLAG_WITH_ENCRYPT);

	free(fContent);
	free(compr);
	free(uncompr);
}
