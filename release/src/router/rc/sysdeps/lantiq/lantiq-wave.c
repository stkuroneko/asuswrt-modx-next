
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bcmnvram.h>
#include <shutils.h>

#include <rc.h>
#include <shared.h>
#include <tcode.h>
// #include "web-qtn.h"
#include <fapi_wlan_private.h>
#include <fapi_wlan.h>
#include <help_objlist.h>
#include <wlan_config_api.h>
#ifdef RTCONFIG_AMAS
#include <obd.h>
#endif

#include "lantiq_common.h"

#define WIFINAME_MAX_LEN 20
#define MAX_CLI_CMD_LEN 255

extern void WLCNT_TRIGGER(char *eaddr, char *ifname, int online);
void set_usb2_to_usb3(void);
void set_usb3_to_usb2(void);

#define FAPI_DB_AP_SECURITY0 "/opt/lantiq/wave/db/instance/wlan0/Device.WiFi.AccessPoint.Security"
#define FAPI_DB_AP_SECURITY1 "/opt/lantiq/wave/db/instance/wlan2/Device.WiFi.AccessPoint.Security"

#define RADIUS_PASSWORD_LEN 100

#define RADIO_CONFIG_FILE "/tmp/wlan_wave/set_radio_config.txt"
#define RADIO_BASIC_CONFIG_FILE "/tmp/wlan_wave/set_radio_basic_config.txt"
#define MACLIST_CONFIG_FILE "/tmp/wlan_wave/set_maclist_config.txt"

#define DB_LOCATION "/jffs/db_instance_20180622.tgz"
#define CMD_LOAD_DB "cd /opt/lantiq/wave/; rm -rf db/default; rm -rf db/instance; rm -rf confs; tar zxf /jffs/db_instance_20180622.tgz; rm -f confs/wlan_notification_*"
#define CMD_SAVE_DB "rm /jffs/db_instance_20180622.tgz; cd /opt/lantiq/wave/; tar zcf /jffs/db_instance_20180622.tgz db/default/ db/instance/ confs/"

#define RE_CONFIG_FILE "/tmp/wlan_wave/set_re_config.txt"

int restart_wifi=0, restart_qo=0, restart_fwl=0;

int config_guest_network_security(int vap_index, int unit, int subunit);
int config_guest_network_professional(int vap_index, int unit, int subunit);
//int aimesh_set_channel(int unit);
int wave_set_macfilter_enable(int unit, int subunit,int enable);
int wave_set_radio_basic_aimesh(int unit, int subunit);
int wave_set_radio_tr181_aimesh(int unit, int subunit);
#ifdef RTCONFIG_AMAS
void wave_set_sta_config(void);
static void wave_add_beacon_vsie(void);
static void wave_del_beacon_vsie(void);
static void wave_add_probe_req_vsie(void);
static void wave_del_probe_req_vsie(void);
static void wave_clear_all_probe_req_vsie(int unit);
#endif

#define VAP_IDX_FILE "/tmp/cur_vap_asuswrt.txt"

int gen_vap_index_file(int vap_index)
{
	FILE *fp = fopen(VAP_IDX_FILE, "w+");

	if(vap_index == 6){
		fprintf(fp, "wlan0.0");
	}else if (vap_index == 7){
		fprintf(fp, "wlan0.1");
	}else if (vap_index == 8){
		fprintf(fp, "wlan0.2");
	}else if (vap_index == 9){
		fprintf(fp, "wlan2.0");
	}else if (vap_index == 10){
		fprintf(fp, "wlan2.1");
	}else if (vap_index == 11){
		fprintf(fp, "wlan2.2");
	}
	fclose(fp);

	return 1;
}

int del_vap_index_file(void)
{
	unlink(VAP_IDX_FILE);
}

void unload_mtlk(void)
{
	while(pidof("hostapd_wlan0") > 0){
		system("kill -9 `pidof hostapd_wlan0`");
	}
	while(pidof("hostapd_wlan2") > 0){
		system("kill -9 `pidof hostapd_wlan2`");
	}
	while(pidof("drvhlpr_wlan0") > 0){
		system("kill -9 `pidof drvhlpr_wlan0`");
	}
	while(pidof("drvhlpr_wlan2") > 0){
		system("kill -9 `pidof drvhlpr_wlan2`");
	}
#if 0
	while(pidof("wave_monitor") > 0){
		system("kill -9 `pidof wave_monitor`");
	}
#endif
	wlan_uninit();
	nvram_set("wave_ready", "0");
	system("rm -rf /opt/lantiq/wave/confs/; mkdir /opt/lantiq/wave/confs/");
	system("rm -rf /tmp/wlan_wave/");
	system("rm -rf /opt/lantiq/wave/db/default/");
	system("rm -rf /opt/lantiq/wave/db/instance/");
	clean_wave_db();
}

void update_txburst_status(void)
{
	int txburst_status;
	system("nvram set wl1_frameburst=\"`iwpriv wlan0 gTxopConfig|awk '{print $3}'`\"");
	txburst_status = nvram_get_int("wl1_frameburst");
	if(txburst_status == 0){
		nvram_set("wl1_frameburst", "off");
	}else{
		nvram_set("wl1_frameburst", "on");
	}
}

void clean_wave_db(void)
{
	system("rm -f /jffs/db_*.tgz");
	system("rm -rf /jffs/db");
}

int skip_ifconfig_up(char *wlan_ifname)
{
	int ret;

	ret = 0;
	if(strcmp(wlan_ifname, "wlan0") == 0){
		if(nvram_get_int("wl0_radio") == 0){
			_dprintf("[%s][%d] wl0_radio=0, skip IFUP wlan0\n",
				__func__, __LINE__);
			ret = -1;
		}
	}else if(strcmp(wlan_ifname, "wlan0.0") == 0){
		if(nvram_get_int("wl0.1_bss_enabled") == 0){
			_dprintf("[%s][%d] wl0.1_bss_enabled=0, skip IFUP"
						"wlan0.0\n", __func__, __LINE__);
			ret = -1;
		}
	}else if(strcmp(wlan_ifname, "wlan0.1") == 0){
		if(nvram_get_int("wl0.2_bss_enabled") == 0){
			_dprintf("[%s][%d] wl0.2_bss_enabled=0, skip IFUP"
						"wlan0.1\n", __func__, __LINE__);
			ret = -1;
		}
	}else if(strcmp(wlan_ifname, "wlan0.2") == 0){
		if(nvram_get_int("wl0.3_bss_enabled") == 0){
			_dprintf("[%s][%d] wl0.3_bss_enabled=0, skip IFUP"
						"wlan0.2\n", __func__, __LINE__);
			ret = -1;
		}
	}else if(strcmp(wlan_ifname, "wlan2") == 0){
		if(nvram_get_int("wl1_radio") == 0){
			_dprintf("[%s][%d] wl1_radio=0, skip IFUP wlan2\n",
				__func__, __LINE__);
			ret = -1;
		}
	}else if(strcmp(wlan_ifname, "wlan2.0") == 0){
			if(nvram_get_int("wl1.1_bss_enabled") == 0){
				_dprintf("[%s][%d] wl1.1_bss_enabled=0, skip IFUP"
							"wlan2.0\n", __func__, __LINE__);
				ret = -1;
			}
		}else if(strcmp(wlan_ifname, "wlan2.1") == 0){
			if(nvram_get_int("wl1.2_bss_enabled") == 0){
				_dprintf("[%s][%d] wl1.2_bss_enabled=0, skip IFUP"
							"wlan2.1\n", __func__, __LINE__);
				ret = -1;
			}
		}else if(strcmp(wlan_ifname, "wlan2.2") == 0){
			if(nvram_get_int("wl1.3_bss_enabled") == 0){
				_dprintf("[%s][%d] wl1.3_bss_enabled=0, skip IFUP"
							"wlan2.2\n", __func__, __LINE__);
				ret = -1;
			}
		}
	return ret;
}
int wl_wave_unit(int unit){
	if(unit == 1)
		return 2;	/* 5G */
	else
		return 0;	/* 2G */
}

char wl_wave_unit_str[2][3] = {"0", "2"};

static struct country_code_list_s {
	char *regulation_domain;
	char *country_code;
} country_code_list[] = {
	{ "AU", "AU"},
	{ "CA", "CA"},
	{ "CN", "CN"},
	{ "GB", "GB"},
	{ "KR", "KR"},
	{ "US", "US"},
	{ NULL, NULL}
};

static struct psd_mod_country_list_s {
	char *tcode;
	char *ori_ccode;
	char *mod_ccode;
} psd_mod_country_list[] = {
	{ "AA", "KR", "US"},
	{ "KR", "AU", "US"},
	{ "CN", "KR", "US"},
	{ "AU", "KR", "US"},
	{ NULL, NULL, NULL}
};

enum {
	DB_AP_SECURITY = 0,
	DB_AP_PROFESSIONAL,
	DB_WDS,
	DB_RADIO_VENDOR,
	DB_RADIO_BASIC,
	DB_END
};

#define MAX_LEN_FAPI_DB_NAME 255
char fapi_db_list[DB_END][MAX_LEN_FAPI_DB_NAME] = {
	/* DB_AP_SECURITY */
	"Device.WiFi.AccessPoint.Security",
	/* DB_AP_PROFESSIONAL */
	"Device.WiFi.AccessPoint",
	/* DB_WDS */
	"Device.WiFi.AccessPoint.X_LANTIQ_COM_Vendor",
	/* DB_RADIO_VENDOR */
	"Device.WiFi.Radio.X_LANTIQ_COM_Vendor",
	/* DB_RADIO_BASIC */
	"Device.WiFi.Radio"
};

int sync_nvram_wireless(void)
{
	_dprintf("sync_nvram_wireless: todo\n");
	return 1;
}

int write_to_file(char *file_name, char *str_to_append)
{
	FILE *fp = fopen(file_name, "w+");
	fprintf(fp, "%s", str_to_append);
	fclose(fp);
	return 1;
}

/* return 1: need to ifconfigUp */
int update_fapi_db(FILE *fp_config, int unit, int db_name_index, char *item_name, char *new_value)
{
	FILE *fp_db;
	char *ptr;
	char buf[255];
	char fapi_db_name[255];
	char wave_ifname[255];
	int wave_index;

	if(unit == 0 || unit == 1)
		wave_index = wl_wave_unit(unit);
	else
		wave_index = unit;	/* vap */

	memset(wave_ifname, 0, sizeof(wave_ifname));
	getInterfaceName(wave_index, wave_ifname);

	/* write to temp tr181 config file */
	fprintf(fp_config, "%s%s\n", item_name, new_value);

	memset(fapi_db_name, 0, sizeof(fapi_db_name));
	snprintf(fapi_db_name, sizeof(fapi_db_name),
		"/opt/lantiq/wave/db/instance/%s/%s",
		wave_ifname, fapi_db_list[db_name_index]);

	fp_db = fopen(fapi_db_name, "r");

	if(fp_db != NULL){
		memset(buf, 0, sizeof(buf));
		while(fgets(buf, sizeof(buf), fp_db)){
			if(strncmp(buf, item_name, strlen(item_name)) == 0){
				ptr = strchr(buf, '=');
				ptr++;
				if(ptr[strlen(ptr)-1] == '\n')
					memset(&(ptr[strlen(ptr)-1]), 0, sizeof(char));
				if(strcmp(ptr, new_value) == 0){
#if 0
					_dprintf("[%s][%d] [%s][%s] = [%s], return 0\n",
						__func__, __LINE__, fapi_db_list[db_name_index],
						ptr, new_value);
#endif
					fclose(fp_db);
					return 0;
				}else{
					_dprintf("[%s][%d] [%s][%s] changed, [%s]!=[%s]\n",
						__func__, __LINE__, fapi_db_list[db_name_index],
						item_name, ptr, new_value);
					fclose(fp_db);
					return 1;
				}
			}

		}
	}
	fclose(fp_db);

	_dprintf("[%s][%d] [%s][%s][%s] new item\n", __func__, __LINE__,
		fapi_db_list[db_name_index], item_name, new_value);
	return 1;
}

#define SSID_CONFIG_FILE "/tmp/wlan_wave/set_ssid_config.txt"
int set_ssid_by_tr181(int wave_unit, char *ssid)
{
	FILE *fp = fopen(SSID_CONFIG_FILE, "w+");
	char fapi_cmd[MAX_CLI_CMD_LEN] = {0};

	fprintf(fp, "Object_0=Device.WiFi.SSID\n");
	fprintf(fp, "SSID_0=%s\n", ssid);
	fclose(fp);
	memset(fapi_cmd, 0, sizeof(fapi_cmd));
	snprintf(fapi_cmd, sizeof(fapi_cmd),
			"fapi_wlan_cli setSsidTR181 -i %d -f %s",
				wave_unit, SSID_CONFIG_FILE);
	_dprintf(fapi_cmd);
	system(fapi_cmd);

	return 0;
}

int is_security_value_changed(int unit)
{
	FILE *fp_db;
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char buf[255], *ptr;
	char new_gtk_key[20];

	if(unit == 0)
		fp_db = fopen(FAPI_DB_AP_SECURITY0, "r");
	else
		fp_db = fopen(FAPI_DB_AP_SECURITY1, "r");

	wl_nvprefix(prefix, sizeof(prefix), unit, -1);

	snprintf(new_gtk_key, sizeof(new_gtk_key), "%s\n",
		nvram_safe_get(strcat_r(prefix, "wpa_gtk_rekey", tmp)));

	if(fp_db != NULL){
		memset(buf, 0, sizeof(buf));
		while(fgets(buf, sizeof(buf), fp_db)){
			if(!strncmp(buf, "RekeyingInterval_0", 18)){
				if((ptr = strchr(buf, '=')) == NULL){
					fclose(fp_db);
					return 0;
				}

				++ptr;
				if(strcmp(ptr, new_gtk_key) != 0){
					fclose(fp_db);
					return 1;
				}
			}
		}
	}
	fclose(fp_db);
	return 0;
}

int is_radius_value_changed(int unit)
{
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char buf[255], *ptr;
	FILE *fp_db;
	char new_ip[20];
	char new_port[8];
	char new_password[RADIUS_PASSWORD_LEN];

	if(unit == 0)
		fp_db = fopen(FAPI_DB_AP_SECURITY0, "r");
	else
		fp_db = fopen(FAPI_DB_AP_SECURITY1, "r");

	wl_nvprefix(prefix, sizeof(prefix), unit, -1);

	snprintf(new_ip, sizeof(new_ip), "%s\n", nvram_safe_get(strcat_r(prefix, "radius_ipaddr", tmp)));
	snprintf(new_port, sizeof(new_port), "%s\n", nvram_safe_get(strcat_r(prefix, "radius_port", tmp)));
	snprintf(new_password, sizeof(new_password), "%s\n", nvram_safe_get(strcat_r(prefix, "radius_key", tmp)));

	if(fp_db != NULL){
		memset(buf, 0, sizeof(buf));
		while(fgets(buf, sizeof(buf), fp_db)){
			if(!strncmp(buf, "RadiusServerIPAddr_0", 20)){
				if((ptr = strchr(buf, '=')) == NULL){
					fclose(fp_db);
					return 0;
				}

				++ptr;
				if(strcmp(ptr, new_ip) != 0){
					fclose(fp_db);
					return 1;
				}
			}
			else if(!strncmp(buf, "RadiusServerPort_0", 18)){
				if((ptr = strchr(buf, '=')) == NULL){
					fclose(fp_db);
					return 0;
				}

				++ptr;
				if(strcmp(ptr, new_port) != 0){
					fclose(fp_db);
					return 1;
				}
			}
			else if(!strncmp(buf, "RadiusSecret_0", 20)){
				if((ptr = strchr(buf, '=')) == NULL){
					fclose(fp_db);
					return 0;
				}

				++ptr;
				if(strcmp(ptr, new_password) != 0){
					fclose(fp_db);
					return 1;
				}
			}
		}
	}
	fclose(fp_db);

	return 0;
}

int wave_set_SSID(int unit, int subunit)
{
	int ret = 0;
	char ssid[255], ssid_orig[255];
	int wave_unit;
	char ifname[WIFINAME_MAX_LEN] = {0};

	if(subunit > 0){
		if(unit == 1)
			wave_unit = VAP_5G_START + subunit;
		else
			wave_unit = VAP_2G_START + subunit;
	}
	else
		wave_unit = wl_wave_unit(unit);

	snprintf(ssid, sizeof(ssid), "%s",
		nvram_safe_get(wl_nvname("ssid", unit, subunit)));
	getInterfaceName(wave_unit, ifname);
	if(!*ifname) {
		_dprintf("[%s][%d]: invalid if for idx %d, ifname:[%s]\n", __func__, __LINE__, wave_unit, ifname);
		return 0;
	}

	if(strlen(ssid) > 32){
		memset(&(ssid[32]), 0, sizeof(char));
		nvram_set(wl_nvname("ssid", unit, subunit), ssid);
	}

#if 1
	ret = wlan_getSSID(wave_unit, ssid_orig);
	if (ret < 0) {
		_dprintf("[%s][%d] getSSID %s error[%d]\n",
				__func__, __LINE__, ifname, ret);
		return 0;
	}

	if(strcmp(ssid, ssid_orig) == 0){
		_dprintf("[%s][%d] [%s] ssid [%s] is not changed\n",
				__func__, __LINE__, ifname, ssid);
		return 0;
	}
	_dprintf("[%s][%d] set_SSID:[%s][%s]\n",
			__func__, __LINE__, ifname, ssid);
	set_ssid_by_tr181(wave_unit, ssid);
#endif

	return 1;
}

int wave_set_channel(int unit, int subunit)
{
	int ret = 0;
	u_int_32 channel, channel_orig;
	char ifname[WIFINAME_MAX_LEN] = {0};
	int wave_unit;

	wave_unit = wl_wave_unit(unit);

	channel = nvram_get_int(wl_nvname("channel", unit, subunit));
	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_wave(unit, subunit));

	ret = wlan_getChannel(wave_unit, &channel_orig);
	if(ret < 0){
		_dprintf("getChannel %s error[%d]\n", ifname, ret);
		return 0;
	}

	if(channel == channel_orig){
		return 0;
	}

	ret = wlan_setChannel(wave_unit, channel);
	if (ret < 0) {
		_dprintf("setChannel %s error[%d]\n", ifname, ret);
		return 0;
	}else{
		_dprintf("setChannel [%s][%d] ok\n", ifname, channel);
	}

	_dprintf("setChannel:[%s][%d]\n", ifname, channel);

	return 1;
}

int switch_to_20mhz(u_int_32 channel)
{
	char country_code[3];

	snprintf(country_code, sizeof(country_code), "%s",
		nvram_safe_get("wl_country_code"));

	if(strcmp(country_code, "GB") == 0){
		if(channel == 116 || channel == 132 ||
			channel == 136 || channel == 140){
			return 1;
		}
	}else{
		/* a specific case for GUI 20/40/80 */
		if(channel == 165 || channel == 140){
			return 1;
		}
	}
	return 0;
}

int wave_set_channelMode(int unit, int subunit)
{
	int ret = 0;
	u_int_32 channel;
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char ifname[WIFINAME_MAX_LEN] = {0};
	char channelMode[20] = {0};
	char channelMode_orig[20] = {0};
	int wave_unit;

	wave_unit = wl_wave_unit(unit);

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);

	channel = nvram_get_int(strcat_r(prefix, "channel", tmp));
	if(channel == 0)
		wlan_getChannel(wave_unit, &channel);
	snprintf(ifname, sizeof(ifname), "%s", wl_vifname_wave(unit, subunit));

	_dprintf("%s: %s's bw to be %s.\n", __func__, prefix, nvram_safe_get(strcat_r(prefix, "bw", tmp)));

	switch(nvram_get_int(strcat_r(prefix, "bw", tmp))){
		case 0:
			if(unit == 0){
				if(channel <= 6){
					snprintf(channelMode, sizeof(channelMode), "11NGHT40PLUS");
				}else{
					snprintf(channelMode, sizeof(channelMode), "11NGHT40MINUS");
				}
			}else if(unit == 1){
				snprintf(channelMode, sizeof(channelMode), "11ACVHT80");
			}
			break;
		case 1:
			if(unit == 0)
				snprintf(channelMode, sizeof(channelMode), "11NGHT20");
			else if(unit == 1)
				snprintf(channelMode, sizeof(channelMode), "11ACVHT20");
			break;
		case 2:	/* 40MHz */
			if(unit == 0){
				if(channel <= 6){
					snprintf(channelMode, sizeof(channelMode), "11NGHT40PLUS");
				}else{
					snprintf(channelMode, sizeof(channelMode), "11NGHT40MINUS");
				}
			}else if(unit == 1){
				if ((channel >= 36) && (channel <= 64)){
					if (((channel - 36) % 8) == 0){
						snprintf(channelMode, sizeof(channelMode), "11NAHT40PLUS");
					}else{
						snprintf(channelMode, sizeof(channelMode), "11NAHT40MINUS");
					}
				}
				else if ((channel >= 100) && (channel <= 144))
				{
					if (((channel - 100) % 8) == 0){
						snprintf(channelMode, sizeof(channelMode), "11NAHT40PLUS");
					}else{
						snprintf(channelMode, sizeof(channelMode), "11NAHT40MINUS");
					}
				}
				else if ((channel >= 149) && (channel <= 161))
				{
					if (((channel - 149) % 8) == 0){
						fprintf(stderr, "5G channel here\n");
						snprintf(channelMode, sizeof(channelMode), "11NAHT40PLUS");
					}else{
						snprintf(channelMode, sizeof(channelMode), "11NAHT40MINUS");
					}
				}
			}
			break;
		case 3: /* 80MHz */
			if(unit == 1){
				snprintf(channelMode, sizeof(channelMode), "11ACVHT80");
			}
			break;
	}

	/* a specific case for GUI 20/40/80 */
	channel = nvram_get_int(wl_nvname("channel", unit, subunit));
	if( switch_to_20mhz(channel) == 1){
		snprintf(channelMode, sizeof(channelMode), "11ACVHT20");
	}

	ret = wlan_getChannelMode(wave_unit, channelMode_orig);
	if(ret < 0){
		_dprintf("getChannelMode %s error[%d]\n", ifname, ret);
		memset(channelMode_orig, 0, sizeof(channelMode_orig));
	}

	if(strcmp(channelMode, channelMode_orig) == 0){
		return 0;
	}
	ret = wlan_setChannelMode(wave_unit, channelMode,
						0 /* not gOnly */,
						0 /* not nOnly */,
						0 /* not acOnly */);
	if (ret < 0) {
		_dprintf("setChannelMode %s error[%d]\n", ifname, ret);
		return 0;
	}
	_dprintf("setChannelMode :[%s][%s]\n", ifname, channelMode);

	return 1;
}

typedef int(*FapiWlanGenericSetNativeFunc)(int index, ObjList *wlObj, unsigned int flags);
int fapi_wlan_generic_set_native2(FapiWlanGenericSetNativeFunc fapiWlanGenericSetNativeFunc,
	int index,
	ObjList *wlObj,
	char *dbCliFileName,
	unsigned int flags)
{
	if (wlanLoadFromDB(dbCliFileName, "", wlObj) == UGW_SUCCESS)
	{
		setLog("wlan0", wlObj, 0);
		if (fapiWlanGenericSetNativeFunc(index, wlObj, flags) == UGW_SUCCESS)
		{
			return UGW_SUCCESS;
		}
		else
		{
			printf("FAPI_WLAN_CLI, fapiWlanGenericSetNativeFunc return with error\n");
			return UGW_FAILURE;
		}
	}
	else
	{
		printf("FAPI_WLAN_CLI, wlanLoadFromDB return with error\n");
		return UGW_FAILURE;
	}
}

#define AP_CONFIG_FILE "/tmp/wlan_wave/set_ap_config.txt"
int wave_set_ap_professional(int unit, int subunit)
{
	char prefix[] = "wlXXXXXXXXXXXXX_";
	char tmp[100];
	int retVal;
	int db_changed;
	ObjList *dbObjPtr = NULL;
	FILE *fp = fopen(AP_CONFIG_FILE, "w+");

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	// _dprintf("[%s][%d][%s] ing.\n", __func__, __LINE__, prefix);

	_dprintf("[%s][%d][%d][%d]\n",
		__func__, __LINE__, unit, subunit);

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);

	/* Object_0=Device.WiFi.AccessPoint */
	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_AP_PROFESSIONAL]);

	db_changed = 0;

	if(nvram_get_int(strcat_r(prefix, "radio", tmp)) == 1
#ifdef RTCONFIG_PROXYSTA
			&& !mediabridge_mode()
#endif
			){
		// _dprintf("%s: %s radio Enable.\n", __func__, prefix);
		db_changed += update_fapi_db(fp, unit, DB_AP_PROFESSIONAL,
			"Enable_0=", "true");
	}
	else{
		// _dprintf("%s: %s radio Disable.\n", __func__, prefix);
		db_changed += update_fapi_db(fp, unit, DB_AP_PROFESSIONAL,
			"Enable_0=", "false");
	}

	if(nvram_get_int(strcat_r(prefix, "ap_isolate", tmp)) == 1){
		db_changed += update_fapi_db(fp, unit, DB_AP_PROFESSIONAL,
			"IsolationEnable_0=", "true");
	}else{
		db_changed += update_fapi_db(fp, unit, DB_AP_PROFESSIONAL,
			"IsolationEnable_0=", "false");
	}

	if(nvram_get_int(strcat_r(prefix, "closed", tmp)) == 1){
		db_changed += update_fapi_db(fp, unit, DB_AP_PROFESSIONAL,
			"SSIDAdvertisementEnabled_0=", "false");
	}else{
		db_changed += update_fapi_db(fp, unit, DB_AP_PROFESSIONAL,
			"SSIDAdvertisementEnabled_0=", "true");
	}

	fclose(fp);

	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_ap_set_native,
			wl_wave_unit(unit), dbObjPtr, AP_CONFIG_FILE, 0 );
	}else{
		_dprintf("[%s][%d]: skip ap_set_native\n",__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}
}

int wave_set_radio_basic(int unit, int subunit)
{
	FILE *fp = fopen(RADIO_BASIC_CONFIG_FILE, "w+");
	u_int_32 channel;
	int bw;
	int extch_lower=0;
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];

	if(fp == NULL)
	{
		_dprintf("open file error\n");
		return 0;
	}

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	bw = nvram_get_int(strcat_r(prefix, "bw", tmp));
	channel = nvram_get_int(strcat_r(prefix, "channel", tmp));
	extch_lower = !strcmp(nvram_safe_get(strcat_r(prefix, "nctrlsb", tmp)),"lower");

	_dprintf("[%s][%d]bw[%d]channel[%d]nctrlsb[%s]\n",
		__func__, __LINE__, bw, channel,nvram_safe_get(strcat_r(prefix, "nctrlsb", tmp)));

	return wave_set_radio_basic_set_config(unit,subunit,fp,bw,channel,extch_lower);
}

int wave_set_radio_basic_set_config( int unit,int subunit, FILE *fp, int bw, int channel, int extch_lower)
{
	ObjList *dbObjPtr = NULL;
	int db_changed ;
	int retVal;
	char channel_s[5] ;
	char cur_country[10] = {0};
	int wave_unit_2g = wl_wave_unit(0);

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);

	db_changed = 0;
	snprintf(channel_s, sizeof(channel_s), "%d", channel);

	_dprintf("[%s][%d]bw[%d]channel[%d]nctrlsb[%d]\n",
		__func__, __LINE__, bw, channel,extch_lower);

	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_RADIO_BASIC]);

	/* channel */
	if(unit == 0){
		if(channel >= 1 && channel <= 4){
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"ExtensionChannel_0=", "AboveControlChannel");
		}else if (channel >= 10 && channel < 14){
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"ExtensionChannel_0=", "BelowControlChannel");
		}else if (channel >= 5 && channel <= 9) {
			if(extch_lower)
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,"ExtensionChannel_0=", "AboveControlChannel");
			else
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,"ExtensionChannel_0=", "BelowControlChannel");
		}
		fprintf(fp, "OperatingFrequencyBand_0=2.4GHz\n");

		if(bw == 0 || bw == 2){
			/* 20/40 */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingStandards_0=", "n,g");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingChannelBandwidth_0=", "40MHz");
		}else if(bw == 1){
			/* 20 */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingStandards_0=", "n,g");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingChannelBandwidth_0=", "20MHz");
		}
	}else if(unit == 1){
		/* a specific case for GUI 20/40/80 */
		if( switch_to_20mhz(channel) == 1){
			bw = 1;
		}

		if(channel >= 36 && channel <= 64){
			if (((channel - 36) % 8) == 0){
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
					"ExtensionChannel_0=", "AboveControlChannel");
			}else{
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
					"ExtensionChannel_0=", "BelowControlChannel");
			}
		}else if ((channel >= 100) && (channel <= 144)){
			if (((channel - 100) % 8) == 0){
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
					"ExtensionChannel_0=", "AboveControlChannel");
			}else{
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
					"ExtensionChannel_0=", "BelowControlChannel");
			}
		}else if ((channel >= 149) && (channel <= 161)){
			if (((channel - 149) % 8) == 0){
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
					"ExtensionChannel_0=", "AboveControlChannel");
			}else{
				db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
					"ExtensionChannel_0=", "BelowControlChannel");
			}
		}

		if(channel == 0){
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"AutoChannelEnable_0=", "true");
		}else{
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"Channel_0=", channel_s);
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"AutoChannelEnable_0=", "false");
		}

		wlan_getCountryCode(wave_unit_2g, cur_country);
		_dprintf("[%s][%d] current country:[%s]\n",
				__func__, __LINE__, cur_country);
		if(strcmp(cur_country, "GB") == 0 ||
			strcmp(cur_country, "GB ") == 0){
			_dprintf("[%s][%d] set IEEE80211hEnable true\n",
					__func__, __LINE__);
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"IEEE80211hEnabled_0=", "true");
		}else{
			_dprintf("[%s][%d] set IEEE80211hEnable false\n",
					__func__, __LINE__);
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"IEEE80211hEnabled_0=", "false");
		}
		fprintf(fp, "OperatingFrequencyBand_0=5GHz\n");

		if(bw == 0 || bw == 3){
			/* 20/40/80 */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingStandards_0=", "n,a,ac");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingChannelBandwidth_0=", "80MHz");
		}else if(bw == 1){
			/* 20 */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingStandards_0=", "n,a,ac");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingChannelBandwidth_0=", "20MHz");
		}else if(bw == 2){
			/* 40 */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingStandards_0=", "n,a");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
				"OperatingChannelBandwidth_0=", "40MHz");
		}
	}else{
		_dprintf("[%s][%d][%d][%d]: band not supported\n",
				__func__, __LINE__, unit, subunit);
	}

	if(channel == 0){
		db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
			"AutoChannelEnable_0=", "true");
	}else{
		db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
			"Channel_0=", channel_s);
		db_changed += update_fapi_db(fp, unit, DB_RADIO_BASIC,
			"AutoChannelEnable_0=", "false");
	}

	fclose(fp);

	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_radio_set_native,
			wl_wave_unit(unit), dbObjPtr, RADIO_BASIC_CONFIG_FILE, 0);
	}else{
		_dprintf("[%s][%d]: skip radio_set_native\n",__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}

}

int wave_set_radio_tr181(int unit, int subunit)
{
	FILE *fp = fopen(RADIO_CONFIG_FILE, "w+");
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	ObjList *dbObjPtr = NULL;
	int db_changed ;
	int retVal;
	int bw;

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	_dprintf("[%s][%d][%d][%d]\n",
		__func__, __LINE__, unit, subunit);

	if( (client_mode() || aimesh_re_mode()) ){
		_dprintf("[%s][%d] this is client mode, skip\n",
				__func__, __LINE__);
		return 0;
	}
	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);

	db_changed = 0;

	bw = nvram_get_int(strcat_r(prefix, "bw", tmp));

	_dprintf("[%s][%d]bw[%d]\n",
		__func__, __LINE__, bw);


	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_RADIO_VENDOR]);
	if(unit == 0){
		if(bw == 0){	/* 20/40MHz */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexEnabled_0=", "true");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexRssiThreshold_0=", "-70");
		}else if(bw == 2){	/* 40MHz */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexEnabled_0=", "false");
		}else{
			/* 20MHz */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexEnabled_0=", "false");
		}
	}

	fclose(fp);

	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_radio_set_native,
			wl_wave_unit(unit), dbObjPtr, RADIO_CONFIG_FILE, 0);
	}else{
		_dprintf("[%s][%d]: skip radio_set_native\n",__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}

}

#define SECURITY_CONFIG_FILE "/tmp/wlan_wave/set_security_config.txt"

int run_security_fapi(int unit, int subunit, char *beacon_type, char *enc_mode, char *key, char *encryption)
{
	FILE *fp = fopen(SECURITY_CONFIG_FILE, "w+");
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char output_string[MAX_LEN_PARAM_VALUE] = {0};
	int ret = 0 ;
	int security_changed = 0;
	int wave_unit;
	ObjList *dbObjPtr = NULL;

	wave_unit = wl_wave_unit(unit);

	if(subunit > 0){
		if(unit == 0) wave_unit = VAP_2G_START + subunit;
		else if(unit ==1) wave_unit = VAP_5G_START + subunit;
	}

	ret = wlan_getApSecurityModeEnabled(wave_unit, output_string);

	if(ret != 0){
		_dprintf("[%s][%d] getApSecurityMode [%d] error[%d]\n",
			__func__, __LINE__, wave_unit, ret);
	}else{
		if(strcmp(enc_mode, output_string) != 0) security_changed = 1;
		_dprintf("[%s][%d] SecurityMode [%d] [%s][%s]\n",
			__func__, __LINE__, wave_unit, enc_mode, output_string);
	}

	ret = wlan_getPassphrase(wave_unit, output_string);
	if(ret != 0){
		_dprintf("[%s][%d] getPassphrase [%d] error[%d]\n",
			__func__, __LINE__, wave_unit, ret);
	}else{
		if(key != NULL){
			if(strcmp(key, output_string) != 0) security_changed = 1;
			_dprintf("key[%d] [%s][%s]\n", wave_unit, key, output_string);
		}
	}

	if(is_security_value_changed(unit) == 1){
		security_changed = 1;
	}

	if(is_radius_value_changed(unit) == 1){
		security_changed = 1;
	}

	if(security_changed == 0){
		_dprintf("[%s][%d][%d]: value is not changed, "
				"skip security configuration\n",
				__func__, __LINE__, wave_unit);
		return 0;
	}

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);
#if 0
	ret = wlan_setBeaconType(wave_unit, beacon_type);
	if (ret < 0) {
		_dprintf("[%s][%d] setBeaconType [%d] error[%d]\n", __func__, __LINE__, wave_unit, ret);
		return ret;
	}
	_dprintf("setBeaconType:[%d][%s]\n", wave_unit, beacon_type);

	if(!strcmp(beacon_type, "None")) return ret;

	ret = wlan_setKeyPassphrase(wave_unit, 0, key);
	if (ret < 0) {
		_dprintf("[%s][%d] setPassphrase [%d] error[%d]\n", __func__, __LINE__, wave_unit, ret);
		return ret;
	}
	_dprintf("[%s][%d] setPassphrase:[%d][%s]\n", __func__, __LINE__, wave_unit, key);
#else
	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_AP_SECURITY]);
	fprintf(fp, "ModeEnabled_0=%s\n", enc_mode);
	fprintf(fp, "KeyPassphrase_0=%s\n", key);
	fprintf(fp, "BeaconType_0=%s\n", beacon_type);
	fprintf(fp, "EncryptionMode_0=%s\n", encryption);

	if(!strcmp(enc_mode, "WPA2-Enterprise") || !strcmp(enc_mode, "WPA-WPA2-Enterprise")){
		wl_nvprefix(prefix, sizeof(prefix), unit, -1);

		fprintf(fp, "RadiusServerIPAddr_0=%s\n", nvram_safe_get(strcat_r(prefix, "radius_ipaddr", tmp)));
		fprintf(fp, "RadiusServerPort_0=%s\n", nvram_safe_get(strcat_r(prefix, "radius_port", tmp)));
		fprintf(fp, "RadiusSecret_0=%s\n", nvram_safe_get(strcat_r(prefix, "radius_key", tmp)));
		fprintf(fp, "RekeyingInterval_0=%s\n", nvram_safe_get(strcat_r(prefix, "wpa_gtk_rekey", tmp)));
	}
	fclose(fp);

	ret = fapi_wlan_generic_set_native2(fapi_wlan_security_set_native, wl_wave_unit(unit), dbObjPtr, SECURITY_CONFIG_FILE, 0);
	_dprintf("[%s][%d][%d]: security configuration:[%s][%s][%s][%s]\n",
			__func__, __LINE__, wave_unit,
			enc_mode, key, beacon_type, encryption);
#endif

	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);
	return 1;
}

int wave_set_security(int unit, int subunit)
{
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char auth[8];
	char crypto[16];
	char key[65];
	char security[64];
	char beacon_type[16];
	char encryption[32];
	int ret = 0;

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);

	strncpy(auth, nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)), sizeof(auth));
	strncpy(crypto, nvram_safe_get(strcat_r(prefix, "crypto", tmp)), sizeof(crypto));
	strncpy(key, nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)), sizeof(key));
	snprintf(security, sizeof(security), "%s", wav_get_security_str(auth, crypto, 0));

	if(strlen(security) <= 0){
		fprintf(stderr, "[%s][%d] [warning] not support"
				" this auth. mode\n", __func__, __LINE__);
		return 0;
	}

	snprintf(beacon_type, sizeof(beacon_type), wav_get_beacon_type(crypto));
	snprintf(encryption, sizeof(encryption), wav_get_encrypt(crypto));

	ret = run_security_fapi(unit, subunit, beacon_type, security, key, encryption);

	return ret;
}

#define MAX_MACLIST_BUF 1800
#define MACLIST_SEP_ASUSWRT "<"
#define MACLIST_SEP_FAPI ","
int gen_maclist_x_txt(int unit, int subunit, FILE *fp, char *prefix)
{
	char maclist_x[MAX_MACLIST_BUF];
	char *p_mac;
	int num_mac;
	char tmp_str[MAX_MACLIST_BUF];
	int mac_idx;
	int db_changed;
	char tmp[100];

	memset(maclist_x, 0, sizeof(maclist_x));
	memset(tmp_str, 0, sizeof(tmp_str));
	if(unit == 0)
		snprintf(maclist_x, sizeof(maclist_x), "%s%s",
			nvram_safe_get(strcat_r(prefix, "maclist_x", tmp)),
			nvram_safe_get("aimesh_macacl_2g_mac") );
	else
		snprintf(maclist_x, sizeof(maclist_x), "%s%s",
			nvram_safe_get(strcat_r(prefix, "maclist_x", tmp)),
			nvram_safe_get("aimesh_macacl_5g_mac") );
	num_mac = 0;
	p_mac= strtok(maclist_x, MACLIST_SEP_ASUSWRT);
	db_changed = 0;
	while( p_mac != NULL ){
		for(mac_idx = 0; p_mac[mac_idx]; ++mac_idx){
			p_mac[mac_idx] = toupper(p_mac[mac_idx]);
		}
		/* add valid mac address to list */
		if (p_mac!= NULL && isValidMacAddr_and_isNotMulticast(p_mac)){
			if(strlen(tmp_str) + strlen(p_mac) + 1 /* MACLIST_SEP_FAPI */
					< MAX_MACLIST_BUF){
				if(num_mac == 0){
					db_changed += update_fapi_db(fp, unit, DB_WDS,
						"MACAddressControlList_0=", p_mac);
				}
				if(num_mac > 0){
					strcat(tmp_str, MACLIST_SEP_FAPI);
				}
				strcat(tmp_str, p_mac);
				num_mac++;
			}
		}
		p_mac = strtok(NULL, MACLIST_SEP_ASUSWRT);
	}
	_dprintf("[%s][%d] write mac [%s] to /tmp/maclist_x.txt\n",
			__func__, __LINE__, tmp_str);
	write_to_file("/tmp/maclist_x.txt", tmp_str);
	sleep(1);

	/* always set 1 because MACAddressControlList is not
		real mac list */
	return 1;
}

int wave_set_macmode(int unit, int subunit)
{
	FILE *fp = fopen(MACLIST_CONFIG_FILE, "w+");
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	ObjList *dbObjPtr = NULL;
	int db_changed ;
	int retVal;

	int acl_mode=0;
	int wave_unit;

	wave_unit = wl_wave_unit(unit);

	if(subunit > 0){
		if(unit == 1)
			wave_unit = VAP_5G_START + subunit;
		else
			wave_unit = VAP_2G_START + subunit;
	}

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	_dprintf("[%s][%d][%d][%d]\n",
		__func__, __LINE__, unit, subunit);

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);
	db_changed = 0;

	acl_mode = !nvram_match(strcat_r(prefix, "macmode", tmp), "disabled") ? nvram_match(strcat_r(prefix, "macmode", tmp), "allow") ? 1 : 2 : 0;
	_dprintf("[%s][%d][%d][%d]: acl_mode is [%s(%d)][%d]\n",
		__func__, __LINE__, unit, subunit, prefix, wave_unit, acl_mode);

	//ret = wlan_setMacAddressControlMode(wave_unit, acl_mode);


	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_WDS]);

	if(acl_mode == 0 )
	{
		db_changed += update_fapi_db(fp, unit, DB_WDS,
					"MACAddressControlEnabled_0=", "false");
		db_changed += update_fapi_db(fp, unit, DB_WDS,
					"MACAddressControlMode_0=", "Disabled");
	} else if( acl_mode == 1) { //allow
		db_changed += update_fapi_db(fp, unit, DB_WDS,
					"MACAddressControlEnabled_0=", "true");
		db_changed += update_fapi_db(fp, unit, DB_WDS,
					"MACAddressControlMode_0=", "Allow");

		db_changed += gen_maclist_x_txt(unit, subunit, fp, prefix);

	} else if( acl_mode == 2) { //deny
		db_changed += update_fapi_db(fp, unit, DB_WDS,
				"MACAddressControlEnabled_0=", "true");
		db_changed += update_fapi_db(fp, unit, DB_WDS,
				"MACAddressControlMode_0=", "Deny");

		nvram_unset("aimesh_macacl_2g_mac");
		nvram_unset("aimesh_macacl_5g_mac");
		db_changed += gen_maclist_x_txt(unit, subunit, fp, prefix);
	}


	fclose(fp);

	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_ap_set_native,
			wave_unit, dbObjPtr, MACLIST_CONFIG_FILE, 0 );
	}else{
		_dprintf("[%s][%d]: skip radio_set_native\n",__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}

}

#define WDS_CONFIG_FILE "/tmp/wds_config.txt"
int rpc_update_wdslist(int unit, int subunit)
{
	char *m = NULL;
	char *p, *pp;
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char ap_list[255] = {0};
	int db_changed ;
	ObjList *dbObjPtr = NULL;
	FILE *fp = fopen(WDS_CONFIG_FILE, "w+");
	int retVal;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);

	db_changed = 0;
	if(nvram_match(strcat_r(prefix, "mode_x", tmp), "0")){
		fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_WDS]);
		db_changed += update_fapi_db(fp, unit, DB_WDS,
					"WaveWDSMode_0=", "Disabled");
		db_changed += update_fapi_db(fp, unit, DB_WDS,
				"Wave4AddressesMode_0=", "Disabled");
	}else{
		pp = p = strdup(nvram_safe_get(strcat_r(prefix, "wdslist", tmp)));
		if (pp) {
			memset(ap_list, 0, sizeof(ap_list));
			while ((m = strsep(&p, "<")) != NULL) {
				if (!strlen(m)) continue;

				_dprintf("mac of wdslist:[%s]\n", m);
				if(strlen(ap_list) > 0) strcat(ap_list, " ");
				strcat(ap_list, m);
			}
			free(pp);
			fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_WDS]);
			db_changed += update_fapi_db(fp, unit, DB_WDS,
					"WaveWDSMode_0=", "Hybrid");

			fprintf(fp, "WaveWDSPeers_0=%s\n", ap_list);
			db_changed += 1; /* todo: check ap_list */

			db_changed += update_fapi_db(fp, unit, DB_WDS,
					"Wave4AddressesMode_0=", "Dynamic");
		}
	}
	fclose(fp);
	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_ap_set_native,
			wl_wave_unit(unit), dbObjPtr, WDS_CONFIG_FILE, 0 );
	}else{
		_dprintf("[%s][%d]: skip rpc_update_wdslist\n",
			__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);
	unlink(WDS_CONFIG_FILE);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}
}

void reset_lanifnames(char *vif, int add) 
{
	char lanifnames[256];

	sprintf(lanifnames, "%s", nvram_safe_get("lan_ifnames"));

	if(add) {
		add_to_list(vif, lanifnames, sizeof(lanifnames));
	} else {  // del
		remove_from_list(vif, lanifnames, sizeof(lanifnames));
	}

	nvram_set("lan_ifnames", lanifnames);
}

/* check bw limiter of guest betwork */
static void guest_bw_enabled(char *prefix)
{
	char tmp[100];
	int bw_en = nvram_get_int(strcat_r(prefix, "bw_enabled", tmp));
	int bw_dl = nvram_get_int(strcat_r(prefix, "bw_dl", tmp));
	int bw_ul = nvram_get_int(strcat_r(prefix, "bw_ul", tmp));

	//_dprintf("%s : prefix=%s, en=%d, dl=%d, ul=%d\n", __FUNCTION__, prefix, bw_en, bw_dl, bw_ul);
	if (bw_en != 0 && bw_dl != 0 && bw_ul != 0 && IS_BW_QOS()) {
		restart_qo = 1;
		restart_fwl = 1;
	}
}

void rpc_parse_nvram_from_httpd(int unit, int subunit)
{
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	int bss_enabled = 0;
	char *ssid;
	int wave_unit;
	int vap_index = 0;
	int retVal;
	char vap_ifname[255];
	char lan_ifname[16];
	char ssid_orig[255];
	int need_ifconfigUp;

	wave_unit = wl_wave_unit(unit);

	snprintf(lan_ifname, sizeof(lan_ifname), "%s", nvram_safe_get("lan_ifname"));

	_dprintf("[%s][%d]: unit=%d, subunit=%d.\n",
			__func__, __LINE__, unit, subunit);

	if ((unit == 0 && subunit == -1) || (unit == 1 && subunit == -1)){
		need_ifconfigUp = 0;
		need_ifconfigUp += wave_set_SSID(unit, subunit);
		need_ifconfigUp += wave_set_radio_basic(unit, subunit);
		need_ifconfigUp += wave_set_ap_professional(unit, subunit);
		need_ifconfigUp += wave_set_radio_tr181(unit, subunit);
		need_ifconfigUp += wave_set_security(unit, subunit);
		need_ifconfigUp += wave_set_macmode(unit, subunit);
		set_all_wps_config(nvram_get_int("w_Setting"));
		// rpc_qcsapi_set_SSID_broadcast(unit, subunit);
		need_ifconfigUp += rpc_update_wdslist(unit, subunit);
		if(need_ifconfigUp > 0){
			_dprintf("[%s][%d] run wlan_ifconfigUp\n",
				__func__,__LINE__);
			wlan_ifconfigUp(wave_unit);

			logmessage("WAVE", "[%s][%d][%d] run wlan_ifconfigUp\n",
				__func__, __LINE__, wave_unit);
		}else{
			_dprintf("[%s][%d][%d] skip wlan_ifconfigUp\n",
				__func__, __LINE__, wave_unit);
		}
	}
	else if (subunit == 1 || subunit == 2 || subunit == 3){
		need_ifconfigUp = 0;
		if(unit == 1)
			vap_index = VAP_5G_START + subunit;
		else
			vap_index = VAP_2G_START + subunit;

		gen_vap_index_file(vap_index);

		// rpc_update_mbss(unit, subunit);
		wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
		bss_enabled = nvram_get_int(strcat_r(prefix, "bss_enabled", tmp));

		if(bss_enabled == 1){
			ssid = nvram_safe_get(strcat_r(prefix, "ssid", tmp));
			retVal = wlan_getSSID(vap_index, ssid_orig);
			if (retVal < 0) {
				retVal = wlan_createVap(vap_index/* VAP */,
						wave_unit/* RADIO */, ssid, 0);
					del_vap_index_file();
				_dprintf("[%s][%d] vap_index:[%d] ssid is not existed, createVap, wave_unit:[%d], retVal:[%d]\n", __func__, __LINE__, vap_index, wave_unit, retVal);
				if(retVal == 0) {
					_dprintf("[%s][%d] vap_index:[%d] "
						"wlan_createVap OK"
						"wave_unit:[%d], retVal:[%d]\n",
						__func__, __LINE__, vap_index, wave_unit, retVal);
				}else{
					_dprintf("[%s][%d] vap_index:[%d] "
						"wlan_createVap failed"
						"wave_unit:[%d], retVal:[%d]\n",
						__func__, __LINE__, vap_index, wave_unit, retVal);
				}
			}else{
				_dprintf("[%s][%d] vap_index:[%d] ssid is existed, don't createVap\n", __func__, __LINE__, vap_index);
			}
			_dprintf("[%s][%d] vap_index:[%d] configure and ifconfigUp VAP\n", __func__, __LINE__, vap_index);
			need_ifconfigUp += wave_set_SSID(unit, subunit);
			need_ifconfigUp += config_guest_network_professional(vap_index, unit, subunit);
			need_ifconfigUp += config_guest_network_security(vap_index, unit, subunit);
			need_ifconfigUp += wave_set_macmode(unit, subunit);
			wlan_ifconfigUp(vap_index);
			memset(vap_ifname, 0, sizeof(vap_ifname));
			getInterfaceName(vap_index, vap_ifname);
			eval("brctl", "addif", lan_ifname, vap_ifname);
			nvram_set(strcat_r(prefix, "ifname", tmp), vap_ifname);
			reset_lanifnames(vap_ifname, 1);
			_dprintf("[%s][%d] vap_index:[%d] reset_lanifnames:[%s][1]\n", __func__, __LINE__, vap_index, vap_ifname);
		}else{
			memset(vap_ifname, 0, sizeof(vap_ifname));
			getInterfaceName(vap_index, vap_ifname);
			eval("brctl", "delif", lan_ifname, vap_ifname);
			_dprintf("[%s][%d] vap_index:[%d] deleteVap\n",
					__func__, __LINE__, vap_index);
			retVal = wlan_deleteVap(vap_index /* HARD CODED VAP NUMBER */);
			nvram_set(strcat_r(prefix, "ifname", tmp), "");
			reset_lanifnames(vap_ifname, 0);
			_dprintf("[%s][%d] vap_index:[%d] reset_lanifnames:[%s][0]\n", __func__, __LINE__, vap_index, vap_ifname);
		}

		/* check bw limiter of guest betwork */
		guest_bw_enabled(prefix);
		_dprintf("[%s][%d] vap_index:[%d] end of rpc_parse_nvram_from_httpd\n", __func__, __LINE__, vap_index);
	}else{
		_dprintf("no such wifi interface:[%d][%d]\n", unit, subunit);
	}
	if(sw_mode() == SW_MODE_ROUTER){
		// create_mbssid_vlan();
	}
//	rpc_show_config();
}

int config_guest_network_bridge(void)
{
	char prefix[] = "wlXXXXXXXXXXXXXXXXXXX_";
	int bss_enabled = 0;
	int i;
	int vap_index;
	char vap_ifname[255] ;
	char lan_ifname[16];
	char fapi_cmd[MAX_CLI_CMD_LEN] = {0};

	snprintf(lan_ifname, sizeof(lan_ifname), "%s", nvram_safe_get("lan_ifname"));

	/* 2G guest network */
	for(i = 1 ; i < 4 ; i++){
		vap_index = VAP_2G_START + i /* i is subunit index */ ;
		memset(vap_ifname, 0, sizeof(vap_ifname));
		getInterfaceName(vap_index, vap_ifname);
		memset(prefix, 0, sizeof(prefix));
		snprintf(prefix, sizeof(prefix), "wl0.%d_bss_enabled", i);
		bss_enabled = nvram_get_int(prefix);
		if(bss_enabled == 1){
			memset(fapi_cmd, 0, sizeof(fapi_cmd));
			snprintf(fapi_cmd, sizeof(fapi_cmd),
					"ppacmd addlan -i %s", vap_ifname);
			_dprintf("[%s][%d] %s\n", __func__, __LINE__, fapi_cmd);
			system(fapi_cmd);
			eval("brctl", "addif", lan_ifname, vap_ifname);
		}else{
			if(strncmp(vap_ifname, "wlan", 4) == 0){
				memset(fapi_cmd, 0, sizeof(fapi_cmd));
				snprintf(fapi_cmd, sizeof(fapi_cmd),
						"ppacmd dellan -i %s", vap_ifname);
				_dprintf("[%s][%d] %s\n", __func__, __LINE__, fapi_cmd);
				system(fapi_cmd);
				_dprintf("btctl delif %s %s\n", lan_ifname, vap_ifname);
				eval("brctl", "delif", lan_ifname, vap_ifname);
			}
		}
	}

	/* 5G guest network */
	for(i = 1 ; i < 4 ; i++){
		vap_index = VAP_5G_START + i /* i is subunit index */ ;
		memset(vap_ifname, 0, sizeof(vap_ifname));
		getInterfaceName(vap_index, vap_ifname);
		memset(prefix, 0, sizeof(prefix));
		snprintf(prefix, sizeof(prefix), "wl1.%d_bss_enabled", i);
		bss_enabled = nvram_get_int(prefix);
		if(bss_enabled == 1){
			memset(fapi_cmd, 0, sizeof(fapi_cmd));
			snprintf(fapi_cmd, sizeof(fapi_cmd),
					"ppacmd addlan -i %s", vap_ifname);
			_dprintf("[%s][%d] %s\n", __func__, __LINE__, fapi_cmd);
			system(fapi_cmd);
			_dprintf("btctl addif %s %s\n", lan_ifname, vap_ifname);
			eval("brctl", "addif", lan_ifname, vap_ifname);
		}else{
			if(strncmp(vap_ifname, "wlan", 4) == 0){
				memset(fapi_cmd, 0, sizeof(fapi_cmd));
				snprintf(fapi_cmd, sizeof(fapi_cmd),
						"ppacmd dellan -i %s", vap_ifname);
				_dprintf("[%s][%d] %s\n", __func__, __LINE__, fapi_cmd);
				system(fapi_cmd);
				_dprintf("btctl delif %s %s\n", lan_ifname, vap_ifname);
				eval("brctl", "delif", lan_ifname, vap_ifname);
			}
		}
	}
	return 1;
}

int config_guest_network_security(int vap_index, int unit, int subunit)
{
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	char fapi_cmd[MAX_CLI_CMD_LEN] = {0};
	FILE *fp = fopen("/tmp/vap_security.txt", "w+");
	char auth[8];
	char crypto[16];
	char key[65];
	int db_changed;

	_dprintf("[%s][%d]: vap_index:[%d], unit:[%d], subunit:[%d]\n",
			__func__, __LINE__, vap_index, unit, subunit);

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);

	strncpy(auth, nvram_safe_get(strcat_r(prefix, "auth_mode_x", tmp)), sizeof(auth));
	strncpy(crypto, nvram_safe_get(strcat_r(prefix, "crypto", tmp)), sizeof(crypto));
	strncpy(key, nvram_safe_get(strcat_r(prefix, "wpa_psk", tmp)), sizeof(key));

	db_changed = 0;
	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_AP_SECURITY]);

	/* auth: open
		WPA2-Personal: auth=psk2, crypto=aes
		WPA-Auto-Personal: auth=pskpsk2, crypto=aes
		WPA-Auto-Personal: auth=pskpsk2, crypto=tkip+aes
		WPA-Personal: auth=psk, crypto=tkip
		WPA2-Enterprise: auth=wpa2, crypto=aes
		WPA-Auto-Enterprise: auth=wpawpa2, crypto=aes
		WPA-Auto-Enterprise: auth=wpawpa2, crypto=tkip+aes
	 */
	db_changed += update_fapi_db(fp, vap_index, DB_AP_SECURITY,
		"ModeEnabled_0=", wav_get_security_str(auth, crypto, 0));
	db_changed += update_fapi_db(fp, vap_index, DB_AP_SECURITY,
		"KeyPassphrase_0=", key);
	db_changed += update_fapi_db(fp, vap_index, DB_AP_SECURITY,
		"BeaconType_0=", wav_get_beacon_type(crypto));
	db_changed += update_fapi_db(fp, vap_index, DB_AP_SECURITY,
		"EncryptionMode_0=", wav_get_encrypt(crypto));

	fclose(fp);

	if(db_changed > 0){
		snprintf(fapi_cmd, sizeof(fapi_cmd),
				"fapi_wlan_cli setSecurityTR181 -i %d -f /tmp/vap_security.txt", vap_index);
		_dprintf(fapi_cmd);
		system(fapi_cmd);
		return 1;
	}else{
		return 0;
	}
}

int config_guest_network_professional(int vap_index, int unit, int subunit)
{
	char prefix[] = "wlXXXXXXXXXXXXX_";
	char fapi_cmd[MAX_CLI_CMD_LEN] = {0};
	char tmp[100];
	int retVal;
	int db_changed;
	FILE *fp = fopen("/tmp/vap_professional.txt", "w+");

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	// _dprintf("[%s][%d][%s] ing.\n", __func__, __LINE__, prefix);

	_dprintf("[%s][%d][%d][%d]\n",
		__func__, __LINE__, unit, subunit);


	/* Object_0=Device.WiFi.AccessPoint */
	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_AP_PROFESSIONAL]);

	db_changed = 0;

	if(nvram_get_int(strcat_r(prefix, "radio", tmp)) == 1
#ifdef RTCONFIG_PROXYSTA
			&& !mediabridge_mode()
#endif
			){
		// _dprintf("%s: %s radio Enable.\n", __func__, prefix);
		db_changed += update_fapi_db(fp, vap_index, DB_AP_PROFESSIONAL,
			"Enable_0=", "true");
	}
	else{
		// _dprintf("%s: %s radio Disable.\n", __func__, prefix);
		db_changed += update_fapi_db(fp, vap_index, DB_AP_PROFESSIONAL,
			"Enable_0=", "false");
	}

	if(nvram_get_int(strcat_r(prefix, "ap_isolate", tmp)) == 1){
		db_changed += update_fapi_db(fp, vap_index, DB_AP_PROFESSIONAL,
			"IsolationEnable_0=", "true");
	}else{
		db_changed += update_fapi_db(fp, vap_index, DB_AP_PROFESSIONAL,
			"IsolationEnable_0=", "false");
	}

	if(nvram_get_int(strcat_r(prefix, "closed", tmp)) == 1){
		db_changed += update_fapi_db(fp, vap_index, DB_AP_PROFESSIONAL,
			"SSIDAdvertisementEnabled_0=", "false");
	}else{
		db_changed += update_fapi_db(fp, vap_index, DB_AP_PROFESSIONAL,
			"SSIDAdvertisementEnabled_0=", "true");
	}

	fclose(fp);

	if(db_changed > 0){
		snprintf(fapi_cmd, sizeof(fapi_cmd),
				"fapi_wlan_cli setApTR181 -i %d -f /tmp/vap_professional.txt", vap_index);
		_dprintf(fapi_cmd);
		system(fapi_cmd);
		return 1;
	}else{
		return 0;
	}
}

int config_guest_network(int from)
{
	if(client_mode() || aimesh_re_mode()){
		_dprintf("[%s][%d] this is client mode,"
				" disable guest network configuration\n",
				__func__, __LINE__);
		wlan_deleteVap(VAP_2G_START + 1 /* HARD CODED VAP NUMBER */);
		wlan_deleteVap(VAP_2G_START + 2 /* HARD CODED VAP NUMBER */);
		wlan_deleteVap(VAP_2G_START + 3 /* HARD CODED VAP NUMBER */);
		wlan_deleteVap(VAP_5G_START + 1 /* HARD CODED VAP NUMBER */);
		wlan_deleteVap(VAP_5G_START + 2 /* HARD CODED VAP NUMBER */);
		wlan_deleteVap(VAP_5G_START + 3 /* HARD CODED VAP NUMBER */);
		return 0;
	}
	if(from == WAVE_FLAG_VAP){
		_dprintf("[%s][%d] config vap[%d][%d]\n",
						__func__, __LINE__,
						nvram_get_int("wl_unit"),
						nvram_get_int("wl_subunit"));
		rpc_parse_nvram_from_httpd(nvram_get_int("wl_unit"),
								nvram_get_int("wl_subunit"));
	}else{
		rpc_parse_nvram_from_httpd(0,1);	/* wifi0.1 */
		rpc_parse_nvram_from_httpd(0,2);	/* wifi0.2 */
		rpc_parse_nvram_from_httpd(0,3);	/* wifi0.3 */

		rpc_parse_nvram_from_httpd(1,1);	/* wifi2.1 */
		rpc_parse_nvram_from_httpd(1,2);	/* wifi2.2 */
		rpc_parse_nvram_from_httpd(1,3);	/* wifi2.3 */
	}

#if 0
	if(nvram_get_int("wl0.1_bss_enabled") == 1 ||
		nvram_get_int("wl0.1_bss_enabled") == 1 ||
		nvram_get_int("wl0.2_bss_enabled") == 1 ){
		wlan_ifconfigUp(wl_wave_unit(0));
	}
	if(nvram_get_int("wl1.1_bss_enabled") == 1 ||
		nvram_get_int("wl1.1_bss_enabled") == 1 ||
		nvram_get_int("wl1.2_bss_enabled") == 1 ){
		wlan_ifconfigUp(wl_wave_unit(1));
	}
#endif
	config_guest_network_bridge();
	nvram_commit();	/* sync new vap lan_ifnames */
	return 1;
}


int check_country_code(void)
{
	FILE *fp;
	ObjList *dbObjPtr = NULL;
	char cur_country[10] = {0};
	char new_country[10] = {0};
	int wave_unit_2g = wl_wave_unit(0);
	const struct tcode_location_s *p;
	const struct psd_mod_country_list_s *p_location;
	char def_tcode[] = "xxxxxx";

	snprintf(def_tcode, sizeof(def_tcode), "%s",
			nvram_safe_get("territory_code"));
	/* 2G and 5G use same country code */
	wlan_getCountryCode(wave_unit_2g, cur_country);
	/* WiFi_data.xml: RegulatoryDomain = "US " */
	if(cur_country[strlen(cur_country)-1] == 0x20 )
		memset(&(cur_country[strlen(cur_country)-1]), 0, sizeof(char));

	for (p = &tcode_location_list[0]; p->location != NULL; ++p) {
		if(strcmp(p->location,
			nvram_safe_get("location_code")) == 0){
			break;
		}
	}
	/* wlan_getCountryCode add space character */

	if(p->ccode_2g != NULL){
		snprintf(new_country, sizeof(new_country), "%s",
			p->ccode_2g);
	}

	_dprintf("[%s][%d] cur_country:[%s], new country:[%s]\n",
		__func__, __LINE__, cur_country, new_country);

	/* if country code is not included in PSD, change country code */
	for (p_location = &psd_mod_country_list[0];
			p_location->tcode != NULL; ++p_location) {
		if(strncmp(p_location->tcode, def_tcode, 2) == 0){
			if(strcmp(p_location->ori_ccode, new_country) == 0){
				snprintf(new_country, sizeof(new_country), "%s",
					p_location->mod_ccode);
				_dprintf("[%s][%d] cur_country:[%s], new country (mod):[%s]\n",
				__func__, __LINE__, cur_country, new_country);
				break;
			}
		}
	}

	/* e.g.: "US" */
	if(strlen(new_country) < 2){
		_dprintf("[%s][%d] invalid country string return 0\n",
			__func__, __LINE__);
		return 0;
	}
	if(strcmp(cur_country, new_country) != 0){
		fp = fopen(RADIO_CONFIG_FILE, "w+");
		fprintf(fp, "Object_0=Device.WiFi.Radio\n");
		fprintf(fp, "Channel_0=0\n");
		fprintf(fp, "AutoChannelSupported_0=true\n");
		_dprintf("[%s][%d] RegulatoryDomain_0=[%s]\n",
				__func__, __LINE__, new_country);
		fprintf(fp, "RegulatoryDomain_0=%s\n", new_country);
		if(strcmp(new_country, "GB") == 0 ||
			strcmp(new_country, "GB ") == 0){
			_dprintf("[%s][%d] set IEEE80211hEnable true\n",
					__func__, __LINE__);
			fprintf(fp, "IEEE80211hEnabled_0=true\n");
		}else{
			_dprintf("[%s][%d] set IEEE80211hEnable false\n",
					__func__, __LINE__);
			fprintf(fp, "IEEE80211hEnabled_0=false\n");
		}
		fclose(fp);
		dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);
		_dprintf("[%s][%d] 2G new country:[%s], auto channel enabled\n",
			__func__, __LINE__, new_country);
		fapi_wlan_generic_set_native2(fapi_wlan_radio_set_native, wl_wave_unit(0), dbObjPtr, RADIO_CONFIG_FILE, 0);
		_dprintf("[%s][%d] 5G new country:[%s], auto channel enabled\n",
			__func__, __LINE__, new_country);
		fapi_wlan_generic_set_native2(fapi_wlan_radio_set_native, wl_wave_unit(1), dbObjPtr, RADIO_CONFIG_FILE, 0);
		HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);
		nvram_set("wl_channel", "0");
		nvram_set("wl0_channel", "0");
		nvram_set("wl1_channel", "0");
		nvram_set("wl_country_code", new_country);
		nvram_set("wl0_country_code", new_country);
		nvram_set("wl1_country_code", new_country);
		nvram_commit();
		return 1;
	}else{
		_dprintf("[%s][%d] country string is not changed\n",
			__func__, __LINE__);
	}
	return 0;
}

static int is_hostapd_running(char *ifname) {
	struct 	wpa_ctrl *wpaCtrlPtr=NULL;
	char wpa_path[256];
	int is_hostapd_running = 0;
	snprintf(wpa_path, sizeof(wpa_path), "/var/run/hostapd/%s", ifname);

	wpaCtrlPtr = wpa_ctrl_open(wpa_path);
	if (!wpaCtrlPtr) {
		return is_hostapd_running;
	}
	else if (wpa_ctrl_attach(wpaCtrlPtr) != 0) {
		wpa_ctrl_close(wpaCtrlPtr);
		return is_hostapd_running;
	} else {
		char buf[256];
		size_t len;
		len = sizeof(buf) - 1;
		if (wpa_ctrl_request(wpaCtrlPtr, "PING", 4, buf, &len, NULL) < 0 ||
			    len < 4 || memcmp(buf, "PONG", 4) != 0) {
			printf("hostapd did not reply to PING "
			       "command - exiting\n");
			wpa_ctrl_close(wpaCtrlPtr);
			return is_hostapd_running;
		} else {
			is_hostapd_running = 1;
		}
	}

	wpa_ctrl_close(wpaCtrlPtr);
	return is_hostapd_running;
}

static void restart_hostapd(char *ifname) {
#define TIMEOUT_VAL 10
	int timeout_cnt = 0;

	if (!strcmp(ifname, "wlan0")) {
		timeout_cnt = 0;
		while (timeout_cnt++ < TIMEOUT_VAL && (is_hostapd_running("wlan0") || pids("hostpad_cli_wlan0"))) {
			system("kill -9 `pidof hostapd_cli_wlan0`");
			system("kill -9 `pidof hostapd_wlan0`");
			sleep(1);
			_dprintf("%s : kill hostapd_cli_wlan0\n", __func__);
			_dprintf("%s : kill hostapd_wlan0\n", __func__);
		}

		timeout_cnt = 0;
		while(timeout_cnt++ < TIMEOUT_VAL && !is_hostapd_running("wlan0")) {
			system("/tmp/hostapd_wlan0 /opt/lantiq/wave/confs/hostapd_wlan0.conf -e /tmp/hostapd_ent_wlan0 -B");
			sleep(1);
			_dprintf("%s : run hostapd_wlan0\n", __func__);
		}

		timeout_cnt = 0;
		while(timeout_cnt++ < TIMEOUT_VAL && !pids("hostapd_cli_wlan0")) {
			system("/tmp/hostapd_cli_wlan0 -iwlan0 -a/opt/lantiq/wave/scripts/fapi_wlan_wave_events_hostapd.sh -B");
			sleep(1);
			_dprintf("%s : run hostapd_cli_wlan0\n", __func__);
		}
	} else if (!strcmp(ifname, "wlan2")) {
		timeout_cnt = 0;
		while (timeout_cnt++ < TIMEOUT_VAL && (is_hostapd_running("wlan2") || pids("hostpad_cli_wlan2"))) {
			system("kill -9 `pidof hostapd_cli_wlan2`");
			system("kill -9 `pidof hostapd_wlan2`");
			sleep(1);
			_dprintf("%s : kill hostapd_cli_wlan2\n", __func__);
			_dprintf("%s : kill hostapd_wlan2\n", __func__);
		}

		timeout_cnt = 0;
		while(timeout_cnt++ < TIMEOUT_VAL && !is_hostapd_running("wlan2")) {
			system("/tmp/hostapd_wlan2 /opt/lantiq/wave/confs/hostapd_wlan2.conf -e /tmp/hostapd_ent_wlan2 -B");
			sleep(1);
			_dprintf("%s : run hostapd_wlan2\n", __func__);
		}

		timeout_cnt = 0;
		while(timeout_cnt++ < TIMEOUT_VAL && !pids("hostapd_cli_wlan2")) {
			system("/tmp/hostapd_cli_wlan2 -iwlan2 -a/opt/lantiq/wave/scripts/fapi_wlan_wave_events_hostapd.sh -B");
			sleep(1);
			_dprintf("%s : run hostapd_cli_wlan2\n", __func__);
		}
	}
}

int wave_set_radio_onoff(int action, int unit, int subunit, int onoff)
{
	char tmp[100];
	int retVal;

	_dprintf("[%s][%d][%d][%d]\n",
		__func__, __LINE__, unit, subunit);

	if(onoff == 0){
		_dprintf("[%s][%d][%d][%d]:set radio off\n",
			__func__, __LINE__, unit, subunit);
		if(unit == 0){
			system("ifconfig wlan0 down");
			nvram_set("wave_wlan0_up", "0");
		}else if(unit == 1){
			system("ifconfig wlan2 down");
			nvram_set("wave_wlan2_up", "0");
		}
		sleep(2);	/* wait for wlan0 or wlan2 down */
	}else if(onoff == 1){
		_dprintf("[%s][%d][%d][%d]:set radio on\n",
			__func__, __LINE__, unit, subunit);
		if(unit == 0){
			restart_hostapd("wlan0");
			nvram_set("wave_wlan0_up", "1");
		}else if(unit == 1){
			restart_hostapd("wlan2");
			nvram_set("wave_wlan2_up", "1");
		}
		//sleep(2);	/* No need to wait here. Instead we perform waiting in the function restart_hostapd.*/
	}else{
		_dprintf("[%s][%d][%d][%d]: error, onoff=[%d], skip this action\n",
				__func__, __LINE__, unit, subunit, onoff);
	}
	return 1;

}

int wave_monitor_core(void)
{
	int ret = 0;
	int i;
	char fapi_cmd[MAX_CLI_CMD_LEN] = {0};
	struct country_code_list_s *p = &country_code_list[0];
	char lan_ifname[16];
	int action;
	char sec_2g[] = "None";
	char sec_5g[] = "None";
	char pwd_2g[] = "test_passphrase";
	char pwd_5g[] = "test_passphrase";
	char reg_2g_default[] = "US";
	int ch_2g = 0, ch_5g = 0;
	int wps_band = nvram_get_int("wps_band_x");
	int wave_unit;
	int need_ifconfigUp;
	static int iwpriv_once = 0;
	int cur_web_unit;
	static int wave_signal_idx = 0;

	snprintf(lan_ifname, sizeof(lan_ifname), "%s", nvram_safe_get("lan_ifname"));
	action = nvram_get_int("wave_action");

	if(nvram_get_int("wave_action") != WAVE_ACTION_INIT &&
		nvram_get_int("wave_ready") != 1){

		_dprintf("[%s][%d] action:[%d], wave_ready is not 1, return\n",
			__func__, __LINE__, action);
		return -1;
	}
	/* clean wave_action to allow new request */
	nvram_set_int("wave_action", WAVE_ACTION_IDLE);

	if(action == WAVE_ACTION_IDLE){
#if 0
		_dprintf("[%s][%d] wave_monitor_main(%d)\n",
			__func__, __LINE__, action);
#endif
		return 0;
	}

	_dprintf("[%s][%d] begin of wave_monitor_core(),"
		"action:[%d] signal_idx:[%d]\n", __func__, __LINE__,
			action, wave_signal_idx);

	nvram_set_int("wave_action_cur", action);

	for (i = 0, p = &country_code_list[i]; p->regulation_domain != NULL && i < ARRAY_SIZE(country_code_list); ++i, ++p) {
		if(strcmp(p->regulation_domain, nvram_safe_get("wl0_country_code")) == 0){
			break;
		}
	}

	if(nvram_match("territory_code", "KR/01")){
		system("mv /tmp/lantiq_wave/images/PSD_KR.bin /tmp/lantiq_wave/images/PSD.bin");
	}

	f_write_string("/proc/sys/kernel/printk", "0", 0, 0);

	switch(action){
		case WAVE_ACTION_INIT:
			nvram_set("wave_ready", "0");

			if(nvram_get_int("x_Setting") == 0){
				_dprintf("[warning] x_Setting=0, remove existed jffs db\n");
				clean_wave_db();
			}
			if(access(DB_LOCATION, R_OK ) != -1 ) {
				_dprintf("***************** jffs db is exist\n");
				system(CMD_LOAD_DB);
				_dprintf(CMD_LOAD_DB);
			}
			else{
				_dprintf("***************** jffs db is not exist\n");
				_dprintf("[warning] no wireless setting, generate again\n");
				clean_wave_db();
				wlan_createInitialConfigFiles(NULL);

				if(p->country_code != NULL){
					if(strcmp(p->country_code, "GB") == 0) ch_5g = 36;

					snprintf(fapi_cmd, sizeof(fapi_cmd),
							"/opt/lantiq/wave/scripts/fapi_wlan_wave_update_defaults.sh %s %s %s %s %d %d %s %s",
							sec_2g, sec_5g, pwd_2g, pwd_5g, ch_2g, ch_5g, p->country_code, p->country_code);
				}
				else{
					snprintf(fapi_cmd, sizeof(fapi_cmd),
							"/opt/lantiq/wave/scripts/fapi_wlan_wave_update_defaults.sh %s %s %s %s %d %d %s %s",
							sec_2g, sec_5g, pwd_2g, pwd_5g, ch_2g, ch_5g, reg_2g_default, reg_2g_default);
				}
				_dprintf("[warning][%s]\n", fapi_cmd);
				system(fapi_cmd);
			}
			_dprintf("--------- fapi_wlan_cli init . -----------\n");
			wlan_init();

			set_wps_enable(wps_band);
			_dprintf("--------- fapi_wlan_cli init End. -----------\n");
#if 1
			if(nvram_get_int("x_Setting") == 1){
				_dprintf("check nvram and wireless configuration start.\n");
				rpc_parse_nvram_from_httpd(0,-1);
				rpc_parse_nvram_from_httpd(1,-1);
				config_guest_network(WAVE_FLAG_NORMAL);
				_dprintf("check nvram and wireless configuration end.\n");
			}
#endif
			eval("brctl", "addif", lan_ifname, "wlan0");
			eval("brctl", "addif", lan_ifname, "wlan2");
#if 0
			eval("brctl", "addif", lan_ifname, "eth0_1");
			eval("brctl", "addif", lan_ifname, "eth0_2");
			eval("brctl", "addif", lan_ifname, "eth0_3");
			eval("brctl", "addif", lan_ifname, "eth0_4");
#endif

#if defined(RTCONFIG_WIRELESSREPEATER)
			if(sw_mode() == SW_MODE_REPEATER || mediabridge_mode()){
				start_wlcconnect();
			}
#endif

#if defined(RTCONFIG_AMAS)
			if ( aimesh_re_mode()) {
				_dprintf("Init wlan1 and wlan3 in RE mode\n");
				wlan_setEndpointEnabled(0);
				wlan_setEndpointEnabled(1);
				wave_set_sta_config();
			} else if (is_default()) {
				_dprintf("Init wlan1 in default state.\n");
				wlan_setEndpointEnabled(0);
			}
#endif

#if 0
			/* move to config_guest_network() */
			config_guest_network_bridge();
#endif
#if 0
			// wlan0, wlan2 will be added into ppa automatically after they are activated.
			system("ppacmd addlan -i wlan0");
			system("ppacmd addlan -i wlan2");
#endif

			if(nvram_get_int(ATE_FACTORY_MODE_STR()) == 1){
				_dprintf("[%s][%d] eanble usb3\n", __func__, __LINE__);
			}else{
				if(nvram_get_int("usb_usb3") == 1){
					_dprintf("[%s][%d] eanble usb3\n", __func__, __LINE__);
					system("set_usb2_to_usb3");
				}else{
					_dprintf("[%s][%d] eanble usb2\n", __func__, __LINE__);
					system("set_usb3_to_usb2");
				}
			}

			/* init 5g possible channel */
			{
				char tmp_buf[256]={0};
				wlan_getPossibleChannels(wl_wave_unit(0),tmp_buf);
				nvram_set("pc_list_2g",tmp_buf);
				memset(tmp_buf,0,256);			
				wlan_getPossibleChannels(wl_wave_unit(1),tmp_buf);
				nvram_set("pc_list_5g",tmp_buf);
			}
			/* update /jffs/db/ */
			system(CMD_SAVE_DB);
			_dprintf(CMD_SAVE_DB);
			nvram_set_int("wave_flag", WAVE_FLAG_NORMAL);
			_dprintf("*********************** start httpd ************************\n");
			nvram_set("wave_ready", "1");
			nvram_set("success_start_service", "1");
			sync(); sync(); sync();
#ifdef LANTIQ_BSD
			start_bsd();
#endif
#ifdef RTCONFIG_AMAS
			if(!no_need_obd()) {
				notify_rc("start_obd");
			}
#endif
#ifdef RTCONFIG_HAPDEVENT
			start_hapdevent();
#endif
			break;

		case WAVE_ACTION_WEB:
			check_wave_ready(WAVE_ACTION_WEB);
#ifdef LANTIQ_BSD
			stop_bsd();
#endif
			if(access("/opt/lantiq/wave/db/instance/wlan0/", R_OK ) == -1 ) {
				_dprintf("[warning] wlan0 configuration is not existed\n");
			}
			if(access("/opt/lantiq/wave/db/instance/wlan2/", R_OK ) == -1 ) {
				_dprintf("[warning] wlan2 configuration is not existed\n");
			}
			nvram_set("wave_ready", "0");

#ifdef RTCONFIG_AMAS
			if(!no_need_obd()) {
				notify_rc("stop_obd");
			}
#endif
#ifdef RTCONFIG_HAPDEVENT
			stop_hapdevent();
#endif
			if(sw_mode() == SW_MODE_AP &&
				nvram_get_int("wlc_psta") == 1 &&
				nvram_get_int("wlc_band") == 1){
				_dprintf("[sw_mode] skip start_psta_wave, WAVE will run scripts automatically\n");
				// start_psta_wave();
			}else{
				_dprintf("[%s][%d] call rpc_parse_nvram_from_httpd, wave_flag:[%d]\n",
						__func__, __LINE__, nvram_get_int("wave_flag"));
				if (nvram_get_int("wave_CFG") == 11){
					_dprintf("[%s][%d] dp-00\n", __func__, __LINE__);
					rpc_parse_nvram_from_httpd(0,-1);	/* wifi0 */
					rpc_parse_nvram_from_httpd(1,-1);	/* wifi2 */
#if 0
					config_guest_network();
#endif
					nvram_set("wave_CFG", "0");
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_QIS){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_QIS] \n", __func__, __LINE__);
					wave_set_SSID(0, -1);
					wave_set_security(0, -1);
					wave_set_SSID(1, -1);
					wave_set_security(1, -1);
					set_all_wps_config(nvram_get_int("w_Setting"));
					_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
					wlan_ifconfigUp(wl_wave_unit(0));
					wlan_ifconfigUp(wl_wave_unit(1));
					nvram_set_int("wave_flag", WAVE_FLAG_NORMAL);
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_WPS){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_WPS] \n", __func__, __LINE__);
					set_all_wps_config(nvram_get_int("w_Setting"));
					set_wps_enable(wps_band);
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_WDS){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_WDS] \n", __func__, __LINE__);
					set_all_wps_config(nvram_get_int("w_Setting"));
					rpc_update_wdslist(nvram_get_int("wl_unit"), -1);
					wave_unit = wl_wave_unit(nvram_get_int("wl_unit"));
					_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
					wlan_ifconfigUp(wave_unit);
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_ACL){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_ACL] \n", __func__, __LINE__);
					wave_set_macmode(nvram_get_int("wl_unit"), nvram_get_int("wl_subunit"));
					set_all_wps_config(nvram_get_int("w_Setting"));
					wave_unit = wl_wave_unit(nvram_get_int("wl_unit"));
					_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
					wlan_ifconfigUp(wave_unit);
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_ADV){
					cur_web_unit = nvram_get_int("wl_unit");
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_ADV] \n", __func__, __LINE__);
					set_all_wps_config(nvram_get_int("w_Setting"));
					wave_unit = wl_wave_unit(cur_web_unit);
					wave_set_ap_professional(cur_web_unit, -1);
					if(check_country_code() == 1){
						_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
						logmessage("WAVE", "[%s][%d][WAVE_FLAG_ADV][0] \n", __func__, __LINE__);
						wlan_ifconfigUp(wl_wave_unit(0));
						logmessage("WAVE", "[%s][%d][WAVE_FLAG_ADV][1] \n", __func__, __LINE__);
						wlan_ifconfigUp(wl_wave_unit(1));
						/* tell httpd to generate new channel list */
						/* 20M: 0x1, 40M: 0x2, 80M: 0x4 */
						nvram_set_int("wl_country_changed", 7);
					}else{
						logmessage("WAVE", "[%s][%d][WAVE_FLAG_ADV][%d] \n", __func__, __LINE__, cur_web_unit);
						_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
						wlan_ifconfigUp(wave_unit);
					}
					if(nvram_get_int("usb_usb3") == 0) set_usb3_to_usb2();
					else set_usb2_to_usb3();
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_VAP){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_VAP] \n", __func__, __LINE__);
					// set_all_wps_config(nvram_get_int("w_Setting"));
					config_guest_network(WAVE_FLAG_VAP);
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_APP_VAP){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_APP_VAP] \n", __func__, __LINE__);
					// set_all_wps_config(nvram_get_int("w_Setting"));
					config_guest_network(WAVE_FLAG_APP_VAP);
					nvram_set_int("wave_flag", WAVE_FLAG_NORMAL);
				}else if(nvram_get_int("wave_flag") == WAVE_FLAG_NETWORKMAP){
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_NETWORKMAP][0]\n", __func__, __LINE__);
					need_ifconfigUp = 0;
					need_ifconfigUp += wave_set_SSID(0, -1);
					need_ifconfigUp += wave_set_security(0, -1);
					if(need_ifconfigUp > 0){
						logmessage("WAVE", "[%s][%d] wlan_ifconfigUp(0) \n", __func__, __LINE__);
						_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
						wlan_ifconfigUp(wl_wave_unit(0));
					}else{
						_dprintf("[%s][%d] skip wlan_ifconfigUp(0)\n",
							__func__, __LINE__);
					}
					logmessage("WAVE", "[%s][%d][WAVE_FLAG_NETWORKMAP][1]\n", __func__, __LINE__);
					need_ifconfigUp = 0;
					need_ifconfigUp += wave_set_SSID(1, -1);
					need_ifconfigUp += wave_set_security(1, -1);
					if(need_ifconfigUp > 0){
						_dprintf("[%s][%d] wlan_ifconfigUp\n",__func__,__LINE__);
						logmessage("WAVE", "[%s][%d] wlan_ifconfigUp(2) \n", __func__, __LINE__);
						wlan_ifconfigUp(wl_wave_unit(1));
					}else{
						_dprintf("[%s][%d] skip wlan_ifconfigUp(2)\n",
							__func__, __LINE__);
					}
				}else{
					logmessage("WAVE", "[%s][%d][no WAVE_FLAG][]\n", __func__, __LINE__);
					_dprintf("[%s][%d][no WAVE_FLAG][]\n", __func__, __LINE__);
					/* wireless configuration, two band configuration */
					rpc_parse_nvram_from_httpd(0,-1);
					rpc_parse_nvram_from_httpd(1,-1);
					config_guest_network(WAVE_FLAG_NORMAL);
				}

			}
			eval("brctl", "addif", lan_ifname, "wlan0");
			eval("brctl", "addif", lan_ifname, "wlan2");
			/* update /jffs/db/ */
			system(CMD_SAVE_DB);
			_dprintf(CMD_SAVE_DB);
			sync(); sync(); sync();
			nvram_set("wave_ready", "1");
#ifdef LANTIQ_BSD
			start_bsd();
#endif
#ifdef RTCONFIG_AMAS
			if(!no_need_obd()) {
				notify_rc("start_obd");
			}
			if (nvram_get_int("re_mode") == 1)
				wave_set_sta_config();
#endif
#ifdef RTCONFIG_HAPDEVENT
			start_hapdevent();
#endif
			break;

		case WAVE_ACTION_RE_AP2G_ON://drop this command if wave_ready!=1?
			check_wave_ready(WAVE_ACTION_RE_AP2G_ON);
			nvram_set_int("wave_ready", 0);
			wave_set_radio_onoff(WAVE_ACTION_RE_AP2G_ON, 0, -1, 1);
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_RE_AP2G_OFF://drop this command if wave_ready!=1?
			check_wave_ready(WAVE_ACTION_RE_AP2G_OFF);
			nvram_set_int("wave_ready", 0);
			wave_set_radio_onoff(WAVE_ACTION_RE_AP2G_OFF, 0, -1, 0);
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_RE_AP5G_ON://drop this command if wave_ready!=1?
			check_wave_ready(WAVE_ACTION_RE_AP5G_ON);
			nvram_set_int("wave_ready", 0);
			wave_set_radio_onoff(WAVE_ACTION_RE_AP5G_ON, 1, -1, 1);
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_RE_AP5G_OFF://drop this command if wave_ready!=1?
			check_wave_ready(WAVE_ACTION_RE_AP5G_OFF);
			nvram_set_int("wave_ready", 0);
			wave_set_radio_onoff(WAVE_ACTION_RE_AP5G_OFF, 1, -1, 0);
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_SET_CHANNEL_2G:
			check_wave_ready(WAVE_ACTION_SET_CHANNEL_2G);
			nvram_set_int("wave_ready", 0);
			need_ifconfigUp = 0;
			need_ifconfigUp += wave_set_radio_basic_aimesh(0,-1);
			need_ifconfigUp += wave_set_radio_tr181_aimesh(0,-1);
			if(need_ifconfigUp > 0){
				_dprintf("\n\n\n[wlan_ifconfigUp]%s %d\n\n\n",__FUNCTION__,__LINE__);
				logmessage("WAVE", "[%s][%d] wlan_ifconfigUp(0) \n", __func__, __LINE__);
				wlan_ifconfigUp(wl_wave_unit(0));
			}else{
				_dprintf("[%s][%d] skip wlan_ifconfigUp(0)\n",
					__func__, __LINE__);
			}
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_SET_CHANNEL_5G:
			check_wave_ready(WAVE_ACTION_SET_CHANNEL_5G);
			nvram_set_int("wave_ready", 0);
			need_ifconfigUp = 0;
			need_ifconfigUp += wave_set_radio_basic_aimesh(1,-1);
			need_ifconfigUp += wave_set_radio_tr181_aimesh(1,-1);
			if(need_ifconfigUp > 0){
				_dprintf("\n\n\n[wlan_ifconfigUp]%s %d\n\n\n",__FUNCTION__,__LINE__);
				logmessage("WAVE", "[%s][%d] wlan_ifconfigUp(2) \n", __func__, __LINE__);
				wlan_ifconfigUp(wl_wave_unit(1));
			}else{
				_dprintf("[%s][%d] skip wlan_ifconfigUp(2)\n",
					__func__, __LINE__);
			}
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_OPENACL_FOR_OBD://OBD only use 2G
			check_wave_ready(WAVE_ACTION_OPENACL_FOR_OBD);
			while(nvram_get_int("wave_ready") == 0)
			{
				_dprintf("wait for ready WAVE_ACTION_OPENACL_FOR_OBD\n");
				sleep(2);
			}
			nvram_set_int("wave_ready", 0);
			need_ifconfigUp = 0;
			need_ifconfigUp += wave_set_macfilter_enable(0,-1,0);//disabled
			if(need_ifconfigUp > 0)
				wlan_ifconfigUp(wl_wave_unit(0));
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_RECOVERACL_FOR_OBD://OBD only use 2G
			check_wave_ready(WAVE_ACTION_RECOVERACL_FOR_OBD);
			while(nvram_get_int("wave_ready") == 0)
			{
				_dprintf("wait for ready WAVE_ACTION_RECOVERACL_FOR_OBD\n");
				sleep(2);
			}
			nvram_set_int("wave_ready", 0);
			need_ifconfigUp = 0;
			need_ifconfigUp += wave_set_macfilter_enable(0,-1,1);//re-enabled = 1
			if(need_ifconfigUp > 0)
				wlan_ifconfigUp(wl_wave_unit(0));
			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_SETALLOWACL_2G://add re mac addr to allow list,only allow mode needed
		{	
			//char *mac=NULL;
			check_wave_ready(WAVE_ACTION_SETALLOWACL_2G);
			while(nvram_get_int("wave_ready") == 0)
			{
				_dprintf("wait for ready WAVE_ACTION_SETALLOWACL_2G\n");
				sleep(5);
			}
			nvram_set_int("wave_ready", 0);
			//mac = nvram_safe_get("aimesh_macacl_2g_mac");
			need_ifconfigUp = 0;
			need_ifconfigUp += wave_set_macmode(0,-1);
			if(need_ifconfigUp > 0)
				wlan_ifconfigUp(wl_wave_unit(0));
			nvram_set_int("wave_ready", 1);
			break;
		}
		case WAVE_ACTION_SETALLOWACL_5G://add re mac addr to allow list,only allow mode needed
		{
			//char *mac=NULL;
			check_wave_ready(WAVE_ACTION_SETALLOWACL_5G);
			while(nvram_get_int("wave_ready") == 0)
			{
				_dprintf("wait for ready WAVE_ACTION_SETALLOWACL_5G\n");
				sleep(5);
			}			
			nvram_set_int("wave_ready", 0);
			//mac = nvram_safe_get("aimesh_macacl_5g_mac");
			need_ifconfigUp = 0;
			need_ifconfigUp += wave_set_macmode(1,-1);
			if(need_ifconfigUp > 0)
				wlan_ifconfigUp(wl_wave_unit(1));
			nvram_set_int("wave_ready", 1);
			break;
		}
		case WAVE_ACTION_CLIENT2G_ON:
			break;
			check_wave_ready(WAVE_ACTION_CLIENT2G_ON);
			nvram_set_int("wave_ready", 0);

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_CLIENT2G_OFF:
			break;
			check_wave_ready(WAVE_ACTION_CLIENT2G_OFF);
			nvram_set_int("wave_ready", 0);

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_CLIENT5G_ON:
			break;
			check_wave_ready(WAVE_ACTION_CLIENT5G_ON);
			nvram_set_int("wave_ready", 0);

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_CLIENT5G_OFF:
			break;
			check_wave_ready(WAVE_ACTION_CLIENT5G_OFF);
			nvram_set_int("wave_ready", 0);

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_SET_WPS2G_CONFIGURED:
			check_wave_ready(WAVE_ACTION_SET_WPS2G_CONFIGURED);
			nvram_set_int("wave_ready", 0);

			set_wps_config(0, nvram_get_int("w_Setting"));
			wlan_ifconfigUp(0);

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_SET_WPS5G_CONFIGURED:
			check_wave_ready(WAVE_ACTION_SET_WPS5G_CONFIGURED);
			nvram_set_int("wave_ready", 0);

			set_wps_config(1, nvram_get_int("w_Setting"));
			wlan_ifconfigUp(1);
			break;
#ifdef RTCONFIG_AMAS
		case WAVE_ACTION_ADD_BEACON_VSIE:
			check_wave_ready(WAVE_ACTION_ADD_BEACON_VSIE);
			nvram_set_int("wave_ready", 0);

			wave_add_beacon_vsie();

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_DEL_BEACON_VSIE:
			check_wave_ready(WAVE_ACTION_DEL_BEACON_VSIE);
			nvram_set_int("wave_ready", 0);

			wave_del_beacon_vsie();

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_ADD_PROBE_REQ_VSIE:
			check_wave_ready(WAVE_ACTION_ADD_PROBE_REQ_VSIE);
			nvram_set_int("wave_ready", 0);

			wave_add_probe_req_vsie();

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_DEL_PROBE_REQ_VSIE:
			check_wave_ready(WAVE_ACTION_DEL_PROBE_REQ_VSIE);
			nvram_set_int("wave_ready", 0);

			wave_del_probe_req_vsie();

			nvram_set_int("wave_ready", 1);
			break;
		case WAVE_ACTION_CLEAR_ALL_PROBE_REQ_VSIE:
			check_wave_ready(WAVE_ACTION_CLEAR_ALL_PROBE_REQ_VSIE);
			nvram_set_int("wave_ready", 0);

			wave_clear_all_probe_req_vsie(0);

			nvram_set_int("wave_ready", 1);
			break;
#endif
		case WAVE_ACTION_SET_STA_CONFIG:
			wave_set_sta_config();
			break;

	}

	if(iwpriv_once == 0){
		system("iwpriv wlan0 sSlowProbingMask 0x3e");
		system("iwpriv wlan2 sSlowProbingMask 0x3e");
		iwpriv_once = 1;
	}

	if(nvram_get_int("wl1_mumimo") == 1){
		_dprintf("[%s][%d] enable wlan2 MU-MIMO\n", __func__, __LINE__);
		system("iwpriv wlan2 sMuOperation 1");
	}else{
		_dprintf("[%s][%d] disable wlan2 MU-MIMO\n", __func__, __LINE__);
		system("iwpriv wlan2 sMuOperation 0");
	}

	_dprintf("[%s][%d] end of wave_monitor_core(),"
		"action:[%d] signal_idx:[%d]\n", __func__, __LINE__,
			action, wave_signal_idx);

	wave_signal_idx++;

	if(nvram_match("x_Setting", "1")){
		stop_bluetooth_service();
	}

	/* for restart service to make function work */
	for(i = 0; i< 20; ++i) {
		if(restart_wifi || restart_qo || restart_fwl) {
			_dprintf("[%s][%d] need to restart wifi/qos/firewall "
				"again, chk %d/%d/%d\n",
				__func__, __LINE__,
				nvram_get_int("restart_wifi"),
				nvram_get_int("restart_qo"),
				nvram_get_int("restart_fwl"));
			sleep(1);

			if(restart_wifi && nvram_match("restart_wifi", "0")) {
				_dprintf("[%s][%d] : restart wireless again\n",
					__func__, __LINE__);
				restart_wifi = 0;
				if(check_wave_ready(3) == -1){
					return;
				}
				notify_rc("restart_wireless");
			}
			if(restart_qo && nvram_match("restart_qo", "0")) {
				_dprintf("[%s][%d] : restart qos again\n",
					__func__, __LINE__);
				restart_qo = 0;
				notify_rc("restart_qos");
			}
			if(restart_fwl && nvram_match("restart_fwl", "0")) {
				_dprintf("[%s][%d] : restart firewall again\n",
					__func__, __LINE__);
				restart_fwl = 0;
				notify_rc("restart_firewall");
			}
		}
		else {
			break;
		}
	}
	
	if(wave_signal_idx > 100) wave_signal_idx = 0;

	nvram_unset("wave_action_cur");
	return ret;
}

void alarmtimer_wave(unsigned long sec, unsigned long usec)
{
	static struct itimerval itv_wave;

	itv_wave.it_value.tv_sec = sec;
	itv_wave.it_value.tv_usec = usec;
	itv_wave.it_interval = itv_wave.it_value;
	setitimer(ITIMER_REAL, &itv_wave, NULL);
}

int wave_monitor_main(int argc, char *argv[])
{
	FILE *fp;
	
	/* write pid */
	if ((fp = fopen("/var/run/wave_monitor.pid", "w")) != NULL) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

#if 0
	/* set the signal handler */
	if(nvram_get_int("wave_CFG") != 1)
		signal(SIGALRM, wave_monitor_core);
#endif

	signal(SIGUSR1, wave_monitor_core);
	signal(SIGCHLD, chld_reap); // To avoid the child process turn to zombie state.

#if 0
	/* set timer */
	if(nvram_get_int("wave_CFG") != 1)
		alarmtimer_wave(30, 0);
#endif

	if(nvram_get_int("wave_CFG") != 1)
		nvram_set("wave_action", "1");

	kill_pidfile_s("/var/run/wave_monitor.pid", SIGUSR1);
	/* Most of time it goes to sleep */
	while(1) {
		pause();
	}
	return 0;
}

void stop_wifi_service(void)
{
	_dprintf("[%s][%d] clean wave files\n", __func__, __LINE__);
	system("rm -rf /opt/lantiq/wave/db/instance/");
	system("rm -rf /tmp/wireless");
	// system("fapi_wlan_cli unInit");
	wlan_uninit();
	// system("cd /opt/lantiq/wave/; rm -rf confs; rm -rf db/default; rm -rf db/instance; rm -rf /tmp/wlan_wave/");
}

void update_client_event(char *client_mac, char *ifname, int status)
{
	WLCNT_TRIGGER(client_mac, ifname, status);
}

int wave_is_radio_on(int unit, int subunit)
{
	int ret =0;

	ret = is_if_up(get_wififname(unit));
	if(ret == 0){
#if 0
		_dprintf("[%s][%d] %s is down\n",
			__func__, __LINE__, get_wififname(unit));
#endif
		return 0;
	}else if(ret == 1){
#if 0
		_dprintf("[%s][%d] %s is up\n",
			__func__, __LINE__, get_wififname(unit));
#endif
		return 1;
	} else {
		_dprintf("[%s][%d] %s get up status error\n",
			__func__, __LINE__, get_wififname(unit));
	}

	return 0;
}

int wave_set_radio_basic_aimesh(int unit, int subunit)
{
	FILE *fp = fopen(RADIO_BASIC_CONFIG_FILE, "w+");
	//char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	ObjList *dbObjPtr = NULL;
	int db_changed ;
	u_int_32 channel;
	int bw, extch_lower;

	//wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	//bw = nvram_get_int(strcat_r(prefix, "bw", tmp));
	//channel = nvram_get_int(strcat_r(prefix, "channel", tmp));
	//extch_lower = !strcmp(nvram_get_int(strcat_r(prefix, "nctrlsb", tmp)),"lower");

	if(!unit) {
		bw = nvram_get_int("aimesh_setchannel_bw_0");
		channel = nvram_get_int("aimesh_setchannel_channel_0");
		extch_lower = nvram_get_int("aimesh_setchannel_nctrlsb_0");
	} else {
		bw = nvram_get_int("aimesh_setchannel_bw_1");
		channel = nvram_get_int("aimesh_setchannel_channel_1");
		extch_lower = nvram_get_int("aimesh_setchannel_nctrlsb_1");
	}

	_dprintf("[%s][%d]bw[%d]channel[%d]\n",
		__func__, __LINE__, bw, channel);

	return wave_set_radio_basic_set_config(unit,subunit,fp,bw,channel,extch_lower);
}

int wave_set_radio_tr181_aimesh(int unit, int subunit)
{
	FILE *fp = fopen(RADIO_CONFIG_FILE, "w+");
	char prefix[] = "wlXXXXXXXXXXXXX_", tmp[100];
	ObjList *dbObjPtr = NULL;
	int db_changed ;
	int retVal;
	int bw;

	wl_nvprefix(prefix, sizeof(prefix), unit, subunit);
	_dprintf("[%s][%d][%d][%d]\n",
		__func__, __LINE__, unit, subunit);

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);

	db_changed = 0;

	if(!unit) {
		bw = nvram_get_int("aimesh_setchannel_bw_0");
	} else {
		bw = nvram_get_int("aimesh_setchannel_bw_1");
	}

	_dprintf("[%s][%d]bw[%d]\n",
		__func__, __LINE__, bw);


	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_RADIO_VENDOR]);
	if(unit == 0){
		if(bw == 0){	/* 20/40MHz */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexEnabled_0=", "true");

			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexRssiThreshold_0=", "-70");
		}else if(bw == 2){	/* 40MHz */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexEnabled_0=", "false");
		}else{
			/* 20MHz */
			db_changed += update_fapi_db(fp, unit, DB_RADIO_VENDOR, "CoexEnabled_0=", "false");
		}
	}

	fclose(fp);

	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_radio_set_native,
			wl_wave_unit(unit), dbObjPtr, RADIO_CONFIG_FILE, 0);
	}else{
		_dprintf("[%s][%d]: skip radio_set_native\n",__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}

}

int replace_str_form_to(char *str, char from, char to)
{
	int i;
	if(!str)
		return 0;

	for(i=0;i<strlen(str);i++)
	{
		if(str[i] == from)
			str[i] = to;
	}

}

int wave_set_macfilter_enable(int unit, int subunit,int enable)
{
	FILE *fp = fopen(MACLIST_CONFIG_FILE, "w+");
	ObjList *dbObjPtr = NULL;
	int db_changed ;
	int retVal;

	dbObjPtr = HELP_CREATE_OBJ(SOPT_OBJVALUE);
	db_changed = 0;

	fprintf(fp, "Object_0=%s\n", fapi_db_list[DB_WDS]);
	
	if(enable == 0 )
	{
		db_changed += update_fapi_db(fp, unit, DB_WDS, "MACAddressControlEnabled_0=", "false");
		db_changed += update_fapi_db(fp, unit, DB_WDS, "MACAddressControlMode_0=", "Disabled");
	} else { 
		//only allow mode use this function
		db_changed += update_fapi_db(fp, unit, DB_WDS, "MACAddressControlEnabled_0=", "true");
		db_changed += update_fapi_db(fp, unit, DB_WDS, "MACAddressControlMode_0=", "Allow");
	}

	fclose(fp);

	if(db_changed > 0){
		retVal = fapi_wlan_generic_set_native2(fapi_wlan_ap_set_native,
			wl_wave_unit(unit), dbObjPtr, MACLIST_CONFIG_FILE, 0 );
	}else{
		_dprintf("[%s][%d]: skip radio_set_native\n",__func__, __LINE__);
	}
	HELP_DELETE_OBJ(dbObjPtr, SOPT_OBJVALUE, FREE_OBJLIST);

	/* return 1 to run ifconfigUp */
	if(db_changed > 0){
		_dprintf("[%s][%d][%d][%d]: need ifconfigUp, retVal=[%d]\n",
				__func__, __LINE__, unit, subunit, retVal);
		return 1;
	}else{
		return 0;
	}

}

#ifdef RTCONFIG_AMAS
char ap_mac_pre[2][20] = {0};
char ap_ssid_pre[2][40] = {0};
char ap_key_pre[2][40] = {0};
char ap_security_pre[2][40] = {0};
char ap_beacon_pre[2][40] = {0};
char ap_encrypt_pre[2][40] = {0};

static int is_wlc_setting_change(int band)
{
	char ap_mac[20] = {0};
	char ap_ssid[40] = {0};
	char ap_auth[40] = {0};
	char ap_crypto[40] = {0};
	char ap_key[40] = {0};
	char ap_security[40] = {0};
	char ap_beacon[40] = {0};
	char ap_encrypt[40] = {0};
	int  ap_weptype=0;
	char tmp[128], prefix_wlc[] = "wlcXXXXXXX_";

	snprintf(prefix_wlc, sizeof(prefix_wlc), "wlc%d_", band);

	snprintf(ap_mac, sizeof(ap_mac), "%s", nvram_safe_get(strcat_r(prefix_wlc, "ap_mac", tmp)));
	snprintf(ap_ssid, sizeof(ap_ssid), "%s", nvram_safe_get(strcat_r(prefix_wlc, "ssid", tmp)));
	snprintf(ap_auth, sizeof(ap_auth), "%s", nvram_safe_get(strcat_r(prefix_wlc, "auth_mode", tmp)));
	snprintf(ap_crypto, sizeof(ap_crypto), "%s", nvram_safe_get(strcat_r(prefix_wlc, "crypto", tmp)));
	ap_weptype = nvram_get_int(strcat_r(prefix_wlc, "wep", tmp));
	if (!strcmp(ap_auth, "open") && ap_weptype > 0)
		snprintf(ap_key, sizeof(ap_key), "%s", nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp)));
	else
		snprintf(ap_key, sizeof(ap_key), "%s", nvram_safe_get(strcat_r(prefix_wlc, "wpa_psk", tmp)));

	if(strlen(ap_ssid) <= 0){
		return 0;
	}

	snprintf(ap_beacon, sizeof(ap_beacon), "%s", wav_get_beacon_type(ap_crypto));
	snprintf(ap_encrypt, sizeof(ap_encrypt), "%s", wav_get_encrypt(ap_crypto));
	snprintf(ap_security, sizeof(ap_security), "%s", wav_get_security_str(ap_auth, ap_crypto,ap_weptype));

	if(strlen(ap_security) <= 0){
		fprintf(stderr, "[warning] not support this auth. mode\n");
		return 0;
	}

	if (memcmp(ap_mac, ap_mac_pre[band], 20) ||
		memcmp(ap_ssid, ap_ssid_pre[band], 40) ||
		memcmp(ap_security, ap_security_pre[band], 40) ||
		memcmp(ap_beacon, ap_beacon_pre[band], 40) ||
		memcmp(ap_encrypt, ap_encrypt_pre[band], 40) ||
		memcmp(ap_key, ap_key_pre[band], 40) )
	{
		memcpy(ap_mac_pre[band],ap_mac,20);
		memcpy(ap_ssid_pre[band],ap_ssid,40);
		memcpy(ap_security_pre[band],ap_security,40);
		memcpy(ap_beacon_pre[band],ap_beacon,40);
		memcpy(ap_encrypt_pre[band],ap_encrypt,40);
		memcpy(ap_key_pre[band],ap_key,40);
		return 1;		
	}
	return 0;
}

void wave_set_sta_config(void)
{
	char *key_mgmt = NULL, *proto = NULL, *auth_alg=NULL, *pairwise = NULL;
	char *group = NULL, *psk = NULL;
	char *str = NULL;
	char tmp[128], prefix_wlc[] = "wlcXXXXXXX_";
	int flag_wep = 0, ifindex = 0;
	FILE *fp = NULL;
	char word[64], *next = NULL;
	int band = 0;

	foreach (word, nvram_safe_get("sta_ifnames"), next) {
		if (!is_wlc_setting_change(band)) {
			band++;
			continue;
		}

		ifindex = (band == 0 ? 1 : 3);

		snprintf(prefix_wlc, sizeof(prefix_wlc), "wlc%d_", band);

		/* Process auth mode */
		str = nvram_safe_get(strcat_r(prefix_wlc, "auth_mode", tmp));
		if (str && strlen(str)) {

			if (!strcmp(str, "open") && nvram_match(strcat_r(prefix_wlc, "wep", tmp), "0"))
			{
				key_mgmt = strdup("NONE"); // open/none
			}
			else if (!strcmp(str, "open"))
			{
				flag_wep = 1;
				key_mgmt = strdup("NONE"); //open
				auth_alg = strdup("OPEN");
			}
			else if (!strcmp(str, "shared"))
			{
				flag_wep = 1;
				key_mgmt = strdup("NONE"); //shared
				auth_alg = strdup("SHARED");
			}
			else if (!strcmp(str, "psk") || !strcmp(str, "psk2") || !strcmp(str, "pskpsk2"))
			{
				key_mgmt = strdup("WPA-PSK");

				if (!strcmp(str, "psk"))
					proto = strdup("WPA"); //wpapsk
				else if (!strcmp(str, "psk2"))
					proto = strdup("RSN"); //wpa2psk
				else
					proto = strdup("WPA RSN");
				//EncrypType
				if (nvram_match(strcat_r(prefix_wlc, "crypto", tmp), "tkip"))
				{
					pairwise = strdup("TKIP");
					group = strdup("TKIP");
				}
				else if (nvram_match(strcat_r(prefix_wlc, "crypto", tmp), "aes"))
				{
					pairwise = strdup("CCMP TKIP");
					group = strdup("CCMP TKIP");
				}
				else {
					pairwise = strdup("CCMP TKIP");
					group = strdup("CCMP TKIP");
				}
				//key
				psk = strdup(nvram_safe_get(strcat_r(prefix_wlc, "wpa_psk", tmp)));
			}
			else
				key_mgmt = strdup("NONE"); //open/none
		}
		else
			key_mgmt = strdup("NONE"); //open/none

		snprintf(tmp, sizeof(tmp), "/tmp/run_wlan%d_wpa.sh", ifindex);
		fp = fopen(tmp, "w+");
		if (!fp) {
			_dprintf("Open wlan%d sh fail.\n", ifindex);
			goto EXIT;
		}

		fprintf(fp, "#!/bin/sh\n");
		fprintf(fp, "wpa_cli -iwlan%d remove_network 0\n", ifindex);
		fprintf(fp, "wpa_cli -iwlan%d add_network 0\n", ifindex);
		fprintf(fp, "wpa_cli -iwlan%d set_network 0 ssid '\"%s\"'\n", ifindex, nvram_invmatch(strcat_r(prefix_wlc, "ssid", tmp), "") ?
		        nvram_safe_get(strcat_r(prefix_wlc, "ssid", tmp)) : "");

		if (key_mgmt)
			fprintf(fp, "wpa_cli -iwlan%d set_network 0 key_mgmt %s\n", ifindex, key_mgmt);
		if (auth_alg)
			fprintf(fp, "wpa_cli -iwlan%d set_network 0 auth_alg %s\n", ifindex, auth_alg);
		if (psk)
			fprintf(fp, "wpa_cli -iwlan%d set_network 0 psk '\"%s\"'\n", ifindex, psk);
		if (proto)
			fprintf(fp, "wpa_cli -iwlan%d set_network 0 proto \"%s\"\n", ifindex, proto);
		if (pairwise)
			fprintf(fp, "wpa_cli -iwlan%d set_network 0 pairwise \"%s\"\n", ifindex, pairwise);
		if (group)
			fprintf(fp, "wpa_cli -iwlan%d set_network 0 group \"%s\"\n", ifindex, group);

		// Let client interface connect to hidden ssid AP.
		fprintf(fp, "wpa_cli -iwlan%d set_network 0 scan_ssid %d\n", ifindex, 1);

		if (flag_wep) //EncrypType
		{
			int p = 0;
			char tmp1[32] = {0};
			for (p = 1; p <= 4; p++)
			{
				if (nvram_get_int(strcat_r(prefix_wlc, "key", tmp)) == p)
				{
					if ((strlen(nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp))) == 5) || (strlen(nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp1))) == 13))
					{
						fprintf(fp, "wpa_cli -iwlan%d set_network 0 wep_tx_keyidx %d\n", ifindex, p - 1);
						fprintf(fp, "wpa_cli -iwlan%d set_network 0 wep_key%d %s\n", ifindex, p - 1, nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp)));

					}
					else if ((strlen(nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp))) == 10) || (strlen(nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp1))) == 26))
					{
						fprintf(fp, "wpa_cli -iwlan%d set_network 0 wep_tx_keyidx %d\n", ifindex, p - 1);
						fprintf(fp, "wpa_cli -iwlan%d set_network 0 wep_key%d %s\n", ifindex, p - 1, nvram_safe_get(strcat_r(prefix_wlc, "wep_key", tmp)));
					}
					else
					{
						fprintf(fp, "wpa_cli -iwlan%d set_network 0 wep_tx_keyidx %d\n", ifindex, p - 1);
						fprintf(fp, "wpa_cli -iwlan%d set_network 0 wep_key%d 0\n", ifindex, p - 1);
					}

				}
			}

		}
		fprintf(fp, "wpa_cli -iwlan%d select_network 0\n", ifindex);
		fprintf(fp, "wpa_cli -iwlan%d enable_network 0\n", ifindex);
		fprintf(fp, "wpa_cli -iwlan%d save_config\n", ifindex);

		if (fp)
			fclose(fp);

		snprintf(tmp, sizeof(tmp), "/tmp/run_wlan%d_wpa.sh", ifindex);
		eval("sh", tmp);

EXIT:
		band++;
		free(key_mgmt);
		key_mgmt = NULL;
		free(auth_alg);
		auth_alg = NULL;
		free(psk);
		psk = NULL;
		free(proto);
		proto = NULL;
		free(pairwise);
		pairwise = NULL;
		free(group);
		group = NULL;
	}
}

static void wave_add_beacon_vsie(void)
{
	// 0: Beacon
	// 1: ProbeRequest
	// 2: ProbeResponse
	// 3: AuthenticationRequest
	// 4: AuthenticationRespnse
	// 5: AssocationRequest
	// 6: AssociationResponse
	// 7: ReassociationRequest
	// 8: ReassociationResponse
	char *beaconVsie;
	char cmd[300] = {0};
	int pktflag = 0x0;
	int len = 0;
	char *ifname = NULL;
	strlen(ifname);

	beaconVsie = nvram_safe_get("amas_add_beacon_vsie");
	if (!strlen(beaconVsie))
		return;

	len = 3 + strlen(beaconVsie)/2;	/* 3 is oui's len */

	ifname = get_wififname(0); // TODO: Should we get the band from nvram?

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s set_vsie %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)len, (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], beaconVsie);
		_dprintf("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
}

static void wave_del_beacon_vsie(void)
{
	// 0: Beacon
	// 1: ProbeRequest
	// 2: ProbeResponse
	// 3: AuthenticationRequest
	// 4: AuthenticationRespnse
	// 5: AssocationRequest
	// 6: AssociationResponse
	// 7: ReassociationRequest
	// 8: ReassociationResponse
	char *beaconVsie;
	char cmd[300] = {0};
	int pktflag = 0x0;
	int len = 0;
	char *ifname = NULL;

	beaconVsie = nvram_safe_get("amas_del_beacon_vsie");
	if (!strlen(beaconVsie))
		return;

	len = 3 + strlen(beaconVsie)/2;	/* 3 is oui's len */

	ifname = get_wififname(0); // TODO: Should we get the band from nvram?

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s del_vsie %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)len,  (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], beaconVsie);
		_dprintf("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
}

static void wave_clear_all_probe_req_vsie(int unit)
{
	char cmd[300] = {0};
	int pktflag = 0xE;
	char *ifname = NULL;
	FILE *fp;

	ifname = get_staifname(unit);

	snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_get %d",
		ifname, pktflag);
	if ((fp = popen(cmd, "r")) != NULL) {
		char *vendor_elem[MAX_VSIE_LEN];
		memset(vendor_elem, 0, sizeof(vendor_elem));

		if (fgets(vendor_elem , sizeof(vendor_elem) , fp) != NULL) {
			if (strlen(vendor_elem)) {
				snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_remove %d %s",
					ifname, pktflag, vendor_elem);
				OBD_DBG("%s: cmd=%s\n", __func__, cmd);
				system(cmd);
			}
		}
		pclose(fp);
	}
}

static void wave_add_probe_req_vsie(void)
{
	// 13 : Associatino Request
	// 14 : Probe Reqeust
	// 15 : Authentication Request
	char *ie_data;
	char cmd[300] = {0};
	//char hexdata[256];
	int pktflag = 0xE;
	int /*i, */ie_len/* = (len - OUI_LEN)*/;
	char *ifname = NULL;
	//FILE *fp;

	ie_data = nvram_safe_get("amas_add_probe_req_vsie");
	ie_len = strlen(ie_data);
	if (!ie_len)
		return;

	ifname = get_staifname(0);
	ie_len /= 2;
/*
	memset(hexdata, 0, sizeof(hexdata));
	for (i = 0; i < ie_len; i++)
		sprintf(&hexdata[2 * i], "%02x", ie_data[i]);
	hexdata[2 * ie_len] = 0;
*/

	wave_clear_all_probe_req_vsie(0);

	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_add %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)(ie_len + OUI_LEN), (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], ie_data);
		OBD_DBG("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
}

static void wave_del_probe_req_vsie(void)
{
	char *ie_data;
	char cmd[300] = {0};
	//char hexdata[256];
	int pktflag = 0xE;
	int /*i, */ie_len/* = (len - OUI_LEN)*/;
	char *ifname = NULL;

	ie_data = nvram_safe_get("amas_del_probe_req_vsie");
	ie_len = strlen(ie_data);
	if (!ie_len)
		return;

	ifname = get_staifname(0);
	ie_len /= 2;
/*
	memset(hexdata, 0, sizeof(hexdata));
	for (i = 0; i < ie_len; i++)
		sprintf(&hexdata[2 * i], "%02x", ie_data[i]);
	hexdata[2 * ie_len] = 0;
*/
	//_dprintf("%s: wl0_ifname=%s\n", __func__, ifname);

	if (ifname && strlen(ifname)) {
		snprintf(cmd, sizeof(cmd), "wpa_cli -i%s vendor_elem_remove %d DD%02X%02X%02X%02X%s",
			ifname, pktflag, (uint8_t)(ie_len + OUI_LEN),  (uint8_t)OUI_ASUS[0],  (uint8_t)OUI_ASUS[1],  (uint8_t)OUI_ASUS[2], ie_data);
		OBD_DBG("%s: cmd=%s\n", __func__, cmd);
		system(cmd);
	}
}
#endif
