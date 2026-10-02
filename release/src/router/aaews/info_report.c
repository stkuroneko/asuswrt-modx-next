#include <json.h>
#include "info_report.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <nt_common.h>
#include <unistd.h>	//write(), close()
#include "common.h"
#include "ws_api.h"
#include "nat_nvram.h"

#ifdef RTCONFIG_NOTIFICATION_CENTER
void write_login_info(char *login_status, char *server, char *psr_server, char *cusid, char *deviceid, char *deviceticket)
{
    struct json_object *json_obj = NULL;
    char fwver[128];
    char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
    char api_level[16];
    snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
    snprintf(api_level, sizeof(api_level), "%d", AIHOME_API_LEVEL);

    json_object *jlogin_status = json_object_new_string((strlen(login_status)==0 ? "100" : login_status));
    json_object *jserver = json_object_new_string(server);
    json_object *jpsr_server = json_object_new_string(psr_server);
    json_object *jcusid = json_object_new_string(cusid);
    json_object *jdeviceid = json_object_new_string(deviceid);
    json_object *jdeviceticket = json_object_new_string(deviceticket);
    json_object *jdevicetype = json_object_new_string(DEVICE_TYPE);
    json_object *jfwver = json_object_new_string(fwver);
    json_object *japilevel = json_object_new_string(api_level);
    json_object *jmodelname = json_object_new_string(model_name);

    json_obj = json_object_new_object();

    json_object_object_add(json_obj, "login_status", jlogin_status);
    json_object_object_add(json_obj, "server", jserver);
    json_object_object_add(json_obj, "psr_server", jpsr_server);
    json_object_object_add(json_obj, "cusid", jcusid);
    json_object_object_add(json_obj, "deviceid", jdeviceid);
    json_object_object_add(json_obj, "deviceticket", jdeviceticket);
    json_object_object_add(json_obj, "devicetype", jdevicetype);
    json_object_object_add(json_obj, "fwver", jfwver);
    json_object_object_add(json_obj, "apilevel", japilevel);
    json_object_object_add(json_obj, "modelname", jmodelname);

    json_object_to_file(PUSH_CONF_PATH, json_obj);

    // Clean JSON object
    json_object_put(json_obj);

}

void write_mac_info(char *mac)
{
    int fd;

    if (!mac)
        return;

    fd = open(PUSH_MAC_PATH, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    write(fd, mac, strlen(mac));
    close(fd);

}
#endif

/*

Example : 
public=1
{
    "ddns_name":"AE4BB02EF8A7CE7CD8A643B86F7D30DCE.asuscomm.com", 
    "public":"1", 
    "https_port":"0", 
    "AiHOMEAPILevel":"19", 
    "aae_enable":"6", 
    "fwver":"3.0.0.4.384_45717-gadd52a8", 
    "modelname":"RT-AC68U"
}
public=0
{
    "public":"0", 
    "name":"RT-AC68U-43F0", 
    "tnlver":"2.1.0.126", 
    "AiHOMEAPILevel":"19", 
    "aae_enable":"7", 
    "fwver":"3.0.0.4.384_45149-g467037b", 
    "modelname":"RT-AC68U"
}
*/

char *generate_device_desc(int public, char *tnl_sdk_version, char *out_buf, int out_len)
{
    const char *json_string;
    struct json_object *json_obj = NULL;
    char fwver[128];
    char *model_name = nvram_safe_get(NVRAM_MODEL_NAME);
    char api_level[16];
    snprintf(fwver, sizeof(fwver), "%s.%s_%s", nvram_safe_get(NVRAM_FIRMVER), nvram_safe_get(NVRAM_BUILDNO), nvram_safe_get(NVRAM_EXTENDNO));
    snprintf(api_level, sizeof(api_level), "%d", AIHOME_API_LEVEL);

    json_object *jfwver = json_object_new_string(fwver);
    json_object *japilevel = json_object_new_string(api_level);
    json_object *jmodelname = json_object_new_string(model_name);
    json_object *jaaeenable = json_object_new_string(nvram_safe_get("aae_enable"));
    json_object *jodmpid = json_object_new_string(nvram_safe_get(NVRAM_ODMPID));
    json_object *jhttps_lanport = json_object_new_string(nvram_safe_get(NVRAM_HTTPS_LANPORT));
    json_object *jhttp_enable = json_object_new_string(nvram_safe_get(NVRAM_HTTP_ENABLE));

    json_obj = json_object_new_object();

    if (public == 1) {
        json_object *jddnsname = json_object_new_string(nvram_safe_get("ddns_hostname_x"));
        json_object *jpublic = json_object_new_string("1");
        json_object *jhttpsport = NULL;
        if (nvram_get_int("misc_http_x") == 1)
            jhttpsport = json_object_new_string(nvram_safe_get("misc_httpsport_x"));
        else
            jhttpsport = json_object_new_string("0");

        json_object_object_add(json_obj, "ddns_name", jddnsname);
        json_object_object_add(json_obj, "public", jpublic);
        json_object_object_add(json_obj, "https_port", jhttpsport);

    } else {
        json_object *jpublic = json_object_new_string("0");
        json_object *jname = json_object_new_string(get_lan_hostname());
        json_object *jtnlver = tnl_sdk_version ? json_object_new_string(tnl_sdk_version) : json_object_new_string("");
        json_object_object_add(json_obj, "public", jpublic);
        json_object_object_add(json_obj, "name", jname);
        json_object_object_add(json_obj, "tnlver", jtnlver);

    }

    json_object_object_add(json_obj, "AiHOMEAPILevel", japilevel);
    json_object_object_add(json_obj, "aae_enable", jaaeenable);
    json_object_object_add(json_obj, "fwver", jfwver);
    json_object_object_add(json_obj, "modelname", jmodelname);
    json_object_object_add(json_obj, "odmpid", jodmpid);
    json_object_object_add(json_obj, "https_lanport", jhttps_lanport);
    json_object_object_add(json_obj, "http_enable", jhttp_enable);

#ifdef RTCONFIG_ACCOUNT_BINDING
    int get_mac_status = 0;
    char mac_str[MAC_LEN];
    memset(mac_str, 0, sizeof(mac_str));

#if NVRAM
    get_mac_status = nvram_get_mac_addr(mac_str);
#else
    unsigned char mac_addr[7]={0};
    get_mac_status = get_mac(mac_addr);
    sprintf(mac_str,"%X:%X:%X:%X:%X:%X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
#endif

    if (get_mac_status>=0) {
        json_object *jmac = json_object_new_string(mac_str);
        json_object_object_add(json_obj, "mac", jmac);
    }
#endif

#if defined(RTCONFIG_ACCOUNT_BINDING) && defined(RTCONFIG_AWSIOT)
    if (is_account_bound()) {
    	json_object *jawsiot_support = json_object_new_string("1");
	    json_object_object_add(json_obj, "awsiot_tunnel_support", jawsiot_support);
    }
#endif

#ifdef RTCONFIG_AMAS
    if (nvram_get("amas_bdl")) {
        json_object *jamasbdl = json_object_new_string(nvram_get("amas_bdl"));
        json_object_object_add(json_obj, "amas_bdl", jamasbdl);
    }
#endif

#ifdef RTCONFIG_ALEXA
    json_object *alexa_support = json_object_new_string("1");
	json_object_object_add(json_obj, "alexa_support", alexa_support);
#endif

#ifdef RTCONFIG_GOOGLE_ASST
    json_object *google_assistant_support = json_object_new_string("1");
	json_object_object_add(json_obj, "google_assistant_support", google_assistant_support);
#endif

    json_object *jtcode = json_object_new_string(nvram_safe_get("territory_code"));
    json_object_object_add(json_obj, "tcode", jtcode);

    json_object *jcoordinate = json_object_new_string(nvram_safe_get("coordinate"));
    json_object_object_add(json_obj, "coordinate", jcoordinate);

    json_string = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PLAIN);
    snprintf(out_buf, out_len, "%s", json_string);

    // Clean JSON object
    json_object_put(json_obj);

    return out_buf;
}
