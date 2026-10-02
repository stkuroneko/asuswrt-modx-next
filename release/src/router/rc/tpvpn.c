/*
 * Copyright 2021, ASUSTeK Inc.
 * All Rights Reserved.
 *
 */

#include "rc.h"

#include <sys/types.h>
#include <unistd.h>
#include <shared.h>
#include <libasc.h>
#include <json.h>
#include <disk_io_tools.h>	//mkdir_if_none()
#ifdef RTCONFIG_OPENVPN
#include <openvpn_config.h>
#include <openvpn_options.h>
#endif
#ifdef RTCONFIG_WIREGUARD
#include <openssl/sha.h>
#include <curl/curl.h>
#endif

#define TPVPN_DL_TMP_FILE   "/tmp/tpvpn"
#define TPVPN_DL_FILESIZE_TH  100
#define TPVPN_DL_FOLDER "/jffs/.sys/vpn"
#define TPVPN_DL_HMA_TCP_LIST   "/jffs/.sys/vpn/HMA_TCP.JSON"
#define TPVPN_DL_HMA_UDP_LIST   "/jffs/.sys/vpn/HMA_UDP.JSON"
#define TPVPN_FW_HMA_TCP_LIST   "/rom/vpn/HMA_TCP.JSON"
#define TPVPN_FW_HMA_UDP_LIST   "/rom/vpn/HMA_UDP.JSON"
#define TPVPN_UI_HMA_LIST   "/tmp/hma.json"
#define TPVPN_HMA_UPDATE_PID     "/var/run/hmavpn_update.pid"

#define TPVPN_PSZ_HMA       "hma"
#define TPVPN_PSZ_NORDVPN   "nordvpn"
#define TPVPN_FILE_LOCK     "tpvpn"

#define TPVPN_CONN_TCP       0x1
#define TPVPN_CONN_UDP       0x2

#define TPVPN_NORD_URL_LOGIN "https://api.nordvpn.com/v1/users/oauth/login"
#define TPVPN_NORD_URL_TOKEN "https://api.nordvpn.com/v1/users/oauth/token"
#define TPVPN_NORD_URL_COUNTRIES "https://api.nordvpn.com/v1/servers/countries"
#define TPVPN_NORD_URL_SERVERS "https://api.nordvpn.com/v1/servers/recommendations?filters[servers_technologies][pivot][status]=online&filters[servers_technologies][id]=35&filters[country_id]=%d"
#define TPVPN_NORD_URL_CONFIG "https://api.nordvpn.com/v1/servers/%d/technologies/35/configurations"

#if defined(RTCONFIG_OPENVPN) && !defined(RTCONFIG_VPN_FUSION)
static void _ovpn_sync_account(int unit)
{
	char *nv = NULL, *nvp = NULL, *b = NULL;
	char *desc, *proto, *ounit, *username, *password;
	char prefix[16] = {0};

	snprintf(prefix, sizeof(prefix), "vpn_client%d_", unit);

	// load "vpnc_clientlist" to set username, password
	nv = nvp = strdup(nvram_safe_get("vpnc_clientlist"));
	while (nv && (b = strsep(&nvp, "<")))
	{
		if (vstrsep(b, ">", &desc, &proto, &ounit, &username, &password) < 3)
			continue;
		if (proto && !strcmp(proto, "HMA") && ounit && atoi(ounit) == unit)
		{
			nvram_pf_set(prefix, "username", username);
			nvram_pf_set(prefix, "password", password);
			break;
		}
	}

}
#endif

int is_tpvpn_configured(int provider, const char* region, const char* conntype, int unit)
{
	char prefix[16] = {0};

	if (!region || !conntype) return 0;

	switch (provider)
	{
		case TPVPN_HMA:
			snprintf(prefix, sizeof(prefix), "vpn_client%d_", unit);
			if (!strcmp(nvram_pf_safe_get(prefix, "tp"), TPVPN_PSZ_HMA)
			 && !strcmp(nvram_pf_safe_get(prefix, "tp_region"), region)
			 && !strcmp(nvram_pf_safe_get(prefix, "tp_proto"), conntype)
			)
				return 1;
			break;
		case TPVPN_NORDVPN:
			snprintf(prefix, sizeof(prefix), "wgc%d_", unit);
			if (!strcmp(nvram_pf_safe_get(prefix, "tp"), TPVPN_PSZ_NORDVPN)
			 && !strcmp(nvram_pf_safe_get(prefix, "tp_region"), region)
			)
				return 1;
			break;
	}
	return 0;
}

char *tpvpn_get_conf_url(char *buf, size_t len)
{
	const char dlurl[][32] = {{ 'v','p','n','c','o','n','f','i','g','.','p','h','p','\0' }};

	if( !buf || len <= 0 )
		return NULL;

	snprintf(buf, len, "%s", dlurl[0]);

	return buf;
}

char *tpvpn_get_list_url(char *buf, size_t len)
{
	const char dlurl[][32] = {{ 'v','p','n','g','e','t','l','i','s','t','.','p','h','p','\0' }};

	if( !buf || len <= 0 )
		return NULL;

	snprintf(buf, len, "%s", dlurl[0]);

	return buf;
}

char *tpvpn_get_ver_url(char *buf, size_t len)
{
	const char dlurl[][32] = {{ 'v','p','n','g','e','t','v','e','r','s','i','o','n','.','p','h','p','\0' }};

	if( !buf || len <= 0 )
		return NULL;

	snprintf(buf, len, "%s", dlurl[0]);

	return buf;
}

size_t tpvpn_write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}


#ifdef RTCONFIG_OPENVPN
static int _hma_get_dl_filename(const char* region, const char* conntype, char *buf, size_t len)
{
	char listfile[32] = {0};
	json_object *root_obj = NULL, *regions_obj = NULL, *regions_array_obj = NULL;
	json_object *region_obj = NULL, *file_obj = NULL;
	int regions_length, i;
	const char *region_data, *file_data;
	int ret = -1;

	if (!strcasecmp(conntype, "TCP"))
	{
		if (check_if_file_exist(TPVPN_DL_HMA_TCP_LIST))
			strlcpy(listfile, TPVPN_DL_HMA_TCP_LIST, sizeof(listfile));
		else
			strlcpy(listfile, TPVPN_FW_HMA_TCP_LIST, sizeof(listfile));
	}
	else if (!strcasecmp(conntype, "UDP"))
	{
		if (check_if_file_exist(TPVPN_DL_HMA_UDP_LIST))
			strlcpy(listfile, TPVPN_DL_HMA_UDP_LIST, sizeof(listfile));
		else
			strlcpy(listfile, TPVPN_FW_HMA_UDP_LIST, sizeof(listfile));
	}
	else
		return -1;

	root_obj = json_object_from_file(listfile);
	if (root_obj)
	{
		if (json_object_object_get_ex(root_obj, "regions", &regions_obj))
		{
			regions_length = json_object_array_length(regions_obj);
			for (i = 0; i < regions_length; i++)
			{
				regions_array_obj = json_object_array_get_idx(regions_obj, i);
				if (regions_array_obj)
				{
					json_object_object_get_ex(regions_array_obj, "region", &region_obj);
					json_object_object_get_ex(regions_array_obj, "file", &file_obj);
					region_data = json_object_get_string(region_obj);
					file_data = json_object_get_string(file_obj);
					if (region_data && file_data && !strcmp(region_data, region))
					{
						snprintf(buf, len, "%s", file_data);
						ret = 0;
						break;
					}
				}
			}
		}
		json_object_put(root_obj);
	}

	return (ret);
}

static int _hma_setconf(int ovpn_unit, const char* region, const char* conntype)
{
	char ovpn_prefix[16] = {0};
	int fd;
	char filename[64] = {0};
	char url[64] = {0};
	int retry = 5;

	if (!region || region[0] == '\0' || !conntype || conntype[0] == '\0')
		return -1;

	snprintf(ovpn_prefix, sizeof(ovpn_prefix), "vpn_client%d_", ovpn_unit);

	fd = file_lock(TPVPN_FILE_LOCK);
	nvram_set("tpvpn_state", "1");
	nvram_set("tpvpn_provider", TPVPN_PSZ_HMA);
	nvram_set("tpvpn_conntype", !strcasecmp(conntype, "TCP") ? "TCP" : "UDP");
	if (_hma_get_dl_filename(region, conntype, filename, sizeof(filename)))
	{
		file_unlock(fd);
		nvram_set("tpvpn_state", "-1");
		logmessage_normal("HMA", "Get Download config filename failed\n");
		return -1;
	}
	else
		nvram_set("tpvpn_filename", filename);
	tpvpn_get_conf_url(url, sizeof(url));
	while (curl_download_file(TPVPN_GET_CONF, url, TPVPN_DL_TMP_FILE) != LIBASC_SUCCESS && retry > 0)
	{
		retry--;
		logmessage_normal("HMA", "Download config failed, retry=[%d]\n", retry);
		sleep(2);
		unlink(TPVPN_DL_TMP_FILE);
	}
	file_unlock(fd);

	if (retry == 0)
	{
		nvram_set("tpvpn_state", "-1");
		return -1;
	}

	if (f_size(TPVPN_DL_TMP_FILE) > TPVPN_DL_FILESIZE_TH)
	{
		reset_ovpn_setting(OVPN_TYPE_CLIENT, ovpn_unit);
		read_config_file(TPVPN_DL_TMP_FILE, ovpn_unit);
		unlink(TPVPN_DL_TMP_FILE);
		nvram_pf_set(ovpn_prefix, "tp", TPVPN_PSZ_HMA);
		nvram_pf_set(ovpn_prefix, "tp_region", region);
		nvram_pf_set(ovpn_prefix, "tp_proto", conntype);
		nvram_set("tpvpn_state", "2");
		return 0;
	}
	else
		logmessage_normal("HMA", "Wrong content of ovpn file\n");

	return -1;
}

static char *_hma_get_list_ver(char *path, char *buf, size_t len)
{
	json_object *root_obj = NULL, *version_obj = NULL;
	if (!path || !check_if_file_exist(path) || !buf)
		return NULL;
	root_obj = json_object_from_file(path);
	if (root_obj)
	{
		if (json_object_object_get_ex(root_obj, "version", &version_obj))
			strlcpy(buf, json_object_get_string(version_obj), len);
		json_object_put(root_obj);
		return buf;
	}
	return NULL;
}

static int _hma_check_ver()
{
	char url[64] = {0};
	int fd;
	int retry = 5;
	json_object *root_obj = NULL, *version_obj = NULL, *tcp_obj = NULL, *udp_obj = NULL;
	char tcp_ver_r[16] = {0}, udp_ver_r[16] = {0}, tcp_ver_l[16] = {0}, udp_ver_l[16] = {0};
	char *path;
	int ret = 0;

	// get remote version info
	fd = file_lock(TPVPN_FILE_LOCK);
	nvram_set("tpvpn_provider", TPVPN_PSZ_HMA);
	tpvpn_get_ver_url(url, sizeof(url));
	while (curl_download_file(TPVPN_GET_VERSION, url, TPVPN_DL_TMP_FILE) != LIBASC_SUCCESS && retry > 0)
	{
		retry--;
		logmessage_normal("HMA", "Download version info failed, retry=[%d]\n", retry);
		sleep(2);
		unlink(TPVPN_DL_TMP_FILE);
	}
	if (retry == 0)
	{
		file_unlock(fd);
		return 0;
	}

	root_obj = json_object_from_file(TPVPN_DL_TMP_FILE);
	if (root_obj)
	{
		if (json_object_object_get_ex(root_obj, "VPN_Version", &version_obj))
		{
			json_object_object_get_ex(version_obj, "TCP", &tcp_obj);
			json_object_object_get_ex(version_obj, "UDP", &udp_obj);
			strlcpy(tcp_ver_r, json_object_get_string(tcp_obj), sizeof(tcp_ver_r));
			strlcpy(udp_ver_r, json_object_get_string(udp_obj), sizeof(udp_ver_r));
		}
		else
			logmessage_normal("HMA", "Wrong content of version info.\n");
		json_object_put(root_obj);
	}
	unlink(TPVPN_DL_TMP_FILE);
	file_unlock(fd);

	// get local version info
	if (check_if_file_exist(TPVPN_DL_HMA_TCP_LIST))
		path = TPVPN_DL_HMA_TCP_LIST;
	else
		path = TPVPN_FW_HMA_TCP_LIST;
	_hma_get_list_ver(path, tcp_ver_l, sizeof(tcp_ver_l));
	if (check_if_file_exist(TPVPN_DL_HMA_UDP_LIST))
		path = TPVPN_DL_HMA_UDP_LIST;
	else
		path = TPVPN_FW_HMA_UDP_LIST;
	_hma_get_list_ver(path, udp_ver_l, sizeof(udp_ver_l));

	if(tcp_ver_r[0] != '\0' && strcmp(tcp_ver_l, tcp_ver_r))
		ret |= TPVPN_CONN_TCP;
	if(udp_ver_r[0] != '\0' && strcmp(udp_ver_l, udp_ver_r))
		ret |= TPVPN_CONN_UDP;
	printf("TCP: %s -> %s\n", tcp_ver_l, tcp_ver_r);
	printf("UDP: %s -> %s\n", udp_ver_l, udp_ver_r);
	printf("ret: %d\n", ret);
	return (ret);
}

static void _hma_update_list()
{
	int check_result = _hma_check_ver();
	char url[64] = {0};
	int fd;
	int retry = 5;

	mkdir_if_none(TPVPN_DL_FOLDER);

	if (check_result & TPVPN_CONN_TCP)
	{
		fd = file_lock(TPVPN_FILE_LOCK);
		nvram_set("tpvpn_provider", TPVPN_PSZ_HMA);
		nvram_set("tpvpn_conntype", "TCP");
		tpvpn_get_list_url(url, sizeof(url));
		while (curl_download_file(TPVPN_GET_LIST, url, TPVPN_DL_HMA_TCP_LIST) != LIBASC_SUCCESS && retry > 0)
		{
			retry--;
			logmessage_normal("HMA", "Download tcp list failed, retry=[%d]\n", retry);
			sleep(2);
		}
		file_unlock(fd);
	}
	if (check_result & TPVPN_CONN_UDP)
	{
		fd = file_lock(TPVPN_FILE_LOCK);
		nvram_set("tpvpn_provider", TPVPN_PSZ_HMA);
		nvram_set("tpvpn_conntype", "UDP");
		tpvpn_get_list_url(url, sizeof(url));
		while (curl_download_file(TPVPN_GET_LIST, url, TPVPN_DL_HMA_UDP_LIST) != LIBASC_SUCCESS && retry > 0)
		{
			retry--;
			logmessage_normal("HMA", "Download udp list failed, retry=[%d]\n", retry);
			sleep(2);
		}
		file_unlock(fd);
	}

	if (check_result)
		tpvpn_gen_hma_list();
}

void tpvpn_gen_hma_list()
{
	json_object *hma_obj = NULL, *tcp_obj = NULL, *udp_obj = NULL;
	json_object *regions_obj = NULL, *regions_array_obj = NULL;
	int regions_length, i;

	hma_obj = json_object_new_object();
	if (!hma_obj) {
		printf("generate %s failed\n", TPVPN_UI_HMA_LIST);
		goto hma_ui_list_end;
	}

	//TCP
	if (check_if_file_exist(TPVPN_DL_HMA_TCP_LIST))
		tcp_obj = json_object_from_file(TPVPN_DL_HMA_TCP_LIST);
	else
		tcp_obj = json_object_from_file(TPVPN_FW_HMA_TCP_LIST);
	if (tcp_obj)
	{
		if (json_object_object_get_ex(tcp_obj, "regions", &regions_obj))
		{
			regions_length = json_object_array_length(regions_obj);
			for (i = 0; i < regions_length; i++)
			{
				regions_array_obj = json_object_array_get_idx(regions_obj, i);
				if (regions_array_obj)
					json_object_object_del(regions_array_obj, "file");
			}
			json_object_object_add(hma_obj, "TCP", regions_obj);
		}
		else
			logmessage_normal("HMA", "Wrong content of TCP list.\n");
	}
	else
	{
		printf("get tcp data failed\n");
		goto hma_ui_list_end;
	}

	//UDP
	if (check_if_file_exist(TPVPN_DL_HMA_UDP_LIST))
		udp_obj = json_object_from_file(TPVPN_DL_HMA_UDP_LIST);
	else
		udp_obj = json_object_from_file(TPVPN_FW_HMA_UDP_LIST);
	if (udp_obj)
	{
		if (json_object_object_get_ex(udp_obj, "regions", &regions_obj))
		{
			regions_length = json_object_array_length(regions_obj);
			for (i = 0; i < regions_length; i++)
			{
				regions_array_obj = json_object_array_get_idx(regions_obj, i);
				if (regions_array_obj)
					json_object_object_del(regions_array_obj, "file");
			}
			json_object_object_add(hma_obj, "UDP", regions_obj);
		}
		else
			logmessage_normal("HMA", "Wrong content of UDP list.\n");
	}
	else
	{
		printf("get udp data failed\n");
		goto hma_ui_list_end;
	}

	json_object_to_file(TPVPN_UI_HMA_LIST, hma_obj);

hma_ui_list_end:
	if (tcp_obj) json_object_put(tcp_obj);
	if (udp_obj) json_object_put(udp_obj);
	if (hma_obj) json_object_put(hma_obj);
}

//hmavpn setconf <region> <conn> <ovpn unit> [<vpnc idx>]
//hmavpn update
int hmavpn_main(int argc, char **argv)
{
	if (argc < 2) goto hma_error;

	if (!strcmp(argv[1], "setconf"))
	{
		char *region = argv[2];
		char *conntype = argv[3];
		int ovpn_unit = 0;
#ifdef RTCONFIG_VPN_FUSION
		int vpnc_unit = 0;
#else
		char action[32] = {0};
#endif

		if (argc < 5)
			goto hma_error;
		ovpn_unit = atoi(argv[4]);
		if (ovpn_unit < 1 || ovpn_unit > OVPN_CLIENT_MAX)
			goto hma_error;
#ifdef RTCONFIG_VPN_FUSION
		if (argc < 6)
			goto hma_error;
		vpnc_unit = atoi(argv[5]);
#endif

		if(_hma_setconf(ovpn_unit, region, conntype) == 0)
		{
#ifdef RTCONFIG_VPN_FUSION
			nvram_set_int("vpnc_unit", vpnc_unit);
			notify_rc("restart_vpnc");
#else
			_ovpn_sync_account(ovpn_unit);
			snprintf(action, sizeof(action), "restart_vpnclient%d", ovpn_unit);
			notify_rc(action);
#endif
		}
		else
			goto hma_error;
	}
	else if (!strcmp(argv[1], "getfn"))
	{
		char *region = argv[2];
		char *conntype = argv[3];
		char buf[32] = {0};
		_hma_get_dl_filename(region, conntype, buf, sizeof(buf));
		printf("%s\n", buf);
	}
	else if (!strcmp(argv[1], "uilist"))
	{
		tpvpn_gen_hma_list();
	}
	else if (!strcmp(argv[1], "check"))
	{
		_hma_check_ver();
	}
	else if (!strcmp(argv[1], "update"))
	{
		FILE* fp;
		if (f_exists(TPVPN_HMA_UPDATE_PID))
			kill_pidfile_tk(TPVPN_HMA_UPDATE_PID);
		fp = fopen(TPVPN_HMA_UPDATE_PID, "w");
		if(fp) {
			fprintf(fp, "%d", getpid());
			fclose(fp);
		}
		_hma_update_list();
		unlink(TPVPN_HMA_UPDATE_PID);
	}

	return 0;

hma_error:
	nvram_set("tpvpn_state", "-1");
	return -1;
}
#endif

#ifdef RTCONFIG_WIREGUARD
static void _nord_challenge(const char* challenge)
{
	CURL *curl = NULL;
	FILE *fp = NULL;
	CURLcode res = CURLE_FAILED_INIT;
	struct curl_httppost *post = NULL;
	struct curl_httppost *last = NULL;
	json_object *root_obj = NULL, *redirect_uri = NULL, *attempt = NULL;

	curl = curl_easy_init();
	if (curl)
	{
		if((fp = fopen(TPVPN_DL_TMP_FILE,"wb")) != NULL)
		{
			curl_formadd(&post, &last,
				CURLFORM_COPYNAME, "challenge",
				CURLFORM_COPYCONTENTS, challenge,
				CURLFORM_END);
			curl_formadd(&post, &last,
				CURLFORM_COPYNAME, "preferred_flow",
				CURLFORM_COPYCONTENTS, "login",
				CURLFORM_END);
			curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
			curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
			curl_easy_setopt(curl, CURLOPT_URL, TPVPN_NORD_URL_LOGIN);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tpvpn_write_data);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			res = curl_easy_perform(curl);
			fclose(fp);
		}

		curl_formfree(post);
		curl_easy_cleanup(curl);
	}

	if (res == CURLE_OK)
	{
		root_obj = json_object_from_file(TPVPN_DL_TMP_FILE);
		if (root_obj)
		{
			if (json_object_object_get_ex(root_obj, "redirect_uri", &redirect_uri))
				nvram_set("nordvpn_redirect_uri", json_object_get_string(redirect_uri));
			printf("Open the following URL with your browser:\n%s\n", json_object_get_string(redirect_uri));
			if (json_object_object_get_ex(root_obj, "attempt", &attempt))
				nvram_set("nordvpn_attempt", json_object_get_string(attempt));
			json_object_put(root_obj);
		}
	}
	else
	{
		printf("%s\n", curl_easy_strerror(res));
		logmessage_normal("NordVPN", "Get Redirect URI failed: %s", curl_easy_strerror(res));
	}

}

static void _nord_login()
{
	char uuid[37] = {0};
	unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
	char uuid_hash[SHA256_DIGEST_LENGTH*2+1] = {0};
	int i;

	f_read_string("/proc/sys/kernel/random/uuid", uuid, sizeof(uuid));
	nvram_set("nordvpn_uuid", uuid);

	SHA256((unsigned char*)uuid, strlen(uuid), hash);

	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
		snprintf(uuid_hash + (i * 2), 3, "%02x", hash[i]);
	nvram_set("nordvpn_uuid_hash", uuid_hash);

	_nord_challenge(uuid_hash);
}

static void _nord_get_token()
{
	CURL *curl = NULL;
	FILE *fp = NULL;
	CURLcode res = CURLE_FAILED_INIT;
	char full_url[512] = {0};
	json_object *root_obj = NULL, *token = NULL, *expires_at = NULL;

	if (nvram_is_empty("nordvpn_exchange_token"))
	{
		printf("Please login first!");
		logmessage_normal("NordVPN", "No exchange token. Please login first\n");
		return;
	}

	curl = curl_easy_init();
	if (curl)
	{
		if((fp = fopen(TPVPN_DL_TMP_FILE,"wb")) != NULL)
		{
			snprintf(full_url, sizeof(full_url),
				"%s?attempt=%s&verifier=%s&exchange_token=%s"
				, TPVPN_NORD_URL_TOKEN
				, nvram_safe_get("nordvpn_attempt")
				, nvram_safe_get("nordvpn_uuid")
				, nvram_safe_get("nordvpn_exchange_token")
				);
			curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
			curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
			curl_easy_setopt(curl, CURLOPT_URL, full_url);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tpvpn_write_data);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			res = curl_easy_perform(curl);
			fclose(fp);
		}

		curl_easy_cleanup(curl);
	}

	if (res == CURLE_OK)
	{
		root_obj = json_object_from_file(TPVPN_DL_TMP_FILE);
		if (root_obj)
		{
			// "user_id", "token", "renew_token", "expires_at", "updated_at", "created_at", "id"
			if (json_object_object_get_ex(root_obj, "token", &token))
				nvram_set("nordvpn_token", json_object_get_string(token));
			printf("token:%s\n", json_object_get_string(token));
			if (json_object_object_get_ex(root_obj, "expires_at", &expires_at))
				nvram_set("nordvpn_token_expire", json_object_get_string(expires_at));
			json_object_put(root_obj);
		}
	}
	else
	{
		printf("%s\n", curl_easy_strerror(res));
		logmessage_normal("NordVPN", "Get Token failed: %s", curl_easy_strerror(res));
	}

}

static int _nord_get_with_token(const char* url)
{
	CURL *curl = NULL;
	FILE *fp = NULL;
	CURLcode res = CURLE_FAILED_INIT;
	char userpass[128] = {0};

	if (nvram_is_empty("nordvpn_token"))
	{
		printf("No token!");
		return (res);
	}

	curl = curl_easy_init();
	if (curl)
	{
		if((fp = fopen(TPVPN_DL_TMP_FILE,"wb")) != NULL)
		{
			curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
			curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
			curl_easy_setopt(curl, CURLOPT_URL, url);
			snprintf(userpass, sizeof(userpass), "token:%s", nvram_safe_get("nordvpn_token"));
			curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tpvpn_write_data);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			res = curl_easy_perform(curl);
			fclose(fp);
		}

		curl_easy_cleanup(curl);
	}

	return (res);
}

static void _nord_get_countries()
{
	CURLcode res = CURLE_FAILED_INIT;
	json_object *root_obj = NULL, *regions_array_obj = NULL;
	json_object *name_obj = NULL, *id_obj = NULL;
	int regions_length, i;

	res = _nord_get_with_token(TPVPN_NORD_URL_COUNTRIES);
	if (res == CURLE_OK)
	{
		root_obj = json_object_from_file(TPVPN_DL_TMP_FILE);
		if (root_obj)
		{
			regions_length = json_object_array_length(root_obj);
			for (i = 0; i < regions_length; i++)
			{
				regions_array_obj = json_object_array_get_idx(root_obj, i);
				if (regions_array_obj)
				{
					json_object_object_get_ex(regions_array_obj, "id", &id_obj);
					json_object_object_get_ex(regions_array_obj, "name", &name_obj);
					printf("%s: %s\n", json_object_get_string(id_obj), json_object_get_string(name_obj));
				}
			}
			json_object_put(root_obj);
		}
	}
	else
	{
		printf("%s\n", curl_easy_strerror(res));
		logmessage_normal("NordVPN", "Get Country List failed: %s", curl_easy_strerror(res));
	}
}

static int _nord_get_server(int country_id)
{
	char url[256] = {0};
	CURLcode res = CURLE_FAILED_INIT;
	json_object *root_obj = NULL, *servers_array_obj = NULL;
	json_object *name_obj = NULL, *id_obj = NULL;
	int servers_length, i;
	unsigned int rand = 0;
	int server_id = 0;

	snprintf(url, sizeof(url), TPVPN_NORD_URL_SERVERS, country_id);
	res = _nord_get_with_token(url);
	if (res == CURLE_OK)
	{
		root_obj = json_object_from_file(TPVPN_DL_TMP_FILE);
		if (root_obj)
		{
			servers_length = json_object_array_length(root_obj);
			f_read("/dev/urandom", &rand, sizeof(rand));
			rand %= servers_length;
			for (i = 0; i < servers_length; i++)
			{
				servers_array_obj = json_object_array_get_idx(root_obj, i);
				if (servers_array_obj)
				{
					json_object_object_get_ex(servers_array_obj, "id", &id_obj);
					json_object_object_get_ex(servers_array_obj, "name", &name_obj);
					printf("%s: %s\n", json_object_get_string(id_obj), json_object_get_string(name_obj));
				}
				if (i == rand)
					server_id = json_object_get_int(id_obj);
			}
			json_object_put(root_obj);
		}
	}
	else
	{
		printf("%s\n", curl_easy_strerror(res));
		logmessage_normal("NordVPN", "Get Server List failed: %s", curl_easy_strerror(res));
	}

	printf("Pick server %d\n", server_id);
	return (server_id);
}

static void _nord_get_config(int server_id)
{
	char url[128] = {0};
	CURLcode res = CURLE_FAILED_INIT;
	json_object *root_obj = NULL;

	snprintf(url, sizeof(url), TPVPN_NORD_URL_CONFIG, server_id);
	res = _nord_get_with_token(url);
	if (res == CURLE_OK)
	{
		root_obj = json_object_from_file(TPVPN_DL_TMP_FILE);
		if (root_obj)
		{
			json_object_put(root_obj);
		}
	}
	else
	{
		printf("%s\n", curl_easy_strerror(res));
		logmessage_normal("NordVPN", "Get Config File failed: %s", curl_easy_strerror(res));
	}
}

static void _reset_wgc_config(int wgc_unit)
{
	struct nvram_tuple *t;
	char prefix_df[32] = {0};
	char prefix_nv[32] = {0};

	snprintf(prefix_df, sizeof(prefix_df), "%s_", WG_CLIENT_NVRAM_PREFIX);
	snprintf(prefix_nv, sizeof(prefix_nv), "%s%d_", WG_CLIENT_NVRAM_PREFIX, wgc_unit);

	for (t = router_defaults; t->name; t++) {
		if ( strlen(t->name) > strlen(prefix_df)
			&& !strncmp(t->name, prefix_df, strlen(prefix_df))
			&& !strstr(t->name, "unit")
		) {
			printf("reset %s%s=%s\n", prefix_nv, t->name + strlen(prefix_df), t->value);
			nvram_pf_set(prefix_nv, t->name + strlen(prefix_df), t->value);
		}
	}

}

static char* _get_wgconf_val(char* buf)
{
	char *p = buf;
	int i = 0, len = 0, j = 0;

	if (!buf)
		return p;
	if ((p = strchr(buf, '='))) p++;

	len = strlen(p);
	for (i = 0; i < len; i++)
	{
		if (p[i] == ' ' || p[i] == '\r' || p[i] == '\n')
		{
			for(j = i; j < len; j++)
			{
				p[j] = p[j+1];
			}
			len--;
		}
	}
	return p;
}

static int _nord_read_wgc_config(int wgc_unit, const char* path)
{
	char wgc_prefix[8] = {0};
	FILE *fp;
	char buf[256] = {0};

	if (!path || path[0] == '\0')
		return -1;

	snprintf(wgc_prefix, sizeof(wgc_prefix), "%s%d_", WG_CLIENT_NVRAM_PREFIX, wgc_unit);

	fp = fopen(path, "r");
	if (fp)
	{
		while (fgets(buf, sizeof(buf), fp))
		{
			if (buf[0] == '[' || buf[0] == '#' || buf[0] == '\n')
				continue;
			else if (!strncmp(buf, "PrivateKey", 10))
				nvram_pf_set(wgc_prefix, "priv", _get_wgconf_val(buf));
			else if (!strncmp(buf, "Address", 7))
				nvram_pf_set(wgc_prefix, "addr", _get_wgconf_val(buf));
			else if (!strncmp(buf, "DNS", 3))
				nvram_pf_set(wgc_prefix, "dns", _get_wgconf_val(buf));
			else if (!strncmp(buf, "PublicKey", 9))
				nvram_pf_set(wgc_prefix, "ppub", _get_wgconf_val(buf));
			else if (!strncmp(buf, "PresharedKey", 12))
				nvram_pf_set(wgc_prefix, "psk", _get_wgconf_val(buf));
			else if (!strncmp(buf, "AllowedIPs", 10))
				nvram_pf_set(wgc_prefix, "aips", _get_wgconf_val(buf));
			else if (!strncmp(buf, "Endpoint", 8))
			{
				char *ep, *p;
				ep = _get_wgconf_val(buf);
				p = strchr(ep, ':');
				*p = '\0';
				nvram_pf_set(wgc_prefix, "ep_addr", ep);
				nvram_pf_set(wgc_prefix, "ep_port", p+1);
			}
			else if (!strncmp(buf, "PersistentKeepalive", 19))
				nvram_pf_set(wgc_prefix, "alive", _get_wgconf_val(buf));

		}
		nvram_pf_set(wgc_prefix, "enable", "1");
		nvram_pf_set(wgc_prefix, "nat", "1");
		fclose(fp);
	}
	else
		return -1;

	return 0;
}

static int _nord_setconf(int wgc_unit, const char* region)
{
	char wgc_prefix[8] = {0};
	int fd;
	int server_id = 0;

	if (!region || region[0] == '\0')
		return -1;

	snprintf(wgc_prefix, sizeof(wgc_prefix), "%s%d_", WG_CLIENT_NVRAM_PREFIX, wgc_unit);

	fd = file_lock(TPVPN_FILE_LOCK);
	nvram_set("tpvpn_state", "1");
	nvram_set("tpvpn_provider", TPVPN_PSZ_NORDVPN);

	/// TODO:
	/// 1. login, 2. get token

	server_id = _nord_get_server(atoi(region));
	if (server_id)
		_nord_get_config(server_id);
	else
	{
		logmessage_normal("NordVPN", "Get Nordlynx config failed\n");
		file_unlock(fd);
		return -1;
	}

	file_unlock(fd);

	if (f_size(TPVPN_DL_TMP_FILE) > TPVPN_DL_FILESIZE_TH)
	{
		_reset_wgc_config(wgc_unit);
		_nord_read_wgc_config(wgc_unit, TPVPN_DL_TMP_FILE);
		unlink(TPVPN_DL_TMP_FILE);
		nvram_pf_set(wgc_prefix, "tp", TPVPN_PSZ_NORDVPN);
		nvram_pf_set(wgc_prefix, "tp_region", region);
		nvram_set("tpvpn_state", "2");
		return 0;
	}
	else
		logmessage_normal("NordVPN", "Wrong Nordlynx config file\n");

	return 0;
}

int nordvpn_main(int argc, char **argv)
{
	if (argc < 2) goto nord_error;

	if (!strcmp(argv[1], "login"))
	{
		_nord_login();
	}
	else if (!strcmp(argv[1], "token"))
	{
		_nord_get_token();
	}
	else if (!strcmp(argv[1], "country"))
	{
		_nord_get_countries();
	}
	else if (!strcmp(argv[1], "server"))
	{
		int country_id = 0;
		if (argc < 3)
			goto nord_error;
		country_id = atoi(argv[2]);
		_nord_get_server(country_id);
	}
	else if (!strcmp(argv[1], "config"))
	{
		int server_id = 0;
		if (argc < 3)
			goto nord_error;
		server_id = atoi(argv[2]);
		_nord_get_config(server_id);
	}
	else if (!strcmp(argv[1], "setconf"))
	{
		//setconf <region id> <wgc unit> [<vpnc unit>]
		char* region = argv[2];
		int wgc_unit = 0;
		char action[32] = {0};

		if (argc < 4)
			goto nord_error;
		wgc_unit = atoi(argv[3]);
		if (wgc_unit < 1 || wgc_unit > WG_CLIENT_MAX)
			goto nord_error;

		if(_nord_setconf(wgc_unit, region) == 0)
		{
			snprintf(action, sizeof(action), "restart_wgc %d", wgc_unit);
			notify_rc(action);
		}
		else
			goto nord_error;
	}

	return 0;

nord_error:
	nvram_set("tpvpn_state", "-1");
	return -1;
}
#endif
