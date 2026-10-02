#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rc.h>
#ifdef RTCONFIG_LIBASUSLOG
#include <libasuslog.h>
#endif
#include <bcmnvram.h>
#include <shared.h>
#include <shutils.h>
#include <curl/curl.h>
#ifdef RTCONFIG_HTTPS
#include <openssl/md5.h>
#endif
#include <json.h>

#ifdef RTCONFIG_FRS_LIVE_UPDATE
#define ALGOVERSION 1
#define FIRMWARE_CHECK_UPDATE_PID	"/var/run/firmware_check_update.pid"

enum{
	COMMON_DL = 0,
	FRS_DL
};

#ifdef RTCONFIG_LIBASUSLOG
#define FWUPDATE_DBG(fmt,args...) \
        if(1) { \
		asusdebuglog(LOG_INFO, WEBSUPG_FILE, LOG_CUSTOM, LOG_SHOWTIME, 30, "[FWUPDATE][%s:(%d)]"fmt"\n", __FUNCTION__, __LINE__ , ##args); \
        }
#else
#define FWUPDATE_DBG(fmt,args...) \
	if(1) { \
		char info[1024]; \
snprintf(info, sizeof(info), "echo \"[FWUPDATE][%s:(%d)]"fmt"\" >> /tmp/webs_upgrade.log", __FUNCTION__, __LINE__, ##args); \
		system(info); \
	}
#endif

#define ASUSCTRL_ACTION_SET(value,x) ( (value) |=  (0x1 << x))

#define ASUSCTRL_ACTION_CLR(value,x) ( (value) &= ~(0x1 << x))

int getPid_fromFile(char *file_name)
{
	FILE *fp;
	char *pidfile = file_name;
	int result = -1;

	fp= fopen(pidfile, "r");
	if (!fp) {
	    dbg("can not open:%s\n", file_name);
	    return -1;
	}
	fscanf(fp,"%d",&result);
	fclose(fp);

	return result;
}

static void trim_dot(char *str)
{
	int i=0, len=0, j=0;
	len=strlen(str);
	for(i=0; i<len; i++)
	{
		if(str[i]=='.')
		{
			for(j=i; j<len; j++)
			{
				str[j]=str[j+1];
			}
		len--;
		}
	}
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

#ifdef RTCONFIG_ASD
#ifndef SAFE_FREE
#define SAFE_FREE(x) if(x){free(x); x=NULL;}
#endif
const char asd_json_log_path[][32] = {{'/','j','f','f','s','/','a','s','d','_','j','s','o','n','\0'}};

static char *_convert_hex_to_ascii(const char *hex_str, const size_t hex_len, char *ascii_str, const size_t ascii_len)
{
	int i, j;
	char hex[5] = {'0', 'x', '0', '0', '\0'}, *end;

	if(!ascii_str || !hex_str || ascii_len <= (hex_len / 2))	//ascii_str need a end-string character in its array.
	{
		return NULL;
	}

	for(i = 0, j = 0; i < hex_len; i += 2, ++j)
	{
		hex[2] = hex_str[i];
		hex[3] = hex_str[i + 1];
		ascii_str[j] = strtol(hex, &end, 16);
	}
	return ascii_str;
}


static int _verify_hex_str(const char *str, const size_t len)
{
	int i;

	if(str)
	{
		for(i = 0; i < len; ++i)
		{
			if((str[i] < '0' || str[i] > '9') &&  //check number
				(str[i] < 'A' || str[i] > 'F') &&   //check A~F
				(str[i] < 'a' || str[i] > 'f')) //check a~f
			{
				return -1;
			}
		}
		return 0;
	}
	return -1;
}

char *read_asd_enc_file(const char *file)
{
	char *buf = NULL, *f_buf = NULL, *hex_str = NULL;
	FILE *fp;
	unsigned long sz, dec_sz, buf_len;

	if(!file)
	{
		return NULL;
	}

	sz = f_size(file);
	if(!sz)
	{
		dbg("[%s] File size (%d) is invalid (%s)!\n", __FUNCTION__, sz, file);
		return NULL;
	}

	fp = fopen(file, "r");
	if(fp)
	{
		f_buf = calloc(sz + 1, 1);
		if(!f_buf)
		{
			dbg("[%s] Memory alloc fail!\n", __FUNCTION__);
			fclose(fp);
			return NULL;
		}
		fread(f_buf, 1, sz, fp);
		fclose(fp);
	}
	else
	{
		dbg("[%s] Cannot open file (%s)!\n", __FUNCTION__, file);
		return NULL;
	}
	dec_sz = pw_dec_len(f_buf);

	if(dec_sz < strlen(f_buf))
	{
		dec_sz = strlen(f_buf);
	}
	hex_str = calloc(dec_sz + 1, 1);
	if(!hex_str)
	{
		dbg("[%s] Memory alloc fail!\n", __FUNCTION__);
		SAFE_FREE(f_buf);
		return NULL;
	}
	//decrypt content and verify
	pw_dec(f_buf, hex_str, dec_sz + 1, 0);

	if(_verify_hex_str(hex_str, strlen(hex_str)) == -1)
	{
		dbg("[%s] HEX string is invalid!\n", __FUNCTION__);
		SAFE_FREE(f_buf);
		return NULL;
	}
	//convert hex to ascii
	buf_len = strlen(hex_str) / 2 + 1;
	buf = calloc(buf_len, 1);
	if(!buf)
	{
		dbg("[%s] Memory alloc fail!\n", __FUNCTION__);
		SAFE_FREE(f_buf);
		SAFE_FREE(hex_str);
		return NULL;
	}
	if(!_convert_hex_to_ascii(hex_str, strlen(hex_str), buf, buf_len))
	{
		dbg("[%s] _convert_hex_to_ascii fail!\n", __FUNCTION__);
		SAFE_FREE(f_buf);
		SAFE_FREE(buf);
		SAFE_FREE(hex_str);
		return NULL;
	}
	SAFE_FREE(hex_str);
	SAFE_FREE(f_buf);
	if(buf[0] != '\0')
	{
		return buf;
	}
	else
		SAFE_FREE(buf);
	return NULL;
}

char* get_asd_json_log(char *buf, const size_t buf_len)
{
	char *tmp = NULL;

	if(!buf || !buf_len)
		return NULL;

	if(!access(asd_json_log_path[0], F_OK))
	{
		tmp = read_asd_enc_file(asd_json_log_path[0]);

		if(tmp)
		{
			strlcpy(buf, tmp, buf_len);
		}
		SAFE_FREE(tmp);		
		//unlink(asd_json_log_path[0]);
			return buf;
		}
	return NULL;
}
#endif

#ifdef RTCONFIG_AHS
int parse_hwsw_status(char *data, hwsw_state_t *hs)
{
	int n = 0;
	char content[256] = {0};
	int envram = 0;
	int frs = 0;
	int eula = 0;

	if((!data)||(!hs))
	{
		return -1;
	}

	//parse data, data format is "string>int>int>int", e.g., "1/2/3/4>1>1>0".
	n = sscanf(data, "%[^>]>%d>%d>%d", content, &envram, &frs, &eula);
	if(n != 4)
	{
		return -2;
	}
	else
	{
		snprintf(hs->content, sizeof(hs->content), "%s", content);
		hs->ctl_envram = envram;
		hs->ctl_frs = frs;
		hs->ctl_eula = eula;
		return 0;
	}
}

enum {
	GED_ERR_NONE = 0,
	GED_ERR_PARAM = -1,
	GED_ERR_EULA = -2,
	GED_ERR_FRS = -3,
	GED_ERR_PARSER = -4,
	GED_ERR_JSONOBJ = -5,
};

int start_envrams_server(void)
{
	FILE  *fp = NULL;
	char buffer[128] = {0};
	int ret = -1;

	fp = popen("which envrams", "r");
	if(fp)
	{
		memset(buffer, 0, sizeof(buffer));
		if(fgets(buffer, sizeof(buffer), fp))
		{
			if(strlen(trimNL(buffer)) > 0)
			{
				if(!pids("envrams"))
				{
					system(buffer);
					sleep(1);
				}
				ret = 0;
			}
		}
		pclose(fp);
	}

	return ret;
}

int get_envram_data(char *name, char *buffer, int len)
{
	FILE  *fp = NULL;
	char databuf[256] = {0};
	char cmdbuf[128] = {0};
	int ret = GED_ERR_PARAM;
//	json_object *status_obj = NULL;
	hwsw_state_t hs;

	if((!name)||(!buffer)||(!len))
	{
		ret = GED_ERR_PARAM;
		goto error;
	}

	memset(&hs, 0, sizeof(hwsw_state_t));

	if(start_envrams_server() == 0)
	{
		snprintf(cmdbuf, sizeof(cmdbuf), "envram get %s", name);
		fp = popen(cmdbuf, "r");
		if(fp)
		{
			memset(databuf, 0, sizeof(databuf));
			if(fgets(databuf, sizeof(databuf), fp))
			{
				trimNL(databuf);
			}
			pclose(fp);
			//parse databuf to extract 1:content, 2:ctl_envram, 3:ctl_frs, and 4:ctl_eula.
			if(parse_hwsw_status(databuf, &hs) == 0)
			{
				if(hs.ctl_frs == 1)
				{
					if(hs.ctl_eula == 0)
					{
						snprintf(buffer, len, "%s", hs.content);
						ret = GED_ERR_NONE;
					}
					else
					{
						//if ctl_eula is 1, then we have to determine whether asus_eula is 1.
						if(nvram_match("asus_eula", "1"))
						{
							snprintf(buffer, len, "%s", hs.content);
							ret = GED_ERR_NONE;
						}
						else
						{
							ret = GED_ERR_EULA;
						}
					}
				}
				else
				{
					ret = GED_ERR_FRS;
				}
			}
			else
			{
				ret = GED_ERR_PARSER;
			}
			goto error;
		}
	}
	else
	{
#if 0
		//file exists, read it
		if(readFileSize("/jffs/ahs/"AHS_HWSW_ST_JFFS_FILE) > 0)
		{
			status_obj = json_object_from_file("/jffs/ahs/"AHS_HWSW_ST_JFFS_FILE);
			if (!status_obj)
			{
				_dprintf("Cannot open %s\n", "/jffs/ahs/"AHS_HWSW_ST_JFFS_FILE);
				ret = GED_ERR_JSONOBJ;
				goto error;
			}
			else
			{
				//handle json file
			}
		}
		else
		{
			//create or overwrite it.
		}
#endif
	}

error:
	_dprintf("[%s]name=[%s], buffer=[%s]\n", __FUNCTION__, name, buffer);
	_dprintf("[%s]ret=[%d]\n", __FUNCTION__, ret);
	return ret;
}

void add_ahs_hwsw_status(struct curl_httppost **post, struct curl_httppost **last)
{
	char *s = NULL, *t = NULL;
	FILE *cmdp = NULL;
	char cmdbuf[128] = {0};
	char keybuf[128] = {0};
	char databuf[128] = {0};

	if((!post)||(!last))
	{
		return;
	}

	if(start_envrams_server() == 0)
	{
		snprintf(cmdbuf, sizeof(cmdbuf), "envram show|grep ahs_st_");
		cmdp = popen(cmdbuf, "r");
		if(cmdp)
		{
			memset(keybuf, 0, sizeof(keybuf));
			while(fgets(keybuf, sizeof(keybuf), cmdp))
			{
				if(strlen(trimNL(keybuf)) > 0)
				{
					if(strstr(keybuf, "ahs_st_"))
					{
						s = keybuf + strlen("ahs_st_");
						t = keybuf + strlen(keybuf);
						while((*s != '=')&&(s <= t))
						{
							s++;
						}
						*s = '\0';
						_dprintf("key=[%s]\n", keybuf);
						memset(databuf, 0, sizeof(databuf));
						if(get_envram_data(keybuf, databuf, sizeof(databuf)) == 0)
						{
							if(strlen(databuf) > 0)
							{
								curl_formadd(post, last,
								CURLFORM_COPYNAME, keybuf,
								CURLFORM_COPYCONTENTS, databuf,
								CURLFORM_END);
							}
						}
					}
				}
				memset(keybuf, 0, sizeof(keybuf));
			}
			pclose(cmdp);
		}
	}
	else
	{
		//read jffs, parse data.
	}
}
#endif /* RTCONFIG_AHS */

void add_value_from_ATE_cmd(struct curl_httppost **post, struct curl_httppost **last, char *cmd, char *name)
{
	FILE *cmdp = NULL;
	char databuf[256] = {0};

	if(!post||!(*post)||!last||!(*last)||!cmd||!name)
	{
		FWUPDATE_DBG("Null pointer!");
		return;
	}

	cmdp = popen(cmd, "r");
	if(cmdp)
	{
		memset(databuf, 0, sizeof(databuf));
		if(fgets(databuf, sizeof(databuf), cmdp))
		{
			trimNL(databuf);
		}
		pclose(cmdp);
	}

	if(strlen(databuf) > 0)
	{
		if(strcmp(databuf, "ATE_UNSUPPORT") != 0)
		{
			curl_formadd(post, last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, databuf,
			CURLFORM_END);
		}
		else
		{
			FWUPDATE_DBG("Unsupported ATE cmd:[%s]", cmd);
		}
	}
}

static int
isValidtimestamp_noletter(char *timestamp)
{
	time_t ts;
	char *ptr = NULL;

	ts = (time_t)strtol(timestamp, &ptr, 10);
	if((0 < ts && ts < 2145888000L) && (ptr && strlen(ptr) == 0))
		return 1;
	else
		return 0;
}

int First_Digit(int num)
{
	while(num >= 10)
	{
		num = num / 10;
	}
	return num;
}

void
get_2G_mac(char *output, int _size)
{
	FILE *cmdp = NULL;
	char buf[20] = {0};
	char mac[16] = {0};
	int n = 0;

	memset(output, 0, _size);
	cmdp = popen("ATE Get_MacAddr_2G", "r");
	if(cmdp)
	{
		if(fgets(buf, sizeof(buf), cmdp))
		{
			trimNL(buf);
		}
		pclose(cmdp);

		if(strlen(buf) > 0)
		{
			n = sscanf(buf, "%[^:]:%[^:]:%[^:]:%[^:]:%[^:]:%s", &mac[0], &mac[2], &mac[4], &mac[6], &mac[8], &mac[10]);
		}
		if(n == 6)
		{
			snprintf(output, _size, "%s", mac);
		}
	}
}

static int
curl_download_file(char *url, char *file_path, int dl_target, int retry, int check_CA)
{
#ifdef RTCONFIG_ASD
	char asd_log[1024] = {0};
#endif
	CURLcode res = -1;
	curl_global_init(CURL_GLOBAL_ALL);

	while(retry > 0 && res != CURLE_OK){
		FILE *fp = NULL;
		CURL *curl = NULL;
		struct curl_httppost *post = NULL;
		struct curl_httppost *last = NULL;
		unsigned long long requests_after_boot_up = 0;
#if defined(RTAX89U)
		FILE *cmdp = NULL;
#endif
		curl = curl_easy_init();
		if (curl && (fp = fopen(file_path,"wb")) != NULL)
		{
			if(dl_target == FRS_DL)
			{
				int i=0;
				unsigned char digest[17]={0};
				char algover[8]={0}, fw_ver[128]={0}, md_label_mac[33]={0}, productid[128]={0};
				char *label_mac_str=NULL;
			char asus_eula[4] = {0};
#ifdef RTCONFIG_BWDPI
			char tm_eula[4] = {0};
#endif

				char label_mac[][16] = {{ 'l', 'a', 'b', 'e', 'l', '_', 'm', 'a', 'c', '\0' }};
				char Model[][8] = {{ 'M', 'o', 'd', 'e', 'l' , '\0'}};
				char TCode[][8] = {{ 'T', 'C', 'o', 'd', 'e', '\0' }};
				char FWVER[][8] = {{ 'F', 'W', 'V', 'E', 'R', '\0' }};
				char IDENT[][8] = {{ 'I', 'D', 'E', 'N', 'T', '\0' }};
				char FTYMAC[][8] = {{ 'F', 'T', 'Y', 'M', 'A', 'C', '\0' }}; //md5 of factory mac address
#ifdef RTCONFIG_CFGSYNC
				char cfg_group[33]={0};
				char GROUPID[][16] = {{ 'G', 'R', 'O', 'U', 'P', 'I', 'D', '\0' }};
#endif
				char AlgoVersion[][16] = {{ 'A', 'l', 'g', 'o', 'V', 'e', 'r', 's', 'i', 'o', 'n', '\0' }};
				char dl_format[][16] = {{ 'd', 'l', 'f', 'o', 'r', 'm', 'a', 't', '\0' }};
				char beta_path[][16] __attribute__((unused)) = {{ 'b', 'e', 't', 'a', '_', 'p', 'a', 't', 'h', '\0' }};
				char trigger_from[][16] = {{ 't', 'r', 'i', 'g', 'g', 'e', 'r', '_', 'f', 'r', 'o', 'm', '\0' }};
#ifdef RTCONFIG_ASD
				char asd[][8] = {{'a','s','d','\0'}};
				char asd_en[][8] = {{'a','s','d','_','e','n','\0'}};
				char asd_ver[][16] = {{'a', 's', 'd', '_', 'v', 'e', 'r', '\0'}};
#endif
				char APP_Access[][16] = {{'a', 'p', 'p', '_', 'a', 'c', 'c', 'e', 's', 's', '\0'}};
				char ASUS_EULA[][16] = {{'A', 'S', 'U', 'S', '_', 'E', 'U', 'L', 'A', '\0'}};
#ifdef RTCONFIG_BWDPI
				char TM_EULA[][16] = {{'T', 'M', '_', 'E', 'U', 'L', 'A', '\0'}};
#endif
				char DateCode[][16] = {{'d', 'a', 't', 'e', 'c', 'o', 'd', 'e', '\0'}};
				char HWVersion[][16] = {{'h', 'w', 'v', 'e', 'r', 's', 'i', 'o', 'n', '\0'}};
				char ReqCountAfterBootup[][16] = {{'r', 'e', 'q', '_', 'c', 'n', 't', '\0'}};
				char L2Ceiling[][16] = {{'l', '2', 'c', 'e', 'i', 'l', 'i', 'n', 'g', '\0'}};
				char PwrCycleCnt[][16] = {{'p', 'w', 'r', 'c', 'y', 'c', 'l', 'e', 'c', 'n', 't', '\0'}};
				char AvgUptime[][16] = {{'a', 'v', 'g', 'u', 'p', 't', 'i', 'm', 'e', '\0'}};
#if defined(RTAX89U)
			char fan_cur_state[][16] = {{'f', 'a', 'n', '_', 'c', 'u', 'r', '_', 's', 't', 'a', 't', 'e', '\0'}};
			char fan_rpm[][16] = {{'f', 'a', 'n', '_', 'r', 'p', 'm', '\0'}};
			char fanctrl_dutycycle[][20] = {{'f', 'a', 'n', 'c', 't', 'r', 'l', '_', 'd', 'u', 't', 'y', 'c', 'y', 'c', 'l', 'e', '\0'}};
			char pwrsave_mode[][16] = {{'p', 'w', 'r', 's', 'a', 'v', 'e', '_', 'm', 'o', 'd', 'e', '\0'}};
#endif
				char asusctrl_flag_update[][32] = {{'a', 's', 'u', 's', 'c', 't', 'r', 'l', '_', 'f', 'l', 'a', 'g', '_', 'u', 'p', 'd', 'a', 't', 'e', '\0'}};
				char databuf[128] = {0};
				char outputbuf[32] = {0};
#ifdef RTCONFIG_HTTPS
				MD5_CTX ate_2G_mac;
				unsigned char digest_2G_mac[17]={0};
				char md5_2G_mac[33]={0};
				char str_2G_mac[13] = {0};
#endif /* RTCONFIG_HTTPS */

				label_mac_str = nvram_safe_get(label_mac[0]);
#ifdef RTCONFIG_HTTPS
				MD5_CTX ctx;
				MD5_Init(&ctx);
				MD5_Update(&ctx, label_mac_str, strlen(label_mac_str));
				MD5_Final(digest, &ctx);
#endif
				for (i = 0; i < 16; i++)
				{
					sprintf(&md_label_mac[i*2], "%02x", (unsigned int)digest[i]);
				}

				get_2G_mac(str_2G_mac, sizeof(str_2G_mac));
#ifdef RTCONFIG_HTTPS
				MD5_Init(&ate_2G_mac);
				MD5_Update(&ate_2G_mac, str_2G_mac, strlen(str_2G_mac));
				MD5_Final(digest_2G_mac, &ate_2G_mac);
#endif /* RTCONFIG_HTTPS */
				for (i = 0; i < 16; i++)
				{
					sprintf(&md5_2G_mac[i*2], "%02x", (unsigned int)digest_2G_mac[i]);
				}
#ifdef RTCONFIG_CFGSYNC
				snprintf(cfg_group, sizeof(cfg_group), "%s", nvram_safe_get("cfg_group"));
#endif
				snprintf(algover, sizeof(algover), "Ver%04d", ALGOVERSION);
				snprintf(fw_ver, sizeof(fw_ver), "%s.%s_%s", nvram_safe_get("firmver"), nvram_safe_get("buildno"), nvram_safe_get("extendno"));
				snprintf(productid, sizeof(productid), "%s#%s", nvram_safe_get("productid"), nvram_safe_get("odmpid"));
				snprintf(asus_eula, sizeof(asus_eula), "%s", nvram_match(ASUS_EULA[0], "1")? "1": "0");
#ifdef RTCONFIG_BWDPI
				snprintf(tm_eula, sizeof(tm_eula), "%s", nvram_match(TM_EULA[0], "1")? "1": "0");
#endif

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, Model[0],
				CURLFORM_COPYCONTENTS, productid,
				CURLFORM_END);

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, TCode[0],
				CURLFORM_COPYCONTENTS, nvram_safe_get("territory_code"),
				CURLFORM_END);

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, FWVER[0],
				CURLFORM_COPYCONTENTS, fw_ver,
				CURLFORM_END);

				memset(databuf, 0, sizeof(databuf));

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, IDENT[0],
				CURLFORM_COPYCONTENTS, md_label_mac,
				CURLFORM_END);

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, FTYMAC[0],
				CURLFORM_COPYCONTENTS, md5_2G_mac,
				CURLFORM_END);
#ifdef RTCONFIG_CFGSYNC
				curl_formadd(&post, &last,
	                        CURLFORM_COPYNAME, GROUPID[0],
	                        CURLFORM_COPYCONTENTS, cfg_group,
	                        CURLFORM_END);
#endif
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, AlgoVersion[0],
				CURLFORM_COPYCONTENTS, algover,
				CURLFORM_END);

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, dl_format[0],
				CURLFORM_COPYCONTENTS, "json",
				CURLFORM_END);
				FWUPDATE_DBG("---- Request file format : json ----");
#ifdef RTCONFIG_BETA_UPGRADE
				curl_formadd(&post, &last,
                                CURLFORM_COPYNAME, beta_path[0],
                                CURLFORM_COPYCONTENTS, nvram_safe_get("webs_update_beta"),
                                CURLFORM_END);
#endif
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, trigger_from[0],
				CURLFORM_COPYCONTENTS, nvram_safe_get("webs_update_trigger"),
				CURLFORM_END);

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, APP_Access[0],
				CURLFORM_COPYCONTENTS, nvram_safe_get("app_access"),
				CURLFORM_END);

#ifdef RTCONFIG_ASD
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, asd_ver[0],
				CURLFORM_COPYCONTENTS, nvram_safe_get(asd_ver[0]),
				CURLFORM_END);

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, asd_en[0],
				CURLFORM_COPYCONTENTS, "1",
				CURLFORM_END);

				if(get_asd_json_log(asd_log, sizeof(asd_log)))
				{
					curl_formadd(&post, &last,
					CURLFORM_COPYNAME, asd[0],
					CURLFORM_COPYCONTENTS, asd_log,
					CURLFORM_END);
				}
#endif

				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, ASUS_EULA[0],
			CURLFORM_COPYCONTENTS, asus_eula,
				CURLFORM_END);

#if defined(RTCONFIG_BWDPI)
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, TM_EULA[0],
			CURLFORM_COPYCONTENTS, tm_eula,
				CURLFORM_END);
#endif
				add_value_from_ATE_cmd(&post, &last, "ATE Get_DateCode", DateCode[0]);
				add_value_from_ATE_cmd(&post, &last, "ATE Get_HwVersion", HWVersion[0]);
				if(nvram_match("fb_fortesting", "yes"))
				{
					//fortesting
					curl_formadd(&post, &last,
					CURLFORM_COPYNAME, "fortesting",
					CURLFORM_COPYCONTENTS, nvram_safe_get("fb_fortesting"),
					CURLFORM_END);
				}

				/* Begin: number of Live Update requests after boot up */
				/* This counter increases when raising a Live Update request */
				/* If device reboots, the counter will be reset to "0" */
				requests_after_boot_up = strtoull(nvram_safe_get("fb_req_cnt"), NULL, 10);
				requests_after_boot_up++;
				snprintf(databuf, sizeof(databuf), "%lld", requests_after_boot_up);
				nvram_set("fb_req_cnt", databuf);
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, ReqCountAfterBootup[0],
				CURLFORM_COPYCONTENTS, databuf,
				CURLFORM_END);
				/* End: number of Live Update requests after boot up */

				memset(outputbuf, 0, sizeof(outputbuf));
#ifdef RTCONFIG_ASUSCTRL
				snprintf(outputbuf, sizeof(outputbuf), "0x%x", nvram_get_hex("asusctrl_flag_update"));
#else
				snprintf(outputbuf, sizeof(outputbuf), "%s", "0xFF");
#endif
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, asusctrl_flag_update[0],
				CURLFORM_COPYCONTENTS, outputbuf,
				CURLFORM_END);

#if defined(RTAX89U)
			/* Begin: add fan related information */
			memset(outputbuf, 0, sizeof(outputbuf));
			cmdp = popen("cat /sys/class/thermal/cooling_device0/cur_state", "r");
			if(cmdp)
			{
				memset(databuf, 0, sizeof(databuf));
				if(fgets(databuf, sizeof(databuf), cmdp))
				{
					if(strlen(trimNL(databuf)) > 0)
					{
						snprintf(outputbuf, sizeof(outputbuf), "%s", trimNL(databuf));
					}
				}
				pclose(cmdp);
			}
			if(strlen(outputbuf) > 0)
			{
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, fan_cur_state[0],
				CURLFORM_COPYCONTENTS, outputbuf,
				CURLFORM_END);
			}

			memset(outputbuf, 0, sizeof(outputbuf));
			cmdp = popen("cat /sys/devices/platform/gpio-fan/hwmon/hwmon0/fan1_input", "r");
			if(cmdp)
			{
				memset(databuf, 0, sizeof(databuf));
				if(fgets(databuf, sizeof(databuf), cmdp))
				{
					if(strlen(trimNL(databuf)) > 0)
					{
						snprintf(outputbuf, sizeof(outputbuf), "%s", trimNL(databuf));
					}
				}
				pclose(cmdp);
			}
			if(strlen(outputbuf) > 0)
			{
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, fan_rpm[0],
				CURLFORM_COPYCONTENTS, outputbuf,
				CURLFORM_END);
			}

			memset(outputbuf, 0, sizeof(outputbuf));
			snprintf(outputbuf, sizeof(outputbuf), "%s", nvram_safe_get("fanctrl_dutycycle"));
			if(strlen(outputbuf) > 0)
			{
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, fanctrl_dutycycle[0],
				CURLFORM_COPYCONTENTS, outputbuf,
				CURLFORM_END);
			}

			memset(outputbuf, 0, sizeof(outputbuf));
			snprintf(outputbuf, sizeof(outputbuf), "%s", nvram_safe_get("pwrsave_mode"));

			if(strlen(outputbuf) > 0)
			{
				curl_formadd(&post, &last,
				CURLFORM_COPYNAME, pwrsave_mode[0],
				CURLFORM_COPYCONTENTS, outputbuf,
				CURLFORM_END);
			}
			/* End: add fan related information */
#endif /* defined(RTAX89U) */

#ifdef RTCONFIG_AHS
				/* Begin: report hardware/software status */
				/* envram parameter format: ahs_st_xxxxx */
				add_ahs_hwsw_status(&post, &last);
				/* End: report hardware/software status */
#endif /* RTCONFIG_AHS */
				add_value_from_ATE_cmd(&post, &last, "ATE Get_L2Ceiling", L2Ceiling[0]);
				add_value_from_ATE_cmd(&post, &last, "ATE Get_PwrCycleCnt", PwrCycleCnt[0]);
				add_value_from_ATE_cmd(&post, &last, "ATE Get_AvgUptime", AvgUptime[0]);
		}

			if(post != NULL)
				curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
			curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);

			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, check_CA); /* do not verify subject/hostname */
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, check_CA); /* since most certs will be self-signed, do not verify against CA */

			/* enable verbose for easier tracing */
			curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
			curl_easy_setopt(curl, CURLOPT_URL, url);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

			res = curl_easy_perform(curl);

			/* always cleanup */
			if(post != NULL)
				curl_formfree(post);
			curl_easy_cleanup(curl);
			if(fp != NULL)
				fclose(fp);

			if(res != CURLE_OK){
				FWUPDATE_DBG("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
				unlink(file_path);
				retry--;
				sleep(1);
			}
		}
	}
	curl_global_cleanup();

	return (res == CURLE_OK);
}

void store_ispinfo(char *jsonString)
{
	char path[] = "/tmp/webs_ispinfo.json";

	if((!jsonString)||(strlen(jsonString) == 0))
	{
		FWUPDATE_DBG("NULL or empty string.\n");
		return;
	}
	else
	{
		struct json_object *_ispinfo_obj = NULL;
		_ispinfo_obj = json_tokener_parse(jsonString);
		if(_ispinfo_obj)
		{
			struct json_object *part_array_obj = NULL;

			part_array_obj = json_object_array_get_idx(_ispinfo_obj, 0);
			if(part_array_obj)
			{
				unlink(path);
				json_object_to_file_ext(path, part_array_obj, JSON_C_TO_STRING_PRETTY);
				FWUPDATE_DBG("Extract ispinfo to [%s]\n", path);
			}
			else
			{
				FWUPDATE_DBG("Failed to extract JSON array.\n");
			}

			json_object_put(_ispinfo_obj);
		}
		else
		{
			FWUPDATE_DBG("Failed to parse JSON:<<<%s>>>\n", jsonString);
		}
	}
}


void set_ispinfo(char *jsonString)
{
	if((!jsonString)||(strlen(jsonString) == 0))
	{
		FWUPDATE_DBG("NULL or empty string.\n");
		return;
	}
	else
	{
		struct json_object *_ispinfo_obj = NULL;
		_ispinfo_obj = json_tokener_parse(jsonString);
		if(_ispinfo_obj)
		{
			struct json_object *part_array_obj = NULL;
			char key_buf[128] = {0};

			part_array_obj = json_object_array_get_idx(_ispinfo_obj, 0);

			/* JSON object traversal, "key" and "value" is declared in macro "json_object_object_foreach" so we don't have to declare them again. */
			if(part_array_obj)
			{
				json_object_object_foreach(part_array_obj, key, value)
				{
					memset(key_buf, 0, sizeof(key_buf));
					snprintf(key_buf, sizeof(key_buf), "webs_state_ispinfo_%s", key);
					nvram_set(key_buf, json_object_get_string(value));
				}
			}

			json_object_put(_ispinfo_obj);
		}
		else
		{
			FWUPDATE_DBG("Failed to parse JSON:<<<%s>>>\n", jsonString);
		}
	}
}

int
firmware_check_update_main(int argc, char *argv[])
{
	int pid = getPid_fromFile(FIRMWARE_CHECK_UPDATE_PID);
	char proc_pid_dir[32] = {0};

	snprintf(proc_pid_dir, sizeof(proc_pid_dir), "/proc/%d", pid);

	if(pid == -1 || !check_if_dir_exist(proc_pid_dir))
	{
		/* Write pid */
		char pid_t[8] = {0};
		snprintf(pid_t, sizeof(pid_t), "%d", getpid());
		f_write_string(FIRMWARE_CHECK_UPDATE_PID, pid_t, 0, 0);
		FWUPDATE_DBG("start firmware_check_update\n");
	}
	else
	{
		FWUPDATE_DBG("firmware_check_update is running. (pid:%d)\n", pid);
		return 0;
	}

	FILE *fp;
	time_t dt=0;
	time_t now = time(NULL);
	int ret=0, i=0, j=0, retry=0;
	int is_support_nt_center __attribute__((unused)) =0, is_fupgrade=0, do_upgrade=0, forsq=0, forbeta __attribute__((unused)) =0;
	unsigned long comp_firmver[2] __attribute__((unused)) ={0}, comp_buildno[2]={0}, comp_lextendno[2]={0}; //[0]: REQ [1]: general
	int fver_idx = 0;
	unsigned long comp_orig_firmver[4][2]={{0}};
	unsigned long orig_current_firmver[4]={0};
	char word[16] = {0}, *next = NULL;
	unsigned long req_firmver=0, req_buildno=0, req_lextendno=0, firmver=0, buildno=0, lextendno=0;
	char req_orig_firmver[16]={0}, orig_firmver[16]={0}, orig_current_firm[16]={0};
	char webs_update_ts[64]={0}, ts_plus_trigger[64]={0}, update_ts[16]={0}, origin_trigger[32]={0};
	char *update_ts_tmp = NULL, *origin_trigger_tmp = NULL;
	char target_url[256]={0}, releasenote_file0[2][256]={{0}};
	char current_firm_str[8]={0}, current_buildno[8]={0}, current_extendno_str[32]={0};
	char current_firm[8]={0}, current_extendno[16]={0};
	char *LANG=NULL;
	char model_name[32]={0}, req_commit_num[16]={0}, commit_num[16]={0};
	char url_dl[256]={0}, dfs[256]={0}, asusctrl_buf[256]={0}, force_lvl[8]={0}, chg_sku_buf[8]={0}, asusctrl_flag_erase_buf[16] = {0};
	char ispinfo[512] = {0};
	char txt_buf[1024]={0};
#ifdef RTCONFIG_ASUSCTRL
	int asus_ctrl_value = 0, asusctrl_flag_update = 0, asus_ctrl_erase = 0;
	char *tcode=NULL, *tcode_p=NULL, *tcode_p_str=NULL;
	char tcode_buf[16]={0}, asus_ctrl_str[8]={0};
#endif
	char webs_state_info[128]={0}, webs_state_REQinfo[128]={0};
	struct json_object *fw_update_obj = NULL;
	struct json_object *model_name_json = NULL, *req_firmver_json=NULL, *req_buildno_json=NULL, *req_lextendno_json=NULL, *req_commit_num_json=NULL;
	struct json_object *firmver_json=NULL, *buildno_json=NULL, *lextendno_json=NULL, *commit_num_json=NULL, *url_dl_json=NULL, *asusctrl_json=NULL, *force_lvl_json=NULL;
	struct json_object *req_orig_firmver_json=NULL, *orig_firmver_json=NULL;
	struct json_object *ispinfo_json = NULL, *chg_sku_json = NULL, *asusctrl_flag_erase_json = NULL;

	char dl_path_SQ[][80] = {{ 'h','t','t','p','s',':','/','/','d','l','c','d','n','e','t','s','.','a','s','u','s','.','c','o','m','/','p','u','b','/','A','S','U','S','/','L','i','v','e','U','p','d','a','t','e','/','R','e','l','e','a','s','e','/','W','i','r','e','l','e','s','s','_','S','Q','\0' }};
	char dl_path_info[][80] __attribute__((unused)) = {{ 'h','t','t','p','s',':','/','/','d','l','c','d','n','e','t','s','.','a','s','u','s','.','c','o','m','/','p','u','b','/','A','S','U','S','/','L','i','v','e','U','p','d','a','t','e','/','R','e','l','e','a','s','e','/','W','i','r','e','l','e','s','s','\0' }};
	char dl_path_file[][64] = {{ 'h','t','t','p','s',':','/','/','d','l','c','d','n','e','t','s','.','a','s','u','s','.','c','o','m','/','p','u','b','/','A','S','U','S','/','w','i','r','e','l','e','s','s','/','A','S','U','S','W','R','T','\0' }};
	char dl_path_FRS[][64] = {{ 'h','t','t','p','s',':','/','/','r','o','u','t','e','r','f','e','e','d','b','a','c','k','.','a','s','u','s','.','c','o','m','\0' }};
	char file_path[][32] = {{ '/','t','m','p','/','w','l','a','n','_','u','p','d','a','t','e','.','t','x','t','\0' }};
	char sq_filename[][20] = {{ 'S','Q','_','d','o','w','n','l','o','a','d','.','p','h','p','\0' }};
	char general_filename[][16] = {{ 'd','o','w','n','l','o','a','d','.','p','h','p','\0' }};
	char releasenote_path0[][32]= {{ '/','t','m','p','/','r','e','l','e','a','s','e','_','n','o','t','e','0','.','t','x','t','\0' }};

	strlcpy(webs_update_ts, nvram_safe_get("webs_update_ts"), sizeof(webs_update_ts));
	if (vstrsep(webs_update_ts, ">", &update_ts_tmp, &origin_trigger_tmp) == 2){
		if(isValidtimestamp_noletter(update_ts_tmp))
			strlcpy(update_ts, update_ts_tmp, sizeof(update_ts));
		strlcpy(origin_trigger, origin_trigger_tmp, sizeof(origin_trigger));
	}

	dt = now - safe_atoi(update_ts);
	FWUPDATE_DBG("now = %lu, update_ts = %s, dt = %ld", now, update_ts, dt);

	if(!strcmp(nvram_safe_get("webs_state_info"), "") || !strcmp(nvram_safe_get("webs_state_REQinfo"), "") || strcmp(origin_trigger, nvram_safe_get("webs_update_trigger")) || dt > 10800)
	{
		// inital nvram
		nvram_set("webs_state_update", "0");	//INITIALIZING
		nvram_set("webs_state_flag", "0");	//0: Don't do upgrade  1: New firmeware available  2: Do Force Upgrade
		nvram_set("webs_state_error", "0");
		nvram_set("webs_state_odm", "0");
		nvram_set("webs_state_url", "");
		nvram_set("webs_state_level", "0");
		nvram_set("webs_update_ts", "0");
#if RTCONFIG_ASUSCTRL
		nvram_set("webs_chg_sku", "0");
		nvram_set("webs_SG_mode", "0");
#endif
		// unlink("/tmp/webs_upgrade.log"); //clean log
		FWUPDATE_DBG("---- trigger from: (%s)!\n", nvram_safe_get("webs_update_trigger"));
		dbg("trigger from:%s\n", nvram_safe_get("webs_update_trigger"));
	}else{
		FWUPDATE_DBG("return Previous info");
		return 0;
	}

	is_support_nt_center = nvram_contains_word("rc_support", "nt_center");
	is_fupgrade = nvram_contains_word("rc_support", "fupgrade");
	forsq = nvram_get_int("apps_sq");
	forbeta = nvram_get_int("webs_update_beta");

	strlcpy(current_firm_str, nvram_safe_get("firmver"), sizeof(current_firm_str));
	strlcpy(current_buildno, nvram_safe_get("buildno"), sizeof(current_buildno));
	strlcpy(current_extendno_str, nvram_safe_get("extendno"), sizeof(current_extendno_str));

	strlcpy(current_firm, current_firm_str, sizeof(current_firm));
	strlcpy(orig_current_firm, current_firm_str, sizeof(orig_current_firm));

	if(First_Digit(atoi(current_firm))==7){	//To see v7 fw as general v3 fw, we replace 7.x.x.x with 3.x.x.x
		current_firm[0] = '3';	//it means new model for early testers to try(not in MP phase), with no official path firmware available yet.
		FWUPDATE_DBG("---- Change current firmver 1st char form7to3 :  %s ----", current_firm);
	}
	trim_dot(current_firm);
	sscanf(current_extendno_str, "%[^-]", current_extendno);

	if(forsq == 1){
		snprintf(target_url, sizeof(target_url), "%s/%s", dl_path_FRS[0], sq_filename[0]);
		FWUPDATE_DBG("---- update SQ for general %s/%s ----", dl_path_FRS[0], sq_filename[0]);
	}else if((forsq >= 2) && (forsq <= 9)){
		snprintf(target_url, sizeof(target_url), "%s/SQ%d_%s", dl_path_FRS[0], forsq, general_filename[0]);
		FWUPDATE_DBG("---- update SQ beta path for specific test %s/SQ%d_%s ----", dl_path_FRS[0], forsq, general_filename[0]);
	}else{
		snprintf(target_url, sizeof(target_url), "%s/%s", dl_path_FRS[0], general_filename[0]);
		FWUPDATE_DBG("---- update dl_path_info for general %s/%s ----", dl_path_FRS[0], general_filename[0]);
	}

	while(retry<3){
		curl_download_file(target_url, file_path[0], FRS_DL, 3, 1);
		fw_update_obj = json_object_from_file(file_path[0]);
		if(fw_update_obj){ //json
			FWUPDATE_DBG("---- download file format : json ----");
			FWUPDATE_DBG("Content of the control file: %s", json_object_to_json_string(fw_update_obj));
			if(json_object_object_get_ex(fw_update_obj, "model_name", &model_name_json))
				strlcpy(model_name, json_object_get_string(model_name_json), sizeof(model_name));
			if(json_object_object_get_ex(fw_update_obj, "req_firmver", &req_firmver_json))
				req_firmver = atoi(json_object_get_string(req_firmver_json));
			if(json_object_object_get_ex(fw_update_obj, "req_orig_firmver", &req_orig_firmver_json))
				strlcpy(req_orig_firmver, json_object_get_string(req_orig_firmver_json), sizeof(req_orig_firmver));
			if(json_object_object_get_ex(fw_update_obj, "req_buildno", &req_buildno_json))
				req_buildno = atoi(json_object_get_string(req_buildno_json));
			if(json_object_object_get_ex(fw_update_obj, "req_lextendno", &req_lextendno_json))
				req_lextendno = atoi(json_object_get_string(req_lextendno_json));
			if(json_object_object_get_ex(fw_update_obj, "req_commit_num", &req_commit_num_json))
				strlcpy(req_commit_num, json_object_get_string(req_commit_num_json), sizeof(req_commit_num));
			if(json_object_object_get_ex(fw_update_obj, "firmver", &firmver_json))
				firmver = atoi(json_object_get_string(firmver_json));
			if(json_object_object_get_ex(fw_update_obj, "orig_firmver", &orig_firmver_json))
				strlcpy(orig_firmver, json_object_get_string(orig_firmver_json), sizeof(orig_firmver));
			if(json_object_object_get_ex(fw_update_obj, "buildno", &buildno_json))
				buildno = atoi(json_object_get_string(buildno_json));
			if(json_object_object_get_ex(fw_update_obj, "lextendno", &lextendno_json))
				lextendno = atoi(json_object_get_string(lextendno_json));
			if(json_object_object_get_ex(fw_update_obj, "commit_num", &commit_num_json))
				strlcpy(commit_num, json_object_get_string(commit_num_json), sizeof(commit_num));
			if(json_object_object_get_ex(fw_update_obj, "url_dl", &url_dl_json))
				strlcpy(url_dl, json_object_get_string(url_dl_json), sizeof(url_dl));
			if(json_object_object_get_ex(fw_update_obj, "asusctrl", &asusctrl_json))
				strlcpy(asusctrl_buf, json_object_get_string(asusctrl_json), sizeof(asusctrl_buf));
			if(json_object_object_get_ex(fw_update_obj, "force_lvl", &force_lvl_json))
				strlcpy(force_lvl, json_object_get_string(force_lvl_json), sizeof(force_lvl));
			if(json_object_object_get_ex(fw_update_obj, "ISPInfo", &ispinfo_json))
				strlcpy(ispinfo, json_object_to_json_string_ext(ispinfo_json, JSON_C_TO_STRING_PLAIN), sizeof(ispinfo));
			if(json_object_object_get_ex(fw_update_obj, "chg_sku", &chg_sku_json))
				strlcpy(chg_sku_buf, json_object_get_string(chg_sku_json), sizeof(chg_sku_buf));
			if(json_object_object_get_ex(fw_update_obj, "asusctrl_flag_erase", &asusctrl_flag_erase_json))
				strlcpy(asusctrl_flag_erase_buf, json_object_get_string(asusctrl_flag_erase_json), sizeof(asusctrl_flag_erase_buf));
		}
		else //txt
		{
			FWUPDATE_DBG("---- download file format  : txt ----");
			if ((fp = fopen(file_path[0], "r")) != NULL) {
				if(fread(txt_buf, 1, sizeof(txt_buf), fp))
				{
					FWUPDATE_DBG("Content of the control file: %s", txt_buf);
					if(strstr(txt_buf, "#REQFW") == NULL || strstr(txt_buf, "#FW") == NULL || strstr(txt_buf, "#DFS") == NULL){
						FWUPDATE_DBG("---- txt_buf : content error ----");
					}
					else
					{
						sscanf(txt_buf, "%20[^#]#REQFW%lu_%lu_%lu-%[^#]#FW%lu_%lu_%lu-%[^#]#%[^#]#DFS%[^#]#LV%[^#]", model_name, &req_firmver, &req_buildno, &req_lextendno, req_commit_num, &firmver, &buildno, &lextendno, commit_num, url_dl, dfs, force_lvl);
					}
				}
				fclose(fp);
			}
		}

		if(firmver == 0 && buildno== 0 && lextendno== 0){
			FWUPDATE_DBG("---- no Info in file : retry %d ----", retry);
			sleep(1);
			retry++;
			continue;
		}

#ifdef RTCONFIG_ASUSCTRL
		strlcpy(tcode_buf, nvram_safe_get("territory_code"), sizeof(tcode_buf));
		tcode = strtok(tcode_buf,"/");
		if(strlen(asusctrl_buf)>0 && tcode != NULL){
			if((tcode_p=strstr(asusctrl_buf, tcode)) != NULL){
				tcode_p_str = strtok(tcode_p+2,"_");
				strlcpy(asus_ctrl_str, tcode_p_str, sizeof(asus_ctrl_str));
				asus_ctrl_sku_write(chg_sku_buf);
				asus_ctrl_write(asus_ctrl_str);
				asus_ctrl_value = strtol(asus_ctrl_str, NULL, 16);
				if(((asus_ctrl_value &(0x1 << ASUSCTRL_CHG_SKU)) && chg_sku_buf[0] != '\0')
				|| ((asus_ctrl_value&(0x1 << ASUSCTRL_CHG_SKU)) == 0 && chg_sku_buf[0] == '\0'))
					ASUSCTRL_ACTION_SET(asusctrl_flag_update, ASUSCTRL_CHG_SKU);
			}
			asus_ctrl_erase = strtol(asusctrl_flag_erase_buf, NULL, 16);
			ASUSCTRL_ACTION_CLR(asusctrl_flag_update, asus_ctrl_erase);
			nvram_set_hex("asusctrl_flag_update", asusctrl_flag_update);
		}else if(strlen(dfs)>0 && tcode != NULL){
			if((tcode_p=strstr(dfs, tcode)) != NULL){
				asus_ctrl_value = nvram_get_hex("asusctrl_flags");

				if(atoi(tcode_p+2)&ASUSCTRL_DFS_BAND2)
					asus_ctrl_value = (asus_ctrl_value | 1<<ASUSCTRL_DFS_BAND2);
				else
					asus_ctrl_value = (asus_ctrl_value & ~(1<<ASUSCTRL_DFS_BAND2));

				if(atoi(tcode_p+2)&ASUSCTRL_DFS_BAND3)
					asus_ctrl_value = (asus_ctrl_value | 1<<ASUSCTRL_DFS_BAND3);
				else
					asus_ctrl_value = (asus_ctrl_value & ~(1<<ASUSCTRL_DFS_BAND3));

				snprintf(asus_ctrl_str, sizeof(asus_ctrl_str), "0x%d", asus_ctrl_value);
				asus_ctrl_write(asus_ctrl_str);
			}
		}
#endif
		FWUPDATE_DBG("---- current version : %s %s %s %s %s----", model_name, current_firm, orig_current_firm, current_buildno, current_extendno);
		FWUPDATE_DBG("---- REQproductid : %s %lu %s %lu %lu----", model_name, req_firmver, req_orig_firmver, req_buildno, req_lextendno);
		FWUPDATE_DBG("---- productid : %s %lu %s %lu %lu----", model_name, firmver, orig_firmver, buildno, lextendno);
		comp_firmver[0] = req_firmver;
		comp_buildno[0] = req_buildno;
		comp_lextendno[0] = req_lextendno;
		comp_firmver[1] = firmver;
		comp_buildno[1] = buildno;
		comp_lextendno[1] = lextendno;

		/* req_orig_firmver */
		__foreach(word, req_orig_firmver, next, "."){
			if(fver_idx > sizeof(comp_orig_firmver)/sizeof(comp_orig_firmver[0])-1) break;
			comp_orig_firmver[fver_idx++][0] = safe_atoi(word);
		}

		/* orig_firmver */
		fver_idx = 0;
		__foreach(word, orig_firmver, next, "."){
			if(fver_idx > sizeof(comp_orig_firmver)/sizeof(comp_orig_firmver[0])-1) break;
			comp_orig_firmver[fver_idx++][1] = safe_atoi(word);
		}

		/* orig_current_firm */
		fver_idx = 0;
		__foreach(word, orig_current_firm, next, "."){
			if(fver_idx > sizeof(orig_current_firmver)/sizeof(orig_current_firmver[0])-1) break;
			orig_current_firmver[fver_idx++] = safe_atoi(word);
		}

		snprintf(webs_state_info, sizeof(webs_state_info), "%lu_%lu_%lu-%s", firmver, buildno, lextendno, commit_num);
		snprintf(webs_state_REQinfo, sizeof(webs_state_REQinfo), "%lu_%lu_%lu-%s", req_firmver, req_buildno, req_lextendno, req_commit_num);
		nvram_set("webs_state_info", webs_state_info);
		nvram_set("webs_state_REQinfo", webs_state_REQinfo);
		nvram_set("webs_state_odm", model_name);
		nvram_set("webs_state_level", force_lvl);

		//store ispinfo into /tmp
		store_ispinfo(ispinfo);
#if 0
		//store ispinfo into nvram, parse its elements, and store these elements into nvram.
		nvram_set("webs_state_ispinfo", ispinfo);

		set_ispinfo(ispinfo);
#endif

		snprintf(ts_plus_trigger, sizeof(ts_plus_trigger), "%ld>%s", now, nvram_safe_get("webs_update_trigger"));
		nvram_set("webs_update_ts", ts_plus_trigger);
		nvram_set("webs_update_trigger","");

		if(!strncmp(url_dl, "http", 4))
			nvram_set("webs_state_url", url_dl);
		
		for(i=0; i<2 && do_upgrade==0; i++){	// 0: Force Upgrade   1: Upgrade
			if(is_fupgrade==0 && i==0) continue; //dont check fupgrade

			if(comp_orig_firmver[1][i] > orig_current_firmver[1]){
				do_upgrade =  1; //Do Upgrade
				FWUPDATE_DBG("---- < %sfirmver2 ----", (i==0)?"REQ":"");
			}
			else if(comp_orig_firmver[1][i] == orig_current_firmver[1]){
				if(comp_orig_firmver[2][i] > orig_current_firmver[2]){
					do_upgrade =  1; //Do Upgrade
					FWUPDATE_DBG("---- < %sfirmver3 ----", (i==0)?"REQ":"");
				}
				else if(comp_orig_firmver[2][i] == orig_current_firmver[2]){
					if(comp_orig_firmver[3][i] > orig_current_firmver[3]){
						do_upgrade =  1; //Do Upgrade
						FWUPDATE_DBG("---- < %sfirmver4 ----", (i==0)?"REQ":"");
					}
					else if(comp_orig_firmver[3][i] == orig_current_firmver[3]){
						if(comp_buildno[i] > atoi(current_buildno)){
							do_upgrade =  1; //Do Upgrade
							FWUPDATE_DBG("---- < %sbuildno ----", (i==0)?"REQ":"");
						}
						else if(comp_buildno[i] == atoi(current_buildno)){
							if(comp_lextendno[i] > atoi(current_extendno)){
								do_upgrade =  1; //Do Upgrade
								FWUPDATE_DBG("---- < %slextendno ----", (i==0)?"REQ":"");
							}
						}
					}
				}
			}

			if(do_upgrade == 1){
				switch(i){
					case 0:	// Do Force Upgrade
						nvram_set("webs_state_flag", "2");
						FWUPDATE_DBG("---- Do Force Upgrade ----");
						break;
					case 1: // Do Upgrade
						nvram_set("webs_state_flag", "1");
						FWUPDATE_DBG("---- Do Upgrade ----");
						break;
				}
			}
		}
		break;
	}

	if(retry==3){
		nvram_set("webs_state_error", "1");
		FWUPDATE_DBG("---- no Info in file : retry finish ----");
	}
#ifdef RTCONFIG_ASD
	else
	{
		unlink(asd_json_log_path[0]);
	}
#endif

	/* download release note */
	if(firmver == 0 && buildno== 0 && lextendno== 0){
		FWUPDATE_DBG("---- no Info in file : skip download release note ----");
	}else{

		LANG = nvram_safe_get("preferred_lang");

		snprintf(releasenote_file0[0], sizeof(releasenote_file0[0]), "%s_%s_%s_note.zip", model_name, nvram_safe_get("webs_state_info"), LANG);
		snprintf(releasenote_file0[1], sizeof(releasenote_file0[1]), "%s_%s_US_note.zip", model_name, nvram_safe_get("webs_state_info"));

		while(ret !=1 && j < (sizeof(releasenote_file0)/sizeof(releasenote_file0[0]))){
			if(forsq == 1){
				snprintf(target_url, sizeof(target_url), "%s/%s", dl_path_SQ[0], releasenote_file0[j]);
				FWUPDATE_DBG("---- download SQ release note %s/%s ----", dl_path_SQ[0], releasenote_file0[j]);
			}else if((forsq >= 2) && (forsq <= 9)){
				snprintf(target_url, sizeof(target_url), "%s/app%d/%s", dl_path_SQ[0], forsq, releasenote_file0[j]);
				FWUPDATE_DBG("---- download release note from beta path for specific test %s/app%d/%s ----", dl_path_SQ[0], forsq, releasenote_file0[j]);
			}else{
				snprintf(target_url, sizeof(target_url), "%s/%s", dl_path_file[0], releasenote_file0[j]);
				FWUPDATE_DBG("---- download real release note %s/%s ----", dl_path_file[0], releasenote_file0[j]);
			}

			ret = curl_download_file(target_url, releasenote_path0[0], COMMON_DL, 1, 0);
			j++;
		}
	}

	if(fw_update_obj)
		json_object_put(fw_update_obj);

	nvram_set("webs_state_update", "1");
	nvram_commit();
	FWUPDATE_DBG("---- firmware check update finish ----");
	unlink(FIRMWARE_CHECK_UPDATE_PID);
	return ret;
}
#endif
