#define _GNU_SOURCE

#include <stdio.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <time.h>
#include <rc.h>
#include <stdlib.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <utils.h>
#include <dirent.h>
#ifdef RTCONFIG_USB
#include <disk_io_tools.h>
#endif
#include <curl/curl.h>
#ifdef RTCONFIG_HTTPS
#include <openssl/md5.h>
#endif
#ifndef MUSL_LIBC
#include <math.h>
#endif	// !MUSL_LIBC
#ifdef HND_ROUTER
#include "shared.h"
#endif

#define DUP_LOG_PATH "/tmp/asusfbsvcs/duplicate_log"
#define SYSLOG_FILE "syslog.log"
#define SYSLOG_1_FILE "syslog.log-1"
#define FB_FILE "/tmp/xdslissuestracking"
#define FB_FILE_WEB "/tmp/xdslissuestracking_web"
#define TOP_FILE "/tmp/top.txt"
#define FREE_FILE "/tmp/free.txt"
#define IPKG_APP_FILE "/tmp/ipkgapp.txt"
#define IPKG_CONTROL_FILE "/tmp/ipkg_control.tgz"
#define IPTABLES_FILE "/tmp/fb_iptables.txt"
#define CFE_FILE "/tmp/cfe.gz"
#define MODEMLOG_FILE "/tmp/modemlog.txt"
#define WLANLOG_FILE "/tmp/wlanlog.txt"
#define WANENV_FILE "/tmp/wan.env.tgz"
#define IPV6_FILE "/tmp/ipv6.txt"
#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114)
#define TRAP_LOG_PATH "/tmp/asusfbsvcs/trap_log"
#endif /* HND_ROUTER || RTCONFIG_BCM_7114 */
#ifdef RTCONFIG_BCM_HND_CRASHLOG
#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2)
#define CRASHLOG_FILE "/jffs/crashlog.log"
#else
#define CRASHLOG_FILE "/tmp/crashlog.log"
#endif
#endif /* RTCONFIG_BCM_HND_CRASHLOG */
#if defined(RTCONFIG_DPSTA)
#define DPSTA_FILE "/tmp/dpsta.log"
#endif

#ifdef RTCONFIG_DBLOG
#define DBLOG_CONTENT "/tmp/dblogmailcontent"
#endif /* RTCONFIG_DBLOG */

#ifdef RTCONFIG_SYSSTATE
#define CPUUSAGE_FILE "/tmp/asusfbsvcs/cpuusage_log.txt"
#define RAMUSAGE_FILE "/tmp/asusfbsvcs/ramusage_log.txt"
#define CPUTEMP_FILE "/tmp/asusfbsvcs/cputemp_log.txt"
#endif /* RTCONFIG_SYSSTATE */

#ifdef RTCONFIG_CFGSYNC
#define CFGMNT_FILE "/tmp/cfgmnt_log.txt"
#if (defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS))
#define CFG_DBG_LOG	"/jffs/.sys/cfg_mnt/cfg_dbg.log"
#define CFG_DBG_LOG_1	"/jffs/.sys/cfg_mnt/cfg_dbg.log-1"
#else
#define CFG_DBG_LOG	"/tmp/cfg_mnt/cfg_dbg.log"
#define CFG_DBG_LOG_1	"/tmp/cfg_mnt/cfg_dbg.log-1"
#endif
#define CFG_DBG_FILE "cfg_dbg.log"
#endif

#ifdef RTCONFIG_AHS
#define AHS_LOG_FILE   "ahs.log"
#define AHS_LOG_1_FILE   "ahs.log.1"
#define AHS_DUMP_FILE  "/tmp/ahs_dump.txt"
#define AHS_JSON_FILE  "/tmp/decjsonfile.txt"
#define AHS_JSONOBJ_FILE  "/tmp/decjsonobj.txt"
#define AHS_LOG_IN_JFFS_FILE "ahs_jffs.log"
#define AHS_LOG_IN_JFFS_1_FILE "ahs_jffs.log.1"
//Macro AHS_HWSW_ST_JFFS_FILE is defined in rc.h
#endif /* RTCONFIG_AHS */

#define TIMEOUT_TCPCHECK 3

#ifdef RTCONFIG_ASD
#define ASD_LOG_PATH	"asd.log"
#define ASD_BK_LOG_PATH	"asd.log.1"
#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || \
    defined(RTCONFIG_YAFFS) || \
    defined(RTCONFIG_UBIFS)
#define ASD_BK_DIR	"/jffs/.asdbk"
#else
#define ASD_BK_DIR	"/tmp/.asdbk"
#endif
#define ASD_BK_NAME	"asdbk.tar.gz"
#endif

#ifdef RTCONFIG_FSMD
#define JFFS_USAGE_FILE "/tmp/jffs_usage.txt"
#endif

#ifdef RTCONFIG_SOFTWIRE46
#define S46_LOG_FILE	"s46.log"
#define S46_LOG_1_FILE	"s46.log.1"
#endif

#define WGET_LOG_PATH	"wglst"
#define WGET_BK_LOG_PATH		"wglst.1"

#define JFFS_LOG "jffs_log.txt"
#define TMP_LOG "tmp_log.txt"
#define CONN_DIAG_LOG_SRC_FOLDER ".diag"
#define CONN_DIAG_LOG_DST_FOLDER "conn_diag_log"

#define SWITCH_LOG	"switch.log"
#define WIFI_AP_STATS_LOG	"wifi_ap_stats.log"
#define WIFI_STA_STATS_LOG	"wifi_sta_stats.log"
#define HOSTAPD_LOG	"hostapd.log"

#ifdef RTCONFIG_DSL
#define SYNC_STATUS_FILE "sync_status_log.txt"
#define INFO_ADSL_FILE "info_adsl.txt"
#endif /* RTCONFIG_DSL */

#ifdef RTCONFIG_BWDPI
#define BWDPI_SIG_UPG_LOG "sig_upgrade.log"
#endif /* RTCONFIG_BWDPI */

#define TIMEOUT_TCPCHECK 3
#define SENDOUT_LIMIT 10
#define MAIL_ADDR_LEN 32
#define ALGOVERSION 1

#define MAX_BUF_LEN 2048

#ifdef RTCONFIG_LANTIQ
#define WIFI_DB1_FILE "/tmp/jffs.tgz"
#define WIFI_DB2_FILE "/tmp/wlan_wave.tgz"
#define WIFI_DB3_FILE "/tmp/wlanconfs.tgz"
#define WIFI_DB3_FILE_LIST "db/default db/instance confs"
#endif

//log for site survey
//path=/jffs/.sys/amas/amas_ssd_dbg.log
//path=/jffs/.sys/amas/amas_ssd_dbg.log-1
#define JFFS_AMAS_SITE_SURVEY_LOG "amas_ssd_dbg.log"
#define JFFS_AMAS_SITE_SURVEY_1_LOG "amas_ssd_dbg.log-1"

//log for connection
//path=/jffs/amas_wlcconnect.log
//path=/jffs/amas_wlcconnect.log-1
#define JFFS_AMAS_WLCCONNECT_LOG "amas_wlcconnect.log"
#define JFFS_AMAS_WLCCONNECT_1_LOG "amas_wlcconnect.log-1"

#ifdef RTCONFIG_UPNPC_NEW
#define IPSEC_UPNPC_LIST "upnpclist"
#define IPSEC_UPNPC_WDG_LIST "upnpclist.wdg"
#endif /* RTCONFIG_UPNPC_NEW */

//path=/var/lib/misc
#define DHCP_LEASES_FILE "dnsmasq.leases"
//path=/tmp/arp.txt
#define ARP_OUTPUT_FILE "arp.txt"

//path=/tmp/asusdebuglog/cfg_abl.log
#define AMAS_AVBLCHAN_LOG "cfg_abl.log"

//path=/jffs/HTTPD_FB_DEBUG.log
#define DUT_HTTPD_FB_DEBUG "/jffs/HTTPD_FB_DEBUG.log"
#define DUT_HTTPD_FB_DEBUG_1 "/jffs/HTTPD_FB_DEBUG.log-1"

/* For Broacom based models */
#if defined(RTCONFIG_BCMARM) || defined(RTCONFIG_BCM7) || defined(RTCONFIG_BCM_794) \
	|| defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM10) || defined(RTCONFIG_BCMWL6) \
	|| defined(RTCONFIG_BCMWL6A) || defined(HND_ROUTER)
	#define BRCM_BASED_MODELS
#else
	#undef BRCM_BASED_MODELS
#endif /* For Broacom based models */

#define FB_TMP_TARBALL "/tmp/fb_data_tmp.tgz"
#define FB_TARBALL "/tmp/fb_data.tgz"
#define BINARY_KEYWORD "EnCrYpTBinFIle"

#if defined(RTCONFIG_BCMARM)
#if defined(HND_ROUTER)
#define PROC_ENTRY_CPUTEMP "/sys/class/thermal/thermal_zone0/temp"
#else /* For BCM470x series */
#define PROC_ENTRY_CPUTEMP "/proc/dmu/temperature"
#endif
#endif /* RTCONFIG_BCMARM */

#define adjustEndian(num) do{num = (((num)>>24) & 0x000000FF) | (((num)<<8) & 0x00FF0000) | (((num)>>8) & 0x0000FF00) | (((num)<<24) & 0xFF000000);}while(0)

#define ASH_HISTORY ".ash_history"
#define CMD_HISTORY "cmd_history.txt"

typedef struct email_auth_data_s{
	char mailServer[32];
	char email[MAIL_ADDR_LEN];
	char acct[32];
	char pwd[32];
}email_auth_data_t;

typedef struct binfile_header_s{
	char productName[16];
	char keyWord[16];  //encryptBinfile
	unsigned long fileLength;
	unsigned int rand;
}binfile_header_t;

/* Global variables */
int current_time[2]={0};
int pre_time[2]={0};
int send_count = 0;

/* Function declaration */
void getUsageStatus(FILE *fp);
void getinfo_transfer_mode(FILE *fp);
int countChar(char *str, char c);

#if defined(RTCONFIG_BCM_7114) || (defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX))
#define SPECIAL_DATA_LEN 20
char* get_encrypt_wifi_status(char *buffer, size_t size);
#endif

#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX) && !defined(RTCONFIG_MFGFW)
void get_bcm4366_PCI_probe_state(FILE *fp, char *result, size_t size);
#endif

#if defined(RTAX88U)
#define PCIE_DATA_LEN 4
char *get_encrypt_pcie_status(char *buffer, size_t size);
#endif

unsigned char get_rand();
unsigned long readFileSize( char *filepath );
int encryptBinaryfile(char *src, char *dst, char *productName);

#ifdef RTCONFIG_DBLOG
void start_dblog(int option);
void stop_dblog(void);
#define DBLOG_ENABLE_DHD (1 << 4)
#endif /* RTCONFIG_DBLOG */

#ifdef RTCONFIG_SYSSTATE
void dump_sysstate_logs(void)
{
	system("asuslog dumplog");
}
#endif /* RTCONFIG_SYSSTATE */

#if defined(RTCONFIG_JFFS_NVRAM) && defined(DSL_AC68U)
//exclude those nvram in jffs
extern int dev_nvram_getall(char *buf, int count);
#define nvram_getall_excl_jffs(param1, param2) dev_nvram_getall(param1, param2)
#else
#define nvram_getall_excl_jffs(param1, param2) nvram_getall(param1, param2)
#endif

static int _dec_asd_log(const char *log_path, const char *dec_path);

/*******************************************************************
* NAME: send_feedback_curl
* AUTHOR: Renjie Lee
* CREATE DATE: 2019/06/13
* DESCRIPTION: Send feedback via libcurl (HTTPS)
* INPUT:  log_from: str: 'feedback' or a 'System Diagnostic' or 'Diagnostic Log'.
*             feedback_file: the feedback content.
*             attach_cmd: attached files. (format:-a file1 -a file2 -a file3)
* OUTPUT:
* RETURN:  0: success, others(>0): failed
* NOTE:
*******************************************************************/
int send_feedback_curl(char *log_from, const char *feedback_file, char *attach_cmd)
{
	CURL *curl;
	CURLcode res = CURLE_FAILED_INIT;
	struct curl_httppost *post = NULL;
	struct curl_httppost *last = NULL;
	double average_speed = 0;
	double bytes_uploaded = 0;
	double total_upload_time = 0;
	unsigned char mac_digest[16], session_buf[10];
	char name[64], value[64], file[MAX_BUF_LEN], *ptr;
	FILE *fp;
	struct {
		char *memory;
		size_t size;
	} resp;
	int i, j = 0;

	char hidden_strs[][64] = {
		{'l', 'a', 'b', 'e', 'l', '_', 'm', 'a', 'c', '\0'},
		{'f', 'b', '_', 'e', 'm', 'a', 'i', 'l', '_', 'd', 'b', 'g', '\0'},
		{'d', 'e', 'b', 'u', 'g', '_', 'e', 'm', 'a', 'i', 'l', '\0'},
		{'s', 'e', 's', 's', 'i', 'o', 'n', '\0'},
		{'A', 'l', 'g', 'o', 'V', 'e', 'r', 's', 'i', 'o', 'n', '\0'},
		{'l', 'o', 'g', '_', 'f', 'r', 'o', 'm', '\0'},
		{'u', 's', 'e', 'r', 'n', 'a', 'm', 'e', '\0'},
		{'a', 'd', 'm', 'i', 'n', 'f', 'b', 's', 'e', 'r', 'v', 'e', 'r', '\0'},
		{'p', 'a', 's', 's', 'w', 'd', '\0'},
		{'l', 'i', 'f', 'e', 'i', 's', 'h', 'a', 'r', 'd', 'e', 'n', 'o', 'u', 'g', 'h', '#', '#', '1', '2', '3', '4', '@', 'f', 'b', 's', 'v', 'r', '.', 'c', 'o', 'm', '\0'},
		{'m', 'o', 'd', 'e', 'l', 'n', 'a', 'm', 'e', '\0'},
		{'F', 'W', 'V', 'E', 'R', '\0'},
		{'I', 'D', 'E', 'N', 'T', '\0'},
		{'u', 's', 'e', 'r', 'e', 'm', 'a', 'i', 'l', '\0'},
		{'u', 'p', 'l', 'o', 'a', 'd', 'f', 'i', 'l', 'e', '\0'},
		{'h', 't', 't', 'p', 's', ':', '/', '/', 'r', 'o', 'u', 't', 'e', 'r', 'f', 'e', 'e', 'd', 'b', 'a', 'c', 'k', '.', 'a', 's', 'u', 's', '.', 'c', 'o', 'm', '/', 'u', 'p', 'l', 'o', 'a', 'd', '.', 'p', 'h', 'p', '\0'}
	};
	enum {
		LABEL_MAC = 0,
		FB_EMAIL_DBG,
		DEBUG_EMAIL,
		SESSION,
		ALGOVER,
		LOG_FROM,
		USERNAME,
		UNAME,
		PASSWD,
		PWD,
		MODELNAME,
		FWVER,
		IDENT,
		USEREMAIL,
		UFILE,
		TARGET_URL
	};

	curl = curl_easy_init();
	if (curl) {
		snprintf(name, sizeof(name), "%s", hidden_strs[LABEL_MAC]);
		ptr = nvram_safe_get(name); /* why not use get_label_mac()? */
#ifdef RTCONFIG_HTTPS
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, ptr, strlen(ptr));
		MD5_Final(mac_digest, &ctx);
#endif

		memset(session_buf, 0, sizeof(session_buf));
		if ((fp = fopen("/dev/urandom", "r")) != NULL) {
			fread(session_buf, 1, sizeof(session_buf), fp);
			fclose(fp);
		}

		snprintf(name, sizeof(name), "%s", hidden_strs[DEBUG_EMAIL]);
		snprintf(value, sizeof(value), "%s", hidden_strs[FB_EMAIL_DBG]);
		if (!nvram_match(value, "")) {
			curl_formadd(&post, &last,
				CURLFORM_COPYNAME, name,
				CURLFORM_COPYCONTENTS, nvram_safe_get(value),
				CURLFORM_END);
		}

		snprintf(name, sizeof(name), "%s", hidden_strs[SESSION]);
		for (i = 0; i < sizeof(session_buf); i++)
			sprintf(&value[i*2], "%02x", session_buf[i]);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[ALGOVER]);
		snprintf(value, sizeof(value), "Ver%04d", ALGOVERSION);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[LOG_FROM]);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, log_from,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[USERNAME]);
		snprintf(value, sizeof(value), "%s", hidden_strs[UNAME]);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[PASSWD]);
		snprintf(value, sizeof(value), "%s", hidden_strs[PWD]);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[MODELNAME]);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, nvram_safe_get("productid"),
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[FWVER]);
		snprintf(value, sizeof(value), "%s.%s_%s",
			 nvram_safe_get("firmver"), nvram_safe_get("buildno"), nvram_safe_get("extendno"));
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[IDENT]);
		for (i = 0; i < sizeof(mac_digest); i++)
			sprintf(&value[i*2], "%02x", mac_digest[i]);
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[USEREMAIL]);
		if (strchr(nvram_safe_get("fb_email"), '`') == NULL)
			snprintf(value, sizeof(value), "%s", nvram_safe_get("fb_email"));
		else
			snprintf(value, sizeof(value), "%s", "email_format_error@attack.com");
		curl_formadd(&post, &last,
			CURLFORM_COPYNAME, name,
			CURLFORM_COPYCONTENTS, value,
			CURLFORM_END);

		snprintf(name, sizeof(name), "%s", hidden_strs[UFILE]);
		if (check_if_file_exist(feedback_file)) {
			snprintf(value, sizeof(value), "%s[%d]", name, j++);
			curl_formadd(&post, &last,
				CURLFORM_COPYNAME, value,
				CURLFORM_FILE, feedback_file,
				CURLFORM_END);
		}
		foreach (file, attach_cmd, ptr) {
			if ((strstr(file, "-a")) == NULL && check_if_file_exist(file)) {
				snprintf(value, sizeof(value), "%s[%d]", name, j++);
				curl_formadd(&post, &last,
					CURLFORM_COPYNAME, value,
					CURLFORM_FILE, file,
					CURLFORM_END);
			}
		}

		/* upload to this place */
		snprintf(value, sizeof(value), "%s", hidden_strs[TARGET_URL]);
		curl_easy_setopt(curl, CURLOPT_URL, value);

		curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);

		curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1); /* verify subject/hostname */

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1); /* verify against CA */

		/* enable verbose for easier tracing */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

		/* complete connection within 10 seconds */
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

		/* complete within 120 seconds */
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

		/* set callback function to read server response */
		memset(&resp, 0, sizeof(resp));
		fp = open_memstream(&resp.memory, &resp.size);
		if (fp)
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)fp);

		res = curl_easy_perform(curl);

		if (fp)
			fclose(fp);

		/* Check for errors */
		if (res == CURLE_OK) {
			dbg("resp=[%s]\n", (resp.memory && resp.size) ? trimNL(resp.memory) : "");
			if (resp.memory && resp.size && strstr(resp.memory, "Upload successfully")) {
				curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &average_speed);
				curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD, &bytes_uploaded);
				curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_upload_time);
				logmessage("frs_feedback", "Transfer rate: %.0f KB/sec (%.0f bytes in %.0f seconds)",
					average_speed / 1024, bytes_uploaded, total_upload_time);
				dbg("Transfer rate: %.0f KB/sec (%.0f bytes in %.0f seconds)\n",
					average_speed / 1024, bytes_uploaded, total_upload_time);
			} else {
				/* 'Failed to upload' or others */
				res = CURLE_HTTP_RETURNED_ERROR;
				logmessage("frs_feedback", "curl_easy_perform() failed: CURLE_HTTP_RETURNED_ERROR\n");
			}
		} else {
			dbg("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			logmessage("frs_feedback", "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}

		/* always cleanup */
		curl_formfree(post);
		curl_easy_cleanup(curl);
		free(resp.memory);
	}

	return res;
}

int send_feedback_curl_retry(char *log_from, const char *feedback_file, char *attach_cmd, int retry)
{
	int retval = CURLE_FAILED_INIT;
	int connectivity_to_server = -1;
	char hidden_strs[][64] = {
		{'r', 'o', 'u', 't', 'e', 'r', 'f', 'e', 'e', 'd', 'b', 'a', 'c', 'k', '.', 'a', 's', 'u', 's', '.', 'c', 'o', 'm', ':', '4', '4', '3', '\0'}
	};

	if(log_from && feedback_file && attach_cmd &&(retry > 0))
	{
		retval = send_feedback_curl(log_from, feedback_file, attach_cmd);
		while((retry > 0) && (retval != CURLE_OK))
		{
			connectivity_to_server = tcpcheck_retval(TIMEOUT_TCPCHECK, hidden_strs[0]);
			dbg("[retry-%d]connectivity_to_server=%d\n", retry, connectivity_to_server);
			logmessage("frs_feedback", "[retry-%d]connectivity_to_server=%d\n", retry, connectivity_to_server);
			if(connectivity_to_server == 0)
			{
				retval = send_feedback_curl(log_from, feedback_file, attach_cmd);
				if(retval == CURLE_OK)
				{
					break;
				}
			}
			retry--;
			sleep(3);
			retval = send_feedback_curl(log_from, feedback_file, attach_cmd);
		}
	}
	return retval;
}

int do_feedback(const char* feedback_file, char* attach_cmd)
{
	int retval = CURLE_FAILED_INIT;
	char log_from[32]={0};

#ifdef RTCONFIG_DBLOG
	if((nvram_get_int("dblog_enable") == 1) || (strncmp(feedback_file, DBLOG_CONTENT, strlen(DBLOG_CONTENT)) == 0)){
		snprintf(log_from, sizeof(log_from), "System Diagnostic");
	}
	else
#endif
	{
		snprintf(log_from, sizeof(log_from), "feedback");
	}

	retval = send_feedback_curl_retry(log_from, feedback_file, attach_cmd, 5);
	logmessage("frs_feedback", "retval = [%d], log_from=[%s]\n", retval, log_from);
	return (retval == CURLE_OK); //CURLE_OK = 0
}

unsigned int accumulate_file_size(char *cmd, size_t _size)
{
	char *substr = NULL;
	const char * const delim = "- ";
	char *buf = NULL;
	struct stat st;
	int ret = -1;
	unsigned int total_size = 0;

	buf = (char *) malloc(_size * sizeof(char));
	if(buf)
	{
		if(cmd && (_size > 0))
		{
			snprintf(buf, _size, "%s", cmd);
			substr = strtok(buf, delim);
			while (substr != NULL)
			{
				if(strcmp(substr, "a") == 0)
				{
					substr = strtok(NULL, delim);
					continue;
				}
				else
				{
					memset(&st, 0, sizeof(struct stat));
					ret = stat(substr, &st);
					if((ret != -1) && (st.st_size > 0))
					{
						total_size += st.st_size;
					}
					substr = strtok(NULL, delim);
				}
			}
			cprintf("accumulate_file_size=[%d]\n", total_size);
		}
		else
		{
			cprintf("cmd=[%s]\n", cmd);
		}
		free(buf);
	}

	return total_size;
}

void get_client_info(void)
{
	int wait_time = 5;

	kill_pidfile_s("/var/run/networkmap.pid", SIGUSR1);

	nvram_set("fb_nmp_scan", "1");

	while((!nvram_match("fb_nmp_scan", "0")) && (wait_time--))
	{
		//wait here
		cprintf("[get_client_info][1]wait networkmap scanning...\n");
		sleep(1);
	}

	sleep(1);

	/* update networkmap twice to get more complete information */
	kill_pidfile_s("/var/run/networkmap.pid", SIGUSR1);

	nvram_set("fb_nmp_scan", "1");

	wait_time = 5;
	while((!nvram_match("fb_nmp_scan", "0")) && (wait_time--))
	{
		//wait here
		cprintf("[get_client_info][2]wait networkmap scanning...\n");
		sleep(1);
	}
}

#ifdef RTAC86U
int pa_defect_detect(FILE *fp, int retry)
{
	FILE *cmd_pipe = NULL;
	char buf[128] = {0}, tmp[4] = {0};
	char cr_tmp[4][8] = {{0}}, la_tmp[4][8] = {{0}};
	float current_rate[4] = {0}, last_adj[4] = {0};
	char word[256], *next, ifnames[128];
	int debug_wl = nvram_get_int("debug_wl"), dy_ed_thresh = 0, i = 0;
	int wl_tp_state[3] = {0}, wl_if_num = 0;/* 0: 2.4G, 1: 5G, 2: 5G-2 */
	char wl_ifname[3][8] = {"-", "-", "-"};
	char wl_current_rate[3][64] = {"-", "-", "-"}, wl_last_adj[3][64] = {"-", "-", "-"};
	float last_adj_max = 0, last_adj_min = 100;

	if (wl_if_num > 2) /* Currently only 3 ifnames are defined: 2.4G, 5G, 5G-2 */
		return 0;

	/* check if debug_wl needs to be enabled */
	if (debug_wl != 1) {
		nvram_set_int("debug_wl", 1);
	}

	strlcpy(ifnames, nvram_safe_get("wl_ifnames"), sizeof(ifnames));
	foreach (word, ifnames, next)
	{
		/* check if dy_ed_thresh needs to be disabled */
		dy_ed_thresh = 0;
		snprintf(buf, sizeof(buf), "wl -i %s dy_ed_thresh", word);
		cmd_pipe = popen(buf, "r");
		if(cmd_pipe)
		{
			fgets(tmp, sizeof(tmp), cmd_pipe);
			if(atoi(tmp) == 1)
			{
				dy_ed_thresh = 1;
				snprintf(buf, sizeof(buf), "wl -i %s dy_ed_thresh 0", word);
				system(buf);
			}
			pclose(cmd_pipe);
		}
		/* fix rate before get */
		snprintf(buf, sizeof(buf), "wl -i %s nrate -m 0 -b 20", word);
		system(buf);
		snprintf(buf, sizeof(buf), "wl -i %s powertable | grep \'the current rate\'", word);
		cmd_pipe = popen(buf, "r");
		if(cmd_pipe)
		{
			memset(buf, 0, sizeof(buf));
			if(fgets(buf, sizeof(buf), cmd_pipe))
			{
				if (sscanf(buf, "%*[^:]: %5s %5s %5s %5s", cr_tmp[0], cr_tmp[1], cr_tmp[2], cr_tmp[3]) != 4) {
					snprintf(wl_current_rate[wl_if_num], sizeof(wl_current_rate[0]), "-");
					pclose(cmd_pipe);
					/* Revert dy_ed_thresh to Enable  */
					if (dy_ed_thresh == 1) {
						snprintf(buf, sizeof(buf), "wl -i %s dy_ed_thresh 1", word);
						system(buf);
					}
					continue;
				}
				else {
					for (i = 0; i < 4; i++) {
						current_rate[i] = atof(cr_tmp[i]);
					}
					snprintf(wl_current_rate[wl_if_num], sizeof(wl_current_rate[0]), "%5s %5s %5s %5s", cr_tmp[0], cr_tmp[1], cr_tmp[2], cr_tmp[3]);
				}
			}
			pclose(cmd_pipe);
		}
		snprintf(buf, sizeof(buf), "wl -i %s powertable | grep \'Last adjusted\'", word);
		cmd_pipe = popen(buf, "r");
		if(cmd_pipe)
		{
			memset(buf, 0, sizeof(buf));
			if(fgets(buf, sizeof(buf), cmd_pipe))
			{
				if (sscanf(buf, "%*[^:]: %5s %5s %5s %5s", la_tmp[0], la_tmp[1], la_tmp[2], la_tmp[3]) != 4) {
					snprintf(wl_last_adj[wl_if_num], sizeof(wl_last_adj[0]), "-");
					pclose(cmd_pipe);
					/* Revert dy_ed_thresh to Enable  */
					if (dy_ed_thresh == 1) {
						snprintf(buf, sizeof(buf), "wl -i %s dy_ed_thresh 1", word);
						system(buf);
					}
					continue;
				}
				else {
					for (i = 0; i < 4; i++) {
						last_adj[i] = atof(la_tmp[i]);
					}
					snprintf(wl_last_adj[wl_if_num], sizeof(wl_last_adj[0]), "%5s %5s %5s %5s", la_tmp[0], la_tmp[1], la_tmp[2], la_tmp[3]);
				}
			}
			pclose(cmd_pipe);
		}

		last_adj_max = 0, last_adj_min = 100;
		for (i = 0; i < 4; i++) {
			int a = (int)(last_adj[i] + 0.5); //Rounding last_adj[i] to an integer
			if (a > 0) {
				if (last_adj[i] > last_adj_max) last_adj_max = last_adj[i];
				if (last_adj[i] < last_adj_min) last_adj_min = last_adj[i];
			}
		}

		/* 1. The difference between the maximum and minimum of [Last est. power] >= 5 dB */
		if (((last_adj_max > 0) && (last_adj_min < 100) && ((last_adj_max-last_adj_min) >= 5))
		/* 2. [Last est. power] and [Power Target for the current rate] any field gap >= 10 dB */
			|| ((current_rate[0] > 0) && (last_adj[0] > 0) && fabs(current_rate[0]-last_adj[0]) >= 10)
			|| ((current_rate[1] > 0) && (last_adj[1] > 0) && fabs(current_rate[1]-last_adj[1]) >= 10)
			|| ((current_rate[2] > 0) && (last_adj[2] > 0) && fabs(current_rate[2]-last_adj[2]) >= 10)
			|| ((current_rate[3] > 0) && (last_adj[3] > 0) && fabs(current_rate[3]-last_adj[3]) >= 10))
		{
			wl_tp_state[wl_if_num] = 1;
		}

		/* Revert dy_ed_thresh to Enable  */
		if (dy_ed_thresh == 1) {
			snprintf(buf, sizeof(buf), "wl -i %s dy_ed_thresh 1", word);
			system(buf);
		}

		wl_if_num++;
	}

	/* Revert debug_wl to Disable */
	if (debug_wl != 1) {
		nvram_set_int("debug_wl", 0);
	}

	/* restore nrate */
	foreach (word, ifnames, next) {
		snprintf(buf, sizeof(buf), "wl -i %s nrate auto", word);
		system(buf);
	}

	if ((wl_tp_state[0] == 1) || (wl_tp_state[1] == 1) || (wl_tp_state[2] == 1)) {
		if (wl_if_num == 0) { //only 2.4G
			fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): %d/-/-\n", wl_tp_state[0]);
			fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): %s/-/-\n", wl_ifname[0]);
			fprintf(fp, "Power Target for the current rate: %s/-/-\n", wl_current_rate[0]);
			fprintf(fp, "Last adjusted est. power: %s/-/-\n", wl_last_adj[0]);
		}
		else if (wl_if_num == 1) { //with 2.4G and 5G
			fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): %d/%d/-\n", wl_tp_state[0], wl_tp_state[1]);
			fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): %s/%s/-\n", wl_ifname[0], wl_ifname[1]);
			fprintf(fp, "Power Target for the current rate: %s/%s/-\n", wl_current_rate[0], wl_current_rate[1]);
			fprintf(fp, "Last adjusted est. power: %s/%s/-\n", wl_last_adj[0], wl_last_adj[1]);
		}
		else if (wl_if_num == 2) { //with 2.4G, 5G and 5G-2
			fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): %d/%d/%d\n", wl_tp_state[0], wl_tp_state[1], wl_tp_state[2]);
			fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): %s/%s/%s\n", wl_ifname[0], wl_ifname[1], wl_ifname[2]);
			fprintf(fp, "Power Target for the current rate: %s/%s/%s\n", wl_current_rate[0], wl_current_rate[1], wl_current_rate[2]);
			fprintf(fp, "Last adjusted est. power: %s/%s/%s\n", wl_last_adj[0], wl_last_adj[1], wl_last_adj[2]);
		}
		else {
			fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): -/-/-\n");
			fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): -/-/-\n");
			fprintf(fp, "Power Target for the current rate: -/-/-\n");
			fprintf(fp, "Last adjusted est. power: -/-/-\n");
		}
		return 1;
	}
	else {
		if (retry == 2) { //3rd retry (the last retry) also need to print
			if (wl_if_num == 0) { //only 2.4G
				fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): %d/-/-\n", wl_tp_state[0]);
				fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): %s/-/-\n", wl_ifname[0]);
				fprintf(fp, "Power Target for the current rate: %s/-/-\n", wl_current_rate[0]);
				fprintf(fp, "Last adjusted est. power: %s/-/-\n", wl_last_adj[0]);
			}
			else if (wl_if_num == 1) { //with 2.4G and 5G
				fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): %d/%d/-\n", wl_tp_state[0], wl_tp_state[1]);
				fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): %s/%s/-\n", wl_ifname[0], wl_ifname[1]);
				fprintf(fp, "Power Target for the current rate: %s/%s/-\n", wl_current_rate[0], wl_current_rate[1]);
				fprintf(fp, "Last adjusted est. power: %s/%s/-\n", wl_last_adj[0], wl_last_adj[1]);
			}
			else if (wl_if_num == 2) { //with 2.4G, 5G and 5G-2
				fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): %d/%d/%d\n", wl_tp_state[0], wl_tp_state[1], wl_tp_state[2]);
				fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): %s/%s/%s\n", wl_ifname[0], wl_ifname[1], wl_ifname[2]);
				fprintf(fp, "Power Target for the current rate: %s/%s/%s\n", wl_current_rate[0], wl_current_rate[1], wl_current_rate[2]);
				fprintf(fp, "Last adjusted est. power: %s/%s/%s\n", wl_last_adj[0], wl_last_adj[1], wl_last_adj[2]);
			}
			else {
				fprintf(fp, "Tx_Power_State(2.4G/5G/5G-2): -/-/-\n");
				fprintf(fp, "PA_detection_interface(2.4G/5G/5G-2): -/-/-\n");
				fprintf(fp, "Power Target for the current rate: -/-/-\n");
				fprintf(fp, "Last adjusted est. power: -/-/-\n");
			}
		}
	}
	return 0;
}
#endif

#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX) && !defined(RTCONFIG_MFGFW)
void get_bcm4366_PCI_probe_state(FILE *fp, char *result, size_t size)
{
	FILE *pfp = NULL;
	char cmdbuf[64] = {0};
	char word[100] = {0};
	char *next = NULL;
	int unit = 0;

	if(!fp)
	{
		_dprintf("[get_bcm4366_PCI_probe_state]No fp to write content.\n");
		return;
	}

	if(!result)
	{
		_dprintf("Null result pointer!\n");
	}

	if(!pids("envrams"))
	{
		system("/usr/sbin/envrams");
		sleep(1);
	}

	unit = 0;
	foreach (word, nvram_safe_get("wl_ifnames"), next) {
		memset(result, 0, size);
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "/usr/sbin/envram get wl%d_state", unit);
		pfp = popen(cmdbuf, "r");
		if(pfp)
		{
			fgets(result, size, pfp);
			pclose(pfp);
		}
		if(strlen(result) > 0)
		{
			fprintf(fp, "wl%d_state: %s", unit, result);
		}
		else
		{
			fprintf(fp, "wl%d_state: \n", unit);
		}
		unit++;
	}
}
#endif

int get_wanlanstatus(wanlan_st_t *wlst)
{
	FILE *pp = NULL;
	char buf[128] = {0};
	int n = 0, expat = 0;

	if(wlst)
	{
		//generally, EOF = -1. sscanf() may return EOF on certain error.
		wlst->numports = EOF -1;
		pp = popen("ATE Get_WanLanStatus", "r");
		if(pp)
		{
			if(fgets(buf, sizeof(buf), pp))
			{
				if (strstr(buf, "W2=")) {
					expat = 11;
					n = sscanf(buf, "W0=%[^;];W1=%[^;];W2=%[^;];L1=%[^;];L2=%[^;];L3=%[^;];L4=%[^;];L5=%[^;];L6=%[^;];L7=%[^;];L8=%[^;];",
						wlst->W0, wlst->W1, wlst->W2, wlst->L1, wlst->L2, wlst->L3, wlst->L4, wlst->L5, wlst->L6, wlst->L7, wlst->L8);
				} else if (strstr(buf, "W1=")) {
					expat = 10;
					n = sscanf(buf, "W0=%[^;];W1=%[^;];L1=%[^;];L2=%[^;];L3=%[^;];L4=%[^;];L5=%[^;];L6=%[^;];L7=%[^;];L8=%[^;];",
						wlst->W0, wlst->W1, wlst->L1, wlst->L2, wlst->L3, wlst->L4, wlst->L5, wlst->L6, wlst->L7, wlst->L8);
				} else if (strstr(buf, "L8=")) {
					expat = 9;
					n = sscanf(buf, "W0=%[^;];L1=%[^;];L2=%[^;];L3=%[^;];L4=%[^;];L5=%[^;];L6=%[^;];L7=%[^;];L8=%[^;];",
						wlst->W0, wlst->L1, wlst->L2, wlst->L3, wlst->L4, wlst->L5, wlst->L6, wlst->L7, wlst->L8);
				} else {
					expat = 5;
					n = sscanf(buf, "W0=%[^;];L1=%[^;];L2=%[^;];L3=%[^;];L4=%[^;];", wlst->W0, wlst->L1, wlst->L2, wlst->L3, wlst->L4);
				}

				if (expat && n == expat) {
					wlst->numports = n;
				} else {
					_dprintf("[%s]Parsing error on [%s]!", __FUNCTION__, buf);
				}
			}
			pclose(pp);
		}
		else
		{
			_dprintf("[%s]Failed to popen!", __FUNCTION__);
		}
	}

	return (n == wlst->numports);
}

char *get_wanlan_linkrate(char c, char *buf, int _size)
{
	if(buf && (c > 0))
	{
		switch(c)
		{
			case 'G':
				snprintf(buf, _size, "1G");
				break;
			case 'M':
				snprintf(buf, _size, "100M");
				break;
			case 'Q':
				snprintf(buf, _size, "2.5G");
				break;
			case 'F':
				snprintf(buf, _size, "5G");
				break;
			case 'T':
				snprintf(buf, _size, "10G");
				break;
			case 'X':
				/* FALL THROUGH */
			default:
				snprintf(buf, _size, "-");
		}
		return buf;
	}
	else
	{
		return NULL;
	}
}

int transform_wanlanstatus(wanlan_st_t *wlst)
{
	char buf[8];
	int n = 0;

	if(wlst)
	{
		if(get_wanlan_linkrate(wlst->W0[0], buf, sizeof(buf)))
		{
			snprintf(wlst->W0, sizeof(wlst->W0), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L1[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L1, sizeof(wlst->L1), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L2[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L2, sizeof(wlst->L2), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L3[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L3, sizeof(wlst->L3), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L4[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L4, sizeof(wlst->L4), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L5[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L5, sizeof(wlst->L5), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L6[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L6, sizeof(wlst->L6), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L7[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L7, sizeof(wlst->L7), "%s", buf);
			n++;
		}
		if(get_wanlan_linkrate(wlst->L8[0], buf, sizeof(buf)))
		{
			snprintf(wlst->L8, sizeof(wlst->L8), "%s", buf);
			n++;
		}

		return (n == wlst->numports);
	}
	else
	{
		return 0;
	}
}

static void _colloct_ipv6_data()
{
	unlink(IPV6_FILE);
	doSystem("printf \"# nvram show |grep ipv6_\n\" >> %s", IPV6_FILE);
	doSystem("nvram show|grep ipv6_ >> %s", IPV6_FILE);
#ifdef RTCONFIG_MULTIWAN_CFG
	doSystem("printf \"\n# nvram show |grep ipv61_\n\" >> %s", IPV6_FILE);
	doSystem("nvram show|grep ipv61_ >> %s", IPV6_FILE);
#endif
	doSystem("printf \"\n# ip -6 route\n\" >> %s", IPV6_FILE);
	doSystem("ip -6 route >> %s", IPV6_FILE);
	doSystem("printf \"\n# ip -6 tunnel\n\" >> %s", IPV6_FILE);
	doSystem("ip -6 tunnel  >> %s", IPV6_FILE);
	doSystem("printf \"\n# ip -6 neigh show dev br0\n\" >> %s", IPV6_FILE);
	doSystem("ip -6 neigh show dev br0 >> %s", IPV6_FILE);
	doSystem("printf \"\n# ifconfig\n\" >> %s", IPV6_FILE);
	doSystem("ifconfig >> %s", IPV6_FILE);
	doSystem("printf \"\n# ip addr show\n\" >> %s", IPV6_FILE);
	doSystem("ip a s >> %s", IPV6_FILE);
}

#if defined(RTCONFIG_SOC_IPQ8074)
struct attach_cmd_args_s {
	char *ptr;
	size_t size;
};

static int append_q6_crash_dmesg_fn(const char *basedir, const struct dirent *de, size_t de_size, void *arg)
{
	struct attach_cmd_args_s *p = arg;
	char path[sizeof("/jffs/dmesg_YYYYMMDD_HHMMSS.txtXXX")];

	if (sizeof(*de) != de_size) {
		/* If size of struct dirent mismatch, make sure readdir_wrapper() and this function see same struct dirent.h.
		 * e.g., it's different in uclibc if _FILE_OFFSET_BITS=64 is defined or not.
		 */
		dbg("%s: size of struct dirent mismatch (%u v.s. %u)!\n", __func__, sizeof(*de), de_size);
		return -1;
	}
	if (!basedir || !de || !arg)
		return -1;

	if (strncmp(de->d_name, "dmesg_", 6))
		return 0;

	snprintf(path, sizeof(path), "%s/%s", basedir, de->d_name);
	if (check_if_file_exist(path)) {
		strlcat(p->ptr, "-a ", p->size);
		strlcat(p->ptr, path, p->size);
		strlcat(p->ptr, " ", p->size);
	}
	return 0;
}
#endif

void start_sendfeedback(void)
{
#if defined(RTCONFIG_SOC_IPQ8074)
	struct attach_cmd_args_s attach_cmd_args;
#endif
#if defined(RTCONFIG_QCA)
	enum wl_band_id band;
#endif
	FILE *fp;
	char cmd[MAX_BUF_LEN] = {0};
	char attach_cmd[MAX_BUF_LEN] = {0};
	struct sysinfo info;
	long sys_uptime = 0;
#ifdef RTCONFIG_DSL
	long dsl_uptime = 0;
#endif
	int days=0, hours=0, minutes=0;
#ifdef RTCONFIG_DSL
	int nValue=0;
#endif
	FILE *cmd_pipe = NULL;
#ifdef RTCONFIG_DUALWAN
	char pri_wan[8] = {0};
	char sec_wan[8] = {0};
	char *dual_ptr = NULL;
#endif
#if defined(RTCONFIG_BCM_7114) || (defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX)) || defined(RTAX88U)
	char status_buffer[100] = {0};
#endif
	time_t now;
	struct tm *tm = NULL;
	int retval = 0;
#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114)
	unsigned int trap_log_size = 0;
	unsigned int attached_file_size = 0;
	DIR *dirp;
	struct dirent *direntp;
	int count_tgz = 0;
	int i = 0;
	int width = 128;
	char *pData = NULL;
	char **filelist_tgz = NULL;
	int processed = 0;
#endif /* HND_ROUTER || RTCONFIG_BCM_7114 */
	struct stat st;
	char fb_email[64]={0};
#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX) && !defined(RTCONFIG_MFGFW)
	char buffer[256] = {0};
#endif
	char buf[MAX_NVRAM_SPACE] = {0};
	char *name = NULL;
	int size = 0;
#ifdef RTCONFIG_AHS
	int retry_cnt = 0;
#endif /* RTCONFIG_AHS */
#ifdef RTCONFIG_BCMARM
	WiFi_temperature_t wt;
#endif /* RTCONFIG_BCMARM */
	wanlan_st_t wlst;
	char filepath[256] = {0}, decpath[256] = {0};
#ifdef RTCONFIG_DBLOG
	int dblog_service __attribute__((unused)) = 0;
#endif /* RTCONFIG_DBLOG */

	_dprintf("Start [%s]\n", __FUNCTION__);
	logmessage("frs_feedback", "start_sendfeedback() start...\n");

#ifdef RTCONFIG_DBLOG
	dblog_service = nvram_get_int("dblog_service");
#endif /* RTCONFIG_DBLOG */

	if (strchr(nvram_safe_get("fb_email"), '`') == NULL)
		strlcpy(fb_email, nvram_safe_get("fb_email"), sizeof(fb_email));

	nvram_set_int("fb_split_files", 1);
	nvram_set_int("fb_total_size", 0);
	time(&now);
	tm = localtime(&now);
	if(tm == NULL)
	{
		logmessage("frs_feedback", "Failed to get time before sending mail!\n");
		return;
	}
	else
	{
		current_time[0] = tm->tm_mon;
		current_time[1] = tm->tm_mday;
	}

	/*the value of fb_state=>
		0 or null: default
		1: success
		2: fail
		3: send more than 10 times per day.
	*/
	if(!nvram_match("fb_email_dbg", ""))
	{
		//do not increase counter.
	}
	else if((current_time[0] == pre_time[0]) && (current_time[1] == pre_time[1])){
		if(send_count >= SENDOUT_LIMIT){
			logmessage("frs_feedback", "You had sent Feedback more than %d times.\n", send_count);
			nvram_set("fb_state", "3");
			return;
		}
		else{
			send_count ++;
		}
	}
	else{
		pre_time[0] = current_time[0];
		pre_time[1] = current_time[1];
		send_count = 1;
	}
	nvram_set_int("fb_feedbackcount", send_count);
	nvram_set("fb_state", "0");

	snprintf(cmd, sizeof(cmd), "mkdir -p %s", DUP_LOG_PATH);
	system(cmd);
	if(!check_if_dir_exist(DUP_LOG_PATH))
	{
		dbg("send_feedback_curl_retry() failed to create folder [%s]\n", DUP_LOG_PATH);
		return ;
	}

#ifndef RTCONFIG_DISABLE_NETWORKMAP
	get_client_info();
#endif /* RTCONFIG_DISABLE_NETWORKMAP */

#ifdef RTCONFIG_DSL
#if defined(RTCONFIG_DSL_TCLINUX)
	eval("req_dsl_drv", "dumplog");
#elif defined(RTCONFIG_DSL_HOST)
	killall("dsld", SIGUSR1);
	sleep(1);
#endif
	if(check_if_file_exist(LOG_RECORD_FILE))
		sprintf(attach_cmd + strlen(attach_cmd), "-a %s ", LOG_RECORD_FILE);

	if(check_if_file_exist(SYNC_LOG_FILE))
	{
		snprintf(cmd, sizeof(cmd), "cp %s %s", SYNC_LOG_FILE, DUP_LOG_PATH);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, SYNC_STATUS_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}
	}

	snprintf(filepath, sizeof(filepath), "/tmp/adsl/%s", INFO_ADSL_FILE);
	if(check_if_file_exist(filepath))
	{
		snprintf(cmd, sizeof(cmd), "cp %s %s", filepath, DUP_LOG_PATH);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, INFO_ADSL_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}
	}
#endif /* RTCONFIG_DSL */

	//user checked
	if(nvram_match("fb_attach_syslog", "1") || nvram_match("fb_attach_wlanlog", "1"))
	{
#if defined(RTCONFIG_CONCURRENTREPEATER) && defined(RTCONFIG_REALTEK)
#if defined(RPAC55)
		_dprintf("---Collect REALTEK log...\n");
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "cat /proc/wl0-vxd/sta_info > /tmp/wl0-vxd_sta_info");
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "cat /proc/wl1-vxd/sta_info > /tmp/wl1-vxd_sta_info");
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "cat /proc/wl0-vxd/mib_all > /tmp/wl0-vxd_mib");
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "cat /proc/wl1-vxd/mib_all > /tmp/wl1-vxd_mib");
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "cat /proc/wl0/sta_info > /tmp/wl0-sta_info");
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "cat /proc/wl1/sta_info > /tmp/wl1-sta_info");
		system(cmd);
	if(check_if_file_exist("/tmp/wl0-vxd_sta_info"))
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ",  "/tmp/wl0-vxd_sta_info");
	if(check_if_file_exist("/tmp/wl1-vxd_sta_info"))
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ",  "/tmp/wl1-vxd_sta_info");
	if(check_if_file_exist("/tmp/wl0-vxd_mib"))
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ",  "/tmp/wl0-vxd_mib");
	if(check_if_file_exist("/tmp/wl1-vxd_mib"))
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ",  "/tmp/wl1-vxd_mib");
	if(check_if_file_exist("/tmp/wl0-sta_info"))
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ",  "/tmp/wl0-sta_info");
	if(check_if_file_exist("/tmp/wl1-sta_info"))
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ",  "/tmp/wl1-sta_info");
#endif
#endif
	}

	if(nvram_match("fb_attach_syslog", "1"))
	{
		_dprintf("---Collect Syslog...\n");

		/* Combine syslogs to single file. */
		if (check_if_file_exist(DUP_LOG_PATH "/" SYSLOG_FILE))
			unlink(DUP_LOG_PATH "/" SYSLOG_FILE);
		if (check_if_file_exist("/tmp/" SYSLOG_1_FILE)) {
			snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/tmp/" SYSLOG_1_FILE, DUP_LOG_PATH "/" SYSLOG_FILE);
			system(cmd);
		}
		if (check_if_file_exist("/tmp/" SYSLOG_FILE)) {
			snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/tmp/" SYSLOG_FILE, DUP_LOG_PATH "/" SYSLOG_FILE);
			system(cmd);
		}
		if (check_if_file_exist(DUP_LOG_PATH "/" SYSLOG_FILE)) {
			strlcat(attach_cmd, "-a " DUP_LOG_PATH "/" SYSLOG_FILE " ", sizeof(attach_cmd));
		}

#if defined(RTCONFIG_QCA)
		/* Combine hostapd.log and hostapd.log-1 and then send */
		if (check_if_file_exist(DUP_LOG_PATH "/" HOSTAPD_LOG))
			unlink(DUP_LOG_PATH "/" HOSTAPD_LOG);
		if (check_if_file_exist("/jffs/" HOSTAPD_LOG "-1")) {
			snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/" HOSTAPD_LOG "-1", DUP_LOG_PATH "/" HOSTAPD_LOG);
			system(cmd);
		}
		if (check_if_file_exist("/jffs/" HOSTAPD_LOG)) {
			snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/" HOSTAPD_LOG, DUP_LOG_PATH "/" HOSTAPD_LOG);
			system(cmd);
		}
		if (check_if_file_exist(DUP_LOG_PATH "/" HOSTAPD_LOG)) {
			strlcat(attach_cmd, "-a " DUP_LOG_PATH "/" HOSTAPD_LOG " ", sizeof(attach_cmd));
		}

		/* Combine (hostapd|wpa_supplicant)_(ath*|staX).log and (hostapd|wpa_supplicant_(ath*|staX).log-1 and then send */
		for (band = WL_2G_BAND; band < MAX_NR_WL_IF; ++band) {
			int y, max_sub_unit;
			char old[sizeof("/jffs/wpa_supplicant_XXX.log-1") + IFNAMSIZ];
			char new[sizeof("/jffs/wpa_supplicant_XXX.log") + IFNAMSIZ];
			char dest[sizeof(DUP_LOG_PATH "/") + sizeof(new) - 5], vap[IFNAMSIZ];
			SKIP_ABSENT_BAND(band);

			max_sub_unit = num_of_mssid_support(band);
			for (y = 0; y < max_sub_unit; ++y) {
				get_wlxy_ifname(band, y, vap);
				snprintf(dest, sizeof(dest), "%s/hostapd_%s.log", DUP_LOG_PATH, vap);
				snprintf(new, sizeof(new), "/jffs/hostapd_%s.log", vap);
				snprintf(old, sizeof(old), "%s-1", new);

				if (check_if_file_exist(dest))
					unlink(dest);
				if (check_if_file_exist(old)) {
					snprintf(cmd, sizeof(cmd), "cp -f %s %s", old, dest);
					system(cmd);
				}
				if (check_if_file_exist(new)) {
					snprintf(cmd, sizeof(cmd), "cat %s >> %s", new, dest);
					system(cmd);
				}
				if (check_if_file_exist(dest)) {
					strlcat(attach_cmd, "-a ", sizeof(attach_cmd));
					strlcat(attach_cmd, dest, sizeof(attach_cmd));
					strlcat(attach_cmd, " ", sizeof(attach_cmd));
				}
			}

			snprintf(dest, sizeof(dest), "%s/wpa_supplicant_%s.log", DUP_LOG_PATH, get_staifname(band));
			snprintf(new, sizeof(new), "/jffs/wpa_supplicant_%s.log", get_staifname(band));
			snprintf(old, sizeof(old), "%s-1", new);

			if (check_if_file_exist(dest))
				unlink(dest);
			if (check_if_file_exist(old)) {
				snprintf(cmd, sizeof(cmd), "cp -f %s %s", old, dest);
				system(cmd);
			}
			if (check_if_file_exist(new)) {
				snprintf(cmd, sizeof(cmd), "cat %s >> %s", new, dest);
				system(cmd);
			}
			if (check_if_file_exist(dest)) {
				strlcat(attach_cmd, "-a ", sizeof(attach_cmd));
				strlcat(attach_cmd, dest, sizeof(attach_cmd));
				strlcat(attach_cmd, " ", sizeof(attach_cmd));
			}
		}
#endif

		//add some system information
		sprintf(cmd, "free > %s;echo >> %s;cat /proc/meminfo >> %s", FREE_FILE, FREE_FILE, FREE_FILE);
		system(cmd);
		if(check_if_file_exist(FREE_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", FREE_FILE);

		sprintf(cmd, "top -n 1 > %s", TOP_FILE);
		system(cmd);
		if(check_if_file_exist(TOP_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", TOP_FILE);
		if(check_if_file_exist(WEBSUPG_1_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", WEBSUPG_1_FILE);
		if(check_if_file_exist(WEBSUPG_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", WEBSUPG_FILE);
		if(check_if_file_exist(DUT_HTTPD_FB_DEBUG_1))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", DUT_HTTPD_FB_DEBUG_1);
		if(check_if_file_exist(DUT_HTTPD_FB_DEBUG))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", DUT_HTTPD_FB_DEBUG);

	#ifdef RTCONFIG_DSL
		eval("req_dsl_drv", "getdmesg");
		if(check_if_file_exist("/tmp/adsl/dmesg.txt"))
			strcat(attach_cmd, "-a /tmp/adsl/dmesg.txt ");

		eval("req_dsl_drv", "getsyslog");
		if(check_if_file_exist("/tmp/adsl/currLogFile.txt"))
			strcat(attach_cmd, "-a /tmp/adsl/currLogFile.txt ");
	#endif
		system("ls /proc >/tmp/proc.tmp");
		system("echo \"#!/bin/sh\" > /tmp/preScript.sh ; chmod +x /tmp/preScript.sh");
		system("ps > /tmp/psInfo.txt");
		system("cat /tmp/proc.tmp | sed -n \"/^[0-9]\\+$/p\" | awk '{printf \"echo [PID:\%d] `cat /proc/\%d/cmdline`  >> /tmp/psInfo.txt\\n\", $0,$0}' >> /tmp/preScript.sh");
		system("/tmp/preScript.sh");
		system("echo \"\" >> /tmp/psInfo.txt");
		system("echo \"==========ps -wT==========\" >> /tmp/psInfo.txt");
		system("ps -wT >> /tmp/psInfo.txt");
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a /tmp/psInfo.txt ");

		system("netstat -na >> /tmp/netstat.txt");
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a /tmp/netstat.txt ");

		system("ls -al /var/lock >> /tmp/var_lock.txt");
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a /tmp/var_lock.txt ");

		/* JFFS_LOG */
		snprintf(cmd, sizeof(cmd), "echo \"# ls -al /jffs\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "ls -al /jffs > /tmp/%s 2>&1", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"# du -sh /jffs\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "du -sh /jffs >> /tmp/%s 2>&1", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"# du -h /jffs\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "du -h /jffs >> /tmp/%s 2>&1", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"# ls -alR /jffs\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "ls -alR /jffs >> /tmp/%s 2>&1", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"# df /jffs\" >> /tmp/%s", JFFS_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "df /jffs >> /tmp/%s 2>&1", JFFS_LOG);
		system(cmd);
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a /tmp/%s ", JFFS_LOG);
		/* JFFS_LOG */

		/* TMP_LOG */
		snprintf(cmd, sizeof(cmd), "ls -al /tmp > /tmp/%s 2>&1", TMP_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", TMP_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "du -sh /tmp >> /tmp/%s 2>&1", TMP_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", TMP_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "du -sh /tmp/* >> /tmp/%s 2>&1", TMP_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "echo \"\" >> /tmp/%s", TMP_LOG);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "df /tmp >> /tmp/%s 2>&1", TMP_LOG);
		system(cmd);
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a /tmp/%s ", TMP_LOG);
		/* TMP_LOG */

		/* command history */
		snprintf(filepath, sizeof(filepath), "/root/%s", ASH_HISTORY);
		if(check_if_file_exist(filepath))
		{
			snprintf(cmd, sizeof(cmd), "cp %s %s/%s", filepath, DUP_LOG_PATH, CMD_HISTORY);
			system(cmd);
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, CMD_HISTORY);
			if(check_if_file_exist(filepath))
			{
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
			}
		}
		/* command history */

		/* WAN info*/
		snprintf(cmd, sizeof(cmd), "cd /tmp/; tar zcf %s wan*.env", WANENV_FILE);
		system(cmd);
		if(check_if_file_exist(WANENV_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", WANENV_FILE);
		/* WAN info*/

#ifdef RTCONFIG_IPV6
		if (ipv6_enabled() && is_routing_enabled()) {
			_colloct_ipv6_data();
			if(check_if_file_exist(IPV6_FILE))
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", IPV6_FILE);
		}
#endif

#ifdef RTCONFIG_FSMD
		snprintf(cmd, sizeof(cmd), "req_fsm dump %s", JFFS_USAGE_FILE);
		system(cmd);
		usleep(500000);
		if(check_if_file_exist(JFFS_USAGE_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", JFFS_USAGE_FILE);
#endif

#ifdef RTCONFIG_SYSSTATE
	dump_sysstate_logs();
	snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", CPUUSAGE_FILE);
	snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", RAMUSAGE_FILE);
	snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", CPUTEMP_FILE);
#else
#endif /* RTCONFIG_SYSSTATE */

#ifdef RTCONFIG_AHS
	/* Combine ahs logs to single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_LOG_FILE);
	if (check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if (check_if_file_exist("/tmp/" AHS_LOG_1_FILE)) {
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/tmp/" AHS_LOG_1_FILE, filepath);
		system(cmd);
	}
	if (check_if_file_exist("/tmp/" AHS_LOG_FILE)) {
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/tmp/" AHS_LOG_FILE, filepath);
		system(cmd);
	}
	if (check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}

	if(check_if_file_exist(AHS_JSON_FILE))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", AHS_JSON_FILE);
	}
	if(check_if_file_exist(AHS_JSONOBJ_FILE))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", AHS_JSONOBJ_FILE);
	}

	kill_pidfile_s("/var/run/ahs.pid", SIGUSR2);
	retry_cnt = 6;
	while(retry_cnt--){
		if (check_if_file_exist(AHS_DUMP_FILE))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", AHS_DUMP_FILE);
			break;
		}else{
			_dprintf("[ahs_dump.txt] does not exist, retry = %d\n", retry_cnt);
			sleep(1);
		}
	}

	/* Combine AHS logs in /jffs/ahs into a single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_LOG_IN_JFFS_FILE);
	if (check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if(check_if_file_exist("/jffs/ahs/" AHS_LOG_IN_JFFS_1_FILE))
	{
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/ahs/" AHS_LOG_IN_JFFS_1_FILE, filepath);
		system(cmd);
	}
	if(check_if_file_exist("/jffs/ahs/" AHS_LOG_IN_JFFS_FILE))
	{
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/ahs/" AHS_LOG_IN_JFFS_FILE, filepath);
		system(cmd);
	}
	if(check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}

	snprintf(filepath, sizeof(filepath), "/jffs/ahs/%s", AHS_HWSW_ST_JFFS_FILE);
	if(check_if_file_exist(filepath))
	{
		snprintf(cmd, sizeof(cmd), "cp /jffs/ahs/%s %s", AHS_HWSW_ST_JFFS_FILE, DUP_LOG_PATH);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_HWSW_ST_JFFS_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}
		snprintf(filepath, sizeof(filepath), "/jffs/ahs/%s", AHS_HWSW_ST_JFFS_FILE);
		unlink(filepath);
	}
#endif /* RTCONFIG_AHS */

#ifdef RTCONFIG_ASD
	/* Combine ASD logs into a single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, ASD_LOG_PATH);
	if (check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if(check_if_file_exist("/jffs/" ASD_BK_LOG_PATH))
	{
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/" ASD_BK_LOG_PATH, filepath);
		system(cmd);
	}
	if(check_if_file_exist("/jffs/" ASD_LOG_PATH))
	{
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/" ASD_LOG_PATH, filepath);
		system(cmd);
	}
	if(check_if_file_exist(filepath))
	{
			//decrypt file
			snprintf(decpath, sizeof(decpath), "%s.dec", filepath);
			if(!_dec_asd_log(filepath, decpath))
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", decpath);
			else
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}
	/*Handle the asdbk folder*/
	if(check_if_dir_empty(ASD_BK_DIR))
	{
		snprintf(cmd, sizeof(cmd), "tar -zcf %s/%s %s", DUP_LOG_PATH, ASD_BK_NAME, ASD_BK_DIR);
		system(cmd);
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s/%s ", DUP_LOG_PATH, ASD_BK_NAME);
	}
#endif

#ifdef RTCONFIG_SOFTWIRE46
	/* Combine S46 logs into a single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, S46_LOG_FILE);
	if (check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if(check_if_file_exist("/jffs/" S46_LOG_1_FILE))
	{
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/" S46_LOG_1_FILE, filepath);
		system(cmd);
	}
	if(check_if_file_exist("/jffs/" S46_LOG_FILE))
	{
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/" S46_LOG_FILE, filepath);
		system(cmd);
	}
	if(check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}
#endif

	/* Combine wget logs into a single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, WGET_LOG_PATH);
	if (check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if(check_if_file_exist("/jffs/" WGET_BK_LOG_PATH))
	{
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/" WGET_BK_LOG_PATH, filepath);
		system(cmd);
	}
	if(check_if_file_exist("/jffs/" WGET_LOG_PATH))
	{
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/" WGET_LOG_PATH, filepath);
		system(cmd);
	}
	if(check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}

#ifdef RTCONFIG_BWDPI
	snprintf(filepath, sizeof(filepath), "/tmp/%s", BWDPI_SIG_UPG_LOG);
	if(check_if_file_exist(filepath))
	{
		snprintf(cmd, sizeof(cmd), "cp /tmp/%s %s", BWDPI_SIG_UPG_LOG, DUP_LOG_PATH);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, BWDPI_SIG_UPG_LOG);
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}
	}
#endif /* RTCONFIG_BWDPI */

#if defined(BRCM_BASED_MODELS)
	#if defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
		envram_dump_factory_data();
	#else
		sprintf(cmd, "gzip -f -c /dev/mtd0 > %s", CFE_FILE);
		system(cmd);
	#endif
		sprintf(attach_cmd + strlen(attach_cmd), "-a %s ", CFE_FILE);
	#if defined(RTCONFIG_DPSTA)
		sprintf(cmd, "cat /proc/dpsta/stats > %s", DPSTA_FILE);
		system(cmd);
		sleep(2);
		sprintf(cmd, "cat /proc/dpsta/stats >> %s", DPSTA_FILE);
		system(cmd);
		sprintf(attach_cmd + strlen(attach_cmd), "-a %s ", DPSTA_FILE);
	#endif
#endif /* BRCM_BASED_MODELS */

#ifdef RTCONFIG_CFGSYNC
	/* for topology information */
	eval("cfg_reportstatus");
	if (check_if_file_exist(CFGMNT_FILE))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", CFGMNT_FILE);
	}

	/* for debug log */
	/* Combine cfg_mnt logs to a single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, CFG_DBG_FILE);
	if(check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if(check_if_file_exist(CFG_DBG_LOG_1))
	{
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", CFG_DBG_LOG_1, filepath);
		system(cmd);
	}
	if(check_if_file_exist(CFG_DBG_LOG))
	{
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", CFG_DBG_LOG, filepath);
		system(cmd);
	}
	if(check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}
#endif

#ifdef RTCONFIG_STRONGSWAN
	/* Combine strongSwan logs to a single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, SS_CHARON_LOG);
	if(check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if(check_if_file_exist("/var/log/" SS_CHARON_1_LOG))
	{
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/var/log/" SS_CHARON_1_LOG, filepath);
		system(cmd);
	}
	if(check_if_file_exist("/var/log/" SS_CHARON_LOG))
	{
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/var/log/" SS_CHARON_LOG, filepath);
		system(cmd);
	}
	if(check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}
#endif /* RTCONFIG_STRONGSWAN */
#ifdef RTCONFIG_UPNPC_NEW
	snprintf(filepath, sizeof(filepath), "/tmp/%s", IPSEC_UPNPC_LIST);
	if(check_if_file_exist(filepath))
	{
		snprintf(cmd, sizeof(cmd), "cp %s %s", filepath, DUP_LOG_PATH);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, IPSEC_UPNPC_LIST);
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}
	}
	snprintf(filepath, sizeof(filepath), "/tmp/%s", IPSEC_UPNPC_WDG_LIST);
	if(check_if_file_exist(filepath))
	{
		snprintf(cmd, sizeof(cmd), "cp %s %s", filepath, DUP_LOG_PATH);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, IPSEC_UPNPC_WDG_LIST);
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}
	}
#endif /* RTCONFIG_UPNPC_NEW */

		killall("dnsmasq", SIGUSR2);
		sleep(1);
		snprintf(filepath, sizeof(filepath), "/var/lib/misc/%s", DHCP_LEASES_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(cmd, sizeof(cmd), "cp %s %s/%s.txt", filepath, DUP_LOG_PATH, DHCP_LEASES_FILE);
			system(cmd);
			snprintf(filepath, sizeof(filepath), "%s/%s.txt", DUP_LOG_PATH, DHCP_LEASES_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
			}
		}

		snprintf(cmd, sizeof(cmd), "arp -avn >> /tmp/%s", ARP_OUTPUT_FILE);
		system(cmd);
		snprintf(filepath, sizeof(filepath), "/tmp/%s", ARP_OUTPUT_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(cmd, sizeof(cmd), "mv %s %s/%s", filepath, DUP_LOG_PATH, ARP_OUTPUT_FILE);
			system(cmd);
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, ARP_OUTPUT_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
			}
		}
	}
#ifdef RTCONFIG_LANTIQ
	snprintf(cmd, sizeof(cmd), "cd /tmp/; rm -f %s; tar zcf %s /jffs",
				WIFI_DB1_FILE, WIFI_DB1_FILE);
	system(cmd);
	snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd),
			"-a %s ", WIFI_DB1_FILE);
	snprintf(cmd, sizeof(cmd), "cd /tmp/; rm -f %s; tar zcf %s wlan_wave",
				WIFI_DB2_FILE, WIFI_DB2_FILE);
	system(cmd);
	snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd),
			"-a %s ", WIFI_DB2_FILE);
	snprintf(cmd, sizeof(cmd), "cd /opt/lantiq/wave/; rm -f %s; tar zcf %s %s",
				WIFI_DB3_FILE, WIFI_DB3_FILE, WIFI_DB3_FILE_LIST);
	system(cmd);
	snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd),
			"-a %s ", WIFI_DB3_FILE);
#endif

#ifdef RTCONFIG_QCA_PLC2
	/* Combine ahs logs to single file. */
	snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, PLC_LOG_FILE);
	if (check_if_file_exist(filepath))
	{
		unlink(filepath);
	}
	if (check_if_file_exist("/tmp/asusdebuglog/" PLC_LOG_1_FILE)) {
		snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/tmp/asusdebuglog/" PLC_LOG_1_FILE, filepath);
		system(cmd);
	}
	if (check_if_file_exist("/tmp/asusdebuglog/" PLC_LOG_FILE)) {
		snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/tmp/asusdebuglog/" PLC_LOG_FILE, filepath);
		system(cmd);
		extern char *plctool_cmd(const char *cmd, char buf[], int size);
		plctool_cmd("-I", cmd, sizeof(cmd));
		doSystem("%s >> %s", cmd, filepath);	//append current plc state
		plctool_cmd("-m", cmd, sizeof(cmd));
		doSystem("%s >> %s", cmd, filepath);	//append current plc connection status
	}
	if (check_if_file_exist(filepath))
	{
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
	}
#endif /* RTCONFIG_QCA_PLC2 */

	if(nvram_match("fb_attach_cfgfile", "1")){
		_dprintf("---Collect cfg...\n");

		nvram_commit();
                //Andy Chiu, 2015/06/10.
		//eval("nvram", "save", "/tmp/settings");
		eval("nvram", "fb_save", "/tmp/settings");
		strcat(attach_cmd, "-a /tmp/settings ");
	}

#ifdef RTCONFIG_DSL
	if(nvram_match("fb_attach_iptables", "1")){
		_dprintf("---Collect iptable...\n");

		sprintf(cmd, "iptables-save > %s", IPTABLES_FILE);
		system(cmd);
		sprintf(attach_cmd + strlen(attach_cmd), "-a %s ", IPTABLES_FILE);
	}
#endif /* RTCONFIG_DSL */

	if(nvram_match("fb_attach_modemlog", "1")){
		_dprintf("---Collect modem log...\n");

		sprintf(cmd, "/usr/sbin/3ginfo.sh > %s", MODEMLOG_FILE);
		system(cmd);
		sprintf(attach_cmd + strlen(attach_cmd), "-a %s ", MODEMLOG_FILE);
	}

	if(nvram_match("fb_attach_wlanlog", "1")){
		int wlanlog_retry = 15;
		char httpd_pid[64];

		_dprintf("---Collect wireless log 1...\n");

		if(nvram_match("http_enable", "1"))
			snprintf(httpd_pid, sizeof(httpd_pid), "/var/run/httpd-%s.pid", nvram_safe_get("https_lanport"));
		else
			strlcpy(httpd_pid, "/var/run/httpd.pid", sizeof(httpd_pid));

		nvram_set("fb_wlanlog_done", "0");
		kill_pidfile_s(httpd_pid, SIGUSR1);

		while(wlanlog_retry--){
			if (check_if_file_exist(WLANLOG_FILE))
			{
				if(nvram_match("fb_wlanlog_done", "1"))
				{
					cprintf("fb_wlanlog_done=1\n");
					snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", WLANLOG_FILE);
					break;
				}
				else
				{
					cprintf("fb_wlanlog_done=0\n");
					sleep(1);
				}
			}else{
				_dprintf("wlanlog.txt is not exist, retry = %d\n", wlanlog_retry);
				sleep(1);
			}
		}

		/*
		* Use sed command to replace MAC address with XX:--:--:--:YY:ZZ in WLANLOG_FILE
		* 88:D7:F6:1D:32:3C => 88:--:--:--:32:3C
		*	sed -r 's/([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2})/\1--:--:--:\5\6/'
		* Note: Do not use 'sed -E' bucause some models do not support '-E' option.
		*/
		snprintf(cmd, sizeof(cmd), "sed -r -i 's/([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2}:)([0-9a-zA-Z]{1,2})/\\1--:--:--:\\5\\6/' %s", WLANLOG_FILE);
		system(cmd);
	}

#if defined(RTCONFIG_QCA) || defined(RTCONFIG_RALINK)
	if (nvram_match("fb_attach_wlanlog", "1") && __gen_wifi_ap_stats_log) {
		__gen_wifi_ap_stats_log("/tmp/" WIFI_AP_STATS_LOG);
		if (check_if_file_exist("/tmp/" WIFI_AP_STATS_LOG)) {
			strlcat(attach_cmd, "-a /tmp/" WIFI_AP_STATS_LOG " ", sizeof(attach_cmd));
		}
	}
	if (nvram_match("fb_attach_wlanlog", "1") && __gen_wifi_sta_stats_log) {
		__gen_wifi_sta_stats_log("/tmp/" WIFI_STA_STATS_LOG);
		if (check_if_file_exist("/tmp/" WIFI_STA_STATS_LOG)) {
			strlcat(attach_cmd, "-a /tmp/" WIFI_STA_STATS_LOG " ", sizeof(attach_cmd));
		}
	}
#endif

#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)
	if(nvram_match("fb_attach_wlanlog", "1")){
		char word[128], *next;
		char file[256];
		int wlstats_retry = 10;
		int unit = -1, subunit = 0;
		char tmp[256], vif_name[] = "wlXXXXXXXXXX";
		int max_no_vifs = 0;

		_dprintf("---Collect wireless log 2...\n");
#ifdef RTCONFIG_BCM_HND_CRASHLOG
		if(check_if_file_exist(CRASHLOG_FILE))
			sprintf(attach_cmd + strlen(attach_cmd), "-a %s ", CRASHLOG_FILE);
#endif
		dump_WlGetDriverStats(1,2);
		sleep(8);

		foreach (word, nvram_safe_get("wl_ifnames"), next) {
			unit++;
			max_no_vifs = wl_max_no_vifs(unit);
			for (subunit = 0; subunit < max_no_vifs; subunit++) {
				snprintf(vif_name, sizeof(vif_name), "wl%d.%d", unit, subunit);
				if(subunit && !nvram_get_int(strcat_r(vif_name, "_bss_enabled", tmp)))
					continue;
				snprintf(file, sizeof(file), "/tmp/WlGetDriverStats_%s.log", subunit?vif_name:word);
				wlstats_retry = 15;

				while(wlstats_retry--){
					if (check_if_file_exist(file)) {
						snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", file);
						break;
					}
					else {
						_dprintf("%s is not exist, retry = %d\n", file, wlstats_retry);
						sleep(1);
					}
				}
			}
		}
	}
#endif

	if(nvram_match("fb_attach_wlanlog", "1")){
		if(check_if_dir_exist("/tmp/"CONN_DIAG_LOG_SRC_FOLDER))
		{
			_dprintf("---Collect wireless log 3...\n");
			snprintf(cmd, sizeof(cmd), "cp -rf /tmp/%s %s/%s", CONN_DIAG_LOG_SRC_FOLDER, DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER);
			system(cmd);

			snprintf(cmd, sizeof(cmd), "tar -zcf %s/%s.tar.gz %s/%s", DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER, DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER);
			system(cmd);

			snprintf(cmd, sizeof(cmd), "rm -rf %s/%s", DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER);
			system(cmd);

			snprintf(filepath, sizeof(filepath), "%s/%s.tar.gz", DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER);
			if(check_if_file_exist(filepath))
			{
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
			}
		}

		/* Combine AMAS site survey log */
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, JFFS_AMAS_SITE_SURVEY_LOG);
		if(check_if_file_exist(filepath))
		{
			unlink(filepath);
		}
		if(check_if_file_exist("/jffs/.sys/amas/" JFFS_AMAS_SITE_SURVEY_1_LOG))
		{
			snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/.sys/amas/" JFFS_AMAS_SITE_SURVEY_1_LOG, filepath);
			system(cmd);
		}
		if(check_if_file_exist("/jffs/.sys/amas/" JFFS_AMAS_SITE_SURVEY_LOG))
		{
			snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/.sys/amas/" JFFS_AMAS_SITE_SURVEY_LOG, filepath);
			system(cmd);
		}
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}

		/* AMAS site survey log */
		/* Combine AMAS connection log */
		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, JFFS_AMAS_WLCCONNECT_LOG);
		if(check_if_file_exist(filepath))
		{
			unlink(filepath);
		}
		if(check_if_file_exist("/jffs/" JFFS_AMAS_WLCCONNECT_1_LOG))
		{
			snprintf(cmd, sizeof(cmd), "cp -f %s %s", "/jffs/" JFFS_AMAS_WLCCONNECT_1_LOG, filepath);
			system(cmd);
		}
		if(check_if_file_exist("/jffs/" JFFS_AMAS_WLCCONNECT_LOG))
		{
			snprintf(cmd, sizeof(cmd), "cat %s >> %s", "/jffs/" JFFS_AMAS_WLCCONNECT_LOG, filepath);
			system(cmd);
		}
		if(check_if_file_exist(filepath))
		{
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
		}

		snprintf(filepath, sizeof(filepath), "/tmp/asusdebuglog/%s", AMAS_AVBLCHAN_LOG);
		if(check_if_file_exist(filepath))
		{
			snprintf(cmd, sizeof(cmd), "cp %s %s/%s", filepath, DUP_LOG_PATH, AMAS_AVBLCHAN_LOG);
			system(cmd);
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, DHCP_LEASES_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filepath);
			}
		}

		/* AMAS connection log */
#if defined(RTCONFIG_HND_ROUTER_AX_675X)
		snprintf(cmd, sizeof(cmd), "cd /tmp; rm -f core.tgz; tar zcf core.tgz core-*");
		system(cmd);
		snprintf(cmd, sizeof(cmd), "rm -rf /tmp/core-*");
		system(cmd);
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", "/tmp/core.tgz");
#endif
	}

#if defined(RTCONFIG_SOC_IPQ8074)
	if (nvram_match("fb_attach_syslog", "1")) {
		/* If /jffs/dmesg_*.txt exist, attach it. */
		attach_cmd_args.ptr = attach_cmd;
		attach_cmd_args.size = sizeof(attach_cmd);
		readdir_wrapper("/jffs", NULL, append_q6_crash_dmesg_fn, &attach_cmd_args);
	}
#endif
#if defined(RTCONFIG_SWITCH_QCA8075_QCA8337_PHY_AQR107_AR8035_QCA8033)
	if (nvram_match("fb_attach_syslog", "1") && __gen_switch_log) {
		__gen_switch_log("/tmp/" SWITCH_LOG);
		if (check_if_file_exist("/tmp/"SWITCH_LOG)) {
			strlcat(attach_cmd, "-a /tmp/" SWITCH_LOG " ", sizeof(attach_cmd));
		}
	}
#endif

#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)
	if (strlen(nvram_safe_get("log_wlstat_dir")) && d_exists(nvram_safe_get("log_wlstat_dir"))) {
		snprintf(cmd, sizeof(cmd), "cd /tmp; rm -f log_wlstat.tgz; tar zcf log_wlstat.tgz %s", nvram_safe_get("log_wlstat_dir"));
		system(cmd);
		snprintf(cmd, sizeof(cmd), "rm -rf %s", nvram_safe_get("log_wlstat_dir"));
		system(cmd);
		snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", "/tmp/log_wlstat.tgz");
	}
#endif

	fp = fopen(FB_FILE, "w");
	if(fp) {
		_dprintf("---Collect mail content...\n");

		fputs("CUSTOMER FEEDBACK\n----------------------------------------------------------------------------------------------------------------\n\n", fp);
		fputs("Model: ", fp);
		fputs(get_productid(), fp);

		fputs("\nFirmware Version: ", fp);
		fprintf(fp, "%s.%s_%s", nvram_safe_get("firmver"), nvram_safe_get("buildno"), nvram_safe_get("extendno"));

		fputs("\nInner Version: ", fp);
		fputs(nvram_safe_get("innerver"), fp);
#ifdef RTCONFIG_DSL
		fputs("\nDSL Firmware Version: ", fp);
		fputs(nvram_safe_get("dsllog_fwver"), fp);

		fputs("\nDSL Driver Version: ", fp);
		fputs(nvram_safe_get("dsllog_drvver"), fp);
#endif /* RTCONFIG_DSL */

#ifdef RTCONFIG_AVS
		fputs("\nCX20921 Firmware Version: ", fp);
		fputs(nvram_safe_get("cx2092x_ver"), fp);
		fputs("\nNUC123 Firmware Version: ", fp);
		fputs(nvram_safe_get("nuc123_ver"), fp);
#endif

#ifdef RTCONFIG_ASD
		fputs("\nASD Version: ", fp);
		fputs(nvram_safe_get("asd_ver"), fp);
		fputs("\nASD_BF Ver: ", fp);
		fputs(nvram_safe_get("blockfile_sigver"), fp);
		fputs("\nASD_CHKNV Version: ", fp);
		fputs(nvram_safe_get("chknvram_sigver"), fp);
		fputs("\nASD_MISC Version: ", fp);
		fputs(nvram_safe_get("misc_sigver"), fp);
#endif

#if 0
		fputs("\nPIN Code: ", fp);
		fputs(nvram_safe_get("wps_device_pin"), fp);
#endif

		fputs("\nMAC Address: ", fp);
		fputs(get_label_mac(), fp);
#if defined(MAPAC2200) || defined(MAPAC1300) || defined(VZWAC1300) || defined(SHAC1300) || defined(MAPAC2200V)
/* for Lyra series */
		fputs("\nMAC_WAN_Address: ", fp);
		fputs(get_lan_hwaddr(), fp);
#endif

		fputs("\nBrowser: ", fp);
		fputs(nvram_safe_get("fb_browserInfo"), fp);

#ifdef RTCONFIG_DSL
		fputs("\nConfigured DSL Modulation: ", fp);
		switch(nvram_get_int("dslx_modulation")) {
			case 0:
				fputs("T1.413", fp);
				break;
			case 1:
				fputs("G.lite", fp);
				break;
			case 2:
				fputs("G.Dmt", fp);
				break;
			case 3:
				fputs("ADSL2", fp);
				break;
			case 4:
				fputs("ADSL2+", fp);
				break;
			case 5:
				fputs("Multiple Mode", fp);
				break;
#ifdef RTCONFIG_VDSL
			case 6:
				fputs("VDSL2", fp);
				break;
#endif
		}

		fputs("\nConfigured Annex Mode: ", fp);
			switch(nvram_get_int("dslx_annex")) {
				case 0:
					fputs("Annex A", fp);
					break;
				case 1:
					fputs("Annex I", fp);
					break;
				case 2:
					fputs("Annex A/L", fp);
					break;
				case 3:
					fputs("Annex M", fp);
					break;
				case 4:
#ifdef RTCONFIG_DSL_TCLINUX
					fputs("Annex A/I/J/L/M", fp);
#elif defined(RTCONFIG_DSL_BCM)
					fputs("Annex A/L/M", fp);
#endif
					break;
				case 5:
					fputs("Annex B", fp);
					break;
				case 6:
					fputs("Annex B/J/M", fp);
					break;
			}

#ifdef RTCONFIG_DSL_TCLINUX
		fputs("\nDynamic Line Adjustment (DLA): ", fp);
		fputs(nvram_safe_get("dslx_dla_enable"), fp);

		fputs("\nStability Adjustment(ADSL): ", fp);
		nValue = nvram_get_int("dslx_snrm_offset");
		if(nValue == 0)
			fprintf(fp, "%d (Disabled)", nValue);
		else
			fprintf(fp, "%d (%d dB)", nValue, nValue/512);

		fputs("\nRx AGC GAIN Adjustment (ADSL): ", fp);
		fputs(nvram_safe_get("dslx_adsl_rx_agc"), fp);

		fputs("\nESNP - Enhanced Sudden Noise Protection (ADSL): ", fp);
		fputs(nvram_safe_get("dslx_adsl_esnp"), fp);

#ifdef RTCONFIG_VDSL
		fputs("\nStability Adjustment(VDSL): ", fp);
		nValue = nvram_get_int("dslx_vdsl_target_snrm");
		if(nValue == 32767)
			fprintf(fp, "%d (Disabled)", nValue);
		else
			fprintf(fp, "%d (%d dB)", nValue, nValue/512);

		fputs("\nG.INP Stability Adjustment: ", fp);
		fputs(nvram_safe_get("dslx_vdsl_ginp"), fp);

		fputs("\nTx Power Control (VDSL): ", fp);
		nValue = nvram_get_int("dslx_vdsl_tx_gain_off");
		if(nValue == 32767)
			fprintf(fp, "%d (Disabled)", nValue);
		else
			fprintf(fp, "%d (%d dB)", nValue, nValue/10);

		fputs("\nRx AGC GAIN Adjustment (VDSL): ", fp);
		nValue = nvram_get_int("dslx_vdsl_rx_agc");
		if(nValue == 65535)
			fprintf(fp, "%d (Default)", nValue);
		else if(nValue == 394)
			fprintf(fp, "%d (Stable)", nValue);
		else if(nValue == 476)
			fprintf(fp, "%d (Balance)", nValue);
		else if(nValue == 550)
			fprintf(fp, "%d (High Performance)", nValue);
		else
			fprintf(fp, "%d", nValue);

		fputs("\nUPBO - Upstream Power Back Off (VDSL): ", fp);
		fputs(nvram_safe_get("dslx_vdsl_upbo"), fp);

		fputs("\nESNP - Enhanced Sudden Noise Protection (VDSL): ", fp);
		fputs(nvram_safe_get("dslx_vdsl_esnp"), fp);

		fputs("\nVDSL Profile: ", fp);
		nValue = nvram_get_int("dslx_vdsl_profile");
		if(nValue == 0)
			fprintf(fp, "%d (30a multi mode)", nValue);
		else if(nValue == 1)
			fprintf(fp, "%d (17a multi mode)", nValue);
		else if(nValue == 2)
			fprintf(fp, "%d (12a multi mode)", nValue);
		else if(nValue == 3)
			fprintf(fp, "%d (8a multi mode)", nValue);
		else
			fprintf(fp, "%d", nValue);
#endif
#elif defined(RTCONFIG_DSL_BCM)
		fputs("\nStability Adjustment(ADSL): ", fp);
		nValue = nvram_get_int("dslx_snrm_offset");
		if(nValue == 0)
			fprintf(fp, "%d (Disabled)", nValue);
		else
			fprintf(fp, "%d (%d dB)", nValue, nValue/16);

		fputs("\nStability Adjustment(VDSL): ", fp);
		nValue = nvram_get_int("dslx_snrm_offset");
		if(nValue == 0)
			fprintf(fp, "%d (Disabled)", nValue);
		else
			fprintf(fp, "%d (%d dB)", nValue, nValue/16);

		fputs("\nVDSL Profile: ", fp);
		nValue = nvram_get_int("dslx_vdsl_profile");
		switch(nValue) {
			case VDSL_PROFILE_ALL:
				fprintf(fp, "%d (multi mode)", nValue);
				break;
			case VDSL_PROFILE_8A:
				fprintf(fp, "%d (8a)", nValue);
				break;
			case VDSL_PROFILE_8B:
				fprintf(fp, "%d (8b)", nValue);
				break;
			case VDSL_PROFILE_8C:
				fprintf(fp, "%d (8c)", nValue);
				break;
			case VDSL_PROFILE_8D:
				fprintf(fp, "%d (8d)", nValue);
				break;
			case VDSL_PROFILE_12A:
				fprintf(fp, "%d (12a)", nValue);
				break;
			case VDSL_PROFILE_12B:
				fprintf(fp, "%d (12b)", nValue);
				break;
			case VDSL_PROFILE_17A:
				fprintf(fp, "%d (17a)", nValue);
				break;
			case VDSL_PROFILE_30A:
				fprintf(fp, "%d (30a)", nValue);
				break;
			case VDSL_PROFILE_35B:
				fprintf(fp, "%d (35b)", nValue);
				break;
			default:
				fprintf(fp, "%d (unknown)", nValue);
				break;
		}
#endif

		fputs("\nSRA (Seamless Rate Adaptation): ", fp);
		fputs(nvram_safe_get("dslx_sra"), fp);

#ifdef RTCONFIG_DSL_TCLINUX
		fputs("\nBitswap (ADSL): ", fp);
		fputs(nvram_safe_get("dslx_bitswap"), fp);

#ifdef RTCONFIG_VDSL
		fputs("\nBitswap (VDSL): ", fp);
		fputs(nvram_safe_get("dslx_vdsl_bitswap"), fp);
#endif

		fputs("\nG.INP: ", fp);
		fputs(nvram_safe_get("dslx_ginp"), fp);

#ifdef RTCONFIG_VDSL
		fputs("\nG.vector: ", fp);
		fputs(nvram_safe_get("dslx_vdsl_vectoring"), fp);
		fputs("\nNon-Standard G.vector: ", fp);
		fputs(nvram_safe_get("dslx_vdsl_nonstd_vectoring"), fp);
#endif
#elif defined(RTCONFIG_DSL_BCM)
		fputs("\nBitswap: ", fp);
		fputs(nvram_safe_get("dslx_bitswap"), fp);

		fputs("\nG.INP: ", fp);
		fputs(nvram_safe_get("dslx_ginp"), fp);
#endif
		fputs("\nMonitor line stability: ", fp);
		if(nvram_match("dsltmp_syncloss", "1")){
			nvram_set("dsltmp_syncloss", "2");
			fputs("2", fp);
		}
		else{
			fputs(nvram_safe_get("dsltmp_syncloss"), fp);
		}
		fprintf(fp, " / %s", nvram_safe_get("dsltmp_syncup_cnt"));

		if(nvram_match("dsltmp_dla_modified", "1")){
			nvram_set("dsltmp_dla_modified", "2");
			fputs(" / 2", fp);
		}
		else{
			fputs(" / 0", fp);
		}

		fputs("\nDSL Line Diagnostic: ", fp);
		fputs(nvram_safe_get("dslx_diag_enable"), fp);
		fputs("\nDiagnostic Duration: ", fp);
		if(!nvram_get_int("dslx_diag_duration")) {
			if(!strncmp(nvram_safe_get("fb_availability"), "Occasional_interruptions", 2))
				fputs("86400", fp);
			else if(!strncmp(nvram_safe_get("fb_availability"), "Frequent_interruptions", 2))
				fputs("43200", fp);
			else
				fputs("3600", fp);
		}
		else {
			fputs(nvram_safe_get("dslx_diag_duration"), fp);
		}
#endif /* RTCONFIG_DSL */

		sysinfo(&info);
		sys_uptime = info.uptime;
#ifdef RTCONFIG_DSL
		dsl_uptime = sys_uptime - nvram_get_int("adsl_timestamp");
#endif

		fputs("\nSystem Up time: ", fp);
		if (sys_uptime > 60*60*24) {
			days = sys_uptime / (60*60*24);
			sys_uptime %= 60*60*24;
		}
		if (sys_uptime > 60*60) {
			hours = sys_uptime / (60*60);
			sys_uptime %= 60*60;
		}
		if (sys_uptime > 60) {
			minutes = sys_uptime / 60;
			sys_uptime %= 60;
		}
		fprintf(fp, "%d days, %d hours, %d minutes, %ld seconds", days, hours, minutes, sys_uptime);

#ifdef RTCONFIG_DSL
		fputs("\nDSL Up time: ", fp);
		if( nvram_match("dsltmp_adslsyncsts", "up") && dsl_uptime > 0){
			days = 0;
			hours = 0;
			minutes = 0;
			if (dsl_uptime > 60*60*24) {
				days = dsl_uptime / (60*60*24);
				dsl_uptime %= 60*60*24;
			}
			if (dsl_uptime > 60*60) {
				hours = dsl_uptime / (60*60);
				dsl_uptime %= 60*60;
			}
			if (dsl_uptime > 60) {
				minutes = dsl_uptime / 60;
				dsl_uptime %= 60;
			}
			fprintf(fp, "%d days, %d hours, %d minutes, %ld seconds", days, hours, minutes, dsl_uptime);
		}
#endif /* RTCONFIG_DSL */

		fputs("\n", fp);

#ifdef RTCONFIG_DSL
		fputs("\nDSL Link Status: ", fp);
		fputs(nvram_safe_get("dsltmp_adslsyncsts"), fp);

		if(nvram_match("dsltmp_adslsyncsts", "up"))
		{
			fputs("\nCurrent DSL Modulation: ", fp);
			fputs(nvram_safe_get("dsllog_opmode"), fp);

			fputs("\nCurrent Annex Mode: ", fp);
			fputs(nvram_safe_get("dsllog_adsltype"), fp);

			fputs("\nCurrent Profile: ", fp);
			fputs(nvram_safe_get("dsllog_vdslcurrentprofile"), fp);

			fputs("\nSNR Down: ", fp);
			fputs(nvram_safe_get("dsllog_snrmargindown"), fp);

			fputs("\nSNR Up: ", fp);
			fputs(nvram_safe_get("dsllog_snrmarginup"), fp);

			fputs("\nLine Attenuation Down: ", fp);
			fputs(nvram_safe_get("dsllog_attendown"), fp);

			fputs("\nLine Attenuation Up: ", fp);
			fputs(nvram_safe_get("dsllog_attenup"), fp);

#if defined(RTCONFIG_DSL_TCLINUX)
			fputs("\nTCM(Trellis Coded Modulation): ", fp);
			fputs(nvram_safe_get("dsllog_tcm"), fp);
#elif defined(RTCONFIG_DSL_BCM)
			fputs("\nTCM(downstream): ", fp);
			fputs(nvram_safe_get("dsllog_tcmdown"), fp);
			fputs("\nTCM(upstream): ", fp);
			fputs(nvram_safe_get("dsllog_tcmup"), fp);
#endif

			fputs("\nPath Mode(downstream): ", fp);
			fputs(nvram_safe_get("dsllog_pathmodedown"), fp);

			fputs("\nInterleave Depth Down: ", fp);
			fputs(nvram_safe_get("dsllog_interleavedepthdown"), fp);

			fputs("\nPath Mode(upstream): ", fp);
			fputs(nvram_safe_get("dsllog_pathmodeup"), fp);

			fputs("\nInterleave Depth Up: ", fp);
			fputs(nvram_safe_get("dsllog_interleavedepthup"), fp);

			fputs("\nData Rate Down: ", fp);
			fputs(nvram_safe_get("dsllog_dataratedown"), fp);

			fputs("\nData Rate Up: ", fp);
			fputs(nvram_safe_get("dsllog_datarateup"), fp);

			fputs("\nMAX Rate Down: ", fp);
			fputs(nvram_safe_get("dsllog_attaindown"), fp);

			fputs("\nMAX Rate Up: ", fp);
			fputs(nvram_safe_get("dsllog_attainup"), fp);

			fputs("\nCRC Down: ", fp);
			fputs(nvram_safe_get("dsllog_crcdown"), fp);

			fputs("\nCRC Up: ", fp);
			fputs(nvram_safe_get("dsllog_crcup"), fp);

			fputs("\nPower Down: ", fp);
			fputs(nvram_safe_get("dsllog_powerdown"), fp);

			fputs("\nPower Up: ", fp);
			fputs(nvram_safe_get("dsllog_powerup"), fp);

#ifdef RTCONFIG_DSL_BCM
			fputs("\nG.INP Down: ", fp);
			fputs(nvram_safe_get("dsllog_ginpdown"), fp);

			fputs("\nG.INP Up: ", fp);
			fputs(nvram_safe_get("dsllog_ginpup"), fp);
#endif

			fputs("\nFar end vendor: ", fp);
			fputs(nvram_safe_get("dsllog_farendvendorid"), fp);

			fputs("\n", fp);
		}
#endif /* RTCONFIG_DSL */

		getUsageStatus(fp);
		if(check_if_file_exist(IPKG_APP_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", IPKG_APP_FILE);

		if(check_if_file_exist(IPKG_CONTROL_FILE))
			snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", IPKG_CONTROL_FILE);

		fprintf(fp, "qos_enable: %s\n", nvram_safe_get("qos_enable"));
		fprintf(fp, "qos_type: %s\n", nvram_safe_get("qos_type"));

		fprintf(fp, "ASUS_EULA: %s\n", nvram_safe_get("ASUS_EULA"));
		fprintf(fp, "aae_support: %s\n", nvram_safe_get("aae_support"));
		fprintf(fp, "aae_enable: %s\n", nvram_safe_get("aae_enable"));
		fprintf(fp, "aae_deviceid: [%s]\n", nvram_safe_get("aae_deviceid"));
		fprintf(fp, "aae_sip_connected: %s\n", nvram_safe_get("aae_sip_connected"));
		fprintf(fp, "aae_status: %s\n", nvram_safe_get("aae_status"));
		fprintf(fp, "aae_sip_last_status: %s\n", nvram_safe_get("aae_sip_last_status"));
		fprintf(fp, "aae_stun_last_status: %s\n", nvram_safe_get("aae_stun_last_status"));
		fprintf(fp, "aae_turn_last_status: %s\n", nvram_safe_get("aae_turn_last_status"));
		fprintf(fp, "DDNS_enable: %d\n", nvram_get_int("ddns_enable_x"));
		fprintf(fp, "Web Access from WAN: %s\n", nvram_safe_get("misc_http_x"));

		fprintf(fp, "aae_sip_last_status: %s\n", nvram_safe_get("aae_sip_last_status"));
		fprintf(fp, "aae_stun_last_status: %s\n", nvram_safe_get("aae_stun_last_status"));
		fprintf(fp, "aae_turn_last_status: %s\n", nvram_safe_get("aae_turn_last_status"));
		fprintf(fp, "[Hardware NAT]\n");
		fprintf(fp, "ctf_disable: %s\n", nvram_safe_get("ctf_disable"));
		fprintf(fp, "ctf_disable_force: %s\n", nvram_safe_get("ctf_disable_force"));
		fprintf(fp, "ctf_fa_mode: %s\n", nvram_safe_get("ctf_fa_mode"));

#if defined(RTCONFIG_BWDPI)
		fprintf(fp, "[TrendMicro]\n");
		fprintf(fp, "functions: %s\n", check_bwdpi_nvram_setting() ? "enable" : "disable");
		sprintf(cmd, "%s", nvram_safe_get("bwdpi_dpi_ver"));
		fprintf(fp, "bwdpi_dpi_ver: %s\n", trimNL(cmd));
		sprintf(cmd, "%s", nvram_safe_get("bwdpi_sig_ver"));
		fprintf(fp, "bwdpi_sig_ver: %s\n", trimNL(cmd));
#endif /* RTCONFIG_BWDPI */

		cmd_pipe = popen("openssl version", "r");
		if(cmd_pipe)
		{
			memset(cmd, 0, sizeof(cmd));
			if(fgets(cmd, sizeof(cmd), cmd_pipe))
			{
				fprintf(fp, "OpenSSL Version: %s\n", trimNL(cmd));
			}
			pclose(cmd_pipe);
		}

		fprintf(fp, "wtf_login: %s\n", nvram_safe_get("wtf_login"));
		fprintf(fp, "wtf_account_type: %s\n", nvram_safe_get("wtf_account_type"));

		cmd_pipe = popen("cat /jffs/.wtfast/version", "r");
		if(cmd_pipe)
		{
			memset(cmd, 0, sizeof(cmd));
			if(fgets(cmd, sizeof(cmd), cmd_pipe))
			{
				fprintf(fp, "gpn-version: %s\n", trimNL(cmd));
			}
			pclose(cmd_pipe);
		}

		nvram_getall_excl_jffs(buf, sizeof(buf));

		for (name = buf; *name; name += strlen(name) + 1)
		{
			;//do nothing
		}
		size = sizeof(struct nvram_header) + (int) (name - buf);
		fprintf(fp, "nvram_used_size: %d bytes (%2.2f%%)\n", size, (100.0*size/MAX_NVRAM_SPACE));
		fprintf(fp, "nvram_free_size: %d bytes\n", MAX_NVRAM_SPACE - size);

#ifdef RTCONFIG_BCMARM
		fprintf(fp, "CPU_Temperature: %.1lf\n", get_cpu_temp());
		if(get_wifi_temps(&wt) == 0)
		{
			fprintf(fp, "WiFi_Temperature(2G/5G/5G2): %.1lf/%.1lf/%.1lf\n", wt.t2g, wt.t5g, wt.t5g2);
		}
		else
		{
			fprintf(fp, "WiFi_Temperature(2G/5G/5G2): 0/0/0\n");
		}
#endif /* RTCONFIG_BCMARM */

		fprintf(fp, "AiMesh_Role: %s\n", nvram_match("cfg_master", "1")?"1":(nvram_match("re_mode", "1")?"0":"-"));
		if(nvram_match("cfg_master", "1"))
		{
			fprintf(fp, "RE_count: %d\n", nvram_get_int("cfg_recount"));
		}

		memset(&wlst, 0, sizeof(wanlan_st_t));
		if(get_wanlanstatus(&wlst))
		{
			_dprintf("wlst.numports22=[%d]\n", wlst.numports);
			if(transform_wanlanstatus(&wlst))
			{
				if(wlst.numports == 5)
				{
					fprintf(fp, "WAN Link Rate: %s\n", wlst.W0);
					fprintf(fp, "LAN Link Rate: %s/%s/%s/%s\n", wlst.L1, wlst.L2, wlst.L3, wlst.L4);
				}
				else if(wlst.numports >= 9 && wlst.numports <= 11)
				{
					if (wlst.numports == 9)
						fprintf(fp, "WAN Link Rate: %s\n", wlst.W0);
					else if (wlst.numports == 10)
						fprintf(fp, "WAN Link Rate: %s/%s\n", wlst.W0, wlst.W1);
					else if (wlst.numports == 11)
						fprintf(fp, "WAN Link Rate: %s/%s/%s\n", wlst.W0, wlst.W1, wlst.W2);
					fprintf(fp, "LAN Link Rate: %s/%s/%s/%s/%s/%s/%s/%s\n", wlst.L1, wlst.L2, wlst.L3, wlst.L4, wlst.L5, wlst.L6, wlst.L7, wlst.L8);
				}
				else
				{
					logmessage("frs_feedback", "The parsed numports=[%d]\n", wlst.numports);
					_dprintf("The parsed numports=[%d]\n", wlst.numports);
				}
			}
			else
			{
				fprintf(fp, "WAN Link Rate: N/A\n");
				fprintf(fp, "LAN Link Rate: N/A\n");
			}
		}
		else
		{
			fprintf(fp, "WAN Link Rate: N/A\n");
			fprintf(fp, "LAN Link Rate: N/A\n");
		}

#ifdef RTAC86U
		/* Wi-Fi PA defect detection */
		fprintf(fp, "[Wi-Fi PA detection]\n");
		i = 0;
		retval = 0;
		while((i < 3)&&((retval=pa_defect_detect(fp, i)) == 0)) {
			i++;
		}
#endif

		if(nvram_safe_get("fb_country") != 0){
			fprintf(fp, "\nCountry/Region: %s\n", nvram_safe_get("fb_country"));
		}

		fprintf(fp, "Preferred_lang: %s\n", nvram_safe_get("preferred_lang"));
		fprintf(fp, "CC(2.4G)/CC(5G)/TC: %s/%s/%s\n", nvram_safe_get("wl0_country_code"),
#if defined(RTCONFIG_HAS_5G)
			nvram_safe_get("wl1_country_code"),
#else
			"N/A",
#endif
			nvram_safe_get("territory_code")
		);

#if defined(BRCM_BASED_MODELS)
		fprintf(fp, "regrev(2.4G)/regrev(5G): %s/%s\n", nvram_safe_get("0:regrev"),
	#if defined(RTCONFIG_HAS_5G)
		nvram_safe_get("1:regrev")
	#else
		"N/A"
	#endif
		);
#endif /* BRCM_BASED_MODELS */

#if defined(RTCONFIG_BCM_7114) || (defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX))
	memset(status_buffer, 0, sizeof(status_buffer));
	get_encrypt_wifi_status(status_buffer, sizeof(status_buffer));
	fprintf(fp, "Wi-Fi status code: %s\n", status_buffer);
	//ASUS proprietary ID
	fprintf(fp, "ASUS_prop_ID_0001: %s/%s/%s\n",
		strlen(nvram_safe_get("wl0_fabid"))?nvram_safe_get("wl0_fabid"):"-",
		strlen(nvram_safe_get("wl1_fabid"))?nvram_safe_get("wl1_fabid"):"-",
		strlen(nvram_safe_get("wl2_fabid"))?nvram_safe_get("wl2_fabid"):"-"
	);
#if defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX) && !defined(RTCONFIG_MFGFW)
	get_bcm4366_PCI_probe_state(fp, buffer, sizeof(buffer));
#endif
#endif

#if defined(RTAX88U)
	memset(status_buffer, 0, sizeof(status_buffer));
	get_encrypt_pcie_status(status_buffer, sizeof(status_buffer));
	fprintf(fp, "PCIE status code: %s\n", status_buffer);
#endif /* RTAX88U */

		fprintf(fp, "Time Zone: %s\n", nvram_safe_get("time_zone_x"));

#ifdef RTCONFIG_DSL
		if(nvram_invmatch("fb_ISP", "")){
			fprintf(fp, "ISP: %s\n", nvram_safe_get("fb_ISP"));
		}
		if(nvram_invmatch("fb_Subscribed_Info", "")){
			fprintf(fp, "Subscribed Package: %s\n", nvram_safe_get("fb_Subscribed_Info"));
		}
#endif /* RTCONFIG_DSL */

		if(nvram_invmatch("fb_email", "")){
			fprintf(fp, "E-mail: %s\n", fb_email);
		}

		if(nvram_invmatch("fb_contact_type", "")){
			fprintf(fp, "User_Contact_Type: %s\n", nvram_safe_get("fb_contact_type"));
		}
		if(nvram_invmatch("fb_phone", "")){
			fprintf(fp, "User_Phone_Number: %s\n", nvram_safe_get("fb_phone"));
		}

		getinfo_transfer_mode(fp);

#ifdef RTCONFIG_DSL
		if(nvram_match("dslx_transmode", "atm")){
			fprintf(fp, "VPI/VCI: %s/%s\n", nvram_safe_get("dsl0_vpi"), nvram_safe_get("dsl0_vci"));
			fprintf(fp, "WAN Connection Type: %s\n", nvram_safe_get("dsl0_proto"));

			nValue = nvram_get_int("dsl0_encap");
			if(nValue)
				fputs("Encapsulation Mode: VC-Mux\n", fp);
			else
				fputs("Encapsulation Mode: LLC\n", fp);
#ifdef RTCONFIG_DSL_TCLINUX
			if(nvram_match("dsl0_dot1q", "1")) {
				fputs("802.1Q: Enabled\n", fp);
				fprintf(fp, "VLAN ID: %s\n", nvram_safe_get("dsl0_vid"));
				fprintf(fp, "802.1P: %s\n", nvram_safe_get("dsl0_dot1p"));
			}
			else {
				fputs("802.1Q: Disabled\n", fp);
			}
#endif
		}
		else{
			fprintf(fp, "WAN Connection Type: %s\n", nvram_safe_get("dsl8_proto"));
			if(nvram_match("dsl8_dot1q", "1")) {
				fputs("802.1Q: Enabled\n", fp);
				fprintf(fp, "VLAN ID: %s\n", nvram_safe_get("dsl8_vid"));
				fprintf(fp, "802.1P: %s\n", nvram_safe_get("dsl8_dot1p"));
			}
			else {
				fputs("802.1Q: Disabled\n", fp);
			}
		}
#endif /* RTCONFIG_DSL */

#ifdef RTCONFIG_DUALWAN
		fprintf(fp, "WAN Interface: %s\n", nvram_safe_get("wans_dualwan"));
		snprintf(cmd, sizeof(cmd), "%s", nvram_safe_get("wans_dualwan"));
		dual_ptr=strstr(cmd, " ");
		if(dual_ptr != NULL)
		{
			*dual_ptr = '\0';
		}
		strcpy(pri_wan, cmd);
		strcpy(sec_wan, dual_ptr+1);
		memset(cmd, 0, sizeof(cmd));

		if(strstr(nvram_safe_get("wans_dualwan"), "none")) //single WAN
		{
			fprintf(fp, "Single WAN Connection Type: %s\n", nvram_safe_get("wan0_proto"));
		}
		else //dual WAN
		{
			fprintf(fp, "Dual WAN Connection Type: %s/%s\n", nvram_safe_get("wan0_proto"), nvram_safe_get("wan1_proto"));
			fprintf(fp, "Dual WAN mode: %s\n", nvram_safe_get("wans_mode"));
			if(( strcmp(nvram_safe_get("wans_mode"), "fo") == 0 ) || ( strcmp(nvram_safe_get("wans_mode"), "fb") == 0 ))
			{
				if( strcmp(nvram_safe_get("wan0_primary"), "1") == 0 ) //primary
				{
					fprintf(fp, "Current working: %s\n", pri_wan);
				}
				else
				{
					fprintf(fp, "Current working: %s\n", sec_wan);
				}
			}
			else
			{
				fprintf(fp, "Load Balance Ratio: %s\n", nvram_safe_get("wans_lb_ratio"));
			}
		}
#else /* products not support dual WAN */
		fprintf(fp, "WAN Interface: %s\n", "Non-dual WAN model");
		fprintf(fp, "Single WAN Connection Type: %s\n", nvram_safe_get("wan0_proto"));
#endif /* RTCONFIG_DUALWAN */

#ifdef RTCONFIG_WIFI_SON
		fprintf(fp, "WiFi SON: %s\n", nvram_safe_get("wifison_ready"));
#endif

#ifdef RTCONFIG_CFGSYNC
		fprintf(fp, "Group Id: %s\n", nvram_safe_get("cfg_group"));
#endif

#ifdef RTCONFIG_DBLOG
		fprintf(fp, "System Diagnostic: %s\n", nvram_safe_get("dblog_enable"));
		fprintf(fp, "Log Duration: %s\n", nvram_safe_get("dblog_duration"));
		fprintf(fp, "Diagnostic Services: %s\n", nvram_safe_get("dblog_service"));
		fprintf(fp, "Store in USB: %s\n", nvram_safe_get("dblog_tousb"));
		fprintf(fp, "Log State: %s\n", nvram_safe_get("dblog_state"));
#endif /* RTCONFIG_DBLOG */

#ifdef RTCONFIG_DBLOG
		if(nvram_match("dblog_enable", "1")){
			fprintf(fp, "Transaction Id: %s\n", nvram_safe_get("dblog_transid"));
			fprintf(fp, "Dblog Remaining Time: %s\n", nvram_safe_get("dblog_remaining"));
		}
#endif /* RTCONFIG_DBLOG */
		fprintf(fp, "Feedback Id: %s\n", nvram_safe_get("fb_transid"));
#ifdef RTCONFIG_DSL
		if(nvram_invmatch("fb_availability", "")){
			fprintf(fp, "DSL connection: %s\n", nvram_safe_get("fb_availability"));
		}
#endif /* RTCONFIG_DSL */
		if(nvram_invmatch("fb_ptype", "")){
			fprintf(fp, "Problem Type: %s\n", nvram_safe_get("fb_ptype"));
		}
		if(nvram_invmatch("fb_pdesc", "")){
			fprintf(fp, "Problem Description: %s\n", nvram_safe_get("fb_pdesc"));
		}

		if(nvram_invmatch("fb_when_occur", "")){
                        fprintf(fp, "When did it occur: %s\n", nvram_safe_get("fb_when_occur"));
                }
		if(nvram_invmatch("fb_which_band", "")){
                        fprintf(fp, "Which band(s): %s\n", nvram_safe_get("fb_which_band"));
                }
		if(nvram_invmatch("fb_unstable_conn", "")){
                        fprintf(fp, "Issue specifically with Wi-Fi or WAN: %s\n", nvram_safe_get("fb_unstable_conn"));
                }

		if(nvram_invmatch("fb_serviceno", "")){
                        fprintf(fp, "ASUS_Service_Number or CRS ID: %s\n", nvram_safe_get("fb_serviceno"));
                }

                if(nvram_invmatch("fb_tech_account", "")){
                        fprintf(fp, "Account_Name_ID: %s\n", nvram_safe_get("fb_tech_account"));
                }

		if(nvram_invmatch("fb_comment", "")){
			fputs("Comments:\n", fp);
			fputs(nvram_safe_get("fb_comment"), fp);
			fputs("\n\n", fp);
		}
		fclose(fp);
	}

	snprintf(cmd, sizeof(cmd), "cp %s %s", FB_FILE, FB_FILE_WEB);
	system(cmd);

#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114)
	if(nvram_match("fb_attach_syslog", "1") || nvram_match("fb_attach_wlanlog", "1"))
	{
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "mkdir -p %s", TRAP_LOG_PATH);
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
#if defined(HND_ROUTER)
		snprintf(cmd, sizeof(cmd), "cp /data/*.tgz %s", TRAP_LOG_PATH);
#elif defined(RTCONFIG_BCM_7114)
		snprintf(cmd, sizeof(cmd), "cp /jffs/config.tgz %s", TRAP_LOG_PATH);
#else
	#error Wrong condition in dsl_fb.c
#endif
		system(cmd);
		if ((dirp = opendir(TRAP_LOG_PATH)) != NULL){
			while((direntp = readdir(dirp)) != NULL){
				if(strstr(direntp->d_name, ".tgz")
					&& (direntp->d_type == DT_REG)
				){
					++count_tgz;
				}
				else{
					continue;
				}
			}

			if(count_tgz > 0){
				filelist_tgz = (char **)malloc(count_tgz*sizeof(char *)+count_tgz*width*sizeof(char));
				if(filelist_tgz){
					for (i = 0, pData = (char *)(filelist_tgz+count_tgz); i < count_tgz; i++, pData += width)
					{
						filelist_tgz[i]=pData;
					}
					rewinddir(dirp);
					i = 0;
					while((direntp = readdir(dirp)) != NULL){
						if(strstr(direntp->d_name, ".tgz")
							&& (direntp->d_type == DT_REG)
						){
							snprintf(filelist_tgz[i++], width, "%s/%s", TRAP_LOG_PATH, direntp->d_name);
							if(i == count_tgz)
							{
								break;
							}
						}
						else{
							continue;
						}
					}
				}
			}
			closedir(dirp);
		}

		trap_log_size = 0;
		for(i = 0;i < count_tgz;++i)
		{
			memset(&st, 0, sizeof(struct stat));
			stat(filelist_tgz[i], &st);
			cprintf("[%s] %d bytes\n", filelist_tgz[i], st.st_size);
			trap_log_size += st.st_size;
		}

		attached_file_size = accumulate_file_size(attach_cmd, sizeof(attach_cmd));
		cprintf("Whole attachment size=[%d] bytes\n", trap_log_size + attached_file_size);
		nvram_set_int("fb_total_size", trap_log_size + attached_file_size);
	} // (fb_attach_syslog == 1) or (fb_attach_wlanlog == 1)

		cprintf("[%s]count_tgz=%d\n", __FUNCTION__, count_tgz);

		processed = 0;
		if(count_tgz == 0)
		{
			retval = do_feedback(FB_FILE, attach_cmd);
			if(retval!=1)
			{
				nvram_set("fb_state", "2");
			}
		}
		else if(count_tgz > 0)
		{
			while((processed < count_tgz)&&(nvram_invmatch("fb_state", "2")))
			{
				while(processed < count_tgz)
				{
					memset(&st, 0, sizeof(struct stat));
					if(filelist_tgz)
					{
						stat(filelist_tgz[processed], &st);
						attached_file_size += st.st_size;
					}
					if(attached_file_size <= 9961472)
					{
						cprintf("===>add file [%s]\n", filelist_tgz[processed]);
						snprintf(attach_cmd + strlen(attach_cmd), sizeof(attach_cmd) - strlen(attach_cmd), "-a %s ", filelist_tgz[processed++]);
					}
					else
					{
						break;
					}
				}

				retval = do_feedback(FB_FILE, attach_cmd);
				if(retval != 1)
				{
					nvram_set("fb_state", "2");
				}

				memset(attach_cmd, 0, sizeof(attach_cmd));
				attached_file_size = 0;
			}

		}
#else /* HND_ROUTER || RTCONFIG_BCM_7114 */
	retval = do_feedback(FB_FILE, attach_cmd);
	if(retval != 1)
	{
		nvram_set("fb_state", "2");
	}
#endif /* HND_ROUTER || RTCONFIG_BCM_7114 */
	if(nvram_match("fb_state", "2")) {
		logmessage("frs_feedback", "Failed to send feedback, start collecting related files for tarball.\n");
		_dprintf("---Collect files for tarball on failed to send case...\n");

		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "cd /tmp; tar zcf %s", FB_TMP_TARBALL);

		if(check_if_file_exist("/tmp/email.log"))
			strcat(cmd, " email.log");

#ifdef RTCONFIG_DSL
		if(check_if_file_exist(LOG_RECORD_FILE))
			strcat(cmd, " adsl/log_record.txt");

		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, SYNC_STATUS_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
		}

		snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, INFO_ADSL_FILE);
		if(check_if_file_exist(filepath))
		{
			snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
		}

		if(check_if_file_exist("/tmp/adsl/dmesg.txt"))
			strcat(cmd, " adsl/dmesg.txt");

		if(check_if_file_exist("/tmp/adsl/currLogFile.txt"))
			strcat(cmd, " adsl/currLogFile.txt");
#endif /* RTCONFIG_DSL */
		if(check_if_file_exist(FREE_FILE))
			strcat(cmd, " free.txt");
		if(check_if_file_exist(IPKG_APP_FILE))
			strcat(cmd, " ipkgapp.txt");
		if(check_if_file_exist(IPKG_CONTROL_FILE))
			strcat(cmd, " ipkg_control.tgz");
		if(check_if_file_exist(TOP_FILE))
			strcat(cmd, " top.txt");
		if(nvram_match("fb_attach_syslog", "1") || nvram_match("fb_attach_wlanlog", "1"))
		{
#if defined(RTCONFIG_CONCURRENTREPEATER) && defined(RTCONFIG_REALTEK)
#if defined(RPAC55)
			if(check_if_file_exist("/tmp/wl0-vxd_sta_info"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "wl0-vxd_sta_info");
			}
			if(check_if_file_exist("/tmp/wl1-vxd_sta_info"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "wl1-vxd_sta_info");
			}
			if(check_if_file_exist("/tmp/wl0-vxd_mib"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "wl0-vxd_mib");
			}
			if(check_if_file_exist("/tmp/wl1-vxd_mib"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "wl1-vxd_mib");
			}
			if(check_if_file_exist("/tmp/wl0-sta_info"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "wl0-sta_info");
			}
			if(check_if_file_exist("/tmp/wl1-sta_info"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "wl1-sta_info");
			}
#endif
#endif
		}

		if(nvram_match("fb_attach_syslog", "1")) {
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, SYSLOG_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			if(check_if_file_exist(WEBSUPG_1_FILE))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " webs_upgrade.log-1");
			}
			if(check_if_file_exist(WEBSUPG_FILE))
				strcat(cmd, " webs_upgrade.log");
		#ifdef RTCONFIG_SYSSTATE
			if(check_if_file_exist(CPUUSAGE_FILE))
				strcat(cmd," asusfbsvcs/cpuusage_log.txt");
			if(check_if_file_exist(RAMUSAGE_FILE))
				strcat(cmd," asusfbsvcs/ramusage_log.txt");
			if(check_if_file_exist(CPUTEMP_FILE))
				strcat(cmd," asusfbsvcs/cputemp_log.txt");
		#endif
			if(check_if_file_exist("/tmp/psInfo.txt"))
				strcat(cmd," psInfo.txt");
			if(check_if_file_exist("/tmp/netstat.txt"))
				strcat(cmd," netstat.txt");
			if(check_if_file_exist("/tmp/var_lock.txt"))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " var_lock.txt");
			}
			snprintf(filepath, sizeof(filepath), "/tmp/%s", JFFS_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", JFFS_LOG);
			}
			snprintf(filepath, sizeof(filepath), "/tmp/%s", TMP_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", TMP_LOG);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, CMD_HISTORY);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", CMD_HISTORY);
			}
			if(check_if_file_exist(WANENV_FILE))
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", WANENV_FILE);
			if(check_if_file_exist(IPV6_FILE))
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", IPV6_FILE);
			if(check_if_file_exist(DUT_HTTPD_FB_DEBUG_1))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " HTTPD_FB_DEBUG.log-1");
			}
			if(check_if_file_exist(DUT_HTTPD_FB_DEBUG))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " HTTPD_FB_DEBUG.log");
			}
		#if defined(BRCM_BASED_MODELS)
			if(check_if_file_exist(CFE_FILE))
				strcat(cmd," cfe.gz");
		#if defined(RTCONFIG_DPSTA)
			if(check_if_file_exist(DPSTA_FILE))
				strcat(cmd," dpsta.log");
		#endif
		#endif
		#ifdef RTCONFIG_CFGSYNC
			if (check_if_file_exist(CFGMNT_FILE))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", "cfgmnt_log.txt");
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, CFG_DBG_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif
		#ifdef RTCONFIG_AHS
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_LOG_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			if(check_if_file_exist(AHS_JSON_FILE))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", AHS_JSON_FILE);
			}
			if(check_if_file_exist(AHS_JSONOBJ_FILE))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", AHS_JSONOBJ_FILE);
			}
			if(check_if_file_exist(AHS_DUMP_FILE))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", AHS_DUMP_FILE);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_LOG_IN_JFFS_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_LOG_IN_JFFS_1_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AHS_HWSW_ST_JFFS_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif /* RTCONFIG_AHS */
		#ifdef RTCONFIG_ASD
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, ASD_LOG_PATH);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, ASD_BK_NAME);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif /*RTCONFIG_ASD*/
		#ifdef RTCONFIG_SOFTWIRE46
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, S46_LOG_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif
		#ifdef RTCONFIG_FSMD
			if(check_if_file_exist(JFFS_USAGE_FILE))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", JFFS_USAGE_FILE);
			}
		#endif
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, WGET_LOG_PATH);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#ifdef RTCONFIG_BWDPI
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, BWDPI_SIG_UPG_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif /* RTCONFIG_BWDPI */
		#ifdef RTCONFIG_STRONGSWAN
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, SS_CHARON_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif /* RTCONFIG_STRONGSWAN */
		#ifdef RTCONFIG_UPNPC_NEW
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, IPSEC_UPNPC_LIST);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, IPSEC_UPNPC_WDG_LIST);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif /* RTCONFIG_UPNPC_NEW */
		#ifdef RTCONFIG_QCA_PLC2
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, PLC_LOG_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		#endif /* RTCONFIG_QCA_PLC2 */
			snprintf(filepath, sizeof(filepath), "%s/%s.txt", DUP_LOG_PATH, DHCP_LEASES_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, ARP_OUTPUT_FILE);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		}

		if(nvram_match("fb_attach_cfgfile", "1")) {
			if(check_if_file_exist("/tmp/settings"))
				strcat(cmd, " settings");
		}

#ifdef RTCONFIG_DSL
		if(nvram_match("fb_attach_iptables", "1")) {
			if(check_if_file_exist("/tmp/fb_iptables.txt"))
				strcat(cmd, " fb_iptables.txt");
		}
#endif /* RTCONFIG_DSL */

		if(nvram_match("fb_attach_modemlog", "1")) {
			if(check_if_file_exist("/tmp/modemlog.txt"))
				strcat(cmd, " modemlog.txt");
		}

		if(nvram_match("fb_attach_wlanlog", "1")) {
			if(check_if_file_exist(WLANLOG_FILE))
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", WLANLOG_FILE);

			snprintf(filepath, sizeof(filepath), "%s/%s.tar.gz", DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, JFFS_AMAS_SITE_SURVEY_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, JFFS_AMAS_WLCCONNECT_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
			snprintf(filepath, sizeof(filepath), "%s/%s", DUP_LOG_PATH, AMAS_AVBLCHAN_LOG);
			if(check_if_file_exist(filepath))
			{
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filepath);
			}
		}

#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114) || defined(RTCONFIG_BCM4708)
		if(nvram_match("fb_attach_wlanlog", "1")){
			char word[128], *next;
			char file[256];
			int unit = -1, vif = 0;
			char tmp[256], vif_name[] = "wlXXXXXXXXXX";
#ifdef RTCONFIG_BCM_HND_CRASHLOG
			if(check_if_file_exist(CRASHLOG_FILE))
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", CRASHLOG_FILE);
#endif
			foreach (word, nvram_safe_get("wl_ifnames"), next) {
			    unit++;
			    snprintf(vif_name, sizeof(vif_name), "wl%d.1", unit);
			    vif = (nvram_get_int("re_mode") & nvram_get_int(strcat_r(vif_name, "_bss_enabled", tmp)));
			    snprintf(file, sizeof(file), "/tmp/WlGetDriverStats_%s.log", vif?vif_name:word);
			    if (check_if_file_exist(file))
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", file);
			}
		}
#endif
#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114)
		for(i = 0; i < count_tgz; ++i)
		{
			if(check_if_file_exist(filelist_tgz[i]))
				snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " %s", filelist_tgz[i]);
		}
#endif /* HND_ROUTER || RTCONFIG_BCM_7114 */
		system(cmd);

		// 1: Collect data in /tmp/fb_data_tmp.tgz
		// 2: Encrypt /tmp/fb_data_tmp.tgz, output file = /tmp/fb_data.tgz
		// 3: gzip the /tmp/fb_data.tgz, it becomes /tmp/fb_data.tgz.gz
		encryptBinaryfile(FB_TMP_TARBALL, FB_TARBALL, nvram_safe_get("productid"));
		if(!nvram_match("fb_from", "app")) unlink(FB_TMP_TARBALL);

		nvram_unset("fb_from");

		if(check_if_file_exist(FB_TARBALL))
		{
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "/bin/rm -f %s.gz;/bin/gzip %s", FB_TARBALL, FB_TARBALL);
			system(cmd);

			memset(&st, 0, sizeof(struct stat));
			memset(cmd, 0, sizeof(cmd));
			snprintf(cmd, sizeof(cmd), "%s.gz", FB_TARBALL);
			stat(cmd, &st);
			cprintf("FB_TARBALL=%d bytes\n", st.st_size);
			cprintf("FB_TARBALL=%d Mbytes\n", st.st_size/1048576);
			if(st.st_size/1048576 >=8)
			{
				nvram_set_int("fb_split_files", 1+ (st.st_size/1048576)/8);

				//split files.
				memset(cmd, 0, sizeof(cmd));
				//fb_data.tgz.gz.parta, fb_data.tgz.gz.partb, ...
				snprintf(cmd, sizeof(cmd), "split -b 8m -a 1 %s.gz %s.gz.part.", FB_TARBALL, FB_TARBALL);
				system(cmd);
			}
		}
	}
	else {
		logmessage("frs_feedback", "Send feedback successfully.\n");
		nvram_set("fb_state", "1");
	}

#ifdef RTCONFIG_DSL
	//diag
	if(nvram_match("dslx_diag_enable", "1")) {
		start_dsl_diag();
	}
	else {
		nvram_set("dslx_diag_state", "0");
	}
#endif /* RTCONFIG_DSL */

	unlink(FB_FILE);
	unlink(TOP_FILE);
	unlink(FREE_FILE);
	unlink(IPKG_APP_FILE);
	unlink(IPKG_CONTROL_FILE);
	unlink(WLANLOG_FILE);
	unlink(WEBSUPG_1_FILE);
	unlink(WEBSUPG_FILE);
#ifdef RTCONFIG_DSL
	unlink(LOG_RECORD_FILE);
	unlink(IPTABLES_FILE);
	unlink("/tmp/adsl/dmesg.txt");
	unlink("/tmp/adsl/currLogFile.txt");
	unlink("/tmp/adsl/currLogFile.txt");
#endif /* RTCONFIG_DSL */
	unlink("/tmp/preScript.sh");
	unlink("/tmp/proc.tmp");
	unlink("/tmp/psInfo.txt");
	unlink("/tmp/netstat.txt");
	unlink("/tmp/var_lock.txt");
	snprintf(filepath, sizeof(filepath), "/tmp/%s", JFFS_LOG);
	unlink(filepath);
	snprintf(filepath, sizeof(filepath), "/tmp/%s", TMP_LOG);
	unlink(filepath);
	unlink(WANENV_FILE);
	unlink(IPV6_FILE);
	unlink(DUT_HTTPD_FB_DEBUG_1);
	unlink(DUT_HTTPD_FB_DEBUG);
#ifdef RTCONFIG_SYSSTATE
	unlink(CPUUSAGE_FILE);
	unlink(RAMUSAGE_FILE);
	unlink(CPUTEMP_FILE);
#endif /* RTCONFIG_SYSSTATE */
#ifdef RTCONFIG_AHS
	snprintf(filepath, sizeof(filepath), "/tmp/%s", AHS_LOG_FILE);
	unlink(filepath);
	snprintf(filepath, sizeof(filepath), "/tmp/%s", AHS_LOG_1_FILE);
	unlink(filepath);
	unlink(AHS_JSON_FILE);
	unlink(AHS_JSONOBJ_FILE);
	unlink(AHS_DUMP_FILE);
#endif /* RTCONFIG_AHS */
#ifdef RTCONFIG_ASD
	snprintf(filepath, sizeof(filepath), "/jffs/%s", ASD_LOG_PATH);
	unlink(filepath);
	snprintf(filepath, sizeof(filepath), "/jffs/%s", ASD_BK_LOG_PATH);
	unlink(filepath);
	snprintf(filepath, sizeof(filepath), "rm -rf %s", ASD_BK_DIR);
	system(filepath);
#endif
#ifdef RTCONFIG_FSMD
	//unlink(JFFS_USAGE_FILE);
#endif
	snprintf(filepath, sizeof(filepath), "/jffs/%s", WGET_LOG_PATH);
	unlink(filepath);
	snprintf(filepath, sizeof(filepath), "/jffs/%s", WGET_BK_LOG_PATH);
	unlink(filepath);
#ifdef RTCONFIG_BWDPI
	snprintf(filepath, sizeof(filepath), "/tmp/%s", BWDPI_SIG_UPG_LOG);
	unlink(filepath);
#endif /* RTCONFIG_BWDPI */
#if defined(BRCM_BASED_MODELS)
	unlink(CFE_FILE);
#if defined(RTCONFIG_DPSTA)
	unlink(DPSTA_FILE);
#endif
#endif
#ifdef RTCONFIG_LANTIQ
	unlink(WIFI_DB1_FILE);
	unlink(WIFI_DB2_FILE);
	unlink(WIFI_DB3_FILE);
#endif
#ifdef RTCONFIG_BCM_HND_CRASHLOG
	unlink(CRASHLOG_FILE);
#endif
#if defined(RTCONFIG_QCA)
	unlink("/tmp/" WIFI_AP_STATS_LOG);
	unlink("/tmp/" WIFI_STA_STATS_LOG);
#endif
#if defined(RTCONFIG_SWITCH_QCA8075_QCA8337_PHY_AQR107_AR8035_QCA8033)
	unlink("/tmp/"SWITCH_LOG);
#endif

	snprintf(filepath, sizeof(filepath), "%s/%s.tar.gz", DUP_LOG_PATH, CONN_DIAG_LOG_DST_FOLDER);
	if(check_if_file_exist(filepath))
	{
		unlink(filepath);
	}

#if defined(RTCONFIG_CONCURRENTREPEATER) && defined(RTCONFIG_REALTEK)
#if defined(RPAC55)
	unlink("/tmp/wl0-vxd_sta_info");
	unlink("/tmp/wl1-vxd_sta_info");
	unlink("/tmp/wl0-vxd_mib");
	unlink("/tmp/wl1-vxd_mib");
	unlink("/tmp/wl0-sta_info");
	unlink("/tmp/wl1-sta_info");
#endif
#endif

#if defined(HND_ROUTER) || defined(RTCONFIG_BCM_7114)
		for(i = 0; i < count_tgz; ++i)
		{
			unlink(filelist_tgz[i]);
		}
		if(filelist_tgz)
		{
			free(filelist_tgz);
			filelist_tgz = NULL;
		}
#endif /* HND_ROUTER || RTCONFIG_BCM_7114 */
	snprintf(cmd, sizeof(cmd), "rm -rf %s", DUP_LOG_PATH);
	system(cmd);
	logmessage("frs_feedback", "start_sendfeedback() end...\n");
#ifdef RTCONFIG_DBLOG
	if(nvram_match("dblog_enable", "1")) {
		cprintf("[%s]start_dblog\n", __FUNCTION__);
		logmessage("frs_feedback", "start_dblog(1)\n");
#ifdef RTCONFIG_HND_ROUTER
		if(dblog_service & DBLOG_ENABLE_DHD)
		{
			nvram_set("dhd_msg_level", "1");
			nvram_set("dblog_adj_syslog", "1");
			logmessage("frs_feedback", "Enable Wi-Fi DHD log flag...\n");
			nvram_commit();
		}
#endif /* RTCONFIG_HND_ROUTER */
		start_dblog(1);
	}
#endif /* RTCONFIG_DBLOG */
#ifdef RTCONFIG_DBLOG
	if(nvram_match("dblog_adj_syslog", "1"))
	{
		//'dblog_adj_syslog' will be reset to 0 in rc/services.c
		logmessage("frs_feedback", "reboot for enabling Wi-Fi DHD log...\n");
		sleep(5);
		system("reboot");
	}
#endif /* RTCONFIG_DBLOG */
}

#ifdef RTCONFIG_DBLOG
enum {
	DBLOG_STATE_INIT = 0
	,DBLOG_STATE_RUN = 1
	,DBLOG_STATE_REBOOT = 2
	,DBLOG_STATE_PAUSE = 3
	,DBLOG_STATE_STOP = 4
	,DBLOG_STATE_FINISH = 5
	,DBLOG_STATE_SENDMAIL_SUCCESS
	,DBLOG_STATE_SENDMAIL_FAIL_SMTP
	,DBLOG_STATE_SENDMAIL_FAIL_DISK_SPACE
	,DBLOG_STATE_SENDMAIL_FAIL_OTHER
	,DBLOG_STATE_ERR_USB
	,DBLOG_STATE_ERR_OTHERS
}; //should sync with dblog/daemon/dblog.c

void start_senddblog(char *path)
{
	FILE *fp;
	char cmd[1024] = {0};
	char attach_cmd[512] = {0};
	char diag_log_dir[256] = {0};
	char file_path[512] = {0};
	struct stat st;
	struct dirent *direntp;
	int retval = 0;
	DIR *dirp;
	int split_flag = 0;
	char *ptr = NULL;
	char *skip_file = NULL;
	char fb_email[64]={0};

	logmessage("senddblog", "start_senddblog() start...\n");
	if (strchr(nvram_safe_get("fb_email"), '`') == NULL)
		strlcpy(fb_email, nvram_safe_get("fb_email"), sizeof(fb_email));

	if(check_if_file_exist(path))
	{
		snprintf(attach_cmd, sizeof(attach_cmd), "-a %s", path);
	}
	else
	{
		logmessage("senddblog", "No dblog file!\n");
		nvram_set_int("dblog_state", DBLOG_STATE_SENDMAIL_FAIL_OTHER);
		return;
	}

	snprintf(diag_log_dir, sizeof(diag_log_dir), "%s", path);
	ptr = strrchr(diag_log_dir, '/');
	if(ptr)
	{
		skip_file = ptr +1;
		*ptr = '\0';
	}

	nvram_set("fb_state", "0");

	//mail content
	fp = fopen(DBLOG_CONTENT, "w");
	if(fp) {
		fputs("SYSTEM DEBUG LOG\n----------------------------------------------------------------------------------------------------------------\n\n", fp);
		fputs("Model: ", fp);
		fputs(get_productid(), fp);

		fputs("\nFirmware Version: ", fp);
		fprintf(fp, "%s.%s_%s", nvram_safe_get("firmver"), nvram_safe_get("buildno"), nvram_safe_get("extendno"));

		fputs("\nInner Version: ", fp);
		fputs(nvram_safe_get("innerver"), fp);

#ifdef RTCONFIG_DSL
		fputs("\nDSL Firmware Version: ", fp);
		fputs(nvram_safe_get("dsllog_fwver"), fp);

		fputs("\nDSL Driver Version: ", fp);
		fputs(nvram_safe_get("dsllog_drvver"), fp);
#endif /* RTCONFIG_DSL */

#if 0
		fputs("\nPIN Code: ", fp);
		fputs(nvram_safe_get("wps_device_pin"), fp);
#endif

		fputs("\nMAC Address: ", fp);
		fputs(get_label_mac(), fp);
#if defined(MAPAC2200) || defined(MAPAC1300) || defined(VZWAC1300) || defined(SHAC1300) || defined(MAPAC2200V)
/* for Lyra series */
		fputs("\nMAC_WAN_Address: ", fp);
		fputs(get_lan_hwaddr(), fp);
#endif

		fprintf(fp, "\nSystem debug log capture duration: %d hrs\n", nvram_get_int("dblog_duration")/3600);

#ifdef RTCONFIG_CFGSYNC
		fprintf(fp, "Group Id: %s\n", nvram_safe_get("cfg_group"));
#endif
		fprintf(fp, "System Diagnostic: %s\n", nvram_safe_get("dblog_enable"));
		fprintf(fp, "Transaction Id: %s\n", nvram_safe_get("dblog_transid"));
		fprintf(fp, "Dblog Remaining Time: %s\n", nvram_safe_get("dblog_remaining"));

#ifdef RTCONFIG_DSL
		if(nvram_invmatch("fb_ISP", "")){
			fprintf(fp, "ISP: %s\n", nvram_safe_get("fb_ISP"));
		}
		if(nvram_invmatch("fb_Subscribed_Info", "")){
			fprintf(fp, "Subscribed Package: %s\n", nvram_safe_get("fb_Subscribed_Info"));
		}
#endif /* RTCONFIG_DSL */

		fprintf(fp, "E-mail: %s\n", fb_email);

		if(nvram_invmatch("fb_contact_type", "")){
			fprintf(fp, "User_Contact_Type: %s\n", nvram_safe_get("fb_contact_type"));
		}
		if(nvram_invmatch("fb_phone", "")){
			fprintf(fp, "User_Phone_Number: %s\n", nvram_safe_get("fb_phone"));
		}

#ifdef RTCONFIG_DSL
		if(nvram_invmatch("fb_availability", "")){
			fprintf(fp, "DSL connection: %s\n", nvram_safe_get("fb_availability"));
		}
#endif /* RTCONFIG_DSL */

		if(nvram_invmatch("fb_ptype", "")){
			fprintf(fp, "Problem Type: %s\n", nvram_safe_get("fb_ptype"));
		}
		if(nvram_invmatch("fb_pdesc", "")){
			fprintf(fp, "Problem Description: %s\n", nvram_safe_get("fb_pdesc"));
		}

		if(nvram_invmatch("fb_when_occur", "")){
			fprintf(fp, "When did it occur: %s\n", nvram_safe_get("fb_when_occur"));
		}
		if(nvram_invmatch("fb_which_band", "")){
			fprintf(fp, "Which band(s): %s\n", nvram_safe_get("fb_which_band"));
		}
		if(nvram_invmatch("fb_unstable_conn", "")){
			fprintf(fp, "Issue specifically with Wi-Fi or WAN: %s\n", nvram_safe_get("fb_unstable_conn"));
		}

		if(nvram_invmatch("fb_serviceno", "")){
			fprintf(fp, "ASUS_Service_Number or CRS ID: %s\n", nvram_safe_get("fb_serviceno"));
		}

		if(nvram_invmatch("fb_tech_account", "")){
			fprintf(fp, "Account_Name_ID: %s\n", nvram_safe_get("fb_tech_account"));
		}

		fclose(fp);
	}

	//split if necessary
	stat(path, &st);
	if(st.st_size > 2*1048576) {
		//split log file
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "split -b 2m -a 1 %s %s.", path, path);//sysdblog00001.tgz.a, sysdblog00001.tgz.b, ...
		//snprintf(cmd, sizeof(cmd), "split -b 800k -a 1 %s %s.;ls -al %s;", path, path, diag_log_dir);//sysdblog00001.tgz.a, sysdblog00001.tgz.b, ...
		retval = system(cmd);
		if(retval) {
			logmessage("senddblog", "Failed to split log file!\n");
			nvram_set_int("dblog_state", DBLOG_STATE_SENDMAIL_FAIL_DISK_SPACE);
			return;
		}
		split_flag = 1;
	}

	//send multiple feedback mail if necessary
	if ((dirp = opendir(diag_log_dir)) == NULL) {
		logmessage("senddblog", "Open Directory %s Error: %s\n", diag_log_dir, strerror(errno));
		nvram_set_int("dblog_state", DBLOG_STATE_SENDMAIL_FAIL_OTHER);
		return;
	}
	while((direntp = readdir(dirp)) != NULL) {
		if(strstr(direntp->d_name, "sysdblog")) {
			if(split_flag && strcmp(direntp->d_name, skip_file) == 0)	//skip sysdblog00001.tgz if is splitted
			{
				continue;
			}

			snprintf(file_path, sizeof(file_path), "%s/%s", diag_log_dir, direntp->d_name);

			char attach_cmd[MAX_BUF_LEN] = {0};
			snprintf(attach_cmd, sizeof(attach_cmd), "-a %s", file_path);
			retval = do_feedback(DBLOG_CONTENT, attach_cmd);

			if(retval != 1) {
				//sent failed
				logmessage("senddblog", "Send Diagnostic Log failed\n");
				nvram_set_int("dblog_state", DBLOG_STATE_SENDMAIL_FAIL_SMTP);
				closedir(dirp);
				nvram_set("fb_state", "2");
				return;
			}
			unlink(file_path);
		}
		else {
			continue;
		}
	}
	closedir(dirp);

	nvram_set_int("dblog_state", DBLOG_STATE_SENDMAIL_SUCCESS);
	nvram_set("fb_state", "1");
	unlink(DBLOG_CONTENT);
	unlink(path);
	nvram_commit();
	logmessage("senddblog", "start_senddblog() end...\n");
}
#endif /* RTCONFIG_DBLOG */

#ifdef RTCONFIG_DSL
enum {
	DSL_DIAG_STATE_NONE=0,
	DSL_DIAG_STATE_START,
	DSL_DIAG_STATE_TASK_COMPLETE,
	DSL_DIAG_STATE_SENDMAIL_SUCCESS,
	DSL_DIAG_STATE_SENDMAIL_FAIL_SMTP,
	DSL_DIAG_STATE_SENDMAIL_FAIL_DISK_SPACE,
	DSL_DIAG_STATE_DUMP_LOG_FAIL,
	DSL_DIAG_STATE_SENDMAIL_FAIL_OTHER	//debug only.
};

void start_sendDSLdiag(void)
{
	FILE *fp;
	char cmd[1024] = {0};
	char diag_log_dir[256] = {0};
	char file_path[512] = {0};
	struct stat st;
	int retval = 0;
	DIR *dirp;
	struct dirent *direntp;
	int split_flag = 0;
	char fb_email[64]={0};
	char log_from[32]={0};
	CURLcode res=CURLE_OK;
	struct sysinfo si;
	long dsl_uptime = 0;
	int days = 0, hours = 0, minutes = 0;

	logmessage("sendDSLdiag", "start_sendDSLdiag() start...\n");
	if (strchr(nvram_safe_get("fb_email"), '`') == NULL)
		strlcpy(fb_email, nvram_safe_get("fb_email"), sizeof(fb_email));

	snprintf(diag_log_dir, sizeof(diag_log_dir), "%s/%s", nvram_safe_get("dsltmp_diag_log_path"), DSL_DIAG_DIR);
	snprintf(file_path, sizeof(file_path), "%s/%s", diag_log_dir, DSL_DIAG_FILE);
	if(!check_if_file_exist(file_path)) {
		memset(file_path, 0, sizeof(file_path));
		snprintf(file_path, sizeof(file_path), "/mnt/%s/%s/%s", nvram_safe_get("usb_path1_fs_path0"), DSL_DIAG_DIR, DSL_DIAG_FILE);
		if(!check_if_file_exist(file_path)) {
			logmessage("sendDSLdiag", "No diagnostic file!\n");
			return;
		}
	}

	nvram_set("fb_state", "0");

	//mail content
	fp = fopen(FB_FILE, "w");
	if(fp) {
		fputs("DSL DIAGNOSTIC LOG\n----------------------------------------------------------------------------------------------------------------\n\n", fp);
		fputs("Model: ", fp);
		fputs(get_productid(), fp);

		fputs("\nFirmware Version: ", fp);
		fprintf(fp, "%s.%s_%s", nvram_safe_get("firmver"), nvram_safe_get("buildno"), nvram_safe_get("extendno"));

		fputs("\nInner Version: ", fp);
		fputs(nvram_safe_get("innerver"), fp);

		fputs("\nDSL Firmware Version: ", fp);
		fputs(nvram_safe_get("dsllog_fwver"), fp);

		fputs("\nDSL Driver Version: ", fp);
		fputs(nvram_safe_get("dsllog_drvver"), fp);

#if 0
		fputs("\nPIN Code: ", fp);
		fputs(nvram_safe_get("wps_device_pin"), fp);
#endif

		fputs("\nMAC Address: ", fp);
		fputs(get_label_mac(), fp);
#if defined(MAPAC2200) || defined(MAPAC1300) || defined(VZWAC1300) || defined(SHAC1300) || defined(MAPAC2200V)
/* for Lyra series */
		fputs("\nMAC_WAN_Address: ", fp);
		fputs(get_lan_hwaddr(), fp);
#endif

		fprintf(fp, "\nDiagnostic debug log capture duration: %d hrs", nvram_get_int("dslx_diag_duration")/3600);

		fputs("\nDSL connection: ", fp);
		fputs(nvram_safe_get("fb_availability"), fp);

		sysinfo(&si);
		dsl_uptime = si.uptime - nvram_get_int("adsl_timestamp");
		fputs("\nDSL Up time: ", fp);
		if( nvram_match("dsltmp_adslsyncsts", "up") && dsl_uptime > 0){
			days = 0;
			hours = 0;
			minutes = 0;
			if (dsl_uptime > 60*60*24) {
				days = dsl_uptime / (60*60*24);
				dsl_uptime %= 60*60*24;
			}
			if (dsl_uptime > 60*60) {
				hours = dsl_uptime / (60*60);
				dsl_uptime %= 60*60;
			}
			if (dsl_uptime > 60) {
				minutes = dsl_uptime / 60;
				dsl_uptime %= 60;
			}
			fprintf(fp, "%d days, %d hours, %d minutes, %ld seconds", days, hours, minutes, dsl_uptime);
		}

		fputs("\nCRC Down: ", fp);
		fputs(nvram_safe_get("dsllog_crcdown"), fp);

		fputs("\nCRC Up: ", fp);
		fputs(nvram_safe_get("dsllog_crcup"), fp);

		fputs("\nE-mail: ", fp);
		fputs(fb_email, fp);

		if(nvram_invmatch("fb_contact_type", "")){
			fprintf(fp, "User_Contact_Type: %s\n", nvram_safe_get("fb_contact_type"));
		}
		if(nvram_invmatch("fb_phone", "")){
			fprintf(fp, "User_Phone_Number: %s\n", nvram_safe_get("fb_phone"));
		}

		fclose(fp);
	}

	snprintf(cmd, sizeof(cmd), "cp %s %s", FB_FILE, FB_FILE_WEB);
	system(cmd);

	//compress log file
	retval = eval("gzip", "-f", file_path);
	if(retval) {
		logmessage("sendDSLdiag", "Failed to compress log file!\n");
		nvram_set_int("dslx_diag_state", DSL_DIAG_STATE_SENDMAIL_FAIL_DISK_SPACE);
		return;
	}
	strcat(file_path, ".gz");

	//split if necessary
	stat(file_path, &st);
	if(st.st_size > 8*1048576) {
		//split log file
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd), "split -b 8m -a 1 %s %s.", file_path, file_path);//xxx.gz.a, xxx.gz.b, ...
		retval = system(cmd);
		if(retval) {
			logmessage("sendDSLdiag", "Failed to split log file!\n");
			nvram_set_int("dslx_diag_state", DSL_DIAG_STATE_SENDMAIL_FAIL_DISK_SPACE);
			return;
		}
		split_flag = 1;
	}

	//send multiple feedback mail if necessary
	if ((dirp = opendir(diag_log_dir)) == NULL) {
		logmessage("sendDSLdiag", "Open Directory %s Error: %s\n", diag_log_dir, strerror(errno));
		nvram_set_int("dslx_diag_state", DSL_DIAG_STATE_SENDMAIL_FAIL_OTHER);
		return;
	}
	while((direntp = readdir(dirp)) != NULL) {
		snprintf(file_path, sizeof(file_path), "%s.gz", DSL_DIAG_FILE);
		if(strstr(direntp->d_name, file_path)
			//&& direntp->d_type == DT_REG
		) {
			if(split_flag && strlen(direntp->d_name) == strlen(file_path))	//skip xx.gz if is splitted
				continue;

			snprintf(file_path, sizeof(file_path), "%s/%s", diag_log_dir, direntp->d_name);
			snprintf(log_from, sizeof(log_from), "Diagnostic Log");
			res = send_feedback_curl_retry(log_from, FB_FILE, file_path, 5);

			if(res != CURLE_OK) {
				//sent failed
				logmessage("sendDSLdiag", "Send Diagnostic Log failed\n");
				nvram_set_int("dslx_diag_state", DSL_DIAG_STATE_SENDMAIL_FAIL_SMTP);
				nvram_set("fb_state", "2");
				return;
			}
			unlink(file_path);
		}
		else {
			continue;
		}
	}
	closedir(dirp);

	//sent sucessfully
	nvram_set_int("dslx_diag_state", DSL_DIAG_STATE_SENDMAIL_SUCCESS);
	nvram_set("fb_state", "1");
	unlink(FB_FILE);
	logmessage("sendDSLdiag", "start_sendDSLdiag() end...\n");
}
#endif

int countChar(char *str, char c)
{
	char *ptr = NULL;
	int num = 0;

	if(!str)
		return 0;

	ptr = str;
	while(*ptr != '\0')
	{
		if(*ptr == c)
		{
			num++;
		}
		ptr++;
	}

	return num;
}

void getUsageStatus(FILE *fp)
{
	FILE *ifp = NULL;
	char tmp_val[80] = {0};
	int statDownloadMaster = 0, statapp_ms=0, statapp_ai=0;
	char verDownloadMaster[80] = {0};
	char tmp_output[256] = {0};
	int unit __attribute__((unused)) = 1, wgs_enable __attribute__((unused)) = 0, wgc_enable = 0;

	if(!fp)
	{
		return;
	}
#if defined (RTCONFIG_USB)
	ifp = fopen("/opt/lib/ipkg/status", "r");
	if(ifp)
	{
		while(fgets(tmp_val, 80, ifp))
		{
			if(strstr(tmp_val, "downloadmaster"))
			{
				statDownloadMaster = 1; //installed
				fgets(tmp_val, 80, ifp);
				if((tmp_val[strlen(tmp_val)-1] == '\r')||(tmp_val[strlen(tmp_val)-1] == '\n'))
				{
					tmp_val[strlen(tmp_val)-1] = '\0';
				}
				snprintf(verDownloadMaster, 80, "%s", tmp_val + strlen("Version: ") );
				//break;
			} else if (strstr(tmp_val, "mediaserver")){

				statapp_ms = 1;

			} else if (strstr(tmp_val, "aicloud")){

				statapp_ai = 1;

				}
		}
		fclose(ifp);
	}

	if(statDownloadMaster || statapp_ms || statapp_ai){

		 system("echo \"--------ls -al /opt/bin/:\" > /tmp/ipkgapp.txt" );
		 system("ls -al /opt/bin/ >> /tmp/ipkgapp.txt" );

		 system("echo \"\n--------ls -al /opt/lib/:\" >>/tmp/ipkgapp.txt" );
		 system("ls -al /opt/lib/ >>/tmp/ipkgapp.txt" );

		 system("tar -zcvf /tmp/ipkg_control.tgz /opt/lib/ipkg/info/*.control" );

	}

	if(statDownloadMaster == 1)
	{
		ifp = fopen("/opt/lib/ipkg/info/downloadmaster.control", "r");
		if(ifp)
		{
			while(fgets(tmp_val, 80, ifp))
			{
				if(strstr(tmp_val, "Enabled"))
				{
					if(strstr(tmp_val, "yes"))
					{
						statDownloadMaster = 2; //installed and enabled
					}
					else
					{
						statDownloadMaster = 3; //installed but disabled
					}
				}
			}
			fclose(ifp);
		}
	}

	fputs("\nDownload Master: ", fp);
	if(statDownloadMaster == 1)
	{
		fputs(verDownloadMaster, fp);
		fputs("(", fp);
		fputs("Unknown status", fp);
		fputs(")", fp);
	}
	else if(statDownloadMaster == 2)
	{
		fputs(verDownloadMaster, fp);
		fputs("(", fp);
		fputs("Enabled", fp);
		fputs(")", fp);
	}
	else if(statDownloadMaster == 3)
	{
		fputs(verDownloadMaster, fp);
		fputs("(", fp);
		fputs("Disabled", fp);
		fputs(")", fp);
	}
	else
	{
		fputs("N/A", fp);
	}

	fputs("\nMinidlna Version: ", fp);
	ifp = popen("minidlna -V", "r");
	if(ifp)
	{
		memset(tmp_val, 0, sizeof(tmp_val));
		if(fgets(tmp_val, sizeof(tmp_val), ifp))
		{
			fputs(trimNL(tmp_val), fp);
		}
		pclose(ifp);
	}

	fputs("\nCloud Disk: ", fp);
	fputs((nvram_get_int("webdav_aidisk") == 1) ? "Enabled" : "Disabled", fp);

	fputs("\nSmart Access: ", fp);
	fputs((nvram_get_int("webdav_proxy") == 1) ? "Enabled" : "Disabled", fp);

	fputs("\nSmart Sync: ", fp);
	fputs((nvram_get_int("enable_cloudsync") == 1) ? "Enabled" : "Disabled", fp);
#endif /* RTCONFIG_USB */

	fputs("\nGuest Network 1/2/3 (2.4G): ", fp);
	fputs(nvram_safe_get("wl0.1_bss_enabled"), fp);
	fputs("/", fp);
	fputs(nvram_safe_get("wl0.2_bss_enabled"), fp);
	fputs("/", fp);
	fputs(nvram_safe_get("wl0.3_bss_enabled"), fp);

	if(strstr(nvram_safe_get("rc_support") ,"5G"))
	{
		fputs("\nGuest Network 1/2/3 (5G): ", fp);
		fputs(nvram_safe_get("wl1.1_bss_enabled"), fp);
		fputs("/", fp);
		fputs(nvram_safe_get("wl1.2_bss_enabled"), fp);
		fputs("/", fp);
		fputs(nvram_safe_get("wl1.3_bss_enabled"), fp);
	}

	fputs("\nCurrent Clients(Wired/Wireless): ", fp);
	memset(tmp_output, 0, sizeof(tmp_output));
	snprintf(tmp_output, sizeof(tmp_output), "%d", nvram_get_int("fb_nmp_wired"));
	fputs(tmp_output, fp);
	fputs("/", fp);
	memset(tmp_output, 0, sizeof(tmp_output));
	snprintf(tmp_output, sizeof(tmp_output), "%d", nvram_get_int("fb_nmp_wlan_2g") + nvram_get_int("fb_nmp_wlan_5g_1") + nvram_get_int("fb_nmp_wlan_5g_2"));
	fputs(tmp_output, fp);

	memset(tmp_output, 0, sizeof(tmp_output));
	snprintf(tmp_output, sizeof(tmp_output), "\nPPTP Server: %s", (nvram_get_int("pptpd_enable") == 1)?"Enabled":"Disabled");
	fputs(tmp_output, fp);

	memset(tmp_output, 0, sizeof(tmp_output));
	snprintf(tmp_output, sizeof(tmp_output), "\nOpenVPN Server: %s", (nvram_get_int("VPNServer_enable") == 1)?"Enabled":"Disabled");
	fputs(tmp_output, fp);

	memset(tmp_output, 0, sizeof(tmp_output));
	snprintf(tmp_output, sizeof(tmp_output), "\nIPSec Server: %s", (nvram_get_int("ipsec_server_enable") == 1)?"Enabled":"Disabled");
	fputs(tmp_output, fp);

#ifdef RTCONFIG_WIREGUARD
	for (unit = 1; unit <= WG_SERVER_MAX; unit++)
	{
		snprintf(tmp_val, sizeof(tmp_val), "wgs%d_enable", unit);
		if (nvram_get_int(tmp_val))
			wgs_enable = 1;
	}
	memset(tmp_output, 0, sizeof(tmp_output));
	snprintf(tmp_output, sizeof(tmp_output), "\nWireGuard Server: %s", (wgs_enable == 1)?"Enabled":"Disabled");
	fputs(tmp_output, fp);
#endif

	if (nvram_contains_word("rc_support", "vpn_fusion")) {
		char *nv = NULL, *nvp = NULL, *b = NULL;
		char *desc = NULL, *proto = NULL, *server = NULL, *username = NULL, *passwd = NULL, *active = NULL;
		int pptp_enable=0, l2tp_enable=0, ovpn_enable=0, ipsec_enable=0, hma_enable=0, nordvpn_enable=0;

		nv = nvp = strdup(nvram_safe_get("vpnc_clientlist"));
		while (nv && (b = strsep(&nvp, "<")) != NULL) {
			//proto and active are mandatory
			if (vstrsep(b, ">", &desc, &proto, &server, &username, &passwd, &active) < 2)
				continue;

			if(active && proto && !strncmp(active, "1", 1))
			{
				if(!strncmp(proto, "PPTP", 4))
				{
					pptp_enable = 1;
				}
				else if(!strncmp(proto, "L2TP", 4))
				{
					l2tp_enable = 1;
				}
				else if(!strncmp(proto, "OpenVPN", 7))
				{
					ovpn_enable = 1;
				}
				else if(!strncmp(proto, "IPSec", 5))
				{
					ipsec_enable = 1;
				}
				else if(!strncmp(proto, "WireGuard", 9))
				{
					wgc_enable = 1;
				}
				else if(!strncmp(proto, "HMA", 3))
				{
					hma_enable = 1;
				}
				else if(!strncmp(proto, "NordVPN", 7))
				{
					nordvpn_enable = 1;
				}
			}
		}
		free(nv);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nPPTP Client: %s", (pptp_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nL2TP Client: %s", (l2tp_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nOpenVPN Client: %s", (ovpn_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nIPSec Client: %s", (ipsec_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nWireGuard Client: %s", (wgc_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nHMA Client: %s", (hma_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nNordVPN Client: %s", (nordvpn_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);
	}
	else {
		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nPPTP Client: %s", (strncmp(nvram_safe_get("vpnc_proto"), "pptp", 4) == 0)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nL2TP Client: %s", (strncmp(nvram_safe_get("vpnc_proto"), "l2tp", 4) == 0)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nOpenVPN Client: %s", (nvram_get_int("vpn_clientx_eas") > 0)?"Enabled":"Disabled");
		fputs(tmp_output, fp);

#ifdef RTCONFIG_WIREGUARD
		for (unit = 1; unit <= WG_CLIENT_MAX; unit++)
		{
			snprintf(tmp_val, sizeof(tmp_val), "wgc%d_enable", unit);
			if (nvram_get_int(tmp_val))
				wgc_enable = 1;
		}
		memset(tmp_output, 0, sizeof(tmp_output));
		snprintf(tmp_output, sizeof(tmp_output), "\nWireGuard Client: %s", (wgc_enable == 1)?"Enabled":"Disabled");
		fputs(tmp_output, fp);
#endif
	}

	fputs("\n", fp);
}

void getinfo_transfer_mode(FILE *fp)
{
#ifdef RTCONFIG_DUALWAN
	char wans_dualwan[16] = {0};
	char *wan0 = NULL;
	char *wan1 = NULL;
	char primary_name[16] = {0};
	char secondary_name[16] = {0};
	int wan0_use = 0;
	int wan1_use = 0;
	int hasSecondWan = 0;
#endif

	if(fp == NULL)
	{
		_dprintf("getinfo_transfer_mode:fp is NULL!\n");
		return;
	}

#ifdef RTCONFIG_DUALWAN
	if(strlen(nvram_safe_get("wans_dualwan")) == 0)
	{
		_dprintf("getinfo_transfer_mode:wans_dualwan is empty!\n");
		return;
	}

	snprintf(wans_dualwan, sizeof(wans_dualwan), nvram_safe_get("wans_dualwan"));
	wan0 = strtok(wans_dualwan, " ");
	if(wan0)
	{
		wan1 = strtok(NULL, " ");
	}

	logmessage("frs_feedback", "wan0=[%s], wan1=[%s]\n", wan0, wan1);

	if(strcmp(wan0, "dsl") == 0)
	{
		if(strcmp("atm", nvram_safe_get("dslx_transmode")) == 0)
		{
			strcpy(primary_name, "ADSL");
		}
		else
		{
			strcpy(primary_name, "VDSL");
		}
	}
	else if(strcmp(wan0, "wan") == 0)
	{
		strcpy(primary_name, "Ethernet WAN");
	}
	else if(strcmp(wan0, "lan") == 0)
	{
		strcpy(primary_name, "Ethernet LAN");
	}
	else if(strcmp(wan0, "usb") == 0)
	{
		strcpy(primary_name, "USB Modem");
	}

	//has dual wan
	if((strlen(wan1) > 0) && (strcmp(wan1, "none") != 0))
	{
		hasSecondWan = 1;
	}

	if(hasSecondWan == 1)
	{
		if(strcmp(wan1, "dsl") == 0)
		{
			if(strcmp("atm", nvram_safe_get("dslx_transmode")) == 0)
			{
				strcpy(secondary_name, "ADSL");
			}
			else
			{
				strcpy(secondary_name, "VDSL");
			}
		}
		else if(strcmp(wan1, "wan") == 0)
		{
			strcpy(secondary_name, "Ethernet WAN");
		}
		else if(strcmp(wan1, "lan") == 0)
		{
			strcpy(secondary_name, "Ethernet LAN");
		}
		else if(strcmp(wan1, "usb") == 0)
		{
			strcpy(secondary_name, "USB Modem");
		}
	}

	wan0_use = nvram_get_int("wan0_primary");
	if(hasSecondWan == 1)
	{
		wan1_use = nvram_get_int("wan1_primary");
	}

	fprintf(fp, "Transfer mode: ");

	//has dual wan
	if(hasSecondWan == 1)
	{
		if(wan0_use)
		{
			fprintf(fp, "%s / %s\n", primary_name, secondary_name);
		}
		else if(wan1_use)
		{
			fprintf(fp, "%s / %s\n", secondary_name, primary_name);
		}
	}
	else
	{
		fprintf(fp, "%s\n", primary_name);
	}
#else
	fprintf(fp, "Transfer mode: Non-dual WAN model\n");
#endif
}

//20 ~ 3800
unsigned int get_random_multiplier()
{
	unsigned int rd = 0;

	f_read("/dev/urandom", &rd, sizeof(unsigned int));
	return (rd%3781) + 20;
}

unsigned int get_hidden_char(char ch)
{
	unsigned int h = 0;

	switch(ch)
	{
		case '0':
			h = 0;
			break;
		case '1':
			h = 1;
			break;
		case '2':
			h = 2;
			break;
		case '3':
			h = 3;
			break;
		case '4':
			h = 4;
			break;
		case '5':
			h = 5;
			break;
		case '6':
			h = 6;
			break;
		case '7':
			h = 7;
			break;
		case '8':
			h = 8;
			break;
		case '9':
			h = 9;
			break;
		case 'a':
			/* Fall-through */
		case 'A':
			h = 10;
			break;
		case 'b':
			/* Fall-through */
		case 'B':
			h = 11;
			break;
		case 'c':
			/* Fall-through */
		case 'C':
			h = 12;
			break;
		case 'd':
			/* Fall-through */
		case 'D':
			h = 13;
			break;
		case 'e':
			/* Fall-through */
		case 'E':
			h = 14;
			break;
		case 'f':
			/* Fall-through */
		case 'F':
			h = 15;
			break;
		case ':':
			h = 16;
			break;
		default:
			_dprintf("Wrong char range!!\n");
			h = 0;
			break;
	}

	return h;
}

#if defined(RTCONFIG_BCM_7114) || (defined(HND_ROUTER) && !defined(RTCONFIG_HND_ROUTER_AX))
void sdk7114_envram_get_int(probe_4366_param_t *probeValue)
{
	FILE *fp = NULL;
	char buffer[64] = {0};
	char cmd[64] = {0};
	int  fabid = 0;
	int  i;

	if(!pids("envrams"))
	{
		system("/usr/sbin/envrams");
		sleep(1);
	}

	fp = popen("/usr/sbin/envram get wl0_dummy", "r");
	if(fp)
	{
		fgets(buffer, sizeof(buffer), fp);
		if(atoi(buffer) > 0)
		{
			probeValue->bECode_2G = 1;
		}
		pclose(fp);
	}

	memset(buffer, 0, sizeof(buffer));
	fp = popen("/usr/sbin/envram get wl1_dummy", "r");
	if(fp)
	{
		fgets(buffer, sizeof(buffer), fp);
		if(atoi(buffer) > 0)
		{
			probeValue->bECode_5G = 1;
		}
		pclose(fp);
	}

	memset(buffer, 0, sizeof(buffer));
	fp = popen("/usr/sbin/envram get wl2_dummy", "r");
	if(fp)
	{
		fgets(buffer, sizeof(buffer), fp);
		if(atoi(buffer) > 0)
		{
			probeValue->bECode_5G_2 = 1;
		}
		pclose(fp);
	}

	for (i = 0; i <= 2; i++)
	{
		snprintf(cmd, sizeof(cmd), "/usr/sbin/envram get wl%d_fabid", i);
		memset(buffer, 0, sizeof(buffer));
		fp = popen(cmd, "r");
		if(fp)
		{
			fgets(buffer, sizeof(buffer), fp);
			/* If "wl fabid" return value >=4 consider as new chip(Broadcom refers as gold part) */
			if(atoi(buffer) >= 4)
			{
				fabid++;
			}
			pclose(fp);
		}
	}

	if (fabid > 0)
	{
		probeValue->bECode_fabid = 1;
	}
}

unsigned int get_probe_result()
{
	probe_4366_param_t probeValue;

	memset(&probeValue, 0, sizeof(probe_4366_param_t));
	sdk7114_envram_get_int(&probeValue);

	return (probeValue.bECode_fabid<<3)|(probeValue.bECode_5G_2<<2)|(probeValue.bECode_5G<<1)|(probeValue.bECode_2G);
}

/***
char* get_encrypt_wifi_status(char *buffer, size_t size)

Sample code:

char wifi_status[100] = {0};
get_encrypt_wifi_status(wifi_status, sizeof(wifi_status));
printf("wifi status code = [%s]\n", wifi_status);

***/

char* get_encrypt_wifi_status(char *buffer, size_t size)
{
	char plain_data[SPECIAL_DATA_LEN + 1] = {0};
	int i = 0;

	if(!buffer)
	{
		_dprintf("Null buffer pointer!\n");
		return NULL;
	}

	if(size < SPECIAL_DATA_LEN*5)
	{
		_dprintf("buffer size is not enough!\n");
		return NULL;
	}

	snprintf(plain_data, sizeof(plain_data), "%s", get_lan_hwaddr());
	// use 17 instead of strlen(plain_data) to prevent from empty MAC address case
	snprintf(plain_data + 17, sizeof(plain_data) - 17, ":%02X", get_probe_result());

	for(i = 0; i < SPECIAL_DATA_LEN; ++i)
	{
		snprintf(buffer+strlen(buffer), size-strlen(buffer), "%04X ", (17*get_random_multiplier())+get_hidden_char(plain_data[i]));
	}

	return buffer;
}
#endif /* RTCONFIG_BCM_7114 || (HND_ROUTER && !RTCONFIG_HND_ROUTER_AX) */

#if defined(RTCONFIG_BCM_7114) || defined(HND_ROUTER)
#define CFE_RAW "/tmp/cfe.txt"
void envram_dump_factory_data()
{
	char cmd[64] = {0};

	if(!pids("envrams"))
	{
		system("/usr/sbin/envrams");
		sleep(1);
	}

	sprintf(cmd, "envram show > %s", CFE_RAW);
	system(cmd);
	if(check_if_file_exist(CFE_RAW)) {
		sprintf(cmd, "gzip -f -c %s > %s", CFE_RAW, CFE_FILE);
		system(cmd);
		unlink(CFE_RAW);
	}
}

#if defined(RTAX88U)
void pcie_envram_get_int(probe_PCIE_param_t *probeValue)
{
	FILE *fp = NULL;
	char buffer[64] = {0};

	if(!pids("envrams"))
	{
		system("/usr/sbin/envrams");
		sleep(1);
	}

	fp = popen("/usr/sbin/envram get pcie_down", "r");
	if(fp)
	{
		fgets(buffer, sizeof(buffer), fp);
		if(atoi(buffer) == 1)
		{
			probeValue->bPCIE_down = 1;
		}
		else
		{
			probeValue->bPCIE_down = 0;
		}
		pclose(fp);
	}
}

unsigned int get_pcie_probe_result()
{
	probe_PCIE_param_t probeValue;

	memset(&probeValue, 0, sizeof(probe_PCIE_param_t));
	pcie_envram_get_int(&probeValue);

	return (probeValue.bPCIE_down);
}

char *get_encrypt_pcie_status(char *buffer, size_t size)
{
	char plain_data[PCIE_DATA_LEN + 1] = {0};
	int i = 0;

	if(!buffer)
	{
		_dprintf("Null buffer pointer!\n");
		return NULL;
	}

	if(size < PCIE_DATA_LEN*5)
	{
		_dprintf("buffer size is not enough!\n");
		return NULL;
	}

	snprintf(plain_data, sizeof(plain_data), "%04X", get_pcie_probe_result());

	for(i = 0; i < PCIE_DATA_LEN; ++i)
	{
		snprintf(buffer+strlen(buffer), size-strlen(buffer), "%04X ", (17*get_random_multiplier())+get_hidden_char(plain_data[i]));
	}

	return buffer;
}
#endif /* RTAX88U */
#endif /* RTCONFIG_BCM_7114 || HND_ROUTER */
unsigned char get_rand()
{
	unsigned char buf[1];
	FILE *fp;

	fp = fopen("/dev/urandom", "r");
	if (fp == NULL) {
		return 0;
	}
	fread(buf, 1, 1, fp);
	fclose(fp);
	cprintf("get_rand=%d\n", buf[0]);
	return buf[0];
}

unsigned long readFileSize( char *filepath )
{
	struct stat sb;

	if( stat(filepath, &sb) == 0 )
	{
		//on success, return file size
		return sb.st_size;
	}
	return 0;

}

enum{
	ENDIAN_UNKNOWN = -1,
	ENDIAN_LITTLE = 0,
	ENDIAN_BIG = 1
};

int detect_endianness(void)
{
	int num = 0x04030201;
	char c = *(char *)(&num);

	if (c == 0x04 || c == 0x01)
	{
		if (c == 0x04)
			return ENDIAN_BIG; //big endian
		else
			return ENDIAN_LITTLE; //little
	}

	cprintf("[warning]this is a word-swapped big or little system\n");
	return ENDIAN_UNKNOWN; //error
}

int encryptBinaryfile(char *src, char *dst, char *productName)
{
	FILE *fp = NULL;
	unsigned long count, i;
	unsigned int rand = 0;
	char *buffer = NULL;
	int srcFD = -1;
	int ret = 0;
	binfile_header_t rhdr;

	if(!src||!dst||!productName)
	{
		return -1;
	}

	unlink(dst);
	if ((fp = fopen(dst, "wb")) == NULL)
	{
		return -1;
	}

	if( ( srcFD = open(src, O_RDONLY) ) < 0 )
	{
		fclose(fp);
		return -2;
	}
	count = readFileSize(src);
	buffer = (char *) calloc( count, sizeof(char));
	if(!buffer)
	{
		close(srcFD);
		fclose(fp);
		return -3;
	}

	ret = read(srcFD, buffer, count);
	close(srcFD);
	if( ret < 0 )
	{
		free(buffer);
		fclose(fp);
		return -3;
	}

	memset(&rhdr, 0, sizeof(rhdr));
	snprintf(rhdr.keyWord, sizeof(rhdr.keyWord), "%s", BINARY_KEYWORD);
	rand = (get_rand() % 216) + 20; //rand will be 20~235
	rhdr.rand = rand;

	rhdr.fileLength = count;
	if(detect_endianness() == ENDIAN_BIG)
	{
		//convert from big to little endian (feedback sever is little endian)
		adjustEndian(rhdr.rand);
		adjustEndian(rhdr.fileLength);
	}

	if( strlen(productName) <= 0 )
	{
		//default case
		strncpy(rhdr.productName, "RT-AC68U", sizeof(rhdr.productName) );
	}
	else
	{
		strncpy(rhdr.productName, productName, sizeof(rhdr.productName) );
		rhdr.productName[sizeof(rhdr.productName)-1] = '\0';
	}

	//write header
	fwrite(&rhdr, 1, sizeof(rhdr), fp);

	//encrypt data
	for (i = 0; i < count; i++)
	{
		buffer[i] = buffer[i] ^ ((rand+i)%255);
	}

	//write data
	fwrite(buffer, 1, count, fp);

	fclose(fp);
	free(buffer);
	return 0;
}

#ifdef RTCONFIG_DBLOG
void start_dblog(int option)
{
	if(nvram_match("dblog_enable", "1"))
	{
		if(option == 1)
		{
			xstart("dblog", "reset");
		}
		else
		{
			xstart("dblog");
		}
	}
}

void stop_dblog(void)
{
	eval("dblogcmd", "exit");
}
#endif /* RTCONFIG_DBLOG */

#if defined(RTCONFIG_BCMARM)
double get_cpu_temp()
{
	double result = 0.0;
#if defined(HND_ROUTER)
	char *buf = NULL;

	buf = file2str(PROC_ENTRY_CPUTEMP);
	if(!buf)
	{
		cprintf("[get_cpu_temp]buf is NULL!!\n");
		return result;
	}
	result = (double) (strtoul(buf, NULL, 10)*1.0)/1000.0;
	free(buf);
#else /* For BCM470x series */
	char buffer[32] = {0};
	double cpu_temperature = 0.0;
	FILE *fp = fopen(PROC_ENTRY_CPUTEMP, "r");

	if(fp)
	{
		if(fgets(buffer, sizeof(buffer), fp))
		{
			// ASCII code of \A2XC is 248 & 67.
			sscanf(buffer, "CPU temperature : %lf\248\67", &cpu_temperature);
			result = cpu_temperature;
		}
		fclose(fp);
	}
#endif /* HND_ROUTER */
	return result;
}

int get_wifi_temps(WiFi_temperature_t *wt)
{
	int ret = -1;
	char word[128], *next = NULL;
	char cmd[256];
	FILE *fp = NULL;
	char buffer[64] = {0};
	double temp[3] = {0};
	int n = 0;
	int index = 0;

	if(!wt)
	{
		cprintf("[get_wifi_temp]wt is NULL!!\n");
		return ret;
	}

	wt->t2g = 0.0;
	wt->t5g = 0.0;
	wt->t5g2 = 0.0;

	foreach (word, nvram_safe_get("wl_ifnames"), next)
	{
		snprintf(cmd, sizeof(cmd), "wl -i %s phy_tempsense", word);
		cprintf("cmd=[%s]\n", cmd);
		fp = popen(cmd, "r");
		if(fp)
		{
			memset(buffer, 0, sizeof(buffer));
			if(fgets(buffer, sizeof(buffer), fp))
			{
				n = sscanf(buffer, "%lf", &temp[index]);
				if(n != 1)
				{
					break;
				}
			}
		}
		if(index == 2)
		{
			ret = 0;
			wt->t2g = temp[0];
			wt->t5g = temp[1];
			wt->t5g2 = temp[2];
			break;
		}
		index++;
	}

	return ret;
}
#endif /* RTCONFIG_BCMARM */

static int _dec_asd_log(const char *log_path, const char *dec_path)
{
	FILE *fp = NULL, * fp_dec = NULL;
	char buf[4096], dec_buf[2048];
	
	if(!log_path || !dec_path)
		return -1;

	fp = fopen(log_path, "r");
	fp_dec = fopen(dec_path, "w");
	if(fp && fp_dec)
	{
		memset(buf, 0, sizeof(buf));
		while(fgets(buf, sizeof(buf), fp))
		{
			//remove /n at the end of the string.
			buf[strlen(buf) - 1] = '0';
			memset(dec_buf, 0, sizeof(dec_buf));
			if(pw_dec(buf, dec_buf, sizeof(dec_buf), 0))
				fputs(dec_buf, fp_dec);			
			else
			{
				fprintf(fp_dec, "%s\n", buf);
			}
		}
		fclose(fp);
		fclose(fp_dec);
		return 0;
	}
	else
	{
		if(fp)
			fclose(fp);
		if(fp_dec)
			fclose(fp_dec);		
	}
	return -1;
}

