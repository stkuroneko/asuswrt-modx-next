/*
**	amas-utils-int.h
**
**
*/
#ifndef __AMASUTILS_INTH__
#define __AMASUTILS_INTH__
#include <bcmnvram.h>
#include <shutils.h>
#include <shared.h>
#include <sysdeps/amas/amas_path.h>

#include "adv_debug.h"
#include "adv_misc.h"
#include "adv_string.h"
#include "amas-utils.h"
#include "debug-int.h"
#include "encrypt.h"

#include <json.h>
#include <pthread.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <lldpctl.h>

////////////////////////////////////////////////////////////////////////////////
//
// Global Lock & Unlock
//
////////////////////////////////////////////////////////////////////////////////
pthread_mutex_t gLock;
#define GLOBAL_LOCK() (pthread_mutex_lock(&gLock))
#define GLOBAL_UNLOCK() (pthread_mutex_unlock(&gLock))

////////////////////////////////////////////////////////////////////////////////
//
// Global variable & function
//
////////////////////////////////////////////////////////////////////////////////
AMAS_RESULT AMASRes = AMAS_RESULT_SUCCESS;
AMAS_RESULT Read_AMASRes(
	void)
{
	AMAS_RESULT res = AMAS_RESULT_FAILED;
	GLOBAL_LOCK();
	res = AMASRes;
	GLOBAL_UNLOCK();
	return res;
}
void Write_AMASRes(
	AMAS_RESULT v)
{
	GLOBAL_LOCK();
	AMASRes = v;
	GLOBAL_UNLOCK();
	return;
}

unsigned int ShowDebug = 0;
unsigned int Read_ShowDebug(
	void)
{
	unsigned int res = 0;
	GLOBAL_LOCK();
	res = (ShowDebug == 1) ? 1 : 0;
	GLOBAL_UNLOCK();
	return res;
}

void Write_ShowDebug(
	unsigned int v)
{
	GLOBAL_LOCK();
	ShowDebug = (v == 1) ? 1 : 0;
	GLOBAL_UNLOCK();
	return;
}

///////////////////////////////////////////////////////////////////////////////
//
//	AMAS_SUBTYPE_ID
//
////////////////////////////////////////////////////////////////////////////////
#define AMAS_SUBTYPE_OBSTATUS		1
#define AMAS_SUBTYPE_COST			2
#define AMAS_SUBTYPE_ID				3
#define AMAS_SUBTYPE_DEVMAC			4
#define AMAS_SUBTYPE_MODELNAME		5
#define AMAS_SUBTYPE_TIMESTAMP		6
/*
  AMAS_SUBTYPE_PEERMAC
  New RE's MAC: Set node's(old RE or CAP) mac that provide security key
  Old RE or CAP: Set New RE's MAC
*/
#define AMAS_SUBTYPE_PEERMAC		7
#define AMAS_SUBTYPE_SESSIONKEY		8
#define AMAS_SUBTYPE_WIFISSID		9
#define AMAS_SUBTYPE_WIFIAUTHMODE	10
#define AMAS_SUBTYPE_WIFICRYPTOMODE	11
#define AMAS_SUBTYPE_WIFIKEY		12
#define AMAS_SUBTYPE_SECSTATUS		13
#define AMAS_SUBTYPE_GROUP			14
#define AMAS_SUBTYPE_REBOOT_TIME	15
#define AMAS_SUBTYPE_CONN_TIMEOUT	16
#define AMAS_SUBTYPE_TRAFFIC_TIMEOUT	17
#define AMAS_SUBTYPE_RSSI_SCORE			18
#define AMAS_SUBTYPE_WIFI_LASTBYTE		19
#define AMAS_SUBTYPE_HASH_BUNDLE_KEY	20
#define AMAS_SUBTYPE_ETH_ROLE		21
#define AMAS_SUBTYPE_TCODE		22
#define AMAS_SUBTYPE_MISC_INFO		23

///////////////////////////////////////////////////////////////////////////////
//
//	DEFINE
//
////////////////////////////////////////////////////////////////////////////////
#if !defined(AMASUTILS_MAJOR_NUMBER) || !defined(AMASUTILS_MINOR_NUMBER) || !defined(AMASUTILS_RESVISION_NUMBER) || !defined(AMASUTILS_BUILD_NUMBER)
#define AMASUTILS_MAJOR_NUMBER			1
#define AMASUTILS_MINOR_NUMBER			0
#define AMASUTILS_RESVISION_NUMBER 		0
#define AMASUTILS_BUILD_NUMBER 			15
#endif

#define MAX_VSIEID_LENGTH		20
#define MAX_HASH_BUNDLE_KEY_LEN	20
#define SZ_LIBRARY_NAME			"amas-utils\0"
#define SZ_AMAS_OUI				"F8,32,E4\0"
#define SZ_LLDPCLI_FILELOCK		"lldpcli\0"

#if !defined(SZ_LLDP_SHOW_NBR_OUTFNAME)
#define SZ_LLDP_SHOW_NBR_OUTFNAME	"/tmp/lldp_show_nbr\0"
#else
#undef SZ_LLDP_SHOW_NBR_OUTFNAME
#define SZ_LLDP_SHOW_NBR_OUTFNAME	"lldp_show_nbr\0"
#endif

#if !defined(SZ_LLDP_SHOW_OBD_OUTFNAME)
#define SZ_LLDP_SHOW_OBD_OUTFNAME	"/tmp/lldp_obd_nbr\0"
#else
#undef SZ_LLDP_SHOW_OBD_OUTFNAME
#define SZ_LLDP_SHOW_OBD_OUTFNAME	"lldp_obd_nbr\0"
#endif

#if !defined(SZ_LLDP_CUSTOM_TLV_OUTFNAME)
#define SZ_LLDP_CUSTOM_TLV_OUTFNAME	"/tmp/lldp_custom_tlv\0"
#else
#undef SZ_LLDP_CUSTOM_TLV_OUTFNAME
#define SZ_LLDP_CUSTOM_TLV_OUTFNAME	"lldp_custom_tlv\0"
#endif

#define MAX_LLDP_TLV_VALUE_SIZE			512
////////////////////////////////////////////////////////////////////////////////
//
// Debug Message
//
////////////////////////////////////////////////////////////////////////////////
#define MAX_DBGMSG_LENGTH	4097

#define DBG_ERR(...) do {\
	if (Read_ShowDebug())\
	{\
		char __BUF__[MAX_DBGMSG_LENGTH];\
		memset(__BUF__,0,sizeof(__BUF__));\
		DEBUG_ERR(SZ_LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
	}\
}while(0)

#define DBG_INFO(...) do {\
	if (Read_ShowDebug())\
	{\
		char __BUF__[MAX_DBGMSG_LENGTH];\
		memset(__BUF__,0,sizeof(__BUF__));\
		DEBUG_INFO(SZ_LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
	}\
}while(0)

#define DBG_NOTICE(...) do {\
	if (Read_ShowDebug())\
	{\
		char __BUF__[MAX_DBGMSG_LENGTH];\
		memset(__BUF__,0,sizeof(__BUF__));\
		DEBUG_NOTICE(SZ_LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
	}\
}while(0)

#define DBG_WARNING(...) do {\
	if (Read_ShowDebug())\
	{\
		char __BUF__[MAX_DBGMSG_LENGTH];\
		memset(__BUF__,0,sizeof(__BUF__));\
		DEBUG_WARNING(SZ_LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,__VA_ARGS__));\
	}\
}while(0)

#define DBG_TRACE_LINE do {\
	if (Read_ShowDebug())\
	{\
		char __BUF__[MAX_DBGMSG_LENGTH];\
		memset(__BUF__,0,sizeof(__BUF__));\
		DEBUG_INFO(SZ_LIBRARY_NAME,args2str(__BUF__,sizeof(__BUF__)-1,"TRACE LINE!!!"));\
	}\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
// 	AMAS RESULT CODE TABLE
//
////////////////////////////////////////////////////////////////////////////////
typedef struct AMAS_RES_CODE_t
{
	AMAS_RESULT AMASRes;
	char *context;
} AMAS_RES_CODE, *P_AMAS_RES_CODE;

static struct AMAS_RES_CODE_t AMAS_RES_CODE_MAP[] =
{
		//AMAS_RESULT							// Context
	{	AMAS_RESULT_FILE_LOCK_ERROR,			"call file_lock() error\0"			},
	{	AMAS_RESULT_NBR_DATA_IS_EMPTY,			"Neighbor data is empty\0"			},
	{	AMAS_RESULT_NBR_SYSDESCR_NO_SEACH,		"No search lldpd sys descr\0"		},
	{	AMAS_RESULT_VERIFY_VSIEID_FAILED,		"Verify VSIE ID failed.\0"			},
	{	AMAS_RESULT_GEN_VSIEID_FAILED, 			"Geneate VSIE ID failed.\0"			},
	{	AMAS_RESULT_LLDPCLI_EXEC_FAILED,		"lldpcli execute failed.\0"			},
	{	AMAS_RESULT_BUFFER_IS_TOO_SMALL,		"Buffer is too small.\0"			},
	{	AMAS_RESULT_NBR_TLV_UNABLE_TO_PARSE,	"Unable to parse tlv content.\0"	},
	{	AMAS_RESULT_NBR_TLV_TYPE_NO_FOUND,		"TLV type not found.\0"				},
	{	AMAS_RESULT_NBR_TLV_NO_SEARCH,			"No search tlv data.\0"				},
	{	AMAS_RESULT_NBR_IFACE_NO_SEARCH,		"No search interface.\0"			},
	{	AMAS_RESULT_JSON_UNABLE_TO_PARSE,		"Unable to parse json content\0"	},
	{	AMAS_RESULT_FILE_OPERATE_FAILED,		"File operation failed.\0"			},
	{	AMAS_RESULT_MEM_ALLOCATE_ERROR,			"Memory allocate failed.\0"			},
	{	AMAS_RESULT_FILE_OPEN_ERROR,			"File open error.\0"				},
	{	AMAS_RESULT_INVALID_VALUE,				"Invalid parameter value.\0"		},
	{	AMAS_RESULT_FAILED,						"Execption error.\0"				},
	{	AMAS_RESULT_SUCCESS, 					"Success.\0"						},
	{	0,										NULL								},
};

#define ENDOF_AMAS_RES_FIELD(__AMAS_RES_CODE__) (__AMAS_RES_CODE__->context == NULL)
#define FIND_ERRCODE_BY_CONTEXT(__AMASRes__, __RetContext__) do {\
	P_AMAS_RES_CODE __P__ = (P_AMAS_RES_CODE)&AMAS_RES_CODE_MAP[0];\
	__RetContext__ = "No context.\0";\
	while (!ENDOF_AMAS_RES_FIELD(__P__))\
	{\
		if (__P__->AMASRes == __AMASRes__)\
		{\
			__RetContext__ = __P__->context;\
			break;\
		}\
		__P__++;\
	}\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
// 	SET_ERROR_CODE
//
////////////////////////////////////////////////////////////////////////////////
#define SET_ERROR_CODE(__CODE__) do {\
	char* __STRERR__ = NULL;\
	FIND_ERRCODE_BY_CONTEXT(__CODE__,__STRERR__);\
	DBG_ERR("%s",__STRERR__);\
	Write_AMASRes(__CODE__);\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
// 	SET_AMAS_RESULT
//
////////////////////////////////////////////////////////////////////////////////
#define SET_AMAS_RESULT(__RESULT__,__CODE__) do {\
	char* __STRERR__ = NULL;\
	if (!IsNULL_PTR(__RESULT__))\
	{\
		*(__RESULT__) = __CODE__;\
		FIND_ERRCODE_BY_CONTEXT(__CODE__,__STRERR__);\
		DBG_ERR("%s", __STRERR__);\
	}\
}while(0);
////////////////////////////////////////////////////////////////////////////////
//
// 	RETURN_AMAS_RESULT_FAILED
//
////////////////////////////////////////////////////////////////////////////////
#define RETURN_AMAS_RESULT_FAILED do {\
	AMAS_RESULT __res__ = Read_AMASRes();\
	return __res__;\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
// 	RETURN_AMAS_RESULT_SUCCESS
//
////////////////////////////////////////////////////////////////////////////////
#define RETURN_AMAS_RESULT_SUCCESS do {\
	Write_AMASRes(AMAS_RESULT_SUCCESS);\
	return AMAS_RESULT_SUCCESS;\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
// JSON_C_FREE
//
////////////////////////////////////////////////////////////////////////////////
#define JSON_C_FREE(__JOBJ__) do {\
	int __RET__ = 0;\
	if (!IsNULL_PTR(__JOBJ__))\
	{\
		if ((__RET__ = json_object_put(__JOBJ__)) != 1)\
		{\
			printf("call json_object_put() failed .. ret : %d", __RET__);\
		}\
		else\
		{\
			__JOBJ__ = NULL;\
		}\
	}\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
//	str2hex_x
//
////////////////////////////////////////////////////////////////////////////////
#if 0
static int _is_hex(char c)
{
        return (((c >= '0') && (c <= '9')) ||
                ((c >= 'A') && (c <= 'F')) ||
                ((c >= 'a') && (c <= 'f')));
} /* End of _is_hex */

int str2hex_x(const char *a, unsigned char *e, int len)
{
        char tmpBuf[4];
        int idx, ii=0;
        for (idx=0; idx<len; idx+=2) {
                tmpBuf[0] = a[idx];
                tmpBuf[1] = a[idx+1];
                tmpBuf[2] = 0;
                if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
                        return 0;
                e[ii++] = (unsigned char) strtol(tmpBuf, (char**)NULL, 16);
        }
        return 1;
} /* End of str2hex */
#endif
////////////////////////////////////////////////////////////////////////////////
//
//	hex2str_x
//
////////////////////////////////////////////////////////////////////////////////
int hex2str_x(unsigned char *hex, char *str, int hex_len)
{
        int i = 0;
        char *d = NULL;
        unsigned char *s = NULL;
        const static char hexdig[] = "0123456789ABCDEF";
        if(hex == NULL||str == NULL)
                return 0;
        d = str;
        s = hex;

        for (i = 0; i < hex_len; i++,s++){
                *d++ = hexdig[(*s >> 4) & 0xf];
                *d++ = hexdig[*s & 0xf];
        }
        *d = 0;
        return 1;
} /* End of hex2str */


////////////////////////////////////////////////////////////////////////////////
//
//	HEXSTR_TO_STR
//
////////////////////////////////////////////////////////////////////////////////
#define HTOB(i, c) do {\
	if ('0' <= c && c <= '9') \
		*i = c - '0'; \
	else if ('a' <= c && c <= 'f') \
		*i = c - 'a' + 10; \
	else if ('A' <= c && c <= 'F') \
		*i = c - 'A' + 10; \
	else \
		*i = 0; \
} while(0)
void str2hex_x(
	char *szString,
	unsigned char *hex)
{
	int i, j, k, len;
	unsigned char *p = NULL;

	if (szString == NULL) return;
	if (hex == NULL) return;
	len = strlen(szString);
	p = hex;

	for (k = 0; k < len; k+=2) {
		i = j = 0;
		HTOB(&i, szString[k]);
		HTOB(&j, szString[k+1]);
		*p = (i << 4) | j;
		p++;
	}

	return;
}

char* HEXSTR_TO_STR(
	char *hexstr,
	size_t hexstr_len,
	size_t *out_str_len)
{
	char *s = NULL, *ss = NULL;
	size_t s_alloc_size = 0;
	int i, j, k;

	if (IsNULL_PTR(hexstr) || hexstr_len <= 0)
	{
		return NULL;
	}

	s_alloc_size = (hexstr_len / 2) + 4;
	MALLOC(s, char, s_alloc_size);
	if (IsNULL_PTR(s))
	{
		return NULL;
	}

	ss = s;
	for (k=0; k<hexstr_len; k+=2)
	{
		i = j = 0;
		HTOB(&i, hexstr[k]);
		HTOB(&j, hexstr[k+1]);
		*ss = (i<<4) | j;
		ss++;
	}

	if (!IsNULL_PTR(out_str_len)) *(out_str_len) = strlen(s);
	return s;
}

char iscolon(unsigned char c)
{
    if ( c== 0x2C)
      return 1;

  return 0;
}

int cal_colon(char *s1)
{

  DBG_INFO("s1 = %s\n", s1);

  int colon = 0;

    if(colon == 0 && iscolon(*s1)) {
        DBG_INFO("format is incorrect.\n");
        return 0;
    }

    while (*s1)
    {
       if (iscolon(*s1))
       {
           colon++;
       }
       s1++;
    }
    s1--;
    if(iscolon(*s1)) {
        DBG_INFO("format is incorrect.\n");
        return 0;
    }

    DBG_INFO("parameter count = %d\n", colon+1);
   return colon + 1;
}

int get_type_by_ifname(char *ifname)
{
    int type = ETH_TYPE_NONE, found_index = -1, i = 0;
    char word[32], *next;
    char lldp_ifnames[128] = {0}, lldp_iftypes[64] = {0};

    strlcpy(lldp_ifnames, nvram_safe_get("amas_lldp_ifnames"), sizeof(lldp_ifnames));
    strlcpy(lldp_iftypes, nvram_safe_get("amas_lldp_iftypes"), sizeof(lldp_iftypes));

    foreach(word, lldp_ifnames, next) {
        if (strcasecmp(ifname, word) == 0) {
	     found_index = i;
            break;
        }
        i++;
    }

    if (found_index >= 0) {
        i = 0;
        foreach(word, lldp_iftypes, next) {
            if (i == found_index) {
                type = atoi(word);
	         break;
            }
            i++;
        }
    }

    return type;
}

////////////////////////////////////////////////////////////////////////////////
//
//	execute
//
////////////////////////////////////////////////////////////////////////////////
#if 0	// >>> Remove by MAX 20170808
int execute(
	char *argv[])
{
	int res = 0, pid = -1;
	int i, c = 0;
	char s[513], ss[133];

	if (Read_ShowDebug() == 1)
	{
		memset(s, 0, sizeof(s));
		for (i=0, c=0; c < sizeof(s)-1 && !IsNULL_PTR(argv[i]); )
		{
			memset(ss, 0, sizeof(ss));
			snprintf(ss, sizeof(ss)-1, "%s ", argv[i]);
			if ((c+strlen(ss)) < sizeof(s)-1) strncat(s, ss, strlen(ss));
			c += strlen(ss);
			i ++;
		}

		DBG_INFO("argv[] : %s", s);
	}

	pid = fork();
	if (pid == -1)
	{
		exit(-1);
		res = -1;
	}
	else if (pid == 0)
	{
		if (execvp(*argv, argv) < 0)
		{
			res = -1;
		}
	}

	waitpid(pid, NULL, 0);
	return res;
}
#endif	// <<< Remove by MAX 20170808

////////////////////////////////////////////////////////////////////////////////
//
//	gen_vsie_id
//
////////////////////////////////////////////////////////////////////////////////
char* gen_vsie_id(
	int ts,
	size_t *out_len)
{
	char id[33], sha256KeyStr[65], *outId = NULL, *cfg_group = NULL;
	unsigned char hexId[16], *sha256Key = NULL;
	size_t sha256KeyLen = 0;
	int i = 0;
	size_t alloc_out_len = 41;

	cfg_group = nvram_safe_get("cfg_group");
	if (IsNULL_PTR(cfg_group) || strlen(cfg_group) <= 0)
	{
		DBG_ERR("cfg_group is empty !!");
		return NULL;
	}
	DBG_INFO("cfg_group : %s", cfg_group);

	memset(id, 0, sizeof(id));
	snprintf(id, sizeof(id), "%s", cfg_group);
	memset(hexId, 0, sizeof(hexId));
	str2hex_x(id, hexId);
	/* each 4 bytes of hexId & (And) timestamp */
	for (i=0; i<sizeof(hexId); i+=4)
	{
		hexId[i] = hexId[i] & ts >> 24;
		hexId[i+1] = hexId[i+1] & ts >> 16;
		hexId[i+2] = hexId[i+2] & ts >> 8;
		hexId[i+3] = hexId[i+3] & ts;
	}

	/* generate sha256's key */
	sha256Key = gen_sha256_key(hexId, sizeof(hexId), &sha256KeyLen);
	if (IsNULL_PTR(sha256Key) || sha256KeyLen <= 0)
	{
		DBG_ERR("gen_sha256_key() failed ...");
		return NULL;
	}
	memset(sha256KeyStr, 0, sizeof(sha256KeyStr));
	hex2str_x(sha256Key, sha256KeyStr, sha256KeyLen);
	free(sha256Key);
	sha256KeyStr[32] = '\0';
	MALLOC(outId, char, alloc_out_len);
	if (IsNULL_PTR(outId))
	{
		DBG_ERR("Memory allocate failed ...");
		return NULL;
	}
	snprintf(outId, alloc_out_len, "%s%02X%02X%02X%02X",
		sha256KeyStr, (ts >> 24) & 0xFF, (ts >> 16) & 0xFF, (ts >> 8) & 0xFF, ts & 0xFF);
	if (!IsNULL_PTR(out_len)) *(out_len) = strlen(outId);
	return outId;
}

////////////////////////////////////////////////////////////////////////////////
//
//	groupid_check
//
////////////////////////////////////////////////////////////////////////////////
AMAS_RESULT group_id_check(
	char *tlv_group_id)
{
	AMAS_RESULT result = AMAS_RESULT_FAILED;
	int ts = 0, c = 0;
	char *id1 = NULL, *id2 = NULL, *s = NULL;
	size_t id1_len = MAX_VSIEID_LENGTH * 2, id2_len = 0;
	unsigned char v[MAX_LLDP_TLV_VALUE_SIZE];

	if (IsNULL_PTR(tlv_group_id) || strlen(tlv_group_id) <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_INVALID_VALUE);
		goto group_id_check_fail;
	}

	if ((c = AdvSplitStr_Count(1, tlv_group_id, ",")) <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_INVALID_VALUE);
		goto group_id_check_fail;
	}

	MALLOC(s, char, ((c * 2) + 1));
	if (IsNULL_PTR(s))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto group_id_check_fail;
	}

	AdvSplitStr(1, tlv_group_id, ",", (char *)s, c, 2);
	memset(v, 0, sizeof(v));
	str2hex_x(s, v);

	// copy timestamp from group_id
	memcpy((unsigned char *)&ts, (unsigned char *)&v[(strlen(s) / 2) - sizeof(int)], sizeof(int));
	ts = ntohl(ts);

	// id1
	MALLOC(id1, char, (id1_len + 1));
	if (IsNULL_PTR(id1))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto group_id_check_fail;
	}
	hex2str_x(v, id1, strlen(s)/2);

	// id2
	id2 = gen_vsie_id(ts, &id2_len);
	if (IsNULL_PTR(id2))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_GEN_VSIEID_FAILED);
		goto group_id_check_fail;
	}

	if (id1_len != id2_len)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_VERIFY_VSIEID_FAILED);
		goto group_id_check_fail;
	}

	if (memcmp((unsigned char *)&id1[0], (unsigned char *)&id2[0], id1_len) != 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_VERIFY_VSIEID_FAILED);
		goto group_id_check_fail;
	}

	MFREE(s);
	MFREE(id1);
	MFREE(id2);
	return AMAS_RESULT_SUCCESS;

group_id_check_fail:
	if (!IsNULL_PTR(s)) MFREE(s);
	if (!IsNULL_PTR(id1)) MFREE(id1);
	if (!IsNULL_PTR(id2)) MFREE(id2);
	return result;
}

#if defined(RTCONFIG_PRELINK)
////////////////////////////////////////////////////////////////////////////////
//
//	gen_hash_bundle_key
//
////////////////////////////////////////////////////////////////////////////////
static char* gen_hash_bundle_key(
	int ts,
	size_t *out_len)
{
	char key[33], sha256KeyStr[65], *outKey = NULL, *bundle_key = NULL;
	unsigned char hexKey[16], *sha256Key = NULL;
	size_t sha256KeyLen = 0;
	int i = 0;
	size_t alloc_out_len = 41;

	bundle_key = nvram_safe_get("amas_bdlkey");
	if (IsNULL_PTR(bundle_key) || strlen(bundle_key) <= 0)
	{
		DBG_ERR("bundle_key is empty !!");
		return NULL;
	}
	DBG_INFO("bundle_key : %s", bundle_key);

	memset(key, 0, sizeof(key));
	snprintf(key, sizeof(key), "%s", bundle_key);
	memset(hexKey, 0, sizeof(hexKey));
	str2hex_x(key, hexKey);
	/* each 4 bytes of hexKey & (And) timestamp */
	for (i=0; i<sizeof(hexKey); i+=4)
	{
		hexKey[i] = hexKey[i] & ts >> 24;
		hexKey[i+1] = hexKey[i+1] & ts >> 16;
		hexKey[i+2] = hexKey[i+2] & ts >> 8;
		hexKey[i+3] = hexKey[i+3] & ts;
	}

	/* generate sha256's key */
	sha256Key = gen_sha256_key(hexKey, sizeof(hexKey), &sha256KeyLen);
	if (IsNULL_PTR(sha256Key) || sha256KeyLen <= 0)
	{
		DBG_ERR("gen_sha256_key() failed ...");
		return NULL;
	}
	memset(sha256KeyStr, 0, sizeof(sha256KeyStr));
	hex2str_x(sha256Key, sha256KeyStr, sha256KeyLen);
	free(sha256Key);
	sha256KeyStr[32] = '\0';
	MALLOC(outKey, char, alloc_out_len);
	if (IsNULL_PTR(outKey))
	{
		DBG_ERR("Memory allocate failed ...");
		return NULL;
	}
	snprintf(outKey, alloc_out_len, "%s%02X%02X%02X%02X",
		sha256KeyStr, (ts >> 24) & 0xFF, (ts >> 16) & 0xFF, (ts >> 8) & 0xFF, ts & 0xFF);
	if (!IsNULL_PTR(out_len)) *(out_len) = strlen(outKey);
	return outKey;
}

////////////////////////////////////////////////////////////////////////////////
//
//	gen_default_backhaul_security
//
////////////////////////////////////////////////////////////////////////////////
static int gen_default_backhaul_security(char *ssid, int ssid_len, char *psk, int psk_len)
{
	unsigned char *bundle_key = NULL, bundle_key_hex[16];
	unsigned char *ssid_hex = NULL, *psk_hex = NULL;
	char ssid_str[65], psk_str[65];
	size_t ssidKeyLen = 0, pskKeyLen = 0;

	bundle_key = nvram_safe_get("amas_bdlkey");
	if (IsNULL_PTR(bundle_key) || strlen(bundle_key) <= 0)
	{
		DBG_ERR("bundle_key is empty !!");
		goto gen_default_backhaul_security_Fail;
	}
	DBG_INFO("bundle_key : %s", bundle_key);

	/* for ssid based on bundle_key_hex */
	memset(bundle_key_hex, 0, sizeof(bundle_key_hex));
	str2hex_x(bundle_key, bundle_key_hex);
	ssid_hex = gen_sha256_key(bundle_key_hex, sizeof(bundle_key_hex), &ssidKeyLen);
	if (IsNULL_PTR(ssid_hex) || ssidKeyLen <= 0)
	{
		DBG_ERR("gen_sha256_key() failed ...");
		goto gen_default_backhaul_security_Fail;
	}

	memset(ssid_str, 0, sizeof(ssid_str));
	hex2str_x(ssid_hex, ssid_str, ssidKeyLen);
	strlcpy(ssid, &ssid_str[ssidKeyLen], ssid_len);
	DBG_INFO("ssid_str (%s), ssidKeyLen (%d)", ssid_str, ssidKeyLen);
	DBG_INFO("ssid (%s)", ssid);

	/* for psk based on ssid_hex */
	psk_hex = gen_sha256_key(ssid_hex, ssidKeyLen, &pskKeyLen);
	if (IsNULL_PTR(psk_hex) || pskKeyLen <= 0)
	{
		DBG_ERR("gen_sha256_key() failed ...");
		goto gen_default_backhaul_security_Fail;
	}

	memset(psk_str, 0, sizeof(psk_str));
	hex2str_x(psk_hex, psk_str, pskKeyLen);
	strlcpy(psk, &psk_str[pskKeyLen], psk_len);
	DBG_INFO("psk_str (%s), pskKeyLen (%d)", psk_str, pskKeyLen);
	DBG_INFO("psk (%s)", psk);

	MFREE(ssid_hex);
	MFREE(psk_hex);
	return 1;

gen_default_backhaul_security_Fail:

	if (!IsNULL_PTR(ssid_hex)) MFREE(ssid_hex);
	if (!IsNULL_PTR(psk_hex)) MFREE(psk_hex);
	return 0;
}
#endif /* RTCONFIG_PRELINK */

#ifdef RTCONFIG_VIF_ONBOARDING
////////////////////////////////////////////////////////////////////////////////
//
//	gen_onoarding_vif_security
//
////////////////////////////////////////////////////////////////////////////////
static int gen_onboarding_vif_security(char *ssid, int ssid_len, char *psk, int psk_len)
{
	unsigned char *ssid_hex = NULL, *psk_hex = NULL;
	char ssid_str[65], psk_str[65], data[64];
	size_t ssidKeyLen = 0, pskKeyLen = 0;
	MD5_CTX ctx;
	unsigned char outmd[16];
	char key[33], key_hex[16];

	snprintf(data, sizeof(data), "%s_%d", get_lan_hwaddr(), (int)time(NULL));
	DBG_INFO("data (%s)", data);
	if (!MD5_Init(&ctx)) {
		DBG_ERR("md5 init failed");
		goto gen_onboarding_vif_security_Fail;
	}

	if (!MD5_Update(&ctx, data, strlen(data))) {
		DBG_ERR("md5 update failed");
		goto gen_onboarding_vif_security_Fail;
	}

	if (!MD5_Final(outmd, &ctx)) {
		DBG_ERR("md5 final failed");
		goto gen_onboarding_vif_security_Fail;
	}

	hex2str_x(&outmd[0], key, sizeof(outmd));
	if (IsNULL_PTR(key) || strlen(key) <= 0)
	{
		DBG_ERR("key is empty !!");
		goto gen_onboarding_vif_security_Fail;
	}
	DBG_INFO("key : %s", key);

	/* for ssid based on bundle_key_hex */
	memset(key_hex, 0, sizeof(key_hex));
	str2hex_x(key, key_hex);
	ssid_hex = gen_sha256_key(key_hex, sizeof(key_hex), &ssidKeyLen);
	if (IsNULL_PTR(ssid_hex) || ssidKeyLen <= 0)
	{
		DBG_ERR("gen_sha256_key() failed ...");
		goto gen_onboarding_vif_security_Fail;
	}

	memset(ssid_str, 0, sizeof(ssid_str));
	hex2str_x(ssid_hex, ssid_str, ssidKeyLen);
	strlcpy(ssid, &ssid_str[ssidKeyLen], ssid_len);
	DBG_INFO("ssid_str (%s), ssidKeyLen (%d)", ssid_str, ssidKeyLen);
	DBG_INFO("ssid (%s)", ssid);

	/* for psk based on ssid_hex */
	psk_hex = gen_sha256_key(ssid_hex, ssidKeyLen, &pskKeyLen);
	if (IsNULL_PTR(psk_hex) || pskKeyLen <= 0)
	{
		DBG_ERR("gen_sha256_key() failed ...");
		goto gen_onboarding_vif_security_Fail;
	}

	memset(psk_str, 0, sizeof(psk_str));
	hex2str_x(psk_hex, psk_str, pskKeyLen);
	strlcpy(psk, &psk_str[pskKeyLen], psk_len);
	DBG_INFO("psk_str (%s), pskKeyLen (%d)", psk_str, pskKeyLen);
	DBG_INFO("psk (%s)", psk);

	MFREE(ssid_hex);
	MFREE(psk_hex);
	return 1;

gen_onboarding_vif_security_Fail:

	if (!IsNULL_PTR(ssid_hex)) MFREE(ssid_hex);
	if (!IsNULL_PTR(psk_hex)) MFREE(psk_hex);
	return 0;
}
#endif /* RTCONFIG_VIF_ONBOARDING */

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_GET
//
////////////////////////////////////////////////////////////////////////////////
#if defined(USE_GET_TLV_SUPPORT_MAC)
char* LLDP_NBR_TLV_GET(
	char *ifname,
	int bandindex,
	int capability5g,
	char *ifmac,
	unsigned int tlv_type,
	size_t *out_len,
	AMAS_RESULT *AMASRes)
#else	// USE_GET_TLV_SUPPORT_MAC
char* LLDP_NBR_TLV_GET(
	char *ifname,
	int bandindex,
	int capability5g,
	unsigned int tlv_type,
	size_t *out_len,
	AMAS_RESULT *AMASRes)
#endif	// USE_GET_TLV_SUPPORT_MAC
{
#define READ_BLOCK_SIZE 	512
	struct json_object *in = NULL, *root_array = NULL, *iface_array = NULL, *root_tlv_array = NULL, *sub_tlv_array = NULL, *root = NULL, *o = NULL, *oo = NULL, *ooo = NULL, *v = NULL, *port = NULL, *descr = NULL, *chassis = NULL, *host = NULL;
	array_list *root_array_list = NULL, *iface_array_list = NULL, *root_tlv_array_list = NULL, *sub_tlv_array_list = NULL;
	FILE *file = NULL;
	char *b = NULL, *s = NULL, *ss = NULL, ifname_isfind = 0, *P = NULL, str[81], *sys_descr = NULL, str1[6][80], str2[100][30], str3[513];
	int i, j, x, k, iface_count = 0, root_tlv_count = 0, sub_tlv_count = 0, str1_count = 0, str2_count = 0;
	size_t read_len = 0, file_size = 0, out_size = 0, tlv_total_data_len = 0;
	AMAS_RESULT res = AMAS_RESULT_FAILED;

#if defined(USE_GET_TLV_SUPPORT_MAC)
	struct json_object *port_id = NULL, *port_type = NULL, *port_value = NULL;
	char *str_port_type = NULL, *str_port_value = NULL;
	char ifname_match = 0, ifmac_match = 0, group_id_match = 0;
#endif	// USE_GET_TLV_SUPPORT_MAC

#if USE_FILE_LOCK
	int f_lock = -1;
#endif	// USE_FILE_LOCK;

#if	defined(USE_GET_TLV_SUPPORT_MAC)
	if ((IsNULL_PTR(ifmac) || strlen(ifmac) <= 0) && (IsNULL_PTR(ifname) || strlen(ifname) <= 0))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	if (!IsNULL_PTR(ifmac) && strlen(ifmac) > 0)
	{
		if (strlen(ifmac) != 17 || AdvSplitStr_Count(1, ifmac, ":") != 6)
		{
			DBG_ERR("mac address invalid ...");
			SET_AMAS_RESULT(&res, AMAS_RESULT_INVALID_VALUE);
			goto LLDP_NBR_TLV_GET_Fail;
		}
	}
#else	// USE_GET_TLV_SUPPORT_MAC
	if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_GET_Fail;
	}
#endif	// USE_GET_TLV_SUPPORT_MAC

#if USE_FILE_LOCK
	if ((f_lock = file_lock(SZ_LLDPCLI_FILELOCK)) == -1)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_FILE_LOCK_ERROR);
		goto LLDP_NBR_TLV_GET_Fail;
	}
#endif	// USE_FILE_LOCK

#if	USE_POPEN_READ_NBRS
	file = popen("lldpcli -f json show neighbors", "r");
	if (IsNULL_PTR(file))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_FILE_OPEN_ERROR);
		goto LLDP_NBR_TLV_GET_Fail;
	}

#elif USE_READ_EXTERNAL_NBR
	DBG_INFO("USE_READ_EXTERNAL_NBR !!!");
	file = fopen(SZ_NBR_EXTERNAL_FILE, "rb");
	if (IsNULL_PTR(file))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_FILE_OPEN_ERROR);
		goto LLDP_NBR_TLV_GET_Fail;
	}

#else	// do "lldpcli -f json show neighbors >%s"
	remove(SZ_LLDP_SHOW_NBR_OUTFNAME);
	doSystem("lldpcli -f json show neighbors >%s", SZ_LLDP_SHOW_NBR_OUTFNAME);
	file = fopen(SZ_LLDP_SHOW_NBR_OUTFNAME, "rb");
	if (IsNULL_PTR(file))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_FILE_OPEN_ERROR);
		goto LLDP_NBR_TLV_GET_Fail;
	}
#endif	// USE_POPEN_READ_NBRS

	b = (char *)realloc(b, READ_BLOCK_SIZE);
	if (IsNULL_PTR(b))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	while ((read_len = fread(&b[file_size], sizeof(char), READ_BLOCK_SIZE, file)) == READ_BLOCK_SIZE)
	{
		file_size += read_len;
		b = (char *)realloc(b, file_size + READ_BLOCK_SIZE);
		if (IsNULL_PTR(b))
		{
			SET_AMAS_RESULT(&res, AMAS_RESULT_MEM_ALLOCATE_ERROR);
			goto LLDP_NBR_TLV_GET_Fail;
		}
	}

	file_size += read_len;
	b[file_size] = 0;

	if (file_size <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_DATA_IS_EMPTY);
		goto LLDP_NBR_TLV_GET_Fail;
	}
#if	USE_POPEN_READ_NBRS
	pclose(file);
#else 	// USE_POPEN_READ_NBRS
	fclose(file);
#endif	// USE_POPEN_READ_NBRS
	file = NULL;

#if USE_FILE_LOCK
	file_unlock(f_lock);
	f_lock = -1;
#endif	// USE_FILE_LOCK

	in = json_tokener_parse(b);
	if (IsNULL_PTR(in))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_JSON_UNABLE_TO_PARSE);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	// lldp
	if (json_object_object_get_ex(in, "lldp\0", &root_array) == FALSE)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_JSON_UNABLE_TO_PARSE);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	if (IsNULL_PTR(root_array))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_JSON_UNABLE_TO_PARSE);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	if (json_object_get_type(root_array) == json_type_array)
	{
		root_array_list = json_object_get_array(root_array);
		if (IsNULL_PTR(root_array_list))
		{
			SET_AMAS_RESULT(&res, AMAS_RESULT_JSON_UNABLE_TO_PARSE);
			goto LLDP_NBR_TLV_GET_Fail;
		}

		if (root_array_list->length <= 0)
		{
			SET_AMAS_RESULT(&res, AMAS_RESULT_JSON_UNABLE_TO_PARSE);
			goto LLDP_NBR_TLV_GET_Fail;
		}

		root = json_object_array_get_idx(root_array, 0);
	}
	else
	{
		root = root_array;
	}

	if (IsNULL_PTR(root))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_JSON_UNABLE_TO_PARSE);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	if (json_object_object_get_ex(root, "interface\0", &iface_array) == FALSE)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_IFACE_NO_SEARCH);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	if (IsNULL_PTR(iface_array))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_IFACE_NO_SEARCH);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	if (json_object_get_type(iface_array) == json_type_array)
	{
		iface_array_list = json_object_get_array(iface_array);
		if (IsNULL_PTR(iface_array_list))
		{
			SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_IFACE_NO_SEARCH);
			goto LLDP_NBR_TLV_GET_Fail;
		}

		if ((iface_count = iface_array_list->length) <= 0)
		{
			SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_IFACE_NO_SEARCH);
			goto LLDP_NBR_TLV_GET_Fail;
		}
	}
	else
	{
		iface_count = 1;
	}

	for (i=0; i<iface_count; i++)
	{
		ifname_isfind = 0;
#if defined(USE_GET_TLV_SUPPORT_MAC)
		ifmac_match = 0;
		ifname_match = 0;
#endif 	// USE_GET_TLV_SUPPORT_MAC

		if (json_object_get_type(iface_array) == json_type_array)
		{
			o = json_object_array_get_idx(iface_array, i);
		}
		else
		{
			o = iface_array;
		}

		if (IsNULL_PTR(o))
		{
			continue;
		}

		json_object_object_foreach(o, kk, vv)
		{
			if (!IsNULL_PTR(kk) && strlen(kk) > 0 && !IsNULL_PTR(vv))
			{
#if	defined(USE_GET_TLV_SUPPORT_MAC)
				if (!IsNULL_PTR(ifname) && strlen(ifname) > 0)
				{
					if (strlen(kk) == strlen(ifname) && strncmp(kk, ifname, strlen(kk)) == 0)
					{
						ifname_match = 1;
					}
				}

				if (!IsNULL_PTR(ifmac) && strlen(ifmac) > 0)
				{
					// port
					if (json_object_object_get_ex(vv, "port\0", &port) == FALSE) continue;
					if (IsNULL_PTR(port)) continue;
					// id
					if (json_object_object_get_ex(port, "id\0", &port_id) == FALSE) continue;
					if (IsNULL_PTR(port_id)) continue;
					// type
					if (json_object_object_get_ex(port_id, "type\0", &port_type) == FALSE) continue;
					if (IsNULL_PTR(port_type)) continue;
					str_port_type = (char *)json_object_get_string(port_type);
					if (IsNULL_PTR(str_port_type)) continue;
					if (strlen(str_port_type) != strlen("mac\0") || strncmp(AdvLowerCase(str_port_type), "mac\0", strlen("mac\0")) != 0) continue;
					// value
					if (json_object_object_get_ex(port_id, "value\0", &port_value) == FALSE) continue;
					if (IsNULL_PTR(port_value)) continue;
					str_port_value = (char *)json_object_get_string(port_value);
					if (IsNULL_PTR(str_port_value)) continue;
					if (strlen(str_port_value) == strlen(ifmac) && strncmp(AdvLowerCase(str_port_value), AdvLowerCase(ifmac), strlen(ifmac)) == 0)
					{
						ifmac_match = 1;
					}
				}

				if (!IsNULL_PTR(ifmac) && strlen(ifmac) > 0 && !IsNULL_PTR(ifname) && strlen(ifname) > 0)
				{
					if (ifname_match == 1 && ifmac_match == 1)
					{
						o = vv;
						ifname_isfind = 1;
						break;
					}
				}
				else
				{
					if (ifname_match == 1 || ifmac_match == 1)
					{
						o = vv;
						ifname_isfind = 1;
						break;
					}
				}

#else	// USE_GET_TLV_SUPPORT_MAC
				if (strlen(kk) == strlen(ifname) && strncmp(kk, ifname, strlen(kk)) == 0)
				{
					if (strncmp(ifname, "dpsta", 5) == 0)
					{
						if (json_object_object_get_ex(vv, "port\0", &port) == FALSE) continue;
						if (IsNULL_PTR(port)) continue;
						if (json_object_object_get_ex(port, "descr\0", &v) == FALSE) continue;
						if (IsNULL_PTR(v)) continue;
						if ((s = (char *)json_object_get_string(v)) == NULL) continue;
						// find chassis
						if (json_object_object_get_ex(vv, "chassis\0", &chassis) == FALSE)
						{
							SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_SYSDESCR_NO_SEACH);
							goto LLDP_NBR_TLV_GET_Fail;
						}
						// find sys descr
						json_object_object_foreach(chassis, ss, host)
						{
							if (IsNULL_PTR(ss) || IsNULL_PTR(host)) continue;
							break;
						}

						if (IsNULL_PTR(host))
						{
							SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_SYSDESCR_NO_SEACH);
							goto LLDP_NBR_TLV_GET_Fail;
						}

						if (json_object_object_get_ex(host, "descr\0", &v) == FALSE)
						{
							SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_SYSDESCR_NO_SEACH);
							goto LLDP_NBR_TLV_GET_Fail;
						}
						if ((sys_descr = (char *)json_object_get_string(v)) == NULL)
						{
							SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_SYSDESCR_NO_SEACH);
							goto LLDP_NBR_TLV_GET_Fail;
						}
						if (strlen(sys_descr) <= 0)
						{
							SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_SYSDESCR_NO_SEACH);
							goto LLDP_NBR_TLV_GET_Fail;
						}

						memset(str1, 0, 6*80);
						str1_count = AdvSplitStr_Count(1, sys_descr, ";");
						AdvSplitStr(1, sys_descr, ";", (char*)str1, 6, 80);
						memset(str3, 0, sizeof(str3));
						for (k=0; k<str1_count; k++)
						{
							if (strlen(str1[k]) > 2)
							{
								if (bandindex > 0 && capability5g == 3)	/* tri band */
								{
									if (atoi(&str1[k][0]) == 1 || atoi(&str2[k][0]) == 2)
									{
										strncat(str3, &str1[k][2], strlen(str1[k])-2);
									}
								}
								else
								{
									if (atoi(&str1[k][0]) == bandindex)
									{
										strncat(str3, &str1[k][2], strlen(str1[k])-2);
										break;
									}
								}
							}
						}

						if (strlen(str3) <= 0)
						{
							SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_SYSDESCR_NO_SEACH);
							goto LLDP_NBR_TLV_GET_Fail;
						}

						memset(str2, 0, 100*30);
						str2_count = AdvSplitStr_Count(1, str3, ",");
						AdvSplitStr(1, str3, ",", (char*)str2, 100, 30);
						for (k=0; k<str2_count; k++)
						{
							if (strncmp(s, str2[k], strlen(str2[k])) == 0)
							{
								ifname_isfind = 1;
								break;
							}
						}

						if (ifname_isfind == 1)
						{
							o = vv;
							break;
						}
					}
					else
					{
						o = vv;
						ifname_isfind = 1;
						break;
					}
				}
#endif	// USE_GET_TLV_SUPPORT_MAC
			}
		}

		if (ifname_isfind == 0)
		{
			continue;
		}

		if (json_object_object_get_ex(o, "unknown-tlvs\0", &root_tlv_array) == FALSE)
		{
			DBG_ERR("json key: unknown-tlvs not found, continue to next ...");
			continue;
		}

		if (json_object_get_type(root_tlv_array) == json_type_array)
		{
			root_tlv_array_list = json_object_get_array(root_tlv_array);
			if (IsNULL_PTR(root_tlv_array_list))
			{
				DBG_ERR("json array unable to parse, continue to next ...");
				continue;
			}

			if ((root_tlv_count = root_tlv_array_list->length) <= 0)
			{
				DBG_ERR("json array unable to parse, continue to next ...");
				continue;
			}
		}
		else
		{
			root_tlv_count = 1;
		}

		for (j = 0; j<root_tlv_count; j++)
		{
			if (json_object_get_type(root_tlv_array) == json_type_array)
			{
				oo = json_object_array_get_idx(root_tlv_array, j);
			}
			else
			{
				oo = root_tlv_array;
			}

			if (IsNULL_PTR(oo)) continue;
			if (json_object_object_get_ex(oo, "unknown-tlv\0", &sub_tlv_array) == FALSE)
			{
				DBG_ERR("json key: unknown-tlv not found, continue to next ...");
				continue;
			}

			if (json_object_get_type(sub_tlv_array) == json_type_array)
			{
				sub_tlv_array_list = json_object_get_array(sub_tlv_array);
				if (IsNULL_PTR(sub_tlv_array_list))
				{
					DBG_ERR("json array unable to parse, continue to next ...");
					continue;
				}

				if ((sub_tlv_count = sub_tlv_array_list->length) <= 0)
				{
					DBG_ERR("json array unable to parse, continue to next ...");
					continue;
				}
			}
			else
			{
				sub_tlv_count = 1;
			}

			// first verify group id
			group_id_match = 0;
			if (tlv_type != AMAS_SUBTYPE_ID)
			{
				for (x = 0; x<sub_tlv_count; x++)
				{
					if (json_object_get_type(sub_tlv_array) == json_type_array)
					{
						ooo = json_object_array_get_idx(sub_tlv_array, x);
					}
					else
					{
						ooo = sub_tlv_array;
					}

					if (IsNULL_PTR(ooo)) continue;
					// oui
					if (json_object_object_get_ex(ooo, "oui\0", &v) == FALSE) continue;
					if (IsNULL_PTR(v)) continue;
					if ((s = (char*)json_object_get_string(v)) == NULL) continue;
					if (strncmp(s, SZ_AMAS_OUI, strlen(SZ_AMAS_OUI)) != 0) continue;
					// subtype
					if (json_object_object_get_ex(ooo, "subtype\0", &v) == FALSE) continue;
					if (IsNULL_PTR(v)) continue;
					if (AMAS_SUBTYPE_ID != (unsigned int)json_object_get_int(v)) continue;
					// len
					if (json_object_object_get_ex(ooo, "len\0", &v) == FALSE)
					{
						DBG_ERR("json key: len not found, continue to next ...");
						continue;
					}

					if (IsNULL_PTR(v))
					{
						DBG_ERR("json key: len is null, continue to next ...");
						continue;
					}

					if (json_object_object_get_ex(ooo, "value\0", &v) == FALSE)
					{
						DBG_ERR("json key: value not found, continue to next ...");
						continue;
					}

					if (IsNULL_PTR(v))
					{
						DBG_ERR("json key: value is null, continue to next ...");
						continue;
					}

					if ((s = (char *)json_object_get_string(v)) == NULL)
					{
						DBG_ERR("json key: value to string is null, continue to next ...");
						continue;
					}

					group_id_match = (group_id_check(s) == AMAS_RESULT_SUCCESS) ? 1 : 0;
					break;
				} // for (x = 0; x<sub_tlv_count; x++)
			}

			if (tlv_type != AMAS_SUBTYPE_ID && group_id_match == 0)
			{
				DBG_ERR("Group ID not match, continue to next ...");
			}

			if ((tlv_type != AMAS_SUBTYPE_ID && group_id_match == 1) || tlv_type == AMAS_SUBTYPE_ID)
			{
				for (x = 0; x<sub_tlv_count; x++)
				{
					if (json_object_get_type(sub_tlv_array) == json_type_array)
					{
						ooo = json_object_array_get_idx(sub_tlv_array, x);
					}
					else
					{
						ooo = sub_tlv_array;
					}
					if (IsNULL_PTR(ooo)) continue;
					// oui
					if (json_object_object_get_ex(ooo, "oui\0", &v) == FALSE) continue;
					if (IsNULL_PTR(v)) continue;
					if ((s = (char*)json_object_get_string(v)) == NULL) continue;
					if (strncmp(s, SZ_AMAS_OUI, strlen(SZ_AMAS_OUI)) != 0) continue;
					// subtype
					if (json_object_object_get_ex(ooo, "subtype\0", &v) == FALSE) continue;
					if (IsNULL_PTR(v)) continue;
					if (tlv_type != (unsigned int)json_object_get_int(v)) continue;
					// len
					if (json_object_object_get_ex(ooo, "len\0", &v) == FALSE)
					{
						DBG_ERR("json key: len not found, continue to next ...");
						continue;
					}

					if (IsNULL_PTR(v))
					{
						DBG_ERR("json key: len is null, continue to next ...");
						continue;
					}

					if (json_object_object_get_ex(ooo, "value\0", &v) == FALSE)
					{
						DBG_ERR("json key: value not found, continue to next ...");
						continue;
					}

					if (IsNULL_PTR(v))
					{
						DBG_ERR("json key: value is null, continue to next ...");
						continue;
					}

					if ((s = (char *)json_object_get_string(v)) == NULL)
					{
						DBG_ERR("json key: value to string is null, continue to next ...");
						continue;
					}

					if (IsNULL_PTR(P))
					{
						MALLOC(P, char, (strlen(s) + 1));
					}
					else
					{
						P = (char *)realloc(P, (out_size + strlen(s) + 1));
					}

					if (IsNULL_PTR(P))
					{
						DBG_ERR("Memory allocate fail, continue to next ...");
						continue;
					}

					memcpy((char *)&P[out_size], (char *)&s[0], strlen(s));
					out_size += strlen(s);
					memcpy((char *)&P[out_size], (char *)";", 1);
					out_size += 1;
					break;
				}	// for (x = 0; x<sub_tlv_count; x++)
			}
			break;
		}	// for (j = 0; j<root_tlv_count; j++)
	}	// for (i=0; i<iface_count; i++)

	if (IsNULL_PTR(P) || out_size <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_IFACE_NO_SEARCH);
		goto LLDP_NBR_TLV_GET_Fail;
	}

	P[out_size-1] = '\0';
	if (!IsNULL_PTR(out_len)) *(out_len) = out_size;
	if (!IsNULL_PTR(b)) MFREE(b);
	if (!IsNULL_PTR(in)) JSON_C_FREE(in);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = AMAS_RESULT_SUCCESS;
	return P;

LLDP_NBR_TLV_GET_Fail:
	if (!IsNULL_PTR(b)) MFREE(b);
	if (!IsNULL_PTR(P)) MFREE(P);
#if	USE_POPEN_READ_NBRS
	if (!IsNULL_PTR(file)) pclose(file);
#else 	// USE_POPEN_READ_NBRS
	if (!IsNULL_PTR(file)) fclose(file);
#endif	// USE_POPEN_READ_NBRS

#if USE_FILE_LOCK
	if (f_lock > -1) file_unlock(f_lock);
#endif	// USE_FILE_LOCK
	if (!IsNULL_PTR(in)) JSON_C_FREE(in);
	if (!IsNULL_PTR(out_len)) *(out_len) = 0;
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = res;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_GET_INT
//
////////////////////////////////////////////////////////////////////////////////
#if defined(USE_GET_TLV_SUPPORT_MAC)
int* LLDP_NBR_TLV_GET_INT(
	char *ifname,
	int bandindex,
	int capability5g,
	char *ifmac,
	unsigned int tlv_type,
	unsigned int *ret_array_size,
	AMAS_RESULT *AMASRes)
#else	// USE_GET_TLV_SUPPORT_MAC
int* LLDP_NBR_TLV_GET_INT(
	char *ifname,
	int bandindex,
	int capability5g,
	unsigned int tlv_type,
	unsigned int *ret_array_size,
	AMAS_RESULT *AMASRes)
#endif	// USE_GET_TLV_SUPPORT_MAC
{
	AMAS_RESULT res = AMAS_RESULT_FAILED, result = AMAS_RESULT_FAILED;
	int i, j, c = 0, x = 0, x1 = 0, x2 = 0, *v = NULL;
	size_t out_len = 0, s1_alloc_size = 0, s2_alloc_size = 0;
	char *b = NULL, *s1 = NULL, *s2 = NULL;

#if !defined(USE_GET_TLV_SUPPORT_MAC)
	if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_GET_INT_Fail;
	}
#endif	// !USE_GET_TLV_SUPPORT_MAC

#if defined(USE_GET_TLV_SUPPORT_MAC)
	b = LLDP_NBR_TLV_GET(ifname, bandindex, capability5g, ifmac, tlv_type, &out_len, &res);
#else	// USE_GET_TLV_SUPPORT_MAC
	b = LLDP_NBR_TLV_GET(ifname, bandindex, capability5g, tlv_type, &out_len, &res);
#endif	// USE_GET_TLV_SUPPORT_MAC
	if (IsNULL_PTR(b))
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_GET_INT_Fail;
	}

	c = AdvSplitStr_Count(1, (char *)b, ";");
	if (c <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_NBR_TLV_UNABLE_TO_PARSE);
		goto LLDP_NBR_TLV_GET_INT_Fail;
	}

	MALLOC(v, int, (c * sizeof(int)));
	if (IsNULL_PTR(v))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto LLDP_NBR_TLV_GET_INT_Fail;
	}

	MALLOC(s1, char, (c * (MAX_LLDP_TLV_VALUE_SIZE + 1)));
	if (IsNULL_PTR(s1))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto LLDP_NBR_TLV_GET_INT_Fail;
	}

	AdvSplitStr(1, b, ";", (char *)s1, c, (MAX_LLDP_TLV_VALUE_SIZE + 1));
	for (i=0; i<c; i++)
	{
		x = AdvSplitStr_Count(1, (char *)&s1[i * (MAX_LLDP_TLV_VALUE_SIZE + 1)], ",");
		if (x > 0)
		{
			MALLOC(s2, char, (x * 2) + 1);
			if (IsNULL_PTR(s2))
			{
				SET_AMAS_RESULT(&result, AMAS_RESULT_MEM_ALLOCATE_ERROR);
				goto LLDP_NBR_TLV_GET_INT_Fail;
			}
			AdvSplitStr(1, (char *)&s1[i * (MAX_LLDP_TLV_VALUE_SIZE + 1)], ",", (char *)s2, x, 2);
			v[i] = (int)strtoul(s2, NULL, 16);
			MFREE(s2);
			s2 = NULL;
		}
	}

	if (!IsNULL_PTR(ret_array_size)) *(ret_array_size) = c;
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = AMAS_RESULT_SUCCESS;
	MFREE(s1);
	MFREE(b);
	return v;

LLDP_NBR_TLV_GET_INT_Fail:
	if (!IsNULL_PTR(s1)) MFREE(s1);
	if (!IsNULL_PTR(s2)) MFREE(s2);
	if (!IsNULL_PTR(v)) MFREE(v);
	if (!IsNULL_PTR(b)) MFREE(b);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = result;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_GET_INT_MAX
//
////////////////////////////////////////////////////////////////////////////////
#if defined(USE_GET_TLV_SUPPORT_MAC)
int LLDP_NBR_TLV_GET_INT_MAX(
	char *ifname,
	int bandindex,
	int capability5g,
	char *ifmac,
	unsigned int tlv_type,
	AMAS_RESULT *AMASRes)
#else	// USE_GET_TLV_SUPPORT_MAC
int LLDP_NBR_TLV_GET_INT_MAX(
	char *ifname,
	int bandindex,
	int capability5g,
	unsigned int tlv_type,
	AMAS_RESULT *AMASRes)
#endif	// USE_GET_TLV_SUPPORT_MAC
{
	AMAS_RESULT res = AMAS_RESULT_FAILED, result = AMAS_RESULT_SUCCESS;
	unsigned array_size = 0;
	int i = 0, val = INT_MIN, *P = NULL;

#if !defined(USE_GET_TLV_SUPPORT_MAC)
	if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_GET_INT_MAX_Fail;
	}
#endif	// !USE_GET_TLV_SUPPORT_MAC

#if defined(USE_GET_TLV_SUPPORT_MAC)
	P = LLDP_NBR_TLV_GET_INT(ifname, bandindex, capability5g, ifmac, tlv_type, &array_size, &res);
#else	// USE_GET_TLV_SUPPORT_MAC
	P = LLDP_NBR_TLV_GET_INT(ifname, bandindex, capability5g, tlv_type, &array_size, &res);
#endif	// USE_GET_TLV_SUPPORT_MAC
	if (res != AMAS_RESULT_SUCCESS)
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_GET_INT_MAX_Fail;
	}

	if (IsNULL_PTR(P) || array_size <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_NBR_TLV_TYPE_NO_FOUND);
		goto LLDP_NBR_TLV_GET_INT_MAX_Fail;
	}

	for (i=0; i<array_size; i++)
	{
		if (P[i] > val)
		{
			val = P[i];
		}
	}

	MFREE(P);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = AMAS_RESULT_SUCCESS;
	return val;

LLDP_NBR_TLV_GET_INT_MAX_Fail:
	if (!IsNULL_PTR(P)) MFREE(P);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = result;
	return -1;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_GET_INT_MIN
//
////////////////////////////////////////////////////////////////////////////////
#if defined(USE_GET_TLV_SUPPORT_MAC)
int LLDP_NBR_TLV_GET_INT_MIN(
	char *ifname,
	int bandindex,
	int capability5g,
	char *ifmac,
	unsigned int tlv_type,
	AMAS_RESULT *AMASRes)
#else	// USE_GET_TLV_SUPPORT_MAC
int LLDP_NBR_TLV_GET_INT_MIN(
	char *ifname,
	int bandindex,
	int capability5g,
	unsigned int tlv_type,
	AMAS_RESULT *AMASRes)
#endif	// USE_GET_TLV_SUPPORT_MAC
{
	AMAS_RESULT res = AMAS_RESULT_FAILED, result = AMAS_RESULT_SUCCESS;
	unsigned array_size = 0;
	int i = 0, val = INT_MAX, *P = NULL;

#if !defined(USE_GET_TLV_SUPPORT_MAC)
	if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_GET_INT_MAX_Fail;
	}
#endif	// !USE_GET_TLV_SUPPORT_MAC

#if defined(USE_GET_TLV_SUPPORT_MAC)
	P = LLDP_NBR_TLV_GET_INT(ifname, bandindex, capability5g, ifmac, tlv_type, &array_size, &res);
#else	// USE_GET_TLV_SUPPORT_MAC
	P = LLDP_NBR_TLV_GET_INT(ifname, bandindex, capability5g, tlv_type, &array_size, &res);
#endif	// USE_GET_TLV_SUPPORT_MAC

	if (res != AMAS_RESULT_SUCCESS)
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_GET_INT_MAX_Fail;
	}

	if (IsNULL_PTR(P) || array_size <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_NBR_TLV_TYPE_NO_FOUND);
		goto LLDP_NBR_TLV_GET_INT_MAX_Fail;
	}

	for (i=0; i<array_size; i++)
	{
		if (P[i] > -1)
		{
			if (P[i] < val)
			{
				val = P[i];
			}
		}
	}

	if (val == INT_MAX)
	{
		val = P[0];
	}

	MFREE(P);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = AMAS_RESULT_SUCCESS;
	return val;

LLDP_NBR_TLV_GET_INT_MAX_Fail:
	if (!IsNULL_PTR(P)) MFREE(P);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = result;
	return -1;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_GET_BUFFER
//
////////////////////////////////////////////////////////////////////////////////
typedef struct LLDP_TLV_t
{
	unsigned int type;
	unsigned int len;
	unsigned char value[MAX_LLDP_TLV_VALUE_SIZE];
} LLDP_TLV;

#if defined(USE_GET_TLV_SUPPORT_MAC)
LLDP_TLV* LLDP_NBR_TLV_GET_BUFFER(
	char *ifname,
	int bandindex,
	int capability5g,
	char *ifmac,
	unsigned int tlv_type,
	unsigned int *ret_array_size,
	AMAS_RESULT *AMASRes)
#else	// USE_GET_TLV_SUPPORT_MAC
LLDP_TLV* LLDP_NBR_TLV_GET_BUFFER(
	char *ifname,
	int bandindex,
	int capability5g,
	unsigned int tlv_type,
	unsigned int *ret_array_size,
	AMAS_RESULT *AMASRes)
#endif	// USE_GET_TLV_SUPPORT_MAC
{
	AMAS_RESULT res = AMAS_RESULT_FAILED;
	LLDP_TLV tlv, *P = NULL, *PP = NULL;
	int i, j, c = 0, x = 0, x1 = 0, array_column_size = (MAX_LLDP_TLV_VALUE_SIZE * 2) + MAX_LLDP_TLV_VALUE_SIZE + 1;
	size_t out_len = 0, s1_alloc_size = 0, s2_alloc_size = 0;
	char *b = NULL, *s1 = NULL, *s2 = NULL;

#if !defined(USE_GET_TLV_SUPPORT_MAC)
	if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_GET_BUFFER_Fail;
	}
#endif	// USE_GET_TLV_SUPPORT_MAC

#if defined(USE_GET_TLV_SUPPORT_MAC)
	b = LLDP_NBR_TLV_GET(ifname, bandindex, capability5g, ifmac, tlv_type, &out_len, &res);
#else	// USE_GET_TLV_SUPPORT_MAC
	b = LLDP_NBR_TLV_GET(ifname, bandindex, capability5g, tlv_type, &out_len, &res);
#endif	// USE_GET_TLV_SUPPORT_MAC
	if (IsNULL_PTR(b))
	{
		SET_AMAS_RESULT(&res, res);
		goto LLDP_NBR_TLV_GET_BUFFER_Fail;
	}

	c = AdvSplitStr_Count(1, (char *)b, ";");
	if (c <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_NBR_TLV_UNABLE_TO_PARSE);
		goto LLDP_NBR_TLV_GET_BUFFER_Fail;
	}

	MALLOC(P, LLDP_TLV, (c * sizeof(LLDP_TLV)));
	if (IsNULL_PTR(P))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto LLDP_NBR_TLV_GET_BUFFER_Fail;
	}
	PP = &P[0];

	MALLOC(s1, char, (c * array_column_size));
	if (IsNULL_PTR(s1))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto LLDP_NBR_TLV_GET_BUFFER_Fail;
	}

	AdvSplitStr(1, b, ";", (char *)s1, c, array_column_size);
	for (i=0; i<c; i++)
	{
		x = AdvSplitStr_Count(1, (char *)&s1[i * array_column_size], ",");
		if (x > 0)
		{
			MALLOC(s2, char, ((x * 2) + 1));
			if (IsNULL_PTR(s2))
			{
				SET_AMAS_RESULT(&res, AMAS_RESULT_MEM_ALLOCATE_ERROR);
				goto LLDP_NBR_TLV_GET_BUFFER_Fail;
			}
			AdvSplitStr(1, (char *)&s1[i * array_column_size], ",", (char *)s2, x, 2);
			memset(&tlv, 0, sizeof(LLDP_TLV));
			tlv.type = tlv_type;
			tlv.len = strlen(s2) / 2;
			str2hex_x(s2, tlv.value);
			memcpy((unsigned char *)PP, (unsigned char *)&tlv, sizeof(LLDP_TLV));
			PP ++;
			MFREE(s2);
			s2 = NULL;
		}
	}

	if (!IsNULL_PTR(ret_array_size)) *(ret_array_size) = c;
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = AMAS_RESULT_SUCCESS;
	MFREE(s1);
	MFREE(b);
	return P;

LLDP_NBR_TLV_GET_BUFFER_Fail:
	if (!IsNULL_PTR(s1)) MFREE(s1);
	if (!IsNULL_PTR(s2)) MFREE(s2);
	if (!IsNULL_PTR(P)) MFREE(P);
	if (!IsNULL_PTR(b)) MFREE(b);
	if (!IsNULL_PTR(AMASRes)) *(AMASRes) = res;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_CLI_SET
//
////////////////////////////////////////////////////////////////////////////////
#define LLDP_CLI_SET(TLV_TYPE, TLV_VALUE, AMAS_RESULT_VALUE) do {\
	AMAS_RESULT AMAS_RES = AMAS_RESULT_FAILED;\
	char *ARGV[] = {"lldpcli", "configure", "lldp", "custom-tlv", "oui", SZ_AMAS_OUI, "subtype", 0, "oui-info", 0, 0};\
	char S_TLV_TYPE[33];\
	\
	if (!IsNULL_PTR(TLV_VALUE))\
	{\
		memset(S_TLV_TYPE, 0, sizeof(S_TLV_TYPE));\
		snprintf(S_TLV_TYPE, sizeof(S_TLV_TYPE)-1, "%02d", TLV_TYPE);\
		ARGV[7] = S_TLV_TYPE;\
		ARGV[9] = TLV_VALUE;\
		\
		{\
			int II;\
			for (II=0; II<10; II++)\
			{\
				printf("ARGV[%d] : %s\n", II, ARGV[II]);\
			}\
		}\
	}\
	else\
	{\
		AMAS_RES = AMAS_RESULT_INVALID_VALUE;\
	}\
	\
	if (!IsNULL_PTR(AMAS_RESULT_VALUE))\
	{\
		*(AMAS_RESULT_VALUE) = AMAS_RES;\
	}\
}while(0)

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_CUSTOM_TLV_CFG_SET
//
////////////////////////////////////////////////////////////////////////////////
AMAS_RESULT LLDP_CUSTOM_TLV_CFG_SET(
	unsigned int tlv_type,
	char *tlv_val,
	size_t tlv_val_len)
{
	AMAS_RESULT res = AMAS_RESULT_SUCCESS;
	char s[133];

#if USE_FILE_LOCK
	int f_lock = -1;
#endif	// USE_FILE_LOCK

	if (IsNULL_PTR(tlv_val) || tlv_val_len <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_CUSTOM_TLV_CFG_SET_Fail;
	}

	memset(s, 0, sizeof(s));
	snprintf(s, sizeof(s)-1, "%d", tlv_type);
#if USE_FILE_LOCK
	if ((f_lock = file_lock(SZ_LLDPCLI_FILELOCK)) == -1)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_FILE_LOCK_ERROR);
		goto LLDP_CUSTOM_TLV_CFG_SET_Fail;
	}
#endif	// USE_FILE_LOCK
DBG_TRACE_LINE;
	DBG_INFO("%s:%d  lldpcli configure lldp custom-tlv replace oui %s subtype %s oui-info %s", __FUNCTION__, __LINE__, SZ_AMAS_OUI, s, tlv_val);
	doSystem("lldpcli configure lldp custom-tlv replace oui %s subtype %s oui-info %s", SZ_AMAS_OUI, s, tlv_val);
DBG_TRACE_LINE;

#if USE_FILE_LOCK
	file_unlock(f_lock);
	f_lock = -1;
#endif	// USE_FILE_LOCK
	return AMAS_RESULT_SUCCESS;

LLDP_CUSTOM_TLV_CFG_SET_Fail:
#if USE_FILE_LOCK
	if (f_lock > -1) file_unlock(f_lock);
#endif 	// USE_FILE_LOCK
	return res;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_SET
//
////////////////////////////////////////////////////////////////////////////////
char* LLDP_NBR_TLV_SET(
	char *tlv_val,
	size_t tlv_val_buffer_size,
	size_t *out_data_len,
	int convert_to_hex,
	AMAS_RESULT *AMASRes)
{
	AMAS_RESULT res = AMAS_RESULT_SUCCESS;
	char *s = NULL, *ss = NULL, sss[33], *P = NULL, *PP = NULL;
	size_t alloc_size = 0;
	int c;

	if (IsNULL_PTR(tlv_val) || tlv_val_buffer_size <= 0)
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_INVALID_VALUE);
		goto LLDP_NBR_TLV_SET_Fail;
	}

	s = &tlv_val[0];
	ss = &tlv_val[tlv_val_buffer_size];

	alloc_size = tlv_val_buffer_size * 4;
	MALLOC(P, char, alloc_size);
	if (IsNULL_PTR(P))
	{
		SET_AMAS_RESULT(&res, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto LLDP_NBR_TLV_SET_Fail;
	}

	if (convert_to_hex == 1)
	{
		for (c=0, PP=&P[0]; s<ss; s++)
		{
			memset(sss, 0, sizeof(sss));
			snprintf(sss, sizeof(sss)-1, "%02X,", (unsigned char)(*s));
			strncpy(PP, sss, strlen(sss));
			PP += strlen(sss);
		}
		P[strlen(P)-1] = '\0';
	}
	else
	{
		for (c=0, PP=&P[0]; s<ss; s+=2)
		{
			memset(sss, 0, sizeof(sss));
			snprintf(sss, sizeof(sss)-1, "%c%c,", *s, *(s+1));
			strncpy(PP, sss, strlen(sss));
			PP += strlen(sss);
		}
		P[strlen(P)-1] = '\0';
	}

	if (!IsNULL_PTR(AMASRes)) *AMASRes = res;
	if (!IsNULL_PTR(out_data_len)) *out_data_len = strlen(P);
	return P;

LLDP_NBR_TLV_SET_Fail:
	if (!IsNULL_PTR(AMASRes)) *AMASRes = res;
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_SET_INT
//
////////////////////////////////////////////////////////////////////////////////
AMAS_RESULT LLDP_NBR_TLV_SET_INT(
	unsigned int tlv_type,
	int tlv_val)
{
	AMAS_RESULT res = AMAS_RESULT_FAILED, result = AMAS_RESULT_FAILED;
	char *s = NULL;
	int v = htonl(tlv_val);

	s = LLDP_NBR_TLV_SET((char *)&v, sizeof(int), NULL, 1, &res);
	if (IsNULL_PTR(s))
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_SET_INT_Fail;
	}

	res = LLDP_CUSTOM_TLV_CFG_SET(tlv_type, s, strlen(s));
	if (res != AMAS_RESULT_SUCCESS)
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_SET_INT_Fail;
	}

	MFREE(s);
	return AMAS_RESULT_SUCCESS;

LLDP_NBR_TLV_SET_INT_Fail:
	if (!IsNULL_PTR(s)) MFREE(s);
	return result;
}

////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_SET_HEX_BUFFER
//
////////////////////////////////////////////////////////////////////////////////
AMAS_RESULT LLDP_NBR_TLV_SET_HEX_BUFFER(
	unsigned int tlv_type,
	char *tlv_val,
	size_t tlv_val_buffer_size)
{
	AMAS_RESULT res = AMAS_RESULT_FAILED, result = AMAS_RESULT_FAILED;
	char *s = NULL;
	size_t out_str_len = 0;

	s = LLDP_NBR_TLV_SET(tlv_val, tlv_val_buffer_size, &out_str_len, 0, &res);
	if (IsNULL_PTR(s))
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_SET_HEX_BUFFER_Fail;
	}

	res = LLDP_CUSTOM_TLV_CFG_SET(tlv_type, s, strlen(s));
	if (res != AMAS_RESULT_SUCCESS)
	{
		SET_AMAS_RESULT(&result, res);
		goto LLDP_NBR_TLV_SET_HEX_BUFFER_Fail;
	}

	MFREE(s);
	return AMAS_RESULT_SUCCESS;

LLDP_NBR_TLV_SET_HEX_BUFFER_Fail:
	if (!IsNULL_PTR(s)) MFREE(s);
	return result;
}


////////////////////////////////////////////////////////////////////////////////
//
//	LLDP_NBR_TLV_CLEAR_BY_SUBTYPE
//
////////////////////////////////////////////////////////////////////////////////
AMAS_RESULT LLDP_NBR_TLV_CLEAR_BY_SUBTYPE(
	unsigned int tlv_type)
{

	DBG_INFO("%s:%d lldpcli unconfigure lldp custom-tlv oui %s subtype %d", __FUNCTION__, __LINE__, SZ_AMAS_OUI, tlv_type);
	doSystem("lldpcli unconfigure lldp custom-tlv oui %s subtype %d", SZ_AMAS_OUI, tlv_type);

	return AMAS_RESULT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//
//	nvram_safe_get_x
//
////////////////////////////////////////////////////////////////////////////////
char *nvram_safe_get_x(
	char *key)
{
typedef struct nvram_t {
	char *k;
	char *v;
} nvram;

static struct nvram_t nvram_map[] =
{
	{	"cfg_group\0", 	"2F76E575E1EB6793292354D007B9DD6C\0"	},
	//{	"cfg_group\0", 	"B75D4ED35BD6BFE2B36E0DCD03BDA75E\0"	},
	{	NULL,			NULL	},
};
	char *PP = NULL;
	nvram *P = (nvram *)&nvram_map[0];
	while (!IsNULL_PTR(P->k))
	{
		if (strncmp(P->k, key, strlen(key)) == 0)
		{
			PP = P->v;
			break;
		}
		P++;
	}

	return PP;
}

#ifdef USE_CHECK_DEBUG
#define CHECK_DEBUG() do {\
	char *s = nvram_safe_get("libamas_utils_dbg");\
	if (!IsNULL_PTR(s) && strlen(s) > 0)\
	{\
		amas_utils_set_debug((atoi(s)==0)?0:1);\
	}\
}while(0)
#else
#define CHECK_DEBUG() do { }while(0)
#endif	/* USE_CHECK_DEBUG */


////////////////////////////////////////////////////////////////////////////////
//
//	verify_vsie_id
//
////////////////////////////////////////////////////////////////////////////////
#if defined(USE_GET_TLV_SUPPORT_MAC)
AMAS_RESULT verify_vsie_id(
	char *ifname,
	int bandindex,
	int capability5g,
	char *ifmac)
#else	// USE_GET_TLV_SUPPORT_MAC
AMAS_RESULT verify_vsie_id(
	char *ifname,
	int bandindex,
	int capability5g)
#endif	// USE_GET_TLV_SUPPORT_MAC
{
	AMAS_RESULT res = AMAS_RESULT_FAILED, result = AMAS_RESULT_FAILED;
	int ts = 0;
	unsigned int array_size = 0;
	LLDP_TLV *P = NULL, *PP = NULL;
	char *id1 = NULL, *id2 = NULL;
	size_t id1_len =  MAX_VSIEID_LENGTH * 2, id2_len = 0;

#if USE_READ_EXTERNAL_NBR
	return AMAS_RESULT_SUCCESS;
#endif	// USE_READ_EXTERNAL_NBR

#if !defined(USE_GET_TLV_SUPPORT_MAC)
	if (IsNULL_PTR(ifname) || strlen(ifname) <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_INVALID_VALUE);
		goto verify_vsie_id_Fail;
	}
#endif	// !USE_GET_TLV_SUPPORT_MAC

#if defined(USE_GET_TLV_SUPPORT_MAC)
	P = LLDP_NBR_TLV_GET_BUFFER(ifname, bandindex, capability5g, ifmac, AMAS_SUBTYPE_ID, &array_size, &res);
#else	// USE_GET_TLV_SUPPORT_MAC
	P = LLDP_NBR_TLV_GET_BUFFER(ifname, bandindex, capability5g, AMAS_SUBTYPE_ID, &array_size, &res);
#endif	// USE_GET_TLV_SUPPORT_MAC
	if (res != AMAS_RESULT_SUCCESS)
	{
		SET_AMAS_RESULT(&result, res);
		goto verify_vsie_id_Fail;
	}

	if (IsNULL_PTR(P) || array_size <= 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_NBR_TLV_TYPE_NO_FOUND);
		goto verify_vsie_id_Fail;
	}

	PP = &P[0];
	// timestamp
	memcpy((unsigned char *)&ts, (unsigned char *)&PP->value[PP->len - sizeof(int)], sizeof(int));
	ts = ntohl(ts);

	// id1
	MALLOC(id1, char, (id1_len + 1));
	if (IsNULL_PTR(id1))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_MEM_ALLOCATE_ERROR);
		goto verify_vsie_id_Fail;
	}
	hex2str_x(PP->value, id1, PP->len);

	// id2
	id2 = gen_vsie_id(ts, &id2_len);
	if (IsNULL_PTR(id2))
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_GEN_VSIEID_FAILED);
		goto verify_vsie_id_Fail;
	}

	if (id1_len != id2_len)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_VERIFY_VSIEID_FAILED);
		goto verify_vsie_id_Fail;
	}

	if (memcmp((unsigned char *)&id1[0], (unsigned char *)&id2[0], id1_len) != 0)
	{
		SET_AMAS_RESULT(&result, AMAS_RESULT_VERIFY_VSIEID_FAILED);
		goto verify_vsie_id_Fail;
	}

	MFREE(P);
	MFREE(id1);
	MFREE(id2);
	return AMAS_RESULT_SUCCESS;

verify_vsie_id_Fail:
	if (!IsNULL_PTR(P)) MFREE(P);
	if (!IsNULL_PTR(id1)) MFREE(id1);
	if (!IsNULL_PTR(id2)) MFREE(id2);
	return result;
}
#if 0
unsigned char s2x(const char c)
{
	unsigned char val = 0;
    switch(c) {
    case '0'...'9':
    	val = (unsigned char)atoi(&c);
    	break;
    case 'a'...'f':
        val = 0xa + (c-'a');
        break;
    case 'A'...'F':
        val = 0xa + (c-'A');
        break;
    default:
        return 0;
    }
    printf("c = %X, val = %x\n", c, val);
    return val;
}
#endif
unsigned char s2x(char *c)
{
	unsigned char val = 0;

    switch(c[0]) {
    case '0'...'9':
    	val = (unsigned char)atoi(c);
    	break;
    case 'a'...'f':
        val = 0xa + (c[0]-'a');
        break;
    case 'A'...'F':
        val = 0xa + (c[0]-'A');
        break;
    default:
        return 0;
    }
    return val;
}

/*
translate String to HEX
for example:
	str (input): D8:50:E6:45:0E:21 (string)
	hex (output): 0xD8 0x50 0xE6 0x45 0x0E 0x21 (hex)

	str (input): 00,00,00,01 (string)
	hex (output): 0x00 0x00 0x00 0x01 (hex)
*/
#define STR2HEX(hex, str, len)  \
    do { \
        int i = 0;\
        char temp1[2]={0};\
        char temp2[2]={0};\
        for(i = 0; i < len; i++) {\
        	temp1[0]=str[i*3];\
        	temp1[1]='\0';\
        	temp2[0]=str[i*3 + 1];\
        	temp2[1]='\0';\
        	hex[i] = (s2x(temp1) << 4) + s2x(temp2);\
        }\
    } while(0)
/*
translate HEX to Decimal
for example:
	hex (input) : 0x00 0x00 0x00 0x11 (hex)
	value (output): 17 (decimal)
*/
#define HEXVAL(hex, value, len)  \
    do { \
         int i = 0, j = 0;\
         j = len - 1;\
        for(i = 0; i < len; i++) {\
            value |= (hex[i]<<(8*j));\
            j--;\
        }\
    } while(0)


/*
translate String to ASCII
for example:
	str (input): "RT-AC68U" (String)
	hex (output): 52 54 2D 41 43 36 38 55 (ASCII)
*/

#define STR2ASCII(hex, str, len)  \
    do { \
         int i = 0;\
        for(i = 0; i < len; i++) {\
            hex[i] = str[i];\
        }\
    } while(0)


/*
translate ASCII to String
for example:
	hex (input): 52 54 2D 41 43 36 38 55 (ASCII)
	str (output): "RT-AC68U"  (String)
*/


#define ASCII2STR(hex, str, len)  \
    do { \
         int i = 0;\
        for(i = 0; i < len; i++) {\
            str[i] = hex[i];\
        }\
    } while(0)

/*
translate String to HEX and string of hex value
for example:
	str (input): "RT-AC68U" (String)
	hex (output): "52542d4143363855" (String)
*/


#define Hex2String(hex, str, len)  \
    do { \
         int i = 0;\
         char temp[3] = {0};\
        for(i = 0; i < len; i++) {\
            memset(temp, 0x00, sizeof(temp));\
            sprintf(temp, "%02x", str[i]);\
            strncat(hex, temp, strlen(temp));\
        }\
    } while(0)

#endif	/* !__AMASUTILS_INTH__ */

/*
check Hex string.
if string == 0, return 1
if string != 0, return 0
*/
int isNull (unsigned char *string, int len) {
  int i = 0;
  int ret = 1;

  for(i = 0; i < len; i++)  {
  	if(string[i] != 0) {
  		return 0;
  	}
  }
  return 1;
}


#if defined(USE_LLDP_CTRL)
//---------------------------------------------------------------------------
extern int str2hex(const char *str, unsigned char *data, size_t size);
#define UNCHANGED_VALUE				-1000
#define COST_UNCHANGED_VALUE			100
#define RSSI_SCORE_UNCHANGED_VALUE	-1000

int
contains(const char *list, const char *element)
{
	int len;
	if (element == NULL || list == NULL) return 0;
	while (list) {
		len = strlen(element);
		if (!strncmp(list, element, len) &&
		    (list[len] == '\0' || list[len] == ','))
			return 1;
		list = strchr(list, ',');
		if (list) list++;
	}
	return 0;
}
//---------------------------------------------------------------------------
lldpctl_atom_t*
cmd_iterate_on_interfaces(struct lldpctl_conn_t *conn, char* interfaces)
{
	static lldpctl_atom_iter_t *iter = NULL;
	static lldpctl_atom_t *iface_list = NULL;
	static lldpctl_atom_t *iface = NULL;

	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				return NULL;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) return NULL;
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				return NULL;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
	} while (interfaces && !contains(interfaces,
		lldpctl_atom_get_str(iface, lldpctl_k_interface_name)));

	return iface;
}
//---------------------------------------------------------------------------
int replace_oui_info(lldpctl_atom_t *port, lldpctl_atom_t *custom_tlvs, uint16_t subtype, uint8_t *oui_info, int oui_info_len)
{
	lldpctl_atom_t *tlv = lldpctl_atom_create(custom_tlvs);
	char *op = "replace";

	if (!tlv) {
		DBG_INFO("unable to create new custom TLV for port");
		return AMAS_RESULT_FAILED;
	} else {
		/* Configure custom TLV */
		lldpctl_atom_set_buffer(tlv, lldpctl_k_custom_tlv_oui, OUI_ASUS, 3);
		lldpctl_atom_set_int(tlv, lldpctl_k_custom_tlv_oui_subtype, subtype);
		lldpctl_atom_set_buffer(tlv, lldpctl_k_custom_tlv_oui_info_string, oui_info, oui_info_len);
		lldpctl_atom_set_str(tlv, lldpctl_k_custom_tlv_op, op);

		/* Assign it to port */
		lldpctl_atom_set(port, lldpctl_k_custom_tlv, tlv);

		lldpctl_atom_dec_ref(tlv);
	}

	return AMAS_RESULT_SUCCESS;
}

/**
 * @brief Get string value by oui type.
 *
 * @param neighbor lldp neighbor info.
 * @param oui_type What oui type for finding.
 * @param output_string String result value
 * @param output_len String result variable length.
 * @return int String result value length.
 */
int lldp_get_string_value_by_oui_type(lldpctl_atom_t* neighbor, int oui_type, char *output_string, int output_len)
{
	lldpctl_atom_t *custom_list, *custom;
	int have_custom_tlvs = 0;
	size_t i, len, slen;
	char buf[512]; /* should be enough for printing */
	int ret = 0, type = 0, need_dot = 0, is_valid = 0, check_id = -999;

	if (output_string == NULL) {
		ret = -1;
		return ret;
	}

	custom_list = lldpctl_atom_get(neighbor, lldpctl_k_custom_tlvs);
	lldpctl_atom_foreach(custom_list, custom) {
		/* This tag gets added only once, if there are any custom TLVs */
		if (!have_custom_tlvs) {
			DBG_INFO("Unknown TLVs");
			have_custom_tlvs++;
		}
		const uint8_t *oui, *oui_info;
		len = 0;
		oui = lldpctl_atom_get_buffer(custom, lldpctl_k_custom_tlv_oui, &len);
		len = 0;
		oui_info = lldpctl_atom_get_buffer(custom, lldpctl_k_custom_tlv_oui_info_string, &len);
		if (!oui)
			continue;

		if (memcmp(oui, OUI_ASUS, 3)) {
			DBG_INFO("oui dismatch", buf);
			continue;
		}

		DBG_INFO("TLV");

		/* Add OUI as attribute */
		snprintf(buf, sizeof(buf), "%02X,%02X,%02X", oui[0], oui[1], oui[2]);
		DBG_INFO("oui (%s)", buf);

		type = (int)lldpctl_atom_get_int(custom, lldpctl_k_custom_tlv_oui_subtype);
		DBG_INFO( "type (%d)", type);

		DBG_INFO( "len (%d)", (int)len);

		if (len > 0) {
			need_dot = 0;

			if (type == AMAS_SUBTYPE_ID)
				need_dot = 1;

			if (type == AMAS_SUBTYPE_ETH_ROLE)
			{
				for (slen=0, i=0; i < len; ++i)
					slen += snprintf(buf + slen, sizeof(buf) > slen ? sizeof(buf) - slen : 0,
									"%c%s", oui_info[i], ((i < len - 1) ? (need_dot ? ",": "") : ""));
			} else {
				for (slen=0, i=0; i < len; ++i)
					slen += snprintf(buf + slen, sizeof(buf) > slen ? sizeof(buf) - slen : 0,
									"%02X%s", oui_info[i], ((i < len - 1) ? (need_dot ? ",": "") : ""));
			}
			DBG_INFO("buf (%s)", buf);

			/* check group id */
			if (type == AMAS_SUBTYPE_ID) {
				DBG_INFO("handle id");
				check_id = group_id_check(buf);
				DBG_INFO("check_id result %d", check_id);
				is_valid = (check_id == AMAS_RESULT_SUCCESS) ? 1 : 0;
			} else if ((type == AMAS_SUBTYPE_ETH_ROLE && oui_type == AMAS_SUBTYPE_ETH_ROLE) ||
				(oui_type == AMAS_SUBTYPE_WIFI_LASTBYTE && type == AMAS_SUBTYPE_WIFI_LASTBYTE)) {
				if (output_len >= slen)
					strcpy(output_string, buf);
				else
					*output_string = '\0';
			}
		}
	}
	lldpctl_atom_dec_ref(custom_list);

	DBG_INFO("is_valid (%d), output (%s)", is_valid, output_string);
	if (oui_type == AMAS_SUBTYPE_ID && check_id == -999)
		ret = -2;
	else if (is_valid && strlen(output_string) > 0)
		ret = strlen(output_string);
	else
		ret = -1;

	return ret;
}

//---------------------------------------------------------------------------
int lldp_get_value_by_oui_type(lldpctl_atom_t* neighbor, int oui_type)
{
	lldpctl_atom_t *custom_list, *custom;
	int have_custom_tlvs = 0;
	size_t i, len, slen;
	const uint8_t *oui, *oui_info;
	char buf[1600]; /* should be enough for printing */
	int ret = 0, value = UNCHANGED_VALUE, is_valid = 0, type = 0, need_dot = 0;
	AMAS_RESULT result = 0;
	char *cfg_group = NULL;

	custom_list = lldpctl_atom_get(neighbor, lldpctl_k_custom_tlvs);
	lldpctl_atom_foreach(custom_list, custom) {
		/* This tag gets added only once, if there are any custom TLVs */
		if (!have_custom_tlvs) {
			DBG_INFO("Unknown TLVs");
			have_custom_tlvs++;
		}
		len = 0;
		oui = lldpctl_atom_get_buffer(custom, lldpctl_k_custom_tlv_oui, &len);
		len = 0;
		oui_info = lldpctl_atom_get_buffer(custom, lldpctl_k_custom_tlv_oui_info_string, &len);
		if (!oui)
			continue;

		if (memcmp(oui, OUI_ASUS, 3)) {
			DBG_INFO("oui dismatch", buf);
			continue;
		}

		DBG_INFO("TLV");

		/* Add OUI as attribute */
		snprintf(buf, sizeof(buf), "%02X,%02X,%02X", oui[0], oui[1], oui[2]);
		DBG_INFO("oui (%s)", buf);

		type = (int)lldpctl_atom_get_int(custom, lldpctl_k_custom_tlv_oui_subtype);
		DBG_INFO( "type (%d)", type);

		DBG_INFO( "len (%d)", (int)len);

		if (len > 0) {
			need_dot = 0;
			if (type == AMAS_SUBTYPE_ID)
				need_dot = 1;

			for (slen=0, i=0; i < len; ++i)
				slen += snprintf(buf + slen, sizeof(buf) > slen ? sizeof(buf) - slen : 0,
				                 "%02X%s", oui_info[i], ((i < len - 1) ? (need_dot ? ",": "") : ""));
			DBG_INFO("buf (%s)", buf);

			/* check group id */
			if (type == AMAS_SUBTYPE_ID) {
				DBG_INFO("handle id");
				result = group_id_check(buf);
				cfg_group = nvram_safe_get("cfg_group");
				/* onboarding process need return valid value */
				if ((result == AMAS_RESULT_GEN_VSIEID_FAILED) && (IsNULL_PTR(cfg_group) || strlen(cfg_group) <= 0) && (nvram_get_int("re_mode") == 1))
					is_valid = 1;
				else
					is_valid = (result == AMAS_RESULT_SUCCESS) ? 1 : 0;
			}
			else if ((oui_type == AMAS_SUBTYPE_COST && type == AMAS_SUBTYPE_COST) ||
				(oui_type == AMAS_SUBTYPE_RSSI_SCORE && type == AMAS_SUBTYPE_RSSI_SCORE) ||
				(oui_type == AMAS_SUBTYPE_WIFI_LASTBYTE && type == AMAS_SUBTYPE_WIFI_LASTBYTE))
			{
				value= (int)strtoul(buf, NULL, 16);
				DBG_INFO("handle for oui type (%d), value (%d)", type, value);
			}
		}
	}
	lldpctl_atom_dec_ref(custom_list);

	DBG_INFO("is_valid (%d), value (%d)", is_valid, value);
	if (is_valid && value != UNCHANGED_VALUE)
		ret = value;
	else
		ret = UNCHANGED_VALUE;

	return ret;
}
//---------------------------------------------------------------------------
int lldp_set_value_by_default_port(lldpctl_conn_t *conn, int oui_type, unsigned char *oui_info, int oui_info_len)
{
	lldpctl_atom_t *port, *custom_tlvs;
	int ret = AMAS_RESULT_SUCCESS;

	DBG_INFO("set default port");
	port = lldpctl_get_default_port(conn);
	if (!(custom_tlvs = lldpctl_atom_get(port, lldpctl_k_custom_tlvs))) {
		DBG_INFO("unable to get custom TLVs for default port");
	} else {
		if (replace_oui_info(port, custom_tlvs, oui_type, oui_info, oui_info_len) != AMAS_RESULT_SUCCESS) {
			DBG_INFO("replace oui info fail");
			ret = AMAS_RESULT_FAILED;
		}

		lldpctl_atom_dec_ref(custom_tlvs);
	}

	lldpctl_atom_dec_ref(port);

	return ret;
}
//---------------------------------------------------------------------------
int lldp_set_value_by_oui_type(int oui_type, unsigned char *oui_info, int oui_info_len)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface = NULL, *port = NULL, *custom_tlvs = NULL;
	int ret = AMAS_RESULT_SUCCESS;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("fail");
		return AMAS_RESULT_FAILED;
	}

	DBG_INFO("list all interface");
	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				ret = lldp_set_value_by_default_port(conn, oui_type, oui_info, oui_info_len);
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				ret = lldp_set_value_by_default_port(conn, oui_type, oui_info, oui_info_len);
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				ret = lldp_set_value_by_default_port(conn, oui_type, oui_info, oui_info_len);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			if (!(custom_tlvs = lldpctl_atom_get(port, lldpctl_k_custom_tlvs))) {
				DBG_INFO("unable to get custom TLVs for port");
				lldpctl_atom_dec_ref(iface);
				break;
			} else {
				if (replace_oui_info(port, custom_tlvs, oui_type, oui_info, oui_info_len) != AMAS_RESULT_SUCCESS) {
					DBG_INFO("replace oui info fail");
					ret = AMAS_RESULT_FAILED;
					lldpctl_atom_dec_ref(custom_tlvs);
					break;
				}

				lldpctl_atom_dec_ref(custom_tlvs);
			}

			lldpctl_atom_dec_ref(port);
			port = NULL;
		}
	} while (iface);

	if (port) lldpctl_atom_dec_ref(port);

	if (conn) lldpctl_release(conn);

	return ret;
}
//---------------------------------------------------------------------------
int lldp_get_rssi_score(char *ifname, char *ifmac, AMAS_RESULT *res)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
	int ret = 0, value_max = RSSI_SCORE_UNCHANGED_VALUE, value;
	char *port_id_mac;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("fail");
		*res = AMAS_RESULT_FAILED;
		return 0;
	}

	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				*res = AMAS_RESULT_FAILED;
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				DBG_INFO("iter is null");
				*res = AMAS_RESULT_FAILED;
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

			lldpctl_atom_foreach(neighbors, neighbor) {
				port_id_mac = (char *)lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
				if (ifmac)
				{
					if (port_id_mac) {
						DBG_INFO("ifmac (%s), port_id_mac (%s)", ifmac, port_id_mac);
						if(strcasecmp(ifmac, port_id_mac) != 0) {
							DBG_INFO("mac dismatch\n");
							continue;
						}
					}
					else
					{
						DBG_INFO("port_id_mac is null");
						continue;
					}
				}

				if ((value = lldp_get_value_by_oui_type(neighbor, AMAS_SUBTYPE_RSSI_SCORE)) != UNCHANGED_VALUE) {
					if (value > value_max)
						value_max = value;
				}
			}
			lldpctl_atom_dec_ref(neighbors);
			lldpctl_atom_dec_ref(port);
		}
	} while (iface);

	if (conn) lldpctl_release(conn);

	DBG_INFO("value (%d)", value_max);
	if (value_max != RSSI_SCORE_UNCHANGED_VALUE) {
		ret = value_max;
		*res = AMAS_RESULT_SUCCESS;
	}
	else
		*res = AMAS_RESULT_FAILED;

	return ret;
}
//---------------------------------------------------------------------------
int lldp_set_rssi_score(char *id, int id_len, int rssi_score)
{
	int ret = AMAS_RESULT_SUCCESS;
	unsigned char oui_info[512];
	int oui_info_len = 0;

	/* set rssi score */
	memset(oui_info, 0, sizeof(oui_info));
	oui_info_len = 4;
	oui_info[0] = (rssi_score >> 24) & 0xFF;
	oui_info[1] = (rssi_score >> 16) & 0xFF;
	oui_info[2] = (rssi_score >> 8) & 0xFF;
	oui_info[3] = rssi_score & 0xFF;

	if (lldp_set_value_by_oui_type(AMAS_SUBTYPE_RSSI_SCORE, &oui_info[0], oui_info_len) != AMAS_RESULT_SUCCESS) {
		DBG_INFO("set rss score fail");
		ret = AMAS_RESULT_FAILED;
		goto lldp_set_rssi_score_fail;
	}

lldp_set_rssi_score_fail:

	return ret;
}
//---------------------------------------------------------------------------
int lldp_get_cost(char *ifname, char *ifmac, AMAS_RESULT *res)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
	int ret = 0, value_min = COST_UNCHANGED_VALUE, value;
	char *port_id_mac;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;
	char port_descr[32] = {}, buf[512] = {};
	int role_tmp = 0, len = 0, role = -1;
	char *eth_type_s = NULL;

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("fail");
		*res = AMAS_RESULT_FAILED;
		return 0;
	}

	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				*res = AMAS_RESULT_FAILED;
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				DBG_INFO("iter is null");
				*res = AMAS_RESULT_FAILED;
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

			lldpctl_atom_foreach(neighbors, neighbor) {
				snprintf(port_descr, sizeof(port_descr), "%s", lldpctl_atom_get_str(neighbor, lldpctl_k_port_descr));
				if (strlen(port_descr) == 0)
					continue;
				len = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_ETH_ROLE, &buf[0], sizeof(buf));
				if (len <= 0) {
					role_tmp = 0;  // None.
				}
				else {
					eth_type_s = strstr(buf, port_descr);
					if (eth_type_s != NULL) {
						sscanf(eth_type_s, "%*[^:]:%d", &role_tmp);
					} else {
						role_tmp = 1;  // LAN
					}
				}
				value = lldp_get_value_by_oui_type(neighbor, AMAS_SUBTYPE_COST);
				DBG_INFO("Port Descr(%s) Role(%d) value(%d)\n", port_descr, role_tmp, value);
				DBG_INFO("Selected Role(%d) value(%d)\n", role, value_min);
				if (role == -1) {  // first lldpd info
					role = role_tmp;
					value_min = value;
				} else if (role != role_tmp) {  // Others > LAN Loop > WAM
					if (role == 2) {  // WAN
						if (role_tmp != 2) {
							role = role_tmp;
							value_min = value;
						}
					} else {
#ifdef RTCONFIG_QCA_PLC2
						if (role_tmp == 1 && value != UNCHANGED_VALUE && value >= 0 && (role != 1 || value_min < 0 || value < value_min))
						{ // ROLE_LAN is the first priority to be backhaul
							role = role_tmp;
							value_min = value;
						}
#else
						// Compare value.
						if (role_tmp != 2 && value != UNCHANGED_VALUE && value >= 0 && (value_min < 0 || value < value_min)) {
							role = role_tmp;
							value_min = value;
						}
#endif	/* RTCONFIG_QCA_PLC2 */
					}
				} else {
					// update value_min
					if (value != UNCHANGED_VALUE && value >= 0 && (value_min < 0 || value < value_min))
						value_min = value;
				}
			}

			lldpctl_atom_dec_ref(neighbors);
			lldpctl_atom_dec_ref(port);

		}
	} while (iface);

	if (conn) lldpctl_release(conn);

	DBG_INFO("value (%d)", value_min);

	if (value_min != COST_UNCHANGED_VALUE) {
		ret = value_min;
		*res = AMAS_RESULT_SUCCESS;
	}
	else
		*res = AMAS_RESULT_FAILED;

	return ret;
}
//---------------------------------------------------------------------------
int lldp_set_cost(char *id, int id_len, int cost)
{
	int ret = AMAS_RESULT_SUCCESS;
	unsigned char oui_info[512];
	int oui_info_len = 0;

	/* set group id */
	DBG_INFO("set group id");
	memset(oui_info, 0, sizeof(oui_info));
	if (str2hex(id, &oui_info[0], id_len)) {
		oui_info_len = id_len / 2;
		if (lldp_set_value_by_oui_type(AMAS_SUBTYPE_ID, &oui_info[0], oui_info_len) != AMAS_RESULT_SUCCESS) {
			DBG_INFO("set id fail");
			ret = AMAS_RESULT_FAILED;
			goto lldp_set_cost_fail;
		}
	}

	/* set cost */
	DBG_INFO("set cost");
	memset(oui_info, 0, sizeof(oui_info));
	oui_info_len = 4;
	oui_info[0] = (cost >> 24) & 0xFF;
	oui_info[1] = (cost >> 16) & 0xFF;
	oui_info[2] = (cost >> 8) & 0xFF;
	oui_info[3] = cost & 0xFF;

	if (lldp_set_value_by_oui_type(AMAS_SUBTYPE_COST, &oui_info[0], oui_info_len) != AMAS_RESULT_SUCCESS) {
		DBG_INFO("set cost fail");
		ret = AMAS_RESULT_FAILED;
		goto lldp_set_cost_fail;
	}

lldp_set_cost_fail:

	return ret;
}

/**
 * @brief Set ethernet port role.
 *
 * @param id VSIE ID.
 * @param id_len VSIE ID length.
 * @param eth_role ethernet port role.
 * @return int Setting result.
 */
int lldp_set_eth_role(char *id, int id_len, char *eth_role)
{
	int ret = AMAS_RESULT_SUCCESS;
	unsigned char oui_info[512];
	int oui_info_len = 0;
	DBG_INFO("eth_role = %s\n", eth_role);
	memcpy(oui_info, eth_role, strlen(eth_role));
	oui_info_len = strlen(eth_role);

	if (lldp_set_value_by_oui_type(AMAS_SUBTYPE_ETH_ROLE, &oui_info[0], oui_info_len) != AMAS_RESULT_SUCCESS) {
		DBG_INFO("set ethernet port role fail");
		ret = AMAS_RESULT_FAILED;
		goto lldp_set_eth_role_fail;
	}

lldp_set_eth_role_fail:

	return ret;
}

/**
 * @brief Get destination ethernet port role.
 *
 * @param ifname recv from ethernet interface.
 * @param res Processing result.
 * @return int destination ethernet port role.
 */
int lldp_get_dest_eth_role(char *ifname, AMAS_RESULT *res) {
    const char *ctlname = NULL;
    lldpctl_conn_t *conn = NULL;
    lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
    int role_tmp = 0, len = 0, role = -1, cost = -1, cost_min = -1, value = 0;
    char port_descr[32] = {};
    lldpctl_atom_iter_t *iter = NULL;
    lldpctl_atom_t *iface_list = NULL;
    char buf[512] = {0}, buf2[512] = {0};
    ctlname = lldpctl_get_default_transport();
    conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
    char *eth_type_s = NULL;
    char * port_id_mac;
    int lan_cnt = 0;

    if (conn == NULL) {
        DBG_INFO("fail");
        *res = AMAS_RESULT_FAILED;
        return role;
    }

    do {
        if (iter == NULL) {
            iface_list = lldpctl_get_interfaces(conn);
            if (!iface_list) {
                DBG_INFO("not able to get the list of interfaces. %s",
                         lldpctl_last_strerror(conn));
                *res = AMAS_RESULT_FAILED;
                break;
            }
            iter = lldpctl_atom_iter(iface_list);
            if (!iter) {
                DBG_INFO("iter is null");
                *res = AMAS_RESULT_FAILED;
                break;
            }
        } else {
            iter = lldpctl_atom_iter_next(iface_list, iter);
            if (iface) {
                lldpctl_atom_dec_ref(iface);
                iface = NULL;
            }
            if (!iter) {
                lldpctl_atom_dec_ref(iface_list);
                break;
            }
        }

        iface = lldpctl_atom_iter_value(iface_list, iter);
        if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
            DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

            port = lldpctl_get_port(iface);
            neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

            lldpctl_atom_foreach(neighbors, neighbor) {
                snprintf(port_descr, sizeof(port_descr), "%s", lldpctl_atom_get_str(neighbor, lldpctl_k_port_descr));
                if (strlen(port_descr) == 0)
                    continue;
                len = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_ETH_ROLE, &buf[0], sizeof(buf));

                if (len <= 0 && strlen(buf)) {
                    buf2[0] = '\0';
                    value = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_ID, &buf2[0], sizeof(buf2));
                    if(value == -2 || nvram_safe_get("cfg_group")[0] == '\0')
                    {
                        /* dest no group_id or self no cfg_group */
                        len = strlen(buf);
                        DBG_INFO("onboarding ROLE buf(%s)\n", buf);
                    }
                }

                if (len <= 0) {
                    role_tmp = 1;  // LAN.
                }
                else {
                    eth_type_s = strstr(buf, port_descr);
                    if (eth_type_s != NULL) {
                        sscanf(eth_type_s, "%*[^:]:%d", &role_tmp);
                    } else {
                        role_tmp = 1;  // LAN
                    }
                }
                cost = lldp_get_value_by_oui_type(neighbor, AMAS_SUBTYPE_COST);
				DBG_INFO("Port Descr(%s) Role(%d) Cost(%d)\n", port_descr, role_tmp, cost);
				DBG_INFO("Selected Role(%d) Cost(%d)\n", role, cost_min);

                if (role_tmp == 1)
                    lan_cnt++;
                port_id_mac = (char *)lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
				DBG_INFO("lan_cnt(%d) peer_mac(%s)\n", lan_cnt, port_id_mac);

                if (role == -1) {
                    role = role_tmp;
                    cost_min = cost;
                } else if (role != role_tmp) {
                    if (role == 2) {  // WAN
                        if (role_tmp != 2) {
                            role = role_tmp;
                            cost_min = cost;
                        }
					} else {
#ifdef RTCONFIG_QCA_PLC2
			if (role_tmp == 1 && cost != UNCHANGED_VALUE && cost >= 0 && (role != 1 || cost_min < 0 || cost < cost_min))
			{ // ROLE_LAN is the first priority to be backhaul
				role = role_tmp;
				cost_min = cost;
			}
#else
                        // Compare cost.
                        if (role_tmp != 2 && cost >= 0 && cost != UNCHANGED_VALUE && (cost_min < 0 || cost < cost_min)) {
                            role = role_tmp;
                            cost_min = cost;
                        }
#endif	/* RTCONFIG_QCA_PLC2 */
                    }
                } else {
                    // update cost_min
                    if (cost != UNCHANGED_VALUE && cost >= 0 && (cost_min < 0 || cost < cost_min))
                        cost_min = cost;
                }
            }
            lldpctl_atom_dec_ref(neighbors);
            lldpctl_atom_dec_ref(port);
        }
    } while (iface);

    if (conn) lldpctl_release(conn);

lldp_get_dest_eth_role_fail:

    if (role >= 0)
        *res = AMAS_RESULT_SUCCESS;
    else
        *res = AMAS_RESULT_FAILED;

    return role;
}

//---------------------------------------------------------------------------
int lldp_set_wifi_lastbyte(char *id, int id_len, char *wifi_lastbyte, int wifi_lastbyte_len)
{
	int ret = AMAS_RESULT_SUCCESS;
	unsigned char oui_info[512];
	int oui_info_len = 0;

	memcpy(oui_info, wifi_lastbyte, sizeof(wifi_lastbyte));
	oui_info_len = wifi_lastbyte_len;
    DBG_INFO("wifi_lastbyte  = %02X%02X%02X%02X%02X%02X%02X%02X\n", wifi_lastbyte[0], wifi_lastbyte[1], wifi_lastbyte[2], wifi_lastbyte[3], wifi_lastbyte[4], wifi_lastbyte[5], wifi_lastbyte[6], wifi_lastbyte[7]);
    DBG_INFO("oui_info_len  = %d\n", oui_info_len);


	if (lldp_set_value_by_oui_type(AMAS_SUBTYPE_WIFI_LASTBYTE, &oui_info[0], oui_info_len) != AMAS_RESULT_SUCCESS) {
		DBG_INFO("set wifi lastbyte fail");
		ret = AMAS_RESULT_FAILED;
		goto lldp_set_wifi_lastbyte_fail;
	}

lldp_set_wifi_lastbyte_fail:

	return ret;
}

//---------------------------------------------------------------------------
int lldp_get_wifi_lastbyte(char *ifname, char *ifmac, char *lastbyte, int lastbyte_len, AMAS_RESULT *res)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
	int ret = 0, len = 0;
	char *port_id_mac;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;
	char buf[64] = {0};

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("fail");
		*res = AMAS_RESULT_FAILED;
		return 0;
	}

	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				*res = AMAS_RESULT_FAILED;
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				DBG_INFO("iter is null");
				*res = AMAS_RESULT_FAILED;
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

			lldpctl_atom_foreach(neighbors, neighbor) {
				port_id_mac = (char *)lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
				if (ifmac)
				{
					if (port_id_mac) {
						DBG_INFO("ifmac (%s), port_id_mac (%s)", ifmac, port_id_mac);
						if(strcasecmp(ifmac, port_id_mac) != 0) {
							DBG_INFO("mac dismatch\n");
							continue;
						}
					}
					else
					{
						DBG_INFO("port_id_mac is null");
						continue;
					}
				}

				if (len == 0 && strlen(buf) == 0) {
					len = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_WIFI_LASTBYTE, &buf[0], sizeof(buf));
				}
			}
			lldpctl_atom_dec_ref(neighbors);
			lldpctl_atom_dec_ref(port);
		}
	} while (iface);

	if (conn) lldpctl_release(conn);

	if (strlen(buf) > 0) {
		DBG_INFO("buf (%s)", buf);
		strlcpy(lastbyte, buf, lastbyte_len);
		*res = AMAS_RESULT_SUCCESS;
		ret = 1;
	}
	else
	{
		*res = AMAS_RESULT_FAILED;
	}

	return ret;
}

#ifdef RTCONFIG_QCA_PLC2
//---------------------------------------------------------------------------
int lldp_is_plc_head(char *ifname, AMAS_RESULT *res)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
	int ret = 1, peer_cost;
	int try_cnt = 0;
	char *port_id_mac;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;
	unsigned char lan_hwaddr[6];
	unsigned char mac[6];
	int cfg_cost;
	char port_descr[32], buf[256];
	int role_tmp = 0, len = 0, role = -1;
	char *eth_type_s = NULL;
	char *cfg_relist;
	char plc_master[18];
	int is_plc_master;
	char amas_cap_addr[18];
	static int last_is_plc_head = 0;
	static int plc_cap = 0;
	static int no_plc_dev_cnt = 0;


	*res = AMAS_RESULT_FAILED;
	if (nvram_get_int("re_mode") == 0) {
		return 0;
	}

	if (nvram_get_int("cfg_alive") != 1) {
		last_is_plc_head = 0;
		return 0;	//not ready
	}

	snprintf(amas_cap_addr, sizeof(amas_cap_addr), "%s", nvram_safe_get("amas_cap_addr"));
	if (!isValidMacAddress(amas_cap_addr)) {
		return 0;
	}

	snprintf(plc_master, sizeof(plc_master), "%s", nvram_safe_get("cfg_plc_master"));
	if (!isValidMacAddress(plc_master))
		strcpy(plc_master, amas_cap_addr);

	is_plc_master = (strcasecmp(plc_master, get_lan_hwaddr()) == 0);

	if (plc_cap == 1 && is_plc_master == 0) {
		*res = AMAS_RESULT_SUCCESS;
		return 0;	//don't need to be PLC head
	}
	if (is_plc_master == 0 && (nvram_get_int("amas_ethernet") / 10) == CONN_PRI_PLC) {
		*res = AMAS_RESULT_SUCCESS;
		return 0;	// power line first, not to be PLC head
	}

	if (cfg_relist = get_cfg_relist(0))
		toLowerCase(cfg_relist);
	cfg_cost = nvram_get_int("cfg_cost");
	ether_atoe(get_lan_hwaddr(), lan_hwaddr);

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("lldpctl_new_name fail");
		free(cfg_relist);
		return 0;
	}

	do {
		if (cfg_relist == NULL)
			break;

		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				DBG_INFO("iter is null");
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

			lldpctl_atom_foreach(neighbors, neighbor) {
				try_cnt++;
				if (ret == 0)
					continue;

				/* get mac to compare */
				port_id_mac = (char *)lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
				DBG_INFO("port_id_mac (%s)", port_id_mac);
				if (port_id_mac == NULL || strlen(port_id_mac) != 17) {
					DBG_INFO("port_id_mac is null");
					continue;
				}
 				else if (strcasecmp(amas_cap_addr, port_id_mac) == 0) {
					plc_cap = 1;
					if (is_plc_master == 0) {
						ret = 0;
						continue;
					}
				}
				else if(!is_plc_master && strcasecmp(plc_master, port_id_mac) == 0) {
					ret = 0;
					continue;
				}
				else if(strstr(cfg_relist, port_id_mac) == NULL) {
					DBG_INFO("port_id_mac(%s) not a member yet", port_id_mac);
					continue;
				}

				/* get role via port_descr */
				snprintf(port_descr, sizeof(port_descr), "%s", lldpctl_atom_get_str(neighbor, lldpctl_k_port_descr));
				if (strlen(port_descr) == 0) {
					DBG_INFO("port_descr is invalid");
					continue;
				}
				*buf='\0';
				len = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_ETH_ROLE, &buf[0], sizeof(buf));
				if (len <= 0) {
					DBG_INFO("lldp_get_string of ETH_ROLE fail len(%d)", len);
					continue;
				}
				else {
					role_tmp = 0;	//ROLE_NONE
					eth_type_s = strstr(buf, port_descr);
					if (eth_type_s != NULL) {
						sscanf(eth_type_s, "%*[^:]:%d", &role_tmp);
						if (role_tmp == 1) //ROLE_LAN, so PLC has been added in bridge by other PLC devices
						{
							ret = 0;
							continue;	//break
						}
						else if (role_tmp == 2) //ROLE_WAN
							continue;
						else if (role_tmp == 5) //ROLE_PLC_1ST
							continue;
					}
					else {
						DBG_INFO("port_descr(%s) not found in buf(%s)", port_descr, buf);
						continue;	//invalid role
					}
				}

			    if (!is_plc_master)
			    { // don't need to check cost for the plc_master (only role on others are needed.
				/* get cost */
				peer_cost = lldp_get_value_by_oui_type(neighbor, AMAS_SUBTYPE_COST);

				if (peer_cost == UNCHANGED_VALUE)
					continue;		//invaild cost
				if (peer_cost < 0 || peer_cost > cfg_cost)
					continue;
				else if (peer_cost == cfg_cost) {
						if(ether_atoe(port_id_mac, mac)) {
							int i;
							int found_min = 0;
							for(i = 5; i >= 0; i--) {
								if (lan_hwaddr[i] > mac[i]) {
									found_min = 1;
									break;
								}
								else if (lan_hwaddr[i] < mac[i]) {
									break;
								}
							}
							if (found_min == 1) {
								ret = 0;
								continue;	//break
							}
						}
				}
				else /* peer_cost < cfg_cost */
				{
					ret = 0;
					continue;	//break
				}
			    } // !is_plc_master
			} //foreach

			lldpctl_atom_dec_ref(neighbors);
			lldpctl_atom_dec_ref(port);
		}
		if (ret == 0)
			break;
	} while (iface);

	if (cfg_relist)
		free(cfg_relist);

	if (conn) lldpctl_release(conn);

	if (try_cnt)
	{
		*res = AMAS_RESULT_SUCCESS;
		no_plc_dev_cnt = 0;
	}
	else if (no_plc_dev_cnt >= 10)
		*res = AMAS_RESULT_SUCCESS;
	else
	{
		*res = AMAS_RESULT_FAILED;
		no_plc_dev_cnt++;
	}

	if (!(last_is_plc_head & ret)) {
		last_is_plc_head = ret;
		return 0;
	}
	last_is_plc_head = ret;
	return ret;
}

int lldp_find_mac_role(char *ifname, char *mac, AMAS_RESULT *res)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
	int found = 0;
	int try_cnt = 0;
	char *port_id_mac;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;
	char port_descr[32], buf[256];
	char *eth_type_s;
	int role_tmp;
	int len;

	if(ifname == NULL || mac == NULL || strlen(mac) != 17)
		return -1;

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("lldpctl_new_name fail");
		return -1;
	}

	role_tmp = -1;
	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				DBG_INFO("iter is null");
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

			lldpctl_atom_foreach(neighbors, neighbor) {
				try_cnt++;
				if (found == 1)
					continue;

				/* get mac to compare */
				port_id_mac = (char *)lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
				DBG_INFO("port_id_mac (%s)", port_id_mac);
				if (port_id_mac == NULL || strlen(port_id_mac) != 17) {
					DBG_INFO("port_id_mac is null");
					continue;
				}
				else if(strcasecmp(mac, port_id_mac) != 0) {
					continue;
				}
				found = 1;

				/* get role via port_descr */
				snprintf(port_descr, sizeof(port_descr), "%s", lldpctl_atom_get_str(neighbor, lldpctl_k_port_descr));
				if (strlen(port_descr) == 0) {
					DBG_INFO("port_descr is invalid");
					continue;
				}
				*buf='\0';
				len = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_ETH_ROLE, &buf[0], sizeof(buf));
				if (len <= 0) {
					DBG_INFO("lldp_get_string of ETH_ROLE fail len(%d)", len);
					continue;
				}
				else {
					eth_type_s = strstr(buf, port_descr);
					if (eth_type_s != NULL) {
						sscanf(eth_type_s, "%*[^:]:%d", &role_tmp);
					}
				}
			} //foreach

			lldpctl_atom_dec_ref(neighbors);
			lldpctl_atom_dec_ref(port);
		}
		if (found == 1)
			break;
	} while (iface);

	if (conn) lldpctl_release(conn);

	if (try_cnt)
		*res = AMAS_RESULT_SUCCESS;
	else
		*res = AMAS_RESULT_FAILED;

	return role_tmp;
}

int lldp_find_role_lan(char *ifname, char *mac, AMAS_RESULT *res)
{
	const char *ctlname = NULL;
	lldpctl_conn_t *conn = NULL;
	lldpctl_atom_t *iface, *port, *neighbors, *neighbor;
	int found = 0;
	int try_cnt = 0;
	char *port_id_mac;
	lldpctl_atom_iter_t *iter = NULL;
	lldpctl_atom_t *iface_list = NULL;
	char port_descr[32], buf[256];
	char *eth_type_s;
	int role_tmp;
	int len;

	if (res == NULL)
		return -1;

	*res = AMAS_RESULT_FAILED;

	if(ifname == NULL || mac == NULL)
		return -1;

	ctlname = lldpctl_get_default_transport();
	conn = lldpctl_new_name(ctlname, NULL, NULL, NULL);
	if (conn == NULL) {
		DBG_INFO("lldpctl_new_name fail");
		return -1;
	}

	role_tmp = -1;
	do {
		if (iter == NULL) {
			iface_list = lldpctl_get_interfaces(conn);
			if (!iface_list) {
				DBG_INFO("not able to get the list of interfaces. %s",
				    lldpctl_last_strerror(conn));
				break;
			}
			iter = lldpctl_atom_iter(iface_list);
			if (!iter) {
				DBG_INFO("iter is null");
				break;
			}
		} else {
			iter = lldpctl_atom_iter_next(iface_list, iter);
			if (iface) {
				lldpctl_atom_dec_ref(iface);
				iface = NULL;
			}
			if (!iter) {
				lldpctl_atom_dec_ref(iface_list);
				break;
			}
		}

		iface = lldpctl_atom_iter_value(iface_list, iter);
		if (iface && strcmp(ifname, lldpctl_atom_get_str(iface, lldpctl_k_interface_name)) == 0) {
			DBG_INFO("iface (%s)", lldpctl_atom_get_str(iface, lldpctl_k_interface_name));

			port = lldpctl_get_port(iface);
			neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);

			lldpctl_atom_foreach(neighbors, neighbor) {
				try_cnt++;
				if (found == 1)
					continue;

				/* get mac to compare */
				port_id_mac = (char *)lldpctl_atom_get_str(neighbor, lldpctl_k_port_id);
				DBG_INFO("port_id_mac (%s)", port_id_mac);
				if (port_id_mac == NULL || strlen(port_id_mac) != 17) {
					DBG_INFO("port_id_mac is null");
					continue;
				}

				/* get role via port_descr */
				snprintf(port_descr, sizeof(port_descr), "%s", lldpctl_atom_get_str(neighbor, lldpctl_k_port_descr));
				if (strlen(port_descr) == 0) {
					DBG_INFO("port_descr is invalid");
					continue;
				}
				*buf='\0';
				len = lldp_get_string_value_by_oui_type(neighbor, AMAS_SUBTYPE_ETH_ROLE, &buf[0], sizeof(buf));
				if (len <= 0) {
					DBG_INFO("lldp_get_string of ETH_ROLE fail len(%d)", len);
					continue;
				}
				else {
					eth_type_s = strstr(buf, port_descr);
					if (eth_type_s != NULL) {
						sscanf(eth_type_s, "%*[^:]:%d", &role_tmp);
					}
					if (role_tmp == 1) { //ROLE_LAN
						found = 1;
						snprintf(mac, 18, "%s", port_id_mac);
					}
				}
			} //foreach

			lldpctl_atom_dec_ref(neighbors);
			lldpctl_atom_dec_ref(port);
		}
		if (found == 1)
			break;
	} while (iface);

	if (conn) lldpctl_release(conn);

	if (try_cnt)
		*res = AMAS_RESULT_SUCCESS;
	else
		*res = AMAS_RESULT_FAILED;

	return try_cnt;
}
#endif	/* RTCONFIG_QCA_PLC2 */
#endif	/* USE_LLDP_CTRL */
