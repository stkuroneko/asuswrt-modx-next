#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <wlutils.h>
#include <shutils.h>
#include <shared.h>
#include <wlioctl.h>
#include <rc.h>


#if defined(RTCONFIG_AMAS)

#ifdef RTCONFIG_SW_HW_AUTH
#include <auth_common.h>
#define APP_ID  "33716237"
#define APP_KEY "g2hkhuig238789ajkhc"
#endif

#include <wlscan.h>
#include <bcmendian.h>

#include <sys/reboot.h>
#include <amas-utils.h>
#include <amas_path.h>
#endif

#if defined(RTCONFIG_CFGSYNC)
#include <json.h>
#include <cfg_lib.h>
#include <cfg_event.h>
#include <cfg_onboarding.h>
#include <cfg_string.h>
#endif

#ifdef __MBEDTLS__
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#else   /* __MBEDTLS__ */
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#endif  /* __MBEDTLS__ */

/* Debug Print */
#define OBD_DEBUG_ERROR     0x000001
#define OBD_DEBUG_WARNING   0x000002
#define OBD_DEBUG_INFO      0x000004
#define OBD_DEBUG_EVENT     0x000008
#define OBD_DEBUG_DETAIL    0x000010

#define NEW_RSSI_INFO       1
#define RETRY_TIMES         30  // 60 seconds
#define WAIT_OBLOCK_TIMES   75  // 150 seconds
#define OBD_EXIT_WAIT       30
int timeout_count = 0;
int timeout_obava = 0;
int printlevel = 0;
char enckey[GEN_KEY_LEN + 1] ={0};

#define OBD_DBG(fmt, arg...) \
        do {    \
               if(printlevel) \
                dbG("obd_monitor %lu: "fmt, uptime(), ##arg); \
        } while (0)


#define NORMAL_PERIOD       2       /* second */
#define MAX_RETRY_COUNT     120
#define OBD_TIMEOUT         300

unsigned char reea[ETHER_ADDR_LEN] = {0};
unsigned char newmac[7]={0};
unsigned char re_lastkey[64]={0};
int rekeystat = OB_OFF;
static time_t time_ref;


static void obd_monitor_exit(int sig);
int reset_monitor_status();

/*
check Hex string.
if string == 0, return 1
if string != 0, return 0
*/
int isNull (unsigned char *string, int len) {
  int i = 0;

  for(i = 0; i < len; i++)  {
    if(string[i] != 0) {
        return 0;
    }
  }
  return 1;
}


static char *gen_key32(char *str, int size)
{
    int n = 0;
    int ts = time((time_t *)NULL);
    unsigned int key = 0;
    int ra = 0;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (size) {
        --size;
        for (n = 0; n < size; n++) {
             ra = rand();
             key = (ra/2 + ts/2) % (int) (sizeof charset - 1);
             str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}


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


unsigned char *gen_sha256_key(
    unsigned char *data,
    size_t data_len,
    size_t *out_len)
{
    unsigned char *md = NULL;
    size_t md_len = SHA256_DIGEST_LENGTH;
    SHA256_CTX ctx;

    if (data == NULL || data_len <= 0)
    {
        goto gen_sha256_key_fail;
    }

    md = (unsigned char *)malloc(md_len);
    if (md == NULL)
    {
        OBD_DBG("%s(%d):Memory allocate failed ...\n", __func__, __LINE__);
        goto gen_sha256_key_fail;
    }

    memset(md, 0, md_len);
    if (!SHA256_Init(&ctx))
    {
        OBD_DBG("%s(%d):SHA256_Init() failed ...\n", __func__, __LINE__);
        goto gen_sha256_key_fail;
    }

    if (!SHA256_Update(&ctx, data, data_len))
    {
        OBD_DBG("%s(%d):SHA256_Update() failed ...\n", __func__, __LINE__);
        goto gen_sha256_key_fail;
    }

    if (!SHA256_Final(md, &ctx))
    {
        OBD_DBG("%s(%d):SHA256_Final() failed ...\n", __func__, __LINE__);
        goto gen_sha256_key_fail;
    }

    if (out_len != NULL) *(out_len) = md_len;
    return md;

gen_sha256_key_fail:
    if (md != NULL) free(md);
    if (out_len != NULL) *(out_len) = 0;
    return NULL;
}

//---------------------------------------------------------------------------
unsigned char *data_aes_encrypt(
    unsigned char *key,
    unsigned char *data,
    size_t data_len,
    size_t *out_len)
{
#ifdef __MBEDTLS__

    char strerr[133];
    int ret = 0;
    size_t pad_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    size_t alloc_size = data_len + pad_len;
    size_t len = data_len, offset_size = 0;
    unsigned char b[AES_BLOCK_SIZE], *out = NULL, *o = NULL, *s = &data[0];
    mbedtls_aes_context ctx;

    memset(strerr, 0, sizeof(strerr));
    mbedtls_aes_init(&ctx);

    out = (unsigned char *)malloc(alloc_size);
    if (out == NULL)
    {
        OBD_DBG("%s(%d):Failed to malloc() !!\n", __func__, __LINE__);
        goto aes_encrypt_err;
    }

    ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
    if (ret != 0)
    {
        mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
        OBD_DBG("%s(%d):Failed to mbedtls_aes_setkey_enc() returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
        goto aes_encrypt_err;
    }

    memset(out, 0, alloc_size);
    o = out;

    while (len > AES_BLOCK_SIZE)
    {
        memcpy(b, s, AES_BLOCK_SIZE);
        if ((mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, b, b)) != 0)
        {
            mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
            OBD_DBG("%s(%d):Failed to mbedtls_aes_crypt_ecb(MBEDTLS_AES_ENCRYPT) returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
            goto aes_encrypt_err;
        }
        memcpy(o, b, AES_BLOCK_SIZE);
        s += AES_BLOCK_SIZE;
        o += AES_BLOCK_SIZE;
        len -= AES_BLOCK_SIZE;
        offset_size += AES_BLOCK_SIZE;
    }

    if (len > 0)
    {
        // set up data including padding
        memcpy(b, s, len);
        memset(b + len, AES_BLOCK_SIZE - len, AES_BLOCK_SIZE - len);
        if ((mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, b, b)) != 0)
        {
            mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
            OBD_DBG("%s(%d):Failed to mbedtls_aes_crypt_ecb(MBEDTLS_AES_ENCRYPT) returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
            goto aes_encrypt_err;
        }
        memcpy(o, b, AES_BLOCK_SIZE);
        o += AES_BLOCK_SIZE;
        offset_size += AES_BLOCK_SIZE;
    }

    if (alloc_size - offset_size > 0)
    {
        // set up data including padding
        memset(b, alloc_size - offset_size, AES_BLOCK_SIZE);
        if ((mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, b, b)) != 0)
        {
            mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
            OBD_DBG("%s(%d):Failed to mbedtls_aes_crypt_ecb(MBEDTLS_AES_ENCRYPT) returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
            goto aes_encrypt_err;
        }
        memcpy(o, b, AES_BLOCK_SIZE);
    }

    *out_len = alloc_size;
    mbedtls_aes_free(&ctx);
    return out;

aes_encrypt_err:
    if (out != NULL) free(out);
    mbedtls_aes_free(&ctx);
    return NULL;

#else   /* __MBEDTLS__ */

    EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
    size_t i = data_len, alloc_size = 0;
    unsigned char *s = data, *o = NULL, *out = NULL;
    size_t enc_size = 0;

    if (e_ctx == NULL)
    {
        OBD_DBG("%s(%d):Failed to EVP_CIPHER_CTX_new()!!\n", __func__, __LINE__);
        return NULL;
    }

    if (!EVP_EncryptInit_ex(e_ctx, EVP_aes_256_ecb(), NULL, key, NULL))
    {
        OBD_DBG("%s(%d):EVP_EncryptInit_ex()!!\n", __func__, __LINE__);
        EVP_CIPHER_CTX_free(e_ctx);
        return NULL;
    }

    *out_len = 0;
    alloc_size = data_len+EVP_CIPHER_CTX_block_size(e_ctx);
    out = (unsigned char *)malloc(alloc_size);
    if (out == NULL)
    {
        OBD_DBG("%s(%d):Failed to malloc() !!\n", __func__, __LINE__);
        EVP_CIPHER_CTX_free(e_ctx);
        return NULL;
    }

    memset(out , 0, alloc_size);
    o = out;
    while (i > AES_BLOCK_SIZE)
    {
        if (!EVP_EncryptUpdate(e_ctx, o, (int*)&enc_size, s, AES_BLOCK_SIZE))
        {
            OBD_DBG("%s(%d):Failed to EVP_EncryptUpdate() !!\n", __func__, __LINE__);
            free(out);
            EVP_CIPHER_CTX_free(e_ctx);
            return NULL;
        }

        i -= AES_BLOCK_SIZE;
        s += AES_BLOCK_SIZE;
        o += enc_size;
        *out_len += enc_size;
    }

    if (i > 0)
    {
        if (!EVP_EncryptUpdate(e_ctx, o, (int*)&enc_size, s, i))
        {
            OBD_DBG("%s(%d):Failed to EVP_EncryptUpdate() !!\n", __func__, __LINE__);
            free(out);
            EVP_CIPHER_CTX_free(e_ctx);
            return NULL;
        }
        o += enc_size;
        *out_len += enc_size;
    }

    if (!EVP_EncryptFinal_ex(e_ctx, o, (int*)&enc_size))
    {
        OBD_DBG("%s(%d):EVP_EncryptUpdate() !!\n", __func__, __LINE__);
        free(out);
        EVP_CIPHER_CTX_free(e_ctx);
        return NULL;
    }

    *out_len += enc_size;
    EVP_CIPHER_CTX_free(e_ctx);
    return out;

#endif  /* __MBEDTLS__ */
}

//---------------------------------------------------------------------------
unsigned char *data_aes_decrypt(
    unsigned char *key,
    unsigned char *enc_data,
    size_t data_len,
    size_t *out_len)
{

#ifdef __MBEDTLS__

    char strerr[133];
    int ret = 0;
    size_t len = data_len, alloc_size = data_len;
    mbedtls_aes_context ctx;
    unsigned char b[AES_BLOCK_SIZE], *o = NULL, *out = NULL, *s = &enc_data[0];

    memset(strerr, 0, sizeof(strerr));
    mbedtls_aes_init(&ctx);

    out = (unsigned char *)malloc(alloc_size);
    if (out == NULL)
    {
        OBD_DBG("%s(%d):Failed to malloc() !!\n", __func__, __LINE__);
        goto aes_decrypt_err;
    }

    ret = mbedtls_aes_setkey_dec(&ctx, key, 256);
    if (ret != 0)
    {
        mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
        OBD_DBG("%s(%d): Failed to aes_setkey_dec() returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
        goto aes_decrypt_err;
    }

    memset(out, 0, alloc_size);
    o = out;

    while (len > AES_BLOCK_SIZE)
    {
        memset(b, 0, sizeof(b));
        memcpy(b, s, AES_BLOCK_SIZE);
        if ((ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, b, b)) != 0)
        {
            mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
            OBD_DBG("%s(%d):Failed to mbedtls_aes_crypt_ecb(MBEDTLS_AES_DECRYPT) returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
            goto aes_decrypt_err;
        }
        memcpy(o, b, AES_BLOCK_SIZE);
        len -= AES_BLOCK_SIZE;
        s += AES_BLOCK_SIZE;
        o += AES_BLOCK_SIZE;
    }

    if (len > 0)
    {
        memset(b, 0, sizeof(b));
        memcpy(b, s, len);
        if ((ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, b, b)) != 0)
        {
            mbedtls_strerror(ret, strerr, sizeof(strerr)-1);
            OBD_DBG("%s(%d):Failed to mbedtls_aes_crypt_ecb(MBEDTLS_AES_DECRYPT) returned : (0x%04x)%s\n", __func__, __LINE__, -ret, strerr);
            goto aes_decrypt_err;
        }
        memcpy(o, b, AES_BLOCK_SIZE);
    }

    *out_len = data_len - out[alloc_size-1];
    mbedtls_aes_free(&ctx);
    return out;

aes_decrypt_err:
    if (out != NULL) free(out);
    mbedtls_aes_free(&ctx);
    return NULL;

#else   /* __MBEDTLS__ */

    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
    size_t i = data_len, alloc_size = 0;
    unsigned char *s = enc_data, *o = NULL, *out = NULL;
    size_t dec_size = 0;

    if (d_ctx == NULL)
    {
        OBD_DBG("%s(%d):Failed to EVP_CIPHER_CTX_new() !!\n", __func__, __LINE__);
        return NULL;
    }

    if (!EVP_DecryptInit_ex(d_ctx, EVP_aes_256_ecb(), NULL, key, NULL))
    {
        OBD_DBG("%s(%d):Failed to EVP_DecryptInit_ex() !!\n", __func__, __LINE__);
        EVP_CIPHER_CTX_free(d_ctx);
        return NULL;
    }

    *out_len = 0;
    alloc_size = data_len+EVP_CIPHER_CTX_block_size(d_ctx);
    out = (unsigned char *)malloc(alloc_size);
    if (out == NULL)
    {
        OBD_DBG("%s(%d):Failed to malloc() !!\n", __func__, __LINE__);
        EVP_CIPHER_CTX_free(d_ctx);
        return NULL;
    }

    memset(out, 0, alloc_size);
    o = out;
    while (i > AES_BLOCK_SIZE)
    {
        if (!EVP_DecryptUpdate(d_ctx, o, (int*)&dec_size, s, AES_BLOCK_SIZE))
        {
            OBD_DBG("%s(%d):Failed to EVP_DecryptUpdate()!!\n", __func__, __LINE__);
            free(out);
            EVP_CIPHER_CTX_free(d_ctx);
            return NULL;
        }

        i -= AES_BLOCK_SIZE;
        s += AES_BLOCK_SIZE;
        o += dec_size;
        *out_len += dec_size;
    }

    if (i > 0)
    {
        if (!EVP_DecryptUpdate(d_ctx, o, (int*)&dec_size, s, i))
        {
            OBD_DBG("%s(%d):Failed to EVP_DecryptUpdate()!!\n", __func__, __LINE__);
            free(out);
            EVP_CIPHER_CTX_free(d_ctx);
            return NULL;
        }
        *out_len += dec_size;
        o += dec_size;
    }


    if (!EVP_DecryptFinal_ex(d_ctx, o, (int*)&dec_size))
    {
        OBD_DBG("%s(%d):Failed to EVP_DecryptFinal_ex()!!\n", __func__, __LINE__);
        free(out);
        EVP_CIPHER_CTX_free(d_ctx);
        return NULL;
    }

    *out_len += dec_size;
    EVP_CIPHER_CTX_free(d_ctx);
    return out;

#endif  /* __MBEDTLS__ */
}

//---------------------------------------------------------------------------



static void
obd_monitor(int sig){

    int res = 0, len = 0, k =0, cfg_res = 0, q = 0, misc_info_len = 0;
    ob_status *P_obstatus = NULL;
    sec_status *P_secstatus = NULL;

    char sha256KeyStr[128]={0};
    char aesKeyStr[1024]={0};
    char outId[128] = {0};
#ifdef RTCONFIG_CFGSYNC
    char data[256] = {0};
#endif

    unsigned char temp_key[17]={0};
    unsigned char *sha256Key = NULL;
    unsigned char *encodeTemKey = NULL;

    size_t sha256KeyLen = 0;
    size_t encodeMsgLen = 0;


    if(nvram_get_int("cfg_obstatus") == OB_AVALIABLE)
    {

        res = amas_set_obstatus(OB_AVALIABLE);
        if (res == AMAS_RESULT_SUCCESS) {
            OBD_DBG("Set OB_AVALIABLE finished\n");
        }
        else{
            OBD_DBG("Set OB_AVALIABLE failed\n");
        }

        res = amas_get_obstatus(&P_obstatus, &len);

        if (res != AMAS_RESULT_SUCCESS) {
            OBD_DBG("Get obstatus failed.\n");
            if(P_obstatus != NULL)
                free(P_obstatus);
            if (rekeystat != OB_OFF)
                timeout_obava++;
            return;
        }
        if (len > 0) {
#ifdef RTCONFIG_CFGSYNC
            json_object *root = json_object_new_object();
            json_object *reObj;
            int process = 0;
            char data[1024] = {0};
            char new_re_mac[18] = {0};
            char miscInfo[256] = {0};
#endif
            for (k = 0; k < len; k ++) {
                OBD_DBG("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_obstatus[k].neighmac[0], P_obstatus[k].neighmac[1], P_obstatus[k].neighmac[2], P_obstatus[k].neighmac[3], P_obstatus[k].neighmac[4], P_obstatus[k].neighmac[5]);
                OBD_DBG("%s:%d  Entry[%d] ob status = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].obstatus);
                OBD_DBG("%s:%d  Entry[%d] ob status Timestamp = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].timestamp);
                OBD_DBG("%s:%d  Entry[%d] ob status Model Name = %s\n", __FUNCTION__, __LINE__, k, P_obstatus[k].modelname);
                OBD_DBG("%s:%d  Entry[%d] ob status Tcode = %s\n", __FUNCTION__, __LINE__, k, P_obstatus[k].tcode);
                OBD_DBG("%s:%d  Entry[%d] ob status Reboot Time = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].reboottime);
                OBD_DBG("%s:%d  Entry[%d] ob status Connection Timeout = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].conntimeout);
                OBD_DBG("%s:%d  Entry[%d] ob status Traffic Timeout = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].traffictimeout);
                OBD_DBG("%s:%d  Entry[%d] ob status Type = %d\n", __FUNCTION__, __LINE__, k, P_obstatus[k].type);
                OBD_DBG("%s:%d  Entry[%d] ob status Misc Info =\n", __FUNCTION__, __LINE__, k);
                misc_info_len = 0;
                for (q = 0; q < sizeof(P_obstatus[k].miscinfo); q++) {
                    if (P_obstatus[k].miscinfo[q] == '\0') {
                        misc_info_len = q;
                        break;
                    }
                    OBD_DBG("%02X ", P_obstatus[k].miscinfo[q]);
                }
                OBD_DBG("\n");
                OBD_DBG("=============================================================\n");

#ifdef RTCONFIG_CFGSYNC
                if(P_obstatus[k].obstatus == OB_REQ) {
                    process = 1;
                    snprintf(new_re_mac, sizeof(new_re_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                        P_obstatus[k].neighmac[0], P_obstatus[k].neighmac[1],
                        P_obstatus[k].neighmac[2], P_obstatus[k].neighmac[3],
                        P_obstatus[k].neighmac[4], P_obstatus[k].neighmac[5]);

                    memset(miscInfo, 0, sizeof(miscInfo));
                    if (misc_info_len > 0) {
                        hex2str(&P_obstatus[k].miscinfo[0], &miscInfo[0], misc_info_len);
                    }

                    if (root) {
                        if (P_obstatus[k].reboottime == 0 || P_obstatus[k].conntimeout == 0 ||
                            P_obstatus[k].traffictimeout == 0) {
                            json_object_object_add(root, new_re_mac,
                                json_object_new_string((char *)P_obstatus[k].modelname));
                        }
                        else
                        {
                            reObj = json_object_new_object();
                            if (reObj) {
                                json_object_object_add(reObj, CFG_STR_MODEL_NAME,
                                    json_object_new_string((char *)P_obstatus[k].modelname));
                                json_object_object_add(reObj, CFG_STR_REBOOT_TIME,
                                    json_object_new_int((int)P_obstatus[k].reboottime));
                                json_object_object_add(reObj, CFG_STR_CONN_TIMEOUT,
                                    json_object_new_int((int)P_obstatus[k].conntimeout));
                                json_object_object_add(reObj, CFG_STR_TRAFFIC_TIMEOUT,
                                    json_object_new_int((int)P_obstatus[k].traffictimeout));
                                if (strlen((char *)P_obstatus[k].tcode))
                                    json_object_object_add(reObj, CFG_STR_TCODE,
                                        json_object_new_string((char *)P_obstatus[k].tcode));
                                json_object_object_add(reObj, CFG_STR_TYPE,
                                    json_object_new_int((int)P_obstatus[k].type));
                                if (misc_info_len > 0)
                                    json_object_object_add(reObj, CFG_STR_MISC_INFO,
                                        json_object_new_string(miscInfo));
                                json_object_object_add(root, new_re_mac, reObj);
                            }
                        }
                    }
                }
#endif
            }
#ifdef RTCONFIG_CFGSYNC
            if (process) {
                snprintf(data, sizeof(data) - 1, ETHEVENT_PROBE_MSG,
                    EID_ETHEVENT_DEVICE_PROBE_REQ, json_object_get_string(root));
                OBD_DBG("data (%s)\n", data);
                send_cfgmnt_event(data);
            }
            json_object_put(root);
#endif
            rekeystat = SS_KEY;
        }
        else {
            OBD_DBG("Can't get obstatus entry.\n");
            timeout_obava++;            
        }
    }
    else if (nvram_get_int("cfg_obstatus") == OB_LOCKED)
    {

        if (rekeystat == SS_KEY)
        {
            memset(reea, 0x00, sizeof(reea));
            memset(newmac, 0x00, sizeof(newmac));
            memset(re_lastkey, 0x00, sizeof(re_lastkey));

            res = amas_set_obstatus(OB_LOCKED);
            if (res == AMAS_RESULT_SUCCESS) {
                OBD_DBG("Set OB_LOCKED finished\n");
            }
            else{
                OBD_DBG("Set OB_LOCKED failed\n");
            }

#if defined(RTCONFIG_AMAS_UNIQUE_MAC)
            ether_atoe(get_label_mac(), reea);
#else
            ether_atoe(get_lan_hwaddr(), reea);
#endif

            ether_atoe(nvram_safe_get("cfg_obnewre"), newmac);

            if(!isNull(reea, sizeof(reea)) && !isNull(newmac, sizeof(newmac))) {
                for(k = 0; k<ETHER_ADDR_LEN; k++) {
                    temp_key[k] = reea[k];
                    temp_key[k+6] =newmac[k];
                }
                sha256Key = gen_sha256_key(temp_key, sizeof(temp_key) - 1, &sha256KeyLen);

                memcpy(re_lastkey, sha256Key, HASH_LEN);

                hex2str_x(sha256Key, sha256KeyStr, sha256KeyLen);
                free(sha256Key);
                sha256KeyStr[64] = '\0';
                memset(outId, 0, sizeof(outId));
                snprintf(outId, sizeof(outId), "%s", sha256KeyStr);
                OBD_DBG("outId (%s)\n", outId);
                OBD_DBG("Generate Session Key finished. (%s)\n", outId);
                timeout_count = 0;
                //goto ACTION;

            }
            else {
                OBD_DBG("RE MAC or NEW RE MAC IS NULL.\n");
                timeout_count++;
            }
        }
        else if(rekeystat == SS_KEY_FIN)
        {
            OBD_DBG("========== exchange security.  ========== \n");

            gen_key32(enckey, GEN_KEY_LEN + 1);

            //OBD_DBG("security key: %s\n", enckey);
            encodeTemKey = data_aes_encrypt(re_lastkey, (unsigned char*) enckey, GEN_KEY_LEN, &encodeMsgLen);

            if (encodeTemKey == NULL)
            {
                OBD_DBG("encodeTemKey: Failed to aes_encrypt() !!!!");
                timeout_count++;
            }
            else {

                hex2str_x(encodeTemKey, aesKeyStr, encodeMsgLen);
                OBD_DBG("aesKeyStr (%s)\n", aesKeyStr);

                rekeystat = SS_SECURITY;
                timeout_count = 0;
            }
            /**/
        }
        else if(rekeystat == SS_SECURITY_FIN)
        {
            res = amas_get_secstatus(&P_secstatus, &len);

            if (res != AMAS_RESULT_SUCCESS) {
                OBD_DBG("Get security status failed.\n");
                if(P_secstatus != NULL)
                    free(P_secstatus);
                timeout_count++;
                return;
            }
            else {
                if (len > 0) {
                    for (k = 0; k < len; k ++)
                    {
                        OBD_DBG("%s:%d  Entry[%d] neighbors MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_secstatus[k].neighmac[0], P_secstatus[k].neighmac[1], P_secstatus[k].neighmac[2], P_secstatus[k].neighmac[3], P_secstatus[k].neighmac[4], P_secstatus[k].neighmac[5]);
                        OBD_DBG("%s:%d  Entry[%d] peer MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",__FUNCTION__,__LINE__, k, P_secstatus[k].peermac[0], P_secstatus[k].peermac[1], P_secstatus[k].peermac[2], P_secstatus[k].peermac[3], P_secstatus[k].peermac[4], P_secstatus[k].peermac[5]);
                        OBD_DBG("%s:%d  Entry[%d] sec status = %d\n", __FUNCTION__, __LINE__, k, P_secstatus[k].secstatus);
                        OBD_DBG("=============================================================\n");

                        if (!memcmp(reea, P_secstatus[k].peermac, ETHER_ADDR_LEN) && !memcmp(newmac, P_secstatus[k].neighmac, ETHER_ADDR_LEN)) {
                            if(P_secstatus[k].secstatus == SS_SUCCESS)
                                rekeystat = SS_SUCCESS_FIN;
                            if(P_secstatus[k].secstatus == SS_SECURITYFAIL) {
                                rekeystat = SS_SECURITYFAIL;
                                timeout_count = 0;
			    }
                        }

                    }
                }
                else {
                    OBD_DBG("Can't get any status for aes key.\n");
                    timeout_count++;
                }
            }
            if(P_secstatus != NULL)
                free(P_secstatus);
        }

    }
    if(timeout_obava >= WAIT_OBLOCK_TIMES) {
        OBD_DBG("Reset due to OB available timeout_count over %d\n\n", WAIT_OBLOCK_TIMES);
        obd_monitor_exit(SIGTERM);
    }

    if (timeout_count >= RETRY_TIMES) {
        OBD_DBG("Reset due to timeout_count over %d\n\n", RETRY_TIMES);
        rekeystat = SS_SECURITYFAIL;
    }
    if ((uptime() - time_ref) > OBD_TIMEOUT) {
        OBD_DBG("Reset due to timeout\n");
        time_ref = uptime();
        reset_monitor_status();
        rekeystat = SS_SECURITYFAIL;
    }

    if (rekeystat == SS_KEY && strlen(outId) > 0) {
        OBD_DBG("Generate sessionkey successfully.\n");
        rekeystat = SS_KEY_FIN;
    }

    if(rekeystat == SS_SECURITY && strlen(aesKeyStr) > 0){
        OBD_DBG("Generate security key successfully.\n");

        res = amas_set_sessionkey((unsigned char*)aesKeyStr);
        if (res == AMAS_RESULT_SUCCESS){
                OBD_DBG("Set security key successfully.\n");
                 rekeystat = SS_SECURITY_FIN;
        }else {
                OBD_DBG("Set security key failed.\n");
        }

        if(encodeTemKey != NULL)
            free(encodeTemKey);
    }
    if(rekeystat == SS_SUCCESS_FIN){

        OBD_DBG("exchange security profile successfully.\n");
#ifdef RTCONFIG_CFGSYNC
        OBD_DBG("enckey (%s)\n", enckey);
        snprintf(data, sizeof(data), ETHEVENT_STATUS_MSG,
            EID_ETHEVENT_ONBOARDING_STATUS, OB_STATUS_WPS_SUCCESS, enckey);
        cfg_res = send_cfgmnt_event(data);
        if (cfg_res == 1) {
            OBD_DBG("successfully: Send sucess message to CFG.\n");
            res = amas_set_secstatus(SS_OBD_FIN);
            if (res == AMAS_RESULT_SUCCESS){
                OBD_DBG("Set security status to SS_OBD_FIN(%d)\n", SS_OBD_FIN);
            }
            sleep(OBD_EXIT_WAIT);
            obd_monitor_exit(SIGTERM);
        }
        else {
            OBD_DBG("failed: Send sucess message to CFG.\n");
        }
#endif
    }
    if(rekeystat == SS_SECURITYFAIL) {
        OBD_DBG("exchange security profile failed.\n");
#ifdef RTCONFIG_CFGSYNC
        snprintf(data, sizeof(data), ETHEVENT_STATUS_MSG,
            EID_ETHEVENT_ONBOARDING_STATUS, OB_STATUS_WPS_FAIL, "");
        cfg_res = send_cfgmnt_event(data);
        if (cfg_res == 1) {
            OBD_DBG("successfully: Send fail message to CFG.\n");
            sleep(OBD_EXIT_WAIT);
            obd_monitor_exit(SIGTERM);
        }
        else {
            OBD_DBG("failed: Send fail message to CFG.\n");
        }
#endif
    }


    alarm(NORMAL_PERIOD);


    return;
}

static struct itimerval itv;
static void
alarmtimer(unsigned long sec, unsigned long usec)
{
    itv.it_value.tv_sec = sec;
    itv.it_value.tv_usec = usec;
    itv.it_interval = itv.it_value;
    setitimer(ITIMER_REAL, &itv, NULL);
}


int reset_monitor_status() {
    int res = 0;
    unsigned char value[8]={0};

    memset(reea, 0x00, sizeof(reea));
    memset(newmac, 0x00, sizeof(newmac));
    memset(re_lastkey, 0x00, sizeof(re_lastkey));

    rekeystat = OB_OFF;
    timeout_count = 0;
    timeout_obava = 0;

    res = amas_set_obstatus(0);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear ob status\n");

    res = amas_set_secstatus(0);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear security key status\n");

    strlcpy(value, "NONE", sizeof(value));
    res = amas_set_sessionkey(value);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear session key status\n");

    res = amas_set_peermac(value);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear new RE's information.\n");

    res = amas_set_group(value);
    if (res == AMAS_RESULT_SUCCESS)
        OBD_DBG("Clear group information.\n");

    return 0;
}

static void
obd_monitor_exit(int sig)
{
    if (sig == SIGTERM)
    {
        alarmtimer(0, 0);
        reset_monitor_status();

        remove("/var/run/obd_monitor.pid");
        exit(0);
    }
}


int obd_monitor_main(int argc, char *argv[]) {

    FILE *fp = NULL;
    char *val = 0;
#ifdef RTCONFIG_SW_HW_AUTH
    time_t timestamp = time(NULL);
    char in_buf[48];
    char out_buf[65];
    char hw_out_buf[65];
    char *hw_auth_code = NULL;

    // initial
    memset(in_buf, 0, sizeof(in_buf));
    memset(out_buf, 0, sizeof(out_buf));
    memset(hw_out_buf, 0, sizeof(hw_out_buf));

    // use timestamp + APP_KEY to get auth_code
    snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s", timestamp, APP_KEY);

    hw_auth_code = hw_auth_check(APP_ID, get_auth_code(in_buf, out_buf, sizeof(out_buf)), timestamp, hw_out_buf, sizeof(hw_out_buf));

    // use timestamp + APP_KEY + APP_ID to get auth_code
    snprintf(in_buf, sizeof(in_buf)-1, "%ld|%s|%s", timestamp, APP_KEY, APP_ID);

    // if check fail, return
    if (strcmp(hw_auth_code, get_auth_code(in_buf, out_buf, sizeof(out_buf))) == 0) {
        dbG("This is ASUS router\n");
    }
    else {
        dbG("This is not ASUS router\n");
        return 0;
    }
#else
    dbG("auth check is disabled\n");
    return 0;
#endif

    /* write pid */
    if ((fp = fopen("/var/run/obd_monitor.pid", "w")) != NULL)
    {
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }
    time_ref = uptime();
    reset_monitor_status();
    signal(SIGALRM, obd_monitor);
    signal(SIGTERM, obd_monitor_exit);

    alarm(NORMAL_PERIOD);


    while (1)
    {
        val = nvram_safe_get("obd_monitor_msglevel");
        if (strcmp(val, ""))
            printlevel = strtoul(val, NULL, 0);

        pause();
    }

    return 0;
}
