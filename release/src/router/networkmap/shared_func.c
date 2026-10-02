#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/file.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>


#include <shared.h>
#include <shutils.h>
#include <libasc.h>

#include <json.h>
#include <version.h>


#include "shared_func.h"
#include "protect_name.h"


//If enable NMP_DEBUG, asd won't check signature and decode the signature file in /jffs/asd.
//You can test your feature without upload the signature files. Just need to put them in /jffs/asd


#define NMP_SIG_LEN	256
#define NMP_SHA256_LEN 32

/*******************************************************************
* NAME: _encrypt_data
* DESCRIPTION: encrypt in string by aes256 and do base64 encode
* INPUT: in: string. data to be encrypted.
*		in_len: size_t. the length of in string.
*		key: 256bits.
*		key_len: int. should be 32 chars(256bits).
* OUTPUT: out: pointer of string. the output for the encrypted string.
* RETURN: the length of out.
* NOTE:
*******************************************************************/
static size_t _encrypt_string(const char *input, char *output, const size_t output_len)
{
	if(!input || !output || output_len < pw_enc_blen(input))
	{
		return 0;
	}
	memset(output, 0, output_len);
	pw_enc(input, output, 0);
	return strlen(output);
}




/*******************************************************************
* NAME: get_file_sha256_checksum
* DESCRIPTION: compare the feature name and return the version
* INPUT:  file: string. file path.
*  		 checksum_len: size_t. the length of checksum buffer
* OUTPUT:  checksim: string. The sha256 checksum of file.
* RETURN: NMP_SUCCESS or NMP_FAIL
* NOTE:
*******************************************************************/
int get_file_sha256_checksum(const char *file, char *checksum, const size_t checksum_len, const int file_enc)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	unsigned char *buf = NULL;
	const size_t buf_size = 1024;
	//FILE *fp = NULL;
	int i, bytes_read = 0;

	if(!file || !checksum || checksum_len <= (SHA256_DIGEST_LENGTH * 2))
	{
		return NMP_FAIL;
	}

	printf("[%s] file_enc status = %d \n", __FUNCTION__, file_enc);
	
	buf = read_file(file, 0, file_enc);

	printf("[%s] buf = %s \n", __FUNCTION__, buf);
	
	if(buf)
	{
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, buf, strlen(buf));
		SHA256_Final(hash, &sha256);
		SAFE_FREE(buf);
		memset(checksum, 0, checksum_len);
		for(i = 0; i < SHA256_DIGEST_LENGTH; ++i)
		{
			sprintf(checksum + (i * 2), "%02x", hash[i]);
		}
	}

	printf("[%s] file = %s, checksum = %s \n", __FUNCTION__, file, checksum);


	return NMP_SUCCESS;
}

/*******************************************************************
* NAME: _read_public_key
* DESCRIPTION: get public key in the device
* INPUT:  None
* OUTPUT:  None
* RETURN: pointer of RSA or NULL
* NOTE: Must free this RSA pointer externally.
*******************************************************************/
static RSA *_read_public_key()
{
	FILE *fp;
	RSA *pubRSA = NULL;

	fp = fopen(public_key_path[0], "r");
	if(fp)
	{
		if(!PEM_read_RSA_PUBKEY(fp, &pubRSA, NULL, NULL))
		{
			printf("[%s]PEM_read_RSA_PUBKEY error\n", __FUNCTION__);
		}
		fclose(fp);
	}
	else
	{
		printf("[%s]Cannot open public key (%s)\n", __FUNCTION__, public_key_path[0]);
	}

	return pubRSA;
}

/*******************************************************************
* NAME: _verify_with_public_key
* DESCRIPTION: verify data with public key
* INPUT:  buf: string, data content for verify.
*         buf_len: number, the length of buf.
*         signature: signature data
*         sig_len: the length of signature
* OUTPUT:  None
* RETURN: NMP_SUCCESS or NMP_FAIL
* NOTE:
*******************************************************************/
static int _verify_with_public_key(const char *buf, const size_t buf_len, const unsigned char *signature, const size_t sig_len)
{
	unsigned char md[NMP_SHA256_LEN + 1];
	RSA *pubRSA = NULL;
	int verified = 0;

#ifdef NMP_DEBUG
	return NMP_SUCCESS; //always return NMP_SUCCESS to skip signature verify.
#endif

	if(!buf || !signature)
	{
		return NMP_FAIL;
	}

	pubRSA = _read_public_key();
	if(!pubRSA)
	{
		printf("[%s]_read_public_key fail!\n", __FUNCTION__);
		return NMP_FAIL;
	}

	memset(md, 0, sizeof(md));
	SHA256(buf, buf_len, md);

	verified = RSA_verify(NID_sha256, md, NMP_SHA256_LEN, signature, sig_len, pubRSA);
	RSA_free(pubRSA);

	return verified == 1 ? NMP_SUCCESS : NMP_FAIL;
}
/*******************************************************************
* NAME: _convert_ascii_to_hex
* DESCRIPTION: convert the ascii string to hex char[]
* INPUT:  ascii_str: string, The string needs to be converted.
*         ascii_len: unsigned number, the length of the ascii_str.
*		  hex_len: unsigned number, the size of the hex_str buffer.
* OUTPUT:  hex_str: string. The result string of the conversion.
* RETURN: If success, return the pointer of hex_str. If not, return NULL.
* NOTE:
*******************************************************************/
static char *_convert_ascii_to_hex(const char *ascii_str, const size_t ascii_len, char *hex_str, const size_t hex_len)
{
	int i;

	if(!ascii_str || !hex_str || hex_len <= (ascii_len * 2))	//hex_str need a end-string character in its array.
	{
		return NULL;
	}

	for(i = 0; i < ascii_len; ++i)
	{
		sprintf(hex_str + (i * 2), "%02X", ascii_str[i]);
	}
	return hex_str;
}

/*******************************************************************
* NAME: _convert_hex_to_ascii
* DESCRIPTION: convert the hex string to ascii string
* INPUT:  hex_str: string, The string needs to be converted.
*		  hex_len: unsigned number, the length of the hex_str string.
*         ascii_len: unsigned number, the size of the ascii_str buffer.
* OUTPUT:  ascii_str: string. The result string of the conversion.
* RETURN: If success, return the pointer of ascii_str. If not, return NULL.
* NOTE:
*******************************************************************/
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


/*******************************************************************
* NAME: _verify_hex_str
* DESCRIPTION: Verify the hex_string. Only 0~9, A~F, a~f are valid.
* INPUT:  str: hex string
*               len: length of str
* OUTPUT:  None
* RETURN: NMP_SUCCESS or NMP_FAIL
* NOTE:
*******************************************************************/
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
				return NMP_FAIL;
			}
		}
		return NMP_SUCCESS;
	}
	return NMP_FAIL;
}

/*******************************************************************
* NAME: read_file
* DESCRIPTION: Verify and read the file and return the content without signature.
*			   If need, decrypt the file contnet.
* INPUT:  file: string, path of the file.
*         check_sig: bool number. If 1, need to check the signature of the file.
*		  file_enc: bool number, If 1, need to decrypt the content of the file.
* OUTPUT:  None
* RETURN: The decrypted content of the file without signature.
* NOTE:
*******************************************************************/
char *read_file(const char *file, const int check_sig, const int file_enc)
{
	char *buf = NULL, *f_buf = NULL, *hex_str = NULL;
	unsigned char sig_buf[NMP_SIG_LEN] = {0};
	FILE *fp;
	unsigned long sz, dec_sz, buf_len;

	if(!file)
	{
		return NULL;
	}

	sz = f_size(file);
	if(!sz || (check_sig && sz <= NMP_SIG_LEN))
	{
		printf("[%s] File size (%d) is invalid (%s)!\n", __FUNCTION__, sz, file);
		return NULL;
	}

	fp = fopen(file, "r");
	if(fp)
	{
		f_buf = calloc(sz + 1, 1);
		if(!f_buf)
		{
			printf("[%s] Memory alloc fail!\n", __FUNCTION__);
			fclose(fp);
			return NULL;
		}
		fread(f_buf, 1, check_sig ? sz - NMP_SIG_LEN : sz, fp);
		if(check_sig)
		{
			fread(sig_buf, 1, NMP_SIG_LEN, fp);
		}
		fclose(fp);
	}
	else
	{
		printf("[%s] Cannot open file (%s)!\n", __FUNCTION__, file);
		return NULL;
	}
	if(file_enc)
	{
		dec_sz = pw_dec_len(f_buf);

		if(dec_sz < strlen(f_buf))
		{
			dec_sz = strlen(f_buf);
		}
		hex_str = calloc(dec_sz + 1, 1);
		if(!hex_str)
		{
			printf("[%s] Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			return NULL;
		}
		//decrypt content and verify
		pw_dec(f_buf, hex_str, dec_sz + 1, 0);

		if(_verify_hex_str(hex_str, strlen(hex_str)) == NMP_FAIL)
		{
			printf("[%s] (%s) HEX string is invalid!\n", __FUNCTION__, file);
			SAFE_FREE(f_buf);
			return NULL;
		}
		//convert hex to ascii
		buf_len = strlen(hex_str) / 2 + 1;
		buf = calloc(buf_len, 1);
		if(!buf)
		{
			printf("[%s] Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			SAFE_FREE(hex_str);
			return NULL;
		}
		if(!_convert_hex_to_ascii(hex_str, strlen(hex_str), buf, buf_len))
		{
			printf("[%s] _convert_hex_to_ascii fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			SAFE_FREE(buf);
			SAFE_FREE(hex_str);
			return NULL;
		}
		SAFE_FREE(hex_str);
	}
	else
	{
		buf = strdup(f_buf);
		if(!buf)
		{
			printf("[%s] Memory alloc fail!\n", __FUNCTION__);
			SAFE_FREE(f_buf);
			return NULL;
		}
	}
	SAFE_FREE(f_buf);
	if(buf[0] != '\0')
	{
		if(check_sig)
		{
			if(_verify_with_public_key(buf, strlen(buf), sig_buf, NMP_SIG_LEN) == NMP_SUCCESS)
			{
				return buf;
			}
		}
		else
		{
			return buf;
		}
	}
	SAFE_FREE(buf);
	return NULL;
}

/*******************************************************************
* NAME: encrypt_file
* DESCRIPTION: encrypted the file content and save it with the signature as another file.
* INPUT:  src_file: string, the path of the source file.
*         dst_file: string, the path of the destination file.
*         with_sig: bool number, if 1, the src file include signature data, on need to encrypted it. Just need to copy it to the destination file.
* OUTPUT:  None
* RETURN: NMP_SUCCESS or NMP_FAIL
* NOTE:
*******************************************************************/
int encrypt_file(const char *src_file, const char *dst_file, const int with_sig)
{
	unsigned long src_sz, dst_sz, hex_len;
	unsigned char sig_buf[NMP_SIG_LEN];
	char *src_buf = NULL, *dst_buf = NULL, *hex_str = NULL;
	FILE *fp;
	int ret = NMP_FAIL;

	if(!src_file || !dst_file)
	{
		return ret;
	}

	//read file content
	src_sz = f_size(src_file);
	
	printf("[%s] aa src_sz = %d,  NMP_SIG_LEN = %d \n", __FUNCTION__, src_sz, NMP_SIG_LEN);
	

	if(!src_sz || (with_sig && src_sz <= NMP_SIG_LEN))
	{
		printf("[%s] File size is invalid (%s)!\n", __FUNCTION__, src_file);
		return ret;
	}

	if(with_sig)
	{
		src_sz -= NMP_SIG_LEN;
	}

	printf("[%s] bb src_sz = %d,  NMP_SIG_LEN = %d \n", __FUNCTION__, src_sz, NMP_SIG_LEN);

	fp = fopen(src_file, "r");
	if(fp)
	{
		src_buf = calloc(src_sz + 1, 1);
		if(!src_buf)
		{
			printf("[%s] Memory alloc fail!\n", __FUNCTION__);
			fclose(fp);
			return ret;
		}
		fread(src_buf, 1, src_sz, fp);
		if(with_sig)
		{
			fread(sig_buf, 1, NMP_SIG_LEN, fp);
		}
		fclose(fp);
	}
	else
	{
		printf("[%s] Cannot open file (%s)!\n", __FUNCTION__, src_file);
		return ret;
	}

	//convert file content to hex string
	hex_len = src_sz * 2 + 1;
	hex_str = calloc(hex_len, 1);
	if(!hex_str)
	{
		printf("[%s] Memory alloc fail!\n", __FUNCTION__);
		SAFE_FREE(src_buf);
		return ret;
	}

	if(!_convert_ascii_to_hex(src_buf, src_sz, hex_str, hex_len))
	{
		printf("[%s] _convert_ascii_to_hex fail!\n", __FUNCTION__);
		SAFE_FREE(hex_str);
		SAFE_FREE(src_buf);
		return ret;
	}

	//the original file content would not be used, free it.
	SAFE_FREE(src_buf);

	//encrypt the hex string
	dst_sz = pw_enc_blen(hex_str);

	dst_buf = calloc(dst_sz + 1, 1);
	if(!dst_buf)
	{
		printf("[%s] Memory alloc fail!\n", __FUNCTION__);
		SAFE_FREE(hex_str);
		return ret;
	}

	pw_enc(hex_str, dst_buf, 0);

	if(dst_buf[0] != '\0')
	{
		fp = fopen(dst_file, "w");
		if(fp)
		{
			fwrite(dst_buf, 1, strlen(dst_buf), fp);
			if(with_sig)
			{
				fwrite(sig_buf, 1, NMP_SIG_LEN, fp);
			}

			fclose(fp);
			ret = NMP_SUCCESS;
		}
		else
		{
			printf("[%s] Cannot open file (%s)!\n", __FUNCTION__, dst_file);
		}
	}
	else
	{
		printf("[%s] Cannot encrypt content.\n", __FUNCTION__);
	}

	SAFE_FREE(hex_str);
	SAFE_FREE(dst_buf);
	return ret;
}

/*******************************************************************
* NAME: download_file
* DESCRIPTION: download the file from server.
* INPUT:  file_name: string, the file name on the server.
*         local_file_path: string.the local file path to store the download file.
* OUTPUT: None
* RETURN:  NMP_SUCCESS or NMP_FAIL
* NOTE:
*	2021/05/31, Andy Chiu.  Change version file path to sdv2.(RSA version).php, sdmv2.(RSA version).php
						  Change signature file path to sdv2.php, sdmv2.php
*******************************************************************/
int download_file(const char *file_name, const char *local_file_path)
{
	char dl_path[64], rsa_ver[4] = {0};
	const char third_party[][16] = {{'3', 'r', 'd', '-', 'p', 'a', 'r', 't', 'y', '\0',}};
	int ver_flag = 0;

	if(!file_name || !local_file_path || !internet_ready())
	{
		return NMP_FAIL;
	}

	const char dl_path_file_end[][32] = {{'.', 'p', 'h', 'p', '\0'}};

	if(!strcmp(file_name, version_name[0]))
	{
		ver_flag = 1;
	}

	if(ver_flag)
	{
#ifdef RTCONFIG_LIVE_UPDATE_RSA
		strlcpy(rsa_ver, LIVE_UPDATE_RSA_VERSION, sizeof(rsa_ver));
		if(rsa_ver[0] == '\0')
		{
			strlcpy(rsa_ver, "0", sizeof(rsa_ver));
		}
#else
		strlcpy(rsa_ver, "0", sizeof(rsa_ver));
#endif
		snprintf(dl_path, sizeof(dl_path), "%s.%s%s", dl_path_file_name[0], rsa_ver, dl_path_file_end[0]);
	}
	else
	{
		snprintf(dl_path, sizeof(dl_path), "%s%s", dl_path_file_name[0], dl_path_file_end[0]);
	}

	printf("[%s] file_name = %s \n", __FUNCTION__, file_name);
	printf("[%s] dl_path = %s \n", __FUNCTION__, dl_path);
	printf("[%s] local_file_path = %s \n", __FUNCTION__, local_file_path);


	nvram_set("nmp_type", file_name);
	
	return (curl_download_file(NETWORKMAP_DB, dl_path, local_file_path) == LIBASC_SUCCESS) ? NMP_SUCCESS : NMP_FAIL;
}

