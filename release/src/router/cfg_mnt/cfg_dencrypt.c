#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <shared.h>
#include <shutils.h>
#include <pthread.h>
#include "encrypt_main.h"
#include "cfg_common.h"
#include "cfg_crc.h"

/*
========================================================================
Routine Description:
	Encrypt message via aes.

Arguments:
	*key		- key for encrypt message
	*msg		- unencrypted message
	msgLen		- the length of message
	*outLen		- the length of encrypted message

Return Value:
        encrypted message

========================================================================
*/
unsigned char *cm_aesEncryptMsg(unsigned char *key, int pktType, unsigned char *msg, size_t msgLen, size_t *outLen)
{
	size_t encLen = 0;
	unsigned char *encryptedTemp = NULL;
	unsigned
	char *encryptedMsg = NULL;
	TLV_Header tlv;

	/* check key is valid or not */
	if (IsNULL_PTR(key)) {
		DBG_ERR("key is NULL !!!");
		return NULL;
	}

	encryptedTemp = aes_encrypt(key, (unsigned char *)&msg[0], msgLen, &encLen);
	if (IsNULL_PTR(encryptedTemp)) {
		DBG_ERR("Failed to aes_encrypt() !!!");
		return NULL;
	}

	MALLOC(encryptedMsg, unsigned char, sizeof(TLV_Header)+encLen);
	if (IsNULL_PTR(encryptedMsg)) {
		DBG_ERR("Failed to MALLOC() !!!");
		MFREE(encryptedTemp);
		return NULL;
	}

	tlv.type = htonl(pktType);
	tlv.len = htonl(encLen);
	tlv.crc = htonl(Adv_CRC32(0, encryptedTemp, encLen));
        memcpy((unsigned char *)encryptedMsg, (unsigned char *)&tlv, sizeof(TLV_Header));
        memcpy((unsigned char *)encryptedMsg+sizeof(TLV_Header), (unsigned char *)encryptedTemp, encLen);
        MFREE(encryptedTemp);

	DBG_INFO("msgLen(%d) encLen(%d)", msgLen, encLen);
	*outLen = encLen + sizeof(TLV_Header);

	return encryptedMsg;
} /* End of cm_aesEncryptMsg */

unsigned char *cm_aesDecryptMsg(unsigned char *key, unsigned char *key1, unsigned char *msg, size_t msgLen)
{
	unsigned char *decodeMsg = NULL;
	size_t decodeMsgLen = 0;

	/* check key is valid or not */
	if (IsNULL_PTR(key)) {
		DBG_ERR("key is NULL !!!");
		return NULL;
	}

	decodeMsg = aes_decrypt(key, (unsigned char *)msg, msgLen, &decodeMsgLen);
	if (IsNULL_PTR(decodeMsg)) {
		DBG_ERR("Failed to aes_decrypt() by key!!!");
		/* check key1 is valid or not */
		if (IsNULL_PTR(key1)) {
			DBG_ERR("key1 is NULL !!!");
			return NULL;
		}

		decodeMsg = aes_decrypt(key1, (unsigned char *)msg, msgLen, &decodeMsgLen);
		if (IsNULL_PTR(decodeMsg)) {
			DBG_ERR("Failed to aes_decrypt() by key1!!!");
			return NULL;
		}
	}

	DBG_INFO("decodeMsg(%s), decodeMsgLen(%d)", decodeMsg, decodeMsgLen);

	return decodeMsg;
}
