 /*
 * Copyright 2017, ASUSTeK Inc.
 * All Rights Reserved.
 *
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include "auth_common.h"
#include <stdint.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#if defined __FreeBSD__
# include <netinet/in.h>
# include <arpa/inet.h>
#elif defined __APPLE__
# include <netinet/in.h>
#else
# include <arpa/inet.h>
#endif

/* ---- Endian Detection ------------------------------------ */

#if defined(__digital__) && defined(__unix__)
# include <sex.h>
# define __BIG_ENDIAN__ (BYTE_ORDER == BIG_ENDIAN)
# define __BYTE_ORDER BYTE_ORDER
#elif defined __FreeBSD__
# include <sys/resource.h>	/* rlimit */
# include <machine/endian.h>
# define __BIG_ENDIAN__ (_BYTE_ORDER == _BIG_ENDIAN)
#elif !defined __APPLE__
# include <byteswap.h>
# include <endian.h>
#endif

/* ---- Endian Detection ------------------------------------ */

#if defined(__BIG_ENDIAN__) && __BIG_ENDIAN__
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || defined(__386__)
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#else
# error "Can't determine endianness"
#endif

#define FAST_FUNC

typedef struct auth_sha256_ctx_t {
	uint32_t hash[8];    /* 5, +3 elements for sha256 */
	uint64_t total64;
	uint8_t wbuffer[64]; /* NB: always correctly aligned for uint64_t */
	void (*process_block)(struct auth_sha256_ctx_t*) FAST_FUNC;
} auth_sha256_ctx_t;
static void auth_sha256_begin(auth_sha256_ctx_t *ctx) FAST_FUNC;
static void auth_sha256_hash(const void *data, size_t length, auth_sha256_ctx_t *ctx) FAST_FUNC;
static void auth_sha256_end(void *resbuf, auth_sha256_ctx_t *ctx) FAST_FUNC;

#define ARRAY_SIZE(x) ((unsigned)(sizeof(x) / sizeof((x)[0])))



#define rotl32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define rotr32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#if BB_LITTLE_ENDIAN
static inline uint64_t hton64(uint64_t v)
{
	return (((uint64_t)htonl(v)) << 32) | htonl(v >> 32);
}
#else
#define hton64(v) (v)
#endif


/* Some arch headers have conflicting defines */
#undef ch
#undef parity
#undef maj
#undef rnd

static void FAST_FUNC auth_sha1_process_block64(auth_sha256_ctx_t *ctx)
{
	unsigned t;
	uint32_t W[80], a, b, c, d, e;
	const uint32_t *words = (uint32_t*) ctx->wbuffer;

	for (t = 0; t < 16; ++t) {
		W[t] = ntohl(*words);
		words++;
	}

	for (/*t = 16*/; t < 80; ++t) {
		uint32_t T = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
		W[t] = rotl32(T, 1);
	}

	a = ctx->hash[0];
	b = ctx->hash[1];
	c = ctx->hash[2];
	d = ctx->hash[3];
	e = ctx->hash[4];

/* Reverse byte order in 32-bit words   */
#define ch(x,y,z)        ((z) ^ ((x) & ((y) ^ (z))))
#define parity(x,y,z)    ((x) ^ (y) ^ (z))
#define maj(x,y,z)       (((x) & (y)) | ((z) & ((x) | (y))))
/* A normal version as set out in the FIPS. This version uses   */
/* partial loop unrolling and is optimised for the Pentium 4    */
#define rnd(f,k) \
	do { \
		uint32_t T = a; \
		a = rotl32(a, 5) + f(b, c, d) + e + k + W[t]; \
		e = d; \
		d = c; \
		c = rotl32(b, 30); \
		b = T; \
	} while (0)

	for (t = 0; t < 20; ++t)
		rnd(ch, 0x5a827999);

	for (/*t = 20*/; t < 40; ++t)
		rnd(parity, 0x6ed9eba1);

	for (/*t = 40*/; t < 60; ++t)
		rnd(maj, 0x8f1bbcdc);

	for (/*t = 60*/; t < 80; ++t)
		rnd(parity, 0xca62c1d6);
#undef ch
#undef parity
#undef maj
#undef rnd

	ctx->hash[0] += a;
	ctx->hash[1] += b;
	ctx->hash[2] += c;
	ctx->hash[3] += d;
	ctx->hash[4] += e;
}

/* Constants for SHA512 from FIPS 180-2:4.2.3.
 * SHA256 constants from FIPS 180-2:4.2.2
 * are the most significant half of first 64 elements
 * of the same array.
 */
static const uint64_t sha_K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, /* [64]+ are used for sha512 only */
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#undef Ch
#undef Maj
#undef S0
#undef S1
#undef R0
#undef R1

static void FAST_FUNC auth_sha256_process_block64(auth_sha256_ctx_t *ctx)
{
	unsigned t;
	uint32_t W[64], a, b, c, d, e, f, g, h;
	const uint32_t *words = (uint32_t*) ctx->wbuffer;

	/* Operators defined in FIPS 180-2:4.1.2.  */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22))
#define S1(x) (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25))
#define R0(x) (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3))
#define R1(x) (rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10))

	/* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
	for (t = 0; t < 16; ++t) {
		W[t] = ntohl(*words);
		words++;
	}

	for (/*t = 16*/; t < 64; ++t)
		W[t] = R1(W[t - 2]) + W[t - 7] + R0(W[t - 15]) + W[t - 16];

	a = ctx->hash[0];
	b = ctx->hash[1];
	c = ctx->hash[2];
	d = ctx->hash[3];
	e = ctx->hash[4];
	f = ctx->hash[5];
	g = ctx->hash[6];
	h = ctx->hash[7];

	/* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
	for (t = 0; t < 64; ++t) {
		/* Need to fetch upper half of sha_K[t]
		 * (I hope compiler is clever enough to just fetch
		 * upper half)
		 */
		uint32_t K_t = sha_K[t] >> 32;
		uint32_t T1 = h + S1(e) + Ch(e, f, g) + K_t + W[t];
		uint32_t T2 = S0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
#undef Ch
#undef Maj
#undef S0
#undef S1
#undef R0
#undef R1
	/* Add the starting values of the context according to FIPS 180-2:6.2.2
	   step 4.  */
	ctx->hash[0] += a;
	ctx->hash[1] += b;
	ctx->hash[2] += c;
	ctx->hash[3] += d;
	ctx->hash[4] += e;
	ctx->hash[5] += f;
	ctx->hash[6] += g;
	ctx->hash[7] += h;
}

static const uint32_t init256[] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
static void FAST_FUNC auth_sha256_begin(auth_sha256_ctx_t *ctx)
{
	memcpy(ctx->hash, init256, sizeof(init256));
	ctx->total64 = 0;
	ctx->process_block = auth_sha256_process_block64;
}


/* Used also for sha256 */
static void FAST_FUNC auth_sha256_hash(const void *buffer, size_t len, auth_sha256_ctx_t *ctx)
{
	unsigned in_buf = ctx->total64 & 63;
	unsigned add = 64 - in_buf;

	ctx->total64 += len;

	while (len >= add) {	/* transfer whole blocks while possible  */
		memcpy(ctx->wbuffer + in_buf, buffer, add);
		buffer = (const char *)buffer + add;
		len -= add;
		add = 64;
		in_buf = 0;
		ctx->process_block(ctx);
	}

	memcpy(ctx->wbuffer + in_buf, buffer, len);
}


/* Used also for sha256 */
static void FAST_FUNC auth_sha256_end(void *resbuf, auth_sha256_ctx_t *ctx)
{
	unsigned pad, in_buf;

	in_buf = ctx->total64 & 63;
	/* Pad the buffer to the next 64-byte boundary with 0x80,0,0,0... */
	ctx->wbuffer[in_buf++] = 0x80;

	/* This loop iterates either once or twice, no more, no less */
	while (1) {
		pad = 64 - in_buf;
		memset(ctx->wbuffer + in_buf, 0, pad);
		in_buf = 0;
		/* Do we have enough space for the length count? */
		if (pad >= 8) {
			/* Store the 64-bit counter of bits in the buffer in BE format */
			uint64_t t = ctx->total64 << 3;
			t = hton64(t);
			/* wbuffer is suitably aligned for this */
			*(uint64_t *) (&ctx->wbuffer[64 - 8]) = t;
		}
		ctx->process_block(ctx);
		if (pad >= 8)
			break;
	}

	in_buf = (ctx->process_block == auth_sha1_process_block64) ? 5 : 8;
	/* This way we do not impose alignment constraints on resbuf: */
	if (BB_LITTLE_ENDIAN) {
		unsigned i;
		for (i = 0; i < in_buf; ++i)
			ctx->hash[i] = htonl(ctx->hash[i]);
	}
	memcpy(resbuf, ctx->hash, sizeof(ctx->hash[0]) * in_buf);
}

static void calc_code(char *string, char out_buf[65])
{
	unsigned char hash[32];
	auth_sha256_ctx_t sha256_ctx;
	auth_sha256_begin(&sha256_ctx);
	auth_sha256_hash((unsigned char *)string, (uint32_t)strlen(string), &sha256_ctx);
	auth_sha256_end(&hash, &sha256_ctx);
	int i = 0;
	for(i = 0; i < sizeof(hash); i++)
	{
		sprintf(out_buf + (i * 2), "%2.2x", hash[i]);
	}
	out_buf[64] = 0;
}

#define GET_RAND_COUNT(count) { \
		srand(time(NULL)); \
		count = rand() % 200 + 20; \
	}

#define MAX_TMP_SIZE 513
char *get_auth_code(char *initial_value, char *out_buf, int out_buf_size)
{
	int i = 0, count = 0;
	char tmp_for_tok[MAX_TMP_SIZE], tmp_for_calc[MAX_TMP_SIZE];
	char *pch, *e, *tmp_init_value = initial_value;

	memset(tmp_for_tok, 0, sizeof(tmp_for_tok));

	// If initial_value is NULL or the length of initial_value is greater than MAX_TMP_SIZE, random a value for it and count.
	if (tmp_init_value == NULL || strlen(tmp_init_value) > (sizeof(tmp_for_tok)-1)) {
		printf("The initial_value is NULL or the length of initial_value is greater than %d.\n", (int)sizeof(tmp_for_tok)-1);
		GET_RAND_COUNT(count);
		snprintf(tmp_for_tok, sizeof(tmp_for_tok)-1, "%d", count);
		tmp_init_value = &tmp_for_tok[0];
		goto do_calc;
	}

	strncpy(tmp_for_tok, tmp_init_value, sizeof(tmp_for_tok)-1);

	pch = strtok(tmp_for_tok, "|");
	if (pch != NULL) {
		long long ts = strtoll(pch, &e, 10);
		// if no value can conversion, random a value for it.
		if (ts == 0 || errno == ERANGE) {
			GET_RAND_COUNT(count)
		}
		else
			count = ts % 200 + 20;
	} else {
		GET_RAND_COUNT(count);
	}

do_calc:
	memset(out_buf, 0, out_buf_size);
	do {
		memset(tmp_for_calc, 0, sizeof(tmp_for_calc));
		snprintf(tmp_for_calc, out_buf_size, "%s|%s|%d", out_buf, tmp_init_value, i);
		calc_code(tmp_for_calc, out_buf);
		i++;
	} while(i<count);
	return out_buf;
}
