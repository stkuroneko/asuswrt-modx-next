 /*
 * Copyright 2021, ASUSTeK Inc.
 * All Rights Reserved.
 */

/*
	update spec in 2020/12/15
	UU      : 2020/12/15
	tencent : 2020/12/15
*/

#include "auth_common.h"
#include <stdint.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
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
		printf("The initial_value is NULL or the length of initial_value is greater than %d.\n", sizeof(tmp_for_tok)-1);
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
		sprintf(tmp_for_calc, "%s|%s|%d", out_buf, tmp_init_value, i);
		calc_code(tmp_for_calc, out_buf);
		i++;
	} while(i<count);
	return out_buf;
}

/****************************
	hw_auth part
*****************************/

/* files.c */
char *gen_rand_value(char *input)
{
	static char ret[64];
	memset(ret, 0, sizeof(ret));

	while (1)
	{
		srand(time(NULL));
		snprintf(ret, sizeof(ret), "%d", rand());
		if (strcmp(ret, input)) break;
	}

	return ret;
}

static int f_read(const char *path, void *buffer, int max)
{
	int f;
	int n;

	if ((f = open(path, O_RDONLY)) < 0) return -1;
	n = read(f, buffer, max);
	close(f);
	return n;
}

static int f_read_string(const char *path, char *buffer, int max)
{
	if (max <= 0) return -1;
	int n = f_read(path, buffer, max - 1);
	buffer[(n > 0) ? n : 0] = 0;
	return n;
}

int f_exists(const char *path)
{
	struct stat st;
	return (stat(path, &st) == 0) && (!S_ISDIR(st.st_mode));
}

/* DEBUG DEFINE */
#define LITE_AUTH_DEBUG             "/tmp/LITE_AUTH_DEBUG"
#define MyDBG(fmt,args...) \
	if(f_exists(LITE_AUTH_DEBUG) > 0) { \
		printf("[LITE_AUTH][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}
/* LOG DEFINE */
#define LITE_AUTH_LOG               "/tmp/LITE_AUTH_LOG"
#define MyLOG(fmt,args...) \
	if(f_exists(LITE_AUTH_LOG) > 0) { \
		char info[1024]; \
		snprintf(info, sizeof(info), "echo \""fmt"\" >> /tmp/LITE_AUTH.log", ##args); \
		system(info); \
	}

/* hw_auth_path */
#define LITE_AUTH_CLM  "/tmp/hw_auth_clm"

/* struct define */
typedef struct SW_AUTH_T sw_auth_t;
struct SW_AUTH_T {
	char *app_name;
	char *app_id;
	char *app_key;
	int  third_party;
};

/* struct define */
typedef struct HW_AUTH_T hw_auth_t;
struct HW_AUTH_T {
	char *productid;
	char *btn_rst_gpio;
	char *btn_wps_gpio;
	char *btn_led_gpio;
	char *btn_wltog_gpio;
	char *clm_data_ver_2g;   // some models don't implement
	char *clm_data_ver_5g1;  // some models don't implement
	char *clm_data_ver_5g2;  // some models don't implement
	char *hwcode;            // hardware code : not to implement now
};

/* 3rd party maintain tuple */
struct SW_AUTH_T s_sw_auth_tuple[] =
{
	/* UU */
	{"uuplugin"       , "43215486", "f233420bbf6b0160425",     0},

	/* Tencent */
	{"qmacc_asus"     , "85432915", "f352564ceb50ec7e731",     0},

	// TODO

	// The End
	{0,0,0,0}
};

/* UU model tuple */
struct HW_AUTH_T s_uu_auth_tuple[] =
{
	/* 382 */
	{"RT-AC85P"      , "4099", "4102",     "",     "",     "RT-AC85P", "", "", ""},
	{"RT-AC2200"     , "4114", "4107",     "",     "",     "RT-AC82U", "", "", ""},

	/* 384 */
	{"RT-AC68U"      , "4107", "4103",    "5", "4111",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC1900P"    , "4107", "4103",    "5", "4111",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC66U_B1"   , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC1750_B1"  , "4107", "4103",  "255",  "255",     "RT-AC68U",     "RT-AC68U",             "", ""},
	{"RT-AC88U"      , "4107", "4116", "4100", "4114",     "RT-AC88U",     "RT-AC88U",             "", ""},
	{"RT-AC5300"     , "4107", "4114", "4100", "4116",    "RT-AC5300",    "RT-AC5300",    "RT-AC5300", ""},
	{"GT-AC5300"     , "4126", "4125", "4127", "4124",    "GT-AC5300",    "GT-AC5300",    "GT-AC5300", ""},
	{"RT-AC86U"      , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
	{"CT-AC2900"     , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
	{"GT-AC2900"     , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},
	{"BLUECAVE"      , "4096", "4126",     "",     "",     "BLUECAVE",             "",             "", ""},
	{"BLUE_CAVE"     , "4096", "4126",     "",     "",     "BLUECAVE",             "",             "", ""},

	/* 386 */
	{"RT-AX88U"      , "4100", "4125", "4127", "4123",     "RT-AX88U",     "RT-AX88U",             "", ""},
	{"GT-AX11000"    , "4100", "4125",     "", "4123",   "GT-AX11000",   "GT-AX11000",             "", ""},
	{"RT-AX92U"      , "4119", "4118",     "",     "",     "RT-AX92U",     "RT-AX92U",             "", ""},
	{"TUF-AX3000"    , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"GS-AX5400"     , "4096", "4097",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"TUF-AX5400"    , "4096", "4117",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"RT-AX68U"      , "4119", "4118",     "",     "",     "RT-AX68U",     "RT-AX68U",             "", ""},
	{"RT-AX86U"      , "4127", "4098", "4111",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
	{"RT-AX86S"      , "4119", "4118", "4110",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
	{"RT-AX82U"      , "4096", "4097", "4106",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"ZenWiFi_XD4"   , "4105", "4104",     "",     "",  "RT-AX56_XD4",  "RT-AX56_XD4",             "", ""},
	{"RT-AX56U_V2"   , "4105", "4100",     "",     "",      "RT-AX55",      "RT-AX55",             "", ""},
	{"ZenWiFi_XD6"   , "4096", "4097",     "",     "",  "RT-AX82_XD6",  "RT-AX82_XD6",             "", ""},

	/* 5.04 */
	{"ZenWiFi_XD4P"  , "4105", "4104",     "",     "",       "XD4PRO",       "XD4PRO",             "", ""},
	{"TUF-AX3000_V2" , "4105", "4104",     "",     "",     "RT-AX58U_V2",  "RT-AX58U_V2",          "", ""},
	{"GT-AX6000"     , "4109", "4108", "4106",     "",    "GT-AX6000",    "GT-AX6000",             "", ""},
	{"GT-AX11000_PRO", "4100", "4125",     "", "4123", "GT-AX11000 PRO", "GT-AX11000 PRO", "GT-AX11000 PRO", ""},

	// The End
	{0,0,0,0,0,0,0,0,0}
};

/* Tencent model tuple */
struct HW_AUTH_T s_tencent_auth_tuple[] =
{
	/* 382 */
	{"RT-AC2200"     , "4114", "4107",     "",     "",     "RT-AC82U", "", "", ""},

	/* 384 */
	{"RT-AC86U"      , "4119", "4118", "4110", "4111",     "RT-AC86U",     "RT-AC86U",             "", ""},

	/* 386 */
	{"TUF-AX5400"    , "4096", "4117",     "",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"RT-AX68U"      , "4119", "4118",     "",     "",     "RT-AX68U",     "RT-AX68U",             "", ""},
	{"RT-AX86U"      , "4127", "4098", "4111",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
	{"RT-AX86S"      , "4119", "4118", "4110",     "",     "RT-AX86U",     "RT-AX86U",             "", ""},
	{"RT-AX82U"      , "4096", "4097", "4106",     "",     "RT-AX58U",     "RT-AX58U",             "", ""},
	{"ZenWiFi_XD4"   , "4105", "4104",     "",     "",  "RT-AX56_XD4",  "RT-AX56_XD4",             "", ""},
	{"RT-AX56U_V2"   , "4105", "4100",     "",     "",      "RT-AX55",      "RT-AX55",             "", ""},

	/* 5.04 */
	{"ZenWiFi_XD4P"  , "4105", "4104",     "",     "",       "XD4PRO",       "XD4PRO",             "", ""},

	// The End
	{0,0,0,0,0,0,0,0,0}
};

#define GET_APP_KEY(app_id, app_key) { \
	struct SW_AUTH_T *p = s_sw_auth_tuple; \
	for (; p->app_id != 0; p++) { \
		if (!strcmp(p->app_id, app_id)) { \
			strcpy(app_key, p->app_key); \
			break; \
		} \
	} \
}

#define GET_APP_ID(app_id, app_key) { \
	struct SW_AUTH_T *p = s_sw_auth_tuple; \
	for (; p->app_key != 0; p++) { \
		if (!strcmp(p->app_key, app_key)) { \
			strcpy(app_id, p->app_id); \
			break; \
		} \
	} \
}

/* new function to get nvram parameters */
static void GetNvramFun(char *val, char *index, int len)
{
	FILE *fp = NULL;
	char buf[64];
	char tmp[32];
	int max = 0;
	int i = 0;

	memset(buf, 0, sizeof(buf));
	memset(tmp, 0, sizeof(tmp));
	snprintf(buf, sizeof(buf), "nvram get %s", index);
	if ((fp = popen(buf, "r")) != NULL) {
		fgets(tmp, sizeof(tmp), fp);
		max = strlen(tmp);

		for (i = 0; i < max - 1 && tmp[i] != '\n' && tmp[i] != '\0'; i++) {
			val[i] = tmp[i];
		}
		for (; i < max; i++) {
			val[max] = '\0';
		}

		if (fp) pclose(fp);
	}
	//MyDBG("[%s] val = %s, tmp = %s, max = %d\n", index, val, tmp, max);
}

static void GetModelName(char *buf, int len)
{
	GetNvramFun(buf, "odmpid", len);

	if (!strcmp(buf, "")) {
		GetNvramFun(buf, "productid", sizeof(buf));
	}
}

static void get_val_bymodel_QCA(char *val, int len)
{
	char buf[128];
	memset(buf, 0, sizeof(buf));

	snprintf(buf, sizeof(buf), "/proc/athversion");
	if (f_read_string(buf, val, len) <= 0)
		memset(val, 0, len);
}

static void get_val_bymodel_BCM(char *ifname, char *val, int len)
{
	char buf[128];
	memset(buf, 0, sizeof(buf));

	MyDBG("ifname=%s\n", ifname);
	snprintf(buf, sizeof(buf), "wl -i %s clm_data_ver > %s", ifname, LITE_AUTH_CLM);
	system(buf);
	snprintf(buf, sizeof(buf), "%s", LITE_AUTH_CLM);
	if (f_read_string(buf, val, len) <= 0)
		memset(val, 0, len);
}

char *hw_component_clm_2g(char *model)
{
	static char val[32];
	int len;

	memset(val, 0, sizeof(val));
	len = sizeof(val);

	if (!strcmp(model, "GT-AC2900") || !strcmp(model, "RT-AC86U") || !strcmp(model, "CT-AC2900") ||!strcmp(model, "RT-AX92U") || !strcmp(model, "TUF-AX3000") || !strcmp(model, "RT-AX82U")
		|| !strcmp(model, "ZenWiFi_XD6")
		|| !strcmp(model, "GS-AX5400")
		|| !strcmp(model, "RT-AX86S") || !strcmp(model, "RT-AX68U")
		|| !strcmp(model, "TUF-AX5400")
	) {
		get_val_bymodel_BCM("eth5", val, len);
	}
	else if (!strcmp(model, "GT-AC5300") || !strcmp(model, "RT-AX88U") || !strcmp(model, "GT-AX11000") || !strcmp(model, "GT-AXE11000") || !strcmp(model, "RT-AX86U")
		|| !strcmp(model, "GT-AX6000") || !strcmp(model, "GT-AX11000_PRO")
	) {
		get_val_bymodel_BCM("eth6", val, len);
	}
	else if (!strcmp(model, "RT-AC68U") || !strcmp(model, "RT-AC1900P") || !strcmp(model, "RT-AC66U_B1") || !strcmp(model, "RT-AC1750_B1") || !strcmp(model, "RT-AC88U") || !strcmp(model, "RT-AC5300")) {
		get_val_bymodel_BCM("eth1", val, len);
	}
	else if (!strcmp(model, "ZenWiFi_XD4") || !strcmp(model, "ZenWiFi_XD4P")) {
		get_val_bymodel_BCM("wl0", val, len);
	}
	else if (!strcmp(model, "RT-AX56U_V2") || !strcmp(model, "TUF-AX3000_V2")) {
		get_val_bymodel_BCM("eth2", val, len);
	}
	else if (!strcmp(model, "RT-AC2200")) {
		get_val_bymodel_QCA(val, len);
	}
	else if (!strcmp(model, "RT-AC85P")) {
		strncpy(val, "RT-AC85P", sizeof(val));
	}
	else if (!strcmp(model, "BLUECAVE") || !strcmp(model, "BLUE_CAVE")) {
		strncpy(val, "BLUECAVE", sizeof(val));
	}
	else {
		snprintf(val, len, "0");
	}

	return val;
}

char *hw_component_clm_5g1(char *model)
{
	static char val[32];
	int len;

	memset(val, 0, sizeof(val));
	len = sizeof(val);

	if (!strcmp(model, "GT-AC2900") || !strcmp(model, "RT-AC86U") || !strcmp(model, "CT-AC2900") ||!strcmp(model, "RT-AX92U") || !strcmp(model, "TUF-AX3000") || !strcmp(model, "RT-AX82U")
		|| !strcmp(model, "ZenWiFi_XD6")
		|| !strcmp(model, "GS-AX5400")
		|| !strcmp(model, "RT-AX86S") || !strcmp(model, "RT-AX68U")
		|| !strcmp(model, "TUF-AX5400")
	) {
		get_val_bymodel_BCM("eth6", val, len);
	}
	else if (!strcmp(model, "GT-AC5300") || !strcmp(model, "RT-AX88U") || !strcmp(model, "GT-AX11000") || !strcmp(model, "GT-AXE11000") || !strcmp(model, "RT-AX86U")
		|| !strcmp(model, "GT-AX6000") || !strcmp(model, "GT-AX11000_PRO")
	) {
		get_val_bymodel_BCM("eth7", val, len);
	}
	else if (!strcmp(model, "RT-AC68U") || !strcmp(model, "RT-AC1900P") || !strcmp(model, "RT-AC66U_B1") || !strcmp(model, "RT-AC1750_B1") || !strcmp(model, "RT-AC88U") || !strcmp(model, "RT-AC5300")) {
		get_val_bymodel_BCM("eth2", val, len);
	}
	else if (!strcmp(model, "ZenWiFi_XD4") || !strcmp(model, "ZenWiFi_XD4P")) {
		get_val_bymodel_BCM("wl1", val, len);
	}
	else if (!strcmp(model, "RT-AX56U_V2") || !strcmp(model, "TUF-AX3000_V2")) {
		get_val_bymodel_BCM("eth3", val, len);
	}
	else {
		snprintf(val, len, "0");
	}

	return val;
}

char *hw_component_clm_5g2(char *model)
{
	static char val[32];
	int len;

	memset(val, 0, sizeof(val));
	len = sizeof(val);

	if (!strcmp(model, "GT-AC5300") || !strcmp(model, "GT-AX11000") || !strcmp(model, "GT-AXE11000")
		|| !strcmp(model, "GT-AX11000_PRO")
	) {
		get_val_bymodel_BCM("eth8", val, len);
	}
	else if (!strcmp(model, "RT-AC5300")) {
		get_val_bymodel_BCM("eth3", val, len);
	}

	snprintf(val, len, "0");

	return val;
}

char *DoHardwareComponent(char *index)
{
	static char val[32];
	memset(val, 0, sizeof(val));
	char odmpid[32] = {0};

	if (!strcmp(index, "productid") || !strcmp(index, "odmpid") || !strcmp(index, "btn_rst_gpio") || !strcmp(index, "btn_wps_gpio") || !strcmp(index, "btn_led_gpio") || !strcmp(index, "btn_wltog_gpio")) {
		GetNvramFun(val, index, sizeof(val));
	}
	else if (!strcmp(index, "clm_data_ver_2g")) {
		GetModelName(odmpid, sizeof(odmpid));
		strncpy(val, hw_component_clm_2g(odmpid), sizeof(val));
	}
	else if (!strcmp(index, "clm_data_ver_5g1")) {
		GetModelName(odmpid, sizeof(odmpid));
		strncpy(val, hw_component_clm_5g1(odmpid), sizeof(val));
	}
	else if (!strcmp(index, "clm_data_ver_5g2")) {
		GetModelName(odmpid, sizeof(odmpid));
		strncpy(val, hw_component_clm_5g2(odmpid), sizeof(val));
	}
	else if (!strcmp(index, "hwcode")) {
		// TODO : in the future, we can add hardware code here
	}
	else {
		MyDBG("The component %s is wrong\n", index);
	}

	MyDBG("val = %s\n", val);
	return val;
}

static int DoHardwareCompare(hw_auth_t *p)
{
	int is_2g  = 0;
	int is_5g1 = 0;
	int is_5g2 = 0;
	int is_product = 0;
	int is_rst = 0;
	int is_wps = 0;
	int is_led = 0;
	int is_tog = 0;
	int is_clm = 0;
	int is_hw  = 0;

	is_2g  = !strncmp(p->clm_data_ver_2g,  DoHardwareComponent("clm_data_ver_2g"),  strlen(p->clm_data_ver_2g));

	/*
		if 5g1 and 5g2 are "", we should consider it as fail case, because our logic is "OR", one condition passed means this logic "TRUE"
	*/
	if (!strcmp(p->clm_data_ver_5g1, "")) {
		is_5g1 = 0;
	}
	else {
		is_5g1 = !strncmp(p->clm_data_ver_5g1, DoHardwareComponent("clm_data_ver_5g1"), strlen(p->clm_data_ver_5g1));
	}

	if (!strcmp(p->clm_data_ver_5g2, "")) {
		is_5g2 = 0;
	}
	else {
		is_5g2 = !strncmp(p->clm_data_ver_5g2, DoHardwareComponent("clm_data_ver_5g2"), strlen(p->clm_data_ver_5g2));
	}

	is_product = !strcmp(p->productid, DoHardwareComponent("productid")) || !strcmp(p->productid, DoHardwareComponent("odmpid"));
	is_rst = !strcmp(p->btn_rst_gpio, DoHardwareComponent("btn_rst_gpio"));
	is_wps = !strcmp(p->btn_wps_gpio, DoHardwareComponent("btn_wps_gpio"));
	//is_led = !strcmp(p->btn_led_gpio, DoHardwareComponent("btn_led_gpio")); // to avoid different branches change the GPIO
	is_led = 1;
	is_tog = !strcmp(p->btn_wltog_gpio, DoHardwareComponent("btn_wltog_gpio"));
	is_clm = is_2g | is_5g1 | is_5g2;
	is_hw  = !strcmp(p->hwcode, DoHardwareComponent("hwcode"));

	MyDBG("productid=%d, is_rst=%d, is_wps=%d, is_led=%d, is_tog=%d, is_clm=%d(%d/%d/%d), is_hw=%d\n",
		is_product, is_rst, is_wps, is_led, is_tog, is_clm, is_2g, is_5g1, is_5g2, is_hw);
	MyLOG("is_productid=%d\nis_rst=%d\nis_wps=%d\nis_led=%d\nis_tog=%d\nis_clm=%d\nis_hw=%d\n",
		is_product, is_rst, is_wps, is_led, is_tog, is_clm, is_hw);

	if (is_product == 1 && is_rst == 1 && is_wps == 1 && is_led == 1
		&& is_tog == 1 && is_clm == 1 && is_hw == 1)
		return 1;
	else
		return 0;
}

char *DoHardwareCheck(char *app_key)
{
	struct HW_AUTH_T *p = s_uu_auth_tuple;
	//struct HW_AUTH_T *p = s_tencent_auth_tuple;

	static char ret[64];
	int is_success = 0; // flag
	char app_id[32];
	char odmpid[32] = {0};

	GetModelName(odmpid, sizeof(odmpid));
	memset(ret, 0, sizeof(ret));
	memset(app_id, 0, sizeof(app_id));
	GET_APP_ID(app_id, app_key);

	// If app_id is empty, skip DoHardwareCompare.
	if (strlen(app_id) == 0)
		goto end;

	for (; p->productid != 0; p++) {
		if (!strcmp(p->productid, odmpid)) {
			// check each hardware components
			is_success = DoHardwareCompare(p);
			break;
		}
	}

end:
	if (is_success != 1) {
		// fail case : get a random code
		strncpy(ret, gen_rand_value(app_id), sizeof(ret));
	}
	else if (is_success == 1) {
		// success case : get app_id
		strncpy(ret, app_id, sizeof(ret));
	}

	MyDBG("odmpid=%s, is_success=%d, ret=%s\n", odmpid, is_success, ret);
	MyLOG("is_success=%d\n", is_success);
	return ret;
}

char *hw_auth_check(char *app_id, char *app_auth_code, time_t timestamp, char *out_buf, int out_buf_size)
{
	char in_buf[128];
	char app_key[64];
	char *hw_check = NULL;
	char *auth_code = NULL;
	char *tmp;

	// vaildate (app_id, app_key)
	memset(app_key, 0, sizeof(app_key));
	GET_APP_KEY(app_id, app_key);
	if (strlen(app_key) == 0) goto end;

	// auth_code : ts + app_key
	snprintf(in_buf, sizeof(in_buf), "%ld|%s", timestamp, app_key);
	auth_code = get_auth_code(in_buf, out_buf, out_buf_size);

	// compare app_auth_code with auth_code
	if (strcmp(app_auth_code, auth_code) != 0) goto end;

	// get hw_check (retrun APP_ID)
	hw_check = DoHardwareCheck(app_key);

	// auth_code : ts + app_key + hw_check
	snprintf(in_buf, sizeof(in_buf), "%ld|%s|%s", timestamp, app_key, hw_check);
	auth_code = get_auth_code(in_buf, out_buf, out_buf_size);

	return auth_code;

end:
	// auth_code : ts + app_key + rand code
	if (hw_check == NULL) hw_check = app_id;
	tmp = gen_rand_value(hw_check);
	snprintf(in_buf, sizeof(in_buf), "%ld|%s|%s", timestamp, app_key, tmp);
	auth_code = get_auth_code(in_buf, out_buf, out_buf_size);
	return auth_code;
}
