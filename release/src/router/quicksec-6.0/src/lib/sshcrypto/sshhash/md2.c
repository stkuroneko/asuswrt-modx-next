/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   MD2 - Message Digest Algorithm 2
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "md2.h"


static const unsigned char ssh_encoded_md2_oid[] =
{0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48, \
 0x86,0xf7,0x0d,0x02,0x02,0x05,0x00,0x04,0x10};

static const int ssh_encoded_md2_oid_len =
sizeof(ssh_encoded_md2_oid) / sizeof(unsigned char);

/* Interface to the crypto library */
const SshHashDefStruct ssh_hash_md2_def =
{
  /* Name of the hash function. */
  "md2",
  /* Certification status */
  0,
  /* ASN.1 Object Identifier
     iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 2 */
  "1.2.840.113549.2.2",

  /* ISO/IEC dedicated hash identifier (doesn't have one). */
  0,
  /* Digest size */
  16,
  /* Input block length */
  16,
  /* Context size */
  ssh_md2_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long operations */
  ssh_md2_reset_context,
  /* Update function for long operations. */
  ssh_md2_update,
  /* Final function to get the digest. */
  ssh_md2_final,
  /* Asn1 compare function. */
  ssh_md2_asn1_compare,
  /* Asn1 generate function. */
  ssh_md2_asn1_generate
};

/* The MD2 "S-BOX", which is a permutation of numbers 0..255, constructed
   from the digits of pi. */

static const unsigned char MD2_SBox[256] =
{
  0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01,
  0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06, 0x13,
  0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c,
  0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca,
  0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16,
  0x67, 0x42, 0x6f, 0x18, 0x8a, 0x17, 0xe5, 0x12,
  0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49,
  0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a,
  0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f,
  0x94, 0xc2, 0x10, 0x89, 0x0b, 0x22, 0x5f, 0x21,
  0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27,
  0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03,
  0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1,
  0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6,
  0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6,
  0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1,
  0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
  0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02,
  0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6,
  0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f,
  0x55, 0x47, 0xa3, 0x23, 0xdd, 0x51, 0xaf, 0x3a,
  0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
  0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09,
  0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52,
  0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1, 0xab, 0xfa,
  0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a,
  0x78, 0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d,
  0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39,
  0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4,
  0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
  0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a,
  0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83, 0x14
};


/* MD2 Context. Used to store the internal state of MD2 when computation
   is in progress. */

typedef struct {
  unsigned char x[48];
  unsigned char c[16];
  size_t offs;
} SshMD2Context;

/* Reset the MD2 context */

void ssh_md2_reset_context(void *context)
{
  SshMD2Context *ctx;

  ctx = context;
  memset(ctx->x, 0, 48);
  memset(ctx->c, 0, 16);
  ctx->offs = 0;
}

/* Return the size of the context */

size_t ssh_md2_ctxsize()
{
  return sizeof(SshMD2Context);
}

/* Transform a 16-byte block in x[16..32] */

#if 0
#define SSH_MD2_TRANSFORM                  \
  t = c[15];                               \
  for (i = 0; i < 16; i++)                 \
    {                                      \
      t = c[i] ^ MD2_SBox[x[i + 16] ^ t];  \
      c[i] = t;                            \
      x[i + 32] = x[i] ^ x[i + 16];        \
    }                                      \
  t = 0;                                   \
  for (i = 0; i < 18; i++)                 \
    {                                      \
      for (j = 0; j < 48; j++)             \
        {                                  \
          t = x[j] ^ MD2_SBox[t];          \
          x[j] = t;                        \
        }                                  \
      t = (t + i) & 0xff;                  \
    }
#else
#define SSH_MD2_ROUND1(pos) \
{ \
  j = x[pos + 16]; \
  t = c[pos] ^ MD2_SBox[j ^ t]; \
  x[pos + 32] = x[pos] ^ j; \
  c[pos] = t; \
}

#define SSH_MD2_ROUND21(pos) \
{ \
  j = x[pos    ]; \
  j ^= MD2_SBox[t]; \
  t = x[pos + 1]; \
  t ^= MD2_SBox[j]; \
  x[pos    ] = j; \
  x[pos + 1] = t; \
}

#define SSH_MD2_ROUND2(pos) \
{ \
  SSH_MD2_ROUND21(pos    ); \
  SSH_MD2_ROUND21(pos + 2); \
  SSH_MD2_ROUND21(pos + 4); \
  SSH_MD2_ROUND21(pos + 6); \
}

#define SSH_MD2_TRANSFORM \
{ \
  t = c[15]; \
  SSH_MD2_ROUND1( 0); \
  SSH_MD2_ROUND1( 1); \
  SSH_MD2_ROUND1( 2); \
  SSH_MD2_ROUND1( 3); \
  SSH_MD2_ROUND1( 4); \
  SSH_MD2_ROUND1( 5); \
  SSH_MD2_ROUND1( 6); \
  SSH_MD2_ROUND1( 7); \
  SSH_MD2_ROUND1( 8); \
  SSH_MD2_ROUND1( 9); \
  SSH_MD2_ROUND1(10); \
  SSH_MD2_ROUND1(11); \
  SSH_MD2_ROUND1(12); \
  SSH_MD2_ROUND1(13); \
  SSH_MD2_ROUND1(14); \
  SSH_MD2_ROUND1(15); \
  t = 0; \
  for (i = 0; i < 18; i++) \
    { \
      SSH_MD2_ROUND2( 0); \
      SSH_MD2_ROUND2( 8); \
      SSH_MD2_ROUND2(16); \
      SSH_MD2_ROUND2(24); \
      SSH_MD2_ROUND2(32); \
      SSH_MD2_ROUND2(40); \
      t = (t + i) & 0xff; \
    } \
}
#endif

/* Mix in a block of data. */

void ssh_md2_update(void *context, const unsigned char *buf, size_t len)
{
  SshMD2Context *ctx;
  size_t pos, offs, blen;
  unsigned int i, j, t;
  unsigned char *x, *c;
  ctx = context;

  x = ctx->x;
  c = ctx->c;
  offs = ctx->offs;
  pos = 0;

  for (;;)
    {
      /* fill in a (possibly) partial block */
      blen = len - pos;
      if (blen > (16 - offs))
        blen = 16 - offs;
      memcpy(&x[16+offs], &buf[pos], blen);
      offs += blen;
      pos += blen;
      if (offs < 16)
        break;

      /* transform every full 16 bytes */
      SSH_MD2_TRANSFORM;

      offs = 0;
    }

  ctx->offs = offs;
}

/* Finalize MD2 */

SshCryptoStatus ssh_md2_final(void *context, unsigned char *digest)
{
  SshMD2Context *ctx;
  unsigned int i, j, t;
  unsigned char *x, *c;

  ctx = context;
  x = ctx->x;
  c = ctx->c;

  /* Compute padding */
  t = 16 - ctx->offs;
  for (i = ctx->offs + 16; i < 32; i++)
    x[i] = t;
  SSH_MD2_TRANSFORM;

  /* Now merge in the checksum and transform it */
  memcpy(&x[16], c, 16);
  SSH_MD2_TRANSFORM;

  /* ok, we have the digest.. */
  memcpy(digest, x, 16);

  memset(ctx, 0, sizeof(*ctx));
  return SSH_CRYPTO_OK;
}

/* Compute a digest of a buffer */

void ssh_md2_of_buffer(unsigned char digest[16], const unsigned char *buf,
                       size_t len)
{
  SshMD2Context context;
  ssh_md2_reset_context(&context);
  ssh_md2_update(&context, buf, len);
  ssh_md2_final(&context, digest);
}

/* Compares the given oid with max size of max_len to the oid
   defined for the hash. If they match, then return the number
   of bytes actually used by the oid. If they do not match, return
   0. */
size_t ssh_md2_asn1_compare(const unsigned char *oid, size_t max_len)
{
  if (max_len < ssh_encoded_md2_oid_len)
    return 0;
  if (memcmp(oid, ssh_encoded_md2_oid, ssh_encoded_md2_oid_len) == 0)
    return ssh_encoded_md2_oid_len;
  return 0;
}

/* Generate encoded asn1 oid. Returns the pointer to the staticly
   allocated buffer of the oid. Sets the len to be the length
   of the oid. */
const unsigned char *ssh_md2_asn1_generate(size_t *len)
{
  if (len) *len = ssh_encoded_md2_oid_len;
  return ssh_encoded_md2_oid;
}
