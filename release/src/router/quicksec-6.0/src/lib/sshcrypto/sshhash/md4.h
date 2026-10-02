/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   MD4 - Message Digest Algorithm 4
*/

#ifndef MD4_H
#define MD4_H


/* Returns the size of an MD4 context. */
size_t ssh_md4_ctxsize(void);

/* Resets the context to its initial state. */
void ssh_md4_reset_context(void *context);

/* Add `len' bytes from the given buffer to the hash. */
void ssh_md4_update(void *context, const unsigned char *buf,
                    size_t len);

/* Finish hashing. 16-byte digest is copied to digest. */
SshCryptoStatus ssh_md4_final(void *context, unsigned char *digest);

/* Compute a MD4 digest from the given buffer. */
void ssh_md4_of_buffer(unsigned char digest[16], const unsigned char *buf,
                       size_t len);

/* Make the defining structure visible everywhere. */
extern const SshHashDefStruct ssh_hash_md4_def;

/* Compares the given oid with max size of max_len to the oid
   defined for the hash. If they match, then return the number
   of bytes actually used by the oid. If they do not match, return
   0. */
size_t ssh_md4_asn1_compare(const unsigned char *oid, size_t max_len);

/* Generate encoded asn1 oid. Returns the pointer to the staticly
   allocated buffer of the oid. Sets the len to be the length
   of the oid. */
const unsigned char *ssh_md4_asn1_generate(size_t *len);

#endif /* MD4_H */
