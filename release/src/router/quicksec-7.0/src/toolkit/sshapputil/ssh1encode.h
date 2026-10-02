/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decode ssh1 type stuff from buffer.
*/

#ifndef SSH1ENCODE_H
#define SSH1ENCODE_H 1

#include "sshbuffer.h"
#include "sshmp.h"

/* Decode ssh1 style encoded 8 bit byte.  Return true on success.
   Buffer is not altered, if decode fails.  Pointer b can also be
   NULL.  In this case, a byte is consumed from the buffer and
   ignored. */
bool ssh1_decode_byte(SshBuffer buffer, uint8_t *b);

/* Decode ssh1 style encoded 32 bit integer.  Return true on success.
   Buffer is not altered, if decode fails.  Pointer n can also be
   NULL.  In this case, 4 bytes are consumed from the buffer and
   ignored. */
bool ssh1_decode_int(SshBuffer buffer, uint32_t *n);

/* Decode ssh1 style encoded multiple precision integer.  Return true
   on success.  Buffer is not altered, if decode fails.  Pointer n
   can also be NULL.  In this case, an integer is decoded and consumed
   from the buffer but not returned to the caller. */
bool ssh1_decode_mp(SshBuffer buffer, SshMPInteger n);

/* Decode ssh1 style encoded string.  Return true on success.  Buffer
   is not altered, if decode fails.  Pointer str can also be NULL.
   In this case, an encoded character string is decoded and consumed
   from the buffer but not returned to the caller. */
bool ssh1_decode_string(SshBuffer buffer, char **str, size_t *len);

/* Decode data from ssh1 style buffer.  Return true on success.  Buffer
   is not altered, if decode fails.  Pointer data can also be NULL.
   In this case, an encoded character string is decoded and consumed
   from the buffer but not returned to the caller. */
bool ssh1_decode_data(SshBuffer buffer, unsigned char **data, size_t len);

/* Encode byte into ssh1 style buffer. */
void ssh1_encode_byte(SshBuffer buffer, uint8_t b);

/* Encode 32 bit integer into ssh1 style buffer. */
void ssh1_encode_int(SshBuffer buffer, uint32_t n);

/* Encode multiple precision integer into ssh1 style buffer. */
void ssh1_encode_mp(SshBuffer buffer, SshMPInteger n);

/* Encode string into ssh1 style buffer. */
void ssh1_encode_string(SshBuffer buffer, const char *str, size_t len);

/* Encode raw data into ssh1 style buffer. */
void ssh1_encode_data(SshBuffer buffer,
                      const unsigned char *data,
                      size_t len);

#endif /* ! SSH1ENCODE_H */
