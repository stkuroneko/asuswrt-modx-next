/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   iprintf.h
*/

#ifndef IPRINTF_H
#define IPRINTF_H

#include "sshmp.h"
#include "x509.h"

typedef enum {
  PRINT_OFFSET_NONE = 0x00,
  PRINT_OFFSET_DEC = 0x01,
  PRINT_OFFSET_HEX = 0x02,
  PRINT_STRING_DECODE = 0x04,
  PRINT_TAG_HEX_DUMP = 0x10,
  PRINT_VALUE_HEX_DUMP = 0x20
} BerPrintOptionsType;

void iprintf_set(int line_width, int indent_level, int indent_step);
void iprintf_get(int *line_width, int *indent_level, int *indent_step);
void iprintf(const char *str, ...);

void cu_dump_critical(bool critical);
void cu_dump_time(SshBerTime ber_time);
void cu_dump_reason(SshX509ReasonFlags flags);
void cu_dump_fingerprints(const unsigned char *der, size_t der_len);

bool cu_dump_number(SshMPInteger number, int base);
bool cu_dump_pub(SshPublicKey pub, int base);
bool cu_dump_prv(SshPrivateKey prv, int base);

void cu_dump_hex_and_text(unsigned char *buf, size_t len);

void
cu_dump_name(SshStr name_str, SshCharset output, bool ldap);

bool cu_dump_ber(unsigned char *buf, size_t buf_size, size_t offset,
                    BerPrintOptionsType print_options);

bool
cu_dump_names(SshX509Name names, SshCharset output, bool ldap);

bool
cu_dump_key_id(SshX509ExtKeyId key_id,
               SshCharset output, bool ldap, int base);


bool
cu_dump_cert(SshX509Certificate c,
             const unsigned char *der, size_t der_len,
             SshX509CertType cert_type,
             SshCharset output, bool ldap, int base, bool verify);

bool
cu_dump_crl(SshX509Crl crl,
            SshCharset output, bool ldap, int base);

typedef enum {
  CU_CERT_KIND_USER       = (1 << 0),
  CU_CERT_KIND_CA         = (1 << 1),
  CU_CERT_KIND_TOPLEVEL   = (1 << 2),
  CU_CERT_KIND_SIGNATURE  = (1 << 3),
  CU_CERT_KIND_ENCRYPTION = (1 << 4)
} CuCertKind;
CuCertKind cu_determine_cert_kind(SshX509Certificate cert);

#endif /* IPRINTF_H */
