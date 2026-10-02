/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Help functions for formatting audit events.
*/

#ifndef SSHAUDIT_UTIL_H
#define SSHAUDIT_UTIL_H

bool
ssh_audit_format_number(SshBuffer buffer, const char *label,
                        unsigned char *data, size_t data_len);

uint64_t
ssh_audit_get_number(unsigned char *data, size_t data_len);



#endif /* not SSHAUDIT_UTIL_H */
