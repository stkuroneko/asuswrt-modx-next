/**
   @copyright
   Copyright (c) 2003 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   quicksecpm_audit.h
*/

#include "sshincludes.h"
#include "sshaudit.h"

struct SshPmAuditEventRec
{
    unsigned char *data;
    size_t data_len;
};
typedef struct SshPmAuditEventRec *SshPmAuditEvent;

typedef struct SshPmAuditContextRec *SshPmAuditContext;

SshPmAuditContext
ssh_ipsecpm_audit_create(uint16_t ringsize);

void ssh_ipsecpm_audit_cb(SshAuditEvent event,
                          uint32_t argc, SshAuditArgument argv,
                          void *context);

uint16_t ssh_ipsecpm_audit_events(SshPmAuditContext pmaudit,
                                   SshPmAuditEvent *array);

void ssh_ipsecpm_audit_destroy(SshPmAuditContext pmaudit);
/** eof */
