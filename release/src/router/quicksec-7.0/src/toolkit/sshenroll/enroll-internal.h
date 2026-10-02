/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal data structures for certificate enrollment.
*/

#include "sshincludes.h"
#include "x509.h"
#include "sshbuffer.h"
#include "sshstream.h"
#include "sshgetput.h"
#include "sshenroll.h"
#include "x509cmp.h"
#include "x509scep.h"

typedef struct SshPkiSessionMethodRec
{
    const char *name;
    SshPkiType method;

    SshPkiStatus  (*start)   (SshPkiSession session);
    SshPkiStatus  (*confirm) (SshPkiSession session);
    void          (*finish)  (SshPkiSession session);
    bool       (*linear)  (SshPkiSession session);
    bool       (*delinear)(SshPkiSession session);
} *SshPkiSessionMethod, SshPkiSessionMethodStruct;

struct SshPkiSessionRec
{
    SshPkiType type;
    SshPkiStatus status;
    SshOperationHandle operation;
    const SshPkiSessionMethodStruct *methods;
    SshPkiSessionDone done;
    void *done_context;
    unsigned char *request;
    size_t request_len;
    unsigned char *response;
    size_t response_len;
    char *access;
    char *proxy;
    char *socks;
    SshBufferStruct statebuffer;

    uint32_t version; /* depends on type */

    /* Enrollment protocol specific context. Opaque data for this
       layer. */
    void *method_context;
    uint32_t polling_id;
    uint64_t polling_time;

    uint32_t polling_interval;
    MonotonicTime expire_time;

#define SSH_ENROLL_CONFIRMED (1 << 1)
#define SSH_ENROLL_RESUMED   (1 << 2)
#define SSH_ENROLL_RESTARTED (1 << 3)
    uint8_t flags;

    unsigned char *extra;
    size_t extra_len;

    SshStream stream;
};


void ssh_pki_session_abort(void *context);

/* eof */
