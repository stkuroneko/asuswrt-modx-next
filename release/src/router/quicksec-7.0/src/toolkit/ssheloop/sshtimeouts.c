/**
   @copyright
   Copyright (c) 2002 - 2016, INSIDE Secure Oy. All rights reserved.
*/

/**
   Some internal functions for timeout handling. The platform
   independent code is here, and the rest of the timeout code can be
   found from the event loop of the platform (sshunixeloop.c for Unix
   and win32/ssheloop.c for Windows).
*/

#include "sshincludes.h"
#include "sshtimeoutsi.h"

#define SSH_DEBUG_MODULE "SshTimeout"


/* Compare two struct timespecs.  This returns -1 if the first argument
   is before, 0 if they are equal, and 1 if the second time is before the
   first. */
static int
ssh_event_loop_compare_time(
        const struct timespec *first,
        const struct timespec *second)
{
    return
        (first->tv_sec  < second->tv_sec)  ? -1 :
        (first->tv_sec  > second->tv_sec)  ?  1 :
        (first->tv_nsec < second->tv_nsec) ? -1 :
        (first->tv_nsec > second->tv_nsec) ?  1 : 0;
}

/* ADT compare function for time */
static int
ssh_timeout_time_compare(
        const void *object1,
        const void *object2,
        void *context)
{
    const struct SshTimeoutRec *timeout1 = object1;
    const struct SshTimeoutRec *timeout2 = object2;

    return
        ssh_event_loop_compare_time(
                &timeout1->firing_time,
                &timeout2->firing_time);
}

/* ADT Hash by the timeoutid */
static uint32_t
ssh_timeout_id_hash(const void *object, void *context)
{
    const struct SshTimeoutRec *timeout = object;

    return (uint32_t)(timeout->identifier & 0xffffffff);
}

/* ADT compare by the timeout id */
static int
ssh_timeout_id_compare(
        const void *object1,
        const void *object2,
        void *context)
{
    const struct SshTimeoutRec *timeout1 = object1;
    const struct SshTimeoutRec *timeout2 = object2;

    if (timeout1->identifier < timeout2->identifier)
    {
        return -1;
    }

    if (timeout1->identifier > timeout2->identifier)
    {
        return 1;
    }

    return 0;
}

/* ADT Hash by the context */
static uint32_t
ssh_timeout_ctx_hash(
        const void *object,
        void *context)
{
    const struct SshTimeoutRec *timeout = object;

    return (uint32_t)((intptr_t) timeout->context & 0xffffffff);
}

/* ADT compare context */
static int
ssh_timeout_ctx_compare(
        const void *object1,
        const void *object2,
        void *context)
{
    const struct SshTimeoutRec *timeout1 = object1;
    const struct SshTimeoutRec *timeout2 = object2;

    if (timeout1->context < timeout2->context)
    {
        return -1;
    }

    if (timeout1->context > timeout2->context)
    {
        return 1;
    }

    return 0;
}

/* Initialize the timeout container. Calls ssh_fatal if the
   initialization failed. */
void
ssh_timeout_container_initialize(
        SshTimeoutContainer toc)
{
    toc->map_by_identifier =
        ssh_adt_create_generic(
                SSH_ADT_MAP,
                SSH_ADT_HASH, ssh_timeout_id_hash,
                SSH_ADT_COMPARE, ssh_timeout_id_compare,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshTimeoutStruct,
                                  adt_id_map_hdr),
                SSH_ADT_ARGS_END);

    SSH_ASSERT(toc->map_by_identifier != NULL);

    toc->ph_by_firing_time =
        ssh_adt_create_generic(
                SSH_ADT_PRIORITY_HEAP,
                SSH_ADT_COMPARE, ssh_timeout_time_compare,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshTimeoutStruct,
                                  adt_ft_ph_hdr),
                SSH_ADT_ARGS_END);

    SSH_ASSERT(toc->ph_by_firing_time != NULL);

    toc->map_by_context =
        ssh_adt_create_generic(
                SSH_ADT_MAP,
                SSH_ADT_HASH, ssh_timeout_ctx_hash,
                SSH_ADT_COMPARE, ssh_timeout_ctx_compare,
                SSH_ADT_HEADER,
                SSH_ADT_OFFSET_OF(SshTimeoutStruct,
                                  adt_ctx_map_hdr),
                SSH_ADT_ARGS_END);

    SSH_ASSERT(toc->map_by_context != NULL);

    toc->next_identifier = 1;
}

/* Uninitialize the event loop timeout container */
void
ssh_timeout_container_uninitialize(
        SshTimeoutContainer toc)
{
    ssh_adt_destroy(toc->map_by_identifier);
    ssh_adt_destroy(toc->ph_by_firing_time);
    ssh_adt_destroy(toc->map_by_context);
}

/* Filter 'list' containing timeout records into two parts. The
   entries matching callback and context are returned in new list of
   'cancel' and those not matching in the list 'keep'. Input 'list' is
   corrupted in the process. */
static void
ssh_to_filter_list(
        SshTimeout list,
        SshTimeoutCallback callback,
        void *context,
        SshTimeout *cancel,
        SshTimeout *keep)
{
    SshTimeout to, nto, cto, kto;

    to = list;

    for (kto = cto = NULL; to; to = nto)
    {
        nto = to->next;

        if ((callback == SSH_ALL_CALLBACKS || to->callback == callback) &&
            (context == SSH_ALL_CONTEXTS || to->context == context))
        {
            /* Add to list of cancelled */
            if (cto)
            {
                to->next = cto->next;
                cto->next = to;
            }
            else
            {
                cto = to;
                to->next = NULL;
            }
        }
        else
        {
            /* Timeout was not cancelled. Add to list of remaining. */
            if (kto)
            {
                to->next = kto->next;
                if (to->next)
                  to->next->prev = to;
                to->prev = kto;
                kto->next = to;
            }
            else
            {
                kto = to;
                to->next = NULL;
                to->prev = NULL;
            }
        }
    }
    *cancel = cto;
    *keep = kto;
}

/* Remove entries matching 'callback' and 'context' from the event
   loop context index from bucket pointed by 'cmh' (as in context map
   handle). This also removes the timeouts cancelled from the priority
   heap, and by-id mapping and frees dynamic entries. */
void
ssh_to_remove_from_contextmap(
        SshTimeoutContainer toc,
        SshTimeoutCallback callback,
        void *context,
        SshADTHandle cmh)
{
    SshADTHandle ph, mh;
    SshTimeout to, nto, cto, rto;

    to = ssh_adt_get(toc->map_by_context, cmh);
    ssh_adt_detach(toc->map_by_context, cmh);

    ssh_to_filter_list(to, callback, context, &cto, &rto);

    /* Re-insert the timeouts not cancelled. */
    if (rto)
    {
        ssh_adt_insert(toc->map_by_context, rto);
    }

    /* Cancel the rest of timeouts */
    for (to = cto; to; to = nto)
    {
        nto = to->next;



        {
            ph = &to->adt_ft_ph_hdr;
            ssh_adt_detach(toc->ph_by_firing_time, ph);
        }

        mh = &to->adt_id_map_hdr;
        ssh_adt_detach(toc->map_by_identifier, mh);

        if (to->is_dynamic)
        {
            ssh_free(to);
        }
        else
        {
            memset(to, 0, sizeof(*to));
        }
    }
}
